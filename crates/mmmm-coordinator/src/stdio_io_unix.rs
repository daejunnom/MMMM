//! Trusted self-worker session ownership. This is not a sandbox against a
//! deliberately escaping program. Keep the leader unreaped until group drain.
use super::{Executable, StdioError, StdioOutput, WorkerReservation};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

// POSIX CLOCK_MONOTONIC is system-wide and cannot be reset by wall-clock writes.
// https://pubs.opengroup.org/onlinepubs/000095399/functions/clock_getres.html
pub(super) const MONOTONIC_MARGIN_MILLIS: u64 = 1;
pub(super) fn monotonic_millis() -> Result<u64, StdioError> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } == -1 {
        return Err(StdioError::io(
            "native_clock",
            std::io::Error::last_os_error(),
        ));
    }
    let seconds = u64::try_from(time.tv_sec).map_err(|_| StdioError::new("native_clock"))?;
    let nanos = u64::try_from(time.tv_nsec).map_err(|_| StdioError::new("native_clock"))?;
    if nanos >= 1_000_000_000 {
        return Err(StdioError::new("native_clock"));
    }
    seconds
        .checked_mul(1000)
        .and_then(|millis| millis.checked_add(nanos / 1_000_000))
        .ok_or_else(|| StdioError::new("native_clock"))
}

pub(super) fn open_executable(path: &Path) -> Result<File, StdioError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| StdioError::io("executable_open", e))?;
    let metadata = file
        .metadata()
        .map_err(|e| StdioError::io("executable_metadata", e))?;
    if !metadata.is_file() || metadata.mode() & 0o022 != 0 {
        return Err(StdioError::new("executable_limits"));
    }
    Ok(file)
}
pub(super) fn same_file(file: &File, path: &Path) -> Result<bool, StdioError> {
    let original = file
        .metadata()
        .map_err(|_| StdioError::new("executable_identity"))?;
    let current = open_executable(path)?
        .metadata()
        .map_err(|_| StdioError::new("executable_identity"))?;
    Ok(original.dev() == current.dev()
        && original.ino() == current.ino()
        && original.len() == current.len()
        && original.mtime() == current.mtime()
        && original.mtime_nsec() == current.mtime_nsec())
}
pub(super) fn worker_stdio(output: StdioOutput) -> Result<(File, File), StdioError> {
    fn file(source: i32) -> Result<File, StdioError> {
        let fd = unsafe { libc::dup(source) };
        if fd == -1 {
            return Err(StdioError::new("external_stdio"));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            return Err(StdioError::new("external_stdio"));
        }
        Ok(file)
    }
    // File reads and writes are unbuffered. A requested public prefix cannot
    // eagerly fill a global Stdin buffer with the following raw capability.
    Ok((
        file(libc::STDIN_FILENO)?,
        file(match output {
            StdioOutput::Stdout => libc::STDOUT_FILENO,
            StdioOutput::Stderr => libc::STDERR_FILENO,
        })?,
    ))
}
fn bootstrap(packet: &[u8]) -> Result<(File, File), StdioError> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
        return Err(StdioError::new("bootstrap_pipe"));
    }
    let read = unsafe { File::from_raw_fd(fds[0]) };
    let mut write = unsafe { File::from_raw_fd(fds[1]) };
    for fd in fds {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            return Err(StdioError::new("bootstrap_pipe"));
        }
    }
    // Nonblocking fresh pipe, one fixed packet below POSIX PIPE_BUF minimum.
    if unsafe { libc::fcntl(write.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } == -1
        || packet.len() != super::BOOTSTRAP_LENGTH
    {
        return Err(StdioError::new("bootstrap_pipe"));
    }
    write
        .write_all(packet)
        .map_err(|_| StdioError::new("bootstrap_pipe"))?;
    Ok((read, write))
}
pub(super) fn read_bootstrap(
    value: usize,
) -> Result<zeroize::Zeroizing<[u8; super::BOOTSTRAP_LENGTH]>, StdioError> {
    let fd = i32::try_from(value).map_err(|_| StdioError::new("bootstrap_handle"))?;
    if fd < 3 {
        return Err(StdioError::new("bootstrap_handle"));
    }
    let mut info: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut info) } == -1 {
        return Err(StdioError::io(
            "bootstrap_type",
            std::io::Error::last_os_error(),
        ));
    }
    if info.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return Err(StdioError::new("bootstrap_type"));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    // Only an inherited anonymous pipe is eligible. Nonblocking avoids a
    // hidden entry hanging when invoked without its trusted parent packet.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(StdioError::io(
            "bootstrap_read",
            std::io::Error::last_os_error(),
        ));
    }
    let mut packet = zeroize::Zeroizing::new([0; super::BOOTSTRAP_LENGTH]);
    file.read_exact(&mut packet[..])
        .map_err(|e| StdioError::io("bootstrap_read", e))?;
    Ok(packet)
}

/// Fixed metadata carried by Command's existing CLOEXEC startup-error pipe.
/// The pre-exec child uses only integer operations and an OS error value; it
/// allocates no diagnostic string or additional pipe. The parent decodes this
/// only after Command has returned an error, without claiming a worker drain.
#[derive(Clone, Copy)]
pub(super) enum SpawnStage {
    Session = 1,
    #[cfg(target_os = "linux")]
    Descriptors = 2,
    #[cfg(target_os = "linux")]
    Bootstrap = 3,
    MemoryLimit = 4,
    CoreLimit = 5,
    Exec = 6,
    #[cfg(target_os = "macos")]
    StdinDescriptor = 7,
    #[cfg(target_os = "macos")]
    StdoutDescriptor = 8,
    #[cfg(target_os = "macos")]
    StderrDescriptor = 9,
    #[cfg(target_os = "macos")]
    BootstrapDescriptor = 10,
    #[cfg(target_os = "macos")]
    BootstrapType = 11,
}
const SPAWN_STAGE_TAG: u32 = 0x4e00_0000;
const SPAWN_NATIVE_NONE: u32 = 65_535;
const SPAWN_NATIVE_UNKNOWN: u32 = 65_534;

pub(super) fn spawn_stage_error(stage: SpawnStage, error: std::io::Error) -> std::io::Error {
    let native = match error.raw_os_error() {
        Some(code) if (0..=65_533).contains(&code) => code as u32,
        None => SPAWN_NATIVE_NONE,
        _ => SPAWN_NATIVE_UNKNOWN,
    };
    encoded_spawn_error(stage, native)
}

fn encoded_spawn_error(stage: SpawnStage, native: u32) -> std::io::Error {
    std::io::Error::from_raw_os_error((SPAWN_STAGE_TAG | (stage as u32) << 16 | native) as i32)
}

pub(super) fn spawn_failure(error: std::io::Error) -> StdioError {
    if let Some(encoded) = error.raw_os_error().map(|code| code as u32)
        && encoded & 0xff00_0000 == SPAWN_STAGE_TAG
    {
        let code = match (encoded >> 16) & 255 {
            1 => "native_spawn_session",
            2 => "native_spawn_descriptors",
            3 => "native_spawn_bootstrap",
            4 => "native_spawn_memory_limit",
            5 => "native_spawn_core_limit",
            6 => "native_spawn_exec",
            #[cfg(target_os = "macos")]
            7 => "native_spawn_stdin_descriptor",
            #[cfg(target_os = "macos")]
            8 => "native_spawn_stdout_descriptor",
            #[cfg(target_os = "macos")]
            9 => "native_spawn_stderr_descriptor",
            #[cfg(target_os = "macos")]
            10 => "native_spawn_bootstrap_descriptor",
            #[cfg(target_os = "macos")]
            11 => "native_spawn_bootstrap_type",
            _ => return StdioError::io("native_spawn", error),
        };
        let native = encoded & 65_535;
        let mut failure = StdioError::new(code);
        failure.native_code = (native < SPAWN_NATIVE_UNKNOWN).then_some(native as i32);
        failure.native_code_unknown = native == SPAWN_NATIVE_UNKNOWN;
        return failure;
    }
    StdioError::io("native_spawn", error)
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    // Public Darwin extension, available since macOS 10.7. The libc crate
    // exposes the opaque action type and spawn flags, but not this function.
    fn posix_spawn_file_actions_addinherit_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        fd: libc::c_int,
    ) -> libc::c_int;
}

/// All allocation and action construction happens in the parent. SETEXEC
/// overlays the already-owned Command child instead of spawning a new child.
#[cfg(target_os = "macos")]
struct MacExec {
    attr: libc::posix_spawnattr_t,
    actions: libc::posix_spawn_file_actions_t,
    attr_ready: bool,
    actions_ready: bool,
    _arguments: Vec<std::ffi::CString>,
    path: usize,
    argv: Vec<usize>,
    env: [usize; 1],
    descriptors: [(SpawnStage, libc::c_int); 4],
}
// The opaque objects are exclusively constructed/destroyed in the parent.
// Command's pre_exec closure only reads its forked copy; no native mutation or
// concurrent access to the parent objects occurs after construction.
#[cfg(target_os = "macos")]
unsafe impl Send for MacExec {}
#[cfg(target_os = "macos")]
unsafe impl Sync for MacExec {}

#[cfg(target_os = "macos")]
impl MacExec {
    fn new(path: &Path, args: &[String], boot: i32) -> Result<Self, StdioError> {
        use std::os::unix::ffi::OsStrExt;
        let arguments = std::iter::once(path.as_os_str())
            .chain(args.iter().map(std::ffi::OsStr::new))
            .map(|arg| {
                std::ffi::CString::new(arg.as_bytes()).map_err(|_| StdioError::new("executable"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let path = arguments[0].as_ptr() as usize;
        let argv = arguments
            .iter()
            .map(|arg| arg.as_ptr() as usize)
            .chain(Some(0))
            .collect();
        let mut plan = Self {
            attr: std::ptr::null_mut(),
            actions: std::ptr::null_mut(),
            attr_ready: false,
            actions_ready: false,
            _arguments: arguments,
            path,
            argv,
            env: [0],
            descriptors: [
                (SpawnStage::StdinDescriptor, libc::STDIN_FILENO),
                (SpawnStage::StdoutDescriptor, libc::STDOUT_FILENO),
                (SpawnStage::StderrDescriptor, libc::STDERR_FILENO),
                (SpawnStage::BootstrapDescriptor, boot),
            ],
        };
        fn check(result: i32) -> Result<(), StdioError> {
            if result == 0 {
                Ok(())
            } else {
                Err(StdioError::io(
                    "native_descriptors",
                    std::io::Error::from_raw_os_error(result),
                ))
            }
        }
        // libc exposes these Darwin constants as c_int, while the native API
        // accepts c_short. Validate in the parent, before the forked exec path.
        let flags =
            libc::c_short::try_from(libc::POSIX_SPAWN_SETEXEC | libc::POSIX_SPAWN_CLOEXEC_DEFAULT)
                .map_err(|_| StdioError::new("native_descriptors"))?;
        check(unsafe { libc::posix_spawnattr_init(&mut plan.attr) })?;
        plan.attr_ready = true;
        check(unsafe { libc::posix_spawn_file_actions_init(&mut plan.actions) })?;
        plan.actions_ready = true;
        check(unsafe { libc::posix_spawnattr_setflags(&mut plan.attr, flags) })?;
        for &(_, fd) in &plan.descriptors {
            check(unsafe { posix_spawn_file_actions_addinherit_np(&mut plan.actions, fd) })?;
        }
        Ok(plan)
    }

    fn exec(&self) -> std::io::Result<()> {
        // Exactly the four roles prepared for inheritance are inspected here.
        // SETEXEC's exec-table clone drops CLOEXEC descriptors before its
        // inherit actions run. Clear only that bit for these same four roles
        // in this forked child; preserve every other original descriptor flag.
        // There is no retry, allocation or descriptor fallback. A syscall
        // error is captured before any other native call. The parent retains
        // its original deadline; these five checks and at most four F_SETFD
        // calls provide no hard interruption bound for a delayed syscall.
        for &(stage, fd) in &self.descriptors {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags == -1 {
                let error = std::io::Error::last_os_error();
                return Err(spawn_stage_error(stage, error));
            }
            if flags & libc::FD_CLOEXEC != 0
                && unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } == -1
            {
                let error = std::io::Error::last_os_error();
                return Err(spawn_stage_error(stage, error));
            }
        }
        let [_, _, _, (_, bootstrap)] = self.descriptors;
        let mut info: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(bootstrap, &mut info) } == -1 {
            let error = std::io::Error::last_os_error();
            return Err(spawn_stage_error(SpawnStage::BootstrapType, error));
        }
        if info.st_mode & libc::S_IFMT != libc::S_IFIFO {
            // A shape mismatch supplies no OS errno. Preserve known absence
            // instead of inventing EBADF, EINVAL or an I/O failure number.
            return Err(encoded_spawn_error(
                SpawnStage::BootstrapType,
                SPAWN_NATIVE_NONE,
            ));
        }
        // Apple's SETEXEC wrapper reads the prepared objects and submits one
        // native spawn syscall. This child path allocates, locks and drops no
        // Rust objects. CLOEXEC_DEFAULT acts on the actual exec descriptor
        // table, including open descriptors above a subsequently lowered limit.
        let result = unsafe {
            libc::posix_spawn(
                std::ptr::null_mut(),
                self.path as *const libc::c_char,
                &self.actions,
                &self.attr,
                self.argv.as_ptr().cast(),
                self.env.as_ptr().cast(),
            )
        };
        // Successful SETEXEC never returns. On failure, return the native
        // errno through Command's original CLOEXEC startup-error pipe, which
        // remains open until successful image activation actually closes it.
        Err(if result <= 0 {
            // SETEXEC success cannot return. Do not turn an unexpected return
            // into a fabricated native EIO code or truncate a negative status.
            encoded_spawn_error(SpawnStage::Exec, SPAWN_NATIVE_UNKNOWN)
        } else {
            spawn_stage_error(SpawnStage::Exec, std::io::Error::from_raw_os_error(result))
        })
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacExec {
    fn drop(&mut self) {
        // This destructor runs only in the parent after Command::spawn, or
        // when preparation fails before any child exists.
        unsafe {
            if self.actions_ready {
                libc::posix_spawn_file_actions_destroy(&mut self.actions);
            }
            if self.attr_ready {
                libc::posix_spawnattr_destroy(&mut self.attr);
            }
        }
    }
}

pub(super) struct Process {
    child: Option<Child>,
    pid: libc::pid_t,
    reaped: bool,
    reserved: bool,
    reaped_code: Option<i32>,
    owner_deadline: Instant,
    reservation: Option<WorkerReservation>,
    #[cfg(target_os = "macos")]
    identity: Option<MacIdentity>,
    #[cfg(target_os = "macos")]
    identity_uncertain: bool,
    #[cfg(target_os = "macos")]
    resource_identity_uncertain: bool,
    #[cfg(target_os = "macos")]
    resources: ResourceTracker,
}
impl Process {
    pub(super) fn spawn(
        executable: &Executable,
        address: SocketAddr,
        packet: &[u8],
        output: StdioOutput,
        owner_deadline: Instant,
        startup_deadline: Instant,
        reservation: WorkerReservation,
    ) -> Result<Self, StdioError> {
        super::deadline_check(startup_deadline)?;
        let (read, write) = bootstrap(packet)?;
        let boot = read.as_raw_fd();
        let args = [
            super::WORKER_COMMAND.to_owned(),
            address.to_string(),
            boot.to_string(),
        ];
        let mut command = Command::new(&executable.path);
        command
            .args(&args)
            .env_clear()
            .stdin(Stdio::inherit())
            .stdout(if output == StdioOutput::Stdout {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .stderr(if output == StdioOutput::Stderr {
                Stdio::inherit()
            } else {
                Stdio::null()
            });
        #[cfg(target_os = "linux")]
        let exec_fd = executable.file.as_raw_fd();
        #[cfg(target_os = "linux")]
        let cargs: Vec<std::ffi::CString> = std::iter::once(executable.path.as_os_str())
            .chain(args.iter().map(std::ffi::OsStr::new))
            .map(|a| {
                use std::os::unix::ffi::OsStrExt;
                std::ffi::CString::new(a.as_bytes()).map_err(|_| StdioError::new("executable"))
            })
            .collect::<Result<_, _>>()?;
        #[cfg(target_os = "linux")]
        let argv: Vec<usize> = cargs
            .iter()
            .map(|a| a.as_ptr() as usize)
            .chain(Some(0))
            .collect();
        #[cfg(target_os = "macos")]
        let mac_exec = MacExec::new(&executable.path, &args, boot)?;
        // pre_exec contains only async-signal-safe syscalls and preallocated
        // argv pointers. Rust's startup error pipe remains CLOEXEC, not closed.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(spawn_stage_error(
                        SpawnStage::Session,
                        std::io::Error::last_os_error(),
                    ));
                }
                #[cfg(target_os = "linux")]
                if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) == -1 {
                    // Linux 5.11+ CLOSE_RANGE_CLOEXEC is required, rather than
                    // silently inheriting descriptors or looping a huge limit.
                    return Err(spawn_stage_error(
                        SpawnStage::Descriptors,
                        std::io::Error::last_os_error(),
                    ));
                }
                #[cfg(target_os = "linux")]
                if libc::fcntl(boot, libc::F_SETFD, 0) == -1 {
                    return Err(spawn_stage_error(
                        SpawnStage::Bootstrap,
                        std::io::Error::last_os_error(),
                    ));
                }
                #[cfg(target_os = "linux")]
                let memory = libc::rlimit {
                    rlim_cur: 256 * 1024 * 1024,
                    rlim_max: 256 * 1024 * 1024,
                };
                #[cfg(target_os = "macos")]
                let memory = mac_address_limit();
                let core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_AS, &memory) == -1 {
                    return Err(spawn_stage_error(
                        SpawnStage::MemoryLimit,
                        std::io::Error::last_os_error(),
                    ));
                }
                #[cfg(target_os = "macos")]
                {
                    let mut installed: libc::rlimit = std::mem::zeroed();
                    if libc::getrlimit(libc::RLIMIT_AS, &mut installed) == -1 {
                        return Err(spawn_stage_error(
                            SpawnStage::MemoryLimit,
                            std::io::Error::last_os_error(),
                        ));
                    }
                    if installed.rlim_cur != memory.rlim_cur
                        || installed.rlim_max != memory.rlim_max
                    {
                        return Err(encoded_spawn_error(
                            SpawnStage::MemoryLimit,
                            SPAWN_NATIVE_UNKNOWN,
                        ));
                    }
                }
                if libc::setrlimit(libc::RLIMIT_CORE, &core) == -1 {
                    return Err(spawn_stage_error(
                        SpawnStage::CoreLimit,
                        std::io::Error::last_os_error(),
                    ));
                }
                #[cfg(target_os = "linux")]
                {
                    // Execute the verified open inode, avoiding a path exchange
                    // between checksum and exec. No inherited environment is read.
                    let env = [std::ptr::null::<libc::c_char>()];
                    libc::fexecve(exec_fd, argv.as_ptr().cast(), env.as_ptr());
                    Err(spawn_stage_error(
                        SpawnStage::Exec,
                        std::io::Error::last_os_error(),
                    ))
                }
                #[cfg(target_os = "macos")]
                mac_exec.exec()
            });
        }
        super::deadline_check(startup_deadline)?;
        // pre_exec errors return through std's startup pipe after its forked
        // child has exited and been reaped. No Process owner is issued here.
        // This is an admission rejection, not an activated worker drain proof.
        // https://doc.rust-lang.org/src/std/sys/process/unix/unix.rs.html#137-150
        #[cfg(target_os = "macos")]
        let spawn_native_millis = monotonic_millis()?;
        let child = command.spawn().map_err(spawn_failure)?;
        let pid = child.id() as i32;
        drop(read);
        drop(write);
        let process = Self {
            child: Some(child),
            pid,
            reaped: false,
            reserved: true,
            reaped_code: None,
            owner_deadline,
            reservation: Some(reservation),
            #[cfg(target_os = "macos")]
            identity: None,
            #[cfg(target_os = "macos")]
            identity_uncertain: true,
            #[cfg(target_os = "macos")]
            resource_identity_uncertain: false,
            #[cfg(target_os = "macos")]
            resources: ResourceTracker::new(spawn_native_millis),
        };
        #[cfg(target_os = "macos")]
        let mut process = process;
        #[cfg(target_os = "macos")]
        {
            let info = match bsd_info(pid, true) {
                Ok(Some(info)) => info,
                Ok(None) => {
                    return Err(super::cleanup_failed_process(
                        process,
                        StdioError::new("native_identity"),
                    ));
                }
                Err(error) => return Err(super::cleanup_failed_process(process, error)),
            };
            let identity = MacIdentity::from_info(&info);
            if info.pid != pid as u32
                || info.pgid != pid as u32
                || info.uid != unsafe { libc::geteuid() }
                || info.ruid != unsafe { libc::getuid() }
            {
                return Err(super::cleanup_failed_process(
                    process,
                    StdioError::new("native_identity"),
                ));
            }
            process.identity = Some(identity);
            process.identity_uncertain = false;
            if let Err(error) = process.check_resources(startup_deadline, true) {
                return Err(super::cleanup_failed_process(process, error));
            }
        }
        if !matches!(same_file(&executable.file, &executable.path), Ok(true)) {
            return Err(super::cleanup_failed_process(
                process,
                StdioError::new("executable_changed"),
            ));
        }
        if let Err(error) = super::deadline_check(startup_deadline) {
            return Err(super::cleanup_failed_process(process, error));
        }
        Ok(process)
    }
    pub(super) fn id(&self) -> u64 {
        self.pid as u64
    }
    pub(super) fn owner_deadline(&self) -> Instant {
        self.owner_deadline
    }
    pub(super) fn reaped_exit_code(&self) -> Option<i32> {
        self.reaped_code
    }
    pub(super) fn exit_code(&mut self) -> Result<Option<i32>, StdioError> {
        if self.reaped {
            return Err(StdioError::new("native_reaped"));
        }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } == -1
        {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                self.reserved = false;
            }
            return Err(StdioError::new("native_observe"));
        }
        #[cfg(target_os = "linux")]
        let (pid, status) = unsafe { (info.si_pid(), info.si_status()) };
        #[cfg(target_os = "macos")]
        let (pid, status) = (info.si_pid, info.si_status);
        if pid == 0 {
            Ok(None)
        } else if info.si_code == libc::CLD_EXITED {
            Ok(Some(status))
        } else {
            // Keep signal termination distinct from a normal eight-bit exit
            // status; it must not look like an encoded helper stage.
            Ok(Some(-status))
        }
    }
    pub(super) fn scope_empty(&self, deadline: Instant) -> Result<bool, StdioError> {
        super::drain_deadline_check(deadline)?;
        if !self.reserved {
            return Err(StdioError::new("native_identity"));
        }
        #[cfg(target_os = "linux")]
        {
            Ok(linux_members(self.pid, deadline)? == 0)
        }
        #[cfg(target_os = "macos")]
        {
            let identity = self
                .identity
                .ok_or_else(|| StdioError::new("native_resource_identity"))?;
            verify_mac_identity(self.pid, identity, MacDeadline::Instant(deadline))?;
            Ok(mac_members(self.pid, identity.birth(), deadline)? == 0)
        }
    }
    #[cfg(not(target_os = "macos"))]
    pub(super) fn terminate(&mut self) -> Result<(), StdioError> {
        self.terminate_before(self.owner_deadline)
    }
    pub(super) fn terminate_before(&mut self, deadline: Instant) -> Result<(), StdioError> {
        #[cfg(target_os = "linux")]
        let _ = deadline;
        if self.reaped {
            return Ok(());
        }
        if !self.reserved {
            return Err(StdioError::new("native_identity"));
        }
        #[cfg(target_os = "macos")]
        {
            let result = self
                .identity
                .ok_or_else(|| StdioError::new("native_resource_identity"))
                .and_then(|identity| {
                    verify_mac_identity(self.pid, identity, MacDeadline::Instant(deadline))
                });
            let verified = match result {
                Ok(verified) => verified,
                Err(error) => {
                    // Keep the unreaped Child and reservation. An unknown native
                    // identity is not permission to signal a numeric replacement.
                    if error.code != "deadline" {
                        self.identity_uncertain = true;
                    }
                    return Err(error.with_resources(self.resource_evidence()));
                }
            };
            self.identity_uncertain = false;
            if self.resource_identity_uncertain {
                // A later explicit finite cleanup may retry the actual fixed
                // identity. Never permanently erase ownership on a timeout.
                let observation = self.check_resources_before(deadline, true);
                if self.identity_uncertain || self.resource_identity_uncertain {
                    return Err(observation.err().unwrap_or_else(|| {
                        StdioError::new("native_resource_identity")
                            .with_resources(self.resource_evidence())
                    }));
                }
                if let Err(error) = observation
                    && error.code == "deadline"
                {
                    return Err(error);
                }
            }
            let terminal_scope_empty = mac_terminal_scope_is_empty(&verified, || {
                super::deadline_check(deadline)?;
                let exited = self.exit_code()?;
                super::deadline_check(deadline)?;
                let empty = if exited.is_some() {
                    self.scope_empty(deadline)?
                } else {
                    false
                };
                super::deadline_check(deadline)?;
                Ok((exited, empty))
            })
            .map_err(|error| error.with_resources(self.resource_evidence()))?;
            if terminal_scope_empty {
                // Suppress only this unnecessary signal. Ownership, the two
                // later stable drain observations and the final reap remain.
                return Ok(());
            }
        }
        let signal_result = unsafe { libc::kill(-self.pid, libc::SIGKILL) };
        if signal_result == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                #[cfg(target_os = "macos")]
                if let Some(native_errno) = error.raw_os_error()
                    && native_errno == libc::EPERM
                {
                    let original = StdioError::io("native_terminate", error);
                    let identity = self.identity;
                    let pid = self.pid;
                    let owner_confirmed = self.reserved
                        && !self.reaped
                        && self.child.is_some()
                        && identity.is_some()
                        && !self.identity_uncertain
                        && !self.resource_identity_uncertain;
                    let mut failure = DarwinStdioSignalFailure {
                        signal_result,
                        native_errno,
                        postcheck: DarwinStdioSignalPostcheck::NotAttempted,
                    };
                    let terminal_scope = mac_signal_failure_terminal_scope(
                        &mut failure,
                        owner_confirmed,
                        || {
                            identity.is_some_and(|identity| {
                                identity.uid == unsafe { libc::geteuid() }
                                    && identity.ruid == unsafe { libc::getuid() }
                            })
                        },
                        || {
                            verify_mac_identity(
                                pid,
                                identity
                                    .ok_or_else(|| StdioError::new("native_resource_identity"))?,
                                MacDeadline::Instant(deadline),
                            )
                        },
                        || {
                            super::deadline_check(deadline)?;
                            let exited = self.exit_code()?;
                            super::deadline_check(deadline)?;
                            let empty = if exited.is_some() {
                                self.scope_empty(deadline)?
                            } else {
                                false
                            };
                            super::deadline_check(deadline)?;
                            Ok((exited, empty))
                        },
                        || super::deadline_check(deadline),
                    );
                    if failure.postcheck.requires_identity_uncertainty() {
                        self.identity_uncertain = true;
                    }
                    self.resources.evidence.0.parent_last_signal_failure = Some(failure);
                    if terminal_scope {
                        // The signal still failed. No further signal is needed;
                        // the original stable drain and reap remain required.
                        return Ok(());
                    }
                    return Err(original.with_resources(self.resource_evidence()));
                }
                return Err(StdioError::io("native_terminate", error));
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    pub(super) fn reap(&mut self) -> Result<Option<i32>, StdioError> {
        self.reap_before(self.owner_deadline)
    }
    pub(super) fn reap_before(&mut self, deadline: Instant) -> Result<Option<i32>, StdioError> {
        #[cfg(target_os = "linux")]
        let _ = deadline;
        if self.exit_code()?.is_none() {
            return Err(StdioError::new("native_reap"));
        }
        #[cfg(target_os = "macos")]
        {
            // A confirmed zombie is terminal identity evidence, not a zero
            // resource sample. Resource failures remain cached during reap.
            if Instant::now() < deadline {
                let _ = self.check_resources_before(deadline, true);
            }
            if !self.reserved || self.identity_uncertain || self.resource_identity_uncertain {
                return Err(StdioError::new("native_resource_identity")
                    .with_resources(self.resource_evidence()));
            }
        }
        let status = self
            .child
            .as_mut()
            .ok_or_else(|| StdioError::new("native_identity"))?
            .wait()
            .map_err(|_| {
                self.reserved = false;
                StdioError::new("native_reap")
            })?;
        self.reaped = true;
        self.reaped_code = status.code();
        self.reservation.take();
        Ok(status.code())
    }
    pub(super) fn drain_blocking(&mut self, deadline: Instant) -> Result<(), StdioError> {
        if self.reaped {
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        if Instant::now() < deadline {
            // A sampled threshold/query failure must not prevent the actual
            // owner from cancelling. Only uncertain identity disables signal.
            let _ = self.check_resources_before(deadline, true);
        }
        self.terminate_before(deadline)?;
        if Instant::now() >= deadline {
            return Err(StdioError::new("drain_uncertain"));
        }
        let mut empty = None;
        loop {
            #[cfg(target_os = "macos")]
            if Instant::now() < deadline {
                let _ = self.check_resources_before(deadline, false);
                if !self.reserved || self.identity_uncertain || self.resource_identity_uncertain {
                    return Err(StdioError::new("native_resource_identity")
                        .with_resources(self.resource_evidence()));
                }
            }
            if self.exit_code()?.is_some() && self.scope_empty(deadline)? {
                if empty.is_some_and(|t: Instant| t.elapsed() >= Duration::from_millis(10)) {
                    if Instant::now() >= deadline {
                        return Err(StdioError::new("drain_uncertain"));
                    }
                    self.reap_before(deadline)?;
                    if Instant::now() >= deadline {
                        let mut error = StdioError::new("drain_deadline");
                        error.drained = true;
                        return Err(error);
                    }
                    return Ok(());
                }
                empty.get_or_insert_with(Instant::now);
            } else {
                empty = None;
            }
            if Instant::now() >= deadline {
                return Err(StdioError::new("drain_uncertain"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if !self.reaped
            && let Err(error) = self.drain_blocking(self.owner_deadline)
            && !error.drained
        {
            let retained = Self {
                child: self.child.take(),
                pid: self.pid,
                reaped: false,
                reserved: self.reserved,
                reaped_code: self.reaped_code,
                owner_deadline: self.owner_deadline,
                reservation: self.reservation.take(),
                #[cfg(target_os = "macos")]
                identity: self.identity,
                #[cfg(target_os = "macos")]
                identity_uncertain: self.identity_uncertain,
                #[cfg(target_os = "macos")]
                resource_identity_uncertain: self.resource_identity_uncertain,
                #[cfg(target_os = "macos")]
                resources: self.resources.clone(),
            };
            self.reaped = true;
            super::retain_uncertain_process(retained);
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_members(group: i32, deadline: Instant) -> Result<usize, StdioError> {
    let mut members = 0;
    let mut leader = false;
    let mut count = 0;
    super::drain_deadline_check(deadline)?;
    for entry in std::fs::read_dir("/proc").map_err(|_| StdioError::new("native_observe"))? {
        super::drain_deadline_check(deadline)?;
        count += 1;
        if count > 100_000 {
            return Err(StdioError::new("native_observe_budget"));
        }
        let entry = entry.map_err(|_| StdioError::new("native_observe"))?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        let mut bytes = Vec::new();
        super::drain_deadline_check(deadline)?;
        match File::open(entry.path().join("stat"))
            .and_then(|f| f.take(8193).read_to_end(&mut bytes))
        {
            Ok(_) if bytes.len() <= 8192 => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            _ => return Err(StdioError::new("native_observe")),
        }
        super::drain_deadline_check(deadline)?;
        let end = bytes
            .iter()
            .rposition(|b| *b == b')')
            .ok_or_else(|| StdioError::new("native_identity"))?;
        let mut fields = bytes[end + 1..]
            .split(|b| b.is_ascii_whitespace())
            .filter(|b| !b.is_empty());
        let state = fields
            .next()
            .ok_or_else(|| StdioError::new("native_identity"))?;
        let _ppid = fields.next();
        let parse = |b: Option<&[u8]>| {
            b.and_then(|b| std::str::from_utf8(b).ok())
                .and_then(|s| s.parse::<i32>().ok())
                .ok_or_else(|| StdioError::new("native_identity"))
        };
        let pgrp = parse(fields.next())?;
        let session = parse(fields.next())?;
        if pid == group {
            if pgrp != group || session != group {
                return Err(StdioError::new("native_identity"));
            }
            leader = true;
        }
        let live = state != b"Z" && state != b"X";
        if session == group && pgrp != group && live {
            return Err(StdioError::new("native_scope_escape"));
        }
        if pgrp == group && live {
            members += 1;
        }
    }
    super::drain_deadline_check(deadline)?;
    if !leader {
        return Err(StdioError::new("native_identity"));
    }
    Ok(members)
}

// This is a separate Darwin policy. AS is a VM limit; RSS and physical
// footprint are independently sampled thresholds and may overshoot between
// observations. In particular, this does not claim the Linux AS guarantee.
#[cfg(target_os = "macos")]
const MAC_VM_LIMIT: u64 = 512 * 1024 * 1024 * 1024;
#[cfg(target_os = "macos")]
const MAC_PHYSICAL_THRESHOLD: u64 = 256 * 1024 * 1024;
#[cfg(target_os = "macos")]
const MAC_SAMPLE_TARGET_MILLIS: u64 = 100;
#[cfg(target_os = "macos")]
const MAC_MAX_GAP_MILLIS: u64 = 1000;
#[cfg(target_os = "macos")]
const MAC_SAMPLE_LIMIT: u64 = 1_000_000;
#[cfg(target_os = "macos")]
pub(super) const RESOURCE_ADMISSION_LENGTH: usize = 176;
#[cfg(target_os = "macos")]
const RESOURCE_ADMISSION_MAGIC: &[u8; 8] = b"MMMMRS01";
// Zero means no completed resource sample yet. Every other value is the
// actual elapsed nanoseconds from the shared worker/watchdog anchor, plus one.
#[cfg(target_os = "macos")]
static WORKER_RESOURCE_HEARTBEAT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(target_os = "macos")]
fn elapsed_nanos(anchor: Instant) -> Result<u64, StdioError> {
    Instant::now()
        .checked_duration_since(anchor)
        .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
        .ok_or_else(|| StdioError::new("native_resource_budget"))
}

#[cfg(target_os = "macos")]
fn publish_worker_resource_sample(anchor: Instant, completed: Instant) -> Result<(), StdioError> {
    // Publishing can itself be scheduled late. Keep the actual successful
    // sample's timestamp; a delayed store must never refresh stale evidence.
    let encoded = completed
        .checked_duration_since(anchor)
        .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
        .ok_or_else(|| StdioError::new("native_resource_budget"))?
        .checked_add(1)
        .ok_or_else(|| StdioError::new("native_resource_budget"))?;
    WORKER_RESOURCE_HEARTBEAT.store(encoded, std::sync::atomic::Ordering::Release);
    Ok(())
}

/// Called by the existing independent deadline watchdog: no native resource
/// query, lock, retry or new worker. Scheduler/native-call delays still mean
/// that this is delayed detection, not an exact one-second termination bound.
#[cfg(target_os = "macos")]
pub(super) fn check_worker_resource_gap(anchor: Instant) -> Result<(), StdioError> {
    let encoded = WORKER_RESOURCE_HEARTBEAT.load(std::sync::atomic::Ordering::Acquire);
    if encoded == 0 {
        return Ok(());
    }
    let result = check_worker_gap_at(encoded, elapsed_nanos(anchor)?);
    if result.is_err()
        && WORKER_RESOURCE_HEARTBEAT.load(std::sync::atomic::Ordering::Acquire) != encoded
    {
        // The watchdog itself may have been descheduled after the first load
        // while successful samples continued. Discard this stale decision;
        // one bounded recheck creates neither a retry loop nor a fresh sample.
        return Ok(());
    }
    result
}

#[cfg(target_os = "macos")]
fn check_worker_gap_at(encoded: u64, now: u64) -> Result<(), StdioError> {
    if encoded == 0 {
        return Ok(());
    }
    let last = encoded - 1;
    let allowed = MAC_MAX_GAP_MILLIS
        .checked_mul(1_000_000)
        .ok_or_else(|| StdioError::new("native_resource_budget"))?;
    let gap = now
        .checked_sub(last)
        .ok_or_else(|| StdioError::new("native_resource_watchdog_gap"))?;
    if gap > allowed {
        Err(StdioError::new("native_resource_watchdog_gap"))
    } else {
        Ok(())
    }
}

/// Actual public evidence contains no PID, path, inherited value or secret.
/// Parent polls and child admission samples have different coverage. The
/// child's later samples are enforced locally but are not transmitted here.
#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DarwinStdioResources(Box<DarwinStdioResourceFacts>);

#[cfg(target_os = "macos")]
impl std::ops::Deref for DarwinStdioResources {
    type Target = DarwinStdioResourceFacts;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DarwinStdioResourceFacts {
    pub policy: &'static str,
    pub vm_limit_bytes: u64,
    pub rss_threshold_bytes: u64,
    pub footprint_threshold_bytes: u64,
    pub worker_limit: u64,
    pub target_sample_interval_millis: u64,
    pub maximum_sample_gap_millis: u64,
    pub sampling_may_overshoot: bool,
    pub activation_memory_coverage_unknown: bool,
    pub activation_interval_millis: Option<u64>,
    pub parent_samples: u64,
    pub parent_peak_vm_bytes: u64,
    pub parent_peak_rss_bytes: u64,
    pub parent_peak_footprint_bytes: u64,
    pub parent_maximum_sample_gap_millis: u64,
    pub parent_elapsed_millis: u64,
    pub parent_sampling_is_poll_driven: bool,
    pub parent_confirmed_zombie_observations: u64,
    pub parent_exit_pending_observations: u64,
    pub parent_last_exit_observation: Option<mmmm_native_process::darwin::NativeResourceError>,
    pub parent_last_resource_failure: Option<&'static str>,
    pub parent_last_resource_error: Option<mmmm_native_process::darwin::NativeResourceError>,
    pub parent_terminal_identity_query_errno: Option<i32>,
    pub parent_last_signal_failure: Option<DarwinStdioSignalFailure>,
    pub child_admitted: bool,
    pub child_as_soft_bytes: Option<u64>,
    pub child_as_hard_bytes: Option<u64>,
    pub child_admission_samples: Option<u64>,
    pub child_admission_vm_bytes: Option<u64>,
    pub child_admission_rss_bytes: Option<u64>,
    pub child_admission_footprint_bytes: Option<u64>,
    pub child_admission_peak_vm_bytes: Option<u64>,
    pub child_admission_peak_rss_bytes: Option<u64>,
    pub child_admission_peak_footprint_bytes: Option<u64>,
    pub child_admission_maximum_sample_gap_millis: Option<u64>,
    pub child_admission_elapsed_millis: Option<u64>,
    pub child_samples_after_admission_unobserved: bool,
    pub child_watchdog_gap_detection_may_be_delayed: bool,
}

#[cfg(target_os = "macos")]
impl DarwinStdioResources {
    fn pending() -> Self {
        Self(Box::new(DarwinStdioResourceFacts {
            policy: "darwin-stdio-sampled-resources/1",
            vm_limit_bytes: MAC_VM_LIMIT,
            rss_threshold_bytes: MAC_PHYSICAL_THRESHOLD,
            footprint_threshold_bytes: MAC_PHYSICAL_THRESHOLD,
            worker_limit: 1,
            target_sample_interval_millis: MAC_SAMPLE_TARGET_MILLIS,
            maximum_sample_gap_millis: MAC_MAX_GAP_MILLIS,
            sampling_may_overshoot: true,
            activation_memory_coverage_unknown: true,
            activation_interval_millis: None,
            parent_samples: 0,
            parent_peak_vm_bytes: 0,
            parent_peak_rss_bytes: 0,
            parent_peak_footprint_bytes: 0,
            parent_maximum_sample_gap_millis: 0,
            parent_elapsed_millis: 0,
            parent_sampling_is_poll_driven: true,
            parent_confirmed_zombie_observations: 0,
            parent_exit_pending_observations: 0,
            parent_last_exit_observation: None,
            parent_last_resource_failure: None,
            parent_last_resource_error: None,
            parent_terminal_identity_query_errno: None,
            parent_last_signal_failure: None,
            child_admitted: false,
            child_as_soft_bytes: None,
            child_as_hard_bytes: None,
            child_admission_samples: None,
            child_admission_vm_bytes: None,
            child_admission_rss_bytes: None,
            child_admission_footprint_bytes: None,
            child_admission_peak_vm_bytes: None,
            child_admission_peak_rss_bytes: None,
            child_admission_peak_footprint_bytes: None,
            child_admission_maximum_sample_gap_millis: None,
            child_admission_elapsed_millis: None,
            child_samples_after_admission_unobserved: true,
            child_watchdog_gap_detection_may_be_delayed: true,
        }))
    }
}

/// Signal failure and its subsequent bounded observations are separate facts.
/// A confirmed terminal scope does not claim signal success or completed drain.
#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DarwinStdioSignalFailure {
    pub signal_result: i32,
    pub native_errno: i32,
    pub postcheck: DarwinStdioSignalPostcheck,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DarwinStdioSignalPostcheck {
    NotAttempted,
    Started,
    OwnerUnconfirmed,
    UidBeforeMismatch,
    IdentityNotTerminal {
        status: u32,
        exit_pending: bool,
        terminal_query_errno: Option<i32>,
    },
    ChildNotExited,
    ScopeNotEmpty,
    UidAfterMismatch,
    ConfirmedTerminalScope {
        exit_code: i32,
    },
    ObservationFailed {
        phase: &'static str,
        code: &'static str,
        native_code: Option<i32>,
        native_code_unknown: bool,
    },
}

#[cfg(target_os = "macos")]
impl DarwinStdioSignalPostcheck {
    fn requires_identity_uncertainty(&self) -> bool {
        match self {
            Self::UidBeforeMismatch | Self::UidAfterMismatch => true,
            Self::ObservationFailed { code, .. } => *code != "deadline",
            _ => false,
        }
    }
}

#[cfg(target_os = "macos")]
fn mac_address_limit() -> libc::rlimit {
    libc::rlimit {
        rlim_cur: MAC_VM_LIMIT,
        rlim_max: MAC_VM_LIMIT,
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct MacIdentity {
    start_sec: u64,
    start_usec: u64,
    uid: u32,
    ruid: u32,
    svuid: u32,
}
#[cfg(target_os = "macos")]
impl MacIdentity {
    fn from_info(info: &BsdInfo) -> Self {
        Self {
            start_sec: info.start_sec,
            start_usec: info.start_usec,
            uid: info.uid,
            ruid: info.ruid,
            svuid: info.svuid,
        }
    }
    fn birth(self) -> (u64, u64) {
        (self.start_sec, self.start_usec)
    }
    fn matches(self, pid: i32, info: &BsdInfo) -> bool {
        info.pid == pid as u32
            && info.pgid == pid as u32
            && self.birth() == (info.start_sec, info.start_usec)
            && self.uid == info.uid
            && self.ruid == info.ruid
            && self.svuid == info.svuid
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
enum MacDeadline {
    Instant(Instant),
    Native(u64),
}
#[cfg(target_os = "macos")]
impl MacDeadline {
    fn check(self) -> Result<(), StdioError> {
        match self {
            Self::Instant(deadline) => super::deadline_check(deadline),
            Self::Native(deadline) => {
                if monotonic_millis()? >= deadline {
                    Err(StdioError::new("deadline"))
                } else {
                    Ok(())
                }
            }
        }
    }
    fn instant(self) -> Result<Instant, StdioError> {
        self.check()?;
        match self {
            Self::Instant(deadline) => Ok(deadline),
            Self::Native(deadline) => {
                // Anchor before reading the native clock. Scheduling between
                // the clocks can shorten this derived bound, never extend it.
                let anchor = Instant::now();
                let remaining = deadline
                    .checked_sub(monotonic_millis()?)
                    .and_then(|value| value.checked_sub(MONOTONIC_MARGIN_MILLIS))
                    .filter(|value| *value > 0)
                    .ok_or_else(|| StdioError::new("deadline"))?;
                anchor
                    .checked_add(Duration::from_millis(remaining))
                    .ok_or_else(|| StdioError::new("deadline"))
            }
        }
    }
}

#[cfg(target_os = "macos")]
struct VerifiedMacIdentity {
    status: u32,
    terminal_query_errno: Option<i32>,
    exit_pending: bool,
}

#[cfg(target_os = "macos")]
fn mac_terminal_scope_is_empty(
    verified: &VerifiedMacIdentity,
    observe: impl FnOnce() -> Result<(Option<i32>, bool), StdioError>,
) -> Result<bool, StdioError> {
    if verified.status != 5 || verified.exit_pending {
        return Ok(false);
    }
    let (exited, empty) = observe()?;
    // A confirmed same-identity zombie alone cannot account for descendants.
    // Both facts must come from fresh observations under the original bound.
    Ok(exited.is_some() && empty)
}

#[cfg(target_os = "macos")]
fn mac_signal_failure_terminal_scope(
    failure: &mut DarwinStdioSignalFailure,
    owner_confirmed: bool,
    mut current_uid_matches: impl FnMut() -> bool,
    verify_identity: impl FnOnce() -> Result<VerifiedMacIdentity, StdioError>,
    observe_scope: impl FnOnce() -> Result<(Option<i32>, bool), StdioError>,
    mut checkpoint: impl FnMut() -> Result<(), StdioError>,
) -> bool {
    if failure.signal_result != -1 || failure.native_errno != libc::EPERM {
        return false;
    }
    failure.postcheck = DarwinStdioSignalPostcheck::Started;
    let mut phase = "initial_deadline";
    let result = (|| {
        checkpoint()?;
        if !owner_confirmed {
            failure.postcheck = DarwinStdioSignalPostcheck::OwnerUnconfirmed;
            return Ok(false);
        }
        phase = "uid_before";
        checkpoint()?;
        if !current_uid_matches() {
            failure.postcheck = DarwinStdioSignalPostcheck::UidBeforeMismatch;
            return Ok(false);
        }
        phase = "identity";
        checkpoint()?;
        let verified = verify_identity()?;
        if verified.status != 5 || verified.exit_pending {
            failure.postcheck = DarwinStdioSignalPostcheck::IdentityNotTerminal {
                status: verified.status,
                exit_pending: verified.exit_pending,
                terminal_query_errno: verified.terminal_query_errno,
            };
            return Ok(false);
        }
        phase = "terminal_scope";
        checkpoint()?;
        let mut observed = None;
        let terminal_scope = mac_terminal_scope_is_empty(&verified, || {
            let actual = observe_scope()?;
            observed = Some(actual);
            Ok(actual)
        })?;
        let exit_code = match observed {
            Some((Some(exit_code), true)) if terminal_scope => exit_code,
            Some((None, _)) => {
                failure.postcheck = DarwinStdioSignalPostcheck::ChildNotExited;
                return Ok(false);
            }
            Some((Some(_), false)) => {
                failure.postcheck = DarwinStdioSignalPostcheck::ScopeNotEmpty;
                return Ok(false);
            }
            _ => return Err(StdioError::new("native_resource_identity")),
        };
        phase = "uid_after";
        checkpoint()?;
        if !current_uid_matches() {
            failure.postcheck = DarwinStdioSignalPostcheck::UidAfterMismatch;
            return Ok(false);
        }
        phase = "final_deadline";
        checkpoint()?;
        failure.postcheck = DarwinStdioSignalPostcheck::ConfirmedTerminalScope { exit_code };
        Ok(true)
    })();
    match result {
        Ok(terminal_scope) => terminal_scope,
        Err(error) => {
            failure.postcheck = DarwinStdioSignalPostcheck::ObservationFailed {
                phase,
                code: error.code,
                native_code: error.native_code,
                native_code_unknown: error.native_code_unknown,
            };
            false
        }
    }
}

#[cfg(target_os = "macos")]
fn verify_mac_identity(
    pid: i32,
    identity: MacIdentity,
    deadline: MacDeadline,
) -> Result<VerifiedMacIdentity, StdioError> {
    deadline.check()?;
    let before = bsd_info(pid, true)
        .map_err(resource_identity_query_error)?
        .ok_or_else(|| StdioError::new("native_resource_identity"))?;
    if !identity.matches(pid, &before) {
        return Err(StdioError::new("native_resource_identity"));
    }
    if before.status == 5 {
        return verify_mac_zombie(pid, identity, deadline, None);
    }
    deadline.check()?;
    let session = unsafe { libc::getsid(pid) };
    if session == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return verify_mac_zombie(pid, identity, deadline, Some(libc::ESRCH));
        }
        return Err(StdioError::io("native_resource_observation", error));
    }
    if session != pid {
        return Err(StdioError::new("native_resource_identity"));
    }
    deadline.check()?;
    let group = unsafe { libc::getpgid(pid) };
    if group == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return verify_mac_zombie(pid, identity, deadline, Some(libc::ESRCH));
        }
        return Err(StdioError::io("native_resource_observation", error));
    }
    if group != pid {
        return Err(StdioError::new("native_resource_identity"));
    }
    deadline.check()?;
    let after = bsd_info(pid, true)
        .map_err(resource_identity_query_error)?
        .ok_or_else(|| StdioError::new("native_resource_identity"))?;
    deadline.check()?;
    if !identity.matches(pid, &after) {
        return Err(StdioError::new("native_resource_identity"));
    }
    if after.status == 5 {
        return verify_mac_zombie(pid, identity, deadline, None);
    }
    Ok(VerifiedMacIdentity {
        status: after.status,
        terminal_query_errno: None,
        exit_pending: false,
    })
}

#[cfg(target_os = "macos")]
fn verify_mac_zombie(
    pid: i32,
    identity: MacIdentity,
    deadline: MacDeadline,
    terminal_query_errno: Option<i32>,
) -> Result<VerifiedMacIdentity, StdioError> {
    // XNU removes a zombie from proc_find(), so getsid/getpgid return ESRCH.
    // This private producer already performed setsid() in this exact child.
    // Keep it unreaped and require two actual matching BSD zombie identities;
    // a missing or reused PID never becomes terminal evidence.
    // https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/kern/kern_prot.c
    deadline.check()?;
    let before = bsd_info(pid, true)
        .map_err(resource_identity_query_error)?
        .ok_or_else(|| StdioError::new("native_resource_identity"))?;
    deadline.check()?;
    let after = bsd_info(pid, true)
        .map_err(resource_identity_query_error)?
        .ok_or_else(|| StdioError::new("native_resource_identity"))?;
    deadline.check()?;
    if !identity.matches(pid, &before) || !identity.matches(pid, &after) {
        return Err(StdioError::new("native_resource_identity"));
    }
    let terminal = before.status == 5 && after.status == 5;
    if !terminal && (before.status == 5 || terminal_query_errno != Some(libc::ESRCH)) {
        return Err(StdioError::new("native_resource_identity"));
    }
    Ok(VerifiedMacIdentity {
        status: after.status,
        terminal_query_errno,
        // P_REF_DEAD precedes SZOMB in XNU. A fixed BSD identity can be
        // exiting while normal PID lookup already returns ESRCH. Preserve
        // that pending observation; neither resource zero nor drain success.
        exit_pending: !terminal,
    })
}

#[cfg(target_os = "macos")]
fn resource_identity_query_error(mut error: StdioError) -> StdioError {
    error.code = "native_resource_observation";
    error
}

#[cfg(target_os = "macos")]
enum MacResourceObservation {
    Live(mmmm_native_process::darwin::MemoryObservation, Option<i32>),
    Zombie(
        Option<mmmm_native_process::darwin::NativeResourceError>,
        Option<i32>,
    ),
    Pending {
        sample: Option<mmmm_native_process::darwin::MemoryObservation>,
        error: Option<mmmm_native_process::darwin::NativeResourceError>,
        terminal_errno: Option<i32>,
    },
}

#[cfg(target_os = "macos")]
impl MacResourceObservation {
    fn sample(&self) -> Option<mmmm_native_process::darwin::MemoryObservation> {
        match self {
            Self::Live(sample, _) => Some(*sample),
            Self::Pending { sample, .. } => *sample,
            Self::Zombie(..) => None,
        }
    }
    fn terminal_errno(&self) -> Option<i32> {
        match self {
            Self::Live(_, number) | Self::Zombie(_, number) => *number,
            Self::Pending { terminal_errno, .. } => *terminal_errno,
        }
    }
}

#[cfg(target_os = "macos")]
struct MacResourceFailure {
    error: StdioError,
    identity_uncertain: bool,
}

#[cfg(target_os = "macos")]
fn observe_mac_resources(
    pid: i32,
    identity: MacIdentity,
    deadline: MacDeadline,
) -> Result<MacResourceObservation, MacResourceFailure> {
    use mmmm_native_process::darwin::{NativeResourceFailure, observe_memory};
    let mut identity_confirmed = false;
    let result = (|| -> Result<MacResourceObservation, StdioError> {
        let before = verify_mac_identity(pid, identity, deadline)?;
        let members =
            mac_members(pid, identity.birth(), deadline.instant()?).map_err(|error| match error
                .code
            {
                "native_observe" => resource_identity_query_error(error),
                _ => error,
            })?;
        deadline.check()?;
        let observation = if before.status == 5 || before.exit_pending {
            None
        } else {
            Some(observe_memory(pid))
        };
        let after = deadline
            .check()
            .and_then(|()| verify_mac_identity(pid, identity, deadline))
            .map_err(|error| match &observation {
                Some(Err(source)) => error.with_resource_source(*source),
                _ => error,
            })?;
        identity_confirmed = true;
        let terminal_errno = after.terminal_query_errno.or(before.terminal_query_errno);
        if members > 1 || (before.status == 5 && members != 0) {
            return Err(StdioError::new("native_resource_budget"));
        }
        if before.exit_pending || after.exit_pending {
            let (sample, error) = match observation {
                Some(Ok(sample)) => (Some(sample), None),
                Some(Err(error)) => (None, Some(error)),
                None => (None, None),
            };
            return Ok(MacResourceObservation::Pending {
                sample,
                error,
                terminal_errno,
            });
        }
        match observation {
            Some(Ok(sample)) => Ok(MacResourceObservation::Live(sample, terminal_errno)),
            Some(Err(error))
                if error.failure == NativeResourceFailure::Exited && after.status == 5 =>
            {
                Ok(MacResourceObservation::Zombie(Some(error), terminal_errno))
            }
            Some(Err(error)) => {
                Err(StdioError::new("native_resource_observation").with_resource_source(error))
            }
            None if after.status == 5 => Ok(MacResourceObservation::Zombie(None, terminal_errno)),
            None => Err(StdioError::new("native_resource_identity")),
        }
    })();
    result.map_err(|error| MacResourceFailure {
        identity_uncertain: !identity_confirmed && error.code != "deadline",
        error,
    })
}

#[cfg(target_os = "macos")]
#[derive(Clone)]
struct ResourceSamples {
    first: Instant,
    last: Instant,
    first_native_millis: u64,
    actual: mmmm_native_process::darwin::MemoryObservation,
    peak_vm: u64,
    peak_rss: u64,
    peak_footprint: u64,
    samples: u64,
    maximum_gap: Duration,
}
#[cfg(target_os = "macos")]
impl ResourceSamples {
    fn first(actual: mmmm_native_process::darwin::MemoryObservation) -> Result<Self, StdioError> {
        let first_native_millis = monotonic_millis()?;
        let now = Instant::now();
        Ok(Self {
            first: now,
            last: now,
            first_native_millis,
            actual,
            peak_vm: actual.adjusted_vm,
            peak_rss: actual.rss,
            peak_footprint: actual.footprint,
            samples: 1,
            maximum_gap: Duration::ZERO,
        })
    }
    fn check_gap(&self) -> Result<(), StdioError> {
        if self.last.elapsed() > Duration::from_millis(MAC_MAX_GAP_MILLIS) {
            Err(StdioError::new("native_resource_gap"))
        } else {
            Ok(())
        }
    }
    fn push(
        &mut self,
        actual: mmmm_native_process::darwin::MemoryObservation,
        enforce_gap: bool,
    ) -> Result<(), StdioError> {
        if self.actual.start_abstime != actual.start_abstime {
            return Err(StdioError::new("native_resource_identity"));
        }
        let now = Instant::now();
        let gap = now.duration_since(self.last);
        self.maximum_gap = self.maximum_gap.max(gap);
        self.last = now;
        self.actual = actual;
        self.peak_vm = self.peak_vm.max(actual.adjusted_vm);
        self.peak_rss = self.peak_rss.max(actual.rss);
        self.peak_footprint = self.peak_footprint.max(actual.footprint);
        self.samples = self
            .samples
            .checked_add(1)
            .filter(|samples| *samples <= MAC_SAMPLE_LIMIT)
            .ok_or_else(|| StdioError::new("native_resource_budget"))?;
        // Preserve the actual sample and peak before returning its failure.
        // A poll-driven parent gap is evidence, not child sampler coverage.
        check_memory_thresholds(actual)?;
        if enforce_gap && gap > Duration::from_millis(MAC_MAX_GAP_MILLIS) {
            return Err(StdioError::new("native_resource_gap"));
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(target_os = "macos")]
fn check_memory_thresholds(
    observation: mmmm_native_process::darwin::MemoryObservation,
) -> Result<(), StdioError> {
    if observation.start_abstime == 0
        || observation.adjusted_vm > MAC_VM_LIMIT
        || observation.rss > MAC_PHYSICAL_THRESHOLD
        || observation.footprint > MAC_PHYSICAL_THRESHOLD
    {
        Err(StdioError::new("native_resource_budget"))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone)]
struct ResourceTracker {
    spawn_native_millis: u64,
    samples: Option<ResourceSamples>,
    evidence: DarwinStdioResources,
    state: ResourceState,
    pending_error: Option<mmmm_native_process::darwin::NativeResourceError>,
}
#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
enum ResourceState {
    Unobserved,
    Live,
    Pending,
    Zombie,
}
#[cfg(target_os = "macos")]
impl ResourceTracker {
    fn new(spawn_native_millis: u64) -> Self {
        Self {
            spawn_native_millis,
            samples: None,
            evidence: DarwinStdioResources::pending(),
            state: ResourceState::Unobserved,
            pending_error: None,
        }
    }
    fn evidence(&self) -> DarwinStdioResources {
        let mut evidence = self.evidence.clone();
        if let Some(samples) = &self.samples {
            evidence.0.parent_samples = samples.samples;
            evidence.0.parent_peak_vm_bytes = samples.peak_vm;
            evidence.0.parent_peak_rss_bytes = samples.peak_rss;
            evidence.0.parent_peak_footprint_bytes = samples.peak_footprint;
            evidence.0.parent_maximum_sample_gap_millis = millis(samples.maximum_gap);
            evidence.0.parent_elapsed_millis = millis(samples.last.duration_since(samples.first));
        }
        evidence
    }
    fn push(
        &mut self,
        actual: mmmm_native_process::darwin::MemoryObservation,
    ) -> Result<(), StdioError> {
        match &mut self.samples {
            Some(samples) => samples.push(actual, false),
            None => {
                self.samples = Some(ResourceSamples::first(actual)?);
                check_memory_thresholds(actual)
            }
        }
    }
}

#[cfg(target_os = "macos")]
impl Process {
    pub(super) fn resource_evidence(&self) -> DarwinStdioResources {
        self.resources.evidence()
    }
    pub(super) fn check_resources(
        &mut self,
        deadline: Instant,
        force: bool,
    ) -> Result<(), StdioError> {
        let deadline = deadline.min(self.owner_deadline);
        self.check_resources_before(deadline, force)?;
        if matches!(
            self.resources.state,
            ResourceState::Pending | ResourceState::Zombie
        ) {
            super::deadline_check(deadline)?;
            let exited = self.exit_code()?;
            super::deadline_check(deadline)?;
            let mut error = match exited {
                Some(status) => super::worker_exit_error(status),
                None => StdioError::new("native_resource_observation"),
            };
            if exited.is_none()
                && let Some(source) = self.resources.pending_error
            {
                error = error.with_resource_source(source);
            }
            return Err(error.with_resources(self.resource_evidence()));
        }
        Ok(())
    }
    fn check_resources_before(&mut self, deadline: Instant, force: bool) -> Result<(), StdioError> {
        let result = (|| {
            super::deadline_check(deadline)?;
            if !self.reserved || self.reaped {
                return Err(StdioError::new("native_resource_identity"));
            }
            if !force
                && self.resources.samples.as_ref().is_some_and(|sample| {
                    sample.last.elapsed() < Duration::from_millis(MAC_SAMPLE_TARGET_MILLIS)
                })
            {
                return Ok(());
            }
            let identity = self
                .identity
                .ok_or_else(|| StdioError::new("native_resource_identity"))?;
            let observed =
                match observe_mac_resources(self.pid, identity, MacDeadline::Instant(deadline)) {
                    Ok(observed) => observed,
                    Err(failure) => {
                        self.identity_uncertain = failure.identity_uncertain;
                        return Err(failure.error);
                    }
                };
            let actual_sample = observed.sample();
            if let Some(actual) = actual_sample
                && self
                    .resources
                    .samples
                    .as_ref()
                    .is_some_and(|samples| samples.actual.start_abstime != actual.start_abstime)
            {
                self.resource_identity_uncertain = true;
                return Err(StdioError::new("native_resource_identity"));
            }
            self.identity_uncertain = false;
            if actual_sample.is_some() {
                self.resource_identity_uncertain = false;
            }
            if let Some(number) = observed.terminal_errno() {
                self.resources
                    .evidence
                    .0
                    .parent_terminal_identity_query_errno = Some(number);
            }
            match observed {
                MacResourceObservation::Live(actual, _) => {
                    self.resources.state = ResourceState::Live;
                    self.resources.pending_error = None;
                    self.resources.push(actual)?;
                }
                MacResourceObservation::Zombie(error, _) => {
                    self.resources.state = ResourceState::Zombie;
                    self.resources.pending_error = error;
                    self.resources
                        .evidence
                        .0
                        .parent_confirmed_zombie_observations = self
                        .resources
                        .evidence
                        .parent_confirmed_zombie_observations
                        .saturating_add(1);
                    if error.is_some() {
                        self.resources.evidence.0.parent_last_exit_observation = error;
                    }
                }
                MacResourceObservation::Pending { sample, error, .. } => {
                    self.resources.state = ResourceState::Pending;
                    self.resources.pending_error = error;
                    self.resources.evidence.0.parent_exit_pending_observations = self
                        .resources
                        .evidence
                        .parent_exit_pending_observations
                        .saturating_add(1);
                    if let Some(error) = error {
                        self.resources.evidence.0.parent_last_resource_failure =
                            Some("native_resource_observation");
                        self.resources.evidence.0.parent_last_resource_error = Some(error);
                    }
                    if let Some(actual) = sample {
                        self.resources.push(actual)?;
                    }
                }
            }
            super::deadline_check(deadline)
        })();
        result.map_err(|error| {
            self.resources.evidence.0.parent_last_resource_failure = Some(error.code);
            if error.resource_source.is_some() {
                self.resources.evidence.0.parent_last_resource_error = error.resource_source;
            }
            if error.code == "native_resource_identity" || error.code == "native_identity" {
                self.identity_uncertain = true;
            }
            error.with_resources(self.resource_evidence())
        })
    }
    pub(super) fn admit_worker_resources(
        &mut self,
        receipt: &[u8],
        deadline: Instant,
    ) -> Result<(), StdioError> {
        let result = (|| {
            self.check_resources(deadline, true)?;
            if receipt.len() != RESOURCE_ADMISSION_LENGTH
                || &receipt[..8] != RESOURCE_ADMISSION_MAGIC
                || self.resources.evidence.child_admitted
            {
                return Err(StdioError::new("native_resource_admission"));
            }
            let mut fields = [0u64; 21];
            for (field, bytes) in fields.iter_mut().zip(receipt[8..].chunks_exact(8)) {
                *field = u64::from_be_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| StdioError::new("native_resource_admission"))?,
                );
            }
            let now = monotonic_millis()?;
            let parent_start = self
                .resources
                .samples
                .as_ref()
                .map(|samples| samples.actual.start_abstime);
            if fields[..10]
                != [
                    1,
                    RESOURCE_ADMISSION_LENGTH as u64,
                    MAC_VM_LIMIT,
                    MAC_PHYSICAL_THRESHOLD,
                    MAC_PHYSICAL_THRESHOLD,
                    MAC_SAMPLE_TARGET_MILLIS,
                    MAC_MAX_GAP_MILLIS,
                    1,
                    MAC_VM_LIMIT,
                    MAC_VM_LIMIT,
                ]
                || parent_start != Some(fields[13])
                || !(1..=MAC_SAMPLE_LIMIT).contains(&fields[14])
                || fields[15] > MAC_MAX_GAP_MILLIS
                || fields[15] > fields[16]
                || fields[20] < self.resources.spawn_native_millis
                || fields[20] > now
                || fields[16] > now - fields[20]
                || fields[10] > fields[17]
                || fields[11] > fields[18]
                || fields[12] > fields[19]
                || fields[17] > MAC_VM_LIMIT
                || fields[18] > MAC_PHYSICAL_THRESHOLD
                || fields[19] > MAC_PHYSICAL_THRESHOLD
            {
                return Err(StdioError::new("native_resource_admission"));
            }
            self.check_resources(deadline, true)?;
            if self
                .resources
                .samples
                .as_ref()
                .is_none_or(|samples| samples.actual.start_abstime != fields[13])
            {
                return Err(StdioError::new("native_resource_admission"));
            }
            let evidence = &mut *self.resources.evidence.0;
            evidence.activation_interval_millis =
                Some(fields[20] - self.resources.spawn_native_millis);
            evidence.child_as_soft_bytes = Some(fields[8]);
            evidence.child_as_hard_bytes = Some(fields[9]);
            evidence.child_admission_vm_bytes = Some(fields[10]);
            evidence.child_admission_rss_bytes = Some(fields[11]);
            evidence.child_admission_footprint_bytes = Some(fields[12]);
            evidence.child_admission_samples = Some(fields[14]);
            evidence.child_admission_maximum_sample_gap_millis = Some(fields[15]);
            evidence.child_admission_elapsed_millis = Some(fields[16]);
            evidence.child_admission_peak_vm_bytes = Some(fields[17]);
            evidence.child_admission_peak_rss_bytes = Some(fields[18]);
            evidence.child_admission_peak_footprint_bytes = Some(fields[19]);
            evidence.child_admitted = true;
            Ok(())
        })();
        result.map_err(|error| {
            if error.code == "native_resource_identity" {
                self.identity_uncertain = true;
            }
            self.resources.evidence.0.parent_last_resource_failure = Some(error.code);
            error.with_resources(self.resource_evidence())
        })
    }
}

/// The sampler never reaps, signals a numeric PID, or releases parent-owned
/// process reservations. A failure exits this same worker; its independent
/// original watchdog and the parent's original owner/drain remain in force.
#[cfg(target_os = "macos")]
pub(super) struct WorkerResources {
    samples: std::sync::Arc<std::sync::Mutex<ResourceSamples>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    native_deadline: u64,
    as_soft: u64,
    as_hard: u64,
    anchor: Instant,
}
#[cfg(target_os = "macos")]
pub(super) fn worker_resources(
    native_deadline: u64,
    anchor: Instant,
) -> Result<WorkerResources, StdioError> {
    use std::sync::{Arc, Mutex, atomic::AtomicBool};
    let deadline = MacDeadline::Native(native_deadline);
    deadline.check()?;
    let requested = mac_address_limit();
    if unsafe { libc::setrlimit(libc::RLIMIT_AS, &requested) } == -1 {
        return Err(StdioError::io(
            "native_resource_budget",
            std::io::Error::last_os_error(),
        ));
    }
    let mut installed: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut installed) } == -1 {
        return Err(StdioError::io(
            "native_resource_admission",
            std::io::Error::last_os_error(),
        ));
    }
    if installed.rlim_cur != requested.rlim_cur || installed.rlim_max != requested.rlim_max {
        return Err(StdioError::new("native_resource_admission"));
    }
    deadline.check()?;
    let pid = unsafe { libc::getpid() };
    let info = bsd_info(pid, true)?.ok_or_else(|| StdioError::new("native_resource_identity"))?;
    if info.uid != unsafe { libc::geteuid() } || info.ruid != unsafe { libc::getuid() } {
        return Err(StdioError::new("native_resource_identity"));
    }
    let identity = MacIdentity::from_info(&info);
    let MacResourceObservation::Live(initial, _) =
        observe_mac_resources(pid, identity, deadline).map_err(|failure| failure.error)?
    else {
        return Err(StdioError::new("native_resource_identity"));
    };
    let initial_samples = ResourceSamples::first(initial)?;
    let initial_completed = initial_samples.last;
    let samples = Arc::new(Mutex::new(initial_samples));
    check_memory_thresholds(initial)?;
    deadline.check()?;
    publish_worker_resource_sample(anchor, initial_completed)?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_samples = Arc::clone(&samples);
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::Builder::new()
        .name("mmmm-stdio-resources".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            use std::sync::atomic::Ordering;
            let run = || -> Result<(), StdioError> {
                while !thread_stop.load(Ordering::Acquire) {
                    deadline.check()?;
                    {
                        let samples = thread_samples
                            .lock()
                            .map_err(|_| StdioError::new("native_resource_thread"))?;
                        samples.check_gap()?;
                    }
                    let observation = observe_mac_resources(pid, identity, deadline)
                        .map_err(|failure| failure.error)?;
                    let completed = {
                        let mut samples = thread_samples
                            .lock()
                            .map_err(|_| StdioError::new("native_resource_thread"))?;
                        let MacResourceObservation::Live(observation, _) = observation else {
                            return Err(StdioError::new("native_resource_identity"));
                        };
                        samples.push(observation, true)?;
                        samples.last
                    };
                    deadline.check()?;
                    publish_worker_resource_sample(anchor, completed)?;
                    let remaining = native_deadline
                        .checked_sub(monotonic_millis()?)
                        .filter(|remaining| *remaining > 0)
                        .ok_or_else(|| StdioError::new("deadline"))?;
                    std::thread::park_timeout(Duration::from_millis(
                        remaining.min(MAC_SAMPLE_TARGET_MILLIS),
                    ));
                }
                Ok(())
            };
            if let Err(error) = run() {
                // Fixed status encoding carries the closed stage. Later child
                // native details are not transmitted by the admission receipt.
                unsafe { libc::_exit(super::worker_failure_exit(&error)) };
            }
        })
        .map_err(|_| StdioError::new("native_resource_thread"))?;
    Ok(WorkerResources {
        samples,
        stop,
        thread: Some(thread),
        native_deadline,
        as_soft: installed.rlim_cur,
        as_hard: installed.rlim_max,
        anchor,
    })
}

#[cfg(target_os = "macos")]
impl WorkerResources {
    pub(super) fn admission_receipt(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, StdioError> {
        MacDeadline::Native(self.native_deadline).check()?;
        check_worker_resource_gap(self.anchor)?;
        let samples = self
            .samples
            .lock()
            .map_err(|_| StdioError::new("native_resource_thread"))?;
        samples.check_gap()?;
        let values = [
            1,
            RESOURCE_ADMISSION_LENGTH as u64,
            MAC_VM_LIMIT,
            MAC_PHYSICAL_THRESHOLD,
            MAC_PHYSICAL_THRESHOLD,
            MAC_SAMPLE_TARGET_MILLIS,
            MAC_MAX_GAP_MILLIS,
            1,
            self.as_soft,
            self.as_hard,
            samples.actual.adjusted_vm,
            samples.actual.rss,
            samples.actual.footprint,
            samples.actual.start_abstime,
            samples.samples,
            millis(samples.maximum_gap),
            millis(samples.last.duration_since(samples.first)),
            samples.peak_vm,
            samples.peak_rss,
            samples.peak_footprint,
            samples.first_native_millis,
        ];
        let mut receipt = zeroize::Zeroizing::new(Vec::with_capacity(RESOURCE_ADMISSION_LENGTH));
        receipt.extend_from_slice(RESOURCE_ADMISSION_MAGIC);
        for value in values {
            receipt.extend_from_slice(&value.to_be_bytes());
        }
        MacDeadline::Native(self.native_deadline).check()?;
        Ok(receipt)
    }
}

#[cfg(target_os = "macos")]
impl Drop for WorkerResources {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            if thread.is_finished() {
                let _ = thread.join();
            }
            // Otherwise this handle detaches without a new wait or deadline.
            // worker_entry_exit ends the whole process, and only the actual
            // outer process drain proves that all its threads have stopped.
        }
    }
}

// ABI from Apple's public proc_info.h; PROC_PIDTBSDINFO=3, SZOMB=5.
#[cfg(target_os = "macos")]
#[repr(C)]
struct BsdInfo {
    flags: u32,
    status: u32,
    xstatus: u32,
    pid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    ruid: u32,
    rgid: u32,
    svuid: u32,
    svgid: u32,
    rfu: u32,
    comm: [u8; 16],
    name: [u8; 32],
    nfiles: u32,
    pgid: u32,
    jobc: u32,
    tdev: u32,
    tpgid: u32,
    nice: i32,
    start_sec: u64,
    start_usec: u64,
}
#[cfg(target_os = "macos")]
fn bsd_info(pid: i32, zombie: bool) -> Result<Option<BsdInfo>, StdioError> {
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut std::ffi::c_void,
            bytes: i32,
        ) -> i32;
    }
    let mut info: BsdInfo = unsafe { std::mem::zeroed() };
    let (bytes, number) = unsafe {
        *libc::__error() = 0;
        let bytes = proc_pidinfo(
            pid,
            3,
            u64::from(zombie),
            (&mut info as *mut BsdInfo).cast(),
            std::mem::size_of::<BsdInfo>() as i32,
        );
        (bytes, *libc::__error())
    };
    if bytes == 0 && number == libc::ESRCH {
        return Ok(None);
    }
    if bytes as usize != std::mem::size_of::<BsdInfo>() {
        if bytes <= 0 {
            return Err(StdioError::io(
                "native_observe",
                std::io::Error::from_raw_os_error(number),
            ));
        }
        return Err(StdioError::new("native_observe"));
    }
    Ok(Some(info))
}
#[cfg(target_os = "macos")]
fn mac_members(group: i32, identity: (u64, u64), deadline: Instant) -> Result<usize, StdioError> {
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_listpids(
            kind: u32,
            typeinfo: u32,
            buffer: *mut std::ffi::c_void,
            bytes: i32,
        ) -> i32;
    }
    let mut capacity = 1024;
    let pids = loop {
        super::drain_deadline_check(deadline)?;
        let mut pids = vec![0i32; capacity];
        let n = unsafe { proc_listpids(1, 0, pids.as_mut_ptr().cast(), (capacity * 4) as i32) };
        super::drain_deadline_check(deadline)?;
        if n <= 0 || n % 4 != 0 {
            return Err(StdioError::new("native_observe"));
        }
        if n as usize >= capacity * 4 {
            if capacity >= 100_000 {
                return Err(StdioError::new("native_observe_budget"));
            }
            capacity = (capacity * 2).min(100_000);
            continue;
        }
        pids.truncate(n as usize / 4);
        break pids;
    };
    let mut count = 0;
    let mut leader = false;
    for pid in pids.into_iter().filter(|p| *p > 0) {
        super::drain_deadline_check(deadline)?;
        if pid == group {
            let before = bsd_info(pid, true)?.ok_or_else(|| StdioError::new("native_identity"))?;
            super::drain_deadline_check(deadline)?;
            let after = bsd_info(pid, true)?.ok_or_else(|| StdioError::new("native_identity"))?;
            super::drain_deadline_check(deadline)?;
            if before.pid != group as u32
                || after.pid != group as u32
                || before.pgid != group as u32
                || after.pgid != group as u32
                || (before.start_sec, before.start_usec) != identity
                || (after.start_sec, after.start_usec) != identity
            {
                return Err(StdioError::new("native_identity"));
            }
            leader = true;
            if after.status != 5 {
                count += 1;
            }
            continue;
        }
        let session = unsafe { libc::getsid(pid) };
        super::drain_deadline_check(deadline)?;
        if session == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            continue;
        }
        if session == -1 {
            return Err(StdioError::new("native_observe"));
        }
        if session != group {
            continue;
        }
        let Some(before) = bsd_info(pid, false)? else {
            continue;
        };
        super::drain_deadline_check(deadline)?;
        let after_session = unsafe { libc::getsid(pid) };
        super::drain_deadline_check(deadline)?;
        let Some(after) = bsd_info(pid, false)? else {
            continue;
        };
        super::drain_deadline_check(deadline)?;
        if after_session != group
            || before.pid != pid as u32
            || after.pid != pid as u32
            || before.start_sec != after.start_sec
            || before.start_usec != after.start_usec
            || before.pgid != after.pgid
        {
            return Err(StdioError::new("native_identity"));
        }
        if after.status != 5 {
            if after.pgid != group as u32 {
                return Err(StdioError::new("native_scope_escape"));
            }
            count += 1;
        }
    }
    super::drain_deadline_check(deadline)?;
    if !leader {
        return Err(StdioError::new("native_identity"));
    }
    Ok(count)
}

#[cfg(all(test, target_os = "macos"))]
mod resource_policy_tests {
    use super::*;
    use mmmm_native_process::darwin::MemoryObservation;

    fn sample() -> MemoryObservation {
        MemoryObservation {
            adjusted_vm: MAC_VM_LIMIT,
            rss: MAC_PHYSICAL_THRESHOLD,
            footprint: MAC_PHYSICAL_THRESHOLD,
            start_abstime: 17,
        }
    }
    fn samples(actual: MemoryObservation, elapsed: Duration) -> ResourceSamples {
        let last = Instant::now().checked_sub(elapsed).unwrap();
        ResourceSamples {
            first: last,
            last,
            first_native_millis: 1,
            actual,
            peak_vm: actual.adjusted_vm,
            peak_rss: actual.rss,
            peak_footprint: actual.footprint,
            samples: 1,
            maximum_gap: Duration::ZERO,
        }
    }

    #[test]
    fn darwin_terminal_signal_preflight_requires_fresh_exit_and_empty_scope() {
        let verified = VerifiedMacIdentity {
            status: 5,
            terminal_query_errno: None,
            exit_pending: false,
        };
        let signal_failure = |native_errno| DarwinStdioSignalFailure {
            signal_result: -1,
            native_errno,
            postcheck: DarwinStdioSignalPostcheck::NotAttempted,
        };
        let terminal_identity = || VerifiedMacIdentity {
            status: verified.status,
            terminal_query_errno: verified.terminal_query_errno,
            exit_pending: verified.exit_pending,
        };
        for (exited, empty, expected) in [
            (Some(0), true, true),
            (Some(101), true, true),
            (Some(-9), true, true),
            (None, true, false),
            (Some(101), false, false),
            (None, false, false),
        ] {
            let mut observations = 0;
            let actual = mac_terminal_scope_is_empty(&verified, || {
                observations += 1;
                Ok((exited, empty))
            })
            .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(observations, 1);
        }
        for (status, exit_pending) in [(0, false), (2, false), (2, true), (5, true)] {
            let unconfirmed = VerifiedMacIdentity {
                status,
                terminal_query_errno: Some(libc::ESRCH),
                exit_pending,
            };
            assert!(
                !mac_terminal_scope_is_empty(&unconfirmed, || {
                    panic!("live, unknown or pending identity cannot skip a signal")
                })
                .unwrap()
            );
        }
        for error in [
            StdioError::new("deadline"),
            StdioError::new("native_observe"),
            StdioError::new("native_resource_identity"),
            StdioError::io(
                "native_resource_observation",
                std::io::Error::from_raw_os_error(libc::EPERM),
            ),
        ] {
            assert_eq!(
                mac_terminal_scope_is_empty(&verified, || Err(error.clone())).unwrap_err(),
                error
            );
            for failure_at_identity in [true, false] {
                let mut failure = signal_failure(libc::EPERM);
                assert!(!mac_signal_failure_terminal_scope(
                    &mut failure,
                    true,
                    || true,
                    || if failure_at_identity {
                        Err(error.clone())
                    } else {
                        Ok(terminal_identity())
                    },
                    || Err(error.clone()),
                    || Ok(()),
                ));
                assert_eq!(failure.signal_result, -1);
                assert_eq!(failure.native_errno, libc::EPERM);
                assert_eq!(
                    failure.postcheck.requires_identity_uncertainty(),
                    error.code != "deadline"
                );
                assert_eq!(
                    failure.postcheck,
                    DarwinStdioSignalPostcheck::ObservationFailed {
                        phase: if failure_at_identity {
                            "identity"
                        } else {
                            "terminal_scope"
                        },
                        code: error.code,
                        native_code: error.native_code,
                        native_code_unknown: error.native_code_unknown,
                    }
                );
            }
        }
        for native_errno in [0, libc::ESRCH, libc::EACCES, libc::EINVAL] {
            let mut failure = signal_failure(native_errno);
            assert!(!mac_signal_failure_terminal_scope(
                &mut failure,
                true,
                || panic!("another signal error cannot query UID"),
                || panic!("another signal error cannot query identity"),
                || panic!("another signal error cannot query scope"),
                || panic!("another signal error cannot start postcheck"),
            ));
            assert_eq!(failure.postcheck, DarwinStdioSignalPostcheck::NotAttempted);
        }
        let mut failure = signal_failure(libc::EPERM);
        assert!(!mac_signal_failure_terminal_scope(
            &mut failure,
            false,
            || panic!("an unconfirmed owner cannot query UID"),
            || panic!("an unconfirmed owner cannot query identity"),
            || panic!("an unconfirmed owner cannot query scope"),
            || Ok(()),
        ));
        assert_eq!(
            failure.postcheck,
            DarwinStdioSignalPostcheck::OwnerUnconfirmed
        );
        for exit_code in [0, 101, -9] {
            let mut failure = signal_failure(libc::EPERM);
            let mut uid_checks = 0;
            let mut identity_checks = 0;
            let mut scope_checks = 0;
            assert!(mac_signal_failure_terminal_scope(
                &mut failure,
                true,
                || {
                    uid_checks += 1;
                    true
                },
                || {
                    identity_checks += 1;
                    Ok(terminal_identity())
                },
                || {
                    scope_checks += 1;
                    Ok((Some(exit_code), true))
                },
                || Ok(()),
            ));
            assert_eq!((uid_checks, identity_checks, scope_checks), (2, 1, 1));
            assert_eq!(failure.signal_result, -1);
            assert_eq!(failure.native_errno, libc::EPERM);
            assert_eq!(
                failure.postcheck,
                DarwinStdioSignalPostcheck::ConfirmedTerminalScope { exit_code }
            );
            assert!(!failure.postcheck.requires_identity_uncertainty());
        }
        for (status, exit_pending) in [
            (0, false),
            (2, false),
            (2, true),
            (5, true),
            (u32::MAX, false),
        ] {
            let mut failure = signal_failure(libc::EPERM);
            assert!(!mac_signal_failure_terminal_scope(
                &mut failure,
                true,
                || true,
                || Ok(VerifiedMacIdentity {
                    status,
                    exit_pending,
                    terminal_query_errno: Some(libc::ESRCH)
                }),
                || panic!("non-terminal identity cannot query exit or scope"),
                || Ok(()),
            ));
            assert_eq!(
                failure.postcheck,
                DarwinStdioSignalPostcheck::IdentityNotTerminal {
                    status,
                    exit_pending,
                    terminal_query_errno: Some(libc::ESRCH),
                }
            );
            assert!(!failure.postcheck.requires_identity_uncertainty());
        }
        for mismatch_after in [false, true] {
            let mut failure = signal_failure(libc::EPERM);
            let mut uid_checks = 0;
            assert!(!mac_signal_failure_terminal_scope(
                &mut failure,
                true,
                || {
                    uid_checks += 1;
                    mismatch_after && uid_checks == 1
                },
                || {
                    assert!(mismatch_after);
                    Ok(terminal_identity())
                },
                || {
                    assert!(mismatch_after);
                    Ok((Some(0), true))
                },
                || Ok(()),
            ));
            assert_eq!(
                failure.postcheck,
                if mismatch_after {
                    DarwinStdioSignalPostcheck::UidAfterMismatch
                } else {
                    DarwinStdioSignalPostcheck::UidBeforeMismatch
                }
            );
            assert!(failure.postcheck.requires_identity_uncertainty());
        }
        for (exited, empty) in [(None, true), (None, false), (Some(0), false)] {
            let mut failure = signal_failure(libc::EPERM);
            let mut uid_checks = 0;
            assert!(!mac_signal_failure_terminal_scope(
                &mut failure,
                true,
                || {
                    uid_checks += 1;
                    true
                },
                || Ok(terminal_identity()),
                || Ok((exited, empty)),
                || Ok(()),
            ));
            assert_eq!(uid_checks, 1);
            assert_eq!(
                failure.postcheck,
                if exited.is_none() {
                    DarwinStdioSignalPostcheck::ChildNotExited
                } else {
                    DarwinStdioSignalPostcheck::ScopeNotEmpty
                }
            );
            assert!(!failure.postcheck.requires_identity_uncertainty());
        }
        for (fail_at, phase) in [
            "initial_deadline",
            "uid_before",
            "identity",
            "terminal_scope",
            "uid_after",
            "final_deadline",
        ]
        .into_iter()
        .enumerate()
        {
            let mut failure = signal_failure(libc::EPERM);
            let mut checkpoints = 0;
            assert!(!mac_signal_failure_terminal_scope(
                &mut failure,
                true,
                || true,
                || Ok(terminal_identity()),
                || Ok((Some(0), true)),
                || {
                    let current = checkpoints;
                    checkpoints += 1;
                    if current == fail_at {
                        Err(StdioError::new("deadline"))
                    } else {
                        Ok(())
                    }
                },
            ));
            assert_eq!(failure.native_errno, libc::EPERM);
            assert_eq!(
                failure.postcheck,
                DarwinStdioSignalPostcheck::ObservationFailed {
                    phase,
                    code: "deadline",
                    native_code: None,
                    native_code_unknown: false,
                }
            );
            assert!(!failure.postcheck.requires_identity_uncertainty());
        }
    }

    // Existing native stdio fixtures exercise lifecycle, but do not distinguish
    // Darwin VM, resident and footprint policy or failed-sample evidence.
    // These small authored values require no libproc call or process fixture.
    #[test]
    fn darwin_vm_resident_and_footprint_limits_are_independent() {
        let exact = sample();
        assert!(check_memory_thresholds(exact).is_ok());
        for invalid in [
            MemoryObservation {
                adjusted_vm: exact.adjusted_vm + 1,
                ..exact
            },
            MemoryObservation {
                rss: exact.rss + 1,
                ..exact
            },
            MemoryObservation {
                footprint: exact.footprint + 1,
                ..exact
            },
            MemoryObservation {
                start_abstime: 0,
                ..exact
            },
        ] {
            assert_eq!(
                check_memory_thresholds(invalid).unwrap_err().code,
                "native_resource_budget"
            );
        }
    }

    #[test]
    fn darwin_failed_samples_preserve_peaks_and_reject_changed_identity() {
        let exact = sample();
        let mut changed = samples(exact, Duration::ZERO);
        assert_eq!(
            changed
                .push(
                    MemoryObservation {
                        start_abstime: exact.start_abstime + 1,
                        ..exact
                    },
                    true,
                )
                .unwrap_err()
                .code,
            "native_resource_identity"
        );
        assert_eq!(changed.samples, 1);
        assert_eq!(changed.actual, exact);

        let mut exceeded = samples(exact, Duration::ZERO);
        assert_eq!(
            exceeded
                .push(
                    MemoryObservation {
                        footprint: exact.footprint + 1,
                        ..exact
                    },
                    true,
                )
                .unwrap_err()
                .code,
            "native_resource_budget"
        );
        assert_eq!(exceeded.peak_footprint, exact.footprint + 1);
        assert_eq!(exceeded.samples, 2);

        let mut overdue = samples(exact, Duration::from_secs(2));
        assert_eq!(
            overdue.push(exact, true).unwrap_err().code,
            "native_resource_gap"
        );
        assert!(overdue.maximum_gap > Duration::from_millis(MAC_MAX_GAP_MILLIS));
        assert_eq!(overdue.samples, 2);

        let mut poll_driven = samples(exact, Duration::from_secs(2));
        assert!(poll_driven.push(exact, false).is_ok());
        assert!(poll_driven.maximum_gap > Duration::from_millis(MAC_MAX_GAP_MILLIS));

        // Pure heartbeat arithmetic does not mutate the live atomic or claim
        // an exact scheduler/termination bound for this polling watchdog.
        assert!(check_worker_gap_at(0, 0).is_ok());
        assert!(check_worker_gap_at(2, 1_000_000_001).is_ok());
        assert_eq!(
            check_worker_gap_at(2, 1_000_000_002).unwrap_err().code,
            "native_resource_watchdog_gap"
        );
        assert_eq!(
            check_worker_gap_at(3, 1).unwrap_err().code,
            "native_resource_watchdog_gap"
        );
    }
}

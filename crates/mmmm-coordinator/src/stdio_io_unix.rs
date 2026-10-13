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
        for fd in [
            libc::STDIN_FILENO,
            libc::STDOUT_FILENO,
            libc::STDERR_FILENO,
            boot,
        ] {
            check(unsafe { posix_spawn_file_actions_addinherit_np(&mut plan.actions, fd) })?;
        }
        Ok(plan)
    }

    fn exec(&self) -> std::io::Result<()> {
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
        Err(std::io::Error::from_raw_os_error(if result == 0 {
            libc::EIO
        } else {
            result
        }))
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
    identity: (u64, u64),
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
                    return Err(std::io::Error::last_os_error());
                }
                #[cfg(target_os = "linux")]
                if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) == -1 {
                    // Linux 5.11+ CLOSE_RANGE_CLOEXEC is required, rather than
                    // silently inheriting descriptors or looping a huge limit.
                    return Err(std::io::Error::last_os_error());
                }
                #[cfg(target_os = "linux")]
                if libc::fcntl(boot, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                let memory = libc::rlimit {
                    rlim_cur: 256 * 1024 * 1024,
                    rlim_max: 256 * 1024 * 1024,
                };
                let core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_AS, &memory) == -1
                    || libc::setrlimit(libc::RLIMIT_CORE, &core) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
                #[cfg(target_os = "linux")]
                {
                    // Execute the verified open inode, avoiding a path exchange
                    // between checksum and exec. No inherited environment is read.
                    let env = [std::ptr::null::<libc::c_char>()];
                    libc::fexecve(exec_fd, argv.as_ptr().cast(), env.as_ptr());
                    Err(std::io::Error::last_os_error())
                }
                #[cfg(target_os = "macos")]
                mac_exec.exec()
            });
        }
        super::deadline_check(startup_deadline)?;
        let child = command
            .spawn()
            .map_err(|error| StdioError::io("native_spawn", error))?;
        let pid = child.id() as i32;
        drop(read);
        drop(write);
        let mut process = Self {
            child: Some(child),
            pid,
            reaped: false,
            reserved: true,
            reaped_code: None,
            owner_deadline,
            reservation: Some(reservation),
            #[cfg(target_os = "macos")]
            identity: (0, 0),
        };
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
            if info.pid != pid as u32 || info.pgid != pid as u32 {
                return Err(super::cleanup_failed_process(
                    process,
                    StdioError::new("native_identity"),
                ));
            }
            process.identity = (info.start_sec, info.start_usec);
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
            Ok(mac_members(self.pid, self.identity, deadline)? == 0)
        }
    }
    pub(super) fn terminate(&mut self) -> Result<(), StdioError> {
        if self.reaped {
            return Ok(());
        }
        if !self.reserved {
            return Err(StdioError::new("native_identity"));
        }
        if unsafe { libc::kill(-self.pid, libc::SIGKILL) } == -1
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        {
            Err(StdioError::new("native_terminate"))
        } else {
            Ok(())
        }
    }
    pub(super) fn reap(&mut self) -> Result<Option<i32>, StdioError> {
        if self.exit_code()?.is_none() {
            return Err(StdioError::new("native_reap"));
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
        self.terminate()?;
        if Instant::now() >= deadline {
            return Err(StdioError::new("drain_uncertain"));
        }
        let mut empty = None;
        loop {
            if self.exit_code()?.is_some() && self.scope_empty(deadline)? {
                if empty.is_some_and(|t: Instant| t.elapsed() >= Duration::from_millis(10)) {
                    if Instant::now() >= deadline {
                        return Err(StdioError::new("drain_uncertain"));
                    }
                    self.reap()?;
                    if Instant::now() >= deadline {
                        return Err(StdioError {
                            code: "drain_deadline",
                            drained: true,
                            native_code: None,
                            native_code_unknown: false,
                            cleanup: None,
                        });
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
        if !self.reaped {
            if let Err(error) = self.drain_blocking(self.owner_deadline) {
                if !error.drained {
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
                    };
                    self.reaped = true;
                    super::retain_uncertain_process(retained);
                }
            }
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
    let bytes = unsafe {
        proc_pidinfo(
            pid,
            3,
            u64::from(zombie),
            (&mut info as *mut BsdInfo).cast(),
            std::mem::size_of::<BsdInfo>() as i32,
        )
    };
    if bytes == 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        return Ok(None);
    }
    if bytes as usize != std::mem::size_of::<BsdInfo>() {
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

//! Trusted self-worker session ownership. This is not a sandbox against a
//! deliberately escaping program. Keep the leader unreaped until group drain.
use super::{Executable, StdioError};
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

pub(super) fn open_executable(path: &Path) -> Result<File, StdioError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| StdioError::new("executable"))?;
    let metadata = file.metadata().map_err(|_| StdioError::new("executable"))?;
    if !metadata.is_file() || metadata.mode() & 0o022 != 0 {
        return Err(StdioError::new("executable"));
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
pub(super) fn worker_stdio() -> Result<(File, File), StdioError> {
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
    Ok((file(libc::STDIN_FILENO)?, file(libc::STDOUT_FILENO)?))
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
        || packet.len() != 96
    {
        return Err(StdioError::new("bootstrap_pipe"));
    }
    write
        .write_all(packet)
        .map_err(|_| StdioError::new("bootstrap_pipe"))?;
    Ok((read, write))
}
pub(super) fn read_bootstrap(value: usize) -> Result<zeroize::Zeroizing<[u8; 96]>, StdioError> {
    let fd = i32::try_from(value).map_err(|_| StdioError::new("bootstrap_pipe"))?;
    if fd < 3 {
        return Err(StdioError::new("bootstrap_pipe"));
    }
    let mut info: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut info) } == -1 || info.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return Err(StdioError::new("bootstrap_pipe"));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    // Only an inherited anonymous pipe is eligible. Nonblocking avoids a
    // hidden entry hanging when invoked without its trusted parent packet.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(StdioError::new("bootstrap_pipe"));
    }
    let mut packet = zeroize::Zeroizing::new([0; 96]);
    file.read_exact(&mut packet[..])
        .map_err(|_| StdioError::new("bootstrap_pipe"))?;
    Ok(packet)
}
pub(super) struct Process {
    child: Child,
    pid: libc::pid_t,
    reaped: bool,
    reserved: bool,
    #[cfg(target_os = "macos")]
    identity: (u64, u64),
}
impl Process {
    pub(super) fn spawn(
        executable: &Executable,
        address: SocketAddr,
        packet: &[u8],
    ) -> Result<Self, StdioError> {
        let (read, write) = bootstrap(packet)?;
        let boot = read.as_raw_fd();
        #[cfg(target_os = "macos")]
        let max_fd = {
            let mut descriptor_limit: libc::rlimit = unsafe { std::mem::zeroed() };
            if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut descriptor_limit) } == -1
                || descriptor_limit.rlim_cur > 65_536
            {
                return Err(StdioError::new("native_descriptors"));
            }
            descriptor_limit.rlim_cur as i32
        };
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
            .stdout(Stdio::inherit())
            .stderr(Stdio::null());
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
                #[cfg(target_os = "macos")]
                for fd in 3..max_fd {
                    if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) == -1
                        && std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                }
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
                Ok(())
            });
        }
        let child = command
            .spawn()
            .map_err(|error| StdioError::io("native_spawn", error))?;
        let pid = child.id() as i32;
        drop(read);
        drop(write);
        let mut process = Self {
            child,
            pid,
            reaped: false,
            reserved: true,
            #[cfg(target_os = "macos")]
            identity: (0, 0),
        };
        #[cfg(target_os = "macos")]
        {
            let info = bsd_info(pid, true)?.ok_or_else(|| StdioError::new("native_identity"))?;
            if info.pid != pid as u32 || info.pgid != pid as u32 {
                let _ = process.drain_blocking(Instant::now() + Duration::from_secs(5));
                return Err(StdioError::new("native_identity"));
            }
            process.identity = (info.start_sec, info.start_usec);
        }
        if !matches!(same_file(&executable.file, &executable.path), Ok(true)) {
            let mut error = StdioError::new("executable_changed");
            error.drained = process
                .drain_blocking(Instant::now() + Duration::from_secs(5))
                .is_ok();
            return Err(error);
        }
        Ok(process)
    }
    pub(super) fn id(&self) -> u64 {
        self.pid as u64
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
            Ok(Some(128 + status))
        }
    }
    pub(super) fn scope_empty(&self) -> Result<bool, StdioError> {
        if !self.reserved {
            return Err(StdioError::new("native_identity"));
        }
        #[cfg(target_os = "linux")]
        {
            Ok(linux_members(self.pid)? == 0)
        }
        #[cfg(target_os = "macos")]
        {
            Ok(mac_members(self.pid, self.identity)? == 0)
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
        let status = self.child.wait().map_err(|_| {
            self.reserved = false;
            StdioError::new("native_reap")
        })?;
        self.reaped = true;
        Ok(status.code())
    }
    pub(super) fn drain_blocking(&mut self, deadline: Instant) -> Result<(), StdioError> {
        if self.reaped {
            return Ok(());
        }
        self.terminate()?;
        let mut empty = None;
        loop {
            if self.exit_code()?.is_some() && self.scope_empty()? {
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
            let _ = self.drain_blocking(Instant::now() + Duration::from_secs(5));
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_members(group: i32) -> Result<usize, StdioError> {
    let mut members = 0;
    let mut leader = false;
    let mut count = 0;
    for entry in std::fs::read_dir("/proc").map_err(|_| StdioError::new("native_observe"))? {
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
        match File::open(entry.path().join("stat"))
            .and_then(|f| f.take(8193).read_to_end(&mut bytes))
        {
            Ok(_) if bytes.len() <= 8192 => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            _ => return Err(StdioError::new("native_observe")),
        }
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
fn mac_members(group: i32, identity: (u64, u64)) -> Result<usize, StdioError> {
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
        let mut pids = vec![0i32; capacity];
        let n = unsafe { proc_listpids(1, 0, pids.as_mut_ptr().cast(), (capacity * 4) as i32) };
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
        if pid == group {
            let before = bsd_info(pid, true)?.ok_or_else(|| StdioError::new("native_identity"))?;
            let after = bsd_info(pid, true)?.ok_or_else(|| StdioError::new("native_identity"))?;
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
        let after_session = unsafe { libc::getsid(pid) };
        let Some(after) = bsd_info(pid, false)? else {
            continue;
        };
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
    if !leader {
        return Err(StdioError::new("native_identity"));
    }
    Ok(count)
}

//! Private current-binary daemon startup. This module never opens SQLite.
//!
//! A spawned daemon acquires DurableStore's singleton lock before publishing.
//! READY is bound to the exact owned child and endpoint, then the real native
//! peer verifies account and kernel PID before the parent commits ownership.
//! Windows keeps KILL_ON_JOB_CLOSE enabled and transfers a live Job handle;
//! Unix keeps the dedicated session/group. No service registration, shell,
//! credential file, environment inheritance, or endpoint repair is performed.

use crate::{
    credential::CredentialRef,
    endpoint::{EndpointError, EndpointRecord, RuntimeDirectory},
    host_relay::{CoordinatorLocator, RelayError},
    peer::{PeerBootstrap, PeerError},
};
use mmmm_contracts::ProjectId;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const DAEMON_CHILD_COMMAND: &str = "--mmmm-daemon-owned";
pub const DEFAULT_DAEMON_LIFETIME: Duration = Duration::from_secs(1800);
const MAGIC: &[u8; 8] = b"MMMMDMN1";
const READY: &[u8; 8] = b"MMMMRDY1";
const OWNED: &[u8; 8] = b"MMMMOWN1";
const PACKET: usize = 96;
const RECEIPT: usize = 80;
const POLL: Duration = Duration::from_millis(5);
const DRAIN_RESERVE: Duration = Duration::from_secs(2);
static STARTING: AtomicBool = AtomicBool::new(false);
static UNCERTAIN: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonLaunchError {
    pub code: &'static str,
    pub cause: Option<&'static str>,
    pub child_termination_confirmed: bool,
    pub native_code: Option<i32>,
}
impl DaemonLaunchError {
    fn new(code: &'static str) -> Self {
        Self {
            code,
            cause: None,
            child_termination_confirmed: false,
            native_code: None,
        }
    }
    fn native(code: &'static str) -> Self {
        Self {
            native_code: std::io::Error::last_os_error().raw_os_error(),
            ..Self::new(code)
        }
    }
    fn from_io(code: &'static str, error: std::io::Error) -> Self {
        Self {
            native_code: error.raw_os_error(),
            ..Self::new(code)
        }
    }
}
impl std::fmt::Display for DaemonLaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Owned Coordinator startup failed: {}", self.code)?;
        if let Some(cause) = self.cause {
            write!(f, " (cause: {cause})")?;
        }
        if let Some(code) = self.native_code {
            write!(f, " (native status: {code})")?;
        }
        Ok(())
    }
}
impl std::error::Error for DaemonLaunchError {}

struct Reservation;
impl Reservation {
    fn acquire() -> Result<Self, DaemonLaunchError> {
        if UNCERTAIN.load(Ordering::Acquire) {
            return Err(DaemonLaunchError::new("termination_uncertain"));
        }
        STARTING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| DaemonLaunchError::new("startup_busy"))?;
        if UNCERTAIN.load(Ordering::Acquire) {
            STARTING.store(false, Ordering::Release);
            return Err(DaemonLaunchError::new("termination_uncertain"));
        }
        Ok(Self)
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        STARTING.store(false, Ordering::Release);
    }
}

struct Executable {
    path: PathBuf,
    file: File,
    _parents: Vec<File>,
    digest: [u8; 32],
}
impl Executable {
    fn current(deadline: Instant) -> Result<Self, DaemonLaunchError> {
        let path = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|_| DaemonLaunchError::new("current_executable"))?;
        let parents = native::pin_executable_ancestors(&path)?;
        let mut file = native::open_current_executable(&path)?;
        let metadata = file
            .metadata()
            .map_err(|e| DaemonLaunchError::from_io("current_executable", e))?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 512 * 1024 * 1024 {
            return Err(DaemonLaunchError::new("current_executable"));
        }
        let hash_deadline = deadline.min(Instant::now() + Duration::from_secs(10));
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65_536];
        let mut length = 0u64;
        loop {
            check(hash_deadline)?;
            let n = file
                .read(&mut buffer)
                .map_err(|e| DaemonLaunchError::from_io("current_executable", e))?;
            if n == 0 {
                break;
            }
            length += n as u64;
            if length > metadata.len() {
                return Err(DaemonLaunchError::new("executable_changed"));
            }
            hash.update(&buffer[..n]);
        }
        let after = file
            .metadata()
            .map_err(|e| DaemonLaunchError::from_io("current_executable", e))?;
        if length != metadata.len()
            || after.len() != metadata.len()
            || after.modified().ok() != metadata.modified().ok()
            || !native::same_file(&file, &path)?
        {
            return Err(DaemonLaunchError::new("executable_changed"));
        }
        Ok(Self {
            path,
            file,
            _parents: parents,
            digest: hash.finalize().into(),
        })
    }
}

/// The native CLI hashes its actual protected current executable using the
/// same pinned file and ancestry checks as owned daemon launch. This identity
/// belongs to Rust composition and cannot be substituted by a host JAR pin.
pub fn current_executable_digest(
    deadline: Instant,
) -> Result<mmmm_contracts::Sha256Digest, DaemonLaunchError> {
    let executable = Executable::current(deadline)?;
    let digest = executable
        .digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    mmmm_contracts::Sha256Digest::new(digest)
        .map_err(|_| DaemonLaunchError::new("current_executable_digest"))
}

/// This locator starts exactly the current approved binary. An unavailable
/// endpoint never authorizes lease stealing: the child must acquire the real
/// Store lock, and a Busy child cannot create another connection or journal.
#[derive(Default)]
pub struct NativeDaemonLocator;
impl NativeDaemonLocator {
    pub fn ensure(
        &mut self,
        root: &Path,
        project: &ProjectId,
        deadline: Instant,
    ) -> Result<EndpointRecord, DaemonLaunchError> {
        check(deadline)?;
        if UNCERTAIN.load(Ordering::Acquire) {
            return Err(DaemonLaunchError::new("termination_uncertain"));
        }
        // RuntimeDirectory holds native no-link ancestor pins throughout startup.
        // Existing malformed/private-path failures are preserved and returned.
        let runtime = RuntimeDirectory::open(&root.join("runtime"))
            .map_err(|_| DaemonLaunchError::new("runtime_directory"))?;
        match runtime.load() {
            Ok(record) => match prove(&runtime, &record, None, deadline) {
                Ok(()) => return Ok(record),
                // Only a missing channel or refused local connection can
                // trigger the single lock-acquiring child. Permissions,
                // identity mismatch, Busy, cancellation and uncertain I/O
                // preserve the existing owner instead of choosing a fallback.
                Err(PeerError::Native(code)) if absent_channel(code) => (),
                Err(_) => return Err(DaemonLaunchError::new("existing_peer_denied")),
            },
            Err(EndpointError::Missing) => (),
            Err(_) => return Err(DaemonLaunchError::new("endpoint_preserved")),
        }
        let _reservation = Reservation::acquire()?;
        if cfg!(target_os = "macos") {
            // Apple's public path-based exec does not bind the verified inode.
            // Until a native loaded-image/FD-exec proof is implemented, a new
            // macOS daemon must be started explicitly by its local owner.
            return Err(DaemonLaunchError::new(
                "macos_exact_executable_launch_unavailable",
            ));
        }
        let startup_deadline = deadline
            .checked_sub(DRAIN_RESERVE)
            .ok_or_else(|| DaemonLaunchError::new("startup_deadline"))?;
        check(startup_deadline)?;
        let executable = Executable::current(startup_deadline)?;
        let mut packet = Zeroizing::new([0u8; PACKET]);
        packet[..8].copy_from_slice(MAGIC);
        let remaining = startup_deadline
            .saturating_duration_since(Instant::now())
            .as_millis();
        if remaining == 0 || remaining > 30_000 {
            return Err(DaemonLaunchError::new("startup_deadline"));
        }
        packet[8..16].copy_from_slice(&(remaining as u64).to_be_bytes());
        packet[16..24].copy_from_slice(&(DEFAULT_DAEMON_LIFETIME.as_millis() as u64).to_be_bytes());
        getrandom::fill(&mut packet[24..56])
            .map_err(|_| DaemonLaunchError::new("startup_nonce"))?;
        packet[56..88].copy_from_slice(&executable.digest);
        let mut pending = PendingChild {
            process: Some(native::Process::spawn(
                &executable,
                root,
                project,
                &packet[..],
                startup_deadline,
            )?),
            terminal: false,
        };
        let result = (|| {
            let child = pending.process.as_mut().expect("owned startup process");
            child.activate(&executable)?;
            let mut receipt = Zeroizing::new([0u8; RECEIPT]);
            child.read(&mut receipt[..], startup_deadline)?;
            if receipt[..8] != READY[..]
                || receipt[8..16] != u64::from(child.id()).to_be_bytes()
                || receipt[48..80] != packet[24..56]
            {
                return Err(DaemonLaunchError::new("ready_receipt"));
            }
            child.require_alive()?;
            let record = runtime
                .load()
                .map_err(|_| DaemonLaunchError::new("ready_endpoint"))?;
            if receipt[16..48] != endpoint_digest(&record)? {
                return Err(DaemonLaunchError::new("ready_endpoint"));
            }
            prove(&runtime, &record, Some(child.id()), startup_deadline)
                .map_err(|peer| peer_error("child_peer_denied", peer))?;
            child.require_alive()?;
            // Parent holds the native scope through real peer proof. Only the
            // running exact child receives its owner; OWNED proves adoption.
            let commit = child.commit_packet()?;
            child.write(&commit, startup_deadline)?;
            let mut owned = [0u8; 8];
            child.read(&mut owned, startup_deadline)?;
            if owned != *OWNED {
                return Err(DaemonLaunchError::new("ownership_receipt"));
            }
            child.require_alive()?;
            child.transfer()?;
            Ok(record)
        })();
        match result {
            Ok(record) => {
                pending.terminal = true;
                drop(pending.process.take());
                Ok(record)
            }
            Err(mut error) => {
                let process = pending.process.as_mut().expect("owned startup process");
                let drained = process.cancel_and_drain(deadline);
                if drained.is_ok() {
                    error.child_termination_confirmed = true;
                    pending.terminal = true;
                    drop(pending.process.take());
                    Err(error)
                } else {
                    UNCERTAIN.store(true, Ordering::Release);
                    // Preserve the full native process/job/pipe owner. No later
                    // launch is admitted and no endpoint or product data is removed.
                    if let Some(process) = pending.process.take() {
                        std::mem::forget(process);
                    }
                    pending.terminal = true;
                    let mut preserved = DaemonLaunchError::new("termination_uncertain");
                    preserved.cause = Some(error.code);
                    preserved.native_code = error
                        .native_code
                        .or_else(|| drained.err().and_then(|e| e.native_code));
                    Err(preserved)
                }
            }
        }
    }
}
impl CoordinatorLocator for NativeDaemonLocator {
    fn ensure_endpoint(
        &mut self,
        root: &Path,
        project: &ProjectId,
        deadline: Instant,
    ) -> Result<EndpointRecord, RelayError> {
        self.ensure(root, project, deadline).map_err(|error| {
            if matches!(error.code, "termination_uncertain" | "native_io_uncertain") {
                RelayError::DrainUncertain
            } else {
                RelayError::CoordinatorUnavailable
            }
        })
    }
}

struct PendingChild {
    process: Option<native::Process>,
    terminal: bool,
}
impl Drop for PendingChild {
    fn drop(&mut self) {
        if !self.terminal {
            UNCERTAIN.store(true, Ordering::Release);
            if let Some(mut process) = self.process.take() {
                // Panic/abandonment is never reported as drained. Preserve the
                // entire owner after requesting only this child's native scope.
                let _ = process.terminate();
                std::mem::forget(process);
            }
        }
    }
}

fn prove(
    runtime: &RuntimeDirectory,
    record: &EndpointRecord,
    pid: Option<u32>,
    deadline: Instant,
) -> Result<(), PeerError> {
    record.validate().map_err(|_| PeerError::Protocol)?;
    let reference = CredentialRef::new(&record.credential_ref).map_err(|_| PeerError::Protocol)?;
    // The peer implementation authenticates UID/SID and kernel server PID
    // before requesting capability bytes. The temporary token is zeroized.
    drop(PeerBootstrap::connect_verified_with_deadline(
        runtime.path(),
        &reference,
        pid,
        deadline,
    )?);
    Ok(())
}
fn endpoint_digest(record: &EndpointRecord) -> Result<[u8; 32], DaemonLaunchError> {
    record
        .validate()
        .map_err(|_| DaemonLaunchError::new("endpoint_contract"))?;
    let value =
        serde_json::to_value(record).map_err(|_| DaemonLaunchError::new("endpoint_contract"))?;
    let bytes = mmmm_contracts::encode_json(&value)
        .map_err(|_| DaemonLaunchError::new("endpoint_contract"))?;
    Ok(Sha256::digest(bytes).into())
}
fn peer_error(code: &'static str, peer: PeerError) -> DaemonLaunchError {
    let mut error = DaemonLaunchError::new(code);
    if let PeerError::Native(status) = peer {
        error.native_code = Some(status);
    }
    error
}
fn check(deadline: Instant) -> Result<(), DaemonLaunchError> {
    if Instant::now() >= deadline {
        Err(DaemonLaunchError::new("deadline"))
    } else {
        Ok(())
    }
}
fn absent_channel(code: i32) -> bool {
    #[cfg(windows)]
    return matches!(code, 2 | 3 | 109 | 233);
    #[cfg(unix)]
    return code == libc::ENOENT || code == libc::ECONNREFUSED;
}

/// Main's hidden entry must adopt this owner before opening Store and retain it
/// through Coordinator::serve and explicit shutdown. It must stop admission at
/// lifetime_deadline; expiry invokes Coordinator shutdown, never cache cleanup.
pub struct DaemonOwnership {
    native: native::ChildOwnership,
    root: PathBuf,
    project: ProjectId,
    nonce: Zeroizing<[u8; 32]>,
    startup_deadline: Instant,
    lifetime_deadline: Instant,
    committed: bool,
}
impl DaemonOwnership {
    pub fn data_root(&self) -> &Path {
        &self.root
    }
    /// Public project selection; the daemon must still check its actual ACL.
    pub fn project_id(&self) -> &ProjectId {
        &self.project
    }
    pub fn lifetime_deadline(&self) -> Instant {
        self.lifetime_deadline
    }
    pub fn startup_deadline(&self) -> Instant {
        self.startup_deadline
    }
    pub fn ready(&mut self, endpoint: &EndpointRecord) -> Result<(), DaemonLaunchError> {
        if self.committed {
            return Err(DaemonLaunchError::new("already_committed"));
        }
        check(self.startup_deadline)?;
        let mut receipt = Zeroizing::new([0u8; RECEIPT]);
        receipt[..8].copy_from_slice(READY);
        receipt[8..16].copy_from_slice(&u64::from(std::process::id()).to_be_bytes());
        receipt[16..48].copy_from_slice(&endpoint_digest(endpoint)?);
        receipt[48..80].copy_from_slice(&self.nonce[..]);
        self.native.write(&receipt[..], self.startup_deadline)?;
        let mut commit = [0u8; 9];
        self.native.read(&mut commit, self.startup_deadline)?;
        if commit[0] != 1 {
            return Err(DaemonLaunchError::new("parent_commit"));
        }
        self.native.adopt_committed(&commit[1..])?;
        self.native.write(OWNED, self.startup_deadline)?;
        self.native.close_startup();
        self.committed = true;
        Ok(())
    }
}
pub fn adopt_child(args: &[String]) -> Result<DaemonOwnership, DaemonLaunchError> {
    let started = Instant::now();
    if args.len() != 10
        || args[0] != "--data-root"
        || args[2] != "--project"
        || args[4] != "--bootstrap-read"
        || args[6] != "--bootstrap-write"
        || args[8] != "--job"
    {
        return Err(DaemonLaunchError::new("child_arguments"));
    }
    let root = PathBuf::from(&args[1]);
    if !root.is_absolute() {
        return Err(DaemonLaunchError::new("child_arguments"));
    }
    let project =
        ProjectId::new(args[3].clone()).map_err(|_| DaemonLaunchError::new("child_arguments"))?;
    let number = |s: &str| s.parse::<usize>().ok().filter(|n| *n > 2);
    let read = number(&args[5]).ok_or_else(|| DaemonLaunchError::new("child_arguments"))?;
    let write = number(&args[7]).ok_or_else(|| DaemonLaunchError::new("child_arguments"))?;
    let job = args[9]
        .parse::<usize>()
        .map_err(|_| DaemonLaunchError::new("child_arguments"))?;
    let mut native = native::ChildOwnership::adopt(read, write, job)?;
    let mut packet = Zeroizing::new([0u8; PACKET]);
    native.read(&mut packet[..], started + Duration::from_secs(1))?;
    let startup_ms = u64::from_be_bytes(packet[8..16].try_into().expect("fixed packet"));
    let lifetime_ms = u64::from_be_bytes(packet[16..24].try_into().expect("fixed packet"));
    if packet[..8] != MAGIC[..]
        || packet[88..].iter().any(|b| *b != 0)
        || startup_ms == 0
        || startup_ms > 30_000
        || lifetime_ms != DEFAULT_DAEMON_LIFETIME.as_millis() as u64
    {
        return Err(DaemonLaunchError::new("child_packet"));
    }
    let startup_deadline = started + Duration::from_millis(startup_ms);
    let actual = Executable::current(startup_deadline)?;
    if actual.digest != packet[56..88] {
        return Err(DaemonLaunchError::new("child_executable"));
    }
    let mut nonce = Zeroizing::new([0u8; 32]);
    nonce.copy_from_slice(&packet[24..56]);
    Ok(DaemonOwnership {
        native,
        root,
        project,
        nonce,
        startup_deadline,
        lifetime_deadline: started + DEFAULT_DAEMON_LIFETIME,
        committed: false,
    })
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        fs::OpenOptions,
        mem::{size_of, size_of_val, zeroed},
        os::windows::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::{AsRawHandle, FromRawHandle},
        },
        ptr::{null, null_mut},
        rc::Rc,
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GENERIC_READ, GENERIC_WRITE,
            HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_OBJECT_0,
            WAIT_TIMEOUT,
        },
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_NORMAL,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_PIPE, GetDriveTypeW,
            GetFileInformationByHandle, GetFileType, OPEN_EXISTING, ReadFile, WriteFile,
        },
        System::{
            IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
            JobObjects::{
                CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
                JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
                QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
            },
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
                GetNamedPipeServerProcessId,
            },
            Threading::{
                CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateEventW,
                CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
                GetCurrentProcess, GetCurrentProcessId, InitializeProcThreadAttributeList,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST,
                PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW,
                UpdateProcThreadAttribute, WaitForSingleObject,
            },
        },
    };
    const IO_PENDING: i32 = 997;
    const IO_INCOMPLETE: i32 = 996;
    const PIPE_CONNECTED: i32 = 535;
    const FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const PIPE_REJECT_REMOTE: u32 = 8;
    const READ_CONTROL: u32 = 0x0002_0000;
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }
    fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }
    fn local_drive(path: &Path) -> Result<(), DaemonLaunchError> {
        let drive = match path.components().next() {
            Some(std::path::Component::Prefix(p)) => match p.kind() {
                std::path::Prefix::Disk(d) | std::path::Prefix::VerbatimDisk(d) => {
                    format!("{}:\\", char::from(d))
                }
                _ => return Err(DaemonLaunchError::new("nonlocal_executable")),
            },
            _ => return Err(DaemonLaunchError::new("nonlocal_executable")),
        };
        if unsafe { GetDriveTypeW(wide(std::ffi::OsStr::new(&drive)).as_ptr()) } != 3 {
            return Err(DaemonLaunchError::new("nonlocal_executable"));
        }
        Ok(())
    }
    pub(super) fn pin_executable_ancestors(path: &Path) -> Result<Vec<File>, DaemonLaunchError> {
        local_drive(path)?;
        let parts: Vec<_> = path.components().collect();
        if parts.len() < 3
            || parts.len() > 66
            || !matches!(parts[1], std::path::Component::RootDir)
            || parts[2..]
                .iter()
                .any(|p| !matches!(p, std::path::Component::Normal(_)))
        {
            return Err(DaemonLaunchError::new("executable_ancestors"));
        }
        let mut current = PathBuf::new();
        current.push(parts[0].as_os_str());
        current.push(parts[1].as_os_str());
        let mut pins = Vec::new();
        for (index, part) in parts.iter().enumerate().take(parts.len() - 1).skip(1) {
            if index > 1 {
                current.push(part.as_os_str());
            }
            let h = unsafe {
                CreateFileW(
                    wide(current.as_os_str()).as_ptr(),
                    READ_CONTROL,
                    FILE_SHARE_READ,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    null_mut(),
                )
            };
            if h == INVALID_HANDLE_VALUE {
                return Err(DaemonLaunchError::native("executable_ancestors"));
            }
            // Pin every actual ancestor without write/delete sharing, so an
            // approved leaf cannot be retargeted through a renamed directory.
            let file = unsafe { File::from_raw_handle(h) };
            let m = file
                .metadata()
                .map_err(|e| DaemonLaunchError::from_io("executable_ancestors", e))?;
            if !m.is_dir() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(DaemonLaunchError::new("executable_ancestors"));
            }
            pins.push(file);
        }
        Ok(pins)
    }
    pub(super) fn open_executable(path: &Path) -> Result<File, DaemonLaunchError> {
        local_drive(path)?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|e| DaemonLaunchError::from_io("executable_handle", e))?;
        if file
            .metadata()
            .map_err(|e| DaemonLaunchError::from_io("executable_handle", e))?
            .file_attributes()
            & FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(DaemonLaunchError::new("executable_handle"));
        }
        Ok(file)
    }
    pub(super) fn open_current_executable(path: &Path) -> Result<File, DaemonLaunchError> {
        open_executable(path)
    }
    fn identity(file: &File) -> Result<(u32, u32, u32), DaemonLaunchError> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(DaemonLaunchError::native("executable_identity"));
        }
        Ok((
            info.dwVolumeSerialNumber,
            info.nFileIndexHigh,
            info.nFileIndexLow,
        ))
    }
    pub(super) fn same_file(file: &File, path: &Path) -> Result<bool, DaemonLaunchError> {
        Ok(identity(file)? == identity(&open_executable(path)?)?)
    }
    struct Attributes(Vec<usize>);
    impl Attributes {
        fn ptr(&mut self) -> *mut std::ffi::c_void {
            self.0.as_mut_ptr().cast()
        }
        fn new() -> Result<Self, DaemonLaunchError> {
            let mut bytes = 0;
            unsafe {
                InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut bytes);
            }
            if bytes == 0 {
                return Err(DaemonLaunchError::native("native_attributes"));
            }
            let mut v = vec![0usize; bytes.div_ceil(size_of::<usize>())];
            if unsafe { InitializeProcThreadAttributeList(v.as_mut_ptr().cast(), 2, 0, &mut bytes) }
                == 0
            {
                return Err(DaemonLaunchError::native("native_attributes"));
            }
            Ok(Self(v))
        }
    }
    impl Drop for Attributes {
        fn drop(&mut self) {
            unsafe {
                DeleteProcThreadAttributeList(self.ptr());
            }
        }
    }
    fn private(h: &Handle) -> Result<(), DaemonLaunchError> {
        if unsafe { SetHandleInformation(h.0, HANDLE_FLAG_INHERIT, 0) } == 0 {
            Err(DaemonLaunchError::native("startup_pipe"))
        } else {
            Ok(())
        }
    }
    // Both endpoints are connected by this process before either is inherited.
    // A generated name is never published or used as a bearer capability.
    fn pipe(deadline: Instant) -> Result<(Rc<Handle>, Rc<Handle>), DaemonLaunchError> {
        check(deadline)?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| DaemonLaunchError::new("startup_pipe_nonce"))?;
        let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let name = wide(std::ffi::OsStr::new(&format!(
            r"\\.\pipe\MMMM.daemon.startup.{suffix}"
        )));
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let r = Rc::new(Handle(unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                1 | FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_REJECT_REMOTE,
                1,
                4096,
                4096,
                0,
                &sa,
            )
        }));
        if r.0 == INVALID_HANDLE_VALUE {
            return Err(DaemonLaunchError::native("startup_pipe"));
        }
        let w = Rc::new(Handle(unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                0,
                &sa,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | 0x0010_0000 | 0x0001_0000,
                null_mut(),
            )
        }));
        if w.0 == INVALID_HANDLE_VALUE {
            return Err(DaemonLaunchError::native("startup_pipe"));
        }
        // A heap owner handles even an unexpected pending Connect. Its status,
        // buffer and handles cannot drop while native completion is unproven.
        io(&r, &mut [], IoKind::Connect, deadline)?;
        let (mut client, mut server) = (0, 0);
        let pid = unsafe { GetCurrentProcessId() };
        if unsafe { GetNamedPipeClientProcessId(r.0, &mut client) } == 0
            || unsafe { GetNamedPipeServerProcessId(w.0, &mut server) } == 0
        {
            return Err(DaemonLaunchError::native("startup_pipe_identity"));
        }
        if client != pid || server != pid {
            return Err(DaemonLaunchError::new("startup_pipe_identity"));
        }
        Ok((r, w))
    }
    // Launch/adoption and overlapped I/O are driven on their owning thread.
    // The operation shares the pipe only to retain it through native completion.
    struct IoState {
        pipe: Rc<Handle>,
        event: Handle,
        overlapped: std::cell::UnsafeCell<OVERLAPPED>,
        buffer: Zeroizing<Vec<u8>>,
    }
    struct IoOwner {
        state: Option<Box<IoState>>,
        pending: bool,
    }
    impl IoOwner {
        fn new(pipe: &Rc<Handle>, size: usize) -> Result<Self, DaemonLaunchError> {
            let event = Handle(unsafe { CreateEventW(null(), 1, 0, null()) });
            if event.0.is_null() {
                return Err(DaemonLaunchError::native("startup_io_event"));
            }
            let mut overlapped: OVERLAPPED = unsafe { zeroed() };
            overlapped.hEvent = event.0;
            Ok(Self {
                state: Some(Box::new(IoState {
                    pipe: pipe.clone(),
                    event,
                    overlapped: std::cell::UnsafeCell::new(overlapped),
                    buffer: Zeroizing::new(vec![0u8; size]),
                })),
                pending: false,
            })
        }
        fn retain(&mut self) {
            UNCERTAIN.store(true, Ordering::Release);
            if let Some(state) = self.state.take() {
                std::mem::forget(state);
            }
            self.pending = false;
        }
    }
    impl Drop for IoOwner {
        fn drop(&mut self) {
            if self.pending {
                self.retain();
            }
        }
    }
    enum Completion {
        Terminal(Result<usize, DaemonLaunchError>),
        Unproven(Option<DaemonLaunchError>),
    }
    fn completion(state: &IoState) -> Completion {
        let mut n = 0;
        // UnsafeCell supplies a raw pointer; Rust never creates an immutable
        // reference to OVERLAPPED while the kernel may mutate its status.
        if unsafe { GetOverlappedResult(state.pipe.0, state.overlapped.get(), &mut n, 0) } != 0 {
            return Completion::Terminal(Ok(n as usize));
        }
        let first = std::io::Error::last_os_error();
        if first.raw_os_error() == Some(IO_INCOMPLETE) {
            return Completion::Unproven(None);
        }
        // Query failure alone is not terminal proof. Require this operation's
        // private event plus a stable native terminal result before release.
        if unsafe { WaitForSingleObject(state.event.0, 0) } != WAIT_OBJECT_0 {
            return Completion::Unproven(Some(DaemonLaunchError::from_io("startup_io", first)));
        }
        if unsafe { GetOverlappedResult(state.pipe.0, state.overlapped.get(), &mut n, 0) } != 0 {
            return Completion::Terminal(Ok(n as usize));
        }
        let second = std::io::Error::last_os_error();
        if second.raw_os_error() == first.raw_os_error()
            && second.raw_os_error() != Some(IO_INCOMPLETE)
        {
            Completion::Terminal(Err(DaemonLaunchError::from_io("startup_io", second)))
        } else {
            Completion::Unproven(Some(DaemonLaunchError::from_io("startup_io", second)))
        }
    }
    fn io_wait_millis(deadline: Instant, now: Instant) -> Option<u32> {
        let remaining = deadline.checked_duration_since(now)?;
        if remaining.is_zero() {
            return None;
        }
        // Round down: a final partial millisecond permits only a nonblocking
        // completion poll, never a wait extending the original I/O budget.
        Some(remaining.as_millis().min(POLL.as_millis()) as u32)
    }
    fn cancel_io(
        owner: &mut IoOwner,
        reason: DaemonLaunchError,
        deadline: Instant,
    ) -> Result<usize, DaemonLaunchError> {
        let state = owner
            .state
            .as_ref()
            .ok_or_else(|| DaemonLaunchError::new("native_io_uncertain"))?;
        unsafe {
            CancelIoEx(state.pipe.0, state.overlapped.get());
        }
        loop {
            let state = owner
                .state
                .as_ref()
                .ok_or_else(|| DaemonLaunchError::new("native_io_uncertain"))?;
            if let Completion::Terminal(_) = completion(state) {
                owner.pending = false;
                return Err(reason);
            }
            let Some(wait) = io_wait_millis(deadline, Instant::now()) else {
                owner.retain();
                let mut error = DaemonLaunchError::new("native_io_uncertain");
                error.cause = Some(reason.code);
                error.native_code = reason.native_code;
                return Err(error);
            };
            // Cancellation is a request, not proof. This event belongs to the
            // retained operation; actual completion is queried after each wait.
            unsafe {
                WaitForSingleObject(state.event.0, wait);
            }
        }
    }
    #[derive(Clone, Copy)]
    enum IoKind {
        Connect,
        Read,
        Write,
    }
    fn io(
        pipe: &Rc<Handle>,
        bytes: &mut [u8],
        kind: IoKind,
        deadline: Instant,
    ) -> Result<usize, DaemonLaunchError> {
        check(deadline)?;
        if UNCERTAIN.load(Ordering::Acquire) {
            return Err(DaemonLaunchError::new("native_io_uncertain"));
        }
        let mut owner = IoOwner::new(pipe, bytes.len())?;
        let state = owner
            .state
            .as_mut()
            .ok_or_else(|| DaemonLaunchError::new("native_io_uncertain"))?;
        if matches!(kind, IoKind::Write) {
            state.buffer.copy_from_slice(bytes);
        }
        let ok = unsafe {
            match kind {
                IoKind::Connect => ConnectNamedPipe(state.pipe.0, state.overlapped.get()),
                IoKind::Read => ReadFile(
                    state.pipe.0,
                    state.buffer.as_mut_ptr(),
                    state.buffer.len() as u32,
                    null_mut(),
                    state.overlapped.get(),
                ),
                IoKind::Write => WriteFile(
                    state.pipe.0,
                    state.buffer.as_ptr(),
                    state.buffer.len() as u32,
                    null_mut(),
                    state.overlapped.get(),
                ),
            }
        };
        if ok == 0 {
            let error = std::io::Error::last_os_error();
            if matches!(kind, IoKind::Connect) && error.raw_os_error() == Some(PIPE_CONNECTED) {
                check(deadline)?;
                return Ok(0);
            }
            if error.raw_os_error() != Some(IO_PENDING) {
                return Err(DaemonLaunchError::from_io("startup_io", error));
            }
            owner.pending = true;
        }
        loop {
            let state = owner
                .state
                .as_ref()
                .ok_or_else(|| DaemonLaunchError::new("native_io_uncertain"))?;
            let query = match completion(state) {
                Completion::Terminal(result) => {
                    owner.pending = false;
                    let n = result?;
                    check(deadline)?;
                    if matches!(kind, IoKind::Connect) {
                        return Ok(0);
                    }
                    if n == 0 || n > bytes.len() {
                        return Err(DaemonLaunchError::new("startup_io_count"));
                    }
                    if matches!(kind, IoKind::Read) {
                        let state = owner.state.as_ref().expect("terminal I/O owner");
                        bytes[..n].copy_from_slice(&state.buffer[..n]);
                    }
                    return Ok(n);
                }
                Completion::Unproven(error) => error,
            };
            owner.pending = true;
            if let Some(error) = query.or_else(|| check(deadline).err()) {
                return cancel_io(&mut owner, error, deadline);
            }
            let Some(wait) = io_wait_millis(deadline, Instant::now()) else {
                return cancel_io(&mut owner, DaemonLaunchError::new("deadline"), deadline);
            };
            let state = owner
                .state
                .as_ref()
                .ok_or_else(|| DaemonLaunchError::new("native_io_uncertain"))?;
            if !matches!(
                unsafe { WaitForSingleObject(state.event.0, wait) },
                WAIT_OBJECT_0 | WAIT_TIMEOUT
            ) {
                let error = DaemonLaunchError::native("startup_io_observe");
                return cancel_io(&mut owner, error, deadline);
            }
        }
    }
    fn read(h: &Rc<Handle>, bytes: &mut [u8], deadline: Instant) -> Result<(), DaemonLaunchError> {
        let mut offset = 0;
        while offset < bytes.len() {
            offset += io(h, &mut bytes[offset..], IoKind::Read, deadline)?;
        }
        Ok(())
    }
    fn write(h: &Rc<Handle>, bytes: &[u8], deadline: Instant) -> Result<(), DaemonLaunchError> {
        if bytes.len() > PACKET {
            return Err(DaemonLaunchError::new("startup_pipe"));
        }
        let mut copy = Zeroizing::new(bytes.to_vec());
        let n = io(h, &mut copy, IoKind::Write, deadline)?;
        if n != bytes.len() {
            return Err(DaemonLaunchError::new("startup_io_count"));
        }
        Ok(())
    }
    fn quote(value: &std::ffi::OsStr) -> Result<String, DaemonLaunchError> {
        let s = value
            .to_str()
            .ok_or_else(|| DaemonLaunchError::new("native_arguments"))?;
        if s.contains('\0') {
            return Err(DaemonLaunchError::new("native_arguments"));
        }
        let mut out = String::from("\"");
        let mut backslashes = 0;
        for c in s.chars() {
            if c == '\\' {
                backslashes += 1;
                continue;
            }
            out.extend(std::iter::repeat_n(
                '\\',
                if c == '"' {
                    backslashes * 2 + 1
                } else {
                    backslashes
                },
            ));
            backslashes = 0;
            out.push(c);
        }
        out.extend(std::iter::repeat_n('\\', backslashes * 2));
        out.push('"');
        Ok(out)
    }
    pub(super) struct Process {
        job: Handle,
        leader: Handle,
        thread: Option<Handle>,
        read: Option<Rc<Handle>>,
        write: Option<Rc<Handle>>,
        pid: u32,
    }
    impl Process {
        pub(super) fn spawn(
            executable: &Executable,
            root: &Path,
            project: &ProjectId,
            packet: &[u8],
            deadline: Instant,
        ) -> Result<Self, DaemonLaunchError> {
            check(deadline)?;
            let sa = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: null_mut(),
                bInheritHandle: 1,
            };
            // The suspended child must not inherit this Job handle. Parent
            // abrupt death before Resume then closes the sole handle and kills
            // the child. Only the already-running verified child receives it.
            let job = Handle(unsafe { CreateJobObjectW(null(), null()) });
            if job.0.is_null() {
                return Err(DaemonLaunchError::native("native_job"));
            }
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_JOB_MEMORY;
            limits.BasicLimitInformation.ActiveProcessLimit = 16;
            limits.JobMemoryLimit = 512 * 1024 * 1024;
            if unsafe {
                SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of_val(&limits) as u32,
                )
            } == 0
            {
                return Err(DaemonLaunchError::native("native_job"));
            }
            let (child_read, parent_write) = pipe(deadline)?;
            private(&parent_write)?;
            let (parent_read, child_write) = pipe(deadline)?;
            private(&parent_read)?;
            write(&parent_write, packet, deadline)?;
            let nul = Handle(unsafe {
                CreateFileW(
                    wide(std::ffi::OsStr::new("NUL")).as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    &sa,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    null_mut(),
                )
            });
            if nul.0 == INVALID_HANDLE_VALUE {
                return Err(DaemonLaunchError::native("native_stdio"));
            }
            let mut handles = [child_read.0, child_write.0, nul.0];
            let mut jobs = [job.0];
            let mut attrs = Attributes::new()?;
            if unsafe {
                UpdateProcThreadAttribute(
                    attrs.ptr(),
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_mut_ptr().cast(),
                    size_of_val(&handles),
                    null_mut(),
                    null_mut(),
                )
            } == 0
                || unsafe {
                    UpdateProcThreadAttribute(
                        attrs.ptr(),
                        0,
                        PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                        jobs.as_mut_ptr().cast(),
                        size_of_val(&jobs),
                        null_mut(),
                        null_mut(),
                    )
                } == 0
            {
                return Err(DaemonLaunchError::native("native_attributes"));
            }
            let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
            startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = nul.0;
            startup.StartupInfo.hStdOutput = nul.0;
            startup.StartupInfo.hStdError = nul.0;
            startup.lpAttributeList = attrs.ptr();
            let cmd = format!(
                "{} {DAEMON_CHILD_COMMAND} --data-root {} --project {} --bootstrap-read {} --bootstrap-write {} --job 0",
                quote(executable.path.as_os_str())?,
                quote(root.as_os_str())?,
                quote(std::ffi::OsStr::new(project.as_str()))?,
                child_read.0 as usize,
                child_write.0 as usize
            );
            let mut cmd = wide(std::ffi::OsStr::new(&cmd));
            if cmd.len() > 32767 {
                return Err(DaemonLaunchError::new("native_arguments"));
            }
            let environment = [0u16, 0];
            let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
            if unsafe {
                CreateProcessW(
                    wide(executable.path.as_os_str()).as_ptr(),
                    cmd.as_mut_ptr(),
                    null(),
                    null(),
                    1,
                    CREATE_SUSPENDED
                        | CREATE_NO_WINDOW
                        | CREATE_UNICODE_ENVIRONMENT
                        | EXTENDED_STARTUPINFO_PRESENT,
                    environment.as_ptr().cast(),
                    null(),
                    &startup.StartupInfo,
                    &mut info,
                )
            } == 0
            {
                return Err(DaemonLaunchError::native("native_spawn"));
            }
            Ok(Self {
                job,
                leader: Handle(info.hProcess),
                thread: Some(Handle(info.hThread)),
                read: Some(parent_read),
                write: Some(parent_write),
                pid: info.dwProcessId,
            })
        }
        pub(super) fn id(&self) -> u32 {
            self.pid
        }
        pub(super) fn activate(
            &mut self,
            executable: &Executable,
        ) -> Result<(), DaemonLaunchError> {
            let mut inside = 0;
            if unsafe { IsProcessInJob(self.leader.0, self.job.0, &mut inside) } == 0 {
                return Err(DaemonLaunchError::native("native_identity"));
            }
            if inside == 0 || !same_file(&executable.file, &executable.path)? {
                return Err(DaemonLaunchError::new("native_identity"));
            }
            let thread = self
                .thread
                .as_ref()
                .ok_or_else(|| DaemonLaunchError::new("native_thread"))?;
            if unsafe { ResumeThread(thread.0) } != 1 {
                return Err(DaemonLaunchError::native("native_resume"));
            }
            drop(self.thread.take());
            Ok(())
        }
        pub(super) fn require_alive(&self) -> Result<(), DaemonLaunchError> {
            match unsafe { WaitForSingleObject(self.leader.0, 0) } {
                WAIT_TIMEOUT => Ok(()),
                WAIT_OBJECT_0 => Err(DaemonLaunchError::new("child_exited")),
                _ => Err(DaemonLaunchError::native("native_observe")),
            }
        }
        pub(super) fn read(&mut self, b: &mut [u8], d: Instant) -> Result<(), DaemonLaunchError> {
            read(
                self.read
                    .as_ref()
                    .ok_or_else(|| DaemonLaunchError::new("startup_pipe"))?,
                b,
                d,
            )
        }
        pub(super) fn write(&mut self, b: &[u8], d: Instant) -> Result<(), DaemonLaunchError> {
            write(
                self.write
                    .as_ref()
                    .ok_or_else(|| DaemonLaunchError::new("startup_pipe"))?,
                b,
                d,
            )
        }
        pub(super) fn commit_packet(&mut self) -> Result<[u8; 9], DaemonLaunchError> {
            self.require_alive()?;
            let mut remote = null_mut();
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    self.job.0,
                    self.leader.0,
                    &mut remote,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                return Err(DaemonLaunchError::native("native_owner_transfer"));
            }
            let mut packet = [0u8; 9];
            packet[0] = 1;
            packet[1..].copy_from_slice(&(remote as usize as u64).to_be_bytes());
            Ok(packet)
        }
        pub(super) fn transfer(&mut self) -> Result<(), DaemonLaunchError> {
            self.require_alive()?;
            drop(self.read.take());
            drop(self.write.take());
            Ok(())
        }
        pub(super) fn terminate(&mut self) -> Result<(), DaemonLaunchError> {
            if unsafe { TerminateJobObject(self.job.0, 124) } == 0 {
                Err(DaemonLaunchError::native("native_terminate"))
            } else {
                Ok(())
            }
        }
        pub(super) fn cancel_and_drain(
            &mut self,
            deadline: Instant,
        ) -> Result<(), DaemonLaunchError> {
            self.terminate()?;
            loop {
                check(deadline)?;
                let mut a: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
                if unsafe {
                    QueryInformationJobObject(
                        self.job.0,
                        JobObjectBasicAccountingInformation,
                        (&mut a as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                        size_of_val(&a) as u32,
                        null_mut(),
                    )
                } == 0
                {
                    return Err(DaemonLaunchError::native("native_observe"));
                }
                if unsafe { WaitForSingleObject(self.leader.0, 0) } == WAIT_OBJECT_0
                    && a.ActiveProcesses == 0
                {
                    return check(deadline);
                }
                std::thread::sleep(POLL);
            }
        }
    }
    pub(super) struct ChildOwnership {
        job: Option<Handle>,
        read: Option<Rc<Handle>>,
        write: Option<Rc<Handle>>,
    }
    impl ChildOwnership {
        pub(super) fn adopt(
            read_value: usize,
            write_value: usize,
            job_value: usize,
        ) -> Result<Self, DaemonLaunchError> {
            if job_value != 0 || read_value == write_value {
                return Err(DaemonLaunchError::new("child_owner"));
            }
            let r = read_value as HANDLE;
            let w = write_value as HANDLE;
            let mut inside = 0;
            if unsafe { GetFileType(r) } != FILE_TYPE_PIPE
                || unsafe { GetFileType(w) } != FILE_TYPE_PIPE
            {
                return Err(DaemonLaunchError::new("child_owner"));
            }
            if unsafe { IsProcessInJob(GetCurrentProcess(), null_mut(), &mut inside) } == 0 {
                return Err(DaemonLaunchError::native("child_owner"));
            }
            if inside == 0 {
                return Err(DaemonLaunchError::new("child_owner"));
            }
            let result = Self {
                job: None,
                read: Some(Rc::new(Handle(r))),
                write: Some(Rc::new(Handle(w))),
            };
            private(result.read.as_ref().expect("owned read"))?;
            private(result.write.as_ref().expect("owned write"))?;
            Ok(result)
        }
        pub(super) fn adopt_committed(&mut self, bytes: &[u8]) -> Result<(), DaemonLaunchError> {
            if self.job.is_some() || bytes.len() != 8 {
                return Err(DaemonLaunchError::new("child_owner_transfer"));
            }
            let value = u64::from_be_bytes(bytes.try_into().expect("fixed owner frame"));
            let value = usize::try_from(value)
                .map_err(|_| DaemonLaunchError::new("child_owner_transfer"))?;
            if value == 0 || value == usize::MAX {
                return Err(DaemonLaunchError::new("child_owner_transfer"));
            }
            let j = value as HANDLE;
            let mut inside = 0;
            if unsafe { IsProcessInJob(GetCurrentProcess(), j, &mut inside) } == 0 {
                return Err(DaemonLaunchError::native("child_owner_transfer"));
            }
            if inside == 0 {
                return Err(DaemonLaunchError::new("child_owner_transfer"));
            }
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
            if unsafe {
                QueryInformationJobObject(
                    j,
                    JobObjectExtendedLimitInformation,
                    (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of_val(&limits) as u32,
                    null_mut(),
                )
            } == 0
            {
                return Err(DaemonLaunchError::native("child_owner_transfer"));
            }
            if limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 {
                return Err(DaemonLaunchError::new("child_owner_transfer"));
            }
            let handle = Handle(j);
            private(&handle)?;
            self.job = Some(handle);
            Ok(())
        }
        pub(super) fn read(&mut self, b: &mut [u8], d: Instant) -> Result<(), DaemonLaunchError> {
            read(
                self.read
                    .as_ref()
                    .ok_or_else(|| DaemonLaunchError::new("startup_pipe"))?,
                b,
                d,
            )
        }
        pub(super) fn write(&mut self, b: &[u8], d: Instant) -> Result<(), DaemonLaunchError> {
            write(
                self.write
                    .as_ref()
                    .ok_or_else(|| DaemonLaunchError::new("startup_pipe"))?,
                b,
                d,
            )
        }
        pub(super) fn close_startup(&mut self) {
            drop(self.read.take());
            drop(self.write.take());
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn io_wait_keeps_the_original_deadline_at_expiry_and_submillisecond_boundary() {
            let started = Instant::now();
            let deadline = started + Duration::from_millis(37);
            assert_eq!(io_wait_millis(deadline, started), Some(5));
            assert_eq!(
                io_wait_millis(deadline, started + Duration::from_millis(33)),
                Some(4)
            );
            assert_eq!(
                io_wait_millis(
                    deadline,
                    started + Duration::from_millis(36) + Duration::from_nanos(1)
                ),
                Some(0)
            );
            assert_eq!(io_wait_millis(deadline, deadline), None);
            assert_eq!(
                io_wait_millis(deadline, deadline + Duration::from_nanos(1)),
                None
            );
        }
    }
}
#[cfg(unix)]
mod native {
    use super::*;
    use std::{
        fs::OpenOptions,
        io::Write,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                fs::{MetadataExt, OpenOptionsExt},
                process::CommandExt,
            },
        },
        process::{Child, Command, Stdio},
    };

    pub(super) fn open_executable(path: &Path) -> Result<File, DaemonLaunchError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| DaemonLaunchError::from_io("executable_handle", e))?;
        verified_executable(file)
    }
    fn verified_executable(file: File) -> Result<File, DaemonLaunchError> {
        let m = file
            .metadata()
            .map_err(|e| DaemonLaunchError::from_io("executable_handle", e))?;
        if !m.is_file() || m.mode() & 0o022 != 0 {
            return Err(DaemonLaunchError::new("executable_handle"));
        }
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } == -1 {
            return Err(DaemonLaunchError::native("nonlocal_executable"));
        }
        #[cfg(target_os = "linux")]
        if matches!(
            filesystem.f_type as u64,
            0x6969
                | 0x517b
                | 0xff534d42
                | 0xfe534d42
                | 0x73757245
                | 0x5346414f
                | 0x01021997
                | 0x65735546
        ) {
            return Err(DaemonLaunchError::new("nonlocal_executable"));
        }
        #[cfg(target_os = "macos")]
        if filesystem.f_flags & libc::MNT_LOCAL as u32 == 0 {
            return Err(DaemonLaunchError::new("nonlocal_executable"));
        }
        Ok(file)
    }
    pub(super) fn open_current_executable(path: &Path) -> Result<File, DaemonLaunchError> {
        #[cfg(target_os = "linux")]
        {
            // Kernel-owned self-image selector, not a caller path or symlink.
            // The running executable inode is write-excluded by Linux. The
            // public locator must still match this held inode before launch.
            let _ = path;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC)
                .open("/proc/self/exe")
                .map_err(|e| DaemonLaunchError::from_io("current_executable", e))?;
            verified_executable(file)
        }
        #[cfg(target_os = "macos")]
        {
            open_executable(path)
        }
    }
    pub(super) fn pin_executable_ancestors(_: &Path) -> Result<Vec<File>, DaemonLaunchError> {
        // Linux fexecve uses the open inode directly. New macOS path execution
        // is explicitly unavailable; descriptor pins would not prevent rename.
        Ok(Vec::new())
    }
    pub(super) fn same_file(file: &File, path: &Path) -> Result<bool, DaemonLaunchError> {
        let a = file
            .metadata()
            .map_err(|_| DaemonLaunchError::new("executable_identity"))?;
        let b = open_executable(path)?
            .metadata()
            .map_err(|_| DaemonLaunchError::new("executable_identity"))?;
        Ok(a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec())
    }
    fn pipe() -> Result<(File, File), DaemonLaunchError> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
            return Err(DaemonLaunchError::native("startup_pipe"));
        }
        let r = unsafe { File::from_raw_fd(fds[0]) };
        let w = unsafe { File::from_raw_fd(fds[1]) };
        for fd in fds {
            if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1
                || unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } == -1
            {
                return Err(DaemonLaunchError::native("startup_pipe"));
            }
        }
        Ok((r, w))
    }
    fn read(file: &mut File, bytes: &mut [u8], deadline: Instant) -> Result<(), DaemonLaunchError> {
        let mut n = 0;
        while n < bytes.len() {
            check(deadline)?;
            match file.read(&mut bytes[n..]) {
                Ok(0) => return Err(DaemonLaunchError::new("startup_pipe")),
                Ok(count) => n += count,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(POLL),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
                Err(e) => return Err(DaemonLaunchError::from_io("startup_pipe", e)),
            }
        }
        check(deadline)
    }
    fn write(file: &mut File, bytes: &[u8], deadline: Instant) -> Result<(), DaemonLaunchError> {
        check(deadline)?;
        if bytes.len() > PACKET {
            return Err(DaemonLaunchError::new("startup_pipe"));
        }
        // One owned writer, total protocol bytes below POSIX PIPE_BUF minimum.
        // A nonblocking atomic write cannot wait on external input or output.
        match file.write(bytes) {
            Ok(n) if n == bytes.len() => check(deadline),
            Ok(_) => Err(DaemonLaunchError::new("startup_pipe_count")),
            Err(e) => Err(DaemonLaunchError::from_io("startup_pipe", e)),
        }
    }
    pub(super) struct Process {
        child: Child,
        pid: libc::pid_t,
        read: Option<File>,
        write: Option<File>,
        reserved: bool,
        #[cfg(target_os = "macos")]
        identity: (u64, u64),
    }
    impl Process {
        pub(super) fn spawn(
            executable: &Executable,
            root: &Path,
            project: &ProjectId,
            packet: &[u8],
            deadline: Instant,
        ) -> Result<Self, DaemonLaunchError> {
            check(deadline)?;
            if cfg!(target_os = "macos") {
                return Err(DaemonLaunchError::new(
                    "macos_exact_executable_launch_unavailable",
                ));
            }
            let (child_read, mut parent_write) = pipe()?;
            let (parent_read, child_write) = pipe()?;
            write(&mut parent_write, packet, deadline)?;
            let r = child_read.as_raw_fd();
            let w = child_write.as_raw_fd();
            let args = vec![
                std::ffi::OsString::from(DAEMON_CHILD_COMMAND),
                std::ffi::OsString::from("--data-root"),
                root.as_os_str().to_owned(),
                std::ffi::OsString::from("--project"),
                std::ffi::OsString::from(project.as_str()),
                std::ffi::OsString::from("--bootstrap-read"),
                std::ffi::OsString::from(r.to_string()),
                std::ffi::OsString::from("--bootstrap-write"),
                std::ffi::OsString::from(w.to_string()),
                std::ffi::OsString::from("--job"),
                std::ffi::OsString::from("0"),
            ];
            let mut command = Command::new(&executable.path);
            command
                .args(&args)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            #[cfg(target_os = "macos")]
            let max_fd = {
                let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
                if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == -1
                    || limit.rlim_cur > 65_536
                {
                    return Err(DaemonLaunchError::new("native_descriptors"));
                }
                limit.rlim_cur as i32
            };
            #[cfg(target_os = "linux")]
            let exec_fd = executable.file.as_raw_fd();
            #[cfg(target_os = "linux")]
            let strings: Vec<std::ffi::CString> = {
                use std::os::unix::ffi::OsStrExt;
                std::iter::once(executable.path.as_os_str())
                    .chain(args.iter().map(|a| a.as_os_str()))
                    .map(|a| {
                        std::ffi::CString::new(a.as_bytes())
                            .map_err(|_| DaemonLaunchError::new("native_arguments"))
                    })
                    .collect::<Result<_, _>>()?
            };
            #[cfg(target_os = "linux")]
            let pointers: Vec<usize> = strings
                .iter()
                .map(|a| a.as_ptr() as usize)
                .chain(Some(0))
                .collect();
            // Only preallocated pointers and async-signal-safe native syscalls
            // run after fork. No inherited application descriptors survive exec.
            unsafe {
                command.pre_exec(move || {
                    if libc::setsid() == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    #[cfg(target_os = "linux")]
                    if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) == -1 {
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
                    if libc::fcntl(r, libc::F_SETFD, 0) == -1
                        || libc::fcntl(w, libc::F_SETFD, 0) == -1
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    let memory = libc::rlimit {
                        rlim_cur: 512 * 1024 * 1024,
                        rlim_max: 512 * 1024 * 1024,
                    };
                    let core = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    let cpu = libc::rlimit {
                        rlim_cur: 1800,
                        rlim_max: 1800,
                    };
                    if libc::setrlimit(libc::RLIMIT_AS, &memory) == -1
                        || libc::setrlimit(libc::RLIMIT_CORE, &core) == -1
                        || libc::setrlimit(libc::RLIMIT_CPU, &cpu) == -1
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    #[cfg(target_os = "linux")]
                    {
                        let env = [std::ptr::null::<libc::c_char>()];
                        libc::fexecve(exec_fd, pointers.as_ptr().cast(), env.as_ptr());
                        Err(std::io::Error::last_os_error())
                    }
                    #[cfg(target_os = "macos")]
                    Ok(())
                });
            }
            let child = command
                .spawn()
                .map_err(|e| DaemonLaunchError::from_io("native_spawn", e))?;
            let pid = child.id() as i32;
            // The child cannot pass READY until these parent-only references
            // have dropped; all remaining handles have exactly one writer.
            drop(child_read);
            drop(child_write);
            Ok(Self {
                child,
                pid,
                read: Some(parent_read),
                write: Some(parent_write),
                reserved: true,
                #[cfg(target_os = "macos")]
                identity: (0, 0),
            })
        }
        pub(super) fn id(&self) -> u32 {
            self.pid as u32
        }
        pub(super) fn activate(
            &mut self,
            executable: &Executable,
        ) -> Result<(), DaemonLaunchError> {
            self.require_alive()?;
            if unsafe { libc::getsid(self.pid) } != self.pid
                || unsafe { libc::getpgid(self.pid) } != self.pid
                || !same_file(&executable.file, &executable.path)?
            {
                return Err(DaemonLaunchError::new("native_identity"));
            }
            #[cfg(target_os = "macos")]
            {
                let info = bsd_info(self.pid, true)?
                    .ok_or_else(|| DaemonLaunchError::new("native_identity"))?;
                if info.pid != self.id() || info.pgid != self.id() {
                    return Err(DaemonLaunchError::new("native_identity"));
                }
                self.identity = (info.start_sec, info.start_usec);
            }
            Ok(())
        }
        fn exited(&self) -> Result<bool, DaemonLaunchError> {
            if !self.reserved {
                return Err(DaemonLaunchError::new("native_identity"));
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
                return Err(DaemonLaunchError::new("native_observe"));
            }
            #[cfg(target_os = "linux")]
            let pid = unsafe { info.si_pid() };
            #[cfg(target_os = "macos")]
            let pid = info.si_pid;
            Ok(pid != 0)
        }
        pub(super) fn require_alive(&self) -> Result<(), DaemonLaunchError> {
            if self.exited()? {
                Err(DaemonLaunchError::new("child_exited"))
            } else {
                Ok(())
            }
        }
        pub(super) fn read(&mut self, b: &mut [u8], d: Instant) -> Result<(), DaemonLaunchError> {
            read(
                self.read
                    .as_mut()
                    .ok_or_else(|| DaemonLaunchError::new("startup_pipe"))?,
                b,
                d,
            )
        }
        pub(super) fn write(&mut self, b: &[u8], d: Instant) -> Result<(), DaemonLaunchError> {
            write(
                self.write
                    .as_mut()
                    .ok_or_else(|| DaemonLaunchError::new("startup_pipe"))?,
                b,
                d,
            )
        }
        pub(super) fn transfer(&mut self) -> Result<(), DaemonLaunchError> {
            self.require_alive()?;
            drop(self.read.take());
            drop(self.write.take());
            Ok(())
        }
        pub(super) fn commit_packet(&mut self) -> Result<[u8; 9], DaemonLaunchError> {
            self.require_alive()?;
            let mut packet = [0u8; 9];
            packet[0] = 1;
            Ok(packet)
        }
        pub(super) fn terminate(&mut self) -> Result<(), DaemonLaunchError> {
            if !self.reserved {
                return Err(DaemonLaunchError::new("native_identity"));
            }
            // WNOWAIT keeps this child PID reserved until the whole group is
            // empty; a failed observation never authorizes a reused PID kill.
            let _ = self.exited()?;
            if unsafe { libc::kill(-self.pid, libc::SIGKILL) } == -1
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err(DaemonLaunchError::new("native_terminate"));
            }
            Ok(())
        }
        pub(super) fn cancel_and_drain(
            &mut self,
            deadline: Instant,
        ) -> Result<(), DaemonLaunchError> {
            self.terminate()?;
            loop {
                check(deadline)?;
                #[cfg(target_os = "linux")]
                let empty = linux_members(self.pid, deadline)? == 0;
                #[cfg(target_os = "macos")]
                let empty = mac_members(self.pid, self.identity, deadline)? == 0;
                if self.exited()? && empty {
                    self.child
                        .wait()
                        .map_err(|_| DaemonLaunchError::new("native_reap"))?;
                    self.reserved = false;
                    return check(deadline);
                }
                std::thread::sleep(POLL);
            }
        }
    }
    pub(super) struct ChildOwnership {
        read: Option<File>,
        write: Option<File>,
    }
    impl ChildOwnership {
        pub(super) fn adopt(
            read_value: usize,
            write_value: usize,
            job_value: usize,
        ) -> Result<Self, DaemonLaunchError> {
            let r = i32::try_from(read_value).map_err(|_| DaemonLaunchError::new("child_owner"))?;
            let w =
                i32::try_from(write_value).map_err(|_| DaemonLaunchError::new("child_owner"))?;
            let pid = unsafe { libc::getpid() };
            if job_value != 0
                || r == w
                || unsafe { libc::getsid(0) } != pid
                || unsafe { libc::getpgrp() } != pid
            {
                return Err(DaemonLaunchError::new("child_owner"));
            }
            for fd in [r, w] {
                let mut info: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(fd, &mut info) } == -1
                    || info.st_mode & libc::S_IFMT != libc::S_IFIFO
                {
                    return Err(DaemonLaunchError::new("child_owner"));
                }
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                if flags == -1
                    || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
                    || unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1
                {
                    return Err(DaemonLaunchError::new("child_owner"));
                }
            }
            Ok(Self {
                read: Some(unsafe { File::from_raw_fd(r) }),
                write: Some(unsafe { File::from_raw_fd(w) }),
            })
        }
        pub(super) fn read(&mut self, b: &mut [u8], d: Instant) -> Result<(), DaemonLaunchError> {
            read(
                self.read
                    .as_mut()
                    .ok_or_else(|| DaemonLaunchError::new("startup_pipe"))?,
                b,
                d,
            )
        }
        pub(super) fn adopt_committed(&mut self, bytes: &[u8]) -> Result<(), DaemonLaunchError> {
            if bytes.len() != 8 || bytes.iter().any(|b| *b != 0) {
                return Err(DaemonLaunchError::new("child_owner_transfer"));
            }
            let pid = unsafe { libc::getpid() };
            if unsafe { libc::getsid(0) } != pid || unsafe { libc::getpgrp() } != pid {
                return Err(DaemonLaunchError::new("child_owner_transfer"));
            }
            Ok(())
        }
        pub(super) fn write(&mut self, b: &[u8], d: Instant) -> Result<(), DaemonLaunchError> {
            write(
                self.write
                    .as_mut()
                    .ok_or_else(|| DaemonLaunchError::new("startup_pipe"))?,
                b,
                d,
            )
        }
        pub(super) fn close_startup(&mut self) {
            drop(self.read.take());
            drop(self.write.take());
        }
    }

    #[cfg(target_os = "linux")]
    fn linux_members(group: i32, deadline: Instant) -> Result<usize, DaemonLaunchError> {
        let mut members = 0;
        let mut leader = false;
        let mut count = 0;
        for entry in
            std::fs::read_dir("/proc").map_err(|_| DaemonLaunchError::new("native_observe"))?
        {
            check(deadline)?;
            count += 1;
            if count > 100_000 {
                return Err(DaemonLaunchError::new("native_observe_budget"));
            }
            let entry = entry.map_err(|_| DaemonLaunchError::new("native_observe"))?;
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
                Ok(_) if bytes.len() <= 8192 => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                _ => return Err(DaemonLaunchError::new("native_observe")),
            }
            let end = bytes
                .iter()
                .rposition(|b| *b == b')')
                .ok_or_else(|| DaemonLaunchError::new("native_identity"))?;
            let mut fields = bytes[end + 1..]
                .split(|b| b.is_ascii_whitespace())
                .filter(|b| !b.is_empty());
            let state = fields
                .next()
                .ok_or_else(|| DaemonLaunchError::new("native_identity"))?;
            let _ppid = fields.next();
            let parse = |b: Option<&[u8]>| {
                b.and_then(|b| std::str::from_utf8(b).ok())
                    .and_then(|s| s.parse::<i32>().ok())
                    .ok_or_else(|| DaemonLaunchError::new("native_identity"))
            };
            let pgid = parse(fields.next())?;
            let sid = parse(fields.next())?;
            if pid == group {
                if pgid != group || sid != group {
                    return Err(DaemonLaunchError::new("native_identity"));
                }
                leader = true;
            }
            let live = state != b"Z" && state != b"X";
            if sid == group && pgid != group && live {
                return Err(DaemonLaunchError::new("native_scope_escape"));
            }
            if pgid == group && live {
                members += 1;
            }
        }
        if !leader {
            return Err(DaemonLaunchError::new("native_identity"));
        }
        Ok(members)
    }
    // ABI is Apple's public proc_info.h PROC_PIDTBSDINFO=3 / SZOMB=5.
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
    fn bsd_info(pid: i32, zombie: bool) -> Result<Option<BsdInfo>, DaemonLaunchError> {
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
            return Err(DaemonLaunchError::new("native_observe"));
        }
        Ok(Some(info))
    }
    #[cfg(target_os = "macos")]
    fn mac_members(
        group: i32,
        identity: (u64, u64),
        deadline: Instant,
    ) -> Result<usize, DaemonLaunchError> {
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
            check(deadline)?;
            let mut pids = vec![0i32; capacity];
            let n = unsafe { proc_listpids(1, 0, pids.as_mut_ptr().cast(), (capacity * 4) as i32) };
            if n <= 0 || n % 4 != 0 {
                return Err(DaemonLaunchError::new("native_observe"));
            }
            if n as usize >= capacity * 4 {
                if capacity >= 100_000 {
                    return Err(DaemonLaunchError::new("native_observe_budget"));
                }
                capacity = (capacity * 2).min(100_000);
                continue;
            }
            pids.truncate(n as usize / 4);
            break pids;
        };
        let mut members = 0;
        let mut leader = false;
        for pid in pids.into_iter().filter(|p| *p > 0) {
            check(deadline)?;
            if pid == group {
                let a = bsd_info(pid, true)?
                    .ok_or_else(|| DaemonLaunchError::new("native_identity"))?;
                let b = bsd_info(pid, true)?
                    .ok_or_else(|| DaemonLaunchError::new("native_identity"))?;
                if a.pid != group as u32
                    || b.pid != group as u32
                    || a.pgid != group as u32
                    || b.pgid != group as u32
                    || (a.start_sec, a.start_usec) != identity
                    || (b.start_sec, b.start_usec) != identity
                {
                    return Err(DaemonLaunchError::new("native_identity"));
                }
                leader = true;
                if b.status != 5 {
                    members += 1;
                }
                continue;
            }
            let session = unsafe { libc::getsid(pid) };
            if session == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                continue;
            }
            if session == -1 {
                return Err(DaemonLaunchError::new("native_observe"));
            }
            if session != group {
                continue;
            }
            let Some(a) = bsd_info(pid, false)? else {
                continue;
            };
            let after_session = unsafe { libc::getsid(pid) };
            let Some(b) = bsd_info(pid, false)? else {
                continue;
            };
            if after_session != group
                || a.pid != pid as u32
                || b.pid != pid as u32
                || a.start_sec != b.start_sec
                || a.start_usec != b.start_usec
                || a.pgid != b.pgid
            {
                return Err(DaemonLaunchError::new("native_identity"));
            }
            if b.status != 5 {
                if b.pgid != group as u32 {
                    return Err(DaemonLaunchError::new("native_scope_escape"));
                }
                members += 1;
            }
        }
        if !leader {
            return Err(DaemonLaunchError::new("native_identity"));
        }
        Ok(members)
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!("Owned MMMM daemon startup requires native Unix or Windows primitives");

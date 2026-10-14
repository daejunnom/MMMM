//! Finite MCP stdio boundary. Blocking external stdio belongs exclusively to
//! an owned helper process; the Coordinator polls a private nonblocking socket.
//! Output is acknowledged only after the helper flushed the selected stdio.
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fs::File,
    io::{self, BufRead, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::{Duration, Instant},
};
use zeroize::Zeroize;

#[cfg(windows)]
#[path = "stdio_io_windows.rs"]
mod native;

#[cfg(target_os = "macos")]
pub use native::DarwinStdioResources;
#[cfg(unix)]
#[path = "stdio_io_unix.rs"]
mod native;

pub const WORKER_COMMAND: &str = "--mmmm-stdio-worker";
const MAGIC: &[u8; 8] = b"MMMMIO01";
const FRAME_LIMIT: usize = 1_048_576;
const WORK_BATCH: usize = 65_536;
// A completed native pipe write must fit a small finite sink range. Sending
// an entire 1 MiB transaction in one synchronous WriteFile can stay pending
// without leaving a completed observable prefix when its owner is terminated.
const EXTERNAL_WRITE_CHUNK: usize = 4096;
const QUEUE_LIMIT: usize = 4 * FRAME_LIMIT;
const HEADER: usize = 13;
const INPUT: u8 = 1;
const EOF: u8 = 2;
const ACK: u8 = 3;
const FAULT: u8 = 4;
const OUTPUT: u8 = 5;
const RAW_OUTPUT: u8 = 6;
const READ_EXACT: u8 = 7;
const RAW_INPUT: u8 = 8;
const TRUNCATED: u8 = 9;
const RAW_EOF: u8 = 10;
const RAW_MODE_FLAG: u64 = 1 << 63;
const STDERR_FLAG: u64 = 1 << 62;
const BOOTSTRAP_FLAGS: u64 = RAW_MODE_FLAG | STDERR_FLAG;
const BOOTSTRAP_LENGTH: usize = 104;
const WORKER_STAGES: &[&str] = &[
    "worker_arguments",
    "bootstrap_handle",
    "bootstrap_type",
    "bootstrap_peek",
    "bootstrap_length",
    "bootstrap_read",
    "bootstrap_pipe",
    "executable_path",
    "executable_open",
    "executable_metadata",
    "executable_limits",
    "executable_read",
    "executable_identity",
    "executable_changed",
    "limits",
    "worker_connect",
    "worker_hello",
    "worker_clone",
    "worker_thread",
    "external_stdio",
    "channel",
    "input_frame",
    "input_budget",
    "output_frame",
    "output_budget",
    "worker_io",
    "channel_frame",
    "deadline",
    "native_clock",
    "worker_unknown",
    "native_resource_budget",
    "native_resource_observation",
    "native_resource_identity",
    "native_resource_gap",
    "native_resource_admission",
    "native_resource_thread",
    "native_resource_watchdog_gap",
];
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Lines,
    Raw,
}

/// The authenticated bootstrap selects exactly one inherited standard sink.
/// The unused sink is null; a caller cannot provide an arbitrary descriptor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StdioOutput {
    #[default]
    Stdout,
    Stderr,
}

static OWNERSHIP_UNCERTAIN: AtomicBool = AtomicBool::new(false);
static OWNER_RESERVED: AtomicBool = AtomicBool::new(false);
// One uncertain native owner stays explicit until process shutdown. New
// workers are denied after this fatal condition; this is not a retry queue.
static RETAINED_PROCESS: Mutex<Option<native::Process>> = Mutex::new(None);

struct WorkerReservation;
impl WorkerReservation {
    fn acquire() -> Result<Self, StdioError> {
        if OWNER_RESERVED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(StdioError::new("owner_busy"));
        }
        if OWNERSHIP_UNCERTAIN.load(Ordering::Acquire) {
            OWNER_RESERVED.store(false, Ordering::Release);
            return Err(StdioError::new("ownership_uncertain"));
        }
        Ok(Self)
    }
}
impl Drop for WorkerReservation {
    fn drop(&mut self) {
        OWNER_RESERVED.store(false, Ordering::Release);
    }
}

fn retain_uncertain_process(process: native::Process) {
    OWNERSHIP_UNCERTAIN.store(true, Ordering::Release);
    let Ok(mut retained) = RETAINED_PROCESS.lock() else {
        std::process::abort();
    };
    if retained.is_some() {
        // Each native owner holds the sole reservation from before spawn.
        // A second owner here is an ownership invariant failure, not timeout.
        std::process::abort();
    }
    *retained = Some(process);
}

fn deadline_check(deadline: Instant) -> Result<(), StdioError> {
    if Instant::now() >= deadline {
        Err(StdioError::new("deadline"))
    } else {
        Ok(())
    }
}
fn drain_deadline_check(deadline: Instant) -> Result<(), StdioError> {
    if Instant::now() >= deadline {
        Err(StdioError::new("drain_uncertain"))
    } else {
        Ok(())
    }
}

fn cleanup_failed_process(mut process: native::Process, mut error: StdioError) -> StdioError {
    let deadline = process.owner_deadline();
    let result = process.drain_blocking(deadline);
    #[cfg(target_os = "macos")]
    {
        error.resources = Some(process.resource_evidence());
    }
    match result {
        Ok(()) => error.drained = true,
        Err(drain) => {
            error.drained = drain.drained;
            error.cleanup = Some(StdioCleanupFailure {
                code: drain.code,
                native_code: drain.native_code,
                native_code_unknown: drain.native_code_unknown,
            });
            if !drain.drained {
                retain_uncertain_process(process);
            }
        }
    }
    error
}

/// Deployment policy supplies finite limits; callers cannot expand them past
/// the supported product maxima. There is no background unbounded I/O task.
#[derive(Clone, Copy, Debug)]
pub struct StdioLimits {
    pub session: Duration,
    pub startup: Duration,
    pub max_frames: u64,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
}
impl Default for StdioLimits {
    fn default() -> Self {
        Self {
            session: Duration::from_secs(1800),
            startup: Duration::from_secs(5),
            max_frames: 4096,
            max_input_bytes: 64 * 1024 * 1024,
            max_output_bytes: 64 * 1024 * 1024,
        }
    }
}
impl StdioLimits {
    fn validate(self) -> Result<Self, StdioError> {
        if self.session < Duration::from_millis(1)
            || self.session > Duration::from_secs(3600)
            || self.startup.is_zero()
            || self.startup > Duration::from_secs(10)
            || self.max_frames == 0
            || self.max_frames > 65_536
            || self.max_input_bytes == 0
            || self.max_input_bytes > 256 * 1024 * 1024
            || self.max_output_bytes == 0
            || self.max_output_bytes > 256 * 1024 * 1024
        {
            return Err(StdioError::new("limits"));
        }
        Ok(self)
    }
}

/// Contains static safe diagnostics only: no capability, frame, path, command,
/// inherited environment, or OS message is included in public errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdioError {
    pub code: &'static str,
    pub drained: bool,
    pub native_code: Option<i32>,
    pub native_code_unknown: bool,
    pub cleanup: Option<StdioCleanupFailure>,
    pub startup: Option<Box<StartupObservation>>,
    #[cfg(target_os = "macos")]
    pub resources: Option<DarwinStdioResources>,
    #[cfg(target_os = "macos")]
    pub resource_source: Option<mmmm_native_process::darwin::NativeResourceError>,
}

/// Closed diagnostics from the actual parent startup attempt. These facts are
/// never an authority grant and retain no token, image digest, path or frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupPhase {
    ParentImage,
    NativeSpawn,
    NoConnection,
    PartialHello,
    RejectedHello,
    ValidatedHello,
    ValidatedLate,
}
impl StartupPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ParentImage => "parent_image",
            Self::NativeSpawn => "native_spawn",
            Self::NoConnection => "no_connection",
            Self::PartialHello => "hello_partial",
            Self::RejectedHello => "hello_rejected",
            Self::ValidatedHello => "hello_validated",
            Self::ValidatedLate => "hello_validated_late",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelloChecks {
    magic: bool,
    capability: bool,
    image: bool,
    process_identity: bool,
}
impl HelloChecks {
    fn valid(self) -> bool {
        self.magic && self.capability && self.image && self.process_identity
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupObservation {
    phase: StartupPhase,
    parent_image_bytes: Option<u64>,
    parent_image_elapsed_ms: u64,
    native_spawn_elapsed_ms: u64,
    auth_elapsed_ms: u64,
    elapsed_ms: u64,
    accepted_connections: u8,
    hello_attempts: u8,
    hello_bytes: u8,
    max_hello_bytes: u8,
    rejected_hellos: u8,
    truncated_hellos: u8,
    last_checks: Option<HelloChecks>,
}
impl StartupObservation {
    fn new() -> Self {
        Self {
            phase: StartupPhase::ParentImage,
            parent_image_bytes: None,
            parent_image_elapsed_ms: 0,
            native_spawn_elapsed_ms: 0,
            auth_elapsed_ms: 0,
            elapsed_ms: 0,
            accepted_connections: 0,
            hello_attempts: 0,
            hello_bytes: 0,
            max_hello_bytes: 0,
            rejected_hellos: 0,
            truncated_hellos: 0,
            last_checks: None,
        }
    }
    fn observe_connection(&mut self) {
        self.accepted_connections = self.accepted_connections.saturating_add(1);
        self.hello_attempts = self.hello_attempts.saturating_add(1);
        self.hello_bytes = 0;
        self.last_checks = None;
        self.phase = StartupPhase::PartialHello;
    }
    fn observe_hello_bytes(&mut self, total: usize) {
        // Only the fixed 80-byte local receive array supplies this count.
        self.hello_bytes = total.min(80) as u8;
        self.max_hello_bytes = self.max_hello_bytes.max(self.hello_bytes);
    }
    fn reject_hello(&mut self, checks: Option<HelloChecks>) {
        self.rejected_hellos = self.rejected_hellos.saturating_add(1);
        self.last_checks = checks;
        self.phase = StartupPhase::RejectedHello;
    }
    fn truncate_hello(&mut self) {
        self.truncated_hellos = self.truncated_hellos.saturating_add(1);
        self.phase = StartupPhase::PartialHello;
    }
    fn validate_hello(&mut self, checks: HelloChecks) {
        self.last_checks = Some(checks);
        self.phase = StartupPhase::ValidatedHello;
    }
}
impl std::fmt::Display for StartupObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "startup={} image_bytes={:?} image_ms={} spawn_ms={} auth_ms={} elapsed_ms={} accepts={} attempts={} hello_bytes={} max_hello_bytes={} rejected={} truncated={} checks={:?}",
            self.phase.as_str(),
            self.parent_image_bytes,
            self.parent_image_elapsed_ms,
            self.native_spawn_elapsed_ms,
            self.auth_elapsed_ms,
            self.elapsed_ms,
            self.accepted_connections,
            self.hello_attempts,
            self.hello_bytes,
            self.max_hello_bytes,
            self.rejected_hellos,
            self.truncated_hellos,
            self.last_checks
        )
    }
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn check_hello(
    hello: &[u8; 80],
    capability: &[u8; 32],
    digest: &[u8; 32],
    pid: u64,
) -> HelloChecks {
    HelloChecks {
        magic: hello[..8] == MAGIC[..],
        capability: hello[8..40]
            .iter()
            .zip(capability)
            .fold(0u8, |value, (actual, expected)| value | (actual ^ expected))
            == 0,
        image: hello[40..72] == digest[..],
        process_identity: u64::from_be_bytes(
            hello[72..80].try_into().expect("fixed hello identity"),
        ) == pid,
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdioCleanupFailure {
    pub code: &'static str,
    pub native_code: Option<i32>,
    pub native_code_unknown: bool,
}
impl std::fmt::Display for StdioCleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "finite stdio cleanup: {}", self.code)?;
        if self.native_code_unknown {
            write!(f, " (UnknownNative)")
        } else if let Some(code) = self.native_code {
            write!(f, " (native {code})")
        } else {
            Ok(())
        }
    }
}
impl std::error::Error for StdioCleanupFailure {}
impl StdioError {
    fn new(code: &'static str) -> Self {
        Self {
            code,
            drained: false,
            native_code: None,
            native_code_unknown: false,
            cleanup: None,
            startup: None,
            #[cfg(target_os = "macos")]
            resources: None,
            #[cfg(target_os = "macos")]
            resource_source: None,
        }
    }
    fn io(code: &'static str, error: io::Error) -> Self {
        Self {
            code,
            drained: false,
            native_code: error.raw_os_error(),
            native_code_unknown: false,
            cleanup: None,
            startup: None,
            #[cfg(target_os = "macos")]
            resources: None,
            #[cfg(target_os = "macos")]
            resource_source: None,
        }
    }
    fn with_startup(mut self, observation: StartupObservation) -> Self {
        self.startup = Some(Box::new(observation));
        self
    }
    #[cfg(target_os = "macos")]
    fn with_resources(mut self, resources: DarwinStdioResources) -> Self {
        self.resources = Some(resources);
        self
    }
    #[cfg(target_os = "macos")]
    fn with_resource_source(
        mut self,
        source: mmmm_native_process::darwin::NativeResourceError,
    ) -> Self {
        self.resource_source = Some(source);
        self
    }
}
impl std::fmt::Display for StdioError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "finite stdio: {}", self.code)?;
        if self.native_code_unknown {
            write!(f, " (UnknownNative)")?;
        } else if let Some(code) = self.native_code {
            write!(f, " (native {code})")?;
        }
        if let Some(cleanup) = &self.cleanup {
            write!(f, "; {cleanup}")?;
        }
        if let Some(startup) = &self.startup {
            write!(f, "; {startup}")?;
        }
        Ok(())
    }
}
impl std::error::Error for StdioError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = &self.cleanup {
            return Some(error);
        }
        #[cfg(target_os = "macos")]
        if let Some(error) = &self.resource_source {
            return Some(error);
        }
        None
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdioDrain {
    pub exit_code: Option<i32>,
    pub terminated: bool,
}

struct Executable {
    path: PathBuf,
    file: File,
    digest: [u8; 32],
    byte_length: u64,
}
impl Executable {
    fn current(deadline: Instant) -> Result<Self, StdioError> {
        deadline_check(deadline)?;
        let path = std::env::current_exe().map_err(|e| StdioError::io("executable_path", e))?;
        let path = path
            .canonicalize()
            .map_err(|e| StdioError::io("executable_path", e))?;
        let mut file = native::open_executable(&path)?;
        deadline_check(deadline)?;
        let metadata = file
            .metadata()
            .map_err(|e| StdioError::io("executable_metadata", e))?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 256 * 1024 * 1024 {
            return Err(StdioError::new("executable_limits"));
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; WORK_BATCH];
        let mut bytes = 0u64;
        loop {
            deadline_check(deadline)?;
            let n = file
                .read(&mut buffer)
                .map_err(|e| StdioError::io("executable_read", e))?;
            if n == 0 {
                break;
            }
            bytes += n as u64;
            if bytes > metadata.len() {
                return Err(StdioError::new("executable_changed"));
            }
            hasher.update(&buffer[..n]);
            deadline_check(deadline)?;
        }
        if bytes != metadata.len() || !native::same_file(&file, &path)? {
            return Err(StdioError::new("executable_changed"));
        }
        deadline_check(deadline)?;
        Ok(Self {
            path,
            file,
            digest: hasher.finalize().into(),
            byte_length: bytes,
        })
    }
}

struct PendingWrite {
    id: u64,
    frame: zeroize::Zeroizing<Vec<u8>>,
    sent: usize,
    acknowledged: bool,
}
struct PendingRead {
    id: u64,
    size: usize,
    frame: Vec<u8>,
    sent: usize,
    response: Option<Option<zeroize::Zeroizing<Vec<u8>>>>,
}
struct Bridge {
    process: Option<native::Process>,
    _executable: Executable,
    socket: TcpStream,
    limits: StdioLimits,
    mode: Mode,
    expires: Instant,
    owner_deadline: Instant,
    receive: zeroize::Zeroizing<Vec<u8>>,
    lines: VecDeque<Vec<u8>>,
    queued: usize,
    input_count: u64,
    input_bytes: u64,
    output_count: u64,
    output_bytes: u64,
    input_eof: bool,
    pending: Option<PendingWrite>,
    pending_read: Option<PendingRead>,
    failure: Option<StdioError>,
    draining: bool,
    empty_observed: Option<Instant>,
    drained: Option<StdioDrain>,
}

/// Poll methods perform bounded nonblocking work. The async facade schedules
/// the next poll and owns its deadline/cancellation; no Tokio stdin is used.
pub struct NativeStdioPort {
    bridge: Mutex<Bridge>,
}
impl NativeStdioPort {
    pub fn spawn_current(limits: StdioLimits) -> Result<Self, StdioError> {
        let limits = limits.validate()?;
        Self::spawn_current_with_deadline(limits, Instant::now() + limits.session)
    }
    pub fn spawn_current_with_deadline(
        limits: StdioLimits,
        owner_deadline: Instant,
    ) -> Result<Self, StdioError> {
        Self::spawn(limits, Mode::Lines, StdioOutput::Stdout, owner_deadline)
    }
    /// Raw stdio uses pull-based exact reads and writes with no terminator or
    /// Unicode transformation. Capability bytes never enter public JSON.
    pub fn spawn_current_raw(limits: StdioLimits) -> Result<Self, StdioError> {
        let limits = limits.validate()?;
        Self::spawn_current_raw_with_deadline(limits, Instant::now() + limits.session)
    }
    pub fn spawn_current_raw_with_deadline(
        limits: StdioLimits,
        owner_deadline: Instant,
    ) -> Result<Self, StdioError> {
        Self::spawn_current_raw_output_with_deadline(limits, StdioOutput::Stdout, owner_deadline)
    }
    pub fn spawn_current_raw_output_with_deadline(
        limits: StdioLimits,
        output: StdioOutput,
        owner_deadline: Instant,
    ) -> Result<Self, StdioError> {
        Self::spawn(limits, Mode::Raw, output, owner_deadline)
    }
    fn spawn(
        limits: StdioLimits,
        mode: Mode,
        output: StdioOutput,
        owner_deadline: Instant,
    ) -> Result<Self, StdioError> {
        deadline_check(owner_deadline)?;
        if OWNERSHIP_UNCERTAIN.load(Ordering::Acquire) {
            return Err(StdioError::new("ownership_uncertain"));
        }
        let limits = limits.validate()?;
        let reservation = WorkerReservation::acquire()?;
        let started = Instant::now();
        deadline_check(owner_deadline)?;
        if owner_deadline.saturating_duration_since(started) > Duration::from_secs(3610) {
            return Err(StdioError::new("limits"));
        }
        let session_deadline = (started + limits.session).min(owner_deadline);
        let startup_deadline = (started + limits.startup).min(owner_deadline);
        let mut startup = StartupObservation::new();
        let image_started = Instant::now();
        let image_result = Executable::current(startup_deadline);
        startup.parent_image_elapsed_ms = elapsed_millis(image_started);
        startup.elapsed_ms = elapsed_millis(started);
        let executable = image_result.map_err(|error| error.with_startup(startup.clone()))?;
        startup.parent_image_bytes = Some(executable.byte_length);
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| StdioError::new("channel"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| StdioError::new("channel"))?;
        let address = listener
            .local_addr()
            .map_err(|_| StdioError::new("channel"))?;
        let mut capability = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut capability[..]).map_err(|_| StdioError::new("random"))?;
        let native_now = native::monotonic_millis()?;
        let native_deadline = native_now
            .checked_add(
                session_deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis() as u64,
            )
            .and_then(|deadline| deadline.checked_sub(native::MONOTONIC_MARGIN_MILLIS))
            .ok_or_else(|| StdioError::new("deadline"))?;
        if native_deadline <= native_now {
            return Err(StdioError::new("deadline"));
        }
        let mut packet = zeroize::Zeroizing::new(Vec::with_capacity(BOOTSTRAP_LENGTH));
        packet.extend_from_slice(&capability[..]);
        packet.extend_from_slice(&executable.digest);
        for value in [
            session_deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as u64
                | if mode == Mode::Raw { RAW_MODE_FLAG } else { 0 }
                | if output == StdioOutput::Stderr {
                    STDERR_FLAG
                } else {
                    0
                },
            limits.max_frames,
            limits.max_input_bytes,
            limits.max_output_bytes,
            native_deadline,
        ] {
            packet.extend_from_slice(&value.to_be_bytes());
        }
        deadline_check(startup_deadline)?;
        startup.phase = StartupPhase::NativeSpawn;
        let spawn_started = Instant::now();
        let spawned = native::Process::spawn(
            &executable,
            address,
            &packet,
            output,
            owner_deadline,
            startup_deadline,
            reservation,
        );
        startup.native_spawn_elapsed_ms = elapsed_millis(spawn_started);
        startup.elapsed_ms = elapsed_millis(started);
        packet.zeroize();
        let mut process = match spawned {
            Ok(p) => p,
            Err(e) => {
                capability.zeroize();
                return Err(e.with_startup(startup));
            }
        };
        startup.phase = StartupPhase::NoConnection;
        let auth_started = Instant::now();
        let result = authenticate_worker(
            &listener,
            &mut process,
            &capability,
            &executable.digest,
            startup_deadline,
            &mut startup,
        );
        startup.auth_elapsed_ms = elapsed_millis(auth_started);
        startup.elapsed_ms = elapsed_millis(started);
        capability.zeroize();
        let socket = match result {
            Ok(socket) => socket,
            Err(error) => {
                return Err(cleanup_failed_process(process, error.with_startup(startup)));
            }
        };
        if let Err(error) = deadline_check(startup_deadline) {
            startup.phase = StartupPhase::ValidatedLate;
            let _ = socket.shutdown(Shutdown::Both);
            return Err(cleanup_failed_process(process, error.with_startup(startup)));
        }
        Ok(Self {
            bridge: Mutex::new(Bridge {
                process: Some(process),
                _executable: executable,
                socket,
                limits,
                mode,
                expires: session_deadline,
                owner_deadline,
                // The private channel may carry a raw capability. Reserving
                // the entire finite frame before reading prevents a later
                // allocation from abandoning an unwiped sensitive prefix.
                receive: zeroize::Zeroizing::new(Vec::with_capacity(FRAME_LIMIT + HEADER)),
                lines: VecDeque::new(),
                queued: 0,
                input_count: 0,
                input_bytes: 0,
                output_count: 0,
                output_bytes: 0,
                input_eof: false,
                pending: None,
                pending_read: None,
                failure: None,
                draining: false,
                empty_observed: None,
                drained: None,
            }),
        })
    }
    pub fn poll_read_line(
        &self,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Poll<Option<Vec<u8>>>, StdioError> {
        let mut bridge = self
            .bridge
            .lock()
            .map_err(|_| StdioError::new("poisoned"))?;
        if bridge.mode != Mode::Lines {
            return bridge.fail("mode");
        }
        bridge.check(deadline, cancel)?;
        bridge.pump()?;
        bridge.check(deadline, cancel)?;
        if let Some(line) = bridge.lines.pop_front() {
            bridge.queued -= line.len();
            return Ok(Poll::Ready(Some(line)));
        }
        if bridge.input_eof {
            return Ok(Poll::Ready(None));
        }
        Ok(Poll::Pending)
    }
    /// Repeated polls must supply the identical line while it is pending.
    /// Ready means stdout write AND flush completed, not socket acceptance.
    pub fn poll_write_line(
        &self,
        line: &[u8],
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Poll<()>, StdioError> {
        validate_line(line, false)?;
        self.poll_write(line, true, deadline, cancel)
    }
    pub fn poll_write_raw(
        &self,
        bytes: &[u8],
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Poll<()>, StdioError> {
        if bytes.is_empty() || bytes.len() > FRAME_LIMIT {
            return Err(StdioError::new("output_frame"));
        }
        self.poll_write(bytes, false, deadline, cancel)
    }
    fn poll_write(
        &self,
        line: &[u8],
        newline: bool,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Poll<()>, StdioError> {
        let mut bridge = self
            .bridge
            .lock()
            .map_err(|_| StdioError::new("poisoned"))?;
        if (bridge.mode == Mode::Lines) != newline {
            return bridge.fail("mode");
        }
        bridge.check(deadline, cancel)?;
        if bridge.pending_read.is_some() {
            return Ok(Poll::Pending);
        }
        if bridge.pending.is_none() {
            if bridge.output_count >= bridge.limits.max_frames
                || bridge
                    .output_bytes
                    .checked_add(line.len() as u64 + u64::from(newline))
                    .is_none_or(|n| n > bridge.limits.max_output_bytes)
            {
                return bridge.fail("output_budget");
            }
            bridge.output_count += 1;
            bridge.output_bytes += line.len() as u64 + u64::from(newline);
            let id = bridge.output_count;
            bridge.pending = Some(PendingWrite {
                id,
                frame: zeroize::Zeroizing::new(frame(
                    if newline { OUTPUT } else { RAW_OUTPUT },
                    id,
                    line,
                )),
                sent: 0,
                acknowledged: false,
            });
        }
        if bridge
            .pending
            .as_ref()
            .is_some_and(|p| p.frame[HEADER..] != *line)
        {
            return bridge.fail("concurrent_output");
        }
        bridge.pump()?;
        bridge.check(deadline, cancel)?;
        let mut pending = bridge
            .pending
            .take()
            .ok_or_else(|| StdioError::new("output_state"))?;
        if pending.acknowledged {
            bridge.check(deadline, cancel)?;
            return Ok(Poll::Ready(()));
        }
        if pending.sent == pending.frame.len() {
            // The helper can be blocked in external stdout while its socket
            // accepted the whole frame. Never treat an empty write as EOF or
            // completion: continue waiting for the actual flush ACK.
            bridge.pending = Some(pending);
            return Ok(Poll::Pending);
        }
        let end = pending.frame.len().min(pending.sent + WORK_BATCH);
        match bridge.socket.write(&pending.frame[pending.sent..end]) {
            Ok(0) => {
                bridge.pending = Some(pending);
                return bridge.fail("worker_channel");
            }
            Ok(n) => pending.sent += n,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                bridge.pending = Some(pending);
                return bridge.fail("worker_channel");
            }
        }
        bridge.pending = Some(pending);
        Ok(Poll::Pending)
    }
    /// Only a requested range is captured. A partial EOF is input_truncated;
    /// None is EOF before any byte. Successful buffers zeroize on caller Drop.
    pub fn poll_read_exact(
        &self,
        size: usize,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Poll<Option<zeroize::Zeroizing<Vec<u8>>>>, StdioError> {
        if size == 0 || size > FRAME_LIMIT {
            return Err(StdioError::new("input_frame"));
        }
        let mut bridge = self
            .bridge
            .lock()
            .map_err(|_| StdioError::new("poisoned"))?;
        if bridge.mode != Mode::Raw {
            return bridge.fail("mode");
        }
        bridge.check(deadline, cancel)?;
        if bridge.pending.is_some() {
            return Ok(Poll::Pending);
        }
        if bridge.pending_read.is_none() {
            if bridge.input_eof {
                return Ok(Poll::Ready(None));
            }
            if bridge.input_count >= bridge.limits.max_frames
                || bridge
                    .input_bytes
                    .checked_add(size as u64)
                    .is_none_or(|n| n > bridge.limits.max_input_bytes)
            {
                return bridge.fail("input_budget");
            }
            bridge.input_count += 1;
            bridge.input_bytes += size as u64;
            let id = bridge.input_count;
            bridge.pending_read = Some(PendingRead {
                id,
                size,
                frame: frame(READ_EXACT, id, &(size as u32).to_be_bytes()),
                sent: 0,
                response: None,
            });
        }
        if bridge.pending_read.as_ref().is_some_and(|p| p.size != size) {
            return bridge.fail("concurrent_input");
        }
        bridge.pump()?;
        bridge.check(deadline, cancel)?;
        let mut pending = bridge
            .pending_read
            .take()
            .ok_or_else(|| StdioError::new("input_state"))?;
        if let Some(response) = pending.response.take() {
            return Ok(Poll::Ready(response));
        }
        if pending.sent < pending.frame.len() {
            match bridge.socket.write(&pending.frame[pending.sent..]) {
                Ok(0) => {
                    bridge.pending_read = Some(pending);
                    return bridge.fail("worker_channel");
                }
                Ok(n) => pending.sent += n,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    bridge.pending_read = Some(pending);
                    return bridge.fail("worker_channel");
                }
            }
        }
        bridge.pending_read = Some(pending);
        Ok(Poll::Pending)
    }
    pub fn poll_cancel_and_drain(&self, deadline: Instant) -> Result<Poll<StdioDrain>, StdioError> {
        let mut bridge = self
            .bridge
            .lock()
            .map_err(|_| StdioError::new("poisoned"))?;
        if let Some(done) = &bridge.drained {
            return Ok(Poll::Ready(done.clone()));
        }
        let deadline = deadline.min(bridge.owner_deadline);
        if !bridge.draining {
            bridge.draining = true;
            bridge.receive.zeroize();
            bridge.pending.take();
            bridge.pending_read.take();
            for line in &mut bridge.lines {
                line.zeroize();
            }
            bridge.lines.clear();
            bridge.queued = 0;
            let _ = bridge.socket.shutdown(Shutdown::Both);
            #[cfg(target_os = "macos")]
            bridge.process_mut()?.terminate_before(deadline)?;
            #[cfg(not(target_os = "macos"))]
            bridge.process_mut()?.terminate()?;
        }
        if Instant::now() >= deadline {
            return Err(StdioError::new("drain_uncertain"));
        }
        let exited = bridge.process_mut()?.exit_code()?;
        let empty = bridge.process_mut()?.scope_empty(deadline)?;
        if empty && exited.is_some() {
            if let Some(observed) = bridge.empty_observed {
                if observed.elapsed() >= Duration::from_millis(10) {
                    if Instant::now() >= deadline {
                        return Err(StdioError::new("drain_uncertain"));
                    }
                    #[cfg(target_os = "macos")]
                    let code = bridge.process_mut()?.reap_before(deadline)?;
                    #[cfg(not(target_os = "macos"))]
                    let code = bridge.process_mut()?.reap()?;
                    let done = StdioDrain {
                        exit_code: code,
                        terminated: true,
                    };
                    bridge.drained = Some(done.clone());
                    if Instant::now() >= deadline {
                        return Err(StdioError {
                            code: "drain_deadline",
                            drained: true,
                            native_code: None,
                            native_code_unknown: false,
                            cleanup: None,
                            startup: None,
                            #[cfg(target_os = "macos")]
                            resources: Some(bridge.process_mut()?.resource_evidence()),
                            #[cfg(target_os = "macos")]
                            resource_source: None,
                        });
                    }
                    return Ok(Poll::Ready(done));
                }
            } else {
                bridge.empty_observed = Some(Instant::now());
            }
        } else {
            bridge.empty_observed = None;
        }
        if Instant::now() >= deadline {
            return Err(StdioError::new("drain_uncertain"));
        }
        Ok(Poll::Pending)
    }

    /// Cached actual samples only. Reading evidence does not perform native
    /// I/O, create a sampling interval, or extend any supervision deadline.
    #[cfg(target_os = "macos")]
    pub fn resource_evidence(&self) -> Result<Option<DarwinStdioResources>, StdioError> {
        let bridge = self
            .bridge
            .lock()
            .map_err(|_| StdioError::new("poisoned"))?;
        Ok(bridge
            .process
            .as_ref()
            .map(native::Process::resource_evidence))
    }

    /// Explicit recovery of the same retained native identity with a newly
    /// supplied finite cleanup budget. No worker or request is retried.
    pub fn cleanup_retained(deadline: Instant) -> Result<StdioDrain, StdioError> {
        deadline_check(deadline)?;
        if deadline.saturating_duration_since(Instant::now()) > Duration::from_secs(10) {
            return Err(StdioError::new("limits"));
        }
        let mut process = RETAINED_PROCESS
            .lock()
            .map_err(|_| StdioError::new("poisoned"))?
            .take()
            .ok_or_else(|| StdioError::new("no_retained_owner"))?;
        match process.drain_blocking(deadline) {
            Ok(()) => {
                OWNERSHIP_UNCERTAIN.store(false, Ordering::Release);
                Ok(StdioDrain {
                    exit_code: process.reaped_exit_code(),
                    terminated: true,
                })
            }
            Err(error) if error.drained => {
                OWNERSHIP_UNCERTAIN.store(false, Ordering::Release);
                Err(error)
            }
            Err(error) => {
                retain_uncertain_process(process);
                Err(error)
            }
        }
    }
}
impl Drop for NativeStdioPort {
    fn drop(&mut self) {
        // Drop uses the original owner deadline, never a fresh grace period.
        // It is not a success report. Callers
        // explicitly poll_cancel_and_drain and preserve its result first.
        if let Ok(bridge) = self.bridge.get_mut() {
            let _ = bridge.socket.shutdown(Shutdown::Both);
            if bridge.drained.is_none()
                && let Some(mut process) = bridge.process.take()
            {
                match process.drain_blocking(bridge.owner_deadline) {
                    Ok(()) => {}
                    Err(error) if error.drained => {}
                    Err(_) => retain_uncertain_process(process),
                }
            }
        }
    }
}
impl Bridge {
    fn process_mut(&mut self) -> Result<&mut native::Process, StdioError> {
        self.process
            .as_mut()
            .ok_or_else(|| StdioError::new("ownership_uncertain"))
    }
    fn fail<T>(&mut self, code: &'static str) -> Result<T, StdioError> {
        let error = StdioError::new(code);
        self.failure = Some(error.clone());
        Err(error)
    }
    fn check(&mut self, deadline: Instant, cancel: &AtomicBool) -> Result<(), StdioError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if self.draining {
            return Err(StdioError::new("shutdown"));
        }
        if cancel.load(Ordering::Acquire) {
            return self.fail("cancelled");
        }
        if Instant::now() >= deadline || Instant::now() >= self.expires {
            return self.fail("deadline");
        }
        #[cfg(target_os = "macos")]
        {
            let resource_deadline = deadline.min(self.expires);
            if let Err(error) = self
                .process_mut()?
                .check_resources(resource_deadline, false)
            {
                self.failure = Some(error.clone());
                return Err(error);
            }
        }
        if self.process_mut()?.exit_code()?.is_some() {
            return self.fail("worker_exit");
        }
        Ok(())
    }
    fn pump(&mut self) -> Result<(), StdioError> {
        let mut processed = 0;
        loop {
            self.decode()?;
            if processed >= WORK_BATCH {
                return Ok(());
            }
            let mut buffer = zeroize::Zeroizing::new([0u8; 8192]);
            let available = buffer.len().min(FRAME_LIMIT + HEADER - self.receive.len());
            if available == 0 {
                return self.fail("input_frame");
            }
            match self.socket.read(&mut buffer[..available]) {
                Ok(0) => return self.fail("worker_channel"),
                Ok(n) => {
                    processed += n;
                    if self.receive.len() + n > FRAME_LIMIT + HEADER {
                        return self.fail("input_frame");
                    }
                    self.receive.extend_from_slice(&buffer[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(()),
                Err(_) => return self.fail("worker_channel"),
            }
        }
    }
    fn decode(&mut self) -> Result<(), StdioError> {
        let mut consumed = 0;
        while self.receive.len() - consumed >= HEADER {
            let header = &self.receive[consumed..consumed + HEADER];
            let tag = header[0];
            let id = u64::from_be_bytes(
                header[1..9]
                    .try_into()
                    .map_err(|_| StdioError::new("channel_frame"))?,
            );
            let n = u32::from_be_bytes(
                header[9..13]
                    .try_into()
                    .map_err(|_| StdioError::new("channel_frame"))?,
            ) as usize;
            if n > FRAME_LIMIT {
                return self.fail("input_frame");
            }
            if self.receive.len() - consumed < HEADER + n {
                break;
            }
            let payload = &self.receive[consumed + HEADER..consumed + HEADER + n];
            match tag {
                INPUT
                    if self.mode == Mode::Lines
                        && !self.input_eof
                        && id == self.input_count + 1 =>
                {
                    validate_line(payload, true)?;
                    if self.input_count >= self.limits.max_frames
                        || self
                            .input_bytes
                            .checked_add(n as u64 + 1)
                            .is_none_or(|v| v > self.limits.max_input_bytes)
                        || self.lines.len() >= 32
                        || self.queued + n > QUEUE_LIMIT
                    {
                        return self.fail("input_budget");
                    }
                    self.input_count += 1;
                    self.input_bytes += n as u64 + 1;
                    self.queued += n;
                    self.lines.push_back(payload.to_vec());
                }
                EOF if self.mode == Mode::Lines
                    && !self.input_eof
                    && n == 0
                    && id == self.input_count =>
                {
                    self.input_eof = true
                }
                RAW_INPUT if self.mode == Mode::Raw => {
                    let Some(pending) = self.pending_read.as_mut() else {
                        return self.fail("channel_frame");
                    };
                    if pending.id != id
                        || pending.size != n
                        || pending.sent != pending.frame.len()
                        || pending.response.is_some()
                    {
                        return self.fail("channel_frame");
                    }
                    pending.response = Some(Some(zeroize::Zeroizing::new(payload.to_vec())));
                }
                RAW_EOF if self.mode == Mode::Raw && n == 0 => {
                    let Some(pending) = self.pending_read.as_mut() else {
                        return self.fail("channel_frame");
                    };
                    if pending.id != id
                        || pending.sent != pending.frame.len()
                        || pending.response.is_some()
                    {
                        return self.fail("channel_frame");
                    }
                    pending.response = Some(None);
                    self.input_eof = true;
                }
                TRUNCATED if self.mode == Mode::Raw && n == 0 => {
                    if self.pending_read.as_ref().is_none_or(|p| {
                        p.id != id || p.sent != p.frame.len() || p.response.is_some()
                    }) {
                        return self.fail("channel_frame");
                    }
                    return self.fail("input_truncated");
                }
                ACK if n == 0 => {
                    if let Some(pending) = self.pending.as_mut() {
                        if pending.id != id
                            || pending.sent != pending.frame.len()
                            || pending.acknowledged
                        {
                            return self.fail("output_ack");
                        }
                        pending.acknowledged = true;
                    } else {
                        return self.fail("output_ack");
                    }
                }
                FAULT if n == 0 => return self.fail("worker_io"),
                _ => return self.fail("channel_frame"),
            }
            consumed += HEADER + n;
        }
        if consumed > 0 {
            // Move the remainder, then wipe every vacated byte before reducing
            // length. Vec::drain alone can leave a copied raw capability behind.
            let remaining = self.receive.len() - consumed;
            self.receive.copy_within(consumed.., 0);
            self.receive[remaining..].zeroize();
            self.receive.truncate(remaining);
        }
        Ok(())
    }
}
fn validate_line(line: &[u8], input: bool) -> Result<(), StdioError> {
    if line.is_empty()
        || line.len() > FRAME_LIMIT
        || line.iter().any(|b| matches!(b, b'\n' | b'\r'))
        || std::str::from_utf8(line).is_err()
    {
        return Err(StdioError::new(if input {
            "input_frame"
        } else {
            "output_frame"
        }));
    }
    Ok(())
}
fn frame(tag: u8, id: u64, data: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(HEADER + data.len());
    value.push(tag);
    value.extend_from_slice(&id.to_be_bytes());
    value.extend_from_slice(&(data.len() as u32).to_be_bytes());
    value.extend_from_slice(data);
    value
}
fn authenticate_worker(
    listener: &TcpListener,
    process: &mut native::Process,
    capability: &[u8; 32],
    digest: &[u8; 32],
    deadline: Instant,
    observation: &mut StartupObservation,
) -> Result<TcpStream, StdioError> {
    let mut attempts = 0;
    loop {
        if Instant::now() >= deadline {
            return Err(StdioError::new("startup_deadline"));
        }
        if let Some(code) = process.exit_code()? {
            return Err(worker_exit_error(code));
        }
        #[cfg(target_os = "macos")]
        process.check_resources(deadline, false)?;
        match listener.accept() {
            Ok((mut socket, address)) if address.ip().is_loopback() => {
                attempts += 1;
                observation.observe_connection();
                if attempts > 4 {
                    return Err(StdioError::new("channel_auth"));
                }
                socket
                    .set_nonblocking(true)
                    .map_err(|_| StdioError::new("channel"))?;
                let mut hello = zeroize::Zeroizing::new([0u8; 80]);
                let mut n = 0;
                while n < hello.len() && Instant::now() < deadline {
                    match socket.read(&mut hello[n..]) {
                        Ok(0) => {
                            observation.truncate_hello();
                            break;
                        }
                        Ok(read) => {
                            n += read;
                            observation.observe_hello_bytes(n);
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
                let checks = (n == hello.len())
                    .then(|| check_hello(&hello, capability, digest, process.id()));
                hello.zeroize();
                if let Some(checks) = checks.filter(|checks| checks.valid()) {
                    observation.validate_hello(checks);
                    if let Err(error) = deadline_check(deadline) {
                        observation.phase = StartupPhase::ValidatedLate;
                        return Err(error);
                    }
                    socket
                        .set_nodelay(true)
                        .map_err(|_| StdioError::new("channel"))?;
                    if let Err(error) = deadline_check(deadline) {
                        observation.phase = StartupPhase::ValidatedLate;
                        return Err(error);
                    }
                    #[cfg(target_os = "macos")]
                    receive_resource_admission(&mut socket, process, deadline)?;
                    return Ok(socket);
                }
                if n == hello.len() {
                    observation.reject_hello(checks);
                }
            }
            Ok(_) => return Err(StdioError::new("channel_auth")),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(StdioError::new("channel")),
        }
    }
}

#[cfg(target_os = "macos")]
fn receive_resource_admission(
    socket: &mut TcpStream,
    process: &mut native::Process,
    deadline: Instant,
) -> Result<(), StdioError> {
    let mut bytes = zeroize::Zeroizing::new(vec![0u8; native::RESOURCE_ADMISSION_LENGTH]);
    let mut received = 0;
    while received < bytes.len() {
        deadline_check(deadline)?;
        process.check_resources(deadline, false)?;
        if let Some(code) = process.exit_code()? {
            return Err(worker_exit_error(code));
        }
        match socket.read(&mut bytes[received..]) {
            Ok(0) => return Err(StdioError::new("native_resource_admission")),
            Ok(count) => received += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(StdioError::io("native_resource_admission", error)),
        }
    }
    deadline_check(deadline)?;
    if let Some(code) = process.exit_code()? {
        return Err(worker_exit_error(code));
    }
    process.admit_worker_resources(&bytes, deadline)?;
    if let Some(code) = process.exit_code()? {
        return Err(worker_exit_error(code));
    }
    deadline_check(deadline)
}

/// Hidden app entry. No secret is accepted in args: only loopback address and
/// one inherited bootstrap handle/fd. The app must immediately exit afterwards.
pub fn worker_entry_exit(args: &[String]) -> ! {
    let code = match worker_entry(args) {
        Ok(()) => 0,
        Err(error) => worker_failure_exit(&error),
    };
    // The sole diagnostic channel is a fixed status. No stderr write can block
    // and no frame, path, argument, capability or environment is emitted.
    std::process::exit(code)
}
fn worker_failure_exit(error: &StdioError) -> i32 {
    let stage = WORKER_STAGES
        .iter()
        .position(|s| *s == error.code)
        .unwrap_or_else(|| {
            WORKER_STAGES
                .iter()
                .position(|stage| *stage == "worker_unknown")
                .expect("fixed unknown worker stage")
        }) as u32
        + 1;
    #[cfg(windows)]
    {
        let native = match error.native_code {
            Some(n) if !error.native_code_unknown && (0..=65_533).contains(&n) => n as u32,
            None if !error.native_code_unknown => 65_535,
            _ => 65_534,
        };
        (0x4D00_0000 | stage << 16 | native) as i32
    }
    #[cfg(unix)]
    {
        // POSIX retains only eight status bits. Preserve the fixed stage and
        // explicitly mark native diagnostics unavailable rather than truncate.
        let native_unavailable = error.native_code.is_some() || error.native_code_unknown;
        #[cfg(target_os = "macos")]
        let native_unavailable = native_unavailable || error.resource_source.is_some();
        if native_unavailable {
            (128 + stage) as i32
        } else {
            let status = 64 + stage;
            // Rust panic exits with 101. Keep that unexpected runtime status
            // distinct while preserving every earlier fixed stage number.
            (status + u32::from(status >= 101)) as i32
        }
    }
}
fn worker_exit_error(status: i32) -> StdioError {
    #[cfg(windows)]
    let encoded = if status as u32 & 0xFF00_0000 == 0x4D00_0000 {
        Some(((status as u32 >> 16) & 255, status as u32 & 65_535))
    } else {
        None
    };
    #[cfg(unix)]
    let encoded = if (65..=100).contains(&status) {
        Some(((status - 64) as u32, 65_535u32))
    } else if (102..=65 + WORKER_STAGES.len() as i32).contains(&status) {
        Some(((status - 65) as u32, 65_535u32))
    } else if (129..=128 + WORKER_STAGES.len() as i32).contains(&status) {
        Some(((status - 128) as u32, 65_534u32))
    } else {
        None
    };
    if let Some((stage, native)) = encoded
        && let Some(code) = stage
            .checked_sub(1)
            .and_then(|n| WORKER_STAGES.get(n as usize))
    {
        let mut error = StdioError::new(code);
        error.native_code = (native < 65_534).then_some(native as i32);
        error.native_code_unknown = native == 65_534;
        return error;
    }
    // Preserve unexpected loader, signal or runtime termination as the actual
    // bounded numeric status. It is never treated as an encoded helper report.
    let mut error = StdioError::new("worker_exit");
    error.native_code = Some(status);
    error
}
pub fn worker_entry(args: &[String]) -> Result<(), StdioError> {
    if args.len() != 2 {
        return Err(StdioError::new("worker_arguments"));
    }
    let address: SocketAddr = args[0]
        .parse()
        .map_err(|_| StdioError::new("worker_arguments"))?;
    if address.ip() != Ipv4Addr::LOCALHOST || address.port() == 0 {
        return Err(StdioError::new("worker_arguments"));
    }
    let handle = args[1]
        .parse::<usize>()
        .map_err(|_| StdioError::new("worker_arguments"))?;
    let mut packet = native::read_bootstrap(handle)?;
    let values: Vec<u64> = packet[64..]
        .chunks_exact(8)
        .map(|c| u64::from_be_bytes(c.try_into().expect("fixed bootstrap field")))
        .collect();
    let mode = if values[0] & RAW_MODE_FLAG != 0 {
        Mode::Raw
    } else {
        Mode::Lines
    };
    let output = if values[0] & STDERR_FLAG != 0 {
        StdioOutput::Stderr
    } else {
        StdioOutput::Stdout
    };
    if output == StdioOutput::Stderr && mode != Mode::Raw {
        return Err(StdioError::new("limits"));
    }
    let limits = StdioLimits {
        session: Duration::from_millis(values[0] & !BOOTSTRAP_FLAGS),
        startup: Duration::from_secs(5),
        max_frames: values[1],
        max_input_bytes: values[2],
        max_output_bytes: values[3],
    }
    .validate()?;
    let anchor = Instant::now();
    let native_now = native::monotonic_millis()?;
    let native_deadline = values[4];
    if native_now >= native_deadline
        || native_deadline - native_now > limits.session.as_millis() as u64
    {
        return Err(StdioError::new("deadline"));
    }
    let expires = anchor + Duration::from_millis(native_deadline - native_now);
    // Start the bounded watchdog before executable hashing or private socket
    // writes. The same system monotonic absolute deadline crosses exec, so
    // image loading and authentication cannot create a fresh child session.
    let _watchdog = std::thread::Builder::new()
        .name("mmmm-stdio-watchdog".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            loop {
                let now = match native::monotonic_millis() {
                    Ok(now) => now,
                    Err(_) => std::process::exit(125),
                };
                if now >= native_deadline {
                    std::process::exit(124);
                }
                #[cfg(target_os = "macos")]
                if let Err(error) = native::check_worker_resource_gap(anchor) {
                    // A lock-free timestamp check cannot be held behind the
                    // sampler's native query. Scheduling may still delay it;
                    // the exit stage does not transmit the late gap's value.
                    unsafe { libc::_exit(worker_failure_exit(&error)) };
                }
                std::thread::sleep(
                    Duration::from_millis(100).min(Duration::from_millis(native_deadline - now)),
                );
            }
        })
        .map_err(|_| StdioError::new("worker_thread"))?;
    #[cfg(target_os = "macos")]
    let resources = native::worker_resources(native_deadline, anchor)?;
    let executable = Executable::current(expires)?;
    if packet[32..64] != executable.digest {
        packet.zeroize();
        return Err(StdioError::new("executable_changed"));
    }
    deadline_check(expires)?;
    let startup = Duration::from_secs(5).min(expires.saturating_duration_since(Instant::now()));
    let mut socket = TcpStream::connect_timeout(&address, startup)
        .map_err(|e| StdioError::io("worker_connect", e))?;
    deadline_check(expires)?;
    socket
        .set_write_timeout(Some(
            Duration::from_secs(5).min(expires.saturating_duration_since(Instant::now())),
        ))
        .map_err(|e| StdioError::io("worker_hello", e))?;
    let mut hello = zeroize::Zeroizing::new(Vec::with_capacity(80));
    hello.extend_from_slice(MAGIC);
    hello.extend_from_slice(&packet[..32]);
    hello.extend_from_slice(&executable.digest);
    hello.extend_from_slice(&(std::process::id() as u64).to_be_bytes());
    packet.zeroize();
    let sent = socket.write_all(&hello);
    hello.zeroize();
    sent.map_err(|e| StdioError::io("worker_hello", e))?;
    deadline_check(expires)?;
    #[cfg(target_os = "macos")]
    {
        let receipt = resources.admission_receipt()?;
        socket
            .write_all(&receipt)
            .map_err(|error| StdioError::io("native_resource_admission", error))?;
        deadline_check(expires)?;
    }
    socket
        .set_write_timeout(None)
        .map_err(|e| StdioError::io("worker_hello", e))?;
    let mut receiver = socket
        .try_clone()
        .map_err(|e| StdioError::io("worker_clone", e))?;
    let sender = std::sync::Arc::new(Mutex::new(socket));
    let output_sender = sender.clone();
    // Every helper thread remains inside the same native-owned process.
    let (mut input, mut external_output) = native::worker_stdio(output)?;
    if mode == Mode::Raw {
        // Rust's global Stdin uses a BufReader and can capture a capability
        // past the requested public prefix. Raw mode owns unbuffered native
        // handles so each read requests exactly the caller's remaining range.
        return worker_raw(
            &mut receiver,
            &sender,
            &mut input,
            &mut external_output,
            limits,
        );
    }
    drop(input);
    let output = std::thread::Builder::new()
        .name("mmmm-stdio-output".into())
        .stack_size(2 * 1024 * 1024)
        .spawn(move || -> Result<(), StdioError> {
            let result = worker_output(receiver, output_sender, limits, external_output);
            // EOF or output failure terminates the whole owned helper, including
            // an input thread currently blocked in external stdin.
            std::process::exit(if result.is_ok() { 0 } else { 3 });
        })
        .map_err(|_| StdioError::new("worker_thread"))?;
    worker_input(&mut io::stdin().lock(), &sender, limits)?;
    // EOF waits for the parent to close its channel. If external stdout blocks,
    // the parent deadline kills the owned process including this entire thread.
    output
        .join()
        .map_err(|_| StdioError::new("worker_thread"))?
}
fn worker_send(sender: &Mutex<TcpStream>, tag: u8, id: u64, line: &[u8]) -> Result<(), StdioError> {
    sender
        .lock()
        .map_err(|_| StdioError::new("worker_thread"))?
        .write_all(&zeroize::Zeroizing::new(frame(tag, id, line)))
        .map_err(|_| StdioError::new("channel"))
}
fn worker_write_chunks(output: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    for chunk in bytes.chunks(EXTERNAL_WRITE_CHUNK) {
        output.write_all(chunk)?;
    }
    Ok(())
}
fn worker_raw(
    receiver: &mut TcpStream,
    sender: &Mutex<TcpStream>,
    input: &mut impl Read,
    output: &mut impl Write,
    limits: StdioLimits,
) -> Result<(), StdioError> {
    let mut input_count = 0u64;
    let mut input_bytes = 0u64;
    let mut output_count = 0u64;
    let mut output_bytes = 0u64;
    let mut input_eof = false;
    let mut failed = false;
    loop {
        let mut header = [0u8; HEADER];
        match receiver.read(&mut header[..1]) {
            Ok(0) => return Ok(()),
            Ok(1) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            _ => return Err(StdioError::new("channel")),
        }
        receiver
            .read_exact(&mut header[1..])
            .map_err(|_| StdioError::new("channel"))?;
        let tag = header[0];
        let id = u64::from_be_bytes(
            header[1..9]
                .try_into()
                .map_err(|_| StdioError::new("channel_frame"))?,
        );
        let size = u32::from_be_bytes(
            header[9..13]
                .try_into()
                .map_err(|_| StdioError::new("channel_frame"))?,
        ) as usize;
        if size == 0
            || size > FRAME_LIMIT
            || (tag == READ_EXACT && size != 4)
            || !matches!(tag, READ_EXACT | RAW_OUTPUT)
        {
            return Err(StdioError::new("channel_frame"));
        }
        let mut payload = zeroize::Zeroizing::new(vec![0u8; size]);
        receiver
            .read_exact(&mut payload)
            .map_err(|_| StdioError::new("channel"))?;
        if failed {
            worker_send(sender, FAULT, 0, &[])?;
            continue;
        }
        if tag == RAW_OUTPUT {
            if id != output_count + 1
                || output_count >= limits.max_frames
                || output_bytes
                    .checked_add(size as u64)
                    .is_none_or(|n| n > limits.max_output_bytes)
            {
                return Err(StdioError::new("output_budget"));
            }
            output_count += 1;
            output_bytes += size as u64;
            if worker_write_chunks(output, &payload)
                .and_then(|_| output.flush())
                .is_err()
            {
                payload.zeroize();
                worker_send(sender, FAULT, 0, &[])?;
                failed = true;
                continue;
            }
            payload.zeroize();
            worker_send(sender, ACK, id, &[])?;
        } else {
            let n = u32::from_be_bytes(
                payload[..]
                    .try_into()
                    .map_err(|_| StdioError::new("channel_frame"))?,
            ) as usize;
            if n == 0
                || n > FRAME_LIMIT
                || id != input_count + 1
                || input_count >= limits.max_frames
                || input_bytes
                    .checked_add(n as u64)
                    .is_none_or(|v| v > limits.max_input_bytes)
            {
                return Err(StdioError::new("input_budget"));
            }
            input_count += 1;
            input_bytes += n as u64;
            if input_eof {
                worker_send(sender, RAW_EOF, id, &[])?;
                continue;
            }
            let mut data = zeroize::Zeroizing::new(vec![0u8; n]);
            let mut read = 0;
            while read < n {
                match input.read(&mut data[read..]) {
                    Ok(0) => {
                        input_eof = true;
                        break;
                    }
                    Ok(count) => read += count,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        data.zeroize();
                        worker_send(sender, FAULT, 0, &[])?;
                        failed = true;
                        break;
                    }
                }
            }
            if failed {
                continue;
            }
            if read == 0 && input_eof {
                worker_send(sender, RAW_EOF, id, &[])?;
            } else if read < n {
                data.zeroize();
                worker_send(sender, TRUNCATED, id, &[])?;
                failed = true;
            } else {
                worker_send(sender, RAW_INPUT, id, &data)?;
            }
            data.zeroize();
        }
    }
}
fn worker_input(
    input: &mut impl BufRead,
    sender: &Mutex<TcpStream>,
    limits: StdioLimits,
) -> Result<(), StdioError> {
    let mut id = 0;
    let mut bytes = 0u64;
    loop {
        let mut line = Vec::new();
        loop {
            let buffer = input.fill_buf().map_err(|_| StdioError::new("worker_io"))?;
            if buffer.is_empty() {
                if !line.is_empty() {
                    let _ = worker_send(sender, FAULT, 0, &[]);
                    return Err(StdioError::new("input_frame"));
                }
                worker_send(sender, EOF, id, &[])?;
                return Ok(());
            }
            let n = buffer
                .iter()
                .position(|b| *b == b'\n')
                .map_or(buffer.len(), |n| n + 1);
            if line.len() + n > FRAME_LIMIT + 2 {
                let _ = worker_send(sender, FAULT, 0, &[]);
                return Err(StdioError::new("input_frame"));
            }
            let finished = buffer[n - 1] == b'\n';
            line.extend_from_slice(&buffer[..n]);
            input.consume(n);
            if finished {
                break;
            }
        }
        bytes = bytes
            .checked_add(line.len() as u64)
            .ok_or_else(|| StdioError::new("input_budget"))?;
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        validate_line(&line, true)?;
        if id >= limits.max_frames || bytes > limits.max_input_bytes {
            let _ = worker_send(sender, FAULT, 0, &[]);
            return Err(StdioError::new("input_budget"));
        }
        id += 1;
        worker_send(sender, INPUT, id, &line)?;
    }
}
fn worker_output(
    mut receiver: TcpStream,
    sender: std::sync::Arc<Mutex<TcpStream>>,
    limits: StdioLimits,
    mut output: File,
) -> Result<(), StdioError> {
    // The owned unbuffered native duplicate keeps every external call within
    // the chunk bound. A global LineWriter may combine or buffer writes.
    worker_output_to(&mut receiver, &sender, limits, &mut output)
}
fn worker_output_to(
    receiver: &mut TcpStream,
    sender: &Mutex<TcpStream>,
    limits: StdioLimits,
    output: &mut impl Write,
) -> Result<(), StdioError> {
    let mut id = 0;
    let mut bytes = 0u64;
    loop {
        let mut header = [0u8; HEADER];
        match receiver.read(&mut header[..1]) {
            Ok(0) => return Ok(()),
            Ok(1) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            _ => return Err(StdioError::new("channel")),
        }
        receiver
            .read_exact(&mut header[1..])
            .map_err(|_| StdioError::new("channel"))?;
        let next = u64::from_be_bytes(
            header[1..9]
                .try_into()
                .map_err(|_| StdioError::new("channel_frame"))?,
        );
        let n = u32::from_be_bytes(
            header[9..13]
                .try_into()
                .map_err(|_| StdioError::new("channel_frame"))?,
        ) as usize;
        if header[0] != OUTPUT || next != id + 1 || id >= limits.max_frames || n > FRAME_LIMIT {
            let _ = worker_send(sender, FAULT, 0, &[]);
            return Err(StdioError::new("output_frame"));
        }
        bytes = bytes
            .checked_add(n as u64 + 1)
            .ok_or_else(|| StdioError::new("output_budget"))?;
        if bytes > limits.max_output_bytes {
            let _ = worker_send(sender, FAULT, 0, &[]);
            return Err(StdioError::new("output_budget"));
        }
        let mut line = vec![0u8; n];
        receiver
            .read_exact(&mut line)
            .map_err(|_| StdioError::new("channel"))?;
        validate_line(&line, false)?;
        if worker_write_chunks(output, &line)
            .and_then(|_| output.write_all(b"\n"))
            .and_then(|_| output.flush())
            .is_err()
        {
            let _ = worker_send(sender, FAULT, 0, &[]);
            return Err(StdioError::new("worker_io"));
        }
        id = next;
        worker_send(sender, ACK, id, &[])?;
    }
}

#[cfg(test)]
#[path = "stdio_io_tests.rs"]
mod tests;

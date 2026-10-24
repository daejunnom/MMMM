//! Bounded native command supervision. A leader exit is not a drained scope.
//!
//! Windows uses an atomic Job List association, suspended verification and a
//! kill-on-close job. Unix uses a fresh session and retains the unreaped leader
//! until its process group is empty. Linux observes procfs; macOS uses libproc.
//! Unix sessions are a cooperative boundary: programs that deliberately detach
//! into another session are outside this API's containment guarantee. Managed
//! commands must disable reusable daemons; this module is not a sandbox.
use serde::Serialize;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(50);
const NATURAL_EXIT_GRACE: Duration = Duration::from_secs(2);
const CAPTURE_READ_BYTES: usize = 64 * 1024;
const MAX_CAPTURE_READ_BYTES: usize = 64 * 1024 * 1024;
const CAPTURE_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MINECRAFT_STOP_BYTES: &[u8; 5] = b"stop\n";
const STOP_REQUESTED: u8 = 1;
const STOP_BOUND: u8 = 2;
const STOP_CLOSED: u8 = 4;
#[cfg(not(target_os = "macos"))]
const READ_BATCH_BYTES: usize = 256 * 1024;
#[cfg(target_os = "macos")]
const READ_BATCH_BYTES: usize = 8192;
#[cfg(any(target_os = "macos", test))]
#[path = "darwin_resources.rs"]
mod darwin_resources;
#[cfg(any(target_os = "linux", test))]
#[path = "linux_resources.rs"]
mod linux_resources;
#[path = "resource_policy.rs"]
mod resource_policy;
pub use resource_policy::ResourcePolicy;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TailPolicy {
    #[default]
    Reject,
    /// Only an explicitly supervised build may terminate its owned native tail
    /// after leader exit. This never permits detached processes or partial drain.
    TerminateForBuild,
}

/// 한 supervision에만 묶이는 고정 console stop 요청이다. 입력 bytes나 writer는 공개하지 않는다.
#[derive(Clone, Debug, Default)]
pub struct MinecraftStopHandle {
    state: Arc<AtomicU8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinecraftStopClosed;
impl fmt::Display for MinecraftStopClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the original Minecraft stop request is closed")
    }
}
impl std::error::Error for MinecraftStopClosed {}
impl MinecraftStopHandle {
    pub fn new() -> Self {
        Self::default()
    }
    /// 같은 요청의 재전송은 idempotent다. 성공은 요청 접수이며 게임의 처리/저장 acknowledgement가 아니다.
    pub fn request(&self) -> Result<(), MinecraftStopClosed> {
        self.state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state & STOP_CLOSED == 0).then_some(state | STOP_REQUESTED)
            })
            .map(|_| ())
            .map_err(|_| MinecraftStopClosed)
    }
    fn requested(&self) -> bool {
        self.state.load(Ordering::Acquire) & STOP_REQUESTED != 0
    }
}
struct MinecraftStopBinding(MinecraftStopHandle);
impl MinecraftStopBinding {
    fn bind(handle: &MinecraftStopHandle) -> Result<Self, ProcessError> {
        handle
            .state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state & (STOP_BOUND | STOP_CLOSED) == 0).then_some(state | STOP_BOUND)
            })
            .map_err(|_| {
                ProcessError::new(
                    "minecraft_stop_binding",
                    "Minecraft stop handle was already bound or closed",
                )
            })?;
        Ok(Self(handle.clone()))
    }
    fn close(&self) -> bool {
        self.0.state.fetch_or(STOP_CLOSED, Ordering::AcqRel) & STOP_REQUESTED != 0
    }
}
impl Drop for MinecraftStopBinding {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct MinecraftStopIoError {
    pub kind: String,
    pub raw_os_error: Option<i32>,
}
impl MinecraftStopIoError {
    fn from_io(error: &std::io::Error) -> Self {
        Self {
            kind: format!("{:?}", error.kind()),
            raw_os_error: error.raw_os_error(),
        }
    }
}
/// 실제 요청/pipe 전송/종료 사실만이다. native command 처리나 월드 저장을 증명하지 않는다.
#[derive(Clone, Debug, Serialize)]
pub struct MinecraftStopEvidence {
    pub requested: bool,
    pub request_observed: bool,
    pub control_closed: bool,
    pub writer_available: bool,
    pub writer_closed: bool,
    pub write_attempts: u32,
    pub would_block: u32,
    pub last_would_block: Option<MinecraftStopIoError>,
    pub bytes_written: usize,
    pub write_error: Option<MinecraftStopIoError>,
    pub close_error: Option<MinecraftStopIoError>,
    pub pipe_capacity_bytes: Option<u32>,
    pub write_mode: &'static str,
    pub acknowledgement: &'static str,
}
impl MinecraftStopEvidence {
    fn new() -> Self {
        Self {
            requested: false,
            request_observed: false,
            control_closed: false,
            writer_available: false,
            writer_closed: false,
            write_attempts: 0,
            would_block: 0,
            last_would_block: None,
            bytes_written: 0,
            write_error: None,
            close_error: None,
            pipe_capacity_bytes: None,
            write_mode: native::STOP_WRITE_MODE,
            acknowledgement: "not_observed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProcessSpec {
    /// Resolved executable. Shell interpolation is never performed here.
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    /// Controlled startup can use only the explicit environment below. General
    /// managed commands retain inheritance; inherited values are never logged.
    pub inherit_environment: bool,
    pub env: BTreeMap<OsString, OsString>,
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
    pub timeout: Duration,
    /// Optional original caller deadline. Relative supervision and observations
    /// may shorten this budget, but never move this absolute deadline forward.
    pub absolute_deadline: Option<Instant>,
    pub observation_interval: Duration,
    pub drain_timeout: Duration,
    /// Combined retained stdout and stderr bytes. Excess output fails the run.
    pub max_log_bytes: u64,
    pub tail_policy: TailPolicy,
    /// Fixed native policy for this platform and managed purpose; foreign modes
    /// are rejected. The default retains the general command policy.
    pub resource_policy: ResourcePolicy,
    /// 기본 None은 기존 null stdin이다. Some은 원 loop가 고정 stop 한 번만 쓸 수 있게 한다.
    pub minecraft_stop: Option<MinecraftStopHandle>,
}

impl ProcessSpec {
    pub fn new(program: PathBuf, cwd: PathBuf, stdout_log: PathBuf, stderr_log: PathBuf) -> Self {
        Self {
            program,
            args: Vec::new(),
            cwd,
            inherit_environment: true,
            env: BTreeMap::new(),
            stdout_log,
            stderr_log,
            timeout: Duration::from_secs(1200),
            absolute_deadline: None,
            observation_interval: Duration::from_secs(5),
            drain_timeout: Duration::from_secs(15),
            max_log_bytes: 64 * 1024 * 1024,
            tail_policy: TailPolicy::Reject,
            resource_policy: ResourcePolicy::current(),
            minecraft_stop: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    Completed,
    CompletedAfterOwnedTailCleanup,
    Cancelled,
    Timeout,
    OutputLimit,
    ObservationFailure,
    ResourceBudget,
    RemainingChildren,
    SupervisorFailure,
}

/// Only Running observations have the original active command checkpoints.
/// PreSpawn retains strict storage observation without recovery waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationPhase {
    PreSpawn,
    Running,
}

#[derive(Debug, Serialize)]
pub struct ProcessOutcome {
    pub command_exit: Option<i32>,
    pub command_signal: Option<i32>,
    pub supervisor_errors: Vec<String>,
    /// The native owned scope has no live processes, and its leader was reaped.
    pub drained: bool,
    pub termination_reason: TerminationReason,
    pub elapsed_ms: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    /// False on an output cap/read/flush failure; retained logs are still evidence.
    pub output_complete: bool,
    /// Explicit build-tail termination of the live owned native scope was
    /// accepted. Drain and capture remain independent completion requirements.
    pub owned_tail_terminated: bool,
    pub native_scope: &'static str,
    pub resource_policy: ResourcePolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minecraft_stop: Option<MinecraftStopEvidence>,
    #[cfg(any(windows, target_os = "linux"))]
    pub resource_limits: Option<resource_policy::Evidence>,
    #[cfg(target_os = "linux")]
    pub linux_original_lifetimes: Option<linux_resources::LifetimeEvidence>,
    #[cfg(target_os = "macos")]
    pub darwin_resources: Option<darwin_resources::Evidence>,
}

/// Closed selection of an original native capture stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureStream {
    Stdout,
    Stderr,
}

/// The original stdout/stderr capture handles and their native completion outcome.
/// Construction is private to supervision; neither JSON nor a log pathname can
/// construct this value. Its bytes are evidence, never a grant or target proof.
/// The caller must retain its managed ownership and lease while reading.
pub struct CapturedProcessOutcome {
    outcome: ProcessOutcome,
    stdout_log: File,
    stderr_log: File,
    process_started: bool,
}

impl fmt::Debug for CapturedProcessOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // File's Debug representation may include its private physical path.
        f.debug_struct("CapturedProcessOutcome")
            .field("outcome", &self.outcome)
            .field("process_started", &self.process_started)
            .finish_non_exhaustive()
    }
}

impl CapturedProcessOutcome {
    pub fn outcome(&self) -> &ProcessOutcome {
        &self.outcome
    }

    /// Set only by this supervisor's actual native spawn result. A pre-spawn
    /// cancellation/expired deadline has a completion record without a child.
    pub fn process_started(&self) -> bool {
        self.process_started
    }

    /// Close both original capture handles and retain the unchanged JSON outcome.
    pub fn into_outcome(self) -> ProcessOutcome {
        self.outcome
    }

    /// Read only the same completed capture, with an explicit positive cap of at
    /// most 64 MiB, 64 KiB chunks and a five-second local read budget. `check`
    /// must validate the caller's original current ownership, cancellation and
    /// deadline; a new local read budget does not extend that caller deadline.
    /// Checks surround every I/O operation. Filesystem calls and caller checks
    /// remain cooperative and cannot be preempted while inside the OS/callback.
    /// Any failure discards the partially read vector.
    pub fn read_stdout(
        &mut self,
        max_bytes: usize,
        check: impl FnMut() -> Result<(), String>,
    ) -> Result<Vec<u8>, ProcessError> {
        if self.outcome.command_exit != Some(0)
            || self.outcome.command_signal.is_some()
            || !self.outcome.drained
            || !self.outcome.output_complete
            || !self.outcome.supervisor_errors.is_empty()
            || !matches!(
                self.outcome.termination_reason,
                TerminationReason::Completed | TerminationReason::CompletedAfterOwnedTailCleanup
            )
        {
            let mut error = ProcessError::new(
                "capture_incomplete",
                "stdout bytes require a successful drained command and complete capture",
            );
            error.drained = self.outcome.drained;
            return Err(error);
        }
        self.read_drained_log(CaptureStream::Stdout, max_bytes, check)
    }

    /// Read retained diagnostic bytes from the original held stream after native drain.
    /// Nonzero exit, cancellation or incomplete output remain unchanged in `outcome`.
    /// These bytes are evidence only; this method does not satisfy the strict stdout
    /// consumer gate or certify command success, complete output or product acceptance.
    /// The 64 MiB cap, 64 KiB chunks and five-second local bound are shared with
    /// `read_stdout`. An explicitly admitted evidence-only post-drain caller may
    /// use its own finite preservation deadline and current ownership checks;
    /// that exception cannot resume the command or extend its execution budget.
    pub fn read_drained_log(
        &mut self,
        stream: CaptureStream,
        max_bytes: usize,
        check: impl FnMut() -> Result<(), String>,
    ) -> Result<Vec<u8>, ProcessError> {
        if !self.outcome.drained {
            let mut error = ProcessError::new(
                "capture_incomplete",
                "raw capture evidence requires a drained native owned scope",
            );
            error.drained = false;
            return Err(error);
        }
        let (log, expected) = match stream {
            CaptureStream::Stdout => (&mut self.stdout_log, self.outcome.stdout_bytes),
            CaptureStream::Stderr => (&mut self.stderr_log, self.outcome.stderr_bytes),
        };
        read_captured_log(log, expected, max_bytes, check)
    }
}

fn read_captured_log(
    log: &mut File,
    recorded_bytes: u64,
    max_bytes: usize,
    mut check: impl FnMut() -> Result<(), String>,
) -> Result<Vec<u8>, ProcessError> {
    if max_bytes == 0 || max_bytes > MAX_CAPTURE_READ_BYTES {
        return Err(ProcessError::new(
            "capture_read_budget",
            "capture read cap must be positive and at most 64 MiB",
        ));
    }
    let expected = usize::try_from(recorded_bytes).map_err(|_| {
        ProcessError::new("capture_read_budget", "capture length exceeds the read cap")
    })?;
    if expected > max_bytes {
        return Err(ProcessError::new(
            "capture_read_budget",
            "capture length exceeds the read cap",
        ));
    }
    let started = Instant::now();
    capture_read_checkpoint(&mut check, started)?;
    let metadata = log
        .metadata()
        .map_err(|error| ProcessError::io("inspect original retained capture", error))?;
    capture_read_checkpoint(&mut check, started)?;
    if !metadata.is_file() || metadata.len() != recorded_bytes {
        return Err(ProcessError::new(
            "capture_changed",
            "original retained capture size or file type changed",
        ));
    }
    log.seek(SeekFrom::Start(0))
        .map_err(|error| ProcessError::io("seek original retained capture", error))?;
    capture_read_checkpoint(&mut check, started)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected)
        .map_err(|_| ProcessError::new("capture_read_budget", "capture read allocation failed"))?;
    let mut buffer = [0; CAPTURE_READ_BYTES];
    while bytes.len() < expected {
        capture_read_checkpoint(&mut check, started)?;
        let remaining = (expected - bytes.len()).min(buffer.len());
        let read = log
            .read(&mut buffer[..remaining])
            .map_err(|error| ProcessError::io("read original retained capture", error))?;
        capture_read_checkpoint(&mut check, started)?;
        if read == 0 {
            return Err(ProcessError::new(
                "capture_changed",
                "original retained capture ended before its recorded length",
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    capture_read_checkpoint(&mut check, started)?;
    let mut excess = [0; 1];
    let excess_bytes = log
        .read(&mut excess)
        .map_err(|error| ProcessError::io("confirm original retained capture EOF", error))?;
    capture_read_checkpoint(&mut check, started)?;
    if excess_bytes != 0 {
        return Err(ProcessError::new(
            "capture_changed",
            "original retained capture grew beyond its recorded length",
        ));
    }
    let final_metadata = log
        .metadata()
        .map_err(|error| ProcessError::io("recheck original retained capture", error))?;
    capture_read_checkpoint(&mut check, started)?;
    if !final_metadata.is_file() || final_metadata.len() != recorded_bytes {
        return Err(ProcessError::new(
            "capture_changed",
            "original retained capture final size or file type changed",
        ));
    }
    Ok(bytes)
}

fn capture_read_checkpoint(
    check: &mut impl FnMut() -> Result<(), String>,
    started: Instant,
) -> Result<(), ProcessError> {
    let timeout = || {
        ProcessError::new(
            "capture_read_timeout",
            "original retained capture read deadline exceeded",
        )
    };
    if started.elapsed() >= CAPTURE_READ_TIMEOUT {
        return Err(timeout());
    }
    check().map_err(|message| ProcessError::new("capture_read_check", message))?;
    if started.elapsed() >= CAPTURE_READ_TIMEOUT {
        return Err(timeout());
    }
    Ok(())
}

#[derive(Debug)]
pub struct ProcessError {
    pub kind: &'static str,
    pub message: String,
    /// False means native ownership could not establish a drained scope.
    pub drained: bool,
    pub minecraft_stop: Option<Box<MinecraftStopEvidence>>,
    #[cfg(any(target_os = "linux", test))]
    linux_pidfd_diagnostic: Option<linux_resources::PidfdDiagnostic>,
    #[cfg(any(target_os = "linux", test))]
    linux_stat_diagnostic: Option<Box<linux_resources::StatDiagnostic>>,
}
impl ProcessError {
    fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            drained: true,
            minecraft_stop: None,
            #[cfg(any(target_os = "linux", test))]
            linux_pidfd_diagnostic: None,
            #[cfg(any(target_os = "linux", test))]
            linux_stat_diagnostic: None,
        }
    }
    #[cfg(any(target_os = "linux", test))]
    fn with_linux_pidfd_diagnostic(mut self, diagnostic: linux_resources::PidfdDiagnostic) -> Self {
        // Keep the first secondary observation and the complete original
        // native error, including its kind, message and drain fact.
        if self.linux_pidfd_diagnostic.is_none() {
            self.linux_pidfd_diagnostic = Some(diagnostic);
        }
        self
    }
    #[cfg(any(target_os = "linux", test))]
    fn with_linux_stat_diagnostic(mut self, diagnostic: linux_resources::StatDiagnostic) -> Self {
        // Closed stat facts supplement, never replace, the original error or
        // the separately retained pidfd observation.
        if self.linux_stat_diagnostic.is_none() {
            self.linux_stat_diagnostic = Some(Box::new(diagnostic));
        }
        self
    }
    fn io(context: &str, error: std::io::Error) -> Self {
        Self::new("io", format!("{context}: {error}"))
    }
}
impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)?;
        #[cfg(any(target_os = "linux", test))]
        if let Some(diagnostic) = self.linux_pidfd_diagnostic {
            write!(f, "; {diagnostic}")?;
        }
        #[cfg(any(target_os = "linux", test))]
        if let Some(diagnostic) = self.linux_stat_diagnostic.as_ref() {
            write!(f, "; {diagnostic}")?;
        }
        Ok(())
    }
}
impl std::error::Error for ProcessError {}

/// The observation callback checks managed ownership and finite disk budgets.
/// No environment values, command arguments or private paths enter the receipt.
pub fn supervise(
    spec: &ProcessSpec,
    cancellation: &AtomicBool,
    mut observe: impl FnMut() -> Result<(), String>,
) -> Result<ProcessOutcome, ProcessError> {
    supervise_with_progress(spec, cancellation, |_| observe())
}

/// Managed observations may checkpoint between bounded filesystem operations.
/// Each checkpoint samples actual native resources according to the fixed
/// platform policy. Darwin deadlines require a complete successful sample.
pub fn supervise_with_progress(
    spec: &ProcessSpec,
    cancellation: &AtomicBool,
    observe: impl FnMut(&mut dyn FnMut() -> Result<(), String>) -> Result<(), String>,
) -> Result<ProcessOutcome, ProcessError> {
    supervise_with_progress_captured(spec, cancellation, observe)
        .map(CapturedProcessOutcome::into_outcome)
}

/// Preserve both original log handles for bounded post-drain reads. The
/// existing observation callback and native completion requirements are shared
/// with `supervise_with_progress`; this API does not acquire a managed lease.
pub fn supervise_with_progress_captured(
    spec: &ProcessSpec,
    cancellation: &AtomicBool,
    mut observe: impl FnMut(&mut dyn FnMut() -> Result<(), String>) -> Result<(), String>,
) -> Result<CapturedProcessOutcome, ProcessError> {
    supervise_with_progress_captured_phased(spec, cancellation, |_, checkpoint| observe(checkpoint))
}

pub fn supervise_with_progress_phased(
    spec: &ProcessSpec,
    cancellation: &AtomicBool,
    observe: impl FnMut(ObservationPhase, &mut dyn FnMut() -> Result<(), String>) -> Result<(), String>,
) -> Result<ProcessOutcome, ProcessError> {
    supervise_with_progress_captured_phased(spec, cancellation, observe)
        .map(CapturedProcessOutcome::into_outcome)
}

/// Retain the original two capture handles while preserving distinct pre-spawn
/// and running observation policies. Post-drain diagnostic reads never grant
/// successful output, managed completion, cleanup or lease release.
pub fn supervise_with_progress_captured_phased(
    spec: &ProcessSpec,
    cancellation: &AtomicBool,
    observe: impl FnMut(ObservationPhase, &mut dyn FnMut() -> Result<(), String>) -> Result<(), String>,
) -> Result<CapturedProcessOutcome, ProcessError> {
    validate(spec)?;
    let binding = spec
        .minecraft_stop
        .as_ref()
        .map(MinecraftStopBinding::bind)
        .transpose()?;
    let mut result = supervise_bound(spec, cancellation, observe);
    if let Some(binding) = &binding {
        let requested = binding.close();
        let evidence = match &mut result {
            Ok(captured) => captured
                .outcome
                .minecraft_stop
                .get_or_insert_with(MinecraftStopEvidence::new),
            Err(error) => error
                .minecraft_stop
                .get_or_insert_with(|| Box::new(MinecraftStopEvidence::new()))
                .as_mut(),
        };
        evidence.requested = requested;
        evidence.control_closed = true;
    }
    result
}

fn supervise_bound(
    spec: &ProcessSpec,
    cancellation: &AtomicBool,
    mut observe: impl FnMut(
        ObservationPhase,
        &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String>,
) -> Result<CapturedProcessOutcome, ProcessError> {
    run_observation(
        &mut |checkpoint| observe(ObservationPhase::PreSpawn, checkpoint),
        || Ok(()),
    )?;
    let started = Instant::now();
    let mut stdout_log = create_log(&spec.stdout_log)?;
    let mut stderr_log = create_log(&spec.stderr_log)?;
    let mut outcome = ProcessOutcome {
        command_exit: None,
        command_signal: None,
        supervisor_errors: Vec::new(),
        drained: false,
        termination_reason: TerminationReason::Completed,
        elapsed_ms: 0,
        stdout_bytes: 0,
        stderr_bytes: 0,
        output_complete: true,
        owned_tail_terminated: false,
        native_scope: native::SCOPE,
        resource_policy: spec.resource_policy,
        minecraft_stop: spec
            .minecraft_stop
            .as_ref()
            .map(|_| MinecraftStopEvidence::new()),
        #[cfg(any(windows, target_os = "linux"))]
        resource_limits: None,
        #[cfg(target_os = "linux")]
        linux_original_lifetimes: None,
        #[cfg(target_os = "macos")]
        darwin_resources: None,
    };
    if cancellation.load(Ordering::Acquire) {
        outcome.drained = true;
        outcome.termination_reason = TerminationReason::Cancelled;
        outcome
            .supervisor_errors
            .push("cancelled before process creation".into());
        return Ok(CapturedProcessOutcome {
            outcome,
            stdout_log,
            stderr_log,
            process_started: false,
        });
    }
    if spec
        .absolute_deadline
        .is_some_and(|deadline| Instant::now() >= deadline)
    {
        outcome.drained = true;
        outcome.termination_reason = TerminationReason::Timeout;
        outcome
            .supervisor_errors
            .push("deadline expired before process creation".into());
        return Ok(CapturedProcessOutcome {
            outcome,
            stdout_log,
            stderr_log,
            process_started: false,
        });
    }
    let mut process = native::Process::spawn(spec)?;
    if let Some(evidence) = &mut outcome.minecraft_stop {
        evidence.writer_available = true;
        evidence.pipe_capacity_bytes = process.minecraft_stop_capacity();
    }
    let mut last_observation = started;
    let mut stopping_at = None;
    let mut exited_at = None;
    let mut leader_exited_at = None;
    let mut capture_failed = false;
    let mut empty_observations = 0u8;
    loop {
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        if failure_checks_active(&outcome, stopping_at) {
            #[cfg(target_os = "linux")]
            let observed = linux_observation_control(
                spec,
                cancellation,
                started,
                stopping_at,
                LinuxObservationPhase::Resource,
                |control| process.observe_resources(control),
            );
            #[cfg(not(target_os = "linux"))]
            let observed = process.observe_resources();
            if let Err(error) = observed {
                request_stop(
                    &mut process,
                    &mut outcome,
                    &mut stopping_at,
                    observation_reason(&error),
                    error.to_string(),
                );
            }
            record_resource_evidence(&process, &mut outcome);
        }
        if !capture_failed {
            // Retain the same finite total capture budget on Darwin, but
            // observe between bounded 8KiB pipe batches rather than after two
            // 256KiB loops.
            let capture_batches = if cfg!(target_os = "macos") { 32 } else { 1 };
            for _ in 0..capture_batches {
                let capture = process.capture(
                    &mut stdout_log,
                    &mut stderr_log,
                    &mut outcome.stdout_bytes,
                    &mut outcome.stderr_bytes,
                    spec.max_log_bytes,
                );
                if let Err(error) = capture {
                    capture_failed = true;
                    outcome.output_complete = false;
                    let reason = if error.kind == "output_limit" {
                        TerminationReason::OutputLimit
                    } else {
                        TerminationReason::SupervisorFailure
                    };
                    request_stop(
                        &mut process,
                        &mut outcome,
                        &mut stopping_at,
                        reason,
                        error.to_string(),
                    );
                    break;
                }
                #[cfg(target_os = "macos")]
                if failure_checks_active(&outcome, stopping_at) {
                    if let Err(error) =
                        progress_sample(&mut process, spec, cancellation, started, stopping_at)
                    {
                        request_stop(
                            &mut process,
                            &mut outcome,
                            &mut stopping_at,
                            observation_reason(&error),
                            error.to_string(),
                        );
                    }
                    record_resource_evidence(&process, &mut outcome);
                }
            }
        }
        // Optional build-tail cleanup remains subject to cancellation, time,
        // output and managed-storage observations until physical completion.
        if failure_checks_active(&outcome, stopping_at) && cancellation.load(Ordering::Acquire) {
            request_stop(
                &mut process,
                &mut outcome,
                &mut stopping_at,
                TerminationReason::Cancelled,
                "command cancelled".into(),
            );
        }
        if failure_checks_active(&outcome, stopping_at) && command_deadline_expired(spec, started) {
            request_stop(
                &mut process,
                &mut outcome,
                &mut stopping_at,
                TerminationReason::Timeout,
                "command timeout exceeded".into(),
            );
        }
        if failure_checks_active(&outcome, stopping_at)
            && last_observation.elapsed() >= spec.observation_interval
        {
            let observation = run_observation(
                &mut |checkpoint| observe(ObservationPhase::Running, checkpoint),
                || {
                    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
                    progress_sample(&mut process, spec, cancellation, started, stopping_at)?;
                    Ok(())
                },
            );
            last_observation = Instant::now();
            record_resource_evidence(&process, &mut outcome);
            if let Err(error) = observation {
                request_stop(
                    &mut process,
                    &mut outcome,
                    &mut stopping_at,
                    observation_reason(&error),
                    format!("managed observation failed: {error}"),
                );
            }
        }
        // 정상 요청은 hard failure와 별개다. storage/resource/capture 및 원 기한은 계속 적용한다.
        if stopping_at.is_none()
            && spec
                .minecraft_stop
                .as_ref()
                .is_some_and(MinecraftStopHandle::requested)
            && outcome
                .minecraft_stop
                .as_ref()
                .is_some_and(|evidence| !evidence.writer_closed)
        {
            // observation callback/OS 호출 동안 원 취소나 기한이 끝났으면 새 입력을 보내지 않는다.
            #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
            let checked = progress_sample(&mut process, spec, cancellation, started, stopping_at);
            #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
            let checked = Err(ProcessError::new(
                "unsupported_os",
                "no native stop writer for this OS",
            ));
            record_resource_evidence(&process, &mut outcome);
            if let Err(error) = checked {
                request_stop(
                    &mut process,
                    &mut outcome,
                    &mut stopping_at,
                    observation_reason(&error),
                    error.to_string(),
                );
            } else if let Some(evidence) = &mut outcome.minecraft_stop {
                evidence.requested = true;
                evidence.request_observed = true;
                if let Err(error) = advance_minecraft_stop(&mut process, evidence) {
                    request_stop(
                        &mut process,
                        &mut outcome,
                        &mut stopping_at,
                        TerminationReason::SupervisorFailure,
                        error.to_string(),
                    );
                }
            }
        }
        let leader = match process.leader_exit() {
            Ok(value) => value,
            Err(error) => {
                request_stop(
                    &mut process,
                    &mut outcome,
                    &mut stopping_at,
                    TerminationReason::SupervisorFailure,
                    error.to_string(),
                );
                None
            }
        };
        if let Some(exit) = leader {
            outcome.command_exit = exit.code;
            outcome.command_signal = exit.signal;
            leader_exited_at.get_or_insert_with(Instant::now);
        }
        #[cfg(target_os = "linux")]
        let scope_observation = linux_observation_control(
            spec,
            cancellation,
            started,
            stopping_at,
            LinuxObservationPhase::Scope,
            |control| process.scope_empty(control),
        );
        #[cfg(not(target_os = "linux"))]
        let scope_observation = process.scope_empty();
        #[cfg(target_os = "linux")]
        {
            outcome.linux_original_lifetimes = Some(process.lifetime_evidence());
        }
        let raw_scope_empty = match scope_observation {
            Ok(value) => value,
            Err(error) => {
                let reason = if matches!(error.kind, "command_cancelled" | "command_timeout") {
                    observation_reason(&error)
                } else {
                    TerminationReason::SupervisorFailure
                };
                request_stop(
                    &mut process,
                    &mut outcome,
                    &mut stopping_at,
                    reason,
                    error.to_string(),
                );
                false
            }
        };
        empty_observations = if leader.is_some() && raw_scope_empty {
            empty_observations.saturating_add(1)
        } else {
            0
        };
        let scope_empty = raw_scope_empty && empty_observations >= 2;
        let drain_deadline_exceeded =
            stopping_at.is_some_and(|at: Instant| at.elapsed() >= spec.drain_timeout);
        if drain_deadline_exceeded {
            outcome.supervisor_errors.push("owned scope drain deadline exceeded; lease must be preserved unless subsequent native proof certifies drain".into());
            if outcome.termination_reason == TerminationReason::CompletedAfterOwnedTailCleanup {
                outcome.termination_reason = TerminationReason::SupervisorFailure;
            }
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let resource_observation_pending =
            failure_checks_active(&outcome, stopping_at) && process.resource_observation_pending();
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let resource_observation_pending = false;
        // A count-only empty observation cannot complete an unresolved RSS
        // sample. Keep the reservation until the next normally scheduled
        // resource observation resolves it, or a finite failure stops it.
        // Physical drain after a hard failure remains independent.
        if leader.is_some()
            && scope_empty
            && !resource_observation_pending
            && (capture_failed || process.outputs_closed())
        {
            match process.reap() {
                Ok(()) => outcome.drained = true,
                Err(error) => {
                    outcome.termination_reason = TerminationReason::SupervisorFailure;
                    outcome.supervisor_errors.push(error.to_string());
                }
            }
            break;
        }
        if drain_deadline_exceeded {
            break;
        }
        if leader.is_some() && raw_scope_empty {
            // EOF is independent from leader/group termination. An escaped
            // writer retaining an inherited pipe must not block forever or be
            // silently reported as complete output and a drained execution.
            let at = exited_at.get_or_insert_with(Instant::now);
            if at.elapsed() >= spec.drain_timeout {
                outcome.output_complete = false;
                outcome.supervisor_errors.push(
                    "output pipes remained open after owned scope exit; drain cannot be certified"
                        .into(),
                );
                outcome.termination_reason = TerminationReason::SupervisorFailure;
                break;
            }
        }
        if leader.is_some()
            && !raw_scope_empty
            && stopping_at.is_none()
            && leader_exited_at.is_some_and(|at: Instant| at.elapsed() >= NATURAL_EXIT_GRACE)
        {
            match spec.tail_policy {
                TailPolicy::Reject => request_stop(
                    &mut process,
                    &mut outcome,
                    &mut stopping_at,
                    TerminationReason::RemainingChildren,
                    "owned children remained after the finite natural exit grace".into(),
                ),
                TailPolicy::TerminateForBuild => {
                    stopping_at = Some(Instant::now());
                    match process.terminate() {
                        Ok(()) => {
                            outcome.owned_tail_terminated = true;
                            outcome.termination_reason =
                                TerminationReason::CompletedAfterOwnedTailCleanup;
                        }
                        Err(error) => {
                            outcome.termination_reason = TerminationReason::SupervisorFailure;
                            outcome.supervisor_errors.push(error.to_string());
                        }
                    }
                }
            }
        }
        std::thread::sleep(POLL);
    }
    #[cfg(target_os = "linux")]
    {
        let closed = linux_observation_control(
            spec,
            cancellation,
            started,
            stopping_at,
            LinuxObservationPhase::Close,
            |control| {
                let (evidence, result) = process.close_linux_observation(control);
                outcome.linux_original_lifetimes = Some(evidence);
                result
            },
        );
        if let Err(error) = closed {
            outcome.supervisor_errors.push(error.to_string());
            if matches!(
                outcome.termination_reason,
                TerminationReason::Completed | TerminationReason::CompletedAfterOwnedTailCleanup
            ) {
                outcome.termination_reason = observation_reason(&error);
            }
        }
    }
    if let Err(error) = close_minecraft_stdin(&mut process, &mut outcome.minecraft_stop) {
        outcome.supervisor_errors.push(error.to_string());
        if matches!(
            outcome.termination_reason,
            TerminationReason::Completed | TerminationReason::CompletedAfterOwnedTailCleanup
        ) {
            outcome.termination_reason = TerminationReason::SupervisorFailure;
        }
    }
    outcome.output_complete &= process.outputs_closed() && !capture_failed;
    for (label, log) in [("stdout", &mut stdout_log), ("stderr", &mut stderr_log)] {
        if let Err(error) = log.sync_all() {
            outcome.output_complete = false;
            outcome
                .supervisor_errors
                .push(format!("flush {label} evidence: {error}"));
            if matches!(
                outcome.termination_reason,
                TerminationReason::Completed | TerminationReason::CompletedAfterOwnedTailCleanup
            ) {
                outcome.termination_reason = TerminationReason::SupervisorFailure;
            }
        }
    }
    if outcome.termination_reason == TerminationReason::CompletedAfterOwnedTailCleanup
        && (!outcome.drained || !outcome.output_complete || !outcome.supervisor_errors.is_empty())
    {
        outcome.termination_reason = TerminationReason::SupervisorFailure;
    }
    outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(CapturedProcessOutcome {
        outcome,
        stdout_log,
        stderr_log,
        process_started: true,
    })
}

fn command_deadline_expired(spec: &ProcessSpec, started: Instant) -> bool {
    started.elapsed() >= spec.timeout
        || spec
            .absolute_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
}

fn observation_reason(error: &ProcessError) -> TerminationReason {
    if error.kind == "command_cancelled" {
        return TerminationReason::Cancelled;
    }
    if error.kind == "command_timeout" {
        return TerminationReason::Timeout;
    }
    if error.kind == "resource_budget" {
        return TerminationReason::ResourceBudget;
    }
    TerminationReason::ObservationFailure
}

fn record_resource_evidence(process: &native::Process, outcome: &mut ProcessOutcome) {
    #[cfg(target_os = "macos")]
    {
        outcome.darwin_resources = Some(process.resource_evidence());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        outcome.resource_limits = Some(process.resource_evidence());
        #[cfg(target_os = "linux")]
        {
            outcome.linux_original_lifetimes = Some(process.lifetime_evidence());
        }
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    let _ = (process, outcome);
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum LinuxObservationPhase {
    Resource,
    Scope,
    Close,
}

#[cfg(target_os = "linux")]
fn linux_observation_control<T>(
    spec: &ProcessSpec,
    cancellation: &AtomicBool,
    started: Instant,
    stopping_at: Option<Instant>,
    phase: LinuxObservationPhase,
    observe: impl FnOnce(&mut linux_resources::ObservationControl<'_>) -> Result<T, ProcessError>,
) -> Result<T, ProcessError> {
    let physical_drain = matches!(
        phase,
        LinuxObservationPhase::Scope | LinuxObservationPhase::Close
    );
    let scope_phase = match (phase, stopping_at.is_some()) {
        (LinuxObservationPhase::Resource, false) => "running_resource",
        (LinuxObservationPhase::Resource, true) => "active_build_tail_resource",
        (LinuxObservationPhase::Scope, false) => "running_scope",
        (LinuxObservationPhase::Scope, true) => "fixed_drain_scope",
        (LinuxObservationPhase::Close, false) => "command_close",
        (LinuxObservationPhase::Close, true) => "fixed_drain_close",
    };
    // A hard-stop's original failure remains sticky in ProcessOutcome. Its
    // already fixed drain interval permits only native queries and close;
    // it never restarts the command or authorizes a new lifetime binding.
    let mut checkpoint = |phase| {
        if physical_drain && let Some(stopped) = stopping_at {
            if stopped.elapsed() >= spec.drain_timeout {
                return Err(ProcessError::new(
                    "command_timeout",
                    format!("Linux fixed drain deadline exceeded; phase={phase}"),
                ));
            }
            return Ok(());
        }
        if cancellation.load(Ordering::Acquire) {
            return Err(ProcessError::new(
                "command_cancelled",
                format!("command cancelled during Linux observation; phase={phase}"),
            ));
        }
        if command_deadline_expired(spec, started)
            || stopping_at.is_some_and(|at| at.elapsed() >= spec.drain_timeout)
        {
            return Err(ProcessError::new(
                "command_timeout",
                format!("original Linux observation deadline exceeded; phase={phase}"),
            ));
        }
        Ok(())
    };
    let mut control =
        linux_resources::ObservationControl::new(&mut checkpoint, stopping_at.is_none())
            .in_scope(scope_phase);
    // Do not skip consuming close merely because the original budget expired.
    // Every normal query checks before doing I/O; close records that failure
    // while independently attempting all owned descriptors exactly once.
    let result = observe(&mut control);
    control.finish(result, "observation_return")
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn progress_sample(
    process: &mut native::Process,
    spec: &ProcessSpec,
    cancellation: &AtomicBool,
    started: Instant,
    stopping_at: Option<Instant>,
) -> Result<(), ProcessError> {
    #[cfg(target_os = "linux")]
    linux_observation_control(
        spec,
        cancellation,
        started,
        stopping_at,
        LinuxObservationPhase::Resource,
        |control| process.observe_resources(control),
    )?;
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stopping_at;
        process.observe_resources()?;
    }
    if cancellation.load(Ordering::Acquire) {
        return Err(ProcessError::new("command_cancelled", "command cancelled"));
    }
    if command_deadline_expired(spec, started) {
        return Err(ProcessError::new(
            "command_timeout",
            "command timeout exceeded",
        ));
    }
    Ok(())
}

fn run_observation(
    observe: &mut impl FnMut(&mut dyn FnMut() -> Result<(), String>) -> Result<(), String>,
    mut sample: impl FnMut() -> Result<(), ProcessError>,
) -> Result<(), ProcessError> {
    let mut first_failure: Option<ProcessError> = None;
    let observation = {
        let mut checkpoint = || {
            if let Some(error) = &first_failure {
                return Err(error.to_string());
            }
            match sample() {
                Ok(()) => Ok(()),
                Err(error) => {
                    let message = error.to_string();
                    first_failure = Some(error);
                    Err(message)
                }
            }
        };
        observe(&mut checkpoint)
    };
    // A callback must not hide a native failure by wrapping its text or
    // ignoring it. Keep the original error kind for termination and evidence.
    match first_failure {
        Some(mut error) => {
            if let Err(context) = observation {
                // Only the storage retry formatter's path-safe native facts
                // may be attached. An arbitrary observer string can contain a
                // private path and must not enter the shared primary message.
                if let Some(safe) = safe_retry_observation_context(&context) {
                    error.message.push_str("; observer_context=");
                    error.message.push_str(&safe);
                }
            }
            Err(error)
        }
        None => observation.map_err(|error| ProcessError::new("observation", error)),
    }
}

fn safe_retry_observation_context(context: &str) -> Option<String> {
    // Copy only fixed/numeric fields before generated_relative. The companion
    // record separately retains the existing escaped/withheld relative label.
    let (_, context) = context.split_once(": metadata reobservation; ")?;
    let (facts, _) = context.split_once("; generated_relative=")?;
    let mut safe = String::new();
    let mut seen = 0u8;
    for field in facts.split("; ") {
        let (name, value) = field.split_once('=')?;
        let (bit, valid) = match name {
            "first_kind" => (1, value == "PermissionDenied"),
            "final_kind" => (
                2,
                matches!(
                    value,
                    "io" | "observation_failed"
                        | "retry_budget"
                        | "retry_evidence"
                        | "ownership"
                        | "link"
                        | "link_escape"
                        | "file_type"
                        | "path_escape"
                        | "secret_path"
                        | "path"
                        | "record"
                        | "record_limit"
                        | "schema"
                ),
            ),
            "attempts" => (4, matches!(value, "1" | "2" | "3")),
            "first_raw_os_error" => (8, value == "Some(5)"),
            "final_raw_os_error" => (
                16,
                value == "None"
                    || value
                        .strip_prefix("Some(")
                        .and_then(|value| value.strip_suffix(')'))
                        .is_some_and(|number| {
                            !number.is_empty()
                                && number.len() <= 11
                                && number.parse::<i32>().is_ok()
                        }),
            ),
            _ => return None,
        };
        if !valid || seen & bit != 0 || safe.len() + field.len() + 2 > 2048 {
            return None;
        }
        seen |= bit;
        if !safe.is_empty() {
            safe.push_str("; ");
        }
        safe.push_str(field);
    }
    (seen == 31).then_some(safe)
}

fn failure_checks_active(outcome: &ProcessOutcome, stopping_at: Option<Instant>) -> bool {
    stopping_at.is_none()
        || outcome.termination_reason == TerminationReason::CompletedAfterOwnedTailCleanup
}

fn request_stop(
    process: &mut native::Process,
    outcome: &mut ProcessOutcome,
    stopping_at: &mut Option<Instant>,
    reason: TerminationReason,
    error: String,
) {
    if !failure_checks_active(outcome, *stopping_at) {
        return;
    }
    stopping_at.get_or_insert_with(Instant::now);
    outcome.termination_reason = reason;
    outcome.supervisor_errors.push(error);
    if let Err(error) = close_minecraft_stdin(process, &mut outcome.minecraft_stop) {
        outcome.supervisor_errors.push(error.to_string());
    }
    if let Err(error) = process.terminate() {
        outcome.supervisor_errors.push(error.to_string());
    }
}

trait MinecraftStopSink {
    fn write_stop(&mut self, offset: usize) -> MinecraftStopWrite;
    fn close_stop(&mut self) -> std::io::Result<bool>;
}
impl MinecraftStopSink for native::Process {
    fn write_stop(&mut self, offset: usize) -> MinecraftStopWrite {
        self.write_minecraft_stop(offset)
    }
    fn close_stop(&mut self) -> std::io::Result<bool> {
        self.close_minecraft_stop()
    }
}
struct MinecraftStopWrite {
    bytes: usize,
    error: Option<std::io::Error>,
}
impl MinecraftStopWrite {
    fn result(result: std::io::Result<usize>) -> Self {
        match result {
            Ok(bytes) => Self { bytes, error: None },
            Err(error) => Self {
                bytes: 0,
                error: Some(error),
            },
        }
    }
}
fn stop_io_failure(operation: &'static str, error: &std::io::Error) -> ProcessError {
    ProcessError::new(
        operation,
        format!(
            "fixed Minecraft stop pipe failed: kind={:?}; raw_os_error={:?}",
            error.kind(),
            error.raw_os_error()
        ),
    )
}
fn advance_minecraft_stop(
    sink: &mut impl MinecraftStopSink,
    evidence: &mut MinecraftStopEvidence,
) -> Result<(), ProcessError> {
    if evidence.bytes_written < MINECRAFT_STOP_BYTES.len() {
        evidence.write_attempts = evidence.write_attempts.saturating_add(1);
        let written = sink.write_stop(evidence.bytes_written);
        if written.bytes > MINECRAFT_STOP_BYTES.len() - evidence.bytes_written {
            let error = std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "native fixed stop count exceeds its remaining payload",
            );
            evidence.write_error = Some(MinecraftStopIoError::from_io(&error));
            return Err(stop_io_failure("minecraft_stop_write", &error));
        }
        evidence.bytes_written += written.bytes;
        if let Some(error) = written.error {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                evidence.would_block = evidence.would_block.saturating_add(1);
                evidence.last_would_block = Some(MinecraftStopIoError::from_io(&error));
                return Ok(());
            }
            evidence.write_error = Some(MinecraftStopIoError::from_io(&error));
            return Err(stop_io_failure("minecraft_stop_write", &error));
        }
        if written.bytes == 0 {
            let error = std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "fixed stop write made no bounded progress",
            );
            evidence.write_error = Some(MinecraftStopIoError::from_io(&error));
            return Err(stop_io_failure("minecraft_stop_write", &error));
        }
    }
    if evidence.bytes_written == MINECRAFT_STOP_BYTES.len() {
        close_minecraft_writer(sink, evidence)?;
    }
    Ok(())
}
fn close_minecraft_writer(
    sink: &mut impl MinecraftStopSink,
    evidence: &mut MinecraftStopEvidence,
) -> Result<(), ProcessError> {
    if !evidence.writer_available || evidence.writer_closed || evidence.close_error.is_some() {
        return Ok(());
    }
    match sink.close_stop() {
        Ok(true) => {
            evidence.writer_closed = true;
            Ok(())
        }
        result => {
            let error = result.err().unwrap_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "original stop writer is unavailable",
                )
            });
            evidence.close_error = Some(MinecraftStopIoError::from_io(&error));
            Err(stop_io_failure("minecraft_stop_close", &error))
        }
    }
}
fn close_minecraft_stdin(
    sink: &mut impl MinecraftStopSink,
    evidence: &mut Option<MinecraftStopEvidence>,
) -> Result<(), ProcessError> {
    if let Some(evidence) = evidence {
        close_minecraft_writer(sink, evidence)?;
    }
    Ok(())
}

fn validate(spec: &ProcessSpec) -> Result<(), ProcessError> {
    spec.resource_policy.validate_current()?;
    if spec.timeout < Duration::from_secs(1)
        || spec.timeout > Duration::from_secs(3600)
        || spec.observation_interval.is_zero()
        || spec.observation_interval > Duration::from_secs(5)
        || spec.drain_timeout.is_zero()
        || spec.drain_timeout > Duration::from_secs(60)
        || spec.max_log_bytes == 0
    {
        return Err(ProcessError::new(
            "budget",
            "timeout must be 1..3600 seconds, observation <=5 seconds, drain <=60 seconds and output budget positive",
        ));
    }
    for path in [&spec.program, &spec.cwd, &spec.stdout_log, &spec.stderr_log] {
        if !path.is_absolute()
            || path
                .components()
                .any(|p| matches!(p, Component::CurDir | Component::ParentDir))
        {
            return Err(ProcessError::new(
                "path",
                "resolved absolute paths without parent/current components are required",
            ));
        }
        reject_secret_path(path)?;
    }
    if spec.stdout_log == spec.stderr_log {
        return Err(ProcessError::new(
            "path",
            "stdout and stderr require distinct new evidence files",
        ));
    }
    // Reject network/device cwd prefixes before any filesystem metadata query.
    #[cfg(windows)]
    native::working_directory_prefix(&spec.cwd)?;
    if !spec.program.is_file() || !spec.cwd.is_dir() {
        return Err(ProcessError::new(
            "path",
            "program file and working directory must exist",
        ));
    }
    for name in spec.env.keys() {
        if name.is_empty() || name.to_string_lossy().contains(['=', '\0']) {
            return Err(ProcessError::new(
                "environment",
                "invalid environment override name",
            ));
        }
    }
    Ok(())
}

fn create_log(path: &Path) -> Result<File, ProcessError> {
    let parent = path
        .parent()
        .ok_or_else(|| ProcessError::new("path", "evidence file has no parent"))?;
    for ancestor in parent.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|e| ProcessError::io("inspect evidence ancestry", e))?;
        let link = metadata.file_type().is_symlink();
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(ProcessError::new(
                    "path",
                    "evidence ancestry contains a reparse point",
                ));
            }
        }
        if link || !metadata.is_dir() {
            return Err(ProcessError::new(
                "path",
                "evidence ancestry contains a link, reparse point or nondirectory",
            ));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Keep ordinary evidence readers compatible while denying independent
        // write/delete/rename handles until this actual capture handle closes.
        options.share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ);
    }
    options
        .open(path)
        .map_err(|e| ProcessError::io("create new evidence log", e))
}

fn reject_secret_path(path: &Path) -> Result<(), ProcessError> {
    for component in path.components() {
        if let Component::Normal(name) = component {
            let name = name.to_string_lossy().to_ascii_lowercase();
            if name == ".env"
                || name.starts_with(".env.")
                || name == ".ssh"
                || name.contains("credential")
                || name.contains("service-account")
                || name.contains("service_account")
                || name.starts_with("id_rsa")
                || name.starts_with("id_ed25519")
                || [".pem", ".key", ".p12", ".pfx"]
                    .iter()
                    .any(|suffix| name.ends_with(suffix))
                || ["api-key", "api_key", "api-keys", "api_keys"].contains(&name.as_str())
            {
                return Err(ProcessError::new(
                    "secret_path",
                    "secret-named paths are not inspected or executed",
                ));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct LeaderExit {
    code: Option<i32>,
    signal: Option<i32>,
}

fn retain_output(
    log: &mut File,
    bytes: &[u8],
    count: &mut u64,
    total: u64,
    cap: u64,
) -> Result<(), ProcessError> {
    let allowed = usize::try_from(cap.saturating_sub(total))
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    log.write_all(&bytes[..allowed])
        .map_err(|e| ProcessError::io("write process evidence", e))?;
    *count += allowed as u64;
    if allowed != bytes.len() {
        return Err(ProcessError::new(
            "output_limit",
            "combined stdout/stderr retention budget exceeded; excess bytes were not retained",
        ));
    }
    Ok(())
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::ffi::OsStr;
    use std::mem::{size_of, size_of_val, zeroed};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::Prefix;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_BROKEN_PIPE, GENERIC_READ, HANDLE, HANDLE_FLAG_INHERIT,
        INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        ReadFile, WriteFile,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
        TerminateJobObject,
    };
    use windows_sys::Win32::System::Pipes::{
        CreatePipe, GetNamedPipeInfo, PIPE_SERVER_END, PeekNamedPipe,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
        DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
        InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
    };

    pub(super) const SCOPE: &str = "windows_job";
    pub(super) const STOP_WRITE_MODE: &str = "exclusive_empty_pipe_capacity";
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    struct Pipe {
        read: Handle,
        eof: bool,
    }
    pub(super) struct Process {
        job: Handle,
        leader: Handle,
        stdout: Pipe,
        stderr: Pipe,
        resources: resource_policy::Tracker,
        minecraft_stdin: Option<Handle>,
        minecraft_stdin_capacity: Option<u32>,
    }
    struct Attributes {
        storage: Vec<usize>,
    }
    impl Attributes {
        fn pointer(&mut self) -> *mut std::ffi::c_void {
            self.storage.as_mut_ptr().cast()
        }
        fn new() -> Result<Self, ProcessError> {
            let mut bytes = 0;
            unsafe {
                InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut bytes);
            }
            if bytes == 0 {
                return Err(last("size native process attributes"));
            }
            let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
            if unsafe {
                InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 2, 0, &mut bytes)
            } == 0
            {
                // A failed initialization must not be passed to Delete.
                return Err(last("initialize native process attributes"));
            }
            Ok(Self { storage })
        }
    }
    impl Drop for Attributes {
        fn drop(&mut self) {
            unsafe {
                DeleteProcThreadAttributeList(self.pointer());
            }
        }
    }

    impl Process {
        pub(super) fn spawn(spec: &ProcessSpec) -> Result<Self, ProcessError> {
            unsafe {
                let job = Handle(CreateJobObjectW(null(), null()));
                if job.0.is_null() {
                    return Err(last("create owned job"));
                }
                let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                    | JOB_OBJECT_LIMIT_JOB_MEMORY
                    | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                limits.BasicLimitInformation.ActiveProcessLimit = resource_policy::PROCESS_LIMIT;
                limits.JobMemoryLimit = resource_policy::MEMORY_LIMIT as usize;
                if SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                ) == 0
                {
                    return Err(last("set finite owned job resource limits"));
                }
                let (readback, _) = job_resource_limits(job.0)?;
                let resources = resource_policy::Tracker::windows(readback)?;
                let (stdout, stdout_write) = pipe()?;
                let (stderr, stderr_write) = pipe()?;
                let attributes = SECURITY_ATTRIBUTES {
                    nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: null_mut(),
                    bInheritHandle: 1,
                };
                let (stdin, minecraft_stdin, minecraft_stdin_capacity) =
                    if spec.minecraft_stop.is_some() {
                        let (read, write, capacity) = minecraft_stop_pipe()?;
                        (read, Some(write), Some(capacity))
                    } else {
                        (
                            Handle(CreateFileW(
                                wide(OsStr::new("NUL")).as_ptr(),
                                GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                &attributes,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,
                                null_mut(),
                            )),
                            None,
                            None,
                        )
                    };
                if stdin.0 == INVALID_HANDLE_VALUE {
                    return Err(last("open null stdin"));
                }
                let mut inherited = [stdin.0, stdout_write.0, stderr_write.0];
                let mut jobs = [job.0];
                let mut attributes = Attributes::new()?;
                if UpdateProcThreadAttribute(
                    attributes.pointer(),
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    inherited.as_mut_ptr().cast(),
                    size_of_val(&inherited),
                    null_mut(),
                    null_mut(),
                ) == 0
                {
                    return Err(last("restrict inherited process handles"));
                }
                // Atomic association prevents an orphan if the supervisor is killed
                // between CreateProcessW and the suspended verification below.
                if UpdateProcThreadAttribute(
                    attributes.pointer(),
                    0,
                    PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                    jobs.as_mut_ptr().cast(),
                    size_of_val(&jobs),
                    null_mut(),
                    null_mut(),
                ) == 0
                {
                    return Err(last("set atomic owned job association"));
                }
                let mut startup: STARTUPINFOEXW = zeroed();
                startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
                startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                startup.StartupInfo.hStdInput = stdin.0;
                startup.StartupInfo.hStdOutput = stdout_write.0;
                startup.StartupInfo.hStdError = stderr_write.0;
                startup.lpAttributeList = attributes.pointer();
                let application = wide(spec.program.as_os_str());
                let directory = current_directory(&spec.cwd)?;
                let mut command = command_line(spec)?;
                let mut environment = environment_block(spec.inherit_environment, &spec.env)?;
                let mut info: PROCESS_INFORMATION = zeroed();
                if CreateProcessW(
                    application.as_ptr(),
                    command.as_mut_ptr(),
                    null(),
                    null(),
                    1,
                    CREATE_SUSPENDED
                        | CREATE_NO_WINDOW
                        | EXTENDED_STARTUPINFO_PRESENT
                        | CREATE_UNICODE_ENVIRONMENT,
                    environment.as_mut_ptr().cast(),
                    directory.as_ptr(),
                    &startup.StartupInfo,
                    &mut info,
                ) == 0
                {
                    return Err(last("create suspended owned command"));
                }
                let leader = Handle(info.hProcess);
                let thread = Handle(info.hThread);
                let mut inside = 0;
                if IsProcessInJob(leader.0, job.0, &mut inside) == 0
                    || (inside == 0 && AssignProcessToJobObject(job.0, leader.0) == 0)
                {
                    let mut error = last("verify suspended owned job association");
                    TerminateProcess(leader.0, 125);
                    error.drained = WaitForSingleObject(leader.0, 15_000) == WAIT_OBJECT_0;
                    return Err(error);
                }
                let process = Self {
                    job,
                    leader,
                    stdout,
                    stderr,
                    resources,
                    minecraft_stdin,
                    minecraft_stdin_capacity,
                };
                let suspend_count = ResumeThread(thread.0);
                if suspend_count != 1 {
                    let mut error = if suspend_count == u32::MAX {
                        last("resume owned command")
                    } else {
                        ProcessError::new(
                            "process_startup",
                            format!("unexpected initial thread suspend count: {suspend_count}"),
                        )
                    };
                    TerminateJobObject(process.job.0, 125);
                    error.drained = WaitForSingleObject(process.leader.0, 15_000) == WAIT_OBJECT_0
                        && process.scope_empty().unwrap_or(false);
                    return Err(error);
                }
                Ok(process)
            }
        }
        pub(super) fn leader_exit(&self) -> Result<Option<LeaderExit>, ProcessError> {
            match unsafe { WaitForSingleObject(self.leader.0, 0) } {
                WAIT_TIMEOUT => Ok(None),
                WAIT_OBJECT_0 => {
                    let mut code = 0;
                    if unsafe { GetExitCodeProcess(self.leader.0, &mut code) } == 0 {
                        return Err(last("read command exit"));
                    }
                    Ok(Some(LeaderExit {
                        code: Some(code as i32),
                        signal: None,
                    }))
                }
                _ => Err(last("observe command handle")),
            }
        }
        pub(super) fn scope_empty(&self) -> Result<bool, ProcessError> {
            let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
            if unsafe {
                QueryInformationJobObject(
                    self.job.0,
                    JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    null_mut(),
                )
            } == 0
            {
                return Err(last("observe owned job drain"));
            }
            Ok(accounting.ActiveProcesses == 0)
        }
        pub(super) fn observe_resources(&mut self) -> Result<(), ProcessError> {
            if !self.resources.due() {
                return Ok(());
            }
            let (readback, peak_committed) = job_resource_limits(self.job.0)?;
            let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
            let mut returned = 0;
            if unsafe {
                QueryInformationJobObject(
                    self.job.0,
                    JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    &mut returned,
                )
            } == 0
            {
                return Err(last("observe owned job resource accounting"));
            }
            if returned != size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32 {
                return Err(ProcessError::new(
                    "resource_observation",
                    "owned job accounting response has an unexpected byte count",
                ));
            }
            self.resources
                .record_windows(readback, accounting.ActiveProcesses, peak_committed)
        }
        pub(super) fn resource_evidence(&self) -> resource_policy::Evidence {
            self.resources.evidence()
        }
        pub(super) fn terminate(&mut self) -> Result<(), ProcessError> {
            if unsafe { TerminateJobObject(self.job.0, 124) } == 0 {
                Err(last("terminate owned job"))
            } else {
                Ok(())
            }
        }
        pub(super) fn minecraft_stop_capacity(&self) -> Option<u32> {
            self.minecraft_stdin_capacity
        }
        pub(super) fn write_minecraft_stop(&mut self, offset: usize) -> MinecraftStopWrite {
            let Some(bytes) = MINECRAFT_STOP_BYTES
                .get(offset..)
                .filter(|bytes| !bytes.is_empty())
            else {
                return MinecraftStopWrite::result(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "fixed stop offset is outside its payload",
                )));
            };
            let Some(writer) = self.minecraft_stdin.as_ref() else {
                return MinecraftStopWrite::result(Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "original stop writer is unavailable",
                )));
            };
            // 독점 writer의 전체 수명 동안 총 5 bytes만 쓴다. 실제 확인한 empty pipe capacity 안이다.
            // WriteFile 자체는 cooperative OS 호출이며 kernel 안에서 선점 취소를 보장하지 않는다.
            let mut written = 0;
            if unsafe {
                WriteFile(
                    writer.0,
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    &mut written,
                    null_mut(),
                )
            } == 0
            {
                return MinecraftStopWrite {
                    bytes: written as usize,
                    error: Some(std::io::Error::last_os_error()),
                };
            }
            MinecraftStopWrite {
                bytes: written as usize,
                error: None,
            }
        }
        pub(super) fn close_minecraft_stop(&mut self) -> std::io::Result<bool> {
            let Some(writer) = self.minecraft_stdin.as_ref() else {
                return Ok(false);
            };
            if unsafe { CloseHandle(writer.0) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            // 성공한 handle만 제거한다. 실패한 handle은 Drop의 best-effort close 대상으로 남는다.
            if let Some(writer) = self.minecraft_stdin.take() {
                std::mem::forget(writer);
            }
            Ok(true)
        }
        pub(super) fn reap(&mut self) -> Result<(), ProcessError> {
            if unsafe { WaitForSingleObject(self.leader.0, 0) } == WAIT_OBJECT_0 {
                Ok(())
            } else {
                Err(last("verify command termination"))
            }
        }
        pub(super) fn capture(
            &mut self,
            stdout: &mut File,
            stderr: &mut File,
            stdout_count: &mut u64,
            stderr_count: &mut u64,
            cap: u64,
        ) -> Result<(), ProcessError> {
            self.stdout
                .capture(stdout, stdout_count, *stderr_count, cap)?;
            self.stderr
                .capture(stderr, stderr_count, *stdout_count, cap)
        }
        pub(super) fn outputs_closed(&self) -> bool {
            self.stdout.eof && self.stderr.eof
        }
    }
    fn job_resource_limits(
        job: HANDLE,
    ) -> Result<(resource_policy::JobReadback, u64), ProcessError> {
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        let mut returned = 0;
        let expected = size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
        if unsafe {
            QueryInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                expected,
                &mut returned,
            )
        } == 0
        {
            return Err(last("read owned job resource limits"));
        }
        Ok((
            resource_policy::JobReadback {
                flags: limits.BasicLimitInformation.LimitFlags,
                committed_bytes: limits.JobMemoryLimit as u64,
                active_limit: limits.BasicLimitInformation.ActiveProcessLimit,
                returned_bytes: returned,
                expected_bytes: expected,
            },
            limits.PeakJobMemoryUsed as u64,
        ))
    }
    impl Pipe {
        fn capture(
            &mut self,
            log: &mut File,
            count: &mut u64,
            other: u64,
            cap: u64,
        ) -> Result<(), ProcessError> {
            if self.eof {
                return Ok(());
            }
            let mut processed = 0;
            loop {
                let mut available = 0;
                if unsafe {
                    PeekNamedPipe(
                        self.read.0,
                        null_mut(),
                        0,
                        null_mut(),
                        &mut available,
                        null_mut(),
                    )
                } == 0
                {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                        self.eof = true;
                        return Ok(());
                    }
                    return Err(ProcessError::io("observe output pipe", error));
                }
                if available == 0 || processed >= READ_BATCH_BYTES {
                    return Ok(());
                }
                let mut bytes = [0u8; 8192];
                let mut read = 0;
                if unsafe {
                    ReadFile(
                        self.read.0,
                        bytes.as_mut_ptr(),
                        available.min(bytes.len() as u32),
                        &mut read,
                        null_mut(),
                    )
                } == 0
                {
                    return Err(last("read output pipe"));
                }
                if read == 0 {
                    return Ok(());
                }
                retain_output(log, &bytes[..read as usize], count, *count + other, cap)?;
                processed += read as usize;
            }
        }
    }
    fn pipe() -> Result<(Pipe, Handle), ProcessError> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let mut read = null_mut();
        let mut write = null_mut();
        if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
            return Err(last("create bounded output pipe"));
        }
        let read = Handle(read);
        let write = Handle(write);
        if unsafe { SetHandleInformation(read.0, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(last("protect supervisor pipe handle"));
        }
        Ok((Pipe { read, eof: false }, write))
    }
    fn minecraft_stop_pipe() -> Result<(Handle, Handle, u32), ProcessError> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let mut read = null_mut();
        let mut write = null_mut();
        if unsafe { CreatePipe(&mut read, &mut write, &attributes, 4096) } == 0 {
            return Err(last("create fixed stop stdin pipe"));
        }
        let read = Handle(read);
        let write = Handle(write);
        if unsafe { SetHandleInformation(write.0, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(last("protect original stop writer"));
        }
        let mut flags = 0;
        let mut outbound = 0;
        let mut inbound = 0;
        if unsafe { GetNamedPipeInfo(write.0, &mut flags, &mut outbound, &mut inbound, null_mut()) }
            == 0
        {
            return Err(last("read actual fixed stop pipe capacity"));
        }
        let capacity = if flags & PIPE_SERVER_END != 0 {
            outbound
        } else {
            inbound
        };
        if capacity < MINECRAFT_STOP_BYTES.len() as u32 {
            return Err(ProcessError::new(
                "minecraft_stop_capacity",
                "actual private stdin capacity cannot hold the fixed stop payload",
            ));
        }
        Ok((read, write, capacity))
    }
    fn last(context: &str) -> ProcessError {
        ProcessError::io(context, std::io::Error::last_os_error())
    }
    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }
    pub(super) fn working_directory_prefix(path: &Path) -> Result<(), ProcessError> {
        match path.components().next() {
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) =>
            {
                Ok(())
            }
            _ => Err(ProcessError::new(
                "path_transport",
                "network, device and non-drive working-directory transports are unsupported",
            )),
        }
    }
    /// Win32 process startup needs a DOS cwd transport even when managed path
    /// identity is represented with a verified VerbatimDisk prefix. Keep that
    /// authoritative identity unchanged and prove both paths resolve identically.
    pub(super) fn current_directory(path: &Path) -> Result<Vec<u16>, ProcessError> {
        working_directory_prefix(path)?;
        let prefix = path
            .components()
            .next()
            .and_then(|component| match component {
                Component::Prefix(prefix) => Some(prefix.kind()),
                _ => None,
            })
            .ok_or_else(|| {
                ProcessError::new(
                    "path_transport",
                    "Windows working directory requires a local drive prefix",
                )
            })?;
        let transport = match prefix {
            Prefix::Disk(_) => path.to_path_buf(),
            Prefix::VerbatimDisk(_) => {
                let units: Vec<u16> = path.as_os_str().encode_wide().collect();
                let expected = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
                if !units.starts_with(&expected) {
                    return Err(ProcessError::new(
                        "path_transport",
                        "unsupported verbatim working-directory representation",
                    ));
                }
                PathBuf::from(OsString::from_wide(&units[expected.len()..]))
            }
            _ => {
                return Err(ProcessError::new(
                    "path_transport",
                    "network and device working-directory transports are unsupported",
                ));
            }
        };
        let directory = wide(transport.as_os_str());
        // SetCurrentDirectory retains a trailing separator. Reserve its space
        // as well as the NUL rather than accept a transport at the native edge.
        let needs_separator = !matches!(directory.get(directory.len().saturating_sub(2)),
            Some(unit) if *unit == b'\\' as u16 || *unit == b'/' as u16);
        if directory.len().saturating_add(usize::from(needs_separator)) > 260 {
            return Err(ProcessError::new(
                "path_transport",
                "working directory exceeds the supported DOS transport length",
            ));
        }
        let original = fs::canonicalize(path)
            .map_err(|e| ProcessError::io("resolve authoritative working directory", e))?;
        let resolved = fs::canonicalize(&transport)
            .map_err(|e| ProcessError::io("resolve working-directory transport", e))?;
        if !matches!(original.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::VerbatimDisk(_)))
        {
            return Err(ProcessError::new(
                "path_transport",
                "resolved working directory is not a local disk path",
            ));
        }
        if original != resolved {
            return Err(ProcessError::new(
                "path_transport",
                "DOS working-directory transport changes the authoritative physical path",
            ));
        }
        Ok(directory)
    }
    fn command_line(spec: &ProcessSpec) -> Result<Vec<u16>, ProcessError> {
        let mut command = Vec::new();
        for arg in std::iter::once(spec.program.as_os_str())
            .chain(spec.args.iter().map(OsString::as_os_str))
        {
            if !command.is_empty() {
                command.push(b' ' as u16);
            }
            command.push(b'"' as u16);
            let mut slashes = 0;
            for unit in arg.encode_wide() {
                if unit == 0 {
                    return Err(ProcessError::new("argument", "NUL in command argument"));
                }
                if unit == b'\\' as u16 {
                    slashes += 1;
                    continue;
                }
                command.extend(std::iter::repeat_n(
                    b'\\' as u16,
                    if unit == b'"' as u16 {
                        slashes * 2 + 1
                    } else {
                        slashes
                    },
                ));
                slashes = 0;
                command.push(unit);
            }
            command.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
            command.push(b'"' as u16);
        }
        command.push(0);
        if command.len() > 32767 {
            return Err(ProcessError::new(
                "argument",
                "Windows command line exceeds native bound",
            ));
        }
        Ok(command)
    }
    fn environment_block(
        inherit: bool,
        overrides: &BTreeMap<OsString, OsString>,
    ) -> Result<Vec<u16>, ProcessError> {
        // Inheritance is used for executable/toolchain discovery. Values are
        // passed to the child only; they are never logged or put into receipts.
        let mut entries = BTreeMap::new();
        if inherit {
            for (name, value) in std::env::vars_os() {
                entries.insert(name.to_string_lossy().to_uppercase(), (name, value));
            }
        }
        for (name, value) in overrides.iter().map(|(k, v)| (k.clone(), v.clone())) {
            entries.insert(name.to_string_lossy().to_uppercase(), (name, value));
        }
        let mut block = Vec::new();
        for (_, (name, value)) in entries {
            let entry: Vec<u16> = name
                .encode_wide()
                .chain(Some(b'=' as u16))
                .chain(value.encode_wide())
                .collect();
            if entry.contains(&0) {
                return Err(ProcessError::new(
                    "environment",
                    "NUL in process environment override",
                ));
            }
            block.extend(entry);
            block.push(0);
        }
        block.push(0);
        if block.len() == 1 {
            block.push(0);
        }
        Ok(block)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native {
    use super::*;
    use std::io::Read;
    use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    #[cfg(target_os = "linux")]
    pub(super) const SCOPE: &str = "linux_process_group";
    #[cfg(target_os = "macos")]
    pub(super) const SCOPE: &str = "macos_process_group_libproc";
    pub(super) const STOP_WRITE_MODE: &str = "nonblocking";
    struct Pipe {
        file: File,
        eof: bool,
    }
    pub(super) struct Process {
        child: Child,
        pid: libc::pid_t,
        stdout: Pipe,
        stderr: Pipe,
        minecraft_stdin: Option<File>,
        reaped: bool,
        reservation_valid: bool,
        #[cfg(target_os = "macos")]
        mac_leader_identity: Option<darwin_resources::LeaderIdentity>,
        #[cfg(target_os = "macos")]
        resources: darwin_resources::Tracker,
        #[cfg(target_os = "linux")]
        resources: resource_policy::Tracker,
        #[cfg(target_os = "linux")]
        linux_group: Option<linux_resources::OwnedGroup>,
    }
    impl Process {
        pub(super) fn spawn(spec: &ProcessSpec) -> Result<Self, ProcessError> {
            #[cfg(target_os = "macos")]
            let mut resources = {
                let pid = unsafe { libc::getpid() };
                let before = mac_bsd_info(pid, false)?;
                let memory =
                    darwin_resources::memory(pid).map_err(darwin_resources::native_error)?;
                let after = mac_bsd_info(pid, false)?;
                verify_memory_identity(before.as_ref(), after.as_ref(), pid)?;
                darwin_resources::Tracker::new(memory)?
            };
            let mut command = Command::new(&spec.program);
            if !spec.inherit_environment {
                command.env_clear();
            }
            #[cfg(target_os = "linux")]
            let linux_address_limit: libc::rlim_t =
                spec.resource_policy.linux_address_space_limit()?;
            command
                .args(&spec.args)
                .current_dir(&spec.cwd)
                .envs(&spec.env)
                .stdin(if spec.minecraft_stop.is_some() {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            // Only async-signal-safe libc calls occur between fork and exec.
            unsafe {
                command.pre_exec(move || {
                    if libc::setsid() == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    #[cfg(target_os = "linux")]
                    {
                        let limits = libc::rlimit {
                            rlim_cur: linux_address_limit,
                            rlim_max: linux_address_limit,
                        };
                        if libc::setrlimit(libc::RLIMIT_AS, &limits) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        let mut readback = libc::rlimit {
                            rlim_cur: 0,
                            rlim_max: 0,
                        };
                        if libc::getrlimit(libc::RLIMIT_AS, &mut readback) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if readback.rlim_cur != limits.rlim_cur
                            || readback.rlim_max != limits.rlim_max
                        {
                            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
                        }
                    }
                    #[cfg(target_os = "macos")]
                    {
                        let pid = libc::getpid();
                        if libc::getsid(0) != pid || libc::getpgrp() != pid {
                            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
                        }
                        darwin_resources::configure_before_exec()?;
                    }
                    Ok(())
                });
            }
            let mut child = command
                .spawn()
                .map_err(|e| ProcessError::io("spawn owned session", e))?;
            let pid = child.id() as libc::pid_t;
            #[cfg(target_os = "macos")]
            resources.configured();
            #[cfg(target_os = "linux")]
            let resources = resource_policy::Tracker::linux_for_policy(spec.resource_policy)?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| ProcessError::new("pipe", "missing stdout pipe"))?;
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| ProcessError::new("pipe", "missing stderr pipe"))?;
            let stdout: OwnedFd = stdout.into();
            let stderr: OwnedFd = stderr.into();
            let minecraft_stdin = child.stdin.take().map(|writer| {
                let writer: OwnedFd = writer.into();
                File::from(writer)
            });
            let mut process = Self {
                child,
                pid,
                stdout: Pipe {
                    file: stdout.into(),
                    eof: false,
                },
                stderr: Pipe {
                    file: stderr.into(),
                    eof: false,
                },
                minecraft_stdin,
                reaped: false,
                reservation_valid: !cfg!(target_os = "linux"),
                #[cfg(target_os = "macos")]
                mac_leader_identity: None,
                #[cfg(target_os = "macos")]
                resources,
                #[cfg(target_os = "linux")]
                resources,
                #[cfg(target_os = "linux")]
                linux_group: None,
            };
            #[cfg(target_os = "linux")]
            {
                match linux_resources::OwnedGroup::capture(pid) {
                    Ok(group) => {
                        process.linux_group = Some(group);
                        process.reservation_valid = true;
                    }
                    Err(mut error) => {
                        // Initial native identity was never established. Do
                        // not signal a numeric group based only on Child, or
                        // invent drain/release its storage lease after failure.
                        error.drained = false;
                        return Err(error);
                    }
                }
            }
            for fd in [
                process.stdout.file.as_raw_fd(),
                process.stderr.file.as_raw_fd(),
            ]
            .into_iter()
            .chain(process.minecraft_stdin.as_ref().map(AsRawFd::as_raw_fd))
            {
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                if flags < 0
                    || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
                {
                    let mut error = ProcessError::io(
                        if process
                            .minecraft_stdin
                            .as_ref()
                            .is_some_and(|writer| writer.as_raw_fd() == fd)
                        {
                            "make fixed stop stdin nonblocking"
                        } else {
                            "make bounded output nonblocking"
                        },
                        std::io::Error::last_os_error(),
                    );
                    let _ = process.terminate();
                    error.drained = false;
                    return Err(error);
                }
            }
            if let Some(writer) = &process.minecraft_stdin {
                let fd = writer.as_raw_fd();
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                if flags < 0
                    || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
                {
                    let mut error = ProcessError::io(
                        "protect original stop writer",
                        std::io::Error::last_os_error(),
                    );
                    let _ = process.terminate();
                    error.drained = false;
                    return Err(error);
                }
            }
            #[cfg(target_os = "macos")]
            {
                let identity = mac_bsd_info(pid, true).and_then(|value| {
                    value.ok_or_else(|| {
                        ProcessError::new("process_identity", "new reserved macOS leader missing")
                    })
                });
                match identity {
                    Ok(info) if info.pid == pid as u32 && info.pgid == pid as u32 => {
                        process.mac_leader_identity = Some(info.observation().identity);
                    }
                    Ok(_) => {
                        process.reservation_valid = false;
                        let mut error = ProcessError::new(
                            "process_identity",
                            "new macOS leader has inconsistent process-group identity",
                        );
                        error.drained = false;
                        return Err(error);
                    }
                    Err(mut error) => {
                        error.drained = false;
                        return Err(error);
                    }
                }
            }
            Ok(process)
        }
        pub(super) fn leader_exit(&mut self) -> Result<Option<LeaderExit>, ProcessError> {
            // WNOWAIT preserves the leader identity, so its process group ID
            // cannot be recycled before the final owned-group observation.
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
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ECHILD) {
                    self.reservation_valid = false;
                }
                return Err(ProcessError::io("observe unreaped command leader", error));
            }
            #[cfg(target_os = "linux")]
            let pid = unsafe { info.si_pid() };
            #[cfg(target_os = "macos")]
            let pid = info.si_pid;
            if pid == 0 {
                return Ok(None);
            }
            #[cfg(target_os = "linux")]
            let status = unsafe { info.si_status() };
            #[cfg(target_os = "macos")]
            let status = info.si_status;
            if info.si_code == libc::CLD_EXITED {
                Ok(Some(LeaderExit {
                    code: Some(status),
                    signal: None,
                }))
            } else {
                Ok(Some(LeaderExit {
                    code: None,
                    signal: Some(status),
                }))
            }
        }
        pub(super) fn scope_empty(
            &mut self,
            #[cfg(target_os = "linux")] control: &mut linux_resources::ObservationControl<'_>,
        ) -> Result<bool, ProcessError> {
            #[cfg(target_os = "linux")]
            {
                self.linux_sample(false, control)
                    .map(|observation| observation.scope_empty())
                    .map_err(|error| self.resources.with_linux_pending_diagnostics(error))
            }
            #[cfg(target_os = "macos")]
            {
                self.mac_group_observation(None)
                    .map(|observation| observation.scope_empty())
                    .map_err(|error| self.resources.with_pending_diagnostics(error))
            }
        }
        #[cfg(target_os = "macos")]
        fn mac_group_observation(
            &mut self,
            resources: Option<&mut darwin_resources::Sample>,
        ) -> Result<darwin_resources::GroupObservation, ProcessError> {
            if self.reaped || !self.reservation_valid {
                return Err(ProcessError::new(
                    "process_identity",
                    "reserved macOS leader is no longer held",
                ));
            }
            let Some(identity) = self.mac_leader_identity else {
                self.reservation_valid = false;
                return Err(ProcessError::new(
                    "process_identity",
                    "missing reserved macOS leader identity",
                ));
            };
            let mut memory_exits = None;
            let mut pending = darwin_resources::PendingObservations::default();
            let allow_missing = self.resources.missing_allowed();
            let result = live_group_members(
                self.pid,
                identity,
                &mut self.reservation_valid,
                resources,
                MacGroupDiagnostics {
                    memory_exits: &mut memory_exits,
                    pending: &mut pending,
                    missing: &mut self.resources.missing,
                },
                allow_missing,
            );
            // Retain native exit facts even if a later member/identity check
            // fails before this partial group sample can be completed.
            self.resources.record_memory_exits(memory_exits);
            if result.is_err() {
                self.resources.record_pending_observations(pending);
            }
            result
        }
        #[cfg(target_os = "macos")]
        pub(super) fn observe_resources(
            &mut self,
        ) -> Result<darwin_resources::ResourceObservation, ProcessError> {
            let result = (|| {
                if self.resources.begin()?.is_none() {
                    return Ok(darwin_resources::ResourceObservation::NotDue);
                }
                let mut sample = darwin_resources::Sample::default();
                let observation = self.mac_group_observation(Some(&mut sample))?;
                self.resources.finish_observation(observation, sample)
            })();
            result.map_err(|error| self.resources.with_pending_diagnostics(error))
        }
        #[cfg(target_os = "macos")]
        pub(super) fn resource_evidence(&self) -> darwin_resources::Evidence {
            self.resources.evidence.clone()
        }
        #[cfg(target_os = "linux")]
        pub(super) fn observe_resources(
            &mut self,
            control: &mut linux_resources::ObservationControl<'_>,
        ) -> Result<(), ProcessError> {
            let result = (|| {
                if !self.resources.begin_linux_sample()? {
                    return Ok(());
                }
                let include_rss = self.resources.requires_linux_rss();
                let observation = self.linux_sample(include_rss, control)?;
                self.resources.finish_linux_sample(observation)
            })();
            result.map_err(|error| self.resources.with_linux_pending_diagnostics(error))
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        pub(super) fn resource_observation_pending(&self) -> bool {
            #[cfg(target_os = "linux")]
            {
                self.resources.linux_pending()
            }
            #[cfg(target_os = "macos")]
            {
                self.resources.pending()
            }
        }
        #[cfg(target_os = "linux")]
        fn linux_sample(
            &mut self,
            include_rss: bool,
            control: &mut linux_resources::ObservationControl<'_>,
        ) -> Result<linux_resources::GroupObservation, ProcessError> {
            let group = self.linux_group.as_mut().ok_or_else(|| {
                ProcessError::new("process_identity", "missing anchored Linux group identity")
            })?;
            let mut pending = linux_resources::PendingObservations::default();
            let result = group.sample(
                include_rss,
                self.reservation_valid && !self.reaped,
                &mut pending,
                control,
            );
            if !group.reservation_valid() {
                self.reservation_valid = false;
            }
            // Merge once on both success and failure, before propagating a
            // later enumeration/member/identity or partial-budget error.
            self.resources.record_linux_pending_observations(pending);
            result
        }
        #[cfg(target_os = "linux")]
        pub(super) fn lifetime_evidence(&self) -> linux_resources::LifetimeEvidence {
            self.linux_group
                .as_ref()
                .map(|group| group.lifetime_evidence())
                .unwrap_or_default()
        }
        #[cfg(target_os = "linux")]
        pub(super) fn close_linux_observation(
            &mut self,
            control: &mut linux_resources::ObservationControl<'_>,
        ) -> (linux_resources::LifetimeEvidence, Result<(), ProcessError>) {
            let Some(group) = self.linux_group.take() else {
                return (
                    linux_resources::LifetimeEvidence::default(),
                    Err(ProcessError::new(
                        "process_identity",
                        "Linux observer was already closed",
                    )),
                );
            };
            // Once anchors are consumed, Drop cannot authorize another group
            // signal. Reap/drain facts were established independently above.
            self.reservation_valid = false;
            group.close(control)
        }
        #[cfg(target_os = "linux")]
        pub(super) fn resource_evidence(&self) -> resource_policy::Evidence {
            self.resources.evidence()
        }
        pub(super) fn terminate(&mut self) -> Result<(), ProcessError> {
            #[cfg(target_os = "macos")]
            if self.mac_leader_identity.is_none() {
                self.reservation_valid = false;
            }
            if self.reaped || !self.reservation_valid {
                return Err(ProcessError::new(
                    "identity",
                    "refusing to signal a process group whose leader reservation was lost",
                ));
            }
            if unsafe { libc::kill(-self.pid, libc::SIGKILL) } == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(ProcessError::io("terminate owned process group", error));
                }
            }
            Ok(())
        }
        pub(super) fn minecraft_stop_capacity(&self) -> Option<u32> {
            None
        }
        pub(super) fn write_minecraft_stop(&mut self, offset: usize) -> MinecraftStopWrite {
            let Some(bytes) = MINECRAFT_STOP_BYTES
                .get(offset..)
                .filter(|bytes| !bytes.is_empty())
            else {
                return MinecraftStopWrite::result(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "fixed stop offset is outside its payload",
                )));
            };
            let Some(writer) = self.minecraft_stdin.as_mut() else {
                return MinecraftStopWrite::result(Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "original stop writer is unavailable",
                )));
            };
            MinecraftStopWrite::result(writer.write(bytes))
        }
        pub(super) fn close_minecraft_stop(&mut self) -> std::io::Result<bool> {
            let Some(writer) = self.minecraft_stdin.take() else {
                return Ok(false);
            };
            let fd = writer.into_raw_fd();
            if unsafe { libc::close(fd) } == -1 {
                // EINTR도 재시도하지 않는다. close의 불확실성을 보존하며 재사용된 fd를 닫지 않는다.
                return Err(std::io::Error::last_os_error());
            }
            Ok(true)
        }
        pub(super) fn reap(&mut self) -> Result<(), ProcessError> {
            if let Err(error) = self.child.wait() {
                // Never signal again after a failed reap: an external reaper
                // may already have released the leader/process-group identity.
                self.reservation_valid = false;
                return Err(ProcessError::io("reap owned command", error));
            }
            self.reaped = true;
            Ok(())
        }
        pub(super) fn capture(
            &mut self,
            stdout: &mut File,
            stderr: &mut File,
            stdout_count: &mut u64,
            stderr_count: &mut u64,
            cap: u64,
        ) -> Result<(), ProcessError> {
            self.stdout
                .capture(stdout, stdout_count, *stderr_count, cap)?;
            self.stderr
                .capture(stderr, stderr_count, *stdout_count, cap)
        }
        pub(super) fn outputs_closed(&self) -> bool {
            self.stdout.eof && self.stderr.eof
        }
    }
    impl Drop for Process {
        fn drop(&mut self) {
            // A panic/error never grants storage cleanup. Best-effort termination
            // is limited to the still-reserved group; no unrelated PID is used.
            if !self.reaped {
                let _ = self.terminate();
            }
        }
    }
    impl Pipe {
        fn capture(
            &mut self,
            log: &mut File,
            count: &mut u64,
            other: u64,
            cap: u64,
        ) -> Result<(), ProcessError> {
            if self.eof {
                return Ok(());
            }
            let mut processed = 0;
            #[cfg(target_os = "macos")]
            let mut interrupted = 0;
            loop {
                let mut bytes = [0u8; 8192];
                match self.file.read(&mut bytes) {
                    Ok(0) => {
                        self.eof = true;
                        return Ok(());
                    }
                    Ok(read) => {
                        retain_output(log, &bytes[..read], count, *count + other, cap)?;
                        processed += read;
                        if processed >= READ_BATCH_BYTES {
                            return Ok(());
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                        #[cfg(target_os = "macos")]
                        {
                            interrupted += 1;
                            if interrupted >= 32 {
                                // Return to the actual resource observer even
                                // under a bounded burst of interrupted reads.
                                return Ok(());
                            }
                        }
                        continue;
                    }
                    Err(error) => return Err(ProcessError::io("read process output", error)),
                }
            }
        }
    }
    // ABI and constants are from Apple's public libproc/proc_info headers.
    // PROC_ALL_PIDS = 1; PROC_PIDTBSDINFO = 3; SZOMB = 5.
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
    impl BsdInfo {
        fn observation(&self) -> darwin_resources::LeaderBsd {
            darwin_resources::LeaderBsd {
                identity: darwin_resources::LeaderIdentity {
                    pid: self.pid,
                    uid: self.uid,
                    pgid: self.pgid,
                    start_sec: self.start_sec,
                    start_usec: self.start_usec,
                },
                status: self.status,
                flags: self.flags,
            }
        }
    }
    #[cfg(target_os = "macos")]
    fn mac_bsd_info(pid: i32, include_zombie: bool) -> Result<Option<BsdInfo>, ProcessError> {
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
                u64::from(include_zombie),
                (&mut info as *mut BsdInfo).cast(),
                std::mem::size_of::<BsdInfo>() as i32,
            )
        };
        if bytes == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(None);
            }
            return Err(ProcessError::io("observe macOS process identity", error));
        }
        if bytes as usize != std::mem::size_of::<BsdInfo>() {
            return Err(ProcessError::new(
                "process_metadata",
                "macOS BSD identity has unexpected byte length",
            ));
        }
        Ok(Some(info))
    }
    #[cfg(target_os = "macos")]
    struct MacGroupDiagnostics<'a> {
        memory_exits: &'a mut Option<darwin_resources::ExitObservationEvidence>,
        pending: &'a mut darwin_resources::PendingObservations,
        missing: &'a mut darwin_resources::MissingMembers,
    }
    #[cfg(target_os = "macos")]
    fn live_group_members(
        group: libc::pid_t,
        leader_identity: darwin_resources::LeaderIdentity,
        reservation_valid: &mut bool,
        mut resources: Option<&mut darwin_resources::Sample>,
        diagnostics: MacGroupDiagnostics<'_>,
        allow_missing: bool,
    ) -> Result<darwin_resources::GroupObservation, ProcessError> {
        let MacGroupDiagnostics {
            memory_exits,
            pending,
            missing,
        } = diagnostics;
        #[link(name = "proc")]
        unsafe extern "C" {
            fn proc_listpids(
                kind: u32,
                typeinfo: u32,
                buffer: *mut std::ffi::c_void,
                bytes: i32,
            ) -> i32;
        }
        let mut capacity = 1024usize;
        let mut pids = loop {
            let mut pids = vec![0i32; capacity];
            let bytes =
                unsafe { proc_listpids(1, 0, pids.as_mut_ptr().cast(), (capacity * 4) as i32) };
            // Apple libproc returns zero on syscall error, not -1. A native
            // snapshot containing our reserved leader cannot legitimately be empty.
            if bytes <= 0 {
                return Err(ProcessError::io(
                    "observe macOS process snapshot",
                    std::io::Error::last_os_error(),
                ));
            }
            if bytes as usize >= capacity * 4 {
                if capacity >= 100_000 {
                    return Err(ProcessError::new(
                        "process_limit",
                        "macOS process group exceeds observation bound",
                    ));
                }
                capacity = (capacity * 2).min(100_000);
                continue;
            }
            if bytes % 4 != 0 {
                return Err(ProcessError::new(
                    "process_metadata",
                    "macOS PID list has invalid byte length",
                ));
            }
            pids.truncate(bytes as usize / 4);
            break pids;
        };
        // Reuse the existing leader branch after all member candidates. This
        // changes scan order, not the native queries of a complete scan.
        pids.sort_by_key(|pid| *pid == group);
        let resource_scan = resources.is_some();
        if resource_scan {
            missing.begin_scan();
        }
        let mut members = 0;
        let mut leader_seen = false;
        let result = (|| {
            for pid in pids.into_iter().filter(|p| *p > 0) {
                if pid == group {
                    // Darwin getsid cannot find a zombie. proc_pidinfo arg=1
                    // explicitly includes it; WNOWAIT still reserves its identity.
                    let before = mac_bsd_info(pid, true)
                        .map_err(|error| {
                            darwin_resources::LeaderDiagnostic::observe(
                                leader_identity,
                                None,
                                None,
                                darwin_resources::LeaderPhase::GroupIdentity,
                                darwin_resources::LeaderSession::NotObserved,
                            )
                            .attach(error)
                        })?
                        .ok_or_else(|| {
                            darwin_resources::LeaderDiagnostic::observe(
                                leader_identity,
                                None,
                                None,
                                darwin_resources::LeaderPhase::GroupIdentity,
                                darwin_resources::LeaderSession::NotObserved,
                            )
                            .attach(ProcessError::new(
                                "process_identity",
                                "reserved macOS leader missing",
                            ))
                        })?;
                    darwin_resources::verify_reserved_identity(
                        leader_identity,
                        Some(before.observation()),
                        Some(before.observation()),
                        darwin_resources::LeaderPhase::GroupIdentity,
                        reservation_valid,
                    )?;
                    let mut leader_pending = false;
                    let memory = if resources.is_some() && before.status != darwin_resources::SZOMB
                    {
                        match live_leader_session_or_confirmed_zombie(
                            pid,
                            leader_identity,
                            &before,
                            darwin_resources::LeaderPhase::BeforeMemory,
                            reservation_valid,
                        )? {
                            darwin_resources::LeaderObservation::Live => {
                                match memory_or_confirmed_zombie(
                                    pid,
                                    &before,
                                    Some((leader_identity, &mut *reservation_valid)),
                                )? {
                                    darwin_resources::MemoryObservation::Measured(memory) => {
                                        Some(memory)
                                    }
                                    darwin_resources::MemoryObservation::Zombie(diagnostic) => {
                                        darwin_resources::ExitObservationEvidence::record(
                                            memory_exits,
                                            diagnostic,
                                        );
                                        None
                                    }
                                    darwin_resources::MemoryObservation::Pending(diagnostic) => {
                                        darwin_resources::ExitObservationEvidence::record(
                                            memory_exits,
                                            diagnostic,
                                        );
                                        pending.record(diagnostic);
                                        leader_pending = true;
                                        None
                                    }
                                    darwin_resources::MemoryObservation::MissingAfterTaskExit(
                                        diagnostic,
                                    ) => {
                                        return Err(diagnostic.attach(ProcessError::new(
                                            "process_identity",
                                            "reserved leader cannot use missing-member admission",
                                        )));
                                    }
                                }
                            }
                            darwin_resources::LeaderObservation::Zombie => None,
                            darwin_resources::LeaderObservation::Pending(diagnostic) => {
                                pending.record(diagnostic);
                                leader_pending = true;
                                None
                            }
                        }
                    } else {
                        None
                    };
                    let after = mac_bsd_info(pid, true)
                        .map_err(|error| {
                            darwin_resources::LeaderDiagnostic::observe(
                                leader_identity,
                                Some(before.observation()),
                                None,
                                darwin_resources::LeaderPhase::GroupIdentity,
                                darwin_resources::LeaderSession::NotObserved,
                            )
                            .attach(error)
                        })?
                        .ok_or_else(|| {
                            darwin_resources::LeaderDiagnostic::observe(
                                leader_identity,
                                Some(before.observation()),
                                None,
                                darwin_resources::LeaderPhase::GroupIdentity,
                                darwin_resources::LeaderSession::NotObserved,
                            )
                            .attach(ProcessError::new(
                                "process_identity",
                                "reserved macOS leader disappeared",
                            ))
                        })?;
                    darwin_resources::verify_reserved_identity(
                        leader_identity,
                        Some(before.observation()),
                        Some(after.observation()),
                        darwin_resources::LeaderPhase::GroupIdentity,
                        reservation_valid,
                    )?;
                    leader_seen = true;
                    if after.status != darwin_resources::SZOMB {
                        if let Some(sample) = resources.as_deref_mut() {
                            // An earlier member's incomplete observation must
                            // not hide this leader's measured lower bound.
                            if leader_pending {
                                continue;
                            }
                            if let Some(memory) = memory {
                                verify_memory_identity(Some(&before), Some(&after), pid)?;
                                match live_leader_session_or_confirmed_zombie(
                                    pid,
                                    leader_identity,
                                    &after,
                                    darwin_resources::LeaderPhase::AfterMemory,
                                    reservation_valid,
                                )? {
                                    darwin_resources::LeaderObservation::Live => {
                                        members += 1;
                                        sample.push(memory)?;
                                    }
                                    darwin_resources::LeaderObservation::Zombie => (),
                                    darwin_resources::LeaderObservation::Pending(diagnostic) => {
                                        pending.record(diagnostic);
                                        // The earlier full memory observation
                                        // remains a lower bound. Pending's
                                        // identity counts this worker once.
                                        sample.push_memory_lower_bound(memory)?;
                                    }
                                }
                            } else {
                                return Err(ProcessError::new(
                                    "resource_observation",
                                    "live macOS leader has no verified resource sample",
                                ));
                            }
                        } else {
                            members += 1;
                        }
                    }
                    continue;
                }
                let session = unsafe { libc::getsid(pid) };
                let latched = missing.contains_pid(pid as u32);
                if session == -1 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::ESRCH) {
                        if resource_scan && latched {
                            missing.unavailable(pid as u32);
                        }
                        continue;
                    }
                    return Err(ProcessError::io("observe macOS process session", error));
                }
                if session != group {
                    if latched {
                        return Err(ProcessError::new(
                            "scope_escape",
                            "latched Darwin member changed session",
                        ));
                    }
                    continue;
                }
                let Some(before) = mac_bsd_info(pid, false)? else {
                    if resource_scan && latched {
                        missing.unavailable(pid as u32);
                    }
                    continue;
                };
                if latched {
                    missing.verify(pid as u32, before.observation())?;
                }
                let memory = if resources.is_some() && before.status != 5 {
                    match memory_or_confirmed_zombie(pid, &before, None)? {
                        darwin_resources::MemoryObservation::Measured(memory) => Some(memory),
                        darwin_resources::MemoryObservation::Zombie(diagnostic) => {
                            darwin_resources::ExitObservationEvidence::record(
                                memory_exits,
                                diagnostic,
                            );
                            None
                        }
                        darwin_resources::MemoryObservation::Pending(diagnostic) => {
                            darwin_resources::ExitObservationEvidence::record(
                                memory_exits,
                                diagnostic,
                            );
                            pending.record(diagnostic);
                            None
                        }
                        darwin_resources::MemoryObservation::MissingAfterTaskExit(diagnostic) => {
                            darwin_resources::ExitObservationEvidence::record(
                                memory_exits,
                                diagnostic,
                            );
                            // The producer checked the actual current UID; the
                            // scan supplies the original session/group binding.
                            if before.pid != pid as u32 || before.pgid != group as u32 {
                                return Err(diagnostic.attach(ProcessError::new(
                                    "process_identity",
                                    "missing Darwin member has no original owned identity",
                                )));
                            }
                            missing.record(diagnostic)?;
                            None
                        }
                    }
                } else {
                    None
                };
                let session_after = unsafe { libc::getsid(pid) };
                if session_after == -1 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::ESRCH) {
                        if resource_scan {
                            missing.unavailable(pid as u32);
                        }
                        continue;
                    }
                    if missing.contains_pid(pid as u32) {
                        return Err(ProcessError::io(
                            "observe latched Darwin member session",
                            error,
                        ));
                    }
                }
                let latched = missing.contains_pid(pid as u32);
                if latched && session_after != group {
                    return Err(ProcessError::new(
                        "scope_escape",
                        "latched Darwin member changed session",
                    ));
                }
                let Some(after) = mac_bsd_info(pid, false)? else {
                    if resource_scan && latched {
                        missing.unavailable(pid as u32);
                    }
                    continue;
                };
                if latched {
                    missing.verify(pid as u32, after.observation())?;
                    if resource_scan
                        && memory.is_none()
                        && after.status != darwin_resources::SZOMB
                        && after.flags & darwin_resources::PROC_FLAG_INEXIT == 0
                    {
                        return Err(ProcessError::new(
                            "resource_observation",
                            "latched Darwin member no longer has the observed exit transition",
                        ));
                    }
                }
                if session_after != group
                    || before.pid != pid as u32
                    || after.pid != pid as u32
                    || before.start_sec != after.start_sec
                    || before.start_usec != after.start_usec
                    || before.pgid != after.pgid
                {
                    return Err(ProcessError::new(
                        "process_identity",
                        "macOS native identity changed during session observation",
                    ));
                }
                if after.pgid != group as u32 && after.status != 5 {
                    return Err(ProcessError::new(
                        "scope_escape",
                        "owned macOS session member changed process group; drain cannot be certified",
                    ));
                }
                if after.pgid == group as u32 && after.status != 5 {
                    members += 1;
                    if let Some(memory) = memory {
                        verify_memory_identity(Some(&before), Some(&after), pid)?;
                        if resource_scan {
                            missing.measured(before.observation().identity);
                        }
                        if let Some(sample) = resources.as_deref_mut() {
                            sample.push(memory)?;
                        }
                    }
                }
            }
            if !leader_seen {
                return Err(ProcessError::new(
                    "process_identity",
                    "reserved macOS group leader missing from native snapshot",
                ));
            }
            if resource_scan {
                missing.admit(allow_missing, leader_seen && *reservation_valid, pending)?;
            }
            Ok(())
        })();
        if let Err(mut error) = result {
            if let Some(diagnostic) = pending.last() {
                error
                    .message
                    .push_str(&format!("; pending_before_failure=[{diagnostic}]"));
            }
            return Err(error);
        }
        Ok(match pending.last() {
            Some(_) => darwin_resources::GroupObservation::Pending(Box::new(*pending)),
            None => darwin_resources::GroupObservation::Complete(members),
        })
    }
    #[cfg(target_os = "macos")]
    fn verify_memory_identity(
        before: Option<&BsdInfo>,
        after: Option<&BsdInfo>,
        pid: i32,
    ) -> Result<(), ProcessError> {
        let uid = unsafe { libc::geteuid() };
        if before.zip(after).is_none_or(|(before, after)| {
            before.pid != pid as u32
                || after.pid != pid as u32
                || before.uid != uid
                || after.uid != uid
                || (before.start_sec, before.start_usec, before.pgid)
                    != (after.start_sec, after.start_usec, after.pgid)
        }) {
            return Err(ProcessError::new(
                "resource_observation",
                "Darwin resource process identity changed or unavailable",
            ));
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    fn memory_or_confirmed_zombie(
        pid: i32,
        before: &BsdInfo,
        reserved: Option<(darwin_resources::LeaderIdentity, &mut bool)>,
    ) -> Result<darwin_resources::MemoryObservation, ProcessError> {
        let native = match darwin_resources::memory(pid) {
            Ok(memory) => return Ok(darwin_resources::MemoryObservation::Measured(memory)),
            Err(native) => native,
        };
        let anchor = reserved
            .as_ref()
            .map(|(anchor, _)| *anchor)
            .unwrap_or(before.observation().identity);
        let is_reserved = reserved.is_some();
        let diagnostic = |after: Option<&BsdInfo>| {
            darwin_resources::LeaderDiagnostic::observe(
                anchor,
                Some(before.observation()),
                after.map(BsdInfo::observation),
                darwin_resources::LeaderPhase::MemoryResult,
                darwin_resources::LeaderSession::NotObserved,
            )
            .with_memory_error(native, is_reserved)
        };
        if native.failure != mmmm_native_process::darwin::NativeResourceFailure::Exited {
            // Other native failures do not authorize another BSD lookup.
            return Err(diagnostic(None).attach(darwin_resources::native_error(native)));
        }
        let after = mac_bsd_info(pid, true).map_err(|error| diagnostic(None).attach(error))?;
        if reserved.is_none() && after.is_none() {
            let uid = unsafe { libc::geteuid() };
            if before.pid != pid as u32 || before.uid != uid {
                return Err(diagnostic(None).attach(ProcessError::new(
                    "resource_observation",
                    "Darwin resource process identity changed or unavailable",
                )));
            }
            // None is produced only by this actual native 0/ESRCH query. It is
            // a deferred resource candidate, never a same-identity sandwich.
            return darwin_resources::missing_after_task_exit(before.observation(), native);
        }
        if reserved.is_none()
            && let Some(first_after) = after.as_ref()
            && darwin_resources::member_exit_confirmation_candidate(
                before.observation(),
                first_after.observation(),
                native,
            )
        {
            // Reject an invalid first sandwich before the single additional
            // BSD query. The original first-after record remains diagnostic.
            verify_memory_identity(Some(before), Some(first_after), pid)
                .map_err(|error| diagnostic(Some(first_after)).attach(error))?;
            if let Some(confirmed) = darwin_resources::confirm_member_memory_exit(
                before.observation(),
                first_after.observation(),
                native,
                || {
                    let confirmed = mac_bsd_info(pid, true)?;
                    let uid = unsafe { libc::geteuid() };
                    Ok((confirmed.map(|info| info.observation()), uid))
                },
            )? {
                return Ok(confirmed);
            }
        }
        // The typed native result and actual same-birth BSD facts are both
        // retained. Classification can close a definitively lost reservation
        // before the original current-UID sandwich returns its primary error.
        let classified = darwin_resources::classify_memory_exit(
            reserved,
            before.observation(),
            after.as_ref().map(BsdInfo::observation),
            native,
        );
        verify_memory_identity(Some(before), after.as_ref(), pid)
            .map_err(|error| diagnostic(after.as_ref()).attach(error))?;
        classified
    }
    #[cfg(target_os = "macos")]
    fn live_leader_session_or_confirmed_zombie(
        pid: i32,
        anchor: darwin_resources::LeaderIdentity,
        before: &BsdInfo,
        phase: darwin_resources::LeaderPhase,
        reservation_valid: &mut bool,
    ) -> Result<darwin_resources::LeaderObservation, ProcessError> {
        let session = unsafe { libc::getsid(pid) };
        let session = if session == pid {
            darwin_resources::LeaderSession::Expected
        } else if session == -1 {
            // Capture errno before the existing follow-up libproc call.
            darwin_resources::LeaderSession::NativeFailure(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            )
        } else {
            darwin_resources::LeaderSession::Mismatch
        };
        if session == darwin_resources::LeaderSession::NativeFailure(libc::ESRCH) {
            let after = mac_bsd_info(pid, true).map_err(|error| {
                darwin_resources::LeaderDiagnostic::observe(
                    anchor,
                    Some(before.observation()),
                    None,
                    phase,
                    session,
                )
                .attach(error)
            })?;
            // Classify before the existing UID/current-process sandwich so a
            // definitive anchor mismatch closes signal rights. The original
            // native identity error stays primary if that sandwich fails.
            let diagnostic = darwin_resources::LeaderDiagnostic::observe(
                anchor,
                Some(before.observation()),
                after.as_ref().map(BsdInfo::observation),
                phase,
                session,
            );
            let classified = darwin_resources::classify_leader_session(
                anchor,
                before.observation(),
                after.as_ref().map(BsdInfo::observation),
                phase,
                session,
                reservation_valid,
            );
            verify_memory_identity(Some(before), after.as_ref(), pid)
                .map_err(|error| diagnostic.attach(error))?;
            return classified;
        }
        darwin_resources::classify_leader_session(
            anchor,
            before.observation(),
            None,
            phase,
            session,
            reservation_valid,
        )
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod native {
    use super::*;
    pub(super) const SCOPE: &str = "unsupported";
    pub(super) const STOP_WRITE_MODE: &str = "unsupported";
    pub(super) struct Process;
    impl Process {
        pub(super) fn spawn(_: &ProcessSpec) -> Result<Self, ProcessError> {
            Err(ProcessError::new(
                "unsupported_os",
                "no native owned process boundary for this OS",
            ))
        }
        pub(super) fn leader_exit(&self) -> Result<Option<LeaderExit>, ProcessError> {
            unreachable!()
        }
        pub(super) fn scope_empty(&self) -> Result<bool, ProcessError> {
            unreachable!()
        }
        pub(super) fn terminate(&mut self) -> Result<(), ProcessError> {
            unreachable!()
        }
        pub(super) fn minecraft_stop_capacity(&self) -> Option<u32> {
            None
        }
        pub(super) fn write_minecraft_stop(&mut self, _: usize) -> MinecraftStopWrite {
            unreachable!()
        }
        pub(super) fn close_minecraft_stop(&mut self) -> std::io::Result<bool> {
            unreachable!()
        }
        pub(super) fn reap(&mut self) -> Result<(), ProcessError> {
            unreachable!()
        }
        pub(super) fn capture(
            &mut self,
            _: &mut File,
            _: &mut File,
            _: &mut u64,
            _: &mut u64,
            _: u64,
        ) -> Result<(), ProcessError> {
            unreachable!()
        }
        pub(super) fn outputs_closed(&self) -> bool {
            unreachable!()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_observation_keeps_original_control_and_fixed_drain_distinct() {
        let mut spec = ProcessSpec::new(
            PathBuf::new(),
            PathBuf::new(),
            PathBuf::new(),
            PathBuf::new(),
        );
        let now = Instant::now();
        spec.absolute_deadline = Some(now);
        let cancelled = AtomicBool::new(true);
        let running = linux_observation_control(
            &spec,
            &cancelled,
            now,
            None,
            LinuxObservationPhase::Resource,
            |control| control.check("test_running"),
        )
        .unwrap_err();
        assert_eq!(running.kind, "command_cancelled");
        // This is a local control test, without child creation or native proof.
        linux_observation_control(
            &spec,
            &cancelled,
            now,
            Some(now),
            LinuxObservationPhase::Scope,
            |control| {
                assert!(!control.allow_new_bindings());
                control.check("test_existing_drain")
            },
        )
        .unwrap();
        let expired = now.checked_sub(spec.drain_timeout).unwrap();
        let result = linux_observation_control(
            &spec,
            &cancelled,
            now,
            Some(expired),
            LinuxObservationPhase::Scope,
            |control| {
                control.finish(
                    Err::<(), _>(ProcessError::new(
                        "process_identity",
                        "original query failure",
                    )),
                    "test_expired_drain",
                )
            },
        )
        .unwrap_err();
        assert_eq!(result.kind, "process_identity");
        assert!(result.message.contains("original query failure"));
        assert!(result.message.contains("fixed drain deadline"));
    }
    use std::sync::{Arc, atomic::AtomicU64};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    #[test]
    fn retry_observer_context_keeps_typed_primary_drain_and_private_paths_out() {
        for kind in ["command_cancelled", "command_timeout", "resource_budget"] {
            let error = run_observation(&mut |checkpoint| {
                assert!(checkpoint().is_err());
                Err("observation_failed: metadata reobservation; first_kind=PermissionDenied; first_raw_os_error=Some(5); attempts=2; final_kind=observation_failed; final_raw_os_error=Some(5); generated_relative=C:\\private-original\\untrusted\nlabel".into())
            }, || {
                let mut error = ProcessError::new(kind, "original primary error");
                error.drained = false;
                Err(error)
            }).unwrap_err();
            assert_eq!(error.kind, kind);
            assert!(!error.drained);
            assert!(
                error
                    .message
                    .starts_with("original primary error; observer_context=")
            );
            assert!(error.message.contains("first_raw_os_error=Some(5)"));
            assert!(!error.message.contains("private-original") && !error.message.contains('\n'));
            assert!(error.message.len() < 2048);
        }
        for context in [
            "untrusted C:\\private-original",
            "io: metadata reobservation; first_kind=C:\\private; generated_relative=safe",
        ] {
            assert!(safe_retry_observation_context(context).is_none());
        }
    }
    #[test]
    fn observation_progress_keeps_the_first_native_failure() {
        let mut samples = 0;
        let error = run_observation(
            &mut |checkpoint| {
                assert_eq!(
                    checkpoint().unwrap_err(),
                    "resource_observation: native resource sample unavailable"
                );
                // Even a caller ignoring/wrapping the failure cannot erase it
                // or silently retry the native sample within this observation.
                assert!(checkpoint().is_err());
                Ok(())
            },
            || {
                samples += 1;
                Err(ProcessError::new(
                    "resource_observation",
                    "native resource sample unavailable",
                ))
            },
        )
        .unwrap_err();
        assert_eq!(samples, 1);
        assert_eq!(error.kind, "resource_observation");
        assert_eq!(error.message, "native resource sample unavailable");
    }
    #[test]
    fn observation_progress_preserves_managed_failure_after_samples() {
        let mut samples = 0;
        let error = run_observation(
            &mut |checkpoint| {
                for _ in 0..4 {
                    checkpoint()?;
                }
                Err("ownership changed".into())
            },
            || {
                samples += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(samples, 4);
        assert_eq!(error.kind, "observation");
        assert_eq!(error.message, "ownership changed");
    }
    #[test]
    fn foreign_resource_policy_is_rejected_before_filesystem_or_process_access() {
        let mut spec = ProcessSpec::new(
            PathBuf::from("unresolved-program"),
            PathBuf::from("unresolved-directory"),
            PathBuf::from("unresolved-stdout"),
            PathBuf::from("unresolved-stderr"),
        );
        spec.resource_policy = if ResourcePolicy::current() == ResourcePolicy::WindowsJob {
            ResourcePolicy::LinuxAddressSpace
        } else {
            ResourcePolicy::WindowsJob
        };
        assert_eq!(validate(&spec).unwrap_err().kind, "resource_configuration");
    }
    struct TestRun {
        root: PathBuf,
        spec: ProcessSpec,
    }
    impl TestRun {
        fn new(mode: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "mmmm-process-test-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            assert!(!root.exists(), "test root must be new");
            fs::create_dir(&root).unwrap();
            // Reproduce managed Windows canonical paths even when the outer
            // runner's TMP happens to use a DOS representation.
            #[cfg(windows)]
            let cwd = fs::canonicalize(&root).unwrap();
            #[cfg(not(windows))]
            let cwd = root.clone();
            let mut spec = ProcessSpec::new(
                std::env::current_exe().unwrap(),
                cwd,
                root.join("stdout.log"),
                root.join("stderr.log"),
            );
            spec.args = [
                "--exact",
                "process::tests::process_fixture_child",
                "--ignored",
                "--nocapture",
            ]
            .into_iter()
            .map(OsString::from)
            .collect();
            spec.env.insert("MMMM_PROCESS_FIXTURE".into(), mode.into());
            spec.timeout = Duration::from_secs(3);
            spec.drain_timeout = Duration::from_secs(5);
            Self { root, spec }
        }
        fn cleanup(self, drained: bool) {
            if drained {
                let root = fs::canonicalize(&self.root).unwrap();
                assert!(root.starts_with(fs::canonicalize(std::env::temp_dir()).unwrap()));
                assert!(
                    !fs::symlink_metadata(&self.root)
                        .unwrap()
                        .file_type()
                        .is_symlink()
                );
                fs::remove_dir_all(root).unwrap();
            }
        }
    }
    #[test]
    #[ignore = "child fixture, executed only by native process supervision tests"]
    fn process_fixture_child() {
        let mode = std::env::var("MMMM_PROCESS_FIXTURE").expect("fixture mode");
        match mode.as_str() {
            "normal" => {
                println!("owned-output");
                eprintln!("owned-error");
            }
            "minecraft_stop" => {
                let mut bytes = Vec::new();
                std::io::stdin().take(6).read_to_end(&mut bytes).unwrap();
                assert_eq!(bytes.as_slice(), MINECRAFT_STOP_BYTES);
                println!("fixed-minecraft-stop-and-eof-observed");
            }
            "minecraft_stdin_closed" => {
                #[cfg(windows)]
                {
                    use std::os::windows::io::AsRawHandle;
                    assert_ne!(
                        unsafe {
                            windows_sys::Win32::Foundation::CloseHandle(
                                std::io::stdin().as_raw_handle().cast(),
                            )
                        },
                        0
                    );
                }
                #[cfg(unix)]
                assert_eq!(unsafe { libc::close(libc::STDIN_FILENO) }, 0);
                fs::write("stdin-closed.ready", b"closed").unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
            "explicit_environment" => {
                assert!(std::env::var_os("PATH").is_none());
                assert_eq!(
                    std::env::var_os("MMMM_OWNED_ENVIRONMENT_SENTINEL"),
                    Some(OsString::from("explicit-only"))
                );
                println!("owned explicit environment verified");
            }
            "failure" => {
                println!("owned-failure-output");
                eprintln!("owned-failure-error");
                std::io::stdout().flush().unwrap();
                std::io::stderr().flush().unwrap();
                std::process::exit(23);
            }
            "hold" => std::thread::sleep(Duration::from_secs(30)),
            "brief_hold" => std::thread::sleep(Duration::from_millis(500)),
            "resource_probe" => {
                #[cfg(target_os = "linux")]
                {
                    let mut limit = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    // SAFETY: this child reads only its own fixed rlimit into
                    // a live writable value; no parent or global quota changes.
                    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut limit) }, 0);
                    assert_eq!(
                        limit.rlim_cur,
                        resource_policy::MEMORY_LIMIT as libc::rlim_t
                    );
                    assert_eq!(
                        limit.rlim_max,
                        resource_policy::MEMORY_LIMIT as libc::rlim_t
                    );
                    println!("owned Linux address-space readback verified");
                }
                #[cfg(windows)]
                println!("owned Windows resource probe executed");
                std::thread::sleep(Duration::from_millis(250));
            }
            #[cfg(target_os = "linux")]
            "jvm_resource_probe" => {
                let mut readback = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                // This isolated fixture reads its inherited limit and reserves
                // VM without committing a large resident allocation.
                assert_eq!(
                    unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut readback) },
                    0
                );
                assert_eq!(readback.rlim_cur, resource_policy::JVM_VM_LIMIT);
                assert_eq!(readback.rlim_max, resource_policy::JVM_VM_LIMIT);
                let reservation_bytes = 8usize * 1024 * 1024 * 1024;
                let reservation = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        reservation_bytes,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                        -1,
                        0,
                    )
                };
                assert_ne!(reservation, libc::MAP_FAILED);
                unsafe { (reservation as *mut u8).write_volatile(1) };
                println!("owned Linux JVM exact readback and finite VM reservation verified");
                std::thread::sleep(Duration::from_millis(350));
                assert_eq!(unsafe { libc::munmap(reservation, reservation_bytes) }, 0);
            }
            #[cfg(target_os = "linux")]
            "many_owned" => {
                // This ignored isolated fixture has a finite count and delay.
                // Its enclosing supervisor owns termination and reap evidence.
                #[allow(clippy::zombie_processes)]
                let children: Vec<_> = (0..33)
                    .map(|_| {
                        std::process::Command::new(std::env::current_exe().unwrap())
                            .args([
                                "--exact",
                                "process::tests::process_fixture_child",
                                "--ignored",
                                "--nocapture",
                            ])
                            .env("MMMM_PROCESS_FIXTURE", "hold")
                            .spawn()
                            .unwrap()
                    })
                    .collect();
                println!("owned process fixture started {} children", children.len());
                std::thread::sleep(Duration::from_secs(30));
                drop(children);
            }
            "remaining" | "remaining_brief" | "remaining_failure" => {
                // The fixture leader must exit before this child. The enclosing
                // native scope owns and drains it; waiting here would remove the
                // remaining-child condition these supervision tests must observe.
                #[allow(clippy::zombie_processes)]
                let child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "process::tests::process_fixture_child",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env(
                        "MMMM_PROCESS_FIXTURE",
                        if mode == "remaining_brief" {
                            "brief_hold"
                        } else {
                            "hold"
                        },
                    )
                    .spawn()
                    .unwrap();
                println!("owned child {}", child.id());
                std::thread::sleep(Duration::from_millis(100));
                if mode == "remaining_failure" {
                    std::process::exit(23);
                }
            }
            "output" => std::io::stdout()
                .write_all(&vec![b'x'; 128 * 1024])
                .unwrap(),
            _ => panic!("unknown child fixture"),
        }
    }
    #[test]
    fn normal_exit_and_raw_logs() {
        let run = TestRun::new("normal");
        let mut captured =
            supervise_with_progress_captured(&run.spec, &AtomicBool::new(false), |_| Ok(()))
                .unwrap();
        let mut current_checks = 0;
        let stdout = captured
            .read_stdout(64 * 1024, || {
                current_checks += 1;
                Ok(())
            })
            .unwrap();
        assert!(current_checks > 1);
        assert!(String::from_utf8(stdout).unwrap().contains("owned-output"));
        assert_eq!(captured.outcome().command_exit, Some(0));
        assert!(captured.process_started());
        let result = captured.into_outcome();
        assert_eq!(result.command_exit, Some(0));
        assert_eq!(result.termination_reason, TerminationReason::Completed);
        assert!(result.drained && result.supervisor_errors.is_empty());
        assert!(
            fs::read_to_string(&run.spec.stdout_log)
                .unwrap()
                .contains("owned-output")
        );
        assert!(
            fs::read_to_string(&run.spec.stderr_log)
                .unwrap()
                .contains("owned-error")
        );
        run.cleanup(result.drained);
    }

    #[test]
    fn drained_raw_logs_keep_both_original_handles_for_success_and_failure() {
        // 기존 native child의 두 stream과 exit23을 재사용한다. 기존 검사는
        // stdout held-read만 다루어 immutable reader의 Windows OS32를 재현하지 못했다.
        for (mode, exit, stdout_marker, stderr_marker) in [
            ("normal", 0, "owned-output", "owned-error"),
            ("failure", 23, "owned-failure-output", "owned-failure-error"),
        ] {
            let run = TestRun::new(mode);
            let mut captured =
                supervise_with_progress_captured(&run.spec, &AtomicBool::new(false), |_| Ok(()))
                    .unwrap();
            assert!(captured.process_started() && captured.outcome().drained);
            assert_eq!(captured.outcome().command_exit, Some(exit));
            let original_outcome = serde_json::to_value(captured.outcome()).unwrap();
            let strict = captured.read_stdout(64 * 1024, || Ok(()));
            if exit == 0 {
                assert!(
                    String::from_utf8(strict.unwrap())
                        .unwrap()
                        .contains(stdout_marker)
                );
            } else {
                assert_eq!(strict.unwrap_err().kind, "capture_incomplete");
            }
            for (stream, path, marker, bytes) in [
                (
                    CaptureStream::Stdout,
                    &run.spec.stdout_log,
                    stdout_marker,
                    captured.outcome().stdout_bytes,
                ),
                (
                    CaptureStream::Stderr,
                    &run.spec.stderr_log,
                    stderr_marker,
                    captured.outcome().stderr_bytes,
                ),
            ] {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::OpenOptionsExt;
                    let reopen = OpenOptions::new()
                        .read(true)
                        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
                        .open(path)
                        .unwrap_err();
                    assert_eq!(reopen.raw_os_error(), Some(32));
                    assert_eq!(
                        OpenOptions::new()
                            .write(true)
                            .open(path)
                            .unwrap_err()
                            .raw_os_error(),
                        Some(32)
                    );
                    assert_eq!(fs::remove_file(path).unwrap_err().raw_os_error(), Some(32));
                }
                #[cfg(unix)]
                {
                    fs::rename(path, path.with_extension("original")).unwrap();
                    fs::write(path, b"foreign replacement bytes").unwrap();
                }
                let raw = captured
                    .read_drained_log(stream, 64 * 1024, || Ok(()))
                    .unwrap();
                assert_eq!(u64::try_from(raw.len()).unwrap(), bytes);
                assert!(String::from_utf8(raw).unwrap().contains(marker));
            }
            assert_eq!(
                serde_json::to_value(captured.outcome()).unwrap(),
                original_outcome
            );
            let outcome = captured.into_outcome();
            assert_eq!(serde_json::to_value(&outcome).unwrap(), original_outcome);
            run.cleanup(outcome.drained);
        }
    }

    #[test]
    fn minecraft_stop_is_delivered_once_and_closes_only_its_original_control() {
        let mut run = TestRun::new("minecraft_stop");
        let stop = MinecraftStopHandle::new();
        let unrelated = MinecraftStopHandle::new();
        stop.request().unwrap();
        stop.clone().request().unwrap();
        run.spec.minecraft_stop = Some(stop.clone());
        let result = supervise(&run.spec, &AtomicBool::new(false), || Ok(())).unwrap();
        assert_eq!(result.command_exit, Some(0));
        assert_eq!(result.termination_reason, TerminationReason::Completed);
        assert!(result.drained && result.output_complete && result.supervisor_errors.is_empty());
        let evidence = result.minecraft_stop.as_ref().unwrap();
        assert!(evidence.requested && evidence.request_observed && evidence.control_closed);
        assert!(evidence.writer_available && evidence.writer_closed);
        assert_eq!(evidence.bytes_written, 5);
        assert!(evidence.write_error.is_none() && evidence.close_error.is_none());
        assert_eq!(evidence.acknowledgement, "not_observed");
        #[cfg(windows)]
        assert!(evidence.pipe_capacity_bytes.unwrap() >= 5);
        assert!(
            fs::read_to_string(&run.spec.stdout_log)
                .unwrap()
                .contains("fixed-minecraft-stop-and-eof-observed")
        );
        assert_eq!(stop.request(), Err(MinecraftStopClosed));
        let original_other_binding = MinecraftStopBinding::bind(&unrelated).unwrap();
        assert!(MinecraftStopBinding::bind(&unrelated).is_err());
        unrelated.request().unwrap();
        drop(original_other_binding);
        assert_eq!(unrelated.request(), Err(MinecraftStopClosed));
        assert_eq!(
            supervise(&run.spec, &AtomicBool::new(false), || Ok(()))
                .unwrap_err()
                .kind,
            "minecraft_stop_binding"
        );
        run.cleanup(result.drained);
    }

    #[test]
    fn unrequested_opt_in_and_default_null_stdin_do_not_send_a_stop() {
        for opt_in in [false, true] {
            let mut run = TestRun::new("normal");
            assert!(run.spec.minecraft_stop.is_none());
            if opt_in {
                run.spec.minecraft_stop = Some(MinecraftStopHandle::new());
            }
            let result = supervise(&run.spec, &AtomicBool::new(false), || Ok(())).unwrap();
            assert_eq!(result.command_exit, Some(0));
            assert!(result.drained && result.supervisor_errors.is_empty());
            if let Some(evidence) = &result.minecraft_stop {
                assert!(!evidence.requested && !evidence.request_observed);
                assert!(
                    evidence.writer_available && evidence.writer_closed && evidence.control_closed
                );
                assert_eq!(evidence.bytes_written, 0);
                assert_eq!(evidence.write_attempts, 0);
                assert_eq!(
                    run.spec.minecraft_stop.as_ref().unwrap().request(),
                    Err(MinecraftStopClosed)
                );
            } else {
                assert!(!opt_in);
            }
            let json = serde_json::to_value(&result).unwrap();
            assert_eq!(json.get("minecraft_stop").is_some(), opt_in);
            run.cleanup(result.drained);
        }
    }

    #[test]
    fn original_peer_close_is_a_stop_write_failure_with_native_error_and_drain() {
        let mut run = TestRun::new("minecraft_stdin_closed");
        let stop = MinecraftStopHandle::new();
        run.spec.minecraft_stop = Some(stop.clone());
        run.spec.observation_interval = Duration::from_millis(50);
        let marker = run.root.join("stdin-closed.ready");
        let result = supervise(&run.spec, &AtomicBool::new(false), || {
            // child가 실제 read end를 닫은 뒤 만든 marker를 관측한다. 임의 sleep 순서를 가정하지 않는다.
            if marker.exists() {
                stop.request().map_err(|error| error.to_string())?;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(
            result.termination_reason,
            TerminationReason::SupervisorFailure
        );
        assert!(result.drained && !result.supervisor_errors.is_empty());
        let evidence = result.minecraft_stop.as_ref().unwrap();
        assert!(evidence.request_observed && evidence.writer_closed && evidence.control_closed);
        assert_eq!(evidence.bytes_written, 0);
        let error = evidence.write_error.as_ref().unwrap();
        assert_eq!(error.kind, "BrokenPipe");
        assert!(error.raw_os_error.is_some());
        assert_eq!(evidence.acknowledgement, "not_observed");
        assert_eq!(stop.request(), Err(MinecraftStopClosed));
        run.cleanup(result.drained);
    }

    #[test]
    fn partial_stop_and_would_block_preserve_offsets_and_a_later_original_error() {
        struct Port {
            calls: Vec<usize>,
            responses: std::collections::VecDeque<MinecraftStopWrite>,
            closes: usize,
            close_error: Option<std::io::Error>,
        }
        impl MinecraftStopSink for Port {
            fn write_stop(&mut self, offset: usize) -> MinecraftStopWrite {
                self.calls.push(offset);
                self.responses.pop_front().unwrap()
            }
            fn close_stop(&mut self) -> std::io::Result<bool> {
                self.closes += 1;
                if let Some(error) = self.close_error.take() {
                    Err(error)
                } else {
                    Ok(true)
                }
            }
        }
        let broken = if cfg!(windows) { 109 } else { 32 };
        let mut sink = Port {
            calls: Vec::new(),
            closes: 0,
            close_error: None,
            responses: [
                MinecraftStopWrite {
                    bytes: 2,
                    error: None,
                },
                MinecraftStopWrite::result(Err(std::io::Error::from(
                    std::io::ErrorKind::WouldBlock,
                ))),
                MinecraftStopWrite {
                    bytes: 1,
                    error: Some(std::io::Error::from_raw_os_error(broken)),
                },
            ]
            .into(),
        };
        let mut evidence = MinecraftStopEvidence::new();
        evidence.writer_available = true;
        advance_minecraft_stop(&mut sink, &mut evidence).unwrap();
        advance_minecraft_stop(&mut sink, &mut evidence).unwrap();
        assert_eq!(
            advance_minecraft_stop(&mut sink, &mut evidence)
                .unwrap_err()
                .kind,
            "minecraft_stop_write"
        );
        assert_eq!(sink.calls, [0, 2, 2]);
        assert_eq!(evidence.bytes_written, 3);
        assert_eq!(evidence.would_block, 1);
        assert_eq!(
            evidence.last_would_block.as_ref().unwrap().kind,
            "WouldBlock"
        );
        assert_eq!(
            evidence.write_error.as_ref().unwrap().raw_os_error,
            Some(broken)
        );
        assert_eq!(evidence.write_error.as_ref().unwrap().kind, "BrokenPipe");
        close_minecraft_writer(&mut sink, &mut evidence).unwrap();
        assert_eq!(sink.closes, 1);
        assert!(evidence.writer_closed);
        assert_eq!(evidence.bytes_written, 3);
        assert_eq!(evidence.acknowledgement, "not_observed");
        let mut failed_close = Port {
            calls: Vec::new(),
            responses: Default::default(),
            closes: 0,
            close_error: Some(std::io::Error::from_raw_os_error(broken)),
        };
        let mut incomplete = MinecraftStopEvidence::new();
        incomplete.writer_available = true;
        incomplete.bytes_written = 5;
        assert_eq!(
            close_minecraft_writer(&mut failed_close, &mut incomplete)
                .unwrap_err()
                .kind,
            "minecraft_stop_close"
        );
        assert!(!incomplete.writer_closed);
        assert_eq!(
            incomplete.close_error.as_ref().unwrap().raw_os_error,
            Some(broken)
        );
        assert_eq!(incomplete.bytes_written, 5);
        assert_eq!(incomplete.acknowledgement, "not_observed");
    }

    #[test]
    fn explicit_environment_has_no_inherited_search_path() {
        let mut run = TestRun::new("explicit_environment");
        assert!(run.spec.inherit_environment);
        run.spec.inherit_environment = false;
        run.spec.env.insert(
            "MMMM_OWNED_ENVIRONMENT_SENTINEL".into(),
            "explicit-only".into(),
        );
        let capture =
            supervise_with_progress_captured(&run.spec, &AtomicBool::new(false), |_| Ok(()))
                .unwrap();
        let outcome = capture.into_outcome();
        assert_eq!(outcome.command_exit, Some(0));
        assert!(outcome.drained && outcome.supervisor_errors.is_empty());
        assert!(
            fs::read_to_string(&run.spec.stdout_log)
                .unwrap()
                .contains("owned explicit environment verified")
        );
        run.cleanup(outcome.drained);
    }

    #[test]
    fn pre_spawn_cancellation_and_original_deadline_have_no_created_process() {
        for cancelled in [true, false] {
            let mut run = TestRun::new("normal");
            let stop = MinecraftStopHandle::new();
            stop.request().unwrap();
            run.spec.minecraft_stop = Some(stop.clone());
            run.spec.absolute_deadline = Some(if cancelled {
                Instant::now() + Duration::from_secs(2)
            } else {
                Instant::now() - Duration::from_secs(1)
            });
            let capture = supervise_with_progress_captured(
                &run.spec,
                &AtomicBool::new(cancelled),
                |_| Ok(()),
            )
            .unwrap();
            assert!(!capture.process_started());
            assert!(capture.outcome().drained);
            assert_eq!(capture.outcome().command_exit, None);
            assert_eq!(capture.outcome().stdout_bytes, 0);
            assert_eq!(capture.outcome().stderr_bytes, 0);
            let evidence = capture.outcome().minecraft_stop.as_ref().unwrap();
            assert!(evidence.requested && evidence.control_closed);
            assert!(
                !evidence.writer_available && !evidence.writer_closed && !evidence.request_observed
            );
            assert_eq!(evidence.bytes_written, 0);
            assert_eq!(evidence.write_attempts, 0);
            assert_eq!(stop.request(), Err(MinecraftStopClosed));
            assert_eq!(
                capture.outcome().termination_reason,
                if cancelled {
                    TerminationReason::Cancelled
                } else {
                    TerminationReason::Timeout
                }
            );
            let outcome = capture.into_outcome();
            run.cleanup(outcome.drained);
        }
    }

    #[test]
    fn original_absolute_deadline_survives_pre_spawn_observation_work() {
        let mut run = TestRun::new("hold");
        run.spec.absolute_deadline = Some(Instant::now() + Duration::from_secs(1));
        let mut initial = true;
        let capture = supervise_with_progress_captured(&run.spec, &AtomicBool::new(false), |_| {
            if initial {
                initial = false;
                std::thread::sleep(Duration::from_millis(350));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(
            capture.outcome().termination_reason,
            TerminationReason::Timeout
        );
        assert!(capture.outcome().drained);
        // The relative fixture budget is three seconds. Native supervision
        // must use the earlier caller deadline after the pre-spawn work.
        assert!(capture.outcome().elapsed_ms < 2500);
        let outcome = capture.into_outcome();
        run.cleanup(outcome.drained);
    }

    // These fixture outcomes exercise only the private captured-read boundary.
    // The normal-exit test above obtains its outcome from real native supervision.
    fn captured_read_fixture(run: &TestRun, body: &[u8]) -> CapturedProcessOutcome {
        let mut stdout_log = create_log(&run.spec.stdout_log).unwrap();
        stdout_log.write_all(body).unwrap();
        stdout_log.sync_all().unwrap();
        CapturedProcessOutcome {
            stdout_log,
            stderr_log: create_log(&run.spec.stderr_log).unwrap(),
            process_started: false,
            outcome: ProcessOutcome {
                command_exit: Some(0),
                command_signal: None,
                supervisor_errors: Vec::new(),
                drained: true,
                termination_reason: TerminationReason::Completed,
                elapsed_ms: 0,
                stdout_bytes: u64::try_from(body.len()).unwrap(),
                stderr_bytes: 0,
                output_complete: true,
                owned_tail_terminated: false,
                native_scope: native::SCOPE,
                resource_policy: ResourcePolicy::current(),
                minecraft_stop: None,
                #[cfg(any(windows, target_os = "linux"))]
                resource_limits: None,
                #[cfg(target_os = "linux")]
                linux_original_lifetimes: None,
                #[cfg(target_os = "macos")]
                darwin_resources: None,
            },
        }
    }

    #[test]
    fn captured_read_rejects_incomplete_or_failed_native_outcomes() {
        for case in 0..8 {
            let run = TestRun::new("capture-read-unit");
            let mut captured = captured_read_fixture(&run, b"retained evidence");
            match case {
                0 => captured.outcome.drained = false,
                1 => captured.outcome.output_complete = false,
                2 => captured.outcome.command_exit = None,
                3 => captured.outcome.command_exit = Some(23),
                4 => captured.outcome.command_signal = Some(15),
                5 => captured
                    .outcome
                    .supervisor_errors
                    .push("native error".into()),
                6 => captured.outcome.termination_reason = TerminationReason::Timeout,
                7 => captured.outcome.termination_reason = TerminationReason::Cancelled,
                _ => unreachable!(),
            }
            let mut checks = 0;
            let error = captured
                .read_stdout(1024, || {
                    checks += 1;
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(error.kind, "capture_incomplete");
            assert_eq!(error.drained, captured.outcome.drained);
            assert_eq!(checks, 0);
            if case == 0 {
                let raw_error = captured
                    .read_drained_log(CaptureStream::Stderr, 1024, || {
                        checks += 1;
                        Ok(())
                    })
                    .unwrap_err();
                assert_eq!(raw_error.kind, "capture_incomplete");
                assert!(!raw_error.drained);
                assert_eq!(checks, 0);
            } else {
                let original_outcome = serde_json::to_value(captured.outcome()).unwrap();
                assert_eq!(
                    captured
                        .read_drained_log(CaptureStream::Stdout, 1024, || Ok(()))
                        .unwrap(),
                    b"retained evidence"
                );
                assert_eq!(
                    captured
                        .read_drained_log(CaptureStream::Stderr, 1024, || Ok(()))
                        .unwrap(),
                    b""
                );
                assert_eq!(
                    serde_json::to_value(captured.outcome()).unwrap(),
                    original_outcome
                );
                assert_eq!(
                    captured.read_stdout(1024, || Ok(())).unwrap_err().kind,
                    "capture_incomplete"
                );
            }
            drop(captured);
            run.cleanup(true);
        }
    }

    #[test]
    fn captured_read_caps_and_current_revocation_never_return_a_prefix() {
        let run = TestRun::new("capture-read-unit");
        let mut captured = captured_read_fixture(&run, b"original bytes");
        for cap in [0, 2, MAX_CAPTURE_READ_BYTES + 1] {
            assert_eq!(
                captured.read_stdout(cap, || Ok(())).unwrap_err().kind,
                "capture_read_budget"
            );
        }
        let error = captured
            .read_stdout(1024, || Err("original current scope revoked".into()))
            .unwrap_err();
        assert_eq!(error.kind, "capture_read_check");
        assert_eq!(error.message, "original current scope revoked");
        let mut original_handle = captured.stdout_log.try_clone().unwrap();
        original_handle.seek(SeekFrom::Start(0)).unwrap();
        let error = captured
            .read_stdout(1024, || {
                if original_handle.stream_position().unwrap() > 0 {
                    Err("current scope revoked after read".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(error.kind, "capture_read_check");
        assert_eq!(error.message, "current scope revoked after read");
        drop(original_handle);
        drop(captured);
        run.cleanup(true);
    }

    #[test]
    fn captured_read_rejects_initial_or_during_read_size_changes() {
        for during_read in [false, true] {
            let run = TestRun::new("capture-read-unit");
            let mut captured = captured_read_fixture(&run, b"original bytes");
            let mut original_handle = captured.stdout_log.try_clone().unwrap();
            original_handle.seek(SeekFrom::Start(0)).unwrap();
            if !during_read {
                original_handle.set_len(1).unwrap();
            }
            let mut changed = false;
            let error = captured
                .read_stdout(1024, || {
                    if during_read && !changed && original_handle.stream_position().unwrap() > 0 {
                        original_handle.set_len(1).unwrap();
                        changed = true;
                    }
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(error.kind, "capture_changed");
            assert_eq!(changed, during_read);
            drop(original_handle);
            drop(captured);
            run.cleanup(true);
        }
    }

    #[test]
    fn captured_read_deadline_is_finite_and_not_retried() {
        let started = Instant::now().checked_sub(CAPTURE_READ_TIMEOUT).unwrap();
        let mut checks = 0;
        let error = capture_read_checkpoint(
            &mut || {
                checks += 1;
                Ok(())
            },
            started,
        )
        .unwrap_err();
        assert_eq!(error.kind, "capture_read_timeout");
        assert_eq!(checks, 0);
    }

    #[test]
    fn captured_read_keeps_the_original_handle_and_windows_share_boundary() {
        let run = TestRun::new("capture-read-unit");
        let mut captured = captured_read_fixture(&run, b"original bytes");
        #[cfg(windows)]
        {
            let write_error = OpenOptions::new()
                .write(true)
                .open(&run.spec.stdout_log)
                .unwrap_err();
            assert_eq!(write_error.raw_os_error(), Some(32));
            assert_eq!(
                fs::remove_file(&run.spec.stdout_log)
                    .unwrap_err()
                    .raw_os_error(),
                Some(32)
            );
            assert_eq!(
                fs::rename(&run.spec.stdout_log, run.root.join("replacement"))
                    .unwrap_err()
                    .raw_os_error(),
                Some(32)
            );
        }
        #[cfg(unix)]
        {
            // Renaming a pathname cannot change which file the capture owns.
            fs::rename(&run.spec.stdout_log, run.root.join("original-capture")).unwrap();
            fs::write(&run.spec.stdout_log, b"foreign path replacement").unwrap();
        }
        assert_eq!(
            captured.read_stdout(1024, || Ok(())).unwrap(),
            b"original bytes"
        );
        let outcome_json = serde_json::to_value(captured.outcome()).unwrap();
        let result = captured.into_outcome();
        assert_eq!(serde_json::to_value(&result).unwrap(), outcome_json);
        // Consuming the capture releases its Windows deny-write/delete handle.
        fs::remove_file(&run.spec.stdout_log).unwrap();
        run.cleanup(true);
    }
    #[test]
    fn failed_command_stays_distinct_from_supervisor() {
        let run = TestRun::new("failure");
        let result = supervise(&run.spec, &AtomicBool::new(false), || Ok(())).unwrap();
        assert_eq!(result.command_exit, Some(23));
        assert!(result.drained && result.supervisor_errors.is_empty());
        run.cleanup(result.drained);
    }
    #[test]
    fn timeout_terminates_and_drains_owned_scope() {
        let mut run = TestRun::new("hold");
        let stop = MinecraftStopHandle::new();
        stop.request().unwrap();
        run.spec.minecraft_stop = Some(stop.clone());
        run.spec.timeout = Duration::from_secs(1);
        let result = supervise(&run.spec, &AtomicBool::new(false), || Ok(())).unwrap();
        assert_eq!(result.termination_reason, TerminationReason::Timeout);
        assert!(result.drained);
        assert!(result.elapsed_ms < 7000);
        let evidence = result.minecraft_stop.as_ref().unwrap();
        assert!(evidence.requested && evidence.control_closed && evidence.writer_closed);
        assert!(evidence.bytes_written <= 5);
        assert_eq!(evidence.acknowledgement, "not_observed");
        assert_eq!(stop.request(), Err(MinecraftStopClosed));
        run.cleanup(result.drained);
    }
    #[test]
    fn cancellation_terminates_and_drains_owned_scope() {
        let mut run = TestRun::new("hold");
        let stop = MinecraftStopHandle::new();
        stop.request().unwrap();
        run.spec.minecraft_stop = Some(stop.clone());
        let cancellation = Arc::new(AtomicBool::new(false));
        let cancel = cancellation.clone();
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            cancel.store(true, Ordering::Release);
        });
        let result = supervise(&run.spec, &cancellation, || Ok(())).unwrap();
        sender.join().unwrap();
        assert_eq!(result.termination_reason, TerminationReason::Cancelled);
        assert!(result.drained);
        let evidence = result.minecraft_stop.as_ref().unwrap();
        assert!(evidence.requested && evidence.control_closed);
        assert_eq!(evidence.writer_closed, evidence.writer_available);
        assert!(evidence.bytes_written <= 5);
        assert_eq!(evidence.acknowledgement, "not_observed");
        assert_eq!(stop.request(), Err(MinecraftStopClosed));
        run.cleanup(result.drained);
    }
    #[test]
    fn leader_exit_with_remaining_child_is_reported_and_drained() {
        let run = TestRun::new("remaining");
        let result = supervise(&run.spec, &AtomicBool::new(false), || Ok(())).unwrap();
        assert_eq!(result.command_exit, Some(0));
        assert_eq!(
            result.termination_reason,
            TerminationReason::RemainingChildren
        );
        assert!(!result.owned_tail_terminated);
        assert!(result.drained);
        run.cleanup(result.drained);
    }
    #[test]
    fn explicit_build_tail_cleanup_preserves_leader_exit_and_records_native_drain() {
        // Existing remaining-child fixtures model compiler telemetry helpers.
        // Opt-in may clean that owned tail without replacing the leader result.
        for (mode, code) in [("remaining", 0), ("remaining_failure", 23)] {
            let mut run = TestRun::new(mode);
            assert_eq!(run.spec.tail_policy, TailPolicy::Reject);
            run.spec.tail_policy = TailPolicy::TerminateForBuild;
            let result = supervise(&run.spec, &AtomicBool::new(false), || Ok(())).unwrap();
            assert_eq!(result.command_exit, Some(code));
            assert_eq!(
                result.termination_reason,
                TerminationReason::CompletedAfterOwnedTailCleanup
            );
            assert!(result.owned_tail_terminated);
            assert!(
                result.drained && result.output_complete && result.supervisor_errors.is_empty()
            );
            run.cleanup(result.drained);
        }
    }
    #[test]
    fn explicit_build_tail_policy_does_not_override_timeout() {
        let mut run = TestRun::new("remaining");
        run.spec.tail_policy = TailPolicy::TerminateForBuild;
        run.spec.timeout = Duration::from_secs(1);
        let result = supervise(&run.spec, &AtomicBool::new(false), || Ok(())).unwrap();
        assert_eq!(result.command_exit, Some(0));
        assert_eq!(result.termination_reason, TerminationReason::Timeout);
        assert!(!result.owned_tail_terminated);
        assert!(result.drained && !result.supervisor_errors.is_empty());
        run.cleanup(result.drained);
    }
    #[test]
    fn child_finishing_during_natural_grace_is_completed() {
        let run = TestRun::new("remaining_brief");
        let result = supervise(&run.spec, &AtomicBool::new(false), || Ok(())).unwrap();
        assert_eq!(result.command_exit, Some(0));
        assert_eq!(result.termination_reason, TerminationReason::Completed);
        assert!(result.drained && result.output_complete && result.supervisor_errors.is_empty());
        run.cleanup(result.drained);
    }
    #[test]
    fn output_budget_is_combined_and_explicit() {
        let mut run = TestRun::new("output");
        run.spec.max_log_bytes = 1024;
        let result = supervise(&run.spec, &AtomicBool::new(false), || Ok(())).unwrap();
        assert_eq!(result.termination_reason, TerminationReason::OutputLimit);
        assert_eq!(result.stdout_bytes + result.stderr_bytes, 1024);
        assert!(result.drained);
        run.cleanup(result.drained);
    }
    #[test]
    fn observation_error_stops_owned_command() {
        let mut run = TestRun::new("hold");
        run.spec.observation_interval = Duration::from_millis(100);
        let mut calls = 0;
        let result = supervise(&run.spec, &AtomicBool::new(false), || {
            calls += 1;
            if calls == 1 {
                Ok(())
            } else {
                Err("ownership changed".into())
            }
        })
        .unwrap();
        assert_eq!(
            result.termination_reason,
            TerminationReason::ObservationFailure
        );
        assert!(result.drained);
        run.cleanup(result.drained);
    }
    #[test]
    fn phased_observation_identifies_pre_spawn_and_running_without_changing_drain() {
        let mut run = TestRun::new("hold");
        run.spec.observation_interval = Duration::from_millis(100);
        let mut phases = Vec::new();
        let result = supervise_with_progress_phased(
            &run.spec,
            &AtomicBool::new(false),
            |phase, checkpoint| {
                phases.push(phase);
                checkpoint()?;
                if phase == ObservationPhase::Running {
                    Err("bounded running observation fixture".into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap();
        assert_eq!(phases.first(), Some(&ObservationPhase::PreSpawn));
        assert!(
            phases
                .iter()
                .skip(1)
                .all(|phase| *phase == ObservationPhase::Running)
        );
        assert!(phases.contains(&ObservationPhase::Running));
        assert_eq!(
            result.termination_reason,
            TerminationReason::ObservationFailure
        );
        assert!(result.drained && result.output_complete);
        run.cleanup(result.drained);
    }
    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn resource_limits_are_configured_before_the_owned_command_executes() {
        let run = TestRun::new("resource_probe");
        let result = supervise(&run.spec, &AtomicBool::new(false), || Ok(())).unwrap();
        assert_eq!(result.resource_policy, ResourcePolicy::current());
        assert_eq!(result.termination_reason, TerminationReason::Completed);
        assert!(result.drained && result.output_complete && result.supervisor_errors.is_empty());
        let evidence = serde_json::to_value(result.resource_limits.as_ref().unwrap()).unwrap();
        assert_eq!(evidence["kernel_resident_quota"], false);
        assert!(evidence["sample_count"].as_u64().unwrap() > 0);
        assert!(evidence["peak_observed_processes"].as_u64().unwrap() > 0);
        #[cfg(windows)]
        {
            assert_eq!(evidence["policy"], "managed-windows-job-resources/1");
            assert_eq!(
                evidence["readback_job_committed_limit_bytes"],
                resource_policy::MEMORY_LIMIT
            );
            assert_eq!(
                evidence["readback_active_process_limit"],
                resource_policy::PROCESS_LIMIT
            );
            assert!(
                evidence["peak_observed_job_committed_bytes"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
        }
        #[cfg(target_os = "linux")]
        {
            assert_eq!(evidence["policy"], "managed-linux-process-resources/1");
            assert_eq!(
                evidence["rlimit_as_readback_soft_bytes"],
                resource_policy::MEMORY_LIMIT
            );
            assert_eq!(
                evidence["rlimit_as_readback_hard_bytes"],
                resource_policy::MEMORY_LIMIT
            );
            assert_eq!(evidence["aggregate_memory_quota"], false);
            assert_eq!(evidence["kernel_process_quota"], false);
        }
        run.cleanup(result.drained);
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated Linux JVM policy proof; requires an outer JVM-purpose scope with its original address-space hard limit"]
    fn linux_jvm_vm_reservation_is_observed_separately_from_resident_memory() {
        let mut run = TestRun::new("jvm_resource_probe");
        run.spec.resource_policy = ResourcePolicy::for_managed_purpose("jvm");
        let result = supervise(&run.spec, &AtomicBool::new(false), || Ok(())).unwrap();
        assert_eq!(result.resource_policy, ResourcePolicy::LinuxJvmObserved);
        assert_eq!(result.termination_reason, TerminationReason::Completed);
        assert!(result.drained && result.output_complete && result.supervisor_errors.is_empty());
        let evidence = serde_json::to_value(result.resource_limits.as_ref().unwrap()).unwrap();
        assert_eq!(
            evidence["rlimit_as_readback_soft_bytes"],
            resource_policy::JVM_VM_LIMIT
        );
        assert_eq!(
            evidence["rlimit_as_readback_hard_bytes"],
            resource_policy::JVM_VM_LIMIT
        );
        assert!(evidence["sample_count"].as_u64().unwrap() > 0);
        assert!(
            evidence["peak_observed_aggregate_rss_bytes"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert!(
            evidence["peak_observed_aggregate_rss_bytes"]
                .as_u64()
                .unwrap()
                <= resource_policy::MEMORY_LIMIT
        );
        assert!(
            evidence["peak_observed_per_process_vm_bytes"]
                .as_u64()
                .unwrap()
                >= 8 * 1024 * 1024 * 1024
        );
        assert_eq!(evidence["kernel_resident_quota"], false);
        assert_eq!(evidence["group_snapshot_atomic"], false);
        run.cleanup(result.drained);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated finite native process-count quota proof; root runs separately"]
    fn linux_more_than_32_owned_live_processes_fail_and_drain() {
        let run = TestRun::new("many_owned");
        let result = supervise(&run.spec, &AtomicBool::new(false), || Ok(())).unwrap();
        assert_eq!(result.termination_reason, TerminationReason::ResourceBudget);
        assert!(result.drained);
        assert!(
            result
                .supervisor_errors
                .iter()
                .any(|error| error.contains("resource_budget"))
        );
        run.cleanup(result.drained);
    }
    #[cfg(windows)]
    #[test]
    fn windows_cwd_transport_preserves_physical_identity() {
        use std::os::windows::ffi::OsStringExt;
        let run = TestRun::new("normal");
        let authoritative = fs::canonicalize(&run.spec.cwd).unwrap();
        let transport = native::current_directory(&authoritative).unwrap();
        let path = PathBuf::from(OsString::from_wide(&transport[..transport.len() - 1]));
        assert!(!path.to_string_lossy().starts_with(r"\\?\"));
        assert_eq!(fs::canonicalize(&path).unwrap(), authoritative);
        run.cleanup(true);
    }
    #[cfg(windows)]
    #[test]
    fn windows_cwd_transport_rejects_network_and_device_before_lookup() {
        for path in [
            r"\\server\share\mmmm",
            r"\\?\UNC\server\share\mmmm",
            r"\\.\C:\mmmm",
        ] {
            let error = native::current_directory(Path::new(path)).unwrap_err();
            assert_eq!(error.kind, "path_transport");
        }
    }
}

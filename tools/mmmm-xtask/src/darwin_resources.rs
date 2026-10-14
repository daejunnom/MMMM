//! Darwin cooperative resource observations, separate from native drain proof.
//! Adjusted VM, RSS and physical footprint are distinct measured quantities.
//! The shared native-process crate owns the public libproc memory ABI only.
use super::ProcessError;
use mmmm_native_process::darwin::{
    NativeResourceError, NativeResourceFailure, NativeResourceStage,
};
use serde::Serialize;
use std::{
    fmt,
    time::{Duration, Instant},
};

pub(super) const VM_LIMIT: u64 = 512 * 1024 * 1024 * 1024;
const MEMORY_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
const WORKER_LIMIT: usize = 32;
const TARGET: Duration = Duration::from_millis(100);
const MAX_GAP: Duration = Duration::from_secs(1);
// Darwin errno.h; pure classification tests also run on non-Unix targets.
const DARWIN_ESRCH: i32 = 3;
// Apple XNU xnu-11417.140.69 bsd/sys/proc_info.h, pbi_flags.
// PROC_FLAG_INEXIT = 4 means the process is working its way through exit().
const PROC_FLAG_INEXIT: u32 = 4;
pub(super) const SZOMB: u32 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LeaderIdentity {
    pub(super) pid: u32,
    pub(super) uid: u32,
    pub(super) pgid: u32,
    pub(super) start_sec: u64,
    pub(super) start_usec: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LeaderBsd {
    pub(super) identity: LeaderIdentity,
    pub(super) status: u32,
    pub(super) flags: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum LeaderPhase {
    BeforeMemory,
    AfterMemory,
    GroupIdentity,
    MemoryResult,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LeaderSession {
    NotObserved,
    Expected,
    Mismatch,
    NativeFailure(i32),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SessionKind {
    NotObserved,
    Expected,
    Mismatch,
    NativeFailure,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct NativeMemoryDiagnostic {
    stage: &'static str,
    failure: &'static str,
    native_result: i32,
    native_errno: i32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MemoryRole {
    ReservedLeader,
    ObservedMember,
}
impl From<NativeResourceError> for NativeMemoryDiagnostic {
    fn from(error: NativeResourceError) -> Self {
        Self {
            stage: error.stage.as_str(),
            failure: error.failure.as_str(),
            native_result: error.native_result,
            native_errno: error.native_errno,
        }
    }
}
/// Closed facts only: no PID, UID, birth timestamp, path or process label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(super) struct LeaderDiagnostic {
    phase: LeaderPhase,
    session_kind: SessionKind,
    native_errno: Option<i32>,
    before_status: Option<u32>,
    after_status: Option<u32>,
    before_inexit: bool,
    after_inexit: bool,
    before_anchor_match: bool,
    after_anchor_match: bool,
    memory_error: Option<NativeMemoryDiagnostic>,
    memory_role: Option<MemoryRole>,
}
impl LeaderDiagnostic {
    pub(super) fn observe(
        anchor: LeaderIdentity,
        before: Option<LeaderBsd>,
        after: Option<LeaderBsd>,
        phase: LeaderPhase,
        session: LeaderSession,
    ) -> Self {
        let (session_kind, native_errno) = match session {
            LeaderSession::NotObserved => (SessionKind::NotObserved, None),
            LeaderSession::Expected => (SessionKind::Expected, None),
            LeaderSession::Mismatch => (SessionKind::Mismatch, None),
            LeaderSession::NativeFailure(number) => (SessionKind::NativeFailure, Some(number)),
        };
        Self {
            phase,
            session_kind,
            native_errno,
            before_status: before.map(|info| info.status),
            after_status: after.map(|info| info.status),
            before_inexit: before.is_some_and(|info| info.flags & PROC_FLAG_INEXIT != 0),
            after_inexit: after.is_some_and(|info| info.flags & PROC_FLAG_INEXIT != 0),
            before_anchor_match: before.is_some_and(|info| info.identity == anchor),
            after_anchor_match: after.is_some_and(|info| info.identity == anchor),
            memory_error: None,
            memory_role: None,
        }
    }
    pub(super) fn with_memory_error(mut self, error: NativeResourceError, reserved: bool) -> Self {
        self.memory_error = Some(error.into());
        self.memory_role = Some(if reserved {
            MemoryRole::ReservedLeader
        } else {
            MemoryRole::ObservedMember
        });
        self
    }
    pub(super) fn attach(self, mut error: ProcessError) -> ProcessError {
        error.message.push_str(&format!("; {self}"));
        error
    }
}
impl fmt::Display for LeaderDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "darwin_leader phase={:?},session_kind={:?},native_errno={:?},before_status={:?},after_status={:?},before_inexit={},after_inexit={},before_anchor_match={},after_anchor_match={}",
            self.phase,
            self.session_kind,
            self.native_errno,
            self.before_status,
            self.after_status,
            self.before_inexit,
            self.after_inexit,
            self.before_anchor_match,
            self.after_anchor_match
        )?;
        if let Some(error) = self.memory_error {
            write!(
                f,
                ",memory_stage={},memory_failure={},memory_native_result={},memory_native_errno={},memory_role={:?}",
                error.stage,
                error.failure,
                error.native_result,
                error.native_errno,
                self.memory_role
            )?;
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LeaderObservation {
    Live,
    Zombie,
    Pending(LeaderDiagnostic),
}
#[derive(Clone, Copy, Debug)]
pub(super) enum MemoryObservation {
    #[cfg(target_os = "macos")]
    Measured(Memory),
    Zombie(LeaderDiagnostic),
    Pending(LeaderDiagnostic),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum GroupObservation {
    Complete(usize),
    Pending(Box<PendingObservations>),
}
impl GroupObservation {
    pub(super) fn scope_empty(&self) -> bool {
        matches!(self, Self::Complete(0))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResourceObservation {
    #[cfg(target_os = "macos")]
    NotDue,
    Complete,
    Pending,
}
fn same_reserved_identity(
    anchor: LeaderIdentity,
    before: Option<LeaderBsd>,
    after: Option<LeaderBsd>,
    reservation_valid: &mut bool,
) -> bool {
    if before.is_some_and(|info| info.identity != anchor)
        || after.is_some_and(|info| info.identity != anchor)
    {
        // A later matching observation cannot restore a lost reservation.
        *reservation_valid = false;
    }
    *reservation_valid
        && before.is_some_and(|info| info.identity == anchor)
        && after.is_some_and(|info| info.identity == anchor)
}
pub(super) fn verify_reserved_identity(
    anchor: LeaderIdentity,
    before: Option<LeaderBsd>,
    after: Option<LeaderBsd>,
    phase: LeaderPhase,
    reservation_valid: &mut bool,
) -> Result<(), ProcessError> {
    if same_reserved_identity(anchor, before, after, reservation_valid) {
        return Ok(());
    }
    Err(
        LeaderDiagnostic::observe(anchor, before, after, phase, LeaderSession::NotObserved).attach(
            ProcessError::new(
                "process_identity",
                "reserved macOS leader identity changed or unavailable",
            ),
        ),
    )
}
pub(super) fn classify_leader_session(
    anchor: LeaderIdentity,
    before: LeaderBsd,
    after: Option<LeaderBsd>,
    phase: LeaderPhase,
    session: LeaderSession,
    reservation_valid: &mut bool,
) -> Result<LeaderObservation, ProcessError> {
    let diagnostic = LeaderDiagnostic::observe(anchor, Some(before), after, phase, session);
    if !same_reserved_identity(anchor, Some(before), Some(before), reservation_valid) {
        return Err(diagnostic.attach(ProcessError::new(
            "process_identity",
            "reserved macOS leader identity changed",
        )));
    }
    if session == LeaderSession::Expected {
        return Ok(LeaderObservation::Live);
    }
    if session == LeaderSession::Mismatch {
        *reservation_valid = false;
    }
    if session == LeaderSession::NativeFailure(DARWIN_ESRCH)
        && same_reserved_identity(anchor, Some(before), after, reservation_valid)
    {
        let after = after.expect("same identity requires an observed BSD result");
        if after.status == SZOMB {
            return Ok(LeaderObservation::Zombie);
        }
        // proc_prepareexit sets P_REF_DEAD before proc_exit sets SZOMB.
        // Exact ESRCH plus this same reserved INEXIT process is incomplete;
        // it proves neither a live memory sample nor native zombie/drain.
        if before.status != SZOMB && after.flags & PROC_FLAG_INEXIT != 0 {
            return Ok(LeaderObservation::Pending(diagnostic));
        }
    }
    Err(diagnostic.attach(ProcessError::new(
        "process_identity",
        "reserved macOS leader session unavailable or changed without native zombie proof",
    )))
}

/// The original typed native error remains a diagnostic input. A reserved
/// leader retains its existing exit-class INEXIT policy. An observed member
/// may only leave the whole sample incomplete for the actually observed
/// TaskInfo 0/ESRCH transition, with the same identity and INEXIT on both sides.
pub(super) fn classify_memory_exit(
    reserved: Option<(LeaderIdentity, &mut bool)>,
    before: LeaderBsd,
    after: Option<LeaderBsd>,
    native: NativeResourceError,
) -> Result<MemoryObservation, ProcessError> {
    let anchor = reserved
        .as_ref()
        .map(|(anchor, _)| *anchor)
        .unwrap_or(before.identity);
    let reserved_leader = reserved.is_some();
    let diagnostic = LeaderDiagnostic::observe(
        anchor,
        Some(before),
        after,
        LeaderPhase::MemoryResult,
        LeaderSession::NotObserved,
    )
    .with_memory_error(native, reserved_leader);
    let same_identity = match reserved {
        Some((anchor, reservation_valid)) => {
            same_reserved_identity(anchor, Some(before), after, reservation_valid)
        }
        None => after.is_some_and(|after| after.identity == before.identity),
    };
    if native.failure != NativeResourceFailure::Exited
        || !matches!(
            native.stage,
            NativeResourceStage::TaskInfo | NativeResourceStage::Rusage
        )
    {
        return Err(diagnostic.attach(native_error(native)));
    }
    if same_identity {
        let after = after.expect("same identity requires an actual BSD observation");
        if after.status == SZOMB {
            return Ok(MemoryObservation::Zombie(diagnostic));
        }
        let observed_member_task_exit = !reserved_leader
            && native.stage == NativeResourceStage::TaskInfo
            && native.native_result == 0
            && native.native_errno == DARWIN_ESRCH
            && before.flags & PROC_FLAG_INEXIT != 0;
        if (reserved_leader || observed_member_task_exit)
            && before.status != SZOMB
            && after.flags & PROC_FLAG_INEXIT != 0
        {
            return Ok(MemoryObservation::Pending(diagnostic));
        }
    }
    Err(diagnostic.attach(ProcessError::new(
        "resource_observation",
        "Darwin resource process exit not confirmed by native zombie identity",
    )))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(super) struct ExitObservationEvidence {
    observations: u64,
    first: LeaderDiagnostic,
    last: LeaderDiagnostic,
}

/// One scan retains each role independently. The bounded last context is only
/// an error suffix; it cannot replace either role's first/last/count evidence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct PendingObservations {
    leader: Option<ExitObservationEvidence>,
    member: Option<ExitObservationEvidence>,
    last: Option<LeaderDiagnostic>,
}
impl PendingObservations {
    pub(super) fn record(&mut self, diagnostic: LeaderDiagnostic) {
        let role = if diagnostic.memory_role == Some(MemoryRole::ObservedMember) {
            &mut self.member
        } else {
            &mut self.leader
        };
        ExitObservationEvidence::record(role, diagnostic);
        self.last = Some(diagnostic);
    }
    pub(super) fn last(&self) -> Option<LeaderDiagnostic> {
        self.last
    }
}
impl From<LeaderDiagnostic> for PendingObservations {
    fn from(diagnostic: LeaderDiagnostic) -> Self {
        let mut observations = Self::default();
        observations.record(diagnostic);
        observations
    }
}
impl ExitObservationEvidence {
    pub(super) fn record(slot: &mut Option<Self>, diagnostic: LeaderDiagnostic) {
        match slot {
            Some(evidence) => {
                evidence.observations = evidence.observations.saturating_add(1);
                evidence.last = diagnostic;
            }
            None => {
                *slot = Some(Self {
                    observations: 1,
                    first: diagnostic,
                    last: diagnostic,
                })
            }
        }
    }
    fn merge(slot: &mut Option<Self>, current: Self) {
        match slot {
            Some(evidence) => {
                evidence.observations = evidence.observations.saturating_add(current.observations);
                evidence.last = current.last;
            }
            None => *slot = Some(current),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    policy: &'static str,
    configured_rlimit_as_bytes: u64,
    rlimit_as_readback_bytes: Option<u64>,
    adjusted_vm_per_pid_limit_bytes: u64,
    aggregate_rss_limit_bytes: u64,
    aggregate_footprint_limit_bytes: u64,
    worker_limit: usize,
    wrapper_limit: usize,
    wrapper_in_memory_sum: bool,
    sample_target_ms: u64,
    max_successful_sample_gap_ms: u64,
    taskinfo_flavor: i32,
    rusage_flavor: i32,
    sample_count: u64,
    peak_observed_adjusted_vm_bytes: u64,
    peak_observed_aggregate_rss_bytes: u64,
    peak_observed_aggregate_footprint_bytes: u64,
    peak_observed_workers: usize,
    max_observed_sample_gap_ms: u64,
    preflight_self_adjusted_vm_bytes: u64,
    preflight_self_rss_bytes: u64,
    preflight_self_footprint_bytes: u64,
    sampling_may_overshoot: bool,
    kernel_resident_quota: bool,
    pending_leader_exit: Option<ExitObservationEvidence>,
    pending_member_exit: Option<ExitObservationEvidence>,
    native_memory_exits: Option<ExitObservationEvidence>,
}

pub(super) struct Tracker {
    pub(super) evidence: Evidence,
    last_success: Instant,
    last_attempt: Option<Instant>,
}
impl Tracker {
    pub(super) fn new(preflight: Memory) -> Result<Self, ProcessError> {
        let mut sample = Sample::default();
        sample.push(preflight)?;
        sample.check()?;
        Ok(Self {
            last_success: Instant::now(),
            last_attempt: None,
            evidence: Evidence {
                policy: "managed-darwin-resources/1",
                configured_rlimit_as_bytes: VM_LIMIT,
                rlimit_as_readback_bytes: None,
                adjusted_vm_per_pid_limit_bytes: VM_LIMIT,
                aggregate_rss_limit_bytes: MEMORY_LIMIT,
                aggregate_footprint_limit_bytes: MEMORY_LIMIT,
                worker_limit: WORKER_LIMIT,
                wrapper_limit: 0,
                wrapper_in_memory_sum: false,
                sample_target_ms: 100,
                max_successful_sample_gap_ms: 1000,
                taskinfo_flavor: 4,
                rusage_flavor: 0,
                sample_count: 0,
                peak_observed_adjusted_vm_bytes: 0,
                peak_observed_aggregate_rss_bytes: 0,
                peak_observed_aggregate_footprint_bytes: 0,
                peak_observed_workers: 0,
                max_observed_sample_gap_ms: 0,
                preflight_self_adjusted_vm_bytes: preflight.adjusted_vm,
                preflight_self_rss_bytes: preflight.rss,
                preflight_self_footprint_bytes: preflight.footprint,
                sampling_may_overshoot: true,
                kernel_resident_quota: false,
                pending_leader_exit: None,
                pending_member_exit: None,
                native_memory_exits: None,
            },
        })
    }
    pub(super) fn configured(&mut self) {
        // Command::spawn returns only after the child's pre_exec hook succeeded.
        // This proves the BSD readback, not map enforcement across later execs.
        self.evidence.rlimit_as_readback_bytes = Some(VM_LIMIT);
    }
    fn gap(&mut self, now: Instant) -> Result<(), ProcessError> {
        let gap = now.duration_since(self.last_success);
        self.evidence.max_observed_sample_gap_ms = self
            .evidence
            .max_observed_sample_gap_ms
            .max(u64::try_from(gap.as_millis()).unwrap_or(u64::MAX));
        if gap > MAX_GAP {
            return Err(ProcessError::new(
                "resource_observation",
                "Darwin successful resource sample gap exceeded 1000ms",
            ));
        }
        Ok(())
    }
    pub(super) fn begin(&mut self) -> Result<Option<Instant>, ProcessError> {
        self.begin_at(Instant::now())
    }
    fn begin_at(&mut self, now: Instant) -> Result<Option<Instant>, ProcessError> {
        self.gap(now)?;
        let due = match self.last_attempt {
            Some(attempt) => now.duration_since(attempt.max(self.last_success)) >= TARGET,
            None => {
                self.evidence.sample_count == 0 || now.duration_since(self.last_success) >= TARGET
            }
        };
        if due {
            // Attempt cadence does not refresh successful observation age.
            // Pending returns to the existing loop instead of reobserving at
            // every capture checkpoint inside the same 100ms sample window.
            self.last_attempt = Some(now);
        }
        Ok(due.then_some(now))
    }
    pub(super) fn finish(&mut self, sample: Sample) -> Result<(), ProcessError> {
        let finished = Instant::now();
        self.evidence.sample_count += 1;
        self.evidence.peak_observed_adjusted_vm_bytes = self
            .evidence
            .peak_observed_adjusted_vm_bytes
            .max(sample.adjusted_vm_peak);
        self.evidence.peak_observed_aggregate_rss_bytes = self
            .evidence
            .peak_observed_aggregate_rss_bytes
            .max(sample.rss);
        self.evidence.peak_observed_aggregate_footprint_bytes = self
            .evidence
            .peak_observed_aggregate_footprint_bytes
            .max(sample.footprint);
        self.evidence.peak_observed_workers =
            self.evidence.peak_observed_workers.max(sample.workers);
        // Preserve a complete observed sample even when its freshness fails.
        self.gap(finished)?;
        self.last_success = finished;
        sample.check()
    }
    pub(super) fn finish_observation(
        &mut self,
        observation: GroupObservation,
        sample: Sample,
    ) -> Result<ResourceObservation, ProcessError> {
        match observation {
            GroupObservation::Complete(_) => {
                self.finish(sample)?;
                Ok(ResourceObservation::Complete)
            }
            GroupObservation::Pending(observations) => {
                self.record_pending_observations(*observations);
                // Other observed members still provide a lower bound: a known
                // over-budget partial sample remains fatal. No partial sample
                // increments success/count/peaks or replaces the missing PID
                // with zero. The original successful-sample gap keeps running.
                sample.check()?;
                self.gap(Instant::now())?;
                Ok(ResourceObservation::Pending)
            }
        }
    }
    pub(super) fn record_pending_observations(&mut self, observations: PendingObservations) {
        if let Some(leader) = observations.leader {
            ExitObservationEvidence::merge(&mut self.evidence.pending_leader_exit, leader);
        }
        if let Some(member) = observations.member {
            ExitObservationEvidence::merge(&mut self.evidence.pending_member_exit, member);
        }
    }
    pub(super) fn record_memory_exits(&mut self, observations: Option<ExitObservationEvidence>) {
        if let Some(observations) = observations {
            ExitObservationEvidence::merge(&mut self.evidence.native_memory_exits, observations);
        }
    }
    pub(super) fn with_pending_diagnostics(&self, mut error: ProcessError) -> ProcessError {
        if let Some(evidence) = self.evidence.pending_leader_exit {
            error.message.push_str(&format!(
                "; first_pending=[{}]; final_pending=[{}]",
                evidence.first, evidence.last
            ));
        }
        if let Some(evidence) = self.evidence.pending_member_exit {
            error.message.push_str(&format!(
                "; first_member_pending=[{}]; final_member_pending=[{}]",
                evidence.first, evidence.last
            ));
        }
        if let Some(evidence) = self.evidence.native_memory_exits {
            error.message.push_str(&format!(
                "; first_memory_exit=[{}]; final_memory_exit=[{}]",
                evidence.first, evidence.last
            ));
        }
        error
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Memory {
    pub(super) adjusted_vm: u64,
    pub(super) rss: u64,
    pub(super) footprint: u64,
}
#[derive(Default)]
pub(super) struct Sample {
    adjusted_vm_peak: u64,
    rss: u64,
    footprint: u64,
    workers: usize,
}
impl Sample {
    pub(super) fn push(&mut self, memory: Memory) -> Result<(), ProcessError> {
        self.adjusted_vm_peak = self.adjusted_vm_peak.max(memory.adjusted_vm);
        self.rss = self.rss.checked_add(memory.rss).ok_or_else(sum_overflow)?;
        self.footprint = self
            .footprint
            .checked_add(memory.footprint)
            .ok_or_else(sum_overflow)?;
        self.workers = self.workers.checked_add(1).ok_or_else(sum_overflow)?;
        Ok(())
    }
    fn check(&self) -> Result<(), ProcessError> {
        if self.adjusted_vm_peak > VM_LIMIT
            || self.rss > MEMORY_LIMIT
            || self.footprint > MEMORY_LIMIT
            || self.workers > WORKER_LIMIT
        {
            return Err(ProcessError::new(
                "resource_budget",
                format!(
                    "Darwin resource budget exceeded; adjusted_vm={}; aggregate_rss={}; aggregate_footprint={}; workers={}",
                    self.adjusted_vm_peak, self.rss, self.footprint, self.workers,
                ),
            ));
        }
        Ok(())
    }
}
fn sum_overflow() -> ProcessError {
    ProcessError::new(
        "resource_observation",
        "Darwin native resource sum overflow",
    )
}

#[cfg(test)]
fn task_result(bytes: i32, number: i32) -> Result<(), ProcessError> {
    mmmm_native_process::darwin::classify_task_result(bytes, number).map_err(native_error)
}
#[cfg(test)]
fn rusage_result(result: i32, number: i32, start: u64, exit: u64) -> Result<(), ProcessError> {
    mmmm_native_process::darwin::classify_rusage_result(result, number, start, exit)
        .map_err(native_error)
}

pub(super) fn native_error(error: NativeResourceError) -> ProcessError {
    // ESRCH and an observed exit timestamp remain exit-class failures. Only
    // process.rs may independently confirm the unchanged native zombie.
    let kind = if error.failure == NativeResourceFailure::Exited {
        "resource_process_exit"
    } else {
        "resource_observation"
    };
    ProcessError::new(kind, error.to_string())
}

#[cfg(target_os = "macos")]
pub(super) fn memory(pid: i32) -> Result<Memory, NativeResourceError> {
    let actual = mmmm_native_process::darwin::observe_memory(pid)?;
    // tools retains its existing before/after BSD birth/UID/group sandwich.
    // The shared observation additionally returns rusage start identity for
    // consumers that keep it fixed throughout a single worker lifecycle.
    Ok(Memory {
        adjusted_vm: actual.adjusted_vm,
        rss: actual.rss,
        footprint: actual.footprint,
    })
}

/// Only async-signal-safe libc calls; no libproc, formatting or allocation.
#[cfg(target_os = "macos")]
pub(super) fn configure_before_exec() -> std::io::Result<()> {
    let configured = libc::rlimit {
        rlim_cur: VM_LIMIT,
        rlim_max: VM_LIMIT,
    };
    let mut readback = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_AS, &configured) } == -1
        || unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut readback) } == -1
    {
        return Err(std::io::Error::last_os_error());
    }
    if readback.rlim_cur != VM_LIMIT || readback.rlim_max != VM_LIMIT {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn small() -> Memory {
        Memory {
            adjusted_vm: 400 * 1024 * 1024 * 1024,
            rss: 16,
            footprint: 8,
        }
    }
    fn reserved_leader() -> LeaderBsd {
        LeaderBsd {
            identity: LeaderIdentity {
                pid: 17,
                uid: 501,
                pgid: 17,
                start_sec: 123456789,
                start_usec: 321,
            },
            status: 2,
            flags: 0,
        }
    }
    fn pending_diagnostic(phase: LeaderPhase) -> LeaderDiagnostic {
        let before = reserved_leader();
        let after = LeaderBsd {
            flags: PROC_FLAG_INEXIT,
            ..before
        };
        let mut reservation = true;
        let LeaderObservation::Pending(diagnostic) = classify_leader_session(
            before.identity,
            before,
            Some(after),
            phase,
            LeaderSession::NativeFailure(DARWIN_ESRCH),
            &mut reservation,
        )
        .unwrap() else {
            panic!("same reserved INEXIT leader was not classified as pending")
        };
        assert!(reservation);
        diagnostic
    }
    fn native_exit_results() -> [NativeResourceError; 3] {
        use mmmm_native_process::darwin::{classify_rusage_result, classify_task_result};
        [
            classify_task_result(0, DARWIN_ESRCH).unwrap_err(),
            classify_rusage_result(-1, DARWIN_ESRCH, 0, 0).unwrap_err(),
            classify_rusage_result(0, 0, 11, 12).unwrap_err(),
        ]
    }
    fn observed_member_pending_diagnostic() -> LeaderDiagnostic {
        let before = LeaderBsd {
            flags: PROC_FLAG_INEXIT,
            ..reserved_leader()
        };
        let MemoryObservation::Pending(diagnostic) =
            classify_memory_exit(None, before, Some(before), native_exit_results()[0]).unwrap()
        else {
            panic!("same-identity observed TaskInfo exit was not an incomplete sample")
        };
        diagnostic
    }
    #[test]
    fn observed_member_task_exit_preserves_an_incomplete_group_and_distinct_closed_facts() {
        let diagnostic = observed_member_pending_diagnostic();
        assert_eq!(diagnostic.memory_role, Some(MemoryRole::ObservedMember));
        assert_eq!(
            diagnostic.memory_error,
            Some(native_exit_results()[0].into())
        );
        assert!(diagnostic.before_inexit && diagnostic.after_inexit);
        assert!(diagnostic.before_anchor_match && diagnostic.after_anchor_match);
        let observation = GroupObservation::Pending(Box::new(diagnostic.into()));
        assert!(!observation.scope_empty());
        let mut tracker = Tracker::new(small()).unwrap();
        let mut initial = Sample::default();
        initial.push(small()).unwrap();
        tracker
            .finish_observation(GroupObservation::Complete(1), initial)
            .unwrap();
        let prior_success = tracker.last_success;
        let mut partial = Sample::default();
        partial
            .push(Memory {
                adjusted_vm: small().adjusted_vm + 1,
                rss: small().rss * 2,
                footprint: small().footprint * 2,
            })
            .unwrap();
        partial.push(small()).unwrap();
        let mut exits = None;
        ExitObservationEvidence::record(&mut exits, diagnostic);
        tracker.record_memory_exits(exits);
        assert_eq!(
            tracker.finish_observation(observation, partial).unwrap(),
            ResourceObservation::Pending
        );
        assert_eq!(tracker.evidence.sample_count, 1);
        assert_eq!(tracker.last_success, prior_success);
        assert_eq!(
            tracker.evidence.peak_observed_aggregate_rss_bytes,
            small().rss
        );
        assert_eq!(
            tracker.evidence.peak_observed_adjusted_vm_bytes,
            small().adjusted_vm
        );
        assert_eq!(
            tracker.evidence.peak_observed_aggregate_footprint_bytes,
            small().footprint
        );
        assert_eq!(tracker.evidence.peak_observed_workers, 1);
        assert!(tracker.evidence.pending_leader_exit.is_none());
        let pending = tracker.evidence.pending_member_exit.unwrap();
        assert_eq!(pending.observations, 1);
        assert_eq!(pending.first, diagnostic);
        assert_eq!(pending.last, diagnostic);
        let evidence = serde_json::to_value(&tracker.evidence).unwrap();
        assert_eq!(
            evidence["pending_member_exit"]["first"]["memory_role"],
            "observed_member"
        );
        assert_eq!(
            evidence["native_memory_exits"]["last"]["memory_error"]["stage"],
            "task_info"
        );
        let mut original = ProcessError::new("command_timeout", "original deadline failure");
        original.drained = false;
        let error = tracker.with_pending_diagnostics(original);
        assert_eq!(error.kind, "command_timeout");
        assert!(!error.drained);
        assert!(
            error
                .message
                .starts_with("original deadline failure; first_member_pending=[")
        );
        assert!(error.message.contains("memory_role=Some(ObservedMember)"));

        let before = LeaderBsd {
            flags: PROC_FLAG_INEXIT,
            ..reserved_leader()
        };
        let MemoryObservation::Pending(second_member) = classify_memory_exit(
            None,
            before,
            Some(LeaderBsd {
                status: 3,
                ..before
            }),
            native_exit_results()[0],
        )
        .unwrap() else {
            panic!("second same-identity member observation was not incomplete")
        };
        assert_ne!(diagnostic, second_member);
        let leader = pending_diagnostic(LeaderPhase::AfterMemory);
        for (events, member_count, member_last, has_leader) in [
            (vec![diagnostic, second_member], 2, second_member, false),
            (vec![diagnostic, leader], 1, diagnostic, true),
            (
                vec![diagnostic, second_member, leader],
                2,
                second_member,
                true,
            ),
        ] {
            let mut scan = PendingObservations::default();
            for event in &events {
                scan.record(*event);
            }
            assert_eq!(scan.last(), events.last().copied());
            let observation = GroupObservation::Pending(Box::new(scan));
            assert!(!observation.scope_empty());
            let mut complete_scan = Tracker::new(small()).unwrap();
            let prior_success = complete_scan.last_success;
            assert_eq!(
                complete_scan
                    .finish_observation(observation, Sample::default())
                    .unwrap(),
                ResourceObservation::Pending
            );
            assert_eq!(complete_scan.evidence.sample_count, 0);
            assert_eq!(complete_scan.last_success, prior_success);
            assert_eq!(complete_scan.evidence.peak_observed_aggregate_rss_bytes, 0);
            assert!(complete_scan.evidence.native_memory_exits.is_none());
            let member = complete_scan.evidence.pending_member_exit.unwrap();
            assert_eq!(member.observations, member_count);
            assert_eq!(member.first, diagnostic);
            assert_eq!(member.last, member_last);
            if has_leader {
                let actual_leader = complete_scan.evidence.pending_leader_exit.unwrap();
                assert_eq!(actual_leader.observations, 1);
                assert_eq!(actual_leader.first, leader);
                assert_eq!(actual_leader.last, leader);
            } else {
                assert!(complete_scan.evidence.pending_leader_exit.is_none());
            }
            let mut failed_scan = Tracker::new(small()).unwrap();
            let prior_success = failed_scan.last_success;
            // A later native/identity failure still retains the scan's already
            // observed role facts without making a successful resource sample.
            failed_scan.record_pending_observations(scan);
            assert_eq!(
                failed_scan.evidence.pending_member_exit,
                complete_scan.evidence.pending_member_exit
            );
            assert_eq!(
                failed_scan.evidence.pending_leader_exit,
                complete_scan.evidence.pending_leader_exit
            );
            assert_eq!(failed_scan.evidence.sample_count, 0);
            assert_eq!(failed_scan.last_success, prior_success);
            let mut original =
                ProcessError::new("process_identity", "later original identity failure");
            original.drained = false;
            let retained = failed_scan.with_pending_diagnostics(original);
            assert_eq!(retained.kind, "process_identity");
            assert!(
                retained
                    .message
                    .starts_with("later original identity failure;")
            );
            assert!(!retained.drained);
            assert!(retained.message.contains("first_member_pending=["));
            assert_eq!(retained.message.contains("first_pending=["), has_leader);
        }
    }
    #[test]
    fn observed_member_pending_does_not_extend_to_other_native_results_or_incomplete_identity() {
        use mmmm_native_process::darwin::classify_task_result;
        let before = LeaderBsd {
            flags: PROC_FLAG_INEXIT,
            ..reserved_leader()
        };
        let native = native_exit_results()[0];
        for other in [
            native_exit_results()[1],
            native_exit_results()[2],
            classify_task_result(95, DARWIN_ESRCH).unwrap_err(),
            classify_task_result(0, 1).unwrap_err(),
            NativeResourceError {
                native_result: -1,
                ..native
            },
            NativeResourceError {
                native_errno: 1,
                ..native
            },
            NativeResourceError {
                stage: NativeResourceStage::ProcessIdentifier,
                ..native
            },
        ] {
            let error = classify_memory_exit(None, before, Some(before), other).unwrap_err();
            assert!(error.message.contains("memory_role=Some(ObservedMember)"));
            assert!(
                error
                    .message
                    .contains(&format!("memory_stage={}", other.stage.as_str()))
            );
            assert!(
                error
                    .message
                    .contains(&format!("memory_native_result={}", other.native_result))
            );
            assert!(
                error
                    .message
                    .contains(&format!("memory_native_errno={}", other.native_errno))
            );
        }
        for (first, after) in [
            (before, None),
            (LeaderBsd { flags: 0, ..before }, Some(before)),
            (before, Some(LeaderBsd { flags: 0, ..before })),
            (
                LeaderBsd {
                    status: SZOMB,
                    ..before
                },
                Some(before),
            ),
        ] {
            assert!(classify_memory_exit(None, first, after, native).is_err());
        }
        for identity in [
            LeaderIdentity {
                pid: 18,
                ..before.identity
            },
            LeaderIdentity {
                uid: 502,
                ..before.identity
            },
            LeaderIdentity {
                pgid: 18,
                ..before.identity
            },
            LeaderIdentity {
                start_sec: 123456790,
                ..before.identity
            },
            LeaderIdentity {
                start_usec: 322,
                ..before.identity
            },
        ] {
            let error =
                classify_memory_exit(None, before, Some(LeaderBsd { identity, ..before }), native)
                    .unwrap_err();
            assert!(error.message.contains("after_anchor_match=false"));
            assert!(error.message.contains("memory_role=Some(ObservedMember)"));
        }
    }
    #[test]
    fn typed_memory_exit_defers_only_the_original_reserved_inexit_leader_without_a_sample() {
        let before = reserved_leader();
        let after = LeaderBsd {
            flags: PROC_FLAG_INEXIT,
            ..before
        };
        for native in native_exit_results() {
            let mut reservation = true;
            let MemoryObservation::Pending(diagnostic) = classify_memory_exit(
                Some((before.identity, &mut reservation)),
                before,
                Some(after),
                native,
            )
            .unwrap() else {
                panic!("typed exit of the same reserved INEXIT leader was not pending")
            };
            assert!(reservation);
            assert_eq!(diagnostic.phase, LeaderPhase::MemoryResult);
            assert_eq!(diagnostic.memory_error, Some(native.into()));
            assert_eq!(diagnostic.after_status, Some(before.status));
            assert!(
                diagnostic.after_inexit
                    && diagnostic.before_anchor_match
                    && diagnostic.after_anchor_match
            );
            let mut tracker = Tracker::new(small()).unwrap();
            let prior_success = tracker.last_success;
            let mut exits = None;
            ExitObservationEvidence::record(&mut exits, diagnostic);
            tracker.record_memory_exits(exits);
            let observation = GroupObservation::Pending(Box::new(diagnostic.into()));
            assert!(!observation.scope_empty());
            assert_eq!(
                tracker
                    .finish_observation(observation, Sample::default())
                    .unwrap(),
                ResourceObservation::Pending
            );
            assert_eq!(tracker.evidence.sample_count, 0);
            assert_eq!(tracker.last_success, prior_success);
            let evidence = serde_json::to_value(&tracker.evidence).unwrap();
            assert_eq!(
                evidence["native_memory_exits"]["first"]["memory_error"]["stage"],
                native.stage.as_str()
            );
            assert_eq!(
                evidence["native_memory_exits"]["first"]["memory_role"],
                "reserved_leader"
            );
            assert_eq!(
                evidence["native_memory_exits"]["last"]["memory_error"]["native_result"],
                native.native_result
            );
            assert_eq!(
                evidence["pending_leader_exit"]["last"]["memory_error"]["native_errno"],
                native.native_errno
            );
        }
    }
    #[test]
    fn confirmed_memory_zombies_preserve_original_native_and_bsd_facts_for_leaders_and_members() {
        let before = reserved_leader();
        let zombie = LeaderBsd {
            status: SZOMB,
            flags: PROC_FLAG_INEXIT,
            ..before
        };
        let mut tracker = Tracker::new(small()).unwrap();
        for reserved in [false, true] {
            for native in native_exit_results() {
                let mut reservation = true;
                let authority = if reserved {
                    Some((before.identity, &mut reservation))
                } else {
                    None
                };
                let MemoryObservation::Zombie(diagnostic) =
                    classify_memory_exit(authority, before, Some(zombie), native).unwrap()
                else {
                    panic!("same-identity native zombie was not confirmed")
                };
                assert!(reservation);
                assert_eq!(diagnostic.memory_error, Some(native.into()));
                assert_eq!(
                    diagnostic.memory_role,
                    Some(if reserved {
                        MemoryRole::ReservedLeader
                    } else {
                        MemoryRole::ObservedMember
                    })
                );
                assert_eq!(diagnostic.after_status, Some(SZOMB));
                let mut exits = None;
                ExitObservationEvidence::record(&mut exits, diagnostic);
                tracker.record_memory_exits(exits);
            }
        }
        assert_eq!(tracker.evidence.sample_count, 0);
        let evidence = tracker.evidence.native_memory_exits.unwrap();
        assert_eq!(evidence.observations, 6);
        assert_eq!(evidence.first.memory_error.unwrap().stage, "task_info");
        assert_eq!(evidence.last.memory_error.unwrap().stage, "rusage");
        let original = ProcessError::new("io", "later BSD observation failed");
        let original = tracker.with_pending_diagnostics(original);
        assert_eq!(original.kind, "io");
        assert!(
            original
                .message
                .starts_with("later BSD observation failed; first_memory_exit=[")
        );
        assert!(
            original
                .message
                .contains("memory_native_result=0,memory_native_errno=3")
        );
        assert!(
            original
                .message
                .contains("memory_native_result=0,memory_native_errno=0")
        );
    }
    #[test]
    fn malformed_and_permission_memory_errors_never_become_pending_or_confirmed_zombies() {
        use mmmm_native_process::darwin::{classify_rusage_result, classify_task_result};
        let before = reserved_leader();
        for native in [
            classify_task_result(95, DARWIN_ESRCH).unwrap_err(),
            classify_task_result(0, 1).unwrap_err(),
            classify_rusage_result(-1, 1, 0, 0).unwrap_err(),
            classify_rusage_result(0, 0, 0, 0).unwrap_err(),
        ] {
            for status in [before.status, SZOMB] {
                let mut reservation = true;
                let error = classify_memory_exit(
                    Some((before.identity, &mut reservation)),
                    before,
                    Some(LeaderBsd {
                        status,
                        flags: PROC_FLAG_INEXIT,
                        ..before
                    }),
                    native,
                )
                .unwrap_err();
                assert_eq!(error.kind, "resource_observation");
                assert!(reservation);
                assert!(
                    error
                        .message
                        .contains(&format!("memory_stage={}", native.stage.as_str()))
                );
                assert!(
                    error
                        .message
                        .contains(&format!("memory_failure={}", native.failure.as_str()))
                );
                assert!(
                    error
                        .message
                        .contains(&format!("memory_native_result={}", native.native_result))
                );
                assert!(
                    error
                        .message
                        .contains(&format!("memory_native_errno={}", native.native_errno))
                );
            }
        }
    }
    #[test]
    fn memory_pending_rejects_incomplete_proof_missing_identity_and_any_reserved_anchor_mismatch() {
        let before = reserved_leader();
        let inexit = LeaderBsd {
            flags: PROC_FLAG_INEXIT,
            ..before
        };
        for native in native_exit_results() {
            assert!(classify_memory_exit(None, before, Some(inexit), native).is_err());
            for after in [None, Some(before), Some(LeaderBsd { flags: 8, ..before })] {
                let mut reservation = true;
                let error = classify_memory_exit(
                    Some((before.identity, &mut reservation)),
                    before,
                    after,
                    native,
                )
                .unwrap_err();
                assert!(reservation);
                assert!(
                    error
                        .message
                        .contains("memory_failure=exit_requires_identity_confirmation")
                );
            }
            for identity in [
                LeaderIdentity {
                    pid: 18,
                    ..before.identity
                },
                LeaderIdentity {
                    uid: 502,
                    ..before.identity
                },
                LeaderIdentity {
                    pgid: 18,
                    ..before.identity
                },
                LeaderIdentity {
                    start_sec: 123456790,
                    ..before.identity
                },
                LeaderIdentity {
                    start_usec: 322,
                    ..before.identity
                },
            ] {
                let mut reservation = true;
                let error = classify_memory_exit(
                    Some((before.identity, &mut reservation)),
                    before,
                    Some(LeaderBsd { identity, ..inexit }),
                    native,
                )
                .unwrap_err();
                assert!(!reservation);
                assert!(error.message.contains("after_anchor_match=false"));
                assert!(error.message.contains("memory_stage="));
            }
            let mut reservation = false;
            assert!(
                classify_memory_exit(
                    Some((before.identity, &mut reservation)),
                    before,
                    Some(inexit),
                    native
                )
                .is_err()
            );
            assert!(!reservation);
            let mut reservation = true;
            let changed = LeaderBsd {
                identity: LeaderIdentity {
                    uid: 502,
                    ..before.identity
                },
                ..inexit
            };
            let error = classify_memory_exit(
                Some((before.identity, &mut reservation)),
                changed,
                Some(changed),
                native,
            )
            .unwrap_err();
            assert!(!reservation);
            assert!(error.message.contains("before_anchor_match=false"));
        }
    }
    #[test]
    fn pending_exit_requires_exact_reserved_identity_and_does_not_reopen_signal_authority() {
        let before = reserved_leader();
        let after = LeaderBsd {
            flags: PROC_FLAG_INEXIT,
            ..before
        };
        pending_diagnostic(LeaderPhase::BeforeMemory);
        for identity in [
            LeaderIdentity {
                pid: 18,
                ..before.identity
            },
            LeaderIdentity {
                uid: 502,
                ..before.identity
            },
            LeaderIdentity {
                pgid: 18,
                ..before.identity
            },
            LeaderIdentity {
                start_sec: 123456790,
                ..before.identity
            },
            LeaderIdentity {
                start_usec: 322,
                ..before.identity
            },
        ] {
            let mut reservation = true;
            let error = classify_leader_session(
                before.identity,
                before,
                Some(LeaderBsd { identity, ..after }),
                LeaderPhase::AfterMemory,
                LeaderSession::NativeFailure(DARWIN_ESRCH),
                &mut reservation,
            )
            .unwrap_err();
            assert_eq!(error.kind, "process_identity");
            assert!(!reservation);
            assert!(error.message.contains("after_anchor_match=false"));
            assert!(!error.message.contains("123456789") && !error.message.contains("501"));
            assert!(
                verify_reserved_identity(
                    before.identity,
                    Some(before),
                    Some(before),
                    LeaderPhase::GroupIdentity,
                    &mut reservation
                )
                .is_err()
            );
            assert!(!reservation);
        }
        let mut reservation = true;
        assert!(
            verify_reserved_identity(
                before.identity,
                Some(LeaderBsd {
                    identity: LeaderIdentity {
                        uid: 502,
                        ..before.identity
                    },
                    ..before
                }),
                Some(before),
                LeaderPhase::GroupIdentity,
                &mut reservation
            )
            .is_err()
        );
        assert!(!reservation);
    }
    #[test]
    fn arbitrary_session_failures_and_unflagged_or_missing_bsd_are_not_pending() {
        let before = reserved_leader();
        for (session, after) in [
            (LeaderSession::NativeFailure(DARWIN_ESRCH), Some(before)),
            (
                LeaderSession::NativeFailure(DARWIN_ESRCH),
                Some(LeaderBsd { flags: 8, ..before }),
            ),
            (LeaderSession::NativeFailure(DARWIN_ESRCH), None),
            (LeaderSession::NativeFailure(1), None), // actual Darwin EPERM
            (LeaderSession::NativeFailure(0), None),
            (LeaderSession::Mismatch, None),
        ] {
            let mut reservation = true;
            let error = classify_leader_session(
                before.identity,
                before,
                after,
                LeaderPhase::BeforeMemory,
                session,
                &mut reservation,
            )
            .unwrap_err();
            assert_eq!(error.kind, "process_identity");
            assert_eq!(reservation, session != LeaderSession::Mismatch);
        }
        let mut reservation = true;
        assert_eq!(
            classify_leader_session(
                before.identity,
                before,
                None,
                LeaderPhase::BeforeMemory,
                LeaderSession::Expected,
                &mut reservation
            )
            .unwrap(),
            LeaderObservation::Live
        );
        assert_eq!(
            classify_leader_session(
                before.identity,
                before,
                Some(LeaderBsd {
                    status: SZOMB,
                    flags: PROC_FLAG_INEXIT,
                    ..before
                }),
                LeaderPhase::AfterMemory,
                LeaderSession::NativeFailure(DARWIN_ESRCH),
                &mut reservation
            )
            .unwrap(),
            LeaderObservation::Zombie
        );
        assert!(reservation);
        reservation = false; // ECHILD or another definitive reservation loss.
        assert!(
            classify_leader_session(
                before.identity,
                before,
                None,
                LeaderPhase::BeforeMemory,
                LeaderSession::Expected,
                &mut reservation
            )
            .is_err()
        );
        assert!(!reservation);
    }
    #[test]
    fn pending_sample_keeps_first_last_facts_without_success_count_zero_usage_or_new_gap() {
        let mut tracker = Tracker::new(small()).unwrap();
        let mut complete = Sample::default();
        complete.push(small()).unwrap();
        tracker
            .finish_observation(GroupObservation::Complete(1), complete)
            .unwrap();
        let prior_success = tracker.last_success;
        for phase in [LeaderPhase::BeforeMemory, LeaderPhase::AfterMemory] {
            let observation = GroupObservation::Pending(Box::new(pending_diagnostic(phase).into()));
            assert!(!observation.scope_empty());
            let mut partial = Sample::default();
            partial
                .push(Memory {
                    rss: small().rss * 2,
                    ..small()
                })
                .unwrap();
            assert_eq!(
                tracker.finish_observation(observation, partial).unwrap(),
                ResourceObservation::Pending
            );
            assert_eq!(tracker.evidence.sample_count, 1);
            assert_eq!(tracker.last_success, prior_success);
            assert_eq!(
                tracker.evidence.peak_observed_aggregate_rss_bytes,
                small().rss
            );
        }
        let pending = tracker.evidence.pending_leader_exit.unwrap();
        assert_eq!(pending.observations, 2);
        assert_eq!(pending.first.phase, LeaderPhase::BeforeMemory);
        assert_eq!(pending.last.phase, LeaderPhase::AfterMemory);
        tracker.last_success = Instant::now() - Duration::from_millis(1001);
        let expired_success = tracker.last_success;
        let error = tracker.begin().unwrap_err();
        let error = tracker.with_pending_diagnostics(error);
        assert_eq!(error.kind, "resource_observation");
        assert!(
            error.message.contains("first_pending=[") && error.message.contains("final_pending=[")
        );
        assert!(error.message.contains("native_errno=Some(3)"));
        assert!(error.message.len() < 2048);
        assert_eq!(tracker.last_success, expired_success);
        assert_eq!(tracker.evidence.sample_count, 1);
        let mut original = ProcessError::new("command_timeout", "original deadline failure");
        original.drained = false;
        let original = tracker.with_pending_diagnostics(original);
        assert_eq!(original.kind, "command_timeout");
        assert!(
            original
                .message
                .starts_with("original deadline failure; first_pending=[")
        );
        assert!(!original.drained);
    }
    #[test]
    fn pending_keeps_the_original_attempt_cadence_without_refreshing_success_age() {
        for diagnostic in [
            pending_diagnostic(LeaderPhase::BeforeMemory),
            observed_member_pending_diagnostic(),
        ] {
            let mut tracker = Tracker::new(small()).unwrap();
            let prior_success = tracker.last_success;
            assert!(tracker.begin_at(prior_success).unwrap().is_some());
            tracker
                .finish_observation(
                    GroupObservation::Pending(Box::new(diagnostic.into())),
                    Sample::default(),
                )
                .unwrap();
            assert_eq!(tracker.last_success, prior_success);
            assert!(
                tracker
                    .begin_at(prior_success + Duration::from_millis(99))
                    .unwrap()
                    .is_none()
            );
            assert_eq!(tracker.evidence.sample_count, 0);
            assert!(
                tracker
                    .begin_at(prior_success + Duration::from_millis(100))
                    .unwrap()
                    .is_some()
            );
            assert!(
                tracker
                    .begin_at(prior_success + Duration::from_millis(1000))
                    .unwrap()
                    .is_some()
            );
            assert_eq!(
                tracker
                    .begin_at(prior_success + Duration::from_millis(1001))
                    .unwrap_err()
                    .kind,
                "resource_observation"
            );
            assert_eq!(tracker.evidence.sample_count, 0);
        }
    }
    #[test]
    fn pending_does_not_hide_known_partial_budget_failure_or_block_later_complete_observation() {
        for diagnostic in [
            pending_diagnostic(LeaderPhase::BeforeMemory),
            observed_member_pending_diagnostic(),
        ] {
            let mut tracker = Tracker::new(small()).unwrap();
            let prior_success = tracker.last_success;
            let mut over_budget = Sample::default();
            over_budget
                .push(Memory {
                    rss: MEMORY_LIMIT + 1,
                    ..small()
                })
                .unwrap();
            let error = tracker
                .finish_observation(
                    GroupObservation::Pending(Box::new(diagnostic.into())),
                    over_budget,
                )
                .unwrap_err();
            assert_eq!(error.kind, "resource_budget");
            assert_eq!(tracker.evidence.sample_count, 0);
            assert_eq!(tracker.last_success, prior_success);
            assert_eq!(
                tracker.evidence.pending_member_exit.is_some(),
                diagnostic.memory_role == Some(MemoryRole::ObservedMember)
            );
            assert_eq!(
                tracker.evidence.pending_leader_exit.is_some(),
                diagnostic.memory_role != Some(MemoryRole::ObservedMember)
            );
            let mut later = Tracker::new(small()).unwrap();
            later
                .finish_observation(
                    GroupObservation::Pending(Box::new(diagnostic.into())),
                    Sample::default(),
                )
                .unwrap();
            assert_eq!(later.evidence.sample_count, 0);
            assert!(GroupObservation::Complete(0).scope_empty());
            assert!(!GroupObservation::Complete(1).scope_empty());
            assert_eq!(
                later
                    .finish_observation(GroupObservation::Complete(0), Sample::default())
                    .unwrap(),
                ResourceObservation::Complete
            );
            assert_eq!(later.evidence.sample_count, 1);
            assert_eq!(
                later.evidence.pending_member_exit.is_some(),
                diagnostic.memory_role == Some(MemoryRole::ObservedMember)
            );
            assert_eq!(
                later.evidence.pending_leader_exit.is_some(),
                diagnostic.memory_role != Some(MemoryRole::ObservedMember)
            );
        }
    }
    #[test]
    fn aggregate_and_distinct_measures_are_bounded() {
        let mut sample = Sample::default();
        sample.push(small()).unwrap();
        sample
            .push(Memory {
                rss: MEMORY_LIMIT,
                ..small()
            })
            .unwrap();
        assert_eq!(sample.check().unwrap_err().kind, "resource_budget");
        let mut sample = Sample::default();
        sample
            .push(Memory {
                footprint: MEMORY_LIMIT + 1,
                ..small()
            })
            .unwrap();
        assert_eq!(sample.check().unwrap_err().kind, "resource_budget");
    }
    #[test]
    fn overflow_and_vm_are_not_silently_normalized() {
        let mut sample = Sample::default();
        sample
            .push(Memory {
                rss: u64::MAX,
                ..small()
            })
            .unwrap();
        assert_eq!(
            sample.push(small()).unwrap_err().kind,
            "resource_observation"
        );
        let mut sample = Sample::default();
        sample
            .push(Memory {
                adjusted_vm: VM_LIMIT + 1,
                ..small()
            })
            .unwrap();
        assert_eq!(sample.check().unwrap_err().kind, "resource_budget");
        let mut sample = Sample::default();
        sample
            .push(Memory {
                footprint: u64::MAX,
                ..small()
            })
            .unwrap();
        assert_eq!(
            sample.push(small()).unwrap_err().kind,
            "resource_observation"
        );
    }
    #[test]
    fn stalled_sampling_fails_and_keeps_the_gap_fact() {
        let mut tracker = Tracker::new(small()).unwrap();
        tracker.last_success = Instant::now() - Duration::from_millis(1001);
        assert_eq!(tracker.begin().unwrap_err().kind, "resource_observation");
        assert!(tracker.evidence.max_observed_sample_gap_ms >= 1001);
    }
    #[test]
    fn complete_sample_preserves_readback_and_observed_failure_peak() {
        let mut tracker = Tracker::new(small()).unwrap();
        tracker.configured();
        assert!(tracker.begin().unwrap().is_some());
        let mut sample = Sample::default();
        sample
            .push(Memory {
                rss: MEMORY_LIMIT + 1,
                ..small()
            })
            .unwrap();
        assert_eq!(tracker.finish(sample).unwrap_err().kind, "resource_budget");
        assert_eq!(tracker.evidence.rlimit_as_readback_bytes, Some(VM_LIMIT));
        assert_eq!(tracker.evidence.sample_count, 1);
        assert_eq!(
            tracker.evidence.peak_observed_aggregate_rss_bytes,
            MEMORY_LIMIT + 1
        );
        assert!(!tracker.evidence.kernel_resident_quota);
    }
    #[test]
    fn worker_limit_counts_the_command_and_all_live_children() {
        let mut sample = Sample::default();
        for _ in 0..WORKER_LIMIT {
            sample.push(small()).unwrap();
        }
        sample.check().unwrap();
        sample.push(small()).unwrap();
        assert_eq!(sample.check().unwrap_err().kind, "resource_budget");
    }
    #[test]
    fn native_resource_failures_require_full_results_and_live_identity() {
        let permission_denied = 1; // Darwin EPERM.
        task_result(96, 0).unwrap();
        for bytes in [-1, 0, 95, 97] {
            assert_eq!(
                task_result(bytes, permission_denied).unwrap_err().kind,
                "resource_observation"
            );
        }
        assert_eq!(
            task_result(0, DARWIN_ESRCH).unwrap_err().kind,
            "resource_process_exit"
        );
        assert_eq!(
            task_result(95, DARWIN_ESRCH).unwrap_err().kind,
            "resource_observation"
        );
        rusage_result(0, 0, 1, 0).unwrap();
        assert_eq!(
            rusage_result(-1, permission_denied, 0, 0).unwrap_err().kind,
            "resource_observation"
        );
        assert_eq!(
            rusage_result(-1, DARWIN_ESRCH, 0, 0).unwrap_err().kind,
            "resource_process_exit"
        );
        assert_eq!(
            rusage_result(0, 0, 0, 0).unwrap_err().kind,
            "resource_observation"
        );
        assert_eq!(
            rusage_result(0, 0, 1, 2).unwrap_err().kind,
            "resource_process_exit"
        );
    }
    #[test]
    fn late_complete_sample_retains_usage_without_refreshing_success() {
        let mut tracker = Tracker::new(small()).unwrap();
        tracker.last_success = Instant::now() - Duration::from_millis(1001);
        let prior_success = tracker.last_success;
        let mut sample = Sample::default();
        sample.push(small()).unwrap();
        assert_eq!(
            tracker.finish(sample).unwrap_err().kind,
            "resource_observation"
        );
        assert_eq!(tracker.last_success, prior_success);
        assert_eq!(
            tracker.evidence.peak_observed_adjusted_vm_bytes,
            small().adjusted_vm
        );
        assert_eq!(tracker.evidence.sample_count, 1);
    }
    #[test]
    fn vm_is_per_pid_and_resident_budgets_include_every_live_member() {
        let half = Memory {
            rss: MEMORY_LIMIT / 2,
            footprint: MEMORY_LIMIT / 2,
            ..small()
        };
        let mut sample = Sample::default();
        sample.push(half).unwrap();
        sample.push(half).unwrap();
        // Two normal Darwin reservations total >512GiB; only each PID's
        // adjusted VM is bounded, while physical measurements are summed.
        sample.check().unwrap();
        sample
            .push(Memory {
                rss: 1,
                footprint: 0,
                ..small()
            })
            .unwrap();
        assert_eq!(sample.check().unwrap_err().kind, "resource_budget");
    }
    #[test]
    fn exactly_one_second_is_fresh_and_any_excess_fails() {
        let mut tracker = Tracker::new(small()).unwrap();
        let origin = tracker.last_success;
        tracker.gap(origin + MAX_GAP).unwrap();
        assert_eq!(
            tracker
                .gap(origin + MAX_GAP + Duration::from_nanos(1))
                .unwrap_err()
                .kind,
            "resource_observation"
        );
        assert_eq!(tracker.last_success, origin);
    }
}

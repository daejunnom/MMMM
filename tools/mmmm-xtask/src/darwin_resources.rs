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
    ops::Deref,
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
pub(super) const PROC_FLAG_INEXIT: u32 = 4;
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct TaskMemoryLowerBound {
    adjusted_vm: u64,
    rss: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct RusageTimestamps {
    start_observed: bool,
    exit_observed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct MemoryExitConfirmation {
    kind: &'static str,
    status: Option<u32>,
    inexit: Option<bool>,
    identity_match: Option<bool>,
    current_uid_match: Option<bool>,
}
/// Kept only for bounded scan deduplication; identity never enters a report.
#[derive(Clone, Copy, PartialEq, Eq)]
struct PendingWorkerIdentity(LeaderIdentity);
impl fmt::Debug for PendingWorkerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingWorkerIdentity")
    }
}
/// Copy adapter keeps existing callers' native fields while partial facts
/// can only enter production through the shared native producer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MemoryFailure {
    native: NativeResourceError,
    task_lower_bound: Option<TaskMemoryLowerBound>,
    rusage_timestamps: Option<RusageTimestamps>,
}
impl Deref for MemoryFailure {
    type Target = NativeResourceError;
    fn deref(&self) -> &Self::Target {
        &self.native
    }
}
impl From<NativeResourceError> for MemoryFailure {
    fn from(native: NativeResourceError) -> Self {
        Self {
            native,
            task_lower_bound: None,
            rusage_timestamps: None,
        }
    }
}
#[cfg(target_os = "macos")]
impl From<mmmm_native_process::darwin::MemoryObservationFailure> for MemoryFailure {
    fn from(actual: mmmm_native_process::darwin::MemoryObservationFailure) -> Self {
        Self {
            native: actual.native_error(),
            task_lower_bound: actual.task_lower_bound().map(|lower| TaskMemoryLowerBound {
                adjusted_vm: lower.adjusted_vm(),
                rss: lower.rss(),
            }),
            rusage_timestamps: actual
                .rusage_timestamps()
                .map(|timestamps| RusageTimestamps {
                    start_observed: timestamps.start_observed(),
                    exit_observed: timestamps.exit_observed(),
                }),
        }
    }
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
/// Reports omit PID, UID, birth timestamp, path and process label. The private
/// Pending worker key is neither serialized nor displayed and grants no authority.
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
    memory_task_lower_bound: Option<TaskMemoryLowerBound>,
    memory_rusage_timestamps: Option<RusageTimestamps>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory_exit_confirmation: Option<MemoryExitConfirmation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_bsd_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_bsd_native_result: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_bsd_native_errno: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pending_admission_anchor_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pending_admission_kind: Option<&'static str>,
    #[serde(skip)]
    pending_worker: Option<PendingWorkerIdentity>,
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
            memory_task_lower_bound: None,
            memory_rusage_timestamps: None,
            memory_exit_confirmation: None,
            after_bsd_kind: None,
            after_bsd_native_result: None,
            after_bsd_native_errno: None,
            pending_admission_anchor_match: None,
            pending_admission_kind: None,
            pending_worker: None,
        }
    }
    pub(super) fn with_memory_error(
        mut self,
        error: impl Into<MemoryFailure>,
        reserved: bool,
    ) -> Self {
        let error = error.into();
        self.memory_error = Some(error.native.into());
        self.memory_task_lower_bound = error.task_lower_bound;
        self.memory_rusage_timestamps = error.rusage_timestamps;
        self.memory_role = Some(if reserved {
            MemoryRole::ReservedLeader
        } else {
            MemoryRole::ObservedMember
        });
        self
    }
    fn with_pending_worker(mut self, identity: LeaderIdentity) -> Self {
        self.pending_worker = Some(PendingWorkerIdentity(identity));
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
        if let Some(lower) = self.memory_task_lower_bound {
            write!(
                f,
                ",memory_task_vm_lower_bound={},memory_task_rss_lower_bound={}",
                lower.adjusted_vm, lower.rss
            )?;
        }
        if let Some(timestamps) = self.memory_rusage_timestamps {
            write!(
                f,
                ",memory_rusage_start_observed={},memory_rusage_exit_observed={}",
                timestamps.start_observed, timestamps.exit_observed
            )?;
        }
        if let Some(confirmation) = self.memory_exit_confirmation {
            write!(
                f,
                ",memory_confirmation_kind={},memory_confirmation_status={:?},memory_confirmation_inexit={:?},memory_confirmation_identity_match={:?},memory_confirmation_current_uid_match={:?}",
                confirmation.kind,
                confirmation.status,
                confirmation.inexit,
                confirmation.identity_match,
                confirmation.current_uid_match
            )?;
        }
        if let Some(kind) = self.after_bsd_kind {
            write!(
                f,
                ",after_bsd_kind={kind},after_bsd_native_result={:?},after_bsd_native_errno={:?},pending_admission_anchor_match={:?},pending_admission_kind={:?}",
                self.after_bsd_native_result,
                self.after_bsd_native_errno,
                self.pending_admission_anchor_match,
                self.pending_admission_kind
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
    // Only the actual BSD query's 0/ESRCH path may produce this candidate.
    // The group reducer must still validate its held leader before admission.
    MissingAfterTaskExit(LeaderDiagnostic),
}

#[derive(Clone, Copy)]
struct MissingMember {
    diagnostic: LeaderDiagnostic,
    fresh: bool,
}
/// A bounded, private uncertainty latch, never a process or signal authority.
/// Birth/PID values are used only for equality and never leave this type.
pub(super) struct MissingMembers {
    entries: [Option<MissingMember>; WORKER_LIMIT + 1],
    current: PendingWorkers,
}
impl Default for MissingMembers {
    fn default() -> Self {
        Self {
            entries: [None; WORKER_LIMIT + 1],
            current: PendingWorkers::default(),
        }
    }
}
impl MissingMembers {
    pub(super) fn is_empty(&self) -> bool {
        self.entries.iter().all(Option::is_none)
    }
    pub(super) fn begin_scan(&mut self) {
        self.current = PendingWorkers::default();
        for entry in self.entries.iter_mut().flatten() {
            entry.fresh = false;
        }
    }
    pub(super) fn contains_pid(&self, pid: u32) -> bool {
        self.entries.iter().flatten().any(|entry| {
            entry
                .diagnostic
                .pending_worker
                .is_some_and(|id| id.0.pid == pid)
        })
    }
    pub(super) fn verify(&self, pid: u32, before: LeaderBsd) -> Result<(), ProcessError> {
        if self.entries.iter().flatten().any(|entry| {
            entry
                .diagnostic
                .pending_worker
                .is_some_and(|id| id.0.pid == pid && id.0 != before.identity)
        }) {
            return Err(ProcessError::new(
                "process_identity",
                "latched Darwin member identity changed",
            ));
        }
        Ok(())
    }
    pub(super) fn unavailable(&mut self, pid: u32) {
        for entry in self.entries.iter_mut().flatten() {
            if let Some(identity) = entry.diagnostic.pending_worker.filter(|id| id.0.pid == pid) {
                let _ = self.current.record(identity, None);
            }
        }
    }
    pub(super) fn record(&mut self, diagnostic: LeaderDiagnostic) -> Result<(), ProcessError> {
        let identity = diagnostic.pending_worker.ok_or_else(sum_overflow)?;
        for entry in self.entries.iter_mut().flatten() {
            if entry.diagnostic.pending_worker == Some(identity) {
                entry.diagnostic = diagnostic;
                entry.fresh = true;
                let _ = self.current.record(identity, None);
                return Ok(());
            }
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or_else(sum_overflow)?;
        *entry = Some(MissingMember {
            diagnostic,
            fresh: true,
        });
        let _ = self.current.record(identity, None);
        Ok(())
    }
    pub(super) fn measured(&mut self, identity: LeaderIdentity) {
        for entry in &mut self.entries {
            if entry.is_some_and(|entry| {
                entry.diagnostic.pending_worker == Some(PendingWorkerIdentity(identity))
            }) {
                *entry = None;
            }
        }
        if let Some(index) = self.current.entries[..self.current.len]
            .iter()
            .position(|worker| {
                worker.is_some_and(|worker| worker.identity == PendingWorkerIdentity(identity))
            })
        {
            self.current
                .entries
                .copy_within(index + 1..self.current.len, index);
            self.current.len -= 1;
            self.current.entries[self.current.len] = None;
        }
    }
    pub(super) fn admit(
        &self,
        allowed: bool,
        anchor_verified: bool,
        pending: &mut PendingObservations,
    ) -> Result<(), ProcessError> {
        if self.is_empty() {
            return Ok(());
        }
        // Preserve this scan's actual observation order in first/last facts,
        // independently of the order in which older latch entries originated.
        for worker in self.current.entries[..self.current.len].iter().flatten() {
            let entry = self
                .entries
                .iter()
                .flatten()
                .find(|entry| entry.diagnostic.pending_worker == Some(worker.identity))
                .ok_or_else(sum_overflow)?;
            if !allowed || !anchor_verified {
                return Err(entry.diagnostic.attach(ProcessError::new(
                    "resource_observation",
                    "Darwin resource process identity changed or unavailable",
                )));
            }
            let mut diagnostic = entry.diagnostic;
            diagnostic.pending_admission_anchor_match = Some(true);
            diagnostic.pending_admission_kind = Some(if entry.fresh {
                "fresh_missing_after_task_exit"
            } else {
                "retained_missing_after_task_exit"
            });
            pending.record(diagnostic);
        }
        if pending.last().is_some() {
            // Include unresolved earlier identities conservatively. A measured
            // same identity was removed above; absent rows clear only at Complete.
            for entry in self.entries.iter().flatten() {
                if let Some(identity) = entry.diagnostic.pending_worker {
                    let _ = pending.workers.record(identity, None);
                }
            }
        }
        Ok(())
    }
    fn clear(&mut self) {
        self.entries.fill(None);
        self.current = PendingWorkers::default();
    }
}

/// Separate producer entry for actual BSD MissingEsrch. Ordinary Option::None
/// in classify_memory_exit retains its strict historical meaning.
pub(super) fn missing_after_task_exit(
    before: LeaderBsd,
    native: MemoryFailure,
) -> Result<MemoryObservation, ProcessError> {
    let mut diagnostic = LeaderDiagnostic::observe(
        before.identity,
        Some(before),
        None,
        LeaderPhase::MemoryResult,
        LeaderSession::NotObserved,
    )
    .with_memory_error(native, false);
    diagnostic.after_bsd_kind = Some("missing_esrch");
    diagnostic.after_bsd_native_result = Some(0);
    diagnostic.after_bsd_native_errno = Some(DARWIN_ESRCH);
    if native.failure == NativeResourceFailure::Exited
        && native.stage == NativeResourceStage::TaskInfo
        && native.native_result == 0
        && native.native_errno == DARWIN_ESRCH
        && before.identity.pid != before.identity.pgid
        && before.status != SZOMB
        && before.flags & PROC_FLAG_INEXIT != 0
    {
        return Ok(MemoryObservation::MissingAfterTaskExit(
            diagnostic.with_pending_worker(before.identity),
        ));
    }
    Err(diagnostic.attach(ProcessError::new(
        "resource_observation",
        "Darwin resource process identity changed or unavailable",
    )))
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
            return Ok(LeaderObservation::Pending(
                diagnostic.with_pending_worker(anchor),
            ));
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
/// TaskInfo 0/ESRCH or successful rusage with actual start/exit timestamps,
/// with the same identity and INEXIT on both sides.
pub(super) fn classify_memory_exit(
    reserved: Option<(LeaderIdentity, &mut bool)>,
    before: LeaderBsd,
    after: Option<LeaderBsd>,
    native: impl Into<MemoryFailure>,
) -> Result<MemoryObservation, ProcessError> {
    let native = native.into();
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
        let observed_member_rusage_exit = !reserved_leader
            && native.stage == NativeResourceStage::Rusage
            && native.native_result == 0
            && native.native_errno == 0
            && native.task_lower_bound.is_some()
            && native.rusage_timestamps
                == Some(RusageTimestamps {
                    start_observed: true,
                    exit_observed: true,
                })
            && before.flags & PROC_FLAG_INEXIT != 0;
        if (reserved_leader || observed_member_task_exit || observed_member_rusage_exit)
            && before.status != SZOMB
            && after.flags & PROC_FLAG_INEXIT != 0
        {
            return Ok(MemoryObservation::Pending(
                diagnostic.with_pending_worker(anchor),
            ));
        }
    }
    Err(diagnostic.attach(ProcessError::new(
        "resource_observation",
        "Darwin resource process exit not confirmed by native zombie identity",
    )))
}

pub(super) fn member_exit_confirmation_candidate(
    before: LeaderBsd,
    first_after: LeaderBsd,
    native: MemoryFailure,
) -> bool {
    // Apple XNU proc.h defines the supported non-zombie states as 1..=4.
    native.failure == NativeResourceFailure::Exited
        && native.stage == NativeResourceStage::TaskInfo
        && native.native_result == 0
        && native.native_errno == DARWIN_ESRCH
        && before.identity.pid != before.identity.pgid
        && before.identity == first_after.identity
        && matches!(before.status, 1..=4)
        && matches!(first_after.status, 1..=4)
        && before.flags & PROC_FLAG_INEXIT == 0
        && first_after.flags & PROC_FLAG_INEXIT != 0
}

/// An observed member can cross into exit() during the memory query. This
/// permits one more actual BSD observation, never a deferred or zero sample.
/// The caller still checks the original current-UID/PID sandwich and the
/// whole scan's reserved leader before consuming a confirmed zombie.
pub(super) fn confirm_member_memory_exit(
    before: LeaderBsd,
    first_after: LeaderBsd,
    native: MemoryFailure,
    confirm: impl FnOnce() -> Result<(Option<LeaderBsd>, u32), ProcessError>,
) -> Result<Option<MemoryObservation>, ProcessError> {
    if !member_exit_confirmation_candidate(before, first_after, native) {
        return Ok(None);
    }
    let mut diagnostic = LeaderDiagnostic::observe(
        before.identity,
        Some(before),
        Some(first_after),
        LeaderPhase::MemoryResult,
        LeaderSession::NotObserved,
    )
    .with_memory_error(native, false);
    let (confirmed, current_uid) = match confirm() {
        Ok(observation) => observation,
        Err(error) => {
            diagnostic.memory_exit_confirmation = Some(MemoryExitConfirmation {
                kind: "query_error",
                status: None,
                inexit: None,
                identity_match: None,
                current_uid_match: None,
            });
            return Err(diagnostic.attach(error));
        }
    };
    diagnostic.memory_exit_confirmation = Some(MemoryExitConfirmation {
        kind: if confirmed.is_some() {
            "observed"
        } else {
            "missing_esrch"
        },
        status: confirmed.map(|info| info.status),
        inexit: confirmed.map(|info| info.flags & PROC_FLAG_INEXIT != 0),
        identity_match: confirmed.map(|info| info.identity == before.identity),
        current_uid_match: Some(current_uid == before.identity.uid),
    });
    if current_uid == before.identity.uid
        && matches!(
            classify_memory_exit(None, before, confirmed, native),
            Ok(MemoryObservation::Zombie(_))
        )
    {
        return Ok(Some(MemoryObservation::Zombie(diagnostic)));
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
    task_lower_bound: Option<TaskMemoryLowerBound>,
    task_sum_overflow: bool,
    workers: PendingWorkers,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingWorker {
    identity: PendingWorkerIdentity,
    rss_lower_bound: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingWorkers {
    // At limit+1 distinct pending workers the original budget must already
    // fail, even without measured workers. No unbounded identity registry.
    entries: [Option<PendingWorker>; WORKER_LIMIT + 1],
    len: usize,
}
impl Default for PendingWorkers {
    fn default() -> Self {
        Self {
            entries: [None; WORKER_LIMIT + 1],
            len: 0,
        }
    }
}
impl PendingWorkers {
    fn record(
        &mut self,
        identity: PendingWorkerIdentity,
        lower: Option<TaskMemoryLowerBound>,
    ) -> Option<u64> {
        let rss = lower.map_or(0, |lower| lower.rss);
        if let Some(worker) = self.entries[..self.len]
            .iter_mut()
            .flatten()
            .find(|worker| worker.identity == identity)
        {
            let additional_rss = rss.saturating_sub(worker.rss_lower_bound);
            worker.rss_lower_bound = worker.rss_lower_bound.max(rss);
            return Some(additional_rss);
        }
        if self.len == self.entries.len() {
            return None; // The retained worker lower bound already exceeds 32.
        }
        self.entries[self.len] = Some(PendingWorker {
            identity,
            rss_lower_bound: rss,
        });
        self.len += 1; // Bounded by the fixed array above.
        Some(rss)
    }
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
        // live_group_members records at most one Pending per native PID-list
        // entry: leader's early Pending skips AfterMemory, and a member has
        // one memory observation. Identity deduplication also keeps repeated
        // diagnostic records from adding the same worker or RSS twice. Like
        // existing Sample::push, measured-versus-Pending uniqueness across
        // entries still relies on the native PID snapshot containing each PID
        // once; this scan-local state cannot deduplicate a measured PID.
        let additional_rss = diagnostic.pending_worker.and_then(|identity| {
            self.workers
                .record(identity, diagnostic.memory_task_lower_bound)
        });
        if let (Some(lower), Some(additional_rss)) =
            (diagnostic.memory_task_lower_bound, additional_rss)
        {
            let accumulated = self.task_lower_bound.get_or_insert(TaskMemoryLowerBound {
                adjusted_vm: 0,
                rss: 0,
            });
            accumulated.adjusted_vm = accumulated.adjusted_vm.max(lower.adjusted_vm);
            match accumulated.rss.checked_add(additional_rss) {
                Some(rss) => accumulated.rss = rss,
                None => self.task_sum_overflow = true,
            }
        }
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
    pub(super) missing: MissingMembers,
    pending: bool,
}
impl Tracker {
    pub(super) fn new(preflight: Memory) -> Result<Self, ProcessError> {
        let mut sample = Sample::default();
        sample.push(preflight)?;
        sample.check()?;
        Ok(Self {
            last_success: Instant::now(),
            last_attempt: None,
            missing: MissingMembers::default(),
            pending: false,
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
        // A late complete observation cannot refresh a missing-member window.
        if self.pending {
            self.gap(finished)?;
        }
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
        sample.check()?;
        self.pending = false;
        self.missing.clear();
        Ok(())
    }
    pub(super) fn finish_observation(
        &mut self,
        observation: GroupObservation,
        mut sample: Sample,
    ) -> Result<ResourceObservation, ProcessError> {
        match observation {
            GroupObservation::Complete(_) => {
                self.finish(sample)?;
                Ok(ResourceObservation::Complete)
            }
            GroupObservation::Pending(observations) => {
                self.pending = true;
                self.record_pending_observations(*observations);
                // Other observed members still provide a lower bound: a known
                // over-budget partial sample remains fatal. No partial sample
                // increments success/count/peaks or replaces the missing PID
                // with zero. The original successful-sample gap keeps running.
                sample.push_pending_workers(observations.workers.len)?;
                if observations.task_sum_overflow {
                    return Err(sum_overflow());
                }
                if let Some(lower) = observations.task_lower_bound {
                    sample.push_task_lower_bound(lower)?;
                }
                sample.check()?;
                self.gap(Instant::now())?;
                Ok(ResourceObservation::Pending)
            }
        }
    }
    pub(super) fn missing_allowed(&self) -> bool {
        self.evidence.sample_count != 0
    }
    pub(super) fn pending(&self) -> bool {
        self.pending
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
    fn push_pending_workers(&mut self, workers: usize) -> Result<(), ProcessError> {
        self.workers = self.workers.checked_add(workers).ok_or_else(sum_overflow)?;
        Ok(())
    }
    fn push_task_lower_bound(&mut self, lower: TaskMemoryLowerBound) -> Result<(), ProcessError> {
        self.adjusted_vm_peak = self.adjusted_vm_peak.max(lower.adjusted_vm);
        self.rss = self.rss.checked_add(lower.rss).ok_or_else(sum_overflow)?;
        Ok(())
    }
    pub(super) fn push_memory_lower_bound(&mut self, memory: Memory) -> Result<(), ProcessError> {
        self.adjusted_vm_peak = self.adjusted_vm_peak.max(memory.adjusted_vm);
        self.rss = self.rss.checked_add(memory.rss).ok_or_else(sum_overflow)?;
        self.footprint = self
            .footprint
            .checked_add(memory.footprint)
            .ok_or_else(sum_overflow)?;
        Ok(())
    }
    pub(super) fn push(&mut self, memory: Memory) -> Result<(), ProcessError> {
        self.push_memory_lower_bound(memory)?;
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

pub(super) fn native_error(error: impl Into<MemoryFailure>) -> ProcessError {
    let error = error.into();
    // ESRCH and an observed exit timestamp remain exit-class failures. Only
    // process.rs may independently confirm the unchanged native zombie.
    let kind = if error.failure == NativeResourceFailure::Exited {
        "resource_process_exit"
    } else {
        "resource_observation"
    };
    ProcessError::new(kind, error.native.to_string())
}

#[cfg(target_os = "macos")]
pub(super) fn memory(pid: i32) -> Result<Memory, MemoryFailure> {
    let actual = mmmm_native_process::darwin::observe_memory_with_partial(pid)
        .map_err(MemoryFailure::from)?;
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
        member_memory_pending(18, native_exit_results()[0])
    }
    fn missing_member_candidate(pid: u32) -> LeaderDiagnostic {
        let before = LeaderBsd {
            identity: LeaderIdentity {
                pid,
                ..reserved_leader().identity
            },
            flags: PROC_FLAG_INEXIT,
            ..reserved_leader()
        };
        let MemoryObservation::MissingAfterTaskExit(diagnostic) =
            missing_after_task_exit(before, native_exit_results()[0].into()).unwrap()
        else {
            panic!("actual missing member was not a deferred candidate")
        };
        diagnostic
    }
    #[test]
    fn missing_after_task_exit_requires_the_exact_nonleader_native_result() {
        let diagnostic = missing_member_candidate(18);
        assert_eq!(diagnostic.after_bsd_kind, Some("missing_esrch"));
        assert_eq!(diagnostic.after_bsd_native_result, Some(0));
        assert_eq!(diagnostic.after_bsd_native_errno, Some(DARWIN_ESRCH));
        assert_eq!(diagnostic.pending_admission_anchor_match, None);
        assert_eq!(diagnostic.after_status, None);
        assert_eq!(diagnostic.memory_role, Some(MemoryRole::ObservedMember));
        let before = LeaderBsd {
            identity: LeaderIdentity {
                pid: 18,
                ..reserved_leader().identity
            },
            flags: PROC_FLAG_INEXIT,
            ..reserved_leader()
        };
        // Bare None remains unavailable. Only the producer reached after an
        // actual BSD 0/ESRCH can construct the separate deferred variant.
        assert!(classify_memory_exit(None, before, None, native_exit_results()[0]).is_err());
        for native in [
            native_exit_results()[1],
            native_exit_results()[2],
            NativeResourceError {
                native_errno: 1,
                ..native_exit_results()[0]
            },
            NativeResourceError {
                native_result: -1,
                ..native_exit_results()[0]
            },
            NativeResourceError {
                failure: NativeResourceFailure::Malformed,
                ..native_exit_results()[0]
            },
        ] {
            let error = missing_after_task_exit(before, native.into()).unwrap_err();
            assert!(
                error
                    .message
                    .contains("Darwin resource process identity changed or unavailable")
            );
            assert!(
                error
                    .message
                    .contains(&format!("memory_native_errno={}", native.native_errno))
            );
        }
        for invalid in [
            LeaderBsd { flags: 0, ..before },
            LeaderBsd {
                status: SZOMB,
                ..before
            },
            LeaderBsd {
                identity: reserved_leader().identity,
                ..before
            },
        ] {
            assert!(missing_after_task_exit(invalid, native_exit_results()[0].into()).is_err());
        }
        let encoded = serde_json::to_string(&diagnostic).unwrap();
        for forbidden in [
            "pending_worker",
            "start_sec",
            "start_usec",
            "uid",
            "pid",
            "pgid",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }
    #[test]
    fn missing_member_latch_requires_fresh_admission_and_never_adopts_reused_identity() {
        let diagnostic = missing_member_candidate(18);
        let identity = diagnostic.pending_worker.unwrap().0;
        let mut latch = MissingMembers::default();
        latch.record(diagnostic).unwrap();
        latch.record(diagnostic).unwrap();
        assert_eq!(latch.entries.iter().flatten().count(), 1);
        for (previous_complete, anchor) in [(false, true), (true, false), (false, false)] {
            let mut scan = PendingObservations::default();
            let error = latch
                .admit(previous_complete, anchor, &mut scan)
                .unwrap_err();
            assert!(error.message.contains("memory_stage=task_info"));
            assert!(scan.last().is_none());
        }
        let mut scan = PendingObservations::default();
        latch.admit(true, true, &mut scan).unwrap();
        assert_eq!(scan.workers.len, 1);
        assert_eq!(scan.member.unwrap().observations, 1);
        assert_eq!(
            scan.last().unwrap().pending_admission_anchor_match,
            Some(true)
        );
        assert_eq!(
            scan.last().unwrap().pending_admission_kind,
            Some("fresh_missing_after_task_exit")
        );
        assert_eq!(diagnostic.pending_admission_anchor_match, None);
        for changed in [
            LeaderIdentity {
                pid: identity.pid + 1,
                ..identity
            },
            LeaderIdentity {
                uid: identity.uid + 1,
                ..identity
            },
            LeaderIdentity {
                pgid: identity.pgid + 1,
                ..identity
            },
            LeaderIdentity {
                start_sec: identity.start_sec + 1,
                ..identity
            },
            LeaderIdentity {
                start_usec: identity.start_usec + 1,
                ..identity
            },
        ] {
            assert!(
                latch
                    .verify(
                        identity.pid,
                        LeaderBsd {
                            identity: changed,
                            ..reserved_leader()
                        }
                    )
                    .is_err()
            );
            latch.measured(changed);
            assert!(latch.contains_pid(identity.pid));
        }
        latch.begin_scan();
        let mut absent = PendingObservations::default();
        latch.admit(true, true, &mut absent).unwrap();
        assert!(absent.last().is_none());
        assert!(!latch.is_empty()); // A membership-only/NotDue scan cannot clear it.
        latch.unavailable(identity.pid);
        let mut again = PendingObservations::default();
        latch.admit(true, true, &mut again).unwrap();
        assert_eq!(again.workers.len, 1);
        assert_eq!(
            again.last().unwrap().pending_admission_kind,
            Some("retained_missing_after_task_exit")
        );
        latch.measured(identity);
        assert!(latch.is_empty());

        latch.record(missing_member_candidate(19)).unwrap();
        latch.record(diagnostic).unwrap();
        latch.begin_scan();
        latch.unavailable(18);
        latch.unavailable(19);
        let mut reordered = PendingObservations::default();
        latch.admit(true, true, &mut reordered).unwrap();
        assert_eq!(
            reordered.member.unwrap().first.pending_worker,
            diagnostic.pending_worker
        );
        assert_eq!(
            reordered.member.unwrap().last.pending_worker,
            missing_member_candidate(19).pending_worker
        );
        latch.measured(identity);
        latch.measured(missing_member_candidate(19).pending_worker.unwrap().0);
        assert!(latch.is_empty());

        for pid in 100..100 + WORKER_LIMIT as u32 + 1 {
            latch.record(missing_member_candidate(pid)).unwrap();
        }
        assert_eq!(latch.entries.iter().flatten().count(), WORKER_LIMIT + 1);
        assert!(latch.record(missing_member_candidate(1000)).is_err());
        let mut scan = PendingObservations::default();
        latch.admit(true, true, &mut scan).unwrap();
        assert_eq!(scan.workers.len, WORKER_LIMIT + 1);
        let mut tracker = Tracker::new(small()).unwrap();
        assert_eq!(
            tracker
                .finish_observation(GroupObservation::Pending(Box::new(scan)), Sample::default())
                .unwrap_err()
                .kind,
            "resource_budget"
        );
        assert_eq!(tracker.evidence.sample_count, 0);
    }
    #[test]
    fn missing_pending_retains_complete_age_partial_caps_and_normal_reap_fence() {
        let mut tracker = Tracker::new(small()).unwrap();
        assert!(!tracker.missing_allowed());
        tracker.finish(Sample::default()).unwrap();
        assert!(tracker.missing_allowed());
        let previous = tracker.last_success;
        tracker.last_attempt = Some(previous);
        let diagnostic = missing_member_candidate(18);
        let identity = diagnostic.pending_worker.unwrap().0;
        tracker.missing.record(diagnostic).unwrap();
        let mut scan = PendingObservations::default();
        tracker
            .missing
            .admit(tracker.missing_allowed(), true, &mut scan)
            .unwrap();
        let group = GroupObservation::Pending(Box::new(scan));
        assert!(!group.scope_empty());
        tracker
            .finish_observation(group, Sample::default())
            .unwrap();
        assert!(tracker.pending());
        assert_eq!(tracker.evidence.sample_count, 1);
        assert_eq!(tracker.last_success, previous);
        assert!(
            tracker
                .begin_at(previous + Duration::from_millis(99))
                .unwrap()
                .is_none()
        );
        assert!(tracker.pending()); // NotDue plus a membership zero is fenced.
        assert!(
            tracker
                .begin_at(previous + Duration::from_millis(100))
                .unwrap()
                .is_some()
        );
        tracker.missing.measured(identity);
        assert!(tracker.missing.is_empty());
        assert!(tracker.pending()); // Measured identity alone is not whole Complete.
        tracker.last_success = Instant::now() - Duration::from_millis(1001);
        let old_success = tracker.last_success;
        let mut late = Sample::default();
        late.push(small()).unwrap();
        let error = tracker
            .finish_observation(GroupObservation::Complete(1), late)
            .unwrap_err();
        assert_eq!(error.kind, "resource_observation");
        assert_eq!(tracker.evidence.sample_count, 1);
        assert_eq!(tracker.evidence.peak_observed_aggregate_rss_bytes, 0);
        assert_eq!(tracker.last_success, old_success);
        assert!(tracker.pending());

        let mut bounded = Tracker::new(small()).unwrap();
        bounded.finish(Sample::default()).unwrap();
        bounded.missing.record(diagnostic).unwrap();
        let mut scan = PendingObservations::default();
        bounded.missing.admit(true, true, &mut scan).unwrap();
        let mut partial = Sample::default();
        partial
            .push(Memory {
                rss: MEMORY_LIMIT + 1,
                ..small()
            })
            .unwrap();
        assert_eq!(
            bounded
                .finish_observation(GroupObservation::Pending(Box::new(scan)), partial)
                .unwrap_err()
                .kind,
            "resource_budget"
        );
        assert_eq!(bounded.evidence.sample_count, 1);
        assert!(bounded.pending());
        // An independent full Complete resolves absence; neither an old
        // diagnostic nor an empty membership scan can perform this step.
        bounded
            .finish_observation(GroupObservation::Complete(0), Sample::default())
            .unwrap();
        assert!(!bounded.pending());
        assert!(bounded.missing.is_empty());
        assert_eq!(bounded.evidence.sample_count, 2);
        assert!(bounded.evidence.pending_member_exit.is_some());
    }
    fn rusage_failure() -> MemoryFailure {
        // Authored adapter facts exercise policy only; the production adapter
        // obtains these sealed facts from the one shared native observation.
        MemoryFailure {
            native: native_exit_results()[2],
            task_lower_bound: Some(TaskMemoryLowerBound {
                adjusted_vm: 17,
                rss: 23,
            }),
            rusage_timestamps: Some(RusageTimestamps {
                start_observed: true,
                exit_observed: true,
            }),
        }
    }
    fn rusage_pending_diagnostic(native: MemoryFailure) -> LeaderDiagnostic {
        member_memory_pending(18, native)
    }
    fn member_memory_pending(pid: u32, native: impl Into<MemoryFailure>) -> LeaderDiagnostic {
        let before = LeaderBsd {
            identity: LeaderIdentity {
                pid,
                ..reserved_leader().identity
            },
            flags: PROC_FLAG_INEXIT,
            ..reserved_leader()
        };
        let MemoryObservation::Pending(diagnostic) =
            classify_memory_exit(None, before, Some(before), native).unwrap()
        else {
            panic!("same-identity member memory exit was not an incomplete sample")
        };
        diagnostic
    }
    #[test]
    fn observed_rusage_exit_requires_actual_timestamps_and_preserves_partial_facts() {
        let native = rusage_failure();
        let before = LeaderBsd {
            flags: PROC_FLAG_INEXIT,
            ..reserved_leader()
        };
        let diagnostic = rusage_pending_diagnostic(native);
        assert_eq!(diagnostic.memory_error, Some(native.native.into()));
        assert_eq!(diagnostic.memory_role, Some(MemoryRole::ObservedMember));
        assert_eq!(diagnostic.memory_task_lower_bound, native.task_lower_bound);
        assert_eq!(
            diagnostic.memory_rusage_timestamps,
            native.rusage_timestamps
        );
        assert!(!GroupObservation::Pending(Box::new(diagnostic.into())).scope_empty());
        let json = serde_json::to_value(diagnostic).unwrap();
        assert!(json.get("pending_worker").is_none());
        let debug = format!("{diagnostic:?}");
        assert!(
            !debug.contains("pid:") && !debug.contains("uid:") && !debug.contains("start_sec:")
        );
        assert_eq!(json["memory_task_lower_bound"]["adjusted_vm"], 17);
        assert_eq!(json["memory_task_lower_bound"]["rss"], 23);
        assert_eq!(json["memory_rusage_timestamps"]["start_observed"], true);
        assert_eq!(json["memory_rusage_timestamps"]["exit_observed"], true);
        assert!(json["memory_task_lower_bound"].get("footprint").is_none());
        assert!(
            json["memory_task_lower_bound"]
                .get("start_abstime")
                .is_none()
        );
        for other in [
            MemoryFailure::from(native.native),
            MemoryFailure {
                task_lower_bound: None,
                ..native
            },
            MemoryFailure {
                rusage_timestamps: None,
                ..native
            },
            MemoryFailure {
                rusage_timestamps: Some(RusageTimestamps {
                    start_observed: false,
                    exit_observed: true,
                }),
                ..native
            },
            MemoryFailure {
                rusage_timestamps: Some(RusageTimestamps {
                    start_observed: true,
                    exit_observed: false,
                }),
                ..native
            },
            MemoryFailure {
                native: NativeResourceError {
                    native_result: -1,
                    ..native.native
                },
                ..native
            },
            MemoryFailure {
                native: NativeResourceError {
                    native_errno: DARWIN_ESRCH,
                    ..native.native
                },
                ..native
            },
            MemoryFailure {
                native: NativeResourceError {
                    stage: NativeResourceStage::TaskInfo,
                    ..native.native
                },
                ..native
            },
            MemoryFailure {
                native: NativeResourceError {
                    stage: NativeResourceStage::ProcessIdentifier,
                    ..native.native
                },
                ..native
            },
            MemoryFailure {
                native: NativeResourceError {
                    failure: NativeResourceFailure::Malformed,
                    ..native.native
                },
                ..native
            },
            MemoryFailure {
                native: NativeResourceError {
                    failure: NativeResourceFailure::Unavailable,
                    ..native.native
                },
                ..native
            },
        ] {
            let error = classify_memory_exit(None, before, Some(before), other).unwrap_err();
            assert!(error.message.contains("memory_role=Some(ObservedMember)"));
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
            assert!(
                classify_memory_exit(None, before, Some(LeaderBsd { identity, ..before }), native)
                    .is_err()
            );
        }
        // The reserved leader keeps its prior typed-exit rule and role. The
        // new member rule neither opens nor closes its original reservation.
        let mut reservation = true;
        let MemoryObservation::Pending(leader) = classify_memory_exit(
            Some((before.identity, &mut reservation)),
            LeaderBsd { flags: 0, ..before },
            Some(before),
            native.native,
        )
        .unwrap() else {
            panic!("the original reserved-leader policy changed")
        };
        assert!(reservation);
        assert_eq!(leader.memory_role, Some(MemoryRole::ReservedLeader));
        assert!(leader.memory_task_lower_bound.is_none());
        assert!(leader.memory_rusage_timestamps.is_none());
        assert!(matches!(
            classify_memory_exit(
                None,
                before,
                Some(LeaderBsd {
                    status: SZOMB,
                    ..before
                }),
                native
            )
            .unwrap(),
            MemoryObservation::Zombie(_)
        ));
    }
    #[test]
    fn pending_task_lower_bounds_are_counted_once_per_scan_without_success_or_carryover() {
        let mut native = rusage_failure();
        native.task_lower_bound.as_mut().unwrap().rss = (MEMORY_LIMIT - small().rss) / 2;
        let first = rusage_pending_diagnostic(native);
        native.task_lower_bound.as_mut().unwrap().adjusted_vm += 1;
        let last = member_memory_pending(19, native);
        let task = member_memory_pending(20, native_exit_results()[0]);
        let leader = pending_diagnostic(LeaderPhase::AfterMemory);
        let mut scan = PendingObservations::default();
        for diagnostic in [first, task, last, leader] {
            scan.record(diagnostic);
        }
        assert_eq!(
            scan.task_lower_bound.unwrap().rss,
            MEMORY_LIMIT - small().rss
        );
        assert_eq!(scan.task_lower_bound.unwrap().adjusted_vm, 18);
        assert!(!scan.task_sum_overflow);
        assert_eq!(scan.workers.len, 4);
        assert_eq!(scan.member.unwrap().observations, 3);
        assert_eq!(scan.member.unwrap().first, first);
        assert_eq!(scan.member.unwrap().last, last);
        assert_eq!(scan.leader.unwrap().observations, 1);
        assert_eq!(scan.last(), Some(leader));
        let mut tracker = Tracker::new(small()).unwrap();
        let prior_success = tracker.last_success;
        // Two actual scans each fit at the original limit. Neither scan's
        // lower bound is stored in the tracker or added to the following one.
        for _ in 0..2 {
            let mut measured = Sample::default();
            measured.push(small()).unwrap();
            assert_eq!(
                tracker
                    .finish_observation(GroupObservation::Pending(Box::new(scan)), measured)
                    .unwrap(),
                ResourceObservation::Pending
            );
        }
        assert_eq!(
            tracker.evidence.pending_member_exit.unwrap().observations,
            6
        );
        assert_eq!(
            tracker.evidence.pending_leader_exit.unwrap().observations,
            2
        );
        assert_eq!(tracker.evidence.sample_count, 0);
        assert_eq!(tracker.last_success, prior_success);
        assert_eq!(tracker.evidence.peak_observed_adjusted_vm_bytes, 0);
        assert_eq!(tracker.evidence.peak_observed_aggregate_rss_bytes, 0);
        assert_eq!(tracker.evidence.peak_observed_aggregate_footprint_bytes, 0);
        assert_eq!(tracker.evidence.peak_observed_workers, 0);
        let mut measured = Sample::default();
        measured.push(small()).unwrap();
        measured
            .push_task_lower_bound(scan.task_lower_bound.unwrap())
            .unwrap();
        assert_eq!(measured.rss, MEMORY_LIMIT);
        assert_eq!(measured.footprint, small().footprint);
        assert_eq!(measured.workers, 1);
        measured.check().unwrap();

        let mut repeated = PendingObservations::default();
        let mut native = rusage_failure();
        native.task_lower_bound.as_mut().unwrap().rss = MEMORY_LIMIT / 2;
        let initial = rusage_pending_diagnostic(native);
        repeated.record(initial);
        repeated.record(initial);
        native.task_lower_bound = Some(TaskMemoryLowerBound {
            adjusted_vm: 19,
            rss: MEMORY_LIMIT,
        });
        repeated.record(rusage_pending_diagnostic(native));
        native.task_lower_bound = Some(TaskMemoryLowerBound {
            adjusted_vm: 18,
            rss: 1,
        });
        repeated.record(rusage_pending_diagnostic(native));
        repeated.record(observed_member_pending_diagnostic());
        assert_eq!(repeated.workers.len, 1);
        assert_eq!(repeated.member.unwrap().observations, 5);
        assert_eq!(
            repeated.task_lower_bound,
            Some(TaskMemoryLowerBound {
                adjusted_vm: 19,
                rss: MEMORY_LIMIT
            })
        );
        assert!(!repeated.task_sum_overflow);
        let mut deduplicated = Tracker::new(small()).unwrap();
        assert_eq!(
            deduplicated
                .finish_observation(
                    GroupObservation::Pending(Box::new(repeated)),
                    Sample::default()
                )
                .unwrap(),
            ResourceObservation::Pending
        );
        assert_eq!(deduplicated.evidence.sample_count, 0);
        assert_eq!(deduplicated.evidence.peak_observed_workers, 0);

        for (lower, twice, measured_rss, kind) in [
            (
                TaskMemoryLowerBound {
                    adjusted_vm: VM_LIMIT + 1,
                    rss: 1,
                },
                false,
                0,
                "resource_budget",
            ),
            (
                TaskMemoryLowerBound {
                    adjusted_vm: 1,
                    rss: MEMORY_LIMIT + 1,
                },
                false,
                0,
                "resource_budget",
            ),
            (
                TaskMemoryLowerBound {
                    adjusted_vm: 1,
                    rss: u64::MAX,
                },
                true,
                0,
                "resource_observation",
            ),
            (
                TaskMemoryLowerBound {
                    adjusted_vm: 1,
                    rss: u64::MAX,
                },
                false,
                1,
                "resource_observation",
            ),
        ] {
            let native = MemoryFailure {
                task_lower_bound: Some(lower),
                ..rusage_failure()
            };
            let diagnostic = rusage_pending_diagnostic(native);
            let mut scan = PendingObservations::from(diagnostic);
            if twice {
                scan.record(member_memory_pending(19, native));
            }
            let mut partial = Sample::default();
            partial
                .push(Memory {
                    rss: measured_rss,
                    ..small()
                })
                .unwrap();
            let mut failed = Tracker::new(small()).unwrap();
            let prior_success = failed.last_success;
            assert_eq!(
                failed
                    .finish_observation(GroupObservation::Pending(Box::new(scan)), partial)
                    .unwrap_err()
                    .kind,
                kind
            );
            assert_eq!(failed.evidence.sample_count, 0);
            assert_eq!(failed.last_success, prior_success);
            assert_eq!(
                failed.evidence.pending_member_exit.unwrap().observations,
                if twice { 2 } else { 1 }
            );
            // A later original failure keeps its own kind, message and drain
            // state. Retaining scan diagnostics cannot apply its budget twice.
            let mut hard_failure = Tracker::new(small()).unwrap();
            hard_failure.record_pending_observations(scan);
            let mut original =
                ProcessError::new("process_identity", "later original identity failure");
            original.drained = false;
            let retained = hard_failure.with_pending_diagnostics(original);
            assert_eq!(retained.kind, "process_identity");
            assert!(!retained.drained);
            assert!(
                retained
                    .message
                    .starts_with("later original identity failure;")
            );
            assert_eq!(hard_failure.evidence.sample_count, 0);
            assert_eq!(
                hard_failure
                    .finish_observation(
                        GroupObservation::Pending(Box::new(
                            rusage_pending_diagnostic(rusage_failure()).into()
                        )),
                        Sample::default()
                    )
                    .unwrap(),
                ResourceObservation::Pending
            );
        }
    }
    #[test]
    fn pending_workers_enforce_the_original_limit_without_duplicate_or_historical_counts() {
        fn measured_workers(count: usize) -> Sample {
            let mut sample = Sample::default();
            for _ in 0..count {
                sample.push(small()).unwrap();
            }
            sample
        }
        let member = observed_member_pending_diagnostic();
        let leader = pending_diagnostic(LeaderPhase::BeforeMemory);
        let rusage = member_memory_pending(19, rusage_failure());
        for (events, workers) in [
            (vec![member], 1),
            (vec![leader], 1),
            (vec![member, leader], 2),
            (vec![member, rusage, leader, member], 3),
        ] {
            let mut scan = PendingObservations::default();
            for event in &events {
                scan.record(*event);
            }
            assert_eq!(scan.workers.len, workers);
            let member_observations = events
                .iter()
                .filter(|event| event.memory_role == Some(MemoryRole::ObservedMember))
                .count() as u64;
            let leader_observations = events.len() as u64 - member_observations;
            let mut tracker = Tracker::new(small()).unwrap();
            let prior_success = tracker.last_success;
            // Each scan has at most 32 known workers. The same pending worker
            // is added once, and neither scan changes successful sample data.
            for _ in 0..2 {
                assert_eq!(
                    tracker
                        .finish_observation(
                            GroupObservation::Pending(Box::new(scan)),
                            measured_workers(WORKER_LIMIT - workers),
                        )
                        .unwrap(),
                    ResourceObservation::Pending
                );
            }
            assert_eq!(
                tracker
                    .evidence
                    .pending_member_exit
                    .map_or(0, |facts| facts.observations),
                member_observations * 2
            );
            assert_eq!(
                tracker
                    .evidence
                    .pending_leader_exit
                    .map_or(0, |facts| facts.observations),
                leader_observations * 2
            );
            assert_eq!(tracker.last_success, prior_success);
            assert_eq!(tracker.evidence.sample_count, 0);
            assert_eq!(tracker.evidence.peak_observed_workers, 0);
            let mut over_budget = Tracker::new(small()).unwrap();
            let prior_success = over_budget.last_success;
            let error = over_budget
                .finish_observation(
                    GroupObservation::Pending(Box::new(scan)),
                    measured_workers(WORKER_LIMIT + 1 - workers),
                )
                .unwrap_err();
            assert_eq!(error.kind, "resource_budget");
            assert!(error.message.contains("workers=33"));
            assert_eq!(over_budget.last_success, prior_success);
            assert_eq!(over_budget.evidence.sample_count, 0);
            assert_eq!(over_budget.evidence.peak_observed_workers, 0);
        }
        let after_memory = pending_diagnostic(LeaderPhase::AfterMemory);
        let mut known_memory = measured_workers(WORKER_LIMIT - 1);
        known_memory.push_memory_lower_bound(small()).unwrap();
        assert_eq!(known_memory.workers, WORKER_LIMIT - 1);
        assert_eq!(known_memory.rss, small().rss * WORKER_LIMIT as u64);
        assert_eq!(
            known_memory.footprint,
            small().footprint * WORKER_LIMIT as u64
        );
        let mut tracker = Tracker::new(small()).unwrap();
        let prior_success = tracker.last_success;
        assert_eq!(
            tracker
                .finish_observation(
                    GroupObservation::Pending(Box::new(after_memory.into())),
                    known_memory
                )
                .unwrap(),
            ResourceObservation::Pending
        );
        assert_eq!(tracker.last_success, prior_success);
        assert_eq!(tracker.evidence.sample_count, 0);
        assert_eq!(tracker.evidence.peak_observed_adjusted_vm_bytes, 0);
        assert_eq!(tracker.evidence.peak_observed_aggregate_rss_bytes, 0);
        assert_eq!(tracker.evidence.peak_observed_aggregate_footprint_bytes, 0);
        assert_eq!(tracker.evidence.peak_observed_workers, 0);
        assert_eq!(
            tracker.evidence.pending_leader_exit.unwrap().observations,
            1
        );
        for memory in [
            Memory {
                adjusted_vm: VM_LIMIT + 1,
                ..small()
            },
            Memory {
                rss: MEMORY_LIMIT + 1,
                ..small()
            },
            Memory {
                footprint: MEMORY_LIMIT + 1,
                ..small()
            },
        ] {
            let mut known_memory = Sample::default();
            known_memory.push_memory_lower_bound(memory).unwrap();
            assert_eq!(known_memory.workers, 0);
            let mut tracker = Tracker::new(small()).unwrap();
            let prior_success = tracker.last_success;
            assert_eq!(
                tracker
                    .finish_observation(
                        GroupObservation::Pending(Box::new(after_memory.into())),
                        known_memory
                    )
                    .unwrap_err()
                    .kind,
                "resource_budget"
            );
            assert_eq!(tracker.last_success, prior_success);
            assert_eq!(tracker.evidence.sample_count, 0);
            assert_eq!(tracker.evidence.peak_observed_adjusted_vm_bytes, 0);
            assert_eq!(tracker.evidence.peak_observed_aggregate_rss_bytes, 0);
            assert_eq!(tracker.evidence.peak_observed_aggregate_footprint_bytes, 0);
            assert_eq!(tracker.evidence.peak_observed_workers, 0);
            assert_eq!(
                tracker.evidence.pending_leader_exit.unwrap().observations,
                1
            );
        }
        for memory in [
            Memory {
                rss: u64::MAX,
                ..small()
            },
            Memory {
                footprint: u64::MAX,
                ..small()
            },
        ] {
            // Match the caller's order: retain Pending before adding the
            // already measured values, including when their sum overflows.
            let mut scan = PendingObservations::default();
            scan.record(after_memory);
            let mut known_memory = measured_workers(1);
            let mut error = known_memory.push_memory_lower_bound(memory).unwrap_err();
            assert_eq!(error.kind, "resource_observation");
            error.drained = false;
            let mut tracker = Tracker::new(small()).unwrap();
            tracker.record_pending_observations(scan);
            let error = tracker.with_pending_diagnostics(error);
            assert_eq!(error.kind, "resource_observation");
            assert!(!error.drained);
            assert!(
                error
                    .message
                    .starts_with("Darwin native resource sum overflow;")
            );
            assert_eq!(
                tracker.evidence.pending_leader_exit.unwrap().observations,
                1
            );
            assert_eq!(tracker.evidence.sample_count, 0);
            assert_eq!(tracker.evidence.peak_observed_workers, 0);
        }
        let mut many = PendingObservations::default();
        for index in 0..WORKER_LIMIT + 2 {
            many.record(member_memory_pending(
                100 + index as u32,
                native_exit_results()[0],
            ));
        }
        assert_eq!(many.workers.len, WORKER_LIMIT + 1);
        assert_eq!(many.member.unwrap().observations, (WORKER_LIMIT + 2) as u64);
        let mut tracker = Tracker::new(small()).unwrap();
        assert_eq!(
            tracker
                .finish_observation(GroupObservation::Pending(Box::new(many)), Sample::default())
                .unwrap_err()
                .kind,
            "resource_budget"
        );
        let mut overflow = Tracker::new(small()).unwrap();
        assert_eq!(
            overflow
                .finish_observation(
                    GroupObservation::Pending(Box::new(member.into())),
                    Sample {
                        workers: usize::MAX,
                        ..Sample::default()
                    },
                )
                .unwrap_err()
                .kind,
            "resource_observation"
        );
        assert_eq!(overflow.evidence.sample_count, 0);

        let before = LeaderBsd {
            identity: LeaderIdentity {
                pid: 18,
                ..reserved_leader().identity
            },
            flags: PROC_FLAG_INEXIT,
            ..reserved_leader()
        };
        for native in [
            MemoryFailure::from(native_exit_results()[0]),
            rusage_failure(),
        ] {
            let MemoryObservation::Zombie(zombie) = classify_memory_exit(
                None,
                before,
                Some(LeaderBsd {
                    status: SZOMB,
                    ..before
                }),
                native,
            )
            .unwrap() else {
                panic!("expected the existing native zombie classification")
            };
            assert!(zombie.pending_worker.is_none());
            let mut excluded = PendingObservations::default();
            // Production records this in native_memory_exits only. Even a direct
            // diagnostic record cannot issue a pending-worker identity for SZOMB.
            excluded.record(zombie);
            assert_eq!(excluded.workers.len, 0);
            assert!(excluded.task_lower_bound.is_none());
        }
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
            identity: LeaderIdentity {
                pid: 19,
                ..reserved_leader().identity
            },
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
            assert_eq!(scan.workers.len, events.len());
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
    fn member_exit_transition_needs_one_actual_same_identity_zombie_confirmation() {
        let before = LeaderBsd {
            identity: LeaderIdentity {
                pid: 18,
                ..reserved_leader().identity
            },
            ..reserved_leader()
        };
        let first_after = LeaderBsd {
            flags: PROC_FLAG_INEXIT,
            ..before
        };
        let zombie = LeaderBsd {
            status: SZOMB,
            ..first_after
        };
        let native = native_exit_results()[0].into();
        let mut queries = 0;
        let Some(MemoryObservation::Zombie(diagnostic)) =
            confirm_member_memory_exit(before, first_after, native, || {
                queries += 1;
                Ok((Some(zombie), before.identity.uid))
            })
            .unwrap()
        else {
            panic!("actual same-identity zombie was not confirmed")
        };
        assert_eq!(queries, 1);
        assert_eq!(diagnostic.before_status, Some(2));
        assert_eq!(diagnostic.after_status, Some(2));
        assert!(!diagnostic.before_inexit && diagnostic.after_inexit);
        assert_eq!(diagnostic.memory_error, Some(native.native.into()));
        let confirmation = diagnostic.memory_exit_confirmation.unwrap();
        assert_eq!(confirmation.kind, "observed");
        assert_eq!(confirmation.status, Some(SZOMB));
        assert_eq!(confirmation.identity_match, Some(true));
        assert_eq!(confirmation.current_uid_match, Some(true));

        let mut confirmations = vec![None, Some(first_after)];
        confirmations.extend([0, 1, 2, 3, 4, 6, u32::MAX].map(|status| {
            Some(LeaderBsd {
                status,
                ..first_after
            })
        }));
        for identity in [
            LeaderIdentity {
                pid: 19,
                ..before.identity
            },
            LeaderIdentity {
                uid: 502,
                ..before.identity
            },
            LeaderIdentity {
                pgid: 19,
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
            confirmations.push(Some(LeaderBsd { identity, ..zombie }));
        }
        for confirmed in confirmations {
            let mut queries = 0;
            let error = confirm_member_memory_exit(before, first_after, native, || {
                queries += 1;
                Ok((confirmed, before.identity.uid))
            })
            .unwrap_err();
            assert_eq!(queries, 1);
            assert!(
                error
                    .message
                    .contains("before_status=Some(2),after_status=Some(2)")
            );
            assert!(error.message.contains("memory_stage=task_info"));
            assert!(error.message.contains("memory_confirmation_kind="));
        }
        let original = ProcessError::new("io", "actual confirmation query unavailable");
        let error =
            confirm_member_memory_exit(before, first_after, native, || Err(original)).unwrap_err();
        assert_eq!(error.kind, "io");
        assert!(
            error
                .message
                .starts_with("actual confirmation query unavailable;")
        );
        assert!(
            error
                .message
                .contains("memory_confirmation_kind=query_error")
        );
        let error = confirm_member_memory_exit(before, first_after, native, || {
            Ok((Some(zombie), before.identity.uid + 1))
        })
        .unwrap_err();
        assert!(
            error
                .message
                .contains("memory_confirmation_current_uid_match=Some(false)")
        );
    }
    #[test]
    fn ineligible_member_exit_facts_never_authorize_the_confirmation_query() {
        let before = LeaderBsd {
            identity: LeaderIdentity {
                pid: 18,
                ..reserved_leader().identity
            },
            ..reserved_leader()
        };
        let first_after = LeaderBsd {
            flags: PROC_FLAG_INEXIT,
            ..before
        };
        let task_exit = native_exit_results()[0];
        let mut invalid = vec![
            (
                reserved_leader(),
                LeaderBsd {
                    flags: PROC_FLAG_INEXIT,
                    ..reserved_leader()
                },
                task_exit,
            ),
            (first_after, first_after, task_exit),
            (before, before, task_exit),
            (
                before,
                LeaderBsd {
                    status: SZOMB,
                    ..first_after
                },
                task_exit,
            ),
            (before, first_after, native_exit_results()[1]),
            (before, first_after, native_exit_results()[2]),
            (
                before,
                first_after,
                NativeResourceError {
                    native_result: -1,
                    ..task_exit
                },
            ),
            (
                before,
                first_after,
                NativeResourceError {
                    native_errno: 1,
                    ..task_exit
                },
            ),
            (
                before,
                first_after,
                NativeResourceError {
                    stage: NativeResourceStage::ProcessIdentifier,
                    ..task_exit
                },
            ),
        ];
        for status in [0, SZOMB, 6, u32::MAX] {
            invalid.push((LeaderBsd { status, ..before }, first_after, task_exit));
            invalid.push((
                before,
                LeaderBsd {
                    status,
                    ..first_after
                },
                task_exit,
            ));
        }
        for identity in [
            LeaderIdentity {
                pid: 19,
                ..before.identity
            },
            LeaderIdentity {
                uid: 502,
                ..before.identity
            },
            LeaderIdentity {
                pgid: 19,
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
            invalid.push((
                before,
                LeaderBsd {
                    identity,
                    ..first_after
                },
                task_exit,
            ));
        }
        for (before, after, native) in invalid {
            let mut queries = 0;
            assert!(
                confirm_member_memory_exit(before, after, native.into(), || {
                    queries += 1;
                    Ok((
                        Some(LeaderBsd {
                            status: SZOMB,
                            ..after
                        }),
                        before.identity.uid,
                    ))
                })
                .unwrap()
                .is_none()
            );
            assert_eq!(queries, 0);
        }
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
            rusage_pending_diagnostic(rusage_failure()),
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
            rusage_pending_diagnostic(rusage_failure()),
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

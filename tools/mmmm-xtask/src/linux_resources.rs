//! Cooperative Linux process-group observations through anchored procfs files.
//!
//! RSS is a sequential sum of per-process smaps_rollup observations. Shared
//! pages occur in each process's RSS; this is neither a simultaneous group
//! snapshot nor a kernel resident-memory quota. Detached sessions are outside
//! the cooperative ownership boundary.
use super::ProcessError;
use serde::Serialize;
use std::fmt;

#[path = "linux_pidfd.rs"]
mod pidfd;
pub(super) use pidfd::Diagnostic as PidfdDiagnostic;

const STAT_BYTES: usize = 8192;
const ROLLUP_BYTES: usize = 32 * 1024;
#[cfg(target_os = "linux")]
const DIRECTORY_ENTRIES: usize = 100_000;
pub(super) const LIVE_LIMIT: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    pid: i32,
    start_ticks: u64,
    group: i32,
    session: i32,
}

#[derive(Clone, Copy, Debug)]
struct Stat {
    identity: Identity,
    state: u8,
    threads: u64,
    virtual_bytes: u64,
}

impl Stat {
    fn definitely_exited(self) -> bool {
        matches!(self.state, b'Z' | b'X' | b'x') && self.threads <= 1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StatState {
    Running,
    Sleeping,
    DiskSleep,
    Zombie,
    Stopped,
    Dead,
    DeadLower,
    TracingStop,
    Wakekill,
    Waking,
    Parked,
    Idle,
}

impl StatState {
    fn observed(state: u8) -> Option<Self> {
        match state {
            b'R' => Some(Self::Running),
            b'S' => Some(Self::Sleeping),
            b'D' => Some(Self::DiskSleep),
            b'Z' => Some(Self::Zombie),
            b'T' => Some(Self::Stopped),
            b'X' => Some(Self::Dead),
            b'x' => Some(Self::DeadLower),
            b't' => Some(Self::TracingStop),
            b'K' => Some(Self::Wakekill),
            b'W' => Some(Self::Waking),
            b'P' => Some(Self::Parked),
            b'I' => Some(Self::Idle),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct IdentityMatches {
    pid: bool,
    start_ticks: bool,
    group: bool,
    session: bool,
}

impl IdentityMatches {
    fn observed(original: Identity, observed: Identity) -> Self {
        Self {
            pid: original.pid == observed.pid,
            start_ticks: original.start_ticks == observed.start_ticks,
            group: original.group == observed.group,
            session: original.session == observed.session,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PidfdBindingState {
    NotRequiredBySample,
    NotAttempted,
    BoundValidated,
    Unavailable,
    OriginalGone,
    Failed,
}

/// Diagnostic-only facts from reads the observer already performed. No native
/// identity values, path, comm or original procfs tokens are retained here.
/// Missing observations stay absent and grant no exit or drain authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(super) struct StatDiagnostic {
    role: ProcessRole,
    before_state: Option<StatState>,
    before_threads: Option<u64>,
    before_original_identity_match: Option<bool>,
    before_identity_matches: Option<IdentityMatches>,
    after_state: Option<StatState>,
    after_threads: Option<u64>,
    after_original_identity_match: Option<bool>,
    after_identity_matches: Option<IdentityMatches>,
    after_group_detached_sentinel: Option<bool>,
    after_session_detached_sentinel: Option<bool>,
    pidfd_binding: PidfdBindingState,
    pidfd_binding_observation: Option<PidfdDiagnostic>,
    pidfd_terminal_observation: Option<PidfdDiagnostic>,
}

impl StatDiagnostic {
    fn observed(
        role: ProcessRole,
        original: Identity,
        before: Option<Stat>,
        after: Option<Stat>,
        include_rss: bool,
    ) -> Self {
        Self {
            role,
            before_state: before.and_then(|stat| StatState::observed(stat.state)),
            before_threads: before.map(|stat| stat.threads),
            before_original_identity_match: before.map(|stat| stat.identity == original),
            before_identity_matches: before
                .map(|stat| IdentityMatches::observed(original, stat.identity)),
            after_state: after.and_then(|stat| StatState::observed(stat.state)),
            after_threads: after.map(|stat| stat.threads),
            after_original_identity_match: after.map(|stat| stat.identity == original),
            after_identity_matches: after
                .map(|stat| IdentityMatches::observed(original, stat.identity)),
            after_group_detached_sentinel: after.map(|stat| stat.identity.group == -1),
            after_session_detached_sentinel: after.map(|stat| stat.identity.session == -1),
            pidfd_binding: if include_rss {
                PidfdBindingState::NotAttempted
            } else {
                PidfdBindingState::NotRequiredBySample
            },
            pidfd_binding_observation: None,
            pidfd_terminal_observation: None,
        }
    }

    fn record_stats(&mut self, original: Identity, before: Option<Stat>, after: Option<Stat>) {
        // Updating the existing stat facts must not erase a binding or poll
        // that the same observation already performed. No new proof is made.
        *self = Self {
            pidfd_binding: self.pidfd_binding,
            pidfd_binding_observation: self.pidfd_binding_observation,
            pidfd_terminal_observation: self.pidfd_terminal_observation,
            ..Self::observed(
                self.role,
                original,
                before,
                after,
                self.pidfd_binding != PidfdBindingState::NotRequiredBySample,
            )
        };
    }
}

impl fmt::Display for StatDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "linux_stat_observation(process_role={}; before_state={:?}; before_threads={:?}; before_original_identity_match={:?}; before_identity_matches={:?}; after_state={:?}; after_threads={:?}; after_original_identity_match={:?}; after_identity_matches={:?}; after_group_detached_sentinel={:?}; after_session_detached_sentinel={:?}; pidfd_binding={:?}",
            self.role.label(),
            self.before_state,
            self.before_threads,
            self.before_original_identity_match,
            self.before_identity_matches,
            self.after_state,
            self.after_threads,
            self.after_original_identity_match,
            self.after_identity_matches,
            self.after_group_detached_sentinel,
            self.after_session_detached_sentinel,
            self.pidfd_binding,
        )?;
        for (label, observation) in [
            ("pidfd_binding_observation", self.pidfd_binding_observation),
            (
                "pidfd_terminal_observation",
                self.pidfd_terminal_observation,
            ),
        ] {
            write!(f, "; {label}=")?;
            if let Some(observation) = observation {
                write!(f, "Some({observation})")?;
            } else {
                write!(f, "None")?;
            }
        }
        write!(f, ")")
    }
}

/// A count-only observation has no RSS value. A memory observation also leaves
/// RSS absent once the live-count limit is exceeded: incomplete memory is never
/// presented as zero or as a complete successful sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Sample {
    pub live_processes: usize,
    pub aggregate_rss_bytes: Option<u64>,
    // Only actually read RSS values contribute. This remains a lower bound
    // when one member is Pending; it never becomes a complete RSS sample.
    pub known_rss_bytes: u64,
    pub max_virtual_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum GroupObservation {
    Complete(Sample),
    Pending(Sample),
}

impl GroupObservation {
    pub(super) fn scope_empty(&self) -> bool {
        matches!(self, Self::Complete(sample) if sample.live_processes == 0)
    }
}

/// Only closed facts from the actual failed RSS read and its existing stat /
/// pidfd observations. No native identity or terminal witness is retained.
#[derive(Clone, Debug, Serialize)]
pub struct PendingObservation {
    role: PendingRole,
    original_error_kind: &'static str,
    original_error: String,
    original_drained: bool,
    stat_observation: StatDiagnostic,
}

impl PendingObservation {
    fn new(error: ProcessError, stat_observation: StatDiagnostic, role: PendingRole) -> Self {
        Self {
            role,
            original_error_kind: error.kind,
            original_error: error.message,
            original_drained: error.drained,
            stat_observation,
        }
    }

    pub(super) fn original_error(&self) -> ProcessError {
        let mut error = ProcessError::new(self.original_error_kind, &self.original_error);
        error.drained = self.original_drained;
        if let Some(observation) = self.stat_observation.pidfd_terminal_observation {
            error = error.with_linux_pidfd_diagnostic(observation);
        }
        error.with_linux_stat_diagnostic(self.stat_observation)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingHistory {
    pub(super) count: u64,
    pub(super) first: PendingObservation,
    pub(super) last: PendingObservation,
}

impl PendingHistory {
    pub(super) fn record(history: &mut Option<Box<Self>>, observation: PendingObservation) {
        if let Some(history) = history {
            history.count = history.count.saturating_add(1);
            history.last = observation;
        } else {
            *history = Some(Box::new(Self {
                count: 1,
                first: observation.clone(),
                last: observation,
            }));
        }
    }

    pub(super) fn merge(history: &mut Option<Box<Self>>, incoming: Box<Self>) {
        if let Some(history) = history {
            history.count = history.count.saturating_add(incoming.count);
            history.last = incoming.last;
        } else {
            *history = Some(incoming);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PendingRole {
    ReservedLeader,
    OwnedMember,
}

impl PendingRole {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::ReservedLeader => "leader",
            Self::OwnedMember => "owned member",
        }
    }
}

/// Bounded per-role facts from one scan. Counts refer to observations, not
/// unique processes. The last role preserves ordering without retaining PID
/// values or a list of members. This collector has no native authority.
#[derive(Default)]
pub(super) struct PendingObservations {
    pub leader: Option<Box<PendingHistory>>,
    pub member: Option<Box<PendingHistory>>,
    pub last_role: Option<PendingRole>,
}

impl PendingObservations {
    pub(super) fn record(&mut self, observation: PendingObservation) {
        let role = observation.role;
        let history = match role {
            PendingRole::ReservedLeader => &mut self.leader,
            PendingRole::OwnedMember => &mut self.member,
        };
        PendingHistory::record(history, observation);
        self.last_role = Some(role);
    }

    pub(super) fn is_empty(&self) -> bool {
        self.last_role.is_none()
    }
}

impl From<PendingObservation> for PendingObservations {
    fn from(observation: PendingObservation) -> Self {
        let mut observations = Self::default();
        observations.record(observation);
        observations
    }
}

enum RssFailure {
    Open(std::io::Error),
    Read(std::io::Error),
    Parse(ProcessError),
}

impl RssFailure {
    fn open_esrch(&self) -> bool {
        matches!(self, Self::Open(error) if error.raw_os_error() == Some(3))
    }

    fn into_process_error(self, role: ProcessRole) -> ProcessError {
        match self {
            Self::Open(error) => metadata_io_error(
                role,
                MetadataRole::RssRollup,
                MetadataOperation::Open,
                error,
            ),
            Self::Read(error) => metadata_io_error(
                role,
                MetadataRole::RssRollup,
                MetadataOperation::Read,
                error,
            ),
            Self::Parse(error) => error,
        }
    }
}

#[derive(Clone, Copy)]
struct OwnerContext {
    leader: Identity,
    reservation_valid: bool,
}

#[derive(Clone, Copy)]
struct PendingConditions {
    role: ProcessRole,
    owner: OwnerContext,
    bound_validated: bool,
    terminal: Option<PidfdDiagnostic>,
}

// This predicate grants no exit, drain or complete-sample authority. The
// native caller supplies these conditions only from its held reservation and
// an actual already validated whole-thread-group pidfd check.
fn pending_exit_transition(
    original: Identity,
    before: Stat,
    after: Option<Stat>,
    failure: &RssFailure,
    conditions: PendingConditions,
) -> bool {
    let leader = conditions.owner.leader;
    let role_matches_anchor = match conditions.role {
        ProcessRole::ReservedLeader => original == leader,
        ProcessRole::OwnedMember => {
            original.pid > 0
                && original.pid != leader.pid
                && original.group == leader.group
                && original.session == leader.session
        }
        ProcessRole::EnumeratedCandidate => false,
    };
    conditions.owner.reservation_valid
        && leader.pid > 0
        && leader.group == leader.pid
        && leader.session == leader.pid
        && role_matches_anchor
        && conditions.bound_validated
        && conditions
            .terminal
            .is_some_and(PidfdDiagnostic::terminal_not_ready)
        && before.identity == original
        && before.state == b'Z'
        && before.threads == 2
        && after.is_some_and(|after| {
            after.identity == original && after.state == b'Z' && after.threads == 2
        })
        && failure.open_esrch()
}

#[derive(Clone, Copy, Debug)]
struct MemberSample {
    live: bool,
    virtual_bytes: u64,
    rss: Option<u64>,
}

enum MemberObservation {
    Settled(Option<MemberSample>),
    Pending(MemberSample, Box<PendingObservation>),
}

fn accumulate(
    sample: &mut Sample,
    observation: MemberObservation,
    pending: &mut PendingObservations,
) -> Result<(), ProcessError> {
    match observation {
        MemberObservation::Settled(Some(member)) => push(sample, member)?,
        MemberObservation::Settled(None) => {}
        MemberObservation::Pending(member, observation) => {
            // Retain this fact before any subsequent partial budget,
            // enumeration, member or final leader check can fail.
            pending.record(*observation);
            push(sample, member)?;
        }
    }
    if !pending.is_empty() {
        super::resource_policy::check_linux_jvm_budget(
            sample.live_processes,
            Some(sample.known_rss_bytes),
            sample.max_virtual_bytes,
        )?;
    }
    Ok(())
}

fn push(sample: &mut Sample, member: MemberSample) -> Result<(), ProcessError> {
    if member.live {
        sample.live_processes = sample
            .live_processes
            .checked_add(1)
            .ok_or_else(|| metadata("native live process count overflow"))?;
    }
    sample.max_virtual_bytes = sample.max_virtual_bytes.max(member.virtual_bytes);
    if let Some(rss) = member.rss {
        sample.known_rss_bytes = sample
            .known_rss_bytes
            .checked_add(rss)
            .ok_or_else(|| metadata("native RSS sum overflow"))?;
    }
    sample.aggregate_rss_bytes = match (sample.aggregate_rss_bytes, member.rss) {
        (Some(sum), Some(rss)) => Some(
            sum.checked_add(rss)
                .ok_or_else(|| metadata("native RSS sum overflow"))?,
        ),
        _ => None,
    };
    Ok(())
}

/// `after=None` is permitted only when the original already opened stat FD's
/// actual read confirmed task disappearance. Callers cannot infer it from an
/// RSS error, a missing pathname, or a fresh PID lookup.
fn settle_member(
    before: Stat,
    after: Option<Stat>,
    memory: Option<Result<u64, ProcessError>>,
    is_leader: bool,
) -> Result<Option<MemberSample>, ProcessError> {
    settle_member_with_terminal(before, after, memory, is_leader, None)
}

fn settle_member_with_terminal(
    before: Stat,
    after: Option<Stat>,
    memory: Option<Result<u64, ProcessError>>,
    is_leader: bool,
    terminal: Option<&pidfd::TerminalWitness>,
) -> Result<Option<MemberSample>, ProcessError> {
    if after.is_none() && is_leader {
        return Err(ProcessError::new(
            "process_identity",
            "reserved Linux leader disappeared during resource observation",
        ));
    }
    if let Some(after) = after {
        verify_identity(before, after)?;
    }
    let kernel_terminal = after.is_some_and(|after| {
        terminal.is_some_and(|witness| witness.matches(before.identity, after.identity))
    });
    let live = after.is_some_and(|stat| !stat.definitely_exited()) && !kernel_terminal;
    let rss = match memory {
        Some(Ok(rss)) => Some(rss),
        Some(Err(error)) if live => return Err(error),
        Some(Err(_)) | None => None,
    };
    if !live && rss.is_none() {
        return Ok(None);
    }
    Ok(Some(MemberSample {
        live,
        virtual_bytes: before
            .virtual_bytes
            .max(after.map_or(0, |stat| stat.virtual_bytes)),
        rss,
    }))
}

fn metadata(message: &'static str) -> ProcessError {
    ProcessError::new("resource_observation", message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProcessRole {
    ReservedLeader,
    EnumeratedCandidate,
    OwnedMember,
}

impl ProcessRole {
    fn label(self) -> &'static str {
        match self {
            Self::ReservedLeader => "reserved_leader",
            Self::EnumeratedCandidate => "enumerated_candidate",
            Self::OwnedMember => "owned_member",
        }
    }
}

#[derive(Clone, Copy)]
enum MetadataRole {
    PidDirectory,
    Stat,
    RssRollup,
}

impl MetadataRole {
    fn label(self) -> &'static str {
        match self {
            Self::PidDirectory => "pid_directory",
            Self::Stat => "stat",
            Self::RssRollup => "rss_rollup",
        }
    }

    #[cfg(target_os = "linux")]
    fn file_name(self) -> Result<&'static std::ffi::CStr, ProcessError> {
        match self {
            Self::Stat => Ok(c"stat"),
            Self::RssRollup => Ok(c"smaps_rollup"),
            Self::PidDirectory => Err(metadata("PID directory is not a fixed metadata file")),
        }
    }
}

#[derive(Clone, Copy)]
enum MetadataOperation {
    Open,
    Rewind,
    Read,
}

impl MetadataOperation {
    fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Rewind => "rewind",
            Self::Read => "read",
        }
    }
}

fn metadata_io_error(
    process: ProcessRole,
    file: MetadataRole,
    operation: MetadataOperation,
    error: std::io::Error,
) -> ProcessError {
    // All context comes from closed roles. Neither the numeric PID, native
    // pathname, comm, raw procfs tokens nor the OS message enters the receipt.
    ProcessError::new(
        "resource_observation",
        format!(
            "native process metadata failed; process_role={}; file_role={}; operation={}; error_kind={:?}; os_error={:?}",
            process.label(),
            file.label(),
            operation.label(),
            error.kind(),
            error.raw_os_error(),
        ),
    )
}

#[derive(Clone, Copy)]
enum NumericField {
    StatPid,
    DirectoryPid,
    ProcessGroup,
    Session,
    ThreadCount,
    StartTicks,
    VirtualBytes,
    RssKib,
}

impl NumericField {
    fn role(self) -> &'static str {
        match self {
            Self::StatPid => "stat_pid",
            Self::DirectoryPid => "directory_pid",
            Self::ProcessGroup => "process_group",
            Self::Session => "session",
            Self::ThreadCount => "thread_count",
            Self::StartTicks => "start_ticks",
            Self::VirtualBytes => "virtual_bytes",
            Self::RssKib => "rss_kib",
        }
    }
}

#[derive(Clone, Copy)]
enum NumericFailure {
    Empty,
    InvalidDecimal,
    Overflow,
    NonPositive,
}

impl NumericFailure {
    fn category(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::InvalidDecimal => "invalid_decimal",
            Self::Overflow => "overflow",
            Self::NonPositive => "non_positive",
        }
    }
}

fn numeric_error(field: NumericField, failure: NumericFailure) -> ProcessError {
    // Both labels come from closed enums. Never include the original token,
    // comm, pathname, or other native process data in this diagnostic.
    ProcessError::new(
        "resource_observation",
        format!(
            "native process numeric field rejected; field={}; category={}",
            field.role(),
            failure.category(),
        ),
    )
}

fn parse_stat(bytes: &[u8], expected_pid: i32) -> Result<Stat, ProcessError> {
    if bytes.len() > STAT_BYTES || expected_pid <= 0 {
        return Err(metadata("native process stat exceeds its bound"));
    }
    let begin = bytes
        .iter()
        .position(|byte| *byte == b'(')
        .ok_or_else(|| metadata("native process stat has no comm boundary"))?;
    let end = bytes
        .iter()
        .rposition(|byte| *byte == b')')
        .filter(|end| *end > begin)
        .ok_or_else(|| metadata("native process stat has no comm terminator"))?;
    let pid = positive_pid(trim(&bytes[..begin]), NumericField::StatPid)?;
    if pid != expected_pid {
        return Err(ProcessError::new(
            "process_identity",
            "native process stat PID differs from its anchored directory",
        ));
    }
    let fields: Vec<_> = bytes[end + 1..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect();
    // Indices start at field 3 (state): num_threads is 20, starttime is 22,
    // and vsize is 23. RSS field 24 is deliberately not used as precise RSS.
    if fields.len() < 21 || fields[0].len() != 1 || !b"RSDZTXxtKWPI".contains(&fields[0][0]) {
        return Err(metadata(
            "native process stat fields are incomplete or invalid",
        ));
    }
    let stat = Stat {
        identity: Identity {
            pid,
            group: signed(fields[2], NumericField::ProcessGroup)?,
            session: signed(fields[3], NumericField::Session)?,
            start_ticks: unsigned(fields[19], NumericField::StartTicks)?,
        },
        state: fields[0][0],
        threads: unsigned(fields[17], NumericField::ThreadCount)?,
        virtual_bytes: unsigned(fields[20], NumericField::VirtualBytes)?,
    };
    if !stat.definitely_exited() && stat.threads == 0 {
        return Err(metadata("live native process has no thread count"));
    }
    Ok(stat)
}

fn parse_rollup(bytes: &[u8]) -> Result<u64, ProcessError> {
    if bytes.len() > ROLLUP_BYTES {
        return Err(metadata("native RSS rollup exceeds its bound"));
    }
    let mut rss = None;
    for line in bytes.split(|byte| *byte == b'\n') {
        if let Some(value) = line.strip_prefix(b"Rss:") {
            if rss.is_some() {
                return Err(metadata("native RSS rollup contains duplicate Rss fields"));
            }
            let fields: Vec<_> = value
                .split(|byte| byte.is_ascii_whitespace())
                .filter(|field| !field.is_empty())
                .collect();
            if fields.len() != 2 || fields[1] != b"kB" {
                return Err(metadata("native RSS rollup has an invalid unit or value"));
            }
            rss = Some(
                unsigned(fields[0], NumericField::RssKib)?
                    .checked_mul(1024)
                    .ok_or_else(|| metadata("native RSS byte conversion overflow"))?,
            );
        }
    }
    rss.ok_or_else(|| metadata("native RSS rollup is missing its Rss field"))
}

fn trim(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn unsigned(bytes: &[u8], field: NumericField) -> Result<u64, ProcessError> {
    if bytes.is_empty() {
        return Err(numeric_error(field, NumericFailure::Empty));
    }
    if !bytes.iter().all(u8::is_ascii_digit) {
        return Err(numeric_error(field, NumericFailure::InvalidDecimal));
    }
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| numeric_error(field, NumericFailure::Overflow))
}

fn signed(bytes: &[u8], field: NumericField) -> Result<i32, ProcessError> {
    // Linux stat fields 5 and 6 use signed decimal output. In particular,
    // fs/proc/array.c initializes pgid/sid to -1 before task signal locking.
    // seq_put_decimal_ll emits digits with an optional minus, never a plus.
    let digits = bytes.strip_prefix(b"-").unwrap_or(bytes);
    if bytes.is_empty() {
        return Err(numeric_error(field, NumericFailure::Empty));
    }
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(numeric_error(field, NumericFailure::InvalidDecimal));
    }
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| numeric_error(field, NumericFailure::Overflow))
}

fn positive_pid(bytes: &[u8], field: NumericField) -> Result<i32, ProcessError> {
    let value = unsigned(bytes, field)?;
    let value = i32::try_from(value).map_err(|_| numeric_error(field, NumericFailure::Overflow))?;
    if value <= 0 {
        return Err(numeric_error(field, NumericFailure::NonPositive));
    }
    Ok(value)
}

fn belongs_to_owned_group(stat: Stat, group: i32) -> Result<bool, ProcessError> {
    if group <= 0 {
        return Err(ProcessError::new(
            "process_identity",
            "reserved Linux process group is not positive",
        ));
    }
    if stat.identity.session == group && stat.identity.group != group && !stat.definitely_exited() {
        return Err(ProcessError::new(
            "scope_escape",
            "owned Linux session member changed process group",
        ));
    }
    if stat.identity.group != group {
        return Ok(false);
    }
    if stat.identity.session != group {
        return Err(ProcessError::new(
            "process_identity",
            "owned Linux process group has inconsistent session identity",
        ));
    }
    Ok(true)
}

fn verify_identity(before: Stat, after: Stat) -> Result<(), ProcessError> {
    if before.identity != after.identity {
        return Err(ProcessError::new(
            "process_identity",
            "anchored native process identity changed during observation",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io::{Read, Seek};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::ptr::NonNull;

    const PROC_MAGIC: libc::c_long = 0x9fa0;
    const READ_CALLS: usize = 64;
    const INTERRUPTED_READS: usize = 32;

    struct ProcDirectory {
        directory: File,
        stat: File,
        initial: Stat,
    }

    /// The supervisor must continue holding its unreaped Child reservation.
    /// Once this observer loses the original leader identity it cannot recover
    /// that reservation, authorize another group signal, or certify drain.
    pub(in super::super) struct OwnedGroup {
        root: File,
        leader: ProcDirectory,
        reservation_valid: bool,
    }

    impl OwnedGroup {
        pub(in super::super) fn capture(leader_pid: libc::pid_t) -> Result<Self, ProcessError> {
            if leader_pid <= 0 {
                return Err(metadata("reserved Linux leader PID is invalid"));
            }
            let descriptor = unsafe {
                libc::open(
                    c"/proc".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            let root = owned_file(descriptor, "open fixed procfs root")?;
            let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatfs(root.as_raw_fd(), &mut filesystem) } != 0 {
                return Err(native_error("verify fixed procfs root"));
            }
            if filesystem.f_type != PROC_MAGIC {
                return Err(metadata("fixed process observation root is not procfs"));
            }
            let leader =
                open_process(&root, leader_pid, ProcessRole::ReservedLeader)?.ok_or_else(|| {
                    ProcessError::new("process_identity", "reserved Linux leader is unavailable")
                })?;
            if leader.initial.identity.group != leader_pid
                || leader.initial.identity.session != leader_pid
            {
                return Err(ProcessError::new(
                    "process_identity",
                    "reserved Linux leader has inconsistent session or group identity",
                ));
            }
            Ok(Self {
                root,
                leader,
                reservation_valid: true,
            })
        }

        pub(in super::super) fn reservation_valid(&self) -> bool {
            self.reservation_valid
        }

        pub(in super::super) fn sample(
            &mut self,
            include_rss: bool,
            held_child_reservation_valid: bool,
            pending: &mut PendingObservations,
        ) -> Result<GroupObservation, ProcessError> {
            // This output belongs only to this scan, including its failure
            // path. Prior observations live in the tracker, never here.
            *pending = PendingObservations::default();
            let leader_before = self.check_leader()?;
            let group = leader_before.identity.pid;
            let owner = OwnerContext {
                leader: leader_before.identity,
                reservation_valid: self.reservation_valid && held_child_reservation_valid,
            };
            let mut sample = Sample {
                live_processes: 0,
                aggregate_rss_bytes: include_rss.then_some(0),
                known_rss_bytes: 0,
                max_virtual_bytes: 0,
            };
            // The held leader is observed explicitly, using its original stat
            // FD. Enumeration is only for the remaining process candidates.
            let leader_sample =
                match observe_member(&self.root, &mut self.leader, include_rss, true, owner) {
                    Ok(sample) => sample,
                    Err(error) => {
                        if error.kind == "process_identity" {
                            self.reservation_valid = false;
                        }
                        return Err(error);
                    }
                };
            accumulate(&mut sample, leader_sample, pending)?;
            let mut entries = DirectoryEntries::new(&self.root)?;
            let mut observed_entries = 0usize;
            while let Some(name) = entries.next()? {
                observed_entries += 1;
                if observed_entries > DIRECTORY_ENTRIES {
                    return Err(metadata(
                        "native process enumeration exceeds its entry bound",
                    ));
                }
                if name.is_empty() || !name.iter().all(u8::is_ascii_digit) {
                    continue;
                }
                let pid = positive_pid(&name, NumericField::DirectoryPid)?;
                if pid == group {
                    continue;
                }
                let Some(mut member) =
                    open_process(&self.root, pid, ProcessRole::EnumeratedCandidate)?
                else {
                    // This candidate disappeared before it had an anchored
                    // identity. It is not a confirmed owned-process exit.
                    continue;
                };
                let stat = member.initial;
                if !belongs_to_owned_group(stat, group)? {
                    continue;
                }
                let read_rss = include_rss && sample.live_processes < LIVE_LIMIT;
                let observation = observe_member(&self.root, &mut member, read_rss, false, owner)?;
                accumulate(&mut sample, observation, pending)?;
            }
            self.check_leader()?;
            // The provisional member facts above never bypass this final
            // check of the original held leader anchor.
            Ok(if !pending.is_empty() {
                GroupObservation::Pending(sample)
            } else {
                GroupObservation::Complete(sample)
            })
        }

        fn check_leader(&mut self) -> Result<Stat, ProcessError> {
            if !self.reservation_valid {
                return Err(ProcessError::new(
                    "process_identity",
                    "reserved Linux leader identity was already lost",
                ));
            }
            let result = read_stat(
                &mut self.leader.stat,
                self.leader.initial.identity.pid,
                ProcessRole::ReservedLeader,
            )
            .and_then(|value| match value {
                Some(value) => {
                    verify_identity(self.leader.initial, value)?;
                    Ok(value)
                }
                None => Err(ProcessError::new(
                    "process_identity",
                    "reserved Linux leader disappeared from its original procfs FD",
                )),
            });
            if result
                .as_ref()
                .is_err_and(|error| error.kind == "process_identity")
            {
                self.reservation_valid = false;
            }
            result
        }
    }

    fn observe_member(
        root: &File,
        process: &mut ProcDirectory,
        include_rss: bool,
        is_leader: bool,
        owner: OwnerContext,
    ) -> Result<MemberObservation, ProcessError> {
        let role = if is_leader {
            ProcessRole::ReservedLeader
        } else {
            ProcessRole::OwnedMember
        };
        let mut diagnostic =
            StatDiagnostic::observed(role, process.initial.identity, None, None, include_rss);
        observe_member_with_facts(
            root,
            process,
            include_rss,
            is_leader,
            owner,
            &mut diagnostic,
        )
        .map_err(|error| error.with_linux_stat_diagnostic(diagnostic))
    }

    fn observe_member_with_facts(
        root: &File,
        process: &mut ProcDirectory,
        include_rss: bool,
        is_leader: bool,
        owner: OwnerContext,
        diagnostic: &mut StatDiagnostic,
    ) -> Result<MemberObservation, ProcessError> {
        let pid = process.initial.identity.pid;
        let role = if is_leader {
            ProcessRole::ReservedLeader
        } else {
            ProcessRole::OwnedMember
        };
        let Some(before) = read_stat(&mut process.stat, pid, role)? else {
            return unavailable_member(is_leader).map(MemberObservation::Settled);
        };
        diagnostic.record_stats(process.initial.identity, Some(before), None);
        verify_identity(process.initial, before)?;
        if before.definitely_exited() {
            return Ok(MemberObservation::Settled(None));
        }
        // Only an already identified member can bind a process-lifetime FD.
        // Binding is optional: unsupported syscalls or uncertain namespace /
        // mount metadata never turn a later RSS error into a successful sample.
        let mut pidfd_diagnostic = None;
        let bound = if include_rss {
            match pidfd::bind(
                root,
                &process.directory,
                &mut process.stat,
                before,
                |file| read_stat(file, pid, role),
            ) {
                Ok(pidfd::Binding::Bound(bound)) => {
                    diagnostic.pidfd_binding = PidfdBindingState::BoundValidated;
                    Some(bound)
                }
                Ok(pidfd::Binding::Unavailable(reason)) => {
                    // Keep the closed reason distinct inside the producer;
                    // it is not a replacement for the actual RSS failure.
                    let observation = reason.diagnostic();
                    diagnostic.pidfd_binding = PidfdBindingState::Unavailable;
                    diagnostic.pidfd_binding_observation = Some(observation);
                    pidfd_diagnostic = Some(observation);
                    None
                }
                Ok(pidfd::Binding::OriginalGone) => {
                    diagnostic.pidfd_binding = PidfdBindingState::OriginalGone;
                    return unavailable_member(is_leader).map(MemberObservation::Settled);
                }
                Err(error) => {
                    diagnostic.pidfd_binding = PidfdBindingState::Failed;
                    return Err(error);
                }
            }
        } else {
            None
        };
        let memory = if include_rss {
            Some(read_rollup(&process.directory))
        } else {
            None
        };
        let after = read_stat(&mut process.stat, pid, role)?;
        diagnostic.record_stats(process.initial.identity, Some(before), after);
        if let Some(after) = after {
            verify_identity(before, after)?;
        }
        // Exactly one nonblocking kernel check, after an actual RSS failure.
        // The witness requires a matching post-RSS original stat identity;
        // losing the leader reservation cannot be repaired with a pidfd.
        let terminal = match (&memory, after, bound.as_ref()) {
            (Some(Err(_)), Some(after), Some(bound)) if !after.definitely_exited() => {
                let check = bound.check_terminal_after(after.identity);
                diagnostic.pidfd_terminal_observation = Some(check.diagnostic);
                pidfd_diagnostic = Some(check.diagnostic);
                check.witness
            }
            _ => None,
        };
        let memory = match memory {
            Some(Err(failure))
                if pending_exit_transition(
                    process.initial.identity,
                    before,
                    after,
                    &failure,
                    PendingConditions {
                        role,
                        owner,
                        bound_validated: bound.is_some(),
                        terminal: diagnostic.pidfd_terminal_observation,
                    },
                ) =>
            {
                let error = failure.into_process_error(role);
                return Ok(MemberObservation::Pending(
                    MemberSample {
                        live: true,
                        virtual_bytes: before
                            .virtual_bytes
                            .max(after.map_or(0, |s| s.virtual_bytes)),
                        rss: None,
                    },
                    Box::new(PendingObservation::new(
                        error,
                        *diagnostic,
                        if is_leader {
                            PendingRole::ReservedLeader
                        } else {
                            PendingRole::OwnedMember
                        },
                    )),
                ));
            }
            result => result.map(|result| result.map_err(|error| error.into_process_error(role))),
        };
        // smaps_rollup ESRCH/ENOENT alone never proves death. Except for the
        // narrow incomplete transition above, a live original stat identity
        // makes that exact RSS observation error fatal.
        // Successful RSS stays an observed fact even when this process exits
        // immediately afterwards. Its live count may drop; its measured RSS
        // and VM must not disappear from the resource budget evidence.
        let failed_rss = memory.as_ref().is_some_and(Result::is_err);
        let settled = if let Some(terminal) = terminal.as_ref() {
            settle_member_with_terminal(before, after, memory, is_leader, Some(terminal))
        } else {
            settle_member(before, after, memory, is_leader)
        };
        settled.map(MemberObservation::Settled).map_err(|error| {
            match (failed_rss, pidfd_diagnostic) {
                (true, Some(diagnostic)) => error.with_linux_pidfd_diagnostic(diagnostic),
                _ => error,
            }
        })
    }

    fn unavailable_member(is_leader: bool) -> Result<Option<MemberSample>, ProcessError> {
        if is_leader {
            Err(ProcessError::new(
                "process_identity",
                "reserved Linux leader disappeared during resource observation",
            ))
        } else {
            Ok(None)
        }
    }

    fn open_process(
        root: &File,
        pid: i32,
        role: ProcessRole,
    ) -> Result<Option<ProcDirectory>, ProcessError> {
        let name = CString::new(pid.to_string()).map_err(|_| metadata("invalid numeric PID"))?;
        let descriptor = unsafe {
            libc::openat(
                root.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(metadata_io_error(
                role,
                MetadataRole::PidDirectory,
                MetadataOperation::Open,
                error,
            ));
        }
        let directory = unsafe { File::from_raw_fd(descriptor) };
        let mut stat = open_file(&directory, MetadataRole::Stat, role)?;
        let Some(initial) = read_stat(&mut stat, pid, role)? else {
            return Ok(None);
        };
        Ok(Some(ProcDirectory {
            directory,
            stat,
            initial,
        }))
    }

    fn read_stat(
        file: &mut File,
        pid: i32,
        role: ProcessRole,
    ) -> Result<Option<Stat>, ProcessError> {
        file.rewind().map_err(|error| {
            metadata_io_error(role, MetadataRole::Stat, MetadataOperation::Rewind, error)
        })?;
        let bytes = match read_bounded(file, STAT_BYTES) {
            Ok(bytes) => bytes,
            // An already opened stat inode's actual read reaches
            // proc_single_show/get_pid_task. ESRCH there confirms that the
            // original task disappeared, rather than merely losing its mm.
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(None),
            Err(error) => {
                return Err(metadata_io_error(
                    role,
                    MetadataRole::Stat,
                    MetadataOperation::Read,
                    error,
                ));
            }
        };
        parse_stat(&bytes, pid).map(Some)
    }

    fn read_rollup(directory: &File) -> Result<u64, RssFailure> {
        let name = MetadataRole::RssRollup
            .file_name()
            .map_err(RssFailure::Parse)?;
        let mut file = open_file_io(directory, name).map_err(RssFailure::Open)?;
        let bytes = read_bounded(&mut file, ROLLUP_BYTES).map_err(RssFailure::Read)?;
        parse_rollup(&bytes).map_err(RssFailure::Parse)
    }

    // Native regression tests reuse the real anchored producers. This private
    // test boundary cannot synthesize an identity, terminal witness or raw FD.
    #[cfg(test)]
    pub(super) fn test_open_member(
        root: &File,
        pid: i32,
        role: ProcessRole,
    ) -> Result<Option<(File, File, Stat)>, ProcessError> {
        open_process(root, pid, role)
            .map(|member| member.map(|member| (member.directory, member.stat, member.initial)))
    }

    #[cfg(test)]
    pub(super) fn test_read_stat(
        file: &mut File,
        pid: i32,
        role: ProcessRole,
    ) -> Result<Option<Stat>, ProcessError> {
        read_stat(file, pid, role)
    }

    #[cfg(test)]
    pub(super) fn test_metadata(
        directory: &File,
        file: MetadataRole,
        role: ProcessRole,
    ) -> Result<Option<u64>, ProcessError> {
        match file {
            MetadataRole::Stat => open_file(directory, file, role).map(|_| None),
            MetadataRole::RssRollup => read_rollup(directory)
                .map(Some)
                .map_err(|error| error.into_process_error(role)),
            MetadataRole::PidDirectory => Err(metadata("test metadata role is not a file")),
        }
    }

    fn open_file(
        directory: &File,
        file: MetadataRole,
        role: ProcessRole,
    ) -> Result<File, ProcessError> {
        let name = file.file_name()?;
        open_file_io(directory, name)
            .map_err(|error| metadata_io_error(role, file, MetadataOperation::Open, error))
    }

    fn open_file_io(directory: &File, name: &CStr) -> std::io::Result<File> {
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }

    fn owned_file(descriptor: i32, context: &'static str) -> Result<File, ProcessError> {
        if descriptor < 0 {
            return Err(native_error(context));
        }
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }

    fn read_bounded(file: &mut File, limit: usize) -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(limit.min(4096));
        let mut calls = 0usize;
        let mut interrupted = 0usize;
        loop {
            calls += 1;
            if calls > READ_CALLS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "native metadata read exceeds its call bound",
                ));
            }
            let mut buffer = [0u8; 4096];
            let remaining = limit + 1 - bytes.len();
            match file.read(&mut buffer[..remaining.min(4096)]) {
                Ok(0) => return Ok(bytes),
                Ok(read) => {
                    bytes.extend_from_slice(&buffer[..read]);
                    if bytes.len() > limit {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "native metadata read exceeds its byte bound",
                        ));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    interrupted += 1;
                    if interrupted > INTERRUPTED_READS {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    struct DirectoryEntries {
        directory: NonNull<libc::DIR>,
    }

    impl DirectoryEntries {
        fn new(root: &File) -> Result<Self, ProcessError> {
            // openat(".") creates a fresh open file description. dup() would
            // share the directory offset and break the next full scan.
            let descriptor = unsafe {
                libc::openat(
                    root.as_raw_fd(),
                    c".".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if descriptor < 0 {
                return Err(native_error("open fresh procfs enumeration"));
            }
            let pointer = unsafe { libc::fdopendir(descriptor) };
            let Some(directory) = NonNull::new(pointer) else {
                let error = std::io::Error::last_os_error();
                unsafe { libc::close(descriptor) };
                return Err(io_error("begin native process enumeration", error));
            };
            Ok(Self { directory })
        }

        fn next(&mut self) -> Result<Option<Vec<u8>>, ProcessError> {
            unsafe { *libc::__errno_location() = 0 };
            let entry = unsafe { libc::readdir(self.directory.as_ptr()) };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(0) {
                    return Ok(None);
                }
                return Err(io_error("read native process directory entry", error));
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name.len() > 255 {
                return Err(metadata("native process entry name exceeds its bound"));
            }
            Ok(Some(name.to_vec()))
        }
    }

    impl Drop for DirectoryEntries {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.directory.as_ptr()) };
        }
    }

    fn native_error(context: &'static str) -> ProcessError {
        io_error(context, std::io::Error::last_os_error())
    }

    fn io_error(context: &'static str, error: std::io::Error) -> ProcessError {
        ProcessError::new(
            "resource_observation",
            format!(
                "{context}; error_kind={:?}; os_error={:?}",
                error.kind(),
                error.raw_os_error(),
            ),
        )
    }
}

#[cfg(target_os = "linux")]
pub(super) use native::OwnedGroup;

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    fn stat_fields(state: char, threads: u64) -> Vec<String> {
        let mut fields = vec!["0".to_owned(); 21];
        fields[0] = state.to_string();
        fields[2] = "123".to_owned();
        fields[3] = "123".to_owned();
        fields[17] = threads.to_string();
        fields[19] = "456".to_owned();
        fields[20] = "987654".to_owned();
        fields
    }

    fn render_stat(pid: &str, fields: &[String]) -> Vec<u8> {
        format!("{pid} (native ) comm) {}\n", fields.join(" ")).into_bytes()
    }

    fn stat(state: char, threads: u64) -> Vec<u8> {
        render_stat("123", &stat_fields(state, threads))
    }

    fn pending_conditions() -> PendingConditions {
        PendingConditions {
            role: ProcessRole::ReservedLeader,
            owner: OwnerContext {
                leader: parse_stat(&stat('Z', 2), 123).unwrap().identity,
                reservation_valid: true,
            },
            bound_validated: true,
            terminal: Some(PidfdDiagnostic::new(
                pidfd::DiagnosticPhase::TerminalPoll,
                pidfd::DiagnosticCategory::NotReady,
                None,
            )),
        }
    }

    // Reuse the existing parsed stat fixture. This has no native reservation,
    // descriptor or exit authority and is available only in pure tests.
    pub(in super::super) fn pending_observation() -> PendingObservation {
        pending_observation_for_role(PendingRole::ReservedLeader)
    }

    pub(in super::super) fn pending_observation_for_role(role: PendingRole) -> PendingObservation {
        let (pid, process_role) = match role {
            PendingRole::ReservedLeader => (123, ProcessRole::ReservedLeader),
            PendingRole::OwnedMember => (124, ProcessRole::OwnedMember),
        };
        let before = parse_stat(&render_stat(&pid.to_string(), &stat_fields('Z', 2)), pid).unwrap();
        let mut diagnostic = StatDiagnostic::observed(
            process_role,
            before.identity,
            Some(before),
            Some(before),
            true,
        );
        diagnostic.pidfd_binding = PidfdBindingState::BoundValidated;
        diagnostic.pidfd_terminal_observation = pending_conditions().terminal;
        PendingObservation::new(
            RssFailure::Open(std::io::Error::from_raw_os_error(3)).into_process_error(process_role),
            diagnostic,
            role,
        )
    }

    #[test]
    fn pending_leader_requires_the_exact_observed_transition_and_never_proves_exit() {
        let before = parse_stat(&stat('Z', 2), 123).unwrap();
        let original = before.identity;
        let failure = RssFailure::Open(std::io::Error::from_raw_os_error(3));
        let conditions = pending_conditions();
        assert!(pending_exit_transition(
            original,
            before,
            Some(before),
            &failure,
            conditions
        ));
        // The old settlement remains fatal without the new incomplete policy.
        assert!(
            settle_member(
                before,
                Some(before),
                Some(Err(pending_observation().original_error())),
                true
            )
            .is_err()
        );
        for changed in [
            Identity {
                pid: original.pid + 1,
                ..original
            },
            Identity {
                start_ticks: original.start_ticks + 1,
                ..original
            },
            Identity {
                group: original.group + 1,
                ..original
            },
            Identity {
                session: original.session + 1,
                ..original
            },
        ] {
            let changed = Stat {
                identity: changed,
                ..before
            };
            assert!(!pending_exit_transition(
                original,
                changed,
                Some(before),
                &failure,
                conditions
            ));
            assert!(!pending_exit_transition(
                original,
                before,
                Some(changed),
                &failure,
                conditions
            ));
        }
        for changed in [
            parse_stat(&stat('S', 2), 123).unwrap(),
            parse_stat(&stat('R', 2), 123).unwrap(),
            parse_stat(&stat('X', 2), 123).unwrap(),
            parse_stat(&stat('x', 2), 123).unwrap(),
            parse_stat(&stat('Z', 1), 123).unwrap(),
            parse_stat(&stat('Z', 3), 123).unwrap(),
        ] {
            assert!(!pending_exit_transition(
                original,
                changed,
                Some(before),
                &failure,
                conditions
            ));
            assert!(!pending_exit_transition(
                original,
                before,
                Some(changed),
                &failure,
                conditions
            ));
        }
        assert!(!pending_exit_transition(
            original, before, None, &failure, conditions
        ));
        for conditions in [
            PendingConditions {
                role: ProcessRole::EnumeratedCandidate,
                ..conditions
            },
            PendingConditions {
                owner: OwnerContext {
                    reservation_valid: false,
                    ..conditions.owner
                },
                ..conditions
            },
            PendingConditions {
                bound_validated: false,
                ..conditions
            },
            PendingConditions {
                terminal: None,
                ..conditions
            },
        ] {
            assert!(!pending_exit_transition(
                original,
                before,
                Some(before),
                &failure,
                conditions
            ));
        }
        for category in [
            pidfd::DiagnosticCategory::Terminal,
            pidfd::DiagnosticCategory::NativeFailure,
            pidfd::DiagnosticCategory::UnexpectedPollEvents,
            pidfd::DiagnosticCategory::UnexpectedPollResult,
        ] {
            let conditions = PendingConditions {
                terminal: Some(PidfdDiagnostic::new(
                    pidfd::DiagnosticPhase::TerminalPoll,
                    category,
                    None,
                )),
                ..conditions
            };
            assert!(!pending_exit_transition(
                original,
                before,
                Some(before),
                &failure,
                conditions
            ));
        }
        for terminal in [
            PidfdDiagnostic::new(
                pidfd::DiagnosticPhase::TerminalIdentity,
                pidfd::DiagnosticCategory::NotReady,
                None,
            ),
            PidfdDiagnostic::new(
                pidfd::DiagnosticPhase::TerminalPoll,
                pidfd::DiagnosticCategory::NotReady,
                Some(3),
            ),
        ] {
            assert!(!pending_exit_transition(
                original,
                before,
                Some(before),
                &failure,
                PendingConditions {
                    terminal: Some(terminal),
                    ..conditions
                }
            ));
        }
        for failure in [
            RssFailure::Open(std::io::Error::from_raw_os_error(2)),
            RssFailure::Read(std::io::Error::from_raw_os_error(3)),
            // Even identical text cannot masquerade as the typed native open.
            RssFailure::Parse(pending_observation().original_error()),
        ] {
            assert!(!pending_exit_transition(
                original,
                before,
                Some(before),
                &failure,
                conditions
            ));
            assert_eq!(
                failure.into_process_error(ProcessRole::ReservedLeader).kind,
                "resource_observation"
            );
        }
        let actual = pending_observation();
        let rendered = actual.original_error().to_string();
        assert!(rendered.starts_with("resource_observation: native process metadata failed; process_role=reserved_leader; file_role=rss_rollup; operation=open;"));
        assert!(rendered.contains("os_error=Some(3)"));
        assert!(rendered.contains(
            "pidfd_observation(phase=terminal_poll; category=not_ready; native_errno=None)"
        ));
        assert!(rendered.len() < 1280);
        let closed = serde_json::to_string(&actual).unwrap();
        assert!(!closed.contains("start_ticks\":456"));
        assert!(!closed.contains("native ) comm"));

        // A member has no Child reservation of its own. Only the already
        // checked original leader anchor and its held Child may admit this
        // incomplete sample; neither Z2 nor NotReady is an exit witness.
        let member = parse_stat(&render_stat("124", &stat_fields('Z', 2)), 124).unwrap();
        let member_conditions = PendingConditions {
            role: ProcessRole::OwnedMember,
            ..conditions
        };
        assert!(pending_exit_transition(
            member.identity,
            member,
            Some(member),
            &failure,
            member_conditions
        ));
        assert!(
            settle_member(
                member,
                Some(member),
                Some(Err(
                    pending_observation_for_role(PendingRole::OwnedMember).original_error()
                )),
                false
            )
            .is_err()
        );
        for identity in [
            Identity {
                pid: original.pid,
                ..member.identity
            },
            Identity {
                pid: 0,
                ..member.identity
            },
            Identity {
                group: original.group + 1,
                ..member.identity
            },
            Identity {
                session: original.session + 1,
                ..member.identity
            },
        ] {
            let wrong = Stat { identity, ..member };
            assert!(!pending_exit_transition(
                identity,
                wrong,
                Some(wrong),
                &failure,
                member_conditions
            ));
        }
        for identity in [
            Identity {
                pid: member.identity.pid + 1,
                ..member.identity
            },
            Identity {
                start_ticks: member.identity.start_ticks + 1,
                ..member.identity
            },
            Identity {
                group: member.identity.group + 1,
                ..member.identity
            },
            Identity {
                session: member.identity.session + 1,
                ..member.identity
            },
        ] {
            let wrong = Stat { identity, ..member };
            assert!(!pending_exit_transition(
                member.identity,
                wrong,
                Some(member),
                &failure,
                member_conditions
            ));
            assert!(!pending_exit_transition(
                member.identity,
                member,
                Some(wrong),
                &failure,
                member_conditions
            ));
        }
        for (state, threads) in [(b'S', 2), (b'X', 2), (b'x', 2), (b'Z', 1), (b'Z', 3)] {
            let wrong = Stat {
                state,
                threads,
                ..member
            };
            assert!(!pending_exit_transition(
                member.identity,
                wrong,
                Some(member),
                &failure,
                member_conditions
            ));
            assert!(!pending_exit_transition(
                member.identity,
                member,
                Some(wrong),
                &failure,
                member_conditions
            ));
        }
        for owner in [
            OwnerContext {
                reservation_valid: false,
                ..conditions.owner
            },
            OwnerContext {
                leader: Identity { pid: 0, ..original },
                ..conditions.owner
            },
            OwnerContext {
                leader: Identity {
                    group: original.group + 1,
                    ..original
                },
                ..conditions.owner
            },
            OwnerContext {
                leader: Identity {
                    session: original.session + 1,
                    ..original
                },
                ..conditions.owner
            },
        ] {
            assert!(!pending_exit_transition(
                member.identity,
                member,
                Some(member),
                &failure,
                PendingConditions {
                    owner,
                    ..member_conditions
                }
            ));
        }
        for unknown in [
            PendingConditions {
                role: ProcessRole::EnumeratedCandidate,
                ..member_conditions
            },
            PendingConditions {
                bound_validated: false,
                ..member_conditions
            },
            PendingConditions {
                terminal: None,
                ..member_conditions
            },
            PendingConditions {
                terminal: Some(PidfdDiagnostic::new(
                    pidfd::DiagnosticPhase::TerminalPoll,
                    pidfd::DiagnosticCategory::Unsupported,
                    None,
                )),
                ..member_conditions
            },
            PendingConditions {
                terminal: Some(PidfdDiagnostic::new(
                    pidfd::DiagnosticPhase::TerminalPoll,
                    pidfd::DiagnosticCategory::NativeFailure,
                    Some(3),
                )),
                ..member_conditions
            },
            PendingConditions {
                terminal: Some(PidfdDiagnostic::new(
                    pidfd::DiagnosticPhase::TerminalPoll,
                    pidfd::DiagnosticCategory::UnexpectedPollEvents,
                    None,
                )),
                ..member_conditions
            },
            PendingConditions {
                terminal: Some(PidfdDiagnostic::new(
                    pidfd::DiagnosticPhase::TerminalPoll,
                    pidfd::DiagnosticCategory::Terminal,
                    None,
                )),
                ..member_conditions
            },
            PendingConditions {
                terminal: Some(PidfdDiagnostic::new(
                    pidfd::DiagnosticPhase::TerminalIdentity,
                    pidfd::DiagnosticCategory::NotReady,
                    None,
                )),
                ..member_conditions
            },
            PendingConditions {
                terminal: Some(PidfdDiagnostic::new(
                    pidfd::DiagnosticPhase::TerminalPoll,
                    pidfd::DiagnosticCategory::NotReady,
                    Some(3),
                )),
                ..member_conditions
            },
        ] {
            assert!(!pending_exit_transition(
                member.identity,
                member,
                Some(member),
                &failure,
                unknown
            ));
        }
        assert!(!pending_exit_transition(
            member.identity,
            member,
            None,
            &failure,
            member_conditions
        ));
        for wrong in [
            RssFailure::Open(std::io::Error::from_raw_os_error(2)),
            RssFailure::Read(std::io::Error::from_raw_os_error(3)),
            RssFailure::Parse(
                pending_observation_for_role(PendingRole::OwnedMember).original_error(),
            ),
        ] {
            assert!(!pending_exit_transition(
                member.identity,
                member,
                Some(member),
                &wrong,
                member_conditions
            ));
        }
    }

    #[test]
    fn stat_diagnostic_retains_only_observed_states_threads_and_identity_matches() {
        let before = parse_stat(&stat('S', 5), 123).unwrap();
        let after = parse_stat(&stat('Z', 2), 123).unwrap();
        let diagnostic = StatDiagnostic::observed(
            ProcessRole::ReservedLeader,
            before.identity,
            Some(before),
            Some(after),
            false,
        );
        assert_eq!(diagnostic.before_state, Some(StatState::Sleeping));
        assert_eq!(diagnostic.before_threads, Some(5));
        assert_eq!(diagnostic.before_original_identity_match, Some(true));
        assert_eq!(diagnostic.after_state, Some(StatState::Zombie));
        assert_eq!(diagnostic.after_threads, Some(2));
        assert_eq!(diagnostic.after_original_identity_match, Some(true));
        assert_eq!(
            diagnostic.to_string(),
            "linux_stat_observation(process_role=reserved_leader; before_state=Some(Sleeping); before_threads=Some(5); before_original_identity_match=Some(true); before_identity_matches=Some(IdentityMatches { pid: true, start_ticks: true, group: true, session: true }); after_state=Some(Zombie); after_threads=Some(2); after_original_identity_match=Some(true); after_identity_matches=Some(IdentityMatches { pid: true, start_ticks: true, group: true, session: true }); after_group_detached_sentinel=Some(false); after_session_detached_sentinel=Some(false); pidfd_binding=NotRequiredBySample; pidfd_binding_observation=None; pidfd_terminal_observation=None)",
        );

        let missing =
            StatDiagnostic::observed(ProcessRole::OwnedMember, before.identity, None, None, false);
        assert_eq!(missing.before_state, None);
        assert_eq!(missing.before_threads, None);
        assert_eq!(missing.before_original_identity_match, None);
        assert_eq!(missing.before_identity_matches, None);
        assert_eq!(missing.after_state, None);
        assert_eq!(missing.after_threads, None);
        assert_eq!(missing.after_original_identity_match, None);
        assert_eq!(missing.after_identity_matches, None);
        assert_eq!(missing.after_group_detached_sentinel, None);
        assert_eq!(missing.after_session_detached_sentinel, None);
        assert_eq!(
            missing.pidfd_binding,
            PidfdBindingState::NotRequiredBySample
        );
        assert_eq!(missing.pidfd_binding_observation, None);
        assert_eq!(missing.pidfd_terminal_observation, None);
        assert!(missing.to_string().contains("process_role=owned_member;"));
    }

    #[test]
    fn stat_diagnostic_compares_each_original_identity_component_without_printing_it() {
        let before = parse_stat(&stat('Z', 3), 123).unwrap();
        for (index, identity) in [
            Identity {
                pid: 124,
                ..before.identity
            },
            Identity {
                start_ticks: 457,
                ..before.identity
            },
            Identity {
                group: 124,
                ..before.identity
            },
            Identity {
                session: 124,
                ..before.identity
            },
        ]
        .into_iter()
        .enumerate()
        {
            let changed = Stat {
                identity,
                state: b'X',
                threads: 0,
                ..before
            };
            let diagnostic = StatDiagnostic::observed(
                ProcessRole::ReservedLeader,
                before.identity,
                Some(before),
                Some(changed),
                false,
            );
            assert_eq!(diagnostic.before_original_identity_match, Some(true));
            assert_eq!(diagnostic.after_original_identity_match, Some(false));
            assert_eq!(diagnostic.after_state, Some(StatState::Dead));
            assert_eq!(diagnostic.after_threads, Some(0));
            let expected = IdentityMatches {
                pid: index != 0,
                start_ticks: index != 1,
                group: index != 2,
                session: index != 3,
            };
            assert_eq!(diagnostic.after_identity_matches, Some(expected));
            let changed_before = StatDiagnostic::observed(
                ProcessRole::OwnedMember,
                before.identity,
                Some(changed),
                None,
                false,
            );
            assert_eq!(changed_before.before_identity_matches, Some(expected));
            assert_eq!(changed_before.after_identity_matches, None);
            let text = diagnostic.to_string();
            for absent in ["123", "124", "456", "457", "native ) comm"] {
                assert!(!text.contains(absent));
            }
        }
    }

    #[test]
    fn dead_stat_sentinels_are_closed_facts_and_never_repair_an_identity_failure() {
        let before = parse_stat(&stat('Z', 3), 123).unwrap();
        for (group, session, group_detached, session_detached) in [
            (-1, 123, true, false),
            (123, -1, false, true),
            (-1, -1, true, true),
            (124, 124, false, false),
        ] {
            let after = Stat {
                identity: Identity {
                    group,
                    session,
                    ..before.identity
                },
                state: b'X',
                threads: 0,
                ..before
            };
            let diagnostic = StatDiagnostic::observed(
                ProcessRole::OwnedMember,
                before.identity,
                Some(before),
                Some(after),
                false,
            );
            assert_eq!(
                diagnostic.after_group_detached_sentinel,
                Some(group_detached)
            );
            assert_eq!(
                diagnostic.after_session_detached_sentinel,
                Some(session_detached)
            );
            assert_eq!(
                diagnostic.pidfd_binding,
                PidfdBindingState::NotRequiredBySample
            );
            assert_eq!(diagnostic.pidfd_terminal_observation, None);
            let mut original = settle_member(before, Some(after), None, false)
                .expect_err("a dead stat cannot hide a changed original identity");
            original.drained = false;
            let original_message = original.message.clone();
            let actual = original.with_linux_stat_diagnostic(diagnostic);
            assert_eq!(actual.kind, "process_identity");
            assert_eq!(actual.message, original_message);
            assert!(!actual.drained);
            assert_eq!(
                actual.to_string(),
                format!("process_identity: {original_message}; {diagnostic}"),
            );
        }
    }

    #[test]
    fn stat_updates_preserve_sample_mode_and_only_the_recorded_pidfd_facts() {
        let before = parse_stat(&stat('S', 2), 123).unwrap();
        let after = parse_stat(&stat('Z', 2), 123).unwrap();
        let mut count_only =
            StatDiagnostic::observed(ProcessRole::OwnedMember, before.identity, None, None, false);
        count_only.record_stats(before.identity, Some(before), Some(after));
        assert_eq!(
            count_only.pidfd_binding,
            PidfdBindingState::NotRequiredBySample
        );
        assert_eq!(count_only.pidfd_binding_observation, None);
        assert_eq!(count_only.pidfd_terminal_observation, None);

        let mut rss = StatDiagnostic::observed(
            ProcessRole::ReservedLeader,
            before.identity,
            None,
            None,
            true,
        );
        assert_eq!(rss.pidfd_binding, PidfdBindingState::NotAttempted);
        assert_eq!(rss.before_identity_matches, None);
        rss.record_stats(before.identity, Some(before), None);
        assert_eq!(rss.pidfd_binding, PidfdBindingState::NotAttempted);
        assert_eq!(rss.after_identity_matches, None);
        assert_eq!(rss.pidfd_binding_observation, None);
        assert_eq!(rss.pidfd_terminal_observation, None);

        // These are diagnostic values only. No test-created value can produce
        // a BoundPidfd, TerminalWitness, native call or successful settlement.
        let binding_observation = PidfdDiagnostic::new(
            pidfd::DiagnosticPhase::PidfdOpen,
            pidfd::DiagnosticCategory::Unsupported,
            Some(38),
        );
        let terminal_observation = PidfdDiagnostic::new(
            pidfd::DiagnosticPhase::TerminalPoll,
            pidfd::DiagnosticCategory::NotReady,
            None,
        );
        for (state, binding, terminal) in [
            (
                PidfdBindingState::BoundValidated,
                None,
                Some(terminal_observation),
            ),
            (
                PidfdBindingState::Unavailable,
                Some(binding_observation),
                None,
            ),
            (PidfdBindingState::OriginalGone, None, None),
            (PidfdBindingState::Failed, None, None),
        ] {
            let mut recorded = rss;
            recorded.pidfd_binding = state;
            recorded.pidfd_binding_observation = binding;
            recorded.pidfd_terminal_observation = terminal;
            recorded.record_stats(before.identity, Some(before), Some(after));
            assert_eq!(recorded.pidfd_binding, state);
            assert_eq!(recorded.pidfd_binding_observation, binding);
            assert_eq!(recorded.pidfd_terminal_observation, terminal);
            assert_eq!(recorded.after_original_identity_match, Some(true));
        }
    }

    #[test]
    fn stat_diagnostic_text_has_a_closed_state_set_and_a_fixed_bound() {
        for state in b"RSDZTXxtKWPI" {
            let before = parse_stat(&stat(*state as char, u64::MAX), 123).unwrap();
            let mut diagnostic = StatDiagnostic::observed(
                ProcessRole::ReservedLeader,
                before.identity,
                Some(before),
                Some(before),
                true,
            );
            // Exercise the closed maximum-width facts without creating any
            // native binding, poll, descriptor or authority in this pure test.
            let widest = PidfdDiagnostic::new(
                pidfd::DiagnosticPhase::ProcessDirectoryFilesystem,
                pidfd::DiagnosticCategory::UnexpectedPollEvents,
                Some(i32::MIN),
            );
            diagnostic.pidfd_binding = PidfdBindingState::Unavailable;
            diagnostic.pidfd_binding_observation = Some(widest);
            diagnostic.pidfd_terminal_observation = Some(widest);
            let text = diagnostic.to_string();
            assert!(diagnostic.before_state.is_some());
            assert!(text.len() < 1280);
            assert!(text.is_ascii());
            assert!(
                !text
                    .bytes()
                    .any(|byte| matches!(byte, b'/' | b'\\' | b'\n' | b'\r'))
            );
        }
        for state in 0..=u8::MAX {
            assert_eq!(
                StatState::observed(state).is_some(),
                b"RSDZTXxtKWPI".contains(&state)
            );
        }
    }

    #[test]
    fn stat_suffix_preserves_fatal_rss_error_pidfd_observation_and_first_facts() {
        let before = parse_stat(&stat('S', 2), 123).unwrap();
        let after = parse_stat(&stat('Z', 2), 123).unwrap();
        for (is_leader, role) in [
            (true, ProcessRole::ReservedLeader),
            (false, ProcessRole::OwnedMember),
        ] {
            let mut original = metadata_io_error(
                role,
                MetadataRole::RssRollup,
                MetadataOperation::Open,
                std::io::Error::from_raw_os_error(3),
            );
            original.drained = false;
            let original_message = original.message.clone();
            let pidfd = PidfdDiagnostic::new(
                pidfd::DiagnosticPhase::TerminalPoll,
                pidfd::DiagnosticCategory::NotReady,
                None,
            );
            let mut diagnostic =
                StatDiagnostic::observed(role, before.identity, Some(before), Some(after), true);
            diagnostic.pidfd_binding = PidfdBindingState::BoundValidated;
            diagnostic.pidfd_terminal_observation = Some(pidfd);
            let actual = settle_member(before, Some(after), Some(Err(original)), is_leader)
                .expect_err("stat diagnostics cannot settle the live original RSS failure")
                .with_linux_pidfd_diagnostic(pidfd)
                .with_linux_stat_diagnostic(diagnostic)
                .with_linux_stat_diagnostic(StatDiagnostic::observed(
                    role,
                    before.identity,
                    None,
                    None,
                    true,
                ));
            assert_eq!(actual.kind, "resource_observation");
            assert_eq!(actual.message, original_message);
            assert!(!actual.drained);
            assert_eq!(
                actual.to_string(),
                format!("resource_observation: {original_message}; {pidfd}; {diagnostic}"),
            );
        }
    }

    #[test]
    fn metadata_failure_roles_stay_bounded_without_native_details() {
        for process in [
            ProcessRole::ReservedLeader,
            ProcessRole::EnumeratedCandidate,
            ProcessRole::OwnedMember,
        ] {
            for file in [
                MetadataRole::PidDirectory,
                MetadataRole::Stat,
                MetadataRole::RssRollup,
            ] {
                for operation in [
                    MetadataOperation::Open,
                    MetadataOperation::Rewind,
                    MetadataOperation::Read,
                ] {
                    let actual = metadata_io_error(
                        process,
                        file,
                        operation,
                        std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "untrusted native detail",
                        ),
                    );
                    assert_eq!(actual.kind, "resource_observation");
                    assert_eq!(
                        actual.message,
                        format!(
                            "native process metadata failed; process_role={}; file_role={}; operation={}; error_kind=PermissionDenied; os_error=None",
                            process.label(),
                            file.label(),
                            operation.label(),
                        )
                    );
                    assert!(actual.message.len() <= 256);
                    assert!(!actual.message.contains("untrusted native detail"));
                }
            }
        }
    }

    #[test]
    fn stat_open_absence_remains_an_error_with_its_exact_static_role_and_code() {
        let actual = metadata_io_error(
            ProcessRole::EnumeratedCandidate,
            MetadataRole::Stat,
            MetadataOperation::Open,
            std::io::Error::from_raw_os_error(2),
        );
        assert_eq!(actual.kind, "resource_observation");
        assert_eq!(
            actual.message,
            "native process metadata failed; process_role=enumerated_candidate; file_role=stat; operation=open; error_kind=NotFound; os_error=Some(2)"
        );
    }

    #[test]
    fn stat_reads_exact_identity_threads_and_vm_after_the_last_comm_terminator() {
        let actual = parse_stat(&stat('S', 5), 123).unwrap();
        assert_eq!(actual.identity.pid, 123);
        assert_eq!(actual.identity.start_ticks, 456);
        assert_eq!(actual.identity.group, 123);
        assert_eq!(actual.identity.session, 123);
        assert_eq!(actual.threads, 5);
        assert_eq!(actual.virtual_bytes, 987654);
        assert!(!actual.definitely_exited());
    }

    #[test]
    fn a_zombie_thread_group_leader_is_not_exited_while_other_threads_remain() {
        for state in ['Z', 'X', 'x'] {
            assert!(
                parse_stat(&stat(state, 1), 123)
                    .unwrap()
                    .definitely_exited()
            );
            assert!(
                !parse_stat(&stat(state, 2), 123)
                    .unwrap()
                    .definitely_exited()
            );
        }
        assert!(parse_stat(&stat('R', 0), 123).is_err());
    }

    #[test]
    fn stat_rejects_wrong_pid_missing_fields_invalid_numbers_and_excess_bytes() {
        assert_eq!(
            parse_stat(&stat('R', 1), 124).unwrap_err().kind,
            "process_identity"
        );
        for bytes in [
            b"123 (missing) R 0 123 123".to_vec(),
            b"123 missing R 0 123 123".to_vec(),
            stat('?', 1),
            vec![b'0'; STAT_BYTES + 1],
        ] {
            assert!(parse_stat(&bytes, 123).is_err());
        }
        assert!(signed(b"2147483648", NumericField::ProcessGroup).is_err());
        assert!(unsigned(b"18446744073709551616", NumericField::StartTicks).is_err());
        assert!(unsigned(b"-1", NumericField::StartTicks).is_err());
        assert!(unsigned(b"+1", NumericField::StartTicks).is_err());
    }

    #[test]
    fn signed_identity_fields_accept_minus_without_loosening_unsigned_or_positive_pid_bounds() {
        for (token, expected) in [
            (b"-2147483648".as_slice(), i32::MIN),
            (b"-1".as_slice(), -1),
            (b"0".as_slice(), 0),
            (b"2147483647".as_slice(), i32::MAX),
        ] {
            assert_eq!(signed(token, NumericField::ProcessGroup).unwrap(), expected);
        }
        for token in [
            b"".as_slice(),
            b"-".as_slice(),
            b"+1".as_slice(),
            b"--1".as_slice(),
            b"1-1".as_slice(),
            b" 1".as_slice(),
            b"1\n".as_slice(),
            b"\xff".as_slice(),
            b"2147483648".as_slice(),
            b"-2147483649".as_slice(),
        ] {
            assert!(signed(token, NumericField::Session).is_err());
        }
        for field in [NumericField::StatPid, NumericField::DirectoryPid] {
            assert_eq!(positive_pid(b"1", field).unwrap(), 1);
            assert_eq!(positive_pid(b"2147483647", field).unwrap(), i32::MAX);
            for token in [b"0".as_slice(), b"-1".as_slice(), b"2147483648".as_slice()] {
                assert!(positive_pid(token, field).is_err());
            }
        }
        for pid in ["0", "-1", "2147483648"] {
            assert!(parse_stat(&render_stat(pid, &stat_fields('S', 1)), 123).is_err());
        }
        assert!(parse_stat(&stat('S', 1), 0).is_err());
    }

    #[test]
    fn unrelated_signed_group_and_session_never_enter_the_owned_group() {
        for (group, session) in [("-1", "-1"), ("-2147483648", "-1"), ("0", "0")] {
            let mut fields = stat_fields('S', 1);
            fields[2] = group.to_owned();
            fields[3] = session.to_owned();
            let actual = parse_stat(&render_stat("124", &fields), 124).unwrap();
            assert!(!belongs_to_owned_group(actual, 123).unwrap());
            assert!(belongs_to_owned_group(actual, -1).is_err());
        }
        let actual = parse_stat(&stat('S', 1), 123).unwrap();
        assert!(belongs_to_owned_group(actual, 123).unwrap());
        for (group, session, expected_kind) in [
            ("-1", "123", "scope_escape"),
            ("124", "123", "scope_escape"),
            ("123", "-1", "process_identity"),
            ("123", "124", "process_identity"),
        ] {
            let mut fields = stat_fields('S', 1);
            fields[2] = group.to_owned();
            fields[3] = session.to_owned();
            let actual = parse_stat(&render_stat("125", &fields), 125).unwrap();
            assert_eq!(
                belongs_to_owned_group(actual, 123).unwrap_err().kind,
                expected_kind
            );
        }
        let mut fields = stat_fields('Z', 1);
        fields[2] = "-1".to_owned();
        let actual = parse_stat(&render_stat("124", &fields), 124).unwrap();
        assert!(!belongs_to_owned_group(actual, 123).unwrap());
    }

    #[test]
    fn numeric_diagnostics_report_only_closed_roles_and_failure_categories() {
        for (index, role) in [
            (2, "process_group"),
            (3, "session"),
            (17, "thread_count"),
            (19, "start_ticks"),
            (20, "virtual_bytes"),
        ] {
            let mut fields = stat_fields('S', 1);
            fields[index] = "private-token".to_owned();
            let error = parse_stat(&render_stat("123", &fields), 123).unwrap_err();
            assert_eq!(error.kind, "resource_observation");
            assert_eq!(
                error.message,
                format!(
                    "native process numeric field rejected; field={role}; category=invalid_decimal"
                )
            );
        }
        for (token, category) in [
            (b"".as_slice(), "empty"),
            (b"private-token".as_slice(), "invalid_decimal"),
            (b"18446744073709551616".as_slice(), "overflow"),
            (b"2147483648".as_slice(), "overflow"),
            (b"0".as_slice(), "non_positive"),
        ] {
            let error = positive_pid(token, NumericField::DirectoryPid).unwrap_err();
            assert_eq!(
                error.message,
                format!(
                    "native process numeric field rejected; field=directory_pid; category={category}"
                )
            );
        }
        let error = parse_rollup(b"Rss: private-token kB\n").unwrap_err();
        assert_eq!(
            error.message,
            "native process numeric field rejected; field=rss_kib; category=invalid_decimal"
        );
    }

    #[test]
    fn identity_change_never_becomes_a_successful_followup_observation() {
        let before = parse_stat(&stat('S', 2), 123).unwrap();
        for identity in [
            Identity {
                pid: 124,
                ..before.identity
            },
            Identity {
                start_ticks: 457,
                ..before.identity
            },
            Identity {
                group: 124,
                ..before.identity
            },
            Identity {
                session: 124,
                ..before.identity
            },
        ] {
            assert_eq!(
                verify_identity(before, Stat { identity, ..before })
                    .unwrap_err()
                    .kind,
                "process_identity"
            );
        }
        verify_identity(
            before,
            Stat {
                state: b'R',
                virtual_bytes: 1,
                ..before
            },
        )
        .unwrap();
    }

    #[test]
    fn rss_rollup_uses_the_exact_rss_field_and_checked_kib_conversion() {
        assert_eq!(
            parse_rollup(b"0000-ffff ---p [rollup]\nPss: 5 kB\nRss: 2048 kB\n").unwrap(),
            2 * 1024 * 1024
        );
        assert_eq!(parse_rollup(b"Rss: 0 kB\n").unwrap(), 0);
    }

    #[test]
    fn malformed_or_incomplete_rss_never_becomes_zero() {
        for bytes in [
            b"Pss: 10 kB\n".to_vec(),
            b"Rss: 1 kB\nRss: 2 kB\n".to_vec(),
            b"Rss: 1 KB\n".to_vec(),
            b"Rss: -1 kB\n".to_vec(),
            b"Rss: 1 kB extra\n".to_vec(),
            b"Rss: 18446744073709551615 kB\n".to_vec(),
            vec![b'0'; ROLLUP_BYTES + 1],
        ] {
            assert!(parse_rollup(&bytes).is_err());
        }
    }

    #[test]
    fn sample_accumulation_preserves_vm_and_rejects_rss_or_count_overflow() {
        let actual = parse_stat(&stat('S', 1), 123).unwrap();
        let mut sample = Sample {
            live_processes: 0,
            aggregate_rss_bytes: Some(0),
            known_rss_bytes: 0,
            max_virtual_bytes: 0,
        };
        for _ in 0..LIVE_LIMIT {
            push(
                &mut sample,
                MemberSample {
                    live: true,
                    virtual_bytes: actual.virtual_bytes,
                    rss: Some(4096),
                },
            )
            .unwrap();
        }
        assert_eq!(sample.live_processes, LIVE_LIMIT);
        assert_eq!(sample.aggregate_rss_bytes, Some(LIVE_LIMIT as u64 * 4096));
        assert_eq!(sample.max_virtual_bytes, actual.virtual_bytes);
        push(
            &mut sample,
            MemberSample {
                live: true,
                virtual_bytes: actual.virtual_bytes,
                rss: None,
            },
        )
        .unwrap();
        assert_eq!(sample.live_processes, LIVE_LIMIT + 1);
        assert_eq!(sample.aggregate_rss_bytes, None);
        let known = sample.known_rss_bytes;
        push(
            &mut sample,
            MemberSample {
                live: true,
                virtual_bytes: 0,
                rss: Some(8192),
            },
        )
        .unwrap();
        assert_eq!(sample.aggregate_rss_bytes, None);
        assert_eq!(sample.known_rss_bytes, known + 8192);
        let mut overflow = Sample {
            live_processes: 0,
            aggregate_rss_bytes: Some(u64::MAX),
            known_rss_bytes: u64::MAX,
            max_virtual_bytes: 0,
        };
        assert!(
            push(
                &mut overflow,
                MemberSample {
                    live: true,
                    virtual_bytes: actual.virtual_bytes,
                    rss: Some(1)
                }
            )
            .is_err()
        );
        overflow.live_processes = usize::MAX;
        assert!(
            push(
                &mut overflow,
                MemberSample {
                    live: true,
                    virtual_bytes: actual.virtual_bytes,
                    rss: None
                }
            )
            .is_err()
        );
    }

    #[test]
    fn pending_scan_preserves_other_members_lower_bounds_and_facts_before_hard_errors() {
        use super::super::resource_policy::{JVM_VM_LIMIT, MEMORY_LIMIT};
        let actual = parse_stat(&stat('Z', 2), 123).unwrap();
        for member in [
            MemberSample {
                live: true,
                virtual_bytes: actual.virtual_bytes,
                rss: Some(MEMORY_LIMIT + 1),
            },
            MemberSample {
                live: true,
                virtual_bytes: JVM_VM_LIMIT + 1,
                rss: Some(1),
            },
        ] {
            let mut sample = Sample {
                live_processes: 0,
                aggregate_rss_bytes: Some(0),
                known_rss_bytes: 0,
                max_virtual_bytes: 0,
            };
            let mut pending = PendingObservations::default();
            accumulate(&mut sample, MemberObservation::Settled(None), &mut pending).unwrap();
            accumulate(
                &mut sample,
                MemberObservation::Pending(
                    MemberSample {
                        live: true,
                        virtual_bytes: actual.virtual_bytes,
                        rss: None,
                    },
                    Box::new(pending_observation()),
                ),
                &mut pending,
            )
            .unwrap();
            assert_eq!(sample.aggregate_rss_bytes, None);
            assert_eq!(sample.known_rss_bytes, 0);
            assert_eq!(sample.live_processes, 1);
            let error = accumulate(
                &mut sample,
                MemberObservation::Settled(Some(member)),
                &mut pending,
            )
            .unwrap_err();
            assert_eq!(error.kind, "resource_budget");
            assert_eq!(sample.live_processes, 2);
            assert_eq!(sample.known_rss_bytes, member.rss.unwrap());
            assert_eq!(
                sample.max_virtual_bytes,
                member.virtual_bytes.max(actual.virtual_bytes)
            );
            assert_eq!(sample.aggregate_rss_bytes, None);
            assert!(
                pending
                    .leader
                    .unwrap()
                    .last
                    .original_error()
                    .to_string()
                    .contains("operation=open;")
            );
        }
        let mut sample = Sample {
            live_processes: LIVE_LIMIT,
            aggregate_rss_bytes: None,
            known_rss_bytes: 4096,
            max_virtual_bytes: actual.virtual_bytes,
        };
        let mut pending = PendingObservations::from(pending_observation());
        assert_eq!(
            accumulate(
                &mut sample,
                MemberObservation::Settled(Some(MemberSample {
                    live: true,
                    virtual_bytes: actual.virtual_bytes,
                    rss: None,
                })),
                &mut pending
            )
            .unwrap_err()
            .kind,
            "resource_budget"
        );
        assert!(!pending.is_empty());
        let empty = Sample {
            live_processes: 0,
            aggregate_rss_bytes: None,
            known_rss_bytes: 0,
            max_virtual_bytes: 0,
        };
        assert!(!GroupObservation::Pending(empty).scope_empty());
        assert!(GroupObservation::Complete(empty).scope_empty());

        for roles in [
            vec![PendingRole::OwnedMember, PendingRole::OwnedMember],
            vec![
                PendingRole::ReservedLeader,
                PendingRole::OwnedMember,
                PendingRole::OwnedMember,
            ],
            vec![PendingRole::OwnedMember, PendingRole::ReservedLeader],
        ] {
            let mut sample = Sample {
                live_processes: 0,
                aggregate_rss_bytes: Some(0),
                known_rss_bytes: 0,
                max_virtual_bytes: 0,
            };
            let mut pending = PendingObservations::default();
            for (index, role) in roles.iter().enumerate() {
                let mut observation = pending_observation_for_role(*role);
                // Vary an existing closed error fact to make first/last
                // ordering observable. This pure fixture grants no proof.
                observation.original_drained = index == 0;
                accumulate(
                    &mut sample,
                    MemberObservation::Pending(
                        MemberSample {
                            live: true,
                            virtual_bytes: actual.virtual_bytes,
                            rss: None,
                        },
                        Box::new(observation),
                    ),
                    &mut pending,
                )
                .unwrap();
            }
            assert_eq!(sample.live_processes, roles.len());
            assert_eq!(sample.aggregate_rss_bytes, None);
            assert_eq!(
                pending.member.as_ref().unwrap().count as usize,
                roles
                    .iter()
                    .filter(|role| **role == PendingRole::OwnedMember)
                    .count()
            );
            assert_eq!(
                pending.leader.as_ref().map_or(0, |h| h.count) as usize,
                roles
                    .iter()
                    .filter(|role| **role == PendingRole::ReservedLeader)
                    .count()
            );
            assert_eq!(pending.last_role, roles.last().copied());
            // A later measured member still contributes to the partial
            // budget. Its failure cannot erase any earlier pending facts.
            let error = accumulate(
                &mut sample,
                MemberObservation::Settled(Some(MemberSample {
                    live: true,
                    virtual_bytes: actual.virtual_bytes,
                    rss: Some(MEMORY_LIMIT + 1),
                })),
                &mut pending,
            )
            .unwrap_err();
            assert_eq!(error.kind, "resource_budget");
            assert_eq!(sample.known_rss_bytes, MEMORY_LIMIT + 1);
            assert_eq!(sample.aggregate_rss_bytes, None);
            assert_eq!(
                pending.member.as_ref().unwrap().count as usize,
                roles
                    .iter()
                    .filter(|role| **role == PendingRole::OwnedMember)
                    .count()
            );
            assert_eq!(
                pending.member.as_ref().unwrap().first.role,
                PendingRole::OwnedMember
            );
            assert_eq!(
                pending.member.as_ref().unwrap().last.role,
                PendingRole::OwnedMember
            );
            let first_member = roles
                .iter()
                .position(|r| *r == PendingRole::OwnedMember)
                .unwrap();
            let last_member = roles
                .iter()
                .rposition(|r| *r == PendingRole::OwnedMember)
                .unwrap();
            assert_eq!(
                pending.member.as_ref().unwrap().first.original_drained,
                first_member == 0
            );
            assert_eq!(
                pending.member.as_ref().unwrap().last.original_drained,
                last_member == 0
            );
            assert_eq!(pending.last_role, roles.last().copied());
            // Merging a complete scan retains the original first fact and
            // the incoming last fact without counting observations twice.
            let mut prior = pending_observation_for_role(PendingRole::OwnedMember);
            prior.original_drained = false;
            let mut history = None;
            PendingHistory::record(&mut history, prior);
            PendingHistory::merge(&mut history, pending.member.take().unwrap());
            let history = history.unwrap();
            assert_eq!(
                history.count as usize,
                1 + roles
                    .iter()
                    .filter(|r| **r == PendingRole::OwnedMember)
                    .count()
            );
            assert!(!history.first.original_drained);
            assert_eq!(history.last.original_drained, last_member == 0);
        }
    }

    #[test]
    fn rss_error_is_fatal_for_the_live_original_task_and_never_becomes_zero() {
        let before = parse_stat(&stat('S', 2), 123).unwrap();
        let error = metadata("actual native RSS observation failed");
        let actual = settle_member(before, Some(before), Some(Err(error)), false).unwrap_err();
        assert_eq!(actual.message, "actual native RSS observation failed");
        let zombie_with_workers = parse_stat(&stat('Z', 2), 123).unwrap();
        assert!(
            settle_member(
                before,
                Some(zombie_with_workers),
                Some(Err(metadata("RSS unavailable"))),
                false
            )
            .is_err()
        );
    }

    #[test]
    fn successful_rss_survives_confirmed_task_exit_without_a_live_count() {
        let before = parse_stat(&stat('S', 1), 123).unwrap();
        let exited = parse_stat(&stat('Z', 1), 123).unwrap();
        for after in [Some(exited), None] {
            let member = settle_member(before, after, Some(Ok(2 * 1024 * 1024 * 1024 + 1)), false)
                .unwrap()
                .unwrap();
            assert!(!member.live);
            let mut sample = Sample {
                live_processes: 0,
                aggregate_rss_bytes: Some(0),
                known_rss_bytes: 0,
                max_virtual_bytes: 0,
            };
            push(&mut sample, member).unwrap();
            assert_eq!(sample.live_processes, 0);
            assert_eq!(sample.aggregate_rss_bytes, Some(2 * 1024 * 1024 * 1024 + 1));
            assert_eq!(sample.max_virtual_bytes, before.virtual_bytes);
        }
    }

    #[test]
    fn only_confirmed_original_task_exit_can_omit_an_unavailable_rss_observation() {
        let before = parse_stat(&stat('S', 1), 123).unwrap();
        let exited = parse_stat(&stat('Z', 1), 123).unwrap();
        assert!(
            settle_member(
                before,
                Some(exited),
                Some(Err(metadata("RSS unavailable"))),
                false
            )
            .unwrap()
            .is_none()
        );
        assert!(
            settle_member(before, None, Some(Err(metadata("RSS unavailable"))), false)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            settle_member(before, None, Some(Ok(4096)), true)
                .unwrap_err()
                .kind,
            "process_identity"
        );
    }
}

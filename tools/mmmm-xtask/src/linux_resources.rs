//! Cooperative Linux process-group observations through anchored procfs files.
//!
//! RSS is a sequential sum of per-process smaps_rollup observations. Shared
//! pages occur in each process's RSS; this is neither a simultaneous group
//! snapshot nor a kernel resident-memory quota. Detached sessions are outside
//! the cooperative ownership boundary.
use super::ProcessError;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// Diagnostic-only facts from reads the observer already performed. No native
/// identity values, path, comm or original procfs tokens are retained here.
/// Missing observations stay absent and grant no exit or drain authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StatDiagnostic {
    role: ProcessRole,
    before_state: Option<StatState>,
    before_threads: Option<u64>,
    before_original_identity_match: Option<bool>,
    after_state: Option<StatState>,
    after_threads: Option<u64>,
    after_original_identity_match: Option<bool>,
}

impl StatDiagnostic {
    fn observed(
        role: ProcessRole,
        original: Identity,
        before: Option<Stat>,
        after: Option<Stat>,
    ) -> Self {
        Self {
            role,
            before_state: before.and_then(|stat| StatState::observed(stat.state)),
            before_threads: before.map(|stat| stat.threads),
            before_original_identity_match: before.map(|stat| stat.identity == original),
            after_state: after.and_then(|stat| StatState::observed(stat.state)),
            after_threads: after.map(|stat| stat.threads),
            after_original_identity_match: after.map(|stat| stat.identity == original),
        }
    }
}

impl fmt::Display for StatDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "linux_stat_observation(process_role={}; before_state={:?}; before_threads={:?}; before_original_identity_match={:?}; after_state={:?}; after_threads={:?}; after_original_identity_match={:?})",
            self.role.label(),
            self.before_state,
            self.before_threads,
            self.before_original_identity_match,
            self.after_state,
            self.after_threads,
            self.after_original_identity_match,
        )
    }
}

/// A count-only observation has no RSS value. A memory observation also leaves
/// RSS absent once the live-count limit is exceeded: incomplete memory is never
/// presented as zero or as a complete successful sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Sample {
    pub live_processes: usize,
    pub aggregate_rss_bytes: Option<u64>,
    pub max_virtual_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct MemberSample {
    live: bool,
    virtual_bytes: u64,
    rss: Option<u64>,
}

fn push(sample: &mut Sample, member: MemberSample) -> Result<(), ProcessError> {
    if member.live {
        sample.live_processes = sample
            .live_processes
            .checked_add(1)
            .ok_or_else(|| metadata("native live process count overflow"))?;
    }
    sample.max_virtual_bytes = sample.max_virtual_bytes.max(member.virtual_bytes);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        ) -> Result<Sample, ProcessError> {
            let leader_before = self.check_leader()?;
            let group = leader_before.identity.pid;
            let mut sample = Sample {
                live_processes: 0,
                aggregate_rss_bytes: include_rss.then_some(0),
                max_virtual_bytes: 0,
            };
            // The held leader is observed explicitly, using its original stat
            // FD. Enumeration is only for the remaining process candidates.
            let leader_sample =
                match observe_member(&self.root, &mut self.leader, include_rss, true) {
                    Ok(sample) => sample,
                    Err(error) => {
                        if error.kind == "process_identity" {
                            self.reservation_valid = false;
                        }
                        return Err(error);
                    }
                };
            if let Some(member) = leader_sample {
                push(&mut sample, member)?;
            }
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
                if let Some(member) = observe_member(&self.root, &mut member, read_rss, false)? {
                    push(&mut sample, member)?;
                }
            }
            self.check_leader()?;
            Ok(sample)
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
    ) -> Result<Option<MemberSample>, ProcessError> {
        let role = if is_leader {
            ProcessRole::ReservedLeader
        } else {
            ProcessRole::OwnedMember
        };
        let mut diagnostic = StatDiagnostic::observed(role, process.initial.identity, None, None);
        observe_member_with_facts(root, process, include_rss, is_leader, &mut diagnostic)
            .map_err(|error| error.with_linux_stat_diagnostic(diagnostic))
    }

    fn observe_member_with_facts(
        root: &File,
        process: &mut ProcDirectory,
        include_rss: bool,
        is_leader: bool,
        diagnostic: &mut StatDiagnostic,
    ) -> Result<Option<MemberSample>, ProcessError> {
        let pid = process.initial.identity.pid;
        let role = if is_leader {
            ProcessRole::ReservedLeader
        } else {
            ProcessRole::OwnedMember
        };
        let Some(before) = read_stat(&mut process.stat, pid, role)? else {
            return unavailable_member(is_leader);
        };
        *diagnostic = StatDiagnostic::observed(role, process.initial.identity, Some(before), None);
        verify_identity(process.initial, before)?;
        if before.definitely_exited() {
            return Ok(None);
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
            )? {
                pidfd::Binding::Bound(bound) => Some(bound),
                pidfd::Binding::Unavailable(reason) => {
                    // Keep the closed reason distinct inside the producer;
                    // it is not a replacement for the actual RSS failure.
                    pidfd_diagnostic = Some(reason.diagnostic());
                    None
                }
                pidfd::Binding::OriginalGone => return unavailable_member(is_leader),
            }
        } else {
            None
        };
        let memory = if include_rss {
            Some(read_rollup(&process.directory, role))
        } else {
            None
        };
        let after = read_stat(&mut process.stat, pid, role)?;
        *diagnostic = StatDiagnostic::observed(role, process.initial.identity, Some(before), after);
        if let Some(after) = after {
            verify_identity(before, after)?;
        }
        // Exactly one nonblocking kernel check, after an actual RSS failure.
        // The witness requires a matching post-RSS original stat identity;
        // losing the leader reservation cannot be repaired with a pidfd.
        let terminal = match (&memory, after, bound.as_ref()) {
            (Some(Err(_)), Some(after), Some(bound)) if !after.definitely_exited() => {
                let check = bound.check_terminal_after(after.identity);
                pidfd_diagnostic = Some(check.diagnostic);
                check.witness
            }
            _ => None,
        };
        // smaps_rollup ESRCH/ENOENT alone never proves death: a live original
        // stat identity makes that exact RSS observation error fatal.
        // Successful RSS stays an observed fact even when this process exits
        // immediately afterwards. Its live count may drop; its measured RSS
        // and VM must not disappear from the resource budget evidence.
        let failed_rss = memory.as_ref().is_some_and(Result::is_err);
        let settled = if let Some(terminal) = terminal.as_ref() {
            settle_member_with_terminal(before, after, memory, is_leader, Some(terminal))
        } else {
            settle_member(before, after, memory, is_leader)
        };
        settled.map_err(|error| match (failed_rss, pidfd_diagnostic) {
            (true, Some(diagnostic)) => error.with_linux_pidfd_diagnostic(diagnostic),
            _ => error,
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

    fn read_rollup(directory: &File, role: ProcessRole) -> Result<u64, ProcessError> {
        let mut file = open_file(directory, MetadataRole::RssRollup, role)?;
        let bytes = read_bounded(&mut file, ROLLUP_BYTES).map_err(|error| {
            metadata_io_error(
                role,
                MetadataRole::RssRollup,
                MetadataOperation::Read,
                error,
            )
        })?;
        parse_rollup(&bytes)
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
            MetadataRole::RssRollup => read_rollup(directory, role).map(Some),
            MetadataRole::PidDirectory => Err(metadata("test metadata role is not a file")),
        }
    }

    fn open_file(
        directory: &File,
        file: MetadataRole,
        role: ProcessRole,
    ) -> Result<File, ProcessError> {
        let name = file.file_name()?;
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(metadata_io_error(
                role,
                file,
                MetadataOperation::Open,
                std::io::Error::last_os_error(),
            ));
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
mod tests {
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

    #[test]
    fn stat_diagnostic_retains_only_observed_states_threads_and_identity_matches() {
        let before = parse_stat(&stat('S', 5), 123).unwrap();
        let after = parse_stat(&stat('Z', 2), 123).unwrap();
        let diagnostic = StatDiagnostic::observed(
            ProcessRole::ReservedLeader,
            before.identity,
            Some(before),
            Some(after),
        );
        assert_eq!(diagnostic.before_state, Some(StatState::Sleeping));
        assert_eq!(diagnostic.before_threads, Some(5));
        assert_eq!(diagnostic.before_original_identity_match, Some(true));
        assert_eq!(diagnostic.after_state, Some(StatState::Zombie));
        assert_eq!(diagnostic.after_threads, Some(2));
        assert_eq!(diagnostic.after_original_identity_match, Some(true));
        assert_eq!(
            diagnostic.to_string(),
            "linux_stat_observation(process_role=reserved_leader; before_state=Some(Sleeping); before_threads=Some(5); before_original_identity_match=Some(true); after_state=Some(Zombie); after_threads=Some(2); after_original_identity_match=Some(true))",
        );

        let missing =
            StatDiagnostic::observed(ProcessRole::OwnedMember, before.identity, None, None);
        assert_eq!(missing.before_state, None);
        assert_eq!(missing.before_threads, None);
        assert_eq!(missing.before_original_identity_match, None);
        assert_eq!(missing.after_state, None);
        assert_eq!(missing.after_threads, None);
        assert_eq!(missing.after_original_identity_match, None);
        assert!(missing.to_string().contains("process_role=owned_member;"));
    }

    #[test]
    fn stat_diagnostic_compares_each_original_identity_component_without_printing_it() {
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
            let changed = Stat { identity, ..before };
            let diagnostic = StatDiagnostic::observed(
                ProcessRole::ReservedLeader,
                before.identity,
                Some(changed),
                Some(changed),
            );
            assert_eq!(diagnostic.before_original_identity_match, Some(false));
            assert_eq!(diagnostic.after_original_identity_match, Some(false));
            let text = diagnostic.to_string();
            for absent in ["123", "124", "456", "457", "start_ticks", "native ) comm"] {
                assert!(!text.contains(absent));
            }
        }
    }

    #[test]
    fn stat_diagnostic_text_has_a_closed_state_set_and_a_fixed_bound() {
        for state in b"RSDZTXxtKWPI" {
            let before = parse_stat(&stat(*state as char, u64::MAX), 123).unwrap();
            let diagnostic = StatDiagnostic::observed(
                ProcessRole::ReservedLeader,
                before.identity,
                Some(before),
                Some(before),
            );
            let text = diagnostic.to_string();
            assert!(diagnostic.before_state.is_some());
            assert!(text.len() < 384);
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
            let diagnostic =
                StatDiagnostic::observed(role, before.identity, Some(before), Some(after));
            let actual = settle_member(before, Some(after), Some(Err(original)), is_leader)
                .expect_err("stat diagnostics cannot settle the live original RSS failure")
                .with_linux_pidfd_diagnostic(pidfd)
                .with_linux_stat_diagnostic(diagnostic)
                .with_linux_stat_diagnostic(StatDiagnostic::observed(
                    role,
                    before.identity,
                    None,
                    None,
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
        let mut overflow = Sample {
            live_processes: 0,
            aggregate_rss_bytes: Some(u64::MAX),
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

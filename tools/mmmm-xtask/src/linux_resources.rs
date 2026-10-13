//! Cooperative Linux process-group observations through anchored procfs files.
//!
//! RSS is a sequential sum of per-process smaps_rollup observations. Shared
//! pages occur in each process's RSS; this is neither a simultaneous group
//! snapshot nor a kernel resident-memory quota. Detached sessions are outside
//! the cooperative ownership boundary.
use super::ProcessError;

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
    if after.is_none() && is_leader {
        return Err(ProcessError::new(
            "process_identity",
            "reserved Linux leader disappeared during resource observation",
        ));
    }
    if let Some(after) = after {
        verify_identity(before, after)?;
    }
    let live = after.is_some_and(|stat| !stat.definitely_exited());
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
    let pid = signed(trim(&bytes[..begin]))?;
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
            group: signed(fields[2])?,
            session: signed(fields[3])?,
            start_ticks: unsigned(fields[19])?,
        },
        state: fields[0][0],
        threads: unsigned(fields[17])?,
        virtual_bytes: unsigned(fields[20])?,
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
                unsigned(fields[0])?
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

fn unsigned(bytes: &[u8]) -> Result<u64, ProcessError> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(metadata("native process numeric field is invalid"));
    }
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| metadata("native process numeric field overflows"))
}

fn signed(bytes: &[u8]) -> Result<i32, ProcessError> {
    let value = unsigned(bytes)?;
    i32::try_from(value).map_err(|_| metadata("native process identity field overflows"))
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
            let leader = open_process(&root, leader_pid)?.ok_or_else(|| {
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
            let leader_sample = match observe_member(&mut self.leader, include_rss, true) {
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
                let pid = signed(&name)?;
                if pid == group {
                    continue;
                }
                let Some(mut member) = open_process(&self.root, pid)? else {
                    // This candidate disappeared before it had an anchored
                    // identity. It is not a confirmed owned-process exit.
                    continue;
                };
                let stat = member.initial;
                if stat.identity.session == group
                    && stat.identity.group != group
                    && !stat.definitely_exited()
                {
                    return Err(ProcessError::new(
                        "scope_escape",
                        "owned Linux session member changed process group",
                    ));
                }
                if stat.identity.group != group {
                    continue;
                }
                if stat.identity.session != group {
                    return Err(ProcessError::new(
                        "process_identity",
                        "owned Linux process group has inconsistent session identity",
                    ));
                }
                let read_rss = include_rss && sample.live_processes < LIVE_LIMIT;
                if let Some(member) = observe_member(&mut member, read_rss, false)? {
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
            let result = read_stat(&mut self.leader.stat, self.leader.initial.identity.pid)
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
        process: &mut ProcDirectory,
        include_rss: bool,
        is_leader: bool,
    ) -> Result<Option<MemberSample>, ProcessError> {
        let pid = process.initial.identity.pid;
        let Some(before) = read_stat(&mut process.stat, pid)? else {
            return unavailable_member(is_leader);
        };
        verify_identity(process.initial, before)?;
        if before.definitely_exited() {
            return Ok(None);
        }
        let memory = if include_rss {
            Some(read_rollup(&process.directory))
        } else {
            None
        };
        let after = read_stat(&mut process.stat, pid)?;
        // smaps_rollup ESRCH/ENOENT alone never proves death: a live original
        // stat identity makes that exact RSS observation error fatal.
        // Successful RSS stays an observed fact even when this process exits
        // immediately afterwards. Its live count may drop; its measured RSS
        // and VM must not disappear from the resource budget evidence.
        settle_member(before, after, memory, is_leader)
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

    fn open_process(root: &File, pid: i32) -> Result<Option<ProcDirectory>, ProcessError> {
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
            return Err(io_error("open native PID directory", error));
        }
        let directory = unsafe { File::from_raw_fd(descriptor) };
        let mut stat = open_file(&directory, c"stat")?;
        let Some(initial) = read_stat(&mut stat, pid)? else {
            return Ok(None);
        };
        Ok(Some(ProcDirectory {
            directory,
            stat,
            initial,
        }))
    }

    fn read_stat(file: &mut File, pid: i32) -> Result<Option<Stat>, ProcessError> {
        file.rewind()
            .map_err(|error| io_error("rewind original native stat FD", error))?;
        let bytes = match read_bounded(file, STAT_BYTES) {
            Ok(bytes) => bytes,
            // An already opened stat inode's actual read reaches
            // proc_single_show/get_pid_task. ESRCH there confirms that the
            // original task disappeared, rather than merely losing its mm.
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(None),
            Err(error) => return Err(io_error("read original native stat FD", error)),
        };
        parse_stat(&bytes, pid).map(Some)
    }

    fn read_rollup(directory: &File) -> Result<u64, ProcessError> {
        let mut file = open_file(directory, c"smaps_rollup")?;
        let bytes = read_bounded(&mut file, ROLLUP_BYTES)
            .map_err(|error| io_error("read native RSS rollup", error))?;
        parse_rollup(&bytes)
    }

    fn open_file(directory: &File, name: &CStr) -> Result<File, ProcessError> {
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        owned_file(descriptor, "open fixed native metadata file")
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

    fn stat(state: char, threads: u64) -> Vec<u8> {
        let mut fields = vec!["0".to_owned(); 21];
        fields[0] = state.to_string();
        fields[2] = "123".to_owned();
        fields[3] = "123".to_owned();
        fields[17] = threads.to_string();
        fields[19] = "456".to_owned();
        fields[20] = "987654".to_owned();
        format!("123 (native ) comm) {}\n", fields.join(" ")).into_bytes()
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
        assert!(signed(b"2147483648").is_err());
        assert!(unsigned(b"18446744073709551616").is_err());
        assert!(unsigned(b"-1").is_err());
        assert!(unsigned(b"+1").is_err());
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

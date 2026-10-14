//! Actual Linux liveness regressions for the private pidfd producer.
//!
//! Pure stat/mask fixtures cannot show that a flags=0 kernel pidfd stays
//! nonterminal after its leader exits while a worker survives. This fixture
//! therefore runs in a fresh owned exec, never arbitrary Rust after fork.
use super::super::super::{
    MetadataRole, ProcessError, ProcessRole, Stat, native as procfs, settle_member_with_terminal,
    verify_identity,
};
use super::super::{Binding, BoundPidfd, PollObservation, bind};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const BUDGET: Duration = Duration::from_secs(3);
const CLEANUP_RESERVE: Duration = Duration::from_millis(500);
const OUTPUT_BYTES: usize = 4096;
const CHECKS: usize = 1500;
const READY: &[u8] = b"MMMM_PIDFD_READY_V1\n";
const WORKER_ALIVE: &[u8] = b"MMMM_PIDFD_WORKER_ALIVE_V1\n";
const FAILURE: &[u8] = b"\0MMMM_PIDFD_FAILURE_V1\0";
const FIXTURE: &str =
    "process::linux_resources::pidfd::tests::native_lifecycle::fixture_process_lifecycle";

type TestResult<T> = Result<T, String>;

fn io_failure(stage: &'static str, error: std::io::Error) -> String {
    format!(
        "pidfd native fixture failed; stage={stage}; error_kind={:?}; os_error={:?}",
        error.kind(),
        error.raw_os_error(),
    )
}

fn native_failure(stage: &'static str, error: ProcessError) -> String {
    format!("pidfd native fixture failed; stage={stage}; {error}")
}

fn unavailable_binding(reason: super::super::BindingUnavailable) -> String {
    format!(
        "pidfd native fixture binding unavailable; category={reason:?}; actual_binding_not_run=true"
    )
}

struct Fixture {
    child: Child,
    deadline: Instant,
    observation_deadline: Instant,
    output: Vec<u8>,
    output_bytes: usize,
    output_eof: bool,
    failure_observed: bool,
    status: Option<ExitStatus>,
}

impl Fixture {
    fn spawn() -> TestResult<Self> {
        let started = Instant::now();
        let deadline = started + BUDGET;
        let executable =
            std::env::current_exe().map_err(|error| io_failure("executable", error))?;
        let child = Command::new(executable)
            .args([
                "--exact",
                FIXTURE,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| io_failure("spawn", error))?;
        let mut fixture = Self {
            child,
            deadline,
            observation_deadline: deadline - CLEANUP_RESERVE,
            output: Vec::new(),
            output_bytes: 0,
            output_eof: false,
            failure_observed: false,
            status: None,
        };
        let stdin = fixture.child.stdin.as_ref().ok_or("fixture stdin absent")?;
        nonblocking(stdin.as_raw_fd())?;
        let stdout = fixture
            .child
            .stdout
            .as_ref()
            .ok_or("fixture stdout absent")?;
        nonblocking(stdout.as_raw_fd())?;
        fixture.frame(READY)?;
        Ok(fixture)
    }

    fn pid(&self) -> TestResult<i32> {
        i32::try_from(self.child.id()).map_err(|_| "fixture child identity out of range".to_owned())
    }

    fn budget(&self) -> TestResult<()> {
        if Instant::now() >= self.observation_deadline {
            Err("pidfd native fixture observation deadline".to_owned())
        } else {
            Ok(())
        }
    }

    fn command(&mut self, command: u8) -> TestResult<()> {
        self.budget()?;
        let stdin = self.child.stdin.as_ref().ok_or("fixture stdin absent")?;
        let written = unsafe { libc::write(stdin.as_raw_fd(), (&command as *const u8).cast(), 1) };
        if written == 1 {
            Ok(())
        } else if written < 0 {
            Err(io_failure("command", std::io::Error::last_os_error()))
        } else {
            Err("pidfd native fixture short command write".to_owned())
        }
    }

    fn read_output(&mut self) -> TestResult<()> {
        if self.output_eof {
            return Ok(());
        }
        let stdout = self.child.stdout.as_mut().ok_or("fixture stdout absent")?;
        let mut bytes = [0u8; 256];
        match stdout.read(&mut bytes) {
            Ok(0) => self.output_eof = true,
            Ok(read) => {
                self.output_bytes += read;
                if self.output_bytes > OUTPUT_BYTES {
                    return Err("pidfd native fixture output bound".to_owned());
                }
                self.output.extend_from_slice(&bytes[..read]);
                if let Some(at) = self
                    .output
                    .windows(FAILURE.len())
                    .position(|part| part == FAILURE)
                    .filter(|_| !self.failure_observed)
                {
                    let frame = &self.output[at + FAILURE.len()..];
                    if frame.len() >= 5 {
                        let stage =
                            failure_stage(frame[0]).ok_or("invalid native fixture failure role")?;
                        let code = i32::from_ne_bytes(
                            frame[1..5]
                                .try_into()
                                .map_err(|_| "invalid native fixture error code")?,
                        );
                        self.failure_observed = true;
                        if code == 0 {
                            return Err(format!(
                                "pidfd native fixture failed; stage={stage}; short_or_invalid_native_result=true"
                            ));
                        }
                        return Err(io_failure(stage, std::io::Error::from_raw_os_error(code)));
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(io_failure("stdout_read", error)),
        }
        Ok(())
    }

    fn update_status(&mut self) -> TestResult<()> {
        if self.status.is_none() {
            self.status = self
                .child
                .try_wait()
                .map_err(|error| io_failure("wait", error))?;
        }
        Ok(())
    }

    fn frame(&mut self, marker: &[u8]) -> TestResult<()> {
        for _ in 0..CHECKS {
            self.budget()?;
            self.read_output()?;
            if let Some(at) = self
                .output
                .windows(marker.len())
                .position(|part| part == marker)
            {
                self.output.drain(..at + marker.len());
                return Ok(());
            }
            self.update_status()?;
            if self.output_eof {
                return Err(format!(
                    "pidfd native fixture ended before protocol frame; exit_code={:?}; signal={:?}",
                    self.status.and_then(|status| status.code()),
                    self.status.and_then(|status| status.signal()),
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Err("pidfd native fixture frame call bound".to_owned())
    }

    fn wait_exit(&mut self) -> TestResult<ExitStatus> {
        for _ in 0..CHECKS {
            if Instant::now() >= self.deadline {
                return Err("pidfd native fixture exit/drain deadline".to_owned());
            }
            self.update_status()?;
            self.read_output()?;
            if self.output_eof
                && let Some(status) = self.status
            {
                return Ok(status);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Err("pidfd native fixture exit/drain call bound".to_owned())
    }

    fn until_stat(
        &mut self,
        member: &mut Member,
        accepted: impl Fn(Stat) -> bool,
    ) -> TestResult<Stat> {
        for _ in 0..CHECKS {
            self.budget().map_err(|_| {
                "pidfd native fixture failed; stage=leader_signal_delivered_not_observed; deadline_reached=true".to_owned()
            })?;
            let stat = member.read()?.ok_or("fixture original stat disappeared")?;
            verify_identity(member.initial, stat)
                .map_err(|error| native_failure("identity", error))?;
            if accepted(stat) {
                return Ok(stat);
            }
            self.update_status()?;
            if self.status.is_some() {
                return Err("fixture exited before required original stat observation".to_owned());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Err("pidfd native fixture failed; stage=leader_signal_delivered_not_observed; call_bound=true".to_owned())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.status.is_some() && self.output_eof {
            return;
        }
        // Only this still-owned Child may be killed. There is no numeric PID
        // fallback after identity uncertainty or after a successful wait.
        if self.status.is_none()
            && let Err(error) = self.child.kill()
        {
            eprintln!("{}", io_failure("cleanup_kill", error));
        }
        if let Err(error) = self.wait_exit() {
            eprintln!("{error}; cleanup_incomplete=true");
        }
    }
}

fn nonblocking(descriptor: libc::c_int) -> TestResult<()> {
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(io_failure("pipe_flags", std::io::Error::last_os_error()));
    }
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(io_failure(
            "pipe_nonblocking",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

struct Member {
    root: File,
    directory: File,
    original_stat: File,
    initial: Stat,
}

impl Member {
    fn capture(fixture: &Fixture) -> TestResult<Self> {
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/proc")
            .map_err(|error| io_failure("proc_root", error))?;
        let (directory, original_stat, initial) =
            procfs::test_open_member(&root, fixture.pid()?, ProcessRole::OwnedMember)
                .map_err(|error| native_failure("open_member", error))?
                .ok_or("fixture had no anchored initial identity")?;
        if initial.definitely_exited() || initial.threads < 2 {
            return Err("fixture leader/worker lifetime was not established".to_owned());
        }
        Ok(Self {
            root,
            directory,
            original_stat,
            initial,
        })
    }

    fn read(&mut self) -> TestResult<Option<Stat>> {
        procfs::test_read_stat(
            &mut self.original_stat,
            self.initial.identity.pid,
            ProcessRole::OwnedMember,
        )
        .map_err(|error| native_failure("original_stat", error))
    }

    fn bind(&mut self) -> TestResult<BoundPidfd> {
        let before = self
            .read()?
            .ok_or("fixture original stat missing before binding")?;
        verify_identity(self.initial, before)
            .map_err(|error| native_failure("before_binding", error))?;
        let pid = self.initial.identity.pid;
        match bind(
            &self.root,
            &self.directory,
            &mut self.original_stat,
            before,
            |file| procfs::test_read_stat(file, pid, ProcessRole::OwnedMember),
        )
        .map_err(|error| native_failure("binding", error))?
        {
            Binding::Bound(bound) => Ok(bound),
            Binding::Unavailable(reason) => Err(unavailable_binding(reason)),
            Binding::OriginalGone => Err("fixture disappeared while binding".to_owned()),
        }
    }
}

fn assert_success(status: ExitStatus) -> TestResult<()> {
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "pidfd native fixture command failed; exit_code={:?}; signal={:?}",
            status.code(),
            status.signal(),
        ))
    }
}

#[test]
fn actual_live_child_binds_then_same_held_pidfd_becomes_terminal() -> TestResult<()> {
    let mut fixture = Fixture::spawn()?;
    let mut member = Member::capture(&fixture)?;
    let bound = member.bind()?;
    assert_eq!(
        super::super::native::poll_once(&bound.descriptor).observation,
        PollObservation::NotReady
    );
    let after = member.read()?.ok_or("live fixture stat absent")?;
    verify_identity(member.initial, after)
        .map_err(|error| native_failure("live_identity", error))?;
    fixture.command(b'Q')?;
    assert_success(fixture.wait_exit()?)?;
    let terminal = bound
        .terminal_after(after.identity)
        .ok_or("same held pidfd not terminal")?;
    assert!(terminal.matches(member.initial.identity, after.identity));
    Ok(())
}

#[test]
fn actual_leader_exit_preserves_rss_error_until_last_worker_exits() -> TestResult<()> {
    let mut fixture = Fixture::spawn()?;
    let mut member = Member::capture(&fixture)?;
    let bound = member.bind()?;
    fixture.command(b'L')?;
    fixture.frame(WORKER_ALIVE)?;
    let before = fixture.until_stat(&mut member, |stat| {
        matches!(stat.state, b'Z' | b'X' | b'x') && stat.threads > 1
    })?;
    let rss_error = procfs::test_metadata(
        &member.directory,
        MetadataRole::RssRollup,
        ProcessRole::OwnedMember,
    )
    .expect_err("leader-only exit must exercise the actual unavailable RSS branch");
    let after = member
        .read()?
        .ok_or("worker lifetime lost its original stat")?;
    verify_identity(before, after).map_err(|error| native_failure("worker_identity", error))?;
    assert!(!after.definitely_exited());
    assert_eq!(
        super::super::native::poll_once(&bound.descriptor).observation,
        PollObservation::NotReady
    );
    assert!(bound.terminal_after(after.identity).is_none());
    let expected = (rss_error.kind, rss_error.message.clone());
    let original_error =
        settle_member_with_terminal(before, Some(after), Some(Err(rss_error)), false, None)
            .expect_err("a surviving worker cannot settle the actual RSS error");
    assert_eq!(
        (original_error.kind, &original_error.message),
        (expected.0, &expected.1)
    );
    fixture.command(b'X')?;
    assert_success(fixture.wait_exit()?)?;
    let terminal = bound
        .terminal_after(after.identity)
        .ok_or("last worker exit was not terminal")?;
    assert!(
        settle_member_with_terminal(
            before,
            Some(after),
            Some(Err(original_error)),
            false,
            Some(&terminal)
        )
        .map_err(|error| native_failure("terminal_settlement", error))?
        .is_none()
    );
    Ok(())
}

#[test]
fn actual_original_stat_loss_during_binding_never_issues_a_witness() -> TestResult<()> {
    let mut fixture = Fixture::spawn()?;
    let mut member = Member::capture(&fixture)?;
    let before = member.read()?.ok_or("fixture original stat missing")?;
    let pid = member.initial.identity.pid;
    let binding = bind(
        &member.root,
        &member.directory,
        &mut member.original_stat,
        before,
        |file| {
            fixture
                .command(b'Q')
                .map_err(|error| ProcessError::new("native_fixture", error))?;
            let status = fixture
                .wait_exit()
                .map_err(|error| ProcessError::new("native_fixture", error))?;
            assert_success(status).map_err(|error| ProcessError::new("native_fixture", error))?;
            procfs::test_read_stat(file, pid, ProcessRole::OwnedMember)
        },
    )
    .map_err(|error| native_failure("stat_loss_binding", error))?;
    match binding {
        Binding::OriginalGone => {}
        Binding::Unavailable(reason) => return Err(unavailable_binding(reason)),
        Binding::Bound(_) => return Err("lost original stat issued a binding".to_owned()),
    }
    let lost = member.read()?;
    assert!(lost.is_none());
    let leader_error = settle_member_with_terminal(before, lost, None, true, None)
        .expect_err("actual original stat loss cannot repair the leader reservation");
    assert_eq!(leader_error.kind, "process_identity");
    Ok(())
}

#[test]
fn actual_stat_reread_rejects_mismatched_full_identity() -> TestResult<()> {
    let mut fixture = Fixture::spawn()?;
    let mut member = Member::capture(&fixture)?;
    let before = member.read()?.ok_or("fixture original stat missing")?;
    // Corrupt the prior snapshot, not the actual producer or syscall result.
    // The closure still rereads the live original stat FD from the kernel.
    let mismatched = Stat {
        identity: super::super::Identity {
            start_ticks: before
                .identity
                .start_ticks
                .checked_add(1)
                .ok_or("start tick bound")?,
            ..before.identity
        },
        ..before
    };
    let pid = member.initial.identity.pid;
    let result = bind(
        &member.root,
        &member.directory,
        &mut member.original_stat,
        mismatched,
        |file| procfs::test_read_stat(file, pid, ProcessRole::OwnedMember),
    );
    match result {
        Err(error) => assert_eq!(error.kind, "process_identity"),
        Ok(Binding::Unavailable(reason)) => return Err(unavailable_binding(reason)),
        Ok(_) => return Err("actual stat reread accepted a mismatched prior identity".to_owned()),
    }
    fixture.command(b'Q')?;
    assert_success(fixture.wait_exit()?)?;
    Ok(())
}

#[test]
fn actual_first_stat_open_error_remains_fatal_after_owned_child_reap() -> TestResult<()> {
    let mut fixture = Fixture::spawn()?;
    let mut member = Member::capture(&fixture)?;
    // Prove the original root/directory/stat namespace and mount before the
    // later first-open error; holding a pidfd still cannot turn that error
    // into a successful initial metadata observation.
    let _bound = member.bind()?;
    fixture.command(b'Q')?;
    assert_success(fixture.wait_exit()?)?;
    let error = procfs::test_metadata(
        &member.directory,
        MetadataRole::Stat,
        ProcessRole::EnumeratedCandidate,
    )
    .expect_err("an actual first stat open failure must not become owned exit proof");
    assert_eq!(error.kind, "resource_observation");
    assert!(
        error
            .message
            .contains("process_role=enumerated_candidate; file_role=stat; operation=open;")
    );
    Ok(())
}

// Only this fresh-exec fixture installs the handler. No Rust, allocation,
// formatting, locking, unwinding or process-wide exit runs in the handler.
extern "C" fn exit_only_this_thread(_: libc::c_int) {
    unsafe {
        libc::syscall(libc::SYS_exit, 0);
        libc::_exit(126);
    }
}

fn fixture_write(bytes: &[u8]) {
    let written = unsafe { libc::write(libc::STDOUT_FILENO, bytes.as_ptr().cast(), bytes.len()) };
    if written < 0 || written as usize != bytes.len() {
        fixture_failure(1, if written < 0 { fixture_errno() } else { 0 });
    }
}

fn fixture_command() -> u8 {
    let mut command = 0u8;
    let read = unsafe { libc::read(libc::STDIN_FILENO, (&mut command as *mut u8).cast(), 1) };
    if read != 1 {
        fixture_failure(2, if read < 0 { fixture_errno() } else { 0 });
    }
    command
}

fn failure_stage(role: u8) -> Option<&'static str> {
    match role {
        1 => Some("fixture_write"),
        2 => Some("fixture_read"),
        3 => Some("fixture_identity"),
        4 => Some("fixture_signal_setup"),
        5 => Some("fixture_leader_signal"),
        6 => Some("fixture_alarm_setup"),
        _ => None,
    }
}

// This runs only in the fresh fixture, outside its signal handler. The parent
// accepts a closed role plus native errno; no raw stderr or native token leaks.
fn fixture_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn fixture_failure(role: u8, code: i32) -> ! {
    let mut frame = [0u8; FAILURE.len() + 5];
    frame[..FAILURE.len()].copy_from_slice(FAILURE);
    frame[FAILURE.len()] = role;
    frame[FAILURE.len() + 1..].copy_from_slice(&code.to_ne_bytes());
    unsafe {
        libc::write(libc::STDOUT_FILENO, frame.as_ptr().cast(), frame.len());
        libc::_exit(126);
    }
}

#[test]
#[ignore = "private fresh-exec fixture; invoked only by the actual lifecycle tests"]
fn fixture_process_lifecycle() {
    let tgid = unsafe { libc::getpid() };
    let worker = unsafe { libc::syscall(libc::SYS_gettid) };
    if tgid <= 0 || worker <= 0 || worker == libc::c_long::from(tgid) {
        fixture_failure(3, if worker < 0 { fixture_errno() } else { 0 });
    }
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = exit_only_this_thread as *const () as usize;
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
        || unsafe { libc::sigaction(libc::SIGUSR2, &action, std::ptr::null_mut()) } != 0
    {
        fixture_failure(4, fixture_errno());
    }
    // Kernel timer bounds the fresh fixture even if the parent aborts. There
    // is no watchdog thread that could outlive the final worker observation.
    let mut alarm_action: libc::sigaction = unsafe { std::mem::zeroed() };
    alarm_action.sa_sigaction = libc::SIG_DFL;
    let mut alarm_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigemptyset(&mut alarm_action.sa_mask) } != 0
        || unsafe { libc::sigaction(libc::SIGALRM, &alarm_action, std::ptr::null_mut()) } != 0
        || unsafe { libc::sigemptyset(&mut alarm_mask) } != 0
        || unsafe { libc::sigaddset(&mut alarm_mask, libc::SIGALRM) } != 0
        || unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &alarm_mask, std::ptr::null_mut()) } != 0
    {
        fixture_failure(6, fixture_errno());
    }
    unsafe { libc::alarm(3) };
    fixture_write(READY);
    match fixture_command() {
        b'Q' => unsafe { libc::_exit(0) },
        b'L' => {
            if unsafe { libc::syscall(libc::SYS_tgkill, tgid, tgid, libc::SIGUSR2) } != 0 {
                fixture_failure(5, fixture_errno());
            }
            fixture_write(WORKER_ALIVE);
            if fixture_command() != b'X' {
                unsafe { libc::_exit(126) };
            }
            unsafe {
                libc::syscall(libc::SYS_exit, 0);
                libc::_exit(126);
            }
        }
        _ => unsafe { libc::_exit(126) },
    }
}

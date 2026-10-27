//! Pure control/lexical checks only. Actual filesystem fixtures already live in
//! Coordinator native_import_files_tests and consume this same production kernel;
//! a second directory fixture here would duplicate their ownership/cleanup logic.
use super::*;
use std::cell::{Cell, RefCell};

// This in-memory stream controls each pass independently, including failures
// that occur while a Control::io operation is in progress.
struct ScriptedObservedStream<'a> {
    passes: [&'a [u8]; 2],
    current: Option<usize>,
    offset: usize,
    seeks: usize,
    eof_reads: [usize; 2],
    data_reads: [usize; 2],
    max_buffer_length: usize,
    revalidations: Cell<usize>,
    events: RefCell<Vec<&'static str>>,
    reported_seek: u64,
    fail_read_pass: Option<usize>,
    cancel_on_failed_read: Option<&'a Cell<bool>>,
}

impl<'a> ScriptedObservedStream<'a> {
    fn new(first: &'a [u8], second: &'a [u8]) -> Self {
        Self {
            passes: [first, second],
            current: None,
            offset: 0,
            seeks: 0,
            eof_reads: [0, 0],
            data_reads: [0, 0],
            max_buffer_length: 0,
            revalidations: Cell::new(0),
            events: RefCell::new(Vec::new()),
            reported_seek: 0,
            fail_read_pass: None,
            cancel_on_failed_read: None,
        }
    }
}

impl ObservedStream<Checks> for ScriptedObservedStream<'_> {
    fn seek_start(&mut self) -> io::Result<u64> {
        self.events.borrow_mut().push("seek");
        if self.seeks >= self.passes.len() {
            return Err(io::Error::other("unexpected extra pass"));
        }
        self.current = Some(self.seeks);
        self.seeks += 1;
        self.offset = 0;
        Ok(self.reported_seek)
    }

    fn read_chunk(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let pass = self
            .current
            .ok_or_else(|| io::Error::other("read before seek"))?;
        self.max_buffer_length = self.max_buffer_length.max(buffer.len());
        if self.fail_read_pass == Some(pass) {
            if let Some(cancelled) = self.cancel_on_failed_read {
                cancelled.set(true);
            }
            return Err(io::Error::from_raw_os_error(5));
        }
        let input = self.passes[pass];
        if self.offset == input.len() {
            self.events.borrow_mut().push("eof");
            self.eof_reads[pass] += 1;
            return Ok(0);
        }
        let count = buffer.len().min(input.len() - self.offset);
        self.data_reads[pass] += usize::from(count > 0);
        buffer[..count].copy_from_slice(&input[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }

    fn revalidate(&self, control: &Checks) -> Result<(), Failure> {
        self.events.borrow_mut().push("revalidate");
        self.revalidations.set(self.revalidations.get() + 1);
        control.check()
    }
}

fn failure_contains_cancelled(error: &Failure) -> bool {
    match error {
        Failure::Cancelled => true,
        Failure::Both(primary, post) => {
            failure_contains_cancelled(primary) || failure_contains_cancelled(post)
        }
        _ => false,
    }
}

fn failure_contains_os_error(error: &Failure, code: i32) -> bool {
    match error {
        Failure::Io(error) => error.raw_os_error() == Some(code),
        Failure::Both(primary, post) => {
            failure_contains_os_error(primary, code) || failure_contains_os_error(post, code)
        }
        _ => false,
    }
}

fn failure_has_io_with_cancelled_post(error: &Failure) -> bool {
    match error {
        Failure::Both(primary, post) => {
            (failure_contains_os_error(primary, 5) && failure_contains_cancelled(post))
                || failure_has_io_with_cancelled_post(primary)
                || failure_has_io_with_cancelled_post(post)
        }
        _ => false,
    }
}

#[test]
fn observed_stream_hash_reads_both_passes_and_exact_eof() {
    let bytes = vec![0x5a; 64 * 1024 + 3];
    let mut stream = ScriptedObservedStream::new(&bytes, &bytes);
    let checks = Checks {
        cancelled: Cell::new(false),
    };
    let observed = observe_stream_sha256(&mut stream, bytes.len() as u64, &checks).unwrap();
    let expected: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(observed, expected);
    assert_eq!(stream.seeks, 2);
    assert_eq!(stream.eof_reads, [1, 1]);
    assert!(stream.data_reads.iter().all(|count| *count >= 2));
    assert_eq!(stream.max_buffer_length, 64 * 1024);
    assert!(stream.revalidations.get() >= 4);
    assert_eq!(stream.offset, bytes.len());
    let events = stream.events.borrow();
    let seek_positions: Vec<_> = events
        .iter()
        .enumerate()
        .filter_map(|(i, e)| (*e == "seek").then_some(i))
        .collect();
    let eof_positions: Vec<_> = events
        .iter()
        .enumerate()
        .filter_map(|(i, e)| (*e == "eof").then_some(i))
        .collect();
    assert!(events[..seek_positions[0]].contains(&"revalidate"));
    assert!(
        events[eof_positions[0] + 1..seek_positions[1]]
            .iter()
            .filter(|e| **e == "revalidate")
            .count()
            >= 2
    );
    assert!(events[eof_positions[1] + 1..].contains(&"revalidate"));
    drop(events);

    let mut empty = ScriptedObservedStream::new(b"", b"");
    let observed = observe_stream_sha256(&mut empty, 0, &checks).unwrap();
    let expected = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    assert_eq!(observed, expected);
    assert_eq!(empty.seeks, 2);
    assert_eq!(empty.eof_reads, [1, 1]);
}

#[test]
fn observed_stream_hash_rejects_changed_pass_and_inexact_lengths() {
    let checks = Checks {
        cancelled: Cell::new(false),
    };
    let mut changed = ScriptedObservedStream::new(b"abc", b"abd");
    assert!(matches!(
        observe_stream_sha256(&mut changed, 3, &checks),
        Err(Failure::Changed)
    ));
    assert_eq!(changed.seeks, 2);
    for (first, second, expected) in [
        (&b"ab"[..], &b"ab"[..], 3),
        (&b"abcd"[..], &b"abcd"[..], 3),
        (&b"abc"[..], &b"ab"[..], 3),
        (&b"abc"[..], &b"abcd"[..], 3),
        (&b"x"[..], &b"x"[..], u64::MAX),
    ] {
        let mut stream = ScriptedObservedStream::new(first, second);
        assert!(matches!(
            observe_stream_sha256(&mut stream, expected, &checks),
            Err(Failure::Changed)
        ));
    }

    let mut bad_seek = ScriptedObservedStream::new(b"abc", b"abc");
    bad_seek.reported_seek = 1;
    assert!(observe_stream_sha256(&mut bad_seek, 3, &checks).is_err());
}

#[test]
fn observed_stream_hash_preserves_io_and_cancellation_failures() {
    let checks = Checks {
        cancelled: Cell::new(false),
    };
    let mut first_failure = ScriptedObservedStream::new(b"abc", b"abc");
    first_failure.fail_read_pass = Some(0);
    let error = observe_stream_sha256(&mut first_failure, 3, &checks).unwrap_err();
    assert!(failure_contains_os_error(&error, 5));
    assert_eq!(first_failure.seeks, 1);

    let mut stream = ScriptedObservedStream::new(b"abc", b"abc");
    stream.fail_read_pass = Some(1);
    let error = observe_stream_sha256(&mut stream, 3, &checks).unwrap_err();
    assert!(failure_contains_os_error(&error, 5));
    assert_eq!(stream.seeks, 2);

    let checks = Checks {
        cancelled: Cell::new(false),
    };
    let mut stream = ScriptedObservedStream::new(b"abc", b"abc");
    stream.fail_read_pass = Some(1);
    stream.cancel_on_failed_read = Some(&checks.cancelled);
    let error = observe_stream_sha256(&mut stream, 3, &checks).unwrap_err();
    assert!(matches!(&error, Failure::Both(_, _)));
    assert!(failure_contains_os_error(&error, 5));
    assert!(failure_contains_cancelled(&error));
    assert!(failure_has_io_with_cancelled_post(&error));
    assert_eq!(stream.seeks, 2);

    let checks = Checks {
        cancelled: Cell::new(true),
    };
    let mut stream = ScriptedObservedStream::new(b"abc", b"abc");
    let error = observe_stream_sha256(&mut stream, 3, &checks).unwrap_err();
    assert!(failure_contains_cancelled(&error));
    assert_eq!(stream.seeks, 0);
}

#[derive(Debug)]
enum Failure {
    Cancelled,
    Unsafe,
    Changed,
    Io(io::Error),
    Both(Box<Failure>, Box<Failure>),
}
struct Checks {
    cancelled: Cell<bool>,
}
impl Control for Checks {
    type Error = Failure;
    fn check(&self) -> Result<(), Failure> {
        if self.cancelled.get() {
            Err(Failure::Cancelled)
        } else {
            Ok(())
        }
    }
    fn io_error(&self, error: io::Error) -> Failure {
        Failure::Io(error)
    }
    fn unsafe_selection(&self) -> Failure {
        Failure::Unsafe
    }
    fn changed(&self) -> Failure {
        Failure::Changed
    }
    fn with_post_failure(&self, primary: Failure, post: Failure) -> Failure {
        Failure::Both(Box::new(primary), Box::new(post))
    }
}
#[test]
fn native_failure_and_post_checkpoint_keep_both_typed_causes() {
    let checks = Checks {
        cancelled: Cell::new(false),
    };
    // Synthetic I/O result: this is causal plumbing, not an OS operation proof.
    let error = checks
        .io::<()>(|| {
            checks.cancelled.set(true);
            Err(io::Error::from_raw_os_error(5))
        })
        .err()
        .unwrap();
    let Failure::Both(primary, post) = error else {
        panic!("both failures required")
    };
    assert!(matches!(*post, Failure::Cancelled));
    let Failure::Io(native) = *primary else {
        panic!("native primary required")
    };
    assert_eq!(native.raw_os_error(), Some(5));
}
#[test]
fn original_cancel_prevents_even_starting_the_operation() {
    let checks = Checks {
        cancelled: Cell::new(true),
    };
    assert!(matches!(
        checks.io::<()>(|| panic!("cancelled operation entered")),
        Err(Failure::Cancelled)
    ));
}

// Synthetic closers exercise mandatory release and causal accounting without
// duplicating the consumers' owned filesystem fixtures or issuing native I/O.
#[test]
fn retained_release_attempts_every_last_pin_after_cancel_and_native_failure() {
    let checks = Checks {
        cancelled: Cell::new(true),
    };
    let mut attempted = Vec::new();
    let report = release_retained_pins_with((0..3).map(Arc::new).collect(), &checks, |pin| {
        attempted.push(pin);
        if pin == 1 {
            Err(io::Error::from_raw_os_error(5))
        } else {
            Ok(())
        }
    });
    assert_eq!(attempted, [2, 1, 0]);
    assert_eq!(report.pins, 3);
    assert_eq!(report.closed, 2);
    assert_eq!(report.shared, 0);
    assert_eq!(report.native_close_uncertain, 1);
    assert!(!report.all_pins_closed());
    assert_eq!(report.failures.len(), 9);
    assert_eq!(report.failures[0].pin, None);
    assert_eq!(report.failures[0].stage, RetainedCloseStage::BeforeClose);
    assert!(matches!(report.failures[0].error, Failure::Cancelled));
    let native = report
        .failures
        .iter()
        .find(|failure| failure.stage == RetainedCloseStage::NativeClose)
        .unwrap();
    assert_eq!(native.pin, Some(1));
    let Failure::Io(error) = &native.error else {
        panic!("original native error required")
    };
    assert_eq!(error.raw_os_error(), Some(5));
    assert_eq!(report.failures.last().unwrap().pin, None);
    assert_eq!(
        report.failures.last().unwrap().stage,
        RetainedCloseStage::AfterClose
    );
}

#[test]
fn retained_release_distinguishes_unobserved_shared_from_successful_native_close() {
    let checks = Checks {
        cancelled: Cell::new(false),
    };
    let other_owner = Arc::new(7);
    let mut attempted = Vec::new();
    let report = release_retained_pins_with(
        vec![Arc::new(3), Arc::clone(&other_owner)],
        &checks,
        |pin| {
            attempted.push(pin);
            Ok(())
        },
    );
    assert_eq!(attempted, [3]);
    assert_eq!(report.pins, 2);
    assert_eq!(report.closed, 1);
    assert_eq!(report.shared, 1);
    assert_eq!(report.native_close_uncertain, 0);
    assert!(report.failures.is_empty());
    assert!(!report.all_pins_closed());
    assert_eq!(*other_owner, 7);

    let report = release_retained_pins_with(vec![other_owner], &checks, |_| Ok(()));
    assert_eq!(report.closed, 1);
    assert!(report.all_pins_closed());
}

#[test]
fn retained_release_keeps_all_bounded_causes_and_closes_after_new_cancellation() {
    let checks = Checks {
        cancelled: Cell::new(false),
    };
    let mut attempted = 0;
    let report = release_retained_pins_with((0..66).map(Arc::new).collect(), &checks, |_| {
        attempted += 1;
        checks.cancelled.set(true);
        Err(io::Error::from_raw_os_error(6))
    });
    assert_eq!(attempted, 66);
    assert_eq!(report.closed, 0);
    assert_eq!(report.native_close_uncertain, 66);
    // Initial and first per-pin checks succeeded; all later causes are kept.
    assert_eq!(report.failures.len(), 198);
    assert_eq!(report.failures[0].pin, Some(65));
    assert_eq!(report.failures[0].stage, RetainedCloseStage::NativeClose);
    assert!(matches!(report.failures[0].error, Failure::Io(_)));
    assert_eq!(
        report
            .failures
            .iter()
            .filter(|failure| failure.stage == RetainedCloseStage::NativeClose)
            .count(),
        66
    );
}

#[test]
fn secret_and_parent_spellings_are_rejected_before_control_or_filesystem_access() {
    struct Never;
    impl Control for Never {
        type Error = Failure;
        fn check(&self) -> Result<(), Failure> {
            panic!("lexical rejection must precede I/O/control")
        }
        fn io_error(&self, error: io::Error) -> Failure {
            Failure::Io(error)
        }
        fn unsafe_selection(&self) -> Failure {
            Failure::Unsafe
        }
        fn changed(&self) -> Failure {
            Failure::Changed
        }
        fn with_post_failure(&self, a: Failure, b: Failure) -> Failure {
            Failure::Both(Box::new(a), Box::new(b))
        }
    }
    for tail in ["credentials", "api-key", ".env", "parent/../game"] {
        #[cfg(windows)]
        let path = Path::new("C:/unopened").join(tail);
        #[cfg(not(windows))]
        let path = Path::new("/unopened").join(tail);
        assert!(matches!(
            HeldDirectory::open_root(&path, &Never),
            Err(Failure::Unsafe)
        ));
        assert!(matches!(
            HeldFile::open_selected(&path, &Never),
            Err(Failure::Unsafe)
        ));
    }
}

#[test]
fn relative_file_preflight_bounds_depth_and_total_encoded_length() {
    use std::ffi::OsStr;

    assert!(!ordinary_relative_components(&[]));
    let max_depth = vec![OsStr::new("leaf"); 64];
    assert!(ordinary_relative_components(&max_depth));
    let too_deep = vec![OsStr::new("leaf"); 65];
    assert!(!ordinary_relative_components(&too_deep));

    // Seventeen 240-byte components plus sixteen separators are exactly 4096
    // UTF-8 bytes; one additional component byte exceeds the relative budget.
    let mut names = vec!["a".repeat(240); 17];
    let components: Vec<&OsStr> = names.iter().map(OsStr::new).collect();
    assert!(ordinary_relative_components(&components));
    names[0].push('a');
    let components: Vec<&OsStr> = names.iter().map(OsStr::new).collect();
    assert!(!ordinary_relative_components(&components));
}

#[test]
fn relative_file_preflight_rejects_forbidden_components_at_any_depth() {
    use std::ffi::OsStr;

    for forbidden in [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        "a:b",
        ".env",
        "credentials",
        "id_ed25519",
    ] {
        assert!(
            !ordinary_relative_components(&[
                OsStr::new("allowed"),
                OsStr::new(forbidden),
                OsStr::new("leaf")
            ]),
            "relative component should be rejected"
        );
    }
    assert!(ordinary_relative_components(&[
        OsStr::new("release"),
        OsStr::new("windows-x64"),
        OsStr::new("mmmm.zip"),
    ]));

    #[cfg(windows)]
    for reserved in ["CON", "lpt1.txt", "trailing.", "trailing ", "name~1"] {
        assert!(!ordinary_relative_components(&[OsStr::new(reserved)]));
    }
    #[cfg(unix)]
    {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        let non_utf8 = OsString::from_vec(vec![0xff]);
        assert!(!ordinary_relative_components(&[non_utf8.as_os_str()]));
    }
}

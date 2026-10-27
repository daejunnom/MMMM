//! Pure control/lexical checks only. Actual filesystem fixtures already live in
//! Coordinator native_import_files_tests and consume this same production kernel;
//! a second directory fixture here would duplicate their ownership/cleanup logic.
use super::*;
use std::cell::Cell;

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
    let components: Vec<&OsStr> = names.iter().map(|name| OsStr::new(name)).collect();
    assert!(ordinary_relative_components(&components));
    names[0].push('a');
    let components: Vec<&OsStr> = names.iter().map(|name| OsStr::new(name)).collect();
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

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

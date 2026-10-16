// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        // Resolve only this test's OS temp root. Selected production inputs
        // never canonicalize through links or retry a rejected namespace.
        let physical = std::env::temp_dir().canonicalize().unwrap();
        let root = physical.join(format!(
            "mmmm-startup-unix-fixture-{}-{}",
            std::process::id(),
            FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self { root }
    }
    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
    fn close(self) {
        let actual = fs::symlink_metadata(&self.root).unwrap();
        assert!(actual.is_dir() && !actual.file_type().is_symlink());
        // Remove only the freshly created, explicitly owned test directory.
        fs::remove_dir_all(self.root).unwrap();
    }
}
fn pin(context: &mut PinContext, path: &Path) -> Result<InputPin, DefinitionStartupError> {
    InputPin::acquire_checked(
        context,
        DefinitionSourceRole::ObserverJar,
        path,
        MAX_INPUT_BYTES,
        &mut || Ok(()),
    )
}
fn rejected(result: Result<InputPin, DefinitionStartupError>) -> DefinitionStartupError {
    match result {
        Ok(_) => panic!("changed/unsupported source must be rejected"),
        Err(error) => error,
    }
}

#[test]
fn anchored_pin_hashes_held_bytes_and_reuses_shared_directory_descriptors() {
    let fixture = Fixture::new();
    let first = fixture.file("first.jar", b"observed first source");
    let second = fixture.file("second.jar", b"observed second source");
    let mut context = PinContext::default();
    let mut first_pin = pin(&mut context, &first).unwrap();
    let directories = context.directories.len();
    let second_pin = pin(&mut context, &second).unwrap();
    assert_eq!(context.directories.len(), directories);
    assert_eq!(context.files, 2);
    assert_eq!(
        first_pin.report.sha256,
        format!("{:x}", Sha256::digest(b"observed first source"))
    );
    assert_eq!(
        second_pin.report.sha256,
        format!("{:x}", Sha256::digest(b"observed second source"))
    );
    first_pin.recheck_checked(&mut || Ok(())).unwrap();
    drop((first_pin, second_pin, context));
    fixture.close();
}

#[test]
fn source_write_and_same_name_replacement_are_detected_without_rebinding_held_fd() {
    for replace in [false, true] {
        let fixture = Fixture::new();
        let path = fixture.file("owned.jar", b"original owned bytes");
        let mut context = PinContext::default();
        let mut source = pin(&mut context, &path).unwrap();
        if replace {
            fs::rename(&path, fixture.root.join("retained-original.jar")).unwrap();
            fs::write(&path, b"replacement same name").unwrap();
        } else {
            fs::write(&path, b"changed owned bytes!").unwrap();
        }
        assert_eq!(
            source.recheck_checked(&mut || Ok(())).unwrap_err().kind(),
            "SOURCE_CHANGED"
        );
        drop((source, context));
        fixture.close();
    }
}

#[test]
fn leaf_and_intermediate_symlinks_are_rejected_before_source_hashing() {
    let fixture = Fixture::new();
    let actual = fixture.file("actual.jar", b"not a source through an alias");
    let leaf = fixture.root.join("alias.jar");
    symlink(&actual, &leaf).unwrap();
    let error = rejected(pin(&mut PinContext::default(), &leaf));
    assert_eq!(error.kind(), "INPUT_FILE");
    let real_directory = fixture.root.join("real");
    fs::create_dir(&real_directory).unwrap();
    fs::write(real_directory.join("owned.jar"), b"nested input").unwrap();
    symlink(&real_directory, fixture.root.join("linked")).unwrap();
    assert_eq!(
        rejected(pin(
            &mut PinContext::default(),
            &fixture.root.join("linked/owned.jar")
        ))
        .kind(),
        "OPEN_INPUT"
    );
    fixture.close();
}

#[test]
fn hardlinks_and_fifo_leaves_do_not_become_source_pins() {
    let fixture = Fixture::new();
    let actual = fixture.file("actual.jar", b"hard linked input");
    fs::hard_link(&actual, fixture.root.join("alias.jar")).unwrap();
    assert_eq!(
        rejected(pin(&mut PinContext::default(), &actual)).kind(),
        "INPUT_FILE"
    );
    let fifo = fixture.root.join("fifo.jar");
    let encoded = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: one new owned test FIFO with a NUL-terminated path and fixed mode.
    assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);
    assert_eq!(
        rejected(pin(&mut PinContext::default(), &fifo)).kind(),
        "INPUT_FILE"
    );
    fixture.close();
}

#[test]
fn namespace_directory_replacement_is_detected_while_original_source_is_still_held() {
    let fixture = Fixture::new();
    let directory = fixture.root.join("input");
    fs::create_dir(&directory).unwrap();
    let path = directory.join("owned.jar");
    fs::write(&path, b"original inode").unwrap();
    let mut context = PinContext::default();
    let mut source = pin(&mut context, &path).unwrap();
    fs::rename(&directory, fixture.root.join("retained-directory")).unwrap();
    fs::create_dir(&directory).unwrap();
    fs::write(&path, b"new directory").unwrap();
    assert_eq!(
        source.recheck_checked(&mut || Ok(())).unwrap_err().kind(),
        "SOURCE_CHANGED"
    );
    drop((source, context));
    fixture.close();
}

#[test]
fn directory_entry_churn_is_not_claimed_to_be_a_file_content_version() {
    let fixture = Fixture::new();
    let path = fixture.file("owned.jar", b"unchanged observed bytes");
    let mut context = PinContext::default();
    let mut source = pin(&mut context, &path).unwrap();
    fixture.file("separate-entry", b"entry churn");
    source.recheck_checked(&mut || Ok(())).unwrap();
    drop((source, context));
    fixture.close();
}

#[test]
fn executable_role_requires_a_posix_execute_mode_bit() {
    let fixture = Fixture::new();
    let path = fixture.file("java", b"authored fixture executable bytes");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let result = InputPin::acquire_checked(
        &mut PinContext::default(),
        DefinitionSourceRole::JavaExecutable,
        &path,
        MAX_INPUT_BYTES,
        &mut || Ok(()),
    );
    assert_eq!(rejected(result).kind(), "INPUT_FILE");
    fixture.close();
}

#[test]
fn handle_budget_bounds_owned_pins_below_the_observed_soft_limit() {
    assert_eq!(handle_budget(64).unwrap_err().kind(), "INPUT_HANDLE_BUDGET");
    assert_eq!(handle_budget(65).unwrap(), 1);
    assert_eq!(handle_budget(u64::MAX).unwrap(), MAX_HELD_HANDLES);
    let fixture = Fixture::new();
    let path = fixture.file("owned.jar", b"bounded descriptor fixture");
    let mut context = PinContext {
        max_handles: Some(1),
        ..PinContext::default()
    };
    assert_eq!(
        rejected(pin(&mut context, &path)).kind(),
        "INPUT_HANDLE_BUDGET"
    );
    fixture.close();
}

#[test]
fn revoked_progress_discards_partial_hash_and_never_returns_a_prefix() {
    let fixture = Fixture::new();
    let path = fixture.file("owned.jar", &vec![b'x'; 130 * 1024]);
    let mut file = File::open(&path).unwrap();
    let mut checkpoints = 0;
    let error = hash(&mut file, MAX_INPUT_BYTES, &mut || {
        checkpoints += 1;
        if checkpoints == 5 {
            Err(DefinitionStartupError::new("CANCELLED"))
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert_eq!(error.kind(), "CANCELLED");
    drop(file);
    fixture.close();
}

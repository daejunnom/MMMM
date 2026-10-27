//! These fixtures are required because lexical tests cannot establish actual
//! file-handle identity, no-follow behavior or the live native owner boundary.
//! Only newly created, marked files outside the checkout are read or removed.
//! Known secret names appear only in pure lexical tests; none are created.
//! Shared-kernel CreateNew cases reuse this fixture rather than creating another
//! ownership/cleanup implementation in the neutral native crate.

use super::*;
use crate::{
    authority::LocalAuthority, host::HostBridge, native_project::create_native_project,
    service::ServiceError, workspace_bootstrap::prepare_workspace,
};
use mmmm_contracts::TargetProfileId;
use mmmm_runtime::storage::{DurableStore, StoreConfig};
use std::{
    fs::{self, OpenOptions},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const MARKER: &[u8] = b"mmmm-selected-source-file-test-v1\n";
struct TestRoot {
    path: PathBuf,
    physical: PathBuf,
}
impl TestRoot {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let parent = fs::canonicalize(parent).unwrap();
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).unwrap();
        let physical = parent.join(format!(
            "mmmm-selected-source-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(nonce)
        ));
        let checkout =
            fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        assert!(physical.is_absolute() && !physical.starts_with(checkout));
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let mut builder = builder;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&physical).unwrap();
        let physical = fs::canonicalize(physical).unwrap();
        assert_eq!(physical.parent(), Some(parent.as_path()));
        let path = selection_spelling(&physical);
        assert_eq!(fs::canonicalize(&path).unwrap(), physical);
        fs::write(path.join("test-owner.txt"), MARKER).unwrap();
        builder.create(path.join("selected")).unwrap();
        Self { path, physical }
    }
}
fn selection_spelling(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        use std::path::Prefix;
        let mut parts = path.components();
        if let Some(Component::Prefix(prefix)) = parts.next()
            && let Prefix::VerbatimDisk(drive) = prefix.kind()
        {
            let mut normal = PathBuf::from(format!("{}:\\", char::from(drive)));
            for part in parts {
                if let Component::Normal(name) = part {
                    normal.push(name);
                }
            }
            return normal;
        }
    }
    path.to_owned()
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        let mut count = 0;
        if fs::canonicalize(&self.path).ok().as_ref() == Some(&self.physical)
            && fs::read(self.path.join("test-owner.txt")).ok().as_deref() == Some(MARKER)
            && plain_tree(&self.path, &self.path, 0, &mut count)
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
fn plain_tree(path: &Path, root: &Path, depth: usize, count: &mut usize) -> bool {
    if !path.starts_with(root) || depth > 16 || *count >= 4096 {
        return false;
    }
    *count += 1;
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    if metadata.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return false;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            if !plain_tree(&entry.path(), root, depth + 1, count) {
                return false;
            }
        }
        true
    } else {
        metadata.is_file()
    }
}
struct Fixture {
    _store: DurableStore,
    owner: NativeOwnerWitness,
    budget: RequestBudget,
    cancelled: Arc<AtomicBool>,
    root: TestRoot,
}
impl Fixture {
    fn new() -> Self {
        let root = TestRoot::new();
        let mut store = DurableStore::open(StoreConfig::new(root.path.join("data"))).unwrap();
        let created = create_native_project(
            &mut store,
            "Selected source acquisition fixture",
            &TargetProfileId::new("unverified-native-target").unwrap(),
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
        let authority = LocalAuthority::new(HostBridge::default());
        let workspace = prepare_workspace(
            &store,
            &authority,
            &created.project_id,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let budget = RequestBudget::new(Duration::from_secs(30), cancelled.clone()).unwrap();
        Self {
            _store: store,
            owner: workspace.witness,
            budget,
            cancelled,
            root,
        }
    }
    fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.root.path.join("selected").join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        use std::io::Write;
        file.write_all(contents).unwrap();
        path
    }
    fn read(
        &self,
        path: &Path,
        role: InputRole,
        totals: &mut ImportReadBudget,
    ) -> Result<Vec<u8>, ImportFileError> {
        read_selected(path, role, &self.owner, &self.budget, totals)
    }
    fn remove_owned_leaf(&self, path: &Path) {
        assert!(path.is_absolute() && path.starts_with(&self.root.path));
        assert_eq!(
            fs::canonicalize(&self.root.path).unwrap(),
            self.root.physical
        );
        assert_eq!(
            fs::read(self.root.path.join("test-owner.txt")).unwrap(),
            MARKER
        );
        let physical_parent = fs::canonicalize(path.parent().unwrap()).unwrap();
        assert!(physical_parent.starts_with(&self.root.physical));
        // lstat inspects this exact owned entry, never a symlink target. Only
        // the known created leaf is unlinked; no recursive removal occurs here.
        assert!(!fs::symlink_metadata(path).unwrap().is_dir());
        fs::remove_file(path).unwrap();
    }
}
fn lexical_path(suffix: &str) -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(format!("C:/selected/{suffix}"))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(format!("/selected/{suffix}"))
    }
}

#[test]
fn shared_create_new_kernel_verifies_original_bytes_and_never_adopts_existing_children() {
    use mmmm_owned_files::HeldDirectory;
    use std::ffi::OsStr;
    let fixture = Fixture::new();
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let root = HeldDirectory::open_root(&fixture.root.path.join("selected"), &checks).unwrap();
    root.require_child_absent(OsStr::new("calibration-pack"), &checks)
        .unwrap();
    let pack = root
        .create_directory_new(OsStr::new("calibration-pack"), &checks)
        .unwrap();
    let original: Vec<u8> = (0..CHUNK + 13).map(|index| (index % 251) as u8).collect();
    let mut file = pack
        .create_file_new(OsStr::new("pack.mcmeta"), original.len() as u64, &checks)
        .unwrap();
    file.write_all(&original, &checks).unwrap();
    let facts = file.verify_original(&original, &checks).unwrap();
    assert_eq!(facts.length, original.len() as u64);
    let expected_digest: [u8; 32] = Sha256::digest(&original).into();
    assert_eq!(facts.sha256, expected_digest);
    file.close(&checks).unwrap();
    assert_eq!(
        pack.require_child_absent(OsStr::new("pack.mcmeta"), &checks)
            .err()
            .unwrap()
            .kind,
        ErrorKind::UnsafeSelection
    );
    let error = pack
        .create_file_new(OsStr::new("pack.mcmeta"), 0, &checks)
        .err()
        .unwrap();
    assert_eq!(error.kind, ErrorKind::Io);
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        root.create_directory_new(OsStr::new("calibration-pack"), &checks)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Io
    );
    pack.close(&checks).unwrap();
    root.close(&checks).unwrap();
    assert_eq!(
        fs::read(
            fixture
                .root
                .path
                .join("selected/calibration-pack/pack.mcmeta")
        )
        .unwrap(),
        original
    );
}
#[test]
fn shared_create_new_mismatch_and_original_cancellation_preserve_partial_files() {
    use mmmm_owned_files::HeldDirectory;
    use std::ffi::OsStr;
    let fixture = Fixture::new();
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let root = HeldDirectory::open_root(&fixture.root.path.join("selected"), &checks).unwrap();
    let pack = root
        .create_directory_new(OsStr::new("partial-pack"), &checks)
        .unwrap();
    let mut mismatch = pack
        .create_file_new(OsStr::new("mismatch.bin"), 3, &checks)
        .unwrap();
    mismatch.write_all(b"abc", &checks).unwrap();
    assert_eq!(
        mismatch
            .verify_original(b"abd", &checks)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Changed
    );
    // A failed original-byte proof cannot become a successful later attempt on
    // the same created-file object. Only close/release remains available.
    assert_eq!(
        mismatch
            .verify_original(b"abc", &checks)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Changed
    );
    mismatch.close(&checks).unwrap();
    let mut partial = pack
        .create_file_new(OsStr::new("partial.bin"), 6, &checks)
        .unwrap();
    partial.write_all(b"abc", &checks).unwrap();
    fixture.cancelled.store(true, Ordering::Release);
    assert_eq!(
        partial.write_all(b"def", &checks).err().unwrap().kind,
        ErrorKind::Request
    );
    assert_eq!(
        partial.close(&checks).err().unwrap().kind,
        ErrorKind::Request
    );
    drop(pack);
    drop(root);
    assert_eq!(
        fs::read(fixture.root.path.join("selected/partial-pack/mismatch.bin")).unwrap(),
        b"abc"
    );
    assert_eq!(
        fs::read(fixture.root.path.join("selected/partial-pack/partial.bin")).unwrap(),
        b"abc"
    );
}
#[test]
fn shared_child_secret_guard_precedes_original_request_and_metadata_checks() {
    use mmmm_owned_files::HeldDirectory;
    use std::ffi::OsStr;
    let fixture = Fixture::new();
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let root = HeldDirectory::open_root(&fixture.root.path.join("selected"), &checks).unwrap();
    fixture.cancelled.store(true, Ordering::Release);
    // These selectors are never created or inspected. The expired checkpoint
    // distinguishes lexical-first rejection from reaching any root/stat query.
    for child in ["credentials", "api-key", ".env"] {
        assert_eq!(
            root.require_descendant_absent(&[OsStr::new("unopened"), OsStr::new(child)], &checks)
                .err()
                .unwrap()
                .kind,
            ErrorKind::UnsafeSelection
        );
        assert_eq!(
            root.require_child_absent(OsStr::new(child), &checks)
                .err()
                .unwrap()
                .kind,
            ErrorKind::UnsafeSelection
        );
        assert_eq!(
            root.create_directory_new(OsStr::new(child), &checks)
                .err()
                .unwrap()
                .kind,
            ErrorKind::UnsafeSelection
        );
        assert_eq!(
            root.create_file_new(OsStr::new(child), 0, &checks)
                .err()
                .unwrap()
                .kind,
            ErrorKind::UnsafeSelection
        );
    }
}

#[test]
fn shared_nested_absence_is_metadata_only_and_rejects_existing_or_non_directory_ancestors() {
    use mmmm_owned_files::HeldDirectory;
    use std::ffi::OsStr;
    let fixture = Fixture::new();
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let existing = fixture.file("occupied.dat", b"preserved native fixture bytes");
    let root = HeldDirectory::open_root(&fixture.root.path.join("selected"), &checks).unwrap();
    let nested = root
        .create_directory_new(OsStr::new("native-data"), &checks)
        .unwrap();
    nested.close(&checks).unwrap();
    root.require_descendant_absent(
        &[OsStr::new("missing-parent"), OsStr::new("future.dat")],
        &checks,
    )
    .unwrap();
    root.require_descendant_absent(
        &[OsStr::new("native-data"), OsStr::new("future.dat")],
        &checks,
    )
    .unwrap();
    assert_eq!(
        root.require_descendant_absent(&[OsStr::new("occupied.dat")], &checks)
            .err()
            .unwrap()
            .kind,
        ErrorKind::UnsafeSelection
    );
    assert_eq!(
        root.require_descendant_absent(
            &[OsStr::new("occupied.dat"), OsStr::new("future.dat")],
            &checks
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::UnsafeSelection
    );
    assert_eq!(
        root.require_descendant_absent(&[], &checks)
            .err()
            .unwrap()
            .kind,
        ErrorKind::UnsafeSelection
    );
    let too_many = vec![OsStr::new("unopened"); 65];
    assert_eq!(
        root.require_descendant_absent(&too_many, &checks)
            .err()
            .unwrap()
            .kind,
        ErrorKind::UnsafeSelection
    );
    root.close(&checks).unwrap();
    assert_eq!(
        fs::read(existing).unwrap(),
        b"preserved native fixture bytes"
    );
}

// The existing selected-file fixtures start from an absolute pathname. They
// cannot establish that this new operation resolves a relative child through
// the caller's already-held root and retains that root's ancestry.
#[test]
fn shared_relative_existing_file_is_bound_to_the_held_root() {
    use mmmm_owned_files::{Control, HeldDirectory};
    use std::{ffi::OsStr, io::Read};

    let fixture = Fixture::new();
    let directory = fixture.root.path.join("selected/relative-child");
    fs::create_dir(&directory).unwrap();
    let path = directory.join("entry.dat");
    fs::write(&path, b"actual selected bytes").unwrap();
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let root = HeldDirectory::open_root(&fixture.root.path.join("selected"), &checks).unwrap();
    let mut file = root
        .open_existing_descendant(
            &[OsStr::new("relative-child"), OsStr::new("entry.dat")],
            &checks,
        )
        .unwrap();
    assert_eq!(file.length(), b"actual selected bytes".len() as u64);
    let mut bytes = [0u8; 21];
    checks.io(|| file.file().read_exact(&mut bytes)).unwrap();
    assert_eq!(&bytes, b"actual selected bytes");
    file.revalidate(&checks).unwrap();
    file.close(&checks).unwrap();
    root.revalidate(&checks).unwrap();

    // No component is opened until every component passes the shared lexical
    // preflight. These names are selectors only; no protected file is created.
    fixture.cancelled.store(true, Ordering::Release);
    assert_eq!(
        root.open_existing_descendant(&[OsStr::new("unopened"), OsStr::new(".env")], &checks)
            .err()
            .unwrap()
            .kind,
        ErrorKind::UnsafeSelection
    );
    fixture.cancelled.store(false, Ordering::Release);
    let missing_directory = root
        .open_existing_descendant(&[OsStr::new("missing"), OsStr::new("entry.dat")], &checks)
        .err()
        .unwrap();
    assert_eq!(missing_directory.kind, ErrorKind::Io);
    let synthetic = missing_directory
        .source()
        .unwrap()
        .downcast_ref::<io::Error>()
        .unwrap();
    assert_eq!(synthetic.kind(), io::ErrorKind::NotFound);
    assert_eq!(synthetic.raw_os_error(), None);
    assert!(missing_directory.checkpoint_failure().is_none());

    let missing_leaf = root
        .open_existing_descendant(
            &[OsStr::new("relative-child"), OsStr::new("missing.dat")],
            &checks,
        )
        .err()
        .unwrap();
    assert_eq!(missing_leaf.kind, ErrorKind::Io);
    let native = missing_leaf
        .source()
        .unwrap()
        .downcast_ref::<io::Error>()
        .unwrap();
    assert_eq!(native.kind(), io::ErrorKind::NotFound);
    #[cfg(unix)]
    assert_eq!(native.raw_os_error(), Some(libc::ENOENT));
    #[cfg(windows)]
    assert_eq!(native.raw_os_error(), Some(2)); // ERROR_FILE_NOT_FOUND
    assert!(missing_leaf.checkpoint_failure().is_none());
    root.close(&checks).unwrap();
    assert_eq!(fs::read(path).unwrap(), b"actual selected bytes");
}

#[test]
fn shared_relative_existing_file_rejects_hardlinks_before_read() {
    use mmmm_owned_files::HeldDirectory;
    use std::ffi::OsStr;

    let fixture = Fixture::new();
    let path = fixture.file("relative-linked.dat", b"unchanged link target");
    let second = fixture.root.path.join("selected/relative-other.dat");
    fs::hard_link(&path, &second).unwrap();
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let root = HeldDirectory::open_root(&fixture.root.path.join("selected"), &checks).unwrap();
    assert!(
        root.open_existing_descendant(&[OsStr::new("relative-linked.dat")], &checks)
            .is_err()
    );
    root.close(&checks).unwrap();
    fixture.remove_owned_leaf(&second);
    assert_eq!(fs::read(path).unwrap(), b"unchanged link target");
}

#[test]
fn shared_relative_file_retains_ancestry_after_root_owner_is_released() {
    use mmmm_owned_files::{Control, HeldDirectory};
    use std::{ffi::OsStr, io::Read};

    let fixture = Fixture::new();
    let directory = fixture.root.path.join("selected/retained-parent");
    fs::create_dir(&directory).unwrap();
    let path = directory.join("entry.dat");
    fs::write(&path, b"retained ancestry").unwrap();
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let root = HeldDirectory::open_root(&fixture.root.path.join("selected"), &checks).unwrap();
    let mut file = root
        .open_existing_descendant(
            &[OsStr::new("retained-parent"), OsStr::new("entry.dat")],
            &checks,
        )
        .unwrap();
    // Closing this owner releases its references; shared ancestry pins remain
    // held by the selected file and are not claimed as individually closed.
    root.close(&checks).unwrap();
    file.revalidate(&checks).unwrap();
    let mut bytes = [0u8; 17];
    checks.io(|| file.file().read_exact(&mut bytes)).unwrap();
    assert_eq!(&bytes, b"retained ancestry");
    file.revalidate(&checks).unwrap();
    file.close(&checks).unwrap();
    assert_eq!(fs::read(path).unwrap(), b"retained ancestry");
}

#[test]
fn shared_relative_selection_preserves_original_cancellation_at_checkpoints() {
    use mmmm_owned_files::{Control, HeldDirectory};
    use std::{cell::Cell, ffi::OsStr};

    struct Counted<'a, C> {
        inner: &'a C,
        cancelled: &'a AtomicBool,
        calls: Cell<usize>,
        cancel_at: Option<usize>,
        missing_at: Cell<Option<usize>>,
    }
    impl<C: Control> Control for Counted<'_, C> {
        type Error = C::Error;
        fn check(&self) -> Result<(), Self::Error> {
            let next = self.calls.get() + 1;
            self.calls.set(next);
            if self.cancel_at == Some(next) {
                self.cancelled.store(true, Ordering::Release);
            }
            self.inner.check()
        }
        fn io_error(&self, error: io::Error) -> Self::Error {
            if error.kind() == io::ErrorKind::NotFound && self.missing_at.get().is_none() {
                self.missing_at.set(Some(self.calls.get()));
            }
            self.inner.io_error(error)
        }
        fn unsafe_selection(&self) -> Self::Error {
            self.inner.unsafe_selection()
        }
        fn changed(&self) -> Self::Error {
            self.inner.changed()
        }
        fn with_post_failure(&self, a: Self::Error, b: Self::Error) -> Self::Error {
            self.inner.with_post_failure(a, b)
        }
    }

    let fixture = Fixture::new();
    let first = fixture.root.path.join("selected/relative-first");
    let second = first.join("relative-second");
    let third = second.join("relative-third");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    fs::create_dir(&third).unwrap();
    fs::write(third.join("entry.dat"), b"bounded test bytes").unwrap();
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let root = HeldDirectory::open_root(&fixture.root.path.join("selected"), &checks).unwrap();
    let probe = Counted {
        inner: &checks,
        cancelled: &fixture.cancelled,
        calls: Cell::new(0),
        cancel_at: None,
        missing_at: Cell::new(None),
    };
    // The first two existing directories are traversed before the third
    // directory is found missing. Its synthetic NotFound records a checkpoint
    // boundary without touching any protected entry or file contents.
    assert!(
        root.open_existing_descendant(
            &[
                OsStr::new("relative-first"),
                OsStr::new("relative-second"),
                OsStr::new("missing-third"),
                OsStr::new("entry.dat")
            ],
            &probe,
        )
        .is_err()
    );
    let middle = probe
        .missing_at
        .get()
        .expect("missing intermediate directory reached");
    let baseline = Counted {
        inner: &checks,
        cancelled: &fixture.cancelled,
        calls: Cell::new(0),
        cancel_at: None,
        missing_at: Cell::new(None),
    };
    let path = [
        OsStr::new("relative-first"),
        OsStr::new("relative-second"),
        OsStr::new("relative-third"),
        OsStr::new("entry.dat"),
    ];
    let file = root.open_existing_descendant(&path, &baseline).unwrap();
    let total = baseline.calls.get();
    assert!(
        middle > 1 && middle < total,
        "intermediate traversal must precede the final checkpoint"
    );
    file.close(&checks).unwrap();
    for cancel_at in [1, middle, total] {
        fixture.cancelled.store(false, Ordering::Release);
        let controlled = Counted {
            inner: &checks,
            cancelled: &fixture.cancelled,
            calls: Cell::new(0),
            cancel_at: Some(cancel_at),
            missing_at: Cell::new(None),
        };
        let error = root
            .open_existing_descendant(&path, &controlled)
            .err()
            .unwrap();
        assert_eq!(error.kind, ErrorKind::Request);
        assert!(fixture.cancelled.load(Ordering::Acquire));
    }
    fixture.cancelled.store(false, Ordering::Release);
    root.revalidate(&checks).unwrap();
    root.close(&checks).unwrap();
}

// Existing source-read fixtures compare supplied original bytes. These cases
// exercise the separate streaming digest observation over the held file itself;
// the returned digest is not a release proof or an immutable snapshot.
#[test]
fn shared_held_file_digest_observes_multichunk_and_empty_files_with_bounds() {
    use mmmm_owned_files::{CHUNK_BYTES, Control, HeldDirectory};
    use std::{
        ffi::OsStr,
        io::{Seek, SeekFrom},
    };

    let fixture = Fixture::new();
    let original: Vec<u8> = (0..(CHUNK_BYTES * 2 + 19))
        .map(|index| (index % 251) as u8)
        .collect();
    let path = fixture.file("streamed-digest.dat", &original);
    let empty = fixture.file("streamed-empty.dat", b"");
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let root = HeldDirectory::open_root(&fixture.root.path.join("selected"), &checks).unwrap();
    let mut selected = root
        .open_existing_descendant(&[OsStr::new("streamed-digest.dat")], &checks)
        .unwrap();
    checks
        .io(|| selected.file().seek(SeekFrom::Start(7)))
        .unwrap();
    let observed = selected
        .observe_sha256(original.len() as u64, &checks)
        .unwrap();
    assert_eq!(observed.length, original.len() as u64);
    let expected: [u8; 32] = Sha256::digest(&original).into();
    assert_eq!(observed.sha256, expected);
    assert_eq!(
        selected
            .observe_sha256(original.len() as u64 - 1, &checks)
            .unwrap_err()
            .kind,
        ErrorKind::UnsafeSelection
    );
    selected.close(&checks).unwrap();

    let mut selected_empty = root
        .open_existing_descendant(&[OsStr::new("streamed-empty.dat")], &checks)
        .unwrap();
    let observed_empty = selected_empty.observe_sha256(0, &checks).unwrap();
    assert_eq!(observed_empty.length, 0);
    let expected_empty: [u8; 32] = Sha256::digest(b"").into();
    assert_eq!(observed_empty.sha256, expected_empty);
    selected_empty.close(&checks).unwrap();
    root.close(&checks).unwrap();
    assert_eq!(fs::read(path).unwrap(), original);
    assert_eq!(fs::read(empty).unwrap(), b"");
}

#[test]
fn shared_held_file_digest_preserves_request_cancellation_at_checkpoints() {
    use mmmm_owned_files::{CHUNK_BYTES, Control, HeldDirectory};
    use std::{cell::Cell, ffi::OsStr};

    struct Counted<'a, C> {
        inner: &'a C,
        cancelled: &'a AtomicBool,
        calls: Cell<usize>,
        cancel_at: Option<usize>,
    }
    impl<C: Control> Control for Counted<'_, C> {
        type Error = C::Error;
        fn check(&self) -> Result<(), Self::Error> {
            let next = self.calls.get() + 1;
            self.calls.set(next);
            if self.cancel_at == Some(next) {
                self.cancelled.store(true, Ordering::Release);
            }
            self.inner.check()
        }
        fn io_error(&self, error: io::Error) -> Self::Error {
            self.inner.io_error(error)
        }
        fn unsafe_selection(&self) -> Self::Error {
            self.inner.unsafe_selection()
        }
        fn changed(&self) -> Self::Error {
            self.inner.changed()
        }
        fn with_post_failure(&self, a: Self::Error, b: Self::Error) -> Self::Error {
            self.inner.with_post_failure(a, b)
        }
    }

    let fixture = Fixture::new();
    let original = vec![b'd'; CHUNK_BYTES * 2 + 1];
    fixture.file("streamed-cancel.dat", &original);
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let root = HeldDirectory::open_root(&fixture.root.path.join("selected"), &checks).unwrap();
    let mut selected = root
        .open_existing_descendant(&[OsStr::new("streamed-cancel.dat")], &checks)
        .unwrap();
    let baseline = Counted {
        inner: &checks,
        cancelled: &fixture.cancelled,
        calls: Cell::new(0),
        cancel_at: None,
    };
    selected
        .observe_sha256(original.len() as u64, &baseline)
        .unwrap();
    let total = baseline.calls.get();
    assert!(
        total > 2,
        "the observation must contain intermediate checkpoints"
    );
    selected.close(&checks).unwrap();

    for cancel_at in [1, total / 2, total] {
        fixture.cancelled.store(false, Ordering::Release);
        let mut selected = root
            .open_existing_descendant(&[OsStr::new("streamed-cancel.dat")], &checks)
            .unwrap();
        let controlled = Counted {
            inner: &checks,
            cancelled: &fixture.cancelled,
            calls: Cell::new(0),
            cancel_at: Some(cancel_at),
        };
        let error = selected
            .observe_sha256(original.len() as u64, &controlled)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Request);
        assert_eq!(
            error
                .source()
                .unwrap()
                .downcast_ref::<ServiceError>()
                .unwrap()
                .code,
            "CANCELLED"
        );
        fixture.cancelled.store(false, Ordering::Release);
        selected.close(&checks).unwrap();
    }
    root.close(&checks).unwrap();
}

#[cfg(unix)]
#[test]
fn unix_held_file_digest_detects_a_truncation_during_observation() {
    use mmmm_owned_files::{CHUNK_BYTES, Control, HeldDirectory};
    use std::{cell::Cell, ffi::OsStr};

    struct TruncateAt<'a, C> {
        inner: &'a C,
        calls: Cell<usize>,
        at: usize,
        path: &'a Path,
    }
    impl<C: Control> Control for TruncateAt<'_, C> {
        type Error = C::Error;
        fn check(&self) -> Result<(), Self::Error> {
            let next = self.calls.get() + 1;
            self.calls.set(next);
            if next == self.at {
                OpenOptions::new()
                    .write(true)
                    .open(self.path)
                    .unwrap()
                    .set_len(1)
                    .unwrap();
            }
            self.inner.check()
        }
        fn io_error(&self, error: io::Error) -> Self::Error {
            self.inner.io_error(error)
        }
        fn unsafe_selection(&self) -> Self::Error {
            self.inner.unsafe_selection()
        }
        fn changed(&self) -> Self::Error {
            self.inner.changed()
        }
        fn with_post_failure(&self, a: Self::Error, b: Self::Error) -> Self::Error {
            self.inner.with_post_failure(a, b)
        }
    }

    let fixture = Fixture::new();
    let original = vec![b'x'; CHUNK_BYTES * 2 + 1];
    let path = fixture.file("streamed-mutation.dat", &original);
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let root = HeldDirectory::open_root(&fixture.root.path.join("selected"), &checks).unwrap();
    let mut selected = root
        .open_existing_descendant(&[OsStr::new("streamed-mutation.dat")], &checks)
        .unwrap();
    // Mutation occurs at an observation checkpoint after selection; the test
    // does not claim which pass observed the race.
    let controlled = TruncateAt {
        inner: &checks,
        calls: Cell::new(0),
        at: 4,
        path: &path,
    };
    let error = selected
        .observe_sha256(original.len() as u64, &controlled)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Changed);
    assert!(controlled.calls.get() >= controlled.at);
    if let Err(close_error) = selected.close(&checks) {
        assert_eq!(close_error.kind, ErrorKind::Changed);
    }
    root.close(&checks).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_held_file_digest_rejects_a_new_external_writer() {
    use mmmm_owned_files::HeldDirectory;
    use std::ffi::OsStr;

    let fixture = Fixture::new();
    let original = b"stable held digest bytes";
    let path = fixture.file("streamed-held.dat", original);
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let root = HeldDirectory::open_root(&fixture.root.path.join("selected"), &checks).unwrap();
    let mut selected = root
        .open_existing_descendant(&[OsStr::new("streamed-held.dat")], &checks)
        .unwrap();
    assert!(OpenOptions::new().write(true).open(&path).is_err());
    let observed = selected
        .observe_sha256(original.len() as u64, &checks)
        .unwrap();
    let expected: [u8; 32] = Sha256::digest(original).into();
    assert_eq!(observed.sha256, expected);
    selected.close(&checks).unwrap();
    root.close(&checks).unwrap();
    assert_eq!(fs::read(path).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn unix_relative_selection_rejects_links_and_detects_root_or_leaf_replacement() {
    use mmmm_owned_files::HeldDirectory;
    use std::{ffi::OsStr, os::unix::fs::symlink};

    let fixture = Fixture::new();
    let target = fixture.file("relative-target.dat", b"stable owned bytes");
    let leaf_link = fixture.root.path.join("selected/relative-link.dat");
    symlink(&target, &leaf_link).unwrap();
    let directory_link = fixture.root.path.join("selected/relative-alias");
    symlink(fixture.root.path.join("selected"), &directory_link).unwrap();
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let selected_path = fixture.root.path.join("selected");
    let root = HeldDirectory::open_root(&selected_path, &checks).unwrap();
    assert!(
        root.open_existing_descendant(&[OsStr::new("relative-link.dat")], &checks)
            .is_err()
    );
    assert!(
        root.open_existing_descendant(
            &[
                OsStr::new("relative-alias"),
                OsStr::new("relative-target.dat")
            ],
            &checks
        )
        .is_err()
    );
    fixture.remove_owned_leaf(&leaf_link);
    fixture.remove_owned_leaf(&directory_link);

    let file = root
        .open_existing_descendant(&[OsStr::new("relative-target.dat")], &checks)
        .unwrap();
    let moved_leaf = fixture.root.path.join("selected/relative-moved.dat");
    fs::rename(&target, &moved_leaf).unwrap();
    fs::write(&target, b"stable owned bytes").unwrap();
    assert_eq!(
        file.revalidate(&checks).err().unwrap().kind,
        ErrorKind::Changed
    );
    fixture.remove_owned_leaf(&target);
    fs::rename(&moved_leaf, &target).unwrap();
    file.close(&checks).unwrap();

    let moved_root = fixture.root.path.join("relative-moved-root");
    fs::rename(&selected_path, &moved_root).unwrap();
    // A missing original name may preserve a native I/O error; either way the
    // held root cannot be silently treated as the current named root.
    assert!(root.revalidate(&checks).is_err());
    fs::rename(&moved_root, &selected_path).unwrap();
    root.close(&checks).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_relative_selection_holds_file_and_root_against_new_writer_or_rename() {
    use mmmm_owned_files::HeldDirectory;
    use std::ffi::OsStr;

    let fixture = Fixture::new();
    let path = fixture.file("relative-held.dat", b"stable owned bytes");
    let selected_path = fixture.root.path.join("selected");
    let moved = fixture.root.path.join("relative-moved-root");
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let root = HeldDirectory::open_root(&selected_path, &checks).unwrap();
    let file = root
        .open_existing_descendant(&[OsStr::new("relative-held.dat")], &checks)
        .unwrap();
    assert!(OpenOptions::new().write(true).open(&path).is_err());
    assert!(fs::rename(&selected_path, &moved).is_err());
    file.revalidate(&checks).unwrap();
    file.close(&checks).unwrap();
    root.close(&checks).unwrap();
    assert_eq!(fs::read(path).unwrap(), b"stable owned bytes");
}

#[cfg(unix)]
#[test]
fn shared_create_new_refuses_existing_symlink_without_opening_its_target() {
    use mmmm_owned_files::HeldDirectory;
    use std::ffi::OsStr;
    let fixture = Fixture::new();
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let target = fixture.file("unchanged.bin", b"original owned target");
    let link = fixture.root.path.join("selected/occupied.bin");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let root = HeldDirectory::open_root(&fixture.root.path.join("selected"), &checks).unwrap();
    assert_eq!(
        root.require_child_absent(OsStr::new("occupied.bin"), &checks)
            .err()
            .unwrap()
            .kind,
        ErrorKind::UnsafeSelection
    );
    let error = root
        .create_file_new(OsStr::new("occupied.bin"), 0, &checks)
        .err()
        .unwrap();
    assert_eq!(error.kind, ErrorKind::Io);
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    root.close(&checks).unwrap();
    fixture.remove_owned_leaf(&link);
    assert_eq!(fs::read(target).unwrap(), b"original owned target");
}

#[test]
fn lexical_validation_is_pure_and_rejects_known_secret_selectors_before_any_file_access() {
    for name in [
        ".env",
        ".env.production",
        ".envrc",
        ".ssh/object.json",
        ".aws/object.json",
        ".azure/object.json",
        ".config/gcloud/object.json",
        ".docker/config.json",
        ".config/gh/hosts.yml",
        "environ",
        "proc/123/environ",
        "credentials.json",
        "public-credentials.json",
        "service-account.json",
        "arbitrary_service_account_data.json",
        "api-key.json",
        "api_keys.json",
        "private-key.json",
        "key.json",
        "keys.json",
        "public-key.json",
        "id_rsa",
        "id_ed25519.pub",
        "id_ed25519_sk",
        "ssh_host_rsa_key",
        "object.ppk",
        "object.pem",
        "object.key",
        "object.p12",
        "object.pfx",
        "object.jks",
        "secret/object.json",
        "tokens.json",
        ".git-credentials",
    ] {
        // No exists/metadata/open/hash or fixture file creation for these names.
        for role in [
            InputRole::Document,
            InputRole::ResourceDescriptor,
            InputRole::ResourceBytes,
        ] {
            assert!(validate_selection(&lexical_path(name), role).is_err());
        }
    }
    for name in [
        "object.json",
        "private/object.json",
        ".config/object.json",
        "var/object.json",
        "monkey.json",
        "keyframe.json",
        "environ/object.json",
    ] {
        assert!(validate_selection(&lexical_path(name), InputRole::Document).is_ok());
    }
    assert!(validate_selection(&lexical_path("object.bin"), InputRole::ResourceBytes).is_ok());
    for name in [
        "object.JSON",
        "object.bin",
        "./object.json",
        "folder/../object.json",
        "folder//object.json",
        "folder/./object.json",
        "object\0.json",
        "object\n.json",
        "object.json/",
    ] {
        assert!(validate_selection(&lexical_path(name), InputRole::Document).is_err());
    }
    assert!(validate_selection(Path::new("relative.json"), InputRole::Document).is_err());
    assert!(
        validate_selection(
            &lexical_path(&format!("{}.json", "a".repeat(4096))),
            InputRole::Document
        )
        .is_err()
    );
    assert!(
        validate_selection(
            &lexical_path(&format!("{}object.json", "a/".repeat(70))),
            InputRole::Document
        )
        .is_err()
    );
}

#[cfg(windows)]
#[test]
fn lexical_windows_rejects_unc_verbatim_devices_ads_and_short_name_spellings() {
    for path in [
        r"\\server\share\object.json",
        r"\\?\C:\selected\object.json",
        r"\\.\C:\selected\object.json",
        r"C:object.json",
        r"C:\selected\object.json:stream",
        r"C:\selected\NUL.json",
        r"C:\selected\COM1.json",
        r"C:\selected\CON .json",
        r"C:\selected\COM¹.json",
        r"C:\selected\LPT³.json",
        r"C:\selected\object .\value.json",
        r"C:\SELECT~1\object.json",
        r"C:\selected\object.json ",
    ] {
        assert!(validate_selection(Path::new(path), InputRole::Document).is_err());
        assert!(validate_selection(Path::new(path), InputRole::ResourceBytes).is_err());
    }
}

#[test]
fn finite_reservations_include_inline_bytes_descriptors_raw_bytes_and_selected_file_count() {
    assert!(ImportReadBudget::new(usize::MAX).is_err());
    let mut totals = ImportReadBudget::new(DOCUMENT_TOTAL as usize).unwrap();
    assert!(totals.reserve(InputRole::ResourceDescriptor, 1).is_err());
    let mut totals = ImportReadBudget::new(0).unwrap();
    assert!(
        totals
            .reserve(InputRole::Document, DOCUMENT_LIMIT + 1)
            .is_err()
    );
    assert!(
        totals
            .reserve(InputRole::ResourceDescriptor, DESCRIPTOR_LIMIT + 1)
            .is_err()
    );
    assert_eq!(
        totals
            .reserve(InputRole::ResourceBytes, RESOURCE_TOTAL)
            .unwrap(),
        RESOURCE_TOTAL as usize
    );
    assert!(totals.reserve(InputRole::ResourceBytes, 1).is_err());
    let mut totals = ImportReadBudget::new(0).unwrap();
    for _ in 0..SELECTED_FILE_LIMIT {
        totals.reserve(InputRole::Document, 0).unwrap();
    }
    assert!(totals.reserve(InputRole::Document, 0).is_err());
}

#[test]
fn actual_owned_file_bytes_survive_both_digest_passes_without_reserialization() {
    let fixture = Fixture::new();
    let bytes = b" { \"value\":1, \"value\":2 }\n";
    let document = fixture.file("object.json", bytes);
    let descriptor = fixture.file("resource.json", b"{}\n");
    let raw = fixture.file("resource.bin", &[0, 255, 10, 0, 42]);
    let empty = fixture.file("empty.bin", b"");
    let mut totals = ImportReadBudget::new(17).unwrap();
    let mut passes = [0usize; 2];
    assert_eq!(
        read_selected_inner(
            &document,
            InputRole::Document,
            &fixture.owner,
            &fixture.budget,
            &mut totals,
            |_, second| passes[usize::from(second)] += 1
        )
        .unwrap(),
        bytes
    );
    assert_eq!(passes, [1, 1]);
    assert_eq!(
        fixture
            .read(&descriptor, InputRole::ResourceDescriptor, &mut totals)
            .unwrap(),
        b"{}\n"
    );
    assert_eq!(
        fixture
            .read(&raw, InputRole::ResourceBytes, &mut totals)
            .unwrap(),
        [0, 255, 10, 0, 42]
    );
    assert_eq!(
        fixture
            .read(&empty, InputRole::ResourceBytes, &mut totals)
            .unwrap(),
        b""
    );
    assert_eq!(totals.documents, 17 + bytes.len() as u64 + 3);
    assert_eq!(totals.resources, 5);
    assert_eq!(totals.selected_files, 4);
}

#[test]
fn missing_directory_and_metadata_oversize_inputs_fail_before_copy_without_path_disclosure() {
    let fixture = Fixture::new();
    let missing = fixture.root.path.join("selected/missing.json");
    let error = fixture
        .read(
            &missing,
            InputRole::Document,
            &mut ImportReadBudget::new(0).unwrap(),
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Io);
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap()
            .kind(),
        io::ErrorKind::NotFound
    );
    assert!(
        !error
            .to_string()
            .contains(fixture.root.path.to_str().unwrap())
    );
    assert!(!format!("{error:?}").contains(fixture.root.path.to_str().unwrap()));
    let directory = fixture.root.path.join("selected/folder.json");
    fs::create_dir(&directory).unwrap();
    assert!(
        fixture
            .read(
                &directory,
                InputRole::Document,
                &mut ImportReadBudget::new(0).unwrap()
            )
            .is_err()
    );
    for (name, role, length) in [
        ("too-large.json", InputRole::Document, DOCUMENT_LIMIT + 1),
        (
            "too-large-descriptor.json",
            InputRole::ResourceDescriptor,
            DESCRIPTOR_LIMIT + 1,
        ),
        (
            "too-large.bin",
            InputRole::ResourceBytes,
            RESOURCE_TOTAL + 1,
        ),
    ] {
        let path = fixture.file(name, b"");
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(length)
            .unwrap();
        let mut totals = ImportReadBudget::new(0).unwrap();
        let error = fixture.read(&path, role, &mut totals).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Limit);
        assert_eq!(totals.selected_files, 0);
    }
}

#[test]
fn original_cancellation_is_checked_before_open_and_between_read_chunks() {
    let fixture = Fixture::new();
    let missing = fixture.root.path.join("selected/missing.json");
    fixture.cancelled.store(true, Ordering::Release);
    let error = fixture
        .read(
            &missing,
            InputRole::Document,
            &mut ImportReadBudget::new(0).unwrap(),
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Request);
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<ServiceError>()
            .unwrap()
            .code,
        "CANCELLED"
    );
    fixture.cancelled.store(false, Ordering::Release);
    let path = fixture.file("cancel.json", &vec![b' '; CHUNK * 2]);
    let mut totals = ImportReadBudget::new(0).unwrap();
    let mut checkpoints = 0;
    let error = read_selected_inner(
        &path,
        InputRole::Document,
        &fixture.owner,
        &fixture.budget,
        &mut totals,
        |_, second| {
            assert!(!second);
            checkpoints += 1;
            fixture.cancelled.store(true, Ordering::Release);
        },
    )
    .unwrap_err();
    assert_eq!(checkpoints, 1);
    assert_eq!(error.kind, ErrorKind::Request);
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<ServiceError>()
            .unwrap()
            .code,
        "CANCELLED"
    );
    assert_eq!(totals.documents, (CHUNK * 2) as u64);
}

#[test]
fn native_io_failure_and_its_following_original_cancellation_both_remain_diagnosable() {
    let fixture = Fixture::new();
    let missing = fixture.root.path.join("selected/missing.json");
    let checks = Checks {
        owner: &fixture.owner,
        budget: &fixture.budget,
    };
    let error = checks
        .io(|| {
            let native = OpenOptions::new().read(true).open(&missing);
            fixture.cancelled.store(true, Ordering::Release);
            native
        })
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Io);
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap()
            .kind(),
        io::ErrorKind::NotFound
    );
    let checkpoint = error.checkpoint_failure().unwrap();
    assert_eq!(checkpoint.kind, ErrorKind::Request);
    assert_eq!(
        checkpoint
            .source()
            .unwrap()
            .downcast_ref::<ServiceError>()
            .unwrap()
            .code,
        "CANCELLED"
    );
}

#[test]
fn an_existing_hardlink_is_rejected_before_any_source_bytes_are_read() {
    let fixture = Fixture::new();
    let path = fixture.file("linked.json", b"ordinary owned link fixture\n");
    let other = fixture.root.path.join("selected/other.json");
    fs::hard_link(&path, &other).unwrap();
    let mut checkpoints = 0;
    let error = read_selected_inner(
        &path,
        InputRole::Document,
        &fixture.owner,
        &fixture.budget,
        &mut ImportReadBudget::new(0).unwrap(),
        |_, _| checkpoints += 1,
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnsafeSelection);
    assert_eq!(checkpoints, 0);
    fixture.remove_owned_leaf(&other);
}

#[cfg(unix)]
#[test]
fn unix_symlink_leaf_ancestor_and_fifo_are_rejected_before_any_read() {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, fs::symlink},
    };
    let fixture = Fixture::new();
    let plain = fixture.file("ordinary.json", b"ordinary owned bytes\n");
    let leaf = fixture.root.path.join("selected/leaf.json");
    symlink(&plain, &leaf).unwrap();
    let ancestor = fixture.root.path.join("alias");
    symlink(fixture.root.path.join("selected"), &ancestor).unwrap();
    let through_ancestor = ancestor.join("ordinary.json");
    let fifo = fixture.root.path.join("selected/pipe.bin");
    let c_fifo = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: exclusively owned, marked fixture path outside the checkout;
    // mkfifo creates no content and the reader must never read from this FIFO.
    assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
    for (path, role) in [
        (&leaf, InputRole::Document),
        (&through_ancestor, InputRole::Document),
        (&fifo, InputRole::ResourceBytes),
    ] {
        let mut checkpoints = 0;
        assert!(
            read_selected_inner(
                path,
                role,
                &fixture.owner,
                &fixture.budget,
                &mut ImportReadBudget::new(0).unwrap(),
                |_, _| checkpoints += 1
            )
            .is_err()
        );
        assert_eq!(checkpoints, 0);
    }
    fixture.remove_owned_leaf(&leaf);
    fixture.remove_owned_leaf(&ancestor);
    fixture.remove_owned_leaf(&fifo);
}

#[cfg(unix)]
#[test]
fn unix_detects_truncation_of_the_actual_held_regular_file_during_read() {
    let fixture = Fixture::new();
    let path = fixture.file("changing.json", &vec![b' '; CHUNK * 2]);
    let mut changed = false;
    let error = read_selected_inner(
        &path,
        InputRole::Document,
        &fixture.owner,
        &fixture.budget,
        &mut ImportReadBudget::new(0).unwrap(),
        |_, second| {
            if !second && !changed {
                changed = true;
                OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(1)
                    .unwrap();
            }
        },
    )
    .unwrap_err();
    assert!(changed);
    assert_eq!(error.kind, ErrorKind::Changed);
}

#[cfg(unix)]
#[test]
fn unix_detects_selected_leaf_and_ancestor_namespace_replacement() {
    let fixture = Fixture::new();
    let bytes = vec![b' '; CHUNK * 2];
    let path = fixture.file("replaced.json", &bytes);
    let moved = fixture.root.path.join("selected/moved.json");
    let mut changed = false;
    let error = read_selected_inner(
        &path,
        InputRole::Document,
        &fixture.owner,
        &fixture.budget,
        &mut ImportReadBudget::new(0).unwrap(),
        |_, second| {
            if !second && !changed {
                changed = true;
                fs::rename(&path, &moved).unwrap();
                fs::write(&path, &bytes).unwrap();
            }
        },
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Changed);
    let directory = fixture.root.path.join("selected/parent");
    fs::create_dir(&directory).unwrap();
    let path = directory.join("object.json");
    fs::write(&path, &bytes).unwrap();
    let moved = fixture.root.path.join("selected/moved-parent");
    let mut changed = false;
    let error = read_selected_inner(
        &path,
        InputRole::Document,
        &fixture.owner,
        &fixture.budget,
        &mut ImportReadBudget::new(0).unwrap(),
        |_, second| {
            if !second && !changed {
                changed = true;
                fs::rename(&directory, &moved).unwrap();
                fs::create_dir(&directory).unwrap();
                fs::write(&path, &bytes).unwrap();
            }
        },
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Changed);
}

#[cfg(windows)]
#[test]
fn windows_held_handles_reject_concurrent_writer_and_namespace_delete_sharing() {
    let fixture = Fixture::new();
    let bytes = vec![b' '; CHUNK * 2];
    let path = fixture.file("held.json", &bytes);
    let moved = fixture.root.path.join("selected/moved.json");
    let parent = fixture.root.path.join("selected");
    let moved_parent = fixture.root.path.join("moved-selected");
    let mut attempted = false;
    let read = read_selected_inner(
        &path,
        InputRole::Document,
        &fixture.owner,
        &fixture.budget,
        &mut ImportReadBudget::new(0).unwrap(),
        |_, second| {
            if !second && !attempted {
                attempted = true;
                assert!(OpenOptions::new().write(true).open(&path).is_err());
                assert!(fs::rename(&path, &moved).is_err());
                assert!(fs::rename(&parent, &moved_parent).is_err());
            }
        },
    )
    .unwrap();
    assert!(attempted);
    assert_eq!(read, bytes);
    assert!(!moved.exists());
    assert!(!moved_parent.exists());
}

//! These fixtures are required because lexical tests cannot establish actual
//! file-handle identity, no-follow behavior or the live native owner boundary.
//! Only newly created, marked files outside the checkout are read or removed.
//! Known secret names appear only in pure lexical tests; none are created.

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

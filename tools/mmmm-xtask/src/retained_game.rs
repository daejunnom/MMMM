//! Explicit retained game storage. No Drop, eviction, or game-data removal path.
use super::*;

const RETAINED_SCHEMA: &str = "mmmm-retained-game/1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    schema: String,
    catalog_id: String,
    slot_id: String,
    checkout_digest: String,
    root_digest: String,
    os: String,
    arch: String,
    purpose: String,
    token: String,
    state: SlotState,
    completed_ms: Option<u64>,
}

/// A private path and both lease tokens intentionally have no Debug/Serialize projection.
/// The borrow prevents completion of the enclosing build while this handle is live.
pub struct RetainedGame<'build> {
    build: &'build ManagedBuild,
    root: PathBuf,
    game: PathBuf,
    root_anchor: DirectoryAnchor,
    game_anchor: DirectoryAnchor,
    owner: Owner,
    owner_bytes: Vec<u8>,
    lease_bytes: Vec<u8>,
}

impl fmt::Debug for RetainedGame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedGame").finish_non_exhaustive()
    }
}

/// Measurements cover this retained root and the current managed catalog only.
/// They do not claim a quota over other retained roots.
#[derive(Clone, Debug, Serialize)]
pub struct RetainedMeasurement {
    pub game_bytes: u64,
    pub retained_bytes: u64,
    pub build_slot_bytes: u64,
    pub build_catalog_bytes: u64,
    pub combined_slot_bytes: u64,
    pub combined_catalog_bytes: u64,
    pub within_budget: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RetainedCompletion {
    pub lease_released: bool,
    pub game_retained: bool,
    /// Includes the complete owner and the lease immediately before release.
    pub observed_before_release: RetainedMeasurement,
}

impl<'build> RetainedGame<'build> {
    /// No default root, unowned-directory adoption, interrupted-lease recovery,
    /// process launch, or EULA consent is implied by this storage handle.
    pub fn acquire(
        build: &'build ManagedBuild,
        checkout: &Path,
        root: &Path,
        progress: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Self, StorageError> {
        observation_checkpoint(progress)?;
        build.verify_ownership()?;
        reject_secret_root(checkout)?;
        validate_absolute_path(checkout)?;
        verify_directory(checkout)?;
        let checkout = fs::canonicalize(checkout)
            .map_err(|e| StorageError::io("resolve retained checkout", e))?;
        reject_secret_root(&checkout)?;
        if digest_bytes(path_identity(&checkout).as_bytes()) != build.slot.checkout_digest {
            return Err(StorageError::new(
                "ownership",
                "retained checkout differs from the current managed build",
            ));
        }
        verify_directory(&build.config.evidence_root)?;
        verify_directory(&build.paths.evidence)?;
        let evidence = fs::canonicalize(&build.config.evidence_root)
            .map_err(|e| StorageError::io("resolve retained evidence boundary", e))?;
        validate_root_path(root)?;
        check_nonoverlap(root, &checkout, &build.paths.catalog, &evidence)?;
        let parent = root.parent().ok_or_else(|| {
            StorageError::new(
                "path",
                "retained root must have an ordinary directory parent",
            )
        })?;
        verify_directory(parent)?;
        observation_checkpoint(progress)?;
        let created = match fs::symlink_metadata(root) {
            Ok(_) => {
                verify_directory(root)?;
                false
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // create_dir is exclusive: an intervening creator is never adopted.
                create_directory(root)?;
                true
            }
            Err(error) => return Err(StorageError::io("inspect retained root", error)),
        };
        let root =
            fs::canonicalize(root).map_err(|e| StorageError::io("resolve retained root", e))?;
        validate_root_path(&root)?;
        check_nonoverlap(&root, &checkout, &build.paths.catalog, &evidence)?;
        let root_anchor = DirectoryAnchor::open(&root)?;
        let entries = root_entries(&root, progress)?;
        let root_digest = digest_bytes(path_identity(&root).as_bytes());
        let previous = if created {
            if entries != RootEntries::default() {
                return Err(StorageError::new(
                    "ownership",
                    "new retained root changed before initialization",
                ));
            }
            None
        } else {
            if entries.lease {
                return Err(busy());
            }
            if !entries.owner || !entries.game {
                return Err(StorageError::new(
                    "ownership",
                    "existing retained root has no recognized complete ownership",
                ));
            }
            let bytes = read_record_bytes(&root.join("owner.json"))?;
            let owner: Owner = serde_json::from_slice(&bytes).map_err(|_| {
                StorageError::new("record", "retained owner is not a closed bounded record")
            })?;
            validate_complete_owner(&owner, build, &root_digest)?;
            verify_directory(&root.join("game"))?;
            Some(bytes)
        };
        let mut lease = build.lease.clone();
        lease.schema = RETAINED_SCHEMA.into();
        let lease_bytes = record_bytes(&lease)?;
        let owner = Owner {
            schema: RETAINED_SCHEMA.into(),
            catalog_id: build.catalog.catalog_id.clone(),
            slot_id: build.slot.slot_id.clone(),
            checkout_digest: build.slot.checkout_digest.clone(),
            root_digest,
            os: build.slot.os.clone(),
            arch: build.slot.arch.clone(),
            purpose: build.slot.purpose.clone(),
            token: build.lease.token.clone(),
            state: SlotState::Active,
            completed_ms: None,
        };
        let owner_bytes = record_bytes(&owner)?;
        observation_checkpoint(progress)?;
        build.verify_ownership()?;
        root_anchor.verify(&root)?;
        if root_entries(&root, progress)? != entries {
            return Err(StorageError::new(
                "ownership",
                "retained root entries changed",
            ));
        }
        if let Some(bytes) = &previous {
            verify_record_bytes(&root.join("owner.json"), bytes)?;
        }
        write_new_record(&root.join("lease.json"), &lease_bytes).map_err(|error| {
            if error.kind == "exists" {
                busy()
            } else {
                error
            }
        })?;
        // Every failure after CreateNew deliberately preserves this exact lease.
        observation_checkpoint(progress)?;
        build.verify_ownership()?;
        root_anchor.verify(&root)?;
        verify_record_bytes(&root.join("lease.json"), &lease_bytes)?;
        let game = root.join("game");
        if created {
            create_directory(&game)?;
            write_new_record(&root.join("owner.json"), &owner_bytes)?;
        } else {
            verify_record_bytes(&root.join("owner.json"), previous.as_deref().unwrap())?;
            atomic_record(&root.join("owner.json"), &owner_bytes)?;
        }
        let game_anchor = DirectoryAnchor::open(&game)?;
        let retained = Self {
            build,
            root,
            game,
            root_anchor,
            game_anchor,
            owner,
            owner_bytes,
            lease_bytes,
        };
        observation_checkpoint(progress)?;
        retained.check_current_ownership()?;
        observation_checkpoint(progress)?;
        Ok(retained)
    }

    /// This path is only a working directory. It grants no process authority.
    pub fn game_directory(&self) -> Result<&Path, StorageError> {
        self.check_current_ownership()?;
        Ok(&self.game)
    }

    pub fn check_current_ownership(&self) -> Result<(), StorageError> {
        self.build.verify_ownership()?;
        self.root_anchor.verify(&self.root)?;
        if root_entries(&self.root, &mut || Ok(()))? != RootEntries::active() {
            return Err(StorageError::new(
                "ownership",
                "retained root entries changed",
            ));
        }
        self.game_anchor.verify(&self.game)?;
        verify_record_bytes(&self.root.join("owner.json"), &self.owner_bytes)?;
        verify_record_bytes(&self.root.join("lease.json"), &self.lease_bytes)?;
        self.root_anchor.verify(&self.root)
    }

    pub fn measure_with_progress(
        &self,
        progress: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<RetainedMeasurement, StorageError> {
        observation_checkpoint(progress)?;
        self.check_current_ownership()?;
        let measured = (|| {
            let build = self.build.measure_with_progress(progress)?;
            let game_bytes = game_tree_bytes(&self.game, progress)?;
            let retained_bytes = checked_sum(
                game_bytes,
                checked_sum(self.owner_bytes.len() as u64, self.lease_bytes.len() as u64)?,
            )?;
            let combined_slot_bytes = checked_sum(build.slot_bytes, retained_bytes)?;
            let combined_catalog_bytes = checked_sum(build.catalog_bytes, retained_bytes)?;
            Ok(RetainedMeasurement {
                game_bytes,
                retained_bytes,
                build_slot_bytes: build.slot_bytes,
                build_catalog_bytes: build.catalog_bytes,
                combined_slot_bytes,
                combined_catalog_bytes,
                within_budget: combined_slot_bytes <= self.build.config.budgets.slot_bytes
                    && combined_catalog_bytes <= self.build.config.budgets.catalog_bytes,
            })
        })();
        let postcheck = self
            .check_current_ownership()
            .and_then(|()| observation_checkpoint(progress));
        checked_result(measured, postcheck)
    }

    /// A failed command can complete storage once native drain and durable
    /// evidence export are verified. No game/world/config is ever removed.
    pub fn complete(
        mut self,
        outcome: &FinishOutcome,
        progress: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<RetainedCompletion, StorageError> {
        observation_checkpoint(progress)?;
        self.check_current_ownership()?;
        if !outcome.drained {
            return Err(StorageError::new(
                "undrained",
                "retained game drain is unverified; lease preserved",
            ));
        }
        if !outcome.evidence_exported {
            return Err(StorageError::new(
                "evidence",
                "retained game evidence export is unverified; lease preserved",
            ));
        }
        // Observe while the original active ownership is still intact as well.
        self.measure_with_progress(progress)?;
        self.owner.state = SlotState::Complete;
        self.owner.completed_ms = Some(now_ms()?);
        let complete_bytes = record_bytes(&self.owner)?;
        observation_checkpoint(progress)?;
        self.check_current_ownership()?;
        atomic_record(&self.root.join("owner.json"), &complete_bytes)?;
        self.owner_bytes = complete_bytes;
        let observed_before_release = self.measure_with_progress(progress)?;
        observation_checkpoint(progress)?;
        self.check_current_ownership()?;
        // Like the enclosing managed catalog, release assumes cooperative
        // filesystem users. Validation followed by path unlink is not an atomic
        // compare-inode-and-unlink primitive against hostile same-UID mutation.
        fs::remove_file(self.root.join("lease.json"))
            .map_err(|e| StorageError::io("release retained game lease", e))?;
        sync_directory(&self.root)?;
        self.build.verify_ownership()?;
        self.root_anchor.verify(&self.root)?;
        self.game_anchor.verify(&self.game)?;
        verify_record_bytes(&self.root.join("owner.json"), &self.owner_bytes)?;
        if root_entries(&self.root, progress)?
            != (RootEntries {
                owner: true,
                lease: false,
                game: true,
            })
        {
            return Err(StorageError::new(
                "ownership",
                "retained root changed after lease release",
            ));
        }
        Ok(RetainedCompletion {
            lease_released: true,
            game_retained: true,
            observed_before_release,
        })
    }
}

fn checked_result<T>(
    result: Result<T, StorageError>,
    postcheck: Result<(), StorageError>,
) -> Result<T, StorageError> {
    match (result, postcheck) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(mut primary), Err(postcheck)) => {
            let mut tail = &mut primary;
            while let Some(ref mut cause) = tail.cause {
                tail = cause;
            }
            tail.cause = Some(Box::new(postcheck));
            Err(primary)
        }
    }
}

fn busy() -> StorageError {
    StorageError::new("busy", "retained lease exists; no automatic lease adoption")
}

fn validate_complete_owner(
    owner: &Owner,
    build: &ManagedBuild,
    root_digest: &str,
) -> Result<(), StorageError> {
    if owner.schema != RETAINED_SCHEMA
        || owner.catalog_id != build.catalog.catalog_id
        || owner.slot_id != build.slot.slot_id
        || owner.checkout_digest != build.slot.checkout_digest
        || owner.root_digest != root_digest
        || owner.os != build.slot.os
        || owner.arch != build.slot.arch
        || owner.purpose != build.slot.purpose
        || !is_digest(&owner.token)
        || owner.state != SlotState::Complete
        || owner.completed_ms.is_none()
    {
        return Err(StorageError::new(
            "ownership",
            "retained owner is not the exact recognized complete owner",
        ));
    }
    Ok(())
}

fn validate_root_path(root: &Path) -> Result<(), StorageError> {
    reject_secret_root(root)?;
    validate_absolute_path(root)?;
    if root.file_name().is_none() {
        return Err(StorageError::new(
            "path",
            "filesystem root is not retained game storage",
        ));
    }
    #[cfg(windows)]
    if !matches!(root.components().next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)))
    {
        return Err(StorageError::new(
            "path",
            "retained root requires a local ordinary drive path",
        ));
    }
    Ok(())
}

fn check_nonoverlap(
    root: &Path,
    checkout: &Path,
    catalog: &Path,
    evidence: &Path,
) -> Result<(), StorageError> {
    for boundary in [checkout, catalog, evidence] {
        reject_overlap(
            root,
            boundary,
            "retained game root overlaps a protected build boundary",
        )?;
    }
    Ok(())
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct RootEntries {
    owner: bool,
    lease: bool,
    game: bool,
}
impl RootEntries {
    fn active() -> Self {
        Self {
            owner: true,
            lease: true,
            game: true,
        }
    }
}
fn root_entries(
    root: &Path,
    progress: &mut dyn FnMut() -> Result<(), String>,
) -> Result<RootEntries, StorageError> {
    observation_checkpoint(progress)?;
    let directory =
        fs::read_dir(root).map_err(|e| StorageError::io("list retained root names", e))?;
    let mut entries = RootEntries::default();
    let mut count = 0usize;
    for entry in directory {
        observation_checkpoint(progress)?;
        count += 1;
        if count > 3 {
            return Err(StorageError::new(
                "unknown",
                "retained root enumeration exceeds its closed entry set",
            ));
        }
        let entry = entry.map_err(|e| StorageError::io("list retained root name", e))?;
        let name = entry.file_name();
        if name == std::ffi::OsStr::new("owner.json") {
            entries.owner = true;
        } else if name == std::ffi::OsStr::new("lease.json") {
            entries.lease = true;
        } else if name == std::ffi::OsStr::new("game") {
            entries.game = true;
        } else {
            return Err(StorageError::new(
                "unknown",
                "unknown retained root entry is preserved without opening it",
            ));
        }
    }
    observation_checkpoint(progress)?;
    Ok(entries)
}

/// Strict one-attempt measurement: disappearing entries fail, and even an
/// internal link is rejected. Files are opened only for no-follow metadata;
/// game bytes, unknown root contents, and secret-named contents are never read.
fn game_tree_bytes(
    root: &Path,
    progress: &mut dyn FnMut() -> Result<(), String>,
) -> Result<u64, StorageError> {
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    let mut entries = 0usize;
    let mut bytes = 0u64;
    while let Some((path, depth)) = pending.pop() {
        observation_checkpoint(progress)?;
        entries += 1;
        if depth > MAX_DEPTH || entries > MAX_ENTRIES {
            return Err(StorageError::new(
                "walk_limit",
                "retained game tree depth or entry limit exceeded",
            ));
        }
        reject_secret_path(&path)?;
        reject_secret_leaf_file(&path)?;
        let parent = path
            .parent()
            .ok_or_else(|| StorageError::new("path", "retained entry has no parent"))?;
        verify_directory(parent)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| measurement_io_error("retained game metadata", &path, root, e))?;
        observation_checkpoint(progress)?;
        if is_link(&metadata) {
            return Err(StorageError::new(
                "link",
                "retained game link or reparse entry is preserved",
            ));
        }
        if metadata.is_dir() {
            verify_directory(&path)?;
            let directory = fs::read_dir(&path)
                .map_err(|e| measurement_io_error("retained game directory", &path, root, e))?;
            observation_checkpoint(progress)?;
            for entry in directory {
                observation_checkpoint(progress)?;
                if pending.len() + entries >= MAX_ENTRIES {
                    return Err(StorageError::new(
                        "walk_limit",
                        "retained game tree entry limit exceeded",
                    ));
                }
                let entry = entry.map_err(|e| {
                    measurement_io_error("retained game enumeration", &path, root, e)
                })?;
                pending.push((entry.path(), depth + 1));
                observation_checkpoint(progress)?;
            }
        } else if metadata.is_file() {
            // Reuse the existing no-follow and single-link handle guard.
            let file = open_record_without_following(&path)?;
            let opened = file
                .metadata()
                .map_err(|e| StorageError::io("inspect retained game file", e))?;
            observation_checkpoint(progress)?;
            verify_directory(parent)?;
            if !opened.is_file() || is_link(&opened) {
                return Err(StorageError::new(
                    "file_type",
                    "retained game entry changed file type",
                ));
            }
            bytes = checked_sum(bytes, opened.len())?;
        } else {
            return Err(special_entry_error(
                "retained game measurement",
                &path,
                root,
                &metadata,
            ));
        }
    }
    observation_checkpoint(progress)?;
    Ok(bytes)
}

struct DirectoryAnchor {
    file: File,
    identity: DirectoryIdentity,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    file: u64,
}
impl DirectoryAnchor {
    fn open(path: &Path) -> Result<Self, StorageError> {
        verify_directory(path)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            };
            options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options
            .open(path)
            .map_err(|e| StorageError::io("anchor retained directory", e))?;
        let metadata = file
            .metadata()
            .map_err(|e| StorageError::io("inspect retained directory handle", e))?;
        if !metadata.is_dir() || is_link(&metadata) {
            return Err(StorageError::new(
                "link",
                "retained directory handle is not ordinary",
            ));
        }
        let identity = directory_identity(&file)?;
        Ok(Self { file, identity })
    }
    fn verify(&self, path: &Path) -> Result<(), StorageError> {
        if directory_identity(&self.file)? != self.identity
            || Self::open(path)?.identity != self.identity
        {
            return Err(StorageError::new(
                "ownership",
                "retained directory physical identity changed",
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn directory_identity(file: &File) -> Result<DirectoryIdentity, StorageError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file
        .metadata()
        .map_err(|e| StorageError::io("inspect retained directory identity", e))?;
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        file: metadata.ino(),
    })
}
#[cfg(windows)]
fn directory_identity(file: &File) -> Result<DirectoryIdentity, StorageError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    // SAFETY: the owned directory handle outlives this synchronous native query.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(StorageError::io(
            "inspect retained directory identity",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(DirectoryIdentity {
        device: information.dwVolumeSerialNumber.into(),
        file: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    })
}
#[cfg(not(any(unix, windows)))]
fn directory_identity(_file: &File) -> Result<DirectoryIdentity, StorageError> {
    Err(StorageError::new(
        "unsupported",
        "retained directory identity is unavailable",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // storage::tests::Fixture is private to its sibling module. This small
    // fixture uses the same owned scratch convention without changing that API.
    struct Fixture {
        root: PathBuf,
        checkout: PathBuf,
        config: StorageConfig,
    }
    impl Fixture {
        fn new() -> Self {
            let temp = fs::canonicalize(std::env::temp_dir()).unwrap();
            let root = temp.join(format!("mmmm-retained-test-{}", new_token()));
            fs::create_dir(&root).unwrap();
            let checkout = root.join("checkout");
            fs::create_dir(&checkout).unwrap();
            Self {
                config: StorageConfig {
                    output_root: Some(root.join("output")),
                    evidence_root: root.join("evidence"),
                    purpose: "retained-game-test".into(),
                    budgets: Budgets::default(),
                },
                root,
                checkout,
            }
        }
        fn build(&self) -> ManagedBuild {
            ManagedBuild::acquire(self.config.clone(), &self.checkout).unwrap()
        }
        fn game_root(&self) -> PathBuf {
            self.root.join("retained")
        }
        fn acquire<'a>(&self, build: &'a ManagedBuild) -> RetainedGame<'a> {
            RetainedGame::acquire(build, &self.checkout, &self.game_root(), &mut || Ok(())).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
            if let Ok(physical) = fs::canonicalize(&self.root)
                && physical.parent() == Some(parent.as_path())
                && reject_link(&self.root).is_ok()
            {
                fs::remove_dir_all(&self.root).expect("remove solely authored retained fixture");
            }
        }
    }
    fn outcome(exit: i32) -> FinishOutcome {
        FinishOutcome {
            command_exit: Some(exit),
            supervisor_errors: Vec::new(),
            drained: true,
            evidence_exported: true,
        }
    }
    fn kind<T>(result: Result<T, StorageError>) -> &'static str {
        match result {
            Err(error) => error.kind,
            Ok(_) => panic!("expected retained failure"),
        }
    }

    #[test]
    fn failed_command_can_complete_and_reuse_only_its_retained_game_without_disclosure() {
        let fixture = Fixture::new();
        let build = fixture.build();
        let retained = fixture.acquire(&build);
        let world = retained.game_directory().unwrap().join("world");
        fs::create_dir(&world).unwrap();
        fs::write(world.join("region.data"), b"retained world bytes").unwrap();
        let debug = format!("{retained:?}");
        assert!(!debug.contains(&retained.root.to_string_lossy().to_string()));
        assert!(!debug.contains(&build.lease.token));
        let completed = retained.complete(&outcome(17), &mut || Ok(())).unwrap();
        assert!(completed.lease_released && completed.game_retained);
        let receipt = serde_json::to_string(&completed).unwrap();
        assert!(!receipt.contains(&build.lease.token));
        assert!(!receipt.contains(&fixture.game_root().to_string_lossy().to_string()));
        assert_eq!(
            fs::read(world.join("region.data")).unwrap(),
            b"retained world bytes"
        );
        assert!(!fixture.game_root().join("lease.json").exists());
        build.finish(outcome(17)).unwrap();

        let build = fixture.build();
        let retained = fixture.acquire(&build);
        assert_eq!(
            retained
                .measure_with_progress(&mut || Ok(()))
                .unwrap()
                .game_bytes,
            20
        );
        retained.complete(&outcome(0), &mut || Ok(())).unwrap();
        build.finish(outcome(0)).unwrap();
        assert_eq!(
            fs::read(world.join("region.data")).unwrap(),
            b"retained world bytes"
        );
    }

    #[test]
    fn drop_and_unknown_lease_never_release_or_adopt_the_retained_root() {
        let fixture = Fixture::new();
        let build = fixture.build();
        let retained = fixture.acquire(&build);
        let lease = fs::read(fixture.game_root().join("lease.json")).unwrap();
        drop(retained);
        assert_eq!(
            fs::read(fixture.game_root().join("lease.json")).unwrap(),
            lease
        );
        assert_eq!(
            kind(RetainedGame::acquire(
                &build,
                &fixture.checkout,
                &fixture.game_root(),
                &mut || Ok(())
            )),
            "busy"
        );
        fs::write(
            fixture.game_root().join("lease.json"),
            b"unrecognized lease; preserve",
        )
        .unwrap();
        assert_eq!(
            kind(RetainedGame::acquire(
                &build,
                &fixture.checkout,
                &fixture.game_root(),
                &mut || Ok(())
            )),
            "busy"
        );
        assert_eq!(
            fs::read(fixture.game_root().join("lease.json")).unwrap(),
            b"unrecognized lease; preserve"
        );
    }

    #[test]
    fn cancellation_after_exclusive_lease_and_later_lease_replacement_are_preserved() {
        let fixture = Fixture::new();
        let build = fixture.build();
        let lease_path = fixture.game_root().join("lease.json");
        let error =
            RetainedGame::acquire(&build, &fixture.checkout, &fixture.game_root(), &mut || {
                if lease_path.exists() {
                    Err("cancel after exclusive retained lease".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(error.kind, "observation_failed");
        let lease: LeaseRecord = read_record(&lease_path).unwrap();
        assert_eq!(lease.catalog_id, build.lease.catalog_id);
        assert_eq!(lease.slot_id, build.lease.slot_id);
        assert_eq!(lease.token, build.lease.token);
        assert!(!fixture.game_root().join("owner.json").exists());
        assert_eq!(
            kind(RetainedGame::acquire(
                &build,
                &fixture.checkout,
                &fixture.game_root(),
                &mut || Ok(())
            )),
            "busy"
        );

        let other = fixture.root.join("other-retained");
        let retained =
            RetainedGame::acquire(&build, &fixture.checkout, &other, &mut || Ok(())).unwrap();
        let replaced = b"different current retained lease";
        fs::write(other.join("lease.json"), replaced).unwrap();
        assert_eq!(kind(retained.game_directory()), "ownership");
        assert_eq!(
            kind(retained.complete(&outcome(0), &mut || Ok(()))),
            "ownership"
        );
        assert_eq!(fs::read(other.join("lease.json")).unwrap(), replaced);
        assert!(other.join("game").is_dir());
    }

    #[test]
    fn missing_drain_or_export_preserves_exact_lease_owner_and_game() {
        for (drained, exported) in [(false, true), (true, false)] {
            let fixture = Fixture::new();
            let build = fixture.build();
            let retained = fixture.acquire(&build);
            fs::write(
                retained.game_directory().unwrap().join("server.properties"),
                b"authored config",
            )
            .unwrap();
            let owner = fs::read(fixture.game_root().join("owner.json")).unwrap();
            let lease = fs::read(fixture.game_root().join("lease.json")).unwrap();
            let mut finish = outcome(1);
            finish.drained = drained;
            finish.evidence_exported = exported;
            assert_eq!(
                kind(retained.complete(&finish, &mut || Ok(()))),
                if drained { "evidence" } else { "undrained" }
            );
            assert_eq!(
                fs::read(fixture.game_root().join("owner.json")).unwrap(),
                owner
            );
            assert_eq!(
                fs::read(fixture.game_root().join("lease.json")).unwrap(),
                lease
            );
            assert_eq!(
                fs::read(fixture.game_root().join("game/server.properties")).unwrap(),
                b"authored config"
            );
        }
    }

    #[test]
    fn existing_empty_product_and_unknown_roots_are_not_initialized() {
        let fixture = Fixture::new();
        let build = fixture.build();
        fs::create_dir(fixture.game_root()).unwrap();
        assert_eq!(
            kind(RetainedGame::acquire(
                &build,
                &fixture.checkout,
                &fixture.game_root(),
                &mut || Ok(())
            )),
            "ownership"
        );
        assert!(!fixture.game_root().join("owner.json").exists());
        fs::write(
            fixture.game_root().join("product.sqlite"),
            b"do not adopt product bytes",
        )
        .unwrap();
        assert_eq!(
            kind(RetainedGame::acquire(
                &build,
                &fixture.checkout,
                &fixture.game_root(),
                &mut || Ok(())
            )),
            "unknown"
        );
        assert_eq!(
            fs::read(fixture.game_root().join("product.sqlite")).unwrap(),
            b"do not adopt product bytes"
        );
        assert!(!fixture.game_root().join("lease.json").exists());
    }

    #[test]
    fn checkout_attestation_overlap_and_secret_roots_fail_before_creation() {
        let fixture = Fixture::new();
        let build = fixture.build();
        let other = fixture.root.join("other-checkout");
        fs::create_dir(&other).unwrap();
        assert_eq!(
            kind(RetainedGame::acquire(
                &build,
                &other,
                &fixture.game_root(),
                &mut || Ok(())
            )),
            "ownership"
        );
        for root in [
            fixture.checkout.join("retained"),
            build.paths.catalog.join("retained"),
            fixture.config.evidence_root.join("retained"),
        ] {
            assert_eq!(
                kind(RetainedGame::acquire(
                    &build,
                    &fixture.checkout,
                    &root,
                    &mut || Ok(())
                )),
                "overlap"
            );
            assert!(!root.exists());
        }
        let secret_named = fixture.root.join(".env");
        assert_eq!(
            kind(RetainedGame::acquire(
                &build,
                &fixture.checkout,
                &secret_named,
                &mut || Ok(())
            )),
            "secret_path"
        );
        assert!(!secret_named.exists());
        assert!(!fixture.game_root().exists());
    }

    #[test]
    fn reuse_rejects_incomplete_foreign_and_extended_owner_records() {
        let fixture = Fixture::new();
        let build = fixture.build();
        fixture
            .acquire(&build)
            .complete(&outcome(0), &mut || Ok(()))
            .unwrap();
        let owner_path = fixture.game_root().join("owner.json");
        let bytes = fs::read(&owner_path).unwrap();
        let original: Owner = serde_json::from_slice(&bytes).unwrap();
        for change in 0..4 {
            let mut owner = original.clone();
            match change {
                0 => {
                    owner.state = SlotState::Active;
                    owner.completed_ms = None;
                }
                1 => owner.checkout_digest = "0".repeat(64),
                2 => owner.purpose = "another-purpose".into(),
                _ => owner.root_digest = "0".repeat(64),
            }
            fs::write(&owner_path, record_bytes(&owner).unwrap()).unwrap();
            assert_eq!(
                kind(RetainedGame::acquire(
                    &build,
                    &fixture.checkout,
                    &fixture.game_root(),
                    &mut || Ok(())
                )),
                "ownership"
            );
            assert!(!fixture.game_root().join("lease.json").exists());
        }
        let mut extended: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        extended["unrecognized"] = true.into();
        fs::write(&owner_path, serde_json::to_vec(&extended).unwrap()).unwrap();
        assert_eq!(
            kind(RetainedGame::acquire(
                &build,
                &fixture.checkout,
                &fixture.game_root(),
                &mut || Ok(())
            )),
            "record"
        );
        assert!(!fixture.game_root().join("lease.json").exists());
    }

    #[test]
    fn replaced_root_with_copied_records_cannot_use_a_held_directory_identity() {
        let fixture = Fixture::new();
        let build = fixture.build();
        let retained = fixture.acquire(&build);
        fs::write(
            retained.game_directory().unwrap().join("world.data"),
            b"preserved original",
        )
        .unwrap();
        let moved = fixture.root.join("moved-retained");
        #[cfg(windows)]
        let original_owner = fs::read(fixture.game_root().join("owner.json")).unwrap();
        #[cfg(windows)]
        let original_lease = fs::read(fixture.game_root().join("lease.json")).unwrap();
        if let Err(error) = fs::rename(fixture.game_root(), &moved) {
            #[cfg(windows)]
            {
                // Held directory handles can prevent the replacement itself.
                // This is an observed native boundary, not a skipped assertion.
                assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                assert_eq!(error.raw_os_error(), Some(5));
                assert!(!moved.exists());
                retained.check_current_ownership().unwrap();
                assert!(
                    fs::read(fixture.game_root().join("owner.json")).unwrap() == original_owner,
                    "retained owner changed after native rename refusal"
                );
                assert!(
                    fs::read(fixture.game_root().join("lease.json")).unwrap() == original_lease,
                    "retained lease changed after native rename refusal"
                );
                assert_eq!(
                    fs::read(retained.game_directory().unwrap().join("world.data")).unwrap(),
                    b"preserved original"
                );
                return;
            }
            #[cfg(not(windows))]
            panic!(
                "retained root rename failed: kind={:?}, os={:?}",
                error.kind(),
                error.raw_os_error()
            );
        }
        fs::create_dir(fixture.game_root()).unwrap();
        fs::create_dir(fixture.game_root().join("game")).unwrap();
        for name in ["owner.json", "lease.json"] {
            fs::copy(moved.join(name), fixture.game_root().join(name)).unwrap();
        }
        assert_eq!(kind(retained.game_directory()), "ownership");
        assert_eq!(
            kind(retained.complete(&outcome(0), &mut || Ok(()))),
            "ownership"
        );
        assert_eq!(
            fs::read(moved.join("game/world.data")).unwrap(),
            b"preserved original"
        );
        assert!(moved.join("lease.json").exists());
        assert!(fixture.game_root().join("lease.json").exists());
    }

    #[test]
    fn bare_secret_selectors_fail_before_missing_parent_or_leaf_metadata() {
        let fixture = Fixture::new();
        let missing_parent = fixture.root.join("not-created");
        for selector in ["credentials", "api-key", "private-key"] {
            // No secret-named file is created, opened, read, or statted: both
            // lexical guards must stop before even this missing parent's I/O.
            let selected = missing_parent.join(selector);
            assert_eq!(
                kind(game_tree_bytes(&selected, &mut || Ok(()))),
                "secret_path"
            );
        }
    }

    #[test]
    fn combined_budget_counts_actual_game_and_records_without_eviction() {
        let fixture = Fixture::new();
        let mut build = fixture.build();
        let base = build.measure().unwrap();
        build.config.budgets.slot_bytes = checked_sum(base.slot_bytes, 4096).unwrap();
        build.config.budgets.catalog_bytes = checked_sum(base.catalog_bytes, 4096).unwrap();
        let retained = fixture.acquire(&build);
        fs::write(
            retained.game_directory().unwrap().join("world.data"),
            [7; 8192],
        )
        .unwrap();
        let observed = retained.measure_with_progress(&mut || Ok(())).unwrap();
        assert_eq!(observed.game_bytes, 8192);
        assert!(observed.retained_bytes > observed.game_bytes);
        assert_eq!(
            observed.combined_slot_bytes - observed.build_slot_bytes,
            observed.retained_bytes
        );
        assert_eq!(
            observed.combined_catalog_bytes - observed.build_catalog_bytes,
            observed.retained_bytes
        );
        assert!(!observed.within_budget);
        assert_eq!(
            fs::metadata(retained.game_directory().unwrap().join("world.data"))
                .unwrap()
                .len(),
            8192
        );
        assert!(fixture.game_root().join("lease.json").exists());
        let completed = retained.complete(&outcome(1), &mut || Ok(())).unwrap();
        assert!(!completed.observed_before_release.within_budget);
        assert_eq!(
            fs::metadata(fixture.game_root().join("game/world.data"))
                .unwrap()
                .len(),
            8192
        );
    }

    #[test]
    fn checkpoint_cancellation_and_changed_owner_keep_both_causes_and_the_lease() {
        let fixture = Fixture::new();
        let build = fixture.build();
        assert_eq!(
            kind(RetainedGame::acquire(
                &build,
                &fixture.checkout,
                &fixture.game_root(),
                &mut || Err("cancel before admission".into())
            )),
            "observation_failed"
        );
        assert!(!fixture.game_root().exists());
        let retained = fixture.acquire(&build);
        let lease = fs::read(fixture.game_root().join("lease.json")).unwrap();
        let mut calls = 0;
        let error = retained
            .measure_with_progress(&mut || {
                calls += 1;
                if calls == 20 {
                    fs::write(
                        fixture.game_root().join("owner.json"),
                        b"changed during observation",
                    )
                    .unwrap();
                    return Err("cancel current observation".into());
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.kind, "observation_failed");
        assert_eq!(error.message, "cancel current observation");
        let postcheck = std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<StorageError>()
            .unwrap();
        assert_eq!(postcheck.kind, "ownership");
        assert_eq!(
            fs::read(fixture.game_root().join("lease.json")).unwrap(),
            lease
        );
        assert!(fixture.game_root().join("game").is_dir());
    }

    #[test]
    fn deep_game_and_multiply_linked_files_fail_without_removing_content() {
        let fixture = Fixture::new();
        let build = fixture.build();
        let retained = fixture.acquire(&build);
        let source = fixture.root.join("authored-source.data");
        fs::write(&source, b"authored file").unwrap();
        let linked = retained.game_directory().unwrap().join("linked.data");
        fs::hard_link(&source, &linked).unwrap();
        assert_eq!(kind(retained.measure_with_progress(&mut || Ok(()))), "link");
        assert_eq!(fs::read(&source).unwrap(), b"authored file");
        fs::remove_file(linked).unwrap();
        let mut deep = retained.game_directory().unwrap().to_path_buf();
        for _ in 0..=MAX_DEPTH {
            deep.push("d");
            fs::create_dir(&deep).unwrap();
        }
        assert_eq!(
            kind(retained.measure_with_progress(&mut || Ok(()))),
            "walk_limit"
        );
        assert!(deep.is_dir());
        assert!(fixture.game_root().join("lease.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn even_internal_game_symlinks_are_rejected_and_targets_are_preserved() {
        let fixture = Fixture::new();
        let build = fixture.build();
        let retained = fixture.acquire(&build);
        let target = retained.game_directory().unwrap().join("world.data");
        fs::write(&target, b"original").unwrap();
        let link = retained.game_directory().unwrap().join("alias.data");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(kind(retained.measure_with_progress(&mut || Ok(()))), "link");
        assert_eq!(kind(retained.complete(&outcome(0), &mut || Ok(()))), "link");
        assert_eq!(fs::read(&target).unwrap(), b"original");
        assert!(fixture.game_root().join("lease.json").exists());
        fs::remove_file(link).unwrap();
    }
}

//! Actual native-owner Project/SQLite and ordinary selected-file fixtures are
//! needed to verify protected persistence and retained post-commit failures.
//! The small JAR bytes do not claim Java execution or a real game observation.

use super::*;
use crate::{
    local_setup::{
        LocalHostSetup, LocalSetupError, finish_read_policy_setup_for_test,
        register_local_host_setup, register_local_host_setup_with_calibration_scope,
        register_local_host_setup_with_read_policy,
    },
    setup::{PublicHostSetup, SetupError},
};
use mmmm_contracts::{ProjectId, Sha256Digest, TargetProfileId, projected_digest};
use mmmm_runtime::storage::StoreConfig;
use serde_json::json;
use std::{
    cell::Cell,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const MARKER: &[u8] = b"mmmm-host-read-policy-fixture-v1\n";
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let parent = fs::canonicalize(
            std::env::var_os("MMMM_TEST_DATA_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir),
        )
        .unwrap();
        let path = parent.join(format!(
            "mmmm-host-read-policy-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let checkout =
            fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        assert!(path.is_absolute() && !path.starts_with(checkout) && !path.exists());
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(path.join("fixture-owner.txt"), MARKER).unwrap();
        fs::write(
            path.join("selected-host.jar"),
            b"ordinary bounded host artifact fixture\n",
        )
        .unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
    fn config(&self) -> StoreConfig {
        StoreConfig::new(self.0.clone())
    }
    fn open(&self) -> DurableStore {
        DurableStore::open(self.config()).unwrap()
    }
    fn project(&self) -> ProjectId {
        crate::native_project::create_native_project(
            &mut self.open(),
            "Explicit host read policy fixture",
            &TargetProfileId::new("target-unverified").unwrap(),
            deadline(),
        )
        .unwrap()
        .project_id
    }
    fn scope(project: &ProjectId) -> Value {
        json!({"projectId":project,"resourceIds":[],"objectIds":[],"regions":[],"externalTargetIds":[]})
    }
    fn selected_setup(
        &self,
        project: &ProjectId,
        policy: Option<&HostReadPolicy>,
    ) -> Result<
        (PublicHostSetup, Option<HostReadPolicyRecord>),
        crate::local_setup::LocalReadPolicySetupError,
    > {
        let executable = std::env::current_exe().unwrap();
        let jar = self.0.join("selected-host.jar");
        let destination = self.0.join("mmmm-host.json");
        let request = LocalHostSetup {
            executable: &executable,
            installed_host_jar: &jar,
            destination: &destination,
            project: project.clone(),
            scope: Self::scope(project),
        };
        if let Some(policy) = policy {
            register_local_host_setup_with_read_policy(self.config(), request, policy, deadline())
                .map(|(setup, record)| (setup, Some(record)))
        } else {
            // The old API intentionally remains unchanged; its errors are not
            // used by this successful compatibility fixture.
            Ok((
                register_local_host_setup(self.config(), request).unwrap(),
                None,
            ))
        }
    }
    fn calibration_setup(
        &self,
        project: &ProjectId,
        revision: &Sha256Digest,
        scope: Value,
        policy: Option<&HostReadPolicy>,
        deadline: Instant,
    ) -> Result<
        (PublicHostSetup, Option<HostReadPolicyRecord>, Sha256Digest),
        crate::local_setup::LocalReadPolicySetupError,
    > {
        let executable = std::env::current_exe().unwrap();
        let jar = self.0.join("selected-host.jar");
        let destination = self.0.join("mmmm-host.json");
        register_local_host_setup_with_calibration_scope(
            self.config(),
            LocalHostSetup {
                executable: &executable,
                installed_host_jar: &jar,
                destination: &destination,
                project: project.clone(),
                scope,
            },
            revision,
            policy,
            deadline,
        )
    }
}
fn plain_tree(path: &Path, root: &Path, count: &mut usize) -> bool {
    *count += 1;
    if *count > 128 || !path.starts_with(root) {
        return false;
    }
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    if metadata.file_type().is_symlink() {
        return false;
    }
    if metadata.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return false;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            if !plain_tree(&entry.path(), root, count) {
                return false;
            }
        }
    }
    metadata.is_dir() || metadata.is_file()
}
impl Drop for Root {
    fn drop(&mut self) {
        if fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0)
            && fs::read(self.0.join("fixture-owner.txt")).ok().as_deref() == Some(MARKER)
            && plain_tree(&self.0, &self.0, &mut 0)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(15)
}
fn policy() -> HostReadPolicy {
    selected_host_read_policy(&["survival".to_owned(), "adventure".to_owned()], true).unwrap()
}

// This test adapter still captures the actual kernel owner and requires the
// same Store/native Project registration. It is not a fabricated pairing.
struct NativeRead<'a> {
    store: &'a DurableStore,
    owner: NativeOwnerWitness,
}
impl HostSetupRpcContext for NativeRead<'_> {
    fn check(&self) -> StorageResult<()> {
        self.owner.check_store(self.store)
    }
    fn authenticated_local_owner(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.owner.principal().clone())
    }
}
struct NativeReadAuthority<'a, 'b>(&'a NativeRead<'b>);
impl HostSetupAuthority for NativeReadAuthority<'_, '_> {
    fn authorize_registration(
        &mut self,
        _: &DurableStore,
        _: &PrincipalId,
        _: &HostSetupRegistration,
    ) -> StorageResult<()> {
        Err(denied())
    }
    fn authorize_read(
        &mut self,
        store: &DurableStore,
        owner: &PrincipalId,
        setup: &HostSetupRecord,
    ) -> StorageResult<()> {
        self.0.check()?;
        if !std::ptr::eq(store, self.0.store)
            || owner != self.0.owner.principal()
            || self.0.owner.check_project(store, &setup.project_id)? != *owner
        {
            return Err(denied());
        }
        Ok(())
    }
    fn authorize_read_policy_read(
        &mut self,
        store: &DurableStore,
        owner: &PrincipalId,
        setup: &HostSetupRecord,
        _: &HostReadPolicyRecord,
    ) -> StorageResult<()> {
        self.authorize_read(store, owner, setup)
    }
}
fn retained(store: &DurableStore, setup: &PublicHostSetup) -> StorageResult<HostReadPolicyRecord> {
    let reader = NativeRead {
        store,
        owner: NativeOwnerWitness::capture(store, deadline()).unwrap(),
    };
    host_read_policy(
        store,
        &reader,
        &mut NativeReadAuthority(&reader),
        &setup.project_id,
        &setup.host_artifact_digest,
        &serde_json::from_value(setup.scope.clone()).unwrap(),
    )
}

#[test]
fn legacy_public_setup_stays_usable_and_first_explicit_policy_survives_existing_config() {
    let root = Root::new();
    let project = root.project();
    let (setup, no_policy) = root.selected_setup(&project, None).unwrap();
    assert!(no_policy.is_none());
    assert!(matches!(
        retained(&root.open(), &setup),
        Err(StorageError::NotFound(_))
    ));
    let before = fs::read(root.0.join("mmmm-host.json")).unwrap();
    let error = root.selected_setup(&project, Some(&policy())).unwrap_err();
    assert!(matches!(
        error.failure,
        LocalSetupError::PublicConfigNotWritten
    ));
    let record = error.retained_policy.as_ref().unwrap();
    assert_eq!(retained(&root.open(), &setup).unwrap(), **record);
    assert_eq!(fs::read(root.0.join("mmmm-host.json")).unwrap(), before);
    assert!(error.to_string().contains(record.policy_digest().as_str()));
    assert!(
        std::error::Error::source(&error)
            .unwrap()
            .is::<SetupError>()
    );
    let config: Value = mmmm_contracts::parse_json(&before).unwrap();
    let expected = [
        "executable",
        "executableSha256",
        "dataRoot",
        "projectId",
        "scope",
        "hostArtifactDigest",
    ];
    assert_eq!(config.as_object().unwrap().len(), expected.len());
    for field in expected {
        assert!(config.get(field).is_some());
    }
}

#[test]
fn explicit_policy_rejects_same_identity_changes_and_busy_store_without_replacement() {
    let root = Root::new();
    let project = root.project();
    let (setup, record) = root.selected_setup(&project, Some(&policy())).unwrap();
    let record = record.unwrap();
    let selected = fs::read(root.0.join("selected-host.jar")).unwrap();
    let changed = selected_host_read_policy(&["creative".to_owned()], false).unwrap();
    let error = root.selected_setup(&project, Some(&changed)).unwrap_err();
    assert!(error.retained_policy.is_none());
    assert!(matches!(
        std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<StorageError>(),
        Some(StorageError::Conflict(_))
    ));
    assert_eq!(retained(&root.open(), &setup).unwrap(), record);
    let held = root.open();
    let error = root.selected_setup(&project, Some(&policy())).unwrap_err();
    assert!(matches!(error.failure, LocalSetupError::Busy));
    assert!(error.retained_policy.is_none());
    drop(held);
    assert_eq!(
        fs::read(root.0.join("selected-host.jar")).unwrap(),
        selected
    );
}

#[test]
fn confirmed_policy_survives_original_deadline_and_final_owner_checkpoint_failures() {
    let root = Root::new();
    let project = root.project();
    let (setup, record) = root.selected_setup(&project, Some(&policy())).unwrap();
    let record = record.unwrap();
    let first = finish_read_policy_setup_for_test(
        &setup,
        &record,
        || Err(LocalSetupError::Deadline),
        || panic!("Expired budget must not write public config"),
    )
    .unwrap_err();
    assert_eq!(first.retained_policy.as_deref(), Some(&record));
    let calls = Cell::new(0);
    let last = finish_read_policy_setup_for_test(
        &setup,
        &record,
        || {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                Err(LocalSetupError::OwnerUnavailable)
            } else {
                Ok(())
            }
        },
        || Ok(()),
    )
    .unwrap_err();
    assert_eq!(last.retained_policy.as_deref(), Some(&record));
    assert_eq!(retained(&root.open(), &setup).unwrap(), record);
}

#[test]
fn canonical_project_without_actual_native_registration_cannot_approve_policy() {
    let root = Root::new();
    let value =
        mmmm_contracts::parse_json(include_bytes!("../../../examples/project.json")).unwrap();
    root.open().save_project(&value, None).unwrap();
    let project = ProjectId::new(value["projectId"].as_str().unwrap()).unwrap();
    let error = root.selected_setup(&project, Some(&policy())).unwrap_err();
    assert!(error.retained_policy.is_none());
    assert!(matches!(
        std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<StorageError>(),
        Some(StorageError::NotFound("Native Project owner registration"))
    ));
    assert!(!root.0.join("mmmm-host.json").exists());
    let revision = projected_digest("Project", &value).unwrap();
    let error = root
        .calibration_setup(&project, &revision, Root::scope(&project), None, deadline())
        .unwrap_err();
    assert!(error.retained_setup.is_none() && error.retained_policy.is_none());
    assert!(matches!(
        std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<StorageError>(),
        Some(StorageError::NotFound("Native Project owner registration"))
    ));
    assert!(!root.0.join("mmmm-host.json").exists());
}

#[test]
fn explicit_calibration_scope_registers_only_canonical_targets_and_checks_original_project_head() {
    let root = Root::new();
    let project = root.project();
    let original_project = root.open().project(&project).unwrap();
    let revision = projected_digest("Project", &original_project).unwrap();
    let mut base = Root::scope(&project);
    base["resourceIds"] = json!(["resource-explicit-existing"]);
    let mut expected_scope = base.clone();
    expected_scope["externalTargetIds"] =
        json!(crate::calibration_bootstrap::normative_bootstrap_target_ids().unwrap());
    let (setup, no_policy, scope_digest) = root
        .calibration_setup(&project, &revision, base.clone(), None, deadline())
        .unwrap();
    assert!(no_policy.is_none());
    assert_eq!(setup.scope, expected_scope);
    assert_eq!(
        scope_digest,
        mmmm_contracts::canonical_digest(&expected_scope).unwrap()
    );
    assert_eq!(
        setup.scope["externalTargetIds"].as_array().unwrap().len(),
        95
    );
    assert!(matches!(
        retained(&root.open(), &setup),
        Err(StorageError::NotFound(_))
    ));
    let before = fs::read(root.0.join("mmmm-host.json")).unwrap();
    let repeated = root
        .calibration_setup(&project, &revision, base.clone(), None, deadline())
        .unwrap_err();
    assert!(matches!(
        repeated.failure,
        LocalSetupError::PublicConfigNotWritten
    ));
    assert_eq!(
        repeated.retained_setup.as_ref().unwrap().scope,
        expected_scope
    );
    assert!(repeated.retained_policy.is_none());
    assert!(
        std::error::Error::source(&repeated)
            .unwrap()
            .is::<SetupError>()
    );
    assert_eq!(fs::read(root.0.join("mmmm-host.json")).unwrap(), before);
    let mut advanced = original_project;
    advanced["name"] = json!("Advanced explicit host setup fixture");
    advanced["revision"] = json!(projected_digest("Project", &advanced).unwrap());
    root.open()
        .save_project(&advanced, Some(&revision))
        .unwrap();
    let stale = root
        .calibration_setup(&project, &revision, base.clone(), None, deadline())
        .unwrap_err();
    assert!(stale.retained_setup.is_none() && stale.retained_policy.is_none());
    assert!(matches!(
        std::error::Error::source(&stale)
            .unwrap()
            .downcast_ref::<StorageError>(),
        Some(StorageError::Conflict(
            "Explicit calibration host setup Project revision"
        ))
    ));
    assert_eq!(fs::read(root.0.join("mmmm-host.json")).unwrap(), before);
    let current = projected_digest("Project", &advanced).unwrap();
    let expired = root
        .calibration_setup(&project, &current, base, None, Instant::now())
        .unwrap_err();
    assert!(matches!(expired.failure, LocalSetupError::Deadline));
    assert!(expired.retained_setup.is_none() && expired.retained_policy.is_none());

    let legacy = Root::new();
    let project = legacy.project();
    let revision = projected_digest("Project", &legacy.open().project(&project).unwrap()).unwrap();
    let (old_setup, _) = legacy.selected_setup(&project, None).unwrap();
    let before = fs::read(legacy.0.join("mmmm-host.json")).unwrap();
    let conflict = legacy
        .calibration_setup(&project, &revision, Root::scope(&project), None, deadline())
        .unwrap_err();
    assert!(matches!(
        conflict.failure,
        LocalSetupError::ReadPolicyConflict
    ));
    assert!(conflict.retained_setup.is_none() && conflict.retained_policy.is_none());
    assert_eq!(old_setup.scope["externalTargetIds"], json!([]));
    assert_eq!(fs::read(legacy.0.join("mmmm-host.json")).unwrap(), before);

    let selected = Root::new();
    let project = selected.project();
    let revision =
        projected_digest("Project", &selected.open().project(&project).unwrap()).unwrap();
    let (setup, record, scope_digest) = selected
        .calibration_setup(
            &project,
            &revision,
            Root::scope(&project),
            Some(&policy()),
            deadline(),
        )
        .unwrap();
    let record = record.unwrap();
    assert_eq!(record.approved_scope_digest(), &scope_digest);
    assert_eq!(retained(&selected.open(), &setup).unwrap(), record);
    assert_eq!(record.policy(), &policy());
}

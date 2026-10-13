//! Actual temporary SQLite fixtures prove registration rollback/restart and
//! finite Offer containment, not a deployed or authenticated real game host.

use super::*;
use crate::storage::{RegionScope, StoreConfig};
use mmmm_contracts::{ContextId, ObjectId, ResourceId, WorldId, parse_json};
use std::{
    cell::Cell,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = parent.join(format!(
            "mmmm-host-setup-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(path.is_absolute());
        assert!(!path.starts_with(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(path.join("test-owner.txt"), b"mmmm-host-setup-test\n").unwrap();
        Self(path)
    }
    fn open(&self) -> DurableStore {
        DurableStore::open(StoreConfig::new(self.0.clone())).unwrap()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        if fs::read(self.0.join("test-owner.txt")).ok().as_deref()
            == Some(b"mmmm-host-setup-test\n")
            && super::super::cas::verify_plain_path(&self.0).is_ok()
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
struct Rpc {
    owner: PrincipalId,
    checks: Cell<usize>,
    cancel_after: Option<usize>,
}
impl Rpc {
    fn new() -> Self {
        Self {
            owner: PrincipalId::new("local-owner-test").unwrap(),
            checks: Cell::new(0),
            cancel_after: None,
        }
    }
}
impl HostSetupRpcContext for Rpc {
    fn check(&self) -> StorageResult<()> {
        let count = self.checks.get() + 1;
        self.checks.set(count);
        if self.cancel_after.is_some_and(|limit| count >= limit) {
            return Err(invalid("Test request cancelled"));
        }
        Ok(())
    }
    fn authenticated_local_owner(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.owner.clone())
    }
}
#[derive(Default)]
struct Authority {
    registration_calls: usize,
    read_calls: usize,
    revoke_registration_at: Option<usize>,
    revoked_read: bool,
}
impl HostSetupAuthority for Authority {
    fn authorize_registration(
        &mut self,
        _: &DurableStore,
        _: &PrincipalId,
        _: &HostSetupRegistration,
    ) -> StorageResult<()> {
        self.registration_calls += 1;
        if self
            .revoke_registration_at
            .is_some_and(|limit| self.registration_calls >= limit)
        {
            return Err(StorageError::Conflict("Test setup approval revoked"));
        }
        Ok(())
    }
    fn authorize_read(
        &mut self,
        _: &DurableStore,
        _: &PrincipalId,
        _: &HostSetupRecord,
    ) -> StorageResult<()> {
        self.read_calls += 1;
        if self.revoked_read {
            return Err(StorageError::Conflict("Test current project ACL revoked"));
        }
        Ok(())
    }
}
fn project(store: &mut DurableStore) -> ProjectId {
    let value = parse_json(
        &fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/project.json"))
            .unwrap(),
    )
    .unwrap();
    store.save_project(&value, None).unwrap();
    ProjectId::new("project-fixture").unwrap()
}
fn scope(project: &ProjectId) -> WriteScope {
    WriteScope {
        project_id: project.clone(),
        resource_ids: vec![ResourceId::new("resource-approved").unwrap()],
        object_ids: vec![ObjectId::new("object-approved").unwrap()],
        external_target_ids: vec![],
        regions: vec![RegionScope {
            context_id: ContextId::new("context-fixture-01").unwrap(),
            world_id: WorldId::new("world-fixture-01").unwrap(),
            dimension: "minecraft:overworld".parse().unwrap(),
            min: [0, 0, 0],
            max_exclusive: [10, 10, 10],
        }],
    }
}
fn request(project: &ProjectId) -> HostSetupRegistration {
    HostSetupRegistration {
        project_id: project.clone(),
        host_artifact_digest: Sha256Digest::new("a".repeat(64)).unwrap(),
        approved_scope: scope(project),
    }
}

#[test]
fn approved_setup_survives_restart_exactly_and_never_rebinds_scope() {
    let root = Root::new();
    let mut store = root.open();
    let project = project(&mut store);
    let rpc = Rpc::new();
    let mut authority = Authority::default();
    let request = request(&project);
    let record = register_host_setup(&mut store, &rpc, &mut authority, &request).unwrap();
    assert_eq!(
        register_host_setup(&mut store, &rpc, &mut authority, &request).unwrap(),
        record
    );
    let mut changed = request.clone();
    changed.approved_scope.object_ids.clear();
    assert!(register_host_setup(&mut store, &rpc, &mut authority, &changed).is_err());
    drop(store);
    let store = root.open();
    assert_eq!(
        host_setup(
            &store,
            &rpc,
            &mut authority,
            &project,
            &request.host_artifact_digest,
            Some(&request.approved_scope)
        )
        .unwrap(),
        record
    );
    let mut other = Rpc::new();
    other.owner = PrincipalId::new("different-local-owner").unwrap();
    assert!(
        host_setup(
            &store,
            &other,
            &mut authority,
            &project,
            &request.host_artifact_digest,
            None
        )
        .is_err()
    );
    assert!(
        host_setup(
            &store,
            &rpc,
            &mut authority,
            &project,
            &Sha256Digest::new("b".repeat(64)).unwrap(),
            None
        )
        .is_err()
    );
    let encoded = encode(&record).unwrap();
    assert!(!encoded.contains("token"));
    assert!(!encoded.contains("policyRevision"));
    assert!(!encoded.contains("path"));
}

#[test]
fn offer_subset_checks_world_bounds_ids_and_current_acl() {
    let root = Root::new();
    let mut store = root.open();
    let project = project(&mut store);
    let rpc = Rpc::new();
    let mut authority = Authority::default();
    let request = request(&project);
    register_host_setup(&mut store, &rpc, &mut authority, &request).unwrap();
    let mut offered = request.approved_scope.clone();
    offered.regions[0].min = [1, 1, 1];
    offered.regions[0].max_exclusive = [9, 9, 9];
    assert!(
        host_setup(
            &store,
            &rpc,
            &mut authority,
            &project,
            &request.host_artifact_digest,
            Some(&offered)
        )
        .is_ok()
    );
    let mut too_large = offered.clone();
    too_large.regions[0].max_exclusive[0] = 11;
    assert!(
        host_setup(
            &store,
            &rpc,
            &mut authority,
            &project,
            &request.host_artifact_digest,
            Some(&too_large)
        )
        .is_err()
    );
    let mut other_world = offered.clone();
    other_world.regions[0].world_id = WorldId::new("another-world").unwrap();
    assert!(!host_scope_is_subset(&other_world, &request.approved_scope).unwrap());
    let mut added_id = offered.clone();
    added_id
        .resource_ids
        .push(ResourceId::new("unapproved").unwrap());
    assert!(!host_scope_is_subset(&added_id, &request.approved_scope).unwrap());
    authority.revoked_read = true;
    assert!(
        host_setup(
            &store,
            &rpc,
            &mut authority,
            &project,
            &request.host_artifact_digest,
            Some(&offered)
        )
        .is_err()
    );
}

#[test]
fn registration_revocation_and_cancellation_roll_back_before_any_approval() {
    let root = Root::new();
    let mut store = root.open();
    let project = project(&mut store);
    let setup = request(&project);
    let rpc = Rpc::new();
    let mut authority = Authority {
        revoke_registration_at: Some(2),
        ..Authority::default()
    };
    assert!(register_host_setup(&mut store, &rpc, &mut authority, &setup).is_err());
    authority.revoke_registration_at = None;
    assert!(
        host_setup(
            &store,
            &rpc,
            &mut authority,
            &project,
            &setup.host_artifact_digest,
            None
        )
        .is_err()
    );
    let cancelled = Rpc {
        cancel_after: Some(1),
        ..Rpc::new()
    };
    assert!(register_host_setup(&mut store, &cancelled, &mut authority, &setup).is_err());
    let missing = ProjectId::new("project-unregistered").unwrap();
    assert!(register_host_setup(&mut store, &rpc, &mut authority, &request(&missing)).is_err());
    assert!(register_host_setup(&mut store, &rpc, &mut authority, &setup).is_ok());
}

//! Actual temporary SQLite/CAS tests are needed for atomic initial metadata,
//! collision and restart boundaries absent from the static authoring examples.
//! Fixture permits exercise this trusted port; they prove no native OS/game grant.

use super::*;
use crate::storage::{
    StoreConfig,
    project_resources::{
        ProjectResourceAuthority, ProjectResourceProvenance, ProjectResourceQuery,
        ProjectResourceReader, ProjectResourceRequest, ProjectSourceRpcContext,
        RegisteredProjectResource,
    },
};
use mmmm_contracts::{ContextId, canonical_digest, projected_digest};
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
            "mmmm-bootstrap-test-{}-{}",
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
        fs::write(path.join("test-owner.txt"), b"mmmm-bootstrap-test\n").unwrap();
        Self(path)
    }
    fn open(&self) -> DurableStore {
        DurableStore::open(StoreConfig::new(self.0.clone())).unwrap()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        if fs::read(self.0.join("test-owner.txt")).ok().as_deref() == Some(b"mmmm-bootstrap-test\n")
            && super::super::cas::verify_plain_path(&self.0).is_ok()
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

struct Permit {
    root: PathBuf,
    owner: PrincipalId,
    approvals: usize,
    deny_approval: Option<usize>,
    change_owner: bool,
    checks: Cell<usize>,
    stop_check: Option<usize>,
}
impl Permit {
    fn new(root: &Root) -> Self {
        Self {
            root: root.0.clone(),
            owner: PrincipalId::new("native-owner-fixture").unwrap(),
            approvals: 0,
            deny_approval: None,
            change_owner: false,
            checks: Cell::new(0),
            stop_check: None,
        }
    }
}
impl NativeOwnerCreatePermit for Permit {
    fn check(&self, store: &DurableStore) -> StorageResult<()> {
        self.checks.set(self.checks.get() + 1);
        if store.data_root() != self.root
            || self
                .stop_check
                .is_some_and(|limit| self.checks.get() >= limit)
        {
            return Err(StorageError::InvalidTransition(
                "Fixture native create permit expired".into(),
            ));
        }
        Ok(())
    }
    fn authorize_create(
        &mut self,
        store: &DurableStore,
        _: &ProjectBootstrapRequest<'_>,
    ) -> StorageResult<PrincipalId> {
        self.check(store)?;
        self.approvals += 1;
        if self.deny_approval == Some(self.approvals) {
            return Err(StorageError::InvalidTransition(
                "Fixture native create was not authorized".into(),
            ));
        }
        if self.change_owner && self.approvals > 1 {
            return Ok(PrincipalId::new("different-native-owner-fixture").unwrap());
        }
        Ok(self.owner.clone())
    }
}
fn example(name: &str) -> Value {
    parse_json(
        &fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples")
                .join(name),
        )
        .unwrap(),
    )
    .unwrap()
}
fn documents(project_id: &str, policy_id: &str) -> (Value, Value) {
    let mut project = example("project.json");
    project["projectId"] = json!(project_id);
    project["policyResourceId"] = json!(policy_id);
    project["resourceIds"] = json!([policy_id]);
    project["prefabIds"] = json!([]);
    project["instanceIds"] = json!([]);
    project["ownedResources"] = json!([]);
    project["revision"] = json!(projected_digest("Project", &project).unwrap());
    (project, example("policy.json"))
}
fn count(store: &DurableStore, table: &str) -> i64 {
    let exists: i64 = store
        .connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [table],
            |row| row.get(0),
        )
        .unwrap();
    if exists == 0 {
        return 0;
    }
    // Only fixed test-owned table names call this helper.
    store
        .connection
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}
fn metadata_counts(store: &DurableStore) -> Vec<i64> {
    [
        "blobs",
        "blob_refs",
        "documents",
        "project_heads",
        "artifact_resources",
        "project_resource_versions",
        "project_resource_heads",
        "project_resource_provenance",
        "native_project_owners",
        "operations",
        "invocations",
        "events",
    ]
    .into_iter()
    .map(|table| count(store, table))
    .collect()
}

struct OwnerReadRpc {
    principal: PrincipalId,
}
impl ProjectSourceRpcContext for OwnerReadRpc {
    fn check(&self) -> StorageResult<()> {
        Ok(())
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        Ok(self.principal.clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        None
    }
}
struct OwnerReadAuthority;
impl ProjectResourceAuthority for OwnerReadAuthority {
    fn authorize_project_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        current_revision: &Sha256Digest,
    ) -> StorageResult<()> {
        let head: String = store.connection.query_row(
            "SELECT revision FROM project_heads WHERE project_id=?1",
            [project.as_str()],
            |row| row.get(0),
        )?;
        if context.is_some()
            || registered_native_project_owner(store, project)? != *principal
            || head != current_revision.as_str()
        {
            return Err(StorageError::Conflict(
                "Fixture current native owner Project ACL",
            ));
        }
        Ok(())
    }
    fn authorize_resource_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> StorageResult<()> {
        let ProjectResourceProvenance::CurrentProject { project_revision } = &resource.provenance
        else {
            return Err(StorageError::Conflict("Fixture current Policy provenance"));
        };
        self.authorize_project_read(store, principal, context, project, project_revision)?;
        if resource.owner != ResourceOwner::Project(project.clone()) {
            return Err(StorageError::Conflict(
                "Fixture native owner Policy resource ACL",
            ));
        }
        Ok(())
    }
}
fn assert_policy_read(
    store: &DurableStore,
    reader: &mut ProjectResourceReader,
    rpc: &OwnerReadRpc,
    request: &ProjectResourceRequest<'_>,
    receipt: &ProjectBootstrapReceipt,
    policy_bytes: &[u8],
) {
    let read = reader
        .read(store, rpc, request, policy_bytes.len() as u64)
        .unwrap();
    assert_eq!(read.bytes, policy_bytes);
    assert_eq!(read.registered.resource, receipt.policy_resource);
    assert_eq!(read.registered.resource["mediaType"], POLICY_MEDIA_TYPE);
    assert_eq!(
        read.registered.resource["sizeBytes"],
        policy_bytes.len() as u64
    );
    assert_eq!(
        read.registered.blob.digest,
        canonical_digest(&parse_json(policy_bytes).unwrap()).unwrap()
    );
    assert_eq!(read.registered.blob.byte_length, policy_bytes.len() as u64);
    assert_eq!(
        read.registered.owner,
        ResourceOwner::Project(receipt.project_id.clone())
    );
    assert_eq!(
        read.registered.provenance,
        ProjectResourceProvenance::CurrentProject {
            project_revision: receipt.project_revision.clone()
        }
    );
}

#[test]
fn fresh_project_policy_and_native_owner_are_atomic_and_restart_readable() {
    let root = Root::new();
    let mut store = root.open();
    assert!(matches!(
        registered_native_project_owner(&store, &ProjectId::new("bootstrap-project").unwrap()),
        Err(StorageError::NotFound(_))
    ));
    let (project, policy) = documents("bootstrap-project", "bootstrap-policy");
    let request = ProjectBootstrapRequest {
        project: &project,
        policy: &policy,
    };
    let mut permit = Permit::new(&root);
    let receipt = create_project(&mut store, &mut permit, &request).unwrap();
    assert_eq!(permit.approvals, 2);
    assert_eq!(
        receipt.project_revision,
        verify_projected_digest("Project", &project).unwrap()
    );
    assert_eq!(
        receipt.policy_resource["sha256"],
        canonical_digest(&policy).unwrap().as_str()
    );
    assert_eq!(receipt.policy_resource["mediaType"], POLICY_MEDIA_TYPE);
    assert_eq!(store.project(&receipt.project_id).unwrap(), project);
    assert_eq!(
        registered_native_project_owner(&store, &receipt.project_id).unwrap(),
        receipt.owner_principal
    );
    // Exercise the production checked source reader, not just raw CAS access.
    // This fixture owner port proves no actual OS or game capability.
    let policy_bytes = canonical_bytes(&policy).unwrap();
    let rpc = OwnerReadRpc {
        principal: permit.owner.clone(),
    };
    let mut reader =
        ProjectResourceReader::new(Box::new(OwnerReadAuthority), MAX_DOCUMENT_BYTES).unwrap();
    let resource_id: ResourceId =
        serde_json::from_value(receipt.policy_resource["resourceId"].clone()).unwrap();
    let query = ProjectResourceQuery::Current {
        resource_id: resource_id.clone(),
    };
    let resource_request = ProjectResourceRequest {
        project: &receipt.project_id,
        current_project_revision: &receipt.project_revision,
        query: &query,
        expected: Some(&receipt.policy_resource),
    };
    assert_policy_read(
        &store,
        &mut reader,
        &rpc,
        &resource_request,
        &receipt,
        &policy_bytes,
    );
    let before = metadata_counts(&store);
    assert_eq!(before[2..9], [2, 1, 1, 1, 1, 1, 1]);
    assert_eq!(before[9..], [0, 0, 0]);
    drop(store);
    let mut store = root.open();
    assert_eq!(metadata_counts(&store), before);
    assert_eq!(store.project(&receipt.project_id).unwrap(), project);
    assert_eq!(
        registered_native_project_owner(&store, &receipt.project_id).unwrap(),
        receipt.owner_principal
    );
    assert_policy_read(
        &store,
        &mut reader,
        &rpc,
        &resource_request,
        &receipt,
        &policy_bytes,
    );
    let (owner, initial, resource, digest): (String, String, String, String) = store.connection.query_row(
        "SELECT owner_principal,initial_revision,policy_resource_id,policy_digest FROM native_project_owners WHERE project_id=?1",
        [receipt.project_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).unwrap();
    assert_eq!(owner, receipt.owner_principal.as_str());
    assert_eq!(initial, receipt.project_revision.as_str());
    assert_eq!(resource, "bootstrap-policy");
    assert_eq!(digest, canonical_digest(&policy).unwrap().as_str());
    let (raw, length): (String, i64) = store.connection.query_row(
        "SELECT r.blob_digest,r.byte_length FROM artifact_resources r JOIN project_resource_provenance p ON p.resource_id=r.resource_id AND p.digest=r.blob_digest WHERE p.project_id=?1 AND p.project_revision=?2",
        params![receipt.project_id.as_str(),receipt.project_revision.as_str()], |row| Ok((row.get(0)?,row.get(1)?)),
    ).unwrap();
    let blob = BlobRef {
        digest: Sha256Digest::new(raw).unwrap(),
        byte_length: length as u64,
    };
    assert_eq!(
        store.read_blob(&blob).unwrap(),
        canonical_bytes(&policy).unwrap()
    );
    // The immutable version requires its exact shared retention owner key.
    // Other Project/artifact pins still exist and must not grant a fallback.
    let retention_owner = canonical_digest(&json!({
        "projectId":receipt.project_id,
        "resourceId":resource_id,
        "sha256":blob.digest
    }))
    .unwrap();
    assert_eq!(
        store
            .connection
            .execute(
                "DELETE FROM blob_refs WHERE owner_kind='project_resource' AND owner_id=?1 AND digest=?2",
                params![retention_owner.as_str(), blob.digest.as_str()],
            )
            .unwrap(),
        1
    );
    assert!(matches!(
        reader.read(&store, &rpc, &resource_request, policy_bytes.len() as u64),
        Err(StorageError::Corrupt(message))
            if message == "Project resource version retention is missing"
    ));
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    pin_blob(
        &transaction,
        "project_resource",
        retention_owner.as_str(),
        &blob,
    )
    .unwrap();
    transaction.commit().unwrap();
    assert_policy_read(
        &store,
        &mut reader,
        &rpc,
        &resource_request,
        &receipt,
        &policy_bytes,
    );
    let mut repeated = Permit::new(&root);
    assert!(matches!(
        create_project(&mut store, &mut repeated, &request),
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(metadata_counts(&store), before);
}

#[test]
fn final_sql_failure_rolls_back_every_initial_mapping_and_survives_restart() {
    let root = Root::new();
    let mut store = root.open();
    store.connection.execute_batch(BOOTSTRAP_SCHEMA).unwrap();
    store.connection.execute_batch("CREATE TEMP TRIGGER bootstrap_owner_failure BEFORE INSERT ON native_project_owners BEGIN SELECT RAISE(ABORT,'fixture atomic owner failure'); END;").unwrap();
    let before = metadata_counts(&store);
    let (project, policy) = documents("rollback-project", "rollback-policy");
    let request = ProjectBootstrapRequest {
        project: &project,
        policy: &policy,
    };
    assert!(create_project(&mut store, &mut Permit::new(&root), &request).is_err());
    assert_eq!(metadata_counts(&store), before);
    assert!(
        store
            .project(&ProjectId::new("rollback-project").unwrap())
            .is_err()
    );
    drop(store);
    let mut store = root.open();
    assert_eq!(metadata_counts(&store), before);
    create_project(&mut store, &mut Permit::new(&root), &request).unwrap();
    assert_eq!(count(&store, "native_project_owners"), 1);
}

#[test]
fn unauthorized_expired_revoked_or_changed_native_owner_publishes_nothing() {
    for scenario in [
        "admission",
        "revocation",
        "changed-owner",
        "expired",
        "cancel-in-cas",
        "other-store",
    ] {
        let root = Root::new();
        let mut store = root.open();
        let before = metadata_counts(&store);
        let (project, policy) = documents("denied-project", "denied-policy");
        let request = ProjectBootstrapRequest {
            project: &project,
            policy: &policy,
        };
        let mut permit = Permit::new(&root);
        match scenario {
            "admission" => permit.deny_approval = Some(1),
            "revocation" => permit.deny_approval = Some(2),
            "changed-owner" => permit.change_owner = true,
            "expired" => permit.stop_check = Some(1),
            "cancel-in-cas" => permit.stop_check = Some(6),
            _ => permit.root = root.0.join("another-store"),
        }
        assert!(
            create_project(&mut store, &mut permit, &request).is_err(),
            "{scenario}"
        );
        assert_eq!(metadata_counts(&store), before, "{scenario}");
    }
}

#[test]
fn occupied_project_or_policy_and_invalid_fresh_memberships_never_overwrite() {
    let root = Root::new();
    let mut store = root.open();
    let (project, policy) = documents("existing-project", "existing-policy");
    create_project(
        &mut store,
        &mut Permit::new(&root),
        &ProjectBootstrapRequest {
            project: &project,
            policy: &policy,
        },
    )
    .unwrap();
    let before = metadata_counts(&store);
    for (project_id, policy_id) in [
        ("existing-project", "different-policy"),
        ("different-project", "existing-policy"),
    ] {
        let (candidate, candidate_policy) = documents(project_id, policy_id);
        assert!(matches!(
            create_project(
                &mut store,
                &mut Permit::new(&root),
                &ProjectBootstrapRequest {
                    project: &candidate,
                    policy: &candidate_policy
                }
            ),
            Err(StorageError::Conflict(_))
        ));
        assert_eq!(metadata_counts(&store), before);
    }
    for altered in [
        "dangling-resource",
        "dangling-object",
        "bad-revision",
        "bad-policy",
        "changed-default-policy",
    ] {
        let (mut candidate, mut altered_policy) = documents("fresh-candidate", "fresh-policy");
        match altered {
            "dangling-resource" => {
                candidate["resourceIds"] = json!(["fresh-policy", "missing-resource"])
            }
            "dangling-object" => candidate["prefabIds"] = json!(["missing-prefab"]),
            "bad-revision" => candidate["revision"] = json!("0".repeat(64)),
            "changed-default-policy" => altered_policy["providerDiscovery"] = json!(false),
            _ => altered_policy["privateReflection"] = json!(true),
        }
        if altered != "bad-revision" {
            candidate["revision"] = json!(projected_digest("Project", &candidate).unwrap());
        }
        assert!(
            create_project(
                &mut store,
                &mut Permit::new(&root),
                &ProjectBootstrapRequest {
                    project: &candidate,
                    policy: &altered_policy
                }
            )
            .is_err()
        );
        assert_eq!(metadata_counts(&store), before);
    }
    assert_eq!(
        store
            .project(&ProjectId::new("existing-project").unwrap())
            .unwrap(),
        project
    );
}

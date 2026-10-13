//! Stateful external SQLite/CAS fixtures exercise source history, corruption,
//! cancellation and revoked current ACL. Fixture registry mutations do not
//! represent a game run; atomic production promotion is tested separately.

use super::*;
use crate::storage::{StoreConfig, artifact::register_resource};
use mmmm_contracts::{canonical_digest, encode_json, projected_digest};
use serde_json::json;
use std::{
    cell::Cell,
    fs,
    path::PathBuf,
    rc::Rc,
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
            "mmmm-project-source-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = fs::canonicalize(path).unwrap();
        assert!(!path.starts_with(
            fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap()
        ));
        fs::write(path.join("test-owner.txt"), b"mmmm-project-source-test\n").unwrap();
        Self(path)
    }
    fn open(&self) -> DurableStore {
        DurableStore::open(StoreConfig::new(self.0.clone())).unwrap()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        if fs::read(self.0.join("test-owner.txt")).ok().as_deref()
            == Some(b"mmmm-project-source-test\n")
            && super::super::cas::verify_plain_path(&self.0).is_ok()
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
struct Rpc {
    principal: PrincipalId,
    context: Option<ContextId>,
    checks: Cell<usize>,
    cancel_at: Option<usize>,
}
impl Rpc {
    fn offline() -> Self {
        Self {
            principal: PrincipalId::new("source-principal").unwrap(),
            context: None,
            checks: Cell::new(0),
            cancel_at: None,
        }
    }
}
impl ProjectSourceRpcContext for Rpc {
    fn check(&self) -> StorageResult<()> {
        let n = self.checks.get() + 1;
        self.checks.set(n);
        if self.cancel_at.is_some_and(|limit| n >= limit) {
            return Err(invalid("Fixture source request cancelled"));
        }
        Ok(())
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.principal.clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        self.context.as_ref()
    }
}
struct Authority {
    resource_checks: Rc<Cell<usize>>,
    revoke_resource_at: Option<usize>,
    deny_project: bool,
}
impl ProjectResourceAuthority for Authority {
    fn authorize_project_read(
        &mut self,
        _: &DurableStore,
        principal: &PrincipalId,
        _: Option<&ContextId>,
        _: &ProjectId,
        _: &Sha256Digest,
    ) -> StorageResult<()> {
        if self.deny_project || principal.as_str() != "source-principal" {
            return Err(StorageError::Conflict("Fixture current Project ACL"));
        }
        Ok(())
    }
    fn authorize_resource_read(
        &mut self,
        _: &DurableStore,
        _: &PrincipalId,
        _: Option<&ContextId>,
        _: &ProjectId,
        _: &RegisteredProjectResource,
    ) -> StorageResult<()> {
        let count = self.resource_checks.get() + 1;
        self.resource_checks.set(count);
        if self.revoke_resource_at.is_some_and(|at| count >= at) {
            return Err(StorageError::Conflict(
                "Fixture current resource ACL revoked",
            ));
        }
        Ok(())
    }
}
fn reader(revoke: Option<usize>) -> ProjectResourceReader {
    ProjectResourceReader::new(
        Box::new(Authority {
            resource_checks: Rc::new(Cell::new(0)),
            revoke_resource_at: revoke,
            deny_project: false,
        }),
        2 * 1024 * 1024,
    )
    .unwrap()
}

/// Revoke Project rights from the actual CAS verification callback after the
/// first final Project ACL check; resource rights deliberately remain valid.
struct RevokingRpc {
    inner: Rpc,
    project_checks: Rc<Cell<usize>>,
    checks_since_final: Cell<usize>,
    revoked: Rc<Cell<bool>>,
}
impl ProjectSourceRpcContext for RevokingRpc {
    fn check(&self) -> StorageResult<()> {
        self.inner.check()?;
        if self.project_checks.get() >= 2 {
            let count = self.checks_since_final.get() + 1;
            self.checks_since_final.set(count);
            // final check, load admission, CAS admission/open, chunk pre/post
            // checks: this fires after an actual final-verification chunk read.
            if count >= 6 {
                self.revoked.set(true);
            }
        }
        Ok(())
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.inner.principal.clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        self.inner.context.as_ref()
    }
}
struct RevokingProjectAuthority {
    project_checks: Rc<Cell<usize>>,
    resource_checks: Rc<Cell<usize>>,
    revoked: Rc<Cell<bool>>,
}
impl ProjectResourceAuthority for RevokingProjectAuthority {
    fn authorize_project_read(
        &mut self,
        _: &DurableStore,
        _: &PrincipalId,
        _: Option<&ContextId>,
        _: &ProjectId,
        _: &Sha256Digest,
    ) -> StorageResult<()> {
        self.project_checks.set(self.project_checks.get() + 1);
        if self.revoked.get() {
            return Err(StorageError::Conflict(
                "Fixture Project ACL revoked during CAS verification",
            ));
        }
        Ok(())
    }
    fn authorize_resource_read(
        &mut self,
        _: &DurableStore,
        _: &PrincipalId,
        _: Option<&ContextId>,
        _: &ProjectId,
        _: &RegisteredProjectResource,
    ) -> StorageResult<()> {
        self.resource_checks.set(self.resource_checks.get() + 1);
        Ok(())
    }
}
fn seed(store: &mut DurableStore) -> (ProjectId, Sha256Digest, Value) {
    let mut value = parse_json(
        &fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/project.json"))
            .unwrap(),
    )
    .unwrap();
    value["ownedResources"] = json!([]);
    value["prefabIds"] = json!([]);
    value["instanceIds"] = json!([]);
    value["resourceIds"] = json!(["resource-source"]);
    value["revision"] = json!(projected_digest("Project", &value).unwrap());
    store.save_project(&value, None).unwrap();
    (
        ProjectId::new("project-fixture").unwrap(),
        serde_json::from_value(value["revision"].clone()).unwrap(),
        value,
    )
}
fn resource(store: &mut DurableStore, project: &ProjectId, id: &str, bytes: &[u8]) -> Value {
    let blob = store.put_blob(bytes).unwrap();
    let value = json!({"resourceId":id,"sha256":blob.digest,"sizeBytes":blob.byte_length,"mediaType":"application/octet-stream"});
    register_resource(store, &value, ResourceOwner::Project(project.clone())).unwrap();
    value
}

// Deliberately controlled registry fixtures use the exact product table keys
// to induce history/head and missing-provenance cases without a world writer.
fn version_fixture(
    store: &mut DurableStore,
    project: &ProjectId,
    revision: &Sha256Digest,
    resource: &Value,
    current: bool,
) {
    store.connection.execute_batch("CREATE TABLE IF NOT EXISTS project_resource_versions(project_id TEXT NOT NULL,resource_id TEXT NOT NULL,digest TEXT NOT NULL REFERENCES blobs(digest),resource_json TEXT NOT NULL,byte_length INTEGER NOT NULL,PRIMARY KEY(project_id,resource_id,digest)) STRICT;
        CREATE TABLE IF NOT EXISTS project_resource_heads(project_id TEXT NOT NULL,resource_id TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(project_id,resource_id),FOREIGN KEY(project_id,resource_id,digest) REFERENCES project_resource_versions(project_id,resource_id,digest)) STRICT;
        CREATE TABLE IF NOT EXISTS project_resource_provenance(project_id TEXT NOT NULL,project_revision TEXT NOT NULL,resource_id TEXT NOT NULL,digest TEXT NOT NULL,project_definition TEXT NOT NULL DEFAULT 'Project',PRIMARY KEY(project_id,project_revision,resource_id,digest),FOREIGN KEY(project_id,resource_id,digest) REFERENCES project_resource_versions(project_id,resource_id,digest),FOREIGN KEY(project_definition,project_id,project_revision) REFERENCES documents(definition,document_id,content_hash)) STRICT;").unwrap();
    let id = resource["resourceId"].as_str().unwrap();
    let digest = resource["sha256"].as_str().unwrap();
    store.connection.execute("INSERT OR IGNORE INTO project_resource_versions(project_id,resource_id,digest,resource_json,byte_length) VALUES(?1,?2,?3,?4,?5)",params![project.as_str(),id,digest,String::from_utf8(encode_json(resource).unwrap()).unwrap(),resource["sizeBytes"].as_u64().unwrap() as i64]).unwrap();
    store.connection.execute("INSERT OR IGNORE INTO project_resource_provenance(project_id,project_revision,resource_id,digest) VALUES(?1,?2,?3,?4)",params![project.as_str(),revision.as_str(),id,digest]).unwrap();
    let owner =
        canonical_digest(&json!({"projectId":project,"resourceId":id,"sha256":digest})).unwrap();
    store.connection.execute("INSERT OR IGNORE INTO blob_refs(owner_kind,owner_id,digest) VALUES('project_resource',?1,?2)",params![owner.as_str(),digest]).unwrap();
    if current {
        store.connection.execute("INSERT INTO project_resource_heads(project_id,resource_id,digest) VALUES(?1,?2,?3) ON CONFLICT(project_id,resource_id) DO UPDATE SET digest=excluded.digest",params![project.as_str(),id,digest]).unwrap();
    }
}
fn query_current() -> ProjectResourceQuery {
    ProjectResourceQuery::Current {
        resource_id: ResourceId::new("resource-source").unwrap(),
    }
}

#[test]
fn current_and_private_staged_sources_require_real_project_owner_and_exact_metadata() {
    let root = Root::new();
    let mut store = root.open();
    let (project, revision, document) = seed(&mut store);
    let reference = resource(
        &mut store,
        &project,
        "resource-source",
        b"registered source",
    );
    let mut unknown_uri = reference.clone();
    unknown_uri["uri"] = json!("opaque:never-opened");
    assert!(
        register_resource(
            &mut store,
            &unknown_uri,
            ResourceOwner::Project(project.clone())
        )
        .is_err()
    );
    let rpc = Rpc::offline();
    let mut reader = reader(None);
    let query = query_current();
    let request = ProjectResourceRequest {
        project: &project,
        current_project_revision: &revision,
        query: &query,
        expected: Some(&reference),
    };
    let actual = reader.read(&store, &rpc, &request, 4096).unwrap();
    assert_eq!(actual.bytes, b"registered source");
    assert_eq!(actual.registered.resource, reference);
    assert_eq!(
        reader
            .read_project(&store, &rpc, &project, &revision, MAX_PROJECT_BYTES)
            .unwrap(),
        document
    );
    let private = resource(
        &mut store,
        &project,
        "private-staged",
        b"compiled private derivative",
    );
    let query = ProjectResourceQuery::RegisteredImmutable {
        resource_id: ResourceId::new("private-staged").unwrap(),
    };
    let request = ProjectResourceRequest {
        project: &project,
        current_project_revision: &revision,
        query: &query,
        expected: Some(&private),
    };
    assert!(reader.read(&store, &rpc, &request, 4096).is_ok());
    let query = ProjectResourceQuery::Current {
        resource_id: ResourceId::new("private-staged").unwrap(),
    };
    let request = ProjectResourceRequest {
        project: &project,
        current_project_revision: &revision,
        query: &query,
        expected: Some(&private),
    };
    assert!(reader.read(&store, &rpc, &request, 4096).is_err());
    let mut wrong = reference.clone();
    wrong["mediaType"] = json!("text/plain");
    let query = query_current();
    let request = ProjectResourceRequest {
        project: &project,
        current_project_revision: &revision,
        query: &query,
        expected: Some(&wrong),
    };
    assert!(reader.read(&store, &rpc, &request, 4096).is_err());
    store
        .connection
        .execute(
            "UPDATE artifact_resources SET owner_json=?1 WHERE resource_id='resource-source'",
            ["{\"kind\":\"principal\",\"id\":\"source-principal\"}"],
        )
        .unwrap();
    let request = ProjectResourceRequest {
        project: &project,
        current_project_revision: &revision,
        query: &query,
        expected: Some(&reference),
    };
    assert!(reader.read(&store, &rpc, &request, 4096).is_err());
}

#[test]
fn unchanged_project_revision_resource_head_and_exact_history_survive_restart() {
    let root = Root::new();
    let mut store = root.open();
    let (project, revision, _) = seed(&mut store);
    let before = resource(&mut store, &project, "resource-source", b"before");
    let mut after = resource(&mut store, &project, "replacement-source", b"after");
    after["resourceId"] = json!("resource-source");
    version_fixture(&mut store, &project, &revision, &before, false);
    version_fixture(&mut store, &project, &revision, &after, true);
    drop(store);
    let store = root.open();
    let rpc = Rpc::offline();
    let mut reader = reader(None);
    let query = query_current();
    let request = ProjectResourceRequest {
        project: &project,
        current_project_revision: &revision,
        query: &query,
        expected: Some(&after),
    };
    assert_eq!(
        reader.read(&store, &rpc, &request, 4096).unwrap().bytes,
        b"after"
    );
    let stale = ProjectResourceRequest {
        project: &project,
        current_project_revision: &revision,
        query: &query,
        expected: Some(&before),
    };
    assert!(reader.read(&store, &rpc, &stale, 4096).is_err());
    let query = ProjectResourceQuery::Historical {
        project_revision: revision.clone(),
        resource_id: ResourceId::new("resource-source").unwrap(),
        digest: serde_json::from_value(before["sha256"].clone()).unwrap(),
    };
    let request = ProjectResourceRequest {
        project: &project,
        current_project_revision: &revision,
        query: &query,
        expected: Some(&before),
    };
    assert_eq!(
        reader.read(&store, &rpc, &request, 4096).unwrap().bytes,
        b"before"
    );
    let invalid = ProjectResourceQuery::Historical {
        project_revision: Sha256Digest::new("b".repeat(64)).unwrap(),
        resource_id: ResourceId::new("resource-source").unwrap(),
        digest: serde_json::from_value(before["sha256"].clone()).unwrap(),
    };
    let request = ProjectResourceRequest {
        project: &project,
        current_project_revision: &revision,
        query: &invalid,
        expected: Some(&before),
    };
    assert!(reader.read(&store, &rpc, &request, 4096).is_err());
}

#[test]
fn current_revision_change_and_revoked_acl_never_release_captured_body() {
    let root = Root::new();
    let mut store = root.open();
    let (project, revision, mut document) = seed(&mut store);
    let reference = resource(
        &mut store,
        &project,
        "resource-source",
        b"withheld source bytes",
    );
    let query = query_current();
    let rpc = Rpc::offline();
    let request = ProjectResourceRequest {
        project: &project,
        current_project_revision: &revision,
        query: &query,
        expected: Some(&reference),
    };
    assert!(reader(Some(2)).read(&store, &rpc, &request, 4096).is_err());
    version_fixture(&mut store, &project, &revision, &reference, true);
    for query in [
        query_current(),
        ProjectResourceQuery::Historical {
            project_revision: revision.clone(),
            resource_id: ResourceId::new("resource-source").unwrap(),
            digest: serde_json::from_value(reference["sha256"].clone()).unwrap(),
        },
    ] {
        for metadata_only in [false, true] {
            let project_checks = Rc::new(Cell::new(0));
            let resource_checks = Rc::new(Cell::new(0));
            let revoked = Rc::new(Cell::new(false));
            let rpc = RevokingRpc {
                inner: Rpc::offline(),
                project_checks: project_checks.clone(),
                checks_since_final: Cell::new(0),
                revoked: revoked.clone(),
            };
            let mut reader = ProjectResourceReader::new(
                Box::new(RevokingProjectAuthority {
                    project_checks: project_checks.clone(),
                    resource_checks: resource_checks.clone(),
                    revoked: revoked.clone(),
                }),
                4096,
            )
            .unwrap();
            let request = ProjectResourceRequest {
                project: &project,
                current_project_revision: &revision,
                query: &query,
                expected: Some(&reference),
            };
            if metadata_only {
                assert!(reader.metadata(&store, &rpc, &request).is_err());
            } else {
                assert!(reader.read(&store, &rpc, &request, 4096).is_err());
            }
            assert!(revoked.get());
            assert_eq!(project_checks.get(), 3);
            assert_eq!(resource_checks.get(), 1);
        }
    }
    document["name"] = json!("new authoring head");
    document["revision"] = json!(projected_digest("Project", &document).unwrap());
    store.save_project(&document, Some(&revision)).unwrap();
    assert!(reader(None).metadata(&store, &rpc, &request).is_err());
    assert!(
        reader(None)
            .read_project(&store, &rpc, &project, &revision, MAX_PROJECT_BYTES)
            .is_err()
    );
}

#[test]
fn full_read_checks_chunks_budget_cancellation_and_corruption_beyond_first_chunk() {
    let root = Root::new();
    let mut store = root.open();
    let (project, revision, _) = seed(&mut store);
    let reference = resource(
        &mut store,
        &project,
        "resource-source",
        &vec![7; 192 * 1024],
    );
    let (_, blob) = validate_resource(&store, &reference).unwrap();
    let calls = Cell::new(0usize);
    assert!(
        store
            .read_blob_checked(&blob, 1024 * 1024, || {
                let n = calls.get() + 1;
                calls.set(n);
                if n >= 5 {
                    Err(invalid("Cancelled mid-stream fixture"))
                } else {
                    Ok(())
                }
            })
            .is_err()
    );
    assert_eq!(calls.get(), 5);
    let query = query_current();
    let request = ProjectResourceRequest {
        project: &project,
        current_project_revision: &revision,
        query: &query,
        expected: Some(&reference),
    };
    let rpc = Rpc::offline();
    assert!(
        reader(None)
            .read(&store, &rpc, &request, 64 * 1024)
            .is_err()
    );
    let cancelled = Rpc {
        cancel_at: Some(1),
        ..Rpc::offline()
    };
    assert!(
        reader(None)
            .read(&store, &cancelled, &request, 1024 * 1024)
            .is_err()
    );
    let mut changed = vec![7; 192 * 1024];
    changed[150 * 1024] = 8;
    fs::write(store.cas.path(&blob.digest), changed).unwrap();
    assert!(
        reader(None)
            .read(&store, &rpc, &request, 1024 * 1024)
            .is_err()
    );
    assert!(reader(None).metadata(&store, &rpc, &request).is_err());
    assert!(
        store
            .read_blob_checked(&blob, MAX_SOURCE_RESOURCE_BYTES + 1, || Ok(()))
            .is_err()
    );
}

#[test]
fn missing_version_provenance_or_retention_is_not_repaired_by_digest_knowledge() {
    let root = Root::new();
    let mut store = root.open();
    let (project, revision, _) = seed(&mut store);
    let before = resource(
        &mut store,
        &project,
        "resource-source",
        b"historical retained bytes",
    );
    version_fixture(&mut store, &project, &revision, &before, true);
    let query = query_current();
    let request = ProjectResourceRequest {
        project: &project,
        current_project_revision: &revision,
        query: &query,
        expected: Some(&before),
    };
    let rpc = Rpc::offline();
    assert!(reader(None).metadata(&store, &rpc, &request).is_ok());
    store
        .connection
        .execute(
            "DELETE FROM blob_refs WHERE owner_kind='project_resource'",
            [],
        )
        .unwrap();
    assert!(reader(None).read(&store, &rpc, &request, 4096).is_err());
    version_fixture(&mut store, &project, &revision, &before, true);
    store
        .connection
        .execute("DELETE FROM project_resource_provenance", [])
        .unwrap();
    assert!(reader(None).read(&store, &rpc, &request, 4096).is_err());
}

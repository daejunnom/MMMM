//! 원본 examples를 재사용하는 실제 외부 SQLite/CAS 원자성 검사다.
//! 기존 pure candidate parser 검사와 별개이며 게임/NativeProof 인수를 뜻하지 않는다.
//! 아래 trusted test permit은 실제 Store root, SQL owner/head/history와 유한한
//! deadline을 검사한다. NativeOwnerWitness, NativeProof나 실행 grant를 위조하지 않는다.
//! 실패 후 미참조 CAS 파일과 rollback된 metadata의 수명은 별도로 검사한다.

use super::*;
use crate::storage::{
    StoreConfig,
    artifact::{ResourceOwner, register_resource},
    bootstrap::{
        NativeOwnerCreatePermit, ProjectBootstrapReceipt, ProjectBootstrapRequest, create_project,
        registered_native_project_owner,
    },
    owned_documents::{
        OwnedDocumentAuthority, OwnedDocumentKind, OwnedDocumentPin, OwnedDocumentReader,
    },
    project_resources::{
        ProjectResourceAuthority, ProjectResourceProvenance, ProjectResourceQuery,
        ProjectResourceReader, ProjectResourceRequest, ProjectSourceRpcContext,
        RegisteredProjectResource,
    },
};
use mmmm_contracts::{
    ContextId, ObjectId, OperationId, PlanId, PrincipalId, ProjectId, ResourceId, Sha256Digest,
    StepId, canonical_bytes, canonical_digest, parse_json, projected_digest, raw_digest,
    verify_projected_digest,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    fs,
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const ROOT_MARKER: &[u8] = b"mmmm-native-owned-source-tests\n";

struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        assert!(parent.is_absolute());
        let root = parent.join(format!(
            "mmmm-native-owned-sources-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed),
        ));
        assert!(!root.exists());
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let root = fs::canonicalize(root).unwrap();
        let checkout =
            fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        assert!(!root.starts_with(checkout));
        fs::write(root.join("test-owner.txt"), ROOT_MARKER).unwrap();
        Self(root)
    }
    fn store(&self) -> DurableStore {
        DurableStore::open(StoreConfig::new(self.0.clone())).unwrap()
    }
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        // 테스트가 만든 정확한 절대 경로/marker/link 경계를 확인한 뒤만 정리한다.
        if fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0)
            && crate::storage::cas::verify_plain_path(&self.0).is_ok()
            && fs::read(self.0.join("test-owner.txt")).ok().as_deref() == Some(ROOT_MARKER)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
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
fn revision(value: &Value) -> Sha256Digest {
    serde_json::from_value(value["revision"].clone()).unwrap()
}
fn revise(definition: &str, value: &mut Value) {
    value["revision"] = json!(projected_digest(definition, value).unwrap());
}
fn raw_json(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.extend_from_slice(b"\n \n");
    bytes
}

struct BootstrapPermit {
    root: PathBuf,
    owner: PrincipalId,
    deadline: Instant,
}
impl NativeOwnerCreatePermit for BootstrapPermit {
    fn check(&self, store: &DurableStore) -> StorageResult<()> {
        if store.data_root() != self.root || Instant::now() >= self.deadline {
            return Err(StorageError::Conflict("Authored bootstrap root/deadline"));
        }
        Ok(())
    }
    fn authorize_create(
        &mut self,
        store: &DurableStore,
        request: &ProjectBootstrapRequest<'_>,
    ) -> StorageResult<PrincipalId> {
        self.check(store)?;
        assert_eq!(*request.policy, example("policy.json"));
        assert_eq!(request.project["ownedResources"], json!([]));
        Ok(self.owner.clone())
    }
}
fn bootstrap(
    store: &mut DurableStore,
    root: &TestRoot,
    project_id: &str,
    policy_id: &str,
) -> (Value, ProjectBootstrapReceipt) {
    let mut project = example("project.json");
    project["projectId"] = json!(project_id);
    project["policyResourceId"] = json!(policy_id);
    project["resourceIds"] = json!([policy_id]);
    project["prefabIds"] = json!([]);
    project["instanceIds"] = json!([]);
    project["ownedResources"] = json!([]);
    revise("Project", &mut project);
    let policy = example("policy.json");
    let mut permit = BootstrapPermit {
        root: root.0.clone(),
        owner: PrincipalId::new("native-source-test-owner").unwrap(),
        deadline: Instant::now() + Duration::from_secs(30),
    };
    let receipt = create_project(
        store,
        &mut permit,
        &ProjectBootstrapRequest {
            project: &project,
            policy: &policy,
        },
    )
    .unwrap();
    (project, receipt)
}

#[derive(Clone, Copy)]
enum FinalFailure {
    None,
    Cancel,
    RevokeOwner,
    Deadline,
}
struct ScopeState {
    root: PathBuf,
    project: ProjectId,
    owner: PrincipalId,
    deadline: Cell<Instant>,
    cancelled: Cell<bool>,
    authorizations: Cell<usize>,
    final_rows_observed: Cell<bool>,
    deny_mesh_after_actual_checks: Cell<bool>,
    mesh_denial_observed: Cell<bool>,
    failure: FinalFailure,
}
impl ScopeState {
    fn check(&self) -> StorageResult<()> {
        if self.cancelled.get() {
            return Err(StorageError::InvalidTransition(
                "Authored native request cancelled".into(),
            ));
        }
        if Instant::now() >= self.deadline.get() {
            return Err(StorageError::InvalidTransition(
                "Authored native request deadline elapsed".into(),
            ));
        }
        Ok(())
    }
    fn authorize_sql(
        &self,
        connection: &Connection,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        current_revision: Option<&Sha256Digest>,
    ) -> StorageResult<()> {
        self.check()?;
        if principal != &self.owner || context.is_some() || project != &self.project {
            return Err(StorageError::Conflict("Authored current Project scope"));
        }
        let actual: Option<(String, String)> = connection
            .query_row(
                "SELECT n.owner_principal,h.revision FROM native_project_owners n JOIN project_heads h USING(project_id) WHERE n.project_id=?1",
                [project.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (owner, head) = actual.ok_or(StorageError::NotFound("Authored native owner"))?;
        if owner != self.owner.as_str()
            || current_revision.is_some_and(|revision| head != revision.as_str())
        {
            return Err(StorageError::Conflict("Authored actual SQL owner/head"));
        }
        Ok(())
    }
}

struct SqlReadAuthority(Rc<ScopeState>);
impl ProjectResourceAuthority for SqlReadAuthority {
    fn authorize_project_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        revision: &Sha256Digest,
    ) -> StorageResult<()> {
        if store.data_root() != self.0.root {
            return Err(StorageError::Conflict("Authored reader root"));
        }
        self.0.authorize_sql(
            &store.connection,
            principal,
            context,
            project,
            Some(revision),
        )
    }
    fn authorize_resource_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> StorageResult<()> {
        if store.data_root() != self.0.root {
            return Err(StorageError::Conflict("Authored resource reader root"));
        }
        self.0
            .authorize_sql(&store.connection, principal, context, project, None)?;
        if resource.owner != ResourceOwner::Project(project.clone()) {
            return Err(StorageError::Conflict("Authored resource actual owner"));
        }
        let actual: String = store.connection.query_row(
            "SELECT resource_json FROM artifact_resources WHERE resource_id=?1 AND blob_digest=?2 AND byte_length=?3",
            params![resource.resource["resourceId"].as_str().unwrap(), resource.blob.digest.as_str(), resource.blob.byte_length as i64],
            |row| row.get(0),
        )?;
        if parse_json(actual.as_bytes())
            .map_err(|cause| StorageError::Contract(cause.to_string()))?
            != resource.resource
        {
            return Err(StorageError::Conflict(
                "Authored immutable resource metadata",
            ));
        }
        // This optional test restriction runs only after the actual SQL owner,
        // Project and immutable resource metadata checks have succeeded.
        if self.0.deny_mesh_after_actual_checks.get()
            && resource.resource["resourceId"].as_str() == Some("resource-physics-mesh")
        {
            self.0.mesh_denial_observed.set(true);
            return Err(StorageError::Conflict("Authored scoped resource denied"));
        }
        Ok(())
    }
}
impl OwnedDocumentAuthority for SqlReadAuthority {
    fn authorize_read(
        &mut self,
        principal: &PrincipalId,
        context: &ContextId,
        project: &ProjectId,
        revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> StorageResult<()> {
        OwnedDocumentAuthority::authorize_project_read(
            self,
            principal,
            Some(context),
            project,
            revision,
            pin,
        )
    }
    fn authorize_project_read(
        &mut self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> StorageResult<()> {
        // 이 reader port에는 Store 인수가 없다. 같은 외부 root의 실제 committed
        // owner/head/history를 별도 read-only WAL connection으로 확인한다.
        crate::storage::cas::verify_plain_path(&self.0.root)?;
        let connection = Connection::open_with_flags(
            self.0.root.join("journal.sqlite3"),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        self.0
            .authorize_sql(&connection, principal, context, project, Some(revision))?;
        let exists: i64 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM owned_document_provenance p JOIN owned_documents d USING(project_id,kind,object_id,revision) WHERE p.project_id=?1 AND p.project_revision=?2 AND p.kind=?3 AND p.object_id=?4 AND p.revision=?5)",
            params![project.as_str(),revision.as_str(),pin.kind.as_str(),pin.object_id.as_str(),pin.revision.as_str()],
            |row| row.get(0),
        )?;
        if exists != 1 {
            return Err(StorageError::Conflict("Authored actual owned provenance"));
        }
        self.0.check()
    }
}

struct TestPermit(Rc<ScopeState>);
impl TestPermit {
    fn new(root: &TestRoot, receipt: &ProjectBootstrapReceipt) -> Self {
        Self::with_failure(root, receipt, FinalFailure::None)
    }
    fn with_failure(
        root: &TestRoot,
        receipt: &ProjectBootstrapReceipt,
        failure: FinalFailure,
    ) -> Self {
        Self(Rc::new(ScopeState {
            root: root.0.clone(),
            project: receipt.project_id.clone(),
            owner: receipt.owner_principal.clone(),
            deadline: Cell::new(Instant::now() + Duration::from_secs(30)),
            cancelled: Cell::new(false),
            authorizations: Cell::new(0),
            final_rows_observed: Cell::new(false),
            deny_mesh_after_actual_checks: Cell::new(false),
            mesh_denial_observed: Cell::new(false),
            failure,
        }))
    }
}
impl ProjectSourceRpcContext for TestPermit {
    fn check(&self) -> StorageResult<()> {
        self.0.check()
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.0.owner.clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        None
    }
}
impl NativeOwnedSourceCommitPermit for TestPermit {
    fn check_store(&self, store: &DurableStore) -> StorageResult<()> {
        if store.data_root() != self.0.root {
            return Err(StorageError::Conflict("Authored native Store root"));
        }
        self.0.authorize_sql(
            &store.connection,
            &self.0.owner,
            None,
            &self.0.project,
            None,
        )
    }
    fn authorize_commit(
        &self,
        store: &DurableStore,
        view: &NativeOwnedSourceCommitView<'_>,
    ) -> StorageResult<PrincipalId> {
        self.check_store(store)?;
        self.0.authorize_sql(
            &store.connection,
            &self.0.owner,
            None,
            view.request.project,
            Some(view.request.expected_revision),
        )?;
        if store.project(view.request.project)? != *view.base_project
            || view.next_project["policyResourceId"] != view.base_project["policyResourceId"]
        {
            return Err(StorageError::Conflict("Authored exact base/policy"));
        }
        let calls = self.0.authorizations.get() + 1;
        self.0.authorizations.set(calls);
        // callback 횟수에 의존하지 않고 실제 provisional 새 revision의 SQL
        // 존재로 최종 publication 지점을 확인한다. 초기 admission에는 없다.
        let provisional_project: i64 = store.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM documents WHERE definition='Project' AND document_id=?1 AND content_hash=?2)",
            params![view.request.project.as_str(), view.next_project["revision"].as_str().unwrap()],
            |row| row.get(0),
        )?;
        if provisional_project == 1 {
            // resource-only 최초 batch에는 owned registry가 아직 없을 수 있다.
            // 실제 테이블 부재는 0개이며, 다음의 기대 문서 개수 비교는 그대로 유지한다.
            let owned_registry: bool = store.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='owned_document_provenance')",
                [], |row| row.get(0),
            )?;
            let owned: i64 = if owned_registry {
                store.connection.query_row(
                    "SELECT count(*) FROM owned_document_provenance WHERE project_id=?1 AND project_revision=?2",
                    params![view.request.project.as_str(), view.next_project["revision"].as_str().unwrap()],
                    |row| row.get(0),
                )?
            } else {
                0
            };
            let resources: i64 = store.connection.query_row(
                "SELECT count(*) FROM project_resource_provenance WHERE project_id=?1 AND project_revision=?2",
                params![view.request.project.as_str(), view.next_project["revision"].as_str().unwrap()],
                |row| row.get(0),
            )?;
            self.0.final_rows_observed.set(
                provisional_project == 1
                    && owned
                        == view.next_project["ownedResources"]
                            .as_array()
                            .unwrap()
                            .len() as i64
                    && resources
                        == view.next_project["resourceIds"].as_array().unwrap().len() as i64,
            );
            match self.0.failure {
                FinalFailure::None => (),
                FinalFailure::Cancel => self.0.cancelled.set(true),
                FinalFailure::Deadline => self.0.deadline.set(Instant::now()),
                FinalFailure::RevokeOwner => {
                    // 실제 소유 SQL 행을 같은 transaction에서 변경한다.
                    // 최종 owner 재검사와 rollback을 시험하며 native 증명은 만들지 않는다.
                    store.connection.execute(
                        "UPDATE native_project_owners SET owner_principal='revoked-source-test-owner' WHERE project_id=?1",
                        [view.request.project.as_str()],
                    )?;
                }
            }
            self.check_store(store)?;
        }
        Ok(self.0.owner.clone())
    }
    fn resource_reader(&self, ceiling: u64) -> StorageResult<ProjectResourceReader> {
        ProjectResourceReader::new(Box::new(SqlReadAuthority(self.0.clone())), ceiling)
    }
    fn owned_document_reader(&self, ceiling: u64) -> StorageResult<OwnedDocumentReader> {
        OwnedDocumentReader::new(Box::new(SqlReadAuthority(self.0.clone())), ceiling)
    }
}

#[derive(Clone)]
struct Batch {
    next: Value,
    pins: Vec<OwnedDocumentPin>,
    documents: Vec<Vec<u8>>,
    resources: Vec<(Value, Vec<u8>)>,
}
impl Batch {
    fn initial(base: &Value) -> Self {
        let bytes = b"authored raw block resource\0\n".to_vec();
        let resource = json!({
            "resourceId":"resource-wall-blocks",
            "sha256":raw_digest(&bytes),
            "mediaType":"application/vnd.mmmm.blockset+json",
            "sizeBytes":bytes.len(),
        });
        let mut prefab = example("prefab.json");
        // 이 batch에는 CommandModule을 제공하지 않으므로 참조를 제거한다.
        // door/Clip과 실제 resource는 유지한다.
        prefab["commandModuleIds"] = json!([]);
        prefab["references"] = json!([]);
        prefab["resources"] = json!([resource]);
        revise("Prefab", &mut prefab);
        let mut instance = example("instance.json");
        instance["prefabRevision"] = prefab["revision"].clone();
        revise("Instance", &mut instance);
        let clip = example("animation-clip.json");
        Self::from_sources(
            base,
            vec![
                (OwnedDocumentKind::Prefab, prefab),
                (OwnedDocumentKind::Instance, instance),
                (OwnedDocumentKind::AnimationClip, clip),
            ],
            vec![(resource, bytes)],
        )
    }
    fn from_sources(
        base: &Value,
        sources: Vec<(OwnedDocumentKind, Value)>,
        resources: Vec<(Value, Vec<u8>)>,
    ) -> Self {
        let pins: Vec<_> = sources
            .iter()
            .map(|(kind, value)| OwnedDocumentPin {
                kind: *kind,
                object_id: ObjectId::new(value[kind.identity_field()].as_str().unwrap()).unwrap(),
                revision: revision(value),
            })
            .collect();
        let mut next = base.clone();
        for pin in &pins {
            next["ownedResources"]
                .as_array_mut()
                .unwrap()
                .push(json!(pin));
            if let Some(field) = match pin.kind {
                OwnedDocumentKind::Prefab => Some("prefabIds"),
                OwnedDocumentKind::Instance => Some("instanceIds"),
                _ => None,
            } {
                next[field]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(pin.object_id));
            }
        }
        for (resource, _) in &resources {
            next["resourceIds"]
                .as_array_mut()
                .unwrap()
                .push(resource["resourceId"].clone());
        }
        revise("Project", &mut next);
        Self {
            next,
            pins,
            documents: sources.iter().map(|(_, value)| raw_json(value)).collect(),
            resources,
        }
    }
    fn commit(
        &self,
        store: &mut DurableStore,
        permit: &TestPermit,
        base: &Value,
    ) -> StorageResult<NativeOwnedSourceCommitReceipt> {
        let project: ProjectId = serde_json::from_value(base["projectId"].clone()).unwrap();
        let expected_revision = revision(base);
        let project_bytes = raw_json(&self.next);
        let documents: Vec<_> = self
            .pins
            .iter()
            .zip(&self.documents)
            .map(|(pin, bytes)| NativeOwnedDocumentSource { pin, bytes })
            .collect();
        let metadata: Vec<_> = self
            .resources
            .iter()
            .map(|(value, _)| raw_json(value))
            .collect();
        let resources: Vec<_> = self
            .resources
            .iter()
            .zip(&metadata)
            .map(|((_, bytes), metadata)| NativeOwnedResourceSource::Raw { metadata, bytes })
            .collect();
        commit_native_owned_sources(
            store,
            permit,
            &NativeOwnedSourceCommitRequest {
                project: &project,
                expected_revision: &expected_revision,
                project_bytes: &project_bytes,
                documents: &documents,
                resources: &resources,
            },
        )
    }
    fn replace_document(&mut self, index: usize, value: &Value) {
        self.documents[index] = raw_json(value);
        self.pins[index].revision = revision(value);
        self.next["ownedResources"][index] = json!(self.pins[index]);
        revise("Project", &mut self.next);
    }
}

fn display_batch(base: &Value, resource_id: &str, declared: Option<&Value>) -> Batch {
    let initial = Batch::initial(base);
    let mut sources: Vec<_> = initial
        .pins
        .iter()
        .zip(&initial.documents)
        .map(|(pin, bytes)| (pin.kind, parse_json(bytes).unwrap()))
        .collect();
    let prefab = &mut sources[0].1;
    prefab["nodes"][0]["display"] = json!({
        "kind": "block",
        "payload": {},
        "resourceRefs": [resource_id],
    });
    if let Some(resource) = declared {
        prefab["resources"]
            .as_array_mut()
            .unwrap()
            .push(resource.clone());
    }
    revise("Prefab", prefab);
    let prefab_revision = prefab["revision"].clone();
    sources[1].1["prefabRevision"] = prefab_revision;
    revise("Instance", &mut sources[1].1);
    Batch::from_sources(base, sources, initial.resources)
}

#[test]
fn display_resource_ids_resolve_through_actual_owned_resources() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let batch = display_batch(&base, "resource-wall-blocks", None);
    let permit = TestPermit::new(&root, &initial);
    let receipt = batch.commit(&mut store, &permit, &base).unwrap();
    assert!(permit.0.final_rows_observed.get());
    assert_eq!(store.project(&initial.project_id).unwrap(), batch.next);
    let query = ProjectResourceQuery::Current {
        resource_id: ResourceId::new("resource-wall-blocks").unwrap(),
    };
    let mut reader = permit.resource_reader(MAX_SOURCE_TOTAL).unwrap();
    let loaded = reader
        .read(
            &store,
            &permit,
            &ProjectResourceRequest {
                project: &initial.project_id,
                current_project_revision: &receipt.project_revision,
                query: &query,
                expected: Some(&batch.resources[0].0),
            },
            MAX_SOURCE_TOTAL,
        )
        .unwrap();
    assert_eq!(loaded.bytes, batch.resources[0].1);
}

#[test]
fn display_resource_id_without_actual_resource_cannot_commit() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let batch = display_batch(&base, "resource-missing", None);
    let baseline = metadata_snapshot(&store);
    assert!(matches!(
        batch.commit(&mut store, &TestPermit::new(&root, &initial), &base),
        Err(StorageError::InvalidInput(message))
            if message == "Owned display resource is unavailable"
    ));
    assert_unchanged(&store, &baseline, &base);
}

#[test]
fn display_current_project_resource_must_be_declared_by_prefab() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let permit = TestPermit::new(&root, &initial);
    let query = ProjectResourceQuery::Current {
        resource_id: ResourceId::new("policy-local").unwrap(),
    };
    let mut reader = permit.resource_reader(MAX_SOURCE_TOTAL).unwrap();
    let actual = reader
        .metadata(
            &store,
            &permit,
            &ProjectResourceRequest {
                project: &initial.project_id,
                current_project_revision: &revision(&base),
                query: &query,
                expected: None,
            },
        )
        .unwrap();
    assert_eq!(actual.resource["resourceId"], json!("policy-local"));
    let batch = display_batch(&base, "policy-local", None);
    let baseline = metadata_snapshot(&store);
    assert!(matches!(
        batch.commit(&mut store, &permit, &base),
        Err(StorageError::InvalidInput(message))
            if message == "Owned display resource is unavailable"
    ));
    assert_unchanged(&store, &baseline, &base);
}

#[test]
fn display_retained_resource_still_requires_actual_reader_authorization() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let (physics, mesh, bytes) = physics_mesh_fixture();
    let first = Batch::from_sources(
        &base,
        vec![(OwnedDocumentKind::PhysicsDefinition, physics)],
        vec![(mesh.clone(), bytes)],
    );
    first
        .commit(&mut store, &TestPermit::new(&root, &initial), &base)
        .unwrap();
    let batch = display_batch(&first.next, "resource-physics-mesh", Some(&mesh));
    let permit = TestPermit::new(&root, &initial);
    permit.0.deny_mesh_after_actual_checks.set(true);
    let baseline = metadata_snapshot(&store);
    assert!(matches!(
        batch.commit(&mut store, &permit, &first.next),
        Err(StorageError::Conflict("Authored scoped resource denied"))
    ));
    assert!(permit.0.mesh_denial_observed.get());
    assert_unchanged(&store, &baseline, &first.next);
}

fn command_batch(base: &Value, mutate: impl FnOnce(&mut Value, &mut Value)) -> Batch {
    let initial = Batch::initial(base);
    let mut sources: Vec<_> = initial
        .pins
        .iter()
        .zip(&initial.documents)
        .map(|(pin, bytes)| (pin.kind, parse_json(bytes).unwrap()))
        .collect();
    let mut module = example("command-module.json");
    sources[0].1["commandModuleIds"] = json!([module["moduleId"]]);
    mutate(&mut sources[0].1, &mut module);
    revise("Prefab", &mut sources[0].1);
    revise("CommandModule", &mut module);
    sources[1].1["prefabRevision"] = sources[0].1["revision"].clone();
    revise("Instance", &mut sources[1].1);
    // Module first: validation must not depend on the order of a batch.
    sources.insert(0, (OwnedDocumentKind::CommandModule, module));
    Batch::from_sources(base, sources, initial.resources)
}

fn physics_batch(
    base: &Value,
    include_physics: bool,
    physics_first: bool,
    mutate: impl FnOnce(&mut Value, &mut Value),
) -> Batch {
    let initial = Batch::initial(base);
    let mut sources: Vec<_> = initial
        .pins
        .iter()
        .zip(&initial.documents)
        .map(|(pin, bytes)| (pin.kind, parse_json(bytes).unwrap()))
        .collect();
    let mut physics = example("physics-definition.json");
    // 원 Prefab 예제에는 physicsBinding이 없다. 기존 door node에 예제 물리
    // 정의를 결속한 파생 입력을 만들고 모든 영향 revision을 다시 계산한다.
    sources[0].1["nodes"][3]["physicsBinding"] = json!({
        "physicsId": physics["physicsId"],
        "bodyId": physics["bodies"][0]["bodyId"],
    });
    mutate(&mut sources[0].1, &mut physics);
    revise("PhysicsDefinition", &mut physics);
    revise("Prefab", &mut sources[0].1);
    sources[1].1["prefabRevision"] = sources[0].1["revision"].clone();
    revise("Instance", &mut sources[1].1);
    if include_physics {
        let source = (OwnedDocumentKind::PhysicsDefinition, physics);
        if physics_first {
            sources.insert(0, source);
        } else {
            sources.push(source);
        }
    }
    Batch::from_sources(base, sources, initial.resources)
}

#[test]
fn physics_source_and_prefab_binding_commit_in_either_batch_order() {
    for physics_first in [true, false] {
        let root = TestRoot::new();
        let mut store = root.store();
        let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
        let batch = physics_batch(&base, true, physics_first, |_, _| ());
        let permit = TestPermit::new(&root, &initial);
        let receipt = batch.commit(&mut store, &permit, &base).unwrap();
        assert!(permit.0.final_rows_observed.get());
        assert_eq!(store.project(&initial.project_id).unwrap(), batch.next);
        let position = batch
            .pins
            .iter()
            .position(|pin| pin.kind == OwnedDocumentKind::PhysicsDefinition)
            .unwrap();
        let (_, blob) = receipt
            .documents
            .iter()
            .find(|(pin, _)| pin == &batch.pins[position])
            .unwrap();
        assert_eq!(store.read_blob(blob).unwrap(), batch.documents[position]);
        let mut reader = permit
            .owned_document_reader(MAX_OWNED_DOCUMENT_BYTES)
            .unwrap();
        let loaded = reader
            .read_known_history_bytes(
                &store,
                &permit,
                &initial.project_id,
                &receipt.project_revision,
                &batch.pins[position],
            )
            .unwrap();
        assert_eq!(loaded.bytes, batch.documents[position]);
        assert_eq!(&loaded.blob, blob);

        let baseline = metadata_snapshot(&store);
        assert!(matches!(
            batch.commit(&mut store, &permit, &base),
            Err(StorageError::Conflict(_))
        ));
        assert_unchanged(&store, &baseline, &batch.next);
    }
}

#[test]
fn physics_binding_rejects_missing_physics_body_and_invalid_graph_without_metadata() {
    for case in 0..3 {
        let root = TestRoot::new();
        let mut store = root.store();
        let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
        let batch = physics_batch(&base, true, true, |prefab, physics| match case {
            0 => prefab["nodes"][3]["physicsBinding"]["physicsId"] = json!("physics-missing"),
            1 => prefab["nodes"][3]["physicsBinding"]["bodyId"] = json!("body-missing"),
            _ => physics["bodies"][0]["colliderIds"] = json!(["collider-missing"]),
        });
        if case == 2 {
            let index = batch
                .pins
                .iter()
                .position(|pin| pin.kind == OwnedDocumentKind::PhysicsDefinition)
                .unwrap();
            let schema_valid = parse_json(&batch.documents[index]).unwrap();
            store
                .validator
                .validate("PhysicsDefinition", &schema_valid)
                .unwrap();
        }
        let baseline = metadata_snapshot(&store);
        let result = batch.commit(&mut store, &TestPermit::new(&root, &initial), &base);
        let expected = match case {
            0 => matches!(result, Err(StorageError::InvalidInput(message))
                if message == "Owned physics binding has no actual Project membership"),
            1 => matches!(result, Err(StorageError::InvalidInput(message))
                if message == "Native physics binding definition or body differs"),
            _ => matches!(result, Err(StorageError::Contract(_))),
        };
        assert!(expected, "case {case}");
        assert_unchanged(&store, &baseline, &base);
    }
}

#[test]
fn retained_physics_document_is_loaded_for_later_prefab_body_binding() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let mut physics = example("physics-definition.json");
    revise("PhysicsDefinition", &mut physics);
    let first = Batch::from_sources(
        &base,
        vec![(OwnedDocumentKind::PhysicsDefinition, physics)],
        vec![],
    );
    first
        .commit(&mut store, &TestPermit::new(&root, &initial), &base)
        .unwrap();

    let baseline = metadata_snapshot(&store);
    let invalid = physics_batch(&first.next, false, false, |prefab, _| {
        prefab["nodes"][3]["physicsBinding"]["bodyId"] = json!("body-missing");
    });
    assert!(matches!(
        invalid.commit(&mut store, &TestPermit::new(&root, &initial), &first.next),
        Err(StorageError::InvalidInput(message))
            if message == "Native physics binding definition or body differs"
    ));
    assert_unchanged(&store, &baseline, &first.next);

    let valid = physics_batch(&first.next, false, false, |_, _| ());
    let permit = TestPermit::new(&root, &initial);
    let receipt = valid.commit(&mut store, &permit, &first.next).unwrap();
    assert!(permit.0.final_rows_observed.get());
    assert_eq!(store.project(&initial.project_id).unwrap(), valid.next);
    let mut reader = permit
        .owned_document_reader(MAX_OWNED_DOCUMENT_BYTES)
        .unwrap();
    let loaded = reader
        .read_known_history_bytes(
            &store,
            &permit,
            &initial.project_id,
            &receipt.project_revision,
            &first.pins[0],
        )
        .unwrap();
    assert_eq!(loaded.bytes, first.documents[0]);
}

#[test]
fn physics_transaction_cancellation_rolls_back_metadata() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let batch = physics_batch(&base, true, true, |_, _| ());
    let baseline = metadata_snapshot(&store);
    let permit = TestPermit::with_failure(&root, &initial, FinalFailure::Cancel);
    assert!(batch.commit(&mut store, &permit, &base).is_err());
    assert!(permit.0.final_rows_observed.get());
    assert_unchanged(&store, &baseline, &base);
}

fn physics_mesh_fixture() -> (Value, Value, Vec<u8>) {
    // 원 예제 collider는 box이므로 ResourceRef 연관을 확인할 때에만 mesh로
    // 파생한다. 이 불투명 bytes는 mesh codec이나 topology 증명이 아니다.
    let bytes = b"opaque authored mesh resource\0\n".to_vec();
    let resource = json!({
        "resourceId": "resource-physics-mesh",
        "sha256": raw_digest(&bytes),
        "mediaType": "application/octet-stream",
        "sizeBytes": bytes.len(),
    });
    let mut physics = example("physics-definition.json");
    physics["colliders"][0]["shape"]["shape"] = json!({
        "kind": "mesh",
        "geometry": resource,
        "topologyDigest": raw_digest(b"opaque topology marker"),
    });
    revise("PhysicsDefinition", &mut physics);
    (physics, resource, bytes)
}

#[test]
fn physics_mesh_geometry_uses_actual_project_resource_and_cas() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let (physics, resource, bytes) = physics_mesh_fixture();
    let batch = Batch::from_sources(
        &base,
        vec![(OwnedDocumentKind::PhysicsDefinition, physics)],
        vec![(resource.clone(), bytes.clone())],
    );
    let permit = TestPermit::new(&root, &initial);
    let receipt = batch.commit(&mut store, &permit, &base).unwrap();
    assert!(permit.0.final_rows_observed.get());
    assert_eq!(store.project(&initial.project_id).unwrap(), batch.next);
    let query = ProjectResourceQuery::Current {
        resource_id: ResourceId::new("resource-physics-mesh").unwrap(),
    };
    let mut reader = permit.resource_reader(MAX_SOURCE_TOTAL).unwrap();
    let loaded = reader
        .read(
            &store,
            &permit,
            &ProjectResourceRequest {
                project: &initial.project_id,
                current_project_revision: &receipt.project_revision,
                query: &query,
                expected: Some(&resource),
            },
            MAX_SOURCE_TOTAL,
        )
        .unwrap();
    assert_eq!(loaded.bytes, bytes);
    assert_eq!(loaded.registered.blob.digest, raw_digest(&bytes));
    assert_eq!(
        loaded.registered.provenance,
        ProjectResourceProvenance::CurrentProject {
            project_revision: receipt.project_revision,
        }
    );
}

#[test]
fn physics_mesh_geometry_rejects_missing_or_inexact_actual_resource() {
    for case in 0..4 {
        let root = TestRoot::new();
        let mut store = root.store();
        let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
        let (mut physics, resource, bytes) = physics_mesh_fixture();
        match case {
            0 => (),
            1 => {
                physics["colliders"][0]["shape"]["shape"]["geometry"]["sha256"] =
                    json!(raw_digest(b"other digest"))
            }
            2 => {
                physics["colliders"][0]["shape"]["shape"]["geometry"]["sizeBytes"] =
                    json!(bytes.len() + 1)
            }
            _ => {
                physics["colliders"][0]["shape"]["shape"]["geometry"]["mediaType"] =
                    json!("application/x-test-alternate")
            }
        }
        revise("PhysicsDefinition", &mut physics);
        store
            .validator
            .validate("PhysicsDefinition", &physics)
            .unwrap();
        let resources = if case == 0 {
            vec![]
        } else {
            vec![(resource, bytes)]
        };
        let batch = Batch::from_sources(
            &base,
            vec![(OwnedDocumentKind::PhysicsDefinition, physics)],
            resources,
        );
        let baseline = metadata_snapshot(&store);
        assert!(
            matches!(
                batch.commit(&mut store, &TestPermit::new(&root, &initial), &base),
                Err(StorageError::InvalidInput(message))
                    if message == "Owned source ResourceRef has no exact actual CAS association"
            ),
            "case {case}"
        );
        assert_unchanged(&store, &baseline, &base);
    }
}

#[test]
fn retained_physics_mesh_is_checked_when_new_prefab_binds_its_body() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let (physics, resource, bytes) = physics_mesh_fixture();
    let first = Batch::from_sources(
        &base,
        vec![(OwnedDocumentKind::PhysicsDefinition, physics)],
        vec![(resource.clone(), bytes.clone())],
    );
    let first_receipt = first
        .commit(&mut store, &TestPermit::new(&root, &initial), &base)
        .unwrap();

    // 새 Prefab의 physicsId/bodyId가 같은 실제 retained mesh Physics를
    // 참조한다. geometry bytes는 불투명하며 topology 검사는 여기서 하지 않는다.
    let second = physics_batch(&first.next, false, false, |_, _| ());
    let permit = TestPermit::new(&root, &initial);
    let second_receipt = second.commit(&mut store, &permit, &first.next).unwrap();
    assert_eq!(second_receipt.base_revision, first_receipt.project_revision);
    assert!(permit.0.final_rows_observed.get());
    assert_eq!(store.project(&initial.project_id).unwrap(), second.next);

    let mut owned = permit
        .owned_document_reader(MAX_OWNED_DOCUMENT_BYTES)
        .unwrap();
    let loaded_physics = owned
        .read_known_history_bytes(
            &store,
            &permit,
            &initial.project_id,
            &second_receipt.project_revision,
            &first.pins[0],
        )
        .unwrap();
    assert_eq!(loaded_physics.bytes, first.documents[0]);

    let query = ProjectResourceQuery::Current {
        resource_id: ResourceId::new("resource-physics-mesh").unwrap(),
    };
    let mut resources = permit.resource_reader(MAX_SOURCE_TOTAL).unwrap();
    let loaded_geometry = resources
        .read(
            &store,
            &permit,
            &ProjectResourceRequest {
                project: &initial.project_id,
                current_project_revision: &second_receipt.project_revision,
                query: &query,
                expected: Some(&resource),
            },
            MAX_SOURCE_TOTAL,
        )
        .unwrap();
    assert_eq!(loaded_geometry.bytes, bytes);
    assert_eq!(loaded_geometry.registered.blob.digest, raw_digest(&bytes));
    assert_eq!(
        loaded_geometry.registered.provenance,
        ProjectResourceProvenance::CurrentProject {
            project_revision: second_receipt.project_revision,
        }
    );
}

#[test]
fn integral_float_mesh_size_preserves_original_through_batch_and_retained_reads() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let (mut physics, resource, bytes) = physics_mesh_fixture();
    // 원 ResourceRef의 N.0과 등록 metadata의 정수 N은 수학적으로 같지만
    // 원 Physics 원문과 projected pin은 정규화된 복사본과 분리해 보존한다.
    let decimal = format!("{}.0", bytes.len());
    physics["colliders"][0]["shape"]["shape"]["geometry"]["sizeBytes"] =
        serde_json::from_str::<Value>(&decimal).unwrap();
    assert!(resource["sizeBytes"].is_u64());
    revise("PhysicsDefinition", &mut physics);
    store
        .validator
        .validate("PhysicsDefinition", &physics)
        .unwrap();

    let first = Batch::from_sources(
        &base,
        vec![(OwnedDocumentKind::PhysicsDefinition, physics)],
        vec![(resource.clone(), bytes.clone())],
    );
    let original = parse_json(&first.documents[0]).unwrap();
    assert!(original["colliders"][0]["shape"]["shape"]["geometry"]["sizeBytes"].is_f64());
    assert!(
        std::str::from_utf8(&first.documents[0])
            .unwrap()
            .contains(&format!("\"sizeBytes\": {decimal}"))
    );
    assert_eq!(
        verify_projected_digest("PhysicsDefinition", &original).unwrap(),
        first.pins[0].revision
    );
    let permit = TestPermit::new(&root, &initial);
    let first_receipt = first.commit(&mut store, &permit, &base).unwrap();
    let mut owned = permit
        .owned_document_reader(MAX_OWNED_DOCUMENT_BYTES)
        .unwrap();
    let loaded = owned
        .read_known_history_bytes(
            &store,
            &permit,
            &initial.project_id,
            &first_receipt.project_revision,
            &first.pins[0],
        )
        .unwrap();
    assert_eq!(loaded.bytes, first.documents[0]);
    assert_eq!(loaded.document, original);
    let query = ProjectResourceQuery::Current {
        resource_id: ResourceId::new("resource-physics-mesh").unwrap(),
    };
    let mut resources = permit.resource_reader(MAX_SOURCE_TOTAL).unwrap();
    let loaded = resources
        .read(
            &store,
            &permit,
            &ProjectResourceRequest {
                project: &initial.project_id,
                current_project_revision: &first_receipt.project_revision,
                query: &query,
                expected: Some(&resource),
            },
            MAX_SOURCE_TOTAL,
        )
        .unwrap();
    assert_eq!(loaded.bytes, bytes);
    assert_eq!(loaded.registered.blob.digest, raw_digest(&bytes));

    let second = physics_batch(&first.next, false, false, |_, _| ());
    let second_receipt = second.commit(&mut store, &permit, &first.next).unwrap();
    assert_eq!(second_receipt.base_revision, first_receipt.project_revision);
    let mut owned = permit
        .owned_document_reader(MAX_OWNED_DOCUMENT_BYTES)
        .unwrap();
    let retained = owned
        .read_known_history_bytes(
            &store,
            &permit,
            &initial.project_id,
            &second_receipt.project_revision,
            &first.pins[0],
        )
        .unwrap();
    assert_eq!(retained.bytes, first.documents[0]);
    assert_eq!(retained.document, original);
    assert_eq!(
        verify_projected_digest("PhysicsDefinition", &retained.document).unwrap(),
        first.pins[0].revision
    );
    let mut resources = permit.resource_reader(MAX_SOURCE_TOTAL).unwrap();
    let retained_geometry = resources
        .read(
            &store,
            &permit,
            &ProjectResourceRequest {
                project: &initial.project_id,
                current_project_revision: &second_receipt.project_revision,
                query: &query,
                expected: Some(&resource),
            },
            MAX_SOURCE_TOTAL,
        )
        .unwrap();
    assert_eq!(retained_geometry.bytes, bytes);
    assert_eq!(retained_geometry.registered.blob.digest, raw_digest(&bytes));
    assert_eq!(
        retained_geometry.registered.provenance,
        ProjectResourceProvenance::CurrentProject {
            project_revision: second_receipt.project_revision,
        }
    );
}

fn rounded_fraction_mesh_batch(base: &Value, preceding_documents: bool) -> (Batch, usize) {
    let (mut physics, resource, bytes) = physics_mesh_fixture();
    let integral_decimal = format!("{}.0", bytes.len());
    physics["colliders"][0]["shape"]["shape"]["geometry"]["sizeBytes"] =
        serde_json::from_str::<Value>(&integral_decimal).unwrap();
    revise("PhysicsDefinition", &mut physics);

    // The original example is a box. This derived mesh covers a ResourceRef
    // whose raw decimal rounds to the same binary64 Value as the accepted N.0.
    let mut sources = Vec::new();
    let mut resources = Vec::new();
    if preceding_documents {
        let initial = Batch::initial(base);
        sources.extend(
            initial
                .pins
                .iter()
                .zip(&initial.documents)
                .map(|(pin, document)| (pin.kind, parse_json(document).unwrap())),
        );
        resources.extend(initial.resources);
    }
    let index = sources.len();
    sources.push((OwnedDocumentKind::PhysicsDefinition, physics));
    resources.push((resource, bytes.clone()));
    let mut batch = Batch::from_sources(base, sources, resources);
    let original = batch.documents[index].clone();
    let original_value = parse_json(&original).unwrap();
    let text = String::from_utf8(original.clone()).unwrap();
    let needle = format!("\"sizeBytes\": {integral_decimal}");
    assert_eq!(text.matches(&needle).count(), 1);
    let fraction = format!("\"sizeBytes\": {}.0000000000000000000001", bytes.len());
    batch.documents[index] = text.replacen(&needle, &fraction, 1).into_bytes();
    assert_ne!(batch.documents[index], original);
    let parsed = parse_json(&batch.documents[index]).unwrap();
    assert_eq!(
        parsed, original_value,
        "the strict Value has already rounded the raw fraction"
    );
    assert_eq!(
        verify_projected_digest("PhysicsDefinition", &parsed).unwrap(),
        batch.pins[index].revision
    );
    assert!(PhysicsDefinition::from_value(&parsed).is_ok());
    (batch, index)
}

#[test]
fn raw_physics_fraction_that_rounds_to_integer_is_rejected_before_its_staging() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let (batch, index) = rounded_fraction_mesh_batch(&base, true);
    assert!(index > 0);
    let (_, mesh_bytes) = batch
        .resources
        .iter()
        .find(|(resource, _)| resource["resourceId"].as_str() == Some("resource-physics-mesh"))
        .unwrap();
    let mesh_blob = BlobRef {
        digest: raw_digest(mesh_bytes),
        byte_length: mesh_bytes.len() as u64,
    };
    let rejected_physics_blob = BlobRef {
        digest: raw_digest(&batch.documents[index]),
        byte_length: batch.documents[index].len() as u64,
    };
    let prior = BlobRef {
        digest: raw_digest(&batch.documents[0]),
        byte_length: batch.documents[0].len() as u64,
    };
    assert_ne!(mesh_blob.digest, rejected_physics_blob.digest);
    assert_ne!(prior.digest, mesh_blob.digest);
    assert_ne!(prior.digest, rejected_physics_blob.digest);
    for blob in [&mesh_blob, &rejected_physics_blob, &prior] {
        assert!(matches!(
            store.read_blob(blob),
            Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
        ));
    }
    let baseline = metadata_snapshot(&store);
    let permit = TestPermit::new(&root, &initial);
    let error = batch.commit(&mut store, &permit, &base).unwrap_err();
    assert!(matches!(
        error,
        StorageError::Contract(message)
            if message.contains("Physics collider 0 mesh sizeBytes is not an exact safe JSON integer")
    ));
    assert_unchanged(&store, &baseline, &base);
    assert!(!permit.0.final_rows_observed.get());

    // The rejected Physics and new mesh resource remain absent from CAS.
    // A previous non-Physics document was already staged; unchanged metadata
    // does not imply that its unreferenced CAS was removed.
    for blob in [&mesh_blob, &rejected_physics_blob] {
        assert!(matches!(
            store.read_blob(blob),
            Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
        ));
    }
    assert_eq!(store.read_blob(&prior).unwrap(), batch.documents[0]);
}

#[test]
fn raw_physics_fraction_does_not_replace_pin_or_original_cancel_error() {
    for bad_pin in [true, false] {
        let root = TestRoot::new();
        let mut store = root.store();
        let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
        let (mut batch, index) = rounded_fraction_mesh_batch(&base, false);
        let permit = TestPermit::new(&root, &initial);
        if bad_pin {
            batch.pins[index].revision = raw_digest(b"different owned revision");
            batch.next["ownedResources"][index] = json!(batch.pins[index]);
            revise("Project", &mut batch.next);
        } else {
            permit.0.cancelled.set(true);
        }
        let baseline = metadata_snapshot(&store);
        let error = batch.commit(&mut store, &permit, &base).unwrap_err();
        if bad_pin {
            assert!(
                matches!(
                    error,
                    StorageError::Contract(message)
                        if message == "Owned document differs from its canonical identity/revision pin"
                ),
                "the original pin failure must precede the added exact check"
            );
        } else {
            assert!(matches!(
                error,
                StorageError::InvalidTransition(message) if message.contains("cancelled")
            ));
        }
        assert_unchanged(&store, &baseline, &base);
    }
}

#[test]
fn actual_scoped_mesh_denial_precedes_same_request_raw_physics_fraction() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let (_, mesh_resource, mesh_bytes) = physics_mesh_fixture();
    let first = Batch::from_sources(&base, vec![], vec![(mesh_resource, mesh_bytes)]);
    let first_receipt = first
        .commit(&mut store, &TestPermit::new(&root, &initial), &base)
        .unwrap();
    assert_eq!(first_receipt.project_revision, revision(&first.next));

    // The same requested Physics document has a schema-valid parsed Value but
    // a fractional raw size token. Its mesh is already registered, so resource
    // authorization must run against the actual current Project membership.
    let (mut batch, _) = rounded_fraction_mesh_batch(&first.next, false);
    batch.resources.clear();
    let ids = batch.next["resourceIds"].as_array_mut().unwrap();
    let removed = ids.pop().unwrap();
    assert_eq!(removed.as_str(), Some("resource-physics-mesh"));
    revise("Project", &mut batch.next);

    let permit = TestPermit::new(&root, &initial);
    permit.0.deny_mesh_after_actual_checks.set(true);
    let baseline = metadata_snapshot(&store);
    assert!(matches!(
        batch.commit(&mut store, &permit, &first.next),
        Err(StorageError::Conflict("Authored scoped resource denied"))
    ));
    assert!(permit.0.mesh_denial_observed.get());
    assert_unchanged(&store, &baseline, &first.next);
}

#[test]
fn retained_physics_mesh_missing_current_resource_provenance_fails_closed() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let (physics, resource, bytes) = physics_mesh_fixture();
    let first = Batch::from_sources(
        &base,
        vec![(OwnedDocumentKind::PhysicsDefinition, physics)],
        vec![(resource.clone(), bytes)],
    );
    let first_receipt = first
        .commit(&mut store, &TestPermit::new(&root, &initial), &base)
        .unwrap();
    // 이 test Store의 현재 revision에서 geometry provenance만 제거한다.
    // 전체 carried-resource 재검사가 먼저 거절할 수 있으므로 이 사례는
    // retained physics 전용 검사 분기의 도달을 따로 증명하지 않는다.
    let removed = store.connection.execute(
        "DELETE FROM project_resource_provenance WHERE project_id=?1 AND project_revision=?2 AND resource_id=?3 AND digest=?4",
        params![initial.project_id.as_str(), first_receipt.project_revision.as_str(),
            resource["resourceId"].as_str().unwrap(), resource["sha256"].as_str().unwrap()],
    ).unwrap();
    assert_eq!(removed, 1);
    let baseline = metadata_snapshot(&store);
    let batch = physics_batch(&first.next, false, false, |_, _| ());
    assert!(
        batch
            .commit(&mut store, &TestPermit::new(&root, &initial), &first.next)
            .is_err()
    );
    assert_unchanged(&store, &baseline, &first.next);
}

#[test]
fn command_module_source_is_committed_with_its_actual_prefab_and_provenance() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let batch = command_batch(&base, |_, _| ());
    let permit = TestPermit::new(&root, &initial);
    let receipt = batch.commit(&mut store, &permit, &base).unwrap();
    assert!(permit.0.final_rows_observed.get());
    assert_eq!(store.project(&initial.project_id).unwrap(), batch.next);
    assert_eq!(batch.next["prefabIds"].as_array().unwrap().len(), 1);
    assert_eq!(batch.next["instanceIds"].as_array().unwrap().len(), 1);
    assert_eq!(
        receipt.documents[0].0.kind,
        OwnedDocumentKind::CommandModule
    );
    assert_eq!(
        store.read_blob(&receipt.documents[0].1).unwrap(),
        batch.documents[0]
    );
    let mut reader = permit
        .owned_document_reader(MAX_OWNED_DOCUMENT_BYTES)
        .unwrap();
    let loaded = reader
        .read_known_history_bytes(
            &store,
            &permit,
            &initial.project_id,
            &receipt.project_revision,
            &batch.pins[0],
        )
        .unwrap();
    assert_eq!(loaded.bytes, batch.documents[0]);
    assert_eq!(loaded.blob, receipt.documents[0].1);

    let baseline = metadata_snapshot(&store);
    assert!(matches!(
        batch.commit(&mut store, &permit, &base),
        Err(StorageError::Conflict(_))
    ));
    assert_unchanged(&store, &baseline, &batch.next);
}

#[test]
fn command_module_missing_owner_membership_or_origin_publishes_no_metadata() {
    for case in 0..3 {
        let root = TestRoot::new();
        let mut store = root.store();
        let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
        let batch = command_batch(&base, |prefab, module| match case {
            0 => module["ownerPrefabId"] = json!("prefab-missing"),
            1 => prefab["commandModuleIds"] = json!([]),
            _ => module["localOriginNodeId"] = json!("missing-node"),
        });
        let baseline = metadata_snapshot(&store);
        let expected = if case == 0 {
            "Native source has no owned Prefab membership"
        } else {
            "Native CommandModule owner, membership or origin differs"
        };
        assert!(
            matches!(
                batch.commit(&mut store, &TestPermit::new(&root, &initial), &base),
                Err(StorageError::InvalidInput(message)) if message == expected
            ),
            "case {case}"
        );
        assert_unchanged(&store, &baseline, &base);
    }
}

#[test]
fn command_module_transaction_cancellation_rolls_back_metadata() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let batch = command_batch(&base, |_, _| ());
    let baseline = metadata_snapshot(&store);
    let permit = TestPermit::with_failure(&root, &initial, FinalFailure::Cancel);
    assert!(batch.commit(&mut store, &permit, &base).is_err());
    assert!(permit.0.final_rows_observed.get());
    assert_unchanged(&store, &baseline, &base);
}

#[test]
fn retained_prefab_and_module_are_checked_by_actual_body_in_both_directions() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let first = command_batch(&base, |_, _| ());
    first
        .commit(&mut store, &TestPermit::new(&root, &initial), &base)
        .unwrap();
    let baseline = metadata_snapshot(&store);

    // The retained Prefab does not reciprocally list this new module.
    let mut module = example("command-module.json");
    module["moduleId"] = json!("module-other");
    revise("CommandModule", &mut module);
    let new_module = Batch::from_sources(
        &first.next,
        vec![(OwnedDocumentKind::CommandModule, module)],
        vec![],
    );
    assert!(matches!(
        new_module.commit(&mut store, &TestPermit::new(&root, &initial), &first.next),
        Err(StorageError::InvalidInput(message)) if message == "Native CommandModule owner, membership or origin differs"
    ));
    assert_unchanged(&store, &baseline, &first.next);

    // The retained module belongs to the original Prefab, not this new one.
    let mut prefab = parse_json(&first.documents[1]).unwrap();
    prefab["prefabId"] = json!("prefab-other");
    revise("Prefab", &mut prefab);
    let new_prefab = Batch::from_sources(
        &first.next,
        vec![(OwnedDocumentKind::Prefab, prefab)],
        vec![],
    );
    assert!(matches!(
        new_prefab.commit(&mut store, &TestPermit::new(&root, &initial), &first.next),
        Err(StorageError::InvalidInput(message)) if message == "Native CommandModule owner, membership or origin differs"
    ));
    assert_unchanged(&store, &baseline, &first.next);
}

// 고정된 test table의 전체 SQL 내용을 비교한다. count만으로 head/body
// 덮어쓰기를 감지할 수 없어 schema 존재와 각 행도 rollback 판정에 포함한다.
type MetadataRows = Vec<Vec<String>>;
type TableSnapshot = (String, Option<(String, MetadataRows)>);

fn metadata_snapshot(store: &DurableStore) -> Vec<TableSnapshot> {
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
        "owned_documents",
        "owned_document_provenance",
        "operations",
        "invocations",
        "events",
        "write_fences",
    ]
    .into_iter()
    .map(|table| {
        let schema: Option<String> = store
            .connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        let content = schema.map(|schema| {
            let mut statement = store
                .connection
                .prepare(&format!("SELECT * FROM {table}"))
                .unwrap();
            let columns = statement.column_count();
            let mut rows: Vec<Vec<String>> = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get_ref(column).map(|value| format!("{value:?}")))
                        .collect()
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            rows.sort();
            (schema, rows)
        });
        (table.to_owned(), content)
    })
    .collect()
}
fn assert_unchanged(store: &DurableStore, baseline: &[TableSnapshot], base: &Value) {
    assert_eq!(metadata_snapshot(store).as_slice(), baseline);
    let project = ProjectId::new(base["projectId"].as_str().unwrap()).unwrap();
    assert_eq!(store.project(&project).unwrap(), *base);
    assert!(
        store
            .connection
            .prepare("PRAGMA foreign_key_check")
            .unwrap()
            .query([])
            .unwrap()
            .next()
            .unwrap()
            .is_none()
    );
}

#[test]
fn raw_sources_project_and_initial_policy_survive_gc_and_reopen() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let batch = Batch::initial(&base);
    let permit = TestPermit::new(&root, &initial);
    let receipt = batch.commit(&mut store, &permit, &base).unwrap();
    assert_eq!(receipt.base_revision, revision(&base));
    assert_eq!(
        receipt.project_revision,
        verify_projected_digest("Project", &batch.next).unwrap()
    );
    assert_eq!(
        receipt.project_blob.digest,
        raw_digest(&raw_json(&batch.next))
    );
    assert_ne!(receipt.project_blob.digest, receipt.project_revision);
    assert_eq!(
        store.read_blob(&receipt.project_blob).unwrap(),
        raw_json(&batch.next)
    );
    assert!(permit.0.final_rows_observed.get());
    for ((pin, bytes), (actual_pin, blob)) in batch
        .pins
        .iter()
        .zip(&batch.documents)
        .zip(&receipt.documents)
    {
        assert_eq!(pin, actual_pin);
        assert_eq!(blob.digest, raw_digest(bytes));
        assert_ne!(blob.digest, pin.revision);
        assert_eq!(store.read_blob(blob).unwrap(), *bytes);
        let parsed = parse_json(bytes).unwrap();
        assert_eq!(
            verify_projected_digest(pin.kind.definition(), &parsed).unwrap(),
            pin.revision
        );
    }
    let owner_record: (String, String, String, String) = store.connection.query_row(
        "SELECT owner_principal,initial_revision,policy_resource_id,policy_digest FROM native_project_owners WHERE project_id=?1",
        [initial.project_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).unwrap();
    assert_eq!(owner_record.0, initial.owner_principal.as_str());
    assert_eq!(owner_record.1, initial.project_revision.as_str());
    assert_eq!(owner_record.2, "policy-local");
    let policy_bytes = canonical_bytes(&example("policy.json")).unwrap();
    assert_eq!(owner_record.3, raw_digest(&policy_bytes).as_str());
    let policy_digest: Sha256Digest =
        serde_json::from_value(initial.policy_resource["sha256"].clone()).unwrap();
    assert_eq!(policy_digest, raw_digest(&policy_bytes));
    assert_eq!(
        canonical_digest(&example("policy.json")).unwrap(),
        policy_digest
    );
    store
        .put_blob(b"native source test unreferenced orphan")
        .unwrap();
    assert_eq!(store.collect_orphan_blobs(100).unwrap().removed_blobs, 1);
    drop(store);
    let store = root.store();
    assert_eq!(store.project(&initial.project_id).unwrap(), batch.next);
    assert_eq!(
        registered_native_project_owner(&store, &initial.project_id).unwrap(),
        initial.owner_principal
    );
    let permit = TestPermit::new(&root, &initial);
    let mut owned = permit
        .owned_document_reader(MAX_OWNED_DOCUMENT_BYTES)
        .unwrap();
    for (pin, bytes) in batch.pins.iter().zip(&batch.documents) {
        let loaded = owned
            .read_known_history_bytes(
                &store,
                &permit,
                &initial.project_id,
                &receipt.project_revision,
                pin,
            )
            .unwrap();
        assert_eq!(loaded.bytes, *bytes);
        assert_eq!(loaded.blob.digest, raw_digest(bytes));
    }
    let mut resources = permit.resource_reader(MAX_SOURCE_TOTAL).unwrap();
    for id in ["policy-local", "resource-wall-blocks"] {
        let query = ProjectResourceQuery::Current {
            resource_id: ResourceId::new(id).unwrap(),
        };
        let loaded = resources
            .read(
                &store,
                &permit,
                &ProjectResourceRequest {
                    project: &initial.project_id,
                    current_project_revision: &receipt.project_revision,
                    query: &query,
                    expected: Some(if id == "policy-local" {
                        &initial.policy_resource
                    } else {
                        &batch.resources[0].0
                    }),
                },
                MAX_SOURCE_TOTAL,
            )
            .unwrap();
        assert_eq!(
            loaded.registered.provenance,
            ProjectResourceProvenance::CurrentProject {
                project_revision: receipt.project_revision.clone()
            }
        );
        let expected = if id == "policy-local" {
            &policy_bytes
        } else {
            &batch.resources[0].1
        };
        assert_eq!(loaded.bytes, *expected);
        assert_eq!(loaded.registered.blob.digest, raw_digest(expected));
    }
}

#[test]
fn later_revision_carries_exact_document_and_resource_provenance() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let first = Batch::initial(&base);
    let first_receipt = first
        .commit(&mut store, &TestPermit::new(&root, &initial), &base)
        .unwrap();
    let mut clip = example("animation-clip.json");
    clip["clipId"] = json!("clip-door-second");
    revise("AnimationClip", &mut clip);
    let second = Batch::from_sources(
        &first.next,
        vec![(OwnedDocumentKind::AnimationClip, clip)],
        vec![],
    );
    let second_receipt = second
        .commit(&mut store, &TestPermit::new(&root, &initial), &first.next)
        .unwrap();
    assert_eq!(second_receipt.base_revision, first_receipt.project_revision);
    assert_eq!(second_receipt.documents.len(), 1);
    for pin in &first.pins {
        for revision in [
            &first_receipt.project_revision,
            &second_receipt.project_revision,
        ] {
            let actual: String = store.connection.query_row(
                "SELECT revision FROM owned_document_provenance WHERE project_id=?1 AND project_revision=?2 AND kind=?3 AND object_id=?4",
                params![initial.project_id.as_str(), revision.as_str(), pin.kind.as_str(), pin.object_id.as_str()], |row| row.get(0),
            ).unwrap();
            assert_eq!(actual, pin.revision.as_str());
        }
    }
    for id in ["policy-local", "resource-wall-blocks"] {
        let first_digest: String = store.connection.query_row(
            "SELECT digest FROM project_resource_provenance WHERE project_id=?1 AND project_revision=?2 AND resource_id=?3",
            params![initial.project_id.as_str(),first_receipt.project_revision.as_str(),id], |row| row.get(0),
        ).unwrap();
        let second_digest: String = store.connection.query_row(
            "SELECT digest FROM project_resource_provenance WHERE project_id=?1 AND project_revision=?2 AND resource_id=?3",
            params![initial.project_id.as_str(),second_receipt.project_revision.as_str(),id], |row| row.get(0),
        ).unwrap();
        assert_eq!(first_digest, second_digest);
    }
    let permit = TestPermit::new(&root, &initial);
    let mut reader = permit
        .owned_document_reader(MAX_OWNED_DOCUMENT_BYTES)
        .unwrap();
    for (pin, bytes) in first.pins.iter().zip(&first.documents) {
        assert_eq!(
            reader
                .read_known_history_bytes(
                    &store,
                    &permit,
                    &initial.project_id,
                    &second_receipt.project_revision,
                    pin
                )
                .unwrap()
                .bytes,
            *bytes
        );
    }
}

#[test]
fn stale_head_and_repeated_owned_identity_do_not_publish_metadata() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let first = Batch::initial(&base);
    first
        .commit(&mut store, &TestPermit::new(&root, &initial), &base)
        .unwrap();
    let baseline = metadata_snapshot(&store);
    assert!(matches!(
        first.commit(&mut store, &TestPermit::new(&root, &initial), &base),
        Err(StorageError::Conflict(_))
    ));
    assert_unchanged(&store, &baseline, &first.next);
    let duplicate = Batch::initial(&first.next);
    assert!(
        duplicate
            .commit(&mut store, &TestPermit::new(&root, &initial), &first.next)
            .is_err()
    );
    assert_unchanged(&store, &baseline, &first.next);
}

#[test]
fn duplicate_pin_identity_body_revision_and_schema_fail_closed() {
    for case in 0..4 {
        let root = TestRoot::new();
        let mut store = root.store();
        let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
        let mut batch = Batch::initial(&base);
        match case {
            0 => {
                batch.pins.push(batch.pins[0].clone());
                batch.documents.push(batch.documents[0].clone());
            }
            1 => {
                batch.pins[0].object_id = ObjectId::new("prefab-wrong-pin").unwrap();
            }
            2 => {
                let mut document = parse_json(&batch.documents[0]).unwrap();
                document["name"] = json!("changed body with old revision");
                batch.documents[0] = raw_json(&document);
            }
            _ => {
                let mut document = parse_json(&batch.documents[0]).unwrap();
                document["contractVersion"] = json!("0.1.0");
                revise("Prefab", &mut document);
                batch.replace_document(0, &document);
            }
        }
        let baseline = metadata_snapshot(&store);
        assert!(
            batch
                .commit(&mut store, &TestPermit::new(&root, &initial), &base)
                .is_err(),
            "case {case}"
        );
        assert_unchanged(&store, &baseline, &base);
    }
}

#[test]
fn raw_resource_digest_length_and_exact_owned_reference_mismatch_are_rejected() {
    for case in 0..4 {
        let root = TestRoot::new();
        let mut store = root.store();
        let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
        let mut batch = Batch::initial(&base);
        match case {
            0 => batch.resources[0].0["sha256"] = json!(raw_digest(b"other raw bytes")),
            1 => batch.resources[0].0["sizeBytes"] = json!(batch.resources[0].1.len() + 1),
            2 => {
                let mut prefab = parse_json(&batch.documents[0]).unwrap();
                prefab["resources"][0]["mediaType"] = json!("application/octet-stream");
                revise("Prefab", &mut prefab);
                batch.replace_document(0, &prefab);
            }
            _ => {
                let mut instance = parse_json(&batch.documents[1]).unwrap();
                instance["prefabRevision"] = json!(raw_digest(b"unowned prefab revision"));
                revise("Instance", &mut instance);
                batch.replace_document(1, &instance);
            }
        }
        let baseline = metadata_snapshot(&store);
        assert!(
            batch
                .commit(&mut store, &TestPermit::new(&root, &initial), &base)
                .is_err(),
            "case {case}"
        );
        assert_unchanged(&store, &baseline, &base);
    }
}

// Exercise the public Runtime source entry with the exact descriptor bytes,
// instead of serializing a Value and losing the author's numeric lexeme.
fn commit_with_resource_metadata(
    batch: &Batch,
    store: &mut DurableStore,
    permit: &TestPermit,
    base: &Value,
    metadata: &[u8],
) -> StorageResult<NativeOwnedSourceCommitReceipt> {
    assert_eq!(batch.resources.len(), 1);
    let project: ProjectId = serde_json::from_value(base["projectId"].clone()).unwrap();
    let expected_revision = revision(base);
    let project_bytes = raw_json(&batch.next);
    let documents: Vec<_> = batch
        .pins
        .iter()
        .zip(&batch.documents)
        .map(|(pin, bytes)| NativeOwnedDocumentSource { pin, bytes })
        .collect();
    let resources = [NativeOwnedResourceSource::Raw {
        metadata,
        bytes: &batch.resources[0].1,
    }];
    commit_native_owned_sources(
        store,
        permit,
        &NativeOwnedSourceCommitRequest {
            project: &project,
            expected_revision: &expected_revision,
            project_bytes: &project_bytes,
            documents: &documents,
            resources: &resources,
        },
    )
}

fn resource_metadata_with_size_lexeme(resource: &Value, lexeme: &str) -> Vec<u8> {
    let original = String::from_utf8(raw_json(resource)).unwrap();
    let needle = format!("\"sizeBytes\": {}", resource["sizeBytes"].as_u64().unwrap());
    assert_eq!(original.matches(&needle).count(), 1);
    original
        .replacen(&needle, &format!("\"sizeBytes\": {lexeme}"), 1)
        .into_bytes()
}

#[test]
fn raw_resource_metadata_exact_decimal_is_normalized_only_for_registration() {
    for lexeme in ["1.0", "1e0"] {
        let root = TestRoot::new();
        let mut store = root.store();
        let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
        let bytes = vec![b'a'];
        let resource = json!({
            "resourceId": "resource-decimal-metadata",
            "sha256": raw_digest(&bytes),
            "mediaType": "application/octet-stream",
            "sizeBytes": 1,
        });
        let metadata = resource_metadata_with_size_lexeme(&resource, lexeme);
        let original = parse_json(&metadata).unwrap();
        assert_ne!(original["sizeBytes"], resource["sizeBytes"]);
        let batch = Batch::from_sources(&base, vec![], vec![(resource.clone(), bytes.clone())]);
        let permit = TestPermit::new(&root, &initial);
        let receipt =
            commit_with_resource_metadata(&batch, &mut store, &permit, &base, &metadata).unwrap();
        assert_eq!(receipt.project_revision, revision(&batch.next));
        let id = ResourceId::new("resource-decimal-metadata").unwrap();
        let query = ProjectResourceQuery::Current { resource_id: id };
        let registered = permit
            .resource_reader(MAX_SOURCE_TOTAL)
            .unwrap()
            .read(
                &store,
                &permit,
                &ProjectResourceRequest {
                    project: &initial.project_id,
                    current_project_revision: &receipt.project_revision,
                    query: &query,
                    expected: Some(&resource),
                },
                MAX_SOURCE_TOTAL,
            )
            .unwrap();
        assert_eq!(registered.registered.resource, resource);
        assert_eq!(registered.bytes, bytes);
        assert_eq!(parse_json(&metadata).unwrap(), original);
    }
}

#[test]
fn rounded_raw_resource_fraction_rejects_before_resource_and_physics_stage() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let (physics, resource, bytes) = physics_mesh_fixture();
    let lexeme = format!("{}.0000000000000000000001", bytes.len());
    let metadata = resource_metadata_with_size_lexeme(&resource, &lexeme);
    let parsed = parse_json(&metadata).unwrap();
    assert_eq!(parsed["sizeBytes"].as_f64(), Some(bytes.len() as f64));
    let batch = Batch::from_sources(
        &base,
        vec![(OwnedDocumentKind::PhysicsDefinition, physics)],
        vec![(resource, bytes.clone())],
    );
    let resource_blob = BlobRef {
        digest: raw_digest(&bytes),
        byte_length: bytes.len() as u64,
    };
    let physics_blob = BlobRef {
        digest: raw_digest(&batch.documents[0]),
        byte_length: batch.documents[0].len() as u64,
    };
    for blob in [&resource_blob, &physics_blob] {
        assert!(
            matches!(store.read_blob(blob), Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
        );
    }
    let baseline = metadata_snapshot(&store);
    let permit = TestPermit::new(&root, &initial);
    let error =
        commit_with_resource_metadata(&batch, &mut store, &permit, &base, &metadata).unwrap_err();
    assert!(matches!(error, StorageError::Contract(message)
        if message.contains("ResourceRef sizeBytes is not an exact safe JSON integer")));
    assert_unchanged(&store, &baseline, &base);
    assert!(!permit.0.final_rows_observed.get());
    for blob in [&resource_blob, &physics_blob] {
        assert!(
            matches!(store.read_blob(blob), Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
        );
    }
}

#[test]
fn value_only_retained_decimal_metadata_does_not_gain_raw_witness() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let bytes = vec![b'a'];
    let resource = json!({
        "resourceId": "resource-value-only-decimal",
        "sha256": raw_digest(&bytes),
        "mediaType": "application/octet-stream",
        "sizeBytes": 1,
    });
    store.put_blob(&bytes).unwrap();
    register_resource(
        &mut store,
        &resource,
        ResourceOwner::Project(initial.project_id.clone()),
    )
    .unwrap();
    let batch = Batch::from_sources(&base, vec![], vec![(resource.clone(), bytes)]);
    let mut unproven = resource.clone();
    unproven["sizeBytes"] = json!(1.0);
    let retained = [NativeOwnedResourceSource::Retained {
        resource: &unproven,
    }];
    let project_bytes = raw_json(&batch.next);
    let baseline = metadata_snapshot(&store);
    let result = commit_native_owned_sources(
        &mut store,
        &TestPermit::new(&root, &initial),
        &NativeOwnedSourceCommitRequest {
            project: &initial.project_id,
            expected_revision: &initial.project_revision,
            project_bytes: &project_bytes,
            documents: &[],
            resources: &retained,
        },
    );
    assert!(matches!(result, Err(StorageError::Contract(message))
        if message == "Native artifact ResourceRef is invalid"));
    assert_unchanged(&store, &baseline, &base);
}

#[test]
fn raw_decimal_for_current_resource_preserves_registration_and_acl_priority() {
    for denied in [false, true] {
        let root = TestRoot::new();
        let mut store = root.store();
        let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
        let (physics, resource, bytes) = physics_mesh_fixture();
        let first = Batch::from_sources(&base, vec![], vec![(resource.clone(), bytes.clone())]);
        first
            .commit(&mut store, &TestPermit::new(&root, &initial), &base)
            .unwrap();

        let mut second = Batch::from_sources(
            &first.next,
            vec![(OwnedDocumentKind::PhysicsDefinition, physics)],
            vec![],
        );
        // This is an already-current resource; do not append its Project ID a
        // second time. The raw descriptor is still independently checked.
        second.resources.push((resource.clone(), bytes.clone()));
        let lexeme = if denied {
            format!("{}.0000000000000000000001", bytes.len())
        } else {
            format!("{}.0", bytes.len())
        };
        let metadata = resource_metadata_with_size_lexeme(&resource, &lexeme);
        let permit = TestPermit::new(&root, &initial);
        permit.0.deny_mesh_after_actual_checks.set(denied);
        let baseline = metadata_snapshot(&store);
        let result =
            commit_with_resource_metadata(&second, &mut store, &permit, &first.next, &metadata);
        if denied {
            assert!(matches!(
                result,
                Err(StorageError::Conflict("Authored scoped resource denied"))
            ));
            assert!(permit.0.mesh_denial_observed.get());
            assert_unchanged(&store, &baseline, &first.next);
        } else {
            let receipt = result.unwrap();
            assert_eq!(receipt.project_revision, revision(&second.next));
            let sql: String = store.connection.query_row(
                "SELECT resource_json FROM project_resource_versions WHERE project_id=?1 AND resource_id=?2 AND digest=?3",
                params![initial.project_id.as_str(), "resource-physics-mesh", resource["sha256"].as_str().unwrap()],
                |row| row.get(0),
            ).unwrap();
            assert_eq!(parse_json(sql.as_bytes()).unwrap(), resource);
        }
    }
}

#[test]
fn project_nonmembership_change_and_missing_membership_are_rejected() {
    for case in 0..2 {
        let root = TestRoot::new();
        let mut store = root.store();
        let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
        let mut batch = Batch::initial(&base);
        if case == 0 {
            batch.next["name"] = json!("unauthorized simultaneous project edit");
        } else {
            batch.next["ownedResources"].as_array_mut().unwrap().pop();
        }
        revise("Project", &mut batch.next);
        let baseline = metadata_snapshot(&store);
        assert!(
            batch
                .commit(&mut store, &TestPermit::new(&root, &initial), &base)
                .is_err()
        );
        assert_unchanged(&store, &baseline, &base);
    }
}

#[test]
fn cross_project_authority_and_globally_owned_resource_id_conflict_rollback() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let (other_base, other) = bootstrap(&mut store, &root, "project-other", "policy-other");
    let other_batch = Batch::initial(&other_base);
    let baseline = metadata_snapshot(&store);
    assert!(
        other_batch
            .commit(&mut store, &TestPermit::new(&root, &initial), &other_base)
            .is_err()
    );
    assert_unchanged(&store, &baseline, &base);
    let batch = Batch::initial(&base);
    store.put_blob(&batch.resources[0].1).unwrap();
    register_resource(
        &mut store,
        &batch.resources[0].0,
        ResourceOwner::Project(other.project_id),
    )
    .unwrap();
    let baseline = metadata_snapshot(&store);
    assert!(
        batch
            .commit(&mut store, &TestPermit::new(&root, &initial), &base)
            .is_err()
    );
    assert_unchanged(&store, &baseline, &base);
    assert!(store.connection.is_autocommit());
}

#[test]
fn existing_same_project_artifact_outside_base_requires_checked_retained_input() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let batch = Batch::initial(&base);
    let resource = &batch.resources[0].0;
    let bytes = &batch.resources[0].1;
    assert!(
        !base["resourceIds"]
            .as_array()
            .unwrap()
            .contains(&resource["resourceId"])
    );
    let actual_blob = store.put_blob(bytes).unwrap();
    register_resource(
        &mut store,
        resource,
        ResourceOwner::Project(initial.project_id.clone()),
    )
    .unwrap();
    let baseline = metadata_snapshot(&store);
    let permit = TestPermit::new(&root, &initial);
    assert!(matches!(
        batch.commit(&mut store, &permit, &base),
        Err(StorageError::Conflict(
            "Raw native resource input requires a new resource ID"
        )),
    ));
    assert_unchanged(&store, &baseline, &base);
    assert!(store.connection.is_autocommit());
    assert_eq!(store.read_blob(&actual_blob).unwrap(), *bytes);

    // 같은 실제 registration은 current ACL과 immutable artifact provenance를
    // 확인하는 checked reader 경로로 읽고 Retained 입력으로 연결할 수 있다.
    let mut reader = permit.resource_reader(MAX_SOURCE_TOTAL).unwrap();
    let query = ProjectResourceQuery::RegisteredImmutable {
        resource_id: ResourceId::new(resource["resourceId"].as_str().unwrap()).unwrap(),
    };
    let registered = reader
        .metadata(
            &store,
            &permit,
            &ProjectResourceRequest {
                project: &initial.project_id,
                current_project_revision: &initial.project_revision,
                query: &query,
                expected: Some(resource),
            },
        )
        .unwrap();
    assert_eq!(registered.resource, *resource);
    assert_eq!(registered.blob, actual_blob);
    assert_eq!(
        registered.provenance,
        ProjectResourceProvenance::ImmutableProjectArtifact,
    );
    assert_unchanged(&store, &baseline, &base);
    let documents: Vec<_> = batch
        .pins
        .iter()
        .zip(&batch.documents)
        .map(|(pin, bytes)| NativeOwnedDocumentSource { pin, bytes })
        .collect();
    let resources = [NativeOwnedResourceSource::Retained { resource }];
    let project_bytes = raw_json(&batch.next);
    let receipt = commit_native_owned_sources(
        &mut store,
        &permit,
        &NativeOwnedSourceCommitRequest {
            project: &initial.project_id,
            expected_revision: &initial.project_revision,
            project_bytes: &project_bytes,
            documents: &documents,
            resources: &resources,
        },
    )
    .unwrap();
    assert_eq!(store.project(&initial.project_id).unwrap(), batch.next);
    let query = ProjectResourceQuery::Current {
        resource_id: ResourceId::new(resource["resourceId"].as_str().unwrap()).unwrap(),
    };
    let loaded = reader
        .read(
            &store,
            &permit,
            &ProjectResourceRequest {
                project: &initial.project_id,
                current_project_revision: &receipt.project_revision,
                query: &query,
                expected: Some(resource),
            },
            MAX_SOURCE_TOTAL,
        )
        .unwrap();
    assert_eq!(loaded.bytes, *bytes);
    assert_eq!(loaded.registered.blob, actual_blob);
    assert_eq!(
        loaded.registered.provenance,
        ProjectResourceProvenance::CurrentProject {
            project_revision: receipt.project_revision,
        },
    );
}

#[test]
fn final_project_head_sql_abort_rolls_back_all_provisional_associations() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let batch = Batch::initial(&base);
    store.connection.execute_batch(
        "CREATE TRIGGER native_source_test_abort BEFORE UPDATE ON project_heads BEGIN SELECT RAISE(ABORT,'authored final head failure'); END;",
    ).unwrap();
    let baseline = metadata_snapshot(&store);
    let permit = TestPermit::new(&root, &initial);
    assert!(matches!(
        batch.commit(&mut store, &permit, &base),
        Err(StorageError::Sqlite(_))
    ));
    assert!(permit.0.final_rows_observed.get());
    assert_unchanged(&store, &baseline, &base);
    assert!(store.connection.is_autocommit());
    // 실패 시 먼저 staged된 CAS와 rollback된 SQL 참조를 구분한다.
    assert!(store.collect_orphan_blobs(100).unwrap().removed_blobs >= 5);
    store
        .connection
        .execute_batch("DROP TRIGGER native_source_test_abort;")
        .unwrap();
    drop(store);
    let store = root.store();
    assert_unchanged(&store, &baseline, &base);
}

#[test]
fn final_cancellation_rolls_back_after_every_source_was_provisionally_registered() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let batch = Batch::initial(&base);
    let baseline = metadata_snapshot(&store);
    let permit = TestPermit::with_failure(&root, &initial, FinalFailure::Cancel);
    let error = batch.commit(&mut store, &permit, &base).unwrap_err();
    assert!(
        matches!(&error, StorageError::InvalidTransition(message) if message.contains("cancelled"))
    );
    assert!(permit.0.final_rows_observed.get());
    assert_unchanged(&store, &baseline, &base);
    assert!(store.connection.is_autocommit());
}

#[test]
fn final_actual_owner_revocation_rolls_back_metadata_and_owner_change() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let batch = Batch::initial(&base);
    let baseline = metadata_snapshot(&store);
    let permit = TestPermit::with_failure(&root, &initial, FinalFailure::RevokeOwner);
    assert!(matches!(
        batch.commit(&mut store, &permit, &base),
        Err(StorageError::Conflict(_))
    ));
    assert!(permit.0.final_rows_observed.get());
    assert_unchanged(&store, &baseline, &base);
    assert_eq!(
        registered_native_project_owner(&store, &initial.project_id).unwrap(),
        initial.owner_principal
    );
    assert!(store.connection.is_autocommit());
}

#[test]
fn final_original_deadline_expiry_preserves_no_success_receipt_or_metadata() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let batch = Batch::initial(&base);
    let baseline = metadata_snapshot(&store);
    let permit = TestPermit::with_failure(&root, &initial, FinalFailure::Deadline);
    assert!(
        matches!(batch.commit(&mut store, &permit, &base), Err(StorageError::InvalidTransition(message)) if message.contains("deadline"))
    );
    assert!(permit.0.final_rows_observed.get());
    assert_unchanged(&store, &baseline, &base);
}

#[test]
fn canonical_public_writer_cannot_overwrite_same_pin_original_raw_source() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let batch = Batch::initial(&base);
    let receipt = batch
        .commit(&mut store, &TestPermit::new(&root, &initial), &base)
        .unwrap();
    let pin = &batch.pins[0];
    let original = &batch.documents[0];
    let parsed = parse_json(original).unwrap();
    let canonical = canonical_bytes(&parsed).unwrap();
    assert_eq!(
        verify_projected_digest("Prefab", &parsed).unwrap(),
        pin.revision
    );
    assert_ne!(canonical, *original);
    assert_ne!(raw_digest(&canonical), receipt.documents[0].1.digest);
    let baseline = metadata_snapshot(&store);
    assert!(matches!(
        crate::storage::owned_documents::register_owned_document(
            &mut store,
            &initial.project_id,
            &receipt.project_revision,
            pin,
            &parsed,
        ),
        Err(StorageError::Conflict("Immutable owned-document pin")),
    ));
    assert_unchanged(&store, &baseline, &batch.next);
    assert!(store.connection.is_autocommit());
    let permit = TestPermit::new(&root, &initial);
    let mut reader = permit
        .owned_document_reader(MAX_OWNED_DOCUMENT_BYTES)
        .unwrap();
    let loaded = reader
        .read_known_history_bytes(
            &store,
            &permit,
            &initial.project_id,
            &receipt.project_revision,
            pin,
        )
        .unwrap();
    assert_eq!(loaded.document, parsed);
    assert_eq!(loaded.bytes, *original);
    assert_eq!(loaded.blob, receipt.documents[0].1);
    assert_eq!(loaded.blob.digest, raw_digest(original));
}

#[test]
fn missing_initial_policy_base_provenance_cannot_be_repaired_from_raw_declaration() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let removed = store
        .connection
        .execute(
            "DELETE FROM project_resource_provenance WHERE project_id=?1 AND project_revision=?2 AND resource_id=?3 AND digest=?4",
            params![
                initial.project_id.as_str(),
                initial.project_revision.as_str(),
                initial.policy_resource["resourceId"].as_str().unwrap(),
                initial.policy_resource["sha256"].as_str().unwrap(),
            ],
        )
        .unwrap();
    assert_eq!(removed, 1);
    // 초기 owner/Policy 원문/immutable artifact/head는 그대로 존재한다.
    // 사라진 실제 base provenance만 선언으로 보완할 수 없어야 한다.
    assert_eq!(
        registered_native_project_owner(&store, &initial.project_id).unwrap(),
        initial.owner_principal,
    );
    let baseline = metadata_snapshot(&store);
    let permit = TestPermit::new(&root, &initial);
    let query = ProjectResourceQuery::Current {
        resource_id: ResourceId::new("policy-local").unwrap(),
    };
    let mut reader = permit.resource_reader(MAX_SOURCE_TOTAL).unwrap();
    assert!(matches!(
        reader.metadata(
            &store,
            &permit,
            &ProjectResourceRequest {
                project: &initial.project_id,
                current_project_revision: &initial.project_revision,
                query: &query,
                expected: Some(&initial.policy_resource),
            },
        ),
        Err(StorageError::NotFound("Project resource provenance")),
    ));
    let mut batch = Batch::initial(&base);
    // 정확한 Policy 원문과 정본 ResourceRef까지 입력에 추가한다. 이것도
    // 기존 head의 실제 history/association을 복구하거나 발급하는 권한은 아니다.
    batch.resources.push((
        initial.policy_resource.clone(),
        canonical_bytes(&example("policy.json")).unwrap(),
    ));
    assert!(matches!(
        batch.commit(&mut store, &TestPermit::new(&root, &initial), &base),
        Err(StorageError::NotFound("Project resource provenance")),
    ));
    assert_unchanged(&store, &baseline, &base);
    assert!(store.connection.is_autocommit());
    let associations: i64 = store
        .connection
        .query_row(
            "SELECT count(*) FROM project_resource_provenance WHERE project_id=?1 AND resource_id='policy-local'",
            [initial.project_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(associations, 0);
}

#[test]
fn unresolved_durable_dispatch_fences_membership_even_with_disjoint_scope() {
    use crate::storage::{OperationState, ReserveOperation};
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let mut plan = example("execution-plan.json");
    plan["scope"]["resourceIds"] = json!(["unrelated-fenced-resource"]);
    plan["steps"][0]["effect"] = json!("write");
    plan["steps"][0]["resourcesWritten"] = json!(["unrelated-fenced-resource"]);
    plan["steps"][0]["verificationRequirement"] = json!("independent_readback");
    plan["projectBaseRevision"] = json!(revision(&base));
    plan["planHash"] = json!(projected_digest("ExecutionPlan", &plan).unwrap());
    store.save_plan(&plan).unwrap();
    let operation = OperationId::new("native-source-fenced-operation").unwrap();
    store
        .reserve_operation(ReserveOperation {
            operation_id: operation.clone(),
            principal: PrincipalId::new("principal-fixture").unwrap(),
            project_id: initial.project_id.clone(),
            idempotency_key: "native-source-fence-key".into(),
            plan_id: PlanId::new(plan["planId"].as_str().unwrap()).unwrap(),
            plan_hash: serde_json::from_value(plan["planHash"].clone()).unwrap(),
            context_id: ContextId::new("context-fixture-01").unwrap(),
        })
        .unwrap();
    let mut invocation = example("invocation.json");
    invocation["operationId"] = json!(operation);
    store
        .dispatch_intent(&operation, &StepId::new("echo-step").unwrap(), &invocation)
        .unwrap();
    // 실제 durable intent를 재개방하여 unknown/fence가 유지되는지 확인한다.
    drop(store);
    let mut store = root.store();
    assert_eq!(
        store.operation(&operation).unwrap().state,
        OperationState::OutcomeUnknown
    );
    let baseline = metadata_snapshot(&store);
    let batch = Batch::initial(&base);
    assert!(
        matches!(batch.commit(&mut store, &TestPermit::new(&root, &initial), &base), Err(StorageError::Fenced(operations)) if operations == vec![operation.clone()])
    );
    assert_unchanged(&store, &baseline, &base);
    assert_eq!(store.unresolved_dispatches().unwrap().len(), 1);
}

// 같은 보호 Store/bootstrap/Batch fixture로 source 사용 결정의 별도 수명을 검사한다.
#[path = "catalog_source_use_tests.rs"]
mod catalog_source_use_tests;

#[path = "compatibility_approval_tests.rs"]
mod compatibility_approval_tests;

#[path = "calibration_approval_tests.rs"]
mod calibration_approval_tests;

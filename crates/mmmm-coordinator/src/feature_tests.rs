//! These new fixtures are needed because the original examples contain no
//! live session revocation or registered-CAS service extension composition.
//! They exercise actual local SQLite/CAS and explicit fixture source policy;
//! they provide no actual game, solver, compiler-target or release evidence.
use super::*;
use crate::{
    auth::{SessionAuthority, SessionPolicy},
    service::{ApplicationPorts, ApplicationService, ExtensionRouter, ServiceDispatcher},
};
use mmmm_application::{
    Access, AppError, AppResult, AuthorityPort, IdKind, IdSource, IndependentObserverPort,
    PlanningPort, PreparedPlan, ProjectInspection, ProviderPort, ReadbackEvidence,
    RecoveryPreparation, SystemClock,
};
use mmmm_contracts::{ProjectId, Sha256Digest, canonical_digest, parse_json};
use mmmm_runtime::{
    artifact::{ResourceOwner, register_resource},
    storage::{
        StorageError, StorageResult, StoreConfig, WriteScope,
        owned_documents::{
            OwnedDocumentKind, OwnedDocumentPin, read_owned_document, register_owned_document,
        },
        project_resources::{
            ProjectResourceAuthority, ProjectResourceQuery, ProjectResourceReader,
            ProjectResourceRequest, ProjectSourceRpcContext, RegisteredProjectResource,
        },
    },
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

const OWNER: &[u8] = b"mmmm-feature-owned-local-fixture\n";
struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random).unwrap();
        let root = std::env::temp_dir().join(format!(
            "mmmm-feature-test-{}",
            &raw_digest(&random).as_str()[..24]
        ));
        let checkout =
            fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        assert!(root.is_absolute() && !root.starts_with(checkout));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(root.join("test-owner.txt"), OWNER).unwrap();
        Self(root)
    }
    fn config(&self) -> StoreConfig {
        StoreConfig::new(self.0.clone())
    }
}
fn plain_owned_tree(root: &Path) -> bool {
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    let mut count = 0_usize;
    while let Some((path, depth)) = pending.pop() {
        count += 1;
        if count > 4096 || depth > 32 || !path.is_absolute() || !path.starts_with(root) {
            return false;
        }
        let Ok(metadata) = fs::symlink_metadata(&path) else {
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
                pending.push((entry.path(), depth + 1));
            }
        } else if !metadata.is_file() {
            return false;
        }
    }
    true
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        if plain_owned_tree(&self.0)
            && fs::read(self.0.join("test-owner.txt")).ok().as_deref() == Some(OWNER)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn project() -> Value {
    parse_json(include_bytes!("../../../examples/project.json")).unwrap()
}
fn selection() -> Value {
    parse_json(include_bytes!("../../../examples/scene-selection.json")).unwrap()
}
fn manual_artifact_ref() -> Value {
    content_resource(
        "fixture-manual-artifact",
        "application/vnd.mmmm.bake-artifact+json",
        include_bytes!("../../../examples/bake-artifact.json"),
    )
}
fn fixture_context() -> Value {
    parse_json(include_bytes!("../../../examples/execution-context.json")).unwrap()
}
fn budget() -> RequestBudget {
    RequestBudget::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false))).unwrap()
}
fn session(methods: &[&str]) -> (SessionAuthority, AuthenticatedPrincipal) {
    let mut authority = SessionAuthority::new(1).unwrap();
    let token = authority
        .install(SessionPolicy {
            principal: PrincipalId::new("principal-fixture").unwrap(),
            allowed_methods: methods.iter().map(|m| (*m).to_owned()).collect(),
            allowed_contexts: BTreeSet::from([ContextId::new("context-fixture-01").unwrap()]),
            lifetime: Duration::from_secs(60),
        })
        .unwrap();
    let principal = authority.authenticate_token(&token).unwrap();
    (authority, principal)
}
type Rights = Rc<RefCell<BTreeMap<String, Redistribution>>>;
type Staged = Rc<RefCell<Vec<Value>>>;
#[derive(Default)]
struct ShapeFinalizationFixture {
    output: Option<Value>,
    pending: bool,
    published: usize,
    cancel_after_dispatch: bool,
}
struct FixtureSources {
    allowed: Arc<AtomicBool>,
    rights: Rights,
    staged: Staged,
    delta_allowed: Rc<Cell<bool>>,
    shape_finalization: Rc<RefCell<ShapeFinalizationFixture>>,
}
impl FeatureSources for FixtureSources {
    // 실제 geometry 권한을 발급하지 않는 공통 facade 순서 관측용이다. 기존
    // 예제에 없는 최종 schema/취소 실패 뒤 발행 여부만 같은 service에서 검사한다.
    fn shape_query_with_catalog(
        &mut self,
        _: &FeatureAccess,
        _: &Value,
        _: &Catalog,
        _: &mut DurableStore,
        budget: &RequestBudget,
    ) -> Result<Value, ServiceError> {
        let mut state = self.shape_finalization.borrow_mut();
        let output = state.output.clone().ok_or_else(unavailable)?;
        state.pending = true;
        if state.cancel_after_dispatch {
            budget.cancellation().store(true, Ordering::Release);
        }
        Ok(output)
    }
    fn shape_finished(
        &mut self,
        _: &FeatureAccess,
        result: &Result<Value, ServiceError>,
        _: &Catalog,
        _: &mut DurableStore,
        _: &RequestBudget,
    ) -> Result<(), ServiceError> {
        let mut state = self.shape_finalization.borrow_mut();
        if state.pending && result.is_ok() {
            state.published += 1;
        }
        state.pending = false;
        Ok(())
    }
    fn access(
        &mut self,
        principal: &AuthenticatedPrincipal,
        method: &str,
        input: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> Result<FeatureAccess, ServiceError> {
        budget.check()?;
        if !self.allowed.load(Ordering::Acquire) || !principal.permits(method) {
            return Err(forbidden());
        }
        let project = store
            .project(&ProjectId::new("project-fixture").unwrap())
            .map_err(|_| invalid_source())?;
        let context = input
            .get("contextId")
            .and_then(Value::as_str)
            .map(|_| fixture_context());
        Ok(FeatureAccess {
            read_principal: ReadPrincipal {
                principal_id: principal.principal().clone(),
                permission_scope_digest: canonical_digest(
                    &json!({"fixturePolicy":"current-local-read", "project":project["revision"]}),
                )
                .unwrap(),
            },
            context,
            project: Some(project),
            granted_permissions: BTreeSet::new(),
        })
    }
    fn resources<'a>(
        &'a mut self,
        access: &'a FeatureAccess,
        store: &'a mut DurableStore,
        budget: &'a RequestBudget,
    ) -> Result<Box<dyn FeatureResourcePort + 'a>, ServiceError> {
        Ok(Box::new(FixtureResources {
            store,
            principal: access.read_principal.principal_id.clone(),
            project: ProjectId::new("project-fixture").unwrap(),
            revision: serde_json::from_value(access.project.as_ref().unwrap()["revision"].clone())
                .unwrap(),
            context: ContextId::new("context-fixture-01").unwrap(),
            allowed: self.allowed.clone(),
            rights: self.rights.clone(),
            staged: self.staged.clone(),
            budget: budget.clone(),
        }))
    }
    fn authorize_exchange_prepare(
        &mut self,
        access: &FeatureAccess,
        input: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> Result<(), ServiceError> {
        budget.check()?;
        if !self.allowed.load(Ordering::Acquire)
            || input["dataSnapshotId"] != "snapshot-fixture"
            || input.get("physics").is_some()
        {
            return Err(forbidden());
        }
        let project = access.project.as_ref().unwrap();
        if input["selection"]["projectRevision"] != project["revision"] {
            return Err(invalid_source());
        }
        // The fixture's catalog explicitly owns this one immutable source
        // selection. Every embedded authored DTO must equal the registered
        // historical owned document, not just present a valid caller digest.
        if input["selection"] != selection() {
            return Err(invalid_source());
        }
        let project_id = ProjectId::new("project-fixture").unwrap();
        let revision = serde_json::from_value(project["revision"].clone()).unwrap();
        for (field, kind, id_field) in [
            ("instances", OwnedDocumentKind::Instance, "instanceId"),
            ("prefabs", OwnedDocumentKind::Prefab, "prefabId"),
        ] {
            for value in input["selection"][field].as_array().unwrap() {
                budget.check()?;
                let pin = OwnedDocumentPin {
                    kind,
                    object_id: serde_json::from_value(value[id_field].clone()).unwrap(),
                    revision: serde_json::from_value(value["revision"].clone()).unwrap(),
                };
                let actual = read_owned_document(store, &project_id, &revision, &pin)
                    .map_err(|_| invalid_source())?;
                if actual != *value {
                    return Err(invalid_source());
                }
            }
        }
        budget.check()
    }
    fn manual_scene(
        &mut self,
        access: &FeatureAccess,
        input: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> Result<ManualSceneInputs, ServiceError> {
        self.authorize_exchange_prepare(
            access,
            &json!({"contextId":input["contextId"], "selection":input["selection"], "dataSnapshotId":"snapshot-fixture"}),
            store,
            budget,
        )?;
        let artifact_ref = manual_artifact_ref();
        let source_map = selection()["sourceMap"].clone();
        if input["sourceMap"] != source_map {
            return Err(invalid_source());
        }
        let project_id = ProjectId::new("project-fixture").unwrap();
        let revision =
            serde_json::from_value(access.project.as_ref().unwrap()["revision"].clone()).unwrap();
        let context = ContextId::new("context-fixture-01").unwrap();
        let rpc = FixtureRpc {
            principal: &access.read_principal.principal_id,
            context: &context,
            budget,
            allowed: &self.allowed,
        };
        let mut reader = ProjectResourceReader::new(
            Box::new(FixtureResourceAuthority {
                allowed: self.allowed.clone(),
            }),
            MAX_CALL_RESOURCE_BYTES,
        )
        .map_err(|_| invalid_source())?;
        let mut documents = Vec::new();
        for resource in [&artifact_ref, &source_map] {
            let query = ProjectResourceQuery::RegisteredImmutable {
                resource_id: serde_json::from_value(resource["resourceId"].clone()).unwrap(),
            };
            let actual = reader
                .read(
                    store,
                    &rpc,
                    &ProjectResourceRequest {
                        project: &project_id,
                        current_project_revision: &revision,
                        query: &query,
                        expected: Some(resource),
                    },
                    MAX_CALL_RESOURCE_BYTES,
                )
                .map_err(|_| invalid_source())?;
            documents.push(parse_json(&actual.bytes).map_err(|_| invalid_source())?);
        }
        if documents[0] != input["artifact"] {
            return Err(invalid_source());
        }
        let validator = ContractValidator::shared().map_err(|_| invalid_source())?;
        validator
            .validate("BakeArtifact", &documents[0])
            .map_err(|_| invalid_source())?;
        validator
            .validate("SourceMap", &documents[1])
            .map_err(|_| invalid_source())?;
        let mut policy = DeltaPolicy::default();
        if self.delta_allowed.get() {
            policy
                .allow(
                    ObjectNode {
                        instance_id: "instance-shop-a".into(),
                        node_id: "door".into(),
                    },
                    DeltaKind::UpdateTransform,
                )
                .map_err(exchange_error)?;
        }
        // This source-codec fixture proposes no edits. It does not construct
        // an IngestedBake, completed solver job or actual-game evidence.
        Ok(ManualSceneInputs {
            selection: Selection::from_value(&input["selection"]).map_err(exchange_error)?,
            edits: vec![],
            artifact: documents.remove(0),
            source_artifact: artifact_ref,
            source_map,
            losses: vec![],
            policy,
        })
    }
}

struct FixtureRpc<'a> {
    principal: &'a PrincipalId,
    context: &'a ContextId,
    budget: &'a RequestBudget,
    allowed: &'a AtomicBool,
}
impl ProjectSourceRpcContext for FixtureRpc<'_> {
    fn check(&self) -> StorageResult<()> {
        self.budget
            .check()
            .map_err(|_| StorageError::InvalidTransition("Fixture live budget stopped".into()))?;
        if !self.allowed.load(Ordering::Acquire) {
            return Err(StorageError::InvalidTransition(
                "Fixture Project ACL revoked".into(),
            ));
        }
        Ok(())
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.principal.clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        Some(self.context)
    }
}
struct FixtureResourceAuthority {
    allowed: Arc<AtomicBool>,
}
impl ProjectResourceAuthority for FixtureResourceAuthority {
    fn authorize_project_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        revision: &Sha256Digest,
    ) -> StorageResult<()> {
        if !self.allowed.load(Ordering::Acquire)
            || principal.as_str() != "principal-fixture"
            || context.is_none_or(|id| id.as_str() != "context-fixture-01")
            || store.project(project)?["revision"] != revision.as_str()
        {
            return Err(StorageError::InvalidTransition(
                "Fixture current Project ACL rejected".into(),
            ));
        }
        Ok(())
    }
    fn authorize_resource_read(
        &mut self,
        _store: &DurableStore,
        _principal: &PrincipalId,
        _context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> StorageResult<()> {
        if !self.allowed.load(Ordering::Acquire)
            || resource.owner != ResourceOwner::Project(project.clone())
        {
            return Err(StorageError::InvalidTransition(
                "Fixture current resource ACL rejected".into(),
            ));
        }
        Ok(())
    }
}
struct FixtureResources<'a> {
    store: &'a mut DurableStore,
    principal: PrincipalId,
    context: ContextId,
    project: ProjectId,
    revision: Sha256Digest,
    allowed: Arc<AtomicBool>,
    rights: Rights,
    staged: Staged,
    budget: RequestBudget,
}
impl ResourcePort for FixtureResources<'_> {
    fn authorize_selection(&mut self, context: &str, value: &Value) -> ExchangeResult<()> {
        self.budget
            .check()
            .map_err(|e| ExchangeError::new(e.code, e.message))?;
        if !self.allowed.load(Ordering::Acquire)
            || context != self.context.as_str()
            || value["projectId"] != self.project.as_str()
            || value["projectRevision"] != self.revision.as_str()
        {
            return Err(ExchangeError::new(
                "PERMISSION_REQUIRED",
                "Fixture current selection source ACL rejected",
            ));
        }
        Ok(())
    }
    fn read(
        &mut self,
        context: &str,
        resource: &Value,
        _purpose: ResourcePurpose,
        max: u64,
    ) -> ExchangeResult<AuthorizedBytes> {
        if context != self.context.as_str() {
            return Err(ExchangeError::new(
                "PERMISSION_REQUIRED",
                "Fixture context differs",
            ));
        }
        let mut reader = ProjectResourceReader::new(
            Box::new(FixtureResourceAuthority {
                allowed: self.allowed.clone(),
            }),
            MAX_CALL_RESOURCE_BYTES,
        )
        .map_err(|_| {
            ExchangeError::new(
                "RESOURCE_FORBIDDEN",
                "Fixture registered reader unavailable",
            )
        })?;
        let rpc = FixtureRpc {
            principal: &self.principal,
            context: &self.context,
            budget: &self.budget,
            allowed: &self.allowed,
        };
        let query = ProjectResourceQuery::RegisteredImmutable {
            resource_id: serde_json::from_value(resource["resourceId"].clone()).unwrap(),
        };
        let request = ProjectResourceRequest {
            project: &self.project,
            current_project_revision: &self.revision,
            query: &query,
            expected: Some(resource),
        };
        let actual = reader
            .read(self.store, &rpc, &request, max.min(MAX_CALL_RESOURCE_BYTES))
            .map_err(|_| {
                ExchangeError::new(
                    "RESOURCE_FORBIDDEN",
                    "Fixture actual registered resource source rejected",
                )
            })?;
        let rights = self
            .rights
            .borrow()
            .get(resource["sha256"].as_str().unwrap())
            .copied()
            .unwrap_or(Redistribution::Unknown);
        Ok(AuthorizedBytes {
            bytes: actual.bytes,
            redistribution: rights,
        })
    }
    fn embedded_rights(
        &mut self,
        _context: &str,
        resource: &Value,
    ) -> ExchangeResult<Redistribution> {
        Ok(self
            .rights
            .borrow()
            .get(resource["sha256"].as_str().unwrap())
            .copied()
            .unwrap_or(Redistribution::Unknown))
    }
}
impl FeatureResourcePort for FixtureResources<'_> {
    fn stage(&mut self, resource: &Value, bytes: &[u8]) -> ExchangeResult<()> {
        self.budget
            .check()
            .map_err(|e| ExchangeError::new(e.code, e.message))?;
        if !self.allowed.load(Ordering::Acquire) {
            return Err(ExchangeError::new(
                "PERMISSION_REQUIRED",
                "Fixture staging ACL revoked",
            ));
        }
        verify_resource(resource, bytes, MAX_CALL_RESOURCE_BYTES)?;
        self.store.put_blob(bytes).map_err(|_| {
            ExchangeError::new("STAGING_FAILED", "Fixture actual CAS staging failed")
        })?;
        register_resource(
            self.store,
            resource,
            ResourceOwner::Project(self.project.clone()),
        )
        .map_err(|e| ExchangeError::new(e.code, "Fixture immutable registration failed"))?;
        self.rights
            .borrow_mut()
            .entry(resource["sha256"].as_str().unwrap().to_owned())
            .or_insert(Redistribution::Allowed);
        self.staged.borrow_mut().push(resource.clone());
        Ok(())
    }
}

#[derive(Clone)]
struct NoHost;
fn no_host<T>() -> AppResult<T> {
    Err(AppError::new(
        "CAPABILITY_UNAVAILABLE",
        "This local source fixture owns no game/provider executor",
    ))
}
impl AuthorityPort for NoHost {
    fn authorize(
        &mut self,
        _principal: &PrincipalId,
        _project: &ProjectId,
        _access: Access,
        _context: Option<&Value>,
        _plan: Option<&Value>,
    ) -> AppResult<()> {
        no_host()
    }
}
impl PlanningPort for NoHost {
    fn inspect_project(
        &mut self,
        _principal: &PrincipalId,
        _project: &Value,
    ) -> AppResult<ProjectInspection> {
        no_host()
    }
    fn prepare(
        &mut self,
        _principal: &PrincipalId,
        _request: &Value,
        _project: &Value,
        _context: &Value,
    ) -> AppResult<PreparedPlan> {
        no_host()
    }
    fn prepare_recovery(
        &mut self,
        _principal: &PrincipalId,
        _recovery: &RecoveryPreparation,
        _project: &Value,
        _context: &Value,
    ) -> AppResult<PreparedPlan> {
        no_host()
    }
}
impl ProviderPort for NoHost {
    fn context(&mut self, _principal: &PrincipalId, _id: &ContextId) -> AppResult<Value> {
        no_host()
    }
    fn action_descriptor(&mut self, _step: &Value, _context: &Value) -> AppResult<Value> {
        no_host()
    }
    fn observe_precondition(
        &mut self,
        _input: &Value,
        _context: &Value,
    ) -> AppResult<Sha256Digest> {
        no_host()
    }
    fn verify_dependencies(&mut self, _pins: &[Value], _context: &Value) -> AppResult<()> {
        no_host()
    }
    fn dispatch(&mut self, _invocation: &Value) -> AppResult<Value> {
        panic!("Public feature facade must never dispatch")
    }
    fn poll(&mut self, _invocation: &Value, _receipt: Option<&str>) -> AppResult<Option<Value>> {
        no_host()
    }
    fn request_cancel(&mut self, _invocation: &Value, _receipt: Option<&str>) -> AppResult<()> {
        no_host()
    }
}
impl IndependentObserverPort for NoHost {
    fn readback(
        &mut self,
        _invocation: &Value,
        _scope: &WriteScope,
    ) -> AppResult<ReadbackEvidence> {
        no_host()
    }
    fn read_target(&mut self, _invocation: &Value, _target: &str) -> AppResult<Vec<u8>> {
        no_host()
    }
}
impl IdSource for NoHost {
    fn next_id(&mut self, _kind: IdKind) -> AppResult<String> {
        no_host()
    }
}
fn ports() -> ApplicationPorts {
    ApplicationPorts {
        authority: Box::new(NoHost),
        planner: Box::new(NoHost),
        provider: Box::new(NoHost),
        observer: Box::new(NoHost),
        ids: Box::new(NoHost),
        clock: Box::new(SystemClock),
    }
}
struct Fixture {
    allowed: Arc<AtomicBool>,
    rights: Rights,
    staged: Staged,
    delta_allowed: Rc<Cell<bool>>,
    shape_finalization: Rc<RefCell<ShapeFinalizationFixture>>,
}
impl Fixture {
    fn new() -> Self {
        Self {
            allowed: Arc::new(AtomicBool::new(true)),
            rights: Rc::new(RefCell::new(BTreeMap::new())),
            staged: Rc::new(RefCell::new(vec![])),
            delta_allowed: Rc::new(Cell::new(false)),
            shape_finalization: Rc::new(RefCell::new(ShapeFinalizationFixture::default())),
        }
    }
    fn sources(&self) -> Box<dyn FeatureSources> {
        Box::new(FixtureSources {
            allowed: self.allowed.clone(),
            rights: self.rights.clone(),
            staged: self.staged.clone(),
            delta_allowed: self.delta_allowed.clone(),
            shape_finalization: self.shape_finalization.clone(),
        })
    }
    fn initialize(&self, root: &TestRoot) {
        let mut store = DurableStore::open(root.config()).unwrap();
        let project = project();
        store.save_project(&project, None).unwrap();
        let project_id = ProjectId::new("project-fixture").unwrap();
        let revision = serde_json::from_value(project["revision"].clone()).unwrap();
        let selection = selection();
        for (field, kind, id_field) in [
            ("instances", OwnedDocumentKind::Instance, "instanceId"),
            ("prefabs", OwnedDocumentKind::Prefab, "prefabId"),
        ] {
            for value in selection[field].as_array().unwrap() {
                let pin = OwnedDocumentPin {
                    kind,
                    object_id: serde_json::from_value(value[id_field].clone()).unwrap(),
                    revision: serde_json::from_value(value["revision"].clone()).unwrap(),
                };
                register_owned_document(&mut store, &project_id, &revision, &pin, value).unwrap();
            }
        }
        for (resource, bytes) in [
            (
                &selection["sourceMap"],
                include_bytes!("../../../examples/source-map.json").as_slice(),
            ),
            (
                &selection["prefabs"][0]["resources"][0],
                include_bytes!("../../../examples/blockset.json").as_slice(),
            ),
        ] {
            verify_resource(resource, bytes, MAX_CALL_RESOURCE_BYTES).unwrap();
            store.put_blob(bytes).unwrap();
            register_resource(
                &mut store,
                resource,
                ResourceOwner::Project(project_id.clone()),
            )
            .unwrap();
            self.rights.borrow_mut().insert(
                resource["sha256"].as_str().unwrap().to_owned(),
                Redistribution::Allowed,
            );
        }
        store
            .put_blob(include_bytes!("../../../examples/bake-artifact.json"))
            .unwrap();
        register_resource(
            &mut store,
            &manual_artifact_ref(),
            ResourceOwner::Project(project_id),
        )
        .unwrap();
    }
    fn service(&self, root: &TestRoot) -> ApplicationService {
        let mut router = ExtensionRouter::default();
        router
            .register(
                FEATURE_METHODS,
                Box::new(FeatureExtension::new(self.sources(), HostBridge::default()).unwrap()),
            )
            .unwrap();
        let mut service = ApplicationService::open(root.config(), ports()).unwrap();
        service.set_extensions(router);
        service
    }
}
fn prepare_input() -> Value {
    let manifest = parse_json(include_bytes!("../../../examples/exchange-manifest.json")).unwrap();
    json!({"contextId":"context-fixture-01", "selection":selection(), "dataSnapshotId":"snapshot-fixture", "coordinates":manifest["coordinates"]})
}

#[test]
fn canonical_feature_registration_excludes_builtins_and_separate_artifact_owner() {
    let fixture = Fixture::new();
    let mut router = ExtensionRouter::default();
    router
        .register(
            FEATURE_METHODS,
            Box::new(FeatureExtension::new(fixture.sources(), HostBridge::default()).unwrap()),
        )
        .unwrap();
    assert!(!FEATURE_METHODS.contains(&"artifact.read"));
    assert_eq!(
        router
            .register(
                ["prefab.validate"],
                Box::new(FeatureExtension::new(fixture.sources(), HostBridge::default()).unwrap())
            )
            .unwrap_err()
            .code,
        "INVALID_REGISTRATION"
    );
    assert_eq!(
        router
            .register(
                ["exchange.prepare"],
                Box::new(FeatureExtension::new(fixture.sources(), HostBridge::default()).unwrap())
            )
            .unwrap_err()
            .code,
        "INVALID_REGISTRATION"
    );
    // 같은 실제 SQLite/service fixture에서 성공한 이전 발행을 남긴 채,
    // 이후의 공통 출력 schema 실패와 취소가 새 pending만 폐기하는지 확인한다.
    let root = TestRoot::new();
    fixture.initialize(&root);
    let mut service = fixture.service(&root);
    let (_sessions, principal) = session(&["world.shape_query"]);
    let query = parse_json(include_bytes!("../../../examples/shape-query.json")).unwrap();
    let valid = parse_json(include_bytes!(
        "../../../examples/shape-result-unknown.json"
    ))
    .unwrap();
    fixture.shape_finalization.borrow_mut().output = Some(valid.clone());
    service
        .call(&principal, "world.shape_query", &query, &budget())
        .unwrap();
    assert_eq!(fixture.shape_finalization.borrow().published, 1);
    fixture.shape_finalization.borrow_mut().output = Some(json!({"status":"known"}));
    assert_eq!(
        service
            .call(&principal, "world.shape_query", &query, &budget())
            .unwrap_err()
            .code,
        "SCHEMA_INVALID"
    );
    assert_eq!(fixture.shape_finalization.borrow().published, 1);
    assert!(!fixture.shape_finalization.borrow().pending);
    {
        let mut state = fixture.shape_finalization.borrow_mut();
        state.output = Some(valid);
        state.cancel_after_dispatch = true;
    }
    assert_eq!(
        service
            .call(&principal, "world.shape_query", &query, &budget())
            .unwrap_err()
            .code,
        "CANCELLED"
    );
    assert_eq!(fixture.shape_finalization.borrow().published, 1);
    assert!(!fixture.shape_finalization.borrow().pending);
}

#[test]
fn public_provider_invocation_rejects_before_source_resolution_and_cannot_dispatch() {
    let root = TestRoot::new();
    let fixture = Fixture::new();
    fixture.initialize(&root);
    fixture.allowed.store(false, Ordering::Release);
    let (_authority, principal) = session(&["provider.invoke"]);
    let mut service = fixture.service(&root);
    assert_eq!(
        service
            .call(
                &principal,
                "provider.invoke",
                &json!({"callerPassedAuthority":true}),
                &budget()
            )
            .unwrap_err()
            .code,
        "INTERNAL_ENTRY_REQUIRED"
    );
}

#[test]
fn actual_service_manual_bundle_roundtrip_retains_registered_payloads_and_zip() {
    let root = TestRoot::new();
    let fixture = Fixture::new();
    fixture.initialize(&root);
    let (_authority, principal) = session(&["exchange.prepare", "exchange.inspect", "scene.diff"]);
    let mut service = fixture.service(&root);
    let manifest = service
        .call(&principal, "exchange.prepare", &prepare_input(), &budget())
        .unwrap();
    ContractValidator::shared()
        .unwrap()
        .validate("SceneExchangeManifest", &manifest)
        .unwrap();
    assert!(manifest.get("zip").is_none());
    assert_eq!(
        service
            .call(&principal, "exchange.prepare", &prepare_input(), &budget())
            .unwrap(),
        manifest
    );
    let staged = fixture.staged.borrow();
    let zip = staged
        .iter()
        .find(|r| r["mediaType"] == "application/zip")
        .unwrap()
        .clone();
    assert!(
        manifest["payloads"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| staged.contains(&p["resource"]))
    );
    drop(staged);
    let inspection = service
        .call(
            &principal,
            "exchange.inspect",
            &json!({"contextId":"context-fixture-01", "resource":zip}),
            &budget(),
        )
        .unwrap();
    assert_eq!(inspection["manifest"], manifest);
    assert!(
        !inspection["resolvedResources"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let scene_input = json!({"contextId":"context-fixture-01", "selection":selection(),
        "artifact":parse_json(include_bytes!("../../../examples/bake-artifact.json")).unwrap(),
        "sourceMap":selection()["sourceMap"]});
    let patch = service
        .call(&principal, "scene.diff", &scene_input, &budget())
        .unwrap();
    assert_eq!(
        service
            .call(&principal, "scene.diff", &scene_input, &budget())
            .unwrap(),
        patch
    );
    assert_eq!(patch["entries"], json!([]));
    fixture.delta_allowed.set(true);
    let changed_policy = service
        .call(&principal, "scene.diff", &scene_input, &budget())
        .unwrap();
    assert_ne!(changed_policy["patchId"], patch["patchId"]);
    let mut caller_digest = scene_input;
    caller_digest["deltaPolicyDigest"] = json!("0".repeat(64));
    assert_eq!(
        service
            .call(&principal, "scene.diff", &caller_digest, &budget())
            .unwrap_err()
            .code,
        "SCHEMA_INVALID"
    );
    drop(service);
    // Actual retained CAS is readable again through the same metadata/ACL
    // reader after a store reopen. No process-owned memory byte cache is used.
    let mut store = DurableStore::open(root.config()).unwrap();
    let access = fixture
        .sources()
        .access(
            &principal,
            "exchange.inspect",
            &json!({"contextId":"context-fixture-01"}),
            &store,
            &budget(),
        )
        .unwrap();
    let call_budget = budget();
    let mut sources = fixture.sources();
    let mut resources = sources
        .resources(&access, &mut store, &call_budget)
        .unwrap();
    let read = resources
        .read(
            "context-fixture-01",
            &zip,
            ResourcePurpose::Read,
            MAX_CALL_RESOURCE_BYTES,
        )
        .unwrap();
    assert_eq!(
        raw_digest(&read.bytes).as_str(),
        zip["sha256"].as_str().unwrap()
    );
    assert_eq!(&read.bytes[..4], b"PK\x03\x04");
}

#[test]
fn reference_only_asset_is_retained_as_reference_and_current_acl_denial_blocks_export() {
    let root = TestRoot::new();
    let fixture = Fixture::new();
    fixture.initialize(&root);
    let asset = selection()["prefabs"][0]["resources"][0].clone();
    fixture.rights.borrow_mut().insert(
        asset["sha256"].as_str().unwrap().to_owned(),
        Redistribution::ReferenceOnly,
    );
    let (_authority, principal) = session(&["exchange.prepare"]);
    let mut service = fixture.service(&root);
    let manifest = service
        .call(&principal, "exchange.prepare", &prepare_input(), &budget())
        .unwrap();
    let payload = manifest["payloads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["resource"] == asset)
        .unwrap();
    assert_eq!(payload["redistribution"], "reference_only");
    assert!(!fixture.staged.borrow().contains(&asset));
    fixture.rights.borrow_mut().insert(
        asset["sha256"].as_str().unwrap().to_owned(),
        Redistribution::Unknown,
    );
    let changed_rights = service
        .call(&principal, "exchange.prepare", &prepare_input(), &budget())
        .unwrap();
    assert_ne!(changed_rights["bundleId"], manifest["bundleId"]);
    fixture.allowed.store(false, Ordering::Release);
    assert_eq!(
        service
            .call(&principal, "exchange.prepare", &prepare_input(), &budget())
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
}

#[test]
fn missing_actual_target_profile_does_not_compile_caller_claims() {
    let root = TestRoot::new();
    let fixture = Fixture::new();
    fixture.initialize(&root);
    let (_authority, principal) = session(&["math.compile"]);
    let mut service = fixture.service(&root);
    let request = json!({"nodes":[], "rootExprId":"expr-root", "targetProfileId":"java-26.3", "outputStorage":"scoreboard", "rounding":"none",
        "symbolTable":{"resourceId":"symbol-fixture", "sha256":"1".repeat(64), "mediaType":"application/json", "sizeBytes":2}});
    assert_eq!(
        service
            .call(&principal, "math.compile", &request, &budget())
            .unwrap_err()
            .code,
        "UNSUPPORTED_TARGET_VERSION"
    );
    assert!(fixture.staged.borrow().is_empty());
}

#[test]
fn caller_pass_arrays_cannot_supply_verified_release_evidence() {
    let root = TestRoot::new();
    let fixture = Fixture::new();
    fixture.initialize(&root);
    let (_authority, principal) = session(&["release.evaluate"]);
    let mut service = fixture.service(&root);
    let mut request =
        parse_json(include_bytes!("../../../examples/release-spec-only.json")).unwrap();
    request["productVersion"] = json!("0.1.0");
    request["claim"] = json!("release_candidate");
    request["passedTestIds"] = request["requiredTestIds"].clone();
    request["notRunTestIds"] = json!([]);
    let result = service
        .call(&principal, "release.evaluate", &request, &budget())
        .unwrap();
    assert_eq!(result["eligible"], false);
    assert!(
        result["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "VERIFIED_EVIDENCE_MISSING")
    );
}

#[test]
fn cancellation_before_bounded_input_clone_and_resource_read_is_observed() {
    let cancelled = Arc::new(AtomicBool::new(true));
    let call_budget = RequestBudget::new(Duration::from_secs(5), cancelled).unwrap();
    assert_eq!(
        bounded_clone(&selection(), &call_budget).unwrap_err().code,
        "CANCELLED"
    );
    let root = TestRoot::new();
    let fixture = Fixture::new();
    fixture.initialize(&root);
    let (_authority, principal) = session(&["exchange.prepare"]);
    let mut service = fixture.service(&root);
    assert_eq!(
        service
            .call(
                &principal,
                "exchange.prepare",
                &prepare_input(),
                &call_budget
            )
            .unwrap_err()
            .code,
        "CANCELLED"
    );
    assert!(fixture.staged.borrow().is_empty());
}

#[test]
fn completion_cursor_rejects_surrogate_splits_without_calling_or_executing_host() {
    let root = TestRoot::new();
    let fixture = Fixture::new();
    fixture.initialize(&root);
    let (_authority, principal) = session(&["command.complete"]);
    let mut service = fixture.service(&root);
    let request = json!({"contextId":"context-fixture-01", "command":"say 😀", "cursorUtf16":5});
    assert_eq!(
        service
            .call(&principal, "command.complete", &request, &budget())
            .unwrap_err()
            .code,
        "CURSOR_INVALID"
    );
    let request = json!({"contextId":"context-fixture-01", "command":"say 😀", "cursorUtf16":7});
    assert_eq!(
        service
            .call(&principal, "command.complete", &request, &budget())
            .unwrap_err()
            .code,
        "CURSOR_INVALID"
    );
    assert!(fixture.staged.borrow().is_empty());
}

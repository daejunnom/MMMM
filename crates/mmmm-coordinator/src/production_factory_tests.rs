//! Real protected Store/native Project initialization exercises composition.
//! The original Prefab example is reused for pure-domain behavior; no game,
//! profile approval, permission evidence or redistribution fixture is invented.

use super::*;
use crate::{
    auth::{AuthenticatedPrincipal, SessionAuthority, SessionPolicy},
    authority::LocalAuthority,
    features::{FEATURE_METHODS, FeatureExtension},
    host::HostBridge,
    native_project::create_native_project,
    native_source_ingress::{
        NativeRawSourceResource, NativeSourceDocument, NativeSourceInput, NativeSourceKind,
        prepare_native_sources,
    },
    planning_source::{PlanningComposition, PlanningStore, StoreAwarePlanner},
    service::{
        ApplicationPorts, ApplicationService, ExtensionRouter, RequestContextSlot,
        RequestContextWitness, ServiceDispatcher, ServiceExtension, ServiceExtensionContext,
    },
    workspace_bootstrap::prepare_workspace,
};
use mmmm_application::{IdKind, IdSource, SystemClock};
use mmmm_contracts::{
    ResourceId, TargetProfileId, encode_json, parse_json, projected_digest, raw_digest,
};
use mmmm_runtime::storage::StoreConfig;
use serde_json::json;
use std::{
    cell::Cell,
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const MARKER: &[u8] = b"mmmm-production-factory-test-v1\n";
struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let parent = fs::canonicalize(parent).unwrap();
        let path = parent.join(format!(
            "mmmm-production-factory-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(path.is_absolute() && !path.exists());
        let checkout =
            fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        assert!(!path.starts_with(checkout));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = fs::canonicalize(path).unwrap();
        assert_eq!(path.parent(), Some(parent.as_path()));
        fs::write(path.join("test-owner.txt"), MARKER).unwrap();
        Self(path)
    }
    fn open(&self) -> DurableStore {
        DurableStore::open(StoreConfig::new(self.0.clone())).unwrap()
    }
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        let mut count = 0;
        if fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0)
            && fs::read(self.0.join("test-owner.txt")).ok().as_deref() == Some(MARKER)
            && plain_tree(&self.0, &self.0, 0, &mut count)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
fn plain_tree(path: &Path, root: &Path, depth: usize, count: &mut usize) -> bool {
    if !path.starts_with(root) || depth > 16 || *count >= 1024 {
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
    } else if !metadata.is_file() {
        return false;
    }
    true
}

fn binary_digest() -> Sha256Digest {
    // Pin this actual running Rust test executable, never a host JAR or
    // fabricated known-good profile/source digest. This is not release evidence.
    let executable = std::env::current_exe().unwrap();
    assert!(fs::metadata(&executable).unwrap().len() <= 256 * 1024 * 1024);
    raw_digest(&fs::read(executable).unwrap())
}
fn handles(store: &mut DurableStore) -> DaemonHandles {
    let created = create_native_project(
        store,
        "Owned offline composition",
        &TargetProfileId::new("unverified-native-target").unwrap(),
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    let hosts = HostBridge::default();
    let authority = LocalAuthority::new(hosts.clone());
    let workspace = prepare_workspace(
        store,
        &authority,
        &created.project_id,
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(workspace.witness.principal(), &created.owner_principal);
    DaemonHandles {
        hosts,
        authority,
        request: RequestContextSlot::default(),
        calibration: crate::calibration_execution::CalibrationRegistry::default(),
        bootstrap: crate::calibration_bootstrap::BootstrapRegistry::default(),
        configured_project: Some(created.project_id),
        workspace: Some(workspace),
    }
}
fn error_code(result: Result<DaemonSourceParts, ServiceError>) -> &'static str {
    match result {
        Ok(_) => panic!("Composition unexpectedly accepted an unavailable source"),
        Err(error) => error.code,
    }
}

#[test]
fn explicit_project_and_actual_workspace_are_required_before_installation() {
    let root = TestRoot::new();
    let mut store = root.open();
    let handles = handles(&mut store);
    let mut factory = ProductionFactory::offline_owned(binary_digest());
    let mut missing = handles.clone();
    missing.configured_project = None;
    assert_eq!(
        error_code(factory.compose(&missing, &store)),
        "COMPOSITION_PROJECT_REQUIRED"
    );
    missing = handles.clone();
    missing.workspace = None;
    assert_eq!(
        error_code(factory.compose(&missing, &store)),
        "COMPOSITION_WORKSPACE_REQUIRED"
    );
    assert!(factory.registries().is_none());
    // Preflight errors did not install a resolver or consume the composition.
    let parts = factory.compose(&handles, &store).unwrap();
    assert!(factory.registries().is_some());
    drop(parts);
    assert_eq!(
        error_code(factory.compose(&handles, &store)),
        "COMPOSITION_ALREADY_USED"
    );
}

#[test]
fn a_native_owner_witness_cannot_be_reused_for_another_store() {
    let root = TestRoot::new();
    let mut store = root.open();
    let local = handles(&mut store);
    let other_root = TestRoot::new();
    let mut other_store = other_root.open();
    let foreign = handles(&mut other_store);
    let mut mismatched = local.clone();
    mismatched.workspace = foreign.workspace;
    let mut factory = ProductionFactory::offline_owned(binary_digest());
    assert_eq!(
        error_code(factory.compose(&mismatched, &store)),
        "PERMISSION_REQUIRED"
    );
    assert!(factory.registries().is_none());
    assert!(factory.compose(&local, &store).is_ok());
}

#[test]
fn stale_project_setup_and_unbounded_options_fail_before_source_installation() {
    let root = TestRoot::new();
    let mut store = root.open();
    let handles = handles(&mut store);
    let mut factory = ProductionFactory::offline_owned(binary_digest());
    let mut stale = handles.clone();
    stale.workspace.as_mut().unwrap().project_revision = raw_digest(b"different-project-revision");
    assert_eq!(error_code(factory.compose(&stale, &store)), "STALE_CONTEXT");
    factory
        .inputs
        .as_mut()
        .unwrap()
        .planner_options
        .time_budget_ms = 0;
    assert_eq!(
        error_code(factory.compose(&handles, &store)),
        "BUDGET_EXCEEDED"
    );
    assert!(factory.registries().is_none());
    factory.inputs.as_mut().unwrap().planner_options = PlannerOptions::default();
    assert!(factory.compose(&handles, &store).is_ok());
}

struct NoGeneratedIds;
impl IdSource for NoGeneratedIds {
    fn next_id(&mut self, _: IdKind) -> AppResult<String> {
        Err(AppError::new(
            "UNEXPECTED_MUTATION",
            "Read and pure functions cannot allocate operation IDs",
        ))
    }
}

type FactorySourceRead =
    Box<dyn FnMut(&mut DurableStore, RequestContextWitness) -> AppResult<Value>>;
struct FactorySourceExtension {
    request: RequestContextSlot,
    read: FactorySourceRead,
}
impl ServiceExtension for FactorySourceExtension {
    fn call(
        &mut self,
        method: &str,
        _: &Value,
        context: &mut ServiceExtensionContext<'_>,
    ) -> Result<Value, ServiceError> {
        context.check(method)?;
        let request = self.request.current_witness(method)?;
        assert!(request.authenticated().same_session(context.principal));
        assert_eq!(request.budget().deadline(), context.budget.deadline());
        assert!(std::ptr::eq(
            request.budget().cancellation(),
            context.budget.cancellation(),
        ));
        (self.read)(context.store, request)
            .map_err(|error| ServiceError::caused_by(error.code, error.message, error))
    }
}
struct FactorySourceFixture {
    service: ApplicationService,
    _sessions: SessionAuthority,
    authenticated: AuthenticatedPrincipal,
    budget: RequestBudget,
}
impl FactorySourceFixture {
    fn call(&mut self) -> Result<Value, ServiceError> {
        self.service
            .call(&self.authenticated, "scene.diff", &json!({}), &self.budget)
    }
}
fn source_fixture(
    store: DurableStore,
    handles: &DaemonHandles,
    parts: DaemonSourceParts,
    budget: RequestBudget,
    read: impl FnMut(&mut DurableStore, RequestContextWitness) -> AppResult<Value> + 'static,
) -> FactorySourceFixture {
    let mut extensions = ExtensionRouter::default();
    extensions
        .register(
            ["scene.diff"],
            Box::new(FactorySourceExtension {
                request: handles.request.clone(),
                read: Box::new(read),
            }),
        )
        .unwrap();
    authenticated_feature_fixture(
        store,
        handles,
        parts,
        budget,
        Some(extensions),
        &["scene.diff"],
    )
}
fn authenticated_feature_fixture(
    store: DurableStore,
    handles: &DaemonHandles,
    parts: DaemonSourceParts,
    budget: RequestBudget,
    extensions: Option<ExtensionRouter>,
    methods: &[&str],
) -> FactorySourceFixture {
    let workspace = handles.workspace.as_ref().unwrap();
    let context = ContextId::new(workspace.context["contextId"].as_str().unwrap()).unwrap();
    let planner = StoreAwarePlanner::new(PlanningComposition {
        request: Box::new(handles.request.clone()),
        authority: handles.authority.clone(),
        hosts: handles.hosts.clone(),
        contexts: parts.contexts,
        data: parts.data,
        backend: parts.backend,
        dependencies: parts.dependencies,
        clock: Box::new(SystemClock),
        options: parts.planner_options,
    })
    .unwrap();
    let mut service = ApplicationService::from_store(
        store,
        ApplicationPorts {
            authority: Box::new(handles.authority.clone()),
            planner: Box::new(planner),
            provider: parts.provider,
            observer: parts.observer,
            ids: Box::new(NoGeneratedIds),
            clock: Box::new(SystemClock),
        },
    );
    service.bind_request_context(handles.request.clone());
    let extensions = extensions.unwrap_or_else(|| {
        let mut extensions = ExtensionRouter::default();
        extensions
            .register(
                FEATURE_METHODS.iter().copied(),
                Box::new(FeatureExtension::new(parts.features, handles.hosts.clone()).unwrap()),
            )
            .unwrap();
        extensions
    });
    service.set_extensions(extensions);
    let mut sessions = SessionAuthority::new(1).unwrap();
    let token = sessions
        .install(SessionPolicy {
            principal: workspace.witness.principal().clone(),
            allowed_methods: methods.iter().map(|method| (*method).to_owned()).collect(),
            allowed_contexts: [context].into(),
            lifetime: Duration::from_secs(30),
        })
        .unwrap();
    let authenticated = sessions.authenticate_token(&token).unwrap();
    FactorySourceFixture {
        service,
        _sessions: sessions,
        authenticated,
        budget,
    }
}

fn release_claim() -> Value {
    let mut input = parse_json(include_bytes!("../../../examples/release-spec-only.json")).unwrap();
    input["productVersion"] = json!("0.1.0");
    input["claim"] = json!("release_candidate");
    input["passedTestIds"] = input["requiredTestIds"].clone();
    input["notRunTestIds"] = json!([]);
    input
}

fn release_fixture(root: &TestRoot) -> (DaemonHandles, FactorySourceFixture, ProductionRegistries) {
    let mut store = root.open();
    let handles = handles(&mut store);
    let mut factory = ProductionFactory::offline_owned(binary_digest());
    let parts = factory.compose(&handles, &store).unwrap();
    let registries = factory.registries().unwrap().clone();
    let budget =
        RequestBudget::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false))).unwrap();
    let fixture =
        authenticated_feature_fixture(store, &handles, parts, budget, None, &["release.evaluate"]);
    (handles, fixture, registries)
}

fn queue_other_project_release_write(
    store: &mut DurableStore,
) -> (
    mmmm_runtime::storage::OperationRecord,
    mmmm_runtime::storage::BlobRef,
) {
    // The existing ExecutionPlan/Invocation examples already supply a matching
    // frozen identity. Its Project is deliberately distinct from the native
    // configured workspace so this test detects a Project-filtered journal.
    let mut plan = parse_json(include_bytes!("../../../examples/execution-plan.json")).unwrap();
    plan["planId"] = json!("plan-private-release-write");
    plan["scope"]["resourceIds"] = json!(["resource-private-release-write"]);
    plan["steps"][0]["effect"] = json!("write");
    plan["steps"][0]["resourcesWritten"] = json!(["resource-private-release-write"]);
    plan["steps"][0]["verificationRequirement"] = json!("independent_readback");
    plan["planHash"] = json!(projected_digest("ExecutionPlan", &plan).unwrap());
    let blob = store.save_plan(&plan).unwrap();
    let record = store
        .reserve_operation(mmmm_runtime::storage::ReserveOperation {
            operation_id: mmmm_contracts::OperationId::new("operation-private-release-write")
                .unwrap(),
            principal: PrincipalId::new("principal-fixture").unwrap(),
            project_id: serde_json::from_value(plan["projectId"].clone()).unwrap(),
            idempotency_key: "private-release-write-key".into(),
            plan_id: serde_json::from_value(plan["planId"].clone()).unwrap(),
            plan_hash: serde_json::from_value(plan["planHash"].clone()).unwrap(),
            context_id: serde_json::from_value(plan["contextId"].clone()).unwrap(),
        })
        .unwrap()
        .record()
        .clone();
    (record, blob)
}

#[test]
fn native_fn36_empty_journal_still_has_no_verified_release_evidence() {
    let root = TestRoot::new();
    let (handles, mut fixture, _) = release_fixture(&root);
    let before = fixture
        .service
        .management_store()
        .journal_snapshot_checked(|| Ok(()))
        .unwrap();
    assert!(before.operations().is_empty());
    assert!(before.write_fences().is_empty());
    let result = fixture
        .service
        .call(
            &fixture.authenticated,
            "release.evaluate",
            &release_claim(),
            &fixture.budget,
        )
        .unwrap();
    assert_eq!(result["eligible"], false);
    assert_eq!(result["missingTestIds"].as_array().unwrap().len(), 82);
    assert!(
        result["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["code"] == "VERIFIED_EVIDENCE_MISSING")
    );
    assert_eq!(
        fixture
            .service
            .management_store()
            .journal_snapshot_checked(|| Ok(()))
            .unwrap(),
        before
    );
    assert!(handles.request.occupied_witness().is_err());
}

#[test]
fn native_fn36_reads_fresh_other_project_unsent_writes_without_repair_or_disclosure() {
    let root = TestRoot::new();
    let (handles, mut fixture, _) = release_fixture(&root);
    let (record, _) = queue_other_project_release_write(fixture.service.management_store());
    assert_ne!(
        &record.project_id,
        handles.configured_project.as_ref().unwrap()
    );
    assert!(
        fixture
            .service
            .management_store()
            .unresolved_dispatches()
            .unwrap()
            .is_empty()
    );
    let before = fixture
        .service
        .management_store()
        .journal_snapshot_checked(|| Ok(()))
        .unwrap();
    assert!(before.write_fences().is_empty());
    let error = fixture
        .service
        .call(
            &fixture.authenticated,
            "release.evaluate",
            &release_claim(),
            &fixture.budget,
        )
        .unwrap_err();
    assert_eq!(error.code, "UNRESOLVED_OPERATIONS");
    for private in [
        record.operation_id.as_str(),
        record.project_id.as_str(),
        record.principal.as_str(),
        record.idempotency_key.as_str(),
    ] {
        assert!(!error.to_string().contains(private));
    }
    assert_eq!(
        fixture
            .service
            .management_store()
            .journal_snapshot_checked(|| Ok(()))
            .unwrap(),
        before
    );
    fixture
        .service
        .management_store()
        .request_cancel(&record.operation_id)
        .unwrap();
    let result = fixture
        .service
        .call(
            &fixture.authenticated,
            "release.evaluate",
            &release_claim(),
            &fixture.budget,
        )
        .unwrap();
    assert_eq!(result["eligible"], false);
    assert!(
        result["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["code"] == "VERIFIED_EVIDENCE_MISSING")
    );
    assert!(handles.request.occupied_witness().is_err());
}

#[test]
fn native_fn36_nonowner_keeps_read_project_evaluation_without_whole_journal_access() {
    let root = TestRoot::new();
    let (handles, mut fixture, registries) = release_fixture(&root);
    let (record, _) = queue_other_project_release_write(fixture.service.management_store());
    let workspace = handles.workspace.as_ref().unwrap();
    let context_id = ContextId::new(workspace.context["contextId"].as_str().unwrap()).unwrap();
    let viewer = PrincipalId::new("principal-release-project-viewer").unwrap();
    assert_ne!(&viewer, workspace.witness.principal());
    let project = handles.configured_project.as_ref().unwrap();
    let revision = handles
        .authority
        .stage_project_access(
            viewer.clone(),
            project.clone(),
            workspace.context["scope"].clone(),
            [context_id.clone()].into(),
            Duration::from_secs(30),
        )
        .unwrap();
    handles
        .authority
        .activate_staged_project(&viewer, project, &revision)
        .unwrap();
    let mut sessions = SessionAuthority::new(1).unwrap();
    let token = sessions
        .install(SessionPolicy {
            principal: viewer,
            allowed_methods: ["release.evaluate".into()].into(),
            allowed_contexts: [context_id].into(),
            lifetime: Duration::from_secs(30),
        })
        .unwrap();
    let authenticated = sessions.authenticate_token(&token).unwrap();
    let mut context = workspace.context.clone();
    context["principalRef"] = json!(authenticated.principal());
    context["policyRevision"] = json!(revision);
    context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
    registries
        .contexts
        .borrow_mut()
        .register_workspace(&authenticated, &handles.authority, context, &fixture.budget)
        .unwrap();
    let before = fixture
        .service
        .management_store()
        .journal_snapshot_checked(|| Ok(()))
        .unwrap();
    let result = fixture
        .service
        .call(
            &authenticated,
            "release.evaluate",
            &release_claim(),
            &fixture.budget,
        )
        .unwrap();
    assert_eq!(result["eligible"], false);
    assert_eq!(result["missingTestIds"].as_array().unwrap().len(), 82);
    assert!(
        result["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["code"] == "VERIFIED_EVIDENCE_MISSING")
    );
    let public = String::from_utf8(encode_json(&result).unwrap()).unwrap();
    assert!(!public.contains(record.operation_id.as_str()));
    assert!(!public.contains(record.project_id.as_str()));
    assert_eq!(
        fixture
            .service
            .management_store()
            .journal_snapshot_checked(|| Ok(()))
            .unwrap(),
        before
    );
    assert!(handles.request.occupied_witness().is_err());
}

#[test]
fn native_fn36_preserves_actual_journal_source_error_and_original_cancellation() {
    let root = TestRoot::new();
    let (handles, mut fixture, _) = release_fixture(&root);
    let (record, blob) = queue_other_project_release_write(fixture.service.management_store());
    let path = fixture
        .service
        .management_store()
        .data_root()
        .join("blobs")
        .join(&blob.digest.as_str()[..2])
        .join(&blob.digest.as_str()[2..]);
    assert!(path.starts_with(&root.0));
    let mut changed = fs::read(&path).unwrap();
    changed[0] ^= 1;
    fs::write(&path, &changed).unwrap();
    let error = fixture
        .service
        .call(
            &fixture.authenticated,
            "release.evaluate",
            &release_claim(),
            &fixture.budget,
        )
        .unwrap_err();
    assert_eq!(error.code, "SOURCE_CORRUPT");
    let mut cause = std::error::Error::source(&error);
    let mut original = None;
    while let Some(current) = cause {
        if let Some(storage) = current.downcast_ref::<mmmm_runtime::storage::StorageError>() {
            original = Some(storage);
            break;
        }
        cause = current.source();
    }
    assert!(matches!(
        original,
        Some(mmmm_runtime::storage::StorageError::Corrupt(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), changed);
    assert_eq!(
        fixture
            .service
            .management_store()
            .operation(&record.operation_id)
            .unwrap(),
        record
    );
    fixture.budget.cancellation().store(true, Ordering::Release);
    let cancelled = fixture
        .service
        .call(
            &fixture.authenticated,
            "release.evaluate",
            &release_claim(),
            &fixture.budget,
        )
        .unwrap_err();
    assert_eq!(cancelled.code, "CANCELLED");
    assert_eq!(fs::read(&path).unwrap(), changed);
    assert!(handles.request.occupied_witness().is_err());
}

struct NativeOwnedScene {
    catalog: ProjectCatalog,
    prefab: Value,
    instance: Value,
    patch: Value,
    map: Value,
}
fn native_owned_scene(
    store: &mut DurableStore,
    handles: &mut DaemonHandles,
    budget: &RequestBudget,
) -> NativeOwnedScene {
    native_owned_scene_with_decimal(store, handles, budget, false)
}

fn native_owned_scene_with_decimal(
    store: &mut DurableStore,
    handles: &mut DaemonHandles,
    budget: &RequestBudget,
    decimal: bool,
) -> NativeOwnedScene {
    native_owned_scene_with_artifact_fraction(store, handles, budget, decimal, false)
}

fn native_owned_scene_with_artifact_fraction(
    store: &mut DurableStore,
    handles: &mut DaemonHandles,
    budget: &RequestBudget,
    decimal: bool,
    artifact_fraction: bool,
) -> NativeOwnedScene {
    // Keep only the original static root/door Nodes: the complete example also
    // requires real blockset, CommandModule and Clip sources. This regression
    // exercises Store forwarding, not those separate admission producers.
    let selection = parse_json(include_bytes!("../../../examples/scene-selection.json")).unwrap();
    let mut prefab = selection["prefabs"][0].clone();
    prefab["nodes"]
        .as_array_mut()
        .unwrap()
        .retain(|node| node["nodeId"] == "root" || node["nodeId"] == "door");
    for field in [
        "ports",
        "references",
        "commandModuleIds",
        "clipIds",
        "resources",
    ] {
        prefab[field] = json!([]);
    }
    let decimal_id = ResourceId::new("resource-factory-decimal").unwrap();
    let decimal_resource = raw_resource(decimal_id.clone(), b"x");
    if decimal {
        prefab["resources"] = json!([decimal_resource.clone()]);
        prefab["nodes"][0]["geometryResource"] = json!(decimal_resource.clone());
    }
    prefab["revision"] = json!(projected_digest("Prefab", &prefab).unwrap());
    let original_instance = &selection["instances"][0];
    let mut instance = mmmm_domain::instantiate(&json!({
        "prefab":prefab,"instanceId":original_instance["instanceId"],
        "worldId":original_instance["worldId"],"dimension":original_instance["dimension"],
        "placement":original_instance["placement"],"statePolicy":"defaults",
    }))
    .unwrap()["instance"]
        .clone();
    if decimal {
        prefab["resources"][0]["sizeBytes"] = json!(1.0);
        prefab["nodes"][0]["geometryResource"]["sizeBytes"] = json!(1.0);
        prefab["revision"] = json!(projected_digest("Prefab", &prefab).unwrap());
        instance["prefabRevision"] = prefab["revision"].clone();
        instance["revision"] = json!(projected_digest("Instance", &instance).unwrap());
    }
    let prefab_bytes = encode_json(&prefab).unwrap();
    // Only the independent artifact's wire bytes change. Its parsed Value is
    // deliberately identical: binary64 has rounded this fractional lexeme.
    let artifact_bytes = if artifact_fraction {
        assert!(decimal);
        let text = std::str::from_utf8(&prefab_bytes).unwrap();
        let needle = "\"sizeBytes\":1.0";
        assert_eq!(text.matches(needle).count(), 2);
        let bytes = text
            .replacen(needle, "\"sizeBytes\":1.0000000000000001", 1)
            .into_bytes();
        assert_ne!(bytes, prefab_bytes);
        assert_eq!(parse_json(&bytes).unwrap(), prefab);
        bytes
    } else {
        prefab_bytes.clone()
    };
    let instance_bytes = encode_json(&instance).unwrap();
    let documents = [
        NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &prefab_bytes,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::Instance,
            bytes: &instance_bytes,
        },
    ];
    let project_id = handles.configured_project.as_ref().unwrap().clone();
    let before = store.project(&project_id).unwrap();
    let old_revision: Sha256Digest = serde_json::from_value(before["revision"].clone()).unwrap();
    let old_workspace = handles.workspace.as_ref().unwrap();
    let original_owner = old_workspace.witness.clone();
    let original_scope = old_workspace.context["scope"].clone();
    let original_policy = old_workspace.context["policyRevision"].clone();
    let original_context = old_workspace.context["contextId"].clone();
    let artifact_id = ResourceId::new("resource-factory-owned-prefab").unwrap();
    let map_id = ResourceId::new("resource-factory-owned-map").unwrap();
    let door = prefab["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .position(|node| node["nodeId"] == "door")
        .unwrap();
    let mut map = json!({"contractVersion":"0.2.0","generatorVersion":"factory-integration",
    "inputRevision":old_revision,"entries":[{
        "sourceObjectId":instance["instanceId"],"sourceNodeId":"door",
        "outputResourceId":artifact_id,"locator":format!("/nodes/{door}/transform"),
    }]});
    let artifact = raw_resource(artifact_id.clone(), &artifact_bytes);
    let artifact_metadata = encode_json(&json!(artifact)).unwrap();
    // An unpublished preview derives membership only. The independent map's
    // bytes/hash do not enter either owned document or the Project revision.
    let preview_map_bytes = encode_json(&map).unwrap();
    let preview_map = raw_resource(map_id.clone(), &preview_map_bytes);
    let preview_map_metadata = encode_json(&json!(preview_map)).unwrap();
    let decimal_metadata = encode_json(&json!(decimal_resource)).unwrap();
    let mut preview_raw = vec![
        NativeRawSourceResource {
            metadata: &artifact_metadata,
            bytes: &artifact_bytes,
        },
        NativeRawSourceResource {
            metadata: &preview_map_metadata,
            bytes: &preview_map_bytes,
        },
    ];
    if decimal {
        preview_raw.push(NativeRawSourceResource {
            metadata: &decimal_metadata,
            bytes: b"x",
        });
    }
    let preview = prepare_native_sources(
        store,
        &original_owner,
        &handles.authority,
        budget,
        &NativeSourceInput {
            project: &project_id,
            expected_revision: &old_revision,
            documents: &documents,
            retained_resources: &[],
            raw_resources: &preview_raw,
        },
    )
    .unwrap();
    assert_eq!(preview.resource_count(), if decimal { 3 } else { 2 });
    let next_revision = preview.proposed_revision().unwrap();
    assert_eq!(store.project(&project_id).unwrap(), before);
    assert_eq!(
        handles
            .authority
            .project_scope(original_owner.principal(), &project_id)
            .unwrap(),
        original_scope
    );
    drop(preview);

    map["inputRevision"] = json!(next_revision);
    let map_bytes = encode_json(&map).unwrap();
    let map_pin = raw_resource(map_id.clone(), &map_bytes);
    let map_metadata = encode_json(&json!(map_pin)).unwrap();
    let mut raw_resources = vec![
        NativeRawSourceResource {
            metadata: &artifact_metadata,
            bytes: &artifact_bytes,
        },
        NativeRawSourceResource {
            metadata: &map_metadata,
            bytes: &map_bytes,
        },
    ];
    if decimal {
        raw_resources.push(NativeRawSourceResource {
            metadata: &decimal_metadata,
            bytes: b"x",
        });
    }
    let prepared = prepare_native_sources(
        store,
        &original_owner,
        &handles.authority,
        budget,
        &NativeSourceInput {
            project: &project_id,
            expected_revision: &old_revision,
            documents: &documents,
            retained_resources: &[],
            raw_resources: &raw_resources,
        },
    )
    .unwrap();
    assert_eq!(prepared.proposed_revision().unwrap(), next_revision);
    assert_eq!(prepared.document_count(), 2);
    assert_eq!(prepared.resource_count(), if decimal { 3 } else { 2 });
    let receipt = prepared.commit(store).unwrap();
    assert_eq!(receipt.project_id, project_id);
    assert_eq!(receipt.base_revision, old_revision);
    assert_eq!(receipt.project_revision, next_revision);
    assert_eq!(receipt.documents.len(), 2);
    assert_eq!(receipt.resources.len(), if decimal { 3 } else { 2 });
    if decimal {
        let (_, blob) = receipt
            .resources
            .iter()
            .find(|(id, _)| id == &decimal_id)
            .unwrap();
        assert_eq!(blob.digest, decimal_resource.sha256);
        assert_eq!(blob.byte_length, 1);
        assert_eq!(store.read_blob(blob).unwrap().as_slice(), b"x");
    }
    for (id, resource, bytes) in [
        (artifact_id.clone(), &artifact, &artifact_bytes),
        (map_id.clone(), &map_pin, &map_bytes),
    ] {
        let (_, blob) = receipt
            .resources
            .iter()
            .find(|(actual, _)| actual == &id)
            .unwrap();
        assert_eq!(blob.digest, resource.sha256);
        assert_eq!(store.read_blob(blob).unwrap(), *bytes);
    }
    for (id, bytes) in [
        (&prefab["prefabId"], &prefab_bytes),
        (&instance["instanceId"], &instance_bytes),
    ] {
        let (_, blob) = receipt
            .documents
            .iter()
            .find(|(pin, _)| pin.object_id.as_str() == id.as_str().unwrap())
            .unwrap();
        assert_eq!(store.read_blob(blob).unwrap(), *bytes);
    }
    let project = store.project(&project_id).unwrap();
    assert_eq!(
        store.project_revision(&project_id, &old_revision).unwrap(),
        before
    );
    assert_eq!(project["policyResourceId"], before["policyResourceId"]);
    assert_eq!(project["revision"], json!(next_revision));
    original_owner.check_store(store).unwrap();
    budget.check().unwrap();
    assert_eq!(
        json!(
            handles
                .authority
                .policy_revision(original_owner.principal(), &project_id)
                .unwrap()
        ),
        original_policy
    );
    // No listener, Factory resolver or external session exists yet. Retire the
    // old grant through its actual management path after the factual commit;
    // never expand its scope or revive the consumed prepared authorization.
    handles
        .authority
        .revoke_project(original_owner.principal(), &project_id)
        .unwrap();
    assert!(
        handles
            .authority
            .project_scope(original_owner.principal(), &project_id)
            .is_err()
    );
    // The normal native reader must now resolve the original policy and every
    // admitted source at this exact new revision before it issues fresh scope.
    // A refresh failure would fail this test after the factual commit above;
    // it must not be represented as a rollback of that completed transaction.
    let workspace =
        prepare_workspace(store, &handles.authority, &project_id, budget.deadline()).unwrap();
    assert_eq!(workspace.witness.principal(), original_owner.principal());
    assert_eq!(workspace.project_revision, next_revision);
    assert_ne!(workspace.context["policyRevision"], original_policy);
    assert_ne!(workspace.context["contextId"], original_context);
    assert!(workspace.excluded_sources.is_empty());
    let objects: BTreeSet<String> =
        serde_json::from_value(workspace.context["scope"]["objectIds"].clone()).unwrap();
    assert_eq!(
        objects,
        [
            prefab["prefabId"].as_str().unwrap().to_owned(),
            instance["instanceId"].as_str().unwrap().to_owned()
        ]
        .into()
    );
    let resources: BTreeSet<ResourceId> =
        serde_json::from_value(workspace.context["scope"]["resourceIds"].clone()).unwrap();
    let mut expected_resources: BTreeSet<ResourceId> =
        serde_json::from_value(before["resourceIds"].clone()).unwrap();
    expected_resources.extend([artifact_id, map_id]);
    if decimal {
        expected_resources.insert(decimal_id);
    }
    assert_eq!(resources, expected_resources);
    handles.workspace = Some(workspace);
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    let patch = json!({"contractVersion":"0.2.0","patchId":"patch-factory-owned",
        "projectId":project_id,"baseRevision":catalog.revision(),
        "sourceArtifact":artifact,"sourceMap":map_pin,"entries":[{
            "kind":"update_transform","instanceId":instance["instanceId"],"nodeId":"door",
            "transform":prefab["nodes"][door]["transform"],
        }],"losses":[],"absenceMeansDeletion":false});
    NativeOwnedScene {
        catalog,
        prefab,
        instance,
        patch,
        map,
    }
}
fn raw_resource(id: ResourceId, bytes: &[u8]) -> ResourceRef {
    ResourceRef {
        resource_id: id,
        sha256: raw_digest(bytes),
        media_type: "application/json".into(),
        size_bytes: bytes.len() as u64,
    }
}

#[test]
fn original_fn24_selection_and_explicit_manual_files_reach_common_scene_plan_without_game_claims() {
    use crate::{
        catalog_source::{
            CatalogEnvironmentRegistration, CatalogSourceBacking, CatalogSourceRegistration,
        },
        native_manual_exchange::NativeManualSelection,
    };
    use mmmm_exchange::{patch::DeltaKind, selection::ObjectNode};
    use mmmm_reference::{CatalogLayer, CatalogSourceCodec, CatalogSourceRole};
    use mmmm_runtime::storage::{
        BlobRef,
        owned_documents::{OwnedDocumentKind, OwnedDocumentPin},
    };

    // Reuse the actual protected Store, native Project and authored source
    // import fixture. No bake, game observation, source-rights verifier or
    // alternative session/receipt issuer is introduced for this regression.
    let root = TestRoot::new();
    let mut store = root.open();
    let mut handles = handles(&mut store);
    let budget =
        RequestBudget::new(Duration::from_secs(30), Arc::new(AtomicBool::new(false))).unwrap();
    let inputs = native_owned_scene(&mut store, &mut handles, &budget);
    let original_project = store.project(inputs.catalog.project_id()).unwrap();
    let workspace = handles.workspace.as_ref().unwrap();
    let context = workspace.context.clone();
    let original_scope = context["scope"].clone();
    let original_policy = context["policyRevision"].clone();
    let context_id = ContextId::new(context["contextId"].as_str().unwrap()).unwrap();
    let mut factory = ProductionFactory::offline_owned(binary_digest());
    let parts = factory.compose(&handles, &store).unwrap();
    let registries = factory.registries().unwrap().clone();
    let mut fixture = authenticated_feature_fixture(
        store,
        &handles,
        parts,
        budget.clone(),
        None,
        &[
            "catalog.capture",
            "exchange.prepare",
            "exchange.inspect",
            "scene.diff",
            "scene.plan",
        ],
    );

    // This existing native owner selects its real retained authored document
    // for local reference capture only. It grants no redistribution rights.
    // The capture's explicit offline input consists of this one authored
    // source, with no selected pack or mod inputs. These source metadata labels
    // describe that extraction; they are not a connected-game observation.
    registries.catalog.register(
        &fixture.authenticated, &budget, fixture.service.management_store(),
        CatalogEnvironmentRegistration {
            context: context.clone(), game_version: Some("26.3".into()), locale: Some("en_us".into()),
            artifact_source: None, server_pack_sources: Some(vec![]), client_pack_sources: Some(vec![]),
            mod_sources: Some(BTreeMap::new()),
            registry_generation: Some(format!("authored-source-{}", raw_digest(&encode_json(&inputs.prefab).unwrap()))),
            native_mod_ids: BTreeMap::new(),
            sources: vec![CatalogSourceRegistration {
                source: json!({"sourceId":"source-manual-owned-prefab","kind":"project_declared",
                    "locator":"mmmm-source://unresolved","sha256":null,"rights":"user_local_only",
                    "verifiedAt":"2026-10-14T00:00:00Z"}),
                layer: CatalogLayer::LocalArtifact, role: CatalogSourceRole::CatalogData,
                codec: CatalogSourceCodec::JsonAsset {
                    kind: mmmm_contracts::ResourceLocation::new("mmmm:prefab_source").unwrap(),
                    resource_id: mmmm_contracts::ResourceLocation::new("example:shop").unwrap(),
                    value_type: "raw_prefab_source".into(), unit: "unitless".into(),
                },
                backing: CatalogSourceBacking::OwnedDocument(OwnedDocumentPin {
                    kind: OwnedDocumentKind::Prefab,
                    object_id: serde_json::from_value(inputs.prefab["prefabId"].clone()).unwrap(),
                    revision: serde_json::from_value(inputs.prefab["revision"].clone()).unwrap(),
                }),
            }],
        },
    ).unwrap();
    let sources = registries
        .catalog
        .source_refs(&fixture.authenticated, &context_id, &budget)
        .unwrap();
    let snapshot = fixture
        .service
        .call(
            &fixture.authenticated,
            "catalog.capture",
            &json!({
                "contextId":context_id,"environment":context["environment"],"sources":sources,
                "kind":"local_artifact","loadPolicy":"no_implicit_runtime_mutation",
            }),
            &budget,
        )
        .unwrap();
    assert_eq!(snapshot["sources"][0]["rights"], "user_local_only");
    let mut selection =
        parse_json(include_bytes!("../../../examples/scene-selection.json")).unwrap();
    selection["projectId"] = json!(inputs.catalog.project_id());
    selection["projectRevision"] = json!(inputs.catalog.revision());
    selection["prefabs"] = json!([inputs.prefab]);
    // The stored document retains integer 0; FN24 exports an equivalent 0.0
    // spelling with the same complete canonical value and original revision.
    assert_eq!(
        inputs.prefab["nodes"][0]["transform"]["translation"][0].as_i64(),
        Some(0)
    );
    selection["prefabs"][0]["nodes"][0]["transform"]["translation"][0] = json!(0.0);
    assert_ne!(selection["prefabs"][0], inputs.prefab);
    assert_eq!(
        mmmm_contracts::canonical_digest(&selection["prefabs"][0]).unwrap(),
        mmmm_contracts::canonical_digest(&inputs.prefab).unwrap()
    );
    assert_eq!(
        mmmm_contracts::verify_projected_digest("Prefab", &selection["prefabs"][0]).unwrap(),
        serde_json::from_value::<Sha256Digest>(inputs.prefab["revision"].clone()).unwrap()
    );
    selection["instances"] = json!([inputs.instance]);
    selection["selectedNodeIds"] = json!(["door"]);
    selection["sourceMap"] = inputs.patch["sourceMap"].clone();
    let coordinates = parse_json(include_bytes!("../../../examples/exchange-manifest.json"))
        .unwrap()["coordinates"]
        .clone();
    let manifest = fixture.service.call(&fixture.authenticated, "exchange.prepare", &json!({
        "contextId":context_id,"selection":selection,"dataSnapshotId":snapshot["snapshotId"],"coordinates":coordinates,
    }), &budget).unwrap();
    let selection_pin = manifest["payloads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|payload| payload["kind"] == "selection")
        .unwrap()["resource"]
        .clone();
    assert_eq!(
        selection_pin["sha256"],
        json!(raw_digest(&encode_json(&selection).unwrap()))
    );
    assert!(
        !original_project["resourceIds"]
            .as_array()
            .unwrap()
            .contains(&selection_pin["resourceId"])
    );
    assert_eq!(
        manifest["payloads"]
            .as_array()
            .unwrap()
            .iter()
            .find(|payload| payload["kind"] == "source_map")
            .unwrap()["redistribution"],
        "unknown"
    );

    let map_id = ResourceId::new("resource-native-manual-return-map").unwrap();
    let payload_id = ResourceId::new("resource-native-manual-return-patch").unwrap();
    let map = json!({"contractVersion":"0.2.0","generatorVersion":"manual-authored-static",
        "inputRevision":inputs.catalog.revision(),"entries":[{"sourceObjectId":"instance-shop-a",
            "sourceNodeId":"door","outputResourceId":payload_id,"locator":"/entries/0"}]});
    // Preserve deliberately noncanonical file bytes: the source pins must bind
    // the selected files, rather than a reserialized replacement document.
    let map_bytes = [b" \n".as_slice(), &encode_json(&map).unwrap(), b"\n "].concat();
    let map_pin = raw_resource(map_id.clone(), &map_bytes);
    let mut transform = selection["prefabs"][0]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["nodeId"] == "door")
        .unwrap()["transform"]
        .clone();
    transform["translation"] = json!([3, 2, 0]);
    let payload = json!({"contractVersion":"0.2.0","patchId":"patch-native-manual-file-input",
        "projectId":inputs.catalog.project_id(),"baseRevision":inputs.catalog.revision(),
        "sourceArtifact":selection_pin,"sourceMap":map_pin,"entries":[{"kind":"update_transform",
            "instanceId":"instance-shop-a","nodeId":"door","transform":transform}],
        "losses":[],"absenceMeansDeletion":false});
    let payload_bytes = [b"\n ".as_slice(), &encode_json(&payload).unwrap(), b" \n"].concat();
    let payload_pin = raw_resource(payload_id.clone(), &payload_bytes);
    let map_path = root.0.join("manual-return-map.json");
    let payload_path = root.0.join("manual-return-patch.json");
    fs::write(&map_path, &map_bytes).unwrap();
    fs::write(&payload_path, &payload_bytes).unwrap();
    // The production selector takes ordinary Windows paths. Keep the root's
    // canonical spelling for the existing fixture's ownership and cleanup.
    let ordinary = |path: &Path| {
        #[cfg(windows)]
        let selected = PathBuf::from(
            path.to_str()
                .unwrap()
                .strip_prefix("\\\\?\\")
                .unwrap_or(path.to_str().unwrap()),
        );
        #[cfg(not(windows))]
        let selected = path.to_path_buf();
        assert_eq!(fs::canonicalize(&selected).unwrap(), path);
        selected
    };
    let native = NativeManualSelection {
        project_id: inputs.catalog.project_id().clone(),
        expected_revision: inputs.catalog.revision().clone(),
        context_id: context_id.clone(),
        selection_resource: serde_json::from_value(selection_pin["resourceId"].clone()).unwrap(),
        source_map_resource: map_id,
        edit_payload_resource: payload_id,
        source_map_file: ordinary(&map_path),
        edit_payload_file: ordinary(&payload_path),
        allowed_deltas: vec![(
            ObjectNode {
                instance_id: "instance-shop-a".into(),
                node_id: "door".into(),
            },
            DeltaKind::UpdateTransform,
        )],
    };
    let mut stale = native.clone();
    stale.expected_revision = raw_digest(b"A different native Project head");
    assert_eq!(
        fixture
            .service
            .import_manual_scene(&fixture.authenticated, &stale, &budget)
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
    assert_eq!(
        fixture
            .service
            .management_store()
            .project(inputs.catalog.project_id())
            .unwrap(),
        original_project
    );
    let receipt = fixture
        .service
        .import_manual_scene(&fixture.authenticated, &native, &budget)
        .unwrap();
    assert_eq!(receipt.project_id, *inputs.catalog.project_id());
    let patch_bytes = fixture
        .service
        .management_store()
        .read_blob(&BlobRef {
            digest: receipt.resource.sha256.clone(),
            byte_length: receipt.resource.size_bytes,
        })
        .unwrap();
    let patch = parse_json(&patch_bytes).unwrap();
    assert_eq!(patch["sourceArtifact"], selection_pin);
    assert_eq!(patch["sourceMap"], json!(map_pin));
    assert_eq!(patch["entries"], payload["entries"]);
    assert_eq!(patch["baseRevision"], json!(inputs.catalog.revision()));
    assert_eq!(patch["losses"], json!([]));
    assert_eq!(patch["absenceMeansDeletion"], false);
    assert!(patch.get("artifactId").is_none());
    for (pin, original) in [(&map_pin, &map_bytes), (&payload_pin, &payload_bytes)] {
        assert_eq!(
            fixture
                .service
                .management_store()
                .read_blob(&BlobRef {
                    digest: pin.sha256.clone(),
                    byte_length: pin.size_bytes,
                })
                .unwrap(),
            *original
        );
    }
    assert_eq!(
        fixture
            .service
            .management_store()
            .project(inputs.catalog.project_id())
            .unwrap(),
        original_project
    );
    assert_eq!(
        handles
            .authority
            .project_scope(
                fixture.authenticated.principal(),
                inputs.catalog.project_id()
            )
            .unwrap(),
        original_scope
    );
    assert_eq!(
        json!(
            handles
                .authority
                .policy_revision(
                    fixture.authenticated.principal(),
                    inputs.catalog.project_id()
                )
                .unwrap()
        ),
        original_policy
    );
    assert!(handles.request.current().is_err());

    // Exercise the actual common planner. A successful static import is not a
    // game target/source/Apply approval, so real target admission stays closed.
    let planning = json!({"contextId":context_id,"patch":patch});
    let unavailable = fixture
        .service
        .call(&fixture.authenticated, "scene.plan", &planning, &budget)
        .unwrap_err();
    assert_eq!(unavailable.code, "CONTEXT_UNKNOWN", "{unavailable:?}");
    assert_eq!(
        fixture
            .service
            .management_store()
            .project(inputs.catalog.project_id())
            .unwrap(),
        original_project
    );
    assert!(handles.request.current().is_err());

    // Reading unchanged files/CAS cannot revive the original session or grant.
    fixture._sessions.revoke_all();
    assert_eq!(
        fixture
            .service
            .import_manual_scene(&fixture.authenticated, &native, &budget)
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
    assert_eq!(
        fixture
            .service
            .call(&fixture.authenticated, "scene.plan", &planning, &budget)
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
    assert_eq!(
        fixture
            .service
            .management_store()
            .read_blob(&BlobRef {
                digest: receipt.resource.sha256,
                byte_length: receipt.resource.size_bytes,
            })
            .unwrap(),
        patch_bytes
    );
}

#[test]
fn offline_factory_data_trait_reads_same_store_owned_scene_and_keeps_state_unavailable() {
    let root = TestRoot::new();
    let mut store = root.open();
    let mut handles = handles(&mut store);
    let budget =
        RequestBudget::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false))).unwrap();
    let inputs = native_owned_scene(&mut store, &mut handles, &budget);
    let workspace = handles.workspace.as_ref().unwrap();
    assert!(workspace.excluded_sources.is_empty());
    let principal = workspace.witness.principal().clone();
    let context = workspace.context.clone();
    let expected_root = root.0.clone();
    let mut factory = ProductionFactory::offline_owned(binary_digest());
    let parts = factory.compose(&handles, &store).unwrap();
    let data = parts.data.clone();
    let mut fixture = source_fixture(store, &handles, parts, budget, move |store, request| {
        let actual_store = std::ptr::from_ref(store);
        let frame = PlanningStore::read(store);
        frame.with_read(|store| {
            assert!(std::ptr::eq(store, actual_store));
            assert_eq!(store.data_root(), expected_root.as_path());
            Ok(())
        })?;
        let mut data = data.try_borrow_mut().unwrap();
        let mut source = data.scene_source_with_store(
            &frame,
            &principal,
            &inputs.catalog,
            &inputs.patch,
            &context,
            request.budget(),
        )?;
        assert_eq!(source.artifact, inputs.prefab);
        assert_eq!(source.source_map, inputs.map);
        assert_eq!(
            source.selection.value()["instances"],
            json!([inputs.instance])
        );
        assert!(source.ingested_bake.is_none());
        data.validate_scene_provenance_with_store(
            &frame,
            &principal,
            &inputs.catalog,
            &inputs.patch,
            &source,
            &context,
            request.budget(),
        )?;
        let missing_state = data
            .state_snapshot_with_store(
                &frame,
                &principal,
                &inputs.catalog,
                &inputs.instance,
                &inputs.prefab,
                &context,
                request.budget(),
            )
            .err()
            .expect("Actual retained authoring data cannot issue live state");
        assert_eq!(missing_state.code, "STATE_SNAPSHOT_REQUIRED");
        source.artifact["name"] = json!("Changed after actual source admission");
        let changed = data
            .validate_scene_provenance_with_store(
                &frame,
                &principal,
                &inputs.catalog,
                &inputs.patch,
                &source,
                &context,
                request.budget(),
            )
            .expect_err("The trait/manual wrapper must preserve owned source provenance");
        assert_eq!(changed.code, "SOURCE_PROVENANCE_INVALID");
        frame.with_read(|store| {
            assert_eq!(
                store.project(inputs.catalog.project_id()).unwrap(),
                *inputs.catalog.project()
            );
            Ok(())
        })?;
        Ok(json!({"ownedSourceRead":true,"liveStateIssued":false}))
    });
    assert_eq!(
        fixture.call().unwrap(),
        json!({"ownedSourceRead":true,"liveStateIssued":false})
    );
    assert!(handles.request.occupied_witness().is_err());
}

#[test]
fn offline_factory_data_reads_decimal_prefab_from_native_source_commit() {
    let root = TestRoot::new();
    let mut store = root.open();
    let mut handles = handles(&mut store);
    let budget =
        RequestBudget::new(Duration::from_secs(30), Arc::new(AtomicBool::new(false))).unwrap();
    let inputs = native_owned_scene_with_decimal(&mut store, &mut handles, &budget, true);
    let original_bytes = encode_json(&inputs.prefab).unwrap();
    assert_eq!(
        std::str::from_utf8(&original_bytes)
            .unwrap()
            .matches("\"sizeBytes\":1.0")
            .count(),
        2
    );
    let context = handles.workspace.as_ref().unwrap().context.clone();
    let principal = handles
        .workspace
        .as_ref()
        .unwrap()
        .witness
        .principal()
        .clone();
    let mut factory = ProductionFactory::offline_owned(binary_digest());
    let parts = factory.compose(&handles, &store).unwrap();
    let data = parts.data.clone();
    let mut fixture = source_fixture(store, &handles, parts, budget, move |store, request| {
        let frame = PlanningStore::read(store);
        let mut data = data.try_borrow_mut().unwrap();
        let source = data.scene_source_with_store(
            &frame,
            &principal,
            &inputs.catalog,
            &inputs.patch,
            &context,
            request.budget(),
        )?;
        assert_eq!(source.artifact, inputs.prefab);
        assert_eq!(
            source.selection.value()["prefabs"],
            json!([inputs.prefab.clone()])
        );
        assert_eq!(
            source.selection.value()["instances"],
            json!([inputs.instance.clone()])
        );
        assert!(source.selection.value()["prefabs"][0]["resources"][0]["sizeBytes"].is_f64());
        assert!(
            source.selection.value()["prefabs"][0]["nodes"][0]["geometryResource"]["sizeBytes"]
                .is_f64()
        );
        data.validate_scene_provenance_with_store(
            &frame,
            &principal,
            &inputs.catalog,
            &inputs.patch,
            &source,
            &context,
            request.budget(),
        )?;
        Ok(json!({"nativeDecimalSourceRead":true,"gameOrPlanIssued":false}))
    });
    assert_eq!(
        fixture.call().unwrap(),
        json!({"nativeDecimalSourceRead":true,"gameOrPlanIssued":false})
    );
    assert!(handles.request.occupied_witness().is_err());
}

// This controlled environment stops as soon as actual source preparation has
// finished. It does not issue a target, a game observation or a completed plan.
struct StopAfterScenePreparation;

fn unexpected_scene_test_environment<T>() -> AppResult<T> {
    Err(AppError::new(
        "TEST_UNEXPECTED_ENVIRONMENT",
        "Unexpected fixture environment call",
    ))
}

impl mmmm_planner::PlanningEnvironmentPort for StopAfterScenePreparation {
    fn execution_budget_ms(&mut self, _: &PrincipalId, _: &Value) -> AppResult<u64> {
        unexpected_scene_test_environment()
    }
    fn inventory(
        &mut self,
        _: &PrincipalId,
        _: &Value,
    ) -> AppResult<mmmm_adapters::InventorySnapshot> {
        Err(AppError::new(
            "TEST_SCENE_PREPARED",
            "Scene source preparation reached the inventory boundary",
        ))
    }
    fn binding_dependency(
        &mut self,
        _: &PrincipalId,
        _: &mmmm_contracts::BindingId,
        _: &Sha256Digest,
        _: &Value,
    ) -> AppResult<Value> {
        unexpected_scene_test_environment()
    }
    fn native_route(
        &mut self,
        _: &PrincipalId,
        _: mmmm_planner::NativeKind,
        _: &Value,
    ) -> AppResult<mmmm_planner::NativeActionRoute> {
        unexpected_scene_test_environment()
    }
    fn verified_native_target(
        &mut self,
        _: &PrincipalId,
        _: &TargetProfileId,
        _: mmmm_planner::NativeKind,
        _: &Value,
    ) -> AppResult<mmmm_planner::VerifiedNativeTarget> {
        unexpected_scene_test_environment()
    }
    fn snapshot_native_targets(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &mmmm_planner::PreparedNativeChange,
        _: &Value,
    ) -> AppResult<mmmm_planner::NativeTargetSnapshot> {
        unexpected_scene_test_environment()
    }
    fn registered_action_footprint(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &mmmm_adapters::ActionDescriptor,
        _: &Value,
    ) -> AppResult<mmmm_planner::RegisteredActionFootprint> {
        unexpected_scene_test_environment()
    }
    fn relocatable_modules(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &[Value],
        _: &Value,
    ) -> AppResult<BTreeSet<mmmm_contracts::ModuleId>> {
        unexpected_scene_test_environment()
    }
    fn command_layout_support(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &Value,
    ) -> AppResult<mmmm_domain::commands::CommandLayoutSupport> {
        unexpected_scene_test_environment()
    }
    fn command_layout_request(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &Value,
        _: &Value,
    ) -> AppResult<Value> {
        unexpected_scene_test_environment()
    }
    fn verify_projection_references(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &mmmm_planner::InstanceProjection,
        _: &Value,
    ) -> AppResult<Vec<Value>> {
        Ok(vec![])
    }
    fn compiler_target(
        &mut self,
        _: &PrincipalId,
        _: &TargetProfileId,
        _: &Value,
    ) -> AppResult<mmmm_compiler::VerifiedTarget> {
        unexpected_scene_test_environment()
    }
    fn pack_inputs(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &[Value],
        _: &Value,
    ) -> AppResult<mmmm_compiler::PackBuildInputs> {
        unexpected_scene_test_environment()
    }
    fn recovery_route(
        &mut self,
        _: &PrincipalId,
        _: &mmmm_application::RecoveryPreparation,
        _: &Value,
    ) -> AppResult<mmmm_planner::NativeActionRoute> {
        unexpected_scene_test_environment()
    }
    fn recovery_scope(
        &mut self,
        _: &PrincipalId,
        _: &mmmm_application::RecoveryPreparation,
        _: &ProjectCatalog,
        _: &Value,
    ) -> AppResult<mmmm_runtime::storage::WriteScope> {
        unexpected_scene_test_environment()
    }
    fn project_bindings_available(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
    ) -> AppResult<bool> {
        unexpected_scene_test_environment()
    }
}

#[test]
fn decimal_prefab_reaches_actual_scene_preparation_but_fractional_artifact_does_not() {
    use crate::planning_source::{BorrowedProjectSource, LocalPlanningAccess};
    use mmmm_application::PlanningPort;
    use mmmm_planner::{NativePlanner, PlannerOptions};

    for fractional_artifact in [false, true] {
        let root = TestRoot::new();
        let mut store = root.open();
        let mut handles = handles(&mut store);
        let budget =
            RequestBudget::new(Duration::from_secs(30), Arc::new(AtomicBool::new(false))).unwrap();
        let inputs = native_owned_scene_with_artifact_fraction(
            &mut store,
            &mut handles,
            &budget,
            true,
            fractional_artifact,
        );
        let context = handles.workspace.as_ref().unwrap().context.clone();
        let authority = handles.authority.clone();
        let hosts = handles.hosts.clone();
        let mut factory = ProductionFactory::offline_owned(binary_digest());
        let parts = factory.compose(&handles, &store).unwrap();
        let contexts = parts.contexts.clone();
        let data = parts.data.clone();
        let mut fixture = source_fixture(store, &handles, parts, budget, move |store, request| {
            let principal = request.authenticated().principal().clone();
            let access = LocalPlanningAccess::new(
                request.authenticated().clone(),
                authority.clone(),
                hosts.clone(),
                request.budget().clone(),
                contexts.clone(),
            )?;
            let frame = PlanningStore::write(store);
            let source = BorrowedProjectSource::new(frame, access, data.clone());
            let mut planner = NativePlanner::new(
                Box::new(source),
                Box::new(StopAfterScenePreparation),
                Box::new(SystemClock),
                PlannerOptions::default(),
            )?;
            let plan_request = json!({"projectId":inputs.catalog.project_id(), "expectedRevision":inputs.catalog.revision(),
                "contextId":context["contextId"], "intent":{"kind":"scene.import_patch", "patch":inputs.patch}});
            let error = planner
                .prepare(
                    &principal,
                    &plan_request,
                    inputs.catalog.project(),
                    &context,
                )
                .err()
                .expect("fixture stops before a plan is issued");
            if fractional_artifact {
                assert_eq!(error.code, "INVALID_INPUT", "{error:?}");
                assert_eq!(error.message, "Prefab artifact failed exact validation");
                assert!(matches!(
                    std::error::Error::source(&error).and_then(|cause| {
                        cause.downcast_ref::<
                        mmmm_contracts::validation::ControlledPrefabContractError<AppError>
                    >()
                    }),
                    Some(
                        mmmm_contracts::validation::ControlledPrefabContractError::ExactInteger { .. }
                    )
                ));
            } else {
                assert_eq!(error.code, "TEST_SCENE_PREPARED", "{error:?}");
            }
            Ok(json!({"fractionalArtifact":fractional_artifact,"completePlanIssued":false}))
        });
        assert_eq!(
            fixture.call().unwrap(),
            json!({"fractionalArtifact":fractional_artifact,"completePlanIssued":false})
        );
        assert!(handles.request.occupied_witness().is_err());
    }
}

struct SuppliedPlanningData {
    request: RequestContextSlot,
    expected_store: Rc<Cell<*const DurableStore>>,
    expected_root: PathBuf,
    project: Value,
    patch: Value,
    context: Value,
    budget: RequestBudget,
    reads: Rc<Cell<usize>>,
}
impl PlanningDataPort for SuppliedPlanningData {
    #[allow(
        clippy::too_many_arguments,
        reason = "Observe unchanged source inputs, the original budget and the same call-scoped Store independently"
    )]
    fn scene_source_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<SceneSource> {
        let request = self.request.occupied_witness().unwrap();
        assert_eq!(request.method(), "scene.diff");
        assert_eq!(request.authenticated().principal(), principal);
        assert_eq!(project.project(), &self.project);
        assert_eq!(patch, &self.patch);
        assert_eq!(context, &self.context);
        assert_eq!(budget.deadline(), self.budget.deadline());
        assert!(std::ptr::eq(
            budget.cancellation(),
            self.budget.cancellation()
        ));
        store.with_read(|store| {
            assert!(std::ptr::eq(store, self.expected_store.get()));
            assert_eq!(store.data_root(), self.expected_root.as_path());
            assert_eq!(store.project(project.project_id()).unwrap(), self.project);
            Ok(())
        })?;
        self.reads.set(self.reads.get() + 1);
        // This adapter returns no source, state, grant or native approval.
        Err(AppError::new(
            "SUPPLIED_SOURCE_REACHED",
            "Original supplied source consumed the actual call",
        ))
    }
    fn state_snapshot(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &Value,
        _: &Value,
        _: &RequestBudget,
    ) -> AppResult<ObservedStateSnapshot> {
        Err(AppError::new(
            "LEGACY_SOURCE_UNEXPECTED",
            "Store-aware consumption was required",
        ))
    }
    fn scene_source(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &Value,
        _: &RequestBudget,
    ) -> AppResult<SceneSource> {
        Err(AppError::new(
            "LEGACY_SOURCE_UNEXPECTED",
            "Store-aware consumption was required",
        ))
    }
    fn validate_scene_provenance(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &SceneSource,
        _: &Value,
        _: &RequestBudget,
    ) -> AppResult<()> {
        Err(AppError::new(
            "LEGACY_SOURCE_UNEXPECTED",
            "Store-aware consumption was required",
        ))
    }
}

#[test]
fn explicit_factory_keeps_supplied_data_and_original_store_budget_and_source_inputs() {
    let root = TestRoot::new();
    let mut store = root.open();
    let handles = handles(&mut store);
    let workspace = handles.workspace.as_ref().unwrap();
    let principal = workspace.witness.principal().clone();
    let context = workspace.context.clone();
    let project = store
        .project(handles.configured_project.as_ref().unwrap())
        .unwrap();
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    // The original proposal's unresolved pins are only arguments to a rejecting
    // adapter. They are never registered, read, or promoted to source evidence.
    let mut patch = parse_json(include_bytes!("../../../examples/scene-patch.json")).unwrap();
    patch["projectId"] = json!(catalog.project_id());
    patch["baseRevision"] = json!(catalog.revision());
    let budget =
        RequestBudget::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false))).unwrap();
    let reads = Rc::new(Cell::new(0));
    // This private address is compared, never dereferenced or serialized. It
    // identifies the service's original Store borrow before adapter forwarding.
    let expected_store = Rc::new(Cell::new(std::ptr::null()));
    let supplied: SharedPlanningData = Rc::new(RefCell::new(Box::new(SuppliedPlanningData {
        request: handles.request.clone(),
        expected_store: expected_store.clone(),
        expected_root: root.0.clone(),
        project,
        patch: patch.clone(),
        context: context.clone(),
        budget: budget.clone(),
        reads: reads.clone(),
    })));
    let mut factory = ProductionFactory::new(
        binary_digest(),
        NativeSourceInputs {
            scene_registry: Rc::new(UnregisteredSceneRegistry),
            animation_owner: None,
            data: supplied,
            dependencies: Rc::new(RefCell::new(PlanningDependencyRegistry::default())),
            permissions: None,
            symbols: None,
            readiness: NativeReadinessRegistry::default(),
            planner_options: PlannerOptions::default(),
        },
    );
    let parts = factory.compose(&handles, &store).unwrap();
    let data = parts.data.clone();
    let mut fixture = source_fixture(store, &handles, parts, budget, move |store, request| {
        expected_store.set(std::ptr::from_ref(store));
        data.try_borrow_mut()
            .unwrap()
            .scene_source_with_store(
                &PlanningStore::read(store),
                &principal,
                &catalog,
                &patch,
                &context,
                request.budget(),
            )
            .map(|_| json!({"unexpectedSourceIssued":true}))
    });
    let error = fixture.call().unwrap_err();
    assert_eq!(error.code, "SUPPLIED_SOURCE_REACHED");
    assert_eq!(reads.get(), 1);
    assert!(handles.request.occupied_witness().is_err());
}

#[test]
fn offline_factory_runs_actual_project_inspection_and_pure_prefab_validation() {
    let root = TestRoot::new();
    let mut store = root.open();
    let handles = handles(&mut store);
    let workspace = handles.workspace.as_ref().unwrap();
    let context_id = ContextId::new(workspace.context["contextId"].as_str().unwrap()).unwrap();
    let project = handles.configured_project.as_ref().unwrap().clone();
    let mut factory = ProductionFactory::offline_owned(binary_digest());
    let parts = factory.compose(&handles, &store).unwrap();
    let registries = factory.registries().unwrap();
    assert!(Rc::ptr_eq(&parts.dependencies, &registries.dependencies));
    let actual = handles
        .authority
        .current_context_with_deadline(
            workspace.witness.principal(),
            &context_id,
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
    assert_eq!(actual, workspace.context);
    let planner = StoreAwarePlanner::new(PlanningComposition {
        request: Box::new(handles.request.clone()),
        authority: handles.authority.clone(),
        hosts: handles.hosts.clone(),
        contexts: parts.contexts,
        data: parts.data,
        backend: parts.backend,
        dependencies: parts.dependencies,
        clock: Box::new(SystemClock),
        options: parts.planner_options,
    })
    .unwrap();
    let mut extensions = ExtensionRouter::default();
    extensions
        .register(
            FEATURE_METHODS.iter().copied(),
            Box::new(FeatureExtension::new(parts.features, handles.hosts.clone()).unwrap()),
        )
        .unwrap();
    let mut service = ApplicationService::from_store(
        store,
        ApplicationPorts {
            authority: Box::new(handles.authority.clone()),
            planner: Box::new(planner),
            provider: parts.provider,
            observer: parts.observer,
            ids: Box::new(NoGeneratedIds),
            clock: Box::new(SystemClock),
        },
    );
    service.bind_request_context(handles.request.clone());
    service.set_extensions(extensions);
    let mut sessions = SessionAuthority::new(1).unwrap();
    let token = sessions
        .install(SessionPolicy {
            principal: workspace.witness.principal().clone(),
            allowed_methods: ["project.inspect".to_owned(), "prefab.validate".to_owned()].into(),
            allowed_contexts: [context_id].into(),
            lifetime: Duration::from_secs(30),
        })
        .unwrap();
    let authenticated = sessions.authenticate_token(&token).unwrap();
    let budget =
        RequestBudget::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false))).unwrap();
    let inspected = service
        .call(
            &authenticated,
            "project.inspect",
            &json!({
                "projectId":project, "expectedRevision":null,
            }),
            &budget,
        )
        .unwrap();
    assert_eq!(inspected["project"]["projectId"], project.as_str());
    assert_eq!(
        inspected["project"]["targetProfileId"],
        "unverified-native-target"
    );
    // Actual Rust metadata registration cannot certify current game bindings.
    assert_eq!(inspected["runtimeBindingsAvailable"], false);
    let prefab = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
    let expected = mmmm_domain::prefab_validate(&prefab).unwrap();
    assert_eq!(
        service
            .call(&authenticated, "prefab.validate", &prefab, &budget)
            .unwrap(),
        expected
    );
    // The actual request scope has retired after both common service calls.
    assert!(handles.request.current().is_err());
    sessions.revoke_all();
    assert_eq!(
        service
            .call(
                &authenticated,
                "project.inspect",
                &json!({
                    "projectId":project,"expectedRevision":null,
                }),
                &budget
            )
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
}

#[test]
fn absent_native_data_is_unavailable_and_cancellation_is_preserved() {
    let root = TestRoot::new();
    let mut store = root.open();
    let handles = handles(&mut store);
    let project = store
        .project(handles.configured_project.as_ref().unwrap())
        .unwrap();
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    let workspace = handles.workspace.as_ref().unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let budget = RequestBudget::new(Duration::from_secs(10), cancelled.clone()).unwrap();
    let mut data = UnregisteredPlanningData;
    assert_eq!(
        data.scene_source(
            workspace.witness.principal(),
            &catalog,
            &Value::Null,
            &workspace.context,
            &budget
        )
        .err()
        .unwrap()
        .code,
        "SOURCE_UNAVAILABLE"
    );
    assert_eq!(
        data.state_snapshot(
            workspace.witness.principal(),
            &catalog,
            &Value::Null,
            &Value::Null,
            &workspace.context,
            &budget
        )
        .err()
        .unwrap()
        .code,
        "SOURCE_UNAVAILABLE"
    );
    cancelled.store(true, Ordering::Release);
    let expected = budget.check().unwrap_err().code;
    assert_eq!(
        data.scene_source(
            workspace.witness.principal(),
            &catalog,
            &Value::Null,
            &workspace.context,
            &budget
        )
        .err()
        .unwrap()
        .code,
        expected
    );
}

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
    service.set_extensions(extensions);
    let mut sessions = SessionAuthority::new(1).unwrap();
    let token = sessions
        .install(SessionPolicy {
            principal: workspace.witness.principal().clone(),
            allowed_methods: ["scene.diff".to_owned()].into(),
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
    prefab["revision"] = json!(projected_digest("Prefab", &prefab).unwrap());
    let original_instance = &selection["instances"][0];
    let instance = mmmm_domain::instantiate(&json!({
        "prefab":prefab,"instanceId":original_instance["instanceId"],
        "worldId":original_instance["worldId"],"dimension":original_instance["dimension"],
        "placement":original_instance["placement"],"statePolicy":"defaults",
    }))
    .unwrap()["instance"]
        .clone();
    let prefab_bytes = encode_json(&prefab).unwrap();
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
    let artifact = raw_resource(artifact_id.clone(), &prefab_bytes);
    let artifact_metadata = encode_json(&json!(artifact)).unwrap();
    // An unpublished preview derives membership only. The independent map's
    // bytes/hash do not enter either owned document or the Project revision.
    let preview_map_bytes = encode_json(&map).unwrap();
    let preview_map = raw_resource(map_id.clone(), &preview_map_bytes);
    let preview_map_metadata = encode_json(&json!(preview_map)).unwrap();
    let preview_raw = [
        NativeRawSourceResource {
            metadata: &artifact_metadata,
            bytes: &prefab_bytes,
        },
        NativeRawSourceResource {
            metadata: &preview_map_metadata,
            bytes: &preview_map_bytes,
        },
    ];
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
    let raw_resources = [
        NativeRawSourceResource {
            metadata: &artifact_metadata,
            bytes: &prefab_bytes,
        },
        NativeRawSourceResource {
            metadata: &map_metadata,
            bytes: &map_bytes,
        },
    ];
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
    assert_eq!(prepared.resource_count(), 2);
    let receipt = prepared.commit(store).unwrap();
    assert_eq!(receipt.project_id, project_id);
    assert_eq!(receipt.base_revision, old_revision);
    assert_eq!(receipt.project_revision, next_revision);
    assert_eq!(receipt.documents.len(), 2);
    assert_eq!(receipt.resources.len(), 2);
    for (id, resource, bytes) in [
        (artifact_id.clone(), &artifact, &prefab_bytes),
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

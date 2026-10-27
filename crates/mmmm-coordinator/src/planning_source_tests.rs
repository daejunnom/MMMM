//! Original canonical examples are reused. These external SQLite/CAS tests are
//! needed for real source provenance, history, restart, permissions and bounded
//! reads; they do not establish a verified game profile or native acceptance.
use super::*;
use crate::auth::{SessionAuthority, SessionPolicy};
use mmmm_contracts::{ObjectId, parse_json, projected_digest};
use mmmm_runtime::storage::{StoreConfig, owned_documents::register_owned_document};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(0);
const OWNER_MARKER: &[u8] = b"mmmm-planning-source-tests\n";
struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        assert!(parent.is_absolute());
        let root = parent.join(format!(
            "mmmm-planning-source-{}-{}",
            std::process::id(),
            NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed)
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
        fs::write(root.join("test-owner.txt"), OWNER_MARKER).unwrap();
        Self(root)
    }
    fn open(&self) -> DurableStore {
        DurableStore::open(StoreConfig::new(self.0.clone())).unwrap()
    }
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        // Only this exact created absolute root can be removed. Bound the walk,
        // reject all nested symlink/reparse boundaries, then remove owned data.
        let mut count = 0;
        if fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0)
            && fs::read(self.0.join("test-owner.txt")).ok().as_deref() == Some(OWNER_MARKER)
            && plain_tree(&self.0, 0, &mut count)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
fn plain_tree(path: &Path, depth: usize, count: &mut usize) -> bool {
    if depth > 10 || *count >= 256 {
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
            if !plain_tree(&entry.path(), depth + 1, count) {
                return false;
            }
        }
    } else if !metadata.is_file() {
        return false;
    }
    true
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
fn prefab_source() -> (ObjectPin, Value) {
    let value = example("prefab.json");
    (
        ObjectPin {
            kind: OwnedKind::Prefab,
            object_id: ObjectId::new(value["prefabId"].as_str().unwrap()).unwrap(),
            revision: serde_json::from_value(value["revision"].clone()).unwrap(),
        },
        value,
    )
}
fn project_for(pin: &ObjectPin, resources: &[ResourceId]) -> Value {
    let mut project = example("project.json");
    project["prefabIds"] = json!([pin.object_id]);
    project["instanceIds"] = json!([]);
    project["ownedResources"] = json!([pin]);
    project["resourceIds"] = json!(resources);
    project["revision"] = json!(projected_digest("Project", &project).unwrap());
    project
}
fn register_prefab(store: &mut DurableStore, project: &Value, pin: &ObjectPin, value: &Value) {
    let catalog = ProjectCatalog::from_project(project).unwrap();
    register_owned_document(
        store,
        catalog.project_id(),
        catalog.revision(),
        &document_pin(pin),
        value,
    )
    .unwrap();
}
struct NoData;
impl PlanningDataPort for NoData {
    fn state_snapshot(
        &mut self,
        _p: &PrincipalId,
        _project: &ProjectCatalog,
        _instance: &Value,
        _definition: &Value,
        _context: &Value,
        _budget: &RequestBudget,
    ) -> AppResult<ObservedStateSnapshot> {
        Err(no_data())
    }
    fn scene_source(
        &mut self,
        _p: &PrincipalId,
        _project: &ProjectCatalog,
        _patch: &Value,
        _context: &Value,
        _budget: &RequestBudget,
    ) -> AppResult<SceneSource> {
        Err(no_data())
    }
    fn validate_scene_provenance(
        &mut self,
        _p: &PrincipalId,
        _project: &ProjectCatalog,
        _patch: &Value,
        _source: &SceneSource,
        _context: &Value,
        _budget: &RequestBudget,
    ) -> AppResult<()> {
        Err(no_data())
    }
}
fn no_data() -> AppError {
    error(
        "SOURCE_UNAVAILABLE",
        "No actual state or scene adapter is installed in this source test",
    )
}
fn no_data_port() -> SharedPlanningData {
    Rc::new(RefCell::new(Box::new(NoData)))
}

// This exercises the exact kind-scoped collector used by pack_inputs. The
// isolated values do not grant Project access, authenticate CAS bytes, or
// establish a verified target or an end-to-end pack build.
#[test]
fn pack_owned_resource_pins_ignore_opaque_values_and_keep_declared_refs() {
    let mut prefab = example("prefab.json");
    let mut fake = prefab["resources"][0].clone();
    fake["sha256"] = json!("f".repeat(64));
    prefab["nodes"][0]["extensions"]["test:opaque"] = fake;
    let geometry = json!({"resourceId":"resource-geometry-test","sha256":"a".repeat(64),
        "mediaType":"application/octet-stream","sizeBytes":4});
    prefab["nodes"][0]["geometryResource"] = geometry.clone();
    prefab["revision"] = json!(projected_digest("Prefab", &prefab).unwrap());
    validate("Prefab", &prefab).unwrap();

    let mut asset = example("asset.json");
    asset["resource"] = prefab["resources"][0].clone();
    asset["revision"] = json!(projected_digest("Asset", &asset).unwrap());
    validate("Asset", &asset).unwrap();
    let mut physics = example("physics-definition.json");
    let mesh = json!({"resourceId":"resource-mesh-test","sha256":"b".repeat(64),
        "mediaType":"application/octet-stream","sizeBytes":8});
    physics["colliders"][0]["shape"]["shape"] =
        json!({"kind":"mesh","geometry":mesh,"topologyDigest":"c".repeat(64)});
    physics["revision"] = json!(projected_digest("PhysicsDefinition", &physics).unwrap());
    validate("PhysicsDefinition", &physics).unwrap();
    let instance = example("instance.json");
    let module = example("command-module.json");
    let clip = example("animation-clip.json");
    validate("Instance", &instance).unwrap();
    validate("CommandModule", &module).unwrap();
    validate("AnimationClip", &clip).unwrap();
    let budget =
        RequestBudget::new(Duration::from_secs(5), Arc::new(AtomicBool::new(false))).unwrap();
    let owned = [
        (OwnedKind::Prefab, &prefab),
        (OwnedKind::Asset, &asset),
        (OwnedKind::PhysicsDefinition, &physics),
        (OwnedKind::Instance, &instance),
        (OwnedKind::CommandModule, &module),
        (OwnedKind::Clip, &clip),
    ];
    let pins = owned_pack_resource_pins(owned, &budget).unwrap();
    let ids = pins
        .values()
        .map(|pin| pin.resource_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ids,
        BTreeSet::from([
            "resource-geometry-test",
            "resource-mesh-test",
            "resource-wall-blocks"
        ])
    );
    assert_eq!(pins.len(), 3);

    let mut conflicting = geometry;
    conflicting["sizeBytes"] = json!(5);
    let mut pins = BTreeMap::new();
    gather_resource_pin(&prefab["nodes"][0]["geometryResource"], &mut pins).unwrap();
    assert_eq!(
        gather_resource_pin(&conflicting, &mut pins)
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
    let cancelled =
        RequestBudget::new(Duration::from_secs(5), Arc::new(AtomicBool::new(true))).unwrap();
    assert_eq!(
        owned_pack_resource_pins([(OwnedKind::Prefab, &prefab)], &cancelled)
            .unwrap_err()
            .code,
        "CANCELLED"
    );
}

// A sentinel backend confirms authenticated source bytes reached the backend;
// it issues no target capability and never completes a pack.
struct PackCollectorSentinel {
    reached: Rc<std::cell::Cell<bool>>,
    expected: ResourceRef,
    bytes: Vec<u8>,
}
fn unexpected_pack_port<T>() -> AppResult<T> {
    Err(error(
        "TEST_UNEXPECTED_PORT",
        "Unexpected pack fixture port",
    ))
}
impl PlanningEnvironmentPort for PackCollectorSentinel {
    fn execution_budget_ms(&mut self, _: &PrincipalId, _: &Value) -> AppResult<u64> {
        unexpected_pack_port()
    }
    fn inventory(&mut self, _: &PrincipalId, _: &Value) -> AppResult<InventorySnapshot> {
        unexpected_pack_port()
    }
    fn binding_dependency(
        &mut self,
        _: &PrincipalId,
        _: &BindingId,
        _: &Sha256Digest,
        _: &Value,
    ) -> AppResult<Value> {
        unexpected_pack_port()
    }
    fn native_route(
        &mut self,
        _: &PrincipalId,
        _: NativeKind,
        _: &Value,
    ) -> AppResult<NativeActionRoute> {
        unexpected_pack_port()
    }
    fn verified_native_target(
        &mut self,
        _: &PrincipalId,
        _: &TargetProfileId,
        _: NativeKind,
        _: &Value,
    ) -> AppResult<VerifiedNativeTarget> {
        unexpected_pack_port()
    }
    fn snapshot_native_targets(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &PreparedNativeChange,
        _: &Value,
    ) -> AppResult<NativeTargetSnapshot> {
        unexpected_pack_port()
    }
    fn registered_action_footprint(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &ActionDescriptor,
        _: &Value,
    ) -> AppResult<RegisteredActionFootprint> {
        unexpected_pack_port()
    }
    fn relocatable_modules(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &[Value],
        _: &Value,
    ) -> AppResult<BTreeSet<ModuleId>> {
        unexpected_pack_port()
    }
    fn command_layout_support(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &Value,
    ) -> AppResult<CommandLayoutSupport> {
        unexpected_pack_port()
    }
    fn command_layout_request(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &Value,
        _: &Value,
    ) -> AppResult<Value> {
        unexpected_pack_port()
    }
    fn verify_projection_references(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &InstanceProjection,
        _: &Value,
    ) -> AppResult<Vec<Value>> {
        unexpected_pack_port()
    }
    fn compiler_target(
        &mut self,
        _: &PrincipalId,
        _: &TargetProfileId,
        _: &Value,
    ) -> AppResult<VerifiedTarget> {
        unexpected_pack_port()
    }
    fn pack_inputs(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &[Value],
        _: &Value,
    ) -> AppResult<PackBuildInputs> {
        unexpected_pack_port()
    }
    fn recovery_route(
        &mut self,
        _: &PrincipalId,
        _: &RecoveryPreparation,
        _: &Value,
    ) -> AppResult<NativeActionRoute> {
        unexpected_pack_port()
    }
    fn recovery_scope(
        &mut self,
        _: &PrincipalId,
        _: &RecoveryPreparation,
        _: &ProjectCatalog,
        _: &Value,
    ) -> AppResult<WriteScope> {
        unexpected_pack_port()
    }
    fn project_bindings_available(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
    ) -> AppResult<bool> {
        unexpected_pack_port()
    }
}
impl PlanningBackendPort for PackCollectorSentinel {
    fn verify_live_target(
        &mut self,
        _: &PrincipalId,
        _: &TargetProfileId,
        _: &Value,
        _: &Value,
        _: &RequestBudget,
    ) -> AppResult<VerifiedPlanningTarget> {
        unexpected_pack_port()
    }
    fn lower_owned_pack(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &[Value],
        resources: &[SceneResource],
        _: &Value,
        _: &RequestBudget,
    ) -> AppResult<PackBuildInputs> {
        self.reached.set(true);
        assert_eq!(resources.len(), 1);
        assert_eq!(
            resources[0].reference.resource_id,
            self.expected.resource_id
        );
        assert_eq!(resources[0].reference.sha256, self.expected.sha256);
        assert_eq!(resources[0].reference.media_type, self.expected.media_type);
        assert_eq!(resources[0].reference.size_bytes, self.expected.size_bytes);
        assert_eq!(resources[0].bytes, self.bytes);
        Err(error(
            "TEST_PACK_SENTINEL",
            "Authorized source reached the controlled backend",
        ))
    }
}

#[test]
fn pack_inputs_reaches_backend_only_with_authorized_declared_cas_resource() {
    let root = TestRoot::new();
    let mut store = root.open();
    let bytes = b"actual owned pack input".to_vec();
    let blob = store.put_blob(&bytes).unwrap();
    let resource = ResourceRef {
        resource_id: ResourceId::new("resource-pack-declared").unwrap(),
        sha256: blob.digest,
        media_type: "application/octet-stream".into(),
        size_bytes: bytes.len() as u64,
    };
    let (mut pin, mut prefab) = prefab_source();
    prefab["resources"] = json!([resource]);
    for node in prefab["nodes"].as_array_mut().unwrap() {
        node.as_object_mut().unwrap().remove("blockGeometry");
    }
    prefab["nodes"][0]["extensions"]["test:opaque"] = json!({
        "resourceId":"resource-pack-opaque-unregistered", "sha256":"f".repeat(64),
        "mediaType":"application/octet-stream", "sizeBytes":1
    });
    prefab["revision"] = json!(projected_digest("Prefab", &prefab).unwrap());
    validate("Prefab", &prefab).unwrap();
    mmmm_contracts::verify_projected_digest("Prefab", &prefab).unwrap();
    pin.revision = serde_json::from_value(prefab["revision"].clone()).unwrap();
    let project = project_for(&pin, std::slice::from_ref(&resource.resource_id));
    store.save_project(&project, None).unwrap();
    register_prefab(&mut store, &project, &pin, &prefab);
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    register_resource(
        &mut store,
        &serde_json::to_value(&resource).unwrap(),
        ResourceOwner::Project(catalog.project_id().clone()),
    )
    .unwrap();
    let reached = Rc::new(std::cell::Cell::new(false));
    let backend: SharedPlanningBackend = Rc::new(RefCell::new(Box::new(PackCollectorSentinel {
        reached: reached.clone(),
        expected: resource.clone(),
        bytes,
    })));
    let dependencies = Rc::new(RefCell::new(PlanningDependencyRegistry::default()));
    let allowed = AccessFixture::new(&catalog);
    let mut environment = ConcretePlanningEnvironment::new(
        PlanningStore::read(&store),
        allowed.access.clone(),
        no_data_port(),
        backend.clone(),
        dependencies.clone(),
    );
    let result = environment.pack_inputs(
        allowed.access.principal(),
        &catalog,
        std::slice::from_ref(&prefab),
        &allowed.context,
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("sentinel must stop before pack completion"),
    };
    assert_eq!(error.code, "TEST_PACK_SENTINEL");
    assert!(reached.get());

    reached.set(false);
    let denied = AccessFixture::scoped(&catalog, vec![pin.object_id.to_string()], vec![]);
    let mut denied_source = BorrowedProjectSource::new(
        PlanningStore::read(&store),
        denied.access.clone(),
        no_data_port(),
    );
    assert_eq!(
        denied_source
            .owned_object(
                denied.access.principal(),
                &catalog,
                &pin,
                Some(&denied.context),
                MAX_DOCUMENT_BYTES
            )
            .unwrap(),
        prefab,
    );
    let denied_resource = denied_source.resource_bytes(
        denied.access.principal(),
        &catalog,
        &resource,
        Some(&denied.context),
        MAX_SOURCE_BYTES,
    );
    let denied_error = match denied_resource {
        Ok(_) => panic!("resource scope must reject"),
        Err(error) => error,
    };
    assert_eq!(denied_error.code, "PERMISSION_REQUIRED");
    let mut environment = ConcretePlanningEnvironment::new(
        PlanningStore::read(&store),
        denied.access.clone(),
        no_data_port(),
        backend,
        dependencies,
    );
    let denied_pack = match environment.pack_inputs(
        denied.access.principal(),
        &catalog,
        &[prefab],
        &denied.context,
    ) {
        Ok(_) => panic!("pack input resource scope must reject"),
        Err(error) => error,
    };
    assert_eq!(denied_pack.code, "PERMISSION_REQUIRED");
    assert!(!reached.get());
}

struct AccessFixture {
    sessions: SessionAuthority,
    token: crate::credential::SecretToken,
    authority: LocalAuthority,
    access: LocalPlanningAccess,
    context: Value,
    cancelled: Arc<AtomicBool>,
}
impl AccessFixture {
    fn new(project: &ProjectCatalog) -> Self {
        Self::scoped(
            project,
            project
                .pins()
                .iter()
                .map(|pin| pin.object_id.as_str().to_owned())
                .collect(),
            project.resource_ids().iter().cloned().collect(),
        )
    }
    fn scoped(
        project: &ProjectCatalog,
        object_ids: Vec<String>,
        resource_ids: Vec<ResourceId>,
    ) -> Self {
        let hosts = HostBridge::default();
        let authority = LocalAuthority::new(hosts.clone());
        let principal_id = PrincipalId::new("principal-planning-source").unwrap();
        let context_id = ContextId::new("context-workspace-planning").unwrap();
        let scope = json!({"projectId":project.project_id(),"objectIds":object_ids,
            "resourceIds":resource_ids,"regions":[],"externalTargetIds":[]});
        let revision = authority
            .stage_project_access(
                principal_id.clone(),
                project.project_id().clone(),
                scope.clone(),
                [context_id.clone()].into(),
                Duration::from_secs(120),
            )
            .unwrap();
        authority
            .activate_staged_project(&principal_id, project.project_id(), &revision)
            .unwrap();
        let mut sessions = SessionAuthority::new(2).unwrap();
        let token = sessions
            .install(SessionPolicy {
                principal: principal_id,
                allowed_methods: ["project.inspect".into(), "plan.create".into()].into(),
                allowed_contexts: [context_id.clone()].into(),
                lifetime: Duration::from_secs(120),
            })
            .unwrap();
        let authenticated = sessions.authenticate_token(&token).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let budget = RequestBudget::new(Duration::from_secs(120), cancelled.clone()).unwrap();
        let mut context = json!({"contractVersion":"0.2.0","contextId":context_id,"principalRef":authenticated.principal(),
            "projectId":project.project_id(),"environment":{"kind":"offline","workspaceId":"workspace-source-test","side":"offline"},
            "policyRevision":revision,"scope":scope,"contextDigest":"0".repeat(64)});
        context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
        let mut workspace = RegisteredWorkspaceContexts::default();
        workspace
            .register(&authenticated, &authority, context.clone(), &budget)
            .unwrap();
        let contexts: SharedPlanningContexts = Rc::new(RefCell::new(Box::new(
            RegisteredPlanningContexts::new(workspace),
        )));
        let access =
            LocalPlanningAccess::new(authenticated, authority.clone(), hosts, budget, contexts)
                .unwrap();
        Self {
            sessions,
            token,
            authority,
            access,
            context,
            cancelled,
        }
    }
}

#[test]
fn current_owned_sources_are_actual_cas_records_without_a_game_context() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (pin, prefab) = prefab_source();
    let project = project_for(&pin, &[]);
    store.save_project(&project, None).unwrap();
    register_prefab(&mut store, &project, &pin, &prefab);
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    let auth = AccessFixture::new(&catalog);
    let mut source = BorrowedProjectSource::new(
        PlanningStore::read(&store),
        auth.access.clone(),
        no_data_port(),
    );
    let read = source
        .inspect_owned(auth.access.principal(), &catalog, MAX_SOURCE_BYTES)
        .unwrap();
    assert_eq!(read.len(), 1);
    assert_eq!(read[0].0, pin);
    assert_eq!(read[0].1, prefab);
}

#[test]
fn historical_owned_pin_is_resolved_from_real_provenance_after_head_advances() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (old_pin, old_prefab) = prefab_source();
    let old_project = project_for(&old_pin, &[]);
    let old_catalog = ProjectCatalog::from_project(&old_project).unwrap();
    store.save_project(&old_project, None).unwrap();
    register_prefab(&mut store, &old_project, &old_pin, &old_prefab);
    let mut current_prefab = old_prefab.clone();
    current_prefab["name"] = json!("Changed authoring definition");
    current_prefab["revision"] = json!(projected_digest("Prefab", &current_prefab).unwrap());
    let mut current_pin = old_pin.clone();
    current_pin.revision = serde_json::from_value(current_prefab["revision"].clone()).unwrap();
    let current_project = project_for(&current_pin, &[]);
    store
        .save_project(&current_project, Some(old_catalog.revision()))
        .unwrap();
    register_prefab(&mut store, &current_project, &current_pin, &current_prefab);
    let current = ProjectCatalog::from_project(&current_project).unwrap();
    let auth = AccessFixture::new(&current);
    let mut source = BorrowedProjectSource::new(
        PlanningStore::read(&store),
        auth.access.clone(),
        no_data_port(),
    );
    assert_eq!(
        source
            .owned_object(
                auth.access.principal(),
                &current,
                &old_pin,
                None,
                MAX_DOCUMENT_BYTES
            )
            .unwrap(),
        old_prefab
    );
    assert_eq!(
        source
            .owned_object(
                auth.access.principal(),
                &current,
                &current_pin,
                None,
                MAX_DOCUMENT_BYTES
            )
            .unwrap(),
        current_prefab
    );
    let missing = ObjectPin {
        revision: raw_digest(b"never registered prefab"),
        ..old_pin
    };
    assert!(
        source
            .owned_object(
                auth.access.principal(),
                &current,
                &missing,
                None,
                MAX_DOCUMENT_BYTES
            )
            .is_err()
    );
}

#[test]
fn caller_catalog_and_digest_knowledge_do_not_register_owned_sources() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (pin, prefab) = prefab_source();
    let project = project_for(&pin, &[]);
    store.save_project(&project, None).unwrap();
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    let auth = AccessFixture::new(&catalog);
    let mut source = BorrowedProjectSource::new(
        PlanningStore::read(&store),
        auth.access.clone(),
        no_data_port(),
    );
    assert!(
        source
            .owned_object(
                auth.access.principal(),
                &catalog,
                &pin,
                None,
                MAX_DOCUMENT_BYTES
            )
            .is_err()
    );
    drop(source);
    register_prefab(&mut store, &project, &pin, &prefab);
    let mut caller_project = project;
    caller_project["name"] = json!("Caller supplied a different stored project");
    caller_project["revision"] = json!(projected_digest("Project", &caller_project).unwrap());
    let caller = ProjectCatalog::from_project(&caller_project).unwrap();
    let mut source = BorrowedProjectSource::new(
        PlanningStore::read(&store),
        auth.access.clone(),
        no_data_port(),
    );
    assert_eq!(
        source
            .owned_object(
                auth.access.principal(),
                &caller,
                &pin,
                None,
                MAX_DOCUMENT_BYTES
            )
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
}

#[test]
fn owned_reads_reject_revoked_authentication_and_current_project_acl() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (pin, prefab) = prefab_source();
    let project = project_for(&pin, &[]);
    store.save_project(&project, None).unwrap();
    register_prefab(&mut store, &project, &pin, &prefab);
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    let mut auth = AccessFixture::new(&catalog);
    let mut source = BorrowedProjectSource::new(
        PlanningStore::read(&store),
        auth.access.clone(),
        no_data_port(),
    );
    auth.sessions.revoke(&auth.token);
    assert_eq!(
        source
            .owned_object(
                auth.access.principal(),
                &catalog,
                &pin,
                None,
                MAX_DOCUMENT_BYTES
            )
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
    drop(source);
    let auth = AccessFixture::new(&catalog);
    let mut source = BorrowedProjectSource::new(
        PlanningStore::read(&store),
        auth.access.clone(),
        no_data_port(),
    );
    auth.authority
        .revoke_project(auth.access.principal(), catalog.project_id())
        .unwrap();
    assert_eq!(
        source
            .inspect_owned(auth.access.principal(), &catalog, MAX_SOURCE_BYTES)
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
}

#[test]
fn source_budget_and_cancellation_are_checked_before_releasing_owned_bytes() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (pin, prefab) = prefab_source();
    let project = project_for(&pin, &[]);
    store.save_project(&project, None).unwrap();
    register_prefab(&mut store, &project, &pin, &prefab);
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    let auth = AccessFixture::new(&catalog);
    let mut source = BorrowedProjectSource::new(
        PlanningStore::read(&store),
        auth.access.clone(),
        no_data_port(),
    );
    assert_eq!(
        source
            .owned_object(auth.access.principal(), &catalog, &pin, None, 10)
            .unwrap_err()
            .code,
        "BUDGET_EXCEEDED"
    );
    auth.cancelled.store(true, Ordering::Release);
    assert_eq!(
        source
            .owned_object(
                auth.access.principal(),
                &catalog,
                &pin,
                None,
                MAX_DOCUMENT_BYTES
            )
            .unwrap_err()
            .code,
        "CANCELLED"
    );
}

#[test]
fn active_project_access_cannot_read_sources_outside_actual_current_scope() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (pin, prefab) = prefab_source();
    let id = ResourceId::new("resource-outside-source-scope").unwrap();
    let project = project_for(&pin, std::slice::from_ref(&id));
    store.save_project(&project, None).unwrap();
    register_prefab(&mut store, &project, &pin, &prefab);
    let bytes = b"registered but not granted";
    let blob = store.put_blob(bytes).unwrap();
    let resource = ResourceRef {
        resource_id: id,
        sha256: blob.digest,
        media_type: "application/octet-stream".into(),
        size_bytes: bytes.len() as u64,
    };
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    register_resource(
        &mut store,
        &serde_json::to_value(&resource).unwrap(),
        ResourceOwner::Project(catalog.project_id().clone()),
    )
    .unwrap();
    let auth = AccessFixture::scoped(&catalog, vec![], vec![]);
    let mut source = BorrowedProjectSource::new(
        PlanningStore::read(&store),
        auth.access.clone(),
        no_data_port(),
    );
    for context in [None, Some(&auth.context)] {
        assert_eq!(
            source
                .owned_object(
                    auth.access.principal(),
                    &catalog,
                    &pin,
                    context,
                    MAX_DOCUMENT_BYTES
                )
                .unwrap_err()
                .code,
            "PERMISSION_REQUIRED"
        );
        assert_eq!(
            source
                .resource_bytes(auth.access.principal(), &catalog, &resource, context, 1024)
                .err()
                .expect("expected rejection")
                .code,
            "PERMISSION_REQUIRED"
        );
        assert_eq!(
            source
                .resource_pin(
                    auth.access.principal(),
                    &catalog,
                    resource.resource_id.as_str(),
                    context
                )
                .unwrap_err()
                .code,
            "PERMISSION_REQUIRED"
        );
    }
}

#[test]
fn private_staging_pins_exact_project_owned_content_and_survives_gc_and_restart() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (pin, _) = prefab_source();
    let project = project_for(&pin, &[]);
    store.save_project(&project, None).unwrap();
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    let auth = AccessFixture::new(&catalog);
    let resource;
    {
        let mut source = BorrowedProjectSource::new(
            PlanningStore::write(&mut store),
            auth.access.clone(),
            no_data_port(),
        );
        resource = source
            .stage_private(
                auth.access.principal(),
                &catalog,
                None,
                b"immutable prepared source",
                "application/octet-stream",
                &auth.context,
            )
            .unwrap();
        assert_eq!(
            source
                .resource_bytes(
                    auth.access.principal(),
                    &catalog,
                    &resource,
                    Some(&auth.context),
                    1024
                )
                .unwrap()
                .bytes,
            b"immutable prepared source"
        );
    }
    assert_eq!(store.project(catalog.project_id()).unwrap(), project);
    store.collect_orphan_blobs(100).unwrap();
    drop(store);
    let store = root.open();
    let mut denied = BorrowedProjectSource::new(
        PlanningStore::read(&store),
        auth.access.clone(),
        no_data_port(),
    );
    // Restart retains bytes and ownership, but does not retain this call's
    // private producer permission. Guessing its content-derived ID cannot read.
    assert_eq!(
        denied
            .resource_bytes(auth.access.principal(), &catalog, &resource, None, 1024)
            .err()
            .expect("expected rejection")
            .code,
        "PERMISSION_REQUIRED"
    );
    let fresh = AccessFixture::scoped(
        &catalog,
        catalog
            .pins()
            .iter()
            .map(|pin| pin.object_id.as_str().to_owned())
            .collect(),
        vec![resource.resource_id.clone()],
    );
    let mut source = BorrowedProjectSource::new(
        PlanningStore::read(&store),
        fresh.access.clone(),
        no_data_port(),
    );
    assert_eq!(
        source
            .resource_pin(
                fresh.access.principal(),
                &catalog,
                resource.resource_id.as_str(),
                None
            )
            .unwrap()
            .sha256,
        resource.sha256
    );
    let bytes = source
        .resource_bytes(fresh.access.principal(), &catalog, &resource, None, 1024)
        .unwrap();
    assert_eq!(bytes.bytes, b"immutable prepared source");
    assert_eq!(bytes.resource.media_type, resource.media_type);
}

#[test]
fn desired_private_identity_cannot_be_silently_rebound() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (pin, _) = prefab_source();
    let project = project_for(&pin, &[]);
    store.save_project(&project, None).unwrap();
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    let auth = AccessFixture::new(&catalog);
    let id = ResourceId::new("private-original-identity").unwrap();
    let mut source = BorrowedProjectSource::new(
        PlanningStore::write(&mut store),
        auth.access.clone(),
        no_data_port(),
    );
    let original = source
        .stage_private(
            auth.access.principal(),
            &catalog,
            Some(&id),
            b"first",
            "application/octet-stream",
            &auth.context,
        )
        .unwrap();
    assert_eq!(
        source
            .stage_private(
                auth.access.principal(),
                &catalog,
                Some(&id),
                b"second",
                "application/octet-stream",
                &auth.context
            )
            .unwrap_err()
            .code,
        "RESOURCE_REGISTRATION_CONFLICT"
    );
    assert_eq!(
        source
            .resource_bytes(
                auth.access.principal(),
                &catalog,
                &original,
                Some(&auth.context),
                1024
            )
            .unwrap()
            .bytes,
        b"first"
    );
}

#[test]
fn resource_read_requires_registered_metadata_and_exact_hash_length_media() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (pin, _) = prefab_source();
    let id = ResourceId::new("resource-actual-source").unwrap();
    let project = project_for(&pin, std::slice::from_ref(&id));
    store.save_project(&project, None).unwrap();
    let bytes = b"actual source bytes";
    let blob = store.put_blob(bytes).unwrap();
    let resource = ResourceRef {
        resource_id: id,
        sha256: blob.digest,
        media_type: "application/octet-stream".into(),
        size_bytes: bytes.len() as u64,
    };
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    let auth = AccessFixture::new(&catalog);
    {
        let mut source = BorrowedProjectSource::new(
            PlanningStore::read(&store),
            auth.access.clone(),
            no_data_port(),
        );
        assert!(
            source
                .resource_bytes(auth.access.principal(), &catalog, &resource, None, 1024)
                .is_err()
        );
    }
    register_resource(
        &mut store,
        &serde_json::to_value(&resource).unwrap(),
        ResourceOwner::Project(catalog.project_id().clone()),
    )
    .unwrap();
    let mut source = BorrowedProjectSource::new(
        PlanningStore::read(&store),
        auth.access.clone(),
        no_data_port(),
    );
    assert_eq!(
        source
            .resource_bytes(auth.access.principal(), &catalog, &resource, None, 1024)
            .unwrap()
            .bytes,
        bytes
    );
    let mut replaced = resource.clone();
    replaced.media_type = "application/json".into();
    assert_eq!(
        source
            .resource_bytes(auth.access.principal(), &catalog, &replaced, None, 1024)
            .err()
            .expect("expected rejection")
            .code,
        "REVISION_CONFLICT"
    );
    replaced = resource.clone();
    replaced.size_bytes += 1;
    assert_eq!(
        source
            .resource_bytes(auth.access.principal(), &catalog, &replaced, None, 1024)
            .err()
            .expect("expected rejection")
            .code,
        "REVISION_CONFLICT"
    );
    replaced = resource;
    replaced.sha256 = raw_digest(b"caller selected another digest");
    assert_eq!(
        source
            .resource_bytes(auth.access.principal(), &catalog, &replaced, None, 1024)
            .err()
            .expect("expected rejection")
            .code,
        "REVISION_CONFLICT"
    );
}

#[test]
fn workspace_registration_is_exact_and_rechecks_the_real_policy_scope() {
    let (pin, _) = prefab_source();
    let catalog = ProjectCatalog::from_project(&project_for(&pin, &[])).unwrap();
    let auth = AccessFixture::new(&catalog);
    auth.access
        .authorize_project(
            auth.access.principal(),
            catalog.project_id(),
            Some(&auth.context),
            Access::Plan,
        )
        .unwrap();
    let mut widened = auth.context.clone();
    widened["scope"]["objectIds"]
        .as_array_mut()
        .unwrap()
        .push(json!("object-ungranted"));
    widened["contextDigest"] = json!(projected_digest("ExecutionContext", &widened).unwrap());
    assert!(
        auth.access
            .authorize_project(
                auth.access.principal(),
                catalog.project_id(),
                Some(&widened),
                Access::Plan
            )
            .is_err()
    );
    auth.authority
        .revoke_project(auth.access.principal(), catalog.project_id())
        .unwrap();
    assert!(
        auth.access
            .authorize_project(
                auth.access.principal(),
                catalog.project_id(),
                Some(&auth.context),
                Access::ReadProject
            )
            .is_err()
    );
}

#[test]
fn safe_store_borrows_reject_conflict_and_read_only_staging() {
    let root = TestRoot::new();
    let mut store = root.open();
    let shared = PlanningStore::write(&mut store);
    assert_eq!(
        shared
            .with_write(|_| shared.with_read(|_| Ok(())))
            .unwrap_err()
            .code,
        "SOURCE_BUSY"
    );
    drop(shared);
    let shared = PlanningStore::read(&store);
    assert_eq!(
        shared.with_write(|_| Ok(())).unwrap_err().code,
        "READ_ONLY_SOURCE"
    );
}

#[test]
fn host_artifact_cannot_claim_rust_owned_component_provenance() {
    let binding = BindingId::new("binding-owned-source").unwrap();
    let action_id = "fixture:echo_text".to_owned();
    let contract_ids = BTreeSet::from(["FN09".to_owned()]);
    for component in ["mmmm-compiler", "mmmm-rust-authored-projection"] {
        assert!(
            RegisteredPlanningDependency::host_artifact(
                binding.clone(),
                component.into(),
                raw_digest(b"host jar"),
                [action_id.clone()].into(),
                contract_ids.clone()
            )
            .is_err()
        );
    }
    let executable = RegisteredPlanningDependency::owned_executable(
        BindingId::new("binding-rust-executable").unwrap(),
        raw_digest(b"actual Rust executable fixture bytes"),
        [action_id.clone()].into(),
        contract_ids.clone(),
    )
    .unwrap();
    assert_eq!(executable.component, "mmmm-rust-authored-projection");
    assert_eq!(executable.provenance, "owned_domain");
    assert_ne!(executable.digest, raw_digest(b"host jar"));
    let mut registry = PlanningDependencyRegistry::default();
    let dependency = RegisteredPlanningDependency::owned(
        binding.clone(),
        OwnedPlanningComponent::Compiler,
        [action_id].into(),
        contract_ids,
    )
    .unwrap();
    registry.register(dependency).unwrap();
    let mut action: ActionDescriptor =
        serde_json::from_value(example("provider-supported.json")["actions"][0].clone()).unwrap();
    action.implementation_digest = mmmm_compiler::compiler_digest();
    let pin = registry
        .pin(&binding, &action.implementation_digest, &[&action])
        .unwrap();
    assert_eq!(pin["componentId"], "mmmm-compiler");
    assert_eq!(pin["provenanceClass"], "owned_domain");
    assert!(
        pin["contractIds"]
            .as_array()
            .unwrap()
            .contains(&json!(action.action_id))
    );
    assert!(
        registry
            .pin(&binding, &raw_digest(b"host jar"), &[&action])
            .is_err()
    );
}

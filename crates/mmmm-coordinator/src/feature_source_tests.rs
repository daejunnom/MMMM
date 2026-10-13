//! Real SQLite/CAS coverage for feature source authorization and manual edits.
//! The original fixture artifact remains an unverified estimate: these tests
//! issue no solver result, game observation, target approval or license proof.
use super::*;
use crate::{
    auth::{SessionAuthority, SessionPolicy},
    planning_context::{
        RegisteredContextLocator, planning_context_adapter, workspace_context_resolver,
    },
    planning_source::{ObservedStateSnapshot, PlanningDataPort},
};
use mmmm_contracts::{parse_json, projected_digest};
use mmmm_exchange::patch::DeltaKind;
use mmmm_planner::SceneSource;
use mmmm_runtime::storage::{
    BlobRef, StoreConfig,
    owned_documents::{OwnedDocumentPin, register_owned_document},
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const OWNER_MARKER: &[u8] = b"mmmm-feature-source-tests\n";
struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        assert!(parent.is_absolute());
        let parent = fs::canonicalize(parent).unwrap();
        let root = parent.join(format!(
            "mmmm-feature-source-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
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
        assert!(
            root.is_absolute()
                && root.starts_with(&parent)
                && root.parent() == Some(parent.as_path())
        );
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
        let mut count = 0;
        if self.0.is_absolute()
            && fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0)
            && fs::read(self.0.join("test-owner.txt")).ok().as_deref() == Some(OWNER_MARKER)
            && plain_tree(&self.0, 0, &mut count)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
fn plain_tree(path: &Path, depth: usize, count: &mut usize) -> bool {
    if depth > 16 || *count >= 1024 {
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
struct NoData;
impl PlanningDataPort for NoData {
    fn state_snapshot(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &Value,
        _: &Value,
        _: &RequestBudget,
    ) -> AppResult<ObservedStateSnapshot> {
        Err(unavailable())
    }
    fn scene_source(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &Value,
        _: &RequestBudget,
    ) -> AppResult<SceneSource> {
        Err(unavailable())
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
        Err(unavailable())
    }
}
fn no_data() -> SharedPlanningData {
    Rc::new(RefCell::new(Box::new(NoData)))
}

struct AccessFixture {
    sessions: SessionAuthority,
    token: crate::credential::SecretToken,
    principal: AuthenticatedPrincipal,
    authority: LocalAuthority,
    hosts: HostBridge,
    locator: SharedRegisteredPlanningContexts,
    access: LocalPlanningAccess,
    context: Value,
    budget: RequestBudget,
    cancelled: Arc<AtomicBool>,
}
impl AccessFixture {
    fn new(project: &ProjectCatalog) -> Self {
        let hosts = HostBridge::default();
        let authority = LocalAuthority::new(hosts.clone());
        let id = ContextId::new("context-feature-offline").unwrap();
        let principal_id = PrincipalId::new("principal-feature-source").unwrap();
        let scope = json!({"projectId":project.project_id(),
            "objectIds":project.pins().iter().map(|pin|pin.object_id.as_str()).collect::<Vec<_>>(),
            "resourceIds":project.resource_ids(),"regions":[],"externalTargetIds":[]});
        let revision = authority
            .stage_project_access(
                principal_id.clone(),
                project.project_id().clone(),
                scope.clone(),
                [id.clone()].into(),
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
                allowed_methods: [
                    "project.inspect".into(),
                    "plan.create".into(),
                    "scene.diff".into(),
                ]
                .into(),
                allowed_contexts: [id.clone()].into(),
                lifetime: Duration::from_secs(120),
            })
            .unwrap();
        let principal = sessions.authenticate_token(&token).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let budget = RequestBudget::new(Duration::from_secs(120), cancelled.clone()).unwrap();
        let mut context = json!({"contractVersion":"0.2.0","contextId":id,"principalRef":principal.principal(),
            "projectId":project.project_id(),"environment":{"kind":"offline","workspaceId":"workspace-feature-test","side":"offline"},
            "policyRevision":revision,"scope":scope,"contextDigest":"0".repeat(64)});
        context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
        let locator = Rc::new(RefCell::new(RegisteredContextLocator::new()));
        locator
            .borrow_mut()
            .register_workspace(&principal, &authority, context.clone(), &budget)
            .unwrap();
        authority
            .install_workspace_resolver(workspace_context_resolver(locator.clone()))
            .unwrap();
        let access = LocalPlanningAccess::new(
            principal.clone(),
            authority.clone(),
            hosts.clone(),
            budget.clone(),
            planning_context_adapter(locator.clone()),
        )
        .unwrap();
        Self {
            sessions,
            token,
            principal,
            authority,
            hosts,
            locator,
            access,
            context,
            budget,
            cancelled,
        }
    }
}
fn project_and_selection(store: &mut DurableStore, resources: &[&str]) -> (ProjectCatalog, Value) {
    let mut selection = example("scene-selection.json");
    selection["selectedNodeIds"] = json!(["door", "sign"]);
    let mut project = example("project.json");
    project["resourceIds"] = json!(resources);
    project["ownedResources"] = json!([
        {"kind":"prefab","objectId":selection["prefabs"][0]["prefabId"],"revision":selection["prefabs"][0]["revision"]},
        {"kind":"instance","objectId":selection["instances"][0]["instanceId"],"revision":selection["instances"][0]["revision"]}
    ]);
    project["revision"] = json!(projected_digest("Project", &project).unwrap());
    store.save_project(&project, None).unwrap();
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    for (index, field) in [(0, "prefabs"), (1, "instances")] {
        let pin: OwnedDocumentPin =
            serde_json::from_value(project["ownedResources"][index].clone()).unwrap();
        register_owned_document(
            store,
            catalog.project_id(),
            catalog.revision(),
            &pin,
            &selection[field][0],
        )
        .unwrap();
    }
    selection["projectRevision"] = json!(catalog.revision());
    (catalog, selection)
}
fn resource(id: &str, media_type: &str, bytes: &[u8]) -> ResourceRef {
    ResourceRef {
        resource_id: ResourceId::new(id).unwrap(),
        sha256: raw_digest(bytes),
        media_type: media_type.into(),
        size_bytes: bytes.len() as u64,
    }
}
fn registered(
    store: &mut DurableStore,
    project: &ProjectCatalog,
    id: &str,
    bytes: &[u8],
) -> ResourceRef {
    let pin = resource(id, "application/json", bytes);
    let blob = store.put_blob(bytes).unwrap();
    assert_eq!(blob.digest, pin.sha256);
    register_resource(
        store,
        &json!(pin),
        ResourceOwner::Project(project.project_id().clone()),
    )
    .unwrap();
    pin
}
fn resource_port<'a>(
    store: &'a mut DurableStore,
    auth: &AccessFixture,
    project: &ProjectCatalog,
) -> LocalFeatureResources<'a> {
    let borrowed = PlanningStore::write(store);
    LocalFeatureResources {
        source: BorrowedProjectSource::new(borrowed.clone(), auth.access.clone(), no_data()),
        store: borrowed,
        principal: auth.principal.clone(),
        project: project.clone(),
        context: auth.context.clone(),
        authority: auth.authority.clone(),
        rights: Rc::new(RefCell::new(ResourceRightsRegistry::default())),
        products: Rc::new(RefCell::new(FeatureProductRegistry::default())),
        budget: auth.budget.clone(),
        origin: FeatureOrigin::default(),
    }
}
fn failure<T>(result: ExchangeResult<T>) -> String {
    match result {
        Ok(_) => panic!("Expected an exchange failure"),
        Err(error) => error.code.to_owned(),
    }
}
fn app_failure<T>(result: AppResult<T>) -> &'static str {
    match result {
        Ok(_) => panic!("Expected a source failure"),
        Err(error) => error.code,
    }
}

#[test]
fn actual_registered_bytes_require_exact_metadata_and_explicit_redistribution() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (project, _) = project_and_selection(&mut store, &["resource-feature-input"]);
    let bytes = br#"{"source":"registered local bytes"}"#;
    let pin = registered(&mut store, &project, "resource-feature-input", bytes);
    let auth = AccessFixture::new(&project);
    let mut port = resource_port(&mut store, &auth, &project);
    let context = auth.context["contextId"].as_str().unwrap();
    let read = port
        .read(context, &json!(pin), ResourcePurpose::Read, 4096)
        .unwrap();
    assert_eq!(read.bytes, bytes);
    assert_eq!(read.redistribution, Redistribution::Unknown);
    assert_eq!(
        port.embedded_rights(context, &json!(pin)).unwrap(),
        Redistribution::Unknown
    );
    assert_eq!(
        failure(port.read(context, &json!(pin), ResourcePurpose::Redistribute, 4096)),
        "PERMISSION_REQUIRED"
    );
    let mut forged = json!(pin);
    forged["mediaType"] = json!("application/vnd.mmmm.claimed+json");
    assert!(
        port.read(context, &forged, ResourcePurpose::Read, 4096)
            .is_err()
    );
    forged = json!(pin);
    forged["sha256"] = json!("0".repeat(64));
    assert!(
        port.read(context, &forged, ResourcePurpose::Read, 4096)
            .is_err()
    );
    assert!(
        port.read(
            "context-unregistered",
            &json!(pin),
            ResourcePurpose::Read,
            4096
        )
        .is_err()
    );
}

#[test]
fn private_producer_receipt_preserves_exact_read_without_creating_rights_or_surviving_revocation() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (project, selection) = project_and_selection(&mut store, &["resource-feature-input"]);
    let source = registered(
        &mut store,
        &project,
        "resource-feature-input",
        br#"{"original":true}"#,
    );
    let mut auth = AccessFixture::new(&project);
    let mut port = resource_port(&mut store, &auth, &project);
    let context = auth.context["contextId"].as_str().unwrap();
    port.authorize_selection(context, &selection).unwrap();
    port.read(context, &json!(source), ResourcePurpose::Read, 4096)
        .unwrap();
    let bytes = br#"{"derived":"private output"}"#;
    let output = resource("resource-feature-output", "application/json", bytes);
    assert!(!project.resource_ids().contains(&output.resource_id));
    port.stage(&json!(output), bytes).unwrap();
    assert_eq!(port.products.borrow().records.len(), 1);
    assert!(port.rights.borrow().records.is_empty());
    assert_eq!(
        port.read(context, &json!(output), ResourcePurpose::Read, 4096)
            .unwrap()
            .bytes,
        bytes
    );
    assert_eq!(
        failure(port.read(context, &json!(output), ResourcePurpose::Redistribute, 4096)),
        "PERMISSION_REQUIRED"
    );
    // A new adapter starts without the source observations made above. Its
    // dependent receipt must inherit them from the actual issued output read.
    let mut dependent_port = LocalFeatureResources {
        source: BorrowedProjectSource::new(port.store.clone(), auth.access.clone(), no_data()),
        store: port.store.clone(),
        principal: auth.principal.clone(),
        project: project.clone(),
        context: auth.context.clone(),
        authority: auth.authority.clone(),
        rights: port.rights.clone(),
        products: port.products.clone(),
        budget: auth.budget.clone(),
        origin: FeatureOrigin::default(),
    };
    assert!(dependent_port.origin.resources.is_empty());
    assert!(dependent_port.origin.objects.is_empty());
    assert_eq!(
        dependent_port
            .read(context, &json!(output), ResourcePurpose::Read, 4096)
            .unwrap()
            .bytes,
        bytes
    );
    let dependent_bytes = br#"{"derived":"dependent private output"}"#;
    let dependent = resource(
        "resource-feature-dependent",
        "application/json",
        dependent_bytes,
    );
    dependent_port
        .stage(&json!(dependent), dependent_bytes)
        .unwrap();
    {
        let products = dependent_port.products.borrow();
        let receipt = products
            .records
            .get(&(project.project_id().clone(), dependent.resource_id.clone()))
            .unwrap();
        assert!(same_resource(
            receipt.origin.resources.get(&source.resource_id).unwrap(),
            &source
        ));
        for pin in project.pins() {
            assert!(receipt.origin.objects.contains(pin));
        }
    }
    assert_eq!(
        dependent_port
            .read(context, &json!(dependent), ResourcePurpose::Read, 4096)
            .unwrap()
            .bytes,
        dependent_bytes
    );
    assert_eq!(
        failure(dependent_port.read(
            context,
            &json!(dependent),
            ResourcePurpose::Redistribute,
            4096
        )),
        "PERMISSION_REQUIRED"
    );
    auth.sessions.revoke(&auth.token);
    assert!(
        port.read(context, &json!(output), ResourcePurpose::Read, 4096)
            .is_err()
    );
    assert!(
        dependent_port
            .read(context, &json!(dependent), ResourcePurpose::Read, 4096)
            .is_err()
    );
    assert!(port.embedded_rights(context, &json!(source)).is_err());
    // Revocation invalidates authority without deleting exact retained CAS data.
    let blob = BlobRef {
        digest: output.sha256.clone(),
        byte_length: output.size_bytes,
    };
    assert_eq!(
        port.store
            .with_read(|store| store.read_blob(&blob).map_err(storage_app))
            .unwrap(),
        bytes
    );
}

#[test]
fn shared_registered_offline_context_rechecks_current_grant_and_cancellation() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (project, _) = project_and_selection(&mut store, &[]);
    let auth = AccessFixture::new(&project);
    let id = context_id(&auth.context).unwrap();
    assert_eq!(
        auth.locator
            .borrow_mut()
            .resolve(
                &auth.principal,
                &mut auth.authority.clone(),
                &auth.hosts,
                &id,
                Access::ReadProject,
                &auth.budget
            )
            .unwrap(),
        auth.context
    );
    auth.access
        .authorize_project(
            auth.principal.principal(),
            project.project_id(),
            Some(&auth.context),
            Access::ReadProject,
        )
        .unwrap();
    assert!(
        auth.locator
            .borrow_mut()
            .resolve(
                &auth.principal,
                &mut auth.authority.clone(),
                &auth.hosts,
                &id,
                Access::Apply,
                &auth.budget
            )
            .is_err()
    );
    let mut public_context = auth.context.clone();
    public_context["environment"]["workspaceId"] = json!("caller-supplied-workspace");
    public_context["contextDigest"] =
        json!(projected_digest("ExecutionContext", &public_context).unwrap());
    assert!(
        auth.access
            .authorize_project(
                auth.principal.principal(),
                project.project_id(),
                Some(&public_context),
                Access::ReadProject
            )
            .is_err()
    );
    auth.authority
        .revoke_project(auth.principal.principal(), project.project_id())
        .unwrap();
    assert!(
        auth.locator
            .borrow_mut()
            .resolve(
                &auth.principal,
                &mut auth.authority.clone(),
                &auth.hosts,
                &id,
                Access::ReadProject,
                &auth.budget
            )
            .is_err()
    );
    auth.cancelled.store(true, Ordering::Relaxed);
    assert!(auth.access.check().is_err());
}

struct RejectRights {
    calls: usize,
}
impl SourceRightsVerifier for RejectRights {
    fn verify(
        &mut self,
        principal: &AuthenticatedPrincipal,
        context: &Value,
        source: &Value,
        resource: &ResourceRef,
        bytes: &[u8],
        evidence: &ResourceRef,
        evidence_bytes: &[u8],
        budget: &RequestBudget,
    ) -> AppResult<Redistribution> {
        budget_check(budget)?;
        assert!(principal.is_current());
        assert_eq!(context["principalRef"], json!(principal.principal()));
        assert_eq!(source["sha256"], json!(resource.sha256));
        assert_eq!(raw_digest(bytes), resource.sha256);
        assert_eq!(raw_digest(evidence_bytes), evidence.sha256);
        self.calls += 1;
        // Actual CAS evidence was delivered, but this test has no trusted
        // license/owner proof. A public rights label must remain insufficient.
        Err(forbidden())
    }
}

#[test]
fn source_labels_and_retained_evidence_cannot_install_redistribution_rights() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (project, _) = project_and_selection(
        &mut store,
        &["resource-rights-input", "resource-rights-evidence"],
    );
    let pin = registered(
        &mut store,
        &project,
        "resource-rights-input",
        br#"{"source":"fixture input"}"#,
    );
    let evidence = registered(
        &mut store,
        &project,
        "resource-rights-evidence",
        br#"{"evidence":"fixture declaration only"}"#,
    );
    let auth = AccessFixture::new(&project);
    let mut source =
        BorrowedProjectSource::new(PlanningStore::read(&store), auth.access.clone(), no_data());
    let mut registry = ResourceRightsRegistry::default();
    let mut verifier = RejectRights { calls: 0 };
    for rights in ["unknown", "owned"] {
        let source_ref = json!({"sourceId":"source-fixture","kind":"fixture","locator":"fixture-local-input",
            "sha256":pin.sha256,"rights":rights,"verifiedAt":"2026-10-14T00:00:00Z"});
        let registration = ResourceRightsRegistration {
            source: source_ref,
            resource: pin.clone(),
            approval_evidence: evidence.clone(),
        };
        assert_eq!(
            app_failure(registry.register(
                &auth.principal,
                &mut source,
                &project,
                &auth.context,
                &auth.authority,
                registration,
                &mut verifier
            )),
            "PERMISSION_REQUIRED"
        );
        assert!(registry.records.is_empty());
        assert_eq!(
            registry
                .lookup(
                    &auth.principal,
                    &project,
                    &auth.context,
                    &pin,
                    &auth.authority
                )
                .unwrap(),
            Redistribution::Unknown
        );
    }
    assert_eq!(verifier.calls, 1);
}

struct ManualFixture {
    selection: Value,
    artifact: Value,
    request: Value,
    map: Value,
    payload: Value,
    registration: ManualSceneRegistration,
}
fn manual_fixture(
    store: &mut DurableStore,
    project: &ProjectCatalog,
    mut selection: Value,
    auth: &AccessFixture,
) -> ManualFixture {
    let mut artifact = example("bake-artifact.json");
    artifact["sourceProjectRevision"] = json!(project.revision());
    let bundle = registered(
        store,
        project,
        "resource-manual-bundle",
        br#"{"manualSource":"fixture-only"}"#,
    );
    let mut request = example("bake-request.json");
    request["projectId"] = json!(project.project_id());
    request["projectRevision"] = json!(project.revision());
    request["sourceBundle"] = json!(bundle);
    artifact["requestId"] = request["requestId"].clone();
    artifact["representation"] = request["representation"].clone();
    artifact["inputDigest"] = json!(projected_digest("BakeRequest", &request).unwrap());
    let request_pin = registered(
        store,
        project,
        "resource-manual-request",
        &encode_json(&request).unwrap(),
    );
    let artifact_pin = registered(
        store,
        project,
        "resource-manual-artifact",
        &encode_json(&artifact).unwrap(),
    );
    let mut node = selection["prefabs"][0]["nodes"][0].clone();
    node["nodeId"] = json!("manual-created");
    node["name"] = json!("Explicitly created node");
    node["parentId"] = json!("root");
    let mut transform = selection["prefabs"][0]["nodes"][3]["transform"].clone();
    transform["translation"] = json!([3, 2, 0]);
    let entries = json!([
        {"kind":"update_transform","instanceId":"instance-shop-a","nodeId":"door","transform":transform},
        {"kind":"create_node","instanceId":"instance-shop-a","nodeId":"manual-created","node":node},
        {"kind":"delete_node","instanceId":"instance-shop-a","nodeId":"sign"}
    ]);
    let map = json!({"contractVersion":"0.2.0","generatorVersion":"fixture-manual-static-only",
        "inputRevision":project.revision(),"entries":entries.as_array().unwrap().iter().enumerate().map(|(index,entry)|json!({
            "sourceObjectId":entry["instanceId"],"sourceNodeId":entry["nodeId"],
            "outputResourceId":"resource-manual-payload","locator":format!("/entries/{index}")})).collect::<Vec<_>>()});
    let map_pin = registered(
        store,
        project,
        "resource-manual-map",
        &encode_json(&map).unwrap(),
    );
    selection["sourceMap"] = json!(map_pin);
    let selection_pin = registered(
        store,
        project,
        "resource-manual-selection",
        &encode_json(&selection).unwrap(),
    );
    let payload = json!({"contractVersion":"0.2.0","patchId":"patch-manual-input","projectId":project.project_id(),
        "baseRevision":project.revision(),"sourceArtifact":artifact_pin,"entries":entries,"sourceMap":map_pin,
        "losses":[],"absenceMeansDeletion":false});
    let payload_pin = registered(
        store,
        project,
        "resource-manual-payload",
        &encode_json(&payload).unwrap(),
    );
    let mut policy = DeltaPolicy::default();
    for (node_id, kind) in [
        ("door", DeltaKind::UpdateTransform),
        ("manual-created", DeltaKind::CreateNode),
        ("sign", DeltaKind::DeleteNode),
    ] {
        policy
            .allow(
                ObjectNode {
                    instance_id: "instance-shop-a".into(),
                    node_id: node_id.into(),
                },
                kind,
            )
            .unwrap();
    }
    ManualFixture {
        selection,
        artifact,
        request,
        map,
        payload,
        registration: ManualSceneRegistration {
            context_id: context_id(&auth.context).unwrap(),
            source_artifact: artifact_pin,
            source_bundle: bundle,
            source_request: request_pin,
            selection: selection_pin,
            source_map: map_pin,
            edit_payload: payload_pin,
            codec: ManualSceneCodec::CanonicalScenePatch,
            policy,
        },
    }
}
const MANUAL_IDS: &[&str] = &[
    "resource-manual-artifact",
    "resource-manual-bundle",
    "resource-manual-request",
    "resource-manual-map",
    "resource-manual-selection",
    "resource-manual-payload",
];
fn diff(decoded: &ManualSceneInputs) -> ExchangeResult<Value> {
    diff_scene_edits(
        &decoded.selection,
        &decoded.edits,
        &decoded.source_artifact,
        &decoded.source_map,
        &decoded.losses,
        "patch-manual-proposal",
        &decoded.policy,
    )
}

#[test]
fn exact_cas_manual_codec_proposes_explicit_create_update_delete_without_bake_completion() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (project, selection) = project_and_selection(&mut store, MANUAL_IDS);
    let auth = AccessFixture::new(&project);
    let manual = manual_fixture(&mut store, &project, selection, &auth);
    let mut source =
        BorrowedProjectSource::new(PlanningStore::read(&store), auth.access.clone(), no_data());
    let selection = read_json(
        &mut source,
        &auth.principal,
        &project,
        &auth.context,
        &manual.registration.selection,
        "SceneSelectionSnapshot",
    )
    .unwrap();
    verify_selection(
        &mut source,
        &auth.principal,
        &project,
        &auth.context,
        &selection,
    )
    .unwrap();
    let artifact = read_json(
        &mut source,
        &auth.principal,
        &project,
        &auth.context,
        &manual.registration.source_artifact,
        "BakeArtifact",
    )
    .unwrap();
    let request = read_json(
        &mut source,
        &auth.principal,
        &project,
        &auth.context,
        &manual.registration.source_request,
        "BakeRequest",
    )
    .unwrap();
    assert_eq!(request, manual.request);
    verify_manual_request(&project, &artifact, &request, &manual.registration).unwrap();
    let map = read_json(
        &mut source,
        &auth.principal,
        &project,
        &auth.context,
        &manual.registration.source_map,
        "SourceMap",
    )
    .unwrap();
    let payload = read_json(
        &mut source,
        &auth.principal,
        &project,
        &auth.context,
        &manual.registration.edit_payload,
        "ScenePatch",
    )
    .unwrap();
    let decoded = decode_manual(
        &selection,
        &artifact,
        &manual.registration,
        &map,
        &payload,
        &auth.budget,
    )
    .unwrap();
    let patch = diff(&decoded).unwrap();
    ContractValidator::shared()
        .unwrap()
        .validate("ScenePatch", &patch)
        .unwrap();
    assert_eq!(patch["baseRevision"], json!(project.revision()));
    assert_eq!(patch["absenceMeansDeletion"], false);
    assert_eq!(patch["entries"].as_array().unwrap().len(), 3);
    assert!(
        patch["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["kind"] == "create_node" && entry["nodeId"] == "manual-created")
    );
    assert!(
        patch["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["kind"] == "delete_node" && entry["nodeId"] == "sign")
    );
    assert!(
        !patch["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["kind"] == "update_display" || entry["nodeId"] == "shell")
    );
    assert_eq!(artifact, manual.artifact);
    assert_eq!(decoded.artifact["initialFinalVerified"], false);
    assert_eq!(decoded.artifact["intermediatePoseVerified"], false);
    assert_eq!(decoded.artifact["cost"]["kind"], "estimate");
    assert_eq!(diff(&decoded).unwrap(), patch);
}

#[test]
fn manual_codec_rejects_ambiguous_mapping_stale_base_clip_claims_and_unowned_selection() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (project, selection) = project_and_selection(&mut store, MANUAL_IDS);
    let auth = AccessFixture::new(&project);
    let manual = manual_fixture(&mut store, &project, selection, &auth);
    let mut source =
        BorrowedProjectSource::new(PlanningStore::read(&store), auth.access.clone(), no_data());
    let request = read_json(
        &mut source,
        &auth.principal,
        &project,
        &auth.context,
        &manual.registration.source_request,
        "BakeRequest",
    )
    .unwrap();
    verify_manual_request(&project, &manual.artifact, &request, &manual.registration).unwrap();
    for (field, value) in [
        ("projectId", json!("project-foreign")),
        ("projectRevision", json!("0".repeat(64))),
        ("representation", json!("triangulated_surface_samples")),
        ("requestId", json!("bake-foreign-request")),
    ] {
        let mut changed_request = request.clone();
        changed_request[field] = value;
        let mut changed_artifact = manual.artifact.clone();
        // Recompute this digest so every identity guard is exercised even when
        // the foreign/stale request is internally consistent with the digest.
        changed_artifact["inputDigest"] =
            json!(projected_digest("BakeRequest", &changed_request).unwrap());
        assert_eq!(
            app_failure(verify_manual_request(
                &project,
                &changed_artifact,
                &changed_request,
                &manual.registration
            )),
            "REVISION_CONFLICT"
        );
    }
    let mut changed_artifact = manual.artifact.clone();
    changed_artifact["inputDigest"] = json!("0".repeat(64));
    assert_eq!(
        app_failure(verify_manual_request(
            &project,
            &changed_artifact,
            &request,
            &manual.registration
        )),
        "REVISION_CONFLICT"
    );
    for (field, value) in [
        ("outputResourceId", json!("resource-other-output")),
        ("sourceObjectId", json!("instance-other")),
        ("sourceNodeId", json!("shell")),
        ("locator", json!("/entries/00")),
        ("locator", json!("/entries/1")),
    ] {
        let mut map = manual.map.clone();
        map["entries"][0][field] = value;
        assert_eq!(
            app_failure(decode_manual(
                &manual.selection,
                &manual.artifact,
                &manual.registration,
                &map,
                &manual.payload,
                &auth.budget
            )),
            "OBJECT_MAPPING_AMBIGUOUS"
        );
    }
    let mut payload = manual.payload.clone();
    payload["baseRevision"] = json!("0".repeat(64));
    assert_eq!(
        app_failure(decode_manual(
            &manual.selection,
            &manual.artifact,
            &manual.registration,
            &manual.map,
            &payload,
            &auth.budget
        )),
        "REVISION_CONFLICT"
    );
    payload = manual.payload.clone();
    payload["entries"][0] = json!({"kind":"attach_clip","instanceId":"instance-shop-a","nodeId":"door","clipId":"clip-door"});
    assert_eq!(
        app_failure(decode_manual(
            &manual.selection,
            &manual.artifact,
            &manual.registration,
            &manual.map,
            &payload,
            &auth.budget
        )),
        "UNSUPPORTED_FORMAT"
    );
    let decoded = decode_manual(
        &manual.selection,
        &manual.artifact,
        &manual.registration,
        &manual.map,
        &manual.payload,
        &auth.budget,
    )
    .unwrap();
    assert_eq!(
        failure(diff_scene_edits(
            &decoded.selection,
            &decoded.edits,
            &decoded.source_artifact,
            &decoded.source_map,
            &decoded.losses,
            "patch-denied",
            &DeltaPolicy::default()
        )),
        "PERMISSION_REQUIRED"
    );
    let mut selection = manual.selection.clone();
    selection["prefabs"][0]["name"] = json!("Caller substituted definition");
    selection["prefabs"][0]["revision"] =
        json!(projected_digest("Prefab", &selection["prefabs"][0]).unwrap());
    selection["instances"][0]["prefabRevision"] = selection["prefabs"][0]["revision"].clone();
    selection["instances"][0]["revision"] =
        json!(projected_digest("Instance", &selection["instances"][0]).unwrap());
    let mut source =
        BorrowedProjectSource::new(PlanningStore::read(&store), auth.access.clone(), no_data());
    assert!(
        verify_selection(
            &mut source,
            &auth.principal,
            &project,
            &auth.context,
            &selection
        )
        .is_err()
    );
}

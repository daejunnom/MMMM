//! Actual owned source producer regressions. Existing source tests install
//! NoData, and manual feature fixtures use externally registered bake artifacts;
//! neither exercises owned Prefab/Instance selection and static source admission.
//! This fixture keeps SQLite/CAS outside the checkout and enters an actual
//! authenticated Service call to acquire its unforgeable request witness.
use super::*;
use crate::auth::{AuthenticatedPrincipal, SessionAuthority, SessionPolicy};
use crate::planning_context::{
    RegisteredContextLocator, planning_context_adapter, workspace_context_resolver,
};
use crate::service::{
    ApplicationPorts, ApplicationService, ExtensionRouter, RequestBudget, RequestContextSlot,
    RequestContextWitness, ServiceDispatcher, ServiceError, ServiceExtension,
    ServiceExtensionContext,
};
use mmmm_application::{
    AuthorityPort, Clock, IdKind, IdSource, IndependentObserverPort, PlanningPort, PreparedPlan,
    ProjectInspection, ProviderPort, ReadbackEvidence, RecoveryPreparation,
};
use mmmm_contracts::{ResourceId, parse_json, projected_digest, raw_digest};
use mmmm_runtime::artifact::{ResourceOwner, register_resource};
use mmmm_runtime::storage::{
    StoreConfig, WriteScope,
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

static NEXT_OWNED_ROOT: AtomicU64 = AtomicU64::new(0);
const OWNED_ROOT_MARKER: &[u8] = b"mmmm-owned-planning-data-tests\n";
struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        assert!(parent.is_absolute());
        let parent = fs::canonicalize(parent).unwrap();
        let root = parent.join(format!(
            "mmmm-owned-planning-data-{}-{}",
            std::process::id(),
            NEXT_OWNED_ROOT.fetch_add(1, Ordering::Relaxed)
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
        assert!(root.is_absolute() && root.parent() == Some(parent.as_path()));
        assert!(!root.starts_with(checkout));
        fs::write(root.join("test-owner.txt"), OWNED_ROOT_MARKER).unwrap();
        Self(root)
    }
    fn open(&self) -> DurableStore {
        DurableStore::open(StoreConfig::new(self.0.clone())).unwrap()
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let mut count = 0;
        if self.0.is_absolute()
            && fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0)
            && fs::read(self.0.join("test-owner.txt")).ok().as_deref() == Some(OWNED_ROOT_MARKER)
            && owned_plain_tree(&self.0, 0, &mut count)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
fn owned_plain_tree(path: &Path, depth: usize, count: &mut usize) -> bool {
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
            if !owned_plain_tree(&entry.path(), depth + 1, count) {
                return false;
            }
        }
    } else if !metadata.is_file() {
        return false;
    }
    true
}
fn owned_example(name: &str) -> Value {
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

// These ports are deliberately unreachable: only the trusted extension is
// installed for this request. A source test cannot accidentally dispatch a
// world/provider operation or run a second application/store algorithm.
struct NoApplicationCalls;
impl AuthorityPort for NoApplicationCalls {
    fn authorize(
        &mut self,
        _: &PrincipalId,
        _: &ProjectId,
        _: Access,
        _: Option<&Value>,
        _: Option<&Value>,
    ) -> AppResult<()> {
        panic!("Unexpected product authority call")
    }
}
impl PlanningPort for NoApplicationCalls {
    fn inspect_project(&mut self, _: &PrincipalId, _: &Value) -> AppResult<ProjectInspection> {
        panic!("Unexpected product inspection")
    }
    fn prepare(
        &mut self,
        _: &PrincipalId,
        _: &Value,
        _: &Value,
        _: &Value,
    ) -> AppResult<PreparedPlan> {
        panic!("Unexpected product planning")
    }
    fn prepare_recovery(
        &mut self,
        _: &PrincipalId,
        _: &RecoveryPreparation,
        _: &Value,
        _: &Value,
    ) -> AppResult<PreparedPlan> {
        panic!("Unexpected product recovery")
    }
}
impl ProviderPort for NoApplicationCalls {
    fn context(&mut self, _: &PrincipalId, _: &ContextId) -> AppResult<Value> {
        panic!("Unexpected provider context")
    }
    fn action_descriptor(&mut self, _: &Value, _: &Value) -> AppResult<Value> {
        panic!("Unexpected provider action")
    }
    fn observe_precondition(&mut self, _: &Value, _: &Value) -> AppResult<Sha256Digest> {
        panic!("Unexpected provider observation")
    }
    fn verify_dependencies(&mut self, _: &[Value], _: &Value) -> AppResult<()> {
        panic!("Unexpected provider dependency")
    }
    fn dispatch(&mut self, _: &Value) -> AppResult<Value> {
        panic!("Owned-source reads cannot dispatch")
    }
    fn poll(&mut self, _: &Value, _: Option<&str>) -> AppResult<Option<Value>> {
        panic!("Unexpected provider poll")
    }
    fn request_cancel(&mut self, _: &Value, _: Option<&str>) -> AppResult<()> {
        panic!("Unexpected provider cancellation")
    }
}
impl IndependentObserverPort for NoApplicationCalls {
    fn readback(&mut self, _: &Value, _: &WriteScope) -> AppResult<ReadbackEvidence> {
        panic!("Unexpected effect observer")
    }
    fn read_target(&mut self, _: &Value, _: &str) -> AppResult<Vec<u8>> {
        panic!("Unexpected target read")
    }
}
impl IdSource for NoApplicationCalls {
    fn next_id(&mut self, _: IdKind) -> AppResult<String> {
        panic!("Owned source reads cannot reserve identities")
    }
}
impl Clock for NoApplicationCalls {
    fn unix_nanos(&self) -> i128 {
        0
    }
}
fn no_application_ports() -> ApplicationPorts {
    ApplicationPorts {
        authority: Box::new(NoApplicationCalls),
        planner: Box::new(NoApplicationCalls),
        provider: Box::new(NoApplicationCalls),
        observer: Box::new(NoApplicationCalls),
        ids: Box::new(NoApplicationCalls),
        clock: Box::new(NoApplicationCalls),
    }
}

type OwnedCall = Box<dyn FnMut(&mut DurableStore, RequestContextWitness) -> AppResult<Value>>;
struct OccupiedRead {
    slot: RequestContextSlot,
    action: OwnedCall,
    witness: Rc<RefCell<Option<RequestContextWitness>>>,
}
impl ServiceExtension for OccupiedRead {
    fn call(
        &mut self,
        method: &str,
        _: &Value,
        context: &mut ServiceExtensionContext<'_>,
    ) -> Result<Value, ServiceError> {
        context.check(method)?;
        let witness = self.slot.current_witness(method)?;
        assert!(witness.authenticated().same_session(context.principal));
        assert_eq!(witness.budget().deadline(), context.budget.deadline());
        witness.check_local()?;
        *self.witness.borrow_mut() = Some(witness.clone());
        (self.action)(context.store, witness)
            .map_err(|error| ServiceError::caused_by(error.code, error.message, error))
    }
}

const STATIC_RESOURCES: &[&str] = &[
    "resource-owned-static-prefab",
    "resource-owned-static-map",
    "resource-owned-foreign-artifact",
];
fn register_static_resource(
    store: &mut DurableStore,
    owner: &ProjectId,
    id: &str,
    value: &Value,
) -> ResourceRef {
    let bytes = encode_json(value).unwrap();
    let blob = store.put_blob(&bytes).unwrap();
    let resource = ResourceRef {
        resource_id: ResourceId::new(id).unwrap(),
        sha256: raw_digest(&bytes),
        media_type: "application/json".into(),
        size_bytes: bytes.len() as u64,
    };
    assert_eq!(resource.sha256, blob.digest);
    register_resource(
        store,
        &json!(resource),
        ResourceOwner::Project(owner.clone()),
    )
    .unwrap();
    resource
}

struct StaticInputs {
    patch: Value,
    artifact: Value,
    map: Value,
}
fn static_inputs(fixture: &mut OwnedFixture, case: &str) -> StaticInputs {
    // The target Instance still pins its actual old Prefab. A separately
    // authored current owned Prefab supplies real new static values; this is
    // meaningful change provenance rather than a caller-created artifact flag.
    let mut artifact = fixture.prefab.clone();
    let door = artifact["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .position(|node| node["nodeId"] == "door")
        .unwrap();
    let sign = artifact["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .position(|node| node["nodeId"] == "sign")
        .unwrap();
    artifact["nodes"][door]["transform"]["translation"] = json!([3, 2, 0]);
    artifact["nodes"][sign]["display"]["payload"]["text"] =
        json!("Actual retained static sign proposal");
    artifact["revision"] = json!(projected_digest("Prefab", &artifact).unwrap());
    let mut project = fixture.project.clone();
    project["ownedResources"][0]["revision"] = artifact["revision"].clone();
    project["revision"] = json!(projected_digest("Project", &project).unwrap());
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    let store = fixture.service.management_store();
    store
        .save_project(&project, Some(fixture.catalog.revision()))
        .unwrap();
    for (index, document) in [&artifact, &fixture.instance].into_iter().enumerate() {
        let pin: OwnedDocumentPin =
            serde_json::from_value(project["ownedResources"][index].clone()).unwrap();
        register_owned_document(
            store,
            catalog.project_id(),
            catalog.revision(),
            &pin,
            document,
        )
        .unwrap();
    }
    fixture.project = project;
    fixture.catalog = catalog;
    let locator_prefix = if case == "selection" {
        "/prefabs/0"
    } else {
        ""
    };
    let mut map = json!({"contractVersion":"0.2.0","generatorVersion":"fixture-owned-static-source",
    "inputRevision":fixture.catalog.revision(),"entries":[
        {"sourceObjectId":fixture.instance["instanceId"],"sourceNodeId":"door","outputResourceId":STATIC_RESOURCES[0],
            "locator":format!("{locator_prefix}/nodes/{door}/transform")},
        {"sourceObjectId":fixture.instance["instanceId"],"sourceNodeId":"sign","outputResourceId":STATIC_RESOURCES[0],
            "locator":format!("{locator_prefix}/nodes/{sign}/display")}
    ]});
    if case == "ambiguous_map" {
        let duplicate = map["entries"][0].clone();
        map["entries"].as_array_mut().unwrap().push(duplicate);
    }
    if case == "map_revision" {
        map["inputRevision"] = json!(raw_digest(b"another-project-source-revision"));
    }
    let map_pin = register_static_resource(
        store,
        fixture.catalog.project_id(),
        STATIC_RESOURCES[1],
        &map,
    );
    let artifact_value = match case {
        "bake" => owned_example("bake-artifact.json"),
        "selection" => {
            let mut selection = owned_example("scene-selection.json");
            selection["projectRevision"] = json!(fixture.catalog.revision());
            selection["instances"] = json!([fixture.instance]);
            selection["prefabs"] = json!([fixture.prefab]);
            // Original artifact order and extra selected nodes must survive a
            // one-node patch; absence does not authorize deletion or shrinking.
            selection["selectedNodeIds"] = json!(["sign", "root", "door"]);
            selection["sourceMap"] = json!(map_pin);
            selection
        }
        _ => artifact.clone(),
    };
    let artifact_pin = register_static_resource(
        store,
        fixture.catalog.project_id(),
        STATIC_RESOURCES[0],
        &artifact_value,
    );
    let mut patch = json!({"contractVersion":"0.2.0","patchId":"patch-owned-static-proposal",
        "projectId":fixture.catalog.project_id(),"baseRevision":fixture.catalog.revision(),
        "sourceArtifact":artifact_pin,"sourceMap":map_pin,"entries":[
            {"kind":"update_transform","instanceId":fixture.instance["instanceId"],"nodeId":"door","transform":artifact["nodes"][door]["transform"]},
            {"kind":"update_display","instanceId":fixture.instance["instanceId"],"nodeId":"sign","display":artifact["nodes"][sign]["display"]}
        ],"losses":[],"absenceMeansDeletion":false});
    match case {
        "selection" => {
            patch["entries"] = json!([{"kind":"update_transform","instanceId":fixture.instance["instanceId"],
            "nodeId":"door","transform":fixture.prefab["nodes"][door]["transform"]}])
        }
        "size" => patch["sourceMap"]["sizeBytes"] = json!(map_pin.size_bytes + 1),
        "attach_clip" => {
            patch["entries"] = json!([{"kind":"attach_clip","instanceId":fixture.instance["instanceId"],"nodeId":"door","clipId":"clip-door"}])
        }
        "foreign" => {
            let mut foreign = fixture.project.clone();
            foreign["projectId"] = json!("project-owned-static-foreign");
            foreign["prefabIds"] = json!([]);
            foreign["instanceIds"] = json!([]);
            foreign["ownedResources"] = json!([]);
            foreign["resourceIds"] = json!([STATIC_RESOURCES[2]]);
            foreign["revision"] = json!(projected_digest("Project", &foreign).unwrap());
            store.save_project(&foreign, None).unwrap();
            let foreign_id: ProjectId = decode(&foreign["projectId"]).unwrap();
            patch["sourceArtifact"] = json!(register_static_resource(
                store,
                &foreign_id,
                STATIC_RESOURCES[2],
                &artifact
            ));
        }
        _ => (),
    }
    StaticInputs {
        patch,
        artifact: artifact_value,
        map,
    }
}

#[test]
fn owned_state_source_reads_real_pinned_documents_in_actual_request_and_retires_without_live_defaults()
 {
    let mut fixture = OwnedFixture::new(&[]);
    let mut data = fixture.data();
    let principal = fixture.principal.principal().clone();
    let catalog = fixture.catalog.clone();
    let instance = fixture.instance.clone();
    let prefab = fixture.prefab.clone();
    let context = fixture.context.clone();
    let captured = Rc::new(RefCell::new(None));
    let retained = captured.clone();
    fixture
        .call(move |store, witness| {
            let borrowed = PlanningStore::read(store);
            let source = data.read_state_source(
                &borrowed,
                &principal,
                &catalog,
                &instance,
                &prefab,
                &context,
                witness.budget(),
            )?;
            assert_eq!(source.request().method(), "scene.diff");
            assert!(
                source
                    .request()
                    .authenticated()
                    .same_session(witness.authenticated())
            );
            assert_eq!(source.context(), &context);
            assert_eq!(
                source.instance().instance_id.as_str(),
                instance["instanceId"].as_str().unwrap()
            );
            assert_eq!(
                source.prefab().revision.as_str(),
                prefab["revision"].as_str().unwrap()
            );
            assert_eq!(
                source.instance_blob().digest,
                raw_digest(&encode_json(&instance).unwrap())
            );
            assert_eq!(
                source.prefab_blob().digest,
                raw_digest(&encode_json(&prefab).unwrap())
            );
            borrowed.with_read(|store| {
                assert_eq!(
                    store.read_blob(source.instance_blob()).unwrap(),
                    encode_json(&instance).unwrap()
                );
                assert_eq!(
                    store.read_blob(source.prefab_blob()).unwrap(),
                    encode_json(&prefab).unwrap()
                );
                Ok(())
            })?;
            source.check_current(&borrowed)?;
            let authored_values = source.authored_defaults()?;
            assert!(matches!(
                authored_values.get(&StateId::new("opened").unwrap()),
                Some(ScalarValue::Boolean(false))
            ));
            let error = data
                .state_snapshot_with_store(
                    &borrowed,
                    &principal,
                    &catalog,
                    &instance,
                    &prefab,
                    &context,
                    witness.budget(),
                )
                .err()
                .expect("Authoring defaults cannot manufacture independent live state");
            assert_eq!(error.code, "STATE_SNAPSHOT_REQUIRED");
            *retained.borrow_mut() = Some(source);
            Ok(json!({"actualSourceRead":true}))
        })
        .unwrap();
    let held = captured.borrow();
    let source = held.as_ref().unwrap();
    let store = fixture.service.management_store();
    assert!(source.check_current(&PlanningStore::read(store)).is_err());
    let instance_blob = source.instance_blob().clone();
    let prefab_blob = source.prefab_blob().clone();
    store.collect_orphan_blobs(1000).unwrap();
    assert!(!store.read_blob(&instance_blob).unwrap().is_empty());
    assert!(!store.read_blob(&prefab_blob).unwrap().is_empty());
    assert_eq!(store.data_root(), fixture.root.0.as_path());
    drop(held);
    let data = fixture.data();
    let principal = fixture.principal.principal().clone();
    let catalog = fixture.catalog.clone();
    let instance = fixture.instance.clone();
    let prefab = fixture.prefab.clone();
    let context = fixture.context.clone();
    let authority = fixture.authority.clone();
    // Reuse the actual session and budget in another real Service call. Its
    // private generation must not revive the earlier source witness.
    fixture
        .call(move |store, witness| {
            let borrowed = PlanningStore::read(store);
            assert!(
                captured
                    .borrow()
                    .as_ref()
                    .unwrap()
                    .check_current(&borrowed)
                    .is_err()
            );
            let current = data.read_state_source(
                &borrowed,
                &principal,
                &catalog,
                &instance,
                &prefab,
                &context,
                witness.budget(),
            )?;
            current.check_current(&borrowed)?;
            authority.revoke_project(&principal, catalog.project_id())?;
            let denied = current
                .check_current(&borrowed)
                .expect_err("A current request cannot keep a revoked source read grant");
            assert_eq!(denied.code, "PERMISSION_REQUIRED");
            Ok(json!({"retiredSourceRevived":false,"currentGrantRevoked":true}))
        })
        .unwrap();
}

#[test]
fn owned_source_denies_before_acl_old_head_cross_project_unknown_registry_and_caller_body_substitution()
 {
    for case in ["revoked", "head", "cross_project", "unknown", "body"] {
        let mut fixture = OwnedFixture::new(&[]);
        let data = fixture.data();
        let mut catalog = fixture.catalog.clone();
        let mut instance = fixture.instance.clone();
        let prefab = fixture.prefab.clone();
        let context = fixture.context.clone();
        let principal = fixture.principal.principal().clone();
        match case {
            "revoked" | "head" => {
                let mut new_head = fixture.project.clone();
                new_head["name"] = json!("Actual head advanced after request preparation");
                new_head["revision"] = json!(projected_digest("Project", &new_head).unwrap());
                fixture
                    .service
                    .management_store()
                    .save_project(&new_head, Some(fixture.catalog.revision()))
                    .unwrap();
                if case == "revoked" {
                    fixture
                        .authority
                        .revoke_project(&principal, catalog.project_id())
                        .unwrap();
                    instance["revision"] =
                        json!(raw_digest(b"unknown-source-also-denied-before-read"));
                }
            }
            "cross_project" => {
                let mut foreign = fixture.project.clone();
                foreign["projectId"] = json!("project-owned-data-foreign");
                foreign["revision"] = json!(projected_digest("Project", &foreign).unwrap());
                let foreign_catalog = ProjectCatalog::from_project(&foreign).unwrap();
                let store = fixture.service.management_store();
                store.save_project(&foreign, None).unwrap();
                for (index, document) in [&prefab, &instance].into_iter().enumerate() {
                    let pin: OwnedDocumentPin = decode(&foreign["ownedResources"][index]).unwrap();
                    register_owned_document(
                        store,
                        foreign_catalog.project_id(),
                        foreign_catalog.revision(),
                        &pin,
                        document,
                    )
                    .unwrap();
                }
                catalog = foreign_catalog;
            }
            "unknown" => {
                instance["revision"] =
                    json!(raw_digest(b"actual-project-pin-with-no-registered-source"));
                let mut project = fixture.project.clone();
                project["ownedResources"][1]["revision"] = instance["revision"].clone();
                project["revision"] = json!(projected_digest("Project", &project).unwrap());
                fixture
                    .service
                    .management_store()
                    .save_project(&project, Some(fixture.catalog.revision()))
                    .unwrap();
                catalog = ProjectCatalog::from_project(&project).unwrap();
            }
            "body" => instance["worldId"] = json!("caller-substituted-world"),
            _ => unreachable!(),
        }
        let result = fixture.call(move |store, witness| {
            let borrowed = PlanningStore::read(store);
            data.read_state_source(
                &borrowed,
                &principal,
                &catalog,
                &instance,
                &prefab,
                &context,
                witness.budget(),
            )
            .map(|_| json!({"unexpectedAdmission":true}))
        });
        let error = result.expect_err(case);
        let actual_cause = std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<AppError>())
            .expect("Service preserves the actual typed source admission error");
        assert_eq!(actual_cause.code, error.code);
        let expected = match case {
            "head" | "body" => "REVISION_CONFLICT",
            "unknown" => "SOURCE_UNAVAILABLE",
            _ => "PERMISSION_REQUIRED",
        };
        assert_eq!(error.code, expected, "case={case}");
    }
}

#[test]
fn owned_static_scene_uses_actual_current_prefab_and_original_instance_history_without_bake() {
    for artifact_kind in ["prefab", "selection"] {
        let mut fixture = OwnedFixture::new(STATIC_RESOURCES);
        let inputs = static_inputs(&mut fixture, artifact_kind);
        let mut data = fixture.data();
        let principal = fixture.principal.principal().clone();
        let catalog = fixture.catalog.clone();
        let context = fixture.context.clone();
        let old_prefab = fixture.prefab.clone();
        let actual_instance = fixture.instance.clone();
        fixture
            .call(move |store, witness| {
                let borrowed = PlanningStore::read(store);
                let mut source = data.scene_source_with_store(
                    &borrowed,
                    &principal,
                    &catalog,
                    &inputs.patch,
                    &context,
                    witness.budget(),
                )?;
                assert_eq!(source.artifact, inputs.artifact);
                assert_eq!(source.source_map, inputs.map);
                assert_eq!(
                    source.selection.value()["instances"],
                    json!([actual_instance])
                );
                assert_eq!(source.selection.value()["prefabs"], json!([old_prefab]));
                if artifact_kind == "selection" {
                    assert_eq!(source.selection.value(), &inputs.artifact);
                    assert_eq!(
                        source.selection.value()["selectedNodeIds"],
                        json!(["sign", "root", "door"])
                    );
                    assert_eq!(inputs.patch["entries"].as_array().unwrap().len(), 1);
                } else {
                    assert_eq!(
                        source.selection.value()["selectedNodeIds"],
                        json!(["door", "sign"])
                    );
                }
                assert!(source.ingested_bake.is_none());
                let target = ObjectNode {
                    instance_id: "instance-shop-a".into(),
                    node_id: "door".into(),
                };
                if artifact_kind == "prefab" {
                    assert_ne!(
                        source.selection.node(&target).unwrap()["transform"],
                        inputs.patch["entries"][0]["transform"]
                    );
                }
                data.validate_scene_provenance_with_store(
                    &borrowed,
                    &principal,
                    &catalog,
                    &inputs.patch,
                    &source,
                    &context,
                    witness.budget(),
                )?;
                source.artifact["name"] = json!("Caller altered retained artifact after admission");
                let error = data
                    .validate_scene_provenance_with_store(
                        &borrowed,
                        &principal,
                        &catalog,
                        &inputs.patch,
                        &source,
                        &context,
                        witness.budget(),
                    )
                    .expect_err("Returned source is not authority to substitute original bytes");
                assert_eq!(error.code, "SOURCE_PROVENANCE_INVALID");
                borrowed.with_read(|store| {
                    assert_eq!(
                        store.project(catalog.project_id()).unwrap(),
                        *catalog.project()
                    );
                    Ok(())
                })?;
                Ok(json!({"actualStaticSourceRead":true,"bakeIssued":false}))
            })
            .unwrap();
    }
}

#[test]
fn owned_static_scene_rejects_wrong_metadata_foreign_owner_ambiguous_maps_and_bake_escalation() {
    for case in [
        "size",
        "foreign",
        "map_revision",
        "ambiguous_map",
        "bake",
        "attach_clip",
    ] {
        let mut fixture = OwnedFixture::new(STATIC_RESOURCES);
        let inputs = static_inputs(&mut fixture, case);
        let mut data = fixture.data();
        let principal = fixture.principal.principal().clone();
        let catalog = fixture.catalog.clone();
        let context = fixture.context.clone();
        let result = fixture.call(move |store, witness| {
            let borrowed = PlanningStore::read(store);
            data.scene_source_with_store(
                &borrowed,
                &principal,
                &catalog,
                &inputs.patch,
                &context,
                witness.budget(),
            )
            .map(|_| json!({"unexpectedAdmission":true}))
        });
        let error = result.expect_err(case);
        let expected = match case {
            "size" | "foreign" | "map_revision" => "REVISION_CONFLICT",
            "ambiguous_map" => "OBJECT_MAPPING_AMBIGUOUS",
            _ => "CAPABILITY_UNAVAILABLE",
        };
        assert_eq!(error.code, expected, "case={case}");
    }
}

struct OwnedFixture {
    // The service's SQLite/CAS lock is dropped before its owned external root.
    service: ApplicationService,
    root: OwnedRoot,
    _sessions: SessionAuthority,
    principal: AuthenticatedPrincipal,
    authority: LocalAuthority,
    hosts: HostBridge,
    contexts: SharedPlanningContexts,
    slot: RequestContextSlot,
    project: Value,
    catalog: ProjectCatalog,
    prefab: Value,
    instance: Value,
    context: Value,
    budget: RequestBudget,
    witness: Rc<RefCell<Option<RequestContextWitness>>>,
}
impl OwnedFixture {
    fn new(resource_ids: &[&str]) -> Self {
        let root = OwnedRoot::new();
        let mut store = root.open();
        let selection = owned_example("scene-selection.json");
        let prefab = selection["prefabs"][0].clone();
        let instance = selection["instances"][0].clone();
        let mut project = owned_example("project.json");
        project["prefabIds"] = json!([prefab["prefabId"]]);
        project["instanceIds"] = json!([instance["instanceId"]]);
        project["resourceIds"] = json!(resource_ids);
        project["ownedResources"] = json!([
            {"kind":"prefab","objectId":prefab["prefabId"],"revision":prefab["revision"]},
            {"kind":"instance","objectId":instance["instanceId"],"revision":instance["revision"]}
        ]);
        project["revision"] = json!(projected_digest("Project", &project).unwrap());
        store.save_project(&project, None).unwrap();
        let catalog = ProjectCatalog::from_project(&project).unwrap();
        for (index, document) in [&prefab, &instance].into_iter().enumerate() {
            let pin: OwnedDocumentPin =
                serde_json::from_value(project["ownedResources"][index].clone()).unwrap();
            register_owned_document(
                &mut store,
                catalog.project_id(),
                catalog.revision(),
                &pin,
                document,
            )
            .unwrap();
        }
        let hosts = HostBridge::default();
        let authority = LocalAuthority::new(hosts.clone());
        let owner = PrincipalId::new("principal-owned-planning-data").unwrap();
        let context_id = ContextId::new("context-owned-planning-data").unwrap();
        let scope = json!({"projectId":catalog.project_id(),"objectIds":[prefab["prefabId"],instance["instanceId"]],
            "resourceIds":resource_ids,"regions":[],"externalTargetIds":[]});
        let revision = authority
            .stage_project_access(
                owner.clone(),
                catalog.project_id().clone(),
                scope.clone(),
                [context_id.clone()].into(),
                Duration::from_secs(120),
            )
            .unwrap();
        authority
            .activate_staged_project(&owner, catalog.project_id(), &revision)
            .unwrap();
        let mut sessions = SessionAuthority::new(2).unwrap();
        let token = sessions
            .install(SessionPolicy {
                principal: owner,
                allowed_methods: ["scene.diff".into()].into(),
                allowed_contexts: [context_id.clone()].into(),
                lifetime: Duration::from_secs(120),
            })
            .unwrap();
        let principal = sessions.authenticate_token(&token).unwrap();
        let budget =
            RequestBudget::new(Duration::from_secs(30), Arc::new(AtomicBool::new(false))).unwrap();
        let mut context = json!({"contractVersion":"0.2.0","contextId":context_id,"principalRef":principal.principal(),
            "projectId":catalog.project_id(),"environment":{"kind":"offline","workspaceId":"workspace-owned-planning-data","side":"offline"},
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
        let contexts = planning_context_adapter(locator);
        let slot = RequestContextSlot::default();
        let mut service = ApplicationService::from_store(store, no_application_ports());
        service.bind_request_context(slot.clone());
        Self {
            service,
            root,
            _sessions: sessions,
            principal,
            authority,
            hosts,
            contexts,
            slot,
            project,
            catalog,
            prefab,
            instance,
            context,
            budget,
            witness: Rc::new(RefCell::new(None)),
        }
    }
    fn data(&self) -> OwnedPlanningData {
        OwnedPlanningData::new(
            self.slot.clone(),
            self.authority.clone(),
            self.hosts.clone(),
            self.contexts.clone(),
            None,
        )
    }
    fn call(
        &mut self,
        action: impl FnMut(&mut DurableStore, RequestContextWitness) -> AppResult<Value> + 'static,
    ) -> Result<Value, ServiceError> {
        assert!(self.slot.occupied_witness().is_err());
        let mut extensions = ExtensionRouter::default();
        extensions
            .register(
                ["scene.diff"],
                Box::new(OccupiedRead {
                    slot: self.slot.clone(),
                    action: Box::new(action),
                    witness: self.witness.clone(),
                }),
            )
            .unwrap();
        self.service.set_extensions(extensions);
        let result = self
            .service
            .call(&self.principal, "scene.diff", &json!({}), &self.budget);
        assert!(self.slot.occupied_witness().is_err());
        if let Some(retired) = self.witness.borrow().as_ref() {
            assert!(retired.check_local().is_err());
        }
        result
    }
}

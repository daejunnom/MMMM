//! Original Project/Prefab examples are reused. External SQLite/CAS cases are
//! necessary for actual bytes, immutable ownership, rights revocation and
//! restart boundaries; they do not prove a native game profile or acceptance.
use super::*;
use crate::{
    auth::{SessionAuthority, SessionPolicy},
    planning_source::{RegisteredPlanningContexts, RegisteredWorkspaceContexts},
};
use mmmm_contracts::{ObjectId, parse_json, projected_digest};
use mmmm_reference::{Catalog, CatalogLimits};
use mmmm_runtime::storage::{
    BlobRef, StoreConfig,
    owned_documents::{OwnedDocumentKind, register_owned_document},
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
const OWNER_MARKER: &[u8] = b"mmmm-catalog-source-tests\n";
struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        assert!(parent.is_absolute());
        let path = parent.join(format!(
            "mmmm-catalog-source-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(!path.exists());
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = fs::canonicalize(path).unwrap();
        let checkout =
            fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        assert!(!path.starts_with(checkout));
        fs::write(path.join("test-owner.txt"), OWNER_MARKER).unwrap();
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
            && fs::read(self.0.join("test-owner.txt")).ok().as_deref() == Some(OWNER_MARKER)
            && owned_tree(&self.0, 0, &mut count)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
fn owned_tree(path: &Path, depth: usize, count: &mut usize) -> bool {
    if depth > 10 || *count >= 256 {
        return false;
    }
    *count += 1;
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if meta.file_type().is_symlink() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    if meta.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return false;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            if !owned_tree(&entry.path(), depth + 1, count) {
                return false;
            }
        }
    } else if !meta.is_file() {
        return false;
    }
    true
}
fn project(resource_ids: &[&str]) -> Value {
    let mut value = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
    value["prefabIds"] = json!([]);
    value["instanceIds"] = json!([]);
    value["ownedResources"] = json!([]);
    value["resourceIds"] = json!(resource_ids);
    value["revision"] = json!(projected_digest("Project", &value).unwrap());
    value
}
fn put_resource(
    store: &mut DurableStore,
    project: &ProjectId,
    id: &str,
    bytes: &[u8],
    media_type: &str,
) -> RegisteredCatalogResource {
    let blob = store.put_blob(bytes).unwrap();
    let resource = json!({"resourceId":id,"sha256":blob.digest,"sizeBytes":blob.byte_length,"mediaType":media_type});
    register_resource(store, &resource, ResourceOwner::Project(project.clone())).unwrap();
    RegisteredCatalogResource {
        query: ProjectResourceQuery::Exact {
            resource_id: ResourceId::new(id).unwrap(),
            digest: blob.digest,
        },
        resource,
    }
}
struct Fixture {
    sessions: SessionAuthority,
    authenticated: AuthenticatedPrincipal,
    budget: RequestBudget,
    cancelled: Arc<AtomicBool>,
    sources: RegisteredCatalogSources,
    context: Value,
}
impl Fixture {
    fn new(project: &Value, objects: &[&str]) -> Self {
        let project_id = ProjectId::new(project["projectId"].as_str().unwrap()).unwrap();
        let principal = PrincipalId::new("principal-catalog-source").unwrap();
        let context_id = ContextId::new("context-catalog-workspace").unwrap();
        let hosts = HostBridge::default();
        let authority = LocalAuthority::new(hosts.clone());
        let scope = json!({"projectId":project_id,"resourceIds":project["resourceIds"],"objectIds":objects,"regions":[],"externalTargetIds":[]});
        let policy = authority
            .stage_project_access(
                principal.clone(),
                project_id.clone(),
                scope.clone(),
                [context_id.clone()].into(),
                Duration::from_secs(120),
            )
            .unwrap();
        authority
            .activate_staged_project(&principal, &project_id, &policy)
            .unwrap();
        let mut sessions = SessionAuthority::new(2).unwrap();
        let token = sessions
            .install(SessionPolicy {
                principal,
                allowed_methods: [
                    "catalog.capture".into(),
                    "catalog.search".into(),
                    "catalog.describe".into(),
                ]
                .into(),
                allowed_contexts: [context_id.clone()].into(),
                lifetime: Duration::from_secs(120),
            })
            .unwrap();
        let authenticated = sessions.authenticate_token(&token).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let budget = RequestBudget::new(Duration::from_secs(120), cancelled.clone()).unwrap();
        let mut context = json!({"contractVersion":"0.2.0","contextId":context_id,"principalRef":authenticated.principal(),"projectId":project_id,
            "environment":{"kind":"offline","workspaceId":"workspace-catalog-source","side":"offline"},"policyRevision":policy,"scope":scope,"contextDigest":"0".repeat(64)});
        context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
        let mut workspace = RegisteredWorkspaceContexts::default();
        workspace
            .register(&authenticated, &authority, context.clone(), &budget)
            .unwrap();
        let contexts: SharedPlanningContexts = Rc::new(RefCell::new(Box::new(
            RegisteredPlanningContexts::new(workspace),
        )));
        Self {
            sessions,
            authenticated,
            budget,
            cancelled,
            sources: RegisteredCatalogSources::new(authority, hosts, contexts),
            context,
        }
    }
    fn registration(
        &self,
        sources: Vec<CatalogSourceRegistration>,
    ) -> CatalogEnvironmentRegistration {
        CatalogEnvironmentRegistration {
            context: self.context.clone(),
            game_version: Some("26.3".into()),
            locale: Some("en_us".into()),
            artifact_source: None,
            server_pack_sources: Some(vec![]),
            client_pack_sources: Some(vec![]),
            mod_sources: Some(BTreeMap::new()),
            registry_generation: Some("actual-source-extraction-1".into()),
            native_mod_ids: BTreeMap::new(),
            sources,
        }
    }
    fn install(&self, store: &DurableStore, registration: CatalogEnvironmentRegistration) {
        self.sources
            .register(&self.authenticated, &self.budget, store, registration)
            .unwrap();
    }
    fn call(&self) -> CatalogCall {
        let id = context_id(&self.context).unwrap();
        CatalogCall {
            sources: self.sources.clone(),
            authenticated: self.authenticated.clone(),
            budget: self.budget.clone(),
            installed: self.sources.environment(&self.authenticated, &id).unwrap(),
            read_principal: self
                .sources
                .read_principal(&self.authenticated, &id)
                .unwrap(),
            native_checkpoint: None,
        }
    }
    fn request(&self, kind: &str) -> Value {
        let refs = self
            .sources
            .source_refs(
                &self.authenticated,
                &context_id(&self.context).unwrap(),
                &self.budget,
            )
            .unwrap();
        json!({"contextId":self.context["contextId"],"environment":self.context["environment"],"sources":refs,"kind":kind,"loadPolicy":"no_implicit_runtime_mutation"})
    }
}
fn source(backing: CatalogSourceBacking, id: &str) -> CatalogSourceRegistration {
    CatalogSourceRegistration {
        source: json!({"sourceId":id,"kind":"project_declared","locator":"mmmm-source://unresolved","sha256":null,"rights":"user_local_only","verifiedAt":"2026-10-14T00:00:00Z"}),
        layer: CatalogLayer::LocalArtifact,
        role: CatalogSourceRole::CatalogData,
        codec: CatalogSourceCodec::JsonAsset {
            kind: ResourceLocation::new("minecraft:model").unwrap(),
            resource_id: ResourceLocation::new("example:offset").unwrap(),
            value_type: "raw_json_asset".into(),
            unit: "unitless".into(),
        },
        backing,
    }
}
fn capture(
    store: &mut DurableStore,
    fixture: &Fixture,
    catalog: &mut Catalog,
    request: &Value,
) -> Result<Value, CatalogError> {
    let call = fixture.call();
    let principal = call.read_principal.clone();
    let access = CatalogAccess(call.clone(), true, None);
    let shared = PlanningStore::write(store);
    let backend = BorrowedCatalogBackend {
        store: shared.clone(),
        call: call.clone(),
        attempt: None,
        retained_sources: Vec::new(),
    };
    let transport = PairedCatalogRegistry {
        store: shared.clone(),
        call: call.clone(),
    };
    let mut port = RetainedCatalogCapture {
        inner: VerifiedSnapshotSource { transport, backend },
        store: shared,
        call,
    };
    let control = CaptureControl {
        cancellation: fixture.budget.cancellation(),
        deadline: fixture.budget.deadline(),
    };
    let snapshot = catalog.capture(request, &principal, &access, &mut port, &control)?;
    drop(port);
    fixture
        .sources
        .complete_capture_call(&fixture.call(), &snapshot, catalog, store)
        .map_err(app_catalog)?;
    Ok(snapshot)
}
fn read_blob(store: &DurableStore, resource: &Value) -> Vec<u8> {
    store
        .read_blob(&BlobRef {
            digest: digest_field(resource, "sha256").unwrap(),
            byte_length: resource["sizeBytes"].as_u64().unwrap(),
        })
        .unwrap()
}

#[test]
fn actual_project_source_raw_bytes_and_snapshot_manifest_survive_store_restart() {
    let root = TestRoot::new();
    let mut store = root.open();
    let project = project(&["catalog-json"]);
    store.save_project(&project, None).unwrap();
    let id = ProjectId::new(project["projectId"].as_str().unwrap()).unwrap();
    let raw=b" { \"elements\": [{\"from\":[12,0,0],\"to\":[16,8,4]}], \"unrecognizedExtension\": null } \n";
    let resource = put_resource(&mut store, &id, "catalog-json", raw, "application/json");
    let fixture = Fixture::new(&project, &[]);
    fixture.install(
        &store,
        fixture.registration(vec![source(
            CatalogSourceBacking::ProjectResource(resource),
            "source-json",
        )]),
    );
    let request = fixture.request("local_artifact");
    let mut catalog = Catalog::new([23; 32], CatalogLimits::default()).unwrap();
    let snapshot = capture(&mut store, &fixture, &mut catalog, &request).unwrap();
    assert_eq!(snapshot["sources"][0]["sha256"], raw_digest(raw).as_str());
    assert!(snapshot["artifactSha256"].is_null());
    let call = fixture.call();
    let read=catalog.describe(&json!({"snapshotId":snapshot["snapshotId"],"contextId":fixture.context["contextId"],"kind":"minecraft:model","resourceId":"example:offset"}),&call.read_principal.clone(),&CatalogAccess(call,false,None)).unwrap();
    assert_eq!(read["value"], parse_json(raw).unwrap());
    assert_eq!(read["unit"], "unitless");
    let sid = SnapshotId::new(snapshot["snapshotId"].as_str().unwrap()).unwrap();
    let receipt = fixture.sources.state.borrow().captures[&sid].clone();
    let manifest = parse_json(&read_blob(&store, &receipt.retained_manifest)).unwrap();
    assert_eq!(manifest["snapshot"], snapshot);
    drop(store);
    let store = root.open();
    assert_eq!(
        parse_json(&read_blob(&store, &receipt.retained_manifest)).unwrap(),
        manifest
    );
    let unregistered = RegisteredCatalogSources::new(
        fixture.sources.authority.clone(),
        fixture.sources.hosts.clone(),
        fixture.sources.contexts.clone(),
    );
    assert!(
        unregistered
            .read_principal(
                &fixture.authenticated,
                &context_id(&fixture.context).unwrap()
            )
            .is_err()
    );
}

#[test]
fn unknown_rights_wrong_caller_hash_and_other_project_source_are_rejected() {
    let root = TestRoot::new();
    let mut store = root.open();
    let project = project(&["catalog-json"]);
    store.save_project(&project, None).unwrap();
    let id = ProjectId::new(project["projectId"].as_str().unwrap()).unwrap();
    let resource = put_resource(
        &mut store,
        &id,
        "catalog-json",
        b"{\"actual\":1}",
        "application/json",
    );
    let fixture = Fixture::new(&project, &[]);
    let mut input = source(
        CatalogSourceBacking::ProjectResource(resource.clone()),
        "source-json",
    );
    input.source["rights"] = json!("unknown");
    assert_eq!(
        fixture
            .sources
            .register(
                &fixture.authenticated,
                &fixture.budget,
                &store,
                fixture.registration(vec![input])
            )
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
    let mut input = source(
        CatalogSourceBacking::ProjectResource(resource.clone()),
        "source-json",
    );
    input.source["sha256"] = json!(raw_digest(b"caller claim"));
    assert_eq!(
        fixture
            .sources
            .register(
                &fixture.authenticated,
                &fixture.budget,
                &store,
                fixture.registration(vec![input])
            )
            .unwrap_err()
            .code,
        "SOURCE_CONFLICT"
    );
    let mut foreign = resource;
    foreign.query = ProjectResourceQuery::RegisteredImmutable {
        resource_id: ResourceId::new("missing-other-project").unwrap(),
    };
    assert!(
        fixture
            .sources
            .register(
                &fixture.authenticated,
                &fixture.budget,
                &store,
                fixture.registration(vec![source(
                    CatalogSourceBacking::ProjectResource(foreign),
                    "source-json"
                )])
            )
            .is_err()
    );
}

#[test]
fn current_scope_and_source_revocation_apply_to_catalog_cache_reads() {
    let root = TestRoot::new();
    let mut store = root.open();
    let project = project(&["catalog-json"]);
    store.save_project(&project, None).unwrap();
    let id = ProjectId::new(project["projectId"].as_str().unwrap()).unwrap();
    let resource = put_resource(
        &mut store,
        &id,
        "catalog-json",
        b"{\"actual\":1}",
        "application/json",
    );
    let fixture = Fixture::new(&project, &[]);
    fixture.install(
        &store,
        fixture.registration(vec![source(
            CatalogSourceBacking::ProjectResource(resource),
            "source-json",
        )]),
    );
    let mut catalog = Catalog::new([31; 32], CatalogLimits::default()).unwrap();
    let snapshot = capture(
        &mut store,
        &fixture,
        &mut catalog,
        &fixture.request("local_artifact"),
    )
    .unwrap();
    let call = fixture.call();
    let access = CatalogAccess(call.clone(), false, None);
    access
        .authorize_snapshot(&call.read_principal, &snapshot)
        .unwrap();
    fixture
        .sources
        .revoke(
            &fixture.authenticated,
            &context_id(&fixture.context).unwrap(),
        )
        .unwrap();
    let error = access
        .authorize_snapshot(&call.read_principal, &snapshot)
        .unwrap_err();
    assert_eq!(error.code(), "PERMISSION_REQUIRED");
    assert!(std::error::Error::source(&error).unwrap().is::<AppError>());
    // Raw historical evidence remains retained. Reading it through the
    // owning catalog still requires the current binding, including cache hits.
    let error = catalog.describe(&json!({"snapshotId":snapshot["snapshotId"],"contextId":fixture.context["contextId"],"kind":"minecraft:model","resourceId":"example:offset"}),&call.read_principal,&access).unwrap_err();
    assert_eq!(error.code(), "PERMISSION_REQUIRED");
    assert!(std::error::Error::source(&error).unwrap().is::<AppError>());
    let snapshot_id = SnapshotId::new(snapshot["snapshotId"].as_str().unwrap()).unwrap();
    let retained = fixture.sources.state.borrow().captures[&snapshot_id].clone();
    assert_eq!(
        read_blob(&store, &retained.source_resources[0].resource),
        b"{\"actual\":1}"
    );
    // Initial resolution without a source installation remains unavailable;
    // that diagnostic must not masquerade as revoked retained authority.
    assert_eq!(
        fixture
            .sources
            .read_principal(
                &fixture.authenticated,
                &context_id(&fixture.context).unwrap()
            )
            .unwrap_err()
            .code,
        "SOURCE_UNAVAILABLE"
    );
}

#[test]
fn cancelled_retained_authority_requires_current_session_and_full_scope_without_host_io() {
    let root = TestRoot::new();
    let mut store = root.open();
    let project = project(&["catalog-json"]);
    store.save_project(&project, None).unwrap();
    let id = ProjectId::new(project["projectId"].as_str().unwrap()).unwrap();
    let resource = put_resource(
        &mut store,
        &id,
        "catalog-json",
        b"{\"actual\":1}",
        "application/json",
    );
    let mut fixture = Fixture::new(&project, &[]);
    fixture.install(
        &store,
        fixture.registration(vec![source(
            CatalogSourceBacking::ProjectResource(resource),
            "source-json",
        )]),
    );
    let call = fixture.call();
    fixture.cancelled.store(true, Ordering::Release);
    assert!(call.fresh().is_err());
    call.local().unwrap();
    let rpc = call.rpc().unwrap();
    let translated = rpc.storage_error(rpc.check().unwrap_err());
    assert_eq!(translated.code, "CANCELLED");
    assert!(std::error::Error::source(&translated).is_some());
    let translated = app_catalog(translated);
    assert_eq!(translated.code(), "CANCELLED");
    assert_eq!(
        std::error::Error::source(&translated)
            .unwrap()
            .downcast_ref::<AppError>()
            .unwrap()
            .code,
        "CANCELLED"
    );
    fixture.sessions.revoke_all();
    assert!(call.local().is_err());
}

#[test]
fn approved_archive_member_uses_exact_container_and_closed_bounded_member_decoder() {
    let root = TestRoot::new();
    let mut store = root.open();
    let project = project(&["approved-pack"]);
    store.save_project(&project, None).unwrap();
    let id = ProjectId::new(project["projectId"].as_str().unwrap()).unwrap();
    let raw = b"{\"parent\":\"example:actual\",\"unknownExtension\":{\"keep\":true}}";
    let member = "assets/example/models/offset.json";
    // The existing exchange archive parser's closed profile requires a root
    // manifest. This tests exact approved member bytes; arbitrary game JARs
    // remain unsupported by that parser rather than silently becoming valid.
    let entries = BTreeMap::from([
        (member.to_owned(), raw.to_vec()),
        ("mmmm-exchange.json".to_owned(), b"{}".to_vec()),
    ]);
    let limits = ArchiveLimits::default();
    let archive_bytes = mmmm_exchange::archive::write_zip(&entries, limits).unwrap();
    let archive = put_resource(
        &mut store,
        &id,
        "approved-pack",
        &archive_bytes,
        "application/zip",
    );
    let fixture = Fixture::new(&project, &[]);
    let backing = CatalogSourceBacking::ArchiveMember {
        archive: archive.clone(),
        member: member.into(),
        member_sha256: raw_digest(raw),
        member_bytes: raw.len() as u64,
        limits,
    };
    fixture.install(
        &store,
        fixture.registration(vec![source(backing, "source-model")]),
    );
    let mut catalog = Catalog::new([11; 32], CatalogLimits::default()).unwrap();
    let snapshot = capture(
        &mut store,
        &fixture,
        &mut catalog,
        &fixture.request("local_artifact"),
    )
    .unwrap();
    assert_eq!(snapshot["sources"][0]["sha256"], raw_digest(raw).as_str());
    let invalid = CatalogSourceBacking::ArchiveMember {
        archive,
        member: "../outside.json".into(),
        member_sha256: raw_digest(raw),
        member_bytes: raw.len() as u64,
        limits,
    };
    assert!(
        fixture
            .sources
            .register(
                &fixture.authenticated,
                &fixture.budget,
                &store,
                fixture.registration(vec![source(invalid, "source-model")])
            )
            .is_err()
    );
}

#[test]
fn actual_owned_document_bytes_use_checked_history_and_not_json_reserialization() {
    let root = TestRoot::new();
    let mut store = root.open();
    let prefab = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
    let pin = OwnedDocumentPin {
        kind: OwnedDocumentKind::Prefab,
        object_id: ObjectId::new(prefab["prefabId"].as_str().unwrap()).unwrap(),
        revision: digest_field(&prefab, "revision").unwrap(),
    };
    let mut project = project(&[]);
    project["prefabIds"] = json!([pin.object_id]);
    project["ownedResources"] = json!([pin]);
    project["revision"] = json!(projected_digest("Project", &project).unwrap());
    store.save_project(&project, None).unwrap();
    let id = ProjectId::new(project["projectId"].as_str().unwrap()).unwrap();
    register_owned_document(
        &mut store,
        &id,
        &digest_field(&project, "revision").unwrap(),
        &pin,
        &prefab,
    )
    .unwrap();
    let fixture = Fixture::new(&project, &[pin.object_id.as_str()]);
    let mut input = source(
        CatalogSourceBacking::OwnedDocument(pin.clone()),
        "source-prefab",
    );
    input.codec = CatalogSourceCodec::JsonAsset {
        kind: ResourceLocation::new("mmmm:prefab_source").unwrap(),
        resource_id: ResourceLocation::new("example:shop").unwrap(),
        value_type: "raw_prefab_source".into(),
        unit: "unitless".into(),
    };
    fixture.install(&store, fixture.registration(vec![input]));
    let call = fixture.call();
    let rpc = call.rpc().unwrap();
    let mut reader = OwnedDocumentReader::new(
        Box::new(CatalogReadAuthority(rpc.clone())),
        MAX_DOCUMENT_BYTES,
    )
    .unwrap();
    let actual = reader
        .read_known_history_bytes(
            &store,
            &rpc,
            &id,
            &digest_field(&project, "revision").unwrap(),
            &pin,
        )
        .unwrap();
    let mut catalog = Catalog::new([22; 32], CatalogLimits::default()).unwrap();
    let snapshot = capture(
        &mut store,
        &fixture,
        &mut catalog,
        &fixture.request("local_artifact"),
    )
    .unwrap();
    assert_eq!(
        snapshot["sources"][0]["sha256"],
        actual.blob.digest.as_str()
    );
    assert_eq!(raw_digest(&actual.bytes), actual.blob.digest);
}

#[test]
fn native_source_receipts_never_fill_unknown_pack_or_client_identity() {
    let archive = b"PK\x03\x04actual-container";
    let sha = raw_digest(archive);
    let resource = RegisteredCatalogResource {
        query: ProjectResourceQuery::RegisteredImmutable {
            resource_id: ResourceId::new("actual-game-container").unwrap(),
        },
        resource: json!({"resourceId":"actual-game-container","sha256":sha,"sizeBytes":archive.len(),"mediaType":"application/java-archive"}),
    };
    let mut game_source = source(
        CatalogSourceBacking::ProjectResource(resource),
        "source-game",
    );
    game_source.role = CatalogSourceRole::GameArtifact;
    game_source.codec = CatalogSourceCodec::FingerprintOnly {
        media_type: "application/java-archive".into(),
    };
    game_source.source["sha256"] = json!(sha);
    let context = json!({"environment":{"kind":"game","gameInstanceId":"game-instance","sessionEpoch":"epoch-one","worldId":"world-one","side":"server"}});
    let facts = json!({"format":"mmmm.native.source-facts/1","environment":context["environment"],"registryGeneration":"7","archiveReceiptScope":"container_input_bytes","transformedClassBytes":"not_observed","resourceContentEnumeration":"not_performed",
        "archives":[{"status":"observed","sourceId":format!("archive-sha256-{sha}"),"sha256":sha,"sizeBytes":archive.len(),"scope":"container_input_bytes"}],"mods":[],
        "originalInputGameJars":[{"status":"observed","sourceId":format!("archive-sha256-{sha}"),"sha256":sha,"sizeBytes":archive.len(),"scope":"original_game_input_container","inputIndex":0}],
        "serverPacks":[{"packIndex":0,"packSourceCompleteness":"unknown","resourceContentObservation":"not_enumerated","linkedRuntimeContainerSources":[]}],"clientPacks":null});
    validate_source_facts(&facts, &context).unwrap();
    let registration = CatalogEnvironmentRegistration {
        context: context.clone(),
        game_version: Some("26.3".into()),
        locale: Some("en_us".into()),
        artifact_source: Some(SourceId::new("source-game").unwrap()),
        server_pack_sources: Some(vec![]),
        client_pack_sources: Some(vec![]),
        mod_sources: Some(BTreeMap::new()),
        registry_generation: None,
        native_mod_ids: BTreeMap::new(),
        sources: vec![game_source.clone()],
    };
    let mut installed = InstalledEnvironment {
        registration,
        sources: BTreeMap::from([(
            SourceId::new("source-game").unwrap(),
            InstalledSource {
                approved: ApprovedCatalogSource {
                    source: game_source.source.clone(),
                    layer: game_source.layer,
                    role: game_source.role,
                    rights_witness: raw_digest(b"explicit current rights"),
                    codec: game_source.codec,
                },
                backing: game_source.backing,
            },
        )]),
        project: ProjectId::new("project-one").unwrap(),
        principal: PrincipalId::new("principal-one").unwrap(),
        revision: raw_digest(b"actual binding"),
    };
    let mut grant = CaptureGrant {
        execution_context: context,
        snapshot_id: SnapshotId::new("snapshot-one").unwrap(),
        game_version: Some("26.3".into()),
        locale: Some("en_us".into()),
        created_at: "2026-10-14T00:00:00Z".into(),
        artifact_source: Some(SourceId::new("source-game").unwrap()),
        server_pack_sources: Some(vec![]),
        client_pack_sources: Some(vec![]),
        mod_sources: Some(BTreeMap::new()),
        registry_generation: None,
        sources: vec![],
    };
    apply_actual_source_identity(&mut grant, &installed, &facts).unwrap();
    assert!(grant.server_pack_sources.is_none());
    assert!(grant.client_pack_sources.is_none());
    assert_eq!(
        grant.artifact_source,
        Some(SourceId::new("source-game").unwrap())
    );
    let canonical_mod = ResourceLocation::new("example:canonical_mod").unwrap();
    let mod_source_id = SourceId::new("source-mod").unwrap();
    let mut mod_source = installed.sources[&SourceId::new("source-game").unwrap()].clone();
    mod_source.approved.source["sourceId"] = json!(mod_source_id);
    mod_source.approved.role = CatalogSourceRole::Mod(canonical_mod.clone());
    installed.sources.insert(mod_source_id.clone(), mod_source);
    let mod_map = BTreeMap::from([(canonical_mod.clone(), mod_source_id)]);
    installed.registration.mod_sources = Some(mod_map.clone());
    installed
        .registration
        .native_mod_ids
        .insert(canonical_mod, "actual_native_mod".into());
    let mut native_mods = facts.clone();
    native_mods["mods"] =
        json!([{"modId":"actual_native_mod","runtimeRoots":[facts["archives"][0].clone()]}]);
    apply_actual_source_identity(&mut grant, &installed, &native_mods).unwrap();
    assert_eq!(grant.mod_sources, Some(mod_map));
    native_mods["mods"][0]["modId"] = json!("example:canonical_mod");
    apply_actual_source_identity(&mut grant, &installed, &native_mods).unwrap();
    assert!(grant.mod_sources.is_none());
    native_mods["mods"][0]["modId"] = json!("actual_native_mod");
    native_mods["mods"][0]["runtimeRoots"][0]["scope"] = json!("loaded_class_container");
    apply_actual_source_identity(&mut grant, &installed, &native_mods).unwrap();
    assert!(grant.mod_sources.is_none());
    let mut unrelated = facts;
    unrelated["originalInputGameJars"][0]["scope"] = json!("loaded_class_container");
    apply_actual_source_identity(&mut grant, &installed, &unrelated).unwrap();
    assert!(grant.artifact_source.is_none());
}

#[test]
fn private_source_facts_pin_excludes_only_observation_time() {
    // This exercises the projection of an internal report, not a wire/version
    // profile digest or a native-game attestation. Unknown fields stay pinned.
    let facts = json!({"format":"mmmm.native.source-facts/1","observedAt":"2026-10-14T00:00:00Z","bytesRead":4096,"entryCount":2,"registryGeneration":"7","originalInputGameJars":[],"clientPacks":null,"extensionUnknown":{"observed":null}});
    let pin = source_facts_pin(&facts).unwrap();
    let mut later = facts.clone();
    later["observedAt"] = json!("2026-10-14T00:00:01Z");
    assert_eq!(source_facts_pin(&later).unwrap(), pin);
    later["bytesRead"] = json!(8192);
    assert_ne!(source_facts_pin(&later).unwrap(), pin);
    let mut different_unknown = facts;
    different_unknown["extensionUnknown"]["observed"] = json!(false);
    assert_ne!(source_facts_pin(&different_unknown).unwrap(), pin);
}

#[test]
fn source_identity_uses_actual_whole_source_approval_and_checked_bytes_without_host_io() {
    let root = TestRoot::new();
    let mut store = root.open();
    let project = project(&["identity-input"]);
    store.save_project(&project, None).unwrap();
    let project_id = ProjectId::new(project["projectId"].as_str().unwrap()).unwrap();
    let raw = b" {\"actualApproved\":true,\"unknownField\":null} ";
    let resource = put_resource(
        &mut store,
        &project_id,
        "identity-input",
        raw,
        "application/json",
    );
    let expected_resource = resource.resource.clone();
    let fixture = Fixture::new(&project, &[]);
    let source_id = SourceId::new("identity-source").unwrap();
    fixture.install(
        &store,
        fixture.registration(vec![source(
            CatalogSourceBacking::ProjectResource(resource),
            source_id.as_str(),
        )]),
    );
    let read = fixture
        .sources
        .source_identity(
            &fixture.authenticated,
            &fixture.context,
            &source_id,
            &store,
            &fixture.budget,
        )
        .unwrap();
    assert_eq!(read.resource, expected_resource);
    assert_eq!(read.source["sha256"], raw_digest(raw).as_str());
    assert_eq!(read.source["rights"], "user_local_only");
    assert!(matches!(read.role, CatalogSourceRole::CatalogData));
    assert_eq!(read.binding_revision, fixture.call().installed.revision);
    let exact = fixture
        .sources
        .source_identity_with_limit(
            &fixture.authenticated,
            &fixture.context,
            &source_id,
            &store,
            &fixture.budget,
            raw.len() as u64,
        )
        .unwrap();
    assert_eq!(exact.resource, read.resource);
    assert_eq!(exact.source, read.source);
    assert_eq!(exact.binding_revision, read.binding_revision);
    for limit in [0, raw.len() as u64 - 1, MAX_SOURCE_BYTES + 1] {
        assert_eq!(
            fixture
                .sources
                .source_identity_with_limit(
                    &fixture.authenticated,
                    &fixture.context,
                    &source_id,
                    &store,
                    &fixture.budget,
                    limit
                )
                .unwrap_err()
                .code,
            "INPUT_LIMIT"
        );
    }
    let mut unregistered_context = fixture.context.clone();
    unregistered_context["environment"]["workspaceId"] = json!("other-workspace");
    assert_eq!(
        fixture
            .sources
            .source_identity(
                &fixture.authenticated,
                &unregistered_context,
                &source_id,
                &store,
                &fixture.budget
            )
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
    fixture
        .sources
        .revoke(
            &fixture.authenticated,
            &context_id(&fixture.context).unwrap(),
        )
        .unwrap();
    assert!(
        fixture
            .sources
            .source_identity(
                &fixture.authenticated,
                &fixture.context,
                &source_id,
                &store,
                &fixture.budget
            )
            .is_err()
    );
}

#[test]
fn generated_binary_resource_requires_completed_capture_and_current_exact_source_rights() {
    let root = TestRoot::new();
    let mut store = root.open();
    let project = project(&["binary-input"]);
    store.save_project(&project, None).unwrap();
    let project_id = ProjectId::new(project["projectId"].as_str().unwrap()).unwrap();
    let raw = b"\x00actual approved binary source\xff";
    let resource = put_resource(
        &mut store,
        &project_id,
        "binary-input",
        raw,
        "application/octet-stream",
    );
    let fixture = Fixture::new(&project, &[]);
    let mut input = source(
        CatalogSourceBacking::ProjectResource(resource),
        "source-binary",
    );
    input.codec = CatalogSourceCodec::BinaryAsset {
        kind: ResourceLocation::new("minecraft:texture").unwrap(),
        resource_id: ResourceLocation::new("example:raw_texture").unwrap(),
        media_type: "application/octet-stream".into(),
    };
    fixture.install(&store, fixture.registration(vec![input]));
    let mut catalog = Catalog::new([41; 32], CatalogLimits::default()).unwrap();
    let snapshot = capture(
        &mut store,
        &fixture,
        &mut catalog,
        &fixture.request("local_artifact"),
    )
    .unwrap();
    let id = SnapshotId::new(snapshot["snapshotId"].as_str().unwrap()).unwrap();
    let receipt = fixture.sources.state.borrow().captures[&id].source_resources[0].clone();
    assert_ne!(receipt.resource["resourceId"], "binary-input");
    assert_eq!(read_blob(&store, &receipt.resource), raw);
    let call = fixture.call();
    let described=catalog.describe(&json!({"snapshotId":id,"contextId":fixture.context["contextId"],"kind":"minecraft:texture","resourceId":"example:raw_texture"}),&call.read_principal.clone(),&CatalogAccess(call,false,None)).unwrap();
    assert_eq!(described["value"], receipt.resource);
    let authorized = fixture
        .sources
        .authorize_generated_resource(
            &fixture.authenticated,
            &fixture.budget,
            &fixture.context,
            &receipt.resource,
            &store,
        )
        .unwrap();
    assert!(authorized.is_some());
    assert_eq!(authorized.unwrap().1.source["rights"], "user_local_only");
    let mut tampered = receipt.resource.clone();
    tampered["mediaType"] = json!("application/json");
    assert_eq!(
        fixture
            .sources
            .authorize_generated_resource(
                &fixture.authenticated,
                &fixture.budget,
                &fixture.context,
                &tampered,
                &store
            )
            .err()
            .unwrap()
            .code,
        "PERMISSION_REQUIRED"
    );
    fixture
        .sources
        .revoke(
            &fixture.authenticated,
            &context_id(&fixture.context).unwrap(),
        )
        .unwrap();
    assert!(
        fixture
            .sources
            .authorize_generated_resource(
                &fixture.authenticated,
                &fixture.budget,
                &fixture.context,
                &receipt.resource,
                &store
            )
            .is_err()
    );
}

#[test]
fn cancellation_after_actual_retention_can_finalize_only_the_inserted_historical_snapshot() {
    struct CancelAfterCapture<'a> {
        source: RetainedCatalogCapture<'a>,
        cancelled: &'a AtomicBool,
    }
    impl SnapshotSource for CancelAfterCapture<'_> {
        fn capture(
            &mut self,
            request: &Value,
            control: &CaptureControl<'_>,
            budget: &CaptureBudget,
            access: &CaptureSourceAccess<'_>,
        ) -> Result<CaptureResult, CatalogError> {
            let mut result = self.source.capture(request, control, budget, access)?;
            // Cancellation occurs after actual CAS retention and before the
            // outer catalog's final validation/insertion, without inventing or
            // changing any captured record, source, coverage or identity pin.
            self.cancelled.store(true, Ordering::Release);
            result.interrupted = true;
            Ok(result)
        }
    }
    let root = TestRoot::new();
    let mut store = root.open();
    let project = project(&["cancel-input"]);
    store.save_project(&project, None).unwrap();
    let project_id = ProjectId::new(project["projectId"].as_str().unwrap()).unwrap();
    let raw = b"{\"actualRetained\":true}";
    let resource = put_resource(
        &mut store,
        &project_id,
        "cancel-input",
        raw,
        "application/json",
    );
    let fixture = Fixture::new(&project, &[]);
    fixture.install(
        &store,
        fixture.registration(vec![source(
            CatalogSourceBacking::ProjectResource(resource),
            "cancel-source",
        )]),
    );
    let call = fixture.call();
    let principal = call.read_principal.clone();
    let request = fixture.request("local_artifact");
    let shared = PlanningStore::write(&mut store);
    let backend = BorrowedCatalogBackend {
        store: shared.clone(),
        call: call.clone(),
        attempt: None,
        retained_sources: Vec::new(),
    };
    let transport = PairedCatalogRegistry {
        store: shared.clone(),
        call: call.clone(),
    };
    let retained = RetainedCatalogCapture {
        inner: VerifiedSnapshotSource { transport, backend },
        store: shared,
        call: call.clone(),
    };
    let mut port = CancelAfterCapture {
        source: retained,
        cancelled: &fixture.cancelled,
    };
    let control = CaptureControl {
        cancellation: fixture.budget.cancellation(),
        deadline: fixture.budget.deadline(),
    };
    let mut catalog = Catalog::new([47; 32], CatalogLimits::default()).unwrap();
    let snapshot = catalog
        .capture(
            &request,
            &principal,
            &CatalogAccess(call.clone(), true, None),
            &mut port,
            &control,
        )
        .unwrap();
    drop(port);
    assert_eq!(fixture.budget.check().unwrap_err().code, "CANCELLED");
    let id = SnapshotId::new(snapshot["snapshotId"].as_str().unwrap()).unwrap();
    assert_eq!(snapshot["coverage"]["status"], "partial");
    assert!(
        catalog
            .snapshot_pin(
                &id,
                &call.read_principal,
                &CatalogAccess(call.clone(), true, None)
            )
            .is_ok()
    );
    assert!(
        fixture
            .sources
            .state
            .borrow()
            .pending_captures
            .contains_key(&id)
    );
    fixture
        .sources
        .complete_capture_call(&call, &snapshot, &catalog, &store)
        .unwrap();
    assert!(fixture.sources.state.borrow().captures.contains_key(&id));
    assert!(
        !fixture
            .sources
            .state
            .borrow()
            .pending_captures
            .contains_key(&id)
    );
    assert_eq!(fixture.budget.check().unwrap_err().code, "CANCELLED");
    // A later call owns a different live budget. The old cancellation remains
    // set and is never refreshed or cleared by retained completion.
    let later =
        RequestBudget::new(Duration::from_secs(30), Arc::new(AtomicBool::new(false))).unwrap();
    fixture
        .sources
        .authorize_retained_snapshot(
            &fixture.authenticated,
            &later,
            &fixture.context,
            &id,
            &store,
        )
        .unwrap();
    assert_eq!(fixture.budget.check().unwrap_err().code, "CANCELLED");
}

#[test]
fn failed_catalog_insertion_keeps_raw_evidence_pending_without_artifact_or_exchange_grants() {
    let root = TestRoot::new();
    let mut store = root.open();
    let project = project(&["first-input", "next-input"]);
    store.save_project(&project, None).unwrap();
    let project_id = ProjectId::new(project["projectId"].as_str().unwrap()).unwrap();
    let first = put_resource(
        &mut store,
        &project_id,
        "first-input",
        b"{\"actual\":1}",
        "application/json",
    );
    let next = put_resource(
        &mut store,
        &project_id,
        "next-input",
        b"{\"actual\":2}",
        "application/json",
    );
    let fixture = Fixture::new(&project, &[]);
    fixture.install(
        &store,
        fixture.registration(vec![source(
            CatalogSourceBacking::ProjectResource(first),
            "first-source",
        )]),
    );
    let mut catalog = Catalog::new(
        [43; 32],
        CatalogLimits {
            max_snapshots: 1,
            ..CatalogLimits::default()
        },
    )
    .unwrap();
    capture(
        &mut store,
        &fixture,
        &mut catalog,
        &fixture.request("local_artifact"),
    )
    .unwrap();
    fixture.install(
        &store,
        fixture.registration(vec![source(
            CatalogSourceBacking::ProjectResource(next),
            "next-source",
        )]),
    );
    assert!(matches!(
        capture(
            &mut store,
            &fixture,
            &mut catalog,
            &fixture.request("local_artifact")
        ),
        Err(CatalogError::InputLimit)
    ));
    let state = fixture.sources.state.borrow();
    assert_eq!(state.captures.len(), 1);
    assert_eq!(state.pending_captures.len(), 1);
    let (id, pending) = state.pending_captures.iter().next().unwrap();
    let id = id.clone();
    let pending = pending.clone();
    drop(state);
    let call = fixture.call();
    assert!(matches!(
        catalog.snapshot_pin(
            &id,
            &call.read_principal,
            &CatalogAccess(call.clone(), true, None)
        ),
        Err(CatalogError::SnapshotNotFound)
    ));
    assert_eq!(
        read_blob(&store, &pending.source_resources[0].resource),
        b"{\"actual\":2}"
    );
    let manifest = parse_json(&read_blob(&store, &pending.retained_manifest)).unwrap();
    assert_eq!(manifest["snapshot"]["snapshotId"], id.as_str());
    assert_eq!(
        fixture
            .sources
            .authorize_retained_snapshot(
                &fixture.authenticated,
                &fixture.budget,
                &fixture.context,
                &id,
                &store
            )
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
    assert_eq!(
        fixture
            .sources
            .authorize_generated_resource(
                &fixture.authenticated,
                &fixture.budget,
                &fixture.context,
                &pending.source_resources[0].resource,
                &store
            )
            .err()
            .unwrap()
            .code,
        "PERMISSION_REQUIRED"
    );
    assert_eq!(
        fixture
            .sources
            .complete_capture_call(&fixture.call(), &manifest["snapshot"], &catalog, &store)
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
}

#[test]
fn inactive_request_slot_and_direct_decoded_runtime_source_cannot_install_authority() {
    let root = TestRoot::new();
    let mut store = root.open();
    let project = project(&["catalog-json"]);
    store.save_project(&project, None).unwrap();
    let id = ProjectId::new(project["projectId"].as_str().unwrap()).unwrap();
    let resource = put_resource(
        &mut store,
        &id,
        "catalog-json",
        b"{\"callerClaim\":\"complete\"}",
        "application/json",
    );
    let fixture = Fixture::new(&project, &[]);
    let mut input = source(
        CatalogSourceBacking::ProjectResource(resource.clone()),
        "source-json",
    );
    input.layer = CatalogLayer::EnvironmentSnapshot;
    assert!(
        fixture
            .sources
            .register(
                &fixture.authenticated,
                &fixture.budget,
                &store,
                fixture.registration(vec![input])
            )
            .is_err()
    );
    fixture.install(
        &store,
        fixture.registration(vec![source(
            CatalogSourceBacking::ProjectResource(resource),
            "source-json",
        )]),
    );
    let call = fixture.call();
    let access = FeatureAccess {
        read_principal: call.read_principal,
        context: Some(fixture.context.clone()),
        project: Some(project),
        granted_permissions: Default::default(),
    };
    let result = fixture.sources.capture_inputs(
        &RequestContextSlot::default(),
        &access,
        &fixture.request("local_artifact"),
        &mut store,
        &fixture.budget,
    );
    assert!(matches!(
        result,
        Err(ServiceError {
            code: "AUTHENTICATION_REQUIRED",
            ..
        })
    ));
}

#[test]
fn native_source_io_without_a_current_call_checkpoint_is_denied_while_explicit_is_unchanged() {
    let root = TestRoot::new();
    let mut store = root.open();
    let project = project(&["catalog-json"]);
    store.save_project(&project, None).unwrap();
    let id = ProjectId::new(project["projectId"].as_str().unwrap()).unwrap();
    let resource = put_resource(&mut store, &id, "catalog-json", b"{}", "application/json");
    let fixture = Fixture::new(&project, &[]);
    fixture.install(
        &store,
        fixture.registration(vec![source(
            CatalogSourceBacking::ProjectResource(resource),
            "source-json",
        )]),
    );
    let call = fixture.call();
    let shared = PlanningStore::read(&store);
    call.check_native_source(&shared).unwrap();
    // Negative publisher metadata is injected only to verify default denial.
    // No completed pairing, native owner, source grant or checkpoint is made.
    let key = (
        fixture.authenticated.principal().clone(),
        context_id(&fixture.context).unwrap(),
    );
    fixture.sources.state.borrow_mut().native_publishers.insert(
        key,
        NativeCatalogOrigin {
            proof: raw_digest(b"negative native origin"),
            read_policy: raw_digest(b"negative policy"),
            source_use: raw_digest(b"negative source use"),
            receipt: Rc::new(()),
        },
    );
    assert_eq!(
        call.check_native_source(&shared).unwrap_err().code,
        "PERMISSION_REQUIRED"
    );
}

#[test]
fn exact_native_retirement_contention_preserves_both_failure_causes_and_the_owned_element() {
    let root = TestRoot::new();
    let mut store = root.open();
    let project = project(&["catalog-json"]);
    store.save_project(&project, None).unwrap();
    let id = ProjectId::new(project["projectId"].as_str().unwrap()).unwrap();
    let resource = put_resource(&mut store, &id, "catalog-json", b"{}", "application/json");
    let fixture = Fixture::new(&project, &[]);
    fixture.install(
        &store,
        fixture.registration(vec![source(
            CatalogSourceBacking::ProjectResource(resource),
            "source-json",
        )]),
    );
    let key = (
        fixture.authenticated.principal().clone(),
        context_id(&fixture.context).unwrap(),
    );
    fixture.sources.state.borrow_mut().native_publishers.insert(
        key.clone(),
        NativeCatalogOrigin {
            proof: raw_digest(b"negative native origin"),
            read_policy: raw_digest(b"negative policy"),
            source_use: raw_digest(b"negative source use"),
            receipt: Rc::new(()),
        },
    );
    let NativeCatalogAdmissionState::Native(publication) = fixture
        .sources
        .native_admission_state(&fixture.authenticated, &fixture.context)
        .unwrap()
    else {
        panic!("native element required for negative retirement test");
    };
    let held = fixture.sources.state.borrow();
    let cleanup = fixture.sources.retire_native_publication(&publication);
    assert_eq!(cleanup.as_ref().unwrap_err().code, "SOURCE_BUSY");
    let primary = CatalogError::caused_by(
        CatalogError::SourceUnavailable("original source failure".into()),
        AppError::new("ORIGINAL_SOURCE_FAILURE", "Original source read failed"),
    );
    let error = finish_native_inspection::<()>(Err(primary), cleanup).unwrap_err();
    assert_eq!(error.code(), "SOURCE_UNAVAILABLE");
    assert_eq!(
        error.to_string(),
        "SOURCE_UNAVAILABLE: original source failure"
    );
    let both = std::error::Error::source(&error)
        .unwrap()
        .downcast_ref::<NativeCatalogInspectionFailure>()
        .unwrap();
    assert_eq!(both.checkpoint.code, "SOURCE_BUSY");
    assert_eq!(
        std::error::Error::source(both.primary.as_ref())
            .unwrap()
            .downcast_ref::<AppError>()
            .unwrap()
            .code,
        "ORIGINAL_SOURCE_FAILURE"
    );
    assert!(held.environments.contains_key(&key));
    assert!(held.native_publishers.contains_key(&key));
}

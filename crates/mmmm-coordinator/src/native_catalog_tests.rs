//! New fixtures are needed for the first operational native source issuer:
//! actual kernel-owned Project/Store/setup, entered service request and bounded
//! TCP host replies exercise that composition. The peer and tiny host JAR are
//! fixtures, not actual game, compatibility, pack or target-profile evidence.

use super::*;
use crate::{
    artifacts::ArtifactExtension,
    auth::{SessionAuthority, SessionPolicy},
    bootstrap::HostBootstrapProcessor,
    catalog_source_use::{LocalCatalogSourceUseAction, manage_catalog_source_use},
    daemon::{DaemonHandles, DaemonSourceFactory, PreparedDaemon},
    features::{FEATURE_METHODS, FeatureExtension},
    local_setup::{
        LocalHostSetup, register_local_host_setup, register_local_host_setup_with_read_policy,
    },
    native_source_ingress::{NativeRawSourceResource, NativeSourceInput},
    peer_management::{
        BootstrapBudget, HostOffer, ManagementRequest, PublicFrame, management_channel,
    },
    planning_source::{PlanningComposition, StoreAwarePlanner},
    production_factory::{ProductionFactory, ProductionRegistries},
    service::{
        ApplicationPorts, ApplicationService, ExtensionRouter, ServiceDispatcher, ServiceError,
    },
    workspace_bootstrap::{native_owner_resource_reader, prepare_workspace},
};
use mmmm_contracts::{ResourceLocation, SessionEpoch, TargetProfileId, raw_digest};
use mmmm_runtime::storage::{
    StoreConfig,
    catalog_source_use::{CatalogSourceUseReplace, CatalogSourceUseSelection},
    host_setup::HostReadPolicy,
    project_resources::ProjectResourceRequest,
};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const MARKER: &[u8] = b"mmmm-native-catalog-test-v1\n";
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let parent = fs::canonicalize(
            std::env::var_os("MMMM_TEST_DATA_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir),
        )
        .unwrap();
        let path = parent.join(format!(
            "mmmm-native-catalog-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let checkout =
            fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        assert!(path.is_absolute() && !path.starts_with(checkout) && !path.exists());
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(path.join("fixture-owner.txt"), MARKER).unwrap();
        fs::write(
            path.join("selected-host.jar"),
            b"bounded ordinary host fixture\n",
        )
        .unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
    fn config(&self) -> StoreConfig {
        StoreConfig::new(self.0.clone())
    }
}
fn plain_tree(path: &Path, root: &Path, count: &mut usize) -> bool {
    *count += 1;
    if *count > 512 || !path.starts_with(root) {
        return false;
    }
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
            if !plain_tree(&entry.path(), root, count) {
                return false;
            }
        }
    }
    meta.is_dir() || meta.is_file()
}
impl Drop for Root {
    fn drop(&mut self) {
        if fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0)
            && fs::read(self.0.join("fixture-owner.txt")).ok().as_deref() == Some(MARKER)
            && plain_tree(&self.0, &self.0, &mut 0)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

struct PeerState {
    hello: Value,
    context: Value,
    registry: Value,
    facts: Value,
    cancel_on_sources: Option<Arc<AtomicBool>>,
    cancel_at_source: Option<usize>,
    drift_on_sources: bool,
    fail_sources: bool,
    fail_at_source: Option<usize>,
    corrupt_at_source: Option<(usize, PathBuf)>,
    shape_probes: usize,
    shape_queries: usize,
}
struct Peer {
    address: SocketAddr,
    state: Arc<Mutex<PeerState>>,
    source_reads: Arc<AtomicUsize>,
    catalog_observations: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<(), &'static str>>>,
}
impl Peer {
    fn new(hello: Value, raw: Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(PeerState {
            hello,
            context: Value::Null,
            registry: raw,
            facts: Value::Null,
            cancel_on_sources: None,
            cancel_at_source: None,
            drift_on_sources: false,
            fail_sources: false,
            fail_at_source: None,
            corrupt_at_source: None,
            shape_probes: 0,
            shape_queries: 0,
        }));
        let source_reads = Arc::new(AtomicUsize::new(0));
        let catalog_observations = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let shared = state.clone();
        let reads = source_reads.clone();
        let observations = catalog_observations.clone();
        let stopping = stop.clone();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !stopping.load(Ordering::Acquire) {
                if Instant::now() >= deadline {
                    return Err("host fixture deadline");
                }
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(_) => return Err("host fixture accept"),
                };
                // Windows and Darwin can inherit nonblocking listener state;
                // read_exact below requires the original bounded blocking mode.
                stream
                    .set_nonblocking(false)
                    .map_err(|_| "host fixture blocking mode")?;
                let request = read_request(&mut stream, deadline)?;
                let body = &request["params"];
                // The public facade resolves and authorizes execution_context
                // before native admission. Count the actual catalog observer
                // methods separately so withdrawal fences ensure's host I/O.
                if body["method"] == "hello"
                    || (body["method"] == "inspect"
                        && matches!(
                            body["payload"]["kind"].as_str(),
                            Some("runtime_sources" | "native_registry")
                        ))
                {
                    observations.fetch_add(1, Ordering::AcqRel);
                }
                let mut state = shared.lock().map_err(|_| "host fixture state")?;
                let mut failure = false;
                let payload = match body["method"].as_str() {
                    Some("hello") => state.hello.clone(),
                    Some("inspect") => match body["payload"]["kind"].as_str() {
                        Some("execution_context") => state.context.clone(),
                        Some("runtime_sources") => {
                            let ordinal = reads.fetch_add(1, Ordering::AcqRel) + 1;
                            if let Some((at, path)) = &state.corrupt_at_source
                                && ordinal == *at
                            {
                                fs::write(path, b"bounded corrupt selected container")
                                    .map_err(|_| "host fixture selected CAS mutation")?;
                            }
                            if let Some(cancelled) = &state.cancel_on_sources
                                && state.cancel_at_source.is_none_or(|at| ordinal == at)
                            {
                                cancelled.store(true, Ordering::Release);
                            }
                            failure = state.fail_sources || state.fail_at_source == Some(ordinal);
                            let mut facts = state.facts.clone();
                            if state.drift_on_sources {
                                facts["registryGeneration"] = json!("8");
                            }
                            facts
                        }
                        Some("native_registry") => registry_payload(&state),
                        Some("world.shape_probe") => {
                            state.shape_probes += 1;
                            return Err("uncaptured snapshot must not probe shape");
                        }
                        Some("world.shape_query") => {
                            state.shape_queries += 1;
                            return Err("uncaptured snapshot must not query geometry");
                        }
                        _ => return Err("unexpected native inspection"),
                    },
                    _ => return Err("unexpected host request"),
                };
                drop(state);
                let result = if failure {
                    json!({"protocolVersion":"0.2.0", "requestId":body["requestId"],
                        "status":"error", "eventSequence":"0",
                        "error":{"code":"SOURCE_FACTS_DRIFT","message":"original fixture source failure",
                            "subjectId":null,"retry":"never","effects":"none_confirmed","evidenceRefs":[]}})
                } else {
                    json!({"protocolVersion":"0.2.0", "requestId":body["requestId"],
                        "status":"ok", "payload":payload, "eventSequence":"0"})
                };
                let response =
                    encode_json(&json!({"jsonrpc":"2.0", "id":request["id"], "result":result}))
                        .map_err(|_| "host fixture response")?;
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                );
                stream
                    .write_all(header.as_bytes())
                    .map_err(|_| "host fixture response header")?;
                stream
                    .write_all(&response)
                    .map_err(|_| "host fixture response body")?;
            }
            Ok(())
        });
        Self {
            address,
            state,
            source_reads,
            catalog_observations,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                assert!(
                    matches!(result, Ok(Ok(()))),
                    "bounded native catalog peer failed"
                );
            }
        }
    }
}
fn read_request(stream: &mut TcpStream, deadline: Instant) -> Result<Value, &'static str> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("host fixture deadline")?;
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|_| "host fixture read timeout")?;
    stream
        .set_write_timeout(Some(remaining))
        .map_err(|_| "host fixture write timeout")?;
    let mut header = zeroize::Zeroizing::new(Vec::new());
    loop {
        let mut byte = [0];
        stream
            .read_exact(&mut byte)
            .map_err(|_| "host fixture header")?;
        header.push(byte[0]);
        if header.len() > 16 * 1024 {
            return Err("host fixture header bound");
        }
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let length = std::str::from_utf8(&header)
        .map_err(|_| "host fixture header encoding")?
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .ok_or("host fixture length")?
        .parse::<usize>()
        .map_err(|_| "host fixture length")?;
    if length > crate::rpc::MAX_CONTROL_BYTES {
        return Err("host fixture body bound");
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .map_err(|_| "host fixture body")?;
    let request = parse_json(&bytes).map_err(|_| "host fixture JSON")?;
    ContractValidator::shared()
        .map_err(|_| "host fixture validator")?
        .validate("HostRequest", &request["params"])
        .map_err(|_| "host fixture request contract")?;
    if request["id"] != request["params"]["requestId"] || request["method"] != "mmmm.host" {
        return Err("host fixture correlation");
    }
    Ok(request)
}
fn registry_payload(state: &PeerState) -> Value {
    let raw = encode_json(&state.registry).unwrap();
    let hex = raw
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    json!({"contextDigest":state.context["contextDigest"], "environment":state.hello["environment"],
        "registryDigest":state.hello["registryDigest"], "registryGeneration":"7",
        "observedFromTick":"10", "observedToTick":"11", "observedAt":"2026-10-14T00:00:00Z",
        "gameVersion":state.hello["gameVersion"], "locale":"en_us", "observationBytesHex":hex})
}

fn container_bytes(is_mod: bool) -> Vec<u8> {
    let mut bytes = b"PK\x05\x06".to_vec();
    bytes.extend_from_slice(&[0; 18]);
    if is_mod {
        bytes[20] = 1;
        bytes.push(b'm');
    }
    bytes
}
fn container_selections() -> Vec<CatalogSourceUseSelection> {
    vec![
        CatalogSourceUseSelection {
            resource_id: ResourceId::new("catalog-game-container").unwrap(),
            role: CatalogSourceUseRole::GameArtifact,
        },
        CatalogSourceUseSelection {
            resource_id: ResourceId::new("catalog-mod-container").unwrap(),
            role: CatalogSourceUseRole::Mod {
                canonical_id: ResourceLocation::new("example:fixture_mod").unwrap(),
                native_id: "fixture_mod".into(),
            },
        },
    ]
}
fn retain_containers(
    root: &Root,
    project: &ProjectId,
    revision: &Sha256Digest,
    approve: bool,
    malformed: bool,
) {
    let budget =
        RequestBudget::new(Duration::from_secs(15), Arc::new(AtomicBool::new(false))).unwrap();
    let digest = crate::daemon_launch::current_executable_digest(budget.deadline()).unwrap();
    let mut factory = ProductionFactory::offline_owned(digest);
    let prepared = PreparedDaemon::open_for_native_source_import(
        root.config(),
        project.clone(),
        &mut factory,
        &budget,
    )
    .unwrap();
    let game = if malformed {
        b"PK\x05\x06".to_vec()
    } else {
        container_bytes(false)
    };
    let mods = container_bytes(true);
    let metadata = |id, bytes: &[u8]| {
        encode_json(&json!({"resourceId":id,
        "sha256":raw_digest(bytes), "mediaType":"application/java-archive", "sizeBytes":bytes.len()})).unwrap()
    };
    let game_metadata = metadata("catalog-game-container", &game);
    let mod_metadata = metadata("catalog-mod-container", &mods);
    let receipt = prepared
        .import_native_sources(&NativeSourceInput {
            project,
            expected_revision: revision,
            documents: &[],
            retained_resources: &[],
            raw_resources: &[
                NativeRawSourceResource {
                    metadata: &game_metadata,
                    bytes: &game,
                },
                NativeRawSourceResource {
                    metadata: &mod_metadata,
                    bytes: &mods,
                },
            ],
        })
        .unwrap();
    if approve {
        let absent = manage_catalog_source_use(
            root.config(),
            project,
            &receipt.project_revision,
            LocalCatalogSourceUseAction::Inspect,
            &budget,
        )
        .unwrap();
        let selected = manage_catalog_source_use(
            root.config(),
            project,
            &receipt.project_revision,
            LocalCatalogSourceUseAction::Replace {
                expected_state_digest: absent.state_digest().clone(),
                selections: container_selections(),
            },
            &budget,
        )
        .unwrap();
        assert_eq!(selected.generation(), 1);
        assert_eq!(selected.selections().len(), 2);
    }
}

struct Fixture {
    service: ApplicationService,
    processor: HostBootstrapProcessor,
    handles: DaemonHandles,
    registries: ProductionRegistries,
    sessions: SessionAuthority,
    principal: AuthenticatedPrincipal,
    context: Value,
    peer: Peer,
    _root: Root,
}
impl Fixture {
    fn new(selected: Option<bool>, complete: bool) -> Self {
        Self::build(selected, complete, None, false, false)
    }
    fn containers(grant: bool, approve: bool) -> Self {
        Self::build(Some(true), true, Some((grant, approve)), false, false)
    }
    fn shapes(containers: bool) -> Self {
        Self::build(
            Some(true),
            true,
            containers.then_some((true, true)),
            true,
            false,
        )
    }
    fn rejected_inventory() -> Self {
        Self::build(Some(true), true, Some((true, true)), false, true)
    }
    fn build(
        selected: Option<bool>,
        complete: bool,
        containers: Option<(bool, bool)>,
        shape_scope: bool,
        malformed: bool,
    ) -> Self {
        let root = Root::new();
        let initialized = {
            let mut store = DurableStore::open(root.config()).unwrap();
            crate::native_project::create_native_project(
                &mut store,
                "Native catalog owner fixture",
                &TargetProfileId::new("unverified-target").unwrap(),
                Instant::now() + Duration::from_secs(15),
            )
            .unwrap()
        };
        let project = initialized.project_id;
        if let Some((_, approve)) = containers {
            retain_containers(
                &root,
                &project,
                &initialized.project_revision,
                approve,
                malformed,
            );
        }
        let executable = std::env::current_exe().unwrap();
        let host_jar = root.0.join("selected-host.jar");
        let config_path = root.0.join("mmmm-host.json");
        let resources = if containers.is_some_and(|(grant, _)| grant) {
            vec!["catalog-game-container", "catalog-mod-container"]
        } else {
            vec![]
        };
        let scope = json!({"projectId":project,"resourceIds":resources,"objectIds":[],
            "regions":if shape_scope { json!([{"contextId":"shape-scope-template","worldId":"world-fixture-01",
                "dimension":"minecraft:overworld","min":[-16,0,-16],"maxExclusive":[16,128,16]}]) } else {json!([])},"externalTargetIds":[]});
        let request = LocalHostSetup {
            executable: &executable,
            installed_host_jar: &host_jar,
            destination: &config_path,
            project: project.clone(),
            scope: scope.clone(),
        };
        let setup = if let Some(observe) = selected {
            register_local_host_setup_with_read_policy(
                root.config(),
                request,
                &HostReadPolicy::new(["survival".to_owned()], observe).unwrap(),
                Instant::now() + Duration::from_secs(15),
            )
            .unwrap()
            .0
        } else {
            register_local_host_setup(root.config(), request).unwrap()
        };
        let mut store = DurableStore::open(root.config()).unwrap();
        let hosts = HostBridge::default();
        let authority = LocalAuthority::new(hosts.clone());
        let workspace = prepare_workspace(
            &store,
            &authority,
            &project,
            Instant::now() + Duration::from_secs(15),
        )
        .unwrap();
        let handles = DaemonHandles {
            hosts: hosts.clone(),
            authority: authority.clone(),
            request: RequestContextSlot::default(),
            calibration: crate::calibration_execution::CalibrationRegistry::default(),
            bootstrap: crate::calibration_bootstrap::BootstrapRegistry::default(),
            configured_project: Some(project.clone()),
            workspace: Some(workspace),
        };
        let mut factory = ProductionFactory::offline_owned(setup.executable_sha256);
        let parts = factory.compose(&handles, &store).unwrap();
        let registries = factory.registries().unwrap().clone();
        let mut processor = HostBootstrapProcessor::new(hosts.clone(), authority.clone()).unwrap();
        let raw =
            json!({"format":"mmmm.native.registry/1","blocks":[],"items":[],"entityTypes":[]});
        let mut hello = parse_json(include_bytes!("../../../examples/host-hello.json")).unwrap();
        hello["hostBuild"] = json!(setup.host_artifact_digest);
        hello["registryDigest"] = json!(canonical_digest(&raw).unwrap());
        hello["loader"]["id"] = json!("fabric");
        let mut action = parse_json(include_bytes!("../../../examples/provider-supported.json"))
            .unwrap()["actions"][0]
            .clone();
        action["implementationDigest"] = json!(setup.host_artifact_digest);
        let peer = Peer::new(hello.clone(), raw);
        let offer = HostOffer::new(PublicFrame::from_value(json!({
            "kind":"host_pairing_offer","protocolVersion":"0.2.0","nonce":"native-catalog-pair",
            "hostArtifactDigest":setup.host_artifact_digest,"principalId":"player-catalog-fixture","playerId":"player-catalog-fixture",
            "hostHello":hello,"dataRoot":root.0,"projectId":project,"scope":scope,
            "playerContext":{"dimension":"minecraft:overworld","executorHandle":"paired-player-fixture",
                "origin":[0,1,0],"rotationDegrees":[0,0],"anchor":"feet"},"nativeActions":[action],
        })).unwrap(), crate::credential::SecretToken::parse(&"b".repeat(64)).unwrap()).unwrap();
        let witness = offer.witness().clone();
        let budget = BootstrapBudget::new();
        let epoch = SessionEpoch::new("native-catalog-coordinator").unwrap();
        let reply = processor
            .handle_with_budget(&mut store, ManagementRequest::Offer(offer), &epoch, &budget)
            .unwrap()
            .unwrap();
        let context = reply.value()["contexts"][0].clone();
        {
            let mut state = peer.state.lock().unwrap();
            state.context = context.clone();
            state.facts = json!({"format":"mmmm.native.source-facts/1","environment":hello["environment"],
                "registryGeneration":"7","observedAt":"2026-10-14T00:00:00Z","archiveReceiptScope":"container_input_bytes",
                "transformedClassBytes":"not_observed","resourceContentEnumeration":"not_performed",
                "archives":[],"mods":[],"originalInputGameJars":[{"status":"unknown","reason":"ORIGINAL_GAME_INPUTS_UNAVAILABLE"}],
                "serverPacks":[{"packIndex":0,"packSourceCompleteness":"unknown","resourceContentObservation":"not_enumerated"}],
                "clientPacks":null,"clientPackObservation":"not_observed"});
        }
        let installed = PublicFrame::from_value(json!({"kind":"host_pairing_installed","protocolVersion":"0.2.0",
            "nonce":"native-catalog-pair","hostEndpoint":{"address":peer.address.to_string(),"path":"/rpc",
                "hostEpoch":hello["environment"]["sessionEpoch"]}})).unwrap();
        processor
            .handle_with_reply_deadline(
                &mut store,
                ManagementRequest::installed(installed, witness.clone()).unwrap(),
                &epoch,
                &budget,
                Instant::now() + Duration::from_secs(10),
            )
            .unwrap();
        let session = if complete {
            let (sender, receiver) = management_channel();
            sender.notify_finished(&witness, true, &budget).unwrap();
            let (finished, responder) = receiver
                .try_receive()
                .unwrap()
                .unwrap()
                .into_parts()
                .unwrap();
            assert!(responder.is_none());
            processor
                .handle_with_budget(&mut store, finished, &epoch, &budget)
                .unwrap();
            processor.current_session_policy().unwrap()
        } else {
            // Session strings are negative input: route observation without a
            // native terminal receipt must never manufacture completion.
            SessionPolicy {
                principal: mmmm_contracts::PrincipalId::new("player-catalog-fixture").unwrap(),
                allowed_methods: [
                    "catalog.capture".into(),
                    "catalog.search".into(),
                    "catalog.describe".into(),
                ]
                .into(),
                allowed_contexts: [ContextId::new(context["contextId"].as_str().unwrap()).unwrap()]
                    .into(),
                lifetime: Duration::from_secs(30),
            }
        };
        let mut sessions = SessionAuthority::new(2).unwrap();
        let token = sessions.install(session).unwrap();
        let principal = sessions.authenticate_token(&token).unwrap();
        let planner = StoreAwarePlanner::new(PlanningComposition {
            request: Box::new(handles.request.clone()),
            authority: authority.clone(),
            hosts: hosts.clone(),
            contexts: parts.contexts,
            data: parts.data,
            backend: parts.backend,
            dependencies: parts.dependencies,
            clock: Box::new(mmmm_application::SystemClock),
            options: parts.planner_options,
        })
        .unwrap();
        let mut extensions = ExtensionRouter::default();
        extensions
            .register(
                ["artifact.read"],
                Box::new(ArtifactExtension::new(parts.artifacts, 32 * 1024 * 1024).unwrap()),
            )
            .unwrap();
        extensions
            .register(
                FEATURE_METHODS.iter().copied(),
                Box::new(FeatureExtension::new(parts.features, hosts).unwrap()),
            )
            .unwrap();
        let mut service = ApplicationService::from_store(
            store,
            ApplicationPorts {
                authority: Box::new(authority),
                planner: Box::new(planner),
                provider: parts.provider,
                observer: parts.observer,
                ids: Box::new(NoIds),
                clock: Box::new(mmmm_application::SystemClock),
            },
        );
        service.bind_request_context(handles.request.clone());
        service.set_extensions(extensions);
        Self {
            service,
            processor,
            handles,
            registries,
            sessions,
            principal,
            context,
            peer,
            _root: root,
        }
    }
    fn budget(&self) -> RequestBudget {
        RequestBudget::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false))).unwrap()
    }
    fn capture(&mut self, budget: &RequestBudget) -> Result<Value, ServiceError> {
        self.service.call(
            &self.principal,
            "catalog.capture",
            &json!({"contextId":self.context["contextId"],
            "sources":[],"environment":self.context["environment"],"kind":"environment_snapshot",
            "loadPolicy":"no_implicit_runtime_mutation"}),
            budget,
        )
    }
    fn describe(&mut self, budget: &RequestBudget) -> Result<Value, ServiceError> {
        self.service.call(
            &self.principal,
            "catalog.describe",
            &json!({
                "contextId":self.context["contextId"],"snapshotId":"snapshot-not-created",
                "kind":"minecraft:block","resourceId":"minecraft:air",
            }),
            budget,
        )
    }
    fn shape(&mut self, snapshot: &Value, budget: &RequestBudget) -> Result<Value, ServiceError> {
        let mut query = parse_json(include_bytes!("../../../examples/shape-query.json")).unwrap();
        query["contextId"] = self.context["contextId"].clone();
        query["snapshotId"] = snapshot["snapshotId"].clone();
        self.service
            .call(&self.principal, "world.shape_query", &query, budget)
    }
    fn state(&self) -> NativeCatalogAdmissionState {
        self.registries
            .catalog
            .native_admission_state(&self.principal, &self.context)
            .unwrap()
    }
    fn observe_containers(&self) {
        let mut state = self.peer.state.lock().unwrap();
        let receipt = |is_mod, scope| {
            let bytes = container_bytes(is_mod);
            let hash = raw_digest(&bytes);
            json!({"status":"observed", "sourceId":format!("archive-sha256-{hash}"),
                "sha256":hash,"sizeBytes":bytes.len(),"scope":scope})
        };
        state.facts["archives"] = json!([
            receipt(false, "container_input_bytes"),
            receipt(true, "container_input_bytes")
        ]);
        let mut original = receipt(false, "original_game_input_container");
        original["inputIndex"] = json!(0);
        state.facts["originalInputGameJars"] = json!([original]);
        state.facts["mods"] = json!([{"modId":"fixture_mod", "runtimeRoots":[receipt(true, "container_input_bytes")]}]);
    }
    fn container_path(&self, is_mod: bool) -> PathBuf {
        let hash = raw_digest(&container_bytes(is_mod));
        self._root
            .0
            .join("blobs")
            .join(&hash.as_str()[..2])
            .join(&hash.as_str()[2..])
    }
    fn withdraw_containers(&mut self) -> CatalogSourceUseSnapshot {
        assert!(self.handles.request.current().is_err());
        let budget = self.budget();
        let project = ProjectId::new(self.context["projectId"].as_str().unwrap()).unwrap();
        let game_principal = self.principal.principal().clone();
        let store = self.service.management_store();
        let permit = EmptyOwnerWithdrawal::new(store, &project, budget);
        assert_ne!(permit.owner.principal(), &game_principal);
        let before = catalog_source_use::inspect_catalog_source_use_state(
            store,
            &permit,
            &project,
            &permit.revision,
        )
        .unwrap();
        assert_eq!(before.selections().len(), 2);
        let after = catalog_source_use::replace_catalog_source_uses(
            store,
            &permit,
            &CatalogSourceUseReplace {
                project: &project,
                expected_project_revision: &permit.revision,
                expected_state_digest: before.state_digest(),
                selections: &[],
            },
        )
        .unwrap();
        assert_eq!(after.generation(), before.generation() + 1);
        assert!(after.selections().is_empty());
        after
    }
}

#[test]
fn fn23_does_not_publish_a_missing_source_or_accept_a_guessed_snapshot() {
    let mut fixture = Fixture::shapes(false);
    let before = fixture.peer.catalog_observations.load(Ordering::Acquire);
    let guessed = json!({"snapshotId":"snapshot-not-issued"});
    assert!(fixture.shape(&guessed, &fixture.budget()).is_err());
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Missing
    ));
    assert_eq!(fixture.peer.source_reads.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture.peer.catalog_observations.load(Ordering::Acquire),
        before
    );
    let state = fixture.peer.state.lock().unwrap();
    assert_eq!((state.shape_probes, state.shape_queries), (0, 0));
}

#[test]
fn fn23_native_publication_with_unknown_identity_does_not_create_a_usable_snapshot() {
    // 현재 producer가 game artifact 또는 ordered pack stack을 입증하지 못하면
    // registry 선택만으로도 capture는 거절된다. offline snapshot을 game pin으로
    // 바꾸지 않으며, mode/neighbor/probe 후 취소/마지막 hello 경계에는 도달하지 않는다.
    for containers in [false, true] {
        let mut fixture = Fixture::shapes(containers);
        if containers {
            fixture.observe_containers();
        }
        assert_eq!(
            fixture.capture(&fixture.budget()).unwrap_err().code,
            "SOURCE_UNAVAILABLE"
        );
        let publication = match fixture.state() {
            NativeCatalogAdmissionState::Native(publication) => publication,
            _ => {
                panic!("actual native source publication must precede incomplete capture rejection")
            }
        };
        let before = fixture.peer.catalog_observations.load(Ordering::Acquire);
        // FN23 admission의 실제 local source-use checkpoint는 통과해야 한다.
        // catalog-only 잔여 검사가 있으면 원 publication을 퇴역시켜 아래서 잡힌다.
        assert_eq!(
            fixture
                .shape(
                    &json!({"snapshotId":"snapshot-not-issued"}),
                    &fixture.budget()
                )
                .unwrap_err()
                .code,
            "PERMISSION_REQUIRED"
        );
        assert_eq!(
            fixture.peer.catalog_observations.load(Ordering::Acquire),
            before
        );
        let after = match fixture.state() {
            NativeCatalogAdmissionState::Native(publication) => publication,
            _ => panic!(
                "an uncaptured snapshot read must not issue or retire a still-current native publication"
            ),
        };
        assert_eq!(publication.read_policy(), after.read_policy());
        assert_eq!(publication.source_use(), after.source_use());
        let state = fixture.peer.state.lock().unwrap();
        assert_eq!((state.shape_probes, state.shape_queries), (0, 0));
    }
}

// The cold CLI cannot acquire a second Store lock while this fixture retains
// its live game publisher. Exercise the actual protected storage transition in
// that same held Store with a freshly captured native owner. This permit can
// only inspect or explicitly withdraw the complete set; it grants no game
// principal, resource bytes, new selection, source or host permission.
struct EmptyOwnerWithdrawal {
    owner: NativeOwnerWitness,
    budget: RequestBudget,
    project: ProjectId,
    revision: Sha256Digest,
    document: Value,
    policy: Value,
    policy_resource: RegisteredProjectResource,
}
impl EmptyOwnerWithdrawal {
    fn new(store: &DurableStore, project: &ProjectId, budget: RequestBudget) -> Self {
        let owner = NativeOwnerWitness::capture(store, budget.deadline()).unwrap();
        owner.check_project(store, project).unwrap();
        let revision = Sha256Digest::new(
            store.project(project).unwrap()["revision"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let mut reader = native_owner_resource_reader(
            &owner,
            project,
            &revision,
            BTreeSet::new(),
            8 * 1024 * 1024,
        )
        .unwrap();
        let document = reader
            .read_project(store, &owner, project, &revision, 8 * 1024 * 1024)
            .unwrap();
        let policy_id = ResourceId::new(document["policyResourceId"].as_str().unwrap()).unwrap();
        let mut reader = native_owner_resource_reader(
            &owner,
            project,
            &revision,
            BTreeSet::from([policy_id.clone()]),
            8 * 1024 * 1024,
        )
        .unwrap();
        let query = ProjectResourceQuery::Current {
            resource_id: policy_id,
        };
        let request = ProjectResourceRequest {
            project,
            current_project_revision: &revision,
            query: &query,
            expected: None,
        };
        let policy_resource = reader.metadata(store, &owner, &request).unwrap();
        let bytes = reader
            .read(
                store,
                &owner,
                &ProjectResourceRequest {
                    expected: Some(&policy_resource.resource),
                    ..request
                },
                8 * 1024 * 1024,
            )
            .unwrap()
            .bytes;
        let policy = ContractValidator::shared()
            .unwrap()
            .parse_and_validate("Policy", &bytes)
            .unwrap();
        Self {
            owner,
            budget,
            project: project.clone(),
            revision,
            document,
            policy,
            policy_resource,
        }
    }
}
impl ProjectSourceRpcContext for EmptyOwnerWithdrawal {
    fn check(&self) -> StorageResult<()> {
        self.budget
            .check()
            .map_err(|cause| StorageError::InvalidTransition(cause.code.into()))?;
        self.owner.check()
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.owner.principal().clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        None
    }
}
impl CatalogSourceUsePermit for EmptyOwnerWithdrawal {
    fn check_store(&self, store: &DurableStore) -> StorageResult<()> {
        self.check()?;
        self.owner.check_project(store, &self.project)?;
        self.check()
    }
    fn authenticated_native_owner(
        &self,
        store: &DurableStore,
        project: &ProjectId,
    ) -> StorageResult<PrincipalId> {
        self.check_store(store)?;
        if project != &self.project {
            return Err(StorageError::Conflict("Exact withdrawal Project"));
        }
        Ok(self.owner.principal().clone())
    }
    fn authorize_current(
        &self,
        store: &DurableStore,
        current: &CatalogSourceUseCurrent<'_>,
    ) -> StorageResult<()> {
        self.check_store(store)?;
        if !matches!(
            current.action,
            CatalogSourceUseAction::Inspect | CatalogSourceUseAction::Replace
        ) || !current.selections.is_empty()
            || current.native_owner != self.owner.principal()
            || current.project != &self.document
            || current.policy != &self.policy
            || current.policy_resource.resource != self.policy_resource.resource
            || current.policy_resource.blob != self.policy_resource.blob
            || current.policy_resource.owner != self.policy_resource.owner
        {
            return Err(StorageError::Conflict(
                "Actual native owner empty withdrawal only",
            ));
        }
        self.check_store(store)
    }
    fn resource_reader(&self, ceiling: u64) -> StorageResult<ProjectResourceReader> {
        self.check()?;
        native_owner_resource_reader(
            &self.owner,
            &self.project,
            &self.revision,
            BTreeSet::from([
                ResourceId::new(self.document["policyResourceId"].as_str().unwrap()).unwrap(),
            ]),
            ceiling,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.processor.shutdown().unwrap();
    }
}
struct NoIds;
impl mmmm_application::IdSource for NoIds {
    fn next_id(&mut self, _: mmmm_application::IdKind) -> AppResult<String> {
        panic!("Native catalog read cannot allocate application IDs")
    }
}

#[test]
fn real_admission_breaks_the_initial_access_cycle_but_does_not_complete_unknown_identity() {
    let mut fixture = Fixture::new(Some(true), true);
    let budget = fixture.budget();
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Missing
    ));
    assert_eq!(
        fixture.capture(&budget).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    assert!(fixture.peer.source_reads.load(Ordering::Acquire) >= 3);
    let NativeCatalogAdmissionState::Native(first) = fixture.state() else {
        panic!("actual native source missing");
    };
    let id = ContextId::new(fixture.context["contextId"].as_str().unwrap()).unwrap();
    let sources = fixture
        .registries
        .catalog
        .source_refs(&fixture.principal, &id, &budget)
        .unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0]["kind"], "runtime_observation");
    assert_eq!(sources[0]["rights"], "user_local_only");
    assert!(sources[0]["sha256"].is_null());
    assert_eq!(
        fixture.capture(&budget).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    let NativeCatalogAdmissionState::Native(second) = fixture.state() else {
        panic!("native source retired unexpectedly");
    };
    // Private exact-receipt retirement is also tested below without depending
    // on the source revision's serialization or observation timestamp.
    fixture
        .registries
        .catalog
        .retire_native_publication(&first)
        .unwrap();
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Missing
    ));
    fixture
        .registries
        .catalog
        .retire_native_publication(&second)
        .unwrap();
}

#[test]
fn retained_containers_and_native_observation_do_not_implicitly_select_sources() {
    let mut fixture = Fixture::containers(true, false);
    fixture.observe_containers();
    let budget = fixture.budget();
    assert_eq!(
        fixture.capture(&budget).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    let id = ContextId::new(fixture.context["contextId"].as_str().unwrap()).unwrap();
    let sources = fixture
        .registries
        .catalog
        .source_refs(&fixture.principal, &id, &budget)
        .unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0]["kind"], "runtime_observation");
}

#[test]
fn protected_selection_does_not_replace_the_actual_game_resource_scope() {
    let mut fixture = Fixture::containers(false, true);
    fixture.observe_containers();
    let budget = fixture.budget();
    assert_eq!(
        fixture.capture(&budget).unwrap_err().code,
        "PERMISSION_REQUIRED"
    );
    assert_eq!(fixture.peer.source_reads.load(Ordering::Acquire), 0);
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Missing
    ));
    // 동일 FN31/SQLite 경로에서 registry가 busy여도 독립적인 실제 resource
    // grant만 먼저 소비한다. 이 검사는 opaque shape receipt를 위조하지 않는다.
    let request = |context: &Value| {
        json!({"contextId":context["contextId"],
        "resourceId":"catalog-game-container","offset":"0","limitBytes":65536})
    };
    let products = fixture.registries.products.clone();
    let busy = products.borrow_mut();
    let read_budget = fixture.budget();
    assert_eq!(
        fixture
            .service
            .call(
                &fixture.principal,
                "artifact.read",
                &request(&fixture.context),
                &read_budget
            )
            .unwrap_err()
            .code,
        "SOURCE_BUSY"
    );
    drop(busy);
    let mut granted = Fixture::containers(true, true);
    granted.observe_containers();
    let granted_budget = granted.budget();
    assert_eq!(
        granted.capture(&granted_budget).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    assert!(matches!(
        granted.state(),
        NativeCatalogAdmissionState::Native(_)
    ));
    granted.withdraw_containers();
    let products = granted.registries.products.clone();
    let _busy = products.borrow_mut();
    let read_budget = granted.budget();
    let result = granted
        .service
        .call(
            &granted.principal,
            "artifact.read",
            &request(&granted.context),
            &read_budget,
        )
        .unwrap();
    assert_eq!(result["resource"]["resourceId"], "catalog-game-container");
    assert_eq!(
        result["resource"]["sha256"],
        raw_digest(&container_bytes(false)).as_str()
    );
    assert_eq!(
        result["resource"]["sizeBytes"],
        container_bytes(false).len()
    );
    assert!(!result["data"].as_str().unwrap().is_empty());
}

#[test]
fn protected_whole_containers_share_the_native_publisher_but_leave_both_pack_stacks_unknown() {
    let mut fixture = Fixture::containers(true, true);
    fixture.observe_containers();
    // 아래 capture/source_refs/capture는 독립 호출이다. 같은 10초 한도를
    // 호출마다 취득하며 원 요청 안의 취소·deadline 검사는 변경하지 않는다.
    assert_eq!(
        fixture.capture(&fixture.budget()).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    let NativeCatalogAdmissionState::Native(original) = fixture.state() else {
        panic!("native publication required")
    };
    let facts = fixture
        .registries
        .catalog
        .input_archive_test_facts()
        .unwrap();
    assert_eq!(facts.len(), 2);
    for fact in &facts {
        let manifest = inventory_json(&mut fixture, &fact["manifest"]);
        assert_eq!(manifest["inventory"]["status"], "complete");
        assert_eq!(manifest["inventory"]["memberCount"], 0);
        assert_eq!(manifest["inventory"]["decodedBytes"], 0);
        assert_eq!(manifest["memberPages"], json!([]));
        assert_eq!(manifest["inputSha256"], fact["input"]["sha256"]);
        let provenance = inventory_json(&mut fixture, &manifest["provenance"]);
        assert_eq!(provenance["sourceUsePin"], original.source_use().as_str());
        assert_eq!(provenance["readPolicyPin"], original.read_policy().as_str());
        assert_eq!(provenance["sourceUse"]["generation"], 1);
        assert_eq!(
            provenance["sourceUse"]["selections"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(provenance["scope"], "selected_input_container_bytes");
    }
    let id = ContextId::new(fixture.context["contextId"].as_str().unwrap()).unwrap();
    let sources = fixture
        .registries
        .catalog
        .source_refs(&fixture.principal, &id, &fixture.budget())
        .unwrap();
    assert_eq!(sources.len(), 3);
    for is_mod in [false, true] {
        let hash = raw_digest(&container_bytes(is_mod));
        let matching = sources
            .iter()
            .filter(|source| source["sha256"] == hash.as_str())
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0]["kind"], "user_file");
        assert_eq!(matching[0]["rights"], "user_local_only");
    }
    assert_eq!(
        fixture.capture(&fixture.budget()).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    let NativeCatalogAdmissionState::Native(current) = fixture.state() else {
        panic!("native publication required")
    };
    assert_eq!(current.source_use(), original.source_use());
    assert_eq!(current.read_policy(), original.read_policy());
    fixture
        .registries
        .catalog
        .retire_native_publication(&original)
        .unwrap();
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Missing
    ));
    assert!(
        fixture
            .registries
            .catalog
            .input_archive_test_facts()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn protected_empty_withdrawal_fences_the_old_publication_before_host_io_and_exact_retirement() {
    let mut fixture = Fixture::containers(true, true);
    fixture.observe_containers();
    assert_eq!(
        fixture.capture(&fixture.budget()).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    let NativeCatalogAdmissionState::Native(original) = fixture.state() else {
        panic!("native publication required")
    };
    let project = ProjectId::new(fixture.context["projectId"].as_str().unwrap()).unwrap();
    let before = fixture
        .service
        .management_store()
        .project(&project)
        .unwrap();
    let withdrawn = fixture.withdraw_containers();
    assert_eq!(withdrawn.generation(), 2);
    assert_eq!(
        fixture
            .service
            .management_store()
            .project(&project)
            .unwrap(),
        before
    );
    let reads = fixture.peer.catalog_observations.load(Ordering::Acquire);
    assert_eq!(
        fixture.capture(&fixture.budget()).unwrap_err().code,
        "TARGET_DRIFT"
    );
    assert_eq!(
        fixture.peer.catalog_observations.load(Ordering::Acquire),
        reads
    );
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Missing
    ));
    // A later explicit request may issue a registry-only publication under the
    // durable tombstone. The old receipt must leave that new owner untouched.
    assert_eq!(
        fixture.capture(&fixture.budget()).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    let id = ContextId::new(fixture.context["contextId"].as_str().unwrap()).unwrap();
    let sources = fixture
        .registries
        .catalog
        .source_refs(&fixture.principal, &id, &fixture.budget())
        .unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0]["kind"], "runtime_observation");
    fixture
        .registries
        .catalog
        .retire_native_publication(&original)
        .unwrap();
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Native(_)
    ));
}

#[test]
fn selected_container_corruption_at_host_io_retires_only_native_receipt_and_preserves_host_error() {
    let mut fixture = Fixture::containers(true, true);
    fixture.observe_containers();
    assert_eq!(
        fixture.capture(&fixture.budget()).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    let NativeCatalogAdmissionState::Native(original) = fixture.state() else {
        panic!("native publication required")
    };
    let ordinal = fixture.peer.source_reads.load(Ordering::Acquire) + 1;
    {
        let mut state = fixture.peer.state.lock().unwrap();
        state.corrupt_at_source = Some((ordinal, fixture.container_path(false)));
        state.fail_at_source = Some(ordinal);
    }
    let error = fixture.capture(&fixture.budget()).unwrap_err();
    assert_eq!(error.code, "HOST_REQUEST_FAILED");
    let app = std::error::Error::source(&error)
        .unwrap()
        .downcast_ref::<AppError>()
        .unwrap();
    let both = std::error::Error::source(app)
        .unwrap()
        .downcast_ref::<NativePairingOwnerFailure>()
        .unwrap();
    assert_eq!(both.primary.code, "HOST_REQUEST_FAILED");
    assert_eq!(both.checkpoint.code, "SOURCE_UNAVAILABLE");
    let original_host = std::error::Error::source(&both.primary)
        .unwrap()
        .downcast_ref::<NativeCatalogHostFailure>()
        .unwrap();
    assert_eq!(
        original_host.response["error"]["code"],
        "SOURCE_FACTS_DRIFT"
    );
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Missing
    ));
    fixture
        .registries
        .catalog
        .retire_native_publication(&original)
        .unwrap();
}

#[test]
fn missing_policy_shape_only_policy_and_incomplete_pairing_never_read_or_issue_sources() {
    for (selected, complete) in [(None, true), (Some(false), true), (Some(true), false)] {
        let mut fixture = Fixture::new(selected, complete);
        let budget = fixture.budget();
        assert!(fixture.capture(&budget).is_err());
        assert_eq!(fixture.peer.source_reads.load(Ordering::Acquire), 0);
        assert!(matches!(
            fixture.state(),
            NativeCatalogAdmissionState::Missing
        ));
    }
}

#[test]
fn cancellation_and_source_drift_retire_only_the_existing_native_publication() {
    for cancel in [true, false] {
        let mut fixture = Fixture::new(Some(true), true);
        let budget = fixture.budget();
        assert_eq!(
            fixture.capture(&budget).unwrap_err().code,
            "SOURCE_UNAVAILABLE"
        );
        let next = fixture.budget();
        {
            let mut state = fixture.peer.state.lock().unwrap();
            if !cancel {
                state.drift_on_sources = true;
            }
        }
        if cancel {
            // Use the exact request cancellation owner, not a newly copied flag.
            let cancellation = Arc::new(AtomicBool::new(false));
            fixture.peer.state.lock().unwrap().cancel_on_sources = Some(cancellation.clone());
            let cancelled = RequestBudget::new(Duration::from_secs(10), cancellation).unwrap();
            assert_eq!(fixture.capture(&cancelled).unwrap_err().code, "CANCELLED");
        } else {
            assert_eq!(fixture.capture(&next).unwrap_err().code, "TARGET_DRIFT");
        }
        assert!(matches!(
            fixture.state(),
            NativeCatalogAdmissionState::Missing
        ));
    }
}

#[test]
fn every_existing_native_access_rechecks_current_completion_route_and_method() {
    let mut fixture = Fixture::new(Some(true), true);
    let budget = fixture.budget();
    assert_eq!(
        fixture.capture(&budget).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    fixture.processor.shutdown().unwrap();
    let before = fixture.peer.source_reads.load(Ordering::Acquire);
    assert!(fixture.capture(&fixture.budget()).is_err());
    assert_eq!(fixture.peer.source_reads.load(Ordering::Acquire), before);
    fixture.sessions.revoke_all();
    assert_eq!(
        fixture.capture(&fixture.budget()).unwrap_err().code,
        "PERMISSION_REQUIRED"
    );
    assert!(fixture.handles.request.current().is_err());
}

fn explicit_native_registration(context: &Value) -> CatalogEnvironmentRegistration {
    CatalogEnvironmentRegistration {
        context: context.clone(),
        game_version: Some("26.3".into()),
        locale: Some("en_us".into()),
        artifact_source: None,
        server_pack_sources: None,
        client_pack_sources: None,
        mod_sources: None,
        registry_generation: Some("7".into()),
        native_mod_ids: BTreeMap::new(),
        sources: vec![CatalogSourceRegistration {
            source: json!({"sourceId":"explicit-native-registry", "kind":"runtime_observation",
                "locator":"mmmm-host://explicit/registry","sha256":null,"rights":"user_local_only",
                "verifiedAt":"2026-10-14T00:00:00Z"}),
            layer: CatalogLayer::EnvironmentSnapshot,
            role: CatalogSourceRole::CatalogData,
            codec: CatalogSourceCodec::NativeRegistry,
            backing: CatalogSourceBacking::NativeRegistry,
        }],
    }
}

// 같은 보호 Store에서 이미 보존된 사실만 관리용으로 확인한다. 이 helper는
// wire read ACL 또는 source/target authority를 발급하지 않는다.
fn inventory_json(fixture: &mut Fixture, reference: &Value) -> Value {
    let blob = mmmm_runtime::storage::BlobRef {
        digest: Sha256Digest::new(reference["sha256"].as_str().unwrap()).unwrap(),
        byte_length: reference["sizeBytes"].as_u64().unwrap(),
    };
    assert!(blob.byte_length <= 256 * 1024);
    let bytes = fixture.service.management_store().read_blob(&blob).unwrap();
    assert_eq!(raw_digest(&bytes), blob.digest);
    parse_json(&bytes).unwrap()
}

#[test]
fn rejected_input_inventory_keeps_raw_source_and_independent_artifact_authority() {
    // 기존 empty ZIP는 structural rejection을 만들 수 없다. 같은 import/owner/
    // source-use fixture에 header만 있는 자체 작성 입력을 추가하며 게임 자료는 없다.
    let mut fixture = Fixture::rejected_inventory();
    fixture.observe_containers();
    assert_eq!(
        fixture.capture(&fixture.budget()).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Native(_)
    ));
    let facts = fixture
        .registries
        .catalog
        .input_archive_test_facts()
        .unwrap();
    assert_eq!(facts.len(), 2);
    let rejected = facts
        .iter()
        .find(|fact| fact["input"]["resourceId"] == "catalog-game-container")
        .unwrap();
    assert_eq!(rejected["inventory"]["status"], "rejected");
    assert_eq!(rejected["inventory"]["code"], "INPUT_ARCHIVE_TRUNCATED");
    let manifest = inventory_json(&mut fixture, &rejected["manifest"]);
    assert_eq!(manifest["inventory"]["complete"], false);
    assert_eq!(manifest["memberPages"], json!([]));
    let budget = fixture.budget();
    let result = fixture
        .service
        .call(
            &fixture.principal,
            "artifact.read",
            &json!({"contextId":fixture.context["contextId"],"resourceId":"catalog-game-container",
            "offset":"0","limitBytes":65536}),
            &budget,
        )
        .unwrap();
    assert_eq!(
        result["resource"]["sha256"],
        raw_digest(b"PK\x05\x06").as_str()
    );
    assert_eq!(result["resource"]["sizeBytes"], 4);
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Native(_)
    ));
    fixture.withdraw_containers();
    assert!(fixture.capture(&fixture.budget()).is_err());
    assert!(
        fixture
            .registries
            .catalog
            .input_archive_test_facts()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn describe_rechecks_existing_native_issuance_but_cannot_issue_a_missing_source() {
    let mut fixture = Fixture::new(Some(true), true);
    // Each service call is an independent request with its own unchanged
    // ten-second limit. Sharing one absolute deadline would time the sequence.
    assert_eq!(
        fixture.describe(&fixture.budget()).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    assert_eq!(fixture.peer.source_reads.load(Ordering::Acquire), 0);
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Missing
    ));
    assert_eq!(
        fixture.capture(&fixture.budget()).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    let before = fixture.peer.source_reads.load(Ordering::Acquire);
    assert!(fixture.describe(&fixture.budget()).is_err());
    assert!(fixture.peer.source_reads.load(Ordering::Acquire) >= before + 2);
    fixture.peer.state.lock().unwrap().drift_on_sources = true;
    assert_eq!(
        fixture.describe(&fixture.budget()).unwrap_err().code,
        "TARGET_DRIFT"
    );
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Missing
    ));
}

#[test]
fn publisher_conflict_and_exact_retirement_preserve_other_registration_owners() {
    let mut fixture = Fixture::new(Some(true), true);
    // 각 capture/register는 독립 호출이며 기존 10초 budget을 새로 취득한다.
    assert_eq!(
        fixture.capture(&fixture.budget()).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    let NativeCatalogAdmissionState::Native(old) = fixture.state() else {
        panic!("native publisher required");
    };
    let explicit = explicit_native_registration(&fixture.context);
    let budget = fixture.budget();
    assert_eq!(
        fixture
            .registries
            .catalog
            .register(
                &fixture.principal,
                &budget,
                fixture.service.management_store(),
                explicit.clone()
            )
            .unwrap_err()
            .code,
        "SOURCE_CONFLICT"
    );
    let id = ContextId::new(fixture.context["contextId"].as_str().unwrap()).unwrap();
    fixture
        .registries
        .catalog
        .revoke(&fixture.principal, &id)
        .unwrap();
    assert_eq!(
        fixture.capture(&fixture.budget()).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    fixture
        .registries
        .catalog
        .retire_native_publication(&old)
        .unwrap();
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Native(_)
    ));
    fixture
        .registries
        .catalog
        .revoke(&fixture.principal, &id)
        .unwrap();
    let budget = fixture.budget();
    fixture
        .registries
        .catalog
        .register(
            &fixture.principal,
            &budget,
            fixture.service.management_store(),
            explicit,
        )
        .unwrap();
    fixture
        .registries
        .catalog
        .retire_native_publication(&old)
        .unwrap();
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Explicit
    ));
}

#[test]
fn explicit_composition_keeps_its_separate_rights_path_without_a_d032_policy() {
    let mut fixture = Fixture::new(None, true);
    let budget = fixture.budget();
    // This is the pre-existing trusted explicit setup API, not the new issuer
    // or an RPC approval. It isolates the required compatibility boundary.
    fixture
        .registries
        .catalog
        .register(
            &fixture.principal,
            &budget,
            fixture.service.management_store(),
            explicit_native_registration(&fixture.context),
        )
        .unwrap();
    assert_eq!(
        fixture.capture(&budget).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    assert_eq!(fixture.peer.source_reads.load(Ordering::Acquire), 1);
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Explicit
    ));
}

#[test]
fn actual_host_failure_survives_the_new_admission_boundary_without_issuing_a_source() {
    let mut fixture = Fixture::new(Some(true), true);
    let budget = fixture.budget();
    fixture.peer.state.lock().unwrap().fail_sources = true;
    let error = fixture.capture(&budget).unwrap_err();
    assert_eq!(error.code, "HOST_REQUEST_FAILED");
    let app = std::error::Error::source(&error)
        .unwrap()
        .downcast_ref::<AppError>()
        .unwrap();
    let failure = std::error::Error::source(app)
        .unwrap()
        .downcast_ref::<NativeCatalogHostFailure>()
        .unwrap();
    assert_eq!(failure.response["error"]["code"], "SOURCE_FACTS_DRIFT");
    assert_eq!(
        failure.response["error"]["message"],
        "original fixture source failure"
    );
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Missing
    ));
}

#[test]
fn subsequent_capture_host_failure_and_native_postcheck_survive_the_facade_together() {
    // 동일 원 요청에서 inventory가 먼저 보존된 경우도 실제 native postcheck의
    // 취소/retirement가 새 current cache를 남기지 않는지 확인한다.
    let mut fixture = Fixture::containers(true, true);
    fixture.observe_containers();
    let cancellation = Arc::new(AtomicBool::new(false));
    let budget = RequestBudget::new(Duration::from_secs(10), cancellation.clone()).unwrap();
    {
        let mut state = fixture.peer.state.lock().unwrap();
        // The admission's two source facts observations succeed. The existing
        // capture backend's subsequent source read returns the original error
        // and ends the same request, exercising its call-scoped postcheck.
        state.cancel_on_sources = Some(cancellation);
        state.cancel_at_source = Some(3);
        state.fail_at_source = Some(3);
    }
    let error = fixture.capture(&budget).unwrap_err();
    assert_eq!(error.code, "SOURCE_UNAVAILABLE");
    let catalog = std::error::Error::source(&error)
        .unwrap()
        .downcast_ref::<mmmm_reference::CatalogError>()
        .unwrap();
    let both = std::error::Error::source(catalog)
        .unwrap()
        .downcast_ref::<crate::catalog_source::NativeCatalogInspectionFailure>()
        .unwrap();
    assert_eq!(both.primary.code(), "SOURCE_UNAVAILABLE");
    assert_eq!(both.checkpoint.code, "CANCELLED");
    let original = std::error::Error::source(both.primary.as_ref())
        .unwrap()
        .downcast_ref::<NativeCatalogHostFailure>()
        .unwrap();
    assert_eq!(original.response["error"]["code"], "SOURCE_FACTS_DRIFT");
    assert_eq!(fixture.peer.source_reads.load(Ordering::Acquire), 3);
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Missing
    ));
    assert!(
        fixture
            .registries
            .catalog
            .input_archive_test_facts()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn opaque_host_failure_and_later_cancellation_keep_both_original_causes() {
    let response =
        json!({"status":"error","error":{"code":"SOURCE_FACTS_DRIFT","data":{"marker":"private"}}});
    let primary = AppError::caused_by(
        "HOST_REQUEST_FAILED",
        "Actual native catalog inspection failed",
        NativeCatalogHostFailure {
            response: response.clone(),
        },
    );
    let result: AppResult<()> = combine(
        Err(primary),
        Err(AppError::new("CANCELLED", "Request was cancelled")),
    );
    let error = result.unwrap_err();
    assert_eq!(error.code, "HOST_REQUEST_FAILED");
    let both = std::error::Error::source(&error)
        .unwrap()
        .downcast_ref::<NativePairingOwnerFailure>()
        .unwrap();
    assert_eq!(both.checkpoint.code, "CANCELLED");
    let host = std::error::Error::source(&both.primary)
        .unwrap()
        .downcast_ref::<NativeCatalogHostFailure>()
        .unwrap();
    assert_eq!(host.response, response);
    assert!(!format!("{host:?} {host}").contains("private"));
}

//! New fixtures are needed for the first operational native source issuer:
//! actual kernel-owned Project/Store/setup, entered service request and bounded
//! TCP host replies exercise that composition. The peer and tiny host JAR are
//! fixtures, not actual game, compatibility, pack or target-profile evidence.

use super::*;
use crate::{
    auth::{SessionAuthority, SessionPolicy},
    bootstrap::HostBootstrapProcessor,
    daemon::{DaemonHandles, DaemonSourceFactory},
    features::{FEATURE_METHODS, FeatureExtension},
    local_setup::{
        LocalHostSetup, register_local_host_setup, register_local_host_setup_with_read_policy,
    },
    peer_management::{
        BootstrapBudget, HostOffer, ManagementRequest, PublicFrame, management_channel,
    },
    planning_source::{PlanningComposition, StoreAwarePlanner},
    production_factory::{ProductionFactory, ProductionRegistries},
    service::{
        ApplicationPorts, ApplicationService, ExtensionRouter, ServiceDispatcher, ServiceError,
    },
    workspace_bootstrap::prepare_workspace,
};
use mmmm_contracts::{SessionEpoch, TargetProfileId};
use mmmm_runtime::storage::{StoreConfig, host_setup::HostReadPolicy};
use std::{
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
}
struct Peer {
    address: SocketAddr,
    state: Arc<Mutex<PeerState>>,
    source_reads: Arc<AtomicUsize>,
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
        }));
        let source_reads = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let shared = state.clone();
        let reads = source_reads.clone();
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
                let state = shared.lock().map_err(|_| "host fixture state")?;
                let mut failure = false;
                let payload = match body["method"].as_str() {
                    Some("hello") => state.hello.clone(),
                    Some("inspect") => match body["payload"]["kind"].as_str() {
                        Some("execution_context") => state.context.clone(),
                        Some("runtime_sources") => {
                            let ordinal = reads.fetch_add(1, Ordering::AcqRel) + 1;
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
        let root = Root::new();
        let project = {
            let mut store = DurableStore::open(root.config()).unwrap();
            crate::native_project::create_native_project(
                &mut store,
                "Native catalog owner fixture",
                &TargetProfileId::new("unverified-target").unwrap(),
                Instant::now() + Duration::from_secs(15),
            )
            .unwrap()
            .project_id
        };
        let executable = std::env::current_exe().unwrap();
        let host_jar = root.0.join("selected-host.jar");
        let config_path = root.0.join("mmmm-host.json");
        let scope = json!({"projectId":project,"resourceIds":[],"objectIds":[],"regions":[],"externalTargetIds":[]});
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
    fn state(&self) -> NativeCatalogAdmissionState {
        self.registries
            .catalog
            .native_admission_state(&self.principal, &self.context)
            .unwrap()
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

#[test]
fn describe_rechecks_existing_native_issuance_but_cannot_issue_a_missing_source() {
    let mut fixture = Fixture::new(Some(true), true);
    let budget = fixture.budget();
    assert_eq!(
        fixture.describe(&budget).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    assert_eq!(fixture.peer.source_reads.load(Ordering::Acquire), 0);
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Missing
    ));
    assert_eq!(
        fixture.capture(&budget).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    let before = fixture.peer.source_reads.load(Ordering::Acquire);
    assert!(fixture.describe(&budget).is_err());
    assert!(fixture.peer.source_reads.load(Ordering::Acquire) >= before + 2);
    fixture.peer.state.lock().unwrap().drift_on_sources = true;
    assert_eq!(fixture.describe(&budget).unwrap_err().code, "TARGET_DRIFT");
    assert!(matches!(
        fixture.state(),
        NativeCatalogAdmissionState::Missing
    ));
}

#[test]
fn publisher_conflict_and_exact_retirement_preserve_other_registration_owners() {
    let mut fixture = Fixture::new(Some(true), true);
    let budget = fixture.budget();
    assert_eq!(
        fixture.capture(&budget).unwrap_err().code,
        "SOURCE_UNAVAILABLE"
    );
    let NativeCatalogAdmissionState::Native(old) = fixture.state() else {
        panic!("native publisher required");
    };
    let explicit = explicit_native_registration(&fixture.context);
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
        fixture.capture(&budget).unwrap_err().code,
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
    let mut fixture = Fixture::new(Some(true), true);
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

//! Actual owned SQLite and canonical example fixtures exercise admission and
//! rollback. These tests do not authenticate a real game or certify its profile.

use super::*;
use crate::peer_management::management_channel;
use mmmm_application::{Access, AuthorityPort};
use mmmm_contracts::{parse_json, verify_projected_digest};
use mmmm_runtime::storage::StoreConfig;
use std::{
    cell::RefCell,
    fs,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const OWNER_MARKER: &[u8] = b"mmmm-bootstrap-fixture-v1\n";
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = parent.join(format!(
            "mmmm-bootstrap-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(path.is_absolute());
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert!(!path.starts_with(repo));
        assert!(!path.exists());
        Self(path)
    }
    fn open(&self) -> DurableStore {
        let store = DurableStore::open(StoreConfig::new(self.0.clone())).unwrap();
        fs::write(self.0.join("fixture-owner.txt"), OWNER_MARKER).unwrap();
        store
    }
}
fn plain_tree(path: &Path, root: &Path) -> bool {
    if !path.starts_with(root) {
        return false;
    }
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    if metadata.file_type().is_symlink() {
        return false;
    }
    if metadata.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return false;
        };
        let mut count = 0;
        for entry in entries {
            count += 1;
            if count > 128 || entry.is_err() || !plain_tree(&entry.unwrap().path(), root) {
                return false;
            }
        }
    }
    metadata.is_dir() || metadata.is_file()
}
impl Drop for Root {
    fn drop(&mut self) {
        if fs::read(self.0.join("fixture-owner.txt")).ok().as_deref() == Some(OWNER_MARKER)
            && plain_tree(&self.0, &self.0)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
fn project(store: &mut DurableStore) -> ProjectId {
    let value = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
    store.save_project(&value, None).unwrap();
    ProjectId::new("project-fixture").unwrap()
}
fn finite_scope() -> Value {
    json!({
        "projectId":"project-fixture", "resourceIds":["resource-approved"],
        "objectIds":["object-approved"], "externalTargetIds":[],
        "regions":[{"dimension":"minecraft:overworld", "min":[0,0,0],
            "maxExclusive":[16,16,16], "contextId":"template-context",
            "worldId":"template-world"}],
    })
}
fn artifact() -> Sha256Digest {
    Sha256Digest::new("a".repeat(64)).unwrap()
}
fn approve_fixture(store: &mut DurableStore, scope: Value) {
    let rpc = OwnerSetupRpcContext::for_store(store, None).unwrap();
    let request = HostSetupRegistration {
        project_id: ProjectId::new(scope["projectId"].as_str().unwrap()).unwrap(),
        host_artifact_digest: artifact(),
        approved_scope: serde_json::from_value(scope).unwrap(),
    };
    let mut authority = OwnerSetupAuthority::for_read(&rpc);
    // Private test composition substitutes an explicit file verification;
    // production read-only pairing can never set this registration witness.
    authority.registration = Some(request.clone());
    register_host_setup(store, &rpc, &mut authority, &request).unwrap();
}
fn offer(root: &Root, nonce: &str, scope: Value) -> HostOffer {
    let project = scope["projectId"].clone();
    let mut hello = parse_json(include_bytes!("../../../examples/host-hello.json")).unwrap();
    hello["loader"]["id"] = json!("fabric");
    let mut action = parse_json(include_bytes!("../../../examples/provider-supported.json"))
        .unwrap()["actions"][0]
        .clone();
    action["implementationDigest"] = json!(artifact());
    let public = PublicFrame::from_value(json!({
        "kind":"host_pairing_offer", "protocolVersion":"0.2.0", "nonce":nonce,
        "hostHello":hello, "hostArtifactDigest":artifact(), "principalId":"player-fixture",
        "playerId":"player-fixture", "playerContext":{
            "dimension":"minecraft:overworld", "executorHandle":"actual-player-handle",
            "origin":[1,2,3], "rotationDegrees":[10,20], "anchor":"feet"},
        "dataRoot":root.0, "projectId":project, "scope":scope,
        "nativeActions":[action],
    }))
    .unwrap();
    HostOffer::new(public, SecretToken::parse(&"b".repeat(64)).unwrap()).unwrap()
}
fn processor() -> (HostBootstrapProcessor, LocalAuthority) {
    let hosts = HostBridge::default();
    let authority = LocalAuthority::new(hosts.clone());
    (
        HostBootstrapProcessor::new(hosts, authority.clone()).unwrap(),
        authority,
    )
}
fn epoch() -> SessionEpoch {
    SessionEpoch::new("coordinator-fixture").unwrap()
}

#[test]
fn read_only_pairing_cannot_register_an_unapproved_artifact() {
    let root = Root::new();
    let mut store = root.open();
    let project = project(&mut store);
    let rpc = OwnerSetupRpcContext::for_store(&store, None).unwrap();
    let mut authority = OwnerSetupAuthority::for_read(&rpc);
    let request = HostSetupRegistration {
        project_id: project,
        host_artifact_digest: artifact(),
        approved_scope: serde_json::from_value(finite_scope()).unwrap(),
    };
    assert!(register_host_setup(&mut store, &rpc, &mut authority, &request).is_err());
    let (mut processor, live_authority) = processor();
    assert!(
        processor
            .handle(
                &mut store,
                ManagementRequest::Offer(offer(&root, "pair-a", finite_scope())),
                &epoch()
            )
            .is_err()
    );
    assert!(processor.pending.is_empty());
    assert!(
        live_authority
            .policy_revision(
                &PrincipalId::new("player-fixture").unwrap(),
                &request.project_id
            )
            .is_err()
    );
}

#[test]
fn approved_scope_rebinds_only_context_world_and_defers_session_activation() {
    let root = Root::new();
    let mut store = root.open();
    project(&mut store);
    let approved = finite_scope();
    approve_fixture(&mut store, approved.clone());
    let (mut processor, mut authority) = processor();
    let original_owner = processor.current_session_policy().unwrap().principal;
    let offer = offer(&root, "pair-a", approved.clone());
    let descriptor_digest = canonical_digest(&offer.public().value()["nativeActions"][0]).unwrap();
    let reply = processor
        .handle(&mut store, ManagementRequest::Offer(offer), &epoch())
        .unwrap()
        .unwrap();
    assert_eq!(reply.kind(), ManagementKind::Authority);
    assert_eq!(
        reply.value()["approvedSources"][NATIVE_SOURCE_ID],
        artifact().as_str()
    );
    assert_eq!(reply.value()["approvedActions"], json!([descriptor_digest]));
    assert_eq!(reply.value()["writeProfileVerified"], false);
    assert_eq!(
        reply.value()["compatibilityApprovals"],
        json!({
            "status":"unavailable","reasonCode":"APPROVAL_SOURCE_UNAVAILABLE","profiles":[]
        })
    );
    // This legacy fixture has no native-owned approval source. Preserve the
    // optional source failure without fabricating compatibility registration
    // or preventing the already approved native read-only pairing.
    assert!(
        processor
            .pending
            .values()
            .next()
            .unwrap()
            .compatibility_failure
            .is_some()
    );
    let context = &reply.value()["contexts"][0];
    verify_projected_digest("ExecutionContext", context).unwrap();
    assert_ne!(context["contextId"], "template-context");
    assert_eq!(
        context["scope"]["regions"][0]["contextId"],
        context["contextId"]
    );
    assert_eq!(
        context["scope"]["regions"][0]["worldId"],
        "world-fixture-01"
    );
    for key in ["resourceIds", "objectIds", "externalTargetIds"] {
        assert_eq!(context["scope"][key], approved[key]);
    }
    for key in ["dimension", "min", "maxExclusive"] {
        assert_eq!(
            context["scope"]["regions"][0][key],
            approved["regions"][0][key]
        );
    }
    let policy = processor.current_session_policy().unwrap();
    assert_eq!(policy.principal, original_owner);
    assert!(policy.allowed_contexts.is_empty());
    assert!(
        authority
            .authorize(
                &PrincipalId::new("player-fixture").unwrap(),
                &ProjectId::new("project-fixture").unwrap(),
                Access::ReadProject,
                None,
                None,
            )
            .is_err()
    );
}

#[test]
fn larger_offer_scope_and_wrong_root_do_not_install_grants() {
    let root = Root::new();
    let mut store = root.open();
    let project = project(&mut store);
    approve_fixture(&mut store, finite_scope());
    let (mut processor, authority) = processor();
    let mut expanded = finite_scope();
    expanded["regions"][0]["maxExclusive"][0] = json!(17);
    assert!(
        processor
            .handle(
                &mut store,
                ManagementRequest::Offer(offer(&root, "pair-wide", expanded)),
                &epoch()
            )
            .is_err()
    );
    let valid = offer(&root, "pair-wrong-root", finite_scope());
    let mut value = valid.public().value().clone();
    value["dataRoot"] = json!(root.0.join("another-root"));
    let wrong_root = HostOffer::new(
        PublicFrame::from_value(value).unwrap(),
        SecretToken::generate().unwrap(),
    )
    .unwrap();
    assert!(
        processor
            .handle(&mut store, ManagementRequest::Offer(wrong_root), &epoch())
            .is_err()
    );
    assert!(processor.pending.is_empty());
    assert!(
        authority
            .policy_revision(&PrincipalId::new("player-fixture").unwrap(), &project)
            .is_err()
    );
}

#[test]
fn wrong_installed_epoch_rolls_back_only_staged_project_generation() {
    let root = Root::new();
    let mut store = root.open();
    let project = project(&mut store);
    approve_fixture(&mut store, finite_scope());
    let (mut processor, authority) = processor();
    let offer = offer(&root, "pair-stale", finite_scope());
    let witness = offer.witness().clone();
    processor
        .handle(&mut store, ManagementRequest::Offer(offer), &epoch())
        .unwrap();
    let principal = PrincipalId::new("player-fixture").unwrap();
    let staged = processor.pending.get(witness.id()).unwrap().policy.clone();
    authority
        .validate_staged_project(&principal, &project, &staged)
        .unwrap();
    assert!(authority.policy_revision(&principal, &project).is_err());
    authority
        .revoke_staged_project(&principal, &project, &staged)
        .unwrap();
    // Another trusted owner generation is installed before the stale reply.
    let mut replacement_scope = finite_scope();
    replacement_scope["regions"][0]["contextId"] = json!("replacement-context");
    let replacement = authority
        .install_project_access(
            principal.clone(),
            project.clone(),
            replacement_scope,
            BTreeSet::from([ContextId::new("replacement-context").unwrap()]),
            SESSION_LIFETIME,
        )
        .unwrap();
    let installed = PublicFrame::from_value(json!({
        "kind":"host_pairing_installed", "protocolVersion":"0.2.0", "nonce":"pair-stale",
        "hostEndpoint":{"address":"127.0.0.1:32123", "path":"/rpc", "hostEpoch":"wrong-epoch"},
    }))
    .unwrap();
    assert!(
        processor
            .handle(
                &mut store,
                ManagementRequest::installed(installed, witness).unwrap(),
                &epoch()
            )
            .is_err()
    );
    assert!(processor.pending.is_empty());
    assert_eq!(
        authority.policy_revision(&principal, &project).unwrap(),
        replacement
    );
    assert!(
        processor
            .current_session_policy()
            .unwrap()
            .allowed_contexts
            .is_empty()
    );
}

#[test]
fn native_failed_delivery_and_cancelled_pending_retire_exact_generation() {
    let root = Root::new();
    let mut store = root.open();
    let project = project(&mut store);
    approve_fixture(&mut store, finite_scope());
    let (mut processor, authority) = processor();
    let first_offer = offer(&root, "pair-undelivered", finite_scope());
    let witness = first_offer.witness().clone();
    let budget = BootstrapBudget::new();
    processor
        .handle_with_budget(
            &mut store,
            ManagementRequest::Offer(first_offer),
            &epoch(),
            &budget,
        )
        .unwrap();
    let (sender, receiver) = management_channel();
    sender.notify_finished(&witness, false, &budget).unwrap();
    let envelope = receiver.try_receive().unwrap().unwrap();
    let (receipt, responder) = envelope.into_parts().unwrap();
    assert!(responder.is_none());
    assert!(
        processor
            .handle_with_budget(&mut store, receipt, &epoch(), &budget)
            .unwrap()
            .is_none()
    );
    assert!(processor.pending.is_empty());
    assert!(
        authority
            .policy_revision(&PrincipalId::new("player-fixture").unwrap(), &project)
            .is_err()
    );
    let budget = BootstrapBudget::new();
    processor
        .handle_with_budget(
            &mut store,
            ManagementRequest::Offer(offer(&root, "pair-cancel", finite_scope())),
            &epoch(),
            &budget,
        )
        .unwrap();
    budget.cancel();
    processor.cleanup_expired().unwrap();
    assert!(processor.pending.is_empty());
    assert!(
        processor
            .current_session_policy()
            .unwrap()
            .allowed_contexts
            .is_empty()
    );
    // The immutable setup and the canonical Project remain retained.
    assert!(store.project(&project).is_ok());
    let rpc = OwnerSetupRpcContext::for_store(&store, None).unwrap();
    let mut setup_authority = OwnerSetupAuthority::for_read(&rpc);
    assert!(
        host_setup(
            &store,
            &rpc,
            &mut setup_authority,
            &project,
            &artifact(),
            None
        )
        .is_ok()
    );
}

fn native_receipt(
    witness: &BootstrapWitness,
    delivered: bool,
    budget: &BootstrapBudget,
) -> ManagementRequest {
    let (sender, receiver) = management_channel();
    sender.notify_finished(witness, delivered, budget).unwrap();
    let (request, responder) = receiver
        .try_receive()
        .unwrap()
        .unwrap()
        .into_parts()
        .unwrap();
    assert!(responder.is_none());
    request
}

/// A finite actual TCP peer returns original HostResponse fixtures. Native
/// completion is simulated through the private receipt API; no game/native
/// administrator authentication or game compatibility is asserted here.
fn host_response_fixture(
    hello: Value,
    context: Value,
) -> (
    SocketAddr,
    std::thread::JoinHandle<Result<(), &'static str>>,
) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let task = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(6);
        for (payload_index, payload) in [hello, context].into_iter().enumerate() {
            let mut stream = loop {
                if Instant::now() >= deadline {
                    return Err("bounded host fixture accept expired");
                }
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return Err("host fixture accept failed"),
                }
            };
            // Accepted sockets may inherit the listener's nonblocking mode.
            // The fixture uses bounded blocking reads, not an async I/O loop.
            stream
                .set_nonblocking(false)
                .map_err(|_| "fixture blocking mode")?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            stream
                .set_read_timeout(Some(remaining))
                .map_err(|_| "fixture read timeout")?;
            stream
                .set_write_timeout(Some(remaining))
                .map_err(|_| "fixture write timeout")?;
            let mut header = zeroize::Zeroizing::new(Vec::new());
            loop {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .ok_or("bounded host fixture header deadline expired")?;
                stream
                    .set_read_timeout(Some(remaining))
                    .map_err(|_| "fixture header timeout configuration")?;
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).map_err(|cause| {
                    eprintln!(
                        "host_fixture_failure payload_index={payload_index}; stage=header; kind={:?}; native_errno={:?}; received_bytes={}; deadline_reached={}",
                        cause.kind(), cause.raw_os_error(), header.len(), Instant::now() >= deadline,
                    );
                    "host fixture header read"
                })?;
                header.push(byte[0]);
                if header.len() > 16 * 1024 {
                    return Err("host fixture header limit");
                }
                if header.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let header_text =
                std::str::from_utf8(&header).map_err(|_| "fixture header encoding")?;
            let length: usize = header_text
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .ok_or("fixture content length")?
                .parse()
                .map_err(|_| "fixture length parse")?;
            if length > crate::rpc::MAX_CONTROL_BYTES {
                return Err("fixture body limit");
            }
            let mut body = vec![0; length];
            stream
                .read_exact(&mut body)
                .map_err(|_| "fixture body read")?;
            let request = parse_json(&body).map_err(|_| "fixture request JSON")?;
            ContractValidator::shared()
                .map_err(|_| "fixture validator")?
                .validate("HostRequest", &request["params"])
                .map_err(|_| "fixture request contract")?;
            if request["method"] != "mmmm.host" || request["id"] != request["params"]["requestId"] {
                return Err("fixture host envelope correlation");
            }
            let response = json!({"jsonrpc":"2.0", "id":request["id"], "result":{
                "protocolVersion":"0.2.0", "requestId":request["params"]["requestId"],
                "status":"ok", "payload":payload, "eventSequence":"0", }});
            let bytes = serde_json::to_vec(&response).map_err(|_| "fixture response encoding")?;
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            );
            stream
                .write_all(header.as_bytes())
                .map_err(|_| "fixture response header")?;
            stream
                .write_all(&bytes)
                .map_err(|_| "fixture response body")?;
        }
        Ok(())
    });
    (address, task)
}

#[test]
fn actual_host_responses_then_terminal_receipt_activate_exact_session() {
    let root = Root::new();
    let mut store = root.open();
    let project = project(&mut store);
    approve_fixture(&mut store, finite_scope());
    let (mut processor, mut authority) = processor();
    let offer = offer(&root, "pair-response", finite_scope());
    let witness = offer.witness().clone();
    let hello = offer.public().value()["hostHello"].clone();
    let budget = BootstrapBudget::new();
    let authority_reply = processor
        .handle_with_budget(
            &mut store,
            ManagementRequest::Offer(offer),
            &epoch(),
            &budget,
        )
        .unwrap()
        .unwrap();
    let context = authority_reply.value()["contexts"][0].clone();
    let (address, host) = host_response_fixture(hello, context.clone());
    let installed = PublicFrame::from_value(json!({
        "kind":"host_pairing_installed", "protocolVersion":"0.2.0", "nonce":"pair-response",
        "hostEndpoint":{"address":address.to_string(), "path":"/rpc", "hostEpoch":"epoch-fixture-01"},
    })).unwrap();
    let reply = processor.handle_with_reply_deadline(
        &mut store,
        ManagementRequest::installed(installed, witness.clone()).unwrap(),
        &epoch(),
        &budget,
        Instant::now() + Duration::from_secs(5),
    );
    let fixture_result = host.join();
    if reply.is_err() || !matches!(&fixture_result, Ok(Ok(()))) {
        eprintln!(
            "host_fixture_caller stage=installed; result={:?}",
            reply
                .as_ref()
                .map(|frame| frame.as_ref().map(PublicFrame::kind)),
        );
    }
    fixture_result.unwrap().unwrap();
    let complete = reply.unwrap().unwrap();
    assert_eq!(complete.kind(), ManagementKind::Complete);
    assert!(processor.has_pending_completion());
    assert!(
        processor
            .current_session_policy()
            .unwrap()
            .allowed_contexts
            .is_empty()
    );
    let principal = PrincipalId::new("player-fixture").unwrap();
    assert!(
        authority
            .authorize(&principal, &project, Access::ReadProject, None, None)
            .is_err()
    );
    processor
        .handle_with_budget(
            &mut store,
            native_receipt(&witness, true, &budget),
            &epoch(),
            &budget,
        )
        .unwrap();
    assert!(!processor.has_pending_completion());
    let policy = processor.current_session_policy().unwrap();
    assert_eq!(policy.principal, principal);
    assert_eq!(
        policy.allowed_contexts,
        BTreeSet::from([ContextId::new(context["contextId"].as_str().unwrap()).unwrap(),])
    );
    assert!(
        authority
            .authorize(&principal, &project, Access::ReadProject, None, None)
            .is_ok()
    );
    assert!(
        authority
            .authorize(&principal, &project, Access::Apply, None, None)
            .is_err()
    );
    // A duplicate receipt cannot retire the already active generation.
    processor
        .handle_with_budget(
            &mut store,
            native_receipt(&witness, false, &budget),
            &epoch(),
            &budget,
        )
        .unwrap();
    assert_eq!(
        processor.current_session_policy().unwrap().principal,
        principal
    );
    assert!(authority.policy_revision(&principal, &project).is_ok());
    let hosts = processor.hosts.clone();
    let context_id = ContextId::new(context["contextId"].as_str().unwrap()).unwrap();
    assert!(hosts.contains_route_for_test(&context_id).unwrap());
    processor.shutdown().unwrap();
    assert!(processor.pending.is_empty());
    assert!(processor.active.is_empty());
    assert!(authority.policy_revision(&principal, &project).is_err());
    assert!(!hosts.contains_route_for_test(&context_id).unwrap());
    assert!(
        processor
            .current_session_policy()
            .unwrap()
            .allowed_contexts
            .is_empty()
    );
    processor.shutdown().unwrap();
}

// These are actual finite TCP Hello/context exchanges and the existing opaque
// native-completion test seam. They prove delivery-provenance composition,
// not a real game's native ACK/EOF, read rights or shape acceptance.
struct ObservedPairingFixture {
    store: DurableStore,
    processor: HostBootstrapProcessor,
    authority: LocalAuthority,
    witness: BootstrapWitness,
    budget: BootstrapBudget,
    context: Value,
    hello: Value,
    _root: Root,
}
fn observed_pairing_fixture(nonce: &str) -> ObservedPairingFixture {
    let root = Root::new();
    let mut store = root.open();
    project(&mut store);
    observed_pairing_with_store(nonce, root, store, finite_scope())
}
fn native_owned_pairing_fixture(nonce: &str) -> ObservedPairingFixture {
    let root = Root::new();
    let mut store = root.open();
    let created = crate::native_project::create_native_project(
        &mut store,
        "Current native pairing owner fixture",
        &mmmm_contracts::TargetProfileId::new("target-unverified").unwrap(),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    let mut scope = finite_scope();
    scope["projectId"] = json!(created.project_id);
    scope["resourceIds"] = json!([created.policy_resource["resourceId"]]);
    scope["objectIds"] = json!([]);
    observed_pairing_with_store(nonce, root, store, scope)
}
fn observed_pairing_with_store(
    nonce: &str,
    root: Root,
    mut store: DurableStore,
    scope: Value,
) -> ObservedPairingFixture {
    approve_fixture(&mut store, scope.clone());
    let (mut processor, authority) = processor();
    let offer = offer(&root, nonce, scope);
    let witness = offer.witness().clone();
    let hello = offer.public().value()["hostHello"].clone();
    let budget = BootstrapBudget::new();
    let reply = processor
        .handle_with_budget(
            &mut store,
            ManagementRequest::Offer(offer),
            &epoch(),
            &budget,
        )
        .unwrap()
        .unwrap();
    let context = reply.value()["contexts"][0].clone();
    let (address, host) = host_response_fixture(hello.clone(), context.clone());
    let installed = PublicFrame::from_value(json!({
        "kind":"host_pairing_installed", "protocolVersion":"0.2.0", "nonce":nonce,
        "hostEndpoint":{"address":address.to_string(), "path":"/rpc", "hostEpoch":"epoch-fixture-01"},
    })).unwrap();
    let installed_result = processor.handle_with_reply_deadline(
        &mut store,
        ManagementRequest::installed(installed, witness.clone()).unwrap(),
        &epoch(),
        &budget,
        Instant::now() + Duration::from_secs(5),
    );
    let fixture_result = host.join();
    if installed_result.is_err() || !matches!(&fixture_result, Ok(Ok(()))) {
        eprintln!(
            "host_fixture_caller stage=installed; result={:?}",
            installed_result
                .as_ref()
                .map(|frame| frame.as_ref().map(PublicFrame::kind)),
        );
    }
    fixture_result.unwrap().unwrap();
    assert_eq!(
        installed_result.unwrap().unwrap().kind(),
        ManagementKind::Complete
    );
    ObservedPairingFixture {
        store,
        processor,
        authority,
        witness,
        budget,
        context,
        hello,
        _root: root,
    }
}
fn finish_observed_pairing(
    fixture: &mut ObservedPairingFixture,
    delivered: bool,
) -> Result<(), ManagementError> {
    fixture
        .processor
        .handle_with_budget(
            &mut fixture.store,
            native_receipt(&fixture.witness, delivered, &fixture.budget),
            &epoch(),
            &fixture.budget,
        )
        .map(|_| ())
}

struct NoPairingApplicationCalls;
impl mmmm_application::AuthorityPort for NoPairingApplicationCalls {
    fn authorize(
        &mut self,
        _: &PrincipalId,
        _: &ProjectId,
        _: Access,
        _: Option<&Value>,
        _: Option<&Value>,
    ) -> mmmm_application::AppResult<()> {
        panic!("Unexpected application authority in pairing provenance fixture")
    }
}
impl mmmm_application::PlanningPort for NoPairingApplicationCalls {
    fn inspect_project(
        &mut self,
        _: &PrincipalId,
        _: &Value,
    ) -> mmmm_application::AppResult<mmmm_application::ProjectInspection> {
        panic!("Unexpected application inspection")
    }
    fn prepare(
        &mut self,
        _: &PrincipalId,
        _: &Value,
        _: &Value,
        _: &Value,
    ) -> mmmm_application::AppResult<mmmm_application::PreparedPlan> {
        panic!("Unexpected application plan")
    }
    fn prepare_recovery(
        &mut self,
        _: &PrincipalId,
        _: &mmmm_application::RecoveryPreparation,
        _: &Value,
        _: &Value,
    ) -> mmmm_application::AppResult<mmmm_application::PreparedPlan> {
        panic!("Unexpected recovery plan")
    }
}
impl mmmm_application::ProviderPort for NoPairingApplicationCalls {
    fn context(&mut self, _: &PrincipalId, _: &ContextId) -> mmmm_application::AppResult<Value> {
        panic!("Unexpected provider context")
    }
    fn action_descriptor(&mut self, _: &Value, _: &Value) -> mmmm_application::AppResult<Value> {
        panic!("Unexpected action descriptor")
    }
    fn observe_precondition(
        &mut self,
        _: &Value,
        _: &Value,
    ) -> mmmm_application::AppResult<Sha256Digest> {
        panic!("Unexpected precondition")
    }
    fn verify_dependencies(&mut self, _: &[Value], _: &Value) -> mmmm_application::AppResult<()> {
        panic!("Unexpected dependency call")
    }
    fn dispatch(&mut self, _: &Value) -> mmmm_application::AppResult<Value> {
        panic!("Pairing provenance cannot dispatch")
    }
    fn poll(&mut self, _: &Value, _: Option<&str>) -> mmmm_application::AppResult<Option<Value>> {
        panic!("Unexpected provider poll")
    }
    fn request_cancel(&mut self, _: &Value, _: Option<&str>) -> mmmm_application::AppResult<()> {
        panic!("Unexpected provider cancellation")
    }
}
impl mmmm_application::IndependentObserverPort for NoPairingApplicationCalls {
    fn readback(
        &mut self,
        _: &Value,
        _: &WriteScope,
    ) -> mmmm_application::AppResult<mmmm_application::ReadbackEvidence> {
        panic!("Unexpected native readback")
    }
    fn read_target(&mut self, _: &Value, _: &str) -> mmmm_application::AppResult<Vec<u8>> {
        panic!("Unexpected native target read")
    }
}
impl mmmm_application::IdSource for NoPairingApplicationCalls {
    fn next_id(&mut self, _: mmmm_application::IdKind) -> mmmm_application::AppResult<String> {
        panic!("Pairing provenance cannot allocate product IDs")
    }
}
impl mmmm_application::Clock for NoPairingApplicationCalls {
    fn unix_nanos(&self) -> i128 {
        0
    }
}
type PairingProbeCall = dyn FnMut(
    &DurableStore,
    crate::service::RequestContextWitness,
) -> mmmm_application::AppResult<()>;
struct PairingProbeExtension {
    request: crate::service::RequestContextSlot,
    inspect: Box<PairingProbeCall>,
}
impl crate::service::ServiceExtension for PairingProbeExtension {
    fn call(
        &mut self,
        method: &str,
        _: &Value,
        context: &mut crate::service::ServiceExtensionContext<'_>,
    ) -> Result<Value, crate::service::ServiceError> {
        context.check(method)?;
        let request = self.request.current_witness(method)?;
        (self.inspect)(context.store, request).map_err(|cause| {
            crate::service::ServiceError::caused_by(cause.code, cause.message, cause)
        })?;
        Ok(json!({}))
    }
}
fn pairing_request_probe(
    store: DurableStore,
    policy: SessionPolicy,
    inspect: impl FnMut(
        &DurableStore,
        crate::service::RequestContextWitness,
    ) -> mmmm_application::AppResult<()>
    + 'static,
) {
    use crate::service::{
        ApplicationPorts, ApplicationService, ExtensionRouter, RequestBudget, RequestContextSlot,
        ServiceDispatcher,
    };
    let request = RequestContextSlot::default();
    let mut sessions = crate::auth::SessionAuthority::new(1).unwrap();
    let token = sessions.install(policy).unwrap();
    let authenticated = sessions.authenticate_token(&token).unwrap();
    let mut service = ApplicationService::from_store(
        store,
        ApplicationPorts {
            authority: Box::new(NoPairingApplicationCalls),
            planner: Box::new(NoPairingApplicationCalls),
            provider: Box::new(NoPairingApplicationCalls),
            observer: Box::new(NoPairingApplicationCalls),
            ids: Box::new(NoPairingApplicationCalls),
            clock: Box::new(NoPairingApplicationCalls),
        },
    );
    service.bind_request_context(request.clone());
    let mut router = ExtensionRouter::default();
    router
        .register(
            ["catalog.capture"],
            Box::new(PairingProbeExtension {
                request,
                inspect: Box::new(inspect),
            }),
        )
        .unwrap();
    service.set_extensions(router);
    let budget = RequestBudget::new(
        Duration::from_secs(5),
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )
    .unwrap();
    service
        .call(&authenticated, "catalog.capture", &json!({}), &budget)
        .unwrap();
}

#[test]
fn completed_pairing_uses_current_request_without_restarting_native_budget() {
    let mut fixture = observed_pairing_fixture("pair-completion-provenance");
    let native = native_receipt(&fixture.witness, true, &fixture.budget);
    let ManagementRequest::Finished(ref native_receipt) = native else {
        panic!("Opaque receipt required");
    };
    let completed_at = native_receipt.completed_at();
    let original_deadline = fixture.budget.deadline();
    // Completion already happened. A later original-budget cancellation must
    // not turn that native observation into an acquisition timeout.
    fixture.budget.cancel();
    fixture
        .processor
        .handle_with_budget(&mut fixture.store, native, &epoch(), &fixture.budget)
        .unwrap();
    let hosts = fixture.processor.hosts.clone();
    let id = ContextId::new(fixture.context["contextId"].as_str().unwrap()).unwrap();
    let authority = fixture.authority.clone();
    let held = Rc::new(RefCell::new(None));
    let capture = held.clone();
    let policy = fixture.processor.current_session_policy().unwrap();
    let digest = fixture.witness.offer_digest().clone();
    pairing_request_probe(fixture.store, policy, move |_, request| {
        let witness = hosts.completed_pairing_witness(&request, &authority, &id)?;
        assert_eq!(witness.completed_at(), completed_at);
        assert_eq!(witness.original_deadline(), original_deadline);
        assert_eq!(witness.offer_digest(), &digest);
        assert_eq!(witness.native_owner(), &local_owner_principal().unwrap());
        witness.with_current_original_offer(&authority, |offer| {
            assert_eq!(canonical_digest(offer).unwrap(), digest);
            Ok(())
        })?;
        let debug = format!("{witness:?}");
        assert!(!debug.contains("pair-completion-provenance"));
        assert!(!debug.contains("dataRoot"));
        *capture.borrow_mut() = Some(witness);
        Ok(())
    });
    assert!(
        held.borrow()
            .as_ref()
            .unwrap()
            .check_current(&fixture.authority)
            .is_err()
    );
    fixture.processor.shutdown().unwrap();
}

#[test]
fn completed_pairing_witness_rechecks_active_policy() {
    let mut fixture = observed_pairing_fixture("pair-revoked-provenance");
    finish_observed_pairing(&mut fixture, true).unwrap();
    let policy = fixture.processor.current_session_policy().unwrap();
    let hosts = fixture.processor.hosts.clone();
    let authority = fixture.authority.clone();
    let context = fixture.context.clone();
    pairing_request_probe(fixture.store, policy, move |_, request| {
        let id = ContextId::new(context["contextId"].as_str().unwrap()).unwrap();
        let witness = hosts.completed_pairing_witness(&request, &authority, &id)?;
        let project = witness.project().clone();
        let principal = witness.principal().clone();
        let policy = Sha256Digest::new(context["policyRevision"].as_str().unwrap()).unwrap();
        authority.revoke_staged_project(&principal, &project, &policy)?;
        assert!(witness.check_current(&authority).is_err());
        assert!(
            hosts
                .completed_pairing_witness(&request, &authority, &id)
                .is_err()
        );
        Ok(())
    });
    fixture.processor.shutdown().unwrap();
}

fn replace_observed_route(hosts: &HostBridge, context: &Value, hello: &Value) -> HostRouteOwner {
    let (address, host) = host_response_fixture(hello.clone(), context.clone());
    let client = HostRpcClient::paired(
        EndpointRecord {
            schema_version: 1,
            contract_version: "0.2.0".into(),
            address,
            path: "/rpc".into(),
            coordinator_epoch: "epoch-fixture-01".into(),
            credential_ref: "MMMM.coordinator.peer-fixture".into(),
        },
        SecretToken::generate().unwrap(),
    )
    .unwrap();
    let result = hosts.attach_owned_with_deadline(
        client,
        PrincipalId::new(context["principalRef"].as_str().unwrap()).unwrap(),
        context.clone(),
        hello.clone(),
        Duration::from_secs(60),
        Instant::now() + Duration::from_secs(5),
    );
    host.join().unwrap().unwrap();
    result.unwrap()
}

#[test]
fn completed_pairing_never_follows_an_identical_context_to_a_new_route() {
    let mut fixture = observed_pairing_fixture("pair-replaced-provenance");
    finish_observed_pairing(&mut fixture, true).unwrap();
    let policy = fixture.processor.current_session_policy().unwrap();
    let hosts = fixture.processor.hosts.clone();
    let authority = fixture.authority.clone();
    let context = fixture.context.clone();
    let hello = fixture.hello.clone();
    pairing_request_probe(fixture.store, policy, move |_, request| {
        let id = ContextId::new(context["contextId"].as_str().unwrap()).unwrap();
        let witness = hosts.completed_pairing_witness(&request, &authority, &id)?;
        let replacement = replace_observed_route(&hosts, &context, &hello);
        assert_eq!(
            witness.check_current(&authority).unwrap_err().code,
            "SESSION_ROUTE_CHANGED"
        );
        assert_eq!(
            hosts
                .completed_pairing_witness(&request, &authority, &id)
                .unwrap_err()
                .code,
            "SOURCE_UNAVAILABLE"
        );
        hosts.detach_owned(&replacement)?;
        Ok(())
    });
    fixture.processor.shutdown().unwrap();
}

#[test]
fn completed_delivery_route_mismatch_rolls_back_only_original_generation() {
    let mut fixture = observed_pairing_fixture("pair-original-route-provenance");
    let hosts = fixture.processor.hosts.clone();
    let replacement = replace_observed_route(&hosts, &fixture.context, &fixture.hello);
    assert_eq!(
        finish_observed_pairing(&mut fixture, true),
        Err(ManagementError::WrongReply)
    );
    let id = ContextId::new(fixture.context["contextId"].as_str().unwrap()).unwrap();
    assert!(hosts.contains_route_for_test(&id).unwrap());
    assert!(fixture.processor.active.is_empty());
    assert!(fixture.processor.pending.is_empty());
    let retained = fixture
        .processor
        .rejected_completions
        .get(fixture.witness.id())
        .unwrap();
    assert!(retained._observation.completion.delivered());
    assert!(matches!(
        retained._rollback,
        RollbackObservation::Completed { .. }
    ));
    assert_eq!(
        retained._publication_failure.as_ref().unwrap().code,
        "SESSION_ROUTE_CHANGED"
    );
    assert!(retained._first_rollback_failure.is_none());
    hosts.detach_owned(&replacement).unwrap();
    fixture.processor.shutdown().unwrap();
}

#[test]
fn completed_pairing_witness_obeys_original_current_request_cancellation() {
    let mut fixture = observed_pairing_fixture("pair-request-cancel-provenance");
    finish_observed_pairing(&mut fixture, true).unwrap();
    let policy = fixture.processor.current_session_policy().unwrap();
    let hosts = fixture.processor.hosts.clone();
    let authority = fixture.authority.clone();
    let id = ContextId::new(fixture.context["contextId"].as_str().unwrap()).unwrap();
    pairing_request_probe(fixture.store, policy, move |_, request| {
        let witness = hosts.completed_pairing_witness(&request, &authority, &id)?;
        request
            .budget()
            .cancellation()
            .store(true, Ordering::Release);
        assert_eq!(
            witness.check_current(&authority).unwrap_err().code,
            "CANCELLED"
        );
        assert_eq!(
            hosts
                .completed_pairing_witness(&request, &authority, &id)
                .unwrap_err()
                .code,
            "CANCELLED"
        );
        Ok(())
    });
    fixture.processor.shutdown().unwrap();
}

#[test]
fn rejected_completion_keeps_original_receipt_after_successful_rollback() {
    let mut fixture = observed_pairing_fixture("pair-rejected-provenance");
    finish_observed_pairing(&mut fixture, false).unwrap();
    assert!(fixture.processor.pending.is_empty());
    assert!(fixture.processor.active.is_empty());
    let retained = fixture
        .processor
        .rejected_completions
        .get(fixture.witness.id())
        .unwrap();
    assert!(!retained._observation.completion.delivered());
    assert_eq!(
        retained._observation.offer_digest(),
        fixture.witness.offer_digest()
    );
    assert!(matches!(
        retained._rollback,
        RollbackObservation::Completed {
            prior_failure: None
        }
    ));
    let retained_bytes = fixture.processor.rejected_encoded_bytes;
    assert!(retained_bytes > 0 && retained_bytes <= MAX_REJECTED_ENCODED_BYTES);
    fixture.processor.cleanup_expired().unwrap();
    fixture.processor.shutdown().unwrap();
    assert_eq!(fixture.processor.rejected_completions.len(), 1);
    assert_eq!(fixture.processor.rejected_encoded_bytes, retained_bytes);
}

#[test]
fn completion_retention_budget_keeps_rolled_back_pending_truth() {
    let mut fixture = observed_pairing_fixture("pair-full-provenance");
    // Exact aggregate boundary injection exercises overflow/capacity without
    // manufacturing eight megabytes of unrelated offers or any source grant.
    fixture.processor.rejected_encoded_bytes = MAX_REJECTED_ENCODED_BYTES;
    assert_eq!(
        finish_observed_pairing(&mut fixture, false),
        Err(ManagementError::TransportUncertain)
    );
    let retained = fixture.processor.pending.get(fixture.witness.id()).unwrap();
    let original = retained.completion.as_ref().unwrap().clone();
    assert!(!original.delivered());
    assert!(matches!(
        retained.rollback_observation,
        RollbackObservation::Completed { .. }
    ));
    assert!(fixture.processor.active.is_empty());
    assert!(fixture.processor.rejected_completions.is_empty());
    assert_eq!(
        fixture.processor.shutdown(),
        Err(ManagementError::TransportUncertain)
    );
    let retained = fixture.processor.pending.get(fixture.witness.id()).unwrap();
    assert!(Arc::ptr_eq(
        retained.completion.as_ref().unwrap(),
        &original
    ));
    assert_eq!(
        fixture.processor.rejected_encoded_bytes,
        MAX_REJECTED_ENCODED_BYTES
    );
}

#[test]
fn current_pairing_owner_reads_only_explicit_same_host_policy() {
    for explicit in [false, true] {
        let mut fixture = native_owned_pairing_fixture(if explicit {
            "pair-owner-explicit-read-policy"
        } else {
            "pair-owner-missing-read-policy"
        });
        let selected = HostReadPolicy::new(["survival".to_owned()], true).unwrap();
        let retained = if explicit {
            let rpc = OwnerSetupRpcContext::for_store(&fixture.store, None).unwrap();
            let project = ProjectId::new(fixture.context["projectId"].as_str().unwrap()).unwrap();
            let mut approval = OwnerSetupAuthority::for_read(&rpc);
            let setup = host_setup(
                &fixture.store,
                &rpc,
                &mut approval,
                &project,
                &artifact(),
                None,
            )
            .unwrap();
            let request = HostSetupRegistration {
                project_id: project,
                host_artifact_digest: artifact(),
                approved_scope: setup.approved_scope,
            };
            // Reuse this fixture's existing private file-verification seam.
            // Kernel owner, native Project registration, actual SQLite policy
            // and current entered-request consumer are real. This is not a
            // game/JAR execution or a source-rights acceptance fixture.
            approval.registration = Some(request.clone());
            approval.selected_read_policy = Some(selected.clone());
            Some(
                register_host_setup_with_read_policy(
                    &mut fixture.store,
                    &rpc,
                    &mut approval,
                    &request,
                    &selected,
                )
                .unwrap()
                .1,
            )
        } else {
            None
        };
        finish_observed_pairing(&mut fixture, true).unwrap();
        let hosts = fixture.processor.hosts.clone();
        let authority = fixture.authority.clone();
        let id = ContextId::new(fixture.context["contextId"].as_str().unwrap()).unwrap();
        let policy = fixture.processor.current_session_policy().unwrap();
        pairing_request_probe(fixture.store, policy, move |store, request| {
            let pairing = hosts.completed_pairing_witness(&request, &authority, &id)?;
            let result = pairing
                .with_current_native_owner(store, &authority, |owner| owner.read_host_policy());
            if let Some(retained) = &retained {
                let actual = result?;
                assert_eq!(&actual, retained);
                assert_eq!(actual.policy(), &selected);
                assert!(actual.policy().native_observation_user_local_only());
                assert!(!actual.policy().shape_modes().contains("creative"));
                assert_eq!(actual.principal(), pairing.native_owner());
                assert_ne!(actual.principal(), pairing.principal());
            } else {
                assert_eq!(result.unwrap_err().code, "SOURCE_UNAVAILABLE");
            }
            Ok(())
        });
        fixture.processor.shutdown().unwrap();
    }
}

#[test]
fn current_pairing_owner_uses_real_native_project_and_current_request_lifetime() {
    let mut fixture = native_owned_pairing_fixture("pair-current-owner");
    finish_observed_pairing(&mut fixture, true).unwrap();
    // This old bootstrap budget must not become the new owner's call budget.
    fixture.budget.cancel();
    let hosts = fixture.processor.hosts.clone();
    let authority = fixture.authority.clone();
    let context = fixture.context.clone();
    let root = fixture._root.0.clone();
    let held = Rc::new(RefCell::new(None));
    let capture = held.clone();
    let policy = fixture.processor.current_session_policy().unwrap();
    pairing_request_probe(fixture.store, policy, move |store, request| {
        let id = ContextId::new(context["contextId"].as_str().unwrap()).unwrap();
        let pairing = hosts.completed_pairing_witness(&request, &authority, &id)?;
        let value = pairing.with_current_native_owner(store, &authority, |owner| {
            owner.check_current()?;
            Ok(17_u8)
        })?;
        assert_eq!(value, 17);
        *capture.borrow_mut() = Some(pairing);
        Ok(())
    });
    // Reopening happens only after the actual service dropped its Store. The
    // old entered request must reject before trying to capture another owner.
    let reopened = DurableStore::open_existing(StoreConfig::new(root)).unwrap();
    let result = held.borrow().as_ref().unwrap().with_current_native_owner(
        &reopened,
        &fixture.authority,
        |_| -> mmmm_application::AppResult<()> {
            panic!("A retired request cannot enter a new owner callback")
        },
    );
    assert_eq!(result.unwrap_err().code, "PERMISSION_REQUIRED");
    drop(reopened);
    fixture.processor.shutdown().unwrap();
}

#[test]
fn current_pairing_owner_rejects_another_held_store_before_callback() {
    let mut fixture = native_owned_pairing_fixture("pair-owner-wrong-store");
    finish_observed_pairing(&mut fixture, true).unwrap();
    let another_root = Root::new();
    let another_store = another_root.open();
    let hosts = fixture.processor.hosts.clone();
    let authority = fixture.authority.clone();
    let id = ContextId::new(fixture.context["contextId"].as_str().unwrap()).unwrap();
    let policy = fixture.processor.current_session_policy().unwrap();
    pairing_request_probe(fixture.store, policy, move |_, request| {
        let pairing = hosts.completed_pairing_witness(&request, &authority, &id)?;
        let result = pairing.with_current_native_owner(
            &another_store,
            &authority,
            |_| -> mmmm_application::AppResult<()> {
                panic!("Another Store cannot enter owner callback")
            },
        );
        assert_eq!(result.unwrap_err().code, "PERMISSION_REQUIRED");
        Ok(())
    });
    fixture.processor.shutdown().unwrap();
}

#[test]
fn current_pairing_owner_requires_actual_native_project_owner_registration() {
    use std::error::Error;
    // The existing original-example fixture intentionally has no native owner
    // registration. A saved canonical Project alone cannot pass this guard.
    let mut fixture = observed_pairing_fixture("pair-owner-not-registered");
    finish_observed_pairing(&mut fixture, true).unwrap();
    let hosts = fixture.processor.hosts.clone();
    let authority = fixture.authority.clone();
    let id = ContextId::new(fixture.context["contextId"].as_str().unwrap()).unwrap();
    let policy = fixture.processor.current_session_policy().unwrap();
    pairing_request_probe(fixture.store, policy, move |store, request| {
        let pairing = hosts.completed_pairing_witness(&request, &authority, &id)?;
        let error = pairing
            .with_current_native_owner(store, &authority, |_| -> mmmm_application::AppResult<()> {
                panic!("Missing native registration cannot enter callback")
            })
            .unwrap_err();
        assert_eq!(error.code, "PERMISSION_REQUIRED");
        assert!(matches!(
            error.source().unwrap().downcast_ref::<StorageError>(),
            Some(StorageError::NotFound(_))
        ));
        Ok(())
    });
    fixture.processor.shutdown().unwrap();
}

// Adversarial metadata registration is negative input only. This permit is
// never used by native_owned_pairing_fixture or any successful owner test;
// no read, Apply, source-rights or game-mode grant is constructed here.
struct ForeignOwnerMetadataFixture {
    current: crate::workspace_bootstrap::NativeOwnerWitness,
    project: Value,
    policy: Value,
}
impl mmmm_runtime::storage::bootstrap::NativeOwnerCreatePermit for ForeignOwnerMetadataFixture {
    fn check(&self, store: &DurableStore) -> StorageResult<()> {
        self.current.check_store(store)
    }
    fn authorize_create(
        &mut self,
        store: &DurableStore,
        request: &mmmm_runtime::storage::bootstrap::ProjectBootstrapRequest<'_>,
    ) -> StorageResult<PrincipalId> {
        self.current.check_store(store)?;
        if request.project != &self.project || request.policy != &self.policy {
            return Err(StorageError::Conflict(
                "Foreign-owner negative fixture document changed",
            ));
        }
        Ok(PrincipalId::new("different-native-owner-metadata").unwrap())
    }
}
#[test]
fn current_pairing_owner_rejects_an_existing_registration_for_another_owner() {
    let root = Root::new();
    let mut store = root.open();
    let mut project = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
    project["projectId"] = json!("project-owner-mismatch");
    project["prefabIds"] = json!([]);
    project["instanceIds"] = json!([]);
    project["ownedResources"] = json!([]);
    project["policyResourceId"] = json!("policy-owner-mismatch");
    project["resourceIds"] = json!(["policy-owner-mismatch"]);
    project["revision"] = json!(projected_digest("Project", &project).unwrap());
    let policy_document = parse_json(include_bytes!("../../../examples/policy.json")).unwrap();
    let mut permit = ForeignOwnerMetadataFixture {
        current: crate::workspace_bootstrap::NativeOwnerWitness::capture(
            &store,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap(),
        project: project.clone(),
        policy: policy_document.clone(),
    };
    let created = mmmm_runtime::storage::bootstrap::create_project(
        &mut store,
        &mut permit,
        &mmmm_runtime::storage::bootstrap::ProjectBootstrapRequest {
            project: &project,
            policy: &policy_document,
        },
    )
    .unwrap();
    let registered = mmmm_runtime::storage::bootstrap::registered_native_project_owner(
        &store,
        &created.project_id,
    )
    .unwrap();
    assert_ne!(registered, local_owner_principal().unwrap());
    let mut scope = finite_scope();
    scope["projectId"] = json!(created.project_id);
    scope["resourceIds"] = json!([created.policy_resource["resourceId"]]);
    scope["objectIds"] = json!([]);
    let mut fixture =
        observed_pairing_with_store("pair-owner-registration-mismatch", root, store, scope);
    finish_observed_pairing(&mut fixture, true).unwrap();
    let hosts = fixture.processor.hosts.clone();
    let authority = fixture.authority.clone();
    let id = ContextId::new(fixture.context["contextId"].as_str().unwrap()).unwrap();
    let policy = fixture.processor.current_session_policy().unwrap();
    pairing_request_probe(fixture.store, policy, move |store, request| {
        let pairing = hosts.completed_pairing_witness(&request, &authority, &id)?;
        let error = pairing
            .with_current_native_owner(store, &authority, |_| -> mmmm_application::AppResult<()> {
                panic!("Foreign registered owner cannot enter callback")
            })
            .unwrap_err();
        assert_eq!(error.code, "PERMISSION_REQUIRED");
        Ok(())
    });
    fixture.processor.shutdown().unwrap();
}

#[test]
fn current_pairing_owner_rejects_route_replacement_after_callback() {
    let mut fixture = native_owned_pairing_fixture("pair-owner-route-replaced");
    finish_observed_pairing(&mut fixture, true).unwrap();
    let hosts = fixture.processor.hosts.clone();
    let authority = fixture.authority.clone();
    let context = fixture.context.clone();
    let hello = fixture.hello.clone();
    let policy = fixture.processor.current_session_policy().unwrap();
    pairing_request_probe(fixture.store, policy, move |store, request| {
        let id = ContextId::new(context["contextId"].as_str().unwrap()).unwrap();
        let pairing = hosts.completed_pairing_witness(&request, &authority, &id)?;
        let mut replacement = None;
        let result = pairing.with_current_native_owner(store, &authority, |owner| {
            owner.check_current()?;
            replacement = Some(replace_observed_route(&hosts, &context, &hello));
            Ok(19_u8)
        });
        assert_eq!(result.unwrap_err().code, "SESSION_ROUTE_CHANGED");
        hosts.detach_owned(replacement.as_ref().unwrap())?;
        Ok(())
    });
    fixture.processor.shutdown().unwrap();
}

#[test]
fn current_pairing_owner_rejects_callback_result_after_current_cancellation() {
    let mut fixture = native_owned_pairing_fixture("pair-owner-callback-cancelled");
    finish_observed_pairing(&mut fixture, true).unwrap();
    let hosts = fixture.processor.hosts.clone();
    let authority = fixture.authority.clone();
    let id = ContextId::new(fixture.context["contextId"].as_str().unwrap()).unwrap();
    let policy = fixture.processor.current_session_policy().unwrap();
    pairing_request_probe(fixture.store, policy, move |store, request| {
        let pairing = hosts.completed_pairing_witness(&request, &authority, &id)?;
        let result = pairing.with_current_native_owner(store, &authority, |owner| {
            owner.check_current()?;
            request
                .budget()
                .cancellation()
                .store(true, Ordering::Release);
            Ok(23_u8)
        });
        assert_eq!(result.unwrap_err().code, "CANCELLED");
        Ok(())
    });
    fixture.processor.shutdown().unwrap();
}

#[test]
fn current_pairing_owner_keeps_first_callback_error_and_final_cancel_cause() {
    use std::error::Error;
    let mut fixture = native_owned_pairing_fixture("pair-owner-two-failures");
    finish_observed_pairing(&mut fixture, true).unwrap();
    let hosts = fixture.processor.hosts.clone();
    let authority = fixture.authority.clone();
    let id = ContextId::new(fixture.context["contextId"].as_str().unwrap()).unwrap();
    let policy = fixture.processor.current_session_policy().unwrap();
    pairing_request_probe(fixture.store, policy, move |store, request| {
        let pairing = hosts.completed_pairing_witness(&request, &authority, &id)?;
        let error = pairing
            .with_current_native_owner(store, &authority, |_| -> mmmm_application::AppResult<()> {
                request
                    .budget()
                    .cancellation()
                    .store(true, Ordering::Release);
                Err(mmmm_application::AppError::storage(
                    "CALLBACK_SOURCE_UNAVAILABLE",
                    StorageError::NotFound("Actual callback source fixture"),
                ))
            })
            .unwrap_err();
        assert_eq!(error.code, "CALLBACK_SOURCE_UNAVAILABLE");
        let both = error
            .source()
            .unwrap()
            .downcast_ref::<crate::host::NativePairingOwnerFailure>()
            .unwrap();
        assert_eq!(both.primary.code, "CALLBACK_SOURCE_UNAVAILABLE");
        assert!(matches!(
            both.primary
                .source()
                .unwrap()
                .downcast_ref::<StorageError>(),
            Some(StorageError::NotFound(_))
        ));
        assert_eq!(both.checkpoint.code, "CANCELLED");
        assert_eq!(
            both.checkpoint
                .source()
                .unwrap()
                .downcast_ref::<crate::service::ServiceError>()
                .unwrap()
                .code,
            "CANCELLED"
        );
        assert!(!format!("{error:?}").contains("Actual callback source fixture"));
        Ok(())
    });
    fixture.processor.shutdown().unwrap();
}

#[test]
fn current_pairing_owner_rejects_callback_result_after_policy_revocation() {
    let mut fixture = native_owned_pairing_fixture("pair-owner-callback-policy-revoked");
    finish_observed_pairing(&mut fixture, true).unwrap();
    let hosts = fixture.processor.hosts.clone();
    let authority = fixture.authority.clone();
    let context = fixture.context.clone();
    let policy = fixture.processor.current_session_policy().unwrap();
    pairing_request_probe(fixture.store, policy, move |store, request| {
        let id = ContextId::new(context["contextId"].as_str().unwrap()).unwrap();
        let pairing = hosts.completed_pairing_witness(&request, &authority, &id)?;
        let result = pairing.with_current_native_owner(store, &authority, |owner| {
            owner.check_current()?;
            authority.revoke_staged_project(
                pairing.principal(),
                pairing.project(),
                &Sha256Digest::new(context["policyRevision"].as_str().unwrap()).unwrap(),
            )?;
            Ok(29_u8)
        });
        assert_eq!(result.unwrap_err().code, "PERMISSION_REQUIRED");
        Ok(())
    });
    fixture.processor.shutdown().unwrap();
}

#[test]
fn expiration_and_shutdown_preserve_newer_authority_generation() {
    let (mut processor, authority) = processor();
    let principal = PrincipalId::new("player-fixture").unwrap();
    let project = ProjectId::new("project-fixture").unwrap();
    let context_id = ContextId::new("template-context").unwrap();
    let old = authority
        .install_project_access(
            principal.clone(),
            project.clone(),
            finite_scope(),
            BTreeSet::from([context_id.clone()]),
            SESSION_LIFETIME,
        )
        .unwrap();
    processor.active.insert(
        context_id.clone(),
        ActiveBootstrap {
            principal: principal.clone(),
            project: project.clone(),
            policy: old.clone(),
            context_id: context_id.clone(),
            route_owner: None,
            expires: Instant::now() - Duration::from_millis(1),
            _compatibility_failure: None,
        },
    );
    authority
        .revoke_staged_project(&principal, &project, &old)
        .unwrap();
    let replacement = authority
        .install_project_access(
            principal.clone(),
            project.clone(),
            finite_scope(),
            BTreeSet::from([context_id.clone()]),
            SESSION_LIFETIME,
        )
        .unwrap();
    processor.cleanup_expired().unwrap();
    assert!(processor.active.is_empty());
    assert_eq!(
        authority.policy_revision(&principal, &project).unwrap(),
        replacement
    );
    processor.active.insert(
        context_id.clone(),
        ActiveBootstrap {
            principal: principal.clone(),
            project: project.clone(),
            policy: old,
            context_id,
            route_owner: None,
            expires: Instant::now() + SESSION_LIFETIME,
            _compatibility_failure: None,
        },
    );
    processor.shutdown().unwrap();
    assert!(processor.active.is_empty());
    assert_eq!(
        authority.policy_revision(&principal, &project).unwrap(),
        replacement
    );
}

#[test]
fn timely_true_receipt_without_host_observations_never_activates() {
    let root = Root::new();
    let mut store = root.open();
    let project = project(&mut store);
    approve_fixture(&mut store, finite_scope());
    let (mut processor, authority) = processor();
    let offer = offer(&root, "pair-no-observation", finite_scope());
    let witness = offer.witness().clone();
    let budget = BootstrapBudget::new();
    processor
        .handle_with_budget(
            &mut store,
            ManagementRequest::Offer(offer),
            &epoch(),
            &budget,
        )
        .unwrap();
    assert!(
        processor
            .handle_with_budget(
                &mut store,
                native_receipt(&witness, true, &budget),
                &epoch(),
                &budget,
            )
            .is_err()
    );
    assert!(processor.pending.is_empty());
    assert!(
        processor
            .current_session_policy()
            .unwrap()
            .allowed_contexts
            .is_empty()
    );
    assert!(
        authority
            .policy_revision(&PrincipalId::new("player-fixture").unwrap(), &project)
            .is_err()
    );
}

// This fixture supplies only the trusted owner-installation seam. It checks
// actual kernel identity and the one locked Store; it is not a game session or
// proof that live source/profile acquisition has passed.
struct WorkspacePermit(OwnerSetupRpcContext);
impl workspace_seal::Sealed for WorkspacePermit {}
impl NativeWorkspacePermit for WorkspacePermit {
    fn check_project(
        &self,
        store: &DurableStore,
        project: &ProjectId,
    ) -> StorageResult<PrincipalId> {
        self.0.check_store(store)?;
        store.project(project)?;
        self.0.authenticated_local_owner()
    }
}
fn install_owner_workspace(
    store: &DurableStore,
    processor: &mut HostBootstrapProcessor,
    authority: &LocalAuthority,
) -> (ContextId, Sha256Digest) {
    let owner = local_owner_principal().unwrap();
    let project = ProjectId::new("project-fixture").unwrap();
    let context = ContextId::new("native-owner-workspace-fixture").unwrap();
    let scope = json!({"projectId":project,"resourceIds":[],"objectIds":[],"regions":[],"externalTargetIds":[]});
    let policy = authority
        .install_project_access(
            owner.clone(),
            project.clone(),
            scope.clone(),
            BTreeSet::from([context.clone()]),
            Duration::from_secs(60),
        )
        .unwrap();
    let mut value = json!({"contractVersion":"0.2.0","contextId":context,"principalRef":owner,"projectId":project,"environment":{"kind":"offline","workspaceId":"actual-owned-fixture","side":"offline"},"policyRevision":policy,"scope":scope,"contextDigest":"0".repeat(64)});
    value["contextDigest"] = json!(projected_digest("ExecutionContext", &value).unwrap());
    processor
        .install_workspace_context(
            &WorkspacePermit(OwnerSetupRpcContext::for_store(store, None).unwrap()),
            store,
            &value,
        )
        .unwrap();
    (context, policy)
}
#[test]
fn native_owner_workspace_session_checks_current_generation_and_retirement() {
    let root = Root::new();
    let mut store = root.open();
    let project = project(&mut store);
    let (mut processor, authority) = processor();
    let (context, policy) = install_owner_workspace(&store, &mut processor, &authority);
    let current = processor.current_session_policy().unwrap();
    assert_eq!(current.principal, local_owner_principal().unwrap());
    assert_eq!(current.allowed_contexts, BTreeSet::from([context]));
    authority
        .revoke_staged_project(&current.principal, &project, &policy)
        .unwrap();
    assert!(
        processor
            .current_session_policy()
            .unwrap()
            .allowed_contexts
            .is_empty()
    );
    processor.cleanup_expired().unwrap();
    assert!(processor.workspace.is_empty());
    processor.shutdown().unwrap();
    drop(store);
}
#[test]
fn game_principal_session_cannot_union_native_owner_workspace_contexts() {
    let root = Root::new();
    let mut store = root.open();
    let project = project(&mut store);
    let (mut processor, authority) = processor();
    let (owner_context, _) = install_owner_workspace(&store, &mut processor, &authority);
    let player = PrincipalId::new("actual-game-fixture-player").unwrap();
    let game_context = ContextId::new("actual-game-fixture-context").unwrap();
    let scope = json!({"projectId":project,"resourceIds":[],"objectIds":[],"regions":[],"externalTargetIds":[]});
    let policy = authority
        .install_project_access(
            player.clone(),
            project.clone(),
            scope,
            BTreeSet::from([game_context.clone()]),
            Duration::from_secs(60),
        )
        .unwrap();
    processor.active.insert(
        game_context.clone(),
        ActiveBootstrap {
            principal: player.clone(),
            project,
            policy,
            context_id: game_context.clone(),
            route_owner: None,
            expires: Instant::now() + Duration::from_secs(60),
            _compatibility_failure: None,
        },
    );
    let current = processor.current_session_policy().unwrap();
    assert_eq!(current.principal, player);
    assert_eq!(current.allowed_contexts, BTreeSet::from([game_context]));
    assert!(!current.allowed_contexts.contains(&owner_context));
    processor.shutdown().unwrap();
    assert!(processor.workspace.is_empty());
    drop(store);
}

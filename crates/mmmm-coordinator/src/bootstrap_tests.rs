//! Actual owned SQLite and canonical example fixtures exercise admission and
//! rollback. These tests do not authenticate a real game or certify its profile.

use super::*;
use crate::peer_management::management_channel;
use mmmm_application::{Access, AuthorityPort};
use mmmm_contracts::{parse_json, verify_projected_digest};
use mmmm_runtime::storage::StoreConfig;
use std::{
    fs,
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
        project_id: ProjectId::new("project-fixture").unwrap(),
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
        "dataRoot":root.0, "projectId":"project-fixture", "scope":scope,
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
        for payload in [hello, context] {
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
            let remaining = deadline.saturating_duration_since(Instant::now());
            stream
                .set_read_timeout(Some(remaining))
                .map_err(|_| "fixture read timeout")?;
            stream
                .set_write_timeout(Some(remaining))
                .map_err(|_| "fixture write timeout")?;
            let mut header = zeroize::Zeroizing::new(Vec::new());
            loop {
                let mut byte = [0_u8; 1];
                stream
                    .read_exact(&mut byte)
                    .map_err(|_| "host fixture header read")?;
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
    host.join().unwrap().unwrap();
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

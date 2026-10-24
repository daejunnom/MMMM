//! Transport fixtures exercise real bounded TCP and SQLite paths. They cannot
//! establish actual game permissions or game acceptance. The original examples
//! contain no malformed transport or capability attacks, so these negative
//! inputs are constructed here; native credential APIs are never invoked.

use crate::{
    auth::{AuthError, AuthenticatedPrincipal, SessionAuthority, SessionPolicy},
    client::CoordinatorClient,
    credential::{CredentialError, CredentialRef, CredentialStore, SecretToken},
    endpoint::{EndpointRecord, RuntimeDirectory},
    http::{self, HttpError, LoopbackServer},
    rpc::handle_rpc,
    service::{
        ApplicationPorts, ApplicationService, RequestBudget, ServiceDispatcher, ServiceError,
    },
};
use mmmm_application::{
    Access, AppError, AppResult, AuthorityPort, IdKind, IdSource, IndependentObserverPort,
    PlanningPort, PreparedPlan, ProjectInspection, ProviderPort, ReadbackEvidence,
    RecoveryPreparation, SystemClock,
};
use mmmm_contracts::{ContextId, PrincipalId, ProjectId, Sha256Digest, encode_json, parse_json};
use mmmm_runtime::storage::{DurableStore, StorageError, StoreConfig, WriteScope};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const OWNER: &[u8] = b"mmmm-coordinator-owned-test-root\n";
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

#[test]
fn trusted_pairing_policy_replacement_revokes_existing_clones_and_preserves_token() {
    let mut authority = SessionAuthority::new(1).unwrap();
    let (token, handle) = authority
        .install_with_handle(policy(&["prefab.validate"], &[]))
        .unwrap();
    let old = authority.authenticate_token(&token).unwrap();
    let mut invalid = policy(&["artifact.read"], &["paired-context"]);
    invalid.lifetime = Duration::ZERO;
    assert_eq!(
        authority.replace(&handle, invalid),
        Err(AuthError::InvalidPolicy)
    );
    assert!(old.is_current());
    let mut paired = policy(&["artifact.read"], &["paired-context"]);
    paired.principal = PrincipalId::new("verified-game-admin").unwrap();
    authority.replace(&handle, paired).unwrap();
    assert!(!old.is_current());
    assert!(!old.permits("prefab.validate"));
    let fresh = authority.authenticate_token(&token).unwrap();
    assert_eq!(fresh.principal().as_str(), "verified-game-admin");
    assert!(fresh.permits_context("paired-context"));
    assert!(!fresh.permits_context("unpaired-context"));
    assert!(!fresh.permits("plan.apply"));
}

fn prefab() -> Value {
    parse_json(include_bytes!("../../../examples/prefab.json")).unwrap()
}
fn project() -> Value {
    parse_json(include_bytes!("../../../examples/project.json")).unwrap()
}
fn policy(methods: &[&str], contexts: &[&str]) -> SessionPolicy {
    SessionPolicy {
        principal: PrincipalId::new("principal-paired-reader").unwrap(),
        allowed_methods: methods.iter().map(|s| (*s).to_owned()).collect(),
        allowed_contexts: contexts
            .iter()
            .map(|s| ContextId::new(*s).unwrap())
            .collect(),
        lifetime: Duration::from_secs(60),
    }
}
fn session(
    methods: &[&str],
    contexts: &[&str],
) -> (SessionAuthority, SecretToken, AuthenticatedPrincipal) {
    let mut authority = SessionAuthority::new(4).unwrap();
    let token = authority.install(policy(methods, contexts)).unwrap();
    let principal = authority.authenticate_token(&token).unwrap();
    (authority, token, principal)
}
fn budget() -> RequestBudget {
    RequestBudget::new(Duration::from_secs(2), Arc::new(AtomicBool::new(false))).unwrap()
}
fn request(method: &str, input: Value) -> Vec<u8> {
    encode_json(&json!({"jsonrpc":"2.0","id":"request-1","method":method,"params":input})).unwrap()
}
fn response(
    dispatcher: &mut dyn ServiceDispatcher,
    principal: &AuthenticatedPrincipal,
    body: &[u8],
) -> Value {
    parse_json(&handle_rpc(dispatcher, principal, body, &budget())).unwrap()
}

#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<String>>>);
impl Seen {
    fn record(&self, principal: &PrincipalId) {
        self.0.lock().unwrap().push(principal.as_str().to_owned());
    }
    fn values(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}
struct SpyDispatcher {
    seen: Seen,
    invalid_output: bool,
}
impl ServiceDispatcher for SpyDispatcher {
    fn call(
        &mut self,
        principal: &AuthenticatedPrincipal,
        _method: &str,
        _input: &Value,
        budget: &RequestBudget,
    ) -> Result<Value, ServiceError> {
        budget.check()?;
        self.seen.record(principal.principal());
        Ok(if self.invalid_output {
            json!({"unexpected":true})
        } else {
            json!({"diagnostics":[]})
        })
    }
}
fn spy() -> (SpyDispatcher, Seen) {
    let seen = Seen::default();
    (
        SpyDispatcher {
            seen: seen.clone(),
            invalid_output: false,
        },
        seen,
    )
}

#[test]
fn capability_generation_revocation_and_capacity_are_enforced() {
    let (mut authority, token, principal) = session(&["prefab.validate"], &["context-paired"]);
    assert_eq!(principal.principal().as_str(), "principal-paired-reader");
    assert!(principal.permits("prefab.validate"));
    assert!(!principal.permits("plan.apply"));
    assert!(principal.permits_context("context-paired"));
    assert!(!principal.permits_context("context-another-user"));
    let replacement = SessionAuthority::new(4).unwrap();
    assert!(matches!(
        replacement.authenticate_token(&token),
        Err(AuthError::InvalidCapability)
    ));
    authority.revoke(&token);
    assert!(!principal.permits("prefab.validate"));
    assert!(!principal.permits_context("context-paired"));
    assert!(!principal.is_current());
    assert!(matches!(
        authority.authenticate_token(&token),
        Err(AuthError::InvalidCapability)
    ));
    let mut limited = SessionAuthority::new(1).unwrap();
    let first = limited.install(policy(&["prefab.validate"], &[])).unwrap();
    assert!(matches!(
        limited.install(policy(&["prefab.validate"], &[])),
        Err(AuthError::SessionLimit)
    ));
    limited.revoke(&first);
    assert!(limited.install(policy(&["prefab.validate"], &[])).is_ok());
}

#[test]
fn expired_session_cannot_start_another_service_call() {
    let mut authority = SessionAuthority::new(1).unwrap();
    let mut paired = policy(&["prefab.validate"], &[]);
    paired.lifetime = Duration::from_millis(1);
    paired
        .allowed_contexts
        .insert(ContextId::new("context-paired").unwrap());
    let token = authority.install(paired).unwrap();
    let clone = authority.authenticate_token(&token).unwrap();
    thread::sleep(Duration::from_millis(5));
    assert!(matches!(
        authority.authenticate_token(&token),
        Err(AuthError::InvalidCapability)
    ));
    assert!(!clone.is_current());
    assert!(!clone.permits_context("context-paired"));
    let (mut dispatcher, seen) = spy();
    assert_eq!(
        response(
            &mut dispatcher,
            &clone,
            &request("prefab.validate", prefab())
        )["error"]["data"]["code"],
        "PERMISSION_REQUIRED"
    );
    assert!(seen.values().is_empty());
}

#[test]
fn authority_generation_drop_revokes_existing_principal_clones() {
    let (authority, _token, principal) = session(&["prefab.validate"], &["context-paired"]);
    let cloned = principal.clone();
    assert!(cloned.is_current());
    drop(authority);
    assert!(!principal.is_current());
    assert!(!cloned.permits("prefab.validate"));
    assert!(!cloned.permits_context("context-paired"));
}

#[test]
fn principal_authority_and_policy_revision_injections_fail_schema_before_dispatch() {
    let (_authority, _token, principal) = session(&["prefab.validate"], &[]);
    let (mut dispatcher, seen) = spy();
    for (field, value) in [
        ("principal", json!("administrator")),
        ("authority", json!("allow_all")),
        ("policyRevision", json!("fabricated")),
    ] {
        let mut input = prefab();
        input[field] = value;
        let result = response(
            &mut dispatcher,
            &principal,
            &request("prefab.validate", input),
        );
        assert_eq!(result["error"]["code"], -32602);
    }
    assert!(seen.values().is_empty());
    let result = response(
        &mut dispatcher,
        &principal,
        &request("prefab.validate", prefab()),
    );
    assert_eq!(result["result"], json!({"diagnostics":[]}));
    assert_eq!(seen.values(), ["principal-paired-reader"]);
}

#[test]
fn unpaired_context_and_ungranted_method_never_dispatch() {
    let (_authority, _token, principal) = session(&["plan.apply"], &["context-paired"]);
    let (mut dispatcher, seen) = spy();
    let apply = parse_json(include_bytes!("../../../examples/apply-request.json")).unwrap();
    let result = response(&mut dispatcher, &principal, &request("plan.apply", apply));
    assert_eq!(result["error"]["data"]["code"], "PERMISSION_REQUIRED");
    let result = response(
        &mut dispatcher,
        &principal,
        &request("prefab.validate", prefab()),
    );
    assert_eq!(result["error"]["data"]["code"], "PERMISSION_REQUIRED");
    assert!(seen.values().is_empty());
}

#[test]
fn malformed_duplicate_batch_notification_and_internal_methods_never_dispatch() {
    let (_authority, _token, principal) = session(&["prefab.validate"], &[]);
    let (mut dispatcher, seen) = spy();
    for body in [
        br#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"prefab.validate","params":{}}"#
            .as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"prefab.validate","params":{"x":NaN}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"prefab.validate","params":{"x":"\ud800"}}"#
            .as_slice(),
    ] {
        assert_eq!(
            response(&mut dispatcher, &principal, body)["error"]["code"],
            -32700
        );
    }
    for body in [
        br#"[]"#.as_slice(),
        br#"{"jsonrpc":"2.0","method":"prefab.validate","params":{}}"#.as_slice(),
        br#"{"jsonrpc":"1.0","id":1,"method":"prefab.validate","params":{}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1.25,"method":"prefab.validate","params":{}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"prefab.validate","params":{},"principal":"admin"}"#
            .as_slice(),
    ] {
        assert_eq!(
            response(&mut dispatcher, &principal, body)["error"]["code"],
            -32600
        );
    }
    assert_eq!(
        response(
            &mut dispatcher,
            &principal,
            &request("coordinator.issuecapability", json!({}))
        )["error"]["code"],
        -32601
    );
    assert!(seen.values().is_empty());
}

#[test]
fn cancellation_and_output_contract_remain_at_the_service_boundary() {
    let (_authority, _token, principal) = session(&["prefab.validate"], &[]);
    let (mut dispatcher, seen) = spy();
    let cancelled =
        RequestBudget::new(Duration::from_secs(1), Arc::new(AtomicBool::new(true))).unwrap();
    let result = parse_json(&handle_rpc(
        &mut dispatcher,
        &principal,
        &request("prefab.validate", prefab()),
        &cancelled,
    ))
    .unwrap();
    assert_eq!(result["error"]["data"]["code"], "TIME_BUDGET_EXCEEDED");
    assert!(seen.values().is_empty());
    dispatcher.invalid_output = true;
    assert_eq!(
        response(
            &mut dispatcher,
            &principal,
            &request("prefab.validate", prefab())
        )["error"]["data"]["code"],
        "OUTPUT_SCHEMA_INVALID"
    );
    assert_eq!(seen.values().len(), 1);
}

#[test]
fn oversized_and_overpopulated_control_json_never_dispatch() {
    let (_authority, _token, principal) = session(&["prefab.validate"], &[]);
    let (mut dispatcher, seen) = spy();
    let oversized = vec![b' '; crate::rpc::MAX_CONTROL_BYTES + 1];
    assert_eq!(
        response(&mut dispatcher, &principal, &oversized)["error"]["code"],
        -32700
    );
    let populated =
        serde_json::to_vec(&json!({"entries":vec![Value::Null; crate::rpc::MAX_CONTROL_NODES]}))
            .unwrap();
    assert_eq!(
        response(&mut dispatcher, &principal, &populated)["error"]["code"],
        -32700
    );
    assert!(seen.values().is_empty());
}

fn socket_pair() -> (TcpStream, TcpStream, SocketAddr) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
    let (server, _) = listener.accept().unwrap();
    client.set_nodelay(true).unwrap();
    server.set_nodelay(true).unwrap();
    (client, server, address)
}
fn http_frame(
    address: SocketAddr,
    epoch: &str,
    bearer: &str,
    body: &[u8],
    extra_headers: &str,
) -> Vec<u8> {
    let mut bytes = format!("POST /rpc HTTP/1.1\r\nHost: {address}\r\nX-MMMM-Epoch: {epoch}\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
fn parse_frame(
    frame: impl FnOnce(SocketAddr) -> Vec<u8>,
    epoch: &str,
) -> Result<Vec<u8>, HttpError> {
    let (mut client, mut server, address) = socket_pair();
    client
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client.write_all(&frame(address)).unwrap();
    http::read_request(
        &mut server,
        address,
        epoch,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
    )
    .map(|request| request.body)
}

#[test]
fn http_rejects_duplicate_headers_origin_and_wrong_epoch() {
    let bearer = "a".repeat(64);
    for extra in [
        "Authorization: Bearer duplicate\r\n",
        "content-LENGTH: 2\r\n",
        "X-MMMM-Epoch: coordinator-other\r\n",
    ] {
        assert!(matches!(
            parse_frame(
                |address| http_frame(address, "coordinator-current", &bearer, b"{}", extra),
                "coordinator-current"
            ),
            Err(HttpError::Malformed)
        ));
    }
    for extra in [
        "Origin: https://example.invalid\r\n",
        "Referer: https://example.invalid/page\r\n",
        "Sec-Fetch-Site: same-origin\r\n",
    ] {
        assert!(matches!(
            parse_frame(
                |address| http_frame(address, "coordinator-current", &bearer, b"{}", extra),
                "coordinator-current"
            ),
            Err(HttpError::Origin)
        ));
    }
    assert!(
        parse_frame(
            |address| http_frame(address, "coordinator-stale", &bearer, b"{}", ""),
            "coordinator-current"
        )
        .is_err()
    );
    assert_eq!(
        parse_frame(
            |address| http_frame(address, "coordinator-current", &bearer, b"{}", ""),
            "coordinator-current"
        )
        .unwrap(),
        b"{}"
    );
}

#[test]
fn http_total_deadline_is_not_extended_by_small_continuous_reads() {
    let (mut client, mut server, address) = socket_pair();
    client
        .set_write_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let frame = http_frame(address, "coordinator-current", &"a".repeat(64), b"{}", "");
    let sender = thread::spawn(move || {
        for byte in frame.iter().take(40) {
            if client.write_all(&[*byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
    });
    let started = Instant::now();
    let result = http::read_request(
        &mut server,
        address,
        "coordinator-current",
        started + Duration::from_millis(120),
        &AtomicBool::new(false),
    );
    assert!(matches!(result, Err(HttpError::Budget)));
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(server);
    sender.join().unwrap();
}

#[test]
fn http_rejects_unbounded_body_and_ambiguous_framing_before_reading_payload() {
    let bearer = "a".repeat(64);
    let oversized = parse_frame(
        |address| {
            format!("POST /rpc HTTP/1.1\r\nHost: {address}\r\nX-MMMM-Epoch: coordinator-current\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", crate::rpc::MAX_CONTROL_BYTES + 1).into_bytes()
        },
        "coordinator-current",
    );
    assert!(matches!(oversized, Err(HttpError::Budget)));
    assert!(matches!(
        parse_frame(
            |address| http_frame(
                address,
                "coordinator-current",
                &bearer,
                b"{}",
                "Transfer-Encoding: chunked\r\n"
            ),
            "coordinator-current"
        ),
        Err(HttpError::Malformed)
    ));
    assert!(matches!(
        parse_frame(
            |address| {
                http_frame(address, "coordinator-current", &bearer, b"{}", "")
                    .strip_prefix(b"POST")
                    .map(|rest| [b"GET".as_slice(), rest].concat())
                    .unwrap()
            },
            "coordinator-current"
        ),
        Err(HttpError::Malformed)
    ));
}

struct RunningServer {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<Result<(), String>>>,
}
impl RunningServer {
    fn finish(mut self) {
        self.stop.store(true, Ordering::Release);
        self.join.take().unwrap().join().unwrap().unwrap();
    }
}
impl Drop for RunningServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[test]
fn unauthenticated_http_is_rejected_before_json_or_dispatch() {
    let (authority, _token, _) = session(&["prefab.validate"], &[]);
    let server = LoopbackServer::bind().unwrap();
    let address = server.address();
    let epoch = server.epoch().to_owned();
    let (mut dispatcher, seen) = spy();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let running = RunningServer {
        stop,
        join: Some(thread::spawn(move || {
            server
                .serve(&authority, &mut dispatcher, server_stop)
                .map_err(|e| e.to_string())
        })),
    };
    let mut client = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let unpaired = SecretToken::generate().unwrap();
    let bearer = unpaired.bearer();
    client
        .write_all(&http_frame(
            address,
            &epoch,
            &bearer,
            b"{duplicate malformed body",
            "",
        ))
        .unwrap();
    let mut bytes = Vec::new();
    client.take(4096).read_to_end(&mut bytes).unwrap();
    assert!(bytes.starts_with(b"HTTP/1.1 401 Unauthorized\r\n"));
    assert!(seen.values().is_empty());
    running.finish();
}

struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = parent.join(format!(
            "mmmm-coordinator-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let checkout =
            fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        assert!(root.is_absolute() && !root.starts_with(checkout));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(root.join("test-owner.txt"), OWNER).unwrap();
        Self(root)
    }
    fn config(&self) -> StoreConfig {
        StoreConfig::new(self.0.clone())
    }
}
fn owned_plain_tree(root: &Path) -> bool {
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    let mut count = 0;
    while let Some((path, depth)) = pending.pop() {
        count += 1;
        if count > 4096 || depth > 32 || !path.is_absolute() || !path.starts_with(root) {
            return false;
        }
        let Ok(metadata) = fs::symlink_metadata(&path) else {
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
            let Ok(entries) = fs::read_dir(&path) else {
                return false;
            };
            for entry in entries {
                let Ok(entry) = entry else {
                    return false;
                };
                pending.push((entry.path(), depth + 1));
            }
        } else if !metadata.is_file() {
            return false;
        }
    }
    true
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        // Only this freshly created fixture's exact external root is eligible.
        // Failed boundary checks retain it for diagnosis rather than broadening
        // cleanup or following links into any product/runtime data.
        if owned_plain_tree(&self.0)
            && fs::read(self.0.join("test-owner.txt")).ok().as_deref() == Some(OWNER)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[derive(Clone)]
struct ReadOnlyPorts {
    seen: Seen,
}
fn unavailable<T>() -> AppResult<T> {
    Err(AppError::new(
        "TEST_UNAVAILABLE",
        "The read-only fixture has no host executor",
    ))
}
impl AuthorityPort for ReadOnlyPorts {
    fn authorize(
        &mut self,
        principal: &PrincipalId,
        _project: &ProjectId,
        access: Access,
        _context: Option<&Value>,
        _plan: Option<&Value>,
    ) -> AppResult<()> {
        self.seen.record(principal);
        if access == Access::ReadProject {
            Ok(())
        } else {
            unavailable()
        }
    }
}
impl PlanningPort for ReadOnlyPorts {
    fn inspect_project(
        &mut self,
        principal: &PrincipalId,
        _project: &Value,
    ) -> AppResult<ProjectInspection> {
        self.seen.record(principal);
        Ok(ProjectInspection {
            diagnostics: vec![],
            unresolved_references: vec![],
            runtime_bindings_available: false,
        })
    }
    fn prepare(
        &mut self,
        _principal: &PrincipalId,
        _request: &Value,
        _project: &Value,
        _context: &Value,
    ) -> AppResult<PreparedPlan> {
        unavailable()
    }
    fn prepare_recovery(
        &mut self,
        _principal: &PrincipalId,
        _recovery: &RecoveryPreparation,
        _project: &Value,
        _context: &Value,
    ) -> AppResult<PreparedPlan> {
        unavailable()
    }
}
impl ProviderPort for ReadOnlyPorts {
    fn context(&mut self, _principal: &PrincipalId, _context: &ContextId) -> AppResult<Value> {
        unavailable()
    }
    fn action_descriptor(&mut self, _step: &Value, _context: &Value) -> AppResult<Value> {
        unavailable()
    }
    fn observe_precondition(
        &mut self,
        _precondition: &Value,
        _context: &Value,
    ) -> AppResult<Sha256Digest> {
        unavailable()
    }
    fn verify_dependencies(
        &mut self,
        _dependency_pins: &[Value],
        _context: &Value,
    ) -> AppResult<()> {
        unavailable()
    }
    fn dispatch(&mut self, _invocation: &Value) -> AppResult<Value> {
        unavailable()
    }
    fn poll(&mut self, _invocation: &Value, _receipt: Option<&str>) -> AppResult<Option<Value>> {
        unavailable()
    }
    fn request_cancel(&mut self, _invocation: &Value, _receipt: Option<&str>) -> AppResult<()> {
        unavailable()
    }
}
impl IndependentObserverPort for ReadOnlyPorts {
    fn readback(
        &mut self,
        _invocation: &Value,
        _scope: &WriteScope,
    ) -> AppResult<ReadbackEvidence> {
        unavailable()
    }
    fn read_target(&mut self, _invocation: &Value, _target: &str) -> AppResult<Vec<u8>> {
        unavailable()
    }
}
impl IdSource for ReadOnlyPorts {
    fn next_id(&mut self, _kind: IdKind) -> AppResult<String> {
        unavailable()
    }
}
fn ports(seen: Seen) -> ApplicationPorts {
    let fixture = ReadOnlyPorts { seen };
    ApplicationPorts {
        authority: Box::new(fixture.clone()),
        planner: Box::new(fixture.clone()),
        provider: Box::new(fixture.clone()),
        observer: Box::new(fixture.clone()),
        ids: Box::new(fixture),
        clock: Box::new(SystemClock),
    }
}

#[test]
fn application_service_owns_one_store_and_authenticates_actual_project_inspection() {
    let root = TestRoot::new();
    let seen = Seen::default();
    let mut service = ApplicationService::open(root.config(), ports(seen.clone())).unwrap();
    service.bootstrap_project(&project()).unwrap();
    assert!(matches!(
        DurableStore::open(root.config()),
        Err(StorageError::Busy)
    ));
    let (_authority, _token, principal) = session(&["project.inspect"], &[]);
    let query = json!({"projectId":"project-fixture", "expectedRevision":null});
    let result = response(
        &mut service,
        &principal,
        &request("project.inspect", query.clone()),
    );
    assert_eq!(result["result"]["project"], project());
    assert_eq!(result["result"]["runtimeBindingsAvailable"], false);
    assert_eq!(
        seen.values(),
        ["principal-paired-reader", "principal-paired-reader"]
    );
    let mut injected = query;
    injected["principal"] = json!("administrator");
    assert_eq!(
        response(
            &mut service,
            &principal,
            &request("project.inspect", injected)
        )["error"]["code"],
        -32602
    );
    assert_eq!(seen.values().len(), 2);
    drop(service);
    drop(DurableStore::open(root.config()).unwrap());
}

#[test]
fn actual_loopback_client_uses_original_prefab_and_shared_application_service() {
    let root = TestRoot::new();
    let config = root.config();
    let server = LoopbackServer::bind().unwrap();
    let endpoint = EndpointRecord {
        schema_version: 1,
        contract_version: "0.2.0".into(),
        address: server.address(),
        path: "/rpc".into(),
        coordinator_epoch: server.epoch().to_owned(),
        credential_ref: "MMMM.coordinator.loopback-fixture".into(),
    };
    let (authority, token, _) = session(&["prefab.validate"], &[]);
    let mut stale_endpoint = endpoint.clone();
    stale_endpoint.coordinator_epoch.push_str("-stale");
    let stale =
        CoordinatorClient::paired(stale_endpoint, SecretToken::parse(&token.bearer()).unwrap())
            .unwrap();
    let client = CoordinatorClient::paired(endpoint, token).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let (ready_send, ready_receive) = mpsc::sync_channel(1);
    let running = RunningServer {
        stop,
        join: Some(thread::spawn(move || {
            let mut service = ApplicationService::open(config, ports(Seen::default()))
                .map_err(|e| e.to_string())?;
            ready_send.send(()).map_err(|e| e.to_string())?;
            server
                .serve(&authority, &mut service, server_stop)
                .map_err(|e| e.to_string())
        })),
    };
    ready_receive.recv_timeout(Duration::from_secs(5)).unwrap();
    let input = prefab();
    let expected = mmmm_domain::prefab_validate(&input).unwrap();
    assert!(stale.call("prefab.validate", &input).is_err());
    let result = client.call("prefab.validate", &input).unwrap();
    assert_eq!(result, expected);
    assert_eq!(input, prefab());
    assert!(matches!(
        DurableStore::open(root.config()),
        Err(StorageError::Busy)
    ));
    running.finish();
    drop(DurableStore::open(root.config()).unwrap());
}

/// Explicit in-memory test double. It never accesses native credential stores,
/// environment secrets, credential files, or user-owned authentication state.
#[derive(Clone, Default)]
struct MemoryCredentials {
    entries: Arc<Mutex<BTreeMap<CredentialRef, SecretToken>>>,
    fail_put: Arc<AtomicBool>,
    fail_remove: Arc<AtomicBool>,
}
impl CredentialStore for MemoryCredentials {
    fn put(&self, reference: &CredentialRef, token: &SecretToken) -> Result<(), CredentialError> {
        if self.fail_put.load(Ordering::Acquire) {
            return Err(CredentialError::UnsupportedPlatform);
        }
        let copied = SecretToken::parse(&token.bearer())?;
        self.entries
            .lock()
            .unwrap()
            .insert(reference.clone(), copied);
        Ok(())
    }
    fn get(&self, reference: &CredentialRef) -> Result<SecretToken, CredentialError> {
        let entries = self.entries.lock().unwrap();
        let token = entries.get(reference).ok_or(CredentialError::NotFound)?;
        SecretToken::parse(&token.bearer())
    }
    fn remove(&self, reference: &CredentialRef) -> Result<(), CredentialError> {
        if self.fail_remove.load(Ordering::Acquire) {
            return Err(CredentialError::UnsupportedPlatform);
        }
        self.entries.lock().unwrap().remove(reference);
        Ok(())
    }
}

#[test]
fn injected_memory_credential_lifecycle_publishes_then_cleans_exact_discovery() {
    let root = TestRoot::new();
    let credentials = MemoryCredentials::default();
    let service = ApplicationService::open(root.config(), ports(Seen::default())).unwrap();
    let coordinator = crate::Coordinator::start_with_native(
        service,
        policy(&["prefab.validate"], &[]),
        Box::new(credentials.clone()),
    )
    .unwrap();
    let record = coordinator.endpoint().clone();
    let runtime = RuntimeDirectory::open(&root.0.join("runtime")).unwrap();
    assert_eq!(runtime.load().unwrap(), record);
    assert_eq!(credentials.entries.lock().unwrap().len(), 1);
    assert_eq!(
        CoordinatorClient::discover(&root.0.join("runtime"), &credentials)
            .unwrap()
            .address(),
        record.address
    );
    assert!(matches!(
        ApplicationService::open(root.config(), ports(Seen::default())),
        Err(StorageError::Busy)
    ));
    coordinator.shutdown().unwrap();
    assert!(matches!(
        runtime.load(),
        Err(crate::endpoint::EndpointError::Missing)
    ));
    assert!(credentials.entries.lock().unwrap().is_empty());
    drop(runtime);
    drop(DurableStore::open(root.config()).unwrap());
}

#[test]
fn injected_credential_put_failure_never_publishes_an_endpoint() {
    let root = TestRoot::new();
    let credentials = MemoryCredentials::default();
    credentials.fail_put.store(true, Ordering::Release);
    let service = ApplicationService::open(root.config(), ports(Seen::default())).unwrap();
    let failed = crate::Coordinator::start_with_native(
        service,
        policy(&["prefab.validate"], &[]),
        Box::new(credentials.clone()),
    );
    assert!(matches!(
        failed,
        Err(crate::lifecycle::CoordinatorError::Credential)
    ));
    let runtime = RuntimeDirectory::open(&root.0.join("runtime")).unwrap();
    assert!(matches!(
        runtime.load(),
        Err(crate::endpoint::EndpointError::Missing)
    ));
    assert!(credentials.entries.lock().unwrap().is_empty());
    drop(runtime);
    drop(DurableStore::open(root.config()).unwrap());
}

#[test]
fn simulated_crash_restart_rotates_generation_and_removes_only_prior_mock_reference() {
    let root = TestRoot::new();
    let credentials = MemoryCredentials::default();
    let first_service = ApplicationService::open(root.config(), ports(Seen::default())).unwrap();
    let first = crate::Coordinator::start_with_native(
        first_service,
        policy(&["prefab.validate"], &[]),
        Box::new(credentials.clone()),
    )
    .unwrap();
    let old = first.endpoint().clone();
    let old_ref = CredentialRef::new(&old.credential_ref).unwrap();
    assert!(credentials.get(&old_ref).is_ok());
    // No explicit shutdown: simulate dropped runtime state while the durable
    // root and exact valid discovery record remain. This is not a native crash.
    drop(first);
    let next_service = ApplicationService::open(root.config(), ports(Seen::default())).unwrap();
    let next = crate::Coordinator::start_with_native(
        next_service,
        policy(&["prefab.validate"], &[]),
        Box::new(credentials.clone()),
    )
    .unwrap();
    let current = next.endpoint().clone();
    assert_ne!(current.coordinator_epoch, old.coordinator_epoch);
    assert_ne!(current.credential_ref, old.credential_ref);
    assert!(matches!(
        credentials.get(&old_ref),
        Err(CredentialError::NotFound)
    ));
    assert_eq!(credentials.entries.lock().unwrap().len(), 1);
    let runtime = RuntimeDirectory::open(&root.0.join("runtime")).unwrap();
    assert_eq!(runtime.load().unwrap(), current);
    assert!(!runtime.remove_if_epoch(&old.coordinator_epoch).unwrap());
    assert_eq!(runtime.load().unwrap(), current);
    next.shutdown().unwrap();
    drop(runtime);
    assert!(credentials.entries.lock().unwrap().is_empty());
}

#[test]
fn injected_credential_cleanup_failure_is_reported_and_does_not_claim_clean_shutdown() {
    let root = TestRoot::new();
    let credentials = MemoryCredentials::default();
    let service = ApplicationService::open(root.config(), ports(Seen::default())).unwrap();
    let coordinator = crate::Coordinator::start_with_native(
        service,
        policy(&["prefab.validate"], &[]),
        Box::new(credentials.clone()),
    )
    .unwrap();
    let record = coordinator.endpoint().clone();
    let reference = CredentialRef::new(&coordinator.endpoint().credential_ref).unwrap();
    credentials.fail_remove.store(true, Ordering::Release);
    assert!(matches!(
        coordinator.shutdown(),
        Err(crate::lifecycle::CoordinatorError::Cleanup)
    ));
    assert!(credentials.get(&reference).is_ok());
    let runtime = RuntimeDirectory::open(&root.0.join("runtime")).unwrap();
    assert_eq!(runtime.load().unwrap(), record);
    // The fixture owner explicitly resolves its injected RAM-only failure.
    credentials.fail_remove.store(false, Ordering::Release);
    credentials.remove(&reference).unwrap();
    assert!(runtime.remove_if_epoch(&record.coordinator_epoch).unwrap());
    drop(runtime);
    drop(DurableStore::open(root.config()).unwrap());
}
#[path = "peer_tests.rs"]
mod peer_tests;

#[path = "artifact_tests.rs"]
mod artifact_tests;

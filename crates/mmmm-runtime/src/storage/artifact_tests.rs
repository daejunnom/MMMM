//! These disk fixtures exercise CAS/ACL failures that the handoff's static
//! examples cannot induce. They are local storage checks, not game evidence.

use super::*;
use crate::storage::{
    DispatchEvidence, EffectEvidence, OperationState, ReserveOperation, StepObservation,
    StoreConfig,
};
use mmmm_contracts::{PlanId, StepId, raw_digest};
use std::{
    cell::Cell,
    collections::BTreeSet,
    fs,
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = parent.join(format!(
            "mmmm-artifact-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(root.is_absolute());
        assert!(!root.starts_with(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(root.join("test-owner.txt"), b"mmmm-artifact-test\n").unwrap();
        Self(root)
    }
    fn open(&self) -> DurableStore {
        DurableStore::open(StoreConfig::new(self.0.clone())).unwrap()
    }
    fn blob_path(&self, blob: &BlobRef) -> PathBuf {
        self.0
            .join("blobs")
            .join(&blob.digest.as_str()[..2])
            .join(&blob.digest.as_str()[2..])
    }
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        if fs::read(self.0.join("test-owner.txt")).ok().as_deref() == Some(b"mmmm-artifact-test\n")
            && super::super::cas::verify_plain_path(&self.0).is_ok()
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

struct TestRpc {
    principal: PrincipalId,
    context: ContextId,
    checks: Cell<usize>,
    cancel_after: Option<usize>,
}
impl TestRpc {
    fn new() -> Self {
        Self {
            principal: PrincipalId::new("principal-artifact").unwrap(),
            context: ContextId::new("context-artifact").unwrap(),
            checks: Cell::new(0),
            cancel_after: None,
        }
    }
}
impl ArtifactRpcContext for TestRpc {
    fn check(&self) -> ArtifactResult<()> {
        let count = self.checks.get() + 1;
        self.checks.set(count);
        if self.cancel_after.is_some_and(|limit| count >= limit) {
            return Err(ArtifactError::new("CANCELLED", "Read was cancelled"));
        }
        Ok(())
    }
    fn principal_for_context(&self, context: &ContextId) -> ArtifactResult<PrincipalId> {
        self.check()?;
        if context != &self.context {
            return Err(ArtifactError::forbidden());
        }
        Ok(self.principal.clone())
    }
}
struct TestAuthority {
    allowed_ids: BTreeSet<String>,
    calls: Rc<Cell<usize>>,
    deny_on_call: Option<usize>,
}
impl ResourceAuthority for TestAuthority {
    fn authorize_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        _context: &ContextId,
        owner: &ResourceOwner,
        resource: &Value,
    ) -> ArtifactResult<()> {
        self.calls.set(self.calls.get() + 1);
        if self
            .deny_on_call
            .is_some_and(|limit| self.calls.get() >= limit)
            || !self
                .allowed_ids
                .contains(resource["resourceId"].as_str().unwrap())
            || matches!(owner, ResourceOwner::Principal(p) if p != principal)
        {
            return Err(ArtifactError::forbidden());
        }
        Ok(())
    }
}
fn reader(ids: &[&str]) -> (ArtifactReader, Rc<Cell<usize>>) {
    let calls = Rc::new(Cell::new(0));
    let authority = TestAuthority {
        allowed_ids: ids.iter().map(|id| (*id).to_owned()).collect(),
        calls: calls.clone(),
        deny_on_call: None,
    };
    (
        ArtifactReader::new(Box::new(authority), 8 * 1024 * 1024).unwrap(),
        calls,
    )
}
fn register(store: &mut DurableStore, id: &str, bytes: &[u8]) -> (Value, BlobRef) {
    let blob = store.put_blob(bytes).unwrap();
    let resource = json!({"resourceId":id,"sha256":blob.digest,"sizeBytes":blob.byte_length,"mediaType":"application/octet-stream"});
    register_resource(
        store,
        &resource,
        ResourceOwner::Principal(PrincipalId::new("principal-artifact").unwrap()),
    )
    .unwrap();
    (resource, blob)
}
fn request(id: &str, offset: &str, limit: u64) -> Value {
    json!({"contextId":"context-artifact","resourceId":id,"offset":offset,"limitBytes":limit})
}
fn operation(store: &mut DurableStore, name: &str) -> OperationId {
    let plan = parse_json(include_bytes!("../../../../examples/execution-plan.json")).unwrap();
    store.save_plan(&plan).unwrap();
    let operation = OperationId::new(name).unwrap();
    store
        .reserve_operation(ReserveOperation {
            operation_id: operation.clone(),
            principal: PrincipalId::new("principal-fixture").unwrap(),
            project_id: ProjectId::new("project-fixture").unwrap(),
            idempotency_key: name.to_owned(),
            plan_id: PlanId::new(plan["planId"].as_str().unwrap()).unwrap(),
            plan_hash: serde_json::from_value(plan["planHash"].clone()).unwrap(),
            context_id: ContextId::new("context-fixture-01").unwrap(),
        })
        .unwrap();
    operation
}

#[test]
fn utf8_boundaries_binary_ranges_and_eof_preserve_exact_bytes() {
    let root = TestRoot::new();
    let mut store = root.open();
    register(&mut store, "resource-text", "a한😀z".as_bytes());
    register(&mut store, "resource-empty", b"");
    register(&mut store, "resource-binary", &[0xff, 0, 0x80]);
    let (mut reader, _) = reader(&["resource-text", "resource-empty", "resource-binary"]);
    let rpc = TestRpc::new();
    let full = reader
        .read(&store, &rpc, &request("resource-text", "0", 65_536))
        .unwrap();
    assert_eq!(full["encoding"], "utf8");
    assert_eq!(full["data"], "a한😀z");
    assert!(full["nextOffset"].is_null());
    let korean = reader
        .read(&store, &rpc, &request("resource-text", "1", 3))
        .unwrap();
    assert_eq!(korean["data"], "한");
    assert_eq!(korean["nextOffset"], "4");
    for (offset, limit) in [(1, 1), (2, 2), (4, 3), (5, 3)] {
        let slice = reader
            .read(
                &store,
                &rpc,
                &request("resource-text", &offset.to_string(), limit),
            )
            .unwrap();
        assert_eq!(slice["encoding"], "base64");
        let exact = &"a한😀z".as_bytes()[offset as usize..(offset + limit) as usize];
        assert_eq!(
            STANDARD.decode(slice["data"].as_str().unwrap()).unwrap(),
            exact
        );
    }
    let binary = reader
        .read(&store, &rpc, &request("resource-binary", "0", 3))
        .unwrap();
    assert_eq!(binary["encoding"], "base64");
    assert_eq!(binary["data"], "/wCA");
    for (id, offset) in [("resource-text", "9"), ("resource-empty", "0")] {
        let eof = reader.read(&store, &rpc, &request(id, offset, 1)).unwrap();
        assert_eq!(eof["data"], "");
        assert!(eof["nextOffset"].is_null());
    }
}

#[test]
fn maximum_slice_and_control_characters_are_bounded_before_json_encoding() {
    let root = TestRoot::new();
    let mut store = root.open();
    register(&mut store, "resource-control", &vec![0; 65_537]);
    let (mut reader, _) = reader(&["resource-control"]);
    let output = reader
        .read(
            &store,
            &TestRpc::new(),
            &request("resource-control", "0", 65_536),
        )
        .unwrap();
    assert_eq!(output["data"].as_str().unwrap().len(), 65_536);
    assert_eq!(output["nextOffset"], "65536");
    assert!(encode_json(&output).unwrap().len() < 1024 * 1024);
}

#[test]
fn decimal_overflow_and_invalid_limits_do_not_wrap_or_repair() {
    let root = TestRoot::new();
    let mut store = root.open();
    register(&mut store, "resource-range", b"range");
    let (mut reader, _) = reader(&["resource-range"]);
    let rpc = TestRpc::new();
    for offset in [
        "6",
        "18446744073709551616",
        "9999999999999999999999999999999999999999",
    ] {
        assert_eq!(
            reader
                .read(&store, &rpc, &request("resource-range", offset, 1))
                .unwrap_err()
                .code,
            "RANGE_INVALID"
        );
    }
    for offset in ["00", "-1", "1.0"] {
        assert_eq!(
            reader
                .read(&store, &rpc, &request("resource-range", offset, 1))
                .unwrap_err()
                .code,
            "INPUT_INVALID"
        );
    }
    for limit in [0, 65_537] {
        assert_eq!(
            reader
                .read(&store, &rpc, &request("resource-range", "0", limit))
                .unwrap_err()
                .code,
            "INPUT_INVALID"
        );
    }
    let mut input = request("resource-range", "0", 1);
    input["uri"] = json!("file:///private-data");
    assert_eq!(
        reader.read(&store, &rpc, &input).unwrap_err().code,
        "INPUT_INVALID"
    );
}

#[test]
fn digest_equality_does_not_grant_another_resource_or_context() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (_, blob) = register(&mut store, "resource-allowed", b"same");
    register(&mut store, "resource-forbidden", b"same");
    let (mut reader, calls) = reader(&["resource-allowed"]);
    let rpc = TestRpc::new();
    assert!(
        reader
            .read(&store, &rpc, &request("resource-allowed", "0", 4))
            .is_ok()
    );
    fs::remove_file(root.blob_path(&blob)).unwrap();
    assert_eq!(
        reader
            .read(&store, &rpc, &request("resource-forbidden", "0", 4))
            .unwrap_err(),
        ArtifactError::forbidden()
    );
    let before = calls.get();
    let mut wrong = request("resource-allowed", "0", 4);
    wrong["contextId"] = json!("context-unpaired");
    assert_eq!(
        reader.read(&store, &rpc, &wrong).unwrap_err(),
        ArtifactError::forbidden()
    );
    assert_eq!(calls.get(), before);
    let mut stranger = TestRpc::new();
    stranger.principal = PrincipalId::new("principal-stranger").unwrap();
    assert_eq!(
        reader
            .read(&store, &stranger, &request("resource-allowed", "0", 4))
            .unwrap_err(),
        ArtifactError::forbidden()
    );
}

#[test]
fn final_acl_recheck_rejects_revocation_before_releasing_data() {
    let root = TestRoot::new();
    let mut store = root.open();
    register(&mut store, "resource-revoked", b"private");
    let calls = Rc::new(Cell::new(0));
    let authority = TestAuthority {
        allowed_ids: BTreeSet::from(["resource-revoked".into()]),
        calls: calls.clone(),
        deny_on_call: Some(2),
    };
    let mut reader = ArtifactReader::new(Box::new(authority), 1024).unwrap();
    assert_eq!(
        reader
            .read(
                &store,
                &TestRpc::new(),
                &request("resource-revoked", "0", 7)
            )
            .unwrap_err(),
        ArtifactError::forbidden()
    );
    assert_eq!(calls.get(), 2);
}

#[test]
fn cancellation_and_verification_budget_reject_without_partial_output() {
    let root = TestRoot::new();
    let mut store = root.open();
    register(&mut store, "resource-long", &vec![b'x'; 200_000]);
    let (mut reader, _) = reader(&["resource-long"]);
    let mut cancelled = TestRpc::new();
    cancelled.cancel_after = Some(12);
    assert_eq!(
        reader
            .read(&store, &cancelled, &request("resource-long", "0", 1))
            .unwrap_err()
            .code,
        "CANCELLED"
    );
    assert!(cancelled.checks.get() >= 12);
    reader.max_verification_bytes = 1024;
    assert_eq!(
        reader
            .read(&store, &TestRpc::new(), &request("resource-long", "0", 1))
            .unwrap_err()
            .code,
        "RESOURCE_READ_BUDGET_EXCEEDED"
    );
}

#[test]
fn corruption_outside_the_range_and_length_changes_are_not_hidden() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (_, blob) = register(&mut store, "resource-corrupt", &vec![b'a'; 100_000]);
    let (mut reader, _) = reader(&["resource-corrupt"]);
    let rpc = TestRpc::new();
    let mut changed = vec![b'a'; 100_000];
    changed[99_999] = b'b';
    fs::write(root.blob_path(&blob), &changed).unwrap();
    let failure = reader
        .read(&store, &rpc, &request("resource-corrupt", "0", 1))
        .unwrap_err();
    assert_eq!(failure.code, "RESOURCE_INTEGRITY_FAILED");
    assert!(!failure.to_string().contains(root.0.to_str().unwrap()));
    for length in [99_999, 100_001] {
        fs::write(root.blob_path(&blob), vec![b'a'; length]).unwrap();
        assert_eq!(
            reader
                .read(&store, &rpc, &request("resource-corrupt", "0", 1))
                .unwrap_err()
                .code,
            "RESOURCE_INTEGRITY_FAILED"
        );
    }
}

#[test]
fn returned_slice_is_captured_in_the_same_pass_that_hashes_it() {
    let root = TestRoot::new();
    let store = root.open();
    let original = vec![b'a'; 131_072];
    let blob = store.put_blob(&original).unwrap();
    let path = root.blob_path(&blob);
    let mut checks = 0;
    let slice = store
        .cas
        .read_verified_slice::<StorageError, _>(&blob, 0, 1, || {
            checks += 1;
            if checks == 5 {
                let mut altered = original.clone();
                altered[0] = b'z';
                fs::write(&path, altered)?;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(slice, b"a");
    assert_eq!(fs::read(&path).unwrap()[0], b'z');
    assert_ne!(raw_digest(&fs::read(path).unwrap()), blob.digest);
}

#[test]
fn diagnostic_registration_keeps_actual_artifact_cas_and_sql_causes_without_changing_public_errors()
{
    let root = TestRoot::new();
    let mut store = root.open();
    let owner = ResourceOwner::Principal(PrincipalId::new("principal-artifact").unwrap());
    let invalid = json!({"resourceId":"resource-invalid"});
    let error =
        register_resource_with_diagnostics(&mut store, &invalid, owner.clone()).unwrap_err();
    assert!(matches!(error, ResourceRegistrationError::Artifact(_)));
    assert!(
        std::error::Error::source(&error)
            .unwrap()
            .is::<ArtifactError>()
    );
    assert_eq!(
        error.public_error(),
        register_resource(&mut store, &invalid, owner.clone()).unwrap_err()
    );

    let absent = json!({"resourceId":"resource-absent","sha256":raw_digest(b"not retained in this CAS"),"sizeBytes":24,"mediaType":"application/octet-stream"});
    let error = register_resource_with_diagnostics(&mut store, &absent, owner.clone()).unwrap_err();
    assert!(matches!(error, ResourceRegistrationError::Storage(_)));
    assert!(
        std::error::Error::source(&error)
            .unwrap()
            .is::<StorageError>()
    );
    assert_eq!(
        error.public_error(),
        register_resource(&mut store, &absent, owner.clone()).unwrap_err()
    );

    let (resource, _) = register(&mut store, "resource-diagnostic-existing", b"kept bytes");
    let mut selected = resource;
    selected["resourceId"] = json!("resource-diagnostic-readonly");
    store
        .connection
        .execute_batch("PRAGMA query_only=ON")
        .unwrap();
    let error =
        register_resource_with_diagnostics(&mut store, &selected, owner.clone()).unwrap_err();
    assert!(matches!(
        error,
        ResourceRegistrationError::Storage(StorageError::Sqlite(_))
    ));
    assert!(
        std::error::Error::source(&error)
            .unwrap()
            .is::<StorageError>()
    );
    assert_eq!(
        error.public_error(),
        register_resource(&mut store, &selected, owner).unwrap_err()
    );
    store
        .connection
        .execute_batch("PRAGMA query_only=OFF")
        .unwrap();
    let count: i64 = store.connection.query_row("SELECT count(*) FROM artifact_resources WHERE resource_id='resource-diagnostic-readonly'", [], |row| row.get(0)).unwrap();
    assert_eq!(count, 0);
}
#[test]
fn immutable_registration_survives_restart_and_gc_and_rejects_rebinding() {
    let root = TestRoot::new();
    let mut store = root.open();
    let (resource, blob) = register(&mut store, "resource-durable", b"durable");
    register_resource(
        &mut store,
        &resource,
        ResourceOwner::Principal(PrincipalId::new("principal-artifact").unwrap()),
    )
    .unwrap();
    let mut altered = resource.clone();
    altered["mediaType"] = json!("text/plain");
    assert_eq!(
        register_resource(
            &mut store,
            &altered,
            ResourceOwner::Principal(PrincipalId::new("principal-artifact").unwrap())
        )
        .unwrap_err()
        .code,
        "RESOURCE_REGISTRATION_CONFLICT"
    );
    assert_eq!(
        register_resource(
            &mut store,
            &resource,
            ResourceOwner::Principal(PrincipalId::new("principal-other").unwrap())
        )
        .unwrap_err()
        .code,
        "RESOURCE_REGISTRATION_CONFLICT"
    );
    drop(store);
    let mut reopened = root.open();
    reopened.collect_orphan_blobs(32).unwrap();
    assert!(root.blob_path(&blob).exists());
    let (mut reader, _) = reader(&["resource-durable"]);
    assert_eq!(
        reader
            .read(
                &reopened,
                &TestRpc::new(),
                &request("resource-durable", "0", 7)
            )
            .unwrap()["data"],
        "durable"
    );
}

#[test]
fn operation_summary_and_sources_commit_atomically_then_issue_owned_artifacts() {
    let root = TestRoot::new();
    let mut store = root.open();
    let operation = operation(&mut store, "operation-artifact");
    let source = store.put_blob(b"original-provider-payload").unwrap();
    let summary = store
        .put_blob(br#"{"status":"succeeded","outputValidated":true}"#)
        .unwrap();
    let unrelated = store.put_blob(b"another operation's bytes").unwrap();
    assert_eq!(
        issue_operation_resource(
            &mut store,
            &operation,
            &unrelated,
            "application/octet-stream"
        )
        .unwrap_err(),
        ArtifactError::forbidden()
    );
    store.connection.execute_batch("CREATE TRIGGER fail_summary BEFORE INSERT ON events WHEN NEW.kind='application_summary' BEGIN SELECT RAISE(ABORT,'summary failure fixture'); END;").unwrap();
    assert!(
        store
            .append_operation_summary(&operation, &summary, std::slice::from_ref(&source))
            .is_err()
    );
    assert!(store.operation_summaries(&operation).unwrap().is_empty());
    assert!(store.operation_evidence(&operation).unwrap().is_empty());
    store
        .connection
        .execute_batch("DROP TRIGGER fail_summary;")
        .unwrap();
    store
        .append_operation_summary(&operation, &summary, std::slice::from_ref(&source))
        .unwrap();
    store
        .append_operation_summary(&operation, &summary, std::slice::from_ref(&source))
        .unwrap();
    assert_eq!(
        store.operation_summaries(&operation).unwrap(),
        vec![summary.clone()]
    );
    assert_eq!(
        store.operation_evidence(&operation).unwrap(),
        vec![source.clone()]
    );
    assert!(
        store
            .append_operation_summary(&operation, &summary, &[])
            .is_err()
    );
    let resource =
        issue_operation_resource(&mut store, &operation, &source, "application/octet-stream")
            .unwrap();
    assert_eq!(
        resource,
        issue_operation_resource(&mut store, &operation, &source, "application/octet-stream")
            .unwrap()
    );
    let manifest = store.put_blob(b"{\"row\":1}\n{\"row\":2}\n").unwrap();
    store.pin_operation_artifact(&operation, &manifest).unwrap();
    assert!(
        issue_operation_resource(&mut store, &operation, &manifest, "application/x-ndjson").is_ok()
    );
    drop(store);
    let mut reopened = root.open();
    reopened.collect_orphan_blobs(64).unwrap();
    assert_eq!(
        reopened.operation_summaries(&operation).unwrap(),
        vec![summary]
    );
    assert_eq!(
        reopened.read_blob(&source).unwrap(),
        b"original-provider-payload"
    );
    let (mut reader, _) = reader(&[resource["resourceId"].as_str().unwrap()]);
    assert_eq!(
        reader
            .read(
                &reopened,
                &TestRpc::new(),
                &request(resource["resourceId"].as_str().unwrap(), "0", 65_536)
            )
            .unwrap()["data"],
        "original-provider-payload"
    );
}

#[test]
fn oversized_summary_or_missing_source_cannot_publish_a_marker() {
    let root = TestRoot::new();
    let mut store = root.open();
    let operation = operation(&mut store, "operation-summary-failure");
    let big = store.put_blob(&vec![0; 65_537]).unwrap();
    assert!(
        store
            .append_operation_summary(&operation, &big, &[])
            .is_err()
    );
    let summary = store.put_blob(b"marker").unwrap();
    let source = store.put_blob(b"source").unwrap();
    fs::remove_file(root.blob_path(&source)).unwrap();
    assert!(
        store
            .append_operation_summary(&operation, &summary, &[source])
            .is_err()
    );
    assert!(store.operation_summaries(&operation).unwrap().is_empty());
}

#[test]
fn lost_summary_source_pin_fails_closed_without_rewriting_observed_truth() {
    let root = TestRoot::new();
    let mut store = root.open();
    let operation = operation(&mut store, "operation-summary-lost-source");
    let source = store.put_blob(b"retained original result").unwrap();
    let summary = store.put_blob(b"bounded successful marker").unwrap();
    store
        .append_operation_summary(&operation, &summary, std::slice::from_ref(&source))
        .unwrap();
    let mut invocation =
        parse_json(include_bytes!("../../../../examples/invocation.json")).unwrap();
    invocation["operationId"] = json!(operation);
    invocation["invocationId"] = json!("invocation-summary-lost-source");
    let step = StepId::new("echo-step").unwrap();
    store
        .dispatch_intent(&operation, &step, &invocation)
        .unwrap();
    store
        .record_observation(
            &operation,
            &step,
            StepObservation {
                dispatch: DispatchEvidence::Observed,
                effect: EffectEvidence::NoneConfirmed,
                further_effects_possible: false,
                provider_receipt: None,
                observation_refs: vec![summary.clone()],
                finished: true,
            },
        )
        .unwrap();
    store
        .finish_operation(&operation, OperationState::Succeeded)
        .unwrap();
    let before = serde_json::to_value(store.operation(&operation).unwrap()).unwrap();
    store.connection.execute(
        "DELETE FROM blob_refs WHERE owner_kind='application_evidence' AND owner_id=?1 AND digest=?2",
        params![operation.as_str(), source.digest.as_str()],
    ).unwrap();
    assert!(matches!(
        store.operation_summaries(&operation),
        Err(StorageError::Corrupt(_))
    ));
    assert!(matches!(
        store.append_operation_summary(&operation, &summary, &[source]),
        Err(StorageError::Corrupt(_))
    ));
    assert_eq!(
        serde_json::to_value(store.operation(&operation).unwrap()).unwrap(),
        before
    );
}

//! Original echo examples are read-only and have no recoverable target bytes.
//! These fixtures adapt their descriptor/step and recompute the canonical pins
//! so real durable writes, independent readback, and recovery can be exercised.
//! A successful fake-target check is never evidence of actual game acceptance.

use crate::*;

#[path = "undo_tests.rs"]
mod undo_tests;
use mmmm_contracts::{
    BindingId, ContextId, InvocationId, ObjectId, OperationId, PlanId, Sha256Digest, StepId,
    canonical_digest, encode_json, parse_json, projected_digest, raw_digest,
};
use mmmm_runtime::artifact::{
    ArtifactError, ArtifactReader, ArtifactResult, ArtifactRpcContext, ResourceAuthority,
    ResourceOwner,
};
use mmmm_runtime::storage::result_binding::{
    RegisteredResultCodec, ResultArgumentSlot, ResultCodecImplementation, ResultFootprint,
    ResultStepBinding,
};
use mmmm_runtime::storage::{
    BlobRef, DispatchEvidence, EffectEvidence, Reservation, ReserveOperation, StoreConfig,
    WriteScope,
};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

const TARGET: &str = "resource-wall-blocks";
const ROOT_MARKER: &[u8] = b"mmmm-application-test\n";
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).expect("managed temporary root");
        let root = parent.join(format!(
            "mmmm-application-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let checkout = fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .expect("source checkout");
        assert!(root.is_absolute() && !root.starts_with(checkout));
        fs::create_dir(&root).expect("fresh owned data root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(root.join("test-owner.txt"), ROOT_MARKER).unwrap();
        Self(root)
    }
}

fn owned_plain_tree(path: &Path, root: &Path) -> bool {
    if !path.is_absolute() || !path.starts_with(root) {
        return false;
    }
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
        entries
            .into_iter()
            .all(|entry| entry.is_ok_and(|entry| owned_plain_tree(&entry.path(), root)))
    } else {
        metadata.is_file()
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        // The Fixture explicitly closes SQLite before this cleanup. Only its
        // freshly created, marked, absolute tree with no links is removed.
        if owned_plain_tree(&self.0, &self.0)
            && fs::read(self.0.join("test-owner.txt")).ok().as_deref() == Some(ROOT_MARKER)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn example(bytes: &[u8]) -> Value {
    parse_json(bytes).unwrap()
}
fn project_example() -> Value {
    example(include_bytes!("../../../examples/project.json"))
}
fn context_example() -> Value {
    example(include_bytes!("../../../examples/execution-context.json"))
}
fn write_descriptor() -> Value {
    let provider = example(include_bytes!("../../../examples/provider-supported.json"));
    let mut descriptor = provider["actions"][0].clone();
    descriptor["effect"] = json!("write");
    descriptor["recovery"] = json!("explicit_patch");
    descriptor["cancellation"] = json!("cooperative");
    descriptor["idempotency"] = json!("coordinator_only");
    descriptor["verificationRequirement"] = json!("independent_readback");
    descriptor["implementationDigest"] = json!(raw_digest(b"application-target-fixture-v1"));
    descriptor["summary"] =
        json!("Mutates the owned test target; independent observer verifies actual bytes.");
    descriptor
}
fn write_step(descriptor: &Value, id: &str, text: &str, dependencies: Vec<&str>) -> Value {
    let plan = example(include_bytes!("../../../examples/execution-plan.json"));
    let mut step = plan["steps"][0].clone();
    step["stepId"] = json!(id);
    step["arguments"] = json!({"text":text});
    step["dependsOn"] = json!(dependencies);
    for field in [
        "effect",
        "recovery",
        "verificationRequirement",
        "implementationDigest",
    ] {
        step[field] = descriptor[field].clone();
    }
    step["actionDigest"] = json!(canonical_digest(descriptor).unwrap());
    step["resourcesWritten"] = json!([TARGET]);
    step
}

#[derive(Clone)]
struct TargetChange {
    before: Vec<u8>,
    after: Vec<u8>,
}
#[derive(Clone, Copy)]
enum PreconditionBatchMode {
    Live,
    Empty,
    DriftSecond,
}
struct TargetState {
    targets: BTreeMap<String, Vec<u8>>,
    invocations: BTreeMap<String, TargetChange>,
    dispatches: usize,
    write_dispatches: usize,
    polls: usize,
    cancel_requests: usize,
    readbacks: usize,
    apply_grant: bool,
    revoke_after_dispatch: bool,
    lose_response: bool,
    malformed_response: bool,
    observer_available: bool,
    edit_after_first_readback: bool,
    fail_read: bool,
    fail_on_dispatch: Option<usize>,
    provider_payload_bytes: usize,
    provider_diagnostic_count: usize,
    provider_diagnostic_bytes: usize,
    observe_grant: bool,
    observation_checks: usize,
    capture_available: bool,
    capture_identity_mismatch: bool,
    capture_bytes_mismatch: bool,
    captures: usize,
    forged_readback_before: bool,
    registered_reads: usize,
    read_grant: bool,
    read_checks: usize,
    revoke_read_after_callback: bool,
    change_context_after_read: bool,
    invalid_read_output: bool,
    producer_result_text: Option<String>,
    job_accepted_on_dispatch: Option<usize>,
    footprint_registered: bool,
    footprint_denied: bool,
    footprint_checks: usize,
    revoke_observe_on_cancel: bool,
    revoke_observe_after_readback: bool,
    observe_scope: Option<WriteScope>,
    last_operation_scope: Option<WriteScope>,
    raw_failed_summary_metadata: Option<bool>,
    legacy_history_uncovered: Option<bool>,
    precondition_batch_mode: Option<PreconditionBatchMode>,
    precondition_batch_calls: usize,
    single_precondition_calls: usize,
    poll_response_missing: bool,
}
impl TargetState {
    fn new() -> Self {
        Self {
            targets: BTreeMap::from([(TARGET.to_owned(), b"before".to_vec())]),
            invocations: BTreeMap::new(),
            dispatches: 0,
            write_dispatches: 0,
            polls: 0,
            cancel_requests: 0,
            readbacks: 0,
            apply_grant: true,
            revoke_after_dispatch: false,
            lose_response: false,
            malformed_response: false,
            observer_available: true,
            edit_after_first_readback: false,
            fail_read: false,
            fail_on_dispatch: None,
            provider_payload_bytes: 0,
            provider_diagnostic_count: 0,
            provider_diagnostic_bytes: 0,
            observe_grant: true,
            observation_checks: 0,
            capture_available: true,
            capture_identity_mismatch: false,
            capture_bytes_mismatch: false,
            captures: 0,
            forged_readback_before: false,
            registered_reads: 0,
            read_grant: true,
            read_checks: 0,
            revoke_read_after_callback: false,
            change_context_after_read: false,
            invalid_read_output: false,
            producer_result_text: None,
            job_accepted_on_dispatch: None,
            footprint_registered: false,
            footprint_denied: false,
            footprint_checks: 0,
            revoke_observe_on_cancel: false,
            revoke_observe_after_readback: false,
            observe_scope: None,
            last_operation_scope: None,
            raw_failed_summary_metadata: None,
            legacy_history_uncovered: None,
            precondition_batch_mode: None,
            precondition_batch_calls: 0,
            single_precondition_calls: 0,
            poll_response_missing: false,
        }
    }
}
type SharedTarget = Rc<RefCell<TargetState>>;

struct Authority {
    target: SharedTarget,
}
impl AuthorityPort for Authority {
    fn authorize_operation(
        &mut self,
        principal: &PrincipalId,
        operation: &mmmm_runtime::storage::OperationRecord,
        access: Access,
    ) -> AppResult<()> {
        if principal != &operation.principal {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Operation belongs to another principal",
            ));
        }
        self.authorize(principal, &operation.project_id, access, None, None)?;
        if access == Access::ObserveOperation {
            let mut target = self.target.borrow_mut();
            target.last_operation_scope = Some(operation.scope.clone());
            if target
                .observe_scope
                .as_ref()
                .is_some_and(|scope| scope != &operation.scope)
            {
                return Err(AppError::new(
                    "PERMISSION_REQUIRED",
                    "Current journal grant does not cover the original operation scope",
                ));
            }
        }
        Ok(())
    }
    fn authorize(
        &mut self,
        _principal: &PrincipalId,
        _project: &ProjectId,
        access: Access,
        _context: Option<&Value>,
        _plan: Option<&Value>,
    ) -> AppResult<()> {
        if access == Access::ReadAction {
            let mut target = self.target.borrow_mut();
            target.read_checks += 1;
            if !target.read_grant {
                return Err(AppError::new(
                    "PERMISSION_REQUIRED",
                    "Current registered read grant is denied",
                ));
            }
        }
        if access == Access::ObserveOperation {
            let mut target = self.target.borrow_mut();
            target.observation_checks += 1;
            if !target.observe_grant {
                return Err(AppError::new(
                    "PERMISSION_REQUIRED",
                    "Current operation observation grant is denied",
                ));
            }
        }
        if access == Access::Apply && !self.target.borrow().apply_grant {
            Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Test grant was revoked",
            ))
        } else {
            Ok(())
        }
    }
}

struct Planner {
    prepared: PreparedPlan,
    preparations: usize,
    recovery_preparations: usize,
    last_recovery_source_count: usize,
    last_request: Option<Value>,
}
impl PlanningPort for Planner {
    fn inspect_project(
        &mut self,
        _principal: &PrincipalId,
        _project: &Value,
    ) -> AppResult<ProjectInspection> {
        Ok(ProjectInspection {
            diagnostics: vec![],
            unresolved_references: vec![],
            runtime_bindings_available: false,
        })
    }
    fn prepare(
        &mut self,
        _principal: &PrincipalId,
        request: &Value,
        _project: &Value,
        _context: &Value,
    ) -> AppResult<PreparedPlan> {
        self.preparations += 1;
        self.last_request = Some(request.clone());
        let mut prepared = self.prepared.clone();
        if request["intent"]["kind"] == "external.action" {
            let action = &request["intent"]["request"];
            for field in [
                "bindingId",
                "actionId",
                "actionDigest",
                "arguments",
                "contextId",
            ] {
                prepared.steps[0][field] = action[field].clone();
            }
        }
        Ok(prepared)
    }
    fn prepare_recovery(
        &mut self,
        _principal: &PrincipalId,
        recovery: &RecoveryPreparation,
        _project: &Value,
        context: &Value,
    ) -> AppResult<PreparedPlan> {
        self.recovery_preparations += 1;
        assert_eq!(recovery.targets.len(), 1);
        let target = &recovery.targets[0];
        self.last_recovery_source_count = target.source_snapshots.len();
        let mut prepared = self.prepared.clone();
        prepared.contexts = vec![context.clone()];
        prepared.steps.truncate(1);
        prepared.steps[0]["arguments"] =
            json!({"text":String::from_utf8(target.before_bytes.clone()).unwrap()});
        prepared.preconditions = vec![json!({
            "kind":"resource_hash", "subject":target.snapshot.target,
            "expected":target.snapshot.after.digest, "coverage":"full_target"
        })];
        Ok(prepared)
    }
}

struct Provider {
    target: SharedTarget,
    live_context: Value,
    descriptor: Value,
    extra_descriptors: BTreeMap<String, Value>,
    codec: Option<RegisteredResultCodec>,
    successor_context: Option<Value>,
}
impl ProviderPort for Provider {
    fn result_codec(
        &mut self,
        id: &ObjectId,
        _digest: &Sha256Digest,
    ) -> AppResult<RegisteredResultCodec> {
        self.codec
            .as_ref()
            .filter(|codec| &codec.codec_id == id)
            .cloned()
            .ok_or_else(|| {
                AppError::new(
                    "CAPABILITY_UNAVAILABLE",
                    "No closed test codec is registered",
                )
            })
    }
    fn validate_resolved_footprint(
        &mut self,
        step: &Value,
        arguments: &Value,
        _context: &Value,
    ) -> AppResult<()> {
        let mut target = self.target.borrow_mut();
        target.footprint_checks += 1;
        if !target.footprint_registered {
            return Err(AppError::new(
                "CAPABILITY_UNAVAILABLE",
                "No trusted result footprint verifier is registered",
            ));
        }
        if target.footprint_denied
            || step["resourcesWritten"] != json!([TARGET])
            || arguments["text"]
                .as_str()
                .is_none_or(|text| text.starts_with("widen:"))
        {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Resolved arguments exceed the original fixed target footprint",
            ));
        }
        Ok(())
    }
    fn registered_read_with_store(
        &mut self,
        store: &DurableStore,
        _request: &Value,
        context: &Value,
    ) -> AppResult<Value> {
        let project: ProjectId = decode(&context["projectId"])?;
        store
            .project(&project)
            .map_err(|e| AppError::storage("NOT_FOUND", e))?;
        let mut target = self.target.borrow_mut();
        target.registered_reads += 1;
        let data = if target.invalid_read_output {
            json!({"text":42})
        } else {
            json!({"text":String::from_utf8(target.targets[TARGET].clone()).unwrap()})
        };
        if target.revoke_read_after_callback {
            target.read_grant = false;
        }
        if target.change_context_after_read {
            self.live_context["policyRevision"] =
                json!(raw_digest(b"registered-read-policy-changed"));
            self.live_context["contextDigest"] =
                json!(projected_digest("ExecutionContext", &self.live_context).unwrap());
        }
        Ok(
            json!({"contractVersion":"0.2.0","status":"complete","data":data,
            "effects":"none","diagnostics":[],"artifacts":[]}),
        )
    }
    fn context(&mut self, _principal: &PrincipalId, _context: &ContextId) -> AppResult<Value> {
        Ok(self.live_context.clone())
    }
    fn successor_observation_context_with_store(
        &mut self,
        _store: &mut DurableStore,
        _principal: &PrincipalId,
        _original: &Value,
    ) -> AppResult<Option<Value>> {
        // Unit-only trusted-port fixture; this issues no native pairing or
        // retained host-attempt capability.
        Ok(self.successor_context.clone())
    }
    fn action_descriptor(&mut self, step: &Value, _context: &Value) -> AppResult<Value> {
        Ok(self
            .extra_descriptors
            .get(step["actionId"].as_str().unwrap())
            .unwrap_or(&self.descriptor)
            .clone())
    }
    fn observe_precondition(
        &mut self,
        precondition: &Value,
        _context: &Value,
    ) -> AppResult<Sha256Digest> {
        let mut target = self.target.borrow_mut();
        target.single_precondition_calls += 1;
        let bytes = target
            .targets
            .get(precondition["subject"].as_str().unwrap())
            .unwrap();
        Ok(raw_digest(bytes))
    }
    fn observe_plan_preconditions_retained_with_store(
        &mut self,
        _store: &mut DurableStore,
        _plan: &Value,
        _step: &Value,
        conditions: &[&Value],
        _context: &Value,
    ) -> AppResult<Option<Vec<Sha256Digest>>> {
        let mut target = self.target.borrow_mut();
        let Some(mode) = target.precondition_batch_mode else {
            return Ok(None);
        };
        target.precondition_batch_calls += 1;
        if matches!(mode, PreconditionBatchMode::Empty) {
            return Ok(Some(vec![]));
        }
        if matches!(mode, PreconditionBatchMode::DriftSecond)
            && target.precondition_batch_calls == 2
        {
            target
                .targets
                .insert(TARGET.into(), b"external-edit-after-capture".to_vec());
        }
        Ok(Some(
            conditions
                .iter()
                .map(|condition| {
                    raw_digest(&target.targets[condition["subject"].as_str().unwrap()])
                })
                .collect(),
        ))
    }
    fn verify_dependencies(&mut self, pins: &[Value], _context: &Value) -> AppResult<()> {
        assert!(pins.is_empty());
        Ok(())
    }
    fn dispatch(&mut self, invocation: &Value) -> AppResult<Value> {
        let is_read = self
            .extra_descriptors
            .get(invocation["actionId"].as_str().unwrap())
            .unwrap_or(&self.descriptor)["effect"]
            == "read";
        let mut target = self.target.borrow_mut();
        let id = invocation["invocationId"].as_str().unwrap().to_owned();
        assert!(
            !target.invocations.contains_key(&id),
            "invocation cannot be retransmitted"
        );
        let before = target.targets[TARGET].clone();
        let after = if is_read {
            before.clone()
        } else {
            invocation["arguments"]["text"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec()
        };
        if !is_read {
            target.targets.insert(TARGET.into(), after.clone());
            target.write_dispatches += 1;
        }
        target
            .invocations
            .insert(id, TargetChange { before, after });
        target.dispatches += 1;
        if target.revoke_after_dispatch {
            target.apply_grant = false;
        }
        if is_read && target.fail_read {
            Ok(
                json!({"contractVersion":"0.2.0","status":"failed","data":{},
                "effects":"none","diagnostics":[],"artifacts":[]}),
            )
        } else if target.lose_response {
            Err(AppError::new(
                "OUTCOME_UNKNOWN",
                "The dispatched response was lost",
            ))
        } else {
            let mut data = if target.malformed_response {
                json!({"text":42})
            } else {
                invocation["arguments"].clone()
            };
            if target.dispatches == 1
                && let Some(text) = &target.producer_result_text
            {
                data["text"] = json!(text);
            }
            if target.provider_payload_bytes > 0 {
                data["payload"] = json!("p".repeat(target.provider_payload_bytes));
            }
            let diagnostics: Vec<_> = (0..target.provider_diagnostic_count).map(|index| {
                json!({"code":format!("PROVIDER_DIAG_{index:04}"),"severity":"warning",
                    "message":format!("diagnostic-{index:04}:{}", "d".repeat(target.provider_diagnostic_bytes))})
            }).collect();
            let mut response = json!({
                "contractVersion":"0.2.0", "status":if target.job_accepted_on_dispatch == Some(target.dispatches) {"job_accepted"} else if target.fail_on_dispatch == Some(target.dispatches) {"failed"} else {"complete"}, "data":data,
                "effects":"recorded", "diagnostics":diagnostics, "artifacts":[]
            });
            if response["status"] == "job_accepted" {
                response["jobHandle"] = json!("job-fixture-original");
            }
            Ok(response)
        }
    }
    fn dispatch_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
    ) -> AppResult<Value> {
        let response = self.dispatch(invocation)?;
        if self.target.borrow().dispatches == 1
            && let Some(uncovered) = self.target.borrow().legacy_history_uncovered
        {
            // Five independently retained legacy bodies total about35MiB.
            // Both a small-summary source association and the original old
            // observation-ref wrapper format must obey the same read cap.
            let operation: OperationId = decode(&invocation["operationId"])?;
            let mut observations = Vec::new();
            for index in 0..5 {
                let body = json!({"contractVersion":"0.2.0",
                    "status":if index == 4 {"failed"} else {"complete"},
                    "data":{"text":format!("old-{index}"),"payload":"p".repeat(7*1024*1024)},
                    "effects":"recorded","diagnostics":[],"artifacts":[]});
                validate("ProviderResult", &body)?;
                if uncovered {
                    let envelope = json!({"kind":"unvalidated_provider_result",
                        "stepId":invocation["stepId"],"invocationId":invocation["invocationId"],"value":body});
                    observations.push(store.put_blob(&encode_json(&envelope).unwrap()).unwrap());
                } else {
                    let blob = store.put_blob(&encode_json(&body).unwrap()).unwrap();
                    let marker = json!({"kind":"unvalidated_provider_result",
                        "stepId":invocation["stepId"],"invocationId":invocation["invocationId"],
                        "sourceRefs":[blob],"resultBlob":blob,"bodyOmitted":true});
                    let summary = store.put_blob(&encode_json(&marker).unwrap()).unwrap();
                    store
                        .append_operation_summary(&operation, &summary, &[blob])
                        .unwrap();
                }
            }
            if uncovered {
                store
                    .record_observation(
                        &operation,
                        &decode(&invocation["stepId"])?,
                        mmmm_runtime::storage::StepObservation {
                            dispatch: DispatchEvidence::Acknowledged,
                            effect: EffectEvidence::Unknown,
                            further_effects_possible: true,
                            provider_receipt: None,
                            observation_refs: observations,
                            finished: false,
                        },
                    )
                    .unwrap();
            }
        }
        let metadata = self.target.borrow().raw_failed_summary_metadata;
        if self.target.borrow().dispatches == 1
            && let Some(metadata) = metadata
        {
            // Model a crash after the raw canonical failed envelope and its
            // source association were retained, before a typed failed marker.
            // A later complete response uses this same original invocation.
            let failed = json!({"contractVersion":"0.2.0","status":"failed","data":{},
                "effects":"recorded","diagnostics":[{"code":"RAW_SOURCE_FAILED",
                    "severity":"error","message":"Original raw provider failure survived the typed-marker crash gap"}],
                "artifacts":[]});
            validate("ProviderResult", &failed)?;
            let blob = store.put_blob(&encode_json(&failed).unwrap()).unwrap();
            let mut marker = json!({"kind":"unvalidated_provider_result",
                "stepId":invocation["stepId"],"invocationId":invocation["invocationId"],
                "sourceRefs":[blob],"resultBlob":blob,"bodyOmitted":true});
            if metadata {
                let envelope = json!({"kind":"provider_result","stepId":invocation["stepId"],
                    "invocationId":invocation["invocationId"],"value":failed,"outputValidated":false,
                    "actionDigest":invocation["actionDigest"],
                    "outputSchemaDigest":canonical_digest(&self.descriptor["outputSchema"]).unwrap(),
                    "resultBlob":blob,"sourceRefs":[blob]});
                marker["envelopeValidated"] = json!(true);
                marker["envelopeStatus"] = json!("failed");
                marker["envelopeSummary"] = crate::report::compact_evidence(&envelope, &blob)?;
            }
            let summary = store.put_blob(&encode_json(&marker).unwrap()).unwrap();
            let operation: OperationId = decode(&invocation["operationId"]).unwrap();
            store
                .append_operation_summary(&operation, &summary, &[blob])
                .unwrap();
        }
        Ok(response)
    }
    fn poll(&mut self, invocation: &Value, _receipt: Option<&str>) -> AppResult<Option<Value>> {
        let mut target = self.target.borrow_mut();
        target.polls += 1;
        assert!(
            target
                .invocations
                .contains_key(invocation["invocationId"].as_str().unwrap())
        );
        // The original invocation is queried; it is never dispatched again.
        // A retained valid complete response is distinct from target readback.
        if target.poll_response_missing {
            return Ok(None);
        }
        Ok(Some(json!({
            "contractVersion":"0.2.0", "status":"complete", "data":invocation["arguments"],
            "effects":"recorded", "diagnostics":[], "artifacts":[]
        })))
    }
    fn request_cancel(&mut self, invocation: &Value, _receipt: Option<&str>) -> AppResult<()> {
        let mut target = self.target.borrow_mut();
        assert!(
            target
                .invocations
                .contains_key(invocation["invocationId"].as_str().unwrap())
        );
        target.cancel_requests += 1;
        if target.revoke_observe_on_cancel {
            target.observe_grant = false;
        }
        // An acknowledgment deliberately does not change bytes or settle work.
        Ok(())
    }
}

struct Observer {
    target: SharedTarget,
}
impl IndependentObserverPort for Observer {
    fn capture_before(
        &mut self,
        invocation: &Value,
        _scope: &WriteScope,
    ) -> AppResult<Option<BeforeCapture>> {
        let mut target = self.target.borrow_mut();
        target.captures += 1;
        assert!(
            !target
                .invocations
                .contains_key(invocation["invocationId"].as_str().unwrap()),
            "independent before capture occurs before target dispatch"
        );
        if !target.capture_available {
            return Ok(None);
        }
        Ok(Some(BeforeCapture {
            invocation_id: decode(&invocation["invocationId"]).unwrap(),
            binding_id: decode(&invocation["bindingId"]).unwrap(),
            context_digest: decode(&invocation["contextDigest"]).unwrap(),
            implementation_digest: decode(&invocation["implementationDigest"]).unwrap(),
            arguments_digest: if target.capture_identity_mismatch {
                raw_digest(b"different-capture-arguments")
            } else {
                decode(&invocation["argumentsDigest"]).unwrap()
            },
            images: vec![BeforeImage {
                target: TARGET.into(),
                bytes: if target.capture_bytes_mismatch {
                    b"different-before-phase".to_vec()
                } else {
                    target.targets[TARGET].clone()
                },
            }],
        }))
    }
    fn readback(&mut self, invocation: &Value, _scope: &WriteScope) -> AppResult<ReadbackEvidence> {
        let mut target = self.target.borrow_mut();
        target.readbacks += 1;
        if !target.observer_available {
            return Err(AppError::new(
                "RECONCILIATION_INSUFFICIENT",
                "Target observer is unavailable",
            ));
        }
        let change = target.invocations[invocation["invocationId"].as_str().unwrap()].clone();
        let actual = target.targets[TARGET].clone();
        if actual != change.after {
            return Err(AppError::new(
                "TARGET_DRIFT",
                "Actual bytes differ from this invocation's target",
            ));
        }
        let evidence = ReadbackEvidence {
            invocation_id: decode::<InvocationId>(&invocation["invocationId"]).unwrap(),
            binding_id: decode::<BindingId>(&invocation["bindingId"]).unwrap(),
            context_digest: decode(&invocation["contextDigest"]).unwrap(),
            implementation_digest: decode(&invocation["implementationDigest"]).unwrap(),
            arguments_digest: decode(&invocation["argumentsDigest"]).unwrap(),
            effect: EffectEvidence::CompleteConfirmed,
            settled: true,
            evidence: json!({"target":TARGET,"actualDigest":raw_digest(&actual)}),
            direct_changes: vec![DirectChange {
                target: TARGET.into(),
                before: if target.forged_readback_before {
                    b"forged-after-dispatch-before".to_vec()
                } else {
                    change.before
                },
                after: actual,
            }],
        };
        if target.edit_after_first_readback && target.readbacks == 1 {
            // The retained observation describes the actual bytes at its read.
            // A later edit must be detected by the successor's own preflight.
            target
                .targets
                .insert(TARGET.into(), b"manual-between-steps".to_vec());
        }
        if target.revoke_observe_after_readback {
            target.observe_grant = false;
        }
        Ok(evidence)
    }
    fn read_target(&mut self, _invocation: &Value, target: &str) -> AppResult<Vec<u8>> {
        Ok(self.target.borrow().targets[target].clone())
    }
}

struct DefaultCaptureObserver(Observer);
impl IndependentObserverPort for DefaultCaptureObserver {
    // Intentionally inherit the default None capability. Successful readback
    // support does not imply independent before-image capture support.
    fn readback(&mut self, invocation: &Value, scope: &WriteScope) -> AppResult<ReadbackEvidence> {
        self.0.readback(invocation, scope)
    }
    fn read_target(&mut self, invocation: &Value, target: &str) -> AppResult<Vec<u8>> {
        self.0.read_target(invocation, target)
    }
}

struct Ids(u64);
impl IdSource for Ids {
    fn next_id(&mut self, kind: IdKind) -> AppResult<String> {
        self.0 += 1;
        let prefix = match kind {
            IdKind::Plan => "plan",
            IdKind::Operation => "operation",
            IdKind::Invocation => "invocation",
        };
        Ok(format!("{prefix}-application-test-{}", self.0))
    }
}
struct TestClock(Cell<i128>);
impl Clock for TestClock {
    fn unix_nanos(&self) -> i128 {
        self.0.get()
    }
}

struct Fixture {
    // Declared first so the actual database lock closes before the owned root.
    store: DurableStore,
    root: TestRoot,
    principal: PrincipalId,
    project: Value,
    target: SharedTarget,
    authority: Authority,
    planner: Planner,
    provider: Provider,
    observer: Observer,
    ids: Ids,
    clock: TestClock,
}

// Reuse the owned SQLite/CAS fixture for trusted setup source checkpoints.
// This adapter grants no native owner or game execution capability.
mod setup_source_tests {
    use super::*;
    use mmmm_runtime::storage::{
        StorageError, StorageResult,
        project_resources::{
            ProjectHeadPin, ProjectResourceAuthority, ProjectResourceReader,
            ProjectSourceRpcContext, RegisteredProjectResource, current_project_head_pin,
        },
    };

    struct Control {
        cancelled: Cell<bool>,
        reading: Cell<bool>,
        read_checks: Cell<usize>,
        case: &'static str,
        locator: RefCell<Option<(PlanId, Sha256Digest)>>,
    }
    struct Rpc {
        principal: PrincipalId,
        control: Rc<Control>,
    }
    impl ProjectSourceRpcContext for Rpc {
        fn check(&self) -> StorageResult<()> {
            if self.control.reading.get() {
                self.control
                    .read_checks
                    .set(self.control.read_checks.get() + 1);
                if self.control.case == "cancel_read" && self.control.read_checks.get() == 3 {
                    self.control.cancelled.set(true);
                }
            }
            if self.control.cancelled.get() {
                return Err(StorageError::Conflict(
                    "Original setup source request cancelled",
                ));
            }
            Ok(())
        }
        fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
            self.check()?;
            Ok(self.principal.clone())
        }
        fn context_id(&self) -> Option<&ContextId> {
            None
        }
    }
    struct ProjectAuthority {
        principal: PrincipalId,
        project: ProjectId,
        revision: Sha256Digest,
    }
    impl ProjectResourceAuthority for ProjectAuthority {
        fn authorize_project_read(
            &mut self,
            _store: &DurableStore,
            principal: &PrincipalId,
            context: Option<&ContextId>,
            project: &ProjectId,
            revision: &Sha256Digest,
        ) -> StorageResult<()> {
            if principal != &self.principal
                || project != &self.project
                || revision != &self.revision
                || context.is_some()
            {
                return Err(StorageError::Conflict(
                    "Actual setup fixture Project source",
                ));
            }
            Ok(())
        }
        fn authorize_resource_read(
            &mut self,
            _store: &DurableStore,
            _principal: &PrincipalId,
            _context: Option<&ContextId>,
            _project: &ProjectId,
            _resource: &RegisteredProjectResource,
        ) -> StorageResult<()> {
            Err(StorageError::Conflict(
                "Setup source test grants no resource read",
            ))
        }
    }
    struct Source {
        rpc: Rpc,
        head: ProjectHeadPin,
        prepared: PreparedPlan,
        preparations: usize,
    }
    impl SetupPlanningPort for Source {
        fn read_current_project_with_store(
            &mut self,
            store: &DurableStore,
            _principal: &PrincipalId,
            selection: &SetupSelection,
        ) -> AppResult<Value> {
            let ceiling = if self.rpc.control.case == "read_limit" {
                1
            } else {
                8 * 1024 * 1024
            };
            let mut reader = ProjectResourceReader::new(
                Box::new(ProjectAuthority {
                    principal: self.rpc.principal.clone(),
                    project: selection.project_id.clone(),
                    revision: self.head.revision.clone(),
                }),
                ceiling,
            )
            .unwrap();
            self.rpc.control.reading.set(true);
            let result = reader.read_project(
                store,
                &self.rpc,
                &selection.project_id,
                &self.head.revision,
                ceiling,
            );
            self.rpc.control.reading.set(false);
            result.map_err(|cause| AppError::storage("SETUP_READ_FAILED", cause))
        }
        fn check_current_project_with_store(
            &self,
            store: &DurableStore,
            principal: &PrincipalId,
            selection: &SetupSelection,
        ) -> AppResult<()> {
            self.rpc
                .check()
                .map_err(|cause| AppError::storage("SETUP_CHECKPOINT_STOPPED", cause))?;
            assert_eq!(principal, &self.rpc.principal);
            let actual = current_project_head_pin(store, &self.rpc, &selection.project_id)
                .map_err(|cause| AppError::storage("SETUP_HEAD_FAILED", cause))?;
            if actual != self.head {
                return Err(AppError::new(
                    "REVISION_CONFLICT",
                    "Actual setup Project head changed",
                ));
            }
            if self.rpc.control.case == "committed_postcheck"
                && self
                    .rpc
                    .control
                    .locator
                    .borrow()
                    .as_ref()
                    .is_some_and(|(id, hash)| store.plan(id, hash).is_ok())
            {
                return Err(AppError::new(
                    "SETUP_POSTCOMMIT_STOPPED",
                    "Original checkpoint failed after actual plan save",
                ));
            }
            Ok(())
        }
        fn prepare_setup_with_store(
            &mut self,
            store: &mut DurableStore,
            _principal: &PrincipalId,
            _selection: &SetupSelection,
            project: &Value,
            _context: &Value,
        ) -> AppResult<PreparedPlan> {
            self.preparations += 1;
            if self.rpc.control.case == "head_drift" {
                let mut changed = project.clone();
                changed["name"] = json!("Actual setup head advanced");
                changed["revision"] = json!(projected_digest("Project", &changed).unwrap());
                store
                    .save_project(&changed, Some(&self.head.revision))
                    .unwrap();
            }
            if self.rpc.control.case == "prepare_and_checkpoint" {
                self.rpc.control.cancelled.set(true);
                return Err(AppError::new(
                    "SETUP_PREPARATION_FAILED",
                    "Original preparation failure",
                ));
            }
            Ok(self.prepared.clone())
        }
    }
    struct FreezeAuthority<'a> {
        actual: &'a mut Authority,
        control: Rc<Control>,
    }
    impl AuthorityPort for FreezeAuthority<'_> {
        fn authorize(
            &mut self,
            principal: &PrincipalId,
            project: &ProjectId,
            access: Access,
            context: Option<&Value>,
            plan: Option<&Value>,
        ) -> AppResult<()> {
            self.actual
                .authorize(principal, project, access, context, plan)?;
            if access == Access::Plan
                && let Some(plan) = plan
            {
                *self.control.locator.borrow_mut() = Some((
                    decode(&plan["planId"]).unwrap(),
                    decode(&plan["planHash"]).unwrap(),
                ));
                if self.control.case == "freeze_and_checkpoint" {
                    self.control.cancelled.set(true);
                    return Err(AppError::new(
                        "SETUP_FREEZE_REJECTED",
                        "Original freeze authority failure",
                    ));
                }
            }
            Ok(())
        }
    }
    #[test]
    fn setup_uses_actual_bounded_project_and_preserves_primary_and_committed_postcheck_failures() {
        for case in [
            "success",
            "read_limit",
            "cancel_before",
            "cancel_read",
            "head_drift",
            "prepare_and_checkpoint",
            "freeze_and_checkpoint",
            "committed_postcheck",
        ] {
            let mut fixture = Fixture::new(1);
            let principal = fixture.principal.clone();
            let selection = SetupSelection {
                project_id: decode(&fixture.project["projectId"]).unwrap(),
                expected_revision: decode(&fixture.project["revision"]).unwrap(),
                context_id: decode(&fixture.provider.live_context["contextId"]).unwrap(),
            };
            let control = Rc::new(Control {
                cancelled: Cell::new(false),
                reading: Cell::new(false),
                read_checks: Cell::new(0),
                case,
                locator: RefCell::new(None),
            });
            let rpc = Rpc {
                principal: principal.clone(),
                control: control.clone(),
            };
            let head =
                current_project_head_pin(&fixture.store, &rpc, &selection.project_id).unwrap();
            let mut source = Source {
                rpc,
                head,
                prepared: fixture.planner.prepared.clone(),
                preparations: 0,
            };
            if case == "cancel_before" {
                control.cancelled.set(true);
            }
            let result = {
                let mut authority = FreezeAuthority {
                    actual: &mut fixture.authority,
                    control: control.clone(),
                };
                let mut app = Application {
                    store: &mut fixture.store,
                    authority: &mut authority,
                    planner: &mut fixture.planner,
                    provider: &mut fixture.provider,
                    observer: &mut fixture.observer,
                    ids: &mut fixture.ids,
                    clock: &fixture.clock,
                };
                app.prepare_setup(&principal, &selection, &mut source)
            };
            assert_eq!(fixture.target.borrow().dispatches, 0, "{case}");
            if case == "success" {
                let plan = result.unwrap();
                assert_eq!(
                    fixture
                        .store
                        .plan(
                            &decode(&plan["planId"]).unwrap(),
                            &decode(&plan["planHash"]).unwrap()
                        )
                        .unwrap(),
                    plan
                );
                assert_eq!(source.preparations, 1);
            } else {
                let error = result.unwrap_err();
                if matches!(case, "read_limit" | "cancel_before" | "cancel_read") {
                    assert_eq!(source.preparations, 0, "{case}");
                }
                if case == "head_drift" {
                    assert_eq!(error.code, "REVISION_CONFLICT");
                }
                if matches!(case, "prepare_and_checkpoint" | "freeze_and_checkpoint") {
                    assert_eq!(
                        error.code,
                        if case == "prepare_and_checkpoint" {
                            "SETUP_PREPARATION_FAILED"
                        } else {
                            "SETUP_FREEZE_REJECTED"
                        }
                    );
                    let both = std::error::Error::source(&error).unwrap();
                    assert!(both.to_string().contains("SETUP_CHECKPOINT_STOPPED"));
                    assert!(
                        std::error::Error::source(both)
                            .unwrap()
                            .downcast_ref::<AppError>()
                            .is_some()
                    );
                }
                if case == "committed_postcheck" {
                    assert_eq!(error.code, "SETUP_PLAN_COMMITTED");
                    let committed = std::error::Error::source(&error)
                        .unwrap()
                        .downcast_ref::<crate::SetupCommittedPlanFailure>()
                        .unwrap();
                    assert_eq!(
                        committed.checkpoint_failure().code,
                        "SETUP_POSTCOMMIT_STOPPED"
                    );
                    let saved = fixture
                        .store
                        .plan(committed.plan_id(), committed.plan_hash())
                        .unwrap();
                    assert_eq!(
                        saved["projectBaseRevision"],
                        selection.expected_revision.as_str()
                    );
                } else if let Some((id, hash)) = control.locator.borrow().as_ref() {
                    assert!(fixture.store.plan(id, hash).is_err(), "{case}");
                }
            }
        }
    }
}
impl Fixture {
    fn new(steps: usize) -> Self {
        let root = TestRoot::new();
        let mut store = DurableStore::open(StoreConfig::new(root.0.clone())).unwrap();
        let mut project = project_example();
        project["revision"] = json!(projected_digest("Project", &project).unwrap());
        store.save_project(&project, None).unwrap();
        let target = Rc::new(RefCell::new(TargetState::new()));
        let mut context = context_example();
        context["scope"]["resourceIds"] = json!([TARGET]);
        context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
        let descriptor = write_descriptor();
        let mut plan_steps = vec![write_step(
            &descriptor,
            "write-first",
            "after-first",
            vec![],
        )];
        if steps == 2 {
            plan_steps.push(write_step(
                &descriptor,
                "write-second",
                "after-second",
                vec!["write-first"],
            ));
        }
        let prepared = PreparedPlan {
            contexts: vec![context.clone()],
            scope: decode(&context["scope"]).unwrap(),
            preconditions: vec![
                json!({"kind":"resource_hash","subject":TARGET,"expected":raw_digest(b"before"),"coverage":"full_target"}),
            ],
            steps: plan_steps,
            atomicity: "none".into(),
            losses: vec![],
            diagnostics: vec![],
            approval_requirement: "within_existing_grant".into(),
            dependency_pins: vec![],
            expires_at: "2099-01-01T00:00:00Z".into(),
            time_budget_ms: 10_000,
        };
        Self {
            store,
            root,
            principal: PrincipalId::new("principal-fixture").unwrap(),
            project,
            authority: Authority {
                target: target.clone(),
            },
            planner: Planner {
                prepared,
                preparations: 0,
                recovery_preparations: 0,
                last_recovery_source_count: 0,
                last_request: None,
            },
            provider: Provider {
                target: target.clone(),
                live_context: context,
                descriptor,
                extra_descriptors: BTreeMap::new(),
                codec: None,
                successor_context: None,
            },
            observer: Observer {
                target: target.clone(),
            },
            target,
            ids: Ids(0),
            clock: TestClock(Cell::new(0)),
        }
    }
    fn app(&mut self) -> Application<'_> {
        Application {
            store: &mut self.store,
            authority: &mut self.authority,
            planner: &mut self.planner,
            provider: &mut self.provider,
            observer: &mut self.observer,
            ids: &mut self.ids,
            clock: &self.clock,
        }
    }
    fn plan(&mut self) -> Value {
        self.try_plan().unwrap()
    }
    fn try_plan(&mut self) -> AppResult<Value> {
        let principal = self.principal.clone();
        let request = json!({
            "projectId":self.project["projectId"], "expectedRevision":self.project["revision"],
            "contextId":self.provider.live_context["contextId"],
            "intent":example(include_bytes!("../../../examples/change-intent.json"))
        });
        self.app().plan_create(&principal, &request)
    }
    fn apply(&mut self, plan: &Value, key: &str) -> AppResult<Value> {
        let principal = self.principal.clone();
        self.app().plan_apply(
            &principal,
            &json!({
                "contractVersion":"0.2.0", "planId":plan["planId"], "planHash":plan["planHash"],
                "contextId":plan["contextId"], "idempotencyKey":key
            }),
        )
    }
    fn query(report: &Value) -> Value {
        json!({"operationId":report["operationId"],"contextId":"context-fixture-01"})
    }
    fn reconcile(&mut self, report: &Value) -> Value {
        let principal = self.principal.clone();
        self.app()
            .operation_reconcile(&principal, &Self::query(report))
            .unwrap()
    }
    fn cancel(&mut self, report: &Value) -> Value {
        let principal = self.principal.clone();
        self.app()
            .operation_cancel(&principal, &Self::query(report))
            .unwrap()
    }
    fn recovery(&mut self, report: &Value) -> AppResult<Value> {
        let principal = self.principal.clone();
        let mut request = Self::query(report);
        request["mode"] = json!("recorded_direct");
        self.app().recovery_plan(&principal, &request)
    }
    fn get(&mut self, report: &Value) -> AppResult<Value> {
        let principal = self.principal.clone();
        self.app().operation_get(&principal, &Self::query(report))
    }
    fn reopen(self) -> Self {
        let Self {
            store,
            root,
            principal,
            project,
            target,
            authority,
            planner,
            provider,
            observer,
            ids,
            clock,
        } = self;
        drop(store);
        let store = DurableStore::open(StoreConfig::new(root.0.clone())).unwrap();
        Self {
            store,
            root,
            principal,
            project,
            target,
            authority,
            planner,
            provider,
            observer,
            ids,
            clock,
        }
    }
}

fn has_diagnostic(report: &Value, code: &str) -> bool {
    report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["code"] == code)
}

struct ArtifactRpc {
    principal: PrincipalId,
    context: ContextId,
}
impl ArtifactRpcContext for ArtifactRpc {
    fn check(&self) -> ArtifactResult<()> {
        Ok(())
    }
    fn principal_for_context(&self, context: &ContextId) -> ArtifactResult<PrincipalId> {
        if context != &self.context {
            return Err(ArtifactError::forbidden());
        }
        Ok(self.principal.clone())
    }
}
struct ArtifactAuthority {
    operation: OperationId,
    allowed: Rc<Cell<bool>>,
    checks: Rc<Cell<usize>>,
}
impl ResourceAuthority for ArtifactAuthority {
    fn authorize_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: &ContextId,
        owner: &ResourceOwner,
        _resource: &Value,
    ) -> ArtifactResult<()> {
        self.checks.set(self.checks.get() + 1);
        if !self.allowed.get() || owner != &ResourceOwner::Operation(self.operation.clone()) {
            return Err(ArtifactError::forbidden());
        }
        let record = store
            .operation(&self.operation)
            .map_err(|_| ArtifactError::forbidden())?;
        if &record.principal != principal || &record.context_id != context {
            return Err(ArtifactError::forbidden());
        }
        Ok(())
    }
}
struct ResourceReader {
    reader: ArtifactReader,
    rpc: ArtifactRpc,
    allowed: Rc<Cell<bool>>,
    checks: Rc<Cell<usize>>,
}
impl ResourceReader {
    fn new(principal: PrincipalId, operation: OperationId) -> Self {
        let allowed = Rc::new(Cell::new(true));
        let checks = Rc::new(Cell::new(0));
        let reader = ArtifactReader::new(
            Box::new(ArtifactAuthority {
                operation,
                allowed: allowed.clone(),
                checks: checks.clone(),
            }),
            32 * 1024 * 1024,
        )
        .unwrap();
        Self {
            reader,
            rpc: ArtifactRpc {
                principal,
                context: ContextId::new("context-fixture-01").unwrap(),
            },
            allowed,
            checks,
        }
    }
    fn admission(&mut self, store: &DurableStore, resource: &Value) -> ArtifactResult<Value> {
        self.reader.read(store, &self.rpc, &json!({
            "contextId":self.rpc.context,"resourceId":resource["resourceId"],"offset":"0","limitBytes":1
        }))
    }
    fn bytes(&mut self, store: &DurableStore, resource: &Value) -> Vec<u8> {
        // One FN31 admission proves registry metadata, ownership and fresh ACL
        // while verifying the whole blob. Trusted in-process read_blob then
        // checks exact full bytes without rehashing a large body per 64 KiB slice.
        let admitted = self.admission(store, resource).unwrap();
        assert_eq!(admitted["resource"], *resource);
        let blob = BlobRef {
            digest: decode(&resource["sha256"]).unwrap(),
            byte_length: resource["sizeBytes"].as_u64().unwrap(),
        };
        let bytes = store.read_blob(&blob).unwrap();
        assert_eq!(bytes.len() as u64, blob.byte_length);
        assert_eq!(raw_digest(&bytes), blob.digest);
        if !bytes.is_empty() {
            assert_eq!(admitted["encoding"], "utf8");
            assert_eq!(admitted["data"].as_str().unwrap().as_bytes(), &bytes[..1]);
        }
        bytes
    }
}

fn manifest_rows(fixture: &Fixture, reader: &mut ResourceReader, report: &Value) -> Vec<Value> {
    assert!(encode_json(report).unwrap().len() <= 64 * 1024);
    assert_eq!(report["result"]["evidenceAccessError"], false);
    assert_eq!(report["result"]["completeEvidenceInManifest"], true);
    let resource = &report["result"]["evidenceManifest"];
    assert_eq!(resource["mediaType"], "application/x-ndjson");
    assert!(report["artifacts"].as_array().unwrap().contains(resource));
    reader
        .bytes(&fixture.store, resource)
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| parse_json(line).unwrap())
        .collect()
}

fn body_resource(row: &Value, minimum_bytes: u64) -> &Value {
    row["resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|resource| {
            resource["sizeBytes"]
                .as_u64()
                .is_some_and(|size| size >= minimum_bytes)
        })
        .expect("manifest retains an issued original ProviderResult body")
}

fn check_body(
    fixture: &Fixture,
    reader: &mut ResourceReader,
    row: &Value,
    minimum_bytes: u64,
) -> Value {
    let resource = body_resource(row, minimum_bytes);
    let bytes = reader.bytes(&fixture.store, resource);
    let body = parse_json(&bytes).unwrap();
    validate("ProviderResult", &body).unwrap();
    assert!(
        body.get("kind").is_none(),
        "CAS retains the original pure ProviderResult envelope"
    );
    assert_eq!(encode_json(&body).unwrap(), bytes);
    assert_eq!(body["status"], row["value"]["status"]);
    assert_eq!(body["effects"], row["value"]["effects"]);
    body
}

#[test]
fn planning_has_no_target_effects_and_apply_twice_retains_one_durable_dispatch() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    assert_eq!(fixture.planner.preparations, 1);
    assert_eq!(fixture.target.borrow().dispatches, 0);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"before");
    let first = fixture.apply(&plan, "same-key").unwrap();
    assert_eq!(first["state"], "succeeded");
    assert_eq!(first["verification"], "independent_readback");
    assert_eq!(first["completedStepIds"], json!(["write-first"]));
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
    // Expiry/revocation cannot turn a retrieval of the original operation into
    // another write. Its durable idempotency identity remains unchanged.
    fixture.target.borrow_mut().apply_grant = false;
    fixture.clock.0.set(i128::MAX);
    let repeated = fixture.apply(&plan, "same-key").unwrap();
    assert_eq!(repeated, first);
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().readbacks, 1);
    let id: OperationId = decode(&first["operationId"]).unwrap();
    let record = fixture.store.operation(&id).unwrap();
    assert_eq!(record.steps[0].dispatch, DispatchEvidence::Observed);
    assert!(record.steps[0].finished);
    let invocation = fixture
        .store
        .stored_invocation(&id, &record.steps[0].step_id)
        .unwrap();
    let duplicate = fixture
        .provider
        .persist_dispatch_intent_with_store(
            &mut fixture.store,
            &id,
            &record.steps[0].step_id,
            &invocation,
            None,
        )
        .unwrap_err();
    assert_eq!(duplicate.code, "DISPATCH_REJECTED");
    assert!(
        std::error::Error::source(&duplicate)
            .unwrap()
            .downcast_ref::<mmmm_runtime::storage::StorageError>()
            .is_some()
    );
    assert_eq!(fixture.store.operation(&id).unwrap(), record);
    assert_eq!(
        fixture
            .store
            .stored_invocation(&id, &record.steps[0].step_id)
            .unwrap(),
        invocation
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.store.recovery_snapshots(&id).unwrap().len(), 1);
    assert!(fixture.root.0.is_absolute());
}

#[test]
fn unknown_dispatch_is_never_retried_and_reconcile_observes_the_original_target() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture.target.borrow_mut().lose_response = true;
    fixture.target.borrow_mut().observer_available = false;
    let unknown = fixture.apply(&plan, "unknown-key").unwrap();
    assert_eq!(unknown["state"], "outcome_unknown");
    assert_eq!(unknown["nextAction"], "reconcile");
    assert_eq!(unknown["completedStepIds"], json!([]));
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
    assert_eq!(fixture.apply(&plan, "unknown-key").unwrap(), unknown);
    assert_eq!(fixture.target.borrow().dispatches, 1);
    fixture.target.borrow_mut().observer_available = true;
    let resolved = fixture.reconcile(&unknown);
    assert_eq!(resolved["state"], "succeeded");
    assert_eq!(resolved["verification"], "independent_readback");
    assert_eq!(resolved["completedStepIds"], json!(["write-first"]));
    assert!(
        has_diagnostic(&resolved, "OUTCOME_UNKNOWN"),
        "failure history is retained"
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().polls, 1);
}

#[test]
fn actual_target_drift_before_dispatch_preserves_bytes_and_has_zero_provider_calls() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture
        .target
        .borrow_mut()
        .targets
        .insert(TARGET.into(), b"manual-before-apply".to_vec());
    let report = fixture.apply(&plan, "drift-key").unwrap();
    assert_eq!(report["state"], "failed_before_effects");
    assert!(has_diagnostic(&report, "TARGET_DRIFT"));
    assert_eq!(report["dispatchEvidence"], "not_dispatched");
    assert_eq!(fixture.target.borrow().dispatches, 0);
    assert_eq!(
        fixture.target.borrow().targets[TARGET],
        b"manual-before-apply"
    );
}

#[test]
fn malformed_complete_output_cannot_succeed_even_when_actual_target_change_is_confirmed() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture.target.borrow_mut().malformed_response = true;
    let unverified = fixture.apply(&plan, "malformed-key").unwrap();
    assert_ne!(unverified["state"], "succeeded");
    assert_eq!(unverified["completedStepIds"], json!([]));
    assert_eq!(unverified["unverifiedStepIds"], json!(["write-first"]));
    assert!(has_diagnostic(&unverified, "INVALID_PROVIDER_OUTPUT"));
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
    assert_eq!(fixture.target.borrow().dispatches, 1);
    let resolved = fixture.reconcile(&unverified);
    assert_eq!(resolved["state"], "succeeded");
    assert_eq!(resolved["completedStepIds"], json!(["write-first"]));
    assert!(has_diagnostic(&resolved, "INVALID_PROVIDER_OUTPUT"));
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().polls, 1);
}

#[test]
fn grant_revocation_after_verified_first_step_blocks_the_successor() {
    let mut fixture = Fixture::new(2);
    let plan = fixture.plan();
    fixture.target.borrow_mut().revoke_after_dispatch = true;
    let report = fixture.apply(&plan, "revoked-key").unwrap();
    assert_eq!(report["state"], "partial");
    assert!(has_diagnostic(&report, "PERMISSION_REQUIRED"));
    assert_eq!(report["completedStepIds"], json!(["write-first"]));
    assert_eq!(report["pendingStepIds"], json!(["write-second"]));
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
    let repeated = fixture.apply(&plan, "revoked-key").unwrap();
    assert_eq!(repeated["operationId"], report["operationId"]);
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

#[test]
fn ordered_same_target_writes_preserve_the_exact_independent_before_after_chain() {
    let mut fixture = Fixture::new(2);
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "ordered-key").unwrap();
    assert_eq!(report["state"], "succeeded");
    assert_eq!(
        report["completedStepIds"],
        json!(["write-first", "write-second"])
    );
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-second");
    assert_eq!(fixture.target.borrow().dispatches, 2);
    assert_eq!(fixture.target.borrow().readbacks, 2);
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let snapshots = fixture.store.recovery_snapshots(&operation).unwrap();
    assert_eq!(snapshots.len(), 2);
    let first = snapshots
        .iter()
        .find(|s| s.step_id.as_str() == "write-first")
        .unwrap();
    let second = snapshots
        .iter()
        .find(|s| s.step_id.as_str() == "write-second")
        .unwrap();
    assert_eq!(fixture.store.read_blob(&first.before).unwrap(), b"before");
    assert_eq!(
        fixture.store.read_blob(&first.after).unwrap(),
        b"after-first"
    );
    assert_eq!(second.before.digest, first.after.digest);
    assert_eq!(
        fixture.store.read_blob(&second.before).unwrap(),
        b"after-first"
    );
    assert_eq!(
        fixture.store.read_blob(&second.after).unwrap(),
        b"after-second"
    );
    let frozen = fixture
        .store
        .plan(
            &decode(&plan["planId"]).unwrap(),
            &decode(&plan["planHash"]).unwrap(),
        )
        .unwrap();
    assert_eq!(
        frozen, plan,
        "execution evidence never rewrites the frozen plan"
    );
    assert_eq!(
        frozen["preconditions"][0]["expected"],
        json!(raw_digest(b"before"))
    );
    let recovery = fixture.recovery(&report).unwrap();
    assert_ne!(recovery["planId"], plan["planId"]);
    assert_eq!(recovery["steps"][0]["arguments"]["text"], "before");
    assert_eq!(
        recovery["preconditions"][0]["expected"],
        json!(raw_digest(b"after-second"))
    );
    assert_eq!(fixture.planner.last_recovery_source_count, 2);
    assert_eq!(
        fixture.target.borrow().dispatches,
        2,
        "aggregated recovery planning is pure"
    );
}

#[test]
fn manual_edit_after_first_readback_blocks_the_ordered_same_target_successor() {
    let mut fixture = Fixture::new(2);
    let plan = fixture.plan();
    fixture.target.borrow_mut().edit_after_first_readback = true;
    let report = fixture.apply(&plan, "intervening-edit-key").unwrap();
    assert_eq!(report["state"], "partial");
    assert!(has_diagnostic(&report, "TARGET_DRIFT"));
    assert_eq!(report["completedStepIds"], json!(["write-first"]));
    assert_eq!(report["pendingStepIds"], json!(["write-second"]));
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().readbacks, 1);
    assert_eq!(
        fixture.target.borrow().targets[TARGET],
        b"manual-between-steps"
    );
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let snapshots = fixture.store.recovery_snapshots(&operation).unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(
        fixture.store.read_blob(&snapshots[0].after).unwrap(),
        b"after-first"
    );
}

#[test]
fn project_inspect_resolves_retained_historical_revision_after_the_head_advances() {
    let mut fixture = Fixture::new(1);
    let original = fixture.project.clone();
    let previous: Sha256Digest = decode(&original["revision"]).unwrap();
    let mut updated = original.clone();
    updated["name"] = json!("Updated authoring project");
    updated["revision"] = json!(projected_digest("Project", &updated).unwrap());
    fixture
        .store
        .save_project(&updated, Some(&previous))
        .unwrap();
    let principal = fixture.principal.clone();
    let historical = fixture
        .app()
        .project_inspect(
            &principal,
            &json!({
                "projectId":original["projectId"], "expectedRevision":original["revision"]
            }),
        )
        .unwrap();
    assert_eq!(historical["project"], original);
    assert_eq!(historical["runtimeBindingsAvailable"], false);
    let current = fixture
        .app()
        .project_inspect(
            &principal,
            &json!({
                "projectId":original["projectId"], "expectedRevision":null
            }),
        )
        .unwrap();
    assert_eq!(current["project"], updated);
    let missing = fixture.app().project_inspect(&principal, &json!({
        "projectId":original["projectId"], "expectedRevision":raw_digest(b"unretained-project-revision")
    })).unwrap_err();
    assert_eq!(missing.code, "REVISION_CONFLICT");
    assert_eq!(fixture.target.borrow().dispatches, 0);
}

#[test]
fn changed_session_with_a_valid_new_digest_still_rejects_the_frozen_context() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture.provider.live_context["environment"]["sessionEpoch"] = json!("epoch-fixture-new");
    fixture.provider.live_context["contextDigest"] =
        json!(projected_digest("ExecutionContext", &fixture.provider.live_context).unwrap());
    let report = fixture.apply(&plan, "stale-context-key").unwrap();
    assert_eq!(report["state"], "failed_before_effects");
    assert!(has_diagnostic(&report, "STALE_CONTEXT"));
    assert_eq!(fixture.target.borrow().dispatches, 0);
}

#[test]
fn changed_implementation_rejects_the_frozen_route_before_dispatch() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture.provider.descriptor["implementationDigest"] =
        json!(raw_digest(b"replacement-implementation"));
    let report = fixture.apply(&plan, "stale-implementation-key").unwrap();
    assert_eq!(report["state"], "failed_before_effects");
    assert!(has_diagnostic(&report, "STALE_PLAN"));
    assert_eq!(fixture.target.borrow().dispatches, 0);
}

#[test]
fn queued_cancel_is_terminal_but_dispatched_cancel_acknowledgment_is_not() {
    let mut queued = Fixture::new(1);
    let plan = queued.plan();
    let reservation = queued
        .store
        .reserve_operation(ReserveOperation {
            operation_id: OperationId::new("operation-queued-test").unwrap(),
            principal: queued.principal.clone(),
            project_id: decode(&plan["projectId"]).unwrap(),
            idempotency_key: "queued-key".into(),
            plan_id: decode::<PlanId>(&plan["planId"]).unwrap(),
            plan_hash: decode(&plan["planHash"]).unwrap(),
            context_id: decode(&plan["contextId"]).unwrap(),
        })
        .unwrap();
    assert!(matches!(reservation, Reservation::Created(_)));
    let cancelled = queued.cancel(&json!({"operationId":"operation-queued-test"}));
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(queued.target.borrow().dispatches, 0);
    assert_eq!(queued.target.borrow().cancel_requests, 0);
    assert_eq!(
        queued.apply(&plan, "queued-key").unwrap()["state"],
        "cancelled"
    );

    let mut dispatched = Fixture::new(1);
    let plan = dispatched.plan();
    dispatched.target.borrow_mut().observer_available = false;
    let unknown = dispatched.apply(&plan, "running-key").unwrap();
    let requested = dispatched.cancel(&unknown);
    assert_eq!(requested["state"], "cancel_requested");
    assert_eq!(requested["nextAction"], "reconcile");
    assert_eq!(dispatched.target.borrow().cancel_requests, 1);
    assert_eq!(dispatched.target.borrow().targets[TARGET], b"after-first");
    let id: OperationId = decode(&requested["operationId"]).unwrap();
    assert!(
        dispatched
            .store
            .operation(&id)
            .unwrap()
            .cancellation_requested
    );
    dispatched.cancel(&requested);
    assert_eq!(dispatched.target.borrow().cancel_requests, 1);
    dispatched.target.borrow_mut().observer_available = true;
    let resolved = dispatched.reconcile(&requested);
    assert_eq!(resolved["state"], "succeeded");
    assert!(
        dispatched
            .store
            .operation(&id)
            .unwrap()
            .cancellation_requested
    );
    assert_eq!(dispatched.target.borrow().dispatches, 1);
}

#[test]
fn recorded_recovery_is_a_new_pinned_plan_and_never_erases_a_manual_edit() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "original-key").unwrap();
    let recovery = fixture.recovery(&report).unwrap();
    assert_ne!(recovery["planId"], plan["planId"]);
    assert_eq!(
        recovery["preconditions"][0]["expected"],
        json!(raw_digest(b"after-first"))
    );
    assert_eq!(
        fixture.target.borrow().dispatches,
        1,
        "recovery planning stays pure"
    );
    fixture
        .target
        .borrow_mut()
        .targets
        .insert(TARGET.into(), b"manual-after-apply".to_vec());
    let conflict = fixture.recovery(&report).unwrap_err();
    assert_eq!(conflict.code, "RECOVERY_CONFLICT");
    assert_eq!(
        fixture.planner.recovery_preparations, 1,
        "conflicting bytes never reach recovery compilation"
    );
    let rejected = fixture.apply(&recovery, "recovery-key").unwrap();
    assert_eq!(rejected["state"], "failed_before_effects");
    assert!(has_diagnostic(&rejected, "TARGET_DRIFT"));
    assert_eq!(
        fixture.target.borrow().targets[TARGET],
        b"manual-after-apply"
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

#[test]
fn same_idempotency_key_cannot_select_a_different_frozen_plan() {
    let mut fixture = Fixture::new(1);
    let first = fixture.plan();
    let second = fixture.plan();
    fixture.apply(&first, "bound-key").unwrap();
    assert_eq!(
        fixture.apply(&second, "bound-key").unwrap_err().code,
        "IDEMPOTENCY_CONFLICT"
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

#[test]
fn failed_read_predecessor_never_authorizes_its_dependent_target_write() {
    let mut fixture = Fixture::new(2);
    let mut descriptor = fixture.provider.descriptor.clone();
    descriptor["actionId"] = json!("fixture:read_text");
    descriptor["effect"] = json!("read");
    descriptor["recovery"] = json!("none");
    descriptor["cancellation"] = json!("none");
    descriptor["idempotency"] = json!("read");
    descriptor["verificationRequirement"] = json!("provider_completion");
    descriptor["summary"] = json!("Reads the owned target without mutating it.");
    let first = &mut fixture.planner.prepared.steps[0];
    first["actionId"] = descriptor["actionId"].clone();
    for field in [
        "effect",
        "recovery",
        "verificationRequirement",
        "implementationDigest",
    ] {
        first[field] = descriptor[field].clone();
    }
    first["actionDigest"] = json!(canonical_digest(&descriptor).unwrap());
    first["resourcesWritten"] = json!([]);
    first["resourcesRead"] = json!([TARGET]);
    fixture
        .provider
        .extra_descriptors
        .insert("fixture:read_text".into(), descriptor);
    fixture.target.borrow_mut().fail_read = true;
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "failed-read-key").unwrap();
    assert_eq!(report["state"], "failed_before_effects");
    assert!(has_diagnostic(&report, "PROVIDER_FAILED"));
    assert_eq!(report["completedStepIds"], json!([]));
    assert_eq!(
        fixture.target.borrow().dispatches,
        1,
        "only the read is called"
    );
    assert_eq!(fixture.target.borrow().write_dispatches, 0);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"before");
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let record = fixture.store.operation(&operation).unwrap();
    assert!(
        !record.steps[0].finished,
        "a failed read is not a verified dependency"
    );
    assert_eq!(record.steps[1].dispatch, DispatchEvidence::NotSent);
    assert!(
        fixture
            .store
            .recovery_snapshots(&operation)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn current_observe_grant_can_reconcile_original_job_after_apply_policy_revocation() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture.target.borrow_mut().lose_response = true;
    fixture.target.borrow_mut().observer_available = false;
    let unknown = fixture.apply(&plan, "policy-change-key").unwrap();
    let operation: OperationId = decode(&unknown["operationId"]).unwrap();
    let step = decode(&plan["steps"][0]["stepId"]).unwrap();
    let original_invocation = fixture.store.stored_invocation(&operation, &step).unwrap();
    fixture.target.borrow_mut().apply_grant = false;
    fixture.target.borrow_mut().observer_available = true;
    fixture.provider.live_context["policyRevision"] =
        json!(raw_digest(b"revoked-apply-current-observe-policy"));
    fixture.provider.live_context["contextDigest"] =
        json!(projected_digest("ExecutionContext", &fixture.provider.live_context).unwrap());
    assert_ne!(
        fixture.provider.live_context["contextDigest"],
        original_invocation["contextDigest"]
    );
    let resolved = fixture.reconcile(&unknown);
    assert_eq!(resolved["state"], "succeeded");
    assert_eq!(resolved["verification"], "independent_readback");
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().polls, 1);
    assert_eq!(
        fixture.store.stored_invocation(&operation, &step).unwrap(),
        original_invocation,
        "a current Observe grant never replaces the original durable invocation"
    );
    assert_eq!(
        fixture.apply(&plan, "policy-change-key").unwrap()["operationId"],
        resolved["operationId"]
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

// These trusted-port fixtures exercise common journal admission only. They do
// not establish actual bootstrap, successor pairing or game acceptance.
fn successor_context_fixture(context: &Value) -> Value {
    let mut current = context.clone();
    current["contextId"] = json!("context-fixture-successor");
    current["environment"]["sessionEpoch"] = json!("epoch-fixture-successor");
    current["contextDigest"] = json!(projected_digest("ExecutionContext", &current).unwrap());
    current
}

#[test]
fn successor_observation_default_none_keeps_the_exact_session_guard() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture.target.borrow_mut().lose_response = true;
    fixture.target.borrow_mut().observer_available = false;
    let unknown = fixture.apply(&plan, "successor-none-key").unwrap();
    let mut current = successor_context_fixture(&fixture.provider.live_context);
    // Ordinary lookup keeps the original context ID; only its session changes.
    current["contextId"] = plan["contextId"].clone();
    current["contextDigest"] = json!(projected_digest("ExecutionContext", &current).unwrap());
    let mut provider = DefaultRegisteredReadProvider(Provider {
        target: fixture.target.clone(),
        live_context: current.clone(),
        descriptor: fixture.provider.descriptor.clone(),
        extra_descriptors: BTreeMap::new(),
        codec: None,
        // The wrapper intentionally inherits the trait's None method, even
        // when its wrapped fixture would offer a successor context.
        successor_context: Some(current),
    });
    let principal = fixture.principal.clone();
    let error = {
        let mut app = fixture.app();
        app.provider = &mut provider;
        app.operation_reconcile(&principal, &Fixture::query(&unknown))
            .unwrap_err()
    };
    assert_eq!(error.code, "STALE_CONTEXT");
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().polls, 0);
}

#[test]
fn admitted_successor_observes_the_original_invocation_and_never_dispatches_successors() {
    let mut fixture = Fixture::new(2);
    let plan = fixture.plan();
    fixture.target.borrow_mut().lose_response = true;
    fixture.target.borrow_mut().observer_available = false;
    let unknown = fixture.apply(&plan, "successor-observe-key").unwrap();
    let operation: OperationId = decode(&unknown["operationId"]).unwrap();
    let step: StepId = decode(&plan["steps"][0]["stepId"]).unwrap();
    let original = fixture.store.stored_invocation(&operation, &step).unwrap();
    fixture.provider.successor_context =
        Some(successor_context_fixture(&fixture.provider.live_context));
    fixture.target.borrow_mut().observer_available = true;
    fixture.target.borrow_mut().apply_grant = false;
    let reconciled = fixture.reconcile(&unknown);
    assert_eq!(reconciled["completedStepIds"], json!(["write-first"]));
    assert_eq!(reconciled["pendingStepIds"], json!(["write-second"]));
    let record = fixture.store.operation(&operation).unwrap();
    assert!(record.steps[0].finished);
    assert_eq!(record.steps[1].dispatch, DispatchEvidence::NotSent);
    assert_eq!(
        fixture.store.stored_invocation(&operation, &step).unwrap(),
        original
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().polls, 1);
}

#[test]
fn successor_observation_rejects_invalid_current_identity_scope_and_action_before_poll() {
    for case in [
        "principal",
        "project",
        "world",
        "game_instance",
        "kind",
        "side",
        "same_epoch",
        "missing_world",
        "scope",
        "digest",
        "descriptor",
        "revoked",
    ] {
        let mut fixture = Fixture::new(1);
        let plan = fixture.plan();
        fixture.target.borrow_mut().lose_response = true;
        fixture.target.borrow_mut().observer_available = false;
        let unknown = fixture.apply(&plan, "successor-invalid-key").unwrap();
        let mut current = successor_context_fixture(&fixture.provider.live_context);
        match case {
            "principal" => current["principalRef"] = json!("principal-other"),
            "project" => current["projectId"] = json!("project-other"),
            "world" => current["environment"]["worldId"] = json!("world-other"),
            "game_instance" => current["environment"]["gameInstanceId"] = json!("game-other"),
            "kind" => current["environment"]["kind"] = json!("daemon"),
            "side" => current["environment"]["side"] = json!("client"),
            "same_epoch" => {
                current["environment"]["sessionEpoch"] =
                    fixture.provider.live_context["environment"]["sessionEpoch"].clone()
            }
            "missing_world" => current["environment"]["worldId"] = Value::Null,
            "scope" => current["scope"]["resourceIds"] = json!([]),
            "descriptor" => {
                fixture.provider.descriptor["implementationDigest"] =
                    json!(raw_digest(b"successor-different-implementation"))
            }
            "revoked" => fixture.target.borrow_mut().observe_grant = false,
            "digest" => {
                current["contextDigest"] = json!(raw_digest(b"invalid-successor-context-digest"))
            }
            _ => unreachable!(),
        }
        if case != "digest" {
            current["contextDigest"] =
                json!(projected_digest("ExecutionContext", &current).unwrap());
        }
        fixture.provider.successor_context = Some(current);
        let principal = fixture.principal.clone();
        assert!(
            fixture
                .app()
                .operation_reconcile(&principal, &Fixture::query(&unknown))
                .is_err(),
            "{case}"
        );
        assert_eq!(fixture.target.borrow().dispatches, 1, "{case}");
        assert_eq!(fixture.target.borrow().polls, 0, "{case}");
        assert!(
            !fixture
                .store
                .operation(&decode(&unknown["operationId"]).unwrap())
                .unwrap()
                .steps[0]
                .finished,
            "{case}"
        );
    }
}

#[test]
fn successor_fresh_readback_without_original_provider_result_keeps_the_step_unfinished() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture.target.borrow_mut().lose_response = true;
    fixture.target.borrow_mut().observer_available = false;
    let unknown = fixture.apply(&plan, "successor-no-result-key").unwrap();
    fixture.provider.successor_context =
        Some(successor_context_fixture(&fixture.provider.live_context));
    fixture.target.borrow_mut().observer_available = true;
    fixture.target.borrow_mut().poll_response_missing = true;
    let reconciled = fixture.reconcile(&unknown);
    let operation: OperationId = decode(&unknown["operationId"]).unwrap();
    let record = fixture.store.operation(&operation).unwrap();
    assert_ne!(reconciled["state"], "succeeded");
    assert_eq!(reconciled["completedStepIds"], json!([]));
    assert_eq!(record.steps[0].effect, EffectEvidence::CompleteConfirmed);
    assert!(!record.steps[0].finished);
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().polls, 1);
}

#[test]
fn successor_observation_keeps_original_query_and_context_pin_checks() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture.target.borrow_mut().lose_response = true;
    fixture.target.borrow_mut().observer_available = false;
    let unknown = fixture.apply(&plan, "successor-original-pin-key").unwrap();
    let operation: OperationId = decode(&unknown["operationId"]).unwrap();
    let step: StepId = decode(&plan["steps"][0]["stepId"]).unwrap();
    let original = fixture.store.stored_invocation(&operation, &step).unwrap();
    let scope = fixture.store.operation(&operation).unwrap().scope;
    fixture.provider.successor_context =
        Some(successor_context_fixture(&fixture.provider.live_context));
    let principal = fixture.principal.clone();
    let mut query = Fixture::query(&unknown);
    query["contextId"] = json!("context-fixture-successor");
    assert_eq!(
        fixture
            .app()
            .operation_reconcile(&principal, &query)
            .unwrap_err()
            .code,
        "STALE_CONTEXT"
    );
    for case in ["pin_digest", "pin_environment", "original_digest"] {
        let mut frozen = plan.clone();
        let mut invocation = original.clone();
        match case {
            "pin_digest" => {
                frozen["contextPins"][0]["contextDigest"] =
                    json!(raw_digest(b"different-original-pin"))
            }
            "pin_environment" => {
                frozen["contextPins"][0]["environment"]["worldId"] = json!("world-other")
            }
            "original_digest" => {
                invocation["contextDigest"] = json!(raw_digest(b"different-original-context"))
            }
            _ => unreachable!(),
        }
        assert_eq!(
            fixture
                .app()
                .reconciliation_context(&principal, &frozen, &invocation, &scope)
                .unwrap_err()
                .code,
            "STALE_CONTEXT",
            "{case}"
        );
    }
    assert_eq!(
        fixture.store.stored_invocation(&operation, &step).unwrap(),
        original
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().polls, 0);
}

#[test]
fn retained_readback_envelope_pins_exact_recovery_bytes_across_orphan_collection() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "retained-snapshot-key").unwrap();
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let record = fixture.store.operation(&operation).unwrap();
    assert!(record.steps[0].finished);
    let envelopes: Vec<_> = record.steps[0]
        .observation_refs
        .iter()
        .map(|blob| parse_json(&fixture.store.read_blob(blob).unwrap()).unwrap())
        .filter(|value| value["kind"] == "independent_readback")
        .collect();
    assert!(!envelopes.is_empty());
    let direct = envelopes.last().unwrap()["directChanges"]
        .as_array()
        .unwrap();
    assert_eq!(direct.len(), 1);
    let retained: mmmm_runtime::storage::RecoverySnapshot = decode(&direct[0]).unwrap();
    assert_eq!(retained.operation_id, operation);
    assert_eq!(retained.before.digest, raw_digest(b"before"));
    assert_eq!(retained.after.digest, raw_digest(b"after-first"));
    assert_eq!(
        fixture.store.read_blob(&retained.before).unwrap(),
        b"before"
    );
    assert_eq!(
        fixture.store.read_blob(&retained.after).unwrap(),
        b"after-first"
    );
    assert_eq!(
        fixture.store.recovery_snapshots(&operation).unwrap(),
        vec![retained.clone()]
    );
    let orphan = fixture
        .store
        .put_blob(b"unreferenced application test blob")
        .unwrap();
    assert!(
        fixture
            .store
            .collect_orphan_blobs(100)
            .unwrap()
            .removed_blobs
            >= 1
    );
    assert!(fixture.store.read_blob(&orphan).is_err());
    assert_eq!(
        fixture.store.read_blob(&retained.before).unwrap(),
        b"before"
    );
    assert_eq!(
        fixture.store.read_blob(&retained.after).unwrap(),
        b"after-first"
    );
    for blob in record.steps[0].observation_refs.iter() {
        assert!(
            fixture.store.read_blob(blob).is_ok(),
            "operation evidence remains pinned"
        );
    }
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

#[test]
fn three_large_provider_bodies_remain_bounded_queryable_and_exact_after_restart() {
    // Each original body is below the strict JSON boundary. Their aggregate
    // exceeds it, which requires separate retained bodies and a small report.
    const BODY_BYTES: usize = 7 * 1024 * 1024;
    let mut fixture = Fixture::new(2);
    fixture.provider.descriptor["outputSchema"]["properties"]["payload"] = json!({"type":"string"});
    fixture.provider.descriptor["outputSchema"]["required"] = json!(["text", "payload"]);
    fixture.planner.prepared.steps = vec![
        write_step(
            &fixture.provider.descriptor,
            "write-first",
            "after-first",
            vec![],
        ),
        write_step(
            &fixture.provider.descriptor,
            "write-second",
            "after-second",
            vec!["write-first"],
        ),
        write_step(
            &fixture.provider.descriptor,
            "write-third",
            "after-third",
            vec!["write-second"],
        ),
    ];
    fixture.planner.prepared.time_budget_ms = 60_000;
    fixture.target.borrow_mut().provider_payload_bytes = BODY_BYTES;
    fixture.target.borrow_mut().fail_on_dispatch = Some(3);
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "large-three-key").unwrap();
    assert_eq!(
        report["state"], "partial",
        "reported failure never erases independently confirmed effects"
    );
    assert_eq!(report["result"]["providerResultCount"], 3);
    assert_eq!(report["result"]["providerStatusCounts"]["complete"], 2);
    assert_eq!(report["result"]["providerStatusCounts"]["failed"], 1);
    assert_eq!(report["result"]["failedStepCount"], 1);
    assert_eq!(report["result"]["effectCounts"]["complete_confirmed"], 3);
    assert_eq!(report["result"]["completedStepCount"], 2);
    assert_eq!(report["result"]["unverifiedStepCount"], 1);
    assert_eq!(report["result"]["omitted"]["providerResults"], 0);
    assert_eq!(fixture.target.borrow().dispatches, 3);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-third");
    for preview in report["result"]["providerResults"].as_array().unwrap() {
        assert_eq!(preview["bodyOmitted"], true);
        assert!(preview.get("response").is_none());
        assert!(preview.get("data").is_none());
    }
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let mut reader = ResourceReader::new(fixture.principal.clone(), operation.clone());
    let rows = manifest_rows(&fixture, &mut reader, &report);
    let provider_rows: Vec<_> = rows
        .iter()
        .filter(|row| row["kind"] == "provider_result")
        .collect();
    assert_eq!(provider_rows.len(), 3);
    let mut aggregate = 0u64;
    let mut original_resources = Vec::new();
    for row in provider_rows {
        let resource = body_resource(row, BODY_BYTES as u64);
        aggregate += resource["sizeBytes"].as_u64().unwrap();
        original_resources.push(resource.clone());
        let body = check_body(&fixture, &mut reader, row, BODY_BYTES as u64);
        assert_eq!(body["data"]["payload"].as_str().unwrap().len(), BODY_BYTES);
        assert!(
            body["data"]["payload"]
                .as_str()
                .unwrap()
                .bytes()
                .all(|byte| byte == b'p')
        );
        if row["stepId"] == "write-third" {
            assert_eq!(body["status"], "failed");
            assert_eq!(row["outputValidated"], false);
        } else {
            assert_eq!(body["status"], "complete");
            assert_eq!(row["outputValidated"], true);
        }
        assert_eq!(body["effects"], "recorded");
    }
    assert!(aggregate > 21 * 1024 * 1024);
    let summaries = fixture.store.operation_summaries(&operation).unwrap();
    assert!(!summaries.is_empty());
    assert!(summaries.iter().all(|blob| blob.byte_length <= 64 * 1024));
    assert_eq!(fixture.get(&report).unwrap(), report);
    assert_eq!(
        fixture.reconcile(&report),
        report,
        "settlement only reads the small retained status markers"
    );
    let mut fixture = fixture.reopen();
    let restarted = fixture.get(&report).unwrap();
    assert_eq!(restarted, report);
    let restarted_rows = manifest_rows(&fixture, &mut reader, &restarted);
    assert_eq!(restarted_rows, rows);
    let orphan = fixture
        .store
        .put_blob(b"unowned large-report test orphan")
        .unwrap();
    fixture.store.collect_orphan_blobs(1000).unwrap();
    assert!(fixture.store.read_blob(&orphan).is_err());
    for resource in original_resources {
        let bytes = reader.bytes(&fixture.store, &resource);
        assert_eq!(bytes.len() as u64, resource["sizeBytes"].as_u64().unwrap());
    }
    assert_eq!(fixture.get(&report).unwrap(), report);
    assert_eq!(fixture.target.borrow().dispatches, 3);
    assert_eq!(fixture.target.borrow().polls, 0);
}

#[test]
fn every_operation_and_manifest_read_rechecks_current_authority() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "fresh-read-grant-key").unwrap();
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let mut reader = ResourceReader::new(fixture.principal.clone(), operation);
    let resource = report["result"]["evidenceManifest"].clone();
    assert!(reader.admission(&fixture.store, &resource).is_ok());
    assert_eq!(
        reader.checks.get(),
        2,
        "admission and release both check resource ownership/ACL"
    );
    assert_eq!(fixture.get(&report).unwrap(), report);
    let checks = fixture.target.borrow().observation_checks;
    fixture.target.borrow_mut().observe_grant = false;
    for _ in 0..2 {
        assert_eq!(
            fixture.get(&report).unwrap_err().code,
            "PERMISSION_REQUIRED"
        );
    }
    assert_eq!(fixture.target.borrow().observation_checks, checks + 2);
    reader.allowed.set(false);
    for _ in 0..2 {
        assert_eq!(
            reader
                .admission(&fixture.store, &resource)
                .unwrap_err()
                .code,
            "RESOURCE_FORBIDDEN"
        );
    }
    assert_eq!(reader.checks.get(), 4);
    fixture.target.borrow_mut().observe_grant = true;
    reader.allowed.set(true);
    assert_eq!(fixture.get(&report).unwrap(), report);
    assert_eq!(
        reader.admission(&fixture.store, &resource).unwrap()["resource"],
        resource
    );
    assert_eq!(reader.checks.get(), 6);
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

#[test]
fn large_diagnostics_have_bounded_previews_and_exact_original_manifest_sources() {
    const DIAGNOSTICS: usize = 48;
    const MESSAGE_BYTES: usize = 20_000;
    let mut fixture = Fixture::new(1);
    fixture.target.borrow_mut().provider_diagnostic_count = DIAGNOSTICS;
    fixture.target.borrow_mut().provider_diagnostic_bytes = MESSAGE_BYTES;
    fixture.target.borrow_mut().fail_on_dispatch = Some(1);
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "large-diagnostics-key").unwrap();
    assert_eq!(report["state"], "partial");
    assert_eq!(report["result"]["providerStatusCounts"]["failed"], 1);
    assert_eq!(report["result"]["failedStepCount"], 1);
    assert_eq!(report["result"]["diagnosticCount"], DIAGNOSTICS + 1);
    assert!(report["result"]["omitted"]["diagnostics"].as_u64().unwrap() > 0);
    assert!(report["diagnostics"].as_array().unwrap().len() <= 16);
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .all(|diagnostic| { diagnostic["message"].as_str().unwrap().chars().count() <= 512 })
    );
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let mut reader = ResourceReader::new(fixture.principal.clone(), operation);
    let rows = manifest_rows(&fixture, &mut reader, &report);
    let provider = rows
        .iter()
        .find(|row| row["kind"] == "provider_result")
        .unwrap();
    assert_eq!(provider["diagnosticCount"], DIAGNOSTICS);
    assert_eq!(provider["diagnosticSeverityCounts"]["warning"], DIAGNOSTICS);
    let body = check_body(
        &fixture,
        &mut reader,
        provider,
        (DIAGNOSTICS * MESSAGE_BYTES) as u64,
    );
    let diagnostics = body["diagnostics"].as_array().unwrap();
    assert_eq!(diagnostics.len(), DIAGNOSTICS);
    for (index, diagnostic) in diagnostics.iter().enumerate() {
        assert_eq!(diagnostic["code"], format!("PROVIDER_DIAG_{index:04}"));
        assert_eq!(
            diagnostic["message"],
            format!("diagnostic-{index:04}:{}", "d".repeat(MESSAGE_BYTES))
        );
    }
    let mut fixture = fixture.reopen();
    let restarted = fixture.get(&report).unwrap();
    assert_eq!(restarted, report);
    assert_eq!(manifest_rows(&fixture, &mut reader, &restarted), rows);
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

#[test]
fn legacy_failed_provider_body_remains_visible_after_new_summary_markers_are_added() {
    let mut fixture = Fixture::new(1);
    fixture.target.borrow_mut().lose_response = true;
    fixture.target.borrow_mut().observer_available = false;
    let plan = fixture.plan();
    let unknown = fixture.apply(&plan, "mixed-legacy-key").unwrap();
    let operation: OperationId = decode(&unknown["operationId"]).unwrap();
    // Old releases retained an envelope, rather than a pure ProviderResult plus
    // its separate small marker. Preserve these exact old bytes during upgrade.
    let legacy = json!({"kind":"provider_result","stepId":"write-first",
        "value":{"contractVersion":"0.2.0","status":"failed","data":{},"effects":"unknown",
            "diagnostics":[{"code":"LEGACY_PROVIDER_FAILED","severity":"error","message":"Original retained failure"}],"artifacts":[]},
        "outputValidated":false,"actionDigest":plan["steps"][0]["actionDigest"],
        "outputSchemaDigest":canonical_digest(&fixture.provider.descriptor["outputSchema"]).unwrap()});
    let legacy_bytes = encode_json(&legacy).unwrap();
    let legacy_blob = fixture.store.put_blob(&legacy_bytes).unwrap();
    fixture
        .store
        .append_operation_evidence(&operation, &legacy_blob)
        .unwrap();
    let legacy_unvalidated = json!({"kind":"unvalidated_provider_result","stepId":"write-first",
        "value":{"contractVersion":"0.2.0","status":"complete","data":{"text":"u".repeat(7 * 1024 * 1024)},
            "effects":"unknown","diagnostics":[],"artifacts":[]}});
    let unvalidated_bytes = encode_json(&legacy_unvalidated).unwrap();
    let unvalidated_blob = fixture.store.put_blob(&unvalidated_bytes).unwrap();
    fixture
        .store
        .append_operation_evidence(&operation, &unvalidated_blob)
        .unwrap();
    let new_source = json!({"kind":"application_diagnostic","diagnostic":{
        "code":"NEW_SUMMARY_PRESENT","severity":"info","message":"A new marker was added after legacy evidence"}});
    let new_blob = fixture
        .store
        .put_blob(&encode_json(&new_source).unwrap())
        .unwrap();
    let new_summary = crate::report::compact_evidence(&new_source, &new_blob).unwrap();
    let marker = fixture
        .store
        .put_blob(&encode_json(&new_summary).unwrap())
        .unwrap();
    fixture
        .store
        .append_operation_summary(&operation, &marker, &[new_blob])
        .unwrap();
    assert!(
        !fixture
            .store
            .operation_summaries(&operation)
            .unwrap()
            .is_empty()
    );
    let mixed = fixture.get(&unknown).unwrap();
    assert_eq!(mixed["result"]["providerStatusCounts"]["failed"], 1);
    assert_eq!(mixed["result"]["failedStepCount"], 1);
    assert!(has_diagnostic(&mixed, "LEGACY_PROVIDER_FAILED"));
    assert!(has_diagnostic(&mixed, "NEW_SUMMARY_PRESENT"));
    let mut reader = ResourceReader::new(fixture.principal.clone(), operation);
    let rows = manifest_rows(&fixture, &mut reader, &mixed);
    let old_row = rows
        .iter()
        .find(|row| row["kind"] == "provider_result" && row["value"]["status"] == "failed")
        .unwrap();
    let resource = old_row["resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|resource| resource["sha256"] == legacy_blob.digest.as_str())
        .unwrap();
    assert_eq!(reader.bytes(&fixture.store, resource), legacy_bytes);
    let raw_row = rows
        .iter()
        .find(|row| row["kind"] == "unvalidated_provider_result")
        .unwrap();
    assert_eq!(raw_row["bodyOmitted"], true);
    assert!(
        raw_row.get("value").is_none(),
        "legacy unvalidated body is referenced rather than embedded in the manifest"
    );
    assert!(encode_json(raw_row).unwrap().len() < 64 * 1024);
    let raw_resource = raw_row["resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|resource| resource["sha256"] == unvalidated_blob.digest.as_str())
        .unwrap();
    assert_eq!(
        reader.bytes(&fixture.store, raw_resource),
        unvalidated_bytes
    );
    assert_eq!(
        mixed["result"]["providerResultCount"], 1,
        "unvalidated legacy status is never promoted to a validated provider result"
    );
    fixture.target.borrow_mut().observer_available = true;
    let reconciled = fixture.reconcile(&mixed);
    assert_eq!(
        reconciled["state"], "partial",
        "new successful response cannot hide an older retained failure"
    );
    assert_eq!(reconciled["result"]["providerStatusCounts"]["failed"], 1);
    assert_eq!(reconciled["result"]["providerStatusCounts"]["complete"], 1);
    assert_eq!(reconciled["completedStepIds"], json!([]));
    assert!(has_diagnostic(&reconciled, "LEGACY_PROVIDER_FAILED"));
    let mut fixture = fixture.reopen();
    assert_eq!(fixture.get(&reconciled).unwrap(), reconciled);
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

#[test]
fn precondition_batches_are_fresh_after_capture_and_keep_common_drift_checks() {
    // Reuse the existing fake target and real SQLite/CAS fixture. The second
    // batch edits the target after capture; this is no native/game approval.
    let mut live = Fixture::new(1);
    let plan = live.plan();
    live.target.borrow_mut().precondition_batch_mode = Some(PreconditionBatchMode::Live);
    let report = live.apply(&plan, "live-precondition-batch").unwrap();
    assert_eq!(report["state"], "succeeded");
    assert_eq!(live.target.borrow().precondition_batch_calls, 2);
    assert_eq!(live.target.borrow().single_precondition_calls, 0);
    assert_eq!(live.target.borrow().captures, 1);
    assert_eq!(live.target.borrow().dispatches, 1);

    let mut drift = Fixture::new(1);
    let plan = drift.plan();
    drift.target.borrow_mut().precondition_batch_mode = Some(PreconditionBatchMode::DriftSecond);
    let report = drift
        .apply(&plan, "changed-second-precondition-batch")
        .unwrap();
    assert_eq!(report["state"], "failed_before_effects");
    assert!(has_diagnostic(&report, "TARGET_DRIFT"));
    assert_eq!(drift.target.borrow().precondition_batch_calls, 2);
    assert_eq!(drift.target.borrow().single_precondition_calls, 0);
    assert_eq!(drift.target.borrow().captures, 1);
    assert_eq!(drift.target.borrow().dispatches, 0);
    assert_eq!(
        drift.target.borrow().targets[TARGET],
        b"external-edit-after-capture"
    );

    let mut short = Fixture::new(1);
    let plan = short.plan();
    short.target.borrow_mut().precondition_batch_mode = Some(PreconditionBatchMode::Empty);
    let report = short.apply(&plan, "short-precondition-batch").unwrap();
    assert_eq!(report["state"], "failed_before_effects");
    assert!(has_diagnostic(&report, "TARGET_DRIFT"));
    assert_eq!(short.target.borrow().precondition_batch_calls, 1);
    assert_eq!(short.target.borrow().single_precondition_calls, 0);
    assert_eq!(short.target.borrow().captures, 0);
    assert_eq!(short.target.borrow().dispatches, 0);

    let mut fallback = Fixture::new(1);
    let plan = fallback.plan();
    fallback.target.borrow_mut().precondition_batch_mode = Some(PreconditionBatchMode::Empty);
    fallback
        .target
        .borrow_mut()
        .targets
        .insert(TARGET.into(), b"external-edit".to_vec());
    // This existing wrapper does not override the new optional method, so the
    // trait's None path must observe the single condition and fail immediately.
    let mut provider = DefaultRegisteredReadProvider(Provider {
        target: fallback.target.clone(),
        live_context: fallback.provider.live_context.clone(),
        descriptor: fallback.provider.descriptor.clone(),
        extra_descriptors: BTreeMap::new(),
        codec: None,
        successor_context: None,
    });
    let principal = fallback.principal.clone();
    let report =
        {
            let mut app = fallback.app();
            app.provider = &mut provider;
            app.plan_apply(&principal, &json!({
            "contractVersion":"0.2.0", "planId":plan["planId"], "planHash":plan["planHash"],
            "contextId":plan["contextId"], "idempotencyKey":"default-none-precondition-batch"
        })).unwrap()
        };
    assert_eq!(report["state"], "failed_before_effects");
    assert!(has_diagnostic(&report, "TARGET_DRIFT"));
    assert_eq!(fallback.target.borrow().precondition_batch_calls, 0);
    assert_eq!(fallback.target.borrow().single_precondition_calls, 1);
    assert_eq!(fallback.target.borrow().captures, 0);
    assert_eq!(fallback.target.borrow().dispatches, 0);
}

#[test]
fn direct_recovery_write_without_before_capture_capability_never_dispatches() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    let principal = fixture.principal.clone();
    let mut observer = DefaultCaptureObserver(Observer {
        target: fixture.target.clone(),
    });
    let report = {
        let mut app = fixture.app();
        app.observer = &mut observer;
        app.plan_apply(
            &principal,
            &json!({
                "contractVersion":"0.2.0","planId":plan["planId"],"planHash":plan["planHash"],
                "contextId":plan["contextId"],"idempotencyKey":"missing-capture-key"
            }),
        )
        .unwrap()
    };
    assert_eq!(report["state"], "failed_before_effects");
    assert_eq!(report["dispatchEvidence"], "not_dispatched");
    assert_eq!(fixture.target.borrow().dispatches, 0);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"before");
    assert_eq!(
        fixture.target.borrow().captures,
        0,
        "default capture capability supplied no implementation"
    );
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    assert!(
        fixture
            .store
            .recovery_snapshots(&operation)
            .unwrap()
            .is_empty()
    );
    let mut unavailable = Fixture::new(1);
    let plan = unavailable.plan();
    unavailable.target.borrow_mut().capture_available = false;
    let report = unavailable.apply(&plan, "unavailable-capture-key").unwrap();
    assert_eq!(report["state"], "failed_before_effects");
    assert_eq!(report["dispatchEvidence"], "not_dispatched");
    assert_eq!(unavailable.target.borrow().captures, 1);
    assert_eq!(unavailable.target.borrow().dispatches, 0);
    assert_eq!(unavailable.target.borrow().targets[TARGET], b"before");
}

#[test]
fn independently_captured_before_images_must_match_original_pins_and_phase_bytes_before_dispatch() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture.target.borrow_mut().capture_identity_mismatch = true;
    let report = fixture.apply(&plan, "mismatched-capture-key").unwrap();
    assert_eq!(report["state"], "failed_before_effects");
    assert_eq!(report["dispatchEvidence"], "not_dispatched");
    assert_eq!(fixture.target.borrow().captures, 1);
    assert_eq!(fixture.target.borrow().dispatches, 0);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"before");
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    assert!(
        fixture
            .store
            .recovery_snapshots(&operation)
            .unwrap()
            .is_empty()
    );
    let mut phase_mismatch = Fixture::new(1);
    let plan = phase_mismatch.plan();
    phase_mismatch.target.borrow_mut().capture_bytes_mismatch = true;
    let report = phase_mismatch
        .apply(&plan, "mismatched-before-bytes-key")
        .unwrap();
    assert_eq!(report["state"], "failed_before_effects");
    assert!(has_diagnostic(&report, "TARGET_DRIFT"));
    assert_eq!(report["dispatchEvidence"], "not_dispatched");
    assert_eq!(phase_mismatch.target.borrow().captures, 1);
    assert_eq!(phase_mismatch.target.borrow().dispatches, 0);
    assert_eq!(phase_mismatch.target.borrow().targets[TARGET], b"before");
}

#[test]
fn recovery_before_bytes_come_from_independent_predispatch_capture_after_restart_and_gc() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture.target.borrow_mut().forged_readback_before = true;
    let report = fixture.apply(&plan, "before-provenance-key").unwrap();
    assert_eq!(report["state"], "succeeded");
    assert_eq!(fixture.target.borrow().captures, 1);
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let snapshot = fixture
        .store
        .recovery_snapshots(&operation)
        .unwrap()
        .remove(0);
    let capture_marker = fixture
        .store
        .operation_summaries(&operation)
        .unwrap()
        .iter()
        .map(|blob| parse_json(&fixture.store.read_blob(blob).unwrap()).unwrap())
        .find(|value| value["kind"] == "before_capture_summary")
        .expect("durable before capture has a bounded retained marker");
    let capture_blob: BlobRef = decode(&capture_marker["captureBlob"]).unwrap();
    let capture_bytes = fixture.store.read_blob(&capture_blob).unwrap();
    let capture = parse_json(&capture_bytes).unwrap();
    assert_eq!(capture["kind"], "before_capture");
    assert_eq!(capture["version"], 1);
    assert_eq!(capture["operationId"], report["operationId"]);
    let invocation = fixture
        .store
        .stored_invocation(&operation, &snapshot.step_id)
        .unwrap();
    for field in [
        "stepId",
        "invocationId",
        "bindingId",
        "contextDigest",
        "implementationDigest",
        "argumentsDigest",
    ] {
        assert_eq!(
            capture[field], invocation[field],
            "capture identifies the exact original dispatch"
        );
    }
    assert_eq!(capture["images"][0]["target"], TARGET);
    let captured_before: BlobRef = decode(&capture["images"][0]["before"]).unwrap();
    assert_eq!(captured_before, snapshot.before);
    assert_eq!(
        fixture.store.read_blob(&captured_before).unwrap(),
        b"before"
    );
    assert_eq!(
        fixture.store.read_blob(&snapshot.before).unwrap(),
        b"before"
    );
    assert_ne!(
        snapshot.before.digest,
        raw_digest(b"forged-after-dispatch-before")
    );
    assert_eq!(
        fixture.store.read_blob(&snapshot.after).unwrap(),
        b"after-first"
    );
    let mut fixture = fixture.reopen();
    assert_eq!(fixture.get(&report).unwrap(), report);
    let orphan = fixture
        .store
        .put_blob(b"unretained before-provenance orphan")
        .unwrap();
    fixture.store.collect_orphan_blobs(100).unwrap();
    assert!(fixture.store.read_blob(&orphan).is_err());
    assert_eq!(
        fixture.store.read_blob(&capture_blob).unwrap(),
        capture_bytes
    );
    assert_eq!(
        fixture.store.read_blob(&captured_before).unwrap(),
        b"before"
    );
    assert_eq!(
        fixture.store.read_blob(&snapshot.before).unwrap(),
        b"before"
    );
    assert_eq!(
        fixture.store.recovery_snapshots(&operation).unwrap(),
        vec![snapshot]
    );
    let recovery = fixture.recovery(&report).unwrap();
    assert_eq!(recovery["steps"][0]["arguments"]["text"], "before");
    assert_eq!(
        recovery["preconditions"][0]["expected"],
        json!(raw_digest(b"after-first"))
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

struct DefaultRegisteredReadProvider(Provider);
impl ProviderPort for DefaultRegisteredReadProvider {
    // Inherit the unavailable registered-read boundary rather than fabricate an invocation.
    fn context(&mut self, principal: &PrincipalId, id: &ContextId) -> AppResult<Value> {
        self.0.context(principal, id)
    }
    fn action_descriptor(&mut self, step: &Value, context: &Value) -> AppResult<Value> {
        self.0.action_descriptor(step, context)
    }
    fn observe_precondition(
        &mut self,
        precondition: &Value,
        context: &Value,
    ) -> AppResult<Sha256Digest> {
        self.0.observe_precondition(precondition, context)
    }
    fn verify_dependencies(&mut self, pins: &[Value], context: &Value) -> AppResult<()> {
        self.0.verify_dependencies(pins, context)
    }
    fn dispatch(&mut self, invocation: &Value) -> AppResult<Value> {
        self.0.dispatch(invocation)
    }
    fn poll(&mut self, invocation: &Value, receipt: Option<&str>) -> AppResult<Option<Value>> {
        self.0.poll(invocation, receipt)
    }
    fn request_cancel(&mut self, invocation: &Value, receipt: Option<&str>) -> AppResult<()> {
        self.0.request_cancel(invocation, receipt)
    }
}

fn registered_read_fixture() -> Fixture {
    let mut fixture = Fixture::new(1);
    let descriptor = &mut fixture.provider.descriptor;
    descriptor["effect"] = json!("read");
    descriptor["recovery"] = json!("none");
    descriptor["cancellation"] = json!("none");
    descriptor["idempotency"] = json!("read");
    descriptor["verificationRequirement"] = json!("schema_only");
    fixture
}

fn registered_request(fixture: &Fixture) -> Value {
    json!({"contextId":fixture.provider.live_context["contextId"],"bindingId":"binding-fixture-01",
        "actionId":fixture.provider.descriptor["actionId"],"actionDigest":canonical_digest(&fixture.provider.descriptor).unwrap(),
        "arguments":{"text":"opaque-request-text"}})
}

#[test]
fn idempotent_apply_cannot_release_existing_results_without_current_observe_permission() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    let original = fixture.apply(&plan, "observe-required-key").unwrap();
    let operation: OperationId = decode(&original["operationId"]).unwrap();
    let stored = fixture.store.operation(&operation).unwrap();
    let checks = fixture.target.borrow().observation_checks;
    fixture.target.borrow_mut().observe_grant = false;
    assert_eq!(
        fixture
            .apply(&plan, "observe-required-key")
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
    assert!(fixture.target.borrow().observation_checks > checks);
    assert_eq!(fixture.store.operation(&operation).unwrap(), stored);
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
    fixture.target.borrow_mut().observe_grant = true;
    assert_eq!(
        fixture.apply(&plan, "observe-required-key").unwrap(),
        original
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

#[test]
fn registered_read_uses_actual_read_boundary_and_default_unavailable_never_dispatches() {
    let mut fixture = registered_read_fixture();
    let request = registered_request(&fixture);
    let principal = fixture.principal.clone();
    let output = fixture.app().action_read(&principal, &request).unwrap();
    assert_eq!(output["data"]["text"], "before");
    assert_eq!(output["effects"], "none");
    assert_eq!(fixture.target.borrow().registered_reads, 1);
    assert_eq!(fixture.target.borrow().read_checks, 2);
    assert_eq!(fixture.target.borrow().dispatches, 0);
    assert_eq!(fixture.ids.0, 0);
    let mut provider = DefaultRegisteredReadProvider(Provider {
        target: fixture.target.clone(),
        live_context: fixture.provider.live_context.clone(),
        descriptor: fixture.provider.descriptor.clone(),
        extra_descriptors: BTreeMap::new(),
        codec: None,
        successor_context: None,
    });
    let error = {
        let mut app = fixture.app();
        app.provider = &mut provider;
        app.action_read(&principal, &request).unwrap_err()
    };
    assert_eq!(error.code, "CAPABILITY_UNAVAILABLE");
    assert_eq!(fixture.target.borrow().registered_reads, 1);
    assert_eq!(fixture.target.borrow().dispatches, 0);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"before");
    assert!(fixture.target.borrow().invocations.is_empty());
}

#[test]
fn registered_read_admission_rejects_bad_input_digest_context_grant_and_write_effect() {
    for case in ["input", "digest", "context", "grant", "write"] {
        let mut fixture = registered_read_fixture();
        if case == "write" {
            fixture.provider.descriptor["effect"] = json!("write");
        }
        let mut request = registered_request(&fixture);
        let code = match case {
            "input" => {
                request["arguments"]["text"] = json!(7);
                "INVALID_INPUT"
            }
            "digest" => {
                request["actionDigest"] = json!(raw_digest(b"unregistered-action-digest"));
                "UNKNOWN_CAPABILITY"
            }
            "context" => {
                fixture.provider.live_context["principalRef"] = json!("principal-different");
                fixture.provider.live_context["contextDigest"] = json!(
                    projected_digest("ExecutionContext", &fixture.provider.live_context).unwrap()
                );
                "PERMISSION_REQUIRED"
            }
            "grant" => {
                fixture.target.borrow_mut().read_grant = false;
                "PERMISSION_REQUIRED"
            }
            "write" => "EFFECT_MISMATCH",
            _ => unreachable!(),
        };
        let principal = fixture.principal.clone();
        assert_eq!(
            fixture
                .app()
                .action_read(&principal, &request)
                .unwrap_err()
                .code,
            code,
            "{case}"
        );
        assert_eq!(fixture.target.borrow().registered_reads, 0, "{case}");
        assert_eq!(fixture.target.borrow().dispatches, 0, "{case}");
        assert_eq!(fixture.target.borrow().targets[TARGET], b"before", "{case}");
    }
}

#[test]
fn registered_read_validates_output_and_reauthorizes_fresh_context_before_releasing_data() {
    for case in ["output", "revoke", "context"] {
        let mut fixture = registered_read_fixture();
        let code = match case {
            "output" => {
                fixture.target.borrow_mut().invalid_read_output = true;
                "OUTPUT_INVALID"
            }
            "revoke" => {
                fixture.target.borrow_mut().revoke_read_after_callback = true;
                "PERMISSION_REQUIRED"
            }
            "context" => {
                fixture.target.borrow_mut().change_context_after_read = true;
                "STALE_CONTEXT"
            }
            _ => unreachable!(),
        };
        let request = registered_request(&fixture);
        let principal = fixture.principal.clone();
        assert_eq!(
            fixture
                .app()
                .action_read(&principal, &request)
                .unwrap_err()
                .code,
            code,
            "{case}"
        );
        assert_eq!(fixture.target.borrow().registered_reads, 1, "{case}");
        assert_eq!(fixture.target.borrow().dispatches, 0, "{case}");
        assert_eq!(fixture.target.borrow().targets[TARGET], b"before", "{case}");
        if case != "output" {
            assert_eq!(fixture.target.borrow().read_checks, 2, "{case}");
        }
    }
}

#[test]
fn registered_action_plan_pins_opaque_request_through_shared_planner_without_preview_or_dispatch() {
    let mut fixture = Fixture::new(1);
    let request = registered_request(&fixture);
    let principal = fixture.principal.clone();
    let plan = fixture.app().action_plan(&principal, &request).unwrap();
    assert_eq!(fixture.planner.preparations, 1);
    let seen = fixture.planner.last_request.as_ref().unwrap();
    assert_eq!(
        seen["intent"],
        json!({"kind":"external.action","request":request})
    );
    for field in [
        "actionId",
        "bindingId",
        "actionDigest",
        "arguments",
        "contextId",
    ] {
        assert_eq!(plan["steps"][0][field], request[field]);
    }
    assert_eq!(
        plan["steps"][0]["implementationDigest"],
        fixture.provider.descriptor["implementationDigest"]
    );
    assert_eq!(fixture.target.borrow().registered_reads, 0);
    assert_eq!(fixture.target.borrow().dispatches, 0);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"before");
    assert_eq!(
        fixture
            .store
            .plan(
                &decode(&plan["planId"]).unwrap(),
                &decode(&plan["planHash"]).unwrap()
            )
            .unwrap(),
        plan
    );
}

fn result_bound_fixture() -> Fixture {
    // Echo alone cannot exercise original-result association: this provider
    // writes after-first but returns different validated data for the consumer.
    let mut fixture = Fixture::new(2);
    fixture.target.borrow_mut().producer_result_text = Some("resolved-from-first".into());
    fixture.target.borrow_mut().footprint_registered = true;
    fixture.planner.prepared.steps[1]["arguments"] = json!({"text":"frozen-placeholder"});
    let codec = RegisteredResultCodec {
        codec_id: ObjectId::new("codec-application-identity").unwrap(),
        implementation: ResultCodecImplementation::JsonIdentityV1,
        input_schema: json!({"type":"string"}),
        output_schema: json!({"type":"string"}),
        allowed_slots: vec![ResultArgumentSlot {
            action_digest: canonical_digest(&fixture.provider.descriptor).unwrap(),
            argument_pointer: "/text".into(),
        }],
    };
    let binding = ResultStepBinding {
        argument_pointer: "/text".into(),
        source_step_id: StepId::new("write-first").unwrap(),
        output_pointer: "/text".into(),
        expected_schema_digest: canonical_digest(&fixture.provider.descriptor["outputSchema"])
            .unwrap(),
        codec_id: codec.codec_id.clone(),
        codec_digest: codec.metadata_digest().unwrap(),
    };
    fixture.planner.prepared.steps[1]["resultBindings"] = json!([binding]);
    fixture.provider.codec = Some(codec);
    fixture
}

fn assert_consumer_not_sent(fixture: &Fixture, report: &Value) {
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let consumer = StepId::new("write-second").unwrap();
    let record = fixture.store.operation(&operation).unwrap();
    let source = record
        .steps
        .iter()
        .find(|s| s.step_id.as_str() == "write-first")
        .unwrap();
    let pending = record.steps.iter().find(|s| s.step_id == consumer).unwrap();
    assert!(source.invocation_id.is_some());
    assert!(source.invocation_digest.is_some());
    assert_eq!(pending.dispatch, DispatchEvidence::NotSent);
    assert!(pending.invocation_id.is_none());
    assert!(
        fixture
            .store
            .stored_invocation(&operation, &consumer)
            .is_err()
    );
    assert!(
        fixture
            .store
            .stored_resolution_witness(&operation, &consumer)
            .is_err()
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().write_dispatches, 1);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
}

#[test]
fn result_bound_consumer_uses_original_validated_data_and_retains_immutable_plan_witness_after_restart_gc()
 {
    let mut fixture = result_bound_fixture();
    let plan = fixture.plan();
    assert_eq!(fixture.target.borrow().dispatches, 0);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"before");
    let report = fixture.apply(&plan, "result-bound-key").unwrap();
    assert_eq!(report["state"], "succeeded");
    assert_eq!(fixture.target.borrow().dispatches, 2);
    assert_eq!(fixture.target.borrow().footprint_checks, 1);
    assert_eq!(
        fixture.target.borrow().targets[TARGET],
        b"resolved-from-first"
    );
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let consumer = StepId::new("write-second").unwrap();
    let invocation = fixture
        .store
        .stored_invocation(&operation, &consumer)
        .unwrap();
    let resolved_arguments = json!({"text":"resolved-from-first"});
    assert_eq!(invocation["arguments"], resolved_arguments);
    assert_ne!(invocation["arguments"], plan["steps"][1]["arguments"]);
    assert_eq!(
        plan["steps"][1]["arguments"],
        json!({"text":"frozen-placeholder"})
    );
    let witness = fixture
        .store
        .stored_resolution_witness(&operation, &consumer)
        .unwrap();
    assert_eq!(witness.kind, "result_resolution_witness");
    assert_eq!(witness.version, 1);
    assert_eq!(witness.operation_id, operation);
    assert_eq!(witness.step_id, consumer);
    assert_eq!(json!(witness.plan_hash), plan["planHash"]);
    assert_eq!(
        witness.template_arguments_digest,
        canonical_digest(&plan["steps"][1]["arguments"]).unwrap()
    );
    assert_eq!(
        witness.arguments_digest,
        canonical_digest(&resolved_arguments).unwrap()
    );
    assert_eq!(
        json!(witness.arguments_digest),
        invocation["argumentsDigest"]
    );
    assert_eq!(json!(witness.context_digest), invocation["contextDigest"]);
    assert_eq!(
        json!(witness.action_digest),
        plan["steps"][1]["actionDigest"]
    );
    assert_eq!(
        json!(witness.implementation_digest),
        plan["steps"][1]["implementationDigest"]
    );
    assert_eq!(
        witness.resolved_footprint,
        ResultFootprint {
            resources_read: decode(&plan["steps"][1]["resourcesRead"]).unwrap(),
            resources_written: decode(&plan["steps"][1]["resourcesWritten"]).unwrap(),
        }
    );
    assert_eq!(
        parse_json(&fixture.store.read_blob(&witness.arguments_blob).unwrap()).unwrap(),
        resolved_arguments
    );
    assert_eq!(witness.bindings.len(), 1);
    let binding = &witness.bindings[0];
    let record = fixture.store.operation(&operation).unwrap();
    let resolved_step = record
        .steps
        .iter()
        .find(|step| step.step_id == consumer)
        .unwrap();
    assert_eq!(resolved_step.dispatch, DispatchEvidence::Observed);
    assert_eq!(
        resolved_step.invocation_digest,
        Some(raw_digest(&encode_json(&invocation).unwrap()))
    );
    let duplicate = fixture
        .provider
        .persist_dispatch_intent_with_store(
            &mut fixture.store,
            &operation,
            &consumer,
            &invocation,
            None,
        )
        .unwrap_err();
    assert_eq!(duplicate.code, "DISPATCH_REJECTED");
    assert_eq!(fixture.store.operation(&operation).unwrap(), record);
    let retained_witness = fixture
        .store
        .stored_resolution_witness(&operation, &consumer)
        .unwrap();
    assert_eq!(json!(retained_witness), json!(witness));
    assert_eq!(fixture.target.borrow().dispatches, 2);
    let source = record
        .steps
        .iter()
        .find(|s| s.step_id.as_str() == "write-first")
        .unwrap();
    assert_eq!(
        Some(binding.source_invocation_id.clone()),
        source.invocation_id
    );
    assert_eq!(
        Some(binding.source_invocation_digest.clone()),
        source.invocation_digest
    );
    assert_eq!(
        json!(binding.binding),
        plan["steps"][1]["resultBindings"][0]
    );
    let raw_result = parse_json(&fixture.store.read_blob(&binding.source_result).unwrap()).unwrap();
    assert_eq!(raw_result["status"], "complete");
    assert_eq!(raw_result["data"]["text"], "resolved-from-first");
    assert!(
        raw_result.get("kind").is_none(),
        "source body remains a plain ProviderResult"
    );
    let marker = parse_json(
        &fixture
            .store
            .read_blob(&binding.source_result_summary)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(marker["kind"], "provider_result");
    assert_eq!(marker["stepId"], "write-first");
    assert_eq!(marker["invocationId"], json!(binding.source_invocation_id));
    assert_eq!(marker["resultBlob"], json!(binding.source_result));
    assert_eq!(marker["outputValidated"], true);
    assert_eq!(marker["value"]["status"], "complete");
    assert_eq!(marker["actionDigest"], plan["steps"][0]["actionDigest"]);
    assert_eq!(
        marker["outputSchemaDigest"],
        json!(binding.binding.expected_schema_digest)
    );
    assert!(
        fixture
            .store
            .operation_summaries(&operation)
            .unwrap()
            .contains(&binding.source_result_summary)
    );
    assert!(
        fixture
            .store
            .operation_evidence_refs(&operation)
            .unwrap()
            .contains(&binding.source_result)
    );
    assert_eq!(
        parse_json(&fixture.store.read_blob(&binding.source_action).unwrap()).unwrap(),
        fixture.provider.descriptor
    );
    assert_eq!(
        parse_json(&fixture.store.read_blob(&binding.codec).unwrap()).unwrap(),
        fixture.provider.codec.as_ref().unwrap().metadata().unwrap()
    );
    assert_eq!(
        binding.selected_value_digest,
        canonical_digest(&json!("resolved-from-first")).unwrap()
    );
    assert_eq!(binding.selected_value_digest, binding.resolved_value_digest);
    let snapshots = fixture.store.recovery_snapshots(&operation).unwrap();
    let second = snapshots.iter().find(|s| s.step_id == consumer).unwrap();
    assert_eq!(
        fixture.store.read_blob(&second.before).unwrap(),
        b"after-first"
    );
    assert_eq!(
        fixture.store.read_blob(&second.after).unwrap(),
        b"resolved-from-first"
    );
    let capture = fixture
        .store
        .operation_summaries(&operation)
        .unwrap()
        .iter()
        .map(|blob| parse_json(&fixture.store.read_blob(blob).unwrap()).unwrap())
        .filter(|value| value["kind"] == "before_capture_summary")
        .map(|marker| {
            let blob: BlobRef = decode(&marker["captureBlob"]).unwrap();
            parse_json(&fixture.store.read_blob(&blob).unwrap()).unwrap()
        })
        .find(|capture| capture["stepId"] == "write-second")
        .unwrap();
    assert_eq!(capture["argumentsDigest"], invocation["argumentsDigest"]);
    let retained = [
        witness.arguments_blob.clone(),
        binding.source_result.clone(),
        binding.source_result_summary.clone(),
        binding.source_action.clone(),
        binding.codec.clone(),
    ];
    let before_gc: Vec<_> = retained
        .iter()
        .map(|blob| fixture.store.read_blob(blob).unwrap())
        .collect();
    let witness_json = json!(witness);
    fixture.store.collect_orphan_blobs(1000).unwrap();
    let mut restarted = fixture.reopen();
    assert_eq!(
        json!(
            restarted
                .store
                .stored_resolution_witness(&operation, &consumer)
                .unwrap()
        ),
        witness_json
    );
    for (blob, bytes) in retained.iter().zip(before_gc) {
        assert_eq!(restarted.store.read_blob(blob).unwrap(), bytes);
    }
    assert_eq!(
        restarted
            .store
            .plan(
                &decode(&plan["planId"]).unwrap(),
                &decode(&plan["planHash"]).unwrap()
            )
            .unwrap(),
        plan
    );
    assert_eq!(
        restarted.apply(&plan, "result-bound-key").unwrap()["operationId"],
        report["operationId"]
    );
    assert_eq!(restarted.target.borrow().dispatches, 2);
}

#[test]
fn result_binding_freeze_rejects_missing_mismatched_overlapping_and_protected_codecs_without_effects()
 {
    for case in [
        "unavailable",
        "digest",
        "slot",
        "overlap",
        "protected_target",
        "source_schema",
    ] {
        let mut fixture = result_bound_fixture();
        match case {
            "unavailable" => fixture.provider.codec = None,
            "digest" => {
                fixture.planner.prepared.steps[1]["resultBindings"][0]["codecDigest"] =
                    json!(raw_digest(b"wrong-codec-digest"))
            }
            "source_schema" => {
                fixture.planner.prepared.steps[1]["resultBindings"][0]["expectedSchemaDigest"] =
                    json!(raw_digest(b"different-source-schema"))
            }
            "slot" => {
                let codec = fixture.provider.codec.as_mut().unwrap();
                codec.allowed_slots[0].action_digest = raw_digest(b"different-consumer-action");
                fixture.planner.prepared.steps[1]["resultBindings"][0]["codecDigest"] =
                    json!(codec.metadata_digest().unwrap());
            }
            "overlap" => {
                let binding = fixture.planner.prepared.steps[1]["resultBindings"][0].clone();
                fixture.planner.prepared.steps[1]["resultBindings"] =
                    json!([binding.clone(), binding]);
            }
            "protected_target" => {
                fixture.provider.descriptor["inputSchema"]["properties"]["target"] =
                    json!({"type":"string"});
                let action_digest = canonical_digest(&fixture.provider.descriptor).unwrap();
                for step in &mut fixture.planner.prepared.steps {
                    step["actionDigest"] = json!(action_digest);
                    step["arguments"]["target"] = json!(TARGET);
                }
                let codec = fixture.provider.codec.as_mut().unwrap();
                codec.allowed_slots[0].action_digest = action_digest;
                codec.allowed_slots[0].argument_pointer = "/target".into();
                fixture.planner.prepared.steps[1]["resultBindings"][0]["argumentPointer"] =
                    json!("/target");
                fixture.planner.prepared.steps[1]["resultBindings"][0]["codecDigest"] =
                    json!(codec.metadata_digest().unwrap());
            }
            _ => unreachable!(),
        }
        let error = fixture.try_plan().unwrap_err();
        assert!(
            ["CAPABILITY_UNAVAILABLE", "INVALID_INPUT", "STALE_PLAN"].contains(&error.code),
            "{case}: {error:?}"
        );
        assert_eq!(fixture.target.borrow().dispatches, 0, "{case}");
        assert_eq!(fixture.target.borrow().captures, 0, "{case}");
        assert_eq!(fixture.target.borrow().targets[TARGET], b"before", "{case}");
    }
}

#[test]
fn result_resolution_rejects_codec_schema_mismatches_preserving_first_effects() {
    for case in ["codec_input", "codec_output"] {
        let mut fixture = result_bound_fixture();
        let codec = fixture.provider.codec.as_mut().unwrap();
        if case == "codec_input" {
            codec.input_schema = json!({"type":"integer"});
        } else {
            codec.output_schema = json!({"type":"integer"});
        }
        fixture.planner.prepared.steps[1]["resultBindings"][0]["codecDigest"] =
            json!(codec.metadata_digest().unwrap());
        let plan = fixture.plan();
        let report = fixture.apply(&plan, "result-schema-key").unwrap();
        assert_eq!(report["state"], "partial", "{case}");
        assert_eq!(report["completedStepIds"], json!(["write-first"]), "{case}");
        assert_consumer_not_sent(&fixture, &report);
        assert_eq!(fixture.target.borrow().footprint_checks, 0, "{case}");
        assert_eq!(fixture.target.borrow().captures, 1, "{case}");
    }
}

#[test]
fn accepted_unverified_and_failed_source_results_never_authorize_consumer_dispatch() {
    for case in ["job_accepted", "unverified", "failed"] {
        let mut fixture = result_bound_fixture();
        match case {
            "job_accepted" => fixture.target.borrow_mut().job_accepted_on_dispatch = Some(1),
            "unverified" => fixture.target.borrow_mut().observer_available = false,
            "failed" => fixture.target.borrow_mut().fail_on_dispatch = Some(1),
            _ => unreachable!(),
        }
        let plan = fixture.plan();
        let report = fixture.apply(&plan, "result-incomplete-key").unwrap();
        assert_ne!(report["state"], "succeeded", "{case}");
        assert_consumer_not_sent(&fixture, &report);
        assert_eq!(fixture.target.borrow().footprint_checks, 0, "{case}");
        let operation: OperationId = decode(&report["operationId"]).unwrap();
        let first = StepId::new("write-first").unwrap();
        let invocation = fixture.store.stored_invocation(&operation, &first).unwrap();
        assert_eq!(invocation["arguments"], json!({"text":"after-first"}));
        assert!(
            !fixture
                .store
                .operation_summaries(&operation)
                .unwrap()
                .is_empty(),
            "{case}"
        );
    }
}

#[test]
fn resolved_footprint_requires_registered_verification_and_rejects_target_widening_after_first_effects()
 {
    for case in ["unavailable", "denied", "widen"] {
        let mut fixture = result_bound_fixture();
        match case {
            "unavailable" => fixture.target.borrow_mut().footprint_registered = false,
            "denied" => fixture.target.borrow_mut().footprint_denied = true,
            "widen" => {
                fixture.target.borrow_mut().producer_result_text =
                    Some("widen:resource-other".into())
            }
            _ => unreachable!(),
        }
        let plan = fixture.plan();
        let report = fixture.apply(&plan, "result-footprint-key").unwrap();
        assert_eq!(report["state"], "partial", "{case}");
        assert_eq!(report["completedStepIds"], json!(["write-first"]), "{case}");
        assert_consumer_not_sent(&fixture, &report);
        assert_eq!(fixture.target.borrow().footprint_checks, 1, "{case}");
        assert_eq!(fixture.target.borrow().targets.len(), 1, "{case}");
        assert_eq!(fixture.target.borrow().captures, 1, "{case}");
        assert!(
            has_diagnostic(
                &report,
                if case == "unavailable" {
                    "CAPABILITY_UNAVAILABLE"
                } else {
                    "PERMISSION_REQUIRED"
                }
            ),
            "{case}"
        );
    }
}

#[test]
fn cancellation_persists_authorized_request_but_requires_current_observe_for_every_report_release()
{
    for case in ["terminal", "already_requested", "after_callback"] {
        let mut fixture = Fixture::new(1);
        let plan = fixture.plan();
        if case != "terminal" {
            fixture.target.borrow_mut().observer_available = false;
        }
        let report = fixture.apply(&plan, "cancel-release-key").unwrap();
        let operation: OperationId = decode(&report["operationId"]).unwrap();
        if case == "already_requested" {
            let requested = fixture.cancel(&report);
            assert_eq!(requested["state"], "cancel_requested");
            assert_eq!(fixture.target.borrow().cancel_requests, 1);
        }
        let before = fixture.store.operation(&operation).unwrap();
        if case == "after_callback" {
            fixture.target.borrow_mut().revoke_observe_on_cancel = true;
        } else {
            fixture.target.borrow_mut().observe_grant = false;
        }
        let principal = fixture.principal.clone();
        let error = fixture
            .app()
            .operation_cancel(&principal, &Fixture::query(&report))
            .unwrap_err();
        assert_eq!(error.code, "PERMISSION_REQUIRED", "{case}");
        let after = fixture.store.operation(&operation).unwrap();
        if case == "after_callback" {
            assert!(!before.cancellation_requested);
            assert!(after.cancellation_requested);
            assert_eq!(after.state.as_str(), "cancel_requested");
            assert!(after.steps[0].further_effects_possible);
            assert_eq!(fixture.target.borrow().cancel_requests, 1);
        } else {
            assert_eq!(after, before, "{case}");
            assert_eq!(
                fixture.target.borrow().cancel_requests,
                usize::from(case == "already_requested")
            );
        }
        assert_eq!(fixture.target.borrow().dispatches, 1, "{case}");
        assert_eq!(
            fixture.target.borrow().targets[TARGET],
            b"after-first",
            "{case}"
        );
        assert!(!fixture.target.borrow().observe_grant, "{case}");
        fixture.target.borrow_mut().observe_grant = true;
        let released = fixture.get(&report).unwrap();
        assert_eq!(
            released["state"],
            if case == "terminal" {
                "succeeded"
            } else {
                "cancel_requested"
            }
        );
        assert_eq!(fixture.target.borrow().dispatches, 1, "{case}");
    }
}

#[test]
fn historical_idempotent_report_survives_host_restart_with_current_full_scope_grant_and_never_redispatches()
 {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    let original = fixture.apply(&plan, "host-restart-report-key").unwrap();
    let operation: OperationId = decode(&original["operationId"]).unwrap();
    let saved = fixture.store.operation(&operation).unwrap();
    let mut fixture = fixture.reopen();
    fixture.provider.live_context["environment"]["sessionEpoch"] =
        json!("epoch-after-host-restart");
    fixture.provider.live_context["policyRevision"] =
        json!(raw_digest(b"new-current-journal-policy"));
    fixture.provider.live_context["contextDigest"] =
        json!(projected_digest("ExecutionContext", &fixture.provider.live_context).unwrap());
    fixture.target.borrow_mut().apply_grant = false;
    fixture.target.borrow_mut().observe_scope = Some(saved.scope.clone());
    assert_eq!(
        fixture.apply(&plan, "host-restart-report-key").unwrap(),
        original
    );
    assert_eq!(fixture.get(&original).unwrap(), original);
    assert_eq!(fixture.store.operation(&operation).unwrap(), saved);
    assert_eq!(
        fixture.target.borrow().last_operation_scope.as_ref(),
        Some(&saved.scope)
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().polls, 0);
    for case in ["revoked", "narrow_scope"] {
        if case == "revoked" {
            fixture.target.borrow_mut().observe_grant = false;
        } else {
            fixture.target.borrow_mut().observe_grant = true;
            let mut narrow = saved.scope.clone();
            narrow.resource_ids.clear();
            fixture.target.borrow_mut().observe_scope = Some(narrow);
        }
        assert_eq!(
            fixture
                .apply(&plan, "host-restart-report-key")
                .unwrap_err()
                .code,
            "PERMISSION_REQUIRED",
            "{case}"
        );
        assert_eq!(
            fixture.get(&original).unwrap_err().code,
            "PERMISSION_REQUIRED",
            "{case}"
        );
        assert_eq!(
            fixture.store.operation(&operation).unwrap(),
            saved,
            "{case}"
        );
        assert_eq!(fixture.target.borrow().dispatches, 1, "{case}");
        assert_eq!(
            fixture.target.borrow().targets[TARGET],
            b"after-first",
            "{case}"
        );
    }
}

#[test]
fn reconcile_callback_observe_revocation_preserves_durable_observation_but_denies_final_report() {
    let mut fixture = Fixture::new(1);
    fixture.target.borrow_mut().observer_available = false;
    let plan = fixture.plan();
    let unknown = fixture.apply(&plan, "reconcile-release-key").unwrap();
    assert_eq!(unknown["state"], "outcome_unknown");
    let operation: OperationId = decode(&unknown["operationId"]).unwrap();
    fixture.target.borrow_mut().observer_available = true;
    fixture.target.borrow_mut().revoke_observe_after_readback = true;
    let principal = fixture.principal.clone();
    assert_eq!(
        fixture
            .app()
            .operation_reconcile(&principal, &Fixture::query(&unknown))
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
    let durable = fixture.store.operation(&operation).unwrap();
    assert_eq!(durable.state.as_str(), "succeeded");
    assert!(durable.steps[0].finished);
    assert_eq!(durable.steps[0].effect, EffectEvidence::CompleteConfirmed);
    assert_eq!(
        fixture.store.recovery_snapshots(&operation).unwrap().len(),
        1
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().polls, 1);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
    assert_eq!(
        fixture.get(&unknown).unwrap_err().code,
        "PERMISSION_REQUIRED"
    );
    fixture.target.borrow_mut().observe_grant = true;
    assert_eq!(fixture.get(&unknown).unwrap()["state"], "succeeded");
    assert_eq!(fixture.store.operation(&operation).unwrap(), durable);
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

#[test]
fn raw_canonical_failed_source_before_typed_marker_gap_cannot_be_erased_by_later_complete_evidence()
{
    for metadata in [true, false] {
        let mut fixture = result_bound_fixture();
        fixture.target.borrow_mut().raw_failed_summary_metadata = Some(metadata);
        let plan = fixture.plan();
        let report = fixture.apply(&plan, "raw-failure-history-key").unwrap();
        assert_eq!(report["state"], "partial", "metadata={metadata}");
        assert_eq!(report["completedStepIds"], json!([]), "metadata={metadata}");
        assert_eq!(
            report["result"]["providerStatusCounts"]["failed"], 1,
            "metadata={metadata}"
        );
        assert_eq!(
            report["result"]["providerStatusCounts"]["complete"], 1,
            "metadata={metadata}"
        );
        assert_eq!(
            report["result"]["failedStepCount"], 1,
            "metadata={metadata}"
        );
        assert!(
            has_diagnostic(&report, "RAW_SOURCE_FAILED"),
            "metadata={metadata}"
        );
        assert_consumer_not_sent(&fixture, &report);
        assert_eq!(
            fixture.target.borrow().footprint_checks,
            0,
            "metadata={metadata}"
        );
        let operation: OperationId = decode(&report["operationId"]).unwrap();
        let source_invocation = fixture
            .store
            .stored_invocation(&operation, &StepId::new("write-first").unwrap())
            .unwrap();
        let (marker_blob, raw_marker) = fixture
            .store
            .operation_summaries(&operation)
            .unwrap()
            .into_iter()
            .filter_map(|blob| {
                let marker = parse_json(&fixture.store.read_blob(&blob).unwrap()).unwrap();
                if marker["kind"] != "unvalidated_provider_result" {
                    return None;
                }
                let body: BlobRef = decode(&marker["resultBlob"]).unwrap();
                let raw = parse_json(&fixture.store.read_blob(&body).unwrap()).unwrap();
                (raw["status"] == "failed").then_some((blob, marker))
            })
            .next()
            .expect("original canonical raw failure is retained without a typed failed marker");
        assert_eq!(
            raw_marker["invocationId"],
            source_invocation["invocationId"]
        );
        assert_eq!(raw_marker["stepId"], "write-first");
        let body: BlobRef = decode(&raw_marker["resultBlob"]).unwrap();
        let original_failed_bytes = fixture.store.read_blob(&body).unwrap();
        let original_failed = parse_json(&original_failed_bytes).unwrap();
        validate("ProviderResult", &original_failed).unwrap();
        assert_eq!(original_failed["status"], "failed");
        assert!(
            fixture
                .store
                .operation_evidence_refs(&operation)
                .unwrap()
                .contains(&body)
        );
        if metadata {
            assert_eq!(raw_marker["envelopeValidated"], true);
            assert_eq!(raw_marker["envelopeStatus"], "failed");
            assert_eq!(raw_marker["envelopeSummary"]["outputValidated"], false);
        } else {
            assert!(
                raw_marker.get("envelopeValidated").is_none(),
                "legacy case must read the real raw body"
            );
            assert!(raw_marker.get("envelopeSummary").is_none());
        }
        assert!(
            !fixture
                .store
                .operation_summaries(&operation)
                .unwrap()
                .iter()
                .any(|blob| {
                    let marker = parse_json(&fixture.store.read_blob(blob).unwrap()).unwrap();
                    marker["kind"] == "provider_result" && marker["value"]["status"] == "failed"
                }),
            "no typed failed marker supplied the failure history"
        );
        let original_marker_bytes = fixture.store.read_blob(&marker_blob).unwrap();
        fixture.store.collect_orphan_blobs(1000).unwrap();
        let mut restarted = fixture.reopen();
        assert_eq!(
            restarted.store.read_blob(&body).unwrap(),
            original_failed_bytes
        );
        assert_eq!(
            restarted.store.read_blob(&marker_blob).unwrap(),
            original_marker_bytes
        );
        let after_restart = restarted.get(&report).unwrap();
        assert_eq!(after_restart, report, "metadata={metadata}");
        assert!(has_diagnostic(&after_restart, "RAW_SOURCE_FAILED"));
        assert_consumer_not_sent(&restarted, &after_restart);
        assert_eq!(
            restarted.apply(&plan, "raw-failure-history-key").unwrap(),
            report
        );
        assert_eq!(restarted.target.borrow().dispatches, 1);
    }
}

#[test]
fn oversized_covered_and_uncovered_legacy_history_stays_readable_and_blocks_consumer_after_restart()
{
    for uncovered in [false, true] {
        let mut fixture = result_bound_fixture();
        fixture.planner.prepared.time_budget_ms = 60_000;
        fixture.target.borrow_mut().legacy_history_uncovered = Some(uncovered);
        let plan = fixture.plan();
        let report = fixture
            .apply(&plan, "oversized-legacy-history-key")
            .unwrap();
        assert_eq!(report["state"], "partial", "uncovered={uncovered}");
        assert_eq!(
            report["result"]["failureHistoryIncomplete"], true,
            "uncovered={uncovered}"
        );
        assert!(
            report["result"]["failureHistoryIncompleteStepCount"]
                .as_u64()
                .unwrap()
                >= 1
        );
        assert!(encode_json(&report).unwrap().len() <= 64 * 1024);
        assert_eq!(report["completedStepIds"], json!([]));
        assert_consumer_not_sent(&fixture, &report);
        let operation: OperationId = decode(&report["operationId"]).unwrap();
        let mut reader = ResourceReader::new(fixture.principal.clone(), operation.clone());
        let rows = manifest_rows(&fixture, &mut reader, &report);
        assert!(
            rows.iter()
                .any(|row| row["failureHistoryIncomplete"] == true)
        );
        let large_resources = rows
            .iter()
            .flat_map(|row| row["resources"].as_array().into_iter().flatten())
            .filter(|resource| resource["sizeBytes"].as_u64().unwrap_or(0) > 7 * 1024 * 1024)
            .map(|resource| resource["sha256"].as_str().unwrap().to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            large_resources.len(),
            5,
            "all original large bodies remain referenced"
        );
        fixture.store.collect_orphan_blobs(1000).unwrap();
        let mut restarted = fixture.reopen();
        let after_restart = restarted.get(&report).unwrap();
        assert_eq!(after_restart, report);
        assert_eq!(
            restarted
                .apply(&plan, "oversized-legacy-history-key")
                .unwrap(),
            report
        );
        assert_consumer_not_sent(&restarted, &after_restart);
        assert_eq!(restarted.target.borrow().dispatches, 1);
    }
}

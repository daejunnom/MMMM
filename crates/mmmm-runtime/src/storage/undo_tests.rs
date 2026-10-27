//! External SQLite/CAS failure fixtures for the provider undo ledger. The
//! handoff echo examples have no host receipt, full write footprint or atomic
//! recovery claim. These authored fixtures are source checks, not game proof.

use super::*;
use crate::storage::{
    OperationState, ReserveOperation, StepObservation, StoreConfig,
    result_binding::{
        RegisteredResultCodec, ResultArgumentSlot, ResultBindingWitness, ResultCodecImplementation,
        ResultFootprint, ResultResolutionWitness, ResultStepBinding,
    },
};
use mmmm_contracts::{ContextId, PlanId, projected_digest, raw_digest};
use std::{
    cell::Cell,
    fs,
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

const PLAYER: &str = "123e4567-e89b-12d3-a456-426614174000";
const TARGET_A: &str = "resource-undo-a";
const TARGET_B: &str = "resource-undo-b";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = parent.join(format!(
            "mmmm-undo-storage-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(path.is_absolute());
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
        fs::write(path.join("test-owner.txt"), b"mmmm-undo-storage-test\n").unwrap();
        Self(path)
    }
    fn open(&self) -> DurableStore {
        DurableStore::open(StoreConfig::new(self.0.clone())).unwrap()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        if fs::read(self.0.join("test-owner.txt")).ok().as_deref()
            == Some(b"mmmm-undo-storage-test\n")
            && super::super::cas::verify_plain_path(&self.0).is_ok()
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
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
fn blob(store: &DurableStore, value: &Value) -> BlobRef {
    store.put_blob(&encode_json(value).unwrap()).unwrap()
}
fn signed_receipt(mut value: Value) -> Value {
    value.as_object_mut().unwrap().remove("tokenRecordDigest");
    value["tokenRecordDigest"] = json!(canonical_digest(&value).unwrap());
    value
}
struct Rpc {
    principal: PrincipalId,
    context: Value,
    checks: Cell<usize>,
    cancel_at: Option<usize>,
    cancelled: Rc<Cell<bool>>,
    context_changed: Rc<Cell<bool>>,
    bound_plan: Option<(PlanId, Sha256Digest)>,
    binding_expired: Rc<Cell<bool>>,
    dispatch_plan_checks: Cell<usize>,
}
impl UndoRpcContext for Rpc {
    fn check(&self) -> StorageResult<()> {
        let count = self.checks.get() + 1;
        self.checks.set(count);
        if self.cancelled.get() || self.cancel_at.is_some_and(|limit| count >= limit) {
            return Err(invalid("Undo fixture request cancelled"));
        }
        Ok(())
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.principal.clone())
    }
    fn current_context(&self) -> StorageResult<Value> {
        self.check()?;
        let mut current = self.context.clone();
        if self.context_changed.get() {
            current["policyRevision"] = json!(raw_digest(b"policy changed after final approval"));
            current["contextDigest"] =
                json!(projected_digest("ExecutionContext", &current).unwrap());
        }
        Ok(current)
    }
    fn check_dispatch_plan(&self, plan_id: &PlanId, plan_hash: &Sha256Digest) -> StorageResult<()> {
        self.check()?;
        self.dispatch_plan_checks
            .set(self.dispatch_plan_checks.get() + 1);
        if self.binding_expired.get()
            || !self
                .bound_plan
                .as_ref()
                .is_some_and(|(id, hash)| id == plan_id && hash == plan_hash)
        {
            return Err(StorageError::Conflict(
                "Fixture Apply approval is not bound to this plan",
            ));
        }
        Ok(())
    }
}
// This Observe context intentionally inherits the trait's deny-by-default
// dispatch method; receipt acquisition alone cannot grant Apply authority.
struct ObserveOnly<'a>(&'a Rpc);
impl UndoRpcContext for ObserveOnly<'_> {
    fn check(&self) -> StorageResult<()> {
        self.0.check()
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.0.authenticated_principal()
    }
    fn current_context(&self) -> StorageResult<Value> {
        self.0.current_context()
    }
}
#[derive(Clone)]
struct CurrentReadEvidence {
    target: String,
    raw: BlobRef,
    envelope: BlobRef,
    summary: BlobRef,
}
struct Authority {
    denied: bool,
    capture_checks: usize,
    capture_revoke_at: Option<usize>,
    recovery_checks: usize,
    revoke_at: Option<usize>,
    change_context_at: Option<usize>,
    context_changed: Rc<Cell<bool>>,
    current: BTreeMap<String, Vec<u8>>,
    target_reads: usize,
    retain_current_reads: bool,
    retained_current_reads: Vec<CurrentReadEvidence>,
    expire_binding_after_read: Option<usize>,
    binding_expired: Rc<Cell<bool>>,
}
impl UndoAuthority for Authority {
    fn authorize_capture(
        &mut self,
        store: &DurableStore,
        _: &OperationRecord,
        _: &Value,
        _: &Value,
    ) -> StorageResult<()> {
        assert!(
            store.connection.is_autocommit(),
            "live capture authorization must not hold a SQLite write transaction"
        );
        self.capture_checks += 1;
        if self.denied
            || self
                .capture_revoke_at
                .is_some_and(|n| self.capture_checks >= n)
        {
            Err(StorageError::Conflict("Fixture capture ACL denied"))
        } else {
            Ok(())
        }
    }
    fn authorize_read(
        &mut self,
        store: &DurableStore,
        _: &ProviderUndoRecord,
        _: &Value,
    ) -> StorageResult<()> {
        assert!(
            store.connection.is_autocommit(),
            "live record read authorization must not hold a SQLite write transaction"
        );
        if self.denied {
            Err(StorageError::Conflict("Fixture current read ACL denied"))
        } else {
            Ok(())
        }
    }
    fn authorize_recovery(
        &mut self,
        store: &DurableStore,
        _: &ProviderUndoRecord,
        _: &Value,
    ) -> StorageResult<()> {
        assert!(
            store.connection.is_autocommit(),
            "live Recovery/Apply authorization must precede the intent transaction"
        );
        self.recovery_checks += 1;
        if self.denied || self.revoke_at.is_some_and(|n| self.recovery_checks >= n) {
            Err(StorageError::Conflict(
                "Fixture fresh Recovery and Apply approval denied",
            ))
        } else {
            if self.change_context_at == Some(self.recovery_checks) {
                self.context_changed.set(true);
            }
            Ok(())
        }
    }
    fn read_current_target(
        &mut self,
        store: &DurableStore,
        _: &ProviderUndoRecord,
        _: &Value,
        target: &str,
        max_bytes: u64,
    ) -> StorageResult<Vec<u8>> {
        assert!(
            store.connection.is_autocommit(),
            "native target reads must not hold a SQLite write transaction"
        );
        self.target_reads += 1;
        let bytes = self
            .current
            .get(target)
            .ok_or(StorageError::NotFound("Fixture original target"))?;
        if bytes.len() as u64 > max_bytes {
            return Err(invalid("Fixture target budget exceeded"));
        }
        Ok(bytes.clone())
    }
    fn read_current_target_retained(
        &mut self,
        store: &mut DurableStore,
        record: &ProviderUndoRecord,
        new_invocation: &Value,
        target: &str,
        max_bytes: u64,
    ) -> StorageResult<Vec<u8>> {
        assert!(store.connection.is_autocommit());
        let bytes = self.read_current_target(store, record, new_invocation, target, max_bytes)?;
        if self.retain_current_reads {
            // The original durable Invocation owns the target locator. Closed
            // new undo arguments provide neither a locator nor source authority.
            let source = store.stored_invocation_checked(
                &record.source_operation_id,
                &record.source_step_id,
                8 * 1024 * 1024,
                || Ok(()),
            )?;
            assert_eq!(source["invocationId"], record.source_invocation_id.as_str());
            assert_eq!(source["context"], record.source_context);
            let original = store
                .stored_invocation_blob(&record.source_operation_id, &record.source_step_id)?;
            let operation = record.source_operation_id.clone();
            let raw = store.put_blob(&bytes)?;
            // The unique envelope has no prior source pin, so its survival
            // proves fresh original-source truth retention before any claim.
            let envelope = store.put_blob(&encode_json(&json!({
                "kind":"authored_recovery_target_observation",
                    "operationId":operation,"stepId":record.source_step_id,"invocationId":record.source_invocation_id,
                    "callOperationId":new_invocation["operationId"],"callInvocationId":new_invocation["invocationId"],
                "sourceOperationId":record.source_operation_id,"sourceInvocation":original,
                "target":target,"targetBlob":raw,
            })).map_err(contract)?)?;
            let summary = store.put_blob(
                &encode_json(&json!({
                    "kind":"authored_recovery_target_summary","operationId":operation,
                    "stepId":record.source_step_id,"invocationId":record.source_invocation_id,
                    "callOperationId":new_invocation["operationId"],"callInvocationId":new_invocation["invocationId"],
                    "target":target,"readbackBlob":envelope,
                }))
                .map_err(contract)?,
            )?;
            let already_pinned: i64 = store.connection.query_row(
                "SELECT count(*) FROM blob_refs WHERE owner_id=?1 AND digest=?2",
                params![operation.as_str(), envelope.digest.as_str()],
                |row| row.get(0),
            )?;
            assert_eq!(
                already_pinned, 0,
                "fresh source truth cannot rely on an existing after pin"
            );
            store.append_operation_summary(
                &operation,
                &summary,
                &[envelope.clone(), raw.clone(), original],
            )?;
            assert!(store.connection.is_autocommit());
            self.retained_current_reads.push(CurrentReadEvidence {
                target: target.into(),
                raw,
                envelope,
                summary,
            });
        }
        if self
            .expire_binding_after_read
            .is_some_and(|n| self.target_reads >= n)
        {
            self.binding_expired.set(true);
        }
        Ok(bytes)
    }
}
struct SourceSession {
    receipt: Value,
    calls: usize,
    expired: bool,
    player: String,
    cancel_after_receipt: bool,
    cancelled: Rc<Cell<bool>>,
}
impl UndoMaterialSource for SourceSession {
    fn inspect_source_material(
        &mut self,
        store: &DurableStore,
        _: &OperationRecord,
        invocation: &Value,
        _: &RegisteredUndoRoute,
        _: &Value,
    ) -> StorageResult<InspectedUndoMaterial> {
        assert!(
            store.connection.is_autocommit(),
            "original host inspection must precede receipt persistence"
        );
        self.calls += 1;
        if self.expired {
            return Err(StorageError::NotFound(
                "Closed fixture original source session",
            ));
        }
        assert_eq!(invocation["invocationId"], "invocation-undo-source");
        if self.cancel_after_receipt {
            self.cancelled.set(true);
        }
        Ok(InspectedUndoMaterial {
            receipt: self.receipt.clone(),
            authenticated_player_id: self.player.clone(),
        })
    }
}
struct Fixture {
    // Close SQLite and its exclusive lease before removing this owned root.
    store: DurableStore,
    root: Root,
    rpc: Rpc,
    authority: Authority,
    session: SourceSession,
    route: RegisteredUndoRoute,
    request: UndoRegistrationRequest,
    invocation: Value,
    plan: Value,
    before: BTreeMap<String, BlobRef>,
}
fn reserve(store: &mut DurableStore, plan: &Value, operation: &OperationId) {
    store.save_plan(plan).unwrap();
    store
        .reserve_operation(ReserveOperation {
            operation_id: operation.clone(),
            principal: PrincipalId::new("principal-fixture").unwrap(),
            project_id: ProjectId::new("project-fixture").unwrap(),
            idempotency_key: operation.as_str().into(),
            plan_id: serde_json::from_value(plan["planId"].clone()).unwrap(),
            plan_hash: serde_json::from_value(plan["planHash"].clone()).unwrap(),
            context_id: ContextId::new("context-fixture-01").unwrap(),
        })
        .unwrap();
}
fn pin_context(plan: &mut Value, context: &Value) {
    plan["policyRevision"] = context["policyRevision"].clone();
    plan["contextPins"] = json!([{"contextId":context["contextId"],"contextDigest":context["contextDigest"],"environment":context["environment"]}]);
    plan["planHash"] = json!(projected_digest("ExecutionPlan", plan).unwrap());
}
fn invocation_for(
    plan: &Value,
    index: usize,
    context: &Value,
    operation: &OperationId,
    id: &str,
) -> Value {
    let mut value = example("invocation.json");
    let step = &plan["steps"][index];
    for key in [
        "stepId",
        "bindingId",
        "actionId",
        "actionContractVersion",
        "actionDigest",
        "implementationDigest",
        "arguments",
    ] {
        value[key] = step[key].clone();
    }
    value["operationId"] = json!(operation);
    value["invocationId"] = json!(id);
    value["idempotencyKey"] = json!(operation.as_str());
    value["context"] = context.clone();
    value["contextDigest"] = context["contextDigest"].clone();
    value["argumentsDigest"] = json!(canonical_digest(&value["arguments"]).unwrap());
    value["deadlineAt"] = json!("2099-01-01T00:00:00Z");
    value
}
impl Fixture {
    fn new(capture_before: bool) -> Self {
        let root = Root::new();
        let mut store = root.open();
        let mut source = example("provider-supported.json")["actions"][0].clone();
        source["actionId"] = json!("fixture:write_for_undo");
        source["effect"] = json!("write");
        source["recovery"] = json!("provider_undo");
        source["idempotency"] = json!("coordinator_only");
        source["verificationRequirement"] = json!("independent_readback");
        let mut undo = source.clone();
        undo["actionId"] = json!("fixture:undo_closed_five");
        undo["recovery"] = json!("none");
        undo["inputSchema"] = json!({"type":"object","properties":{
            "tokenRecordId":{"type":"string"},"tokenRecordDigest":{"type":"string"},
            "sourceOperationId":{"type":"string"},"sourceStepId":{"type":"string"},"sourceInvocationId":{"type":"string"}},
            "required":["tokenRecordId","tokenRecordDigest","sourceOperationId","sourceStepId","sourceInvocationId"],"additionalProperties":false});
        undo["outputSchema"] = json!({"type":"object","properties":{"restored":{"type":"boolean"}},"required":["restored"],"additionalProperties":false});
        let binding = BindingId::new("binding-fixture-01").unwrap();
        let route = RegisteredUndoRoute {
            source_binding_id: binding.clone(),
            source_action: source.clone(),
            undo_binding_id: binding,
            undo_action: undo,
            provider_origin: json!({"kind":"authored_fixture","sourceId":"owned-test-host"}),
        };
        let route_digest = register_undo_route(&mut store, &route).unwrap();
        let mut context = example("execution-context.json");
        context["scope"]["resourceIds"] = json!([TARGET_A, TARGET_B]);
        context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
        let mut plan = example("execution-plan.json");
        plan["planId"] = json!("plan-undo-source");
        plan["scope"] = context["scope"].clone();
        plan["expiresAt"] = json!("2099-01-01T00:00:00Z");
        let step = &mut plan["steps"][0];
        step["stepId"] = json!("source-write");
        for key in [
            "actionId",
            "effect",
            "recovery",
            "verificationRequirement",
            "implementationDigest",
            "completion",
        ] {
            step[key] = source[key].clone();
        }
        step["actionDigest"] = json!(canonical_digest(&source).unwrap());
        step["resourcesWritten"] = json!([TARGET_A, TARGET_B]);
        pin_context(&mut plan, &context);
        let operation = OperationId::new("operation-undo-source").unwrap();
        reserve(&mut store, &plan, &operation);
        let invocation = invocation_for(&plan, 0, &context, &operation, "invocation-undo-source");
        let mut before = BTreeMap::new();
        if capture_before {
            let mut images = Vec::new();
            for target in [TARGET_A, TARGET_B] {
                let bytes = store
                    .put_blob(format!("original-before-{target}").as_bytes())
                    .unwrap();
                store.pin_operation_artifact(&operation, &bytes).unwrap();
                before.insert(target.into(), bytes.clone());
                images.push(json!({"target":target,"before":bytes}));
            }
            let mut envelope = observation_pins(&invocation);
            envelope["kind"] = json!("before_capture");
            envelope["version"] = json!(1);
            envelope["operationId"] = json!(operation);
            envelope["images"] = json!(images);
            let body = blob(&store, &envelope);
            let marker = blob(
                &store,
                &json!({"kind":"before_capture_summary","stepId":invocation["stepId"],"invocationId":invocation["invocationId"],"captureBlob":body}),
            );
            store
                .append_operation_summary(&operation, &marker, std::slice::from_ref(&body))
                .unwrap();
        }
        let intent = store
            .dispatch_intent(
                &operation,
                &StepId::new("source-write").unwrap(),
                &invocation,
            )
            .unwrap();
        let request = UndoRegistrationRequest {
            source_operation_id: operation,
            source_step_id: StepId::new("source-write").unwrap(),
            source_invocation_id: InvocationId::new("invocation-undo-source").unwrap(),
            source_invocation_digest: intent.invocation_digest.unwrap(),
            route_digest,
        };
        let receipt = signed_receipt(
            json!({"contractVersion":"0.2.0","tokenRecordId":"host-undo-source",
            "principalRef":context["principalRef"],"sessionEpoch":context["environment"]["sessionEpoch"],
            "gameInstanceId":context["environment"]["gameInstanceId"],"side":context["environment"]["side"],"playerId":PLAYER,
            "bindingId":invocation["bindingId"],"sourceActionId":invocation["actionId"],"sourceActionDigest":invocation["actionDigest"],
            "sourceImplementationDigest":invocation["implementationDigest"],"sourceArgumentsDigest":invocation["argumentsDigest"],
            "sourceContextDigest":invocation["contextDigest"],"sourceOperationId":invocation["operationId"],"sourceStepId":invocation["stepId"],
            "sourceInvocationId":invocation["invocationId"],"undoActionId":route.undo_action["actionId"],"sourceContext":context,
            "privateTokenSha256":raw_digest(b"host-owned opaque fixture material") }),
        );
        let context_changed = Rc::new(Cell::new(false));
        let cancelled = Rc::new(Cell::new(false));
        let binding_expired = Rc::new(Cell::new(false));
        Self {
            store,
            root,
            rpc: Rpc {
                principal: PrincipalId::new("principal-fixture").unwrap(),
                context,
                checks: Cell::new(0),
                cancel_at: None,
                cancelled: cancelled.clone(),
                context_changed: context_changed.clone(),
                bound_plan: None,
                binding_expired: binding_expired.clone(),
                dispatch_plan_checks: Cell::new(0),
            },
            authority: Authority {
                denied: false,
                capture_checks: 0,
                capture_revoke_at: None,
                recovery_checks: 0,
                revoke_at: None,
                change_context_at: None,
                context_changed,
                current: BTreeMap::from([
                    (TARGET_A.into(), b"after-a".to_vec()),
                    (TARGET_B.into(), b"after-b".to_vec()),
                ]),
                target_reads: 0,
                retain_current_reads: false,
                retained_current_reads: vec![],
                expire_binding_after_read: None,
                binding_expired,
            },
            session: SourceSession {
                receipt,
                calls: 0,
                expired: false,
                player: PLAYER.into(),
                cancel_after_receipt: false,
                cancelled,
            },
            route,
            request,
            invocation,
            plan,
            before,
        }
    }
    fn pending(&mut self) -> StorageResult<ProviderUndoRecord> {
        register_undo_record(
            &mut self.store,
            &self.rpc,
            &mut self.authority,
            &mut self.session,
            &self.request,
        )
    }
    fn settle(&mut self, effect: EffectEvidence, variant: &str) -> BlobRef {
        let operation = &self.request.source_operation_id;
        let mut states = Vec::new();
        for target in [TARGET_A, TARGET_B] {
            let after = self
                .store
                .put_blob(&self.authority.current[target])
                .unwrap();
            if variant != "after-pin" || target != TARGET_A {
                self.store
                    .pin_operation_artifact(operation, &after)
                    .unwrap();
            }
            states.push(UndoTargetState {
                target: target.into(),
                before: self.before.get(target).cloned(),
                after,
            });
        }
        match variant {
            "missing-target" => {
                states.pop();
            }
            "duplicate-target" => states.push(states[0].clone()),
            "extra-target" => {
                let mut extra = states[0].clone();
                extra.target = "resource-outside-source".into();
                states.push(extra);
            }
            "fake-before" => {
                let fake = self
                    .store
                    .put_blob(b"not the original before capture")
                    .unwrap();
                self.store.pin_operation_artifact(operation, &fake).unwrap();
                states[0].before = Some(fake);
            }
            _ => (),
        }
        let raw = blob(
            &self.store,
            &json!({"kind":"authored_independent_evidence","source":self.invocation["invocationId"],"effect":effect}),
        );
        let mut envelope = observation_pins(&self.invocation);
        envelope["kind"] = json!("independent_readback");
        envelope["effect"] = json!(effect);
        envelope["settled"] = json!(true);
        envelope["sourceRefs"] = json!([raw]);
        envelope["afterStates"] = json!(states);
        if variant == "source-step" {
            envelope["stepId"] = json!("another-source-step");
        }
        let body = blob(&self.store, &envelope);
        if variant != "summary" {
            let marker = blob(
                &self.store,
                &json!({"kind":"independent_readback_summary","stepId":self.invocation["stepId"],"invocationId":self.invocation["invocationId"],"effect":effect,"settled":true,"readbackBlob":body}),
            );
            let mut sources = vec![body.clone(), raw];
            sources.extend(
                states
                    .iter()
                    .filter(|state| variant != "after-association" || state.target != TARGET_A)
                    .map(|state| state.after.clone()),
            );
            self.store
                .append_operation_summary(operation, &marker, &sources)
                .unwrap();
        }
        self.store
            .record_observation(
                operation,
                &self.request.source_step_id,
                StepObservation {
                    dispatch: DispatchEvidence::Observed,
                    effect,
                    further_effects_possible: false,
                    provider_receipt: None,
                    observation_refs: vec![body.clone()],
                    finished: true,
                },
            )
            .unwrap();
        self.store
            .finish_operation(
                operation,
                if effect == EffectEvidence::CompleteConfirmed {
                    OperationState::Succeeded
                } else {
                    OperationState::Partial
                },
            )
            .unwrap();
        body
    }
    fn promote(&mut self, id: &ObjectId) -> StorageResult<ProviderUndoRecord> {
        promote_undo_record(&mut self.store, &self.rpc, &mut self.authority, id)
    }
    fn read(&mut self, id: &ObjectId) -> StorageResult<ProviderUndoRecord> {
        provider_undo_record(&self.store, &self.rpc, &mut self.authority, id)
    }
    fn reopen(self) -> Self {
        let Self {
            store,
            root,
            rpc,
            authority,
            session,
            route,
            request,
            invocation,
            plan,
            before,
        } = self;
        drop(store);
        let store = root.open();
        Self {
            store,
            root,
            rpc,
            authority,
            session,
            route,
            request,
            invocation,
            plan,
            before,
        }
    }
    fn undo_plan(&self, record: &ProviderUndoRecord, name: &str) -> Value {
        let mut plan = self.plan.clone();
        plan["planId"] = json!(format!("plan-{name}"));
        let descriptor = &self.route.undo_action;
        let targets: Vec<_> = record
            .after_states
            .iter()
            .map(|s| s.target.clone())
            .collect();
        let step = &mut plan["steps"][0];
        step["stepId"] = json!("undo-step");
        for key in [
            "actionId",
            "effect",
            "completion",
            "recovery",
            "verificationRequirement",
            "implementationDigest",
        ] {
            step[key] = descriptor[key].clone();
        }
        step["bindingId"] = json!(self.route.undo_binding_id);
        step["actionDigest"] = json!(canonical_digest(descriptor).unwrap());
        step["resourcesRead"] = json!(targets);
        step["resourcesWritten"] = json!(targets);
        step["arguments"] = json!({"tokenRecordId":record.receipt["tokenRecordId"],"tokenRecordDigest":record.receipt["tokenRecordDigest"],"sourceOperationId":record.source_operation_id,"sourceStepId":record.source_step_id,"sourceInvocationId":record.source_invocation_id});
        plan["approvalRequirement"] = json!("explicit_approval");
        plan["preconditions"]=json!(record.after_states.iter().map(|s|json!({"kind":"resource_hash","subject":s.target,"expected":s.after.digest,"coverage":"full_target"})).collect::<Vec<_>>());
        pin_context(&mut plan, &self.rpc.context);
        plan
    }
    fn new_intent(
        &mut self,
        record: &ProviderUndoRecord,
        name: &str,
        change: impl FnOnce(&mut Value),
    ) -> (OperationId, Value) {
        let mut plan = self.undo_plan(record, name);
        change(&mut plan);
        pin_context(&mut plan, &self.rpc.context);
        let operation = OperationId::new(name).unwrap();
        reserve(&mut self.store, &plan, &operation);
        self.rpc.bound_plan = Some((
            serde_json::from_value(plan["planId"].clone()).unwrap(),
            serde_json::from_value(plan["planHash"].clone()).unwrap(),
        ));
        let invocation = invocation_for(
            &plan,
            0,
            &self.rpc.context,
            &operation,
            &format!("invocation-{name}"),
        );
        (operation, invocation)
    }
    fn dispatch(
        &mut self,
        record: &ProviderUndoRecord,
        operation: &OperationId,
        invocation: &Value,
    ) -> StorageResult<StepRecord> {
        dispatch_undo_intent(
            &mut self.store,
            &self.rpc,
            &mut self.authority,
            &UndoDispatchRequest {
                operation_id: operation,
                step_id: &StepId::new("undo-step").unwrap(),
                invocation,
                undo_record_id: &record.record_id,
            },
        )
    }
    fn assert_no_intent(&self, operation: &OperationId) {
        assert_eq!(
            self.store
                .operation(operation)
                .unwrap()
                .steps
                .last()
                .unwrap()
                .dispatch,
            DispatchEvidence::NotSent
        );
        let count: i64 = self
            .store
            .connection
            .query_row(
                "SELECT count(*) FROM invocations WHERE operation_id=?1",
                [operation.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}
fn observation_pins(invocation: &Value) -> Value {
    let mut value = json!({});
    for key in [
        "stepId",
        "invocationId",
        "bindingId",
        "contextDigest",
        "implementationDigest",
        "argumentsDigest",
    ] {
        value[key] = invocation[key].clone();
    }
    value
}

#[test]
fn pending_receipt_survives_restart_without_reopening_source_session_then_promotes() {
    let mut fixture = Fixture::new(false);
    let pending = fixture.pending().unwrap();
    assert_eq!(pending.state, UndoRecordState::Pending);
    assert!(pending.after_states.is_empty());
    let raw_receipt = fixture.store.read_blob(&pending.receipt_blob).unwrap();
    assert_eq!(raw_receipt, encode_json(&fixture.session.receipt).unwrap());
    assert!(fixture.promote(&pending.record_id).is_err());
    fixture.session.expired = true;
    let mut fixture = fixture.reopen();
    assert_eq!(fixture.pending().unwrap().record_id, pending.record_id);
    assert_eq!(fixture.session.calls, 1);
    assert_eq!(
        fixture.store.read_blob(&pending.receipt_blob).unwrap(),
        raw_receipt
    );
    let operation = &fixture.request.source_operation_id;
    let step = &fixture.request.source_step_id;
    let original_invocation = fixture
        .store
        .stored_invocation_blob(operation, step)
        .unwrap();
    let invocation_bytes = encode_json(&fixture.invocation).unwrap();
    assert_eq!(original_invocation.digest, raw_digest(&invocation_bytes));
    assert_eq!(
        original_invocation.byte_length,
        invocation_bytes.len() as u64
    );
    assert_eq!(
        fixture.store.read_blob(&original_invocation).unwrap(),
        invocation_bytes
    );
    assert_eq!(
        fixture
            .store
            .stored_invocation_checked(operation, step, original_invocation.byte_length, || Ok(()))
            .unwrap(),
        fixture.invocation
    );
    assert!(
        fixture
            .store
            .stored_invocation_checked(operation, step, original_invocation.byte_length - 1, || Ok(
                ()
            ))
            .is_err()
    );
    let mut read_checks = 0;
    let cancelled = fixture.store.stored_invocation_checked(
        operation,
        step,
        original_invocation.byte_length,
        || {
            read_checks += 1;
            if read_checks >= 5 {
                Err(invalid(
                    "Original invocation read cancelled at CAS checkpoint",
                ))
            } else {
                Ok(())
            }
        },
    );
    assert!(matches!(cancelled, Err(StorageError::InvalidInput(message))
        if message == "Original invocation read cancelled at CAS checkpoint"));
    assert_eq!(read_checks, 5);

    // Matching row/journal digest metadata cannot authorize bytes from another
    // step. Restore the exact original records before testing promotion.
    let original_record = fixture.store.operation(operation).unwrap();
    let mut crossed_invocation = fixture.invocation.clone();
    crossed_invocation["stepId"] = json!("another-source-step");
    let crossed_blob = blob(&fixture.store, &crossed_invocation);
    fixture
        .store
        .pin_operation_artifact(operation, &crossed_blob)
        .unwrap();
    let mut crossed_record = original_record.clone();
    crossed_record.steps[0].invocation_digest = Some(crossed_blob.digest.clone());
    fixture
        .store
        .connection
        .execute(
            "UPDATE invocations SET invocation_hash=?2,blob_digest=?2 WHERE invocation_id=?1",
            params![
                fixture.request.source_invocation_id.as_str(),
                crossed_blob.digest.as_str()
            ],
        )
        .unwrap();
    fixture
        .store
        .connection
        .execute(
            "UPDATE operations SET record_json=?2 WHERE operation_id=?1",
            params![operation.as_str(), encode(&crossed_record).unwrap()],
        )
        .unwrap();
    assert_eq!(
        fixture
            .store
            .stored_invocation_blob(operation, step)
            .unwrap(),
        crossed_blob
    );
    assert!(matches!(
        fixture
            .store
            .stored_invocation_checked(operation, step, crossed_blob.byte_length, || Ok(())),
        Err(StorageError::Conflict(
            "Original invocation identity/digest changed"
        ))
    ));
    fixture
        .store
        .connection
        .execute(
            "UPDATE invocations SET invocation_hash=?2,blob_digest=?2 WHERE invocation_id=?1",
            params![
                fixture.request.source_invocation_id.as_str(),
                original_invocation.digest.as_str()
            ],
        )
        .unwrap();
    fixture
        .store
        .connection
        .execute(
            "UPDATE operations SET record_json=?2 WHERE operation_id=?1",
            params![operation.as_str(), encode(&original_record).unwrap()],
        )
        .unwrap();
    fixture
        .store
        .connection
        .execute(
            "DELETE FROM blob_refs WHERE owner_kind='operation' AND owner_id=?1 AND digest=?2",
            params![operation.as_str(), crossed_blob.digest.as_str()],
        )
        .unwrap();
    assert_eq!(
        fixture.store.stored_invocation(operation, step).unwrap(),
        fixture.invocation
    );
    fixture.settle(EffectEvidence::CompleteConfirmed, "valid");
    let available = fixture.promote(&pending.record_id).unwrap();
    assert_eq!(available.state, UndoRecordState::Available);
    assert_eq!(available.after_states.len(), 2);
    assert!(available.after_states.iter().all(|s| s.before.is_none()));
    fixture.store.collect_orphan_blobs(1000).unwrap();
    let mut fixture = fixture.reopen();
    assert_eq!(
        fixture.read(&pending.record_id).unwrap().after_states,
        available.after_states
    );
    assert_eq!(fixture.session.calls, 1);
}

#[test]
fn full_material_registry_rejects_capture_before_original_host_callback() {
    for case in ["summary", "evidence", "provider-records"] {
        let mut fixture = Fixture::new(false);
        let original = fixture
            .store
            .operation(&fixture.request.source_operation_id)
            .unwrap();
        let invocation = fixture
            .store
            .stored_invocation_blob(
                &fixture.request.source_operation_id,
                &fixture.request.source_step_id,
            )
            .unwrap();
        {
            // Synthetic failure metadata fills only the bounded registry. No
            // placeholder CAS file, observed game state or host receipt exists.
            // The actual source operation and original intent remain untouched.
            let transaction = fixture.store.connection.transaction().unwrap();
            if case == "provider-records" {
                let mut invocations = transaction.prepare(
                    "INSERT INTO invocations(invocation_id,operation_id,step_id,invocation_hash,blob_digest) VALUES(?1,?2,?3,?4,?4)",
                ).unwrap();
                let mut records = transaction.prepare(
                    "INSERT INTO provider_undo_records(record_id,source_operation_id,source_step_id,source_invocation_id,route_digest,receipt_digest,receipt_blob,record_json,state) VALUES(?1,?2,?3,?4,?5,?6,?6,'{}','pending')",
                ).unwrap();
                for index in 0..ENTRIES {
                    let fake_step = format!("capacity-placeholder-step-{index}");
                    let fake_invocation = format!("capacity-placeholder-invocation-{index}");
                    invocations
                        .execute(params![
                            fake_invocation,
                            fixture.request.source_operation_id.as_str(),
                            fake_step,
                            invocation.digest.as_str(),
                        ])
                        .unwrap();
                    records
                        .execute(params![
                            format!("capacity-placeholder-record-{index}"),
                            fixture.request.source_operation_id.as_str(),
                            fake_step,
                            fake_invocation,
                            fixture.request.route_digest.as_str(),
                            invocation.digest.as_str(),
                        ])
                        .unwrap();
                }
            } else {
                let kind = if case == "summary" {
                    "application_summary"
                } else {
                    "application_evidence"
                };
                let mut blobs = transaction
                    .prepare("INSERT INTO blobs(digest,byte_length) VALUES(?1,1)")
                    .unwrap();
                let mut pins = transaction
                    .prepare("INSERT INTO blob_refs(owner_kind,owner_id,digest) VALUES(?1,?2,?3)")
                    .unwrap();
                for index in 0..ENTRIES {
                    let digest =
                        raw_digest(format!("synthetic-capacity-{case}-{index}").as_bytes());
                    blobs.execute([digest.as_str()]).unwrap();
                    pins.execute(params![
                        kind,
                        fixture.request.source_operation_id.as_str(),
                        digest.as_str()
                    ])
                    .unwrap();
                }
            }
            transaction.commit().unwrap();
        }
        let counts = |store: &DurableStore| -> (i64, i64, i64, i64) {
            store.connection.query_row(
                "SELECT (SELECT count(*) FROM provider_undo_records),(SELECT count(*) FROM blob_refs),(SELECT count(*) FROM events),(SELECT count(*) FROM blobs)",
                [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).unwrap()
        };
        let before = counts(&fixture.store);
        assert!(
            matches!(fixture.pending(), Err(StorageError::InvalidInput(message))
            if message.contains("capacity")),
            "case={case}"
        );
        assert_eq!(fixture.session.calls, 0, "case={case}");
        assert_eq!(counts(&fixture.store), before, "case={case}");
        assert_eq!(
            fixture
                .store
                .operation(&fixture.request.source_operation_id)
                .unwrap(),
            original,
            "case={case}"
        );
        let source_pending: i64 = fixture
            .store
            .connection
            .query_row(
                "SELECT count(*) FROM provider_undo_records WHERE source_invocation_id=?1",
                [fixture.request.source_invocation_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let summaries: i64 = fixture
            .store
            .connection
            .query_row(
                "SELECT count(*) FROM events WHERE operation_id=?1 AND kind='application_summary'",
                [fixture.request.source_operation_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(source_pending, 0, "case={case}");
        assert_eq!(summaries, 0, "case={case}");
    }

    // At the exact boundary, existing owned digest pins consume no new slots.
    // This checks accounting only; synthetic pins grant no material authority.
    let mut fixture = Fixture::new(false);
    let operation = &fixture.request.source_operation_id;
    let (_, route_blob) =
        load_route(&fixture.store, &fixture.rpc, &fixture.request.route_digest).unwrap();
    let invocation_blob = fixture
        .store
        .stored_invocation_blob(operation, &fixture.request.source_step_id)
        .unwrap();
    let summary = blob(
        &fixture.store,
        &json!({"kind":"authored_capacity_accounting_fixture"}),
    );
    {
        let transaction = fixture.store.connection.transaction().unwrap();
        pin_blob(
            &transaction,
            "application_summary",
            operation.as_str(),
            &summary,
        )
        .unwrap();
        for source in [&route_blob, &invocation_blob] {
            pin_blob(
                &transaction,
                "application_evidence",
                operation.as_str(),
                source,
            )
            .unwrap();
        }
        {
            let mut blobs = transaction
                .prepare("INSERT INTO blobs(digest,byte_length) VALUES(?1,1)")
                .unwrap();
            let mut pins = transaction
                .prepare("INSERT INTO blob_refs(owner_kind,owner_id,digest) VALUES(?1,?2,?3)")
                .unwrap();
            for index in 0..ENTRIES - 2 {
                let digest = raw_digest(format!("synthetic-dedup-boundary-{index}").as_bytes());
                blobs.execute([digest.as_str()]).unwrap();
                pins.execute(params![
                    "application_summary",
                    operation.as_str(),
                    digest.as_str()
                ])
                .unwrap();
                if index < ENTRIES - 3 {
                    pins.execute(params![
                        "application_evidence",
                        operation.as_str(),
                        digest.as_str()
                    ])
                    .unwrap();
                }
            }
        }
        transaction.commit().unwrap();
    }
    let repeated_sources = vec![
        route_blob.clone(),
        invocation_blob.clone(),
        route_blob,
        invocation_blob,
    ];
    // 4095 existing slots + one unknown receipt fits the pre-callback check.
    check_material_capacity(
        &fixture.store.connection,
        operation,
        None,
        &repeated_sources,
        1,
    )
    .unwrap();
    check_material_capacity(
        &fixture.store.connection,
        operation,
        Some(&summary),
        &repeated_sources,
        0,
    )
    .unwrap();

    let extra_summary = raw_digest(b"synthetic-dedup-extra-summary");
    fixture
        .store
        .connection
        .execute(
            "INSERT INTO blobs(digest,byte_length) VALUES(?1,1)",
            [extra_summary.as_str()],
        )
        .unwrap();
    fixture
        .store
        .connection
        .execute(
            "INSERT INTO blob_refs(owner_kind,owner_id,digest) VALUES('application_summary',?1,?2)",
            params![operation.as_str(), extra_summary.as_str()],
        )
        .unwrap();
    // A known summary may be reused at 4096; an unknown new summary may not.
    check_material_capacity(
        &fixture.store.connection,
        operation,
        Some(&summary),
        &repeated_sources,
        0,
    )
    .unwrap();
    assert!(
        check_material_capacity(
            &fixture.store.connection,
            operation,
            None,
            &repeated_sources,
            0
        )
        .is_err()
    );

    let final_evidence = raw_digest(format!("synthetic-dedup-boundary-{}", ENTRIES - 3).as_bytes());
    fixture.store.connection.execute(
        "INSERT INTO blob_refs(owner_kind,owner_id,digest) VALUES('application_evidence',?1,?2)",
        params![operation.as_str(),final_evidence.as_str()],
    ).unwrap();
    check_material_capacity(
        &fixture.store.connection,
        operation,
        Some(&summary),
        &repeated_sources,
        0,
    )
    .unwrap();
    assert!(
        check_material_capacity(
            &fixture.store.connection,
            operation,
            Some(&summary),
            &repeated_sources,
            1
        )
        .is_err()
    );
    assert_eq!(fixture.session.calls, 0);
}

#[test]
fn acquired_receipt_is_retained_on_late_cancel_or_acl_revocation_without_claim_authority() {
    for case in ["late-cancel", "late-acl"] {
        let mut fixture = Fixture::new(false);
        let original = fixture
            .store
            .operation(&fixture.request.source_operation_id)
            .unwrap();
        if case == "late-cancel" {
            fixture.session.cancel_after_receipt = true;
        } else {
            fixture.authority.capture_revoke_at = Some(2);
        }
        let result = fixture.pending();
        assert!(result.is_err(), "case={case}");
        assert_eq!(fixture.session.calls, 1, "case={case}");
        assert!(fixture.store.connection.is_autocommit());
        let id: String = fixture
            .store
            .connection
            .query_row(
                "SELECT record_id FROM provider_undo_records WHERE source_invocation_id=?1",
                [fixture.request.source_invocation_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let pending = read_record_inner(&fixture.store, &ObjectId::new(id).unwrap()).unwrap();
        assert_eq!(pending.state, UndoRecordState::Pending, "case={case}");
        assert!(pending.after_states.is_empty());
        assert!(pending.settled_observation.is_none());
        let receipt_bytes = encode_json(&fixture.session.receipt).unwrap();
        assert_eq!(
            fixture.store.read_blob(&pending.receipt_blob).unwrap(),
            receipt_bytes
        );
        assert_eq!(
            fixture
                .store
                .operation(&fixture.request.source_operation_id)
                .unwrap(),
            original
        );

        // A later authenticated call may read retained truth. Regaining current
        // authority does not manufacture settled source history or an undo grant.
        fixture.rpc.cancelled.set(false);
        fixture.session.cancel_after_receipt = false;
        fixture.authority.capture_revoke_at = None;
        let associations =
            associations(&fixture.store, &fixture.rpc, &pending.source_operation_id).unwrap();
        let association = associations
            .iter()
            .find(|a| a.summary == pending.material_summary)
            .unwrap();
        let invocation_blob = fixture
            .store
            .stored_invocation_blob(
                &fixture.request.source_operation_id,
                &fixture.request.source_step_id,
            )
            .unwrap();
        assert_eq!(
            association.source_blobs,
            vec![
                pending.receipt_blob.clone(),
                pending.route_blob.clone(),
                invocation_blob,
            ]
        );
        assert_eq!(
            fixture
                .store
                .operation_summaries(&pending.source_operation_id)
                .unwrap(),
            vec![pending.material_summary.clone()]
        );
        fixture.session.expired = true;
        fixture.store.collect_orphan_blobs(1000).unwrap();
        let mut fixture = fixture.reopen();
        assert_eq!(
            encode_record(&fixture.pending().unwrap()).unwrap(),
            encode_record(&pending).unwrap(),
            "case={case}"
        );
        assert_eq!(fixture.session.calls, 1);
        assert_eq!(
            fixture.store.read_blob(&pending.receipt_blob).unwrap(),
            receipt_bytes
        );
        assert!(fixture.promote(&pending.record_id).is_err());
        let (operation, invocation) =
            fixture.new_intent(&pending, &format!("undo-{case}"), |plan| {
                plan["steps"][0]["resourcesRead"] = json!([TARGET_A, TARGET_B]);
                plan["steps"][0]["resourcesWritten"] = json!([TARGET_A, TARGET_B]);
            });
        assert!(
            matches!(
                fixture.dispatch(&pending, &operation, &invocation),
                Err(StorageError::Conflict(
                    "Provider undo material is pending or already claimed"
                ))
            ),
            "case={case}"
        );
        fixture.assert_no_intent(&operation);
        assert_eq!(
            fixture.read(&pending.record_id).unwrap().state,
            UndoRecordState::Pending
        );
        let claims: i64 = fixture
            .store
            .connection
            .query_row(
                "SELECT count(*) FROM provider_undo_records WHERE claim_operation_id IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(claims, 0);
    }
}

#[test]
fn settled_partial_failed_source_retains_original_failure_and_real_before_capture() {
    let mut fixture = Fixture::new(true);
    let pending = fixture.pending().unwrap();
    let response = json!({"status":"failed","effects":"partial","diagnostics":[{"code":"SOURCE_FIXTURE_FAILED"}]});
    let source_response = blob(&fixture.store, &response);
    let marker = blob(
        &fixture.store,
        &json!({"kind":"provider_result","stepId":fixture.invocation["stepId"],"invocationId":fixture.invocation["invocationId"],"resultBlob":source_response,"outputValidated":true}),
    );
    fixture
        .store
        .append_operation_summary(
            &fixture.request.source_operation_id,
            &marker,
            std::slice::from_ref(&source_response),
        )
        .unwrap();
    fixture.settle(EffectEvidence::SomeConfirmed, "valid");
    let original = fixture
        .store
        .operation(&fixture.request.source_operation_id)
        .unwrap();
    let available = fixture.promote(&pending.record_id).unwrap();
    assert_eq!(available.state, UndoRecordState::Available);
    for state in &available.after_states {
        assert_eq!(state.before.as_ref(), fixture.before.get(&state.target));
    }
    assert_eq!(
        fixture
            .store
            .operation(&fixture.request.source_operation_id)
            .unwrap(),
        original
    );
    assert_eq!(original.state, OperationState::Partial);
    assert_eq!(original.steps[0].effect, EffectEvidence::SomeConfirmed);
    assert_eq!(
        fixture.store.read_blob(&source_response).unwrap(),
        encode_json(&response).unwrap()
    );
}

#[test]
fn forged_receipt_source_identity_actor_and_context_cannot_create_pending_material() {
    for case in [
        "receipt-hash",
        "source-step",
        "source-invocation",
        "arguments",
        "actor",
        "epoch",
        "extra-field",
        "source-digest",
        "principal",
        "cancel",
    ] {
        let mut fixture = Fixture::new(false);
        match case {
            "receipt-hash" => {
                fixture.session.receipt["tokenRecordDigest"] = json!(raw_digest(b"wrong-self-hash"))
            }
            "source-step" => fixture.session.receipt["sourceStepId"] = json!("another-source-step"),
            "source-invocation" => {
                fixture.session.receipt["sourceInvocationId"] = json!("another-source-invocation")
            }
            "arguments" => {
                fixture.session.receipt["sourceArgumentsDigest"] =
                    json!(raw_digest(b"other-arguments"))
            }
            "actor" => fixture.session.player = "123e4567-e89b-12d3-a456-426614174001".into(),
            "epoch" => {
                fixture.rpc.context["environment"]["sessionEpoch"] = json!("another-epoch");
                fixture.rpc.context["contextDigest"] =
                    json!(projected_digest("ExecutionContext", &fixture.rpc.context).unwrap());
            }
            "extra-field" => {
                fixture.session.receipt["privateToken"] = json!("untrusted-wire-extra")
            }
            "source-digest" => {
                fixture.request.source_invocation_digest = raw_digest(b"another-invocation")
            }
            "principal" => fixture.rpc.principal = PrincipalId::new("principal-stranger").unwrap(),
            "cancel" => fixture.rpc.cancel_at = Some(1),
            _ => unreachable!(),
        }
        if !matches!(case, "receipt-hash") {
            fixture.session.receipt = signed_receipt(fixture.session.receipt.clone());
        }
        assert!(fixture.pending().is_err(), "case={case}");
        let count: i64 = fixture
            .store
            .connection
            .query_row("SELECT count(*) FROM provider_undo_records", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "case={case}");
    }
}

#[test]
fn promotion_requires_same_source_summary_after_pins_and_complete_frozen_targets() {
    for case in [
        "source-step",
        "summary",
        "after-pin",
        "after-association",
        "missing-target",
        "extra-target",
        "duplicate-target",
        "fake-before",
        "receipt-pin",
        "receipt-bytes",
    ] {
        let mut fixture = Fixture::new(true);
        let pending = fixture.pending().unwrap();
        fixture.settle(EffectEvidence::SomeConfirmed, case);
        let original = fixture
            .store
            .operation(&fixture.request.source_operation_id)
            .unwrap();
        if case == "receipt-pin" {
            fixture.store.connection.execute("DELETE FROM blob_refs WHERE owner_kind='application_evidence' AND owner_id=?1 AND digest=?2",params![fixture.request.source_operation_id.as_str(),pending.receipt_blob.digest.as_str()]).unwrap();
        }
        if case == "receipt-bytes" {
            fs::write(
                fixture.store.cas.path(&pending.receipt_blob.digest),
                b"corrupt receipt",
            )
            .unwrap();
        }
        assert!(fixture.promote(&pending.record_id).is_err(), "case={case}");
        assert_eq!(
            read_record_inner(&fixture.store, &pending.record_id)
                .unwrap()
                .state,
            UndoRecordState::Pending,
            "case={case}"
        );
        assert_eq!(
            fixture
                .store
                .operation(&fixture.request.source_operation_id)
                .unwrap(),
            original,
            "case={case}"
        );
    }
}

// A valid codec and retained source response distinguish a recovery role guard
// from ordinary resolution failure; no made-up witness can satisfy this test.
fn resolved_undo_fixture(
    fixture: &mut Fixture,
    record: &ProviderUndoRecord,
) -> (OperationId, Value, BlobRef) {
    let action = example("provider-supported.json")["actions"][0].clone();
    let action_digest = canonical_digest(&action).unwrap();
    let action_blob = fixture
        .store
        .register_result_action(&fixture.route.source_binding_id, &action)
        .unwrap();
    fixture
        .store
        .register_result_action(&fixture.route.undo_binding_id, &fixture.route.undo_action)
        .unwrap();
    let undo_digest = canonical_digest(&fixture.route.undo_action).unwrap();
    let codec = RegisteredResultCodec {
        codec_id: ObjectId::new("undo-fixture-identity-codec").unwrap(),
        implementation: ResultCodecImplementation::JsonIdentityV1,
        input_schema: json!({"type":"string"}),
        output_schema: json!({"type":"string"}),
        allowed_slots: vec![ResultArgumentSlot {
            action_digest: undo_digest.clone(),
            argument_pointer: "/tokenRecordId".into(),
        }],
    };
    let codec_blob = fixture.store.register_result_codec(&codec).unwrap();
    let binding = ResultStepBinding {
        argument_pointer: "/tokenRecordId".into(),
        source_step_id: StepId::new("read-token-reference").unwrap(),
        output_pointer: "/text".into(),
        expected_schema_digest: canonical_digest(&action["outputSchema"]).unwrap(),
        codec_id: codec.codec_id.clone(),
        codec_digest: codec.metadata_digest().unwrap(),
    };
    let mut plan = fixture.undo_plan(record, "undo-resolved");
    let mut consumer = plan["steps"][0].clone();
    consumer["dependsOn"] = json!([binding.source_step_id]);
    consumer["resultBindings"] = json!([binding]);
    consumer["arguments"]["tokenRecordId"] = json!("frozen-template-reference");
    let mut producer = fixture.plan["steps"][0].clone();
    producer["stepId"] = json!("read-token-reference");
    for key in [
        "actionId",
        "effect",
        "completion",
        "recovery",
        "verificationRequirement",
        "implementationDigest",
    ] {
        producer[key] = action[key].clone();
    }
    producer["actionDigest"] = json!(action_digest);
    producer["resourcesRead"] = json!([]);
    producer["resourcesWritten"] = json!([]);
    producer["arguments"] = json!({"text":"reference-only"});
    plan["steps"] = json!([producer, consumer]);
    pin_context(&mut plan, &fixture.rpc.context);
    let operation = OperationId::new("undo-resolved").unwrap();
    reserve(&mut fixture.store, &plan, &operation);
    let source_invocation = invocation_for(
        &plan,
        0,
        &fixture.rpc.context,
        &operation,
        "invocation-resolved-reference",
    );
    let source_record = fixture
        .store
        .dispatch_intent(&operation, &binding.source_step_id, &source_invocation)
        .unwrap();
    let selected = record.receipt["tokenRecordId"].clone();
    let result = blob(
        &fixture.store,
        &json!({"contractVersion":"0.2.0","status":"complete","data":{"text":selected},"effects":"none","diagnostics":[],"artifacts":[]}),
    );
    let marker = blob(
        &fixture.store,
        &json!({"kind":"provider_result","stepId":binding.source_step_id,"invocationId":source_invocation["invocationId"],"actionDigest":action_digest,"outputSchemaDigest":binding.expected_schema_digest,"outputValidated":true,"value":{"status":"complete"},"resultBlob":result,"sourceRefs":[result]}),
    );
    fixture
        .store
        .append_operation_summary(&operation, &marker, std::slice::from_ref(&result))
        .unwrap();
    fixture
        .store
        .record_observation(
            &operation,
            &binding.source_step_id,
            StepObservation {
                dispatch: DispatchEvidence::Acknowledged,
                effect: EffectEvidence::NoneConfirmed,
                further_effects_possible: false,
                provider_receipt: None,
                observation_refs: vec![marker.clone()],
                finished: true,
            },
        )
        .unwrap();
    let mut invocation = invocation_for(
        &plan,
        1,
        &fixture.rpc.context,
        &operation,
        "invocation-undo-resolved",
    );
    invocation["arguments"]["tokenRecordId"] = selected.clone();
    invocation["argumentsDigest"] = json!(canonical_digest(&invocation["arguments"]).unwrap());
    let arguments = blob(&fixture.store, &invocation["arguments"]);
    let witness = ResultResolutionWitness {
        kind: "result_resolution_witness".into(),
        version: 1,
        operation_id: operation.clone(),
        plan_hash: serde_json::from_value(plan["planHash"].clone()).unwrap(),
        step_id: StepId::new("undo-step").unwrap(),
        template_arguments_digest: canonical_digest(&plan["steps"][1]["arguments"]).unwrap(),
        arguments_blob: arguments,
        arguments_digest: canonical_digest(&invocation["arguments"]).unwrap(),
        context_digest: serde_json::from_value(invocation["contextDigest"].clone()).unwrap(),
        action_digest: undo_digest,
        implementation_digest: serde_json::from_value(invocation["implementationDigest"].clone())
            .unwrap(),
        resolved_footprint: ResultFootprint {
            resources_read: vec![json!(TARGET_A), json!(TARGET_B)],
            resources_written: vec![json!(TARGET_A), json!(TARGET_B)],
        },
        bindings: vec![ResultBindingWitness {
            binding,
            source_invocation_id: InvocationId::new("invocation-resolved-reference").unwrap(),
            source_invocation_digest: source_record.invocation_digest.unwrap(),
            source_result: result,
            source_result_summary: marker,
            source_action: action_blob,
            codec: codec_blob,
            selected_value_digest: canonical_digest(&selected).unwrap(),
            resolved_value_digest: canonical_digest(&selected).unwrap(),
        }],
    };
    (
        operation,
        invocation,
        blob(&fixture.store, &serde_json::to_value(witness).unwrap()),
    )
}

#[test]
fn ordinary_and_valid_result_resolved_plans_cannot_dispatch_registered_undo_routes() {
    let mut fixture = Fixture::new(false);
    let pending = fixture.pending().unwrap();
    fixture.settle(EffectEvidence::CompleteConfirmed, "valid");
    let available = fixture.promote(&pending.record_id).unwrap();
    let (operation, invocation) = fixture.new_intent(&available, "undo-ordinary", |_| {});
    assert!(
        matches!(fixture.store.dispatch_intent(&operation,&StepId::new("undo-step").unwrap(),&invocation),Err(StorageError::InvalidTransition(message)) if message.contains("atomic recovery claim"))
    );
    fixture.assert_no_intent(&operation);
    let (operation, invocation, witness) = resolved_undo_fixture(&mut fixture, &available);
    assert!(
        matches!(fixture.store.dispatch_resolved_intent(&operation,&StepId::new("undo-step").unwrap(),&invocation,&witness),Err(StorageError::InvalidTransition(message)) if message.contains("atomic recovery claim"))
    );
    assert!(
        fixture
            .store
            .stored_invocation(&operation, &StepId::new("undo-step").unwrap())
            .is_err()
    );
    assert_eq!(
        read_record_inner(&fixture.store, &available.record_id)
            .unwrap()
            .state,
        UndoRecordState::Available
    );
}

#[test]
fn actual_plan_binding_and_retained_target_truth_are_checked_before_and_inside_claim() {
    for case in [
        "other-plan-id",
        "other-plan-hash",
        "unbound-observe",
        "default-deny-observe",
        "wrong-invocation-operation",
        "retained-expiry",
        "writer-expiry",
        "retained-valid",
    ] {
        let mut fixture = Fixture::new(false);
        if matches!(case, "unbound-observe" | "default-deny-observe") {
            fixture.rpc.binding_expired.set(true);
        }
        assert!(fixture.rpc.bound_plan.is_none());
        let pending = if case == "default-deny-observe" {
            register_undo_record(
                &mut fixture.store,
                &ObserveOnly(&fixture.rpc),
                &mut fixture.authority,
                &mut fixture.session,
                &fixture.request,
            )
            .unwrap()
        } else {
            fixture.pending().unwrap()
        };
        assert_eq!(pending.state, UndoRecordState::Pending);
        fixture.settle(EffectEvidence::CompleteConfirmed, "valid");
        let available = fixture.promote(&pending.record_id).unwrap();
        assert_eq!(available.state, UndoRecordState::Available);
        assert_eq!(
            fixture.rpc.dispatch_plan_checks.get(),
            0,
            "Observe capture and durable promotion do not grant Apply authority"
        );
        fixture.rpc.binding_expired.set(false);
        let original = fixture
            .store
            .operation(&fixture.request.source_operation_id)
            .unwrap();

        let (operation_a, invocation_a) = fixture.new_intent(&available, "undo-approved-a", |_| {});
        let approved_a = fixture.rpc.bound_plan.clone().unwrap();
        let actual_a = fixture.store.operation(&operation_a).unwrap();
        let (operation_b, mut invocation_b) =
            fixture.new_intent(&available, "undo-actual-b", |_| {});
        let actual_b = fixture.store.operation(&operation_b).unwrap();
        let plan_a = fixture
            .store
            .plan(&actual_a.plan_id, &actual_a.plan_hash)
            .unwrap();
        let plan_b = fixture
            .store
            .plan(&actual_b.plan_id, &actual_b.plan_hash)
            .unwrap();
        assert_ne!(actual_a.plan_id, actual_b.plan_id);
        assert_ne!(actual_a.plan_hash, actual_b.plan_hash);
        assert_eq!(plan_a["steps"], plan_b["steps"]);
        assert_eq!(plan_a["scope"], plan_b["scope"]);
        assert_eq!(plan_a["contextPins"], plan_b["contextPins"]);
        assert_eq!(invocation_a["arguments"], invocation_b["arguments"]);
        assert_eq!(invocation_a["context"], invocation_b["context"]);
        match case {
            "other-plan-id" => fixture.rpc.bound_plan = Some(approved_a),
            "other-plan-hash" => {
                fixture.rpc.bound_plan =
                    Some((actual_b.plan_id.clone(), actual_a.plan_hash.clone()))
            }
            "unbound-observe" => {
                fixture.rpc.bound_plan = None;
                fixture.rpc.binding_expired.set(true);
            }
            "wrong-invocation-operation" => invocation_b["operationId"] = json!(operation_a),
            "retained-expiry" => {
                fixture.authority.retain_current_reads = true;
                fixture.authority.expire_binding_after_read = Some(1);
            }
            "writer-expiry" | "retained-valid" => fixture.authority.retain_current_reads = true,
            _ => (),
        }

        let result = if case == "default-deny-observe" {
            dispatch_undo_intent(
                &mut fixture.store,
                &ObserveOnly(&fixture.rpc),
                &mut fixture.authority,
                &UndoDispatchRequest {
                    operation_id: &operation_b,
                    step_id: &StepId::new("undo-step").unwrap(),
                    invocation: &invocation_b,
                    undo_record_id: &available.record_id,
                },
            )
        } else if case == "writer-expiry" {
            // Use the real precheck and SQLite writer, then expire only the
            // local Apply binding. Native observations may not run in writer.
            let step = StepId::new("undo-step").unwrap();
            let request = UndoDispatchRequest {
                operation_id: &operation_b,
                step_id: &step,
                invocation: &invocation_b,
                undo_record_id: &available.record_id,
            };
            let seal = prepare_undo_authorization(
                &mut fixture.store,
                &fixture.rpc,
                &mut fixture.authority,
                &request,
            )
            .unwrap();
            let reads = fixture.authority.target_reads;
            let checks = fixture.rpc.dispatch_plan_checks.get();
            fixture.rpc.binding_expired.set(true);
            let result = fixture.store.dispatch_intent_internal(
                &operation_b,
                &step,
                &invocation_b,
                None,
                Some(seal),
            );
            assert_eq!(fixture.authority.target_reads, reads);
            assert!(fixture.rpc.dispatch_plan_checks.get() > checks);
            result
        } else {
            fixture.dispatch(&available, &operation_b, &invocation_b)
        };

        if case == "retained-valid" {
            assert_eq!(result.unwrap().dispatch, DispatchEvidence::IntentDurable);
            assert!(
                matches!(read_record_inner(&fixture.store, &available.record_id).unwrap().state,
                UndoRecordState::Reserved { ref operation_id, .. } if operation_id == &operation_b)
            );
            assert_eq!(
                fixture
                    .store
                    .stored_invocation(&operation_b, &StepId::new("undo-step").unwrap())
                    .unwrap(),
                invocation_b
            );
        } else {
            match case {
                "default-deny-observe" => assert!(
                    matches!(result, Err(StorageError::InvalidTransition(message))
                    if message.contains("actual approved plan binding"))
                ),
                "wrong-invocation-operation" => assert!(matches!(
                    result,
                    Err(StorageError::Conflict("Undo new invocation identity"))
                )),
                _ => assert!(
                    matches!(
                        result,
                        Err(StorageError::Conflict(
                            "Fixture Apply approval is not bound to this plan"
                        ))
                    ),
                    "case={case}"
                ),
            }
            fixture.assert_no_intent(&operation_b);
            assert_eq!(
                read_record_inner(&fixture.store, &available.record_id)
                    .unwrap()
                    .state,
                UndoRecordState::Available,
                "case={case}"
            );
            let claim_rows: i64 = fixture.store.connection.query_row(
                "SELECT count(*) FROM events WHERE operation_id=?1 AND kind IN ('provider_undo_claim','dispatch_intent')",
                [operation_b.as_str()], |row| row.get(0),
            ).unwrap();
            let claim_pins: i64 = fixture
                .store
                .connection
                .query_row(
                    "SELECT count(*) FROM blob_refs WHERE owner_kind='undo_claim' AND owner_id=?1",
                    [invocation_b["invocationId"].as_str().unwrap()],
                    |row| row.get(0),
                )
                .unwrap();
            let fences: i64 = fixture
                .store
                .connection
                .query_row(
                    "SELECT count(*) FROM write_fences WHERE operation_id=?1",
                    [operation_b.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!((claim_rows, claim_pins, fences), (0, 0, 0), "case={case}");
        }
        assert_eq!(
            fixture
                .store
                .operation(&fixture.request.source_operation_id)
                .unwrap(),
            original
        );
        fixture.assert_no_intent(&operation_a);
        assert_eq!(fixture.session.calls, 1);

        if matches!(case, "retained-expiry" | "writer-expiry" | "retained-valid") {
            assert_eq!(fixture.authority.target_reads, 2);
            assert_eq!(fixture.authority.retained_current_reads.len(), 2);
            let retained = fixture.authority.retained_current_reads.clone();
            let exact: Vec<_> = retained
                .iter()
                .map(|evidence| {
                    (
                        fixture.store.read_blob(&evidence.raw).unwrap(),
                        fixture.store.read_blob(&evidence.envelope).unwrap(),
                        fixture.store.read_blob(&evidence.summary).unwrap(),
                    )
                })
                .collect();
            fixture.store.collect_orphan_blobs(1000).unwrap();
            let fixture = fixture.reopen();
            let associations =
                associations(&fixture.store, &fixture.rpc, &available.source_operation_id).unwrap();
            for (evidence, (raw, envelope, summary)) in retained.iter().zip(exact) {
                assert_eq!(fixture.store.read_blob(&evidence.raw).unwrap(), raw);
                assert_eq!(
                    fixture.store.read_blob(&evidence.envelope).unwrap(),
                    envelope
                );
                assert_eq!(fixture.store.read_blob(&evidence.summary).unwrap(), summary);
                let observed = parse_json(&envelope).unwrap();
                assert_eq!(
                    observed["sourceOperationId"],
                    available.source_operation_id.as_str()
                );
                assert_eq!(observed["target"], evidence.target);
                let association = associations
                    .iter()
                    .find(|item| item.summary == evidence.summary)
                    .unwrap();
                assert!(association.source_blobs.contains(&evidence.raw));
                assert!(association.source_blobs.contains(&evidence.envelope));
                let source_pin: i64 = fixture
                    .store
                    .connection
                    .query_row(
                        "SELECT count(*) FROM blob_refs WHERE owner_kind='application_evidence' AND owner_id=?1 AND digest=?2",
                        params![
                            available.source_operation_id.as_str(),
                            evidence.envelope.digest.as_str()
                        ],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(source_pin, 1, "new truth retains the original source owner");
            }
            assert_eq!(
                read_record_inner(&fixture.store, &available.record_id)
                    .unwrap()
                    .state,
                if case == "retained-valid" {
                    UndoRecordState::Reserved {
                        operation_id: operation_b.clone(),
                        step_id: StepId::new("undo-step").unwrap(),
                        invocation_id: serde_json::from_value(invocation_b["invocationId"].clone())
                            .unwrap(),
                        invocation_digest: raw_digest(&encode_json(&invocation_b).unwrap()),
                    }
                } else {
                    UndoRecordState::Available
                }
            );
            if case != "retained-valid" {
                fixture.assert_no_intent(&operation_b);
            }
        } else {
            assert_eq!(fixture.authority.target_reads, 0, "case={case}");
            assert_eq!(fixture.authority.recovery_checks, 0, "case={case}");
        }
    }
}

#[test]
fn closed_arguments_context_drift_after_drift_and_fresh_acl_fail_without_claim() {
    for case in [
        "extra-argument",
        "other-source",
        "footprint",
        "precondition",
        "epoch",
        "executor",
        "origin",
        "after-drift",
        "acl",
        "late-acl",
        "late-context",
        "cancel",
    ] {
        let mut fixture = Fixture::new(false);
        let pending = fixture.pending().unwrap();
        fixture.settle(EffectEvidence::CompleteConfirmed, "valid");
        let available = fixture.promote(&pending.record_id).unwrap();
        match case {
            "epoch" => {
                fixture.rpc.context["environment"]["sessionEpoch"] = json!("new-host-generation")
            }
            "executor" => fixture.rpc.context["executorHandle"] = json!("another-executor"),
            "origin" => fixture.rpc.context["origin"] = json!([1, 64, 0]),
            _ => (),
        }
        fixture.rpc.context["contextDigest"] =
            json!(projected_digest("ExecutionContext", &fixture.rpc.context).unwrap());
        let (operation, invocation) =
            fixture.new_intent(&available, "undo-denied", |plan| match case {
                "extra-argument" => {
                    plan["steps"][0]["arguments"]["before"] = json!("caller-fabricated")
                }
                "other-source" => {
                    plan["steps"][0]["arguments"]["sourceInvocationId"] =
                        json!("other-source-invocation")
                }
                "footprint" => plan["steps"][0]["resourcesWritten"] = json!([TARGET_A]),
                "precondition" => plan["preconditions"] = json!([]),
                _ => (),
            });
        if case == "after-drift" {
            fixture
                .authority
                .current
                .insert(TARGET_A.into(), b"later actor changed target".to_vec());
        }
        if case == "acl" {
            fixture.authority.denied = true;
        }
        if case == "late-acl" {
            fixture.authority.revoke_at = Some(2);
        }
        if case == "late-context" {
            fixture.authority.change_context_at = Some(2);
        }
        if case == "cancel" {
            fixture.rpc.cancel_at = Some(fixture.rpc.checks.get() + 2);
        }
        let original = fixture
            .store
            .operation(&fixture.request.source_operation_id)
            .unwrap();
        assert!(
            fixture
                .dispatch(&available, &operation, &invocation)
                .is_err(),
            "case={case}"
        );
        fixture.assert_no_intent(&operation);
        assert_eq!(
            read_record_inner(&fixture.store, &available.record_id)
                .unwrap()
                .state,
            UndoRecordState::Available,
            "case={case}"
        );
        assert_eq!(
            fixture
                .store
                .operation(&fixture.request.source_operation_id)
                .unwrap(),
            original,
            "case={case}"
        );
    }
}

#[test]
fn last_dispatch_event_failure_rolls_back_claim_invocation_fence_and_journal() {
    let mut fixture = Fixture::new(true);
    let pending = fixture.pending().unwrap();
    fixture.settle(EffectEvidence::SomeConfirmed, "valid");
    let available = fixture.promote(&pending.record_id).unwrap();
    let (operation, invocation) = fixture.new_intent(&available, "undo-rollback", |_| {});
    fixture.store.connection.execute_batch("CREATE TRIGGER fail_undo_intent BEFORE INSERT ON events WHEN NEW.kind='dispatch_intent' AND NEW.operation_id='undo-rollback' BEGIN SELECT RAISE(ABORT,'owned undo rollback fixture'); END;").unwrap();
    let original = fixture
        .store
        .operation(&fixture.request.source_operation_id)
        .unwrap();
    assert!(
        fixture
            .dispatch(&available, &operation, &invocation)
            .is_err()
    );
    fixture.assert_no_intent(&operation);
    assert_eq!(
        read_record_inner(&fixture.store, &available.record_id)
            .unwrap()
            .state,
        UndoRecordState::Available
    );
    for table in ["write_fences", "events"] {
        let count: i64 = fixture
            .store
            .connection
            .query_row(
                &format!("SELECT count(*) FROM {table} WHERE operation_id=?1"),
                [operation.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        if table == "events" {
            assert_eq!(count, 1, "only the original reservation event is retained");
        } else {
            assert_eq!(count, 0);
        }
    }
    let pins: i64 = fixture
        .store
        .connection
        .query_row(
            "SELECT count(*) FROM blob_refs WHERE owner_kind='undo_claim' AND owner_id=?1",
            [invocation["invocationId"].as_str().unwrap()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pins, 0);
    assert_eq!(
        fixture
            .store
            .operation(&fixture.request.source_operation_id)
            .unwrap(),
        original
    );
    fixture
        .store
        .connection
        .execute_batch("DROP TRIGGER fail_undo_intent;")
        .unwrap();
    assert_eq!(
        fixture
            .dispatch(&available, &operation, &invocation)
            .unwrap()
            .dispatch,
        DispatchEvidence::IntentDurable
    );
}

#[test]
fn committed_claim_survives_restart_and_cannot_be_reclaimed_with_new_operation() {
    let mut fixture = Fixture::new(true);
    let pending = fixture.pending().unwrap();
    fixture.settle(EffectEvidence::SomeConfirmed, "valid");
    let available = fixture.promote(&pending.record_id).unwrap();
    let original = fixture
        .store
        .operation(&fixture.request.source_operation_id)
        .unwrap();
    fixture.rpc.context["policyRevision"] =
        json!(raw_digest(b"new separately approved undo policy"));
    fixture.rpc.context["contextDigest"] =
        json!(projected_digest("ExecutionContext", &fixture.rpc.context).unwrap());
    let (operation, invocation) = fixture.new_intent(&available, "undo-committed", |_| {});
    let intent = fixture
        .dispatch(&available, &operation, &invocation)
        .unwrap();
    assert_eq!(intent.dispatch, DispatchEvidence::IntentDurable);
    let invocation_id: InvocationId =
        serde_json::from_value(invocation["invocationId"].clone()).unwrap();
    let claimed = claimed_undo_record(
        &fixture.store,
        &operation,
        &StepId::new("undo-step").unwrap(),
        &invocation_id,
    )
    .unwrap();
    assert!(
        matches!(claimed.state,UndoRecordState::Reserved {ref operation_id,..} if operation_id==&operation)
    );
    fixture.session.expired = true;
    let mut fixture = fixture.reopen();
    let reserved = fixture.read(&available.record_id).unwrap();
    assert!(matches!(reserved.state, UndoRecordState::Reserved { .. }));
    let interrupted = fixture.store.operation(&operation).unwrap();
    assert!(interrupted.reconciliation_required);
    assert_eq!(
        interrupted.steps[0].dispatch,
        DispatchEvidence::IntentDurable
    );
    // A separately retained no-effect observation clears the ordinary write
    // fence. The committed undo claim still cannot become Available, even if
    // no host effect occurred; otherwise a fence could mask a broken claim.
    let no_effect = blob(
        &fixture.store,
        &json!({"kind":"authored_undo_no_effect_readback","invocationId":invocation_id}),
    );
    fixture
        .store
        .record_observation(
            &operation,
            &StepId::new("undo-step").unwrap(),
            StepObservation {
                dispatch: DispatchEvidence::Observed,
                effect: EffectEvidence::NoneConfirmed,
                further_effects_possible: false,
                provider_receipt: None,
                observation_refs: vec![no_effect],
                finished: true,
            },
        )
        .unwrap();
    fixture
        .store
        .finish_operation(&operation, OperationState::FailedBeforeEffects)
        .unwrap();
    let mut fixture = fixture.reopen();
    let (another, attempt) = fixture.new_intent(&available, "undo-second-claim", |_| {});
    assert!(matches!(
        fixture.dispatch(&available, &another, &attempt),
        Err(StorageError::Conflict(message)) if message.contains("already claimed")
    ));
    fixture.assert_no_intent(&another);
    assert!(fixture.promote(&available.record_id).is_err());
    assert_eq!(fixture.session.calls, 1);
    assert_eq!(
        fixture
            .store
            .operation(&fixture.request.source_operation_id)
            .unwrap(),
        original
    );
    assert_eq!(
        fixture
            .store
            .stored_invocation(&operation, &StepId::new("undo-step").unwrap())
            .unwrap(),
        invocation
    );
}

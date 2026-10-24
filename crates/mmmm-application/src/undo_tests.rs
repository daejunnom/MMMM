//! Child of the existing stateful SQLite/CAS fixture module. Trusted fixture
//! RPC and host ports exercise durable undo authority; no fake result proves
//! real game-host or transport acceptance.
use super::*;
use crate::undo::{
    HostUndoReceipt, HostUndoRegistration, InspectedHostUndoMaterial, UndoMaterialPort,
    assemble_undo_plan, check_host_material, check_undo_context,
};
use mmmm_runtime::storage::undo::{
    self as durable_undo, ProviderUndoRecord, UndoAuthority, UndoRecordState, UndoRpcContext,
};
use mmmm_runtime::storage::{
    OperationRecord, OperationState, StepObservation, StorageError, StorageResult,
};

#[path = "undo_bundle_tests.rs"]
mod undo_bundle_tests;

fn undo_source_fixture(capture: bool, failed: bool) -> Fixture {
    let mut fixture = Fixture::new(1);
    fixture.provider.descriptor["recovery"] = json!("provider_undo");
    fixture.planner.prepared.steps = vec![write_step(
        &fixture.provider.descriptor,
        "write-first",
        "after-first",
        vec![],
    )];
    fixture.target.borrow_mut().capture_available = capture;
    fixture.target.borrow_mut().fail_on_dispatch = failed.then_some(1);
    fixture
}

fn inspected_material(fixture: &Fixture, invocation: &Value) -> InspectedHostUndoMaterial {
    assert!(
        fixture
            .target
            .borrow()
            .invocations
            .contains_key(invocation["invocationId"].as_str().unwrap())
    );
    let mut descriptor = fixture.provider.descriptor.clone();
    descriptor["actionId"] = json!("fixture:provider_undo");
    descriptor["recovery"] = json!("none");
    descriptor["inputSchema"] = json!({"type":"object","properties":{
        "tokenRecordId":{"type":"string"},"tokenRecordDigest":{"type":"string"},
        "sourceOperationId":{"type":"string"},"sourceStepId":{"type":"string"},
        "sourceInvocationId":{"type":"string"}},"required":["tokenRecordId","tokenRecordDigest",
        "sourceOperationId","sourceStepId","sourceInvocationId"],"additionalProperties":false});
    descriptor["outputSchema"] = json!({"type":"object","properties":{"restored":{"type":"boolean"}},
        "required":["restored"],"additionalProperties":false});
    let registration = HostUndoRegistration {
        binding_id: decode(&invocation["bindingId"]).unwrap(),
        source_action_id: decode(&invocation["actionId"]).unwrap(),
        source_action_digest: decode(&invocation["actionDigest"]).unwrap(),
        source_implementation_digest: decode(&invocation["implementationDigest"]).unwrap(),
        undo_action_digest: canonical_digest(&descriptor).unwrap(),
        undo_action: descriptor,
        provider_origin: json!({"kind":"native","label":"stateful-test-host"}),
    };
    let mut receipt = HostUndoReceipt {
        contract_version: "0.2.0".into(),
        token_record_id: ObjectId::new("undo-fixture-source").unwrap(),
        principal_ref: fixture.principal.clone(),
        session_epoch: invocation["context"]["environment"]["sessionEpoch"]
            .as_str()
            .unwrap()
            .into(),
        game_instance_id: invocation["context"]["environment"]["gameInstanceId"]
            .as_str()
            .unwrap()
            .into(),
        side: invocation["context"]["environment"]["side"]
            .as_str()
            .unwrap()
            .into(),
        player_id: "123e4567-e89b-12d3-a456-426614174000".into(),
        binding_id: registration.binding_id.clone(),
        source_action_id: registration.source_action_id.clone(),
        source_action_digest: registration.source_action_digest.clone(),
        source_implementation_digest: registration.source_implementation_digest.clone(),
        source_arguments_digest: decode(&invocation["argumentsDigest"]).unwrap(),
        source_context_digest: decode(&invocation["contextDigest"]).unwrap(),
        source_operation_id: decode(&invocation["operationId"]).unwrap(),
        source_step_id: decode(&invocation["stepId"]).unwrap(),
        source_invocation_id: decode(&invocation["invocationId"]).unwrap(),
        undo_action_id: decode(&registration.undo_action["actionId"]).unwrap(),
        source_context: invocation["context"].clone(),
        private_token_sha256: canonical_digest(&json!({"private-test-host-material":"owned"}))
            .unwrap(),
        token_record_digest: Sha256Digest::new("0".repeat(64)).unwrap(),
    };
    let mut projection = json!(receipt);
    projection
        .as_object_mut()
        .unwrap()
        .remove("tokenRecordDigest");
    receipt.token_record_digest = canonical_digest(&projection).unwrap();
    InspectedHostUndoMaterial {
        registration,
        authenticated_player_id: receipt.player_id.clone(),
        receipt,
    }
}

#[test]
fn undo_independent_after_is_retained_without_fabricating_before_and_survives_gc() {
    let mut fixture = undo_source_fixture(false, false);
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "undo-after-without-before").unwrap();
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let invocation = fixture
        .store
        .stored_invocation(&operation, &StepId::new("write-first").unwrap())
        .unwrap();
    assert!(
        fixture
            .store
            .recovery_snapshots(&operation)
            .unwrap()
            .is_empty()
    );
    let observed = fixture
        .observer
        .readback(&invocation, &fixture.planner.prepared.scope)
        .unwrap();
    let states = fixture
        .app()
        .retain_undo_after_targets(&operation, &plan["steps"][0], &invocation, &observed)
        .unwrap();
    assert_eq!(states.len(), 1);
    assert!(
        states[0].before.is_none(),
        "no provider/arguments before authority is created"
    );
    assert_eq!(
        fixture.store.read_blob(&states[0].after).unwrap(),
        b"after-first"
    );
    fixture.store.collect_orphan_blobs(1000).unwrap();
    let restarted = fixture.reopen();
    assert_eq!(
        restarted.store.read_blob(&states[0].after).unwrap(),
        b"after-first"
    );
}

#[test]
fn undo_material_checks_original_host_receipt_identity_and_preserves_failed_source() {
    let mut fixture = undo_source_fixture(true, true);
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "undo-failed-source").unwrap();
    assert_eq!(report["result"]["providerStatusCounts"]["failed"], 1);
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let record = fixture.store.operation(&operation).unwrap();
    let invocation = fixture
        .store
        .stored_invocation(&operation, &StepId::new("write-first").unwrap())
        .unwrap();
    let material = inspected_material(&fixture, &invocation);
    check_host_material(
        &fixture.principal,
        &record,
        &invocation,
        &plan["steps"][0],
        &fixture.provider.descriptor,
        &material,
    )
    .unwrap();
    let original_receipt = json!(material.receipt);
    for field in [
        "sourceInvocationId",
        "sourceOperationId",
        "sourceArgumentsDigest",
        "playerId",
        "sessionEpoch",
    ] {
        let mut bad = original_receipt.clone();
        bad[field] = match field {
            "sourceArgumentsDigest" => json!(raw_digest(b"wrong-arguments")),
            "playerId" => json!("123e4567-e89b-12d3-a456-426614174001"),
            _ => json!("different-source"),
        };
        let mut projection = bad.clone();
        projection
            .as_object_mut()
            .unwrap()
            .remove("tokenRecordDigest");
        bad["tokenRecordDigest"] = json!(canonical_digest(&projection).unwrap());
        let mut forged = material.clone();
        forged.receipt = decode(&bad).unwrap();
        assert_eq!(
            check_host_material(
                &fixture.principal,
                &record,
                &invocation,
                &plan["steps"][0],
                &fixture.provider.descriptor,
                &forged
            )
            .unwrap_err()
            .code,
            "RECOVERY_EXPIRED",
            "field={field}"
        );
    }
    assert_eq!(fixture.get(&report).unwrap(), report);
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

#[test]
fn undo_fresh_policy_preserves_physical_context_and_rejects_new_epoch_scope_or_anchor() {
    let fixture = undo_source_fixture(true, false);
    let original = fixture.provider.live_context.clone();
    let project: ProjectId = decode(&original["projectId"]).unwrap();
    let mut current = original.clone();
    current["policyRevision"] = json!(raw_digest(b"fresh-undo-policy"));
    current["contextDigest"] = json!(projected_digest("ExecutionContext", &current).unwrap());
    check_undo_context(&fixture.principal, &project, &original, &current).unwrap();
    for field in ["sessionEpoch", "scope", "anchor", "contextId"] {
        let mut bad = current.clone();
        match field {
            "sessionEpoch" => bad["environment"]["sessionEpoch"] = json!("new-host-generation"),
            "scope" => bad["scope"]["resourceIds"] = json!(["different-resource"]),
            "anchor" => {
                bad["anchor"] = if bad["anchor"] == "eyes" {
                    json!("feet")
                } else {
                    json!("eyes")
                }
            }
            "contextId" => bad["contextId"] = json!("different-context"),
            _ => unreachable!(),
        }
        bad["contextDigest"] = json!(projected_digest("ExecutionContext", &bad).unwrap());
        assert!(
            check_undo_context(&fixture.principal, &project, &original, &bad).is_err(),
            "field={field}"
        );
    }
}

#[test]
fn undo_plan_assembly_uses_closed_original_receipt_and_exact_after_preconditions() {
    let mut fixture = undo_source_fixture(true, false);
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "undo-pure-assembly").unwrap();
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let record = fixture.store.operation(&operation).unwrap();
    let invocation = fixture
        .store
        .stored_invocation(&operation, &StepId::new("write-first").unwrap())
        .unwrap();
    let material = inspected_material(&fixture, &invocation);
    let observed = fixture
        .observer
        .readback(&invocation, &record.scope)
        .unwrap();
    let states = fixture
        .app()
        .retain_undo_after_targets(&operation, &plan["steps"][0], &invocation, &observed)
        .unwrap();
    assert_eq!(
        fixture
            .store
            .read_blob(states[0].before.as_ref().unwrap())
            .unwrap(),
        b"before"
    );
    let prepared = assemble_undo_plan(
        &fixture.clock,
        &record,
        &plan["steps"][0],
        &material,
        &invocation["context"],
        &states,
    )
    .unwrap();
    assert_eq!(prepared.steps.len(), 1);
    assert_eq!(prepared.steps[0]["arguments"].as_object().unwrap().len(), 5);
    assert_eq!(
        prepared.steps[0]["arguments"]["sourceInvocationId"],
        invocation["invocationId"]
    );
    assert_eq!(
        prepared.preconditions[0]["expected"],
        states[0].after.digest.as_str()
    );
    assert_eq!(prepared.preconditions[0]["coverage"], "full_target");
    assert_eq!(prepared.approval_requirement, "explicit_approval");
    assert_eq!(prepared.scope, record.scope);
    assert_eq!(
        fixture.target.borrow().dispatches,
        1,
        "assembly performs no target effects"
    );
}

struct TestUndoRpc {
    principal: PrincipalId,
    context: Rc<RefCell<Value>>,
    cancelled: Rc<Cell<bool>>,
    checks: Cell<usize>,
    deadline: std::time::Instant,
    approved_plan: RefCell<Option<(PlanId, Sha256Digest)>>,
}
impl TestUndoRpc {
    fn from_authenticated_fixture(fixture: &Fixture) -> Self {
        Self {
            principal: fixture.principal.clone(),
            context: Rc::new(RefCell::new(fixture.provider.live_context.clone())),
            cancelled: Rc::new(Cell::new(false)),
            checks: Cell::new(0),
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
            approved_plan: RefCell::new(None),
        }
    }
    fn approve_stored_plan(&self, store: &DurableStore, plan: &Value) {
        self.check().unwrap();
        validate("ExecutionPlan", plan).unwrap();
        let id: PlanId = decode(&plan["planId"]).unwrap();
        let hash: Sha256Digest = decode(&plan["planHash"]).unwrap();
        assert_eq!(store.plan(&id, &hash).unwrap(), *plan);
        assert_eq!(plan["approvalRequirement"], "explicit_approval");
        let current = self.context.borrow();
        assert_eq!(current["principalRef"], self.principal.as_str());
        assert_eq!(plan["projectId"], current["projectId"]);
        assert_eq!(plan["contextId"], current["contextId"]);
        // Only the trusted fixture request composition records this approval.
        // A new reservation, source receipt or caller ID never grants it.
        *self.approved_plan.borrow_mut() = Some((id, hash));
    }
}
impl UndoRpcContext for TestUndoRpc {
    fn check(&self) -> StorageResult<()> {
        self.checks.set(self.checks.get() + 1);
        if self.cancelled.get() || std::time::Instant::now() >= self.deadline {
            Err(StorageError::InvalidTransition(
                "Owned test RPC was cancelled".into(),
            ))
        } else {
            Ok(())
        }
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.principal.clone())
    }
    fn current_context(&self) -> StorageResult<Value> {
        self.check()?;
        Ok(self.context.borrow().clone())
    }
    fn check_dispatch_plan(&self, plan: &PlanId, hash: &Sha256Digest) -> StorageResult<()> {
        self.check()?;
        if self.approved_plan.borrow().as_ref() == Some(&(plan.clone(), hash.clone())) {
            Ok(())
        } else {
            Err(StorageError::Conflict(
                "Exact owned fixture Apply plan seal",
            ))
        }
    }
}

struct TestSourceHost {
    material: InspectedHostUndoMaterial,
    source_invocation: Value,
    target: SharedTarget,
    closed: bool,
    inspections: usize,
    registration_inspections: usize,
    cancel_after_receipt: bool,
    cancelled: Rc<Cell<bool>>,
}
impl TestSourceHost {
    fn actual_source(fixture: &mut Fixture, report: &Value, rpc: &TestUndoRpc) -> Self {
        let operation: OperationId = decode(&report["operationId"]).unwrap();
        let invocation = fixture
            .store
            .stored_invocation(&operation, &StepId::new("write-first").unwrap())
            .unwrap();
        let material = inspected_material(fixture, &invocation);
        fixture.provider.extra_descriptors.insert(
            material.registration.undo_action["actionId"]
                .as_str()
                .unwrap()
                .into(),
            material.registration.undo_action.clone(),
        );
        Self {
            material,
            source_invocation: invocation,
            target: fixture.target.clone(),
            closed: false,
            inspections: 0,
            registration_inspections: 0,
            cancel_after_receipt: false,
            cancelled: rpc.cancelled.clone(),
        }
    }
}
impl UndoMaterialPort for TestSourceHost {
    fn inspect_undo_registration_with_store(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        source_step: &Value,
        _current_context: &Value,
    ) -> AppResult<Option<HostUndoRegistration>> {
        self.registration_inspections += 1;
        if self.closed {
            return Err(AppError::new(
                "RECOVERY_EXPIRED",
                "Original source host session is closed",
            ));
        }
        assert_eq!(principal, &self.material.receipt.principal_ref);
        assert_eq!(source_step["actionId"], self.source_invocation["actionId"]);
        Ok(Some(self.material.registration.clone()))
    }
    fn inspect_source_undo_with_store(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        invocation: &Value,
        _current_context: &Value,
    ) -> AppResult<Option<InspectedHostUndoMaterial>> {
        self.inspections += 1;
        if self.closed {
            return Err(AppError::new(
                "RECOVERY_EXPIRED",
                "Original source host session is closed",
            ));
        }
        assert_eq!(principal, &self.material.receipt.principal_ref);
        assert_eq!(invocation, &self.source_invocation);
        assert!(
            self.target
                .borrow()
                .invocations
                .contains_key(invocation["invocationId"].as_str().unwrap()),
            "host receipt is acquired for an actually dispatched source, never authenticated by raw IDs"
        );
        if self.cancel_after_receipt {
            self.cancelled.set(true);
        }
        Ok(Some(self.material.clone()))
    }
}

struct TestUndoAuthority {
    principal: PrincipalId,
    scope: WriteScope,
    target: SharedTarget,
}
impl TestUndoAuthority {
    fn actual_source(fixture: &Fixture, report: &Value) -> Self {
        let operation: OperationId = decode(&report["operationId"]).unwrap();
        Self {
            principal: fixture.principal.clone(),
            scope: fixture.store.operation(&operation).unwrap().scope,
            target: fixture.target.clone(),
        }
    }
    fn read_grant(&self, principal: &PrincipalId, scope: &WriteScope) -> StorageResult<()> {
        if principal != &self.principal
            || scope != &self.scope
            || !self.target.borrow().observe_grant
        {
            Err(StorageError::Conflict(
                "Current fixture full-scope journal grant denied",
            ))
        } else {
            Ok(())
        }
    }
}
impl UndoAuthority for TestUndoAuthority {
    fn authorize_capture(
        &mut self,
        _store: &DurableStore,
        source: &OperationRecord,
        _invocation: &Value,
        _current: &Value,
    ) -> StorageResult<()> {
        self.read_grant(&source.principal, &source.scope)
    }
    fn authorize_read(
        &mut self,
        _store: &DurableStore,
        record: &ProviderUndoRecord,
        _current: &Value,
    ) -> StorageResult<()> {
        self.read_grant(&record.principal, &record.scope)
    }
    fn authorize_recovery(
        &mut self,
        _store: &DurableStore,
        record: &ProviderUndoRecord,
        invocation: &Value,
    ) -> StorageResult<()> {
        self.read_grant(&record.principal, &record.scope)?;
        if !self.target.borrow().apply_grant
            || invocation["context"]["principalRef"] != self.principal.as_str()
        {
            Err(StorageError::Conflict(
                "Fresh fixture Recovery and Apply approval denied",
            ))
        } else {
            Ok(())
        }
    }
    fn read_current_target(
        &mut self,
        _store: &DurableStore,
        record: &ProviderUndoRecord,
        _invocation: &Value,
        target: &str,
        max_bytes: u64,
    ) -> StorageResult<Vec<u8>> {
        self.read_grant(&record.principal, &record.scope)?;
        if !record
            .scope
            .resource_ids
            .iter()
            .any(|id| id.as_str() == target)
        {
            return Err(StorageError::Conflict(
                "Undo target is outside the actual source scope",
            ));
        }
        let bytes = self
            .target
            .borrow()
            .targets
            .get(target)
            .cloned()
            .ok_or(StorageError::NotFound("Actual owned undo target"))?;
        if bytes.len() as u64 > max_bytes {
            return Err(StorageError::InvalidInput(
                "Actual target read exceeded its byte budget".into(),
            ));
        }
        Ok(bytes)
    }
}

fn capture_pending(
    fixture: &mut Fixture,
    rpc: &TestUndoRpc,
    host: &mut TestSourceHost,
    report: &Value,
) -> AppResult<ProviderUndoRecord> {
    let principal = fixture.principal.clone();
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    fixture
        .app()
        .capture_provider_undo_record(
            &principal,
            rpc,
            host,
            &operation,
            &StepId::new("write-first").unwrap(),
        )?
        .ok_or_else(|| {
            AppError::new(
                "RECOVERY_EXPIRED",
                "Actual undo source did not provide material",
            )
        })
}

fn undo_request(report: &Value) -> Value {
    let mut request = Fixture::query(report);
    request["mode"] = json!("provider_undo");
    request
}

fn undo_plan(fixture: &mut Fixture, rpc: &TestUndoRpc, report: &Value) -> AppResult<Value> {
    let principal = fixture.principal.clone();
    fixture
        .app()
        .provider_undo_plan(&principal, &undo_request(report), rpc)
}

fn retain_actual_settlement(
    fixture: &mut Fixture,
    plan: &Value,
    report: &Value,
    associate_after: bool,
) -> BlobRef {
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let step = StepId::new("write-first").unwrap();
    let record = fixture.store.operation(&operation).unwrap();
    let invocation = fixture.store.stored_invocation(&operation, &step).unwrap();
    fixture.target.borrow_mut().observer_available = true;
    let observed = fixture
        .observer
        .readback(&invocation, &record.scope)
        .unwrap();
    let states = fixture
        .app()
        .retain_undo_after_targets(&operation, &plan["steps"][0], &invocation, &observed)
        .unwrap();
    let raw = fixture
        .store
        .put_blob(&encode_json(&observed.evidence).unwrap())
        .unwrap();
    let mut envelope = json!({"kind":"independent_readback","effect":observed.effect,"settled":observed.settled,
        "sourceRefs":[raw],"afterStates":states});
    for field in [
        "stepId",
        "invocationId",
        "bindingId",
        "contextDigest",
        "implementationDigest",
        "argumentsDigest",
    ] {
        envelope[field] = invocation[field].clone();
    }
    let body = fixture
        .store
        .put_blob(&encode_json(&envelope).unwrap())
        .unwrap();
    let mut sources = vec![body.clone(), raw];
    if associate_after {
        sources.extend(states.iter().map(|state| state.after.clone()));
    }
    let summary = fixture
        .store
        .put_blob(
            &encode_json(&json!({"kind":"independent_readback_summary",
        "stepId":step,"invocationId":invocation["invocationId"],"effect":observed.effect,
        "settled":true,"readbackBlob":body,"sourceRefs":sources}))
            .unwrap(),
        )
        .unwrap();
    fixture
        .store
        .append_operation_summary(&operation, &summary, &sources)
        .unwrap();
    fixture
        .store
        .record_observation(
            &operation,
            &step,
            StepObservation {
                dispatch: DispatchEvidence::Observed,
                effect: observed.effect,
                further_effects_possible: false,
                provider_receipt: None,
                observation_refs: vec![body.clone()],
                finished: true,
            },
        )
        .unwrap();
    fixture
        .store
        .finish_operation(
            &operation,
            if fixture.target.borrow().fail_on_dispatch.is_some() {
                OperationState::Partial
            } else {
                OperationState::Succeeded
            },
        )
        .unwrap();
    body
}

#[test]
fn app_provider_undo_pending_material_survives_restart_and_requires_actual_associated_settlement() {
    let mut fixture = undo_source_fixture(true, false);
    fixture.target.borrow_mut().observer_available = false;
    let plan = fixture.plan();
    let source_report = fixture.apply(&plan, "pending-undo-source").unwrap();
    let rpc = TestUndoRpc::from_authenticated_fixture(&fixture);
    let mut host = TestSourceHost::actual_source(&mut fixture, &source_report, &rpc);
    let pending = capture_pending(&mut fixture, &rpc, &mut host, &source_report).unwrap();
    assert_eq!(pending.state, UndoRecordState::Pending);
    assert!(pending.after_states.is_empty());
    assert!(pending.settled_observation.is_none());
    assert_eq!(host.inspections, 1);
    assert!(
        undo_plan(&mut fixture, &rpc, &source_report).is_err(),
        "provider response and receipt alone cannot promote material"
    );
    fixture.store.collect_orphan_blobs(1000).unwrap();
    let mut fixture = fixture.reopen();
    host.closed = true;
    let mut authority = TestUndoAuthority::actual_source(&fixture, &source_report);
    let restored_pending = durable_undo::provider_undo_record(
        &fixture.store,
        &rpc,
        &mut authority,
        &pending.record_id,
    )
    .unwrap();
    assert_eq!(json!(restored_pending), json!(pending));
    let observation = retain_actual_settlement(&mut fixture, &plan, &source_report, true);
    let undo = undo_plan(&mut fixture, &rpc, &source_report).unwrap();
    let available = durable_undo::provider_undo_record(
        &fixture.store,
        &rpc,
        &mut authority,
        &pending.record_id,
    )
    .unwrap();
    assert_eq!(available.state, UndoRecordState::Available);
    assert_eq!(available.settled_observation.as_ref(), Some(&observation));
    assert_eq!(available.after_states.len(), 1);
    assert_eq!(
        fixture
            .store
            .read_blob(available.after_states[0].before.as_ref().unwrap())
            .unwrap(),
        b"before"
    );
    assert_eq!(
        fixture
            .store
            .read_blob(&available.after_states[0].after)
            .unwrap(),
        b"after-first"
    );
    assert_ne!(undo["planId"], plan["planId"]);
    assert_eq!(
        undo["steps"][0]["arguments"]["sourceInvocationId"],
        json!(pending.source_invocation_id)
    );
    assert_eq!(
        undo["preconditions"][0]["expected"],
        available.after_states[0].after.digest.as_str()
    );
    assert_eq!(undo["approvalRequirement"], "explicit_approval");
    assert_eq!(
        host.inspections, 1,
        "planning uses retained material without reopening the closed source host"
    );
    assert_eq!(
        fixture.target.borrow().dispatches,
        1,
        "undo planning is effect-free"
    );
    fixture.store.collect_orphan_blobs(1000).unwrap();
    let fixture = fixture.reopen();
    assert_eq!(
        json!(
            durable_undo::provider_undo_record(
                &fixture.store,
                &rpc,
                &mut authority,
                &available.record_id
            )
            .unwrap()
        ),
        json!(available)
    );
    assert_eq!(
        fixture.store.read_blob(&observation).unwrap(),
        encode_json(&parse_json(&fixture.store.read_blob(&observation).unwrap()).unwrap()).unwrap()
    );
    assert_eq!(
        fixture
            .store
            .plan(
                &decode(&undo["planId"]).unwrap(),
                &decode(&undo["planHash"]).unwrap()
            )
            .unwrap(),
        undo
    );
}

#[test]
fn app_provider_undo_rejects_after_blob_pin_without_original_summary_source_association() {
    let mut fixture = undo_source_fixture(true, false);
    fixture.target.borrow_mut().observer_available = false;
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "undo-missing-association").unwrap();
    let rpc = TestUndoRpc::from_authenticated_fixture(&fixture);
    let mut host = TestSourceHost::actual_source(&mut fixture, &report, &rpc);
    let pending = capture_pending(&mut fixture, &rpc, &mut host, &report).unwrap();
    retain_actual_settlement(&mut fixture, &plan, &report, false);
    assert_eq!(
        undo_plan(&mut fixture, &rpc, &report).unwrap_err().code,
        "RECOVERY_EXPIRED"
    );
    let mut authority = TestUndoAuthority::actual_source(&fixture, &report);
    assert_eq!(
        durable_undo::provider_undo_record(
            &fixture.store,
            &rpc,
            &mut authority,
            &pending.record_id
        )
        .unwrap()
        .state,
        UndoRecordState::Pending
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
}

#[test]
fn app_provider_undo_retains_acquired_pending_truth_when_rpc_cancelled_before_release() {
    let mut fixture = undo_source_fixture(true, false);
    fixture.target.borrow_mut().observer_available = false;
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "undo-cancelled-capture").unwrap();
    let rpc = TestUndoRpc::from_authenticated_fixture(&fixture);
    let mut host = TestSourceHost::actual_source(&mut fixture, &report, &rpc);
    host.cancel_after_receipt = true;
    assert!(capture_pending(&mut fixture, &rpc, &mut host, &report).is_err());
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let materials: Vec<Value> = fixture
        .store
        .operation_summaries(&operation)
        .unwrap()
        .iter()
        .map(|blob| parse_json(&fixture.store.read_blob(blob).unwrap()).unwrap())
        .filter(|value| value["kind"] == "provider_undo_material")
        .collect();
    assert_eq!(
        materials.len(),
        1,
        "caller cancellation cannot discard an acquired original receipt"
    );
    let record_id: ObjectId = decode(&materials[0]["recordId"]).unwrap();
    fixture.store.collect_orphan_blobs(1000).unwrap();
    let fixture = fixture.reopen();
    rpc.cancelled.set(false);
    let mut authority = TestUndoAuthority::actual_source(&fixture, &report);
    let pending =
        durable_undo::provider_undo_record(&fixture.store, &rpc, &mut authority, &record_id)
            .unwrap();
    assert_eq!(pending.state, UndoRecordState::Pending);
    assert_eq!(pending.receipt, json!(host.material.receipt));
    assert_eq!(host.inspections, 1);
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
}

#[test]
fn app_provider_undo_rejects_expired_epoch_and_manual_target_drift_without_mutation() {
    for case in ["epoch", "drift"] {
        let mut fixture = undo_source_fixture(true, false);
        fixture.target.borrow_mut().observer_available = false;
        let plan = fixture.plan();
        let report = fixture.apply(&plan, "undo-live-conflict").unwrap();
        let rpc = TestUndoRpc::from_authenticated_fixture(&fixture);
        let mut host = TestSourceHost::actual_source(&mut fixture, &report, &rpc);
        let pending = capture_pending(&mut fixture, &rpc, &mut host, &report).unwrap();
        retain_actual_settlement(&mut fixture, &plan, &report, true);
        let expected = if case == "epoch" {
            let mut current = rpc.context.borrow_mut();
            current["environment"]["sessionEpoch"] = json!("new-authenticated-host-generation");
            current["contextDigest"] =
                json!(projected_digest("ExecutionContext", &current).unwrap());
            "RECOVERY_EXPIRED"
        } else {
            fixture
                .target
                .borrow_mut()
                .targets
                .insert(TARGET.into(), b"manual-edit-after-source".to_vec());
            "RECOVERY_CONFLICT"
        };
        assert_eq!(
            undo_plan(&mut fixture, &rpc, &report).unwrap_err().code,
            expected,
            "{case}"
        );
        assert_eq!(fixture.target.borrow().dispatches, 1, "{case}");
        assert_eq!(host.inspections, 1, "{case}");
        let mut authority = TestUndoAuthority::actual_source(&fixture, &report);
        if case == "epoch" {
            *rpc.context.borrow_mut() = fixture.provider.live_context.clone();
            assert_eq!(
                durable_undo::provider_undo_record(
                    &fixture.store,
                    &rpc,
                    &mut authority,
                    &pending.record_id
                )
                .unwrap()
                .state,
                UndoRecordState::Pending
            );
            assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
        } else {
            assert_eq!(
                durable_undo::provider_undo_record(
                    &fixture.store,
                    &rpc,
                    &mut authority,
                    &pending.record_id
                )
                .unwrap()
                .state,
                UndoRecordState::Available
            );
            assert_eq!(
                fixture.target.borrow().targets[TARGET],
                b"manual-edit-after-source"
            );
        }
    }
}

fn reserve_undo_candidate(
    fixture: &mut Fixture,
    rpc: &TestUndoRpc,
    plan: &Value,
    label: &str,
) -> (OperationId, StepId, Value) {
    let operation = OperationId::new(format!("operation-{label}")).unwrap();
    let step: StepId = decode(&plan["steps"][0]["stepId"]).unwrap();
    assert!(matches!(
        fixture
            .store
            .reserve_operation(ReserveOperation {
                operation_id: operation.clone(),
                principal: fixture.principal.clone(),
                project_id: decode(&plan["projectId"]).unwrap(),
                idempotency_key: label.into(),
                plan_id: decode(&plan["planId"]).unwrap(),
                plan_hash: decode(&plan["planHash"]).unwrap(),
                context_id: decode(&plan["contextId"]).unwrap(),
            })
            .unwrap(),
        Reservation::Created(_)
    ));
    let frozen = &plan["steps"][0];
    let context = rpc.context.borrow().clone();
    let invocation = json!({"contractVersion":"0.2.0","invocationId":format!("invocation-{label}"),
        "operationId":operation,"stepId":step,"bindingId":frozen["bindingId"],
        "actionId":frozen["actionId"],"actionContractVersion":frozen["actionContractVersion"],
        "actionDigest":frozen["actionDigest"],"arguments":frozen["arguments"],"context":context,
        "deadlineAt":plan["expiresAt"],"idempotencyKey":label,
        "implementationDigest":frozen["implementationDigest"],
        "argumentsDigest":canonical_digest(&frozen["arguments"]).unwrap(),"contextDigest":context["contextDigest"]});
    validate("Invocation", &invocation).unwrap();
    (operation, step, invocation)
}

#[test]
fn app_undo_intent_atomically_reserves_original_material_and_invocation_once_across_restart() {
    let mut fixture = undo_source_fixture(true, false);
    fixture.target.borrow_mut().observer_available = false;
    let source_plan = fixture.plan();
    let source_report = fixture.apply(&source_plan, "undo-claim-source").unwrap();
    let rpc = TestUndoRpc::from_authenticated_fixture(&fixture);
    let mut host = TestSourceHost::actual_source(&mut fixture, &source_report, &rpc);
    let pending = capture_pending(&mut fixture, &rpc, &mut host, &source_report).unwrap();
    retain_actual_settlement(&mut fixture, &source_plan, &source_report, true);
    let plan = undo_plan(&mut fixture, &rpc, &source_report).unwrap();
    rpc.approve_stored_plan(&fixture.store, &plan);
    let (operation, step, invocation) =
        reserve_undo_candidate(&mut fixture, &rpc, &plan, "undo-first-claim");
    let principal = fixture.principal.clone();
    let capture = fixture
        .app()
        .capture_registered_undo_before(&principal, &rpc, &invocation)
        .unwrap();
    assert_eq!(capture.images.len(), 1);
    assert_eq!(capture.images[0].target, TARGET);
    assert_eq!(capture.images[0].bytes, b"after-first");
    assert_eq!(
        capture.arguments_digest,
        canonical_digest(&invocation["arguments"]).unwrap()
    );
    assert_eq!(
        capture.invocation_id.as_str(),
        invocation["invocationId"].as_str().unwrap()
    );
    let intent = fixture
        .app()
        .dispatch_registered_undo_intent(&principal, &rpc, &operation, &step, &invocation)
        .unwrap()
        .unwrap();
    assert_eq!(intent.dispatch, DispatchEvidence::IntentDurable);
    assert_eq!(
        intent.invocation_id.as_ref().unwrap().as_str(),
        invocation["invocationId"].as_str().unwrap()
    );
    assert_eq!(
        intent.invocation_digest,
        Some(raw_digest(&encode_json(&invocation).unwrap()))
    );
    let mut authority = TestUndoAuthority::actual_source(&fixture, &source_report);
    let reserved = durable_undo::provider_undo_record(
        &fixture.store,
        &rpc,
        &mut authority,
        &pending.record_id,
    )
    .unwrap();
    assert_eq!(
        reserved.state,
        UndoRecordState::Reserved {
            operation_id: operation.clone(),
            step_id: step.clone(),
            invocation_id: decode(&invocation["invocationId"]).unwrap(),
            invocation_digest: raw_digest(&encode_json(&invocation).unwrap()),
        }
    );
    assert_eq!(
        fixture.store.stored_invocation(&operation, &step).unwrap(),
        invocation
    );
    assert_eq!(
        fixture.target.borrow().dispatches,
        1,
        "atomic intent does not dispatch a native undo by itself"
    );
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
    fixture.store.collect_orphan_blobs(1000).unwrap();
    let mut fixture = fixture.reopen();
    host.closed = true;
    assert_eq!(
        fixture.store.stored_invocation(&operation, &step).unwrap(),
        invocation
    );
    let claim = durable_undo::claimed_undo_record(
        &fixture.store,
        &operation,
        &step,
        &decode(&invocation["invocationId"]).unwrap(),
    )
    .unwrap();
    assert_eq!(json!(claim), json!(reserved));
    let original_intent = fixture.store.operation(&operation).unwrap();
    assert!(
        fixture
            .app()
            .dispatch_registered_undo_intent(&principal, &rpc, &operation, &step, &invocation)
            .is_err()
    );
    assert_eq!(
        fixture.store.operation(&operation).unwrap(),
        original_intent
    );
    let (second_operation, second_step, second_invocation) =
        reserve_undo_candidate(&mut fixture, &rpc, &plan, "undo-second-claim");
    assert!(
        fixture
            .app()
            .dispatch_registered_undo_intent(
                &principal,
                &rpc,
                &second_operation,
                &second_step,
                &second_invocation
            )
            .is_err()
    );
    assert_eq!(
        fixture.store.operation(&second_operation).unwrap().steps[0].dispatch,
        DispatchEvidence::NotSent
    );
    assert!(
        fixture
            .store
            .stored_invocation(&second_operation, &second_step)
            .is_err()
    );
    assert_eq!(
        json!(
            durable_undo::provider_undo_record(
                &fixture.store,
                &rpc,
                &mut authority,
                &pending.record_id
            )
            .unwrap()
        ),
        json!(reserved)
    );
    assert_eq!(host.inspections, 1);
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
}

#[test]
fn app_undo_claim_rejects_drift_epoch_cancelled_revoked_apply_forged_arguments_and_unbound_or_wrong_plan()
 {
    for case in [
        "drift",
        "epoch",
        "cancelled",
        "apply_revoked",
        "forged_arguments",
        "unbound_plan",
        "wrong_plan",
    ] {
        let mut fixture = undo_source_fixture(true, false);
        fixture.target.borrow_mut().observer_available = false;
        let source_plan = fixture.plan();
        let report = fixture
            .apply(&source_plan, "undo-claim-negative-source")
            .unwrap();
        let rpc = TestUndoRpc::from_authenticated_fixture(&fixture);
        let mut host = TestSourceHost::actual_source(&mut fixture, &report, &rpc);
        let pending = capture_pending(&mut fixture, &rpc, &mut host, &report).unwrap();
        retain_actual_settlement(&mut fixture, &source_plan, &report, true);
        let mut plan = undo_plan(&mut fixture, &rpc, &report).unwrap();
        if case == "forged_arguments" {
            plan["planId"] = json!("plan-forged-undo-arguments");
            plan["steps"][0]["arguments"]["tokenRecordDigest"] =
                json!(raw_digest(b"caller-selected-undo-token"));
            plan["planHash"] = json!(projected_digest("ExecutionPlan", &plan).unwrap());
            fixture.store.save_plan(&plan).unwrap();
        }
        match case {
            "unbound_plan" => (),
            "wrong_plan" => {
                let other_actual_plan = undo_plan(&mut fixture, &rpc, &report).unwrap();
                assert_ne!(other_actual_plan["planId"], plan["planId"]);
                rpc.approve_stored_plan(&fixture.store, &other_actual_plan);
            }
            _ => rpc.approve_stored_plan(&fixture.store, &plan),
        }
        let (operation, step, invocation) =
            reserve_undo_candidate(&mut fixture, &rpc, &plan, "undo-negative-claim");
        match case {
            "drift" => {
                fixture
                    .target
                    .borrow_mut()
                    .targets
                    .insert(TARGET.into(), b"manual-edit-after-approval".to_vec());
            }
            "epoch" => {
                let mut context = rpc.context.borrow_mut();
                context["environment"]["sessionEpoch"] = json!("new-host-epoch-after-plan");
                context["contextDigest"] =
                    json!(projected_digest("ExecutionContext", &context).unwrap());
            }
            "cancelled" => rpc.cancelled.set(true),
            "apply_revoked" => fixture.target.borrow_mut().apply_grant = false,
            "forged_arguments" | "unbound_plan" | "wrong_plan" => (),
            _ => unreachable!(),
        }
        let principal = fixture.principal.clone();
        assert!(
            fixture
                .app()
                .dispatch_registered_undo_intent(&principal, &rpc, &operation, &step, &invocation)
                .is_err(),
            "{case}"
        );
        assert_eq!(
            fixture.store.operation(&operation).unwrap().steps[0].dispatch,
            DispatchEvidence::NotSent,
            "{case}"
        );
        assert!(
            fixture.store.stored_invocation(&operation, &step).is_err(),
            "{case}"
        );
        rpc.cancelled.set(false);
        *rpc.context.borrow_mut() = fixture.provider.live_context.clone();
        let mut authority = TestUndoAuthority::actual_source(&fixture, &report);
        assert_eq!(
            durable_undo::provider_undo_record(
                &fixture.store,
                &rpc,
                &mut authority,
                &pending.record_id
            )
            .unwrap()
            .state,
            UndoRecordState::Available,
            "{case}"
        );
        assert_eq!(fixture.target.borrow().dispatches, 1, "{case}");
        assert_eq!(host.inspections, 1, "{case}");
        assert_eq!(
            fixture.target.borrow().targets[TARGET],
            if case == "drift" {
                b"manual-edit-after-approval".as_slice()
            } else {
                b"after-first".as_slice()
            },
            "{case}"
        );
    }
}

#[test]
fn app_undo_capture_requires_authenticated_fixture_principal_and_current_rpc_budget() {
    for case in ["wrong_principal", "cancelled", "forged_receipt"] {
        let mut fixture = undo_source_fixture(true, false);
        fixture.target.borrow_mut().observer_available = false;
        let plan = fixture.plan();
        let report = fixture.apply(&plan, "undo-authenticated-source").unwrap();
        let mut rpc = TestUndoRpc::from_authenticated_fixture(&fixture);
        let mut host = TestSourceHost::actual_source(&mut fixture, &report, &rpc);
        match case {
            "wrong_principal" => rpc.principal = PrincipalId::new("principal-raw-caller").unwrap(),
            "cancelled" => rpc.cancelled.set(true),
            "forged_receipt" => {
                host.material.receipt.source_arguments_digest =
                    raw_digest(b"different-actual-source-arguments");
                let mut projection = json!(host.material.receipt);
                projection
                    .as_object_mut()
                    .unwrap()
                    .remove("tokenRecordDigest");
                host.material.receipt.token_record_digest = canonical_digest(&projection).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            capture_pending(&mut fixture, &rpc, &mut host, &report).is_err(),
            "{case}"
        );
        let operation: OperationId = decode(&report["operationId"]).unwrap();
        assert!(
            !fixture
                .store
                .operation_summaries(&operation)
                .unwrap()
                .iter()
                .any(
                    |blob| parse_json(&fixture.store.read_blob(blob).unwrap()).unwrap()["kind"]
                        == "provider_undo_material"
                ),
            "{case}"
        );
        assert_eq!(
            host.inspections,
            usize::from(case == "forged_receipt"),
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
fn app_provider_undo_promotes_settled_failed_source_without_erasing_original_failure_or_effects() {
    let mut fixture = undo_source_fixture(true, true);
    fixture.target.borrow_mut().observer_available = false;
    let plan = fixture.plan();
    let initial = fixture.apply(&plan, "undo-original-failure").unwrap();
    assert_eq!(initial["result"]["providerStatusCounts"]["failed"], 1);
    let rpc = TestUndoRpc::from_authenticated_fixture(&fixture);
    let mut host = TestSourceHost::actual_source(&mut fixture, &initial, &rpc);
    let pending = capture_pending(&mut fixture, &rpc, &mut host, &initial).unwrap();
    retain_actual_settlement(&mut fixture, &plan, &initial, true);
    let before_undo_plan = fixture.get(&initial).unwrap();
    assert_eq!(before_undo_plan["state"], "partial");
    let undo = undo_plan(&mut fixture, &rpc, &initial).unwrap();
    let mut authority = TestUndoAuthority::actual_source(&fixture, &initial);
    let available = durable_undo::provider_undo_record(
        &fixture.store,
        &rpc,
        &mut authority,
        &pending.record_id,
    )
    .unwrap();
    assert_eq!(available.state, UndoRecordState::Available);
    assert_eq!(
        fixture
            .store
            .read_blob(available.after_states[0].before.as_ref().unwrap())
            .unwrap(),
        b"before"
    );
    assert_eq!(
        fixture
            .store
            .read_blob(&available.after_states[0].after)
            .unwrap(),
        b"after-first"
    );
    assert_eq!(
        undo["steps"][0]["arguments"]["sourceOperationId"],
        initial["operationId"]
    );
    assert_eq!(
        fixture.get(&initial).unwrap(),
        before_undo_plan,
        "undo availability neither changes source failure nor reports a rollback"
    );
    assert_eq!(
        before_undo_plan["result"]["providerStatusCounts"]["failed"],
        1
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
}

#[test]
fn app_provider_undo_keeps_material_without_original_before_but_cannot_plan_restoration() {
    let mut fixture = undo_source_fixture(false, false);
    fixture.target.borrow_mut().observer_available = false;
    let plan = fixture.plan();
    let report = fixture
        .apply(&plan, "undo-without-original-before")
        .unwrap();
    let rpc = TestUndoRpc::from_authenticated_fixture(&fixture);
    let mut host = TestSourceHost::actual_source(&mut fixture, &report, &rpc);
    let pending = capture_pending(&mut fixture, &rpc, &mut host, &report).unwrap();
    retain_actual_settlement(&mut fixture, &plan, &report, true);
    assert_eq!(
        undo_plan(&mut fixture, &rpc, &report).unwrap_err().code,
        "RECONCILIATION_INSUFFICIENT"
    );
    let mut authority = TestUndoAuthority::actual_source(&fixture, &report);
    let available = durable_undo::provider_undo_record(
        &fixture.store,
        &rpc,
        &mut authority,
        &pending.record_id,
    )
    .unwrap();
    assert_eq!(available.state, UndoRecordState::Available);
    assert!(available.after_states[0].before.is_none());
    fixture.store.collect_orphan_blobs(1000).unwrap();
    let mut fixture = fixture.reopen();
    assert_eq!(
        json!(
            durable_undo::provider_undo_record(
                &fixture.store,
                &rpc,
                &mut authority,
                &pending.record_id
            )
            .unwrap()
        ),
        json!(available)
    );
    assert_eq!(
        undo_plan(&mut fixture, &rpc, &report).unwrap_err().code,
        "RECONCILIATION_INSUFFICIENT"
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
}

fn dispatch_owned_host_restore(
    fixture: &mut Fixture,
    host: &TestSourceHost,
    invocation: &Value,
    partial: bool,
) -> Value {
    // This is the trusted owned fake host's private generation history. A raw
    // receipt or successful result never manufactures a mutation grant: the
    // actual original material must first have the matching durable claim.
    let operation: OperationId = decode(&invocation["operationId"]).unwrap();
    let step: StepId = decode(&invocation["stepId"]).unwrap();
    let id: InvocationId = decode(&invocation["invocationId"]).unwrap();
    let claim = durable_undo::claimed_undo_record(&fixture.store, &operation, &step, &id).unwrap();
    assert_eq!(claim.receipt, json!(host.material.receipt));
    assert_eq!(
        fixture.store.stored_invocation(&operation, &step).unwrap(),
        *invocation
    );
    let source_id = claim.source_invocation_id.as_str();
    let mut target = fixture.target.borrow_mut();
    assert!(
        !target.invocations.contains_key(id.as_str()),
        "the fake host never retransmits an undo invocation"
    );
    let actual_private_before = target.invocations[source_id].before.clone();
    assert_eq!(
        fixture
            .store
            .read_blob(claim.after_states[0].before.as_ref().unwrap())
            .unwrap(),
        actual_private_before
    );
    let before = target.targets[TARGET].clone();
    let after = if partial {
        b"partial-owned-undo".to_vec()
    } else {
        actual_private_before
    };
    target.targets.insert(TARGET.into(), after.clone());
    target
        .invocations
        .insert(id.as_str().into(), TargetChange { before, after });
    target.dispatches += 1;
    target.write_dispatches += 1;
    json!({"contractVersion":"0.2.0","status":"complete","data":{"restored":true},
        "effects":"recorded","diagnostics":[],"artifacts":[]})
}

struct CallbackCauseAuthority<'a>(&'a mut Authority);
impl AuthorityPort for CallbackCauseAuthority<'_> {
    fn authorize(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectId,
        access: Access,
        context: Option<&Value>,
        plan: Option<&Value>,
    ) -> AppResult<()> {
        if access == Access::ObserveOperation && !self.0.target.borrow().observe_grant {
            return Err(AppError::caused_by(
                "PERMISSION_REQUIRED",
                "Current owned observer grant was revoked",
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "owned undo callback authorization cause",
                ),
            ));
        }
        self.0.authorize(principal, project, access, context, plan)
    }
    fn authorize_operation(
        &mut self,
        principal: &PrincipalId,
        record: &OperationRecord,
        access: Access,
    ) -> AppResult<()> {
        if access == Access::ObserveOperation && !self.0.target.borrow().observe_grant {
            return self.authorize(principal, &record.project_id, access, None, None);
        }
        self.0.authorize_operation(principal, record, access)
    }
}

#[test]
fn app_undo_independent_verification_uses_claimed_original_before_and_preserves_partial_or_denied_results()
 {
    for case in ["restored", "partial", "wrong_pins", "observe_revoked"] {
        let mut fixture = undo_source_fixture(true, false);
        fixture.target.borrow_mut().observer_available = false;
        let source_plan = fixture.plan();
        let source_report = fixture.apply(&source_plan, "undo-verified-source").unwrap();
        let rpc = TestUndoRpc::from_authenticated_fixture(&fixture);
        let mut host = TestSourceHost::actual_source(&mut fixture, &source_report, &rpc);
        let pending = capture_pending(&mut fixture, &rpc, &mut host, &source_report).unwrap();
        retain_actual_settlement(&mut fixture, &source_plan, &source_report, true);
        let source_id: OperationId = decode(&source_report["operationId"]).unwrap();
        let immutable_source = fixture.store.operation(&source_id).unwrap();
        let plan = undo_plan(&mut fixture, &rpc, &source_report).unwrap();
        rpc.approve_stored_plan(&fixture.store, &plan);
        let (operation, step, invocation) =
            reserve_undo_candidate(&mut fixture, &rpc, &plan, "undo-verify-claim");
        let principal = fixture.principal.clone();
        let capture = fixture
            .app()
            .capture_registered_undo_before(&principal, &rpc, &invocation)
            .unwrap();
        assert_eq!(capture.images[0].bytes, b"after-first");
        fixture
            .app()
            .dispatch_registered_undo_intent(&principal, &rpc, &operation, &step, &invocation)
            .unwrap()
            .unwrap();
        let response =
            dispatch_owned_host_restore(&mut fixture, &host, &invocation, case == "partial");
        validate("ProviderResult", &response).unwrap();
        assert_eq!(response["status"], "complete");
        assert_eq!(
            response["data"]["restored"], true,
            "a provider complete assertion is not independent restoration evidence"
        );
        let scope = fixture.store.operation(&operation).unwrap().scope;
        let mut observed = fixture.observer.readback(&invocation, &scope).unwrap();
        if case == "wrong_pins" {
            observed.arguments_digest = raw_digest(b"different-undo-observation");
        }
        if case == "observe_revoked" {
            fixture.target.borrow_mut().observe_grant = false;
        }
        let verified = if case == "observe_revoked" {
            let mut authority = CallbackCauseAuthority(&mut fixture.authority);
            let mut app = Application {
                store: &mut fixture.store,
                authority: &mut authority,
                planner: &mut fixture.planner,
                provider: &mut fixture.provider,
                observer: &mut fixture.observer,
                ids: &mut fixture.ids,
                clock: &fixture.clock,
            };
            app.verify_provider_undo_readback(&principal, &rpc, &invocation, observed)
        } else {
            fixture
                .app()
                .verify_provider_undo_readback(&principal, &rpc, &invocation, observed)
        };
        if case == "wrong_pins" || case == "observe_revoked" {
            let error = verified.unwrap_err();
            if case == "observe_revoked" {
                assert_eq!(error.code, "PERMISSION_REQUIRED");
                let cause = std::error::Error::source(&error)
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .expect(
                        "the actual callback cause crosses the storage adapter without replacement",
                    );
                assert_eq!(cause.kind(), std::io::ErrorKind::PermissionDenied);
                assert_eq!(cause.to_string(), "owned undo callback authorization cause");
            } else {
                assert_eq!(error.code, "RECONCILIATION_INSUFFICIENT");
            }
        } else {
            let verified = verified.unwrap();
            assert!(verified.settled, "{case}");
            assert_eq!(verified.evidence["restored"], case == "restored", "{case}");
            assert_eq!(
                verified.effect,
                if case == "restored" {
                    EffectEvidence::CompleteConfirmed
                } else {
                    EffectEvidence::SomeConfirmed
                },
                "{case}"
            );
            assert_eq!(verified.direct_changes.len(), 1);
            assert_eq!(verified.direct_changes[0].before, capture.images[0].bytes);
            assert_eq!(
                verified.direct_changes[0].after,
                fixture.target.borrow().targets[TARGET]
            );
            assert_eq!(
                verified.evidence["sourceOperationId"],
                source_report["operationId"]
            );
            assert_eq!(verified.evidence["undoRecordId"], json!(pending.record_id));
        }
        assert_eq!(
            fixture.store.operation(&source_id).unwrap(),
            immutable_source,
            "{case}"
        );
        assert_eq!(fixture.target.borrow().dispatches, 2, "{case}");
        fixture.target.borrow_mut().observe_grant = true;
        let mut authority = TestUndoAuthority::actual_source(&fixture, &source_report);
        assert!(
            matches!(
                durable_undo::provider_undo_record(
                    &fixture.store,
                    &rpc,
                    &mut authority,
                    &pending.record_id
                )
                .unwrap()
                .state,
                UndoRecordState::Reserved { .. }
            ),
            "{case}: observation never releases the unique claim"
        );
        let actual = fixture.target.borrow().targets[TARGET].clone();
        fixture.store.collect_orphan_blobs(1000).unwrap();
        let fixture = fixture.reopen();
        assert_eq!(
            fixture.store.stored_invocation(&operation, &step).unwrap(),
            invocation
        );
        assert_eq!(fixture.target.borrow().targets[TARGET], actual, "{case}");
        assert_eq!(fixture.target.borrow().dispatches, 2, "{case}");
    }
}

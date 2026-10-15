//! Child of undo_tests covering the common trusted undo execution bundle.
//! These cases use the existing owned SQLite/CAS fixture. A trusted
//! in-process host owns actual source/job history; raw invocation IDs never
//! authenticate a request or recreate an original host session.
use super::*;
use crate::undo_context::{UndoContextPort, UndoExecutionContext};
use crate::undo_provider::{InspectedUndoRoles, UndoActionRole, UndoExecutionPort};
use mmmm_runtime::storage::undo::RegisteredUndoRoute;

struct SealedBundleRpc {
    authenticated: TestUndoRpc,
    approved: Option<(PlanId, Sha256Digest)>,
}
impl UndoRpcContext for SealedBundleRpc {
    fn check(&self) -> StorageResult<()> {
        self.authenticated.check()
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.authenticated.authenticated_principal()
    }
    fn current_context(&self) -> StorageResult<Value> {
        self.authenticated.current_context()
    }
    // The additive production seal is intentionally fail-closed. An Observe
    // request or a current principal alone cannot approve a new dispatch.
    fn check_dispatch_plan(&self, plan: &PlanId, hash: &Sha256Digest) -> StorageResult<()> {
        self.check()?;
        if self.approved.as_ref() == Some(&(plan.clone(), hash.clone())) {
            Ok(())
        } else {
            Err(StorageError::Conflict("Actual approved undo plan seal"))
        }
    }
}

struct BundleContexts {
    principal: PrincipalId,
    current: Rc<RefCell<Value>>,
    cancelled: Rc<Cell<bool>>,
    approved: Option<(PlanId, Sha256Digest)>,
    opens: usize,
    offline: bool,
    unbound_dispatch: bool,
}
impl UndoContextPort for BundleContexts {
    fn open(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: &ContextId,
        approved: Option<(&PlanId, &Sha256Digest)>,
    ) -> AppResult<Box<dyn UndoRpcContext + 'static>> {
        self.opens += 1;
        if self.offline {
            return Err(AppError::new(
                "RECOVERY_EXPIRED",
                "Actual owned game session is offline",
            ));
        }
        assert_eq!(principal, &self.principal);
        assert_eq!(
            context.as_str(),
            self.current.borrow()["contextId"].as_str().unwrap()
        );
        let sealed = match approved {
            Some((id, hash)) => {
                let actual = store.plan(id, hash).unwrap();
                assert_eq!(actual["planId"], id.as_str());
                assert_eq!(actual["planHash"], hash.as_str());
                if self.approved.as_ref() != Some(&(id.clone(), hash.clone())) {
                    return Err(AppError::new(
                        "PERMISSION_REQUIRED",
                        "New frozen plan was not actually approved",
                    ));
                }
                (!self.unbound_dispatch).then(|| (id.clone(), hash.clone()))
            }
            None => None,
        };
        Ok(Box::new(SealedBundleRpc {
            authenticated: TestUndoRpc {
                principal: self.principal.clone(),
                context: self.current.clone(),
                cancelled: self.cancelled.clone(),
                checks: Cell::new(0),
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
                approved_plan: RefCell::new(None),
            },
            approved: sealed,
        }))
    }
}

#[derive(Clone)]
struct OwnedSourceJob {
    invocation: Value,
    material: InspectedHostUndoMaterial,
    change: TargetChange,
}
#[derive(Clone)]
struct OwnedRecoverJob {
    invocation: Value,
    response: Value,
    changed: bool,
    settled: bool,
    before: Vec<u8>,
    after: Vec<u8>,
}
#[derive(Clone, Copy)]
enum RecoverBehavior {
    Restore,
    FailBeforeMutation,
}
struct BundleHostState {
    principal: PrincipalId,
    original_context: Value,
    source_descriptor: Value,
    registration: HostUndoRegistration,
    target: SharedTarget,
    session_open: Cell<bool>,
    source_jobs: RefCell<BTreeMap<String, OwnedSourceJob>>,
    recover_jobs: RefCell<BTreeMap<String, OwnedRecoverJob>>,
    behavior: Cell<RecoverBehavior>,
    role_inspections: Cell<usize>,
    receipt_inspections: Cell<usize>,
    recover_dispatches: Cell<usize>,
    recover_observations: Cell<usize>,
    intent_calls: Cell<usize>,
    reject_intent: Cell<bool>,
    intent_operation: RefCell<Option<OperationId>>,
}
impl BundleHostState {
    fn check_session(&self, principal: &PrincipalId, context: &Value) -> AppResult<()> {
        if !self.session_open.get() || principal != &self.principal {
            return Err(AppError::new(
                "RECOVERY_EXPIRED",
                "Original actual host session is closed",
            ));
        }
        let project: ProjectId = decode(&self.original_context["projectId"])?;
        check_undo_context(principal, &project, &self.original_context, context)
    }
    fn route(&self) -> RegisteredUndoRoute {
        RegisteredUndoRoute {
            source_binding_id: self.registration.binding_id.clone(),
            source_action: self.source_descriptor.clone(),
            undo_binding_id: self.registration.binding_id.clone(),
            undo_action: self.registration.undo_action.clone(),
            provider_origin: self.registration.provider_origin.clone(),
        }
    }
    fn is_undo(&self, value: &Value) -> bool {
        value["actionId"] == self.registration.undo_action["actionId"]
    }
    fn material_for_actual_source(&self, invocation: &Value) -> InspectedHostUndoMaterial {
        let id = invocation["invocationId"].as_str().unwrap();
        assert!(self.target.borrow().invocations.contains_key(id));
        let registration = self.registration.clone();
        assert_eq!(
            invocation["actionDigest"],
            registration.source_action_digest.as_str()
        );
        let mut receipt = HostUndoReceipt {
            contract_version: "0.2.0".into(),
            token_record_id: ObjectId::new(format!("undo-bundle-{id}")).unwrap(),
            principal_ref: self.principal.clone(),
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
            private_token_sha256: canonical_digest(&json!({"actualOwnedGeneration":id})).unwrap(),
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
}

struct BundleHost(Rc<BundleHostState>);
impl UndoMaterialPort for BundleHost {
    fn inspect_undo_registration_with_store(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        step: &Value,
        current: &Value,
    ) -> AppResult<Option<HostUndoRegistration>> {
        self.0.check_session(principal, current)?;
        assert_eq!(step["actionId"], self.0.source_descriptor["actionId"]);
        Ok(Some(self.0.registration.clone()))
    }
    fn inspect_source_undo_with_store(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        invocation: &Value,
        current: &Value,
    ) -> AppResult<Option<InspectedHostUndoMaterial>> {
        self.0.check_session(principal, current)?;
        self.0
            .receipt_inspections
            .set(self.0.receipt_inspections.get() + 1);
        let operation: OperationId = decode(&invocation["operationId"])?;
        let step: StepId = decode(&invocation["stepId"])?;
        assert_eq!(
            store.stored_invocation(&operation, &step).unwrap(),
            *invocation
        );
        let jobs = self.0.source_jobs.borrow();
        let owned = jobs
            .get(invocation["invocationId"].as_str().unwrap())
            .ok_or_else(|| {
                AppError::new(
                    "RECOVERY_EXPIRED",
                    "Raw caller identity has no actual original source job",
                )
            })?;
        assert_eq!(owned.invocation, *invocation);
        Ok(Some(owned.material.clone()))
    }
}
impl UndoExecutionPort for BundleHost {
    fn inspect_undo_roles_with_store(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        step: &Value,
        current: &Value,
    ) -> AppResult<InspectedUndoRoles> {
        self.0.check_session(principal, current)?;
        self.0
            .role_inspections
            .set(self.0.role_inspections.get() + 1);
        let role = if self.0.is_undo(step) {
            UndoActionRole::RecoveryOnly
        } else if step["actionId"] == self.0.source_descriptor["actionId"]
            && step["recovery"] == "provider_undo"
        {
            UndoActionRole::Source
        } else {
            UndoActionRole::Ordinary
        };
        Ok(InspectedUndoRoles {
            selected_role: role,
            routes: if role == UndoActionRole::Ordinary {
                vec![]
            } else {
                vec![self.0.route()]
            },
        })
    }
    fn observe_registered_undo_job_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        claimed: &ProviderUndoRecord,
        scope: &WriteScope,
    ) -> AppResult<ReadbackEvidence> {
        self.0
            .check_session(&claimed.principal, &invocation["context"])?;
        let operation: OperationId = decode(&invocation["operationId"])?;
        let step: StepId = decode(&invocation["stepId"])?;
        let id: InvocationId = decode(&invocation["invocationId"])?;
        let actual_claim = durable_undo::claimed_undo_record(store, &operation, &step, &id)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
        assert_eq!(json!(actual_claim), json!(claimed));
        assert_eq!(scope, &claimed.scope);
        let jobs = self.0.recover_jobs.borrow();
        let job = jobs.get(id.as_str()).ok_or_else(|| {
            AppError::new("RECOVERY_EXPIRED", "Actual original undo job is absent")
        })?;
        assert_eq!(job.invocation, *invocation);
        self.0
            .recover_observations
            .set(self.0.recover_observations.get() + 1);
        let actual = self.0.target.borrow().targets[TARGET].clone();
        if actual != job.after {
            return Err(AppError::new(
                "TARGET_DRIFT",
                "Undo job target was edited after its actual effect",
            ));
        }
        Ok(ReadbackEvidence {
            invocation_id: id,
            binding_id: decode(&invocation["bindingId"]).unwrap(),
            context_digest: decode(&invocation["contextDigest"]).unwrap(),
            implementation_digest: decode(&invocation["implementationDigest"]).unwrap(),
            arguments_digest: decode(&invocation["argumentsDigest"]).unwrap(),
            effect: if job.changed {
                EffectEvidence::CompleteConfirmed
            } else {
                EffectEvidence::NoneConfirmed
            },
            settled: job.settled,
            evidence: json!({"actualOriginalJob":invocation["invocationId"],"actualDigest":raw_digest(&actual),
                "jobStatus":job.response["status"],"failedBeforeMutation":!job.changed}),
            direct_changes: if job.changed {
                vec![DirectChange {
                    target: TARGET.into(),
                    before: job.before.clone(),
                    after: actual,
                }]
            } else {
                vec![]
            },
        })
    }
}

struct BundleProvider<'a> {
    ordinary: &'a mut Provider,
    host: Rc<BundleHostState>,
}
impl ProviderPort for BundleProvider<'_> {
    fn context(&mut self, principal: &PrincipalId, context: &ContextId) -> AppResult<Value> {
        self.ordinary.context(principal, context)
    }
    fn action_descriptor(&mut self, step: &Value, context: &Value) -> AppResult<Value> {
        self.ordinary.action_descriptor(step, context)
    }
    fn observe_precondition(
        &mut self,
        condition: &Value,
        context: &Value,
    ) -> AppResult<Sha256Digest> {
        self.ordinary.observe_precondition(condition, context)
    }
    fn verify_dependencies(&mut self, pins: &[Value], context: &Value) -> AppResult<()> {
        self.ordinary.verify_dependencies(pins, context)
    }
    fn dispatch(&mut self, _invocation: &Value) -> AppResult<Value> {
        panic!("Bundle dispatch must pass its actual unique durable store")
    }
    fn poll(&mut self, _invocation: &Value, _receipt: Option<&str>) -> AppResult<Option<Value>> {
        panic!("Bundle observation must pass its actual unique durable store")
    }
    fn request_cancel(&mut self, invocation: &Value, receipt: Option<&str>) -> AppResult<()> {
        self.ordinary.request_cancel(invocation, receipt)
    }
    fn persist_dispatch_intent_with_store(
        &mut self,
        store: &mut DurableStore,
        original_operation: &OperationId,
        original_step: &StepId,
        original_invocation: &Value,
        resolution_witness: Option<&BlobRef>,
    ) -> AppResult<mmmm_runtime::storage::StepRecord> {
        assert!(
            !self.host.is_undo(original_invocation),
            "Registered undo must retain its separate atomic claim"
        );
        assert_eq!(
            json!(original_operation),
            original_invocation["operationId"]
        );
        assert_eq!(json!(original_step), original_invocation["stepId"]);
        self.host.intent_calls.set(self.host.intent_calls.get() + 1);
        *self.host.intent_operation.borrow_mut() = Some(original_operation.clone());
        if self.host.reject_intent.get() {
            return Err(AppError::storage(
                "DISPATCH_REJECTED",
                StorageError::Conflict("Fixture protected dispatch claim rejected"),
            ));
        }
        let record = self.ordinary.persist_dispatch_intent_with_store(
            store,
            original_operation,
            original_step,
            original_invocation,
            resolution_witness,
        )?;
        assert_eq!(record.dispatch, DispatchEvidence::IntentDurable);
        assert_eq!(
            store
                .stored_invocation(original_operation, original_step)
                .unwrap(),
            *original_invocation
        );
        Ok(record)
    }
    fn dispatch_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
    ) -> AppResult<Value> {
        let operation: OperationId = decode(&invocation["operationId"])?;
        let step: StepId = decode(&invocation["stepId"])?;
        let id: InvocationId = decode(&invocation["invocationId"])?;
        assert_eq!(
            store.stored_invocation(&operation, &step).unwrap(),
            *invocation
        );
        if !self.host.is_undo(invocation) {
            let response = self.ordinary.dispatch_with_store(store, invocation);
            if invocation["actionId"] == self.host.source_descriptor["actionId"]
                && self.host.source_descriptor["recovery"] == "provider_undo"
            {
                let change = self.host.target.borrow().invocations[id.as_str()].clone();
                let material = self.host.material_for_actual_source(invocation);
                assert!(
                    self.host
                        .source_jobs
                        .borrow_mut()
                        .insert(
                            id.as_str().into(),
                            OwnedSourceJob {
                                invocation: invocation.clone(),
                                material,
                                change,
                            }
                        )
                        .is_none()
                );
            }
            return response;
        }
        self.host
            .check_session(&self.host.principal, &invocation["context"])?;
        let claimed = durable_undo::claimed_undo_record(store, &operation, &step, &id)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
        assert!(matches!(claimed.state, UndoRecordState::Reserved { .. }));
        assert_eq!(
            claimed.source_invocation_id.as_str(),
            invocation["arguments"]["sourceInvocationId"]
                .as_str()
                .unwrap()
        );
        let source = self.host.source_jobs.borrow()[claimed.source_invocation_id.as_str()].clone();
        assert_eq!(
            source.material.receipt.token_record_id.as_str(),
            invocation["arguments"]["tokenRecordId"].as_str().unwrap()
        );
        assert_eq!(
            store
                .read_blob(claimed.after_states[0].before.as_ref().unwrap())
                .unwrap(),
            source.change.before
        );
        let before = self.host.target.borrow().targets[TARGET].clone();
        if before != source.change.after {
            return Err(AppError::new(
                "RECOVERY_CONFLICT",
                "Actual native compare refused edited undo target",
            ));
        }
        assert!(!self.host.recover_jobs.borrow().contains_key(id.as_str()));
        let changed = !matches!(
            self.host.behavior.get(),
            RecoverBehavior::FailBeforeMutation
        );
        let after = if changed {
            source.change.before
        } else {
            before.clone()
        };
        let response = json!({"contractVersion":"0.2.0","status":if changed {"complete"} else {"failed"},
            "data":if changed {json!({"restored":true})} else {json!({})},
            "effects":if changed {"recorded"} else {"none"},"diagnostics":[],"artifacts":[]});
        self.host
            .recover_dispatches
            .set(self.host.recover_dispatches.get() + 1);
        {
            let mut target = self.host.target.borrow_mut();
            target.dispatches += 1;
            if changed {
                target.write_dispatches += 1;
                target.targets.insert(TARGET.into(), after.clone());
                target.invocations.insert(
                    id.as_str().into(),
                    TargetChange {
                        before: before.clone(),
                        after: after.clone(),
                    },
                );
            }
        }
        self.host.recover_jobs.borrow_mut().insert(
            id.as_str().into(),
            OwnedRecoverJob {
                invocation: invocation.clone(),
                response: response.clone(),
                changed,
                settled: true,
                before,
                after,
            },
        );
        Ok(response)
    }
    fn poll_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        receipt: Option<&str>,
    ) -> AppResult<Option<Value>> {
        if !self.host.is_undo(invocation) {
            return self.ordinary.poll_with_store(store, invocation, receipt);
        }
        let operation: OperationId = decode(&invocation["operationId"])?;
        let step: StepId = decode(&invocation["stepId"])?;
        assert_eq!(
            store.stored_invocation(&operation, &step).unwrap(),
            *invocation
        );
        self.host
            .check_session(&self.host.principal, &invocation["context"])?;
        let jobs = self.host.recover_jobs.borrow();
        let job = &jobs[invocation["invocationId"].as_str().unwrap()];
        assert_eq!(job.invocation, *invocation);
        Ok(Some(job.response.clone()))
    }
}

struct BundleObserver<'a> {
    ordinary: &'a mut Observer,
    host: Rc<BundleHostState>,
}
impl IndependentObserverPort for BundleObserver<'_> {
    fn capture_before(
        &mut self,
        invocation: &Value,
        scope: &WriteScope,
    ) -> AppResult<Option<BeforeCapture>> {
        self.ordinary.capture_before(invocation, scope)
    }
    fn readback(&mut self, invocation: &Value, scope: &WriteScope) -> AppResult<ReadbackEvidence> {
        assert!(
            !self.host.is_undo(invocation),
            "Actual inverse job requires its dedicated original-job observer"
        );
        self.ordinary.readback(invocation, scope)
    }
    fn read_target(&mut self, invocation: &Value, target: &str) -> AppResult<Vec<u8>> {
        self.ordinary.read_target(invocation, target)
    }
}

struct BundleFixture {
    fixture: Fixture,
    contexts: BundleContexts,
    host: BundleHost,
}
impl BundleFixture {
    fn new(provider_undo: bool, failed_source: bool) -> Self {
        let mut fixture = if provider_undo {
            undo_source_fixture(true, failed_source)
        } else {
            Fixture::new(1)
        };
        let source = fixture.provider.descriptor.clone();
        let mut undo = source.clone();
        undo["actionId"] = json!("fixture:provider_undo");
        undo["recovery"] = json!("none");
        undo["inputSchema"] = json!({"type":"object","properties":{
            "tokenRecordId":{"type":"string"},"tokenRecordDigest":{"type":"string"},
            "sourceOperationId":{"type":"string"},"sourceStepId":{"type":"string"},
            "sourceInvocationId":{"type":"string"}},"required":["tokenRecordId","tokenRecordDigest",
            "sourceOperationId","sourceStepId","sourceInvocationId"],"additionalProperties":false});
        undo["outputSchema"] = json!({"type":"object","properties":{"restored":{"type":"boolean"}},
            "required":["restored"],"additionalProperties":false});
        let registration = HostUndoRegistration {
            binding_id: decode(&fixture.planner.prepared.steps[0]["bindingId"]).unwrap(),
            source_action_id: decode(&source["actionId"]).unwrap(),
            source_action_digest: canonical_digest(&source).unwrap(),
            source_implementation_digest: decode(&source["implementationDigest"]).unwrap(),
            undo_action_digest: canonical_digest(&undo).unwrap(),
            undo_action: undo.clone(),
            provider_origin: json!({"kind":"native","label":"stateful-bundle-host"}),
        };
        fixture
            .provider
            .extra_descriptors
            .insert(undo["actionId"].as_str().unwrap().into(), undo);
        let contexts = BundleContexts {
            principal: fixture.principal.clone(),
            current: Rc::new(RefCell::new(fixture.provider.live_context.clone())),
            cancelled: Rc::new(Cell::new(false)),
            approved: None,
            opens: 0,
            offline: false,
            unbound_dispatch: false,
        };
        let host = BundleHost(Rc::new(BundleHostState {
            principal: fixture.principal.clone(),
            original_context: fixture.provider.live_context.clone(),
            source_descriptor: source,
            registration,
            target: fixture.target.clone(),
            session_open: Cell::new(true),
            source_jobs: RefCell::new(BTreeMap::new()),
            recover_jobs: RefCell::new(BTreeMap::new()),
            behavior: Cell::new(RecoverBehavior::Restore),
            role_inspections: Cell::new(0),
            receipt_inspections: Cell::new(0),
            recover_dispatches: Cell::new(0),
            recover_observations: Cell::new(0),
            intent_calls: Cell::new(0),
            reject_intent: Cell::new(false),
            intent_operation: RefCell::new(None),
        }));
        Self {
            fixture,
            contexts,
            host,
        }
    }
    fn plan(&mut self) -> Value {
        self.fixture.plan()
    }
    fn approve(&mut self, plan: &Value) {
        self.contexts.approved = Some((
            decode(&plan["planId"]).unwrap(),
            decode(&plan["planHash"]).unwrap(),
        ));
    }
    fn sync_actual_context(&mut self) {
        *self.contexts.current.borrow_mut() = self.fixture.provider.live_context.clone();
    }
    fn run(&mut self, input: &Value, method: u8) -> AppResult<Value> {
        self.sync_actual_context();
        let principal = self.fixture.principal.clone();
        let mut provider = BundleProvider {
            ordinary: &mut self.fixture.provider,
            host: self.host.0.clone(),
        };
        let mut observer = BundleObserver {
            ordinary: &mut self.fixture.observer,
            host: self.host.0.clone(),
        };
        let mut context = UndoExecutionContext {
            contexts: &mut self.contexts,
            material: &mut self.host,
        };
        let mut app = Application {
            store: &mut self.fixture.store,
            authority: &mut self.fixture.authority,
            planner: &mut self.fixture.planner,
            provider: &mut provider,
            observer: &mut observer,
            ids: &mut self.fixture.ids,
            clock: &self.fixture.clock,
        };
        match method {
            0 => app.plan_apply_with_undo(&principal, input, Some(&mut context)),
            1 => app.operation_reconcile_with_undo(&principal, input, Some(&mut context)),
            2 => app.recovery_plan_with_undo(&principal, input, Some(&mut context)),
            _ => unreachable!(),
        }
    }
    fn apply(&mut self, plan: &Value, key: &str) -> AppResult<Value> {
        self.run(
            &json!({"contractVersion":"0.2.0","planId":plan["planId"],"planHash":plan["planHash"],
            "contextId":plan["contextId"],"idempotencyKey":key}),
            0,
        )
    }
    fn reconcile(&mut self, report: &Value) -> AppResult<Value> {
        self.run(&Fixture::query(report), 1)
    }
    fn recovery(&mut self, report: &Value) -> AppResult<Value> {
        self.run(&undo_request(report), 2)
    }
    fn source_record(&self, report: &Value) -> ProviderUndoRecord {
        let operation: OperationId = decode(&report["operationId"]).unwrap();
        let materials: Vec<Value> = self
            .fixture
            .store
            .operation_summaries(&operation)
            .unwrap()
            .iter()
            .map(|blob| parse_json(&self.fixture.store.read_blob(blob).unwrap()).unwrap())
            .filter(|summary| summary["kind"] == "provider_undo_material")
            .collect();
        assert_eq!(
            materials.len(),
            1,
            "Common source path must durably retain exactly its actual receipt"
        );
        let id: ObjectId = decode(&materials[0]["recordId"]).unwrap();
        let rpc = TestUndoRpc::from_authenticated_fixture(&self.fixture);
        let mut authority = TestUndoAuthority::actual_source(&self.fixture, report);
        durable_undo::provider_undo_record(&self.fixture.store, &rpc, &mut authority, &id).unwrap()
    }
    fn reopen(self) -> Self {
        Self {
            fixture: self.fixture.reopen(),
            contexts: self.contexts,
            host: self.host,
        }
    }
}

#[test]
fn common_undo_existing_key_and_terminal_report_open_no_offline_game_rpc() {
    let mut fixture = BundleFixture::new(true, false);
    let plan = fixture.plan();
    fixture.approve(&plan);
    let report = fixture.apply(&plan, "bundle-existing-key").unwrap();
    assert_eq!(report["state"], "succeeded");
    assert_eq!(fixture.host.0.intent_calls.get(), 1);
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let before = json!(fixture.fixture.store.operation(&operation).unwrap());
    let opens = fixture.contexts.opens;
    let roles = fixture.host.0.role_inspections.get();
    fixture.contexts.offline = true;
    fixture.host.0.session_open.set(false);
    fixture.fixture.provider.live_context["environment"]["sessionEpoch"] =
        json!("different-live-epoch");
    fixture.fixture.provider.live_context["contextDigest"] = json!(
        projected_digest("ExecutionContext", &fixture.fixture.provider.live_context).unwrap()
    );
    assert_eq!(fixture.apply(&plan, "bundle-existing-key").unwrap(), report);
    assert_eq!(fixture.reconcile(&report).unwrap(), report);
    assert_eq!(fixture.contexts.opens, opens);
    assert_eq!(fixture.host.0.role_inspections.get(), roles);
    assert_eq!(fixture.host.0.intent_calls.get(), 1);
    assert_eq!(
        json!(fixture.fixture.store.operation(&operation).unwrap()),
        before
    );
    fixture.fixture.target.borrow_mut().observe_grant = false;
    assert_eq!(
        fixture
            .apply(&plan, "bundle-existing-key")
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
    assert_eq!(fixture.contexts.opens, opens);
    assert_eq!(fixture.fixture.target.borrow().dispatches, 1);
    assert_eq!(
        json!(fixture.fixture.store.operation(&operation).unwrap()),
        before
    );
}

#[test]
fn common_undo_ordinary_external_write_needs_no_game_role_or_rpc() {
    let mut fixture = BundleFixture::new(false, false);
    fixture.fixture.provider.live_context["environment"] = json!({"kind":"external","toolHostId":"tool-host-undo-fixture",
            "sessionEpoch":"external-epoch-undo-fixture","side":"external"});
    for field in [
        "dimension",
        "executorHandle",
        "origin",
        "rotationDegrees",
        "anchor",
    ] {
        fixture
            .fixture
            .provider
            .live_context
            .as_object_mut()
            .unwrap()
            .remove(field);
    }
    fixture.fixture.provider.descriptor["side"] = json!("external");
    fixture.fixture.provider.descriptor["requiredContext"] = json!(["project"]);
    fixture.fixture.planner.prepared.steps = vec![write_step(
        &fixture.fixture.provider.descriptor,
        "write-first",
        "after-first",
        vec![],
    )];
    fixture.fixture.provider.live_context["contextDigest"] = json!(
        projected_digest("ExecutionContext", &fixture.fixture.provider.live_context).unwrap()
    );
    fixture.fixture.planner.prepared.contexts = vec![fixture.fixture.provider.live_context.clone()];
    fixture.contexts.offline = true;
    fixture.host.0.session_open.set(false);
    let plan = fixture.plan();
    fixture.approve(&plan);
    let report = fixture.apply(&plan, "bundle-ordinary-external").unwrap();
    assert_eq!(report["state"], "succeeded");
    assert_eq!(fixture.contexts.opens, 0);
    assert_eq!(fixture.host.0.role_inspections.get(), 0);
    assert_eq!(fixture.host.0.receipt_inspections.get(), 0);
    assert_eq!(
        fixture.fixture.target.borrow().targets[TARGET],
        b"after-first"
    );
    assert_eq!(fixture.fixture.target.borrow().write_dispatches, 1);

    let mut rejected = BundleFixture::new(false, false);
    let rejected_plan = rejected.plan();
    rejected.approve(&rejected_plan);
    rejected.host.0.reject_intent.set(true);
    let error = rejected
        .apply(&rejected_plan, "bundle-intent-rejected")
        .unwrap_err();
    assert_eq!(error.code, "DISPATCH_REJECTED");
    assert!(matches!(
        std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<StorageError>(),
        Some(StorageError::Conflict(
            "Fixture protected dispatch claim rejected"
        ))
    ));
    assert_eq!(rejected.host.0.intent_calls.get(), 1);
    assert_eq!(rejected.fixture.target.borrow().dispatches, 0);
    assert_eq!(rejected.fixture.target.borrow().targets[TARGET], b"before");
    let operation = rejected.host.0.intent_operation.borrow().clone().unwrap();
    let record = rejected.fixture.store.operation(&operation).unwrap();
    assert_eq!(record.steps[0].dispatch, DispatchEvidence::NotSent);
    assert!(record.steps[0].invocation_id.is_none());
    assert!(
        rejected
            .fixture
            .store
            .stored_invocation(&operation, &record.steps[0].step_id)
            .is_err()
    );
}

#[test]
fn common_undo_failed_source_first_settled_provenance_fresh_plan_claim_restore_and_restart() {
    let mut fixture = BundleFixture::new(true, true);
    let source_plan = fixture.plan();
    fixture.approve(&source_plan);
    let source_report = fixture.apply(&source_plan, "bundle-failed-source").unwrap();
    assert_eq!(source_report["state"], "partial");
    assert_eq!(fixture.host.0.intent_calls.get(), 1);
    fixture.host.0.reject_intent.set(true);
    assert_eq!(source_report["result"]["providerStatusCounts"]["failed"], 1);
    let undo_plan = fixture.recovery(&source_report).unwrap();
    assert_ne!(undo_plan["planId"], source_plan["planId"]);
    assert_eq!(undo_plan["approvalRequirement"], "explicit_approval");
    let available = fixture.source_record(&source_report);
    assert_eq!(available.state, UndoRecordState::Available);
    let source_operation: OperationId = decode(&source_report["operationId"]).unwrap();
    let source = fixture.fixture.store.operation(&source_operation).unwrap();
    let first_settled = source.steps[0]
        .observation_refs
        .iter()
        .find_map(|blob| {
            let envelope = parse_json(&fixture.fixture.store.read_blob(blob).unwrap()).unwrap();
            (envelope["kind"] == "independent_readback" && envelope["settled"] == true)
                .then(|| (blob.clone(), envelope))
        })
        .unwrap();
    assert_eq!(
        available.settled_observation.as_ref(),
        Some(&first_settled.0)
    );
    assert_eq!(
        first_settled.1["afterStates"],
        json!(available.after_states)
    );
    let associated = fixture
        .fixture
        .store
        .operation_evidence_refs(&source_operation)
        .unwrap();
    let summary = fixture
        .fixture
        .store
        .operation_summaries(&source_operation)
        .unwrap()
        .iter()
        .map(|blob| parse_json(&fixture.fixture.store.read_blob(blob).unwrap()).unwrap())
        .find(|value| {
            value["kind"] == "independent_readback_summary"
                && value["sourceRefs"]
                    .as_array()
                    .is_some_and(|sources| sources.contains(&json!(first_settled.0)))
        })
        .unwrap();
    let summary_sources: Vec<BlobRef> = decode(&summary["sourceRefs"]).unwrap();
    assert!(summary_sources.contains(&first_settled.0));
    let raw_sources: Vec<BlobRef> = decode(&first_settled.1["sourceRefs"]).unwrap();
    for raw in raw_sources {
        assert!(summary_sources.contains(&raw));
    }
    for state in &available.after_states {
        assert!(associated.contains(&state.after));
        assert!(summary_sources.contains(&state.after));
        assert_eq!(
            fixture
                .fixture
                .store
                .read_blob(state.before.as_ref().unwrap())
                .unwrap(),
            b"before"
        );
        assert_eq!(
            fixture.fixture.store.read_blob(&state.after).unwrap(),
            b"after-first"
        );
    }
    let undo_report = fixture.apply(&undo_plan, "bundle-no-new-approval");
    assert!(
        undo_report.is_err() || undo_report.as_ref().unwrap()["state"] == "failed_before_effects"
    );
    assert_eq!(fixture.host.0.recover_dispatches.get(), 0);
    assert_eq!(
        fixture.fixture.target.borrow().targets[TARGET],
        b"after-first"
    );
    fixture.approve(&undo_plan);
    fixture.contexts.unbound_dispatch = true;
    let unsealed = fixture.apply(&undo_plan, "bundle-approved-but-unsealed-undo");
    assert!(unsealed.is_err() || unsealed.as_ref().unwrap()["state"] == "failed_before_effects");
    assert_eq!(fixture.host.0.recover_dispatches.get(), 0);
    assert_eq!(
        fixture.source_record(&source_report).state,
        UndoRecordState::Available
    );
    fixture.contexts.unbound_dispatch = false;
    let restored = fixture.apply(&undo_plan, "bundle-approved-undo").unwrap();
    assert_eq!(restored["state"], "succeeded");
    assert_eq!(fixture.host.0.intent_calls.get(), 1);
    assert_eq!(fixture.fixture.target.borrow().targets[TARGET], b"before");
    assert_eq!(fixture.host.0.recover_dispatches.get(), 1);
    assert_eq!(fixture.host.0.recover_observations.get(), 1);
    let undo_operation: OperationId = decode(&restored["operationId"]).unwrap();
    let undo_record = fixture.fixture.store.operation(&undo_operation).unwrap();
    let step = &undo_record.steps[0];
    let invocation = fixture
        .fixture
        .store
        .stored_invocation(&undo_operation, &step.step_id)
        .unwrap();
    let claim = durable_undo::claimed_undo_record(
        &fixture.fixture.store,
        &undo_operation,
        &step.step_id,
        step.invocation_id.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(claim.record_id, available.record_id);
    let captured = fixture
        .fixture
        .app()
        .captured_before(&undo_operation, &step.step_id, &invocation)
        .unwrap();
    assert_eq!(
        fixture.fixture.store.read_blob(&captured[TARGET]).unwrap(),
        b"after-first"
    );
    let snapshot = fixture
        .fixture
        .store
        .recovery_snapshots(&undo_operation)
        .unwrap();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(
        fixture
            .fixture
            .store
            .read_blob(&snapshot[0].before)
            .unwrap(),
        b"after-first"
    );
    assert_eq!(
        fixture.fixture.store.read_blob(&snapshot[0].after).unwrap(),
        b"before"
    );
    fixture.fixture.store.collect_orphan_blobs(1000).unwrap();
    let mut fixture = fixture.reopen();
    assert_eq!(fixture.fixture.get(&source_report).unwrap(), source_report);
    assert_eq!(fixture.fixture.get(&restored).unwrap(), restored);
    assert!(matches!(
        fixture.source_record(&source_report).state,
        UndoRecordState::Reserved { .. }
    ));
    let opens = fixture.contexts.opens;
    fixture.contexts.offline = true;
    assert_eq!(
        fixture.apply(&undo_plan, "bundle-approved-undo").unwrap(),
        restored
    );
    assert_eq!(fixture.reconcile(&restored).unwrap(), restored);
    assert_eq!(fixture.contexts.opens, opens);
    fixture.contexts.offline = false;
    // Manual restoration of the expected after bytes removes target drift as
    // the reason for rejection. The original durable token claim still wins.
    fixture
        .fixture
        .target
        .borrow_mut()
        .targets
        .insert(TARGET.into(), b"after-first".to_vec());
    let _ = fixture.apply(&undo_plan, "bundle-replay-new-operation");
    assert_eq!(fixture.host.0.recover_dispatches.get(), 1);
    assert_eq!(
        fixture.fixture.target.borrow().targets[TARGET],
        b"after-first"
    );
    assert!(matches!(
        fixture.source_record(&source_report).state,
        UndoRecordState::Reserved { .. }
    ));
}

#[test]
fn common_undo_actual_failed_job_before_mutation_preserves_none_and_empty_direct_changes() {
    let mut fixture = BundleFixture::new(true, true);
    let source_plan = fixture.plan();
    fixture.approve(&source_plan);
    let source_report = fixture
        .apply(&source_plan, "bundle-failed-source-for-no-effect-undo")
        .unwrap();
    let undo_plan = fixture.recovery(&source_report).unwrap();
    fixture.approve(&undo_plan);
    fixture
        .host
        .0
        .behavior
        .set(RecoverBehavior::FailBeforeMutation);
    let failed = fixture
        .apply(&undo_plan, "bundle-undo-native-failed-before-mutation")
        .unwrap();
    assert_eq!(failed["state"], "failed_before_effects");
    assert_eq!(failed["result"]["providerStatusCounts"]["failed"], 1);
    assert_eq!(
        fixture.fixture.target.borrow().targets[TARGET],
        b"after-first"
    );
    assert_eq!(fixture.fixture.target.borrow().write_dispatches, 1);
    assert_eq!(fixture.host.0.recover_dispatches.get(), 1);
    let operation: OperationId = decode(&failed["operationId"]).unwrap();
    let record = fixture.fixture.store.operation(&operation).unwrap();
    assert_eq!(record.steps[0].effect, EffectEvidence::NoneConfirmed);
    assert!(record.steps[0].finished);
    assert!(!record.steps[0].further_effects_possible);
    assert!(
        fixture
            .fixture
            .store
            .recovery_snapshots(&operation)
            .unwrap()
            .is_empty()
    );
    let readbacks: Vec<Value> = record.steps[0]
        .observation_refs
        .iter()
        .map(|blob| parse_json(&fixture.fixture.store.read_blob(blob).unwrap()).unwrap())
        .filter(|envelope| envelope["kind"] == "independent_readback")
        .collect();
    assert_eq!(readbacks.len(), 1);
    assert_eq!(readbacks[0]["effect"], json!(EffectEvidence::NoneConfirmed));
    assert_eq!(readbacks[0]["directChanges"], json!([]));
    fixture.fixture.store.collect_orphan_blobs(1000).unwrap();
    let mut fixture = fixture.reopen();
    assert_eq!(fixture.fixture.get(&failed).unwrap(), failed);
    assert_eq!(fixture.fixture.get(&source_report).unwrap(), source_report);
    assert!(matches!(
        fixture.source_record(&source_report).state,
        UndoRecordState::Reserved { .. }
    ));
    let _ = fixture.apply(&undo_plan, "bundle-failed-undo-replay");
    assert_eq!(fixture.host.0.recover_dispatches.get(), 1);
    assert_eq!(
        fixture.fixture.target.borrow().targets[TARGET],
        b"after-first"
    );
}

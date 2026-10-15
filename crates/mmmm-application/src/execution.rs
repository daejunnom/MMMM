use crate::planning::{check_descriptor, invocation_deadline, step_order};
use crate::*;
use mmmm_contracts::{
    ContextId, InvocationId, OperationId, PlanId, Sha256Digest, StepId, canonical_digest,
    encode_json,
};
use mmmm_runtime::storage::{
    DispatchEvidence, EffectEvidence, OperationRecord, OperationState, RecoverySnapshot,
    Reservation, ReserveOperation, StepObservation, StorageError, VerificationRequirement,
};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

impl Application<'_> {
    pub fn plan_apply(&mut self, principal: &PrincipalId, input: &Value) -> AppResult<Value> {
        self.plan_apply_with_undo(principal, input, None)
    }

    pub fn plan_apply_with_undo(
        &mut self,
        principal: &PrincipalId,
        input: &Value,
        undo: Option<&mut UndoExecutionContext<'_>>,
    ) -> AppResult<Value> {
        validate("ApplyRequest", input)?;
        let id: PlanId = decode(&input["planId"])?;
        let hash: Sha256Digest = decode(&input["planHash"])?;
        let plan = self
            .store
            .plan(&id, &hash)
            .map_err(|e| AppError::storage("STALE_PLAN", e))?;
        let project: ProjectId = decode(&plan["projectId"])?;
        self.authority
            .authorize(principal, &project, Access::ReadPlan, None, Some(&plan))?;
        if input["contextId"] != plan["contextId"] {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Apply context differs from the frozen plan",
            ));
        }
        let operation = OperationId::new(self.ids.next_id(IdKind::Operation)?).map_err(|_| {
            AppError::new(
                "INVALID_INPUT",
                "ID source returned an invalid operation identity",
            )
        })?;
        let reservation = self
            .store
            .reserve_operation(ReserveOperation {
                operation_id: operation,
                principal: principal.clone(),
                project_id: project,
                idempotency_key: text(input, "idempotencyKey")?.to_owned(),
                plan_id: id,
                plan_hash: hash,
                context_id: decode(&input["contextId"])?,
            })
            .map_err(|e| {
                let code = if matches!(e, StorageError::Conflict("Idempotency key")) {
                    "IDEMPOTENCY_CONFLICT"
                } else {
                    "STALE_PLAN"
                };
                AppError::storage(code, e)
            })?;
        let record = match reservation {
            // Existing status retrieval stays valid after expiry/revocation of a
            // write grant, provided ReadPlan/journal authorization still exists.
            Reservation::Existing(record) => {
                self.authorize_report_release(principal, &plan, &record)?;
                return self.operation_report(&record);
            }
            Reservation::Created(record) => record,
        };
        self.execute_reserved(principal, &plan, &record.operation_id, undo)?;
        let record = self
            .store
            .operation(&record.operation_id)
            .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?;
        self.authorize_report_release(principal, &plan, &record)?;
        self.operation_report(&record)
    }

    fn authorize_report_release(
        &mut self,
        principal: &PrincipalId,
        _plan: &Value,
        record: &OperationRecord,
    ) -> AppResult<()> {
        // A current journal grant permits reading immutable historical state
        // even when its host is offline or has a new epoch. Effectful observe
        // and cancel callbacks retain their separate actual context checks.
        self.authority
            .authorize_operation(principal, record, Access::ObserveOperation)
    }

    fn execute_reserved(
        &mut self,
        principal: &PrincipalId,
        plan: &Value,
        operation: &OperationId,
        mut undo: Option<&mut UndoExecutionContext<'_>>,
    ) -> AppResult<()> {
        let steps = plan["steps"]
            .as_array()
            .ok_or_else(|| AppError::new("STALE_PLAN", "Frozen plan steps are absent"))?;
        let order = step_order(steps)?;
        let budget = plan["timeBudgetMs"]
            .as_u64()
            .filter(|v| *v <= 3_600_000)
            .ok_or_else(|| {
                AppError::new("BUDGET_EXCEEDED", "Frozen execution time budget is invalid")
            })?;
        let started = Instant::now();
        for index in order {
            let record = self
                .store
                .operation(operation)
                .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?;
            if record.cancellation_requested {
                break;
            }
            let step = &steps[index];
            let step_id: StepId = decode(&step["stepId"])?;
            if started.elapsed() >= Duration::from_millis(budget) {
                self.note(operation, "BUDGET_EXCEEDED", "Execution stopped before another dispatch because its finite time budget elapsed")?;
                break;
            }
            let (context, descriptor, recovery_only) = match self.preflight_with_undo(
                principal,
                plan,
                step,
                operation,
                undo.as_deref_mut(),
            ) {
                Ok(v) => v,
                Err(e) => {
                    self.note(operation, e.code, e.message)?;
                    break;
                }
            };
            if step["effect"] != "read"
                && let Err(e) = self.store.check_write_scope(
                    &record.scope,
                    record.whole_project_fence,
                    Some(operation),
                )
            {
                self.note(
                    operation,
                    "WRITE_SCOPE_FENCED",
                    "An unresolved operation holds this write scope",
                )?;
                if !matches!(e, StorageError::Fenced(_)) {
                    return Err(AppError::storage("WRITE_SCOPE_FENCED", e));
                }
                break;
            }
            let invocation_id =
                InvocationId::new(self.ids.next_id(IdKind::Invocation)?).map_err(|_| {
                    AppError::new(
                        "INVALID_INPUT",
                        "ID source returned an invalid invocation identity",
                    )
                })?;
            let (arguments, result_bindings) =
                match self.resolve_step_arguments(principal, plan, step, operation, &context) {
                    Ok(value) => value,
                    Err(e) => {
                        self.note(operation, e.code, e.message)?;
                        break;
                    }
                };
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let deadline =
                invocation_deadline(self.clock, plan, budget.saturating_sub(elapsed_ms))?;
            let invocation = json!({
                "contractVersion":"0.2.0", "invocationId":invocation_id, "operationId":operation,
                "stepId":step["stepId"], "bindingId":step["bindingId"], "actionId":step["actionId"],
                "actionContractVersion":step["actionContractVersion"], "actionDigest":step["actionDigest"],
                "arguments":arguments, "context":context, "deadlineAt":deadline,
                "idempotencyKey":record.idempotency_key, "implementationDigest":step["implementationDigest"],
                "argumentsDigest":canonical_digest(&arguments).map_err(|_| AppError::new("STALE_PLAN", "Resolved arguments digest is invalid"))?,
                "contextDigest":context["contextDigest"]
            });
            validate("Invocation", &invocation)?;
            let resolution_witness = if result_bindings.is_empty() {
                None
            } else {
                match self.retain_resolution_witness(
                    plan,
                    step,
                    operation,
                    &invocation,
                    result_bindings,
                ) {
                    Ok(blob) => Some(blob),
                    Err(e) => {
                        self.note(operation, e.code, e.message)?;
                        break;
                    }
                }
            };
            let undo_rpc = if recovery_only {
                let opened = undo
                    .as_deref_mut()
                    .ok_or_else(|| {
                        AppError::new(
                            "RECOVERY_EXPIRED",
                            "Registered undo requires an actual approved request context",
                        )
                    })
                    .and_then(|bundle| {
                        bundle.open_for_plan(self.store, principal, plan, step, &context)
                    });
                match opened {
                    Ok(rpc) => Some(rpc),
                    Err(error) => {
                        self.note(operation, error.code, error.message)?;
                        break;
                    }
                }
            } else {
                None
            };
            let capture = match undo_rpc.as_ref() {
                Some(rpc) => self
                    .capture_registered_undo_before(principal, rpc.as_ref(), &invocation)
                    .and_then(|capture| {
                        self.retain_checked_before_capture(
                            plan,
                            step,
                            operation,
                            &invocation,
                            &record.scope,
                            Some(capture),
                        )
                    }),
                None => {
                    self.retain_before_capture(plan, step, operation, &invocation, &record.scope)
                }
            };
            if let Err(e) = capture {
                self.note(operation, e.code, e.message)?;
                break;
            }
            // Capture must match the durable phase digest itself, and a fresh
            // preflight after capture checks policy, expiry and target drift.
            // The native mutation still performs its atomic expected-state check.
            if let Err(e) =
                self.preflight_with_undo(principal, plan, step, operation, undo.as_deref_mut())
            {
                self.note(operation, e.code, e.message)?;
                break;
            }
            if started.elapsed() >= Duration::from_millis(budget)
                || self
                    .store
                    .operation(operation)
                    .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?
                    .cancellation_requested
            {
                self.note(
                    operation,
                    "BUDGET_EXCEEDED",
                    "Execution stopped after capture before durable dispatch",
                )?;
                break;
            }
            // This commits Invocation bytes, the fence, and intent before any
            // provider call. An error afterwards is never a retry permission.
            let intent = if let Some(rpc) = undo_rpc.as_ref() {
                if resolution_witness.is_some() {
                    Err(AppError::new(
                        "RECOVERY_CONFLICT",
                        "A registered undo cannot resolve new result bindings",
                    ))
                } else {
                    self.dispatch_registered_undo_intent(
                        principal,
                        rpc.as_ref(),
                        operation,
                        &step_id,
                        &invocation,
                    )
                    .and_then(|record| {
                        record.ok_or_else(|| {
                            AppError::new(
                                "RECOVERY_EXPIRED",
                                "Registered undo role is absent from its atomic claim",
                            )
                        })
                    })
                }
            } else {
                self.provider.persist_dispatch_intent_with_store(
                    self.store,
                    operation,
                    &step_id,
                    &invocation,
                    resolution_witness.as_ref(),
                )
            };
            if let Err(e) = intent {
                self.note(
                    operation,
                    "DISPATCH_REJECTED",
                    "Durable runtime rejected a new dispatch intent",
                )?;
                return Err(e);
            }
            match self.provider.dispatch_with_store(self.store, &invocation) {
                Ok(response) => {
                    if let Err(e) = self.accept_response(
                        operation,
                        &step_id,
                        &invocation,
                        &descriptor,
                        &response,
                    ) {
                        self.ambiguous(operation, &step_id, e.code, e.message)?;
                    }
                }
                Err(e) => {
                    self.ambiguous(operation, &step_id, e.code, e.message)?;
                }
            }
            self.retain_source_undo_material(
                principal,
                operation,
                &step_id,
                &invocation,
                &descriptor,
                undo.as_deref_mut(),
            )?;
            // Writes always need actual effect evidence. Provider completion is
            // retained separately and cannot stand in for the target observer.
            let current = self
                .store
                .operation(operation)
                .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?;
            let stored = current
                .steps
                .iter()
                .find(|s| s.step_id == step_id)
                .ok_or_else(|| AppError::new("OPERATION_NOT_FOUND", "Durable step is absent"))?;
            if !stored.finished
                && (stored.write_effect
                    || stored.verification_requirement
                        == VerificationRequirement::IndependentReadback)
            {
                match self.observe(
                    principal,
                    operation,
                    &step_id,
                    &invocation,
                    undo.as_deref_mut(),
                ) {
                    Ok(()) => (),
                    Err(e) => self.ambiguous(operation, &step_id, e.code, e.message)?,
                }
            }
            let current = self
                .store
                .operation(operation)
                .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?;
            let step = current
                .steps
                .iter()
                .find(|s| s.step_id == step_id)
                .ok_or_else(|| AppError::new("OPERATION_NOT_FOUND", "Durable step is absent"))?;
            let provider_failed = self
                .evidence_values(&current)?
                .iter()
                .any(|v| crate::report::failure_blocks_step(v, step_id.as_str()));
            if provider_failed || !crate::report::step_verified(step) {
                break;
            }
        }
        self.settle(operation)
    }

    pub fn operation_get(&mut self, principal: &PrincipalId, input: &Value) -> AppResult<Value> {
        let record = self.authorized_operation(principal, input, Access::ObserveOperation)?;
        self.operation_report(&record)
    }

    pub fn operation_cancel(&mut self, principal: &PrincipalId, input: &Value) -> AppResult<Value> {
        let record = self.authorized_operation(principal, input, Access::Cancel)?;
        let plan = self
            .store
            .plan(&record.plan_id, &record.plan_hash)
            .map_err(|e| AppError::storage("STALE_PLAN", e))?;
        if record.state.terminal() || record.cancellation_requested {
            self.authorize_report_release(principal, &plan, &record)?;
            return self.operation_report(&record);
        }
        let mut dispatched = Vec::new();
        for stored in &record.steps {
            if stored.dispatch == DispatchEvidence::NotSent || stored.finished {
                continue;
            }
            let invocation = self
                .store
                .stored_invocation(&record.operation_id, &stored.step_id)
                .map_err(|e| AppError::storage("STALE_CONTEXT", e))?;
            let step = plan["steps"]
                .as_array()
                .and_then(|steps| {
                    steps
                        .iter()
                        .find(|s| s["stepId"] == stored.step_id.as_str())
                })
                .ok_or_else(|| AppError::new("STALE_PLAN", "Frozen step is absent"))?;
            let context_id: ContextId = decode(&invocation["context"]["contextId"])?;
            let context = self.observation_context(principal, &plan, &context_id)?;
            self.authority.authorize(
                principal,
                &record.project_id,
                Access::Cancel,
                Some(&context),
                Some(&plan),
            )?;
            let descriptor = self.provider.action_descriptor(step, &context)?;
            check_descriptor(step, &context, &descriptor)?;
            if descriptor["cancellation"] != "cooperative" {
                return Err(AppError::new(
                    "CANCEL_UNSUPPORTED",
                    "Dispatched action does not expose cooperative cancellation",
                ));
            }
            dispatched.push((invocation, stored.provider_receipt.clone()));
        }
        let requested = self
            .store
            .request_cancel(&record.operation_id)
            .map_err(|e| AppError::storage("CANCEL_UNSUPPORTED", e))?;
        for (invocation, receipt) in dispatched {
            if let Err(e) =
                self.provider
                    .request_cancel_with_store(self.store, &invocation, receipt.as_deref())
            {
                self.note(&record.operation_id, e.code, e.message)?;
            }
        }
        // A cooperative acknowledgment never marks a dispatched write cancelled.
        self.authorize_report_release(principal, &plan, &requested)?;
        self.operation_report(&requested)
    }

    pub fn operation_reconcile(
        &mut self,
        principal: &PrincipalId,
        input: &Value,
    ) -> AppResult<Value> {
        self.operation_reconcile_with_undo(principal, input, None)
    }

    pub fn operation_reconcile_with_undo(
        &mut self,
        principal: &PrincipalId,
        input: &Value,
        mut undo: Option<&mut UndoExecutionContext<'_>>,
    ) -> AppResult<Value> {
        let record = self.authorized_operation(principal, input, Access::ObserveOperation)?;
        if record.state.terminal() {
            return self.operation_report(&record);
        }
        let plan = self
            .store
            .plan(&record.plan_id, &record.plan_hash)
            .map_err(|e| AppError::storage("STALE_PLAN", e))?;
        for stored in &record.steps {
            if stored.dispatch == DispatchEvidence::NotSent || stored.finished {
                continue;
            }
            let invocation = self
                .store
                .stored_invocation(&record.operation_id, &stored.step_id)
                .map_err(|e| AppError::storage("STALE_CONTEXT", e))?;
            let id: ContextId = decode(&invocation["context"]["contextId"])?;
            let context = self.observation_context(principal, &plan, &id)?;
            self.authority.authorize(
                principal,
                &record.project_id,
                Access::ObserveOperation,
                Some(&context),
                Some(&plan),
            )?;
            let step = plan["steps"]
                .as_array()
                .and_then(|s| s.iter().find(|s| s["stepId"] == stored.step_id.as_str()))
                .ok_or_else(|| AppError::new("STALE_PLAN", "Frozen step is absent"))?;
            let descriptor = self.provider.action_descriptor(step, &context)?;
            check_descriptor(step, &context, &descriptor)?;
            match self.provider.poll_with_store(
                self.store,
                &invocation,
                stored.provider_receipt.as_deref(),
            ) {
                Ok(Some(response)) => {
                    if let Err(e) = self.accept_response(
                        &record.operation_id,
                        &stored.step_id,
                        &invocation,
                        &descriptor,
                        &response,
                    ) {
                        self.ambiguous(&record.operation_id, &stored.step_id, e.code, e.message)?;
                    }
                }
                Ok(None) => (),
                Err(e) => self.note(&record.operation_id, e.code, e.message)?,
            }
            self.retain_source_undo_material(
                principal,
                &record.operation_id,
                &stored.step_id,
                &invocation,
                &descriptor,
                undo.as_deref_mut(),
            )?;
            let current = self
                .store
                .operation(&record.operation_id)
                .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?;
            let step = current
                .steps
                .iter()
                .find(|s| s.step_id == stored.step_id)
                .ok_or_else(|| AppError::new("OPERATION_NOT_FOUND", "Durable step is absent"))?;
            if !step.finished
                && (step.write_effect
                    || step.verification_requirement
                        == VerificationRequirement::IndependentReadback)
                && let Err(e) = self.observe(
                    principal,
                    &record.operation_id,
                    &stored.step_id,
                    &invocation,
                    undo.as_deref_mut(),
                )
            {
                self.note(&record.operation_id, e.code, e.message)?;
            }
        }
        // Reconciliation never dispatches NotSent successors or repeats an intent.
        self.settle(&record.operation_id)?;
        let final_record = self
            .store
            .operation(&record.operation_id)
            .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?;
        self.authorize_report_release(principal, &plan, &final_record)?;
        self.operation_report(&final_record)
    }

    pub(crate) fn authorized_operation(
        &mut self,
        principal: &PrincipalId,
        input: &Value,
        access: Access,
    ) -> AppResult<OperationRecord> {
        validate("OperationQuery", input)?;
        let id: OperationId = decode(&input["operationId"])?;
        let record = self
            .store
            .operation(&id)
            .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?;
        self.authority
            .authorize_operation(principal, &record, access)?;
        if input["contextId"] != record.context_id.as_str() {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Query context differs from the operation's frozen root",
            ));
        }
        // Authority permits explicit administrators; ordinary owner checks must
        // be enforced by the injected authorization policy, not request JSON.
        Ok(record)
    }

    fn accept_response(
        &mut self,
        operation: &OperationId,
        step: &StepId,
        invocation: &Value,
        descriptor: &Value,
        response: &Value,
    ) -> AppResult<()> {
        // Retain even malformed responses in the operation CAS evidence; they
        // remain data and cannot select another endpoint or operation arguments.
        let bytes = encode_json(response).map_err(|_| {
            AppError::new(
                "INVALID_PROVIDER_OUTPUT",
                "Provider output exceeds the strict JSON boundary",
            )
        })?;
        let blob = self
            .store
            .put_blob(&bytes)
            .map_err(|e| AppError::storage("OUTCOME_UNKNOWN", e))?;
        let envelope_validated = validate("ProviderResult", response).is_ok();
        let mut raw_summary = json!({"kind":"unvalidated_provider_result", "stepId":step,"invocationId":invocation["invocationId"],
            "sourceRefs":[blob],"resultBlob":blob, "bodyOmitted":true,
            "envelopeValidated":envelope_validated,
            "envelopeStatus":if envelope_validated {response["status"].clone()} else {Value::Null}});
        if envelope_validated {
            raw_summary["envelopeSummary"] = crate::report::compact_evidence(
                &json!({
                "kind":"provider_result","stepId":step,"invocationId":invocation["invocationId"],
                "value":response,"outputValidated":false,"actionDigest":invocation["actionDigest"],
                "outputSchemaDigest":canonical_digest(&descriptor["outputSchema"]).map_err(AppError::digest)?,
                "resultBlob":blob,"sourceRefs":[blob]}),
                &blob,
            )?;
        }
        self.retain_summary(operation, &raw_summary, std::slice::from_ref(&blob))?;
        validate("ProviderResult", response).map_err(|_| {
            AppError::new(
                "INVALID_PROVIDER_OUTPUT",
                "Provider result does not match its canonical envelope",
            )
        })?;
        if response["status"] == "complete" {
            ContractValidator::shared()
                .map_err(AppError::contract)?
                .compile_action_schema(&descriptor["outputSchema"])
                .map_err(AppError::contract)?
                .validate(&response["data"])
                .map_err(|_| {
                    AppError::new(
                        "INVALID_PROVIDER_OUTPUT",
                        "Provider result data does not match the pinned action schema",
                    )
                })?;
        }
        let validated = json!({
            "kind":"provider_result", "stepId":step,"invocationId":invocation["invocationId"], "value":response,
            "outputValidated":response["status"] == "complete", "actionDigest":invocation["actionDigest"],
            "outputSchemaDigest":canonical_digest(&descriptor["outputSchema"])
                .map_err(|_| AppError::new("INVALID_PROVIDER_OUTPUT", "Pinned output schema digest is invalid"))?
        });
        let summary = crate::report::compact_evidence(&validated, &blob)?;
        let summary_blob = self.retain_summary(operation, &summary, std::slice::from_ref(&blob))?;
        let record = self
            .store
            .operation(operation)
            .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?;
        let stored = record
            .steps
            .iter()
            .find(|s| &s.step_id == step)
            .ok_or_else(|| AppError::new("OPERATION_NOT_FOUND", "Durable step is absent"))?;
        if stored.finished {
            return Ok(());
        }
        let receipt = response
            .get("jobHandle")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| stored.provider_receipt.clone());
        let finished = !stored.write_effect
            && stored.verification_requirement != VerificationRequirement::IndependentReadback
            && response["status"] == "complete";
        let dispatch = stored.dispatch.max(DispatchEvidence::Acknowledged);
        self.store
            .record_observation(
                operation,
                step,
                StepObservation {
                    dispatch,
                    effect: if stored.write_effect {
                        stored.effect
                    } else {
                        EffectEvidence::NoneConfirmed
                    },
                    further_effects_possible: stored.further_effects_possible,
                    provider_receipt: receipt,
                    observation_refs: vec![summary_blob],
                    finished,
                },
            )
            .map_err(|e| AppError::storage("OUTCOME_UNKNOWN", e))?;
        if response["status"] == "failed" {
            self.note(operation, "PROVIDER_FAILED", "The original provider reported failure; existing effects remain separately observed")?;
        }
        Ok(())
    }

    /// Receipt acquisition uses a separate current Observe context, never a
    /// possibly expired/revoked source Apply seal. The runtime commits acquired
    /// truthful Pending material before a late release denial. Failure here
    /// does not prevent the existing independent effect observation.
    fn retain_source_undo_material(
        &mut self,
        principal: &PrincipalId,
        operation: &OperationId,
        step: &StepId,
        invocation: &Value,
        descriptor: &Value,
        undo: Option<&mut UndoExecutionContext<'_>>,
    ) -> AppResult<()> {
        if descriptor["recovery"] != "provider_undo" || descriptor["effect"] == "read" {
            return Ok(());
        }
        let Some(bundle) = undo else {
            return Ok(());
        };
        let acquired = bundle
            .open_for_observation(self.store, principal, operation, step, invocation)
            .and_then(|rpc| {
                self.capture_provider_undo_record(
                    principal,
                    rpc.as_ref(),
                    bundle.material,
                    operation,
                    step,
                )
            });
        if let Err(error) = acquired {
            self.note(operation, error.code, error.message)?;
        }
        Ok(())
    }

    fn observe(
        &mut self,
        principal: &PrincipalId,
        operation: &OperationId,
        step: &StepId,
        invocation: &Value,
        undo: Option<&mut UndoExecutionContext<'_>>,
    ) -> AppResult<()> {
        let record = self
            .store
            .operation(operation)
            .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?;
        self.authority
            .authorize_operation(principal, &record, Access::ObserveOperation)?;
        let observed = if crate::undo_provider::is_recovery_only_step(self.store, invocation)? {
            let bundle = undo.ok_or_else(|| {
                AppError::new(
                    "RECOVERY_EXPIRED",
                    "Registered undo observation requires its actual request composition",
                )
            })?;
            let rpc =
                bundle.open_for_observation(self.store, principal, operation, step, invocation)?;
            let claimed = mmmm_runtime::storage::undo::claimed_undo_record(
                self.store,
                operation,
                step,
                &decode(&invocation["invocationId"])?,
            )
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
            let job = bundle.material.observe_registered_undo_job_with_store(
                self.store,
                invocation,
                &claimed,
                &record.scope,
            )?;
            self.verify_provider_undo_readback(principal, rpc.as_ref(), invocation, job)?
        } else {
            self.observer
                .readback_with_store(self.store, invocation, &record.scope)?
        };
        if observed.invocation_id.as_str() != invocation["invocationId"].as_str().unwrap_or("")
            || observed.binding_id.as_str() != invocation["bindingId"].as_str().unwrap_or("")
            || observed.context_digest.as_str()
                != invocation["contextDigest"].as_str().unwrap_or("")
            || observed.implementation_digest.as_str()
                != invocation["implementationDigest"].as_str().unwrap_or("")
            || observed.arguments_digest.as_str()
                != invocation["argumentsDigest"].as_str().unwrap_or("")
        {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Independent readback does not identify the original pinned invocation",
            ));
        }
        if observed.settled && observed.effect == EffectEvidence::Unknown {
            return Err(AppError::new(
                "RECONCILIATION_INSUFFICIENT",
                "An unknown effect cannot be declared settled",
            ));
        }
        let stored = record
            .steps
            .iter()
            .find(|s| &s.step_id == step)
            .ok_or_else(|| AppError::new("OPERATION_NOT_FOUND", "Durable step is absent"))?;
        if !stored.write_effect && observed.effect != EffectEvidence::NoneConfirmed {
            return Err(AppError::new(
                "RECONCILIATION_INSUFFICIENT",
                "Read action unexpectedly reports target effects",
            ));
        }
        let output_evidence = self.evidence_values(&record)?;
        let validated_output = output_evidence.iter().any(|v| {
            v["kind"] == "provider_result"
                && v["stepId"] == step.as_str()
                && v["outputValidated"] == true
        });
        let provider_failed = output_evidence
            .iter()
            .any(|v| v["stepId"] == step.as_str() && crate::report::known_provider_failure(v));
        let source_after = if invocation["actionId"].is_string()
            && observed.settled
            && matches!(
                observed.effect,
                EffectEvidence::SomeConfirmed | EffectEvidence::CompleteConfirmed
            ) {
            let plan = self
                .store
                .plan(&record.plan_id, &record.plan_hash)
                .map_err(|error| AppError::storage("STALE_PLAN", error))?;
            let selected = plan["steps"]
                .as_array()
                .and_then(|steps| {
                    steps
                        .iter()
                        .find(|selected| selected["stepId"] == step.as_str())
                })
                .ok_or_else(|| {
                    AppError::new(
                        "STALE_PLAN",
                        "Observed source step is absent from its actual plan",
                    )
                })?;
            if selected["recovery"] == "provider_undo" {
                match self.retain_undo_after_targets(operation, selected, invocation, &observed) {
                    Ok(states) => states,
                    Err(error) => {
                        // Missing optional undo proof must not erase known
                        // physical target truth or infer a restoration image.
                        self.note(operation, error.code, error.message)?;
                        Vec::new()
                    }
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        if observed.direct_changes.len() > 4096
            || observed
                .direct_changes
                .iter()
                .try_fold(0usize, |sum, change| {
                    sum.checked_add(change.before.len())
                        .and_then(|sum| sum.checked_add(change.after.len()))
                })
                .is_none_or(|bytes| bytes > 256 * 1024 * 1024)
        {
            return Err(AppError::new(
                "BUDGET_EXCEEDED",
                "Direct readback snapshots exceed their finite capture budget",
            ));
        }
        if !observed.direct_changes.is_empty()
            && !matches!(
                observed.effect,
                EffectEvidence::SomeConfirmed | EffectEvidence::CompleteConfirmed
            )
        {
            return Err(AppError::new(
                "RECONCILIATION_INSUFFICIENT",
                "Direct changes contradict the reported effect evidence",
            ));
        }
        let captured = self.captured_before(operation, step, invocation)?;
        let mut snapshots = Vec::new();
        let mut changed_targets = std::collections::BTreeSet::new();
        let mut after_bytes = 0usize;
        for change in observed.direct_changes {
            if !changed_targets.insert(change.target.clone()) {
                return Err(AppError::new(
                    "RECONCILIATION_INSUFFICIENT",
                    "Independent after target is duplicated",
                ));
            }
            after_bytes = after_bytes
                .checked_add(change.after.len())
                .filter(|size| *size <= 128 * 1024 * 1024)
                .ok_or_else(|| {
                    AppError::new(
                        "BUDGET_EXCEEDED",
                        "Independent after images exceed their finite budget",
                    )
                })?;
            let Some(before) = captured.get(&change.target).cloned() else {
                // Legacy invocations without pre-dispatch capture cannot obtain
                // recovery authority from a post-write observer before image.
                if captured.is_empty() {
                    continue;
                }
                return Err(AppError::new(
                    "RECONCILIATION_INSUFFICIENT",
                    "Independent after target has no original durable before capture",
                ));
            };
            let after = self
                .store
                .put_blob(&change.after)
                .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
            // These artifact pins precede the observation envelope: GC does not
            // infer recursive references from arbitrary JSON payloads.
            self.store
                .pin_operation_artifact(operation, &before)
                .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
            self.store
                .pin_operation_artifact(operation, &after)
                .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
            snapshots.push(RecoverySnapshot {
                operation_id: operation.clone(),
                step_id: step.clone(),
                target: change.target,
                context_id: decode(&invocation["context"]["contextId"])?,
                binding_id: text(invocation, "bindingId")?.to_owned(),
                epoch: invocation["context"]["environment"]["sessionEpoch"]
                    .as_str()
                    .map(str::to_owned),
                before,
                after,
            });
        }
        if observed.settled
            && matches!(
                observed.effect,
                EffectEvidence::SomeConfirmed | EffectEvidence::CompleteConfirmed
            )
        {
            for (target, before) in &captured {
                if snapshots.iter().any(|snapshot| &snapshot.target == target) {
                    continue;
                }
                let bytes = self
                    .observer
                    .read_target_retained_with_store(self.store, invocation, target)?;
                after_bytes = after_bytes
                    .checked_add(bytes.len())
                    .filter(|size| *size <= 128 * 1024 * 1024)
                    .ok_or_else(|| {
                        AppError::new(
                            "BUDGET_EXCEEDED",
                            "Independent after images exceed their finite budget",
                        )
                    })?;
                let after = self
                    .store
                    .put_blob(&bytes)
                    .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
                self.store
                    .pin_operation_artifact(operation, &after)
                    .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
                snapshots.push(RecoverySnapshot {
                    operation_id: operation.clone(),
                    step_id: step.clone(),
                    target: target.clone(),
                    context_id: decode(&invocation["context"]["contextId"])?,
                    binding_id: text(invocation, "bindingId")?.to_owned(),
                    epoch: invocation["context"]["environment"]["sessionEpoch"]
                        .as_str()
                        .map(str::to_owned),
                    before: before.clone(),
                    after,
                });
            }
        }
        let retained_readbacks = self.readback_values(&record, step)?;
        for retained in retained_readbacks.iter().filter(|v| {
            v["kind"] == "independent_readback"
                && v["stepId"] == step.as_str()
                && v["invocationId"] == invocation["invocationId"]
                && v["settled"] == true
        }) {
            for entry in retained["directChanges"].as_array().into_iter().flatten() {
                let prior: RecoverySnapshot = decode(entry)?;
                let Some(before) = captured.get(&prior.target) else {
                    continue;
                };
                if before != &prior.before {
                    return Err(AppError::new(
                        "RECOVERY_EXPIRED",
                        "Retained readback before image differs from the original independent capture",
                    ));
                }
                if let Some(current) = snapshots.iter_mut().find(|s| s.target == prior.target) {
                    if current.after == prior.after {
                        // A host may no longer carry its old before image after
                        // reconnect. Reuse the retained exact settled pair rather
                        // than replace it with a post-write before observation.
                        *current = prior;
                    }
                    continue;
                }
                let current = self.observer.read_target_retained_with_store(
                    self.store,
                    invocation,
                    &prior.target,
                )?;
                if mmmm_contracts::raw_digest(&current) != prior.after.digest
                    || current.len() as u64 != prior.after.byte_length
                {
                    return Err(AppError::new(
                        "RECONCILIATION_INSUFFICIENT",
                        "Retained settled target changed before recovery metadata could be finalized",
                    ));
                }
                snapshots.push(prior);
            }
        }
        let evidence_blob = self
            .store
            .put_blob(&encode_json(&observed.evidence).map_err(|_| {
                AppError::new(
                    "RECONCILIATION_INSUFFICIENT",
                    "Independent evidence exceeds its JSON budget",
                )
            })?)
            .map_err(|e| AppError::storage("RECONCILIATION_INSUFFICIENT", e))?;
        let envelope = json!({"kind":"independent_readback", "stepId":step, "invocationId":observed.invocation_id,
            "bindingId":observed.binding_id,"contextDigest":observed.context_digest,
            "implementationDigest":observed.implementation_digest,"argumentsDigest":observed.arguments_digest,
            "effect":observed.effect,"settled":observed.settled,"sourceRefs":[evidence_blob],"directChanges":snapshots,
            "afterStates":source_after});
        let blob = self
            .store
            .put_blob(&encode_json(&envelope).map_err(|_| {
                AppError::new(
                    "RECONCILIATION_INSUFFICIENT",
                    "Independent evidence exceeds its JSON budget",
                )
            })?)
            .map_err(|e| AppError::storage("RECONCILIATION_INSUFFICIENT", e))?;
        let mut sources = vec![blob.clone(), evidence_blob];
        sources.extend(source_after.iter().map(|state| state.after.clone()));
        sources.sort_by(|left, right| left.digest.cmp(&right.digest));
        sources.dedup();
        let mut summary = crate::report::compact_evidence(&envelope, &blob)?;
        summary["sourceRefs"] = json!(sources);
        self.retain_summary(operation, &summary, &sources)?;
        self.store
            .record_observation(
                operation,
                step,
                StepObservation {
                    dispatch: DispatchEvidence::Observed,
                    effect: observed.effect,
                    further_effects_possible: !observed.settled,
                    provider_receipt: stored.provider_receipt.clone(),
                    observation_refs: vec![blob.clone()],
                    finished: false,
                },
            )
            .map_err(|e| AppError::storage("RECONCILIATION_INSUFFICIENT", e))?;
        if observed.settled {
            for snapshot in snapshots {
                self.store
                    .save_recovery_snapshot(snapshot)
                    .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
            }
        }
        if observed.settled && (validated_output || (provider_failed && stored.write_effect)) {
            self.store
                .record_observation(
                    operation,
                    step,
                    StepObservation {
                        dispatch: DispatchEvidence::Observed,
                        effect: observed.effect,
                        further_effects_possible: false,
                        provider_receipt: stored.provider_receipt.clone(),
                        observation_refs: vec![blob],
                        finished: true,
                    },
                )
                .map_err(|e| AppError::storage("RECONCILIATION_INSUFFICIENT", e))?;
        }
        Ok(())
    }

    fn ambiguous(
        &mut self,
        operation: &OperationId,
        step: &StepId,
        code: &str,
        message: &str,
    ) -> AppResult<()> {
        self.note(operation, code, message)?;
        let record = self
            .store
            .operation(operation)
            .map_err(|e| AppError::storage("OUTCOME_UNKNOWN", e))?;
        if record.steps.iter().any(|s| {
            &s.step_id == step
                && (s.finished
                    || (s.dispatch == DispatchEvidence::Observed
                        && s.effect != EffectEvidence::Unknown
                        && !s.further_effects_possible))
        }) {
            return Ok(());
        }
        self.store
            .mark_outcome_unknown(operation, step)
            .map_err(|e| AppError::storage("OUTCOME_UNKNOWN", e))?;
        Ok(())
    }

    pub(crate) fn note(
        &mut self,
        operation: &OperationId,
        code: &str,
        message: &str,
    ) -> AppResult<()> {
        let note = diagnostic(code, message);
        validate("Diagnostic", &note)?;
        let bytes = encode_json(&json!({"kind":"application_diagnostic","diagnostic":note}))
            .map_err(|_| {
                AppError::new(
                    "OUTCOME_UNKNOWN",
                    "Application evidence exceeds its JSON budget",
                )
            })?;
        let blob = self
            .store
            .put_blob(&bytes)
            .map_err(|e| AppError::storage("OUTCOME_UNKNOWN", e))?;
        let summary = crate::report::compact_evidence(
            &json!({"kind":"application_diagnostic","diagnostic":note}),
            &blob,
        )?;
        self.retain_summary(operation, &summary, std::slice::from_ref(&blob))?;
        Ok(())
    }

    pub(crate) fn retain_summary(
        &mut self,
        operation: &OperationId,
        summary: &Value,
        sources: &[mmmm_runtime::storage::BlobRef],
    ) -> AppResult<mmmm_runtime::storage::BlobRef> {
        let bytes = encode_json(summary).map_err(|_| {
            AppError::new(
                "OUTCOME_UNKNOWN",
                "Operation summary exceeds its strict JSON boundary",
            )
        })?;
        let blob = self
            .store
            .put_blob(&bytes)
            .map_err(|e| AppError::storage("OUTCOME_UNKNOWN", e))?;
        self.store
            .append_operation_summary(operation, &blob, sources)
            .map_err(|e| AppError::storage("OUTCOME_UNKNOWN", e))?;
        Ok(blob)
    }

    fn settle(&mut self, operation: &OperationId) -> AppResult<()> {
        let record = self
            .store
            .operation(operation)
            .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?;
        if record.state.terminal() {
            return Ok(());
        }
        let evidence = self.evidence_values(&record)?;
        let failed = evidence.iter().any(|v| {
            v["kind"] == "application_diagnostic" && v["diagnostic"]["severity"] == "error"
        });
        let provider_failed = evidence.iter().any(|v| {
            crate::report::known_provider_failure(v) || crate::report::unresolved_failure_history(v)
        });
        let known_effect = record.steps.iter().any(|s| {
            matches!(
                s.effect,
                EffectEvidence::SomeConfirmed | EffectEvidence::CompleteConfirmed
            )
        });
        let unknown = record
            .steps
            .iter()
            .any(|s| s.further_effects_possible || s.effect == EffectEvidence::Unknown);
        let no_effect = record.steps.iter().all(|s| {
            s.dispatch == DispatchEvidence::NotSent
                || (!s.write_effect
                    && s.effect == EffectEvidence::NoneConfirmed
                    && !s.further_effects_possible)
                || (s.finished
                    && s.effect == EffectEvidence::NoneConfirmed
                    && !s.further_effects_possible)
        });
        let verified = record.steps.iter().all(crate::report::step_verified);
        let state = if verified && !provider_failed {
            Some(OperationState::Succeeded)
        } else if no_effect && record.cancellation_requested {
            Some(OperationState::Cancelled)
        } else if no_effect && (failed || provider_failed) {
            Some(OperationState::FailedBeforeEffects)
        } else if known_effect
            && (failed || provider_failed || unknown || record.cancellation_requested || !verified)
        {
            Some(OperationState::Partial)
        } else if unknown {
            Some(OperationState::OutcomeUnknown)
        } else {
            None
        };
        if let Some(state) = state {
            self.store
                .finish_operation(operation, state)
                .map_err(|e| AppError::storage("OUTCOME_UNKNOWN", e))?;
        }
        Ok(())
    }
}

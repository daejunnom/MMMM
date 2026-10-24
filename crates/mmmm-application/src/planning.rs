use crate::*;
use mmmm_contracts::{
    ContextId, PlanId, Sha256Digest, canonical_digest, projected_digest, verify_projected_digest,
};
use mmmm_runtime::storage::WriteScope;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

impl Application<'_> {
    pub fn plan_create(&mut self, principal: &PrincipalId, input: &Value) -> AppResult<Value> {
        self.plan_create_with_undo(principal, input, None)
    }

    pub fn plan_create_with_undo(
        &mut self,
        principal: &PrincipalId,
        input: &Value,
        undo: Option<&mut UndoExecutionContext<'_>>,
    ) -> AppResult<Value> {
        validate("CreatePlanRequest", input)?;
        let project_id: ProjectId = decode(&input["projectId"])?;
        self.authority
            .authorize(principal, &project_id, Access::Plan, None, None)?;
        let project = self
            .store
            .project(&project_id)
            .map_err(|e| AppError::storage("NOT_FOUND", e))?;
        if project["revision"] != input["expectedRevision"] {
            return Err(AppError::new(
                "REVISION_CONFLICT",
                "Authoring revision changed before planning",
            ));
        }
        let context_id: ContextId = decode(&input["contextId"])?;
        let context = self.provider.context(principal, &context_id)?;
        check_context(principal, &project_id, &context_id, &context)?;
        self.authority
            .authorize(principal, &project_id, Access::Plan, Some(&context), None)?;
        let prepared = self
            .planner
            .prepare_with_store(self.store, principal, input, &project, &context)?;
        self.freeze_ordinary_plan(principal, &project, &context, prepared, undo)
    }

    /// Ordinary preparation, including trusted setup, shares one role admission
    /// boundary. Only the private validated FN15 undo path may freeze a plan for
    /// a registered recovery-only action.
    pub(crate) fn freeze_ordinary_plan(
        &mut self,
        principal: &PrincipalId,
        project: &Value,
        root_context: &Value,
        prepared: PreparedPlan,
        mut undo: Option<&mut UndoExecutionContext<'_>>,
    ) -> AppResult<Value> {
        check_prepared_limits(&prepared)?;
        let project_id: ProjectId = decode(&project["projectId"])?;
        let root_id: ContextId = decode(&root_context["contextId"])?;
        check_context(principal, &project_id, &root_id, root_context)?;
        if prepared.scope.project_id != project_id {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Prepared scope belongs to a different project",
            ));
        }
        for step in &prepared.steps {
            let context = prepared
                .contexts
                .iter()
                .find(|context| context["contextId"] == step["contextId"])
                .ok_or_else(|| {
                    AppError::new("STALE_CONTEXT", "Prepared step has no actual context")
                })?;
            check_context(
                principal,
                &project_id,
                &decode(&step["contextId"])?,
                context,
            )?;
            self.authority
                .authorize(principal, &project_id, Access::Plan, Some(context), None)?;
            let recovery_only = if let Some(bundle) = undo.as_deref_mut() {
                let descriptor = self.provider.action_descriptor(step, context)?;
                crate::undo_provider::install_selected_role(
                    bundle.material,
                    self.store,
                    principal,
                    step,
                    context,
                    &descriptor,
                )? == UndoActionRole::RecoveryOnly
            } else {
                crate::undo_provider::is_recovery_only_step(self.store, step)?
            };
            if recovery_only {
                return Err(AppError::new(
                    "RECOVERY_REQUIRED",
                    "A registered undo action requires its retained source and a separately approved recovery plan",
                ));
            }
        }
        self.freeze_plan(principal, project, root_context, prepared)
    }

    pub fn plan_inspect(&mut self, principal: &PrincipalId, input: &Value) -> AppResult<Value> {
        validate("PlanQuery", input)?;
        let id: PlanId = decode(&input["planId"])?;
        let plan = self
            .store
            .plan_by_id(&id)
            .map_err(|e| AppError::storage("PLAN_NOT_FOUND", e))?;
        let project: ProjectId = decode(&plan["projectId"])?;
        self.authority
            .authorize(principal, &project, Access::ReadPlan, None, Some(&plan))?;
        if input["contextId"] != plan["contextId"] {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Query context differs from the frozen root context",
            ));
        }
        // Reading an expired plan preserves its exact original route and pins.
        Ok(plan)
    }

    pub(crate) fn freeze_plan(
        &mut self,
        principal: &PrincipalId,
        project: &Value,
        root_context: &Value,
        prepared: PreparedPlan,
    ) -> AppResult<Value> {
        let project_id: ProjectId = decode(&project["projectId"])?;
        let root_id: ContextId = decode(&root_context["contextId"])?;
        let mut contexts = BTreeMap::new();
        check_prepared_limits(&prepared)?;
        for context in &prepared.contexts {
            let id: ContextId = decode(&context["contextId"])?;
            check_context(principal, &project_id, &id, context)?;
            if context["policyRevision"] != root_context["policyRevision"] {
                return Err(AppError::new(
                    "STALE_CONTEXT",
                    "Steps require one current policy revision",
                ));
            }
            if contexts.insert(id, context).is_some() {
                return Err(AppError::new(
                    "INVALID_INPUT",
                    "Duplicate prepared context ID",
                ));
            }
        }
        if contexts.get(&root_id).copied() != Some(root_context) {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Prepared plan did not retain the exact root context",
            ));
        }
        if prepared.scope.project_id != project_id {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Plan scope belongs to a different project",
            ));
        }
        prepared
            .scope
            .validate()
            .map_err(|e| AppError::storage("INVALID_INPUT", e))?;
        let pins: Vec<Value> = contexts.values().map(|c| json!({
            "contextId":c["contextId"], "contextDigest":c["contextDigest"], "environment":c["environment"]
        })).collect();
        let mut descriptors = BTreeMap::new();
        for step in &prepared.steps {
            validate("PlanStep", step)?;
            let id: ContextId = decode(&step["contextId"])?;
            let context = contexts.get(&id).ok_or_else(|| {
                AppError::new("STALE_CONTEXT", "Step context has no immutable pin")
            })?;
            let descriptor = self.provider.action_descriptor(step, context)?;
            check_descriptor(step, context, &descriptor)?;
            self.store
                .register_result_action(&decode(&step["bindingId"])?, &descriptor)
                .map_err(|e| AppError::storage("CAPABILITY_UNAVAILABLE", e))?;
            let step_id = step["stepId"].as_str().ok_or_else(|| {
                AppError::new("INVALID_INPUT", "Prepared step identity is absent")
            })?;
            if descriptors.insert(step_id.to_owned(), descriptor).is_some() {
                return Err(AppError::new(
                    "INVALID_INPUT",
                    "Duplicate prepared step identity",
                ));
            }
        }
        for step in &prepared.steps {
            self.check_result_bindings(&prepared.steps, &descriptors, step)?;
        }
        let order = step_order(&prepared.steps)?;
        check_conflict_order(&prepared.steps, &order)?;
        let plan_id = PlanId::new(self.ids.next_id(IdKind::Plan)?).map_err(|_| {
            AppError::new(
                "INVALID_INPUT",
                "ID source returned an invalid plan identity",
            )
        })?;
        let mut plan = json!({
            "contractVersion":"0.2.0", "planId":plan_id, "planHash":"0".repeat(64),
            "projectId":project_id, "contextId":root_id, "policyRevision":root_context["policyRevision"],
            "expiresAt":prepared.expires_at, "scope":prepared.scope, "preconditions":prepared.preconditions,
            "steps":prepared.steps, "atomicity":prepared.atomicity, "losses":prepared.losses,
            "diagnostics":prepared.diagnostics, "approvalRequirement":prepared.approval_requirement,
            "contextPins":pins, "dependencyPins":prepared.dependency_pins,
            "projectBaseRevision":project["revision"], "timeBudgetMs":prepared.time_budget_ms
        });
        validate("ExecutionPlan", &plan)?;
        ensure_unexpired(self.clock, &plan)?;
        if plan["steps"]
            .as_array()
            .is_some_and(|s| s.iter().any(|s| s["effect"] == "unknown"))
            && plan["approvalRequirement"] != "explicit_approval"
        {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Unknown effects require explicit approval",
            ));
        }
        if !plan["losses"].as_array().is_some_and(|v| v.is_empty())
            && plan["approvalRequirement"] != "explicit_approval"
        {
            return Err(AppError::new(
                "LOSS_APPROVAL_REQUIRED",
                "Declared losses require explicit approval",
            ));
        }
        plan["planHash"] = json!(
            projected_digest("ExecutionPlan", &plan)
                .map_err(|_| AppError::new("INVALID_INPUT", "Plan digest could not be derived"))?
        );
        self.authority.authorize(
            principal,
            &project_id,
            Access::Plan,
            Some(root_context),
            Some(&plan),
        )?;
        // Only private durable plan/CAS state changes. Target effects remain absent.
        self.store
            .save_plan(&plan)
            .map_err(|e| AppError::storage("INVALID_INPUT", e))?;
        Ok(plan)
    }

    pub(crate) fn live_context(
        &mut self,
        principal: &PrincipalId,
        plan: &Value,
        context_id: &ContextId,
    ) -> AppResult<Value> {
        let project: ProjectId = decode(&plan["projectId"])?;
        let context = self.provider.context(principal, context_id)?;
        check_context(principal, &project, context_id, &context)?;
        let pin = plan["contextPins"]
            .as_array()
            .and_then(|p| p.iter().find(|p| p["contextId"] == context_id.as_str()))
            .ok_or_else(|| AppError::new("STALE_CONTEXT", "Step has no frozen context pin"))?;
        if context["contextDigest"] != pin["contextDigest"]
            || context["environment"] != pin["environment"]
            || context["policyRevision"] != plan["policyRevision"]
        {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Live context, session or policy differs from the frozen plan",
            ));
        }
        Ok(context)
    }

    pub(crate) fn observation_context(
        &mut self,
        principal: &PrincipalId,
        plan: &Value,
        context_id: &ContextId,
    ) -> AppResult<Value> {
        let project: ProjectId = decode(&plan["projectId"])?;
        let context = self.provider.context(principal, context_id)?;
        check_context(principal, &project, context_id, &context)?;
        let pin = plan["contextPins"]
            .as_array()
            .and_then(|pins| pins.iter().find(|p| p["contextId"] == context_id.as_str()))
            .ok_or_else(|| {
                AppError::new(
                    "STALE_CONTEXT",
                    "Original observation context pin is absent",
                )
            })?;
        if context["environment"] != pin["environment"] {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Observation binding belongs to a different environment or session",
            ));
        }
        // Current Observe/Cancel/Recovery grants are evaluated separately. A
        // revoked Apply policy may change this digest without changing the old
        // job identity; no new dispatch is authorized by this method.
        Ok(context)
    }

    /// Reconciliation alone can use an independently admitted successor read
    /// context. The original invocation and its frozen pin remain unchanged.
    pub(crate) fn reconciliation_context(
        &mut self,
        principal: &PrincipalId,
        plan: &Value,
        original: &Value,
        scope: &WriteScope,
    ) -> AppResult<Value> {
        let Some(context) = self
            .provider
            .successor_observation_context_with_store(self.store, principal, original)?
        else {
            return self.observation_context(
                principal,
                plan,
                &decode(&original["context"]["contextId"])?,
            );
        };
        let project: ProjectId = decode(&plan["projectId"])?;
        let current_id: ContextId = decode(&context["contextId"])?;
        check_context(principal, &project, &current_id, &context)?;
        let original_context = &original["context"];
        validate("ExecutionContext", original_context)?;
        verify_projected_digest("ExecutionContext", original_context).map_err(|_| {
            AppError::new(
                "STALE_CONTEXT",
                "Original observation context digest is invalid",
            )
        })?;
        let pin = plan["contextPins"]
            .as_array()
            .and_then(|pins| {
                pins.iter()
                    .find(|pin| pin["contextId"] == original_context["contextId"])
            })
            .ok_or_else(|| {
                AppError::new(
                    "STALE_CONTEXT",
                    "Original observation context pin is absent",
                )
            })?;
        if original_context["projectId"] != project.as_str()
            || original["contextDigest"] != original_context["contextDigest"]
            || original["contextDigest"] != pin["contextDigest"]
            || original_context["environment"] != pin["environment"]
        {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Successor observation does not identify the original frozen context",
            ));
        }
        check_successor_environment(&original_context["environment"], &context["environment"])?;
        let current_scope: WriteScope = decode(&context["scope"])?;
        if !scope_contains(&current_scope, scope) {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Successor observation context does not cover the original operation scope",
            ));
        }
        Ok(context)
    }

    pub(crate) fn preflight_with_undo(
        &mut self,
        principal: &PrincipalId,
        plan: &Value,
        step: &Value,
        operation: &mmmm_contracts::OperationId,
        undo: Option<&mut UndoExecutionContext<'_>>,
    ) -> AppResult<(Value, Value, bool)> {
        ensure_unexpired(self.clock, plan)?;
        let project_id: ProjectId = decode(&plan["projectId"])?;
        let project = self
            .store
            .project(&project_id)
            .map_err(|e| AppError::storage("REVISION_CONFLICT", e))?;
        if project["revision"] != plan["projectBaseRevision"] {
            return Err(AppError::new(
                "REVISION_CONFLICT",
                "Project changed after this plan was frozen",
            ));
        }
        let id: ContextId = decode(&step["contextId"])?;
        let context = self.live_context(principal, plan, &id)?;
        self.authority.authorize(
            principal,
            &project_id,
            Access::Apply,
            Some(&context),
            Some(plan),
        )?;
        let descriptor = self.provider.action_descriptor(step, &context)?;
        check_descriptor(step, &context, &descriptor)?;
        self.provider.verify_dependencies(
            plan["dependencyPins"]
                .as_array()
                .ok_or_else(|| AppError::new("STALE_PLAN", "Dependency pins are absent"))?,
            &context,
        )?;
        let recovery_only = if let Some(bundle) = undo {
            crate::undo_provider::install_selected_role(
                bundle.material,
                self.store,
                principal,
                step,
                &context,
                &descriptor,
            )? == UndoActionRole::RecoveryOnly
        } else {
            crate::undo_provider::is_recovery_only_step(self.store, step)?
        };
        let preconditions = plan["preconditions"]
            .as_array()
            .ok_or_else(|| AppError::new("STALE_PLAN", "Preconditions are absent"))?;
        if recovery_only {
            let written: BTreeSet<String> = decode::<Vec<String>>(&step["resourcesWritten"])?
                .into_iter()
                .collect();
            let mut targets = BTreeSet::new();
            if written.is_empty()
                || !preconditions.iter().all(|condition| {
                    condition["kind"] == "resource_hash"
                        && condition["coverage"] == "full_target"
                        && condition["subject"].as_str().is_some_and(|target| {
                            written.contains(target) && targets.insert(target.to_owned())
                        })
                })
                || targets != written
            {
                return Err(AppError::new(
                    "RECOVERY_CONFLICT",
                    "Registered undo requires exactly its frozen full-target source-after preconditions",
                ));
            }
            // Live target reads are performed through the immutable original
            // source locator before capture and again before atomic claim. The
            // closed undo arguments cannot select the generic provider target.
            return Ok((context, descriptor, true));
        }
        let phase_expected = self.phase_expected_digests(plan, step, operation)?;
        let conditions: Vec<&Value> = preconditions.iter().collect();
        let observed_batch = self
            .provider
            .observe_plan_preconditions_retained_with_store(
                self.store,
                plan,
                step,
                &conditions,
                &context,
            )?;
        if observed_batch
            .as_ref()
            .is_some_and(|digests| digests.len() != preconditions.len())
        {
            return Err(AppError::new(
                "TARGET_DRIFT",
                "A frozen precondition observation batch changed its target count",
            ));
        }
        for (index, precondition) in preconditions.iter().enumerate() {
            let expected: Sha256Digest = phase_expected
                .get(&(
                    text(precondition, "kind")?.to_owned(),
                    text(precondition, "subject")?.to_owned(),
                ))
                .cloned()
                .map(Ok)
                .unwrap_or_else(|| decode(&precondition["expected"]))?;
            let observed = match &observed_batch {
                Some(digests) => digests[index].clone(),
                None => self
                    .provider
                    .observe_plan_precondition_retained_with_store(
                        self.store,
                        plan,
                        step,
                        precondition,
                        &context,
                    )?,
            };
            if observed != expected {
                return Err(AppError::new(
                    "TARGET_DRIFT",
                    "A frozen precondition no longer matches the actual target",
                ));
            }
        }
        Ok((context, descriptor, false))
    }
    pub(crate) fn phase_expected_digests(
        &self,
        plan: &Value,
        step: &Value,
        operation: &mmmm_contracts::OperationId,
    ) -> AppResult<BTreeMap<(String, String), Sha256Digest>> {
        let id: ContextId = decode(&step["contextId"])?;
        let preconditions = plan["preconditions"]
            .as_array()
            .ok_or_else(|| AppError::new("STALE_PLAN", "Preconditions are absent"))?;
        let mut phase_expected: BTreeMap<(String, String), Sha256Digest> = BTreeMap::new();
        for precondition in preconditions {
            if matches!(
                precondition["kind"].as_str(),
                Some("resource_hash" | "region_snapshot")
            ) {
                let key = (
                    text(precondition, "kind")?.to_owned(),
                    text(precondition, "subject")?.to_owned(),
                );
                let digest: Sha256Digest = decode(&precondition["expected"])?;
                if phase_expected
                    .insert(key, digest.clone())
                    .is_some_and(|old| old != digest)
                {
                    return Err(AppError::new(
                        "STALE_PLAN",
                        "One precondition target has contradictory original digests",
                    ));
                }
            }
        }
        if !phase_expected.is_empty() {
            // Read durable phase evidence once. Each snapshot is visited once in
            // frozen DAG order, without rescanning CAS per precondition.
            let record = self
                .store
                .operation(operation)
                .map_err(|e| AppError::storage("STALE_PLAN", e))?;
            let snapshots = self
                .store
                .recovery_snapshots(operation)
                .map_err(|e| AppError::storage("STALE_PLAN", e))?;
            let records: BTreeMap<&str, _> = record
                .steps
                .iter()
                .map(|s| (s.step_id.as_str(), s))
                .collect();
            let evidence = self.evidence_values(&record)?;
            let failed: BTreeSet<String> = record
                .steps
                .iter()
                .filter(|step| {
                    evidence.iter().any(|value| {
                        crate::report::failure_blocks_step(value, step.step_id.as_str())
                    })
                })
                .map(|step| step.step_id.as_str().to_owned())
                .collect();
            let mut by_step: BTreeMap<&str, Vec<_>> = BTreeMap::new();
            for snapshot in &snapshots {
                by_step
                    .entry(snapshot.step_id.as_str())
                    .or_default()
                    .push(snapshot);
            }
            let steps = plan["steps"]
                .as_array()
                .ok_or_else(|| AppError::new("STALE_PLAN", "Frozen steps are absent"))?;
            for prior in step_order(steps)? {
                if steps[prior]["stepId"] == step["stepId"] {
                    break;
                }
                let prior_id = text(&steps[prior], "stepId")?;
                if failed.contains(prior_id)
                    || !records
                        .get(prior_id)
                        .is_some_and(|stored| crate::report::step_verified(stored))
                {
                    continue;
                }
                for snapshot in by_step
                    .get(prior_id)
                    .into_iter()
                    .flatten()
                    .filter(|s| s.context_id == id)
                {
                    for kind in ["resource_hash", "region_snapshot"] {
                        let Some(expected) =
                            phase_expected.get_mut(&(kind.to_owned(), snapshot.target.clone()))
                        else {
                            continue;
                        };
                        if snapshot.before.digest != *expected {
                            return Err(AppError::new(
                                "TARGET_DRIFT",
                                "Recorded direct-change chain differs from the original precondition",
                            ));
                        }
                        *expected = snapshot.after.digest.clone();
                    }
                }
            }
        }
        Ok(phase_expected)
    }
}

pub(crate) fn ensure_unexpired(clock: &dyn Clock, plan: &Value) -> AppResult<()> {
    let expiry = OffsetDateTime::parse(text(plan, "expiresAt")?, &Rfc3339).map_err(|_| {
        AppError::new(
            "STALE_PLAN",
            "Plan expiration is not an interpretable RFC 3339 timestamp",
        )
    })?;
    if clock.unix_nanos() >= expiry.unix_timestamp_nanos() {
        return Err(AppError::new("STALE_PLAN", "Frozen plan has expired"));
    }
    Ok(())
}

pub(crate) fn invocation_deadline(
    clock: &dyn Clock,
    plan: &Value,
    remaining_ms: u64,
) -> AppResult<String> {
    let expiry = OffsetDateTime::parse(text(plan, "expiresAt")?, &Rfc3339).map_err(|_| {
        AppError::new(
            "STALE_PLAN",
            "Plan expiration is not an interpretable timestamp",
        )
    })?;
    let budget_end = clock
        .unix_nanos()
        .checked_add(i128::from(remaining_ms) * 1_000_000)
        .ok_or_else(|| AppError::new("BUDGET_EXCEEDED", "Invocation deadline overflowed"))?;
    OffsetDateTime::from_unix_timestamp_nanos(expiry.unix_timestamp_nanos().min(budget_end))
        .map_err(|_| {
            AppError::new(
                "BUDGET_EXCEEDED",
                "Invocation deadline is outside the supported clock range",
            )
        })?
        .format(&Rfc3339)
        .map_err(|_| AppError::new("BUDGET_EXCEEDED", "Invocation deadline cannot be encoded"))
}

fn check_prepared_limits(prepared: &PreparedPlan) -> AppResult<()> {
    if prepared.contexts.len() > 128
        || prepared.steps.len() > 4096
        || prepared.preconditions.len() > 4096
        || prepared.dependency_pins.len() > 1024
        || prepared.time_budget_ms == 0
        || prepared.time_budget_ms > 3_600_000
    {
        return Err(AppError::new(
            "BUDGET_EXCEEDED",
            "Prepared plan exceeds finite application budgets",
        ));
    }
    Ok(())
}

fn check_successor_environment(original: &Value, current: &Value) -> AppResult<()> {
    let original_epoch = original["sessionEpoch"].as_str();
    let current_epoch = current["sessionEpoch"].as_str();
    let valid_epochs = original_epoch.is_some_and(|epoch| !epoch.is_empty())
        && current_epoch.is_some_and(|epoch| !epoch.is_empty())
        && original_epoch != current_epoch;
    let actual_game = current["kind"] == "game"
        && current["worldId"].as_str().is_some_and(|id| !id.is_empty())
        && current["gameInstanceId"]
            .as_str()
            .is_some_and(|id| !id.is_empty());
    let mut original_identity = original
        .as_object()
        .cloned()
        .ok_or_else(|| AppError::new("STALE_CONTEXT", "Original game environment is absent"))?;
    let mut current_identity = current
        .as_object()
        .cloned()
        .ok_or_else(|| AppError::new("STALE_CONTEXT", "Successor game environment is absent"))?;
    original_identity.remove("sessionEpoch");
    current_identity.remove("sessionEpoch");
    if !valid_epochs || !actual_game || original_identity != current_identity {
        return Err(AppError::new(
            "STALE_CONTEXT",
            "Successor observation requires the same actual game and world with a new session",
        ));
    }
    Ok(())
}

fn scope_contains(current: &WriteScope, original: &WriteScope) -> bool {
    current.project_id == original.project_id
        && original
            .resource_ids
            .iter()
            .all(|id| current.resource_ids.contains(id))
        && original
            .object_ids
            .iter()
            .all(|id| current.object_ids.contains(id))
        && original
            .external_target_ids
            .iter()
            .all(|id| current.external_target_ids.contains(id))
        && original.regions.iter().all(|original_region| {
            current.regions.iter().any(|current_region| {
                current_region.world_id == original_region.world_id
                    && current_region.dimension == original_region.dimension
                    && (0..3).all(|axis| {
                        current_region.min[axis] <= original_region.min[axis]
                            && current_region.max_exclusive[axis]
                                >= original_region.max_exclusive[axis]
                    })
            })
        })
}

pub(crate) fn check_context(
    principal: &PrincipalId,
    project: &ProjectId,
    id: &ContextId,
    context: &Value,
) -> AppResult<()> {
    validate("ExecutionContext", context)?;
    verify_projected_digest("ExecutionContext", context)
        .map_err(|_| AppError::new("STALE_CONTEXT", "Execution context digest is invalid"))?;
    if context["contextId"] != id.as_str()
        || context["principalRef"] != principal.as_str()
        || context["projectId"] != project.as_str()
    {
        return Err(AppError::new(
            "PERMISSION_REQUIRED",
            "Execution context does not belong to this authenticated principal and project",
        ));
    }
    let scope: WriteScope = decode(&context["scope"])?;
    scope
        .validate()
        .map_err(|e| AppError::storage("INVALID_INPUT", e))?;
    if scope.project_id != *project {
        return Err(AppError::new(
            "PERMISSION_REQUIRED",
            "Context scope belongs to a different project",
        ));
    }
    Ok(())
}

pub(crate) fn check_descriptor(step: &Value, context: &Value, descriptor: &Value) -> AppResult<()> {
    validate("ActionDescriptor", descriptor)?;
    let digest = canonical_digest(descriptor)
        .map_err(|_| AppError::new("STALE_PLAN", "Action descriptor digest is invalid"))?;
    if step["actionId"] != descriptor["actionId"]
        || step["actionContractVersion"] != descriptor["contractVersion"]
        || step["actionDigest"] != digest.as_str()
        || step["implementationDigest"] != descriptor["implementationDigest"]
        || step["effect"] != descriptor["effect"]
        || step["completion"] != descriptor["completion"]
        || step["recovery"] != descriptor["recovery"]
        || step["verificationRequirement"] != descriptor["verificationRequirement"]
    {
        return Err(AppError::new(
            "STALE_PLAN",
            "Frozen action contract, implementation or behavior pins changed",
        ));
    }
    if descriptor["side"] != context["environment"]["side"] {
        return Err(AppError::new(
            "CAPABILITY_UNAVAILABLE",
            "Action side differs from the step's actual context",
        ));
    }
    for required in descriptor["requiredContext"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let present = match required.as_str() {
            Some("world") => !context["environment"]["worldId"].is_null(),
            Some("executor") => !context["executorHandle"].is_null(),
            Some("origin") => !context["origin"].is_null(),
            Some("rotation") => !context["rotationDegrees"].is_null(),
            Some("anchor") => !context["anchor"].is_null(),
            Some("selection") => !context["selectionRef"].is_null(),
            Some("dimension") => !context["dimension"].is_null(),
            Some("project") => !context["projectId"].is_null(),
            _ => false,
        };
        if !present {
            return Err(AppError::new(
                "CAPABILITY_UNAVAILABLE",
                "A required action context field is unavailable",
            ));
        }
    }
    ContractValidator::shared()
        .map_err(AppError::contract)?
        .compile_action_schema(&descriptor["inputSchema"])
        .map_err(AppError::contract)?
        .validate(&step["arguments"])
        .map_err(AppError::contract)
}

pub(crate) fn step_order(steps: &[Value]) -> AppResult<Vec<usize>> {
    let mut ids = BTreeMap::new();
    for (i, step) in steps.iter().enumerate() {
        if ids.insert(text(step, "stepId")?, i).is_some() {
            return Err(AppError::new(
                "INVALID_INPUT",
                "Duplicate plan step identity",
            ));
        }
    }
    let mut order = Vec::with_capacity(steps.len());
    let mut visited = BTreeSet::new();
    while order.len() < steps.len() {
        let mut advanced = false;
        for (i, step) in steps.iter().enumerate() {
            if visited.contains(&i) {
                continue;
            }
            let dependencies = step["dependsOn"]
                .as_array()
                .ok_or_else(|| AppError::new("INVALID_INPUT", "Step dependency list is absent"))?;
            let mut ready = true;
            for dependency in dependencies {
                let index = ids
                    .get(dependency.as_str().ok_or_else(|| {
                        AppError::new("INVALID_INPUT", "Dependency identity is invalid")
                    })?)
                    .ok_or_else(|| {
                        AppError::new("INVALID_INPUT", "Step dependency does not exist")
                    })?;
                ready &= visited.contains(index);
            }
            if ready {
                visited.insert(i);
                order.push(i);
                advanced = true;
            }
        }
        if !advanced {
            return Err(AppError::new(
                "INVALID_INPUT",
                "Step dependency graph contains a cycle",
            ));
        }
    }
    Ok(order)
}

fn check_conflict_order(steps: &[Value], order: &[usize]) -> AppResult<()> {
    let ids: BTreeMap<&str, usize> = steps
        .iter()
        .enumerate()
        .map(|(i, s)| (s["stepId"].as_str().unwrap_or(""), i))
        .collect();
    let mut ancestors = vec![BTreeSet::<usize>::new(); steps.len()];
    for &i in order {
        for dependency in steps[i]["dependsOn"].as_array().into_iter().flatten() {
            let prior = ids[dependency.as_str().unwrap_or("")];
            let previous = ancestors[prior].clone();
            ancestors[i].insert(prior);
            ancestors[i].extend(previous);
        }
    }
    for (left, a) in steps.iter().enumerate() {
        for (right, b) in steps.iter().enumerate().skip(left + 1) {
            let writes_a: BTreeSet<&str> = a["resourcesWritten"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            let writes_b: BTreeSet<&str> = b["resourcesWritten"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            let used_a: BTreeSet<&str> = a["resourcesRead"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .chain(writes_a.iter().copied())
                .collect();
            let used_b: BTreeSet<&str> = b["resourcesRead"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .chain(writes_b.iter().copied())
                .collect();
            let conflict = !writes_a.is_disjoint(&used_b)
                || !writes_b.is_disjoint(&used_a)
                || (a["effect"] != "read"
                    && b["effect"] != "read"
                    && (writes_a.is_empty() || writes_b.is_empty()));
            if conflict && !ancestors[right].contains(&left) && !ancestors[left].contains(&right) {
                return Err(AppError::new(
                    "INVALID_INPUT",
                    "Conflicting step footprints need an explicit dependency order",
                ));
            }
        }
    }
    Ok(())
}

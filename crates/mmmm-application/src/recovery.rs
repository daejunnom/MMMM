use crate::planning::{check_context, step_order};
use crate::*;
use mmmm_contracts::{ContextId, OperationId};
use serde_json::{Value, json};
use std::collections::BTreeMap;

impl Application<'_> {
    pub fn recovery_plan(&mut self, principal: &PrincipalId, input: &Value) -> AppResult<Value> {
        validate("RecoveryRequest", input)?;
        let operation: OperationId = decode(&input["operationId"])?;
        let context_id: ContextId = decode(&input["contextId"])?;
        let record = self.authorized_operation(
            principal,
            &json!({"operationId":operation,"contextId":context_id}),
            Access::Recovery,
        )?;
        if input["mode"] != "recorded_direct" {
            // No token registry exists yet. A descriptor claiming undo support
            // cannot supply a valid session-bound durable token by itself.
            return Err(AppError::new(
                "RECOVERY_EXPIRED",
                "No retained provider undo token is available for this operation",
            ));
        }
        let project = self
            .store
            .project(&record.project_id)
            .map_err(|e| AppError::storage("NOT_FOUND", e))?;
        let context = self.provider.context(principal, &context_id)?;
        check_context(principal, &record.project_id, &context_id, &context)?;
        self.authority.authorize(
            principal,
            &record.project_id,
            Access::Recovery,
            Some(&context),
            None,
        )?;
        let mut snapshots = self
            .store
            .recovery_snapshots(&operation)
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        if snapshots.is_empty() {
            return Err(AppError::new(
                "RECOVERY_EXPIRED",
                "No recorded direct target snapshots are available",
            ));
        }
        if snapshots.len() > 4096 {
            return Err(AppError::new(
                "BUDGET_EXCEEDED",
                "Recovery target count exceeds its finite budget",
            ));
        }
        let original = self
            .store
            .plan(&record.plan_id, &record.plan_hash)
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        let steps = original["steps"].as_array().ok_or_else(|| {
            AppError::new("RECOVERY_EXPIRED", "Original frozen step graph is absent")
        })?;
        let order = step_order(steps)?;
        let rank: BTreeMap<&str, usize> = order
            .iter()
            .enumerate()
            .map(|(rank, index)| (steps[*index]["stepId"].as_str().unwrap_or(""), rank))
            .collect();
        snapshots.sort_by_key(|s| rank.get(s.step_id.as_str()).copied().unwrap_or(usize::MAX));
        let mut chains: BTreeMap<String, Vec<mmmm_runtime::storage::RecoverySnapshot>> =
            BTreeMap::new();
        for snapshot in snapshots {
            let invocation = self
                .store
                .stored_invocation(&operation, &snapshot.step_id)
                .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
            if self
                .captured_before(&operation, &snapshot.step_id, &invocation)?
                .get(&snapshot.target)
                != Some(&snapshot.before)
            {
                return Err(AppError::new(
                    "RECOVERY_EXPIRED",
                    "Recorded direct recovery has no matching original independent before capture",
                ));
            }
            let chain = chains.entry(snapshot.target.clone()).or_default();
            if chain.last().is_some_and(|previous| {
                previous.after != snapshot.before
                    || previous.context_id != snapshot.context_id
                    || previous.epoch != snapshot.epoch
            }) {
                return Err(AppError::new(
                    "RECOVERY_CONFLICT",
                    "Recorded direct target changes do not form one exact before-to-after chain",
                ));
            }
            chain.push(snapshot);
        }
        let mut targets = Vec::new();
        for (_, source_snapshots) in chains {
            let snapshot = source_snapshots.last().ok_or_else(|| {
                AppError::new("RECOVERY_EXPIRED", "Recorded direct chain is empty")
            })?;
            let first_before = &source_snapshots
                .first()
                .ok_or_else(|| AppError::new("RECOVERY_EXPIRED", "Recorded direct chain is empty"))?
                .before;
            let invocation = self
                .store
                .stored_invocation(&operation, &snapshot.step_id)
                .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
            if snapshot.context_id != context_id
                || invocation["context"]["environment"] != context["environment"]
            {
                return Err(AppError::new(
                    "RECOVERY_EXPIRED",
                    "Recovery belongs to an earlier binding, world or session epoch",
                ));
            }
            let current =
                self.observer
                    .read_target_with_store(self.store, &invocation, &snapshot.target)?;
            let current_ref = self
                .store
                .put_blob(&current)
                .map_err(|e| AppError::storage("RECOVERY_CONFLICT", e))?;
            let retained = self
                .store
                .recovery_snapshot(
                    &operation,
                    &snapshot.step_id,
                    &snapshot.target,
                    &context_id,
                    &snapshot.binding_id,
                    context["environment"]["sessionEpoch"].as_str(),
                    &current_ref,
                )
                .map_err(|e| AppError::storage("RECOVERY_CONFLICT", e))?;
            let before = self
                .store
                .read_blob(first_before)
                .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
            targets.push(RecoveryTarget {
                snapshot: retained,
                source_snapshots,
                before_bytes: before,
                current_after_bytes: current,
            });
        }
        let prepared = self.planner.prepare_recovery_with_store(
            self.store,
            principal,
            &RecoveryPreparation {
                operation_id: operation,
                context_id,
                targets: targets.clone(),
            },
            &project,
            &context,
        )?;
        // Every exact after digest is checked again by normal apply preflight.
        // A recovery planner cannot omit it and overwrite a later manual edit.
        for target in &targets {
            if !prepared.preconditions.iter().any(|p| {
                p["subject"] == target.snapshot.target
                    && p["expected"] == target.snapshot.after.digest.as_str()
                    && p["coverage"] == "full_target"
            }) {
                return Err(AppError::new(
                    "RECOVERY_CONFLICT",
                    "Recovery plan omitted an exact current after-state precondition",
                ));
            }
        }
        self.freeze_plan(principal, &project, &context, prepared)
    }
}

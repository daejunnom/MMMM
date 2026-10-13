use crate::*;
use mmmm_runtime::storage::{
    DispatchEvidence, EffectEvidence, OperationRecord, OperationState, StepRecord,
    VerificationRequirement,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

impl Application<'_> {
    pub(crate) fn evidence_values(&self, record: &OperationRecord) -> AppResult<Vec<Value>> {
        let mut blobs = self
            .store
            .operation_evidence(&record.operation_id)
            .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?;
        for step in &record.steps {
            for blob in &step.observation_refs {
                if !blobs.contains(blob) {
                    blobs.push(blob.clone());
                }
            }
        }
        if blobs.len() > 8192 {
            return Err(AppError::new(
                "BUDGET_EXCEEDED",
                "Operation evidence exceeds the finite summary budget",
            ));
        }
        if blobs
            .iter()
            .try_fold(0u64, |size, blob| size.checked_add(blob.byte_length))
            .is_none_or(|size| size > 16 * 1024 * 1024)
        {
            return Err(AppError::new(
                "BUDGET_EXCEEDED",
                "Operation evidence requires a paged read beyond this summary budget",
            ));
        }
        let mut values = Vec::new();
        for blob in blobs {
            let bytes = self
                .store
                .read_blob(&blob)
                .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?;
            let value = mmmm_contracts::parse_json(&bytes).map_err(|_| {
                AppError::new(
                    "INVALID_STORED_EVIDENCE",
                    "Stored operation evidence is not strict JSON",
                )
            })?;
            values.push(value);
        }
        Ok(values)
    }

    pub(crate) fn operation_report(&self, record: &OperationRecord) -> AppResult<Value> {
        let evidence = self.evidence_values(record)?;
        let mut diagnostics = Vec::new();
        let mut provider_results = Vec::new();
        let mut artifacts = Vec::<Value>::new();
        let mut failed_steps = BTreeSet::new();
        for value in evidence {
            if value["kind"] == "application_diagnostic" {
                validate("Diagnostic", &value["diagnostic"])?;
                if !diagnostics.contains(&value["diagnostic"]) {
                    diagnostics.push(value["diagnostic"].clone());
                }
            } else if value["kind"] == "provider_result"
                && validate("ProviderResult", &value["value"]).is_ok()
            {
                if value["value"]["status"] == "failed" {
                    failed_steps.insert(value["stepId"].as_str().unwrap_or("").to_owned());
                }
                provider_results.push(json!({"stepId":value["stepId"],"response":value["value"]}));
                for d in value["value"]["diagnostics"]
                    .as_array()
                    .into_iter()
                    .flatten()
                {
                    if !diagnostics.contains(d) {
                        diagnostics.push(d.clone());
                    }
                }
                // References retain identity; digest knowledge alone never grants
                // permission to artifact.read in any facade.
                for artifact in value["value"]["artifacts"].as_array().into_iter().flatten() {
                    if !artifacts.contains(artifact) {
                        artifacts.push(artifact.clone());
                    }
                }
            }
        }
        let completed: Vec<_> = record
            .steps
            .iter()
            .filter(|s| step_verified(s) && !failed_steps.contains(s.step_id.as_str()))
            .map(|s| s.step_id.clone())
            .collect();
        let pending: Vec<_> = record
            .steps
            .iter()
            .filter(|s| s.dispatch == DispatchEvidence::NotSent && !record.state.terminal())
            .map(|s| s.step_id.clone())
            .collect();
        let unverified: Vec<_> = record
            .steps
            .iter()
            .filter(|s| {
                s.dispatch != DispatchEvidence::NotSent
                    && (!step_verified(s) || failed_steps.contains(s.step_id.as_str()))
            })
            .map(|s| s.step_id.clone())
            .collect();
        let max_dispatch = record
            .steps
            .iter()
            .map(|s| s.dispatch)
            .max()
            .unwrap_or(DispatchEvidence::NotSent);
        let dispatch = match max_dispatch {
            DispatchEvidence::NotSent => "not_dispatched",
            DispatchEvidence::IntentDurable | DispatchEvidence::Sent => "dispatched",
            DispatchEvidence::Acknowledged => "provider_acknowledged",
            DispatchEvidence::Observed => "readback_confirmed",
        };
        let any_readback = record
            .steps
            .iter()
            .any(|s| s.dispatch == DispatchEvidence::Observed);
        let verification = if any_readback {
            "independent_readback"
        } else if max_dispatch >= DispatchEvidence::Acknowledged {
            "provider_report_only"
        } else {
            "not_run"
        };
        let unknown = record
            .steps
            .iter()
            .any(|s| s.further_effects_possible || s.effect == EffectEvidence::Unknown);
        let next = if record.state.terminal() {
            "none"
        } else if unknown
            || record.state == OperationState::OutcomeUnknown
            || record
                .steps
                .iter()
                .any(|s| s.dispatch != DispatchEvidence::NotSent && !s.finished)
        {
            "reconcile"
        } else if record.state == OperationState::Partial {
            "request_review"
        } else {
            "poll"
        };
        let snapshots = self
            .store
            .recovery_snapshots(&record.operation_id)
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        let recovery = if snapshots.is_empty() {
            json!({"mode":"none","coverage":"none"})
        } else {
            json!({"mode":"explicit_patch","coverage":"recorded_direct_changes"})
        };
        let step_evidence: Vec<_> = record.steps.iter().map(|s| json!({
            "stepId":s.step_id, "dispatch":s.dispatch, "effect":s.effect,
            "providerReceipt":s.provider_receipt, "furtherEffectsPossible":s.further_effects_possible,
            "observationRefs":s.observation_refs.iter().map(|b| format!("obs-{}",b.digest)).collect::<Vec<_>>()
        })).collect();
        let output = json!({
            "contractVersion":"0.2.0", "operationId":record.operation_id, "planId":record.plan_id,
            "state":record.state, "dispatchEvidence":dispatch, "completedStepIds":completed,
            "pendingStepIds":pending, "unverifiedStepIds":unverified,
            "result":{"providerResults":provider_results},"diagnostics":diagnostics,"artifacts":artifacts,
            "recovery":recovery,"verification":verification,"nextAction":next,"stepEvidence":step_evidence
        });
        validate("OperationReport", &output)?;
        Ok(output)
    }
}

pub(crate) fn step_verified(step: &StepRecord) -> bool {
    step.finished
        && !step.further_effects_possible
        && step.effect != EffectEvidence::Unknown
        && match step.verification_requirement {
            VerificationRequirement::SchemaOnly => step.dispatch >= DispatchEvidence::Sent,
            VerificationRequirement::ProviderCompletion => {
                step.dispatch >= DispatchEvidence::Acknowledged
            }
            VerificationRequirement::IndependentReadback => {
                step.dispatch == DispatchEvidence::Observed && !step.observation_refs.is_empty()
            }
        }
        && (!step.write_effect || step.effect == EffectEvidence::CompleteConfirmed)
}

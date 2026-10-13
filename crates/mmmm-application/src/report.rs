use crate::*;
use mmmm_contracts::{StepId, encode_json};
use mmmm_runtime::artifact::issue_operation_resource;
use mmmm_runtime::storage::{
    BlobRef, DispatchEvidence, EffectEvidence, OperationRecord, OperationState, StepRecord,
    VerificationRequirement,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const PREVIEW_ITEMS: usize = 16;
const SUMMARY_BYTES: usize = 64 * 1024;
const MANIFEST_BYTES: usize = 32 * 1024 * 1024;
const LEGACY_RESULT_BYTES: u64 = 32 * 1024 * 1024;

pub(crate) fn known_provider_failure(value: &Value) -> bool {
    (value["kind"] == "provider_result" && value["value"]["status"] == "failed")
        || (value["kind"] == "unvalidated_provider_result"
            && value["envelopeValidated"] == true
            && value["envelopeStatus"] == "failed")
}

pub(crate) fn unresolved_failure_history(value: &Value) -> bool {
    value["failureHistoryIncomplete"] == true
}

pub(crate) fn failure_blocks_step(value: &Value, step: &str) -> bool {
    (value["stepId"] == step && known_provider_failure(value))
        || (unresolved_failure_history(value)
            && (value["stepId"].is_null() || value["stepId"] == step))
}

struct ReportTotals {
    completed: usize,
    pending: usize,
    unverified: usize,
    failed: usize,
    providers: usize,
    steps: usize,
    diagnostics: usize,
}

/// Metadata projects retained evidence; it is not another effect authority.
pub(crate) fn compact_evidence(value: &Value, blob: &BlobRef) -> AppResult<Value> {
    let mut output = match value["kind"].as_str() {
        Some("unvalidated_provider_result") => json!({"kind":"unvalidated_provider_result",
            "stepId":value["stepId"],"invocationId":value["invocationId"],
            "bodyOmitted":true,"resultBlob":value.get("resultBlob").cloned().unwrap_or_else(||json!(blob)),
            "envelopeValidated":value["envelopeValidated"],"envelopeStatus":value["envelopeStatus"],
            "envelopeSummary":value["envelopeSummary"]}),
        Some("before_capture") => json!({"kind":"before_capture_summary",
            "stepId":value["stepId"],"invocationId":value["invocationId"],"imageCount":value["images"].as_array().map_or(0,Vec::len),
            "captureBlob":blob,"bodyOmitted":true}),
        Some("provider_result") => {
            let response = &value["value"];
            let diagnostics = response["diagnostics"].as_array();
            let mut severities = BTreeMap::<String, usize>::new();
            for diagnostic in diagnostics.into_iter().flatten() {
                *severities
                    .entry(text(diagnostic, "severity")?.to_owned())
                    .or_default() += 1;
            }
            let preview: Vec<_> = diagnostics
                .into_iter()
                .flatten()
                .take(8)
                .map(compact_diagnostic)
                .collect::<AppResult<_>>()?;
            let severity_counts = value
                .get("diagnosticSeverityCounts")
                .cloned()
                .unwrap_or_else(|| json!(severities));
            json!({"kind":"provider_result", "stepId":value["stepId"],"invocationId":value["invocationId"],
                "value":{"contractVersion":"0.2.0", "status":response["status"],
                    "effects":response["effects"], "data":{}, "diagnostics":preview,"artifacts":[]},
                "outputValidated":value["outputValidated"],"actionDigest":value["actionDigest"],
                "outputSchemaDigest":value["outputSchemaDigest"],"bodyOmitted":true,
                "resultBlob":value.get("resultBlob").cloned().unwrap_or_else(||json!(blob)),
                "diagnosticCount":value["diagnosticCount"].as_u64().unwrap_or(diagnostics.map_or(0,Vec::len) as u64),
                "diagnosticSeverityCounts":severity_counts,
                "artifactCount":value["artifactCount"].as_u64().unwrap_or(response["artifacts"].as_array().map_or(0,Vec::len) as u64)})
        }
        Some("application_diagnostic") => json!({"kind":"application_diagnostic",
            "diagnostic":compact_diagnostic(&value["diagnostic"])?, "bodyOmitted":true}),
        Some("independent_readback") => json!({"kind":"independent_readback_summary",
            "stepId":value["stepId"],"invocationId":value["invocationId"],
            "effect":value["effect"],"settled":value["settled"],
            "directChangeCount":value["directChanges"].as_array().map_or(0,Vec::len),"bodyOmitted":true}),
        _ => value.clone(),
    };
    if output["kind"] == "provider_result"
        && let Some(handle) = value["value"].get("jobHandle")
    {
        output["value"]["jobHandle"] = handle.clone();
    }
    let mut refs: Vec<BlobRef> = value["sourceRefs"]
        .as_array()
        .into_iter()
        .flatten()
        .map(decode)
        .collect::<AppResult<_>>()?;
    if !refs.contains(blob) {
        refs.push(blob.clone());
    }
    output["sourceRefs"] = json!(refs);
    Ok(output)
}

fn compact_diagnostic(value: &Value) -> AppResult<Value> {
    validate("Diagnostic", value)?;
    let mut output = json!({"code":value["code"],"severity":value["severity"],
        "message":text(value,"message")?.chars().take(512).collect::<String>()});
    if let Some(id) = value.get("objectId") {
        output["objectId"] = id.clone();
    }
    if value["path"].as_str().is_some_and(|path| path.len() <= 256) {
        output["path"] = value["path"].clone();
    }
    Ok(output)
}

impl Application<'_> {
    pub(crate) fn evidence_values(&self, record: &OperationRecord) -> AppResult<Vec<Value>> {
        let blobs = self
            .store
            .operation_summaries(&record.operation_id)
            .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?;
        let mut seen: BTreeSet<_> = blobs.iter().map(|b| b.digest.clone()).collect();
        let mut covered = BTreeSet::new();
        let mut values = Vec::new();
        for blob in blobs {
            let value = self.evidence_blob(&blob)?;
            for source in value["sourceRefs"].as_array().into_iter().flatten() {
                covered.insert(decode::<BlobRef>(source)?.digest);
            }
            if value.get("kind").is_some() {
                values.push(compact_evidence(&value, &blob)?);
            }
        }
        // A partially upgraded journal may contain old provider evidence as
        // well as new summaries. Only represented sources skip body reads;
        // old failed status must not disappear when the first marker is added.
        let mut remaining = self
            .store
            .operation_evidence_refs(&record.operation_id)
            .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?
            .into_iter()
            .map(|blob| (None, blob))
            .collect::<Vec<_>>();
        for step in &record.steps {
            for blob in &step.observation_refs {
                remaining.push((Some(step.step_id.clone()), blob.clone()));
            }
        }
        let mut legacy_bytes = 0u64;
        for (step, blob) in remaining {
            if covered.contains(&blob.digest) || !seen.insert(blob.digest.clone()) {
                continue;
            }
            let Some(next_bytes) = legacy_bytes
                .checked_add(blob.byte_length)
                .filter(|size| *size <= LEGACY_RESULT_BYTES)
            else {
                values.push(json!({"kind":"legacy_evidence_uninspected","stepId":step,
                    "failureHistoryIncomplete":true,"sourceRefs":[blob],"bodyOmitted":true}));
                continue;
            };
            legacy_bytes = next_bytes;
            let mut value = self.evidence_blob(&blob)?;
            if value["kind"] == "unvalidated_provider_result"
                && validate("ProviderResult", &value["value"]).is_ok()
            {
                // An old wrapper body was already read within the same budget;
                // preserve its canonical envelope status without rereading it.
                let summary = compact_evidence(
                    &json!({"kind":"provider_result",
                    "stepId":value["stepId"],"invocationId":value["invocationId"],
                    "value":value["value"],"outputValidated":false,
                    "actionDigest":value["actionDigest"],"outputSchemaDigest":value["outputSchemaDigest"],
                    "resultBlob":blob,"sourceRefs":[blob]}),
                    &blob,
                )?;
                value["envelopeValidated"] = json!(true);
                value["envelopeStatus"] = value["value"]["status"].clone();
                value["envelopeSummary"] = summary;
            }
            if value.get("kind").is_some() {
                values.push(compact_evidence(&value, &blob)?);
            }
        }
        self.recover_raw_failures(&mut values, &mut legacy_bytes)?;
        Ok(values)
    }

    fn recover_raw_failures(&self, values: &mut Vec<Value>, bytes: &mut u64) -> AppResult<()> {
        let typed_failures = values
            .iter()
            .filter(|value| {
                value["kind"] == "provider_result" && value["value"]["status"] == "failed"
            })
            .filter_map(|value| {
                Some((
                    value["stepId"].as_str()?.to_owned(),
                    value["resultBlob"]["digest"].as_str()?.to_owned(),
                ))
            })
            .collect::<BTreeSet<_>>();
        let mut recovered = Vec::new();
        let mut seen = typed_failures;
        for marker in values
            .iter_mut()
            .filter(|value| value["kind"] == "unvalidated_provider_result")
        {
            let blob: BlobRef = decode(&marker["resultBlob"])?;
            let key = (
                text(marker, "stepId")?.to_owned(),
                blob.digest.as_str().to_owned(),
            );
            if seen.contains(&key) {
                continue;
            }
            if marker["envelopeValidated"] == true
                && marker["envelopeStatus"] == "failed"
                && marker["envelopeSummary"]["kind"] == "provider_result"
                && marker["envelopeSummary"]["value"]["status"] == "failed"
            {
                // This server-derived metadata grants no success. Runtime
                // resolution independently verifies the original retained body.
                let mut summary = marker["envelopeSummary"].clone();
                summary["sourceRefs"] = marker["sourceRefs"].clone();
                summary["outputValidated"] = json!(false);
                summary["rawFailureRecovered"] = json!(true);
                recovered.push(summary);
                seen.insert(key);
                continue;
            }
            if marker["envelopeValidated"].is_boolean() && marker["envelopeStatus"] != "failed" {
                continue;
            }
            let Some(next_bytes) = bytes
                .checked_add(blob.byte_length)
                .filter(|size| *size <= LEGACY_RESULT_BYTES)
            else {
                // Keep historical state and its full artifact refs readable,
                // but an uninspected old result cannot authorize a successor.
                marker["failureHistoryIncomplete"] = json!(true);
                continue;
            };
            *bytes = next_bytes;
            let body = self.evidence_blob(&blob)?;
            let response = if body["kind"] == "unvalidated_provider_result"
                || body["kind"] == "provider_result"
            {
                &body["value"]
            } else {
                &body
            };
            if validate("ProviderResult", response).is_ok() && response["status"] == "failed" {
                let mut summary = compact_evidence(
                    &json!({"kind":"provider_result",
                    "stepId":marker["stepId"],"invocationId":marker["invocationId"],
                    "value":response,"outputValidated":false,"actionDigest":marker["actionDigest"],
                    "outputSchemaDigest":marker["outputSchemaDigest"],"resultBlob":blob,
                    "sourceRefs":marker["sourceRefs"]}),
                    &blob,
                )?;
                summary["rawFailureRecovered"] = json!(true);
                marker["envelopeValidated"] = json!(true);
                marker["envelopeStatus"] = json!("failed");
                recovered.push(summary);
                seen.insert(key);
            }
        }
        values.extend(recovered);
        Ok(())
    }

    fn evidence_blob(&self, blob: &BlobRef) -> AppResult<Value> {
        let bytes = self
            .store
            .read_blob(blob)
            .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?;
        mmmm_contracts::parse_json(&bytes).map_err(|_| {
            AppError::new(
                "INVALID_STORED_EVIDENCE",
                "Stored operation evidence is not strict JSON",
            )
        })
    }

    pub(crate) fn readback_values(
        &self,
        record: &OperationRecord,
        step: &StepId,
    ) -> AppResult<Vec<Value>> {
        let mut values = Vec::new();
        if let Some(stored) = record.steps.iter().find(|s| &s.step_id == step) {
            let mut bytes = 0u64;
            for blob in &stored.observation_refs {
                let Some(next_bytes) = bytes
                    .checked_add(blob.byte_length)
                    .filter(|size| *size <= LEGACY_RESULT_BYTES)
                else {
                    // This lookup only reuses prior recovery pairs. Fresh
                    // independent readback is retained separately; incomplete
                    // original history already blocks every new successor.
                    continue;
                };
                bytes = next_bytes;
                let value = self.evidence_blob(blob)?;
                if value["kind"] == "independent_readback" {
                    values.push(value);
                }
            }
        }
        Ok(values)
    }

    pub(crate) fn operation_report(&mut self, record: &OperationRecord) -> AppResult<Value> {
        let evidence = self.evidence_values(record)?;
        let mut diagnostics = Vec::new();
        let mut failed_steps = evidence
            .iter()
            .filter(|value| known_provider_failure(value))
            .filter_map(|value| value["stepId"].as_str().map(str::to_owned))
            .collect::<BTreeSet<_>>();
        let mut incomplete_history: BTreeSet<_> = evidence
            .iter()
            .filter(|value| unresolved_failure_history(value))
            .filter_map(|value| value["stepId"].as_str().map(str::to_owned))
            .collect();
        if evidence
            .iter()
            .any(|value| unresolved_failure_history(value) && value["stepId"].is_null())
        {
            incomplete_history.extend(
                record
                    .steps
                    .iter()
                    .map(|step| step.step_id.as_str().to_owned()),
            );
        }
        let mut provider_counts = BTreeMap::<String, usize>::new();
        let mut provider_results = Vec::new();
        let mut manifest = Vec::new();
        let mut resources = BTreeMap::<_, Value>::new();
        let mut evidence_access_error = false;
        let mut diagnostic_count = 0usize;
        let mut provider_artifact_count = 0usize;
        for value in &evidence {
            if value["kind"] == "application_diagnostic" {
                diagnostic_count += 1;
                if diagnostics.len() < PREVIEW_ITEMS && !diagnostics.contains(&value["diagnostic"])
                {
                    diagnostics.push(value["diagnostic"].clone());
                }
            } else if value["kind"] == "provider_result" {
                let status = text(&value["value"], "status")?;
                *provider_counts.entry(status.to_owned()).or_default() += 1;
                if status == "failed" {
                    failed_steps.insert(text(value, "stepId")?.to_owned());
                }
                diagnostic_count += value["diagnosticCount"].as_u64().unwrap_or(0) as usize;
                provider_artifact_count += value["artifactCount"].as_u64().unwrap_or(0) as usize;
                for diagnostic in value["value"]["diagnostics"]
                    .as_array()
                    .into_iter()
                    .flatten()
                {
                    if diagnostics.len() < PREVIEW_ITEMS && !diagnostics.contains(diagnostic) {
                        diagnostics.push(diagnostic.clone());
                    }
                }
            }
            let mut row = value.clone();
            let mut row_resources = Vec::new();
            for blob in value["sourceRefs"]
                .as_array()
                .into_iter()
                .flatten()
                .map(decode::<BlobRef>)
            {
                let blob = blob?;
                let resource = if let Some(resource) = resources.get(&blob.digest) {
                    Some(resource.clone())
                } else {
                    match issue_operation_resource(
                        self.store,
                        &record.operation_id,
                        &blob,
                        "application/json",
                    ) {
                        Ok(resource) => {
                            resources.insert(blob.digest.clone(), resource.clone());
                            Some(resource)
                        }
                        Err(_) => {
                            evidence_access_error = true;
                            None
                        }
                    }
                };
                if let Some(resource) = resource {
                    row_resources.push(resource);
                }
            }
            row["resources"] = json!(row_resources);
            if append_manifest(&mut manifest, &row).is_err() {
                evidence_access_error = true;
            }
            if value["kind"] == "provider_result" && provider_results.len() < PREVIEW_ITEMS {
                provider_results.push(
                    json!({"stepId":value["stepId"],"status":value["value"]["status"],
                    "effects":value["value"]["effects"],"outputValidated":value["outputValidated"],
                    "bodyOmitted":true,"resources":row["resources"]}),
                );
            }
        }
        let completed: Vec<_> = record
            .steps
            .iter()
            .filter(|s| {
                step_verified(s)
                    && !failed_steps.contains(s.step_id.as_str())
                    && !incomplete_history.contains(s.step_id.as_str())
            })
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
                    && (!step_verified(s)
                        || failed_steps.contains(s.step_id.as_str())
                        || incomplete_history.contains(s.step_id.as_str()))
            })
            .map(|s| s.step_id.clone())
            .collect();
        let mut effect_counts = BTreeMap::<String, usize>::new();
        let mut step_evidence = Vec::new();
        for step in &record.steps {
            *effect_counts
                .entry(step.effect.as_str().to_owned())
                .or_default() += 1;
            let full = json!({"kind":"step_state","stepId":step.step_id,"dispatch":step.dispatch,
                "effect":step.effect,"providerReceipt":step.provider_receipt,
                "furtherEffectsPossible":step.further_effects_possible,"finished":step.finished,
                "providerFailed":failed_steps.contains(step.step_id.as_str()),
                "failureHistoryIncomplete":incomplete_history.contains(step.step_id.as_str()),
                "completed":completed.contains(&step.step_id),"pending":pending.contains(&step.step_id),
                "unverified":unverified.contains(&step.step_id),"observationRefs":step.observation_refs});
            if append_manifest(&mut manifest, &full).is_err() {
                evidence_access_error = true;
            }
            if step_evidence.len() < PREVIEW_ITEMS {
                step_evidence.push(json!({"stepId":step.step_id,"dispatch":step.dispatch,
                    "effect":step.effect,"providerReceipt":step.provider_receipt,
                    "furtherEffectsPossible":step.further_effects_possible,
                    "observationRefs":step.observation_refs.iter().take(4)
                        .map(|b|format!("obs-{}",b.digest)).collect::<Vec<_>>()}));
            }
        }
        let mut artifacts = Vec::new();
        let manifest_ref = match self.store.put_blob(&manifest) {
            Ok(blob) => match self
                .store
                .pin_operation_artifact(&record.operation_id, &blob)
            {
                Ok(()) => match issue_operation_resource(
                    self.store,
                    &record.operation_id,
                    &blob,
                    "application/x-ndjson",
                ) {
                    Ok(resource) => {
                        artifacts.push(resource.clone());
                        Some(resource)
                    }
                    Err(_) => {
                        evidence_access_error = true;
                        None
                    }
                },
                Err(_) => {
                    evidence_access_error = true;
                    None
                }
            },
            Err(_) => {
                evidence_access_error = true;
                None
            }
        };
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
        let verification = if record
            .steps
            .iter()
            .any(|s| s.dispatch == DispatchEvidence::Observed)
        {
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
            || record.reconciliation_required
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
        let recovery = match self.store.recovery_snapshots(&record.operation_id) {
            Ok(snapshots) if !snapshots.is_empty() => {
                json!({"mode":"explicit_patch","coverage":"recorded_direct_changes"})
            }
            Ok(_) => json!({"mode":"none","coverage":"none"}),
            Err(_) => {
                evidence_access_error = true;
                json!({"mode":"none","coverage":"none"})
            }
        };
        let provider_total = provider_counts.values().sum::<usize>();
        let mut output = json!({"contractVersion":"0.2.0","operationId":record.operation_id,"planId":record.plan_id,
            "state":record.state,"dispatchEvidence":dispatch,
            "completedStepIds":completed.iter().take(PREVIEW_ITEMS).collect::<Vec<_>>(),
            "pendingStepIds":pending.iter().take(PREVIEW_ITEMS).collect::<Vec<_>>(),
            "unverifiedStepIds":unverified.iter().take(PREVIEW_ITEMS).collect::<Vec<_>>(),
            "result":{"providerResults":provider_results,"providerStatusCounts":provider_counts,
                "effectCounts":effect_counts,"failedStepIds":failed_steps.iter().take(PREVIEW_ITEMS).collect::<Vec<_>>(),
                "failedStepCount":failed_steps.len(),"totalStepCount":record.steps.len(),
                "completedStepCount":completed.len(),"pendingStepCount":pending.len(),"unverifiedStepCount":unverified.len(),
                "providerResultCount":provider_total,"diagnosticCount":diagnostic_count,
                "providerArtifactCount":provider_artifact_count,"evidenceCount":evidence.len(),
                "failureHistoryIncomplete":!incomplete_history.is_empty(),
                "failureHistoryIncompleteStepCount":incomplete_history.len(),
                "evidenceManifest":manifest_ref,"evidenceAccessError":evidence_access_error,
                "inlineLimit":PREVIEW_ITEMS,"completeEvidenceInManifest":!evidence_access_error},
            "diagnostics":diagnostics,"artifacts":artifacts,"recovery":recovery,
            "verification":verification,"nextAction":next,"stepEvidence":step_evidence});
        let totals = ReportTotals {
            completed: completed.len(),
            pending: pending.len(),
            unverified: unverified.len(),
            failed: failed_steps.len(),
            providers: provider_total,
            steps: record.steps.len(),
            diagnostics: diagnostic_count,
        };
        set_omitted(&mut output, &totals);
        if encode_json(&output).is_err()
            || encode_json(&output).is_ok_and(|bytes| bytes.len() > SUMMARY_BYTES)
        {
            for field in [
                "completedStepIds",
                "pendingStepIds",
                "unverifiedStepIds",
                "diagnostics",
                "stepEvidence",
            ] {
                output[field] = json!([]);
            }
            output["result"]["providerResults"] = json!([]);
            output["result"]["failedStepIds"] = json!([]);
            output["result"]["inlineLimit"] = json!(0);
            set_omitted(&mut output, &totals);
        }
        validate("OperationReport", &output)?;
        Ok(output)
    }
}

fn set_omitted(output: &mut Value, totals: &ReportTotals) {
    output["result"]["omitted"] = json!({
        "completedStepIds":totals.completed-output["completedStepIds"].as_array().map_or(0,Vec::len),
        "pendingStepIds":totals.pending-output["pendingStepIds"].as_array().map_or(0,Vec::len),
        "unverifiedStepIds":totals.unverified-output["unverifiedStepIds"].as_array().map_or(0,Vec::len),
        "failedStepIds":totals.failed-output["result"]["failedStepIds"].as_array().map_or(0,Vec::len),
        "providerResults":totals.providers-output["result"]["providerResults"].as_array().map_or(0,Vec::len),
        "stepEvidence":totals.steps-output["stepEvidence"].as_array().map_or(0,Vec::len),
        "diagnostics":totals.diagnostics.saturating_sub(output["diagnostics"].as_array().map_or(0,Vec::len))});
}

fn append_manifest(bytes: &mut Vec<u8>, value: &Value) -> AppResult<()> {
    let row = encode_json(value).map_err(|_| {
        AppError::new(
            "INVALID_STORED_EVIDENCE",
            "Evidence manifest row exceeds strict JSON bounds",
        )
    })?;
    if bytes
        .len()
        .checked_add(row.len() + 1)
        .is_none_or(|size| size > MANIFEST_BYTES)
    {
        return Err(AppError::new(
            "BUDGET_EXCEEDED",
            "Evidence manifest exceeds its finite byte budget",
        ));
    }
    bytes.extend(row);
    bytes.push(b'\n');
    Ok(())
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

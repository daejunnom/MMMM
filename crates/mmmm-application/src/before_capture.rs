use crate::*;
use mmmm_contracts::{OperationId, StepId, encode_json, raw_digest};
use mmmm_runtime::storage::{BlobRef, WriteScope};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const CAPTURE_BYTES: usize = 128 * 1024 * 1024;

impl Application<'_> {
    /// This private evidence is obtained before durable dispatch intent. Input
    /// arguments and provider output never create a target before image.
    pub(crate) fn retain_before_capture(
        &mut self,
        plan: &Value,
        step: &Value,
        operation: &OperationId,
        invocation: &Value,
        scope: &WriteScope,
    ) -> AppResult<()> {
        if step["effect"] == "read" {
            return Ok(());
        }
        let required = matches!(
            step["recovery"].as_str(),
            Some("explicit_patch" | "file_snapshot")
        );
        let capture = self
            .observer
            .capture_before_retained_with_store(self.store, invocation, scope)?;
        let Some(capture) = capture else {
            return if required {
                Err(AppError::new(
                    "CAPABILITY_UNAVAILABLE",
                    "Direct-recovery writes require independently captured before images",
                ))
            } else {
                Ok(())
            };
        };
        if capture.invocation_id.as_str() != text(invocation, "invocationId")?
            || capture.binding_id.as_str() != text(invocation, "bindingId")?
            || capture.context_digest.as_str() != text(invocation, "contextDigest")?
            || capture.implementation_digest.as_str() != text(invocation, "implementationDigest")?
            || capture.arguments_digest.as_str() != text(invocation, "argumentsDigest")?
        {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Before capture does not identify this exact pinned invocation",
            ));
        }
        if capture.images.len() > 4096
            || (required && capture.images.is_empty())
            || capture
                .images
                .iter()
                .try_fold(0usize, |total, image| total.checked_add(image.bytes.len()))
                .is_none_or(|size| size > CAPTURE_BYTES)
        {
            return Err(AppError::new(
                "BUDGET_EXCEEDED",
                "Before capture exceeds its finite budget or omits direct targets",
            ));
        }
        let expected = self.phase_expected_digests(plan, step, operation)?;
        let mut targets = BTreeSet::new();
        let mut images = Vec::new();
        for image in capture.images {
            if image.target.len() > 512
                || image.target.is_empty()
                || !targets.insert(image.target.clone())
                || !step["resourcesWritten"]
                    .as_array()
                    .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(&image.target)))
            {
                return Err(AppError::new(
                    "PERMISSION_REQUIRED",
                    "Before capture target is absent from the frozen write footprint or duplicated",
                ));
            }
            self.observer
                .validate_capture_target(invocation, scope, &image.target)?;
            let candidates: Vec<_> = plan["preconditions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|p| {
                    p["subject"] == image.target
                        && p["coverage"] == "full_target"
                        && matches!(
                            p["kind"].as_str(),
                            Some("resource_hash" | "region_snapshot")
                        )
                })
                .collect();
            let digest = raw_digest(&image.bytes);
            if candidates.is_empty()
                || candidates.iter().any(|p| {
                    expected.get(&(
                        p["kind"].as_str().unwrap_or("").to_owned(),
                        image.target.clone(),
                    )) != Some(&digest)
                })
            {
                return Err(AppError::new(
                    "TARGET_DRIFT",
                    "Actual before bytes differ from the frozen current phase precondition",
                ));
            }
            let before = self
                .store
                .put_blob(&image.bytes)
                .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
            self.store
                .pin_operation_artifact(operation, &before)
                .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
            images.push(json!({"target":image.target,"before":before}));
        }
        if required
            && !step["resourcesWritten"].as_array().is_some_and(|ids| {
                ids.iter()
                    .all(|id| id.as_str().is_some_and(|id| targets.contains(id)))
            })
        {
            return Err(AppError::new(
                "CAPABILITY_UNAVAILABLE",
                "Direct before capture omitted a frozen write target",
            ));
        }
        let envelope = json!({"kind":"before_capture", "version":1,"operationId":operation,
            "stepId":step["stepId"],"invocationId":capture.invocation_id,"bindingId":capture.binding_id,
            "contextDigest":capture.context_digest,"implementationDigest":capture.implementation_digest,
            "argumentsDigest":capture.arguments_digest,"images":images});
        let blob = self
            .store
            .put_blob(&encode_json(&envelope).map_err(|_| {
                AppError::new(
                    "BUDGET_EXCEEDED",
                    "Before capture envelope exceeds its JSON budget",
                )
            })?)
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        let summary = json!({"kind":"before_capture_summary","stepId":step["stepId"],
            "invocationId":invocation["invocationId"],"imageCount":images.len(),"captureBlob":blob,"sourceRefs":[blob]});
        self.retain_summary(operation, &summary, &[blob])?;
        Ok(())
    }

    /// Reload only the original operation's retained capture. A reconnecting
    /// observer supplies fresh after bytes without recreating old before state.
    pub(crate) fn captured_before(
        &self,
        operation: &OperationId,
        step: &StepId,
        invocation: &Value,
    ) -> AppResult<BTreeMap<String, BlobRef>> {
        let mut images = BTreeMap::new();
        for summary in self
            .store
            .operation_summaries(operation)
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?
        {
            let value = mmmm_contracts::parse_json(
                &self
                    .store
                    .read_blob(&summary)
                    .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?,
            )
            .map_err(|_| {
                AppError::new(
                    "RECOVERY_EXPIRED",
                    "Retained capture summary is invalid JSON",
                )
            })?;
            if value["kind"] != "before_capture_summary"
                || value["stepId"] != step.as_str()
                || value["invocationId"] != invocation["invocationId"]
            {
                continue;
            }
            let blob: BlobRef = decode(&value["captureBlob"])?;
            let envelope = mmmm_contracts::parse_json(
                &self
                    .store
                    .read_blob(&blob)
                    .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?,
            )
            .map_err(|_| {
                AppError::new(
                    "RECOVERY_EXPIRED",
                    "Retained capture envelope is invalid JSON",
                )
            })?;
            if envelope["kind"] != "before_capture"
                || envelope["version"] != 1
                || envelope["operationId"] != operation.as_str()
                || envelope["stepId"] != step.as_str()
                || [
                    "invocationId",
                    "bindingId",
                    "contextDigest",
                    "implementationDigest",
                    "argumentsDigest",
                ]
                .iter()
                .any(|key| envelope[*key] != invocation[*key])
            {
                return Err(AppError::new(
                    "RECOVERY_EXPIRED",
                    "Retained capture pins differ from the original invocation",
                ));
            }
            for image in envelope["images"].as_array().ok_or_else(|| {
                AppError::new("RECOVERY_EXPIRED", "Retained capture targets are absent")
            })? {
                let target = text(image, "target")?.to_owned();
                let before: BlobRef = decode(&image["before"])?;
                self.store
                    .read_blob(&before)
                    .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
                if images.insert(target, before).is_some() {
                    return Err(AppError::new(
                        "RECOVERY_EXPIRED",
                        "Retained before target is duplicated",
                    ));
                }
            }
        }
        Ok(images)
    }
}

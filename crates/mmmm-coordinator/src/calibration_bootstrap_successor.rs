//! Reload 이후의 현재 pairing으로 원 시도의 사실만 읽는다.
//! 원 grant를 되살리거나 현재 파일/함수 관측을 원 실행 성공으로 바꾸지 않는다.

use super::*;
use crate::host::{CompletedPairingWitness, HostBridge};
use mmmm_application::ReadbackEvidence;
use mmmm_contracts::{ContractValidator, encode_json};
use mmmm_runtime::storage::{DispatchEvidence, EffectEvidence};

struct EnteredSuccessor<'a> {
    registry: &'a BootstrapRegistry,
    entry: Rc<PreparedBootstrap>,
    confirmed: Rc<ConfirmedBootstrap>,
    operation: OperationRecord,
    original: &'a Value,
    request: &'a RequestContextWitness,
    authority: &'a LocalAuthority,
    pairing: CompletedPairingWitness,
}

pub(crate) struct SuccessorObservation {
    context: Value,
    payload: Value,
    evidence: BlobRef,
    prior_effect: EffectEvidence,
}

impl SuccessorObservation {
    pub(crate) fn context(&self) -> &Value {
        &self.context
    }

    pub(crate) fn original_result(&self) -> Option<Value> {
        self.payload["history"]["originalResult"]
            .as_object()
            .map(|_| self.payload["history"]["originalResult"].clone())
    }

    pub(crate) fn readback(self, original: &Value) -> AppResult<ReadbackEvidence> {
        // The present pack reader cannot prove original root identity continuity;
        // selected resource bytes do not prove the loaded function's causality.
        // Keep previously confirmed journal effects without promoting new facts.
        Ok(ReadbackEvidence {
            invocation_id: decode(&original["invocationId"])?,
            binding_id: decode(&original["bindingId"])?,
            context_digest: decode(&original["contextDigest"])?,
            implementation_digest: decode(&original["implementationDigest"])?,
            arguments_digest: decode(&original["argumentsDigest"])?,
            effect: self.prior_effect,
            settled: false,
            evidence: json!({"kind":"native_calibration_bootstrap_successor_readback",
                "sourceRefs":[self.evidence],"currentContext":self.context,
                "originalInvocationId":original["invocationId"],
                "limitations":["original_pack_root_identity_continuity_unproven",
                    "loaded_function_source_causality_unproven"]}),
            direct_changes: Vec::new(),
        })
    }
}

impl BootstrapRegistry {
    /// Only the exact private bootstrap action can select this boundary. A
    /// matching but invalid original or missing required successor is an error.
    /// A still-current, fully revalidated original generation keeps its ordinary
    /// exact-environment observation. No request/owner/pairing token is retained.
    pub(crate) fn observe_successor(
        &self,
        store: &mut DurableStore,
        request: &RequestContextWitness,
        authority: &LocalAuthority,
        hosts: &HostBridge,
        original: &Value,
    ) -> AppResult<Option<SuccessorObservation>> {
        if original["actionId"] != ACTION {
            return Ok(None);
        }
        request.check_local().map_err(request_error)?;
        if request.method() != "operation.reconcile" {
            return Err(denied());
        }
        let operation_id: OperationId = decode(&original["operationId"])?;
        let operation = store.operation(&operation_id).map_err(storage)?;
        let plan = store
            .plan(&operation.plan_id, &operation.plan_hash)
            .map_err(storage)?;
        let entry = self.prepared(store, &plan)?;
        let confirmed = entry
            .confirmed
            .try_borrow()
            .map_err(|_| unavailable())?
            .as_ref()
            .cloned()
            .ok_or_else(unavailable)?;
        if confirmed.route.check_current(request).is_ok() {
            // The original generation may still own an interrupted preparation
            // before reload. Preserve its ordinary exact-environment observer;
            // only a fully revalidated original intent can take this branch.
            self.enter(
                store,
                request,
                authority,
                original,
                BootstrapAccess::Observe,
            )?
            .ok_or_else(unavailable)?
            .verify_intent(store)?;
            self.check_source(store, &plan, &|| {
                request.check_local().map_err(request_error)?;
                confirmed.route.check_current(request)
            })?;
            return Ok(None);
        }
        let pairing = hosts.bootstrap_successor_pairing(store, request, authority, original)?;
        let entered = EnteredSuccessor {
            registry: self,
            entry,
            confirmed,
            operation,
            original,
            request,
            authority,
            pairing,
        };
        entered.check(store)?;
        let manifest_digest =
            canonical_digest(&entered.confirmed.manifest).map_err(|_| unavailable())?;
        let selector = json!({"kind":"calibration_bootstrap_successor",
            "invocationId":original["invocationId"],
            "invocationDigest":canonical_digest(original).map_err(|_| unavailable())?,
            "sourceBundleDigest":entered.entry.source.digest(),"frozenManifestDigest":manifest_digest});
        let observed = hosts.inspect_bootstrap_successor_with_store(
            store,
            authority,
            original,
            &entered.pairing,
            selector,
            &|store| entered.check(store),
        );
        let payload = finish_native_observation(observed, entered.check(store))?;
        validate_payload(&payload, &entered, &manifest_digest)?;
        let bytes = encode_json(&payload).map_err(|_| unavailable())?;
        if bytes.len() > crate::rpc::MAX_CONTROL_BYTES {
            return Err(unavailable());
        }
        let evidence = store.put_blob(&bytes).map_err(storage)?;
        store
            .append_operation_evidence(&operation_id, &evidence)
            .map_err(storage)?;
        entered.check(store)?;
        let step_id: StepId = decode(&original["stepId"])?;
        let prior_effect = store
            .operation(&operation_id)
            .map_err(storage)?
            .steps
            .iter()
            .find(|step| step.step_id == step_id)
            .ok_or_else(unavailable)?
            .effect;
        Ok(Some(SuccessorObservation {
            context: entered.pairing.context().clone(),
            payload,
            evidence,
            prior_effect,
        }))
    }
}

impl EnteredSuccessor<'_> {
    fn check(&self, store: &DurableStore) -> AppResult<()> {
        self.request.check_local().map_err(request_error)?;
        self.pairing
            .with_current_native_owner(store, self.authority, |_| self.check_original(store))?;
        self.registry.check_source(store, &self.entry.plan, &|| {
            self.pairing.check_current(self.authority)
        })?;
        self.request.check_local().map_err(request_error)
    }

    fn check_original(&self, store: &DurableStore) -> AppResult<()> {
        let current = store
            .operation(&self.operation.operation_id)
            .map_err(storage)?;
        let step_id: StepId = decode(&self.original["stepId"])?;
        let step = current
            .steps
            .iter()
            .find(|step| step.step_id == step_id)
            .ok_or_else(denied)?;
        let plan = &self.entry.plan;
        let frozen = &plan["steps"][0];
        if self.request.method() != "operation.reconcile"
            || current.principal != *self.request.authenticated().principal()
            || current.principal != self.entry.source.principal
            || current.project_id != self.entry.source.project
            || self.pairing.principal() != &current.principal
            || self.pairing.project() != &current.project_id
            || current.plan_id != self.operation.plan_id
            || current.plan_hash != self.operation.plan_hash
            || current.context_id != self.operation.context_id
            || current.scope != self.operation.scope
            || self.original["contextId"] != current.context_id.as_str()
            || self.original["context"] != *self.confirmed.route.context()
            || self.original["contextDigest"] != self.original["context"]["contextDigest"]
            || self.original["operationId"] != current.operation_id.as_str()
            || !self.confirmed.completion.delivered()
            || self.confirmed.publication_failure.is_some()
            || self.confirmed.manifest["sourceBundle"] != self.entry.source.bundle
            || self.confirmed.manifest["plan"]["planHash"] != current.plan_hash.as_str()
            || step.dispatch == DispatchEvidence::NotSent
            || !Rc::ptr_eq(&self.registry.prepared(store, plan)?, &self.entry)
            || self
                .entry
                .operation
                .try_borrow()
                .map_err(|_| unavailable())?
                .as_ref()
                != Some(&current.operation_id)
            || [
                "stepId",
                "bindingId",
                "actionId",
                "actionContractVersion",
                "actionDigest",
                "implementationDigest",
                "arguments",
            ]
            .iter()
            .any(|field| self.original[*field] != frozen[*field])
        {
            return Err(denied());
        }
        let blob = store
            .stored_invocation_blob(&current.operation_id, &step_id)
            .map_err(storage)?;
        verify_raw_invocation_pin(self.original, &blob)?;
        if store
            .stored_invocation(&current.operation_id, &step_id)
            .map_err(storage)?
            != *self.original
        {
            return Err(denied());
        }
        let key = canonical_digest(self.original).map_err(|_| unavailable())?;
        if self
            .entry
            .captures
            .try_borrow()
            .map_err(|_| unavailable())?
            .get(key.as_str())
            .is_none_or(|images| images.len() != 95)
        {
            return Err(unavailable());
        }
        self.authority.clone().authorize_operation(
            &current.principal,
            &current,
            Access::ObserveOperation,
        )
    }
}

fn validate_payload(
    payload: &Value,
    entered: &EnteredSuccessor<'_>,
    manifest: &Sha256Digest,
) -> AppResult<()> {
    exact(
        payload,
        &[
            "format",
            "originalInvocation",
            "frozenManifestDigest",
            "sourceBundleDigest",
            "currentContext",
            "history",
            "observation",
        ],
    )?;
    if payload["format"] != "mmmm.native.calibration-bootstrap-successor/1"
        || payload["originalInvocation"] != *entered.original
        || payload["frozenManifestDigest"] != manifest.as_str()
        || payload["sourceBundleDigest"] != *entered.entry.source.digest()
        || payload["currentContext"] != *entered.pairing.context()
    {
        return Err(denied());
    }
    validate_history(&payload["history"])?;
    let facts = &payload["history"]["fileFacts"];
    if !facts.is_null() {
        if facts["sourceBundleDigest"] != *entered.entry.source.digest() {
            return Err(denied());
        }
        let entries = entered.entry.source.bundle["entries"]
            .as_array()
            .ok_or_else(unavailable)?;
        for row in facts["files"].as_array().ok_or_else(unavailable)? {
            let entry = entries
                .iter()
                .find(|entry| entry["path"] == row["path"])
                .ok_or_else(unavailable)?;
            if row["rawSha256"] != entry["rawSha256"] || row["byteLength"] != entry["byteLength"] {
                return Err(unavailable());
            }
        }
    }
    validate_observation(&payload["observation"], &entered.entry.source)
}

fn validate_history(history: &Value) -> AppResult<()> {
    exact(
        history,
        &[
            "originalResult",
            "originalFailure",
            "resultTerminal",
            "effectPhase",
            "fileFacts",
            "initializationAttemptedCount",
            "initializationReturns",
            "reloadOutcome",
            "reloadFailure",
        ],
    )?;
    let terminal = history["resultTerminal"]
        .as_bool()
        .ok_or_else(unavailable)?;
    if !history["effectPhase"]
        .as_str()
        .is_some_and(|value| !value.is_empty() && value.len() <= 64)
    {
        return Err(unavailable());
    }
    let returns = history["initializationReturns"]
        .as_array()
        .filter(|rows| rows.len() <= 47)
        .ok_or_else(unavailable)?;
    let attempted = history["initializationAttemptedCount"]
        .as_u64()
        .filter(|value| *value <= 47)
        .ok_or_else(unavailable)?;
    if attempted < returns.len() as u64
        || returns.iter().any(|value| {
            value
                .as_i64()
                .is_none_or(|value| i32::try_from(value).is_err())
        })
    {
        return Err(unavailable());
    }
    let outcome = history["reloadOutcome"].as_str().ok_or_else(unavailable)?;
    if !matches!(
        outcome,
        "not_attempted" | "call_attempted_without_future" | "pending" | "completed" | "failed"
    ) {
        return Err(unavailable());
    }
    if !history["originalResult"].is_null() {
        if !terminal || !history["originalFailure"].is_null() {
            return Err(unavailable());
        }
        ContractValidator::shared()
            .map_err(|_| unavailable())?
            .validate("ProviderResult", &history["originalResult"])
            .map_err(|_| unavailable())?;
    }
    if !history["originalFailure"].is_null() && !terminal {
        return Err(unavailable());
    }
    for field in ["originalFailure", "reloadFailure"] {
        validate_failure(&history[field])?;
    }
    if (outcome == "failed") == history["reloadFailure"].is_null() {
        return Err(unavailable());
    }
    if !history["fileFacts"].is_null() {
        let facts = &history["fileFacts"];
        exact(facts, &["sourceBundleDigest", "verifiedFileCount", "files"])?;
        let rows = facts["files"]
            .as_array()
            .filter(|rows| rows.len() == 48)
            .ok_or_else(unavailable)?;
        if facts["verifiedFileCount"] != 48
            || Sha256Digest::new(
                facts["sourceBundleDigest"]
                    .as_str()
                    .ok_or_else(unavailable)?,
            )
            .is_err()
        {
            return Err(unavailable());
        }
        let mut paths = BTreeSet::new();
        for row in rows {
            exact(row, &["path", "byteLength", "rawSha256"])?;
            if !row["path"]
                .as_str()
                .is_some_and(|path| !path.is_empty() && path.len() <= 4096 && paths.insert(path))
                || row["byteLength"]
                    .as_u64()
                    .is_none_or(|size| size > MAX_IMAGE_BYTES as u64)
                || Sha256Digest::new(row["rawSha256"].as_str().ok_or_else(unavailable)?).is_err()
            {
                return Err(unavailable());
            }
        }
    }
    Ok(())
}

fn validate_failure(value: &Value) -> AppResult<()> {
    if value.is_null() {
        return Ok(());
    }
    if !value.is_object() || encode_json(value).map_err(|_| unavailable())?.len() > 16 * 1024 {
        return Err(unavailable());
    }
    let mut pending = vec![(value, 0usize)];
    let mut count = 0usize;
    while let Some((node, depth)) = pending.pop() {
        count += 1;
        if count > 64 || depth > 8 {
            return Err(unavailable());
        }
        exact(node, &["type", "code", "cause", "suppressed", "truncated"])?;
        if !node["type"]
            .as_str()
            .is_some_and(|value| !value.is_empty() && value.len() <= 2048)
            || (!node["code"].is_null()
                && !node["code"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty() && value.len() <= 128))
            || !node["truncated"].is_boolean()
        {
            return Err(unavailable());
        }
        if !node["cause"].is_null() {
            pending.push((&node["cause"], depth + 1));
        }
        for suppressed in node["suppressed"]
            .as_array()
            .filter(|rows| rows.len() <= 8)
            .ok_or_else(unavailable)?
        {
            pending.push((suppressed, depth + 1));
        }
    }
    Ok(())
}

fn validate_observation(value: &Value, source: &BootstrapSource) -> AppResult<()> {
    exact(
        value,
        &[
            "format",
            "observedFromTick",
            "observedToTick",
            "pack",
            "loadedSources",
            "targetImages",
        ],
    )?;
    if value["format"] != "mmmm.native.calibration-bootstrap-observation/1" {
        return Err(unavailable());
    }
    let tick = |field: &str| {
        value[field]
            .as_str()
            .filter(|text| {
                !text.is_empty()
                    && text.len() <= 10
                    && text.bytes().all(|byte| byte.is_ascii_digit())
            })
            .and_then(|text| text.parse::<u32>().ok())
            .ok_or_else(unavailable)
    };
    let from = tick("observedFromTick")?;
    let to = tick("observedToTick")?;
    if to < from {
        return Err(unavailable());
    }
    exact(&value["pack"], &["status", "reason", "identityContinuity"])?;
    if value["pack"]
        != json!({"status":"unknown","reason":"readonly_pack_observer_unavailable","identityContinuity":"unproven"})
    {
        return Err(unavailable());
    }
    let loaded = &value["loadedSources"];
    exact(loaded, &["status", "causalLink", "functions", "failure"])?;
    if loaded["causalLink"] != "unproven" {
        return Err(unavailable());
    }
    let functions = loaded["functions"]
        .as_array()
        .filter(|rows| rows.len() <= 47)
        .ok_or_else(unavailable)?;
    validate_status(&loaded["status"], functions.len(), 47)?;
    validate_failure(&loaded["failure"])?;
    if loaded["status"] == "known" && !loaded["failure"].is_null() {
        return Err(unavailable());
    }
    let expected = source
        .programs
        .as_array()
        .filter(|programs| programs.len() == 47)
        .ok_or_else(unavailable)?;
    let mut seen = BTreeSet::new();
    for function in functions {
        exact(
            function,
            &[
                "functionId",
                "resourceId",
                "sourcePackId",
                "rawSha256",
                "byteLength",
            ],
        )?;
        let id = function["functionId"].as_str().ok_or_else(unavailable)?;
        if !seen.insert(id)
            || !expected.iter().any(|program| program["functionId"] == id)
            || function["sourcePackId"] != "file/mmmm-calibration-normative47"
        {
            return Err(unavailable());
        }
        let suffix = id
            .strip_prefix("mmmm_calibration:")
            .ok_or_else(unavailable)?;
        let resource = format!("mmmm_calibration:function/{suffix}.mcfunction");
        let path = format!("data/mmmm_calibration/function/{suffix}.mcfunction");
        let entry = source.bundle["entries"]
            .as_array()
            .ok_or_else(unavailable)?
            .iter()
            .find(|entry| entry["path"] == path)
            .ok_or_else(unavailable)?;
        if function["resourceId"] != resource
            || function["rawSha256"] != entry["rawSha256"]
            || function["byteLength"] != entry["byteLength"]
        {
            return Err(unavailable());
        }
    }
    let targets = &value["targetImages"];
    exact(targets, &["status", "targets", "failure"])?;
    let images = targets["targets"]
        .as_array()
        .filter(|rows| rows.len() <= 94)
        .ok_or_else(unavailable)?;
    validate_status(&targets["status"], images.len(), 94)?;
    validate_failure(&targets["failure"])?;
    if targets["status"] == "known" && !targets["failure"].is_null() {
        return Err(unavailable());
    }
    let mut total = 0usize;
    let mut seen_targets = BTreeSet::new();
    for image in images {
        exact(image, &["targetId", "rawBytesHex", "rawSha256"])?;
        let id = image["targetId"].as_str().ok_or_else(unavailable)?;
        if !seen_targets.insert(id)
            || !source.targets[1..]
                .iter()
                .any(|target| target.as_str() == id)
        {
            return Err(unavailable());
        }
        let bytes = decode_hex(image["rawBytesHex"].as_str().ok_or_else(unavailable)?)?;
        total = total
            .checked_add(bytes.len())
            .filter(|total| *total <= MAX_IMAGE_BYTES)
            .ok_or_else(unavailable)?;
        if image["rawSha256"] != raw_digest(&bytes).as_str() {
            return Err(unavailable());
        }
    }
    Ok(())
}

fn validate_status(status: &Value, count: usize, maximum: usize) -> AppResult<()> {
    match status.as_str() {
        Some("known") if count == maximum => Ok(()),
        Some("unknown") if count <= maximum => Ok(()),
        _ => Err(unavailable()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_prefix_cannot_claim_complete_membership() {
        // Existing source fixtures do not encode this new private partial-read
        // envelope. This pure decoder check grants no owner or native facts.
        assert!(validate_status(&json!("known"), 46, 47).is_err());
        assert!(validate_status(&json!("unknown"), 46, 47).is_ok());
        assert!(validate_status(&json!("known"), 47, 47).is_ok());
        assert!(validate_status(&json!("known"), 95, 94).is_err());
    }

    #[test]
    fn original_result_requires_actual_terminal_history() {
        let mut history = json!({"originalResult":null,"originalFailure":null,"resultTerminal":false,
            "effectPhase":"accepted","fileFacts":null,"initializationAttemptedCount":0,
            "initializationReturns":[],"reloadOutcome":"not_attempted","reloadFailure":null});
        assert!(validate_history(&history).is_ok());
        history["originalFailure"] = json!({"type":"unit-syntax-only"});
        assert!(validate_history(&history).is_err());
        history["originalFailure"] = Value::Null;
        history["reloadOutcome"] = json!("completed");
        history["reloadFailure"] = json!({"type":"unit-syntax-only"});
        assert!(validate_history(&history).is_err());
    }
}

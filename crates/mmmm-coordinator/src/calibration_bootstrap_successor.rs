//! Reload 이후의 현재 pairing으로 원 시도의 사실만 읽는다.
//! 원 grant를 되살리거나 현재 파일/함수 관측을 원 실행 성공으로 바꾸지 않는다.

use super::*;
use crate::host::{CompletedPairingWitness, HostBridge};
use mmmm_application::ReadbackEvidence;
use mmmm_contracts::{ContractValidator, encode_json};
use mmmm_runtime::storage::{DispatchEvidence, EffectEvidence};

const MAX_SUCCESSOR_PAYLOAD_BYTES: usize = 256 * 1024;

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
        // A retained root observation covers only that original directory.
        // It proves neither current pack bytes nor loaded function causality.
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
                "limitations":["retained_root_identity_is_not_current_pack_bytes_or_membership",
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
        if bytes.len() > crate::rpc::MAX_CONTROL_BYTES.min(MAX_SUCCESSOR_PAYLOAD_BYTES) {
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
    validate_observation(&payload["observation"], &entered.entry.source)?;
    if payload["observation"]["pack"]["status"] == "observed"
        && payload["history"]["rootAnchorRecorded"] != true
    {
        return Err(unavailable());
    }
    Ok(())
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
            "rootAnchorReserved",
            "rootAnchorRecorded",
            "rootRetirement",
            "rootRetirementFailure",
        ],
    )?;
    let reserved = history["rootAnchorReserved"]
        .as_bool()
        .ok_or_else(unavailable)?;
    let recorded = history["rootAnchorRecorded"]
        .as_bool()
        .ok_or_else(unavailable)?;
    if recorded && !reserved {
        return Err(unavailable());
    }
    if !history["rootRetirement"].is_null() {
        if !reserved {
            return Err(unavailable());
        }
        validate_held_root(&history["rootRetirement"], 4)?;
    }
    validate_failure(&history["rootRetirementFailure"])?;
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
    if !value.is_object() || encode_json(value).map_err(|_| unavailable())?.len() > 32 * 1024 {
        return Err(unavailable());
    }
    let mut pending = vec![(value, 0usize)];
    let mut count = 0usize;
    while let Some((node, depth)) = pending.pop() {
        count += 1;
        if count > 64 || depth > 8 {
            return Err(unavailable());
        }
        validate_failure_fields(node)?;
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

fn validate_failure_fields(node: &Value) -> AppResult<()> {
    let mut fields = vec!["type", "code", "cause", "suppressed", "truncated"];
    if node["type"]
        == "io.github.daejunnom.mmmm.observer.DefinitionOwnedPackFilesBridge$NativeFailure"
    {
        fields.push("effectsMayExist");
        if !node["effectsMayExist"].is_boolean()
            || !matches!(
                node["code"].as_str(),
                Some(
                    "UNSAFE_SELECTION"
                        | "NATIVE_UNAVAILABLE"
                        | "NATIVE_BUSY"
                        | "SOURCE_CHANGED"
                        | "NATIVE_IO"
                        | "ORIGINAL_CHECKPOINT"
                        | "NATIVE_PANIC"
                        | "NATIVE_CHANGED"
                        | "NATIVE_LIFETIME_UNAVAILABLE"
                        | "NATIVE_RETAINED_CLOSE"
                )
            )
        {
            return Err(unavailable());
        }
        for field in [
            "nativeError",
            "nativeCreate",
            "nativeLifetime",
            "retainedClose",
        ] {
            if node.get(field).is_some() {
                fields.push(field);
            }
        }
        if let Some(error) = node.get("nativeError")
            && (node["code"] != "NATIVE_IO" || !signed_i32(error))
        {
            return Err(unavailable());
        }
        if let Some(create) = node.get("nativeCreate") {
            exact(
                create,
                &[
                    "ntStatus",
                    "completionStatus",
                    "informationUnsigned",
                    "closeNativeError",
                ],
            )?;
            if node["code"] != "NATIVE_IO"
                || !signed_i32(&create["ntStatus"])
                || !optional_i32(&create["completionStatus"])
                || !optional_i32(&create["closeNativeError"])
                || (!create["informationUnsigned"].is_null()
                    && !create["informationUnsigned"].as_str().is_some_and(|text| {
                        !text.is_empty()
                            && text.len() <= 20
                            && text.bytes().all(|byte| byte.is_ascii_digit())
                            && text.parse::<u64>().is_ok()
                    }))
            {
                return Err(unavailable());
            }
        }
        if let Some(lifetime) = node.get("nativeLifetime") {
            exact(lifetime, &["kind", "operation", "status", "nativeCode"])?;
            let kind = lifetime["kind"].as_str().ok_or_else(unavailable)?;
            if node["code"] != "NATIVE_LIFETIME_UNAVAILABLE"
                || !matches!(
                    kind,
                    "unsupported_target" | "native_failure" | "invalid_observation"
                )
                || !lifetime["operation"].as_str().is_some_and(|text| {
                    !text.is_empty()
                        && text.len() <= 96
                        && text.bytes().all(|byte| (32..=126).contains(&byte))
                })
                || !optional_i32(&lifetime["status"])
                || !optional_i32(&lifetime["nativeCode"])
                || (kind == "native_failure" && lifetime["status"].is_null())
                || (kind == "invalid_observation"
                    && (!lifetime["status"].is_null() || !lifetime["nativeCode"].is_null()))
                || (kind == "unsupported_target"
                    && (lifetime["operation"] != "target"
                        || !lifetime["status"].is_null()
                        || !lifetime["nativeCode"].is_null()))
            {
                return Err(unavailable());
            }
        }
        if let Some(close) = node.get("retainedClose") {
            exact(close, &["stage", "pin"])?;
            if node["code"] != "NATIVE_RETAINED_CLOSE"
                || !matches!(
                    close["stage"].as_str(),
                    Some("before_close" | "native_close" | "after_close")
                )
                || (!close["pin"].is_null() && close["pin"].as_u64().is_none_or(|pin| pin >= 66))
                || (!(node["truncated"] == true && node["cause"].is_null())
                    && (node["cause"]["code"] != "NATIVE_IO"
                        || node["cause"]["type"]
                            != "io.github.daejunnom.mmmm.observer.DefinitionOwnedPackFilesBridge$NativeFailure"))
            {
                return Err(unavailable());
            }
        }
        if (node["code"] == "NATIVE_LIFETIME_UNAVAILABLE") != node.get("nativeLifetime").is_some()
            || (node["code"] == "NATIVE_RETAINED_CLOSE") != node.get("retainedClose").is_some()
        {
            return Err(unavailable());
        }
    }
    exact(node, &fields)
}
fn signed_i32(value: &Value) -> bool {
    value
        .as_i64()
        .is_some_and(|value| i32::try_from(value).is_ok())
}
fn optional_i32(value: &Value) -> bool {
    value.is_null() || signed_i32(value)
}

/// Closed descriptive codec only. The private host producer's actual object /
/// native root join supplies evidence; parsed JSON cannot construct that join.
fn validate_held_root(value: &Value, operation: u64) -> AppResult<()> {
    exact(
        value,
        &[
            "operation",
            "state",
            "evidenceGrade",
            "identity",
            "pins",
            "closed",
            "shared",
            "uncertain",
        ],
    )?;
    let state = value["state"].as_str().ok_or_else(unavailable)?;
    if value["operation"] != operation
        || !matches!(
            state,
            "unknown"
                | "reserved"
                | "held_unpublished"
                | "published_partial"
                | "complete"
                | "retiring"
                | "reference_released"
                | "close_uncertain"
                | "vm_owned"
        )
        || !matches!(
            value["evidenceGrade"].as_str(),
            Some("unknown" | "windows_create_handle" | "posix_cooperative")
        )
        || !matches!(
            value["identity"].as_str(),
            Some("not_observed" | "same" | "different")
        )
    {
        return Err(unavailable());
    }
    let counts = ["pins", "closed", "shared", "uncertain"]
        .map(|field| value[field].as_u64().filter(|count| *count <= 66));
    let [Some(pins), Some(closed), Some(shared), Some(uncertain)] = counts else {
        return Err(unavailable());
    };
    if closed + shared + uncertain > pins
        || (operation == 4 && value["identity"] != "not_observed")
        || (matches!(state, "unknown" | "reserved")
            && (value["evidenceGrade"] != "unknown"
                || value["identity"] != "not_observed"
                || pins != 0
                || closed != 0
                || shared != 0
                || uncertain != 0))
    {
        return Err(unavailable());
    }
    Ok(())
}

fn validate_pack(value: &Value) -> AppResult<()> {
    exact(
        value,
        &[
            "status",
            "reason",
            "identityContinuity",
            "currentBytes",
            "fullPackMembership",
            "retainedRoot",
            "failure",
        ],
    )?;
    if value["currentBytes"] != "not_observed" || value["fullPackMembership"] != "unproven" {
        return Err(unavailable());
    }
    if !value["retainedRoot"].is_null() {
        validate_held_root(&value["retainedRoot"], 3)?;
    }
    validate_failure(&value["failure"])?;
    match (value["status"].as_str(), value["reason"].as_str()) {
        (Some("observed"), Some("native_retained_root_identity_only"))
            if value["failure"].is_null()
                && value["identityContinuity"] == "same"
                && value["retainedRoot"]["identity"] == "same"
                && matches!(
                    value["retainedRoot"]["state"].as_str(),
                    Some("held_unpublished" | "published_partial" | "complete")
                )
                && matches!(
                    value["retainedRoot"]["evidenceGrade"].as_str(),
                    Some("windows_create_handle" | "posix_cooperative")
                ) =>
        {
            Ok(())
        }
        (Some("unknown"), Some("retained_root_not_published"))
            if value["identityContinuity"] == "unproven"
                && value["retainedRoot"].is_null()
                && value["failure"].is_null() =>
        {
            Ok(())
        }
        (Some("unknown"), Some("native_retained_root_observation_failed"))
            if value["identityContinuity"] == "unproven" && !value["failure"].is_null() =>
        {
            Ok(())
        }
        _ => Err(unavailable()),
    }
}

fn validate_observation(value: &Value, source: &BootstrapSource) -> AppResult<()> {
    exact(
        value,
        &[
            "format",
            "observedFromTick",
            "observedToTick",
            "pack",
            "loadedSourceTrace",
            "loadedSources",
            "targetImages",
        ],
    )?;
    // This validates only the fresh private host reply. Previously stored /1
    // evidence remains untouched; it is not replayed through this decoder.
    if value["format"] != "mmmm.native.calibration-bootstrap-observation/2" {
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
    validate_pack(&value["pack"])?;
    validate_loaded_source_trace(&value["loadedSourceTrace"])?;
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

/// Opaque evidence transport only. Neither this envelope nor decoded JSON
/// constructs the actual native object joins or a SourceAdmission witness.
fn validate_loaded_source_trace(value: &Value) -> AppResult<()> {
    exact(
        value,
        &[
            "format",
            "armAttempted",
            "receiptOrigin",
            "receiptBytesHex",
            "failure",
            "currentFailure",
        ],
    )?;
    if value["format"] != "mmmm.native.calibration-loaded-source-trace/1"
        || !value["armAttempted"].is_boolean()
    {
        return Err(unavailable());
    }
    validate_failure(&value["failure"])?;
    validate_failure(&value["currentFailure"])?;
    let attempted = value["armAttempted"].as_bool().ok_or_else(unavailable)?;
    match value["receiptOrigin"].as_str() {
        Some("none") if value["receiptBytesHex"].is_null() => {}
        Some("historical_only" | "current_call_return") if attempted => {
            let raw = value["receiptBytesHex"].as_str().ok_or_else(unavailable)?;
            if raw.is_empty()
                || raw.len() > 2 * 64 * 1024
                || raw.len() % 2 != 0
                || !raw
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || (value["receiptOrigin"] == "current_call_return"
                    && !value["currentFailure"].is_null())
            {
                return Err(unavailable());
            }
        }
        _ => return Err(unavailable()),
    }
    if !attempted
        && (value["receiptOrigin"] != "none"
            || !value["failure"].is_null()
            || !value["currentFailure"].is_null())
    {
        return Err(unavailable());
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
    fn loaded_source_trace_is_bounded_opaque_transport_without_admission() {
        // No prior fixture includes this bridge envelope. Its arbitrary bytes
        // are deliberately not native facts or an actual capture witness.
        let mut trace = json!({"format":"mmmm.native.calibration-loaded-source-trace/1",
            "armAttempted":false,"receiptOrigin":"none","receiptBytesHex":null,
            "failure":null,"currentFailure":null});
        assert!(validate_loaded_source_trace(&trace).is_ok());
        trace["armAttempted"] = json!(true);
        trace["receiptOrigin"] = json!("current_call_return");
        trace["receiptBytesHex"] = json!("ff".repeat(64 * 1024));
        assert!(validate_loaded_source_trace(&trace).is_ok());
        trace["receiptBytesHex"] = json!("ff".repeat(64 * 1024 + 1));
        assert!(validate_loaded_source_trace(&trace).is_err());
        for raw in ["", "0", "GG", "Ff", "00 1", "é"] {
            trace["receiptBytesHex"] = json!(raw);
            assert!(validate_loaded_source_trace(&trace).is_err());
        }
        trace["receiptBytesHex"] = json!("00");
        trace["armAttempted"] = json!(false);
        assert!(validate_loaded_source_trace(&trace).is_err());
        trace["armAttempted"] = json!(true);
        trace["currentFailure"] = json!({"type":"syntax-only","code":null,
            "cause":null,"suppressed":[],"truncated":false});
        assert!(validate_loaded_source_trace(&trace).is_err());
        trace["receiptOrigin"] = json!("historical_only");
        assert!(validate_loaded_source_trace(&trace).is_ok());
        trace["known"] = json!(true);
        assert!(validate_loaded_source_trace(&trace).is_err());
    }

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
            "initializationReturns":[],"reloadOutcome":"not_attempted","reloadFailure":null,
            "rootAnchorReserved":false,"rootAnchorRecorded":false,"rootRetirement":null,"rootRetirementFailure":null});
        assert!(validate_history(&history).is_ok());
        history["originalFailure"] = json!({"type":"unit-syntax-only"});
        assert!(validate_history(&history).is_err());
        history["originalFailure"] = Value::Null;
        history["reloadOutcome"] = json!("completed");
        history["reloadFailure"] = json!({"type":"unit-syntax-only"});
        assert!(validate_history(&history).is_err());
    }

    #[test]
    fn retained_root_description_cannot_expand_to_pack_bytes_or_loaded_causality() {
        // Grammar-only values: parsing these creates no JNI anchor, native
        // identity, authenticated host or current authority association.
        let mut pack = json!({"status":"observed","reason":"native_retained_root_identity_only",
            "identityContinuity":"same","currentBytes":"not_observed","fullPackMembership":"unproven",
            "failure":null,"retainedRoot":{"operation":3,"state":"complete","evidenceGrade":"posix_cooperative",
                "identity":"same","pins":0,"closed":0,"shared":0,"uncertain":0}});
        assert!(validate_pack(&pack).is_ok());
        pack["currentBytes"] = json!("known");
        assert!(validate_pack(&pack).is_err());
        pack["currentBytes"] = json!("not_observed");
        pack["fullPackMembership"] = json!("known");
        assert!(validate_pack(&pack).is_err());
        pack["fullPackMembership"] = json!("unproven");
        pack["retainedRoot"]["identity"] = json!("different");
        assert!(validate_pack(&pack).is_err());
        pack["retainedRoot"]["identity"] = json!("same");
        pack["retainedRoot"]["extraAuthority"] = json!(true);
        assert!(validate_pack(&pack).is_err());
    }

    #[test]
    fn retained_close_keeps_consumed_uncertainty_and_bounds_distinct_pin_counts() {
        let mut close = json!({"operation":4,"state":"close_uncertain","evidenceGrade":"windows_create_handle",
            "identity":"not_observed","pins":66,"closed":63,"shared":2,"uncertain":1});
        assert!(validate_held_root(&close, 4).is_ok());
        close["uncertain"] = json!(2);
        assert!(validate_held_root(&close, 4).is_err());
        close["uncertain"] = json!(1);
        close["identity"] = json!("same");
        assert!(validate_held_root(&close, 4).is_err());
        close = json!({"operation":4,"state":"unknown","evidenceGrade":"unknown",
            "identity":"not_observed","pins":0,"closed":0,"shared":0,"uncertain":0});
        assert!(validate_held_root(&close, 4).is_ok());
        close["pins"] = json!(1);
        assert!(validate_held_root(&close, 4).is_err());
    }

    #[test]
    fn typed_native_failure_keeps_actual_signed_codes_and_close_context() {
        let io = json!({"type":"io.github.daejunnom.mmmm.observer.DefinitionOwnedPackFilesBridge$NativeFailure",
            "code":"NATIVE_IO","effectsMayExist":true,"nativeError":5,"cause":null,"suppressed":[],"truncated":false,
            "nativeCreate":{"ntStatus":-1073741790i32,"completionStatus":null,"informationUnsigned":"18446744073709551615","closeNativeError":6}});
        let mut close = json!({"type":"io.github.daejunnom.mmmm.observer.DefinitionOwnedPackFilesBridge$NativeFailure",
            "code":"NATIVE_RETAINED_CLOSE","effectsMayExist":true,"cause":io,"suppressed":[],"truncated":false,
            "retainedClose":{"stage":"native_close","pin":65}});
        assert!(validate_failure(&close).is_ok());
        close["retainedClose"]["pin"] = json!(66);
        assert!(validate_failure(&close).is_err());
        close["retainedClose"]["pin"] = json!(65);
        close["cause"]["nativeError"] = json!(2147483648u64);
        assert!(validate_failure(&close).is_err());
        close["cause"] = Value::Null;
        close["truncated"] = json!(true);
        assert!(validate_failure(&close).is_ok());
        close["retainedClose"]["path"] = json!("caller-syntax-only");
        assert!(validate_failure(&close).is_err());
    }
}

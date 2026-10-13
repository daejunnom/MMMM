//! Provider undo receipts are private host-issued references, never tokens or
//! caller authority. One product SQLite/CAS retains Pending source material,
//! promotes only independently settled full target history, and claims it in
//! the original dispatch-intent transaction. No claim is made available again.

use super::{
    BlobRef, DispatchEvidence, DurableStore, EffectEvidence, OperationRecord, StepRecord,
    StorageError, StorageResult, WriteScope,
    journal::{decode, encode, pin_blob},
};
use mmmm_contracts::{
    BindingId, InvocationId, ObjectId, OperationId, PrincipalId, ProjectId, Sha256Digest, StepId,
    canonical_digest, encode_json, parse_json, verify_projected_digest,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

const METADATA_BYTES: u64 = 1024 * 1024;
const RECEIPT_BYTES: u64 = 65_536;
const RECORD_BYTES: usize = 4 * 1024 * 1024;
const HISTORY_BYTES: u64 = 32 * 1024 * 1024;
const STATE_BYTES: u64 = 128 * 1024 * 1024;
const ENTRIES: usize = 4096;
const SCHEMA:&str="
CREATE TABLE IF NOT EXISTS undo_routes (
 route_digest TEXT PRIMARY KEY, source_binding_id TEXT NOT NULL,
 source_action_id TEXT NOT NULL, source_action_digest TEXT NOT NULL,
 undo_binding_id TEXT NOT NULL, undo_action_id TEXT NOT NULL,
 undo_action_digest TEXT NOT NULL, blob_digest TEXT NOT NULL REFERENCES blobs(digest),
 byte_length INTEGER NOT NULL CHECK(byte_length>0 AND byte_length<=1048576)
) STRICT;
CREATE TABLE IF NOT EXISTS provider_undo_records (
 record_id TEXT PRIMARY KEY, source_operation_id TEXT NOT NULL REFERENCES operations(operation_id),
 source_step_id TEXT NOT NULL, source_invocation_id TEXT NOT NULL UNIQUE REFERENCES invocations(invocation_id),
 route_digest TEXT NOT NULL REFERENCES undo_routes(route_digest), receipt_digest TEXT NOT NULL,
 receipt_blob TEXT NOT NULL REFERENCES blobs(digest), record_json TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','available','reserved')),
 claim_operation_id TEXT REFERENCES operations(operation_id), claim_step_id TEXT,
 claim_invocation_id TEXT UNIQUE,
 CHECK((state='reserved' AND claim_operation_id IS NOT NULL AND claim_step_id IS NOT NULL AND claim_invocation_id IS NOT NULL)
    OR (state!='reserved' AND claim_operation_id IS NULL AND claim_step_id IS NULL AND claim_invocation_id IS NULL))
) STRICT;";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegisteredUndoRoute {
    pub source_binding_id: BindingId,
    pub source_action: Value,
    pub undo_binding_id: BindingId,
    pub undo_action: Value,
    pub provider_origin: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UndoTargetState {
    pub target: String,
    pub before: Option<BlobRef>,
    pub after: BlobRef,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, tag = "state", rename_all = "snake_case")]
pub enum UndoRecordState {
    Pending,
    Available,
    Reserved {
        operation_id: OperationId,
        step_id: StepId,
        invocation_id: InvocationId,
        invocation_digest: Sha256Digest,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderUndoRecord {
    pub record_id: ObjectId,
    pub principal: PrincipalId,
    pub project_id: ProjectId,
    pub source_operation_id: OperationId,
    pub source_plan_hash: Sha256Digest,
    pub source_step_id: StepId,
    pub source_invocation_id: InvocationId,
    pub source_invocation_digest: Sha256Digest,
    pub source_context: Value,
    pub scope: WriteScope,
    pub route_digest: Sha256Digest,
    pub route_blob: BlobRef,
    pub receipt: Value,
    pub receipt_blob: BlobRef,
    pub material_summary: BlobRef,
    pub settled_observation: Option<BlobRef>,
    pub after_states: Vec<UndoTargetState>,
    pub state: UndoRecordState,
}
pub struct UndoRegistrationRequest {
    pub source_operation_id: OperationId,
    pub source_step_id: StepId,
    pub source_invocation_id: InvocationId,
    pub source_invocation_digest: Sha256Digest,
    pub route_digest: Sha256Digest,
}
/// Constructed by the configured actual source-session callback. This holds
/// only the closed SDK receipt; the private host token never enters Rust CAS.
pub struct InspectedUndoMaterial {
    pub receipt: Value,
    pub authenticated_player_id: String,
}
pub trait UndoRpcContext {
    /// These methods inspect the authenticated call snapshot and its local
    /// cancellation/deadline budget. They must perform no transport/native I/O.
    fn check(&self) -> StorageResult<()>;
    fn authenticated_principal(&self) -> StorageResult<PrincipalId>;
    fn current_context(&self) -> StorageResult<Value>;
}
// The original receipt is already observed truth. A revoked caller budget must
// not discard it after acquisition; this separate bounded local retention phase
// performs no host I/O and grants no caller access or future mutation authority.
struct CapturedTruthContext {
    principal: PrincipalId,
    context: Value,
    deadline: Instant,
}
impl UndoRpcContext for CapturedTruthContext {
    fn check(&self) -> StorageResult<()> {
        if Instant::now() >= self.deadline {
            return Err(StorageError::InvalidTransition(
                "Undo truth retention deadline exceeded".into(),
            ));
        }
        Ok(())
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        Ok(self.principal.clone())
    }
    fn current_context(&self) -> StorageResult<Value> {
        Ok(self.context.clone())
    }
}
pub trait UndoMaterialSource {
    fn inspect_source_material(
        &mut self,
        store: &DurableStore,
        source: &OperationRecord,
        invocation: &Value,
        route: &RegisteredUndoRoute,
        current_context: &Value,
    ) -> StorageResult<InspectedUndoMaterial>;
}
/// These are trusted transport/provider ports, not JSON grants. Recovery checks
/// must verify fresh Recovery AND Apply approval over the original full scope.
pub trait UndoAuthority {
    fn authorize_capture(
        &mut self,
        store: &DurableStore,
        source: &OperationRecord,
        invocation: &Value,
        current_context: &Value,
    ) -> StorageResult<()>;
    fn authorize_read(
        &mut self,
        store: &DurableStore,
        record: &ProviderUndoRecord,
        current_context: &Value,
    ) -> StorageResult<()>;
    fn authorize_recovery(
        &mut self,
        store: &DurableStore,
        record: &ProviderUndoRecord,
        invocation: &Value,
    ) -> StorageResult<()>;
    fn read_current_target(
        &mut self,
        store: &DurableStore,
        record: &ProviderUndoRecord,
        invocation: &Value,
        target: &str,
        max_bytes: u64,
    ) -> StorageResult<Vec<u8>>;
}
pub struct UndoDispatchRequest<'a> {
    pub operation_id: &'a OperationId,
    pub step_id: &'a StepId,
    pub invocation: &'a Value,
    pub undo_record_id: &'a ObjectId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HostReceipt {
    contract_version: String,
    token_record_id: ObjectId,
    principal_ref: PrincipalId,
    session_epoch: String,
    game_instance_id: String,
    side: String,
    player_id: String,
    binding_id: BindingId,
    source_action_id: mmmm_contracts::ActionId,
    source_action_digest: Sha256Digest,
    source_implementation_digest: Sha256Digest,
    source_arguments_digest: Sha256Digest,
    source_context_digest: Sha256Digest,
    source_operation_id: OperationId,
    source_step_id: StepId,
    source_invocation_id: InvocationId,
    undo_action_id: mmmm_contracts::ActionId,
    source_context: Value,
    private_token_sha256: Sha256Digest,
    token_record_digest: Sha256Digest,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryAssociation {
    summary: BlobRef,
    source_blobs: Vec<BlobRef>,
}

fn invalid(message: &'static str) -> StorageError {
    StorageError::InvalidInput(message.into())
}
fn contract(error: impl std::fmt::Display) -> StorageError {
    StorageError::Contract(error.to_string())
}
fn digest(value: &Value) -> StorageResult<Sha256Digest> {
    canonical_digest(value).map_err(contract)
}
fn field<T: serde::de::DeserializeOwned>(value: &Value, key: &str) -> StorageResult<T> {
    serde_json::from_value(value[key].clone()).map_err(contract)
}
fn table_exists(connection: &Connection, name: &str) -> StorageResult<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [name],
        |row| row.get::<_, i64>(0),
    )? == 1)
}
fn read_json(
    store: &DurableStore,
    rpc: &dyn UndoRpcContext,
    blob: &BlobRef,
    limit: u64,
) -> StorageResult<Value> {
    parse_json(&store.read_blob_checked(blob, limit, || rpc.check())?).map_err(contract)
}
fn retained(
    connection: &Connection,
    operation: &OperationId,
    kinds: &[&str],
    blob: &BlobRef,
) -> StorageResult<()> {
    let mut found = false;
    for kind in kinds {
        found |= connection.query_row("SELECT EXISTS(SELECT 1 FROM blob_refs r JOIN blobs b ON b.digest=r.digest WHERE r.owner_kind=?1 AND r.owner_id=?2 AND r.digest=?3 AND b.byte_length=?4)",params![kind,operation.as_str(),blob.digest.as_str(),i64::try_from(blob.byte_length).map_err(|_|invalid("Undo source length is invalid"))?],|r|r.get::<_,i64>(0))?==1;
    }
    if !found {
        return Err(StorageError::Corrupt(
            "Undo material lost its original operation pin".into(),
        ));
    }
    Ok(())
}
fn raw_blob(digest: String, length: i64) -> StorageResult<BlobRef> {
    Ok(BlobRef {
        digest: Sha256Digest::new(digest).map_err(contract)?,
        byte_length: u64::try_from(length).map_err(|_| invalid("Negative undo blob length"))?,
    })
}

/// Server registry installation must happen before ordinary plan admission.
/// It does not accept a wire flag purporting to identify a recovery-only action.
pub fn register_undo_route(
    store: &mut DurableStore,
    route: &RegisteredUndoRoute,
) -> StorageResult<Sha256Digest> {
    validate_route(store, route)?;
    let value = serde_json::to_value(route).map_err(contract)?;
    let bytes = encode_json(&value).map_err(contract)?;
    if bytes.len() as u64 > METADATA_BYTES {
        return Err(invalid("Undo route metadata budget exceeded"));
    }
    let route_digest = digest(&value)?;
    let blob = store.put_blob(&bytes)?;
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA)?;
    let old: Option<(String, i64)> = transaction
        .query_row(
            "SELECT blob_digest,byte_length FROM undo_routes WHERE route_digest=?1",
            [route_digest.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((old_digest, length)) = old {
        if raw_blob(old_digest, length)? != blob {
            return Err(StorageError::Conflict("Immutable registered undo route"));
        }
    } else {
        let count: i64 =
            transaction.query_row("SELECT count(*) FROM undo_routes", [], |r| r.get(0))?;
        if count >= ENTRIES as i64 {
            return Err(invalid("Undo registry capacity exceeded"));
        }
        // CAS was flushed above. Register its actual bytes before the route's
        // immediate FK references blobs; route and owner pin still commit in
        // this same transaction and roll back together on any later failure.
        super::journal::register_blob(&transaction, &blob)?;
        transaction.execute("INSERT INTO undo_routes(route_digest,source_binding_id,source_action_id,source_action_digest,undo_binding_id,undo_action_id,undo_action_digest,blob_digest,byte_length) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![route_digest.as_str(),route.source_binding_id.as_str(),route.source_action["actionId"].as_str(),digest(&route.source_action)?.as_str(),route.undo_binding_id.as_str(),route.undo_action["actionId"].as_str(),digest(&route.undo_action)?.as_str(),blob.digest.as_str(),blob.byte_length as i64])?;
    }
    pin_blob(&transaction, "undo_route", route_digest.as_str(), &blob)?;
    transaction.commit()?;
    Ok(route_digest)
}
fn validate_route(store: &DurableStore, route: &RegisteredUndoRoute) -> StorageResult<()> {
    for descriptor in [&route.source_action, &route.undo_action] {
        store
            .validator
            .validate("ActionDescriptor", descriptor)
            .map_err(contract)?;
        store
            .validator
            .compile_action_schema(&descriptor["inputSchema"])
            .map_err(contract)?;
        store
            .validator
            .compile_action_schema(&descriptor["outputSchema"])
            .map_err(contract)?;
    }
    if route.source_action["recovery"] != "provider_undo"
        || route.source_action["effect"] == "read"
        || route.source_action["verificationRequirement"] != "independent_readback"
        || route.undo_action["recovery"] != "none"
        || route.undo_action["effect"] == "read"
        || route.undo_action["verificationRequirement"] != "independent_readback"
        || (route.source_binding_id == route.undo_binding_id
            && route.source_action["actionId"] == route.undo_action["actionId"])
        || !route.provider_origin.is_object()
    {
        return Err(invalid(
            "Undo route is not an independently verified source-to-recovery registration",
        ));
    }
    Ok(())
}
fn load_route(
    store: &DurableStore,
    rpc: &dyn UndoRpcContext,
    route_digest: &Sha256Digest,
) -> StorageResult<(RegisteredUndoRoute, BlobRef)> {
    if !table_exists(&store.connection, "undo_routes")? {
        return Err(StorageError::NotFound("Registered undo route"));
    }
    let row: Option<(String, i64)> = store
        .connection
        .query_row(
            "SELECT blob_digest,byte_length FROM undo_routes WHERE route_digest=?1",
            [route_digest.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (raw, length) = row.ok_or(StorageError::NotFound("Registered undo route"))?;
    let blob = raw_blob(raw, length)?;
    let pinned:i64=store.connection.query_row("SELECT EXISTS(SELECT 1 FROM blob_refs WHERE owner_kind='undo_route' AND owner_id=?1 AND digest=?2)",params![route_digest.as_str(),blob.digest.as_str()],|r|r.get(0))?;
    if pinned != 1 {
        return Err(StorageError::Corrupt(
            "Registered undo route lost its pin".into(),
        ));
    }
    let value = read_json(store, rpc, &blob, METADATA_BYTES)?;
    if digest(&value)? != *route_digest {
        return Err(StorageError::Conflict("Registered undo route digest"));
    }
    let route: RegisteredUndoRoute = serde_json::from_value(value).map_err(contract)?;
    validate_route(store, &route)?;
    Ok((route, blob))
}

struct OriginalSource {
    operation: OperationRecord,
    invocation: Value,
    invocation_blob: BlobRef,
    step: Value,
}
fn load_source(
    store: &DurableStore,
    rpc: &dyn UndoRpcContext,
    request: &UndoRegistrationRequest,
) -> StorageResult<OriginalSource> {
    rpc.check()?;
    let operation = store.operation(&request.source_operation_id)?;
    let stored = operation
        .steps
        .iter()
        .find(|s| s.step_id == request.source_step_id)
        .ok_or(StorageError::NotFound("Original undo source step"))?;
    if stored.dispatch == DispatchEvidence::NotSent
        || !stored.write_effect
        || stored.invocation_id.as_ref() != Some(&request.source_invocation_id)
        || stored.invocation_digest.as_ref() != Some(&request.source_invocation_digest)
    {
        return Err(StorageError::Conflict("Original undo source intent"));
    }
    let row:Option<(String,String,String,i64)>=store.connection.query_row("SELECT i.invocation_id,i.invocation_hash,i.blob_digest,b.byte_length FROM invocations i JOIN blobs b ON b.digest=i.blob_digest WHERE i.operation_id=?1 AND i.step_id=?2",params![operation.operation_id.as_str(),request.source_step_id.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let (id, hash, raw, length) = row.ok_or(StorageError::NotFound("Original undo invocation"))?;
    if id != request.source_invocation_id.as_str()
        || hash != request.source_invocation_digest.as_str()
        || raw != hash
    {
        return Err(StorageError::Conflict("Original undo invocation digest"));
    }
    let invocation_blob = raw_blob(raw, length)?;
    retained(
        &store.connection,
        &operation.operation_id,
        &["operation"],
        &invocation_blob,
    )?;
    let invocation = read_json(store, rpc, &invocation_blob, 8 * 1024 * 1024)?;
    store
        .validator
        .validate("Invocation", &invocation)
        .map_err(contract)?;
    if invocation["operationId"] != operation.operation_id.as_str()
        || invocation["stepId"] != request.source_step_id.as_str()
        || invocation["invocationId"] != id
        || invocation["context"]["projectId"] != operation.project_id.as_str()
        || invocation["context"]["principalRef"] != operation.principal.as_str()
        || invocation["argumentsDigest"] != digest(&invocation["arguments"])?.as_str()
        || invocation["contextDigest"]
            != verify_projected_digest("ExecutionContext", &invocation["context"])
                .map_err(contract)?
                .as_str()
    {
        return Err(StorageError::Conflict(
            "Original undo invocation identity/pins",
        ));
    }
    let plan = frozen_plan(store, rpc, &operation)?;
    let step = plan["steps"]
        .as_array()
        .and_then(|v| {
            v.iter()
                .find(|s| s["stepId"] == request.source_step_id.as_str())
        })
        .ok_or(StorageError::NotFound("Frozen undo source step"))?
        .clone();
    for key in [
        "bindingId",
        "actionId",
        "actionContractVersion",
        "actionDigest",
        "implementationDigest",
    ] {
        if step[key] != invocation[key] {
            return Err(StorageError::Conflict("Original undo source frozen route"));
        }
    }
    if step["recovery"] != "provider_undo"
        || step["verificationRequirement"] != "independent_readback"
        || step["contextId"] != invocation["context"]["contextId"]
        || plan["policyRevision"] != invocation["context"]["policyRevision"]
    {
        return Err(StorageError::Conflict(
            "Original undo source recovery/context",
        ));
    }
    Ok(OriginalSource {
        operation,
        invocation,
        invocation_blob,
        step,
    })
}
fn frozen_plan(
    store: &DurableStore,
    rpc: &dyn UndoRpcContext,
    operation: &OperationRecord,
) -> StorageResult<Value> {
    let row: Option<(String, i64)> = store.connection.query_row(
        "SELECT d.blob_digest,b.byte_length FROM documents d JOIN blobs b ON b.digest=d.blob_digest WHERE d.definition='ExecutionPlan' AND d.document_id=?1 AND d.content_hash=?2",
        params![operation.plan_id.as_str(),operation.plan_hash.as_str()],|r|Ok((r.get(0)?,r.get(1)?)),
    ).optional()?;
    let (raw, length) = row.ok_or(StorageError::NotFound("Original undo frozen plan"))?;
    let plan = read_json(store, rpc, &raw_blob(raw, length)?, 8 * 1024 * 1024)?;
    store
        .validator
        .validate("ExecutionPlan", &plan)
        .map_err(contract)?;
    if plan["planId"] != operation.plan_id.as_str()
        || verify_projected_digest("ExecutionPlan", &plan).map_err(contract)? != operation.plan_hash
    {
        return Err(StorageError::Conflict(
            "Original undo frozen plan identity/digest",
        ));
    }
    Ok(plan)
}
fn context_matches(store: &DurableStore, original: &Value, current: &Value) -> StorageResult<()> {
    store
        .validator
        .validate("ExecutionContext", current)
        .map_err(contract)?;
    verify_projected_digest("ExecutionContext", current).map_err(contract)?;
    let mut left = original.clone();
    let mut right = current.clone();
    for key in ["policyRevision", "contextDigest"] {
        left.as_object_mut()
            .ok_or_else(|| invalid("Original undo context is invalid"))?
            .remove(key);
        right
            .as_object_mut()
            .ok_or_else(|| invalid("Current undo context is invalid"))?
            .remove(key);
    }
    if left != right {
        return Err(StorageError::Conflict(
            "Undo physical context/epoch changed",
        ));
    }
    Ok(())
}
fn source_route_matches(source: &OriginalSource, route: &RegisteredUndoRoute) -> StorageResult<()> {
    if source.invocation["bindingId"] != route.source_binding_id.as_str()
        || source.invocation["actionDigest"] != digest(&route.source_action)?.as_str()
        || source.invocation["actionId"] != route.source_action["actionId"]
        || source.invocation["implementationDigest"] != route.source_action["implementationDigest"]
    {
        return Err(StorageError::Conflict(
            "Actual registered source undo route",
        ));
    }
    Ok(())
}
fn validate_receipt(
    source: &OriginalSource,
    route: &RegisteredUndoRoute,
    material: &InspectedUndoMaterial,
) -> StorageResult<HostReceipt> {
    if encode_json(&material.receipt).map_err(contract)?.len() as u64 > RECEIPT_BYTES {
        return Err(invalid("Undo receipt byte budget exceeded"));
    }
    let receipt: HostReceipt =
        serde_json::from_value(material.receipt.clone()).map_err(contract)?;
    let mut projection = material.receipt.clone();
    projection
        .as_object_mut()
        .ok_or_else(|| invalid("Undo receipt is invalid"))?
        .remove("tokenRecordDigest");
    let inv = &source.invocation;
    let context = &inv["context"];
    let environment = &context["environment"];
    if digest(&projection)? != receipt.token_record_digest
        || receipt.contract_version != "0.2.0"
        || receipt.principal_ref != source.operation.principal
        || receipt.source_operation_id != source.operation.operation_id
        || receipt.source_step_id.as_str() != inv["stepId"].as_str().unwrap_or("")
        || receipt.source_invocation_id.as_str() != inv["invocationId"].as_str().unwrap_or("")
        || receipt.binding_id != route.source_binding_id
        || receipt.source_action_id.as_str() != inv["actionId"].as_str().unwrap_or("")
        || receipt.source_action_digest.as_str() != inv["actionDigest"].as_str().unwrap_or("")
        || receipt.source_implementation_digest.as_str()
            != inv["implementationDigest"].as_str().unwrap_or("")
        || receipt.source_arguments_digest.as_str() != inv["argumentsDigest"].as_str().unwrap_or("")
        || receipt.source_context_digest.as_str() != inv["contextDigest"].as_str().unwrap_or("")
        || receipt.source_context != *context
        || environment["kind"] != "game"
        || receipt.session_epoch != environment["sessionEpoch"].as_str().unwrap_or("")
        || receipt.game_instance_id != environment["gameInstanceId"].as_str().unwrap_or("")
        || receipt.side != environment["side"].as_str().unwrap_or("")
        || receipt.undo_action_id.as_str() != route.undo_action["actionId"].as_str().unwrap_or("")
        || receipt.player_id != material.authenticated_player_id
        || !canonical_player(&receipt.player_id)
    {
        return Err(StorageError::Conflict(
            "Authenticated original host undo receipt",
        ));
    }
    // Parsing validates the host-private token hash spelling without acquiring,
    // retaining, logging or reconstructing the actual private token.
    let _private_digest = &receipt.private_token_sha256;
    Ok(receipt)
}
fn canonical_player(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

fn request_for(record: &ProviderUndoRecord) -> UndoRegistrationRequest {
    UndoRegistrationRequest {
        source_operation_id: record.source_operation_id.clone(),
        source_step_id: record.source_step_id.clone(),
        source_invocation_id: record.source_invocation_id.clone(),
        source_invocation_digest: record.source_invocation_digest.clone(),
        route_digest: record.route_digest.clone(),
    }
}
fn encode_record(record: &ProviderUndoRecord) -> StorageResult<String> {
    let text = encode(record)?;
    if text.len() > RECORD_BYTES {
        return Err(invalid("Undo record metadata budget exceeded"));
    }
    Ok(text)
}
struct StoredUndoRow {
    text: String,
    state: String,
    operation: String,
    step: String,
    invocation: String,
    receipt: String,
    route_digest: String,
    receipt_digest: String,
    claim_operation: Option<String>,
    claim_step: Option<String>,
    claim_invocation: Option<String>,
}
fn read_record_inner(store: &DurableStore, id: &ObjectId) -> StorageResult<ProviderUndoRecord> {
    if !table_exists(&store.connection, "provider_undo_records")? {
        return Err(StorageError::NotFound("Provider undo record"));
    }
    let row: Option<StoredUndoRow> = store.connection.query_row(
        "SELECT record_json,state,source_operation_id,source_step_id,source_invocation_id,receipt_blob,claim_operation_id,claim_step_id,claim_invocation_id,route_digest,receipt_digest FROM provider_undo_records WHERE record_id=?1 AND length(CAST(record_json AS BLOB))<=4194304",[id.as_str()],|r|Ok(StoredUndoRow {
            text:r.get(0)?, state:r.get(1)?, operation:r.get(2)?, step:r.get(3)?, invocation:r.get(4)?, receipt:r.get(5)?, claim_operation:r.get(6)?, claim_step:r.get(7)?, claim_invocation:r.get(8)?, route_digest:r.get(9)?, receipt_digest:r.get(10)?
        })).optional()?;
    let StoredUndoRow {
        text,
        state,
        operation: op,
        step,
        invocation: inv,
        receipt,
        route_digest,
        receipt_digest,
        claim_operation: claim_op,
        claim_step,
        claim_invocation: claim_inv,
    } = row.ok_or(StorageError::NotFound("Provider undo record"))?;
    let record: ProviderUndoRecord = decode(&text)?;
    let expected_state = match &record.state {
        UndoRecordState::Pending => "pending",
        UndoRecordState::Available => "available",
        UndoRecordState::Reserved {
            operation_id,
            step_id,
            invocation_id,
            ..
        } => {
            if claim_op.as_deref() != Some(operation_id.as_str())
                || claim_step.as_deref() != Some(step_id.as_str())
                || claim_inv.as_deref() != Some(invocation_id.as_str())
            {
                return Err(StorageError::Corrupt(
                    "Undo claim index differs from its record".into(),
                ));
            }
            "reserved"
        }
    };
    if record.record_id != *id
        || state != expected_state
        || op != record.source_operation_id.as_str()
        || step != record.source_step_id.as_str()
        || inv != record.source_invocation_id.as_str()
        || receipt != record.receipt_blob.digest.as_str()
        || route_digest != record.route_digest.as_str()
        || record.receipt["tokenRecordDigest"] != receipt_digest
        || (expected_state != "reserved"
            && (claim_op.is_some() || claim_step.is_some() || claim_inv.is_some()))
        || (expected_state == "pending"
            && (!record.after_states.is_empty() || record.settled_observation.is_some()))
    {
        return Err(StorageError::Corrupt(
            "Undo record index/state is inconsistent".into(),
        ));
    }
    Ok(record)
}
fn verify_material(
    store: &DurableStore,
    rpc: &dyn UndoRpcContext,
    record: &ProviderUndoRecord,
) -> StorageResult<(OriginalSource, RegisteredUndoRoute)> {
    let source = load_source(store, rpc, &request_for(record))?;
    let (route, route_blob) = load_route(store, rpc, &record.route_digest)?;
    source_route_matches(&source, &route)?;
    if source.operation.principal != record.principal
        || source.operation.project_id != record.project_id
        || source.operation.plan_hash != record.source_plan_hash
        || source.operation.scope != record.scope
        || source.invocation["context"] != record.source_context
        || route_blob != record.route_blob
    {
        return Err(StorageError::Conflict(
            "Undo record original durable provenance",
        ));
    }
    retained(
        &store.connection,
        &record.source_operation_id,
        &["application_evidence"],
        &record.receipt_blob,
    )?;
    let receipt = read_json(store, rpc, &record.receipt_blob, RECEIPT_BYTES)?;
    if receipt != record.receipt {
        return Err(StorageError::Corrupt(
            "Undo receipt differs from actual retained bytes".into(),
        ));
    }
    let parsed: HostReceipt = serde_json::from_value(receipt.clone()).map_err(contract)?;
    validate_receipt(
        &source,
        &route,
        &InspectedUndoMaterial {
            receipt,
            authenticated_player_id: parsed.player_id,
        },
    )?;
    let associations = associations(store, rpc, &record.source_operation_id)?;
    let association = associations
        .iter()
        .find(|a| a.summary == record.material_summary)
        .ok_or(StorageError::NotFound("Original undo receipt association"))?;
    for reference in [
        &record.receipt_blob,
        &record.route_blob,
        &source.invocation_blob,
    ] {
        if !association.source_blobs.contains(reference) {
            return Err(StorageError::Conflict(
                "Original undo receipt source association",
            ));
        }
    }
    let marker = read_json(store, rpc, &record.material_summary, RECEIPT_BYTES)?;
    if marker["kind"] != "provider_undo_material"
        || marker["recordId"] != record.record_id.as_str()
        || marker["stepId"] != record.source_step_id.as_str()
        || marker["invocationId"] != record.source_invocation_id.as_str()
        || marker["receiptBlob"] != serde_json::to_value(&record.receipt_blob).map_err(contract)?
        || marker["routeBlob"] != serde_json::to_value(&record.route_blob).map_err(contract)?
    {
        return Err(StorageError::Conflict("Original undo material summary"));
    }
    Ok((source, route))
}
fn associations(
    store: &DurableStore,
    rpc: &dyn UndoRpcContext,
    operation: &OperationId,
) -> StorageResult<Vec<SummaryAssociation>> {
    let mut stmt=store.connection.prepare("SELECT record_json FROM events WHERE operation_id=?1 AND kind='application_summary' ORDER BY sequence LIMIT 4097")?;
    let mut rows = stmt.query([operation.as_str()])?;
    let mut result = Vec::new();
    let mut bytes = 0u64;
    while let Some(row) = rows.next()? {
        rpc.check()?;
        if result.len() >= ENTRIES {
            return Err(invalid("Undo original summary history budget exceeded"));
        }
        let text: String = row.get(0)?;
        if text.len() > 32768 {
            return Err(invalid("Undo source association metadata budget exceeded"));
        }
        let association: SummaryAssociation = decode(&text)?;
        if association.source_blobs.len() > 64 {
            return Err(invalid("Undo original summary source budget exceeded"));
        }
        retained(
            &store.connection,
            operation,
            &["application_summary"],
            &association.summary,
        )?;
        for source in &association.source_blobs {
            retained(
                &store.connection,
                operation,
                &["application_evidence"],
                source,
            )?;
        }
        bytes = bytes
            .checked_add(association.summary.byte_length)
            .filter(|v| *v <= HISTORY_BYTES)
            .ok_or_else(|| invalid("Undo summary history byte budget exceeded"))?;
        result.push(association);
    }
    Ok(result)
}
fn check_material_capacity(
    connection: &Connection,
    operation: &OperationId,
    summary: Option<&BlobRef>,
    sources: &[BlobRef],
    potential_new_sources: usize,
) -> StorageResult<()> {
    let record_count: i64 =
        connection.query_row("SELECT count(*) FROM provider_undo_records", [], |r| {
            r.get(0)
        })?;
    if record_count >= ENTRIES as i64 {
        return Err(invalid("Provider undo record capacity exceeded"));
    }
    let summary_count: i64 = connection.query_row(
        "SELECT count(*) FROM blob_refs WHERE owner_kind='application_summary' AND owner_id=?1",
        [operation.as_str()],
        |r| r.get(0),
    )?;
    let source_count: i64 = connection.query_row(
        "SELECT count(*) FROM blob_refs WHERE owner_kind='application_evidence' AND owner_id=?1",
        [operation.as_str()],
        |r| r.get(0),
    )?;
    let summary_new = match summary {
        Some(summary) => 1 - connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM blob_refs WHERE owner_kind='application_summary' AND owner_id=?1 AND digest=?2)",
            params![operation.as_str(),summary.digest.as_str()],|r|r.get::<_,i64>(0))?,
        None => 1,
    };
    let mut new_sources = BTreeSet::new();
    for source in sources {
        let present: i64 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM blob_refs WHERE owner_kind='application_evidence' AND owner_id=?1 AND digest=?2)",
            params![operation.as_str(),source.digest.as_str()],|r|r.get(0))?;
        if present == 0 {
            new_sources.insert(source.digest.clone());
        }
    }
    let required_sources = new_sources
        .len()
        .checked_add(potential_new_sources)
        .ok_or_else(|| invalid("Undo material capacity arithmetic exceeded"))?;
    if summary_count
        .checked_add(summary_new)
        .is_none_or(|v| v > ENTRIES as i64)
        || source_count
            .checked_add(
                i64::try_from(required_sources)
                    .map_err(|_| invalid("Undo material source capacity exceeded"))?,
            )
            .is_none_or(|v| v > ENTRIES as i64)
    {
        return Err(invalid("Undo material retention capacity exceeded"));
    }
    Ok(())
}
fn pin_material_summary(
    transaction: &Transaction<'_>,
    operation: &OperationId,
    summary: &BlobRef,
    sources: &[BlobRef],
) -> StorageResult<()> {
    check_material_capacity(transaction, operation, Some(summary), sources, 0)?;
    for source in sources {
        pin_blob(
            transaction,
            "application_evidence",
            operation.as_str(),
            source,
        )?;
    }
    pin_blob(
        transaction,
        "application_summary",
        operation.as_str(),
        summary,
    )?;
    transaction.execute(
        "INSERT INTO events(operation_id,kind,record_json) VALUES(?1,'application_summary',?2)",
        params![
            operation.as_str(),
            encode(&SummaryAssociation {
                summary: summary.clone(),
                source_blobs: sources.to_vec()
            })?
        ],
    )?;
    Ok(())
}

/// Capture an actual host receipt while the original source session is alive.
/// Pending is deliberately not claimable and does not assert source effects.
pub fn register_undo_record(
    store: &mut DurableStore,
    rpc: &dyn UndoRpcContext,
    authority: &mut dyn UndoAuthority,
    material_source: &mut dyn UndoMaterialSource,
    request: &UndoRegistrationRequest,
) -> StorageResult<ProviderUndoRecord> {
    let source = load_source(store, rpc, request)?;
    let principal = rpc.authenticated_principal()?;
    let current = rpc.current_context()?;
    if principal != source.operation.principal {
        return Err(StorageError::Conflict("Undo material owner"));
    }
    context_matches(store, &source.invocation["context"], &current)?;
    authority.authorize_capture(store, &source.operation, &source.invocation, &current)?;
    let (route, route_blob) = load_route(store, rpc, &request.route_digest)?;
    source_route_matches(&source, &route)?;
    if table_exists(&store.connection, "provider_undo_records")? {
        let old: Option<String> = store
            .connection
            .query_row(
                "SELECT record_id FROM provider_undo_records WHERE source_invocation_id=?1",
                [request.source_invocation_id.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            let old = read_record_inner(store, &ObjectId::new(old).map_err(contract)?)?;
            if old.route_digest != request.route_digest
                || old.source_invocation_digest != request.source_invocation_digest
            {
                return Err(StorageError::Conflict("Immutable undo source material"));
            }
            verify_material(store, rpc, &old)?;
            let fresh = rpc.current_context()?;
            context_matches(store, &source.invocation["context"], &fresh)?;
            if rpc.authenticated_principal()? != principal {
                return Err(StorageError::Conflict(
                    "Undo repeated capture principal changed",
                ));
            }
            authority.authorize_capture(store, &source.operation, &source.invocation, &fresh)?;
            rpc.check()?;
            if rpc.authenticated_principal()? != principal || rpc.current_context()? != fresh {
                return Err(StorageError::Conflict(
                    "Undo repeated capture release changed",
                ));
            }
            return Ok(old);
        }
    }
    // The unique Store prevents a concurrent writer between this admission and
    // callback. Known route/invocation pins are deduplicated; one receipt and
    // one summary slot remain necessary until actual bytes are acquired.
    check_material_capacity(
        &store.connection,
        &request.source_operation_id,
        None,
        &[route_blob.clone(), source.invocation_blob.clone()],
        1,
    )?;
    rpc.check()?;
    let material = material_source.inspect_source_material(
        store,
        &source.operation,
        &source.invocation,
        &route,
        &current,
    )?;
    let receipt_bytes = encode_json(&material.receipt).map_err(contract)?;
    if receipt_bytes.len() as u64 > RECEIPT_BYTES {
        return Err(invalid("Undo acquired receipt byte budget exceeded"));
    }
    let receipt = validate_receipt(&source, &route, &material)?;
    let captured = CapturedTruthContext {
        principal: principal.clone(),
        context: current.clone(),
        deadline: Instant::now() + Duration::from_secs(30),
    };
    captured.check()?;
    let receipt_blob = store.put_blob(&receipt_bytes)?;
    let record_id=ObjectId::new(format!("undo-{}",digest(&json!({"sourceInvocationId":request.source_invocation_id,"sourceInvocationDigest":request.source_invocation_digest,"routeDigest":request.route_digest,"tokenRecordDigest":receipt.token_record_digest}))?.as_str())).map_err(contract)?;
    let marker = json!({"kind":"provider_undo_material","recordId":record_id,"stepId":request.source_step_id,"invocationId":request.source_invocation_id,"receiptBlob":receipt_blob,"routeBlob":route_blob,"sourceRefs":[receipt_blob,route_blob,source.invocation_blob]});
    let material_summary = store.put_blob(&encode_json(&marker).map_err(contract)?)?;
    let record = ProviderUndoRecord {
        record_id,
        principal: principal.clone(),
        project_id: source.operation.project_id.clone(),
        source_operation_id: request.source_operation_id.clone(),
        source_plan_hash: source.operation.plan_hash.clone(),
        source_step_id: request.source_step_id.clone(),
        source_invocation_id: request.source_invocation_id.clone(),
        source_invocation_digest: request.source_invocation_digest.clone(),
        source_context: source.invocation["context"].clone(),
        scope: source.operation.scope.clone(),
        route_digest: request.route_digest.clone(),
        route_blob: route_blob.clone(),
        receipt: material.receipt,
        receipt_blob: receipt_blob.clone(),
        material_summary: material_summary.clone(),
        settled_observation: None,
        after_states: vec![],
        state: UndoRecordState::Pending,
    };
    // Initial actual-session capture authority retains private Pending truth.
    // Fresh caller authority controls release after this commit, never retention.
    // No native/transport callback is invoked while SQLite's writer is held.
    let transaction =
        Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA)?;
    let now = load_source(store, &captured, request)?;
    if now.invocation != source.invocation || now.operation.principal != principal {
        return Err(StorageError::Conflict("Undo source changed during capture"));
    }
    pin_material_summary(
        &transaction,
        &request.source_operation_id,
        &material_summary,
        &[receipt_blob.clone(), route_blob, source.invocation_blob],
    )?;
    transaction.execute("INSERT INTO provider_undo_records(record_id,source_operation_id,source_step_id,source_invocation_id,route_digest,receipt_digest,receipt_blob,record_json,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'pending')",params![record.record_id.as_str(),record.source_operation_id.as_str(),record.source_step_id.as_str(),record.source_invocation_id.as_str(),record.route_digest.as_str(),receipt.token_record_digest.as_str(),receipt_blob.digest.as_str(),encode_record(&record)?])?;
    captured.check()?;
    transaction.commit()?;
    rpc.check()?;
    let fresh = rpc.current_context()?;
    context_matches(store, &record.source_context, &fresh)?;
    if rpc.authenticated_principal()? != principal {
        return Err(StorageError::Conflict("Undo capture principal changed"));
    }
    authority.authorize_capture(store, &now.operation, &now.invocation, &fresh)?;
    rpc.check()?;
    if rpc.authenticated_principal()? != principal || rpc.current_context()? != fresh {
        return Err(StorageError::Conflict(
            "Undo capture release authority changed",
        ));
    }
    Ok(record)
}

fn eligible_source(source: &OriginalSource) -> StorageResult<()> {
    let step = source
        .operation
        .steps
        .iter()
        .find(|s| s.step_id.as_str() == source.invocation["stepId"].as_str().unwrap_or(""))
        .ok_or(StorageError::NotFound("Undo source observation"))?;
    if source.operation.reconciliation_required
        || step.dispatch != DispatchEvidence::Observed
        || !step.finished
        || !step.write_effect
        || step.further_effects_possible
        || !matches!(
            step.effect,
            EffectEvidence::SomeConfirmed | EffectEvidence::CompleteConfirmed
        )
    {
        return Err(StorageError::InvalidTransition(
            "Undo promotion/claim requires the actual settled observed source".into(),
        ));
    }
    Ok(())
}
fn same_observation_pins(value: &Value, invocation: &Value) -> bool {
    [
        "stepId",
        "invocationId",
        "bindingId",
        "contextDigest",
        "implementationDigest",
        "argumentsDigest",
    ]
    .iter()
    .all(|key| value[*key] == invocation[*key])
}
fn source_targets(source: &OriginalSource) -> StorageResult<BTreeSet<String>> {
    let list: Vec<String> = field(&source.step, "resourcesWritten")?;
    let targets: BTreeSet<_> = list.iter().cloned().collect();
    if targets.is_empty()
        || targets.len() != list.len()
        || targets.len() > ENTRIES
        || targets.iter().any(|v| v.is_empty() || v.len() > 512)
    {
        return Err(invalid("Undo original target footprint is invalid"));
    }
    Ok(targets)
}
fn verify_state_blob(
    store: &DurableStore,
    rpc: &dyn UndoRpcContext,
    operation: &OperationId,
    blob: &BlobRef,
    total: &mut u64,
) -> StorageResult<()> {
    retained(&store.connection, operation, &["operation"], blob)?;
    *total = total
        .checked_add(blob.byte_length)
        .filter(|v| *v <= STATE_BYTES)
        .ok_or_else(|| invalid("Undo state byte budget exceeded"))?;
    store
        .cas
        .read_verified_slice::<StorageError, _>(blob, blob.byte_length, 1, || rpc.check())?;
    Ok(())
}
fn retained_before(
    store: &DurableStore,
    rpc: &dyn UndoRpcContext,
    source: &OriginalSource,
    associations: &[SummaryAssociation],
) -> StorageResult<BTreeMap<String, BlobRef>> {
    let mut result = BTreeMap::new();
    let mut bytes = 0u64;
    for association in associations {
        let marker = read_json(store, rpc, &association.summary, RECEIPT_BYTES)?;
        if marker["kind"] != "before_capture_summary"
            || marker["stepId"] != source.invocation["stepId"]
            || marker["invocationId"] != source.invocation["invocationId"]
        {
            continue;
        }
        let body: BlobRef = field(&marker, "captureBlob")?;
        if !association.source_blobs.contains(&body) {
            return Err(StorageError::Conflict("Undo before capture association"));
        }
        bytes = bytes
            .checked_add(body.byte_length)
            .filter(|v| *v <= HISTORY_BYTES)
            .ok_or_else(|| invalid("Undo before history budget exceeded"))?;
        let envelope = read_json(store, rpc, &body, 8 * 1024 * 1024)?;
        if envelope["kind"] != "before_capture"
            || envelope["version"] != 1
            || envelope["operationId"] != source.operation.operation_id.as_str()
            || !same_observation_pins(&envelope, &source.invocation)
        {
            return Err(StorageError::Conflict("Original undo before capture pins"));
        }
        let images = envelope["images"]
            .as_array()
            .ok_or_else(|| invalid("Undo before capture entries missing"))?;
        if images.len() > ENTRIES {
            return Err(invalid("Undo before capture entry budget exceeded"));
        }
        let mut local = BTreeSet::new();
        for entry in images {
            let target: String = field(entry, "target")?;
            let before: BlobRef = field(entry, "before")?;
            if !local.insert(target.clone()) {
                return Err(StorageError::Conflict(
                    "Duplicate undo before capture target",
                ));
            }
            retained(
                &store.connection,
                &source.operation.operation_id,
                &["operation"],
                &before,
            )?;
            if let Some(old) = result.insert(target, before.clone())
                && old != before
            {
                return Err(StorageError::Conflict(
                    "Original undo before capture changed",
                ));
            }
        }
    }
    Ok(result)
}
fn after_provenance(
    store: &DurableStore,
    rpc: &dyn UndoRpcContext,
    source: &OriginalSource,
) -> StorageResult<(BlobRef, Vec<UndoTargetState>)> {
    eligible_source(source)?;
    let targets = source_targets(source)?;
    let associations = associations(store, rpc, &source.operation.operation_id)?;
    let before = retained_before(store, rpc, source, &associations)?;
    let step = source
        .operation
        .steps
        .iter()
        .find(|s| s.step_id.as_str() == source.invocation["stepId"].as_str().unwrap_or(""))
        .ok_or(StorageError::NotFound("Undo source observation"))?;
    if step.observation_refs.len() > ENTRIES {
        return Err(invalid("Undo observation history entry budget exceeded"));
    }
    let mut history = 0u64;
    // The byte budget covers the whole retained observation history, including
    // repeated settled envelopes, rather than resetting for each envelope.
    let mut state_bytes = 0u64;
    let mut selected = None;
    for blob in &step.observation_refs {
        retained(
            &store.connection,
            &source.operation.operation_id,
            &["operation"],
            blob,
        )?;
        history = history
            .checked_add(blob.byte_length)
            .filter(|v| *v <= HISTORY_BYTES)
            .ok_or_else(|| invalid("Undo observation history byte budget exceeded"))?;
        let envelope = read_json(store, rpc, blob, 8 * 1024 * 1024)?;
        if envelope["kind"] != "independent_readback" {
            continue;
        }
        if !same_observation_pins(&envelope, &source.invocation) {
            return Err(StorageError::Conflict(
                "Undo original independent observation pins",
            ));
        }
        if envelope["settled"] != true
            || !matches!(
                envelope["effect"].as_str(),
                Some("some_confirmed" | "complete_confirmed")
            )
        {
            continue;
        }
        let association = associations
            .iter()
            .find(|a| a.source_blobs.contains(blob))
            .ok_or(StorageError::NotFound(
                "Undo independent observation association",
            ))?;
        let marker = read_json(store, rpc, &association.summary, RECEIPT_BYTES)?;
        if marker["kind"] != "independent_readback_summary"
            || marker["stepId"] != source.invocation["stepId"]
            || marker["invocationId"] != source.invocation["invocationId"]
            || marker["effect"] != envelope["effect"]
            || marker["settled"] != envelope["settled"]
        {
            return Err(StorageError::Conflict(
                "Undo original readback summary provenance",
            ));
        }
        let refs: Vec<BlobRef> = field(&envelope, "sourceRefs")?;
        if refs.len() > 64
            || refs
                .iter()
                .any(|reference| !association.source_blobs.contains(reference))
        {
            return Err(StorageError::Conflict(
                "Undo independent raw source association",
            ));
        }
        for reference in refs {
            history = history
                .checked_add(reference.byte_length)
                .filter(|v| *v <= HISTORY_BYTES)
                .ok_or_else(|| invalid("Undo raw observation source byte budget exceeded"))?;
            store.cas.read_verified_slice::<StorageError, _>(
                &reference,
                reference.byte_length,
                1,
                || rpc.check(),
            )?;
        }
        let entries = envelope["afterStates"]
            .as_array()
            .ok_or(StorageError::NotFound("Full independent undo after states"))?;
        if entries.len() > ENTRIES {
            return Err(invalid("Undo after state entry budget exceeded"));
        }
        let mut actual = BTreeSet::new();
        let mut states = Vec::new();
        for entry in entries {
            let state: UndoTargetState = serde_json::from_value(entry.clone()).map_err(contract)?;
            if !targets.contains(&state.target)
                || !actual.insert(state.target.clone())
                || state.before.as_ref() != before.get(&state.target)
                || !association.source_blobs.contains(&state.after)
            {
                return Err(StorageError::Conflict("Undo full target/before provenance"));
            }
            verify_state_blob(
                store,
                rpc,
                &source.operation.operation_id,
                &state.after,
                &mut state_bytes,
            )?;
            if let Some(before) = &state.before {
                verify_state_blob(
                    store,
                    rpc,
                    &source.operation.operation_id,
                    before,
                    &mut state_bytes,
                )?;
            }
            states.push(state);
        }
        if actual != targets {
            return Err(StorageError::Conflict(
                "Undo after states omit original targets",
            ));
        }
        states.sort_by(|a, b| a.target.cmp(&b.target));
        if let Some((_, prior)) = &selected
            && prior != &states
        {
            return Err(StorageError::Conflict(
                "Settled undo after history disagrees",
            ));
        }
        selected = Some((blob.clone(), states));
    }
    selected.ok_or(StorageError::NotFound(
        "Original settled independent undo after states",
    ))
}

/// Promote only actual retained original readback. It never calls the expired
/// original host session, never infers rollback, and never erases source failure.
pub fn promote_undo_record(
    store: &mut DurableStore,
    rpc: &dyn UndoRpcContext,
    authority: &mut dyn UndoAuthority,
    id: &ObjectId,
) -> StorageResult<ProviderUndoRecord> {
    let mut record = read_record_inner(store, id)?;
    let principal = rpc.authenticated_principal()?;
    let current = rpc.current_context()?;
    if principal != record.principal {
        return Err(StorageError::Conflict("Undo record owner"));
    }
    context_matches(store, &record.source_context, &current)?;
    authority.authorize_read(store, &record, &current)?;
    let (source, _) = verify_material(store, rpc, &record)?;
    if matches!(record.state, UndoRecordState::Reserved { .. }) {
        return Err(StorageError::Conflict(
            "Provider undo material already claimed",
        ));
    }
    let (observation, states) = after_provenance(store, rpc, &source)?;
    if record.state == UndoRecordState::Available {
        if record.settled_observation.as_ref() != Some(&observation)
            || record.after_states != states
        {
            return Err(StorageError::Conflict(
                "Immutable available undo after history",
            ));
        }
        let fresh = rpc.current_context()?;
        context_matches(store, &record.source_context, &fresh)?;
        if rpc.authenticated_principal()? != principal {
            return Err(StorageError::Conflict(
                "Undo repeated promotion principal changed",
            ));
        }
        authority.authorize_read(store, &record, &fresh)?;
        rpc.check()?;
        if rpc.authenticated_principal()? != principal || rpc.current_context()? != fresh {
            return Err(StorageError::Conflict(
                "Undo repeated promotion release changed",
            ));
        }
        return Ok(record);
    }
    record.state = UndoRecordState::Available;
    record.settled_observation = Some(observation.clone());
    record.after_states = states;
    let authorized_context = rpc.current_context()?;
    context_matches(store, &record.source_context, &authorized_context)?;
    if rpc.authenticated_principal()? != principal {
        return Err(StorageError::Conflict("Undo promotion principal changed"));
    }
    authority.authorize_read(store, &record, &authorized_context)?;
    rpc.check()?;
    if rpc.authenticated_principal()? != principal || rpc.current_context()? != authorized_context {
        return Err(StorageError::Conflict(
            "Undo promotion authority changed before transaction",
        ));
    }
    let transaction =
        Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate)?;
    let fresh_source = load_source(store, rpc, &request_for(&record))?;
    let (fresh_observation, fresh_states) = after_provenance(store, rpc, &fresh_source)?;
    if fresh_observation != observation || fresh_states != record.after_states {
        return Err(StorageError::Conflict(
            "Undo after history changed during promotion",
        ));
    }
    let changed=transaction.execute("UPDATE provider_undo_records SET state='available',record_json=?1 WHERE record_id=?2 AND state='pending'",params![encode_record(&record)?,id.as_str()])?;
    if changed != 1 {
        return Err(StorageError::Conflict("Undo material promotion state"));
    }
    for state in &record.after_states {
        pin_blob(&transaction, "undo_record", id.as_str(), &state.after)?;
        if let Some(before) = &state.before {
            pin_blob(&transaction, "undo_record", id.as_str(), before)?;
        }
    }
    pin_blob(&transaction, "undo_record", id.as_str(), &observation)?;
    transaction.execute(
        "INSERT INTO events(operation_id,kind,record_json) VALUES(?1,'provider_undo_available',?2)",
        params![record.source_operation_id.as_str(), encode_record(&record)?],
    )?;
    let fresh = rpc.current_context()?;
    context_matches(store, &record.source_context, &fresh)?;
    if rpc.authenticated_principal()? != principal {
        return Err(StorageError::Conflict("Undo promotion principal changed"));
    }
    if fresh != authorized_context {
        return Err(StorageError::Conflict(
            "Undo promotion current context changed",
        ));
    }
    rpc.check()?;
    transaction.commit()?;
    authority.authorize_read(store, &record, &authorized_context)?;
    rpc.check()?;
    if rpc.authenticated_principal()? != principal || rpc.current_context()? != authorized_context {
        return Err(StorageError::Conflict(
            "Undo promotion release authority changed",
        ));
    }
    Ok(record)
}
pub fn provider_undo_record(
    store: &DurableStore,
    rpc: &dyn UndoRpcContext,
    authority: &mut dyn UndoAuthority,
    id: &ObjectId,
) -> StorageResult<ProviderUndoRecord> {
    let record = read_record_inner(store, id)?;
    let principal = rpc.authenticated_principal()?;
    let current = rpc.current_context()?;
    if principal != record.principal {
        return Err(StorageError::Conflict("Undo record owner"));
    }
    authority.authorize_read(store, &record, &current)?;
    verify_material(store, rpc, &record)?;
    if let Some(observation) = &record.settled_observation {
        retained(
            &store.connection,
            &record.source_operation_id,
            &["operation"],
            observation,
        )?;
    }
    if rpc.authenticated_principal()? != principal {
        return Err(StorageError::Conflict("Undo record read principal changed"));
    }
    let fresh = rpc.current_context()?;
    authority.authorize_read(store, &record, &fresh)?;
    rpc.check()?;
    if rpc.authenticated_principal()? != principal || rpc.current_context()? != fresh {
        return Err(StorageError::Conflict(
            "Undo record release authority changed",
        ));
    }
    Ok(record)
}
/// Metadata lookup for the concrete host dispatcher and independent observer.
/// It is not a claim constructor or an access grant; the caller still composes
/// provider_undo_record with fresh current ACL before reading/using the record.
pub fn claimed_undo_record(
    store: &DurableStore,
    operation: &OperationId,
    step: &StepId,
    invocation: &InvocationId,
) -> StorageResult<ProviderUndoRecord> {
    if !table_exists(&store.connection, "provider_undo_records")? {
        return Err(StorageError::NotFound("Durable undo claim"));
    }
    let id:Option<String>=store.connection.query_row("SELECT record_id FROM provider_undo_records WHERE state='reserved' AND claim_operation_id=?1 AND claim_step_id=?2 AND claim_invocation_id=?3",params![operation.as_str(),step.as_str(),invocation.as_str()],|r|r.get(0)).optional()?;
    let record = read_record_inner(
        store,
        &ObjectId::new(id.ok_or(StorageError::NotFound("Durable undo claim"))?)
            .map_err(contract)?,
    )?;
    let new = store.operation(operation)?;
    let actual = new
        .steps
        .iter()
        .find(|s| s.step_id == *step)
        .ok_or(StorageError::NotFound("Undo claimed intent step"))?;
    if actual.invocation_id.as_ref() != Some(invocation)
        || actual.dispatch == DispatchEvidence::NotSent
    {
        return Err(StorageError::Conflict(
            "Undo claim has no actual dispatched intent",
        ));
    }
    if let UndoRecordState::Reserved {
        invocation_digest, ..
    } = &record.state
        && actual.invocation_digest.as_ref() != Some(invocation_digest)
    {
        return Err(StorageError::Conflict(
            "Undo claim actual invocation digest",
        ));
    }
    Ok(record)
}

/// Every ordinary/result-resolved route calls this guard. Binding plus action
/// identity is reserved, so changing a descriptor digest cannot bypass its role.
pub(crate) fn reject_recovery_only_route(
    connection: &Connection,
    invocation: &Value,
) -> StorageResult<()> {
    let binding: BindingId = field(invocation, "bindingId")?;
    let action: mmmm_contracts::ActionId = field(invocation, "actionId")?;
    let action_digest: Sha256Digest = field(invocation, "actionDigest")?;
    if registered_role(connection, &binding, &action, &action_digest)? {
        return Err(StorageError::InvalidTransition(
            "Registered provider undo actions require an atomic recovery claim".into(),
        ));
    }
    Ok(())
}
fn registered_role(
    connection: &Connection,
    binding: &BindingId,
    action: &mmmm_contracts::ActionId,
    action_digest: &Sha256Digest,
) -> StorageResult<bool> {
    if !table_exists(connection, "undo_routes")? {
        return Ok(false);
    }
    Ok(connection.query_row("SELECT EXISTS(SELECT 1 FROM undo_routes WHERE undo_binding_id=?1 AND (undo_action_id=?2 OR undo_action_digest=?3))",params![binding.as_str(),action.as_str(),action_digest.as_str()],|r|r.get::<_,i64>(0))? == 1)
}
/// Immutable server role membership; this read grants no execution authority.
pub fn is_registered_undo_action(
    store: &DurableStore,
    binding: &BindingId,
    action: &mmmm_contracts::ActionId,
    action_digest: &Sha256Digest,
) -> StorageResult<bool> {
    registered_role(&store.connection, binding, action, action_digest)
}
pub(crate) struct UndoIntentAuthorization<'a> {
    record_id: &'a ObjectId,
    rpc: &'a dyn UndoRpcContext,
    record_digest: Sha256Digest,
    invocation_digest: Sha256Digest,
    current_context: Value,
}
pub(crate) struct UndoClaimInput<'a> {
    pub operation: &'a OperationRecord,
    pub plan: &'a Value,
    pub step: &'a Value,
    pub invocation: &'a Value,
    pub invocation_blob: &'a BlobRef,
}
fn validate_claim(
    store: &DurableStore,
    input: &UndoClaimInput<'_>,
    rpc: &dyn UndoRpcContext,
    record_id: &ObjectId,
) -> StorageResult<(ProviderUndoRecord, OriginalSource, BlobRef, Value)> {
    let record = read_record_inner(store, record_id)?;
    if record.state != UndoRecordState::Available {
        return Err(StorageError::Conflict(
            "Provider undo material is pending or already claimed",
        ));
    }
    rpc.check()?;
    if rpc.authenticated_principal()? != record.principal
        || input.operation.principal != record.principal
        || input.operation.project_id != record.project_id
        || input.operation.scope != record.scope
        || input.operation.operation_id == record.source_operation_id
    {
        return Err(StorageError::Conflict(
            "Undo new operation owner/project/full scope",
        ));
    }
    let (source, route) = verify_material(store, rpc, &record)?;
    let (observation, states) = after_provenance(store, rpc, &source)?;
    if record.settled_observation.as_ref() != Some(&observation) || record.after_states != states {
        return Err(StorageError::Conflict(
            "Undo available source observation changed",
        ));
    }
    let receipt: HostReceipt = serde_json::from_value(record.receipt.clone()).map_err(contract)?;
    let arguments = json!({"tokenRecordId":receipt.token_record_id,"tokenRecordDigest":receipt.token_record_digest,
        "sourceOperationId":record.source_operation_id,"sourceStepId":record.source_step_id,"sourceInvocationId":record.source_invocation_id});
    if input.invocation["arguments"] != arguments
        || input.step["arguments"] != arguments
        || input.invocation["bindingId"] != route.undo_binding_id.as_str()
        || input.invocation["actionId"] != route.undo_action["actionId"]
        || input.invocation["actionDigest"] != digest(&route.undo_action)?.as_str()
        || input.invocation["implementationDigest"] != route.undo_action["implementationDigest"]
        || input.step["recovery"] != "none"
        || input.step["verificationRequirement"] != "independent_readback"
        || input.step["effect"] == "read"
        || !input.step["resultBindings"]
            .as_array()
            .is_some_and(|v| v.is_empty())
    {
        return Err(StorageError::Conflict(
            "Undo registered route and closed original-source arguments",
        ));
    }
    store
        .validator
        .compile_action_schema(&route.undo_action["inputSchema"])
        .map_err(contract)?
        .validate(&arguments)
        .map_err(contract)?;
    let expected: BTreeSet<String> = record
        .after_states
        .iter()
        .map(|s| s.target.clone())
        .collect();
    for key in ["resourcesRead", "resourcesWritten"] {
        let list: Vec<String> = field(input.step, key)?;
        if list.len() != expected.len() || list.into_iter().collect::<BTreeSet<_>>() != expected {
            return Err(StorageError::Conflict(
                "Undo approved full frozen target footprint",
            ));
        }
    }
    let preconditions = input.plan["preconditions"]
        .as_array()
        .ok_or_else(|| invalid("Undo approved preconditions missing"))?;
    for state in &record.after_states {
        if !preconditions.iter().any(|p| {
            p["kind"] == "resource_hash"
                && p["subject"] == state.target
                && p["coverage"] == "full_target"
                && p["expected"] == state.after.digest.as_str()
        }) {
            return Err(StorageError::Conflict(
                "Undo approved original full-target after precondition",
            ));
        }
    }
    context_matches(store, &record.source_context, &input.invocation["context"])?;
    let current = rpc.current_context()?;
    if current != input.invocation["context"] {
        return Err(StorageError::Conflict(
            "Undo actual current context differs from approved invocation",
        ));
    }
    Ok((record, source, observation, current))
}
fn prepare_undo_authorization<'a>(
    store: &DurableStore,
    rpc: &'a dyn UndoRpcContext,
    authority: &mut dyn UndoAuthority,
    request: &UndoDispatchRequest<'a>,
) -> StorageResult<UndoIntentAuthorization<'a>> {
    rpc.check()?;
    store
        .validator
        .validate("Invocation", request.invocation)
        .map_err(contract)?;
    let operation = store.operation(request.operation_id)?;
    let plan = frozen_plan(store, rpc, &operation)?;
    let step = plan["steps"]
        .as_array()
        .and_then(|steps| {
            steps
                .iter()
                .find(|step| step["stepId"] == request.step_id.as_str())
        })
        .ok_or(StorageError::NotFound("Frozen undo claim step"))?;
    let invocation_bytes = encode_json(request.invocation).map_err(contract)?;
    let invocation_blob = BlobRef {
        digest: mmmm_contracts::raw_digest(&invocation_bytes),
        byte_length: invocation_bytes.len() as u64,
    };
    let input = UndoClaimInput {
        operation: &operation,
        plan: &plan,
        step,
        invocation: request.invocation,
        invocation_blob: &invocation_blob,
    };
    let (record, _, _, current) = validate_claim(store, &input, rpc, request.undo_record_id)?;
    authority.authorize_recovery(store, &record, request.invocation)?;
    let mut total = 0u64;
    for state in &record.after_states {
        rpc.check()?;
        let remaining = STATE_BYTES
            .checked_sub(total)
            .ok_or_else(|| invalid("Undo current state byte budget exceeded"))?;
        let bytes = authority.read_current_target(
            store,
            &record,
            request.invocation,
            &state.target,
            remaining.min(state.after.byte_length),
        )?;
        total = total
            .checked_add(bytes.len() as u64)
            .filter(|v| *v <= STATE_BYTES)
            .ok_or_else(|| invalid("Undo current state byte budget exceeded"))?;
        if bytes.len() as u64 != state.after.byte_length
            || mmmm_contracts::raw_digest(&bytes) != state.after.digest
        {
            return Err(StorageError::Conflict("Undo live original target drift"));
        }
    }
    rpc.check()?;
    if rpc.authenticated_principal()? != record.principal || rpc.current_context()? != current {
        return Err(StorageError::Conflict(
            "Undo claim authenticated current context changed",
        ));
    }
    authority.authorize_recovery(store, &record, request.invocation)?;
    rpc.check()?;
    if rpc.authenticated_principal()? != record.principal || rpc.current_context()? != current {
        return Err(StorageError::Conflict(
            "Undo authority changed during precheck",
        ));
    }
    Ok(UndoIntentAuthorization {
        record_id: request.undo_record_id,
        rpc,
        record_digest: mmmm_contracts::raw_digest(encode_record(&record)?.as_bytes()),
        invocation_digest: invocation_blob.digest,
        current_context: current,
    })
}
/// The precheck seal contains no public constructor or transport port. Inside
/// the common intent transaction only durable provenance, the local call budget
/// and immutable request identity are rechecked. The host Recover handler must
/// independently recheck live after-state immediately before its mutation.
pub(crate) fn reserve_undo_in(
    transaction: &Transaction<'_>,
    store: &DurableStore,
    input: UndoClaimInput<'_>,
    authorization: &UndoIntentAuthorization<'_>,
) -> StorageResult<()> {
    let (mut record, source, observation, current) =
        validate_claim(store, &input, authorization.rpc, authorization.record_id)?;
    if mmmm_contracts::raw_digest(encode_record(&record)?.as_bytes()) != authorization.record_digest
        || input.invocation_blob.digest != authorization.invocation_digest
        || current != authorization.current_context
    {
        return Err(StorageError::Conflict(
            "Undo precheck seal differs from durable/current claim",
        ));
    }
    let invocation_id: InvocationId = field(input.invocation, "invocationId")?;
    record.state = UndoRecordState::Reserved {
        operation_id: input.operation.operation_id.clone(),
        step_id: field(input.step, "stepId")?,
        invocation_id: invocation_id.clone(),
        invocation_digest: input.invocation_blob.digest.clone(),
    };
    let changed=transaction.execute("UPDATE provider_undo_records SET state='reserved',record_json=?1,claim_operation_id=?2,claim_step_id=?3,claim_invocation_id=?4 WHERE record_id=?5 AND state='available'",params![encode_record(&record)?,input.operation.operation_id.as_str(),input.step["stepId"].as_str(),invocation_id.as_str(),record.record_id.as_str()])?;
    if changed != 1 {
        return Err(StorageError::Conflict(
            "Provider undo material unique claim",
        ));
    }
    transaction.execute(
        "INSERT INTO events(operation_id,kind,record_json) VALUES(?1,'provider_undo_claim',?2)",
        params![
            input.operation.operation_id.as_str(),
            encode_record(&record)?
        ],
    )?;
    let mut refs = vec![
        record.receipt_blob,
        record.material_summary,
        record.route_blob,
        source.invocation_blob,
        observation,
    ];
    for state in record.after_states {
        refs.push(state.after);
        if let Some(before) = state.before {
            refs.push(before);
        }
    }
    refs.sort_by(|a, b| a.digest.cmp(&b.digest));
    refs.dedup();
    for reference in &refs {
        pin_blob(transaction, "undo_claim", invocation_id.as_str(), reference)?;
    }
    authorization.rpc.check()?;
    Ok(())
}

/// Fresh live reads and grants are checked before opening SQLite's write
/// transaction; claim and original intent commit remain inseparable.
pub fn dispatch_undo_intent(
    store: &mut DurableStore,
    rpc: &dyn UndoRpcContext,
    authority: &mut dyn UndoAuthority,
    request: &UndoDispatchRequest<'_>,
) -> StorageResult<StepRecord> {
    let authorization = prepare_undo_authorization(store, rpc, authority, request)?;
    store.dispatch_intent_internal(
        request.operation_id,
        request.step_id,
        request.invocation,
        None,
        Some(authorization),
    )
}

#[cfg(test)]
#[path = "undo_tests.rs"]
mod tests;

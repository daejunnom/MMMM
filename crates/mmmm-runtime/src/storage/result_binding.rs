//! Closed, server-registered result codecs resolve data slots in one frozen
//! invocation. CAS references and witness JSON are evidence, never registry or
//! dispatch authority. The existing dispatch transaction owns the only intent.

use super::{
    BlobRef, DurableStore, OperationRecord, StorageError, StorageResult,
    cas::Cas,
    journal::{decode, pin_blob, step_verified},
};
use mmmm_contracts::{
    BindingId, ContractValidator, InvocationId, ObjectId, OperationId, Sha256Digest, StepId,
    canonical_digest, encode_json, parse_json,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const MAX_BINDINGS: usize = 64;
const MAX_WITNESS_BYTES: u64 = 65_536;
const MAX_REGISTRY_BYTES: usize = 1_048_576;
const MAX_TOTAL_SOURCE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_REGISTRY_ROWS: i64 = 4096;
const REGISTRY_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS result_codecs (
 codec_id TEXT PRIMARY KEY, metadata_digest TEXT NOT NULL CHECK(length(metadata_digest)=64),
 blob_digest TEXT NOT NULL REFERENCES blobs(digest), byte_length INTEGER NOT NULL CHECK(byte_length>0)
) STRICT;
CREATE TABLE IF NOT EXISTS result_actions (
 binding_id TEXT NOT NULL, action_digest TEXT NOT NULL CHECK(length(action_digest)=64),
 action_id TEXT NOT NULL, contract_version TEXT NOT NULL,
 implementation_digest TEXT NOT NULL CHECK(length(implementation_digest)=64),
 blob_digest TEXT NOT NULL REFERENCES blobs(digest), byte_length INTEGER NOT NULL CHECK(byte_length>0),
 PRIMARY KEY(binding_id,action_digest)
) STRICT;";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResultCodecImplementation {
    #[serde(rename = "mmmm.json.identity.v1")]
    JsonIdentityV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultArgumentSlot {
    pub action_digest: Sha256Digest,
    pub argument_pointer: String,
}

/// Only trusted server composition registers this closed Rust implementation.
/// No RPC is provided; allowed slots must be reviewed against the pinned action.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisteredResultCodec {
    pub codec_id: ObjectId,
    pub implementation: ResultCodecImplementation,
    pub input_schema: Value,
    pub output_schema: Value,
    pub allowed_slots: Vec<ResultArgumentSlot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultStepBinding {
    pub argument_pointer: String,
    pub source_step_id: StepId,
    pub output_pointer: String,
    pub expected_schema_digest: Sha256Digest,
    pub codec_id: ObjectId,
    pub codec_digest: Sha256Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultBindingWitness {
    pub binding: ResultStepBinding,
    pub source_invocation_id: InvocationId,
    pub source_invocation_digest: Sha256Digest,
    pub source_result: BlobRef,
    pub source_result_summary: BlobRef,
    pub source_action: BlobRef,
    pub codec: BlobRef,
    pub selected_value_digest: Sha256Digest,
    pub resolved_value_digest: Sha256Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultFootprint {
    pub resources_read: Vec<Value>,
    pub resources_written: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultResolutionWitness {
    pub kind: String,
    pub version: u32,
    pub operation_id: OperationId,
    pub plan_hash: Sha256Digest,
    pub step_id: StepId,
    pub template_arguments_digest: Sha256Digest,
    pub arguments_blob: BlobRef,
    pub arguments_digest: Sha256Digest,
    pub context_digest: Sha256Digest,
    pub action_digest: Sha256Digest,
    pub implementation_digest: Sha256Digest,
    pub resolved_footprint: ResultFootprint,
    pub bindings: Vec<ResultBindingWitness>,
}

fn contract(error: impl std::fmt::Display) -> StorageError {
    StorageError::Contract(error.to_string())
}
fn invalid(message: &'static str) -> StorageError {
    StorageError::InvalidInput(message.into())
}
fn digest(value: &Value) -> StorageResult<Sha256Digest> {
    canonical_digest(value).map_err(contract)
}
fn text<'a>(value: &'a Value, field: &str) -> StorageResult<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| invalid("Result witness string missing"))
}
fn table_exists(connection: &Connection, name: &str) -> StorageResult<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [name],
        |row| row.get::<_, i64>(0),
    )? == 1)
}
fn row_blob(row: (String, i64)) -> StorageResult<BlobRef> {
    Ok(BlobRef {
        digest: Sha256Digest::new(row.0).map_err(contract)?,
        byte_length: u64::try_from(row.1).map_err(|_| invalid("Negative registry blob length"))?,
    })
}

fn registry_pin(
    connection: &Connection,
    kind: &str,
    owner: &str,
    blob: &BlobRef,
) -> StorageResult<()> {
    let length = i64::try_from(blob.byte_length)
        .map_err(|_| invalid("Registry length exceeds SQLite range"))?;
    let exists:i64=connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM blob_refs r JOIN blobs b ON b.digest=r.digest WHERE r.owner_kind=?1 AND r.owner_id=?2 AND r.digest=?3 AND b.byte_length=?4)",
        params![kind,owner,blob.digest.as_str(),length],|row|row.get(0),
    )?;
    if exists != 1 {
        return Err(StorageError::Corrupt(
            "Registered result source retention differs".into(),
        ));
    }
    Ok(())
}

/// Strict RFC 6901 tokens, bounded before allocation. Empty/root replacement,
/// append indexes and malformed escape spelling never select a new slot.
pub fn result_pointer_tokens(pointer: &str) -> StorageResult<Vec<String>> {
    if !pointer.starts_with('/') || pointer.len() > 1024 {
        return Err(invalid(
            "Result pointer must select a bounded existing slot",
        ));
    }
    let parts: Vec<_> = pointer[1..].split('/').collect();
    if parts.len() > 32 {
        return Err(invalid("Result pointer depth exceeds its budget"));
    }
    parts
        .into_iter()
        .map(|part| {
            let mut token = String::new();
            let mut chars = part.chars();
            while let Some(ch) = chars.next() {
                if ch == '~' {
                    token.push(match chars.next() {
                        Some('0') => '~',
                        Some('1') => '/',
                        _ => return Err(invalid("Invalid result pointer escape")),
                    });
                } else {
                    token.push(ch);
                }
            }
            if token.is_empty() || token == "-" {
                return Err(invalid("Result pointer must select an existing named slot"));
            }
            Ok(token)
        })
        .collect()
}

fn protected(token: &str) -> bool {
    let key: String = token
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    matches!(
        key.as_str(),
        "authority"
            | "principal"
            | "principalref"
            | "grant"
            | "grants"
            | "permission"
            | "permissions"
            | "context"
            | "contextid"
            | "contextdigest"
            | "policy"
            | "policyrevision"
            | "endpoint"
            | "url"
            | "uri"
            | "path"
            | "binding"
            | "bindingid"
            | "action"
            | "actionid"
            | "actiondigest"
            | "implementationdigest"
            | "target"
            | "targets"
            | "targetid"
            | "targetids"
            | "targetprofileid"
            | "scope"
            | "command"
            | "commands"
            | "executor"
            | "selector"
            | "runtime"
            | "config"
            | "configuration"
            | "environment"
            | "world"
            | "worldid"
            | "dimension"
            | "dimensionid"
            | "origin"
            | "position"
            | "positions"
            | "rotation"
            | "rotationdegrees"
            | "anchor"
            | "selection"
            | "executorhandle"
            | "deadline"
            | "deadlineat"
            | "timeout"
            | "timeoutms"
            | "project"
            | "projectid"
            | "budget"
            | "budgets"
            | "timebudget"
            | "timebudgetms"
            | "cost"
            | "costbudget"
            | "resourceid"
            | "resourceids"
            | "resourceref"
            | "resourcerefs"
            | "resourcesread"
            | "resourceswritten"
            | "objectid"
            | "instanceid"
            | "prefabid"
            | "moduleid"
            | "clipid"
            | "assetid"
            | "physicsid"
            | "preparedchange"
    )
}
fn check_slot(tokens: &[String]) -> StorageResult<()> {
    if tokens.iter().any(|token| protected(token)) {
        return Err(invalid(
            "Result binding cannot select authority, route, target or runtime settings",
        ));
    }
    Ok(())
}
fn check_data_subtree(value: &Value) -> StorageResult<()> {
    let mut stack = vec![value];
    let mut count = 0usize;
    while let Some(value) = stack.pop() {
        count += 1;
        if count > 100_000 {
            return Err(invalid("Resolved data exceeds its node budget"));
        }
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    if protected(key) {
                        return Err(invalid(
                            "Resolved data contains an authority or target selector",
                        ));
                    }
                    stack.push(value);
                }
            }
            Value::Array(values) => stack.extend(values),
            _ => (),
        }
    }
    Ok(())
}
fn array_index(token: &str) -> StorageResult<usize> {
    if token.is_empty()
        || (token.len() > 1 && token.starts_with('0'))
        || !token.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid("Result pointer has a noncanonical array index"));
    }
    token
        .parse()
        .map_err(|_| invalid("Result pointer index exceeds its range"))
}
fn selected<'a>(root: &'a Value, tokens: &[String]) -> StorageResult<&'a Value> {
    let mut node = root;
    for token in tokens {
        node = match node {
            Value::Object(values) => values.get(token),
            Value::Array(values) => values.get(array_index(token)?),
            _ => None,
        }
        .ok_or_else(|| invalid("Result pointer does not identify an existing value"))?;
    }
    Ok(node)
}
fn replace(root: &mut Value, tokens: &[String], value: Value) -> StorageResult<()> {
    let (last, parents) = tokens
        .split_last()
        .ok_or_else(|| invalid("Root result replacement denied"))?;
    let mut node = root;
    for token in parents {
        node = match node {
            Value::Object(values) => values.get_mut(token),
            Value::Array(values) => values.get_mut(array_index(token)?),
            _ => None,
        }
        .ok_or_else(|| invalid("Result argument parent does not exist"))?;
    }
    let slot = match node {
        Value::Object(values) => values.get_mut(last),
        Value::Array(values) => values.get_mut(array_index(last)?),
        _ => None,
    }
    .ok_or_else(|| invalid("Result argument slot does not exist"))?;
    *slot = value;
    Ok(())
}

impl RegisteredResultCodec {
    pub fn metadata(&self) -> StorageResult<Value> {
        serde_json::to_value(self).map_err(contract)
    }
    pub fn metadata_digest(&self) -> StorageResult<Sha256Digest> {
        digest(&self.metadata()?)
    }
}

impl DurableStore {
    pub fn register_result_codec(
        &mut self,
        codec: &RegisteredResultCodec,
    ) -> StorageResult<BlobRef> {
        if codec.allowed_slots.is_empty() || codec.allowed_slots.len() > MAX_BINDINGS {
            return Err(invalid("Result codec requires finite reviewed slots"));
        }
        self.validator
            .compile_action_schema(&codec.input_schema)
            .map_err(contract)?;
        self.validator
            .compile_action_schema(&codec.output_schema)
            .map_err(contract)?;
        let mut slots = BTreeSet::new();
        for slot in &codec.allowed_slots {
            let tokens = result_pointer_tokens(&slot.argument_pointer)?;
            check_slot(&tokens)?;
            if slots
                .iter()
                .any(|(action, previous): &(Sha256Digest, Vec<String>)| {
                    action == &slot.action_digest
                        && (tokens.starts_with(previous) || previous.starts_with(&tokens))
                })
            {
                return Err(invalid("Result codec allowed slots overlap"));
            }
            if !slots.insert((slot.action_digest.clone(), tokens)) {
                return Err(invalid("Result codec allowed slot is duplicated"));
            }
        }
        let metadata = codec.metadata()?;
        let metadata_digest = digest(&metadata)?;
        let bytes = encode_json(&metadata).map_err(contract)?;
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(invalid("Result codec metadata exceeds its budget"));
        }
        let blob = self.cas.put(&bytes)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(REGISTRY_SCHEMA)?;
        let old: Option<(String,String,i64)> = transaction.query_row(
            "SELECT metadata_digest,blob_digest,byte_length FROM result_codecs WHERE codec_id=?1",
            [codec.codec_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional()?;
        if let Some((hash, raw, length)) = old {
            if hash != metadata_digest.as_str()
                || raw != blob.digest.as_str()
                || u64::try_from(length).ok() != Some(blob.byte_length)
            {
                return Err(StorageError::Conflict("Immutable registered result codec"));
            }
            registry_pin(&transaction, "result_codec", codec.codec_id.as_str(), &blob)?;
        } else {
            let count: i64 =
                transaction.query_row("SELECT count(*) FROM result_codecs", [], |r| r.get(0))?;
            if count >= MAX_REGISTRY_ROWS {
                return Err(invalid("Result codec registry is full"));
            }
            pin_blob(&transaction, "result_codec", codec.codec_id.as_str(), &blob)?;
            transaction.execute("INSERT INTO result_codecs(codec_id,metadata_digest,blob_digest,byte_length) VALUES(?1,?2,?3,?4)",
                params![codec.codec_id.as_str(),metadata_digest.as_str(),blob.digest.as_str(),blob.byte_length as i64])?;
        }
        transaction.commit()?;
        Ok(blob)
    }

    pub fn result_codec(
        &self,
        id: &ObjectId,
        expected: &Sha256Digest,
    ) -> StorageResult<(RegisteredResultCodec, BlobRef)> {
        load_codec(&self.connection, &self.cas, &self.validator, id, expected)
    }

    /// Trusted server registry provenance includes binding identity; the public
    /// descriptor alone does not authorize a caller-selected route.
    pub fn register_result_action(
        &mut self,
        binding: &BindingId,
        descriptor: &Value,
    ) -> StorageResult<BlobRef> {
        self.validator
            .validate("ActionDescriptor", descriptor)
            .map_err(contract)?;
        self.validator
            .compile_action_schema(&descriptor["inputSchema"])
            .map_err(contract)?;
        self.validator
            .compile_action_schema(&descriptor["outputSchema"])
            .map_err(contract)?;
        let action_digest = digest(descriptor)?;
        let bytes = encode_json(descriptor).map_err(contract)?;
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(invalid("Registered result action exceeds its budget"));
        }
        let blob = self.cas.put(&bytes)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(REGISTRY_SCHEMA)?;
        let old:Option<(String,i64)>=transaction.query_row(
            "SELECT blob_digest,byte_length FROM result_actions WHERE binding_id=?1 AND action_digest=?2",
            params![binding.as_str(),action_digest.as_str()], |row|Ok((row.get(0)?,row.get(1)?)),
        ).optional()?;
        if let Some(old) = old {
            if row_blob(old)? != blob {
                return Err(StorageError::Conflict("Immutable registered result action"));
            }
            registry_pin(&transaction, "result_action", action_digest.as_str(), &blob)?;
        } else {
            let count: i64 =
                transaction.query_row("SELECT count(*) FROM result_actions", [], |r| r.get(0))?;
            if count >= MAX_REGISTRY_ROWS {
                return Err(invalid("Result action registry is full"));
            }
            pin_blob(&transaction, "result_action", action_digest.as_str(), &blob)?;
            transaction.execute("INSERT INTO result_actions(binding_id,action_digest,action_id,contract_version,implementation_digest,blob_digest,byte_length) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![binding.as_str(),action_digest.as_str(),text(descriptor,"actionId")?,text(descriptor,"contractVersion")?,text(descriptor,"implementationDigest")?,blob.digest.as_str(),blob.byte_length as i64])?;
        }
        transaction.commit()?;
        Ok(blob)
    }

    pub fn dispatch_resolved_intent(
        &mut self,
        operation: &OperationId,
        step: &StepId,
        invocation: &Value,
        witness: &BlobRef,
    ) -> StorageResult<super::StepRecord> {
        self.dispatch_intent_internal(operation, step, invocation, Some(witness), None)
    }

    /// Retrieve retained original resolution evidence for an existing intent.
    /// This read performs no provider dispatch or new codec authorization.
    pub fn stored_resolution_witness(
        &self,
        operation: &OperationId,
        step: &StepId,
    ) -> StorageResult<ResultResolutionWitness> {
        let record = self.operation(operation)?;
        let stored = record
            .steps
            .iter()
            .find(|s| &s.step_id == step)
            .ok_or(StorageError::NotFound("Resolution step"))?;
        let invocation = stored
            .invocation_id
            .as_ref()
            .ok_or(StorageError::NotFound("Resolution invocation"))?;
        let mut statement=self.connection.prepare(
            "SELECT r.digest,b.byte_length FROM invocations i JOIN blob_refs r ON r.owner_id=i.invocation_id AND r.owner_kind='result_resolution_witness' JOIN blobs b ON b.digest=r.digest WHERE i.operation_id=?1 AND i.step_id=?2 AND i.invocation_id=?3 ORDER BY r.digest LIMIT 2",
        )?;
        let rows = statement
            .query_map(
                params![operation.as_str(), step.as_str(), invocation.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let [row] = rows.as_slice() else {
            return if rows.is_empty() {
                Err(StorageError::NotFound("Stored resolution witness"))
            } else {
                Err(StorageError::Corrupt(
                    "Resolution invocation has multiple witness pins".into(),
                ))
            };
        };
        let blob = row_blob(row.clone())?;
        registry_pin(
            &self.connection,
            "result_resolution",
            invocation.as_str(),
            &blob,
        )?;
        let value = read_json(&self.cas, &blob, MAX_WITNESS_BYTES)?;
        let witness: ResultResolutionWitness = serde_json::from_value(value).map_err(contract)?;
        if witness.kind != "result_resolution_witness"
            || witness.version != 1
            || &witness.operation_id != operation
            || &witness.step_id != step
            || witness.plan_hash != record.plan_hash
            || witness.bindings.is_empty()
            || witness.bindings.len() > MAX_BINDINGS
        {
            return Err(StorageError::Corrupt(
                "Stored resolution witness identity differs".into(),
            ));
        }
        Ok(witness)
    }
}

fn load_codec(
    connection: &Connection,
    cas: &Cas,
    validator: &ContractValidator,
    id: &ObjectId,
    expected: &Sha256Digest,
) -> StorageResult<(RegisteredResultCodec, BlobRef)> {
    if !table_exists(connection, "result_codecs")? {
        return Err(StorageError::NotFound("Registered result codec"));
    }
    let row: Option<(String, String, i64)> = connection
        .query_row(
            "SELECT metadata_digest,blob_digest,byte_length FROM result_codecs WHERE codec_id=?1",
            [id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (hash, raw, length) = row.ok_or(StorageError::NotFound("Registered result codec"))?;
    if hash != expected.as_str() {
        return Err(StorageError::Conflict("Pinned result codec digest"));
    }
    let blob = row_blob((raw, length))?;
    registry_pin(connection, "result_codec", id.as_str(), &blob)?;
    let value = read_json(cas, &blob, MAX_REGISTRY_BYTES as u64)?;
    let codec: RegisteredResultCodec = serde_json::from_value(value.clone()).map_err(contract)?;
    if &codec.codec_id != id || digest(&value)? != *expected {
        return Err(StorageError::Corrupt(
            "Registered codec metadata differs".into(),
        ));
    }
    validator
        .compile_action_schema(&codec.input_schema)
        .map_err(contract)?;
    validator
        .compile_action_schema(&codec.output_schema)
        .map_err(contract)?;
    Ok((codec, blob))
}
fn registered_action(
    connection: &Connection,
    cas: &Cas,
    validator: &ContractValidator,
    invocation: &Value,
) -> StorageResult<(Value, BlobRef)> {
    if !table_exists(connection, "result_actions")? {
        return Err(StorageError::NotFound("Registered result action"));
    }
    let row:Option<(String,i64)>=connection.query_row(
        "SELECT blob_digest,byte_length FROM result_actions WHERE binding_id=?1 AND action_digest=?2 AND action_id=?3 AND contract_version=?4 AND implementation_digest=?5",
        params![text(invocation,"bindingId")?,text(invocation,"actionDigest")?,text(invocation,"actionId")?,text(invocation,"actionContractVersion")?,text(invocation,"implementationDigest")?],
        |r|Ok((r.get(0)?,r.get(1)?)),
    ).optional()?;
    let blob = row_blob(row.ok_or(StorageError::NotFound("Registered pinned result action"))?)?;
    registry_pin(
        connection,
        "result_action",
        text(invocation, "actionDigest")?,
        &blob,
    )?;
    let value = read_json(cas, &blob, MAX_REGISTRY_BYTES as u64)?;
    validator
        .validate("ActionDescriptor", &value)
        .map_err(contract)?;
    if digest(&value)?.as_str() != text(invocation, "actionDigest")?
        || value["actionId"] != invocation["actionId"]
        || value["contractVersion"] != invocation["actionContractVersion"]
        || value["implementationDigest"] != invocation["implementationDigest"]
    {
        return Err(StorageError::Corrupt(
            "Registered action route differs".into(),
        ));
    }
    Ok((value, blob))
}
fn read_json(cas: &Cas, blob: &BlobRef, max: u64) -> StorageResult<Value> {
    let bytes = cas.read_verified_document::<StorageError, _>(blob, max, || Ok(()))?;
    parse_json(&bytes).map_err(contract)
}

fn ancestral_steps(plan: &Value, consumer: &StepId) -> StorageResult<BTreeSet<StepId>> {
    let steps = plan["steps"]
        .as_array()
        .ok_or_else(|| invalid("Frozen step list missing"))?;
    if steps.len() > 4096 {
        return Err(invalid("Frozen DAG exceeds its budget"));
    }
    let mut by_id = BTreeMap::new();
    for step in steps {
        let id: StepId = serde_json::from_value(step["stepId"].clone()).map_err(contract)?;
        if by_id.insert(id, step).is_some() {
            return Err(invalid("Frozen DAG has duplicate steps"));
        }
    }
    let start = by_id
        .get(consumer)
        .ok_or(StorageError::NotFound("Frozen consumer step"))?;
    let mut pending: Vec<StepId> =
        serde_json::from_value(start["dependsOn"].clone()).map_err(contract)?;
    let mut ancestors = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if &id == consumer {
            return Err(invalid("Result source DAG is cyclic"));
        }
        if ancestors.insert(id.clone()) {
            let step = by_id
                .get(&id)
                .ok_or(StorageError::NotFound("Frozen ancestor step"))?;
            let parents: Vec<StepId> =
                serde_json::from_value(step["dependsOn"].clone()).map_err(contract)?;
            if parents.len() > 4096 {
                return Err(invalid("Frozen dependency budget exceeded"));
            }
            pending.extend(parents);
        }
    }
    // Detect cycles among ancestors as well as a cycle through the consumer.
    // A visited set alone would silently accept A -> B -> A.
    let mut remaining = ancestors.clone();
    let mut completed = BTreeSet::new();
    while !remaining.is_empty() {
        let ready: Vec<_> = remaining
            .iter()
            .filter(|id| {
                by_id
                    .get(*id)
                    .and_then(|step| step["dependsOn"].as_array())
                    .is_some_and(|parents| {
                        parents.iter().all(|parent| {
                            parent.as_str().is_some_and(|id| {
                                completed.iter().any(|done: &StepId| done.as_str() == id)
                            })
                        })
                    })
            })
            .cloned()
            .collect();
        if ready.is_empty() {
            return Err(invalid("Result source DAG is cyclic"));
        }
        for id in ready {
            remaining.remove(&id);
            completed.insert(id);
        }
    }
    Ok(ancestors)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryAssociation {
    summary: BlobRef,
    source_blobs: Vec<BlobRef>,
}
fn retained(
    connection: &Connection,
    operation: &OperationId,
    kind: &str,
    blob: &BlobRef,
) -> StorageResult<()> {
    let length = i64::try_from(blob.byte_length)
        .map_err(|_| invalid("Witness source length exceeds SQLite range"))?;
    let exists:i64=connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM blob_refs r JOIN blobs b ON b.digest=r.digest WHERE r.owner_kind=?1 AND r.owner_id=?2 AND r.digest=?3 AND b.byte_length=?4)",
        params![kind,operation.as_str(),blob.digest.as_str(),length],|r|r.get(0),
    )?;
    if exists != 1 {
        return Err(StorageError::Conflict(
            "Result source is not retained by the original operation",
        ));
    }
    Ok(())
}
fn summary_associated(
    connection: &Connection,
    history: &BTreeMap<Sha256Digest, SummaryAssociation>,
    operation: &OperationId,
    summary: &BlobRef,
    source: &BlobRef,
) -> StorageResult<()> {
    retained(connection, operation, "application_summary", summary)?;
    retained(connection, operation, "application_evidence", source)?;
    let association = history.get(&summary.digest).ok_or(StorageError::NotFound(
        "Original result summary association",
    ))?;
    if &association.summary != summary || !association.source_blobs.contains(source) {
        return Err(StorageError::Conflict(
            "Result summary has conflicting source association",
        ));
    }
    Ok(())
}

/// Called inside the existing intent transaction. Returned refs are pinned by
/// that same transaction only after every original plan/source check succeeds.
pub(crate) struct ResolutionInput<'a> {
    pub record: &'a OperationRecord,
    pub plan: &'a Value,
    pub step: &'a Value,
    pub invocation: &'a Value,
    pub witness_blob: &'a BlobRef,
}
pub(crate) fn verify_resolution(
    transaction: &Transaction<'_>,
    cas: &Cas,
    validator: &ContractValidator,
    input: ResolutionInput<'_>,
) -> StorageResult<Vec<BlobRef>> {
    let ResolutionInput {
        record,
        plan,
        step,
        invocation,
        witness_blob,
    } = input;
    let witness_value = read_json(cas, witness_blob, MAX_WITNESS_BYTES)?;
    let witness: ResultResolutionWitness =
        serde_json::from_value(witness_value).map_err(contract)?;
    let expected_bindings: Vec<ResultStepBinding> =
        serde_json::from_value(step["resultBindings"].clone()).map_err(contract)?;
    if expected_bindings.is_empty()
        || expected_bindings.len() > MAX_BINDINGS
        || witness.bindings.len() != expected_bindings.len()
    {
        return Err(invalid(
            "Resolved dispatch requires the exact finite frozen bindings",
        ));
    }
    if witness.kind != "result_resolution_witness"
        || witness.version != 1
        || witness.operation_id != record.operation_id
        || witness.plan_hash != record.plan_hash
        || witness.step_id.as_str() != text(step, "stepId")?
        || witness.template_arguments_digest != digest(&step["arguments"])?
        || witness.arguments_digest != digest(&invocation["arguments"])?
        || witness.arguments_digest.as_str() != text(invocation, "argumentsDigest")?
        || witness.context_digest.as_str() != text(invocation, "contextDigest")?
        || witness.action_digest.as_str() != text(invocation, "actionDigest")?
        || witness.implementation_digest.as_str() != text(invocation, "implementationDigest")?
        || serde_json::to_value(&witness.resolved_footprint).map_err(contract)?
            != json!({"resourcesRead":step["resourcesRead"],"resourcesWritten":step["resourcesWritten"]})
    {
        return Err(StorageError::Conflict(
            "Result witness frozen invocation pins",
        ));
    }
    if read_json(cas, &witness.arguments_blob, 8 * 1024 * 1024)? != invocation["arguments"] {
        return Err(StorageError::Conflict(
            "Result witness resolved argument bytes",
        ));
    }
    let (consumer_descriptor, consumer_action_blob) =
        registered_action(transaction, cas, validator, invocation)?;
    let ancestors = ancestral_steps(plan, &witness.step_id)?;
    let (history, mut failed_steps, history_bytes) = summary_history(transaction, cas, record)?;
    let mut reconstructed = step["arguments"].clone();
    let mut used: Vec<Vec<String>> = Vec::new();
    let mut refs = vec![
        witness_blob.clone(),
        witness.arguments_blob.clone(),
        consumer_action_blob,
    ];
    let mut read_bytes = witness_blob
        .byte_length
        .checked_add(witness.arguments_blob.byte_length)
        .and_then(|v| v.checked_add(refs[2].byte_length))
        .and_then(|v| v.checked_add(history_bytes))
        .ok_or_else(|| invalid("Result evidence byte overflow"))?;
    extend_original_failure_history(
        transaction,
        cas,
        validator,
        record,
        &history,
        &mut failed_steps,
        &mut read_bytes,
    )?;
    for (expected, binding) in expected_bindings.iter().zip(&witness.bindings) {
        if expected != &binding.binding || !ancestors.contains(&expected.source_step_id) {
            return Err(StorageError::Conflict("Result witness source binding/DAG"));
        }
        let tokens = result_pointer_tokens(&expected.argument_pointer)?;
        check_slot(&tokens)?;
        if used
            .iter()
            .any(|old| tokens.starts_with(old) || old.starts_with(&tokens))
        {
            return Err(invalid("Result argument slots overlap"));
        }
        selected(&step["arguments"], &tokens)?;
        used.push(tokens.clone());
        let source_step = record
            .steps
            .iter()
            .find(|s| s.step_id == expected.source_step_id)
            .ok_or(StorageError::NotFound("Result source durable step"))?;
        if !step_verified(source_step)
            || failed_steps.contains(&expected.source_step_id)
            || source_step.invocation_id.as_ref() != Some(&binding.source_invocation_id)
            || source_step.invocation_digest.as_ref() != Some(&binding.source_invocation_digest)
        {
            return Err(StorageError::InvalidTransition(
                "Result source is not the original verified finished invocation".into(),
            ));
        }
        let source_row:Option<(String,String,String,i64)>=transaction.query_row(
            "SELECT i.invocation_id,i.invocation_hash,i.blob_digest,b.byte_length FROM invocations i JOIN blobs b ON b.digest=i.blob_digest WHERE i.operation_id=?1 AND i.step_id=?2",
            params![record.operation_id.as_str(),expected.source_step_id.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional()?;
        let (source_id, source_hash, raw, length) =
            source_row.ok_or(StorageError::NotFound("Original source invocation"))?;
        if source_id != binding.source_invocation_id.as_str()
            || source_hash != binding.source_invocation_digest.as_str()
            || raw != source_hash
        {
            return Err(StorageError::Conflict("Original result invocation digest"));
        }
        let source_blob = row_blob((raw, length))?;
        let source_invocation = read_json(cas, &source_blob, 8 * 1024 * 1024)?;
        validator
            .validate("Invocation", &source_invocation)
            .map_err(contract)?;
        let frozen_source = plan["steps"]
            .as_array()
            .and_then(|steps| {
                steps
                    .iter()
                    .find(|s| s["stepId"] == expected.source_step_id.as_str())
            })
            .ok_or(StorageError::NotFound("Original frozen source step"))?;
        for field in [
            "bindingId",
            "actionId",
            "actionContractVersion",
            "actionDigest",
            "implementationDigest",
        ] {
            if source_invocation[field] != frozen_source[field] {
                return Err(StorageError::Conflict("Original source frozen route"));
            }
        }
        if source_invocation["operationId"] != record.operation_id.as_str()
            || source_invocation["stepId"] != expected.source_step_id.as_str()
            || source_invocation["invocationId"] != source_id
            || source_invocation["context"]["contextId"] != frozen_source["contextId"]
        {
            return Err(StorageError::Conflict(
                "Original source invocation identity",
            ));
        }
        let source_context = mmmm_contracts::verify_projected_digest(
            "ExecutionContext",
            &source_invocation["context"],
        )
        .map_err(contract)?;
        if source_invocation["contextDigest"] != source_context.as_str()
            || source_invocation["argumentsDigest"]
                != digest(&source_invocation["arguments"])?.as_str()
            || source_invocation["context"]["projectId"] != record.project_id.as_str()
            || source_invocation["context"]["principalRef"] != record.principal.as_str()
            || source_invocation["context"]["policyRevision"] != plan["policyRevision"]
            || !plan["contextPins"].as_array().is_some_and(|pins| {
                pins.iter().any(|pin| {
                    pin["contextId"] == frozen_source["contextId"]
                        && pin["contextDigest"] == source_context.as_str()
                })
            })
        {
            return Err(StorageError::Conflict(
                "Original source context/arguments pins",
            ));
        }
        if frozen_source["resultBindings"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && source_invocation["arguments"] != frozen_source["arguments"]
        {
            return Err(StorageError::Conflict("Original source frozen arguments"));
        }
        let (source_action, action_blob) =
            registered_action(transaction, cas, validator, &source_invocation)?;
        if action_blob != binding.source_action
            || digest(&source_action["outputSchema"])? != expected.expected_schema_digest
        {
            return Err(StorageError::Conflict(
                "Original source output schema registration",
            ));
        }
        summary_associated(
            transaction,
            &history,
            &record.operation_id,
            &binding.source_result_summary,
            &binding.source_result,
        )?;
        let summary = read_json(cas, &binding.source_result_summary, MAX_WITNESS_BYTES)?;
        let summary_result: BlobRef =
            serde_json::from_value(summary["resultBlob"].clone()).map_err(contract)?;
        let summary_sources: Vec<BlobRef> =
            serde_json::from_value(summary["sourceRefs"].clone()).map_err(contract)?;
        if summary["kind"] != "provider_result"
            || summary["stepId"] != expected.source_step_id.as_str()
            || summary["invocationId"] != source_id
            || summary["actionDigest"] != source_invocation["actionDigest"]
            || summary["outputSchemaDigest"] != expected.expected_schema_digest.as_str()
            || summary["outputValidated"] != true
            || summary["value"]["status"] != "complete"
            || summary_result != binding.source_result
            || !summary_sources.contains(&binding.source_result)
        {
            return Err(StorageError::Conflict("Original validated result marker"));
        }
        read_bytes = read_bytes
            .checked_add(binding.source_result.byte_length)
            .and_then(|v| v.checked_add(binding.source_result_summary.byte_length))
            .and_then(|v| v.checked_add(source_blob.byte_length))
            .and_then(|v| v.checked_add(action_blob.byte_length))
            .and_then(|v| v.checked_add(binding.codec.byte_length))
            .ok_or_else(|| invalid("Result source byte budget overflow"))?;
        if read_bytes > MAX_TOTAL_SOURCE_BYTES {
            return Err(invalid("Result resolution evidence budget exceeded"));
        }
        let result = read_json(cas, &binding.source_result, 8 * 1024 * 1024)?;
        validator
            .validate("ProviderResult", &result)
            .map_err(contract)?;
        if result["status"] != "complete" {
            return Err(StorageError::InvalidTransition(
                "Incomplete or failed provider result cannot feed another step".into(),
            ));
        }
        validator
            .compile_action_schema(&source_action["outputSchema"])
            .map_err(contract)?
            .validate(&result["data"])
            .map_err(contract)?;
        let output_tokens = result_pointer_tokens(&expected.output_pointer)?;
        let value = selected(&result["data"], &output_tokens)?.clone();
        check_data_subtree(&value)?;
        if digest(&value)? != binding.selected_value_digest
            || binding.selected_value_digest != binding.resolved_value_digest
        {
            return Err(StorageError::Conflict(
                "Closed identity codec resolved value digest",
            ));
        }
        let (codec, codec_blob) = load_codec(
            transaction,
            cas,
            validator,
            &expected.codec_id,
            &expected.codec_digest,
        )?;
        if codec_blob != binding.codec
            || !codec.allowed_slots.iter().any(|slot| {
                slot.action_digest == witness.action_digest
                    && slot.argument_pointer == expected.argument_pointer
            })
        {
            return Err(StorageError::Conflict(
                "Result codec does not allow the frozen consumer slot",
            ));
        }
        validator
            .compile_action_schema(&codec.input_schema)
            .map_err(contract)?
            .validate(&value)
            .map_err(contract)?;
        validator
            .compile_action_schema(&codec.output_schema)
            .map_err(contract)?
            .validate(&value)
            .map_err(contract)?;
        match codec.implementation {
            ResultCodecImplementation::JsonIdentityV1 => {
                replace(&mut reconstructed, &tokens, value)?
            }
        }
        refs.extend([
            source_blob,
            action_blob,
            codec_blob,
            binding.source_result.clone(),
            binding.source_result_summary.clone(),
        ]);
    }
    if reconstructed != invocation["arguments"] {
        return Err(StorageError::Conflict(
            "Resolved invocation changed arguments outside frozen data slots",
        ));
    }
    validator
        .compile_action_schema(&consumer_descriptor["inputSchema"])
        .map_err(contract)?
        .validate(&reconstructed)
        .map_err(contract)?;
    refs.sort_by(|left, right| left.digest.cmp(&right.digest));
    refs.dedup();
    Ok(refs)
}

fn summary_history(
    connection: &Connection,
    cas: &Cas,
    record: &OperationRecord,
) -> StorageResult<(
    BTreeMap<Sha256Digest, SummaryAssociation>,
    BTreeSet<StepId>,
    u64,
)> {
    let operation = &record.operation_id;
    let mut statement=connection.prepare("SELECT record_json FROM events WHERE operation_id=?1 AND kind='application_summary' ORDER BY sequence LIMIT 4097")?;
    let mut rows = statement.query([operation.as_str()])?;
    let mut count = 0;
    let mut history = BTreeMap::new();
    let mut failed = BTreeSet::new();
    let mut total = 0u64;
    while let Some(row) = rows.next()? {
        count += 1;
        if count > 4096 {
            return Err(invalid("Provider summary history exceeds its budget"));
        }
        let text: String = row.get(0)?;
        if text.len() > 32768 {
            return Err(invalid("Provider summary association exceeds its budget"));
        }
        let association: SummaryAssociation = decode(&text)?;
        if association.source_blobs.len() > 64 {
            return Err(invalid("Provider summary source budget exceeded"));
        }
        retained(
            connection,
            operation,
            "application_summary",
            &association.summary,
        )?;
        for source in &association.source_blobs {
            retained(connection, operation, "application_evidence", source)?;
        }
        total = total
            .checked_add(association.summary.byte_length)
            .ok_or_else(|| invalid("Provider summary byte overflow"))?;
        if total > MAX_TOTAL_SOURCE_BYTES {
            return Err(invalid("Provider summary history byte budget exceeded"));
        }
        let marker = read_json(cas, &association.summary, MAX_WITNESS_BYTES)?;
        if marker["kind"] == "provider_result" && marker["value"]["status"] == "failed" {
            failed.insert(original_marker_step(record, &marker, None)?);
        }
        if history
            .insert(association.summary.digest.clone(), association)
            .is_some()
        {
            return Err(StorageError::Corrupt(
                "Provider summary has duplicate durable associations".into(),
            ));
        }
    }
    Ok((history, failed, total))
}

/// Labels only identify a candidate. Actual original intent and, where present,
/// observation ownership must establish the marker's source before it is used.
fn original_marker_step(
    record: &OperationRecord,
    marker: &Value,
    observation_owners: Option<&BTreeSet<StepId>>,
) -> StorageResult<StepId> {
    let step: StepId = serde_json::from_value(marker["stepId"].clone()).map_err(contract)?;
    let invocation: InvocationId =
        serde_json::from_value(marker["invocationId"].clone()).map_err(contract)?;
    let source = record
        .steps
        .iter()
        .find(|source| source.step_id == step)
        .ok_or(StorageError::NotFound("Original provider marker step"))?;
    if source.dispatch == super::DispatchEvidence::NotSent
        || source.invocation_id.as_ref() != Some(&invocation)
        || source.invocation_digest.is_none()
        || observation_owners
            .is_some_and(|owners| owners.is_empty() || owners.iter().any(|owner| owner != &step))
    {
        return Err(StorageError::Conflict(
            "Original provider marker invocation/observation ownership",
        ));
    }
    Ok(step)
}

/// Older journals may retain a failed original envelope only in observation
/// refs/evidence, or as an unvalidated raw marker before the typed marker was
/// committed. A later complete summary cannot erase that original failure.
fn extend_original_failure_history(
    connection: &Connection,
    cas: &Cas,
    validator: &ContractValidator,
    record: &OperationRecord,
    history: &BTreeMap<Sha256Digest, SummaryAssociation>,
    failed: &mut BTreeSet<StepId>,
    bytes: &mut u64,
) -> StorageResult<()> {
    let mut refs = BTreeMap::<Sha256Digest, BlobRef>::new();
    let mut source_for_observation = BTreeMap::<Sha256Digest, BTreeSet<StepId>>::new();
    let mut statement=connection.prepare(
        "SELECT r.digest,b.byte_length FROM blob_refs r JOIN blobs b ON b.digest=r.digest WHERE r.owner_kind='application_evidence' AND r.owner_id=?1 ORDER BY r.digest LIMIT 4097",
    )?;
    let rows = statement
        .query_map([record.operation_id.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > 4096 {
        return Err(invalid(
            "Original result failure history entry budget exceeded",
        ));
    }
    for row in rows {
        let blob = row_blob(row)?;
        refs.insert(blob.digest.clone(), blob);
    }
    for step in &record.steps {
        for blob in &step.observation_refs {
            retained(connection, &record.operation_id, "operation", blob)?;
            source_for_observation
                .entry(blob.digest.clone())
                .or_default()
                .insert(step.step_id.clone());
            if let Some(old) = refs.insert(blob.digest.clone(), blob.clone())
                && old != *blob
            {
                return Err(StorageError::Corrupt(
                    "Original failure evidence lengths conflict".into(),
                ));
            }
            if refs.len() > 4096 {
                return Err(invalid(
                    "Original result observation history budget exceeded",
                ));
            }
        }
    }
    // Link raw source blobs through actual committed association metadata, not
    // marker sourceRefs or a caller-provided digest declaration alone.
    let mut raw_sources = BTreeMap::<Sha256Digest, BTreeSet<StepId>>::new();
    for association in history.values() {
        let marker = read_json(cas, &association.summary, MAX_WITNESS_BYTES)?;
        if marker["kind"] == "unvalidated_provider_result" {
            let step = original_marker_step(
                record,
                &marker,
                source_for_observation.get(&association.summary.digest),
            )?;
            let blob: BlobRef =
                serde_json::from_value(marker["resultBlob"].clone()).map_err(contract)?;
            if !association.source_blobs.contains(&blob) {
                return Err(StorageError::Conflict(
                    "Original raw result source association",
                ));
            }
            raw_sources
                .entry(blob.digest.clone())
                .or_default()
                .insert(step);
        } else if marker["kind"] == "provider_result" {
            let step = original_marker_step(
                record,
                &marker,
                source_for_observation.get(&association.summary.digest),
            )?;
            if let Some(blob) = marker.get("resultBlob") {
                let blob: BlobRef = serde_json::from_value(blob.clone()).map_err(contract)?;
                if !association.source_blobs.contains(&blob) {
                    return Err(StorageError::Conflict(
                        "Original typed result source association",
                    ));
                }
                raw_sources
                    .entry(blob.digest.clone())
                    .or_default()
                    .insert(step);
            }
        }
    }
    for blob in refs.values() {
        *bytes = bytes
            .checked_add(blob.byte_length)
            .ok_or_else(|| invalid("Original result failure history byte overflow"))?;
        if *bytes > MAX_TOTAL_SOURCE_BYTES {
            return Err(invalid(
                "Original result failure history byte budget exceeded",
            ));
        }
        let content =
            cas.read_verified_document::<StorageError, _>(blob, 8 * 1024 * 1024, || Ok(()))?;
        // Direct snapshot sources can be arbitrary bytes. They are not parsed
        // as provider JSON, but their actual CAS digest/size was still checked.
        let Ok(value) = parse_json(&content) else {
            continue;
        };
        let mut candidate = &value;
        let mut indicated_step = None;
        if value["kind"] == "provider_result" || value["kind"] == "unvalidated_provider_result" {
            let observation_owners = source_for_observation.get(&blob.digest);
            if observation_owners.is_none() && !history.contains_key(&blob.digest) {
                return Err(StorageError::Conflict(
                    "Original provider marker has no committed source association",
                ));
            }
            indicated_step = Some(original_marker_step(record, &value, observation_owners)?);
            candidate = &value["value"];
            if candidate.is_null() {
                if let Some(reference) = value.get("resultBlob") {
                    let reference: BlobRef =
                        serde_json::from_value(reference.clone()).map_err(contract)?;
                    // Legacy wrapper references still need an actual original
                    // operation pin; do not follow an arbitrary supplied ref.
                    let allowed = refs
                        .get(&reference.digest)
                        .is_some_and(|pinned| pinned == &reference);
                    if !allowed {
                        return Err(StorageError::Conflict(
                            "Legacy original result body retention",
                        ));
                    }
                    let step = indicated_step
                        .clone()
                        .ok_or_else(|| invalid("Legacy result step missing"))?;
                    raw_sources
                        .entry(reference.digest)
                        .or_default()
                        .insert(step);
                }
                continue;
            }
        }
        if validator.validate("ProviderResult", candidate).is_ok()
            && candidate["status"] == "failed"
        {
            let mut attributed = false;
            if let Some(step) = indicated_step {
                failed.insert(step);
                attributed = true;
            }
            if let Some(steps) = raw_sources.get(&blob.digest) {
                failed.extend(steps.iter().cloned());
                attributed = true;
            }
            if let Some(steps) = source_for_observation.get(&blob.digest) {
                failed.extend(steps.iter().cloned());
                attributed = true;
            }
            if !attributed {
                return Err(StorageError::InvalidTransition(
                    "An original failed provider result lacks complete source history".into(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "result_binding_tests.rs"]
mod tests;

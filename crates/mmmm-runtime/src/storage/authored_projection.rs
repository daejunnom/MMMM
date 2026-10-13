//! The local document phase of one frozen composite native invocation.
//!
//! This trusted composition API never sends a world write, finishes a step or
//! interprets a JSON success claim as world verification. Files are prestaged;
//! one existing SQLite journal transaction promotes all metadata and its receipt.
//! A restart may replay an exact committed receipt, but cannot create a commit
//! for an interrupted invocation without the application reconciliation policy.

use super::{
    BlobRef, DispatchEvidence, DurableStore, OperationRecord, OperationState, StorageError,
    StorageResult, VerificationRequirement,
    journal::{decode, encode, pin_blob, register_blob},
    owned_documents::{
        MAX_OWNED_DOCUMENT_BYTES, MAX_OWNED_DOCUMENTS_PER_PROJECT, OwnedDocumentKind,
        OwnedDocumentPin,
    },
};
use mmmm_contracts::{
    ContextId, InvocationId, ObjectId, OperationId, PrincipalId, ProjectId, ResourceId,
    Sha256Digest, StepId, canonical_digest, encode_json, parse_json, verify_projected_digest,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const MAX_ITEMS: usize = 4096;
const MAX_RESOURCE_METADATA_BYTES: usize = 16_384;
const MAX_RESOURCE_VERSIONS: i64 = 65_536;
const MAX_PROJECTION_BYTES: u64 = 256 * 1024 * 1024;

// The owned-document tables intentionally match the existing source registry.
// Shared transactional helpers can replace this declaration at integration.
const PROJECTION_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS owned_documents (
 project_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('prefab','instance','command_module','clip','asset','physics_definition')),
 object_id TEXT NOT NULL,
 revision TEXT NOT NULL CHECK(length(revision)=64),
 blob_digest TEXT NOT NULL REFERENCES blobs(digest),
 byte_length INTEGER NOT NULL CHECK(byte_length>0 AND byte_length<=8388608),
 PRIMARY KEY(project_id,kind,object_id,revision)
) STRICT;
CREATE TABLE IF NOT EXISTS owned_document_provenance (
 project_id TEXT NOT NULL, project_revision TEXT NOT NULL,
 kind TEXT NOT NULL, object_id TEXT NOT NULL, revision TEXT NOT NULL,
 project_definition TEXT NOT NULL DEFAULT 'Project' CHECK(project_definition='Project'),
 PRIMARY KEY(project_id,project_revision,kind,object_id),
 FOREIGN KEY(project_id,kind,object_id,revision)
  REFERENCES owned_documents(project_id,kind,object_id,revision),
 FOREIGN KEY(project_definition,project_id,project_revision)
  REFERENCES documents(definition,document_id,content_hash)
) STRICT;
CREATE TABLE IF NOT EXISTS project_resource_versions (
 project_id TEXT NOT NULL, resource_id TEXT NOT NULL,
 digest TEXT NOT NULL REFERENCES blobs(digest),
 resource_json TEXT NOT NULL CHECK(length(CAST(resource_json AS BLOB))<=16384),
 byte_length INTEGER NOT NULL CHECK(byte_length>=0),
 PRIMARY KEY(project_id,resource_id,digest)
) STRICT;
CREATE TABLE IF NOT EXISTS project_resource_heads (
 project_id TEXT NOT NULL, resource_id TEXT NOT NULL, digest TEXT NOT NULL,
 PRIMARY KEY(project_id,resource_id),
 FOREIGN KEY(project_id,resource_id,digest)
  REFERENCES project_resource_versions(project_id,resource_id,digest)
) STRICT;
CREATE TABLE IF NOT EXISTS project_resource_provenance (
 project_id TEXT NOT NULL, project_revision TEXT NOT NULL,
 resource_id TEXT NOT NULL, digest TEXT NOT NULL,
 project_definition TEXT NOT NULL DEFAULT 'Project' CHECK(project_definition='Project'),
 PRIMARY KEY(project_id,project_revision,resource_id,digest),
 FOREIGN KEY(project_id,resource_id,digest)
  REFERENCES project_resource_versions(project_id,resource_id,digest),
 FOREIGN KEY(project_definition,project_id,project_revision)
  REFERENCES documents(definition,document_id,content_hash)
) STRICT;
CREATE TABLE IF NOT EXISTS authored_projection_commits (
 operation_id TEXT NOT NULL REFERENCES operations(operation_id),
 step_id TEXT NOT NULL, invocation_id TEXT NOT NULL REFERENCES invocations(invocation_id),
 invocation_digest TEXT NOT NULL CHECK(length(invocation_digest)=64),
 change_digest TEXT NOT NULL CHECK(length(change_digest)=64),
 receipt_json TEXT NOT NULL CHECK(length(CAST(receipt_json AS BLOB))<=65536),
 receipt_digest TEXT NOT NULL REFERENCES blobs(digest),
 PRIMARY KEY(operation_id,step_id), UNIQUE(invocation_id)
) STRICT;";

/// Internal identifiers only. The new Project and all changes are read from the
/// immutable CAS payload referenced by durable Invocation.arguments.preparedChange.
/// A document body is never supplied independently by an RPC.
#[derive(Clone, Debug)]
pub struct ProjectionCommitRequest {
    pub operation_id: OperationId,
    pub step_id: StepId,
    pub invocation_id: InvocationId,
    pub invocation_digest: Sha256Digest,
}

/// Coordinator transport identity, cancellation, deadline and generation checks.
/// No JSON wire principal or context claim constructs this capability.
pub trait ProjectionRpcContext {
    fn check(&self) -> StorageResult<()>;
    fn principal_for_context(&self, context: &ContextId) -> StorageResult<PrincipalId>;
}

pub struct ProjectionInput<'a> {
    pub principal: &'a PrincipalId,
    pub operation: &'a OperationRecord,
    pub invocation: &'a Value,
    pub invocation_digest: &'a Sha256Digest,
    pub change: &'a Value,
    pub change_digest: &'a Sha256Digest,
}

/// Concrete producer integration must authorize the actual current context,
/// project, every source pin and native scope, and verify its settled WORLD
/// phase through an independent observer. This port is trusted configuration;
/// it must not accept a provider result's JSON claims as evidence of execution.
/// authorize_projection must validate the actual loaded CAS payload through the
/// planner's PreparedNativeChange::from_payload and its closed payload schema.
/// Runtime does not define a second copy of that internal action schema.
pub trait ProjectionAuthority {
    fn authorize_operation(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        operation: &OperationRecord,
        request: &ProjectionCommitRequest,
        replay: bool,
    ) -> StorageResult<()>;
    fn authorize_projection(
        &mut self,
        store: &DurableStore,
        input: &ProjectionInput<'_>,
        replay: bool,
    ) -> StorageResult<()>;
    fn observe_settled_world_phase(
        &mut self,
        store: &DurableStore,
        input: &ProjectionInput<'_>,
    ) -> StorageResult<WorldPhaseObservation>;
}

/// Raw data from the trusted independent observer, never a deserialized RPC
/// success envelope. Runtime checks every binding and actual retained bytes.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldPhaseObservation {
    pub invocation_id: InvocationId,
    pub invocation_digest: Sha256Digest,
    pub change_digest: Sha256Digest,
    pub context_digest: Sha256Digest,
    pub scope_digest: Sha256Digest,
    pub world_phase_complete: bool,
    pub further_world_effects_possible: bool,
    pub evidence: Vec<BlobRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionReceipt {
    pub operation_id: OperationId,
    pub step_id: StepId,
    pub invocation_id: InvocationId,
    pub invocation_digest: Sha256Digest,
    pub change_digest: Sha256Digest,
    pub project_id: ProjectId,
    pub project_base_revision: Sha256Digest,
    pub project_revision: Sha256Digest,
    pub world_verification_digest: Sha256Digest,
    pub world_evidence: Vec<BlobRef>,
}
#[derive(Clone, Debug)]
pub struct ProjectionCommitResult {
    pub receipt: ProjectionReceipt,
    pub replayed: bool,
}

struct FrozenProjection {
    operation: OperationRecord,
    invocation: Value,
    change: Value,
    invocation_digest: Sha256Digest,
    change_digest: Sha256Digest,
}
impl FrozenProjection {
    fn input<'a>(&'a self, principal: &'a PrincipalId) -> ProjectionInput<'a> {
        ProjectionInput {
            principal,
            operation: &self.operation,
            invocation: &self.invocation,
            invocation_digest: &self.invocation_digest,
            change: &self.change,
            change_digest: &self.change_digest,
        }
    }
}
struct StagedDocument {
    pin: OwnedDocumentPin,
    blob: BlobRef,
}
struct StagedResource {
    reference: Value,
    id: ResourceId,
    blob: BlobRef,
}
struct StagedProjection {
    project: Value,
    base_revision: Sha256Digest,
    after_revision: Sha256Digest,
    project_blob: BlobRef,
    base_resource_ids: BTreeSet<ResourceId>,
    documents: Vec<StagedDocument>,
    carried_documents: Vec<OwnedDocumentPin>,
    before_resources: Vec<StagedResource>,
    after_resources: Vec<StagedResource>,
    carried_resources: Vec<StagedResource>,
    source_resources: Vec<StagedResource>,
}

fn invalid(message: &str) -> StorageError {
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
fn array<'a>(value: &'a Value, key: &str) -> StorageResult<&'a [Value]> {
    let values = value[key]
        .as_array()
        .ok_or_else(|| invalid("Native projection array missing"))?;
    if values.len() > MAX_ITEMS {
        return Err(invalid("Native projection item budget exceeded"));
    }
    Ok(values)
}
fn has_table(connection: &Connection, table: &str) -> StorageResult<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [table],
        |r| r.get::<_, i64>(0),
    )? == 1)
}
fn blob_row(row: (String, i64)) -> StorageResult<BlobRef> {
    Ok(BlobRef {
        digest: Sha256Digest::new(row.0).map_err(contract)?,
        byte_length: u64::try_from(row.1).map_err(|_| invalid("Stored blob length is negative"))?,
    })
}
fn verify_blob(
    store: &DurableStore,
    rpc: &dyn ProjectionRpcContext,
    blob: &BlobRef,
) -> StorageResult<()> {
    // Capture no payload while hashing the full same-open-handle content.
    store
        .cas
        .read_verified_slice::<StorageError, _>(blob, blob.byte_length, 1, || rpc.check())?;
    Ok(())
}
fn check_principal(
    rpc: &dyn ProjectionRpcContext,
    frozen: &FrozenProjection,
) -> StorageResult<PrincipalId> {
    rpc.check()?;
    let actual = rpc.principal_for_context(&frozen.operation.context_id)?;
    if actual != frozen.operation.principal {
        return Err(StorageError::Conflict("Authenticated projection principal"));
    }
    Ok(actual)
}

fn read_document(
    store: &DurableStore,
    rpc: &dyn ProjectionRpcContext,
    definition: &str,
    id: &str,
    revision: &Sha256Digest,
) -> StorageResult<Value> {
    rpc.check()?;
    let row: Option<(String, i64)> = store.connection.query_row(
        "SELECT d.blob_digest,b.byte_length FROM documents d JOIN blobs b ON b.digest=d.blob_digest WHERE definition=?1 AND document_id=?2 AND content_hash=?3",
        params![definition, id, revision.as_str()], |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional()?;
    let blob = blob_row(row.ok_or(StorageError::NotFound("Frozen projection source"))?)?;
    let bytes = store.cas.read_verified_document::<StorageError, _>(
        &blob,
        MAX_OWNED_DOCUMENT_BYTES,
        || rpc.check(),
    )?;
    let value = store
        .validator
        .parse_and_validate(definition, &bytes)
        .map_err(contract)?;
    if verify_projected_digest(definition, &value).map_err(contract)? != *revision {
        return Err(StorageError::Corrupt(
            "Stored projection source digest differs".into(),
        ));
    }
    Ok(value)
}

fn load_frozen(
    store: &DurableStore,
    rpc: &dyn ProjectionRpcContext,
    request: &ProjectionCommitRequest,
    operation: OperationRecord,
) -> StorageResult<FrozenProjection> {
    let row: Option<(String, String, String, i64)> = store.connection.query_row(
        "SELECT i.invocation_id,i.invocation_hash,i.blob_digest,b.byte_length FROM invocations i JOIN blobs b ON b.digest=i.blob_digest WHERE operation_id=?1 AND step_id=?2",
        params![request.operation_id.as_str(), request.step_id.as_str()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    ).optional()?;
    let (id, invocation_hash, blob_digest, length) =
        row.ok_or(StorageError::NotFound("Durable projection invocation"))?;
    if id != request.invocation_id.as_str()
        || invocation_hash != request.invocation_digest.as_str()
        || blob_digest != request.invocation_digest.as_str()
    {
        return Err(StorageError::Conflict("Durable projection invocation"));
    }
    let blob = blob_row((blob_digest, length))?;
    let bytes = store.cas.read_verified_document::<StorageError, _>(
        &blob,
        MAX_OWNED_DOCUMENT_BYTES,
        || rpc.check(),
    )?;
    let invocation = store
        .validator
        .parse_and_validate("Invocation", &bytes)
        .map_err(contract)?;
    let stored_step = operation
        .steps
        .iter()
        .find(|s| s.step_id == request.step_id)
        .ok_or(StorageError::NotFound("Projection step"))?;
    if stored_step.invocation_id.as_ref() != Some(&request.invocation_id)
        || stored_step.invocation_digest.as_ref() != Some(&request.invocation_digest)
        || stored_step.dispatch == DispatchEvidence::NotSent
        || invocation["invocationId"] != request.invocation_id.as_str()
        || invocation["operationId"] != request.operation_id.as_str()
        || invocation["stepId"] != request.step_id.as_str()
        || invocation["context"]["contextId"] != operation.context_id.as_str()
        || invocation["context"]["principalRef"] != operation.principal.as_str()
        || invocation["context"]["projectId"] != operation.project_id.as_str()
    {
        return Err(StorageError::Conflict("Frozen projection identity"));
    }
    let context_digest =
        verify_projected_digest("ExecutionContext", &invocation["context"]).map_err(contract)?;
    if invocation["contextDigest"] != context_digest.as_str()
        || invocation["argumentsDigest"] != digest(&invocation["arguments"])?.as_str()
    {
        return Err(StorageError::Conflict(
            "Frozen projection context/arguments digest",
        ));
    }
    let plan = read_document(
        store,
        rpc,
        "ExecutionPlan",
        operation.plan_id.as_str(),
        &operation.plan_hash,
    )?;
    let step = array(&plan, "steps")?
        .iter()
        .find(|s| s["stepId"] == request.step_id.as_str())
        .ok_or(StorageError::NotFound("Frozen projection plan step"))?;
    for key in [
        "bindingId",
        "actionId",
        "actionContractVersion",
        "actionDigest",
        "implementationDigest",
        "arguments",
    ] {
        if invocation[key] != step[key] {
            return Err(StorageError::Conflict("Frozen projection route/arguments"));
        }
    }
    if plan["planId"] != operation.plan_id.as_str()
        || plan["projectId"] != operation.project_id.as_str()
        || step["effect"] != "write"
        || !stored_step.write_effect
        || step["verificationRequirement"] != "independent_readback"
        || stored_step.verification_requirement != VerificationRequirement::IndependentReadback
        || invocation["context"]["policyRevision"] != plan["policyRevision"]
        || step["contextId"] != operation.context_id.as_str()
        || encode(&operation.scope)? != encode(&plan["scope"])?
        || !array(step, "resultBindings")?.is_empty()
        || !array(&plan, "contextPins")?.iter().any(|pin| {
            pin["contextId"] == operation.context_id.as_str()
                && pin["contextDigest"] == context_digest.as_str()
        })
    {
        return Err(StorageError::Conflict(
            "Frozen projection plan/context/scope",
        ));
    }
    let arguments = invocation["arguments"]
        .as_object()
        .ok_or_else(|| invalid("Frozen native arguments missing"))?;
    if arguments.len() != 1 || !arguments.contains_key("preparedChange") {
        return Err(invalid(
            "Expected the closed composite native action envelope",
        ));
    }
    let change = load_prepared_change(
        store,
        rpc,
        &operation,
        &invocation["arguments"]["preparedChange"],
    )?;
    let allowed = [
        "format",
        "kind",
        "projectId",
        "projectBaseRevision",
        "targetProfileId",
        "projectAfter",
        "documentChanges",
        "worldProjection",
        "resourceReplacements",
        "recoveryReplacements",
        "sourceObjectPins",
        "sourceResourcePins",
        "stagedResources",
        "scenePatch",
        "packManifest",
        "lossRecords",
    ];
    let shape = change
        .as_object()
        .ok_or_else(|| invalid("Frozen native change missing"))?;
    if shape.keys().any(|k| !allowed.contains(&k.as_str()))
        || allowed[..13].iter().any(|k| !shape.contains_key(*k))
        || !shape.contains_key("lossRecords")
        || change["format"] != "mmmm-native-change/1"
        || !matches!(
            change["kind"].as_str(),
            Some(
                "prefab.instantiate"
                    | "instance.clone"
                    | "instance.relocate"
                    | "display.patch"
                    | "command_module.patch"
                    | "clip.retime"
                    | "pack.build"
                    | "resource.patch"
                    | "scene.import_patch"
                    | "recovery.plan"
            )
        )
        || change["projectId"] != operation.project_id.as_str()
        || change["projectBaseRevision"] != plan["projectBaseRevision"]
        || change["targetProfileId"] != change["projectAfter"]["targetProfileId"]
    {
        return Err(StorageError::Conflict("Frozen native change/project base"));
    }
    for key in [
        "documentChanges",
        "worldProjection",
        "resourceReplacements",
        "recoveryReplacements",
        "sourceObjectPins",
        "sourceResourcePins",
        "stagedResources",
        "lossRecords",
    ] {
        array(&change, key)?;
    }
    let change_digest = digest(&change)?;
    Ok(FrozenProjection {
        operation,
        invocation,
        change,
        invocation_digest: blob.digest,
        change_digest,
    })
}

fn load_prepared_change(
    store: &DurableStore,
    rpc: &dyn ProjectionRpcContext,
    operation: &OperationRecord,
    reference: &Value,
) -> StorageResult<Value> {
    let resource = validate_resource(store, reference)?;
    if reference["mediaType"] != "application/vnd.mmmm.prepared-change+json" {
        return Err(StorageError::Conflict("Prepared native payload media type"));
    }
    if !has_table(&store.connection, "artifact_resources")? {
        return Err(StorageError::NotFound("Registered prepared native payload"));
    }
    let row: Option<(String, String, String, i64)> = store.connection.query_row(
        "SELECT resource_json,owner_json,blob_digest,byte_length FROM artifact_resources WHERE resource_id=?1 AND length(CAST(resource_json AS BLOB))<=16384 AND length(CAST(owner_json AS BLOB))<=512",
        [resource.id.as_str()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    ).optional()?;
    let (registered, owner, digest, length) =
        row.ok_or(StorageError::NotFound("Registered prepared native payload"))?;
    if parse_json(registered.as_bytes()).map_err(contract)? != *reference
        || parse_json(owner.as_bytes()).map_err(contract)?
            != json!({"kind":"project","id":operation.project_id})
        || digest != resource.blob.digest.as_str()
        || u64::try_from(length).ok() != Some(resource.blob.byte_length)
    {
        return Err(StorageError::Conflict(
            "Prepared native payload ownership/content",
        ));
    }
    let bytes = store.cas.read_verified_document::<StorageError, _>(
        &resource.blob,
        MAX_OWNED_DOCUMENT_BYTES,
        || rpc.check(),
    )?;
    let payload = parse_json(&bytes).map_err(contract)?;
    let shape = payload
        .as_object()
        .ok_or_else(|| invalid("Prepared native CAS envelope missing"))?;
    if shape.len() != 1 || !shape.contains_key("change") {
        return Err(invalid(
            "Prepared native CAS envelope must contain only change",
        ));
    }
    Ok(payload["change"].clone())
}

fn require_live(frozen: &FrozenProjection, request: &ProjectionCommitRequest) -> StorageResult<()> {
    let record = &frozen.operation;
    let step = record
        .steps
        .iter()
        .find(|s| s.step_id == request.step_id)
        .ok_or(StorageError::NotFound("Projection step"))?;
    if record.state != OperationState::Running
        || record.cancellation_requested
        || record.reconciliation_required
        || step.finished
        || step.dispatch == DispatchEvidence::NotSent
    {
        return Err(StorageError::InvalidTransition(
            "Document commit requires a live composite invocation without pending reconciliation"
                .into(),
        ));
    }
    record.scope.validate()?;
    if record.scope.project_id != record.project_id {
        return Err(StorageError::Conflict("Projection scope project"));
    }
    Ok(())
}

fn validate_world_observation(
    store: &DurableStore,
    rpc: &dyn ProjectionRpcContext,
    frozen: &FrozenProjection,
    observation: &WorldPhaseObservation,
    require_retained: bool,
) -> StorageResult<Sha256Digest> {
    if observation.invocation_id.as_str()
        != frozen.invocation["invocationId"].as_str().unwrap_or("")
        || observation.invocation_digest != frozen.invocation_digest
        || observation.change_digest != frozen.change_digest
        || observation.context_digest.as_str()
            != frozen.invocation["contextDigest"].as_str().unwrap_or("")
        || observation.scope_digest
            != digest(&serde_json::to_value(&frozen.operation.scope).map_err(contract)?)?
        || !observation.world_phase_complete
        || observation.further_world_effects_possible
        || observation.evidence.is_empty()
        || observation.evidence.len() > 64
        || observation
            .evidence
            .iter()
            .map(|b| &b.digest)
            .collect::<BTreeSet<_>>()
            .len()
            != observation.evidence.len()
    {
        return Err(StorageError::Conflict(
            "Independent world-phase verification",
        ));
    }
    let mut total = 0u64;
    for blob in &observation.evidence {
        account(&mut total, blob.byte_length)?;
        if require_retained {
            let retained: i64 = store.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM blob_refs r JOIN blobs b ON b.digest=r.digest WHERE r.owner_id=?1 AND r.digest=?2 AND b.byte_length=?3 AND r.owner_kind IN ('operation','application_evidence'))",
                params![frozen.operation.operation_id.as_str(), blob.digest.as_str(), i64::try_from(blob.byte_length).map_err(contract)?],
                |r| r.get(0),
            )?;
            if retained != 1 {
                return Err(StorageError::Conflict("Retained operation world evidence"));
            }
        }
        verify_blob(store, rpc, blob)?;
    }
    canonical_digest(&serde_json::to_value(observation).map_err(contract)?).map_err(contract)
}

fn account(total: &mut u64, bytes: u64) -> StorageResult<()> {
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| invalid("Projection byte count overflow"))?;
    if *total > MAX_PROJECTION_BYTES {
        return Err(invalid("Projection cumulative byte budget exceeded"));
    }
    Ok(())
}

fn project_pins(
    project: &Value,
) -> StorageResult<BTreeMap<(OwnedDocumentKind, ObjectId), OwnedDocumentPin>> {
    let mut pins = BTreeMap::new();
    for raw in array(project, "ownedResources")? {
        let pin: OwnedDocumentPin = serde_json::from_value(raw.clone()).map_err(contract)?;
        if pins
            .insert((pin.kind, pin.object_id.clone()), pin)
            .is_some()
        {
            return Err(invalid("Project ownership identities are ambiguous"));
        }
    }
    for (kind, key) in [
        (OwnedDocumentKind::Prefab, "prefabIds"),
        (OwnedDocumentKind::Instance, "instanceIds"),
    ] {
        let listed: Vec<ObjectId> = array(project, key)?
            .iter()
            .map(|v| serde_json::from_value(v.clone()).map_err(contract))
            .collect::<StorageResult<_>>()?;
        let listed_set: BTreeSet<_> = listed.iter().cloned().collect();
        let owned: BTreeSet<_> = pins
            .keys()
            .filter(|(k, _)| *k == kind)
            .map(|(_, id)| id.clone())
            .collect();
        if listed.len() != listed_set.len() || listed_set != owned {
            return Err(invalid("Project authored indexes differ from ownership"));
        }
    }
    let resource_ids: Vec<ResourceId> = array(project, "resourceIds")?
        .iter()
        .map(|v| serde_json::from_value(v.clone()).map_err(contract))
        .collect::<StorageResult<_>>()?;
    if resource_ids.iter().collect::<BTreeSet<_>>().len() != resource_ids.len() {
        return Err(invalid("Project resource identities are ambiguous"));
    }
    Ok(pins)
}

fn owned_blob(
    store: &DurableStore,
    project: &ProjectId,
    revision: &Sha256Digest,
    pin: &OwnedDocumentPin,
) -> StorageResult<BlobRef> {
    if !has_table(&store.connection, "owned_documents")?
        || !has_table(&store.connection, "owned_document_provenance")?
    {
        return Err(StorageError::NotFound("Authored source provenance"));
    }
    let row: Option<(String, i64, i64)> = store.connection.query_row(
        "SELECT d.blob_digest,d.byte_length,b.byte_length FROM owned_documents d JOIN owned_document_provenance p ON p.project_id=d.project_id AND p.kind=d.kind AND p.object_id=d.object_id AND p.revision=d.revision JOIN blobs b ON b.digest=d.blob_digest WHERE d.project_id=?1 AND p.project_revision=?2 AND d.kind=?3 AND d.object_id=?4 AND d.revision=?5 AND p.project_definition='Project'",
        params![project.as_str(), revision.as_str(), pin.kind.as_str(), pin.object_id.as_str(), pin.revision.as_str()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).optional()?;
    let (digest, length, indexed_length) =
        row.ok_or(StorageError::NotFound("Authored source provenance"))?;
    if length != indexed_length || length <= 0 || length as u64 > MAX_OWNED_DOCUMENT_BYTES {
        return Err(StorageError::Corrupt(
            "Authored source length index differs".into(),
        ));
    }
    blob_row((digest, length))
}

fn validate_owned_value(
    store: &DurableStore,
    pin: &OwnedDocumentPin,
    value: &Value,
) -> StorageResult<Vec<u8>> {
    store
        .validator
        .validate(pin.kind.definition(), value)
        .map_err(contract)?;
    if value[pin.kind.identity_field()] != pin.object_id.as_str()
        || verify_projected_digest(pin.kind.definition(), value).map_err(contract)? != pin.revision
    {
        return Err(StorageError::Conflict("Canonical authored document pin"));
    }
    encode_json(value).map_err(contract)
}

fn read_owned_source(
    store: &DurableStore,
    rpc: &dyn ProjectionRpcContext,
    project: &ProjectId,
    revision: &Sha256Digest,
    pin: &OwnedDocumentPin,
    total: &mut u64,
) -> StorageResult<Value> {
    let blob = owned_blob(store, project, revision, pin)?;
    account(total, blob.byte_length)?;
    let bytes = store.cas.read_verified_document::<StorageError, _>(
        &blob,
        MAX_OWNED_DOCUMENT_BYTES,
        || rpc.check(),
    )?;
    let value = parse_json(&bytes).map_err(contract)?;
    validate_owned_value(store, pin, &value)?;
    Ok(value)
}

fn validate_resource(store: &DurableStore, value: &Value) -> StorageResult<StagedResource> {
    store
        .validator
        .validate("ResourceRef", value)
        .map_err(contract)?;
    if encode_json(value).map_err(contract)?.len() > MAX_RESOURCE_METADATA_BYTES {
        return Err(invalid("Resource metadata exceeds byte budget"));
    }
    Ok(StagedResource {
        reference: value.clone(),
        id: field(value, "resourceId")?,
        blob: BlobRef {
            digest: field(value, "sha256")?,
            byte_length: value["sizeBytes"]
                .as_u64()
                .ok_or_else(|| invalid("Resource byte length is invalid"))?,
        },
    })
}

fn artifact_reference(
    store: &DurableStore,
    resource: &StagedResource,
    project: &ProjectId,
    operation: Option<&OperationRecord>,
) -> StorageResult<bool> {
    if !has_table(&store.connection, "artifact_resources")? {
        return Ok(false);
    }
    let row: Option<(String, String, String, i64)> = store.connection.query_row(
        "SELECT resource_json,owner_json,blob_digest,byte_length FROM artifact_resources WHERE resource_id=?1 AND length(CAST(resource_json AS BLOB))<=16384 AND length(CAST(owner_json AS BLOB))<=512",
        [resource.id.as_str()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    ).optional()?;
    let Some((reference, owner, digest, length)) = row else {
        return Ok(false);
    };
    let owner = parse_json(owner.as_bytes()).map_err(contract)?;
    let allowed_owner = owner == json!({"kind":"project", "id":project})
        || operation.is_some_and(|op| {
            owner == json!({"kind":"operation", "id":op.operation_id})
                || owner == json!({"kind":"principal", "id":op.principal})
        });
    Ok(allowed_owner
        && parse_json(reference.as_bytes()).map_err(contract)? == resource.reference
        && digest == resource.blob.digest.as_str()
        && u64::try_from(length).ok() == Some(resource.blob.byte_length))
}

fn current_resource(
    store: &DurableStore,
    project: &ProjectId,
    resource: &StagedResource,
) -> StorageResult<()> {
    if has_table(&store.connection, "project_resource_heads")? {
        let row: Option<(String, String, i64)> = store.connection.query_row(
            "SELECT v.digest,v.resource_json,v.byte_length FROM project_resource_heads h JOIN project_resource_versions v ON v.project_id=h.project_id AND v.resource_id=h.resource_id AND v.digest=h.digest WHERE h.project_id=?1 AND h.resource_id=?2 AND length(CAST(v.resource_json AS BLOB))<=16384",
            params![project.as_str(), resource.id.as_str()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).optional()?;
        if let Some((digest, reference, length)) = row {
            if digest != resource.blob.digest.as_str()
                || parse_json(reference.as_bytes()).map_err(contract)? != resource.reference
                || u64::try_from(length).ok() != Some(resource.blob.byte_length)
            {
                return Err(StorageError::Conflict(
                    "Current project resource before-image",
                ));
            }
            return Ok(());
        }
        let head_exists: i64 = store.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM project_resource_heads WHERE project_id=?1 AND resource_id=?2)",
            params![project.as_str(), resource.id.as_str()], |r| r.get(0),
        )?;
        if head_exists == 1 {
            return Err(StorageError::Corrupt(
                "Project resource head has no immutable version".into(),
            ));
        }
    }
    if !artifact_reference(store, resource, project, None)? {
        return Err(StorageError::Conflict(
            "Registered project resource before-image",
        ));
    }
    Ok(())
}

fn require_registered_source(
    store: &DurableStore,
    operation: &OperationRecord,
    resource: &StagedResource,
) -> StorageResult<()> {
    if has_table(&store.connection, "project_resource_versions")? {
        let row: Option<(String, i64)> = store.connection.query_row(
            "SELECT v.resource_json,v.byte_length FROM project_resource_versions v WHERE v.project_id=?1 AND v.resource_id=?2 AND v.digest=?3 AND length(CAST(v.resource_json AS BLOB))<=16384 AND EXISTS(SELECT 1 FROM project_resource_provenance p WHERE p.project_id=v.project_id AND p.resource_id=v.resource_id AND p.digest=v.digest)",
            params![operation.project_id.as_str(), resource.id.as_str(), resource.blob.digest.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).optional()?;
        if let Some((reference, length)) = row {
            if parse_json(reference.as_bytes()).map_err(contract)? == resource.reference
                && u64::try_from(length).ok() == Some(resource.blob.byte_length)
            {
                return Ok(());
            }
            return Err(StorageError::Conflict("Immutable project source resource"));
        }
    }
    if artifact_reference(store, resource, &operation.project_id, Some(operation))? {
        return Ok(());
    }
    Err(StorageError::NotFound(
        "Registered authorized source resource",
    ))
}

fn resolve_current_resource(
    store: &DurableStore,
    project: &ProjectId,
    id: &ResourceId,
) -> StorageResult<StagedResource> {
    if has_table(&store.connection, "project_resource_heads")? {
        let raw: Option<String> = store.connection.query_row(
            "SELECT v.resource_json FROM project_resource_heads h JOIN project_resource_versions v ON v.project_id=h.project_id AND v.resource_id=h.resource_id AND v.digest=h.digest WHERE h.project_id=?1 AND h.resource_id=?2 AND length(CAST(v.resource_json AS BLOB))<=16384",
            params![project.as_str(), id.as_str()], |r| r.get(0),
        ).optional()?;
        if let Some(raw) = raw {
            let resource =
                validate_resource(store, &parse_json(raw.as_bytes()).map_err(contract)?)?;
            if resource.id != *id {
                return Err(StorageError::Corrupt(
                    "Resource head identity differs".into(),
                ));
            }
            current_resource(store, project, &resource)?;
            return Ok(resource);
        }
    }
    if !has_table(&store.connection, "artifact_resources")? {
        return Err(StorageError::NotFound("Current project resource"));
    }
    let raw: Option<String> = store.connection.query_row(
        "SELECT resource_json FROM artifact_resources WHERE resource_id=?1 AND length(CAST(resource_json AS BLOB))<=16384", [id.as_str()], |r| r.get(0),
    ).optional()?;
    let raw = raw.ok_or(StorageError::NotFound("Current project resource"))?;
    let resource = validate_resource(store, &parse_json(raw.as_bytes()).map_err(contract)?)?;
    if resource.id != *id || !artifact_reference(store, &resource, project, None)? {
        return Err(StorageError::Conflict("Current project resource owner"));
    }
    Ok(resource)
}

fn stage_projection(
    store: &DurableStore,
    rpc: &dyn ProjectionRpcContext,
    frozen: &FrozenProjection,
) -> StorageResult<StagedProjection> {
    let change = &frozen.change;
    let project_id = &frozen.operation.project_id;
    let base_revision: Sha256Digest = field(change, "projectBaseRevision")?;
    let base = read_document(store, rpc, "Project", project_id.as_str(), &base_revision)?;
    if base["projectId"] != project_id.as_str()
        || base["targetProfileId"] != change["targetProfileId"]
    {
        return Err(StorageError::Conflict("Stored authored Project base"));
    }
    let old_pins = project_pins(&base)?;
    let base_resource_ids: BTreeSet<ResourceId> = array(&base, "resourceIds")?
        .iter()
        .map(|v| serde_json::from_value(v.clone()).map_err(contract))
        .collect::<StorageResult<_>>()?;
    let project = change["projectAfter"].clone();
    store
        .validator
        .validate("Project", &project)
        .map_err(contract)?;
    let after_revision = verify_projected_digest("Project", &project).map_err(contract)?;
    if project["projectId"] != project_id.as_str()
        || project["targetProfileId"] != base["targetProfileId"]
    {
        return Err(StorageError::Conflict("Authored Project identity/target"));
    }
    let new_pins = project_pins(&project)?;
    let mut total = encode_json(&base).map_err(contract)?.len() as u64;
    let mut expected = base.clone();
    let mut documents = Vec::new();
    let mut changed = BTreeSet::new();
    let mut after_values = BTreeMap::new();
    for document in array(change, "documentChanges")? {
        rpc.check()?;
        let kind: OwnedDocumentKind = field(document, "kind")?;
        let id: ObjectId = field(document, "objectId")?;
        let before: Option<Sha256Digest> = field(document, "beforeRevision")?;
        let pin = OwnedDocumentPin {
            kind,
            object_id: id.clone(),
            revision: field(document, "afterRevision")?,
        };
        if !changed.insert((kind, id.clone()))
            || new_pins.get(&(kind, id.clone())) != Some(&pin)
            || !frozen.operation.scope.object_ids.contains(&id)
        {
            return Err(StorageError::Conflict("Frozen authored mutation scope/pin"));
        }
        match (old_pins.get(&(kind, id.clone())), before.as_ref()) {
            (Some(old), Some(before)) if &old.revision == before => {
                read_owned_source(store, rpc, project_id, &base_revision, old, &mut total)?;
                let entries = expected["ownedResources"]
                    .as_array_mut()
                    .ok_or_else(|| invalid("Project owned index missing"))?;
                let entry = entries
                    .iter_mut()
                    .find(|e| e["objectId"] == id.as_str() && e["kind"] == json!(kind))
                    .ok_or(StorageError::Conflict("Original authored mutation pin"))?;
                entry["revision"] = json!(pin.revision);
            }
            (None, None) => {
                expected["ownedResources"]
                    .as_array_mut()
                    .ok_or_else(|| invalid("Project owned index missing"))?
                    .push(json!(pin));
                let index = match kind {
                    OwnedDocumentKind::Prefab => Some("prefabIds"),
                    OwnedDocumentKind::Instance => Some("instanceIds"),
                    _ => None,
                };
                if let Some(index) = index {
                    expected[index]
                        .as_array_mut()
                        .ok_or_else(|| invalid("Project authored index missing"))?
                        .push(json!(id));
                }
            }
            _ => {
                return Err(StorageError::Conflict(
                    "Original authored mutation before-revision",
                ));
            }
        }
        let bytes = validate_owned_value(store, &pin, &document["after"])?;
        account(&mut total, bytes.len() as u64)?;
        let blob = store.cas.put(&bytes)?;
        verify_blob(store, rpc, &blob)?;
        after_values.insert((kind, id), document["after"].clone());
        documents.push(StagedDocument { pin, blob });
    }
    let mut carried_documents = Vec::new();
    for (identity, pin) in &new_pins {
        if !changed.contains(identity) {
            if old_pins.get(identity) != Some(pin) {
                return Err(StorageError::Conflict("Unlisted authored mutation"));
            }
            read_owned_source(store, rpc, project_id, &base_revision, pin, &mut total)?;
            carried_documents.push(pin.clone());
        }
    }
    if old_pins.keys().any(|id| !new_pins.contains_key(id)) {
        return Err(StorageError::Conflict("Unlisted authored deletion"));
    }
    let mut source_resources = Vec::new();
    let mut source_ids = BTreeMap::new();
    for raw in array(change, "sourceResourcePins")? {
        let resource = validate_resource(store, raw)?;
        let identity = (resource.id.clone(), resource.blob.digest.clone());
        if source_ids
            .insert(identity, resource.reference.clone())
            .is_some()
        {
            return Err(invalid("Duplicate frozen resource source pin"));
        }
        require_registered_source(store, &frozen.operation, &resource)?;
        account(&mut total, resource.blob.byte_length)?;
        verify_blob(store, rpc, &resource.blob)?;
        source_resources.push(resource);
    }
    let mut object_sources = BTreeSet::new();
    for raw in array(change, "sourceObjectPins")? {
        let pin: OwnedDocumentPin = serde_json::from_value(raw.clone()).map_err(contract)?;
        if old_pins.get(&(pin.kind, pin.object_id.clone())) != Some(&pin)
            || !object_sources.insert(pin.clone())
        {
            return Err(StorageError::Conflict("Original authored source pin"));
        }
        read_owned_source(store, rpc, project_id, &base_revision, &pin, &mut total)?;
    }
    let mut before_resources = Vec::new();
    let mut after_resources = Vec::new();
    let mut target_ids = BTreeSet::new();
    for raw in array(change, "resourceReplacements")? {
        let target: ResourceId = field(raw, "targetResourceId")?;
        let before = validate_resource(store, &raw["before"])?;
        let source = validate_resource(store, &raw["replacementSource"])?;
        if target != before.id
            || !target_ids.insert(target.clone())
            || !frozen.operation.scope.resource_ids.contains(&target)
            || !array(&base, "resourceIds")?
                .iter()
                .any(|id| id == target.as_str())
            || source_ids.get(&(before.id.clone(), before.blob.digest.clone()))
                != Some(&before.reference)
            || source_ids.get(&(source.id.clone(), source.blob.digest.clone()))
                != Some(&source.reference)
        {
            return Err(StorageError::Conflict(
                "Frozen resource replacement scope/source",
            ));
        }
        current_resource(store, project_id, &before)?;
        account(&mut total, before.blob.byte_length)?;
        verify_blob(store, rpc, &before.blob)?;
        let mut after = source.reference.clone();
        after["resourceId"] = json!(target);
        before_resources.push(before);
        after_resources.push(validate_resource(store, &after)?);
    }
    for raw in array(change, "stagedResources")? {
        let resource = validate_resource(store, raw)?;
        if !target_ids.insert(resource.id.clone())
            || !frozen.operation.scope.resource_ids.contains(&resource.id)
        {
            return Err(StorageError::Conflict(
                "Frozen staged resource scope/identity",
            ));
        }
        account(&mut total, resource.blob.byte_length)?;
        verify_blob(store, rpc, &resource.blob)?;
        if !documents.is_empty() {
            let ids = expected["resourceIds"]
                .as_array_mut()
                .ok_or_else(|| invalid("Project resource index missing"))?;
            if !ids.iter().any(|id| id == resource.id.as_str()) {
                ids.push(json!(resource.id));
            }
        }
        after_resources.push(resource);
    }
    expected["revision"] =
        json!(mmmm_contracts::projected_digest("Project", &expected).map_err(contract)?);
    if expected != project {
        return Err(StorageError::Conflict(
            "Exact frozen authored Project promotion",
        ));
    }
    if after_revision != base_revision
        && !frozen
            .operation
            .scope
            .object_ids
            .iter()
            .any(|id| id.as_str() == project_id.as_str())
    {
        return Err(StorageError::Conflict("Frozen Project mutation scope"));
    }
    validate_world_documents(
        store,
        rpc,
        frozen,
        &old_pins,
        &new_pins,
        &after_values,
        &mut total,
    )?;
    let project_bytes = encode_json(&project).map_err(contract)?;
    account(&mut total, project_bytes.len() as u64)?;
    let project_blob = store.cas.put(&project_bytes)?;
    verify_blob(store, rpc, &project_blob)?;
    let mut carried_resources = Vec::new();
    for raw_id in array(&project, "resourceIds")? {
        let id: ResourceId = serde_json::from_value(raw_id.clone()).map_err(contract)?;
        if !after_resources.iter().any(|r| r.id == id) {
            let resource = resolve_current_resource(store, project_id, &id)?;
            account(&mut total, resource.blob.byte_length)?;
            verify_blob(store, rpc, &resource.blob)?;
            carried_resources.push(resource);
        }
    }
    Ok(StagedProjection {
        project,
        base_revision,
        after_revision,
        project_blob,
        base_resource_ids,
        documents,
        carried_documents,
        before_resources,
        after_resources,
        carried_resources,
        source_resources,
    })
}

fn validate_world_documents(
    store: &DurableStore,
    rpc: &dyn ProjectionRpcContext,
    frozen: &FrozenProjection,
    old_pins: &BTreeMap<(OwnedDocumentKind, ObjectId), OwnedDocumentPin>,
    new_pins: &BTreeMap<(OwnedDocumentKind, ObjectId), OwnedDocumentPin>,
    after_values: &BTreeMap<(OwnedDocumentKind, ObjectId), Value>,
    total: &mut u64,
) -> StorageResult<()> {
    let base_revision: Sha256Digest = field(&frozen.change, "projectBaseRevision")?;
    let mut instance_ids = BTreeSet::new();
    for projection in array(&frozen.change, "worldProjection")? {
        rpc.check()?;
        let after_id: ObjectId = field(&projection["after"], "instanceId")?;
        if !instance_ids.insert(after_id.clone())
            || after_values.get(&(OwnedDocumentKind::Instance, after_id.clone()))
                != Some(&projection["after"])
            || !frozen.operation.scope.object_ids.contains(&after_id)
        {
            return Err(StorageError::Conflict(
                "Frozen world projection authored instance/scope",
            ));
        }
        if projection["before"].is_null() != projection["beforeDefinition"].is_null() {
            return Err(StorageError::Conflict("Frozen world before pair"));
        }
        for (kind, key) in [
            (OwnedDocumentKind::Instance, "before"),
            (OwnedDocumentKind::Prefab, "beforeDefinition"),
        ] {
            if !projection[key].is_null() {
                let id: ObjectId = field(&projection[key], kind.identity_field())?;
                if kind == OwnedDocumentKind::Instance
                    && !frozen.operation.scope.object_ids.contains(&id)
                {
                    return Err(StorageError::Conflict("Frozen world before instance scope"));
                }
                let pin = old_pins
                    .get(&(kind, id))
                    .ok_or(StorageError::Conflict("Frozen world before ownership"))?;
                if read_owned_source(
                    store,
                    rpc,
                    &frozen.operation.project_id,
                    &base_revision,
                    pin,
                    total,
                )? != projection[key]
                {
                    return Err(StorageError::Conflict(
                        "Frozen world before source document",
                    ));
                }
            }
        }
        let mut values = vec![
            (OwnedDocumentKind::Instance, &projection["after"]),
            (OwnedDocumentKind::Prefab, &projection["definition"]),
        ];
        for (kind, key) in [
            (OwnedDocumentKind::CommandModule, "commandModules"),
            (OwnedDocumentKind::AnimationClip, "clips"),
            (OwnedDocumentKind::PhysicsDefinition, "physicsDefinitions"),
        ] {
            values.extend(array(projection, key)?.iter().map(|v| (kind, v)));
        }
        for (kind, value) in values {
            let id: ObjectId = field(value, kind.identity_field())?;
            let pin = new_pins
                .get(&(kind, id.clone()))
                .ok_or(StorageError::Conflict("Frozen world after ownership"))?;
            validate_owned_value(store, pin, value)?;
            if let Some(changed) = after_values.get(&(kind, id.clone())) {
                if changed != value {
                    return Err(StorageError::Conflict(
                        "Frozen world/authored after document",
                    ));
                }
            } else {
                let original = old_pins
                    .get(&(kind, id))
                    .ok_or(StorageError::Conflict("Frozen world source ownership"))?;
                if original != pin
                    || read_owned_source(
                        store,
                        rpc,
                        &frozen.operation.project_id,
                        &base_revision,
                        original,
                        total,
                    )? != *value
                {
                    return Err(StorageError::Conflict(
                        "Frozen world immutable source document",
                    ));
                }
            }
        }
        for raw in array(projection, "resourcePins")? {
            let resource = validate_resource(store, raw)?;
            if !array(&frozen.change, "sourceResourcePins")?
                .iter()
                .chain(array(&frozen.change, "stagedResources")?.iter())
                .any(|r| r == &resource.reference)
            {
                return Err(StorageError::Conflict("Frozen world resource source pin"));
            }
        }
    }
    Ok(())
}

fn insert_document(
    transaction: &Transaction<'_>,
    definition: &str,
    id: &str,
    revision: &Sha256Digest,
    blob: &BlobRef,
) -> StorageResult<()> {
    register_blob(transaction, blob)?;
    let old: Option<String> = transaction.query_row(
        "SELECT blob_digest FROM documents WHERE definition=?1 AND document_id=?2 AND content_hash=?3",
        params![definition, id, revision.as_str()], |r| r.get(0),
    ).optional()?;
    if old.as_ref().is_some_and(|old| old != blob.digest.as_str()) {
        return Err(StorageError::Conflict("Immutable canonical document bytes"));
    }
    transaction.execute(
        "INSERT OR IGNORE INTO documents(definition,document_id,content_hash,blob_digest) VALUES(?1,?2,?3,?4)",
        params![definition, id, revision.as_str(), blob.digest.as_str()],
    )?;
    Ok(())
}

fn insert_owned_document(
    transaction: &Transaction<'_>,
    project: &ProjectId,
    revision: &Sha256Digest,
    document: &StagedDocument,
) -> StorageResult<()> {
    let pin = &document.pin;
    let old: Option<(String, i64)> = transaction.query_row(
        "SELECT blob_digest,byte_length FROM owned_documents WHERE project_id=?1 AND kind=?2 AND object_id=?3 AND revision=?4",
        params![project.as_str(), pin.kind.as_str(), pin.object_id.as_str(), pin.revision.as_str()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional()?;
    if let Some((digest, length)) = old {
        if digest != document.blob.digest.as_str()
            || u64::try_from(length).ok() != Some(document.blob.byte_length)
        {
            return Err(StorageError::Conflict("Immutable authored document bytes"));
        }
    } else {
        let count: i64 = transaction.query_row(
            "SELECT count(*) FROM owned_documents WHERE project_id=?1",
            [project.as_str()],
            |r| r.get(0),
        )?;
        if count >= MAX_OWNED_DOCUMENTS_PER_PROJECT as i64 {
            return Err(invalid("Authored document project capacity exhausted"));
        }
    }
    insert_document(
        transaction,
        pin.kind.definition(),
        pin.object_id.as_str(),
        &pin.revision,
        &document.blob,
    )?;
    let owner = digest(
        &json!({"projectId":project,"kind":pin.kind,"objectId":pin.object_id,"revision":pin.revision}),
    )?;
    pin_blob(
        transaction,
        "owned_document",
        owner.as_str(),
        &document.blob,
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO owned_documents(project_id,kind,object_id,revision,blob_digest,byte_length) VALUES(?1,?2,?3,?4,?5,?6)",
        params![project.as_str(), pin.kind.as_str(), pin.object_id.as_str(), pin.revision.as_str(), document.blob.digest.as_str(), i64::try_from(document.blob.byte_length).map_err(contract)?],
    )?;
    insert_owned_provenance(transaction, project, revision, pin)
}

fn insert_owned_provenance(
    transaction: &Transaction<'_>,
    project: &ProjectId,
    revision: &Sha256Digest,
    pin: &OwnedDocumentPin,
) -> StorageResult<()> {
    let prior: Option<String> = transaction.query_row(
        "SELECT revision FROM owned_document_provenance WHERE project_id=?1 AND project_revision=?2 AND kind=?3 AND object_id=?4",
        params![project.as_str(), revision.as_str(), pin.kind.as_str(), pin.object_id.as_str()], |r| r.get(0),
    ).optional()?;
    if prior
        .as_ref()
        .is_some_and(|old| old != pin.revision.as_str())
    {
        return Err(StorageError::Conflict("Immutable authored provenance"));
    }
    transaction.execute(
        "INSERT OR IGNORE INTO owned_document_provenance(project_id,project_revision,kind,object_id,revision) VALUES(?1,?2,?3,?4,?5)",
        params![project.as_str(), revision.as_str(), pin.kind.as_str(), pin.object_id.as_str(), pin.revision.as_str()],
    )?;
    Ok(())
}

fn insert_resource_version(
    transaction: &Transaction<'_>,
    project: &ProjectId,
    resource: &StagedResource,
) -> StorageResult<()> {
    let encoded = encode(&resource.reference)?;
    let old: Option<(String, i64)> = transaction.query_row(
        "SELECT resource_json,byte_length FROM project_resource_versions WHERE project_id=?1 AND resource_id=?2 AND digest=?3 AND length(CAST(resource_json AS BLOB))<=16384",
        params![project.as_str(), resource.id.as_str(), resource.blob.digest.as_str()], |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional()?;
    if let Some((old, length)) = old {
        if parse_json(old.as_bytes()).map_err(contract)? != resource.reference
            || u64::try_from(length).ok() != Some(resource.blob.byte_length)
        {
            return Err(StorageError::Conflict("Immutable project resource version"));
        }
    } else {
        let count: i64 = transaction.query_row(
            "SELECT count(*) FROM project_resource_versions WHERE project_id=?1",
            [project.as_str()],
            |r| r.get(0),
        )?;
        if count >= MAX_RESOURCE_VERSIONS {
            return Err(invalid("Project resource version capacity exhausted"));
        }
    }
    let owner = digest(
        &json!({"projectId":project,"resourceId":resource.id,"sha256":resource.blob.digest}),
    )?;
    pin_blob(
        transaction,
        "project_resource",
        owner.as_str(),
        &resource.blob,
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO project_resource_versions(project_id,resource_id,digest,resource_json,byte_length) VALUES(?1,?2,?3,?4,?5)",
        params![project.as_str(), resource.id.as_str(), resource.blob.digest.as_str(), encoded, i64::try_from(resource.blob.byte_length).map_err(contract)?],
    )?;
    Ok(())
}
fn insert_resource_provenance(
    transaction: &Transaction<'_>,
    project: &ProjectId,
    revision: &Sha256Digest,
    resource: &StagedResource,
) -> StorageResult<()> {
    transaction.execute(
        "INSERT OR IGNORE INTO project_resource_provenance(project_id,project_revision,resource_id,digest) VALUES(?1,?2,?3,?4)",
        params![project.as_str(), revision.as_str(), resource.id.as_str(), resource.blob.digest.as_str()],
    )?;
    Ok(())
}
fn set_resource_head(
    transaction: &Transaction<'_>,
    project: &ProjectId,
    resource: &StagedResource,
) -> StorageResult<()> {
    transaction.execute(
        "INSERT INTO project_resource_heads(project_id,resource_id,digest) VALUES(?1,?2,?3) ON CONFLICT(project_id,resource_id) DO UPDATE SET digest=excluded.digest",
        params![project.as_str(), resource.id.as_str(), resource.blob.digest.as_str()],
    )?;
    Ok(())
}

fn guard_project_base(
    store: &DurableStore,
    project: &ProjectId,
    expected: &Sha256Digest,
) -> StorageResult<()> {
    let row: Option<(String, String, Option<String>)> = store.connection.query_row(
        "SELECT p.revision,p.blob_digest,d.blob_digest FROM project_heads p LEFT JOIN documents d ON d.definition='Project' AND d.document_id=p.project_id AND d.content_hash=?2 WHERE p.project_id=?1",
        params![project.as_str(), expected.as_str()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).optional()?;
    let Some((revision, blob, stored_blob)) = row else {
        return Err(StorageError::NotFound("Project head"));
    };
    if revision != expected.as_str() || stored_blob.as_deref() != Some(blob.as_str()) {
        return Err(StorageError::Conflict("Project base revision"));
    }
    Ok(())
}

fn receipt_exists(store: &DurableStore, request: &ProjectionCommitRequest) -> StorageResult<bool> {
    if !has_table(&store.connection, "authored_projection_commits")? {
        return Ok(false);
    }
    Ok(store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM authored_projection_commits WHERE operation_id=?1 AND step_id=?2)",
        params![request.operation_id.as_str(), request.step_id.as_str()], |r| r.get::<_, i64>(0),
    )? == 1)
}

fn load_receipt(
    store: &DurableStore,
    rpc: &dyn ProjectionRpcContext,
    request: &ProjectionCommitRequest,
    frozen: &FrozenProjection,
) -> StorageResult<ProjectionReceipt> {
    let row: Option<(String, String, String, String, String, i64)> = store.connection.query_row(
        "SELECT c.invocation_id,c.invocation_digest,c.change_digest,c.receipt_json,c.receipt_digest,b.byte_length FROM authored_projection_commits c JOIN blobs b ON b.digest=c.receipt_digest WHERE operation_id=?1 AND step_id=?2 AND length(CAST(c.receipt_json AS BLOB))<=65536",
        params![request.operation_id.as_str(), request.step_id.as_str()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
    ).optional()?;
    let (id, invocation_digest, change_digest, receipt_json, receipt_digest, length) = row.ok_or(
        StorageError::NotFound("Committed authored projection receipt"),
    )?;
    if id != request.invocation_id.as_str()
        || invocation_digest != request.invocation_digest.as_str()
        || change_digest != frozen.change_digest.as_str()
    {
        return Err(StorageError::Conflict(
            "Committed projection invocation/change",
        ));
    }
    let blob = blob_row((receipt_digest, length))?;
    let retained: i64 = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM blob_refs WHERE owner_kind='operation' AND owner_id=?1 AND digest=?2)",
        params![request.operation_id.as_str(), blob.digest.as_str()], |r| r.get(0),
    )?;
    if retained != 1 {
        return Err(StorageError::Corrupt(
            "Projection receipt operation retention is missing".into(),
        ));
    }
    let bytes = store.cas.read_verified_document::<StorageError, _>(
        &blob,
        MAX_OWNED_DOCUMENT_BYTES,
        || rpc.check(),
    )?;
    if bytes != receipt_json.as_bytes() {
        return Err(StorageError::Corrupt(
            "Projection receipt CAS/index differ".into(),
        ));
    }
    let receipt: ProjectionReceipt = decode(&receipt_json)?;
    if receipt.operation_id != request.operation_id
        || receipt.step_id != request.step_id
        || receipt.invocation_id != request.invocation_id
        || receipt.invocation_digest != request.invocation_digest
        || receipt.change_digest != frozen.change_digest
        || receipt.project_id != frozen.operation.project_id
        || receipt.project_base_revision.as_str()
            != frozen.change["projectBaseRevision"].as_str().unwrap_or("")
        || receipt.project_revision.as_str()
            != frozen.change["projectAfter"]["revision"]
                .as_str()
                .unwrap_or("")
        || receipt.world_evidence.is_empty()
        || receipt.world_evidence.len() > 64
    {
        return Err(StorageError::Corrupt(
            "Projection receipt durable identity differs".into(),
        ));
    }
    let actual = read_document(
        store,
        rpc,
        "Project",
        receipt.project_id.as_str(),
        &receipt.project_revision,
    )?;
    if actual != frozen.change["projectAfter"] {
        return Err(StorageError::Corrupt(
            "Committed authored Project differs".into(),
        ));
    }
    let mut total = 0u64;
    for pin in project_pins(&actual)?.values() {
        let document = read_owned_source(
            store,
            rpc,
            &receipt.project_id,
            &receipt.project_revision,
            pin,
            &mut total,
        )?;
        if let Some(changed) = array(&frozen.change, "documentChanges")?
            .iter()
            .find(|d| d["kind"] == json!(pin.kind) && d["objectId"] == pin.object_id.as_str())
            && document != changed["after"]
        {
            return Err(StorageError::Corrupt(
                "Committed authored document differs".into(),
            ));
        }
    }
    let observation = WorldPhaseObservation {
        invocation_id: receipt.invocation_id.clone(),
        invocation_digest: receipt.invocation_digest.clone(),
        change_digest: receipt.change_digest.clone(),
        context_digest: field(&frozen.invocation, "contextDigest")?,
        scope_digest: digest(&serde_json::to_value(&frozen.operation.scope).map_err(contract)?)?,
        world_phase_complete: true,
        further_world_effects_possible: false,
        evidence: receipt.world_evidence.clone(),
    };
    if validate_world_observation(store, rpc, frozen, &observation, true)?
        != receipt.world_verification_digest
    {
        return Err(StorageError::Corrupt(
            "Projection world verification receipt differs".into(),
        ));
    }
    for raw in array(&frozen.change, "resourceReplacements")? {
        let before = validate_resource(store, &raw["before"])?;
        verify_resource_provenance(
            store,
            rpc,
            &receipt.project_id,
            &receipt.project_base_revision,
            &before,
        )?;
        let mut after = raw["replacementSource"].clone();
        after["resourceId"] = raw["targetResourceId"].clone();
        let after = validate_resource(store, &after)?;
        verify_resource_provenance(
            store,
            rpc,
            &receipt.project_id,
            &receipt.project_revision,
            &after,
        )?;
    }
    for raw in array(&frozen.change, "stagedResources")? {
        let resource = validate_resource(store, raw)?;
        if array(&actual, "resourceIds")?
            .iter()
            .any(|id| id == resource.id.as_str())
        {
            verify_resource_provenance(
                store,
                rpc,
                &receipt.project_id,
                &receipt.project_revision,
                &resource,
            )?;
        } else {
            let retained: i64 = store.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM blob_refs r JOIN blobs b ON b.digest=r.digest WHERE r.owner_kind='operation' AND r.owner_id=?1 AND r.digest=?2 AND b.byte_length=?3)",
                params![receipt.operation_id.as_str(), resource.blob.digest.as_str(), i64::try_from(resource.blob.byte_length).map_err(contract)?], |r| r.get(0),
            )?;
            if retained != 1 {
                return Err(StorageError::Corrupt(
                    "Committed operation output retention is missing".into(),
                ));
            }
            verify_blob(store, rpc, &resource.blob)?;
        }
    }
    Ok(receipt)
}

fn verify_resource_provenance(
    store: &DurableStore,
    rpc: &dyn ProjectionRpcContext,
    project: &ProjectId,
    revision: &Sha256Digest,
    resource: &StagedResource,
) -> StorageResult<()> {
    let row: Option<(String, i64, i64)> = store.connection.query_row(
        "SELECT v.resource_json,v.byte_length,b.byte_length FROM project_resource_versions v JOIN project_resource_provenance p ON p.project_id=v.project_id AND p.resource_id=v.resource_id AND p.digest=v.digest JOIN blobs b ON b.digest=v.digest WHERE v.project_id=?1 AND p.project_revision=?2 AND v.resource_id=?3 AND v.digest=?4 AND p.project_definition='Project' AND length(CAST(v.resource_json AS BLOB))<=16384",
        params![project.as_str(), revision.as_str(), resource.id.as_str(), resource.blob.digest.as_str()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).optional()?;
    let (reference, length, indexed_length) = row.ok_or(StorageError::NotFound(
        "Committed project resource provenance",
    ))?;
    if parse_json(reference.as_bytes()).map_err(contract)? != resource.reference
        || length != indexed_length
        || u64::try_from(length).ok() != Some(resource.blob.byte_length)
    {
        return Err(StorageError::Corrupt(
            "Committed resource provenance differs".into(),
        ));
    }
    verify_blob(store, rpc, &resource.blob)
}

/// Commit only the local phase inside one still-live native invocation. A
/// committed replay verifies immutable metadata and current ACL without calling
/// the observer or executing a world write. A missing receipt after restart is
/// rejected even if the caller knows an old proof or still sees the old head.
pub fn commit_authored_projection(
    store: &mut DurableStore,
    rpc: &dyn ProjectionRpcContext,
    authority: &mut dyn ProjectionAuthority,
    request: &ProjectionCommitRequest,
) -> StorageResult<ProjectionCommitResult> {
    rpc.check()?;
    let operation = store.operation(&request.operation_id)?;
    let principal = rpc.principal_for_context(&operation.context_id)?;
    if principal != operation.principal {
        return Err(StorageError::Conflict("Authenticated projection principal"));
    }
    let replay = receipt_exists(store, request)?;
    authority.authorize_operation(store, &principal, &operation, request, replay)?;
    let frozen = load_frozen(store, rpc, request, operation)?;
    let principal = check_principal(rpc, &frozen)?;
    authority.authorize_projection(store, &frozen.input(&principal), replay)?;
    if replay {
        let receipt = load_receipt(store, rpc, request, &frozen)?;
        let current_principal = check_principal(rpc, &frozen)?;
        authority.authorize_projection(store, &frozen.input(&current_principal), true)?;
        rpc.check()?;
        return Ok(ProjectionCommitResult {
            receipt,
            replayed: true,
        });
    }
    require_live(&frozen, request)?;
    let observation = authority.observe_settled_world_phase(store, &frozen.input(&principal))?;
    validate_world_observation(store, rpc, &frozen, &observation, false)?;
    guard_project_base(
        store,
        &frozen.operation.project_id,
        &field(&frozen.change, "projectBaseRevision")?,
    )?;
    let staged = stage_projection(store, rpc, &frozen)?;
    rpc.check()?;
    // The root is exclusively leased and this API holds &mut DurableStore.
    // Borrowing the connection immutably lets the read-only authority inspect
    // the actual store inside this one immediate transaction. No nesting exists.
    let transaction =
        Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate)?;
    transaction.execute_batch(PROJECTION_SCHEMA)?;
    if receipt_exists(store, request)? {
        return Err(StorageError::Conflict(
            "Projection receipt appeared during commit",
        ));
    }
    let current = store.operation(&request.operation_id)?;
    if current != frozen.operation {
        return Err(StorageError::Conflict("Live projection operation changed"));
    }
    require_live(&frozen, request)?;
    guard_project_base(store, &frozen.operation.project_id, &staged.base_revision)?;
    for resource in &staged.before_resources {
        current_resource(store, &frozen.operation.project_id, resource)?;
    }
    for resource in &staged.carried_resources {
        current_resource(store, &frozen.operation.project_id, resource)?;
    }
    let old_ids: BTreeSet<_> = staged
        .before_resources
        .iter()
        .map(|r| r.id.clone())
        .collect();
    for resource in &staged.after_resources {
        if !old_ids.contains(&resource.id) {
            let exists: i64 = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM project_resource_heads WHERE project_id=?1 AND resource_id=?2)",
                params![frozen.operation.project_id.as_str(), resource.id.as_str()], |r| r.get(0),
            )?;
            if exists == 1 {
                return Err(StorageError::Conflict(
                    "Staged resource would replace an existing resource head",
                ));
            }
            if staged.base_resource_ids.contains(&resource.id) {
                // A staged output cannot silently replace an existing identity.
                // The explicit replacement path is the only changing path.
                current_resource(store, &frozen.operation.project_id, resource)?;
            }
        }
        verify_blob(store, rpc, &resource.blob)?;
    }
    for document in &staged.documents {
        verify_blob(store, rpc, &document.blob)?;
    }
    verify_blob(store, rpc, &staged.project_blob)?;
    insert_document(
        &transaction,
        "Project",
        frozen.operation.project_id.as_str(),
        &staged.after_revision,
        &staged.project_blob,
    )?;
    for document in &staged.documents {
        insert_owned_document(
            &transaction,
            &frozen.operation.project_id,
            &staged.after_revision,
            document,
        )?;
    }
    for pin in &staged.carried_documents {
        insert_owned_provenance(
            &transaction,
            &frozen.operation.project_id,
            &staged.after_revision,
            pin,
        )?;
    }
    for resource in &staged.before_resources {
        insert_resource_version(&transaction, &frozen.operation.project_id, resource)?;
        insert_resource_provenance(
            &transaction,
            &frozen.operation.project_id,
            &staged.base_revision,
            resource,
        )?;
    }
    for resource in staged
        .after_resources
        .iter()
        .chain(&staged.carried_resources)
    {
        if array(&staged.project, "resourceIds")?
            .iter()
            .any(|id| id == resource.id.as_str())
        {
            insert_resource_version(&transaction, &frozen.operation.project_id, resource)?;
            insert_resource_provenance(
                &transaction,
                &frozen.operation.project_id,
                &staged.after_revision,
                resource,
            )?;
            set_resource_head(&transaction, &frozen.operation.project_id, resource)?;
        }
        pin_blob(
            &transaction,
            "operation",
            request.operation_id.as_str(),
            &resource.blob,
        )?;
    }
    for resource in &staged.source_resources {
        pin_blob(
            &transaction,
            "operation",
            request.operation_id.as_str(),
            &resource.blob,
        )?;
    }
    if transaction.execute(
        "UPDATE project_heads SET revision=?2,blob_digest=?3 WHERE project_id=?1 AND revision=?4",
        params![
            frozen.operation.project_id.as_str(),
            staged.after_revision.as_str(),
            staged.project_blob.digest.as_str(),
            staged.base_revision.as_str()
        ],
    )? != 1
    {
        return Err(StorageError::Conflict(
            "Project head changed during projection commit",
        ));
    }
    let principal = check_principal(rpc, &frozen)?;
    authority.authorize_projection(store, &frozen.input(&principal), false)?;
    let final_observation =
        authority.observe_settled_world_phase(store, &frozen.input(&principal))?;
    let proof_digest = validate_world_observation(store, rpc, &frozen, &final_observation, false)?;
    if store.operation(&request.operation_id)? != frozen.operation {
        return Err(StorageError::Conflict(
            "Operation changed during projection verification",
        ));
    }
    let receipt = ProjectionReceipt {
        operation_id: request.operation_id.clone(),
        step_id: request.step_id.clone(),
        invocation_id: request.invocation_id.clone(),
        invocation_digest: request.invocation_digest.clone(),
        change_digest: frozen.change_digest.clone(),
        project_id: frozen.operation.project_id.clone(),
        project_base_revision: staged.base_revision.clone(),
        project_revision: staged.after_revision.clone(),
        world_verification_digest: proof_digest,
        world_evidence: final_observation.evidence,
    };
    let receipt_json = encode(&receipt)?;
    let receipt_blob = store.cas.put(receipt_json.as_bytes())?;
    verify_blob(store, rpc, &receipt_blob)?;
    pin_blob(
        &transaction,
        "operation",
        request.operation_id.as_str(),
        &receipt_blob,
    )?;
    for evidence in &observation.evidence {
        pin_blob(
            &transaction,
            "operation",
            request.operation_id.as_str(),
            evidence,
        )?;
    }
    for evidence in &receipt.world_evidence {
        pin_blob(
            &transaction,
            "operation",
            request.operation_id.as_str(),
            evidence,
        )?;
    }
    transaction.execute(
        "INSERT INTO authored_projection_commits(operation_id,step_id,invocation_id,invocation_digest,change_digest,receipt_json,receipt_digest) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![request.operation_id.as_str(), request.step_id.as_str(), request.invocation_id.as_str(), request.invocation_digest.as_str(), frozen.change_digest.as_str(), receipt_json, receipt_blob.digest.as_str()],
    )?;
    // Preserve the actual aggregate dispatch/effect/fence state. The composite
    // provider/application completes its own independent final observation.
    transaction.execute(
        "INSERT INTO events(operation_id,kind,record_json) VALUES(?1,'authored_projection_committed',?2)",
        params![request.operation_id.as_str(), encode(&frozen.operation)?],
    )?;
    let principal = check_principal(rpc, &frozen)?;
    authority.authorize_projection(store, &frozen.input(&principal), false)?;
    if store.operation(&request.operation_id)? != frozen.operation {
        return Err(StorageError::Conflict(
            "Operation changed before projection commit",
        ));
    }
    check_principal(rpc, &frozen)?;
    transaction.commit()?;
    Ok(ProjectionCommitResult {
        receipt,
        replayed: false,
    })
}

#[cfg(test)]
#[path = "authored_projection_tests.rs"]
mod tests;

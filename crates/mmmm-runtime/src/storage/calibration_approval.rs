//! Private native-owner selection and actual ADMIN confirmation for the finite
//! numeric calibration run. These facts share the existing SQLite/CAS and the
//! original operation journal; they are not a new operation ledger or a grant
//! that can be reconstructed from imported JSON or a claimed host boolean.

use super::bootstrap::registered_native_project_owner;
use super::journal::{decode, encode, pin_blob};
use super::{BlobRef, DurableStore, OperationRecord, StepRecord, StorageError, StorageResult};
use mmmm_contracts::{
    OperationId, PlanId, PrincipalId, ProjectId, Sha256Digest, StepId, canonical_digest, raw_digest,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CALIBRATION_PURPOSE: &str = "numeric_calibration_normative47/1";
pub const MAX_CALIBRATION_RECIPE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 65_536;
const MAX_CONFIRMATION_BYTES: usize = 8192;
const MAX_APPROVALS: i64 = 4096;
const MAX_PROJECT_APPROVALS: i64 = 128;
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS calibration_selections (
 approval_ref TEXT PRIMARY KEY CHECK(length(approval_ref) BETWEEN 1 AND 256),
 native_owner TEXT NOT NULL,
 project_id TEXT NOT NULL REFERENCES native_project_owners(project_id),
 plan_id TEXT NOT NULL, plan_hash TEXT NOT NULL CHECK(length(plan_hash)=64),
 selection_digest TEXT NOT NULL CHECK(length(selection_digest)=64),
 record_json TEXT NOT NULL CHECK(length(CAST(record_json AS BLOB))<=65536),
 UNIQUE(project_id,plan_id,plan_hash)
) STRICT;
CREATE TABLE IF NOT EXISTS calibration_approvals (
 approval_ref TEXT PRIMARY KEY REFERENCES calibration_selections(approval_ref),
 approval_digest TEXT NOT NULL CHECK(length(approval_digest)=64),
 record_json TEXT NOT NULL CHECK(length(CAST(record_json AS BLOB))<=8192)
) STRICT;
CREATE TABLE IF NOT EXISTS calibration_operation_claims (
 approval_ref TEXT PRIMARY KEY REFERENCES calibration_approvals(approval_ref),
 operation_id TEXT NOT NULL UNIQUE REFERENCES operations(operation_id)
) STRICT;
CREATE TABLE IF NOT EXISTS calibration_step_claims (
 approval_ref TEXT NOT NULL REFERENCES calibration_operation_claims(approval_ref),
 step_id TEXT NOT NULL, operation_id TEXT NOT NULL REFERENCES operations(operation_id),
 invocation_id TEXT NOT NULL UNIQUE REFERENCES invocations(invocation_id),
 invocation_digest TEXT NOT NULL CHECK(length(invocation_digest)=64),
 PRIMARY KEY(approval_ref,step_id)
) STRICT;";

/// Pins supplied by trusted composition, never an owner or an ADMIN claim.
/// There is no public JSON deserializer for this request or either record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CalibrationSelectionRequest {
    pub approval_ref: String,
    pub project_id: ProjectId,
    pub project_base_revision: Sha256Digest,
    pub plan_id: PlanId,
    pub plan_hash: Sha256Digest,
    pub policy_revision: Sha256Digest,
    /// Actual permanent Policy semantic digest, distinct from the session
    /// grant revision retained in ExecutionPlan.policyRevision.
    pub policy_digest: Sha256Digest,
    pub suite_digest: Sha256Digest,
    pub recipe: BlobRef,
    pub host_artifact_digest: Sha256Digest,
    pub scope_digest: Sha256Digest,
    pub context_pins: Value,
    pub expires_at: String,
}
#[derive(Serialize, Deserialize)]
#[serde(
    remote = "CalibrationSelectionRequest",
    rename_all = "camelCase",
    deny_unknown_fields
)]
struct SelectionCodec {
    approval_ref: String,
    project_id: ProjectId,
    project_base_revision: Sha256Digest,
    plan_id: PlanId,
    plan_hash: Sha256Digest,
    policy_revision: Sha256Digest,
    policy_digest: Sha256Digest,
    suite_digest: Sha256Digest,
    recipe: BlobRef,
    host_artifact_digest: Sha256Digest,
    scope_digest: Sha256Digest,
    context_pins: Value,
    expires_at: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredSelection {
    format: String,
    purpose: String,
    native_owner: PrincipalId,
    #[serde(with = "SelectionCodec")]
    pins: CalibrationSelectionRequest,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CalibrationSelectionRecord {
    stored: StoredSelection,
    selection_digest: Sha256Digest,
}
impl CalibrationSelectionRecord {
    pub fn approval_ref(&self) -> &str {
        &self.stored.pins.approval_ref
    }
    pub fn native_owner(&self) -> &PrincipalId {
        &self.stored.native_owner
    }
    pub fn selection_digest(&self) -> &Sha256Digest {
        &self.selection_digest
    }
    pub fn purpose(&self) -> &str {
        &self.stored.purpose
    }
    pub fn pins(&self) -> &CalibrationSelectionRequest {
        &self.stored.pins
    }
}

/// Factual inputs from the original completed bootstrap. A request alone is
/// untrusted until authorize_confirmation verifies actual ACK/EOF completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CalibrationConfirmationRequest {
    pub selection_digest: Sha256Digest,
    pub principal_id: PrincipalId,
    pub player_id: String,
    pub original_offer_digest: Sha256Digest,
    pub nonce: String,
    pub host_epoch: String,
    pub registry_generation: String,
    pub runtime_source_facts_digest: Sha256Digest,
    pub manifest_digest: Sha256Digest,
}
#[derive(Serialize, Deserialize)]
#[serde(
    remote = "CalibrationConfirmationRequest",
    rename_all = "camelCase",
    deny_unknown_fields
)]
struct ConfirmationCodec {
    selection_digest: Sha256Digest,
    principal_id: PrincipalId,
    player_id: String,
    original_offer_digest: Sha256Digest,
    nonce: String,
    host_epoch: String,
    registry_generation: String,
    runtime_source_facts_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredConfirmation {
    format: String,
    #[serde(with = "ConfirmationCodec")]
    facts: CalibrationConfirmationRequest,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CalibrationApprovalRecord {
    selection: CalibrationSelectionRecord,
    stored: StoredConfirmation,
    approval_digest: Sha256Digest,
}
impl CalibrationApprovalRecord {
    pub fn selection(&self) -> &CalibrationSelectionRecord {
        &self.selection
    }
    pub fn confirmation(&self) -> &CalibrationConfirmationRequest {
        &self.stored.facts
    }
    pub fn approval_digest(&self) -> &Sha256Digest {
        &self.approval_digest
    }
}

/// Implement with the actual same-store NativeOwnerWitness and original
/// request. check_current_approval is local-only, including original expiry,
/// cancellation and the current completed pairing/ADMIN/source witness. It
/// must never do host/provider I/O inside the operation writer transaction.
pub trait CalibrationApprovalRpcContext {
    fn check(&self) -> StorageResult<()>;
    fn authenticated_local_owner(&self) -> StorageResult<PrincipalId>;
    fn check_current_approval(
        &self,
        store: &DurableStore,
        approval: &CalibrationApprovalRecord,
    ) -> StorageResult<()>;
}
/// No permissive defaults. Selection verifies explicit native-owner choice,
/// current Project/Policy rights, the sealed normative47 compiler recipe and
/// its exact ordered commands. Confirmation additionally requires the actual
/// ADMIN completed-bootstrap receipt and exact offered manifest/source facts.
/// Dispatch verifies fresh current source/ADMIN rights before the writer tx.
pub trait CalibrationApprovalAuthority {
    fn authorize_selection(
        &mut self,
        store: &DurableStore,
        owner: &PrincipalId,
        request: &CalibrationSelectionRequest,
    ) -> StorageResult<()>;
    fn authorize_confirmation(
        &mut self,
        store: &DurableStore,
        selection: &CalibrationSelectionRecord,
        confirmation: &CalibrationConfirmationRequest,
    ) -> StorageResult<()>;
    fn authorize_dispatch(
        &mut self,
        store: &DurableStore,
        approval: &CalibrationApprovalRecord,
        invocation: &Value,
    ) -> StorageResult<()>;
}

fn contract(error: impl std::fmt::Display) -> StorageError {
    StorageError::Contract(error.to_string())
}
fn conflict(message: &'static str) -> StorageError {
    StorageError::Conflict(message)
}
fn bounded_ref(value: &str) -> StorageResult<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        return Err(StorageError::InvalidInput(
            "Calibration identifier is invalid".into(),
        ));
    }
    Ok(())
}
fn digest<T: Serialize>(value: &T) -> StorageResult<Sha256Digest> {
    canonical_digest(&serde_json::to_value(value).map_err(contract)?).map_err(contract)
}
pub(crate) fn checked_after<T>(
    result: StorageResult<T>,
    checkpoint: StorageResult<()>,
) -> StorageResult<T> {
    match (result, checkpoint) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Err(checkpoint)) => Err(StorageError::CalibrationCheckpointFailure {
            primary: Box::new(primary),
            checkpoint: Box::new(checkpoint),
        }),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(checkpoint)) => Err(checkpoint),
    }
}
fn finish_request<T>(
    result: StorageResult<T>,
    rpc: &dyn CalibrationApprovalRpcContext,
) -> StorageResult<T> {
    // Bound this wrapper to one retained checkpoint pair. Successful commits
    // have no fallible delivery/check after them; already paired failures keep
    // both original causes instead of accumulating repeated cancellation copies.
    if result.is_err()
        && !matches!(
            &result,
            Err(StorageError::CalibrationCheckpointFailure { .. })
        )
    {
        checked_after(result, rpc.check())
    } else {
        result
    }
}
fn owner(
    store: &DurableStore,
    rpc: &dyn CalibrationApprovalRpcContext,
    project: &ProjectId,
    expected: Option<&PrincipalId>,
) -> StorageResult<PrincipalId> {
    rpc.check()?;
    let actual = rpc.authenticated_local_owner()?;
    if expected.is_some_and(|expected| expected != &actual)
        || registered_native_project_owner(store, project)? != actual
    {
        return Err(conflict("Calibration native owner changed"));
    }
    rpc.check()?;
    Ok(actual)
}
fn verify_selection(
    store: &DurableStore,
    rpc: &dyn CalibrationApprovalRpcContext,
    request: &CalibrationSelectionRequest,
) -> StorageResult<Value> {
    bounded_ref(&request.approval_ref)?;
    rpc.check()?;
    let head: Option<String> = store
        .connection
        .query_row(
            "SELECT revision FROM project_heads WHERE project_id=?1",
            [request.project_id.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    if head.as_deref() != Some(request.project_base_revision.as_str()) {
        return Err(conflict("Calibration current Project revision"));
    }
    let plan = store.plan(&request.plan_id, &request.plan_hash)?;
    store
        .validator
        .validate("ExecutionPlan", &plan)
        .map_err(contract)?;
    if plan["projectId"] != request.project_id.as_str()
        || plan["projectBaseRevision"] != request.project_base_revision.as_str()
        || plan["policyRevision"] != request.policy_revision.as_str()
        || plan["expiresAt"] != request.expires_at
        || plan["contextPins"] != request.context_pins
        || canonical_digest(&plan["scope"]).map_err(contract)? != request.scope_digest
    {
        return Err(conflict("Calibration frozen plan pins"));
    }
    let pins = request
        .context_pins
        .as_array()
        .filter(|p| p.len() == 1)
        .ok_or_else(|| conflict("Calibration exact context pin"))?;
    if pins[0]["contextId"] != plan["contextId"]
        || pins[0]["environment"]["side"] != "server"
        || pins[0]["environment"]["kind"] != "game"
    {
        return Err(conflict("Calibration actual server world context"));
    }
    let steps = plan["steps"]
        .as_array()
        .filter(|steps| steps.len() == 47)
        .ok_or_else(|| conflict("Calibration requires exactly 47 original steps"))?;
    for step in steps {
        rpc.check()?;
        if step["actionId"] != "mmmm:command_execute"
            || step["effect"] == "read"
            || step["recovery"] != "none"
            || step["contextId"] != plan["contextId"]
            || !step["resultBindings"]
                .as_array()
                .is_some_and(|v| v.is_empty())
            || !step["arguments"]
                .as_object()
                .is_some_and(|a| a.len() == 1 && a.get("command").is_some_and(Value::is_string))
        {
            return Err(conflict("Calibration original command step shape"));
        }
    }
    if request.recipe.byte_length == 0
        || request.recipe.byte_length > MAX_CALIBRATION_RECIPE_BYTES
        || request.recipe.digest != request.suite_digest
    {
        return Err(conflict("Calibration exact normative recipe pin"));
    }
    store.read_blob_checked(&request.recipe, MAX_CALIBRATION_RECIPE_BYTES, || {
        rpc.check()
    })?;
    rpc.check()?;
    Ok(plan)
}
fn selection_inner(
    store: &DurableStore,
    approval_ref: &str,
) -> StorageResult<Option<CalibrationSelectionRecord>> {
    bounded_ref(approval_ref)?;
    if !table_exists(&store.connection, "calibration_selections")? {
        return Ok(None);
    }
    let row: Option<(String, String, String, String, String, Vec<u8>)> = store.connection.query_row("SELECT native_owner,project_id,plan_id,plan_hash,selection_digest,substr(CAST(record_json AS BLOB),1,65537) FROM calibration_selections WHERE approval_ref=?1", [approval_ref], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
    let Some((native_owner, project, plan, plan_hash, expected, bytes)) = row else {
        return Ok(None);
    };
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(StorageError::Corrupt(
            "Calibration selection byte budget".into(),
        ));
    }
    let stored: StoredSelection = decode(std::str::from_utf8(&bytes).map_err(contract)?)?;
    let selection_digest = digest(&stored)?;
    if stored.format != "mmmm.calibration-selection/1"
        || stored.purpose != CALIBRATION_PURPOSE
        || stored.pins.approval_ref != approval_ref
        || selection_digest.as_str() != expected
        || stored.native_owner.as_str() != native_owner
        || stored.pins.project_id.as_str() != project
        || stored.pins.plan_id.as_str() != plan
        || stored.pins.plan_hash.as_str() != plan_hash
    {
        return Err(StorageError::Corrupt(
            "Calibration immutable selection differs".into(),
        ));
    }
    Ok(Some(CalibrationSelectionRecord {
        stored,
        selection_digest,
    }))
}
fn approval_inner(
    store: &DurableStore,
    approval_ref: &str,
) -> StorageResult<Option<CalibrationApprovalRecord>> {
    let Some(selection) = selection_inner(store, approval_ref)? else {
        return Ok(None);
    };
    let row: Option<(String, Vec<u8>)> = store.connection.query_row("SELECT approval_digest,substr(CAST(record_json AS BLOB),1,8193) FROM calibration_approvals WHERE approval_ref=?1", [approval_ref], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((expected, bytes)) = row else {
        return Ok(None);
    };
    if bytes.len() > MAX_CONFIRMATION_BYTES {
        return Err(StorageError::Corrupt(
            "Calibration confirmation byte budget".into(),
        ));
    }
    let stored: StoredConfirmation = decode(std::str::from_utf8(&bytes).map_err(contract)?)?;
    let approval_digest = digest(&stored)?;
    verify_confirmation(&selection, &stored.facts)?;
    if stored.format != "mmmm.calibration-confirmation/1" || approval_digest.as_str() != expected {
        return Err(StorageError::Corrupt(
            "Calibration immutable confirmation differs".into(),
        ));
    }
    Ok(Some(CalibrationApprovalRecord {
        selection,
        stored,
        approval_digest,
    }))
}
fn verify_confirmation(
    selection: &CalibrationSelectionRecord,
    confirmation: &CalibrationConfirmationRequest,
) -> StorageResult<()> {
    bounded_ref(&confirmation.player_id)?;
    bounded_ref(&confirmation.nonce)?;
    bounded_ref(&confirmation.host_epoch)?;
    let generation = &confirmation.registry_generation;
    if generation.is_empty()
        || generation.len() > 19
        || generation.starts_with('0')
        || !generation.bytes().all(|b| b.is_ascii_digit())
        || generation
            .parse::<u64>()
            .ok()
            .is_none_or(|n| n > i64::MAX as u64)
    {
        return Err(conflict("Calibration actual Java registry generation"));
    }
    if confirmation.selection_digest != *selection.selection_digest()
        || selection.pins().context_pins[0]["environment"]["sessionEpoch"]
            != confirmation.host_epoch
    {
        return Err(conflict("Calibration original confirmation identity"));
    }
    Ok(())
}
fn table_exists(connection: &rusqlite::Connection, table: &str) -> StorageResult<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [table],
        |r| r.get(0),
    )?)
}

pub fn register_calibration_selection(
    store: &mut DurableStore,
    rpc: &dyn CalibrationApprovalRpcContext,
    authority: &mut dyn CalibrationApprovalAuthority,
    request: &CalibrationSelectionRequest,
) -> StorageResult<CalibrationSelectionRecord> {
    let outcome = (|| {
        let native_owner = owner(store, rpc, &request.project_id, None)?;
        let precheck = (|| {
            verify_selection(store, rpc, request)?;
            authority.authorize_selection(store, &native_owner, request)
        })();
        checked_after(precheck, rpc.check())?;
        let stored = StoredSelection {
            format: "mmmm.calibration-selection/1".into(),
            purpose: CALIBRATION_PURPOSE.into(),
            native_owner: native_owner.clone(),
            pins: request.clone(),
        };
        let record = CalibrationSelectionRecord {
            selection_digest: digest(&stored)?,
            stored,
        };
        let encoded = encode(&record.stored)?;
        if encoded.len() > MAX_RECORD_BYTES {
            return Err(StorageError::InvalidInput(
                "Calibration selection byte budget".into(),
            ));
        }
        let result = (|| {
            let transaction =
                Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate)?;
            transaction.execute_batch(SCHEMA)?;
            if let Some(old) = selection_inner(store, &request.approval_ref)? {
                if old != record {
                    return Err(conflict("Immutable calibration owner selection"));
                }
            } else {
                let total: i64 = transaction.query_row(
                    "SELECT count(*) FROM (SELECT 1 FROM calibration_selections LIMIT 4097)",
                    [],
                    |r| r.get(0),
                )?;
                let project_count: i64 = transaction.query_row("SELECT count(*) FROM (SELECT 1 FROM calibration_selections WHERE project_id=?1 LIMIT 129)", [request.project_id.as_str()], |r| r.get(0))?;
                if total >= MAX_APPROVALS || project_count >= MAX_PROJECT_APPROVALS {
                    return Err(StorageError::InvalidInput(
                        "Calibration selection capacity".into(),
                    ));
                }
                transaction.execute("INSERT INTO calibration_selections(approval_ref,native_owner,project_id,plan_id,plan_hash,selection_digest,record_json) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![request.approval_ref,native_owner.as_str(),request.project_id.as_str(),request.plan_id.as_str(),request.plan_hash.as_str(),record.selection_digest.as_str(),encoded])?;
                pin_blob(
                    &transaction,
                    "calibration_selection",
                    &request.approval_ref,
                    &request.recipe,
                )?;
            }
            owner(store, rpc, &request.project_id, Some(&native_owner))?;
            verify_selection(store, rpc, request)?;
            // The second selection check is local/current rights only; this port
            // must not acquire new host/provider facts while the writer is open.
            authority.authorize_selection(store, &native_owner, request)?;
            owner(store, rpc, &request.project_id, Some(&native_owner))?;
            if selection_inner(store, &request.approval_ref)?.as_ref() != Some(&record) {
                return Err(conflict("Calibration selection changed before commit"));
            }
            rpc.check()?;
            transaction.commit()?;
            Ok(record)
        })();
        // A successful commit is returned directly: later delivery/cancellation
        // cannot turn it into a claimed rollback or authorize a fresh selection.
        result
    })();
    finish_request(outcome, rpc)
}

pub fn calibration_selection(
    store: &DurableStore,
    rpc: &dyn CalibrationApprovalRpcContext,
    authority: &mut dyn CalibrationApprovalAuthority,
    project: &ProjectId,
    approval_ref: &str,
) -> StorageResult<Option<CalibrationSelectionRecord>> {
    let outcome = (|| {
        let native_owner = owner(store, rpc, project, None)?;
        let record = selection_inner(store, approval_ref)?;
        if let Some(record) = &record {
            if record.native_owner() != &native_owner || &record.pins().project_id != project {
                return Err(conflict("Calibration selection owner/project"));
            }
            let result = (|| {
                verify_selection(store, rpc, record.pins())?;
                authority.authorize_selection(store, &native_owner, record.pins())
            })();
            checked_after(result, rpc.check())?;
        }
        owner(store, rpc, project, Some(&native_owner))?;
        Ok(record)
    })();
    finish_request(outcome, rpc)
}

pub fn confirm_calibration_approval(
    store: &mut DurableStore,
    rpc: &dyn CalibrationApprovalRpcContext,
    authority: &mut dyn CalibrationApprovalAuthority,
    selection: &CalibrationSelectionRecord,
    confirmation: &CalibrationConfirmationRequest,
) -> StorageResult<CalibrationApprovalRecord> {
    let outcome = (|| {
        let native_owner = owner(
            store,
            rpc,
            &selection.pins().project_id,
            Some(selection.native_owner()),
        )?;
        let precheck = (|| {
            if selection_inner(store, selection.approval_ref())?.as_ref() != Some(selection) {
                return Err(conflict("Calibration actual retained selection"));
            }
            verify_selection(store, rpc, selection.pins())?;
            verify_confirmation(selection, confirmation)?;
            authority.authorize_confirmation(store, selection, confirmation)
        })();
        checked_after(precheck, rpc.check())?;
        let stored = StoredConfirmation {
            format: "mmmm.calibration-confirmation/1".into(),
            facts: confirmation.clone(),
        };
        let record = CalibrationApprovalRecord {
            selection: selection.clone(),
            approval_digest: digest(&stored)?,
            stored,
        };
        let encoded = encode(&record.stored)?;
        if encoded.len() > MAX_CONFIRMATION_BYTES {
            return Err(StorageError::InvalidInput(
                "Calibration confirmation byte budget".into(),
            ));
        }
        (|| {
            let transaction =
                Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate)?;
            if let Some(old) = approval_inner(store, selection.approval_ref())? {
                if old != record {
                    return Err(conflict("Immutable calibration ADMIN confirmation"));
                }
            } else {
                transaction.execute("INSERT INTO calibration_approvals(approval_ref,approval_digest,record_json) VALUES(?1,?2,?3)", params![selection.approval_ref(),record.approval_digest.as_str(),encoded])?;
            }
            owner(
                store,
                rpc,
                &selection.pins().project_id,
                Some(&native_owner),
            )?;
            verify_selection(store, rpc, selection.pins())?;
            rpc.check_current_approval(store, &record)?;
            owner(
                store,
                rpc,
                &selection.pins().project_id,
                Some(&native_owner),
            )?;
            if approval_inner(store, selection.approval_ref())?.as_ref() != Some(&record) {
                return Err(conflict("Calibration confirmation changed before commit"));
            }
            rpc.check()?;
            transaction.commit()?;
            Ok(record)
        })()
    })();
    finish_request(outcome, rpc)
}

pub fn calibration_approval(
    store: &DurableStore,
    rpc: &dyn CalibrationApprovalRpcContext,
    project: &ProjectId,
    approval_ref: &str,
) -> StorageResult<Option<CalibrationApprovalRecord>> {
    let outcome = (|| {
        let native_owner = owner(store, rpc, project, None)?;
        let record = approval_inner(store, approval_ref)?;
        if let Some(record) = &record {
            if record.selection().native_owner() != &native_owner
                || &record.selection().pins().project_id != project
            {
                return Err(conflict("Calibration confirmed owner/project"));
            }
            verify_selection(store, rpc, record.selection().pins())?;
            checked_after(rpc.check_current_approval(store, record), rpc.check())?;
        }
        owner(store, rpc, project, Some(&native_owner))?;
        Ok(record)
    })();
    finish_request(outcome, rpc)
}

pub struct CalibrationDispatchRequest<'a> {
    pub approval_ref: &'a str,
    pub operation_id: &'a OperationId,
    pub step_id: &'a StepId,
    pub invocation: &'a Value,
}
pub(crate) struct CalibrationIntentAuthorization<'a> {
    rpc: &'a dyn CalibrationApprovalRpcContext,
    approval: CalibrationApprovalRecord,
    invocation_digest: Sha256Digest,
}
pub fn dispatch_calibration_intent(
    store: &mut DurableStore,
    rpc: &dyn CalibrationApprovalRpcContext,
    authority: &mut dyn CalibrationApprovalAuthority,
    request: &CalibrationDispatchRequest<'_>,
) -> StorageResult<StepRecord> {
    let outcome = (|| {
        let operation = store.operation(request.operation_id)?;
        let approval =
            calibration_approval(store, rpc, &operation.project_id, request.approval_ref)?
                .ok_or(StorageError::NotFound("Confirmed calibration approval"))?;
        let result = authority.authorize_dispatch(store, &approval, request.invocation);
        checked_after(result, rpc.check_current_approval(store, &approval))?;
        let invocation_digest =
            raw_digest(&mmmm_contracts::encode_json(request.invocation).map_err(contract)?);
        let authorization = CalibrationIntentAuthorization {
            rpc,
            approval,
            invocation_digest,
        };
        store.dispatch_intent_authorized(
            request.operation_id,
            request.step_id,
            request.invocation,
            None,
            None,
            Some(authorization),
        )
    })();
    finish_request(outcome, rpc)
}

pub(crate) fn reject_unclaimed_plan(
    transaction: &Transaction<'_>,
    operation: &OperationRecord,
) -> StorageResult<()> {
    if !table_exists(transaction, "calibration_selections")? {
        return Ok(());
    }
    let selected: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM calibration_selections WHERE project_id=?1 AND plan_id=?2 AND plan_hash=?3)", params![operation.project_id.as_str(),operation.plan_id.as_str(),operation.plan_hash.as_str()], |r| r.get(0))?;
    if selected {
        return Err(conflict(
            "Calibration plan requires its protected approval claim",
        ));
    }
    Ok(())
}
pub(crate) fn claim_in(
    transaction: &Transaction<'_>,
    store: &DurableStore,
    operation: &OperationRecord,
    plan: &Value,
    step_id: &StepId,
    invocation: &Value,
    authorization: &CalibrationIntentAuthorization<'_>,
) -> StorageResult<()> {
    let approval = &authorization.approval;
    let selection = approval.selection();
    let pins = selection.pins();
    owner(
        store,
        authorization.rpc,
        &pins.project_id,
        Some(selection.native_owner()),
    )?;
    authorization.rpc.check_current_approval(store, approval)?;
    if approval_inner(store, selection.approval_ref())?.as_ref() != Some(approval)
        || operation.principal != approval.confirmation().principal_id
        || operation.project_id != pins.project_id
        || operation.plan_id != pins.plan_id
        || operation.plan_hash != pins.plan_hash
        || canonical_digest(&serde_json::to_value(&operation.scope).map_err(contract)?)
            .map_err(contract)?
            != pins.scope_digest
        || plan["contextId"] != operation.context_id.as_str()
        || raw_digest(&mmmm_contracts::encode_json(invocation).map_err(contract)?)
            != authorization.invocation_digest
    {
        return Err(conflict("Calibration claim immutable identity"));
    }
    verify_selection(store, authorization.rpc, pins)?;
    if plan["planHash"] != pins.plan_hash.as_str() {
        return Err(conflict("Calibration claim frozen plan"));
    }
    let original_steps = plan["steps"]
        .as_array()
        .ok_or_else(|| conflict("Calibration frozen step list"))?;
    if operation.steps.len() != 47
        || operation
            .steps
            .iter()
            .zip(original_steps)
            .any(|(retained, original)| {
                !retained.write_effect || original["stepId"] != retained.step_id.as_str()
            })
    {
        return Err(conflict("Calibration original operation step identities"));
    }
    let original: Option<String> = transaction
        .query_row(
            "SELECT operation_id FROM calibration_operation_claims WHERE approval_ref=?1",
            [selection.approval_ref()],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(original) = original {
        if original != operation.operation_id.as_str() {
            return Err(conflict(
                "Calibration approval already belongs to another operation",
            ));
        }
    } else {
        if operation
            .steps
            .iter()
            .any(|s| &s.step_id != step_id && s.dispatch != super::DispatchEvidence::NotSent)
        {
            return Err(conflict(
                "Calibration approval must be fixed at first durable intent",
            ));
        }
        transaction.execute(
            "INSERT INTO calibration_operation_claims(approval_ref,operation_id) VALUES(?1,?2)",
            params![selection.approval_ref(), operation.operation_id.as_str()],
        )?;
    }
    let index = operation
        .steps
        .iter()
        .position(|s| &s.step_id == step_id)
        .ok_or(StorageError::NotFound("Calibration original step"))?;
    let claims: i64 = transaction.query_row("SELECT count(*) FROM (SELECT 1 FROM calibration_step_claims WHERE approval_ref=?1 LIMIT 48)", [selection.approval_ref()], |r| r.get(0))?;
    if usize::try_from(claims).ok() != Some(index) || index >= 47 {
        return Err(conflict("Calibration original ordered one-use step"));
    }
    let invocation_id = invocation["invocationId"]
        .as_str()
        .ok_or_else(|| conflict("Calibration original invocation ID"))?;
    transaction.execute("INSERT INTO calibration_step_claims(approval_ref,step_id,operation_id,invocation_id,invocation_digest) VALUES(?1,?2,?3,?4,?5)", params![selection.approval_ref(),step_id.as_str(),operation.operation_id.as_str(),invocation_id,authorization.invocation_digest.as_str()])?;
    transaction.execute("INSERT INTO events(operation_id,kind,record_json) VALUES(?1,'calibration_claim',?2)", params![operation.operation_id.as_str(),encode(&serde_json::json!({"approvalRef":selection.approval_ref(),"selectionDigest":selection.selection_digest(),"approvalDigest":approval.approval_digest(),"stepId":step_id,"invocationId":invocation_id,"invocationDigest":authorization.invocation_digest}))?])?;
    authorization.rpc.check_current_approval(store, approval)?;
    owner(
        store,
        authorization.rpc,
        &pins.project_id,
        Some(selection.native_owner()),
    )?;
    Ok(())
}

pub(crate) fn precommit(
    store: &DurableStore,
    authorization: &CalibrationIntentAuthorization<'_>,
) -> StorageResult<()> {
    authorization
        .rpc
        .check_current_approval(store, &authorization.approval)?;
    let selection = authorization.approval.selection();
    owner(
        store,
        authorization.rpc,
        &selection.pins().project_id,
        Some(selection.native_owner()),
    )?;
    if approval_inner(store, selection.approval_ref())?.as_ref() != Some(&authorization.approval) {
        return Err(conflict(
            "Calibration approval changed before intent commit",
        ));
    }
    authorization.rpc.check()
}
pub(crate) fn failure_checkpoint(
    store: &DurableStore,
    authorization: &CalibrationIntentAuthorization<'_>,
) -> StorageResult<()> {
    authorization
        .rpc
        .check_current_approval(store, &authorization.approval)?;
    let selection = authorization.approval.selection();
    owner(
        store,
        authorization.rpc,
        &selection.pins().project_id,
        Some(selection.native_owner()),
    )?;
    authorization.rpc.check()
}

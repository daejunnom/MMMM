//! Provider undo uses the original ledger and a separately approved new plan.
//! Receipt integrity is not issuance: only authenticated original-session host
//! inspection may supply material to the runtime's persistent undo registry.
//! This module remains unexported until the common intent hooks are integrated.

use crate::planning::{check_context, check_descriptor};
use crate::*;
use mmmm_contracts::{
    ActionId, BindingId, ContextId, InvocationId, ObjectId, OperationId, PrincipalId, Sha256Digest,
    StepId, canonical_digest, encode_json, raw_digest,
};
use mmmm_runtime::storage::undo::{
    self as durable_undo, InspectedUndoMaterial, ProviderUndoRecord, RegisteredUndoRoute,
    UndoAuthority, UndoMaterialSource, UndoRecordState, UndoRegistrationRequest, UndoRpcContext,
};
use mmmm_runtime::storage::{BlobRef, DispatchEvidence, EffectEvidence, OperationRecord};
use mmmm_runtime::storage::{DurableStore, StorageError, StorageResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const RECEIPT_BYTES: usize = 64 * 1024;
const AFTER_BYTES: usize = 128 * 1024 * 1024;
// A readback summary can associate at most64 refs: envelope + raw observation
// +62 after states. Larger target sets need separately associated chunks.
const TARGETS: usize = 62;

/// Exact closed HostRuntime undoRegistration DTO. It must originate in the
/// authenticated host's immutable source-to-undo registration, never a request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HostUndoRegistration {
    pub binding_id: BindingId,
    pub source_action_id: ActionId,
    pub source_action_digest: Sha256Digest,
    pub source_implementation_digest: Sha256Digest,
    pub undo_action_digest: Sha256Digest,
    pub undo_action: Value,
    pub provider_origin: Value,
}

/// Only references to host-private material cross this boundary. The private
/// token stays in host generation history; its JCS digest grants no authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HostUndoReceipt {
    pub contract_version: String,
    pub token_record_id: ObjectId,
    pub principal_ref: PrincipalId,
    pub session_epoch: String,
    pub game_instance_id: String,
    pub side: String,
    pub player_id: String,
    pub binding_id: BindingId,
    pub source_action_id: ActionId,
    pub source_action_digest: Sha256Digest,
    pub source_implementation_digest: Sha256Digest,
    pub source_arguments_digest: Sha256Digest,
    pub source_context_digest: Sha256Digest,
    pub source_operation_id: OperationId,
    pub source_step_id: StepId,
    pub source_invocation_id: InvocationId,
    pub undo_action_id: ActionId,
    pub source_context: Value,
    pub private_token_sha256: Sha256Digest,
    pub token_record_digest: Sha256Digest,
}

#[derive(Clone, Debug)]
pub struct InspectedHostUndoMaterial {
    pub registration: HostUndoRegistration,
    pub receipt: HostUndoReceipt,
    /// Real actor identity supplied by the authenticated host session.
    pub authenticated_player_id: String,
}

/// A trusted composition calls the real original source session. JSON supplied
/// by a facade cannot implement this port, authenticate itself or mint records.
/// Lookup must occur while the original HostRuntime.operation session is open.
pub trait UndoMaterialPort {
    fn inspect_undo_registration_with_store(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        source_step: &Value,
        current_context: &Value,
    ) -> AppResult<Option<HostUndoRegistration>>;
    fn inspect_source_undo_with_store(
        &mut self,
        store: &mmmm_runtime::storage::DurableStore,
        principal: &PrincipalId,
        original_invocation: &Value,
        current_context: &Value,
    ) -> AppResult<Option<InspectedHostUndoMaterial>>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UndoAfterTarget {
    pub target: String,
    /// Present only when actually captured independently before the source.
    pub before: Option<BlobRef>,
    pub after: BlobRef,
}

/// Compare physical execution identity, not an old permission grant. Only the
/// policy revision and its derived context digest may change for fresh approval.
pub(crate) fn check_undo_context(
    principal: &PrincipalId,
    project: &ProjectId,
    original: &Value,
    current: &Value,
) -> AppResult<()> {
    let id: ContextId = decode(&original["contextId"])?;
    check_context(principal, project, &id, original)?;
    check_context(principal, project, &id, current)?;
    let mut original = original.clone();
    let mut current = current.clone();
    for field in ["policyRevision", "contextDigest"] {
        original.as_object_mut().ok_or_else(expired)?.remove(field);
        current.as_object_mut().ok_or_else(expired)?.remove(field);
    }
    if original != current {
        return Err(expired());
    }
    Ok(())
}

/// This checks exact source identity/integrity after trusted host acquisition.
/// Runtime registration must additionally bind the original source observation
/// and summary association; passing this check alone creates no undo authority.
pub(crate) fn check_host_material(
    principal: &PrincipalId,
    source: &OperationRecord,
    invocation: &Value,
    step: &Value,
    source_descriptor: &Value,
    material: &InspectedHostUndoMaterial,
) -> AppResult<()> {
    validate("Invocation", invocation)?;
    check_descriptor(step, &invocation["context"], source_descriptor)?;
    let route = &material.registration;
    let receipt = &material.receipt;
    let stored = source
        .steps
        .iter()
        .find(|stored| stored.step_id.as_str() == invocation["stepId"].as_str().unwrap_or(""))
        .ok_or_else(expired)?;
    if principal != &source.principal
        || source.operation_id.as_str() != invocation["operationId"].as_str().unwrap_or("")
        || source_descriptor["recovery"] != "provider_undo"
        || source_descriptor["effect"] == "read"
        || stored.invocation_id.as_ref().map(InvocationId::as_str)
            != invocation["invocationId"].as_str()
        || stored.invocation_digest.as_ref()
            != Some(&raw_digest(
                &encode_json(invocation).map_err(AppError::json)?,
            ))
        || step["verificationRequirement"] != "independent_readback"
        || route.binding_id.as_str() != step["bindingId"].as_str().unwrap_or("")
        || route.source_action_id.as_str() != step["actionId"].as_str().unwrap_or("")
        || route.source_action_digest.as_str() != step["actionDigest"].as_str().unwrap_or("")
        || route.source_implementation_digest.as_str()
            != step["implementationDigest"].as_str().unwrap_or("")
    {
        return Err(expired());
    }
    validate("ActionDescriptor", &route.undo_action)?;
    if canonical_digest(&route.undo_action).map_err(AppError::digest)? != route.undo_action_digest
        || route.undo_action["effect"] == "read"
        || route.undo_action["recovery"] != "none"
        || route.undo_action["verificationRequirement"] != "independent_readback"
        || route.undo_action["actionId"] == step["actionId"]
        || !route.provider_origin.is_object()
    {
        return Err(expired());
    }
    let receipt_value = json!(receipt);
    if encode_json(&receipt_value).map_err(AppError::json)?.len() > RECEIPT_BYTES {
        return Err(AppError::new(
            "BUDGET_EXCEEDED",
            "Undo receipt exceeds its finite budget",
        ));
    }
    let mut projection = receipt_value.clone();
    projection
        .as_object_mut()
        .ok_or_else(expired)?
        .remove("tokenRecordDigest");
    if canonical_digest(&projection).map_err(AppError::digest)? != receipt.token_record_digest
        || receipt.contract_version != "0.2.0"
        || &receipt.principal_ref != principal
        || receipt.player_id != material.authenticated_player_id
        || !canonical_player_id(&receipt.player_id)
        || receipt.source_context != invocation["context"]
        || receipt.source_context["environment"]["kind"] != "game"
        || receipt.session_epoch
            != receipt.source_context["environment"]["sessionEpoch"]
                .as_str()
                .unwrap_or("")
        || receipt.game_instance_id
            != receipt.source_context["environment"]["gameInstanceId"]
                .as_str()
                .unwrap_or("")
        || receipt.side
            != receipt.source_context["environment"]["side"]
                .as_str()
                .unwrap_or("")
        || receipt.binding_id != route.binding_id
        || receipt.source_action_id != route.source_action_id
        || receipt.source_action_digest != route.source_action_digest
        || receipt.source_implementation_digest != route.source_implementation_digest
        || receipt.undo_action_id.as_str() != route.undo_action["actionId"].as_str().unwrap_or("")
        || receipt.source_operation_id != source.operation_id
        || receipt.source_step_id.as_str() != invocation["stepId"].as_str().unwrap_or("")
        || receipt.source_invocation_id.as_str()
            != invocation["invocationId"].as_str().unwrap_or("")
        || receipt.source_arguments_digest.as_str()
            != invocation["argumentsDigest"].as_str().unwrap_or("")
        || receipt.source_context_digest.as_str()
            != invocation["contextDigest"].as_str().unwrap_or("")
    {
        return Err(expired());
    }
    Ok(())
}

impl Application<'_> {
    /// Retain a trusted host receipt as Pending immediately after source return
    /// or polling, before independent settlement and original-session closure.
    /// The RPC context is supplied by the real authenticated Service request;
    /// a PrincipalId or old Invocation is never wrapped into a new RPC grant.
    pub(crate) fn capture_provider_undo_record(
        &mut self,
        principal: &PrincipalId,
        rpc: &dyn UndoRpcContext,
        host: &mut dyn UndoMaterialPort,
        operation: &OperationId,
        step_id: &StepId,
    ) -> AppResult<Option<ProviderUndoRecord>> {
        check_rpc(rpc, principal)?;
        let source = self
            .store
            .operation(operation)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
        self.authority
            .authorize_operation(principal, &source, Access::ObserveOperation)?;
        let original = self
            .store
            .plan(&source.plan_id, &source.plan_hash)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
        let step = original["steps"]
            .as_array()
            .and_then(|steps| steps.iter().find(|step| step["stepId"] == step_id.as_str()))
            .ok_or_else(expired)?
            .clone();
        if step["recovery"] != "provider_undo" {
            return Ok(None);
        }
        let invocation = self
            .store
            .stored_invocation(operation, step_id)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
        let current = rpc
            .current_context()
            .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?;
        check_undo_context(
            principal,
            &source.project_id,
            &invocation["context"],
            &current,
        )?;
        let descriptor = self.provider.action_descriptor(&step, &current)?;
        check_descriptor(&step, &current, &descriptor)?;
        let registration = host
            .inspect_undo_registration_with_store(self.store, principal, &step, &current)?
            .ok_or_else(expired)?;
        let route = registered_route(&step, &descriptor, &registration)?;
        let route_digest = durable_undo::register_undo_route(self.store, &route)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
        let stored = source
            .steps
            .iter()
            .find(|stored| &stored.step_id == step_id)
            .ok_or_else(expired)?;
        let request = UndoRegistrationRequest {
            source_operation_id: operation.clone(),
            source_step_id: step_id.clone(),
            source_invocation_id: stored.invocation_id.clone().ok_or_else(expired)?,
            source_invocation_digest: stored.invocation_digest.clone().ok_or_else(expired)?,
            route_digest,
        };
        let failures = CallbackFailures::default();
        let mut material = CheckedMaterialSource {
            failures: failures.clone(),
            host,
            principal,
            step,
            descriptor,
        };
        let mut authority = AppUndoAuthority {
            failures: failures.clone(),
            authority: self.authority,
            observer: self.observer,
            principal,
            read_access: Access::ObserveOperation,
        };
        durable_undo::register_undo_record(self.store, rpc, &mut authority, &mut material, &request)
            .map(Some)
            .map_err(|error| failures.release(error))
    }

    /// FN15 provider_undo enters the same freeze/apply algorithm. Reading a
    /// Pending row cannot promote it from a receipt or ProviderResult alone.
    pub(crate) fn provider_undo_plan(
        &mut self,
        principal: &PrincipalId,
        input: &Value,
        rpc: &dyn UndoRpcContext,
    ) -> AppResult<Value> {
        validate("RecoveryRequest", input)?;
        if input["mode"] != "provider_undo" {
            return Err(expired());
        }
        check_rpc(rpc, principal)?;
        let operation: OperationId = decode(&input["operationId"])?;
        let source = self.authorized_operation(
            principal,
            &json!({"operationId":operation,
            "contextId":input["contextId"]}),
            Access::Recovery,
        )?;
        if source
            .steps
            .iter()
            .filter(|step| step.write_effect && step.dispatch != DispatchEvidence::NotSent)
            .count()
            != 1
        {
            return Err(AppError::new(
                "RECOVERY_REQUIRED",
                "Provider undo requires one unambiguous settled source write",
            ));
        }
        let current = rpc
            .current_context()
            .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?;
        self.authority.authorize(
            principal,
            &source.project_id,
            Access::Recovery,
            Some(&current),
            None,
        )?;
        let ids = source_material_ids(self.store, rpc, &operation)?;
        if ids.len() != 1 {
            return Err(expired());
        }
        let record = {
            let failures = CallbackFailures::default();
            let mut authority = AppUndoAuthority {
                failures: failures.clone(),
                authority: self.authority,
                observer: self.observer,
                principal,
                read_access: Access::Recovery,
            };
            durable_undo::promote_undo_record(self.store, rpc, &mut authority, &ids[0])
                .map_err(|error| failures.release(error))?
        };
        if record.state != UndoRecordState::Available {
            return Err(expired());
        }
        check_undo_context(
            principal,
            &source.project_id,
            &record.source_context,
            &current,
        )?;
        let invocation = self
            .store
            .stored_invocation(&record.source_operation_id, &record.source_step_id)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
        let mut targets = Vec::new();
        let mut total = 0usize;
        for target in &record.after_states {
            if target.before.is_none() {
                return Err(AppError::new(
                    "RECONCILIATION_INSUFFICIENT",
                    "Undo restoration has no actual independently captured source before state",
                ));
            }
            self.observer
                .validate_capture_target(&invocation, &record.scope, &target.target)?;
            let bytes =
                self.observer
                    .read_target_with_store(self.store, &invocation, &target.target)?;
            total = total
                .checked_add(bytes.len())
                .filter(|size| *size <= AFTER_BYTES)
                .ok_or_else(|| {
                    AppError::new(
                        "BUDGET_EXCEEDED",
                        "Undo current target reads exceed their finite budget",
                    )
                })?;
            if raw_digest(&bytes) != target.after.digest
                || bytes.len() as u64 != target.after.byte_length
            {
                return Err(AppError::new(
                    "RECOVERY_CONFLICT",
                    "Undo target changed after the original independent settled observation",
                ));
            }
            targets.push(UndoAfterTarget {
                target: target.target.clone(),
                before: target.before.clone(),
                after: target.after.clone(),
            });
        }
        let route: RegisteredUndoRoute = decode(
            &mmmm_contracts::parse_json(
                &self
                    .store
                    .read_blob(&record.route_blob)
                    .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?,
            )
            .map_err(AppError::json)?,
        )?;
        let receipt: HostUndoReceipt = decode(&record.receipt)?;
        let material = InspectedHostUndoMaterial {
            registration: HostUndoRegistration {
                binding_id: route.source_binding_id,
                source_action_id: decode(&route.source_action["actionId"])?,
                source_action_digest: canonical_digest(&route.source_action)
                    .map_err(AppError::digest)?,
                source_implementation_digest: decode(&route.source_action["implementationDigest"])?,
                undo_action_digest: canonical_digest(&route.undo_action)
                    .map_err(AppError::digest)?,
                undo_action: route.undo_action,
                provider_origin: route.provider_origin,
            },
            authenticated_player_id: receipt.player_id.clone(),
            receipt,
        };
        let original = self
            .store
            .plan(&source.plan_id, &source.plan_hash)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
        let source_step = original["steps"]
            .as_array()
            .and_then(|steps| {
                steps
                    .iter()
                    .find(|step| step["stepId"] == record.source_step_id.as_str())
            })
            .ok_or_else(expired)?;
        let prepared = assemble_undo_plan(
            self.clock,
            &source,
            source_step,
            &material,
            &current,
            &targets,
        )?;
        let project = self
            .store
            .project(&source.project_id)
            .map_err(|error| AppError::storage("NOT_FOUND", error))?;
        check_rpc(rpc, principal)?;
        let fresh = rpc
            .current_context()
            .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?;
        check_undo_context(
            principal,
            &source.project_id,
            &record.source_context,
            &fresh,
        )?;
        if fresh != current {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Undo planning context changed during independent target reads",
            ));
        }
        self.authority
            .authorize_operation(principal, &source, Access::Recovery)?;
        self.freeze_plan(principal, &project, &current, prepared)
    }

    /// Select the specialized atomic intent only for a server-registered undo
    /// role. An ordinary action stays on its existing intent path; any failure
    /// in an undo role is final for this admission and grants no fallback.
    pub(crate) fn dispatch_registered_undo_intent(
        &mut self,
        principal: &PrincipalId,
        rpc: &dyn UndoRpcContext,
        operation: &OperationId,
        step_id: &StepId,
        invocation: &Value,
    ) -> AppResult<Option<mmmm_runtime::storage::StepRecord>> {
        check_rpc(rpc, principal)?;
        validate("Invocation", invocation)?;
        let binding: BindingId = decode(&invocation["bindingId"])?;
        let action: ActionId = decode(&invocation["actionId"])?;
        let action_digest: Sha256Digest = decode(&invocation["actionDigest"])?;
        if !durable_undo::is_registered_undo_action(self.store, &binding, &action, &action_digest)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?
        {
            return Ok(None);
        }
        let arguments: UndoArguments = decode(&invocation["arguments"])?;
        let source = self
            .store
            .operation(&arguments.source_operation_id)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
        self.authority
            .authorize_operation(principal, &source, Access::Recovery)?;
        let ids = source_material_ids(self.store, rpc, &arguments.source_operation_id)?;
        let failures = CallbackFailures::default();
        let mut authority = AppUndoAuthority {
            failures: failures.clone(),
            authority: self.authority,
            observer: self.observer,
            principal,
            read_access: Access::Recovery,
        };
        let mut selected = None;
        for id in ids {
            let record = durable_undo::provider_undo_record(self.store, rpc, &mut authority, &id)
                .map_err(|error| failures.release(error))?;
            let receipt: HostUndoReceipt = decode(&record.receipt)?;
            if receipt.token_record_id == arguments.token_record_id {
                if selected.is_some()
                    || receipt.token_record_digest != arguments.token_record_digest
                    || record.source_step_id != arguments.source_step_id
                    || record.source_invocation_id != arguments.source_invocation_id
                    || record.source_operation_id != arguments.source_operation_id
                {
                    return Err(expired());
                }
                selected = Some(record.record_id);
            }
        }
        let record_id = selected.ok_or_else(expired)?;
        let current = rpc
            .current_context()
            .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?;
        if current != invocation["context"] {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Undo intent differs from the actual approved request context",
            ));
        }
        durable_undo::dispatch_undo_intent(
            self.store,
            rpc,
            &mut authority,
            &durable_undo::UndoDispatchRequest {
                operation_id: operation,
                step_id,
                invocation,
                undo_record_id: &record_id,
            },
        )
        .map(Some)
        .map_err(|error| failures.release(error))
    }

    /// Actual independent reads before claim establish the undo operation's
    /// own before capture. Retained original after refs are comparison pins.
    pub(crate) fn capture_registered_undo_before(
        &mut self,
        principal: &PrincipalId,
        rpc: &dyn UndoRpcContext,
        invocation: &Value,
    ) -> AppResult<BeforeCapture> {
        check_rpc(rpc, principal)?;
        validate("Invocation", invocation)?;
        let args: UndoArguments = decode(&invocation["arguments"])?;
        let source = self
            .store
            .operation(&args.source_operation_id)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
        self.authority
            .authorize_operation(principal, &source, Access::Recovery)?;
        let ids = source_material_ids(self.store, rpc, &source.operation_id)?;
        let failures = CallbackFailures::default();
        let mut authority = AppUndoAuthority {
            failures: failures.clone(),
            authority: self.authority,
            observer: self.observer,
            principal,
            read_access: Access::Recovery,
        };
        let mut selected = None;
        for id in ids {
            let record = durable_undo::provider_undo_record(self.store, rpc, &mut authority, &id)
                .map_err(|error| failures.release(error))?;
            let receipt: HostUndoReceipt = decode(&record.receipt)?;
            if receipt.token_record_id == args.token_record_id {
                if selected.is_some()
                    || receipt.token_record_digest != args.token_record_digest
                    || record.source_step_id != args.source_step_id
                    || record.source_invocation_id != args.source_invocation_id
                    || record.state != UndoRecordState::Available
                {
                    return Err(expired());
                }
                selected = Some(record);
            }
        }
        let record = selected.ok_or_else(expired)?;
        authority
            .authorize_recovery(self.store, &record, invocation)
            .map_err(|error| failures.release(error))?;
        let mut total = 0usize;
        let mut images = Vec::new();
        for state in &record.after_states {
            if state.before.is_none() {
                return Err(AppError::new(
                    "RECONCILIATION_INSUFFICIENT",
                    "Undo restoration requires actual independent source before states",
                ));
            }
            let bytes = authority
                .read_current_target(
                    self.store,
                    &record,
                    invocation,
                    &state.target,
                    (AFTER_BYTES - total) as u64,
                )
                .map_err(|error| failures.release(error))?;
            total += bytes.len();
            if raw_digest(&bytes) != state.after.digest
                || bytes.len() as u64 != state.after.byte_length
            {
                return Err(AppError::new(
                    "RECOVERY_CONFLICT",
                    "Undo target changed before independent undo capture",
                ));
            }
            images.push(BeforeImage {
                target: state.target.clone(),
                bytes,
            });
        }
        check_rpc(rpc, principal)?;
        Ok(BeforeCapture {
            invocation_id: decode(&invocation["invocationId"])?,
            binding_id: decode(&invocation["bindingId"])?,
            context_digest: decode(&invocation["contextDigest"])?,
            implementation_digest: decode(&invocation["implementationDigest"])?,
            arguments_digest: decode(&invocation["argumentsDigest"])?,
            images,
        })
    }

    /// Combine actual independent job settlement with fresh target bytes at the
    /// original source locator. Only its durable captured before state defines
    /// restoration; a receipt or provider completion flag cannot define it.
    pub(crate) fn verify_provider_undo_readback(
        &mut self,
        principal: &PrincipalId,
        rpc: &dyn UndoRpcContext,
        invocation: &Value,
        mut observed: ReadbackEvidence,
    ) -> AppResult<ReadbackEvidence> {
        check_rpc(rpc, principal)?;
        let operation: OperationId = decode(&invocation["operationId"])?;
        let step: StepId = decode(&invocation["stepId"])?;
        let id: InvocationId = decode(&invocation["invocationId"])?;
        let actual = self
            .store
            .stored_invocation(&operation, &step)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
        if actual != *invocation {
            return Err(expired());
        }
        let claimed = durable_undo::claimed_undo_record(self.store, &operation, &step, &id)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
        let failures = CallbackFailures::default();
        let mut authority = AppUndoAuthority {
            failures: failures.clone(),
            authority: self.authority,
            observer: self.observer,
            principal,
            read_access: Access::ObserveOperation,
        };
        let record =
            durable_undo::provider_undo_record(self.store, rpc, &mut authority, &claimed.record_id)
                .map_err(|error| failures.release(error))?;
        let undo_operation = self
            .store
            .operation(&operation)
            .map_err(|error| AppError::storage("OPERATION_NOT_FOUND", error))?;
        authority.authority.authorize_operation(
            principal,
            &undo_operation,
            Access::ObserveOperation,
        )?;
        check_undo_context(
            principal,
            &record.project_id,
            &invocation["context"],
            &rpc.current_context()
                .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?,
        )?;
        if observed.invocation_id != id
            || observed.binding_id.as_str() != invocation["bindingId"].as_str().unwrap_or("")
            || observed.context_digest.as_str()
                != invocation["contextDigest"].as_str().unwrap_or("")
            || observed.implementation_digest.as_str()
                != invocation["implementationDigest"].as_str().unwrap_or("")
            || observed.arguments_digest.as_str()
                != invocation["argumentsDigest"].as_str().unwrap_or("")
        {
            return Err(AppError::new(
                "RECONCILIATION_INSUFFICIENT",
                "Undo independent evidence differs from the actual claimed invocation",
            ));
        }
        let original = self
            .store
            .stored_invocation(&record.source_operation_id, &record.source_step_id)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
        let mut total = 0usize;
        let mut restored = true;
        let mut changes = Vec::new();
        for state in &record.after_states {
            authority
                .observer
                .validate_capture_target(&original, &record.scope, &state.target)?;
            let expected = state.before.as_ref().ok_or_else(|| {
                AppError::new(
                    "RECONCILIATION_INSUFFICIENT",
                    "Undo source lacks an independent expected restoration state",
                )
            })?;
            let bytes =
                authority
                    .observer
                    .read_target_with_store(self.store, &original, &state.target)?;
            total = total
                .checked_add(bytes.len())
                .filter(|size| *size <= AFTER_BYTES)
                .ok_or_else(|| {
                    AppError::new(
                        "BUDGET_EXCEEDED",
                        "Undo target verification exceeds its finite budget",
                    )
                })?;
            restored &=
                raw_digest(&bytes) == expected.digest && bytes.len() as u64 == expected.byte_length;
            let before = self
                .store
                .read_blob(&state.after)
                .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
            total = total
                .checked_add(before.len())
                .filter(|size| *size <= AFTER_BYTES)
                .ok_or_else(|| {
                    AppError::new(
                        "BUDGET_EXCEEDED",
                        "Undo observation images exceed their finite budget",
                    )
                })?;
            changes.push(DirectChange {
                target: state.target.clone(),
                before,
                after: bytes,
            });
        }
        if restored
            && observed.settled
            && matches!(
                observed.effect,
                EffectEvidence::SomeConfirmed | EffectEvidence::CompleteConfirmed
            )
        {
            observed.effect = EffectEvidence::CompleteConfirmed;
        } else if !restored && observed.effect == EffectEvidence::CompleteConfirmed {
            observed.effect = EffectEvidence::SomeConfirmed;
        }
        observed.evidence = json!({"independentJobEvidence":observed.evidence,"sourceOperationId":record.source_operation_id,
            "sourceInvocationId":record.source_invocation_id,"undoRecordId":record.record_id,"restored":restored});
        observed.direct_changes = changes;
        check_rpc(rpc, principal)?;
        let current = rpc
            .current_context()
            .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?;
        authority
            .authorize_read(self.store, &record, &current)
            .map_err(|error| failures.release(error))?;
        authority.authority.authorize_operation(
            principal,
            &undo_operation,
            Access::ObserveOperation,
        )?;
        check_rpc(rpc, principal)?;
        if rpc
            .current_context()
            .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?
            != current
        {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Undo observation release context changed during current authorization",
            ));
        }
        Ok(observed)
    }
    /// Stage actual independent after bytes for the existing source readback
    /// envelope. Caller must commit these refs with its original observation;
    /// staging alone cannot register material or claim a token.
    pub(crate) fn retain_undo_after_targets(
        &mut self,
        operation: &OperationId,
        step: &Value,
        invocation: &Value,
        observed: &ReadbackEvidence,
    ) -> AppResult<Vec<UndoAfterTarget>> {
        let record = self
            .store
            .operation(operation)
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        let step_id: StepId = decode(&step["stepId"])?;
        let plan = self
            .store
            .plan(&record.plan_id, &record.plan_hash)
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        let frozen = plan["steps"]
            .as_array()
            .and_then(|steps| {
                steps
                    .iter()
                    .find(|frozen| frozen["stepId"] == step_id.as_str())
            })
            .ok_or_else(expired)?;
        let original = self
            .store
            .stored_invocation(operation, &step_id)
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        if frozen != step || &original != invocation {
            return Err(expired());
        }
        let stored = record
            .steps
            .iter()
            .find(|s| s.step_id == step_id)
            .ok_or_else(expired)?;
        if stored.dispatch == DispatchEvidence::NotSent
            || !stored.write_effect
            || step["recovery"] != "provider_undo"
            || !observed.settled
            || !matches!(
                observed.effect,
                EffectEvidence::SomeConfirmed | EffectEvidence::CompleteConfirmed
            )
            || observed.invocation_id.as_str() != invocation["invocationId"].as_str().unwrap_or("")
            || observed.binding_id.as_str() != invocation["bindingId"].as_str().unwrap_or("")
            || observed.context_digest.as_str()
                != invocation["contextDigest"].as_str().unwrap_or("")
            || observed.implementation_digest.as_str()
                != invocation["implementationDigest"].as_str().unwrap_or("")
            || observed.arguments_digest.as_str()
                != invocation["argumentsDigest"].as_str().unwrap_or("")
        {
            return Err(expired());
        }
        let targets: BTreeSet<String> = decode::<Vec<String>>(&step["resourcesWritten"])?
            .into_iter()
            .collect();
        if targets.is_empty() || targets.len() > TARGETS || observed.direct_changes.len() > TARGETS
        {
            return Err(AppError::new(
                "RECONCILIATION_INSUFFICIENT",
                "Undo requires a finite full target footprint",
            ));
        }
        let before = self.captured_before(operation, &step_id, invocation)?;
        let mut supplied = BTreeMap::new();
        for change in &observed.direct_changes {
            if !targets.contains(&change.target)
                || supplied
                    .insert(change.target.clone(), &change.after)
                    .is_some()
            {
                return Err(AppError::new(
                    "RECONCILIATION_INSUFFICIENT",
                    "Undo after targets exceed the original footprint or repeat",
                ));
            }
        }
        let mut total = 0usize;
        let mut states = Vec::new();
        for target in targets {
            if target.is_empty() || target.len() > 512 {
                return Err(expired());
            }
            self.observer
                .validate_capture_target(invocation, &record.scope, &target)?;
            let fresh;
            let bytes = if let Some(bytes) = supplied.get(&target) {
                bytes.as_slice()
            } else {
                fresh = self
                    .observer
                    .read_target_with_store(self.store, invocation, &target)?;
                fresh.as_slice()
            };
            total = total
                .checked_add(bytes.len())
                .filter(|size| *size <= AFTER_BYTES)
                .ok_or_else(|| {
                    AppError::new(
                        "BUDGET_EXCEEDED",
                        "Undo after states exceed their finite budget",
                    )
                })?;
            let after = self
                .store
                .put_blob(bytes)
                .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
            self.store
                .pin_operation_artifact(operation, &after)
                .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
            states.push(UndoAfterTarget {
                target: target.clone(),
                before: before.get(&target).cloned(),
                after,
            });
        }
        Ok(states)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UndoArguments {
    token_record_id: ObjectId,
    token_record_digest: Sha256Digest,
    source_operation_id: OperationId,
    source_step_id: StepId,
    source_invocation_id: InvocationId,
}

fn check_rpc(rpc: &dyn UndoRpcContext, principal: &PrincipalId) -> AppResult<()> {
    rpc.check()
        .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?;
    if rpc
        .authenticated_principal()
        .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?
        != *principal
    {
        return Err(AppError::new(
            "PERMISSION_REQUIRED",
            "Undo request belongs to a different authenticated principal",
        ));
    }
    Ok(())
}

fn registered_route(
    step: &Value,
    descriptor: &Value,
    registration: &HostUndoRegistration,
) -> AppResult<RegisteredUndoRoute> {
    validate("ActionDescriptor", descriptor)?;
    validate("ActionDescriptor", &registration.undo_action)?;
    if descriptor["recovery"] != "provider_undo"
        || descriptor["effect"] == "read"
        || descriptor["verificationRequirement"] != "independent_readback"
        || registration.binding_id.as_str() != step["bindingId"].as_str().unwrap_or("")
        || registration.source_action_id.as_str() != descriptor["actionId"].as_str().unwrap_or("")
        || canonical_digest(descriptor).map_err(AppError::digest)?
            != registration.source_action_digest
        || registration.source_implementation_digest.as_str()
            != descriptor["implementationDigest"].as_str().unwrap_or("")
        || canonical_digest(&registration.undo_action).map_err(AppError::digest)?
            != registration.undo_action_digest
        || registration.undo_action["effect"] == "read"
        || registration.undo_action["recovery"] != "none"
        || registration.undo_action["verificationRequirement"] != "independent_readback"
        || registration.undo_action["actionId"] == descriptor["actionId"]
        || !registration.provider_origin.is_object()
    {
        return Err(expired());
    }
    Ok(RegisteredUndoRoute {
        source_binding_id: registration.binding_id.clone(),
        source_action: descriptor.clone(),
        undo_binding_id: registration.binding_id.clone(),
        undo_action: registration.undo_action.clone(),
        provider_origin: registration.provider_origin.clone(),
    })
}

fn source_material_ids(
    store: &DurableStore,
    rpc: &dyn UndoRpcContext,
    operation: &OperationId,
) -> AppResult<Vec<ObjectId>> {
    let summaries = store
        .operation_summaries(operation)
        .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
    let mut bytes = 0u64;
    let mut ids = BTreeSet::new();
    for reference in summaries {
        rpc.check()
            .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?;
        bytes = bytes
            .checked_add(reference.byte_length)
            .filter(|size| *size <= 32 * 1024 * 1024)
            .ok_or_else(|| {
                AppError::new(
                    "BUDGET_EXCEEDED",
                    "Undo material summary lookup exceeds its finite budget",
                )
            })?;
        if reference.byte_length > RECEIPT_BYTES as u64 {
            return Err(expired());
        }
        let marker = mmmm_contracts::parse_json(
            &store
                .read_blob(&reference)
                .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?,
        )
        .map_err(AppError::json)?;
        if marker["kind"] == "provider_undo_material" {
            ids.insert(decode::<ObjectId>(&marker["recordId"])?);
        }
    }
    Ok(ids.into_iter().collect())
}

struct CheckedMaterialSource<'a> {
    failures: CallbackFailures,
    host: &'a mut dyn UndoMaterialPort,
    principal: &'a PrincipalId,
    step: Value,
    descriptor: Value,
}
impl UndoMaterialSource for CheckedMaterialSource<'_> {
    fn inspect_source_material(
        &mut self,
        store: &DurableStore,
        source: &OperationRecord,
        invocation: &Value,
        route: &RegisteredUndoRoute,
        current_context: &Value,
    ) -> StorageResult<InspectedUndoMaterial> {
        let material = self
            .host
            .inspect_source_undo_with_store(store, self.principal, invocation, current_context)
            .map_err(|error| self.failures.capture(error))?
            .ok_or(StorageError::NotFound("Original-session undo receipt"))?;
        check_host_material(
            self.principal,
            source,
            invocation,
            &self.step,
            &self.descriptor,
            &material,
        )
        .map_err(|error| self.failures.capture(error))?;
        let inspected_route =
            registered_route(&self.step, &self.descriptor, &material.registration)
                .map_err(|error| self.failures.capture(error))?;
        if json!(inspected_route) != json!(route) {
            return Err(StorageError::Conflict(
                "Undo route changed during actual source inspection",
            ));
        }
        Ok(InspectedUndoMaterial {
            receipt: json!(material.receipt),
            authenticated_player_id: material.authenticated_player_id,
        })
    }
}

struct AppUndoAuthority<'a> {
    failures: CallbackFailures,
    authority: &'a mut dyn AuthorityPort,
    observer: &'a mut dyn IndependentObserverPort,
    principal: &'a PrincipalId,
    read_access: Access,
}
impl UndoAuthority for AppUndoAuthority<'_> {
    fn authorize_capture(
        &mut self,
        _store: &DurableStore,
        source: &OperationRecord,
        invocation: &Value,
        current_context: &Value,
    ) -> StorageResult<()> {
        check_undo_context(
            self.principal,
            &source.project_id,
            &invocation["context"],
            current_context,
        )
        .map_err(|error| self.failures.capture(error))?;
        self.authority
            .authorize_operation(self.principal, source, Access::ObserveOperation)
            .map_err(|error| self.failures.capture(error))?;
        self.authority
            .authorize(
                self.principal,
                &source.project_id,
                Access::ObserveOperation,
                Some(current_context),
                None,
            )
            .map_err(|error| self.failures.capture(error))
    }
    fn authorize_read(
        &mut self,
        store: &DurableStore,
        record: &ProviderUndoRecord,
        current_context: &Value,
    ) -> StorageResult<()> {
        check_undo_context(
            self.principal,
            &record.project_id,
            &record.source_context,
            current_context,
        )
        .map_err(|error| self.failures.capture(error))?;
        let source = store.operation(&record.source_operation_id)?;
        if self.principal != &record.principal
            || source.principal != record.principal
            || source.scope != record.scope
        {
            return Err(StorageError::Conflict("Undo original owner/scope"));
        }
        self.authority
            .authorize_operation(self.principal, &source, self.read_access)
            .map_err(|error| self.failures.capture(error))?;
        self.authority
            .authorize(
                self.principal,
                &record.project_id,
                self.read_access,
                Some(current_context),
                None,
            )
            .map_err(|error| self.failures.capture(error))
    }
    fn authorize_recovery(
        &mut self,
        store: &DurableStore,
        record: &ProviderUndoRecord,
        invocation: &Value,
    ) -> StorageResult<()> {
        self.authorize_read(store, record, &invocation["context"])?;
        let source = store.operation(&record.source_operation_id)?;
        self.authority
            .authorize_operation(self.principal, &source, Access::Recovery)
            .map_err(|error| self.failures.capture(error))?;
        self.authority
            .authorize(
                self.principal,
                &record.project_id,
                Access::Recovery,
                Some(&invocation["context"]),
                None,
            )
            .map_err(|error| self.failures.capture(error))?;
        let operation: OperationId =
            decode(&invocation["operationId"]).map_err(|error| self.failures.capture(error))?;
        let current = store.operation(&operation)?;
        if current.principal != *self.principal
            || current.project_id != record.project_id
            || current.scope != record.scope
        {
            return Err(StorageError::Conflict("Undo approved new operation scope"));
        }
        let plan = store.plan(&current.plan_id, &current.plan_hash)?;
        self.authority
            .authorize(
                self.principal,
                &record.project_id,
                Access::Apply,
                Some(&invocation["context"]),
                Some(&plan),
            )
            .map_err(|error| self.failures.capture(error))
    }
    fn read_current_target(
        &mut self,
        store: &DurableStore,
        record: &ProviderUndoRecord,
        invocation: &Value,
        target: &str,
        max_bytes: u64,
    ) -> StorageResult<Vec<u8>> {
        self.authorize_recovery(store, record, invocation)?;
        let original =
            store.stored_invocation(&record.source_operation_id, &record.source_step_id)?;
        self.observer
            .validate_capture_target(&original, &record.scope, target)
            .map_err(|error| self.failures.capture(error))?;
        if !record
            .after_states
            .iter()
            .any(|state| state.target == target)
        {
            return Err(StorageError::Conflict("Undo original target footprint"));
        }
        let bytes = self
            .observer
            .read_target_with_store(store, &original, target)
            .map_err(|error| self.failures.capture(error))?;
        if bytes.len() as u64 > max_bytes {
            return Err(StorageError::InvalidTransition(
                "Undo current target read budget exceeded".into(),
            ));
        }
        Ok(bytes)
    }
}

/// A synchronous callback error relay preserves its original boxed cause
/// across the runtime's StorageResult port. It carries no identity, grants or
/// durable state and is discarded after one use-case call.
#[derive(Clone, Default)]
struct CallbackFailures(Rc<RefCell<Option<AppError>>>);
impl CallbackFailures {
    fn capture(&self, error: AppError) -> StorageError {
        let boundary = StorageError::Contract(format!("{}: {}", error.code, error.message));
        let mut original = self.0.borrow_mut();
        if original.is_none() {
            *original = Some(error);
        }
        boundary
    }
    fn release(&self, error: StorageError) -> AppError {
        self.0.borrow_mut().take().unwrap_or_else(|| {
            let code = if matches!(
                error,
                StorageError::Conflict("Undo live original target drift")
            ) {
                "RECOVERY_CONFLICT"
            } else {
                "RECOVERY_EXPIRED"
            };
            AppError::storage(code, error)
        })
    }
}

/// Pure frozen assembly. This does not invoke a preview, claim material or
/// authorize apply. Only a runtime-registered source record may feed this path.
pub(crate) fn assemble_undo_plan(
    clock: &dyn Clock,
    source: &OperationRecord,
    source_step: &Value,
    material: &InspectedHostUndoMaterial,
    current_context: &Value,
    targets: &[UndoAfterTarget],
) -> AppResult<PreparedPlan> {
    let descriptor = &material.registration.undo_action;
    let receipt = &material.receipt;
    if targets.is_empty() || targets.len() > TARGETS {
        return Err(expired());
    }
    let source_written: BTreeSet<String> = decode::<Vec<String>>(&source_step["resourcesWritten"])?
        .into_iter()
        .collect();
    let written: BTreeSet<_> = targets.iter().map(|t| t.target.clone()).collect();
    if written.len() != targets.len() || written != source_written {
        return Err(expired());
    }
    let arguments = json!({"tokenRecordId":receipt.token_record_id,"tokenRecordDigest":receipt.token_record_digest,
        "sourceOperationId":receipt.source_operation_id,"sourceStepId":receipt.source_step_id,
        "sourceInvocationId":receipt.source_invocation_id});
    let step = json!({"stepId":"provider-undo","bindingId":material.registration.binding_id,
        "actionId":descriptor["actionId"],"actionContractVersion":descriptor["contractVersion"],
        "actionDigest":material.registration.undo_action_digest,"arguments":arguments,"dependsOn":[],
        "effect":descriptor["effect"],"completion":descriptor["completion"],"recovery":descriptor["recovery"],
        "resourcesRead":written,"resourcesWritten":written,"verificationRequirement":descriptor["verificationRequirement"],
        "contextId":current_context["contextId"],"implementationDigest":descriptor["implementationDigest"],"resultBindings":[]});
    check_descriptor(&step, current_context, descriptor)?;
    let expires = OffsetDateTime::from_unix_timestamp_nanos(clock.unix_nanos())
        .map_err(|_| AppError::new("INVALID_INPUT", "Clock is outside its supported range"))?
        .checked_add(Duration::seconds(60))
        .ok_or_else(expired)?
        .format(&Rfc3339)
        .map_err(|_| AppError::new("INVALID_INPUT", "Clock cannot format an undo expiry"))?;
    Ok(PreparedPlan {
        contexts: vec![current_context.clone()],
        scope: source.scope.clone(),
        preconditions: targets
            .iter()
            .map(|target| {
                json!({"kind":"resource_hash","subject":target.target,
            "expected":target.after.digest,"coverage":"full_target"})
            })
            .collect(),
        steps: vec![step],
        atomicity: "none".into(),
        losses: vec![],
        diagnostics: vec![],
        approval_requirement: "explicit_approval".into(),
        dependency_pins: vec![],
        expires_at: expires,
        time_budget_ms: 30_000,
    })
}

fn canonical_player_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn expired() -> AppError {
    AppError::new(
        "RECOVERY_EXPIRED",
        "Provider undo material is unavailable or differs from its original source",
    )
}

//! Trusted undo admission and job observation. These ports carry no public
//! request constructor; only the server's actual host composition supplies the
//! immutable registration inspection and original job observation.

use crate::planning::check_descriptor;
use crate::undo::UndoMaterialPort;
use crate::{AppError, AppResult, ReadbackEvidence, decode, validate};
use mmmm_contracts::{ActionId, BindingId, PrincipalId, Sha256Digest};
use mmmm_runtime::storage::{
    DurableStore, WriteScope,
    undo::{
        ProviderUndoRecord, RegisteredUndoRoute, is_registered_undo_action, register_undo_route,
    },
};
use serde_json::Value;

const ROLE_ROUTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UndoActionRole {
    Ordinary,
    Source,
    RecoveryOnly,
}

/// Acquired from an authenticated host Registrar inspection, including both
/// complete descriptors. Caller JSON, action argument names and a descriptor's
/// `recovery` value cannot prove that an action has no registered undo role.
pub struct InspectedUndoRoles {
    pub selected_role: UndoActionRole,
    pub routes: Vec<RegisteredUndoRoute>,
}

pub trait UndoExecutionPort: UndoMaterialPort {
    /// Inspect the selected original action and its inverse registrations. The
    /// real adapter must distinguish an explicitly inspected ordinary action
    /// from unsupported/unknown role metadata. It must not alias a source job's
    /// original HostSession to another session with matching scalar IDs.
    fn inspect_undo_roles_with_store(
        &mut self,
        _store: &DurableStore,
        _principal: &PrincipalId,
        _step: &Value,
        _current_context: &Value,
    ) -> AppResult<InspectedUndoRoles> {
        Err(AppError::new(
            "CAPABILITY_UNAVAILABLE",
            "The actual host does not expose trusted undo role inspection",
        ))
    }

    /// Observe the actual registered undo job using the original claimed
    /// Invocation and its original host route. ProviderResult completion alone
    /// cannot make `settled` or effect evidence. Retain the actual job response
    /// and fresh observation provenance in the unique product store; this port
    /// may acquire private evidence but cannot mutate a world or project head.
    /// The application separately checks exact source-target restoration.
    fn observe_registered_undo_job_with_store(
        &mut self,
        _store: &mut DurableStore,
        _invocation: &Value,
        _claimed: &ProviderUndoRecord,
        _scope: &WriteScope,
    ) -> AppResult<ReadbackEvidence> {
        Err(AppError::new(
            "CAPABILITY_UNAVAILABLE",
            "The actual host does not expose independent undo job observation",
        ))
    }
}

/// Install actual inspected memberships before ordinary admission. The returned
/// role is checked against the same runtime registry used by the atomic intent
/// guard. This helper performs no native mutation, reservation or intent.
pub(crate) fn install_selected_role(
    port: &mut dyn UndoExecutionPort,
    store: &mut DurableStore,
    principal: &PrincipalId,
    step: &Value,
    current_context: &Value,
    descriptor: &Value,
) -> AppResult<UndoActionRole> {
    validate("PlanStep", step)?;
    validate("ExecutionContext", current_context)?;
    check_descriptor(step, current_context, descriptor)?;
    if current_context["principalRef"] != principal.as_str()
        || current_context["contextId"] != step["contextId"]
    {
        return Err(AppError::new(
            "PERMISSION_REQUIRED",
            "Undo role inspection requires the actual selected context and principal",
        ));
    }
    let binding: BindingId = decode(&step["bindingId"])?;
    let action: ActionId = decode(&step["actionId"])?;
    let digest: Sha256Digest = decode(&step["actionDigest"])?;
    // Host undo tokens apply to game sessions. Non-game actions still pass the
    // durable role guard without opening a game RPC or changing their context.
    if current_context["environment"]["kind"] != "game" {
        if descriptor["recovery"] == "provider_undo" {
            return Err(AppError::new(
                "CAPABILITY_UNAVAILABLE",
                "The configured host undo receipt requires its actual game session",
            ));
        }
        if is_registered_undo_action(store, &binding, &action, &digest)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?
        {
            return Err(AppError::new(
                "RECOVERY_EXPIRED",
                "A registered host undo action requires its original game environment",
            ));
        }
        return Ok(UndoActionRole::Ordinary);
    }
    let inspected = port.inspect_undo_roles_with_store(store, principal, step, current_context)?;
    if inspected.routes.len() > ROLE_ROUTES {
        return Err(AppError::new(
            "BUDGET_EXCEEDED",
            "Selected undo role registrations exceed their finite inspection budget",
        ));
    }
    let mut matching_source = false;
    for route in &inspected.routes {
        validate("ActionDescriptor", &route.source_action)?;
        validate("ActionDescriptor", &route.undo_action)?;
        let source_digest =
            mmmm_contracts::canonical_digest(&route.source_action).map_err(AppError::digest)?;
        matching_source |= route.source_binding_id == binding
            && route.source_action["actionId"] == action.as_str()
            && source_digest == digest;
        register_undo_route(store, route)
            .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
    }
    let recovery_only = is_registered_undo_action(store, &binding, &action, &digest)
        .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))?;
    let consistent = match inspected.selected_role {
        UndoActionRole::Ordinary => {
            !recovery_only && !matching_source && descriptor["recovery"] != "provider_undo"
        }
        UndoActionRole::Source => {
            !recovery_only && matching_source && descriptor["recovery"] == "provider_undo"
        }
        UndoActionRole::RecoveryOnly => recovery_only && descriptor["effect"] != "read",
    };
    if !consistent {
        return Err(AppError::new(
            "RECOVERY_EXPIRED",
            "Actual undo role inspection differs from its registered immutable action",
        ));
    }
    Ok(inspected.selected_role)
}

/// Metadata-only branch selection precedes creation of a live game RPC. This
/// grants no authority; the selected branch still requires the approved plan,
/// current full scope and specialized same-transaction runtime claim.
pub(crate) fn is_recovery_only_step(store: &DurableStore, step: &Value) -> AppResult<bool> {
    is_registered_undo_action(
        store,
        &decode(&step["bindingId"])?,
        &decode(&step["actionId"])?,
        &decode(&step["actionDigest"])?,
    )
    .map_err(|error| AppError::storage("RECOVERY_EXPIRED", error))
}

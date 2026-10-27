//! Lazy trusted undo composition. Construction of this bundle performs no host
//! observation. The common use case opens an actual request context only after
//! a new reservation or when an effectful recovery/observation is required.
//! This source is not exported until the common algorithm is connected.

use crate::undo::check_undo_context;
use crate::undo_provider::UndoExecutionPort;
use crate::{AppError, AppResult, decode, validate};
use mmmm_contracts::{ContextId, OperationId, PlanId, PrincipalId, Sha256Digest, StepId};
use mmmm_runtime::storage::{DurableStore, undo::UndoRpcContext};
use serde_json::Value;

/// Implemented by the real Coordinator request composition. The implementation
/// owns the opaque occupied request slot, original deadline/cancellation and
/// method. A PrincipalId or context JSON cannot create a request identity.
pub trait UndoContextPort {
    /// Acquire fresh bounded native context before the runtime writer opens.
    /// With approved_plan, load those exact stored pins and bind the current
    /// explicit Apply approval to the subsequent local-only SQL checkpoints.
    fn open(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context_id: &ContextId,
        approved_plan: Option<(&PlanId, &Sha256Digest)>,
    ) -> AppResult<Box<dyn UndoRpcContext + 'static>>;
}

/// Trusted server ports share the actual HostBridge/session but never own a
/// second product store. Passing this object does not probe a live host, reserve
/// an operation, install a public token or change journal reporting behavior.
pub struct UndoExecutionContext<'a> {
    pub contexts: &'a mut dyn UndoContextPort,
    pub material: &'a mut dyn UndoExecutionPort,
}

impl UndoExecutionContext<'_> {
    /// Called only within the common Created execution branch after current
    /// preflight, for an actual selected frozen step requiring undo material or
    /// a recovery-only role. Existing idempotency keys never enter this method.
    pub(crate) fn open_for_plan(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        plan: &Value,
        step: &Value,
        current_context: &Value,
    ) -> AppResult<Box<dyn UndoRpcContext + 'static>> {
        validate("ExecutionPlan", plan)?;
        let id: PlanId = decode(&plan["planId"])?;
        let hash: Sha256Digest = decode(&plan["planHash"])?;
        let actual = store
            .plan(&id, &hash)
            .map_err(|error| AppError::storage("STALE_PLAN", error))?;
        if actual != *plan
            || !actual["steps"]
                .as_array()
                .is_some_and(|steps| steps.iter().any(|selected| selected == step))
        {
            return Err(AppError::new(
                "STALE_PLAN",
                "Undo context requires the actual stored plan and selected step",
            ));
        }
        let context: ContextId = decode(&step["contextId"])?;
        let rpc = self
            .contexts
            .open(store, principal, &context, Some((&id, &hash)))?;
        check_actual_rpc(rpc.as_ref(), principal)?;
        if rpc
            .current_context()
            .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?
            != *current_context
        {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Undo request differs from the actual selected preflight context",
            ));
        }
        Ok(rpc)
    }

    /// Effectful nonterminal reconciliation uses the immutable original
    /// invocation as its locator while a fresh current Observe grant controls
    /// access. A terminal report never calls this method or opens a native RPC.
    pub(crate) fn open_for_observation(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        operation: &OperationId,
        step: &StepId,
        invocation: &Value,
    ) -> AppResult<Box<dyn UndoRpcContext + 'static>> {
        let record = store
            .operation(operation)
            .map_err(|error| AppError::storage("OPERATION_NOT_FOUND", error))?;
        let actual = store
            .stored_invocation(operation, step)
            .map_err(|error| AppError::storage("STALE_CONTEXT", error))?;
        if record.principal != *principal || record.state.terminal() || actual != *invocation {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Undo observation requires its actual nonterminal invocation and owner",
            ));
        }
        let context: ContextId = decode(&invocation["context"]["contextId"])?;
        let rpc = self.contexts.open(store, principal, &context, None)?;
        check_actual_rpc(rpc.as_ref(), principal)?;
        let current = rpc
            .current_context()
            .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?;
        check_undo_context(
            principal,
            &record.project_id,
            &invocation["context"],
            &current,
        )?;
        Ok(rpc)
    }

    /// FN15 provider_undo needs a live same-epoch context but grants no Apply
    /// authority yet. Its output is a new frozen plan for separate approval.
    pub(crate) fn open_for_recovery(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: &ContextId,
    ) -> AppResult<Box<dyn UndoRpcContext + 'static>> {
        let rpc = self.contexts.open(store, principal, context, None)?;
        check_actual_rpc(rpc.as_ref(), principal)?;
        Ok(rpc)
    }
}

fn check_actual_rpc(rpc: &dyn UndoRpcContext, principal: &PrincipalId) -> AppResult<()> {
    rpc.check()
        .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?;
    if rpc
        .authenticated_principal()
        .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?
        != *principal
    {
        return Err(AppError::new(
            "PERMISSION_REQUIRED",
            "Undo context belongs to a different authenticated request principal",
        ));
    }
    Ok(())
}

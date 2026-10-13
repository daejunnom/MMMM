//! Current authenticated service context for provider-undo runtime ports. A
//! public PrincipalId, receipt, context JSON or old session clone cannot create
//! this adapter; the actual private request slot is its identity/budget source.

use crate::{
    AuthenticatedPrincipal,
    authority::LocalAuthority,
    host::{HostBridge, HostContextWitness},
    service::{RequestBudget, RequestContextSlot, RequestContextWitness},
};
use mmmm_application::{AppError, AppResult, undo_context::UndoContextPort};
use mmmm_contracts::{ContextId, PlanId, PrincipalId, ProjectId, Sha256Digest};
use mmmm_runtime::storage::{DurableStore, StorageError, StorageResult, undo::UndoRpcContext};
use serde_json::Value;

/// The original request deadline/cancellation and exact session generation are
/// preserved. No new timeout is started by a stream/CAS checkpoint.
#[derive(Clone)]
pub struct CurrentUndoRpcContext {
    request: RequestContextWitness,
    authority: LocalAuthority,
    authenticated: AuthenticatedPrincipal,
    budget: RequestBudget,
    method: &'static str,
    context: Value,
    context_id: ContextId,
    project: ProjectId,
    policy: Sha256Digest,
    paired: HostContextWitness,
    approved_plan: Option<Value>,
}

/// Construction performs no context lookup. The common application opens this
/// factory only for a new effectful branch, so existing-key and terminal journal
/// reports do not acquire a dependency on the original live game process.
pub struct CurrentUndoContextFactory {
    request: RequestContextSlot,
    authority: LocalAuthority,
    hosts: HostBridge,
    method: &'static str,
}
impl CurrentUndoContextFactory {
    /// Only the actual service dispatcher supplies the current method. A JSON
    /// method string, principal or context record is not a constructor input.
    pub(crate) fn new(
        request: RequestContextSlot,
        authority: LocalAuthority,
        hosts: HostBridge,
        method: &'static str,
    ) -> AppResult<Self> {
        if !matches!(
            method,
            "plan.create"
                | "action.plan"
                | "plan.apply"
                | "operation.get"
                | "operation.reconcile"
                | "recovery.plan"
        ) {
            return Err(AppError::new(
                "INTERNAL_ENTRY_REQUIRED",
                "This service method cannot open the trusted undo context",
            ));
        }
        Ok(Self {
            request,
            authority,
            hosts,
            method,
        })
    }
}
impl UndoContextPort for CurrentUndoContextFactory {
    fn open(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context_id: &ContextId,
        approved_plan: Option<(&PlanId, &Sha256Digest)>,
    ) -> AppResult<Box<dyn UndoRpcContext + 'static>> {
        let actual_request = self
            .request
            .current_witness(self.method)
            .map_err(|error| AppError::caused_by(error.code, error.message, error))?;
        let actual = actual_request.authenticated();
        if actual.principal() != principal
            || !actual.permits(self.method)
            || !actual.permits_context(context_id.as_str())
        {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Undo requires the actual occupied request principal and context",
            ));
        }
        let context = CurrentUndoRpcContext::from_request(
            self.request.clone(),
            self.authority.clone(),
            self.hosts.clone(),
            context_id,
            self.method,
        )
        .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?;
        // This lookup precedes the runtime writer. Capture/Observe deliberately
        // stays unbound: a revoked Apply grant cannot turn received source truth
        // into lost material, while a new recovery claim needs exact approval.
        let context = match approved_plan {
            Some((id, hash)) => context
                .bind_apply_plan(store, id, hash)
                .map_err(|error| AppError::storage("PERMISSION_REQUIRED", error))?,
            None => context,
        };
        Ok(Box::new(context))
    }
}
impl CurrentUndoRpcContext {
    /// contextId is only a locator. Its actual immutable record is independently
    /// resolved from the authority/paired host under this current request.
    pub fn from_request(
        request: RequestContextSlot,
        authority: LocalAuthority,
        hosts: HostBridge,
        context_id: &ContextId,
        method: &'static str,
    ) -> StorageResult<Self> {
        let request = request.current_witness(method).map_err(|_| denied())?;
        let authenticated = request.authenticated().clone();
        let budget = request.budget().clone();
        if !authenticated.permits(method) || !authenticated.permits_context(context_id.as_str()) {
            return Err(denied());
        }
        // Native freshness is established before entering any runtime writer
        // transaction. Its opaque installed generation is checked locally at
        // subsequent CAS/SQL checkpoints; no transport executes while locked.
        let paired = hosts
            .observe_context_witness(authenticated.principal(), context_id, budget.deadline())
            .map_err(|_| denied())?;
        let context = paired.context().clone();
        if context["environment"]["kind"] != "game" {
            return Err(denied());
        }
        let project = ProjectId::new(text(&context, "projectId")?).map_err(|_| denied())?;
        let policy = Sha256Digest::new(text(&context, "policyRevision")?).map_err(|_| denied())?;
        let result = Self {
            request,
            authority,
            authenticated,
            budget,
            method,
            context,
            context_id: context_id.clone(),
            project,
            policy,
            paired,
            approved_plan: None,
        };
        result.check()?;
        Ok(result)
    }
    /// Lookup the real stored plan before recovery claim. Subsequent SQL
    /// checkpoints recheck its current explicit approval locally; a caller
    /// supplied JSON plan or an old hash does not supply this stored record.
    pub fn bind_apply_plan(
        mut self,
        store: &DurableStore,
        plan: &PlanId,
        hash: &Sha256Digest,
    ) -> StorageResult<Self> {
        self.check()?;
        let stored = store.plan(plan, hash)?;
        self.authority
            .authorize_retained_apply(self.authenticated.principal(), &self.context, &stored)
            .map_err(|_| denied())?;
        self.approved_plan = Some(stored);
        self.check()?;
        Ok(self)
    }
    fn request_is_current(&self) -> StorageResult<()> {
        self.request.check_local().map_err(|_| denied())?;
        let current = self.request.authenticated();
        let budget = self.request.budget();
        if !current.same_session(&self.authenticated)
            || self.request.method() != self.method
            || budget.deadline() != self.budget.deadline()
            || !std::ptr::eq(budget.cancellation(), self.budget.cancellation())
            || !current.permits(self.method)
            || !current.permits_context(self.context_id.as_str())
            || crate::peer::fatal_stop_requested()
        {
            return Err(denied());
        }
        self.budget.check().map_err(|_| denied())
    }
    fn live_context(&self) -> StorageResult<Value> {
        self.request_is_current()?;
        self.authority
            .authorize_retained_scope(
                self.authenticated.principal(),
                &self.project,
                &self.context_id,
                &self.policy,
                &self.context["scope"],
            )
            .map_err(|_| denied())?;
        self.paired.check_local().map_err(|_| denied())?;
        if let Some(plan) = &self.approved_plan {
            self.authority
                .authorize_retained_apply(self.authenticated.principal(), &self.context, plan)
                .map_err(|_| denied())?;
        }
        // This local witness does not claim current native state. Actual fresh
        // target observation and source receipt lookup belong to the material/
        // authority ports before their writer transaction. The actual Project
        // grant and same service generation must still hold at every checkpoint.
        self.authority
            .authorize_retained_scope(
                self.authenticated.principal(),
                &self.project,
                &self.context_id,
                &self.policy,
                &self.context["scope"],
            )
            .map_err(|_| denied())?;
        self.request_is_current()?;
        Ok(self.context.clone())
    }
}
impl UndoRpcContext for CurrentUndoRpcContext {
    fn check(&self) -> StorageResult<()> {
        self.live_context().map(|_| ())
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.authenticated.principal().clone())
    }
    fn current_context(&self) -> StorageResult<Value> {
        self.live_context()
    }
    fn check_dispatch_plan(&self, plan_id: &PlanId, plan_hash: &Sha256Digest) -> StorageResult<()> {
        self.check()?;
        let bound = self.approved_plan.as_ref().ok_or_else(denied)?;
        if bound["planId"] != plan_id.as_str() || bound["planHash"] != plan_hash.as_str() {
            return Err(denied());
        }
        // The runtime supplies the actual claim Operation's stored pins. This
        // final local check closes expiry/revocation after pretransaction reads;
        // an unbound Observe context can retain truth but cannot reserve undo.
        self.authority
            .authorize_retained_apply(self.authenticated.principal(), &self.context, bound)
            .map_err(|_| denied())?;
        self.request_is_current()
    }
}
fn text<'a>(value: &'a Value, key: &str) -> StorageResult<&'a str> {
    value[key].as_str().ok_or_else(denied)
}
fn denied() -> StorageError {
    StorageError::InvalidTransition(
        "Current authenticated undo session/context is unavailable".into(),
    )
}

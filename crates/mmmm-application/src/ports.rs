use crate::types::*;
use mmmm_contracts::{ContextId, PrincipalId, ProjectId, Sha256Digest};
use mmmm_runtime::storage::WriteScope;
use serde_json::Value;

/// Authenticated composition supplies this port. It intersects the live user
/// policy, explicit per-operation grant, actual game principal, and host
/// capability. `planHash` binds explicit approvals; model JSON is not a grant.
/// Observe/Recovery permissions remain distinct after Apply permission revocation.
pub trait AuthorityPort {
    fn authorize(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectId,
        access: Access,
        context: Option<&Value>,
        plan: Option<&Value>,
    ) -> AppResult<()>;
    fn authorize_operation(
        &mut self,
        principal: &PrincipalId,
        operation: &mmmm_runtime::storage::OperationRecord,
        access: Access,
    ) -> AppResult<()> {
        if principal != &operation.principal {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Operation belongs to a different principal",
            ));
        }
        self.authorize(principal, &operation.project_id, access, None, None)
    }
}

pub trait PlanningPort {
    fn inspect_project(
        &mut self,
        principal: &PrincipalId,
        project: &Value,
    ) -> AppResult<ProjectInspection>;
    /// Read/compile/private-cache only. A provider preview that writes targets
    /// needs its own separately approved plan and cannot implement this method.
    fn prepare(
        &mut self,
        principal: &PrincipalId,
        request: &Value,
        project: &Value,
        context: &Value,
    ) -> AppResult<PreparedPlan>;
    fn prepare_recovery(
        &mut self,
        principal: &PrincipalId,
        recovery: &RecoveryPreparation,
        project: &Value,
        context: &Value,
    ) -> AppResult<PreparedPlan>;
}

/// Implementations perform bounded calls using Invocation.deadlineAt and the
/// frozen binding, never discover a replacement route after dispatch.
pub trait ProviderPort {
    fn context(&mut self, principal: &PrincipalId, context_id: &ContextId) -> AppResult<Value>;
    /// Return the currently observed descriptor for this exact binding/action.
    fn action_descriptor(&mut self, step: &Value, context: &Value) -> AppResult<Value>;
    fn observe_precondition(
        &mut self,
        precondition: &Value,
        context: &Value,
    ) -> AppResult<Sha256Digest>;
    fn verify_dependencies(&mut self, dependency_pins: &[Value], context: &Value) -> AppResult<()>;
    /// This is called only after SQLite commits the full dispatch intent.
    /// Any error at this point is ambiguous; it cannot authorize another write.
    fn dispatch(&mut self, invocation: &Value) -> AppResult<Value>;
    /// Query only the original durable invocation/job handle. Its old context
    /// identifies the job; it is not the authority for this read. Composition
    /// applies the fresh ObserveOperation grant from the current context lookup.
    fn poll(&mut self, invocation: &Value, receipt: Option<&str>) -> AppResult<Option<Value>>;
    /// A successful return acknowledges a request, not stopped effects. Apply
    /// revocation does not revoke a separately authorized current Cancel grant.
    fn request_cancel(&mut self, invocation: &Value, receipt: Option<&str>) -> AppResult<()>;
}

/// Separate readback composition observes the real target rather than treating
/// ProviderResult.data as a target snapshot. No write method is exposed here.
/// The stored invocation identifies the target, not permission: the caller's
/// fresh observation/recovery authority is enforced independently of its old
/// policyRevision. This port must bound all reads and retain exact before images.
pub trait IndependentObserverPort {
    fn readback(&mut self, invocation: &Value, scope: &WriteScope) -> AppResult<ReadbackEvidence>;
    fn read_target(&mut self, stored_invocation: &Value, target: &str) -> AppResult<Vec<u8>>;
}

pub trait IdSource {
    /// Runtime supplies collision-resistant identities; the application validates
    /// their original lexical form and SQLite rejects any durable collision.
    fn next_id(&mut self, kind: IdKind) -> AppResult<String>;
}

pub trait Clock {
    fn unix_nanos(&self) -> i128;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn unix_nanos(&self) -> i128 {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_nanos().min(i128::MAX as u128) as i128,
            Err(e) => -(e.duration().as_nanos().min(i128::MAX as u128) as i128),
        }
    }
}

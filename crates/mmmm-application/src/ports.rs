use crate::types::*;
use mmmm_contracts::{
    ContextId, ObjectId, OperationId, PrincipalId, ProjectId, Sha256Digest, StepId,
};
use mmmm_runtime::storage::result_binding::RegisteredResultCodec;
use mmmm_runtime::storage::{BlobRef, DurableStore, StepRecord, WriteScope};
use serde_json::Value;

/// Authenticated composition supplies this port. It intersects the live user
/// policy, explicit per-operation grant, actual game principal, and host
/// capability. `planHash` binds explicit approvals; model JSON is not a grant.
/// Observe/Recovery permissions remain distinct after Apply permission revocation.
/// authorize_operation must enforce its current journal grant against the full
/// original record scope; old invocation context/permission claims grant no read.
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
    fn inspect_project_with_store(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        project: &Value,
    ) -> AppResult<ProjectInspection> {
        self.inspect_project(principal, project)
    }
    /// A short borrow of the application's unique store permits owned document
    /// reads and private CAS staging without another database or target effects.
    fn prepare_with_store(
        &mut self,
        _store: &mut DurableStore,
        principal: &PrincipalId,
        request: &Value,
        project: &Value,
        context: &Value,
    ) -> AppResult<PreparedPlan> {
        self.prepare(principal, request, project, context)
    }
    fn prepare_recovery_with_store(
        &mut self,
        _store: &mut DurableStore,
        principal: &PrincipalId,
        recovery: &RecoveryPreparation,
        project: &Value,
        context: &Value,
    ) -> AppResult<PreparedPlan> {
        self.prepare_recovery(principal, recovery, project, context)
    }
}

/// Implementations perform bounded calls using Invocation.deadlineAt and the
/// frozen binding, never discover a replacement route after dispatch.
pub trait ProviderPort {
    /// Only the authenticated server's closed immutable codec registry can
    /// implement this. Public/model JSON cannot register transformations.
    fn result_codec(
        &mut self,
        _id: &ObjectId,
        _digest: &Sha256Digest,
    ) -> AppResult<RegisteredResultCodec> {
        Err(AppError::new(
            "CAPABILITY_UNAVAILABLE",
            "No server-registered result codec is available",
        ))
    }
    /// Validate resolved data against the original target/cost/route footprint
    /// using the registered action's actual semantics. No target widening.
    fn validate_resolved_footprint(
        &mut self,
        _step: &Value,
        _arguments: &Value,
        _context: &Value,
    ) -> AppResult<()> {
        Err(AppError::new(
            "CAPABILITY_UNAVAILABLE",
            "No registered result-slot footprint verifier is available",
        ))
    }
    fn context(&mut self, principal: &PrincipalId, context_id: &ContextId) -> AppResult<Value>;
    /// A trusted composition may admit a fresh read-only context for one
    /// original durable invocation after its actual host session was replaced.
    /// It must verify this store's original operation and retained actual host
    /// attempt, the new pairing and its current observation authority. Public
    /// JSON, equal digests or an old approval cannot issue this admission.
    /// None retains the ordinary exact-session observation path; an admission
    /// failure must be returned as an error rather than downgraded to None.
    /// This never permits dispatch, cancellation, recovery or another mutation.
    fn successor_observation_context_with_store(
        &mut self,
        _store: &mut DurableStore,
        _principal: &PrincipalId,
        _original: &Value,
    ) -> AppResult<Option<Value>> {
        Ok(None)
    }
    /// Return the currently observed descriptor for this exact binding/action.
    fn action_descriptor(&mut self, step: &Value, context: &Value) -> AppResult<Value>;
    fn observe_precondition(
        &mut self,
        precondition: &Value,
        context: &Value,
    ) -> AppResult<Sha256Digest>;
    fn verify_dependencies(&mut self, dependency_pins: &[Value], context: &Value) -> AppResult<()>;
    /// Persist this original intent through the same durable store before any
    /// provider dispatch. Trusted composition may select a protected atomic
    /// claim; invocation JSON and a resolution witness confer no such authority.
    /// Registered undo retains its separate atomic claim boundary.
    fn persist_dispatch_intent_with_store(
        &mut self,
        store: &mut DurableStore,
        original_operation: &OperationId,
        original_step: &StepId,
        original_invocation: &Value,
        resolution_witness: Option<&BlobRef>,
    ) -> AppResult<StepRecord> {
        match resolution_witness {
            Some(witness) => store.dispatch_resolved_intent(
                original_operation,
                original_step,
                original_invocation,
                witness,
            ),
            None => store.dispatch_intent(original_operation, original_step, original_invocation),
        }
        .map_err(|error| AppError::storage("DISPATCH_REJECTED", error))
    }
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
    /// The common cancel path supplies the same durable store that owns this
    /// original invocation. A provider may validate its retained host route
    /// through that ownership before issuing the cooperative request.
    fn request_cancel_with_store(
        &mut self,
        _store: &mut DurableStore,
        invocation: &Value,
        receipt: Option<&str>,
    ) -> AppResult<()> {
        self.request_cancel(invocation, receipt)
    }
    /// A dedicated registered read boundary enforces mutation prohibition. It
    /// uses the current authenticated context, not a fabricated write operation.
    fn registered_read_with_store(
        &mut self,
        _store: &DurableStore,
        _request: &Value,
        _context: &Value,
    ) -> AppResult<Value> {
        Err(AppError::new(
            "CAPABILITY_UNAVAILABLE",
            "No authenticated registered read boundary is available",
        ))
    }
    fn observe_precondition_with_store(
        &mut self,
        _store: &DurableStore,
        precondition: &Value,
        context: &Value,
    ) -> AppResult<Sha256Digest> {
        self.observe_precondition(precondition, context)
    }
    /// Admission supplies the actual immutable plan loaded from this store and
    /// its selected step. A prepared private CAS reference can be read only
    /// through its authenticated producer/plan association, never from a hash,
    /// media type or project permission alone.
    fn observe_plan_precondition_with_store(
        &mut self,
        store: &DurableStore,
        _plan: &Value,
        _step: &Value,
        precondition: &Value,
        context: &Value,
    ) -> AppResult<Sha256Digest> {
        self.observe_precondition_with_store(store, precondition, context)
    }
    /// Same admission boundary with a short mutable store borrow for retaining
    /// actual private CAS evidence and pins. This permits no target mutation or
    /// authored project/head commit; the frozen plan and current grant remain
    /// the authorities for the independently acquired evidence.
    fn observe_plan_precondition_retained_with_store(
        &mut self,
        store: &mut DurableStore,
        plan: &Value,
        step: &Value,
        precondition: &Value,
        context: &Value,
    ) -> AppResult<Sha256Digest> {
        self.observe_plan_precondition_with_store(store, plan, step, precondition, context)
    }
    /// One stack-scoped observation for this exact preflight. A concrete
    /// platform may return digests in the supplied condition order; the common
    /// application still compares every digest with its phase expectation.
    /// None preserves the existing per-condition fail-fast observation path.
    fn observe_plan_preconditions_retained_with_store(
        &mut self,
        _store: &mut DurableStore,
        _plan: &Value,
        _step: &Value,
        _conditions: &[&Value],
        _context: &Value,
    ) -> AppResult<Option<Vec<Sha256Digest>>> {
        Ok(None)
    }
    /// This short unique-store borrow is granted only after durable intent. The
    /// composition may commit authenticated owned projection evidence there;
    /// it must never redispatch a world mutation after a local commit failure.
    fn dispatch_with_store(
        &mut self,
        _store: &mut DurableStore,
        invocation: &Value,
    ) -> AppResult<Value> {
        self.dispatch(invocation)
    }
    fn poll_with_store(
        &mut self,
        _store: &mut DurableStore,
        invocation: &Value,
        receipt: Option<&str>,
    ) -> AppResult<Option<Value>> {
        self.poll(invocation, receipt)
    }
}

/// Separate readback composition observes the real target rather than treating
/// ProviderResult.data as a target snapshot. No write method is exposed here.
/// The stored invocation identifies the target, not permission: the caller's
/// fresh observation/recovery authority is enforced independently of its old
/// policyRevision. This port must bound all reads and retain exact before images.
pub trait IndependentObserverPort {
    /// A composition with region target keys must independently validate their
    /// dimension/position against this step's context and approved region. The
    /// default supports only exact identifiers present in the durable scope.
    fn validate_capture_target(
        &mut self,
        _invocation: &Value,
        scope: &WriteScope,
        target: &str,
    ) -> AppResult<()> {
        if scope.resource_ids.iter().any(|id| id.as_str() == target)
            || scope.object_ids.iter().any(|id| id.as_str() == target)
            || scope
                .external_target_ids
                .iter()
                .any(|id| id.as_str() == target)
        {
            Ok(())
        } else {
            Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Capture target is absent from the authorized scope",
            ))
        }
    }
    /// Actual independent target reads before dispatch. Default means this
    /// composition has no direct before-image capability; direct-recovery writes
    /// are rejected rather than inferring bytes from arguments/provider output.
    fn capture_before(
        &mut self,
        _invocation: &Value,
        _scope: &WriteScope,
    ) -> AppResult<Option<BeforeCapture>> {
        Ok(None)
    }
    fn readback(&mut self, invocation: &Value, scope: &WriteScope) -> AppResult<ReadbackEvidence>;
    fn read_target(&mut self, stored_invocation: &Value, target: &str) -> AppResult<Vec<u8>>;
    fn capture_before_with_store(
        &mut self,
        _store: &DurableStore,
        invocation: &Value,
        scope: &WriteScope,
    ) -> AppResult<Option<BeforeCapture>> {
        self.capture_before(invocation, scope)
    }
    /// Before durable intent, a trusted observer can retain its actual private
    /// observation evidence using the application's unique store. Only private
    /// CAS/pins may change here; target and authored projection writes remain
    /// behind the separately approved durable dispatch boundary.
    fn capture_before_retained_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        scope: &WriteScope,
    ) -> AppResult<Option<BeforeCapture>> {
        self.capture_before_with_store(store, invocation, scope)
    }
    fn readback_with_store(
        &mut self,
        _store: &mut DurableStore,
        invocation: &Value,
        scope: &WriteScope,
    ) -> AppResult<ReadbackEvidence> {
        self.readback(invocation, scope)
    }
    fn read_target_with_store(
        &mut self,
        _store: &DurableStore,
        stored_invocation: &Value,
        target: &str,
    ) -> AppResult<Vec<u8>> {
        self.read_target(stored_invocation, target)
    }
    /// Acquire and retain fresh private observation evidence before a recovery
    /// claim or while observing its original target. Only CAS/pins may change;
    /// this hook grants no mutation or authored-project commit authority.
    fn read_target_retained_with_store(
        &mut self,
        store: &mut DurableStore,
        stored_invocation: &Value,
        target: &str,
    ) -> AppResult<Vec<u8>> {
        self.read_target_with_store(store, stored_invocation, target)
    }
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

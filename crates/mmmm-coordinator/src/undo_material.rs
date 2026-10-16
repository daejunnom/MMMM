//! Authenticated original-session inspection of public provider undo material.
//!
//! The caller supplies the existing product store; this adapter never opens a
//! second store, issues a private token, dispatches a mutation or fabricates a
//! source Invocation. Inspection does not promote a Pending record or prove job
//! settlement. Registrar role attestation remains separate from target/profile
//! admission, and executor quiescence does not establish restored world state.
//! The opaque per-enter request witness proves the actual method/generation;
//! same principal/session/budget scalars alone cannot establish that grant.
use crate::{
    AuthenticatedPrincipal,
    authority::LocalAuthority,
    catalog_source::{source_facts_pin, validate_source_facts},
    host::{HostBridge, HostContextWitness},
    service::{RequestBudget, RequestContextSlot, RequestContextWitness, ServiceError},
};
use mmmm_application::{
    Access, AppError, AppResult, AuthorityPort, HostUndoReceipt, HostUndoRegistration,
    InspectedHostUndoMaterial, InspectedUndoRoles, ReadbackEvidence, UndoActionRole,
    UndoExecutionPort, UndoMaterialPort,
};
use mmmm_contracts::{
    ActionId, BindingId, ContextId, ContractValidator, InvocationId, JsonLimits, OperationId,
    PrincipalId, ProjectId, Sha256Digest, StepId, canonical_digest, encode_json,
    parse_json_with_limits, verify_projected_digest,
};
use mmmm_runtime::storage::{
    BlobRef, DurableStore, OperationRecord, StorageError, WriteScope,
    undo::{ProviderUndoRecord, RegisteredUndoRoute, claimed_undo_record},
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 64 * 1024;
const MAX_LOCAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_STEPS: usize = 4096;

/// Construct only in the service's trusted composition. The actual method
/// never comes from a public JSON authority setter.
pub(crate) struct HostUndoMaterialAdapter {
    request: RequestContextSlot,
    authority: LocalAuthority,
    hosts: HostBridge,
    method: &'static str,
}
impl HostUndoMaterialAdapter {
    pub(crate) fn new(
        request: RequestContextSlot,
        authority: LocalAuthority,
        hosts: HostBridge,
        method: &'static str,
    ) -> Self {
        Self {
            request,
            authority,
            hosts,
            method,
        }
    }
    fn begin(&self, principal: &PrincipalId, context: &Value) -> AppResult<InspectionGuard> {
        let request_witness = self
            .request
            .current_witness(self.method)
            .map_err(service_error)?;
        bounded(context, MAX_RESPONSE_BYTES)?;
        validate("ExecutionContext", context)?;
        verify_projected_digest("ExecutionContext", context).map_err(digest_error)?;
        let id: ContextId = decode(&context["contextId"])?;
        let project: ProjectId = decode(&context["projectId"])?;
        let policy: Sha256Digest = decode(&context["policyRevision"])?;
        let authenticated = request_witness.authenticated().clone();
        let budget = request_witness.budget().clone();
        if authenticated.principal() != principal
            || !authenticated.permits(self.method)
            || !authenticated.permits_context(id.as_str())
            || context["principalRef"] != principal.as_str()
            || context["environment"]["kind"] != "game"
        {
            return Err(denied());
        }
        let paired = self
            .hosts
            .observe_context_witness(principal, &id, budget.deadline())?;
        if paired.context() != context {
            return Err(stale());
        }
        let guard = InspectionGuard {
            request_witness,
            authority: self.authority.clone(),
            authenticated,
            budget,
            paired,
            context: context.clone(),
            id,
            project,
            policy,
        };
        guard.check(&context["scope"])?;
        Ok(guard)
    }
    fn source_descriptor(
        &self,
        guard: &InspectionGuard,
        step: &Value,
        scope: &Value,
    ) -> AppResult<Value> {
        guard.check(scope)?;
        let binding: BindingId = decode(&step["bindingId"])?;
        let action: ActionId = decode(&step["actionId"])?;
        // Parent-owned future narrow HostBridge API: keep the full bounded
        // HostResponse and exact failure cause, rather than infer describe data.
        let reply = self.hosts.describe_response_with_deadline(
            guard.authenticated.principal(),
            &guard.id,
            &binding,
            &action,
            guard.budget.deadline(),
        )?;
        guard.check_received(scope, &reply)?;
        let descriptor = host_payload(&reply, false)?.ok_or_else(invalid)?;
        validate_source_descriptor(step, &guard.context, &descriptor)?;
        guard.check_received(scope, &reply)?;
        Ok(descriptor)
    }
}

impl UndoMaterialPort for HostUndoMaterialAdapter {
    fn inspect_undo_registration_with_store(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        source_step: &Value,
        current_context: &Value,
    ) -> AppResult<Option<HostUndoRegistration>> {
        let guard = self.begin(principal, current_context)?;
        bounded(source_step, MAX_LOCAL_BYTES)?;
        validate("PlanStep", source_step)?;
        // Metadata lookup precedes plan freezing and grants no mutation or
        // recovery authority. It reads the actual Registrar, not a guessed plan.
        let scope = &current_context["scope"];
        guard.check(scope)?;
        let descriptor = self.source_descriptor(&guard, source_step, scope)?;
        let reply = self.hosts.inspect_response_with_deadline(principal, &guard.id,
            json!({"kind":"undo_registration","bindingId":source_step["bindingId"],"sourceActionId":source_step["actionId"]}),
            guard.budget.deadline())?;
        guard.check_received(scope, &reply)?;
        let registration = match host_payload(&reply, true)? {
            None | Some(Value::Null) => None,
            Some(payload) => Some(validate_registration(&payload, source_step, &descriptor)?),
        };
        guard.check_received(scope, &reply)?;
        Ok(registration)
    }

    fn inspect_source_undo_with_store(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        original_invocation: &Value,
        current_context: &Value,
    ) -> AppResult<Option<InspectedHostUndoMaterial>> {
        let guard = self.begin(principal, current_context)?;
        bounded(original_invocation, MAX_LOCAL_BYTES)?;
        validate("Invocation", original_invocation)?;
        validate_current_source_context(&original_invocation["context"], current_context)?;
        let operation: OperationId = decode(&original_invocation["operationId"])?;
        let step_id: StepId = decode(&original_invocation["stepId"])?;
        let record = store
            .operation(&operation)
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        authorize_original(&guard, &record)?;
        let full_scope = serde_json::to_value(&record.scope).map_err(dto_error)?;
        let original = store
            .stored_invocation_checked(&operation, &step_id, MAX_LOCAL_BYTES as u64, || {
                guard.check(&full_scope).map_err(local_storage_error)
            })
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        if original != *original_invocation {
            return Err(stale());
        }
        let plan = store
            .plan(&record.plan_id, &record.plan_hash)
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        bounded(&plan, MAX_LOCAL_BYTES)?;
        let step = exact_step(&plan, step_id.as_str())?;
        validate_plan_step(&plan, step, &original["context"], &full_scope)?;
        validate_original_step(step, &original)?;
        guard.check(&full_scope)?;
        // Original metadata and material use the retained original HostSession
        // route. Current paired scalar IDs cannot replace that session object.
        let acquired = self.hosts.describe_original_acquired_with_deadline(
            store,
            principal,
            &original,
            current_context,
            &decode::<BindingId>(&step["bindingId"])?,
            &decode::<ActionId>(&step["actionId"])?,
            guard.budget.deadline(),
        )?;
        let description = acquired.into_response()?;
        let descriptor = host_payload(&description, false)?.ok_or_else(invalid)?;
        validate_source_descriptor(step, &original["context"], &descriptor)?;
        guard.check_received(&full_scope, &description)?;
        let acquired = self.hosts.inspect_original_acquired_with_deadline(
            store,
            principal,
            &original,
            current_context,
            json!({"kind":"undo_material","sourceInvocationId":original["invocationId"]}),
            guard.budget.deadline(),
        )?;
        let reply = acquired.into_acquired_response()?;
        // Receipt acquisition has happened. Bounded pure validation retains its
        // original truth even if the caller budget now expires or is revoked.
        // Runtime CapturedTruthContext commits private Pending material and then
        // separately rechecks current caller access before releasing a result.
        let payload = host_payload(&reply, false)?.ok_or_else(invalid)?;
        let material = validate_source_material(&payload, &original, step, &descriptor)?;
        Ok(material)
    }
}
impl UndoExecutionPort for HostUndoMaterialAdapter {
    fn inspect_undo_roles_with_store(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        step: &Value,
        current_context: &Value,
    ) -> AppResult<InspectedUndoRoles> {
        let guard = self.begin(principal, current_context)?;
        bounded(step, MAX_LOCAL_BYTES)?;
        validate("PlanStep", step)?;
        let scope = &current_context["scope"];
        let descriptor = self.source_descriptor(&guard, step, scope)?;
        let hello =
            self.hosts
                .hello_with_deadline(principal, &guard.id, guard.budget.deadline())?;
        guard.check(scope)?;
        let facts_reply = self.hosts.inspect_response_with_deadline(
            principal,
            &guard.id,
            json!({"kind":"runtime_sources"}),
            guard.budget.deadline(),
        )?;
        guard.check_received(scope, &facts_reply)?;
        let facts = host_payload(&facts_reply, false)?.ok_or_else(invalid)?;
        validate_source_facts(&facts, current_context)?;
        let reply = self.hosts.inspect_response_with_deadline(
            principal,
            &guard.id,
            json!({"kind":"undo_role","bindingId":step["bindingId"],"actionId":step["actionId"]}),
            guard.budget.deadline(),
        )?;
        guard.check_received(scope, &reply)?;
        let payload = host_payload(&reply, false)?.ok_or_else(invalid)?;
        let roles =
            validate_role_wrapper(&payload, step, current_context, &descriptor, &hello, &facts)?;
        guard.check_received(scope, &reply)?;
        Ok(roles)
    }
    fn observe_registered_undo_job_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        claimed: &ProviderUndoRecord,
        scope: &WriteScope,
    ) -> AppResult<ReadbackEvidence> {
        let request = self
            .request
            .current_witness(self.method)
            .map_err(service_error)?;
        bounded(invocation, MAX_LOCAL_BYTES)?;
        validate("Invocation", invocation)?;
        let principal = request.authenticated().principal().clone();
        let operation_id: OperationId = decode(&invocation["operationId"])?;
        let step_id: StepId = decode(&invocation["stepId"])?;
        let invocation_id: InvocationId = decode(&invocation["invocationId"])?;
        let context_id: ContextId = decode(&invocation["context"]["contextId"])?;
        if !request.authenticated().permits_context(context_id.as_str()) {
            return Err(denied());
        }
        let operation = store
            .operation(&operation_id)
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        let mut authority = self.authority.clone();
        authority.authorize_operation(&principal, &operation, Access::ObserveOperation)?;
        if operation.scope != *scope {
            return Err(stale());
        }
        let actual = store
            .stored_invocation_checked(&operation_id, &step_id, MAX_LOCAL_BYTES as u64, || {
                request
                    .check_local()
                    .map_err(|e| local_storage_error(service_error(e)))
            })
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        if actual != *invocation {
            return Err(stale());
        }
        let durable_claim = claimed_undo_record(store, &operation_id, &step_id, &invocation_id)
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        let claimed_value = serde_json::to_value(claimed).map_err(dto_error)?;
        bounded(&claimed_value, 4 * 1024 * 1024)?;
        if serde_json::to_value(&durable_claim).map_err(dto_error)? != claimed_value {
            return Err(stale());
        }
        let current = self.authority.current_context_with_deadline(
            &principal,
            &context_id,
            request.budget().deadline(),
        )?;
        request.check_local().map_err(service_error)?;
        let guard = self.begin(&principal, &current)?;
        validate_current_source_context(&actual["context"], &current)?;
        authorize_original(&guard, &operation)?;
        let source_operation = store
            .operation(&durable_claim.source_operation_id)
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        authorize_original(&guard, &source_operation)?;
        if source_operation.scope != durable_claim.scope {
            return Err(stale());
        }
        let source_scope = serde_json::to_value(&source_operation.scope).map_err(dto_error)?;
        let source = store
            .stored_invocation_checked(
                &durable_claim.source_operation_id,
                &durable_claim.source_step_id,
                MAX_LOCAL_BYTES as u64,
                || guard.check(&source_scope).map_err(local_storage_error),
            )
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        validate_current_source_context(&source["context"], &current)?;
        let source_blob = store
            .stored_invocation_blob(
                &durable_claim.source_operation_id,
                &durable_claim.source_step_id,
            )
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        if source_blob.digest != durable_claim.source_invocation_digest
            || source_operation.plan_hash != durable_claim.source_plan_hash
        {
            return Err(stale());
        }
        let source_plan = store
            .plan(&source_operation.plan_id, &source_operation.plan_hash)
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        bounded(&source_plan, MAX_LOCAL_BYTES)?;
        let source_step = exact_step(&source_plan, durable_claim.source_step_id.as_str())?;
        validate_plan_step(&source_plan, source_step, &source["context"], &source_scope)?;
        validate_original_step(source_step, &source)?;
        let route_bytes = store
            .read_blob_checked(&durable_claim.route_blob, MAX_RESPONSE_BYTES as u64, || {
                guard.check(&source_scope).map_err(local_storage_error)
            })
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        let route_value = parse_json_with_limits(
            &route_bytes,
            JsonLimits {
                max_bytes: MAX_RESPONSE_BYTES,
                max_depth: 64,
                max_nodes: 100_000,
            },
        )
        .map_err(|e| {
            AppError::caused_by(
                "RECOVERY_EXPIRED",
                "Retained registered undo route is invalid",
                e,
            )
        })?;
        if canonical_digest(&route_value).map_err(digest_error)? != durable_claim.route_digest {
            return Err(stale());
        }
        let route: RegisteredUndoRoute = decode(&route_value)?;
        validate_source_descriptor(source_step, &source["context"], &route.source_action)?;
        let undo_plan = store
            .plan(&operation.plan_id, &operation.plan_hash)
            .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
        bounded(&undo_plan, MAX_LOCAL_BYTES)?;
        let undo_step = exact_step(&undo_plan, step_id.as_str())?;
        validate("ActionDescriptor", &route.undo_action)?;
        validate_source_descriptor(undo_step, &actual["context"], &route.undo_action)?;
        if route.undo_binding_id.as_str() != text(&actual, "bindingId")?
            || route.source_binding_id.as_str() != text(&source, "bindingId")?
            || route.source_action["actionId"] != source["actionId"]
            || canonical_digest(&route.source_action)
                .map_err(digest_error)?
                .as_str()
                != text(&source, "actionDigest")?
            || durable_claim.source_invocation_id.as_str() != text(&source, "invocationId")?
            || durable_claim.source_context != source["context"]
        {
            return Err(stale());
        }
        guard.check(&source_scope)?;
        let acquired = self.hosts.inspect_original_acquired_with_deadline(
            store,
            &principal,
            &actual,
            &current,
            json!({"kind":"undo_job","invocationId":actual["invocationId"]}),
            guard.budget.deadline(),
        )?;
        let response = acquired.into_acquired_response()?;
        let payload = match host_payload(&response, false) {
            Ok(payload) => payload.ok_or_else(invalid)?,
            Err(failure) => {
                // A closed actual host error is also original observed truth.
                retain_job_response(store, &operation_id, &response)?;
                return Err(failure);
            }
        };
        let job = validate_job(
            &payload,
            &actual,
            &source,
            &durable_claim.receipt,
            &route.undo_action,
        )?;
        // The actual closed public DTO is now captured truth. Retain one bounded
        // response under the same operation even if its caller budget just ended.
        // This local evidence pin grants no resource marker or future mutation.
        let evidence = retain_job_response(store, &operation_id, &response)?;
        guard.check(&source_scope)?;
        authorize_original(&guard, &operation)?;
        // SDK executor facts are useful evidence, but this composition has no
        // admitted original source locator→fresh full target producer for an
        // arbitrary registered Recover callback. It cannot assert world settled.
        Err(AppError::caused_by(
            "CAPABILITY_UNAVAILABLE",
            "Registered undo needs independent full source target observation",
            RetainedJobUnavailable {
                evidence,
                executor_state: job.executor_state,
            },
        ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UndoJobDto {
    format: String,
    invocation: Value,
    invocation_digest: Sha256Digest,
    source_invocation: Option<Value>,
    source_receipt: Option<Value>,
    callback_entered: bool,
    mutation_started: bool,
    cancellation_requested: bool,
    polling: bool,
    raw_callback_settled: bool,
    raw_callback_failed: bool,
    context_closed: bool,
    pending_game_thread_tasks: u32,
    provider_job_outstanding: bool,
    executor_state: String,
}
fn validate_job(
    payload: &Value,
    invocation: &Value,
    source: &Value,
    receipt: &Value,
    undo_action: &Value,
) -> AppResult<UndoJobDto> {
    bounded(payload, MAX_RESPONSE_BYTES)?;
    exact_fields(
        payload,
        &[
            "format",
            "invocation",
            "invocationDigest",
            "sourceInvocation",
            "sourceReceipt",
            "callbackEntered",
            "mutationStarted",
            "cancellationRequested",
            "polling",
            "rawCallbackSettled",
            "rawCallbackFailed",
            "contextClosed",
            "pendingGameThreadTasks",
            "providerJobOutstanding",
            "executorState",
        ],
    )?;
    let job: UndoJobDto = decode(payload)?;
    let source_receipt = validate_receipt(receipt, source, None, text(receipt, "playerId")?)?;
    if job.format != "mmmm.host.undo-job/1"
        || job.invocation != *invocation
        || job.invocation_digest != canonical_digest(invocation).map_err(digest_error)?
        || job.pending_game_thread_tasks > i32::MAX as u32
        || job.mutation_started && !job.callback_entered
        || job.raw_callback_failed && !job.raw_callback_settled
    {
        return Err(stale());
    }
    if source_receipt.undo_action_id.as_str() != text(undo_action, "actionId")?
        || invocation["actionId"] != undo_action["actionId"]
        || invocation["arguments"]["tokenRecordId"] != receipt["tokenRecordId"]
        || invocation["arguments"]["tokenRecordDigest"] != receipt["tokenRecordDigest"]
        || invocation["arguments"]["sourceOperationId"] != source["operationId"]
        || invocation["arguments"]["sourceStepId"] != source["stepId"]
        || invocation["arguments"]["sourceInvocationId"] != source["invocationId"]
    {
        return Err(stale());
    }
    match (&job.source_invocation, &job.source_receipt) {
        (Some(actual_source), Some(actual_receipt))
            if actual_source == source && actual_receipt == receipt => {}
        (None, None) if !job.callback_entered && !job.mutation_started => (),
        _ => return Err(stale()),
    }
    // Cancellation is a recorded request, not proof of stopped effects.
    let _cancellation_requested = job.cancellation_requested;
    match job.executor_state.as_str() {
        "synchronous_quiescent"
            if job.callback_entered
                && job.raw_callback_settled
                && job.context_closed
                && job.pending_game_thread_tasks == 0
                && !job.polling
                && !job.provider_job_outstanding
                && undo_action["completion"] == "synchronous"
                && job.source_invocation.is_some() => {}
        "not_entered" if !job.callback_entered && !job.mutation_started => (),
        "running" if !job.context_closed => (),
        "unknown" => (),
        _ => return Err(stale()),
    }
    Ok(job)
}
fn retain_job_response(
    store: &mut DurableStore,
    operation: &OperationId,
    response: &Value,
) -> AppResult<BlobRef> {
    let retain_until = std::time::Instant::now() + std::time::Duration::from_secs(30);
    bounded(response, MAX_RESPONSE_BYTES)?;
    let bytes = encode_json(response).map_err(|e| {
        AppError::caused_by("INVALID_INPUT", "Undo job evidence encoding failed", e)
    })?;
    if bytes.len() > MAX_RESPONSE_BYTES || std::time::Instant::now() >= retain_until {
        return Err(limit());
    }
    let evidence = store
        .put_blob(&bytes)
        .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
    store
        .append_operation_evidence(operation, &evidence)
        .map_err(|e| AppError::storage("RECOVERY_EXPIRED", e))?;
    if std::time::Instant::now() >= retain_until {
        return Err(limit());
    }
    Ok(evidence)
}
#[derive(Debug)]
struct RetainedJobUnavailable {
    evidence: BlobRef,
    executor_state: String,
}
impl std::fmt::Display for RetainedJobUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Independent target mapping is unavailable; original {} executor evidence is retained at {}",
            self.executor_state, self.evidence.digest
        )
    }
}
impl std::error::Error for RetainedJobUnavailable {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RoleCore {
    binding_id: BindingId,
    action_id: ActionId,
    selected_action: Value,
    selected_action_digest: Sha256Digest,
    provider_origin: Value,
    role: String,
    registration_generation: Sha256Digest,
    routes: Vec<RegisteredUndoRoute>,
}
fn validate_role_wrapper(
    wrapper: &Value,
    step: &Value,
    context: &Value,
    descriptor: &Value,
    hello: &Value,
    facts: &Value,
) -> AppResult<InspectedUndoRoles> {
    bounded(wrapper, MAX_RESPONSE_BYTES)?;
    exact_fields(
        wrapper,
        &[
            "registration",
            "contextId",
            "contextDigest",
            "environment",
            "runtimeSourceFactsDigest",
            "hostArtifactDigest",
            "registryGeneration",
            "observedFromTick",
            "observedToTick",
            "observedAt",
        ],
    )?;
    if wrapper["contextId"] != context["contextId"]
        || wrapper["contextDigest"] != context["contextDigest"]
        || wrapper["environment"] != context["environment"]
        || hello["environment"] != context["environment"]
        || facts["environment"] != context["environment"]
        || wrapper["runtimeSourceFactsDigest"] != source_facts_pin(facts)?.as_str()
        || wrapper["hostArtifactDigest"] != hello["hostBuild"]
        || wrapper["registryGeneration"] != facts["registryGeneration"]
    {
        return Err(stale());
    }
    let _: Sha256Digest = decode(&wrapper["hostArtifactDigest"])?;
    canonical_counter(text(wrapper, "registryGeneration")?, i64::MAX as u64)?;
    let from = canonical_counter(text(wrapper, "observedFromTick")?, u32::MAX as u64)?;
    let to = canonical_counter(text(wrapper, "observedToTick")?, u32::MAX as u64)?;
    if from > to
        || time::OffsetDateTime::parse(
            text(wrapper, "observedAt")?,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
    {
        return Err(invalid());
    }
    validate_role_core(&wrapper["registration"], step, context, descriptor)
}
fn validate_role_core(
    value: &Value,
    step: &Value,
    context: &Value,
    descriptor: &Value,
) -> AppResult<InspectedUndoRoles> {
    bounded(value, MAX_RESPONSE_BYTES)?;
    let core: RoleCore = decode(value)?;
    validate_source_descriptor(step, context, descriptor)?;
    if core.binding_id.as_str() != text(step, "bindingId")?
        || core.action_id.as_str() != text(step, "actionId")?
        || core.selected_action != *descriptor
        || core.selected_action_digest != canonical_digest(descriptor).map_err(digest_error)?
        || !core.provider_origin.is_object()
        || core.routes.len() > 64
    {
        return Err(stale());
    }
    // This is the actual SDK's whole sealed registry-generation SHA. Selected
    // routes alone cannot reproduce it, and it is no Apply/profile capability.
    let _generation = &core.registration_generation;
    let mut source = false;
    let mut inverse = false;
    let mut unique = std::collections::BTreeSet::new();
    for route in &core.routes {
        validate("ActionDescriptor", &route.source_action)?;
        validate("ActionDescriptor", &route.undo_action)?;
        if route.source_binding_id != core.binding_id
            || route.undo_binding_id != core.binding_id
            || route.provider_origin != core.provider_origin
            || route.source_action["recovery"] != "provider_undo"
            || route.source_action["effect"] == "read"
            || route.source_action["verificationRequirement"] != "independent_readback"
            || route.undo_action["recovery"] != "none"
            || route.undo_action["effect"] == "read"
            || route.undo_action["verificationRequirement"] != "independent_readback"
            || route.source_action["actionId"] == route.undo_action["actionId"]
            || route.source_action["side"] != context["environment"]["side"]
            || route.undo_action["side"] != context["environment"]["side"]
            || !unique.insert(
                canonical_digest(&serde_json::to_value(route).map_err(dto_error)?)
                    .map_err(digest_error)?,
            )
        {
            return Err(stale());
        }
        let selected_source = route.source_action["actionId"] == core.action_id.as_str();
        let selected_inverse = route.undo_action["actionId"] == core.action_id.as_str();
        if !selected_source && !selected_inverse {
            return Err(stale());
        }
        if selected_source && route.source_action != *descriptor
            || selected_inverse && route.undo_action != *descriptor
        {
            return Err(stale());
        }
        source |= selected_source;
        inverse |= selected_inverse;
    }
    let selected_role = match core.role.as_str() {
        // Ordinary is a positive sealed SDK proof, not an empty local lookup.
        // SDK also rejects every unlinked provider_undo or Recover callback.
        "ordinary"
            if !source
                && !inverse
                && core.routes.is_empty()
                && descriptor["recovery"] != "provider_undo" =>
        {
            UndoActionRole::Ordinary
        }
        "source" if source && !inverse && descriptor["recovery"] == "provider_undo" => {
            UndoActionRole::Source
        }
        "recovery_only"
            if inverse
                && !source
                && descriptor["recovery"] == "none"
                && descriptor["effect"] != "read" =>
        {
            UndoActionRole::RecoveryOnly
        }
        "unknown" | "unsupported" => {
            return Err(AppError::new(
                "CAPABILITY_UNAVAILABLE",
                "Actual host Registrar role metadata is unavailable",
            ));
        }
        _ => return Err(stale()),
    };
    Ok(InspectedUndoRoles {
        selected_role,
        routes: core.routes,
    })
}
fn canonical_counter(text: &str, maximum: u64) -> AppResult<u64> {
    let value = text.parse::<u64>().map_err(|_| invalid())?;
    if value > maximum || value.to_string() != text {
        return Err(invalid());
    }
    Ok(value)
}
fn exact_fields(value: &Value, fields: &[&str]) -> AppResult<()> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object.len() != fields.len() || fields.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid());
    }
    Ok(())
}

struct InspectionGuard {
    request_witness: RequestContextWitness,
    authority: LocalAuthority,
    authenticated: AuthenticatedPrincipal,
    budget: RequestBudget,
    paired: HostContextWitness,
    context: Value,
    id: ContextId,
    project: ProjectId,
    policy: Sha256Digest,
}
impl InspectionGuard {
    fn check_received(&self, scope: &Value, response: &Value) -> AppResult<()> {
        self.check(scope).map_err(|cause| {
            AppError::caused_by(
                cause.code,
                cause.message,
                ReceivedMetadataInterrupted {
                    cause,
                    response: response.clone(),
                },
            )
        })
    }
    /// Local only: safe at the supplied store's checked CAS checkpoints. The
    /// native context was actually observed before material acquisition.
    fn check(&self, scope: &Value) -> AppResult<()> {
        self.request_witness.check_local().map_err(service_error)?;
        if !self.authenticated.permits_context(self.id.as_str())
            || crate::peer::fatal_stop_requested()
        {
            return Err(denied());
        }
        self.budget.check().map_err(service_error)?;
        self.paired.check_local()?;
        self.authority.authorize_retained_scope(
            self.authenticated.principal(),
            &self.project,
            &self.id,
            &self.policy,
            scope,
        )?;
        self.authority.authorize_retained_scope(
            self.authenticated.principal(),
            &self.project,
            &self.id,
            &self.policy,
            &self.context["scope"],
        )?;
        self.paired.check_local()?;
        self.budget.check().map_err(service_error)
    }
}
fn authorize_original(guard: &InspectionGuard, record: &OperationRecord) -> AppResult<()> {
    guard.check(&guard.context["scope"])?;
    if record.project_id != guard.project {
        return Err(denied());
    }
    let mut authority = guard.authority.clone();
    authority.authorize_operation(
        guard.authenticated.principal(),
        record,
        Access::ObserveOperation,
    )?;
    guard.check(&serde_json::to_value(&record.scope).map_err(dto_error)?)
}

fn validate_plan_step(
    plan: &Value,
    step: &Value,
    context: &Value,
    full_scope: &Value,
) -> AppResult<()> {
    validate("ExecutionPlan", plan)?;
    validate("PlanStep", step)?;
    verify_projected_digest("ExecutionPlan", plan).map_err(digest_error)?;
    if plan["projectId"] != context["projectId"]
        || plan["policyRevision"] != context["policyRevision"]
        || step["contextId"] != context["contextId"]
        || plan["scope"] != *full_scope
        || exact_step(plan, text(step, "stepId")?)? != step
    {
        return Err(stale());
    }
    let pins = plan["contextPins"]
        .as_array()
        .filter(|v| v.len() <= 128)
        .ok_or_else(invalid)?;
    let selected: Vec<&Value> = pins
        .iter()
        .filter(|pin| pin["contextId"] == step["contextId"])
        .collect();
    let [pin] = selected.as_slice() else {
        return Err(stale());
    };
    if pin["contextDigest"] != context["contextDigest"]
        || pin["environment"] != context["environment"]
    {
        return Err(stale());
    }
    Ok(())
}
fn exact_step<'a>(plan: &'a Value, id: &str) -> AppResult<&'a Value> {
    let steps = plan["steps"]
        .as_array()
        .filter(|v| v.len() <= MAX_STEPS)
        .ok_or_else(invalid)?;
    let mut selected = steps.iter().filter(|step| step["stepId"] == id);
    let step = selected.next().ok_or_else(stale)?;
    if selected.next().is_some() {
        return Err(stale());
    }
    Ok(step)
}
fn validate_original_step(step: &Value, original: &Value) -> AppResult<()> {
    for key in [
        "stepId",
        "bindingId",
        "actionId",
        "actionContractVersion",
        "actionDigest",
        "implementationDigest",
    ] {
        if step[key] != original[key] {
            return Err(stale());
        }
    }
    if step["contextId"] != original["context"]["contextId"]
        || step["recovery"] != "provider_undo"
        || step["verificationRequirement"] != "independent_readback"
        || original["argumentsDigest"]
            != canonical_digest(&original["arguments"])
                .map_err(digest_error)?
                .as_str()
        || original["contextDigest"]
            != verify_projected_digest("ExecutionContext", &original["context"])
                .map_err(digest_error)?
                .as_str()
    {
        return Err(stale());
    }
    Ok(())
}
fn validate_current_source_context(original: &Value, current: &Value) -> AppResult<()> {
    validate("ExecutionContext", original)?;
    validate("ExecutionContext", current)?;
    verify_projected_digest("ExecutionContext", original).map_err(digest_error)?;
    verify_projected_digest("ExecutionContext", current).map_err(digest_error)?;
    let mut original = original.clone();
    let mut current = current.clone();
    for field in ["policyRevision", "contextDigest"] {
        original.as_object_mut().ok_or_else(invalid)?.remove(field);
        current.as_object_mut().ok_or_else(invalid)?.remove(field);
    }
    if original != current {
        return Err(stale());
    }
    Ok(())
}
fn validate_source_descriptor(step: &Value, context: &Value, descriptor: &Value) -> AppResult<()> {
    bounded(descriptor, MAX_RESPONSE_BYTES)?;
    validate("ActionDescriptor", descriptor)?;
    let digest = canonical_digest(descriptor).map_err(digest_error)?;
    if step["contextId"] != context["contextId"]
        || step["actionDigest"] != digest.as_str()
        || descriptor["side"] != context["environment"]["side"]
    {
        return Err(stale());
    }
    for (step_key, descriptor_key) in [
        ("actionId", "actionId"),
        ("actionContractVersion", "contractVersion"),
        ("implementationDigest", "implementationDigest"),
        ("effect", "effect"),
        ("completion", "completion"),
        ("recovery", "recovery"),
        ("verificationRequirement", "verificationRequirement"),
    ] {
        if step[step_key] != descriptor[descriptor_key] {
            return Err(stale());
        }
    }
    Ok(())
}
fn validate_registration(
    payload: &Value,
    step: &Value,
    descriptor: &Value,
) -> AppResult<HostUndoRegistration> {
    bounded(payload, MAX_RESPONSE_BYTES)?;
    let route: HostUndoRegistration = decode(payload)?;
    validate("ActionDescriptor", &route.undo_action)?;
    if route.binding_id.as_str() != text(step, "bindingId")?
        || route.source_action_id.as_str() != text(step, "actionId")?
        || route.source_action_digest != canonical_digest(descriptor).map_err(digest_error)?
        || route.source_action_digest.as_str() != text(step, "actionDigest")?
        || route.source_implementation_digest.as_str() != text(descriptor, "implementationDigest")?
        || route.source_implementation_digest.as_str() != text(step, "implementationDigest")?
        || route.undo_action_digest != canonical_digest(&route.undo_action).map_err(digest_error)?
        || descriptor["recovery"] != "provider_undo"
        || descriptor["effect"] == "read"
        || descriptor["verificationRequirement"] != "independent_readback"
        || route.undo_action["effect"] == "read"
        || route.undo_action["recovery"] != "none"
        || route.undo_action["verificationRequirement"] != "independent_readback"
        || route.undo_action["actionId"] == descriptor["actionId"]
        || route.undo_action["side"] != descriptor["side"]
        || !route.provider_origin.is_object()
    {
        return Err(stale());
    }
    Ok(route)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MaterialDto {
    authenticated_player_id: String,
    source_invocation: Value,
    registration: Option<Value>,
    receipt: Option<Value>,
}
fn validate_source_material(
    payload: &Value,
    original: &Value,
    step: &Value,
    descriptor: &Value,
) -> AppResult<Option<InspectedHostUndoMaterial>> {
    bounded(payload, MAX_RESPONSE_BYTES)?;
    let object = payload.as_object().ok_or_else(invalid)?;
    if object.len() != 4
        || [
            "authenticatedPlayerId",
            "sourceInvocation",
            "registration",
            "receipt",
        ]
        .iter()
        .any(|key| !object.contains_key(*key))
    {
        return Err(invalid());
    }
    let material: MaterialDto = decode(payload)?;
    validate("Invocation", &material.source_invocation)?;
    if material.source_invocation != *original || !canonical_uuid(&material.authenticated_player_id)
    {
        return Err(stale());
    }
    let registration = material
        .registration
        .as_ref()
        .map(|value| validate_registration(value, step, descriptor))
        .transpose()?;
    let receipt = material
        .receipt
        .as_ref()
        .map(|value| {
            validate_receipt(
                value,
                original,
                registration.as_ref(),
                &material.authenticated_player_id,
            )
        })
        .transpose()?;
    let (Some(registration), Some(receipt)) = (registration, receipt) else {
        return Ok(None);
    };
    Ok(Some(InspectedHostUndoMaterial {
        registration,
        receipt,
        authenticated_player_id: material.authenticated_player_id,
    }))
}
fn validate_receipt(
    value: &Value,
    original: &Value,
    registration: Option<&HostUndoRegistration>,
    player: &str,
) -> AppResult<HostUndoReceipt> {
    bounded(value, MAX_RECEIPT_BYTES)?;
    let receipt: HostUndoReceipt = decode(value)?;
    let mut projection = value.clone();
    projection
        .as_object_mut()
        .ok_or_else(invalid)?
        .remove("tokenRecordDigest");
    if receipt.token_record_digest != canonical_digest(&projection).map_err(digest_error)?
        || receipt.contract_version != mmmm_contracts::CONTRACT_VERSION
        || receipt.player_id != player
        || receipt.source_context != original["context"]
        || receipt.source_context["environment"]["kind"] != "game"
        || receipt.principal_ref.as_str() != text(&original["context"], "principalRef")?
        || receipt.session_epoch != text(&original["context"]["environment"], "sessionEpoch")?
        || receipt.game_instance_id != text(&original["context"]["environment"], "gameInstanceId")?
        || receipt.side != text(&original["context"]["environment"], "side")?
        || receipt.binding_id.as_str() != text(original, "bindingId")?
        || receipt.source_action_id.as_str() != text(original, "actionId")?
        || receipt.source_action_digest.as_str() != text(original, "actionDigest")?
        || receipt.source_implementation_digest.as_str() != text(original, "implementationDigest")?
        || receipt.source_arguments_digest.as_str() != text(original, "argumentsDigest")?
        || receipt.source_context_digest.as_str() != text(original, "contextDigest")?
        || receipt.source_operation_id.as_str() != text(original, "operationId")?
        || receipt.source_step_id.as_str() != text(original, "stepId")?
        || receipt.source_invocation_id.as_str() != text(original, "invocationId")?
    {
        return Err(stale());
    }
    if let Some(route) = registration
        && receipt.undo_action_id.as_str() != text(&route.undo_action, "actionId")?
    {
        return Err(stale());
    }
    Ok(receipt)
}

// Local error cause keeps the closed actual HostResponse. Debug/Display do not
// print its untrusted text or any values, and no private token DTO is accepted.
struct HostReplyFailure {
    response: Value,
}
impl std::fmt::Debug for HostReplyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Canonical HostResponse status is a fixed enum, not source diagnostic text.
        f.debug_struct("HostReplyFailure")
            .field(
                "status",
                &self.response.get("status").and_then(Value::as_str),
            )
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for HostReplyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("The actual host returned a closed undo inspection error")
    }
}
impl std::error::Error for HostReplyFailure {}
struct ReceivedMetadataInterrupted {
    cause: AppError,
    response: Value,
}
impl std::fmt::Debug for ReceivedMetadataInterrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivedMetadataInterrupted")
            .field("code", &self.cause.code)
            .field(
                "status",
                &self.response.get("status").and_then(Value::as_str),
            )
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for ReceivedMetadataInterrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.cause.fmt(f)
    }
}
impl std::error::Error for ReceivedMetadataInterrupted {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
fn host_payload(response: &Value, absent_registration: bool) -> AppResult<Option<Value>> {
    bounded(response, MAX_RESPONSE_BYTES)?;
    validate("HostResponse", response)?;
    if response["status"] == "ok" {
        return Ok(Some(response.get("payload").ok_or_else(invalid)?.clone()));
    }
    if absent_registration && response["error"]["code"] == "RECOVERY_UNSUPPORTED" {
        return Ok(None);
    }
    Err(AppError::caused_by(
        "HOST_REQUEST_FAILED",
        "The original host rejected the undo inspection",
        HostReplyFailure {
            response: response.clone(),
        },
    ))
}
fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn bounded(value: &Value, max_bytes: usize) -> AppResult<()> {
    let mut pending = vec![(value, 1usize)];
    let mut nodes = 0usize;
    let mut text_bytes = 0usize;
    while let Some((current, depth)) = pending.pop() {
        nodes += 1;
        if nodes > 100_000 || depth > 64 {
            return Err(limit());
        }
        match current {
            Value::String(text) => {
                text_bytes = text_bytes
                    .checked_add(text.len())
                    .filter(|n| *n <= max_bytes)
                    .ok_or_else(limit)?;
            }
            Value::Array(items) => {
                if items.len() > 100_000 - nodes || pending.len() > 100_000 - nodes - items.len() {
                    return Err(limit());
                }
                pending.extend(items.iter().map(|child| (child, depth + 1)));
            }
            Value::Object(object) => {
                if object.len() > 100_000 - nodes || pending.len() > 100_000 - nodes - object.len()
                {
                    return Err(limit());
                }
                for (key, child) in object {
                    text_bytes = text_bytes
                        .checked_add(key.len())
                        .filter(|n| *n <= max_bytes)
                        .ok_or_else(limit)?;
                    pending.push((child, depth + 1));
                }
            }
            _ => (),
        }
    }
    let bytes = encode_json(value).map_err(|e| {
        AppError::caused_by("INVALID_INPUT", "Undo inspection JSON encoding failed", e)
    })?;
    parse_json_with_limits(
        &bytes,
        JsonLimits {
            max_bytes,
            max_depth: 64,
            max_nodes: 100_000,
        },
    )
    .map(|_| ())
    .map_err(|e| {
        AppError::caused_by(
            "BUDGET_EXCEEDED",
            "Undo inspection exceeds its finite JSON budget",
            e,
        )
    })
}
fn validate(definition: &str, value: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .map_err(|e| {
            AppError::caused_by(
                "INVALID_INPUT",
                "Canonical undo validator is unavailable",
                e,
            )
        })?
        .validate(definition, value)
        .map_err(|e| {
            AppError::caused_by("INVALID_INPUT", "Canonical undo DTO validation failed", e)
        })
}
fn decode<T: DeserializeOwned>(value: &Value) -> AppResult<T> {
    serde_json::from_value(value.clone()).map_err(dto_error)
}
fn dto_error(error: serde_json::Error) -> AppError {
    AppError::caused_by("INVALID_INPUT", "Closed undo DTO validation failed", error)
}
fn digest_error(error: mmmm_contracts::DigestError) -> AppError {
    AppError::caused_by(
        "RECOVERY_EXPIRED",
        "Undo source digest validation failed",
        error,
    )
}
fn service_error(error: ServiceError) -> AppError {
    AppError::caused_by(error.code, error.message, error)
}
fn local_storage_error(error: AppError) -> StorageError {
    StorageError::InvalidTransition(error.to_string())
}
fn text<'a>(value: &'a Value, key: &str) -> AppResult<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(invalid)
}
fn denied() -> AppError {
    AppError::new(
        "PERMISSION_REQUIRED",
        "Current authenticated undo inspection is not authorized",
    )
}
fn stale() -> AppError {
    AppError::new(
        "RECOVERY_EXPIRED",
        "Undo inspection differs from its actual original stored source or host route",
    )
}
fn invalid() -> AppError {
    AppError::new(
        "INVALID_INPUT",
        "Undo inspection does not match its closed DTO",
    )
}
fn limit() -> AppError {
    AppError::new(
        "BUDGET_EXCEEDED",
        "Undo inspection exceeds its finite JSON budget",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    // Existing original handoff examples provide the common wire shapes. The
    // small added DTO variations inspect boundaries absent from those examples;
    // they do not create authentication or prove native game acceptance.
    fn fixture() -> (Value, Value, Value, Value, Value) {
        let provider: Value =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/provider-supported.json"))
                .unwrap();
        let mut source = provider["actions"][0].clone();
        source["effect"] = json!("write");
        source["recovery"] = json!("provider_undo");
        source["verificationRequirement"] = json!("independent_readback");
        let mut undo = source.clone();
        undo["actionId"] = json!("fixture:undo_text");
        undo["recovery"] = json!("none");
        let mut original: Value =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/invocation.json"))
                .unwrap();
        original["actionDigest"] = json!(canonical_digest(&source).unwrap());
        let mut plan: Value =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/execution-plan.json"))
                .unwrap();
        plan["steps"][0]["effect"] = json!("write");
        plan["steps"][0]["recovery"] = json!("provider_undo");
        plan["steps"][0]["verificationRequirement"] = json!("independent_readback");
        plan["steps"][0]["actionDigest"] = original["actionDigest"].clone();
        rehash_plan(&mut plan);
        let registration = json!({"bindingId":original["bindingId"],"sourceActionId":original["actionId"],
            "sourceActionDigest":original["actionDigest"],"sourceImplementationDigest":original["implementationDigest"],
            "undoActionDigest":canonical_digest(&undo).unwrap(),"undoAction":undo,"providerOrigin":provider["origin"]});
        let mut receipt = json!({"contractVersion":"0.2.0","tokenRecordId":"undo-fixture-original",
            "principalRef":original["context"]["principalRef"],"sessionEpoch":original["context"]["environment"]["sessionEpoch"],
            "gameInstanceId":original["context"]["environment"]["gameInstanceId"],"side":original["context"]["environment"]["side"],
            "playerId":"123e4567-e89b-12d3-a456-426614174000","bindingId":original["bindingId"],
            "sourceActionId":original["actionId"],"sourceActionDigest":original["actionDigest"],
            "sourceImplementationDigest":original["implementationDigest"],"sourceArgumentsDigest":original["argumentsDigest"],
            "sourceContextDigest":original["contextDigest"],"sourceOperationId":original["operationId"],"sourceStepId":original["stepId"],
            "sourceInvocationId":original["invocationId"],"undoActionId":"fixture:undo_text","sourceContext":original["context"],
            "privateTokenSha256":"0000000000000000000000000000000000000000000000000000000000000000"});
        rehash_receipt(&mut receipt);
        let material = json!({"authenticatedPlayerId":receipt["playerId"],"sourceInvocation":original,"registration":registration,"receipt":receipt});
        (source, plan, original, registration, material)
    }
    fn rehash_plan(plan: &mut Value) {
        let mut projection = plan.clone();
        projection.as_object_mut().unwrap().remove("planHash");
        plan["planHash"] = json!(canonical_digest(&projection).unwrap());
    }
    fn rehash_receipt(receipt: &mut Value) {
        let mut projection = receipt.clone();
        projection
            .as_object_mut()
            .unwrap()
            .remove("tokenRecordDigest");
        receipt["tokenRecordDigest"] = json!(canonical_digest(&projection).unwrap());
    }
    fn failure(code: &str) -> Value {
        json!({"protocolVersion":"0.2.0","requestId":"request-undo-fixture","eventSequence":"0","status":"error",
            "error":{"code":code,"message":"untrusted-diagnostic-marker","subjectId":null,"retry":"never","effects":"none_confirmed","evidenceRefs":[]}})
    }

    #[test]
    fn closed_source_material_accepts_public_receipt_without_private_token_contents() {
        let (source, plan, original, registration, material) = fixture();
        let step = &plan["steps"][0];
        validate_source_descriptor(step, &original["context"], &source).unwrap();
        validate_plan_step(&plan, step, &original["context"], &plan["scope"]).unwrap();
        validate_original_step(step, &original).unwrap();
        validate_registration(&registration, step, &source).unwrap();
        let inspected = validate_source_material(&material, &original, step, &source)
            .unwrap()
            .unwrap();
        assert_eq!(
            inspected.receipt.source_invocation_id.as_str(),
            original["invocationId"].as_str().unwrap()
        );
        assert_eq!(
            inspected.authenticated_player_id,
            "123e4567-e89b-12d3-a456-426614174000"
        );
        assert!(material.get("privateToken").is_none());
    }

    #[test]
    fn absent_receipt_or_registration_stays_unavailable_and_missing_fields_are_invalid() {
        let (source, plan, original, _, material) = fixture();
        for field in ["registration", "receipt"] {
            let mut absent = material.clone();
            absent[field] = Value::Null;
            assert!(
                validate_source_material(&absent, &original, &plan["steps"][0], &source)
                    .unwrap()
                    .is_none()
            );
            absent.as_object_mut().unwrap().remove(field);
            assert_eq!(
                validate_source_material(&absent, &original, &plan["steps"][0], &source)
                    .unwrap_err()
                    .code,
                "INVALID_INPUT"
            );
        }
    }

    #[test]
    fn unknown_private_material_fields_are_rejected_at_each_closed_boundary() {
        let (source, plan, original, registration, material) = fixture();
        for field in ["privateToken", "providerToken", "unexpected"] {
            let mut changed = registration.clone();
            changed[field] = json!({});
            assert_eq!(
                validate_registration(&changed, &plan["steps"][0], &source)
                    .unwrap_err()
                    .code,
                "INVALID_INPUT"
            );
            let mut changed = material.clone();
            changed[field] = json!({});
            assert_eq!(
                validate_source_material(&changed, &original, &plan["steps"][0], &source)
                    .unwrap_err()
                    .code,
                "INVALID_INPUT"
            );
            let mut changed = material.clone();
            changed["receipt"][field] = json!({});
            assert_eq!(
                validate_source_material(&changed, &original, &plan["steps"][0], &source)
                    .unwrap_err()
                    .code,
                "INVALID_INPUT"
            );
        }
    }

    #[test]
    fn original_wire_is_compared_whole_and_never_reconstructed_from_scalar_ids() {
        let (source, plan, original, _, material) = fixture();
        for field in [
            "invocationId",
            "operationId",
            "stepId",
            "bindingId",
            "idempotencyKey",
        ] {
            let mut changed = material.clone();
            changed["sourceInvocation"][field] = json!("replacement-source");
            assert_eq!(
                validate_source_material(&changed, &original, &plan["steps"][0], &source)
                    .unwrap_err()
                    .code,
                "RECOVERY_EXPIRED"
            );
        }
        let mut changed = material;
        changed["sourceInvocation"]["context"]["executorHandle"] = json!("handle-rebound");
        assert_eq!(
            validate_source_material(&changed, &original, &plan["steps"][0], &source)
                .unwrap_err()
                .code,
            "RECOVERY_EXPIRED"
        );
    }

    #[test]
    fn receipt_identity_tampering_is_rejected_even_after_attacker_rehashes_it() {
        let (source, plan, original, _, material) = fixture();
        for field in [
            "principalRef",
            "sessionEpoch",
            "gameInstanceId",
            "bindingId",
            "sourceOperationId",
            "sourceStepId",
            "sourceInvocationId",
        ] {
            let mut changed = material.clone();
            changed["receipt"][field] = json!("replacement-source");
            rehash_receipt(&mut changed["receipt"]);
            assert_eq!(
                validate_source_material(&changed, &original, &plan["steps"][0], &source)
                    .unwrap_err()
                    .code,
                "RECOVERY_EXPIRED",
                "{field}"
            );
        }
        for field in [
            "sourceActionDigest",
            "sourceImplementationDigest",
            "sourceArgumentsDigest",
            "sourceContextDigest",
        ] {
            let mut changed = material.clone();
            changed["receipt"][field] = json!("0".repeat(64));
            rehash_receipt(&mut changed["receipt"]);
            assert_eq!(
                validate_source_material(&changed, &original, &plan["steps"][0], &source)
                    .unwrap_err()
                    .code,
                "RECOVERY_EXPIRED",
                "{field}"
            );
        }
        let mut changed = material.clone();
        changed["receipt"]["playerId"] = json!("123e4567-e89b-12d3-a456-426614174001");
        rehash_receipt(&mut changed["receipt"]);
        assert_eq!(
            validate_source_material(&changed, &original, &plan["steps"][0], &source)
                .unwrap_err()
                .code,
            "RECOVERY_EXPIRED"
        );
        let mut changed = material;
        changed["receipt"]["sourceContext"]["executorHandle"] = json!("handle-rebound");
        rehash_receipt(&mut changed["receipt"]);
        assert_eq!(
            validate_source_material(&changed, &original, &plan["steps"][0], &source)
                .unwrap_err()
                .code,
            "RECOVERY_EXPIRED"
        );
    }

    #[test]
    fn actual_source_and_undo_descriptor_digests_and_roles_must_match() {
        let (source, plan, _, registration, _) = fixture();
        for field in [
            "sourceActionDigest",
            "sourceImplementationDigest",
            "undoActionDigest",
        ] {
            let mut changed = registration.clone();
            changed[field] = json!("0".repeat(64));
            assert_eq!(
                validate_registration(&changed, &plan["steps"][0], &source)
                    .unwrap_err()
                    .code,
                "RECOVERY_EXPIRED"
            );
        }
        let mut changed = registration.clone();
        changed["undoAction"]["recovery"] = json!("provider_undo");
        changed["undoActionDigest"] = json!(canonical_digest(&changed["undoAction"]).unwrap());
        assert_eq!(
            validate_registration(&changed, &plan["steps"][0], &source)
                .unwrap_err()
                .code,
            "RECOVERY_EXPIRED"
        );
        let mut changed = registration;
        changed["undoAction"]["actionId"] = source["actionId"].clone();
        changed["undoActionDigest"] = json!(canonical_digest(&changed["undoAction"]).unwrap());
        assert_eq!(
            validate_registration(&changed, &plan["steps"][0], &source)
                .unwrap_err()
                .code,
            "RECOVERY_EXPIRED"
        );
    }

    #[test]
    fn stored_step_membership_and_full_plan_scope_cannot_be_substituted() {
        let (_, plan, original, _, _) = fixture();
        let mut changed_step = plan["steps"][0].clone();
        changed_step["arguments"]["text"] = json!("different request");
        assert_eq!(
            validate_plan_step(&plan, &changed_step, &original["context"], &plan["scope"])
                .unwrap_err()
                .code,
            "RECOVERY_EXPIRED"
        );
        let mut duplicate = plan.clone();
        duplicate["steps"]
            .as_array_mut()
            .unwrap()
            .push(plan["steps"][0].clone());
        rehash_plan(&mut duplicate);
        assert_eq!(
            validate_plan_step(
                &duplicate,
                &plan["steps"][0],
                &original["context"],
                &plan["scope"]
            )
            .unwrap_err()
            .code,
            "RECOVERY_EXPIRED"
        );
        let full_scope = plan["scope"].clone();
        let mut wider = plan;
        wider["scope"]["resourceIds"] = json!(["resource-outside-original"]);
        rehash_plan(&mut wider);
        assert_eq!(
            validate_plan_step(
                &wider,
                &wider["steps"][0],
                &original["context"],
                &full_scope
            )
            .unwrap_err()
            .code,
            "RECOVERY_EXPIRED"
        );
    }

    #[test]
    fn actual_host_error_cause_is_preserved_without_diagnostic_values_in_debug() {
        let response = failure("INVOCATION_UNKNOWN");
        let error = host_payload(&response, false).unwrap_err();
        assert_eq!(error.code, "HOST_REQUEST_FAILED");
        let actual = error
            .source()
            .unwrap()
            .downcast_ref::<HostReplyFailure>()
            .unwrap();
        assert_eq!(actual.response, response);
        assert!(!format!("{error:?}").contains("untrusted-diagnostic-marker"));
        assert!(
            host_payload(&failure("RECOVERY_UNSUPPORTED"), true)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            host_payload(&failure("RECOVERY_UNSUPPORTED"), false)
                .unwrap_err()
                .code,
            "HOST_REQUEST_FAILED"
        );
    }

    #[test]
    fn fresh_policy_context_keeps_original_wire_and_requires_same_physical_target() {
        let (_, _, original, _, _) = fixture();
        let mut current = original["context"].clone();
        current["policyRevision"] = json!("0".repeat(64));
        let mut projection = current.clone();
        projection.as_object_mut().unwrap().remove("contextDigest");
        current["contextDigest"] = json!(canonical_digest(&projection).unwrap());
        validate_current_source_context(&original["context"], &current).unwrap();
        let mut changed = current;
        changed["environment"]["sessionEpoch"] = json!("epoch-replacement");
        let mut projection = changed.clone();
        projection.as_object_mut().unwrap().remove("contextDigest");
        changed["contextDigest"] = json!(canonical_digest(&projection).unwrap());
        assert_eq!(
            validate_current_source_context(&original["context"], &changed)
                .unwrap_err()
                .code,
            "RECOVERY_EXPIRED"
        );
    }

    fn role_core(source: &Value, original: &Value, registration: &Value) -> Value {
        json!({"bindingId":original["bindingId"],"actionId":source["actionId"],"selectedAction":source,
            "selectedActionDigest":canonical_digest(source).unwrap(),"providerOrigin":registration["providerOrigin"],"role":"source",
            "registrationGeneration":"0000000000000000000000000000000000000000000000000000000000000000",
            "routes":[{"sourceBindingId":original["bindingId"],"sourceAction":source,"undoBindingId":original["bindingId"],
                "undoAction":registration["undoAction"],"providerOrigin":registration["providerOrigin"]}]})
    }
    fn undo_job_fixture() -> (Value, Value, Value, Value, Value) {
        let (_, _, source, registration, material) = fixture();
        let undo_action = registration["undoAction"].clone();
        let receipt = material["receipt"].clone();
        let mut invocation = source.clone();
        invocation["invocationId"] = json!("invocation-undo");
        invocation["operationId"] = json!("operation-undo");
        invocation["stepId"] = json!("undo-step");
        invocation["actionId"] = undo_action["actionId"].clone();
        invocation["actionDigest"] = json!(canonical_digest(&undo_action).unwrap());
        invocation["arguments"] = json!({"tokenRecordId":receipt["tokenRecordId"],"tokenRecordDigest":receipt["tokenRecordDigest"],
            "sourceOperationId":source["operationId"],"sourceStepId":source["stepId"],"sourceInvocationId":source["invocationId"]});
        invocation["argumentsDigest"] = json!(canonical_digest(&invocation["arguments"]).unwrap());
        let job = json!({"format":"mmmm.host.undo-job/1","invocation":invocation,"invocationDigest":canonical_digest(&invocation).unwrap(),
            "sourceInvocation":source,"sourceReceipt":receipt,"callbackEntered":true,"mutationStarted":true,"cancellationRequested":false,
            "polling":false,"rawCallbackSettled":true,"rawCallbackFailed":false,"contextClosed":true,
            "pendingGameThreadTasks":0,"providerJobOutstanding":false,"executorState":"synchronous_quiescent"});
        (job, invocation, source, receipt, undo_action)
    }

    #[test]
    fn sealed_role_dto_requires_exact_related_descriptors_and_never_guesses_ordinary() {
        let (source, plan, original, registration, _) = fixture();
        let core = role_core(&source, &original, &registration);
        assert_eq!(
            validate_role_core(&core, &plan["steps"][0], &original["context"], &source)
                .unwrap()
                .selected_role,
            UndoActionRole::Source
        );
        let mut inverse = core.clone();
        let undo = &registration["undoAction"];
        inverse["actionId"] = undo["actionId"].clone();
        inverse["selectedAction"] = undo.clone();
        inverse["selectedActionDigest"] = json!(canonical_digest(undo).unwrap());
        inverse["role"] = json!("recovery_only");
        let mut undo_step = plan["steps"][0].clone();
        undo_step["actionId"] = undo["actionId"].clone();
        undo_step["actionDigest"] = json!(canonical_digest(undo).unwrap());
        undo_step["recovery"] = json!("none");
        assert_eq!(
            validate_role_core(&inverse, &undo_step, &original["context"], undo)
                .unwrap()
                .selected_role,
            UndoActionRole::RecoveryOnly
        );
        for changed in [
            {
                let mut c = core.clone();
                c["role"] = json!("ordinary");
                c["routes"] = json!([]);
                c
            },
            {
                let mut c = inverse.clone();
                c["routes"] = json!([]);
                c
            },
            {
                let mut c = core.clone();
                c["selectedActionDigest"] = json!("0".repeat(64));
                c
            },
            {
                let mut c = core.clone();
                c["routes"]
                    .as_array_mut()
                    .unwrap()
                    .push(core["routes"][0].clone());
                c
            },
        ] {
            let selected = if changed["actionId"] == undo["actionId"] {
                (&undo_step, undo)
            } else {
                (&plan["steps"][0], &source)
            };
            assert_eq!(
                validate_role_core(&changed, selected.0, &original["context"], selected.1)
                    .err()
                    .unwrap()
                    .code,
                "RECOVERY_EXPIRED"
            );
        }
        let mut unknown = core;
        unknown["role"] = json!("unknown");
        assert_eq!(
            validate_role_core(&unknown, &plan["steps"][0], &original["context"], &source)
                .err()
                .unwrap()
                .code,
            "CAPABILITY_UNAVAILABLE"
        );
    }

    #[test]
    fn role_attestation_wrapper_pins_actual_context_artifact_source_and_native_counters() {
        let (source, plan, original, registration, _) = fixture();
        let facts = json!({"format":"mmmm.native.source-facts/1","registryGeneration":"3","environment":original["context"]["environment"],"observedAt":"2026-10-14T00:00:00Z"});
        let hello = json!({"hostBuild":"0000000000000000000000000000000000000000000000000000000000000000","environment":original["context"]["environment"]});
        let wrapper = json!({"registration":role_core(&source,&original,&registration),"contextId":original["context"]["contextId"],
            "contextDigest":original["context"]["contextDigest"],"environment":original["context"]["environment"],
            "runtimeSourceFactsDigest":source_facts_pin(&facts).unwrap(),"hostArtifactDigest":hello["hostBuild"],"registryGeneration":"3",
            "observedFromTick":"5","observedToTick":"6","observedAt":"2026-10-14T00:00:00Z"});
        validate_role_wrapper(
            &wrapper,
            &plan["steps"][0],
            &original["context"],
            &source,
            &hello,
            &facts,
        )
        .unwrap();
        for (key, value) in [
            ("contextId", json!("context-rebound")),
            ("hostArtifactDigest", json!("1".repeat(64))),
            ("runtimeSourceFactsDigest", json!("1".repeat(64))),
            ("registryGeneration", json!("4")),
            ("observedFromTick", json!("05")),
            ("observedToTick", json!("4294967296")),
            ("observedAt", json!("unknown")),
        ] {
            let mut changed = wrapper.clone();
            changed[key] = value;
            assert!(
                validate_role_wrapper(
                    &changed,
                    &plan["steps"][0],
                    &original["context"],
                    &source,
                    &hello,
                    &facts
                )
                .is_err(),
                "{key}"
            );
        }
        let mut changed = wrapper;
        changed["verifiedTarget"] = json!(true);
        assert_eq!(
            validate_role_wrapper(
                &changed,
                &plan["steps"][0],
                &original["context"],
                &source,
                &hello,
                &facts
            )
            .err()
            .unwrap()
            .code,
            "INVALID_INPUT"
        );
    }

    #[test]
    fn synchronous_executor_observation_rejects_pending_work_and_generic_async_completion() {
        let (job, invocation, source, receipt, undo) = undo_job_fixture();
        assert_eq!(
            validate_job(&job, &invocation, &source, &receipt, &undo)
                .unwrap()
                .executor_state,
            "synchronous_quiescent"
        );
        for (key, value) in [
            ("providerJobOutstanding", json!(true)),
            ("polling", json!(true)),
            ("rawCallbackSettled", json!(false)),
            ("contextClosed", json!(false)),
            ("pendingGameThreadTasks", json!(1)),
            ("callbackEntered", json!(false)),
        ] {
            let mut changed = job.clone();
            changed[key] = value;
            assert_eq!(
                validate_job(&changed, &invocation, &source, &receipt, &undo)
                    .err()
                    .unwrap()
                    .code,
                "RECOVERY_EXPIRED",
                "{key}"
            );
        }
        let mut asynchronous = undo.clone();
        asynchronous["completion"] = json!("job");
        assert_eq!(
            validate_job(&job, &invocation, &source, &receipt, &asynchronous)
                .err()
                .unwrap()
                .code,
            "RECOVERY_EXPIRED"
        );
        // Raw failure remains truth even when this executor is quiescent. The
        // DTO validator does not construct settled/effect/restoration evidence.
        let mut failed = job.clone();
        failed["rawCallbackFailed"] = json!(true);
        failed["cancellationRequested"] = json!(true);
        let preserved = validate_job(&failed, &invocation, &source, &receipt, &undo).unwrap();
        assert!(preserved.raw_callback_failed && preserved.cancellation_requested);
        let mut running = job;
        running["contextClosed"] = json!(false);
        running["executorState"] = json!("running");
        running["providerJobOutstanding"] = json!(true);
        running["rawCallbackSettled"] = json!(false);
        validate_job(&running, &invocation, &source, &receipt, &undo).unwrap();
    }

    #[test]
    fn undo_job_source_route_receipt_and_private_fields_cannot_be_substituted() {
        let (job, invocation, source, receipt, undo) = undo_job_fixture();
        for key in ["invocationDigest", "sourceInvocation", "sourceReceipt"] {
            let mut changed = job.clone();
            changed[key] = if key == "invocationDigest" {
                json!("0".repeat(64))
            } else {
                Value::Null
            };
            assert_eq!(
                validate_job(&changed, &invocation, &source, &receipt, &undo)
                    .err()
                    .unwrap()
                    .code,
                "RECOVERY_EXPIRED",
                "{key}"
            );
        }
        let mut changed = job.clone();
        changed["sourceInvocation"]["operationId"] = json!("operation-unrelated");
        assert_eq!(
            validate_job(&changed, &invocation, &source, &receipt, &undo)
                .err()
                .unwrap()
                .code,
            "RECOVERY_EXPIRED"
        );
        let mut changed = job;
        changed["privateToken"] = json!({});
        assert_eq!(
            validate_job(&changed, &invocation, &source, &receipt, &undo)
                .err()
                .unwrap()
                .code,
            "INVALID_INPUT"
        );
    }

    #[test]
    fn finite_dto_budget_rejects_excessive_text_and_structure() {
        let mut value = json!("x".repeat(MAX_RECEIPT_BYTES));
        assert_eq!(
            bounded(&value, MAX_RECEIPT_BYTES).unwrap_err().code,
            "BUDGET_EXCEEDED"
        );
        value = Value::Null;
        for _ in 0..64 {
            value = json!([value]);
        }
        assert_eq!(
            bounded(&value, MAX_RESPONSE_BYTES).unwrap_err().code,
            "BUDGET_EXCEEDED"
        );
    }

    #[test]
    fn absent_actual_service_call_cannot_be_replaced_by_public_context_and_principal() {
        let (_, _, original, _, _) = fixture();
        let hosts = HostBridge::default();
        let adapter = HostUndoMaterialAdapter::new(
            RequestContextSlot::default(),
            LocalAuthority::new(hosts.clone()),
            hosts,
            "operation.reconcile",
        );
        let principal: PrincipalId = decode(&original["context"]["principalRef"]).unwrap();
        // An absent per-call witness is rejected before any public context is
        // inspected, even when that DTO names a real principal. The witness
        // path uses the same denial as a retired original request.
        for context in [&original["context"], &Value::Null] {
            assert_eq!(
                adapter.begin(&principal, context).err().unwrap().code,
                "PERMISSION_REQUIRED"
            );
        }
    }
}

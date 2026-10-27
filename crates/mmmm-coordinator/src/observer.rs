//! Native target reads are separate from dispatch and provider result data.
//! Before images come from actual loaded-world observations; after images use
//! fresh read authority and the original job identity, including on reconcile.

use crate::{
    authority::LocalAuthority,
    host::{HostBridge, HostContextWitness},
    service::{RequestContextSlot, RequestContextWitness},
};
use mmmm_application::{
    Access, AppError, AppResult, AuthorityPort, BeforeCapture, BeforeImage, DirectChange,
    IndependentObserverPort, ReadbackEvidence,
};
use mmmm_contracts::{
    BindingId, ContextId, ContractValidator, InvocationId, OperationId, ResourceLocation,
    Sha256Digest, StepId, canonical_bytes, canonical_digest,
};
use mmmm_runtime::storage::{
    DispatchEvidence, DurableStore, EffectEvidence, OperationRecord, OperationState, StorageError,
    WriteScope,
};
use serde_json::{Value, json};

#[path = "direct_block_observer.rs"]
mod direct_block;
pub(crate) use direct_block::finish as finish_native_observation;

pub struct NativeObserver {
    bridge: HostBridge,
    authentication: Option<ObserverAuthentication>,
}
struct ObserverAuthentication {
    authority: LocalAuthority,
    request: RequestContextSlot,
}
struct ObservationAdmission {
    request: RequestContextWitness,
    host: HostContextWitness,
    scope: WriteScope,
    operation: OperationRecord,
    original: Option<Value>,
}
impl NativeObserver {
    pub fn new(bridge: HostBridge) -> Self {
        Self {
            bridge,
            authentication: None,
        }
    }
    /// The service owns the occupied request. A principal string in a stored
    /// Invocation cannot supply authentication or current observation authority.
    pub fn authenticated(
        bridge: HostBridge,
        authority: LocalAuthority,
        request: RequestContextSlot,
    ) -> Self {
        Self {
            bridge,
            authentication: Some(ObserverAuthentication { authority, request }),
        }
    }
    fn authentication(&self) -> AppResult<&ObserverAuthentication> {
        self.authentication.as_ref().ok_or_else(|| {
            failure(
                "AUTHENTICATION_REQUIRED",
                "Native observation requires the actual authenticated service request",
            )
        })
    }
    fn admission(
        &self,
        store: &DurableStore,
        invocation: &Value,
        scope: &WriteScope,
        original_required: bool,
    ) -> AppResult<ObservationAdmission> {
        validate("Invocation", invocation)?;
        let authentication = self.authentication()?;
        let request = authentication
            .request
            .occupied_witness()
            .map_err(service_error)?;
        let principal = request.authenticated().principal();
        let context = ContextId::new(text(&invocation["context"], "contextId")?)
            .map_err(|_| failure("STALE_CONTEXT", "Stored context identity is invalid"))?;
        if invocation["context"]["principalRef"] != principal.as_str()
            || !request.authenticated().permits_context(context.as_str())
        {
            return Err(failure(
                "PERMISSION_REQUIRED",
                "Original native observation belongs to another authenticated caller",
            ));
        }
        let operation = store
            .operation(&id::<OperationId>(invocation, "operationId")?)
            .map_err(storage_error)?;
        if scope != &operation.scope
            || operation.project_id.as_str() != text(&invocation["context"], "projectId")?
        {
            return Err(failure(
                "PERMISSION_REQUIRED",
                "Native observation must cover the exact durable operation scope",
            ));
        }
        let mut authority = authentication.authority.clone();
        authority.authorize_operation(principal, &operation, Access::ObserveOperation)?;
        let host = self.bridge.observe_context_witness(
            principal,
            &context,
            request.budget().deadline(),
        )?;
        if host.context()["environment"] != invocation["context"]["environment"]
            || host.context()["projectId"] != operation.project_id.as_str()
            || host.context()["principalRef"] != principal.as_str()
        {
            return Err(failure(
                "STALE_CONTEXT",
                "Independent read belongs to another native epoch",
            ));
        }
        let mut admission = ObservationAdmission {
            request,
            host,
            scope: scope.clone(),
            operation,
            original: None,
        };
        self.check_admission(&admission)?;
        let step = id::<StepId>(invocation, "stepId")?;
        match store.stored_invocation_blob(&admission.operation.operation_id, &step) {
            Ok(_) => {
                let mut callback_failure = None;
                let original = store.stored_invocation_checked(
                    &admission.operation.operation_id,
                    &step,
                    8 * 1024 * 1024,
                    || {
                        self.check_admission(&admission).map_err(|error| {
                            callback_failure = Some(error);
                            StorageError::InvalidTransition(
                                "Original native observation request ended".into(),
                            )
                        })
                    },
                );
                let original = match original {
                    Ok(original) => original,
                    Err(error) => {
                        return Err(callback_failure.unwrap_or_else(|| storage_error(error)));
                    }
                };
                if original != *invocation {
                    return Err(failure(
                        "STALE_CONTEXT",
                        "Supplied native Invocation differs from its exact durable source",
                    ));
                }
                admission.original = Some(original);
            }
            Err(StorageError::NotFound("Durable invocation")) if !original_required => {
                let step = admission
                    .operation
                    .steps
                    .iter()
                    .find(|stored| stored.step_id == step)
                    .ok_or_else(|| failure("STALE_CONTEXT", "Before-capture step is absent"))?;
                if step.dispatch != DispatchEvidence::NotSent
                    || step.invocation_id.is_some()
                    || step.invocation_digest.is_some()
                    || step.finished
                    || admission.operation.cancellation_requested
                    || admission.operation.reconciliation_required
                    || !matches!(
                        admission.operation.state,
                        OperationState::Queued | OperationState::Running
                    )
                    || admission.host.context() != &invocation["context"]
                {
                    return Err(failure(
                        "STALE_CONTEXT",
                        "Current before capture must precede durable intent in its frozen context",
                    ));
                }
            }
            Err(error) => return Err(storage_error(error)),
        }
        self.check_admission(&admission)?;
        Ok(admission)
    }
    fn check_admission(&self, admission: &ObservationAdmission) -> AppResult<()> {
        admission.request.check_local().map_err(service_error)?;
        admission.host.check_local()?;
        let authentication = self.authentication()?;
        let principal = admission.request.authenticated().principal();
        let context = admission.host.context();
        let scope = serde_json::to_value(&admission.scope).map_err(|_| {
            failure(
                "PERMISSION_REQUIRED",
                "Actual operation scope cannot be encoded",
            )
        })?;
        if !crate::authority::scope_contains(&context["scope"], &scope) {
            return Err(failure(
                "PERMISSION_REQUIRED",
                "Current paired context no longer covers the complete durable operation scope",
            ));
        }
        let mut authority = authentication.authority.clone();
        authority.authorize_operation(principal, &admission.operation, Access::ObserveOperation)?;
        authority.authorize_retained_scope(
            principal,
            &admission.operation.project_id,
            &id::<ContextId>(context, "contextId")?,
            &digest(context, "policyRevision")?,
            &scope,
        )?;
        admission.request.check_local().map_err(service_error)
    }
    fn observe(
        &self,
        store: &DurableStore,
        admission: &ObservationAdmission,
        target: &BlockTarget,
    ) -> AppResult<(Vec<u8>, Value)> {
        self.check_admission(admission)?;
        let principal = admission.request.authenticated().principal();
        let context = admission.host.context();
        let selector =
            json!({"kind":"block_read","dimension":target.dimension,"position":target.position});
        let observed = if let Some(original) = &admission.original {
            let response = self
                .bridge
                .inspect_original_acquired_with_deadline(
                    store,
                    principal,
                    original,
                    context,
                    selector,
                    admission.request.budget().deadline(),
                )?
                .into_response()?;
            if response["status"] != "ok" {
                return Err(AppError::caused_by(
                    "NATIVE_OBSERVATION_FAILED",
                    "Original paired host could not observe the native block",
                    NativeObservationFailure(response),
                ));
            }
            response.get("payload").cloned().ok_or_else(|| {
                failure(
                    "OBSERVATION_INVALID",
                    "Original native observation payload is absent",
                )
            })?
        } else {
            self.bridge.inspect_with_deadline(
                principal,
                &id::<ContextId>(context, "contextId")?,
                selector,
                admission.request.budget().deadline(),
            )?
        };
        let projection = validate_block_observation(target, &observed)?;
        self.check_admission(admission)?;
        Ok((
            canonical_bytes(&projection).map_err(|_| {
                failure(
                    "OBSERVATION_INVALID",
                    "Observed native bytes cannot be encoded",
                )
            })?,
            observed,
        ))
    }
}
impl IndependentObserverPort for NativeObserver {
    fn validate_capture_target(
        &mut self,
        invocation: &Value,
        scope: &WriteScope,
        target: &str,
    ) -> AppResult<()> {
        if direct_block::uses_native_subjects(invocation) {
            return direct_block::validate_target(invocation, scope, target);
        }
        let target = BlockTarget::parse(target)?;
        validate_region(invocation, scope, &target)
    }
    fn capture_before(
        &mut self,
        invocation: &Value,
        _scope: &WriteScope,
    ) -> AppResult<Option<BeforeCapture>> {
        if invocation["actionId"] != "mmmm:block_patch" {
            return Ok(None);
        }
        Err(store_required())
    }
    fn capture_before_with_store(
        &mut self,
        store: &DurableStore,
        invocation: &Value,
        scope: &WriteScope,
    ) -> AppResult<Option<BeforeCapture>> {
        if invocation["actionId"] != "mmmm:block_patch" {
            return Ok(None);
        }
        if direct_block::uses_native_subjects(invocation) {
            return Err(store_required());
        }
        let target = BlockTarget::from_arguments(&invocation["arguments"])?;
        validate_region(invocation, scope, &target)?;
        let admission = self.admission(store, invocation, scope, false)?;
        let (bytes, _) = self.observe(store, &admission, &target)?;
        Ok(Some(BeforeCapture {
            invocation_id: id::<InvocationId>(invocation, "invocationId")?,
            binding_id: id::<BindingId>(invocation, "bindingId")?,
            context_digest: digest(invocation, "contextDigest")?,
            implementation_digest: digest(invocation, "implementationDigest")?,
            arguments_digest: digest(invocation, "argumentsDigest")?,
            images: vec![BeforeImage {
                target: target.subject(),
                bytes,
            }],
        }))
    }
    fn capture_before_retained_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        scope: &WriteScope,
    ) -> AppResult<Option<BeforeCapture>> {
        if direct_block::uses_native_subjects(invocation) {
            return self
                .capture_direct_block(store, invocation, scope)
                .map(Some);
        }
        self.capture_before_with_store(store, invocation, scope)
    }
    fn readback(
        &mut self,
        _invocation: &Value,
        _scope: &WriteScope,
    ) -> AppResult<ReadbackEvidence> {
        Err(store_required())
    }
    fn readback_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        scope: &WriteScope,
    ) -> AppResult<ReadbackEvidence> {
        if invocation["actionId"] != "mmmm:block_patch" {
            return Err(failure(
                "CAPABILITY_UNAVAILABLE",
                "No native readback codec is installed for this action",
            ));
        }
        if direct_block::uses_native_subjects(invocation) {
            return self.readback_direct_block(store, invocation, scope);
        }
        let target = BlockTarget::from_arguments(&invocation["arguments"])?;
        validate_region(invocation, scope, &target)?;
        let admission = self.admission(store, invocation, scope, true)?;
        let original = admission.original.as_ref().ok_or_else(store_required)?;
        let job = self.bridge.job_observation_with_store_and_deadline(
            store,
            admission.request.authenticated().principal(),
            original,
            admission.host.context(),
            admission.request.budget().deadline(),
        )?;
        if job["invocationId"] != invocation["invocationId"]
            || !job["providerCompleted"].is_boolean()
        {
            return Err(failure(
                "OBSERVATION_INVALID",
                "Original native completion identity is absent",
            ));
        }
        let (after, observed) = self.observe(store, &admission, &target)?;
        let desired = json!({"dimension":target.dimension,"position":target.position,"blockState":invocation["arguments"]["desiredState"]});
        let desired = canonical_bytes(&desired)
            .map_err(|_| failure("INVALID_INPUT", "Desired native state cannot be encoded"))?;
        let settled = job["providerCompleted"] == true;
        let effect = if settled && after == desired {
            EffectEvidence::CompleteConfirmed
        } else {
            EffectEvidence::Unknown
        };
        self.check_admission(&admission)?;
        Ok(ReadbackEvidence {
            invocation_id: id::<InvocationId>(invocation, "invocationId")?,
            binding_id: id::<BindingId>(invocation, "bindingId")?,
            context_digest: digest(invocation, "contextDigest")?,
            implementation_digest: digest(invocation, "implementationDigest")?,
            arguments_digest: digest(invocation, "argumentsDigest")?,
            effect,
            settled,
            evidence: json!({"kind":"native_block_independent_readback","invocationId":invocation["invocationId"],"jobObservation":job,"targetObservation":observed}),
            direct_changes: vec![DirectChange {
                target: target.subject(),
                before: Vec::new(),
                after,
            }],
        })
    }
    fn read_target(&mut self, _invocation: &Value, _target: &str) -> AppResult<Vec<u8>> {
        Err(store_required())
    }
    fn read_target_with_store(
        &mut self,
        store: &DurableStore,
        invocation: &Value,
        target: &str,
    ) -> AppResult<Vec<u8>> {
        if invocation["actionId"] != "mmmm:block_patch" {
            return Err(failure(
                "CAPABILITY_UNAVAILABLE",
                "No original native target codec is installed for this action",
            ));
        }
        if direct_block::uses_native_subjects(invocation) {
            return Err(store_required());
        }
        let target = BlockTarget::parse(target)?;
        let original = BlockTarget::from_arguments(&invocation["arguments"])?;
        if target != original {
            return Err(failure(
                "PERMISSION_REQUIRED",
                "Recovery target differs from the original native footprint",
            ));
        }
        let operation = store
            .operation(&id::<OperationId>(invocation, "operationId")?)
            .map_err(storage_error)?;
        let scope = operation.scope;
        validate_region(invocation, &scope, &target)?;
        let admission = self.admission(store, invocation, &scope, true)?;
        self.observe(store, &admission, &target)
            .map(|(bytes, _)| bytes)
    }
    fn read_target_retained_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        target: &str,
    ) -> AppResult<Vec<u8>> {
        if direct_block::uses_native_subjects(invocation) {
            return self.read_direct_block_target(store, invocation, target);
        }
        self.read_target_with_store(store, invocation, target)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct BlockTarget {
    pub dimension: ResourceLocation,
    pub position: [i32; 3],
}
impl BlockTarget {
    pub(crate) fn from_arguments(arguments: &Value) -> AppResult<Self> {
        let dimension = ResourceLocation::new(text(arguments, "dimension")?)
            .map_err(|_| failure("INVALID_INPUT", "Native block dimension is invalid"))?;
        let coordinates = arguments["position"]
            .as_array()
            .filter(|coordinates| coordinates.len() == 3)
            .ok_or_else(|| failure("INVALID_INPUT", "Native block position is invalid"))?;
        let mut position = [0; 3];
        for (index, coordinate) in coordinates.iter().enumerate() {
            position[index] = coordinate
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .ok_or_else(|| {
                    failure("INVALID_INPUT", "Native block position is outside int32")
                })?;
        }
        Ok(Self {
            dimension,
            position,
        })
    }
    pub(crate) fn parse(subject: &str) -> AppResult<Self> {
        let value = subject.strip_prefix("block:").ok_or_else(|| {
            failure(
                "CAPABILITY_UNAVAILABLE",
                "Target is not a native block locator",
            )
        })?;
        let mut parts = value.rsplitn(4, ':');
        let mut position = [0; 3];
        for index in (0..3).rev() {
            let part = parts
                .next()
                .ok_or_else(|| failure("INVALID_INPUT", "Native target locator is incomplete"))?;
            position[index] = part
                .parse::<i32>()
                .map_err(|_| failure("INVALID_INPUT", "Native target coordinate is invalid"))?;
            if position[index].to_string() != part {
                return Err(failure(
                    "INVALID_INPUT",
                    "Native target coordinate is not canonical",
                ));
            }
        }
        let dimension = ResourceLocation::new(
            parts
                .next()
                .ok_or_else(|| failure("INVALID_INPUT", "Native target dimension is absent"))?,
        )
        .map_err(|_| failure("INVALID_INPUT", "Native target dimension is invalid"))?;
        let target = Self {
            dimension,
            position,
        };
        if target.subject() != subject {
            return Err(failure(
                "INVALID_INPUT",
                "Native target locator is not canonical",
            ));
        }
        Ok(target)
    }
    pub(crate) fn subject(&self) -> String {
        format!(
            "block:{}:{}:{}:{}",
            self.dimension.as_str(),
            self.position[0],
            self.position[1],
            self.position[2]
        )
    }
}
pub(crate) fn validate_region(
    invocation: &Value,
    scope: &WriteScope,
    target: &BlockTarget,
) -> AppResult<()> {
    scope
        .validate()
        .map_err(|_| failure("PERMISSION_REQUIRED", "Native scope is invalid"))?;
    if scope.project_id.as_str() != text(&invocation["context"], "projectId")?
        || !scope.regions.iter().any(|region| {
            region.context_id.as_str() == invocation["context"]["contextId"].as_str().unwrap_or("")
                && region.world_id.as_str()
                    == invocation["context"]["environment"]["worldId"]
                        .as_str()
                        .unwrap_or("")
                && region.dimension == target.dimension
                && (0..3).all(|axis| {
                    region.min[axis] <= i64::from(target.position[axis])
                        && i64::from(target.position[axis]) < region.max_exclusive[axis]
                })
        })
    {
        return Err(failure(
            "PERMISSION_REQUIRED",
            "Native target is outside the approved world region",
        ));
    }
    Ok(())
}
fn validate_block_observation(target: &BlockTarget, observed: &Value) -> AppResult<Value> {
    let object = observed
        .as_object()
        .ok_or_else(|| failure("OBSERVATION_INVALID", "Native block observation is absent"))?;
    if object.len() != 5
        || ![
            "dimension",
            "position",
            "blockState",
            "observedTick",
            "snapshotDigest",
        ]
        .iter()
        .all(|key| object.contains_key(*key))
        || observed["dimension"] != target.dimension.as_str()
        || observed["position"] != json!(target.position)
    {
        return Err(failure(
            "OBSERVATION_INVALID",
            "Native observation target differs from the requested target",
        ));
    }
    mmmm_contracts::UnsignedDecimal::new(text(observed, "observedTick")?)
        .map_err(|_| failure("OBSERVATION_INVALID", "Native observation tick is invalid"))?;
    let block = &observed["blockState"];
    let block_object = block
        .as_object()
        .ok_or_else(|| failure("OBSERVATION_INVALID", "Native block state is invalid"))?;
    let properties = block["properties"]
        .as_object()
        .ok_or_else(|| failure("OBSERVATION_INVALID", "Native block properties are absent"))?;
    if block_object.len() != 2
        || properties.len() > 256
        || properties.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > 128
                || value.as_str().is_none_or(|value| value.len() > 128)
        })
    {
        return Err(failure(
            "OBSERVATION_INVALID",
            "Native block state exceeds its codec limits",
        ));
    }
    ResourceLocation::new(text(block, "blockId")?)
        .map_err(|_| failure("OBSERVATION_INVALID", "Native block ID is invalid"))?;
    let projection =
        json!({"dimension":target.dimension,"position":target.position,"blockState":block});
    if canonical_digest(&projection)
        .map_err(|_| {
            failure(
                "OBSERVATION_INVALID",
                "Native observation digest is unavailable",
            )
        })?
        .as_str()
        != text(observed, "snapshotDigest")?
    {
        return Err(failure(
            "OBSERVATION_INVALID",
            "Native observation digest differs from actual raw bytes",
        ));
    }
    Ok(projection)
}
fn id<T: serde::de::DeserializeOwned>(value: &Value, key: &str) -> AppResult<T> {
    serde_json::from_value(value[key].clone())
        .map_err(|_| failure("INVALID_INPUT", "Original invocation identity is invalid"))
}
fn digest(value: &Value, key: &str) -> AppResult<Sha256Digest> {
    Sha256Digest::new(text(value, key)?)
        .map_err(|_| failure("INVALID_INPUT", "Original invocation digest is invalid"))
}
fn text<'a>(value: &'a Value, key: &str) -> AppResult<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| failure("INVALID_INPUT", "Required native field is absent"))
}
fn validate(name: &str, value: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .and_then(|validator| validator.validate(name, value))
        .map_err(|_| failure("INVALID_INPUT", "Original native contract is invalid"))
}
struct NativeObservationFailure(Value);
impl std::fmt::Debug for NativeObservationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativeObservationFailure")
    }
}
impl std::fmt::Display for NativeObservationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = &self.0;
        formatter.write_str("Original bounded native failure response is retained privately")
    }
}
impl std::error::Error for NativeObservationFailure {}
fn service_error(error: crate::service::ServiceError) -> AppError {
    AppError::caused_by(error.code, error.message, error)
}
fn storage_error(error: StorageError) -> AppError {
    AppError::storage("NATIVE_SOURCE_UNAVAILABLE", error)
}
fn store_required() -> AppError {
    failure(
        "STORE_REQUIRED",
        "Native observation requires the original invocation in the application's actual Store",
    )
}
fn failure(code: &'static str, message: &'static str) -> AppError {
    AppError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_block_locator_keeps_dimension_and_signed_coordinates() {
        let target = BlockTarget::parse("block:minecraft:overworld:-1:64:2147483647").unwrap();
        assert_eq!(target.position, [-1, 64, i32::MAX]);
        for value in [
            "block:minecraft:overworld:01:64:0",
            "block:minecraft:overworld:+1:64:0",
            "block:minecraft:overworld:2147483648:64:0",
            "block:minecraft:overworld:0:64",
        ] {
            assert!(BlockTarget::parse(value).is_err());
        }
        let mut legacy = NativeObserver::new(HostBridge::default());
        assert_eq!(
            legacy
                .read_target(&Value::Null, &target.subject())
                .unwrap_err()
                .code,
            "STORE_REQUIRED"
        );
    }
    #[test]
    fn observation_hash_is_actual_projection_and_tick_is_metadata() {
        let target = BlockTarget::parse("block:minecraft:overworld:0:64:0").unwrap();
        let projection = json!({"dimension":target.dimension,"position":target.position,"blockState":{"blockId":"minecraft:stone","properties":{}}});
        let mut observation = projection.clone();
        observation["observedTick"] = json!("10");
        observation["snapshotDigest"] = json!(canonical_digest(&projection).unwrap());
        assert_eq!(
            validate_block_observation(&target, &observation).unwrap(),
            projection
        );
        observation["observedTick"] = json!("11");
        assert!(validate_block_observation(&target, &observation).is_ok());
        observation["blockState"]["blockId"] = json!("minecraft:dirt");
        assert!(validate_block_observation(&target, &observation).is_err());
    }
}

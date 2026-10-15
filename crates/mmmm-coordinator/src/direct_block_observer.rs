//! The SDK direct-block receipt has two native serializer subjects. Legacy
//! `block:` projection snapshots remain a separate codec and are never hashed
//! or decoded as these raw native observations.
use super::*;
use crate::native_targets::{
    NativeObservation, NativeRead, NativeSelector, NativeTargetError, NativeTargetReader,
};
use std::collections::BTreeSet;

pub(super) fn uses_native_subjects(value: &Value) -> bool {
    value["actionId"] == "mmmm:block_patch"
        && value["arguments"]
            .get("expectedRegistryGeneration")
            .is_some()
}
struct DirectTarget {
    block: BlockTarget,
    generation: String,
    selectors: Vec<NativeSelector>,
    subjects: Vec<String>,
}
impl DirectTarget {
    fn from_step(step: &Value) -> AppResult<Self> {
        if !uses_native_subjects(step) {
            return Err(unavailable());
        }
        let arguments = step["arguments"].as_object().ok_or_else(unavailable)?;
        if arguments.len() != 5
            || [
                "dimension",
                "position",
                "expectedState",
                "desiredState",
                "expectedRegistryGeneration",
            ]
            .iter()
            .any(|key| !arguments.contains_key(*key))
        {
            return Err(unavailable());
        }
        let block = BlockTarget::from_arguments(&step["arguments"])?;
        let generation = text(&step["arguments"], "expectedRegistryGeneration")?;
        let parsed = generation.parse::<u64>().map_err(|_| unavailable())?;
        if parsed.to_string() != generation {
            return Err(unavailable());
        }
        let mut selectors = Vec::new();
        let mut subjects = Vec::new();
        for kind in ["block_state", "block_entity"] {
            let selector = NativeSelector::from_value(
                &json!({"kind":kind,"dimension":block.dimension,"position":block.position}),
            )
            .map_err(native_error)?;
            subjects.push(format!(
                "native:{}",
                canonical_digest(selector.value()).map_err(|_| unavailable())?
            ));
            selectors.push(selector);
        }
        Ok(Self {
            block,
            generation: generation.into(),
            selectors,
            subjects,
        })
    }
    fn validate_scope(&self, invocation: &Value, scope: &WriteScope) -> AppResult<()> {
        validate_region(invocation, scope, &self.block)?;
        // This is the approved conservative fence, not an assertion that all
        // engine effects are contained in this box or captured by this codec.
        if !scope.regions.iter().any(|region| {
            region.dimension == self.block.dimension
                && region.context_id.as_str()
                    == invocation["context"]["contextId"].as_str().unwrap_or("")
                && region.world_id.as_str()
                    == invocation["context"]["environment"]["worldId"]
                        .as_str()
                        .unwrap_or("")
                && (0..3).all(|axis| {
                    region.min[axis] <= i64::from(self.block.position[axis]) - 1
                        && region.max_exclusive[axis] >= i64::from(self.block.position[axis]) + 2
                })
        }) {
            return Err(forbidden());
        }
        Ok(())
    }
    fn validate_written(&self, step: &Value) -> AppResult<()> {
        let written = step["resourcesWritten"].as_array().ok_or_else(forbidden)?;
        let actual: BTreeSet<_> = written
            .iter()
            .map(Value::as_str)
            .collect::<Option<_>>()
            .ok_or_else(forbidden)?;
        let expected: BTreeSet<_> = self.subjects.iter().map(String::as_str).collect();
        if actual != expected || written.len() != expected.len() {
            return Err(forbidden());
        }
        Ok(())
    }
    fn matching<'a>(
        &self,
        observations: &'a [NativeObservation],
    ) -> AppResult<Vec<&'a NativeObservation>> {
        if observations.len() != self.selectors.len() {
            return Err(unavailable());
        }
        for (observation, selector) in observations.iter().zip(&self.selectors) {
            if observation.selector().value() != selector.value() {
                return Err(forbidden());
            }
        }
        Ok(observations.iter().collect())
    }
}

pub(super) fn validate_target(
    invocation: &Value,
    scope: &WriteScope,
    target: &str,
) -> AppResult<()> {
    let direct = DirectTarget::from_step(invocation)?;
    direct.validate_scope(invocation, scope)?;
    if !direct.subjects.iter().any(|subject| subject == target) {
        return Err(forbidden());
    }
    Ok(())
}

impl NativeObserver {
    /// Called only after the composite's durable plan/step/grant admission. The
    /// requested hash can select only one of this codec's two exact locators;
    /// the actual current reader supplies the bytes and remains the authority.
    pub(crate) fn observe_direct_plan_precondition(
        &self,
        store: &mut DurableStore,
        step: &Value,
        condition: &Value,
        context: &Value,
        scope: &WriteScope,
    ) -> AppResult<Sha256Digest> {
        let direct = DirectTarget::from_step(step)?;
        direct.validate_written(step)?;
        let invocation_scope = json!({"context":context});
        direct.validate_scope(&invocation_scope, scope)?;
        if condition["kind"] != "region_snapshot" || condition["coverage"] != "full_target" {
            return Err(forbidden());
        }
        let index = direct
            .subjects
            .iter()
            .position(|subject| condition["subject"] == subject.as_str())
            .ok_or_else(forbidden)?;
        let authentication = self.authentication()?;
        let request = authentication
            .request
            .occupied_witness()
            .map_err(service_error)?;
        let host = self.bridge.observe_context_witness(
            request.authenticated().principal(),
            &id::<ContextId>(context, "contextId")?,
            request.budget().deadline(),
        )?;
        if host.context() != context {
            return Err(forbidden());
        }
        let check = || {
            request.check_local().map_err(service_error)?;
            host.check_local()?;
            authentication.authority.authorize_retained_scope(
                request.authenticated().principal(),
                &id::<mmmm_contracts::ProjectId>(context, "projectId")?,
                &id::<ContextId>(context, "contextId")?,
                &digest(context, "policyRevision")?,
                &json!(scope),
            )?;
            Ok(())
        };
        check()?;
        let read = self
            .direct_reader()?
            .observe_retained(store, context, &direct.selectors, &direct.generation)
            .map_err(native_error);
        let read = finish(read, check())?;
        if read.retained_resource().is_none() {
            return Err(forbidden());
        }
        let observations = direct.matching(read.targets())?;
        ensure_direct_images(&observations)?;
        check()?;
        Ok(observations[index].digest().clone())
    }

    fn direct_reader(&self) -> AppResult<NativeTargetReader> {
        let authentication = self.authentication()?;
        Ok(NativeTargetReader::new(
            self.bridge.clone(),
            authentication.authority.clone(),
            authentication.request.clone(),
        ))
    }
    fn observe_direct(
        &self,
        store: &mut DurableStore,
        admission: &ObservationAdmission,
        invocation: &Value,
        target: &DirectTarget,
    ) -> AppResult<NativeRead> {
        self.check_admission(admission)?;
        let reader = self.direct_reader()?;
        let read = if admission.original.is_some() {
            reader.observe_original_retained_in_context(
                store,
                &admission.operation.operation_id,
                &id::<StepId>(invocation, "stepId")?,
                admission.host.context(),
                &target.selectors,
                &target.generation,
            )
        } else {
            reader.observe_retained(
                store,
                admission.host.context(),
                &target.selectors,
                &target.generation,
            )
        }
        .map_err(native_error);
        let read = finish(read, self.check_admission(admission))?;
        if read.retained_resource().is_none() {
            return Err(forbidden());
        }
        store
            .append_operation_evidence(&admission.operation.operation_id, read.response())
            .map_err(storage_error)?;
        self.check_admission(admission)?;
        Ok(read)
    }
    pub(super) fn capture_direct_block(
        &self,
        store: &mut DurableStore,
        invocation: &Value,
        scope: &WriteScope,
    ) -> AppResult<BeforeCapture> {
        let direct = DirectTarget::from_step(invocation)?;
        direct.validate_scope(invocation, scope)?;
        let admission = self.admission(store, invocation, scope, false)?;
        if admission.original.is_some() {
            return Err(forbidden());
        }
        let step = direct_stored_step(store, &admission, invocation)?;
        direct.validate_written(&step)?;
        let read = self.observe_direct(store, &admission, invocation, &direct)?;
        let observed = direct.matching(read.targets())?;
        ensure_direct_images(&observed)?;
        if observed.iter().any(|observation| {
            observation.raw()["payload"]["blockState"] != invocation["arguments"]["expectedState"]
        }) {
            return Err(failure(
                "TARGET_DRIFT",
                "The independently captured direct block no longer equals its expected state",
            ));
        }
        self.check_admission(&admission)?;
        Ok(BeforeCapture {
            invocation_id: id(invocation, "invocationId")?,
            binding_id: id(invocation, "bindingId")?,
            context_digest: digest(invocation, "contextDigest")?,
            implementation_digest: digest(invocation, "implementationDigest")?,
            arguments_digest: digest(invocation, "argumentsDigest")?,
            images: observed
                .iter()
                .zip(&direct.subjects)
                .map(|(observation, subject)| BeforeImage {
                    target: subject.clone(),
                    bytes: observation.bytes().to_vec(),
                })
                .collect(),
        })
    }
    pub(super) fn readback_direct_block(
        &self,
        store: &mut DurableStore,
        invocation: &Value,
        scope: &WriteScope,
    ) -> AppResult<ReadbackEvidence> {
        let direct = DirectTarget::from_step(invocation)?;
        direct.validate_scope(invocation, scope)?;
        let admission = self.admission(store, invocation, scope, true)?;
        let step = direct_stored_step(store, &admission, invocation)?;
        direct.validate_written(&step)?;
        let original = admission.original.as_ref().ok_or_else(store_required)?;
        self.check_admission(&admission)?;
        let job = self.bridge.job_observation_with_store_and_deadline(
            store,
            admission.request.authenticated().principal(),
            original,
            admission.host.context(),
            admission.request.budget().deadline(),
        );
        let job = finish(job, self.check_admission(&admission))?;
        if job["invocationId"] != invocation["invocationId"]
            || !job["providerCompleted"].is_boolean()
            || !job["dispatched"].is_boolean()
        {
            return Err(unavailable());
        }
        let job_blob = store
            .put_blob(&mmmm_contracts::encode_json(&job).map_err(|_| unavailable())?)
            .map_err(storage_error)?;
        store
            .append_operation_evidence(&admission.operation.operation_id, &job_blob)
            .map_err(storage_error)?;
        let read = self.observe_direct(store, &admission, invocation, &direct)?;
        let observed = direct.matching(read.targets())?;
        let complete_direct = ensure_direct_images(&observed).is_ok();
        let matches_desired = complete_direct
            && observed.iter().all(|observation| {
                observation.raw()["payload"]["blockState"]
                    == invocation["arguments"]["desiredState"]
            });
        let settled = job["providerCompleted"] == true;
        let effect = if settled && matches_desired {
            EffectEvidence::CompleteConfirmed
        } else {
            EffectEvidence::Unknown
        };
        self.check_admission(&admission)?;
        Ok(ReadbackEvidence {
            invocation_id: id(invocation, "invocationId")?,
            binding_id: id(invocation, "bindingId")?,
            context_digest: digest(invocation, "contextDigest")?,
            implementation_digest: digest(invocation, "implementationDigest")?,
            arguments_digest: digest(invocation, "argumentsDigest")?,
            effect,
            settled,
            evidence: json!({"kind":"native_direct_block_independent_readback","invocationId":invocation["invocationId"],
                "sourceRefs":[job_blob,read.response()],"directCoverage":"block_state_cells","indirectEffects":"not_observed",
                "exactUndoSupported":false,"conservativeFence":"3x3x3_only"}),
            direct_changes: if complete_direct {
                observed
                    .iter()
                    .zip(&direct.subjects)
                    .map(|(observation, subject)| DirectChange {
                        target: subject.clone(),
                        before: Vec::new(),
                        after: observation.bytes().to_vec(),
                    })
                    .collect()
            } else {
                Vec::new()
            },
        })
    }
    pub(super) fn read_direct_block_target(
        &self,
        store: &mut DurableStore,
        invocation: &Value,
        subject: &str,
    ) -> AppResult<Vec<u8>> {
        let direct = DirectTarget::from_step(invocation)?;
        let index = direct
            .subjects
            .iter()
            .position(|target| target == subject)
            .ok_or_else(forbidden)?;
        let operation = store
            .operation(&id(invocation, "operationId")?)
            .map_err(storage_error)?;
        direct.validate_scope(invocation, &operation.scope)?;
        let admission = self.admission(store, invocation, &operation.scope, true)?;
        direct.validate_written(&direct_stored_step(store, &admission, invocation)?)?;
        let read = self.observe_direct(store, &admission, invocation, &direct)?;
        let observed = direct.matching(read.targets())?;
        ensure_direct_images(&observed)?;
        self.check_admission(&admission)?;
        Ok(observed[index].bytes().to_vec())
    }
}

fn direct_stored_step(
    store: &DurableStore,
    admission: &ObservationAdmission,
    invocation: &Value,
) -> AppResult<Value> {
    let plan = store
        .plan(&admission.operation.plan_id, &admission.operation.plan_hash)
        .map_err(storage_error)?;
    let step = plan["steps"]
        .as_array()
        .and_then(|steps| {
            steps
                .iter()
                .find(|step| step["stepId"] == invocation["stepId"])
        })
        .ok_or_else(forbidden)?;
    for field in [
        "bindingId",
        "actionId",
        "actionContractVersion",
        "actionDigest",
        "implementationDigest",
        "arguments",
    ] {
        if step[field] != invocation[field] {
            return Err(forbidden());
        }
    }
    if step["effect"] != "write"
        || step["verificationRequirement"] != "independent_readback"
        || step["contextId"] != invocation["context"]["contextId"]
        || step["resultBindings"]
            .as_array()
            .is_none_or(|bindings| !bindings.is_empty())
        || plan["scope"] != json!(admission.scope)
    {
        return Err(forbidden());
    }
    Ok(step.clone())
}
fn ensure_direct_images(observations: &[&NativeObservation]) -> AppResult<()> {
    if observations.len() != 2
        || observations
            .iter()
            .any(|observation| !observation.full_target())
        || observations[0].presence() != "present"
        || observations[1].presence() != "absent"
        || observations[0].raw()["payload"]["blockState"]
            != observations[1].raw()["payload"]["blockState"]
    {
        return Err(unavailable());
    }
    Ok(())
}
fn native_error(error: NativeTargetError) -> AppError {
    match error {
        NativeTargetError::Authority(error) => error,
        NativeTargetError::Storage(error) => storage_error(error),
        NativeTargetError::Retention(error) => {
            AppError::caused_by(error.code, error.message, error)
        }
        NativeTargetError::Invalid => unavailable(),
        NativeTargetError::Host(error) => AppError::caused_by(
            "NATIVE_OBSERVATION_FAILED",
            "The original direct block observation failed and remains in private CAS",
            error.causal_snapshot(),
        ),
    }
}
fn unavailable() -> AppError {
    failure(
        "CAPABILITY_UNAVAILABLE",
        "Current direct block native observations are incomplete or outside this exact codec",
    )
}
fn forbidden() -> AppError {
    failure(
        "PERMISSION_REQUIRED",
        "The native subject is outside the original approved direct block footprint",
    )
}
#[derive(Debug)]
struct ObservationBoundaryFailure {
    original: AppError,
    checkpoint: AppError,
}
impl std::fmt::Display for ObservationBoundaryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Original {} and current {} both failed",
            self.original.code, self.checkpoint.code
        )
    }
}
impl std::error::Error for ObservationBoundaryFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
pub(crate) fn finish<T>(result: AppResult<T>, checkpoint: AppResult<()>) -> AppResult<T> {
    match (result, checkpoint) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(original), Err(checkpoint)) => Err(AppError::caused_by(
            original.code,
            original.message,
            ObservationBoundaryFailure {
                original,
                checkpoint,
            },
        )),
    }
}

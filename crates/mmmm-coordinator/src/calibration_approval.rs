//! Private native-owner selection and actual game ADMIN confirmation.
//! Neither a public plan locator nor this closed codec grants general writes.

use super::*;
use crate::{
    calibration_execution::{CalibrationPendingSlot, CalibrationRegistry, ConfirmedCalibration},
    host::{CalibrationHostRoute, HostContextWitness, PackRunHostRoute},
    workspace_bootstrap::{NativeOwnerWitness, native_owner_resource_reader},
};
use mmmm_compiler::calibration_dispatch::CalibrationDispatchPlan;
use mmmm_contracts::{PlanId, ResourceId, SourceId, raw_digest, verify_projected_digest};
use mmmm_runtime::storage::{
    calibration_approval::{
        CalibrationApprovalAuthority, CalibrationApprovalRecord, CalibrationApprovalRpcContext,
        CalibrationConfirmationRequest, CalibrationSelectionRecord, CalibrationSelectionRequest,
        calibration_selection, confirm_calibration_approval, register_calibration_selection,
    },
    project_resources::{ProjectResourceQuery, ProjectResourceRequest, ProjectSourceRpcContext},
};

pub(crate) const PURPOSE: &str = "numeric_calibration_normative47/1";

fn invalid() -> ManagementError {
    ManagementError::InvalidFrame
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str, ManagementError> {
    value[key].as_str().ok_or_else(invalid)
}
fn exact(value: &Value, fields: &[&str]) -> Result<(), ManagementError> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object.len() != fields.len() || fields.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid());
    }
    Ok(())
}
fn sha(value: &Value, key: &str) -> Result<(), ManagementError> {
    Sha256Digest::new(field(value, key)?)
        .map(|_| ())
        .map_err(|_| invalid())
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], ManagementError> {
    value[key].as_array().map(Vec::as_slice).ok_or_else(invalid)
}
fn absolute_root(value: &Value) -> Result<(), ManagementError> {
    let root = field(value, "dataRoot")?;
    if root.len() > 4096 || root.chars().any(char::is_control) || !Path::new(root).is_absolute() {
        return Err(invalid());
    }
    Ok(())
}
fn selected_plan(value: &Value) -> Result<(), ManagementError> {
    ProjectId::new(field(value, "projectId")?).map_err(|_| invalid())?;
    PlanId::new(field(value, "planId")?).map_err(|_| invalid())?;
    sha(value, "planHash")
}

/// This checks only exact bounded private grammar. Trusted storage callbacks
/// separately establish owner, source CAS, active pairing and fixed recipe.
pub(crate) fn validate_frame(
    value: &Value,
    validator: &ContractValidator,
) -> Result<ManagementKind, ManagementError> {
    let pack_run = value["purpose"] == crate::calibration_pack_run::PURPOSE;
    if value["purpose"] != PURPOSE && !pack_run {
        return Err(invalid());
    }
    match field(value, "kind")? {
        "native_calibration_owner_offer" => {
            exact(
                value,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "purpose",
                    "dataRoot",
                    "projectId",
                    "planId",
                    "planHash",
                ],
            )?;
            absolute_root(value)?;
            selected_plan(value)?;
            Ok(ManagementKind::Offer)
        }
        "native_calibration_owner_selected" => {
            exact(
                value,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "purpose",
                    "projectId",
                    "planId",
                    "planHash",
                    "approvalRef",
                    "selectionDigest",
                    "expiresAt",
                ],
            )?;
            selected_plan(value)?;
            reference(field(value, "approvalRef")?)?;
            sha(value, "selectionDigest")?;
            instant(field(value, "expiresAt")?)?;
            Ok(ManagementKind::Authority)
        }
        "host_apply_approval_offer" => {
            exact(
                value,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "purpose",
                    "dataRoot",
                    "projectId",
                    "principalId",
                    "playerId",
                    "planId",
                    "planHash",
                    "hostArtifactDigest",
                    "hostHello",
                    "contextIds",
                    "runtimeSourceFacts",
                ],
            )?;
            absolute_root(value)?;
            selected_plan(value)?;
            PrincipalId::new(field(value, "principalId")?).map_err(|_| invalid())?;
            RequestId::new(field(value, "playerId")?).map_err(|_| invalid())?;
            sha(value, "hostArtifactDigest")?;
            validator
                .validate("HostHello", &value["hostHello"])
                .map_err(|_| invalid())?;
            let contexts = array(value, "contextIds")?;
            if contexts.len() != 1 {
                return Err(invalid());
            }
            ContextId::new(contexts[0].as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
            if !value["runtimeSourceFacts"].is_object() {
                return Err(invalid());
            }
            Ok(ManagementKind::Offer)
        }
        "host_apply_approval_authority" => {
            exact(
                value,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "purpose",
                    "contexts",
                    "approvedSources",
                    "approvedActions",
                    "permissions",
                    "manifest",
                ],
            )?;
            let contexts = array(value, "contexts")?;
            if contexts.len() != 1 {
                return Err(invalid());
            }
            for context in contexts {
                validator
                    .validate("ExecutionContext", context)
                    .map_err(|_| invalid())?;
                verify_projected_digest("ExecutionContext", context).map_err(|_| invalid())?;
            }
            let sources = value["approvedSources"].as_object().ok_or_else(invalid)?;
            if sources.len() != 1 {
                return Err(invalid());
            }
            for (id, digest) in sources {
                SourceId::new(id).map_err(|_| invalid())?;
                Sha256Digest::new(digest.as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
            }
            let mut actions = BTreeSet::new();
            for action in array(value, "approvedActions")? {
                let digest = Sha256Digest::new(action.as_str().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
                if !actions.insert(digest) {
                    return Err(invalid());
                }
            }
            let permissions = array(value, "permissions")?
                .iter()
                .map(|v| v.as_str().ok_or_else(invalid))
                .collect::<Result<BTreeSet<_>, _>>()?;
            if array(value, "permissions")?.len() != READ_PERMISSIONS.len()
                || permissions != BTreeSet::from(READ_PERMISSIONS)
            {
                return Err(invalid());
            }
            validate_manifest(&value["manifest"], validator)?;
            if value["manifest"]["purpose"] != value["purpose"] {
                return Err(invalid());
            }
            let context = &contexts[0];
            let manifest = &value["manifest"];
            let plan = &manifest["plan"];
            if context["principalRef"] != plan["principalId"]
                || context["projectId"] != plan["projectId"]
                || context["contextId"] != plan["contextPins"][0]["contextId"]
                || context["contextDigest"] != plan["contextPins"][0]["contextDigest"]
                || context["environment"] != plan["contextPins"][0]["environment"]
            {
                return Err(invalid());
            }
            if pack_run {
                if !context["scope"]["externalTargetIds"]
                    .as_array()
                    .is_some_and(|targets| targets.contains(&manifest["targetId"]))
                    || actions
                        != array(plan, "steps")?
                            .iter()
                            .map(|step| {
                                Sha256Digest::new(field(step, "actionDigest")?)
                                    .map_err(|_| invalid())
                            })
                            .collect::<Result<BTreeSet<_>, _>>()?
                {
                    return Err(invalid());
                }
            } else {
                for program in array(manifest, "programs")? {
                    for binding in array(program, "targetBindings")? {
                        if !context["scope"]["externalTargetIds"]
                            .as_array()
                            .is_some_and(|targets| targets.contains(&binding["targetId"]))
                        {
                            return Err(invalid());
                        }
                    }
                }
            }
            Ok(ManagementKind::Authority)
        }
        "host_apply_approval_installed" => {
            exact(
                value,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "purpose",
                    "selectionDigest",
                    "manifestDigest",
                    "hostEndpoint",
                ],
            )?;
            sha(value, "selectionDigest")?;
            sha(value, "manifestDigest")?;
            exact(&value["hostEndpoint"], &["address", "path", "hostEpoch"])?;
            let address: SocketAddr = field(&value["hostEndpoint"], "address")?
                .parse()
                .map_err(|_| invalid())?;
            if !address.ip().is_loopback()
                || !address.is_ipv4()
                || address.port() == 0
                || value["hostEndpoint"]["path"] != "/rpc"
            {
                return Err(invalid());
            }
            SessionEpoch::new(field(&value["hostEndpoint"], "hostEpoch")?)
                .map_err(|_| invalid())?;
            Ok(ManagementKind::Installed)
        }
        "host_apply_approval_complete" => {
            exact(
                value,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "purpose",
                    "selectionDigest",
                    "manifestDigest",
                    "ready",
                    "coordinatorEpoch",
                    "hostEpoch",
                    "contextId",
                ],
            )?;
            sha(value, "selectionDigest")?;
            sha(value, "manifestDigest")?;
            if value["ready"] != true {
                return Err(invalid());
            }
            SessionEpoch::new(field(value, "coordinatorEpoch")?).map_err(|_| invalid())?;
            SessionEpoch::new(field(value, "hostEpoch")?).map_err(|_| invalid())?;
            ContextId::new(field(value, "contextId")?).map_err(|_| invalid())?;
            Ok(ManagementKind::Complete)
        }
        _ => Err(invalid()),
    }
}

fn validate_manifest(value: &Value, validator: &ContractValidator) -> Result<(), ManagementError> {
    if value["purpose"] == crate::calibration_pack_run::PURPOSE {
        return validate_pack_run_manifest(value, validator);
    }
    exact(
        value,
        &[
            "kind",
            "purpose",
            "selectionDigest",
            "hostEpoch",
            "registryGeneration",
            "runtimeSourceFactsDigest",
            "suiteDigest",
            "recipeSha256",
            "plan",
            "programs",
        ],
    )?;
    if value["kind"] != "native_calibration_approval/2" || value["purpose"] != PURPOSE {
        return Err(invalid());
    }
    for key in [
        "selectionDigest",
        "runtimeSourceFactsDigest",
        "suiteDigest",
        "recipeSha256",
    ] {
        sha(value, key)?;
    }
    SessionEpoch::new(field(value, "hostEpoch")?).map_err(|_| invalid())?;
    generation(field(value, "registryGeneration")?)?;
    let plan = &value["plan"];
    exact(
        plan,
        &[
            "kind",
            "protocolVersion",
            "principalId",
            "projectId",
            "planId",
            "planHash",
            "policyRevision",
            "contextPins",
            "expiresAt",
            "steps",
            "nativeExecutions",
        ],
    )?;
    if plan["kind"] != "native_plan_approval"
        || plan["protocolVersion"] != mmmm_contracts::CONTRACT_VERSION
        || !array(plan, "nativeExecutions")?.is_empty()
    {
        return Err(invalid());
    }
    selected_plan(plan)?;
    PrincipalId::new(field(plan, "principalId")?).map_err(|_| invalid())?;
    sha(plan, "policyRevision")?;
    instant(field(plan, "expiresAt")?)?;
    if array(plan, "contextPins")?.len() != 1
        || array(plan, "steps")?.len() != 47
        || array(value, "programs")?.len() != 47
    {
        return Err(invalid());
    }
    for pin in array(plan, "contextPins")? {
        validator
            .validate("ContextPin", pin)
            .map_err(|_| invalid())?;
    }
    let mut ids = BTreeSet::new();
    let mut raw_total = 0usize;
    let suite = CalibrationDispatchPlan::normative47().map_err(|_| invalid())?;
    if value["suiteDigest"] != suite.suite_digest().as_str()
        || value["recipeSha256"] != suite.suite_digest().as_str()
    {
        return Err(invalid());
    }
    for (index, (step, program)) in array(plan, "steps")?
        .iter()
        .zip(array(value, "programs")?)
        .enumerate()
    {
        exact(
            step,
            &[
                "stepId",
                "bindingId",
                "actionId",
                "actionDigest",
                "implementationDigest",
                "argumentsDigest",
                "contextId",
                "contextDigest",
                "resourcesRead",
                "resourcesWritten",
                "preconditions",
            ],
        )?;
        if step["actionId"] != "mmmm:calibration_command_execute"
            || step["stepId"] != program["stepId"]
            || step["contextId"] != plan["contextPins"][0]["contextId"]
            || step["contextDigest"] != plan["contextPins"][0]["contextDigest"]
            || !ids.insert(field(step, "stepId")?)
        {
            return Err(invalid());
        }
        for key in ["stepId", "bindingId", "contextId"] {
            RequestId::new(field(step, key)?).map_err(|_| invalid())?;
        }
        for key in [
            "actionDigest",
            "implementationDigest",
            "argumentsDigest",
            "contextDigest",
        ] {
            sha(step, key)?;
        }
        for key in ["resourcesRead", "resourcesWritten"] {
            for id in array(step, key)? {
                mmmm_contracts::TargetId::new(id.as_str().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            }
        }
        for condition in array(step, "preconditions")? {
            validator
                .validate("Precondition", condition)
                .map_err(|_| invalid())?;
        }
        exact(
            program,
            &[
                "stepId",
                "caseId",
                "functionId",
                "command",
                "programDigest",
                "sourceSha256",
                "sourceBytesHex",
                "targetBindings",
                "commands",
                "preseedEndIndex",
                "selectedCommandStageIndex",
                "initializationCommands",
                "cleanupCommands",
            ],
        )?;
        for key in ["programDigest", "sourceSha256"] {
            sha(program, key)?;
        }
        let raw = field(program, "sourceBytesHex")?;
        if raw.is_empty()
            || raw.len() > 131072
            || !raw.len().is_multiple_of(2)
            || !raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid());
        }
        raw_total = raw_total
            .checked_add(raw.len() / 2)
            .filter(|v| *v <= 1024 * 1024)
            .ok_or_else(invalid)?;
        let bytes = (0..raw.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).map_err(|_| invalid()))
            .collect::<Result<Vec<_>, _>>()?;
        if raw_digest(&bytes).as_str() != field(program, "sourceSha256")? {
            return Err(invalid());
        }
        // Compare only source recipe data. This creates no native observation,
        // loaded-function receipt, initialization ownership or execution grant.
        let sealed =
            program_manifest(&step["stepId"], &suite.programs()[index]).map_err(|_| invalid())?;
        if program != &sealed {
            return Err(invalid());
        }
        let bindings = crate::calibration_observer::target_bindings(&suite.programs()[index]);
        let targets = bindings
            .as_array()
            .ok_or_else(invalid)?
            .iter()
            .map(|binding| binding["targetId"].clone())
            .collect::<Vec<_>>();
        if step["resourcesRead"] != json!(targets)
            || step["resourcesWritten"] != json!(targets)
            || array(step, "preconditions")?.len() != 2
        {
            return Err(invalid());
        }
        for (condition, target) in array(step, "preconditions")?.iter().zip(&targets) {
            if condition["kind"] != "resource_hash"
                || condition["coverage"] != "full_target"
                || condition["subject"] != *target
            {
                return Err(invalid());
            }
            Sha256Digest::new(condition["expected"].as_str().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
        }
    }
    Ok(())
}
fn validate_pack_run_manifest(
    value: &Value,
    validator: &ContractValidator,
) -> Result<(), ManagementError> {
    exact(
        value,
        &[
            "kind",
            "purpose",
            "selectionDigest",
            "hostEpoch",
            "registryGeneration",
            "runtimeSourceFactsDigest",
            "programDigest",
            "sourceBundleDigest",
            "sourceZipResource",
            "sourceOrigin",
            "plan",
            "targetId",
            "stepGuards",
        ],
    )?;
    if value["kind"] != "native_pack_calibration_run_approval/1"
        || value["purpose"] != crate::calibration_pack_run::PURPOSE
        || value["targetId"] != "calibration-objective-mcalpack"
    {
        return Err(invalid());
    }
    for key in [
        "selectionDigest",
        "runtimeSourceFactsDigest",
        "programDigest",
        "sourceBundleDigest",
    ] {
        sha(value, key)?;
    }
    let recipe =
        mmmm_compiler::calibration::CalibrationPackProgram::java_26_3().map_err(|_| invalid())?;
    if value["programDigest"] != recipe.program_digest().as_str() {
        return Err(invalid());
    }
    SessionEpoch::new(field(value, "hostEpoch")?).map_err(|_| invalid())?;
    generation(field(value, "registryGeneration")?)?;
    let zip = &value["sourceZipResource"];
    exact(zip, &["resourceId", "sha256", "sizeBytes", "mediaType"])?;
    ResourceId::new(field(zip, "resourceId")?).map_err(|_| invalid())?;
    sha(zip, "sha256")?;
    if zip["sizeBytes"].as_u64().is_none_or(|size| size == 0)
        || zip["mediaType"] != "application/zip"
    {
        return Err(invalid());
    }
    let origin = &value["sourceOrigin"];
    exact(
        origin,
        &[
            "operationId",
            "invocationId",
            "invocationDigest",
            "frozenManifestDigest",
        ],
    )?;
    mmmm_contracts::OperationId::new(field(origin, "operationId")?).map_err(|_| invalid())?;
    mmmm_contracts::InvocationId::new(field(origin, "invocationId")?).map_err(|_| invalid())?;
    sha(origin, "invocationDigest")?;
    sha(origin, "frozenManifestDigest")?;
    let plan = &value["plan"];
    exact(
        plan,
        &[
            "kind",
            "protocolVersion",
            "principalId",
            "projectId",
            "planId",
            "planHash",
            "policyRevision",
            "contextPins",
            "expiresAt",
            "steps",
            "nativeExecutions",
        ],
    )?;
    if plan["kind"] != "native_plan_approval"
        || plan["protocolVersion"] != mmmm_contracts::CONTRACT_VERSION
        || !array(plan, "nativeExecutions")?.is_empty()
        || array(plan, "contextPins")?.len() != 1
        || array(plan, "steps")?.len() != 3
    {
        return Err(invalid());
    }
    selected_plan(plan)?;
    PrincipalId::new(field(plan, "principalId")?).map_err(|_| invalid())?;
    sha(plan, "policyRevision")?;
    instant(field(plan, "expiresAt")?)?;
    validator
        .validate("ContextPin", &plan["contextPins"][0])
        .map_err(|_| invalid())?;
    let guards = json!({
        "pack-init-objective":{"kind":"initial_absence"},
        "pack-seed-marker":{"kind":"actual_previous_after","previousStepId":"pack-init-objective"},
        "pack-entry":{"kind":"actual_previous_after","previousStepId":"pack-seed-marker"},
    });
    if value["stepGuards"] != guards {
        return Err(invalid());
    }
    let first_conditions = &plan["steps"][0]["preconditions"];
    for (step, (id, command)) in array(plan, "steps")?.iter().zip([
        (
            "pack-init-objective",
            "scoreboard objectives add mcalpack dummy",
        ),
        (
            "pack-seed-marker",
            "scoreboard players set #marker mcalpack 7331",
        ),
        ("pack-entry", "function mmmm_calibration:pack/entry"),
    ]) {
        exact(
            step,
            &[
                "stepId",
                "bindingId",
                "actionId",
                "actionDigest",
                "implementationDigest",
                "argumentsDigest",
                "contextId",
                "contextDigest",
                "resourcesRead",
                "resourcesWritten",
                "preconditions",
            ],
        )?;
        if step["stepId"] != id
            || step["actionId"] != "mmmm:command_execute"
            || step["argumentsDigest"]
                != canonical_digest(&json!({"command":command}))
                    .map_err(|_| invalid())?
                    .as_str()
            || step["contextId"] != plan["contextPins"][0]["contextId"]
            || step["contextDigest"] != plan["contextPins"][0]["contextDigest"]
            || step["resourcesRead"] != json!([value["targetId"]])
            || step["resourcesWritten"] != json!([value["targetId"]])
            || &step["preconditions"] != first_conditions
        {
            return Err(invalid());
        }
        for key in ["stepId", "bindingId", "contextId"] {
            RequestId::new(field(step, key)?).map_err(|_| invalid())?;
        }
        for key in [
            "actionDigest",
            "implementationDigest",
            "argumentsDigest",
            "contextDigest",
        ] {
            sha(step, key)?;
        }
        for condition in array(step, "preconditions")? {
            validator
                .validate("Precondition", condition)
                .map_err(|_| invalid())?;
        }
    }
    Ok(())
}
fn reference(value: &str) -> Result<(), ManagementError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn instant(value: &str) -> Result<time::OffsetDateTime, ManagementError> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|_| invalid())
}
fn generation(value: &str) -> Result<(), ManagementError> {
    if value.is_empty()
        || value.len() > 19
        || value.starts_with('0')
        || !value.bytes().all(|b| b.is_ascii_digit())
        || value.parse::<i64>().ok().is_none_or(|v| v <= 0)
    {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Default)]
pub(super) struct CalibrationApprovals {
    pending: BTreeMap<RequestId, PendingCalibration>,
    pack_pending: BTreeMap<RequestId, PendingPackRun>,
    confirmed: CalibrationRegistry,
    // Retain original typed source/transport failures; public diagnostics never
    // expose untrusted messages, local paths, capabilities or raw offers.
    failures: Vec<CalibrationFailure>,
}
struct CalibrationFailure {
    _witness: BootstrapWitness,
    _cause: StorageError,
    _completion: Option<Arc<CompletedBootstrap>>,
    _original_offer: Arc<PublicFrame>,
}
struct PendingCalibration {
    _slot: CalibrationPendingSlot,
    public: Arc<PublicFrame>,
    witness: BootstrapWitness,
    budget: BootstrapBudget,
    selection: CalibrationSelectionRecord,
    manifest_digest: Sha256Digest,
    confirmation: CalibrationConfirmationRequest,
    context: Value,
    token: Option<SecretToken>,
    route: Option<CalibrationHostRoute>,
    complete_issued: bool,
    completion: Option<Arc<CompletedBootstrap>>,
    first_failure: Option<StorageError>,
}
struct PendingPackRun {
    _slot: CalibrationPendingSlot,
    public: Arc<PublicFrame>,
    witness: BootstrapWitness,
    budget: BootstrapBudget,
    plan: Value,
    selection: Value,
    manifest: Value,
    manifest_digest: Sha256Digest,
    context: Value,
    policy_digest: Sha256Digest,
    token: Option<SecretToken>,
    route: Option<PackRunHostRoute>,
    complete_issued: bool,
    completion: Option<Arc<CompletedBootstrap>>,
    first_failure: Option<StorageError>,
    current_failure: Option<StorageError>,
}
fn retain_pack_failure(pending: &mut PendingPackRun, cause: StorageError) {
    if pending.first_failure.is_none() {
        pending.first_failure = Some(cause);
    } else {
        // Keep the original cause and the current checkpoint in bounded slots.
        // Repeated invalid transport messages cannot grow a recursive history.
        pending.current_failure = Some(cause);
    }
}
fn take_pack_failure(pending: &mut PendingPackRun) -> Option<StorageError> {
    match (pending.first_failure.take(), pending.current_failure.take()) {
        (Some(primary), Some(checkpoint)) => Some(StorageError::CalibrationCheckpointFailure {
            primary: Box::new(primary),
            checkpoint: Box::new(checkpoint),
        }),
        (primary, checkpoint) => primary.or(checkpoint),
    }
}
#[derive(Debug)]
struct PackPublicationFailure(Arc<mmmm_application::AppError>);
impl std::fmt::Display for PackPublicationFailure {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("Original PACK approval publication failure is retained")
    }
}
impl std::error::Error for PackPublicationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
fn pack_confirmation_result(
    confirmed: mmmm_application::AppResult<()>,
    publication_failure: Option<Arc<mmmm_application::AppError>>,
) -> StorageResult<bool> {
    match confirmed {
        Ok(()) => Ok(publication_failure.is_some()),
        Err(cause) => {
            let checkpoint = app_failure(cause);
            Err(match publication_failure {
                Some(primary) => StorageError::CalibrationCheckpointFailure {
                    primary: Box::new(StorageError::Io(std::io::Error::other(
                        PackPublicationFailure(primary),
                    ))),
                    checkpoint: Box::new(checkpoint),
                },
                None => checkpoint,
            })
        }
    }
}
impl CalibrationApprovals {
    pub(super) fn with_registry(confirmed: CalibrationRegistry) -> Self {
        Self {
            confirmed,
            ..Self::default()
        }
    }
    pub(super) fn registry(&self) -> CalibrationRegistry {
        self.confirmed.clone()
    }
}

struct ApprovalRpc<'a> {
    owner: NativeOwnerWitness,
    budget: &'a BootstrapBudget,
    deadline: Instant,
    route: Option<&'a CalibrationHostRoute>,
    completion: Option<&'a CompletedBootstrap>,
    expected: Option<&'a CalibrationConfirmationRequest>,
}
impl CalibrationApprovalRpcContext for ApprovalRpc<'_> {
    fn check(&self) -> StorageResult<()> {
        if Instant::now() >= self.deadline {
            return Err(codec_failure(ManagementError::Deadline));
        }
        self.budget
            .check()
            .map_err(|cause| StorageError::Io(std::io::Error::other(cause)))?;
        self.owner.check()
    }
    fn authenticated_local_owner(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.owner.principal().clone())
    }
    fn check_current_approval(
        &self,
        store: &DurableStore,
        approval: &CalibrationApprovalRecord,
    ) -> StorageResult<()> {
        self.check()?;
        self.owner
            .check_project(store, &approval.selection().pins().project_id)?;
        if self.expected != Some(approval.confirmation())
            || !self
                .completion
                .is_some_and(|r| r.delivered() && r.completed_at() < self.budget.deadline())
        {
            return Err(denied());
        }
        // A live remote check is performed before the transaction by the
        // confirmation authority. The claim checkpoint must remain local.
        self.route
            .ok_or_else(denied)?
            .check_bootstrap_local(self.budget)
            .map_err(app_failure)?;
        self.check()
    }
}
struct PolicyRpc<'a> {
    owner: &'a NativeOwnerWitness,
    budget: &'a BootstrapBudget,
}
impl ProjectSourceRpcContext for PolicyRpc<'_> {
    fn check(&self) -> StorageResult<()> {
        self.budget.check().map_err(codec_failure)?;
        self.owner.check()
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.owner.principal().clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        None
    }
}
struct SelectionAuthority<'a> {
    owner: &'a NativeOwnerWitness,
    budget: &'a BootstrapBudget,
    authority: &'a LocalAuthority,
    context: &'a Value,
    context_witness: &'a HostContextWitness,
    expected: &'a CalibrationSelectionRequest,
    confirmed: Option<(
        &'a CalibrationConfirmationRequest,
        &'a CompletedBootstrap,
        &'a CalibrationHostRoute,
    )>,
}
impl SelectionAuthority<'_> {
    fn check(&self, store: &DurableStore) -> StorageResult<()> {
        self.owner.check_project(store, &self.expected.project_id)?;
        self.budget
            .check()
            .map_err(|cause| StorageError::Io(std::io::Error::other(cause)))?;
        self.context_witness.check_local().map_err(app_failure)?;
        let principal =
            PrincipalId::new(field(self.context, "principalRef").map_err(codec_failure)?)
                .map_err(|_| denied())?;
        let id = ContextId::new(field(self.context, "contextId").map_err(codec_failure)?)
            .map_err(|_| denied())?;
        self.authority
            .authorize_retained_scope(
                &principal,
                &self.expected.project_id,
                &id,
                &self.expected.policy_revision,
                &self.context["scope"],
            )
            .map_err(app_failure)?;
        if policy_digest(
            store,
            self.owner,
            self.budget,
            &self.expected.project_id,
            &self.expected.project_base_revision,
        )? != self.expected.policy_digest
        {
            return Err(denied());
        }
        let plan = store.plan(&self.expected.plan_id, &self.expected.plan_hash)?;
        verify_normative_plan(&plan)?;
        if plan["contextPins"] != self.expected.context_pins {
            return Err(denied());
        }
        self.authority
            .authorize_retained_scope(
                &principal,
                &self.expected.project_id,
                &id,
                &self.expected.policy_revision,
                &plan["scope"],
            )
            .map_err(app_failure)?;
        Ok(())
    }
}
impl CalibrationApprovalAuthority for SelectionAuthority<'_> {
    fn authorize_selection(
        &mut self,
        store: &DurableStore,
        owner: &PrincipalId,
        request: &CalibrationSelectionRequest,
    ) -> StorageResult<()> {
        if owner != self.owner.principal() || request != self.expected {
            return Err(denied());
        }
        self.check(store)
    }
    fn authorize_confirmation(
        &mut self,
        store: &DurableStore,
        selection: &CalibrationSelectionRecord,
        confirmation: &CalibrationConfirmationRequest,
    ) -> StorageResult<()> {
        self.check(store)?;
        let (expected, completion, route) = self.confirmed.ok_or_else(denied)?;
        if selection.pins() != self.expected
            || confirmation != expected
            || !completion.delivered()
            || completion.completed_at() >= self.budget.deadline()
        {
            return Err(denied());
        }
        route
            .check_bootstrap_current(self.budget)
            .map_err(app_failure)?;
        self.check(store)
    }
    fn authorize_dispatch(
        &mut self,
        _store: &DurableStore,
        _approval: &CalibrationApprovalRecord,
        _invocation: &Value,
    ) -> StorageResult<()> {
        // This first path registers real ADMIN issuance; no runner exists yet.
        // A later actual entered-request composition must supply this callback.
        Err(StorageError::Conflict("Calibration runner is unavailable"))
    }
}
fn denied() -> StorageError {
    StorageError::Conflict("Native calibration owner, current plan or pairing authority")
}
fn app_failure(cause: mmmm_application::AppError) -> StorageError {
    StorageError::Io(std::io::Error::other(cause))
}
fn verify_pack_host_artifact(plan: &Value, artifact: &Sha256Digest) -> StorageResult<()> {
    let steps = plan["steps"]
        .as_array()
        .filter(|steps| steps.len() == 3)
        .ok_or_else(denied)?;
    if steps
        .iter()
        .any(|step| step["implementationDigest"].as_str() != Some(artifact.as_str()))
    {
        return Err(denied());
    }
    Ok(())
}
fn codec_failure(cause: ManagementError) -> StorageError {
    StorageError::Io(std::io::Error::other(cause))
}

pub(crate) fn verify_normative_plan(plan: &Value) -> StorageResult<CalibrationDispatchPlan> {
    let suite = CalibrationDispatchPlan::normative47()
        .map_err(|e| StorageError::Contract(e.to_string()))?;
    let steps = plan["steps"]
        .as_array()
        .filter(|s| s.len() == 47)
        .ok_or_else(denied)?;
    if plan["contextPins"].as_array().is_none_or(|p| p.len() != 1) {
        return Err(denied());
    }
    let mut seen_steps = BTreeSet::new();
    let conditions = plan["preconditions"]
        .as_array()
        .filter(|v| v.len() == 94)
        .ok_or_else(denied)?;
    let mut targets = Vec::with_capacity(94);
    for (index, (step, program)) in steps.iter().zip(suite.programs()).enumerate() {
        let step_id = step["stepId"].as_str().ok_or_else(denied)?;
        let dependencies = step["dependsOn"].as_array().ok_or_else(denied)?;
        let predecessor_matches = if index == 0 {
            dependencies.is_empty()
        } else {
            dependencies.len() == 1 && dependencies[0] == steps[index - 1]["stepId"]
        };
        if step["actionId"] != "mmmm:calibration_command_execute"
            || step["arguments"] != json!({"command":program.invocation_command()})
            || step["actionContractVersion"] != "0.2.0"
            || !matches!(step["effect"].as_str(), Some("write" | "unknown"))
            || step["completion"] != "synchronous"
            || step["recovery"] != "none"
            || !step["resultBindings"].as_array().is_some_and(Vec::is_empty)
            || step["contextId"] != plan["contextId"]
            || step["verificationRequirement"] != "independent_readback"
            || !predecessor_matches
            || !seen_steps.insert(step_id)
        {
            return Err(denied());
        }
        let bindings = crate::calibration_observer::target_bindings(program);
        let owned = bindings
            .as_array()
            .ok_or_else(denied)?
            .iter()
            .map(|binding| binding["targetId"].clone())
            .collect::<Vec<_>>();
        if step["resourcesRead"] != json!(owned) || step["resourcesWritten"] != json!(owned) {
            return Err(denied());
        }
        for (condition, target) in conditions[index * 2..index * 2 + 2].iter().zip(&owned) {
            if condition["kind"] != "resource_hash"
                || condition["coverage"] != "full_target"
                || condition["subject"] != *target
                || condition.as_object().is_none_or(|v| v.len() != 4)
            {
                return Err(denied());
            }
            Sha256Digest::new(condition["expected"].as_str().ok_or_else(denied)?)
                .map_err(|_| denied())?;
        }
        targets.extend(owned);
    }
    if plan["scope"]["externalTargetIds"] != json!(targets)
        || plan["scope"]["resourceIds"]
            .as_array()
            .is_none_or(|v| !v.is_empty())
    {
        return Err(denied());
    }
    Ok(suite)
}

#[derive(Debug)]
enum CalibrationCleanupStop {
    Budget(ManagementError),
    Shutdown,
}
impl std::fmt::Display for CalibrationCleanupStop {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Budget(_) => "Original calibration bootstrap control ended",
            Self::Shutdown => "Calibration owner lifecycle is shutting down",
        })
    }
}
impl std::error::Error for CalibrationCleanupStop {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Budget(cause) => Some(cause),
            Self::Shutdown => None,
        }
    }
}
fn calibration_cleanup_stop(
    budget: &BootstrapBudget,
    shutdown: bool,
) -> Option<CalibrationCleanupStop> {
    match budget.check() {
        Err(cause) => Some(CalibrationCleanupStop::Budget(cause)),
        Ok(()) if shutdown => Some(CalibrationCleanupStop::Shutdown),
        Ok(()) => None,
    }
}
fn calibration_cleanup_failure(
    previous: Option<StorageError>,
    stopped: CalibrationCleanupStop,
) -> StorageError {
    let checkpoint = StorageError::Io(std::io::Error::other(stopped));
    match previous {
        Some(primary) => StorageError::CalibrationCheckpointFailure {
            primary: Box::new(primary),
            checkpoint: Box::new(checkpoint),
        },
        None => checkpoint,
    }
}
fn policy_digest(
    store: &DurableStore,
    owner: &NativeOwnerWitness,
    budget: &BootstrapBudget,
    project: &ProjectId,
    revision: &Sha256Digest,
) -> StorageResult<Sha256Digest> {
    let rpc = PolicyRpc { owner, budget };
    policy_digest_for_rpc(store, owner, &rpc, project, revision)
}
/// Shared bounded Policy read. Entered execution supplies its actual borrowed
/// request RPC; bootstrap supplies its original exchange budget. Neither is
/// retained by the reader or substituted with a newly allocated budget.
pub(crate) fn policy_digest_for_rpc(
    store: &DurableStore,
    owner: &NativeOwnerWitness,
    rpc: &dyn ProjectSourceRpcContext,
    project: &ProjectId,
    revision: &Sha256Digest,
) -> StorageResult<Sha256Digest> {
    use mmmm_runtime::storage::project_resources::current_project_head_pin;
    let head = current_project_head_pin(store, rpc, project)?;
    if &head.revision != revision {
        return Err(denied());
    }
    let project_value = store.project(project)?;
    let resource = ResourceId::new(
        project_value["policyResourceId"]
            .as_str()
            .ok_or_else(denied)?,
    )
    .map_err(|_| denied())?;
    let mut reader = native_owner_resource_reader(
        owner,
        project,
        revision,
        BTreeSet::from([resource.clone()]),
        1024 * 1024,
    )?;
    let query = ProjectResourceQuery::Current {
        resource_id: resource,
    };
    let request = ProjectResourceRequest {
        project,
        current_project_revision: revision,
        query: &query,
        expected: None,
    };
    let metadata = reader.metadata(store, rpc, &request)?;
    if metadata.resource["mediaType"] != "application/vnd.mmmm.policy+json" {
        return Err(denied());
    }
    let bytes = reader
        .read(
            store,
            rpc,
            &ProjectResourceRequest {
                expected: Some(&metadata.resource),
                ..request
            },
            1024 * 1024,
        )?
        .bytes;
    let value = mmmm_contracts::strict_json::parse_json_with_control(
        &bytes,
        mmmm_contracts::JsonLimits {
            max_bytes: 1024 * 1024,
            max_depth: 64,
            max_nodes: 100_000,
        },
        || rpc.check(),
    )
    .map_err(|cause| match cause {
        mmmm_contracts::strict_json::ControlledJsonError::Control(cause) => cause,
        mmmm_contracts::strict_json::ControlledJsonError::Json(cause) => {
            StorageError::Contract(cause.to_string())
        }
    })?;
    ContractValidator::shared()
        .map_err(|e| StorageError::Contract(e.to_string()))?
        .validate("Policy", &value)
        .map_err(|e| StorageError::Contract(e.to_string()))?;
    owner.check_project(store, project)?;
    projected_digest("Policy", &value).map_err(|e| StorageError::Contract(e.to_string()))
}

impl HostBootstrapProcessor {
    #[allow(clippy::too_many_arguments)] // Independent retained owner, context and original controls.
    fn pack_calibration_authority(
        &self,
        store: &DurableStore,
        owner: &NativeOwnerWitness,
        budget: &BootstrapBudget,
        plan: &Value,
        context: &Value,
        context_witness: &HostContextWitness,
        expected_policy: Option<&Sha256Digest>,
    ) -> StorageResult<Sha256Digest> {
        budget.check().map_err(codec_failure)?;
        let project = ProjectId::new(field(plan, "projectId").map_err(codec_failure)?)
            .map_err(|_| denied())?;
        let revision =
            Sha256Digest::new(field(plan, "projectBaseRevision").map_err(codec_failure)?)
                .map_err(|_| denied())?;
        let policy = Sha256Digest::new(field(plan, "policyRevision").map_err(codec_failure)?)
            .map_err(|_| denied())?;
        let context_id = ContextId::new(field(context, "contextId").map_err(codec_failure)?)
            .map_err(|_| denied())?;
        owner.check_project(store, &project)?;
        context_witness.check_local().map_err(app_failure)?;
        if context["principalRef"] != owner.principal().as_str()
            || context["contextDigest"] != plan["contextPins"][0]["contextDigest"]
            || context["environment"] != plan["contextPins"][0]["environment"]
        {
            return Err(denied());
        }
        self.authority
            .authorize_retained_scope(
                owner.principal(),
                &project,
                &context_id,
                &policy,
                &context["scope"],
            )
            .map_err(app_failure)?;
        self.authority
            .authorize_retained_scope(
                owner.principal(),
                &project,
                &context_id,
                &policy,
                &plan["scope"],
            )
            .map_err(app_failure)?;
        let pin = policy_digest(store, owner, budget, &project, &revision)?;
        if expected_policy.is_some_and(|expected| expected != &pin) {
            return Err(denied());
        }
        self.calibration
            .confirmed
            .pack_runs()
            .check_prepared(store, plan, &|| {
                budget.check().map_err(|cause| {
                    mmmm_application::AppError::caused_by(
                        "HOST_UNAVAILABLE",
                        "Original PACK approval control ended",
                        cause,
                    )
                })?;
                owner.check_project(store, &project).map_err(|cause| {
                    mmmm_application::AppError::storage("PERMISSION_REQUIRED", cause)
                })?;
                context_witness.check_local()
            })
            .map_err(app_failure)?;
        Ok(pin)
    }

    fn pack_calibration_offer(
        &mut self,
        store: &DurableStore,
        public: Arc<PublicFrame>,
        token: Option<SecretToken>,
        witness: BootstrapWitness,
        budget: &BootstrapBudget,
        reply_deadline: Instant,
    ) -> Result<PublicFrame, ManagementError> {
        let result = (|| -> StorageResult<PublicFrame> {
            let value = public.value();
            budget.check().map_err(codec_failure)?;
            if Instant::now() >= reply_deadline {
                return Err(codec_failure(ManagementError::Deadline));
            }
            let project = ProjectId::new(field(value, "projectId").map_err(codec_failure)?)
                .map_err(|_| denied())?;
            let id = PlanId::new(field(value, "planId").map_err(codec_failure)?)
                .map_err(|_| denied())?;
            let hash = Sha256Digest::new(field(value, "planHash").map_err(codec_failure)?)
                .map_err(|_| denied())?;
            let owner = NativeOwnerWitness::capture(store, budget.deadline().min(reply_deadline))?;
            owner.check_project(store, &project)?;
            let plan = store.plan(&id, &hash)?;
            if plan["projectId"] != project.as_str() {
                return Err(denied());
            }
            let (context, context_witness, artifact) =
                self.calibration_snapshot(store, &plan, budget)?;
            verify_pack_host_artifact(&plan, &artifact)?;
            let policy_digest = self.pack_calibration_authority(
                store,
                &owner,
                budget,
                &plan,
                &context,
                &context_witness,
                None,
            )?;
            let registry = self.calibration.confirmed.pack_runs();
            if value["kind"] == "native_calibration_owner_offer" {
                if token.is_some() {
                    return Err(denied());
                }
                let selected = registry.select(store, &plan).map_err(app_failure)?;
                exact(&selected, &["approvalRef", "selectionDigest", "expiresAt"])
                    .map_err(codec_failure)?;
                reference(field(&selected, "approvalRef").map_err(codec_failure)?)
                    .map_err(codec_failure)?;
                sha(&selected, "selectionDigest").map_err(codec_failure)?;
                instant(field(&selected, "expiresAt").map_err(codec_failure)?)
                    .map_err(codec_failure)?;
                return PublicFrame::from_value(json!({
                    "kind":"native_calibration_owner_selected", "protocolVersion":mmmm_contracts::CONTRACT_VERSION,
                    "nonce":witness.nonce(), "purpose":crate::calibration_pack_run::PURPOSE,
                    "projectId":project, "planId":id, "planHash":hash,
                    "approvalRef":selected["approvalRef"], "selectionDigest":selected["selectionDigest"],
                    "expiresAt":selected["expiresAt"],
                })).map_err(codec_failure);
            }
            if value["kind"] != "host_apply_approval_offer"
                || token.is_none()
                || context["principalRef"] != value["principalId"]
                || context["environment"] != value["hostHello"]["environment"]
                || value["hostArtifactDigest"] != artifact.as_str()
                || value["hostHello"]["hostBuild"] != artifact.as_str()
                || value["contextIds"] != json!([context["contextId"]])
            {
                return Err(denied());
            }
            crate::catalog_source::validate_source_facts(&value["runtimeSourceFacts"], &context)
                .map_err(app_failure)?;
            let selection = registry.selection(store, &plan).map_err(app_failure)?;
            let manifest = registry
                .manifest(store, &plan, &context, &value["runtimeSourceFacts"])
                .map_err(app_failure)?;
            validate_pack_run_manifest(
                &manifest,
                ContractValidator::shared()
                    .map_err(|cause| StorageError::Contract(cause.to_string()))?,
            )
            .map_err(codec_failure)?;
            if manifest["selectionDigest"] != selection["selectionDigest"]
                || manifest["plan"]["planId"] != plan["planId"]
                || manifest["plan"]["planHash"] != plan["planHash"]
            {
                return Err(denied());
            }
            let manifest_digest = canonical_digest(&manifest)
                .map_err(|cause| StorageError::Contract(cause.to_string()))?;
            let actions = plan["steps"]
                .as_array()
                .ok_or_else(denied)?
                .iter()
                .map(|step| {
                    field(step, "actionDigest")
                        .map(str::to_owned)
                        .map_err(codec_failure)
                })
                .collect::<StorageResult<BTreeSet<_>>>()?;
            let reply = PublicFrame::from_value(json!({
                "kind":"host_apply_approval_authority", "protocolVersion":mmmm_contracts::CONTRACT_VERSION,
                "nonce":witness.nonce(), "purpose":crate::calibration_pack_run::PURPOSE,
                "contexts":[context], "approvedSources":{(NATIVE_SOURCE_ID):artifact},
                "approvedActions":actions, "permissions":READ_PERMISSIONS, "manifest":manifest,
            })).map_err(codec_failure)?;
            budget.check().map_err(codec_failure)?;
            if Instant::now() >= reply_deadline {
                return Err(codec_failure(ManagementError::Deadline));
            }
            let slot = self
                .calibration
                .confirmed
                .reserve_pending(store, &witness, budget, &owner)
                .map_err(codec_failure)?;
            self.calibration.pack_pending.insert(
                witness.id().clone(),
                PendingPackRun {
                    _slot: slot,
                    public: public.clone(),
                    witness: witness.clone(),
                    budget: budget.clone(),
                    plan,
                    selection,
                    manifest,
                    manifest_digest,
                    context,
                    policy_digest,
                    token,
                    route: None,
                    complete_issued: false,
                    completion: None,
                    first_failure: None,
                    current_failure: None,
                },
            );
            Ok(reply)
        })();
        match result {
            Ok(reply) => Ok(reply),
            Err(cause) => {
                self.calibration.failures.push(CalibrationFailure {
                    _witness: witness,
                    _cause: cause,
                    _completion: None,
                    _original_offer: public,
                });
                Err(ManagementError::InvalidFrame)
            }
        }
    }

    fn install_pack_calibration(
        &mut self,
        store: &DurableStore,
        public: PublicFrame,
        witness: BootstrapWitness,
        coordinator_epoch: &SessionEpoch,
        budget: &BootstrapBudget,
        reply_deadline: Instant,
    ) -> Result<PublicFrame, ManagementError> {
        let pending = self
            .calibration
            .pack_pending
            .get_mut(witness.id())
            .ok_or(ManagementError::WrongReply)?;
        if !same_witness(&pending.witness, &witness)
            || public.nonce() != pending.witness.nonce()
            || public.value()["kind"] != "host_apply_approval_installed"
            || public.value()["purpose"] != crate::calibration_pack_run::PURPOSE
            || public.value()["selectionDigest"] != pending.selection["selectionDigest"]
            || public.value()["manifestDigest"] != pending.manifest_digest.as_str()
            || pending.complete_issued
        {
            return Err(ManagementError::WrongReply);
        }
        budget.check()?;
        pending.budget.check()?;
        if Instant::now() >= reply_deadline {
            return Err(ManagementError::Deadline);
        }
        // This is still the same retained prepared source in this Store, not
        // an admission derived from the public purpose or manifest JSON.
        self.calibration
            .confirmed
            .pack_runs()
            .check_prepared(store, &pending.plan, &|| {
                pending.budget.check().map_err(|cause| {
                    mmmm_application::AppError::caused_by(
                        "HOST_UNAVAILABLE",
                        "Original PACK approval control ended",
                        cause,
                    )
                })
            })
            .map_err(|cause| {
                retain_pack_failure(pending, app_failure(cause));
                ManagementError::WrongReply
            })?;
        let endpoint = &public.value()["hostEndpoint"];
        if endpoint["hostEpoch"] != pending.context["environment"]["sessionEpoch"] {
            return Err(ManagementError::WrongReply);
        }
        let epoch = field(endpoint, "hostEpoch")?;
        let record = EndpointRecord {
            schema_version: 1,
            contract_version: mmmm_contracts::CONTRACT_VERSION.into(),
            address: field(endpoint, "address")?.parse().map_err(|_| invalid())?,
            path: field(endpoint, "path")?.into(),
            coordinator_epoch: epoch.into(),
            credential_ref: format!("MMMM.coordinator.calibration-{}", witness.id()),
        };
        let token = pending.token.take().ok_or(ManagementError::WrongReply)?;
        let client = HostRpcClient::paired(record, token).map_err(|cause| {
            retain_pack_failure(pending, StorageError::Io(std::io::Error::other(cause)));
            ManagementError::Disconnected
        })?;
        let remaining =
            instant(field(&pending.selection, "expiresAt")?)? - time::OffsetDateTime::now_utc();
        let expires = Instant::now()
            .checked_add(Duration::try_from(remaining).map_err(|_| ManagementError::Deadline)?)
            .ok_or(ManagementError::Deadline)?;
        let principal =
            PrincipalId::new(field(&pending.context, "principalRef")?).map_err(|_| invalid())?;
        match self.hosts.prepare_pack_run_route(
            client,
            principal,
            vec![pending.context.clone()],
            pending.public.value()["hostHello"].clone(),
            expires,
            &pending.budget,
        ) {
            Ok(route) => pending.route = Some(route),
            Err(cause) => {
                retain_pack_failure(pending, app_failure(cause));
                return Err(ManagementError::Disconnected);
            }
        }
        budget.check()?;
        pending.budget.check()?;
        if Instant::now() >= reply_deadline {
            return Err(ManagementError::Deadline);
        }
        let reply = PublicFrame::from_value(json!({
            "kind":"host_apply_approval_complete", "protocolVersion":mmmm_contracts::CONTRACT_VERSION,
            "nonce":witness.nonce(), "purpose":crate::calibration_pack_run::PURPOSE,
            "selectionDigest":pending.selection["selectionDigest"], "manifestDigest":pending.manifest_digest,
            "ready":true, "coordinatorEpoch":coordinator_epoch, "hostEpoch":epoch,
            "contextId":pending.context["contextId"],
        }))?;
        pending.complete_issued = true;
        Ok(reply)
    }

    fn finish_pack_calibration(
        &mut self,
        store: &DurableStore,
        receipt: CompletedBootstrap,
    ) -> Result<(), ManagementError> {
        let mut pending = self
            .calibration
            .pack_pending
            .remove(receipt.witness().id())
            .ok_or(ManagementError::WrongReply)?;
        if !same_witness(&pending.witness, receipt.witness()) {
            self.calibration
                .pack_pending
                .insert(pending.witness.id().clone(), pending);
            return Err(ManagementError::WrongReply);
        }
        if let Some(old) = &pending.completion {
            if old.delivered() != receipt.delivered()
                || old.completed_at() != receipt.completed_at()
            {
                self.calibration
                    .pack_pending
                    .insert(pending.witness.id().clone(), pending);
                return Err(ManagementError::WrongReply);
            }
        } else {
            pending.completion = Some(Arc::new(receipt));
        }
        let observed = pending
            .completion
            .as_ref()
            .ok_or(ManagementError::WrongReply)?
            .clone();
        let result = (|| -> StorageResult<bool> {
            if !pending.complete_issued
                || !observed.delivered()
                || observed.completed_at() >= pending.budget.deadline()
            {
                return Err(denied());
            }
            let route = pending.route.as_ref().ok_or_else(denied)?;
            route
                .check_bootstrap_current(&pending.budget)
                .map_err(app_failure)?;
            let owner = NativeOwnerWitness::capture(store, pending.budget.deadline())?;
            let (context, context_witness, artifact) =
                self.calibration_snapshot(store, &pending.plan, &pending.budget)?;
            verify_pack_host_artifact(&pending.plan, &artifact)?;
            self.pack_calibration_authority(
                store,
                &owner,
                &pending.budget,
                &pending.plan,
                &context,
                &context_witness,
                Some(&pending.policy_digest),
            )?;
            let registry = self.calibration.confirmed.pack_runs();
            if registry
                .selection(store, &pending.plan)
                .map_err(app_failure)?
                != pending.selection
                || registry
                    .manifest(
                        store,
                        &pending.plan,
                        &context,
                        &pending.public.value()["runtimeSourceFacts"],
                    )
                    .map_err(app_failure)?
                    != pending.manifest
            {
                return Err(denied());
            }
            let principal =
                PrincipalId::new(field(&context, "principalRef").map_err(codec_failure)?)
                    .map_err(|_| denied())?;
            let project = ProjectId::new(field(&pending.plan, "projectId").map_err(codec_failure)?)
                .map_err(|_| denied())?;
            let lifetime = route
                .lease_expires()
                .saturating_duration_since(Instant::now());
            // Borrow the original control and local witnesses across both the
            // authority publication and the final retained confirmation.
            let current = || {
                pending.budget.check().map_err(|cause| {
                    mmmm_application::AppError::caused_by(
                        match cause {
                            ManagementError::Cancelled => "CANCELLED",
                            ManagementError::Deadline => "TIME_BUDGET_EXCEEDED",
                            _ => "HOST_UNAVAILABLE",
                        },
                        "Original PACK confirmation control is no longer current",
                        cause,
                    )
                })?;
                owner.check_project(store, &project).map_err(|cause| {
                    mmmm_application::AppError::storage("PERMISSION_REQUIRED", cause)
                })?;
                context_witness.check_local()?;
                route.check_bootstrap_local(&pending.budget)
            };
            let publication = self.authority.approve_plan_with_control(
                &principal,
                &pending.plan,
                lifetime,
                pending.budget.deadline(),
                &current,
            );
            let publication_failure = publication.err().map(Arc::new);
            // A completed real ADMIN exchange is retained even when LocalAuthority
            // publication fails. Registry presence cannot erase that failure or
            // admit execution; the consumer must check publication_failure.
            let confirmed = registry.confirm(
                store,
                &pending.plan,
                &pending.manifest,
                route.clone(),
                observed.clone(),
                publication_failure.clone(),
                &current,
            );
            pack_confirmation_result(confirmed, publication_failure)
        })();
        match result {
            Ok(false) => Ok(()),
            Ok(true) => Err(ManagementError::WrongReply),
            Err(cause) => {
                retain_pack_failure(&mut pending, cause);
                if self.calibration.failures.len() >= MAX_REJECTED_COMPLETIONS {
                    self.calibration
                        .pack_pending
                        .insert(pending.witness.id().clone(), pending);
                    return Err(ManagementError::TransportUncertain);
                }
                if let Some(route) = &pending.route
                    && let Err(cause) = route.retire()
                {
                    retain_pack_failure(&mut pending, app_failure(cause));
                    self.calibration
                        .pack_pending
                        .insert(pending.witness.id().clone(), pending);
                    return Err(ManagementError::TransportUncertain);
                }
                let delivered = observed.delivered();
                let cause =
                    take_pack_failure(&mut pending).ok_or(ManagementError::TransportUncertain)?;
                self.calibration.failures.push(CalibrationFailure {
                    _witness: pending.witness,
                    _cause: cause,
                    _completion: Some(observed),
                    _original_offer: pending.public,
                });
                if delivered {
                    Err(ManagementError::WrongReply)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn cleanup_pack_calibration(&mut self, shutdown: bool) -> Result<(), ManagementError> {
        let expired = self
            .calibration
            .pack_pending
            .iter()
            .filter_map(|(id, pending)| {
                calibration_cleanup_stop(&pending.budget, shutdown).map(|stop| (id.clone(), stop))
            })
            .collect::<Vec<_>>();
        for (id, stop) in expired {
            if self.calibration.failures.len() >= MAX_REJECTED_COMPLETIONS {
                return Err(ManagementError::TransportUncertain);
            }
            let mut pending = self
                .calibration
                .pack_pending
                .remove(&id)
                .ok_or(ManagementError::WrongReply)?;
            if let Some(route) = &pending.route
                && let Err(cause) = route.retire()
            {
                let stopped = StorageError::Io(std::io::Error::other(stop));
                retain_pack_failure(&mut pending, stopped);
                retain_pack_failure(&mut pending, app_failure(cause));
                self.calibration.pack_pending.insert(id, pending);
                return Err(ManagementError::TransportUncertain);
            }
            let previous = take_pack_failure(&mut pending);
            self.calibration.failures.push(CalibrationFailure {
                _witness: pending.witness,
                _cause: calibration_cleanup_failure(previous, stop),
                _completion: pending.completion,
                _original_offer: pending.public,
            });
        }
        self.calibration
            .confirmed
            .pack_runs()
            .retire_expired(shutdown)
            .map_err(|_| ManagementError::TransportUncertain)
    }

    fn calibration_snapshot(
        &self,
        store: &DurableStore,
        plan: &Value,
        budget: &BootstrapBudget,
    ) -> StorageResult<(Value, HostContextWitness, Sha256Digest)> {
        budget.check().map_err(codec_failure)?;
        let id =
            ContextId::new(plan["contextId"].as_str().ok_or_else(denied)?).map_err(|_| denied())?;
        let active = self
            .active
            .get(&id)
            .filter(|active| Instant::now() < active.expires && active.route_owner.is_some())
            .ok_or_else(denied)?;
        if plan["projectId"] != active.project.as_str()
            || plan["policyRevision"] != active.policy.as_str()
        {
            return Err(denied());
        }
        let witness = self
            .hosts
            .observe_context_witness(&active.principal, &id, budget.deadline())
            .map_err(app_failure)?;
        let context = witness.context().clone();
        let hello = self
            .hosts
            .hello_with_deadline(&active.principal, &id, budget.deadline())
            .map_err(app_failure)?;
        if plan["contextPins"][0]["contextDigest"] != context["contextDigest"]
            || plan["contextPins"][0]["environment"] != context["environment"]
            || context["environment"]["side"] != "server"
        {
            return Err(denied());
        }
        let artifact = Sha256Digest::new(hello["hostBuild"].as_str().ok_or_else(denied)?)
            .map_err(|_| denied())?;
        let rpc = OwnerSetupRpcContext::for_store(store, Some(budget))?;
        let mut authority = OwnerSetupAuthority::for_read(&rpc);
        host_setup(
            store,
            &rpc,
            &mut authority,
            &active.project,
            &artifact,
            None,
        )?;
        Ok((context, witness, artifact))
    }
    fn calibration_selection_request(
        &self,
        store: &DurableStore,
        owner: &NativeOwnerWitness,
        budget: &BootstrapBudget,
        plan: &Value,
        artifact: Sha256Digest,
    ) -> StorageResult<CalibrationSelectionRequest> {
        let suite = verify_normative_plan(plan)?;
        let project_id =
            ProjectId::new(plan["projectId"].as_str().ok_or_else(denied)?).map_err(|_| denied())?;
        let revision = Sha256Digest::new(plan["projectBaseRevision"].as_str().ok_or_else(denied)?)
            .map_err(|_| denied())?;
        let hash = Sha256Digest::new(plan["planHash"].as_str().ok_or_else(denied)?)
            .map_err(|_| denied())?;
        Ok(CalibrationSelectionRequest {
            approval_ref: format!("calibration-{}", hash),
            project_id: project_id.clone(),
            project_base_revision: revision.clone(),
            plan_id: PlanId::new(plan["planId"].as_str().ok_or_else(denied)?)
                .map_err(|_| denied())?,
            plan_hash: hash,
            policy_revision: Sha256Digest::new(plan["policyRevision"].as_str().ok_or_else(denied)?)
                .map_err(|_| denied())?,
            policy_digest: policy_digest(store, owner, budget, &project_id, &revision)?,
            suite_digest: suite.suite_digest().clone(),
            recipe: store.put_blob(suite.canonical_recipe_bytes())?,
            host_artifact_digest: artifact,
            scope_digest: canonical_digest(&plan["scope"])
                .map_err(|e| StorageError::Contract(e.to_string()))?,
            context_pins: plan["contextPins"].clone(),
            expires_at: plan["expiresAt"].as_str().ok_or_else(denied)?.into(),
        })
    }
    pub(super) fn calibration_offer(
        &mut self,
        store: &mut DurableStore,
        offer: HostOffer,
        budget: &BootstrapBudget,
        reply_deadline: Instant,
    ) -> Result<PublicFrame, ManagementError> {
        // The shared registry counts prepared, confirmed and RAII-reserved
        // pending entries. A local remove/reinsert keeps the same reservation.
        if self.calibration.confirmed.len()? >= MAX_PENDING
            || self.calibration.failures.len() >= MAX_REJECTED_COMPLETIONS
        {
            return Err(ManagementError::Busy);
        }
        let (public, token, witness) = offer.into_parts();
        if Path::new(field(public.value(), "dataRoot")?) != store.data_root()
            || canonical_digest(public.value()).map_err(|_| invalid())? != *witness.offer_digest()
        {
            return Err(ManagementError::WrongReply);
        }
        let public = Arc::new(public);
        if public.value()["purpose"] == crate::calibration_pack_run::PURPOSE {
            return self.pack_calibration_offer(
                store,
                public,
                token,
                witness,
                budget,
                reply_deadline,
            );
        }
        let result = (|| -> StorageResult<PublicFrame> {
            let value = public.value();
            budget.check().map_err(codec_failure)?;
            let project = ProjectId::new(field(value, "projectId").map_err(codec_failure)?)
                .map_err(|_| denied())?;
            let plan_id = PlanId::new(field(value, "planId").map_err(codec_failure)?)
                .map_err(|_| denied())?;
            let hash = Sha256Digest::new(field(value, "planHash").map_err(codec_failure)?)
                .map_err(|_| denied())?;
            let owner = NativeOwnerWitness::capture(store, budget.deadline().min(reply_deadline))?;
            owner.check_project(store, &project)?;
            let plan = store.plan(&plan_id, &hash)?;
            if plan["projectId"] != project.as_str() {
                return Err(denied());
            }
            let (context, context_witness, artifact) =
                self.calibration_snapshot(store, &plan, budget)?;
            let request =
                self.calibration_selection_request(store, &owner, budget, &plan, artifact.clone())?;
            let rpc = ApprovalRpc {
                owner: owner.clone(),
                budget,
                deadline: reply_deadline,
                route: None,
                completion: None,
                expected: None,
            };
            let mut authority = SelectionAuthority {
                owner: &owner,
                budget,
                authority: &self.authority,
                context: &context,
                context_witness: &context_witness,
                expected: &request,
                confirmed: None,
            };
            if value["kind"] == "native_calibration_owner_offer" {
                if token.is_some() {
                    return Err(denied());
                }
                // Commit is final here. Response publication failures retain
                // this immutable selection; they cannot withdraw other grants.
                let selected =
                    register_calibration_selection(store, &rpc, &mut authority, &request)?;
                return PublicFrame::from_value(json!({"kind":"native_calibration_owner_selected",
                    "protocolVersion":mmmm_contracts::CONTRACT_VERSION,"nonce":witness.nonce(),"purpose":PURPOSE,
                    "projectId":project,"planId":plan_id,"planHash":hash,"approvalRef":selected.approval_ref(),
                    "selectionDigest":selected.selection_digest(),"expiresAt":selected.pins().expires_at})).map_err(codec_failure);
            }
            if token.is_none()
                || context["principalRef"] != value["principalId"]
                || context["environment"] != value["hostHello"]["environment"]
                || value["hostArtifactDigest"] != artifact.as_str()
                || value["hostHello"]["hostBuild"] != artifact.as_str()
                || value["contextIds"] != json!([context["contextId"]])
            {
                return Err(denied());
            }
            crate::catalog_source::validate_source_facts(&value["runtimeSourceFacts"], &context)
                .map_err(app_failure)?;
            let selection = calibration_selection(
                store,
                &rpc,
                &mut authority,
                &project,
                &request.approval_ref,
            )?
            .ok_or_else(denied)?;
            let manifest = build_manifest(&plan, &context, value, &selection)?;
            let manifest_digest =
                canonical_digest(&manifest).map_err(|e| StorageError::Contract(e.to_string()))?;
            let confirmation = CalibrationConfirmationRequest {
                selection_digest: selection.selection_digest().clone(),
                principal_id: PrincipalId::new(field(value, "principalId").map_err(codec_failure)?)
                    .map_err(|_| denied())?,
                player_id: field(value, "playerId").map_err(codec_failure)?.into(),
                original_offer_digest: witness.offer_digest().clone(),
                nonce: witness.nonce().into(),
                host_epoch: field(&context["environment"], "sessionEpoch")
                    .map_err(codec_failure)?
                    .into(),
                registry_generation: field(&value["runtimeSourceFacts"], "registryGeneration")
                    .map_err(codec_failure)?
                    .into(),
                runtime_source_facts_digest: crate::catalog_source::source_facts_pin(
                    &value["runtimeSourceFacts"],
                )
                .map_err(app_failure)?,
                manifest_digest: manifest_digest.clone(),
            };
            let actions = plan["steps"]
                .as_array()
                .ok_or_else(denied)?
                .iter()
                .map(|step| {
                    step["actionDigest"]
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(denied)
                })
                .collect::<StorageResult<BTreeSet<_>>>()?;
            let authority=PublicFrame::from_value(json!({"kind":"host_apply_approval_authority","protocolVersion":mmmm_contracts::CONTRACT_VERSION,
                "nonce":witness.nonce(),"purpose":PURPOSE,"contexts":[context],"approvedSources":{(NATIVE_SOURCE_ID):artifact},
                "approvedActions":actions,"permissions":READ_PERMISSIONS,"manifest":manifest})).map_err(codec_failure)?;
            rpc.check()?;
            let slot = self
                .calibration
                .confirmed
                .reserve_pending(store, &witness, budget, &owner)
                .map_err(codec_failure)?;
            self.calibration.pending.insert(
                witness.id().clone(),
                PendingCalibration {
                    _slot: slot,
                    public: public.clone(),
                    witness: witness.clone(),
                    budget: budget.clone(),
                    selection,
                    manifest_digest,
                    confirmation,
                    context,
                    token,
                    route: None,
                    complete_issued: false,
                    completion: None,
                    first_failure: None,
                },
            );
            Ok(authority)
        })();
        match result {
            Ok(reply) => Ok(reply),
            Err(cause) => {
                self.calibration.failures.push(CalibrationFailure {
                    _witness: witness,
                    _cause: cause,
                    _completion: None,
                    _original_offer: public,
                });
                Err(ManagementError::InvalidFrame)
            }
        }
    }
    pub(super) fn has_calibration_witness(&self, witness: &BootstrapWitness) -> bool {
        self.calibration.pending.contains_key(witness.id())
            || self.calibration.pack_pending.contains_key(witness.id())
    }
    pub(super) fn has_calibration_completion(&self) -> bool {
        self.calibration
            .pending
            .values()
            .any(|pending| pending.complete_issued)
            || self
                .calibration
                .pack_pending
                .values()
                .any(|pending| pending.complete_issued)
    }
    pub(super) fn install_calibration(
        &mut self,
        store: &DurableStore,
        public: PublicFrame,
        witness: BootstrapWitness,
        coordinator_epoch: &SessionEpoch,
        budget: &BootstrapBudget,
        reply_deadline: Instant,
    ) -> Result<PublicFrame, ManagementError> {
        if self.calibration.pack_pending.contains_key(witness.id()) {
            return self.install_pack_calibration(
                store,
                public,
                witness,
                coordinator_epoch,
                budget,
                reply_deadline,
            );
        }
        let pending = self
            .calibration
            .pending
            .get_mut(witness.id())
            .ok_or(ManagementError::WrongReply)?;
        if !same_witness(&pending.witness, &witness)
            || public.nonce() != pending.witness.nonce()
            || public.value()["kind"] != "host_apply_approval_installed"
            || public.value()["purpose"] != PURPOSE
            || pending.complete_issued
            || public.value()["selectionDigest"] != pending.selection.selection_digest().as_str()
            || public.value()["manifestDigest"] != pending.manifest_digest.as_str()
        {
            return Err(ManagementError::WrongReply);
        }
        budget.check()?;
        pending.budget.check()?;
        if Instant::now() >= reply_deadline {
            return Err(ManagementError::Deadline);
        }
        let endpoint = &public.value()["hostEndpoint"];
        if endpoint["hostEpoch"] != pending.context["environment"]["sessionEpoch"] {
            return Err(ManagementError::WrongReply);
        }
        let epoch = field(endpoint, "hostEpoch")?;
        let record = EndpointRecord {
            schema_version: 1,
            contract_version: mmmm_contracts::CONTRACT_VERSION.into(),
            address: field(endpoint, "address")?.parse().map_err(|_| invalid())?,
            path: field(endpoint, "path")?.into(),
            coordinator_epoch: epoch.into(),
            credential_ref: format!("MMMM.coordinator.calibration-{}", witness.id()),
        };
        let token = pending.token.take().ok_or(ManagementError::WrongReply)?;
        let client = HostRpcClient::paired(record, token).map_err(|_| invalid())?;
        let remaining =
            instant(&pending.selection.pins().expires_at)? - time::OffsetDateTime::now_utc();
        let duration = Duration::try_from(remaining).map_err(|_| ManagementError::Deadline)?;
        let expires = Instant::now()
            .checked_add(duration)
            .ok_or(ManagementError::Deadline)?;
        let principal = pending.confirmation.principal_id.clone();
        let route = self.hosts.prepare_calibration_route(
            client,
            principal,
            vec![pending.context.clone()],
            pending.public.value()["hostHello"].clone(),
            expires,
            &pending.budget,
        );
        match route {
            Ok(route) => pending.route = Some(route),
            Err(cause) => {
                pending.first_failure = Some(app_failure(cause));
                return Err(ManagementError::Disconnected);
            }
        }
        budget.check()?;
        pending.budget.check()?;
        if Instant::now() >= reply_deadline {
            return Err(ManagementError::Deadline);
        }
        let complete = PublicFrame::from_value(
            json!({"kind":"host_apply_approval_complete","protocolVersion":mmmm_contracts::CONTRACT_VERSION,
            "nonce":witness.nonce(),"purpose":PURPOSE,"selectionDigest":pending.selection.selection_digest(),"manifestDigest":pending.manifest_digest,
            "ready":true,"coordinatorEpoch":coordinator_epoch,"hostEpoch":epoch,"contextId":pending.context["contextId"]}),
        )?;
        pending.complete_issued = true;
        Ok(complete)
    }
    pub(super) fn finish_calibration(
        &mut self,
        store: &mut DurableStore,
        receipt: CompletedBootstrap,
    ) -> Result<(), ManagementError> {
        if self
            .calibration
            .pack_pending
            .contains_key(receipt.witness().id())
        {
            return self.finish_pack_calibration(store, receipt);
        }
        let mut pending = self
            .calibration
            .pending
            .remove(receipt.witness().id())
            .ok_or(ManagementError::WrongReply)?;
        if !same_witness(&pending.witness, receipt.witness()) {
            self.calibration
                .pending
                .insert(pending.witness.id().clone(), pending);
            return Err(ManagementError::WrongReply);
        }
        if let Some(old) = &pending.completion {
            if old.delivered() != receipt.delivered()
                || old.completed_at() != receipt.completed_at()
            {
                self.calibration
                    .pending
                    .insert(pending.witness.id().clone(), pending);
                return Err(ManagementError::WrongReply);
            }
        } else {
            pending.completion = Some(Arc::new(receipt));
        }
        let observed = pending
            .completion
            .as_ref()
            .ok_or(ManagementError::WrongReply)?
            .clone();
        let result = (|| -> StorageResult<CalibrationApprovalRecord> {
            if self
                .calibration
                .confirmed
                .contains(pending.selection.approval_ref())
                .map_err(codec_failure)?
            {
                return Err(StorageError::Conflict(
                    "Calibration confirmed private generation cannot be replaced",
                ));
            }
            if !pending.complete_issued
                || !observed.delivered()
                || observed.completed_at() >= pending.budget.deadline()
            {
                return Err(denied());
            }
            let route = pending.route.as_ref().ok_or_else(denied)?;
            let owner = NativeOwnerWitness::capture(store, pending.budget.deadline())?;
            let plan = store.plan(
                &pending.selection.pins().plan_id,
                &pending.selection.pins().plan_hash,
            )?;
            let (context, context_witness, _) =
                self.calibration_snapshot(store, &plan, &pending.budget)?;
            let rpc = ApprovalRpc {
                owner: owner.clone(),
                budget: &pending.budget,
                deadline: pending.budget.deadline(),
                route: Some(route),
                completion: Some(&observed),
                expected: Some(&pending.confirmation),
            };
            let mut authority = SelectionAuthority {
                owner: &owner,
                budget: &pending.budget,
                authority: &self.authority,
                context: &context,
                context_witness: &context_witness,
                expected: pending.selection.pins(),
                confirmed: Some((&pending.confirmation, &observed, route)),
            };
            confirm_calibration_approval(
                store,
                &rpc,
                &mut authority,
                &pending.selection,
                &pending.confirmation,
            )
        })();
        match result {
            Ok(record) => {
                // The protected confirmation already committed. No output or
                // subsequent budget check is allowed to hide that receipt.
                let route = pending
                    .route
                    .as_ref()
                    .ok_or(ManagementError::TransportUncertain)?
                    .clone();
                let publication = (|| {
                    let plan = store
                        .plan(
                            &record.selection().pins().plan_id,
                            &record.selection().pins().plan_hash,
                        )
                        .map_err(|cause| {
                            mmmm_application::AppError::storage(
                                "CALIBRATION_APPROVAL_SOURCE_UNAVAILABLE",
                                cause,
                            )
                        })?;
                    let lifetime = route
                        .lease_expires()
                        .saturating_duration_since(Instant::now());
                    self.authority.approve_plan_with_control(&pending.confirmation.principal_id,&plan,lifetime,pending.budget.deadline(),&|| {
                        pending.budget.check().map_err(|cause|mmmm_application::AppError::caused_by(
                            match cause {ManagementError::Cancelled=>"CANCELLED",ManagementError::Deadline=>"TIME_BUDGET_EXCEEDED",_=>"HOST_UNAVAILABLE"},
                            "Original calibration confirmation control is no longer current",cause))
                    })
                })();
                let failed = publication.is_err();
                let retained = self.calibration.confirmed.insert(
                    pending.selection.approval_ref().into(),
                    std::rc::Rc::new(ConfirmedCalibration {
                        capacity: pending._slot.confirmed(&observed),
                        record,
                        route,
                        completion: observed,
                        publication_failure: publication.err().map(Arc::new),
                        store_root: store.data_root().to_path_buf(),
                    }),
                );
                if let Err(cause) = retained {
                    if pending.first_failure.is_none() {
                        pending.first_failure = Some(codec_failure(cause));
                    }
                    self.calibration
                        .pending
                        .insert(pending.witness.id().clone(), pending);
                    return Err(ManagementError::TransportUncertain);
                }
                if failed {
                    Err(ManagementError::WrongReply)
                } else {
                    Ok(())
                }
            }
            Err(cause) => {
                if pending.first_failure.is_none() {
                    pending.first_failure = Some(cause);
                }
                if self.calibration.failures.len() >= MAX_REJECTED_COMPLETIONS {
                    self.calibration
                        .pending
                        .insert(pending.witness.id().clone(), pending);
                    return Err(ManagementError::TransportUncertain);
                }
                if let Some(route) = &pending.route
                    && route.retire().is_err()
                {
                    self.calibration
                        .pending
                        .insert(pending.witness.id().clone(), pending);
                    return Err(ManagementError::TransportUncertain);
                }
                let delivered = observed.delivered();
                self.calibration.failures.push(CalibrationFailure {
                    _witness: pending.witness,
                    _cause: pending
                        .first_failure
                        .take()
                        .ok_or(ManagementError::TransportUncertain)?,
                    _completion: Some(observed),
                    _original_offer: pending.public,
                });
                if delivered {
                    Err(ManagementError::WrongReply)
                } else {
                    Ok(())
                }
            }
        }
    }
    pub(super) fn cleanup_calibration(&mut self, shutdown: bool) -> Result<(), ManagementError> {
        self.cleanup_pack_calibration(shutdown)?;
        let expired = self
            .calibration
            .pending
            .iter()
            .filter_map(|(id, pending)| {
                calibration_cleanup_stop(&pending.budget, shutdown)
                    .map(|stopped| (id.clone(), stopped))
            })
            .collect::<Vec<_>>();
        for (id, stopped) in expired {
            if self.calibration.failures.len() >= MAX_REJECTED_COMPLETIONS {
                return Err(ManagementError::TransportUncertain);
            }
            let mut pending = self
                .calibration
                .pending
                .remove(&id)
                .ok_or(ManagementError::WrongReply)?;
            if let Some(route) = &pending.route
                && route.retire().is_err()
            {
                self.calibration.pending.insert(id, pending);
                return Err(ManagementError::TransportUncertain);
            }
            self.calibration.failures.push(CalibrationFailure {
                _witness: pending.witness,
                _cause: calibration_cleanup_failure(pending.first_failure.take(), stopped),
                _completion: pending.completion,
                _original_offer: pending.public,
            });
        }
        let expired = self.calibration.confirmed.expired(shutdown)?;
        for id in expired {
            let confirmed = self
                .calibration
                .confirmed
                .remove(&id)?
                .ok_or(ManagementError::WrongReply)?;
            if confirmed.route.retire().is_err() {
                self.calibration.confirmed.insert(id, confirmed)?;
                return Err(ManagementError::TransportUncertain);
            }
        }
        Ok(())
    }
}

/// Render only the exact retained plan summary for the private PACK exchange.
/// This codec issues neither source authority nor a plan execution grant.
pub(crate) fn pack_run_plan_manifest(
    plan: &Value,
    context: &Value,
) -> mmmm_application::AppResult<Value> {
    let failure = || {
        mmmm_application::AppError::new(
            "PACK_SOURCE_UNAVAILABLE",
            "The retained PACK plan summary is unavailable",
        )
    };
    if plan["contextPins"]
        .as_array()
        .is_none_or(|pins| pins.len() != 1)
        || context["contextId"] != plan["contextPins"][0]["contextId"]
        || context["contextDigest"] != plan["contextPins"][0]["contextDigest"]
        || context["environment"] != plan["contextPins"][0]["environment"]
    {
        return Err(failure());
    }
    let conditions = plan["preconditions"].as_array().ok_or_else(failure)?;
    let steps = plan["steps"].as_array().filter(|steps| steps.len() == 3)
        .ok_or_else(failure)?.iter().map(|step| {
            let arguments_digest = canonical_digest(&step["arguments"])
                .map_err(|_| failure())?;
            Ok(json!({
                "stepId":step["stepId"], "bindingId":step["bindingId"],
                "actionId":step["actionId"], "actionDigest":step["actionDigest"],
                "implementationDigest":step["implementationDigest"], "argumentsDigest":arguments_digest,
                "contextId":step["contextId"], "contextDigest":plan["contextPins"][0]["contextDigest"],
                "resourcesRead":step["resourcesRead"], "resourcesWritten":step["resourcesWritten"],
                "preconditions":conditions,
            }))
        }).collect::<mmmm_application::AppResult<Vec<_>>>()?;
    Ok(json!({
        "kind":"native_plan_approval", "protocolVersion":mmmm_contracts::CONTRACT_VERSION,
        "principalId":context["principalRef"], "projectId":plan["projectId"],
        "planId":plan["planId"], "planHash":plan["planHash"], "policyRevision":plan["policyRevision"],
        "contextPins":plan["contextPins"], "expiresAt":plan["expiresAt"],
        "steps":steps, "nativeExecutions":[],
    }))
}

fn build_manifest(
    plan: &Value,
    context: &Value,
    offer: &Value,
    selection: &CalibrationSelectionRecord,
) -> StorageResult<Value> {
    let suite = verify_normative_plan(plan)?;
    let steps = plan["steps"].as_array().ok_or_else(denied)?;
    let programs = steps
        .iter()
        .zip(suite.programs())
        .map(|(step, program)| program_manifest(&step["stepId"], program))
        .collect::<StorageResult<Vec<_>>>()?;
    let steps = steps
        .iter()
        .enumerate().map(|(index,step)| {
            let arguments_digest = canonical_digest(&step["arguments"])
                .map_err(|cause| StorageError::Contract(cause.to_string()))?;
            Ok(json!({"stepId":step["stepId"],"bindingId":step["bindingId"],"actionId":step["actionId"],"actionDigest":step["actionDigest"],
                "implementationDigest":step["implementationDigest"],"argumentsDigest":arguments_digest,"contextId":step["contextId"],"contextDigest":plan["contextPins"][0]["contextDigest"],
                "resourcesRead":step["resourcesRead"],"resourcesWritten":step["resourcesWritten"],"preconditions":&plan["preconditions"].as_array().ok_or_else(denied)?[index*2..index*2+2]}))
        })
        .collect::<StorageResult<Vec<_>>>()?;
    Ok(
        json!({"kind":"native_calibration_approval/2","purpose":PURPOSE,"selectionDigest":selection.selection_digest(),
        "hostEpoch":context["environment"]["sessionEpoch"],"registryGeneration":offer["runtimeSourceFacts"]["registryGeneration"],
        "runtimeSourceFactsDigest":crate::catalog_source::source_facts_pin(&offer["runtimeSourceFacts"]).map_err(app_failure)?,
        "suiteDigest":suite.suite_digest(),"recipeSha256":suite.suite_digest(),"programs":programs,
        "plan":{"kind":"native_plan_approval","protocolVersion":mmmm_contracts::CONTRACT_VERSION,"principalId":context["principalRef"],
            "projectId":plan["projectId"],"planId":plan["planId"],"planHash":plan["planHash"],"policyRevision":plan["policyRevision"],
            "contextPins":plan["contextPins"],"expiresAt":plan["expiresAt"],"steps":steps,"nativeExecutions":[]}}),
    )
}

fn program_manifest(
    step: &Value,
    program: &mmmm_compiler::calibration::CalibrationProgram,
) -> StorageResult<Value> {
    let function = program
        .invocation_command()
        .strip_prefix("function ")
        .ok_or_else(denied)?;
    // sourceBytesHex keeps the exact original comments and LF bytes. commands
    // is the sealed non-comment native execution sequence, not a replacement
    // body reconstructed by Java or permission to execute the function inline.
    let hex = program
        .source_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(json!({
        "stepId":step,"caseId":program.case().case_id(),"functionId":function,
        "command":program.invocation_command(),"programDigest":program.source_digest(),
        "sourceSha256":program.source_digest(),"sourceBytesHex":hex,"targetBindings":crate::calibration_observer::target_bindings(program),
        "commands":program.commands(),
        // [0, preseedEndIndex) is the prefix after which independent preseed
        // capture occurs; the selected stage is a zero-based native body site,
        // not the whole function's final command return.
        "preseedEndIndex":program.preseed_end_index(),
        "selectedCommandStageIndex":program.command_stage_index(),
        // These are comparison inputs from the same sealed program. They do
        // not grant a separate initialization/cleanup operation or lifetime.
        "initializationCommands":program.initialization_commands(),
        "cleanupCommands":program.cleanup_commands()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    // This minimal value exercises the private normative guard alone. Full
    // ExecutionPlan schema and storage admission remain separate checks.
    fn normative_guard_input() -> Value {
        let suite = CalibrationDispatchPlan::normative47().unwrap();
        let steps = suite
            .programs()
            .iter()
            .enumerate()
            .map(|(index, program)| {
                let bindings=crate::calibration_observer::target_bindings(program);
                let owned=bindings.as_array().unwrap().iter().map(|value|value["targetId"].clone()).collect::<Vec<_>>();
                json!({
                    "stepId": format!("calibration-{index}"),
                    "actionId": "mmmm:calibration_command_execute",
                    "arguments": {"command": program.invocation_command()},
                    "effect": "write",
                    "actionContractVersion":"0.2.0","completion":"synchronous","recovery":"none",
                    "resultBindings": [],
                    "contextId": "calibration-context",
                    "verificationRequirement": "independent_readback",
                    "resourcesRead":owned,"resourcesWritten":owned,
                    "dependsOn": if index == 0 { vec![] } else { vec![format!("calibration-{}", index - 1)] }
                })
            })
            .collect::<Vec<_>>();
        let targets = steps
            .iter()
            .flat_map(|step| step["resourcesWritten"].as_array().unwrap().clone())
            .collect::<Vec<_>>();
        let conditions=targets.iter().map(|target|json!({"kind":"resource_hash","subject":target,"expected":"6".repeat(64),"coverage":"full_target"})).collect::<Vec<_>>();
        json!({"contextId":"calibration-context", "contextPins":[{}], "steps":steps,"scope":{"resourceIds":[],"externalTargetIds":targets},"preconditions":conditions})
    }

    #[test]
    fn normative_guard_requires_independent_readback_and_original_predecessor_chain() {
        let original = normative_guard_input();
        assert!(verify_normative_plan(&original).is_ok());
        for weak in ["schema_only", "provider_completion"] {
            let mut changed = original.clone();
            changed["steps"][23]["verificationRequirement"] = json!(weak);
            assert!(verify_normative_plan(&changed).is_err());
        }
        for dependencies in [
            json!([]),
            json!(["calibration-21"]),
            json!(["calibration-23"]),
            json!(["calibration-22", "calibration-21"]),
            Value::Null,
        ] {
            let mut changed = original.clone();
            changed["steps"][23]["dependsOn"] = dependencies;
            assert!(verify_normative_plan(&changed).is_err());
        }
        let mut changed = original.clone();
        changed["steps"][0]["dependsOn"] = json!(["calibration-46"]);
        assert!(verify_normative_plan(&changed).is_err());
        let mut changed = original;
        changed["steps"][23]["stepId"] = json!("calibration-22");
        changed["steps"][24]["dependsOn"] = json!(["calibration-22"]);
        assert!(verify_normative_plan(&changed).is_err());
    }

    // Reuses the existing ContextPin example and sealed compiler recipe. The
    // private grammar previously lacked native body-site/init/cleanup inputs;
    // this fixture exercises that new producer/consumer boundary, not a game run.
    fn normative_manifest_input() -> Value {
        let suite = CalibrationDispatchPlan::normative47().unwrap();
        let example =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/execution-plan.json"))
                .unwrap();
        let steps = suite.programs().iter().enumerate().map(|(index, program)| {
            let addresses = &suite.owned_addresses()[index];
            // Match project_steps' two sealed-address footprint locators. This
            // checks the production frame shape, not target ownership or grants.
            let owned = [
                format!("calibration-objective-{}", addresses.objective()),
                format!("calibration-storage-{}", raw_digest(addresses.storage().as_str().as_bytes())),
            ];
            json!({
                "stepId":format!("calibration-{index}"),"bindingId":"calibration-binding",
                "actionId":"mmmm:calibration_command_execute","actionDigest":"1".repeat(64),"implementationDigest":"2".repeat(64),
                "argumentsDigest":canonical_digest(&json!({"command":program.invocation_command()})).unwrap(),
                "contextId":example["contextPins"][0]["contextId"],"contextDigest":example["contextPins"][0]["contextDigest"],
                "resourcesRead":owned,"resourcesWritten":owned,"preconditions":owned.iter().map(|target|json!({"kind":"resource_hash","subject":target,"expected":"6".repeat(64),"coverage":"full_target"})).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>();
        let programs = suite
            .programs()
            .iter()
            .enumerate()
            .map(|(index, program)| program_manifest(&steps[index]["stepId"], program).unwrap())
            .collect::<Vec<_>>();
        json!({
            "kind":"native_calibration_approval/2","purpose":PURPOSE,"selectionDigest":"3".repeat(64),
            "hostEpoch":"epoch-fixture-01","registryGeneration":"1","runtimeSourceFactsDigest":"4".repeat(64),
            "suiteDigest":suite.suite_digest(),"recipeSha256":suite.suite_digest(),"programs":programs,
            "plan":{"kind":"native_plan_approval","protocolVersion":"0.2.0","principalId":"principal-fixture",
                "projectId":"project-fixture","planId":"plan-fixture","planHash":"5".repeat(64),
                "policyRevision":example["policyRevision"],"contextPins":example["contextPins"],
                "expiresAt":"2099-01-01T00:00:00Z","steps":steps,"nativeExecutions":[]}
        })
    }

    #[test]
    fn private_program_manifest_requires_exact_sealed_body_sites_and_lifecycle_inputs() {
        let validator = ContractValidator::shared().unwrap();
        let original = normative_manifest_input();
        validate_manifest(&original, validator).unwrap();
        let mut old = original.clone();
        old["kind"] = json!("native_calibration_approval");
        assert!(validate_manifest(&old, validator).is_err());
        let mut old = original.clone();
        old["programs"][0]["readbackAddresses"] = json!({});
        assert!(validate_manifest(&old, validator).is_err());
        let mut changed = original.clone();
        changed["plan"]["steps"][0]["actionId"] = json!("mmmm:command_execute");
        assert!(validate_manifest(&changed, validator).is_err());
        let mut changed = original.clone();
        changed["plan"]["steps"][0]["preconditions"][1] =
            changed["plan"]["steps"][0]["preconditions"][0].clone();
        assert!(validate_manifest(&changed, validator).is_err());
        for key in [
            "targetBindings",
            "commands",
            "preseedEndIndex",
            "selectedCommandStageIndex",
            "initializationCommands",
            "cleanupCommands",
        ] {
            let mut changed = original.clone();
            changed["programs"][0].as_object_mut().unwrap().remove(key);
            assert!(validate_manifest(&changed, validator).is_err());
        }
        for (key, changed_value) in [
            ("commands", json!(["say caller_supplied"])),
            (
                "preseedEndIndex",
                json!(original["programs"][0]["preseedEndIndex"].as_u64().unwrap() + 1),
            ),
            (
                "selectedCommandStageIndex",
                json!(
                    original["programs"][0]["selectedCommandStageIndex"]
                        .as_u64()
                        .unwrap()
                        + 1
                ),
            ),
            (
                "initializationCommands",
                json!(["scoreboard objectives add caller_owned dummy"]),
            ),
            ("cleanupCommands", json!([])),
        ] {
            let mut changed = original.clone();
            changed["programs"][0][key] = changed_value;
            assert!(validate_manifest(&changed, validator).is_err());
        }
        let mut changed = original.clone();
        changed["programs"][0]["commands"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert!(validate_manifest(&changed, validator).is_err());
        let mut changed = original.clone();
        changed["programs"][0]["sourceBytesHex"] = json!("00");
        changed["programs"][0]["sourceSha256"] = json!(raw_digest(&[0]));
        changed["programs"][0]["programDigest"] = json!(raw_digest(&[0]));
        assert!(validate_manifest(&changed, validator).is_err());
        let mut changed = original.clone();
        changed["programs"].as_array_mut().unwrap().swap(0, 1);
        changed["plan"]["steps"].as_array_mut().unwrap().swap(0, 1);
        assert!(validate_manifest(&changed, validator).is_err());

        // Keep the actual authority frame's existing 1MiB/node bounds honest
        // after adding the sealed command lists; do not relax them silently.
        let mut context =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/execution-context.json"))
                .unwrap();
        context["scope"]["resourceIds"] = json!([]);
        context["scope"]["externalTargetIds"] = json!(
            original["plan"]["steps"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|step| step["resourcesWritten"].as_array().unwrap().clone())
                .collect::<Vec<_>>()
        );
        context["contextDigest"] =
            json!(mmmm_contracts::projected_digest("ExecutionContext", &context).unwrap());
        let mut original = original;
        original["plan"]["contextPins"][0]["contextDigest"] = context["contextDigest"].clone();
        for step in original["plan"]["steps"].as_array_mut().unwrap() {
            step["contextDigest"] = context["contextDigest"].clone();
        }
        let authority = json!({"kind":"host_apply_approval_authority","protocolVersion":"0.2.0","nonce":"calibration-manifest",
            "purpose":PURPOSE,"contexts":[context],"approvedSources":{"mmmm_host":"0".repeat(64)},
            "approvedActions":["1".repeat(64)],"permissions":READ_PERMISSIONS,"manifest":original});
        let bytes = serde_json::to_vec(&authority).unwrap().len();
        let mut pending = vec![&authority];
        let mut nodes = 0usize;
        while let Some(value) = pending.pop() {
            nodes += 1;
            match value {
                Value::Array(children) => pending.extend(children),
                Value::Object(children) => pending.extend(children.values()),
                _ => (),
            }
        }
        PublicFrame::from_value(authority).unwrap_or_else(|cause| {
            panic!("Normative authority frame failed its existing bounds: bytes={bytes}, nodes={nodes}, cause={cause}")
        });
        println!(
            "normative_calibration_authority bytes={bytes} nodes={nodes} limit_bytes={} limit_nodes=4096",
            crate::peer_management::MAX_PUBLIC_BYTES
        );
    }

    // Reuses the existing plan/context examples and the sealed PACK recipe.
    // Numeric fixtures cannot exercise the three distinct Invocation summaries,
    // immutable shared preconditions and private predecessor guards.
    fn pack_run_manifest_input() -> Value {
        let mut plan =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/execution-plan.json"))
                .unwrap();
        let context =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/execution-context.json"))
                .unwrap();
        plan["contextPins"][0]["contextId"] = context["contextId"].clone();
        plan["contextPins"][0]["contextDigest"] = context["contextDigest"].clone();
        plan["contextPins"][0]["environment"] = context["environment"].clone();
        plan["contextId"] = context["contextId"].clone();
        plan["steps"] = json!(
            [
                (
                    "pack-init-objective",
                    "scoreboard objectives add mcalpack dummy"
                ),
                (
                    "pack-seed-marker",
                    "scoreboard players set #marker mcalpack 7331"
                ),
                ("pack-entry", "function mmmm_calibration:pack/entry"),
            ]
            .into_iter()
            .map(|(id, command)| json!({
                "stepId":id, "bindingId":"pack-binding", "actionId":"mmmm:command_execute",
                "actionDigest":"1".repeat(64), "implementationDigest":"2".repeat(64),
                "arguments":{"command":command}, "contextId":context["contextId"],
                "resourcesRead":["calibration-objective-mcalpack"],
                "resourcesWritten":["calibration-objective-mcalpack"],
            }))
            .collect::<Vec<_>>()
        );
        let recipe = mmmm_compiler::calibration::CalibrationPackProgram::java_26_3().unwrap();
        json!({
            "kind":"native_pack_calibration_run_approval/1", "purpose":crate::calibration_pack_run::PURPOSE,
            "selectionDigest":"3".repeat(64), "hostEpoch":"pack-epoch", "registryGeneration":"1",
            "runtimeSourceFactsDigest":"4".repeat(64), "programDigest":recipe.program_digest(),
            "sourceBundleDigest":"5".repeat(64),
            "sourceZipResource":{"resourceId":"pack-zip-fixture", "sha256":"6".repeat(64), "sizeBytes":32, "mediaType":"application/zip"},
            "sourceOrigin":{"operationId":"pack-origin-operation", "invocationId":"pack-origin-invocation",
                "invocationDigest":"7".repeat(64), "frozenManifestDigest":"8".repeat(64)},
            "plan":pack_run_plan_manifest(&plan, &context).unwrap(), "targetId":"calibration-objective-mcalpack",
            "stepGuards":{
                "pack-init-objective":{"kind":"initial_absence"},
                "pack-seed-marker":{"kind":"actual_previous_after","previousStepId":"pack-init-objective"},
                "pack-entry":{"kind":"actual_previous_after","previousStepId":"pack-seed-marker"},
            },
        })
    }

    #[test]
    fn pack_run_manifest_keeps_purpose_commands_whole_target_and_actual_guard_order_closed() {
        let validator = ContractValidator::shared().unwrap();
        let original = pack_run_manifest_input();
        validate_manifest(&original, validator).unwrap();
        assert_eq!(
            original["plan"]["steps"][0]["preconditions"],
            original["plan"]["steps"][2]["preconditions"]
        );
        assert!(
            !original["plan"]["steps"][0]["preconditions"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        for (path, replacement) in [
            ("/purpose", json!(PURPOSE)),
            ("/kind", json!("native_calibration_approval/2")),
            ("/targetId", json!("pack-marker-only")),
            ("/programDigest", json!("9".repeat(64))),
            ("/sourceZipResource/mediaType", json!("application/json")),
            ("/sourceZipResource/sizeBytes", json!(0)),
            ("/stepGuards", json!([])),
            (
                "/stepGuards/pack-entry/previousStepId",
                json!("pack-init-objective"),
            ),
            (
                "/plan/steps/0/actionId",
                json!("mmmm:calibration_command_execute"),
            ),
            ("/plan/steps/1/stepId", json!("pack-init-objective")),
            (
                "/plan/steps/2/argumentsDigest",
                json!(
                    canonical_digest(&json!({"command":"function mmmm_calibration:pack/entry "}))
                        .unwrap()
                ),
            ),
            ("/plan/steps/1/preconditions", json!([])),
            (
                "/plan/steps/2/resourcesWritten",
                json!(["calibration-objective-mcalpack", "another-objective"]),
            ),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(path).unwrap() = replacement;
            assert!(validate_manifest(&changed, validator).is_err(), "{path}");
        }
        let mut changed = original;
        changed["sourceOrigin"]["ownerClaim"] = json!(true);
        assert!(validate_manifest(&changed, validator).is_err());
        let owner = json!({
            "kind":"native_calibration_owner_offer", "protocolVersion":mmmm_contracts::CONTRACT_VERSION,
            "nonce":"pack-owner-fixture", "purpose":crate::calibration_pack_run::PURPOSE,
            "dataRoot":std::env::temp_dir().to_str().unwrap(), "projectId":"project-fixture",
            "planId":"pack-plan-fixture", "planHash":"1".repeat(64),
        });
        assert!(validate_frame(&owner, validator).is_ok());
        let mut changed = owner;
        changed["purpose"] = json!("pack_calibration_run/2");
        assert!(validate_frame(&changed, validator).is_err());
    }

    #[test]
    fn pack_confirmation_failure_retains_actual_publication_and_confirmation_causes() {
        let publication = Arc::new(mmmm_application::AppError::new(
            "PACK_PUBLICATION_FAILED",
            "Actual publication failed",
        ));
        let failed = pack_confirmation_result(
            Err(mmmm_application::AppError::new(
                "PACK_CONFIRMATION_FAILED",
                "Actual confirmation failed",
            )),
            Some(publication.clone()),
        )
        .unwrap_err();
        let StorageError::CalibrationCheckpointFailure {
            primary,
            checkpoint,
        } = failed
        else {
            panic!("Both actual failures must remain in the typed failure graph");
        };
        let StorageError::Io(primary) = *primary else {
            panic!("Missing publication failure");
        };
        let retained = primary
            .get_ref()
            .unwrap()
            .downcast_ref::<PackPublicationFailure>()
            .unwrap();
        assert!(Arc::ptr_eq(&retained.0, &publication));
        let StorageError::Io(checkpoint) = *checkpoint else {
            panic!("Missing confirmation failure");
        };
        let checkpoint = checkpoint
            .get_ref()
            .unwrap()
            .downcast_ref::<mmmm_application::AppError>()
            .unwrap();
        assert_eq!(checkpoint.code, "PACK_CONFIRMATION_FAILED");
        assert!(pack_confirmation_result(Ok(()), Some(publication)).unwrap());
        assert!(!pack_confirmation_result(Ok(()), None).unwrap());
    }

    #[test]
    fn pack_owner_selection_requires_each_step_to_match_the_observed_host_artifact() {
        let artifact = Sha256Digest::new("1".repeat(64)).unwrap();
        let original = json!({"steps":[
            {"implementationDigest":artifact},
            {"implementationDigest":artifact},
            {"implementationDigest":artifact},
        ]});
        verify_pack_host_artifact(&original, &artifact).unwrap();
        for index in 0..3 {
            let mut changed = original.clone();
            changed["steps"][index]["implementationDigest"] = json!("2".repeat(64));
            assert!(verify_pack_host_artifact(&changed, &artifact).is_err());
        }
        let mut changed = original.clone();
        changed["steps"][1]
            .as_object_mut()
            .unwrap()
            .remove("implementationDigest");
        assert!(verify_pack_host_artifact(&changed, &artifact).is_err());
        let mut changed = original;
        changed["steps"].as_array_mut().unwrap().pop();
        assert!(verify_pack_host_artifact(&changed, &artifact).is_err());
    }

    fn retained_stop(cause: &StorageError) -> &CalibrationCleanupStop {
        let StorageError::Io(cause) = cause else {
            panic!("cleanup checkpoint must retain its typed lifecycle reason");
        };
        cause.get_ref().unwrap().downcast_ref().unwrap()
    }

    #[test]
    fn cleanup_preserves_observed_cancel_deadline_shutdown_and_original_failure() {
        let current = BootstrapBudget::new();
        assert!(calibration_cleanup_stop(&current, false).is_none());
        let shutdown =
            calibration_cleanup_failure(None, calibration_cleanup_stop(&current, true).unwrap());
        assert!(matches!(
            retained_stop(&shutdown),
            CalibrationCleanupStop::Shutdown
        ));
        assert!(retained_stop(&shutdown).source().is_none());

        let cancelled = BootstrapBudget::new();
        cancelled.cancel();
        let expired = BootstrapBudget::with_deadline(Instant::now());
        for (budget, expected) in [
            (&cancelled, ManagementError::Cancelled),
            (&expired, ManagementError::Deadline),
        ] {
            // Even shutdown must retain the original budget failure actually
            // observed during selection rather than inventing another reason.
            let stopped = calibration_cleanup_stop(budget, true).unwrap();
            let failure = calibration_cleanup_failure(Some(StorageError::Busy), stopped);
            assert!(matches!(failure.primary_failure(), StorageError::Busy));
            assert!(matches!(
                failure.source().unwrap().downcast_ref::<StorageError>(),
                Some(StorageError::Busy)
            ));
            let retained = retained_stop(failure.checkpoint_failure().unwrap());
            assert!(
                matches!(retained, CalibrationCleanupStop::Budget(cause) if *cause == expected)
            );
            assert_eq!(
                retained.source().unwrap().downcast_ref::<ManagementError>(),
                Some(&expected)
            );
        }
    }
}

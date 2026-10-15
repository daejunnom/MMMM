//! Factual calibration reads share the original Store, request and operation.
//! Raw native images never grant write, restore, source admission or a profile.
use crate::{
    calibration_execution::EnteredCalibration, host::HostBridge,
    observer::finish_native_observation, service::RequestContextWitness,
};
use mmmm_application::{
    AppError, AppResult, BeforeCapture, BeforeImage, DirectChange, ReadbackEvidence,
};
use mmmm_compiler::{
    BindingAddress,
    calibration::{CalibrationCase, CalibrationProgram},
};
use mmmm_contracts::{
    ContextId, ProjectId, Sha256Digest, canonical_digest, encode_json, raw_digest,
    strict_json::{ControlledJsonError, JsonLimits, parse_json_with_control},
};
use mmmm_runtime::storage::{
    BlobRef, DurableStore, EffectEvidence,
    artifact::{ResourceOwner, register_resource},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const IMAGE_BYTES: usize = 256 * 1024;
const NATIVE_BYTES: usize = 64 * 1024;
pub(crate) struct Images {
    pub(crate) images: Vec<BeforeImage>,
    pub(crate) value: Value,
}

pub(crate) fn target_bindings(program: &CalibrationProgram) -> Value {
    json!([
        {"targetId":format!("calibration-objective-{}",program.scope().objective()),"kind":"objective","objective":program.scope().objective()},
        {"targetId":format!("calibration-storage-{}",raw_digest(program.scope().storage().as_str().as_bytes())),"kind":"owned_storage","storage":program.scope().storage(),"ownedSubtrees":["inputs","invocation"]}
    ])
}
pub(crate) fn program_for(original: &Value) -> AppResult<CalibrationProgram> {
    let command = original["arguments"]["command"]
        .as_str()
        .ok_or_else(invalid)?;
    for case in CalibrationCase::ALL {
        let program = CalibrationProgram::for_case(*case).map_err(|e| {
            AppError::caused_by(
                e.code,
                "Sealed calibration source could not be constructed",
                e,
            )
        })?;
        if program.invocation_command() == command {
            return Ok(program);
        }
    }
    Err(invalid())
}
pub(crate) fn plan_images(
    store: &mut DurableStore,
    hosts: &HostBridge,
    request: &RequestContextWitness,
    context: &Value,
    program: &CalibrationProgram,
    current: &dyn Fn(&DurableStore) -> AppResult<()>,
) -> AppResult<Images> {
    current(store)?;
    let id: ContextId = decode(&context["contextId"])?;
    let selector = json!({"kind":"calibration_target_state","caseId":program.case().case_id(),"functionId":program.invocation_command().strip_prefix("function ").ok_or_else(invalid)?,"targetBindings":target_bindings(program)});
    let acquired = hosts.inspect_acquired_with_deadline(
        request.authenticated().principal(),
        &id,
        selector,
        request.budget().deadline(),
    )?;
    // A complete authenticated failure/success is retained before late control
    // checks. This is a Project-owned factual resource, never a grant marker.
    let response = acquired.into_acquired_response()?;
    retain_project_response(store, context, &response)?;
    let result = (|| {
        current(store)?;
        if response["status"] != "ok" {
            return Err(AppError::caused_by(
                "CALIBRATION_CAPTURE_UNAVAILABLE",
                "Actual calibration target query failed; its response is retained",
                NativeQueryFailure(response.clone()),
            ));
        }
        decode_images(&response["payload"], context, program, None, &|| {
            current(store)
        })
    })();
    finish_native_observation(result, current(store))
}
fn retain_project_response(
    store: &mut DurableStore,
    context: &Value,
    response: &Value,
) -> AppResult<()> {
    let bytes = encode_json(response).map_err(|_| invalid())?;
    if bytes.len() > crate::rpc::MAX_CONTROL_BYTES {
        return Err(limit());
    }
    let blob = store.put_blob(&bytes).map_err(storage)?;
    let project: ProjectId = decode(&context["projectId"])?;
    let resource = json!({"resourceId":format!("calibration-observation-{}",blob.digest),"sha256":blob.digest,"mediaType":"application/vnd.mmmm.calibration-observation+json","sizeBytes":blob.byte_length});
    register_resource(store, &resource, ResourceOwner::Project(project))
        .map_err(|e| AppError::caused_by(e.code, e.message, e))?;
    Ok(())
}
pub(crate) fn decode_images(
    value: &Value,
    context: &Value,
    program: &CalibrationProgram,
    pins: Option<(&Sha256Digest, &str)>,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<Images> {
    exact(
        value,
        &[
            "format",
            "protocolVersion",
            "environment",
            "contextId",
            "contextDigest",
            "runtimeSourceFactsDigest",
            "hostArtifactDigest",
            "registryGeneration",
            "targets",
            "observedFromTick",
            "observedToTick",
            "observedAt",
        ],
    )?;
    if value["format"] != "mmmm.native.calibration-target-images/1"
        || value["protocolVersion"] != "0.2.0"
        || value["environment"] != context["environment"]
        || value["contextId"] != context["contextId"]
        || value["contextDigest"] != context["contextDigest"]
    {
        return Err(invalid());
    }
    digest_field(value, "runtimeSourceFactsDigest")?;
    digest_field(value, "hostArtifactDigest")?;
    let generation = text(value, "registryGeneration")?;
    if generation.starts_with('0') || generation.parse::<i64>().ok().is_none_or(|v| v == 0) {
        return Err(invalid());
    }
    if let Some((facts, generation)) = pins
        && (value["runtimeSourceFactsDigest"] != facts.as_str()
            || value["registryGeneration"] != generation)
    {
        return Err(invalid());
    }
    for binding in target_bindings(program).as_array().ok_or_else(invalid)? {
        if !context["scope"]["externalTargetIds"]
            .as_array()
            .is_some_and(|targets| targets.contains(&binding["targetId"]))
        {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Calibration image target is outside the current external target scope",
            ));
        }
    }
    if text(value, "observedAt")?.len() > 128
        || time::OffsetDateTime::parse(
            text(value, "observedAt")?,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
    {
        return Err(invalid());
    }
    decode_pair(value, program, check)
}
pub(crate) fn decode_pair(
    value: &Value,
    program: &CalibrationProgram,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<Images> {
    check()?;
    if tick(&value["observedFromTick"])? > tick(&value["observedToTick"])? {
        return Err(invalid());
    }
    let bindings = target_bindings(program);
    let targets = value["targets"]
        .as_array()
        .filter(|v| v.len() == 2)
        .ok_or_else(invalid)?;
    let mut images = Vec::with_capacity(2);
    let mut total = 0usize;
    for (entry, binding) in targets.iter().zip(bindings.as_array().ok_or_else(invalid)?) {
        exact(entry, &["targetId", "rawBytesHex", "rawSha256"])?;
        if entry["targetId"] != binding["targetId"] {
            return Err(invalid());
        }
        let bytes = hex(text(entry, "rawBytesHex")?, IMAGE_BYTES, check)?;
        total = total
            .checked_add(bytes.len())
            .filter(|v| *v <= 2 * IMAGE_BYTES)
            .ok_or_else(limit)?;
        if raw_digest(&bytes) != digest_field(entry, "rawSha256")? {
            return Err(invalid());
        }
        let raw = parse(&bytes, IMAGE_BYTES, 16384, check)?;
        crate::native_payload::validate_calibration_image(&raw, binding).map_err(|e| {
            AppError::caused_by(
                "CALIBRATION_IMAGE_INVALID",
                "Actual native full-target image is invalid",
                e,
            )
        })?;
        if raw["status"] != "known" || raw["coverage"] != "full_target" {
            return Err(AppError::new(
                "CALIBRATION_CAPTURE_UNAVAILABLE",
                "Actual full-target state remains unknown",
            ));
        }
        // Validate every sidecar, including native metadata not selected by the
        // numeric recipe. Complete raw images remain the phase precondition.
        validate_image_nbt(&raw, check)?;
        images.push(BeforeImage {
            target: text(entry, "targetId")?.to_owned(),
            bytes,
        });
    }
    check()?;
    Ok(Images {
        images,
        value: value.clone(),
    })
}
pub(crate) fn prepare_images(
    entered: &EnteredCalibration<'_>,
    store: &mut DurableStore,
) -> AppResult<Images> {
    let original = entered.original();
    let program = program_for(original)?;
    let ready = entered
        .route()
        .prepare_observed(store, entered.request(), original, &|store| {
            entered.check_local(store)
        })?;
    exact(
        &ready,
        &[
            "format",
            "invocationId",
            "invocationDigest",
            "programDigest",
            "targetImages",
        ],
    )?;
    if ready["format"] != "mmmm.native.calibration-ready/1"
        || ready["invocationId"] != original["invocationId"]
        || ready["invocationDigest"] != canonical_digest(original).map_err(|_| invalid())?.as_str()
        || ready["programDigest"] != program.source_digest().as_str()
    {
        return Err(invalid());
    }
    let confirmation = entered.approval().confirmation();
    let images = decode_images(
        &ready["targetImages"],
        &original["context"],
        &program,
        Some((
            &confirmation.runtime_source_facts_digest,
            &confirmation.registry_generation,
        )),
        &|| entered.check_local(store),
    )?;
    if ready["targetImages"]["hostArtifactDigest"]
        != entered
            .approval()
            .selection()
            .pins()
            .host_artifact_digest
            .as_str()
    {
        return Err(invalid());
    }
    Ok(images)
}
pub(crate) fn capture(
    entered: &EnteredCalibration<'_>,
    store: &mut DurableStore,
) -> AppResult<Option<BeforeCapture>> {
    let images = prepare_images(entered, store)?;
    let original = entered.original();
    Ok(Some(BeforeCapture {
        invocation_id: decode(&original["invocationId"])?,
        binding_id: decode(&original["bindingId"])?,
        context_digest: digest_field(original, "contextDigest")?,
        implementation_digest: digest_field(original, "implementationDigest")?,
        arguments_digest: digest_field(original, "argumentsDigest")?,
        images: images.images,
    }))
}
pub(crate) fn check_prepared_capture(
    entered: &EnteredCalibration<'_>,
    store: &mut DurableStore,
) -> AppResult<()> {
    let fresh = prepare_images(entered, store)?;
    let retained = before_images(store, entered.original(), &|| entered.check_local(store))?;
    if fresh.images.len() != retained.len()
        || fresh
            .images
            .iter()
            .any(|image| retained.get(&image.target) != Some(&raw_digest(&image.bytes)))
    {
        return Err(AppError::new(
            "TARGET_DRIFT",
            "Fresh readiness images differ from the original retained before capture",
        ));
    }
    Ok(())
}
fn before_images(
    store: &DurableStore,
    original: &Value,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<BTreeMap<String, Sha256Digest>> {
    let operation = decode(&original["operationId"])?;
    let mut result = BTreeMap::new();
    let summaries = store.operation_summaries(&operation).map_err(storage)?;
    if summaries.len() > 4096 {
        return Err(limit());
    }
    for reference in summaries {
        check()?;
        let bytes = store
            .read_blob_checked(&reference, 64 * 1024, || {
                check().map_err(|cause| {
                    mmmm_runtime::storage::StorageError::Io(std::io::Error::other(cause))
                })
            })
            .map_err(storage)?;
        let value = parse(&bytes, 64 * 1024, 4096, check)?;
        if value["kind"] != "before_capture_summary"
            || value["stepId"] != original["stepId"]
            || value["invocationId"] != original["invocationId"]
        {
            continue;
        }
        let blob: BlobRef = decode(&value["captureBlob"])?;
        let bytes = store
            .read_blob_checked(&blob, 64 * 1024, || {
                check().map_err(|cause| {
                    mmmm_runtime::storage::StorageError::Io(std::io::Error::other(cause))
                })
            })
            .map_err(storage)?;
        let capture = parse(&bytes, 64 * 1024, 4096, check)?;
        if capture["kind"] != "before_capture"
            || capture["operationId"] != original["operationId"]
            || [
                "stepId",
                "invocationId",
                "bindingId",
                "contextDigest",
                "implementationDigest",
                "argumentsDigest",
            ]
            .iter()
            .any(|key| capture[*key] != original[*key])
        {
            return Err(invalid());
        }
        for image in capture["images"].as_array().ok_or_else(invalid)? {
            let before: BlobRef = decode(&image["before"])?;
            if result
                .insert(text(image, "target")?.to_owned(), before.digest)
                .is_some()
            {
                return Err(invalid());
            }
        }
    }
    if result.len() != 2 {
        return Err(invalid());
    }
    Ok(result)
}
pub(crate) fn readback(
    entered: &EnteredCalibration<'_>,
    store: &mut DurableStore,
) -> AppResult<ReadbackEvidence> {
    entered.verify_claim(store, entered.original())?;
    let original = entered.original();
    let program = program_for(original)?;
    let confirmation = entered.approval().confirmation();
    let run=entered.route().inspect_original_with_store(store,entered.request(),original,json!({"kind":"calibration_run_source","invocationId":original["invocationId"],"invocationDigest":canonical_digest(original).map_err(|_|invalid())?,"expectedRuntimeSourceFactsDigest":confirmation.runtime_source_facts_digest,"expectedRegistryGeneration":confirmation.registry_generation}),&|store|entered.verify_claim(store,original))?;
    verify_run_source(
        &run,
        original,
        &program,
        &confirmation.runtime_source_facts_digest,
        &confirmation.registry_generation,
        &entered.approval().selection().pins().host_artifact_digest,
        &|| entered.verify_claim(store, original),
    )?;
    let value=entered.route().inspect_original_with_store(store,entered.request(),original,json!({"kind":"calibration_state","invocationId":original["invocationId"],"invocationDigest":canonical_digest(original).map_err(|_|invalid())?}),&|store|entered.verify_claim(store,original))?;
    let images = decode_images(
        &value,
        &original["context"],
        &program,
        Some((
            &confirmation.runtime_source_facts_digest,
            &confirmation.registry_generation,
        )),
        &|| entered.verify_claim(store, original),
    )?;
    if value["hostArtifactDigest"]
        != entered
            .approval()
            .selection()
            .pins()
            .host_artifact_digest
            .as_str()
    {
        return Err(invalid());
    }
    let observed = state(&images, &program, &|| entered.check_local(store))?;
    let matches = observed == expected_state(&program);
    // This fresh observation contains no historical command return. Source3
    // independently attests that return and actual entry causality above.
    let evidence = json!({"format":"mmmm.target-case-readback/3","caseId":program.case().case_id(),"invocationId":original["invocationId"],"invocationDigest":canonical_digest(original).map_err(|_|invalid())?,"programDigest":program.source_digest(),"runtimeSourceFactsDigest":confirmation.runtime_source_facts_digest,"targetImages":value,"state":observed,"runSource":run});
    if encode_json(&evidence).map_err(|_| invalid())?.len() > 2 * 1024 * 1024 {
        return Err(limit());
    }
    entered.verify_claim(store, original)?;
    Ok(ReadbackEvidence {
        invocation_id: decode(&original["invocationId"])?,
        binding_id: decode(&original["bindingId"])?,
        context_digest: digest_field(original, "contextDigest")?,
        implementation_digest: digest_field(original, "implementationDigest")?,
        arguments_digest: digest_field(original, "argumentsDigest")?,
        effect: if matches {
            EffectEvidence::CompleteConfirmed
        } else {
            EffectEvidence::SomeConfirmed
        },
        settled: true,
        evidence,
        direct_changes: images
            .images
            .into_iter()
            .map(|image| DirectChange {
                target: image.target,
                before: vec![],
                after: image.bytes,
            })
            .collect(),
    })
}
fn expected_state(program: &CalibrationProgram) -> Value {
    let expected = program.expectation();
    json!({"okScore":expected.ok_score,"output":program.expected_readback()["output"],"scratchPresent":expected.scratch_present})
}

/// Source3 is issued only by the actual private Accepted-run producer. Caller
/// CAS pins are absent; this consumer supplies its independently loaded sealed
/// source and original same-Store Invocation for every equality check.
pub(crate) fn verify_run_source(
    value: &Value,
    original: &Value,
    program: &CalibrationProgram,
    facts: &Sha256Digest,
    generation: &str,
    artifact: &Sha256Digest,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<Option<i32>> {
    check()?;
    let bytes = encode_json(value).map_err(|_| invalid())?;
    // Actual transport additionally counts its JSON-RPC/HostResponse wrapper.
    // Retained case resources cannot bypass that original logical node budget.
    parse(
        &bytes,
        crate::rpc::MAX_CONTROL_BYTES,
        crate::rpc::MAX_CONTROL_NODES,
        check,
    )?;
    exact(
        value,
        &[
            "format",
            "protocolVersion",
            "environment",
            "contextId",
            "contextDigest",
            "runtimeSourceFactsDigest",
            "hostArtifactDigest",
            "registryGeneration",
            "invocationId",
            "invocationDigest",
            "programDigest",
            "functionId",
            "sourceResourceId",
            "sourcePackId",
            "sourceRawSha256",
            "commandsDigest",
            "preseedEndIndex",
            "commandStageIndex",
            "commands",
            "executableViews",
            "preseedState",
            "afterState",
            "observedFromTick",
            "observedToTick",
            "observedAt",
        ],
    )?;
    check()?;
    let function = program
        .invocation_command()
        .strip_prefix("function ")
        .ok_or_else(invalid)?;
    let (namespace, path) = function.split_once(':').ok_or_else(invalid)?;
    if value["format"] != "mmmm.native.calibration-run-source/3"
        || value["protocolVersion"] != "0.2.0"
        || value["environment"] != original["context"]["environment"]
        || value["contextId"] != original["context"]["contextId"]
        || value["contextDigest"] != original["contextDigest"]
        || value["runtimeSourceFactsDigest"] != facts.as_str()
        || value["hostArtifactDigest"] != artifact.as_str()
        || value["registryGeneration"] != generation
        || value["invocationId"] != original["invocationId"]
        || value["invocationDigest"] != canonical_digest(original).map_err(|_| invalid())?.as_str()
        || value["programDigest"] != program.source_digest().as_str()
        || value["sourceRawSha256"] != raw_digest(program.source_bytes()).as_str()
        || value["functionId"] != function
        || value["sourceResourceId"] != format!("{namespace}:function/{path}.mcfunction")
        || value["commandsDigest"]
            != canonical_digest(&json!(program.commands()))
                .map_err(|_| invalid())?
                .as_str()
        || value["preseedEndIndex"] != program.preseed_end_index()
        || value["commandStageIndex"] != program.command_stage_index()
    {
        return Err(invalid());
    }
    let pack = text(value, "sourcePackId")?;
    if pack.is_empty() || pack.len() > 256 || pack.chars().any(char::is_control) {
        return Err(invalid());
    }
    if time::OffsetDateTime::parse(
        text(value, "observedAt")?,
        &time::format_description::well_known::Rfc3339,
    )
    .is_err()
    {
        return Err(invalid());
    }
    let from = tick(&value["observedFromTick"])?;
    let to = tick(&value["observedToTick"])?;
    if from > to {
        return Err(invalid());
    }
    let views = value["executableViews"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 64)
        .ok_or_else(invalid)?;
    let mut native = Vec::with_capacity(views.len());
    let mut identities = BTreeSet::new();
    let mut view_bytes = 0usize;
    for view in views {
        exact(view, &["sourceKind", "nativeEnvelopeHex"])?;
        if view["sourceKind"] != "current_vm_executable" {
            return Err(invalid());
        }
        let bytes = hex(
            text(view, "nativeEnvelopeHex")?,
            crate::rpc::MAX_CONTROL_BYTES,
            check,
        )?;
        view_bytes = view_bytes
            .checked_add(bytes.len())
            .filter(|v| *v <= 8 * 1024 * 1024)
            .ok_or_else(limit)?;
        let parsed = Executable::decode(&bytes, check)?;
        if native
            .first()
            .is_some_and(|first: &Executable| first.epoch != parsed.epoch)
            || !identities.insert((parsed.epoch, parsed.identity))
        {
            return Err(invalid());
        }
        native.push(parsed);
    }
    let commands = value["commands"]
        .as_array()
        .filter(|v| v.len() == program.commands().len())
        .ok_or_else(invalid)?;
    let mut sequence = 0u64;
    let mut last_tick = from;
    let mut queue = false;
    let mut preseed = false;
    let mut selected = None;
    for (ordinal, (entry, source)) in commands.iter().zip(program.commands()).enumerate() {
        check()?;
        exact(
            entry,
            &[
                "ordinal",
                "commandDigest",
                "chainInputDigest",
                "consumedUtf16",
                "rangeStartUtf16",
                "rangeEndUtf16",
                "nativeReturn",
                "executables",
                "events",
            ],
        )?;
        let digest = canonical_digest(&json!(source)).map_err(|_| invalid())?;
        if entry["ordinal"] != ordinal
            || entry["commandDigest"] != digest.as_str()
            || entry["chainInputDigest"] != digest.as_str()
            || entry["rangeStartUtf16"] != 0
            || entry["rangeEndUtf16"] != source.encode_utf16().count()
            || entry["consumedUtf16"] != source.encode_utf16().count()
        {
            return Err(invalid());
        }
        let returned = nullable_i32(entry.get("nativeReturn"))?;
        let executables = entry["executables"]
            .as_array()
            .filter(|v| !v.is_empty() && v.len() <= 256)
            .ok_or_else(invalid)?;
        for executable in executables {
            validate_executable(executable, &native, check)?;
        }
        let events = entry["events"]
            .as_array()
            .filter(|v| !v.is_empty() && v.len() <= 4096)
            .ok_or_else(invalid)?;
        let mut begin = false;
        let mut actual_return = None;
        let mut handler_terminal = false;
        for event in events {
            if queue
                || (!begin && !matches!(text(event, "kind")?, "preseed_capture" | "entry_begin"))
            {
                return Err(invalid());
            }
            if event["sequence"].as_u64() != Some(sequence) {
                return Err(invalid());
            }
            sequence = sequence
                .checked_add(1)
                .filter(|v| *v <= 4096)
                .ok_or_else(limit)?;
            let at = tick(&event["tick"])?;
            if at < last_tick || at > to {
                return Err(invalid());
            }
            last_tick = at;
            match text(event, "kind")? {
                "entry_begin" => {
                    exact(event, &["kind", "sequence", "tick"])?;
                    if begin || queue {
                        return Err(invalid());
                    }
                    begin = true;
                }
                "handler_return" => {
                    exact(
                        event,
                        &["kind", "sequence", "tick", "executableRef", "returned"],
                    )?;
                    executable_ref(executables, &event["executableRef"], "handler")?;
                    if handler_terminal {
                        return Err(invalid());
                    }
                    handler_terminal = true;
                    actual_return = Some(i32_value(&event["returned"])?);
                }
                "handler_failure" => {
                    exact(
                        event,
                        &["kind", "sequence", "tick", "executableRef", "failureKind"],
                    )?;
                    executable_ref(executables, &event["executableRef"], "handler")?;
                    if handler_terminal {
                        return Err(invalid());
                    }
                    handler_terminal = true;
                    if !matches!(
                        text(event, "failureKind")?,
                        "command_syntax" | "runtime" | "error"
                    ) {
                        return Err(invalid());
                    }
                }
                "custom_return" => {
                    exact(
                        event,
                        &["kind", "sequence", "tick", "executableRef", "customKind"],
                    )?;
                    let role = match text(event, "customKind")? {
                        "modifier" => "redirect",
                        "command" => "handler",
                        _ => return Err(invalid()),
                    };
                    executable_ref(executables, &event["executableRef"], role)?;
                }
                "frame_return" => {
                    exact(event, &["kind", "sequence", "tick", "returned"])?;
                    nullable_i32(event.get("returned"))?;
                }
                "preseed_capture" => {
                    exact(event, &["kind", "sequence", "tick"])?;
                    if preseed || begin || ordinal != program.preseed_end_index() as usize {
                        return Err(invalid());
                    }
                    preseed = true;
                }
                "queue_return" => {
                    exact(
                        event,
                        &[
                            "kind",
                            "sequence",
                            "tick",
                            "commandQuota",
                            "queueOverflow",
                            "queued",
                            "newTopCommands",
                        ],
                    )?;
                    if queue
                        || ordinal + 1 != commands.len()
                        || event["commandQuota"].as_i64().is_none_or(|v| v <= 0)
                        || event["queueOverflow"] != false
                        || event["queued"] != 0
                        || event["newTopCommands"] != 0
                    {
                        return Err(invalid());
                    }
                    queue = true;
                }
                _ => return Err(invalid()),
            }
        }
        if !begin || returned != actual_return {
            return Err(invalid());
        }
        if ordinal == program.command_stage_index() as usize {
            selected = returned;
        }
    }
    if !queue || !preseed {
        return Err(invalid());
    }
    check_selected_return(program, selected)?;
    for key in ["preseedState", "afterState"] {
        exact(
            &value[key],
            &["targets", "observedFromTick", "observedToTick"],
        )?;
        if tick(&value[key]["observedFromTick"])? < from
            || tick(&value[key]["observedToTick"])? > to
        {
            return Err(invalid());
        }
    }
    let preseed_images = decode_pair(&value["preseedState"], program, check)?;
    verify_preseed(&preseed_images, program, check)?;
    let after = decode_pair(&value["afterState"], program, check)?;
    if state(&after, program, check)? != expected_state(program) {
        return Err(invalid());
    }
    check()?;
    Ok(selected)
}
fn executable_ref(values: &[Value], index: &Value, role: &str) -> AppResult<()> {
    let selected = index
        .as_u64()
        .and_then(|v| usize::try_from(v).ok())
        .and_then(|v| values.get(v))
        .ok_or_else(invalid)?;
    if selected["role"] != role {
        return Err(invalid());
    }
    Ok(())
}
fn check_selected_return(program: &CalibrationProgram, selected: Option<i32>) -> AppResult<()> {
    if ((program.expectation().command_success || program.expectation().command_return.is_some())
        && selected.is_none())
        || program
            .expectation()
            .command_return
            .is_some_and(|expected| Some(expected) != selected)
    {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn validate_executable(
    value: &Value,
    views: &[Executable],
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<()> {
    exact(
        value,
        &[
            "role",
            "receiverViewRef",
            "selectedMethod",
            "implementation",
            "hiddenTarget",
        ],
    )?;
    if !matches!(
        text(value, "role")?,
        "parser" | "predicate" | "handler" | "redirect"
    ) {
        return Err(invalid());
    }
    let receiver = view_ref(views, &value["receiverViewRef"])?;
    let method = &value["selectedMethod"];
    exact(method, &["name", "descriptor"])?;
    method_text(method)?;
    let implementation = &value["implementation"];
    exact(implementation, &["viewRef", "name", "descriptor"])?;
    method_text(implementation)?;
    let implementing = view_ref(views, &implementation["viewRef"])?;
    let key = (
        text(implementation, "name")?.to_owned(),
        text(implementation, "descriptor")?.to_owned(),
    );
    let (modifiers, kind) = implementing
        .methods
        .get(&key)
        .copied()
        .ok_or_else(invalid)?;
    if method["name"] != implementation["name"]
        || method["descriptor"] != implementation["descriptor"]
        || kind != 0
        || modifiers & 1 == 0
        || modifiers & (8 | 0x100 | 0x400) != 0
        || (!receiver.hidden && modifiers & 0x1000 != 0 && modifiers & 0x40 == 0)
        || (receiver.hidden && value["receiverViewRef"] != implementation["viewRef"])
    {
        return Err(invalid());
    }
    // A missing hidden target is factual partial body evidence. It supplies no
    // captured values, virtual equivalence or static-forwarder target proof.
    if !value["hiddenTarget"].is_null() {
        let hidden = &value["hiddenTarget"];
        exact(
            hidden,
            &["viewRef", "name", "descriptor", "forwarderEnvelopeHex"],
        )?;
        method_text(hidden)?;
        let target = view_ref(views, &hidden["viewRef"])?;
        let (flags, kind) = target
            .methods
            .get(&(
                text(hidden, "name")?.to_owned(),
                text(hidden, "descriptor")?.to_owned(),
            ))
            .copied()
            .ok_or_else(invalid)?;
        if !receiver.hidden
            || target.hidden
            || kind != 0
            || flags & 8 == 0
            || flags & (0x100 | 0x400 | 0x40) != 0
        {
            return Err(invalid());
        }
        let raw = hex(
            text(hidden, "forwarderEnvelopeHex")?,
            crate::rpc::MAX_CONTROL_BYTES,
            check,
        )?;
        verify_forwarder(&raw, receiver, target, method, hidden, check)?;
    }
    Ok(())
}
fn method_text(value: &Value) -> AppResult<()> {
    for field in ["name", "descriptor"] {
        let value = text(value, field)?;
        if value.is_empty() || value.len() > 16 * 1024 || value.chars().any(char::is_control) {
            return Err(invalid());
        }
    }
    Ok(())
}
fn view_ref<'a>(views: &'a [Executable], value: &Value) -> AppResult<&'a Executable> {
    views
        .get(
            value
                .as_u64()
                .and_then(|v| usize::try_from(v).ok())
                .ok_or_else(invalid)?,
        )
        .ok_or_else(invalid)
}
fn nullable_i32(value: Option<&Value>) -> AppResult<Option<i32>> {
    let value = value.ok_or_else(invalid)?;
    if value.is_null() {
        Ok(None)
    } else {
        i32_value(value).map(Some)
    }
}
fn i32_value(value: &Value) -> AppResult<i32> {
    value
        .as_i64()
        .and_then(|v| i32::try_from(v).ok())
        .ok_or_else(invalid)
}
fn verify_preseed(
    images: &Images,
    program: &CalibrationProgram,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<()> {
    let objective = parse(&images.images[0].bytes, IMAGE_BYTES, 16384, check)?;
    let storage = parse(&images.images[1].bytes, IMAGE_BYTES, 16384, check)?;
    let score = objective["payload"]["scores"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .find(|score| score["holder"] == "#result")
        .ok_or_else(invalid)?;
    if i32_value(&score["value"])? != program.expectation().preseed_score
        || storage["payload"]["invocation"]["presence"] != "present"
    {
        return Err(invalid());
    }
    let tag = decode_nbt(&storage["payload"]["invocation"]["nativeValueNbt"], check)?;
    if !matches!(tag.at("stale"), Some(Tag::Byte(1))) {
        return Err(invalid());
    }
    let matches = match (tag.at("result"), program.expectation().preseed_storage) {
        (
            Some(Tag::Float(actual)),
            mmmm_compiler::calibration::CalibrationScalar::FloatTag { bits },
        ) => *actual == bits,
        (
            Some(Tag::Int(actual)),
            mmmm_compiler::calibration::CalibrationScalar::IntTag(expected),
        ) => *actual == expected,
        _ => false,
    };
    if !matches {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn state(
    images: &Images,
    program: &CalibrationProgram,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<Value> {
    let objective = parse(&images.images[0].bytes, IMAGE_BYTES, 16384, check)?;
    let storage = parse(&images.images[1].bytes, IMAGE_BYTES, 16384, check)?;
    let score = |holder: &str| -> AppResult<Option<i32>> {
        if objective["presence"] == "absent" {
            return Ok(None);
        }
        let scores = objective["payload"]["scores"]
            .as_array()
            .ok_or_else(invalid)?;
        scores
            .iter()
            .find(|entry| entry["holder"] == holder)
            .map(|entry| {
                entry["value"]
                    .as_i64()
                    .and_then(|n| i32::try_from(n).ok())
                    .ok_or_else(invalid)
            })
            .transpose()
    };
    let invocation = &storage["payload"]["invocation"];
    let scratch = invocation["presence"] == "present";
    let output = match program.scope().result_address() {
        BindingAddress::Score { holder, .. } => score(holder)?
            .map(|v| json!({"kind":"score","value":v}))
            .unwrap_or(json!({"kind":"absent"})),
        BindingAddress::Storage { path, .. } => {
            if !scratch {
                json!({"kind":"absent"})
            } else {
                let tag = decode_nbt(&invocation["nativeValueNbt"], check)?;
                let suffix = path.strip_prefix("invocation.").ok_or_else(invalid)?;
                match tag.at(suffix) {
                    None => json!({"kind":"absent"}),
                    Some(Tag::Int(value)) => json!({"kind":"int_tag","value":value}),
                    Some(Tag::Float(bits)) => {
                        json!({"kind":"float_tag","bits":format!("{bits:08x}")})
                    }
                    _ => return Err(invalid()),
                }
            }
        }
    };
    Ok(
        json!({"okScore":score("#ok")?.ok_or_else(invalid)?,"output":output,"scratchPresent":scratch}),
    )
}

#[derive(Clone, Debug)]
enum Tag {
    End,
    Byte(i8),
    Short,
    Int(i32),
    Long,
    Float(u32),
    Double(u64),
    Array,
    List(Vec<Tag>),
    String,
    Compound(BTreeMap<Vec<u16>, Tag>),
}
impl Tag {
    fn at(&self, path: &str) -> Option<&Tag> {
        let mut current = self;
        for key in path.split('.') {
            current = match current {
                Self::Compound(map) => map.get(&key.encode_utf16().collect::<Vec<_>>())?,
                _ => return None,
            }
        }
        Some(current)
    }
}
fn validate_image_nbt(image: &Value, check: &dyn Fn() -> AppResult<()>) -> AppResult<()> {
    let payload = &image["payload"];
    if image["selector"]["kind"] == "objective" && image["presence"] == "present" {
        decode_nbt(&payload["nativeObjectiveNbt"], check)?;
        for score in payload["scores"].as_array().ok_or_else(invalid)? {
            decode_nbt(&score["nativeScoreNbt"], check)?;
        }
    } else if image["selector"]["kind"] == "owned_storage" {
        for key in ["inputs", "invocation"] {
            if payload[key]["presence"] == "present" {
                decode_nbt(&payload[key]["nativeValueNbt"], check)?;
            }
        }
    }
    Ok(())
}
fn decode_nbt(value: &Value, check: &dyn Fn() -> AppResult<()>) -> AppResult<Tag> {
    exact(value, &["format", "bytesHex", "sha256", "rawFloatingBits"])?;
    let bytes = hex(text(value, "bytesHex")?, NATIVE_BYTES, check)?;
    if raw_digest(&bytes) != digest_field(value, "sha256")? {
        return Err(invalid());
    }
    let mut reader = Nbt {
        bytes: &bytes,
        offset: 0,
        nodes: 0,
        check,
    };
    let kind = reader.byte()?;
    match text(value, "format")? {
        "minecraft.nbt.named-compound/uncompressed" => {
            if kind != 10 {
                return Err(invalid());
            }
            reader.string()?;
        }
        "minecraft.nbt.any-tag/uncompressed" => {}
        _ => return Err(invalid()),
    }
    let mut tag = if kind == 0 {
        Tag::End
    } else {
        reader.tag(kind, 0)?
    };
    actual_tag_budget(&tag)?;
    if reader.offset != bytes.len() {
        return Err(invalid());
    }
    let entries = value["rawFloatingBits"].as_array().ok_or_else(invalid)?;
    if encode_json(&value["rawFloatingBits"])
        .map_err(|_| invalid())?
        .len()
        > NATIVE_BYTES
    {
        return Err(limit());
    }
    let mut seen = BTreeSet::new();
    for entry in entries {
        exact(entry, &["path", "kind", "bits"])?;
        let path = entry["path"]
            .as_array()
            .filter(|v| v.len() <= 64)
            .ok_or_else(invalid)?;
        let encoded = encode_json(&entry["path"]).map_err(|_| invalid())?;
        if !seen.insert(encoded) {
            return Err(invalid());
        }
        let mut current = &mut tag;
        for part in path {
            if let Some(key) = part.get("key").and_then(Value::as_str) {
                exact(part, &["key"])?;
                current = match current {
                    Tag::Compound(map) => map
                        .get_mut(&key.encode_utf16().collect::<Vec<_>>())
                        .ok_or_else(invalid)?,
                    _ => return Err(invalid()),
                };
            } else {
                exact(part, &["index"])?;
                let index = part["index"]
                    .as_u64()
                    .and_then(|v| usize::try_from(v).ok())
                    .ok_or_else(invalid)?;
                current = match current {
                    Tag::List(list) => list.get_mut(index).ok_or_else(invalid)?,
                    _ => return Err(invalid()),
                };
            }
        }
        let raw = text(entry, "bits")?;
        match current {
            Tag::Float(bits) if entry["kind"] == "float_tag" && raw.len() == 8 => {
                let actual =
                    u32::from_be_bytes(hex(raw, 4, check)?.try_into().map_err(|_| invalid())?);
                let encoded = if f32::from_bits(actual).is_nan() {
                    0x7fc00000
                } else {
                    actual
                };
                if *bits != encoded {
                    return Err(invalid());
                }
                *bits = actual;
            }
            Tag::Double(bits) if entry["kind"] == "double_tag" && raw.len() == 16 => {
                let actual =
                    u64::from_be_bytes(hex(raw, 8, check)?.try_into().map_err(|_| invalid())?);
                let encoded = if f64::from_bits(actual).is_nan() {
                    0x7ff8000000000000
                } else {
                    actual
                };
                if *bits != encoded {
                    return Err(invalid());
                }
                *bits = actual;
            }
            _ => return Err(invalid()),
        }
    }
    fn floats(tag: &Tag) -> usize {
        match tag {
            Tag::Float(_) | Tag::Double(_) => 1,
            Tag::List(values) => values.iter().map(floats).sum(),
            Tag::Compound(values) => values.values().map(floats).sum(),
            _ => 0,
        }
    }
    if floats(&tag) != entries.len() {
        return Err(invalid());
    }
    check()?;
    Ok(tag)
}
struct Nbt<'a> {
    bytes: &'a [u8],
    offset: usize,
    nodes: usize,
    check: &'a dyn Fn() -> AppResult<()>,
}
// Native ListTag.write may add exactly one empty-key Compound wrapper to each
// child. Decode its bounded physical encoding, then apply the original actual
// Tag-tree limits after native TYPE.load's one-layer per-list-element unwrap.
fn actual_tag_budget(tag: &Tag) -> AppResult<()> {
    let mut pending = vec![(tag, 0usize)];
    let mut nodes = 0usize;
    while let Some((tag, depth)) = pending.pop() {
        nodes += 1;
        if nodes > 16384 || depth > 64 {
            return Err(limit());
        }
        match tag {
            Tag::List(values) => pending.extend(values.iter().map(|value| (value, depth + 1))),
            Tag::Compound(values) => {
                pending.extend(values.values().map(|value| (value, depth + 1)))
            }
            _ => {}
        }
    }
    Ok(())
}
impl Nbt<'_> {
    fn take(&mut self, n: usize) -> AppResult<&[u8]> {
        let end = self
            .offset
            .checked_add(n)
            .filter(|v| *v <= self.bytes.len())
            .ok_or_else(invalid)?;
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> AppResult<u8> {
        Ok(self.take(1)?[0])
    }
    fn length(&mut self) -> AppResult<usize> {
        let n = i32::from_be_bytes(self.take(4)?.try_into().map_err(|_| invalid())?);
        usize::try_from(n)
            .ok()
            .filter(|n| *n <= 4096)
            .ok_or_else(limit)
    }
    fn units(&mut self) -> AppResult<Vec<u16>> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| invalid())?) as usize;
        let bytes = self.take(n)?; // NBT uses Java modified UTF-8, including surrogate pairs.
        let mut units = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let a = bytes[i];
            if a > 0 && a < 128 {
                units.push(a as u16);
                i += 1;
            } else if a & 0xe0 == 0xc0 && i + 1 < bytes.len() {
                let b = bytes[i + 1];
                if b & 0xc0 != 0x80 {
                    return Err(invalid());
                }
                let unit = (((a & 31) as u16) << 6) | ((b & 63) as u16);
                if unit < 128 && unit != 0 {
                    return Err(invalid());
                }
                units.push(unit);
                i += 2;
            } else if a & 0xf0 == 0xe0 && i + 2 < bytes.len() {
                let b = bytes[i + 1];
                let c = bytes[i + 2];
                if b & 0xc0 != 0x80 || c & 0xc0 != 0x80 {
                    return Err(invalid());
                }
                let unit = (((a & 15) as u16) << 12) | (((b & 63) as u16) << 6) | ((c & 63) as u16);
                if unit < 2048 {
                    return Err(invalid());
                }
                units.push(unit);
                i += 3;
            } else {
                return Err(invalid());
            }
        }
        Ok(units)
    }
    fn string(&mut self) -> AppResult<String> {
        String::from_utf16(&self.units()?).map_err(|_| invalid())
    }
    fn tag(&mut self, kind: u8, depth: usize) -> AppResult<Tag> {
        self.nodes += 1;
        if self.nodes > 32768 || depth > 128 {
            return Err(limit());
        }
        (self.check)()?;
        Ok(match kind {
            1 => Tag::Byte(self.byte()? as i8),
            2 => {
                self.take(2)?;
                Tag::Short
            }
            3 => Tag::Int(i32::from_be_bytes(
                self.take(4)?.try_into().map_err(|_| invalid())?,
            )),
            4 => {
                self.take(8)?;
                Tag::Long
            }
            5 => Tag::Float(u32::from_be_bytes(
                self.take(4)?.try_into().map_err(|_| invalid())?,
            )),
            6 => Tag::Double(u64::from_be_bytes(
                self.take(8)?.try_into().map_err(|_| invalid())?,
            )),
            7 | 11 | 12 => {
                let n = self.length()?;
                self.take(
                    n * if kind == 7 {
                        1
                    } else if kind == 11 {
                        4
                    } else {
                        8
                    },
                )?;
                Tag::Array
            }
            8 => {
                self.units()?;
                Tag::String
            }
            9 => {
                let child = self.byte()?;
                let n = self.length()?;
                if child > 12 || (child == 0 && n != 0) {
                    return Err(invalid());
                }
                let mut values = Vec::with_capacity(n);
                for _ in 0..n {
                    let mut entry = self.tag(child, depth + 1)?;
                    if let Tag::Compound(map) = &mut entry
                        && map.len() == 1
                        && map.contains_key(&Vec::<u16>::new())
                    {
                        entry = map.remove(&Vec::<u16>::new()).ok_or_else(invalid)?;
                    }
                    values.push(entry)
                }
                Tag::List(values)
            }
            10 => {
                let mut values = BTreeMap::new();
                loop {
                    let child = self.byte()?;
                    if child == 0 {
                        break;
                    }
                    if values.len() >= 4096 {
                        return Err(limit());
                    }
                    let name = self.units()?;
                    let child = self.tag(child, depth + 1)?;
                    if values.insert(name, child).is_some() {
                        return Err(invalid());
                    }
                }
                Tag::Compound(values)
            }
            _ => return Err(invalid()),
        })
    }
}
struct Executable {
    hidden: bool,
    identity: u64,
    generation: u64,
    epoch: u64,
    name: String,
    methods: BTreeMap<(String, String), (u32, u8)>,
}
impl Executable {
    fn decode(bytes: &[u8], check: &dyn Fn() -> AppResult<()>) -> AppResult<Self> {
        let mut bin = Binary {
            bytes,
            at: 0,
            check,
        };
        if bin.take(8)? != b"MMMMDEF1" {
            return Err(invalid());
        }
        let kind = bin.byte()?;
        let flags = bin.byte()?;
        if !matches!(kind, 1 | 2) || !matches!(flags, 1 | 3) || bin.take(2)? != [0, 0] {
            return Err(invalid());
        }
        let identity = bin.u64()?;
        let generation = bin.u64()?;
        let attempt = bin.u64()?;
        let epoch = bin.u64()?;
        if [identity, generation, attempt, epoch].contains(&0) {
            return Err(invalid());
        }
        let name = bin.text()?;
        let ordinary = bin.blob()?.len();
        let hidden = bin.blob()?.len();
        let hidden_flags = bin.u32()?;
        let initialize = bin.byte()?;
        if initialize > 1 || bin.take(3)? != [0, 0, 0] {
            return Err(invalid());
        }
        let lookup = bin.u64()?;
        bin.u64()?;
        let requested = bin.text_optional()?;
        let pool = bin.u32()?;
        if !(1..=65535).contains(&pool) || bin.blob()?.is_empty() {
            return Err(invalid());
        }
        let count = bin.u32()?;
        if count == 0 || count > 4096 {
            return Err(invalid());
        }
        let mut methods = BTreeMap::new();
        for _ in 0..count {
            check()?;
            let name = bin.text()?;
            let descriptor = bin.text()?;
            let modifiers = bin.u32()?;
            let code_kind = bin.byte()?;
            let code = bin.blob()?;
            let native = modifiers & 0x100 != 0;
            let abstract_method = modifiers & 0x400 != 0;
            if code_kind > 2
                || (native && abstract_method)
                || (code_kind == 0 && (code.is_empty() || native || abstract_method))
                || (code_kind != 0 && !code.is_empty())
                || (code_kind == 1 && !native)
                || (code_kind == 2 && !abstract_method)
                || methods
                    .insert((name, descriptor), (modifiers, code_kind))
                    .is_some()
            {
                return Err(invalid());
            }
        }
        if bin.at != bytes.len()
            || if kind == 1 {
                ordinary == 0
                    || hidden != 0
                    || hidden_flags != 0
                    || initialize != 0
                    || lookup != 0
                    || !requested.is_empty()
            } else {
                ordinary != 0 || hidden == 0 || lookup == 0 || flags != 3 || requested.is_empty()
            }
        {
            return Err(invalid());
        }
        Ok(Self {
            hidden: kind == 2,
            identity,
            generation,
            epoch,
            name,
            methods,
        })
    }
}
struct Binary<'a> {
    bytes: &'a [u8],
    at: usize,
    check: &'a dyn Fn() -> AppResult<()>,
}
impl Binary<'_> {
    fn take(&mut self, n: usize) -> AppResult<&[u8]> {
        (self.check)()?;
        let end = self
            .at
            .checked_add(n)
            .filter(|v| *v <= self.bytes.len())
            .ok_or_else(invalid)?;
        let bytes = &self.bytes[self.at..end];
        self.at = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> AppResult<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> AppResult<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| invalid())?,
        ))
    }
    fn u64(&mut self) -> AppResult<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| invalid())?,
        ))
    }
    fn blob(&mut self) -> AppResult<&[u8]> {
        let size = self.u32()? as usize;
        if size > crate::rpc::MAX_CONTROL_BYTES {
            return Err(limit());
        }
        self.take(size)
    }
    fn text_optional(&mut self) -> AppResult<String> {
        let value = self.blob()?;
        if value.len() > 16 * 1024 {
            return Err(limit());
        }
        let mut encoded = Vec::with_capacity(value.len() + 2);
        encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
        encoded.extend_from_slice(value);
        Nbt {
            bytes: &encoded,
            offset: 0,
            nodes: 0,
            check: self.check,
        }
        .string()
    }
    fn text(&mut self) -> AppResult<String> {
        let text = self.text_optional()?;
        if text.is_empty() {
            Err(invalid())
        } else {
            Ok(text)
        }
    }
    fn utf8(&mut self) -> AppResult<String> {
        let value = self.blob()?;
        if value.is_empty() || value.len() > 4096 {
            return Err(invalid());
        }
        let text = std::str::from_utf8(value).map_err(|_| invalid())?;
        if text.contains('\0') {
            return Err(invalid());
        }
        Ok(text.to_owned())
    }
}
fn verify_forwarder(
    bytes: &[u8],
    receiver: &Executable,
    target: &Executable,
    selected: &Value,
    hidden: &Value,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<()> {
    let mut bin = Binary {
        bytes,
        at: 0,
        check,
    };
    if bin.take(8)? != b"MMMMSAM1"
        || bin.take(4)? != [0, 1, 0, 0]
        || bin.u64()? != receiver.epoch
        || bin.u64()? != receiver.identity
        || bin.u64()? != receiver.generation
        || bin.u64()? != target.identity
        || bin.u64()? != target.generation
        || receiver.epoch != target.epoch
    {
        return Err(invalid());
    }
    let status = bin.u32()?;
    if status & 2 == 0 || status & !0x3f != 0 {
        return Err(invalid());
    }
    let mut symbols = Vec::with_capacity(7);
    for _ in 0..7 {
        symbols.push(bin.utf8()?)
    }
    let interface = bin.byte()?;
    if interface > 1 || bin.take(3)? != [0, 0, 0] {
        return Err(invalid());
    }
    let count = bin.u32()?;
    if count == 0 || count > 256 {
        return Err(invalid());
    }
    let mut refs = BTreeSet::new();
    for _ in 0..count {
        if !refs.insert(bin.utf8()?) {
            return Err(invalid());
        }
    }
    if bin.at != bytes.len()
        || !receiver
            .name
            .starts_with(&(symbols[0].replace('/', ".") + "/"))
        || !refs.contains(&symbols[1])
        || !refs.contains(&symbols[4])
        || symbols[2] != text(selected, "name")?
        || symbols[3] != text(selected, "descriptor")?
        || symbols[4].replace('/', ".") != target.name
        || symbols[5] != text(hidden, "name")?
        || symbols[6] != text(hidden, "descriptor")?
    {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn parse(
    bytes: &[u8],
    maximum: usize,
    nodes: usize,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<Value> {
    parse_json_with_control(
        bytes,
        JsonLimits {
            max_bytes: maximum,
            max_depth: 64,
            max_nodes: nodes,
        },
        check,
    )
    .map_err(|e| match e {
        ControlledJsonError::Control(e) => e,
        ControlledJsonError::Json(e) => AppError::caused_by(
            "CALIBRATION_EVIDENCE_INVALID",
            "Calibration factual bytes violate their finite codec",
            e,
        ),
    })
}
pub(crate) fn hex(
    value: &str,
    maximum: usize,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) || value.len() / 2 > maximum {
        return Err(limit());
    }
    let mut result = Vec::with_capacity(value.len() / 2);
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        if i % 4096 == 0 {
            check()?
        }
        let digit = |b: u8| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(invalid()),
        };
        result.push(digit(pair[0])? * 16 + digit(pair[1])?)
    }
    check()?;
    Ok(result)
}
pub(crate) fn exact(value: &Value, fields: &[&str]) -> AppResult<()> {
    if value.as_object().is_none_or(|map| {
        map.len() != fields.len() || fields.iter().any(|key| !map.contains_key(*key))
    }) {
        Err(invalid())
    } else {
        Ok(())
    }
}
pub(crate) fn text<'a>(value: &'a Value, key: &str) -> AppResult<&'a str> {
    value[key].as_str().ok_or_else(invalid)
}
pub(crate) fn digest_field(value: &Value, key: &str) -> AppResult<Sha256Digest> {
    Sha256Digest::new(text(value, key)?).map_err(|_| invalid())
}
pub(crate) fn tick(value: &Value) -> AppResult<u64> {
    let value = value.as_str().ok_or_else(invalid)?;
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|v| v.is_ascii_digit())
    {
        return Err(invalid());
    }
    value.parse().map_err(|_| invalid())
}
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> AppResult<T> {
    serde_json::from_value(value.clone()).map_err(|_| invalid())
}
fn storage(e: mmmm_runtime::storage::StorageError) -> AppError {
    AppError::storage("CALIBRATION_EVIDENCE_UNAVAILABLE", e)
}
struct NativeQueryFailure(Value);
impl std::fmt::Debug for NativeQueryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Retained actual calibration query failure")
    }
}
impl std::fmt::Display for NativeQueryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = &self.0;
        f.write_str("Original authenticated host rejection is retained privately")
    }
}
impl std::error::Error for NativeQueryFailure {}
pub(crate) fn invalid() -> AppError {
    AppError::new(
        "CALIBRATION_EVIDENCE_INVALID",
        "Actual calibration evidence differs from its original source, context or closed codec",
    )
}
fn limit() -> AppError {
    AppError::new(
        "BUDGET_EXCEEDED",
        "Calibration factual observation exceeds its finite budget",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    // Existing sealed program/context inputs cannot represent the newly
    // factual raw-bit sidecar. These tiny native byte codecs exercise loss and
    // unknown-state rejection only; they are no native issuer or game proof.
    fn nbt(bytes: &[u8], sidecar: Value) -> Value {
        json!({"format":"minecraft.nbt.any-tag/uncompressed","bytesHex":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>(),"sha256":raw_digest(bytes),"rawFloatingBits":sidecar})
    }
    #[test]
    fn native_float_sidecar_preserves_negative_zero_and_actual_nan_payload() {
        for (serialized, actual) in [(0x80000000u32, 0x80000000u32), (0x7fc00000, 0x7fc12345)] {
            let mut raw = vec![5];
            raw.extend_from_slice(&serialized.to_be_bytes());
            let value = nbt(
                &raw,
                json!([{"path":[],"kind":"float_tag","bits":format!("{actual:08x}")}]),
            );
            assert!(
                matches!(decode_nbt(&value,&||Ok(())).unwrap(),Tag::Float(bits) if bits==actual)
            );
            let mut missing = value.clone();
            missing["rawFloatingBits"] = json!([]);
            assert!(decode_nbt(&missing, &|| Ok(())).is_err());
            let mut duplicate = value.clone();
            duplicate["rawFloatingBits"]
                .as_array_mut()
                .unwrap()
                .push(value["rawFloatingBits"][0].clone());
            assert!(decode_nbt(&duplicate, &|| Ok(())).is_err());
            let mut wrong = value.clone();
            wrong["rawFloatingBits"][0]["path"] = json!([{"key":"caller_path"}]);
            assert!(decode_nbt(&wrong, &|| Ok(())).is_err());
        }
        let value = nbt(
            &[5, 0, 0, 0, 0],
            json!([{"path":[],"kind":"float_tag","bits":"80000000"}]),
        );
        assert!(decode_nbt(&value, &|| Ok(())).is_err());
        let noncanonical = nbt(
            &[5, 0x7f, 0xc0, 0x12, 0x34],
            json!([{"path":[],"kind":"float_tag","bits":"7fc01234"}]),
        );
        assert!(decode_nbt(&noncanonical, &|| Ok(())).is_err());
        assert!(matches!(
            decode_nbt(&nbt(&[0], json!([])), &|| Ok(())).unwrap(),
            Tag::End
        ));
        assert!(matches!(
            decode_nbt(&nbt(&[8, 0, 3, 0xed, 0xa0, 0x80], json!([])), &|| Ok(())).unwrap(),
            Tag::String
        ));
        assert!(decode_nbt(&nbt(&[9, 255, 0, 0, 0, 0], json!([])), &|| Ok(())).is_err());
        assert!(decode_nbt(&nbt(&[9, 0, 0, 0, 0, 1], json!([])), &|| Ok(())).is_err());
        let mut unknown = nbt(
            &[5, 0x80, 0, 0, 0],
            json!([{"path":[],"kind":"float_tag","bits":"80000000"}]),
        );
        unknown["rawFloatingBits"][0]["verified"] = json!(true);
        assert!(decode_nbt(&unknown, &|| Ok(())).is_err());
    }
    #[test]
    fn executable_join_requires_original_method_body_and_actual_event_role() {
        // Pure decoder inputs only. These values have no JNI issuer, source
        // registration, ADMIN, NativeCalibrationRunFacts or public grant path.
        let make = |hidden, identity| Executable {
            hidden,
            identity,
            generation: 1,
            epoch: 7,
            name: format!("fixture-{identity}"),
            methods: [(("run".into(), "()I".into()), (1, 0))].into(),
        };
        let mut views = vec![make(true, 1), make(false, 2)];
        let original = json!({"role":"handler","receiverViewRef":0,"selectedMethod":{"name":"run","descriptor":"()I"},"implementation":{"viewRef":0,"name":"run","descriptor":"()I"},"hiddenTarget":null});
        validate_executable(&original, &views, &|| Ok(())).unwrap();
        let mut changed = original.clone();
        changed["implementation"]["viewRef"] = json!(1);
        assert!(validate_executable(&changed, &views, &|| Ok(())).is_err());
        let mut changed = original.clone();
        changed["selectedMethod"]["descriptor"] = json!("()J");
        assert!(validate_executable(&changed, &views, &|| Ok(())).is_err());
        views[0]
            .methods
            .insert(("run".into(), "()I".into()), (0x401, 2));
        assert!(validate_executable(&original, &views, &|| Ok(())).is_err());
        assert!(executable_ref(std::slice::from_ref(&original), &json!(0), "handler").is_ok());
        assert!(executable_ref(std::slice::from_ref(&original), &json!(0), "redirect").is_err());
        assert!(executable_ref(&[original], &json!(1), "handler").is_err());
        let program = CalibrationProgram::for_case(CalibrationCase::Int32ScoreZero).unwrap();
        assert!(check_selected_return(&program, None).is_err());
        assert!(check_selected_return(&program, Some(0)).is_ok());
    }
    #[test]
    fn native_list_codec_unwraps_only_one_serialized_empty_key_layer() {
        // Actual managed API 452 observed ListTag.write/wrapIfNeeded and its
        // TYPE.load/addAndUnwrap. These are finite binary codec inputs only.
        let mut mixed = vec![9, 10, 0, 0, 0, 2, 3, 0, 0];
        mixed.extend_from_slice(&7i32.to_be_bytes());
        mixed.push(0);
        mixed.extend_from_slice(&[5, 0, 0]);
        mixed.extend_from_slice(&0x80000000u32.to_be_bytes());
        mixed.push(0);
        let value = nbt(
            &mixed,
            json!([{"path":[{"index":1}],"kind":"float_tag","bits":"80000000"}]),
        );
        let Tag::List(values) = decode_nbt(&value, &|| Ok(())).unwrap() else {
            panic!("native list must remain a list")
        };
        assert!(matches!(values[0], Tag::Int(7)));
        assert!(matches!(values[1], Tag::Float(0x80000000)));
        let mut escaped = vec![9, 10, 0, 0, 0, 1, 10, 0, 0, 5, 0, 0];
        escaped.extend_from_slice(&0x80000000u32.to_be_bytes());
        escaped.extend_from_slice(&[0, 0]);
        let value = nbt(
            &escaped,
            json!([{"path":[{"index":0},{"key":""}],"kind":"float_tag","bits":"80000000"}]),
        );
        let Tag::List(values) = decode_nbt(&value, &|| Ok(())).unwrap() else {
            panic!("native list must remain a list")
        };
        assert!(matches!(values[0].at(""), Some(Tag::Float(0x80000000))));
        // A root Compound is never passed through ListTag.addAndUnwrap.
        let root = &escaped[6..];
        let mut named = vec![10, 0, 0];
        named.extend_from_slice(root);
        let value = json!({"format":"minecraft.nbt.named-compound/uncompressed","bytesHex":named.iter().map(|b|format!("{b:02x}")).collect::<String>(),"sha256":raw_digest(&named),"rawFloatingBits":[{"path":[{"key":""},{"key":""}],"kind":"float_tag","bits":"80000000"}]});
        let tag = decode_nbt(&value, &|| Ok(())).unwrap();
        assert!(matches!(tag.at("."), Some(Tag::Float(0x80000000))));
        for depth in [64, 65] {
            let mut actual = vec![3, 0, 0, 0, 7];
            for _ in 0..depth {
                // Heterogeneous actual [child,Byte] forces one native wrapper
                // per element while retaining the original actual depth cap.
                let mut encoded = vec![9, 10, 0, 0, 0, 2, actual[0], 0, 0];
                encoded.extend_from_slice(&actual[1..]);
                encoded.push(0);
                encoded.extend_from_slice(&[1, 0, 0, 0, 0]);
                actual = encoded;
            }
            assert_eq!(
                decode_nbt(&nbt(&actual, json!([])), &|| Ok(())).is_ok(),
                depth == 64
            );
        }
    }
    fn pair(program: &CalibrationProgram) -> Value {
        let bindings = target_bindings(program);
        let raws = [
            json!({"format":"mmmm.native.calibration-target/1","selector":bindings[0],"status":"known","presence":"absent","membershipScope":"current_native_scoreboard","captureScope":"native_objective_and_all_scores","coverage":"full_target","reason":null,"payload":{}}),
            json!({"format":"mmmm.native.calibration-target/1","selector":bindings[1],"status":"known","presence":"absent","membershipScope":"current_cached_command_storage","captureScope":"native_owned_storage_subtrees","coverage":"full_target","reason":null,"payload":{"storagePresent":true,"inputs":{"presence":"absent","nativeValueNbt":null},"invocation":{"presence":"absent","nativeValueNbt":null}}}),
        ];
        json!({"targets":raws.iter().zip(bindings.as_array().unwrap()).map(|(raw,binding)| {let bytes=mmmm_contracts::canonical_bytes(raw).unwrap();json!({"targetId":binding["targetId"],"rawBytesHex":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>(),"rawSha256":raw_digest(&bytes)})}).collect::<Vec<_>>(),"observedFromTick":"1","observedToTick":"1"})
    }
    fn replace_raw(pair: &mut Value, index: usize, mutate: impl FnOnce(&mut Value)) {
        let bytes = hex(
            pair["targets"][index]["rawBytesHex"].as_str().unwrap(),
            IMAGE_BYTES,
            &|| Ok(()),
        )
        .unwrap();
        let mut raw = mmmm_contracts::parse_json(&bytes).unwrap();
        mutate(&mut raw);
        let bytes = mmmm_contracts::canonical_bytes(&raw).unwrap();
        pair["targets"][index]["rawBytesHex"] =
            json!(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
        pair["targets"][index]["rawSha256"] = json!(raw_digest(&bytes));
    }
    #[test]
    fn full_target_images_keep_known_absence_separate_from_unknown_and_scalar_coverage() {
        let program = CalibrationProgram::for_case(CalibrationCase::Int32ScoreZero).unwrap();
        let original = pair(&program);
        let decoded = decode_pair(&original, &program, &|| Ok(())).unwrap();
        assert_eq!(decoded.images.len(), 2);
        let mut missing = original.clone();
        replace_raw(&mut missing, 1, |raw| {
            raw["payload"]["storagePresent"] = json!(false)
        });
        let missing_decoded = decode_pair(&missing, &program, &|| Ok(())).unwrap();
        let missing_raw = mmmm_contracts::parse_json(&missing_decoded.images[1].bytes).unwrap();
        assert_eq!(missing_raw["payload"]["storagePresent"], json!(false));
        assert_eq!(
            missing_decoded.images[1].bytes,
            hex(
                missing["targets"][1]["rawBytesHex"].as_str().unwrap(),
                IMAGE_BYTES,
                &|| Ok(())
            )
            .unwrap()
        );
        assert_ne!(missing_decoded.images[1].bytes, decoded.images[1].bytes);
        let missing_digest = raw_digest(&missing_decoded.images[1].bytes);
        assert_eq!(
            missing_digest.as_str(),
            missing["targets"][1]["rawSha256"].as_str().unwrap()
        );
        assert_ne!(missing_digest, raw_digest(&decoded.images[1].bytes));
        for key in ["inputs", "invocation"] {
            let mut present = original.clone();
            replace_raw(&mut present, 1, |raw| {
                raw["presence"] = json!("present");
                raw["payload"][key] = json!({
                    "presence":"present",
                    "nativeValueNbt":nbt(&[3, 0, 0, 0, 1], json!([]))
                });
            });
            assert!(decode_pair(&present, &program, &|| Ok(())).is_ok());
            replace_raw(&mut present, 1, |raw| {
                raw["payload"]["storagePresent"] = json!(false)
            });
            assert!(decode_pair(&present, &program, &|| Ok(())).is_err());
            let mut changed = missing.clone();
            replace_raw(&mut changed, 1, |raw| {
                raw["payload"][key]["nativeValueNbt"] = nbt(&[3, 0, 0, 0, 1], json!([]))
            });
            assert!(decode_pair(&changed, &program, &|| Ok(())).is_err());
        }
        for value in [Value::Null, json!("false"), json!(0)] {
            let mut changed = missing.clone();
            replace_raw(&mut changed, 1, |raw| {
                raw["payload"]["storagePresent"] = value
            });
            assert!(decode_pair(&changed, &program, &|| Ok(())).is_err());
        }
        for (field, value) in [
            ("membershipScope", json!("unknown")),
            ("captureScope", json!("native_storage_key")),
            ("coverage", json!("best_effort")),
            ("reason", json!("native_storage_namespace_not_observed")),
        ] {
            let mut changed = missing.clone();
            replace_raw(&mut changed, 1, |raw| raw[field] = value);
            assert!(decode_pair(&changed, &program, &|| Ok(())).is_err());
        }
        let mut changed = missing.clone();
        replace_raw(&mut changed, 1, |raw| raw["presence"] = json!("present"));
        assert!(decode_pair(&changed, &program, &|| Ok(())).is_err());
        let mut changed = missing.clone();
        replace_raw(&mut changed, 1, |raw| {
            raw["status"] = json!("unknown");
            raw["presence"] = json!("unknown");
            raw["membershipScope"] = json!("unknown");
            raw["coverage"] = json!("best_effort");
            raw["reason"] = json!("native_storage_namespace_not_observed");
            raw["payload"] = Value::Null;
        });
        assert_eq!(
            decode_pair(&changed, &program, &|| Ok(()))
                .err()
                .unwrap()
                .code,
            "CALIBRATION_CAPTURE_UNAVAILABLE"
        );
        let mut changed = original.clone();
        replace_raw(&mut changed, 0, |raw| {
            raw["coverage"] = json!("tracked_changes_only")
        });
        assert!(decode_pair(&changed, &program, &|| Ok(())).is_err());
        let mut changed = original.clone();
        changed["targets"][0]["rawSha256"] = json!("0".repeat(64));
        assert!(decode_pair(&changed, &program, &|| Ok(())).is_err());
        let mut changed = original.clone();
        changed["targets"].as_array_mut().unwrap().swap(0, 1);
        assert!(decode_pair(&changed, &program, &|| Ok(())).is_err());
        assert_eq!(
            decode_pair(&missing, &program, &|| Err(AppError::new(
                "CANCELLED",
                "Original request ended"
            )))
            .err()
            .unwrap()
            .code,
            "CANCELLED"
        );
        let mut context =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/execution-context.json"))
                .unwrap();
        let mut full = missing.clone();
        let object = full.as_object_mut().unwrap();
        object.insert(
            "format".into(),
            json!("mmmm.native.calibration-target-images/1"),
        );
        object.insert("protocolVersion".into(), json!("0.2.0"));
        for key in ["environment", "contextId", "contextDigest"] {
            object.insert(key.into(), context[key].clone());
        }
        for key in ["runtimeSourceFactsDigest", "hostArtifactDigest"] {
            object.insert(key.into(), json!("1".repeat(64)));
        }
        object.insert("registryGeneration".into(), json!("1"));
        object.insert("observedAt".into(), json!("2026-10-16T00:00:00Z"));
        assert_eq!(
            decode_images(&full, &context, &program, None, &|| Ok(()))
                .err()
                .unwrap()
                .code,
            "PERMISSION_REQUIRED"
        );
        context["scope"]["externalTargetIds"] = json!(
            target_bindings(&program)
                .as_array()
                .unwrap()
                .iter()
                .map(|binding| binding["targetId"].clone())
                .collect::<Vec<_>>()
        );
        assert!(decode_images(&full, &context, &program, None, &|| Ok(())).is_ok());
        assert!(
            decode_images(
                &full,
                &context,
                &program,
                Some((&raw_digest(b"another source"), "1")),
                &|| Ok(())
            )
            .is_err()
        );
    }
}

//! Private PACK observations borrow the actual new run and its existing journal.
//! Decoding bytes creates neither a run registration nor native source authority.

use crate::{
    calibration_observer as codec, calibration_pack_run::EnteredPackRun,
    observer::finish_native_observation,
};
use mmmm_application::{
    AppError, AppResult, BeforeCapture, BeforeImage, DirectChange, ReadbackEvidence,
};
use mmmm_compiler::calibration::CalibrationPackProgram;
use mmmm_contracts::{Sha256Digest, StepId, canonical_digest, encode_json, raw_digest};
use mmmm_runtime::storage::{
    BlobRef, DispatchEvidence, DurableStore, EffectEvidence, StorageError, VerificationRequirement,
};
use serde_json::{Value, json};

pub(crate) const TARGET: &str = "calibration-objective-mcalpack";
pub(crate) const CASE: &str = "data_pack_pair_function_dependency_closure";
const IMAGE_BYTES: usize = 256 * 1024;
const EVIDENCE_BYTES: usize = 2 * 1024 * 1024;

/// Pins borrowed from the actual retained private run, never from its reply.
pub(crate) struct SourcePins<'a> {
    pub(crate) facts: &'a Sha256Digest,
    pub(crate) generation: &'a str,
    pub(crate) artifact: &'a Sha256Digest,
    pub(crate) bundle_digest: &'a Sha256Digest,
    pub(crate) zip_resource: &'a Value,
    pub(crate) load_invocation_digest: &'a Sha256Digest,
}

struct ObjectiveImage {
    image: BeforeImage,
    value: Value,
    present: bool,
    marker: Option<i32>,
    holders: usize,
    completion: bool,
}

/// Factual current-image pins only. The staging caller must independently bind
/// them to its actual owner, context, host and private readiness acquisition.
pub(crate) struct PlanTargetImage {
    pub(crate) image: BeforeImage,
    pub(crate) runtime_source_facts_digest: Sha256Digest,
    pub(crate) host_artifact_digest: Sha256Digest,
    pub(crate) registry_generation: String,
}

fn not_executed(value: &Value) -> AppResult<()> {
    if *value
        != json!({"commandReturnObserved":false,"singleCallbackObserved":false,
        "queueTerminalObserved":false,"actualTaskTerminalObserved":false,"continuationPending":null,
        "terminationConfirmed":false,"furtherEffectsPossible":true})
    {
        return Err(invalid());
    }
    Ok(())
}

/// The initial readonly readiness snapshot must actually observe absence. It
/// is not a synthesized expected image or a future Invocation's before state.
pub(crate) fn initial_plan_image(
    value: &Value,
    context: &Value,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<PlanTargetImage> {
    check()?;
    let facts = codec::digest_field(value, "runtimeSourceFactsDigest")?;
    let artifact = codec::digest_field(value, "hostArtifactDigest")?;
    let generation = codec::text(value, "registryGeneration")?.to_owned();
    let image = decode_images_with_pins(value, context, &facts, &generation, &artifact, check)?;
    not_executed(&value["commandObservation"])?;
    if image.present {
        return Err(drift());
    }
    check()?;
    Ok(PlanTargetImage {
        image: image.image,
        runtime_source_facts_digest: facts,
        host_artifact_digest: artifact,
        registry_generation: generation,
    })
}

/// Common phase preflight compares these actual bytes with Application's
/// before-to-after digest chain. It must not reassert global initial absence.
pub(crate) fn preflight_plan_image(
    value: &Value,
    context: &Value,
    facts: &Sha256Digest,
    artifact: &Sha256Digest,
    generation: &str,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<BeforeImage> {
    let image = decode_images_with_pins(value, context, facts, generation, artifact, check)?;
    not_executed(&value["commandObservation"])?;
    check()?;
    Ok(image.image)
}

fn decode_image(bytes: Vec<u8>, check: &dyn Fn() -> AppResult<()>) -> AppResult<ObjectiveImage> {
    let value = codec::parse(&bytes, IMAGE_BYTES, 16384, check)?;
    codec::exact(
        &value,
        &[
            "format",
            "selector",
            "status",
            "presence",
            "membershipScope",
            "captureScope",
            "coverage",
            "reason",
            "payload",
        ],
    )?;
    let selector = json!({"kind":"objective","objective":"mcalpack"});
    if value["format"] != "mmmm.native.target/1" || value["selector"] != selector {
        return Err(invalid());
    }
    // Reuse the complete objective DTO grammar without changing the retained
    // original bytes or ordinary NativeTargets grammar/authority.
    let mut grammar = value.clone();
    let binding = json!({"targetId":TARGET,"kind":"objective","objective":"mcalpack"});
    grammar["format"] = json!("mmmm.native.calibration-target/1");
    grammar["selector"] = binding.clone();
    crate::native_payload::validate_calibration_image(&grammar, &binding).map_err(|cause| {
        AppError::caused_by(
            "PACK_CALIBRATION_IMAGE_INVALID",
            "Actual whole-objective image violates its native grammar",
            cause,
        )
    })?;
    if value["status"] != "known" || !value["reason"].is_null() {
        return Err(unavailable());
    }
    let present = value["presence"] == "present";
    let mut marker = None;
    let mut holders = 0;
    if present {
        codec::decode_native_nbt(&value["payload"]["nativeObjectiveNbt"], check)?;
        for score in value["payload"]["scores"].as_array().ok_or_else(invalid)? {
            check()?;
            codec::decode_native_nbt(&score["nativeScoreNbt"], check)?;
            holders += 1;
            if score["holder"] == "#marker" {
                marker = Some(
                    score["value"]
                        .as_i64()
                        .and_then(|v| i32::try_from(v).ok())
                        .ok_or_else(invalid)?,
                );
            }
        }
    }
    check()?;
    Ok(ObjectiveImage {
        image: BeforeImage {
            target: TARGET.into(),
            bytes,
        },
        value,
        present,
        marker,
        holders,
        completion: false,
    })
}

fn decode_images(
    value: &Value,
    context: &Value,
    pins: &SourcePins<'_>,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<ObjectiveImage> {
    decode_images_with_pins(
        value,
        context,
        pins.facts,
        pins.generation,
        pins.artifact,
        check,
    )
}

fn decode_images_with_pins(
    value: &Value,
    context: &Value,
    facts: &Sha256Digest,
    generation: &str,
    artifact: &Sha256Digest,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<ObjectiveImage> {
    check()?;
    mmmm_contracts::ContractValidator::shared()
        .map_err(|_| invalid())?
        .validate("ExecutionContext", context)
        .map_err(|_| invalid())?;
    if generation.is_empty()
        || generation.len() > 256
        || generation.starts_with('0')
        || !generation.bytes().all(|byte| byte.is_ascii_digit())
        || generation
            .parse::<i64>()
            .ok()
            .is_none_or(|value| value <= 0)
    {
        return Err(invalid());
    }
    codec::exact(
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
            "commandObservation",
        ],
    )?;
    if value["format"] != "mmmm.native.pack-calibration-target-images/1"
        || value["protocolVersion"] != "0.2.0"
        || value["environment"] != context["environment"]
        || value["contextId"] != context["contextId"]
        || value["contextDigest"] != context["contextDigest"]
        || value["runtimeSourceFactsDigest"] != facts.as_str()
        || value["hostArtifactDigest"] != artifact.as_str()
        || value["registryGeneration"] != generation
        || !context["scope"]["externalTargetIds"]
            .as_array()
            .is_some_and(|scope| scope.contains(&json!(TARGET)))
        || codec::tick(&value["observedFromTick"])? > codec::tick(&value["observedToTick"])?
        || time::OffsetDateTime::parse(
            codec::text(value, "observedAt")?,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
    {
        return Err(invalid());
    }
    let targets = value["targets"]
        .as_array()
        .filter(|v| v.len() == 1)
        .ok_or_else(invalid)?;
    codec::exact(&targets[0], &["targetId", "rawBytesHex", "rawSha256"])?;
    if targets[0]["targetId"] != TARGET {
        return Err(invalid());
    }
    let bytes = codec::hex(codec::text(&targets[0], "rawBytesHex")?, IMAGE_BYTES, check)?;
    if raw_digest(&bytes) != codec::digest_field(&targets[0], "rawSha256")? {
        return Err(invalid());
    }
    let mut image = decode_image(bytes, check)?;
    image.completion = command_completion(&value["commandObservation"])?;
    Ok(image)
}

fn command_completion(value: &Value) -> AppResult<bool> {
    codec::exact(
        value,
        &[
            "commandReturnObserved",
            "singleCallbackObserved",
            "queueTerminalObserved",
            "actualTaskTerminalObserved",
            "continuationPending",
            "terminationConfirmed",
            "furtherEffectsPossible",
        ],
    )?;
    let mut observations = true;
    for key in [
        "commandReturnObserved",
        "singleCallbackObserved",
        "queueTerminalObserved",
        "actualTaskTerminalObserved",
    ] {
        observations &= value[key].as_bool().ok_or_else(invalid)?;
    }
    let termination = value["terminationConfirmed"]
        .as_bool()
        .ok_or_else(invalid)?;
    let further = value["furtherEffectsPossible"]
        .as_bool()
        .ok_or_else(invalid)?;
    let pending = if value["continuationPending"].is_null() {
        None
    } else {
        Some(value["continuationPending"].as_bool().ok_or_else(invalid)?)
    };
    let complete = observations && pending == Some(false) && termination && !further;
    if (termination && !complete) || (!termination && (!further || pending == Some(false))) {
        return Err(invalid());
    }
    Ok(complete)
}

fn step_index(entered: &EnteredPackRun<'_>) -> AppResult<usize> {
    let steps = entered.plan()["steps"]
        .as_array()
        .filter(|steps| steps.len() == 3)
        .ok_or_else(invalid)?;
    let program = entered.program();
    let commands = program
        .initialization_commands()
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(program.invocation_command()))
        .collect::<Vec<_>>();
    if commands.len() != 3 {
        return Err(invalid());
    }
    for (step, command) in steps.iter().zip(commands) {
        if step["actionId"] != "mmmm:command_execute"
            || step["arguments"] != json!({"command":command})
            || step["resourcesWritten"] != json!([TARGET])
            || step["resourcesRead"] != json!([TARGET])
        {
            return Err(invalid());
        }
    }
    steps
        .iter()
        .position(|step| step["stepId"] == entered.original()["stepId"])
        .ok_or_else(invalid)
}

fn pins<'a>(entered: &'a EnteredPackRun<'_>) -> SourcePins<'a> {
    SourcePins {
        facts: entered.runtime_source_facts_digest(),
        generation: entered.registry_generation(),
        artifact: entered.host_artifact_digest(),
        bundle_digest: entered.source_bundle_digest(),
        zip_resource: entered.source_zip_resource(),
        load_invocation_digest: entered.load_invocation_digest(),
    }
}

fn source_rows(program: &CalibrationPackProgram) -> AppResult<(Value, Value)> {
    let entries = program
        .source_entries()
        .iter()
        .map(|(path, bytes)| {
            json!({
                "path":path,"rawSha256":raw_digest(bytes),"byteLength":bytes.len(),
                "rawBytesHex":bytes.iter().map(|byte|format!("{byte:02x}")).collect::<String>()
            })
        })
        .collect::<Vec<_>>();
    let mut functions = std::collections::BTreeMap::new();
    for (path, bytes) in program.source_entries() {
        if path == "pack.mcmeta" {
            continue;
        }
        let (namespace, suffix) = path
            .strip_prefix("data/")
            .and_then(|rest| rest.split_once("/function/"))
            .ok_or_else(invalid)?;
        let name = suffix.strip_suffix(".mcfunction").ok_or_else(invalid)?;
        let id = format!("{namespace}:{name}");
        functions.insert(id.clone(), json!({"functionId":id,"resourceId":format!("{namespace}:function/{name}.mcfunction"),"rawSha256":raw_digest(bytes)}));
    }
    if entries.len() != 3
        || functions.len() != 2
        || functions
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            != *program.function_ids()
    {
        return Err(invalid());
    }
    Ok((
        json!(entries),
        json!(functions.into_values().collect::<Vec<_>>()),
    ))
}

fn native_packet(value: &Value, phase: u8, check: &dyn Fn() -> AppResult<()>) -> AppResult<Value> {
    let bytes = codec::hex(value.as_str().ok_or_else(invalid)?, 64 * 1024, check)?;
    if bytes.len() < 12
        || &bytes[..8] != b"MMMMPR01"
        || bytes[8] != phase
        || bytes[9] != 1
        || usize::from(u16::from_be_bytes([bytes[10], bytes[11]])) != bytes.len() - 12
    {
        return Err(unavailable());
    }
    codec::parse(&bytes[12..], 65524, crate::rpc::MAX_CONTROL_NODES, check)
}

fn verify_load_receipt(value: &Value, functions: &Value, pins: &SourcePins<'_>) -> AppResult<()> {
    codec::exact(
        value,
        &[
            "format",
            "loadOnly",
            "sourceKind",
            "loadInvocationDigest",
            "sourceBundleDigest",
            "logicalProgramDigest",
            "selectedFunctionSourceDigest",
            "functions",
        ],
    )?;
    if value["format"] != "mmmm.native.pack-run-readiness/1"
        || value["loadOnly"] != true
        || value["sourceKind"] != "pack_case"
        || value["loadInvocationDigest"] != pins.load_invocation_digest.as_str()
        || value["sourceBundleDigest"] != pins.bundle_digest.as_str()
        || value["functions"] != *functions
        || value["selectedFunctionSourceDigest"]
            != canonical_digest(functions).map_err(|_| invalid())?.as_str()
    {
        return Err(invalid());
    }
    Ok(())
}

fn verify_completed_receipt(
    value: &Value,
    original: &Value,
    program: &CalibrationPackProgram,
    functions: &Value,
    pins: &SourcePins<'_>,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<()> {
    check()?;
    codec::exact(
        value,
        &[
            "format",
            "loadOnly",
            "sourceKind",
            "loadInvocationDigest",
            "runInvocationDigest",
            "sourceBundleDigest",
            "logicalProgramDigest",
            "selectedFunctionSourceDigest",
            "functions",
            "eventKind",
            "completed",
            "eventsObserved",
            "instantiations",
            "functionCalls",
            "scheduledFunctions",
            "tasksCreated",
            "entriesExecuted",
            "framesReturned",
            "queueTerminal",
            "closureWitnesses",
            "failure",
        ],
    )?;
    if value["format"] != "mmmm.native.pack-run-facts/1"
        || value["loadOnly"] != false
        || value["sourceKind"] != "pack_case"
        || value["loadInvocationDigest"] != pins.load_invocation_digest.as_str()
        || value["runInvocationDigest"]
            != canonical_digest(original).map_err(|_| invalid())?.as_str()
        || value["sourceBundleDigest"] != pins.bundle_digest.as_str()
        || value["logicalProgramDigest"] != program.program_digest().as_str()
        || value["selectedFunctionSourceDigest"]
            != canonical_digest(functions).map_err(|_| invalid())?.as_str()
        || value["functions"] != *functions
        || value["eventKind"] != 13
        || value["completed"] != true
        || !value["failure"].is_null()
        || value["eventsObserved"]
            .as_u64()
            .is_none_or(|count| count == 0 || count > 4096)
        || value["instantiations"] != 2
        || value["functionCalls"] != 2
        || value["scheduledFunctions"] != 2
        || value["tasksCreated"] != 5
        || value["entriesExecuted"] != 5
        || value["framesReturned"] != 2
    {
        return Err(unavailable());
    }
    let queue = &value["queueTerminal"];
    codec::exact(
        queue,
        &["commandQuota", "overflow", "queued", "newTopCommands"],
    )?;
    if queue["commandQuota"]
        .as_i64()
        .and_then(|value| i32::try_from(value).ok())
        .is_none_or(|quota| quota <= 0)
        || queue["overflow"] != false
        || queue["queued"] != 0
        || queue["newTopCommands"] != 0
    {
        return Err(unavailable());
    }
    let closures = &value["closureWitnesses"];
    codec::exact(closures, &["taskProvider", "entryAction"])?;
    for (key, recipe, count) in [
        ("taskProvider", "call_function_task_provider", 2),
        ("entryAction", "unbound_entry_action", 5),
    ] {
        let witness = &closures[key];
        codec::exact(witness, &["recipe", "bindingsVerified"])?;
        if witness["recipe"] != recipe || witness["bindingsVerified"] != count {
            return Err(unavailable());
        }
    }
    // These are facts from the separately admitted native private factory, not
    // a SAM envelope, a public whitelist or a constructor from the JSON flags.
    check()
}

/// Strict source-byte relation, used only below the actual private registry
/// and authenticated current request. A decoded packet is not a constructor
/// for an Accepted run, a captured closure or target admission.
pub(crate) fn verify_run_source(
    value: &Value,
    original: &Value,
    program: &CalibrationPackProgram,
    pins: &SourcePins<'_>,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<()> {
    check()?;
    let bytes = encode_json(value).map_err(|_| invalid())?;
    codec::parse(
        &bytes,
        crate::rpc::MAX_CONTROL_BYTES,
        crate::rpc::MAX_CONTROL_NODES,
        check,
    )?;
    codec::exact(
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
            "operationId",
            "stepId",
            "invocationId",
            "invocationDigest",
            "programDigest",
            "sourceBundleDigest",
            "sourceZipResource",
            "loadReceiptHex",
            "runReceiptHex",
            "observedFromTick",
            "observedToTick",
            "observedAt",
        ],
    )?;
    let (entries, functions) = source_rows(program)?;
    if value["format"] != "mmmm.native.pack-calibration-source/1"
        || value["protocolVersion"] != "0.2.0"
        || value["environment"] != original["context"]["environment"]
        || value["contextId"] != original["context"]["contextId"]
        || value["contextDigest"] != original["contextDigest"]
        || value["runtimeSourceFactsDigest"] != pins.facts.as_str()
        || value["hostArtifactDigest"] != pins.artifact.as_str()
        || value["registryGeneration"] != pins.generation
        || value["operationId"] != original["operationId"]
        || value["stepId"] != "pack-entry"
        || value["stepId"] != original["stepId"]
        || value["invocationId"] != original["invocationId"]
        || value["invocationDigest"] != canonical_digest(original).map_err(|_| invalid())?.as_str()
        || original["actionId"] != "mmmm:command_execute"
        || original["arguments"] != json!({"command":program.invocation_command()})
        || value["programDigest"] != program.program_digest().as_str()
        || value["sourceBundleDigest"] != pins.bundle_digest.as_str()
        || canonical_digest(&entries).map_err(|_| invalid())? != *pins.bundle_digest
        || value["sourceZipResource"] != *pins.zip_resource
        || codec::tick(&value["observedFromTick"])? > codec::tick(&value["observedToTick"])?
        || time::OffsetDateTime::parse(
            codec::text(value, "observedAt")?,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
    {
        return Err(invalid());
    }
    mmmm_contracts::ContractValidator::shared()
        .map_err(|_| invalid())?
        .validate("ResourceRef", pins.zip_resource)
        .map_err(|_| invalid())?;
    let load = native_packet(&value["loadReceiptHex"], 47, check)?;
    verify_load_receipt(&load, &functions, pins)?;
    if load["logicalProgramDigest"] != program.program_digest().as_str() {
        return Err(invalid());
    }
    let run = native_packet(&value["runReceiptHex"], 48, check)?;
    verify_completed_receipt(&run, original, program, &functions, pins, check)?;
    check()
}

fn prepare_image(
    entered: &EnteredPackRun<'_>,
    store: &mut DurableStore,
) -> AppResult<ObjectiveImage> {
    entered.check_local(store)?;
    let ready =
        entered
            .route()
            .prepare_observed(store, entered.request(), entered.original(), &|store| {
                entered.check_local(store)
            });
    let ready = finish_native_observation(ready, entered.check_local(store))?;
    codec::exact(
        &ready,
        &[
            "format",
            "invocationId",
            "invocationDigest",
            "programDigest",
            "targetImages",
        ],
    )?;
    if ready["format"] != "mmmm.native.pack-calibration-ready/1"
        || ready["invocationId"] != entered.original()["invocationId"]
        || ready["invocationDigest"]
            != canonical_digest(entered.original())
                .map_err(|_| invalid())?
                .as_str()
        || ready["programDigest"] != entered.program_digest().as_str()
    {
        return Err(invalid());
    }
    let image = decode_images(
        &ready["targetImages"],
        &entered.original()["context"],
        &pins(entered),
        &|| entered.check_local(store),
    )?;
    check_before(entered, store, &image)?;
    Ok(image)
}

pub(crate) fn capture_before(
    entered: &EnteredPackRun<'_>,
    store: &mut DurableStore,
) -> AppResult<Option<BeforeCapture>> {
    let image = prepare_image(entered, store)?;
    let original = entered.original();
    Ok(Some(BeforeCapture {
        invocation_id: decode(&original["invocationId"])?,
        binding_id: decode(&original["bindingId"])?,
        context_digest: codec::digest_field(original, "contextDigest")?,
        implementation_digest: codec::digest_field(original, "implementationDigest")?,
        arguments_digest: codec::digest_field(original, "argumentsDigest")?,
        images: vec![image.image],
    }))
}

pub(crate) fn check_prepared_capture(
    entered: &EnteredPackRun<'_>,
    store: &mut DurableStore,
) -> AppResult<()> {
    let fresh = prepare_image(entered, store)?;
    let retained = retained_before(store, entered.original(), &|| entered.check_local(store))?;
    if fresh.image.bytes != retained {
        return Err(drift());
    }
    entered.check_local(store)
}

fn check_before(
    entered: &EnteredPackRun<'_>,
    store: &DurableStore,
    image: &ObjectiveImage,
) -> AppResult<()> {
    let index = step_index(entered)?;
    if index == 0 {
        if image.present {
            return Err(drift());
        }
    } else {
        let prior = prior_after(entered, store, index - 1)?;
        if prior != image.image.bytes
            || !image.present
            || (index == 1 && image.holders != 0)
            || (index == 2 && (image.marker != Some(7331) || image.holders != 1))
        {
            return Err(drift());
        }
    }
    entered.check_local(store)
}

fn retained_before(
    store: &DurableStore,
    original: &Value,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<Vec<u8>> {
    let operation = decode(&original["operationId"])?;
    let summaries = store.operation_summaries(&operation).map_err(storage)?;
    if summaries.len() > 4096 {
        return Err(limit());
    }
    let mut retained = None;
    for reference in summaries {
        let value = read_json(store, &reference, 64 * 1024, check)?;
        if value["kind"] != "before_capture_summary"
            || value["stepId"] != original["stepId"]
            || value["invocationId"] != original["invocationId"]
        {
            continue;
        }
        let capture = read_json(
            store,
            &decode(&value["captureBlob"])?,
            EVIDENCE_BYTES,
            check,
        )?;
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
        let images = capture["images"]
            .as_array()
            .filter(|v| v.len() == 1)
            .ok_or_else(invalid)?;
        if images[0]["target"] != TARGET || retained.is_some() {
            return Err(invalid());
        }
        let before: BlobRef = decode(&images[0]["before"])?;
        retained = Some(read_bytes(store, &before, IMAGE_BYTES, check)?);
    }
    retained.ok_or_else(unavailable)
}

fn prior_after(
    entered: &EnteredPackRun<'_>,
    store: &DurableStore,
    index: usize,
) -> AppResult<Vec<u8>> {
    let steps = entered.plan()["steps"].as_array().ok_or_else(invalid)?;
    let step_id: StepId = decode(&steps.get(index).ok_or_else(invalid)?["stepId"])?;
    let operation = store
        .operation(&entered.operation().operation_id)
        .map_err(storage)?;
    let step = operation
        .steps
        .iter()
        .find(|step| step.step_id == step_id)
        .ok_or_else(unavailable)?;
    if !step.write_effect
        || step.dispatch != DispatchEvidence::Observed
        || !step.finished
        || step.verification_requirement != VerificationRequirement::IndependentReadback
        || step.further_effects_possible
        || step.effect != EffectEvidence::CompleteConfirmed
        || step.observation_refs.len() > 64
    {
        return Err(unavailable());
    }
    let original_blob = store
        .stored_invocation_blob(&operation.operation_id, &step_id)
        .map_err(storage)?;
    let original = store
        .stored_invocation_checked(&operation.operation_id, &step_id, 64 * 1024, || {
            entered
                .check_local(store)
                .map_err(|cause| StorageError::Io(std::io::Error::other(cause)))
        })
        .map_err(storage)?;
    if original["invocationId"].as_str() != step.invocation_id.as_ref().map(|id| id.as_str())
        || step.invocation_digest.as_ref() != Some(&original_blob.digest)
        || original["stepId"] != step_id.as_str()
        || original["operationId"] != operation.operation_id.as_str()
        || original["context"] != entered.original()["context"]
        || original["arguments"] != steps[index]["arguments"]
        || original["actionId"] != "mmmm:command_execute"
    {
        return Err(invalid());
    }
    let members = store
        .operation_evidence_refs(&operation.operation_id)
        .map_err(storage)?;
    let mut result = None;
    for reference in &step.observation_refs {
        let envelope = read_json(store, reference, EVIDENCE_BYTES, &|| {
            entered.check_local(store)
        })?;
        if envelope["kind"] != "independent_readback" {
            continue;
        }
        if envelope["stepId"] != original["stepId"]
            || envelope["invocationId"] != original["invocationId"]
            || [
                "bindingId",
                "contextDigest",
                "implementationDigest",
                "argumentsDigest",
            ]
            .iter()
            .any(|key| envelope[*key] != original[*key])
        {
            return Err(invalid());
        }
        // Older partial/unknown observations remain in the original journal.
        // Only an actual subsequently confirmed terminal readback may be the
        // predecessor; selecting it never changes the older record's meaning.
        if envelope["settled"] != true
            || envelope["effect"]
                != serde_json::to_value(EffectEvidence::CompleteConfirmed).map_err(|_| invalid())?
        {
            continue;
        }
        let sources = envelope["sourceRefs"]
            .as_array()
            .filter(|v| v.len() == 1)
            .ok_or_else(invalid)?;
        let source: BlobRef = decode(&sources[0])?;
        if !members.contains(&source) {
            return Err(invalid());
        }
        let observation = read_json(store, &source, EVIDENCE_BYTES, &|| {
            entered.check_local(store)
        })?;
        codec::exact(
            &observation,
            &[
                "format",
                "caseId",
                "stepIndex",
                "invocationId",
                "invocationDigest",
                "programDigest",
                "runtimeSourceFactsDigest",
                "beforeImageSha256",
                "targetImages",
                "state",
                "runSource",
            ],
        )?;
        if observation["format"] != "mmmm.target-pack-readback/2"
            || observation["stepIndex"] != index
            || observation["caseId"] != CASE
            || observation["programDigest"] != entered.program_digest().as_str()
            || observation["runtimeSourceFactsDigest"]
                != entered.runtime_source_facts_digest().as_str()
            || !observation["runSource"].is_null()
            || observation["invocationId"] != original["invocationId"]
            || observation["invocationDigest"]
                != canonical_digest(&original).map_err(|_| invalid())?.as_str()
        {
            return Err(invalid());
        }
        let before = retained_before(store, &original, &|| entered.check_local(store))?;
        if observation["beforeImageSha256"] != raw_digest(&before).as_str() {
            return Err(invalid());
        }
        let image = decode_images(
            &observation["targetImages"],
            &original["context"],
            &pins(entered),
            &|| entered.check_local(store),
        )?;
        if observation["state"] != actual_state(&image)
            || !expected_after(&image, index)
            || !image.completion
        {
            return Err(invalid());
        }
        if result
            .as_ref()
            .is_some_and(|previous| previous != &image.image.bytes)
        {
            return Err(drift());
        }
        result = Some(image.image.bytes);
    }
    result.ok_or_else(unavailable)
}

fn actual_state(image: &ObjectiveImage) -> Value {
    json!({"presence":if image.present {"present"} else {"absent"},"marker":image.marker,"holderCount":image.holders})
}

fn expected_after(image: &ObjectiveImage, index: usize) -> bool {
    image.present
        && match index {
            0 => {
                image.holders == 0
                    && image.marker.is_none()
                    && image.value["payload"]["displaySlots"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
            }
            1 => image.holders == 1 && image.marker == Some(7331),
            2 => image.holders == 1 && image.marker == Some(1337),
            _ => false,
        }
}

fn target_state(
    entered: &EnteredPackRun<'_>,
    store: &mut DurableStore,
) -> AppResult<(Value, ObjectiveImage)> {
    entered.verify_claim(store, entered.original())?;
    let original = entered.original();
    let value = entered.route().inspect_original_with_store(
        store,
        entered.request(),
        original,
        json!({"kind":"pack_calibration_run_target_state","invocationId":original["invocationId"],
            "invocationDigest":canonical_digest(original).map_err(|_| invalid())?}),
        &|store| entered.verify_claim(store, original),
    )?;
    let image = decode_images(&value, &original["context"], &pins(entered), &|| {
        entered.verify_claim(store, original)
    })?;
    entered.verify_claim(store, original)?;
    Ok((value, image))
}

pub(crate) fn read_target(
    entered: &EnteredPackRun<'_>,
    store: &mut DurableStore,
    target: &str,
) -> AppResult<Vec<u8>> {
    if target != TARGET {
        return Err(invalid());
    }
    let (_, image) = target_state(entered, store)?;
    Ok(image.image.bytes)
}

pub(crate) fn readback(
    entered: &EnteredPackRun<'_>,
    store: &mut DurableStore,
) -> AppResult<ReadbackEvidence> {
    entered.verify_claim(store, entered.original())?;
    let index = step_index(entered)?;
    let original = entered.original();
    let before = retained_before(store, original, &|| entered.check_local(store))?;
    let before_image = decode_image(before.clone(), &|| entered.check_local(store))?;
    check_before(entered, store, &before_image)?;
    let run = if index == 2 {
        let source = entered.route().inspect_original_with_store(
            store,
            entered.request(),
            original,
            json!({"kind":"pack_calibration_run_source","invocationId":original["invocationId"],
                "invocationDigest":canonical_digest(original).map_err(|_| invalid())?,
                "expectedRuntimeSourceFactsDigest":entered.runtime_source_facts_digest(),
                "expectedRegistryGeneration":entered.registry_generation()}),
            &|store| entered.verify_claim(store, original),
        )?;
        verify_run_source(
            &source,
            original,
            entered.program(),
            &pins(entered),
            &|| entered.verify_claim(store, original),
        )?;
        source
    } else {
        Value::Null
    };
    let (images, after) = target_state(entered, store)?;
    let matches = expected_after(&after, index);
    // The current owned Accepted producer separately observed the command
    // return, single callback, engine queue drain and actual submitted task's
    // terminal stage. Request/ProviderResult completion cannot substitute it.
    // Entry additionally passed the native COMPLETE(13) run witness above.
    let settled = after.completion;
    let evidence = json!({"format":"mmmm.target-pack-readback/2","caseId":CASE,"stepIndex":index,
        "invocationId":original["invocationId"],"invocationDigest":canonical_digest(original).map_err(|_| invalid())?,
        "programDigest":entered.program_digest(),"runtimeSourceFactsDigest":entered.runtime_source_facts_digest(),
        "beforeImageSha256":raw_digest(&before),"targetImages":images,"state":actual_state(&after),"runSource":run});
    if encode_json(&evidence).map_err(|_| invalid())?.len() > EVIDENCE_BYTES {
        return Err(limit());
    }
    entered.verify_claim(store, original)?;
    Ok(ReadbackEvidence {
        invocation_id: decode(&original["invocationId"])?,
        binding_id: decode(&original["bindingId"])?,
        context_digest: codec::digest_field(original, "contextDigest")?,
        implementation_digest: codec::digest_field(original, "implementationDigest")?,
        arguments_digest: codec::digest_field(original, "argumentsDigest")?,
        effect: if matches && settled {
            EffectEvidence::CompleteConfirmed
        } else {
            EffectEvidence::SomeConfirmed
        },
        settled,
        evidence,
        direct_changes: vec![DirectChange {
            target: TARGET.into(),
            before,
            after: after.image.bytes,
        }],
    })
}

/// Pure retained-byte verification. Only a separately entered same-Store
/// private run can use this relation as part of actual source issuance.
pub(crate) fn verify_readback(
    value: &Value,
    original: &Value,
    program: &CalibrationPackProgram,
    pins: &SourcePins<'_>,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<()> {
    verify_readback_images(
        value,
        original,
        program,
        pins.facts,
        pins.generation,
        pins.artifact,
        check,
    )?;
    verify_run_source(&value["runSource"], original, program, pins, check)
}

/// This relation checks independent target bytes only. It deliberately cannot
/// supply the missing original-load or actual-run source issuer.
pub(crate) fn verify_readback_images(
    value: &Value,
    original: &Value,
    program: &CalibrationPackProgram,
    facts: &Sha256Digest,
    generation: &str,
    artifact: &Sha256Digest,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<()> {
    codec::exact(
        value,
        &[
            "format",
            "caseId",
            "stepIndex",
            "invocationId",
            "invocationDigest",
            "programDigest",
            "runtimeSourceFactsDigest",
            "beforeImageSha256",
            "targetImages",
            "state",
            "runSource",
        ],
    )?;
    if value["format"] != "mmmm.target-pack-readback/2"
        || value["caseId"] != CASE
        || value["stepIndex"] != 2
        || original["stepId"] != "pack-entry"
        || original["actionId"] != "mmmm:command_execute"
        || original["arguments"] != json!({"command":program.invocation_command()})
        || value["invocationId"] != original["invocationId"]
        || value["invocationDigest"] != canonical_digest(original).map_err(|_| invalid())?.as_str()
        || value["programDigest"] != program.program_digest().as_str()
        || value["runtimeSourceFactsDigest"] != facts.as_str()
    {
        return Err(invalid());
    }
    codec::digest_field(value, "beforeImageSha256")?;
    let image = decode_images_with_pins(
        &value["targetImages"],
        &original["context"],
        facts,
        generation,
        artifact,
        check,
    )?;
    if !expected_after(&image, 2)
        || !image.completion
        || value["state"] != actual_state(&image)
        || !value["runSource"].is_object()
    {
        return Err(invalid());
    }
    check()
}

pub(crate) fn verify_before_capture_pin(
    store: &DurableStore,
    original: &Value,
    digest: &Sha256Digest,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<()> {
    let bytes = retained_before(store, original, check)?;
    if raw_digest(&bytes) != *digest {
        return Err(invalid());
    }
    let before = decode_image(bytes, check)?;
    if !before.present || before.marker != Some(7331) || before.holders != 1 {
        return Err(invalid());
    }
    check()
}

pub(crate) fn verify_completed_chain(
    entered: &EnteredPackRun<'_>,
    store: &DurableStore,
) -> AppResult<()> {
    entered.verify_claim(store, entered.original())?;
    if step_index(entered)? != 2 {
        return Err(invalid());
    }
    let originals = entered.ordered_originals(store)?;
    if originals.len() != 3 || &originals[2] != entered.original() {
        return Err(invalid());
    }
    let mut identities = std::collections::BTreeSet::new();
    let mut previous = None;
    for (index, original) in originals.iter().enumerate() {
        if !identities.insert(codec::text(original, "invocationId")?) {
            return Err(invalid());
        }
        let before = retained_before(store, original, &|| entered.check_local(store))?;
        let image = decode_image(before.clone(), &|| entered.check_local(store))?;
        if index == 0 {
            if image.present {
                return Err(invalid());
            }
        } else if previous.as_ref() != Some(&before)
            || !image.present
            || (index == 1 && image.holders != 0)
            || (index == 2 && (image.holders != 1 || image.marker != Some(7331)))
        {
            return Err(invalid());
        }
        if index < 2 {
            let after = prior_after(entered, store, index)?;
            let image = decode_image(after.clone(), &|| entered.check_local(store))?;
            if !expected_after(&image, index) {
                return Err(invalid());
            }
            previous = Some(after);
        }
    }
    entered.verify_claim(store, entered.original())
}

fn read_bytes(
    store: &DurableStore,
    reference: &BlobRef,
    maximum: usize,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<Vec<u8>> {
    store
        .read_blob_checked(reference, maximum as u64, || {
            check().map_err(|cause| StorageError::Io(std::io::Error::other(cause)))
        })
        .map_err(storage)
}
fn read_json(
    store: &DurableStore,
    reference: &BlobRef,
    maximum: usize,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<Value> {
    codec::parse(
        &read_bytes(store, reference, maximum, check)?,
        maximum,
        crate::rpc::MAX_CONTROL_NODES,
        check,
    )
}
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> AppResult<T> {
    serde_json::from_value(value.clone()).map_err(|_| invalid())
}
fn invalid() -> AppError {
    AppError::new(
        "PACK_CALIBRATION_EVIDENCE_INVALID",
        "PACK facts differ from the actual original run and closed source recipe",
    )
}
fn unavailable() -> AppError {
    AppError::new(
        "CALIBRATION_RUN_ISSUER_UNAVAILABLE",
        "Actual privately issued PACK run or whole-objective evidence is unavailable",
    )
}
fn drift() -> AppError {
    AppError::new(
        "TARGET_DRIFT",
        "Actual whole-objective state differs from the same-operation retained predecessor",
    )
}
fn limit() -> AppError {
    AppError::new(
        "BUDGET_EXCEEDED",
        "PACK observation exceeds its finite original evidence bounds",
    )
}
fn storage(cause: StorageError) -> AppError {
    AppError::storage("PACK_CALIBRATION_EVIDENCE_UNAVAILABLE", cause)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(phase: u8, status: u8, payload: &[u8]) -> Value {
        let mut bytes = b"MMMMPR01".to_vec();
        bytes.extend_from_slice(&[phase, status]);
        bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(payload);
        json!(
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    }

    #[test]
    fn packet_phase_status_and_exact_length_do_not_imply_completed_run() {
        // Header/grammar checks only. No fake run, source registry, VM closure,
        // actual command, root or issuer capability is created by these bytes.
        let value = packet(47, 1, br#"{"loadOnly":true}"#);
        assert_eq!(
            native_packet(&value, 47, &|| Ok(())).unwrap(),
            json!({"loadOnly":true})
        );
        assert!(native_packet(&value, 48, &|| Ok(())).is_err());
        assert!(native_packet(&packet(48, 0, b"{}"), 48, &|| Ok(())).is_err());
        let mut changed = value.as_str().unwrap().to_owned();
        changed.push_str("00");
        assert!(native_packet(&json!(changed), 47, &|| Ok(())).is_err());
        assert!(native_packet(&packet(43, 1, b"{}"), 48, &|| Ok(())).is_err());
        assert!(native_packet(&json!("4d4d4d4d50523031"), 48, &|| Ok(())).is_err());
    }

    #[test]
    fn pack_recipe_rows_keep_two_sources_and_three_logical_entries_separate() {
        let program = CalibrationPackProgram::java_26_3().unwrap();
        let (entries, functions) = source_rows(&program).unwrap();
        assert_eq!(entries.as_array().unwrap().len(), 3);
        assert_eq!(functions.as_array().unwrap().len(), 2);
        assert_eq!(
            functions[0]["functionId"],
            "mmmm_calibration:pack/dependency"
        );
        assert_eq!(functions[1]["functionId"], "mmmm_calibration:pack/entry");
        assert_ne!(
            canonical_digest(&entries).unwrap(),
            *program.program_digest()
        );
        assert_ne!(
            canonical_digest(&functions).unwrap(),
            *program.program_digest()
        );
        let raw = mmmm_contracts::canonical_bytes(&entries).unwrap();
        assert_eq!(canonical_digest(&entries).unwrap(), raw_digest(&raw));
        let unknown = json!({"format":"mmmm.native.target/1","selector":{"kind":"objective","objective":"mcalpack"},
            "status":"unknown","presence":"unknown","membershipScope":"unknown","captureScope":"native_objective_and_all_scores",
            "coverage":"best_effort","reason":"actual_native_unavailable","payload":null});
        assert!(decode_image(encode_json(&unknown).unwrap(), &|| Ok(())).is_err());
    }

    #[test]
    fn legacy_marker_summary_cannot_replace_whole_objective_or_actual_entry_source() {
        let program = CalibrationPackProgram::java_26_3().unwrap();
        let digest = raw_digest(b"codec pin only; no source or actual run");
        let legacy = json!({"format":"mmmm.target-pack-readback/1","caseId":CASE,"marker":1337,
            "installedFunctionIds":["mmmm_calibration:pack/entry","mmmm_calibration:pack/dependency"]});
        assert!(
            verify_readback_images(
                &legacy,
                &Value::Null,
                &program,
                &digest,
                "1",
                &digest,
                &|| Ok(())
            )
            .is_err()
        );
        let (_, functions) = source_rows(&program).unwrap();
        let resource = Value::Null;
        let pins = SourcePins {
            facts: &digest,
            generation: "1",
            artifact: &digest,
            bundle_digest: &digest,
            zip_resource: &resource,
            load_invocation_digest: &digest,
        };
        let old = json!({"schema":"mmmm-loaded-pack-source-facts/1","phase":43,
            "nativeFacts":{"currentAssessmentComplete":true},"historicalFacts":{"consumedParsePublicationObserved":true}});
        assert!(verify_load_receipt(&old, &functions, &pins).is_err());
    }

    #[test]
    fn an_event_accepted_by_native_is_not_a_completed_pack_run() {
        // This pure negative codec input is not a private-issued native packet.
        // All source-looking fields still cannot replace actual COMPLETE(13),
        // terminal queues and both exact captured-closure relations.
        let program = CalibrationPackProgram::java_26_3().unwrap();
        let (entries, functions) = source_rows(&program).unwrap();
        let bundle = canonical_digest(&entries).unwrap();
        let digest = raw_digest(b"pure negative relation only");
        let resource = Value::Null;
        let pins = SourcePins {
            facts: &digest,
            generation: "1",
            artifact: &digest,
            bundle_digest: &bundle,
            zip_resource: &resource,
            load_invocation_digest: &digest,
        };
        let original = json!({"invocationId":"codec-only"});
        let value = json!({"format":"mmmm.native.pack-run-facts/1","loadOnly":false,"sourceKind":"pack_case",
            "loadInvocationDigest":digest,"runInvocationDigest":canonical_digest(&original).unwrap(),
            "sourceBundleDigest":bundle,"logicalProgramDigest":program.program_digest(),
            "selectedFunctionSourceDigest":canonical_digest(&functions).unwrap(),"functions":functions,
            "eventKind":12,"completed":false,"eventsObserved":20,"instantiations":2,"functionCalls":2,
            "scheduledFunctions":2,"tasksCreated":5,"entriesExecuted":5,"framesReturned":2,
            "queueTerminal":{"commandQuota":1,"overflow":false,"queued":0,"newTopCommands":0},
            "closureWitnesses":{"taskProvider":{"recipe":"call_function_task_provider","bindingsVerified":2},
                "entryAction":{"recipe":"unbound_entry_action","bindingsVerified":5}},"failure":null});
        assert!(
            verify_completed_receipt(
                &value,
                &original,
                &program,
                &value["functions"],
                &pins,
                &|| Ok(())
            )
            .is_err()
        );
        let mut queued = value.clone();
        queued["eventKind"] = json!(13);
        queued["completed"] = json!(true);
        queued["queueTerminal"]["queued"] = json!(1);
        assert!(
            verify_completed_receipt(
                &queued,
                &original,
                &program,
                &value["functions"],
                &pins,
                &|| Ok(())
            )
            .is_err()
        );
        let mut missing = value.clone();
        missing["eventKind"] = json!(13);
        missing["completed"] = json!(true);
        missing["closureWitnesses"]["entryAction"]["bindingsVerified"] = json!(4);
        assert!(
            verify_completed_receipt(
                &missing,
                &original,
                &program,
                &value["functions"],
                &pins,
                &|| Ok(())
            )
            .is_err()
        );
    }

    #[test]
    fn request_or_command_return_cannot_substitute_actual_game_task_termination() {
        let pending = json!({"commandReturnObserved":true,"singleCallbackObserved":true,
            "queueTerminalObserved":true,"actualTaskTerminalObserved":false,"continuationPending":null,
            "terminationConfirmed":false,"furtherEffectsPossible":true});
        assert!(!command_completion(&pending).unwrap());
        let mut forged = pending.clone();
        forged["terminationConfirmed"] = json!(true);
        forged["furtherEffectsPossible"] = json!(false);
        forged["continuationPending"] = json!(false);
        assert!(command_completion(&forged).is_err());
        let mut complete_shape = forged;
        complete_shape["actualTaskTerminalObserved"] = json!(true);
        assert!(command_completion(&complete_shape).unwrap());
        // This is only a codec relation; the caller must still enter the
        // private actual Accepted route and preserve its original raw reply.
        complete_shape["requestFutureDone"] = json!(true);
        assert!(command_completion(&complete_shape).is_err());
    }

    #[test]
    fn initial_absence_is_read_from_bytes_and_is_not_reasserted_by_phase_preflight() {
        // Pure DTO/codec samples only: no current host acquisition, owner,
        // initial absence witness, future Invocation or operation is issued.
        let mut context: Value =
            serde_json::from_slice(include_bytes!("../../../examples/execution-context.json"))
                .unwrap();
        context["scope"]["externalTargetIds"] = json!([TARGET]);
        context["contextDigest"] =
            json!(mmmm_contracts::projected_digest("ExecutionContext", &context).unwrap());
        let digest = raw_digest(b"codec-only pins");
        let raw = json!({"format":"mmmm.native.target/1","selector":{"kind":"objective","objective":"mcalpack"},
            "status":"known","presence":"absent","membershipScope":"current_native_scoreboard",
            "captureScope":"native_objective_and_all_scores","coverage":"full_target","reason":null,"payload":{}});
        let bytes = encode_json(&raw).unwrap();
        let pending = json!({"commandReturnObserved":false,"singleCallbackObserved":false,"queueTerminalObserved":false,
            "actualTaskTerminalObserved":false,"continuationPending":null,"terminationConfirmed":false,"furtherEffectsPossible":true});
        let mut envelope = json!({"format":"mmmm.native.pack-calibration-target-images/1","protocolVersion":"0.2.0",
            "environment":context["environment"],"contextId":context["contextId"],"contextDigest":context["contextDigest"],
            "runtimeSourceFactsDigest":digest,"hostArtifactDigest":digest,"registryGeneration":"1",
            "targets":[{"targetId":TARGET,"rawBytesHex":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>(),"rawSha256":raw_digest(&bytes)}],
            "observedFromTick":"1","observedToTick":"1","observedAt":"2026-01-01T00:00:00Z","commandObservation":pending});
        assert_eq!(
            initial_plan_image(&envelope, &context, &|| Ok(()))
                .unwrap()
                .image
                .bytes,
            bytes
        );
        let empty_compound = [10_u8, 0, 0, 0];
        let mut present = raw;
        present["presence"] = json!("present");
        present["payload"] = json!({"nativeObjectiveNbt":{"format":"minecraft.nbt.named-compound/uncompressed",
            "bytesHex":"0a000000","sha256":raw_digest(&empty_compound),"rawFloatingBits":[]},"scores":[],"displaySlots":[]});
        let bytes = encode_json(&present).unwrap();
        envelope["targets"][0]["rawBytesHex"] =
            json!(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
        envelope["targets"][0]["rawSha256"] = json!(raw_digest(&bytes));
        assert!(initial_plan_image(&envelope, &context, &|| Ok(())).is_err());
        assert_eq!(
            preflight_plan_image(&envelope, &context, &digest, &digest, "1", &|| Ok(()))
                .unwrap()
                .bytes,
            bytes
        );
        envelope["commandObservation"]["actualTaskTerminalObserved"] = json!(true);
        assert!(
            preflight_plan_image(&envelope, &context, &digest, &digest, "1", &|| Ok(())).is_err()
        );
        envelope["commandObservation"]["actualTaskTerminalObserved"] = json!(false);
        envelope["registryGeneration"] = json!("+1");
        assert!(
            preflight_plan_image(&envelope, &context, &digest, &digest, "+1", &|| Ok(())).is_err()
        );
    }
}

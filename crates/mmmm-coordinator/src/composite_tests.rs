//! Pure contract and phase-classification checks. These tests neither dispatch
//! a native job nor prove world, transport or product acceptance.

use super::*;
use mmmm_contracts::ContractValidator;
use mmmm_runtime::storage::authored_projection::ProjectionReceipt;

fn fixture_digest(byte: char) -> Sha256Digest {
    Sha256Digest::new(byte.to_string().repeat(64)).unwrap()
}

fn descriptor_context() -> Value {
    let mut context = json!({
        "contractVersion":"0.2.0", "contextId":"context-composite-fixture",
        "principalRef":"principal-composite-fixture", "projectId":"project-composite-fixture",
        "environment":{
            "gameInstanceId":"game-composite-fixture", "sessionEpoch":"epoch-composite-fixture",
            "worldId":"world-composite-fixture", "side":"server", "kind":"game"
        },
        "dimension":"minecraft:overworld", "executorHandle":"handle-composite-fixture",
        "origin":[0,64,0], "rotationDegrees":[0,0], "anchor":"feet",
        "policyRevision":fixture_digest('c'),
        "scope":{
            "projectId":"project-composite-fixture", "resourceIds":[], "objectIds":[],
            "regions":[], "externalTargetIds":[]
        },
        "contextDigest":fixture_digest('0')
    });
    context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
    ContractValidator::shared()
        .unwrap()
        .validate("ExecutionContext", &context)
        .unwrap();
    context
}

fn registry(implementation: Sha256Digest) -> RustMetadataRegistry {
    RustMetadataRegistry::new(implementation, LocalAuthority::new(HostBridge::default()))
}

fn projection_result(replayed: bool) -> ProjectionCommitResult {
    ProjectionCommitResult {
        receipt: ProjectionReceipt {
            operation_id: OperationId::new("operation-composite-fixture").unwrap(),
            step_id: StepId::new("step-composite-fixture").unwrap(),
            invocation_id: InvocationId::new("invocation-composite-fixture").unwrap(),
            invocation_digest: fixture_digest('a'),
            change_digest: fixture_digest('b'),
            project_id: ProjectId::new("project-composite-fixture").unwrap(),
            project_base_revision: fixture_digest('c'),
            project_revision: fixture_digest('d'),
            world_verification_digest: fixture_digest('e'),
            world_evidence: vec![BlobRef {
                digest: fixture_digest('f'),
                byte_length: 17,
            }],
        },
        replayed,
    }
}

#[test]
fn metadata_descriptors_pin_the_separate_rust_implementation() {
    let rust_executable = fixture_digest('a');
    let host_jar = fixture_digest('b');
    let owned = registry(rust_executable.clone());
    let context = descriptor_context();
    let descriptors = owned.action_descriptors(&context).unwrap();
    assert_eq!(descriptors.len(), 3);
    for (kind, descriptor) in metadata_kinds().into_iter().zip(descriptors) {
        let (action, semantic) = metadata_route(kind).unwrap();
        ContractValidator::shared()
            .unwrap()
            .validate("ActionDescriptor", &descriptor)
            .unwrap();
        let typed: ActionDescriptor = serde_json::from_value(descriptor.clone()).unwrap();
        assert_eq!(typed.action_id.as_str(), action);
        assert_eq!(typed.semantic_kind.as_str(), semantic);
        assert_eq!(typed.implementation_digest, rust_executable);
        assert_ne!(typed.implementation_digest, host_jar);
        assert_eq!(
            descriptor["verificationRequirement"],
            "independent_readback"
        );
        assert_eq!(descriptor["completion"], "synchronous");
        assert!(owned.contract_ids().contains(action));
        ContractValidator::shared()
            .unwrap()
            .compile_action_schema(&descriptor["inputSchema"])
            .unwrap();
        ContractValidator::shared()
            .unwrap()
            .compile_action_schema(&descriptor["outputSchema"])
            .unwrap();
    }
    // A registry with another approved implementation produces another source
    // pin; the Java artifact is never implicitly selected from the context.
    let other = registry(fixture_digest('c'));
    assert_ne!(
        owned
            .descriptor(NativeKind::ResourcePatch, &context)
            .unwrap(),
        other
            .descriptor(NativeKind::ResourcePatch, &context)
            .unwrap()
    );
}

#[test]
fn recovery_and_world_kinds_cannot_use_a_metadata_route() {
    let owned = registry(fixture_digest('a'));
    let context = descriptor_context();
    for kind in [
        NativeKind::Recovery,
        NativeKind::Instantiate,
        NativeKind::Clone,
        NativeKind::Relocate,
        NativeKind::DisplayPatch,
        NativeKind::CommandPatch,
        NativeKind::ScenePatch,
    ] {
        assert!(metadata_route(kind).is_none());
        assert_eq!(
            owned.descriptor(kind, &context).unwrap_err().code,
            "CAPABILITY_UNAVAILABLE"
        );
    }
}

#[test]
fn metadata_result_has_the_canonical_envelope_and_pinned_receipt_output() {
    let result = projection_result(false);
    let output = metadata_result(&result).unwrap();
    ContractValidator::shared()
        .unwrap()
        .validate("ProviderResult", &output)
        .unwrap();
    let keys: BTreeSet<_> = output
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "contractVersion",
            "status",
            "effects",
            "diagnostics",
            "artifacts",
            "data"
        ])
    );
    assert_eq!(output["contractVersion"], "0.2.0");
    assert_eq!(output["status"], "complete");
    assert_eq!(output["effects"], "recorded");
    assert_eq!(output["diagnostics"], json!([]));
    assert_eq!(output["artifacts"], json!([]));
    assert_eq!(
        output["data"]["projectRevision"],
        json!(result.receipt.project_revision)
    );
    let receipt = serde_json::to_value(&result.receipt).unwrap();
    assert_eq!(
        output["data"]["projectionReceiptDigest"],
        json!(raw_digest(&encode_json(&receipt).unwrap()))
    );
    assert_eq!(output["data"]["replayed"], false);
    for kind in metadata_kinds() {
        let descriptor = registry(fixture_digest('a'))
            .descriptor(kind, &descriptor_context())
            .unwrap();
        ContractValidator::shared()
            .unwrap()
            .compile_action_schema(&descriptor["outputSchema"])
            .unwrap()
            .validate(&output["data"])
            .unwrap();
    }
}

#[test]
fn replay_output_preserves_the_same_receipt_identity() {
    let fresh = metadata_result(&projection_result(false)).unwrap();
    let replay = metadata_result(&projection_result(true)).unwrap();
    assert_eq!(
        fresh["data"]["projectRevision"],
        replay["data"]["projectRevision"]
    );
    assert_eq!(
        fresh["data"]["projectionReceiptDigest"],
        replay["data"]["projectionReceiptDigest"]
    );
    assert_eq!(fresh["data"]["replayed"], false);
    assert_eq!(replay["data"]["replayed"], true);
    assert_eq!(replay["effects"], "recorded");
}

#[test]
fn only_the_exact_typed_receipt_absence_is_classified_as_missing() {
    assert!(missing_receipt(&storage(StorageError::NotFound(
        "Original authored projection receipt"
    ))));
    for cause in [
        StorageError::NotFound("Prepared native payload"),
        StorageError::Conflict("Original authored projection receipt"),
        StorageError::Corrupt("Original authored projection receipt".into()),
    ] {
        assert!(!missing_receipt(&storage(cause)));
    }
    assert!(!missing_receipt(&AppError::new(
        "COMPOSITE_STORAGE_FAILED",
        "Original authored projection receipt"
    )));
}

#[test]
fn capture_images_preserve_actual_bytes_and_reject_duplicate_targets() {
    let mut images = BTreeMap::new();
    // These native bytes deliberately contain NUL, non-UTF-8 and whitespace;
    // a textual or JSON reserialization would change their raw digest.
    let actual = vec![0, 0xff, b' ', b'\n', b'{', b'}', 0x80];
    let target = "native:exact-owned-fixture".to_owned();
    insert_image(&mut images, target.clone(), actual.clone()).unwrap();
    assert_eq!(images.get(&target), Some(&actual));
    assert_eq!(
        raw_digest(images.get(&target).unwrap()),
        raw_digest(&actual)
    );
    assert!(insert_image(&mut images, target.clone(), vec![1, 2, 3]).is_err());
    assert_eq!(images.len(), 1);
    assert_eq!(images.get(&target), Some(&actual));
}

fn world_read(complete: bool, settled: bool, any_change: bool, all_before: bool) -> WorldRead {
    WorldRead {
        complete,
        settled,
        any_change,
        all_before,
        evidence: Vec::new(),
        targets: BTreeMap::new(),
    }
}

#[test]
fn metadata_without_a_receipt_cannot_fabricate_world_or_authored_effects() {
    assert_eq!(
        composite_effect(None, false, false),
        (EffectEvidence::Unknown, false)
    );
    assert_eq!(
        composite_effect(None, true, true),
        (EffectEvidence::CompleteConfirmed, true)
    );
}

#[test]
fn settled_world_without_complete_documents_remains_partial() {
    let world = world_read(true, true, true, false);
    assert_eq!(
        composite_effect(Some(&world), false, false),
        (EffectEvidence::SomeConfirmed, true)
    );
    assert_eq!(
        composite_effect(Some(&world), true, true),
        (EffectEvidence::CompleteConfirmed, true)
    );
    let running = world_read(false, false, true, false);
    assert_eq!(
        composite_effect(Some(&running), false, false),
        (EffectEvidence::SomeConfirmed, false)
    );
}

#[test]
fn no_effect_requires_exact_before_state_and_a_settled_world() {
    let unchanged = world_read(false, true, false, true);
    assert_eq!(
        composite_effect(Some(&unchanged), false, false),
        (EffectEvidence::NoneConfirmed, true)
    );
    let running = world_read(false, false, false, true);
    assert_eq!(
        composite_effect(Some(&running), false, false),
        (EffectEvidence::Unknown, false)
    );
    let incomplete = world_read(false, true, false, false);
    assert_eq!(
        composite_effect(Some(&incomplete), false, false),
        (EffectEvidence::Unknown, false)
    );
}

#[test]
fn a_committed_receipt_preserves_authored_effects_after_current_head_drift() {
    assert_eq!(
        composite_effect(None, false, true),
        (EffectEvidence::SomeConfirmed, true)
    );
    let reverted_world = world_read(false, true, false, true);
    assert_eq!(
        composite_effect(Some(&reverted_world), false, true),
        (EffectEvidence::SomeConfirmed, true)
    );
    let still_running = world_read(false, false, false, true);
    assert_eq!(
        composite_effect(Some(&still_running), false, true),
        (EffectEvidence::SomeConfirmed, false)
    );
}

/// Reuse the existing canonical context for codec selection checks.
/// These facts deliberately have no occupied request, paired route, approval,
/// native reader or operation: passing them cannot authorize any actual I/O.
fn direct_block_step() -> (Value, Value, WriteScope, Vec<String>) {
    let mut context = descriptor_context();
    context["scope"]["regions"] = json!([{"dimension":"minecraft:overworld","min":[-1,63,-1],"maxExclusive":[2,66,2],
        "contextId":context["contextId"],"worldId":context["environment"]["worldId"]}]);
    context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
    let scope: WriteScope = decode(&context["scope"]).unwrap();
    let subjects: Vec<_> = ["block_state", "block_entity"]
        .into_iter()
        .map(|kind| {
            let selector = crate::native_targets::NativeSelector::from_value(
                &json!({"kind":kind,"dimension":"minecraft:overworld","position":[0,64,0]}),
            )
            .unwrap();
            format!("native:{}", canonical_digest(selector.value()).unwrap())
        })
        .collect();
    let step = json!({"stepId":"direct-block-fixture","bindingId":"binding-fixture-01","actionId":"mmmm:block_patch",
        "actionContractVersion":"0.2.0","actionDigest":fixture_digest('a'),
        "arguments":{"dimension":"minecraft:overworld","position":[0,64,0],
            "expectedState":{"blockId":"minecraft:air","properties":{}},"desiredState":{"blockId":"minecraft:stone","properties":{}},
            "expectedRegistryGeneration":"7"},"dependsOn":[],"effect":"write","completion":"synchronous","recovery":"none",
        "resourcesRead":subjects,"resourcesWritten":subjects,"verificationRequirement":"independent_readback",
        "contextId":context["contextId"],"implementationDigest":fixture_digest('b'),"resultBindings":[]});
    validate("PlanStep", &step).unwrap();
    validate("ExecutionContext", &context).unwrap();
    (step, context, scope, subjects)
}

#[test]
fn direct_block_codec_requires_both_exact_native_subjects_and_the_conservative_fence() {
    let (step, context, scope, subjects) = direct_block_step();
    assert!(registered_direct_block(&step));
    NativeObserver::validate_direct_block_step(&step, &context, &scope).unwrap();
    for targets in [
        json!([subjects[0]]),
        json!([subjects[0], subjects[0]]),
        json!([subjects[0], subjects[1], "native:caller-added-target"]),
    ] {
        let mut changed = step.clone();
        changed["resourcesWritten"] = targets;
        assert_eq!(
            NativeObserver::validate_direct_block_step(&changed, &context, &scope)
                .unwrap_err()
                .code,
            "PERMISSION_REQUIRED"
        );
    }
    let mut narrow = scope.clone();
    narrow.regions[0].min = [0, 64, 0];
    narrow.regions[0].max_exclusive = [1, 65, 1];
    // A point is a valid legacy block region; the new codec requires its
    // explicitly approved conservative box without expanding this old rule.
    let invocation =
        json!({"context":context,"actionId":step["actionId"],"arguments":step["arguments"]});
    let point = crate::observer::BlockTarget::from_arguments(&step["arguments"]).unwrap();
    crate::observer::validate_region(&invocation, &narrow, &point).unwrap();
    assert_eq!(
        NativeObserver::validate_direct_block_step(&step, &context, &narrow)
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
    let mut another_world = scope;
    another_world.regions[0].world_id =
        mmmm_contracts::WorldId::new("world-other-fixture").unwrap();
    assert!(NativeObserver::validate_direct_block_step(&step, &context, &another_world).is_err());
}

#[test]
fn direct_block_capture_never_confuses_legacy_snapshot_subjects_or_hashes_with_a_grant() {
    let (step, context, scope, subjects) = direct_block_step();
    let mut invocation = step.clone();
    invocation["context"] = context;
    let mut observer = NativeObserver::new(HostBridge::default());
    for subject in &subjects {
        observer
            .validate_capture_target(&invocation, &scope, subject)
            .unwrap();
    }
    let legacy = crate::observer::BlockTarget::from_arguments(&step["arguments"])
        .unwrap()
        .subject();
    assert_eq!(
        observer
            .validate_capture_target(&invocation, &scope, &legacy)
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
    assert_eq!(
        observer
            .validate_capture_target(
                &invocation,
                &scope,
                &format!("native:{}", fixture_digest('c'))
            )
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
    assert_eq!(
        observer
            .capture_before(&invocation, &scope)
            .err()
            .unwrap()
            .code,
        "STORE_REQUIRED"
    );
    assert_eq!(
        observer
            .read_target(&invocation, &subjects[0])
            .unwrap_err()
            .code,
        "STORE_REQUIRED"
    );
    let mut malformed = step.clone();
    malformed["arguments"]["expectedRegistryGeneration"] = json!("007");
    assert!(
        NativeObserver::validate_direct_block_step(&malformed, &invocation["context"], &scope)
            .is_err()
    );
    let mut forged = step;
    forged["arguments"]["profileDigest"] = json!(fixture_digest('d'));
    assert!(
        NativeObserver::validate_direct_block_step(&forged, &invocation["context"], &scope)
            .is_err()
    );
}

#[test]
fn original_native_observation_failure_and_current_revocation_both_survive() {
    let result: AppResult<()> = finish_native_observation(
        Err(AppError::new(
            "NATIVE_OBSERVATION_FAILED",
            "Original native response failed",
        )),
        Err(AppError::new(
            "PERMISSION_REQUIRED",
            "Current observation scope was revoked",
        )),
    );
    let error = result.unwrap_err();
    assert_eq!(error.code, "NATIVE_OBSERVATION_FAILED");
    let cause = std::error::Error::source(&error).unwrap();
    assert!(cause.to_string().contains("PERMISSION_REQUIRED"));
    assert_eq!(
        cause.source().unwrap().to_string(),
        "NATIVE_OBSERVATION_FAILED: Original native response failed"
    );
}

#[test]
fn direct_postcheck_uses_the_current_real_grant_and_keeps_observe_separate_from_apply() {
    let (step, mut context, scope, _) = direct_block_step();
    let authority = LocalAuthority::new(HostBridge::default());
    let principal: PrincipalId = decode(&context["principalRef"]).unwrap();
    let project: ProjectId = decode(&context["projectId"]).unwrap();
    let id: ContextId = decode(&context["contextId"]).unwrap();
    let policy = authority
        .install_project_access(
            principal.clone(),
            project.clone(),
            json!(scope),
            BTreeSet::from([id.clone()]),
            std::time::Duration::from_secs(10),
        )
        .unwrap();
    context["policyRevision"] = json!(policy);
    context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
    let mut plan = parse_json(include_bytes!("../../../examples/execution-plan.json")).unwrap();
    plan["projectId"] = json!(project);
    plan["contextId"] = json!(id);
    plan["policyRevision"] = json!(policy);
    plan["scope"] = json!(scope);
    plan["steps"] = json!([step]);
    plan["contextPins"] = json!([{"contextId":id,"contextDigest":context["contextDigest"],"environment":context["environment"]}]);
    plan["approvalRequirement"] = json!("explicit_approval");
    plan["planHash"] = json!(projected_digest("ExecutionPlan", &plan).unwrap());
    let operation = OperationRecord {
        operation_id: OperationId::new("operation-direct-postcheck-fixture").unwrap(),
        principal: principal.clone(),
        project_id: project.clone(),
        idempotency_key: "direct-postcheck-once".into(),
        plan_id: decode(&plan["planId"]).unwrap(),
        plan_hash: decode(&plan["planHash"]).unwrap(),
        context_id: id.clone(),
        state: OperationState::OutcomeUnknown,
        cancellation_requested: false,
        reconciliation_required: true,
        scope: scope.clone(),
        whole_project_fence: false,
        steps: vec![],
    };
    authorize_direct_retained(
        &authority,
        &principal,
        &context,
        &operation,
        &plan,
        Access::ObserveOperation,
    )
    .unwrap();
    // There is a real Project read grant, but no host or plan approval. The
    // production checkpoint must never treat the read grant as Apply authority.
    assert_eq!(
        authorize_direct_retained(
            &authority,
            &principal,
            &context,
            &operation,
            &plan,
            Access::Apply
        )
        .unwrap_err()
        .code,
        "PERMISSION_REQUIRED"
    );
    authority.revoke_project(&principal, &project).unwrap();
    let after_success = authorize_direct_retained(
        &authority,
        &principal,
        &context,
        &operation,
        &plan,
        Access::ObserveOperation,
    );
    assert_eq!(
        finish_native_observation(Ok("received provider success"), after_success)
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
    let after_failure = authorize_direct_retained(
        &authority,
        &principal,
        &context,
        &operation,
        &plan,
        Access::ObserveOperation,
    );
    let error = finish_native_observation::<()>(
        Err(AppError::new(
            "HOST_RESULT_UNKNOWN",
            "Original native failure",
        )),
        after_failure,
    )
    .unwrap_err();
    assert_eq!(error.code, "HOST_RESULT_UNKNOWN");
    let cause = std::error::Error::source(&error).unwrap();
    assert!(cause.to_string().contains("PERMISSION_REQUIRED"));
    assert_eq!(
        cause.source().unwrap().to_string(),
        "HOST_RESULT_UNKNOWN: Original native failure"
    );

    let successor = authority
        .install_project_access(
            principal.clone(),
            project.clone(),
            json!(scope),
            BTreeSet::from([id]),
            std::time::Duration::from_secs(10),
        )
        .unwrap();
    assert_ne!(policy, successor);
    assert!(
        authorize_direct_retained(
            &authority,
            &principal,
            &context,
            &operation,
            &plan,
            Access::ObserveOperation
        )
        .is_err()
    );
    context["policyRevision"] = json!(successor);
    context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
    // A current reader may still observe this original operation under the
    // successor read grant. Its obsolete Apply policy/approval stays unusable.
    authorize_direct_retained(
        &authority,
        &principal,
        &context,
        &operation,
        &plan,
        Access::ObserveOperation,
    )
    .unwrap();
    assert!(
        authorize_direct_retained(
            &authority,
            &principal,
            &context,
            &operation,
            &plan,
            Access::Apply
        )
        .is_err()
    );
}

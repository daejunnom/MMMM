//! Source-only boundary regressions reuse canonical examples and the owning
//! compiler. Explicit authored verifier doubles exist only in this test module;
//! they are not game/profile acceptance or provider readiness evidence.
use super::*;
use crate::native_animation::{NativeAnimationCall, assemble_owned_animations};
use mmmm_compiler::{
    TargetEvidenceVerifier, TargetRuntimeRules,
    animation::{
        AnimationBindingVerifier, AnimationBindings, AnimationCompileSettings,
        AnimationEventBinding, AnimationEvidenceVerifier, AnimationTargetRules,
    },
    scene::{ResolvedSceneCommand, SceneBlockState, SceneCodecCapabilities, SceneStateBinding},
};
use mmmm_contracts::{RationalTime, ResourceLocation, StateId, SymbolId};
use mmmm_domain::{
    DomainError, Instance, Prefab,
    commands::{CommandModule, CommandNode},
    transform::Matrix4,
    types::Display,
};
use std::cell::Cell;

fn example(bytes: &[u8]) -> Value {
    mmmm_contracts::parse_json(bytes).unwrap()
}
fn revise(definition: &str, value: &mut Value) {
    value["revision"] = json!(mmmm_contracts::projected_digest(definition, value).unwrap());
}
struct AuthoredTarget;
impl TargetEvidenceVerifier for AuthoredTarget {
    fn verify_target(
        &self,
        _: &Value,
        _: &Sha256Digest,
        _: &Sha256Digest,
    ) -> Result<TargetRuntimeRules, DomainError> {
        Ok(TargetRuntimeRules {
            native_compute_26_3: true,
            checked_numeric_and_success: true,
            data_pack_26_3: true,
        })
    }
}
fn source_only_target() -> VerifiedTarget {
    let mut profile = example(include_bytes!("../../../examples/version-profile.json"));
    profile["validationStatus"] = json!("runtime_verified");
    profile["writeSupport"] = json!("verified");
    profile["artifactSha256"] = json!("11".repeat(32));
    profile["javaMajor"] = json!(25);
    profile["testedLoaders"] = json!(["authored-source-test-only"]);
    profile["evidenceResourceIds"] = json!(["authored-source-test-only"]);
    VerifiedTarget::verify(&profile, &AuthoredTarget).unwrap()
}
struct BlockOnlyRegistry;
impl SceneRegistryVerifier for BlockOnlyRegistry {
    fn verify_codec(
        &self,
        _: &VerifiedTarget,
        _: &Sha256Digest,
    ) -> Result<SceneCodecCapabilities, DomainError> {
        Ok(SceneCodecCapabilities {
            static_affine_display: false,
            text_background_geometry: false,
            staged_command_blocks: false,
            scoped_state: false,
            resource_pack_assets: false,
        })
    }
    fn verify_encoded(
        &self,
        _: &VerifiedTarget,
        _: &Sha256Digest,
        instruction: &NativeSceneInstruction,
        _command: &str,
    ) -> Result<(), DomainError> {
        if matches!(instruction, NativeSceneInstruction::Block { .. }) {
            Ok(())
        } else {
            Err(DomainError::new(
                "TEST_CODEC_UNSUPPORTED",
                "Only direct blocks are covered by this source-only witness",
            ))
        }
    }
    fn display_payload(
        &self,
        _: &VerifiedTarget,
        _: &Display,
    ) -> Result<BTreeMap<String, Value>, DomainError> {
        Err(DomainError::new(
            "TEST_CODEC_UNSUPPORTED",
            "No display witness",
        ))
    }
    fn block_state(
        &self,
        _: &VerifiedTarget,
        state: &SceneBlockState,
        turns: i32,
    ) -> Result<SceneBlockState, DomainError> {
        if turns == 0 {
            Ok(state.clone())
        } else {
            Err(DomainError::new(
                "TEST_CODEC_UNSUPPORTED",
                "No rotated native state witness",
            ))
        }
    }
    fn resolve_command(
        &self,
        _: &VerifiedTarget,
        _: &CommandModule,
        _: &CommandNode,
        _: &Prefab,
        _: &Instance,
        _: &Matrix4,
        _: &BTreeMap<StateId, SceneStateBinding>,
    ) -> Result<ResolvedSceneCommand, DomainError> {
        Err(DomainError::new(
            "TEST_CODEC_UNSUPPORTED",
            "No command witness",
        ))
    }
    fn asset_path(
        &self,
        _: &VerifiedTarget,
        _: &Value,
        _: &SceneResource,
    ) -> Result<Option<String>, DomainError> {
        Err(DomainError::new(
            "TEST_CODEC_UNSUPPORTED",
            "No asset witness",
        ))
    }
    fn resource_media(
        &self,
        _: &VerifiedTarget,
        declared: &ResourceRef,
        stored: &ResourceRef,
    ) -> Result<(), DomainError> {
        if declared.media_type == stored.media_type {
            Ok(())
        } else {
            Err(DomainError::new(
                "TEST_CODEC_UNSUPPORTED",
                "No media alias witness",
            ))
        }
    }
}

/// The original example contains displays, state and many block cells which
/// would obscure a one-cell delta regression. This derived in-memory source
/// retains its canonical DTOs and one original blockset cell; no fixture file
/// or runtime acceptance record is created.
fn block_scene(block: &str, origin_x: i32) -> (SceneDraft, Value, Value, Value) {
    let mut blockset = example(include_bytes!("../../../examples/blockset.json"));
    blockset["cells"] = json!([blockset["cells"][0].clone()]);
    blockset["palette"][0]["blockId"] = json!(block);
    let bytes = encode_json(&blockset).unwrap();
    let resource = ResourceRef {
        resource_id: ResourceId::new("resource-wall-blocks").unwrap(),
        sha256: raw_digest(&bytes),
        media_type: "application/json".into(),
        size_bytes: bytes.len() as u64,
    };
    let mut prefab = example(include_bytes!("../../../examples/prefab.json"));
    prefab["nodes"]
        .as_array_mut()
        .unwrap()
        .retain(|node| node["nodeId"] == "root" || node["nodeId"] == "shell");
    prefab["nodes"][1]["blockGeometry"]["bounds"] = json!({"min":[0,0,0],"maxExclusive":[1,1,1]});
    for field in ["ports", "state", "commandModuleIds", "clipIds"] {
        prefab[field] = json!([]);
    }
    prefab["resources"] = json!([resource]);
    revise("Prefab", &mut prefab);
    let mut instance = example(include_bytes!("../../../examples/instance.json"));
    instance["prefabRevision"] = prefab["revision"].clone();
    instance["placement"]["translation"][0] = json!(origin_x);
    revise("Instance", &mut instance);
    let mut project = example(include_bytes!("../../../examples/project.json"));
    project["prefabIds"] = json!([prefab["prefabId"]]);
    project["instanceIds"] = json!([instance["instanceId"]]);
    project["resourceIds"] = json!([resource.resource_id]);
    project["ownedResources"] = json!([
        {"kind":"prefab","objectId":prefab["prefabId"],"revision":prefab["revision"]},
        {"kind":"instance","objectId":instance["instanceId"],"revision":instance["revision"]}]);
    revise("Project", &mut project);
    let draft = scene_lower(
        &source_only_target(),
        SceneBuildInputs::new(
            project.clone(),
            vec![prefab.clone()],
            vec![instance.clone()],
            vec![],
            vec![],
            vec![SceneResource {
                reference: resource,
                bytes,
            }],
        ),
        &Native26_3SceneCodec,
        &BlockOnlyRegistry,
    )
    .unwrap();
    (draft, project, prefab, instance)
}

#[test]
fn static_owned_pack_uses_only_sealed_scene_coverage() {
    let (draft, project, _, _) = block_scene("minecraft:stone", 128);
    let request = |project: &Value| {
        json!({"contextId":"static-pack-context","projectId":project["projectId"],
            "expectedRevision":project["revision"],"targetProfileId":project["targetProfileId"],
            "outputPolicy":"private_staging_only"})
    };
    let pack = mmmm_compiler::pack_build(
        &request(&project),
        &source_only_target(),
        static_scene_pack_inputs(&project, draft),
    )
    .unwrap();
    // This existing authored fixture verifies the production coverage adapter,
    // not a live target, pack installation, reload or world execution.
    assert_eq!(pack.manifest().validation_stage, "statically_checked");
    assert!(pack.manifest().entry_points.contains_key("scene_stage"));
    for (case, expected) in [
        ("missing", "UNOWNED_REQUIRED_CAPABILITY"),
        ("extra", "UNOWNED_REQUIRED_CAPABILITY"),
        ("stale", "REVISION_CONFLICT"),
    ] {
        let (draft, mut changed, _, _) = block_scene("minecraft:stone", 128);
        match case {
            "missing" => {
                changed["ownedResources"].as_array_mut().unwrap().remove(0);
            }
            "extra" => changed["ownedResources"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "kind":"asset","objectId":"unlowered-asset","revision":"ab".repeat(32)
                })),
            "stale" => changed["ownedResources"][0]["revision"] = json!("ab".repeat(32)),
            _ => unreachable!(),
        }
        revise("Project", &mut changed);
        assert_eq!(
            mmmm_compiler::pack_build(
                &request(&changed),
                &source_only_target(),
                static_scene_pack_inputs(&changed, draft),
            )
            .unwrap_err()
            .code,
            expected,
            "{case} owned coverage must retain the existing compiler rejection"
        );
    }
}

/// Existing canonical Prefab/Instance/Clip examples are reduced in memory to
/// one display and two placements. The block fixture cannot exercise per-
/// instance display UUID/origin joins; no new source fixture or proof is stored.
fn animated_scene(
    instances: usize,
    mutate_clip: impl FnOnce(&mut Value),
) -> (ProjectCatalog, Vec<Value>, SceneDraft) {
    let mut prefab = example(include_bytes!("../../../examples/prefab.json"));
    prefab["nodes"]
        .as_array_mut()
        .unwrap()
        .retain(|node| node["nodeId"] == "root" || node["nodeId"] == "door");
    for field in [
        "ports",
        "state",
        "references",
        "commandModuleIds",
        "resources",
    ] {
        prefab[field] = json!([]);
    }
    prefab["clipIds"] = json!(["clip-door"]);
    revise("Prefab", &mut prefab);
    let mut clip = example(include_bytes!("../../../examples/animation-clip.json"));
    mutate_clip(&mut clip);
    revise("AnimationClip", &mut clip);
    let mut placements = Vec::new();
    for index in 0..instances {
        let mut instance = example(include_bytes!("../../../examples/instance.json"));
        instance["instanceId"] = json!(format!("instance-animation-{index}"));
        instance["prefabRevision"] = prefab["revision"].clone();
        instance["placement"]["translation"][0] = json!(index * 16);
        revise("Instance", &mut instance);
        placements.push(instance);
    }
    let mut project = example(include_bytes!("../../../examples/project.json"));
    project["prefabIds"] = json!([prefab["prefabId"]]);
    project["instanceIds"] = json!(
        placements
            .iter()
            .map(|value| value["instanceId"].clone())
            .collect::<Vec<_>>()
    );
    project["resourceIds"] = json!([]);
    let mut pins = vec![
        json!({"kind":"prefab","objectId":prefab["prefabId"],"revision":prefab["revision"]}),
        json!({"kind":"clip","objectId":clip["clipId"],"revision":clip["revision"]}),
    ];
    pins.extend(placements.iter().map(|value| json!({"kind":"instance","objectId":value["instanceId"],"revision":value["revision"]})));
    project["ownedResources"] = json!(pins);
    revise("Project", &mut project);
    let scene = scene_lower(
        &source_only_target(),
        SceneBuildInputs::new(
            project.clone(),
            vec![prefab.clone()],
            placements.clone(),
            vec![],
            vec![],
            vec![],
        ),
        &Native26_3SceneCodec,
        &DisplaySourceRegistry,
    )
    .unwrap();
    let mut owned = vec![prefab, clip];
    owned.extend(placements);
    (
        ProjectCatalog::from_project(&project).unwrap(),
        owned,
        scene,
    )
}

struct DisplaySourceRegistry;
impl SceneRegistryVerifier for DisplaySourceRegistry {
    fn verify_codec(
        &self,
        _: &VerifiedTarget,
        _: &Sha256Digest,
    ) -> Result<SceneCodecCapabilities, DomainError> {
        Ok(SceneCodecCapabilities {
            static_affine_display: true,
            text_background_geometry: false,
            staged_command_blocks: false,
            scoped_state: false,
            resource_pack_assets: false,
        })
    }
    fn verify_encoded(
        &self,
        _: &VerifiedTarget,
        _: &Sha256Digest,
        instruction: &NativeSceneInstruction,
        _: &str,
    ) -> Result<(), DomainError> {
        if matches!(
            instruction,
            NativeSceneInstruction::Display { .. } | NativeSceneInstruction::DisplayRemove { .. }
        ) {
            Ok(())
        } else {
            Err(DomainError::new(
                "TEST_CODEC_UNSUPPORTED",
                "Only authored display instructions are covered",
            ))
        }
    }
    fn display_payload(
        &self,
        _: &VerifiedTarget,
        display: &Display,
    ) -> Result<BTreeMap<String, Value>, DomainError> {
        Ok(display
            .payload
            .iter()
            .map(|(key, value)| {
                (
                    if key == "blockState" {
                        "block_state".into()
                    } else {
                        key.clone()
                    },
                    value.clone(),
                )
            })
            .collect())
    }
    fn block_state(
        &self,
        target: &VerifiedTarget,
        state: &SceneBlockState,
        turns: i32,
    ) -> Result<SceneBlockState, DomainError> {
        BlockOnlyRegistry.block_state(target, state, turns)
    }
    fn resolve_command(
        &self,
        target: &VerifiedTarget,
        module: &CommandModule,
        node: &CommandNode,
        prefab: &Prefab,
        instance: &Instance,
        matrix: &Matrix4,
        state: &BTreeMap<StateId, SceneStateBinding>,
    ) -> Result<ResolvedSceneCommand, DomainError> {
        BlockOnlyRegistry.resolve_command(target, module, node, prefab, instance, matrix, state)
    }
    fn asset_path(
        &self,
        target: &VerifiedTarget,
        value: &Value,
        resource: &SceneResource,
    ) -> Result<Option<String>, DomainError> {
        BlockOnlyRegistry.asset_path(target, value, resource)
    }
    fn resource_media(
        &self,
        target: &VerifiedTarget,
        declared: &ResourceRef,
        stored: &ResourceRef,
    ) -> Result<(), DomainError> {
        BlockOnlyRegistry.resource_media(target, declared, stored)
    }
}

/// Authored verifier doubles remain confined to this source-boundary module.
/// They never enter ProductionFactory or attest real artifacts/UUIDs/game state.
struct AuthoredAnimationCall {
    reject: &'static str,
    interrupted: Cell<bool>,
    snapshots: Cell<usize>,
}
impl AuthoredAnimationCall {
    fn new(reject: &'static str) -> Self {
        Self {
            reject,
            interrupted: Cell::new(false),
            snapshots: Cell::new(0),
        }
    }
}
impl AnimationBindingVerifier for AuthoredAnimationCall {
    fn verify_animation_bindings(
        &self,
        _: &ResourceRef,
        bytes: &[u8],
        _: &AnimationBindings,
    ) -> Result<Sha256Digest, DomainError> {
        if self.reject == "binding" {
            Err(DomainError::new(
                "BINDING_UNVERIFIED",
                "Authored binding oracle refused",
            ))
        } else {
            Ok(raw_digest(bytes))
        }
    }
}
impl AnimationEvidenceVerifier for AuthoredAnimationCall {
    fn verify_animation_target(
        &self,
        _: &Sha256Digest,
        _: &Sha256Digest,
    ) -> Result<AnimationTargetRules, DomainError> {
        if self.reject == "target-and-cancel" {
            self.interrupted.set(true);
            return Err(DomainError::new(
                "ACTUAL_TARGET_ERROR",
                "Authored target refused before cancellation",
            ));
        }
        if self.reject == "target" {
            return Err(DomainError::new(
                "TARGET_UNVERIFIED",
                "Authored target oracle refused",
            ));
        }
        Ok(AnimationTargetRules {
            row_major_f32_matrix_codec: true,
            explicit_zero_disables_interpolation: true,
            sampled_linear_trs_whole_interval: true,
        })
    }
    fn verify_linear_interval(
        &self,
        _: &VerifiedTarget,
        _: &Sha256Digest,
        _: &Sha256Digest,
        _: &Sha256Digest,
        _: &RationalTime,
    ) -> Result<(), DomainError> {
        if self.reject == "interval" {
            Err(DomainError::new(
                "UNSUPPORTED_TRANSFORM",
                "Authored interval oracle refused",
            ))
        } else {
            Ok(())
        }
    }
}
impl NativeAnimationCall for AuthoredAnimationCall {
    fn check_current(&self) -> AppResult<()> {
        Ok(())
    }
    fn settings(&self) -> AppResult<AnimationCompileSettings> {
        Ok(AnimationCompileSettings {
            target_tps: RationalTime::from_integer(if self.reject == "tps" { 60 } else { 20 }),
            max_component_error: 1e-6,
            max_catchup_ticks: 8,
            max_catchup_events: 4096,
        })
    }
    fn event_bindings(
        &self,
        _: &mmmm_domain::time::AnimationClip,
    ) -> AppResult<BTreeMap<SymbolId, AnimationEventBinding>> {
        if self.reject == "source-and-cancel" {
            self.interrupted.set(true);
            return Err(AppError::new(
                "ACTUAL_SOURCE_ERROR",
                "Authored source refused before cancellation",
            ));
        }
        if self.reject == "event-invalid" || self.reject == "metadata" {
            let bytes = b"return 1\n".to_vec();
            let mut source = mmmm_compiler::StagedResource {
                reference: ResourceRef {
                    resource_id: ResourceId::new("authored-event-source").unwrap(),
                    sha256: raw_digest(&bytes),
                    media_type: "text/x-mcfunction; charset=utf-8".into(),
                    size_bytes: bytes.len() as u64,
                },
                bytes,
            };
            if self.reject == "event-invalid" {
                source.reference.sha256 = Sha256Digest::from_bytes([0; 32]);
            }
            return Ok(BTreeMap::from([(
                SymbolId::new("event-function").unwrap(),
                AnimationEventBinding {
                    function: ResourceLocation::new("fixture:authored_event").unwrap(),
                    source,
                    contract: mmmm_compiler::GeneratedFunctionContract {
                        inputs: vec![],
                        outputs: vec![],
                        state_reads: vec![],
                        state_writes: vec![],
                        execution_context: "server",
                        reentrancy: "non_reentrant",
                        scheduled_callbacks: vec![],
                        cleanup: vec![],
                        requirements: if self.reject == "metadata" {
                            vec!["x".repeat(8 * 1024 * 1024 + 1)]
                        } else {
                            vec![]
                        },
                    },
                },
            )]));
        }
        Ok(BTreeMap::new())
    }
    fn binding_snapshot(&self, _: &AnimationBindings, bytes: &[u8]) -> AppResult<ResourceRef> {
        self.snapshots.set(self.snapshots.get() + 1);
        Ok(ResourceRef {
            resource_id: ResourceId::new(format!(
                "source-test-binding-{}",
                &raw_digest(bytes).as_str()[..16]
            ))
            .unwrap(),
            sha256: if self.reject == "snapshot" {
                Sha256Digest::from_bytes([0; 32])
            } else {
                raw_digest(bytes)
            },
            media_type: "application/json".into(),
            size_bytes: bytes.len() as u64,
        })
    }
}

#[test]
fn owned_animation_assembler_preserves_two_exact_instance_bindings_without_runtime_claims() {
    let (project, owned, scene) = animated_scene(2, |_| {});
    assert_ne!(
        scene.animation_bindings().values().next().unwrap().nodes
            [&mmmm_contracts::NodeId::new("door").unwrap()]
            .display_uuid,
        scene.animation_bindings().values().nth(1).unwrap().nodes
            [&mmmm_contracts::NodeId::new("door").unwrap()]
            .display_uuid
    );
    let inputs = assemble_owned_animations(
        &project,
        &owned,
        scene,
        &source_only_target(),
        &AuthoredAnimationCall::new(""),
        &|| Ok(()),
    )
    .unwrap();
    let request = json!({"contextId":"animation-source-context","projectId":project.project_id(),"expectedRevision":project.revision(),"targetProfileId":project.target_profile_id(),"outputPolicy":"private_staging_only"});
    let pack = mmmm_compiler::pack_build(&request, &source_only_target(), inputs).unwrap();
    assert_eq!(pack.manifest().validation_stage, "statically_checked");
    assert_eq!(
        pack.manifest()
            .entry_points
            .keys()
            .filter(|key| key.starts_with("clip_"))
            .count(),
        18
    );
    assert!(
        pack.manifest()
            .runtime_dependencies
            .iter()
            .any(|value| value == "mmmm:animation_tick_dispatch")
    );
}

#[test]
fn owned_animation_assembler_refuses_missing_duplicate_stale_and_uninstantiated_sources() {
    for case in ["missing", "duplicate", "stale", "uninstantiated"] {
        let (project, mut owned, scene) =
            animated_scene(if case == "uninstantiated" { 0 } else { 1 }, |_| {});
        match case {
            "missing" => {
                owned.remove(1);
            }
            "duplicate" => owned.push(owned[1].clone()),
            "stale" => {
                owned[1]["duration"] = json!({"numerator":"3","denominator":"1"});
                revise("AnimationClip", &mut owned[1]);
            }
            _ => {}
        }
        assert!(
            assemble_owned_animations(
                &project,
                &owned,
                scene,
                &source_only_target(),
                &AuthoredAnimationCall::new(""),
                &|| Ok(())
            )
            .is_err(),
            "{case} cannot omit an actual owned clip"
        );
    }
}

#[test]
fn owned_animation_assembler_keeps_each_independent_verifier_and_original_failure() {
    for (case, expected) in [
        ("binding", "BINDING_UNVERIFIED"),
        ("target", "TARGET_UNVERIFIED"),
        ("interval", "UNSUPPORTED_TRANSFORM"),
        ("snapshot", "RESOURCE_DIGEST_MISMATCH"),
        ("tps", "STALE_CONTEXT"),
    ] {
        let (project, owned, scene) = animated_scene(1, |_| {});
        assert_eq!(
            assemble_owned_animations(
                &project,
                &owned,
                scene,
                &source_only_target(),
                &AuthoredAnimationCall::new(case),
                &|| Ok(())
            )
            .unwrap_err()
            .code,
            expected
        );
    }
    let (project, owned, scene) = animated_scene(1, |clip| {
        clip["events"] = json!([{"eventId":"event-required","at":{"numerator":"1","denominator":"1"},"functionSymbolId":"event-function","scrubPolicy":"suppress","authoredSequence":0}]);
    });
    assert_eq!(
        assemble_owned_animations(
            &project,
            &owned,
            scene,
            &source_only_target(),
            &AuthoredAnimationCall::new(""),
            &|| Ok(())
        )
        .unwrap_err()
        .code,
        "REFERENCE_UNRESOLVED"
    );
    for (case, expected) in [
        ("event-invalid", "RESOURCE_DIGEST_MISMATCH"),
        ("metadata", "RESOURCE_BUDGET_EXCEEDED"),
    ] {
        let (project, owned, scene) = animated_scene(1, |clip| {
            clip["events"] = json!([{"eventId":"event-required","at":{"numerator":"1","denominator":"1"},"functionSymbolId":"event-function","scrubPolicy":"suppress","authoredSequence":0}]);
        });
        let call = AuthoredAnimationCall::new(case);
        assert_eq!(
            assemble_owned_animations(
                &project,
                &owned,
                scene,
                &source_only_target(),
                &call,
                &|| Ok(())
            )
            .unwrap_err()
            .code,
            expected
        );
        assert_eq!(
            call.snapshots.get(),
            0,
            "Invalid source/metadata must fail before private snapshot staging"
        );
    }
    for (case, expected) in [
        ("source-and-cancel", "ACTUAL_SOURCE_ERROR"),
        ("target-and-cancel", "ACTUAL_TARGET_ERROR"),
    ] {
        let (project, owned, scene) = animated_scene(1, |_| {});
        let call = AuthoredAnimationCall::new(case);
        let error = assemble_owned_animations(
            &project,
            &owned,
            scene,
            &source_only_target(),
            &call,
            &|| {
                if call.interrupted.get() {
                    Err(AppError::new(
                        "DEADLINE_EXCEEDED",
                        "Original checkpoint expired",
                    ))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert_eq!(error.code, expected);
        let cause = std::error::Error::source(&error).unwrap().to_string();
        assert!(cause.contains(expected) && cause.contains("DEADLINE_EXCEEDED"));
    }
}

#[test]
fn changed_block_uses_one_exact_stage_delta_and_loaded_subject_pair() {
    let (before, _, _, instance) = block_scene("minecraft:stone", 128);
    let (after, _, _, _) = block_scene("minecraft:dirt", 128);
    let affected =
        BTreeSet::from([InstanceId::new(instance["instanceId"].as_str().unwrap()).unwrap()]);
    let selected = select_stage_delta(&before, &after, &affected).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].phase(), SceneLifecyclePhase::Stage);
    assert_eq!(
        selected[0].encoded_commands(),
        ["execute in minecraft:overworld run setblock 128 64 128 minecraft:dirt"]
    );
    let selectors = selectors_for_steps(&selected).unwrap();
    assert_eq!(selectors.len(), 2);
    assert!(
        selectors
            .iter()
            .any(|selector| selector.kind() == "block_state")
    );
    assert!(
        selectors
            .iter()
            .any(|selector| selector.kind() == "block_entity")
    );
    for selector in selectors {
        assert_eq!(selector.value()["position"], json!([128, 64, 128]));
    }
}

#[test]
fn moved_target_requires_cleanup_and_unchanged_scene_is_not_an_apply() {
    let (before, _, _, instance) = block_scene("minecraft:stone", 128);
    let (moved, _, _, _) = block_scene("minecraft:stone", 129);
    let affected =
        BTreeSet::from([InstanceId::new(instance["instanceId"].as_str().unwrap()).unwrap()]);
    assert_eq!(
        select_stage_delta(&before, &moved, &affected)
            .err()
            .unwrap()
            .code,
        "NATIVE_CLEANUP_REQUIRED"
    );
    assert_eq!(
        select_stage_delta(&before, &before, &affected)
            .err()
            .unwrap()
            .code,
        "NATIVE_DELTA_UNSUPPORTED"
    );
}

#[test]
fn metadata_routes_cannot_be_attributed_to_the_java_platform_jar() {
    for kind in [
        NativeKind::ClipRetime,
        NativeKind::PackBuild,
        NativeKind::ResourcePatch,
        NativeKind::Recovery,
    ] {
        assert!(world_route(kind).is_none());
    }
    assert_eq!(
        world_route(NativeKind::CommandPatch),
        Some(("mmmm:authored/command_patch", "mmmm:command_module_patch"))
    );
    assert_eq!(
        world_route(NativeKind::ScenePatch),
        Some(("mmmm:authored/scene_patch", "mmmm:scene_import_patch"))
    );
}

#[test]
fn current_project_sources_cannot_be_dropped_or_replaced_at_another_revision() {
    let (_, project, _, instance) = block_scene("minecraft:stone", 128);
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    let values: Vec<_> = catalog
        .pins()
        .iter()
        .map(|pin| {
            let value = if pin.kind == OwnedKind::Instance {
                instance.clone()
            } else {
                let (_, _, prefab, _) = block_scene("minecraft:stone", 128);
                prefab
            };
            (pin.clone(), value)
        })
        .collect();
    let mut change = PreparedNativeChange {
        format: "mmmm.prepared-native-change/1".into(),
        kind: NativeKind::Relocate,
        project_id: catalog.project_id().clone(),
        project_base_revision: catalog.revision().clone(),
        target_profile_id: catalog.target_profile_id().clone(),
        project_after: project.clone(),
        document_changes: vec![],
        world_projection: vec![],
        resource_replacements: vec![],
        recovery_replacements: vec![],
        source_object_pins: vec![],
        source_resource_pins: vec![],
        staged_resources: vec![],
        scene_patch: None,
        pack_manifest: None,
        loss_records: vec![],
    };
    assert_eq!(
        apply_document_changes(&catalog, &change, &values)
            .unwrap()
            .len(),
        2
    );
    change.project_after["instanceIds"] = json!([]);
    change.project_after["ownedResources"]
        .as_array_mut()
        .unwrap()
        .retain(|pin| pin["kind"] != "instance");
    revise("Project", &mut change.project_after);
    assert_eq!(
        apply_document_changes(&catalog, &change, &values)
            .err()
            .unwrap()
            .code,
        "STALE_CONTEXT"
    );
    change.project_after = project;
    let revision = Sha256Digest::new(instance["revision"].as_str().unwrap()).unwrap();
    change.document_changes.push(mmmm_planner::DocumentChange {
        kind: OwnedKind::Instance,
        object_id: instance["instanceId"].as_str().unwrap().into(),
        before_revision: Some(Sha256Digest::new("ab".repeat(32)).unwrap()),
        after_revision: revision,
        after: instance,
    });
    assert_eq!(
        apply_document_changes(&catalog, &change, &values)
            .err()
            .unwrap()
            .code,
        "STALE_CONTEXT"
    );
}

#[test]
fn selectors_never_guess_a_storage_resource_identity() {
    let instruction = NativeSceneInstruction::StateRemove {
        storage: ResourceLocation::new("mmmm:test").unwrap(),
        key: "x".into(),
        storage_kind: "storage_nbt".into(),
        objective: "x".into(),
        holder: "x".into(),
    };
    assert_eq!(
        instruction_selectors(&instruction).err().unwrap().code,
        "NATIVE_SOURCE_MAPPING_REQUIRED"
    );
}

#[test]
fn contradictory_resource_aliases_cannot_choose_a_desired_source() {
    let digest = raw_digest(b"original");
    let resource = json!({"resourceId":"exact-source","sha256":digest,"mediaType":"application/json","sizeBytes":8.0});
    let mut pins = BTreeMap::new();
    collect_resources(&resource, &mut pins, 0).unwrap();
    assert_eq!(
        pins[&ResourceId::new("exact-source").unwrap()].size_bytes,
        8
    );
    let mut conflicting = resource;
    conflicting["sha256"] = json!(raw_digest(b"replacement"));
    assert_eq!(
        collect_resources(&conflicting, &mut pins, 0)
            .err()
            .unwrap()
            .code,
        "STALE_CONTEXT"
    );
}

/// The existing canonical DTOs are enough for these closed decoder boundaries.
/// This in-memory response is factual test input, never pairing, source approval,
/// a runtime profile, actual native readback or game acceptance evidence.
fn direct_block_receipt() -> (Value, Value, block_footprint::SourcePins) {
    let context = example(include_bytes!("../../../examples/execution-context.json"));
    let pins = block_footprint::SourcePins {
        host: raw_digest(b"own-host-artifact-test-only"),
        source_facts: raw_digest(b"actual-source-facts-test-only"),
    };
    let mut cells = Vec::new();
    for y in -1..=1 {
        for z in -1..=1 {
            for x in -1..=1 {
                cells.push(json!({"position":[x,64+y,z],"state":{"blockId":"minecraft:air","properties":{}},
            "registryIdentity":"vanilla_air","blockEntityAbsent":true,"fluidEmpty":true}));
            }
        }
    }
    let mut receipt = json!({"format":"mmmm.owned-block-footprint/1","status":"known","reasonCode":null,
        "producerId":"mmmm:vanilla_air_stone_direct_block_patch/v1","hostArtifactDigest":pins.host,
        "implementationDigest":pins.host,"profileDigest":block_footprint::direct_profile(&pins.host).unwrap(),
        "runtimeSourceFactsDigest":pins.source_facts,"registryGeneration":"7","contextDigest":context["contextDigest"],
        "dimension":"minecraft:overworld","position":[0,64,0],
        "expectedState":{"blockId":"minecraft:air","properties":{}},
        "desiredState":{"blockId":"minecraft:stone","properties":{}},"observedFromTick":"100","observedToTick":"100",
        "cells":cells,"conditionsDigest":null,"directCoverage":"block_state_cells","indirectEffects":"not_observed",
        "exactUndoSupported":false,"lossCode":"INDIRECT_ENGINE_EFFECTS_EXCLUDED",
        "limitations":["conservative_3x3x3_fence_only","entity_poi_lighting_neighbor_effects_not_observed",
            "indirect_effect_recovery_not_guaranteed","exact_undo_not_supported"]});
    revise_direct_conditions(&mut receipt);
    (receipt, context, pins)
}
fn direct_block_arguments(receipt: &Value) -> Value {
    json!({"dimension":receipt["dimension"],"position":receipt["position"],
        "expectedState":receipt["expectedState"],"desiredState":receipt["desiredState"],"expectedRegistryGeneration":receipt["registryGeneration"]})
}
fn revise_direct_conditions(receipt: &mut Value) {
    let mut stable = receipt.clone();
    let fields = stable.as_object_mut().unwrap();
    for field in ["observedFromTick", "observedToTick", "conditionsDigest"] {
        fields.remove(field);
    }
    receipt["conditionsDigest"] = json!(canonical_digest(&stable).unwrap());
}

#[test]
fn direct_block_receipt_binds_current_pins_and_preserves_indirect_limitations() {
    let (receipt, context, pins) = direct_block_receipt();
    let arguments =
        block_footprint::BlockArguments::decode(&direct_block_arguments(&receipt)).unwrap();
    assert!(block_footprint::decode_receipt(&receipt, &arguments, &pins, &context).is_ok());
    for field in [
        "contextDigest",
        "runtimeSourceFactsDigest",
        "hostArtifactDigest",
        "implementationDigest",
    ] {
        let mut changed = receipt.clone();
        changed[field] = json!(raw_digest(b"different-current-source"));
        revise_direct_conditions(&mut changed);
        assert_eq!(
            block_footprint::decode_receipt(&changed, &arguments, &pins, &context)
                .err()
                .unwrap()
                .code,
            "STALE_CONTEXT"
        );
    }
    for (field, value) in [
        ("exactUndoSupported", json!(true)),
        ("indirectEffects", json!("complete")),
        ("directCoverage", json!("all_engine_effects")),
        ("limitations", json!([])),
    ] {
        let mut changed = receipt.clone();
        changed[field] = value;
        revise_direct_conditions(&mut changed);
        assert!(block_footprint::decode_receipt(&changed, &arguments, &pins, &context).is_err());
    }
    let loss = block_footprint::direct_limitation();
    validate("LossRecord", &loss).unwrap();
    assert_eq!(loss["disposition"], "dropped");
    assert_eq!(loss["severity"], "warning");
    assert_eq!(loss["approvalRequired"], true);
}

#[test]
fn direct_block_receipt_rejects_reordered_cells_unknown_reasons_and_reconstructed_recipe() {
    let (receipt, context, pins) = direct_block_receipt();
    let arguments =
        block_footprint::BlockArguments::decode(&direct_block_arguments(&receipt)).unwrap();
    for variant in 0..5 {
        let mut changed = receipt.clone();
        match variant {
            0 => changed["cells"].as_array_mut().unwrap().swap(0, 1),
            1 => changed["cells"][0]["fluidEmpty"] = json!(false),
            2 => changed["profileDigest"] = json!(raw_digest(b"caller-reconstructed-profile")),
            3 => changed["cells"][0]["registryIdentity"] = json!("caller_air_alias"),
            _ => {
                changed["extraGrant"] = json!(true);
            }
        }
        revise_direct_conditions(&mut changed);
        assert!(block_footprint::decode_receipt(&changed, &arguments, &pins, &context).is_err());
    }
    let mut unsupported = receipt;
    unsupported["status"] = json!("unsupported");
    unsupported["cells"] = json!([]);
    unsupported["conditionsDigest"] = Value::Null;
    unsupported["reasonCode"] = json!("OWNED_BLOCK_NEIGHBOR_NOT_AIR");
    assert_eq!(
        block_footprint::decode_receipt(&unsupported, &arguments, &pins, &context)
            .err()
            .unwrap()
            .code,
        "CAPABILITY_UNAVAILABLE"
    );
    unsupported["reasonCode"] = json!("PERMISSION_DENIED");
    assert_eq!(
        block_footprint::decode_receipt(&unsupported, &arguments, &pins, &context)
            .err()
            .unwrap()
            .code,
        "INVALID_INPUT"
    );
}

#[test]
fn direct_block_arguments_are_closed_and_neighbors_never_wrap_int32() {
    let (receipt, _, _) = direct_block_receipt();
    let args = direct_block_arguments(&receipt);
    for invalid_position in [
        json!([i32::MIN, 64, 0]),
        json!([i32::MAX, 64, 0]),
        json!([0, 64.5, 0]),
    ] {
        let mut changed = args.clone();
        changed["position"] = invalid_position;
        assert!(block_footprint::BlockArguments::decode(&changed).is_err());
    }
    let mut extra = args.clone();
    extra["producerId"] = receipt["producerId"].clone();
    assert!(block_footprint::BlockArguments::decode(&extra).is_err());
    let mut generation = args;
    generation["expectedRegistryGeneration"] = json!("007");
    assert!(block_footprint::BlockArguments::decode(&generation).is_err());
}

#[test]
fn direct_block_readiness_requires_actual_builtin_source_and_current_descriptor() {
    let (receipt, context, pins) = direct_block_receipt();
    let mut provider = example(include_bytes!("../../../examples/provider-supported.json"));
    provider["providerId"] = json!("mmmm:native");
    provider["origin"] = json!({"kind":"builtin","sourceId":"mmmm_host","sourceDigest":pins.host});
    provider["environment"] = context["environment"].clone();
    let action = &mut provider["actions"][0];
    action["actionId"] = json!("mmmm:block_patch");
    action["semanticKind"] = json!("mmmm:block_state_patch");
    action["effect"] = json!("write");
    action["verificationRequirement"] = json!("independent_readback");
    action["requiredPermissions"] = json!(["mmmm:world_write"]);
    action["implementationDigest"] = json!(pins.host);
    action["inputSchema"] = json!({"type":"object","additionalProperties":false,
        "required":["dimension","position","expectedState","desiredState","expectedRegistryGeneration"],
        "properties":{"dimension":{"type":"string"},"position":{"type":"array"},"expectedState":{"type":"object"},
            "desiredState":{"type":"object"},"expectedRegistryGeneration":{"type":"string"}}});
    action["outputSchema"] = json!({"type":"object","additionalProperties":false,
        "required":["kind","setBlockReportedSuccess","before","after","indirectEffects","knownProducerId","preflightPin",
            "directCoverage","exactUndoSupported","lossCode","limitations"],
        "properties":{"kind":{"const":"direct_block_state"},"indirectEffects":{"const":"not_observed"},
            "knownProducerId":{"const":receipt["producerId"]},"directCoverage":{"const":"block_state_cells"},
            "exactUndoSupported":{"const":false},"lossCode":{"const":receipt["lossCode"]},"limitations":{"const":receipt["limitations"]}}});
    let provider: mmmm_adapters::ProviderDescriptor = serde_json::from_value(provider).unwrap();
    let hello = json!({"hostBuild":pins.host,"environment":context["environment"],"gameVersion":"26.3","javaMajor":25,"loader":{"id":"fabric"}});
    assert_eq!(
        block_footprint::known_losses(&provider, &provider.actions[0], &hello, &context),
        Some(BTreeSet::from(["INDIRECT_ENGINE_EFFECTS_EXCLUDED".into()]))
    );
    let mut other = provider.clone();
    other.origin.source_id = "other_sdk_mod".into();
    assert!(block_footprint::known_losses(&other, &other.actions[0], &hello, &context).is_none());
    let mut other = provider.clone();
    other.actions[0].implementation_digest = raw_digest(b"another-implementation");
    assert!(block_footprint::known_losses(&other, &other.actions[0], &hello, &context).is_none());
    let mut other = provider;
    other.actions[0].output_schema["properties"]["exactUndoSupported"]["const"] = json!(true);
    assert!(block_footprint::known_losses(&other, &other.actions[0], &hello, &context).is_none());
}

#[test]
fn direct_block_host_failure_keeps_the_simultaneous_current_checkpoint_cause() {
    let result: AppResult<()> = block_footprint::finish(
        Err(error("NATIVE_OBSERVATION_FAILED", "Original host failure")),
        Err(error("TIME_BUDGET_EXCEEDED", "Original call ended")),
    );
    let failure = result.err().unwrap();
    assert_eq!(failure.code, "NATIVE_OBSERVATION_FAILED");
    let source = std::error::Error::source(&failure).unwrap();
    assert!(source.to_string().contains("TIME_BUDGET_EXCEEDED"));
    assert_eq!(
        source.source().unwrap().to_string(),
        "NATIVE_OBSERVATION_FAILED: Original host failure"
    );
}

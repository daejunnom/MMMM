//! Authored source-only witnesses. The original package has no compiler scene
//! draft, command activation bytes, quarter-turn cell output, or resource-pack
//! closure fixtures; these tests need explicit independent expected coordinates
//! and lifecycle ordering. They do not verify a Minecraft target or count as
//! visual, multiplayer, block-state rotation, or game acceptance evidence.

use super::*;
use crate::{TargetEvidenceVerifier, TargetRuntimeRules};
use mmmm_contracts::TargetProfileId;
use std::cell::Cell;

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
fn target() -> VerifiedTarget {
    let mut profile: Value =
        serde_json::from_slice(include_bytes!("../../../examples/version-profile.json")).unwrap();
    profile["validationStatus"] = json!("runtime_verified");
    profile["writeSupport"] = json!("verified");
    profile["artifactSha256"] = json!("11".repeat(32));
    profile["javaMajor"] = json!(25);
    profile["testedLoaders"] = json!(["authored-test-only"]);
    profile["evidenceResourceIds"] = json!(["authored-test-only"]);
    VerifiedTarget::verify(&profile, &AuthoredTarget).unwrap()
}

#[derive(Default)]
struct AuthoredRegistry {
    reject_codec: bool,
    reject_pose: bool,
    reject_rotation: bool,
    alter_opaque: bool,
    path: Option<String>,
    checked_lines: Cell<usize>,
    display_requests: Cell<usize>,
}
impl SceneRegistryVerifier for AuthoredRegistry {
    fn verify_codec(
        &self,
        _: &VerifiedTarget,
        _: &Sha256Digest,
    ) -> Result<SceneCodecCapabilities, DomainError> {
        if self.reject_codec {
            return Err(DomainError::new(
                "EVIDENCE_UNVERIFIED",
                "Authored evidence rejected",
            ));
        }
        Ok(SceneCodecCapabilities {
            static_affine_display: true,
            text_background_geometry: true,
            staged_command_blocks: true,
            scoped_state: true,
            resource_pack_assets: true,
        })
    }
    fn verify_encoded(
        &self,
        _: &VerifiedTarget,
        _: &Sha256Digest,
        instruction: &NativeSceneInstruction,
        _: &str,
    ) -> Result<(), DomainError> {
        if self.reject_pose && matches!(instruction, NativeSceneInstruction::DisplayPose { .. }) {
            return Err(DomainError::new(
                "EVIDENCE_UNVERIFIED",
                "Authored pose command witness rejected",
            ));
        }
        self.checked_lines.set(self.checked_lines.get() + 1);
        Ok(())
    }
    fn display_payload(
        &self,
        _: &VerifiedTarget,
        display: &Display,
    ) -> Result<BTreeMap<String, Value>, DomainError> {
        self.display_requests.set(self.display_requests.get() + 1);
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
        _: &VerifiedTarget,
        state: &SceneBlockState,
        turns: i32,
    ) -> Result<SceneBlockState, DomainError> {
        if self.reject_rotation && turns != 0 {
            return Err(DomainError::new(
                "EVIDENCE_UNVERIFIED",
                "No rotation witness",
            ));
        }
        Ok(state.clone())
    }
    fn resolve_command(
        &self,
        _: &VerifiedTarget,
        _: &CommandModule,
        command: &CommandNode,
        _: &Prefab,
        _: &Instance,
        _: &Matrix4,
        _: &BTreeMap<mmmm_contracts::StateId, SceneStateBinding>,
    ) -> Result<ResolvedSceneCommand, DomainError> {
        // This witness only knows the one authored fixture command; it is not
        // a general parser and cannot admit unknown arbitrary command source.
        let mut referenced = BTreeSet::new();
        let mut external = BTreeMap::new();
        if command.source == "function fixture:open" {
            let id = ResourceLocation::new("fixture:open").unwrap();
            referenced.insert(id.clone());
            external.insert(id, Sha256Digest::from_bytes([8; 32]));
        } else if command.parse_status != ParseStatus::Opaque {
            return Err(unresolved("Unknown authored fixture command"));
        }
        Ok(ResolvedSceneCommand {
            source: if self.alter_opaque {
                format!("{} changed", command.source)
            } else {
                command.source.clone()
            },
            referenced_functions: referenced,
            external_functions: external,
            state_reads: BTreeSet::new(),
            state_writes: BTreeSet::new(),
        })
    }
    fn asset_path(
        &self,
        _: &VerifiedTarget,
        _: &Value,
        _: &SceneResource,
    ) -> Result<Option<String>, DomainError> {
        Ok(self.path.clone())
    }
    fn resource_media(
        &self,
        _: &VerifiedTarget,
        _: &ResourceRef,
        _: &ResourceRef,
    ) -> Result<(), DomainError> {
        Ok(())
    }
}

/// Shared source-only fixture for pack/animation composition regressions. The
/// canonical project owns the actual original clip revision, while scene
/// lowering only seals its own per-instance node/UUID/origin projection.
pub(crate) fn animation_pack_fixture() -> (Value, SceneDraft) {
    animation_pack_fixture_at_tps(20)
}

pub(crate) fn animation_pose_registry(reject_pose: bool) -> impl SceneRegistryVerifier {
    AuthoredRegistry {
        reject_pose,
        ..AuthoredRegistry::default()
    }
}

pub(crate) fn animation_pack_fixture_at_tps(tps: i32) -> (Value, SceneDraft) {
    animation_pack_fixture_instances(tps, false)
}

pub(crate) fn animation_pack_fixture_two_instances() -> (Value, SceneDraft) {
    animation_pack_fixture_instances(20, true)
}

fn animation_pack_fixture_instances(tps: i32, two_instances: bool) -> (Value, SceneDraft) {
    let mut prefab = prefab_value();
    prefab["nodes"][1]["nodeId"] = json!("door");
    prefab["nodes"][1]["transform"] =
        json!({"kind":"trs","translation":[3,1,0],"rotationXyzw":[0,0,0,1],"scale":[1,1,1]});
    prefab["clipIds"] = json!(["clip-door"]);
    stamp("Prefab", &mut prefab);
    let instance = instance_value(&prefab);
    let mut instances = vec![instance];
    if two_instances {
        // The existing fixture has one instance; duplicate source identities
        // cannot exercise disjoint native pose ownership across two instances.
        let mut second = instances[0].clone();
        second["instanceId"] = json!("instance-shop-b");
        stamp("Instance", &mut second);
        instances.push(second);
    }
    let mut source = inputs(vec![prefab], instances, vec![], vec![], vec![]);
    let clip: Value =
        serde_json::from_slice(include_bytes!("../../../examples/animation-clip.json")).unwrap();
    source.project["ownedResources"]
        .as_array_mut()
        .unwrap()
        .push(json!({"kind":"clip","objectId":clip["clipId"],"revision":clip["revision"]}));
    source.project["gameTicksPerSecond"] = json!({"numerator":tps.to_string(),"denominator":"1"});
    stamp("Project", &mut source.project);
    let project = source.project.clone();
    (
        project,
        lower(source, &AuthoredRegistry::default()).unwrap(),
    )
}

#[test]
fn display_pose_codec_emits_one_closed_owned_uuid_merge_without_rounding_caller_values() {
    let instruction = NativeSceneInstruction::DisplayPose {
        dimension: ResourceLocation::new("minecraft:overworld").unwrap(),
        tag: "mmmm.fixture".into(),
        entity_kind: "block".into(),
        uuid: [0x11; 16],
        matrix: *Matrix4::identity().values(),
    };
    assert_eq!(
        Native26_3SceneCodec
            .encode_instruction(&instruction)
            .unwrap(),
        vec![
            "execute in minecraft:overworld as 11111111-1111-1111-1111-111111111111 if entity @s[type=minecraft:block_display,tag=mmmm.fixture] run data merge entity @s {transformation:[1f,0f,0f,0f,0f,1f,0f,0f,0f,0f,1f,0f,0f,0f,0f,1f],interpolation_duration:0,start_interpolation:0,teleport_duration:0}"
        ]
    );
    for invalid in [f64::NAN, f64::INFINITY, 1.1] {
        let mut changed = instruction.clone();
        let NativeSceneInstruction::DisplayPose { matrix, .. } = &mut changed else {
            unreachable!()
        };
        matrix[0] = invalid;
        assert_eq!(
            Native26_3SceneCodec
                .encode_instruction(&changed)
                .unwrap_err()
                .code,
            "NUMERIC_RANGE"
        );
    }
    for unowned in ["tag", "type"] {
        let mut changed = instruction.clone();
        let NativeSceneInstruction::DisplayPose {
            tag, entity_kind, ..
        } = &mut changed
        else {
            unreachable!()
        };
        if unowned == "tag" {
            *tag = "injected,tag=other".into();
        } else {
            *entity_kind = "armor_stand".into();
        }
        assert!(Native26_3SceneCodec.encode_instruction(&changed).is_err());
    }
}

#[test]
fn binding_projection_uses_the_same_explicit_uuid_and_origin_as_summon_output() {
    let (_, draft) = animation_pack_fixture();
    let binding = &draft.animation_bindings()[&InstanceId::new("instance-shop-a").unwrap()];
    let node = &binding.nodes[&mmmm_contracts::NodeId::new("door").unwrap()];
    assert_eq!(node.display_origin, [13.0, 21.0, 30.0]);
    assert_eq!(
        node.parent,
        Some(mmmm_contracts::NodeId::new("root").unwrap())
    );
    let uuid = node.display_uuid.as_ref().unwrap();
    assert_eq!(uuid.len(), 36);
    assert_eq!(&uuid[14..15], "8");
    let hex = uuid.replace('-', "");
    let bytes: Vec<_> = (0..16)
        .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
        .collect();
    let native = bytes
        .chunks_exact(4)
        .map(|chunk| i32::from_be_bytes(chunk.try_into().unwrap()).to_string())
        .collect::<Vec<_>>()
        .join(",");
    assert!(function(&draft, "stage").contains(&format!("UUID:[I;{native}]")));
    assert_eq!(
        draft.required_animation_bindings(),
        &BTreeSet::from([("instance-shop-a".into(), "clip-door".into())])
    );
}

#[test]
fn final_world_placement_rejects_cross_instance_chain_edges() {
    let (prefab, instance, mut module) = command_fixture();
    module["commands"].as_array_mut().unwrap().truncate(1);
    module["commands"][0]["kind"] = json!("chain");
    module["commands"][0]["nextId"] = Value::Null;
    module["physicalClearanceBlocks"] = json!(0);
    stamp("CommandModule", &mut module);
    let mut other = instance.clone();
    other["instanceId"] = json!("instance-shop-b");
    other["placement"]["translation"][0] = json!(11);
    stamp("Instance", &mut other);
    assert_eq!(
        lower(
            inputs(
                vec![prefab],
                vec![instance, other],
                vec![module],
                vec![],
                vec![]
            ),
            &AuthoredRegistry::default()
        )
        .unwrap_err()
        .code,
        "CHAIN_GRAPH_MISMATCH"
    );
}

#[test]
fn oversized_display_is_rejected_before_the_registry_can_clone_it_per_instance() {
    let mut prefab = prefab_value();
    prefab["nodes"][1]["display"]["payload"]["text"] = json!("a".repeat(MAX_LINE_BYTES + 1));
    stamp("Prefab", &mut prefab);
    let instance = instance_value(&prefab);
    let registry = AuthoredRegistry::default();
    assert_eq!(
        lower(
            inputs(vec![prefab], vec![instance], vec![], vec![], vec![]),
            &registry
        )
        .unwrap_err()
        .code,
        "NUMERIC_RANGE"
    );
    assert_eq!(registry.display_requests.get(), 0);
    assert_eq!(registry.checked_lines.get(), 0);
}

#[test]
fn load_once_state_is_guarded_and_survives_scene_cleanup() {
    let mut prefab = prefab_value();
    prefab["state"] = json!([
        {"stateId":"same","scope":"project","type":"boolean","unit":"unitless","storage":"scoreboard","initialValue":false,"lifecycle":"load_once"},
        {"stateId":"other","scope":"instance","type":"int32","unit":"unitless","storage":"storage_nbt","initialValue":0,"lifecycle":"spawn"}
    ]);
    stamp("Prefab", &mut prefab);
    let instance = instance_value(&prefab);
    let draft = lower(
        inputs(vec![prefab], vec![instance], vec![], vec![], vec![]),
        &AuthoredRegistry::default(),
    )
    .unwrap();
    assert!(function(&draft, "stage").contains("execute unless score"));
    assert!(!function(&draft, "cleanup").contains("scoreboard objectives remove"));
    assert!(function(&draft, "cleanup").contains("data remove storage"));
    assert!(
        draft
            .state_symbols()
            .iter()
            .any(|symbol| symbol.starts_with("project/project-fixture/state/"))
    );
    assert!(draft.state_symbols().iter().any(|symbol| {
        symbol.starts_with("project/project-fixture/instance/instance-shop-a/state/")
    }));
    let cleanup = &draft.function_contracts()[&draft.entry_points()["scene_cleanup"]][0];
    assert_eq!(cleanup.state_writes.len(), 1);
}

#[test]
fn unrelated_authoring_revision_preserves_load_once_native_addresses() {
    let mut prefab = prefab_value();
    prefab["state"] = json!([
        {"stateId":"saved","scope":"project","type":"int32","unit":"unitless","storage":"storage_nbt","initialValue":0,"lifecycle":"load_once"},
        {"stateId":"saved_score","scope":"instance","type":"boolean","unit":"unitless","storage":"scoreboard","initialValue":false,"lifecycle":"load_once"}
    ]);
    stamp("Prefab", &mut prefab);
    let instance = instance_value(&prefab);
    let source = inputs(vec![prefab], vec![instance], vec![], vec![], vec![]);
    let first = lower(source.clone(), &AuthoredRegistry::default()).unwrap();
    let mut edited = source;
    edited.project["name"] = json!("Unrelated authoring label edit");
    stamp("Project", &mut edited.project);
    let second = lower(edited, &AuthoredRegistry::default()).unwrap();
    assert_ne!(first.input_revision(), second.input_revision());
    assert_ne!(first.entry_points(), second.entry_points());
    let instance_id = InstanceId::new("instance-shop-a").unwrap();
    let panel = mmmm_contracts::NodeId::new("panel").unwrap();
    assert_eq!(
        first.animation_bindings()[&instance_id].nodes[&panel].display_uuid,
        second.animation_bindings()[&instance_id].nodes[&panel].display_uuid
    );
    for state_id in ["saved", "saved_score"] {
        let id = mmmm_contracts::StateId::new(state_id).unwrap();
        let before = &first.state_bindings()[&instance_id][&id];
        let after = &second.state_bindings()[&instance_id][&id];
        assert_eq!(before.qualified_state, after.qualified_state);
        assert_eq!(before.storage, after.storage);
        assert_eq!(before.key, after.key);
        assert_eq!(before.objective, after.objective);
        assert_eq!(before.holder, after.holder);
    }
    assert!(function(&second, "stage").contains("execute unless data storage"));
    assert!(function(&second, "stage").contains("execute unless score"));
    assert!(!function(&second, "cleanup").contains("data remove storage"));
    assert!(!function(&second, "cleanup").contains("scoreboard objectives remove"));
}

#[test]
fn helper_only_instance_cross_product_is_bounded_before_native_encoding() {
    // No display, block or command instructions are present: native output
    // budgets cannot protect this retained per-instance projection by itself.
    let mut prefab = prefab_value();
    let root = prefab["nodes"][0].clone();
    let mut nodes = vec![root.clone()];
    for index in 0..256 {
        let mut helper = root.clone();
        helper["nodeId"] = json!(format!("helper-{index}"));
        helper["parentId"] = json!("root");
        nodes.push(helper);
    }
    prefab["nodes"] = json!(nodes);
    stamp("Prefab", &mut prefab);
    let mut instances = Vec::new();
    for index in 0..65 {
        let mut instance = instance_value(&prefab);
        instance["instanceId"] = json!(format!("instance-helper-{index}"));
        stamp("Instance", &mut instance);
        instances.push(instance);
    }
    let registry = AuthoredRegistry::default();
    let error = lower(
        inputs(vec![prefab], instances, vec![], vec![], vec![]),
        &registry,
    )
    .unwrap_err();
    assert_eq!(error.code, "NUMERIC_RANGE");
    assert!(error.message.contains("retained bindings"));
    assert_eq!(registry.display_requests.get(), 0);
    assert_eq!(registry.checked_lines.get(), 0);
}

#[test]
fn same_project_state_id_requires_an_identical_full_definition() {
    let mut prefab = prefab_value();
    prefab["state"] = json!([{ "stateId":"same","scope":"project","type":"int32","unit":"unitless","storage":"scoreboard","initialValue":0,"lifecycle":"load_once" }]);
    stamp("Prefab", &mut prefab);
    let mut other = prefab.clone();
    other["prefabId"] = json!("prefab-other");
    other["state"][0]["storage"] = json!("storage_nbt");
    stamp("Prefab", &mut other);
    let instance = instance_value(&prefab);
    let mut other_instance = instance_value(&other);
    other_instance["prefabId"] = other["prefabId"].clone();
    other_instance["instanceId"] = json!("instance-other");
    stamp("Instance", &mut other_instance);
    assert_eq!(
        lower(
            inputs(
                vec![prefab, other],
                vec![instance, other_instance],
                vec![],
                vec![],
                vec![]
            ),
            &AuthoredRegistry::default()
        )
        .unwrap_err()
        .code,
        "SCHEMA_INVALID"
    );
}

fn stamp(definition: &str, value: &mut Value) {
    value["revision"] = json!(projected_digest(definition, value).unwrap());
}
fn prefab_value() -> Value {
    let mut value: Value =
        serde_json::from_slice(include_bytes!("../../../examples/prefab.json")).unwrap();
    value["nodes"] = json!([
        {"nodeId":"root","name":"Root","parentId":null,"transform":{"kind":"trs","translation":[0,0,0],"rotationXyzw":[0,0,0,1],"scale":[1,1,1]},"colliders":[],"extensions":{}},
        {"nodeId":"panel","name":"Panel","parentId":"root","transform":{"kind":"matrix","layout":"row_major_column_vector","values":[-2,0.5,0,3,0,1,0,4,0,0,2,5,0,0,0,1]},"colliders":[],"extensions":{},"display":{"kind":"text","payload":{"text":" ","background":-16776961},"textRole":"background_geometry","resourceRefs":[]}}
    ]);
    value["ports"] = json!([]);
    value["state"] = json!([]);
    value["references"] = json!([]);
    value["commandModuleIds"] = json!([]);
    value["clipIds"] = json!([]);
    value["resources"] = json!([]);
    stamp("Prefab", &mut value);
    value
}
fn instance_value(prefab: &Value) -> Value {
    let mut value: Value =
        serde_json::from_slice(include_bytes!("../../../examples/instance.json")).unwrap();
    value["prefabRevision"] = prefab["revision"].clone();
    value["placement"] =
        json!({"kind":"trs","translation":[10,20,30],"rotationXyzw":[0,0,0,1],"scale":[1,1,1]});
    stamp("Instance", &mut value);
    value
}
fn inputs(
    prefabs: Vec<Value>,
    instances: Vec<Value>,
    modules: Vec<Value>,
    assets: Vec<Value>,
    resources: Vec<SceneResource>,
) -> SceneBuildInputs {
    let mut project: Value =
        serde_json::from_slice(include_bytes!("../../../examples/project.json")).unwrap();
    project["prefabIds"] = json!(
        prefabs
            .iter()
            .map(|value| value["prefabId"].clone())
            .collect::<Vec<_>>()
    );
    project["instanceIds"] = json!(
        instances
            .iter()
            .map(|value| value["instanceId"].clone())
            .collect::<Vec<_>>()
    );
    project["resourceIds"] = json!(
        resources
            .iter()
            .map(|value| value.reference.resource_id.clone())
            .collect::<Vec<_>>()
    );
    let mut owned = Vec::new();
    for (kind, id, sources) in [
        ("prefab", "prefabId", &prefabs),
        ("instance", "instanceId", &instances),
        ("command_module", "moduleId", &modules),
        ("asset", "assetId", &assets),
    ] {
        for source in sources {
            owned.push(json!({"kind":kind,"objectId":source[id],"revision":source["revision"]}));
        }
    }
    project["ownedResources"] = json!(owned);
    stamp("Project", &mut project);
    SceneBuildInputs::new(project, prefabs, instances, modules, assets, resources)
}
fn lower(inputs: SceneBuildInputs, registry: &AuthoredRegistry) -> Result<SceneDraft, DomainError> {
    scene_lower(&target(), inputs, &Native26_3SceneCodec, registry)
}
fn function(draft: &SceneDraft, name: &str) -> String {
    let id = &draft.entry_points()[&format!("scene_{name}")];
    let (namespace, path) = id.as_str().split_once(':').unwrap();
    String::from_utf8(
        draft.resources()[&format!("data/{namespace}/function/{path}.mcfunction")]
            .bytes
            .clone(),
    )
    .unwrap()
}

#[test]
fn affine_background_text_and_exact_lifecycle_closure_are_preserved() {
    let prefab = prefab_value();
    let instance = instance_value(&prefab);
    let sources = inputs(vec![prefab.clone()], vec![instance], vec![], vec![], vec![]);
    let registry = AuthoredRegistry::default();
    let before = sources.clone();
    let draft = lower(sources, &registry).unwrap();
    let stage = function(&draft, "stage");
    assert!(stage.contains("summon minecraft:text_display 13 24 35"));
    assert!(stage.contains("transformation:[-2f,0.5f,0f,0f,0f,1f,0f,0f,0f,0f,2f,0f,0f,0f,0f,1f]"));
    assert!(stage.contains("\"text\":\" \""));
    assert!(stage.contains("\"background\":-16776961"));
    assert!(stage.contains("interpolation_duration:0"));
    assert_eq!(draft.defined_functions().len(), 3);
    assert_eq!(draft.covered_owned_sources().len(), 2);
    assert_eq!(draft.source_map_entries().len(), 2);
    assert_eq!(registry.checked_lines.get(), 2);
    assert!(function(&draft, "activate").is_empty());
    assert!(
        function(&draft, "cleanup")
            .contains("if entity @s[type=minecraft:text_display] run kill @s")
    );
    let second = lower(before, &AuthoredRegistry::default()).unwrap();
    assert_eq!(stage, function(&second, "stage"));
    assert!(draft.runtime_dependencies().is_empty());
    assert!(draft.resource_pack_resources().is_empty());
    assert_eq!(prefab["nodes"][1]["transform"]["values"][0], -2);
}

fn command_fixture() -> (Value, Value, Value) {
    let mut prefab = prefab_value();
    prefab["commandModuleIds"] = json!(["module-shop-button"]);
    stamp("Prefab", &mut prefab);
    let instance = instance_value(&prefab);
    let mut module: Value =
        serde_json::from_slice(include_bytes!("../../../examples/command-module.json")).unwrap();
    module["localOriginNodeId"] = json!("root");
    module["commands"] = json!([
        {"commandId":"a","source":"function fixture:open","kind":"impulse","conditional":false,"auto":true,"localPosition":[0,0,0],"facing":"east","nextId":"b","conditionSourceId":null,"references":[],"parseStatus":"parsed"},
        {"commandId":"b","source":"function fixture:open","kind":"chain","conditional":true,"auto":true,"localPosition":[1,0,0],"facing":"east","nextId":null,"conditionSourceId":"a","references":[],"parseStatus":"parsed"}
    ]);
    module["inputSymbols"] = json!([]);
    module["outputSymbols"] = json!([]);
    module["sharedStateIds"] = json!([]);
    stamp("CommandModule", &mut module);
    (prefab, instance, module)
}
#[test]
fn all_command_shells_are_disabled_before_sources_and_activation_is_separate() {
    let (prefab, instance, module) = command_fixture();
    let draft = lower(
        inputs(vec![prefab], vec![instance], vec![module], vec![], vec![]),
        &AuthoredRegistry::default(),
    )
    .unwrap();
    let stage = function(&draft, "stage");
    let shell_a = stage
        .find("minecraft:command_block[facing=east,conditional=false]{Command:\"\",auto:0b")
        .unwrap();
    let shell_b = stage
        .find("minecraft:chain_command_block[facing=east,conditional=true]{Command:\"\",auto:0b")
        .unwrap();
    let data = stage.find("Command:\"function fixture:open\"").unwrap();
    assert!(shell_a < shell_b && shell_b < data);
    assert!(!stage.contains("auto:1b"));
    let activate = function(&draft, "activate");
    assert_eq!(activate.matches("auto:1b").count(), 2);
    assert!(!activate.contains("function fixture:open"));
    assert_eq!(draft.referenced_functions().len(), 1);
    assert_eq!(draft.external_functions().len(), 1);
    assert_eq!(draft.covered_owned_sources().len(), 3);
    assert!(function(&draft, "cleanup").contains("auto:0b"));
    assert!(!function(&draft, "cleanup").contains("setblock"));
}

#[test]
fn retained_native_steps_preserve_verified_function_bytes_and_instance_provenance() {
    let (prefab, instance, module) = command_fixture();
    let mut other = instance.clone();
    other["instanceId"] = json!("instance-shop-b");
    other["placement"]["translation"][0] = json!(40);
    stamp("Instance", &mut other);
    let registry = AuthoredRegistry::default();
    let draft = lower(
        inputs(
            vec![prefab],
            vec![instance, other],
            vec![module],
            vec![],
            vec![],
        ),
        &registry,
    )
    .unwrap();
    assert_eq!(draft.target_profile_id(), target().profile_id());
    let mut retained_lines = 0;
    for (name, phase) in [
        ("stage", SceneLifecyclePhase::Stage),
        ("activate", SceneLifecyclePhase::Activate),
        ("cleanup", SceneLifecyclePhase::Cleanup),
    ] {
        let lines = draft
            .native_steps()
            .iter()
            .filter(|step| step.phase() == phase)
            .flat_map(NativeSceneStep::encoded_commands)
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        assert_eq!(lines, function(&draft, name));
        retained_lines += lines.lines().count();
    }
    assert_eq!(retained_lines, registry.checked_lines.get());
    let mut shell_positions = BTreeMap::<String, Vec<[i32; 3]>>::new();
    for step in draft.native_steps() {
        assert_eq!(step.owner_prefab_id().as_str(), "prefab-shop");
        match step.instruction() {
            NativeSceneInstruction::CommandShell { position, .. } => {
                assert_eq!(step.phase(), SceneLifecyclePhase::Stage);
                assert_eq!(step.source_object_id().as_str(), "module-shop-button");
                assert_eq!(step.source_node_id().unwrap().as_str(), "root");
                assert!(step.encoded_commands()[0].contains("Command:\"\",auto:0b"));
                shell_positions
                    .entry(step.instance_id().as_str().to_owned())
                    .or_default()
                    .push(*position);
            }
            NativeSceneInstruction::Display { uuid, position, .. } => {
                let projection = &draft.animation_bindings()[step.instance_id()];
                let node = &projection.nodes[step.source_node_id().unwrap()];
                assert_eq!(node.display_uuid.as_deref(), Some(uuid_text(uuid).as_str()));
                assert_eq!(&node.display_origin, position);
                assert_eq!(
                    step.source_object_id().as_str(),
                    step.instance_id().as_str()
                );
            }
            _ => {}
        }
    }
    assert_eq!(
        shell_positions["instance-shop-a"],
        vec![[10, 20, 30], [11, 20, 30]]
    );
    assert_eq!(
        shell_positions["instance-shop-b"],
        vec![[40, 20, 30], [41, 20, 30]]
    );
}

fn blocks() -> (Value, SceneResource) {
    let blockset = json!({"contractVersion":"0.2.0","palette":[{"blockId":"minecraft:stone","properties":{}}],"cells":[{"position":[2,1,3],"paletteIndex":0}],"blockEntities":[]});
    let bytes = canonical_bytes(&blockset).unwrap();
    let resource = SceneResource {
        reference: ResourceRef {
            resource_id: ResourceId::new("authored-blocks").unwrap(),
            sha256: raw_digest(&bytes),
            media_type: "application/vnd.mmmm.blockset+json".into(),
            size_bytes: bytes.len() as u64,
        },
        bytes,
    };
    let mut prefab = prefab_value();
    prefab["nodes"][1]
        .as_object_mut()
        .unwrap()
        .remove("display");
    prefab["nodes"][1]["transform"] = json!({"kind":"matrix","layout":"row_major_column_vector","values":[0,0,1,0,0,1,0,0,-1,0,0,0,0,0,0,1]});
    prefab["nodes"][1]["blockGeometry"] = json!({"resourceId":"authored-blocks","bounds":{"min":[0,0,0],"maxExclusive":[5,5,5]},"rotationPolicy":"quarter_turn_y_only","cellOrigin":"minimum_corner"});
    prefab["resources"] = json!([resource.reference]);
    stamp("Prefab", &mut prefab);
    (prefab, resource)
}
#[test]
fn quarter_turn_rotates_cell_minimum_corner_and_registry_rotation_is_required() {
    let (prefab, resource) = blocks();
    let instance = instance_value(&prefab);
    let source = inputs(vec![prefab], vec![instance], vec![], vec![], vec![resource]);
    let draft = lower(source.clone(), &AuthoredRegistry::default()).unwrap();
    // Independent unit cube rotation: (x,z)=(2,3) -> (3,-3),
    // then world translation (10,20,30) -> (13,21,27).
    assert!(function(&draft, "stage").contains("setblock 13 21 27 minecraft:stone"));
    let registry = AuthoredRegistry {
        reject_rotation: true,
        ..Default::default()
    };
    assert_eq!(
        lower(source, &registry).unwrap_err().code,
        "EVIDENCE_UNVERIFIED"
    );
}
#[test]
fn quarter_turn_facing_and_command_cell_adjacency_remain_consistent() {
    let (prefab, mut instance, module) = command_fixture();
    instance["placement"] = json!({"kind":"matrix","layout":"row_major_column_vector","values":[0,0,1,10,0,1,0,20,-1,0,0,30,0,0,0,1]});
    stamp("Instance", &mut instance);
    let draft = lower(
        inputs(vec![prefab], vec![instance], vec![module], vec![], vec![]),
        &AuthoredRegistry::default(),
    )
    .unwrap();
    let stage = function(&draft, "stage");
    assert!(stage.contains("setblock 10 20 29 minecraft:command_block[facing=north"));
    assert!(stage.contains("setblock 10 20 28 minecraft:chain_command_block[facing=north"));
}
#[test]
fn bad_hash_missing_inventory_unsupported_geometry_and_fractional_block_translation_fail() {
    let (prefab, mut resource) = blocks();
    let instance = instance_value(&prefab);
    resource.bytes.push(0);
    assert_eq!(
        lower(
            inputs(vec![prefab], vec![instance], vec![], vec![], vec![resource]),
            &AuthoredRegistry::default()
        )
        .unwrap_err()
        .code,
        "DIGEST_MISMATCH"
    );
    let prefab = prefab_value();
    let instance = instance_value(&prefab);
    let mut source = inputs(vec![prefab.clone()], vec![instance], vec![], vec![], vec![]);
    source.project["ownedResources"] = json!([]);
    stamp("Project", &mut source.project);
    assert_eq!(
        lower(source, &AuthoredRegistry::default())
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
    let mut prefab = prefab;
    prefab["nodes"][1]["geometryRepresentation"] = json!("surface_sample");
    stamp("Prefab", &mut prefab);
    let instance = instance_value(&prefab);
    assert_eq!(
        lower(
            inputs(vec![prefab], vec![instance], vec![], vec![], vec![]),
            &AuthoredRegistry::default()
        )
        .unwrap_err()
        .code,
        "UNOWNED_REQUIRED_CAPABILITY"
    );
    let (prefab, resource) = blocks();
    let mut instance = instance_value(&prefab);
    instance["placement"]["translation"][0] = json!(10.0000000001);
    stamp("Instance", &mut instance);
    assert_eq!(
        lower(
            inputs(vec![prefab], vec![instance], vec![], vec![], vec![resource]),
            &AuthoredRegistry::default()
        )
        .unwrap_err()
        .code,
        "UNOWNED_REQUIRED_CAPABILITY"
    );
}
#[test]
fn opaque_commands_never_rewrite_or_move() {
    let (prefab, mut instance, mut module) = command_fixture();
    module["commands"][0]["parseStatus"] = json!("opaque");
    module["commands"][0]["source"] = json!("raw @p 10 20 30");
    stamp("CommandModule", &mut module);
    let moved = inputs(
        vec![prefab.clone()],
        vec![instance.clone()],
        vec![module.clone()],
        vec![],
        vec![],
    );
    assert_eq!(
        lower(moved, &AuthoredRegistry::default()).unwrap_err().code,
        "OPAQUE_RELOCATION"
    );
    instance["placement"] =
        json!({"kind":"trs","translation":[0,0,0],"rotationXyzw":[0,0,0,1],"scale":[1,1,1]});
    stamp("Instance", &mut instance);
    let source = inputs(vec![prefab], vec![instance], vec![module], vec![], vec![]);
    let registry = AuthoredRegistry {
        alter_opaque: true,
        ..Default::default()
    };
    assert_eq!(
        lower(source, &registry).unwrap_err().code,
        "OPAQUE_RELOCATION"
    );
}
#[test]
fn output_strings_are_escaped_reserved_fields_rejected_and_state_type_preserved() {
    let codec = Native26_3SceneCodec;
    let instruction = NativeSceneInstruction::CommandData {
        dimension: ResourceLocation::new("minecraft:overworld").unwrap(),
        position: [0, 0, 0],
        source: "say \"quoted\" \\ value".into(),
    };
    let output = codec.encode_instruction(&instruction).unwrap();
    assert!(output[0].contains("Command:\"say \\\"quoted\\\" \\\\ value\""));
    assert!(!output[0].contains('\n'));
    let instruction = NativeSceneInstruction::Display {
        dimension: ResourceLocation::new("minecraft:overworld").unwrap(),
        tag: "mmmm_owned.a".into(),
        entity_kind: "text".into(),
        uuid: [0; 16],
        position: [0.0; 3],
        matrix: *Matrix4::identity().values(),
        payload: BTreeMap::from([("Tags".into(), json!(["other"]))]),
    };
    assert_eq!(
        codec.encode_instruction(&instruction).unwrap_err().code,
        "UNOWNED_REQUIRED_CAPABILITY"
    );
    let instruction = NativeSceneInstruction::StateInitialize {
        storage: ResourceLocation::new("fixture:state").unwrap(),
        key: "s_1".into(),
        value: ScalarValue::Number(serde_json::Number::from(1)),
        storage_kind: "storage_nbt".into(),
        state_type: StateType::Int32,
        lifecycle: "spawn".into(),
        objective: "m1".into(),
        holder: "#s1".into(),
    };
    assert_eq!(
        codec.encode_instruction(&instruction).unwrap(),
        vec!["data modify storage fixture:state states.s_1 set value 1"]
    );
}
#[test]
fn asset_bytes_go_to_separate_resource_pack_and_nonportable_paths_fail() {
    let prefab = prefab_value();
    let instance = instance_value(&prefab);
    let bytes = b"authored texture bytes".to_vec();
    let resource = SceneResource {
        reference: ResourceRef {
            resource_id: ResourceId::new("texture-bytes").unwrap(),
            sha256: raw_digest(&bytes),
            media_type: "image/png".into(),
            size_bytes: bytes.len() as u64,
        },
        bytes,
    };
    let mut asset: Value =
        serde_json::from_slice(include_bytes!("../../../examples/asset.json")).unwrap();
    asset["kind"] = json!("texture");
    asset["resource"] = json!(resource.reference);
    stamp("Asset", &mut asset);
    let source = inputs(
        vec![prefab],
        vec![instance],
        vec![],
        vec![asset],
        vec![resource],
    );
    let registry = AuthoredRegistry {
        path: Some("assets/fixture/textures/block/panel.png".into()),
        ..Default::default()
    };
    let draft = lower(source.clone(), &registry).unwrap();
    assert_eq!(draft.resource_pack_resources().len(), 1);
    assert!(
        !draft
            .resources()
            .keys()
            .any(|path| path.starts_with("assets/"))
    );
    assert!(!draft.resource_pack_resources().contains_key("pack.mcmeta"));
    let registry = AuthoredRegistry {
        path: Some("assets/fixture/../outside.png".into()),
        ..Default::default()
    };
    assert_eq!(lower(source, &registry).unwrap_err().code, "SCHEMA_INVALID");
}
#[test]
fn caller_target_text_and_unbound_scene_codec_do_not_grant_support() {
    let prefab = prefab_value();
    let instance = instance_value(&prefab);
    let source = inputs(vec![prefab], vec![instance], vec![], vec![], vec![]);
    let registry = AuthoredRegistry {
        reject_codec: true,
        ..Default::default()
    };
    assert_eq!(
        lower(source, &registry).unwrap_err().code,
        "EVIDENCE_UNVERIFIED"
    );
    assert_eq!(
        target().profile_id(),
        &TargetProfileId::new("java-26.3").unwrap()
    );
}

#[test]
fn native_float_conversion_needs_an_explicit_budget_and_records_actual_loss() {
    let mut prefab = prefab_value();
    prefab["nodes"][1]["transform"]["values"][0] = json!(0.1);
    stamp("Prefab", &mut prefab);
    let instance = instance_value(&prefab);
    let source = inputs(vec![prefab], vec![instance], vec![], vec![], vec![]);
    assert_eq!(
        lower(source.clone(), &AuthoredRegistry::default())
            .unwrap_err()
            .code,
        "NUMERIC_RANGE"
    );
    let draft = lower(
        source.with_max_component_error(1e-8),
        &AuthoredRegistry::default(),
    )
    .unwrap();
    assert_eq!(draft.losses().len(), 1);
    assert_eq!(draft.losses()[0]["code"], "DISPLAY_F32_ROUNDING");
    assert_eq!(draft.losses()[0]["disposition"], "approximated");
    assert_eq!(draft.losses()[0]["approvalRequired"], true);
    assert!(
        draft.losses()[0]["message"]
            .as_str()
            .unwrap()
            .contains("not observed game readback")
    );
}

#[test]
fn native_steps_expose_actual_target_float_values_separately_from_authored_sources() {
    let mut prefab = prefab_value();
    prefab["nodes"][1]["transform"]["values"][0] = json!(0.1);
    prefab["state"] = json!([
        {"stateId":"fraction","scope":"instance","type":"float32","unit":"unitless","storage":"storage_nbt","initialValue":0.1,"lifecycle":"spawn"}
    ]);
    stamp("Prefab", &mut prefab);
    let instance = instance_value(&prefab);
    let draft = lower(
        inputs(vec![prefab], vec![instance], vec![], vec![], vec![]).with_max_component_error(1e-8),
        &AuthoredRegistry::default(),
    )
    .unwrap();
    let native_value = f64::from(0.1_f32);
    assert_ne!(native_value, 0.1_f64);
    let mut seen_matrix = false;
    let mut seen_state = false;
    for step in draft.native_steps() {
        match step.instruction() {
            NativeSceneInstruction::Display { matrix, .. } => {
                assert_eq!(matrix[0], native_value);
                assert!(step.encoded_commands()[0].contains("transformation:[0.1f,"));
                seen_matrix = true;
            }
            NativeSceneInstruction::StateInitialize {
                value: ScalarValue::Number(value),
                state_type: StateType::Float32,
                ..
            } => {
                assert_eq!(value.as_f64(), Some(native_value));
                assert!(step.encoded_commands()[0].ends_with("set value 0.1f"));
                seen_state = true;
            }
            _ => {}
        }
    }
    assert!(seen_matrix && seen_state);
    assert_eq!(draft.losses().len(), 2);
    assert!(
        draft
            .losses()
            .iter()
            .all(|loss| loss["approvalRequired"] == true)
    );
}

#[test]
fn sealed_scene_pack_composition_covers_owned_sources_and_inherits_requirements() {
    use crate::{PackBuildInputs, PackFunction, PackInstruction, pack_build};
    let prefab = prefab_value();
    let instance = instance_value(&prefab);
    let source = inputs(vec![prefab], vec![instance], vec![], vec![], vec![]);
    let project = source.project.clone();
    let scene = lower(source, &AuthoredRegistry::default()).unwrap();
    let stage = scene.entry_points()["scene_stage"].clone();
    let wrapper = ResourceLocation::new("fixture:scene_wrapper").unwrap();
    let owned = project["ownedResources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["objectId"].as_str().unwrap().to_owned())
        .collect();
    let inputs = PackBuildInputs::new(
        project.clone(),
        vec![PackFunction {
            id: wrapper.clone(),
            source_object_id: "prefab-shop".into(),
            instructions: vec![PackInstruction::Call(stage.clone())],
        }],
        BTreeMap::from([("run".into(), wrapper.clone())]),
        owned,
    )
    .with_scene(scene);
    let request = json!({"contextId":"build-context","projectId":project["projectId"],"expectedRevision":project["revision"],"targetProfileId":"java-26.3","outputPolicy":"private_staging_only"});
    let pack = pack_build(&request, &target(), inputs).unwrap();
    assert_eq!(pack.manifest().validation_stage, "statically_checked");
    assert!(pack.manifest().defined_functions.contains(&stage));
    assert!(
        pack.function_contracts()[&wrapper][0]
            .requirements
            .iter()
            .any(|requirement| requirement.contains("world identity"))
    );
    assert!(pack.manifest().external_functions.is_empty());
    assert!(pack.manifest().losses.is_empty());
}

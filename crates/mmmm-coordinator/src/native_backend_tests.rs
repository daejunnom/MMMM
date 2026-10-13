//! Source-only boundary regressions reuse canonical examples and the owning
//! compiler. Explicit authored verifier doubles exist only in this test module;
//! they are not game/profile acceptance or provider readiness evidence.
use super::*;
use mmmm_compiler::{
    TargetEvidenceVerifier, TargetRuntimeRules,
    scene::{ResolvedSceneCommand, SceneBlockState, SceneCodecCapabilities, SceneStateBinding},
};
use mmmm_contracts::{ResourceLocation, StateId};
use mmmm_domain::{
    DomainError, Instance, Prefab,
    commands::{CommandModule, CommandNode},
    transform::Matrix4,
    types::Display,
};

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

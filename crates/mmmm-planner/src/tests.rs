//! Pure source/plan invariants. Fixtures never become host/runtime acceptance.
use crate::preparation::{document, empty_change, update_project};
use crate::*;
use mmmm_contracts::{parse_json, projected_digest};
use serde_json::json;

#[test]
fn authored_clip_change_promotes_one_pin_and_preserves_original_project() {
    let original = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
    let catalog = ProjectCatalog::from_project(&original).unwrap();
    let before = parse_json(include_bytes!("../../../examples/animation-clip.json")).unwrap();
    let after=mmmm_domain::clip_retime(&json!({"clip":before,"duration":{"numerator":"4","denominator":"1"},"eventPolicy":"scale_with_clip"})).unwrap();
    let mut change = empty_change(&catalog, NativeKind::ClipRetime);
    change.document_changes.push(
        document(
            OwnedKind::Clip,
            Some(
                catalog
                    .owned_pin(OwnedKind::Clip, "clip-door")
                    .unwrap()
                    .revision
                    .clone(),
            ),
            after.clone(),
        )
        .unwrap(),
    );
    update_project(&mut change).unwrap();
    let changed = ProjectCatalog::from_project(&change.project_after).unwrap();
    assert_eq!(
        changed
            .owned_pin(OwnedKind::Clip, "clip-door")
            .unwrap()
            .revision
            .as_str(),
        after["revision"].as_str().unwrap()
    );
    assert_eq!(catalog.project(), &original);
    assert_ne!(changed.revision(), catalog.revision());
    assert_eq!(changed.used_instance_ids(), catalog.used_instance_ids());
    let payload = change.to_arguments().unwrap();
    let decoded = PreparedNativeChange::from_payload(&payload).unwrap();
    assert_eq!(decoded.project_after, change.project_after);
    let mut injected = payload;
    injected["change"]["endpoint"] = json!("unregistered-target");
    assert_eq!(
        PreparedNativeChange::from_payload(&injected)
            .unwrap_err()
            .code,
        "INVALID_INPUT"
    );
}

#[test]
fn prepared_document_pin_cannot_lie_about_after_id_or_revision() {
    let original = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
    let catalog = ProjectCatalog::from_project(&original).unwrap();
    let clip = parse_json(include_bytes!("../../../examples/animation-clip.json")).unwrap();
    let mut change = empty_change(&catalog, NativeKind::ClipRetime);
    let mut changed = document(
        OwnedKind::Clip,
        Some(
            catalog
                .owned_pin(OwnedKind::Clip, "clip-door")
                .unwrap()
                .revision
                .clone(),
        ),
        clip,
    )
    .unwrap();
    changed.object_id = "other-clip".into();
    change.document_changes.push(changed);
    assert_eq!(change.to_arguments().unwrap_err().code, "REVISION_CONFLICT");
    change.document_changes[0].object_id = "clip-door".into();
    change.document_changes[0].after["duration"] = json!({"numerator":"8","denominator":"1"});
    assert_eq!(change.to_arguments().unwrap_err().code, "REVISION_CONFLICT");
}

#[test]
fn content_revision_is_recomputed_after_authoring_index_promotion() {
    let original = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
    let catalog = ProjectCatalog::from_project(&original).unwrap();
    let mut instance = parse_json(include_bytes!("../../../examples/instance.json")).unwrap();
    instance["instanceId"] = json!("instance-new");
    instance["revision"] = json!(projected_digest("Instance", &instance).unwrap());
    let mut change = empty_change(&catalog, NativeKind::Clone);
    change
        .document_changes
        .push(document(OwnedKind::Instance, None, instance).unwrap());
    update_project(&mut change).unwrap();
    assert_eq!(
        change.project_after["revision"],
        json!(projected_digest("Project", &change.project_after).unwrap())
    );
    assert_eq!(
        change.project_after["instanceIds"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(original["instanceIds"].as_array().unwrap().len(), 1);
}

#[test]
fn default_plan_budget_fits_observed_host_admission_without_deadline_rewrite() {
    let options = PlannerOptions::default();
    options.validate().unwrap();
    assert_eq!(options.time_budget_ms, 30_000);
    let mut invalid = options;
    invalid.time_budget_ms = 0;
    assert_eq!(invalid.validate().unwrap_err().code, "BUDGET_EXCEEDED");
}

#[test]
fn typed_and_cas_codecs_preserve_large_finite_float_wire_spelling() {
    let mut prefab = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
    prefab["nodes"][0]["transform"]["translation"][0] = json!(9_007_199_254_740_992.0f64);
    prefab["revision"] = json!(projected_digest("Prefab", &prefab).unwrap());
    let typed: mmmm_domain::Prefab = decode("Prefab", &prefab).unwrap();
    let encoded = mmmm_contracts::encode_json(&wire("Prefab", &typed).unwrap()).unwrap();
    parse_json(&encoded).unwrap();

    let project = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    let mut clip = parse_json(include_bytes!("../../../examples/animation-clip.json")).unwrap();
    clip["tracks"][0]["keys"][0]["transform"]["translation"][0] = json!(9_007_199_254_740_992.0f64);
    clip["revision"] = json!(projected_digest("AnimationClip", &clip).unwrap());
    let mut change = empty_change(&catalog, NativeKind::ClipRetime);
    change.document_changes.push(
        document(
            OwnedKind::Clip,
            Some(
                catalog
                    .owned_pin(OwnedKind::Clip, "clip-door")
                    .unwrap()
                    .revision
                    .clone(),
            ),
            clip,
        )
        .unwrap(),
    );
    update_project(&mut change).unwrap();
    let payload = change.to_arguments().unwrap();
    let bytes = mmmm_contracts::encode_json(&payload).unwrap();
    let read = parse_json(&bytes).unwrap();
    let decoded = PreparedNativeChange::from_payload(&read).unwrap();
    assert_eq!(
        decoded.document_changes[0].after["tracks"][0]["keys"][0]["transform"]["translation"][0],
        json!(9_007_199_254_740_992.0f64)
    );

    let resource = json!({"resourceId":"typed-size","sha256":"0".repeat(64),"mediaType":"application/json","sizeBytes":1.0});
    let typed: mmmm_domain::types::ResourceRef = decode("ResourceRef", &resource).unwrap();
    assert_eq!(typed.size_bytes, 1);
}

#[test]
fn resource_ref_shaped_display_payload_remains_opaque_in_instance_and_draft() {
    let opaque = json!({"resourceId":"opaque-payload","sha256":"0".repeat(64),"mediaType":"application/json","sizeBytes":1.0});
    let display = json!({"kind":"item","payload":{"nested":{"shape":opaque}},"resourceRefs":[]});
    let typed_display: mmmm_domain::types::Display = decode("Display", &display).unwrap();
    let display_wire = wire("Display", &typed_display).unwrap();
    assert_eq!(display_wire["payload"]["nested"]["shape"], opaque);
    assert!(
        display_wire["payload"]["nested"]["shape"]["sizeBytes"]
            .as_u64()
            .is_none()
    );

    let mut instance = parse_json(include_bytes!("../../../examples/instance.json")).unwrap();
    instance["overrides"] = json!([{"kind":"display","nodeId":"door","display":display}]);
    instance["revision"] = json!(projected_digest("Instance", &instance).unwrap());
    let typed_instance: mmmm_domain::Instance = decode("Instance", &instance).unwrap();
    let instance_wire = wire("Instance", &typed_instance).unwrap();
    assert_eq!(
        instance_wire["overrides"][0]["display"]["payload"]["nested"]["shape"],
        opaque
    );
    assert!(
        instance_wire["overrides"][0]["display"]["payload"]["nested"]["shape"]["sizeBytes"]
            .as_u64()
            .is_none()
    );

    let draft = json!({"instance":instance,"newSymbolBindings":[],"diagnostics":[],"losses":[]});
    let typed_draft: mmmm_domain::types::InstanceDraft = decode("InstanceDraft", &draft).unwrap();
    let draft_wire = wire("InstanceDraft", &typed_draft).unwrap();
    assert_eq!(
        draft_wire["instance"]["overrides"][0]["display"]["payload"]["nested"]["shape"],
        opaque
    );
    assert!(draft_wire["instance"]["overrides"][0]["display"]["payload"]["nested"]["shape"]["sizeBytes"].as_u64().is_none());

    let ordinary = parse_json(include_bytes!("../../../examples/instance.json")).unwrap();
    let ordinary_typed: mmmm_domain::Instance = decode("Instance", &ordinary).unwrap();
    assert_eq!(
        wire("Instance", &ordinary_typed).unwrap()["instanceId"],
        ordinary["instanceId"]
    );
    let ordinary_display = json!({"kind":"text","payload":{"text":"hello"},"resourceRefs":[]});
    let ordinary_typed: mmmm_domain::types::Display = decode("Display", &ordinary_display).unwrap();
    assert_eq!(wire("Display", &ordinary_typed).unwrap(), ordinary_display);
    let ordinary_draft =
        json!({"instance":ordinary,"newSymbolBindings":[],"diagnostics":[],"losses":[]});
    let ordinary_typed: mmmm_domain::types::InstanceDraft =
        decode("InstanceDraft", &ordinary_draft).unwrap();
    assert!(wire("InstanceDraft", &ordinary_typed).is_ok());

    let mut invalid = display;
    invalid["payload"] = json!([]);
    assert_eq!(
        decode::<mmmm_domain::types::Display>("Display", &invalid)
            .unwrap_err()
            .code,
        "INVALID_INPUT"
    );
}

#[test]
fn prefab_comparison_preserves_original_and_value_only_requires_integer_lengths() {
    let original = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
    require_value_only_prefab_integer_lengths(&original).unwrap();
    let resource_length = original["resources"][0]["sizeBytes"].as_u64().unwrap();
    let mut decimal = original.clone();
    decimal["resources"][0]["sizeBytes"] = json!(resource_length as f64);
    assert_eq!(
        require_value_only_prefab_integer_lengths(&decimal)
            .unwrap_err()
            .code,
        "CAPABILITY_UNAVAILABLE"
    );
    let before = decimal.clone();
    let typed = decode_prefab_scoped(&decimal, || Ok(())).unwrap();
    assert_eq!(typed.resources[0].size_bytes, resource_length);
    assert_eq!(decimal, before);
    let mut calls = 0;
    let error = decode_prefab_scoped(&original, || {
        calls += 1;
        if calls == 2 {
            Err(AppError::new("CANCELLED", "test cancellation"))
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert_eq!(error.code, "CANCELLED");
}

// Controlled ports isolate Planner dependency accounting; they do not prove a
// real Store, resource grant, external target, complete plan, or game action.
#[derive(Clone, Copy)]
pub(super) enum MeshReadMode {
    Allowed,
    Denied,
    Corrupt,
}

pub(super) struct MeshSource {
    pub(super) physics: serde_json::Value,
    pub(super) mesh: mmmm_domain::types::ResourceRef,
    pub(super) mode: MeshReadMode,
    pub(super) reads: std::rc::Rc<std::cell::Cell<usize>>,
}

fn mesh_unexpected<T>() -> mmmm_application::AppResult<T> {
    Err(AppError::new(
        "TEST_UNEXPECTED_PORT",
        "Unexpected mesh test port call",
    ))
}

impl ProjectSourcePort for MeshSource {
    fn inspect_owned(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: u64,
    ) -> mmmm_application::AppResult<Vec<(ObjectPin, serde_json::Value)>> {
        mesh_unexpected()
    }
    fn owned_object(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        pin: &ObjectPin,
        _: Option<&serde_json::Value>,
        _: u64,
    ) -> mmmm_application::AppResult<serde_json::Value> {
        assert_eq!(pin.kind, OwnedKind::PhysicsDefinition);
        assert_eq!(pin.object_id.as_str(), "physics-door");
        Ok(self.physics.clone())
    }
    fn resource_pin(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &str,
        _: Option<&serde_json::Value>,
    ) -> mmmm_application::AppResult<mmmm_domain::types::ResourceRef> {
        mesh_unexpected()
    }
    fn resource_bytes(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        resource: &mmmm_domain::types::ResourceRef,
        _: Option<&serde_json::Value>,
        _: u64,
    ) -> mmmm_application::AppResult<PinnedResourceBytes> {
        self.reads.set(self.reads.get() + 1);
        assert_eq!(resource.resource_id, self.mesh.resource_id);
        assert_eq!(resource.sha256, self.mesh.sha256);
        match self.mode {
            MeshReadMode::Denied => Err(AppError::new("FORBIDDEN", "mesh source scope denied")),
            MeshReadMode::Allowed => Ok(PinnedResourceBytes {
                resource: self.mesh.clone(),
                bytes: b"mesh".to_vec(),
            }),
            MeshReadMode::Corrupt => Ok(PinnedResourceBytes {
                resource: self.mesh.clone(),
                bytes: b"nope".to_vec(),
            }),
        }
    }
    fn stage_private(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: Option<&mmmm_contracts::ResourceId>,
        _: &[u8],
        _: &str,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<mmmm_domain::types::ResourceRef> {
        mesh_unexpected()
    }
    fn allocate_instance_id(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &std::collections::BTreeSet<mmmm_contracts::InstanceId>,
    ) -> mmmm_application::AppResult<mmmm_contracts::InstanceId> {
        mesh_unexpected()
    }
    fn state_snapshot(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &serde_json::Value,
        _: &serde_json::Value,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<PinnedStateSnapshot> {
        mesh_unexpected()
    }
    fn scene_source(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &serde_json::Value,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<SceneSource> {
        mesh_unexpected()
    }
    fn validate_scene_provenance(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &serde_json::Value,
        _: &SceneSource,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<()> {
        mesh_unexpected()
    }
}

pub(super) struct MeshEnvironment;
impl PlanningEnvironmentPort for MeshEnvironment {
    fn execution_budget_ms(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<u64> {
        mesh_unexpected()
    }
    fn inventory(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<mmmm_adapters::InventorySnapshot> {
        mesh_unexpected()
    }
    fn binding_dependency(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &mmmm_contracts::BindingId,
        _: &mmmm_contracts::Sha256Digest,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<serde_json::Value> {
        mesh_unexpected()
    }
    fn native_route(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: NativeKind,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<NativeActionRoute> {
        mesh_unexpected()
    }
    fn verified_native_target(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &mmmm_contracts::TargetProfileId,
        _: NativeKind,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<VerifiedNativeTarget> {
        mesh_unexpected()
    }
    fn snapshot_native_targets(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &PreparedNativeChange,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<NativeTargetSnapshot> {
        mesh_unexpected()
    }
    fn registered_action_footprint(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &serde_json::Value,
        _: &mmmm_adapters::ActionDescriptor,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<RegisteredActionFootprint> {
        mesh_unexpected()
    }
    fn relocatable_modules(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &[serde_json::Value],
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<std::collections::BTreeSet<mmmm_contracts::ModuleId>> {
        mesh_unexpected()
    }
    fn command_layout_support(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &serde_json::Value,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<mmmm_domain::commands::CommandLayoutSupport> {
        mesh_unexpected()
    }
    fn command_layout_request(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &serde_json::Value,
        _: &serde_json::Value,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<serde_json::Value> {
        mesh_unexpected()
    }
    fn verify_projection_references(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &InstanceProjection,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<Vec<serde_json::Value>> {
        Ok(vec![])
    }
    fn compiler_target(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &mmmm_contracts::TargetProfileId,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<mmmm_compiler::VerifiedTarget> {
        mesh_unexpected()
    }
    fn pack_inputs(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &[serde_json::Value],
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<mmmm_compiler::PackBuildInputs> {
        mesh_unexpected()
    }
    fn recovery_route(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &mmmm_application::RecoveryPreparation,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<NativeActionRoute> {
        mesh_unexpected()
    }
    fn recovery_scope(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &mmmm_application::RecoveryPreparation,
        _: &ProjectCatalog,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<mmmm_runtime::storage::WriteScope> {
        mesh_unexpected()
    }
    fn project_bindings_available(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
    ) -> mmmm_application::AppResult<bool> {
        mesh_unexpected()
    }
}

#[test]
fn projection_loads_physics_only_mesh_and_rejects_missing_authority_or_conflicting_pins() {
    use crate::preparation::Sources;
    use mmmm_contracts::{PrincipalId, raw_digest};
    use mmmm_domain::types::ResourceRef;
    use std::{cell::Cell, rc::Rc};

    for (mode, conflict, decimal, limited) in [
        (MeshReadMode::Allowed, 0, false, false),
        (MeshReadMode::Denied, 0, false, false),
        (MeshReadMode::Corrupt, 0, false, false),
        (MeshReadMode::Allowed, 1, false, false),
        (MeshReadMode::Allowed, 2, false, false),
        (MeshReadMode::Allowed, 3, false, false),
        (MeshReadMode::Allowed, 0, true, false),
        (MeshReadMode::Allowed, 0, false, true),
    ] {
        let mesh = ResourceRef {
            resource_id: mmmm_contracts::ResourceId::new("resource-physics-mesh").unwrap(),
            sha256: raw_digest(b"mesh"),
            media_type: "application/octet-stream".into(),
            size_bytes: 4,
        };
        let mut physics =
            parse_json(include_bytes!("../../../examples/physics-definition.json")).unwrap();
        physics["colliders"][0]["shape"]["shape"] =
            json!({"kind":"mesh","geometry":mesh,"topologyDigest":"0".repeat(64)});
        if decimal {
            physics["colliders"][0]["shape"]["shape"]["geometry"]["sizeBytes"] = json!(4.0);
        }
        physics["revision"] = json!(projected_digest("PhysicsDefinition", &physics).unwrap());
        let physics_len = mmmm_contracts::encode_json(&physics).unwrap().len() as u64;
        let mut prefab = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
        for field in [
            "ports",
            "references",
            "commandModuleIds",
            "clipIds",
            "resources",
        ] {
            prefab[field] = json!([]);
        }
        let nodes = prefab["nodes"].as_array_mut().unwrap();
        nodes.retain(|node| node["nodeId"] == "root" || node["nodeId"] == "door");
        for node in nodes.iter_mut() {
            let object = node.as_object_mut().unwrap();
            for field in [
                "geometryResource",
                "blockGeometry",
                "display",
                "physicsBinding",
            ] {
                object.remove(field);
            }
        }
        nodes
            .iter_mut()
            .find(|node| node["nodeId"] == "door")
            .unwrap()["physicsBinding"] = json!({"physicsId":"physics-door","bodyId":"body-door"});
        if conflict != 0 {
            let mut conflicting = mesh.clone();
            match conflict {
                1 => conflicting.sha256 = raw_digest(b"xxxx"),
                2 => conflicting.media_type = "application/json".into(),
                3 => conflicting.size_bytes += 1,
                _ => unreachable!(),
            }
            prefab["resources"] = json!([conflicting]);
        }
        let definition = decode("Prefab", &prefab).unwrap();
        let mut instance = parse_json(include_bytes!("../../../examples/instance.json")).unwrap();
        instance["overrides"] = json!([]);
        let instance = decode("Instance", &instance).unwrap();
        let mut projection = InstanceProjection {
            before: None,
            before_definition: None,
            after: instance,
            definition,
            command_modules: vec![],
            clips: vec![],
            physics_definitions: vec![],
            resource_pins: vec![],
        };
        let mut project = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
        project["ownedResources"].as_array_mut().unwrap().push(json!({"kind":"physics_definition","objectId":"physics-door","revision":physics["revision"]}));
        project["revision"] = json!(projected_digest("Project", &project).unwrap());
        let catalog = ProjectCatalog::from_project(&project).unwrap();
        let reads = Rc::new(Cell::new(0));
        let source = MeshSource {
            physics,
            mesh: mesh.clone(),
            mode,
            reads: reads.clone(),
        };
        let options = if limited {
            PlannerOptions {
                max_source_bytes: physics_len + 3,
                ..PlannerOptions::default()
            }
        } else {
            PlannerOptions::default()
        };
        let mut planner = NativePlanner::new(
            Box::new(source),
            Box::new(MeshEnvironment),
            Box::new(mmmm_application::SystemClock),
            options,
        )
        .unwrap();
        let mut sources = Sources::default();
        let result = planner.fill_projection(
            &PrincipalId::new("principal-mesh-test").unwrap(),
            &catalog,
            &mut projection,
            &json!({}),
            &mut sources,
        );
        let expected = if conflict != 0 {
            Some("REVISION_CONFLICT")
        } else if decimal {
            Some("CAPABILITY_UNAVAILABLE")
        } else if limited {
            Some("BUDGET_EXCEEDED")
        } else {
            match mode {
                MeshReadMode::Allowed => None,
                MeshReadMode::Denied => Some("FORBIDDEN"),
                MeshReadMode::Corrupt => Some("INPUT_DIGEST_MISMATCH"),
            }
        };
        if let Some(code) = expected {
            assert_eq!(result.unwrap_err().code, code);
            assert_eq!(
                reads.get(),
                if conflict != 0 || decimal || limited {
                    0
                } else {
                    1
                }
            );
        } else {
            result.unwrap();
            assert_eq!(reads.get(), 1);
            assert_eq!(projection.resource_pins.len(), 1);
            assert_eq!(projection.resource_pins[0].resource_id, mesh.resource_id);
            assert_eq!(projection.resource_pins[0].sha256, mesh.sha256);
            assert_eq!(sources.resources.len(), 1);
            assert_eq!(
                sources.resources.values().next().unwrap().sha256,
                mesh.sha256
            );
        }
    }
}

#[test]
fn physics_mesh_resource_comparison_rejects_decimal_and_invalid_shape() {
    use crate::preparation::physics_mesh_resources;
    let mut physics =
        parse_json(include_bytes!("../../../examples/physics-definition.json")).unwrap();
    let geometry = json!({"resourceId":"resource-physics-mesh","sha256":mmmm_contracts::raw_digest(b"x"),"mediaType":"application/octet-stream","sizeBytes":1});
    physics["colliders"][0]["shape"]["shape"] =
        json!({"kind":"mesh","geometry":geometry,"topologyDigest":"0".repeat(64)});
    assert_eq!(physics_mesh_resources(&physics).unwrap().len(), 1);

    let mut decimal = physics.clone();
    decimal["colliders"][0]["shape"]["shape"]["geometry"]["sizeBytes"] = json!(1.0);
    assert_eq!(
        physics_mesh_resources(&decimal).unwrap_err().code,
        "CAPABILITY_UNAVAILABLE"
    );
    let rounded = parse_json(br#"{"sizeBytes":1.0000000000000001}"#).unwrap();
    assert_eq!(rounded["sizeBytes"], json!(1.0));
    decimal["colliders"][0]["shape"]["shape"]["geometry"]["sizeBytes"] =
        rounded["sizeBytes"].clone();
    assert_eq!(
        physics_mesh_resources(&decimal).unwrap_err().code,
        "CAPABILITY_UNAVAILABLE"
    );

    let mut malformed = physics.clone();
    malformed["colliders"][0]["shape"]["shape"]["kind"] = json!("unknown");
    assert!(physics_mesh_resources(&malformed).is_err());
    let mut missing_shape = physics.clone();
    missing_shape["colliders"][0]["shape"]
        .as_object_mut()
        .unwrap()
        .remove("shape");
    assert!(physics_mesh_resources(&missing_shape).is_err());

    let mut duplicate = physics.clone();
    let mut other = duplicate["colliders"][0].clone();
    other["colliderId"] = json!("collider-other");
    other["shape"]["shape"]["geometry"]["mediaType"] = json!("application/json");
    duplicate["colliders"].as_array_mut().unwrap().push(other);
    assert_eq!(
        physics_mesh_resources(&duplicate).unwrap_err().code,
        "REVISION_CONFLICT"
    );
}

// Controlled source observes the actual Planner call only; it does not claim
// Coordinator authority, a real state codec, a completed clone or a game.
struct SnapshotSource {
    instance: serde_json::Value,
    prefab: serde_json::Value,
    prefab_bytes: Vec<u8>,
    calls: std::rc::Rc<std::cell::Cell<usize>>,
    deny: bool,
}

impl ProjectSourcePort for SnapshotSource {
    fn inspect_owned(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: u64,
    ) -> mmmm_application::AppResult<Vec<(ObjectPin, serde_json::Value)>> {
        mesh_unexpected()
    }
    fn owned_object(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        pin: &ObjectPin,
        _: Option<&serde_json::Value>,
        _: u64,
    ) -> mmmm_application::AppResult<serde_json::Value> {
        assert_eq!(pin.kind, OwnedKind::Instance);
        Ok(self.instance.clone())
    }
    fn owned_object_bytes(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        pin: &ObjectPin,
        _: Option<&serde_json::Value>,
        _: u64,
    ) -> mmmm_application::AppResult<Option<PinnedOwnedObjectBytes>> {
        assert_eq!(pin.kind, OwnedKind::Prefab);
        Ok(Some(PinnedOwnedObjectBytes {
            value: self.prefab.clone(),
            bytes: self.prefab_bytes.clone(),
            digest: mmmm_contracts::raw_digest(&self.prefab_bytes),
        }))
    }
    fn check_owned_source(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        pin: &ObjectPin,
        _: Option<&serde_json::Value>,
    ) -> mmmm_application::AppResult<()> {
        assert_eq!(pin.kind, OwnedKind::Prefab);
        Ok(())
    }
    fn checkpoint_source(&mut self) -> mmmm_application::AppResult<()> {
        Ok(())
    }
    fn resource_pin(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &str,
        _: Option<&serde_json::Value>,
    ) -> mmmm_application::AppResult<mmmm_domain::types::ResourceRef> {
        mesh_unexpected()
    }
    fn resource_bytes(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &mmmm_domain::types::ResourceRef,
        _: Option<&serde_json::Value>,
        _: u64,
    ) -> mmmm_application::AppResult<PinnedResourceBytes> {
        mesh_unexpected()
    }
    fn stage_private(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: Option<&mmmm_contracts::ResourceId>,
        _: &[u8],
        _: &str,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<mmmm_domain::types::ResourceRef> {
        mesh_unexpected()
    }
    fn allocate_instance_id(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &std::collections::BTreeSet<mmmm_contracts::InstanceId>,
    ) -> mmmm_application::AppResult<mmmm_contracts::InstanceId> {
        Ok(mmmm_contracts::InstanceId::new("instance-snapshot-clone").unwrap())
    }
    fn state_snapshot(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        instance: &serde_json::Value,
        prefab: &serde_json::Value,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<PinnedStateSnapshot> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(instance, &self.instance);
        assert_eq!(prefab, &self.prefab);
        Err(if self.deny {
            AppError::new("FORBIDDEN", "snapshot source scope denied")
        } else {
            AppError::new(
                "TEST_SNAPSHOT_SOURCE_REACHED",
                "original source values reached the controlled port",
            )
        })
    }
    fn scene_source(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &serde_json::Value,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<SceneSource> {
        mesh_unexpected()
    }
    fn validate_scene_provenance(
        &mut self,
        _: &mmmm_contracts::PrincipalId,
        _: &ProjectCatalog,
        _: &serde_json::Value,
        _: &SceneSource,
        _: &serde_json::Value,
    ) -> mmmm_application::AppResult<()> {
        mesh_unexpected()
    }
}

#[test]
fn clone_snapshot_receives_original_validated_values_and_preserves_port_error() {
    use std::{cell::Cell, rc::Rc};
    let mut prefab = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
    let size = prefab["resources"][0]["sizeBytes"].as_u64().unwrap();
    prefab["resources"][0]["sizeBytes"] = json!(size as f64);
    prefab["revision"] = json!(projected_digest("Prefab", &prefab).unwrap());
    let prefab_bytes = serde_json::to_vec(&prefab).unwrap();
    let mut instance = parse_json(include_bytes!("../../../examples/instance.json")).unwrap();
    instance["placement"]["translation"][0] = json!(1);
    instance["prefabRevision"] = prefab["revision"].clone();
    instance["revision"] = json!(projected_digest("Instance", &instance).unwrap());
    let mut project = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
    for pin in project["ownedResources"].as_array_mut().unwrap() {
        if pin["kind"] == "prefab" && pin["objectId"] == prefab["prefabId"] {
            pin["revision"] = prefab["revision"].clone();
        }
        if pin["kind"] == "instance" && pin["objectId"] == instance["instanceId"] {
            pin["revision"] = instance["revision"].clone();
        }
    }
    project["revision"] = json!(projected_digest("Project", &project).unwrap());
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    let typed_prefab = decode_prefab_scoped(&prefab, || Ok(())).unwrap();
    let typed_instance: mmmm_domain::Instance = decode("Instance", &instance).unwrap();
    assert_ne!(wire("Prefab", &typed_prefab).unwrap(), prefab);
    assert_ne!(wire("Instance", &typed_instance).unwrap(), instance);

    for deny in [false, true] {
        let calls = Rc::new(Cell::new(0));
        let source = SnapshotSource {
            instance: instance.clone(),
            prefab: prefab.clone(),
            prefab_bytes: prefab_bytes.clone(),
            calls: calls.clone(),
            deny,
        };
        let mut planner = NativePlanner::new(
            Box::new(source),
            Box::new(MeshEnvironment),
            Box::new(mmmm_application::SystemClock),
            PlannerOptions::default(),
        )
        .unwrap();
        let intent = json!({"kind":"instance.clone","instanceId":instance["instanceId"],"expectedRevision":instance["revision"],
            "placement":instance["placement"],"statePolicy":"explicit_snapshot","externalReferencePolicy":"preserve"});
        let result = planner.prepare_change(
            &mmmm_contracts::PrincipalId::new("principal-snapshot-test").unwrap(),
            &intent,
            &catalog,
            &json!({}),
        );
        let error = match result {
            Ok(_) => panic!("controlled snapshot port must stop preparation"),
            Err(error) => error,
        };
        assert_eq!(
            error.code,
            if deny {
                "FORBIDDEN"
            } else {
                "TEST_SNAPSHOT_SOURCE_REACHED"
            }
        );
        assert_eq!(calls.get(), 1);
    }
    let missing = crate::preparation::Sources::default();
    let pin = catalog
        .owned_pin(
            OwnedKind::Instance,
            instance["instanceId"].as_str().unwrap(),
        )
        .unwrap();
    assert_eq!(
        missing
            .retained_object(OwnedKind::Instance, pin.object_id.as_str(), &pin.revision)
            .unwrap_err()
            .code,
        "SOURCE_PROVENANCE_INVALID"
    );
}

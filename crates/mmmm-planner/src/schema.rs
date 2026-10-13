//! Closed input contract for the internal registered native action payload.
//!
//! This validates a prepared value's shape independently of Rust serialization.
//! Source provenance, ID/revision equality, authority, target observations and
//! semantic effect checks remain the authenticated planner/host's obligations.
//! Referenced canonical definitions keep the original schema as their authority.

use crate::{NativeKind, OwnedKind};
use mmmm_contracts::CANONICAL_SCHEMA_ID;
use serde_json::{Value, json};

/// Internal action envelope discriminator; this is not a Project wire version.
pub const NATIVE_CHANGE_FORMAT: &str = "mmmm-native-change/1";
pub const PREPARED_CHANGE_MEDIA_TYPE: &str = "application/vnd.mmmm.prepared-change+json";

/// Original Invocation.arguments contains only this immutable private CAS pin.
/// The composite Rust provider authenticates access and validates the exact
/// referenced bytes using prepared_native_change_schema before native lowering.
pub fn native_action_input_schema() -> Value {
    let mut schema = closed_object(
        json!({"preparedChange": canonical("ResourceRef")}),
        &["preparedChange"],
    );
    schema["$schema"] = json!("https://json-schema.org/draft/2020-12/schema");
    schema
}

/// Draft 2020-12 schema for `{ "change": PreparedNativeChange }`. The schema
/// has no credential, permission, endpoint, receiver or live-readiness fields.
/// This is an internal CAS payload schema. Registrations use the small immutable
/// reference envelope returned by native_action_input_schema instead.
pub fn prepared_native_change_schema() -> Value {
    let document_variants: Vec<Value> = [
        (OwnedKind::Prefab, "prefab"),
        (OwnedKind::Instance, "instance"),
        (OwnedKind::CommandModule, "command_module"),
        (OwnedKind::Clip, "clip"),
        (OwnedKind::Asset, "asset"),
        (OwnedKind::PhysicsDefinition, "physics_definition"),
    ]
    .into_iter()
    .map(|(kind, wire)| {
        closed_object(
            json!({
                "kind": {"const": wire},
                "objectId": canonical("Project/properties/ownedResources/items/properties/objectId"),
                "beforeRevision": nullable(canonical("Project/properties/revision")),
                "afterRevision": canonical("Project/properties/revision"),
                "after": canonical(kind.definition())
            }),
            &["kind", "objectId", "afterRevision", "after"],
        )
    })
    .collect();

    let native_kinds: Vec<&str> = [
        NativeKind::Instantiate,
        NativeKind::Clone,
        NativeKind::Relocate,
        NativeKind::DisplayPatch,
        NativeKind::CommandPatch,
        NativeKind::ClipRetime,
        NativeKind::PackBuild,
        NativeKind::ResourcePatch,
        NativeKind::ScenePatch,
        NativeKind::Recovery,
    ]
    .into_iter()
    .map(NativeKind::wire)
    .collect();

    let mut schema = closed_object(
        json!({"change": local("preparedNativeChange")}),
        &["change"],
    );
    schema["$schema"] = json!("https://json-schema.org/draft/2020-12/schema");
    schema["$defs"] = json!({
        "documentChange": {"oneOf": document_variants},
        "instanceProjection": closed_object(json!({
            "before": nullable(canonical("Instance")),
            "beforeDefinition": nullable(canonical("Prefab")),
            "after": canonical("Instance"),
            "definition": canonical("Prefab"),
            "commandModules": bounded_array(canonical("CommandModule"), 4096),
            "clips": bounded_array(canonical("AnimationClip"), 4096),
            "physicsDefinitions": bounded_array(canonical("PhysicsDefinition"), 4096),
            "resourcePins": bounded_array(canonical("ResourceRef"), 4096)
        }), &["beforeDefinition", "after", "definition", "commandModules", "clips", "physicsDefinitions", "resourcePins"]),
        "resourceReplacement": closed_object(json!({
            "targetResourceId": canonical("ResourceRef/properties/resourceId"),
            "before": canonical("ResourceRef"),
            "replacementSource": canonical("ResourceRef")
        }), &["targetResourceId", "before", "replacementSource"]),
        "recoveryReplacement": closed_object(json!({
            "target": canonical("Precondition/properties/subject"),
            "beforeResource": canonical("ResourceRef"),
            "expectedCurrentSha256": canonical("ResourceRef/properties/sha256"),
            "sourceStepIds": bounded_array(canonical("PlanStep/properties/stepId"), 4096)
        }), &["target", "beforeResource", "expectedCurrentSha256", "sourceStepIds"]),
        "objectPin": canonical("Project/properties/ownedResources/items"),
        "preparedNativeChange": closed_object(json!({
            "format": {"const": NATIVE_CHANGE_FORMAT},
            "kind": {"enum": native_kinds},
            "projectId": canonical("Project/properties/projectId"),
            "projectBaseRevision": canonical("Project/properties/revision"),
            "targetProfileId": canonical("Project/properties/targetProfileId"),
            "projectAfter": canonical("Project"),
            "documentChanges": bounded_array(local("documentChange"), 4096),
            "worldProjection": bounded_array(local("instanceProjection"), 4096),
            "resourceReplacements": bounded_array(local("resourceReplacement"), 4096),
            "recoveryReplacements": bounded_array(local("recoveryReplacement"), 4096),
            "sourceObjectPins": bounded_array(local("objectPin"), 4096),
            "sourceResourcePins": bounded_array(canonical("ResourceRef"), 4096),
            "stagedResources": bounded_array(canonical("ResourceRef"), 4096),
            "scenePatch": nullable(canonical("ScenePatch")),
            "packManifest": nullable(canonical("ExportManifest")),
            "lossRecords": bounded_array(canonical("LossRecord"), 1024)
        }), &[
            "format", "kind", "projectId", "projectBaseRevision", "targetProfileId",
            "projectAfter", "documentChanges", "worldProjection", "resourceReplacements",
            "recoveryReplacements", "sourceObjectPins", "sourceResourcePins",
            "stagedResources", "lossRecords"
        ])
    });
    schema
}

fn canonical(definition_pointer: &str) -> Value {
    json!({"$ref": format!("{CANONICAL_SCHEMA_ID}#/$defs/{definition_pointer}")})
}

fn local(definition: &str) -> Value {
    json!({"$ref": format!("#/$defs/{definition}")})
}

fn nullable(schema: Value) -> Value {
    json!({"anyOf": [schema, {"type": "null"}]})
}

fn bounded_array(items: Value, maximum: usize) -> Value {
    json!({"type": "array", "items": items, "maxItems": maximum})
}

fn closed_object(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object", "properties": properties,
        "required": required, "additionalProperties": false
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mmmm_contracts::{ContractValidator, OfflineActionSchema, parse_json};

    fn compiled() -> OfflineActionSchema {
        ContractValidator::shared()
            .unwrap()
            .compile_action_schema(&prepared_native_change_schema())
            .unwrap()
    }

    #[test]
    fn action_envelope_is_only_one_immutable_resource_pin() {
        let schema = ContractValidator::shared()
            .unwrap()
            .compile_action_schema(&native_action_input_schema())
            .unwrap();
        let reference = json!({"resourceId":"prepared-private","sha256":"0".repeat(64),"mediaType":PREPARED_CHANGE_MEDIA_TYPE,"sizeBytes":1});
        let valid = json!({"preparedChange":reference});
        schema.validate(&valid).unwrap();
        assert!(schema.validate(&input()).is_err());
        let mut changed = valid;
        changed["scope"] = json!({});
        assert!(schema.validate(&changed).is_err());
    }

    fn input() -> Value {
        let project = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
        json!({"change": {
            "format": NATIVE_CHANGE_FORMAT,
            "kind": "clip.retime",
            "projectId": project["projectId"],
            "projectBaseRevision": project["revision"],
            "targetProfileId": project["targetProfileId"],
            "projectAfter": project,
            "documentChanges": [],
            "worldProjection": [],
            "resourceReplacements": [],
            "recoveryReplacements": [],
            "sourceObjectPins": [],
            "sourceResourcePins": [],
            "stagedResources": [],
            "scenePatch": null,
            "packManifest": null,
            "lossRecords": []
        }})
    }

    fn document(kind: OwnedKind, bytes: &[u8]) -> Value {
        let after = parse_json(bytes).unwrap();
        json!({
            "kind": kind,
            "objectId": after[kind.id_field()],
            "beforeRevision": null,
            "afterRevision": after["revision"],
            "after": after
        })
    }

    #[test]
    fn independent_closed_schema_accepts_each_native_kind_and_optional_nulls() {
        let schema = compiled();
        for kind in [
            "prefab.instantiate",
            "instance.clone",
            "instance.relocate",
            "display.patch",
            "command_module.patch",
            "clip.retime",
            "pack.build",
            "resource.patch",
            "scene.import_patch",
            "recovery.plan",
        ] {
            let mut value = input();
            value["change"]["kind"] = json!(kind);
            schema.validate(&value).unwrap();
            value["change"]
                .as_object_mut()
                .unwrap()
                .remove("scenePatch");
            value["change"]
                .as_object_mut()
                .unwrap()
                .remove("packManifest");
            schema.validate(&value).unwrap();
        }
    }

    #[test]
    fn document_kind_constrains_after_to_its_original_canonical_definition() {
        let schema = compiled();
        for (kind, bytes) in [
            (
                OwnedKind::Prefab,
                include_bytes!("../../../examples/prefab.json").as_slice(),
            ),
            (
                OwnedKind::Instance,
                include_bytes!("../../../examples/instance.json").as_slice(),
            ),
            (
                OwnedKind::CommandModule,
                include_bytes!("../../../examples/command-module.json").as_slice(),
            ),
            (
                OwnedKind::Clip,
                include_bytes!("../../../examples/animation-clip.json").as_slice(),
            ),
            (
                OwnedKind::Asset,
                include_bytes!("../../../examples/asset.json").as_slice(),
            ),
            (
                OwnedKind::PhysicsDefinition,
                include_bytes!("../../../examples/physics-definition.json").as_slice(),
            ),
        ] {
            let mut value = input();
            value["change"]["documentChanges"] = json!([document(kind, bytes)]);
            schema.validate(&value).unwrap();
            value["change"]["documentChanges"][0]
                .as_object_mut()
                .unwrap()
                .remove("beforeRevision");
            schema.validate(&value).unwrap();
            value["change"]["documentChanges"][0]["kind"] = if kind == OwnedKind::Asset {
                json!("prefab")
            } else {
                json!("asset")
            };
            assert!(schema.validate(&value).is_err());
        }
    }

    #[test]
    fn projection_and_source_pins_validate_original_shapes_and_nominal_ids() {
        let schema = compiled();
        let instance = parse_json(include_bytes!("../../../examples/instance.json")).unwrap();
        let definition = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
        let module = parse_json(include_bytes!("../../../examples/command-module.json")).unwrap();
        let clip = parse_json(include_bytes!("../../../examples/animation-clip.json")).unwrap();
        let asset = parse_json(include_bytes!("../../../examples/asset.json")).unwrap();
        let physics =
            parse_json(include_bytes!("../../../examples/physics-definition.json")).unwrap();
        let mut value = input();
        value["change"]["worldProjection"] = json!([{
            "before": null, "beforeDefinition": null, "after": instance, "definition": definition,
            "commandModules": [module], "clips": [clip], "physicsDefinitions": [physics], "resourcePins": [asset["resource"]]
        }]);
        value["change"]["sourceObjectPins"] =
            value["change"]["projectAfter"]["ownedResources"].clone();
        value["change"]["sourceResourcePins"] = json!([asset["resource"]]);
        schema.validate(&value).unwrap();
        value["change"]["worldProjection"][0]
            .as_object_mut()
            .unwrap()
            .remove("before");
        schema.validate(&value).unwrap();
        let mut invalid = value.clone();
        invalid["change"]["worldProjection"][0]
            .as_object_mut()
            .unwrap()
            .remove("beforeDefinition");
        assert!(schema.validate(&invalid).is_err());
        let mut invalid = value.clone();
        invalid["change"]["worldProjection"][0]
            .as_object_mut()
            .unwrap()
            .remove("physicsDefinitions");
        assert!(schema.validate(&invalid).is_err());
        let mut invalid = value.clone();
        invalid["change"]["sourceObjectPins"][0]["objectId"] = json!("UPPERCASE");
        assert!(schema.validate(&invalid).is_err());
        let mut invalid = value.clone();
        invalid["change"]["sourceObjectPins"][0]["revision"] = json!("not-a-digest");
        assert!(schema.validate(&invalid).is_err());
        let mut invalid = value;
        invalid["change"]["sourceObjectPins"][0]["grant"] = json!("world.write");
        assert!(schema.validate(&invalid).is_err());
    }

    #[test]
    fn envelope_discriminator_closed_records_and_required_fields_are_enforced() {
        let schema = compiled();
        for (pointer, replacement) in [
            ("/change/format", json!("mmmm-native-change/2")),
            ("/change/kind", json!("external.action")),
            ("/change/projectId", json!("InvalidProject")),
            ("/change/projectBaseRevision", json!("0")),
            ("/change/scenePatch", json!({})),
            ("/change/packManifest", json!({})),
        ] {
            let mut invalid = input();
            *invalid.pointer_mut(pointer).unwrap() = replacement;
            assert!(schema.validate(&invalid).is_err(), "{pointer}");
        }
        let mut invalid = input();
        invalid["worldWriteApproved"] = json!(true);
        assert!(schema.validate(&invalid).is_err());
        let mut invalid = input();
        invalid["change"]["endpoint"] = json!("unregistered:receiver");
        assert!(schema.validate(&invalid).is_err());
        let required: Vec<String> =
            prepared_native_change_schema()["$defs"]["preparedNativeChange"]["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|name| name.as_str().unwrap().to_owned())
                .collect();
        for name in required {
            let mut invalid = input();
            invalid["change"].as_object_mut().unwrap().remove(&name);
            assert!(schema.validate(&invalid).is_err(), "{name}");
        }
    }

    #[test]
    fn replacement_loss_and_optional_scene_records_remain_canonical_and_closed() {
        let schema = compiled();
        let asset = parse_json(include_bytes!("../../../examples/asset.json")).unwrap();
        let scene = parse_json(include_bytes!("../../../examples/scene-patch.json")).unwrap();
        let mut value = input();
        value["change"]["scenePatch"] = scene.clone();
        value["change"]["lossRecords"] = scene["losses"].clone();
        value["change"]["resourceReplacements"] = json!([{
            "targetResourceId": asset["resource"]["resourceId"],
            "before": asset["resource"], "replacementSource": asset["resource"]
        }]);
        value["change"]["recoveryReplacements"] = json!([{
            "target": "owned-resource:resource-wall-blocks",
            "beforeResource": asset["resource"],
            "expectedCurrentSha256": asset["resource"]["sha256"],
            "sourceStepIds": ["step-recorded-direct"]
        }]);
        schema.validate(&value).unwrap();
        let mut invalid = value.clone();
        invalid["change"]["recoveryReplacements"][0]["sourceStepIds"] = json!(["not a step id"]);
        assert!(schema.validate(&invalid).is_err());
        let mut invalid = value;
        invalid["change"]["resourceReplacements"][0]["command"] = json!("unplanned command");
        assert!(schema.validate(&invalid).is_err());
    }

    #[test]
    fn prepared_array_budgets_are_schema_constraints() {
        let schema = compiled();
        let asset = parse_json(include_bytes!("../../../examples/asset.json")).unwrap();
        let resource = asset["resource"].clone();
        let mut value = input();
        // Existing fixtures contain small arrays. Repeating one immutable ref
        // in memory isolates the 4096 boundary without a large disk fixture.
        value["change"]["stagedResources"] = json!(vec![resource.clone(); 4096]);
        schema.validate(&value).unwrap();
        value["change"]["stagedResources"] = json!(vec![resource; 4097]);
        assert!(schema.validate(&value).is_err());
    }
}

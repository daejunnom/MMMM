use crate::{ObjectPin, OwnedKind, validate};
use mmmm_application::{AppError, AppResult};
use mmmm_contracts::{
    ActionId, BindingId, CapabilityId, InstanceId, ProjectId, ResourceId, Sha256Digest,
    TargetProfileId,
};
use mmmm_domain::{
    Instance, Prefab, commands::CommandModule, time::AnimationClip, types::ResourceRef,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NativeKind {
    #[serde(rename = "prefab.instantiate")]
    Instantiate,
    #[serde(rename = "instance.clone")]
    Clone,
    #[serde(rename = "instance.relocate")]
    Relocate,
    #[serde(rename = "display.patch")]
    DisplayPatch,
    #[serde(rename = "command_module.patch")]
    CommandPatch,
    #[serde(rename = "clip.retime")]
    ClipRetime,
    #[serde(rename = "pack.build")]
    PackBuild,
    #[serde(rename = "resource.patch")]
    ResourcePatch,
    #[serde(rename = "scene.import_patch")]
    ScenePatch,
    #[serde(rename = "recovery.plan")]
    Recovery,
}

impl NativeKind {
    pub fn world_effect(self) -> bool {
        matches!(
            self,
            Self::Instantiate
                | Self::Clone
                | Self::Relocate
                | Self::DisplayPatch
                | Self::CommandPatch
                | Self::ScenePatch
        )
    }
    pub fn wire(self) -> &'static str {
        match self {
            Self::Instantiate => "prefab.instantiate",
            Self::Clone => "instance.clone",
            Self::Relocate => "instance.relocate",
            Self::DisplayPatch => "display.patch",
            Self::CommandPatch => "command_module.patch",
            Self::ClipRetime => "clip.retime",
            Self::PackBuild => "pack.build",
            Self::ResourcePatch => "resource.patch",
            Self::ScenePatch => "scene.import_patch",
            Self::Recovery => "recovery.plan",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentChange {
    pub kind: OwnedKind,
    pub object_id: String,
    pub before_revision: Option<Sha256Digest>,
    pub after_revision: Sha256Digest,
    /// Canonical named DTO; not arbitrary JSON patch instructions.
    pub after: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstanceProjection {
    pub before: Option<Instance>,
    pub before_definition: Option<Prefab>,
    pub after: Instance,
    pub definition: Prefab,
    pub command_modules: Vec<CommandModule>,
    pub clips: Vec<AnimationClip>,
    pub physics_definitions: Vec<Value>,
    pub resource_pins: Vec<ResourceRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceReplacement {
    pub target_resource_id: ResourceId,
    pub before: ResourceRef,
    pub replacement_source: ResourceRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryReplacement {
    pub target: String,
    pub before_resource: ResourceRef,
    pub expected_current_sha256: Sha256Digest,
    pub source_step_ids: Vec<String>,
}

/// A closed immutable CAS payload prepared by Rust. The registered composite
/// action accepts its exact ResourceRef and revalidates these bytes; this is not
/// another stored project or public wire format. Opaque returned data cannot
/// select a receiver, endpoint, command or path.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedNativeChange {
    pub format: String,
    pub kind: NativeKind,
    pub project_id: ProjectId,
    pub project_base_revision: Sha256Digest,
    pub target_profile_id: TargetProfileId,
    pub project_after: Value,
    pub document_changes: Vec<DocumentChange>,
    pub world_projection: Vec<InstanceProjection>,
    pub resource_replacements: Vec<ResourceReplacement>,
    pub recovery_replacements: Vec<RecoveryReplacement>,
    pub source_object_pins: Vec<ObjectPin>,
    pub source_resource_pins: Vec<ResourceRef>,
    pub staged_resources: Vec<ResourceRef>,
    pub scene_patch: Option<Value>,
    pub pack_manifest: Option<Value>,
    pub loss_records: Vec<Value>,
}

impl PreparedNativeChange {
    /// Decode bounded CAS data, checking closed schema, identity and revision
    /// invariants. The caller must separately authenticate raw CAS bytes, all
    /// sources, current policy/scope, and actual independent target observations.
    pub fn from_payload(value: &Value) -> AppResult<Self> {
        mmmm_contracts::encode_json(value).map_err(|_| {
            AppError::new(
                "BUDGET_EXCEEDED",
                "Prepared CAS payload exceeds its JSON budget",
            )
        })?;
        mmmm_contracts::ContractValidator::shared()
            .and_then(|validator| {
                validator.compile_action_schema(&crate::prepared_native_change_schema())
            })
            .and_then(|schema| schema.validate(value))
            .map_err(|_| {
                AppError::new(
                    "INVALID_INPUT",
                    "Prepared CAS payload violates its closed schema",
                )
            })?;
        // Inspect the original Value before the typed comparison copy rewrites
        // resource lengths. A rounded float is not an original-byte witness.
        reject_unwitnessed_physics_lengths(&value["change"])?;
        let mut typed = value["change"].clone();
        normalize_typed_resource_lengths(&mut typed);
        let change: Self = serde_json::from_value(typed)
            .map_err(|_| AppError::new("INVALID_INPUT", "Prepared CAS payload cannot be typed"))?;
        change.to_arguments()?;
        Ok(change)
    }

    /// Internal `{change: ...}` CAS payload. Invocation.arguments uses only
    /// `{preparedChange: ResourceRef}` and never receives this large object.
    pub fn to_arguments(&self) -> AppResult<Value> {
        if self.document_changes.len() > 4096
            || self.world_projection.len() > 4096
            || self.source_resource_pins.len() > 4096
            || self.source_object_pins.len() > 4096
            || self.resource_replacements.len() > 4096
            || self.recovery_replacements.len() > 4096
            || self.staged_resources.len() > 4096
            || self.world_projection.iter().any(|projection| {
                projection.command_modules.len() > 4096
                    || projection.clips.len() > 4096
                    || projection.resource_pins.len() > 4096
                    || projection.physics_definitions.len() > 4096
                    || projection.definition.nodes.len() > 16384
                    || projection
                        .before_definition
                        .as_ref()
                        .is_some_and(|definition| definition.nodes.len() > 16384)
            })
            || self.loss_records.len() > 1024
        {
            return Err(AppError::new(
                "BUDGET_EXCEEDED",
                "Prepared native change exceeds finite object limits",
            ));
        }
        validate("Project", &self.project_after)?;
        let project = crate::ProjectCatalog::from_project(&self.project_after)?;
        if project.project_id() != &self.project_id
            || project.target_profile_id() != &self.target_profile_id
        {
            return Err(AppError::new(
                "REVISION_CONFLICT",
                "Prepared project identity differs from its pinned authoring source",
            ));
        }
        let mut documents = BTreeSet::new();
        for change in &self.document_changes {
            validate(change.kind.definition(), &change.after)?;
            if !documents.insert((change.kind, &change.object_id))
                || crate::text(&change.after, change.kind.id_field())? != change.object_id
                || mmmm_contracts::verify_projected_digest(change.kind.definition(), &change.after)
                    .map_err(|_| {
                        AppError::new(
                            "REVISION_CONFLICT",
                            "Prepared document is not its actual self-digest",
                        )
                    })?
                    != change.after_revision
                || project.owned_pin(change.kind, &change.object_id)?.revision
                    != change.after_revision
            {
                return Err(AppError::new(
                    "REVISION_CONFLICT",
                    "Prepared document ID, digest or promoted project pin differs",
                ));
            }
            if change.kind == OwnedKind::PhysicsDefinition {
                crate::preparation::physics_mesh_resources(&change.after)?;
            }
        }
        self.validate_effect_shape()?;
        let mut projected_instances = BTreeSet::new();
        for projection in &self.world_projection {
            if !projected_instances.insert(&projection.after.instance_id) {
                return Err(AppError::new(
                    "ID_COLLISION",
                    "One instance has multiple prepared projections",
                ));
            }
            validate_projection_closure(projection)?;
            mmmm_domain::instance::require_source(&projection.after, &projection.definition)
                .map_err(crate::domain)?;
            mmmm_contracts::verify_projected_digest(
                "Instance",
                &crate::wire("Instance", &projection.after)?,
            )
            .map_err(|_| {
                AppError::new("REVISION_CONFLICT", "After instance self-digest differs")
            })?;
            mmmm_contracts::verify_projected_digest(
                "Prefab",
                &crate::wire("Prefab", &projection.definition)?,
            )
            .map_err(|_| {
                AppError::new("REVISION_CONFLICT", "After definition self-digest differs")
            })?;
            match (&projection.before, &projection.before_definition) {
                (Some(before), Some(definition)) => {
                    mmmm_domain::instance::require_source(before, definition)
                        .map_err(crate::domain)?;
                }
                (None, None) => {}
                _ => {
                    return Err(AppError::new(
                        "TARGET_UNVERIFIED",
                        "Before instance and definition pins must be present together",
                    ));
                }
            }
            if !self.document_changes.iter().any(|change| {
                change.kind == OwnedKind::Instance
                    && change.object_id == projection.after.instance_id.as_str()
                    && change.after_revision == projection.after.revision
            }) {
                return Err(AppError::new(
                    "REVISION_CONFLICT",
                    "World projection lacks its exact authored after instance mutation",
                ));
            }
            for module in &projection.command_modules {
                let value = crate::wire("CommandModule", module)?;
                mmmm_contracts::verify_projected_digest("CommandModule", &value).map_err(|_| {
                    AppError::new("REVISION_CONFLICT", "Command module self-digest differs")
                })?;
                if module.owner_prefab_id != projection.definition.prefab_id
                    || !projection
                        .definition
                        .command_module_ids
                        .contains(&module.module_id)
                {
                    return Err(AppError::new(
                        "REFERENCE_UNRESOLVED",
                        "Prepared command module is outside its definition ownership",
                    ));
                }
            }
            for clip in &projection.clips {
                let value = crate::wire("AnimationClip", clip)?;
                mmmm_contracts::verify_projected_digest("AnimationClip", &value).map_err(|_| {
                    AppError::new("REVISION_CONFLICT", "Animation clip self-digest differs")
                })?;
                if clip.owner_prefab_id != projection.definition.prefab_id
                    || !projection.definition.clip_ids.contains(&clip.clip_id)
                {
                    return Err(AppError::new(
                        "REFERENCE_UNRESOLVED",
                        "Prepared clip is outside its definition ownership",
                    ));
                }
            }
            for physics in &projection.physics_definitions {
                validate("PhysicsDefinition", physics)?;
                mmmm_contracts::verify_projected_digest("PhysicsDefinition", physics).map_err(
                    |_| {
                        AppError::new(
                            "REVISION_CONFLICT",
                            "Physics definition self-digest differs",
                        )
                    },
                )?;
                if !projection
                    .definition
                    .nodes
                    .iter()
                    .filter_map(|node| node.physics_binding.as_ref())
                    .any(|binding| {
                        physics["physicsId"].as_str() == Some(binding.physics_id.as_str())
                    })
                {
                    return Err(AppError::new(
                        "REFERENCE_UNRESOLVED",
                        "Prepared physics definition is not used by its instance projection",
                    ));
                }
            }
        }
        for replacement in &self.resource_replacements {
            if replacement.target_resource_id != replacement.before.resource_id {
                return Err(AppError::new(
                    "REVISION_CONFLICT",
                    "Resource replacement changes the requested target identity",
                ));
            }
        }
        for loss in &self.loss_records {
            validate("LossRecord", loss)?;
        }
        #[derive(Serialize)]
        struct Arguments<'a> {
            change: &'a PreparedNativeChange,
        }
        let mut writer = BoundedJsonWriter {
            bytes: Vec::new(),
            limit: 8 * 1024 * 1024,
        };
        serde_json::to_writer(&mut writer, &Arguments { change: self }).map_err(|_| {
            AppError::new(
                "BUDGET_EXCEEDED",
                "Prepared native action exceeds its encoded input limit",
            )
        })?;
        let value = mmmm_contracts::parse_json(&writer.bytes).map_err(|_| {
            AppError::new(
                "INVALID_INPUT",
                "Prepared native action cannot be decoded as strict JSON",
            )
        })?;
        mmmm_contracts::ContractValidator::shared()
            .and_then(|validator| {
                validator.compile_action_schema(&crate::prepared_native_change_schema())
            })
            .and_then(|schema| schema.validate(&value))
            .map_err(|_| {
                AppError::new(
                    "INVALID_INPUT",
                    "Prepared native action violates its closed input schema",
                )
            })?;
        mmmm_contracts::encode_json(&value).map_err(|_| {
            AppError::new(
                "BUDGET_EXCEEDED",
                "Prepared native action exceeds its encoded input limit",
            )
        })?;
        Ok(value)
    }
    pub fn object_ids(&self) -> BTreeSet<String> {
        let mut ids: BTreeSet<String> = self
            .document_changes
            .iter()
            .map(|change| change.object_id.clone())
            .chain(self.world_projection.iter().flat_map(|projection| {
                projection
                    .before
                    .iter()
                    .chain(std::iter::once(&projection.after))
                    .map(|instance| instance.instance_id.as_str().to_owned())
            }))
            .collect();
        if self.project_after["revision"].as_str() != Some(self.project_base_revision.as_str()) {
            ids.insert(self.project_id.to_string());
        }
        ids
    }
    pub fn resource_ids(&self) -> BTreeSet<ResourceId> {
        self.resource_replacements
            .iter()
            .map(|change| change.target_resource_id.clone())
            .chain(
                self.staged_resources
                    .iter()
                    .map(|resource| resource.resource_id.clone()),
            )
            .collect()
    }
    pub fn affected_instances(&self) -> BTreeSet<InstanceId> {
        self.world_projection
            .iter()
            .map(|projection| projection.after.instance_id.clone())
            .collect()
    }

    fn validate_effect_shape(&self) -> AppResult<()> {
        let invalid = || {
            AppError::new(
                "INVALID_INPUT",
                "Prepared effect is inconsistent with its closed native kind",
            )
        };
        if (!self.kind.world_effect() && !self.world_projection.is_empty())
            || (self.kind.world_effect() && self.world_projection.is_empty())
            || (self.kind != NativeKind::ResourcePatch && !self.resource_replacements.is_empty())
            || (self.kind != NativeKind::Recovery && !self.recovery_replacements.is_empty())
            || (self.kind != NativeKind::ScenePatch && self.scene_patch.is_some())
            || (self.kind != NativeKind::PackBuild && self.pack_manifest.is_some())
        {
            return Err(invalid());
        }
        match self.kind {
            NativeKind::Instantiate
            | NativeKind::Clone
            | NativeKind::Relocate
            | NativeKind::DisplayPatch => {
                if self.document_changes.len() != 1
                    || self.document_changes[0].kind != OwnedKind::Instance
                    || self.world_projection.len() != 1
                {
                    return Err(invalid());
                }
                let creating = matches!(self.kind, NativeKind::Instantiate | NativeKind::Clone);
                if self.world_projection[0].before.is_none() != creating
                    || self.document_changes[0].before_revision.is_none() != creating
                {
                    return Err(invalid());
                }
            }
            NativeKind::CommandPatch | NativeKind::ScenePatch => {
                if self
                    .document_changes
                    .iter()
                    .any(|document| document.kind == OwnedKind::Asset)
                    || self
                        .world_projection
                        .iter()
                        .any(|projection| projection.before.is_none())
                    || (self.kind == NativeKind::CommandPatch && self.world_projection.len() != 1)
                    || (self.kind == NativeKind::ScenePatch && self.scene_patch.is_none())
                {
                    return Err(invalid());
                }
            }
            NativeKind::ClipRetime => {
                if self.document_changes.len() != 1
                    || self.document_changes[0].kind != OwnedKind::Clip
                    || self.document_changes[0].before_revision.is_none()
                {
                    return Err(invalid());
                }
            }
            NativeKind::ResourcePatch | NativeKind::PackBuild | NativeKind::Recovery => {
                if !self.document_changes.is_empty()
                    || self.project_after["revision"].as_str()
                        != Some(self.project_base_revision.as_str())
                    || (self.kind == NativeKind::ResourcePatch
                        && self.resource_replacements.len() != 1)
                    || (self.kind == NativeKind::PackBuild && self.pack_manifest.is_none())
                    || (self.kind == NativeKind::Recovery && self.recovery_replacements.is_empty())
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}

// Only schema-owned ResourceRef fields deserialize into u64. Other Values,
// including display payloads and authored documents, remain opaque.
fn normalize_typed_resource_lengths(change: &mut Value) {
    fn list(value: Option<&mut Value>) {
        if let Some(values) = value.and_then(Value::as_array_mut) {
            for resource in values {
                crate::normalize_resource_lengths(resource);
            }
        }
    }
    fn prefab(value: Option<&mut Value>) {
        if let Some(prefab) = value.and_then(Value::as_object_mut) {
            list(prefab.get_mut("resources"));
            if let Some(nodes) = prefab.get_mut("nodes").and_then(Value::as_array_mut) {
                for node in nodes {
                    if let Some(resource) = node.get_mut("geometryResource") {
                        crate::normalize_resource_lengths(resource);
                    }
                }
            }
        }
    }
    if let Some(projections) = change
        .get_mut("worldProjection")
        .and_then(Value::as_array_mut)
    {
        for projection in projections {
            prefab(projection.get_mut("beforeDefinition"));
            prefab(projection.get_mut("definition"));
            list(projection.get_mut("resourcePins"));
        }
    }
    if let Some(replacements) = change
        .get_mut("resourceReplacements")
        .and_then(Value::as_array_mut)
    {
        for replacement in replacements {
            if let Some(before) = replacement.get_mut("before") {
                crate::normalize_resource_lengths(before);
            }
            if let Some(source) = replacement.get_mut("replacementSource") {
                crate::normalize_resource_lengths(source);
            }
        }
    }
    if let Some(replacements) = change
        .get_mut("recoveryReplacements")
        .and_then(Value::as_array_mut)
    {
        for replacement in replacements {
            if let Some(before) = replacement.get_mut("beforeResource") {
                crate::normalize_resource_lengths(before);
            }
        }
    }
    list(change.get_mut("sourceResourcePins"));
    list(change.get_mut("stagedResources"));
}

fn reject_unwitnessed_physics_lengths(change: &Value) -> AppResult<()> {
    fn check(physics: &Value) -> AppResult<()> {
        let has_decimal_mesh_length = physics["colliders"].as_array().is_some_and(|colliders| {
            colliders.iter().any(|collider| {
                let shape = &collider["shape"]["shape"];
                let size = &shape["geometry"]["sizeBytes"];
                shape["kind"] == "mesh" && size.is_number() && size.as_u64().is_none()
            })
        });
        if has_decimal_mesh_length {
            // Keep invalid physics a contract error before the decimal-only
            // limitation. Other shapes follow the existing receiver path.
            validate("PhysicsDefinition", physics)?;
            return Err(AppError::new(
                "CAPABILITY_UNAVAILABLE",
                "Physics mesh decimal length requires an original-byte witness",
            ));
        }
        Ok(())
    }

    for document in crate::scene::array(change, "documentChanges")? {
        if document["kind"] == "physics_definition" {
            check(&document["after"])?;
        }
    }
    for projection in crate::scene::array(change, "worldProjection")? {
        for physics in crate::scene::array(projection, "physicsDefinitions")? {
            check(physics)?;
        }
    }
    Ok(())
}

fn validate_projection_closure(projection: &InstanceProjection) -> AppResult<()> {
    let modules: BTreeSet<_> = projection
        .command_modules
        .iter()
        .map(|module| &module.module_id)
        .collect();
    let clips: BTreeSet<_> = projection.clips.iter().map(|clip| &clip.clip_id).collect();
    let physics: BTreeSet<_> = projection
        .physics_definitions
        .iter()
        .map(|definition| crate::text(definition, "physicsId"))
        .collect::<AppResult<_>>()?;
    let required_physics: BTreeSet<_> = projection
        .definition
        .nodes
        .iter()
        .filter_map(|node| node.physics_binding.as_ref())
        .map(|binding| binding.physics_id.as_str())
        .collect();
    if modules.len() != projection.command_modules.len()
        || clips.len() != projection.clips.len()
        || physics.len() != projection.physics_definitions.len()
        || modules != projection.definition.command_module_ids.iter().collect()
        || clips != projection.definition.clip_ids.iter().collect()
        || physics != required_physics
    {
        return Err(AppError::new(
            "REFERENCE_UNRESOLVED",
            "Prepared projection does not contain its exact complete typed dependency sets",
        ));
    }
    let resources: std::collections::BTreeMap<_, _> = projection
        .resource_pins
        .iter()
        .map(|resource| (&resource.resource_id, resource))
        .collect();
    for physics in &projection.physics_definitions {
        for required in crate::preparation::physics_mesh_resources(physics)? {
            if resources
                .get(&required.resource_id)
                .is_none_or(|actual| !crate::preparation::same_resource(actual, &required))
            {
                return Err(AppError::new(
                    "REFERENCE_UNRESOLVED",
                    "Prepared projection lacks its exact physics mesh resource pin",
                ));
            }
        }
    }
    if resources.len() != projection.resource_pins.len()
        || projection.definition.resources.iter().any(|required| {
            resources
                .get(&required.resource_id)
                .is_none_or(|actual| !crate::preparation::same_resource(actual, required))
        })
        || projection.definition.nodes.iter().any(|node| {
            node.block_geometry
                .as_ref()
                .is_some_and(|geometry| !resources.contains_key(&geometry.resource_id))
                || node.geometry_resource.as_ref().is_some_and(|required| {
                    resources
                        .get(&required.resource_id)
                        .is_none_or(|actual| !crate::preparation::same_resource(actual, required))
                })
                || node.display.as_ref().is_some_and(|display| {
                    display
                        .resource_refs
                        .iter()
                        .any(|id| !resources.contains_key(id))
                })
        })
        || projection
            .after
            .overrides
            .iter()
            .any(|override_value| match override_value {
                mmmm_domain::types::InstanceOverride::Display { display, .. } => display
                    .resource_refs
                    .iter()
                    .any(|id| !resources.contains_key(id)),
                _ => false,
            })
    {
        return Err(AppError::new(
            "REFERENCE_UNRESOLVED",
            "Prepared projection resource closure is missing, duplicated or changes an exact pin",
        ));
    }
    Ok(())
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    limit: usize,
}

#[cfg(test)]
mod allocation_tests {
    use super::*;

    fn payload_with_physics_mesh() -> Value {
        payload_with_physics_mesh_and_opaque(false)
    }

    fn payload_with_physics_mesh_and_opaque(with_opaque: bool) -> Value {
        use crate::preparation::{document, empty_change, update_project};
        use mmmm_contracts::{parse_json, projected_digest};
        use serde_json::json;

        let mesh = ResourceRef {
            resource_id: ResourceId::new("resource-physics-mesh").unwrap(),
            sha256: mmmm_contracts::raw_digest(b"mesh"),
            media_type: "application/octet-stream".into(),
            size_bytes: 4,
        };
        let mut physics =
            parse_json(include_bytes!("../../../examples/physics-definition.json")).unwrap();
        physics["colliders"][0]["shape"]["shape"] =
            json!({"kind":"mesh","geometry":mesh,"topologyDigest":"0".repeat(64)});
        physics["revision"] = json!(projected_digest("PhysicsDefinition", &physics).unwrap());

        let mut prefab = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
        let opaque = json!({"resourceId":"opaque-shape","sha256":"0".repeat(64),"mediaType":"application/json","sizeBytes":1.0});
        if with_opaque {
            prefab["nodes"][0]["extensions"]["test:opaque"] = opaque.clone();
            let geometry = prefab["resources"][0].clone();
            prefab["nodes"][0]["geometryResource"] = geometry;
        }
        let door = prefab["nodes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|node| node["nodeId"] == "door")
            .unwrap();
        door["physicsBinding"] = json!({"physicsId":"physics-door","bodyId":"body-door"});
        prefab["revision"] = json!(projected_digest("Prefab", &prefab).unwrap());
        let mut instance = parse_json(include_bytes!("../../../examples/instance.json")).unwrap();
        if with_opaque {
            instance["overrides"] = json!([{"kind":"display","nodeId":"door","display":{"kind":"item","payload":{"shape":opaque},"resourceRefs":[]}}]);
        }
        instance["prefabRevision"] = prefab["revision"].clone();
        instance["revision"] = json!(projected_digest("Instance", &instance).unwrap());
        let mut project = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
        for pin in project["ownedResources"].as_array_mut().unwrap() {
            if pin["kind"] == "prefab" && pin["objectId"] == prefab["prefabId"] {
                pin["revision"] = prefab["revision"].clone();
            } else if pin["kind"] == "instance" && pin["objectId"] == instance["instanceId"] {
                pin["revision"] = instance["revision"].clone();
            }
        }
        project["resourceIds"]
            .as_array_mut()
            .unwrap()
            .push(json!(mesh.resource_id));
        project["revision"] = json!(projected_digest("Project", &project).unwrap());
        let catalog = crate::ProjectCatalog::from_project(&project).unwrap();
        let definition: Prefab = crate::decode_prefab_scoped(&prefab, || Ok(())).unwrap();
        let instance_typed: Instance = crate::decode("Instance", &instance).unwrap();
        let module = parse_json(include_bytes!("../../../examples/command-module.json")).unwrap();
        let clip = parse_json(include_bytes!("../../../examples/animation-clip.json")).unwrap();
        let mut resources = definition.resources.clone();
        resources.push(mesh.clone());
        let projection = InstanceProjection {
            before: Some(instance_typed.clone()),
            before_definition: Some(definition.clone()),
            after: instance_typed,
            definition,
            command_modules: vec![crate::decode("CommandModule", &module).unwrap()],
            clips: vec![crate::decode("AnimationClip", &clip).unwrap()],
            physics_definitions: vec![physics.clone()],
            resource_pins: resources,
        };
        let mut change = empty_change(&catalog, NativeKind::ScenePatch);
        change
            .document_changes
            .push(document(OwnedKind::PhysicsDefinition, None, physics).unwrap());
        change.document_changes.push(
            document(
                OwnedKind::Instance,
                Some(serde_json::from_value(instance["revision"].clone()).unwrap()),
                instance.clone(),
            )
            .unwrap(),
        );
        change.world_projection.push(projection);
        change.source_resource_pins.push(mesh.clone());
        let entry = if with_opaque {
            json!({"kind":"update_display","instanceId":instance["instanceId"],"nodeId":"door",
                "display":{"kind":"item","payload":{"shape":opaque},"resourceRefs":[]}})
        } else {
            json!({"kind":"update_transform","instanceId":instance["instanceId"],"nodeId":"door","transform":prefab["nodes"][3]["transform"]})
        };
        change.scene_patch = Some(
            json!({"contractVersion":"0.2.0","patchId":"patch-mesh-test",
            "projectId":project["projectId"],"baseRevision":project["revision"],
            "sourceArtifact":mesh,"sourceMap":mesh,"entries":[entry],
            "losses":[],"absenceMeansDeletion":false}),
        );
        update_project(&mut change).unwrap();
        change.to_arguments().unwrap()
    }

    #[test]
    fn from_payload_preserves_opaque_values_and_converts_only_typed_resources() {
        let mut payload = payload_with_physics_mesh_and_opaque(true);
        for field in ["beforeDefinition", "definition"] {
            let definition = &mut payload["change"]["worldProjection"][0][field];
            let size = definition["resources"][0]["sizeBytes"].as_u64().unwrap();
            definition["resources"][0]["sizeBytes"] = serde_json::json!(size as f64);
            definition["nodes"][0]["geometryResource"]["sizeBytes"] =
                serde_json::json!(size as f64);
        }
        let projection = &mut payload["change"]["worldProjection"][0];
        for resource in projection["resourcePins"].as_array_mut().unwrap() {
            let size = resource["sizeBytes"].as_u64().unwrap();
            resource["sizeBytes"] = serde_json::json!(size as f64);
        }
        let source = &mut payload["change"]["sourceResourcePins"][0];
        source["sizeBytes"] = serde_json::json!(4.0);
        let staged = source.clone();
        payload["change"]["stagedResources"] = serde_json::json!([staged]);
        payload["change"]["scenePatch"]["sourceArtifact"]["sizeBytes"] = serde_json::json!(4.0);
        let decoded = PreparedNativeChange::from_payload(&payload).unwrap();
        let output = decoded.to_arguments().unwrap();
        for field in ["beforeDefinition", "definition"] {
            let definition = &output["change"]["worldProjection"][0][field];
            assert!(definition["resources"][0]["sizeBytes"].as_u64().is_some());
            assert!(
                definition["nodes"][0]["geometryResource"]["sizeBytes"]
                    .as_u64()
                    .is_some()
            );
            assert_eq!(
                definition["nodes"][0]["extensions"]["test:opaque"]["sizeBytes"],
                serde_json::json!(1.0)
            );
        }
        for field in ["before", "after"] {
            let size = &output["change"]["worldProjection"][0][field]["overrides"][0]["display"]["payload"]
                ["shape"]["sizeBytes"];
            assert_eq!(*size, serde_json::json!(1.0));
            assert!(size.as_u64().is_none());
        }
        assert_eq!(
            output["change"]["documentChanges"][1]["after"]["overrides"][0]["display"]["payload"]["shape"]
                ["sizeBytes"],
            serde_json::json!(1.0)
        );
        assert_eq!(
            output["change"]["scenePatch"]["entries"][0]["display"]["payload"]["shape"]["sizeBytes"],
            serde_json::json!(1.0)
        );
        assert_eq!(
            output["change"]["scenePatch"]["sourceArtifact"]["sizeBytes"],
            serde_json::json!(4.0)
        );
        assert!(
            output["change"]["worldProjection"][0]["resourcePins"][0]["sizeBytes"]
                .as_u64()
                .is_some()
        );
        assert_eq!(
            output["change"]["sourceResourcePins"][0]["sizeBytes"].as_u64(),
            Some(4)
        );
        assert_eq!(
            output["change"]["stagedResources"][0]["sizeBytes"].as_u64(),
            Some(4)
        );
    }

    #[test]
    fn from_payload_converts_replacement_resource_lengths() {
        use crate::preparation::empty_change;
        use serde_json::json;
        let project =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/project.json")).unwrap();
        let catalog = crate::ProjectCatalog::from_project(&project).unwrap();
        let resource = ResourceRef {
            resource_id: ResourceId::new("resource-replacement-test").unwrap(),
            sha256: mmmm_contracts::raw_digest(b"mesh"),
            media_type: "application/octet-stream".into(),
            size_bytes: 4,
        };
        let mut replacement = empty_change(&catalog, NativeKind::ResourcePatch);
        replacement.resource_replacements.push(ResourceReplacement {
            target_resource_id: resource.resource_id.clone(),
            before: resource.clone(),
            replacement_source: resource.clone(),
        });
        let mut payload = replacement.to_arguments().unwrap();
        payload["change"]["resourceReplacements"][0]["before"]["sizeBytes"] = json!(4.0);
        payload["change"]["resourceReplacements"][0]["replacementSource"]["sizeBytes"] = json!(4.0);
        let output = PreparedNativeChange::from_payload(&payload)
            .unwrap()
            .to_arguments()
            .unwrap();
        assert_eq!(
            output["change"]["resourceReplacements"][0]["before"]["sizeBytes"].as_u64(),
            Some(4)
        );
        assert_eq!(
            output["change"]["resourceReplacements"][0]["replacementSource"]["sizeBytes"].as_u64(),
            Some(4)
        );

        let mut recovery = empty_change(&catalog, NativeKind::Recovery);
        recovery.recovery_replacements.push(RecoveryReplacement {
            target: "owned-resource:resource-replacement-test".into(),
            before_resource: resource.clone(),
            expected_current_sha256: resource.sha256,
            source_step_ids: vec!["step-recorded-direct".into()],
        });
        let mut payload = recovery.to_arguments().unwrap();
        payload["change"]["recoveryReplacements"][0]["beforeResource"]["sizeBytes"] = json!(4.0);
        let output = PreparedNativeChange::from_payload(&payload)
            .unwrap()
            .to_arguments()
            .unwrap();
        assert_eq!(
            output["change"]["recoveryReplacements"][0]["beforeResource"]["sizeBytes"].as_u64(),
            Some(4)
        );
    }

    #[test]
    fn from_payload_rejects_unwitnessed_decimal_physics_in_projection_and_documents() {
        let payload = payload_with_physics_mesh();
        PreparedNativeChange::from_payload(&payload).unwrap();
        let rounded = mmmm_contracts::parse_json(br#"{"sizeBytes":4.0000000000000001}"#).unwrap();
        assert_eq!(rounded["sizeBytes"], serde_json::json!(4.0));
        for document in [false, true] {
            for value in [serde_json::json!(4.0), rounded["sizeBytes"].clone()] {
                let mut altered = payload.clone();
                let physics = if document {
                    &mut altered["change"]["documentChanges"][0]["after"]
                } else {
                    &mut altered["change"]["worldProjection"][0]["physicsDefinitions"][0]
                };
                physics["colliders"][0]["shape"]["shape"]["geometry"]["sizeBytes"] = value;
                assert_eq!(
                    PreparedNativeChange::from_payload(&altered)
                        .unwrap_err()
                        .code,
                    "CAPABILITY_UNAVAILABLE"
                );
            }
            let mut malformed = payload.clone();
            let physics = if document {
                &mut malformed["change"]["documentChanges"][0]["after"]
            } else {
                &mut malformed["change"]["worldProjection"][0]["physicsDefinitions"][0]
            };
            physics["colliders"][0]["shape"]["shape"]["kind"] = serde_json::json!("unknown");
            assert!(PreparedNativeChange::from_payload(&malformed).is_err());
        }
    }

    #[test]
    fn to_arguments_rejects_decimal_only_in_direct_physics_document() {
        let payload = payload_with_physics_mesh();
        let mut change = PreparedNativeChange::from_payload(&payload).unwrap();
        change.to_arguments().unwrap();
        let physics = change
            .document_changes
            .iter_mut()
            .find(|document| document.kind == OwnedKind::PhysicsDefinition)
            .unwrap();
        physics.after["colliders"][0]["shape"]["shape"]["geometry"]["sizeBytes"] =
            serde_json::json!(4.0);
        assert_eq!(
            change.to_arguments().unwrap_err().code,
            "CAPABILITY_UNAVAILABLE"
        );
    }

    #[test]
    fn escaped_serialization_is_bounded_before_allocating_the_full_json_value() {
        let mut writer = BoundedJsonWriter {
            bytes: Vec::new(),
            limit: 40,
        };
        let source = ["\"\\\n"; 24];
        assert!(serde_json::to_writer(&mut writer, &source).is_err());
        assert!(writer.bytes.len() <= writer.limit);
        let bytes_before = writer.bytes.clone();
        assert!(std::io::Write::write(&mut writer, &[0; 41]).is_err());
        assert_eq!(writer.bytes, bytes_before);
    }

    #[test]
    fn receiver_requires_exact_physics_mesh_resource_and_valid_shape() {
        let prefab =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
        let instance =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/instance.json")).unwrap();
        let module =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/command-module.json"))
                .unwrap();
        let clip =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/animation-clip.json"))
                .unwrap();
        let mut definition: Prefab = crate::decode("Prefab", &prefab).unwrap();
        definition
            .nodes
            .iter_mut()
            .find(|node| node.node_id.as_str() == "door")
            .unwrap()
            .physics_binding = Some(mmmm_domain::types::PhysicsBinding {
            physics_id: mmmm_contracts::PhysicsId::new("physics-door").unwrap(),
            body_id: mmmm_contracts::BodyId::new("body-door").unwrap(),
        });
        let mesh = ResourceRef {
            resource_id: ResourceId::new("resource-physics-mesh").unwrap(),
            sha256: mmmm_contracts::raw_digest(b"mesh"),
            media_type: "application/octet-stream".into(),
            size_bytes: 4,
        };
        let mut physics =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/physics-definition.json"))
                .unwrap();
        physics["colliders"][0]["shape"]["shape"] =
            serde_json::json!({"kind":"mesh","geometry":mesh,"topologyDigest":"0".repeat(64)});
        let mut projection = InstanceProjection {
            before: None,
            before_definition: None,
            after: crate::decode("Instance", &instance).unwrap(),
            resource_pins: definition.resources.clone(),
            definition,
            command_modules: vec![crate::decode("CommandModule", &module).unwrap()],
            clips: vec![crate::decode("AnimationClip", &clip).unwrap()],
            physics_definitions: vec![physics],
        };
        assert_eq!(
            validate_projection_closure(&projection).unwrap_err().code,
            "REFERENCE_UNRESOLVED"
        );
        projection.resource_pins.push(mesh.clone());
        validate_projection_closure(&projection).unwrap();
        let index = projection.resource_pins.len() - 1;
        for change in 0..3 {
            let mut altered = mesh.clone();
            match change {
                0 => altered.sha256 = mmmm_contracts::raw_digest(b"other"),
                1 => altered.media_type = "application/json".into(),
                _ => altered.size_bytes += 1,
            }
            projection.resource_pins[index] = altered;
            assert_eq!(
                validate_projection_closure(&projection).unwrap_err().code,
                "REFERENCE_UNRESOLVED"
            );
        }
        projection.resource_pins[index] = mesh;
        projection.physics_definitions[0]["colliders"][0]["shape"]["shape"]["kind"] =
            serde_json::json!("unknown");
        assert!(validate_projection_closure(&projection).is_err());
    }

    #[test]
    fn receiver_rejects_incomplete_dependency_closure_and_hidden_world_effects() {
        let prefab =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
        let instance =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/instance.json")).unwrap();
        let module =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/command-module.json"))
                .unwrap();
        let clip =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/animation-clip.json"))
                .unwrap();
        let definition: Prefab = crate::decode("Prefab", &prefab).unwrap();
        let mut projection = InstanceProjection {
            before: Some(crate::decode("Instance", &instance).unwrap()),
            before_definition: Some(definition.clone()),
            after: crate::decode("Instance", &instance).unwrap(),
            resource_pins: definition.resources.clone(),
            definition,
            command_modules: vec![crate::decode("CommandModule", &module).unwrap()],
            clips: vec![crate::decode("AnimationClip", &clip).unwrap()],
            physics_definitions: vec![],
        };
        validate_projection_closure(&projection).unwrap();
        let removed = projection.command_modules.pop().unwrap();
        assert_eq!(
            validate_projection_closure(&projection).unwrap_err().code,
            "REFERENCE_UNRESOLVED"
        );
        projection.command_modules.push(removed);
        projection.clips.push(projection.clips[0].clone());
        assert_eq!(
            validate_projection_closure(&projection).unwrap_err().code,
            "REFERENCE_UNRESOLVED"
        );
        projection.clips.pop();
        let project =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/project.json")).unwrap();
        let catalog = crate::ProjectCatalog::from_project(&project).unwrap();
        let mut change = crate::preparation::empty_change(&catalog, NativeKind::ClipRetime);
        change.world_projection.push(projection);
        assert_eq!(
            change.validate_effect_shape().unwrap_err().code,
            "INVALID_INPUT"
        );
    }
}
impl std::io::Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("native action byte budget"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// This catalog is authenticated registration configuration, never parsed from
/// the user intent. It selects one exact observed binding/action per native kind.
#[derive(Clone, Debug)]
pub struct NativeActionRoute {
    pub binding_id: BindingId,
    pub action_id: ActionId,
    pub semantic_kind: CapabilityId,
    pub required_guarantees: BTreeSet<String>,
    pub acceptable_loss_codes: BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub struct PlannerOptions {
    pub expiry_seconds: u32,
    pub time_budget_ms: u64,
    pub max_source_bytes: u64,
}
impl Default for PlannerOptions {
    fn default() -> Self {
        Self {
            expiry_seconds: 300,
            time_budget_ms: 30_000,
            max_source_bytes: 32 * 1024 * 1024,
        }
    }
}
impl PlannerOptions {
    pub(crate) fn validate(&self) -> AppResult<()> {
        if !(1..=3600).contains(&self.expiry_seconds)
            || !(1..=3_600_000).contains(&self.time_budget_ms)
            || self.max_source_bytes == 0
            || self.max_source_bytes > 256 * 1024 * 1024
        {
            return Err(AppError::new(
                "BUDGET_EXCEEDED",
                "Planner options exceed their finite range",
            ));
        }
        Ok(())
    }
}

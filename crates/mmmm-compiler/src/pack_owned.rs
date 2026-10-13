//! Composition of sealed scene/animation drafts. Caller-supplied inventory
//! labels cannot authorize or substitute for an implemented owned lowering.

use crate::{
    GeneratedFunctionContract, StagedResource, VerifiedTarget,
    animation::AnimationDraft,
    packs::{charge_metadata, function_path, insert_resource, validate_function_id},
    scene::SceneDraft,
};
use mmmm_contracts::{RationalTime, ResourceLocation, Sha256Digest, raw_digest};
use mmmm_domain::DomainError;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(crate) struct OwnedBundle {
    pub resources: BTreeMap<String, StagedResource>,
    pub resource_pack: BTreeMap<String, StagedResource>,
    pub contracts: BTreeMap<ResourceLocation, Vec<GeneratedFunctionContract>>,
    pub contract_sizes: BTreeMap<ResourceLocation, usize>,
    pub contract_bytes: usize,
    pub map_entries: Vec<Value>,
    pub map_bytes: usize,
    pub entries: BTreeMap<String, ResourceLocation>,
    pub defined: BTreeSet<ResourceLocation>,
    pub referenced: BTreeSet<ResourceLocation>,
    pub external: BTreeMap<ResourceLocation, Sha256Digest>,
    pub state: BTreeSet<String>,
    pub runtime: BTreeSet<String>,
    pub seals: Vec<Value>,
    pub calls: BTreeMap<ResourceLocation, Vec<ResourceLocation>>,
    pub line_costs: BTreeMap<ResourceLocation, usize>,
    pub losses: Vec<Value>,
    pub loss_bytes: usize,
    pub private_addresses: BTreeMap<String, String>,
}

pub(crate) fn prepare_owned(
    project: &Value,
    target: &VerifiedTarget,
    compiler: &Sha256Digest,
    scene: Option<&SceneDraft>,
    animations: &[AnimationDraft],
) -> Result<OwnedBundle, DomainError> {
    let mut output = OwnedBundle::default();
    let owned = project["ownedResources"]
        .as_array()
        .ok_or_else(|| error("SCHEMA_INVALID", "Project inventory absent"))?;
    if owned.len() > 4096 || animations.len() > 4096 {
        return Err(error(
            "NUMERIC_RANGE",
            "Owned source count exceeds finite budget",
        ));
    }
    let expected: BTreeSet<_> = owned
        .iter()
        .map(|item| {
            (
                item["kind"].as_str().unwrap_or_default().to_owned(),
                item["objectId"].as_str().unwrap_or_default().to_owned(),
                item["revision"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    if expected.len() != owned.len() {
        return Err(error("SCHEMA_INVALID", "Duplicate owned source identity"));
    }
    let expected_keys: BTreeSet<_> = expected.iter().map(|(kind, id, _)| (kind, id)).collect();
    if expected_keys.len() != expected.len() {
        return Err(error(
            "SCHEMA_INVALID",
            "Owned source identity has conflicting revisions",
        ));
    }
    // Check the aggregate before any resource bytes or contracts are cloned.
    let all_resources = scene
        .into_iter()
        .flat_map(|scene| {
            scene
                .resources()
                .values()
                .chain(scene.resource_pack_resources().values())
        })
        .chain(
            animations
                .iter()
                .flat_map(|animation| animation.resources().values()),
        );
    let mut preflight_bytes = 0usize;
    let mut preflight_count = 0usize;
    for resource in all_resources {
        preflight_bytes = preflight_bytes
            .checked_add(resource.bytes.len())
            .ok_or_else(|| error("NUMERIC_RANGE", "Owned resource size overflow"))?;
        preflight_count += 1;
        if preflight_bytes > 32 * 1024 * 1024 || preflight_count > 8192 {
            return Err(error(
                "NUMERIC_RANGE",
                "Owned resource aggregate exceeds finite budget before cloning",
            ));
        }
    }
    let generated_count = scene
        .map_or(0, |scene| scene.defined_functions().len())
        .saturating_add(
            animations
                .iter()
                .map(|animation| animation.resources().len())
                .sum::<usize>(),
        );
    if generated_count > 4096 {
        return Err(error(
            "NUMERIC_RANGE",
            "Combined owned function count exceeds budget before cloning",
        ));
    }
    let mut covered = BTreeSet::new();
    let external_count = scene
        .map_or(0, |scene| scene.external_functions().len())
        .saturating_add(
            animations
                .iter()
                .map(|animation| animation.external_functions().len())
                .sum::<usize>(),
        );
    let reference_count = scene
        .map_or(0, |scene| scene.referenced_functions().len())
        .saturating_add(
            animations
                .iter()
                .map(|animation| animation.referenced_functions().len())
                .sum::<usize>(),
        );
    if external_count > 8192 || reference_count > 16384 {
        return Err(error(
            "NUMERIC_RANGE",
            "Owned function references exceed finite budget before merging",
        ));
    }
    let mut binding_pairs = BTreeSet::new();
    let mut total_bytes = 0usize;
    if let Some(scene) = scene {
        check_pins(
            scene.compiler_digest(),
            scene.target_profile_digest(),
            scene.target_artifact_digest(),
            target,
            compiler,
        )?;
        if project["revision"] != scene.input_revision().as_str() {
            return Err(error(
                "REVISION_CONFLICT",
                "Scene draft belongs to a different immutable project revision",
            ));
        }
        for item in scene.covered_owned_sources() {
            covered.insert((
                item.kind.clone(),
                item.object_id.to_string(),
                item.revision.to_string(),
            ));
        }
        check_ids(project, "prefabIds", scene.prefab_ids())?;
        check_ids(project, "instanceIds", scene.instance_ids())?;
        check_ids(project, "resourceIds", scene.resource_ids())?;
        for (path, resource) in scene.resources() {
            check_resource(resource)?;
            insert_resource(
                &mut output.resources,
                &mut total_bytes,
                path.clone(),
                resource.clone(),
            )?;
        }
        for (path, resource) in scene.resource_pack_resources() {
            if !path.starts_with("assets/") {
                return Err(error(
                    "SCHEMA_INVALID",
                    "Resource pack content must be a verified assets path",
                ));
            }
            check_resource(resource)?;
            insert_resource(
                &mut output.resource_pack,
                &mut total_bytes,
                path.clone(),
                resource.clone(),
            )?;
        }
        for (id, contracts) in scene.function_contracts() {
            insert_contracts(&mut output, id, contracts)?;
        }
        for entry in scene.source_map_entries() {
            charge_metadata(&mut output.map_bytes, entry)?;
            output.map_entries.push(entry.clone());
        }
        output.entries.extend(scene.entry_points().clone());
        output
            .defined
            .extend(scene.defined_functions().iter().cloned());
        for id in scene.defined_functions() {
            output.calls.insert(id.clone(), Vec::new());
            output.line_costs.insert(
                id.clone(),
                scene.resources()[&function_path(id)]
                    .bytes
                    .iter()
                    .filter(|byte| **byte == b'\n')
                    .count(),
            );
        }
        output
            .referenced
            .extend(scene.referenced_functions().iter().cloned());
        for (id, digest) in scene.external_functions() {
            insert_external(&mut output.external, id, digest)?;
        }
        output.state.extend(scene.state_symbols().iter().cloned());
        for bindings in scene.state_bindings().values() {
            for binding in bindings.values() {
                let address = if binding.storage_kind == "scoreboard" {
                    format!("objective:{}", binding.objective)
                } else {
                    format!("storage:{}:{}", binding.storage, binding.key)
                };
                register_private_address(
                    &mut output.private_addresses,
                    address,
                    binding.qualified_state.clone(),
                )?;
            }
        }
        output
            .runtime
            .extend(scene.runtime_dependencies().iter().cloned());
        if scene.private_distribution_required() {
            output
                .runtime
                .insert("asset_redistribution_requires_private_distribution".into());
        }
        output.seals.push(json!({"scene":scene.input_revision(),"codec":scene.codec_digest(),
            "resources":scene.resources().iter().map(|(path,r)|json!({"path":path,"resource":r.reference})).collect::<Vec<_>>(),
            "resourcePack":scene.resource_pack_resources().iter().map(|(path,r)|json!({"path":path,"resource":r.reference})).collect::<Vec<_>>()}));
        for loss in scene.losses() {
            append_loss(&mut output, loss)?;
        }
    } else {
        for field in ["prefabIds", "instanceIds", "resourceIds"] {
            if project[field]
                .as_array()
                .is_none_or(|items| !items.is_empty())
            {
                return Err(error(
                    "UNOWNED_REQUIRED_CAPABILITY",
                    "Project scene inventory requires a sealed scene draft",
                ));
            }
        }
    }
    let mut ordered_animations: Vec<_> = animations.iter().collect();
    ordered_animations.sort_by(|left, right| {
        (left.instance_id(), left.clip_id()).cmp(&(right.instance_id(), right.clip_id()))
    });
    for animation in ordered_animations {
        check_pins(
            animation.compiler_digest(),
            animation.target_profile_digest(),
            animation.target_artifact_digest(),
            target,
            compiler,
        )?;
        let pair = (
            animation.instance_id().to_string(),
            animation.clip_id().to_string(),
        );
        if !binding_pairs.insert(pair.clone()) {
            return Err(error(
                "ID_COLLISION",
                "Duplicate instance-qualified animation draft",
            ));
        }
        if !project["instanceIds"]
            .as_array()
            .is_some_and(|items| items.iter().any(|id| id == &Value::String(pair.0.clone())))
        {
            return Err(error(
                "REFERENCE_UNRESOLVED",
                "Animation binding instance is absent from immutable project",
            ));
        }
        let project_tps: RationalTime =
            serde_json::from_value(project["gameTicksPerSecond"].clone())
                .map_err(|error| self::error("SCHEMA_INVALID", &error.to_string()))?;
        if animation.target_tps() != &project_tps {
            return Err(error(
                "STALE_CONTEXT",
                "Animation target TPS differs from immutable project",
            ));
        }
        let scene_projection = scene
            .and_then(|scene| scene.animation_bindings().get(animation.instance_id()))
            .ok_or_else(|| {
                error(
                    "REFERENCE_UNRESOLVED",
                    "Animation requires its exact sealed generated scene instance binding",
                )
            })?;
        let projection = animation.scene_projection();
        if projection.instance_id != scene_projection.instance_id
            || projection.world_id != scene_projection.world_id
            || projection.dimension != scene_projection.dimension
            || projection.owner_prefab_id != scene_projection.owner_prefab_id
            || projection.owner_prefab_id != *animation.owner_prefab_id()
            || projection.instance_world != scene_projection.instance_world
            || projection.nodes.len() != scene_projection.nodes.len()
            || projection.nodes.iter().any(|(id, node)| {
                scene_projection.nodes.get(id).is_none_or(|expected| {
                    node.parent != expected.parent
                        || node.rest_local != expected.rest_local
                        || node.display_uuid != expected.display_uuid
                        || node.display_origin != expected.display_origin
                })
            })
        {
            return Err(error(
                "STALE_CONTEXT",
                "Animation parent/rest/UUID/origin/prefab binding differs from generated scene",
            ));
        }
        covered.insert((
            "clip".into(),
            pair.1.clone(),
            animation.clip_revision().to_string(),
        ));
        for (id, resource) in animation.resources() {
            validate_function_id(id)?;
            check_resource(resource)?;
            if !output.defined.insert(id.clone()) {
                return Err(error(
                    "ID_COLLISION",
                    "Generated scene/animation function collision",
                ));
            }
            insert_resource(
                &mut output.resources,
                &mut total_bytes,
                function_path(id),
                resource.clone(),
            )?;
            output.line_costs.insert(
                id.clone(),
                resource.bytes.iter().filter(|byte| **byte == b'\n').count(),
            );
        }
        output.calls.extend(animation.function_calls().clone());
        register_private_address(
            &mut output.private_addresses,
            format!("objective:{}", animation.timer_objective()),
            format!(
                "animation:{}:{}:{}",
                animation.instance_id(),
                animation.clip_id(),
                animation.input_digest()
            ),
        )?;
        for (id, contract) in animation.function_contracts() {
            insert_contracts(&mut output, id, std::slice::from_ref(contract))?;
        }
        for origin in animation.line_origins() {
            let resource = animation.resources().get(&origin.function).ok_or_else(|| {
                error(
                    "REFERENCE_UNRESOLVED",
                    "Animation source map function absent",
                )
            })?;
            let mut entry = json!({"sourceObjectId":origin.source_object_id,
                "outputResourceId":resource.reference.resource_id,"locator":format!("line:{}",origin.line)});
            if let Some(node) = &origin.node_id {
                entry["sourceNodeId"] = json!(node);
            }
            charge_metadata(&mut output.map_bytes, &entry)?;
            output.map_entries.push(entry);
        }
        let qualifier =
            raw_digest(format!("{}\0{}", pair.0, pair.1).as_bytes()).as_str()[..16].to_owned();
        for (role, id) in animation.entry_points() {
            let key = format!("clip_{qualifier}_{role}");
            if key.len() > 64 || output.entries.insert(key, id.clone()).is_some() {
                return Err(error(
                    "ID_COLLISION",
                    "Qualified animation entry point collision",
                ));
            }
        }
        output
            .referenced
            .extend(animation.referenced_functions().iter().cloned());
        for (id, resource) in animation.external_functions() {
            insert_external(&mut output.external, id, &resource.sha256)?;
        }
        output.state.extend(animation.state_symbols());
        output
            .runtime
            .extend(animation.runtime_dependencies().iter().cloned());
        output.seals.push(json!({"clip":animation.clip_id(),"revision":animation.clip_revision(),"instance":animation.instance_id(),
            "input":animation.input_digest(),"bindings":animation.binding_digest(),"authority":animation.authority_digest(),
            "resources":animation.resources().iter().map(|(id,r)|json!({"function":id,"resource":r.reference})).collect::<Vec<_>>() }));
        for loss in animation.losses() {
            append_loss(&mut output, loss)?;
        }
    }
    if covered != expected {
        return Err(error(
            "UNOWNED_REQUIRED_CAPABILITY",
            "Every owned kind/object/revision requires sealed lowering; extra or stale coverage is rejected",
        ));
    }
    if let Some(scene) = scene
        && scene.required_animation_bindings() != &binding_pairs
    {
        return Err(error(
            "REFERENCE_UNRESOLVED",
            "Each instantiated scene clip binding requires its own exact animation draft",
        ));
    }
    if output.defined.len() > 4096 || output.entries.len() > 4096 {
        return Err(error(
            "NUMERIC_RANGE",
            "Combined generated function/entry point count exceeds budget",
        ));
    }
    for id in &output.defined {
        validate_function_id(id)?;
        if !output.resources.contains_key(&function_path(id)) || !output.contracts.contains_key(id)
        {
            return Err(error(
                "REFERENCE_UNRESOLVED",
                "Generated function lacks source bytes or contract",
            ));
        }
    }
    Ok(output)
}

fn append_loss(output: &mut OwnedBundle, loss: &Value) -> Result<(), DomainError> {
    if output.losses.len() >= 4096 {
        return Err(error(
            "NUMERIC_RANGE",
            "Aggregate loss record count exceeds budget",
        ));
    }
    charge_metadata(&mut output.loss_bytes, loss)?;
    output.losses.push(loss.clone());
    Ok(())
}

fn check_pins(
    implementation: &Sha256Digest,
    profile: &Sha256Digest,
    artifact: &Sha256Digest,
    target: &VerifiedTarget,
    compiler: &Sha256Digest,
) -> Result<(), DomainError> {
    if implementation != compiler
        || profile != target.profile_digest()
        || artifact != target.artifact_digest()
    {
        return Err(error(
            "STALE_CONTEXT",
            "Owned draft compiler/profile/artifact pins differ",
        ));
    }
    Ok(())
}
fn check_ids(project: &Value, field: &str, actual: &BTreeSet<String>) -> Result<(), DomainError> {
    let expected: BTreeSet<_> = project[field]
        .as_array()
        .ok_or_else(|| error("SCHEMA_INVALID", "Project reference inventory absent"))?
        .iter()
        .map(|id| id.as_str().unwrap_or_default().to_owned())
        .collect();
    if &expected != actual {
        return Err(error(
            "REFERENCE_UNRESOLVED",
            "Scene reference inventory differs from immutable project",
        ));
    }
    Ok(())
}
fn check_resource(resource: &StagedResource) -> Result<(), DomainError> {
    if raw_digest(&resource.bytes) != resource.reference.sha256
        || resource.bytes.len() as u64 != resource.reference.size_bytes
    {
        return Err(error(
            "STALE_CONTEXT",
            "Generated resource byte identity differs",
        ));
    }
    Ok(())
}
fn insert_contracts(
    output: &mut OwnedBundle,
    id: &ResourceLocation,
    contracts: &[GeneratedFunctionContract],
) -> Result<(), DomainError> {
    validate_function_id(id)?;
    if output.contracts.contains_key(id) {
        return Err(error(
            "ID_COLLISION",
            "Generated function contract collision",
        ));
    }
    charge_metadata(&mut output.contract_bytes, id)?;
    let size = charge_metadata(&mut output.contract_bytes, &contracts)?;
    for contract in contracts {
        output.state.extend(contract.state_reads.iter().cloned());
        output.state.extend(contract.state_writes.iter().cloned());
    }
    output.contract_sizes.insert(id.clone(), size);
    output.contracts.insert(id.clone(), contracts.to_vec());
    Ok(())
}
pub(crate) fn insert_external(
    map: &mut BTreeMap<ResourceLocation, Sha256Digest>,
    id: &ResourceLocation,
    pin: &Sha256Digest,
) -> Result<(), DomainError> {
    if map.get(id).is_some_and(|old| old != pin) {
        return Err(error(
            "REFERENCE_UNRESOLVED",
            "External function has conflicting immutable byte pins",
        ));
    }
    map.entry(id.clone()).or_insert_with(|| pin.clone());
    Ok(())
}
pub(crate) fn register_private_address(
    map: &mut BTreeMap<String, String>,
    address: String,
    owner: String,
) -> Result<(), DomainError> {
    if map.get(&address).is_some_and(|previous| previous != &owner) {
        return Err(error(
            "ID_COLLISION",
            "Generated native symbol hash collides across distinct owners",
        ));
    }
    map.entry(address).or_insert(owner);
    Ok(())
}

fn error(code: &'static str, message: &str) -> DomainError {
    DomainError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn truncated_native_name_collision_cannot_alias_distinct_generated_owners() {
        // An authored name collision is necessary: searching for a real
        // 60-bit digest collision would add cost without exercising a new path.
        let mut addresses = BTreeMap::new();
        let name = "objective:m000000000000000".to_owned();
        register_private_address(&mut addresses, name.clone(), "project:one/state:a".into())
            .unwrap();
        register_private_address(&mut addresses, name.clone(), "project:one/state:a".into())
            .unwrap();
        assert_eq!(
            register_private_address(
                &mut addresses,
                name,
                "project:one/instance:two/state:a".into()
            )
            .unwrap_err()
            .code,
            "ID_COLLISION"
        );
    }
}

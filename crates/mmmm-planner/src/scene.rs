//! Scene/command edits lower into canonical immutable documents. Only the
//! selected instance changes its definition pin; shared originals remain owned
//! and unchanged. Source DTOs carry data, never authorization or bake evidence.
use crate::preparation::{
    Sources, append_instance, dependency, document, revise_instance, same_resource,
};
use crate::*;
use mmmm_application::{AppError, AppResult};
use mmmm_contracts::{
    ClipId, InstanceId, ModuleId, NodeId, ObjectId, PhysicsId, PrefabId, PrincipalId, Sha256Digest,
    TargetId, canonical_digest, projected_digest,
};
use mmmm_domain::{
    Instance, Prefab,
    commands::{CommandModule, CommandStateRules},
    time::AnimationClip,
    transform::Transform,
    types::{
        Display, InstanceOverride, Node, ReferenceScope, ResourceRef, StateScope, SymbolReference,
    },
};
use mmmm_exchange::{
    bake::IngestedBake,
    physics::PhysicsDefinition,
    selection::{ObjectNode, Selection},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn invalid() -> AppError {
    AppError::new(
        "INVALID_INPUT",
        "Scene change has an absent or invalid canonical field",
    )
}
fn conflict() -> AppError {
    AppError::new(
        "REVISION_CONFLICT",
        "Scene source differs from the exact owned base revision",
    )
}
fn unresolved() -> AppError {
    AppError::new(
        "REFERENCE_UNRESOLVED",
        "Variant retains a missing or inconsistent typed target",
    )
}
fn array<'a>(value: &'a Value, field: &str) -> AppResult<&'a [Value]> {
    value[field]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(invalid)
}

struct Variant {
    after: Instance,
    definition: Prefab,
    modules: Vec<CommandModule>,
    clips: Vec<AnimationClip>,
    physics: Vec<Value>,
}

impl NativePlanner<'_> {
    pub(crate) fn prepare_scene_change(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        context: &Value,
        sources: &mut Sources,
        change: &mut PreparedNativeChange,
        patch: &Value,
    ) -> AppResult<Vec<Value>> {
        validate("ScenePatch", patch)?;
        if patch["projectId"].as_str() != Some(project.project_id().as_str())
            || patch["baseRevision"].as_str() != Some(project.revision().as_str())
        {
            return Err(conflict());
        }
        let source = self
            .source
            .scene_source(principal, project, patch, context)?;
        source
            .selection
            .check_revision(project.project_id().as_str(), project.revision().as_str())
            .map_err(exchange)?;
        let mut originals = BTreeMap::new();
        // A port cannot replace the selected base with a similarly named object.
        // Loading every supplied instance also rejects unowned snapshot members.
        for selected in array(source.selection.value(), "instances")? {
            let id = text(selected, "instanceId")?;
            let (before, definition) = self.instance_source(
                principal,
                project,
                id,
                Some(&selected["revision"]),
                context,
                sources,
            )?;
            if wire("Instance", &before)? != *selected {
                return Err(conflict());
            }
            let selected_definition = array(source.selection.value(), "prefabs")?
                .iter()
                .find(|value| value["prefabId"].as_str() == Some(before.prefab_id.as_str()))
                .ok_or_else(unresolved)?;
            if wire("Prefab", &definition)? != *selected_definition {
                return Err(conflict());
            }
            originals.insert(id.to_owned(), (before, definition));
        }
        for selected in array(source.selection.value(), "prefabs")? {
            let revision: Sha256Digest =
                serde_json::from_value(selected["revision"].clone()).map_err(|_| invalid())?;
            let pin =
                project.authorize_pin(OwnedKind::Prefab, text(selected, "prefabId")?, &revision)?;
            if self.load_owned(principal, project, &pin, context, sources)? != *selected {
                return Err(conflict());
            }
        }
        let artifact_ref: ResourceRef = decode("ResourceRef", &patch["sourceArtifact"])?;
        let map_ref: ResourceRef = decode("ResourceRef", &patch["sourceMap"])?;
        let artifact_bytes =
            self.load_resource(principal, project, &artifact_ref, context, sources)?;
        let artifact = mmmm_contracts::parse_json(&artifact_bytes).map_err(|_| invalid())?;
        let map_bytes = self.load_resource(principal, project, &map_ref, context, sources)?;
        let map = mmmm_contracts::parse_json(&map_bytes).map_err(|_| invalid())?;
        validate("SourceMap", &map)?;
        if artifact != source.artifact
            || map != source.source_map
            || map["inputRevision"].as_str() != Some(project.revision().as_str())
        {
            return Err(conflict());
        }
        validate_artifact(&artifact, project)?;
        self.source
            .validate_scene_provenance(principal, project, patch, &source, context)?;
        mmmm_exchange::patch::validate_scene_patch(patch, &source.selection, &source.delta_policy)
            .map_err(exchange)?;

        let entries = array(patch, "entries")?;
        let mut dependencies = Vec::new();
        let mut imported = BTreeMap::<String, Vec<AnimationClip>>::new();
        let mut derivative_resources = BTreeMap::<String, Vec<ResourceRef>>::new();
        if entries.iter().any(|entry| entry["kind"] == "attach_clip") {
            let baked = source.ingested_bake.as_ref().ok_or_else(|| {
                AppError::new(
                    "CAPABILITY_UNAVAILABLE",
                    "Clip attachment requires sealed independently verified bake ingestion",
                )
            })?;
            baked.check_selection(&source.selection).map_err(exchange)?;
            if baked.original_bytes() != artifact_bytes
                || baked.artifact() != &artifact
                || baked.resource() != &patch["sourceArtifact"]
            {
                return Err(AppError::new(
                    "INPUT_DIGEST_MISMATCH",
                    "Scene patch does not pin the sealed bake's original bytes",
                ));
            }
            let attachments = verified_attachments(patch, &map, &source.selection, baked)?;
            let resources = baked.canonical_clip_resources().map_err(exchange)?;
            if resources.len() != baked.canonical_clips().len() {
                return Err(invalid());
            }
            for (index, instance_id) in attachments {
                let clip: AnimationClip = decode("AnimationClip", &baked.canonical_clips()[index])?;
                let (resource_value, bytes) = &resources[index];
                let expected: ResourceRef = decode("ResourceRef", resource_value)?;
                let staged = self.stage_named_bytes(
                    principal,
                    project,
                    Some(&expected.resource_id),
                    bytes,
                    &expected.media_type,
                    context,
                )?;
                if !same_resource(&expected, &staged) {
                    return Err(AppError::new(
                        "INPUT_DIGEST_MISMATCH",
                        "Canonical bake derivative staging changed its immutable resource pin",
                    ));
                }
                change.staged_resources.push(staged.clone());
                derivative_resources
                    .entry(instance_id.clone())
                    .or_default()
                    .push(staged);
                imported.entry(instance_id).or_default().push(clip);
            }
            dependencies.push(dependency(
                "scene-coordinate-normalization",
                &baked.normalization_digest().map_err(exchange)?,
                &["FN27", "FN28"],
                "owned_domain",
            )?);
        }
        for entry in entries
            .iter()
            .filter(|entry| entry["kind"] != "attach_clip")
        {
            manual_mapping(entry, &artifact, &map, &artifact_ref, &source.selection)?;
        }
        let mut grouped = BTreeMap::<String, Vec<&Value>>::new();
        for entry in entries {
            grouped
                .entry(text(entry, "instanceId")?.to_owned())
                .or_default()
                .push(entry);
        }
        for (id, edits) in grouped {
            let (before, original) = originals.get(&id).cloned().ok_or_else(unresolved)?;
            let mut after = before.clone();
            let mut candidate = original.clone();
            let structural = edits.iter().any(|entry| {
                matches!(
                    entry["kind"].as_str(),
                    Some("create_node" | "delete_node" | "attach_clip")
                )
            });
            for entry in &edits {
                apply_node_edit(&mut after, &mut candidate, entry)?;
            }
            if structural {
                let (modules, mut clips, physics) = self.variant_sources(
                    principal,
                    project,
                    context,
                    sources,
                    &before,
                    &original,
                    &candidate,
                    Some(&source.selection),
                )?;
                for clip in imported.remove(&id).unwrap_or_default() {
                    // Attachment registers authored inactive alternatives; it
                    // does not start animation or choose an active clip. The
                    // sealed artifact still proves its own track/writer closure.
                    if let Some(existing) = clips
                        .iter_mut()
                        .find(|existing| existing.clip_id == clip.clip_id)
                    {
                        *existing = clip;
                    } else {
                        clips.push(clip);
                    }
                }
                for resource in derivative_resources.remove(&id).unwrap_or_default() {
                    insert_resource(&mut candidate, &resource)?;
                }
                let edit_values = edits
                    .iter()
                    .map(|entry| (*entry).clone())
                    .collect::<Vec<_>>();
                let variant = build_variant(
                    &before,
                    after,
                    &original,
                    candidate,
                    modules,
                    clips,
                    physics,
                    &json!({"sceneEntries":edit_values,"sourceArtifact":artifact_ref,"sourceMap":map_ref}),
                )?;
                append_variant(project, change, before, original, variant)?;
            } else {
                revise_instance(&mut after)?;
                mmmm_domain::instance::require_source(&after, &candidate).map_err(domain)?;
                append_instance(change, Some(before), after, candidate)?;
            }
        }
        for loss in array(patch, "losses")? {
            append_loss(change, loss.clone())?;
        }
        change.scene_patch = Some(patch.clone());
        Ok(dependencies)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Authenticated source context, accumulated pins/change, and exact authored command inputs retain separate roles"
    )]
    pub(crate) fn prepare_command_variant(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        context: &Value,
        sources: &mut Sources,
        change: &mut PreparedNativeChange,
        before: Instance,
        definition: Prefab,
        laid_out: CommandModule,
    ) -> AppResult<()> {
        if laid_out.owner_prefab_id != definition.prefab_id {
            return Err(unresolved());
        }
        let (mut modules, clips, physics) = self.variant_sources(
            principal,
            project,
            context,
            sources,
            &before,
            &definition,
            &definition,
            None,
        )?;
        let seed = wire("CommandModule", &laid_out)?;
        if let Some(existing) = modules
            .iter_mut()
            .find(|module| module.module_id == laid_out.module_id)
        {
            *existing = laid_out;
        } else {
            modules.push(laid_out);
        }
        let variant = build_variant(
            &before,
            before.clone(),
            &definition,
            definition.clone(),
            modules,
            clips,
            physics,
            &json!({"commandModule":seed}),
        )?;
        append_variant(project, change, before, definition, variant)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Actual source authority and pin collection remain separate from original/candidate documents and optional selection"
    )]
    fn variant_sources(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        context: &Value,
        sources: &mut Sources,
        before: &Instance,
        original: &Prefab,
        candidate: &Prefab,
        selection: Option<&Selection>,
    ) -> AppResult<(Vec<CommandModule>, Vec<AnimationClip>, Vec<Value>)> {
        let mut modules = Vec::new();
        for id in &original.command_module_ids {
            let module: CommandModule = decode(
                "CommandModule",
                &self.load_current(
                    principal,
                    project,
                    OwnedKind::CommandModule,
                    id.as_str(),
                    context,
                    sources,
                )?,
            )?;
            if module.owner_prefab_id != original.prefab_id {
                return Err(conflict());
            }
            modules.push(module);
        }
        let mut clips = Vec::new();
        for id in &original.clip_ids {
            let clip: AnimationClip = decode(
                "AnimationClip",
                &self.load_current(
                    principal,
                    project,
                    OwnedKind::Clip,
                    id.as_str(),
                    context,
                    sources,
                )?,
            )?;
            if clip.owner_prefab_id != original.prefab_id {
                return Err(conflict());
            }
            mmmm_domain::time::validate_clip(&clip).map_err(domain)?;
            clips.push(clip);
        }
        let ids: BTreeSet<_> = original
            .nodes
            .iter()
            .chain(candidate.nodes.iter())
            .filter_map(|node| {
                node.physics_binding
                    .as_ref()
                    .map(|binding| binding.physics_id.clone())
            })
            .collect();
        let mut physics = Vec::new();
        for id in ids {
            let value = self.load_current(
                principal,
                project,
                OwnedKind::PhysicsDefinition,
                id.as_str(),
                context,
                sources,
            )?;
            let definition = PhysicsDefinition::from_value(&value).map_err(exchange)?;
            if let Some(selection) = selection {
                definition
                    .validate_selection(selection.value())
                    .map_err(exchange)?;
            }
            for collider in array(&value, "colliders")? {
                if collider["shape"]["shape"]["kind"] == "mesh" {
                    let resource: ResourceRef =
                        decode("ResourceRef", &collider["shape"]["shape"]["geometry"])?;
                    self.load_resource(principal, project, &resource, context, sources)?;
                }
            }
            // A bound body must actually own this qualified visual node. Having
            // the same body label in a different definition proves nothing.
            for node in original
                .nodes
                .iter()
                .chain(candidate.nodes.iter())
                .filter(|node| {
                    node.physics_binding
                        .as_ref()
                        .is_some_and(|binding| binding.physics_id == id)
                })
            {
                let binding = node.physics_binding.as_ref().ok_or_else(unresolved)?;
                let body = array(&value, "bodies")?
                    .iter()
                    .find(|body| body["bodyId"].as_str() == Some(binding.body_id.as_str()))
                    .ok_or_else(unresolved)?;
                if !array(body, "visualBindings")?.iter().any(|visual| {
                    visual["node"]["instanceId"].as_str() == Some(before.instance_id.as_str())
                        && visual["node"]["nodeId"].as_str() == Some(node.node_id.as_str())
                }) {
                    return Err(unresolved());
                }
            }
            physics.push(value);
        }
        Ok((modules, clips, physics))
    }
}

fn validate_artifact(artifact: &Value, project: &ProjectCatalog) -> AppResult<()> {
    if artifact.get("artifactId").is_some() {
        validate("BakeArtifact", artifact)?;
    } else if artifact.get("prefabId").is_some() {
        let prefab: Prefab = decode("Prefab", artifact)?;
        mmmm_contracts::verify_projected_digest("Prefab", artifact).map_err(|_| conflict())?;
        mmmm_domain::prefab::require_valid(&prefab).map_err(domain)?;
    } else if artifact.get("instances").is_some() && artifact.get("prefabs").is_some() {
        let selection = Selection::from_value(artifact).map_err(exchange)?;
        selection
            .check_revision(project.project_id().as_str(), project.revision().as_str())
            .map_err(exchange)?;
    } else {
        return Err(AppError::new(
            "CAPABILITY_UNAVAILABLE",
            "Scene source artifact has no supported canonical authored or sealed bake format",
        ));
    }
    Ok(())
}

/// Every selected imported clip is installed as a whole. Each of its tracks
/// must therefore have one authorized attach entry for the same instance.
fn verified_attachments(
    patch: &Value,
    map: &Value,
    selection: &Selection,
    baked: &IngestedBake,
) -> AppResult<BTreeMap<usize, String>> {
    let raw = array(baked.artifact(), "clips")?;
    if raw.len() != baked.canonical_clips().len() {
        return Err(invalid());
    }
    let entries = array(patch, "entries")?;
    let reported_losses: BTreeSet<_> = array(patch, "losses")?
        .iter()
        .map(|loss| canonical_digest(loss).map_err(|_| invalid()))
        .collect::<AppResult<_>>()?;
    for loss in array(baked.artifact(), "losses")?
        .iter()
        .chain(
            raw.iter()
                .flat_map(|clip| clip["losses"].as_array().into_iter().flatten()),
        )
        .chain(
            baked
                .canonical_clips()
                .iter()
                .flat_map(|clip| clip["losses"].as_array().into_iter().flatten()),
        )
    {
        if !reported_losses.contains(&canonical_digest(loss).map_err(|_| invalid())?) {
            return Err(AppError::new(
                "LOSS_APPROVAL_REQUIRED",
                "Scene patch omits a sealed artifact or canonical clip loss record",
            ));
        }
    }
    let mut selected = BTreeMap::<usize, String>::new();
    let mut final_writers = BTreeSet::new();
    let mut matched = BTreeSet::new();
    for entry in entries
        .iter()
        .filter(|entry| entry["kind"] == "attach_clip")
    {
        let matches = baked
            .canonical_clips()
            .iter()
            .enumerate()
            .filter(|(_, clip)| clip["clipId"] == entry["clipId"])
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(AppError::new(
                "OBJECT_MAPPING_AMBIGUOUS",
                "Attached clip is not one exact sealed canonical derivative",
            ));
        }
        let index = matches[0].0;
        let id = text(entry, "instanceId")?;
        if selected
            .insert(index, id.to_owned())
            .is_some_and(|previous| previous != id)
        {
            return Err(AppError::new(
                "OBJECT_MAPPING_AMBIGUOUS",
                "One whole clip cannot span several instance variants",
            ));
        }
    }
    for (index, instance) in &selected {
        let canonical = &baked.canonical_clips()[*index];
        let original = &raw[*index];
        if canonical["ownerPrefabId"] != original["ownerPrefabId"]
            || array(canonical, "tracks")?.len() != array(original, "tracks")?.len()
        {
            return Err(conflict());
        }
        for (track_index, track) in array(original, "tracks")?.iter().enumerate() {
            let canonical_track = &array(canonical, "tracks")?[track_index];
            if track["nodeId"] != canonical_track["nodeId"] {
                return Err(conflict());
            }
            let target = ObjectNode {
                instance_id: instance.clone(),
                node_id: text(track, "nodeId")?.to_owned(),
            };
            if !selection.selected(&target)
                || selection.node(&target).is_none()
                || selection.prefab_for(instance) != original["ownerPrefabId"].as_str()
            {
                return Err(unresolved());
            }
            let locator = format!("/clips/{index}/tracks/{track_index}");
            let mappings = array(map, "entries")?
                .iter()
                .filter(|entry| {
                    entry["locator"].as_str() == Some(locator.as_str())
                        && entry["outputResourceId"] == patch["sourceArtifact"]["resourceId"]
                })
                .collect::<Vec<_>>();
            if mappings.len() != 1
                || mappings[0]["sourceObjectId"].as_str() != Some(instance.as_str())
                || mappings[0]["sourceNodeId"] != track["nodeId"]
            {
                return Err(AppError::new(
                    "OBJECT_MAPPING_AMBIGUOUS",
                    "Imported track has no exact qualified raw artifact source mapping",
                ));
            }
            let attachments = entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| {
                    entry["kind"] == "attach_clip"
                        && entry["instanceId"].as_str() == Some(instance.as_str())
                        && entry["nodeId"] == track["nodeId"]
                        && entry["clipId"] == canonical["clipId"]
                })
                .collect::<Vec<_>>();
            if attachments.len() != 1 || !final_writers.insert(target) {
                return Err(AppError::new(
                    "POSE_WRITER_CONFLICT",
                    "Imported whole clip lacks track closure or overlaps a final pose writer",
                ));
            }
            matched.insert(attachments[0].0);
        }
    }
    if entries
        .iter()
        .enumerate()
        .any(|(index, entry)| entry["kind"] == "attach_clip" && !matched.contains(&index))
    {
        return Err(unresolved());
    }
    Ok(selected)
}

fn manual_mapping(
    entry: &Value,
    artifact: &Value,
    map: &Value,
    resource: &ResourceRef,
    selection: &Selection,
) -> AppResult<()> {
    let instance = text(entry, "instanceId")?;
    let node = text(entry, "nodeId")?;
    let prefab = selection.prefab_for(instance).ok_or_else(unresolved)?;
    let mut candidates = Vec::new();
    if artifact["prefabId"].as_str() == Some(prefab) {
        for (index, value) in array(artifact, "nodes")?
            .iter()
            .enumerate()
            .filter(|(_, value)| value["nodeId"].as_str() == Some(node))
        {
            candidates.push((format!("/nodes/{index}"), value));
        }
    } else if artifact.get("instances").is_some() {
        let source_instance = array(artifact, "instances")?
            .iter()
            .find(|value| value["instanceId"].as_str() == Some(instance))
            .ok_or_else(unresolved)?;
        if source_instance["prefabId"].as_str() != Some(prefab) {
            return Err(unresolved());
        }
        for (prefab_index, definition) in array(artifact, "prefabs")?
            .iter()
            .enumerate()
            .filter(|(_, value)| value["prefabId"].as_str() == Some(prefab))
        {
            for (node_index, value) in array(definition, "nodes")?
                .iter()
                .enumerate()
                .filter(|(_, value)| value["nodeId"].as_str() == Some(node))
            {
                candidates.push((format!("/prefabs/{prefab_index}/nodes/{node_index}"), value));
            }
        }
    } else {
        return Err(AppError::new(
            "CAPABILITY_UNAVAILABLE",
            "Authored node edits require a canonical prefab or scene selection artifact",
        ));
    }
    if candidates.len() != 1 {
        return Err(unresolved());
    }
    let (locator, source_node) = &candidates[0];
    let field = match text(entry, "kind")? {
        "update_transform" => Some("transform"),
        "update_display" => Some("display"),
        "create_node" | "delete_node" => None,
        _ => return Err(invalid()),
    };
    let mappings = array(map, "entries")?
        .iter()
        .filter(|value| {
            value["sourceObjectId"].as_str() == Some(instance)
                && value["sourceNodeId"].as_str() == Some(node)
                && value["outputResourceId"].as_str() == Some(resource.resource_id.as_str())
                && (value["locator"].as_str() == Some(locator.as_str())
                    || field.is_some_and(|field| {
                        value["locator"].as_str() == Some(format!("{locator}/{field}").as_str())
                    }))
        })
        .collect::<Vec<_>>();
    if mappings.len() != 1 {
        return Err(AppError::new(
            "OBJECT_MAPPING_AMBIGUOUS",
            "Node edit has no unique supported source DTO locator",
        ));
    }
    match text(entry, "kind")? {
        "create_node" if entry["node"] != **source_node => return Err(conflict()),
        "update_transform" | "update_display"
            if field.is_some_and(|field| entry[field] != source_node[field]) =>
        {
            return Err(conflict());
        }
        "delete_node" => {
            let target = ObjectNode {
                instance_id: instance.to_owned(),
                node_id: node.to_owned(),
            };
            let original = array(selection.value(), "prefabs")?
                .iter()
                .find(|value| value["prefabId"].as_str() == Some(prefab))
                .and_then(|value| value["nodes"].as_array())
                .and_then(|values| {
                    values
                        .iter()
                        .find(|value| value["nodeId"].as_str() == Some(node))
                })
                .ok_or_else(unresolved)?;
            if selection.node(&target) != Some(*source_node) && original != *source_node {
                return Err(conflict());
            }
        }
        _ => {}
    }
    Ok(())
}

fn apply_node_edit(instance: &mut Instance, prefab: &mut Prefab, entry: &Value) -> AppResult<()> {
    validate("ScenePatchEntry", entry)?;
    let node_id = NodeId::new(text(entry, "nodeId")?).map_err(|_| invalid())?;
    match text(entry, "kind")? {
        "create_node" => {
            let node: Node = decode("Node", &entry["node"])?;
            if node.node_id != node_id || prefab.nodes.iter().any(|node| node.node_id == node_id) {
                return Err(AppError::new(
                    "ID_COLLISION",
                    "Created stable node already exists in the instance definition",
                ));
            }
            prefab.nodes.push(node);
        }
        "delete_node" => {
            if !prefab.nodes.iter().any(|node| node.node_id == node_id) {
                return Err(unresolved());
            }
            prefab.nodes.retain(|node| node.node_id != node_id);
        }
        "update_transform" => {
            let transform: Transform = decode("Transform", &entry["transform"])?;
            instance.overrides.retain(|value|!matches!(value,InstanceOverride::Transform {node_id:target,..} if target==&node_id));
            instance
                .overrides
                .push(InstanceOverride::Transform { node_id, transform });
        }
        "update_display" => {
            let display: Display = decode("Display", &entry["display"])?;
            instance.overrides.retain(|value|!matches!(value,InstanceOverride::Display {node_id:target,..} if target==&node_id));
            instance
                .overrides
                .push(InstanceOverride::Display { node_id, display });
        }
        "attach_clip" => {}
        _ => return Err(invalid()),
    }
    Ok(())
}

fn variant_id(kind: &str, original: &str, seed: &Sha256Digest) -> AppResult<String> {
    let digest=canonical_digest(&json!({"profile":"mmmm-instance-definition-variant/1","kind":kind,"sourceId":original,"changeDigest":seed})).map_err(|_|invalid())?;
    let id = format!("{kind}-variant-{digest}");
    ObjectId::new(&id).map_err(|_| invalid())?;
    Ok(id)
}

#[allow(
    clippy::too_many_arguments,
    reason = "Exact original and candidate state plus separately owned module, clip, physics and edit inputs form the variant digest"
)]
fn build_variant(
    before: &Instance,
    mut after: Instance,
    original: &Prefab,
    mut prefab: Prefab,
    mut modules: Vec<CommandModule>,
    mut clips: Vec<AnimationClip>,
    physics: Vec<Value>,
    edit: &Value,
) -> AppResult<Variant> {
    mmmm_domain::instance::require_source(before, original).map_err(domain)?;
    let seed=canonical_digest(&json!({"profile":"mmmm-instance-definition-variant/1","sourceInstance":before,"sourceDefinition":original,"candidateDefinition":prefab,"candidateOverrides":after.overrides,"modules":modules,"clips":clips,"physics":physics,"edit":edit})).map_err(|_|invalid())?;
    let new_prefab = PrefabId::new(variant_id("prefab", original.prefab_id.as_str(), &seed)?)
        .map_err(|_| invalid())?;
    let self_object_map = BTreeMap::from([(
        original.prefab_id.as_str().to_owned(),
        new_prefab.as_str().to_owned(),
    )]);
    let mut physics_map: BTreeMap<PhysicsId, PhysicsId> = BTreeMap::new();
    let mut variants = Vec::new();
    for source in physics {
        if let Some(mut variant) = physics_variant(&source, &before.instance_id, &prefab)? {
            let old = text(&source, "physicsId")?;
            let id = PhysicsId::new(variant_id("physics", old, &seed)?).map_err(|_| invalid())?;
            variant["physicsId"] = json!(id);
            variant["revision"] =
                json!(projected_digest("PhysicsDefinition", &variant).map_err(|_| invalid())?);
            PhysicsDefinition::from_value(&variant).map_err(exchange)?;
            if physics_map
                .insert(PhysicsId::new(old).map_err(|_| invalid())?, id)
                .is_some()
            {
                return Err(unresolved());
            }
            variants.push(variant);
        }
    }
    for node in &mut prefab.nodes {
        if let Some(binding) = &mut node.physics_binding {
            let id = physics_map
                .get(&binding.physics_id)
                .ok_or_else(unresolved)?;
            binding.physics_id = id.clone();
        }
    }
    prefab.prefab_id = new_prefab.clone();
    for reference in &mut prefab.references {
        rebind_reference(reference, &self_object_map);
    }
    let mut module_ids = BTreeSet::new();
    for module in &mut modules {
        if module.owner_prefab_id != original.prefab_id
            || !module_ids.insert(module.module_id.clone())
        {
            return Err(unresolved());
        }
        module.module_id = ModuleId::new(variant_id("module", module.module_id.as_str(), &seed)?)
            .map_err(|_| invalid())?;
        module.owner_prefab_id = new_prefab.clone();
        for command in &mut module.commands {
            for reference in &mut command.references {
                rebind_reference(reference, &self_object_map);
            }
        }
        validate_module_targets(module, &prefab, &self_object_map)?;
        mmmm_domain::commands::validate_command_graph(
            module,
            CommandStateRules::SixAxisAdjacentChainConditionBehind,
        )
        .map_err(domain)?;
        module.revision = projected_digest("CommandModule", &wire("CommandModule", module)?)
            .map_err(|_| invalid())?;
    }
    let mut clip_ids = BTreeSet::new();
    for clip in &mut clips {
        if clip.owner_prefab_id != original.prefab_id || !clip_ids.insert(clip.clip_id.clone()) {
            return Err(unresolved());
        }
        clip.clip_id = ClipId::new(variant_id("clip", clip.clip_id.as_str(), &seed)?)
            .map_err(|_| invalid())?;
        clip.owner_prefab_id = new_prefab.clone();
        if clip.tracks.iter().any(|track| {
            !prefab
                .nodes
                .iter()
                .any(|node| node.node_id == track.node_id)
        }) {
            return Err(unresolved());
        }
        for event in &clip.events {
            if !prefab.references.iter().any(|reference| {
                reference.symbol_id == event.function_symbol_id && reference.kind == "function"
            }) {
                return Err(unresolved());
            }
        }
        mmmm_domain::time::validate_clip(clip).map_err(domain)?;
        clip.revision = projected_digest("AnimationClip", &wire("AnimationClip", clip)?)
            .map_err(|_| invalid())?;
    }
    prefab.command_module_ids = modules
        .iter()
        .map(|module| module.module_id.clone())
        .collect();
    prefab.clip_ids = clips.iter().map(|clip| clip.clip_id.clone()).collect();
    mmmm_domain::prefab::require_valid(&prefab).map_err(domain)?;
    prefab.revision =
        projected_digest("Prefab", &wire("Prefab", &prefab)?).map_err(|_| invalid())?;
    rebind_instance(&mut after, original, &prefab, &self_object_map)?;
    after.prefab_id = new_prefab;
    after.prefab_revision = prefab.revision.clone();
    revise_instance(&mut after)?;
    mmmm_domain::instance::require_source(&after, &prefab).map_err(domain)?;
    Ok(Variant {
        after,
        definition: prefab,
        modules,
        clips,
        physics: variants,
    })
}

fn insert_resource(prefab: &mut Prefab, resource: &ResourceRef) -> AppResult<()> {
    if let Some(existing) = prefab
        .resources
        .iter()
        .find(|existing| existing.resource_id == resource.resource_id)
    {
        if !same_resource(existing, resource) {
            return Err(conflict());
        }
    } else {
        prefab.resources.push(resource.clone());
    }
    Ok(())
}

fn rebind_reference(reference: &mut SymbolReference, map: &BTreeMap<String, String>) {
    if reference.scope == ReferenceScope::Local
        && reference.kind == "object"
        && let Some(target) = map.get(&reference.target_id)
    {
        reference.target_id = target.clone();
    }
}

fn authoring_target(instance: &InstanceId, kind: &str, target: &str) -> String {
    format!(
        "mmmm-local:{}:{}:{}:{}:{}",
        instance.as_str().len(),
        instance,
        kind.len(),
        kind,
        target
    )
}

fn rebind_instance(
    instance: &mut Instance,
    original: &Prefab,
    variant: &Prefab,
    map: &BTreeMap<String, String>,
) -> AppResult<()> {
    let original_overrides = instance.overrides.clone();
    for entry in &mut instance.overrides {
        if let InstanceOverride::Reference {
            symbol_id,
            target_id,
        } = entry
        {
            let reference = original
                .references
                .iter()
                .find(|reference| reference.symbol_id == *symbol_id)
                .ok_or_else(unresolved)?;
            if reference.scope == ReferenceScope::Local
                && reference.kind == "object"
                && let Some(target) = map.get(target_id.as_str())
            {
                *target_id = TargetId::new(target).map_err(|_| invalid())?;
            }
        }
    }
    for binding in &mut instance.bindings {
        if let Some(reference) = original
            .references
            .iter()
            .find(|reference| reference.symbol_id == binding.symbol_id)
        {
            if reference.scope != ReferenceScope::Local {
                continue;
            }
            let original_target = original_overrides
                .iter()
                .find_map(|entry| match entry {
                    InstanceOverride::Reference {
                        symbol_id,
                        target_id,
                    } if symbol_id == &binding.symbol_id => Some(target_id.as_str()),
                    _ => None,
                })
                .unwrap_or(&reference.target_id);
            let variant_reference = variant
                .references
                .iter()
                .find(|reference| reference.symbol_id == binding.symbol_id)
                .ok_or_else(unresolved)?;
            let new_target = instance
                .overrides
                .iter()
                .find_map(|entry| match entry {
                    InstanceOverride::Reference {
                        symbol_id,
                        target_id,
                    } if symbol_id == &binding.symbol_id => Some(target_id.as_str()),
                    _ => None,
                })
                .unwrap_or(&variant_reference.target_id);
            let qualifies = matches!(
                reference.kind.as_str(),
                "node" | "port" | "state" | "function" | "object"
            );
            if qualifies
                && binding.target_id
                    == authoring_target(&instance.instance_id, &reference.kind, original_target)
            {
                binding.target_id =
                    authoring_target(&instance.instance_id, &reference.kind, new_target);
            } else if binding.target_id == original_target {
                binding.target_id = new_target.to_owned();
            } else {
                return Err(AppError::new(
                    "REFERENCE_UNRESOLVED",
                    "Local binding differs from its exact authored typed reference",
                ));
            }
        } else {
            let state = original
                .state
                .iter()
                .find(|state| state.state_id.as_str() == binding.symbol_id.as_str())
                .ok_or_else(unresolved)?;
            if state.scope != StateScope::Project
                && binding.target_id != state.state_id.as_str()
                && binding.target_id
                    != authoring_target(&instance.instance_id, "state", state.state_id.as_str())
            {
                return Err(unresolved());
            }
        }
    }
    Ok(())
}

fn validate_module_targets(
    module: &CommandModule,
    prefab: &Prefab,
    objects: &BTreeMap<String, String>,
) -> AppResult<()> {
    if !prefab
        .nodes
        .iter()
        .any(|node| node.node_id == module.local_origin_node_id)
    {
        return Err(unresolved());
    }
    let symbols: BTreeSet<_> = prefab
        .references
        .iter()
        .map(|reference| reference.symbol_id.as_str())
        .chain(prefab.state.iter().map(|state| state.state_id.as_str()))
        .collect();
    if module
        .input_symbols
        .iter()
        .chain(module.output_symbols.iter())
        .any(|id| !symbols.contains(id.as_str()))
        || module
            .shared_state_ids
            .iter()
            .any(|id| !prefab.state.iter().any(|state| &state.state_id == id))
    {
        return Err(unresolved());
    }
    for reference in module
        .commands
        .iter()
        .flat_map(|command| command.references.iter())
        .filter(|reference| reference.scope == ReferenceScope::Local)
    {
        let valid = match reference.kind.as_str() {
            "node" => prefab
                .nodes
                .iter()
                .any(|node| node.node_id.as_str() == reference.target_id),
            "port" => prefab
                .ports
                .iter()
                .any(|port| port.port_id.as_str() == reference.target_id),
            "state" => prefab
                .state
                .iter()
                .any(|state| state.state_id.as_str() == reference.target_id),
            "resource" => prefab
                .resources
                .iter()
                .any(|resource| resource.resource_id.as_str() == reference.target_id),
            "object" => {
                prefab.prefab_id.as_str() == reference.target_id
                    || objects.values().any(|id| id == &reference.target_id)
            }
            "function" => true, // Exact function resolution remains an environment dependency.
            _ => false,
        };
        if !valid {
            return Err(unresolved());
        }
    }
    Ok(())
}

/// Retain the complete joint closure of bound bodies. Cross-instance visual
/// ownership cannot be split by a node edit. Local body/collider/joint/material
/// IDs retain their meaning under the new immutable PhysicsDefinition ID.
fn physics_variant(
    source: &Value,
    instance: &InstanceId,
    prefab: &Prefab,
) -> AppResult<Option<Value>> {
    PhysicsDefinition::from_value(source).map_err(exchange)?;
    let physics_id = text(source, "physicsId")?;
    let wanted: BTreeSet<String> = prefab
        .nodes
        .iter()
        .filter_map(|node| {
            node.physics_binding
                .as_ref()
                .filter(|binding| binding.physics_id.as_str() == physics_id)
                .map(|binding| binding.body_id.as_str().to_owned())
        })
        .collect();
    if wanted.is_empty() {
        return Err(AppError::new(
            "CAPABILITY_UNAVAILABLE",
            "Removing the last physics binding requires an explicit body removal or ownership transfer contract",
        ));
    }
    let mut retained = wanted.clone();
    let bodies = array(source, "bodies")?;
    for id in &wanted {
        if !bodies
            .iter()
            .any(|body| body["bodyId"].as_str() == Some(id.as_str()))
        {
            return Err(unresolved());
        }
    }
    loop {
        let count = retained.len();
        for joint in array(source, "joints")? {
            let a = text(joint, "bodyA")?;
            let b = text(joint, "bodyB")?;
            if retained.contains(a) || retained.contains(b) {
                retained.insert(a.to_owned());
                retained.insert(b.to_owned());
            }
        }
        if count == retained.len() {
            break;
        }
    }
    let nodes: BTreeSet<_> = prefab
        .nodes
        .iter()
        .map(|node| node.node_id.as_str())
        .collect();
    let mut candidate = source.clone();
    let mut kept = Vec::new();
    for body in bodies.iter().filter(|body| {
        body["bodyId"]
            .as_str()
            .is_some_and(|id| retained.contains(id))
    }) {
        let mut body = body.clone();
        let mut visuals = Vec::new();
        for visual in array(&body, "visualBindings")? {
            if visual["node"]["instanceId"].as_str() != Some(instance.as_str()) {
                return Err(AppError::new(
                    "CAPABILITY_UNAVAILABLE",
                    "Physical joint/body closure crosses an unselected instance ownership boundary",
                ));
            }
            if !nodes.contains(text(&visual["node"], "nodeId")?) {
                return Err(AppError::new(
                    "REFERENCE_UNRESOLVED",
                    "Node deletion would retain a body or joint with a missing visual binding",
                ));
            }
            let node = prefab
                .nodes
                .iter()
                .find(|node| {
                    node.node_id.as_str() == visual["node"]["nodeId"].as_str().unwrap_or("")
                })
                .ok_or_else(unresolved)?;
            let binding = node.physics_binding.as_ref().ok_or_else(unresolved)?;
            if binding.physics_id.as_str() != physics_id
                || body["bodyId"].as_str() != Some(binding.body_id.as_str())
            {
                return Err(AppError::new(
                    "REFERENCE_UNRESOLVED",
                    "Retained physical visual has no matching active node-to-body binding",
                ));
            }
            visuals.push(visual.clone());
        }
        body["visualBindings"] = json!(visuals);
        kept.push(body);
    }
    candidate["bodies"] = json!(kept);
    candidate["colliders"] = json!(
        array(source, "colliders")?
            .iter()
            .filter(|collider| collider["bodyId"]
                .as_str()
                .is_some_and(|id| retained.contains(id)))
            .cloned()
            .collect::<Vec<_>>()
    );
    candidate["joints"] = json!(
        array(source, "joints")?
            .iter()
            .filter(|joint| joint["bodyA"]
                .as_str()
                .is_some_and(|id| retained.contains(id))
                && joint["bodyB"]
                    .as_str()
                    .is_some_and(|id| retained.contains(id)))
            .cloned()
            .collect::<Vec<_>>()
    );
    PhysicsDefinition::from_value(&candidate).map_err(exchange)?;
    Ok(Some(candidate))
}

fn append_variant(
    project: &ProjectCatalog,
    change: &mut PreparedNativeChange,
    before: Instance,
    original: Prefab,
    variant: Variant,
) -> AppResult<()> {
    let mut documents = Vec::new();
    for module in &variant.modules {
        documents.push(document(
            OwnedKind::CommandModule,
            None,
            wire("CommandModule", module)?,
        )?);
    }
    for clip in &variant.clips {
        for loss in &clip.losses {
            append_loss(change, serde_json::to_value(loss).map_err(|_| invalid())?)?;
        }
        documents.push(document(
            OwnedKind::Clip,
            None,
            wire("AnimationClip", clip)?,
        )?);
    }
    for physics in &variant.physics {
        documents.push(document(
            OwnedKind::PhysicsDefinition,
            None,
            physics.clone(),
        )?);
    }
    documents.push(document(
        OwnedKind::Prefab,
        None,
        wire("Prefab", &variant.definition)?,
    )?);
    let mut ids = BTreeSet::new();
    for document in &documents {
        if !ids.insert((document.kind, &document.object_id))
            || project.pins().iter().any(|pin| {
                pin.kind == document.kind && pin.object_id.as_str() == document.object_id
            })
            || change.document_changes.iter().any(|existing| {
                existing.kind == document.kind && existing.object_id == document.object_id
            })
        {
            return Err(AppError::new(
                "ID_COLLISION",
                "Content-pinned variant ID already belongs to an authored object",
            ));
        }
    }
    documents.push(document(
        OwnedKind::Instance,
        Some(before.revision.clone()),
        wire("Instance", &variant.after)?,
    )?);
    change.document_changes.extend(documents);
    change.world_projection.push(InstanceProjection {
        before: Some(before),
        before_definition: Some(original),
        after: variant.after,
        definition: variant.definition,
        command_modules: variant.modules,
        clips: variant.clips,
        physics_definitions: variant.physics,
        resource_pins: vec![],
    });
    Ok(())
}

fn append_loss(change: &mut PreparedNativeChange, loss: Value) -> AppResult<()> {
    validate("LossRecord", &loss)?;
    let digest = canonical_digest(&loss).map_err(|_| invalid())?;
    if !change
        .loss_records
        .iter()
        .any(|existing| canonical_digest(existing).ok().as_ref() == Some(&digest))
    {
        if change.loss_records.len() >= 1024 {
            return Err(AppError::new(
                "BUDGET_EXCEEDED",
                "Variant loss records exceed their finite limit",
            ));
        }
        change.loss_records.push(loss);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preparation::{empty_change, update_project};
    use mmmm_domain::types::SymbolBinding;

    fn source() -> (Instance, Prefab, CommandModule, AnimationClip) {
        (
            decode(
                "Instance",
                &serde_json::from_str(include_str!("../../../examples/instance.json")).unwrap(),
            )
            .unwrap(),
            decode(
                "Prefab",
                &serde_json::from_str(include_str!("../../../examples/prefab.json")).unwrap(),
            )
            .unwrap(),
            decode(
                "CommandModule",
                &serde_json::from_str(include_str!("../../../examples/command-module.json"))
                    .unwrap(),
            )
            .unwrap(),
            decode(
                "AnimationClip",
                &serde_json::from_str(include_str!("../../../examples/animation-clip.json"))
                    .unwrap(),
            )
            .unwrap(),
        )
    }
    fn revisions(instance: &mut Instance, prefab: &mut Prefab) {
        prefab.revision = projected_digest("Prefab", &wire("Prefab", prefab).unwrap()).unwrap();
        instance.prefab_revision = prefab.revision.clone();
        revise_instance(instance).unwrap();
    }
    fn make(
        before: &Instance,
        original: &Prefab,
        candidate: Prefab,
        module: CommandModule,
        clip: AnimationClip,
    ) -> AppResult<Variant> {
        build_variant(
            before,
            before.clone(),
            original,
            candidate,
            vec![module],
            vec![clip],
            vec![],
            &json!({"testPurpose":"pure authored variant isolation"}),
        )
    }

    #[test]
    fn command_variant_is_deterministic_and_preserves_shared_source_and_destination() {
        let (mut before, original, mut module, clip) = source();
        before.bindings.push(SymbolBinding {
            symbol_id: mmmm_contracts::SymbolId::new("open_fn").unwrap(),
            target_id: "fixture:retained_destination".into(),
        });
        revise_instance(&mut before).unwrap();
        let mut other = before.clone();
        other.instance_id = InstanceId::new("instance-shop-b").unwrap();
        revise_instance(&mut other).unwrap();
        let other_wire = wire("Instance", &other).unwrap();
        let source_wire = wire("Prefab", &original).unwrap();
        module.commands[0].source = "function fixture:updated_shop".into();
        let first = make(
            &before,
            &original,
            original.clone(),
            module.clone(),
            clip.clone(),
        )
        .unwrap();
        let second = make(&before, &original, original.clone(), module, clip).unwrap();
        assert_eq!(
            wire("Prefab", &first.definition).unwrap(),
            wire("Prefab", &second.definition).unwrap()
        );
        assert_ne!(first.definition.prefab_id, original.prefab_id);
        assert_ne!(first.modules[0].module_id, original.command_module_ids[0]);
        assert_ne!(first.clips[0].clip_id, original.clip_ids[0]);
        assert_eq!(first.modules[0].owner_prefab_id, first.definition.prefab_id);
        assert_eq!(first.clips[0].owner_prefab_id, first.definition.prefab_id);
        assert_eq!(
            first.modules[0].commands[0].source,
            "function fixture:updated_shop"
        );
        assert_eq!(
            first.after.bindings[0].target_id,
            "fixture:retained_destination"
        );
        assert_eq!(wire("Prefab", &original).unwrap(), source_wire);
        assert_eq!(wire("Instance", &other).unwrap(), other_wire);
        assert_eq!(other.prefab_id, original.prefab_id);
    }

    #[test]
    fn typed_local_object_rebinds_exact_locator_without_rewriting_command_text() {
        let (mut before, mut original, module, clip) = source();
        let symbol = mmmm_contracts::SymbolId::new("self_object").unwrap();
        original.references.push(SymbolReference {
            symbol_id: symbol.clone(),
            kind: "object".into(),
            scope: ReferenceScope::Local,
            target_id: original.prefab_id.as_str().into(),
        });
        before.bindings.push(SymbolBinding {
            symbol_id: symbol,
            target_id: authoring_target(&before.instance_id, "object", original.prefab_id.as_str()),
        });
        revisions(&mut before, &mut original);
        let variant = make(&before, &original, original.clone(), module.clone(), clip).unwrap();
        assert_eq!(
            variant.after.bindings[0].target_id,
            authoring_target(
                &before.instance_id,
                "object",
                variant.definition.prefab_id.as_str()
            )
        );
        assert_eq!(
            variant.modules[0].commands[0].source,
            module.commands[0].source
        );
        assert_eq!(
            variant
                .definition
                .references
                .iter()
                .find(|reference| reference.kind == "object")
                .unwrap()
                .target_id,
            variant.definition.prefab_id.as_str()
        );
    }

    #[test]
    fn unrelated_local_binding_is_not_accepted_as_source_of_a_rebind() {
        let (mut before, mut original, module, clip) = source();
        let symbol = mmmm_contracts::SymbolId::new("self_object").unwrap();
        original.references.push(SymbolReference {
            symbol_id: symbol.clone(),
            kind: "object".into(),
            scope: ReferenceScope::Local,
            target_id: original.prefab_id.as_str().into(),
        });
        before.bindings.push(SymbolBinding {
            symbol_id: symbol,
            target_id: authoring_target(
                &InstanceId::new("instance-shop-b").unwrap(),
                "object",
                original.prefab_id.as_str(),
            ),
        });
        revisions(&mut before, &mut original);
        assert_eq!(
            make(&before, &original, original.clone(), module, clip)
                .err()
                .unwrap()
                .code,
            "REFERENCE_UNRESOLVED"
        );
    }

    #[test]
    fn create_and_delete_preserve_unmentioned_nodes_and_owned_documents() {
        let (before, original, module, clip) = source();
        let mut candidate = original.clone();
        let mut extra = candidate
            .nodes
            .iter()
            .find(|node| node.node_id.as_str() == "root")
            .unwrap()
            .clone();
        extra.node_id = NodeId::new("new_node").unwrap();
        extra.parent_id = Some(NodeId::new("root").unwrap());
        let entry = json!({"kind":"create_node","instanceId":before.instance_id,"nodeId":"new_node","node":extra});
        let mut after = before.clone();
        apply_node_edit(&mut after, &mut candidate, &entry).unwrap();
        apply_node_edit(
            &mut after,
            &mut candidate,
            &json!({"kind":"delete_node","instanceId":before.instance_id,"nodeId":"sign"}),
        )
        .unwrap();
        let variant = make(&before, &original, candidate, module, clip).unwrap();
        assert!(
            variant
                .definition
                .nodes
                .iter()
                .any(|node| node.node_id.as_str() == "new_node")
        );
        assert!(
            !variant
                .definition
                .nodes
                .iter()
                .any(|node| node.node_id.as_str() == "sign")
        );
        assert_eq!(
            serde_json::to_value(
                variant
                    .definition
                    .nodes
                    .iter()
                    .find(|node| node.node_id.as_str() == "shell")
                    .unwrap()
            )
            .unwrap(),
            serde_json::to_value(
                original
                    .nodes
                    .iter()
                    .find(|node| node.node_id.as_str() == "shell")
                    .unwrap()
            )
            .unwrap()
        );
        let project = ProjectCatalog::from_project(
            &serde_json::from_str(include_str!("../../../examples/project.json")).unwrap(),
        )
        .unwrap();
        let mut change = empty_change(&project, NativeKind::ScenePatch);
        append_variant(&project, &mut change, before, original.clone(), variant).unwrap();
        update_project(&mut change).unwrap();
        assert_eq!(change.world_projection.len(), 1);
        assert_eq!(
            wire(
                "Prefab",
                change.world_projection[0]
                    .before_definition
                    .as_ref()
                    .unwrap()
            )
            .unwrap(),
            wire("Prefab", &original).unwrap()
        );
        assert!(
            change
                .document_changes
                .iter()
                .all(|document| document.kind == OwnedKind::Instance
                    || document.before_revision.is_none())
        );
        assert!(
            ProjectCatalog::from_project(&change.project_after)
                .unwrap()
                .owned_pin(OwnedKind::Prefab, original.prefab_id.as_str())
                .is_ok()
        );
    }

    #[test]
    fn deleting_clip_target_or_parent_retains_failure_instead_of_erasing_references() {
        let (before, original, module, clip) = source();
        let mut candidate = original.clone();
        candidate
            .nodes
            .retain(|node| node.node_id.as_str() != "door");
        assert_eq!(
            make(&before, &original, candidate, module.clone(), clip.clone())
                .err()
                .unwrap()
                .code,
            "REFERENCE_UNRESOLVED"
        );
        let mut candidate = original.clone();
        candidate
            .nodes
            .retain(|node| node.node_id.as_str() != "root");
        assert!(make(&before, &original, candidate, module, clip).is_err());
    }

    #[test]
    fn transform_and_display_are_separate_overrides_and_missing_value_is_rejected() {
        let (mut before, mut original, _, _) = source();
        let node_before = serde_json::to_value(&original.nodes).unwrap();
        let transform =
            json!({"kind":"trs","translation":[3,4,0],"rotationXyzw":[0,0,0,1],"scale":[1,1,1]});
        apply_node_edit(&mut before,&mut original,&json!({"kind":"update_transform","instanceId":"instance-shop-a","nodeId":"sign","transform":transform})).unwrap();
        let display = serde_json::to_value(
            original
                .nodes
                .iter()
                .find(|node| node.node_id.as_str() == "sign")
                .unwrap()
                .display
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        apply_node_edit(&mut before,&mut original,&json!({"kind":"update_display","instanceId":"instance-shop-a","nodeId":"sign","display":display})).unwrap();
        assert_eq!(before.overrides.len(), 2);
        assert_eq!(serde_json::to_value(&original.nodes).unwrap(), node_before);
        assert_eq!(
            apply_node_edit(
                &mut before,
                &mut original,
                &json!({"kind":"update_transform","instanceId":"instance-shop-a","nodeId":"sign"})
            )
            .err()
            .unwrap()
            .code,
            "INVALID_INPUT"
        );
    }

    #[test]
    fn variant_identity_and_rebinding_preserve_separate_owned_kind_namespaces() {
        let (mut before, mut original, mut module, clip) = source();
        let self_symbol = mmmm_contracts::SymbolId::new("self_object").unwrap();
        let self_reference = SymbolReference {
            symbol_id: self_symbol.clone(),
            kind: "object".into(),
            scope: ReferenceScope::Local,
            target_id: original.prefab_id.as_str().into(),
        };
        original.references.push(self_reference.clone());
        module.commands[0].references.push(self_reference);
        before.bindings.push(SymbolBinding {
            symbol_id: self_symbol,
            target_id: authoring_target(&before.instance_id, "object", original.prefab_id.as_str()),
        });
        let mut physics: Value =
            serde_json::from_str(include_str!("../../../examples/physics-definition.json"))
                .unwrap();
        physics["physicsId"] = json!(original.prefab_id.as_str());
        physics["revision"] = json!(projected_digest("PhysicsDefinition", &physics).unwrap());
        original
            .nodes
            .iter_mut()
            .find(|node| node.node_id.as_str() == "door")
            .unwrap()
            .physics_binding = Some(mmmm_domain::types::PhysicsBinding {
            physics_id: PhysicsId::new(original.prefab_id.as_str()).unwrap(),
            body_id: mmmm_contracts::BodyId::new("body-door").unwrap(),
        });
        module.revision =
            projected_digest("CommandModule", &wire("CommandModule", &module).unwrap()).unwrap();
        revisions(&mut before, &mut original);
        let build = || {
            build_variant(
                &before,
                before.clone(),
                &original,
                original.clone(),
                vec![module.clone()],
                vec![clip.clone()],
                vec![physics.clone()],
                &json!({"testPurpose":"typed authored identity collision"}),
            )
            .unwrap()
        };
        let variant = build();
        let prefab_id = variant.definition.prefab_id.as_str();
        let physics_id = text(&variant.physics[0], "physicsId").unwrap();
        assert_ne!(prefab_id, physics_id);
        assert_eq!(
            variant.definition.references.last().unwrap().target_id,
            prefab_id
        );
        assert_eq!(
            variant.modules[0].commands[0]
                .references
                .last()
                .unwrap()
                .target_id,
            prefab_id
        );
        assert_eq!(
            variant.after.bindings.last().unwrap().target_id,
            authoring_target(&before.instance_id, "object", prefab_id)
        );
        assert_eq!(
            variant
                .definition
                .nodes
                .iter()
                .find(|node| node.node_id.as_str() == "door")
                .unwrap()
                .physics_binding
                .as_ref()
                .unwrap()
                .physics_id
                .as_str(),
            physics_id
        );
        let mut project: Value =
            serde_json::from_str(include_str!("../../../examples/project.json")).unwrap();
        for pin in project["ownedResources"].as_array_mut().unwrap() {
            match pin["kind"].as_str().unwrap() {
                "prefab" => pin["revision"] = json!(original.revision),
                "instance" => pin["revision"] = json!(before.revision),
                "command_module" => pin["revision"] = json!(module.revision),
                _ => {}
            }
        }
        // An unrelated PhysicsDefinition may legitimately have the same lexical
        // ID as this new Prefab; ownership identity includes the declared kind.
        project["ownedResources"]
            .as_array_mut()
            .unwrap()
            .push(json!({"kind":"physics_definition","objectId":prefab_id,"revision":physics["revision"]}));
        project["revision"] = json!(projected_digest("Project", &project).unwrap());
        let catalog = ProjectCatalog::from_project(&project).unwrap();
        let mut change = empty_change(&catalog, NativeKind::ScenePatch);
        append_variant(
            &catalog,
            &mut change,
            before.clone(),
            original.clone(),
            variant,
        )
        .unwrap();
        assert_eq!(
            append_variant(
                &catalog,
                &mut change,
                before.clone(),
                original.clone(),
                build(),
            )
            .err()
            .unwrap()
            .code,
            "ID_COLLISION"
        );
    }

    #[test]
    fn physics_variant_preserves_semantic_local_ids_and_original_definition() {
        let (mut before, mut original, module, clip) = source();
        let physics: Value =
            serde_json::from_str(include_str!("../../../examples/physics-definition.json"))
                .unwrap();
        original
            .nodes
            .iter_mut()
            .find(|node| node.node_id.as_str() == "door")
            .unwrap()
            .physics_binding = Some(mmmm_domain::types::PhysicsBinding {
            physics_id: PhysicsId::new("physics-door").unwrap(),
            body_id: mmmm_contracts::BodyId::new("body-door").unwrap(),
        });
        revisions(&mut before, &mut original);
        let variant = build_variant(
            &before,
            before.clone(),
            &original,
            original.clone(),
            vec![module],
            vec![clip],
            vec![physics.clone()],
            &json!({"commandVariant":true}),
        )
        .unwrap();
        assert_ne!(variant.physics[0]["physicsId"], physics["physicsId"]);
        assert_eq!(variant.physics[0]["bodies"], physics["bodies"]);
        assert_eq!(variant.physics[0]["colliders"], physics["colliders"]);
        assert_eq!(variant.physics[0]["materials"], physics["materials"]);
        let binding = variant
            .definition
            .nodes
            .iter()
            .find(|node| node.node_id.as_str() == "door")
            .unwrap()
            .physics_binding
            .as_ref()
            .unwrap();
        assert_eq!(
            binding.physics_id.as_str(),
            text(&variant.physics[0], "physicsId").unwrap()
        );
        assert_eq!(
            original
                .nodes
                .iter()
                .find(|node| node.node_id.as_str() == "door")
                .unwrap()
                .physics_binding
                .as_ref()
                .unwrap()
                .physics_id
                .as_str(),
            "physics-door"
        );
    }

    #[test]
    fn physical_body_shared_with_unselected_instance_fails_closed() {
        let (before, mut prefab, _, _) = source();
        prefab
            .nodes
            .iter_mut()
            .find(|node| node.node_id.as_str() == "door")
            .unwrap()
            .physics_binding = Some(mmmm_domain::types::PhysicsBinding {
            physics_id: PhysicsId::new("physics-door").unwrap(),
            body_id: mmmm_contracts::BodyId::new("body-door").unwrap(),
        });
        let mut physics: Value =
            serde_json::from_str(include_str!("../../../examples/physics-definition.json"))
                .unwrap();
        let mut foreign = physics["bodies"][0]["visualBindings"][0].clone();
        foreign["node"]["instanceId"] = json!("instance-shop-b");
        physics["bodies"][0]["visualBindings"]
            .as_array_mut()
            .unwrap()
            .push(foreign);
        assert_eq!(
            physics_variant(&physics, &before.instance_id, &prefab)
                .err()
                .unwrap()
                .code,
            "CAPABILITY_UNAVAILABLE"
        );
    }

    #[test]
    fn last_physical_binding_removal_and_unbound_retained_visual_fail_closed() {
        let (before, mut prefab, _, _) = source();
        let physics: Value =
            serde_json::from_str(include_str!("../../../examples/physics-definition.json"))
                .unwrap();
        assert_eq!(
            physics_variant(&physics, &before.instance_id, &prefab)
                .err()
                .unwrap()
                .code,
            "CAPABILITY_UNAVAILABLE"
        );
        prefab
            .nodes
            .iter_mut()
            .find(|node| node.node_id.as_str() == "door")
            .unwrap()
            .physics_binding = Some(mmmm_domain::types::PhysicsBinding {
            physics_id: PhysicsId::new("physics-door").unwrap(),
            body_id: mmmm_contracts::BodyId::new("body-door").unwrap(),
        });
        let mut physics = physics;
        let mut visual = physics["bodies"][0]["visualBindings"][0].clone();
        visual["node"]["nodeId"] = json!("sign");
        physics["bodies"][0]["visualBindings"]
            .as_array_mut()
            .unwrap()
            .push(visual);
        assert_eq!(
            physics_variant(&physics, &before.instance_id, &prefab)
                .err()
                .unwrap()
                .code,
            "REFERENCE_UNRESOLVED"
        );
    }

    #[test]
    fn manual_source_map_resolves_actual_node_payload_and_rejects_missing_locator() {
        let (before, prefab, _, _) = source();
        let selection = Selection::from_value(
            &serde_json::from_str(include_str!("../../../examples/scene-selection.json")).unwrap(),
        )
        .unwrap();
        let artifact = wire("Prefab", &prefab).unwrap();
        let resource = ResourceRef {
            resource_id: mmmm_contracts::ResourceId::new("artifact-prefab").unwrap(),
            sha256: mmmm_contracts::raw_digest(&mmmm_contracts::encode_json(&artifact).unwrap()),
            media_type: "application/json".into(),
            size_bytes: mmmm_contracts::encode_json(&artifact).unwrap().len() as u64,
        };
        let index = prefab
            .nodes
            .iter()
            .position(|node| node.node_id.as_str() == "sign")
            .unwrap();
        let entry = json!({"kind":"update_display","instanceId":before.instance_id,"nodeId":"sign","display":artifact["nodes"][index]["display"]});
        let mut map = json!({"entries":[{"sourceObjectId":"instance-shop-a","sourceNodeId":"sign","outputResourceId":"artifact-prefab","locator":format!("/nodes/{index}/display")} ]});
        manual_mapping(&entry, &artifact, &map, &resource, &selection).unwrap();
        map["entries"][0]["locator"] = json!("display-name");
        assert_eq!(
            manual_mapping(&entry, &artifact, &map, &resource, &selection)
                .err()
                .unwrap()
                .code,
            "OBJECT_MAPPING_AMBIGUOUS"
        );
        let mut changed = entry.clone();
        changed["display"]["payload"]["text"] = json!("unverified replacement");
        map["entries"][0]["locator"] = json!(format!("/nodes/{index}/display"));
        assert_eq!(
            manual_mapping(&changed, &artifact, &map, &resource, &selection)
                .err()
                .unwrap()
                .code,
            "REVISION_CONFLICT"
        );
    }
}

//! FN28: import is an explicit immutable proposal. Stable identities and exact
//! base revisions define its boundary; missing fields never become deletions.
use crate::archive::ArchiveLimits;
use crate::bake::IngestedBake;
use crate::resources::{ResourcePort, ResourcePurpose, parse_resource, read_resource};
use crate::selection::{ObjectNode, Selection};
use crate::{ExchangeError, ExchangeResult, array, text, validate};
use mmmm_contracts::{Sha256Digest, canonical_digest};
use mmmm_domain::transform::Transform;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeltaKind {
    CreateNode,
    UpdateTransform,
    UpdateDisplay,
    DeleteNode,
    AttachClip,
}
impl DeltaKind {
    fn wire(self) -> &'static str {
        match self {
            Self::CreateNode => "create_node",
            Self::UpdateTransform => "update_transform",
            Self::UpdateDisplay => "update_display",
            Self::DeleteNode => "delete_node",
            Self::AttachClip => "attach_clip",
        }
    }
}
/// Local allowed deltas bound a pure proposal. They are not a runtime grant and
/// cannot approve world writes; common application policy/grant checks still run.
#[derive(Clone, Debug, Default)]
pub struct DeltaPolicy {
    allowed: BTreeMap<ObjectNode, BTreeSet<DeltaKind>>,
    approved_loss_digests: BTreeSet<Sha256Digest>,
}
impl DeltaPolicy {
    pub fn allow(&mut self, target: ObjectNode, kind: DeltaKind) -> ExchangeResult<()> {
        if self.allowed.len() >= 65536 && !self.allowed.contains_key(&target) {
            return Err(ExchangeError::new(
                "BUDGET_EXCEEDED",
                "Allowed delta map exceeds its finite object limit",
            ));
        }
        self.allowed.entry(target).or_default().insert(kind);
        Ok(())
    }
    pub fn acknowledge_loss(&mut self, loss: &Value) -> ExchangeResult<()> {
        validate("LossRecord", loss)?;
        if self.approved_loss_digests.len() >= 1024 {
            return Err(ExchangeError::new(
                "BUDGET_EXCEEDED",
                "Loss acknowledgements exceed their finite limit",
            ));
        }
        self.approved_loss_digests.insert(
            canonical_digest(loss)
                .map_err(|e| ExchangeError::new("SCHEMA_INVALID", e.to_string()))?,
        );
        Ok(())
    }
    pub fn check(&self, target: &ObjectNode, kind: DeltaKind) -> ExchangeResult<()> {
        if !self
            .allowed
            .get(target)
            .is_some_and(|allowed| allowed.contains(&kind))
        {
            return Err(ExchangeError::new(
                "PERMISSION_REQUIRED",
                "Proposal exceeds the explicitly allowed qualified object delta",
            ));
        }
        Ok(())
    }
    fn losses(&self, losses: &[Value]) -> ExchangeResult<()> {
        if losses.len() > 1024 {
            return Err(ExchangeError::new(
                "BUDGET_EXCEEDED",
                "Loss list exceeds its finite limit",
            ));
        }
        for loss in losses {
            validate("LossRecord", loss)?;
            if loss["severity"] == "error"
                || matches!(
                    loss["disposition"].as_str(),
                    Some("unsupported" | "unknown")
                )
            {
                return Err(ExchangeError::new(
                    "UNSUPPORTED_FORMAT",
                    "Unsupported or unknown representation loss cannot be approved into a supported import",
                ));
            }
            if loss["approvalRequired"] == true
                && !self.approved_loss_digests.contains(
                    &canonical_digest(loss)
                        .map_err(|e| ExchangeError::new("SCHEMA_INVALID", e.to_string()))?,
                )
            {
                return Err(ExchangeError::new(
                    "LOSS_APPROVAL_REQUIRED",
                    "Loss requires acknowledgement of its exact subject/feature/disposition",
                ));
            }
        }
        Ok(())
    }
}

/// Internal typed edit DTOs do not define another wire schema. All emitted nodes,
/// displays, transforms and patch entries cross the original schema unchanged.
#[derive(Clone, Debug)]
pub enum SceneEdit {
    Existing {
        target: ObjectNode,
        transform: Option<Value>,
        display: Option<Value>,
    },
    Create {
        target: ObjectNode,
        node: Value,
    },
    Delete {
        target: ObjectNode,
    },
}

pub fn diff_scene_edits(
    selection: &Selection,
    edits: &[SceneEdit],
    source_artifact: &Value,
    source_map: &Value,
    losses: &[Value],
    patch_id: &str,
    policy: &DeltaPolicy,
) -> ExchangeResult<Value> {
    validate("ResourceRef", source_artifact)?;
    validate("ResourceRef", source_map)?;
    policy.losses(losses)?;
    if edits.len() > 4096 {
        return Err(ExchangeError::new(
            "BUDGET_EXCEEDED",
            "Scene edits exceed the finite patch limit",
        ));
    }
    let mut entries = Vec::new();
    let mut touched = BTreeSet::new();
    let mut created = BTreeMap::new();
    for edit in edits {
        match edit {
            SceneEdit::Existing {
                target,
                transform,
                display,
            } => {
                let base = selected_node(selection, target)?;
                if let Some(transform) = transform {
                    validate("Transform", transform)?;
                    Transform::from_value(transform)
                        .map_err(|e| ExchangeError::new("UNSUPPORTED_TRANSFORM", e.to_string()))?;
                    if base["transform"] != *transform {
                        push_delta(
                            &mut entries,
                            &mut touched,
                            target,
                            DeltaKind::UpdateTransform,
                            "transform",
                            Some(transform),
                            policy,
                        )?;
                    }
                }
                if let Some(display) = display {
                    validate("Display", display)?;
                    if base.get("display") != Some(display) {
                        push_delta(
                            &mut entries,
                            &mut touched,
                            target,
                            DeltaKind::UpdateDisplay,
                            "display",
                            Some(display),
                            policy,
                        )?;
                    }
                }
            }
            SceneEdit::Create { target, node } => {
                validate("Node", node)?;
                Transform::from_value(&node["transform"])
                    .map_err(|e| ExchangeError::new("UNSUPPORTED_TRANSFORM", e.to_string()))?;
                if node["nodeId"].as_str() != Some(target.node_id.as_str())
                    || selection.node(target).is_some()
                    || selection.prefab_for(&target.instance_id).is_none()
                    || created.insert(target.clone(), node).is_some()
                {
                    return Err(ExchangeError::new(
                        "OBJECT_MAPPING_AMBIGUOUS",
                        "Create needs a new stable node ID in an existing explicitly scoped instance",
                    ));
                }
                push_delta(
                    &mut entries,
                    &mut touched,
                    target,
                    DeltaKind::CreateNode,
                    "node",
                    Some(node),
                    policy,
                )?;
            }
            SceneEdit::Delete { target } => {
                selected_node(selection, target)?;
                push_delta(
                    &mut entries,
                    &mut touched,
                    target,
                    DeltaKind::DeleteNode,
                    "",
                    None,
                    policy,
                )?;
            }
        }
    }
    // One canonical validation path checks incompatible operations before
    // constructing the candidate graph, then validates every resulting edit.
    let patch = make_patch(
        selection,
        patch_id,
        source_artifact,
        source_map,
        entries,
        losses,
    )?;
    validate_scene_patch(&patch, selection, policy)?;
    Ok(patch)
}

/// Original SceneImportRequest imports a verified bake. The SourceMap must map
/// each clip track locator to a stable qualified instance/node at this exact base
/// revision. A display label or node ID shared by two instances is insufficient.
pub fn scene_diff(
    input: &Value,
    ingested: &IngestedBake,
    patch_id: &str,
    policy: &DeltaPolicy,
    resources: &mut dyn ResourcePort,
    limits: ArchiveLimits,
) -> ExchangeResult<Value> {
    validate("SceneImportRequest", input)?;
    if &input["artifact"] != ingested.artifact() {
        return Err(ExchangeError::new(
            "INPUT_DIGEST_MISMATCH",
            "Import artifact differs from the verified ingested bytes",
        ));
    }
    let selection = Selection::from_value(&input["selection"])?;
    ingested.check_selection(&selection)?;
    resources.authorize_selection(text(input, "contextId")?, selection.value())?;
    let map_bytes = read_resource(
        resources,
        text(input, "contextId")?,
        &input["sourceMap"],
        ResourcePurpose::Read,
        limits.max_member_bytes,
    )?;
    let map = parse_resource("SourceMap", &map_bytes.bytes)?;
    if map["inputRevision"] != selection.value()["projectRevision"] {
        return Err(ExchangeError::new(
            "REVISION_CONFLICT",
            "Import source map belongs to a different base project revision",
        ));
    }
    if input["artifact"]["representation"] == "triangulated_surface_samples" {
        return Err(ExchangeError::new(
            "CAPABILITY_UNAVAILABLE",
            "Surface-to-game installation requires a declared surface compiler/runtime profile",
        ));
    }
    let mut entries = Vec::new();
    let mut touched = BTreeSet::new();
    let mut loss_map = BTreeMap::new();
    for loss in array(&input["artifact"], "losses")? {
        loss_map.insert(
            canonical_digest(loss)
                .map_err(|e| ExchangeError::new("SCHEMA_INVALID", e.to_string()))?,
            loss.clone(),
        );
    }
    for (clip_index, clip) in array(&input["artifact"], "clips")?.iter().enumerate() {
        policy.losses(array(clip, "losses")?)?;
        for loss in array(clip, "losses")? {
            loss_map.insert(
                canonical_digest(loss)
                    .map_err(|e| ExchangeError::new("SCHEMA_INVALID", e.to_string()))?,
                loss.clone(),
            );
        }
        for (track_index, track) in array(clip, "tracks")?.iter().enumerate() {
            let locator = format!("/clips/{clip_index}/tracks/{track_index}");
            let candidates: Vec<_> = array(&map, "entries")?
                .iter()
                .filter(|entry| {
                    entry["locator"].as_str() == Some(locator.as_str())
                        && entry["outputResourceId"] == ingested.resource()["resourceId"]
                        && entry["sourceNodeId"] == track["nodeId"]
                })
                .collect();
            if candidates.len() != 1 {
                return Err(ExchangeError::new(
                    "OBJECT_MAPPING_AMBIGUOUS",
                    "Each imported track needs one exact stable source mapping",
                ));
            }
            let target = ObjectNode {
                instance_id: text(candidates[0], "sourceObjectId")?.to_owned(),
                node_id: text(track, "nodeId")?.to_owned(),
            };
            selected_node(&selection, &target)?;
            if selection.prefab_for(&target.instance_id) != clip["ownerPrefabId"].as_str() {
                return Err(ExchangeError::new(
                    "OBJECT_MAPPING_AMBIGUOUS",
                    "Imported clip owner differs from the mapped instance prefab",
                ));
            }
            if !touched.insert(target.clone()) {
                return Err(ExchangeError::new(
                    "POSE_WRITER_CONFLICT",
                    "Several imported tracks claim the same final pose writer",
                ));
            }
            policy.check(&target, DeltaKind::AttachClip)?;
            let canonical_clip = ingested.canonical_clips().get(clip_index).ok_or_else(|| {
                ExchangeError::new("INCOMPLETE_OUTPUT", "Canonical clip derivation is absent")
            })?;
            entries.push(json!({"kind":"attach_clip","instanceId":target.instance_id,"nodeId":target.node_id,"clipId":canonical_clip["clipId"]}));
        }
    }
    let losses = loss_map.into_values().collect::<Vec<_>>();
    policy.losses(&losses)?;
    let patch = make_patch(
        &selection,
        patch_id,
        ingested.resource(),
        &input["sourceMap"],
        entries,
        &losses,
    )?;
    validate_scene_patch(&patch, &selection, policy)?;
    Ok(patch)
}

pub fn validate_scene_patch(
    patch: &Value,
    selection: &Selection,
    policy: &DeltaPolicy,
) -> ExchangeResult<()> {
    validate("ScenePatch", patch)?;
    selection.check_revision(text(patch, "projectId")?, text(patch, "baseRevision")?)?;
    policy.losses(array(patch, "losses")?)?;
    if array(patch, "entries")?.len() > 4096 {
        return Err(ExchangeError::new(
            "BUDGET_EXCEEDED",
            "Patch exceeds its finite entry limit",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut created = BTreeMap::new();
    let mut deleted = BTreeSet::new();
    let mut target_operations: BTreeMap<ObjectNode, BTreeSet<DeltaKind>> = BTreeMap::new();
    for entry in array(patch, "entries")? {
        let target = ObjectNode {
            instance_id: text(entry, "instanceId")?.to_owned(),
            node_id: text(entry, "nodeId")?.to_owned(),
        };
        let kind = match text(entry, "kind")? {
            "create_node" => DeltaKind::CreateNode,
            "update_transform" => DeltaKind::UpdateTransform,
            "update_display" => DeltaKind::UpdateDisplay,
            "delete_node" => DeltaKind::DeleteNode,
            "attach_clip" => DeltaKind::AttachClip,
            _ => {
                return Err(ExchangeError::new(
                    "SCHEMA_INVALID",
                    "Unknown scene patch entry",
                ));
            }
        };
        if !seen.insert((target.clone(), kind)) {
            return Err(ExchangeError::new(
                "OBJECT_MAPPING_AMBIGUOUS",
                "Duplicate patch operation on the same stable node",
            ));
        }
        target_operations
            .entry(target.clone())
            .or_default()
            .insert(kind);
        policy.check(&target, kind)?;
        if kind == DeltaKind::CreateNode {
            if selection.node(&target).is_some()
                || selection.prefab_for(&target.instance_id).is_none()
                || entry["node"]["nodeId"].as_str() != Some(target.node_id.as_str())
            {
                return Err(ExchangeError::new(
                    "OBJECT_MAPPING_AMBIGUOUS",
                    "Create collides with existing IDs or crosses the instance boundary",
                ));
            }
            Transform::from_value(&entry["node"]["transform"])
                .map_err(|e| ExchangeError::new("UNSUPPORTED_TRANSFORM", e.to_string()))?;
            created.insert(target, &entry["node"]);
        } else {
            selected_node(selection, &target)?;
            if kind == DeltaKind::DeleteNode {
                deleted.insert(target);
            } else if kind == DeltaKind::UpdateTransform {
                Transform::from_value(&entry["transform"])
                    .map_err(|e| ExchangeError::new("UNSUPPORTED_TRANSFORM", e.to_string()))?;
            }
        }
    }
    for kinds in target_operations.values() {
        if kinds.len() > 1
            && (kinds.contains(&DeltaKind::DeleteNode) || kinds.contains(&DeltaKind::CreateNode))
        {
            return Err(ExchangeError::new(
                "OBJECT_MAPPING_AMBIGUOUS",
                "Create/delete cannot coexist with another operation on the same node",
            ));
        }
    }
    validate_result_graph(selection, &created, &deleted, array(patch, "entries")?)
}

fn selected_node<'a>(selection: &'a Selection, target: &ObjectNode) -> ExchangeResult<&'a Value> {
    if !selection.selected(target) {
        return Err(ExchangeError::new(
            "REFERENCE_UNRESOLVED",
            "Patch target is outside the stable selected boundary",
        ));
    }
    selection
        .node(target)
        .ok_or_else(|| ExchangeError::new("REFERENCE_UNRESOLVED", "Patch target is missing"))
}
fn push_delta(
    entries: &mut Vec<Value>,
    touched: &mut BTreeSet<(ObjectNode, DeltaKind)>,
    target: &ObjectNode,
    kind: DeltaKind,
    field: &str,
    value: Option<&Value>,
    policy: &DeltaPolicy,
) -> ExchangeResult<()> {
    policy.check(target, kind)?;
    if !touched.insert((target.clone(), kind)) {
        return Err(ExchangeError::new(
            "OBJECT_MAPPING_AMBIGUOUS",
            "Duplicate edit for stable object field",
        ));
    }
    let mut entry =
        json!({"kind":kind.wire(),"instanceId":target.instance_id,"nodeId":target.node_id});
    if let Some(value) = value {
        entry[field] = value.clone();
    }
    validate("ScenePatchEntry", &entry)?;
    entries.push(entry);
    Ok(())
}
fn make_patch(
    selection: &Selection,
    patch_id: &str,
    source: &Value,
    map: &Value,
    entries: Vec<Value>,
    losses: &[Value],
) -> ExchangeResult<Value> {
    let patch = json!({"contractVersion":"0.2.0","patchId":patch_id,"projectId":selection.value()["projectId"],"baseRevision":selection.value()["projectRevision"],"sourceArtifact":source,"entries":entries,"sourceMap":map,"losses":losses,"absenceMeansDeletion":false});
    validate("ScenePatch", &patch)?;
    Ok(patch)
}
fn validate_result_graph(
    selection: &Selection,
    created: &BTreeMap<ObjectNode, &Value>,
    deleted: &BTreeSet<ObjectNode>,
    entries: &[Value],
) -> ExchangeResult<()> {
    let affected: BTreeSet<_> = created
        .keys()
        .chain(deleted.iter())
        .map(|target| target.instance_id.as_str())
        .chain(
            entries
                .iter()
                .filter(|entry| {
                    matches!(
                        entry["kind"].as_str(),
                        Some("update_transform" | "update_display")
                    )
                })
                .filter_map(|entry| entry["instanceId"].as_str()),
        )
        .collect();
    for instance_id in affected {
        let prefab_id = selection.prefab_for(instance_id).ok_or_else(|| {
            ExchangeError::new("REFERENCE_UNRESOLVED", "Edited instance is absent")
        })?;
        let mut variant = array(selection.value(), "prefabs")?
            .iter()
            .find(|prefab| prefab["prefabId"].as_str() == Some(prefab_id))
            .ok_or_else(|| ExchangeError::new("REFERENCE_UNRESOLVED", "Edited prefab is absent"))?
            .clone();
        let semantic = selection.semantic_prefab(prefab_id);
        if let Some(semantic) = semantic {
            // These values come only from the same Prefab bytes validated by
            // Selection; the original selection and its pins stay unchanged.
            variant["resources"] = semantic.resources.clone();
        }
        let mut nodes: Vec<Value> = selection
            .nodes()
            .filter(|(target, _)| target.instance_id == instance_id && !deleted.contains(*target))
            .map(|(target, node)| {
                let mut candidate = node.clone();
                if let Some(semantic) = semantic {
                    match (
                        node.get("geometryResource"),
                        semantic.geometry.get(&target.node_id),
                    ) {
                        (Some(_), Some(resource)) => {
                            candidate["geometryResource"] = resource.clone()
                        }
                        (None, None) => {}
                        _ => {
                            return Err(ExchangeError::new(
                                "REFERENCE_UNRESOLVED",
                                "Validated geometry comparison differs",
                            ));
                        }
                    }
                }
                Ok(candidate)
            })
            .collect::<ExchangeResult<_>>()?;
        nodes.extend(
            created
                .iter()
                .filter(|(target, _)| target.instance_id == instance_id)
                .map(|(_, node)| (*node).clone()),
        );
        for entry in entries
            .iter()
            .filter(|entry| entry["instanceId"] == instance_id)
        {
            let field = match entry["kind"].as_str() {
                Some("update_transform") => "transform",
                Some("update_display") => "display",
                _ => continue,
            };
            let node = nodes
                .iter_mut()
                .find(|node| node["nodeId"] == entry["nodeId"])
                .ok_or_else(|| {
                    ExchangeError::new("REFERENCE_UNRESOLVED", "Updated candidate node is absent")
                })?;
            node[field] = entry[field].clone();
        }
        variant["nodes"] = json!(nodes);
        // Candidate validation preserves the original immutable prefab elsewhere;
        // this temporary value has no new revision and is never committed here.
        let diagnostics = mmmm_domain::prefab_validate(&variant)
            .map_err(|e| ExchangeError::new("REFERENCE_UNRESOLVED", e.to_string()))?;
        if array(&diagnostics, "diagnostics")?
            .iter()
            .any(|diagnostic| diagnostic["severity"] == "error")
        {
            return Err(ExchangeError::new(
                "REFERENCE_UNRESOLVED",
                "Proposed scene edit violates retained prefab graph/port/state/display/resource references",
            ));
        }
    }
    Ok(())
}

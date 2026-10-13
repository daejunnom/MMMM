//! Spatial trees and resource references are validated separately. A behavioral
//! cycle is not a spatial parent cycle; this module never infers parentage from
//! a display name or a command string.

use crate::{transform::Matrix4, types::{Diagnostic, DomainError, InstanceOverride, Node, Prefab}};
use mmmm_contracts::NodeId;
use std::collections::{BTreeMap, BTreeSet};

pub fn spatial_diagnostics(nodes: &[Node]) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let mut indexed = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        if indexed.insert(node.node_id.clone(), index).is_some() {
            diagnostics.push(Diagnostic::error("DUPLICATE_ID", "A node ID occurs more than once",
                Some(node.node_id.as_str()), &format!("/nodes/{index}/nodeId")));
        }
    }
    let roots = nodes.iter().filter(|node| node.parent_id.is_none()).count();
    if roots != 1 {
        diagnostics.push(Diagnostic::error("SPATIAL_ROOT_COUNT", format!("Expected one root, found {roots}"), None, "/nodes"));
    }
    for (index, node) in nodes.iter().enumerate() {
        if let Some(parent) = &node.parent_id {
            if !indexed.contains_key(parent) {
                diagnostics.push(Diagnostic::error("REFERENCE_UNRESOLVED", "The spatial parent does not exist",
                    Some(node.node_id.as_str()), &format!("/nodes/{index}/parentId")));
            }
        }
    }
    // Iterative traversal bounds stack usage even when the canonical DTO permits
    // a long parent chain. Each ID reaches a terminal state once.
    let mut finished = BTreeSet::new();
    for node in nodes {
        if finished.contains(&node.node_id) { continue; }
        let mut chain = Vec::new();
        let mut in_chain = BTreeSet::new();
        let mut current = Some(node.node_id.clone());
        while let Some(id) = current {
            if finished.contains(&id) { break; }
            if !in_chain.insert(id.clone()) {
                diagnostics.push(Diagnostic::error("SPATIAL_CYCLE", "Spatial parent links form a cycle",
                    Some(id.as_str()), "/nodes"));
                break;
            }
            let Some(index) = indexed.get(&id) else { break; };
            chain.push(id);
            current = nodes[*index].parent_id.clone();
        }
        finished.extend(chain);
    }
    diagnostics
}

/// World transforms include placement and typed transform overrides. Ports
/// remain node-local, so moving placement never rewrites their authoring values.
pub fn world_transforms(prefab: &Prefab, placement: &crate::transform::Transform,
    overrides: &[InstanceOverride]) -> Result<BTreeMap<NodeId, Matrix4>, DomainError> {
    let diagnostics = spatial_diagnostics(&prefab.nodes);
    if !diagnostics.is_empty() {
        return Err(DomainError::with_diagnostics("SCHEMA_INVALID", diagnostics));
    }
    let placement = placement.matrix().map_err(|error| DomainError::new(error.code(), error.to_string()))?;
    let indexed: BTreeMap<_, _> = prefab.nodes.iter().map(|node| (node.node_id.clone(), node)).collect();
    let transforms: BTreeMap<_, _> = overrides.iter().filter_map(|entry| match entry {
        InstanceOverride::Transform { node_id, transform } => Some((node_id, transform)),
        _ => None,
    }).collect();
    let mut worlds = BTreeMap::<NodeId, Matrix4>::new();
    for node in &prefab.nodes {
        let mut pending = Vec::new();
        let mut current = Some(node.node_id.clone());
        while let Some(id) = current {
            if worlds.contains_key(&id) { break; }
            let node = indexed.get(&id).ok_or_else(|| DomainError::new("REFERENCE_UNRESOLVED", "Missing spatial node"))?;
            pending.push(id);
            current = node.parent_id.clone();
        }
        while let Some(id) = pending.pop() {
            let node = indexed[&id];
            let local = transforms.get(&id).copied().unwrap_or(&node.transform)
                .matrix().map_err(|error| DomainError::new(error.code(), error.to_string()))?;
            let parent = match &node.parent_id {
                None => &placement,
                Some(parent_id) => worlds.get(parent_id).ok_or_else(|| DomainError::new("REFERENCE_UNRESOLVED", "Missing parent transform"))?,
            };
            let world = parent.multiply(&local)
                .map_err(|error| DomainError::new(error.code(), error.to_string()))?;
            worlds.insert(id, world);
        }
    }
    Ok(worlds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode;
    use serde_json::{Value, json};

    fn prefab() -> Prefab {
        let value: Value = mmmm_contracts::parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
        decode("Prefab", &value).unwrap()
    }

    #[test]
    fn graph_checks_stable_ids_without_name_inference() {
        let mut prefab = prefab();
        prefab.nodes[1].name = prefab.nodes[0].name.clone();
        assert!(spatial_diagnostics(&prefab.nodes).is_empty());
        prefab.nodes[1].node_id = prefab.nodes[0].node_id.clone();
        assert!(spatial_diagnostics(&prefab.nodes).iter().any(|diagnostic| diagnostic.code == "DUPLICATE_ID"));
    }

    #[test]
    fn cycle_is_distinct_from_a_missing_parent() {
        let mut prefab = prefab();
        prefab.nodes[0].parent_id = Some(prefab.nodes[1].node_id.clone());
        let codes: BTreeSet<_> = spatial_diagnostics(&prefab.nodes).into_iter().map(|diagnostic| diagnostic.code).collect();
        assert!(codes.contains("SPATIAL_CYCLE"));
        assert!(codes.contains("SPATIAL_ROOT_COUNT"));
        prefab.nodes[0].parent_id = None;
        prefab.nodes[1].parent_id = Some(NodeId::new("missing").unwrap());
        assert!(spatial_diagnostics(&prefab.nodes).iter().any(|diagnostic| diagnostic.code == "REFERENCE_UNRESOLVED"));
    }

    #[test]
    fn known_world_position_uses_parent_times_local() {
        let prefab = prefab();
        let placement = crate::transform::Transform::from_value(&json!({
            "kind":"trs", "translation":[10,20,30], "rotationXyzw":[0,0,0,1], "scale":[1,1,1]
        })).unwrap();
        let worlds = world_transforms(&prefab, &placement, &[]).unwrap();
        assert_eq!(worlds[&NodeId::new("sign").unwrap()].transform_point([0.0; 3]).unwrap(), [14.0,23.0,30.0]);
    }
}

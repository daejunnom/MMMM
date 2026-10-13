//! Definition semantic checks never resolve external resources or execute an
//! unknown component. Format validation and domain diagnostics are distinct.

use crate::{decode, encode, graph::spatial_diagnostics, state::state_diagnostics,
    types::{Diagnostic, DomainError, Prefab, ReferenceScope}};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize)]
struct DiagnosticList { diagnostics: Vec<Diagnostic> }

/// FN02: schema-invalid input is an error; well-formed but semantically invalid
/// definitions return the complete deterministic diagnostic list.
pub fn prefab_validate(value: &Value) -> Result<Value, DomainError> {
    let prefab: Prefab = decode("Prefab", value)?;
    encode("DiagnosticList", &DiagnosticList { diagnostics: semantic_diagnostics(&prefab) })
}

pub fn semantic_diagnostics(prefab: &Prefab) -> Vec<Diagnostic> {
    let mut diagnostics = spatial_diagnostics(&prefab.nodes);
    let nodes: BTreeSet<_> = prefab.nodes.iter().map(|node| node.node_id.as_str()).collect();
    let ports: BTreeSet<_> = prefab.ports.iter().map(|port| port.port_id.as_str()).collect();
    let states: BTreeSet<_> = prefab.state.iter().map(|state| state.state_id.as_str()).collect();
    let resources: BTreeSet<_> = prefab.resources.iter().map(|resource| resource.resource_id.as_str()).collect();
    let modules: BTreeSet<_> = prefab.command_module_ids.iter().map(|module| module.as_str()).collect();
    duplicates(prefab.ports.iter().map(|port| port.port_id.as_str()), "/ports", &mut diagnostics);
    duplicates(prefab.state.iter().map(|state| state.state_id.as_str()), "/state", &mut diagnostics);
    duplicates(prefab.references.iter().map(|reference| reference.symbol_id.as_str()), "/references", &mut diagnostics);
    duplicates(prefab.resources.iter().map(|resource| resource.resource_id.as_str()), "/resources", &mut diagnostics);

    for (index, node) in prefab.nodes.iter().enumerate() {
        if let Some(blocks) = &node.block_geometry {
            missing_resource(blocks.resource_id.as_str(), &resources, node.node_id.as_str(), &format!("/nodes/{index}/blockGeometry/resourceId"), &mut diagnostics);
            if blocks.bounds.min.iter().zip(blocks.bounds.max_exclusive).any(|(minimum, maximum)| *minimum > maximum) {
                diagnostics.push(Diagnostic::error("INVALID_BOUNDS", "Block bounds must have min <= maxExclusive on every axis",
                    Some(node.node_id.as_str()), &format!("/nodes/{index}/blockGeometry/bounds")));
            }
        }
        if let Some(display) = &node.display {
            for resource in &display.resource_refs {
                missing_resource(resource.as_str(), &resources, node.node_id.as_str(), &format!("/nodes/{index}/display/resourceRefs"), &mut diagnostics);
            }
            if display.kind == "text" && display.text_role.is_none() {
                diagnostics.push(Diagnostic::error("DISPLAY_ROLE_REQUIRED", "Text displays need an explicit label, hud, or background_geometry role",
                    Some(node.node_id.as_str()), &format!("/nodes/{index}/display/textRole")));
            }
            if display.kind != "text" && display.text_role.is_some() {
                diagnostics.push(Diagnostic::error("DISPLAY_ROLE_MISMATCH", "A text role applies only to a text display",
                    Some(node.node_id.as_str()), &format!("/nodes/{index}/display/textRole")));
            }
        }
        if let Some(geometry) = &node.geometry_resource {
            if let Some(registered) = prefab.resources.iter().find(|resource| resource.resource_id == geometry.resource_id) {
                if registered.sha256 != geometry.sha256 || registered.size_bytes != geometry.size_bytes || registered.media_type != geometry.media_type {
                    diagnostics.push(Diagnostic::error("RESOURCE_PIN_CONFLICT", "The same resource ID has inconsistent content pins",
                        Some(node.node_id.as_str()), &format!("/nodes/{index}/geometryResource")));
                }
            }
        }
        for (collider_index, collider) in node.colliders.iter().enumerate() {
            if collider.shape == "box" {
                let valid = collider.parameters.get("halfExtents").and_then(Value::as_array)
                    .is_some_and(|values| values.iter().all(|value| value.as_f64().is_some_and(|number| number.is_finite() && number > 0.0)));
                if !valid {
                    diagnostics.push(Diagnostic::error("INVALID_COLLIDER", "Box half extents must be finite and positive",
                        Some(node.node_id.as_str()), &format!("/nodes/{index}/colliders/{collider_index}/parameters/halfExtents")));
                }
            }
        }
    }
    for (index, port) in prefab.ports.iter().enumerate() {
        if !nodes.contains(port.node_id.as_str()) {
            diagnostics.push(Diagnostic::error("REFERENCE_UNRESOLVED", "Port node does not exist", Some(port.port_id.as_str()), &format!("/ports/{index}/nodeId")));
        }
    }
    diagnostics.extend(state_diagnostics(&prefab.state));
    for (index, state) in prefab.state.iter().enumerate() {
        if state.owner_node_id.as_ref().is_some_and(|id| !nodes.contains(id.as_str())) {
            diagnostics.push(Diagnostic::error("REFERENCE_UNRESOLVED", "State owner node does not exist", Some(state.state_id.as_str()), &format!("/state/{index}/ownerNodeId")));
        }
    }
    for (index, reference) in prefab.references.iter().enumerate() {
        if reference.scope != ReferenceScope::Local { continue; }
        let present = match reference.kind.as_str() {
            "node" => nodes.contains(reference.target_id.as_str()),
            "port" => ports.contains(reference.target_id.as_str()),
            "state" => states.contains(reference.target_id.as_str()),
            "resource" => resources.contains(reference.target_id.as_str()),
            "function" => modules.contains(reference.target_id.as_str()),
            "object" => reference.target_id == prefab.prefab_id.as_str(),
            _ => false,
        };
        if !present {
            diagnostics.push(Diagnostic::error("REFERENCE_UNRESOLVED", "A local typed reference has no target in this definition",
                Some(reference.symbol_id.as_str()), &format!("/references/{index}/targetId")));
        }
    }
    if let Some(source_map) = &prefab.source_map_resource_id {
        missing_resource(source_map.as_str(), &resources, prefab.prefab_id.as_str(), "/sourceMapResourceId", &mut diagnostics);
    }
    // State definitions and explicit references share the Instance bindings
    // namespace. A collision must be diagnosed before generating a symbol table.
    let references: BTreeSet<_> = prefab.references.iter().map(|reference| reference.symbol_id.as_str()).collect();
    for state in &prefab.state {
        if references.contains(state.state_id.as_str()) {
            diagnostics.push(Diagnostic::error("SYMBOL_ID_COLLISION", "State and reference symbol IDs collide",
                Some(state.state_id.as_str()), "/state"));
        }
    }
    diagnostics.sort_by(|a, b| (&a.path, &a.code, &a.object_id, &a.message).cmp(&(&b.path, &b.code, &b.object_id, &b.message)));
    diagnostics
}

pub fn require_valid(prefab: &Prefab) -> Result<(), DomainError> {
    let diagnostics = semantic_diagnostics(prefab);
    if diagnostics.iter().any(|diagnostic| diagnostic.severity == "error") {
        return Err(DomainError::with_diagnostics("SCHEMA_INVALID", diagnostics));
    }
    Ok(())
}

fn duplicates<'a>(ids: impl Iterator<Item = &'a str>, path: &str, diagnostics: &mut Vec<Diagnostic>) {
    let mut counts = BTreeMap::new();
    for id in ids { *counts.entry(id).or_insert(0) += 1; }
    for (id, count) in counts {
        if count > 1 {
            diagnostics.push(Diagnostic::error("DUPLICATE_ID", "A stable ID occurs more than once in its identity space", Some(id), path));
        }
    }
}

fn missing_resource(id: &str, resources: &BTreeSet<&str>, subject: &str, path: &str, diagnostics: &mut Vec<Diagnostic>) {
    if !resources.contains(id) {
        diagnostics.push(Diagnostic::error("REFERENCE_UNRESOLVED", "A declared resource is not pinned in this definition", Some(subject), path));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Value { mmmm_contracts::parse_json(include_bytes!("../../../examples/prefab.json")).unwrap() }

    #[test]
    fn original_prefab_is_semantically_valid_without_reading_its_resources() {
        assert_eq!(prefab_validate(&fixture()).unwrap(), json!({"diagnostics":[]}));
    }

    #[test]
    fn semantic_validation_is_deterministic_and_does_not_mutate_input() {
        let mut input = fixture();
        input["nodes"][1]["parentId"] = json!("absent");
        input["ports"][1]["nodeId"] = json!("absent");
        input["references"].as_array_mut().unwrap().push(json!({"symbolId":"local_bad","kind":"node","scope":"local","targetId":"absent"}));
        let before = input.clone();
        let a = prefab_validate(&input).unwrap();
        assert_eq!(a, prefab_validate(&input).unwrap());
        assert_eq!(input, before);
        assert_eq!(a["diagnostics"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn unknown_namespaced_component_is_preserved_without_execution() {
        let mut input = fixture();
        input["nodes"][0]["extensions"]["fixture:unknown"] = json!({"opaque":true,"value":null});
        let decoded: Prefab = decode("Prefab", &input).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap()["nodes"][0]["extensions"], input["nodes"][0]["extensions"]);
    }

    #[test]
    fn namespaced_project_and_external_ids_are_never_shortened() {
        let mut input = fixture();
        input["references"][0]["targetId"] = json!("custom_namespace:door/open");
        input["references"][0]["scope"] = json!("external");
        assert!(prefab_validate(&input).unwrap()["diagnostics"].as_array().unwrap().is_empty());
    }
}

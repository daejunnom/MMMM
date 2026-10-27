//! Traverse only ResourceRef locations owned by an already validated document.
//!
//! The caller supplies the kind from its verified source pin or checked change
//! key and remains responsible for validation, limits, authority and bytes.

use mmmm_application::{AppError, AppResult};
use mmmm_planner::OwnedKind;
use serde_json::Value;

pub(crate) fn visit_owned_resource_refs(
    kind: OwnedKind,
    value: &Value,
    mut check: impl FnMut() -> AppResult<()>,
    mut visit: impl FnMut(&Value) -> AppResult<()>,
    invalid: impl Fn() -> AppError,
) -> AppResult<()> {
    check()?;
    match kind {
        OwnedKind::Prefab => {
            for node in value["nodes"].as_array().ok_or_else(&invalid)? {
                check()?;
                if let Some(resource) = node.get("geometryResource") {
                    visit(resource)?;
                }
            }
            for resource in value["resources"].as_array().ok_or_else(&invalid)? {
                check()?;
                visit(resource)?;
            }
        }
        OwnedKind::Asset => visit(&value["resource"])?,
        OwnedKind::PhysicsDefinition => {
            for collider in value["colliders"].as_array().ok_or_else(&invalid)? {
                check()?;
                let shape = &collider["shape"]["shape"];
                match shape["kind"].as_str() {
                    Some("mesh") => visit(&shape["geometry"])?,
                    Some("box" | "sphere" | "capsule") => {}
                    _ => return Err(invalid()),
                }
            }
        }
        OwnedKind::Instance | OwnedKind::CommandModule | OwnedKind::Clip => {}
    }
    Ok(())
}

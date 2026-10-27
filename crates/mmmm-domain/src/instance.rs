//! FN03–FN05 create immutable authoring drafts. IDs are caller allocated;
//! runtime entities, worlds, state snapshots, and command payloads are not loaded.

use crate::{
    decode, encode,
    graph::world_transforms,
    prefab::require_valid,
    state::{effective_defaults, value_matches_type},
    transform::{Matrix4, Transform},
    types::*,
};
use mmmm_contracts::{InstanceId, ModuleId, Sha256Digest, StateId, SymbolId};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// A decoded snapshot is supplied by the application codec, not interpreted as
/// a second domain wire schema. This proof binds its raw blob to the ResourceRef
/// and its values to the source/prefab pins supplied by that trusted codec.
#[derive(Debug, Clone)]
pub struct ResolvedStateSnapshot {
    resource: ResourceRef,
    source_instance_id: InstanceId,
    prefab_revision: Sha256Digest,
    values: BTreeMap<StateId, ScalarValue>,
}

impl ResolvedStateSnapshot {
    pub fn from_verified_blob(
        resource: ResourceRef,
        raw_bytes: &[u8],
        source_instance_id: InstanceId,
        prefab_revision: Sha256Digest,
        values: BTreeMap<StateId, ScalarValue>,
    ) -> Result<Self, DomainError> {
        if resource.size_bytes != raw_bytes.len() as u64
            || resource.sha256 != mmmm_contracts::raw_digest(raw_bytes)
        {
            return Err(DomainError::new(
                "STATE_SNAPSHOT_REQUIRED",
                "Snapshot bytes do not match the pinned resource digest and length",
            ));
        }
        Ok(Self {
            resource,
            source_instance_id,
            prefab_revision,
            values,
        })
    }
}

/// FN03. The caller already owns the allocation registry. Use the contextual
/// entry point when that registry is available to this pure function.
pub fn instantiate(value: &Value) -> Result<Value, DomainError> {
    instantiate_with_existing_ids(value, &BTreeSet::new())
}

pub fn instantiate_with_existing_ids(
    value: &Value,
    used_ids: &BTreeSet<InstanceId>,
) -> Result<Value, DomainError> {
    let request: InstantiateRequest = decode("InstantiateRequest", value)?;
    require_valid(&request.prefab)?;
    if request.state_policy != "defaults" {
        return Err(DomainError::new(
            "SCHEMA_INVALID",
            "Instantiation requires definition defaults",
        ));
    }
    if used_ids.contains(&request.instance_id) {
        return Err(DomainError::new(
            "ID_COLLISION",
            "The allocated instance ID is already in use",
        ));
    }
    ensure_placement(&request.prefab, &request.placement, &[])?;
    let references = authored_bindings(&request.prefab, &request.instance_id, &[])?;
    let instance = Instance {
        contract_version: mmmm_contracts::CONTRACT_VERSION.into(),
        instance_id: request.instance_id,
        revision: zero_digest(),
        prefab_id: request.prefab.prefab_id.clone(),
        prefab_revision: request.prefab.revision.clone(),
        world_id: request.world_id,
        dimension: request.dimension,
        placement: request.placement,
        bindings: binding_pairs(&references),
        overrides: Vec::new(),
        lifecycle: Lifecycle::Planned,
    };
    finish_draft(instance, references, pending_diagnostics(&request.prefab))
}

/// FN04 defaults path. An opaque ResourceRef alone cannot establish live state;
/// explicit snapshots must use `clone_with_snapshot` after application decoding.
pub fn clone_instance(value: &Value) -> Result<Value, DomainError> {
    clone_with_snapshot(value, None, &BTreeSet::new())
}

pub fn clone_with_snapshot(
    value: &Value,
    snapshot: Option<&ResolvedStateSnapshot>,
    used_ids: &BTreeSet<InstanceId>,
) -> Result<Value, DomainError> {
    let request: CloneRequest = decode("CloneRequest", value)?;
    require_source(&request.source, &request.definition)?;
    if request.allocated_instance_id == request.source.instance_id
        || used_ids.contains(&request.allocated_instance_id)
    {
        return Err(DomainError::new(
            "ID_COLLISION",
            "Cloning requires an independently allocated instance ID",
        ));
    }
    let mut overrides = request.source.overrides.clone();
    if request.state_policy == "explicit_snapshot" {
        let reference = request.state_snapshot.as_ref().ok_or_else(|| {
            DomainError::new(
                "STATE_SNAPSHOT_REQUIRED",
                "An explicit snapshot reference is required",
            )
        })?;
        let snapshot = snapshot.ok_or_else(|| {
            DomainError::new(
                "STATE_SNAPSHOT_REQUIRED",
                "The pinned snapshot has not been decoded and verified",
            )
        })?;
        if reference.resource_id != snapshot.resource.resource_id
            || reference.sha256 != snapshot.resource.sha256
            || reference.media_type != snapshot.resource.media_type
            || reference.size_bytes != snapshot.resource.size_bytes
            || snapshot.source_instance_id != request.source.instance_id
            || snapshot.prefab_revision != request.definition.revision
        {
            return Err(DomainError::new(
                "STATE_SNAPSHOT_REQUIRED",
                "Snapshot identity does not match the source and resource pins",
            ));
        }
        let state: BTreeMap<_, _> = request
            .definition
            .state
            .iter()
            .map(|state| (&state.state_id, state))
            .collect();
        let expected: BTreeSet<_> = request
            .definition
            .state
            .iter()
            .filter(|state| state.scope == StateScope::Instance)
            .map(|state| state.state_id.clone())
            .collect();
        if snapshot.values.keys().cloned().collect::<BTreeSet<_>>() != expected {
            return Err(DomainError::new(
                "STATE_SNAPSHOT_REQUIRED",
                "The snapshot must cover exactly the definition's instance-scoped state",
            ));
        }
        for (state_id, value) in &snapshot.values {
            let definition = state.get(state_id).ok_or_else(|| {
                DomainError::new(
                    "REFERENCE_UNRESOLVED",
                    "Snapshot state definition is missing",
                )
            })?;
            if definition.scope != StateScope::Instance {
                return Err(DomainError::new(
                    "STATE_SNAPSHOT_REQUIRED",
                    "Project, player, and invocation state cannot be reinterpreted as instance defaults",
                ));
            }
            if !value_matches_type(value, definition.state_type) {
                return Err(DomainError::new(
                    "STATE_TYPE_MISMATCH",
                    "Snapshot state value does not fit the definition type",
                ));
            }
            overrides.retain(|entry| !matches!(entry, InstanceOverride::StateDefault { state_id: existing, .. } if existing == state_id));
            overrides.push(InstanceOverride::StateDefault {
                state_id: state_id.clone(),
                value: value.clone(),
            });
        }
    }
    ensure_placement(&request.definition, &request.placement, &overrides)?;
    let mut references = authored_bindings(
        &request.definition,
        &request.allocated_instance_id,
        &overrides,
    )?;
    preserve_nonlocal_targets(&request.source, &request.definition, &mut references);
    for state in request
        .definition
        .state
        .iter()
        .filter(|state| state.scope == StateScope::Project)
    {
        if references
            .iter()
            .any(|reference| reference.symbol_id.as_str() == state.state_id.as_str())
        {
            continue;
        }
        if let Some(binding) = request
            .source
            .bindings
            .iter()
            .find(|binding| binding.symbol_id.as_str() == state.state_id.as_str())
        {
            references.push(SymbolReference {
                symbol_id: binding.symbol_id.clone(),
                kind: "state".into(),
                scope: ReferenceScope::Project,
                target_id: binding.target_id.clone(),
            });
        }
    }
    references.sort_by(|a, b| a.symbol_id.cmp(&b.symbol_id));
    let mut instance = request.source.clone();
    instance.instance_id = request.allocated_instance_id;
    instance.placement = request.placement;
    instance.overrides = overrides;
    instance.bindings = binding_pairs(&references);
    instance.lifecycle = Lifecycle::Planned;
    finish_draft(
        instance,
        references,
        pending_diagnostics(&request.definition),
    )
}

/// FN05 without command payload attestations. Definitions referencing command
/// modules need the contextual path; this function never relocates opaque text.
pub fn relocate(value: &Value) -> Result<Value, DomainError> {
    relocate_with_command_support(value, &BTreeSet::new())
}

/// The application parser must attest each referenced immutable command module
/// as position-independent or symbolically relocatable before calling this API.
/// This attestation grants no permission and does not itself execute commands.
pub fn relocate_with_command_support(
    value: &Value,
    relocatable_modules: &BTreeSet<ModuleId>,
) -> Result<Value, DomainError> {
    let request: RelocateRequest = decode("RelocateRequest", value)?;
    require_source(&request.source, &request.definition)?;
    if request.external_reference_policy != "preserve" {
        return Err(DomainError::new(
            "SCHEMA_INVALID",
            "External destinations must be preserved",
        ));
    }
    if request
        .definition
        .command_module_ids
        .iter()
        .any(|module| !relocatable_modules.contains(module))
    {
        return Err(DomainError::new(
            "OPAQUE_RELOCATION",
            "A referenced command module has no verified relocation semantics",
        ));
    }
    ensure_placement(
        &request.definition,
        &request.placement,
        &request.source.overrides,
    )?;
    let mut instance = request.source;
    instance.placement = request.placement;
    instance.lifecycle = Lifecycle::Planned;
    // Definition coordinates, local ports and external destinations retain
    // their values. New world matrices follow from placement × node × port.
    finish_draft(
        instance,
        Vec::new(),
        pending_diagnostics(&request.definition),
    )
}

pub fn require_source(source: &Instance, definition: &Prefab) -> Result<(), DomainError> {
    require_valid(definition)?;
    if source.prefab_id != definition.prefab_id || source.prefab_revision != definition.revision {
        return Err(DomainError::new(
            "REVISION_CONFLICT",
            "The source instance is pinned to another prefab revision",
        ));
    }
    effective_defaults(definition, &source.overrides)?;
    let mut override_keys = BTreeSet::new();
    let nodes: BTreeSet<_> = definition.nodes.iter().map(|node| &node.node_id).collect();
    let node_ids: BTreeSet<_> = definition
        .nodes
        .iter()
        .map(|node| node.node_id.as_str())
        .collect();
    let ports: BTreeSet<_> = definition
        .ports
        .iter()
        .map(|port| port.port_id.as_str())
        .collect();
    let state_ids: BTreeSet<_> = definition
        .state
        .iter()
        .map(|state| state.state_id.as_str())
        .collect();
    let state_scopes: BTreeMap<_, _> = definition
        .state
        .iter()
        .map(|state| (state.state_id.as_str(), state.scope))
        .collect();
    let resource_ids: BTreeSet<_> = definition
        .resources
        .iter()
        .map(|resource| resource.resource_id.as_str())
        .collect();
    let references: BTreeMap<_, _> = definition
        .references
        .iter()
        .map(|reference| (&reference.symbol_id, reference))
        .collect();
    for (index, entry) in source.overrides.iter().enumerate() {
        let key = match entry {
            InstanceOverride::Transform { node_id, .. }
            | InstanceOverride::Display { node_id, .. } => {
                if !nodes.contains(node_id) {
                    return Err(DomainError::new(
                        "REFERENCE_UNRESOLVED",
                        "Override node is absent",
                    ));
                }
                if let InstanceOverride::Display { display, .. } = entry {
                    let diagnostics = crate::prefab::display_diagnostics(
                        display,
                        &resource_ids,
                        node_id.as_str(),
                        &format!("/overrides/{index}/display"),
                    );
                    if !diagnostics.is_empty() {
                        return Err(DomainError::with_diagnostics("SCHEMA_INVALID", diagnostics));
                    }
                }
                match entry {
                    InstanceOverride::Transform { .. } => format!("transform:{node_id}"),
                    _ => format!("display:{node_id}"),
                }
            }
            InstanceOverride::StateDefault { state_id, .. } => format!("state_default:{state_id}"),
            InstanceOverride::Reference {
                symbol_id,
                target_id,
            } => {
                let reference = references.get(symbol_id).ok_or_else(|| {
                    DomainError::new("REFERENCE_UNRESOLVED", "Override symbol is absent")
                })?;
                if reference.kind == "state"
                    && let Some(scope) = state_scopes.get(target_id.as_str())
                    && !crate::state::reference_scope_matches(reference.scope, *scope)
                {
                    return Err(DomainError::new(
                        "STATE_SCOPE_MISMATCH",
                        "Reference override would change state ownership scope",
                    ));
                }
                if reference.scope == ReferenceScope::Local {
                    let valid = match reference.kind.as_str() {
                        "node" => node_ids.contains(target_id.as_str()),
                        "port" => ports.contains(target_id.as_str()),
                        "state" => state_ids.contains(target_id.as_str()),
                        "resource" => resource_ids.contains(target_id.as_str()),
                        "function" => true, // Explicit pending function resolution is retained in draft diagnostics.
                        "object" => definition.prefab_id.as_str() == target_id.as_str(),
                        _ => false,
                    };
                    if !valid {
                        return Err(DomainError::new(
                            "REFERENCE_UNRESOLVED",
                            "Local reference override target is absent",
                        ));
                    }
                }
                format!("reference:{symbol_id}")
            }
        };
        if !override_keys.insert(key) {
            return Err(DomainError::new(
                "DUPLICATE_OVERRIDE",
                "A typed override is specified more than once",
            ));
        }
    }
    let mut binding_ids = BTreeSet::new();
    for binding in &source.bindings {
        if !binding_ids.insert(&binding.symbol_id) {
            return Err(DomainError::new(
                "SYMBOL_ID_COLLISION",
                "Duplicate source symbol binding",
            ));
        }
        if !references.contains_key(&binding.symbol_id)
            && !state_ids.contains(binding.symbol_id.as_str())
        {
            return Err(DomainError::new(
                "REFERENCE_UNRESOLVED",
                "Source binding has no typed definition",
            ));
        }
    }
    ensure_placement(definition, &source.placement, &source.overrides)
}

pub fn ensure_placement(
    prefab: &Prefab,
    placement: &Transform,
    overrides: &[InstanceOverride],
) -> Result<(), DomainError> {
    let worlds = world_transforms(prefab, placement, overrides)?;
    for node in &prefab.nodes {
        if node.block_geometry.is_some() && !is_block_placement(&worlds[&node.node_id]) {
            return Err(DomainError::new(
                "UNSUPPORTED_TRANSFORM",
                "Actual blocks support integer translation and Y quarter-turn rotation only",
            ));
        }
    }
    Ok(())
}

pub fn is_block_placement(matrix: &Matrix4) -> bool {
    let values = matrix.values();
    let tolerance = 1e-9;
    [3, 7, 11].into_iter().all(|index| {
        (values[index] - values[index].round()).abs() <= tolerance
            && values[index] >= i32::MIN as f64
            && values[index] <= i32::MAX as f64
    }) && (0..4).any(|turn| {
        let expected = Matrix4::quarter_turn_y(turn);
        [0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 15]
            .into_iter()
            .all(|index| (values[index] - expected.values()[index]).abs() <= tolerance)
    })
}

fn authored_bindings(
    prefab: &Prefab,
    instance_id: &InstanceId,
    overrides: &[InstanceOverride],
) -> Result<Vec<SymbolReference>, DomainError> {
    let changed: BTreeMap<_, _> = overrides
        .iter()
        .filter_map(|entry| match entry {
            InstanceOverride::Reference {
                symbol_id,
                target_id,
            } => Some((symbol_id, target_id.as_str())),
            _ => None,
        })
        .collect();
    let mut bindings = Vec::new();
    for reference in &prefab.references {
        let mut binding = reference.clone();
        let target = changed
            .get(&reference.symbol_id)
            .copied()
            .unwrap_or(&reference.target_id);
        binding.target_id = match (reference.scope, reference.kind.as_str()) {
            (ReferenceScope::Local, "node" | "port" | "state" | "function" | "object") => {
                authoring_target(instance_id, &reference.kind, target)
            }
            _ => target.to_owned(), // Immutable assets and nonlocal destinations remain shared.
        };
        bindings.push(binding);
    }
    for state in &prefab.state {
        if state.scope != StateScope::Project
            && !bindings
                .iter()
                .any(|reference| reference.symbol_id.as_str() == state.state_id.as_str())
        {
            let symbol_id = SymbolId::new(state.state_id.as_str())
                .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
            bindings.push(SymbolReference {
                symbol_id,
                kind: "state".into(),
                scope: ReferenceScope::Local,
                target_id: authoring_target(instance_id, "state", state.state_id.as_str()),
            });
        }
    }
    bindings.sort_by(|a, b| a.symbol_id.cmp(&b.symbol_id));
    Ok(bindings)
}

fn authoring_target(instance_id: &InstanceId, kind: &str, target: &str) -> String {
    // These are authoring locators, never scoreboard objectives or runtime UUIDs.
    // Length prefixes keep separators inside a stable ID unambiguous.
    format!(
        "mmmm-local:{}:{}:{}:{}:{}",
        instance_id.as_str().len(),
        instance_id,
        kind.len(),
        kind,
        target
    )
}

fn binding_pairs(references: &[SymbolReference]) -> Vec<SymbolBinding> {
    references
        .iter()
        .map(|reference| SymbolBinding {
            symbol_id: reference.symbol_id.clone(),
            target_id: reference.target_id.clone(),
        })
        .collect()
}

fn preserve_nonlocal_targets(
    source: &Instance,
    prefab: &Prefab,
    generated: &mut [SymbolReference],
) {
    let sources: BTreeMap<_, _> = source
        .bindings
        .iter()
        .map(|binding| (&binding.symbol_id, &binding.target_id))
        .collect();
    let nonlocal: BTreeSet<_> = prefab
        .references
        .iter()
        .filter(|reference| reference.scope != ReferenceScope::Local)
        .map(|reference| &reference.symbol_id)
        .collect();
    for reference in generated {
        if nonlocal.contains(&reference.symbol_id)
            && let Some(target) = sources.get(&reference.symbol_id)
        {
            reference.target_id = (*target).clone();
        }
    }
}

fn finish_draft(
    mut instance: Instance,
    new_symbol_bindings: Vec<SymbolReference>,
    diagnostics: Vec<Diagnostic>,
) -> Result<Value, DomainError> {
    let value = serde_json::to_value(&instance)
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    instance.revision = mmmm_contracts::projected_digest("Instance", &value)
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    encode(
        "InstanceDraft",
        &InstanceDraft {
            instance,
            new_symbol_bindings,
            diagnostics,
            losses: Vec::new(),
        },
    )
}

fn pending_diagnostics(prefab: &Prefab) -> Vec<Diagnostic> {
    crate::prefab::semantic_diagnostics(prefab)
        .into_iter()
        .filter(|diagnostic| diagnostic.severity != "error")
        .collect()
}

fn zero_digest() -> Sha256Digest {
    Sha256Digest::from_bytes([0; 32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(name: &str) -> Value {
        match name {
            "prefab" => {
                mmmm_contracts::parse_json(include_bytes!("../../../examples/prefab.json")).unwrap()
            }
            "instance" => {
                mmmm_contracts::parse_json(include_bytes!("../../../examples/instance.json"))
                    .unwrap()
            }
            _ => unreachable!(),
        }
    }
    fn placement() -> Value {
        json!({"kind":"trs","translation":[12,64,-4],"rotationXyzw":[0,0,0,1],"scale":[1,1,1]})
    }
    fn clone_request() -> Value {
        json!({"source":fixture("instance"),"definition":fixture("prefab"),"allocatedInstanceId":"instance-copy","placement":placement(),"statePolicy":"defaults"})
    }
    fn relocation_request() -> Value {
        json!({"source":fixture("instance"),"definition":fixture("prefab"),"placement":placement(),"externalReferencePolicy":"preserve"})
    }

    #[test]
    fn instantiate_is_deterministic_and_has_no_runtime_identity() {
        let input = json!({"prefab":fixture("prefab"),"instanceId":"instance-new","worldId":"world-fixture-01","dimension":"minecraft:overworld","placement":placement(),"statePolicy":"defaults"});
        let result = instantiate(&input).unwrap();
        assert_eq!(result, instantiate(&input).unwrap());
        assert_eq!(result["instance"]["lifecycle"], "planned");
        assert!(result["instance"].get("runtimeUuid").is_none());
        assert!(
            result["instance"]["overrides"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        mmmm_contracts::verify_projected_digest("Instance", &result["instance"]).unwrap();
        let used = BTreeSet::from([InstanceId::new("instance-new").unwrap()]);
        assert_eq!(
            instantiate_with_existing_ids(&input, &used)
                .unwrap_err()
                .code,
            "ID_COLLISION"
        );
    }

    #[test]
    fn clone_rebinds_instance_state_preserves_external_and_shared_resources() {
        let mut input = clone_request();
        input["definition"]["references"].as_array_mut().unwrap().extend([
            json!({"symbolId":"local_node","kind":"node","scope":"local","targetId":"door"}),
            json!({"symbolId":"asset_ref","kind":"resource","scope":"local","targetId":"resource-wall-blocks"}),
            json!({"symbolId":"exit_ref","kind":"port","scope":"external","targetId":"custom:outside"}),
        ]);
        let before = input.clone();
        let result = clone_instance(&input).unwrap();
        assert_eq!(input, before);
        let bindings: BTreeMap<_, _> = result["newSymbolBindings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|binding| {
                (
                    binding["symbolId"].as_str().unwrap(),
                    binding["targetId"].as_str().unwrap(),
                )
            })
            .collect();
        assert!(bindings["local_node"].contains("instance-copy"));
        assert!(bindings["opened"].contains("instance-copy"));
        assert_eq!(bindings["asset_ref"], "resource-wall-blocks");
        assert_eq!(bindings["exit_ref"], "custom:outside");
        assert_eq!(bindings["open_fn"], "fixture:open_shop");
        assert_eq!(
            result["instance"]["prefabRevision"],
            input["source"]["prefabRevision"]
        );
    }

    #[test]
    fn clone_rejects_same_id_revision_conflict_and_unresolved_snapshot() {
        let mut input = clone_request();
        input["allocatedInstanceId"] = input["source"]["instanceId"].clone();
        assert_eq!(clone_instance(&input).unwrap_err().code, "ID_COLLISION");
        input = clone_request();
        input["source"]["prefabRevision"] = json!("a".repeat(64));
        assert_eq!(
            clone_instance(&input).unwrap_err().code,
            "REVISION_CONFLICT"
        );
        input = clone_request();
        input["statePolicy"] = json!("explicit_snapshot");
        input["stateSnapshot"] = json!({"resourceId":"snapshot-1","sha256":"a".repeat(64),"mediaType":"application/json","sizeBytes":0});
        assert_eq!(
            clone_instance(&input).unwrap_err().code,
            "STATE_SNAPSHOT_REQUIRED"
        );
    }

    #[test]
    fn clone_keeps_project_state_binding_and_authored_false_override() {
        let mut input = clone_request();
        input["definition"]["state"].as_array_mut().unwrap().push(json!({
            "stateId":"global_count","scope":"project","type":"int32","unit":"unitless", "storage":"scoreboard","initialValue":0,"lifecycle":"load_once"
        }));
        input["source"]["bindings"] =
            json!([{"symbolId":"global_count","targetId":"custom:project_global_count"}]);
        input["source"]["overrides"] =
            json!([{"kind":"state_default","stateId":"opened","value":false}]);
        let result = clone_instance(&input).unwrap();
        let bindings: BTreeMap<_, _> = result["instance"]["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|binding| {
                (
                    binding["symbolId"].as_str().unwrap(),
                    binding["targetId"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(bindings["global_count"], "custom:project_global_count");
        assert_eq!(result["instance"]["overrides"][0]["value"], false);
    }

    #[test]
    fn explicit_snapshot_false_is_copied_with_raw_digest_pins() {
        let mut input = clone_request();
        let bytes = b"application-owned snapshot bytes";
        let resource = ResourceRef {
            resource_id: mmmm_contracts::ResourceId::new("snapshot-1").unwrap(),
            sha256: mmmm_contracts::raw_digest(bytes),
            media_type: "application/vnd.mmmm.state-snapshot".into(),
            size_bytes: bytes.len() as u64,
        };
        let snapshot = ResolvedStateSnapshot::from_verified_blob(
            resource.clone(),
            bytes,
            InstanceId::new("instance-shop-a").unwrap(),
            input["definition"]["revision"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            BTreeMap::from([(StateId::new("opened").unwrap(), ScalarValue::Boolean(false))]),
        )
        .unwrap();
        input["statePolicy"] = json!("explicit_snapshot");
        input["stateSnapshot"] = serde_json::to_value(&resource).unwrap();
        let result = clone_with_snapshot(&input, Some(&snapshot), &BTreeSet::new()).unwrap();
        assert_eq!(
            result["instance"]["overrides"][0],
            json!({"kind":"state_default","stateId":"opened","value":false})
        );
        assert!(
            ResolvedStateSnapshot::from_verified_blob(
                resource,
                b"different",
                InstanceId::new("instance-shop-a").unwrap(),
                Sha256Digest::from_bytes([0; 32]),
                BTreeMap::new()
            )
            .is_err()
        );
    }

    #[test]
    fn block_placement_rejects_scale_arbitrary_rotation_and_fractional_translation() {
        let mut input = clone_request();
        input["placement"]["scale"] = json!([1, 1, 0.00005]);
        assert_eq!(
            clone_instance(&input).unwrap_err().code,
            "UNSUPPORTED_TRANSFORM"
        );
        input = clone_request();
        input["placement"]["translation"] = json!([1.5, 64, 0]);
        assert_eq!(
            clone_instance(&input).unwrap_err().code,
            "UNSUPPORTED_TRANSFORM"
        );
    }

    #[test]
    fn relocate_requires_command_semantics_and_preserves_definition_ports() {
        let input = relocation_request();
        assert_eq!(relocate(&input).unwrap_err().code, "OPAQUE_RELOCATION");
        let before = input.clone();
        let supported = BTreeSet::from([ModuleId::new("module-shop-button").unwrap()]);
        let result = relocate_with_command_support(&input, &supported).unwrap();
        assert_eq!(input, before);
        assert_eq!(
            result["instance"]["instanceId"],
            input["source"]["instanceId"]
        );
        assert_eq!(
            Transform::from_value(&result["instance"]["placement"]).unwrap(),
            Transform::from_value(&input["placement"]).unwrap()
        );
        assert!(result["newSymbolBindings"].as_array().unwrap().is_empty());
        let prefab: Prefab = decode("Prefab", &input["definition"]).unwrap();
        let instance: Instance = decode("Instance", &result["instance"]).unwrap();
        let worlds = world_transforms(&prefab, &instance.placement, &instance.overrides).unwrap();
        let entrance = &prefab.ports[0];
        let port_world = worlds[&entrance.node_id]
            .multiply(&entrance.transform.matrix().unwrap())
            .unwrap();
        assert_eq!(
            port_world.transform_point([0.0; 3]).unwrap(),
            [15.5, 65.0, -2.5]
        );
    }

    #[test]
    fn display_affine_shear_reflection_and_thin_scale_are_preserved() {
        let mut input = clone_request();
        input["definition"]["nodes"][1]
            .as_object_mut()
            .unwrap()
            .remove("blockGeometry");
        let matrix = json!({"kind":"matrix","layout":"row_major_column_vector","values":[-1.0,0.5,0.0,7.0,0.0,1.0,0.0,3.0,0.0,0.0,0.00005,9.0,0.0,0.0,0.0,1.0]});
        input["placement"] = matrix.clone();
        let output = clone_instance(&input).unwrap();
        assert_eq!(output["instance"]["placement"], matrix);
    }

    #[test]
    fn display_override_cannot_bypass_role_or_resource_validation() {
        let mut input = clone_request();
        input["source"]["overrides"] = json!([{"kind":"display","nodeId":"sign","display":{
            "kind":"text","payload":{"text":"example"},"resourceRefs":["missing-resource"]
        }}]);
        let error = clone_instance(&input).unwrap_err();
        assert_eq!(error.code, "SCHEMA_INVALID");
        let codes: BTreeSet<_> = error
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect();
        assert!(codes.contains("REFERENCE_UNRESOLVED"));
        assert!(codes.contains("DISPLAY_ROLE_REQUIRED"));
    }

    #[test]
    fn relocating_a_display_only_instance_does_not_require_an_inverse() {
        let mut input = relocation_request();
        input["definition"]["nodes"][1]
            .as_object_mut()
            .unwrap()
            .remove("blockGeometry");
        input["definition"]["commandModuleIds"] = json!([]);
        input["source"]["placement"]["scale"] = json!([0, 1, 1]);
        let result = relocate(&input).unwrap();
        assert_eq!(
            Transform::from_value(&result["instance"]["placement"]).unwrap(),
            Transform::from_value(&input["placement"]).unwrap()
        );
    }
}

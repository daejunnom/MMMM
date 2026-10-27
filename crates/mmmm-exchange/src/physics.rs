//! Physics model assignments are authored solver inputs, never native game
//! facts. Graph validation resolves qualified object nodes without I/O or a
//! solver invocation and preserves source declarations and runtime intent.

use crate::{ExchangeError, ExchangeResult, coordinates::CoordinateSystem, validate};
#[cfg(test)]
use mmmm_contracts::InstanceId;
use mmmm_contracts::{NodeId, PhysicsId, ProjectId, ResourceLocation, SelectionId, Sha256Digest};
use mmmm_domain::{
    graph::world_transforms,
    transform::{Matrix4, Transform},
    types::{Instance, InstanceOverride, Prefab, ResourceRef},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub use mmmm_domain::physics::{
    BodyMode, CapsuleAxis, CollisionShape, InertiaPolicy, JointKind, JointLimitUnit, JointLimits,
    MaterialSource, ObjectNodeRef, PhysicsBody, PhysicsCollider, PhysicsJoint,
    PhysicsMaterialAssignment, RuntimeIntent, ShapeDefinition, ShapeExactness, ShapeProvenance,
    ShapeSpace, VisualBinding,
};

/// Typed immutable model input. Validation does not issue game or solver authority.
#[derive(Clone)]
pub struct PhysicsDefinition {
    model: mmmm_domain::physics::PhysicsDefinition,
    coordinates: CoordinateSystem,
}
impl std::fmt::Debug for PhysicsDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.model, f)
    }
}
impl Serialize for PhysicsDefinition {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.model.serialize(serializer)
    }
}
fn from_domain_error(error: mmmm_domain::types::DomainError) -> ExchangeError {
    ExchangeError::new(error.code, error.message)
}
impl PhysicsDefinition {
    pub fn from_value(value: &Value) -> ExchangeResult<Self> {
        let model = mmmm_domain::physics::PhysicsDefinition::from_value(value)
            .map_err(from_domain_error)?;
        let coordinates = CoordinateSystem::from_domain(model.coordinates());
        Ok(Self { model, coordinates })
    }
    pub fn to_value(&self) -> ExchangeResult<Value> {
        self.model.to_value().map_err(from_domain_error)
    }
    pub fn physics_id(&self) -> &PhysicsId {
        self.model.physics_id()
    }
    pub fn revision(&self) -> &Sha256Digest {
        self.model.revision()
    }
    pub fn selection_id(&self) -> &SelectionId {
        self.model.selection_id()
    }
    pub fn coordinates(&self) -> &CoordinateSystem {
        &self.coordinates
    }
    pub fn gravity_meters_per_second_squared(&self) -> [f64; 3] {
        self.model.gravity_meters_per_second_squared()
    }
    pub fn materials(&self) -> &[PhysicsMaterialAssignment] {
        self.model.materials()
    }
    pub fn bodies(&self) -> &[PhysicsBody] {
        self.model.bodies()
    }
    pub fn colliders(&self) -> &[PhysicsCollider] {
        self.model.colliders()
    }
    pub fn joints(&self) -> &[PhysicsJoint] {
        self.model.joints()
    }
    pub fn runtime_intent(&self) -> RuntimeIntent {
        self.model.runtime_intent()
    }
    pub fn required_capabilities(&self) -> &[ResourceLocation] {
        self.model.required_capabilities()
    }
    pub fn validate_selection(&self, selection: &Value) -> ExchangeResult<()> {
        self.validate_selection_index(&SelectionIndex::from_value(selection)?)
    }
    pub fn validate_selection_index(&self, selection: &SelectionIndex) -> ExchangeResult<()> {
        if self.selection_id() != selection.selection_id() {
            return Err(ExchangeError::new(
                "SELECTION_MISMATCH",
                "physics selection ID differs",
            ));
        }
        for body in self.bodies() {
            for binding in &body.visual_bindings {
                if !selection.contains(&binding.node) {
                    return Err(ExchangeError::new(
                        "REFERENCE_UNRESOLVED",
                        format!(
                            "visual node {}/{} is outside the qualified selection",
                            binding.node.instance_id, binding.node.node_id
                        ),
                    ));
                }
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SelectionWire {
    contract_version: String,
    selection_id: SelectionId,
    project_id: ProjectId,
    project_revision: Sha256Digest,
    instances: Vec<Instance>,
    prefabs: Vec<Prefab>,
    selected_node_ids: Vec<NodeId>,
    external_reference_policy: String,
    source_map: ResourceRef,
}

#[derive(Debug, Clone)]
struct SelectedNode {
    world: Matrix4,
    parent_world: Matrix4,
}

/// An immutable selection index keyed by instance and node together. Bare node
/// IDs define a filter within every included instance, not a global object ID.
/// This index checks authored structure and referential revision equality. The
/// exchange pipeline's `Selection` gate verifies the source DTO self-digests;
/// building this index alone is not proof of a frozen project revision.
#[derive(Debug, Clone)]
pub struct SelectionIndex {
    selection_id: SelectionId,
    project_id: ProjectId,
    project_revision: Sha256Digest,
    source_map: ResourceRef,
    nodes: BTreeMap<ObjectNodeRef, SelectedNode>,
}

impl SelectionIndex {
    pub fn from_value(value: &Value) -> ExchangeResult<Self> {
        validate("SceneSelectionSnapshot", value)?;
        selection_budget(value)?;
        let selection: SelectionWire = serde_json::from_value(value.clone())
            .map_err(|error| ExchangeError::new("SCHEMA_INVALID", error.to_string()))?;
        if selection.contract_version != "0.2.0"
            || selection.external_reference_policy != "preserve"
        {
            return Err(ExchangeError::new(
                "SCHEMA_INVALID",
                "invalid selection contract",
            ));
        }
        let mut prefabs = BTreeMap::new();
        let mut prefab_ids = BTreeSet::new();
        for prefab in &selection.prefabs {
            if !prefab_ids.insert(&prefab.prefab_id) {
                return Err(ExchangeError::new(
                    "OBJECT_MAPPING_AMBIGUOUS",
                    "one selection cannot contain several revisions of the same prefab ID",
                ));
            }
            if prefabs
                .insert((&prefab.prefab_id, &prefab.revision), prefab)
                .is_some()
            {
                return Err(ExchangeError::new(
                    "DUPLICATE_ID",
                    "selection repeats a prefab revision",
                ));
            }
            mmmm_domain::prefab::require_valid(prefab)
                .map_err(|error| ExchangeError::new(error.code, error.to_string()))?;
        }
        let selected: BTreeSet<_> = selection.selected_node_ids.iter().cloned().collect();
        let mut encountered = BTreeSet::new();
        let mut instance_ids = BTreeSet::new();
        let mut nodes = BTreeMap::new();
        let mut expanded_nodes = 0_usize;
        for instance in &selection.instances {
            if !instance_ids.insert(instance.instance_id.clone()) {
                return Err(ExchangeError::new(
                    "DUPLICATE_ID",
                    "selection repeats an instance ID",
                ));
            }
            let prefab = prefabs
                .get(&(&instance.prefab_id, &instance.prefab_revision))
                .ok_or_else(|| {
                    ExchangeError::new(
                        "REFERENCE_UNRESOLVED",
                        "instance prefab revision is absent from selection",
                    )
                })?;
            expanded_nodes = expanded_nodes
                .checked_add(prefab.nodes.len())
                .ok_or_else(|| {
                    ExchangeError::new("BUDGET_EXCEEDED", "selection node expansion overflow")
                })?;
            if expanded_nodes > 65536 {
                return Err(ExchangeError::new(
                    "BUDGET_EXCEEDED",
                    "qualified selection node expansion exceeds its budget",
                ));
            }
            validate_overrides(instance, prefab)?;
            mmmm_domain::instance::require_source(instance, prefab)
                .map_err(|error| ExchangeError::new(error.code, error.to_string()))?;
            let worlds = world_transforms(prefab, &instance.placement, &instance.overrides)
                .map_err(|error| ExchangeError::new(error.code, error.to_string()))?;
            let placement = instance.placement.matrix().map_err(transform_error)?;
            for node in &prefab.nodes {
                if !selected.contains(&node.node_id) {
                    continue;
                }
                encountered.insert(node.node_id.clone());
                let parent_world = match &node.parent_id {
                    Some(parent) => *worlds.get(parent).ok_or_else(|| {
                        ExchangeError::new("REFERENCE_UNRESOLVED", "selected node parent is absent")
                    })?,
                    None => placement,
                };
                let world = *worlds.get(&node.node_id).ok_or_else(|| {
                    ExchangeError::new(
                        "REFERENCE_UNRESOLVED",
                        "selected node world transform is absent",
                    )
                })?;
                nodes.insert(
                    ObjectNodeRef {
                        instance_id: instance.instance_id.clone(),
                        node_id: node.node_id.clone(),
                    },
                    SelectedNode {
                        world,
                        parent_world,
                    },
                );
            }
        }
        if encountered != selected {
            return Err(ExchangeError::new(
                "REFERENCE_UNRESOLVED",
                "a selected node ID does not exist in an included instance",
            ));
        }
        Ok(Self {
            selection_id: selection.selection_id,
            project_id: selection.project_id,
            project_revision: selection.project_revision,
            source_map: selection.source_map,
            nodes,
        })
    }

    pub fn selection_id(&self) -> &SelectionId {
        &self.selection_id
    }
    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }
    pub fn project_revision(&self) -> &Sha256Digest {
        &self.project_revision
    }
    pub fn source_map(&self) -> &ResourceRef {
        &self.source_map
    }
    pub fn contains(&self, node: &ObjectNodeRef) -> bool {
        self.nodes.contains_key(node)
    }
    pub fn selected_nodes(&self) -> impl Iterator<Item = &ObjectNodeRef> {
        self.nodes.keys()
    }
    pub fn world_transform(&self, node: &ObjectNodeRef) -> Option<&Matrix4> {
        self.nodes.get(node).map(|node| &node.world)
    }
    pub fn parent_world_transform(&self, node: &ObjectNodeRef) -> Option<&Matrix4> {
        self.nodes.get(node).map(|node| &node.parent_world)
    }
}

/// Structural validation of an authored physics candidate and qualified
/// selection. The manifest pipeline owns byte hashes and revision acceptance.
pub fn validate_physics_definition(
    physics: &Value,
    selection: &Value,
) -> ExchangeResult<PhysicsDefinition> {
    let physics = PhysicsDefinition::from_value(physics)?;
    physics.validate_selection(selection)?;
    Ok(physics)
}

/// `WorldNode = WorldBody * bodyToNode`. The offset is not an absolute pose or
/// a COM position. Parent-local output is an explicit separate inverse step.
pub fn visual_world_pose(
    body_world: &Matrix4,
    binding: &VisualBinding,
) -> ExchangeResult<Transform> {
    let offset = binding.body_to_node.matrix().map_err(transform_error)?;
    body_world
        .multiply(&offset)
        .map(Transform::from_matrix)
        .map_err(transform_error)
}

fn validate_overrides(instance: &Instance, prefab: &Prefab) -> ExchangeResult<()> {
    mmmm_domain::state::effective_defaults(prefab, &instance.overrides)
        .map_err(|error| ExchangeError::new(error.code, error.to_string()))?;
    let nodes: BTreeSet<_> = prefab.nodes.iter().map(|node| &node.node_id).collect();
    let states: BTreeSet<_> = prefab.state.iter().map(|state| &state.state_id).collect();
    let references: BTreeSet<_> = prefab
        .references
        .iter()
        .map(|reference| &reference.symbol_id)
        .collect();
    let mut seen = BTreeSet::new();
    for entry in &instance.overrides {
        let (kind, id, exists) = match entry {
            InstanceOverride::Transform { node_id, transform } => {
                transform.validate().map_err(transform_error)?;
                ("transform", node_id.as_str(), nodes.contains(node_id))
            }
            InstanceOverride::Display { node_id, .. } => {
                ("display", node_id.as_str(), nodes.contains(node_id))
            }
            InstanceOverride::StateDefault { state_id, .. } => (
                "state_default",
                state_id.as_str(),
                states.contains(state_id),
            ),
            InstanceOverride::Reference { symbol_id, .. } => (
                "reference",
                symbol_id.as_str(),
                references.contains(symbol_id),
            ),
        };
        if !exists {
            return Err(ExchangeError::new(
                "REFERENCE_UNRESOLVED",
                "instance override target is absent",
            ));
        }
        if !seen.insert((kind, id)) {
            return Err(ExchangeError::new(
                "DUPLICATE_ID",
                "instance repeats an override target and kind",
            ));
        }
    }
    Ok(())
}

fn selection_budget(value: &Value) -> ExchangeResult<()> {
    if crate::array(value, "instances")?.len() > 4096
        || crate::array(value, "prefabs")?.len() > 4096
        || crate::array(value, "selectedNodeIds")?.len() > 16384
    {
        return Err(ExchangeError::new(
            "BUDGET_EXCEEDED",
            "selection exceeds object budgets",
        ));
    }
    let mut nodes = 0_usize;
    for prefab in crate::array(value, "prefabs")? {
        nodes = nodes
            .checked_add(crate::array(prefab, "nodes")?.len())
            .ok_or_else(|| {
                ExchangeError::new(
                    "BUDGET_EXCEEDED",
                    "selection definition node count overflow",
                )
            })?;
        if nodes > 16384 {
            return Err(ExchangeError::new(
                "BUDGET_EXCEEDED",
                "selection exceeds definition node budget",
            ));
        }
    }
    Ok(())
}

fn transform_error(error: mmmm_domain::transform::TransformError) -> ExchangeError {
    ExchangeError::new(error.code(), error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn physics() -> Value {
        mmmm_contracts::parse_json(include_bytes!("../../../examples/physics-definition.json"))
            .unwrap()
    }
    fn selection() -> Value {
        mmmm_contracts::parse_json(include_bytes!("../../../examples/scene-selection.json"))
            .unwrap()
    }

    #[test]
    fn original_model_material_is_preserved_and_not_a_native_fact() {
        let input = physics();
        let definition = validate_physics_definition(&input, &selection()).unwrap();
        assert_eq!(
            mmmm_contracts::canonical_bytes(&definition.to_value().unwrap()).unwrap(),
            mmmm_contracts::canonical_bytes(&input).unwrap()
        );
        assert_eq!(
            definition.materials()[0].source,
            MaterialSource::UserDeclared
        );
        assert_eq!(definition.materials()[0].friction, 0.5);
        let mut native_claim = input;
        native_claim["materials"][0]["source"] = json!("observed");
        assert!(PhysicsDefinition::from_value(&native_claim).is_err());
    }

    #[test]
    fn one_body_can_write_multiple_visual_targets_and_empty_selection_expands_nothing() {
        let mut selected = selection();
        selected["selectedNodeIds"] = json!(["door", "sign"]);
        let mut input = physics();
        let mut sign = input["bodies"][0]["visualBindings"][0].clone();
        sign["node"]["nodeId"] = json!("sign");
        input["bodies"][0]["visualBindings"]
            .as_array_mut()
            .unwrap()
            .push(sign);
        let definition = validate_physics_definition(&input, &selected).unwrap();
        assert_eq!(definition.bodies()[0].visual_bindings.len(), 2);
        selected["selectedNodeIds"] = json!([]);
        assert_eq!(
            SelectionIndex::from_value(&selected)
                .unwrap()
                .selected_nodes()
                .count(),
            0
        );
        assert!(definition.validate_selection(&selected).is_err());
    }

    #[test]
    fn transform_override_affects_pose_and_duplicate_override_is_rejected() {
        let mut selected = selection();
        let changed = json!({"kind":"transform", "nodeId":"door", "transform":{
            "kind":"trs", "translation":[8,2,1], "rotationXyzw":[0,0,0,1], "scale":[1,1,1]
        }});
        selected["instances"][0]["overrides"] = json!([changed]);
        let index = SelectionIndex::from_value(&selected).unwrap();
        let door = ObjectNodeRef {
            instance_id: InstanceId::new("instance-shop-a").unwrap(),
            node_id: NodeId::new("door").unwrap(),
        };
        assert_eq!(
            index
                .world_transform(&door)
                .unwrap()
                .transform_point([0.0; 3])
                .unwrap(),
            [136.0, 66.0, 129.0]
        );
        selected["instances"][0]["overrides"]
            .as_array_mut()
            .unwrap()
            .push(changed);
        assert!(SelectionIndex::from_value(&selected).is_err());
    }

    #[test]
    fn collision_group_accepts_a_mathematical_integer_json_lexeme() {
        let mut input = physics();
        input["colliders"][0]["collisionGroup"] = json!(1.0);
        assert_eq!(
            PhysicsDefinition::from_value(&input).unwrap().colliders()[0].collision_group,
            1
        );
    }

    #[test]
    fn two_instances_can_share_node_id_but_each_requires_qualified_binding() {
        let mut selection = selection();
        let mut second_instance = selection["instances"][0].clone();
        second_instance["instanceId"] = json!("instance-shop-b");
        second_instance["placement"]["translation"] = json!([256, 64, 128]);
        selection["instances"]
            .as_array_mut()
            .unwrap()
            .push(second_instance);
        let mut physics = physics();
        let mut second_body = physics["bodies"][0].clone();
        second_body["bodyId"] = json!("body-door-b");
        second_body["colliderIds"] = json!(["collider-door-b"]);
        second_body["visualBindings"][0]["node"]["instanceId"] = json!("instance-shop-b");
        physics["bodies"].as_array_mut().unwrap().push(second_body);
        let mut second_collider = physics["colliders"][0].clone();
        second_collider["colliderId"] = json!("collider-door-b");
        second_collider["bodyId"] = json!("body-door-b");
        physics["colliders"]
            .as_array_mut()
            .unwrap()
            .push(second_collider);
        validate_physics_definition(&physics, &selection).unwrap();
        let index = SelectionIndex::from_value(&selection).unwrap();
        assert_eq!(index.selected_nodes().count(), 2);
        let node = ObjectNodeRef {
            instance_id: InstanceId::new("instance-shop-b").unwrap(),
            node_id: NodeId::new("door").unwrap(),
        };
        assert_eq!(
            index
                .world_transform(&node)
                .unwrap()
                .transform_point([0.0; 3])
                .unwrap(),
            [259.0, 65.0, 128.0]
        );
        physics["bodies"][1]["visualBindings"][0]["node"]["instanceId"] = json!("instance-shop-a");
        assert!(PhysicsDefinition::from_value(&physics).is_err());
    }

    #[test]
    fn missing_pins_unselected_nodes_and_cross_body_colliders_are_rejected() {
        let input = physics();
        let mut selected = selection();
        selected["instances"][0]["prefabRevision"] = json!("0".repeat(64));
        assert!(validate_physics_definition(&input, &selected).is_err());
        selected = selection();
        selected["selectedNodeIds"] = json!(["sign"]);
        assert!(validate_physics_definition(&input, &selected).is_err());
        let mut changed = input;
        changed["colliders"][0]["bodyId"] = json!("missing-body");
        assert!(PhysicsDefinition::from_value(&changed).is_err());
    }

    #[test]
    fn inertia_orientation_and_degenerate_shapes_are_not_repaired() {
        let mut input = physics();
        input["bodies"][0]["inertiaPolicy"] = json!("explicit");
        input["bodies"][0]["inertiaDiagonal"] = json!([2.0, 3.0, 4.0]);
        input["bodies"][0]["inertiaOrientationXyzw"] = json!([0.0, 0.0, 0.0, 1.0]);
        PhysicsDefinition::from_value(&input).unwrap();
        input["bodies"][0]["inertiaOrientationXyzw"] = json!([0.0, 0.0, 0.0, 2.0]);
        assert!(PhysicsDefinition::from_value(&input).is_err());
        input = physics();
        input["colliders"][0]["shape"]["shape"]["halfExtents"] = json!([0.5, 0.0, 0.05]);
        assert!(PhysicsDefinition::from_value(&input).is_err());
        input = physics();
        input["bodies"][0]["massKg"] = Value::Null;
        assert!(PhysicsDefinition::from_value(&input).is_err());
    }

    #[test]
    fn runtime_requirement_and_body_to_visual_offset_are_preserved() {
        let mut input = physics();
        input["runtimeIntent"] = json!("runtime_required");
        input["bodies"][0]["visualBindings"][0]["bodyToNode"]["translation"] =
            json!([1.0, 2.0, 3.0]);
        let definition = PhysicsDefinition::from_value(&input).unwrap();
        assert_eq!(definition.runtime_intent(), RuntimeIntent::RuntimeRequired);
        let body_world = Transform::Trs {
            translation: [10.0, 20.0, 30.0],
            rotation_xyzw: [0.0, 0.0, 0.0, 1.0],
            scale: [1.0; 3],
        }
        .matrix()
        .unwrap();
        let pose =
            visual_world_pose(&body_world, &definition.bodies()[0].visual_bindings[0]).unwrap();
        assert_eq!(
            pose.matrix().unwrap().transform_point([0.0; 3]).unwrap(),
            [11.0, 22.0, 33.0]
        );
        assert_eq!(
            definition.to_value().unwrap()["runtimeIntent"],
            "runtime_required"
        );
    }

    #[test]
    fn invalid_joint_units_and_ranges_are_rejected() {
        let mut input = physics();
        let mut second_body = input["bodies"][0].clone();
        second_body["bodyId"] = json!("body-anchor");
        second_body["mode"] = json!("static");
        second_body["colliderIds"] = json!([]);
        second_body["visualBindings"] = json!([]);
        input["bodies"].as_array_mut().unwrap().push(second_body);
        input["joints"] = json!([{
            "jointId":"joint-door", "kind":"hinge", "bodyA":"body-door", "bodyB":"body-anchor",
            "frameA": Transform::identity(), "frameB": Transform::identity(),
            "limits":{"lower":0.0,"upper":1.57,"unit":"radians"}
        }]);
        PhysicsDefinition::from_value(&input).unwrap();
        input["joints"][0]["limits"]["unit"] = json!("meters");
        assert!(PhysicsDefinition::from_value(&input).is_err());
        input["joints"][0]["limits"] = json!({"lower":2.0,"upper":1.0,"unit":"radians"});
        assert!(PhysicsDefinition::from_value(&input).is_err());
    }
}

//! Pure authored physics DTOs and graph validation; no solver or I/O authority.
use crate::{
    coordinates::CoordinateSystem,
    transform::Transform,
    types::{DomainError, ResourceRef},
};
use mmmm_contracts::{
    BodyId, ColliderId, InstanceId, JointId, MaterialId, NodeId, PhysicsId, ResourceId,
    ResourceLocation, SelectionId, Sha256Digest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
type DomainResult<T> = Result<T, DomainError>;
fn validate(definition: &str, value: &Value) -> DomainResult<()> {
    mmmm_contracts::ContractValidator::shared()
        .and_then(|v| v.validate(definition, value))
        .map_err(|e| DomainError::new("SCHEMA_INVALID", e.to_string()))
}
fn array<'a>(value: &'a Value, field: &str) -> DomainResult<&'a [Value]> {
    value[field]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| DomainError::new("SCHEMA_INVALID", format!("Missing array {field}")))
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObjectNodeRef {
    pub instance_id: InstanceId,
    pub node_id: NodeId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterialSource {
    UserDeclared,
    ApprovedPreset,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PhysicsMaterialAssignment {
    pub material_id: MaterialId,
    pub source: MaterialSource,
    pub friction: f64,
    pub restitution: f64,
    pub linear_damping: f64,
    pub angular_damping: f64,
    pub semantics: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyMode {
    Static,
    Kinematic,
    Dynamic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InertiaPolicy {
    Explicit,
    DeriveFromColliders,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VisualBinding {
    pub node: ObjectNodeRef,
    pub body_to_node: Transform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PhysicsBody {
    pub body_id: BodyId,
    pub mode: BodyMode,
    pub transform: Transform,
    pub mass_kg: Option<f64>,
    pub center_of_mass_local: [f64; 3],
    pub inertia_policy: InertiaPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inertia_diagonal: Option<[f64; 3]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inertia_orientation_xyzw: Option<[f64; 4]>,
    pub initial_linear_velocity_meters_per_second: [f64; 3],
    pub initial_angular_velocity_radians_per_second: [f64; 3],
    pub visual_bindings: Vec<VisualBinding>,
    pub collider_ids: Vec<ColliderId>,
    pub material_id: MaterialId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShapeSpace {
    NodeLocal,
    BodyLocal,
    World,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShapeExactness {
    Exact,
    Approximated,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShapeProvenance {
    Observed,
    Extracted,
    UserDeclared,
    Estimated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleAxis {
    X,
    Y,
    Z,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CollisionShape {
    Box {
        #[serde(rename = "halfExtents")]
        half_extents: [f64; 3],
    },
    Sphere {
        radius: f64,
    },
    Capsule {
        radius: f64,
        #[serde(rename = "halfHeight")]
        half_height: f64,
        axis: CapsuleAxis,
    },
    Mesh {
        geometry: ResourceRef,
        #[serde(rename = "topologyDigest")]
        topology_digest: Sha256Digest,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShapeDefinition {
    pub shape: CollisionShape,
    pub space: ShapeSpace,
    pub exactness: ShapeExactness,
    pub provenance: ShapeProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PhysicsCollider {
    pub collider_id: ColliderId,
    pub body_id: BodyId,
    pub shape: ShapeDefinition,
    pub transform: Transform,
    pub is_sensor: bool,
    #[serde(deserialize_with = "deserialize_safe_u64")]
    pub collision_group: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JointKind {
    Fixed,
    Hinge,
    Slider,
    Ball,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JointLimitUnit {
    Radians,
    Meters,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct JointLimits {
    pub lower: f64,
    pub upper: f64,
    pub unit: JointLimitUnit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PhysicsJoint {
    pub joint_id: JointId,
    pub kind: JointKind,
    pub body_a: BodyId,
    pub body_b: BodyId,
    pub frame_a: Transform,
    pub frame_b: Transform,
    pub limits: Option<JointLimits>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeIntent {
    BakeOnly,
    RuntimeRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PhysicsWire {
    contract_version: String,
    physics_id: PhysicsId,
    revision: Sha256Digest,
    selection_id: SelectionId,
    coordinates: CoordinateSystem,
    gravity_meters_per_second_squared: [f64; 3],
    materials: Vec<PhysicsMaterialAssignment>,
    bodies: Vec<PhysicsBody>,
    colliders: Vec<PhysicsCollider>,
    joints: Vec<PhysicsJoint>,
    runtime_intent: RuntimeIntent,
    required_capabilities: Vec<ResourceLocation>,
}

/// Typed immutable model input. Successful validation makes no claim about a
/// solver, payload codec, game carrier, native material, or runtime capability.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct PhysicsDefinition(PhysicsWire);

impl PhysicsDefinition {
    /// Validate an authored candidate's schema and model relationships. This
    /// supports editing before a revision is allocated and never rewrites one.
    /// Immutable prepare/inspect/bake callers must separately verify the raw
    /// PhysicsDefinition projected digest and source pins before accepting it.
    pub fn from_value(value: &Value) -> DomainResult<Self> {
        validate("PhysicsDefinition", value)?;
        physics_budget(value)?;
        // ResourceRef accepts mathematical JSON integers. Limit conversion to
        // the validated mesh geometry fields on a private copy; callers retain
        // the original authored Value and own its raw bytes and revision pin.
        let mut typed = value.clone();
        normalize_mesh_resource_lengths(&mut typed)?;
        let wire: PhysicsWire = serde_json::from_value(typed)
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
        validate_graph(&wire)?;
        Ok(Self(wire))
    }

    pub fn to_value(&self) -> DomainResult<Value> {
        let value = serde_json::to_value(self)
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
        validate("PhysicsDefinition", &value)?;
        Ok(value)
    }

    pub fn physics_id(&self) -> &PhysicsId {
        &self.0.physics_id
    }
    pub fn revision(&self) -> &Sha256Digest {
        &self.0.revision
    }
    pub fn selection_id(&self) -> &SelectionId {
        &self.0.selection_id
    }
    pub fn coordinates(&self) -> &CoordinateSystem {
        &self.0.coordinates
    }
    pub fn gravity_meters_per_second_squared(&self) -> [f64; 3] {
        self.0.gravity_meters_per_second_squared
    }
    pub fn materials(&self) -> &[PhysicsMaterialAssignment] {
        &self.0.materials
    }
    pub fn bodies(&self) -> &[PhysicsBody] {
        &self.0.bodies
    }
    pub fn colliders(&self) -> &[PhysicsCollider] {
        &self.0.colliders
    }
    pub fn joints(&self) -> &[PhysicsJoint] {
        &self.0.joints
    }
    pub fn runtime_intent(&self) -> RuntimeIntent {
        self.0.runtime_intent
    }
    pub fn required_capabilities(&self) -> &[ResourceLocation] {
        &self.0.required_capabilities
    }
}

fn validate_graph(physics: &PhysicsWire) -> DomainResult<()> {
    if physics.contract_version != "0.2.0" {
        return Err(DomainError::new(
            "SCHEMA_INVALID",
            "invalid physics contract version",
        ));
    }
    finite(&physics.gravity_meters_per_second_squared, "gravity")?;
    let mut materials = BTreeSet::new();
    for material in &physics.materials {
        unique(&mut materials, material.material_id.clone(), "material")?;
        nonnegative(
            &[
                material.friction,
                material.restitution,
                material.linear_damping,
                material.angular_damping,
            ],
            "material coefficients",
        )?;
    }
    let mut bodies = BTreeMap::new();
    let mut collider_owners = BTreeMap::new();
    let mut writers = BTreeSet::new();
    for body in &physics.bodies {
        if bodies.insert(body.body_id.clone(), body).is_some() {
            return Err(DomainError::new("DUPLICATE_ID", "duplicate body ID"));
        }
        body.transform.validate().map_err(transform_error)?;
        finite(&body.center_of_mass_local, "center of mass")?;
        finite(
            &body.initial_linear_velocity_meters_per_second,
            "linear velocity",
        )?;
        finite(
            &body.initial_angular_velocity_radians_per_second,
            "angular velocity",
        )?;
        if body
            .mass_kg
            .is_some_and(|mass| !mass.is_finite() || mass <= 0.0)
            || (body.mode == BodyMode::Dynamic && body.mass_kg.is_none())
        {
            return Err(DomainError::new(
                "INVALID_PHYSICS",
                "dynamic mass must be finite and positive",
            ));
        }
        if body.inertia_policy == InertiaPolicy::Explicit
            && (body.inertia_diagonal.is_none() || body.inertia_orientation_xyzw.is_none())
        {
            return Err(DomainError::new(
                "INVALID_PHYSICS",
                "explicit inertia requires moments and principal orientation",
            ));
        }
        if let Some(moments) = body.inertia_diagonal {
            positive(&moments, "principal moments in kg·m²")?;
        }
        if let Some(orientation) = body.inertia_orientation_xyzw {
            Transform::Trs {
                translation: [0.0; 3],
                rotation_xyzw: orientation,
                scale: [1.0; 3],
            }
            .validate()
            .map_err(transform_error)?;
        }
        if body.mode == BodyMode::Dynamic
            && body.inertia_policy == InertiaPolicy::DeriveFromColliders
            && body.collider_ids.is_empty()
        {
            return Err(DomainError::new(
                "INVALID_PHYSICS",
                "dynamic collider-derived inertia requires colliders",
            ));
        }
        if !materials.contains(&body.material_id) {
            return Err(DomainError::new(
                "REFERENCE_UNRESOLVED",
                "body material is absent",
            ));
        }
        let mut body_colliders = BTreeSet::new();
        for collider in &body.collider_ids {
            unique(&mut body_colliders, collider.clone(), "body collider")?;
        }
        collider_owners.insert(body.body_id.clone(), body_colliders);
        for binding in &body.visual_bindings {
            binding.body_to_node.validate().map_err(transform_error)?;
            if !writers.insert(binding.node.clone()) {
                return Err(DomainError::new(
                    "POSE_WRITER_CONFLICT",
                    "multiple bindings write the same qualified visual node",
                ));
            }
        }
    }
    let mut colliders = BTreeMap::new();
    let mut mesh_pins = BTreeMap::<ResourceId, &ResourceRef>::new();
    for collider in &physics.colliders {
        if colliders
            .insert(collider.collider_id.clone(), collider)
            .is_some()
        {
            return Err(DomainError::new("DUPLICATE_ID", "duplicate collider ID"));
        }
        let owned_ids = collider_owners
            .get(&collider.body_id)
            .ok_or_else(|| DomainError::new("REFERENCE_UNRESOLVED", "collider body is absent"))?;
        if !owned_ids.contains(&collider.collider_id) {
            return Err(DomainError::new(
                "REFERENCE_UNRESOLVED",
                "collider is not listed by its owning body",
            ));
        }
        collider.transform.validate().map_err(transform_error)?;
        match &collider.shape.shape {
            CollisionShape::Box { half_extents } => positive(half_extents, "box half extents")?,
            CollisionShape::Sphere { radius } => positive(&[*radius], "sphere radius")?,
            CollisionShape::Capsule {
                radius,
                half_height,
                ..
            } => {
                positive(&[*radius], "capsule radius")?;
                nonnegative(&[*half_height], "capsule half height")?;
            }
            CollisionShape::Mesh { geometry, .. } => {
                if let Some(previous) = mesh_pins.insert(geometry.resource_id.clone(), geometry)
                    && (previous.sha256 != geometry.sha256
                        || previous.size_bytes != geometry.size_bytes
                        || previous.media_type != geometry.media_type)
                {
                    return Err(DomainError::new(
                        "RESOURCE_PIN_CONFLICT",
                        "mesh resource ID has inconsistent pins",
                    ));
                }
            }
        }
    }
    for body in &physics.bodies {
        for collider_id in &body.collider_ids {
            let collider = colliders.get(collider_id).ok_or_else(|| {
                DomainError::new("REFERENCE_UNRESOLVED", "body collider is absent")
            })?;
            if collider.body_id != body.body_id {
                return Err(DomainError::new(
                    "REFERENCE_UNRESOLVED",
                    "body references another body's collider",
                ));
            }
        }
    }
    let mut joints = BTreeSet::new();
    for joint in &physics.joints {
        unique(&mut joints, joint.joint_id.clone(), "joint")?;
        if !bodies.contains_key(&joint.body_a) || !bodies.contains_key(&joint.body_b) {
            return Err(DomainError::new(
                "REFERENCE_UNRESOLVED",
                "joint body is absent",
            ));
        }
        if joint.body_a == joint.body_b {
            return Err(DomainError::new(
                "INVALID_PHYSICS",
                "joint endpoints must be different bodies",
            ));
        }
        joint.frame_a.validate().map_err(transform_error)?;
        joint.frame_b.validate().map_err(transform_error)?;
        if let Some(limits) = &joint.limits {
            finite(&[limits.lower, limits.upper], "joint limits")?;
            if limits.lower > limits.upper
                || (joint.kind == JointKind::Hinge && limits.unit != JointLimitUnit::Radians)
                || (joint.kind == JointKind::Slider && limits.unit != JointLimitUnit::Meters)
            {
                return Err(DomainError::new(
                    "INVALID_PHYSICS",
                    "joint limit range or unit is invalid",
                ));
            }
        }
    }
    Ok(())
}

fn physics_budget(value: &Value) -> DomainResult<()> {
    for (field, limit) in [
        ("materials", 4096),
        ("bodies", 16384),
        ("colliders", 65536),
        ("joints", 65536),
        ("requiredCapabilities", 4096),
    ] {
        if array(value, field)?.len() > limit {
            return Err(DomainError::new(
                "BUDGET_EXCEEDED",
                format!("physics {field} exceeds its budget"),
            ));
        }
    }
    let mut bindings = 0_usize;
    let mut collider_links = 0_usize;
    for body in array(value, "bodies")? {
        bindings = bindings
            .checked_add(array(body, "visualBindings")?.len())
            .ok_or_else(|| {
                DomainError::new("BUDGET_EXCEEDED", "physics visual binding count overflow")
            })?;
        if bindings > 65536 {
            return Err(DomainError::new(
                "BUDGET_EXCEEDED",
                "physics exceeds visual binding budget",
            ));
        }
        collider_links = collider_links
            .checked_add(array(body, "colliderIds")?.len())
            .ok_or_else(|| {
                DomainError::new(
                    "BUDGET_EXCEEDED",
                    "physics collider reference count overflow",
                )
            })?;
        if collider_links > 65536 {
            return Err(DomainError::new(
                "BUDGET_EXCEEDED",
                "physics exceeds collider reference budget",
            ));
        }
    }
    Ok(())
}

/// Validate and normalize one mesh geometry ResourceRef on an independent
/// copy. The authored value, raw bytes, and its projected pin remain owned by
/// the caller. This is not an assertion that the referenced resource exists.
pub fn normalize_mesh_resource_ref(value: &Value) -> Result<Value, DomainError> {
    validate("ResourceRef", value)?;
    let size = value
        .get("sizeBytes")
        .and_then(Value::as_f64)
        .filter(|size| {
            size.is_finite()
                && size.fract() == 0.0
                && (0.0..=9_007_199_254_740_991.0).contains(size)
        })
        .ok_or_else(|| {
            DomainError::new(
                "SCHEMA_INVALID",
                "mesh resource size must be a nonnegative safe JSON integer",
            )
        })?;
    let mut normalized = value.clone();
    let fields = normalized
        .as_object_mut()
        .ok_or_else(|| DomainError::new("SCHEMA_INVALID", "mesh resource must be an object"))?;
    fields.insert("sizeBytes".into(), Value::from(size as u64));
    Ok(normalized)
}

fn normalize_mesh_resource_lengths(value: &mut Value) -> DomainResult<()> {
    let colliders = value
        .get_mut("colliders")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| DomainError::new("SCHEMA_INVALID", "Missing array colliders"))?;
    for collider in colliders {
        let shape = collider
            .get_mut("shape")
            .and_then(|outer| outer.get_mut("shape"))
            .ok_or_else(|| DomainError::new("SCHEMA_INVALID", "mesh collider shape is missing"))?;
        if shape.get("kind").and_then(Value::as_str) != Some("mesh") {
            continue;
        }
        let geometry = shape.get_mut("geometry").ok_or_else(|| {
            DomainError::new("SCHEMA_INVALID", "mesh geometry resource is missing")
        })?;
        let normalized = normalize_mesh_resource_ref(geometry)?;
        *geometry = normalized;
    }
    Ok(())
}

fn deserialize_safe_u64<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<u64, D::Error> {
    let value = serde_json::Number::deserialize(deserializer)?;
    let number = value
        .as_f64()
        .ok_or_else(|| serde::de::Error::custom("collision group must be numeric"))?;
    if number.is_finite() && number.fract() == 0.0 && (0.0..=9007199254740991.0).contains(&number) {
        Ok(number as u64)
    } else {
        Err(serde::de::Error::custom(
            "collision group must be a nonnegative safe JSON integer",
        ))
    }
}

fn unique<T: Ord>(set: &mut BTreeSet<T>, item: T, kind: &str) -> DomainResult<()> {
    if !set.insert(item) {
        return Err(DomainError::new(
            "DUPLICATE_ID",
            format!("duplicate {kind} ID"),
        ));
    }
    Ok(())
}

fn finite(values: &[f64], field: &str) -> DomainResult<()> {
    if values.iter().any(|value| !value.is_finite()) {
        return Err(DomainError::new(
            "INVALID_PHYSICS",
            format!("{field} must be finite"),
        ));
    }
    Ok(())
}

fn positive(values: &[f64], field: &str) -> DomainResult<()> {
    finite(values, field)?;
    if values.iter().any(|value| *value <= 0.0) {
        return Err(DomainError::new(
            "INVALID_PHYSICS",
            format!("{field} must be positive"),
        ));
    }
    Ok(())
}

fn nonnegative(values: &[f64], field: &str) -> DomainResult<()> {
    finite(values, field)?;
    if values.iter().any(|value| *value < 0.0) {
        return Err(DomainError::new(
            "INVALID_PHYSICS",
            format!("{field} must be nonnegative"),
        ));
    }
    Ok(())
}

fn transform_error(error: crate::transform::TransformError) -> DomainError {
    DomainError::new(error.code(), error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{CollisionShape, PhysicsDefinition, normalize_mesh_resource_ref, validate};
    use serde_json::{Value, json};

    fn physics_with_mesh(size: Value) -> Value {
        // The original authored physics example uses a box. Derive a mesh
        // shape to cover its nested ResourceRef without inventing a fixture.
        let mut physics: Value =
            serde_json::from_slice(include_bytes!("../../../examples/physics-definition.json"))
                .unwrap();
        physics["colliders"][0]["shape"]["shape"] = json!({
            "kind": "mesh",
            "geometry": {
                "resourceId": "resource-mesh",
                "sha256": "0".repeat(64),
                "mediaType": "application/octet-stream",
                "sizeBytes": size
            },
            "topologyDigest": "1".repeat(64)
        });
        physics
    }

    #[test]
    fn mesh_resource_size_accepts_mathematical_integers_without_mutating_authored_value() {
        for (number, expected) in [
            ("1", 1_u64),
            ("1.0", 1),
            ("1e0", 1),
            ("-0.0", 0),
            ("9007199254740991.0", 9_007_199_254_740_991),
        ] {
            let number: Value = serde_json::from_str(number).unwrap();
            let physics = physics_with_mesh(number);
            let before = physics.clone();
            let geometry = &physics["colliders"][0]["shape"]["shape"]["geometry"];
            let original_geometry = geometry.clone();
            let normalized = normalize_mesh_resource_ref(geometry).unwrap();
            assert_eq!(normalized["sizeBytes"], Value::from(expected));
            assert_eq!(normalized["resourceId"], geometry["resourceId"]);
            assert_eq!(normalized["sha256"], geometry["sha256"]);
            assert_eq!(normalized["mediaType"], geometry["mediaType"]);
            assert_eq!(*geometry, original_geometry);
            let before_revision =
                mmmm_contracts::projected_digest("PhysicsDefinition", &physics).unwrap();
            validate("PhysicsDefinition", &physics).unwrap();
            let result = PhysicsDefinition::from_value(&physics).unwrap();
            let CollisionShape::Mesh { geometry, .. } = &result.colliders()[0].shape.shape else {
                panic!("the derived collider must remain a mesh");
            };
            assert_eq!(geometry.size_bytes, expected);
            assert_eq!(physics, before);
            assert_eq!(
                mmmm_contracts::projected_digest("PhysicsDefinition", &physics).unwrap(),
                before_revision
            );
        }
    }

    #[test]
    fn mesh_resource_size_rejects_values_outside_schema_integer_range() {
        for number in ["-1", "0.5", "9007199254740992", "\"1\""] {
            let number: Value = serde_json::from_str(number).unwrap();
            let physics = physics_with_mesh(number);
            let before = physics.clone();
            let geometry = &physics["colliders"][0]["shape"]["shape"]["geometry"];
            assert!(normalize_mesh_resource_ref(geometry).is_err());
            assert!(validate("PhysicsDefinition", &physics).is_err());
            assert!(PhysicsDefinition::from_value(&physics).is_err());
            assert_eq!(physics, before);
        }
    }

    #[test]
    fn mesh_resource_normalizer_rejects_non_resource_objects_without_mutation() {
        let physics = physics_with_mesh(json!(1));
        let geometry = &physics["colliders"][0]["shape"]["shape"]["geometry"];
        let mut missing = geometry.clone();
        missing.as_object_mut().unwrap().remove("sha256");
        let mut extra = geometry.clone();
        extra["unexpected"] = json!(true);
        for input in [json!(false), missing, extra] {
            let before = input.clone();
            let error = normalize_mesh_resource_ref(&input).unwrap_err();
            assert_eq!(error.code, "SCHEMA_INVALID");
            assert_eq!(input, before);
        }
    }
}

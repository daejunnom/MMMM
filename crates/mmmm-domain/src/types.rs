//! DTOs mirror the canonical contract; only extensible payloads remain JSON.

use crate::transform::Transform;
use mmmm_contracts::{
    InstanceId, NodeId, PortId, PrefabId, ResourceId, ResourceLocation, Sha256Digest, StateId,
    SymbolId, WorldId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};
use std::{collections::BTreeMap, error::Error, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainError {
    pub code: &'static str,
    pub message: String,
    pub diagnostics: Vec<Diagnostic>,
}

impl DomainError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            diagnostics: Vec::new(),
        }
    }
    pub fn with_diagnostics(code: &'static str, diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            code,
            message: "Authoring semantics are invalid".into(),
            diagnostics,
        }
    }
}
impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}
impl Error for DomainError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Diagnostic {
    pub code: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl Diagnostic {
    pub fn error(code: &str, message: impl Into<String>, object: Option<&str>, path: &str) -> Self {
        Self {
            code: code.into(),
            severity: "error".into(),
            message: message.into(),
            object_id: object.map(str::to_owned),
            path: Some(path.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Prefab {
    pub contract_version: String,
    pub prefab_id: PrefabId,
    pub revision: Sha256Digest,
    pub name: String,
    pub nodes: Vec<Node>,
    pub ports: Vec<Port>,
    pub state: Vec<StateVariable>,
    pub references: Vec<SymbolReference>,
    pub command_module_ids: Vec<mmmm_contracts::ModuleId>,
    pub clip_ids: Vec<mmmm_contracts::ClipId>,
    pub resources: Vec<ResourceRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_map_resource_id: Option<ResourceId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Node {
    pub node_id: NodeId,
    pub name: String,
    pub parent_id: Option<NodeId>,
    pub transform: Transform,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_geometry: Option<BlockGeometry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Display>,
    pub colliders: Vec<Collider>,
    pub extensions: BTreeMap<mmmm_contracts::ExtensionKey, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geometry_representation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geometry_resource: Option<ResourceRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physics_binding: Option<PhysicsBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PhysicsBinding {
    pub physics_id: mmmm_contracts::PhysicsId,
    pub body_id: mmmm_contracts::BodyId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceRef {
    pub resource_id: ResourceId,
    pub sha256: Sha256Digest,
    pub media_type: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BlockGeometry {
    pub resource_id: ResourceId,
    pub bounds: CellBounds,
    pub rotation_policy: String,
    pub cell_origin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CellBounds {
    #[serde(deserialize_with = "mmmm_contracts::deserialize_i32_vec3")]
    pub min: [i32; 3],
    #[serde(deserialize_with = "mmmm_contracts::deserialize_i32_vec3")]
    pub max_exclusive: [i32; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Display {
    pub kind: String,
    pub payload: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_role: Option<String>,
    pub resource_refs: Vec<ResourceId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Collider {
    pub role: String,
    pub shape: String,
    pub parameters: BTreeMap<String, Value>,
    pub transform: Transform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Port {
    pub port_id: PortId,
    pub kind: String,
    pub node_id: NodeId,
    pub transform: Transform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateScope {
    Project,
    Instance,
    Player,
    Ephemeral,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateType {
    Int32,
    Float32,
    Boolean,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScalarValue {
    Boolean(bool),
    Number(Number),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StateVariable {
    pub state_id: StateId,
    pub scope: StateScope,
    #[serde(rename = "type")]
    pub state_type: StateType,
    pub unit: String,
    pub storage: String,
    pub initial_value: ScalarValue,
    pub lifecycle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_node_id: Option<NodeId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceScope {
    Local,
    Project,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SymbolReference {
    pub symbol_id: SymbolId,
    pub kind: String,
    pub scope: ReferenceScope,
    pub target_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Instance {
    pub contract_version: String,
    pub instance_id: InstanceId,
    pub revision: Sha256Digest,
    pub prefab_id: PrefabId,
    pub prefab_revision: Sha256Digest,
    pub world_id: WorldId,
    pub dimension: ResourceLocation,
    pub placement: Transform,
    pub bindings: Vec<SymbolBinding>,
    pub overrides: Vec<InstanceOverride>,
    pub lifecycle: Lifecycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Planned,
    Applied,
    Drifted,
    Detached,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SymbolBinding {
    pub symbol_id: SymbolId,
    pub target_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InstanceOverride {
    Transform {
        #[serde(rename = "nodeId")]
        node_id: NodeId,
        transform: Transform,
    },
    Display {
        #[serde(rename = "nodeId")]
        node_id: NodeId,
        display: Display,
    },
    StateDefault {
        #[serde(rename = "stateId")]
        state_id: StateId,
        value: ScalarValue,
    },
    Reference {
        #[serde(rename = "symbolId")]
        symbol_id: SymbolId,
        #[serde(rename = "targetId")]
        target_id: mmmm_contracts::TargetId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InstanceDraft {
    pub instance: Instance,
    pub new_symbol_bindings: Vec<SymbolReference>,
    pub diagnostics: Vec<Diagnostic>,
    pub losses: Vec<LossRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LossRecord {
    pub code: String,
    pub severity: String,
    pub subject_id: mmmm_contracts::ObjectId,
    pub feature: ResourceLocation,
    pub disposition: String,
    pub message: String,
    pub approval_required: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InstantiateRequest {
    pub prefab: Prefab,
    pub instance_id: InstanceId,
    pub world_id: WorldId,
    pub dimension: ResourceLocation,
    pub placement: Transform,
    pub state_policy: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CloneRequest {
    pub source: Instance,
    pub definition: Prefab,
    pub allocated_instance_id: InstanceId,
    pub placement: Transform,
    pub state_policy: String,
    #[serde(default)]
    pub state_snapshot: Option<ResourceRef>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RelocateRequest {
    pub source: Instance,
    pub definition: Prefab,
    pub placement: Transform,
    pub external_reference_policy: String,
}

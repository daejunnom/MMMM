//! Pure scene lowering. Codec/registry evidence is an application-owned port,
//! separate from caller profile text and from this source-only compiler draft.
//! Generated lifecycle functions are never called by compilation.

use crate::animation::{AnimationDraft, AnimationNodeBinding, AnimationSceneProjection};
use crate::{GeneratedFunctionContract, StagedResource, VerifiedTarget, compiler_digest, decode};
use mmmm_contracts::{
    InstanceId, NodeId, ObjectId, PrefabId, RationalTime, ResourceId, ResourceLocation,
    Sha256Digest, TargetProfileId, canonical_bytes, canonical_digest, projected_digest, raw_digest,
};
use mmmm_domain::{
    DomainError,
    commands::{
        CommandKind, CommandModule, CommandNode, CommandStateRules, Facing, ParseStatus,
        validate_command_graph,
    },
    graph::world_transforms,
    instance::require_source,
    state::effective_defaults,
    transform::{Matrix4, rotate_block_cell_y},
    types::{
        Display, Instance, InstanceOverride, Prefab, ResourceRef, ScalarValue, StateScope,
        StateType,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::{cell::RefCell, rc::Rc};

const MAX_SOURCES: usize = 4096;
const MAX_COMMANDS: usize = 16384;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 16384;
const MAX_RETAINED_BINDINGS: usize = 16384;

#[derive(Debug, Clone)]
pub struct SceneResource {
    pub reference: ResourceRef,
    pub bytes: Vec<u8>,
}

/// Constructed from private immutable resource-store snapshots. Construction
/// itself grants no authority; every contract/revision/blob is checked below.
#[derive(Debug, Clone)]
pub struct SceneBuildInputs {
    project: Value,
    prefabs: Vec<Value>,
    instances: Vec<Value>,
    command_modules: Vec<Value>,
    assets: Vec<Value>,
    resources: Vec<SceneResource>,
    max_component_error: f64,
}
impl SceneBuildInputs {
    pub fn new(
        project: Value,
        prefabs: Vec<Value>,
        instances: Vec<Value>,
        command_modules: Vec<Value>,
        assets: Vec<Value>,
        resources: Vec<SceneResource>,
    ) -> Self {
        Self {
            project,
            prefabs,
            instances,
            command_modules,
            assets,
            resources,
            max_component_error: 0.0,
        }
    }
    /// Zero is exact conversion. A nonzero authored policy admits a measured
    /// native f32 approximation, recorded as an approval-required loss.
    pub fn with_max_component_error(mut self, error: f64) -> Self {
        self.max_component_error = error;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoveredSceneSource {
    pub kind: String,
    pub object_id: ObjectId,
    pub revision: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SceneBlockState {
    pub block_id: ResourceLocation,
    pub properties: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NativeSceneInstruction {
    Display {
        dimension: ResourceLocation,
        tag: String,
        entity_kind: String,
        uuid: [u8; 16],
        position: [f64; 3],
        matrix: [f64; 16],
        payload: BTreeMap<String, Value>,
    },
    /// A pose for an existing owned display. The codec always resets all three
    /// interpolation/teleport fields to zero and never spawns or teleports it.
    DisplayPose {
        dimension: ResourceLocation,
        tag: String,
        entity_kind: String,
        uuid: [u8; 16],
        matrix: [f64; 16],
    },
    Block {
        dimension: ResourceLocation,
        position: [i32; 3],
        state: SceneBlockState,
    },
    CommandShell {
        dimension: ResourceLocation,
        position: [i32; 3],
        command_kind: CommandKind,
        facing: Facing,
        conditional: bool,
    },
    CommandData {
        dimension: ResourceLocation,
        position: [i32; 3],
        source: String,
    },
    CommandActivation {
        dimension: ResourceLocation,
        position: [i32; 3],
        auto: bool,
    },
    StateInitialize {
        storage: ResourceLocation,
        key: String,
        value: ScalarValue,
        storage_kind: String,
        state_type: StateType,
        lifecycle: String,
        objective: String,
        holder: String,
    },
    StateRemove {
        storage: ResourceLocation,
        key: String,
        storage_kind: String,
        objective: String,
        holder: String,
    },
    DisplayRemove {
        dimension: ResourceLocation,
        uuid: [u8; 16],
        entity_kind: String,
    },
}

#[derive(Debug, Clone)]
pub struct ResolvedSceneCommand {
    /// Parser-generated complete source. Never produced by substring rewrite.
    pub source: String,
    pub referenced_functions: BTreeSet<ResourceLocation>,
    /// Exact source/artifact resource pins for external function definitions.
    pub external_functions: BTreeMap<ResourceLocation, Sha256Digest>,
    pub state_reads: BTreeSet<String>,
    pub state_writes: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SceneStateBinding {
    pub qualified_state: String,
    pub storage: ResourceLocation,
    pub key: String,
    pub objective: String,
    pub holder: String,
    pub storage_kind: String,
    pub state_type: StateType,
    pub lifecycle: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SceneLifecyclePhase {
    Stage,
    Activate,
    Cleanup,
}

/// Immutable Rust source projection. This is the exact instruction and command
/// sequence accepted by the independent codec verifier, never a live before
/// snapshot or permission to execute. Its target/compiler/codec pins are the
/// containing SceneDraft's pins. Matrix/Float32 scalar components are the exact
/// target f32 values widened to f64, with any authored conversion loss recorded
/// separately. The immutable original sources remain in draft resources.
#[derive(Debug, Clone, Serialize)]
pub struct NativeSceneStep {
    phase: SceneLifecyclePhase,
    source_object_id: ObjectId,
    source_node_id: Option<NodeId>,
    instance_id: InstanceId,
    owner_prefab_id: PrefabId,
    instruction: NativeSceneInstruction,
    encoded_commands: Vec<String>,
}
impl NativeSceneStep {
    pub fn phase(&self) -> SceneLifecyclePhase {
        self.phase
    }
    pub fn source_object_id(&self) -> &ObjectId {
        &self.source_object_id
    }
    pub fn source_node_id(&self) -> Option<&NodeId> {
        self.source_node_id.as_ref()
    }
    pub fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }
    pub fn owner_prefab_id(&self) -> &PrefabId {
        &self.owner_prefab_id
    }
    pub fn instruction(&self) -> &NativeSceneInstruction {
        &self.instruction
    }
    pub fn encoded_commands(&self) -> &[String] {
        &self.encoded_commands
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SceneCodecCapabilities {
    pub static_affine_display: bool,
    pub text_background_geometry: bool,
    pub staged_command_blocks: bool,
    pub scoped_state: bool,
    pub resource_pack_assets: bool,
}

/// Independent registry/evidence owner. Each method must verify the immutable
/// target artifact/profile pins and producer evidence, not caller arrays. The
/// encoder has a concrete implementation below; this port validates its exact
/// parse/readback and registry semantics before draft publication.
pub trait SceneRegistryVerifier {
    fn verify_codec(
        &self,
        target: &VerifiedTarget,
        codec_digest: &Sha256Digest,
    ) -> Result<SceneCodecCapabilities, DomainError>;
    fn verify_encoded(
        &self,
        target: &VerifiedTarget,
        codec_digest: &Sha256Digest,
        instruction: &NativeSceneInstruction,
        command: &str,
    ) -> Result<(), DomainError>;
    fn display_payload(
        &self,
        target: &VerifiedTarget,
        display: &Display,
    ) -> Result<BTreeMap<String, Value>, DomainError>;
    /// Must verify state-by-state rotation (doors/stairs/rails included). There
    /// is no universal property-name replacement fallback in this compiler.
    fn block_state(
        &self,
        target: &VerifiedTarget,
        state: &SceneBlockState,
        quarter_turns: i32,
    ) -> Result<SceneBlockState, DomainError>;
    // Keep each exact-target, source, world and state authority input explicit
    // on this verifier boundary; grouping them would change consumer adapters.
    #[allow(
        clippy::too_many_arguments,
        reason = "Explicit independently pinned verifier inputs preserve the frozen registry port"
    )]
    fn resolve_command(
        &self,
        target: &VerifiedTarget,
        module: &CommandModule,
        command: &CommandNode,
        prefab: &Prefab,
        instance: &Instance,
        world: &Matrix4,
        states: &BTreeMap<mmmm_contracts::StateId, SceneStateBinding>,
    ) -> Result<ResolvedSceneCommand, DomainError>;
    /// The exact payload's media codec and redistribution/source rights must
    /// be checked. Return a portable `assets/<namespace>/...` resource-pack
    /// path, or None for a consumed blockset retained as provenance only.
    fn asset_path(
        &self,
        target: &VerifiedTarget,
        asset: &Value,
        resource: &SceneResource,
    ) -> Result<Option<String>, DomainError>;
    /// Equal bytes may carry explicitly verified media aliases (the original
    /// blockset fixture has JSON and a vendor JSON media type). Hash/size/ID
    /// equality is enforced here before this media-codec check.
    fn resource_media(
        &self,
        target: &VerifiedTarget,
        declared: &ResourceRef,
        stored: &ResourceRef,
    ) -> Result<(), DomainError>;
}

pub trait SceneTargetCodec {
    fn codec_digest(&self) -> Sha256Digest;
    fn encode_instruction(
        &self,
        instruction: &NativeSceneInstruction,
    ) -> Result<Vec<String>, DomainError>;
}

/// Native syntax adapter for Java 26.3. All untrusted strings are encoded as
/// SNBT strings or validated resource/property tokens. No user SNBT is spliced
/// into generated commands. Exact target acceptance still requires the port.
/// Official target notes: https://www.minecraft.net/en-us/article/minecraft-java-edition-26-3
#[derive(Debug, Default)]
pub struct Native26_3SceneCodec;
impl SceneTargetCodec for Native26_3SceneCodec {
    fn codec_digest(&self) -> Sha256Digest {
        raw_digest(include_bytes!("scene.rs"))
    }
    fn encode_instruction(
        &self,
        instruction: &NativeSceneInstruction,
    ) -> Result<Vec<String>, DomainError> {
        let lines = match instruction {
            NativeSceneInstruction::Display {
                dimension,
                tag,
                entity_kind,
                uuid,
                position,
                matrix,
                payload,
            } => {
                if !["block", "item", "text"].contains(&entity_kind.as_str()) {
                    return unsupported("Unknown display entity kind");
                }
                safe_token(tag)?;
                let mut fields = Vec::new();
                for (key, value) in payload {
                    if key == "billboard" {
                        if value != "fixed" {
                            return unsupported("Display billboard differs from fixed world pose");
                        }
                        continue;
                    }
                    if [
                        "Tags",
                        "transformation",
                        "interpolation_duration",
                        "start_interpolation",
                        "teleport_duration",
                        "Pos",
                        "Passengers",
                        "id",
                        "UUID",
                        "Rotation",
                        "rotation",
                    ]
                    .contains(&key.as_str())
                    {
                        return unsupported(
                            "Display payload overrides generated lifecycle/transform fields",
                        );
                    }
                    fields.push(format!("{}:{}", quote(key)?, snbt(value, 0)?));
                }
                fields.extend([
                    format!("Tags:[{}]", quote(tag)?),
                    format!(
                        "UUID:[I;{}]",
                        uuid.chunks_exact(4)
                            .map(
                                |part| i32::from_be_bytes([part[0], part[1], part[2], part[3]])
                                    .to_string()
                            )
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                    "billboard:\"fixed\",Rotation:[0f,0f]".into(),
                    format!(
                        "transformation:[{}]",
                        matrix
                            .iter()
                            .map(|number| float_literal(*number))
                            .collect::<Result<Vec<_>, _>>()?
                            .join(",")
                    ),
                    "start_interpolation:0,interpolation_duration:0,teleport_duration:0".into(),
                ]);
                vec![format!(
                    "execute in {dimension} run summon minecraft:{entity_kind}_display {} {} {} {{{}}}",
                    coordinate(position[0])?,
                    coordinate(position[1])?,
                    coordinate(position[2])?,
                    fields.join(",")
                )]
            }
            NativeSceneInstruction::Block {
                dimension,
                position,
                state,
            } => vec![format!(
                "execute in {dimension} run setblock {} {} {} {}",
                position[0],
                position[1],
                position[2],
                block_token(state)?
            )],
            NativeSceneInstruction::CommandShell {
                dimension,
                position,
                command_kind,
                facing,
                conditional,
            } => {
                let block = match command_kind {
                    CommandKind::Impulse => "command_block",
                    CommandKind::Chain => "chain_command_block",
                    CommandKind::Repeating => "repeating_command_block",
                };
                vec![format!(
                    "execute in {dimension} run setblock {} {} {} minecraft:{block}[facing={},conditional={conditional}]{{Command:\"\",auto:0b,TrackOutput:0b}}",
                    position[0],
                    position[1],
                    position[2],
                    facing_name(*facing)
                )]
            }
            NativeSceneInstruction::CommandData {
                dimension,
                position,
                source,
            } => vec![format!(
                "execute in {dimension} run data merge block {} {} {} {{Command:{},auto:0b,TrackOutput:0b}}",
                position[0],
                position[1],
                position[2],
                quote(source)?
            )],
            NativeSceneInstruction::CommandActivation {
                dimension,
                position,
                auto,
            } => vec![format!(
                "execute in {dimension} run data merge block {} {} {} {{auto:{}b}}",
                position[0],
                position[1],
                position[2],
                u8::from(*auto)
            )],
            NativeSceneInstruction::StateInitialize {
                storage,
                key,
                value,
                storage_kind,
                state_type,
                lifecycle,
                objective,
                holder,
            } => {
                safe_token(key)?;
                safe_token(objective)?;
                safe_token(holder)?;
                if storage_kind == "scoreboard" {
                    let integer = scalar_integer(value)?;
                    let set = format!("scoreboard players set {holder} {objective} {integer}");
                    vec![
                        format!("scoreboard objectives add {objective} dummy"),
                        if lifecycle == "load_once" {
                            format!(
                                "execute unless score {holder} {objective} matches -2147483648..2147483647 run {set}"
                            )
                        } else {
                            set
                        },
                    ]
                } else if storage_kind == "storage_nbt" {
                    let value = match (state_type, value) {
                        (StateType::Boolean, ScalarValue::Boolean(value)) => {
                            format!("{}b", u8::from(*value))
                        }
                        (StateType::Int32, value) => scalar_integer(value)?.to_string(),
                        (StateType::Float32, ScalarValue::Number(number)) => float_literal(
                            number
                                .as_f64()
                                .ok_or_else(|| fail("Invalid scalar number"))?,
                        )?,
                        _ => return Err(fail("State scalar does not match its codec type")),
                    };
                    let set =
                        format!("data modify storage {storage} states.{key} set value {value}");
                    vec![if lifecycle == "load_once" {
                        format!("execute unless data storage {storage} states.{key} run {set}")
                    } else {
                        set
                    }]
                } else {
                    return unsupported("Unknown state storage codec");
                }
            }
            NativeSceneInstruction::StateRemove {
                storage,
                key,
                storage_kind,
                objective,
                holder,
            } => {
                safe_token(key)?;
                safe_token(objective)?;
                safe_token(holder)?;
                if storage_kind == "scoreboard" {
                    vec![
                        format!("scoreboard players reset {holder} {objective}"),
                        format!("scoreboard objectives remove {objective}"),
                    ]
                } else if storage_kind == "storage_nbt" {
                    vec![format!("data remove storage {storage} states.{key}")]
                } else {
                    return unsupported("Unknown state storage codec");
                }
            }
            NativeSceneInstruction::DisplayPose {
                dimension,
                tag,
                entity_kind,
                uuid,
                matrix,
            } => {
                if !["block", "item", "text"].contains(&entity_kind.as_str()) {
                    return unsupported("Unknown display entity kind");
                }
                safe_token(tag)?;
                if matrix
                    .iter()
                    .any(|value| !value.is_finite() || f64::from(*value as f32) != *value)
                {
                    return Err(range(
                        "Native pose matrix must already contain exact finite target f32 values",
                    ));
                }
                let matrix = matrix
                    .iter()
                    .map(|number| float_literal(*number))
                    .collect::<Result<Vec<_>, _>>()?
                    .join(",");
                vec![format!(
                    "execute in {dimension} as {} if entity @s[type=minecraft:{entity_kind}_display,tag={tag}] run data merge entity @s {{transformation:[{matrix}],interpolation_duration:0,start_interpolation:0,teleport_duration:0}}",
                    uuid_text(uuid)
                )]
            }
            NativeSceneInstruction::DisplayRemove {
                dimension,
                uuid,
                entity_kind,
            } => {
                if !["block", "item", "text"].contains(&entity_kind.as_str()) {
                    return unsupported("Unknown display entity kind");
                }
                vec![format!(
                    "execute in {dimension} as {} if entity @s[type=minecraft:{entity_kind}_display] run kill @s",
                    uuid_text(uuid)
                )]
            }
        };
        for line in &lines {
            validate_line(line)?;
        }
        Ok(lines)
    }
}

#[derive(Debug, Clone)]
pub struct SceneDraft {
    resources: BTreeMap<String, StagedResource>,
    resource_pack_resources: BTreeMap<String, StagedResource>,
    function_contracts: BTreeMap<ResourceLocation, Vec<GeneratedFunctionContract>>,
    source_map_entries: Vec<Value>,
    entry_points: BTreeMap<String, ResourceLocation>,
    defined_functions: BTreeSet<ResourceLocation>,
    referenced_functions: BTreeSet<ResourceLocation>,
    external_functions: BTreeMap<ResourceLocation, Sha256Digest>,
    state_symbols: BTreeSet<String>,
    covered_owned_sources: BTreeSet<CoveredSceneSource>,
    prefab_ids: BTreeSet<String>,
    instance_ids: BTreeSet<String>,
    resource_ids: BTreeSet<String>,
    required_clip_ids: BTreeSet<String>,
    required_animation_bindings: BTreeSet<(String, String)>,
    owned_clip_revisions: BTreeMap<ObjectId, Sha256Digest>,
    game_ticks_per_second: RationalTime,
    animation_bindings: BTreeMap<InstanceId, AnimationSceneProjection>,
    state_bindings: BTreeMap<InstanceId, BTreeMap<mmmm_contracts::StateId, SceneStateBinding>>,
    input_revision: Sha256Digest,
    target_profile_digest: Sha256Digest,
    target_artifact_digest: Sha256Digest,
    compiler_digest: Sha256Digest,
    codec_digest: Sha256Digest,
    private_distribution_required: bool,
    losses: Vec<Value>,
    native_steps: Vec<NativeSceneStep>,
    target_profile_id: TargetProfileId,
}
impl SceneDraft {
    pub fn resources(&self) -> &BTreeMap<String, StagedResource> {
        &self.resources
    }
    /// Separate resource pack content. Parent supplies its independently
    /// verified resource-pack metadata; these paths never share datapack metadata.
    pub fn resource_pack_resources(&self) -> &BTreeMap<String, StagedResource> {
        &self.resource_pack_resources
    }
    pub fn function_contracts(
        &self,
    ) -> &BTreeMap<ResourceLocation, Vec<GeneratedFunctionContract>> {
        &self.function_contracts
    }
    pub fn source_map_entries(&self) -> &[Value] {
        &self.source_map_entries
    }
    pub fn entry_points(&self) -> &BTreeMap<String, ResourceLocation> {
        &self.entry_points
    }
    pub fn defined_functions(&self) -> &BTreeSet<ResourceLocation> {
        &self.defined_functions
    }
    pub fn referenced_functions(&self) -> &BTreeSet<ResourceLocation> {
        &self.referenced_functions
    }
    pub fn external_functions(&self) -> &BTreeMap<ResourceLocation, Sha256Digest> {
        &self.external_functions
    }
    pub fn state_symbols(&self) -> &BTreeSet<String> {
        &self.state_symbols
    }
    pub fn runtime_dependencies(&self) -> &[String] {
        &[]
    }
    pub fn covered_owned_sources(&self) -> &BTreeSet<CoveredSceneSource> {
        &self.covered_owned_sources
    }
    pub fn prefab_ids(&self) -> &BTreeSet<String> {
        &self.prefab_ids
    }
    pub fn instance_ids(&self) -> &BTreeSet<String> {
        &self.instance_ids
    }
    pub fn resource_ids(&self) -> &BTreeSet<String> {
        &self.resource_ids
    }
    pub fn required_clip_ids(&self) -> &BTreeSet<String> {
        &self.required_clip_ids
    }
    pub fn required_animation_bindings(&self) -> &BTreeSet<(String, String)> {
        &self.required_animation_bindings
    }
    pub fn animation_bindings(&self) -> &BTreeMap<InstanceId, AnimationSceneProjection> {
        &self.animation_bindings
    }
    pub fn state_bindings(
        &self,
    ) -> &BTreeMap<InstanceId, BTreeMap<mmmm_contracts::StateId, SceneStateBinding>> {
        &self.state_bindings
    }
    pub fn input_revision(&self) -> &Sha256Digest {
        &self.input_revision
    }
    pub fn target_profile_digest(&self) -> &Sha256Digest {
        &self.target_profile_digest
    }
    pub fn target_artifact_digest(&self) -> &Sha256Digest {
        &self.target_artifact_digest
    }
    pub fn compiler_digest(&self) -> &Sha256Digest {
        &self.compiler_digest
    }
    pub fn codec_digest(&self) -> &Sha256Digest {
        &self.codec_digest
    }
    pub fn private_distribution_required(&self) -> bool {
        self.private_distribution_required
    }
    pub fn losses(&self) -> &[Value] {
        &self.losses
    }
    /// Generated canonical domain effects only. Runtime observed before-state,
    /// authorized footprint, diff, fencing, and recovery belong to Coordinator.
    pub fn native_steps(&self) -> &[NativeSceneStep] {
        &self.native_steps
    }
    pub fn target_profile_id(&self) -> &TargetProfileId {
        &self.target_profile_id
    }

    pub(crate) fn project_animation_poses(
        &self,
        animation: &AnimationDraft,
        target: &VerifiedTarget,
        tick: i32,
        codec: &dyn SceneTargetCodec,
        registry: &dyn SceneRegistryVerifier,
    ) -> Result<Vec<NativeSceneStep>, DomainError> {
        let codec_digest = codec.codec_digest();
        if self.target_profile_digest != *target.profile_digest()
            || self.target_artifact_digest != *target.artifact_digest()
            || self.target_profile_digest != *animation.target_profile_digest()
            || self.target_artifact_digest != *animation.target_artifact_digest()
            || self.compiler_digest != compiler_digest()
            || self.compiler_digest != *animation.compiler_digest()
            || self.codec_digest != codec_digest
            || self.game_ticks_per_second != *animation.target_tps()
        {
            return Err(DomainError::new(
                "STALE_CONTEXT",
                "Native animation target, compiler, codec or exact TPS differs from its scene",
            ));
        }
        let clip =
            ObjectId::new(animation.clip_id().as_str()).map_err(|error| fail(error.to_string()))?;
        if self.owned_clip_revisions.get(&clip) != Some(animation.clip_revision())
            || !self.required_animation_bindings.contains(&(
                animation.instance_id().to_string(),
                animation.clip_id().to_string(),
            ))
        {
            return Err(DomainError::new(
                "REVISION_CONFLICT",
                "Native animation is outside the exact instance-qualified Project clip pin",
            ));
        }
        let projection = self
            .animation_bindings
            .get(animation.instance_id())
            .ok_or_else(|| unresolved("Native animation instance binding is absent"))?;
        if animation.scene_projection() != projection {
            return Err(DomainError::new(
                "STALE_CONTEXT",
                "Native animation parent, rest, origin, UUID, world or prefab binding differs",
            ));
        }
        if !registry
            .verify_codec(target, &codec_digest)?
            .static_affine_display
        {
            return unsupported("Native display pose codec is unverified");
        }
        let mut displays = BTreeMap::new();
        for step in &self.native_steps {
            if step.phase != SceneLifecyclePhase::Stage
                || step.instance_id != *animation.instance_id()
                || !matches!(step.instruction, NativeSceneInstruction::Display { .. })
            {
                continue;
            }
            let node = step
                .source_node_id
                .as_ref()
                .ok_or_else(|| unresolved("Native display has no exact source node"))?;
            if displays.insert(node.clone(), step).is_some() {
                return Err(unresolved(
                    "Native animation node has duplicate display projections",
                ));
            }
        }
        let mut seen = BTreeSet::new();
        let mut steps = Vec::new();
        let mut output_bytes = 0;
        for pose in animation.poses().iter().filter(|pose| pose.tick == tick) {
            if !seen.insert(pose.node_id.clone()) || steps.len() >= MAX_RETAINED_BINDINGS {
                return Err(range(
                    "Native pose node count is duplicated or exceeds policy",
                ));
            }
            let binding = projection
                .nodes
                .get(&pose.node_id)
                .ok_or_else(|| unresolved("Native pose node is outside its sealed binding"))?;
            let source = displays
                .get(&pose.node_id)
                .ok_or_else(|| unresolved("Native pose has no exact owned display source"))?;
            let NativeSceneInstruction::Display {
                dimension,
                tag,
                entity_kind,
                uuid,
                position,
                ..
            } = &source.instruction
            else {
                return Err(unresolved("Native pose source is not a display"));
            };
            if source.owner_prefab_id != *animation.owner_prefab_id()
                || dimension != &projection.dimension
                || binding.display_uuid.as_deref() != Some(uuid_text(uuid).as_str())
                || position != &binding.display_origin
            {
                return Err(DomainError::new(
                    "STALE_CONTEXT",
                    "Native pose UUID, type origin or owner differs from its sealed scene source",
                ));
            }
            let instruction = NativeSceneInstruction::DisplayPose {
                dimension: dimension.clone(),
                tag: tag.clone(),
                entity_kind: entity_kind.clone(),
                uuid: *uuid,
                matrix: pose.matrix.map(f64::from),
            };
            let mut instruction_bytes = 0;
            charge_serialized(&mut instruction_bytes, &instruction)?;
            if instruction_bytes > MAX_LINE_BYTES {
                return Err(range("Native pose instruction exceeds line policy"));
            }
            let encoded_commands = codec.encode_instruction(&instruction)?;
            if encoded_commands.len() != 1 {
                return Err(fail(
                    "Native display pose requires exactly one closed command",
                ));
            }
            validate_line(&encoded_commands[0])?;
            registry.verify_encoded(target, &codec_digest, &instruction, &encoded_commands[0])?;
            let step = NativeSceneStep {
                phase: SceneLifecyclePhase::Activate,
                source_object_id: clip.clone(),
                source_node_id: Some(pose.node_id.clone()),
                instance_id: animation.instance_id().clone(),
                owner_prefab_id: animation.owner_prefab_id().clone(),
                instruction,
                encoded_commands,
            };
            charge_serialized(&mut output_bytes, &step)?;
            steps.push(step);
        }
        if steps.is_empty()
            || seen.len()
                != projection
                    .nodes
                    .values()
                    .filter(|node| node.display_uuid.is_some())
                    .count()
            || seen.len() != displays.len()
        {
            return Err(unresolved(
                "Native pose does not cover every exact bound display once",
            ));
        }
        Ok(steps)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Asset {
    asset_id: ObjectId,
    kind: String,
    resource: ResourceRef,
    dependencies: Vec<ResourceId>,
    redistribution: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlockSet {
    palette: Vec<SceneBlockStateWire>,
    cells: Vec<BlockCell>,
    block_entities: Vec<Value>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SceneBlockStateWire {
    block_id: ResourceLocation,
    properties: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlockCell {
    #[serde(deserialize_with = "mmmm_contracts::deserialize_i32_vec3")]
    position: [i32; 3],
    #[serde(deserialize_with = "deserialize_palette_index")]
    palette_index: usize,
}

#[derive(Serialize)]
struct OriginInstruction {
    object: String,
    node: Option<String>,
    instance: InstanceId,
    prefab: PrefabId,
    instruction: NativeSceneInstruction,
}

#[derive(Default)]
struct InstructionBudget {
    count: usize,
    bytes: usize,
    error: Option<DomainError>,
}
struct InstructionBuffer {
    entries: Vec<OriginInstruction>,
    budget: Rc<RefCell<InstructionBudget>>,
}
impl InstructionBuffer {
    fn new(budget: &Rc<RefCell<InstructionBudget>>) -> Self {
        Self {
            entries: Vec::new(),
            budget: Rc::clone(budget),
        }
    }
    fn push(&mut self, instruction: OriginInstruction) {
        let mut budget = self.budget.borrow_mut();
        if budget.error.is_some() {
            return;
        }
        let mut size = 0;
        let result = charge_serialized(&mut size, &instruction).and_then(|()| {
            if size > MAX_LINE_BYTES {
                return Err(range(
                    "Native instruction exceeds finite line budget before collection",
                ));
            }
            charge(&mut budget.bytes, size)?;
            budget.count = budget
                .count
                .checked_add(1)
                .ok_or_else(|| range("Instruction count overflow"))?;
            if budget.count > MAX_COMMANDS {
                return Err(range("Scene instruction budget exceeded before collection"));
            }
            Ok(())
        });
        if let Err(error) = result {
            budget.error = Some(error);
            return;
        }
        self.entries.push(instruction);
    }
    fn extend(&mut self, mut other: Self) {
        self.entries.append(&mut other.entries);
    }
}
impl IntoIterator for InstructionBuffer {
    type Item = OriginInstruction;
    type IntoIter = std::vec::IntoIter<OriginInstruction>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

struct PlacedCommand {
    scoped_id: (String, String, String),
    next: Option<(String, String, String)>,
    condition: Option<(String, String, String)>,
    dimension: ResourceLocation,
    position: [i32; 3],
    facing: Facing,
    kind: CommandKind,
    clearance: i32,
}

pub fn scene_lower(
    target: &VerifiedTarget,
    inputs: SceneBuildInputs,
    codec: &dyn SceneTargetCodec,
    registry: &dyn SceneRegistryVerifier,
) -> Result<SceneDraft, DomainError> {
    let codec_digest = codec.codec_digest();
    if !inputs.max_component_error.is_finite() || inputs.max_component_error < 0.0 {
        return Err(range(
            "Native component error policy must be finite and nonnegative",
        ));
    }
    let capabilities = registry.verify_codec(target, &codec_digest)?;
    let mut source_bytes = 0;
    charge_json(&mut source_bytes, &inputs.project)?;
    let _: Value = decode("Project", &inputs.project)?;
    mmmm_contracts::verify_projected_digest("Project", &inputs.project)
        .map_err(|error| fail(error.to_string()))?;
    if inputs.project["targetProfileId"] != target.profile_id().as_str() {
        return unsupported("Project and verified target differ");
    }
    let input_revision: Sha256Digest = serde_json::from_value(inputs.project["revision"].clone())
        .map_err(|error| fail(error.to_string()))?;
    let count = inputs
        .prefabs
        .len()
        .checked_add(inputs.instances.len())
        .and_then(|n| n.checked_add(inputs.command_modules.len()))
        .and_then(|n| n.checked_add(inputs.assets.len()))
        .and_then(|n| n.checked_add(inputs.resources.len()))
        .ok_or_else(|| range("Scene source count overflow"))?;
    if count > MAX_SOURCES {
        return Err(range("Scene source count exceeds budget"));
    }
    for source in inputs
        .prefabs
        .iter()
        .chain(&inputs.instances)
        .chain(&inputs.command_modules)
        .chain(&inputs.assets)
    {
        charge_json(&mut source_bytes, source)?;
    }
    let mut blobs = BTreeMap::new();
    for resource in inputs.resources {
        charge(&mut source_bytes, resource.bytes.len())?;
        let _: Value = decode(
            "ResourceRef",
            &serde_json::to_value(&resource.reference).map_err(|error| fail(error.to_string()))?,
        )?;
        if resource.reference.sha256 != raw_digest(&resource.bytes)
            || resource.reference.size_bytes != resource.bytes.len() as u64
        {
            return Err(DomainError::new(
                "DIGEST_MISMATCH",
                "Source resource bytes differ from digest/length",
            ));
        }
        if blobs
            .insert(resource.reference.resource_id.clone(), resource)
            .is_some()
        {
            return Err(fail("Duplicate source resource ID"));
        }
    }
    let mut covered = BTreeSet::new();
    let mut prefabs = BTreeMap::new();
    let mut required_clip_ids = BTreeSet::new();
    for value in &inputs.prefabs {
        let prefab: Prefab = checked_source(
            "Prefab",
            "prefab",
            "prefabId",
            value,
            &inputs.project,
            &mut covered,
        )?;
        mmmm_domain::prefab::require_valid(&prefab)?;
        for resource in &prefab.resources {
            require_blob(target, resource, &blobs, registry)?;
        }
        for node in &prefab.nodes {
            if node.physics_binding.is_some()
                || node.geometry_representation.as_deref() == Some("surface_sample")
                || node.geometry_resource.is_some()
                || !node.colliders.is_empty()
                || !node.extensions.is_empty()
            {
                return unsupported(
                    "Physics, surface, skinning and unknown extension lowering require separate verified capabilities",
                );
            }
            // Colliders do not silently become physical/interaction carriers.
        }
        required_clip_ids.extend(prefab.clip_ids.iter().map(|id| id.as_str().to_owned()));
        if prefabs.insert(prefab.prefab_id.clone(), prefab).is_some() {
            return Err(fail("Duplicate prefab ID"));
        }
    }
    let mut modules = BTreeMap::new();
    for value in &inputs.command_modules {
        let module: CommandModule = checked_source(
            "CommandModule",
            "command_module",
            "moduleId",
            value,
            &inputs.project,
            &mut covered,
        )?;
        validate_command_graph(
            &module,
            CommandStateRules::SixAxisAdjacentChainConditionBehind,
        )?;
        if !prefabs.contains_key(&module.owner_prefab_id) {
            return Err(unresolved("Command module owner is absent"));
        }
        if modules.insert(module.module_id.clone(), module).is_some() {
            return Err(fail("Duplicate module ID"));
        }
    }
    for prefab in prefabs.values() {
        for id in &prefab.command_module_ids {
            let module = modules
                .get(id)
                .ok_or_else(|| unresolved("Prefab command module is missing"))?;
            if module.owner_prefab_id != prefab.prefab_id
                || !prefab
                    .nodes
                    .iter()
                    .any(|node| node.node_id == module.local_origin_node_id)
            {
                return Err(unresolved(
                    "Command module owner/origin differs from prefab",
                ));
            }
        }
    }
    if modules.values().any(|module| {
        !prefabs[&module.owner_prefab_id]
            .command_module_ids
            .contains(&module.module_id)
    }) {
        return Err(unresolved("Owned module is not referenced by its owner"));
    }
    let mut instances = BTreeMap::new();
    for value in &inputs.instances {
        let instance: Instance = checked_source(
            "Instance",
            "instance",
            "instanceId",
            value,
            &inputs.project,
            &mut covered,
        )?;
        let prefab = prefabs
            .get(&instance.prefab_id)
            .ok_or_else(|| unresolved("Instance prefab source is absent"))?;
        require_source(&instance, prefab)?;
        if instances
            .insert(instance.instance_id.clone(), instance)
            .is_some()
        {
            return Err(fail("Duplicate instance ID"));
        }
    }
    let worlds: BTreeSet<_> = instances
        .values()
        .map(|instance| instance.world_id.clone())
        .collect();
    if worlds.len() > 1 {
        return unsupported("A vanilla function bundle requires one pinned server world identity");
    }
    let prefab_ids: BTreeSet<_> = prefabs.keys().map(|id| id.as_str().to_owned()).collect();
    let instance_ids: BTreeSet<_> = instances.keys().map(|id| id.as_str().to_owned()).collect();
    if string_set(&inputs.project["prefabIds"])? != prefab_ids
        || string_set(&inputs.project["instanceIds"])? != instance_ids
    {
        return Err(unresolved(
            "Scene sources do not close the project prefab/instance inventory",
        ));
    }
    let resource_ids = blobs
        .keys()
        .map(|id| id.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    if !string_set(&inputs.project["resourceIds"])?.is_subset(&resource_ids) {
        return Err(unresolved(
            "Project resource inventory lacks pinned source bytes",
        ));
    }
    // Reject the full retained cross-product before world-transform maps and
    // per-instance node/state projections are allocated. Helper-only nodes and
    // shared project state are counted even when they emit no commands.
    let mut retained_nodes = 0usize;
    let mut retained_states = 0usize;
    for instance in instances.values() {
        let prefab = &prefabs[&instance.prefab_id];
        retained_nodes = retained_nodes
            .checked_add(prefab.nodes.len())
            .ok_or_else(|| range("Retained node binding count overflow"))?;
        retained_states = retained_states
            .checked_add(prefab.state.len())
            .ok_or_else(|| range("Retained state binding count overflow"))?;
        if retained_nodes > MAX_RETAINED_BINDINGS || retained_states > MAX_RETAINED_BINDINGS {
            return Err(range(
                "Instance-qualified retained bindings exceed finite count budget",
            ));
        }
    }
    let identity = canonical_digest(&json!({"project":input_revision,"target":target.profile_digest(),"codec":codec_digest,"compiler":compiler_digest()}))
        .map_err(|error| fail(error.to_string()))?;
    let namespace = format!("mmmm_{}", &identity.as_str()[..16]);
    // Gameplay state addresses are stable across authoring/compiler revisions.
    // Exact profile ID remains part of the address: profile-specific storage
    // must not alias a different target's state without an explicit migration.
    let state_identity = canonical_digest(&json!({
        "projectId": inputs.project["projectId"],
        "targetProfileId": target.profile_id(),
    }))
    .map_err(|error| fail(error.to_string()))?;
    let state_namespace = format!("mmmm_{}", &state_identity.as_str()[..16]);
    let storage = ResourceLocation::new(format!("{state_namespace}:state"))
        .map_err(|error| fail(error.to_string()))?;
    let instruction_budget = Rc::new(RefCell::new(InstructionBudget::default()));
    let mut stage = InstructionBuffer::new(&instruction_budget);
    let mut shells = InstructionBuffer::new(&instruction_budget);
    let mut data = InstructionBuffer::new(&instruction_budget);
    let mut activation = InstructionBuffer::new(&instruction_budget);
    let mut cleanup = InstructionBuffer::new(&instruction_budget);
    let mut state_symbols = BTreeSet::new();
    let mut state_values = BTreeMap::new();
    let mut required_animation_bindings = BTreeSet::new();
    let mut animation_bindings = BTreeMap::new();
    let mut state_bindings = BTreeMap::new();
    let mut display_uuids = BTreeSet::new();
    let mut placed_commands = Vec::new();
    let mut positions = BTreeSet::new();
    let mut references = BTreeSet::new();
    let mut external = BTreeMap::new();
    let mut state_reads = BTreeSet::new();
    let mut stage_state_writes = BTreeSet::new();
    let mut cleanup_state_writes = BTreeSet::new();
    let mut command_state_writes = BTreeSet::new();
    let mut losses = Vec::new();
    let mut binding_metadata_bytes = 0usize;
    let mut state_objectives = BTreeMap::new();
    let mut state_keys = BTreeMap::new();
    for instance in instances.values() {
        let prefab = &prefabs[&instance.prefab_id];
        let world = world_transforms(prefab, &instance.placement, &instance.overrides)?;
        let mut binding_nodes = BTreeMap::new();
        let mut instance_state_bindings = BTreeMap::new();
        let defaults = effective_defaults(prefab, &instance.overrides)?;
        required_animation_bindings.extend(prefab.clip_ids.iter().map(|id| {
            (
                instance.instance_id.as_str().to_owned(),
                id.as_str().to_owned(),
            )
        }));
        for state in &prefab.state {
            if !capabilities.scoped_state {
                return unsupported("Exact scoped state codec is unverified");
            }
            if matches!(state.scope, StateScope::Player | StateScope::Ephemeral) {
                return unsupported(
                    "Player/invocation state needs an independently bound execution context",
                );
            }
            if !["spawn", "load_once"].contains(&state.lifecycle.as_str()) {
                return unsupported(
                    "Session/invocation lifecycle needs an independently bound session",
                );
            }
            let scope = if state.scope == StateScope::Project {
                format!(
                    "project/{}",
                    inputs.project["projectId"].as_str().unwrap_or_default()
                )
            } else {
                format!(
                    "project/{}/instance/{}",
                    inputs.project["projectId"].as_str().unwrap_or_default(),
                    instance.instance_id
                )
            };
            let symbol = format!("{scope}/state/{}", state.state_id);
            let state_address = canonical_digest(&json!({
                "qualifiedState": symbol,
                "targetProfileId": target.profile_id(),
            }))
            .map_err(|error| fail(error.to_string()))?;
            let key = format!("s_{}", &state_address.as_str()[..24]);
            let value = defaults[&state.state_id].clone();
            if state.state_type == StateType::Float32
                && let ScalarValue::Number(number) = &value
            {
                let error = component_error(
                    number
                        .as_f64()
                        .ok_or_else(|| fail("State scalar is not a number"))?,
                    inputs.max_component_error,
                )?;
                if error > 0.0 {
                    losses.push(native_loss(
                        state.state_id.as_str(),
                        "STATE_F32_ROUNDING",
                        "minecraft:float32_state",
                        error,
                    )?);
                }
            }
            let signature = canonical_digest(&json!({"value":value,"type":state.state_type,"storage":state.storage,"lifecycle":state.lifecycle,"unit":state.unit})).map_err(|error| fail(error.to_string()))?;
            let objective = format!("m{}", &raw_digest(key.as_bytes()).as_str()[..15]);
            let holder = format!("#{key}");
            for (map, native) in [(&mut state_objectives, &objective), (&mut state_keys, &key)] {
                if map
                    .insert(native.clone(), symbol.clone())
                    .is_some_and(|prior| prior != symbol)
                {
                    return Err(DomainError::new(
                        "ID_COLLISION",
                        "Generated native state address collision",
                    ));
                }
            }
            let binding = SceneStateBinding {
                qualified_state: symbol.clone(),
                storage: storage.clone(),
                key: key.clone(),
                objective: objective.clone(),
                holder: holder.clone(),
                storage_kind: state.storage.clone(),
                state_type: state.state_type,
                lifecycle: state.lifecycle.clone(),
            };
            charge_serialized(&mut binding_metadata_bytes, &binding)?;
            instance_state_bindings.insert(state.state_id.clone(), binding);
            if let Some(previous) = state_values.insert(symbol.clone(), signature.clone()) {
                if previous != signature {
                    return Err(fail(
                        "Shared project state has conflicting instance defaults",
                    ));
                }
                continue;
            }
            state_symbols.insert(symbol.clone());
            stage_state_writes.insert(symbol.clone());
            let instruction = NativeSceneInstruction::StateInitialize {
                storage: storage.clone(),
                key: key.clone(),
                value: native_scalar(value, state.state_type)?,
                storage_kind: state.storage.clone(),
                state_type: state.state_type,
                lifecycle: state.lifecycle.clone(),
                objective: objective.clone(),
                holder: holder.clone(),
            };
            stage.push(origin(
                instance,
                instance.instance_id.as_str(),
                None,
                instruction,
            ));
            if state.lifecycle != "load_once" {
                cleanup_state_writes.insert(symbol);
                cleanup.push(origin(
                    instance,
                    instance.instance_id.as_str(),
                    None,
                    NativeSceneInstruction::StateRemove {
                        storage: storage.clone(),
                        key,
                        storage_kind: state.storage.clone(),
                        objective,
                        holder,
                    },
                ));
            }
            ensure_instruction_budget(&stage, &shells, &data, &activation, &cleanup)?;
        }
        for node in &prefab.nodes {
            let matrix = world[&node.node_id];
            let rest_local = instance
                .overrides
                .iter()
                .find_map(|entry| match entry {
                    InstanceOverride::Transform { node_id, transform }
                        if node_id == &node.node_id =>
                    {
                        Some(transform)
                    }
                    _ => None,
                })
                .unwrap_or(&node.transform)
                .clone();
            let mut binding = AnimationNodeBinding {
                parent: node.parent_id.clone(),
                rest_local,
                display_uuid: None,
                display_origin: [0.0; 3],
            };
            if let Some(geometry) = &node.block_geometry {
                if geometry.rotation_policy != "quarter_turn_y_only"
                    || geometry.cell_origin != "minimum_corner"
                {
                    return unsupported("Unsupported block cell rotation/origin policy");
                }
                let (quarter_turns, translation) = block_placement(&matrix)?;
                let reference = prefab
                    .resources
                    .iter()
                    .find(|resource| resource.resource_id == geometry.resource_id)
                    .ok_or_else(|| unresolved("Block geometry source reference is absent"))?;
                let resource = require_blob(target, reference, &blobs, registry)?;
                let block_value = mmmm_contracts::parse_json(&resource.bytes)
                    .map_err(|error| fail(error.to_string()))?;
                let set: BlockSet = decode("BlockSet", &block_value)?;
                if !set.block_entities.is_empty() {
                    return unsupported(
                        "Block-entity codec lowering is unverified; NBT resources are not injected",
                    );
                }
                for cell in set.cells {
                    if (0..3).any(|axis| {
                        cell.position[axis] < geometry.bounds.min[axis]
                            || cell.position[axis] >= geometry.bounds.max_exclusive[axis]
                    }) {
                        return Err(fail("Block cell lies outside declared half-open bounds"));
                    }
                    let source_state = set
                        .palette
                        .get(cell.palette_index)
                        .ok_or_else(|| unresolved("Block cell palette index is absent"))?;
                    let state = registry.block_state(
                        target,
                        &SceneBlockState {
                            block_id: source_state.block_id.clone(),
                            properties: source_state.properties.clone(),
                        },
                        quarter_turns,
                    )?;
                    if [
                        "minecraft:command_block",
                        "minecraft:chain_command_block",
                        "minecraft:repeating_command_block",
                    ]
                    .contains(&state.block_id.as_str())
                    {
                        return unsupported(
                            "Command blocks must use explicit command module lowering",
                        );
                    }
                    let position = cell_position(cell.position, quarter_turns, translation)?;
                    if !positions.insert((instance.dimension.clone(), position)) {
                        return Err(fail("Block/command cells overlap in compiled world"));
                    }
                    stage.push(origin(
                        instance,
                        instance.instance_id.as_str(),
                        Some(node.node_id.as_str()),
                        NativeSceneInstruction::Block {
                            dimension: instance.dimension.clone(),
                            position,
                            state,
                        },
                    ));
                    ensure_instruction_budget(&stage, &shells, &data, &activation, &cleanup)?;
                }
            }
            let display = instance
                .overrides
                .iter()
                .find_map(|entry| match entry {
                    InstanceOverride::Display { node_id, display } if node_id == &node.node_id => {
                        Some(display)
                    }
                    _ => None,
                })
                .or(node.display.as_ref());
            if let Some(display) = display {
                if !capabilities.static_affine_display
                    || (display.text_role.as_deref() == Some("background_geometry")
                        && !capabilities.text_background_geometry)
                {
                    return unsupported("Exact affine or text background codec is unverified");
                }
                for id in &display.resource_refs {
                    if !blobs.contains_key(id) {
                        return Err(unresolved("Display resource is absent"));
                    }
                }
                let mut authored_payload_bytes = 0;
                charge_serialized(&mut authored_payload_bytes, &display.payload)?;
                if authored_payload_bytes > MAX_LINE_BYTES {
                    return Err(range(
                        "Display payload exceeds line budget before per-instance codec cloning",
                    ));
                }
                let payload = registry.display_payload(target, display)?;
                if payload
                    .get("billboard")
                    .is_some_and(|value| value != "fixed")
                    || payload.contains_key("Rotation")
                    || payload.contains_key("rotation")
                {
                    return unsupported(
                        "Static world affine and animation bindings require a fixed billboard and identity entity rotation",
                    );
                }
                let tag = format!(
                    "{namespace}.{}",
                    &raw_digest(format!("{}/{}", instance.instance_id, node.node_id).as_bytes())
                        .as_str()[..24]
                );
                let values = matrix.values();
                let position = [values[3], values[7], values[11]];
                // A clip or unrelated authoring edit must keep the same live
                // display identity. World/dimension/profile changes require a
                // separately authorized relocation/migration at the apply layer.
                let digest = canonical_digest(&json!({
                    "projectId": inputs.project["projectId"],
                    "targetProfileId": target.profile_id(),
                    "worldId": instance.world_id,
                    "dimension": instance.dimension,
                    "instanceId": instance.instance_id,
                    "nodeId": node.node_id,
                }))
                .map_err(|error| fail(error.to_string()))?;
                let mut uuid = [0; 16];
                uuid.copy_from_slice(&digest.to_bytes()[..16]);
                uuid[6] = (uuid[6] & 0x0f) | 0x80;
                uuid[8] = (uuid[8] & 0x3f) | 0x80;
                if !display_uuids.insert(uuid) {
                    return Err(fail("Generated display UUID collision"));
                }
                binding.display_uuid = Some(uuid_text(&uuid));
                binding.display_origin = position;
                let mut affine = *values;
                affine[3] = 0.0;
                affine[7] = 0.0;
                affine[11] = 0.0;
                let mut conversion_error = 0.0_f64;
                for value in &mut affine {
                    conversion_error =
                        conversion_error.max(component_error(*value, inputs.max_component_error)?);
                    *value = f64::from(*value as f32);
                }
                if conversion_error > 0.0 {
                    losses.push(native_loss(
                        node.node_id.as_str(),
                        "DISPLAY_F32_ROUNDING",
                        "minecraft:display_affine",
                        conversion_error,
                    )?);
                }
                stage.push(origin(
                    instance,
                    instance.instance_id.as_str(),
                    Some(node.node_id.as_str()),
                    NativeSceneInstruction::Display {
                        dimension: instance.dimension.clone(),
                        tag,
                        entity_kind: display.kind.clone(),
                        uuid,
                        position,
                        matrix: affine,
                        payload,
                    },
                ));
                cleanup.push(origin(
                    instance,
                    instance.instance_id.as_str(),
                    Some(node.node_id.as_str()),
                    NativeSceneInstruction::DisplayRemove {
                        dimension: instance.dimension.clone(),
                        uuid,
                        entity_kind: display.kind.clone(),
                    },
                ));
                ensure_instruction_budget(&stage, &shells, &data, &activation, &cleanup)?;
            }
            charge_serialized(
                &mut binding_metadata_bytes,
                &(
                    &node.node_id,
                    &binding.parent,
                    &binding.rest_local,
                    &binding.display_uuid,
                    &binding.display_origin,
                ),
            )?;
            charge(&mut binding_metadata_bytes, 128)?;
            binding_nodes.insert(node.node_id.clone(), binding);
        }
        charge_serialized(
            &mut binding_metadata_bytes,
            &(
                &instance.instance_id,
                &prefab.prefab_id,
                &instance.world_id,
                &instance.dimension,
                &instance.placement,
            ),
        )?;
        animation_bindings.insert(
            instance.instance_id.clone(),
            AnimationSceneProjection {
                instance_id: instance.instance_id.clone(),
                owner_prefab_id: prefab.prefab_id.clone(),
                world_id: instance.world_id.clone(),
                dimension: instance.dimension.clone(),
                instance_world: instance.placement.clone(),
                nodes: binding_nodes,
            },
        );
        for id in &prefab.command_module_ids {
            if !capabilities.staged_command_blocks {
                return unsupported("Command block inactive setup/activation codec is unverified");
            }
            let module = &modules[id];
            let matrix = world[&module.local_origin_node_id];
            let (turns, translation) = block_placement(&matrix)?;
            // Rack lowering is not an implicit authoring relocation. FN06's
            // inactive layout must already be committed to the source revision.
            for command in &module.commands {
                let moved = matrix != Matrix4::identity();
                if command.parse_status == ParseStatus::Opaque && moved {
                    return Err(DomainError::new(
                        "OPAQUE_RELOCATION",
                        "Opaque command source cannot move with an instance",
                    ));
                }
                let resolved = registry.resolve_command(
                    target,
                    module,
                    command,
                    prefab,
                    instance,
                    &matrix,
                    &instance_state_bindings,
                )?;
                validate_line(&resolved.source)?;
                let mut resolved_bytes = 0;
                charge_serialized(
                    &mut resolved_bytes,
                    &(
                        &resolved.referenced_functions,
                        &resolved.external_functions,
                        &resolved.state_reads,
                        &resolved.state_writes,
                    ),
                )?;
                charge(&mut instruction_budget.borrow_mut().bytes, resolved_bytes)?;
                if command.parse_status == ParseStatus::Opaque && resolved.source != command.source
                {
                    return Err(DomainError::new(
                        "OPAQUE_RELOCATION",
                        "Opaque source must remain byte-for-byte unchanged",
                    ));
                }
                for (function, pin) in resolved.external_functions {
                    if !resolved.referenced_functions.contains(&function) {
                        return Err(fail("External function witness is not referenced"));
                    }
                    if external
                        .insert(function, pin.clone())
                        .is_some_and(|previous| previous != pin)
                    {
                        return Err(fail("External function has conflicting exact digest pins"));
                    }
                }
                references.extend(resolved.referenced_functions);
                state_reads.extend(resolved.state_reads);
                command_state_writes.extend(resolved.state_writes);
                let position = cell_position(command.local_position, turns, translation)?;
                if !positions.insert((instance.dimension.clone(), position)) {
                    return Err(fail("Block/command cells overlap in compiled world"));
                }
                let facing = rotate_facing(command.facing, turns);
                let scoped = |id: &mmmm_contracts::CommandId| {
                    (
                        instance.instance_id.as_str().to_owned(),
                        module.module_id.as_str().to_owned(),
                        id.as_str().to_owned(),
                    )
                };
                placed_commands.push(PlacedCommand {
                    scoped_id: scoped(&command.command_id),
                    next: command.next_id.as_ref().map(scoped),
                    condition: command.condition_source_id.as_ref().map(scoped),
                    dimension: instance.dimension.clone(),
                    position,
                    facing,
                    kind: command.kind,
                    clearance: module.physical_clearance_blocks,
                });
                shells.push(origin(
                    instance,
                    module.module_id.as_str(),
                    Some(module.local_origin_node_id.as_str()),
                    NativeSceneInstruction::CommandShell {
                        dimension: instance.dimension.clone(),
                        position,
                        command_kind: command.kind,
                        facing,
                        conditional: command.conditional,
                    },
                ));
                data.push(origin(
                    instance,
                    module.module_id.as_str(),
                    Some(module.local_origin_node_id.as_str()),
                    NativeSceneInstruction::CommandData {
                        dimension: instance.dimension.clone(),
                        position,
                        source: resolved.source,
                    },
                ));
                activation.push(origin(
                    instance,
                    module.module_id.as_str(),
                    Some(module.local_origin_node_id.as_str()),
                    NativeSceneInstruction::CommandActivation {
                        dimension: instance.dimension.clone(),
                        position,
                        auto: command.auto,
                    },
                ));
                cleanup.push(origin(
                    instance,
                    module.module_id.as_str(),
                    Some(module.local_origin_node_id.as_str()),
                    NativeSceneInstruction::CommandActivation {
                        dimension: instance.dimension.clone(),
                        position,
                        auto: false,
                    },
                ));
                ensure_instruction_budget(&stage, &shells, &data, &activation, &cleanup)?;
            }
        }
        state_bindings.insert(instance.instance_id.clone(), instance_state_bindings);
    }
    validate_placed_commands(&placed_commands)?;
    // Every shell is inactive before any source is installed. Activation lives
    // in a separate function and is never called from staging or pack load.
    stage.extend(shells);
    stage.extend(data);
    let mut resources = BTreeMap::new();
    let mut resource_pack_resources = BTreeMap::new();
    let mut private_distribution_required = false;
    let mut output_bytes = 0;
    charge_serialized(&mut output_bytes, &losses)?;
    let mut asset_ids = BTreeSet::new();
    for value in &inputs.assets {
        let asset: Asset = checked_source(
            "Asset",
            "asset",
            "assetId",
            value,
            &inputs.project,
            &mut covered,
        )?;
        if !asset_ids.insert(asset.asset_id.clone()) {
            return Err(fail("Duplicate asset ID"));
        }
        if !["allowed", "user_local_only"].contains(&asset.redistribution.as_str()) {
            return Err(DomainError::new(
                "REDISTRIBUTION_DENIED",
                "Asset redistribution is absent or denied",
            ));
        }
        private_distribution_required |= asset.redistribution == "user_local_only";
        if asset.dependencies.iter().any(|id| !blobs.contains_key(id)) {
            return Err(unresolved("Asset dependency lacks pinned resource bytes"));
        }
        let blob = require_blob(target, &asset.resource, &blobs, registry)?;
        let path = registry.asset_path(target, value, blob)?;
        if let Some(path) = path {
            if !capabilities.resource_pack_assets || target.resource_pack_version().is_none() {
                return unsupported("Exact resource-pack metadata/asset codec is unverified");
            }
            validate_asset_path(&path)?;
            insert(
                &mut resource_pack_resources,
                &mut output_bytes,
                path,
                StagedResource::new(
                    asset.resource.resource_id.clone(),
                    &asset.resource.media_type,
                    blob.bytes.clone(),
                ),
            )?;
        } else if asset.kind != "block_set" {
            return unsupported("Unlowered asset cannot claim project coverage");
        }
        let source = canonical_bytes(value).map_err(|error| fail(error.to_string()))?;
        let revision = value["revision"]
            .as_str()
            .ok_or_else(|| fail("Asset revision is absent"))?;
        let path = format!("mmmm/scene-sources/asset_{}.json", &revision[..24]);
        insert(
            &mut resources,
            &mut output_bytes,
            path,
            StagedResource::new(
                ResourceId::new(format!("scene-asset:{}", &revision[..24]))
                    .map_err(|error| fail(error.to_string()))?,
                "application/json",
                source,
            ),
        )?;
    }
    // Include immutable definitions even if there are no placed instances.
    // The pack's source map and CAS pins keep authoring ownership auditable.
    for (kind, values) in [
        ("prefab", &inputs.prefabs),
        ("instance", &inputs.instances),
        ("command_module", &inputs.command_modules),
    ] {
        for value in values {
            let digest = canonical_digest(value).map_err(|error| fail(error.to_string()))?;
            insert(
                &mut resources,
                &mut output_bytes,
                format!("mmmm/scene-sources/{kind}_{}.json", &digest.as_str()[..24]),
                StagedResource::new(
                    ResourceId::new(format!("scene-source:{}", &digest.as_str()[..24]))
                        .map_err(|error| fail(error.to_string()))?,
                    "application/json",
                    canonical_bytes(value).map_err(|error| fail(error.to_string()))?,
                ),
            )?;
        }
    }
    let mut function_contracts = BTreeMap::new();
    let mut entries = Vec::new();
    let mut entry_points = BTreeMap::new();
    let mut defined = BTreeSet::new();
    let mut native_steps = Vec::new();
    for (name, phase, instructions) in [
        ("stage", SceneLifecyclePhase::Stage, stage),
        ("activate", SceneLifecyclePhase::Activate, activation),
        ("cleanup", SceneLifecyclePhase::Cleanup, cleanup),
    ] {
        let id = ResourceLocation::new(format!("{namespace}:scene/{name}"))
            .map_err(|error| fail(error.to_string()))?;
        let resource_id = ResourceId::new(format!(
            "scene-function:{}",
            &raw_digest(id.as_str().as_bytes()).as_str()[..24]
        ))
        .map_err(|error| fail(error.to_string()))?;
        let mut bytes = Vec::new();
        let mut line_number = 1;
        for origin in instructions {
            // Check before the encoder can serialize or clone a normalized
            // payload supplied by a trusted codec registry.
            let mut native_bytes = 0;
            charge_serialized(&mut native_bytes, &origin.instruction)?;
            if native_bytes > MAX_LINE_BYTES {
                return Err(range("Native instruction exceeds finite line budget"));
            }
            let encoded = codec.encode_instruction(&origin.instruction)?;
            if encoded.is_empty() || encoded.len() > 4 {
                return Err(fail(
                    "A native instruction must emit a finite nonempty command sequence",
                ));
            }
            for command in &encoded {
                validate_line(command)?;
                registry.verify_encoded(target, &codec_digest, &origin.instruction, command)?;
                charge(&mut output_bytes, command.len() + 1)?;
                bytes.extend_from_slice(command.as_bytes());
                bytes.push(b'\n');
                let mut entry = json!({"sourceObjectId":origin.object,"outputResourceId":resource_id,"locator":format!("line:{line_number}")});
                if let Some(node) = &origin.node {
                    entry["sourceNodeId"] = json!(node);
                }
                charge_json(&mut output_bytes, &entry)?;
                entries.push(entry);
                line_number += 1;
                if line_number > MAX_COMMANDS + 1 {
                    return Err(range("Generated command count exceeds budget"));
                }
            }
            let step = NativeSceneStep {
                phase,
                source_object_id: ObjectId::new(origin.object)
                    .map_err(|error| fail(error.to_string()))?,
                source_node_id: origin
                    .node
                    .map(NodeId::new)
                    .transpose()
                    .map_err(|error| fail(error.to_string()))?,
                instance_id: origin.instance,
                owner_prefab_id: origin.prefab,
                instruction: origin.instruction,
                encoded_commands: encoded,
            };
            // Retaining the source projection consumes the same finite output
            // metadata budget before collection; command files already consume
            // their separate actual byte copies above. No payload clone occurs.
            charge_serialized(&mut output_bytes, &step)?;
            native_steps.push(step);
        }
        // A function with no actions remains an explicitly empty private file,
        // preserving lifecycle entry point closure without inventing effects.
        let path = format!("data/{namespace}/function/scene/{name}.mcfunction");
        if resources
            .insert(
                path,
                StagedResource::new(resource_id, "text/x-mcfunction", bytes),
            )
            .is_some()
        {
            return Err(fail("Scene function output collision"));
        }
        let contract = GeneratedFunctionContract { inputs: Vec::new(), outputs: Vec::new(),
            state_reads: if name == "activate" { state_reads.iter().cloned().collect() } else { Vec::new() },
            state_writes: match name { "stage" => stage_state_writes.iter().cloned().collect(), "activate" => command_state_writes.iter().cloned().collect(), _ => cleanup_state_writes.iter().cloned().collect() },
            execution_context: "explicit_pinned_world_and_dimension", reentrancy: "exclusive_owned_scene", scheduled_callbacks: Vec::new(),
            cleanup: if name == "stage" { vec![format!("function {namespace}:scene/cleanup")] } else { Vec::new() },
            requirements: vec!["application must verify generated score/tag/storage ownership and exact server world identity before lifecycle effects".into(),
                "all command cells must remain loaded, unpowered, and fenced from external triggers during staging; stage must finish and independently read back before activation; command execution is a separate authorized effect".into(),
                "load_once state remains owned after scene cleanup and requires a separately authorized project-state teardown".into(),
                "existing load_once native state type/unit/lifecycle must be independently verified before stage; source compilation cannot migrate persisted state".into(),
                "placed world blocks require journal snapshots and an independent restore plan; cleanup only deactivates command blocks and removes owned displays/state".into()] };
        charge_serialized(&mut output_bytes, &contract)?;
        function_contracts.insert(id.clone(), vec![contract]);
        entry_points.insert(format!("scene_{name}"), id.clone());
        defined.insert(id);
    }
    let expected: BTreeSet<_> = inputs.project["ownedResources"]
        .as_array()
        .ok_or_else(|| fail("Project ownership is absent"))?
        .iter()
        .filter(|record| {
            ["prefab", "instance", "command_module", "asset"]
                .contains(&record["kind"].as_str().unwrap_or_default())
        })
        .map(|record| {
            serde_json::from_value::<CoveredSceneSourceWire>(record.clone())
                .map(|record| CoveredSceneSource {
                    kind: record.kind,
                    object_id: record.object_id,
                    revision: record.revision,
                })
                .map_err(|error| fail(error.to_string()))
        })
        .collect::<Result<_, _>>()?;
    if covered != expected {
        return Err(unresolved(
            "Scene lowering does not cover exactly all scene-kind owned sources",
        ));
    }
    let mut owned_clip_revisions = BTreeMap::new();
    for record in inputs.project["ownedResources"]
        .as_array()
        .ok_or_else(|| fail("Project ownership is absent"))?
        .iter()
        .filter(|record| record["kind"] == "clip")
    {
        if owned_clip_revisions.len() >= MAX_SOURCES {
            return Err(range("Project clip pin count exceeds policy"));
        }
        let record: CoveredSceneSourceWire =
            serde_json::from_value(record.clone()).map_err(|error| fail(error.to_string()))?;
        if owned_clip_revisions
            .insert(record.object_id, record.revision)
            .is_some()
        {
            return Err(fail("Project has duplicate clip source pins"));
        }
    }
    let game_ticks_per_second: RationalTime =
        serde_json::from_value(inputs.project["gameTicksPerSecond"].clone())
            .map_err(|error| fail(error.to_string()))?;
    charge_serialized(&mut output_bytes, &owned_clip_revisions)?;
    charge_serialized(&mut output_bytes, &game_ticks_per_second)?;
    Ok(SceneDraft {
        resources,
        resource_pack_resources,
        function_contracts,
        source_map_entries: entries,
        entry_points,
        defined_functions: defined,
        referenced_functions: references,
        external_functions: external,
        state_symbols,
        covered_owned_sources: covered,
        prefab_ids,
        instance_ids,
        resource_ids,
        required_clip_ids,
        required_animation_bindings,
        owned_clip_revisions,
        game_ticks_per_second,
        animation_bindings,
        state_bindings,
        input_revision,
        target_profile_digest: target.profile_digest().clone(),
        target_artifact_digest: target.artifact_digest().clone(),
        compiler_digest: compiler_digest(),
        codec_digest,
        private_distribution_required,
        losses,
        native_steps,
        target_profile_id: target.profile_id().clone(),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CoveredSceneSourceWire {
    kind: String,
    object_id: ObjectId,
    revision: Sha256Digest,
}

fn checked_source<T: serde::de::DeserializeOwned>(
    definition: &str,
    kind: &str,
    id_key: &str,
    value: &Value,
    project: &Value,
    covered: &mut BTreeSet<CoveredSceneSource>,
) -> Result<T, DomainError> {
    let source = decode(definition, value)?;
    mmmm_contracts::verify_projected_digest(definition, value)
        .map_err(|error| fail(error.to_string()))?;
    let id = value[id_key]
        .as_str()
        .ok_or_else(|| fail("Source stable ID is absent"))?;
    let revision = projected_digest(definition, value).map_err(|error| fail(error.to_string()))?;
    let found = project["ownedResources"].as_array().is_some_and(|owned| {
        owned.iter().any(|record| {
            record["kind"] == kind
                && record["objectId"] == id
                && record["revision"] == revision.as_str()
        })
    });
    if !found {
        return Err(DomainError::new(
            "REVISION_CONFLICT",
            "Source is outside exact project-owned revision inventory",
        ));
    }
    if !covered.insert(CoveredSceneSource {
        kind: kind.into(),
        object_id: ObjectId::new(id).map_err(|error| fail(error.to_string()))?,
        revision,
    }) {
        return Err(fail("Duplicate owned source identity"));
    }
    Ok(source)
}
fn require_blob<'a>(
    target: &VerifiedTarget,
    reference: &ResourceRef,
    blobs: &'a BTreeMap<ResourceId, SceneResource>,
    registry: &dyn SceneRegistryVerifier,
) -> Result<&'a SceneResource, DomainError> {
    let resource = blobs
        .get(&reference.resource_id)
        .ok_or_else(|| unresolved("Source resource bytes are absent"))?;
    if reference.sha256 != resource.reference.sha256
        || reference.size_bytes != resource.reference.size_bytes
    {
        return Err(DomainError::new(
            "DIGEST_MISMATCH",
            "Source resource pin differs",
        ));
    }
    registry.resource_media(target, reference, &resource.reference)?;
    Ok(resource)
}
fn origin(
    instance: &Instance,
    object: &str,
    node: Option<&str>,
    instruction: NativeSceneInstruction,
) -> OriginInstruction {
    OriginInstruction {
        object: object.into(),
        node: node.map(str::to_owned),
        instance: instance.instance_id.clone(),
        prefab: instance.prefab_id.clone(),
        instruction,
    }
}
fn block_placement(matrix: &Matrix4) -> Result<(i32, [i64; 3]), DomainError> {
    let values = matrix.values();
    let translation = [values[3], values[7], values[11]];
    if translation
        .iter()
        .any(|value| value.fract() != 0.0 || *value < i32::MIN as f64 || *value > i32::MAX as f64)
    {
        return unsupported("Blocks require exact integer translation");
    }
    for turns in 0..4 {
        let rotation = Matrix4::quarter_turn_y(turns);
        if [0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 15]
            .into_iter()
            .all(|index| (values[index] - rotation.values()[index]).abs() <= 1e-9)
        {
            return Ok((turns, translation.map(|value| value as i64)));
        }
    }
    unsupported("Blocks require a proper Y quarter-turn without reflection, shear, or scale")
}
fn cell_position(
    cell: [i32; 3],
    turns: i32,
    translation: [i64; 3],
) -> Result<[i32; 3], DomainError> {
    let rotated = rotate_block_cell_y(cell.map(i64::from), turns, translation)
        .map_err(|error| fail(error.to_string()))?;
    Ok([
        i32::try_from(rotated[0]).map_err(|_| range("Block coordinate overflow"))?,
        i32::try_from(rotated[1]).map_err(|_| range("Block coordinate overflow"))?,
        i32::try_from(rotated[2]).map_err(|_| range("Block coordinate overflow"))?,
    ])
}
fn rotate_facing(facing: Facing, turns: i32) -> Facing {
    let cycle = [Facing::North, Facing::West, Facing::South, Facing::East];
    match facing {
        Facing::Up | Facing::Down => facing,
        _ => {
            cycle[(cycle.iter().position(|value| value == &facing).unwrap_or(0)
                + turns.rem_euclid(4) as usize)
                % 4]
        }
    }
}
fn facing_name(facing: Facing) -> &'static str {
    match facing {
        Facing::North => "north",
        Facing::South => "south",
        Facing::West => "west",
        Facing::East => "east",
        Facing::Up => "up",
        Facing::Down => "down",
    }
}
fn block_token(state: &SceneBlockState) -> Result<String, DomainError> {
    let mut properties = Vec::new();
    for (key, value) in &state.properties {
        safe_token(key)?;
        safe_token(value)?;
        properties.push(format!("{key}={value}"));
    }
    Ok(if properties.is_empty() {
        state.block_id.to_string()
    } else {
        format!("{}[{}]", state.block_id, properties.join(","))
    })
}
fn safe_token(value: &str) -> Result<(), DomainError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.#".contains(&byte))
    {
        return Err(fail("Unsafe native token"));
    }
    Ok(())
}
fn validate_line(line: &str) -> Result<(), DomainError> {
    if line.is_empty()
        || line.len() > MAX_LINE_BYTES
        || line.starts_with('/')
        || line
            .bytes()
            .any(|byte| byte == b'\n' || byte == b'\r' || byte == 0)
    {
        return Err(fail("Invalid bounded single command line"));
    }
    Ok(())
}
fn quote(value: &str) -> Result<String, DomainError> {
    serde_json::to_string(value).map_err(|error| fail(error.to_string()))
}
fn snbt(value: &Value, depth: usize) -> Result<String, DomainError> {
    if depth > 64 {
        return Err(range("SNBT nesting exceeds budget"));
    }
    match value {
        Value::Null => unsupported("Null is not an NBT payload value"),
        Value::Bool(value) => Ok(format!("{}b", u8::from(*value))),
        Value::String(value) => quote(value),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                Ok(if i32::try_from(integer).is_ok() {
                    integer.to_string()
                } else {
                    format!("{integer}L")
                })
            } else if let Some(integer) = number.as_u64() {
                i64::try_from(integer)
                    .map(|integer| format!("{integer}L"))
                    .map_err(|_| range("NBT integer exceeds signed int64"))
            } else {
                let number = number.as_f64().ok_or_else(|| fail("Invalid NBT number"))?;
                if number.is_finite() {
                    Ok(format!("{number}d"))
                } else {
                    Err(range("NBT number is nonfinite"))
                }
            }
        }
        Value::Array(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(|value| snbt(value, depth + 1))
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        )),
        Value::Object(values) => Ok(format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| Ok(format!("{}:{}", quote(key)?, snbt(value, depth + 1)?)))
                .collect::<Result<Vec<_>, DomainError>>()?
                .join(",")
        )),
    }
}
fn float_literal(value: f64) -> Result<String, DomainError> {
    let value = value as f32;
    if !value.is_finite() {
        return Err(range("Target float matrix/scalar is nonfinite"));
    }
    Ok(format!("{value}f"))
}
fn component_error(value: f64, budget: f64) -> Result<f64, DomainError> {
    let native = value as f32;
    let error = (value - f64::from(native)).abs();
    if !native.is_finite() || !error.is_finite() || error > budget {
        return Err(range(
            "Native f32 conversion exceeds explicit component error policy",
        ));
    }
    Ok(error)
}
fn native_scalar(value: ScalarValue, state_type: StateType) -> Result<ScalarValue, DomainError> {
    match (state_type, value) {
        (StateType::Boolean, value @ ScalarValue::Boolean(_)) => Ok(value),
        (StateType::Int32, value @ ScalarValue::Number(_)) => Ok(ScalarValue::Number(
            serde_json::Number::from(scalar_integer(&value)?),
        )),
        (StateType::Float32, ScalarValue::Number(number)) => {
            let authored = number
                .as_f64()
                .ok_or_else(|| fail("Invalid float state value"))?;
            let native = authored as f32;
            if !native.is_finite() {
                return Err(range("Native float state value is nonfinite"));
            }
            Ok(ScalarValue::Number(
                serde_json::Number::from_f64(f64::from(native))
                    .ok_or_else(|| range("Native float state value is not representable"))?,
            ))
        }
        _ => Err(fail("State scalar does not match its native type")),
    }
}
fn native_loss(subject: &str, code: &str, feature: &str, error: f64) -> Result<Value, DomainError> {
    let value = json!({"code":code,"severity":"warning","subjectId":subject,"feature":feature,"disposition":"approximated","message":format!("Authored native f32 conversion maximum absolute component error: {error}; source-only calculation, not observed game readback"),"approvalRequired":true});
    let _: Value = decode("LossRecord", &value)?;
    Ok(value)
}
fn coordinate(value: f64) -> Result<String, DomainError> {
    if !value.is_finite() || value.abs() > 30_000_000.0 {
        return Err(range("World coordinate exceeds target bounds"));
    }
    Ok(value.to_string())
}
fn scalar_integer(value: &ScalarValue) -> Result<i32, DomainError> {
    match value {
        ScalarValue::Boolean(value) => Ok(i32::from(*value)),
        ScalarValue::Number(number) => {
            let value = number.as_f64().ok_or_else(|| fail("Invalid score value"))?;
            if value.fract() == 0.0 && value >= i32::MIN as f64 && value <= i32::MAX as f64 {
                Ok(value as i32)
            } else {
                Err(range("Score value exceeds int32"))
            }
        }
    }
}
fn deserialize_palette_index<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<usize, D::Error> {
    let value = Value::deserialize(deserializer)?;
    let value = value
        .as_f64()
        .ok_or_else(|| serde::de::Error::custom("Palette index must be a number"))?;
    if !value.is_finite()
        || value.fract() != 0.0
        || !(0.0..=9_007_199_254_740_991.0).contains(&value)
    {
        return Err(serde::de::Error::custom(
            "Palette index must be a nonnegative exact safe integer",
        ));
    }
    usize::try_from(value as u64).map_err(serde::de::Error::custom)
}
fn string_set(value: &Value) -> Result<BTreeSet<String>, DomainError> {
    value
        .as_array()
        .ok_or_else(|| fail("Inventory array is absent"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| fail("Inventory ID is absent"))
        })
        .collect()
}
fn ensure_instruction_budget(
    groups1: &InstructionBuffer,
    _groups2: &InstructionBuffer,
    _groups3: &InstructionBuffer,
    _groups4: &InstructionBuffer,
    _groups5: &InstructionBuffer,
) -> Result<(), DomainError> {
    if let Some(error) = &groups1.budget.borrow().error {
        return Err(error.clone());
    }
    Ok(())
}
fn uuid_text(uuid: &[u8; 16]) -> String {
    let hex: String = uuid.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}
fn validate_placed_commands(commands: &[PlacedCommand]) -> Result<(), DomainError> {
    let by_position: BTreeMap<_, _> = commands
        .iter()
        .map(|command| {
            (
                (command.dimension.clone(), command.position.map(i64::from)),
                command,
            )
        })
        .collect();
    for command in commands {
        let direction = command.facing.direction();
        let front = std::array::from_fn::<_, 3, _>(|axis| {
            i64::from(command.position[axis]) + direction[axis]
        });
        let next = by_position
            .get(&(command.dimension.clone(), front))
            .filter(|next| next.kind == CommandKind::Chain)
            .map(|next| &next.scoped_id);
        if next != command.next.as_ref() {
            return Err(DomainError::new(
                "CHAIN_GRAPH_MISMATCH",
                "Final placement creates an undeclared physical command chain edge",
            ));
        }
        if command.condition.is_some() {
            let behind = std::array::from_fn::<_, 3, _>(|axis| {
                i64::from(command.position[axis]) - direction[axis]
            });
            if by_position
                .get(&(command.dimension.clone(), behind))
                .map(|other| &other.scoped_id)
                != command.condition.as_ref()
            {
                return Err(DomainError::new(
                    "CONDITION_SOURCE_MISMATCH",
                    "Final conditional predecessor differs from authored scoped identity",
                ));
            }
        }
        if command.clearance > 0
            && commands.iter().any(|other| {
                other.dimension == command.dimension
                    && (other.scoped_id.0 != command.scoped_id.0
                        || other.scoped_id.1 != command.scoped_id.1)
                    && (0..3).all(|axis| {
                        (i64::from(other.position[axis]) - i64::from(command.position[axis])).abs()
                            <= i64::from(command.clearance)
                    })
            })
        {
            return Err(DomainError::new(
                "COMMAND_POSITION_COLLISION",
                "Final command modules violate authored physical clearance",
            ));
        }
    }
    Ok(())
}
fn validate_asset_path(path: &str) -> Result<(), DomainError> {
    let parts: Vec<_> = path.split('/').collect();
    if path.len() > 240
        || parts.len() < 3
        || parts[0] != "assets"
        || path.contains('\\')
        || path.contains(':')
        || parts.iter().any(|part| {
            part.is_empty()
                || *part == "."
                || *part == ".."
                || part.len() > 64
                || part.ends_with('.')
                || !part.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
                })
                || [
                    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6",
                    "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7",
                    "lpt8", "lpt9",
                ]
                .contains(&part.split('.').next().unwrap_or_default())
        })
    {
        return Err(fail(
            "Asset path is not a portable resource-pack relative path",
        ));
    }
    Ok(())
}
fn insert(
    resources: &mut BTreeMap<String, StagedResource>,
    total: &mut usize,
    path: String,
    resource: StagedResource,
) -> Result<(), DomainError> {
    charge(total, resource.bytes.len())?;
    if resources.contains_key(&path)
        || resources.keys().any(|other| {
            path.starts_with(&format!("{other}/")) || other.starts_with(&format!("{path}/"))
        })
    {
        return Err(fail("Scene output path collision"));
    }
    resources.insert(path, resource);
    Ok(())
}
fn charge(total: &mut usize, bytes: usize) -> Result<(), DomainError> {
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| range("Scene byte budget overflow"))?;
    if *total > MAX_BYTES {
        return Err(range("Scene aggregate bytes exceed budget"));
    }
    Ok(())
}
fn charge_json(total: &mut usize, value: &Value) -> Result<(), DomainError> {
    charge_serialized(total, value)
}
fn charge_serialized<T: Serialize>(total: &mut usize, value: &T) -> Result<(), DomainError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("overflow"))?;
            if self.0 > MAX_BYTES {
                return Err(std::io::Error::other("budget"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).map_err(|error| range(error.to_string()))?;
    charge(total, counter.0)
}
fn fail(message: impl Into<String>) -> DomainError {
    DomainError::new("SCHEMA_INVALID", message)
}
fn range(message: impl Into<String>) -> DomainError {
    DomainError::new("NUMERIC_RANGE", message)
}
fn unresolved(message: impl Into<String>) -> DomainError {
    DomainError::new("REFERENCE_UNRESOLVED", message)
}
fn unsupported<T>(message: impl Into<String>) -> Result<T, DomainError> {
    Err(DomainError::new("UNOWNED_REQUIRED_CAPABILITY", message))
}

#[cfg(test)]
#[path = "scene_tests.rs"]
pub(crate) mod tests;

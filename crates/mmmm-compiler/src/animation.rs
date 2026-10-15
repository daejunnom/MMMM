//! Pure FN30 animation lowering. Display NBT grammar is documented at
//! https://www.minecraft.net/en-us/article/minecraft-java-edition-1-19-4 .
//! Those source notes are not runtime evidence for 26.3. Exact target witnesses
//! below independently gate matrix decoding, zero interpolation reset and the
//! complete sampled linear-TRS interval. No entity is spawned, moved or deleted.

use crate::{GeneratedFunctionContract, StagedResource, VerifiedTarget, compiler_digest, decode};
use mmmm_contracts::{
    ClipId, InstanceId, NodeId, ObjectId, PrefabId, RationalTime, ResourceId, ResourceLocation,
    Sha256Digest, SymbolId, WorldId, canonical_bytes, canonical_digest, raw_digest,
};
use mmmm_domain::{
    DomainError,
    time::{
        AnimationClip, AnimationTrack, ClipRepresentation, Interpolation, PoseWriter, TickRounding,
        TimeDomain, validate_clip,
    },
    transform::{Matrix4, Transform},
    types::ResourceRef,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const MAX_NODES: usize = 1024;
const MAX_TICKS: i32 = 200_000;
const MAX_POSES: usize = 200_000;
const MAX_EVENTS: usize = 4096;
const MAX_SOURCE_BYTES: usize = 32 * 1024 * 1024;
const MAX_COMMAND_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct AnimationTargetRules {
    pub row_major_f32_matrix_codec: bool,
    pub explicit_zero_disables_interpolation: bool,
    /// Includes parent composition and the quaternion shortest-arc SLERP
    /// semantics used here. Negative scale and matrix interpolation remain
    /// unsupported even when this capability is present.
    pub sampled_linear_trs_whole_interval: bool,
}

pub trait AnimationEvidenceVerifier {
    /// Verify actual immutable evidence against both exact target identities.
    /// Public source references or caller-supplied success arrays are insufficient.
    fn verify_animation_target(
        &self,
        profile_digest: &Sha256Digest,
        artifact_digest: &Sha256Digest,
    ) -> Result<AnimationTargetRules, DomainError>;
    /// Requires exact function bytes and game evidence for an explicit return
    /// value of 1 only after all declared effects complete. Functions must not
    /// write compiler-private state, call animation controls, or schedule a
    /// reentrant call. A failed/unknown effect must return 0 or fail, never 1.
    fn verify_event_functions(
        &self,
        _profile_digest: &Sha256Digest,
        _artifact_digest: &Sha256Digest,
        _events: &BTreeMap<SymbolId, AnimationEventBinding>,
        _private_objective: &str,
        _private_function_prefix: &str,
    ) -> Result<(), DomainError> {
        Err(DomainError::new(
            "UNOWNED_REQUIRED_CAPABILITY",
            "Exact event success/failure/reentrancy semantics are unverified",
        ))
    }
    /// A generic target capability does not attest an authored affine interval.
    /// Bind the complete interval evidence to exact clip, hierarchy, compiler
    /// and TPS identities before allowing sampled linear-TRS lowering.
    fn verify_linear_interval(
        &self,
        _target: &VerifiedTarget,
        _clip_digest: &Sha256Digest,
        _binding_digest: &Sha256Digest,
        _compiler_digest: &Sha256Digest,
        _target_tps: &RationalTime,
    ) -> Result<(), DomainError> {
        Err(DomainError::new(
            "UNSUPPORTED_TRANSFORM",
            "Exact authored linear interval evidence is absent",
        ))
    }
    /// Bind an unequal zero-duration reset to exact input and target evidence.
    /// Old endpoint holds must survive target client update coalescing.
    fn verify_loop_seam(
        &self,
        _target: &VerifiedTarget,
        _clip_digest: &Sha256Digest,
        _binding_digest: &Sha256Digest,
        _compiler_digest: &Sha256Digest,
        _target_tps: &RationalTime,
    ) -> Result<(), DomainError> {
        Err(DomainError::new(
            "UNSUPPORTED_TRANSFORM",
            "Exact unequal loop seam witness is absent",
        ))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnimationNodeBinding {
    pub parent: Option<NodeId>,
    pub rest_local: Transform,
    /// Lowercase canonical UUID of one independently owned display entity.
    /// UUID targeting avoids an unproven selector uniqueness assumption.
    pub display_uuid: Option<String>,
    /// Fixed display entity origin in the same world frame as instance_world.
    /// A native body must not own this origin while this animation owns its pose.
    pub display_origin: [f64; 3],
}

#[derive(Debug, Clone)]
pub struct AnimationEventBinding {
    pub function: ResourceLocation,
    pub source: StagedResource,
    pub contract: GeneratedFunctionContract,
}

#[derive(Debug, Clone)]
pub struct AnimationBindings {
    pub instance_id: InstanceId,
    pub owner_prefab_id: PrefabId,
    pub world_id: WorldId,
    pub dimension: ResourceLocation,
    pub instance_world: Transform,
    pub nodes: BTreeMap<NodeId, AnimationNodeBinding>,
    pub events: BTreeMap<SymbolId, AnimationEventBinding>,
}

/// Sealed draft projection used when composing with the scene generator.
/// The pack builder must compare this exact topology/anchor/UUID projection
/// against its scene draft, not accept a matching instance identifier alone.
#[derive(Debug, Clone, PartialEq)]
pub struct AnimationSceneProjection {
    pub instance_id: InstanceId,
    pub owner_prefab_id: PrefabId,
    pub world_id: WorldId,
    pub dimension: ResourceLocation,
    pub instance_world: Transform,
    pub nodes: BTreeMap<NodeId, AnimationNodeBinding>,
}

impl AnimationBindings {
    /// The resource snapshot binds parent topology, absolute anchor, UUIDs,
    /// exact event source pins and declared contracts, not just symbol names.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DomainError> {
        let nodes: BTreeMap<_, _> = self
            .nodes
            .iter()
            .map(|(id, node)| {
                (
                    id.as_str(),
                    json!({"parent":node.parent,"restLocal":node.rest_local,
                "displayUuid":node.display_uuid,"displayOrigin":node.display_origin}),
                )
            })
            .collect();
        let events: BTreeMap<_, _> = self
            .events
            .iter()
            .map(|(id, binding)| {
                (
                    id.as_str(),
                    json!({"function":binding.function,"source":binding.source.reference,
                "contract":binding.contract}),
                )
            })
            .collect();
        canonical_bytes(
            &json!({"instanceId":self.instance_id,"ownerPrefabId":self.owner_prefab_id,"worldId":self.world_id,
                "dimension":self.dimension,"instanceWorld":self.instance_world,
            "nodes":nodes,"events":events}),
        )
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))
    }
}

pub trait AnimationBindingVerifier {
    /// Resolve authenticated ownership/ACLs and one active pose writer from the
    /// same immutable context. This must also verify that each UUID is a display
    /// with a fixed origin, fixed billboard and identity entity yaw/pitch, and
    /// event source pins correspond to approved functions.
    fn verify_animation_bindings(
        &self,
        snapshot: &ResourceRef,
        bytes: &[u8],
        bindings: &AnimationBindings,
    ) -> Result<Sha256Digest, DomainError>;
}

#[derive(Debug, Clone)]
pub struct VerifiedAnimationBindings {
    bindings: AnimationBindings,
    snapshot: ResourceRef,
    authority_digest: Sha256Digest,
    parent_order: Vec<NodeId>,
}

impl VerifiedAnimationBindings {
    pub fn verify(
        bindings: AnimationBindings,
        snapshot: ResourceRef,
        bytes: &[u8],
        verifier: &dyn AnimationBindingVerifier,
    ) -> Result<Self, DomainError> {
        if bindings.nodes.len() > MAX_NODES
            || bindings.events.len() > MAX_EVENTS
            || bytes.len() > 8 * 1024 * 1024
            || snapshot.size_bytes != bytes.len() as u64
            || snapshot.sha256 != raw_digest(bytes)
            || bindings.canonical_bytes()? != bytes
        {
            return Err(DomainError::new(
                "RESOURCE_DIGEST_MISMATCH",
                "Animation binding snapshot identity or budget differs",
            ));
        }
        bindings
            .instance_world
            .validate()
            .map_err(transform_error)?;
        let mut uuids = BTreeSet::new();
        for node in bindings.nodes.values() {
            node.rest_local.validate().map_err(transform_error)?;
            if node.display_origin.iter().any(|v| !v.is_finite())
                || node
                    .display_uuid
                    .as_ref()
                    .is_some_and(|uuid| !valid_uuid(uuid) || !uuids.insert(uuid))
            {
                return Err(DomainError::new(
                    "SCHEMA_INVALID",
                    "Display UUID/origin is invalid or duplicated",
                ));
            }
        }
        let mut function_pins = BTreeMap::new();
        let mut event_bytes = 0usize;
        for event in bindings.events.values() {
            event_bytes = event_bytes
                .checked_add(event.source.bytes.len())
                .filter(|size| *size <= MAX_SOURCE_BYTES)
                .ok_or_else(|| DomainError::new("NUMERIC_RANGE", "Event source budget exceeded"))?;
            let pin = canonical_bytes(
                &json!({"source":event.source.reference,"contract":event.contract}),
            )
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
            if event.source.bytes.len() > MAX_SOURCE_BYTES
                || event.source.reference.size_bytes != event.source.bytes.len() as u64
                || event.source.reference.sha256 != raw_digest(&event.source.bytes)
                || std::str::from_utf8(&event.source.bytes).is_err()
                || function_pins
                    .insert(&event.function, pin.clone())
                    .is_some_and(|previous| previous != pin)
            {
                return Err(DomainError::new(
                    "RESOURCE_DIGEST_MISMATCH",
                    "Event function bytes or immutable pins differ",
                ));
            }
        }
        let parent_order = parent_order(&bindings.nodes)?;
        let authority_digest = verifier.verify_animation_bindings(&snapshot, bytes, &bindings)?;
        Ok(Self {
            bindings,
            snapshot,
            authority_digest,
            parent_order,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AnimationCompileSettings {
    pub target_tps: RationalTime,
    /// Explicit absolute budget for conversion from computed f64 matrices to
    /// target f32 components. No scale clamp or automatic error-budget increase.
    pub max_component_error: f64,
    /// One absolute-time catch-up admits 1..=1024 logical ticks. Repeated
    /// guarded calls are finitely emitted and pack admission charges their cost.
    pub max_catchup_ticks: u16,
    /// Conservative per-catch-up bound: remaining ticks times source event
    /// count, including zero and terminal occurrences at the same loop seam.
    pub max_catchup_events: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuantizedTime {
    pub object_id: String,
    pub authored: RationalTime,
    pub tick: i32,
    pub emitted_seconds: RationalTime,
    pub absolute_error: RationalTime,
}

#[derive(Debug, Clone)]
pub struct AnimationPose {
    pub node_id: NodeId,
    pub tick: i32,
    pub matrix: [f32; 16],
    pub max_component_error: f64,
}

#[derive(Debug, Clone)]
pub struct AnimationScheduledEvent {
    pub event_id: ObjectId,
    pub authored_at: RationalTime,
    pub authored_sequence: u64,
    pub tick: i32,
    pub function: ResourceLocation,
}

#[derive(Debug, Clone)]
pub struct AnimationLineOrigin {
    pub function: ResourceLocation,
    pub line: usize,
    pub source_object_id: String,
    pub node_id: Option<NodeId>,
    pub event_id: Option<ObjectId>,
    pub tick: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct AnimationDraft {
    pub(crate) resources: BTreeMap<ResourceLocation, StagedResource>,
    pub(crate) contracts: BTreeMap<ResourceLocation, GeneratedFunctionContract>,
    pub(crate) entry_points: BTreeMap<String, ResourceLocation>,
    pub(crate) external_functions: BTreeMap<ResourceLocation, ResourceRef>,
    pub(crate) event_contracts: BTreeMap<ResourceLocation, GeneratedFunctionContract>,
    pub(crate) line_origins: Vec<AnimationLineOrigin>,
    pub(crate) runtime_dependencies: Vec<String>,
    pub(crate) objective: String,
    pub(crate) input_digest: Sha256Digest,
    pub(crate) binding_digest: Sha256Digest,
    pub(crate) authority_digest: Sha256Digest,
    pub(crate) target_profile_digest: Sha256Digest,
    pub(crate) target_artifact_digest: Sha256Digest,
    pub(crate) compiler_digest: Sha256Digest,
    pub(crate) referenced_functions: BTreeSet<ResourceLocation>,
    pub(crate) binding_snapshot: ResourceRef,
    pub(crate) clip_revision: Sha256Digest,
    pub(crate) function_calls: BTreeMap<ResourceLocation, Vec<ResourceLocation>>,
    pub(crate) owner_prefab_id: PrefabId,
    pub(crate) scene_projection: AnimationSceneProjection,
    pub(crate) target_tps: RationalTime,
    pub(crate) losses: Vec<Value>,
    pub(crate) max_catchup_ticks: u16,
    pub(crate) max_catchup_events: u32,
    clip_id: ClipId,
    instance_id: InstanceId,
    duration_ticks: i32,
    looping: bool,
    poses: Vec<AnimationPose>,
    events: Vec<AnimationScheduledEvent>,
    quantization: Vec<QuantizedTime>,
}

/// One exact source tick derived from two sealed compiler drafts. This borrows
/// their immutable provenance rather than issuing a runtime owner or before
/// snapshot. Coordinator still owns current target reads, scope, and dispatch.
#[derive(Debug)]
pub struct NativeAnimationPoseProjection<'source> {
    animation: &'source AnimationDraft,
    scene: &'source crate::scene::SceneDraft,
    tick: i32,
    steps: Vec<crate::scene::NativeSceneStep>,
}
impl NativeAnimationPoseProjection<'_> {
    pub fn animation(&self) -> &AnimationDraft {
        self.animation
    }
    pub fn scene(&self) -> &crate::scene::SceneDraft {
        self.scene
    }
    pub fn tick(&self) -> i32 {
        self.tick
    }
    pub fn steps(&self) -> &[crate::scene::NativeSceneStep] {
        &self.steps
    }
}

impl AnimationDraft {
    /// Project only already-compiled, instance-qualified poses. Caller matrices,
    /// UUIDs, tags, reset durations, and claimed live before pins are not inputs.
    /// Activate is a source phase; this neither schedules a tick nor plays a clip.
    pub fn native_pose_projection<'source>(
        &'source self,
        target: &VerifiedTarget,
        scene: &'source crate::scene::SceneDraft,
        tick: i32,
        codec: &dyn crate::scene::SceneTargetCodec,
        registry: &dyn crate::scene::SceneRegistryVerifier,
    ) -> Result<NativeAnimationPoseProjection<'source>, DomainError> {
        if self.looping || !self.events.is_empty() {
            return Err(DomainError::new(
                "UNOWNED_REQUIRED_CAPABILITY",
                "Native pose projection does not implement loop or event execution",
            ));
        }
        if !(0..=self.duration_ticks).contains(&tick) {
            return Err(DomainError::new(
                "INVALID_TIME",
                "Native pose tick is outside the sealed clip interval",
            ));
        }
        let steps = scene.project_animation_poses(self, target, tick, codec, registry)?;
        Ok(NativeAnimationPoseProjection {
            animation: self,
            scene,
            tick,
            steps,
        })
    }

    pub fn resources(&self) -> &BTreeMap<ResourceLocation, StagedResource> {
        &self.resources
    }
    pub fn function_contracts(&self) -> &BTreeMap<ResourceLocation, GeneratedFunctionContract> {
        &self.contracts
    }
    pub fn entry_points(&self) -> &BTreeMap<String, ResourceLocation> {
        &self.entry_points
    }
    pub fn external_functions(&self) -> &BTreeMap<ResourceLocation, ResourceRef> {
        &self.external_functions
    }
    pub fn event_function_contracts(
        &self,
    ) -> &BTreeMap<ResourceLocation, GeneratedFunctionContract> {
        &self.event_contracts
    }
    pub fn line_origins(&self) -> &[AnimationLineOrigin] {
        &self.line_origins
    }
    pub fn runtime_dependencies(&self) -> &[String] {
        &self.runtime_dependencies
    }
    pub fn timer_objective(&self) -> &str {
        &self.objective
    }
    pub fn clip_id(&self) -> &ClipId {
        &self.clip_id
    }
    pub fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }
    pub fn duration_ticks(&self) -> i32 {
        self.duration_ticks
    }
    pub fn looping(&self) -> bool {
        self.looping
    }
    pub fn poses(&self) -> &[AnimationPose] {
        &self.poses
    }
    pub fn events(&self) -> &[AnimationScheduledEvent] {
        &self.events
    }
    pub fn quantization(&self) -> &[QuantizedTime] {
        &self.quantization
    }
    pub fn input_digest(&self) -> &Sha256Digest {
        &self.input_digest
    }
    pub fn binding_digest(&self) -> &Sha256Digest {
        &self.binding_digest
    }
    pub fn authority_digest(&self) -> &Sha256Digest {
        &self.authority_digest
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
    pub fn binding_snapshot(&self) -> &ResourceRef {
        &self.binding_snapshot
    }
    pub fn clip_revision(&self) -> &Sha256Digest {
        &self.clip_revision
    }
    pub fn defined_functions(&self) -> BTreeSet<ResourceLocation> {
        self.resources.keys().cloned().collect()
    }
    pub fn referenced_functions(&self) -> &BTreeSet<ResourceLocation> {
        &self.referenced_functions
    }
    pub fn state_symbols(&self) -> Vec<String> {
        vec![format!("score:*:{}", self.objective)]
    }
    pub fn function_calls(&self) -> &BTreeMap<ResourceLocation, Vec<ResourceLocation>> {
        &self.function_calls
    }
    pub fn owner_prefab_id(&self) -> &PrefabId {
        &self.owner_prefab_id
    }
    pub fn scene_projection(&self) -> &AnimationSceneProjection {
        &self.scene_projection
    }
    pub fn target_tps(&self) -> &RationalTime {
        &self.target_tps
    }
    pub fn losses(&self) -> &[Value] {
        &self.losses
    }
    pub fn max_catchup_ticks(&self) -> u16 {
        self.max_catchup_ticks
    }
    pub fn max_catchup_events(&self) -> u32 {
        self.max_catchup_events
    }
}

pub fn animation_compile(
    value: &Value,
    target: &VerifiedTarget,
    bindings: &VerifiedAnimationBindings,
    verifier: &dyn AnimationEvidenceVerifier,
    settings: AnimationCompileSettings,
) -> Result<AnimationDraft, DomainError> {
    let clip: AnimationClip = decode("AnimationClip", value)?;
    validate_clip(&clip)?;
    mmmm_contracts::verify_projected_digest("AnimationClip", value)
        .map_err(|error| DomainError::new("REVISION_CONFLICT", error.to_string()))?;
    let input_digest = raw_digest(
        &mmmm_contracts::encode_json(value)
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?,
    );
    if clip.owner_prefab_id != bindings.bindings.owner_prefab_id {
        return Err(DomainError::new(
            "REFERENCE_UNRESOLVED",
            "Clip owner prefab differs from authenticated instance binding",
        ));
    }
    if clip.time_domain != TimeDomain::GameSeconds
        || clip.pose_writer != PoseWriter::Animation
        || clip.requires_bake
        || clip.representation == ClipRepresentation::TriangulatedSurfaceSamples
    {
        return Err(DomainError::new(
            "UNOWNED_REQUIRED_CAPABILITY",
            "Direct vanilla compiler requires baked game-seconds part tracks with one animation pose writer",
        ));
    }
    if !settings.target_tps.is_positive()
        || settings.target_tps > RationalTime::from_integer(1000)
        || !settings.max_component_error.is_finite()
        || settings.max_component_error < 0.0
        || settings.max_catchup_ticks == 0
        || settings.max_catchup_ticks > 1024
        || settings.max_catchup_events > 16384
        || clip.tracks.len() > MAX_NODES
        || clip.events.len() > MAX_EVENTS
        || clip.events.len() > settings.max_catchup_events as usize
        || clip.sampling.sample_times.len() > MAX_POSES
        || clip
            .tracks
            .iter()
            .try_fold(0usize, |count, track| count.checked_add(track.keys.len()))
            .is_none_or(|count| count > MAX_POSES)
    {
        return Err(DomainError::new(
            "NUMERIC_RANGE",
            "Animation target TPS, component error or source count exceeds explicit policy",
        ));
    }
    let rules =
        verifier.verify_animation_target(target.profile_digest(), target.artifact_digest())?;
    if !rules.row_major_f32_matrix_codec || !rules.explicit_zero_disables_interpolation {
        return Err(DomainError::new(
            "UNSUPPORTED_TARGET_VERSION",
            "Display matrix/reset behavior is not independently verified",
        ));
    }
    let mut quantization = Vec::new();
    let duration_ticks = quantize(
        &clip.duration,
        &clip,
        &settings.target_tps,
        "duration",
        &mut quantization,
    )?;
    if duration_ticks <= 0 || duration_ticks > MAX_TICKS {
        return Err(DomainError::new(
            "INVALID_TIME",
            "Quantized duration must remain positive and bounded",
        ));
    }
    if clip.r#loop && !quantization[0].absolute_error.is_zero() {
        return Err(DomainError::new(
            "INVALID_TIME",
            "Loop period must be exact; unbounded iteration drift cannot use a per-event error tolerance",
        ));
    }
    let mut track_ticks = BTreeMap::new();
    for track in &clip.tracks {
        if track.pose_space != "absolute_parent_local"
            || !bindings.bindings.nodes.contains_key(&track.node_id)
        {
            return Err(DomainError::new(
                "REFERENCE_UNRESOLVED",
                "Clip track parent-local node binding is absent",
            ));
        }
        if track.interpolation == Interpolation::LinearTrs
            && (!rules.sampled_linear_trs_whole_interval || track.keys.iter().any(|key| {
                !matches!(&key.transform, Transform::Trs { scale, .. } if scale.iter().all(|v| *v > 0.0))
            }))
        {
            return Err(DomainError::new("UNSUPPORTED_TRANSFORM", "Linear TRS needs whole-interval evidence and positive-scale TRS keys; raw matrices/shear are never lerped"));
        }
        let mut ticks = Vec::new();
        for (index, key) in track.keys.iter().enumerate() {
            let tick = quantize(
                &key.at,
                &clip,
                &settings.target_tps,
                &format!("{}:key:{index}", track.node_id),
                &mut quantization,
            )?;
            if ticks.last().is_some_and(|previous| *previous >= tick) {
                return Err(DomainError::new(
                    "INVALID_TIME",
                    "Distinct authored keys collapse after tick quantization",
                ));
            }
            ticks.push(tick);
        }
        track_ticks.insert(track.node_id.clone(), ticks);
    }
    if clip
        .tracks
        .iter()
        .any(|track| track.interpolation == Interpolation::LinearTrs)
    {
        verifier.verify_linear_interval(
            target,
            &input_digest,
            &bindings.snapshot.sha256,
            &compiler_digest(),
            &settings.target_tps,
        )?;
    }
    let mut previous_sample = None;
    for (index, at) in clip.sampling.sample_times.iter().enumerate() {
        let tick = quantize(
            at,
            &clip,
            &settings.target_tps,
            &format!("sample:{index}"),
            &mut quantization,
        )?;
        if previous_sample.is_some_and(|previous| previous >= tick) {
            return Err(DomainError::new(
                "INVALID_TIME",
                "Distinct source sampling times collapse after tick quantization",
            ));
        }
        previous_sample = Some(tick);
    }
    let display_count = bindings
        .bindings
        .nodes
        .values()
        .filter(|node| node.display_uuid.is_some())
        .count();
    if display_count == 0
        || (duration_ticks as usize + 1)
            .checked_mul(display_count)
            .is_none_or(|count| count > MAX_POSES)
    {
        return Err(DomainError::new(
            "NUMERIC_RANGE",
            "Generated pose count is absent or exceeds policy",
        ));
    }
    let tracks: BTreeMap<_, _> = clip
        .tracks
        .iter()
        .map(|track| (&track.node_id, track))
        .collect();
    let mut poses = Vec::new();
    for tick in 0..=duration_ticks {
        let mut world: BTreeMap<NodeId, Matrix4> = BTreeMap::new();
        for node_id in &bindings.parent_order {
            let node = &bindings.bindings.nodes[node_id];
            let local = if let Some(track) = tracks.get(node_id) {
                sample(track, &track_ticks[node_id], tick)?
            } else {
                node.rest_local.clone()
            };
            let parent = node.parent.as_ref().map(|id| world[id]).unwrap_or(
                bindings
                    .bindings
                    .instance_world
                    .matrix()
                    .map_err(transform_error)?,
            );
            let composed = parent
                .multiply(&local.matrix().map_err(transform_error)?)
                .map_err(transform_error)?;
            world.insert(node_id.clone(), composed);
            if node.display_uuid.is_some() {
                let mut relative = *composed.values();
                for axis in 0..3 {
                    relative[axis * 4 + 3] -= node.display_origin[axis];
                }
                let mut matrix = [0.0f32; 16];
                let mut error = 0.0f64;
                for (index, component) in relative.iter().enumerate() {
                    matrix[index] = *component as f32;
                    let difference = (*component - f64::from(matrix[index])).abs();
                    if !matrix[index].is_finite()
                        || !difference.is_finite()
                        || difference > settings.max_component_error
                    {
                        return Err(DomainError::new(
                            "NUMERIC_RANGE",
                            "Display f32 component conversion exceeds explicit error policy",
                        ));
                    }
                    error = error.max(difference);
                }
                poses.push(AnimationPose {
                    node_id: node_id.clone(),
                    tick,
                    matrix,
                    max_component_error: error,
                });
            }
        }
    }
    let mut unequal_loop_seam = false;
    if clip.r#loop {
        for node in bindings.bindings.nodes.keys() {
            let initial = poses
                .iter()
                .find(|pose| &pose.node_id == node && pose.tick == 0);
            let final_pose = poses
                .iter()
                .find(|pose| &pose.node_id == node && pose.tick == duration_ticks);
            if initial
                .zip(final_pose)
                .is_some_and(|(first, last)| first.matrix != last.matrix)
            {
                verifier.verify_loop_seam(
                    target,
                    &input_digest,
                    &bindings.snapshot.sha256,
                    &compiler_digest(),
                    &settings.target_tps,
                )?;
                unequal_loop_seam = true;
                break;
            }
        }
    }
    let mut events = Vec::new();
    let mut external_functions = BTreeMap::new();
    let mut event_contracts = BTreeMap::new();
    for event in &clip.events {
        if event.scrub_policy != "suppress" {
            return Err(DomainError::new(
                "UNOWNED_REQUIRED_CAPABILITY",
                "Scrub effects are unsupported",
            ));
        }
        let binding = bindings
            .bindings
            .events
            .get(&event.function_symbol_id)
            .ok_or_else(|| {
                DomainError::new(
                    "REFERENCE_UNRESOLVED",
                    "Event function immutable binding is absent",
                )
            })?;
        let tick = quantize(
            &event.at,
            &clip,
            &settings.target_tps,
            event.event_id.as_str(),
            &mut quantization,
        )?;
        events.push(AnimationScheduledEvent {
            event_id: event.event_id.clone(),
            authored_at: event.at.clone(),
            authored_sequence: event.authored_sequence,
            tick,
            function: binding.function.clone(),
        });
        external_functions.insert(binding.function.clone(), binding.source.reference.clone());
        event_contracts.insert(binding.function.clone(), binding.contract.clone());
    }
    // Quantization can collapse different timestamps. Preserve the authored
    // total order within the emitted tick instead of re-sorting by sequence alone.
    events.sort_by(|a, b| {
        (&a.authored_at, a.authored_sequence).cmp(&(&b.authored_at, b.authored_sequence))
    });
    let identity = canonical_digest(&json!({"clip":input_digest,"bindings":bindings.snapshot.sha256,
        "authority":bindings.authority_digest,"compiler":compiler_digest(),"target":target.profile_digest(),
        "artifact":target.artifact_digest(),"tps":settings.target_tps,"componentError":settings.max_component_error,
        "maxCatchupTicks":settings.max_catchup_ticks,"maxCatchupEvents":settings.max_catchup_events}))
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    let suffix = &identity.as_str()[..24];
    let objective = format!("a{}", &identity.as_str()[..15]);
    if !clip.events.is_empty() {
        verifier.verify_event_functions(
            target.profile_digest(),
            target.artifact_digest(),
            &bindings.bindings.events,
            &objective,
            &format!("mmmm:animation/{suffix}/"),
        )?;
    }
    let mut losses = clip
        .losses
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    if let Some(error) = quantization
        .iter()
        .map(|record| &record.absolute_error)
        .max()
        .filter(|error| !error.is_zero())
    {
        losses.push(json!({"code":"TICK_QUANTIZATION","severity":"warning","subjectId":clip.clip_id,
            "feature":"mmmm:animation/tick_quantization","disposition":"approximated",
            "message":format!("Explicit {:?} target tick policy; maximum exact seconds error {error}; no key/sample collision allowed",clip.sampling.tick_rounding),"approvalRequired":false}));
    }
    let component_error = poses
        .iter()
        .map(|pose| pose.max_component_error)
        .fold(0.0f64, f64::max);
    if component_error > 0.0 {
        losses.push(json!({"code":"DISPLAY_FLOAT32_QUANTIZATION","severity":"warning","subjectId":clip.clip_id,
            "feature":"mmmm:animation/display_matrix","disposition":"approximated",
            "message":format!("Maximum computed matrix component conversion error {component_error} within explicit {} policy; this is not actual game visual/readback evidence",settings.max_component_error),"approvalRequired":false}));
    }
    let mut draft = AnimationDraft {
        resources: BTreeMap::new(),
        contracts: BTreeMap::new(),
        entry_points: BTreeMap::new(),
        external_functions,
        event_contracts,
        line_origins: Vec::new(),
        runtime_dependencies: vec![
            "mmmm:animation_display_matrix_codec".into(),
            "mmmm:animation_zero_interpolation_reset".into(),
            "mmmm:animation_pose_writer_ownership".into(),
            "mmmm:animation_tick_dispatch".into(),
            "mmmm:animation_target_tps".into(),
            "mmmm:animation_bounded_catchup".into(),
        ],
        objective,
        input_digest,
        binding_digest: bindings.snapshot.sha256.clone(),
        authority_digest: bindings.authority_digest.clone(),
        target_profile_digest: target.profile_digest().clone(),
        target_artifact_digest: target.artifact_digest().clone(),
        compiler_digest: compiler_digest(),
        referenced_functions: BTreeSet::new(),
        binding_snapshot: bindings.snapshot.clone(),
        clip_revision: clip.revision.clone(),
        function_calls: BTreeMap::new(),
        owner_prefab_id: clip.owner_prefab_id.clone(),
        scene_projection: AnimationSceneProjection {
            instance_id: bindings.bindings.instance_id.clone(),
            owner_prefab_id: bindings.bindings.owner_prefab_id.clone(),
            world_id: bindings.bindings.world_id.clone(),
            dimension: bindings.bindings.dimension.clone(),
            instance_world: bindings.bindings.instance_world.clone(),
            nodes: bindings.bindings.nodes.clone(),
        },
        target_tps: settings.target_tps.clone(),
        losses,
        max_catchup_ticks: settings.max_catchup_ticks,
        max_catchup_events: settings.max_catchup_events,
        clip_id: clip.clip_id.clone(),
        instance_id: bindings.bindings.instance_id.clone(),
        duration_ticks,
        looping: clip.r#loop,
        poses,
        events,
        quantization,
    };
    if !draft.events.is_empty() {
        draft
            .runtime_dependencies
            .push("mmmm:animation_event_checked_dispatch".into());
    }
    if unequal_loop_seam {
        draft
            .runtime_dependencies
            .push("mmmm:animation_unequal_loop_seam".into());
    }
    if clip
        .tracks
        .iter()
        .any(|track| track.interpolation == Interpolation::LinearTrs)
    {
        draft
            .runtime_dependencies
            .push("mmmm:animation_linear_interval_proof".into());
    }
    emit_functions(&mut draft, bindings, suffix)?;
    Ok(draft)
}

fn quantize(
    at: &RationalTime,
    clip: &AnimationClip,
    tps: &RationalTime,
    object: &str,
    records: &mut Vec<QuantizedTime>,
) -> Result<i32, DomainError> {
    let ticks = at * tps;
    let rounded = match clip.sampling.tick_rounding {
        TickRounding::Exact => {
            if ticks.denominator().as_str() != "1" {
                return Err(DomainError::new(
                    "INVALID_TIME",
                    "Exact tick rounding rejects a fractional target tick",
                ));
            }
            ticks.numerator().to_bigint()
        }
        TickRounding::Floor => ticks.floor(),
        TickRounding::NearestEven => ticks.round_ties_even(),
    };
    let tick: i32 = rounded
        .to_string()
        .parse()
        .map_err(|_| DomainError::new("NUMERIC_RANGE", "Target tick exceeds int32"))?;
    let emitted_seconds = RationalTime::from_integer(tick)
        .checked_div(tps)
        .map_err(|error| DomainError::new("INVALID_TIME", error.to_string()))?;
    let delta = &emitted_seconds - at;
    let absolute_error = if delta.is_negative() {
        delta.negated()
    } else {
        delta
    };
    if absolute_error > exact_nonnegative_f64(clip.sampling.max_time_error_seconds)? {
        return Err(DomainError::new(
            "INVALID_TIME",
            "Tick quantization exceeds the exact declared seconds error budget",
        ));
    }
    records.push(QuantizedTime {
        object_id: object.into(),
        authored: at.clone(),
        tick,
        emitted_seconds,
        absolute_error,
    });
    Ok(tick)
}

fn exact_nonnegative_f64(value: f64) -> Result<RationalTime, DomainError> {
    if !value.is_finite() || value < 0.0 {
        return Err(DomainError::new(
            "INVALID_TIME",
            "Error budget must be finite and nonnegative",
        ));
    }
    if value == 0.0 {
        return Ok(RationalTime::zero());
    }
    let bits = value.to_bits();
    let exponent_bits = ((bits >> 52) & 0x7ff) as i32;
    let mantissa = (bits & ((1u64 << 52) - 1)) | if exponent_bits == 0 { 0 } else { 1u64 << 52 };
    let exponent = if exponent_bits == 0 {
        -1074
    } else {
        exponent_bits - 1023 - 52
    };
    let mut numerator = RationalTime::from_integer(mantissa).numerator().to_bigint();
    let mut denominator = RationalTime::one().numerator().to_bigint();
    let power = RationalTime::from_integer(2)
        .numerator()
        .to_bigint()
        .pow(exponent.unsigned_abs());
    if exponent >= 0 {
        numerator *= power;
    } else {
        denominator = power;
    }
    RationalTime::from_integers(numerator, denominator)
        .map_err(|error| DomainError::new("INVALID_TIME", error.to_string()))
}

fn sample(track: &AnimationTrack, ticks: &[i32], tick: i32) -> Result<Transform, DomainError> {
    let upper = ticks.partition_point(|at| *at <= tick);
    if upper == 0 {
        return Ok(track.keys[0].transform.clone());
    }
    if upper == ticks.len() || track.interpolation != Interpolation::LinearTrs {
        return Ok(track.keys[upper - 1].transform.clone());
    }
    let left = upper - 1;
    let alpha = f64::from(tick - ticks[left]) / f64::from(ticks[upper] - ticks[left]);
    let (
        Transform::Trs {
            translation: a_t,
            rotation_xyzw: a_r,
            scale: a_s,
        },
        Transform::Trs {
            translation: b_t,
            rotation_xyzw: b_r,
            scale: b_s,
        },
    ) = (&track.keys[left].transform, &track.keys[upper].transform)
    else {
        return Err(DomainError::new(
            "UNSUPPORTED_TRANSFORM",
            "Raw matrix interpolation is unsupported",
        ));
    };
    let translation = std::array::from_fn(|i| a_t[i] + (b_t[i] - a_t[i]) * alpha);
    let scale = std::array::from_fn(|i| a_s[i] + (b_s[i] - a_s[i]) * alpha);
    let mut end = *b_r;
    let mut dot: f64 = a_r.iter().zip(end).map(|(a, b)| *a * b).sum();
    if dot < 0.0 {
        end = end.map(|v| -v);
        dot = -dot;
    }
    let mut rotation_xyzw = if dot > 0.9995 {
        std::array::from_fn(|i| a_r[i] + (end[i] - a_r[i]) * alpha)
    } else {
        let angle = dot.clamp(-1.0, 1.0).acos();
        let divisor = angle.sin();
        let left_weight = ((1.0 - alpha) * angle).sin() / divisor;
        let right_weight = (alpha * angle).sin() / divisor;
        std::array::from_fn(|i| a_r[i] * left_weight + end[i] * right_weight)
    };
    // This normalization is an explicit verified interpolation algorithm;
    // authored endpoint quaternions are validated and never silently repaired.
    let norm = rotation_xyzw.iter().map(|v| v * v).sum::<f64>().sqrt();
    for value in &mut rotation_xyzw {
        *value /= norm;
    }
    let transform = Transform::Trs {
        translation,
        rotation_xyzw,
        scale,
    };
    transform.validate().map_err(transform_error)?;
    Ok(transform)
}

fn parent_order(
    nodes: &BTreeMap<NodeId, AnimationNodeBinding>,
) -> Result<Vec<NodeId>, DomainError> {
    let mut order = Vec::new();
    let mut emitted = BTreeSet::new();
    while order.len() < nodes.len() {
        let previous = order.len();
        for (id, node) in nodes {
            if emitted.contains(id) {
                continue;
            }
            if node
                .parent
                .as_ref()
                .is_some_and(|parent| !nodes.contains_key(parent))
            {
                return Err(DomainError::new(
                    "REFERENCE_UNRESOLVED",
                    "Animation parent binding is absent",
                ));
            }
            if node
                .parent
                .as_ref()
                .is_none_or(|parent| emitted.contains(parent))
            {
                emitted.insert(id.clone());
                order.push(id.clone());
            }
        }
        if order.len() == previous {
            return Err(DomainError::new(
                "REFERENCE_UNRESOLVED",
                "Animation parent bindings contain a cycle",
            ));
        }
    }
    Ok(order)
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}
fn transform_error(error: mmmm_domain::transform::TransformError) -> DomainError {
    DomainError::new(error.code(), error.to_string())
}

struct FunctionLines {
    id: ResourceLocation,
    lines: Vec<String>,
    origins: Vec<AnimationLineOrigin>,
}
impl FunctionLines {
    fn push(
        &mut self,
        text: String,
        clip: &ClipId,
        node: Option<NodeId>,
        event: Option<ObjectId>,
        tick: Option<i32>,
    ) -> Result<(), DomainError> {
        if text.len() > MAX_COMMAND_BYTES || text.contains(['\r', '\n', '\0']) {
            return Err(DomainError::new(
                "NUMERIC_RANGE",
                "Generated animation command exceeds line policy",
            ));
        }
        self.origins.push(AnimationLineOrigin {
            function: self.id.clone(),
            line: self.lines.len() + 1,
            source_object_id: clip.to_string(),
            node_id: node,
            event_id: event,
            tick,
        });
        self.lines.push(text);
        Ok(())
    }
}

fn checked_event(
    lines: &mut FunctionLines,
    event: &AnimationScheduledEvent,
    event_index: usize,
    condition: &str,
    objective: &str,
    fault: &ResourceLocation,
    clip: &ClipId,
) -> Result<(), DomainError> {
    let prefix = if condition.is_empty() {
        "execute ".to_owned()
    } else {
        format!("execute {condition} ")
    };
    let mut push = |command: String| {
        lines.push(
            command,
            clip,
            None,
            Some(event.event_id.clone()),
            Some(event.tick),
        )
    };
    push(format!(
        "{prefix}run scoreboard players set #event_index {objective} {event_index}"
    ))?;
    push(format!(
        "{prefix}run scoreboard players operation #event_run {objective} = #run {objective}"
    ))?;
    push(format!(
        "{prefix}run scoreboard players operation #event_iteration {objective} = #iteration {objective}"
    ))?;
    push(format!(
        "{prefix}run scoreboard players set #event_ok {objective} 0"
    ))?;
    push(format!(
        "{prefix}run scoreboard players set #tainted {objective} 1"
    ))?;
    push(format!(
        "{prefix}store result score #event_ok {objective} run function {}",
        event.function
    ))?;
    // Any partial/unknown event retains tainted. No control can erase it, and
    // the crossing baseline is not published. Recovery requires the host's
    // independent event-effect evidence, never an automatic resend.
    push(format!(
        "execute if score #tainted {objective} matches 1 unless score #event_ok {objective} matches 1 run function {fault}"
    ))?;
    push(format!(
        "execute if score #tainted {objective} matches 1 unless score #playing {objective} matches 1 run function {fault}"
    ))?;
    push(format!(
        "execute if score #tainted {objective} matches 1 unless score #busy {objective} matches 1 run function {fault}"
    ))?;
    push(format!(
        "execute unless score #error {objective} matches 0 run return 0"
    ))?;
    push(format!(
        "execute if score #tainted {objective} matches 1 run scoreboard players set #tainted {objective} 0"
    ))?;
    Ok(())
}

fn emit_functions(
    draft: &mut AnimationDraft,
    bindings: &VerifiedAnimationBindings,
    suffix: &str,
) -> Result<(), DomainError> {
    let name = |part: &str| {
        ResourceLocation::new(format!("mmmm:animation/{suffix}/{part}"))
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))
    };
    let mut all = BTreeMap::new();
    for part in [
        "init",
        "play",
        "resume",
        "tick",
        "catch_up",
        "catchup_step",
        "advance",
        "pose",
        "scrub",
        "stop",
        "cleanup",
        "fault",
        "loop_boundary",
    ] {
        let id = name(part)?;
        all.insert(
            part.to_owned(),
            FunctionLines {
                id,
                lines: Vec::new(),
                origins: Vec::new(),
            },
        );
    }
    let ids: BTreeMap<_, _> = all
        .iter()
        .map(|(part, lines)| (part.clone(), lines.id.clone()))
        .collect();
    // Typed emission adjacency, retaining repeated conditional call sites for
    // conservative expanded-call budgeting. No untrusted function text is parsed.
    for (part, calls) in [
        ("init", vec![ids["pose"].clone()]),
        ("play", vec![ids["fault"].clone(), ids["advance"].clone()]),
        ("resume", vec![]),
        ("tick", vec![ids["fault"].clone(), ids["catch_up"].clone()]),
        (
            "catchup_step",
            vec![ids["fault"].clone(), ids["advance"].clone()],
        ),
        ("pose", vec![]),
        ("scrub", vec![ids["pose"].clone()]),
        ("stop", vec![]),
        ("cleanup", vec![ids["stop"].clone()]),
        ("fault", vec![ids["stop"].clone()]),
    ] {
        draft.function_calls.insert(ids[part].clone(), calls);
    }
    let mut catchup_calls = vec![ids["fault"].clone(); if draft.looping { 17 } else { 13 }];
    catchup_calls.extend(vec![
        ids["catchup_step"].clone();
        usize::from(draft.max_catchup_ticks)
    ]);
    draft
        .function_calls
        .insert(ids["catch_up"].clone(), catchup_calls);
    let mut advance_calls = vec![ids["fault"].clone(); if draft.looping { 18 } else { 15 }];
    advance_calls.push(ids["pose"].clone());
    for event in &draft.events {
        advance_calls.push(event.function.clone());
        advance_calls.extend(vec![ids["fault"].clone(); 3]);
    }
    if draft.looping {
        advance_calls.push(ids["loop_boundary"].clone());
        let mut loop_calls = Vec::new();
        loop_calls.push(ids["pose"].clone());
        for event in draft.events.iter().filter(|event| event.tick == 0) {
            loop_calls.push(event.function.clone());
            loop_calls.extend(vec![ids["fault"].clone(); 3]);
        }
        draft
            .function_calls
            .insert(ids["loop_boundary"].clone(), loop_calls);
    }
    draft
        .function_calls
        .insert(ids["advance"].clone(), advance_calls);
    draft.referenced_functions.extend(
        [
            "pose",
            "advance",
            "fault",
            "stop",
            "catch_up",
            "catchup_step",
        ]
        .iter()
        .map(|part| ids[*part].clone()),
    );
    if draft.looping {
        draft
            .referenced_functions
            .insert(ids["loop_boundary"].clone());
    }
    draft
        .referenced_functions
        .extend(draft.external_functions.keys().cloned());
    let objective = draft.objective.clone();
    let clip = draft.clip_id.clone();
    let duration = draft.duration_ticks;
    macro_rules! line {
        ($part:expr,$text:expr) => {
            all.get_mut($part)
                .expect("known function")
                .push($text, &clip, None, None, None)?
        };
    }
    // Initialization is only for an absent owned objective, independently
    // checked by the installer. A valid existing run is never reset by init.
    line!(
        "init",
        format!("execute if score #run {objective} matches -2147483648..2147483647 run return 0")
    );
    line!(
        "init",
        format!("scoreboard objectives add {objective} dummy")
    );
    for holder in [
        "#cursor",
        "#from",
        "#playing",
        "#iteration",
        "#run",
        "#error",
        "#seek",
        "#busy",
        "#tainted",
        "#event_ok",
        "#crossed_end",
        "#event_index",
        "#event_run",
        "#event_iteration",
        "#elapsed",
        "#elapsed_request",
        "#remaining",
        "#candidate_events",
        "#delta",
        "#room",
        "#base",
        "#possible_seams",
        "#iteration_room",
    ] {
        line!(
            "init",
            format!("scoreboard players set {holder} {objective} 0")
        );
    }
    line!(
        "init",
        format!("scoreboard players set #i32max {objective} 2147483647")
    );
    line!(
        "init",
        format!(
            "scoreboard players set #event_count {objective} {}",
            draft.events.len()
        )
    );
    line!(
        "init",
        format!("scoreboard players set #period {objective} {duration}")
    );
    line!("init", format!("function {}", ids["pose"]));
    for part in ["play", "resume", "tick", "scrub"] {
        line!(
            part,
            format!("execute unless score #tainted {objective} matches 0 run return 0")
        );
        line!(
            part,
            format!("execute unless score #busy {objective} matches 0 run return 0")
        );
    }
    line!(
        "play",
        format!(
            "execute if score #run {objective} matches 2147483647 run function {}",
            ids["fault"]
        )
    );
    line!(
        "play",
        format!("execute unless score #run {objective} matches 0..2147483646 run return 0")
    );
    line!("play", format!("scoreboard players add #run {objective} 1"));
    for (holder, value) in [
        ("#cursor", 0),
        ("#from", -1),
        ("#playing", 1),
        ("#iteration", 0),
        ("#error", 0),
        ("#elapsed", 0),
        ("#elapsed_request", 0),
    ] {
        line!(
            "play",
            format!("scoreboard players set {holder} {objective} {value}")
        );
    }
    line!("play", format!("function {}", ids["advance"]));
    for part in ["resume", "tick"] {
        line!(
            part,
            format!("execute unless score #run {objective} matches 1..2147483647 run return 0")
        );
        line!(
            part,
            format!(
                "execute unless score #iteration {objective} matches 0..2147483647 run return 0"
            )
        );
        line!(
            part,
            format!("execute unless score #error {objective} matches 0 run return 0")
        );
    }
    line!(
        "resume",
        format!(
            "execute unless score #cursor {objective} matches 0..{} run return 0",
            duration - 1
        )
    );
    line!(
        "resume",
        format!("scoreboard players set #playing {objective} 1")
    );
    line!(
        "tick",
        format!("execute unless score #playing {objective} matches 1 run return 0")
    );
    line!(
        "tick",
        format!(
            "execute unless score #elapsed {objective} matches 0..2147483646 run function {}",
            ids["fault"]
        )
    );
    line!(
        "tick",
        format!("execute unless score #error {objective} matches 0 run return 0")
    );
    line!(
        "tick",
        format!("scoreboard players operation #elapsed_request {objective} = #elapsed {objective}")
    );
    line!(
        "tick",
        format!("scoreboard players add #elapsed_request {objective} 1")
    );
    line!("tick", format!("function {}", ids["catch_up"]));
    line!(
        "catch_up",
        format!("execute unless score #playing {objective} matches 1 run return 0")
    );
    line!(
        "catch_up",
        format!("execute unless score #tainted {objective} matches 0 run return 0")
    );
    line!(
        "catch_up",
        format!(
            "execute unless score #busy {objective} matches 0 run function {}",
            ids["fault"]
        )
    );
    line!(
        "catch_up",
        format!(
            "execute unless score #run {objective} matches 1..2147483647 run function {}",
            ids["fault"]
        )
    );
    line!(
        "catch_up",
        format!(
            "execute unless score #iteration {objective} matches 0..2147483647 run function {}",
            ids["fault"]
        )
    );
    line!(
        "catch_up",
        format!(
            "execute unless score #elapsed {objective} matches 0..2147483647 run function {}",
            ids["fault"]
        )
    );
    line!(
        "catch_up",
        format!(
            "execute unless score #elapsed_request {objective} matches 0..2147483647 run function {}",
            ids["fault"]
        )
    );
    line!(
        "catch_up",
        format!(
            "execute if score #elapsed_request {objective} < #elapsed {objective} run function {}",
            ids["fault"]
        )
    );
    line!(
        "catch_up",
        format!(
            "execute unless score #cursor {objective} = #from {objective} run function {}",
            ids["fault"]
        )
    );
    line!(
        "catch_up",
        format!(
            "execute unless score #event_count {objective} matches {} run function {}",
            draft.events.len(),
            ids["fault"]
        )
    );
    line!(
        "catch_up",
        format!(
            "execute unless score #i32max {objective} matches 2147483647 run function {}",
            ids["fault"]
        )
    );
    line!(
        "catch_up",
        format!("execute unless score #error {objective} matches 0 run return 0")
    );
    line!(
        "catch_up",
        format!(
            "scoreboard players operation #remaining {objective} = #elapsed_request {objective}"
        )
    );
    line!(
        "catch_up",
        format!("scoreboard players operation #remaining {objective} -= #elapsed {objective}")
    );
    line!(
        "catch_up",
        format!(
            "execute unless score #remaining {objective} matches 0..{} run function {}",
            draft.max_catchup_ticks, ids["fault"]
        )
    );
    line!(
        "catch_up",
        format!("execute unless score #error {objective} matches 0 run return 0")
    );
    line!(
        "catch_up",
        format!(
            "scoreboard players operation #candidate_events {objective} = #remaining {objective}"
        )
    );
    line!(
        "catch_up",
        format!(
            "scoreboard players operation #candidate_events {objective} *= #event_count {objective}"
        )
    );
    line!(
        "catch_up",
        format!(
            "execute unless score #candidate_events {objective} matches 0..{} run function {}",
            draft.max_catchup_events, ids["fault"]
        )
    );
    if !draft.looping {
        line!(
            "catch_up",
            format!(
                "execute unless score #elapsed_request {objective} matches 0..{duration} run function {}",
                ids["fault"]
            )
        );
        line!(
            "catch_up",
            format!(
                "execute unless score #elapsed {objective} = #cursor {objective} run function {}",
                ids["fault"]
            )
        );
    } else {
        line!(
            "catch_up",
            format!(
                "execute unless score #cursor {objective} matches 0..{} run function {}",
                duration - 1,
                ids["fault"]
            )
        );
        line!(
            "catch_up",
            format!(
                "execute unless score #period {objective} matches {duration} run function {}",
                ids["fault"]
            )
        );
        line!(
            "catch_up",
            format!("execute unless score #error {objective} matches 0 run return 0")
        );
        line!(
            "catch_up",
            format!(
                "execute if score #elapsed {objective} < #cursor {objective} run function {}",
                ids["fault"]
            )
        );
        line!(
            "catch_up",
            format!("execute unless score #error {objective} matches 0 run return 0")
        );
        line!(
            "catch_up",
            format!("scoreboard players operation #base {objective} = #elapsed {objective}")
        );
        line!(
            "catch_up",
            format!("scoreboard players operation #base {objective} -= #cursor {objective}")
        );
        line!(
            "catch_up",
            format!("scoreboard players operation #possible_seams {objective} = #base {objective}")
        );
        line!(
            "catch_up",
            format!(
                "scoreboard players operation #possible_seams {objective} /= #period {objective}"
            )
        );
        line!(
            "catch_up",
            format!(
                "execute unless score #possible_seams {objective} = #iteration {objective} run function {}",
                ids["fault"]
            )
        );
        line!(
            "catch_up",
            format!(
                "scoreboard players operation #possible_seams {objective} *= #period {objective}"
            )
        );
        line!(
            "catch_up",
            format!(
                "execute unless score #possible_seams {objective} = #base {objective} run function {}",
                ids["fault"]
            )
        );
        line!(
            "catch_up",
            format!("execute unless score #error {objective} matches 0 run return 0")
        );
        line!(
            "catch_up",
            format!(
                "scoreboard players operation #possible_seams {objective} = #cursor {objective}"
            )
        );
        line!(
            "catch_up",
            format!(
                "scoreboard players operation #possible_seams {objective} += #remaining {objective}"
            )
        );
        line!(
            "catch_up",
            format!(
                "scoreboard players operation #possible_seams {objective} /= #period {objective}"
            )
        );
        line!(
            "catch_up",
            format!(
                "scoreboard players operation #iteration_room {objective} = #i32max {objective}"
            )
        );
        line!(
            "catch_up",
            format!(
                "scoreboard players operation #iteration_room {objective} -= #iteration {objective}"
            )
        );
        line!(
            "catch_up",
            format!(
                "execute if score #iteration_room {objective} < #possible_seams {objective} run function {}",
                ids["fault"]
            )
        );
    }
    line!(
        "catch_up",
        format!("execute unless score #error {objective} matches 0 run return 0")
    );
    // Finite unrolling avoids an immediate function-call cycle. Pack validation
    // charges every possible call site before admission; no runtime recursion.
    for _ in 0..draft.max_catchup_ticks {
        line!(
            "catch_up",
            format!(
                "execute if score #remaining {objective} matches 1..{} if score #playing {objective} matches 1 run function {}",
                draft.max_catchup_ticks, ids["catchup_step"]
            )
        );
    }
    line!(
        "catchup_step",
        format!(
            "execute unless score #remaining {objective} matches 1..{} run return 0",
            draft.max_catchup_ticks
        )
    );
    line!(
        "catchup_step",
        format!("execute unless score #playing {objective} matches 1 run return 0")
    );
    line!(
        "catchup_step",
        format!(
            "execute unless score #cursor {objective} matches 0..{} run function {}",
            duration - 1,
            ids["fault"]
        )
    );
    line!(
        "catchup_step",
        format!("execute unless score #error {objective} matches 0 run return 0")
    );
    line!(
        "catchup_step",
        format!("scoreboard players add #cursor {objective} 1")
    );
    line!("catchup_step", format!("function {}", ids["advance"]));
    line!(
        "catchup_step",
        format!("execute unless score #error {objective} matches 0 run return 0")
    );
    line!(
        "catchup_step",
        format!("scoreboard players add #remaining {objective} -1")
    );
    line!(
        "advance",
        format!("execute unless score #playing {objective} matches 1 run return 0")
    );
    line!(
        "advance",
        format!("execute unless score #tainted {objective} matches 0 run return 0")
    );
    line!(
        "advance",
        format!(
            "execute unless score #busy {objective} matches 0 run function {}",
            ids["fault"]
        )
    );
    line!(
        "advance",
        format!(
            "execute unless score #run {objective} matches 1..2147483647 run function {}",
            ids["fault"]
        )
    );
    line!(
        "advance",
        format!(
            "execute unless score #iteration {objective} matches 0..2147483647 run function {}",
            ids["fault"]
        )
    );
    line!(
        "advance",
        format!(
            "execute unless score #cursor {objective} matches 0..{duration} run function {}",
            ids["fault"]
        )
    );
    line!(
        "advance",
        format!(
            "execute unless score #from {objective} matches -1..{duration} run function {}",
            ids["fault"]
        )
    );
    line!(
        "advance",
        format!(
            "execute if score #cursor {objective} < #from {objective} run function {}",
            ids["fault"]
        )
    );
    if draft.looping {
        line!(
            "advance",
            format!(
                "execute if score #cursor {objective} matches {duration} if score #iteration {objective} matches 2147483647 run function {}",
                ids["fault"]
            )
        );
    }
    line!(
        "advance",
        format!("execute unless score #error {objective} matches 0 run return 0")
    );
    line!(
        "advance",
        format!(
            "execute unless score #elapsed {objective} matches 0..2147483647 run function {}",
            ids["fault"]
        )
    );
    line!(
        "advance",
        format!(
            "execute unless score #i32max {objective} matches 2147483647 run function {}",
            ids["fault"]
        )
    );
    for (holder, expected) in [("#iteration", 0), ("#elapsed", 0), ("#cursor", 0)] {
        line!(
            "advance",
            format!(
                "execute if score #from {objective} matches -1 unless score {holder} {objective} matches {expected} run function {}",
                ids["fault"]
            )
        );
    }
    if draft.looping {
        line!(
            "advance",
            format!(
                "execute unless score #period {objective} matches {duration} run function {}",
                ids["fault"]
            )
        );
        line!(
            "advance",
            format!(
                "execute if score #from {objective} matches 0..{duration} if score #elapsed {objective} < #from {objective} run function {}",
                ids["fault"]
            )
        );
        line!(
            "advance",
            format!("execute unless score #error {objective} matches 0 run return 0")
        );
        let committed = format!("execute if score #from {objective} matches 0..{duration}");
        line!(
            "advance",
            format!(
                "{committed} run scoreboard players operation #base {objective} = #elapsed {objective}"
            )
        );
        line!(
            "advance",
            format!(
                "{committed} run scoreboard players operation #base {objective} -= #from {objective}"
            )
        );
        line!(
            "advance",
            format!(
                "{committed} run scoreboard players operation #possible_seams {objective} = #base {objective}"
            )
        );
        line!(
            "advance",
            format!(
                "{committed} run scoreboard players operation #possible_seams {objective} /= #period {objective}"
            )
        );
        line!(
            "advance",
            format!(
                "{committed} unless score #possible_seams {objective} = #iteration {objective} run function {}",
                ids["fault"]
            )
        );
        line!(
            "advance",
            format!(
                "{committed} run scoreboard players operation #possible_seams {objective} *= #period {objective}"
            )
        );
        line!(
            "advance",
            format!(
                "{committed} unless score #possible_seams {objective} = #base {objective} run function {}",
                ids["fault"]
            )
        );
    } else {
        line!(
            "advance",
            format!(
                "execute unless score #iteration {objective} matches 0 run function {}",
                ids["fault"]
            )
        );
        line!(
            "advance",
            format!(
                "execute if score #from {objective} matches 0..{duration} unless score #elapsed {objective} = #from {objective} run function {}",
                ids["fault"]
            )
        );
    }
    line!(
        "advance",
        format!("execute unless score #error {objective} matches 0 run return 0")
    );
    line!(
        "advance",
        format!("scoreboard players set #delta {objective} 0")
    );
    line!(
        "advance",
        format!(
            "execute if score #from {objective} matches 0..{duration} run scoreboard players operation #delta {objective} = #cursor {objective}"
        )
    );
    line!(
        "advance",
        format!(
            "execute if score #from {objective} matches 0..{duration} run scoreboard players operation #delta {objective} -= #from {objective}"
        )
    );
    line!(
        "advance",
        format!(
            "execute unless score #delta {objective} matches 0..{duration} run function {}",
            ids["fault"]
        )
    );
    line!(
        "advance",
        format!("scoreboard players operation #room {objective} = #i32max {objective}")
    );
    line!(
        "advance",
        format!("scoreboard players operation #room {objective} -= #elapsed {objective}")
    );
    line!(
        "advance",
        format!(
            "execute if score #room {objective} < #delta {objective} run function {}",
            ids["fault"]
        )
    );
    line!(
        "advance",
        format!("execute unless score #error {objective} matches 0 run return 0")
    );
    line!(
        "advance",
        format!("scoreboard players set #busy {objective} 1")
    );
    line!(
        "advance",
        format!("scoreboard players set #crossed_end {objective} 0")
    );
    line!(
        "advance",
        format!(
            "execute if score #from {objective} matches -1..{} if score #cursor {objective} matches {duration} run scoreboard players set #crossed_end {objective} 1",
            duration - 1
        )
    );
    line!("advance", format!("function {}", ids["pose"]));
    for (event_index, event) in draft.events.iter().enumerate() {
        let range = if event.tick == 0 {
            "-1".into()
        } else {
            format!("-1..{}", event.tick - 1)
        };
        checked_event(
            all.get_mut("advance").unwrap(),
            event,
            event_index,
            &format!(
                "if score #from {objective} matches {range} if score #cursor {objective} matches {}..{duration}",
                event.tick
            ),
            &objective,
            &ids["fault"],
            &clip,
        )?;
    }
    line!(
        "advance",
        format!("scoreboard players operation #elapsed {objective} += #delta {objective}")
    );
    line!(
        "advance",
        format!("scoreboard players operation #from {objective} = #cursor {objective}")
    );
    if draft.looping {
        line!(
            "advance",
            format!(
                "execute if score #crossed_end {objective} matches 1 run function {}",
                ids["loop_boundary"]
            )
        );
        line!(
            "loop_boundary",
            format!("execute unless score #busy {objective} matches 1 run return 0")
        );
        line!(
            "loop_boundary",
            format!("execute unless score #tainted {objective} matches 0 run return 0")
        );
        line!(
            "loop_boundary",
            format!("execute unless score #crossed_end {objective} matches 1 run return 0")
        );
        line!(
            "loop_boundary",
            format!("execute unless score #from {objective} matches {duration} run return 0")
        );
        line!(
            "loop_boundary",
            format!("execute unless score #cursor {objective} matches {duration} run return 0")
        );
        line!(
            "loop_boundary",
            format!("execute unless score #error {objective} matches 0 run return 0")
        );
        line!(
            "loop_boundary",
            format!("scoreboard players add #iteration {objective} 1")
        );
        line!(
            "loop_boundary",
            format!("scoreboard players set #cursor {objective} 0")
        );
        line!(
            "loop_boundary",
            format!("scoreboard players set #from {objective} 0")
        );
        line!("loop_boundary", format!("function {}", ids["pose"]));
        // Old iteration D events precede new iteration 0 events. They are
        // different occurrences even with identical authored sequence values.
        for (event_index, event) in draft
            .events
            .iter()
            .enumerate()
            .filter(|(_, event)| event.tick == 0)
        {
            checked_event(
                all.get_mut("loop_boundary").unwrap(),
                event,
                event_index,
                "",
                &objective,
                &ids["fault"],
                &clip,
            )?;
        }
    } else {
        line!(
            "advance",
            format!(
                "execute if score #cursor {objective} matches {duration} run scoreboard players set #playing {objective} 0"
            )
        );
    }
    line!(
        "advance",
        format!("scoreboard players set #busy {objective} 0")
    );
    for pose in &draft.poses {
        let uuid = bindings.bindings.nodes[&pose.node_id]
            .display_uuid
            .as_ref()
            .expect("display pose");
        let matrix = pose
            .matrix
            .iter()
            .map(|value| format!("{value}f"))
            .collect::<Vec<_>>()
            .join(",");
        all.get_mut("pose").unwrap().push(format!("execute in {} if score #cursor {objective} matches {} run data merge entity {uuid} {{interpolation_duration:0,start_interpolation:0,transformation:[{matrix}]}}",bindings.bindings.dimension,pose.tick),&clip,Some(pose.node_id.clone()),None,Some(pose.tick))?;
    }
    line!(
        "scrub",
        format!("execute unless score #seek {objective} matches 0..{duration} run return 0")
    );
    line!(
        "scrub",
        format!("execute unless score #elapsed {objective} matches 0..2147483647 run return 0")
    );
    line!(
        "scrub",
        format!("execute unless score #cursor {objective} matches 0..{duration} run return 0")
    );
    line!(
        "scrub",
        format!("execute unless score #i32max {objective} matches 2147483647 run return 0")
    );
    line!(
        "scrub",
        format!("execute if score #elapsed {objective} < #cursor {objective} run return 0")
    );
    line!(
        "scrub",
        format!("scoreboard players operation #base {objective} = #elapsed {objective}")
    );
    line!(
        "scrub",
        format!("scoreboard players operation #base {objective} -= #cursor {objective}")
    );
    line!(
        "scrub",
        format!("scoreboard players operation #room {objective} = #i32max {objective}")
    );
    line!(
        "scrub",
        format!("scoreboard players operation #room {objective} -= #base {objective}")
    );
    line!(
        "scrub",
        format!("execute if score #room {objective} < #seek {objective} run return 0")
    );
    line!(
        "scrub",
        format!("scoreboard players operation #elapsed {objective} = #base {objective}")
    );
    line!(
        "scrub",
        format!("scoreboard players operation #elapsed {objective} += #seek {objective}")
    );
    line!(
        "scrub",
        format!("scoreboard players operation #elapsed_request {objective} = #elapsed {objective}")
    );
    line!(
        "scrub",
        format!("scoreboard players set #remaining {objective} 0")
    );
    line!(
        "scrub",
        format!("scoreboard players set #playing {objective} 0")
    );
    line!(
        "scrub",
        format!("scoreboard players set #error {objective} 0")
    );
    line!(
        "scrub",
        format!("scoreboard players operation #cursor {objective} = #seek {objective}")
    );
    line!(
        "scrub",
        format!("scoreboard players operation #from {objective} = #seek {objective}")
    );
    line!("scrub", format!("function {}", ids["pose"]));
    line!(
        "stop",
        format!("scoreboard players set #playing {objective} 0")
    );
    for node in bindings
        .bindings
        .nodes
        .values()
        .filter(|node| node.display_uuid.is_some())
    {
        let uuid = node.display_uuid.as_ref().unwrap();
        line!(
            "stop",
            format!(
                "execute in {} run data merge entity {uuid} {{interpolation_duration:0,start_interpolation:0}}",
                bindings.bindings.dimension
            )
        );
    }
    line!(
        "fault",
        format!("scoreboard players set #error {objective} 1")
    );
    line!(
        "fault",
        format!("scoreboard players set #busy {objective} 0")
    );
    line!("fault", format!("function {}", ids["stop"]));
    line!("cleanup", format!("function {}", ids["stop"]));
    line!(
        "cleanup",
        format!("execute unless score #tainted {objective} matches 0 run return 0")
    );
    line!(
        "cleanup",
        format!("execute unless score #busy {objective} matches 0 run return 0")
    );
    line!(
        "cleanup",
        format!("scoreboard objectives remove {objective}")
    );
    let mut total = 0usize;
    for (part, lines) in all {
        if lines.lines.is_empty() {
            continue;
        }
        let bytes = (lines.lines.join("\n") + "\n").into_bytes();
        total = total
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_SOURCE_BYTES)
            .ok_or_else(|| {
                DomainError::new(
                    "NUMERIC_RANGE",
                    "Generated animation source budget exceeded",
                )
            })?;
        let source = StagedResource::new(
            ResourceId::new(format!("animation-source:{suffix}:{part}"))
                .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?,
            "text/x-mcfunction; charset=utf-8",
            bytes,
        );
        let event_effects = matches!(
            part.as_str(),
            "advance" | "play" | "tick" | "catch_up" | "catchup_step" | "loop_boundary"
        );
        let mut state_reads = BTreeSet::from([format!("score:*:{objective}")]);
        let mut state_writes = BTreeSet::from([format!("score:*:{objective}")]);
        let mut input_symbols = BTreeSet::new();
        let mut output_symbols = BTreeSet::new();
        let mut scheduled = BTreeSet::new();
        if matches!(
            part.as_str(),
            "pose"
                | "advance"
                | "play"
                | "tick"
                | "catch_up"
                | "catchup_step"
                | "scrub"
                | "stop"
                | "cleanup"
                | "fault"
                | "init"
        ) {
            state_writes.extend(
                bindings
                    .bindings
                    .nodes
                    .values()
                    .filter_map(|node| node.display_uuid.as_ref())
                    .map(|uuid| format!("entity:{uuid}:display_transform")),
            );
        }
        let mut requirements = vec![
            "exact target display matrix/reset readback and visual proof".into(),
            "owned fixed-origin display UUIDs loaded at execution; one pose writer".into(),
            "serialized server tick invocation; target TPS selected by separate authorized plan"
                .into(),
            "same-iteration local advance or bounded absolute multi-period catch_up; rewind requires explicit scrub or restart"
                .into(),
        ];
        requirements.push("initialization only after host confirms absent owned objective; tainted event state retained for independent recovery".into());
        requirements.push(format!("catch_up consumes a fresh absolute #elapsed_request from a committed cursor/from/iteration/elapsed baseline; at most {} ticks and conservative remaining*event_count <= {} before any effect; backward requests fail; successful scrub resets the pending request",draft.max_catchup_ticks,draft.max_catchup_events));
        requirements.push("game score/entity/event crash consistency is not established by generated source; retain event index/run/iteration for independent recovery evidence".into());
        if event_effects {
            requirements.push("event exact-return-1 witness and private-state/reentrancy exclusion verified; crossing is not independent proof of successful game effects".into());
            for contract in draft.event_contracts.values() {
                input_symbols.extend(contract.inputs.iter().cloned());
                output_symbols.extend(contract.outputs.iter().cloned());
                state_reads.extend(contract.state_reads.iter().cloned());
                state_writes.extend(contract.state_writes.iter().cloned());
                scheduled.extend(contract.scheduled_callbacks.iter().cloned());
                requirements.extend(contract.requirements.iter().cloned());
            }
        }
        if part == "tick" {
            scheduled.insert(ids["tick"].to_string());
        }
        let contract = GeneratedFunctionContract {
            inputs: input_symbols.into_iter().collect(),
            outputs: output_symbols.into_iter().collect(),
            state_reads: state_reads.into_iter().collect(),
            state_writes: state_writes.into_iter().collect(),
            execution_context: "server; owned fixed-origin display UUIDs",
            reentrancy: "serialized_per_instance_clip_with_busy_guard",
            scheduled_callbacks: scheduled.into_iter().collect(),
            cleanup: vec![ids["cleanup"].to_string()],
            requirements,
        };
        draft.line_origins.extend(lines.origins);
        draft.contracts.insert(lines.id.clone(), contract);
        draft.resources.insert(lines.id.clone(), source);
        if matches!(
            part.as_str(),
            "init"
                | "play"
                | "resume"
                | "tick"
                | "catch_up"
                | "advance"
                | "scrub"
                | "stop"
                | "cleanup"
        ) {
            draft.entry_points.insert(part, lines.id);
        }
    }
    if draft
        .external_functions
        .keys()
        .any(|id| draft.resources.contains_key(id))
    {
        return Err(DomainError::new(
            "ID_COLLISION",
            "Event function identifier collides with generated private function",
        ));
    }
    Ok(())
}
#[cfg(test)]
#[path = "animation_tests.rs"]
mod tests;

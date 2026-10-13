//! FN27 verifies bytes and semantic constraints before returning an immutable
//! bake artifact. A completed job, evaluated pose and mesh identity are separate
//! observations; caller-supplied booleans are never verification authority.
use crate::archive::ArchiveLimits;
use crate::coordinates::CoordinateSystem;
use crate::manifest::{InspectedBundle, collect_resources, inspect_resource};
use crate::resources::{ResourcePort, ResourcePurpose, parse_resource, read_resource};
use crate::selection::Selection;
use crate::{ExchangeError, ExchangeResult, array, text, validate};
use mmmm_contracts::{
    RationalTime, Sha256Digest, canonical_digest, projected_digest, verify_projected_digest,
};
use mmmm_domain::transform::Transform;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BakeCompletion {
    Completed,
    JobAccepted,
    InProgress,
    Failed,
}

#[derive(Clone, Debug)]
pub struct MeshObservation {
    pub topology_digest: Sha256Digest,
    pub vertex_count: u64,
    pub triangle_count: u64,
}

/// These facts come from an authenticated completed operation/manifest and an
/// independent evaluator/codec, not BakeArtifact or ProviderResult.data JSON.
#[derive(Clone, Debug)]
pub struct BakeObservation {
    pub completion: BakeCompletion,
    pub artifact_digest: Sha256Digest,
    pub input_digest: Sha256Digest,
    pub implementation_digest: Sha256Digest,
    pub provider_id: String,
    pub tool_version: String,
    pub solver_settings_digest: Sha256Digest,
    pub sampling_digest: Sha256Digest,
    pub evaluated_scene_verified: bool,
    pub initial_final_verified: bool,
    pub intermediate_pose_verified: bool,
    /// Independent evaluated/decoded pose coverage for each clip/node. This
    /// allows a declared sparse interpolation codec without inventing samples
    /// from sampling metadata alone. A concrete evaluator must supply the facts.
    pub part_sample_times: BTreeMap<(String, String), Vec<RationalTime>>,
    /// Exact mesh resource SHA -> independently decoded stable topology digest.
    pub mesh_topologies: BTreeMap<Sha256Digest, MeshObservation>,
    /// Exact mapping resource hashes verified by the declared mesh codec.
    pub verified_identity_maps: BTreeSet<Sha256Digest>,
    /// Present only when a trusted independent observer measured this exact
    /// external output cost. An estimate never becomes a measured game result.
    pub measured_cost: Option<Value>,
}
pub struct BakeVerificationInput<'a> {
    pub context_id: &'a str,
    pub request: &'a Value,
    pub artifact_resource: &'a Value,
    pub artifact: &'a Value,
    pub source: &'a InspectedBundle,
}
/// Runtime connects this port to the original durable invocation/job's completed
/// output and independent pose/mesh readback. No execution method is exposed.
/// A disconnected or undeclared codec returns CAPABILITY_UNAVAILABLE.
pub trait BakeVerifierPort {
    fn observe(&mut self, input: BakeVerificationInput<'_>) -> ExchangeResult<BakeObservation>;
}

pub struct IngestedBake {
    artifact: Value,
    resource: Value,
    source_revision: String,
    source_project: String,
    source_selection_digest: Sha256Digest,
    source_selection: Value,
    artifact_bytes: Vec<u8>,
    canonical_clips: Vec<Value>,
}
impl IngestedBake {
    pub fn artifact(&self) -> &Value {
        &self.artifact
    }
    pub fn resource(&self) -> &Value {
        &self.resource
    }
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }
    /// Separate immutable Minecraft-space variants. These are Rust-derived
    /// clips, never replacement bytes under the external artifact's raw hash.
    pub fn canonical_clips(&self) -> &[Value] {
        &self.canonical_clips
    }
    /// Composition stages these exact derived resources in product CAS. The
    /// public accessor exposes bytes without granting a way to forge ingestion.
    pub fn canonical_clip_resources(&self) -> ExchangeResult<Vec<(Value, Vec<u8>)>> {
        self.canonical_clips
            .iter()
            .map(|clip| {
                let bytes = crate::json_bytes(clip)?;
                Ok((
                    crate::resources::content_resource(
                        "canonical-clip",
                        "application/vnd.mmmm.animation-clip+json",
                        &bytes,
                    ),
                    bytes,
                ))
            })
            .collect()
    }
    /// Common planning pins this derivation alongside the original operation
    /// evidence; it is distinct from the external artifact's producer digest.
    pub fn normalization_digest(&self) -> ExchangeResult<Sha256Digest> {
        canonical_digest(&serde_json::json!({"profile":crate::normalization::PROFILE,"sourceArtifact":self.resource,
            "sourceSelectionDigest":self.source_selection_digest,"clips":self.canonical_clips}))
            .map_err(|error| ExchangeError::new("INPUT_DIGEST_MISMATCH",error.to_string()))
    }
    pub fn source_selection(&self) -> &Value {
        &self.source_selection
    }
    pub fn original_bytes(&self) -> &[u8] {
        &self.artifact_bytes
    }
    pub fn check_selection(&self, selection: &Selection) -> ExchangeResult<()> {
        selection.check_revision(&self.source_project, &self.source_revision)?;
        if canonical_digest(selection.value())
            .map_err(|e| ExchangeError::new("SCHEMA_INVALID", e.to_string()))?
            != self.source_selection_digest
        {
            return Err(ExchangeError::new(
                "REVISION_CONFLICT",
                "Import base selection differs from the exact pinned source snapshot",
            ));
        }
        Ok(())
    }
}

pub fn bake_ingest(
    input: &Value,
    resources: &mut dyn ResourcePort,
    verifier: &mut dyn BakeVerifierPort,
    limits: ArchiveLimits,
) -> ExchangeResult<IngestedBake> {
    validate("BakeIngestRequest", input)?;
    let context = text(input, "contextId")?;
    let request = &input["request"];
    validate_bake_request(request)?;
    let requested_bytes = text(&request["budget"], "maxArtifactBytes")?
        .parse::<u64>()
        .map_err(|_| {
            ExchangeError::new(
                "BUDGET_EXCEEDED",
                "Artifact byte budget is outside the supported finite range",
            )
        })?;
    let artifact_bytes = read_resource(
        resources,
        context,
        &input["artifactResource"],
        ResourcePurpose::Read,
        requested_bytes.min(limits.max_member_bytes),
    )?;
    let artifact = parse_resource("BakeArtifact", &artifact_bytes.bytes)?;
    let source_bytes = read_resource(
        resources,
        context,
        &request["sourceBundle"],
        ResourcePurpose::Read,
        limits.max_archive_bytes,
    )?;
    let source = inspect_resource(
        context,
        &source_bytes.bytes,
        text(&request["sourceBundle"], "mediaType")?,
        resources,
        limits,
    )?;
    validate_source_pins(request, &source)?;
    validate_artifact(&artifact, request, source.working_selection())?;
    if CoordinateSystem::from_value(&artifact["coordinates"])?
        != CoordinateSystem::from_value(&source.bundle().manifest()["coordinates"])?
    {
        return Err(ExchangeError::new(
            "UNIT_MISMATCH",
            "Artifact and source coordinate pins differ; normalization cannot be applied twice or inferred",
        ));
    }
    let observation = verifier.observe(BakeVerificationInput {
        context_id: context,
        request,
        artifact_resource: &input["artifactResource"],
        artifact: &artifact,
        source: &source,
    })?;
    verify_observation(&artifact, request, &input["artifactResource"], &observation)?;
    let coordinates = CoordinateSystem::from_value(&artifact["coordinates"])?;
    let canonical_clips = array(&artifact, "clips")?
        .iter()
        .map(|clip| crate::normalization::canonical_clip(clip, &coordinates))
        .collect::<ExchangeResult<Vec<_>>>()?;
    let refs = collect_resources(&artifact)?;
    let mut bytes = artifact_bytes.bytes.len() as u64;
    for resource in refs.values() {
        let remaining = requested_bytes
            .min(limits.max_total_bytes)
            .checked_sub(bytes)
            .ok_or_else(|| {
                ExchangeError::new(
                    "BUDGET_EXCEEDED",
                    "Bake resources exceed the output byte budget",
                )
            })?;
        let read = read_resource(
            resources,
            context,
            resource,
            ResourcePurpose::Read,
            remaining.min(limits.max_member_bytes),
        )?;
        bytes = bytes
            .checked_add(read.bytes.len() as u64)
            .ok_or_else(|| ExchangeError::new("BUDGET_EXCEEDED", "Bake resource count overflow"))?;
    }
    // Return the original verified artifact exactly. False pose flags remain
    // false; independent evidence does not silently rewrite the producer bytes.
    Ok(IngestedBake {
        source_revision: text(request, "projectRevision")?.to_owned(),
        source_project: text(request, "projectId")?.to_owned(),
        source_selection_digest: canonical_digest(source.selection().value())
            .map_err(|e| ExchangeError::new("SCHEMA_INVALID", e.to_string()))?,
        artifact,
        resource: input["artifactResource"].clone(),
        source_selection: source.selection().value().clone(),
        artifact_bytes: artifact_bytes.bytes,
        canonical_clips,
    })
}

pub fn validate_bake_request(request: &Value) -> ExchangeResult<()> {
    validate("BakeRequest", request)?;
    let duration = time(&request["duration"])?;
    if !duration.is_positive() {
        return Err(ExchangeError::new(
            "INVALID_TIME",
            "Bake duration must be positive",
        ));
    }
    let fps = time(&request["sampling"]["sourceFps"])?;
    if !fps.is_positive() {
        return Err(ExchangeError::new(
            "INVALID_TIME",
            "Source FPS must be positive",
        ));
    }
    let samples = times(&request["sampling"]["sampleTimes"])?;
    if samples.len() > 16384
        || samples.len() as u64 > integer(&request["budget"], "maxSamples")?
        || integer(&request["budget"], "maxParts")? > 65536
        || integer(&request["budget"], "maxWallMilliseconds")? == 0
        || integer(&request["budget"], "maxWallMilliseconds")? > 3_600_000
    {
        return Err(ExchangeError::new(
            "BUDGET_EXCEEDED",
            "Bake request exceeds supported finite sample/part/time budgets",
        ));
    }
    let mut previous = None;
    for at in &samples {
        if at.is_negative() || at > &duration || previous.is_some_and(|p: &RationalTime| at <= p) {
            return Err(ExchangeError::new(
                "INVALID_TIME",
                "Sample times must increase strictly within the declared duration",
            ));
        }
        previous = Some(at);
    }
    if request["sampling"]["initialFinalIncluded"] == true
        && (samples.first() != Some(&RationalTime::zero()) || samples.last() != Some(&duration))
    {
        return Err(ExchangeError::new(
            "INCOMPLETE_OUTPUT",
            "Declared initial/final samples are absent",
        ));
    }
    Ok(())
}

pub fn validate_source_pins(request: &Value, source: &InspectedBundle) -> ExchangeResult<()> {
    source.verify_source_resource(&request["sourceBundle"])?;
    source.selection().check_revision(
        text(request, "projectId")?,
        text(request, "projectRevision")?,
    )?;
    let mut matching = None;
    for payload in array(source.bundle().manifest(), "payloads")? {
        if payload["kind"] == "physics" {
            let bytes = source
                .bundle()
                .payload(text(payload, "path")?)
                .ok_or_else(|| {
                    ExchangeError::new(
                        "REFERENCE_UNRESOLVED",
                        "Physics must be embedded in the pinned source bundle",
                    )
                })?;
            let physics = parse_resource("PhysicsDefinition", bytes)?;
            if physics["physicsId"] == request["physicsId"]
                && physics["revision"] == request["physicsRevision"]
            {
                matching = Some(physics);
            }
        }
    }
    let physics = matching.ok_or_else(|| {
        ExchangeError::new(
            "INPUT_DIGEST_MISMATCH",
            "Requested physics identity/revision is not present in the pinned source bundle",
        )
    })?;
    let capabilities = array(request, "requiredCapabilities")?;
    if array(&physics, "requiredCapabilities")?
        .iter()
        .any(|required| !capabilities.contains(required))
    {
        return Err(ExchangeError::new(
            "CAPABILITY_UNAVAILABLE",
            "Bake request omits a required pinned physics capability",
        ));
    }
    if physics["runtimeIntent"] == "runtime_required" {
        return Err(ExchangeError::new(
            "CAPABILITY_UNAVAILABLE",
            "A real-time solver dependency cannot be represented as a completed offline bake",
        ));
    }
    Ok(())
}

pub fn validate_artifact(
    artifact: &Value,
    request: &Value,
    selection: &Selection,
) -> ExchangeResult<()> {
    validate("BakeArtifact", artifact)?;
    validate_bake_request(request)?;
    CoordinateSystem::from_value(&artifact["coordinates"])?;
    let digest = projected_digest("BakeRequest", request)
        .map_err(|e| ExchangeError::new("INPUT_DIGEST_MISMATCH", e.to_string()))?;
    if artifact["requestId"] != request["requestId"]
        || artifact["inputDigest"].as_str() != Some(digest.as_str())
        || artifact["sourceProjectRevision"] != request["projectRevision"]
        || artifact["representation"] != request["representation"]
    {
        return Err(ExchangeError::new(
            "INPUT_DIGEST_MISMATCH",
            "Bake output does not match its exact request/source/representation pins",
        ));
    }
    selection.check_revision(
        text(request, "projectId")?,
        text(request, "projectRevision")?,
    )?;
    let clips = array(artifact, "clips")?;
    let surface = array(artifact, "surfaceSamples")?;
    let representation = text(artifact, "representation")?;
    if clips.len() > 4096 || surface.len() > 16384 {
        return Err(ExchangeError::new(
            "BUDGET_EXCEEDED",
            "Artifact graph exceeds finite object limits",
        ));
    }
    if representation == "triangulated_surface_samples" {
        if !clips.is_empty() || surface.is_empty() {
            return Err(ExchangeError::new(
                "UNSUPPORTED_FORMAT",
                "Surface samples cannot be relabeled as part tracks",
            ));
        }
        validate_surface(artifact, request)?;
    } else if clips.is_empty()
        || !surface.is_empty()
        || artifact["topologyPolicy"] != "not_applicable"
        || !artifact["topologyDigest"].is_null()
    {
        return Err(ExchangeError::new(
            "UNSUPPORTED_FORMAT",
            "Part tracks need clips and no surface topology claim",
        ));
    }
    let duration = time(&request["duration"])?;
    let mut clip_ids = BTreeSet::new();
    let mut parts = 0_u64;
    let mut observed_max_samples = surface.len() as u64;
    for clip in clips {
        if array(clip, "tracks")?.is_empty() {
            return Err(ExchangeError::new(
                "INCOMPLETE_OUTPUT",
                "Completed part bake requires actual part pose tracks",
            ));
        }
        verify_projected_digest("AnimationClip", clip)
            .map_err(|e| ExchangeError::new("INPUT_DIGEST_MISMATCH", e.to_string()))?;
        if !clip_ids.insert(text(clip, "clipId")?) {
            return Err(ExchangeError::new(
                "OBJECT_MAPPING_AMBIGUOUS",
                "Duplicate clip identity",
            ));
        }
        if clip["representation"] != artifact["representation"]
            || clip["duration"] != request["duration"]
            || clip["sampling"] != request["sampling"]
            || clip["timeDomain"] != artifact["coordinates"]["timeDomain"]
            || clip["requiresBake"] != false
            || clip["poseWriter"] != "animation"
        {
            return Err(ExchangeError::new(
                "UNSUPPORTED_FORMAT",
                "Clip coordinate/time/evaluation/pose-writer declaration is not a completed offline part bake",
            ));
        }
        let mut node_ids = BTreeSet::new();
        for track in array(clip, "tracks")? {
            let node_id = text(track, "nodeId")?;
            if !node_ids.insert(node_id)
                || !selection.nodes().any(|(node, _)| {
                    node.node_id == node_id
                        && selection.prefab_for(&node.instance_id) == clip["ownerPrefabId"].as_str()
                        && selection.selected(node)
                })
            {
                return Err(ExchangeError::new(
                    "OBJECT_MAPPING_AMBIGUOUS",
                    "Clip track must address a stable selected node of its owner prefab exactly once",
                ));
            }
            parts = parts
                .checked_add(1)
                .ok_or_else(|| ExchangeError::new("BUDGET_EXCEEDED", "Part count overflow"))?;
            let keys = array(track, "keys")?;
            if keys.len() > 16384 {
                return Err(ExchangeError::new(
                    "BUDGET_EXCEEDED",
                    "Track sample count exceeds supported limit",
                ));
            }
            observed_max_samples = observed_max_samples.max(keys.len() as u64);
            let mut previous = None;
            let mut rigid_scale = None;
            for key in keys {
                let at = time(&key["at"])?;
                if at.is_negative() || at > duration || previous.as_ref().is_some_and(|p| &at <= p)
                {
                    return Err(ExchangeError::new(
                        "INVALID_TIME",
                        "Track keys must increase strictly within bake duration",
                    ));
                }
                previous = Some(at);
                let transform = Transform::from_value(&key["transform"])
                    .map_err(|e| ExchangeError::new("UNSUPPORTED_TRANSFORM", e.to_string()))?;
                if track["interpolation"] == "linear_trs"
                    && !matches!(transform, Transform::Trs { .. })
                {
                    return Err(ExchangeError::new(
                        "LOSS_APPROVAL_REQUIRED",
                        "Raw affine/shear data cannot use undeclared TRS interpolation",
                    ));
                }
                if representation == "rigid_part_tracks" {
                    if let Transform::Trs { scale, .. } = transform {
                        if rigid_scale.is_some_and(|s| s != scale) {
                            return Err(ExchangeError::new(
                                "UNSUPPORTED_TRANSFORM",
                                "Rigid tracks cannot contain changing scale",
                            ));
                        }
                        rigid_scale = Some(scale);
                    } else {
                        return Err(ExchangeError::new(
                            "UNSUPPORTED_TRANSFORM",
                            "Raw matrices require an affine part representation",
                        ));
                    }
                }
            }
            if time(&keys[0]["at"])? != RationalTime::zero() {
                return Err(ExchangeError::new(
                    "INCOMPLETE_OUTPUT",
                    "Each part track requires an explicit initial parent-local pose",
                ));
            }
            if request["sampling"]["initialFinalIncluded"] == true
                && time(&keys[keys.len() - 1]["at"])? != duration
            {
                return Err(ExchangeError::new(
                    "INCOMPLETE_OUTPUT",
                    "Track lacks its declared explicit final sample",
                ));
            }
        }
        let mut events = BTreeSet::new();
        let mut order = None;
        for event in array(clip, "events")? {
            let at = time(&event["at"])?;
            let sequence = integer(event, "authoredSequence")?;
            if at.is_negative()
                || at > duration
                || !events.insert(text(event, "eventId")?)
                || order
                    .as_ref()
                    .is_some_and(|prior| &(at.clone(), sequence) < prior)
            {
                return Err(ExchangeError::new(
                    "INVALID_TIME",
                    "Events require stable identities and authored (time,sequence) order within duration",
                ));
            }
            order = Some((at, sequence));
        }
    }
    if parts > integer(&request["budget"], "maxParts")?
        || observed_max_samples > integer(&request["budget"], "maxSamples")?
        || integer(&artifact["cost"], "parts")? < parts
        || integer(&artifact["cost"], "samples")? < observed_max_samples
        || integer(&artifact["cost"], "parts")? > integer(&request["budget"], "maxParts")?
        || integer(&artifact["cost"], "samples")? > integer(&request["budget"], "maxSamples")?
    {
        return Err(ExchangeError::new(
            "BUDGET_EXCEEDED",
            "Actual track footprint exceeds budget or producer's cost declaration",
        ));
    }
    Ok(())
}

fn validate_surface(artifact: &Value, request: &Value) -> ExchangeResult<()> {
    if artifact["topologyPolicy"] != "stable_verified" || artifact["topologyDigest"].is_null() {
        return Err(ExchangeError::new(
            "TOPOLOGY_CHANGED",
            "Changing/unknown topology needs an explicit spawn/delete strategy unavailable in the base surface codec",
        ));
    }
    let expected = times(&request["sampling"]["sampleTimes"])?;
    let surface = array(artifact, "surfaceSamples")?;
    if surface.len() != expected.len() {
        return Err(ExchangeError::new(
            "INCOMPLETE_OUTPUT",
            "Surface output must contain exactly each requested rational sample time",
        ));
    }
    let mut counts = None;
    for (sample, at) in surface.iter().zip(expected) {
        if time(&sample["at"])? != at || sample["topologyDigest"] != artifact["topologyDigest"] {
            return Err(ExchangeError::new(
                "TOPOLOGY_CHANGED",
                "Surface time/topology pins differ from the declared stable samples",
            ));
        }
        let current = (
            integer(sample, "vertexCount")?,
            integer(sample, "triangleCount")?,
        );
        if current.0 < 3 || current.1 == 0 || counts.is_some_and(|p| p != current) {
            return Err(ExchangeError::new(
                "TOPOLOGY_CHANGED",
                "Empty or changing surface footprint is unsupported",
            ));
        }
        counts = Some(current);
    }
    Ok(())
}

fn verify_observation(
    artifact: &Value,
    request: &Value,
    resource: &Value,
    proof: &BakeObservation,
) -> ExchangeResult<()> {
    if proof.completion != BakeCompletion::Completed {
        return Err(ExchangeError::new(
            "INCOMPLETE_OUTPUT",
            "An accepted or partial job is not a completed artifact manifest",
        ));
    }
    if artifact["cost"]["kind"] == "measured"
        && proof.measured_cost.as_ref() != Some(&artifact["cost"])
    {
        return Err(ExchangeError::new(
            "INCOMPLETE_OUTPUT",
            "Measured cost requires an independent observation of this exact external output",
        ));
    }
    if resource["sha256"].as_str() != Some(proof.artifact_digest.as_str())
        || artifact["inputDigest"].as_str() != Some(proof.input_digest.as_str())
        || artifact["tool"]["implementationDigest"].as_str()
            != Some(proof.implementation_digest.as_str())
        || artifact["tool"]["providerId"].as_str() != Some(proof.provider_id.as_str())
        || artifact["tool"]["version"].as_str() != Some(proof.tool_version.as_str())
        || artifact["solverSettings"]["sha256"].as_str()
            != Some(proof.solver_settings_digest.as_str())
        || canonical_digest(&request["sampling"])
            .map_err(|e| ExchangeError::new("SCHEMA_INVALID", e.to_string()))?
            != proof.sampling_digest
    {
        return Err(ExchangeError::new(
            "INPUT_DIGEST_MISMATCH",
            "Independent completion/evaluation evidence does not bind these exact output/tool/settings/sample bytes",
        ));
    }
    if request["sampling"]["evaluation"] == "evaluated_scene" && !proof.evaluated_scene_verified {
        return Err(ExchangeError::new(
            "CAPABILITY_UNAVAILABLE",
            "Declared evaluated scene requires independent final parent/rig pose evaluation",
        ));
    }
    if artifact["initialFinalVerified"] == true && !proof.initial_final_verified
        || artifact["intermediatePoseVerified"] == true && !proof.intermediate_pose_verified
    {
        return Err(ExchangeError::new(
            "INCOMPLETE_OUTPUT",
            "Producer pose verification flags lack independent evidence",
        ));
    }
    if proof.mesh_topologies.len() > 16384 || proof.verified_identity_maps.len() > 16384 {
        return Err(ExchangeError::new(
            "BUDGET_EXCEEDED",
            "Independent mesh evidence exceeds its finite budget",
        ));
    }
    let expected = times(&request["sampling"]["sampleTimes"])?;
    let observations = proof
        .part_sample_times
        .values()
        .try_fold(0_usize, |sum, times| sum.checked_add(times.len()))
        .ok_or_else(|| ExchangeError::new("BUDGET_EXCEEDED", "Pose observation count overflow"))?;
    if proof.part_sample_times.len() > 65536 || observations > 1_000_000 {
        return Err(ExchangeError::new(
            "BUDGET_EXCEEDED",
            "Independent pose coverage exceeds its finite budget",
        ));
    }
    for clip in array(artifact, "clips")? {
        for track in array(clip, "tracks")? {
            let key = (
                text(clip, "clipId")?.to_owned(),
                text(track, "nodeId")?.to_owned(),
            );
            if proof.part_sample_times.get(&key) != Some(&expected) {
                return Err(ExchangeError::new(
                    "INCOMPLETE_OUTPUT",
                    "Every requested part pose time needs independent evaluated/decoded coverage",
                ));
            }
        }
    }
    for sample in array(artifact, "surfaceSamples")? {
        let mesh: Sha256Digest = serde_json::from_value(sample["mesh"]["sha256"].clone())
            .map_err(|_| ExchangeError::new("SCHEMA_INVALID", "Invalid mesh digest"))?;
        let topology: Sha256Digest = serde_json::from_value(sample["topologyDigest"].clone())
            .map_err(|_| ExchangeError::new("SCHEMA_INVALID", "Invalid topology digest"))?;
        let observed = proof.mesh_topologies.get(&mesh).ok_or_else(|| {
            ExchangeError::new(
                "TOPOLOGY_CHANGED",
                "Mesh bytes lack independent codec verification",
            )
        })?;
        if observed.topology_digest != topology
            || observed.vertex_count != integer(sample, "vertexCount")?
            || observed.triangle_count != integer(sample, "triangleCount")?
        {
            return Err(ExchangeError::new(
                "TOPOLOGY_CHANGED",
                "Claimed topology/counts differ from the independently decoded mesh identity/order",
            ));
        }
        if !sample["identityMap"].is_null() {
            let map: Sha256Digest = serde_json::from_value(sample["identityMap"]["sha256"].clone())
                .map_err(|_| ExchangeError::new("SCHEMA_INVALID", "Invalid identity-map digest"))?;
            if !proof.verified_identity_maps.contains(&map) {
                return Err(ExchangeError::new(
                    "TOPOLOGY_CHANGED",
                    "Surface identity map lacks codec verification",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn time(value: &Value) -> ExchangeResult<RationalTime> {
    serde_json::from_value(value.clone()).map_err(|e| {
        ExchangeError::new(
            "INVALID_TIME",
            format!("Invalid canonical rational time: {e}"),
        )
    })
}
pub(crate) fn times(value: &Value) -> ExchangeResult<Vec<RationalTime>> {
    value
        .as_array()
        .ok_or_else(|| ExchangeError::new("INVALID_TIME", "Missing time array"))?
        .iter()
        .map(time)
        .collect()
}
fn integer(value: &Value, field: &str) -> ExchangeResult<u64> {
    crate::nonnegative_integer(&value[field]).ok_or_else(|| {
        ExchangeError::new("SCHEMA_INVALID", format!("Missing bounded integer {field}"))
    })
}

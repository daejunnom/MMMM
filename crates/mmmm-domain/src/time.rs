//! FN08 changes authored time only. Sampling, key reduction, target tick
//! quantization and event execution remain distinct application operations.

use crate::{
    decode, encode,
    transform::Transform,
    types::{DomainError, LossRecord},
};
use mmmm_contracts::{
    ClipId, NodeId, ObjectId, PrefabId, RationalTime, Sha256Digest, SignedDecimal, SymbolId,
};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;
use std::{collections::BTreeSet, fmt};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AnimationClip {
    pub contract_version: String,
    pub clip_id: ClipId,
    pub owner_prefab_id: PrefabId,
    pub time_domain: TimeDomain,
    pub duration: RationalTime,
    pub r#loop: bool,
    pub tracks: Vec<AnimationTrack>,
    pub events: Vec<AnimationEvent>,
    pub pose_writer: PoseWriter,
    pub requires_bake: bool,
    pub revision: Sha256Digest,
    pub sampling: SamplingPolicy,
    pub representation: ClipRepresentation,
    pub losses: Vec<LossRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeDomain {
    GameSeconds,
    WallSeconds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoseWriter {
    Animation,
    NativeBody,
    ExternalPhysics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipRepresentation {
    RigidPartTracks,
    AffinePartTracks,
    TriangulatedSurfaceSamples,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AnimationTrack {
    pub node_id: NodeId,
    pub interpolation: Interpolation,
    pub keys: Vec<AnimationKey>,
    pub pose_space: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Interpolation {
    Step,
    LinearTrs,
    BakedMatrix,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AnimationKey {
    pub at: RationalTime,
    pub transform: Transform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AnimationEvent {
    pub event_id: ObjectId,
    pub at: RationalTime,
    pub function_symbol_id: SymbolId,
    pub scrub_policy: String,
    #[serde(deserialize_with = "deserialize_sequence")]
    pub authored_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SamplingPolicy {
    pub evaluation: SamplingEvaluation,
    pub source_fps: RationalTime,
    pub source_frame_zero: SignedDecimal,
    pub sample_times: Vec<RationalTime>,
    pub tick_rounding: TickRounding,
    pub max_time_error_seconds: f64,
    pub initial_final_included: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SamplingEvaluation {
    AuthoredKeys,
    EvaluatedScene,
    AlreadyBaked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TickRounding {
    Exact,
    Floor,
    NearestEven,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventPolicy {
    ScaleWithClip,
    KeepAuthoredTimes,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RetimeRequest {
    pub clip: AnimationClip,
    pub duration: RationalTime,
    pub event_policy: EventPolicy,
}

/// FN08: positive exact scaling preserves key gaps, endpoint inclusion, holds,
/// loop seams, source provenance, payloads and stable identities. The sampling
/// error tolerance is a policy in seconds and is not changed or newly measured.
pub fn clip_retime(value: &Value) -> Result<Value, DomainError> {
    let request: RetimeRequest = decode("RetimeRequest", value)?;
    let clip = retime(request)?;
    encode("AnimationClip", &clip)
}

pub fn retime(request: RetimeRequest) -> Result<AnimationClip, DomainError> {
    if !request.duration.is_positive() {
        return Err(DomainError::new(
            "INVALID_TIME",
            "Requested duration must be positive",
        ));
    }
    validate_clip(&request.clip)?;
    let ratio = request
        .duration
        .checked_div(&request.clip.duration)
        .map_err(|error| DomainError::new("INVALID_TIME", error.to_string()))?;
    let mut clip = request.clip;
    for track in &mut clip.tracks {
        for key in &mut track.keys {
            key.at = &key.at * &ratio;
        }
    }
    for at in &mut clip.sampling.sample_times {
        *at = &*at * &ratio;
    }
    for event in &mut clip.events {
        if request.event_policy == EventPolicy::ScaleWithClip {
            event.at = &event.at * &ratio;
        }
        if event.at > request.duration {
            return Err(DomainError::new(
                "EVENT_OUT_OF_RANGE",
                format!("Event {} is after requested duration", event.event_id),
            ));
        }
    }
    clip.duration = request.duration;
    // Positive scaling cannot invert the authored total order. A wire array may
    // be unordered; execution order is always (timestamp, authoredSequence).
    clip.events.sort_by(|left, right| {
        (&left.at, left.authored_sequence).cmp(&(&right.at, right.authored_sequence))
    });
    let output = encode("AnimationClip", &clip)?;
    clip.revision = mmmm_contracts::projected_digest("AnimationClip", &output)
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    Ok(clip)
}

/// Checks time, identity and authored transform validity. This does not certify
/// a target's interpolation codec, bake result or actual event execution.
pub fn validate_clip(clip: &AnimationClip) -> Result<(), DomainError> {
    if !clip.duration.is_positive() || !clip.sampling.source_fps.is_positive() {
        return Err(DomainError::new(
            "INVALID_TIME",
            "Clip duration and source FPS must be positive",
        ));
    }
    let mut nodes = BTreeSet::new();
    for track in &clip.tracks {
        if !nodes.insert(&track.node_id) {
            return Err(DomainError::new(
                "ID_COLLISION",
                "A clip has multiple tracks for one node",
            ));
        }
        if track.keys.is_empty() {
            return Err(DomainError::new(
                "INVALID_TIME",
                "A track requires at least one key",
            ));
        }
        let mut previous: Option<&RationalTime> = None;
        for key in &track.keys {
            bounded_time(&key.at, &clip.duration, "INVALID_TIME", "key")?;
            if previous.is_some_and(|previous| previous >= &key.at) {
                return Err(DomainError::new(
                    "INVALID_TIME",
                    "Track key times must increase strictly",
                ));
            }
            previous = Some(&key.at);
            key.transform
                .validate()
                .map_err(|error| DomainError::new(error.code(), error.to_string()))?;
        }
    }
    let mut event_ids = BTreeSet::new();
    let mut event_order = BTreeSet::new();
    for event in &clip.events {
        bounded_time(&event.at, &clip.duration, "EVENT_OUT_OF_RANGE", "event")?;
        if !event_ids.insert(&event.event_id) {
            return Err(DomainError::new(
                "ID_COLLISION",
                "Event stable IDs must be unique",
            ));
        }
        if !event_order.insert((&event.at, event.authored_sequence)) {
            return Err(DomainError::new(
                "INVALID_TIME",
                "Two events have an ambiguous timestamp/authoredSequence pair",
            ));
        }
    }
    if clip.sampling.sample_times.is_empty() {
        return Err(DomainError::new(
            "INVALID_TIME",
            "Sampling policy requires at least one sample time",
        ));
    }
    let mut previous: Option<&RationalTime> = None;
    for at in &clip.sampling.sample_times {
        bounded_time(at, &clip.duration, "INVALID_TIME", "sample")?;
        if previous.is_some_and(|previous| previous >= at) {
            return Err(DomainError::new(
                "INVALID_TIME",
                "Sample times must increase strictly",
            ));
        }
        previous = Some(at);
    }
    if clip.sampling.initial_final_included
        && (clip
            .sampling
            .sample_times
            .first()
            .is_none_or(|at| !at.is_zero())
            || clip.sampling.sample_times.last() != Some(&clip.duration))
    {
        return Err(DomainError::new(
            "INVALID_TIME",
            "Sampling policy claims endpoints which its times do not contain",
        ));
    }
    if !clip.sampling.max_time_error_seconds.is_finite()
        || clip.sampling.max_time_error_seconds < 0.0
    {
        return Err(DomainError::new(
            "INVALID_TIME",
            "Sampling error tolerance must be finite and nonnegative",
        ));
    }
    Ok(())
}

fn bounded_time(
    at: &RationalTime,
    duration: &RationalTime,
    code: &'static str,
    subject: &str,
) -> Result<(), DomainError> {
    if at.is_negative() || at > duration {
        Err(DomainError::new(
            code,
            format!("Clip {subject} time must be in the inclusive duration range"),
        ))
    } else {
        Ok(())
    }
}

fn deserialize_sequence<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    struct SequenceVisitor;
    const MAXIMUM: u64 = 9_007_199_254_740_991;
    impl<'de> de::Visitor<'de> for SequenceVisitor {
        type Value = u64;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an integer in the canonical authored sequence range")
        }
        fn visit_u64<E: de::Error>(self, value: u64) -> Result<u64, E> {
            if value <= MAXIMUM {
                Ok(value)
            } else {
                Err(E::custom("Authored sequence exceeds safe integer range"))
            }
        }
        fn visit_i64<E: de::Error>(self, value: i64) -> Result<u64, E> {
            u64::try_from(value)
                .map_err(|_| E::custom("Authored sequence must be nonnegative"))
                .and_then(|value| self.visit_u64(value))
        }
        fn visit_f64<E: de::Error>(self, value: f64) -> Result<u64, E> {
            if value.is_finite() && value.fract() == 0.0 && value >= 0.0 && value <= MAXIMUM as f64
            {
                Ok(value as u64)
            } else {
                Err(E::custom(
                    "Authored sequence must be a finite safe nonnegative integer",
                ))
            }
        }
    }
    deserializer.deserialize_any(SequenceVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Value {
        mmmm_contracts::parse_json(include_bytes!("../../../examples/animation-clip.json")).unwrap()
    }
    fn rational(n: &str, d: &str) -> Value {
        json!({"numerator":n,"denominator":d})
    }
    fn request(duration: Value, policy: &str) -> Value {
        json!({"clip":fixture(),"duration":duration,"eventPolicy":policy})
    }
    fn event(id: &str, n: &str, d: &str, sequence: u64) -> Value {
        json!({"eventId":id,"at":rational(n,d),"functionSymbolId":"open_fn","scrubPolicy":"suppress","authoredSequence":sequence})
    }

    // Original examples have endpoint keys only. Interior equal poses and
    // endpoint events expose accidental key reduction or endpoint exclusion.
    #[test]
    fn exact_retime_preserves_holds_equal_poses_endpoint_events_and_ids() {
        let mut input = request(rational("3", "1"), "scale_with_clip");
        let pose = input["clip"]["tracks"][0]["keys"][0]["transform"].clone();
        input["clip"]["tracks"][0]["keys"] = json!([
            {"at":rational("1","4"),"transform":pose},
            {"at":rational("7","4"),"transform":pose}
        ]);
        input["clip"]["events"] = json!([event("last", "2", "1", 8), event("first", "0", "1", 4)]);
        let before = input.clone();
        let output = clip_retime(&input).unwrap();
        assert_eq!(input, before);
        assert_eq!(output["clipId"], "clip-door");
        assert_eq!(output["tracks"][0]["nodeId"], "door");
        assert_eq!(output["tracks"][0]["keys"][0]["at"], rational("3", "8"));
        assert_eq!(output["tracks"][0]["keys"][1]["at"], rational("21", "8"));
        assert_eq!(output["tracks"][0]["keys"].as_array().unwrap().len(), 2);
        assert_eq!(output["events"][0]["eventId"], "first");
        assert_eq!(output["events"][1]["at"], rational("3", "1"));
        assert_eq!(
            output["sampling"]["sampleTimes"],
            json!([rational("0", "1"), rational("3", "2"), rational("3", "1")])
        );
        assert_eq!(
            output["sampling"]["sourceFps"],
            before["clip"]["sampling"]["sourceFps"]
        );
        assert_eq!(output["poseWriter"], before["clip"]["poseWriter"]);
        assert_eq!(output["loop"], before["clip"]["loop"]);
        mmmm_contracts::verify_projected_digest("AnimationClip", &output).unwrap();
    }

    #[test]
    fn huge_rational_duration_never_crosses_floating_point() {
        let input = request(rational("9007199254740993", "7"), "scale_with_clip");
        let output = clip_retime(&input).unwrap();
        assert_eq!(
            output["sampling"]["sampleTimes"][1],
            rational("9007199254740993", "14")
        );
        assert_eq!(output["tracks"][0]["keys"][1]["at"], input["duration"]);
        assert_eq!(output, clip_retime(&input).unwrap());
    }

    #[test]
    fn authored_event_times_are_retained_and_shortening_rejects_without_clipping() {
        let mut input = request(rational("1", "1"), "keep_authored_times");
        input["clip"]["events"] = json!([event("event-final", "2", "1", 0)]);
        assert_eq!(clip_retime(&input).unwrap_err().code, "EVENT_OUT_OF_RANGE");
        input["duration"] = rational("3", "1");
        let output = clip_retime(&input).unwrap();
        assert_eq!(output["events"][0]["at"], rational("2", "1"));
        assert_eq!(output["tracks"][0]["keys"][1]["at"], rational("3", "1"));
    }

    #[test]
    fn simultaneous_events_use_authored_sequence_and_preserve_scrub_suppression() {
        let mut input = request(rational("4", "1"), "scale_with_clip");
        input["clip"]["events"] =
            json!([event("later", "1", "1", 9), event("earlier", "1", "1", 3)]);
        let output = clip_retime(&input).unwrap();
        assert_eq!(output["events"][0]["eventId"], "earlier");
        assert_eq!(output["events"][1]["eventId"], "later");
        assert!(
            output["events"]
                .as_array()
                .unwrap()
                .iter()
                .all(|event| event["scrubPolicy"] == "suppress")
        );
        input["clip"]["events"][1]["authoredSequence"] = json!(9);
        assert_eq!(clip_retime(&input).unwrap_err().code, "INVALID_TIME");
    }

    #[test]
    fn rejects_nonpositive_duration_negative_keys_event_range_and_lying_sampling_endpoints() {
        for duration in [rational("0", "1"), rational("-1", "1")] {
            assert_eq!(
                clip_retime(&request(duration, "scale_with_clip"))
                    .unwrap_err()
                    .code,
                "INVALID_TIME"
            );
        }
        let mut input = request(rational("3", "1"), "scale_with_clip");
        input["clip"]["tracks"][0]["keys"][0]["at"] = rational("-1", "2");
        assert_eq!(clip_retime(&input).unwrap_err().code, "INVALID_TIME");
        input = request(rational("3", "1"), "scale_with_clip");
        input["clip"]["events"] = json!([event("outside", "5", "2", 0)]);
        assert_eq!(clip_retime(&input).unwrap_err().code, "EVENT_OUT_OF_RANGE");
        input = request(rational("3", "1"), "scale_with_clip");
        input["clip"]["sampling"]["sampleTimes"][2] = rational("3", "2");
        assert_eq!(clip_retime(&input).unwrap_err().code, "INVALID_TIME");
    }

    #[test]
    fn loop_affine_payload_and_sampling_policy_are_not_reinterpreted() {
        let mut input = request(rational("4", "1"), "scale_with_clip");
        input["clip"]["loop"] = json!(true);
        input["clip"]["timeDomain"] = json!("wall_seconds");
        input["clip"]["sampling"]["sourceFrameZero"] = json!("-17");
        input["clip"]["sampling"]["maxTimeErrorSeconds"] = json!(0.125);
        input["clip"]["sampling"]["tickRounding"] = json!("nearest_even");
        let matrix = json!({"kind":"matrix","layout":"row_major_column_vector","values":[-1.0,0.5,0.0,7.0,0.0,1.0,0.0,3.0,0.0,0.0,0.00005,9.0,0.0,0.0,0.0,1.0]});
        input["clip"]["tracks"][0]["interpolation"] = json!("baked_matrix");
        input["clip"]["tracks"][0]["keys"][0]["transform"] = matrix.clone();
        let output = clip_retime(&input).unwrap();
        assert_eq!(output["tracks"][0]["keys"][0]["transform"], matrix);
        assert_eq!(output["sampling"]["maxTimeErrorSeconds"], 0.125);
        assert_eq!(output["sampling"]["sourceFrameZero"], "-17");
        assert_eq!(output["timeDomain"], "wall_seconds");
        assert_eq!(output["loop"], true);
    }

    #[test]
    fn mathematical_integer_authored_sequence_accepts_exponent_lexeme() {
        let mut input = request(rational("4", "1"), "scale_with_clip");
        input["clip"]["events"] = json!([event("event-1", "1", "1", 0)]);
        input["clip"]["events"][0]["authoredSequence"] = serde_json::from_str("3e0").unwrap();
        assert_eq!(
            clip_retime(&input).unwrap()["events"][0]["authoredSequence"],
            3
        );
    }
}

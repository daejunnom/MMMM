//! The original clip has only two endpoint keys and no events. These authored
//! cases are required for exact TPS/error boundaries, sparse holds, parent-local
//! evaluation, and emitted-command event/failure control. The command interpreter
//! is a narrow independent test oracle; it is neither the game parser nor runtime
//! acceptance evidence. Actual display readback, client visuals and 3-OS servers
//! remain separate release requirements.

use super::*;
use crate::{TargetEvidenceVerifier, TargetRuntimeRules};
use serde_json::json;

struct AuthoredEvidence;
impl TargetEvidenceVerifier for AuthoredEvidence {
    fn verify_target(
        &self,
        _: &Value,
        _: &Sha256Digest,
        _: &Sha256Digest,
    ) -> Result<TargetRuntimeRules, DomainError> {
        Ok(TargetRuntimeRules {
            native_compute_26_3: true,
            checked_numeric_and_success: true,
            data_pack_26_3: true,
        })
    }
}
impl AnimationEvidenceVerifier for AuthoredEvidence {
    fn verify_loop_seam(
        &self,
        _: &VerifiedTarget,
        _: &Sha256Digest,
        _: &Sha256Digest,
        _: &Sha256Digest,
        _: &RationalTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    fn verify_animation_target(
        &self,
        _: &Sha256Digest,
        _: &Sha256Digest,
    ) -> Result<AnimationTargetRules, DomainError> {
        Ok(AnimationTargetRules {
            row_major_f32_matrix_codec: true,
            explicit_zero_disables_interpolation: true,
            sampled_linear_trs_whole_interval: true,
        })
    }
    fn verify_event_functions(
        &self,
        _: &Sha256Digest,
        _: &Sha256Digest,
        _: &BTreeMap<SymbolId, AnimationEventBinding>,
        _: &str,
        _: &str,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    fn verify_linear_interval(
        &self,
        _: &VerifiedTarget,
        _: &Sha256Digest,
        _: &Sha256Digest,
        _: &Sha256Digest,
        _: &RationalTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }
}
impl AnimationBindingVerifier for AuthoredEvidence {
    fn verify_animation_bindings(
        &self,
        _: &ResourceRef,
        bytes: &[u8],
        _: &AnimationBindings,
    ) -> Result<Sha256Digest, DomainError> {
        Ok(raw_digest(bytes))
    }
}
fn target() -> VerifiedTarget {
    let mut profile: Value =
        serde_json::from_slice(include_bytes!("../../../examples/version-profile.json")).unwrap();
    profile["validationStatus"] = json!("runtime_verified");
    profile["writeSupport"] = json!("verified");
    profile["artifactSha256"] = json!("11".repeat(32));
    profile["javaMajor"] = json!(25);
    profile["testedLoaders"] = json!(["authored-test-only"]);
    profile["evidenceResourceIds"] = json!(["authored-test-only"]);
    VerifiedTarget::verify(&profile, &AuthoredEvidence).unwrap()
}
fn clip() -> Value {
    serde_json::from_slice(include_bytes!("../../../examples/animation-clip.json")).unwrap()
}
fn rational(n: &str, d: &str) -> Value {
    json!({"numerator":n,"denominator":d})
}
fn pin(mut value: Value) -> Value {
    value["revision"] = json!(mmmm_contracts::projected_digest("AnimationClip", &value).unwrap());
    value
}
fn event(id: &str, n: &str, d: &str, sequence: u64, symbol: &str) -> Value {
    json!({"eventId":id,"at":rational(n,d),"functionSymbolId":symbol,"scrubPolicy":"suppress","authoredSequence":sequence})
}
fn function_contract() -> GeneratedFunctionContract {
    GeneratedFunctionContract {
        inputs: vec![],
        outputs: vec![],
        state_reads: vec!["score:fixture:events".into()],
        state_writes: vec!["score:fixture:events".into()],
        execution_context: "server",
        reentrancy: "non_reentrant",
        scheduled_callbacks: vec![],
        cleanup: vec![],
        requirements: vec!["authored test oracle only".into()],
    }
}
fn raw_bindings(instance: &str) -> AnimationBindings {
    let mut instance_world = Transform::identity();
    if let Transform::Trs { translation, .. } = &mut instance_world {
        translation[0] = 10.0;
    }
    let mut rest = Transform::identity();
    if let Transform::Trs { translation, .. } = &mut rest {
        translation[0] = 100.0;
    }
    let mut events = BTreeMap::new();
    for name in ["early", "late", "start", "end", "faulty"] {
        events.insert(
            SymbolId::new(name).unwrap(),
            AnimationEventBinding {
                function: ResourceLocation::new(format!("fixture:{name}")).unwrap(),
                source: StagedResource::new(
                    ResourceId::new(format!("fixture-source:{name}")).unwrap(),
                    "text/x-mcfunction; charset=utf-8",
                    b"return 1\n".to_vec(),
                ),
                contract: function_contract(),
            },
        );
    }
    AnimationBindings {
        instance_id: InstanceId::new(instance).unwrap(),
        owner_prefab_id: PrefabId::new("prefab-shop").unwrap(),
        world_id: WorldId::new("world-fixture-01").unwrap(),
        dimension: ResourceLocation::new("minecraft:overworld").unwrap(),
        instance_world,
        nodes: BTreeMap::from([(
            NodeId::new("door").unwrap(),
            AnimationNodeBinding {
                parent: None,
                rest_local: rest,
                display_uuid: Some("00000000-0000-0000-0000-000000000001".into()),
                display_origin: [0.0; 3],
            },
        )]),
        events,
    }
}
fn verified(input: AnimationBindings) -> VerifiedAnimationBindings {
    let bytes = input.canonical_bytes().unwrap();
    let reference = ResourceRef {
        resource_id: ResourceId::new("fixture-binding-snapshot").unwrap(),
        sha256: raw_digest(&bytes),
        media_type: "application/json".into(),
        size_bytes: bytes.len() as u64,
    };
    VerifiedAnimationBindings::verify(input, reference, &bytes, &AuthoredEvidence).unwrap()
}
fn settings(tps: i32) -> AnimationCompileSettings {
    AnimationCompileSettings {
        target_tps: RationalTime::from_integer(tps),
        max_component_error: 1e-6,
        max_catchup_ticks: 128,
        max_catchup_events: 4096,
    }
}
fn compile(value: Value, tps: i32) -> AnimationDraft {
    animation_compile(
        &pin(value),
        &target(),
        &verified(raw_bindings("instance-one")),
        &AuthoredEvidence,
        settings(tps),
    )
    .unwrap()
}
fn source<'a>(draft: &'a AnimationDraft, part: &str) -> &'a str {
    std::str::from_utf8(&draft.resources[&draft.entry_points[part]].bytes).unwrap()
}
fn error(value: Value) -> &'static str {
    animation_compile(
        &pin(value),
        &target(),
        &verified(raw_bindings("instance-one")),
        &AuthoredEvidence,
        settings(20),
    )
    .unwrap_err()
    .code
}

#[test]
fn two_seconds_preserves_endpoints_and_parent_local_absolute_poses_at_both_rates() {
    for tps in [20, 60] {
        let draft = compile(clip(), tps);
        assert_eq!(draft.duration_ticks(), 2 * tps);
        assert_eq!(draft.poses.len(), (2 * tps + 1) as usize);
        assert_eq!(draft.poses[0].matrix[3], 13.0); // 10 instance + 3 authored; never +100 rest.
        assert_eq!(draft.poses[tps as usize].matrix[7], 2.0);
        assert_eq!(draft.poses[(2 * tps) as usize].matrix[7], 3.0);
        assert!(
            draft
                .quantization
                .iter()
                .all(|record| record.absolute_error.is_zero())
        );
        assert!(
            source(&draft, "stop").contains("{interpolation_duration:0,start_interpolation:0}")
        );
        assert!(draft.resources.values().all(|resource| {
            !std::str::from_utf8(&resource.bytes)
                .unwrap()
                .contains("teleport ")
        }));
    }
}

#[test]
fn sparse_keys_keep_initial_final_holds_and_equal_pose_key_times() {
    let mut value = clip();
    value["tracks"][0]["interpolation"] = json!("step");
    let first = value["tracks"][0]["keys"][0]["transform"].clone();
    let last = value["tracks"][0]["keys"][1]["transform"].clone();
    value["tracks"][0]["keys"] = json!([
        {"at":rational("1","2"),"transform":first},
        {"at":rational("1","1"),"transform":first},
        {"at":rational("3","2"),"transform":last}]);
    let draft = compile(value, 20);
    assert!(draft.poses[..30].iter().all(|pose| pose.matrix[7] == 1.0));
    assert!(draft.poses[30..].iter().all(|pose| pose.matrix[7] == 3.0));
    assert_eq!(draft.duration_ticks(), 40);
    assert_eq!(
        draft
            .quantization
            .iter()
            .filter(|time| time.object_id.starts_with("door:key:"))
            .map(|time| time.tick)
            .collect::<Vec<_>>(),
        vec![10, 20, 30]
    );
}

#[test]
fn parent_hierarchy_is_composed_without_changing_raw_matrix_shear_or_thin_scale() {
    let mut input = raw_bindings("instance-one");
    let mut parent = Transform::identity();
    if let Transform::Trs { translation, .. } = &mut parent {
        translation[0] = 2.0;
    }
    input.nodes.insert(
        NodeId::new("parent").unwrap(),
        AnimationNodeBinding {
            parent: None,
            rest_local: parent,
            display_uuid: None,
            display_origin: [0.0; 3],
        },
    );
    input
        .nodes
        .get_mut(&NodeId::new("door").unwrap())
        .unwrap()
        .parent = Some(NodeId::new("parent").unwrap());
    let mut value = clip();
    value["tracks"][0]["interpolation"] = json!("baked_matrix");
    value["representation"] = json!("affine_part_tracks");
    let transform = json!({"kind":"matrix","layout":"row_major_column_vector","values":[-1,0.5,0,3,0,1,0,1,0,0,0.00005,0,0,0,0,1]});
    value["tracks"][0]["keys"][0]["transform"] = transform.clone();
    value["tracks"][0]["keys"][1]["transform"] = transform;
    let draft = animation_compile(
        &pin(value),
        &target(),
        &verified(input),
        &AuthoredEvidence,
        settings(20),
    )
    .unwrap();
    assert_eq!(draft.poses[0].matrix[3], 15.0);
    assert_eq!(draft.poses[0].matrix[0], -1.0);
    assert_eq!(draft.poses[0].matrix[1], 0.5);
    assert_eq!(draft.poses[0].matrix[10], 0.00005f32);
    assert!(draft.poses[0].max_component_error > 0.0);
}

#[test]
fn midpoint_rotation_uses_shortest_arc_quaternion_not_matrix_component_lerp() {
    let mut value = clip();
    value["tracks"][0]["keys"][1]["transform"]["rotationXyzw"] = json!([0, 1, 0, 0]);
    let draft = compile(value, 20);
    let midpoint = draft.poses.iter().find(|pose| pose.tick == 20).unwrap();
    assert!(midpoint.matrix[0].abs() < 1e-6);
    assert!((midpoint.matrix[2] - 1.0).abs() < 1e-6);
    assert!((midpoint.matrix[8] + 1.0).abs() < 1e-6);
    // A component-wise blend of endpoint rotation matrices would shrink these
    // axes to zero. The independently expected 90-degree matrix stays rigid.
    let x_length = midpoint.matrix[0]
        .hypot(midpoint.matrix[4])
        .hypot(midpoint.matrix[8]);
    assert!((x_length - 1.0).abs() < 1e-6);
    let mut value = clip();
    value["tracks"][0]["keys"][1]["transform"]["rotationXyzw"] = json!([0, 0, 0, -1]);
    let draft = compile(value, 20);
    assert!(
        draft
            .poses
            .iter()
            .all(|pose| pose.matrix[0] == 1.0 && pose.matrix[5] == 1.0 && pose.matrix[10] == 1.0)
    );
}

#[test]
fn exact_quantization_uses_ties_even_and_binary64_error_boundary_without_float_decisions() {
    let mut typed: AnimationClip = serde_json::from_value(clip()).unwrap();
    typed.sampling.tick_rounding = TickRounding::NearestEven;
    typed.sampling.max_time_error_seconds = 0.5;
    let mut records = Vec::new();
    for (numerator, expected) in [("1", 0), ("3", 2), ("5", 2)] {
        assert_eq!(
            quantize(
                &RationalTime::new(numerator, "2").unwrap(),
                &typed,
                &RationalTime::one(),
                "fixture",
                &mut records
            )
            .unwrap(),
            expected
        );
    }
    assert_eq!(
        records[0].absolute_error,
        RationalTime::new("1", "2").unwrap()
    );
    typed.sampling.max_time_error_seconds = f64::from_bits(0.5f64.to_bits() - 1);
    assert!(
        quantize(
            &RationalTime::new("1", "2").unwrap(),
            &typed,
            &RationalTime::one(),
            "fixture",
            &mut records
        )
        .is_err()
    );
    typed.sampling.tick_rounding = TickRounding::Exact;
    assert!(
        quantize(
            &RationalTime::new("1", "2").unwrap(),
            &typed,
            &RationalTime::one(),
            "fixture",
            &mut records
        )
        .is_err()
    );
    assert_eq!(
        exact_nonnegative_f64(f64::from_bits(1))
            .unwrap()
            .numerator()
            .as_str(),
        "1"
    );
    assert!(
        quantize(
            &RationalTime::new("9007199254740993", "1").unwrap(),
            &typed,
            &RationalTime::one(),
            "fixture",
            &mut records
        )
        .is_err()
    );
}

#[test]
fn reject_fractional_key_collisions_zero_duration_and_loop_period_drift() {
    let mut value = clip();
    value["sampling"]["tickRounding"] = json!("floor");
    value["sampling"]["maxTimeErrorSeconds"] = json!(0.05);
    value["tracks"][0]["keys"][1]["at"] = rational("1", "100");
    assert_eq!(error(value), "INVALID_TIME");
    let mut value = clip();
    value["duration"] = rational("1", "100");
    value["sampling"]["tickRounding"] = json!("floor");
    value["sampling"]["maxTimeErrorSeconds"] = json!(1);
    value["tracks"][0]["keys"] =
        json!([{"at":rational("0","1"),"transform":Transform::identity()}]);
    value["sampling"]["sampleTimes"] = json!([rational("0", "1"), rational("1", "100")]);
    assert_eq!(error(value), "INVALID_TIME");
    let mut value = clip();
    value["loop"] = json!(true);
    value["duration"] = rational("201", "100");
    value["sampling"]["tickRounding"] = json!("floor");
    value["sampling"]["maxTimeErrorSeconds"] = json!(0.05);
    value["sampling"]["sampleTimes"][2] = rational("201", "100");
    assert_eq!(error(value), "INVALID_TIME");
}

#[test]
fn raw_matrix_linear_negative_scale_nonanimation_writer_and_wall_time_fail_closed() {
    let mut value = clip();
    value["tracks"][0]["keys"][0]["transform"] = json!({"kind":"matrix","layout":"row_major_column_vector","values":[1,0.5,0,0,0,1,0,0,0,0,1,0,0,0,0,1]});
    assert_eq!(error(value), "UNSUPPORTED_TRANSFORM");
    let mut value = clip();
    value["tracks"][0]["keys"][0]["transform"]["scale"][0] = json!(-1);
    assert_eq!(error(value), "UNSUPPORTED_TRANSFORM");
    for (field, unsupported) in [
        ("timeDomain", json!("wall_seconds")),
        ("poseWriter", json!("native_body")),
        ("requiresBake", json!(true)),
    ] {
        let mut value = clip();
        value[field] = unsupported;
        assert_eq!(error(value), "UNOWNED_REQUIRED_CAPABILITY");
    }
}

#[test]
fn source_only_or_unbound_linear_event_witness_cannot_enable_compilation() {
    struct DisplayOnly;
    impl AnimationEvidenceVerifier for DisplayOnly {
        fn verify_animation_target(
            &self,
            _: &Sha256Digest,
            _: &Sha256Digest,
        ) -> Result<AnimationTargetRules, DomainError> {
            Ok(AnimationTargetRules {
                row_major_f32_matrix_codec: true,
                explicit_zero_disables_interpolation: true,
                sampled_linear_trs_whole_interval: true,
            })
        }
    }
    let result = animation_compile(
        &clip(),
        &target(),
        &verified(raw_bindings("instance-one")),
        &DisplayOnly,
        settings(20),
    );
    assert_eq!(result.unwrap_err().code, "UNSUPPORTED_TRANSFORM");
    let mut unequal_seam = clip();
    unequal_seam["tracks"][0]["interpolation"] = json!("step");
    unequal_seam["loop"] = json!(true);
    assert_eq!(
        animation_compile(
            &pin(unequal_seam),
            &target(),
            &verified(raw_bindings("instance-one")),
            &DisplayOnly,
            settings(20)
        )
        .unwrap_err()
        .code,
        "UNSUPPORTED_TRANSFORM"
    );
    let mut value = clip();
    value["tracks"][0]["interpolation"] = json!("step");
    value["events"] = json!([event("event-zero", "0", "1", 0, "start")]);
    assert_eq!(
        animation_compile(
            &pin(value),
            &target(),
            &verified(raw_bindings("instance-one")),
            &DisplayOnly,
            settings(20)
        )
        .unwrap_err()
        .code,
        "UNOWNED_REQUIRED_CAPABILITY"
    );
}

#[test]
fn independent_instance_and_clip_timers_pins_and_cleanup_are_disjoint() {
    let one = compile(clip(), 20);
    let two = animation_compile(
        &clip(),
        &target(),
        &verified(raw_bindings("instance-two")),
        &AuthoredEvidence,
        settings(20),
    )
    .unwrap();
    let mut value = clip();
    value["clipId"] = json!("clip-another");
    let another = compile(value, 20);
    assert_ne!(one.timer_objective(), two.timer_objective());
    assert_ne!(one.timer_objective(), another.timer_objective());
    assert_ne!(one.entry_points["cleanup"], two.entry_points["cleanup"]);
    assert_eq!(one.target_artifact_digest(), target().artifact_digest());
    assert!(
        one.referenced_functions()
            .iter()
            .all(|id| one.resources.contains_key(id) || one.external_functions.contains_key(id))
    );
    assert!(
        one.line_origins
            .iter()
            .all(|origin| one.resources.contains_key(&origin.function) && origin.line > 0)
    );
}

/// Executes only emitted vanilla control primitives, not the Rust schedule
/// algorithm. Unexpected grammar panics so an invented command is not ignored.
struct CommandOracle {
    functions: BTreeMap<String, Vec<String>>,
    scores: BTreeMap<(String, String), i32>,
    objectives: BTreeSet<String>,
    objective: String,
    events: Vec<String>,
    display_writes: Vec<String>,
    fail_function: Option<String>,
    event_callbacks: BTreeMap<String, String>,
    fail_after: BTreeMap<String, usize>,
    depth: usize,
}
impl CommandOracle {
    fn new(draft: &AnimationDraft) -> Self {
        Self {
            functions: draft
                .resources
                .iter()
                .map(|(id, source)| {
                    (
                        id.to_string(),
                        std::str::from_utf8(&source.bytes)
                            .unwrap()
                            .lines()
                            .map(str::to_owned)
                            .collect(),
                    )
                })
                .collect(),
            scores: BTreeMap::new(),
            objectives: BTreeSet::new(),
            objective: draft.objective.clone(),
            events: Vec::new(),
            display_writes: Vec::new(),
            fail_function: None,
            event_callbacks: BTreeMap::new(),
            fail_after: BTreeMap::new(),
            depth: 0,
        }
    }
    fn score(&self, holder: &str) -> Option<i32> {
        self.scores
            .get(&(holder.into(), self.objective.clone()))
            .copied()
    }
    fn set(&mut self, holder: &str, value: i32) {
        self.scores
            .insert((holder.into(), self.objective.clone()), value);
    }
    fn invoke(&mut self, draft: &AnimationDraft, part: &str) {
        self.function(draft.entry_points[part].as_str());
    }
    fn function(&mut self, id: &str) -> i32 {
        self.depth += 1;
        assert!(self.depth < 32, "unexpected recursive generated function");
        let output = if let Some(lines) = self.functions.get(id).cloned() {
            let mut output = 1;
            for command in lines {
                let (result, returned) = self.command(&command);
                if returned {
                    output = result;
                    break;
                }
            }
            output
        } else {
            assert!(id.starts_with("fixture:"));
            self.events.push(id.into());
            if let Some(callback) = self.event_callbacks.get(id).cloned() {
                self.function(&callback);
            }
            if self.fail_function.as_deref() == Some(id)
                || self.fail_after.get(id).is_some_and(|after| {
                    self.events
                        .iter()
                        .filter(|event| event.as_str() == id)
                        .count()
                        > *after
                })
            {
                0
            } else {
                1
            }
        };
        self.depth -= 1;
        output
    }
    fn command(&mut self, command: &str) -> (i32, bool) {
        let tokens: Vec<_> = command.split_whitespace().collect();
        if tokens[0] == "return" {
            return (tokens[1].parse().unwrap(), true);
        }
        if tokens[0] == "function" {
            return (self.function(tokens[1]), false);
        }
        if tokens[0] == "data" {
            assert_eq!(&tokens[..3], ["data", "merge", "entity"]);
            self.display_writes.push(command.to_owned());
            return (1, false);
        }
        if tokens[0] == "scoreboard" {
            match (tokens[1], tokens[2]) {
                ("objectives", "add") => {
                    return (i32::from(self.objectives.insert(tokens[3].into())), false);
                }
                ("objectives", "remove") => {
                    self.scores
                        .retain(|(_, objective), _| objective != tokens[3]);
                    return (i32::from(self.objectives.remove(tokens[3])), false);
                }
                ("players", "set") => {
                    if !self.objectives.contains(tokens[4]) {
                        return (0, false);
                    }
                    self.scores.insert(
                        (tokens[3].into(), tokens[4].into()),
                        tokens[5].parse().unwrap(),
                    );
                    return (1, false);
                }
                ("players", "add") => {
                    if !self.objectives.contains(tokens[4]) {
                        return (0, false);
                    }
                    let value = self
                        .scores
                        .entry((tokens[3].into(), tokens[4].into()))
                        .or_insert(0);
                    *value = value.checked_add(tokens[5].parse().unwrap()).unwrap();
                    return (1, false);
                }
                ("players", "operation") => {
                    if !self.objectives.contains(tokens[4]) {
                        return (0, false);
                    }
                    let Some(value) = self
                        .scores
                        .get(&(tokens[6].into(), tokens[7].into()))
                        .copied()
                    else {
                        return (0, false);
                    };
                    let address = (tokens[3].into(), tokens[4].into());
                    let current = self.scores.get(&address).copied().unwrap_or(0);
                    let result = match tokens[5] {
                        "=" => value,
                        "+=" => current.checked_add(value).unwrap(),
                        "-=" => current.checked_sub(value).unwrap(),
                        "*=" => current.checked_mul(value).unwrap(),
                        "/=" => {
                            assert!(
                                current >= 0 && value > 0,
                                "test oracle division covers positive exact tick accounting only"
                            );
                            current / value
                        }
                        op => panic!("Unexpected score operation {op}"),
                    };
                    self.scores.insert(address, result);
                    return (1, false);
                }
                _ => panic!("Unexpected scoreboard command {command}"),
            }
        }
        assert_eq!(tokens[0], "execute", "Unexpected command {command}");
        let mut index = 1;
        let mut store = None;
        while tokens[index] != "run" {
            match tokens[index] {
                "in" => {
                    assert_eq!(tokens[index + 1], "minecraft:overworld");
                    index += 2;
                }
                "if" | "unless" => {
                    let inverted = tokens[index] == "unless";
                    assert_eq!(tokens[index + 1], "score");
                    let left = self
                        .scores
                        .get(&(tokens[index + 2].into(), tokens[index + 3].into()))
                        .copied();
                    let (passed, width) = if tokens[index + 4] == "matches" {
                        (
                            left.is_some_and(|value| matches_range(value, tokens[index + 5])),
                            6,
                        )
                    } else {
                        let right = self
                            .scores
                            .get(&(tokens[index + 5].into(), tokens[index + 6].into()))
                            .copied();
                        let passed =
                            left.zip(right)
                                .is_some_and(|(a, b)| match tokens[index + 4] {
                                    "<" => a < b,
                                    "=" => a == b,
                                    op => panic!("Unexpected score comparison {op}"),
                                });
                        (passed, 7)
                    };
                    if passed == inverted {
                        return (0, false);
                    }
                    index += width;
                }
                "store" => {
                    assert_eq!(&tokens[index + 1..index + 3], ["result", "score"]);
                    store = Some((tokens[index + 3].to_owned(), tokens[index + 4].to_owned()));
                    index += 5;
                }
                token => panic!("Unexpected execute component {token}: {command}"),
            }
        }
        let remainder = tokens[index + 1..].join(" ");
        let (result, returned) = self.command(&remainder);
        if let Some(address) = store {
            self.scores.insert(address, result);
        }
        (result, returned)
    }
}
fn matches_range(value: i32, range: &str) -> bool {
    if let Some((start, end)) = range.split_once("..") {
        (start.is_empty() || value >= start.parse().unwrap())
            && (end.is_empty() || value <= end.parse().unwrap())
    } else {
        value == range.parse::<i32>().unwrap()
    }
}

#[test]
fn emitted_forward_crossing_orders_events_once_and_scrub_suppresses_effects() {
    let mut value = clip();
    value["events"] = json!([
        event("end", "2", "1", 0, "end"),
        event("later", "1", "1", 9, "late"),
        event("earlier", "1", "1", 3, "early"),
        event("start", "0", "1", 0, "start")
    ]);
    for tps in [20, 60] {
        let draft = compile(value.clone(), tps);
        let mut vm = CommandOracle::new(&draft);
        vm.invoke(&draft, "init");
        vm.invoke(&draft, "resume");
        assert_eq!(vm.score("#playing"), Some(0));
        vm.invoke(&draft, "play");
        assert_eq!(vm.events, vec!["fixture:start"]);
        vm.set("#cursor", tps + 1);
        vm.invoke(&draft, "advance");
        vm.invoke(&draft, "advance");
        assert_eq!(
            vm.events,
            vec!["fixture:start", "fixture:early", "fixture:late"]
        );
        vm.set("#seek", tps - 1);
        vm.invoke(&draft, "scrub");
        vm.invoke(&draft, "advance");
        assert_eq!(vm.events.len(), 3);
        vm.invoke(&draft, "resume");
        vm.invoke(&draft, "tick");
        assert_eq!(&vm.events[3..], ["fixture:early", "fixture:late"]);
        vm.set("#cursor", 2 * tps);
        vm.invoke(&draft, "advance");
        vm.invoke(&draft, "advance");
        assert_eq!(vm.events.last().unwrap(), "fixture:end");
        assert_eq!(vm.events.len(), 6);
        assert_eq!(vm.score("#playing"), Some(0));
    }
}

#[test]
fn emitted_loop_boundary_keeps_old_end_then_new_start_and_never_adds_an_extra_tick() {
    let mut value = clip();
    value["loop"] = json!(true);
    value["tracks"][0]["keys"][1]["transform"] = value["tracks"][0]["keys"][0]["transform"].clone();
    value["events"] = json!([
        event("start", "0", "1", 0, "start"),
        event("end", "2", "1", 0, "end")
    ]);
    let draft = compile(value, 20);
    let mut vm = CommandOracle::new(&draft);
    vm.invoke(&draft, "init");
    vm.invoke(&draft, "play");
    for _ in 0..40 {
        vm.invoke(&draft, "tick");
    }
    assert_eq!(
        vm.events,
        vec!["fixture:start", "fixture:end", "fixture:start"]
    );
    assert_eq!(vm.score("#iteration"), Some(1));
    assert_eq!(vm.score("#cursor"), Some(0));
    vm.invoke(&draft, "advance");
    assert_eq!(vm.events.len(), 3);
    vm.set("#seek", 40);
    vm.invoke(&draft, "scrub");
    vm.invoke(&draft, "advance");
    assert_eq!(vm.events.len(), 3);
    assert_eq!(vm.score("#iteration"), Some(1));
    vm.invoke(&draft, "play");
    vm.invoke(&draft, "stop");
    vm.invoke(&draft, "advance");
    assert_eq!(vm.events.len(), 4);
}

#[test]
fn emitted_invalid_rewind_iteration_and_overflow_fail_before_events() {
    let mut value = clip();
    value["loop"] = json!(true);
    value["tracks"][0]["keys"][1]["transform"] = value["tracks"][0]["keys"][0]["transform"].clone();
    value["events"] = json!([event("end", "2", "1", 0, "end")]);
    let draft = compile(value, 20);
    for iteration in [None, Some(-1), Some(i32::MAX)] {
        let mut vm = CommandOracle::new(&draft);
        vm.invoke(&draft, "init");
        vm.invoke(&draft, "play");
        vm.set("#cursor", 40);
        if let Some(iteration) = iteration {
            vm.set("#iteration", iteration);
        } else {
            vm.scores
                .remove(&("#iteration".into(), draft.objective.clone()));
        }
        vm.invoke(&draft, "advance");
        assert!(vm.events.is_empty());
        assert_eq!(vm.score("#error"), Some(1));
    }
    let mut vm = CommandOracle::new(&draft);
    vm.invoke(&draft, "init");
    vm.invoke(&draft, "play");
    vm.set("#from", 5);
    vm.set("#cursor", 4);
    vm.invoke(&draft, "advance");
    assert!(vm.events.is_empty());
    assert_eq!(vm.score("#from"), Some(5));
    assert_eq!(vm.score("#error"), Some(1));
}

#[test]
fn emitted_uncertain_event_preserves_taint_and_never_resends_or_removes_recovery_state() {
    let mut value = clip();
    value["events"] = json!([
        event("failed", "1", "1", 0, "faulty"),
        event("later", "1", "1", 1, "late")
    ]);
    let draft = compile(value, 20);
    let mut vm = CommandOracle::new(&draft);
    vm.fail_function = Some("fixture:faulty".into());
    vm.invoke(&draft, "init");
    vm.invoke(&draft, "play");
    vm.set("#cursor", 20);
    vm.invoke(&draft, "advance");
    assert_eq!(vm.events, vec!["fixture:faulty"]);
    assert_eq!(vm.score("#from"), Some(0));
    assert_eq!(vm.score("#tainted"), Some(1));
    for part in ["advance", "play", "resume", "scrub", "cleanup"] {
        vm.invoke(&draft, part);
    }
    assert_eq!(vm.events.len(), 1);
    assert_eq!(vm.score("#tainted"), Some(1));
    assert_eq!(vm.score("#error"), Some(1));
    assert_eq!(vm.score("#event_index"), Some(0));
    assert_eq!(vm.score("#event_run"), Some(1));
    assert_eq!(vm.score("#event_iteration"), Some(0));
    assert!(vm.objectives.contains(draft.timer_objective()));
}

#[test]
fn emitted_callback_controls_cannot_duplicate_dispatch_or_delete_uncertain_event_state() {
    let mut value = clip();
    value["events"] = json!([
        event("callback", "1", "1", 0, "early"),
        event("later", "1", "1", 1, "late")
    ]);
    let draft = compile(value, 20);
    for part in ["advance", "play", "scrub", "cleanup", "stop"] {
        let mut vm = CommandOracle::new(&draft);
        vm.event_callbacks
            .insert("fixture:early".into(), draft.entry_points[part].to_string());
        vm.invoke(&draft, "init");
        vm.invoke(&draft, "play");
        vm.set("#cursor", 20);
        vm.invoke(&draft, "advance");
        assert_eq!(
            vm.events
                .iter()
                .filter(|event| event.as_str() == "fixture:early")
                .count(),
            1
        );
        assert!(vm.objectives.contains(draft.timer_objective()));
        if matches!(part, "cleanup" | "stop") {
            assert_eq!(vm.events, vec!["fixture:early"]);
            assert_eq!(vm.score("#tainted"), Some(1));
            assert_eq!(vm.score("#error"), Some(1));
        } else {
            assert_eq!(vm.events, vec!["fixture:early", "fixture:late"]);
            assert_eq!(vm.score("#tainted"), Some(0));
        }
    }
}

#[test]
fn private_seam_callback_is_blocked_and_new_iteration_start_failure_cannot_resend() {
    let mut value = clip();
    value["loop"] = json!(true);
    value["tracks"][0]["keys"][1]["transform"] = value["tracks"][0]["keys"][0]["transform"].clone();
    value["events"] = json!([
        event("start", "0", "1", 0, "start"),
        event("end", "2", "1", 0, "end")
    ]);
    let draft = compile(value, 20);
    let boundary = draft
        .resources
        .keys()
        .find(|id| id.as_str().ends_with("/loop_boundary"))
        .unwrap()
        .to_string();
    let mut vm = CommandOracle::new(&draft);
    vm.event_callbacks.insert("fixture:end".into(), boundary);
    vm.invoke(&draft, "init");
    vm.invoke(&draft, "play");
    vm.set("#cursor", 40);
    vm.invoke(&draft, "advance");
    assert_eq!(
        vm.events,
        vec!["fixture:start", "fixture:end", "fixture:start"]
    );
    assert_eq!(vm.score("#iteration"), Some(1));
    let mut vm = CommandOracle::new(&draft);
    vm.fail_after.insert("fixture:start".into(), 1);
    vm.invoke(&draft, "init");
    vm.invoke(&draft, "play");
    vm.set("#cursor", 40);
    vm.invoke(&draft, "advance");
    assert_eq!(
        vm.events,
        vec!["fixture:start", "fixture:end", "fixture:start"]
    );
    assert_eq!(vm.score("#tainted"), Some(1));
    assert_eq!(vm.score("#event_index"), Some(0));
    assert_eq!(vm.score("#event_iteration"), Some(1));
    for part in ["advance", "play", "resume", "scrub", "cleanup"] {
        vm.invoke(&draft, part);
    }
    assert_eq!(vm.events.len(), 3);
    assert!(vm.objectives.contains(draft.timer_objective()));
}

#[test]
fn quantized_same_tick_events_preserve_authored_timestamp_order_before_sequence() {
    let mut value = clip();
    value["sampling"]["tickRounding"] = json!("floor");
    value["sampling"]["maxTimeErrorSeconds"] = json!(0.05);
    value["events"] = json!([
        event("first", "101", "100", 99, "early"),
        event("second", "51", "50", 0, "late")
    ]);
    let draft = compile(value, 20);
    assert_eq!(
        draft
            .events
            .iter()
            .map(|event| event.tick)
            .collect::<Vec<_>>(),
        vec![20, 20]
    );
    let mut vm = CommandOracle::new(&draft);
    vm.invoke(&draft, "init");
    vm.invoke(&draft, "play");
    vm.set("#cursor", 20);
    vm.invoke(&draft, "advance");
    assert_eq!(vm.events, vec!["fixture:early", "fixture:late"]);
}

#[test]
fn bounded_absolute_catchup_crosses_multiple_periods_and_commits_exact_elapsed_time() {
    let mut value = clip();
    value["loop"] = json!(true);
    value["tracks"][0]["interpolation"] = json!("step");
    value["tracks"][0]["keys"][1]["transform"] = value["tracks"][0]["keys"][0]["transform"].clone();
    value["events"] = json!([
        event("start", "0", "1", 0, "start"),
        event("middle", "1", "1", 0, "early"),
        event("end", "2", "1", 0, "end")
    ]);
    for tps in [20, 60] {
        let mut policy = settings(tps);
        policy.max_catchup_ticks = 256;
        let draft = animation_compile(
            &pin(value.clone()),
            &target(),
            &verified(raw_bindings("instance-one")),
            &AuthoredEvidence,
            policy,
        )
        .unwrap();
        let mut vm = CommandOracle::new(&draft);
        vm.invoke(&draft, "init");
        vm.invoke(&draft, "play");
        vm.set("#elapsed_request", 4 * tps + 5);
        vm.invoke(&draft, "catch_up");
        assert_eq!(
            vm.events,
            vec![
                "fixture:start",
                "fixture:early",
                "fixture:end",
                "fixture:start",
                "fixture:early",
                "fixture:end",
                "fixture:start"
            ]
        );
        assert_eq!(vm.score("#elapsed"), Some(4 * tps + 5));
        assert_eq!(vm.score("#iteration"), Some(2));
        assert_eq!(vm.score("#cursor"), Some(5));
        assert_eq!(vm.score("#from"), Some(5));
        assert_eq!(vm.score("#remaining"), Some(0));
        vm.invoke(&draft, "catch_up");
        assert_eq!(vm.events.len(), 7);
        vm.set("#elapsed_request", 4 * tps + 4);
        vm.invoke(&draft, "catch_up");
        assert_eq!(vm.events.len(), 7);
        assert_eq!(vm.score("#error"), Some(1));
        assert_eq!(vm.score("#elapsed"), Some(4 * tps + 5));
    }
}

#[test]
fn catchup_tick_event_overflow_and_uncommitted_local_jump_are_rejected_before_effects() {
    let mut value = clip();
    value["loop"] = json!(true);
    value["tracks"][0]["interpolation"] = json!("step");
    value["tracks"][0]["keys"][1]["transform"] = value["tracks"][0]["keys"][0]["transform"].clone();
    value["events"] = json!([event("middle", "1", "1", 0, "early")]);
    let mut policy = settings(20);
    policy.max_catchup_events = 2;
    let draft = animation_compile(
        &pin(value),
        &target(),
        &verified(raw_bindings("instance-one")),
        &AuthoredEvidence,
        policy,
    )
    .unwrap();
    for request in [3, 129] {
        let mut vm = CommandOracle::new(&draft);
        vm.invoke(&draft, "init");
        vm.invoke(&draft, "play");
        let writes = vm.display_writes.len();
        vm.set("#elapsed_request", request);
        vm.invoke(&draft, "catch_up");
        assert!(vm.events.is_empty());
        assert_eq!(vm.score("#elapsed"), Some(0));
        assert_eq!(vm.score("#cursor"), Some(0));
        assert_eq!(vm.score("#error"), Some(1));
        // Fault only disables interpolation, with no pose emitted after failure.
        assert!(
            vm.display_writes[writes..]
                .iter()
                .all(|line| !line.contains("transformation:"))
        );
    }
    let draft = compile(clip(), 20);
    let mut vm = CommandOracle::new(&draft);
    vm.invoke(&draft, "init");
    vm.invoke(&draft, "play");
    vm.set("#cursor", 20); // An authored local input was never committed by advance.
    vm.set("#elapsed_request", 40);
    vm.invoke(&draft, "catch_up");
    assert_eq!(vm.score("#elapsed"), Some(0));
    assert_eq!(vm.score("#from"), Some(0));
    assert_eq!(vm.score("#error"), Some(1));
    let mut vm = CommandOracle::new(&draft);
    vm.invoke(&draft, "init");
    vm.invoke(&draft, "play");
    vm.set("#elapsed", i32::MAX);
    vm.invoke(&draft, "tick");
    assert_eq!(vm.score("#elapsed"), Some(i32::MAX));
    assert_eq!(vm.score("#error"), Some(1));
}

#[test]
fn unequal_step_loop_preserves_terminal_hold_and_explicit_zero_pose_reset_with_witness() {
    let mut value = clip();
    value["loop"] = json!(true);
    value["tracks"][0]["interpolation"] = json!("step");
    value["tracks"][0]["keys"][1]["at"] = rational("3", "2");
    let draft = compile(value, 20);
    assert!(
        draft
            .runtime_dependencies()
            .iter()
            .any(|id| id == "mmmm:animation_unequal_loop_seam")
    );
    for tick in 0..30 {
        assert_eq!(
            draft
                .poses
                .iter()
                .find(|pose| pose.tick == tick)
                .unwrap()
                .matrix[7],
            1.0
        );
    }
    for tick in 30..=40 {
        assert_eq!(
            draft
                .poses
                .iter()
                .find(|pose| pose.tick == tick)
                .unwrap()
                .matrix[7],
            3.0
        );
    }
    let mut vm = CommandOracle::new(&draft);
    vm.invoke(&draft, "init");
    vm.invoke(&draft, "play");
    vm.set("#elapsed_request", 40);
    vm.invoke(&draft, "catch_up");
    assert_eq!(vm.score("#elapsed"), Some(40));
    assert_eq!(vm.score("#iteration"), Some(1));
    assert_eq!(vm.score("#cursor"), Some(0));
    assert!(
        vm.display_writes[vm.display_writes.len() - 2]
            .contains("transformation:[1f,0f,0f,13f,0f,1f,0f,3f,0f,0f,1f,0f,0f,0f,0f,1f]")
    );
    assert!(
        vm.display_writes
            .last()
            .unwrap()
            .contains("transformation:[1f,0f,0f,13f,0f,1f,0f,1f,0f,0f,1f,0f,0f,0f,0f,1f]")
    );
    assert!(
        vm.display_writes
            .iter()
            .all(|line| line.contains("interpolation_duration:0,start_interpolation:0"))
    );
}

fn scene_animation_fixture(
    tps: i32,
    mutate: impl FnOnce(&mut AnimationBindings),
) -> (Value, crate::scene::SceneDraft, AnimationDraft) {
    let (project, scene) = crate::scene::tests::animation_pack_fixture();
    let projection = scene.animation_bindings().values().next().unwrap();
    let mut input = AnimationBindings {
        instance_id: projection.instance_id.clone(),
        owner_prefab_id: projection.owner_prefab_id.clone(),
        world_id: projection.world_id.clone(),
        dimension: projection.dimension.clone(),
        instance_world: projection.instance_world.clone(),
        nodes: projection.nodes.clone(),
        events: BTreeMap::new(),
    };
    mutate(&mut input);
    let mut policy = settings(tps);
    policy.max_catchup_ticks = 8;
    let draft = animation_compile(
        &clip(),
        &target(),
        &verified(input),
        &AuthoredEvidence,
        policy,
    )
    .unwrap();
    (project, scene, draft)
}

fn animation_pack_inputs(
    project: &Value,
    scene: crate::scene::SceneDraft,
    animation: AnimationDraft,
) -> crate::PackBuildInputs {
    use crate::{PackBuildInputs, PackFunction, PackInstruction};
    let play = ResourceLocation::new("fixture:animation_play").unwrap();
    let tick = ResourceLocation::new("fixture:animation_tick").unwrap();
    let functions = vec![
        PackFunction {
            id: play.clone(),
            source_object_id: "clip-door".into(),
            instructions: vec![PackInstruction::Call(
                animation.entry_points()["play"].clone(),
            )],
        },
        PackFunction {
            id: tick.clone(),
            source_object_id: "clip-door".into(),
            instructions: vec![PackInstruction::Call(
                animation.entry_points()["tick"].clone(),
            )],
        },
    ];
    let covered = project["ownedResources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["objectId"].as_str().unwrap().to_owned())
        .collect();
    PackBuildInputs::new(
        project.clone(),
        functions,
        BTreeMap::from([("play".into(), play), ("tick".into(), tick)]),
        covered,
    )
    .with_scene(scene)
    .with_animation(animation)
}
fn animation_pack_request(project: &Value) -> Value {
    json!({"contextId":"animation-build-context","projectId":project["projectId"],
        "expectedRevision":project["revision"],"targetProfileId":"java-26.3","outputPolicy":"private_staging_only"})
}

#[test]
fn sealed_animation_pack_inherits_backend_effects_and_requires_exact_project_tps_scene_bindings() {
    let (project, scene, animation) = scene_animation_fixture(20, |_| {});
    let objective = animation.timer_objective().to_owned();
    let play = animation.entry_points()["play"].clone();
    let pack = crate::pack_build(
        &animation_pack_request(&project),
        &target(),
        animation_pack_inputs(&project, scene, animation),
    )
    .unwrap();
    assert_eq!(pack.manifest().validation_stage, "statically_checked");
    assert!(pack.manifest().defined_functions.contains(&play));
    assert!(
        pack.manifest()
            .runtime_dependencies
            .iter()
            .any(|id| id == "mmmm:animation_target_tps")
    );
    for id in ["fixture:animation_play", "fixture:animation_tick"] {
        let contracts = &pack.function_contracts()[&ResourceLocation::new(id).unwrap()];
        assert!(contracts.iter().any(|contract| {
            contract
                .state_writes
                .iter()
                .any(|state| state.contains(&objective))
        }));
        assert!(contracts.iter().any(|contract| {
            contract
                .state_writes
                .iter()
                .any(|state| state.contains("entity:"))
        }));
        assert!(contracts.iter().any(|contract| {
            contract
                .requirements
                .iter()
                .any(|requirement| requirement.contains("one pose writer"))
        }));
    }
    let (project, scene, animation) = scene_animation_fixture(30, |_| {});
    assert_eq!(
        crate::pack_build(
            &animation_pack_request(&project),
            &target(),
            animation_pack_inputs(&project, scene, animation)
        )
        .unwrap_err()
        .code,
        "STALE_CONTEXT"
    );
    for change_uuid in [false, true] {
        let (project, scene, animation) = scene_animation_fixture(20, |input| {
            let node = input.nodes.get_mut(&NodeId::new("door").unwrap()).unwrap();
            if change_uuid {
                node.display_uuid = Some("ffffffff-ffff-ffff-ffff-ffffffffffff".into());
            } else {
                node.display_origin[0] += 0.125;
            }
        });
        assert_eq!(
            crate::pack_build(
                &animation_pack_request(&project),
                &target(),
                animation_pack_inputs(&project, scene, animation)
            )
            .unwrap_err()
            .code,
            "STALE_CONTEXT"
        );
    }
}

#[test]
fn scrub_resets_absolute_request_and_corrupt_budget_constants_fail_closed() {
    let mut value = clip();
    value["events"] = json!([event("middle", "1", "1", 0, "early")]);
    let draft = compile(value, 20);
    let mut vm = CommandOracle::new(&draft);
    vm.invoke(&draft, "init");
    vm.invoke(&draft, "play");
    vm.set("#elapsed_request", 20);
    vm.invoke(&draft, "catch_up");
    assert_eq!(vm.events, vec!["fixture:early"]);
    vm.set("#seek", 5);
    vm.invoke(&draft, "scrub");
    assert_eq!(vm.score("#elapsed"), Some(5));
    assert_eq!(vm.score("#elapsed_request"), Some(5));
    vm.invoke(&draft, "resume");
    vm.invoke(&draft, "catch_up");
    assert_eq!(vm.events.len(), 1);
    assert_eq!(vm.score("#cursor"), Some(5));
    for holder in ["#event_count", "#i32max"] {
        for corrupted in [None, Some(0)] {
            let mut vm = CommandOracle::new(&draft);
            vm.invoke(&draft, "init");
            vm.invoke(&draft, "play");
            if let Some(value) = corrupted {
                vm.set(holder, value);
            } else {
                vm.scores.remove(&(holder.into(), draft.objective.clone()));
            }
            vm.set("#elapsed_request", 20);
            vm.invoke(&draft, "catch_up");
            assert!(vm.events.is_empty());
            assert_eq!(vm.score("#elapsed"), Some(0));
            assert_eq!(vm.score("#error"), Some(1));
        }
    }
}

#[test]
fn typed_call_adjacency_accounts_for_every_emitted_call_and_repeated_step() {
    let mut value = clip();
    value["events"] = json!([
        event("start", "0", "1", 0, "start"),
        event("end", "2", "1", 0, "end")
    ]);
    for looping in [false, true] {
        value["loop"] = json!(looping);
        let draft = compile(value.clone(), 20);
        for (id, resource) in draft.resources() {
            let mut emitted = BTreeMap::<String, usize>::new();
            for line in std::str::from_utf8(&resource.bytes).unwrap().lines() {
                let words: Vec<_> = line.split_whitespace().collect();
                for pair in words.windows(2) {
                    if pair[0] == "function" {
                        *emitted.entry(pair[1].into()).or_default() += 1;
                    }
                }
            }
            let mut declared = BTreeMap::<String, usize>::new();
            for callee in &draft.function_calls()[id] {
                *declared.entry(callee.to_string()).or_default() += 1;
            }
            assert_eq!(
                declared, emitted,
                "typed generated call graph lost a call or its multiplicity in {id}"
            );
        }
        let catchup = &draft.function_calls()[&draft.entry_points()["catch_up"]];
        assert_eq!(
            catchup
                .iter()
                .filter(|id| id.as_str().ends_with("/catchup_step"))
                .count(),
            usize::from(draft.max_catchup_ticks())
        );
    }
}

#[test]
fn local_advance_rejects_inconsistent_elapsed_iteration_and_initial_sentinel_before_events() {
    let mut value = clip();
    value["events"] = json!([event("middle", "1", "1", 0, "early")]);
    for looping in [false, true] {
        value["loop"] = json!(looping);
        let draft = compile(value.clone(), 20);
        for corrupt_sentinel in [false, true] {
            let mut vm = CommandOracle::new(&draft);
            vm.invoke(&draft, "init");
            vm.invoke(&draft, "play");
            if corrupt_sentinel {
                vm.set("#from", -1);
                vm.set("#elapsed", 1);
            } else if looping {
                vm.set("#iteration", 1);
            } else {
                vm.set("#elapsed", 1);
            }
            vm.set("#cursor", 20);
            vm.invoke(&draft, "advance");
            assert!(vm.events.is_empty());
            assert_eq!(vm.score("#error"), Some(1));
            assert_eq!(
                vm.score("#from"),
                Some(if corrupt_sentinel { -1 } else { 0 })
            );
        }
    }
}

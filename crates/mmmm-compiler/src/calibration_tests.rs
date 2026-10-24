//! These fixtures check the closed calibration source corpus, not target
//! admission or an actual run. Existing math fixtures accept an authored
//! VerifiedTarget and cannot detect a calibration program that skips its
//! named experiment, substitutes an expected constant, or observes cleanup.

use super::{
    CalibrationCase, CalibrationPackProgram, CalibrationProgram, CalibrationScalar,
    CalibrationSourceKind,
};
use crate::BindingAddress;
use mmmm_contracts::{Sha256Digest, raw_digest};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

// Kept independent of the production enum's ALL array: removing a required
// experiment from both construction and enumeration must still fail here.
const REQUIRED_IDS: [&str; 47] = [
    "int32_score_zero",
    "int32_nbt_min",
    "int32_nbt_max",
    "float_nbt_fraction",
    "float_binary32_chain",
    "int_div_negative",
    "int_floor_div_negative",
    "float_from_float_negative",
    "float_floor_then_from_float_negative",
    "int_add_overflow",
    "int_sub_overflow",
    "int_mul_overflow",
    "int_div_overflow",
    "int_floor_div_overflow",
    "int_div_zero",
    "int_floor_div_zero",
    "float_from_float_upper_range",
    "float_from_float_lower_range",
    "float_div_positive_zero",
    "float_div_zero_zero",
    "float_sqrt_negative",
    "float_mul_overflow",
    "float_undefined_provider",
    "score_present_zero_lazy_fallback",
    "float_storage_present_fraction_lazy_fallback",
    "score_absent_fallback",
    "float_storage_absent_fallback",
    "float_finite_zero_guard",
    "later_node_failure_cleanup",
    "native_compute_float_return_floor_vs_nbt",
    "float_signed_zero",
    "int_add_normal",
    "int_sub_normal",
    "int_mul_normal",
    "int_min_normal",
    "int_max_normal",
    "int_clamp_normal",
    "float_add_normal",
    "float_sub_normal",
    "float_mul_normal",
    "float_div_normal",
    "float_min_normal",
    "float_max_normal",
    "float_clamp_normal",
    "float_sin_zero",
    "float_cos_zero",
    "float_sqrt_four",
];

fn program(id: &str) -> CalibrationProgram {
    CalibrationProgram::for_case(CalibrationCase::from_case_id(id).expect("fixed suite case"))
        .expect("finite normative program")
}

fn evaluation(program: &CalibrationProgram) -> &[String] {
    &program.commands()[program.preseed_end_index() as usize..]
}

fn source(program: &CalibrationProgram) -> &str {
    std::str::from_utf8(program.source_bytes()).expect("UTF-8 native source")
}

fn producer<'a>(program: &'a CalibrationProgram, numeric: &str, op: &str) -> &'a str {
    let root_provider = format!("set compute default {numeric} {{type:\"minecraft:{op}\",");
    evaluation(program)
        .iter()
        .find(|command| command.contains(&root_provider))
        .map(String::as_str)
        .expect("named native operator must execute, rather than appear only in a fallback")
}

#[test]
fn calibration_corpus_is_exact_and_rejects_caller_labels() {
    let expected: BTreeSet<_> = REQUIRED_IDS.into_iter().collect();
    let actual: BTreeSet<_> = CalibrationCase::ALL
        .iter()
        .map(|case| case.case_id())
        .collect();
    assert_eq!(CalibrationCase::ALL.len(), 47);
    assert_eq!(actual, expected);
    for case in CalibrationCase::ALL {
        assert_eq!(CalibrationCase::from_case_id(case.case_id()), Some(*case));
    }
    for label in [
        "",
        "Int32ScoreZero",
        "int32_score_zero ",
        "int32_score_zero\nreturn 1",
        "../../int32_score_zero",
        "data_pack_pair_function_dependency_closure",
        "custom_success_case",
    ] {
        assert_eq!(CalibrationCase::from_case_id(label), None);
    }
}

#[test]
fn programs_are_deterministic_bounded_and_use_distinct_finite_private_addresses() {
    let mut digests = BTreeSet::new();
    let mut entries = BTreeSet::new();
    let mut objectives = BTreeSet::new();
    let mut storages = BTreeSet::new();
    for case in CalibrationCase::ALL {
        let first = CalibrationProgram::for_case(*case).unwrap();
        let second = CalibrationProgram::for_case(*case).unwrap();
        assert_eq!(first.case(), *case);
        assert_eq!(first.source_bytes(), second.source_bytes());
        assert_eq!(first.commands(), second.commands());
        assert_eq!(first.invocation_command(), second.invocation_command());
        assert_eq!(first.source_digest(), &raw_digest(first.source_bytes()));
        assert!(digests.insert(first.source_digest().as_str().to_owned()));
        assert!(entries.insert(first.invocation_command().to_owned()));
        assert!(
            first
                .invocation_command()
                .starts_with("function mmmm_calibration:")
        );
        assert!(first.source_bytes().len() <= 64 * 1024);
        assert!(first.source_bytes().ends_with(b"\n"));
        assert!(!first.source_bytes().contains(&b'\r'));
        assert!(first.commands().len() <= 128);
        assert!(first.commands().iter().all(|command| {
            !command.is_empty() && command.len() <= 8192 && !command.contains(['\r', '\n', '\0'])
        }));
        let executable: Vec<_> = source(&first)
            .lines()
            .filter(|line| !line.starts_with('#'))
            .collect();
        assert_eq!(
            executable,
            first
                .commands()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        );

        let scope = first.scope();
        assert!(objectives.insert(scope.objective().to_owned()));
        assert!(scope.objective().len() <= 16);
        assert!(
            scope
                .objective()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
        );
        assert!(storages.insert(scope.storage().as_str().to_owned()));
        assert_eq!(scope.scratch_path(), "invocation");
        let inputs: BTreeSet<_> = scope
            .input_addresses()
            .iter()
            .map(BindingAddress::description)
            .collect();
        assert_eq!(inputs.len(), scope.input_addresses().len());
        for address in scope.input_addresses() {
            match address {
                BindingAddress::Score { holder, objective } => {
                    assert!(holder.starts_with("#input"));
                    assert_eq!(objective, scope.objective());
                }
                BindingAddress::Storage { storage, path } => {
                    assert_eq!(storage, scope.storage());
                    assert!(path.starts_with("inputs.n"));
                }
            }
        }
        assert_eq!(
            first.initialization_commands(),
            &[format!(
                "scoreboard objectives add {} dummy",
                scope.objective()
            )]
        );
        assert_eq!(
            first.cleanup_commands(),
            &[
                format!("data remove storage {} inputs", scope.storage()),
                format!("data remove storage {} invocation", scope.storage()),
                format!("scoreboard objectives remove {}", scope.objective()),
            ]
        );
    }
}

#[test]
fn expectations_preserve_independent_score_int_tag_and_binary32_meanings() {
    use CalibrationScalar::{Absent, FloatTag, IntTag, Score};
    let successes = [
        ("int32_score_zero", Score(0)),
        ("int32_nbt_min", IntTag(i32::MIN)),
        ("int32_nbt_max", IntTag(i32::MAX)),
        ("float_nbt_fraction", FloatTag { bits: 0x3fa0_0000 }),
        ("float_binary32_chain", FloatTag { bits: 0 }),
        ("int_div_negative", Score(-3)),
        ("int_floor_div_negative", Score(-4)),
        ("float_from_float_negative", Score(-1)),
        ("float_floor_then_from_float_negative", Score(-2)),
        ("score_present_zero_lazy_fallback", Score(0)),
        (
            "float_storage_present_fraction_lazy_fallback",
            FloatTag { bits: 0x3fa0_0000 },
        ),
        ("float_finite_zero_guard", FloatTag { bits: 0 }),
        (
            "native_compute_float_return_floor_vs_nbt",
            FloatTag { bits: 0xbfc0_0000 },
        ),
        ("float_signed_zero", FloatTag { bits: 0x8000_0000 }),
        ("int_add_normal", Score(12)),
        ("int_sub_normal", Score(2)),
        ("int_mul_normal", Score(-12)),
        ("int_min_normal", Score(-3)),
        ("int_max_normal", Score(4)),
        ("int_clamp_normal", Score(5)),
        ("float_add_normal", FloatTag { bits: 0x3fe0_0000 }),
        ("float_sub_normal", FloatTag { bits: 0x3fa0_0000 }),
        ("float_mul_normal", FloatTag { bits: 0x4040_0000 }),
        ("float_div_normal", FloatTag { bits: 0x3fc0_0000 }),
        ("float_min_normal", FloatTag { bits: 0xbfc0_0000 }),
        ("float_max_normal", FloatTag { bits: 0x4000_0000 }),
        ("float_clamp_normal", FloatTag { bits: 0x40a0_0000 }),
        ("float_sin_zero", FloatTag { bits: 0 }),
        ("float_cos_zero", FloatTag { bits: 0x3f80_0000 }),
        ("float_sqrt_four", FloatTag { bits: 0x4000_0000 }),
    ];
    assert_eq!(successes.len(), 30);
    for id in REQUIRED_IDS {
        let built = program(id);
        let expected_output = successes
            .iter()
            .find_map(|(case_id, value)| (*case_id == id).then_some(*value))
            .unwrap_or(Absent);
        let expected_success = expected_output != Absent;
        let expectation = built.expectation();
        assert_eq!(expectation.output, expected_output, "{id}");
        assert_eq!(expectation.command_success, expected_success, "{id}");
        assert_eq!(expectation.ok_score, i32::from(expected_success), "{id}");
        assert_eq!(expectation.scratch_present, expected_success, "{id}");
        assert_eq!(expectation.preseed_score, 7331);
        assert_eq!(
            expectation.preseed_storage,
            FloatTag {
                bits: 7331f32.to_bits()
            }
        );
        assert_eq!(built.expected_readback()["staleOutputSeeded"], json!(true));
        if let FloatTag { bits } = expected_output {
            assert_eq!(
                built.expected_readback()["output"],
                json!({"kind":"float_tag","bits":format!("{bits:08x}")})
            );
        }
    }
    // Equal numeric values have distinct presence/tag identities.
    assert_ne!(Score(0), Absent);
    assert_ne!(Score(0), IntTag(0));
    assert_ne!(FloatTag { bits: 0 }, FloatTag { bits: 0x8000_0000 });
}

#[test]
fn operators_execute_dynamic_inputs_with_distinct_negative_semantics() {
    let div = program("int_div_negative");
    let floor = program("int_floor_div_negative");
    let trunc = program("float_from_float_negative");
    let float_floor = program("float_floor_then_from_float_negative");
    assert!(producer(&div, "integer", "div").contains("path:\"invocation.n0\""));
    assert!(producer(&floor, "integer", "floor_div").contains("path:\"invocation.n0\""));
    assert!(!producer(&trunc, "integer", "from_float").contains("minecraft:floor\""));
    assert!(producer(&float_floor, "integer", "from_float").contains("minecraft:floor\""));
    let preflight = div
        .commands()
        .iter()
        .position(|line| {
            line.contains("run compute default integer {type:\"minecraft:floor_div\",")
        })
        .unwrap();
    let actual_div = div
        .commands()
        .iter()
        .position(|line| line.contains("set compute default integer {type:\"minecraft:div\","))
        .unwrap();
    assert!(preflight < actual_div);

    for (id, numeric, operator) in [
        ("int_add_normal", "integer", "add"),
        ("int_sub_normal", "integer", "sub"),
        ("int_mul_normal", "integer", "mul"),
        ("int_min_normal", "integer", "min"),
        ("int_max_normal", "integer", "max"),
        ("int_clamp_normal", "integer", "min"),
        ("float_add_normal", "float", "add"),
        ("float_sub_normal", "float", "sub"),
        ("float_mul_normal", "float", "mul"),
        ("float_div_normal", "float", "div"),
        ("float_min_normal", "float", "min"),
        ("float_max_normal", "float", "max"),
        ("float_clamp_normal", "float", "min"),
        ("float_sin_zero", "float", "sin"),
        ("float_cos_zero", "float", "cos"),
        ("float_sqrt_four", "float", "sqrt"),
    ] {
        let built = program(id);
        let command = producer(&built, numeric, operator);
        assert!(command.contains("type:\"minecraft:storage\""), "{id}");
        if id.contains("clamp") {
            assert!(command.contains("type:\"minecraft:max\""));
        }
    }

    for (id, numeric, operator) in [
        ("int_add_overflow", "integer", "add"),
        ("int_sub_overflow", "integer", "sub"),
        ("int_mul_overflow", "integer", "mul"),
        ("int_div_overflow", "integer", "div"),
        ("int_floor_div_overflow", "integer", "floor_div"),
        ("int_div_zero", "integer", "div"),
        ("int_floor_div_zero", "integer", "floor_div"),
        ("float_from_float_upper_range", "integer", "from_float"),
        ("float_from_float_lower_range", "integer", "from_float"),
        ("float_div_positive_zero", "float", "div"),
        ("float_div_zero_zero", "float", "div"),
        ("float_sqrt_negative", "float", "sqrt"),
        ("float_mul_overflow", "float", "mul"),
        ("later_node_failure_cleanup", "integer", "div"),
    ] {
        let built = program(id);
        let command = producer(&built, numeric, operator);
        assert!(command.contains("type:\"minecraft:storage\""), "{id}");
        assert!(command.contains("path:\"invocation.n"), "{id}");
        assert_eq!(
            built.expectation().output,
            CalibrationScalar::Absent,
            "{id}"
        );
    }
    // Divisor 0 and sqrt(-1) themselves remain dynamic native reads.
    let zero = program("int_div_zero");
    assert!(
        zero.commands()[..zero.preseed_end_index() as usize]
            .iter()
            .any(|line| line.ends_with("inputs.n1 set value 0"))
    );
    let sqrt = program("float_sqrt_negative");
    assert!(
        sqrt.commands()[..sqrt.preseed_end_index() as usize]
            .iter()
            .any(|line| line.ends_with("inputs.n0 set value -1f"))
    );
}

#[test]
fn binary32_spills_and_finite_zero_success_are_observed_separately_from_return() {
    let built = program("float_binary32_chain");
    let add = producer(&built, "float", "add");
    let sub = producer(&built, "float", "sub");
    assert!(add.contains("invocation.n2 set compute default float"));
    assert!(sub.contains("left:{type:\"minecraft:storage\""));
    assert!(sub.contains("path:\"invocation.n2\""));
    assert!(sub.contains("path:\"invocation.n0\""));

    let finite = program("float_finite_zero_guard");
    let stage = &finite.commands()[finite.command_stage_index() as usize];
    assert!(stage.contains("store success score #ok"));
    assert!(!stage.contains("store result score #ok"));
    assert!(stage.contains(
        "run compute default integer {type:\"minecraft:from_float\",input:{type:\"minecraft:mul\""
    ));
    assert!(stage.contains("path:\"invocation.n0\""));
    assert!(stage.contains("0.0f"));
    assert_eq!(finite.expectation().command_return, Some(0));
    assert!(finite.expectation().command_success);
    assert_eq!(finite.expectation().ok_score, 1);

    let float_return = program("native_compute_float_return_floor_vs_nbt");
    let stage = &float_return.commands()[float_return.command_stage_index() as usize];
    assert!(stage.contains("run compute default float"));
    assert!(stage.ends_with(" 1.0"));
    assert_eq!(float_return.expectation().command_return, Some(-2));
    assert_eq!(
        float_return.expectation().output,
        CalibrationScalar::FloatTag { bits: 0xbfc0_0000 }
    );
    let negative_zero = program("float_signed_zero");
    assert!(
        negative_zero
            .commands()
            .iter()
            .any(|line| line.ends_with("inputs.n0 set value -0f"))
    );
    assert_ne!(negative_zero.source_bytes(), finite.source_bytes());
    assert_ne!(negative_zero.source_digest(), finite.source_digest());
}

#[test]
fn lazy_fallback_corpus_distinguishes_existing_zero_fraction_and_absence() {
    for (present_id, absent_id, is_score) in [
        (
            "score_present_zero_lazy_fallback",
            "score_absent_fallback",
            true,
        ),
        (
            "float_storage_present_fraction_lazy_fallback",
            "float_storage_absent_fallback",
            false,
        ),
    ] {
        let present = program(present_id);
        let absent = program(absent_id);
        let present_prefix = &present.commands()[..present.preseed_end_index() as usize];
        let absent_prefix = &absent.commands()[..absent.preseed_end_index() as usize];
        if is_score {
            assert!(
                present_prefix
                    .iter()
                    .any(|line| line.starts_with("scoreboard players set #input0 ")
                        && line.ends_with(" 0"))
            );
            assert!(
                absent_prefix
                    .iter()
                    .any(|line| line.starts_with("scoreboard players reset #input0 "))
            );
        } else {
            assert!(
                present_prefix
                    .iter()
                    .any(|line| line.ends_with("inputs.n0 set value 1.25f"))
            );
            assert!(absent_prefix.iter().any(
                |line| line.ends_with(" inputs.n0") && line.starts_with("data remove storage ")
            ));
        }
        for built in [&present, &absent] {
            let read = evaluation(built)
                .iter()
                .find(|line| line.contains("invocation.n0 set compute default"))
                .unwrap();
            assert!(read.contains("fallback:{type:\"minecraft:"));
            if is_score {
                assert!(read.contains("type:\"minecraft:score\""));
                assert!(read.contains("fallback:{type:\"minecraft:div\",left:1,right:0}"));
            } else {
                assert!(read.contains("type:\"minecraft:storage\""));
                assert!(read.contains("fallback:{type:\"minecraft:from_int\",input:{type:\"minecraft:div\",left:1,right:0}}"));
            }
            assert!(!evaluation(built).iter().any(|line| {
                line.ends_with(
                    "run compute default integer {type:\"minecraft:div\",left:1,right:0}",
                )
            }));
        }
        assert!(present.expectation().command_success);
        assert!(!absent.expectation().command_success);
        assert_ne!(present.expectation().output, absent.expectation().output);
    }
}

#[test]
fn preseed_evaluation_observation_and_failure_cleanup_have_required_order() {
    for case in CalibrationCase::ALL {
        let built = CalibrationProgram::for_case(*case).unwrap();
        let commands = built.commands();
        let barrier = built.preseed_end_index() as usize;
        let stage = built.command_stage_index() as usize;
        let objective = built.scope().objective();
        let storage = built.scope().storage();
        assert!(barrier > 0 && barrier < stage && stage < commands.len() - 1);
        assert!(
            commands[..barrier]
                .contains(&format!("scoreboard players set #result {objective} 7331"))
        );
        assert!(commands[..barrier].contains(&format!(
            "data modify storage {storage} invocation set value {{stale:1b,result:7331f}}"
        )));
        assert_eq!(
            commands[barrier],
            format!("data remove storage {storage} invocation")
        );
        assert_eq!(
            commands[barrier + 1],
            format!("scoreboard players reset #result {objective}")
        );
        assert_eq!(
            commands[barrier + 2],
            format!("scoreboard players set #ok {objective} 1")
        );
        assert!(commands[stage].starts_with(&format!(
            "execute if score #ok {objective} matches 1 store success score #ok {objective}"
        )));
        assert!(commands[stage].contains("compute default"));
        assert!(!commands[stage].contains(" run data remove "));
        assert!(!commands[stage].contains("run scoreboard players reset"));
        assert_eq!(
            commands.last().unwrap(),
            &format!(
                "execute unless score #ok {objective} matches 1 run data remove storage {storage} invocation"
            )
        );
        if matches!(built.scope().result_address(), BindingAddress::Score { .. }) {
            assert!(commands.iter().any(|line| line.contains(&format!(
                "store success score #ok {objective} store result score #result {objective}"
            ))));
            assert!(commands.contains(&format!("execute unless score #ok {objective} matches 1 run scoreboard players reset #result {objective}")));
        }
        if !built.expectation().command_success {
            assert_eq!(built.expectation().ok_score, 0);
            assert_eq!(built.expectation().output, CalibrationScalar::Absent);
            assert!(!built.expectation().scratch_present);
        }
    }
    let later = program("later_node_failure_cleanup");
    let successful_write = later
        .commands()
        .iter()
        .position(|line| {
            line.contains("invocation.n2 set compute default integer {type:\"minecraft:add\"")
        })
        .unwrap();
    let failing_read = later.command_stage_index() as usize;
    assert!(successful_write < failing_read);
    assert!(later.commands()[failing_read].contains("path:\"invocation.n2\""));
    assert!(later.commands()[failing_read].contains("path:\"invocation.n1\""));
}

#[test]
fn private_source_kinds_keep_numeric_and_pack_recipes_separate() {
    let numeric = CalibrationSourceKind::Numeric47;
    let pack = CalibrationSourceKind::PackCase;
    assert_eq!(
        (
            numeric.name(),
            numeric.entry_count(),
            numeric.function_count()
        ),
        ("numeric47", 48, 47)
    );
    assert_eq!(
        (pack.name(), pack.entry_count(), pack.function_count()),
        ("pack_case", 3, 2)
    );
    assert_eq!(numeric.root_basename(), "mmmm-calibration-normative47");
    assert_eq!(pack.root_basename(), "mmmm-calibration-pack-case");
    let numeric_entries = numeric.source_entries().unwrap();
    let pack_entries = pack.source_entries().unwrap();
    assert_eq!(numeric_entries.len(), numeric.entry_count());
    assert_eq!(pack_entries.len(), pack.entry_count());
    assert_eq!(
        pack_entries,
        *CalibrationPackProgram::java_26_3()
            .unwrap()
            .source_entries()
    );
    assert!(!numeric_entries.contains_key("data/mmmm_calibration/function/pack/entry.mcfunction"));
    assert!(pack_entries.contains_key("data/mmmm_calibration/function/pack/entry.mcfunction"));
    assert_ne!(numeric_entries, pack_entries);
}

fn logical_pack_digest(entries: &BTreeMap<String, Vec<u8>>) -> Sha256Digest {
    let mut framed = Vec::new();
    for (path, bytes) in entries {
        framed.extend_from_slice(&(path.len() as u64).to_le_bytes());
        framed.extend_from_slice(path.as_bytes());
        framed.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        framed.extend_from_slice(bytes);
    }
    raw_digest(&framed)
}

#[test]
fn pack_program_has_native_pair_codec_singular_paths_and_complete_owned_dispatch() {
    let built = CalibrationPackProgram::java_26_3().unwrap();
    let again = CalibrationPackProgram::java_26_3().unwrap();
    assert_eq!(
        raw_digest(built.canonical_recipe_bytes()),
        *built.program_digest()
    );
    assert_eq!(
        built.canonical_recipe_bytes(),
        again.canonical_recipe_bytes()
    );
    let paths: BTreeSet<_> = built.source_entries().keys().map(String::as_str).collect();
    assert_eq!(
        paths,
        [
            "pack.mcmeta",
            "data/mmmm_calibration/function/pack/entry.mcfunction",
            "data/mmmm_calibration/function/pack/dependency.mcfunction",
        ]
        .into()
    );
    let meta: serde_json::Value =
        serde_json::from_slice(&built.source_entries()["pack.mcmeta"]).unwrap();
    assert_eq!(meta["pack"]["min_format"], json!([121, 0]));
    assert_eq!(meta["pack"]["max_format"], json!([121, 0]));
    assert!(meta["pack"].get("pack_format").is_none());
    assert_eq!(built.source_entries(), again.source_entries());
    assert_eq!(
        built.program_digest(),
        &logical_pack_digest(built.source_entries())
    );
    assert_eq!(
        built.invocation_command(),
        "function mmmm_calibration:pack/entry"
    );
    assert_eq!(
        built.commands()[built.command_stage_index() as usize],
        "function mmmm_calibration:pack/dependency"
    );
    assert_eq!(built.commands().last().unwrap(), "return 1");
    let expected_functions: BTreeSet<String> = [
        "mmmm_calibration:pack/entry".to_owned(),
        "mmmm_calibration:pack/dependency".to_owned(),
    ]
    .into();
    assert_eq!(built.function_ids(), &expected_functions);
    for function in built.function_ids() {
        let (namespace, path) = function.split_once(':').unwrap();
        let entry_path = format!("data/{namespace}/function/{path}.mcfunction");
        let bytes = &built.source_entries()[&entry_path];
        assert!(bytes.len() <= 64 * 1024);
        let function_source = std::str::from_utf8(bytes).unwrap();
        assert!(function_source.ends_with("return 1\n"));
        for line in function_source.lines() {
            if let Some(callee) = line.strip_prefix("function ") {
                assert!(built.function_ids().contains(callee));
            }
        }
    }
    let dependency =
        &built.source_entries()["data/mmmm_calibration/function/pack/dependency.mcfunction"];
    assert!(
        std::str::from_utf8(dependency)
            .unwrap()
            .contains("scoreboard players set #marker mcalpack 1337\n")
    );
    assert_eq!(
        built.marker_address(),
        &BindingAddress::Score {
            holder: "#marker".into(),
            objective: "mcalpack".into()
        }
    );
    assert_eq!(
        built.initialization_commands(),
        &[
            "scoreboard objectives add mcalpack dummy".to_owned(),
            "scoreboard players set #marker mcalpack 7331".to_owned()
        ]
    );
    assert_eq!(
        built.commands()[0],
        "scoreboard players reset #marker mcalpack"
    );
    assert_eq!(
        built.cleanup_commands(),
        &["scoreboard objectives remove mcalpack".to_owned()]
    );

    // An export copy may be edited, but it cannot rebind the normative source
    // or its identity. Logical entry identity is separate from ZIP bytes.
    let mut exported = built.source_entries().clone();
    exported
        .get_mut("data/mmmm_calibration/function/pack/dependency.mcfunction")
        .unwrap()
        .extend_from_slice(b"# changed export copy\n");
    assert_ne!(logical_pack_digest(&exported), *built.program_digest());
    assert_eq!(built.source_entries(), again.source_entries());
    assert_eq!(built.program_digest(), again.program_digest());
}

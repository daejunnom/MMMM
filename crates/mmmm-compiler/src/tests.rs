//! These authored compiler witnesses are deliberately not runtime target
//! evidence. New fixtures are needed because the original package has no math
//! DAG or generated pack examples, and MC01–03/11 require numeric failures and
//! complete internal function closure beyond JSON shape validation.

use super::*;
use mmmm_contracts::{
    ResourceId, ResourceLocation, Sha256Digest, StateId, SymbolId, projected_digest, raw_digest,
};
use mmmm_domain::{DomainError, types::ResourceRef};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

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
impl SymbolTableVerifier for AuthoredEvidence {
    fn verify_symbols(
        &self,
        _: &ResourceRef,
        bytes: &[u8],
        _: &BTreeMap<StateId, SymbolBinding>,
        _: &BTreeMap<ContextComponent, SymbolBinding>,
    ) -> Result<Sha256Digest, DomainError> {
        Ok(raw_digest(bytes))
    }
}

fn profile() -> Value {
    let mut value: Value =
        serde_json::from_slice(include_bytes!("../../../examples/version-profile.json")).unwrap();
    // An explicitly authored private verifier fixture, never published in the
    // runtime registry or used to enable product profile support.
    value["validationStatus"] = json!("runtime_verified");
    value["writeSupport"] = json!("verified");
    value["artifactSha256"] = json!("11".repeat(32));
    value["testedLoaders"] = json!(["authored-test-only"]);
    value["evidenceResourceIds"] = json!(["authored-test-only"]);
    value["javaMajor"] = json!(25);
    value
}
fn target() -> VerifiedTarget {
    VerifiedTarget::verify(&profile(), &AuthoredEvidence).unwrap()
}
fn resource() -> ResourceRef {
    ResourceRef {
        resource_id: ResourceId::new("math-symbols").unwrap(),
        sha256: raw_digest(b"authored-symbol-bindings"),
        media_type: "application/json".into(),
        size_bytes: b"authored-symbol-bindings".len() as u64,
    }
}
fn symbols() -> ResolvedSymbols {
    ResolvedSymbols::verify(
        resource(),
        b"authored-symbol-bindings",
        BTreeMap::new(),
        BTreeMap::new(),
        &AuthoredEvidence,
    )
    .unwrap()
}
fn request(nodes: Vec<Value>, root: &str, storage: &str, rounding: &str) -> Value {
    json!({"nodes": nodes, "rootExprId": root, "targetProfileId": "java-26.3",
        "outputStorage": storage, "rounding": rounding, "symbolTable": resource()})
}
fn constant(id: &str, value: Value, kind: &str, unit: &str) -> Value {
    json!({"exprId": id, "op": "constant", "type": kind, "unit": unit, "inputs": [], "value": value})
}
fn operation(id: &str, op: &str, inputs: &[&str], kind: &str, unit: &str) -> Value {
    json!({"exprId": id, "op": op, "type": kind, "unit": unit, "inputs": inputs})
}
fn source(draft: &CompiledFragmentDraft) -> &str {
    std::str::from_utf8(&draft.source().bytes).unwrap()
}
fn error(request: &Value) -> &'static str {
    math_compile(request, &target(), &symbols())
        .unwrap_err()
        .code
}

#[test]
fn original_reference_profile_cannot_enable_compiler() {
    let original: Value =
        serde_json::from_slice(include_bytes!("../../../examples/version-profile.json")).unwrap();
    assert_eq!(
        VerifiedTarget::verify(&original, &AuthoredEvidence)
            .unwrap_err()
            .code,
        "UNSUPPORTED_TARGET_VERSION"
    );
    let mut patch = profile();
    patch["gameVersion"] = json!("26.3.1");
    assert_eq!(
        VerifiedTarget::verify(&patch, &AuthoredEvidence)
            .unwrap_err()
            .code,
        "UNSUPPORTED_TARGET_VERSION"
    );
}

#[test]
fn pure_entrypoint_rejects_oversized_contract_before_decoding_clone() {
    // The transport bound alone cannot protect an in-process library caller.
    // Original examples do not contain an oversized wire object.
    let oversized = json!({"padding":"x".repeat(8 * 1024 * 1024)});
    assert_eq!(
        decode::<Value>("MathCompileRequest", &oversized)
            .unwrap_err()
            .code,
        "NUMERIC_RANGE"
    );
}

#[test]
fn verified_pack_format_accepts_equivalent_mathematical_integer_lexemes() {
    let original = profile();
    let mut decimal = original.clone();
    for field in ["dataPackVersion", "resourcePackVersion"] {
        if decimal[field].is_object() {
            for component in ["major", "minor"] {
                let integer = decimal[field][component].as_u64().unwrap();
                decimal[field][component] = json!(integer as f64);
            }
        }
    }
    let integer = VerifiedTarget::verify(&original, &AuthoredEvidence).unwrap();
    let decimal = VerifiedTarget::verify(&decimal, &AuthoredEvidence).unwrap();
    assert_eq!(integer.profile_digest(), decimal.profile_digest());
    assert_eq!(
        integer.pack_version().unwrap(),
        decimal.pack_version().unwrap()
    );
    assert_eq!(
        integer.resource_pack_version(),
        decimal.resource_pack_version()
    );
}

#[test]
fn runtime_rule_failure_is_not_hidden_by_profile_claims() {
    struct Reject;
    impl TargetEvidenceVerifier for Reject {
        fn verify_target(
            &self,
            _: &Value,
            _: &Sha256Digest,
            _: &Sha256Digest,
        ) -> Result<TargetRuntimeRules, DomainError> {
            Err(DomainError::new(
                "EVIDENCE_UNVERIFIED",
                "fixture verifier refuses caller claims",
            ))
        }
    }
    assert_eq!(
        VerifiedTarget::verify(&profile(), &Reject)
            .unwrap_err()
            .code,
        "EVIDENCE_UNVERIFIED"
    );
}

#[test]
fn deterministic_int_fragment_has_exact_native_source_and_declared_state() {
    let input = request(
        vec![constant("answer", json!(42), "int32", "unitless")],
        "answer",
        "scoreboard",
        "none",
    );
    let first = math_compile(&input, &target(), &symbols()).unwrap();
    let second = math_compile(&input, &target(), &symbols()).unwrap();
    assert_eq!(first.source().bytes, second.source().bytes);
    assert_eq!(
        first.source().reference.sha256,
        raw_digest(&first.source().bytes)
    );
    assert!(source(&first).contains("set compute default integer 42\n"));
    assert!(source(&first).contains("store success score #ok"));
    assert!(source(&first).contains("store result score #result"));
    assert_eq!(first.fragment().defined_symbols.len(), 1);
    assert!(first.fragment().referenced_symbols.is_empty());
    assert_eq!(
        first.function_contract().reentrancy,
        "forbidden_requires_serialized_invocation"
    );
    assert!(!first.function_contract().cleanup.is_empty());
    first.to_wire().unwrap();
}

#[test]
fn signed_zero_source_bytes_have_distinct_exact_input_pins() {
    let positive = request(
        vec![constant("zero", json!(0.0), "float32", "unitless")],
        "zero",
        "storage_nbt",
        "none",
    );
    let negative = request(
        vec![constant("zero", json!(-0.0), "float32", "unitless")],
        "zero",
        "storage_nbt",
        "none",
    );
    assert_eq!(
        mmmm_contracts::canonical_digest(&positive).unwrap(),
        mmmm_contracts::canonical_digest(&negative).unwrap()
    );
    let positive = math_compile(&positive, &target(), &symbols()).unwrap();
    let negative = math_compile(&negative, &target(), &symbols()).unwrap();
    assert_ne!(positive.pins().input_digest, negative.pins().input_digest);
    assert_ne!(
        positive.source().reference.resource_id,
        negative.source().reference.resource_id
    );
    assert!(source(&negative).contains("set compute default float -0f"));
}

#[test]
fn generated_call_wrappers_inherit_function_contracts_and_bound_expansion() {
    let fragment = math_compile(
        &request(
            vec![constant("answer", json!(42), "int32", "unitless")],
            "answer",
            "scoreboard",
            "none",
        ),
        &target(),
        &symbols(),
    )
    .unwrap();
    let root = project();
    let inputs = PackBuildInputs::new(
        root.clone(),
        vec![
            function(
                "fixture:math",
                vec![PackInstruction::Math(Box::new(fragment))],
            ),
            function(
                "fixture:run",
                vec![PackInstruction::Call(
                    ResourceLocation::new("fixture:math").unwrap(),
                )],
            ),
        ],
        BTreeMap::from([("run".into(), ResourceLocation::new("fixture:run").unwrap())]),
        BTreeSet::new(),
    );
    let pack = pack_build(&build_request(&root), &target(), inputs).unwrap();
    assert_eq!(
        pack.function_contracts()[&ResourceLocation::new("fixture:run").unwrap()].len(),
        1
    );
    assert!(
        !pack.function_contracts()[&ResourceLocation::new("fixture:run").unwrap()][0]
            .outputs
            .is_empty()
    );
    let mut functions = vec![function("fixture:n0", Vec::new())];
    for index in 1..=17 {
        let previous = ResourceLocation::new(format!("fixture:n{}", index - 1)).unwrap();
        functions.push(function(
            &format!("fixture:n{index}"),
            vec![
                PackInstruction::Call(previous.clone()),
                PackInstruction::Call(previous),
            ],
        ));
    }
    let inputs = PackBuildInputs::new(
        root.clone(),
        functions,
        BTreeMap::from([("run".into(), ResourceLocation::new("fixture:n17").unwrap())]),
        BTreeSet::new(),
    );
    assert_eq!(
        pack_build(&build_request(&root), &target(), inputs)
            .unwrap_err()
            .code,
        "NUMERIC_RANGE"
    );
}

#[test]
fn contract_byte_budget_rejects_heavy_wrapper_clones_before_materialization() {
    let mut fragment = math_compile(
        &request(
            vec![constant("answer", json!(42), "int32", "unitless")],
            "answer",
            "scoreboard",
            "none",
        ),
        &target(),
        &symbols(),
    )
    .unwrap();
    // An internal fixture models the size of thousands of legitimate storage
    // addresses, without cloning thousands of source programs or relying on an
    // allocation failure to demonstrate the bug.
    fragment.contract.state_reads = (0..4096)
        .map(|index| format!("storage:fixture:source:{}:{index}", "a".repeat(500)))
        .collect();
    let mut functions = vec![function(
        "fixture:heavy",
        vec![PackInstruction::Math(Box::new(fragment))],
    )];
    for index in 0..4 {
        functions.push(function(
            &format!("fixture:wrapper{index}"),
            vec![PackInstruction::Call(
                ResourceLocation::new("fixture:heavy").unwrap(),
            )],
        ));
    }
    let root = project();
    let inputs = PackBuildInputs::new(
        root.clone(),
        functions,
        BTreeMap::from([(
            "run".into(),
            ResourceLocation::new("fixture:wrapper3").unwrap(),
        )]),
        BTreeSet::new(),
    );
    let error = pack_build(&build_request(&root), &target(), inputs).unwrap_err();
    assert_eq!(error.code, "NUMERIC_RANGE");
    assert!(error.message.contains("before cloning/serialization"));
}

#[test]
fn file_directory_collision_is_rejected_and_source_map_uses_authored_object() {
    let root = project();
    let inputs = PackBuildInputs::new(
        root.clone(),
        vec![
            function("fixture:run", Vec::new()),
            function("fixture:run.mcfunction/child", Vec::new()),
        ],
        BTreeMap::from([("run".into(), ResourceLocation::new("fixture:run").unwrap())]),
        BTreeSet::new(),
    );
    assert_eq!(
        pack_build(&build_request(&root), &target(), inputs)
            .unwrap_err()
            .code,
        "NUMERIC_RANGE"
    );
    let pack = pack_build(&build_request(&root), &target(), simple_pack()).unwrap();
    let map: Value = serde_json::from_slice(&pack.source_map().bytes).unwrap();
    assert!(
        map["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["sourceObjectId"] == "math-authoring-object")
    );
    assert!(
        !map["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["sourceObjectId"] == "answer")
    );
}

#[test]
fn lifecycle_contracts_do_not_claim_writes_to_external_read_state() {
    let binding = SymbolBinding {
        symbol_id: SymbolId::new("clock-symbol").unwrap(),
        numeric_type: NumericType::Int32,
        unit: "ticks".into(),
        address: BindingAddress::Score {
            holder: "#clock".into(),
            objective: "external_clock".into(),
        },
    };
    let symbols = ResolvedSymbols::verify(
        resource(),
        b"authored-symbol-bindings",
        BTreeMap::from([(StateId::new("clock-state").unwrap(), binding)]),
        BTreeMap::new(),
        &AuthoredEvidence,
    )
    .unwrap();
    let node = json!({"exprId": "clock", "op": "state", "type": "int32", "unit": "ticks", "inputs": [], "stateId": "clock-state"});
    let fragment = math_compile(
        &request(vec![node], "clock", "scoreboard", "none"),
        &target(),
        &symbols,
    )
    .unwrap();
    let root = project();
    let inputs = PackBuildInputs::new(
        root.clone(),
        vec![function(
            "fixture:clock",
            vec![PackInstruction::Math(Box::new(fragment))],
        )],
        BTreeMap::from([(
            "run".into(),
            ResourceLocation::new("fixture:clock").unwrap(),
        )]),
        BTreeSet::new(),
    );
    let pack = pack_build(&build_request(&root), &target(), inputs).unwrap();
    assert!(
        pack.manifest()
            .state_symbols
            .contains(&"score:#clock:external_clock".into())
    );
    for role in ["initialize", "cleanup"] {
        let id = &pack.manifest().entry_points[role];
        assert!(pack.function_contracts()[id].iter().all(|contract| {
            !contract
                .state_writes
                .contains(&"score:#clock:external_clock".into())
        }));
    }
    let init = &pack.function_contracts()[&pack.manifest().entry_points["initialize"]][0];
    assert!(
        init.state_writes
            .iter()
            .all(|state| state.starts_with("objective:"))
    );
}

#[test]
fn negative_division_uses_distinct_native_operators_and_checked_preflight() {
    let nodes = vec![
        constant("a", json!(-7), "int32", "unitless"),
        constant("b", json!(2), "int32", "unitless"),
    ];
    let mut div_nodes = nodes.clone();
    div_nodes.push(operation("result", "div", &["a", "b"], "int32", "unitless"));
    let div = math_compile(
        &request(div_nodes, "result", "scoreboard", "none"),
        &target(),
        &symbols(),
    )
    .unwrap();
    let mut floor_nodes = nodes;
    floor_nodes.push(operation(
        "result",
        "floor_div",
        &["a", "b"],
        "int32",
        "unitless",
    ));
    let floor = math_compile(
        &request(floor_nodes, "result", "scoreboard", "none"),
        &target(),
        &symbols(),
    )
    .unwrap();
    assert!(
        source(&div).contains("run compute default integer {type:\"minecraft:floor_div\",left:")
    );
    assert!(source(&div).contains("set compute default integer {type:\"minecraft:div\",left:"));
    assert!(
        source(&floor).contains("set compute default integer {type:\"minecraft:floor_div\",left:")
    );
    assert!(!source(&div).contains("scoreboard players operation"));
    // Independent integer witnesses for the documented two semantics.
    assert_eq!(-7i32 / 2, -3);
    assert_eq!((-7f64 / 2.0).floor() as i32, -4);
}

#[test]
fn constant_overflow_zero_division_and_min_div_negative_one_are_errors() {
    for (left, right, op) in [
        (i32::MAX, 1, "add"),
        (i32::MIN, -1, "div"),
        (i32::MIN, -1, "floor_div"),
        (8, 0, "div"),
        (i32::MAX, 2, "mul"),
    ] {
        let nodes = vec![
            constant("a", json!(left), "int32", "unitless"),
            constant("b", json!(right), "int32", "unitless"),
            operation("result", op, &["a", "b"], "int32", "unitless"),
        ];
        assert_eq!(
            error(&request(nodes, "result", "scoreboard", "none")),
            "NUMERIC_RANGE"
        );
    }
}

#[test]
fn float_math_remains_binary32_native_without_host_fold() {
    let nodes = vec![
        constant("a", json!(16777216), "float32", "unitless"),
        constant("b", json!(1), "float32", "unitless"),
        operation("sum", "add", &["a", "b"], "float32", "unitless"),
        operation("result", "sub", &["sum", "a"], "float32", "unitless"),
    ];
    let draft = math_compile(
        &request(nodes, "result", "storage_nbt", "none"),
        &target(),
        &symbols(),
    )
    .unwrap();
    assert!(source(&draft).contains("minecraft:add"));
    assert!(source(&draft).contains("minecraft:sub"));
    assert!(source(&draft).contains("set compute default float 16777216f"));
    assert!(source(&draft).contains("minecraft:from_float\",input:{type:\"minecraft:mul\""));
    assert!(!source(&draft).contains("run compute default float"));
    assert_eq!((16777216f32 + 1f32) - 16777216f32, 0f32);
    assert_eq!((16777216f64 + 1f64) - 16777216f64, 1f64);
}

#[test]
fn floor_and_truncation_are_explicit_and_upper_float_boundary_is_rejected() {
    let nodes = vec![constant("value", json!(-1.5), "float32", "unitless")];
    let floor = math_compile(
        &request(nodes.clone(), "value", "scoreboard", "floor"),
        &target(),
        &symbols(),
    )
    .unwrap();
    let trunc = math_compile(
        &request(nodes.clone(), "value", "scoreboard", "trunc"),
        &target(),
        &symbols(),
    )
    .unwrap();
    assert!(source(&floor).contains("minecraft:from_float\",input:{type:\"minecraft:floor\""));
    assert!(!source(&trunc).contains("minecraft:floor"));
    assert_eq!(
        error(&request(nodes, "value", "scoreboard", "none")),
        "UNSUPPORTED_OPERATOR"
    );
    assert_eq!(
        error(&request(
            vec![constant(
                "value",
                json!(2147483648.0),
                "float32",
                "unitless"
            )],
            "value",
            "scoreboard",
            "trunc"
        )),
        "NUMERIC_RANGE"
    );
    for op in ["to_int_floor", "to_int_trunc"] {
        let nodes = vec![
            constant("value", json!(2147483648.0), "float32", "unitless"),
            operation("result", op, &["value"], "int32", "unitless"),
        ];
        assert_eq!(
            error(&request(nodes, "result", "scoreboard", "none")),
            "NUMERIC_RANGE"
        );
    }
}

#[test]
fn unit_type_cycles_missing_ids_and_arity_fail_before_emission() {
    let mismatched = vec![
        constant("a", json!(1), "float32", "degrees"),
        operation("result", "sin", &["a"], "float32", "unitless"),
    ];
    assert_eq!(
        error(&request(mismatched, "result", "storage_nbt", "none")),
        "UNIT_MISMATCH"
    );
    let implicit = vec![
        constant("a", json!(1), "int32", "unitless"),
        constant("b", json!(1), "float32", "unitless"),
        operation("result", "add", &["a", "b"], "float32", "unitless"),
    ];
    assert_eq!(
        error(&request(implicit, "result", "storage_nbt", "none")),
        "UNIT_MISMATCH"
    );
    assert_eq!(
        error(&request(
            vec![
                operation("a", "add", &["b", "b"], "int32", "unitless"),
                operation("b", "add", &["a", "a"], "int32", "unitless")
            ],
            "a",
            "scoreboard",
            "none"
        )),
        "SCHEMA_INVALID"
    );
    assert_eq!(
        error(&request(
            vec![operation(
                "a",
                "add",
                &["missing", "missing"],
                "int32",
                "unitless"
            )],
            "a",
            "scoreboard",
            "none"
        )),
        "REFERENCE_UNRESOLVED"
    );
    assert_eq!(
        error(&request(
            vec![operation("a", "add", &[], "int32", "unitless")],
            "a",
            "scoreboard",
            "none"
        )),
        "SCHEMA_INVALID"
    );
}

#[test]
fn clamp_is_min_max_lowering_and_float_floor_div_is_unsupported() {
    let nodes = vec![
        constant("value", json!(9), "float32", "unitless"),
        constant("low", json!(0), "float32", "unitless"),
        constant("high", json!(4), "float32", "unitless"),
        operation(
            "result",
            "clamp",
            &["value", "low", "high"],
            "float32",
            "unitless",
        ),
    ];
    let draft = math_compile(
        &request(nodes, "result", "storage_nbt", "none"),
        &target(),
        &symbols(),
    )
    .unwrap();
    assert!(source(&draft).contains("minecraft:min\",inputs:[{type:\"minecraft:max\""));
    assert!(!source(&draft).contains("minecraft:clamp"));
    let nodes = vec![
        constant("a", json!(1), "float32", "unitless"),
        constant("b", json!(2), "float32", "unitless"),
        operation("result", "floor_div", &["a", "b"], "float32", "unitless"),
    ];
    assert_eq!(
        error(&request(nodes, "result", "storage_nbt", "none")),
        "UNSUPPORTED_OPERATOR"
    );
}

#[test]
fn squared_distance_and_velocity_units_preserve_dimensions_without_angle_conversion() {
    let nodes = vec![
        constant("distance", json!(3), "float32", "blocks"),
        operation(
            "square",
            "mul",
            &["distance", "distance"],
            "float32",
            "blocks^2",
        ),
        operation("root", "sqrt", &["square"], "float32", "blocks"),
    ];
    let draft = math_compile(
        &request(nodes, "root", "storage_nbt", "none"),
        &target(),
        &symbols(),
    )
    .unwrap();
    assert!(source(&draft).contains("minecraft:mul"));
    assert!(source(&draft).contains("minecraft:sqrt"));
    let velocity = vec![
        constant("distance", json!(3), "float32", "blocks"),
        constant("ticks", json!(2), "float32", "ticks"),
        operation(
            "velocity",
            "div",
            &["distance", "ticks"],
            "float32",
            "blocks_per_tick",
        ),
    ];
    math_compile(
        &request(velocity, "velocity", "storage_nbt", "none"),
        &target(),
        &symbols(),
    )
    .unwrap();
    let bad_root = vec![
        constant("distance", json!(3), "float32", "blocks"),
        operation("root", "sqrt", &["distance"], "float32", "blocks"),
    ];
    assert_eq!(
        error(&request(bad_root, "root", "storage_nbt", "none")),
        "UNIT_MISMATCH"
    );
}

#[test]
fn score_state_has_failure_fallback_and_exact_referenced_symbol() {
    let binding = SymbolBinding {
        symbol_id: SymbolId::new("state-score").unwrap(),
        numeric_type: NumericType::Int32,
        unit: "ticks".into(),
        address: BindingAddress::Score {
            holder: "#clock".into(),
            objective: "clock".into(),
        },
    };
    let states = BTreeMap::from([(StateId::new("clock-state").unwrap(), binding)]);
    let symbols = ResolvedSymbols::verify(
        resource(),
        b"authored-symbol-bindings",
        states,
        BTreeMap::new(),
        &AuthoredEvidence,
    )
    .unwrap();
    let node = json!({"exprId": "clock", "op": "state", "type": "int32", "unit": "ticks", "inputs": [], "stateId": "clock-state"});
    let draft = math_compile(
        &request(vec![node], "clock", "scoreboard", "none"),
        &target(),
        &symbols,
    )
    .unwrap();
    assert!(source(&draft).contains("target:{type:\"fixed\",name:\"#clock\"}"));
    assert!(source(&draft).contains("fallback:{type:\"minecraft:div\",left:1,right:0}"));
    assert_eq!(
        draft.fragment().referenced_symbols[0].as_str(),
        "state-score"
    );
    assert_eq!(
        draft.function_contract().state_reads,
        vec!["score:#clock:clock"]
    );
}

#[test]
fn context_requires_authorized_prepared_float_storage_and_has_no_fabricated_provider() {
    let node = json!({"exprId": "origin", "op": "context_component", "type": "float32", "unit": "blocks", "inputs": [], "contextComponent": "origin_x"});
    assert_eq!(
        error(&request(
            vec![node.clone()],
            "origin",
            "storage_nbt",
            "none"
        )),
        "REFERENCE_UNRESOLVED"
    );
    let binding = SymbolBinding {
        symbol_id: SymbolId::new("context-x").unwrap(),
        numeric_type: NumericType::Float32,
        unit: "blocks".into(),
        address: BindingAddress::Storage {
            storage: ResourceLocation::new("mmmm:context").unwrap(),
            path: "origin.x".into(),
        },
    };
    let symbols = ResolvedSymbols::verify(
        resource(),
        b"authored-symbol-bindings",
        BTreeMap::new(),
        BTreeMap::from([(ContextComponent::OriginX, binding)]),
        &AuthoredEvidence,
    )
    .unwrap();
    let draft = math_compile(
        &request(vec![node], "origin", "storage_nbt", "none"),
        &target(),
        &symbols,
    )
    .unwrap();
    assert!(source(&draft).contains("storage:\"mmmm:context\",path:\"origin.x\""));
    assert!(!source(&draft).contains("minecraft:context"));
}

#[test]
fn resource_digest_authorization_and_address_injection_are_rejected() {
    assert_eq!(
        ResolvedSymbols::verify(
            resource(),
            b"changed",
            BTreeMap::new(),
            BTreeMap::new(),
            &AuthoredEvidence
        )
        .unwrap_err()
        .code,
        "RESOURCE_DIGEST_MISMATCH"
    );
    let binding = SymbolBinding {
        symbol_id: SymbolId::new("x").unwrap(),
        numeric_type: NumericType::Int32,
        unit: "unitless".into(),
        address: BindingAddress::Score {
            holder: "#x\nkill @e".into(),
            objective: "x".into(),
        },
    };
    assert_eq!(
        ResolvedSymbols::verify(
            resource(),
            b"authored-symbol-bindings",
            BTreeMap::from([(StateId::new("x").unwrap(), binding)]),
            BTreeMap::new(),
            &AuthoredEvidence
        )
        .unwrap_err()
        .code,
        "SCHEMA_INVALID"
    );
    struct Reject;
    impl SymbolTableVerifier for Reject {
        fn verify_symbols(
            &self,
            _: &ResourceRef,
            _: &[u8],
            _: &BTreeMap<StateId, SymbolBinding>,
            _: &BTreeMap<ContextComponent, SymbolBinding>,
        ) -> Result<Sha256Digest, DomainError> {
            Err(DomainError::new(
                "RESOURCE_FORBIDDEN",
                "authored ACL denied",
            ))
        }
    }
    assert_eq!(
        ResolvedSymbols::verify(
            resource(),
            b"authored-symbol-bindings",
            BTreeMap::new(),
            BTreeMap::new(),
            &Reject
        )
        .unwrap_err()
        .code,
        "RESOURCE_FORBIDDEN"
    );
}

#[test]
fn changed_internal_symbol_interpretation_cannot_reuse_source_identity() {
    let node = json!({"exprId": "clock", "op": "state", "type": "int32", "unit": "ticks", "inputs": [], "stateId": "clock-state"});
    let input = request(vec![node], "clock", "scoreboard", "none");
    let compile = |holder: &str| {
        let binding = SymbolBinding {
            symbol_id: SymbolId::new("clock-symbol").unwrap(),
            numeric_type: NumericType::Int32,
            unit: "ticks".into(),
            address: BindingAddress::Score {
                holder: holder.into(),
                objective: "clock".into(),
            },
        };
        let symbols = ResolvedSymbols::verify(
            resource(),
            b"authored-symbol-bindings",
            BTreeMap::from([(StateId::new("clock-state").unwrap(), binding)]),
            BTreeMap::new(),
            &AuthoredEvidence,
        )
        .unwrap();
        math_compile(&input, &target(), &symbols).unwrap()
    };
    let first = compile("#first");
    let second = compile("#second");
    assert_ne!(
        first.pins().symbol_authority_digest,
        second.pins().symbol_authority_digest
    );
    assert_ne!(
        first.source().reference.resource_id,
        second.source().reference.resource_id
    );
}

fn project() -> Value {
    let mut value: Value =
        serde_json::from_slice(include_bytes!("../../../examples/project.json")).unwrap();
    value["ownedResources"] = json!([]);
    value["prefabIds"] = json!([]);
    value["instanceIds"] = json!([]);
    value["resourceIds"] = json!([]);
    value["revision"] = json!(projected_digest("Project", &value).unwrap());
    value
}
fn build_request(project: &Value) -> Value {
    json!({"contextId": "build-context", "projectId": project["projectId"], "expectedRevision": project["revision"],
        "targetProfileId": "java-26.3", "outputPolicy": "private_staging_only"})
}
fn function(id: &str, instructions: Vec<PackInstruction>) -> PackFunction {
    PackFunction {
        id: ResourceLocation::new(id).unwrap(),
        source_object_id: "math-authoring-object".into(),
        instructions,
    }
}
fn simple_pack() -> PackBuildInputs {
    let fragment = math_compile(
        &request(
            vec![constant("answer", json!(42), "int32", "unitless")],
            "answer",
            "scoreboard",
            "none",
        ),
        &target(),
        &symbols(),
    )
    .unwrap();
    PackBuildInputs::new(
        project(),
        vec![function(
            "fixture:math",
            vec![PackInstruction::Math(Box::new(fragment))],
        )],
        BTreeMap::from([("run".into(), ResourceLocation::new("fixture:math").unwrap())]),
        BTreeSet::new(),
    )
}

#[test]
fn pack_manifest_tracks_exact_resources_source_map_lifecycle_and_only_static_stage() {
    let inputs = simple_pack();
    let request = build_request(&project());
    let pack = pack_build(&request, &target(), inputs.clone()).unwrap();
    let second = pack_build(&request, &target(), inputs).unwrap();
    assert_eq!(pack.to_wire().unwrap(), second.to_wire().unwrap());
    assert_eq!(pack.manifest().validation_stage, "statically_checked");
    assert_eq!(pack.manifest().defined_functions.len(), 3);
    assert!(
        pack.resources()
            .contains_key("data/fixture/function/math.mcfunction")
    );
    assert!(pack.manifest().entry_points.contains_key("initialize"));
    assert!(pack.manifest().entry_points.contains_key("cleanup"));
    assert!(
        pack.resources()
            .contains_key("mmmm/function-contracts.json")
    );
    for file in &pack.manifest().files {
        let resource = &pack.resources()[&file.path];
        assert_eq!(file.resource.sha256, raw_digest(&resource.bytes));
        assert_eq!(file.resource.size_bytes, resource.bytes.len() as u64);
    }
    let metadata: Value = serde_json::from_slice(&pack.resources()["pack.mcmeta"].bytes).unwrap();
    assert_eq!(metadata["pack"]["min_format"], json!([121, 0]));
    assert_eq!(metadata["pack"]["max_format"], json!([121, 0]));
    assert!(pack.manifest().runtime_dependencies.is_empty());
    assert!(pack.manifest().external_functions.is_empty());
}

#[test]
fn pack_missing_internal_function_cycles_reserved_paths_and_revision_are_rejected() {
    let root = project();
    let request = build_request(&root);
    let inputs = PackBuildInputs::new(
        root.clone(),
        vec![function(
            "fixture:run",
            vec![PackInstruction::Call(
                ResourceLocation::new("fixture:missing").unwrap(),
            )],
        )],
        BTreeMap::from([("run".into(), ResourceLocation::new("fixture:run").unwrap())]),
        BTreeSet::new(),
    );
    assert_eq!(
        pack_build(&request, &target(), inputs).unwrap_err().code,
        "REFERENCE_UNRESOLVED"
    );
    let inputs = PackBuildInputs::new(
        root.clone(),
        vec![
            function(
                "fixture:a",
                vec![PackInstruction::Call(
                    ResourceLocation::new("fixture:b").unwrap(),
                )],
            ),
            function(
                "fixture:b",
                vec![PackInstruction::Call(
                    ResourceLocation::new("fixture:a").unwrap(),
                )],
            ),
        ],
        BTreeMap::from([("run".into(), ResourceLocation::new("fixture:a").unwrap())]),
        BTreeSet::new(),
    );
    assert_eq!(
        pack_build(&request, &target(), inputs).unwrap_err().code,
        "UNSUPPORTED_OPERATOR"
    );
    for id in ["fixture:../escape", "fixture:con", "minecraft:run"] {
        let inputs = PackBuildInputs::new(
            root.clone(),
            vec![function(id, Vec::new())],
            BTreeMap::from([("run".into(), ResourceLocation::new(id).unwrap())]),
            BTreeSet::new(),
        );
        assert_eq!(
            pack_build(&request, &target(), inputs).unwrap_err().code,
            "SCHEMA_INVALID"
        );
    }
    let mut changed = build_request(&root);
    changed["expectedRevision"] = json!("22".repeat(32));
    assert_eq!(
        pack_build(&changed, &target(), simple_pack())
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
}

#[test]
fn unsupported_owned_scene_is_never_marked_lowered_from_caller_coverage() {
    let original: Value =
        serde_json::from_slice(include_bytes!("../../../examples/project.json")).unwrap();
    let covered = original["ownedResources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["objectId"].as_str().unwrap().to_owned())
        .collect();
    let inputs = PackBuildInputs::new(
        original.clone(),
        vec![function("fixture:run", Vec::new())],
        BTreeMap::from([("run".into(), ResourceLocation::new("fixture:run").unwrap())]),
        covered,
    );
    assert_eq!(
        pack_build(&build_request(&original), &target(), inputs)
            .unwrap_err()
            .code,
        "UNOWNED_REQUIRED_CAPABILITY"
    );
}

use super::*;
use mmmm_compiler::scene::SceneStateBinding;
use mmmm_contracts::{ResourceLocation, StateId};
use mmmm_domain::types::{ScalarValue, StateScope, StateType, StateVariable};
use serde_json::json;

fn state(scope: StateScope, state_type: StateType, storage: &str) -> StateVariable {
    StateVariable {
        state_id: StateId::new("opened").unwrap(),
        scope,
        state_type,
        unit: "dimensionless".into(),
        storage: storage.into(),
        initial_value: ScalarValue::Boolean(false),
        lifecycle: "spawn".into(),
        owner_node_id: None,
    }
}

// 공개 metadata만 사용한다. opaque source, NativeRead, runtime alias receipt
// 또는 게임 읽기 권한 fixture를 만들지 않는다.
fn binding(state_type: StateType, storage: &str) -> SceneStateBinding {
    SceneStateBinding {
        qualified_state: "project/example/instance/example-instance/state/opened".into(),
        storage: ResourceLocation::new("example:state").unwrap(),
        key: "original_compiler_key".into(),
        objective: "original_objective".into(),
        holder: "#original_holder".into(),
        storage_kind: storage.into(),
        state_type,
        lifecycle: "spawn".into(),
    }
}

#[test]
fn player_and_invocation_owned_states_need_the_actual_runtime_issuer() {
    let metadata = binding(StateType::Boolean, "scoreboard");
    for scope in [StateScope::Player, StateScope::Ephemeral] {
        assert_eq!(
            require_state_metadata(&state(scope, StateType::Boolean, "scoreboard"), &metadata)
                .unwrap_err()
                .code,
            "CAPABILITY_UNAVAILABLE"
        );
    }
    let mut definition = state(StateScope::Instance, StateType::Boolean, "scoreboard");
    definition.lifecycle = "invocation".into();
    assert_eq!(
        require_state_metadata(&definition, &metadata)
            .unwrap_err()
            .code,
        "CAPABILITY_UNAVAILABLE"
    );
}

#[test]
fn same_state_id_cannot_promote_a_different_type_or_storage_codec() {
    let definition = state(StateScope::Instance, StateType::Boolean, "scoreboard");
    for metadata in [
        binding(StateType::Int32, "scoreboard"),
        binding(StateType::Boolean, "storage_nbt"),
    ] {
        assert_eq!(
            require_state_metadata(&definition, &metadata)
                .unwrap_err()
                .code,
            "STALE_DEPENDENCY"
        );
    }
}

#[test]
fn state_selection_has_no_duplicate_or_unbounded_alias_expansion() {
    let id = StateId::new("opened").unwrap();
    for selection in [
        vec![],
        vec![id.clone(), id.clone()],
        vec![id; MAX_STATES + 1],
    ] {
        assert_eq!(
            selected_states(&selection).unwrap_err().code,
            "INVALID_INPUT"
        );
    }
}

#[test]
fn compiler_numeric_normalization_does_not_conflate_boolean_zero_or_wrong_native_type() {
    let zero: ScalarValue = serde_json::from_value(json!(0)).unwrap();
    let float_zero: ScalarValue = serde_json::from_value(json!(0.0)).unwrap();
    let boolean: ScalarValue = serde_json::from_value(json!(false)).unwrap();
    assert!(same_native_scalar(StateType::Int32, &zero, &float_zero));
    assert!(same_native_scalar(StateType::Float32, &float_zero, &zero));
    assert!(!same_native_scalar(StateType::Boolean, &zero, &boolean));
    let fractional: ScalarValue = serde_json::from_value(json!(0.25)).unwrap();
    assert!(!same_native_scalar(StateType::Int32, &fractional, &zero));
    let not_widened: ScalarValue = serde_json::from_value(json!(0.1)).unwrap();
    assert!(!same_native_scalar(
        StateType::Float32,
        &not_widened,
        &not_widened
    ));
}

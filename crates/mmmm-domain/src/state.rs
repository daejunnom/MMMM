//! State values keep booleans, numeric zero, and absence distinct. Target
//! scoreboard/NBT lowering belongs to the compiler, not this authoring model.

use crate::types::{Diagnostic, DomainError, InstanceOverride, Prefab, ScalarValue, StateType, StateVariable};
use mmmm_contracts::StateId;
use std::collections::BTreeMap;

pub fn value_matches_type(value: &ScalarValue, state_type: StateType) -> bool {
    match (value, state_type) {
        (ScalarValue::Boolean(_), StateType::Boolean) => true,
        (ScalarValue::Number(number), StateType::Int32) => number.as_f64().is_some_and(|value| {
            value.is_finite() && value.fract() == 0.0 && value >= i32::MIN as f64 && value <= i32::MAX as f64
        }),
        (ScalarValue::Number(number), StateType::Float32) => number.as_f64().is_some_and(|value| {
            value.is_finite() && (value as f32).is_finite()
        }),
        _ => false,
    }
}

pub fn state_diagnostics(state: &[StateVariable]) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for (index, variable) in state.iter().enumerate() {
        if !value_matches_type(&variable.initial_value, variable.state_type) {
            diagnostics.push(Diagnostic::error("STATE_TYPE_MISMATCH", "The initial value does not fit the declared state type",
                Some(variable.state_id.as_str()), &format!("/state/{index}/initialValue")));
        }
        if variable.state_type == StateType::Float32 && variable.storage != "storage_nbt" {
            diagnostics.push(Diagnostic::error("STATE_STORAGE_MISMATCH", "float32 state requires storage NBT",
                Some(variable.state_id.as_str()), &format!("/state/{index}/storage")));
        }
        if variable.scope == crate::types::StateScope::Ephemeral && variable.lifecycle != "invocation" {
            diagnostics.push(Diagnostic::error("STATE_LIFECYCLE_MISMATCH", "Ephemeral state must be owned by an invocation",
                Some(variable.state_id.as_str()), &format!("/state/{index}/lifecycle")));
        }
    }
    diagnostics
}

/// Effective authoring defaults include explicit false and zero overrides.
/// This is not a snapshot of a player's or world's live gameplay state.
pub fn effective_defaults(prefab: &Prefab, overrides: &[InstanceOverride]) -> Result<BTreeMap<StateId, ScalarValue>, DomainError> {
    let definitions: BTreeMap<_, _> = prefab.state.iter().map(|state| (&state.state_id, state)).collect();
    let mut values: BTreeMap<_, _> = prefab.state.iter().map(|state| (state.state_id.clone(), state.initial_value.clone())).collect();
    for entry in overrides {
        if let InstanceOverride::StateDefault { state_id, value } = entry {
            let definition = definitions.get(state_id).ok_or_else(|| DomainError::new("REFERENCE_UNRESOLVED", "State override references an absent definition"))?;
            if !value_matches_type(value, definition.state_type) {
                return Err(DomainError::new("STATE_TYPE_MISMATCH", "State override does not fit the declared type"));
            }
            values.insert(state_id.clone(), value.clone());
        }
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode;
    use serde_json::Value;

    #[test]
    fn explicit_false_is_not_missing_and_zero_is_not_boolean() {
        let prefab: Prefab = decode("Prefab", &mmmm_contracts::parse_json(include_bytes!("../../../examples/prefab.json")).unwrap()).unwrap();
        let overrides = vec![InstanceOverride::StateDefault {
            state_id: StateId::new("opened").unwrap(), value: ScalarValue::Boolean(false)
        }];
        assert_eq!(effective_defaults(&prefab, &overrides).unwrap()[&StateId::new("opened").unwrap()], ScalarValue::Boolean(false));
        let zero: ScalarValue = serde_json::from_value(Value::from(0)).unwrap();
        assert!(!value_matches_type(&zero, StateType::Boolean));
        assert!(value_matches_type(&zero, StateType::Int32));
    }

    #[test]
    fn float32_overflow_is_rejected_instead_of_becoming_infinity() {
        let value: ScalarValue = serde_json::from_value(serde_json::json!(1e100)).unwrap();
        assert!(!value_matches_type(&value, StateType::Float32));
    }
}

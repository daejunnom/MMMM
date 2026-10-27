//! Neutral exchange semantics never apply a world change or execute editor code.
//! The original schema is the wire authority. Immutable bundles cross hash,
//! schema, identity, coordinate and rights gates before becoming import inputs.
pub mod archive;
pub mod bake;
pub mod coordinates;
pub mod manifest;
pub mod normalization;
pub mod patch;
pub mod physics;
pub mod physics_normalization;
pub mod planning;
pub mod resources;
pub mod selection;

use mmmm_contracts::{ContractValidator, encode_json};
use serde_json::Value;
use std::fmt;

pub type ExchangeResult<T> = Result<T, ExchangeError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeError {
    pub code: &'static str,
    pub message: String,
}
impl ExchangeError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
impl fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for ExchangeError {}

pub(crate) fn validate(definition: &str, value: &Value) -> ExchangeResult<()> {
    ContractValidator::shared()
        .and_then(|validator| validator.validate(definition, value))
        .map_err(|e| ExchangeError::new("SCHEMA_INVALID", e.to_string()))
}
pub(crate) fn json_bytes(value: &Value) -> ExchangeResult<Vec<u8>> {
    encode_json(value).map_err(|e| ExchangeError::new("BUDGET_EXCEEDED", e.to_string()))
}
pub(crate) fn text<'a>(value: &'a Value, field: &str) -> ExchangeResult<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", format!("Missing string {field}")))
}
pub(crate) fn array<'a>(value: &'a Value, field: &str) -> ExchangeResult<&'a [Value]> {
    value[field]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", format!("Missing array {field}")))
}
pub(crate) fn nonnegative_integer(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        value
            .as_f64()
            .filter(|number| {
                number.is_finite()
                    && *number >= 0.0
                    && *number <= 9_007_199_254_740_991.0
                    && number.fract() == 0.0
            })
            .map(|number| number as u64)
    })
}

#[cfg(test)]
mod tests;

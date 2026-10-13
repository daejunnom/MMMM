//! Concrete pure native preparation. Registry observations and target read
//! witnesses come from authenticated Coordinator ports; no input DTO grants
//! authority. The shared application owns freeze, dispatch and recovery state.
mod catalog;
mod native;
mod planning;
pub mod ports;
mod preparation;
mod scene;
mod schema;

pub use catalog::*;
pub use native::*;
pub use planning::{domain_digest, planner_digest};
pub use ports::*;
pub use schema::*;

use mmmm_application::{AppError, AppResult};
use mmmm_contracts::ContractValidator;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

pub struct NativePlanner<'a> {
    pub source: Box<dyn ProjectSourcePort + 'a>,
    pub environment: Box<dyn PlanningEnvironmentPort + 'a>,
    pub clock: Box<dyn mmmm_application::Clock + 'a>,
    pub options: PlannerOptions,
}

pub(crate) fn validate(name: &str, value: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .and_then(|validator| validator.validate(name, value))
        .map_err(|_| AppError::new("INVALID_INPUT", "Canonical planning input is invalid"))
}
pub(crate) fn decode<T: DeserializeOwned>(name: &str, value: &Value) -> AppResult<T> {
    validate(name, value)?;
    mmmm_contracts::encode_json(value).map_err(|_| {
        AppError::new(
            "INVALID_INPUT",
            "Planning input cannot be encoded within its wire budget",
        )
    })?;
    let mut typed = value.clone();
    normalize_resource_lengths(&mut typed);
    serde_json::from_value(typed)
        .map_err(|_| AppError::new("INVALID_INPUT", "Typed planning input is invalid"))
}

/// ResourceRef.sizeBytes is mathematically integral in JSON Schema. Its Rust
/// u64 field accepts the same safe values without JCS reencoding unrelated f64
/// authoring numbers. Wire/CAS bytes always retain their original float tags.
pub(crate) fn normalize_resource_lengths(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(normalize_resource_lengths),
        Value::Object(values) => {
            if values.len() == 4
                && ["resourceId", "sha256", "mediaType", "sizeBytes"]
                    .iter()
                    .all(|key| values.contains_key(*key))
                && let Some(length) = values["sizeBytes"].as_f64().filter(|length| {
                    length.is_finite()
                        && length.fract() == 0.0
                        && *length >= 0.0
                        && *length <= 9_007_199_254_740_991.0
                })
            {
                values.insert("sizeBytes".into(), Value::from(length as u64));
            }
            values.values_mut().for_each(normalize_resource_lengths);
        }
        _ => {}
    }
}
pub(crate) fn wire<T: Serialize>(name: &str, value: &T) -> AppResult<Value> {
    let value = serde_json::to_value(value)
        .map_err(|_| AppError::new("INVALID_INPUT", "Prepared value cannot be encoded"))?;
    validate(name, &value)?;
    Ok(value)
}
pub(crate) fn domain(error: mmmm_domain::DomainError) -> AppError {
    AppError::new(
        error.code,
        "Pure authoring preparation rejected the requested change",
    )
}
pub(crate) fn exchange(error: mmmm_exchange::ExchangeError) -> AppError {
    AppError::new(
        error.code,
        "Scene provenance or stable delta validation rejected the requested change",
    )
}
pub(crate) fn adapter(error: mmmm_adapters::AdapterError) -> AppError {
    AppError::new(
        error.code,
        "Pinned provider inventory rejected the requested action",
    )
}
pub(crate) fn text<'a>(value: &'a Value, key: &str) -> AppResult<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| AppError::new("INVALID_INPUT", "Required planning field is absent"))
}

#[cfg(test)]
mod tests;

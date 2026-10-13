//! Pure authoring semantics. This crate never applies a world change, allocates
//! a runtime UUID, loads a resource, or performs I/O. Wire values cross the
//! canonical validator before they become typed immutable domain inputs.

pub mod graph;
pub mod instance;
pub mod prefab;
pub mod state;
pub mod transform;
pub mod types;

pub use instance::{clone_instance, instantiate, relocate};
pub use prefab::prefab_validate;
pub use types::{Diagnostic, DomainError, Instance, InstanceDraft, Prefab};

use mmmm_contracts::ContractValidator;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::sync::OnceLock;

fn validator() -> Result<&'static ContractValidator, DomainError> {
    static VALIDATOR: OnceLock<Result<ContractValidator, String>> = OnceLock::new();
    VALIDATOR
        .get_or_init(|| ContractValidator::embedded().map_err(|error| error.to_string()))
        .as_ref()
        .map_err(|message| DomainError::new("SCHEMA_INVALID", message.clone()))
}

pub(crate) fn decode<T: DeserializeOwned>(definition: &str, value: &Value) -> Result<T, DomainError> {
    validator()?.validate(definition, value)
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    serde_json::from_value(value.clone())
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))
}

pub(crate) fn encode<T: Serialize>(definition: &str, value: &T) -> Result<Value, DomainError> {
    let value = serde_json::to_value(value)
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    validator()?.validate(definition, &value)
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    Ok(value)
}

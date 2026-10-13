//! FN35/FN36 are pure decisions. They do not adopt a dependency, execute a
//! worker, inspect a filesystem, or publish a release. Wire arrays are claims.
//! Only the application's injected, authenticated evidence verifier can create
//! the opaque evidence values that these decisions consume.

mod admission;
mod evidence;
mod release;
mod types;

pub use admission::*;
pub use evidence::*;
pub use release::*;
pub use types::*;

use mmmm_contracts::ContractValidator;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{error::Error, fmt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError {
    pub code: &'static str,
    pub message: String,
}

impl PolicyError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl Error for PolicyError {}

pub(crate) fn decode<T: DeserializeOwned>(
    definition: &str,
    value: &Value,
) -> Result<T, PolicyError> {
    ContractValidator::shared()
        .and_then(|validator| validator.validate(definition, value))
        .map_err(|error| PolicyError::new("INCOMPATIBLE_CONTRACT", error.to_string()))?;
    serde_json::from_value(value.clone())
        .map_err(|error| PolicyError::new("INCOMPATIBLE_CONTRACT", error.to_string()))
}

pub(crate) fn wire<T: Serialize>(definition: &str, value: &T) -> Result<Value, PolicyError> {
    let value = serde_json::to_value(value)
        .map_err(|error| PolicyError::new("INCOMPATIBLE_CONTRACT", error.to_string()))?;
    ContractValidator::shared()
        .and_then(|validator| validator.validate(definition, &value))
        .map_err(|error| PolicyError::new("INCOMPATIBLE_CONTRACT", error.to_string()))?;
    Ok(value)
}

#[cfg(test)]
mod tests;

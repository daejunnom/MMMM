//! Metadata registration and routing do not execute providers or confer authority.
//! Authenticated host observations and approved policy are supplied by the runtime.
//! A selected route is a pin; dispatch, recovery and uncertain-write fencing belong
//! to the Coordinator's durable journal, never to a registry fallback loop.

mod compatibility;
mod mapping;
mod registry;
mod types;

pub use compatibility::*;
pub use mapping::*;
pub use registry::*;
pub use types::*;

/// Host transport version is negotiated independently of stored wire contracts.
/// The initial supported transport happens to use the same version text.
pub const HOST_PROTOCOL_VERSION: &str = "0.2.0";

use mmmm_contracts::{ContractError, ContractValidator, DigestError};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{error::Error, fmt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterError {
    pub code: &'static str,
    pub message: String,
}

impl AdapterError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for AdapterError {}

impl From<ContractError> for AdapterError {
    fn from(error: ContractError) -> Self {
        Self::new("INCOMPATIBLE_CONTRACT", error.to_string())
    }
}

impl From<DigestError> for AdapterError {
    fn from(error: DigestError) -> Self {
        Self::new("DIGEST_INVALID", error.to_string())
    }
}

pub(crate) fn decode<T: DeserializeOwned>(
    definition: &str,
    value: &Value,
) -> Result<T, AdapterError> {
    ContractValidator::shared()?.validate(definition, value)?;
    serde_json::from_value(value.clone())
        .map_err(|error| AdapterError::new("INCOMPATIBLE_CONTRACT", error.to_string()))
}

pub(crate) fn wire<T: Serialize>(definition: &str, value: &T) -> Result<Value, AdapterError> {
    let value = serde_json::to_value(value)
        .map_err(|error| AdapterError::new("INCOMPATIBLE_CONTRACT", error.to_string()))?;
    ContractValidator::shared()?.validate(definition, &value)?;
    Ok(value)
}

#[cfg(test)]
mod tests;

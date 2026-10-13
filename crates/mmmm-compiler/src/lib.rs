//! FN07/FN30 staging drafts. No game execution, filesystem writes, package
//! installation, reload, authority construction, or acceptance claims occur here.

pub mod animation;
pub mod calibration;
pub mod calibration_dispatch;
pub mod math;
mod pack_owned;
pub mod packs;
pub mod scene;
pub mod symbols;
pub mod target;
pub mod types;

pub use math::{CompiledFragmentDraft, math_compile};
pub use packs::{PackBuildInputs, PackDraft, PackFunction, PackInstruction, pack_build};
pub use symbols::{BindingAddress, ResolvedSymbols, SymbolBinding, SymbolTableVerifier};
pub use target::{TargetEvidenceVerifier, TargetRuntimeRules, VerifiedTarget};
pub use types::*;

use mmmm_contracts::ContractValidator;
use mmmm_domain::DomainError;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

pub(crate) fn decode<T: DeserializeOwned>(name: &str, value: &Value) -> Result<T, DomainError> {
    // A caller may use the pure Rust API without the transport's message
    // ceiling. Measure before schema traversal or serde's deep value clone.
    let mut input_bytes = 0usize;
    packs::charge_metadata(&mut input_bytes, value)?;
    ContractValidator::shared()
        .and_then(|validator| validator.validate(name, value))
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    serde_json::from_value(value.clone())
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))
}

pub(crate) fn encode<T: Serialize>(name: &str, value: &T) -> Result<Value, DomainError> {
    let value = serde_json::to_value(value)
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    ContractValidator::shared()
        .and_then(|validator| validator.validate(name, &value))
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    Ok(value)
}

/// Covers this crate's implementation bytes and the canonical wire contract.
/// This is a compiler implementation pin; the final release still binds its
/// independently built artifact and frozen source commit.
pub fn compiler_digest() -> mmmm_contracts::Sha256Digest {
    let mut bytes = Vec::new();
    for input in [
        include_bytes!("lib.rs").as_slice(),
        include_bytes!("types.rs").as_slice(),
        include_bytes!("target.rs").as_slice(),
        include_bytes!("symbols.rs").as_slice(),
        include_bytes!("math.rs").as_slice(),
        include_bytes!("calibration.rs").as_slice(),
        include_bytes!("calibration_dispatch.rs").as_slice(),
        include_bytes!("packs.rs").as_slice(),
        include_bytes!("pack_owned.rs").as_slice(),
        include_bytes!("scene.rs").as_slice(),
        include_bytes!("animation.rs").as_slice(),
        mmmm_contracts::CANONICAL_SCHEMA,
    ] {
        bytes.extend_from_slice(&(input.len() as u64).to_le_bytes());
        bytes.extend_from_slice(input);
    }
    mmmm_contracts::raw_digest(&bytes)
}

#[cfg(test)]
mod tests;

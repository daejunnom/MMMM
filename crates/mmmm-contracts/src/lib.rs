//! The original contract is the sole format authority. This crate owns no I/O,
//! database, authentication, game execution, or operation state.

pub mod digest;
pub mod identity;
pub mod number;
pub mod strict_json;
pub mod time;
pub mod validation;

pub use digest::{
    DigestError, canonical_bytes, canonical_digest, projected_digest, raw_digest,
    verify_projected_digest,
};
pub use identity::*;
pub use number::{Int32, deserialize_i32, deserialize_i32_vec3};
pub use strict_json::{JsonError, JsonLimits, encode_json, parse_json, parse_json_with_limits};
pub use time::{RationalTime, SignedDecimal, TimeError, UnsignedDecimal};
pub use validation::{
    ContractError, ContractValidator, ContractViolation, FunctionContract, OfflineActionSchema,
};

pub const CONTRACT_VERSION: &str = "0.2.0";
pub const CANONICAL_SCHEMA_ID: &str = "urn:mmmm:contracts:0.2.0";
pub const CANONICAL_SCHEMA: &[u8] = include_bytes!("../../../contracts/mmmm.schema.json");
pub const DIGEST_PROJECTIONS: &[u8] = include_bytes!("../../../contracts/digest-projections.json");
pub const FUNCTION_INDEX: &[u8] = include_bytes!("../../../contracts/function-index.json");

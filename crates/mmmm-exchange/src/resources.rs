//! Resource authority is injected by authenticated composition. A ResourceRef
//! carries a digest, never permission or a path/URL to fetch automatically.
use crate::{ExchangeError, ExchangeResult, validate};
use mmmm_contracts::{parse_json, raw_digest};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourcePurpose {
    Read,
    Redistribute,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Redistribution {
    Allowed,
    ReferenceOnly,
    Unknown,
}
impl Redistribution {
    pub fn wire(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::ReferenceOnly => "reference_only",
            Self::Unknown => "unknown",
        }
    }
}
pub struct AuthorizedBytes {
    pub bytes: Vec<u8>,
    pub redistribution: Redistribution,
}
/// The implementation checks the live principal/context grant before opening a
/// local CAS resource, bounds the read at `max_bytes`, and never resolves a URI.
/// It must not read or inspect a secret file even when a request names one.
pub trait ResourcePort {
    fn authorize_selection(&mut self, context_id: &str, selection: &Value) -> ExchangeResult<()>;
    fn read(
        &mut self,
        context_id: &str,
        resource: &Value,
        purpose: ResourcePurpose,
        max_bytes: u64,
    ) -> ExchangeResult<AuthorizedBytes>;
    /// Rights/provenance lookup for bytes already inside an authorized bundle.
    /// Absence of a trusted rights record is unknown, never an implicit license.
    fn embedded_rights(
        &mut self,
        _context_id: &str,
        _resource: &Value,
    ) -> ExchangeResult<Redistribution> {
        Ok(Redistribution::Unknown)
    }
}

pub fn verify_resource(resource: &Value, bytes: &[u8], max_bytes: u64) -> ExchangeResult<()> {
    validate("ResourceRef", resource)?;
    if bytes.len() as u64 > max_bytes
        || crate::nonnegative_integer(&resource["sizeBytes"]) != Some(bytes.len() as u64)
    {
        return Err(ExchangeError::new(
            "BUDGET_EXCEEDED",
            "Resource length differs from its pin or exceeds the read budget",
        ));
    }
    if resource["sha256"].as_str() != Some(raw_digest(bytes).as_str()) {
        return Err(ExchangeError::new(
            "RESOURCE_HASH_MISMATCH",
            "Resource bytes differ from their exact raw SHA-256 pin",
        ));
    }
    Ok(())
}
pub(crate) fn read_resource(
    port: &mut dyn ResourcePort,
    context: &str,
    resource: &Value,
    purpose: ResourcePurpose,
    max: u64,
) -> ExchangeResult<AuthorizedBytes> {
    validate("ResourceRef", resource)?;
    if crate::nonnegative_integer(&resource["sizeBytes"]).is_none_or(|size| size > max) {
        return Err(ExchangeError::new(
            "BUDGET_EXCEEDED",
            "Declared resource length exceeds the finite read budget",
        ));
    }
    let read = port.read(context, resource, purpose, max)?;
    verify_resource(resource, &read.bytes, max)?;
    if purpose == ResourcePurpose::Redistribute && read.redistribution != Redistribution::Allowed {
        return Err(ExchangeError::new(
            "RESOURCE_FORBIDDEN",
            "Embedding requires an explicit redistribution right",
        ));
    }
    Ok(read)
}
pub(crate) fn parse_resource(definition: &str, bytes: &[u8]) -> ExchangeResult<Value> {
    let value =
        parse_json(bytes).map_err(|e| ExchangeError::new("SCHEMA_INVALID", e.to_string()))?;
    validate(definition, &value)?;
    Ok(value)
}
pub(crate) fn content_resource(prefix: &str, media_type: &str, bytes: &[u8]) -> Value {
    let hash = raw_digest(bytes);
    json!({"resourceId":format!("{prefix}-{}", &hash.as_str()[..24]),"sha256":hash,"mediaType":media_type,"sizeBytes":bytes.len()})
}

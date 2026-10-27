use crate::PolicyError;
use mmmm_contracts::{canonical_digest, raw_digest};
use serde::Serialize;

/// Internal proof material, deliberately not a wire DTO or Deserialize type.
/// The bytes are opaque to this crate. The injected verifier must authenticate
/// their producer, inspect their actual evidence, and bind them to claim_sha256.
#[derive(Clone, Debug)]
pub struct ProofMaterial {
    pub reference: String,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceDomain {
    DependencyAdmission,
    Release,
}

#[derive(Clone, Debug)]
pub struct ProofSubject {
    pub domain: EvidenceDomain,
    pub claim_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceOrigin {
    /// An authenticated actual observation or review, not a metadata-only,
    /// cache-hit, dispatch, schema-validation, or self-declared success.
    Actual,
    /// Synthetic unit fixtures are useful for testing the evaluator but cannot
    /// enter an eligible release evidence index.
    Synthetic,
}

/// This port is supplied by trusted application/xtask configuration. Never
/// construct an implementation from an RPC argument or a vendor callback.
/// A successful verifier must authenticate bytes, their producer and scope,
/// and the entire canonical claim digest. Hash matching alone is insufficient.
pub trait TrustedEvidenceVerifier {
    fn verify(
        &self,
        subject: &ProofSubject,
        material: &ProofMaterial,
    ) -> Result<EvidenceOrigin, PolicyError>;
}

pub(crate) fn authenticate<T: Serialize>(
    domain: EvidenceDomain,
    claim: &T,
    material: &ProofMaterial,
    verifier: &dyn TrustedEvidenceVerifier,
) -> Result<EvidenceOrigin, PolicyError> {
    if !stable_id(&material.reference)
        || material.bytes.is_empty()
        || material.bytes.len() > 1_048_576
    {
        return Err(PolicyError::new(
            "EVIDENCE_MISSING",
            "Proof reference or bounded proof bytes are invalid",
        ));
    }
    if !sha256(&material.sha256) || raw_digest(&material.bytes).as_str() != material.sha256.as_str()
    {
        return Err(PolicyError::new(
            "EVIDENCE_MISSING",
            "Proof bytes do not match their SHA-256",
        ));
    }
    let value = serde_json::to_value(claim)
        .map_err(|error| PolicyError::new("EVIDENCE_MISSING", error.to_string()))?;
    let subject = ProofSubject {
        domain,
        claim_sha256: canonical_digest(&value)
            .map_err(|error| PolicyError::new("EVIDENCE_MISSING", error.to_string()))?
            .into_string(),
    };
    verifier.verify(&subject, material)
}

pub(crate) fn sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn source_sha(text: &str) -> bool {
    matches!(text.len(), 40 | 64)
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn stable_id(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && (text.as_bytes()[0].is_ascii_lowercase() || text.as_bytes()[0].is_ascii_digit())
        && text.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._:-".contains(&byte)
        })
}

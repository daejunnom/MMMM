//! Public profile text and evidence resource names are claims. The application
//! must resolve the evidence in its authenticated registry before this private
//! compile capability exists. A reference-only example cannot create it.

use crate::decode;
use mmmm_contracts::{Int32, Sha256Digest, TargetProfileId, canonical_digest};
use mmmm_domain::DomainError;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetRuntimeRules {
    /// Exact parse/readback evidence for native 26.3 providers and commands.
    pub native_compute_26_3: bool,
    /// Full producer -> data-modify compute -> finite check -> publication
    /// chain, including integer range/zero errors, from_float NaN/range,
    /// undefined float failure propagation, lazy invalid fallbacks, zero-valued
    /// command success, and exact output absence after a failed invocation.
    pub checked_numeric_and_success: bool,
    /// Singular function directory and min_format/max_format pair codec.
    pub data_pack_26_3: bool,
}

/// A trusted application registry port. Implementations must verify immutable
/// evidence bytes, exact artifact/profile identity and the actual runtime
/// cases represented by these rules. Never implement this from caller arrays.
pub trait TargetEvidenceVerifier {
    fn verify_target(
        &self,
        profile: &Value,
        profile_digest: &Sha256Digest,
        artifact_digest: &Sha256Digest,
    ) -> Result<TargetRuntimeRules, DomainError>;
}

#[derive(Debug, Clone)]
pub struct VerifiedTarget {
    profile_id: TargetProfileId,
    profile_digest: Sha256Digest,
    artifact_digest: Sha256Digest,
    data_pack_version: [u64; 2],
    resource_pack_version: Option<[u64; 2]>,
    rules: TargetRuntimeRules,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileFields {
    profile_id: TargetProfileId,
    game_version: String,
    native_float_compute: bool,
    write_support: String,
    validation_status: String,
    artifact_sha256: Option<Sha256Digest>,
    data_pack_version: Option<PackVersion>,
    resource_pack_version: Option<PackVersion>,
}

#[derive(Deserialize)]
struct PackVersion {
    // The native game's format components are signed integers; the schema
    // additionally rejects negatives. Int32 honors 121, 121.0 and 1.21e2 as
    // the same mathematical JSON integer instead of rejecting float lexemes.
    major: Int32,
    minor: Int32,
}

impl VerifiedTarget {
    pub fn verify(
        profile: &Value,
        verifier: &dyn TargetEvidenceVerifier,
    ) -> Result<Self, DomainError> {
        let fields: ProfileFields = decode("VersionProfile", profile)?;
        if fields.game_version != "26.3"
            || fields.validation_status != "runtime_verified"
            || fields.write_support != "verified"
            || !fields.native_float_compute
        {
            return Err(DomainError::new(
                "UNSUPPORTED_TARGET_VERSION",
                "Compiler requires an independently verified exact Java 26.3 profile",
            ));
        }
        let artifact_digest = fields.artifact_sha256.ok_or_else(|| {
            DomainError::new(
                "UNSUPPORTED_TARGET_VERSION",
                "Target artifact digest is absent",
            )
        })?;
        let pack = fields.data_pack_version.ok_or_else(|| {
            DomainError::new("UNSUPPORTED_TARGET_VERSION", "Target pack codec is absent")
        })?;
        let profile_digest = canonical_digest(profile)
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
        let rules = verifier.verify_target(profile, &profile_digest, &artifact_digest)?;
        if !rules.native_compute_26_3 || !rules.checked_numeric_and_success {
            return Err(DomainError::new(
                "UNSUPPORTED_TARGET_VERSION",
                "Native grammar and numeric failure/readback rules have not been verified",
            ));
        }
        Ok(Self {
            profile_id: fields.profile_id,
            profile_digest,
            artifact_digest,
            data_pack_version: [pack.major.get() as u64, pack.minor.get() as u64],
            resource_pack_version: fields
                .resource_pack_version
                .map(|pack| [pack.major.get() as u64, pack.minor.get() as u64]),
            rules,
        })
    }
    pub fn profile_id(&self) -> &TargetProfileId {
        &self.profile_id
    }
    pub fn profile_digest(&self) -> &Sha256Digest {
        &self.profile_digest
    }
    pub fn artifact_digest(&self) -> &Sha256Digest {
        &self.artifact_digest
    }
    /// Exact format pair from the pinned canonical profile. Presence does not
    /// verify a resource-pack codec or grant scene/asset lowering permission.
    pub fn resource_pack_version(&self) -> Option<[u64; 2]> {
        self.resource_pack_version
    }
    pub(crate) fn pack_version(&self) -> Result<[u64; 2], DomainError> {
        if !self.rules.data_pack_26_3 {
            return Err(DomainError::new(
                "UNSUPPORTED_TARGET_VERSION",
                "Exact pack codec is unverified",
            ));
        }
        Ok(self.data_pack_version)
    }
}

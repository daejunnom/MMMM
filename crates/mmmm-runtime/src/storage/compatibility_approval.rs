//! Explicit native-owner approval of exact CompatibilityProfile inputs in the
//! existing protected journal. CAS possession, imported JSON and this factual
//! record are not Java observation, source rights or a reusable execution grant.

use super::{
    BlobRef, DurableStore, StorageError, StorageResult, WriteScope,
    bootstrap::registered_native_project_owner,
    journal::{decode, encode, pin_blob},
};
use mmmm_contracts::{PrincipalId, ProjectId, ResourceId, Sha256Digest, canonical_digest};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// Reuse the actual-owner/request port. No principal, context or owner witness
// can be constructed by deserializing an approval request or retained record.
pub use super::host_setup::HostSetupRpcContext as CompatibilityApprovalRpcContext;

pub const MAX_COMPATIBILITY_PROFILE_BYTES: u64 = 65_536;
const MAX_RECORD_BYTES: usize = 8192;
const MAX_PROJECT_APPROVALS: i64 = 128;
const MAX_APPROVALS: i64 = 4096;
const FORMAT: &str = "mmmm.compatibility-approval/1";
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS compatibility_approvals (
 native_owner TEXT NOT NULL,
 project_id TEXT NOT NULL REFERENCES native_project_owners(project_id),
 approved_profile_ref TEXT NOT NULL CHECK(length(approved_profile_ref) BETWEEN 1 AND 256),
 profile_resource_id TEXT NOT NULL,
 profile_resource_digest TEXT NOT NULL CHECK(length(profile_resource_digest)=64),
 record_json TEXT NOT NULL CHECK(length(CAST(record_json AS BLOB))<=8192),
 PRIMARY KEY(native_owner,project_id,approved_profile_ref),
 FOREIGN KEY(project_id,profile_resource_id,profile_resource_digest)
  REFERENCES project_resource_versions(project_id,resource_id,digest)
) STRICT;";

/// Trusted composition prepares these pins from the actual checked source and
/// current Policy/scope. This request deliberately contains no owner or grant.
#[derive(Clone, Debug)]
pub struct CompatibilityApprovalRegistration {
    pub project_id: ProjectId,
    pub approved_profile_ref: String,
    pub profile_resource: Value,
    pub profile_digest: Sha256Digest,
    pub artifact_digest: Sha256Digest,
    pub allowed_interface_digest: Sha256Digest,
    pub policy_revision: Sha256Digest,
    pub scope_digest: Sha256Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredApproval {
    format: String,
    native_owner: PrincipalId,
    project_id: ProjectId,
    approved_profile_ref: String,
    profile_resource: Value,
    profile_digest: Sha256Digest,
    artifact_digest: Sha256Digest,
    allowed_interface_digest: Sha256Digest,
    policy_revision: Sha256Digest,
    scope_digest: Sha256Digest,
    local_use_only: bool,
}

/// Private journal fact with getters only. It has no public JSON constructor or
/// deserializer. Consumers must re-enter the current authorized read operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompatibilityApprovalRecord(StoredApproval);

impl CompatibilityApprovalRecord {
    pub fn native_owner(&self) -> &PrincipalId {
        &self.0.native_owner
    }
    pub fn project_id(&self) -> &ProjectId {
        &self.0.project_id
    }
    pub fn approved_profile_ref(&self) -> &str {
        &self.0.approved_profile_ref
    }
    pub fn profile_resource(&self) -> &Value {
        &self.0.profile_resource
    }
    pub fn profile_digest(&self) -> &Sha256Digest {
        &self.0.profile_digest
    }
    pub fn artifact_digest(&self) -> &Sha256Digest {
        &self.0.artifact_digest
    }
    pub fn allowed_interface_digest(&self) -> &Sha256Digest {
        &self.0.allowed_interface_digest
    }
    pub fn policy_revision(&self) -> &Sha256Digest {
        &self.0.policy_revision
    }
    pub fn scope_digest(&self) -> &Sha256Digest {
        &self.0.scope_digest
    }
    pub fn local_use_only(&self) -> bool {
        self.0.local_use_only
    }
}

/// Implement only in native composition using the original finite request,
/// private NativeOwnerWitness, same Store and current Project/Policy ACL/scope.
/// Both callbacks must re-read the exact registered profile through the checked
/// ProjectResourceReader (at most 64KiB), preserve source rights/provenance and
/// verify projected profile, separate implementation and interface digests.
/// Registration additionally requires the explicit local management action;
/// read approval cannot be inferred from public JSON, CAS or host claims.
/// These callbacks run before and after journal work, including pre-commit;
/// there is no permissive default implementation or new observation issuer.
pub trait CompatibilityApprovalAuthority {
    fn authorize_registration(
        &mut self,
        store: &DurableStore,
        owner: &PrincipalId,
        request: &CompatibilityApprovalRegistration,
    ) -> StorageResult<()>;
    fn authorize_read(
        &mut self,
        store: &DurableStore,
        owner: &PrincipalId,
        record: &CompatibilityApprovalRecord,
    ) -> StorageResult<()>;
}

fn invalid(message: &'static str) -> StorageError {
    StorageError::InvalidInput(message.into())
}
fn validate_ref(value: &str) -> StorageResult<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        return Err(invalid("Compatibility approval reference is invalid"));
    }
    Ok(())
}
fn resource_pin(store: &DurableStore, resource: &Value) -> StorageResult<(ResourceId, BlobRef)> {
    store
        .validator
        .validate("ResourceRef", resource)
        .map_err(|e| StorageError::Contract(e.to_string()))?;
    if mmmm_contracts::encode_json(resource)
        .map_err(|e| StorageError::Contract(e.to_string()))?
        .len()
        > MAX_RECORD_BYTES
    {
        return Err(invalid("Compatibility approval ResourceRef byte budget"));
    }
    let id = serde_json::from_value(resource["resourceId"].clone())
        .map_err(|e| StorageError::Contract(e.to_string()))?;
    let blob = BlobRef {
        digest: serde_json::from_value(resource["sha256"].clone())
            .map_err(|e| StorageError::Contract(e.to_string()))?,
        byte_length: resource["sizeBytes"]
            .as_u64()
            .ok_or_else(|| invalid("Compatibility profile size is invalid"))?,
    };
    if blob.byte_length == 0 || blob.byte_length > MAX_COMPATIBILITY_PROFILE_BYTES {
        return Err(invalid("Compatibility profile byte budget"));
    }
    Ok((id, blob))
}
fn verify_owner(
    store: &DurableStore,
    rpc: &dyn CompatibilityApprovalRpcContext,
    project: &ProjectId,
    expected: Option<&PrincipalId>,
) -> StorageResult<PrincipalId> {
    rpc.check()?;
    let owner = rpc.authenticated_local_owner()?;
    if expected.is_some_and(|value| value != &owner)
        || registered_native_project_owner(store, project)? != owner
    {
        return Err(StorageError::Conflict(
            "Compatibility approval native owner changed",
        ));
    }
    rpc.check()?;
    Ok(owner)
}
fn verify_resource(
    store: &DurableStore,
    project: &ProjectId,
    resource: &Value,
) -> StorageResult<(ResourceId, BlobRef)> {
    let (id, blob) = resource_pin(store, resource)?;
    // The trusted callback performs the actual current ACL/provenance/full CAS
    // read. This independent exact-version check is metadata, never a grant.
    let row: Option<(Vec<u8>, i64)> = store.connection.query_row(
        "SELECT substr(CAST(resource_json AS BLOB),1,8193),byte_length FROM project_resource_versions WHERE project_id=?1 AND resource_id=?2 AND digest=?3",
        params![project.as_str(), id.as_str(), blob.digest.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    let (bytes, length) = row.ok_or(StorageError::NotFound(
        "Approved compatibility profile source",
    ))?;
    if bytes.len() > MAX_RECORD_BYTES || u64::try_from(length).ok() != Some(blob.byte_length) {
        return Err(StorageError::Corrupt(
            "Compatibility profile registration differs".into(),
        ));
    }
    let actual: Value =
        serde_json::from_slice(&bytes).map_err(|e| StorageError::Contract(e.to_string()))?;
    if &actual != resource {
        return Err(StorageError::Conflict(
            "Compatibility profile exact ResourceRef differs",
        ));
    }
    Ok((id, blob))
}
fn read_record(
    store: &DurableStore,
    owner: &PrincipalId,
    project: &ProjectId,
    approved_ref: &str,
) -> StorageResult<Option<CompatibilityApprovalRecord>> {
    let exists: bool = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='compatibility_approvals')",
        [], |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let row: Option<(String, String, Vec<u8>)> = store.connection.query_row(
        "SELECT profile_resource_id,profile_resource_digest,substr(CAST(record_json AS BLOB),1,8193) FROM compatibility_approvals WHERE native_owner=?1 AND project_id=?2 AND approved_profile_ref=?3",
        params![owner.as_str(), project.as_str(), approved_ref],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional()?;
    let Some((id, digest, bytes)) = row else {
        return Ok(None);
    };
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(StorageError::Corrupt(
            "Compatibility approval record byte budget".into(),
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| StorageError::Corrupt("Compatibility approval UTF-8 is invalid".into()))?;
    let stored: StoredApproval = decode(text)?;
    validate_ref(&stored.approved_profile_ref)?;
    let (resource, blob) = verify_resource(store, project, &stored.profile_resource)?;
    if stored.format != FORMAT
        || &stored.native_owner != owner
        || &stored.project_id != project
        || stored.approved_profile_ref != approved_ref
        || !stored.local_use_only
        || resource.as_str() != id
        || blob.digest.as_str() != digest
    {
        return Err(StorageError::Corrupt(
            "Compatibility approval identity or pins differ".into(),
        ));
    }
    Ok(Some(CompatibilityApprovalRecord(stored)))
}
fn check_fence(store: &DurableStore, project: &ProjectId) -> StorageResult<()> {
    store.check_write_scope(
        &WriteScope {
            project_id: project.clone(),
            resource_ids: vec![],
            object_ids: vec![],
            regions: vec![],
            external_target_ids: vec![],
        },
        true,
        None,
    )
}

/// Exact replay is idempotent; a changed pin under the same approval reference
/// conflicts. The single immediate transaction includes schema, row and CAS pin.
/// The original commit error is preserved; no fallible post-commit delivery or
/// check changes a committed receipt into a claimed rollback or safe retry.
pub fn register_compatibility_approval(
    store: &mut DurableStore,
    rpc: &dyn CompatibilityApprovalRpcContext,
    authority: &mut dyn CompatibilityApprovalAuthority,
    request: &CompatibilityApprovalRegistration,
) -> StorageResult<CompatibilityApprovalRecord> {
    validate_ref(&request.approved_profile_ref)?;
    resource_pin(store, &request.profile_resource)?;
    let owner = verify_owner(store, rpc, &request.project_id, None)?;
    authority.authorize_registration(store, &owner, request)?;
    let (resource, blob) = verify_resource(store, &request.project_id, &request.profile_resource)?;
    check_fence(store, &request.project_id)?;
    let record = CompatibilityApprovalRecord(StoredApproval {
        format: FORMAT.into(),
        native_owner: owner.clone(),
        project_id: request.project_id.clone(),
        approved_profile_ref: request.approved_profile_ref.clone(),
        profile_resource: request.profile_resource.clone(),
        profile_digest: request.profile_digest.clone(),
        artifact_digest: request.artifact_digest.clone(),
        allowed_interface_digest: request.allowed_interface_digest.clone(),
        policy_revision: request.policy_revision.clone(),
        scope_digest: request.scope_digest.clone(),
        local_use_only: true,
    });
    let encoded = encode(&record.0)?;
    if encoded.len() > MAX_RECORD_BYTES {
        return Err(invalid("Compatibility approval record byte budget"));
    }
    rpc.check()?;
    let transaction =
        Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA)?;
    if let Some(old) = read_record(
        store,
        &owner,
        &request.project_id,
        &request.approved_profile_ref,
    )? {
        if old != record {
            return Err(StorageError::Conflict("Immutable compatibility approval"));
        }
    } else {
        let total: i64 = transaction.query_row(
            "SELECT count(*) FROM (SELECT 1 FROM compatibility_approvals LIMIT 4097)",
            [],
            |row| row.get(0),
        )?;
        if total >= MAX_APPROVALS {
            return Err(invalid("Compatibility approval registry capacity"));
        }
        let project_count: i64 = transaction.query_row(
            "SELECT count(*) FROM (SELECT 1 FROM compatibility_approvals WHERE project_id=?1 LIMIT 129)",
            [request.project_id.as_str()], |row| row.get(0),
        )?;
        if project_count >= MAX_PROJECT_APPROVALS {
            return Err(invalid("Compatibility approval registry capacity"));
        }
        transaction.execute(
            "INSERT INTO compatibility_approvals(native_owner,project_id,approved_profile_ref,profile_resource_id,profile_resource_digest,record_json) VALUES(?1,?2,?3,?4,?5,?6)",
            params![owner.as_str(), request.project_id.as_str(), request.approved_profile_ref, resource.as_str(), blob.digest.as_str(), encoded],
        )?;
        let pin = canonical_digest(&json!({"nativeOwner":owner,"projectId":request.project_id,"approvedProfileRef":request.approved_profile_ref}))
            .map_err(|e| StorageError::Contract(e.to_string()))?;
        pin_blob(&transaction, "compatibility_approval", pin.as_str(), &blob)?;
    }
    verify_owner(store, rpc, &request.project_id, Some(&owner))?;
    authority.authorize_registration(store, &owner, request)?;
    verify_resource(store, &request.project_id, &request.profile_resource)?;
    check_fence(store, &request.project_id)?;
    verify_owner(store, rpc, &request.project_id, Some(&owner))?;
    if read_record(
        store,
        &owner,
        &request.project_id,
        &request.approved_profile_ref,
    )?
    .as_ref()
        != Some(&record)
    {
        return Err(StorageError::Conflict(
            "Compatibility approval changed before commit",
        ));
    }
    rpc.check()?;
    transaction.commit()?;
    Ok(record)
}

/// Bounded protected locators for this actual native owner and Project. These
/// strings are not approvals: each consumer must enter `compatibility_approval`
/// with its current source/Policy authority before using any profile bytes.
pub fn compatibility_approval_references(
    store: &DurableStore,
    rpc: &dyn CompatibilityApprovalRpcContext,
    project: &ProjectId,
) -> StorageResult<Vec<String>> {
    let owner = verify_owner(store, rpc, project, None)?;
    let exists: bool = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='compatibility_approvals')",
        [], |row| row.get(0),
    )?;
    if !exists {
        verify_owner(store, rpc, project, Some(&owner))?;
        return Ok(Vec::new());
    }
    let mut statement = store.connection.prepare(
        "SELECT substr(CAST(approved_profile_ref AS BLOB),1,257) FROM compatibility_approvals WHERE native_owner=?1 AND project_id=?2 ORDER BY approved_profile_ref LIMIT 129",
    )?;
    let mut rows = statement.query(params![owner.as_str(), project.as_str()])?;
    let mut references = Vec::new();
    while let Some(row) = rows.next()? {
        rpc.check()?;
        if references.len() >= MAX_PROJECT_APPROVALS as usize {
            return Err(StorageError::Corrupt(
                "Compatibility approval registry capacity".into(),
            ));
        }
        let bytes: Vec<u8> = row.get(0)?;
        let reference = std::str::from_utf8(&bytes)
            .map_err(|_| StorageError::Corrupt("Compatibility approval reference UTF-8".into()))?;
        validate_ref(reference)?;
        references.push(reference.to_owned());
    }
    verify_owner(store, rpc, project, Some(&owner))?;
    Ok(references)
}

/// Missing approval stays unavailable and never creates a table. Current owner,
/// source/Policy/scope and request checks are mandatory on each successful read.
pub fn compatibility_approval(
    store: &DurableStore,
    rpc: &dyn CompatibilityApprovalRpcContext,
    authority: &mut dyn CompatibilityApprovalAuthority,
    project: &ProjectId,
    approved_profile_ref: &str,
) -> StorageResult<Option<CompatibilityApprovalRecord>> {
    validate_ref(approved_profile_ref)?;
    let owner = verify_owner(store, rpc, project, None)?;
    let Some(record) = read_record(store, &owner, project, approved_profile_ref)? else {
        verify_owner(store, rpc, project, Some(&owner))?;
        return Ok(None);
    };
    authority.authorize_read(store, &owner, &record)?;
    verify_owner(store, rpc, project, Some(&owner))?;
    if read_record(store, &owner, project, approved_profile_ref)?.as_ref() != Some(&record) {
        return Err(StorageError::Conflict(
            "Compatibility approval changed during read",
        ));
    }
    authority.authorize_read(store, &owner, &record)?;
    verify_owner(store, rpc, project, Some(&owner))?;
    if read_record(store, &owner, project, approved_profile_ref)?.as_ref() != Some(&record) {
        return Err(StorageError::Conflict(
            "Compatibility approval changed before release",
        ));
    }
    rpc.check()?;
    Ok(Some(record))
}

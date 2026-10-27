//! Explicit local-owner host approval, retained in the unique product journal.
//! An offered digest/scope is matched against this server-owned maximum. This
//! registry stores no pairing token, credential, path or wire grant. Explicit
//! read policy is separate immutable metadata in this same protected journal.

use super::{
    DurableStore, StorageError, StorageResult, WriteScope,
    journal::{decode, encode},
};
use mmmm_contracts::{PrincipalId, ProjectId, Sha256Digest, canonical_digest};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;

const MAX_SETUP_ROWS: i64 = 4096;
const MAX_SETUP_BYTES: usize = 65_536;
const MAX_SCOPE_ITEMS: usize = 4096;
const MAX_READ_POLICY_BYTES: usize = 4096;
const READ_POLICY_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS approved_host_read_policies (
 principal TEXT NOT NULL, project_id TEXT NOT NULL,
 host_artifact_digest TEXT NOT NULL CHECK(length(host_artifact_digest)=64),
 record_json TEXT NOT NULL CHECK(length(CAST(record_json AS BLOB))<=4096),
 PRIMARY KEY(principal,project_id,host_artifact_digest),
 FOREIGN KEY(principal,project_id,host_artifact_digest)
 REFERENCES approved_host_setups(principal,project_id,host_artifact_digest)
) STRICT;";
const SETUP_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS approved_host_setups (
 principal TEXT NOT NULL, project_id TEXT NOT NULL,
 host_artifact_digest TEXT NOT NULL CHECK(length(host_artifact_digest)=64),
 record_json TEXT NOT NULL,
 PRIMARY KEY(principal,project_id,host_artifact_digest)
) STRICT;";

#[derive(Clone, Debug)]
pub struct HostSetupRegistration {
    pub project_id: ProjectId,
    pub host_artifact_digest: Sha256Digest,
    pub approved_scope: WriteScope,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostSetupRecord {
    pub principal: PrincipalId,
    pub project_id: ProjectId,
    pub host_artifact_digest: Sha256Digest,
    pub approved_scope: WriteScope,
}

/// Storage representation only. The actual GameMode type belongs to the
/// reference boundary, not the wire schema or a second runtime enum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostReadPolicy {
    shape_modes: BTreeSet<String>,
    native_observation_user_local_only: bool,
}
impl HostReadPolicy {
    pub fn new(
        modes: impl IntoIterator<Item = String>,
        native_observation_user_local_only: bool,
    ) -> StorageResult<Self> {
        let mut shape_modes = BTreeSet::new();
        for mode in modes {
            if shape_modes.len() >= 4 || !shape_modes.insert(mode) {
                return Err(invalid("Host read policy has duplicate or excessive modes"));
            }
        }
        let policy = Self {
            shape_modes,
            native_observation_user_local_only,
        };
        policy.validate()?;
        Ok(policy)
    }
    fn validate(&self) -> StorageResult<()> {
        if self.shape_modes.len() > 4
            || self.shape_modes.iter().any(|mode| {
                !matches!(
                    mode.as_str(),
                    "survival" | "creative" | "adventure" | "spectator"
                )
            })
        {
            return Err(invalid("Host read policy contains an unknown mode"));
        }
        Ok(())
    }
    pub fn shape_modes(&self) -> &BTreeSet<String> {
        &self.shape_modes
    }
    pub fn native_observation_user_local_only(&self) -> bool {
        self.native_observation_user_local_only
    }
}

/// Factual protected metadata; neither this record nor its digest is a grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostReadPolicyRecord {
    principal: PrincipalId,
    project_id: ProjectId,
    host_artifact_digest: Sha256Digest,
    approved_scope_digest: Sha256Digest,
    policy: HostReadPolicy,
    policy_digest: Sha256Digest,
}
impl HostReadPolicyRecord {
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }
    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }
    pub fn host_artifact_digest(&self) -> &Sha256Digest {
        &self.host_artifact_digest
    }
    pub fn approved_scope_digest(&self) -> &Sha256Digest {
        &self.approved_scope_digest
    }
    pub fn policy(&self) -> &HostReadPolicy {
        &self.policy
    }
    pub fn policy_digest(&self) -> &Sha256Digest {
        &self.policy_digest
    }
}

fn read_policy_record(
    setup: &HostSetupRecord,
    policy: &HostReadPolicy,
) -> StorageResult<HostReadPolicyRecord> {
    policy.validate()?;
    let approved_scope_digest = canonical_digest(&json!(setup.approved_scope))
        .map_err(|_| invalid("Host read policy scope digest failed"))?;
    let policy_digest = canonical_digest(&json!({
        "kind":"mmmm_host_read_policy", "version":1,
        "principal":setup.principal, "projectId":setup.project_id,
        "hostArtifactDigest":setup.host_artifact_digest,
        "approvedScopeDigest":approved_scope_digest, "policy":policy,
    }))
    .map_err(|_| invalid("Host read policy digest failed"))?;
    Ok(HostReadPolicyRecord {
        principal: setup.principal.clone(),
        project_id: setup.project_id.clone(),
        host_artifact_digest: setup.host_artifact_digest.clone(),
        approved_scope_digest,
        policy: policy.clone(),
        policy_digest,
    })
}

/// The actual CLI or daemon authenticated local owner supplies this capability.
/// Neither a configuration principal string nor a HostHello constructs it.
pub trait HostSetupRpcContext {
    fn check(&self) -> StorageResult<()>;
    fn authenticated_local_owner(&self) -> StorageResult<PrincipalId>;
}

/// Trusted composition verifies explicit setup authorization and the current
/// Project ACL. Artifact approval must originate in the actual CLI setup path;
/// a host's claimed jar digest or public config maximum never grants approval.
pub trait HostSetupAuthority {
    fn authorize_registration(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        request: &HostSetupRegistration,
    ) -> StorageResult<()>;
    fn authorize_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        record: &HostSetupRecord,
    ) -> StorageResult<()>;
    /// Existing setup approval does not approve any additional read policy.
    fn authorize_read_policy_registration(
        &mut self,
        _store: &DurableStore,
        _principal: &PrincipalId,
        _request: &HostSetupRegistration,
        _policy: &HostReadPolicy,
    ) -> StorageResult<()> {
        Err(StorageError::Conflict(
            "Explicit host read policy approval required",
        ))
    }
    fn authorize_read_policy_read(
        &mut self,
        _store: &DurableStore,
        _principal: &PrincipalId,
        _setup: &HostSetupRecord,
        _policy: &HostReadPolicyRecord,
    ) -> StorageResult<()> {
        Err(StorageError::Conflict(
            "Current host read policy authority required",
        ))
    }
}

fn invalid(message: &'static str) -> StorageError {
    StorageError::InvalidInput(message.into())
}
fn validate_scope(scope: &WriteScope, project: &ProjectId) -> StorageResult<()> {
    scope.validate()?;
    let total = scope
        .resource_ids
        .len()
        .checked_add(scope.object_ids.len())
        .and_then(|v| v.checked_add(scope.regions.len()))
        .and_then(|v| v.checked_add(scope.external_target_ids.len()))
        .ok_or_else(|| invalid("Host setup scope item overflow"))?;
    if &scope.project_id != project || total > MAX_SCOPE_ITEMS {
        return Err(invalid(
            "Host setup requires the exact project and finite scope",
        ));
    }
    Ok(())
}

/// An offered finite rectangle must fit in one explicitly approved rectangle;
/// combining overlapping grants into a larger implicit union is not allowed.
pub fn host_scope_is_subset(requested: &WriteScope, approved: &WriteScope) -> StorageResult<bool> {
    validate_scope(requested, &requested.project_id)?;
    validate_scope(approved, &approved.project_id)?;
    Ok(requested.project_id == approved.project_id
        && requested
            .resource_ids
            .iter()
            .all(|id| approved.resource_ids.contains(id))
        && requested
            .object_ids
            .iter()
            .all(|id| approved.object_ids.contains(id))
        && requested
            .external_target_ids
            .iter()
            .all(|id| approved.external_target_ids.contains(id))
        && requested.regions.iter().all(|region| {
            approved.regions.iter().any(|maximum| {
                region.world_id == maximum.world_id
                    && region.context_id == maximum.context_id
                    && region.dimension == maximum.dimension
                    && (0..3).all(|axis| {
                        region.min[axis] >= maximum.min[axis]
                            && region.max_exclusive[axis] <= maximum.max_exclusive[axis]
                    })
            })
        }))
}

fn principal(rpc: &dyn HostSetupRpcContext) -> StorageResult<PrincipalId> {
    rpc.check()?;
    rpc.authenticated_local_owner()
}
fn verify_project_exists(store: &DurableStore, project: &ProjectId) -> StorageResult<()> {
    let exists: i64 = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM project_heads WHERE project_id=?1)",
        [project.as_str()],
        |row| row.get(0),
    )?;
    if exists != 1 {
        return Err(StorageError::NotFound("Host setup project"));
    }
    Ok(())
}

pub fn register_host_setup(
    store: &mut DurableStore,
    rpc: &dyn HostSetupRpcContext,
    authority: &mut dyn HostSetupAuthority,
    request: &HostSetupRegistration,
) -> StorageResult<HostSetupRecord> {
    register_setup(store, rpc, authority, request, None).map(|(record, _)| record)
}

/// Both immutable rows commit together. A commit error retains its original
/// storage cause and is not evidence of a completed rollback. No fallible
/// post-commit delivery/checkpoint is performed before returning the receipt.
pub fn register_host_setup_with_read_policy(
    store: &mut DurableStore,
    rpc: &dyn HostSetupRpcContext,
    authority: &mut dyn HostSetupAuthority,
    request: &HostSetupRegistration,
    policy: &HostReadPolicy,
) -> StorageResult<(HostSetupRecord, HostReadPolicyRecord)> {
    let (setup, retained) = register_setup(store, rpc, authority, request, Some(policy))?;
    // Some is constructed before the transaction whenever policy is Some.
    Ok((
        setup,
        retained.expect("explicit read policy was prepared before commit"),
    ))
}

fn register_setup(
    store: &mut DurableStore,
    rpc: &dyn HostSetupRpcContext,
    authority: &mut dyn HostSetupAuthority,
    request: &HostSetupRegistration,
    policy: Option<&HostReadPolicy>,
) -> StorageResult<(HostSetupRecord, Option<HostReadPolicyRecord>)> {
    validate_scope(&request.approved_scope, &request.project_id)?;
    let owner = principal(rpc)?;
    authority.authorize_registration(store, &owner, request)?;
    if let Some(policy) = policy {
        policy.validate()?;
        authority.authorize_read_policy_registration(store, &owner, request, policy)?;
    }
    verify_project_exists(store, &request.project_id)?;
    let record = HostSetupRecord {
        principal: owner.clone(),
        project_id: request.project_id.clone(),
        host_artifact_digest: request.host_artifact_digest.clone(),
        approved_scope: request.approved_scope.clone(),
    };
    let encoded = encode(&record)?;
    let retained_policy = policy
        .map(|policy| read_policy_record(&record, policy))
        .transpose()?;
    let encoded_policy = retained_policy.as_ref().map(encode).transpose()?;
    if encoded_policy
        .as_ref()
        .is_some_and(|bytes| bytes.len() > MAX_READ_POLICY_BYTES)
    {
        return Err(invalid("Host read policy metadata byte budget exceeded"));
    }
    if encoded.len() > MAX_SETUP_BYTES {
        return Err(invalid("Host setup metadata byte budget exceeded"));
    }
    // The authority callbacks have read-only store access, including during the
    // immediate transaction; they cannot issue another metadata mutation.
    let transaction =
        Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate)?;
    transaction.execute_batch(SETUP_SCHEMA)?;
    let old:Option<String>=transaction.query_row(
        "SELECT substr(record_json,1,65537) FROM approved_host_setups WHERE principal=?1 AND project_id=?2 AND host_artifact_digest=?3",
        params![owner.as_str(),request.project_id.as_str(),request.host_artifact_digest.as_str()],|row|row.get(0),
    ).optional()?;
    if let Some(old) = old {
        if old.len() > MAX_SETUP_BYTES {
            return Err(StorageError::Corrupt(
                "Approved host setup byte budget exceeded".into(),
            ));
        }
        let retained: HostSetupRecord = decode(&old)?;
        if retained != record {
            return Err(StorageError::Conflict("Immutable approved host setup"));
        }
    } else {
        let count: i64 =
            transaction.query_row("SELECT count(*) FROM approved_host_setups", [], |r| {
                r.get(0)
            })?;
        if count >= MAX_SETUP_ROWS {
            return Err(invalid("Approved host setup capacity exhausted"));
        }
        transaction.execute(
            "INSERT INTO approved_host_setups(principal,project_id,host_artifact_digest,record_json) VALUES(?1,?2,?3,?4)",
            params![owner.as_str(),request.project_id.as_str(),request.host_artifact_digest.as_str(),encoded],
        )?;
    }
    if let Some(encoded_policy) = encoded_policy {
        transaction.execute_batch(READ_POLICY_SCHEMA)?;
        let old: Option<String> = transaction.query_row(
            "SELECT substr(record_json,1,4097) FROM approved_host_read_policies WHERE principal=?1 AND project_id=?2 AND host_artifact_digest=?3",
            params![owner.as_str(), request.project_id.as_str(), request.host_artifact_digest.as_str()],
            |row| row.get(0),
        ).optional()?;
        if let Some(old) = old {
            if old.len() > MAX_READ_POLICY_BYTES {
                return Err(StorageError::Corrupt(
                    "Host read policy byte budget exceeded".into(),
                ));
            }
            let retained: HostReadPolicyRecord = decode(&old)?;
            if Some(&retained) != retained_policy.as_ref() {
                return Err(StorageError::Conflict(
                    "Immutable approved host read policy",
                ));
            }
        } else {
            let count: i64 = transaction.query_row(
                "SELECT count(*) FROM approved_host_read_policies",
                [],
                |row| row.get(0),
            )?;
            if count >= MAX_SETUP_ROWS {
                return Err(invalid("Approved host read policy capacity exhausted"));
            }
            transaction.execute(
                "INSERT INTO approved_host_read_policies(principal,project_id,host_artifact_digest,record_json) VALUES(?1,?2,?3,?4)",
                params![owner.as_str(), request.project_id.as_str(), request.host_artifact_digest.as_str(), encoded_policy],
            )?;
        }
    }
    rpc.check()?;
    if principal(rpc)? != owner {
        return Err(StorageError::Conflict(
            "Host setup authenticated owner changed",
        ));
    }
    authority.authorize_registration(store, &owner, request)?;
    if let Some(policy) = policy {
        authority.authorize_read_policy_registration(store, &owner, request, policy)?;
    }
    verify_project_exists(store, &request.project_id)?;
    transaction.commit()?;
    Ok((record, retained_policy))
}

/// Read approval through the actual current owner/project authorization. A
/// digest match still grants no new scope; a larger Offer fails closed here.
pub fn host_setup(
    store: &DurableStore,
    rpc: &dyn HostSetupRpcContext,
    authority: &mut dyn HostSetupAuthority,
    project: &ProjectId,
    artifact: &Sha256Digest,
    requested_scope: Option<&WriteScope>,
) -> StorageResult<HostSetupRecord> {
    let owner = principal(rpc)?;
    let tables:i64=store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='approved_host_setups')",[],|r|r.get(0),
    )?;
    if tables != 1 {
        return Err(StorageError::NotFound("Approved host setup"));
    }
    let encoded:Option<String>=store.connection.query_row(
        "SELECT substr(record_json,1,65537) FROM approved_host_setups WHERE principal=?1 AND project_id=?2 AND host_artifact_digest=?3",
        params![owner.as_str(),project.as_str(),artifact.as_str()],|row|row.get(0),
    ).optional()?;
    let encoded = encoded.ok_or(StorageError::NotFound("Approved host setup"))?;
    if encoded.len() > MAX_SETUP_BYTES {
        return Err(StorageError::Corrupt(
            "Approved host setup byte budget exceeded".into(),
        ));
    }
    let record: HostSetupRecord = decode(&encoded)?;
    if record.principal != owner
        || &record.project_id != project
        || &record.host_artifact_digest != artifact
    {
        return Err(StorageError::Corrupt(
            "Approved host setup identity differs".into(),
        ));
    }
    validate_scope(&record.approved_scope, project)?;
    authority.authorize_read(store, &owner, &record)?;
    verify_project_exists(store, project)?;
    if let Some(requested) = requested_scope
        && !host_scope_is_subset(requested, &record.approved_scope)?
    {
        return Err(StorageError::Conflict(
            "Host Offer exceeds the approved setup scope",
        ));
    }
    rpc.check()?;
    if principal(rpc)? != owner {
        return Err(StorageError::Conflict(
            "Host setup authenticated owner changed",
        ));
    }
    authority.authorize_read(store, &owner, &record)?;
    Ok(record)
}

/// A missing companion remains unavailable. Reads never create a registry or
/// adopt a policy from public setup, HostHello, permissions or SourceRef DTOs.
pub fn host_read_policy(
    store: &DurableStore,
    rpc: &dyn HostSetupRpcContext,
    authority: &mut dyn HostSetupAuthority,
    project: &ProjectId,
    artifact: &Sha256Digest,
    requested_scope: &WriteScope,
) -> StorageResult<HostReadPolicyRecord> {
    let setup = host_setup(
        store,
        rpc,
        authority,
        project,
        artifact,
        Some(requested_scope),
    )?;
    let exists: i64 = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='approved_host_read_policies')",
        [], |row| row.get(0),
    )?;
    if exists != 1 {
        return Err(StorageError::NotFound("Approved host read policy"));
    }
    let encoded: Option<String> = store.connection.query_row(
        "SELECT substr(record_json,1,4097) FROM approved_host_read_policies WHERE principal=?1 AND project_id=?2 AND host_artifact_digest=?3",
        params![setup.principal.as_str(), project.as_str(), artifact.as_str()], |row| row.get(0),
    ).optional()?;
    let encoded = encoded.ok_or(StorageError::NotFound("Approved host read policy"))?;
    if encoded.len() > MAX_READ_POLICY_BYTES {
        return Err(StorageError::Corrupt(
            "Host read policy byte budget exceeded".into(),
        ));
    }
    let record: HostReadPolicyRecord = decode(&encoded)?;
    if record != read_policy_record(&setup, &record.policy)? {
        return Err(StorageError::Corrupt(
            "Host read policy identity, scope or digest differs".into(),
        ));
    }
    authority.authorize_read_policy_read(store, &setup.principal, &setup, &record)?;
    rpc.check()?;
    if principal(rpc)? != setup.principal {
        return Err(StorageError::Conflict(
            "Host read policy authenticated owner changed",
        ));
    }
    authority.authorize_read(store, &setup.principal, &setup)?;
    authority.authorize_read_policy_read(store, &setup.principal, &setup, &record)?;
    Ok(record)
}

#[cfg(test)]
#[path = "host_setup_tests.rs"]
mod tests;

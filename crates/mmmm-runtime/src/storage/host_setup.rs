//! Explicit local-owner host approval, retained in the unique product journal.
//! An offered digest/scope is matched against this server-owned maximum. This
//! registry stores no pairing token, credential, path, policy or wire grant.

use super::{
    DurableStore, StorageError, StorageResult, WriteScope,
    journal::{decode, encode},
};
use mmmm_contracts::{PrincipalId, ProjectId, Sha256Digest};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

const MAX_SETUP_ROWS: i64 = 4096;
const MAX_SETUP_BYTES: usize = 65_536;
const MAX_SCOPE_ITEMS: usize = 4096;
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
    validate_scope(&request.approved_scope, &request.project_id)?;
    let owner = principal(rpc)?;
    authority.authorize_registration(store, &owner, request)?;
    verify_project_exists(store, &request.project_id)?;
    let record = HostSetupRecord {
        principal: owner.clone(),
        project_id: request.project_id.clone(),
        host_artifact_digest: request.host_artifact_digest.clone(),
        approved_scope: request.approved_scope.clone(),
    };
    let encoded = encode(&record)?;
    if encoded.len() > MAX_SETUP_BYTES {
        return Err(invalid("Host setup metadata byte budget exceeded"));
    }
    // The authority callbacks have read-only store access, including during the
    // immediate transaction; they cannot issue another metadata mutation.
    let transaction =
        Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate)?;
    transaction.execute_batch(SETUP_SCHEMA)?;
    let old:Option<String>=transaction.query_row(
        "SELECT record_json FROM approved_host_setups WHERE principal=?1 AND project_id=?2 AND host_artifact_digest=?3",
        params![owner.as_str(),request.project_id.as_str(),request.host_artifact_digest.as_str()],|row|row.get(0),
    ).optional()?;
    if let Some(old) = old {
        let retained: HostSetupRecord = decode(&old)?;
        if old.len() > MAX_SETUP_BYTES || retained != record {
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
    rpc.check()?;
    if principal(rpc)? != owner {
        return Err(StorageError::Conflict(
            "Host setup authenticated owner changed",
        ));
    }
    authority.authorize_registration(store, &owner, request)?;
    verify_project_exists(store, &request.project_id)?;
    transaction.commit()?;
    Ok(record)
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
        "SELECT record_json FROM approved_host_setups WHERE principal=?1 AND project_id=?2 AND host_artifact_digest=?3",
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

#[cfg(test)]
#[path = "host_setup_tests.rs"]
mod tests;

//! FN31 reads registered CAS resources. Public references are locators, never
//! authority and never filesystem/network paths. Trusted composition registers
//! immutable metadata; each read obtains fresh authenticated context and ACL.

use super::{BlobRef, DurableStore, StorageError, journal::pin_blob};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use mmmm_contracts::{
    ContextId, ContractValidator, OperationId, PrincipalId, ProjectId, ResourceId, Sha256Digest,
    canonical_digest, encode_json, parse_json,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const MAX_REGISTERED_RESOURCES: i64 = 65_536;
const MAX_RESOURCE_METADATA_BYTES: usize = 16_384;
const REGISTRY_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS artifact_resources (
    resource_id TEXT PRIMARY KEY,
    resource_json TEXT NOT NULL,
    owner_json TEXT NOT NULL,
    blob_digest TEXT NOT NULL REFERENCES blobs(digest),
    byte_length INTEGER NOT NULL CHECK(byte_length>=0)
) STRICT;";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactError {
    pub code: &'static str,
    pub message: &'static str,
}
impl ArtifactError {
    pub const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
    pub const fn forbidden() -> Self {
        Self::new(
            "RESOURCE_FORBIDDEN",
            "Current resource access is not permitted",
        )
    }
    const fn invalid() -> Self {
        Self::new(
            "INPUT_INVALID",
            "Artifact input violates the canonical contract",
        )
    }
    const fn range() -> Self {
        Self::new("RANGE_INVALID", "Artifact byte range is invalid")
    }
}
impl std::fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for ArtifactError {}
impl From<StorageError> for ArtifactError {
    fn from(error: StorageError) -> Self {
        // No path, SQLite statement or untrusted diagnostic is exposed over RPC.
        match error {
            StorageError::Corrupt(_) | StorageError::UnsafePath => Self::new(
                "RESOURCE_INTEGRITY_FAILED",
                "Registered artifact failed integrity verification",
            ),
            StorageError::Conflict(_) => Self::new(
                "RESOURCE_REGISTRATION_CONFLICT",
                "Resource identity is already registered with different metadata",
            ),
            StorageError::NotFound(_) => Self::forbidden(),
            _ => Self::new("RESOURCE_UNAVAILABLE", "Registered artifact cannot be read"),
        }
    }
}
pub type ArtifactResult<T> = Result<T, ArtifactError>;

/// Internal ownership is persisted separately from the public ResourceRef. It
/// is not an authority claim accepted from JSON-RPC callers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ResourceOwner {
    Operation(OperationId),
    Project(ProjectId),
    Principal(PrincipalId),
}

/// The Coordinator implements this with its opaque AuthenticatedPrincipal and
/// RequestBudget. It must check current method permission, pairing and session
/// validity rather than constructing identity from request JSON.
pub trait ArtifactRpcContext {
    fn check(&self) -> ArtifactResult<()>;
    fn principal_for_context(&self, context: &ContextId) -> ArtifactResult<PrincipalId>;
}

/// Concrete host/application integration must reload current context and check
/// owner/project/resource ACL. Digest knowledge and a public reference grant no
/// permission. Called at admission and again before releasing the slice.
pub trait ResourceAuthority {
    fn authorize_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: &ContextId,
        owner: &ResourceOwner,
        resource: &Value,
    ) -> ArtifactResult<()>;
}

struct RegisteredResource {
    resource: Value,
    owner: ResourceOwner,
    blob: BlobRef,
}

/// Registration is a trusted bootstrap/issuance API, not a public RPC. CAS must
/// already contain the exact bytes. Retention and immutable metadata are added
/// in one transaction after readback verification, using the existing blob_refs.
pub fn register_resource(
    store: &mut DurableStore,
    resource: &Value,
    owner: ResourceOwner,
) -> ArtifactResult<()> {
    register_resource_inner(store, resource, owner, true)
}

fn register_resource_inner(
    store: &mut DurableStore,
    resource: &Value,
    owner: ResourceOwner,
    verify_bytes: bool,
) -> ArtifactResult<()> {
    let (resource_id, blob) = validate_resource(&store.validator, resource)?;
    let resource_bytes = encode_json(resource).map_err(|_| ArtifactError::invalid())?;
    if resource_bytes.len() > MAX_RESOURCE_METADATA_BYTES {
        return Err(ArtifactError::invalid());
    }
    let owner_bytes =
        encode_json(&serde_json::to_value(&owner).map_err(|_| ArtifactError::invalid())?)
            .map_err(|_| ArtifactError::invalid())?;
    let resource_json = String::from_utf8(resource_bytes).map_err(|_| ArtifactError::invalid())?;
    let owner_json = String::from_utf8(owner_bytes).map_err(|_| ArtifactError::invalid())?;
    match &owner {
        ResourceOwner::Operation(id) => {
            store.operation(id)?;
        }
        ResourceOwner::Project(id) => {
            store.project(id)?;
        }
        ResourceOwner::Principal(_) => (),
    }
    if verify_bytes {
        store.cas.verify(&blob)?;
    }
    store
        .connection
        .execute_batch(REGISTRY_SCHEMA)
        .map_err(StorageError::from)?;
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(StorageError::from)?;
    let old: Option<(String, String, String, i64)> = transaction.query_row(
        "SELECT resource_json,owner_json,blob_digest,byte_length FROM artifact_resources WHERE resource_id=?1",
        [resource_id.as_str()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).optional().map_err(StorageError::from)?;
    if let Some((old_resource, old_owner, old_digest, old_length)) = old {
        if parse_json(old_resource.as_bytes()).map_err(|_| ArtifactError::invalid())? != *resource
            || parse_json(old_owner.as_bytes()).map_err(|_| ArtifactError::invalid())?
                != serde_json::to_value(&owner).map_err(|_| ArtifactError::invalid())?
            || old_digest != blob.digest.as_str()
            || old_length != blob.byte_length as i64
        {
            return Err(StorageError::Conflict("Immutable artifact resource identity").into());
        }
        transaction.commit().map_err(StorageError::from)?;
        return Ok(());
    }
    let count: i64 = transaction
        .query_row("SELECT count(*) FROM artifact_resources", [], |row| {
            row.get(0)
        })
        .map_err(StorageError::from)?;
    if count >= MAX_REGISTERED_RESOURCES {
        return Err(ArtifactError::new(
            "RESOURCE_LIMIT",
            "Resource registry capacity is exhausted",
        ));
    }
    pin_blob(&transaction, "artifact", resource_id.as_str(), &blob)?;
    transaction.execute(
        "INSERT INTO artifact_resources(resource_id,resource_json,owner_json,blob_digest,byte_length) VALUES(?1,?2,?3,?4,?5)",
        params![resource_id.as_str(), resource_json, owner_json, blob.digest.as_str(), blob.byte_length as i64],
    ).map_err(StorageError::from)?;
    transaction.commit().map_err(StorageError::from)?;
    Ok(())
}

/// Application calls this only after authorizing the operation. The source must
/// already be retained by that operation, preventing accidental cross-operation
/// publication. Previously verified/pinned source metadata is reused here;
/// artifact.read always verifies actual bytes again. Repeated issuance returns
/// the same immutable resource identity without rescanning every report payload.
pub fn issue_operation_resource(
    store: &mut DurableStore,
    operation: &OperationId,
    blob: &BlobRef,
    media_type: &str,
) -> ArtifactResult<Value> {
    store.operation(operation)?;
    if media_type.is_empty() || media_type.len() > MAX_RESOURCE_METADATA_BYTES / 2 {
        return Err(ArtifactError::invalid());
    }
    let owned: i64 = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM blob_refs r JOIN blobs b ON b.digest=r.digest WHERE r.owner_id=?1 AND r.digest=?2 AND b.byte_length=?3 AND r.owner_kind IN ('operation','application_evidence','application_summary','recovery'))",
        params![operation.as_str(), blob.digest.as_str(), i64::try_from(blob.byte_length).map_err(|_| ArtifactError::invalid())?], |row| row.get(0),
    ).map_err(StorageError::from)?;
    if owned != 1 {
        return Err(ArtifactError::forbidden());
    }
    let owner = ResourceOwner::Operation(operation.clone());
    let identity = canonical_digest(&json!({"owner":owner,"sha256":blob.digest,"sizeBytes":blob.byte_length,"mediaType":media_type}))
        .map_err(|_| ArtifactError::invalid())?;
    let resource = json!({
        "resourceId":format!("artifact-{}", identity.as_str()),
        "sha256":blob.digest,"sizeBytes":blob.byte_length,"mediaType":media_type,
    });
    register_resource_inner(store, &resource, owner, false)?;
    Ok(resource)
}

pub struct ArtifactReader {
    authority: Box<dyn ResourceAuthority>,
    validator: ContractValidator,
    max_verification_bytes: u64,
}
impl ArtifactReader {
    pub fn new(
        authority: Box<dyn ResourceAuthority>,
        max_verification_bytes: u64,
    ) -> ArtifactResult<Self> {
        if max_verification_bytes == 0 || max_verification_bytes > i64::MAX as u64 {
            return Err(ArtifactError::new(
                "INVALID_BUDGET",
                "Artifact verification budget is invalid",
            ));
        }
        Ok(Self {
            authority,
            validator: ContractValidator::embedded().map_err(|_| ArtifactError::invalid())?,
            max_verification_bytes,
        })
    }

    pub fn read(
        &mut self,
        store: &DurableStore,
        rpc: &dyn ArtifactRpcContext,
        input: &Value,
    ) -> ArtifactResult<Value> {
        rpc.check()?;
        encode_json(input).map_err(|_| ArtifactError::invalid())?;
        self.validator
            .validate("ArtifactReadRequest", input)
            .map_err(|_| ArtifactError::invalid())?;
        let context = ContextId::new(
            input["contextId"]
                .as_str()
                .ok_or_else(ArtifactError::invalid)?,
        )
        .map_err(|_| ArtifactError::invalid())?;
        let resource_id = ResourceId::new(
            input["resourceId"]
                .as_str()
                .ok_or_else(ArtifactError::invalid)?,
        )
        .map_err(|_| ArtifactError::invalid())?;
        let offset = input["offset"]
            .as_str()
            .ok_or_else(ArtifactError::invalid)?
            .parse::<u64>()
            .map_err(|_| ArtifactError::range())?;
        let limit = input["limitBytes"]
            .as_u64()
            .ok_or_else(ArtifactError::range)? as usize;
        let principal = rpc.principal_for_context(&context)?;
        let registered = load_resource(store, &self.validator, &resource_id)?;
        self.authority.authorize_read(
            store,
            &principal,
            &context,
            &registered.owner,
            &registered.resource,
        )?;
        rpc.check()?;
        if offset > registered.blob.byte_length {
            return Err(ArtifactError::range());
        }
        if registered.blob.byte_length > self.max_verification_bytes {
            return Err(ArtifactError::new(
                "RESOURCE_READ_BUDGET_EXCEEDED",
                "Artifact exceeds its verification byte budget",
            ));
        }
        let bytes = store.cas.read_verified_slice::<ArtifactError, _>(
            &registered.blob,
            offset,
            limit,
            || rpc.check(),
        )?;
        let next = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(ArtifactError::range)?;
        let (encoding, data) = match std::str::from_utf8(&bytes) {
            Ok(text) => ("utf8", text.to_owned()),
            Err(_) => ("base64", STANDARD.encode(&bytes)),
        };
        let output = json!({
            "resource":registered.resource,"offset":offset.to_string(),
            "encoding":encoding,"data":data,
            "nextOffset":if next < registered.blob.byte_length { Some(next.to_string()) } else { None },
        });
        self.validator
            .validate("ArtifactSlice", &output)
            .map_err(|_| ArtifactError::invalid())?;
        // Worst-case escaping/base64 is finite, and the common RPC boundary owns
        // its separate control-frame budget. No truncation repairs the slice.
        encode_json(&output).map_err(|_| ArtifactError::invalid())?;
        rpc.check()?;
        let current_principal = rpc.principal_for_context(&context)?;
        if current_principal != principal {
            return Err(ArtifactError::forbidden());
        }
        self.authority.authorize_read(
            store,
            &principal,
            &context,
            &registered.owner,
            &output["resource"],
        )?;
        rpc.check()?;
        Ok(output)
    }
}

fn validate_resource(
    validator: &ContractValidator,
    resource: &Value,
) -> ArtifactResult<(ResourceId, BlobRef)> {
    validator
        .validate("ResourceRef", resource)
        .map_err(|_| ArtifactError::invalid())?;
    let resource_id = ResourceId::new(
        resource["resourceId"]
            .as_str()
            .ok_or_else(ArtifactError::invalid)?,
    )
    .map_err(|_| ArtifactError::invalid())?;
    let digest = Sha256Digest::new(
        resource["sha256"]
            .as_str()
            .ok_or_else(ArtifactError::invalid)?,
    )
    .map_err(|_| ArtifactError::invalid())?;
    let byte_length = resource["sizeBytes"]
        .as_u64()
        .ok_or_else(ArtifactError::invalid)?;
    Ok((
        resource_id,
        BlobRef {
            digest,
            byte_length,
        },
    ))
}

fn load_resource(
    store: &DurableStore,
    validator: &ContractValidator,
    resource_id: &ResourceId,
) -> ArtifactResult<RegisteredResource> {
    let installed: i64 = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='artifact_resources')",
        [], |row| row.get(0),
    ).map_err(StorageError::from)?;
    if installed != 1 {
        return Err(ArtifactError::forbidden());
    }
    let row: Option<(String, String, String, i64)> = store.connection.query_row(
        "SELECT resource_json,owner_json,blob_digest,byte_length FROM artifact_resources WHERE resource_id=?1",
        [resource_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).optional().map_err(StorageError::from)?;
    let (resource_json, owner_json, digest, length) = row.ok_or_else(ArtifactError::forbidden)?;
    if resource_json.len() > MAX_RESOURCE_METADATA_BYTES
        || owner_json.len() > MAX_RESOURCE_METADATA_BYTES
    {
        return Err(
            StorageError::Corrupt("Artifact metadata exceeds its byte budget".into()).into(),
        );
    }
    let resource = parse_json(resource_json.as_bytes()).map_err(|_| ArtifactError::invalid())?;
    let owner: ResourceOwner = serde_json::from_value(
        parse_json(owner_json.as_bytes()).map_err(|_| ArtifactError::invalid())?,
    )
    .map_err(|_| ArtifactError::invalid())?;
    let (record_id, blob) = validate_resource(validator, &resource)?;
    if &record_id != resource_id
        || digest != blob.digest.as_str()
        || u64::try_from(length).ok() != Some(blob.byte_length)
    {
        return Err(StorageError::Corrupt(
            "Artifact index differs from its immutable metadata".into(),
        )
        .into());
    }
    Ok(RegisteredResource {
        resource,
        owner,
        blob,
    })
}

#[cfg(test)]
#[path = "artifact_tests.rs"]
mod tests;

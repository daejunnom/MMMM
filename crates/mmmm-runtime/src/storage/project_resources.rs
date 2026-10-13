//! Checked authoring source reads from the unique product store. Identifiers,
//! historical pins and ResourceRef URIs are not access grants or I/O paths.
//! The caller supplies actual authentication and current Project/resource ACL.

use super::{
    BlobRef, DurableStore, StorageError, StorageResult, artifact::ResourceOwner, journal::decode,
};
use mmmm_contracts::{
    ContextId, PrincipalId, ProjectId, ResourceId, Sha256Digest, parse_json,
    verify_projected_digest,
};
use rusqlite::{OptionalExtension, params};
use serde_json::Value;
use std::collections::BTreeSet;

const MAX_PROJECT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_SOURCE_RESOURCE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 16_384;
const MAX_PROJECT_ENTRIES: usize = 4096;

/// Opaque actual transport identity and the same per-request budget. Read-only
/// Project inspection may have no game context; no fake context is created.
pub trait ProjectSourceRpcContext {
    fn check(&self) -> StorageResult<()>;
    fn authenticated_principal(&self) -> StorageResult<PrincipalId>;
    fn context_id(&self) -> Option<&ContextId>;
}

#[derive(Clone, Debug)]
pub enum ProjectResourceQuery {
    Current {
        resource_id: ResourceId,
    },
    Exact {
        resource_id: ResourceId,
        digest: Sha256Digest,
    },
    Historical {
        project_revision: Sha256Digest,
        resource_id: ResourceId,
        digest: Sha256Digest,
    },
    /// Private staged compiler/export inputs need not appear in resourceIds.
    /// They must have an exact immutable registration owned by this Project.
    RegisteredImmutable {
        resource_id: ResourceId,
    },
}
pub struct ProjectResourceRequest<'a> {
    pub project: &'a ProjectId,
    pub current_project_revision: &'a Sha256Digest,
    pub query: &'a ProjectResourceQuery,
    pub expected: Option<&'a Value>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectResourceProvenance {
    CurrentProject { project_revision: Sha256Digest },
    HistoricalProject { project_revision: Sha256Digest },
    ImmutableProjectArtifact,
}
#[derive(Clone, Debug)]
pub struct RegisteredProjectResource {
    pub resource: Value,
    pub blob: BlobRef,
    pub owner: ResourceOwner,
    pub provenance: ProjectResourceProvenance,
}
pub struct ProjectResourceBytes {
    pub registered: RegisteredProjectResource,
    pub bytes: Vec<u8>,
}

/// Recheck actual current Project ACL before any content read and resource ACL
/// against the server-owned registration before CAS access and before return.
/// A None context is authorized by Project rights, not invented game grants.
pub trait ProjectResourceAuthority {
    fn authorize_project_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        current_revision: &Sha256Digest,
    ) -> StorageResult<()>;
    fn authorize_resource_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> StorageResult<()>;
}
pub struct ProjectResourceReader {
    authority: Box<dyn ProjectResourceAuthority>,
    max_resource_bytes: u64,
}
impl ProjectResourceReader {
    pub fn new(
        authority: Box<dyn ProjectResourceAuthority>,
        max_resource_bytes: u64,
    ) -> StorageResult<Self> {
        if max_resource_bytes == 0 || max_resource_bytes > MAX_SOURCE_RESOURCE_BYTES {
            return Err(invalid("Project resource read ceiling is invalid"));
        }
        Ok(Self {
            authority,
            max_resource_bytes,
        })
    }
    pub fn read_project(
        &mut self,
        store: &DurableStore,
        rpc: &dyn ProjectSourceRpcContext,
        project: &ProjectId,
        current_revision: &Sha256Digest,
        max_bytes: u64,
    ) -> StorageResult<Value> {
        if max_bytes == 0 || max_bytes > MAX_PROJECT_BYTES {
            return Err(invalid("Project document read budget is invalid"));
        }
        let principal = principal(rpc)?;
        self.authority.authorize_project_read(
            store,
            &principal,
            rpc.context_id(),
            project,
            current_revision,
        )?;
        check_current_head(store, project, current_revision)?;
        let document = load_project(store, rpc, project, current_revision, max_bytes)?;
        self.final_project_check(store, rpc, &principal, project, current_revision)?;
        Ok(document)
    }
    /// Resolve only the authenticated Project's durable head metadata, then
    /// perform the same bounded schema/hash/ACL path as an exact revision read.
    pub fn current_project(
        &mut self,
        store: &DurableStore,
        rpc: &dyn ProjectSourceRpcContext,
        project: &ProjectId,
        max_bytes: u64,
    ) -> StorageResult<Value> {
        rpc.check()?;
        let revision: Option<String> = store
            .connection
            .query_row(
                "SELECT revision FROM project_heads WHERE project_id=?1",
                [project.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        let revision =
            Sha256Digest::new(revision.ok_or(StorageError::NotFound("Current Project source"))?)
                .map_err(contract)?;
        self.read_project(store, rpc, project, &revision, max_bytes)
    }
    /// Metadata is returned only after bounded full-CAS hash/size verification.
    /// The body is discarded; no URI or caller path is opened.
    pub fn metadata(
        &mut self,
        store: &DurableStore,
        rpc: &dyn ProjectSourceRpcContext,
        request: &ProjectResourceRequest<'_>,
    ) -> StorageResult<RegisteredProjectResource> {
        let (principal, registered) = self.admit(store, rpc, request)?;
        self.check_resource_size(&registered.blob, self.max_resource_bytes)?;
        store.cas.read_verified_slice::<StorageError, _>(
            &registered.blob,
            registered.blob.byte_length,
            1,
            || rpc.check(),
        )?;
        self.final_resource_check(store, rpc, &principal, request, &registered)?;
        Ok(registered)
    }
    /// Exact expected hash, size, media and metadata are mandatory on whole
    /// reads. One handle captures and hashes the same <=64KiB stream chunks.
    pub fn read(
        &mut self,
        store: &DurableStore,
        rpc: &dyn ProjectSourceRpcContext,
        request: &ProjectResourceRequest<'_>,
        max_bytes: u64,
    ) -> StorageResult<ProjectResourceBytes> {
        if request.expected.is_none() {
            return Err(invalid(
                "Whole resource read requires exact expected metadata",
            ));
        }
        let (principal, registered) = self.admit(store, rpc, request)?;
        self.check_resource_size(&registered.blob, max_bytes)?;
        let bytes = store.read_blob_checked(&registered.blob, max_bytes, || rpc.check())?;
        self.final_resource_check(store, rpc, &principal, request, &registered)?;
        Ok(ProjectResourceBytes { registered, bytes })
    }
    fn check_resource_size(&self, blob: &BlobRef, max_bytes: u64) -> StorageResult<()> {
        if max_bytes == 0 || max_bytes > self.max_resource_bytes || blob.byte_length > max_bytes {
            return Err(invalid("Project resource exceeds its finite read budget"));
        }
        Ok(())
    }
    fn admit(
        &mut self,
        store: &DurableStore,
        rpc: &dyn ProjectSourceRpcContext,
        request: &ProjectResourceRequest<'_>,
    ) -> StorageResult<(PrincipalId, RegisteredProjectResource)> {
        let principal = principal(rpc)?;
        self.authority.authorize_project_read(
            store,
            &principal,
            rpc.context_id(),
            request.project,
            request.current_project_revision,
        )?;
        check_current_head(store, request.project, request.current_project_revision)?;
        let current = load_project(
            store,
            rpc,
            request.project,
            request.current_project_revision,
            MAX_PROJECT_BYTES,
        )?;
        let registration = resolve(store, rpc, request, &current)?;
        if let Some(expected) = request.expected {
            validate_resource(store, expected)?;
            if expected != &registration.resource {
                return Err(StorageError::Conflict("Exact source ResourceRef metadata"));
            }
        }
        self.authority.authorize_resource_read(
            store,
            &principal,
            rpc.context_id(),
            request.project,
            &registration,
        )?;
        rpc.check()?;
        Ok((principal, registration))
    }
    fn final_project_check(
        &mut self,
        store: &DurableStore,
        rpc: &dyn ProjectSourceRpcContext,
        initial: &PrincipalId,
        project: &ProjectId,
        current_revision: &Sha256Digest,
    ) -> StorageResult<()> {
        if &principal(rpc)? != initial {
            return Err(StorageError::Conflict("Project source principal changed"));
        }
        check_current_head(store, project, current_revision)?;
        self.authority.authorize_project_read(
            store,
            initial,
            rpc.context_id(),
            project,
            current_revision,
        )?;
        rpc.check()
    }
    fn final_resource_check(
        &mut self,
        store: &DurableStore,
        rpc: &dyn ProjectSourceRpcContext,
        initial: &PrincipalId,
        request: &ProjectResourceRequest<'_>,
        registered: &RegisteredProjectResource,
    ) -> StorageResult<()> {
        self.final_project_check(
            store,
            rpc,
            initial,
            request.project,
            request.current_project_revision,
        )?;
        // Metadata/current-head changes during the read cannot authorize stale
        // bytes. Resolve and compare again before releasing the captured body.
        let current = load_project(
            store,
            rpc,
            request.project,
            request.current_project_revision,
            MAX_PROJECT_BYTES,
        )?;
        let actual = resolve(store, rpc, request, &current)?;
        if actual.resource != registered.resource
            || actual.blob != registered.blob
            || actual.owner != registered.owner
            || actual.provenance != registered.provenance
        {
            return Err(StorageError::Conflict(
                "Project resource registration changed during read",
            ));
        }
        // Re-resolving current/historical provenance can perform CAS I/O after
        // the first final ACL check. Recheck Project authority after that I/O;
        // a separate resource ACL must not keep a revoked Project read alive.
        self.final_project_check(
            store,
            rpc,
            initial,
            request.project,
            request.current_project_revision,
        )?;
        self.authority.authorize_resource_read(
            store,
            initial,
            rpc.context_id(),
            request.project,
            registered,
        )?;
        rpc.check()
    }
}

fn invalid(message: &'static str) -> StorageError {
    StorageError::InvalidInput(message.into())
}
fn contract(error: impl std::fmt::Display) -> StorageError {
    StorageError::Contract(error.to_string())
}
fn principal(rpc: &dyn ProjectSourceRpcContext) -> StorageResult<PrincipalId> {
    rpc.check()?;
    rpc.authenticated_principal()
}
fn table_exists(store: &DurableStore, name: &str) -> StorageResult<bool> {
    Ok(store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [name],
        |r| r.get::<_, i64>(0),
    )? == 1)
}
fn check_current_head(
    store: &DurableStore,
    project: &ProjectId,
    revision: &Sha256Digest,
) -> StorageResult<()> {
    let row:Option<(String,String,Option<String>)>=store.connection.query_row(
        "SELECT h.revision,h.blob_digest,d.blob_digest FROM project_heads h LEFT JOIN documents d ON d.definition='Project' AND d.document_id=h.project_id AND d.content_hash=h.revision WHERE h.project_id=?1",
        [project.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).optional()?;
    let (current, head_blob, document_blob) =
        row.ok_or(StorageError::NotFound("Current Project source"))?;
    if current != revision.as_str() || document_blob.as_deref() != Some(head_blob.as_str()) {
        return Err(StorageError::Conflict(
            "Current Project source revision/index",
        ));
    }
    Ok(())
}
fn load_project(
    store: &DurableStore,
    rpc: &dyn ProjectSourceRpcContext,
    project: &ProjectId,
    revision: &Sha256Digest,
    max_bytes: u64,
) -> StorageResult<Value> {
    rpc.check()?;
    let row:Option<(String,i64)>=store.connection.query_row(
        "SELECT d.blob_digest,b.byte_length FROM documents d JOIN blobs b ON b.digest=d.blob_digest WHERE d.definition='Project' AND d.document_id=?1 AND d.content_hash=?2",
        params![project.as_str(),revision.as_str()],|r|Ok((r.get(0)?,r.get(1)?)),
    ).optional()?;
    let blob = blob_from_row(row.ok_or(StorageError::NotFound("Historical Project source"))?)?;
    let bytes = store.read_blob_checked(&blob, max_bytes, || rpc.check())?;
    let value = store
        .validator
        .parse_and_validate("Project", &bytes)
        .map_err(contract)?;
    if value["projectId"] != project.as_str()
        || verify_projected_digest("Project", &value).map_err(contract)? != *revision
    {
        return Err(StorageError::Corrupt(
            "Stored Project source identity/digest differs".into(),
        ));
    }
    rpc.check()?;
    Ok(value)
}
fn resource_membership(project: &Value, id: &ResourceId) -> StorageResult<()> {
    let entries = project["resourceIds"]
        .as_array()
        .ok_or_else(|| invalid("Project resource index missing"))?;
    if entries.len() > MAX_PROJECT_ENTRIES {
        return Err(invalid("Project resource index budget exceeded"));
    }
    let mut ids = BTreeSet::new();
    for entry in entries {
        let id: ResourceId = serde_json::from_value(entry.clone()).map_err(contract)?;
        if !ids.insert(id) {
            return Err(StorageError::Corrupt(
                "Project repeats a resource identity".into(),
            ));
        }
    }
    if !ids.contains(id) {
        return Err(StorageError::Conflict(
            "Resource is not owned by the Project source",
        ));
    }
    Ok(())
}
fn blob_from_row((digest, length): (String, i64)) -> StorageResult<BlobRef> {
    Ok(BlobRef {
        digest: Sha256Digest::new(digest).map_err(contract)?,
        byte_length: u64::try_from(length).map_err(|_| invalid("Negative source blob length"))?,
    })
}
fn validate_resource(
    store: &DurableStore,
    resource: &Value,
) -> StorageResult<(ResourceId, BlobRef)> {
    if mmmm_contracts::encode_json(resource)
        .map_err(contract)?
        .len()
        > MAX_METADATA_BYTES
    {
        return Err(invalid("Source ResourceRef metadata exceeds its budget"));
    }
    store
        .validator
        .validate("ResourceRef", resource)
        .map_err(contract)?;
    Ok((
        serde_json::from_value(resource["resourceId"].clone()).map_err(contract)?,
        BlobRef {
            digest: serde_json::from_value(resource["sha256"].clone()).map_err(contract)?,
            byte_length: resource["sizeBytes"]
                .as_u64()
                .ok_or_else(|| invalid("Source resource size is invalid"))?,
        },
    ))
}
fn retained_blob(store: &DurableStore, blob: &BlobRef) -> StorageResult<()> {
    let length: Option<i64> = store
        .connection
        .query_row(
            "SELECT byte_length FROM blobs WHERE digest=?1",
            [blob.digest.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    if length.and_then(|v| u64::try_from(v).ok()) != Some(blob.byte_length) {
        return Err(StorageError::Corrupt(
            "Source ResourceRef CAS metadata differs".into(),
        ));
    }
    Ok(())
}
fn immutable_artifact(
    store: &DurableStore,
    project: &ProjectId,
    id: &ResourceId,
) -> StorageResult<RegisteredProjectResource> {
    if !table_exists(store, "artifact_resources")? {
        return Err(StorageError::NotFound("Immutable Project resource"));
    }
    let row:Option<(String,String,String,i64)>=store.connection.query_row(
        "SELECT resource_json,owner_json,blob_digest,byte_length FROM artifact_resources WHERE resource_id=?1 AND length(CAST(resource_json AS BLOB))<=16384 AND length(CAST(owner_json AS BLOB))<=16384",
        [id.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
    ).optional()?;
    let (json, owner_json, digest, length) =
        row.ok_or(StorageError::NotFound("Immutable Project resource"))?;
    let resource = parse_json(json.as_bytes()).map_err(contract)?;
    let owner: ResourceOwner = decode(&owner_json)?;
    let (actual_id, blob) = validate_resource(store, &resource)?;
    if actual_id != *id
        || owner != ResourceOwner::Project(project.clone())
        || blob_from_row((digest, length))? != blob
    {
        return Err(StorageError::Conflict(
            "Immutable Project resource owner/content",
        ));
    }
    retained_blob(store, &blob)?;
    let pinned:i64=store.connection.query_row("SELECT EXISTS(SELECT 1 FROM blob_refs WHERE owner_kind='artifact' AND owner_id=?1 AND digest=?2)",params![id.as_str(),blob.digest.as_str()],|r|r.get(0))?;
    if pinned != 1 {
        return Err(StorageError::Corrupt(
            "Immutable Project artifact retention is missing".into(),
        ));
    }
    Ok(RegisteredProjectResource {
        resource,
        blob,
        owner,
        provenance: ProjectResourceProvenance::ImmutableProjectArtifact,
    })
}
fn version(
    store: &DurableStore,
    project: &ProjectId,
    id: &ResourceId,
    digest: &Sha256Digest,
) -> StorageResult<RegisteredProjectResource> {
    if !table_exists(store, "project_resource_versions")?
        || !table_exists(store, "project_resource_provenance")?
    {
        return Err(StorageError::NotFound("Versioned Project resource"));
    }
    let row:Option<(String,i64)>=store.connection.query_row(
        "SELECT resource_json,byte_length FROM project_resource_versions WHERE project_id=?1 AND resource_id=?2 AND digest=?3 AND length(CAST(resource_json AS BLOB))<=16384",
        params![project.as_str(),id.as_str(),digest.as_str()],|r|Ok((r.get(0)?,r.get(1)?)),
    ).optional()?;
    let (json, length) = row.ok_or(StorageError::NotFound("Versioned Project resource"))?;
    let resource = parse_json(json.as_bytes()).map_err(contract)?;
    let (actual_id, blob) = validate_resource(store, &resource)?;
    if actual_id != *id
        || &blob.digest != digest
        || u64::try_from(length).ok() != Some(blob.byte_length)
    {
        return Err(StorageError::Corrupt(
            "Project resource version metadata differs".into(),
        ));
    }
    retained_blob(store, &blob)?;
    let owner = mmmm_contracts::canonical_digest(
        &serde_json::json!({"projectId":project,"resourceId":id,"sha256":digest}),
    )
    .map_err(contract)?;
    let retained:i64=store.connection.query_row("SELECT EXISTS(SELECT 1 FROM blob_refs WHERE owner_kind='project_resource' AND owner_id=?1 AND digest=?2)",params![owner.as_str(),digest.as_str()],|r|r.get(0))?;
    if retained != 1 {
        return Err(StorageError::Corrupt(
            "Project resource version retention is missing".into(),
        ));
    }
    // The immutable version remains anchored by historical Project membership.
    let revisions = provenance_revisions(store, project, id, digest)?;
    let revision = revisions
        .into_iter()
        .next()
        .ok_or(StorageError::NotFound("Project resource provenance"))?;
    Ok(RegisteredProjectResource {
        resource,
        blob,
        owner: ResourceOwner::Project(project.clone()),
        provenance: ProjectResourceProvenance::HistoricalProject {
            project_revision: revision,
        },
    })
}
fn provenance_revisions(
    store: &DurableStore,
    project: &ProjectId,
    id: &ResourceId,
    digest: &Sha256Digest,
) -> StorageResult<Vec<Sha256Digest>> {
    let mut statement=store.connection.prepare(
        "SELECT p.project_revision FROM project_resource_provenance p JOIN documents d ON d.definition='Project' AND d.document_id=p.project_id AND d.content_hash=p.project_revision WHERE p.project_id=?1 AND p.resource_id=?2 AND p.digest=?3 AND p.project_definition='Project' ORDER BY p.project_revision LIMIT 4097",
    )?;
    let values = statement
        .query_map(
            params![project.as_str(), id.as_str(), digest.as_str()],
            |r| r.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() > MAX_PROJECT_ENTRIES {
        return Err(invalid("Resource historical provenance budget exceeded"));
    }
    values
        .into_iter()
        .map(|v| Sha256Digest::new(v).map_err(contract))
        .collect()
}
fn validate_history(
    store: &DurableStore,
    rpc: &dyn ProjectSourceRpcContext,
    project: &ProjectId,
    id: &ResourceId,
    digest: &Sha256Digest,
    revision: &Sha256Digest,
) -> StorageResult<()> {
    if !provenance_revisions(store, project, id, digest)?.contains(revision) {
        return Err(StorageError::Conflict(
            "Exact historical Project resource provenance",
        ));
    }
    let historical = load_project(store, rpc, project, revision, MAX_PROJECT_BYTES)?;
    resource_membership(&historical, id)
}
fn current_version(
    store: &DurableStore,
    project: &ProjectId,
    id: &ResourceId,
) -> StorageResult<Option<RegisteredProjectResource>> {
    if !table_exists(store, "project_resource_heads")? {
        return Ok(None);
    }
    let digest: Option<String> = store
        .connection
        .query_row(
            "SELECT digest FROM project_resource_heads WHERE project_id=?1 AND resource_id=?2",
            params![project.as_str(), id.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    digest
        .map(|digest| {
            version(
                store,
                project,
                id,
                &Sha256Digest::new(digest).map_err(contract)?,
            )
        })
        .transpose()
}
fn resolve(
    store: &DurableStore,
    rpc: &dyn ProjectSourceRpcContext,
    request: &ProjectResourceRequest<'_>,
    current: &Value,
) -> StorageResult<RegisteredProjectResource> {
    rpc.check()?;
    match request.query {
        ProjectResourceQuery::RegisteredImmutable { resource_id } => {
            immutable_artifact(store, request.project, resource_id)
        }
        ProjectResourceQuery::Current { resource_id } => {
            resource_membership(current, resource_id)?;
            if let Some(mut registered) = current_version(store, request.project, resource_id)? {
                validate_history(
                    store,
                    rpc,
                    request.project,
                    resource_id,
                    &registered.blob.digest,
                    request.current_project_revision,
                )?;
                registered.provenance = ProjectResourceProvenance::CurrentProject {
                    project_revision: request.current_project_revision.clone(),
                };
                Ok(registered)
            } else {
                let mut registered = immutable_artifact(store, request.project, resource_id)?;
                registered.provenance = ProjectResourceProvenance::CurrentProject {
                    project_revision: request.current_project_revision.clone(),
                };
                Ok(registered)
            }
        }
        ProjectResourceQuery::Exact {
            resource_id,
            digest,
        } => {
            resource_membership(current, resource_id)?;
            let registered = if table_exists(store, "project_resource_versions")? {
                let exists:i64=store.connection.query_row("SELECT EXISTS(SELECT 1 FROM project_resource_versions WHERE project_id=?1 AND resource_id=?2 AND digest=?3)",params![request.project.as_str(),resource_id.as_str(),digest.as_str()],|r|r.get(0))?;
                if exists == 1 {
                    version(store, request.project, resource_id, digest)?
                } else {
                    immutable_artifact(store, request.project, resource_id)?
                }
            } else {
                immutable_artifact(store, request.project, resource_id)?
            };
            if &registered.blob.digest != digest {
                return Err(StorageError::Conflict("Exact Project resource digest"));
            }
            if let ProjectResourceProvenance::HistoricalProject { project_revision } =
                &registered.provenance
            {
                validate_history(
                    store,
                    rpc,
                    request.project,
                    resource_id,
                    digest,
                    project_revision,
                )?;
            }
            Ok(registered)
        }
        ProjectResourceQuery::Historical {
            project_revision,
            resource_id,
            digest,
        } => {
            resource_membership(current, resource_id)?;
            let mut registered = version(store, request.project, resource_id, digest)?;
            validate_history(
                store,
                rpc,
                request.project,
                resource_id,
                digest,
                project_revision,
            )?;
            registered.provenance = ProjectResourceProvenance::HistoricalProject {
                project_revision: project_revision.clone(),
            };
            Ok(registered)
        }
    }
}

#[cfg(test)]
#[path = "project_resources_tests.rs"]
mod tests;

//! Native local-owner workspace setup. The explicit Project locator is read
//! from the already locked protected Store; public contexts/scopes/policies
//! never create this kernel-owner witness or this read-only grant.

use crate::{authority::LocalAuthority, credential::local_owner_principal};
use mmmm_contracts::{
    ContextId, PrincipalId, ProjectId, ResourceId, Sha256Digest, encode_json, projected_digest,
    verify_projected_digest,
};
use mmmm_runtime::storage::{
    DurableStore, StorageError, StorageResult,
    artifact::ResourceOwner,
    owned_documents::{OwnedDocumentAuthority, OwnedDocumentPin, OwnedDocumentReader},
    project_resources::{
        ProjectResourceAuthority, ProjectResourceQuery, ProjectResourceReader,
        ProjectResourceRequest, ProjectSourceRpcContext, RegisteredProjectResource,
    },
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

const MAX_PROJECT: u64 = 8 * 1024 * 1024;
const MAX_SOURCE: u64 = 128 * 1024 * 1024;
const MAX_ITEMS: usize = 4096;
const READ_LIFETIME: Duration = Duration::from_secs(1800);

/// No Deserialize/Debug/JSON constructor. The witness can only be captured
/// from an actual protected Store under the current UID/SID. Its lifetime is
/// the original native setup budget, not a caller-claimed policy expiration.
#[derive(Clone)]
pub struct NativeOwnerWitness {
    owner: PrincipalId,
    root: PathBuf,
    deadline: Instant,
}
impl NativeOwnerWitness {
    pub(crate) fn capture(store: &DurableStore, deadline: Instant) -> StorageResult<Self> {
        let witness = Self {
            owner: local_owner_principal().map_err(|_| denied())?,
            root: store.data_root().to_path_buf(),
            deadline,
        };
        witness.check_store(store)?;
        Ok(witness)
    }
    pub fn principal(&self) -> &PrincipalId {
        &self.owner
    }
    pub fn check(&self) -> StorageResult<()> {
        if Instant::now() >= self.deadline
            || crate::peer::fatal_stop_requested()
            || local_owner_principal().map_err(|_| denied())? != self.owner
        {
            return Err(denied());
        }
        Ok(())
    }
    pub fn check_store(&self, store: &DurableStore) -> StorageResult<()> {
        self.check()?;
        if store.data_root() != self.root {
            return Err(denied());
        }
        Ok(())
    }
}
impl ProjectSourceRpcContext for NativeOwnerWitness {
    fn check(&self) -> StorageResult<()> {
        NativeOwnerWitness::check(self)
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.owner.clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        None
    }
}
impl crate::bootstrap::workspace_seal::Sealed for NativeOwnerWitness {}
impl crate::bootstrap::NativeWorkspacePermit for NativeOwnerWitness {
    fn check_project(
        &self,
        store: &DurableStore,
        project: &ProjectId,
    ) -> StorageResult<PrincipalId> {
        self.check_store(store)?;
        let owner =
            mmmm_runtime::storage::bootstrap::registered_native_project_owner(store, project)?;
        if owner != *self.principal() {
            return Err(denied());
        }
        self.check_store(store)?;
        Ok(owner)
    }
}

#[derive(Clone)]
pub struct WorkspaceBootstrap {
    pub witness: NativeOwnerWitness,
    pub context: Value,
    pub project_revision: Sha256Digest,
    /// Missing retained source bytes grant no object/resource read permission.
    pub excluded_sources: Vec<Value>,
}

/// Called only by explicit native daemon --project composition while it holds
/// the sole protected Store. Sources are verified before the grant is issued.
/// The caller must register the returned context using this same witness and
/// current grant in the shared workspace registry before publishing a listener.
pub fn prepare_workspace(
    store: &DurableStore,
    authority: &LocalAuthority,
    project_id: &ProjectId,
    deadline: Instant,
) -> StorageResult<WorkspaceBootstrap> {
    let witness = NativeOwnerWitness::capture(store, deadline)?;
    if mmmm_runtime::storage::bootstrap::registered_native_project_owner(store, project_id)?
        != *witness.principal()
    {
        return Err(denied());
    }
    let project = store.project(project_id)?;
    let revision = verify_projected_digest("Project", &project).map_err(|_| denied())?;
    let bytes = encode_json(&project).map_err(|_| denied())?;
    if bytes.len() as u64 > MAX_PROJECT {
        return Err(budget());
    }
    let resources: Vec<ResourceId> =
        serde_json::from_value(project["resourceIds"].clone()).map_err(|_| denied())?;
    let documents: Vec<OwnedDocumentPin> =
        serde_json::from_value(project["ownedResources"].clone()).map_err(|_| denied())?;
    if resources
        .len()
        .checked_add(documents.len())
        .is_none_or(|n| n > MAX_ITEMS)
    {
        return Err(budget());
    }
    let access = OwnerSourceAccess {
        witness: witness.clone(),
        project: project_id.clone(),
        revision: revision.clone(),
        resources: resources.iter().cloned().collect(),
        documents: documents.iter().cloned().collect(),
    };
    let access = Arc::new(access);
    let mut resource_ids = BTreeSet::new();
    let mut object_ids = BTreeSet::new();
    let mut excluded = Vec::new();
    let mut remaining = MAX_SOURCE;
    for resource in resources {
        witness.check_store(store)?;
        let mut reader = ProjectResourceReader::new(
            Box::new(OwnerResourceAuthority(access.clone())),
            remaining.max(1),
        )?;
        let query = ProjectResourceQuery::Current {
            resource_id: resource.clone(),
        };
        let request = ProjectResourceRequest {
            project: project_id,
            current_project_revision: &revision,
            query: &query,
            expected: None,
        };
        match reader.metadata(store, &witness, &request) {
            Ok(actual) => {
                remaining = remaining
                    .checked_sub(actual.blob.byte_length)
                    .ok_or_else(budget)?;
                resource_ids.insert(resource);
            }
            Err(StorageError::NotFound(_)) => excluded.push(exclusion(resource.as_str())),
            Err(error) => return Err(error),
        }
    }
    for pin in documents {
        witness.check_store(store)?;
        let mut reader = OwnedDocumentReader::new(
            Box::new(OwnerDocumentAuthority(access.clone())),
            remaining.clamp(1, MAX_PROJECT),
        )?;
        match reader.read_known_history_bytes(store, &witness, project_id, &revision, &pin) {
            Ok(actual) => {
                remaining = remaining
                    .checked_sub(actual.bytes.len() as u64)
                    .ok_or_else(budget)?;
                object_ids.insert(pin.object_id);
            }
            Err(StorageError::NotFound(_)) => excluded.push(exclusion(pin.object_id.as_str())),
            Err(error) => return Err(error),
        }
    }
    witness.check_store(store)?;
    if store.project(project_id)? != project {
        return Err(StorageError::Conflict("Native workspace Project revision"));
    }
    let context_id = ContextId::new(random_id("workspace-context")?).map_err(|_| denied())?;
    let workspace_id = random_id("workspace")?;
    let scope = json!({
        "projectId":project_id,"resourceIds":resource_ids,"objectIds":object_ids,
        "regions":[],"externalTargetIds":[]
    });
    let policy = authority
        .stage_project_access(
            witness.owner.clone(),
            project_id.clone(),
            scope.clone(),
            BTreeSet::from([context_id.clone()]),
            READ_LIFETIME,
        )
        .map_err(|_| denied())?;
    let mut context = json!({
        "contractVersion":mmmm_contracts::CONTRACT_VERSION,"contextId":context_id,
        "principalRef":witness.owner,"projectId":project_id,
        "environment":{"kind":"offline","workspaceId":workspace_id,"side":"offline"},
        "policyRevision":policy,"scope":scope,"contextDigest":"0".repeat(64)
    });
    let mut finalize = || -> StorageResult<()> {
        context["contextDigest"] =
            json!(projected_digest("ExecutionContext", &context).map_err(|_| denied())?);
        witness.check_store(store)?;
        authority
            .activate_staged_project(&witness.owner, project_id, &policy)
            .map_err(|_| denied())?;
        witness.check_store(store)
    };
    if let Err(error) = finalize() {
        authority
            .revoke_staged_project(&witness.owner, project_id, &policy)
            .map_err(|_| {
                StorageError::Conflict("Native workspace authority retirement unconfirmed")
            })?;
        return Err(error);
    }
    Ok(WorkspaceBootstrap {
        witness,
        context,
        project_revision: revision,
        excluded_sources: excluded,
    })
}

struct OwnerSourceAccess {
    witness: NativeOwnerWitness,
    project: ProjectId,
    revision: Sha256Digest,
    resources: BTreeSet<ResourceId>,
    documents: BTreeSet<OwnedDocumentPin>,
}
impl OwnerSourceAccess {
    fn authorize(
        &self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        revision: &Sha256Digest,
    ) -> StorageResult<()> {
        self.witness.check()?;
        if principal != &self.witness.owner
            || context.is_some()
            || project != &self.project
            || revision != &self.revision
        {
            return Err(denied());
        }
        Ok(())
    }
}
struct OwnerResourceAuthority(Arc<OwnerSourceAccess>);
/// Cold native 관리용 좁은 reader다. workspace/context/grant를 설치하지 않는다.
/// 실제 owner witness와 명시적으로 선택한 IDs만 사용하며 membership/provenance/
/// CAS는 기존 ProjectResourceReader가 검사한다. caller는 원래 budget과 등록된
/// Project owner를 이 reader 호출 전후에 계속 확인해야 한다.
pub(crate) fn native_owner_resource_reader(
    owner: &NativeOwnerWitness,
    project: &ProjectId,
    revision: &Sha256Digest,
    resources: BTreeSet<ResourceId>,
    ceiling: u64,
) -> StorageResult<ProjectResourceReader> {
    owner.check()?;
    if resources.len() > MAX_ITEMS {
        return Err(budget());
    }
    ProjectResourceReader::new(
        Box::new(OwnerResourceAuthority(Arc::new(OwnerSourceAccess {
            witness: owner.clone(),
            project: project.clone(),
            revision: revision.clone(),
            resources,
            documents: BTreeSet::new(),
        }))),
        ceiling,
    )
}
impl ProjectResourceAuthority for OwnerResourceAuthority {
    fn authorize_project_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        revision: &Sha256Digest,
    ) -> StorageResult<()> {
        self.0.witness.check_store(store)?;
        self.0.authorize(principal, context, project, revision)
    }
    fn authorize_resource_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> StorageResult<()> {
        self.0.witness.check_store(store)?;
        self.0
            .authorize(principal, context, project, &self.0.revision)?;
        let id: ResourceId = serde_json::from_value(resource.resource["resourceId"].clone())
            .map_err(|_| denied())?;
        if resource.owner != ResourceOwner::Project(project.clone())
            || !self.0.resources.contains(&id)
        {
            return Err(denied());
        }
        Ok(())
    }
}
struct OwnerDocumentAuthority(Arc<OwnerSourceAccess>);
impl OwnedDocumentAuthority for OwnerDocumentAuthority {
    fn authorize_read(
        &mut self,
        _principal: &PrincipalId,
        _context: &ContextId,
        _project: &ProjectId,
        _revision: &Sha256Digest,
        _pin: &OwnedDocumentPin,
    ) -> StorageResult<()> {
        Err(denied())
    }
    fn authorize_project_read(
        &mut self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> StorageResult<()> {
        self.0.authorize(principal, context, project, revision)?;
        if !self.0.documents.contains(pin) {
            return Err(denied());
        }
        Ok(())
    }
}
fn random_id(prefix: &str) -> StorageResult<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| denied())?;
    let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{prefix}-{suffix}"))
}
fn exclusion(id: &str) -> Value {
    json!({"code":"SOURCE_UNAVAILABLE","severity":"warning","message":"Declared source has no retained registered bytes","path":id})
}
fn denied() -> StorageError {
    StorageError::Conflict("Native workspace local owner/source authority")
}
fn budget() -> StorageError {
    StorageError::InvalidInput("Native workspace source budget exceeded".into())
}

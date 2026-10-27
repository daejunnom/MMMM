//! Native owner authoring ingress in the one locked product Store. Preparation
//! changes nothing; its private immutable candidate can publish only through
//! the runtime's single atomic source/head transaction. No game grant is made.

use crate::{
    authority::LocalAuthority, service::RequestBudget, workspace_bootstrap::NativeOwnerWitness,
};
use mmmm_application::{AppError, AppResult};
use mmmm_contracts::{
    ContextId, ContractValidator, JsonLimits, PrincipalId, ProjectId, ResourceId, Sha256Digest,
    encode_json, projected_digest, raw_digest,
    strict_json::{ControlledJsonError, parse_json_with_control},
    verify_projected_digest,
};
use mmmm_domain::{
    Instance, Prefab,
    commands::CommandModule,
    instance::require_source,
    prefab::semantic_diagnostics,
    time::{AnimationClip, validate_clip},
};
use mmmm_planner::{OwnedKind, ProjectCatalog};
use mmmm_runtime::storage::{
    DurableStore, StorageError, StorageResult, WriteScope,
    artifact::ResourceOwner,
    bootstrap::registered_native_project_owner,
    native_owned_sources::{
        NativeOwnedDocumentSource, NativeOwnedResourceSource, NativeOwnedSourceCommitPermit,
        NativeOwnedSourceCommitReceipt, NativeOwnedSourceCommitRequest,
        NativeOwnedSourceCommitView, commit_native_owned_sources,
    },
    owned_documents::{
        OwnedDocumentAuthority, OwnedDocumentKind, OwnedDocumentPin, OwnedDocumentReader,
    },
    project_resources::{
        ProjectResourceAuthority, ProjectResourceQuery, ProjectResourceReader,
        ProjectResourceRequest, ProjectSourceRpcContext, RegisteredProjectResource,
    },
};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

const MAX_DOCUMENT: usize = 8 * 1024 * 1024;
const MAX_RAW_TOTAL: usize = 32 * 1024 * 1024;
const MAX_RETAINED_TOTAL: u64 = 128 * 1024 * 1024;
const MAX_ITEMS: usize = 256;
const MAX_PROJECT_ITEMS: usize = 4096;
const MAX_RESOURCE_METADATA: usize = 16_384;

/// Raw authoring content supplied by the actual native owner management call.
/// Metadata is the canonical ResourceRef; it carries no owner/read/write grant
/// and no URI is resolved. Existing registrations cannot become new inputs by
/// supplying their digest or copying their bytes; runtime enforces new IDs.
pub struct NativeRawSourceResource<'a> {
    pub metadata: &'a [u8],
    pub bytes: &'a [u8],
}

/// Closed authoring kinds supported by this initial admission path. A source
/// body may contain references; no kind admits executable source or grants
/// component, host, Apply, external-target or redistribution authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeSourceKind {
    Prefab,
    Instance,
    Clip,
    CommandModule,
}
impl NativeSourceKind {
    fn stored(self) -> OwnedDocumentKind {
        match self {
            Self::Prefab => OwnedDocumentKind::Prefab,
            Self::Instance => OwnedDocumentKind::Instance,
            Self::Clip => OwnedDocumentKind::AnimationClip,
            Self::CommandModule => OwnedDocumentKind::CommandModule,
        }
    }
}

/// Raw bounded canonical contract documents, not a second wire schema. Bytes
/// are parsed before validation so duplicate fields cannot replace identity.
pub struct NativeSourceDocument<'a> {
    pub kind: NativeSourceKind,
    pub bytes: &'a [u8],
}
pub struct NativeSourceInput<'a> {
    /// A locator and optimistic precondition; neither constructs owner access.
    pub project: &'a ProjectId,
    pub expected_revision: &'a Sha256Digest,
    pub documents: &'a [NativeSourceDocument<'a>],
    /// Exact ResourceRef metadata for already retained Project-owned resources.
    /// No supplied digest is read directly from CAS; the actual registration is
    /// resolved by resource ID under the current source ACL before CAS access.
    pub retained_resources: &'a [&'a [u8]],
    /// New immutable resource bytes for this exact source batch. Existing
    /// resources continue through the original current source ACL reader.
    pub raw_resources: &'a [NativeRawSourceResource<'a>],
}

struct PreparedDocument {
    pin: OwnedDocumentPin,
    value: Value,
    original_bytes: Vec<u8>,
    original_digest: Sha256Digest,
}
struct PreparedRawResource {
    resource: Value,
    metadata_bytes: Vec<u8>,
    metadata_digest: Sha256Digest,
    bytes: Vec<u8>,
    digest: Sha256Digest,
}

/// Private construction, no Deserialize/Serialize or authority constructor.
/// This is a checked candidate, not a source registration, grant or proof that
/// a Project mutation succeeded. It retains the original owner and call budget.
pub struct PreparedNativeSources {
    access: NativeSourceAccess,
    base_project: Value,
    next_project: Value,
    documents: Vec<PreparedDocument>,
    retained_resources: Vec<RegisteredProjectResource>,
    raw_resources: Vec<PreparedRawResource>,
    policy_resource: RegisteredProjectResource,
    policy: Value,
}
impl PreparedNativeSources {
    pub fn project_id(&self) -> &ProjectId {
        &self.access.project
    }
    pub fn base_revision(&self) -> &Sha256Digest {
        &self.access.revision
    }
    pub fn proposed_revision(&self) -> AppResult<Sha256Digest> {
        verify_projected_digest("Project", &self.next_project).map_err(digest_error)
    }
    pub fn document_count(&self) -> usize {
        self.documents.len()
    }
    pub fn resource_count(&self) -> usize {
        self.retained_resources.len() + self.raw_resources.len()
    }
    /// Returning the same candidate later cannot reset its deadline or restore
    /// a revoked owner/policy/scope. Runtime repeats current ownership, source
    /// ACL, exact head/provenance and fence checks in the commit transaction.
    pub fn check_current(&self, store: &DurableStore) -> AppResult<()> {
        self.access.check_store(store)?;
        let mut reader = resource_reader(&self.access, MAX_DOCUMENT as u64)?;
        let current = reader
            .read_project(
                store,
                &self.access,
                &self.access.project,
                &self.access.revision,
                MAX_DOCUMENT as u64,
            )
            .map_err(|error| self.access.release(error))?;
        if current != self.base_project {
            return Err(conflict());
        }
        let catalog = ProjectCatalog::from_project(&current)?;
        for document in &self.documents {
            self.access.check_local()?;
            if raw_digest(&document.original_bytes) != document.original_digest
                || parse_checked(&self.access, &document.original_bytes, MAX_DOCUMENT)?
                    != document.value
                || verify_projected_digest(document.pin.kind.definition(), &document.value)
                    .map_err(digest_error)?
                    != document.pin.revision
            {
                return Err(conflict());
            }
            self.access.check_local()?;
        }
        for resource in &self.raw_resources {
            self.access.check_store(store)?;
            if raw_digest(&resource.metadata_bytes) != resource.metadata_digest
                || parse_checked(
                    &self.access,
                    &resource.metadata_bytes,
                    MAX_RESOURCE_METADATA,
                )? != resource.resource
                || raw_digest(&resource.bytes) != resource.digest
            {
                return Err(conflict());
            }
            check_raw_resource(&resource.resource, &resource.bytes)?;
            let id: ResourceId = decode(&resource.resource["resourceId"])?;
            if catalog.resource_ids().contains(&id) {
                return Err(conflict());
            }
        }
        if derive_project(
            &self.base_project,
            &self.documents,
            &self.retained_resources,
            &self.raw_resources,
        )? != self.next_project
        {
            return Err(conflict());
        }
        let query = ProjectResourceQuery::Current {
            resource_id: decode(&self.policy_resource.resource["resourceId"])?,
        };
        let request = ProjectResourceRequest {
            project: &self.access.project,
            current_project_revision: &self.access.revision,
            query: &query,
            expected: Some(&self.policy_resource.resource),
        };
        let mut reader = resource_reader(&self.access, MAX_RETAINED_TOTAL)?;
        let policy = reader
            .read(store, &self.access, &request, MAX_DOCUMENT as u64)
            .map_err(|error| self.access.release(error))?;
        if parse_checked(&self.access, &policy.bytes, MAX_DOCUMENT)? != self.policy {
            return Err(conflict());
        }
        for resource in &self.retained_resources {
            self.access.check_store(store)?;
            let id: ResourceId = decode(&resource.resource["resourceId"])?;
            let query = if catalog.resource_ids().contains(&id) {
                ProjectResourceQuery::Exact {
                    resource_id: id,
                    digest: resource.blob.digest.clone(),
                }
            } else {
                ProjectResourceQuery::RegisteredImmutable { resource_id: id }
            };
            let request = ProjectResourceRequest {
                project: &self.access.project,
                current_project_revision: &self.access.revision,
                query: &query,
                expected: Some(&resource.resource),
            };
            let current = reader
                .metadata(store, &self.access, &request)
                .map_err(|error| self.access.release(error))?;
            if current.blob != resource.blob
                || current.owner != resource.owner
                || current.provenance != resource.provenance
            {
                return Err(conflict());
            }
        }
        self.access.check_store(store)
    }

    /// Consumes the exact preparation and its original owner/request lifetime.
    /// Success is a factual SQLite commit receipt, never a reusable authority
    /// or Apply grant. Failed publication may leave unreferenced immutable CAS
    /// bytes; the runtime transaction preserves the previous head/associations.
    pub fn commit(self, store: &mut DurableStore) -> AppResult<NativeOwnedSourceCommitReceipt> {
        self.check_current(store)?;
        let project_bytes = encode_json(&self.next_project).map_err(|_| invalid())?;
        let documents = self
            .documents
            .iter()
            .map(|document| NativeOwnedDocumentSource {
                pin: &document.pin,
                bytes: &document.original_bytes,
            })
            .collect::<Vec<_>>();
        let resources = self
            .retained_resources
            .iter()
            .map(|resource| NativeOwnedResourceSource::Retained {
                resource: &resource.resource,
            })
            .chain(
                self.raw_resources
                    .iter()
                    .map(|resource| NativeOwnedResourceSource::Raw {
                        metadata: &resource.metadata_bytes,
                        bytes: &resource.bytes,
                    }),
            )
            .collect::<Vec<_>>();
        let request = NativeOwnedSourceCommitRequest {
            project: &self.access.project,
            expected_revision: &self.access.revision,
            project_bytes: &project_bytes,
            documents: &documents,
            resources: &resources,
        };
        let permit = PreparedNativeCommitPermit {
            prepared: &self,
            project_bytes: &project_bytes,
        };
        // A completed transaction stays a completed commit even if cancellation
        // arrives after it. Do not replace its factual receipt with rollback.
        commit_native_owned_sources(store, &permit, &request)
            .map_err(|cause| self.access.release(cause))
    }
}

struct PreparedNativeCommitPermit<'a> {
    prepared: &'a PreparedNativeSources,
    project_bytes: &'a [u8],
}
impl ProjectSourceRpcContext for PreparedNativeCommitPermit<'_> {
    fn check(&self) -> StorageResult<()> {
        self.prepared.access.check()
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.prepared.access.authenticated_principal()
    }
    fn context_id(&self) -> Option<&ContextId> {
        None
    }
}
impl NativeOwnedSourceCommitPermit for PreparedNativeCommitPermit<'_> {
    fn check_store(&self, store: &DurableStore) -> StorageResult<()> {
        // Head changes only at runtime's final metadata action. This local
        // checkpoint intentionally retains policy/owner/fence checks without
        // performing a base-head source read after that action.
        self.prepared
            .access
            .check_store(store)
            .map_err(|cause| self.prepared.access.reject(cause))
    }
    fn authorize_commit(
        &self,
        store: &DurableStore,
        view: &NativeOwnedSourceCommitView<'_>,
    ) -> StorageResult<PrincipalId> {
        self.check_store(store)?;
        let prepared = self.prepared;
        let request = view.request;
        if request.project != &prepared.access.project
            || request.expected_revision != &prepared.access.revision
            || request.project_bytes != self.project_bytes
            || view.base_project != &prepared.base_project
            || view.next_project != &prepared.next_project
            || request.documents.len() != prepared.documents.len()
            || request.resources.len() != prepared.resource_count()
        {
            return Err(prepared.access.reject(conflict()));
        }
        for (actual, expected) in request.documents.iter().zip(&prepared.documents) {
            if actual.pin != &expected.pin || actual.bytes != expected.original_bytes {
                return Err(prepared.access.reject(conflict()));
            }
        }
        for (actual, expected) in request
            .resources
            .iter()
            .take(prepared.retained_resources.len())
            .zip(&prepared.retained_resources)
        {
            if !matches!(actual, NativeOwnedResourceSource::Retained { resource } if *resource == &expected.resource)
            {
                return Err(prepared.access.reject(conflict()));
            }
        }
        for (actual, expected) in request
            .resources
            .iter()
            .skip(prepared.retained_resources.len())
            .zip(&prepared.raw_resources)
        {
            if !matches!(actual, NativeOwnedResourceSource::Raw { metadata, bytes }
                if *metadata == expected.metadata_bytes && *bytes == expected.bytes)
            {
                return Err(prepared.access.reject(conflict()));
            }
        }
        prepared
            .check_current(store)
            .map_err(|cause| prepared.access.reject(cause))?;
        self.check_store(store)?;
        Ok(prepared.access.owner.principal().clone())
    }
    fn resource_reader(&self, ceiling: u64) -> StorageResult<ProjectResourceReader> {
        self.check()?;
        ProjectResourceReader::new(Box::new(self.prepared.access.clone()), ceiling)
    }
    fn owned_document_reader(&self, ceiling: u64) -> StorageResult<OwnedDocumentReader> {
        self.check()?;
        OwnedDocumentReader::new(Box::new(self.prepared.access.clone()), ceiling)
    }
}

#[derive(Clone)]
struct NativeSourceAccess {
    owner: NativeOwnerWitness,
    budget: RequestBudget,
    authority: LocalAuthority,
    project: ProjectId,
    revision: Sha256Digest,
    policy_revision: Sha256Digest,
    read_scope: Value,
    callback_failure: Rc<RefCell<Option<AppError>>>,
}
impl NativeSourceAccess {
    fn check_local(&self) -> AppResult<()> {
        self.budget.check().map_err(service_error)?;
        self.owner.check().map_err(storage_error)?;
        if self
            .authority
            .policy_revision(self.owner.principal(), &self.project)?
            != self.policy_revision
            || self
                .authority
                .project_scope(self.owner.principal(), &self.project)?
                != self.read_scope
        {
            return Err(denied());
        }
        self.budget.check().map_err(service_error)
    }
    fn check_store(&self, store: &DurableStore) -> AppResult<()> {
        self.check_local()?;
        self.owner.check_store(store).map_err(storage_error)?;
        if registered_native_project_owner(store, &self.project).map_err(storage_error)?
            != *self.owner.principal()
        {
            return Err(denied());
        }
        // This checkpoint observes fences and never claims one. The publisher
        // repeats it inside the one actual source commit transaction.
        store
            .check_write_scope(
                &WriteScope {
                    project_id: self.project.clone(),
                    resource_ids: Vec::new(),
                    object_ids: Vec::new(),
                    regions: Vec::new(),
                    external_target_ids: Vec::new(),
                },
                true,
                None,
            )
            .map_err(storage_error)?;
        self.check_local()
    }
    fn authorize(
        &self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        revision: &Sha256Digest,
    ) -> StorageResult<()> {
        self.check_local().map_err(|error| self.reject(error))?;
        if principal != self.owner.principal()
            || context.is_some()
            || project != &self.project
            || revision != &self.revision
        {
            return Err(self.reject(denied()));
        }
        Ok(())
    }
    fn source_scope(&self, key: &str, id: &str) -> StorageResult<()> {
        self.check_local().map_err(|error| self.reject(error))?;
        if !self.read_scope[key]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|value| value.as_str() == Some(id)))
        {
            return Err(self.reject(denied()));
        }
        Ok(())
    }
    fn reject(&self, error: AppError) -> StorageError {
        if let Ok(mut failure) = self.callback_failure.try_borrow_mut()
            && failure.is_none()
        {
            *failure = Some(error);
        }
        StorageError::Conflict("Current native source owner/read authority")
    }
    fn release(&self, error: StorageError) -> AppError {
        self.callback_failure
            .try_borrow_mut()
            .ok()
            .and_then(|mut failure| failure.take())
            .unwrap_or_else(|| storage_error(error))
    }
}
impl ProjectSourceRpcContext for NativeSourceAccess {
    fn check(&self) -> StorageResult<()> {
        self.check_local().map_err(|error| self.reject(error))
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.owner.principal().clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        None
    }
}
impl ProjectResourceAuthority for NativeSourceAccess {
    fn authorize_project_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        revision: &Sha256Digest,
    ) -> StorageResult<()> {
        self.check_store(store)
            .map_err(|error| self.reject(error))?;
        self.authorize(principal, context, project, revision)
    }
    fn authorize_resource_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> StorageResult<()> {
        self.check_store(store)
            .map_err(|error| self.reject(error))?;
        self.authorize(principal, context, project, &self.revision)?;
        if resource.owner != ResourceOwner::Project(self.project.clone()) {
            return Err(self.reject(denied()));
        }
        self.source_scope(
            "resourceIds",
            text(&resource.resource, "resourceId").map_err(|error| self.reject(error))?,
        )
    }
}
impl OwnedDocumentAuthority for NativeSourceAccess {
    fn authorize_read(
        &mut self,
        _: &PrincipalId,
        _: &ContextId,
        _: &ProjectId,
        _: &Sha256Digest,
        _: &OwnedDocumentPin,
    ) -> StorageResult<()> {
        Err(self.reject(denied()))
    }
    fn authorize_project_read(
        &mut self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> StorageResult<()> {
        self.authorize(principal, context, project, revision)?;
        self.source_scope("objectIds", pin.object_id.as_str())
    }
}

/// Only trusted native owner management composition passes the actual witness
/// and original budget. Caller JSON cannot supply principal, read scope, policy,
/// paths, raw CAS pins, profile evidence or source rights. New IDs are added to a
/// derived Project only; this function does not publish any of those memberships.
pub fn prepare_native_sources(
    store: &DurableStore,
    owner: &NativeOwnerWitness,
    authority: &LocalAuthority,
    budget: &RequestBudget,
    input: &NativeSourceInput<'_>,
) -> AppResult<PreparedNativeSources> {
    budget.check().map_err(service_error)?;
    owner.check_store(store).map_err(storage_error)?;
    if registered_native_project_owner(store, input.project).map_err(storage_error)?
        != *owner.principal()
    {
        return Err(denied());
    }
    let access = NativeSourceAccess {
        owner: owner.clone(),
        budget: budget.clone(),
        authority: authority.clone(),
        project: input.project.clone(),
        revision: input.expected_revision.clone(),
        policy_revision: authority.policy_revision(owner.principal(), input.project)?,
        read_scope: authority.project_scope(owner.principal(), input.project)?,
        callback_failure: Rc::new(RefCell::new(None)),
    };
    access.check_store(store)?;
    check_input_budget(input)?;
    let mut reader = resource_reader(&access, MAX_RETAINED_TOTAL)?;
    let base_project = reader
        .read_project(
            store,
            &access,
            input.project,
            input.expected_revision,
            MAX_DOCUMENT as u64,
        )
        .map_err(|error| access.release(error))?;
    let catalog = ProjectCatalog::from_project(&base_project)?;
    let policy_id: ResourceId = decode(&base_project["policyResourceId"])?;
    let policy_query = ProjectResourceQuery::Current {
        resource_id: policy_id,
    };
    let policy_request = ProjectResourceRequest {
        project: input.project,
        current_project_revision: input.expected_revision,
        query: &policy_query,
        expected: None,
    };
    let policy_metadata = reader
        .metadata(store, &access, &policy_request)
        .map_err(|error| access.release(error))?;
    if policy_metadata.resource["mediaType"] != mmmm_runtime::storage::bootstrap::POLICY_MEDIA_TYPE
    {
        return Err(invalid());
    }
    let policy_request = ProjectResourceRequest {
        expected: Some(&policy_metadata.resource),
        ..policy_request
    };
    let policy_bytes = reader
        .read(store, &access, &policy_request, MAX_DOCUMENT as u64)
        .map_err(|error| access.release(error))?
        .bytes;
    let policy = parse_checked(&access, &policy_bytes, MAX_DOCUMENT)?;
    validate("Policy", &policy)?;
    access.check_store(store)?;

    let mut documents = Vec::new();
    let mut identities = catalog
        .pins()
        .iter()
        .map(|pin| (pin.kind, pin.object_id.clone()))
        .collect::<BTreeSet<_>>();
    let mut resources = BTreeMap::new();
    for raw in input.retained_resources {
        let value = parse_checked(&access, raw, MAX_RESOURCE_METADATA)?;
        insert_resource(&mut resources, value)?;
    }
    let mut raw_resources = BTreeMap::new();
    for raw in input.raw_resources {
        access.check_store(store)?;
        let value = parse_checked(&access, raw.metadata, MAX_RESOURCE_METADATA)?;
        let (id, digest) = check_raw_resource(&value, raw.bytes)?;
        if catalog.resource_ids().contains(&id)
            || resources.contains_key(&id)
            || raw_resources.contains_key(&id)
        {
            return Err(conflict());
        }
        insert_resource(&mut resources, value.clone())?;
        access.check_local()?;
        raw_resources.insert(
            id,
            PreparedRawResource {
                resource: value,
                metadata_bytes: raw.metadata.to_vec(),
                metadata_digest: raw_digest(raw.metadata),
                bytes: raw.bytes.to_vec(),
                digest,
            },
        );
        access.check_local()?;
    }
    for raw in input.documents {
        access.check_store(store)?;
        let value = parse_checked(&access, raw.bytes, MAX_DOCUMENT)?;
        let kind = raw.kind.stored();
        validate(kind.definition(), &value)?;
        let pin = OwnedDocumentPin {
            kind,
            object_id: decode(&value[kind.identity_field()])?,
            revision: verify_projected_digest(kind.definition(), &value).map_err(digest_error)?,
        };
        let identity_kind = match raw.kind {
            NativeSourceKind::Prefab => OwnedKind::Prefab,
            NativeSourceKind::Instance => OwnedKind::Instance,
            NativeSourceKind::Clip => OwnedKind::Clip,
            NativeSourceKind::CommandModule => OwnedKind::CommandModule,
        };
        if !identities.insert((identity_kind, pin.object_id.clone())) {
            return Err(AppError::new(
                "ID_COLLISION",
                "Native source admission requires unused owned object IDs",
            ));
        }
        if raw.kind == NativeSourceKind::Prefab {
            let prefab: Prefab = decode_domain(&value)?;
            if semantic_diagnostics(&prefab)
                .iter()
                .any(|diagnostic| diagnostic.severity == "error")
            {
                return Err(AppError::new(
                    "INVALID_INPUT",
                    "Native source Prefab has invalid authoring semantics",
                ));
            }
            for reference in array(&value, "resources")? {
                insert_resource(&mut resources, reference.clone())?;
            }
            for node in array(&value, "nodes")? {
                if let Some(reference) = node.get("geometryResource") {
                    insert_resource(&mut resources, reference.clone())?;
                }
            }
        } else if raw.kind == NativeSourceKind::Instance && value["lifecycle"] != "planned" {
            return Err(AppError::new(
                "INVALID_INPUT",
                "Native source admission requires a planned authored Instance",
            ));
        } else if raw.kind == NativeSourceKind::Clip {
            let clip: AnimationClip = decode_domain(&value)?;
            validate_clip(&clip).map_err(domain_error)?;
        }
        access.check_local()?;
        let original_digest = raw_digest(raw.bytes);
        access.check_local()?;
        documents.push(PreparedDocument {
            pin,
            value,
            original_bytes: raw.bytes.to_vec(),
            original_digest,
        });
    }
    let mut retained_total = policy_bytes.len() as u64;
    let mut owner_prefabs = BTreeMap::new();
    for document in &documents {
        let owner_id = match document.pin.kind {
            OwnedDocumentKind::AnimationClip => {
                decode_domain::<AnimationClip>(&document.value)?.owner_prefab_id
            }
            OwnedDocumentKind::CommandModule => {
                decode_domain::<CommandModule>(&document.value)?.owner_prefab_id
            }
            _ => continue,
        };
        access.check_store(store)?;
        if let std::collections::btree_map::Entry::Vacant(entry) =
            owner_prefabs.entry(owner_id.clone())
        {
            let value = authoring_source(
                store,
                &access,
                &catalog,
                &documents,
                OwnedKind::Prefab,
                owner_id.as_str(),
                &mut retained_total,
            )?;
            let prefab: Prefab = decode_domain(&value)?;
            // Recheck the actual owner's declared resources through the same
            // current ACL/CAS reader used for other admitted source documents.
            mmmm_domain::prefab::require_valid(&prefab).map_err(domain_error)?;
            for reference in array(&value, "resources")? {
                insert_resource(&mut resources, reference.clone())?;
            }
            for node in array(&value, "nodes")? {
                if let Some(reference) = node.get("geometryResource") {
                    insert_resource(&mut resources, reference.clone())?;
                }
            }
            entry.insert(prefab);
        }
        if document.pin.kind == OwnedDocumentKind::AnimationClip {
            let clip: AnimationClip = decode_domain(&document.value)?;
            validate_clip_owner(&clip, &owner_prefabs[&owner_id])?;
        } else {
            let module: CommandModule = decode_domain(&document.value)?;
            validate_command_module_owner(&module, &owner_prefabs[&owner_id])?;
        }
    }
    for resource in raw_resources.values() {
        retained_total = add_retained(retained_total, resource.bytes.len() as u64)?;
    }
    let mut retained_resources = Vec::new();
    for (id, expected) in resources {
        access.check_store(store)?;
        if raw_resources.contains_key(&id) {
            continue;
        }
        let expected_length = expected["sizeBytes"].as_f64().ok_or_else(invalid)?;
        if expected_length > MAX_RETAINED_TOTAL.saturating_sub(retained_total) as f64 {
            return Err(budget_error());
        }
        let query = if catalog.resource_ids().contains(&id) {
            ProjectResourceQuery::Exact {
                resource_id: id,
                digest: decode(&expected["sha256"])?,
            }
        } else {
            ProjectResourceQuery::RegisteredImmutable { resource_id: id }
        };
        let request = ProjectResourceRequest {
            project: input.project,
            current_project_revision: input.expected_revision,
            query: &query,
            expected: Some(&expected),
        };
        let actual = reader
            .metadata(store, &access, &request)
            .map_err(|error| access.release(error))?;
        retained_total = add_retained(retained_total, actual.blob.byte_length)?;
        retained_resources.push(actual);
    }
    // A declared Project ID alone proves no retained bytes. Optional source-map
    // dependencies must have exact metadata admitted through the same reader.
    let mut available_resources = BTreeSet::new();
    for retained in &retained_resources {
        available_resources.insert(decode(&retained.resource["resourceId"])?);
    }
    available_resources.extend(raw_resources.keys().cloned());
    for document in &documents {
        access.check_store(store)?;
        if document.pin.kind == OwnedDocumentKind::Prefab {
            for (field, kind) in [
                ("commandModuleIds", OwnedKind::CommandModule),
                ("clipIds", OwnedKind::Clip),
            ] {
                for id in array(&document.value, field)? {
                    let value = authoring_source(
                        store,
                        &access,
                        &catalog,
                        &documents,
                        kind,
                        id.as_str().ok_or_else(invalid)?,
                        &mut retained_total,
                    )?;
                    if kind == OwnedKind::Clip {
                        let clip: AnimationClip = decode_domain(&value)?;
                        let prefab: Prefab = decode_domain(&document.value)?;
                        validate_clip_owner(&clip, &prefab)?;
                    } else if kind == OwnedKind::CommandModule {
                        let module: CommandModule = decode_domain(&value)?;
                        let prefab: Prefab = decode_domain(&document.value)?;
                        validate_command_module_owner(&module, &prefab)?;
                    }
                }
            }
            if let Some(id) = document.value.get("sourceMapResourceId")
                && !available_resources.contains(&decode::<ResourceId>(id)?)
            {
                return Err(AppError::new(
                    "SOURCE_UNAVAILABLE",
                    "Native source map is not an actual retained Project resource",
                ));
            }
        } else if document.pin.kind == OwnedDocumentKind::Instance {
            let instance: Instance = decode_domain(&document.value)?;
            let prefab_value = match documents.iter().find(|candidate| {
                candidate.pin.kind == OwnedDocumentKind::Prefab
                    && candidate.pin.object_id.as_str() == instance.prefab_id.as_str()
                    && candidate.pin.revision == instance.prefab_revision
            }) {
                Some(candidate) => candidate.value.clone(),
                None => {
                    let current = catalog.authorize_pin(
                        OwnedKind::Prefab,
                        instance.prefab_id.as_str(),
                        &instance.prefab_revision,
                    )?;
                    let pin = OwnedDocumentPin {
                        kind: OwnedDocumentKind::Prefab,
                        object_id: current.object_id,
                        revision: current.revision,
                    };
                    let loaded = read_owned(store, &access, &pin)?;
                    retained_total = add_retained(retained_total, loaded.bytes.len() as u64)?;
                    loaded.document
                }
            };
            let prefab: Prefab = decode_domain(&prefab_value)?;
            require_source(&instance, &prefab).map_err(domain_error)?;
            mmmm_domain::instance::ensure_placement(
                &prefab,
                &instance.placement,
                &instance.overrides,
            )
            .map_err(domain_error)?;
        } else if document.pin.kind == OwnedDocumentKind::AnimationClip {
            let clip: AnimationClip = decode_domain(&document.value)?;
            validate_clip_owner(
                &clip,
                owner_prefabs.get(&clip.owner_prefab_id).ok_or_else(|| {
                    AppError::new(
                        "SOURCE_UNAVAILABLE",
                        "Native Clip has no checked owner Prefab source",
                    )
                })?,
            )?;
        } else if document.pin.kind == OwnedDocumentKind::CommandModule {
            let module: CommandModule = decode_domain(&document.value)?;
            validate_command_module_owner(
                &module,
                owner_prefabs.get(&module.owner_prefab_id).ok_or_else(|| {
                    AppError::new(
                        "SOURCE_UNAVAILABLE",
                        "Native CommandModule has no checked owner Prefab source",
                    )
                })?,
            )?;
        }
        access.check_local()?;
    }
    let raw_resources = raw_resources.into_values().collect::<Vec<_>>();
    if documents
        .len()
        .checked_add(retained_resources.len())
        .and_then(|n| n.checked_add(raw_resources.len()))
        .is_none_or(|n| n > MAX_ITEMS)
    {
        return Err(budget_error());
    }
    let next_project = derive_project(
        &base_project,
        &documents,
        &retained_resources,
        &raw_resources,
    )?;
    let prepared = PreparedNativeSources {
        access,
        base_project,
        next_project,
        documents,
        retained_resources,
        raw_resources,
        policy_resource: policy_metadata,
        policy,
    };
    prepared.check_current(store)?;
    Ok(prepared)
}

/// Resolve a same-batch immutable document or an actual current Project pin.
/// Existing source bytes always traverse the original owner/current read scope
/// and count against the same finite retained-source budget.
fn authoring_source(
    store: &DurableStore,
    access: &NativeSourceAccess,
    catalog: &ProjectCatalog,
    documents: &[PreparedDocument],
    kind: OwnedKind,
    id: &str,
    retained_total: &mut u64,
) -> AppResult<Value> {
    access.check_store(store)?;
    let stored_kind = match kind {
        OwnedKind::Prefab => OwnedDocumentKind::Prefab,
        OwnedKind::Clip => OwnedDocumentKind::AnimationClip,
        OwnedKind::CommandModule => OwnedDocumentKind::CommandModule,
        _ => {
            return Err(AppError::new(
                "UNOWNED_REQUIRED_CAPABILITY",
                "Native authoring source kind is unsupported",
            ));
        }
    };
    if let Some(document) = documents
        .iter()
        .find(|document| document.pin.kind == stored_kind && document.pin.object_id.as_str() == id)
    {
        access.check_local()?;
        return Ok(document.value.clone());
    }
    let pin = catalog.owned_pin(kind, id).map_err(|cause| {
        AppError::caused_by(
            "SOURCE_UNAVAILABLE",
            "Native source has no current owned document binding",
            cause,
        )
    })?;
    let loaded = read_owned(
        store,
        access,
        &OwnedDocumentPin {
            kind: stored_kind,
            object_id: pin.object_id.clone(),
            revision: pin.revision.clone(),
        },
    )?;
    *retained_total = add_retained(*retained_total, loaded.bytes.len() as u64)?;
    access.check_store(store)?;
    Ok(loaded.document)
}

fn validate_clip_owner(clip: &AnimationClip, prefab: &Prefab) -> AppResult<()> {
    validate_clip(clip).map_err(domain_error)?;
    if clip.owner_prefab_id != prefab.prefab_id || !prefab.clip_ids.contains(&clip.clip_id) {
        return Err(AppError::new(
            "REFERENCE_UNRESOLVED",
            "Native Clip and its actual owner Prefab lack an exact authored clip binding",
        ));
    }
    let nodes = prefab
        .nodes
        .iter()
        .map(|node| node.node_id.as_str())
        .collect::<BTreeSet<_>>();
    for track in &clip.tracks {
        if !nodes.contains(track.node_id.as_str()) {
            return Err(AppError::new(
                "REFERENCE_UNRESOLVED",
                "Native Clip track has no node in its actual owner Prefab",
            ));
        }
    }
    let functions = prefab
        .references
        .iter()
        .filter(|reference| reference.kind == "function")
        .map(|reference| reference.symbol_id.as_str())
        .collect::<BTreeSet<_>>();
    for event in &clip.events {
        if !functions.contains(event.function_symbol_id.as_str()) {
            return Err(AppError::new(
                "REFERENCE_UNRESOLVED",
                "Native Clip event has no function symbol in its actual owner Prefab",
            ));
        }
    }
    // This validates authored references, not loaded functions, actual event
    // completion/return, a bake, pose ownership, display UUIDs or target codec.
    // Preserve all source flags; trusted compiler/runtime producers must still
    // prove their own binding and capability requirements before generation.
    Ok(())
}

fn validate_command_module_owner(module: &CommandModule, prefab: &Prefab) -> AppResult<()> {
    if module.owner_prefab_id != prefab.prefab_id
        || !prefab.command_module_ids.contains(&module.module_id)
    {
        return Err(AppError::new(
            "REFERENCE_UNRESOLVED",
            "Native CommandModule and its actual owner Prefab lack an exact authored binding",
        ));
    }
    if !prefab
        .nodes
        .iter()
        .any(|node| node.node_id == module.local_origin_node_id)
    {
        return Err(AppError::new(
            "REFERENCE_UNRESOLVED",
            "Native CommandModule origin has no node in its actual owner Prefab",
        ));
    }
    // Authored parse status does not prove host parsing or execution authority.
    Ok(())
}

fn check_input_budget(input: &NativeSourceInput<'_>) -> AppResult<()> {
    if input
        .documents
        .len()
        .checked_add(input.retained_resources.len())
        .and_then(|n| n.checked_add(input.raw_resources.len()))
        .is_none_or(|n| n == 0 || n > MAX_ITEMS)
    {
        return Err(budget_error());
    }
    let mut total = 0usize;
    for bytes in input
        .documents
        .iter()
        .map(|document| document.bytes)
        .chain(input.retained_resources.iter().copied())
    {
        total = total.checked_add(bytes.len()).ok_or_else(budget_error)?;
        if bytes.is_empty() || bytes.len() > MAX_DOCUMENT || total > MAX_RAW_TOTAL {
            return Err(budget_error());
        }
    }
    let mut raw_total = 0u64;
    for source in input.raw_resources {
        if source.metadata.is_empty() || source.metadata.len() > MAX_RESOURCE_METADATA {
            return Err(budget_error());
        }
        total = total
            .checked_add(source.metadata.len())
            .ok_or_else(budget_error)?;
        if total > MAX_RAW_TOTAL {
            return Err(budget_error());
        }
        raw_total = add_retained(raw_total, source.bytes.len() as u64)?;
    }
    Ok(())
}
fn check_raw_resource(value: &Value, bytes: &[u8]) -> AppResult<(ResourceId, Sha256Digest)> {
    validate("ResourceRef", value)?;
    let id = decode(&value["resourceId"])?;
    let digest: Sha256Digest = decode(&value["sha256"])?;
    let length = value["sizeBytes"]
        .as_f64()
        .filter(|length| {
            length.is_finite()
                && length.fract() == 0.0
                && *length >= 0.0
                && *length <= MAX_RETAINED_TOTAL as f64
        })
        .ok_or_else(budget_error)?;
    if length != bytes.len() as f64 || raw_digest(bytes) != digest {
        return Err(AppError::new(
            "INPUT_DIGEST_MISMATCH",
            "Native raw source size or digest differs from its exact ResourceRef",
        ));
    }
    Ok((id, digest))
}
fn parse_checked(access: &NativeSourceAccess, bytes: &[u8], maximum: usize) -> AppResult<Value> {
    parse_json_with_control(
        bytes,
        JsonLimits {
            max_bytes: maximum,
            max_depth: 64,
            max_nodes: 100_000,
        },
        || access.check_local(),
    )
    .map_err(|error| match error {
        ControlledJsonError::Control(error) => error,
        ControlledJsonError::Json(error) => AppError::caused_by(
            "INVALID_INPUT",
            "Native source is not bounded strict JSON",
            error,
        ),
    })
}
fn read_owned(
    store: &DurableStore,
    access: &NativeSourceAccess,
    pin: &OwnedDocumentPin,
) -> AppResult<mmmm_runtime::storage::owned_documents::OwnedDocumentBytes> {
    access.check_store(store)?;
    let mut reader = OwnedDocumentReader::new(Box::new(access.clone()), MAX_DOCUMENT as u64)
        .map_err(storage_error)?;
    let loaded = reader
        .read_known_history_bytes(store, access, &access.project, &access.revision, pin)
        .map_err(|error| access.release(error))?;
    access.check_store(store)?;
    Ok(loaded)
}
fn resource_reader(access: &NativeSourceAccess, maximum: u64) -> AppResult<ProjectResourceReader> {
    ProjectResourceReader::new(Box::new(access.clone()), maximum).map_err(storage_error)
}
fn insert_resource(resources: &mut BTreeMap<ResourceId, Value>, value: Value) -> AppResult<()> {
    validate("ResourceRef", &value)?;
    if encode_json(&value).map_err(|_| budget_error())?.len() > MAX_RESOURCE_METADATA {
        return Err(budget_error());
    }
    let id: ResourceId = decode(&value["resourceId"])?;
    if let Some(old) = resources.get(&id) {
        if old != &value {
            return Err(conflict());
        }
    } else {
        if resources.len() >= MAX_ITEMS {
            return Err(budget_error());
        }
        resources.insert(id, value);
    }
    Ok(())
}
fn derive_project(
    base: &Value,
    documents: &[PreparedDocument],
    resources: &[RegisteredProjectResource],
    raw_resources: &[PreparedRawResource],
) -> AppResult<Value> {
    let mut next = base.clone();
    for document in documents {
        let index = match document.pin.kind {
            OwnedDocumentKind::Prefab => Some("prefabIds"),
            OwnedDocumentKind::Instance => Some("instanceIds"),
            OwnedDocumentKind::AnimationClip | OwnedDocumentKind::CommandModule => None,
            _ => return Err(invalid()),
        };
        if let Some(index) = index {
            next[index]
                .as_array_mut()
                .ok_or_else(invalid)?
                .push(json!(document.pin.object_id));
        }
        next["ownedResources"]
            .as_array_mut()
            .ok_or_else(invalid)?
            .push(serde_json::to_value(&document.pin).map_err(|_| invalid())?);
    }
    for resource in resources
        .iter()
        .map(|resource| &resource.resource)
        .chain(raw_resources.iter().map(|resource| &resource.resource))
    {
        let id = &resource["resourceId"];
        let ids = next["resourceIds"].as_array_mut().ok_or_else(invalid)?;
        if !ids.contains(id) {
            ids.push(id.clone());
        }
    }
    for field in ["prefabIds", "instanceIds", "resourceIds", "ownedResources"] {
        if array(&next, field)?.len() > MAX_PROJECT_ITEMS {
            return Err(budget_error());
        }
    }
    next["revision"] = json!(projected_digest("Project", &next).map_err(digest_error)?);
    if encode_json(&next).map_err(|_| budget_error())?.len() > MAX_DOCUMENT {
        return Err(budget_error());
    }
    ProjectCatalog::from_project(&next)?;
    Ok(next)
}
fn decode_domain<T: serde::de::DeserializeOwned>(value: &Value) -> AppResult<T> {
    let mut typed = value.clone();
    normalize_resource_lengths(&mut typed);
    decode(&typed)
}
fn normalize_resource_lengths(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(normalize_resource_lengths),
        Value::Object(fields) => {
            if fields.len() == 4
                && ["resourceId", "sha256", "mediaType", "sizeBytes"]
                    .iter()
                    .all(|key| fields.contains_key(*key))
                && let Some(size) = fields["sizeBytes"].as_f64().filter(|size| {
                    size.is_finite()
                        && size.fract() == 0.0
                        && *size >= 0.0
                        && *size <= 9_007_199_254_740_991.0
                })
            {
                fields.insert("sizeBytes".into(), Value::from(size as u64));
            }
            fields.values_mut().for_each(normalize_resource_lengths);
        }
        _ => {}
    }
}
fn add_retained(total: u64, length: u64) -> AppResult<u64> {
    total
        .checked_add(length)
        .filter(|sum| *sum <= MAX_RETAINED_TOTAL)
        .ok_or_else(budget_error)
}
fn array<'a>(value: &'a Value, key: &str) -> AppResult<&'a [Value]> {
    value[key].as_array().map(Vec::as_slice).ok_or_else(invalid)
}
fn text<'a>(value: &'a Value, key: &str) -> AppResult<&'a str> {
    value[key].as_str().ok_or_else(invalid)
}
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> AppResult<T> {
    serde_json::from_value(value.clone()).map_err(|_| invalid())
}
fn validate(definition: &str, value: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .and_then(|validator| validator.validate(definition, value))
        .map_err(|error| {
            AppError::caused_by(
                "INVALID_INPUT",
                "Native source violates the canonical contract",
                error,
            )
        })
}
fn service_error(error: crate::service::ServiceError) -> AppError {
    AppError::caused_by(error.code, error.message, error)
}
fn storage_error(error: StorageError) -> AppError {
    let code = match &error {
        StorageError::Fenced(_) => "WRITE_SCOPE_FENCED",
        StorageError::Conflict(_) => "REVISION_CONFLICT",
        StorageError::Corrupt(_) => "INVALID_STORED_EVIDENCE",
        _ => "SOURCE_UNAVAILABLE",
    };
    AppError::caused_by(
        code,
        "Native source admission could not verify retained ownership and bytes",
        error,
    )
}
fn digest_error(error: mmmm_contracts::DigestError) -> AppError {
    AppError::caused_by(
        "INPUT_DIGEST_MISMATCH",
        "Native source canonical self-digest is invalid",
        error,
    )
}
fn domain_error(error: mmmm_domain::DomainError) -> AppError {
    AppError::caused_by(
        error.code,
        "Native source has invalid authored semantics",
        error,
    )
}
fn denied() -> AppError {
    AppError::new(
        "PERMISSION_REQUIRED",
        "Current native owner policy and read scope do not cover the source",
    )
}
fn invalid() -> AppError {
    AppError::new(
        "INVALID_INPUT",
        "Native source identity or canonical document is invalid",
    )
}
fn conflict() -> AppError {
    AppError::new(
        "REVISION_CONFLICT",
        "Native source admission differs from its exact retained Project or resource pin",
    )
}
fn budget_error() -> AppError {
    AppError::new(
        "BUDGET_EXCEEDED",
        "Native source admission exceeds its finite document, item or byte budget",
    )
}

#[cfg(test)]
#[path = "native_source_ingress_tests.rs"]
mod tests;

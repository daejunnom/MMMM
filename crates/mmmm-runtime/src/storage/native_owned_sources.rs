//! Native owner가 준비한 authoring 입력을 한 보호 Store에 원자적으로 반영한다.
//! CAS 원문은 먼저 보존하지만 SQLite association/head/history는 한 transaction이다.
//! 실패 시 미참조 CAS 파일은 남을 수 있으며 metadata rollback과 구분한다.
//! Game/Profile/SourceAdmission/Apply 권한, 별도 원장이나 plan 알고리즘을 만들지 않는다.

use super::{
    BlobRef, DurableStore, StorageError, StorageResult, WriteScope,
    artifact::{ArtifactError, ResourceOwner, register_resource_blob_in},
    bootstrap::{BOOTSTRAP_SCHEMA, registered_native_project_owner},
    journal::register_blob,
    owned_documents::{
        MAX_OWNED_DOCUMENT_BYTES, MAX_OWNED_DOCUMENTS_PER_PROJECT, OwnedDocumentKind,
        OwnedDocumentPin, OwnedDocumentReader, register_owned_document_blob_in, validate_document,
    },
    project_resources::{
        ProjectResourceQuery, ProjectResourceReader, ProjectResourceRequest,
        ProjectSourceRpcContext, RegisteredProjectResource, pin_resource_version,
    },
};
use mmmm_contracts::{
    ContextId, JsonLimits, ObjectId, PrincipalId, ProjectId, ResourceId, Sha256Digest, encode_json,
    projected_digest, raw_digest,
    strict_json::{ControlledJsonError, parse_json_with_control},
    validation::{ControlledContractError, ExactSelector},
    verify_projected_digest,
};
use mmmm_domain::physics::{PhysicsDefinition, normalize_mesh_resource_ref};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const MAX_NEW_ITEMS: usize = 256;
const MAX_METADATA: usize = 16_384;
const MAX_RAW_DOCUMENT_TOTAL: usize = 32 * 1024 * 1024;
const MAX_SOURCE_TOTAL: u64 = 256 * 1024 * 1024;
const MAX_RAW_RESOURCE: u64 = 128 * 1024 * 1024;
const MAX_RESOURCE_VERSIONS: i64 = 65_536;

/// Pin은 locator/precondition이다. 같은 원문을 strict parse하고 projected
/// revision과 identity를 확인한 뒤 그 원문 자체의 별도 raw CAS pin을 만든다.
pub struct NativeOwnedDocumentSource<'a> {
    pub pin: &'a OwnedDocumentPin,
    pub bytes: &'a [u8],
}
pub enum NativeOwnedResourceSource<'a> {
    /// 실제 ProjectResourceReader의 현재 ACL/provenance/CAS 경로로 다시 읽는다.
    Retained { resource: &'a Value },
    /// 기존 ingress에는 아직 없는 typed port. 정본 ResourceRef 원문과 실제
    /// raw content를 함께 받아 digest/length를 확인하며 임의 URI는 열지 않는다.
    Raw { metadata: &'a [u8], bytes: &'a [u8] },
}
pub struct NativeOwnedSourceCommitRequest<'a> {
    pub project: &'a ProjectId,
    pub expected_revision: &'a Sha256Digest,
    /// 원래 source preparation이 만든 Project의 bytes. 기존 필드 변경 없이
    /// 문서/resource membership 추가와 정확한 projected revision만 허용한다.
    pub project_bytes: &'a [u8],
    pub documents: &'a [NativeOwnedDocumentSource<'a>],
    pub resources: &'a [NativeOwnedResourceSource<'a>],
}

pub struct NativeOwnedSourceCommitView<'a> {
    pub request: &'a NativeOwnedSourceCommitRequest<'a>,
    pub base_project: &'a Value,
    pub next_project: &'a Value,
}

/// Coordinator의 실제 NativeOwnerWitness/current request·policy·source grant
/// adapter가 구현한다. Bool/JSON owner/permission이나 기본 허용 구현은 없다.
/// check_store/authorize_commit은 같은 원래 deadline·취소·owner·fence를 확인하고
/// transaction 안에서는 local/SQLite 검사만 한다. reader는 같은 live 권리로
/// 기존 checked source reader를 구성한다. 새 입력의 domain/Clip semantics와
/// 개별 쓰기 권한은 이 실제 producer가 별도로 검증해야 한다.
pub trait NativeOwnedSourceCommitPermit: ProjectSourceRpcContext {
    fn check_store(&self, store: &DurableStore) -> StorageResult<()>;
    fn authorize_commit(
        &self,
        store: &DurableStore,
        view: &NativeOwnedSourceCommitView<'_>,
    ) -> StorageResult<PrincipalId>;
    fn resource_reader(&self, ceiling: u64) -> StorageResult<ProjectResourceReader>;
    fn owned_document_reader(&self, ceiling: u64) -> StorageResult<OwnedDocumentReader>;
}

/// SQLite commit의 실제 결과만 설명한다. 재사용 가능한 승인 token이 아니며
/// public release는 caller가 원래 request/권리를 별도로 확인해야 한다.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeOwnedSourceCommitReceipt {
    pub project_id: ProjectId,
    pub base_revision: Sha256Digest,
    pub project_revision: Sha256Digest,
    pub project_blob: BlobRef,
    pub documents: Vec<(OwnedDocumentPin, BlobRef)>,
    pub resources: Vec<(ResourceId, BlobRef)>,
}

struct PermitRpc<'a>(&'a dyn NativeOwnedSourceCommitPermit);
impl ProjectSourceRpcContext for PermitRpc<'_> {
    fn check(&self) -> StorageResult<()> {
        self.0.check()
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.0.authenticated_principal()
    }
    fn context_id(&self) -> Option<&ContextId> {
        self.0.context_id()
    }
}
struct StagedDocument {
    pin: OwnedDocumentPin,
    blob: BlobRef,
}
/// A document being prepared is not yet a publication record. Physics bytes
/// remain pending until all current resource and reference checks complete;
/// only an actual verified CAS write can produce its final StagedDocument.
struct PendingDocument<'a> {
    pin: OwnedDocumentPin,
    value: Value,
    bytes: &'a [u8],
    staged_blob: Option<BlobRef>,
}
struct StagedResource {
    id: ResourceId,
    resource: Value,
    blob: BlobRef,
    previous: Option<RegisteredProjectResource>,
}
/// A resource candidate is either an authorized existing registration or raw
/// input whose metadata and bytes were checked but which is not yet in CAS.
/// The latter's expected pin is only a comparison target, never provenance.
struct PendingResource<'a> {
    id: ResourceId,
    resource: Value,
    source: PendingResourceSource<'a>,
}
enum PendingResourceSource<'a> {
    Existing(RegisteredProjectResource),
    Raw {
        metadata: &'a [u8],
        original_metadata: Value,
        bytes: &'a [u8],
        expected: BlobRef,
    },
}
struct CheckedPhysics {
    physics_id: String,
    body_ids: BTreeSet<String>,
}
struct PreparedSources {
    base_project: Value,
    base_blob: BlobRef,
    next_project: Value,
    next_revision: Sha256Digest,
    project_blob: BlobRef,
    documents: Vec<StagedDocument>,
    carried_documents: Vec<(OwnedDocumentPin, BlobRef)>,
    resources: BTreeMap<ResourceId, StagedResource>,
    new_resource_ids: Vec<ResourceId>,
    scope: WriteScope,
}

/// One mutable Store borrow + its protected root lock + one Immediate transaction.
/// Nested transaction, provider dispatch, workspace/host grant 발급은 없다.
pub fn commit_native_owned_sources(
    store: &mut DurableStore,
    permit: &dyn NativeOwnedSourceCommitPermit,
    request: &NativeOwnedSourceCommitRequest<'_>,
) -> StorageResult<NativeOwnedSourceCommitReceipt> {
    let scope = request_scope(request)?;
    let owner = checkpoint(store, permit, request.project, &scope)?;
    let staged = prepare(store, permit, request, scope)?;
    let view = NativeOwnedSourceCommitView {
        request,
        base_project: &staged.base_project,
        next_project: &staged.next_project,
    };
    if permit.authorize_commit(store, &view)? != owner {
        return Err(conflict("Native source commit owner changed"));
    }
    checkpoint(store, permit, request.project, &staged.scope)?;
    let transaction =
        Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate)?;
    transaction.execute_batch(BOOTSTRAP_SCHEMA)?;
    guard_head(
        store,
        request.project,
        request.expected_revision,
        Some(&staged.base_blob),
    )?;
    if checkpoint(store, permit, request.project, &staged.scope)? != owner
        || permit.authorize_commit(store, &view)? != owner
    {
        return Err(conflict("Native source commit authority changed"));
    }
    // All unchanged ownership/provenance is re-read before publication. A new
    // revision cannot repair an absent old revision association by declaration.
    recheck_sources(store, permit, request, &staged)?;
    insert_project(
        &transaction,
        request.project,
        &staged.next_revision,
        &staged.project_blob,
    )?;
    let mut check = || {
        if checkpoint(store, permit, request.project, &staged.scope)? != owner {
            return Err(conflict(
                "Native source original owner changed during transaction",
            ));
        }
        Ok(())
    };
    for document in &staged.documents {
        register_owned_document_blob_in(
            store,
            &transaction,
            request.project,
            &staged.next_revision,
            &document.pin,
            &document.blob,
            &mut check,
        )?;
    }
    for (pin, _) in &staged.carried_documents {
        check()?;
        carry_owned_provenance(
            &transaction,
            request.project,
            request.expected_revision,
            &staged.next_revision,
            pin,
        )?;
    }
    for resource in staged.resources.values() {
        check()?;
        if resource.previous.is_none() {
            require_new_resource_id(store, &resource.id)?;
        }
        // ArtifactError's public mapping intentionally removes transport/storage
        // details. Preserve this call's original cancellation/deadline/fence
        // error before crossing that mapping, rather than calling it bad input.
        let mut callback_failure = None;
        let registered = register_resource_blob_in(
            store,
            &transaction,
            &resource.resource,
            &ResourceOwner::Project(request.project.clone()),
            &resource.blob,
            &mut || match check() {
                Ok(()) => Ok(()),
                Err(cause) => {
                    callback_failure = Some(cause);
                    Err(conflict("Native artifact callback stopped"))
                }
            },
        );
        if let Err(cause) = registered {
            return Err(callback_failure.unwrap_or_else(|| artifact_error(cause)));
        }
        associate_resource(
            &transaction,
            request.project,
            &staged.next_revision,
            resource,
            &mut check,
        )?;
    }
    // Final authority callbacks still see the original actual head. Switching
    // that head is the final metadata action after every source association.
    if permit.authorize_commit(store, &view)? != owner {
        return Err(conflict("Native source permission changed before commit"));
    }
    check()?;
    guard_head(
        store,
        request.project,
        request.expected_revision,
        Some(&staged.base_blob),
    )?;
    if transaction.execute("UPDATE project_heads SET revision=?2,blob_digest=?3 WHERE project_id=?1 AND revision=?4 AND blob_digest=?5",
        params![request.project.as_str(),staged.next_revision.as_str(),staged.project_blob.digest.as_str(),request.expected_revision.as_str(),staged.base_blob.digest.as_str()])? != 1 {
        return Err(conflict("Native source Project head changed during commit"));
    }
    check()?;
    guard_head(
        store,
        request.project,
        &staged.next_revision,
        Some(&staged.project_blob),
    )?;
    transaction.commit()?;
    // A cancellation after a completed commit is not rollback. This factual
    // receipt survives as Project history; caller controls authorization/release.
    Ok(NativeOwnedSourceCommitReceipt {
        project_id: request.project.clone(),
        base_revision: request.expected_revision.clone(),
        project_revision: staged.next_revision,
        project_blob: staged.project_blob,
        documents: staged
            .documents
            .into_iter()
            .map(|document| (document.pin, document.blob))
            .collect(),
        resources: staged
            .new_resource_ids
            .iter()
            .map(|id| (id.clone(), staged.resources[id].blob.clone()))
            .collect(),
    })
}

fn checkpoint(
    store: &DurableStore,
    permit: &dyn NativeOwnedSourceCommitPermit,
    project: &ProjectId,
    scope: &WriteScope,
) -> StorageResult<PrincipalId> {
    permit.check_store(store)?;
    permit.check()?;
    let principal = permit.authenticated_principal()?;
    if registered_native_project_owner(store, project)? != principal {
        return Err(conflict("Current native Project owner differs"));
    }
    // The Project membership/head itself changes. Any unresolved write for the
    // same Project fences this edit; no caller-supplied exception is accepted.
    store.check_write_scope(scope, true, None)?;
    permit.check()?;
    Ok(principal)
}

fn request_scope(request: &NativeOwnedSourceCommitRequest<'_>) -> StorageResult<WriteScope> {
    if request
        .documents
        .len()
        .checked_add(request.resources.len())
        .is_none_or(|count| count == 0 || count > MAX_NEW_ITEMS)
        || request.project_bytes.is_empty()
        || request.project_bytes.len() as u64 > MAX_OWNED_DOCUMENT_BYTES
    {
        return Err(invalid("Native source batch/document budget"));
    }
    let mut object_ids = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut total = request.project_bytes.len();
    for document in request.documents {
        if !matches!(
            document.pin.kind,
            OwnedDocumentKind::Prefab
                | OwnedDocumentKind::Instance
                | OwnedDocumentKind::AnimationClip
                | OwnedDocumentKind::CommandModule
                | OwnedDocumentKind::PhysicsDefinition
        ) || document.bytes.is_empty()
            || document.bytes.len() as u64 > MAX_OWNED_DOCUMENT_BYTES
            || !identities.insert((document.pin.kind, document.pin.object_id.clone()))
        {
            return Err(invalid("Native owned source kind, identity or byte budget"));
        }
        object_ids.insert(document.pin.object_id.clone());
        total = total
            .checked_add(document.bytes.len())
            .ok_or_else(|| invalid("Native raw document total overflow"))?;
    }
    if total > MAX_RAW_DOCUMENT_TOTAL {
        return Err(invalid("Native raw document batch budget"));
    }
    let mut raw_resource_total = 0u64;
    for resource in request.resources {
        if let NativeOwnedResourceSource::Raw { metadata, bytes } = resource {
            if metadata.is_empty()
                || metadata.len() > MAX_METADATA
                || bytes.len() as u64 > MAX_RAW_RESOURCE
            {
                return Err(invalid("Native raw resource input budget"));
            }
            raw_resource_total = raw_resource_total
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| invalid("Native raw resource input total overflow"))?;
            if raw_resource_total > MAX_SOURCE_TOTAL {
                return Err(invalid("Native raw resource input total budget"));
            }
        }
    }
    let scope = WriteScope {
        project_id: request.project.clone(),
        resource_ids: Vec::new(),
        object_ids: object_ids.into_iter().collect(),
        regions: Vec::new(),
        external_target_ids: Vec::new(),
    };
    scope.validate()?;
    Ok(scope)
}

fn prepare(
    store: &DurableStore,
    permit: &dyn NativeOwnedSourceCommitPermit,
    request: &NativeOwnedSourceCommitRequest<'_>,
    scope: WriteScope,
) -> StorageResult<PreparedSources> {
    let rpc = PermitRpc(permit);
    let base_blob = guard_head(store, request.project, request.expected_revision, None)?;
    let mut reader = permit.resource_reader(MAX_SOURCE_TOTAL)?;
    let base_project = reader.read_project(
        store,
        &rpc,
        request.project,
        request.expected_revision,
        MAX_OWNED_DOCUMENT_BYTES,
    )?;
    let next_project = parse(
        store,
        permit,
        request.project_bytes,
        MAX_OWNED_DOCUMENT_BYTES as usize,
    )?;
    store
        .validator
        .validate("Project", &next_project)
        .map_err(contract)?;
    let next_revision = verify_projected_digest("Project", &next_project).map_err(contract)?;
    if next_project["projectId"] != request.project.as_str()
        || next_revision == *request.expected_revision
    {
        return Err(invalid(
            "Native source Project identity or unchanged revision",
        ));
    }
    // Authorize the exact producer-owned request before even prestaging CAS.
    // Runtime validation below remains mandatory; this callback is not inferred
    // from the Project/body/owner identifiers supplied by a caller.
    let initial_view = NativeOwnedSourceCommitView {
        request,
        base_project: &base_project,
        next_project: &next_project,
    };
    let current_owner = checkpoint(store, permit, request.project, &scope)?;
    if permit.authorize_commit(store, &initial_view)? != current_owner {
        return Err(conflict("Native source write permission is not current"));
    }
    let base_pins = owned_pins(&base_project)?;
    let base_resources = resource_ids(&base_project)?;
    let mut documents = Vec::new();
    let mut physics_documents = BTreeMap::new();
    let mut after_pins = base_pins.clone();
    let mut expected = base_project.clone();
    let mut remaining = MAX_SOURCE_TOTAL;
    account(&mut remaining, request.project_bytes.len() as u64)?;
    for document in request.documents {
        checkpoint(store, permit, request.project, &scope)?;
        if after_pins.contains_key(&(document.pin.kind, document.pin.object_id.clone())) {
            return Err(conflict(
                "Native source import requires a new owned identity",
            ));
        }
        let value = parse(
            store,
            permit,
            document.bytes,
            MAX_OWNED_DOCUMENT_BYTES as usize,
        )?;
        validate_document(store, document.pin, &value, false)?;
        if document.pin.kind == OwnedDocumentKind::PhysicsDefinition {
            let definition = checked_physics(store, permit, request.project, &scope, &value)?;
            physics_documents.insert(document.pin.object_id.clone(), definition);
        }
        if document.pin.kind == OwnedDocumentKind::Instance && value["lifecycle"] != "planned" {
            return Err(invalid(
                "Native source Instance must remain an authored planned definition",
            ));
        }
        account(&mut remaining, document.bytes.len() as u64)?;
        // Preserve ordinary document staging order. Physics remains pending
        // until the current resources, retained sources and their authored
        // relationships are checked; a predicted hash is not a CAS receipt.
        let staged_blob = if document.pin.kind == OwnedDocumentKind::PhysicsDefinition {
            None
        } else {
            Some(stage_bytes(store, permit, document.bytes)?)
        };
        after_pins.insert(
            (document.pin.kind, document.pin.object_id.clone()),
            document.pin.clone(),
        );
        match document.pin.kind {
            OwnedDocumentKind::Prefab => {
                append(&mut expected, "prefabIds", json!(document.pin.object_id))?
            }
            OwnedDocumentKind::Instance => {
                append(&mut expected, "instanceIds", json!(document.pin.object_id))?
            }
            OwnedDocumentKind::AnimationClip
            | OwnedDocumentKind::CommandModule
            | OwnedDocumentKind::PhysicsDefinition => (),
            _ => return Err(invalid("Native source authoring kind")),
        }
        append(
            &mut expected,
            "ownedResources",
            serde_json::to_value(document.pin).map_err(contract)?,
        )?;
        documents.push(PendingDocument {
            pin: document.pin.clone(),
            value,
            bytes: document.bytes,
            staged_blob,
        });
    }
    let mut resources = BTreeMap::new();
    for id in &base_resources {
        let query = ProjectResourceQuery::Current {
            resource_id: id.clone(),
        };
        let source = reader.metadata(
            store,
            &rpc,
            &ProjectResourceRequest {
                project: request.project,
                current_project_revision: request.expected_revision,
                query: &query,
                expected: None,
            },
        )?;
        require_project_resource(request.project, &source)?;
        account(&mut remaining, source.blob.byte_length)?;
        resources.insert(
            id.clone(),
            PendingResource {
                id: id.clone(),
                resource: source.resource.clone(),
                source: PendingResourceSource::Existing(source),
            },
        );
    }
    let mut new_resource_ids = Vec::new();
    let mut input_resources = BTreeSet::new();
    let mut existing_raw_metadata = Vec::new();
    for input in request.resources {
        checkpoint(store, permit, request.project, &scope)?;
        let mut original_metadata = None;
        let resource = match input {
            NativeOwnedResourceSource::Retained { resource } => {
                // Validate/bound the original metadata before allocating a copy.
                resource_pin(store, resource)?;
                (*resource).clone()
            }
            NativeOwnedResourceSource::Raw { metadata, .. } => {
                let original = parse(store, permit, metadata, MAX_METADATA)?;
                let comparable = raw_resource_comparison_copy(store, &original)?;
                original_metadata = Some(original);
                comparable
            }
        };
        let (id, blob) = resource_pin(store, &resource)?;
        if !input_resources.insert(id.clone()) {
            return Err(invalid("Native source repeats an input resource ID"));
        }
        if let Some(existing) = resources.get(&id) {
            let actual = match &existing.source {
                PendingResourceSource::Existing(actual) => actual,
                PendingResourceSource::Raw { .. } => {
                    return Err(invalid("Native source repeats an input resource ID"));
                }
            };
            if existing.resource != resource || actual.blob != blob {
                return Err(conflict("Native source would replace a current resource"));
            }
            if let NativeOwnedResourceSource::Raw { bytes, .. } = input
                && (bytes.len() as u64 != blob.byte_length || raw_digest(bytes) != blob.digest)
            {
                return Err(invalid("Native raw resource digest or size differs"));
            }
            if let NativeOwnedResourceSource::Raw { metadata, .. } = input {
                existing_raw_metadata.push((
                    id,
                    *metadata,
                    original_metadata.ok_or_else(|| invalid("Native raw metadata missing"))?,
                ));
            }
            continue;
        }
        account(&mut remaining, blob.byte_length)?;
        let source = match input {
            NativeOwnedResourceSource::Retained { .. } => {
                let query = ProjectResourceQuery::RegisteredImmutable {
                    resource_id: id.clone(),
                };
                let actual = reader.metadata(
                    store,
                    &rpc,
                    &ProjectResourceRequest {
                        project: request.project,
                        current_project_revision: request.expected_revision,
                        query: &query,
                        expected: Some(&resource),
                    },
                )?;
                require_project_resource(request.project, &actual)?;
                PendingResourceSource::Existing(actual)
            }
            NativeOwnedResourceSource::Raw { metadata, bytes } => {
                // Raw bytes are new input, not an alternate read-grant path
                // for an existing hidden/out-of-scope resource registration.
                require_new_resource_id(store, &id)?;
                if blob.byte_length > MAX_RAW_RESOURCE
                    || bytes.len() as u64 != blob.byte_length
                    || raw_digest(bytes) != blob.digest
                {
                    return Err(invalid(
                        "Native raw resource digest, size or ceiling differs",
                    ));
                }
                PendingResourceSource::Raw {
                    metadata,
                    original_metadata: original_metadata
                        .ok_or_else(|| invalid("Native raw metadata missing"))?,
                    bytes,
                    expected: blob,
                }
            }
        };
        append(&mut expected, "resourceIds", json!(id))?;
        new_resource_ids.push(id.clone());
        resources.insert(
            id.clone(),
            PendingResource {
                id,
                resource,
                source,
            },
        );
    }
    expected["revision"] = json!(projected_digest("Project", &expected).map_err(contract)?);
    if expected != next_project
        || owned_pins(&next_project)? != after_pins
        || resource_ids(&next_project)?.len() != resources.len()
    {
        return Err(conflict(
            "Native source Project is not the exact membership-only derivation",
        ));
    }
    // Only retain existing bodies needed for the new Prefab/CommandModule and
    // Prefab/PhysicsDefinition relationships.
    // They are read by the same authorized history reader as all carried sources.
    let mut related = BTreeSet::new();
    for document in &documents {
        checkpoint(store, permit, request.project, &scope)?;
        match document.pin.kind {
            OwnedDocumentKind::CommandModule => {
                related.insert((
                    OwnedDocumentKind::Prefab,
                    decode(&document.value["ownerPrefabId"])?,
                ));
            }
            OwnedDocumentKind::Prefab => {
                for id in array(&document.value, "commandModuleIds")? {
                    related.insert((OwnedDocumentKind::CommandModule, decode(id)?));
                }
                for node in array(&document.value, "nodes")? {
                    if let Some(binding) = node.get("physicsBinding") {
                        related.insert((
                            OwnedDocumentKind::PhysicsDefinition,
                            decode(&binding["physicsId"])?,
                        ));
                    }
                }
            }
            _ => (),
        }
    }
    let mut retained = BTreeMap::new();
    let mut owned_reader = permit.owned_document_reader(MAX_OWNED_DOCUMENT_BYTES)?;
    let mut carried_documents = Vec::new();
    let mut retained_physics_bytes = Vec::new();
    for pin in base_pins.values() {
        checkpoint(store, permit, request.project, &scope)?;
        let loaded = owned_reader.read_known_history_bytes(
            store,
            &rpc,
            request.project,
            request.expected_revision,
            pin,
        )?;
        account(&mut remaining, loaded.blob.byte_length)?;
        if related.contains(&(pin.kind, pin.object_id.clone())) {
            if pin.kind == OwnedDocumentKind::PhysicsDefinition {
                let definition =
                    checked_physics(store, permit, request.project, &scope, &loaded.document)?;
                require_physics_mesh_resources(
                    store,
                    permit,
                    request.project,
                    &scope,
                    &loaded.document,
                    &resources,
                )?;
                retained_physics_bytes.push((pin.object_id.clone(), loaded.bytes));
                physics_documents.insert(pin.object_id.clone(), definition);
            }
            retained.insert((pin.kind, pin.object_id.clone()), loaded.document);
        }
        carried_documents.push((pin.clone(), loaded.blob));
    }
    for document in &documents {
        require_references(&document.value, &after_pins, &resources)?;
        checkpoint(store, permit, request.project, &scope)?;
        match document.pin.kind {
            OwnedDocumentKind::PhysicsDefinition => {
                require_physics_mesh_resources(
                    store,
                    permit,
                    request.project,
                    &scope,
                    &document.value,
                    &resources,
                )?;
            }
            OwnedDocumentKind::CommandModule => {
                let owner = decode(&document.value["ownerPrefabId"])?;
                let prefab =
                    related_document(OwnedDocumentKind::Prefab, &owner, &documents, &retained)?;
                require_command_module_binding(prefab, &document.value)?;
            }
            OwnedDocumentKind::Prefab => {
                for id in array(&document.value, "commandModuleIds")? {
                    checkpoint(store, permit, request.project, &scope)?;
                    let id = decode(id)?;
                    let module = related_document(
                        OwnedDocumentKind::CommandModule,
                        &id,
                        &documents,
                        &retained,
                    )?;
                    require_command_module_binding(&document.value, module)?;
                }
                for node in array(&document.value, "nodes")? {
                    checkpoint(store, permit, request.project, &scope)?;
                    if let Some(binding) = node.get("physicsBinding") {
                        let id: ObjectId = decode(&binding["physicsId"])?;
                        let physics = physics_documents.get(&id).ok_or_else(|| {
                            invalid("Native physics binding has no checked actual definition")
                        })?;
                        require_physics_binding(binding, physics)?;
                    }
                }
            }
            _ => (),
        }
    }
    // Existing resource ACL, current Project membership and document relation
    // failures must remain observable before a newly added exact-decimal error.
    // Earlier ordinary document CAS files may already exist; raw resources and
    // Physics documents remain pending without a storage/provenance claim.
    let needs_exact = !retained_physics_bytes.is_empty()
        || documents
            .iter()
            .any(|document| document.pin.kind == OwnedDocumentKind::PhysicsDefinition)
        || !existing_raw_metadata.is_empty()
        || resources
            .values()
            .any(|resource| matches!(&resource.source, PendingResourceSource::Raw { .. }));
    if needs_exact {
        if checkpoint(store, permit, request.project, &scope)? != current_owner
            || permit.authorize_commit(store, &initial_view)? != current_owner
        {
            return Err(conflict("Native source write permission is not current"));
        }
        guard_head(
            store,
            request.project,
            request.expected_revision,
            Some(&base_blob),
        )?;
    }
    for (id, bytes) in retained_physics_bytes {
        checkpoint(store, permit, request.project, &scope)?;
        let value = retained
            .get(&(OwnedDocumentKind::PhysicsDefinition, id))
            .ok_or_else(|| invalid("Native retained physics source is missing"))?;
        check_exact_input(
            store,
            permit,
            &bytes,
            MAX_OWNED_DOCUMENT_BYTES as usize,
            ExactSelector::PhysicsDefinition,
            value,
        )?;
    }
    for document in &documents {
        if document.pin.kind == OwnedDocumentKind::PhysicsDefinition {
            checkpoint(store, permit, request.project, &scope)?;
            check_exact_input(
                store,
                permit,
                document.bytes,
                MAX_OWNED_DOCUMENT_BYTES as usize,
                ExactSelector::PhysicsDefinition,
                &document.value,
            )?;
        }
    }
    for (id, metadata, original_metadata) in existing_raw_metadata {
        checkpoint(store, permit, request.project, &scope)?;
        let resource = resources
            .get(&id)
            .ok_or_else(|| invalid("Native current resource is missing"))?;
        check_exact_input(
            store,
            permit,
            metadata,
            MAX_METADATA,
            ExactSelector::ResourceRef,
            &original_metadata,
        )?;
        // The original token is now checked; the provisional copy must still
        // match the exact retained registration, including every other field.
        if raw_resource_comparison_copy(store, &original_metadata)? != resource.resource {
            return Err(conflict("Native source would replace a current resource"));
        }
    }
    for resource in resources.values() {
        if let PendingResourceSource::Raw {
            metadata,
            original_metadata,
            ..
        } = &resource.source
        {
            checkpoint(store, permit, request.project, &scope)?;
            check_exact_input(
                store,
                permit,
                metadata,
                MAX_METADATA,
                ExactSelector::ResourceRef,
                original_metadata,
            )?;
            if raw_resource_comparison_copy(store, original_metadata)? != resource.resource {
                return Err(StorageError::RawExactCaptureUnavailable);
            }
        }
    }
    let mut staged_documents = Vec::with_capacity(documents.len());
    for document in documents {
        let blob = match document.staged_blob {
            Some(blob) => blob,
            None => {
                checkpoint(store, permit, request.project, &scope)?;
                let actual = stage_bytes(store, permit, document.bytes)?;
                if actual.byte_length != document.bytes.len() as u64
                    || actual.digest != raw_digest(document.bytes)
                {
                    return Err(conflict("Native Physics actual CAS pin differs"));
                }
                actual
            }
        };
        staged_documents.push(StagedDocument {
            pin: document.pin,
            blob,
        });
    }
    let mut staged_resources = BTreeMap::new();
    for (id, resource) in resources {
        let (blob, previous) = match resource.source {
            PendingResourceSource::Existing(actual) => (actual.blob.clone(), Some(actual)),
            PendingResourceSource::Raw {
                bytes, expected, ..
            } => {
                checkpoint(store, permit, request.project, &scope)?;
                let actual = stage_bytes(store, permit, bytes)?;
                if actual != expected {
                    return Err(conflict("Native raw resource actual CAS pin differs"));
                }
                (actual, None)
            }
        };
        staged_resources.insert(
            id,
            StagedResource {
                id: resource.id,
                resource: resource.resource,
                blob,
                previous,
            },
        );
    }
    let project_blob = stage_bytes(store, permit, request.project_bytes)?;
    checkpoint(store, permit, request.project, &scope)?;
    guard_head(
        store,
        request.project,
        request.expected_revision,
        Some(&base_blob),
    )?;
    Ok(PreparedSources {
        base_project,
        base_blob,
        next_project,
        next_revision,
        project_blob,
        documents: staged_documents,
        carried_documents,
        resources: staged_resources,
        new_resource_ids,
        scope,
    })
}

fn recheck_sources(
    store: &DurableStore,
    permit: &dyn NativeOwnedSourceCommitPermit,
    request: &NativeOwnedSourceCommitRequest<'_>,
    staged: &PreparedSources,
) -> StorageResult<()> {
    let rpc = PermitRpc(permit);
    let mut reader = permit.resource_reader(MAX_SOURCE_TOTAL)?;
    for source in staged.resources.values() {
        checkpoint(store, permit, request.project, &staged.scope)?;
        if let Some(previous) = &source.previous {
            let query = match &previous.provenance {
                super::project_resources::ProjectResourceProvenance::CurrentProject { .. } => {
                    ProjectResourceQuery::Current {
                        resource_id: source.id.clone(),
                    }
                }
                super::project_resources::ProjectResourceProvenance::ImmutableProjectArtifact => {
                    ProjectResourceQuery::RegisteredImmutable {
                        resource_id: source.id.clone(),
                    }
                }
                _ => {
                    return Err(conflict(
                        "Native source input cannot use an untracked historical resource",
                    ));
                }
            };
            let actual = reader.metadata(
                store,
                &rpc,
                &ProjectResourceRequest {
                    project: request.project,
                    current_project_revision: request.expected_revision,
                    query: &query,
                    expected: Some(&source.resource),
                },
            )?;
            if actual.resource != previous.resource
                || actual.blob != previous.blob
                || actual.owner != previous.owner
                || actual.provenance != previous.provenance
            {
                return Err(conflict("Native retained resource provenance changed"));
            }
        } else {
            require_new_resource_id(store, &source.id)?;
            verify_blob(store, permit, &source.blob)?;
        }
    }
    let mut owned_reader = permit.owned_document_reader(MAX_OWNED_DOCUMENT_BYTES)?;
    for (pin, previous_blob) in &staged.carried_documents {
        checkpoint(store, permit, request.project, &staged.scope)?;
        let loaded = owned_reader.read_known_history_bytes(
            store,
            &rpc,
            request.project,
            request.expected_revision,
            pin,
        )?;
        if &loaded.blob != previous_blob {
            return Err(conflict("Native carried document provenance changed"));
        }
    }
    for document in &staged.documents {
        verify_blob(store, permit, &document.blob)?;
    }
    verify_blob(store, permit, &staged.project_blob)
}

fn related_document<'a>(
    kind: OwnedDocumentKind,
    id: &ObjectId,
    documents: &'a [PendingDocument<'_>],
    retained: &'a BTreeMap<(OwnedDocumentKind, ObjectId), Value>,
) -> StorageResult<&'a Value> {
    documents
        .iter()
        .find(|document| document.pin.kind == kind && &document.pin.object_id == id)
        .map(|document| &document.value)
        .or_else(|| retained.get(&(kind, id.clone())))
        .ok_or_else(|| invalid("Native source has no actual related document"))
}

fn require_command_module_binding(prefab: &Value, module: &Value) -> StorageResult<()> {
    let prefab_id = prefab
        .get("prefabId")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Native CommandModule owner identity missing"))?;
    let module_id = module
        .get("moduleId")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Native CommandModule identity missing"))?;
    let origin = module
        .get("localOriginNodeId")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Native CommandModule origin missing"))?;
    if module.get("ownerPrefabId").and_then(Value::as_str) != Some(prefab_id)
        || !array(prefab, "commandModuleIds")?
            .iter()
            .any(|id| id.as_str() == Some(module_id))
        || !array(prefab, "nodes")?
            .iter()
            .any(|node| node.get("nodeId").and_then(Value::as_str) == Some(origin))
    {
        return Err(invalid(
            "Native CommandModule owner, membership or origin differs",
        ));
    }
    Ok(())
}

fn checked_physics(
    store: &DurableStore,
    permit: &dyn NativeOwnedSourceCommitPermit,
    project: &ProjectId,
    scope: &WriteScope,
    value: &Value,
) -> StorageResult<CheckedPhysics> {
    checkpoint(store, permit, project, scope)?;
    let physics = PhysicsDefinition::from_value(value).map_err(contract)?;
    checkpoint(store, permit, project, scope)?;
    let mut body_ids = BTreeSet::new();
    for (index, body) in physics.bodies().iter().enumerate() {
        if index.is_multiple_of(128) {
            checkpoint(store, permit, project, scope)?;
        }
        body_ids.insert(body.body_id.as_str().to_owned());
    }
    checkpoint(store, permit, project, scope)?;
    Ok(CheckedPhysics {
        physics_id: physics.physics_id().as_str().to_owned(),
        body_ids,
    })
}

fn require_physics_binding(binding: &Value, physics: &CheckedPhysics) -> StorageResult<()> {
    let physics_id = binding
        .get("physicsId")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Native physics binding identity missing"))?;
    let body_id = binding
        .get("bodyId")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Native physics binding body identity missing"))?;
    if physics.physics_id != physics_id || !physics.body_ids.contains(body_id) {
        return Err(invalid("Native physics binding definition or body differs"));
    }
    Ok(())
}

fn require_exact_resource(
    value: &Value,
    resources: &BTreeMap<ResourceId, PendingResource<'_>>,
) -> StorageResult<()> {
    let id: ResourceId = decode(&value["resourceId"])?;
    if resources
        .get(&id)
        .is_none_or(|resource| resource.resource != *value)
    {
        return Err(invalid(
            "Owned source ResourceRef has no exact actual CAS association",
        ));
    }
    Ok(())
}

fn require_physics_mesh_resources(
    store: &DurableStore,
    permit: &dyn NativeOwnedSourceCommitPermit,
    project: &ProjectId,
    scope: &WriteScope,
    physics: &Value,
    resources: &BTreeMap<ResourceId, PendingResource<'_>>,
) -> StorageResult<()> {
    // Normalize only a comparison copy of the mesh ResourceRef. The authored
    // Physics bytes and projected pin are unchanged. This storage association
    // does not attest mesh topology or a solver.
    for collider in array(physics, "colliders")? {
        checkpoint(store, permit, project, scope)?;
        let shape = &collider["shape"]["shape"];
        if shape.get("kind").and_then(Value::as_str) == Some("mesh") {
            let geometry = shape
                .get("geometry")
                .ok_or_else(|| invalid("Native mesh geometry reference missing"))?;
            let comparable = normalize_mesh_resource_ref(geometry).map_err(contract)?;
            require_exact_resource(&comparable, resources)?;
        }
    }
    Ok(())
}

fn require_references(
    document: &Value,
    pins: &BTreeMap<(OwnedDocumentKind, ObjectId), OwnedDocumentPin>,
    resources: &BTreeMap<ResourceId, PendingResource<'_>>,
) -> StorageResult<()> {
    if let Some(id) = document
        .get("prefabId")
        .filter(|_| document.get("instanceId").is_some())
    {
        let pin = pins
            .get(&(OwnedDocumentKind::Prefab, decode(id)?))
            .ok_or_else(|| invalid("Native Instance has no actual owned Prefab membership"))?;
        if document["prefabRevision"] != pin.revision.as_str() {
            return Err(invalid(
                "Native Instance Prefab revision differs from Project membership",
            ));
        }
    }
    if let Some(id) = document.get("ownerPrefabId")
        && !pins.contains_key(&(OwnedDocumentKind::Prefab, decode(id)?))
    {
        return Err(invalid("Native source has no owned Prefab membership"));
    }
    if let Some(id) = document.get("sourceMapResourceId")
        && !resources.contains_key(&decode::<ResourceId>(id)?)
    {
        return Err(invalid(
            "Native source map is not an actual Project resource",
        ));
    }
    for (field, kind) in [
        ("commandModuleIds", OwnedDocumentKind::CommandModule),
        ("clipIds", OwnedDocumentKind::AnimationClip),
    ] {
        if let Some(ids) = document.get(field).and_then(Value::as_array) {
            for id in ids {
                if !pins.contains_key(&(kind, decode(id)?)) {
                    return Err(invalid("Native Prefab references a missing owned source"));
                }
            }
        }
    }
    let mut declared_resources = BTreeSet::new();
    if let Some(values) = document.get("resources").and_then(Value::as_array) {
        for value in values {
            require_exact_resource(value, resources)?;
            declared_resources.insert(decode::<ResourceId>(&value["resourceId"])?);
        }
    }
    if let Some(nodes) = document.get("nodes").and_then(Value::as_array) {
        for node in nodes {
            if let Some(resource) = node.get("geometryResource") {
                require_exact_resource(resource, resources)?;
            }
            if let Some(block) = node.get("blockGeometry")
                && !resources.contains_key(&decode::<ResourceId>(&block["resourceId"])?)
            {
                return Err(invalid("Owned block geometry resource is unavailable"));
            }
            if let Some(values) = node
                .get("display")
                .and_then(|display| display.get("resourceRefs"))
                .and_then(Value::as_array)
            {
                for value in values {
                    let id: ResourceId = decode(value)?;
                    if !resources.contains_key(&id) || !declared_resources.contains(&id) {
                        return Err(invalid("Owned display resource is unavailable"));
                    }
                }
            }
            if let Some(binding) = node.get("physicsBinding")
                && !pins.contains_key(&(
                    OwnedDocumentKind::PhysicsDefinition,
                    decode(&binding["physicsId"])?,
                ))
            {
                return Err(invalid(
                    "Owned physics binding has no actual Project membership",
                ));
            }
        }
    }
    // Extension payloads are opaque contract data, not recursively interpreted
    // as ResourceRef or source/permission declarations. Their registered domain
    // codec and semantics remain the trusted preparation producer's obligation.
    Ok(())
}

fn insert_project(
    transaction: &Transaction<'_>,
    project: &ProjectId,
    revision: &Sha256Digest,
    blob: &BlobRef,
) -> StorageResult<()> {
    let old: Option<String> = transaction.query_row("SELECT blob_digest FROM documents WHERE definition='Project' AND document_id=?1 AND content_hash=?2",params![project.as_str(),revision.as_str()],|row|row.get(0)).optional()?;
    if old.as_ref().is_some_and(|old| old != blob.digest.as_str()) {
        return Err(conflict("Immutable raw Project revision differs"));
    }
    register_blob(transaction, blob)?;
    transaction.execute("INSERT OR IGNORE INTO documents(definition,document_id,content_hash,blob_digest) VALUES('Project',?1,?2,?3)",params![project.as_str(),revision.as_str(),blob.digest.as_str()])?;
    Ok(())
}
fn carry_owned_provenance(
    transaction: &Transaction<'_>,
    project: &ProjectId,
    base: &Sha256Digest,
    revision: &Sha256Digest,
    pin: &OwnedDocumentPin,
) -> StorageResult<()> {
    let old: Option<String> = transaction.query_row("SELECT revision FROM owned_document_provenance WHERE project_id=?1 AND project_revision=?2 AND kind=?3 AND object_id=?4",params![project.as_str(),base.as_str(),pin.kind.as_str(),pin.object_id.as_str()],|row|row.get(0)).optional()?;
    if old.as_deref() != Some(pin.revision.as_str()) {
        return Err(conflict(
            "Native carried document lacks exact base provenance",
        ));
    }
    transaction.execute("INSERT INTO owned_document_provenance(project_id,project_revision,kind,object_id,revision) VALUES(?1,?2,?3,?4,?5)",params![project.as_str(),revision.as_str(),pin.kind.as_str(),pin.object_id.as_str(),pin.revision.as_str()])?;
    Ok(())
}
fn associate_resource(
    transaction: &Transaction<'_>,
    project: &ProjectId,
    revision: &Sha256Digest,
    resource: &StagedResource,
    check: &mut impl FnMut() -> StorageResult<()>,
) -> StorageResult<()> {
    let metadata =
        String::from_utf8(encode_json(&resource.resource).map_err(contract)?).map_err(contract)?;
    let old: Option<(String,i64)> = transaction.query_row("SELECT resource_json,byte_length FROM project_resource_versions WHERE project_id=?1 AND resource_id=?2 AND digest=?3",params![project.as_str(),resource.id.as_str(),resource.blob.digest.as_str()],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
    if let Some((old, length)) = old {
        let original = parse_json_with_control(
            old.as_bytes(),
            JsonLimits {
                max_bytes: MAX_METADATA,
                max_depth: 32,
                max_nodes: 1024,
            },
            &mut *check,
        )
        .map_err(|cause| match cause {
            ControlledJsonError::Control(cause) => cause,
            ControlledJsonError::Json(cause) => contract(cause),
        })?;
        if original != resource.resource
            || u64::try_from(length).ok() != Some(resource.blob.byte_length)
        {
            return Err(conflict("Immutable raw resource version differs"));
        }
    } else {
        let count: i64 = transaction.query_row(
            "SELECT count(*) FROM project_resource_versions",
            [],
            |row| row.get(0),
        )?;
        if count >= MAX_RESOURCE_VERSIONS {
            return Err(invalid("Project resource version capacity exhausted"));
        }
        transaction.execute("INSERT INTO project_resource_versions(project_id,resource_id,digest,resource_json,byte_length) VALUES(?1,?2,?3,?4,?5)",params![project.as_str(),resource.id.as_str(),resource.blob.digest.as_str(),metadata,resource.blob.byte_length as i64])?;
    }
    pin_resource_version(transaction, project, &resource.id, &resource.blob)?;
    transaction.execute("INSERT INTO project_resource_provenance(project_id,project_revision,resource_id,digest) VALUES(?1,?2,?3,?4)",params![project.as_str(),revision.as_str(),resource.id.as_str(),resource.blob.digest.as_str()])?;
    let old: Option<String> = transaction
        .query_row(
            "SELECT digest FROM project_resource_heads WHERE project_id=?1 AND resource_id=?2",
            params![project.as_str(), resource.id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    if old
        .as_ref()
        .is_some_and(|old| old != resource.blob.digest.as_str())
    {
        return Err(conflict("Native source cannot replace a resource head"));
    }
    transaction.execute("INSERT OR IGNORE INTO project_resource_heads(project_id,resource_id,digest) VALUES(?1,?2,?3)",params![project.as_str(),resource.id.as_str(),resource.blob.digest.as_str()])?;
    Ok(())
}

fn guard_head(
    store: &DurableStore,
    project: &ProjectId,
    revision: &Sha256Digest,
    expected: Option<&BlobRef>,
) -> StorageResult<BlobRef> {
    let row: Option<(String,String,String,i64)> = store.connection.query_row("SELECT h.revision,h.blob_digest,d.blob_digest,b.byte_length FROM project_heads h JOIN documents d ON d.definition='Project' AND d.document_id=h.project_id AND d.content_hash=h.revision JOIN blobs b ON b.digest=h.blob_digest WHERE h.project_id=?1",[project.as_str()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional()?;
    let (actual, raw, history, length) =
        row.ok_or(StorageError::NotFound("Native source current Project"))?;
    let blob = BlobRef {
        digest: Sha256Digest::new(raw).map_err(contract)?,
        byte_length: u64::try_from(length).map_err(contract)?,
    };
    if actual != revision.as_str()
        || history != blob.digest.as_str()
        || blob.byte_length == 0
        || blob.byte_length > MAX_OWNED_DOCUMENT_BYTES
        || expected.is_some_and(|expected| *expected != blob)
    {
        return Err(conflict(
            "Native source current Project revision/raw history differs",
        ));
    }
    Ok(blob)
}
fn parse(
    store: &DurableStore,
    permit: &dyn NativeOwnedSourceCommitPermit,
    bytes: &[u8],
    maximum: usize,
) -> StorageResult<Value> {
    parse_json_with_control(
        bytes,
        JsonLimits {
            max_bytes: maximum,
            max_depth: 64,
            max_nodes: 100_000,
        },
        || {
            permit.check_store(store)?;
            permit.check()
        },
    )
    .map_err(|cause| match cause {
        ControlledJsonError::Control(cause) => cause,
        ControlledJsonError::Json(cause) => contract(cause),
    })
}

/// Check only bytes from this request or the authorized retained CAS read.
/// The returned Value is compared to the earlier strict parse; this does not
/// establish a separate witness for retained ResourceRef metadata that exists
/// only as a Value or prove that retained CAS bytes are an author's first input.
fn check_exact_input(
    store: &DurableStore,
    permit: &dyn NativeOwnedSourceCommitPermit,
    bytes: &[u8],
    maximum: usize,
    selector: ExactSelector,
    expected: &Value,
) -> StorageResult<()> {
    let actual = store
        .validator
        .parse_validate_exact_with_control(
            selector,
            bytes,
            JsonLimits {
                max_bytes: maximum,
                max_depth: 64,
                max_nodes: 100_000,
            },
            || {
                permit.check_store(store)?;
                permit.check()
            },
        )
        .map_err(|cause| match cause {
            ControlledContractError::Control(cause) => cause,
            ControlledContractError::Contract(cause) => contract(cause),
            cause @ ControlledContractError::ExactInteger { .. } => contract(cause),
            ControlledContractError::CaptureUnavailable => StorageError::RawExactCaptureUnavailable,
        })?;
    if &actual != expected {
        return Err(StorageError::RawExactCaptureUnavailable);
    }
    Ok(())
}
fn stage_bytes(
    store: &DurableStore,
    permit: &dyn NativeOwnedSourceCommitPermit,
    bytes: &[u8],
) -> StorageResult<BlobRef> {
    permit.check_store(store)?;
    permit.check()?;
    let blob = store.cas.put(bytes)?;
    verify_blob(store, permit, &blob)?;
    Ok(blob)
}
fn verify_blob(
    store: &DurableStore,
    permit: &dyn NativeOwnedSourceCommitPermit,
    blob: &BlobRef,
) -> StorageResult<()> {
    store
        .cas
        .read_verified_slice::<StorageError, _>(blob, blob.byte_length, 1, || {
            permit.check_store(store)?;
            permit.check()
        })?;
    Ok(())
}
fn resource_pin(store: &DurableStore, resource: &Value) -> StorageResult<(ResourceId, BlobRef)> {
    if encode_json(resource).map_err(contract)?.len() > MAX_METADATA {
        return Err(invalid("Native ResourceRef metadata budget"));
    }
    super::artifact::validate_resource(&store.validator, resource).map_err(artifact_error)
}

/// Private comparison copy for a ResourceRef parsed from this request's raw
/// metadata bytes. This is provisional: a parsed float may have rounded an
/// inexact decimal, so the caller must check the original bytes and Value with
/// `check_exact_input` before staging or publishing. Existing stored rows and
/// Value-only retained inputs never pass through this conversion.
fn raw_resource_comparison_copy(store: &DurableStore, original: &Value) -> StorageResult<Value> {
    let original_error = match resource_pin(store, original) {
        Ok(_) => return Ok(original.clone()),
        Err(error) => error,
    };
    if original.get("sizeBytes").and_then(Value::as_u64).is_some()
        || !matches!(encode_json(original), Ok(encoded) if encoded.len() <= MAX_METADATA)
        || store.validator.validate("ResourceRef", original).is_err()
    {
        return Err(original_error);
    }
    let Ok(comparable) = normalize_mesh_resource_ref(original) else {
        return Err(original_error);
    };
    if resource_pin(store, &comparable).is_err() {
        return Err(original_error);
    }
    Ok(comparable)
}
fn require_project_resource(
    project: &ProjectId,
    resource: &RegisteredProjectResource,
) -> StorageResult<()> {
    if resource.owner != ResourceOwner::Project(project.clone()) {
        return Err(conflict("Native source resource belongs to another owner"));
    }
    Ok(())
}
fn require_new_resource_id(store: &DurableStore, resource: &ResourceId) -> StorageResult<()> {
    let exists: i64 = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM artifact_resources WHERE resource_id=?1) OR EXISTS(SELECT 1 FROM project_resource_versions WHERE resource_id=?1) OR EXISTS(SELECT 1 FROM project_resource_heads WHERE resource_id=?1)",
        [resource.as_str()], |row|row.get(0),
    )?;
    if exists != 0 {
        return Err(conflict(
            "Raw native resource input requires a new resource ID",
        ));
    }
    Ok(())
}
fn owned_pins(
    project: &Value,
) -> StorageResult<BTreeMap<(OwnedDocumentKind, ObjectId), OwnedDocumentPin>> {
    let values = array(project, "ownedResources")?;
    if values.len() > MAX_OWNED_DOCUMENTS_PER_PROJECT {
        return Err(invalid("Native Project owned membership budget"));
    }
    let mut pins = BTreeMap::new();
    for value in values {
        let pin: OwnedDocumentPin = decode(value)?;
        if pins
            .insert((pin.kind, pin.object_id.clone()), pin)
            .is_some()
        {
            return Err(invalid("Native Project repeats an owned identity"));
        }
    }
    for (key, kind) in [
        ("prefabIds", OwnedDocumentKind::Prefab),
        ("instanceIds", OwnedDocumentKind::Instance),
    ] {
        let ids: BTreeSet<ObjectId> = decode(&project[key])?;
        if ids.len() != array(project, key)?.len()
            || ids
                != pins
                    .iter()
                    .filter(|((owned_kind, _), _)| *owned_kind == kind)
                    .map(|((_, id), _)| id.clone())
                    .collect()
        {
            return Err(invalid(
                "Native Project object index does not match owned membership",
            ));
        }
    }
    Ok(pins)
}
fn resource_ids(project: &Value) -> StorageResult<BTreeSet<ResourceId>> {
    let ids: BTreeSet<ResourceId> = decode(&project["resourceIds"])?;
    if ids.len() != array(project, "resourceIds")?.len()
        || ids.len() > MAX_OWNED_DOCUMENTS_PER_PROJECT
    {
        return Err(invalid(
            "Native Project resource index budget or duplicates",
        ));
    }
    Ok(ids)
}
fn append(project: &mut Value, key: &str, value: Value) -> StorageResult<()> {
    let values = project[key]
        .as_array_mut()
        .ok_or_else(|| invalid("Native Project index missing"))?;
    if values.len() >= MAX_OWNED_DOCUMENTS_PER_PROJECT {
        return Err(invalid("Native Project membership capacity exhausted"));
    }
    values.push(value);
    Ok(())
}
fn account(remaining: &mut u64, bytes: u64) -> StorageResult<()> {
    *remaining = remaining
        .checked_sub(bytes)
        .ok_or_else(|| invalid("Native source total read/staging budget exhausted"))?;
    Ok(())
}
fn array<'a>(value: &'a Value, key: &str) -> StorageResult<&'a [Value]> {
    value[key]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| invalid("Native Project/source array missing"))
}
fn decode<T: DeserializeOwned>(value: &Value) -> StorageResult<T> {
    serde_json::from_value(value.clone()).map_err(contract)
}
fn invalid(message: &'static str) -> StorageError {
    StorageError::InvalidInput(message.into())
}
fn conflict(message: &'static str) -> StorageError {
    StorageError::Conflict(message)
}
fn contract(cause: impl std::fmt::Display) -> StorageError {
    StorageError::Contract(cause.to_string())
}
fn artifact_error(cause: ArtifactError) -> StorageError {
    match cause.code {
        "RESOURCE_REGISTRATION_CONFLICT" => {
            conflict("Native artifact resource identity is immutable")
        }
        "RESOURCE_INTEGRITY_FAILED" => {
            StorageError::Corrupt("Native artifact raw CAS integrity failed".into())
        }
        "INPUT_INVALID" => StorageError::Contract("Native artifact ResourceRef is invalid".into()),
        "RESOURCE_LIMIT" => invalid("Native artifact resource capacity exhausted"),
        _ => StorageError::InvalidTransition(format!("{}: {}", cause.code, cause.message)),
    }
}

#[cfg(test)]
#[path = "native_owned_sources_tests.rs"]
mod tests;

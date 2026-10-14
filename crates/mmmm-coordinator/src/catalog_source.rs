//! FN22 composition uses authenticated registrations and the service's one
//! borrowed store. SourceRef locators, caller hashes and decoded JSON never
//! install rights, source bindings, pack selections or verified game targets.

use crate::{
    auth::AuthenticatedPrincipal,
    authority::LocalAuthority,
    features::{CaptureInputs, FeatureAccess},
    host::HostBridge,
    native_catalog::{NativeCatalogAdmission, NativeCatalogCheckpoint, NativeCatalogHostFailure},
    planning_source::{LocalPlanningAccess, PlanningStore, SharedPlanningContexts},
    service::{RequestBudget, RequestContextSlot, ServiceError},
};
use mmmm_application::{Access, AppError, AppResult};
use mmmm_contracts::{
    ContextId, ContractValidator, PrincipalId, ProjectId, ResourceId, ResourceLocation,
    Sha256Digest, SnapshotId, SourceId, canonical_digest, encode_json, raw_digest,
};
use mmmm_exchange::archive::{ArchiveLimits, read_zip_with_cancel, validate_member_path};
use mmmm_reference::{
    AccessControl, ApprovedCatalogSource, CaptureBudget, CaptureControl, CaptureGrant,
    CaptureResult, CaptureSourceAccess, CapturedSourceBytes, Catalog, CatalogCaptureBackend,
    CatalogError, CatalogLayer, CatalogLimits, CatalogSourceCodec, CatalogSourceRole,
    HostRegistryTransport, MAX_NATIVE_REGISTRY_BYTES, ReadPrincipal, RegistryCaptureWitness,
    SnapshotSource, VerifiedSnapshotSource,
};
use mmmm_runtime::storage::{
    DurableStore, StorageError,
    artifact::{
        ArtifactError, ArtifactResult, ResourceAuthority, ResourceOwner, register_resource,
    },
    owned_documents::{OwnedDocumentAuthority, OwnedDocumentPin, OwnedDocumentReader},
    project_resources::{
        ProjectResourceAuthority, ProjectResourceQuery, ProjectResourceReader,
        ProjectResourceRequest, ProjectSourceRpcContext, RegisteredProjectResource,
    },
};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc, sync::Arc};

const MAX_SOURCES: usize = 256;
const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DOCUMENT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_BINDINGS: usize = 64;
const MAX_CAPTURE_RECEIPTS: usize = 1024;
const MAX_CAPTURED_RESOURCES: usize = 4096;
const SOURCE_EVIDENCE_MEDIA: &str = "application/vnd.mmmm.catalog-source-evidence+json";
const CAPTURE_EVIDENCE_MEDIA: &str = "application/vnd.mmmm.catalog-capture-evidence+json";
const HOST_EVIDENCE_MEDIA: &str = "application/vnd.mmmm.host-inspection-evidence+json";

/// Exact server-owned ResourceRef and Project query. It opens only the product
/// CAS through ProjectResourceReader, never a caller file/URI or a broad scan.
#[derive(Clone, Debug)]
pub struct RegisteredCatalogResource {
    pub query: ProjectResourceQuery,
    pub resource: Value,
}

#[derive(Clone, Debug)]
pub enum CatalogSourceBacking {
    ProjectResource(RegisteredCatalogResource),
    /// The approved root is this exact immutable CAS archive. Member paths are
    /// literal portable file keys. No extraction, filesystem links or URI I/O.
    /// This initial adapter uses the strict neutral exchange ZIP profile (root
    /// mmmm-exchange.json, file entries, finite sizes). Arbitrary game JAR/pack
    /// content enumeration needs its own approved archive decoder port.
    ArchiveMember {
        archive: RegisteredCatalogResource,
        member: String,
        member_sha256: Sha256Digest,
        member_bytes: u64,
        limits: ArchiveLimits,
    },
    OwnedDocument(OwnedDocumentPin),
    NativeRegistry,
}

/// Trusted local setup supplies an explicit rights decision separately from
/// source bytes. This is not deserializable or exposed as a registration RPC.
/// Current Project/source ACL and actual stored provenance are still required.
#[derive(Clone, Debug)]
pub struct CatalogSourceRegistration {
    pub source: Value,
    pub layer: CatalogLayer,
    pub role: CatalogSourceRole,
    pub codec: CatalogSourceCodec,
    pub backing: CatalogSourceBacking,
}

/// Offline selections are exact authenticated setup facts. For a game context
/// they are expectations only: current native source facts must independently
/// bind every identity. Missing/native-unknown pack data is never an empty list.
#[derive(Clone, Debug)]
pub struct CatalogEnvironmentRegistration {
    pub context: Value,
    pub game_version: Option<String>,
    pub locale: Option<String>,
    pub artifact_source: Option<SourceId>,
    pub server_pack_sources: Option<Vec<SourceId>>,
    pub client_pack_sources: Option<Vec<SourceId>>,
    pub mod_sources: Option<BTreeMap<ResourceLocation, SourceId>>,
    pub registry_generation: Option<String>,
    /// Exact setup mapping from canonical mod IDs to observed Fabric IDs.
    pub native_mod_ids: BTreeMap<ResourceLocation, String>,
    pub sources: Vec<CatalogSourceRegistration>,
}

#[derive(Clone)]
struct InstalledSource {
    approved: ApprovedCatalogSource,
    backing: CatalogSourceBacking,
}
#[derive(Clone)]
struct InstalledEnvironment {
    registration: CatalogEnvironmentRegistration,
    sources: BTreeMap<SourceId, InstalledSource>,
    project: ProjectId,
    principal: PrincipalId,
    revision: Sha256Digest,
}
#[derive(Clone)]
enum CatalogPublisher {
    Explicit,
    NativeObservation(NativeCatalogOrigin),
}
#[derive(Clone)]
struct NativeCatalogOrigin {
    proof: Sha256Digest,
    read_policy: Sha256Digest,
    source_use: Sha256Digest,
    receipt: Rc<()>,
}
/// An exact in-process publication owner, never a source or wire capability.
/// A failed admission may remove only this native publisher's current element.
#[derive(Clone)]
pub(crate) struct NativeCatalogPublication {
    key: (PrincipalId, ContextId),
    revision: Sha256Digest,
    receipt: Rc<()>,
    read_policy: Sha256Digest,
    source_use: Sha256Digest,
}
impl NativeCatalogPublication {
    pub(crate) fn read_policy(&self) -> &Sha256Digest {
        &self.read_policy
    }
    pub(crate) fn source_use(&self) -> &Sha256Digest {
        &self.source_use
    }
}
pub(crate) enum NativeCatalogAdmissionState {
    Explicit,
    Missing,
    Native(NativeCatalogPublication),
}
#[derive(Clone)]
struct CaptureAuthorityReceipt {
    context: ContextId,
    binding_revision: Sha256Digest,
    context_digest: Value,
    retained_manifest: Value,
    source_resources: Vec<CapturedResourceReceipt>,
    snapshot_digest: Sha256Digest,
}
#[derive(Clone)]
struct CapturedResourceReceipt {
    resource: Value,
    source_manifest: Value,
    source: Value,
    rights_witness: Sha256Digest,
}

/// Obtained only from the exact private capture/source issuance relation and
/// live source grant. `source.rights` remains the original approved decision;
/// neither Project ownership nor successful decoding grants redistribution.
pub struct CatalogResourceBytes {
    pub bytes: Vec<u8>,
    pub source: Value,
}

/// This identifies an approved whole source input, not a verified game target,
/// transformed class set, resource merge, pack fingerprint or profile proof.
/// Only current authenticated setup and a checked raw CAS read issue it; there
/// is deliberately no wire deserializer or target-admission field.
#[derive(Clone, Debug)]
pub struct RegisteredCatalogSourceIdentity {
    pub source: Value,
    pub role: CatalogSourceRole,
    pub resource: Value,
    pub binding_revision: Sha256Digest,
}
#[derive(Default)]
struct CatalogRegistrations {
    environments: BTreeMap<(PrincipalId, ContextId), InstalledEnvironment>,
    native_publishers: BTreeMap<(PrincipalId, ContextId), NativeCatalogOrigin>,
    captures: BTreeMap<SnapshotId, CaptureAuthorityReceipt>,
    pending_captures: BTreeMap<SnapshotId, CaptureAuthorityReceipt>,
}

/// In-process registrations have no wire constructor. A restart must reinstall
/// real current source/rights grants; retained CAS evidence alone grants none.
#[derive(Clone)]
pub struct RegisteredCatalogSources {
    state: Rc<RefCell<CatalogRegistrations>>,
    authority: LocalAuthority,
    hosts: HostBridge,
    contexts: SharedPlanningContexts,
}
impl RegisteredCatalogSources {
    pub fn new(
        authority: LocalAuthority,
        hosts: HostBridge,
        contexts: SharedPlanningContexts,
    ) -> Self {
        Self {
            state: Rc::new(RefCell::new(CatalogRegistrations::default())),
            authority,
            hosts,
            contexts,
        }
    }

    /// Called only by explicit authenticated setup after ownership and the
    /// separate rights decision. Never pass a public capture DTO as this input.
    /// Actual current Project metadata/CAS provenance is verified on install.
    pub fn register(
        &self,
        authenticated: &AuthenticatedPrincipal,
        budget: &RequestBudget,
        store: &DurableStore,
        registration: CatalogEnvironmentRegistration,
    ) -> AppResult<Sha256Digest> {
        self.register_with_publisher(
            authenticated,
            budget,
            store,
            registration,
            CatalogPublisher::Explicit,
        )
    }

    fn register_with_publisher(
        &self,
        authenticated: &AuthenticatedPrincipal,
        budget: &RequestBudget,
        store: &DurableStore,
        registration: CatalogEnvironmentRegistration,
        publisher: CatalogPublisher,
    ) -> AppResult<Sha256Digest> {
        budget.check().map_err(service_app)?;
        if !authenticated.permits("catalog.capture")
            || registration.sources.is_empty()
            || registration.sources.len() > MAX_SOURCES
        {
            return Err(forbidden());
        }
        if registration
            .server_pack_sources
            .as_ref()
            .is_some_and(|s| s.len() > MAX_SOURCES)
            || registration
                .client_pack_sources
                .as_ref()
                .is_some_and(|s| s.len() > MAX_SOURCES)
            || registration
                .mod_sources
                .as_ref()
                .is_some_and(|s| s.len() > MAX_SOURCES)
            || registration.native_mod_ids.len() > MAX_SOURCES
            || registration
                .native_mod_ids
                .values()
                .any(|s| s.is_empty() || s.len() > 128)
            || registration
                .native_mod_ids
                .values()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != registration.native_mod_ids.len()
        {
            return Err(budget_error());
        }
        validate("ExecutionContext", &registration.context)?;
        let project = project_id(&registration.context)?;
        let context_id = context_id(&registration.context)?;
        let access = self.planning_access(authenticated.clone(), budget.clone())?;
        access.authorize_project(
            authenticated.principal(),
            &project,
            Some(&registration.context),
            Access::ReadProject,
        )?;
        let rpc = CatalogRpc::new(
            authenticated.clone(),
            budget.clone(),
            self.authority.clone(),
            &registration.context,
        )?;
        let project_document = current_project(store, &rpc, &project)?;
        let revision = digest_field(&project_document, "revision")?;
        let mut sources = BTreeMap::new();
        let mut metadata_total = 0usize;
        let mut requested_bytes = 0u64;
        for requested in &registration.sources {
            budget.check().map_err(service_app)?;
            validate("SourceRef", &requested.source)?;
            if requested.source["rights"] == "unknown" {
                return Err(error(
                    "PERMISSION_REQUIRED",
                    "Source rights have no explicit approved decision",
                ));
            }
            metadata_total = metadata_total
                .checked_add(encode_json(&requested.source).map_err(json_app)?.len())
                .ok_or_else(budget_error)?;
            if metadata_total > 1024 * 1024
                || encode_json(&requested.source).map_err(json_app)?.len() > 16 * 1024
            {
                return Err(budget_error());
            }
            let id = source_id(&requested.source)?;
            if sources.contains_key(&id) {
                return Err(error("SOURCE_CONFLICT", "Source ID is duplicated"));
            }
            let mut source = requested.source.clone();
            let input_bytes = match &requested.backing {
                CatalogSourceBacking::ProjectResource(r) => r.resource["sizeBytes"].as_u64(),
                CatalogSourceBacking::ArchiveMember { archive, .. } => {
                    archive.resource["sizeBytes"].as_u64()
                }
                CatalogSourceBacking::OwnedDocument(_) | CatalogSourceBacking::NativeRegistry => {
                    Some(0)
                }
            }
            .ok_or_else(budget_error)?;
            requested_bytes = requested_bytes
                .checked_add(input_bytes)
                .ok_or_else(budget_error)?;
            if requested_bytes > MAX_SOURCE_BYTES {
                return Err(budget_error());
            }
            match &requested.backing {
                CatalogSourceBacking::ProjectResource(resource) => {
                    let actual =
                        verify_resource_metadata(store, &rpc, &project, &revision, resource)?;
                    source["sha256"] = actual.resource["sha256"].clone();
                    source["locator"] = json!(format!(
                        "mmmm-source://project/{}/{}/{}",
                        project.as_str(),
                        text(&actual.resource, "resourceId")?,
                        text(&actual.resource, "sha256")?
                    ));
                }
                CatalogSourceBacking::ArchiveMember {
                    archive,
                    member,
                    member_sha256,
                    member_bytes,
                    limits,
                } => {
                    validate_member_path(member, *limits).map_err(|_| {
                        error("SOURCE_INVALID", "Approved archive member path is invalid")
                    })?;
                    if *member_bytes > limits.max_member_bytes || *member_bytes > MAX_SOURCE_BYTES {
                        return Err(budget_error());
                    }
                    let actual =
                        verify_resource_metadata(store, &rpc, &project, &revision, archive)?;
                    archive_type(&actual.resource)?;
                    source["sha256"] = json!(member_sha256);
                    source["locator"] = json!(format!(
                        "mmmm-source://archive/{}/{}",
                        text(&actual.resource, "sha256")?,
                        raw_digest(member.as_bytes())
                    ));
                }
                CatalogSourceBacking::OwnedDocument(pin) => {
                    let mut reader = OwnedDocumentReader::new(
                        Box::new(CatalogReadAuthority(rpc.clone())),
                        MAX_DOCUMENT_BYTES,
                    )
                    .map_err(|e| rpc.storage_error(e))?;
                    let actual = reader
                        .read_known_history_bytes(store, &rpc, &project, &revision, pin)
                        .map_err(|e| rpc.storage_error(e))?;
                    source["sha256"] = json!(actual.blob.digest);
                    source["locator"] = json!(format!(
                        "mmmm-source://owned/{}/{}/{}/{}",
                        project.as_str(),
                        pin.kind.as_str(),
                        pin.object_id.as_str(),
                        pin.revision.as_str()
                    ));
                }
                CatalogSourceBacking::NativeRegistry => {
                    if registration.context["environment"]["kind"] != "game"
                        || !matches!(requested.codec, CatalogSourceCodec::NativeRegistry)
                        || requested.source["kind"] != "runtime_observation"
                    {
                        return Err(error(
                            "SOURCE_INVALID",
                            "Native registry requires an actual paired game source",
                        ));
                    }
                    source["sha256"] = Value::Null;
                    source["locator"] = json!(format!(
                        "mmmm-host://catalog/{}/native_registry",
                        context_id.as_str()
                    ));
                }
            }
            if !requested.source["sha256"].is_null()
                && !source["sha256"].is_null()
                && requested.source["sha256"] != source["sha256"]
            {
                return Err(error(
                    "SOURCE_CONFLICT",
                    "Setup source hash differs from actual stored source",
                ));
            }
            source["verifiedAt"] = json!(now()?);
            validate("SourceRef", &source)?;
            validate_source_registration(requested)?;
            let witness = canonical_digest(&json!({"format":"mmmm.catalog-source-rights/1","principal":authenticated.principal(),"project":project,
                "contextDigest":registration.context["contextDigest"],"source":source,"backing":backing_identity(&requested.backing)})).map_err(digest_app)?;
            sources.insert(
                id,
                InstalledSource {
                    approved: ApprovedCatalogSource {
                        source,
                        layer: requested.layer,
                        role: requested.role.clone(),
                        rights_witness: witness,
                        codec: requested.codec.clone(),
                    },
                    backing: requested.backing.clone(),
                },
            );
        }
        access.authorize_project(
            authenticated.principal(),
            &project,
            Some(&registration.context),
            Access::ReadProject,
        )?;
        let source_pins = sources.iter().map(|(id,s)| json!({"sourceId":id,"source":s.approved.source,"rightsWitness":s.approved.rights_witness,"layer":s.approved.layer,"role":role_identity(&s.approved.role),"codec":codec_identity(&s.approved.codec),"backing":backing_identity(&s.backing)})).collect::<Vec<_>>();
        let binding_revision = canonical_digest(&json!({"format":"mmmm.catalog-binding/1","principal":authenticated.principal(),"project":project,"context":registration.context,
            "gameVersion":registration.game_version,"locale":registration.locale,"artifact":registration.artifact_source,"serverPacks":registration.server_pack_sources,
            "clientPacks":registration.client_pack_sources,"mods":registration.mod_sources,"nativeModIds":registration.native_mod_ids,"generation":registration.registry_generation,"sources":source_pins})).map_err(digest_app)?;
        let installed = InstalledEnvironment {
            registration,
            sources,
            project,
            principal: authenticated.principal().clone(),
            revision: binding_revision.clone(),
        };
        let mut state = self.state.try_borrow_mut().map_err(|_| busy())?;
        let key = (authenticated.principal().clone(), context_id);
        if state.environments.contains_key(&key)
            && (state.native_publishers.contains_key(&key)
                || matches!(publisher, CatalogPublisher::NativeObservation(_)))
        {
            // Explicit source composition retains its existing replacement
            // policy. A lazy native publisher cannot replace it, or vice versa.
            return Err(error(
                "SOURCE_CONFLICT",
                "Catalog source publisher already owns this context",
            ));
        }
        if state.environments.len() >= MAX_BINDINGS && !state.environments.contains_key(&key) {
            return Err(budget_error());
        }
        if let CatalogPublisher::NativeObservation(origin) = publisher {
            state.native_publishers.insert(key.clone(), origin);
        }
        state.environments.insert(key, installed);
        Ok(binding_revision)
    }

    /// Selection only; current request, native owner and actual source facts
    /// are checked by the native consumer before either issuance or reuse.
    pub(crate) fn native_admission_state(
        &self,
        authenticated: &AuthenticatedPrincipal,
        context: &Value,
    ) -> AppResult<NativeCatalogAdmissionState> {
        let id = context_id(context)?;
        if !authenticated.is_current() || !authenticated.permits_context(id.as_str()) {
            return Err(forbidden());
        }
        let key = (authenticated.principal().clone(), id);
        let state = self.state.try_borrow().map_err(|_| busy())?;
        let Some(installed) = state.environments.get(&key) else {
            return Ok(NativeCatalogAdmissionState::Missing);
        };
        match state.native_publishers.get(&key) {
            None => Ok(NativeCatalogAdmissionState::Explicit),
            Some(origin) => Ok(NativeCatalogAdmissionState::Native(
                NativeCatalogPublication {
                    key,
                    revision: installed.revision.clone(),
                    receipt: origin.receipt.clone(),
                    read_policy: origin.read_policy.clone(),
                    source_use: origin.source_use.clone(),
                },
            )),
        }
    }

    /// Only the actual completed-pairing consumer constructs this opaque
    /// observation. DTOs, policy records and hashes have no issuance entry.
    pub(crate) fn register_native_observation(
        &self,
        authenticated: &AuthenticatedPrincipal,
        budget: &RequestBudget,
        store: &DurableStore,
        observation: crate::native_catalog::NativeCatalogObservation,
    ) -> AppResult<NativeCatalogPublication> {
        let (registration, proof, read_policy, source_use, method) = observation.into_parts();
        budget.check().map_err(service_app)?;
        let id = context_id(&registration.context)?;
        if !authenticated.is_current()
            || !authenticated.permits(&method)
            || !authenticated.permits_context(id.as_str())
        {
            return Err(forbidden());
        }
        let key = (authenticated.principal().clone(), id);
        {
            let state = self.state.try_borrow().map_err(|_| busy())?;
            if let Some(previous) = state.environments.get(&key) {
                let Some(original) = state.native_publishers.get(&key) else {
                    return Err(error(
                        "SOURCE_CONFLICT",
                        "Explicit catalog sources already own this context",
                    ));
                };
                if original.proof != proof
                    || original.read_policy != read_policy
                    || original.source_use != source_use
                    || previous.registration.context != registration.context
                {
                    return Err(error(
                        "TARGET_DRIFT",
                        "Actual native catalog source identity changed",
                    ));
                }
                // Search/describe may reuse an existing source after the same
                // actual admission checks, but cannot create a missing grant.
                return Ok(NativeCatalogPublication {
                    key,
                    revision: previous.revision.clone(),
                    receipt: original.receipt.clone(),
                    read_policy: original.read_policy.clone(),
                    source_use: original.source_use.clone(),
                });
            }
        }
        if method != "catalog.capture" {
            return Err(forbidden());
        }
        let receipt = Rc::new(());
        let revision = self.register_with_publisher(
            authenticated,
            budget,
            store,
            registration,
            CatalogPublisher::NativeObservation(NativeCatalogOrigin {
                proof,
                read_policy: read_policy.clone(),
                source_use: source_use.clone(),
                receipt: receipt.clone(),
            }),
        )?;
        Ok(NativeCatalogPublication {
            key,
            revision,
            receipt,
            read_policy,
            source_use,
        })
    }

    /// Pure exact-owner retirement. A replacement, explicit publisher or
    /// missing element is left untouched; registry contention is not hidden.
    pub(crate) fn retire_native_publication(
        &self,
        publication: &NativeCatalogPublication,
    ) -> AppResult<()> {
        let mut state = self.state.try_borrow_mut().map_err(|_| busy())?;
        let matches = state
            .environments
            .get(&publication.key)
            .is_some_and(|current| {
                current.revision == publication.revision
                    && state
                        .native_publishers
                        .get(&publication.key)
                        .is_some_and(|origin| Rc::ptr_eq(&origin.receipt, &publication.receipt))
            });
        if matches {
            state.environments.remove(&publication.key);
            state.native_publishers.remove(&publication.key);
        }
        Ok(())
    }

    pub fn revoke(&self, authenticated: &AuthenticatedPrincipal, id: &ContextId) -> AppResult<()> {
        if !authenticated.permits("catalog.capture") || !authenticated.permits_context(id.as_str())
        {
            return Err(forbidden());
        }
        let mut state = self.state.try_borrow_mut().map_err(|_| busy())?;
        let key = (authenticated.principal().clone(), id.clone());
        state.environments.remove(&key);
        state.native_publishers.remove(&key);
        Ok(())
    }

    pub fn read_principal(
        &self,
        authenticated: &AuthenticatedPrincipal,
        id: &ContextId,
    ) -> AppResult<ReadPrincipal> {
        let installed = self.environment(authenticated, id)?;
        let scope = self
            .authority
            .project_scope(authenticated.principal(), &installed.project)?;
        let policy = self
            .authority
            .policy_revision(authenticated.principal(), &installed.project)?;
        let digest = canonical_digest(&json!({"format":"mmmm.catalog-read-authority/1","principal":authenticated.principal(),"context":id,
            "contextDigest":installed.registration.context["contextDigest"],"sourceBinding":installed.revision,"currentScope":scope,"currentPolicy":policy})).map_err(digest_app)?;
        Ok(ReadPrincipal {
            principal_id: authenticated.principal().clone(),
            permission_scope_digest: digest,
        })
    }

    pub fn source_refs(
        &self,
        authenticated: &AuthenticatedPrincipal,
        id: &ContextId,
        budget: &RequestBudget,
    ) -> AppResult<Vec<Value>> {
        let environment = self.environment(authenticated, id)?;
        let access = self.planning_access(authenticated.clone(), budget.clone())?;
        access.authorize_project(
            authenticated.principal(),
            &environment.project,
            Some(&environment.registration.context),
            Access::ReadProject,
        )?;
        Ok(environment
            .sources
            .values()
            .map(|source| source.approved.source.clone())
            .collect())
    }

    /// Pure current source/session/Project authority plus one checked CAS read.
    /// This performs no host I/O and may run inside PlanningStore::with_read.
    /// A consumer needing current native target facts must obtain and compare
    /// those facts outside the store guard. Members, owned documents and runtime
    /// registry bytes cannot be promoted to a whole input artifact through this
    /// method; they keep their existing narrower capture paths.
    pub fn source_identity(
        &self,
        authenticated: &AuthenticatedPrincipal,
        context: &Value,
        source_id: &SourceId,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> AppResult<RegisteredCatalogSourceIdentity> {
        self.source_identity_with_limit(
            authenticated,
            context,
            source_id,
            store,
            budget,
            MAX_SOURCE_BYTES,
        )
    }

    /// The caller can lower the existing source ceiling, never raise it. The
    /// same checked reader admits exact stored ResourceRef/blob metadata and
    /// compares its actual byte length with this limit before opening the
    /// source CAS body. No separate metadata read or second source reader runs.
    pub fn source_identity_with_limit(
        &self,
        authenticated: &AuthenticatedPrincipal,
        context: &Value,
        source_id: &SourceId,
        store: &DurableStore,
        budget: &RequestBudget,
        max_bytes: u64,
    ) -> AppResult<RegisteredCatalogSourceIdentity> {
        budget.check().map_err(service_app)?;
        if max_bytes == 0 || max_bytes > MAX_SOURCE_BYTES {
            return Err(budget_error());
        }
        let id = context_id(context)?;
        let installed = self.environment(authenticated, &id)?;
        if installed.registration.context != *context {
            return Err(forbidden());
        }
        let call = CatalogCall {
            sources: self.clone(),
            authenticated: authenticated.clone(),
            budget: budget.clone(),
            read_principal: self.read_principal(authenticated, &id)?,
            installed,
            native_checkpoint: None,
        };
        call.local()?;
        let registered = call
            .installed
            .sources
            .get(source_id)
            .ok_or_else(forbidden)?;
        let current = call.source(&registered.approved.source)?;
        let CatalogSourceBacking::ProjectResource(resource) = &current.backing else {
            return Err(error(
                "SOURCE_UNAVAILABLE",
                "Source is not an approved whole Project resource input",
            ));
        };
        let rpc = call.rpc()?;
        let project = current_project(store, &rpc, &call.installed.project)?;
        let revision = digest_field(&project, "revision")?;
        let bytes = read_resource(
            store,
            &rpc,
            &call.installed.project,
            &revision,
            resource,
            max_bytes,
        )?;
        if current.approved.source["sha256"] != raw_digest(&bytes).as_str() {
            return Err(error(
                "SOURCE_CONFLICT",
                "Approved whole source differs from its actual input bytes",
            ));
        }
        if !matches!(current.approved.role, CatalogSourceRole::CatalogData) {
            archive_type(&resource.resource)?;
            archive_header(&bytes).map_err(|_| {
                error(
                    "SOURCE_INVALID",
                    "Approved fingerprint input is not a ZIP container",
                )
            })?;
        }
        call.source(&current.approved.source)?;
        call.local()?;
        budget.check().map_err(service_app)?;
        Ok(RegisteredCatalogSourceIdentity {
            source: current.approved.source,
            role: current.approved.role,
            resource: resource.resource.clone(),
            binding_revision: call.installed.revision,
        })
    }

    pub fn capture_inputs<'a>(
        &self,
        slot: &RequestContextSlot,
        access: &FeatureAccess,
        input: &Value,
        store: &'a mut DurableStore,
        budget: &RequestBudget,
    ) -> Result<CaptureInputs<'a>, ServiceError> {
        let (authenticated, actual_budget) = slot.current()?;
        if actual_budget.deadline() != budget.deadline()
            || !authenticated.permits("catalog.capture")
        {
            return Err(service_forbidden());
        }
        let context = access.context.as_ref().ok_or_else(service_unavailable)?;
        let id = context_id(context).map_err(app_service)?;
        let installed = self.environment(&authenticated, &id).map_err(app_service)?;
        let expected = self
            .read_principal(&authenticated, &id)
            .map_err(app_service)?;
        if access.read_principal.principal_id != expected.principal_id
            || access.read_principal.permission_scope_digest != expected.permission_scope_digest
            || *context != installed.registration.context
            || input["contextId"] != id.as_str()
        {
            return Err(service_forbidden());
        }
        let native_checkpoint = NativeCatalogAdmission {
            request: slot,
            authority: &self.authority,
            hosts: &self.hosts,
            sources: self,
        }
        .checkpoint(&authenticated, context, store, &actual_budget)
        .map_err(|cause| ServiceError::caused_by(cause.code, cause.message, cause))?;
        let shared = PlanningStore::write(store);
        let call = CatalogCall {
            sources: self.clone(),
            authenticated,
            budget: actual_budget,
            installed,
            read_principal: expected,
            native_checkpoint,
        };
        call.fresh().map_err(app_service)?;
        let backend = BorrowedCatalogBackend {
            store: shared.clone(),
            call: call.clone(),
            attempt: None,
            retained_sources: Vec::new(),
        };
        let transport = PairedCatalogRegistry {
            store: shared.clone(),
            call: call.clone(),
        };
        let source = RetainedCatalogCapture {
            inner: VerifiedSnapshotSource { transport, backend },
            store: shared,
            call: call.clone(),
        };
        Ok(CaptureInputs {
            access: Box::new(CatalogAccess(call, true)),
            source: Box::new(source),
        })
    }

    pub fn catalog_access<'a>(
        &self,
        slot: &RequestContextSlot,
        access: &FeatureAccess,
        budget: &RequestBudget,
    ) -> Result<Box<dyn AccessControl + 'a>, ServiceError> {
        let (authenticated, actual_budget) = slot.current()?;
        if actual_budget.deadline() != budget.deadline() {
            return Err(service_forbidden());
        }
        let context = access.context.as_ref().ok_or_else(service_unavailable)?;
        let id = context_id(context).map_err(app_service)?;
        let installed = self.environment(&authenticated, &id).map_err(app_service)?;
        let expected = self
            .read_principal(&authenticated, &id)
            .map_err(app_service)?;
        if access.read_principal.principal_id != expected.principal_id
            || access.read_principal.permission_scope_digest != expected.permission_scope_digest
            || *context != installed.registration.context
        {
            return Err(service_forbidden());
        }
        let call = CatalogCall {
            sources: self.clone(),
            authenticated,
            budget: actual_budget,
            installed,
            read_principal: expected,
            native_checkpoint: None,
        };
        call.fresh().map_err(app_service)?;
        Ok(Box::new(CatalogAccess(call, false)))
    }

    /// FN24 resolves its dataSnapshotId through this actual retained capture
    /// receipt. A caller's DataSnapshot/schema/digest does not create a receipt.
    pub fn authorize_exchange_snapshot(
        &self,
        slot: &RequestContextSlot,
        context: &Value,
        id: &SnapshotId,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        let (authenticated, actual_budget) = slot.current().map_err(service_app)?;
        if actual_budget.deadline() != budget.deadline()
            || !authenticated.permits("exchange.prepare")
        {
            return Err(forbidden());
        }
        self.authorize_retained_snapshot(&authenticated, &actual_budget, context, id, store)
    }

    fn authorize_retained_snapshot(
        &self,
        authenticated: &AuthenticatedPrincipal,
        budget: &RequestBudget,
        context: &Value,
        id: &SnapshotId,
        store: &DurableStore,
    ) -> AppResult<()> {
        let context_id = context_id(context)?;
        let installed = self.environment(authenticated, &context_id)?;
        if installed.registration.context != *context {
            return Err(forbidden());
        }
        let call = CatalogCall {
            sources: self.clone(),
            authenticated: authenticated.clone(),
            budget: budget.clone(),
            read_principal: self.read_principal(authenticated, &context_id)?,
            installed,
            native_checkpoint: None,
        };
        call.fresh()?;
        let receipt = self
            .state
            .try_borrow()
            .map_err(|_| busy())?
            .captures
            .get(id)
            .cloned()
            .ok_or_else(forbidden)?;
        self.verify_capture_manifest(&call, id, &receipt, store)?;
        Ok(())
    }

    /// The feature facade invokes this only after its owning Catalog.capture
    /// succeeded. The actual Catalog pin, not the supplied JSON alone, proves
    /// insertion. A stopped call can finalize only already acquired evidence
    /// under pure current ACL checks; it performs no new host/source/CAS read.
    pub fn complete_capture(
        &self,
        slot: &RequestContextSlot,
        access: &FeatureAccess,
        snapshot: &Value,
        catalog: &Catalog,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        let (authenticated, actual_budget) = if budget.check().is_err() {
            slot.current_retained()
        } else {
            slot.current()
        }
        .map_err(service_app)?;
        if actual_budget.deadline() != budget.deadline()
            || !authenticated.permits("catalog.capture")
        {
            return Err(forbidden());
        }
        let context = access.context.as_ref().ok_or_else(forbidden)?;
        let installed = self.environment(&authenticated, &context_id(context)?)?;
        let expected = self.read_principal(&authenticated, &context_id(context)?)?;
        if *context != installed.registration.context
            || access.read_principal.principal_id != expected.principal_id
            || access.read_principal.permission_scope_digest != expected.permission_scope_digest
        {
            return Err(forbidden());
        }
        self.complete_capture_call(
            &CatalogCall {
                sources: self.clone(),
                authenticated,
                budget: actual_budget,
                installed,
                read_principal: expected,
                native_checkpoint: None,
            },
            snapshot,
            catalog,
            store,
        )
    }
    fn complete_capture_call(
        &self,
        call: &CatalogCall,
        snapshot: &Value,
        catalog: &Catalog,
        store: &DurableStore,
    ) -> AppResult<()> {
        let stopped = call.budget.check().is_err();
        if stopped {
            call.local()?;
        } else {
            call.fresh()?;
        }
        let id = SnapshotId::new(text(snapshot, "snapshotId")?).map_err(|_| forbidden())?;
        let receipt = self
            .state
            .try_borrow()
            .map_err(|_| busy())?
            .pending_captures
            .get(&id)
            .cloned()
            .ok_or_else(forbidden)?;
        let pin = catalog
            .snapshot_pin(
                &id,
                &call.read_principal,
                &CatalogAccess(call.clone(), true),
            )
            .map_err(|_| forbidden())?;
        if pin.snapshot != *snapshot
            || canonical_digest(snapshot).map_err(digest_app)? != receipt.snapshot_digest
        {
            return Err(forbidden());
        }
        if stopped {
            if receipt.retained_manifest.is_null()
                || receipt.context != context_id(&call.installed.registration.context)?
                || receipt.binding_revision != call.installed.revision
                || receipt.context_digest != call.installed.registration.context["contextDigest"]
            {
                return Err(forbidden());
            }
            for source in snapshot["sources"].as_array().ok_or_else(forbidden)? {
                call.source(source)?;
            }
            for source in &receipt.source_resources {
                let current = call.source(&source.source)?;
                if current.approved.rights_witness != source.rights_witness {
                    return Err(forbidden());
                }
            }
            call.local()?;
        } else {
            self.verify_capture_manifest(call, &id, &receipt, store)?;
            call.fresh()?;
        }
        let mut state = self.state.try_borrow_mut().map_err(|_| busy())?;
        if state.captures.contains_key(&id)
            || state.pending_captures.get(&id).is_none_or(|pending| {
                pending.snapshot_digest != receipt.snapshot_digest
                    || pending.binding_revision != receipt.binding_revision
            })
        {
            return Err(forbidden());
        }
        state.pending_captures.remove(&id);
        state.captures.insert(id, receipt);
        Ok(())
    }

    fn verify_capture_manifest(
        &self,
        call: &CatalogCall,
        id: &SnapshotId,
        receipt: &CaptureAuthorityReceipt,
        store: &DurableStore,
    ) -> AppResult<Value> {
        let context = &call.installed.registration.context;
        let context_id = context_id(context)?;
        let authenticated = &call.authenticated;
        if receipt.context != context_id
            || receipt.binding_revision != call.installed.revision
            || receipt.context_digest != context["contextDigest"]
        {
            return Err(forbidden());
        }
        for source in call.installed.sources.values() {
            call.source(&source.approved.source)?;
        }
        let rpc = call.rpc()?;
        let project = current_project(store, &rpc, &call.installed.project)?;
        let current_revision = digest_field(&project, "revision")?;
        let resource_id = ResourceId::new(text(&receipt.retained_manifest, "resourceId")?)
            .map_err(|_| forbidden())?;
        // Only this module's exact actual capture issuance is exempt from the
        // original input-resource ID list. The ordinary public artifact reader
        // receives no grant for newly generated capture evidence IDs.
        let mut reader = ProjectResourceReader::new(
            Box::new(CaptureManifestAuthority {
                rpc: rpc.clone(),
                resource: receipt.retained_manifest.clone(),
            }),
            MAX_DOCUMENT_BYTES,
        )
        .map_err(|e| rpc.storage_error(e))?;
        let query = ProjectResourceQuery::RegisteredImmutable { resource_id };
        let read = reader
            .read(
                store,
                &rpc,
                &ProjectResourceRequest {
                    project: &call.installed.project,
                    current_project_revision: &current_revision,
                    query: &query,
                    expected: Some(&receipt.retained_manifest),
                },
                MAX_DOCUMENT_BYTES,
            )
            .map_err(|e| rpc.storage_error(e))?;
        let manifest = parse_controlled(&read.bytes, &call.budget)?;
        if manifest["format"] != "mmmm.catalog-capture-evidence/1"
            || manifest["principal"] != authenticated.principal().as_str()
            || manifest["project"] != call.installed.project.as_str()
            || manifest["sourceBindingRevision"] != call.installed.revision.as_str()
            || manifest["snapshot"]["snapshotId"] != id.as_str()
            || manifest["identity"]["queryContextDigest"] != context["contextDigest"]
            || manifest["snapshot"]["environment"] != context["environment"]
            || !scope_contains(&context["scope"], &manifest["retainedScope"])
        {
            return Err(forbidden());
        }
        if canonical_digest(&manifest["snapshot"]).map_err(digest_app)? != receipt.snapshot_digest
            || manifest["sourceEvidence"]
                != json!(
                    receipt
                        .source_resources
                        .iter()
                        .map(source_receipt_value)
                        .collect::<Vec<_>>()
                )
        {
            return Err(forbidden());
        }
        validate("DataSnapshot", &manifest["snapshot"])?;
        for source in manifest["snapshot"]["sources"]
            .as_array()
            .ok_or_else(forbidden)?
        {
            call.source(source)?;
        }
        call.fresh()?;
        Ok(manifest)
    }

    /// Decorates ordinary FN31 authority only for exact completed-capture
    /// resources. Unknown resources still use the supplied current authority.
    pub fn resource_authority(
        &self,
        slot: RequestContextSlot,
        fallback: LocalAuthority,
    ) -> Box<dyn ResourceAuthority> {
        Box::new(CatalogResourceAuthority {
            sources: self.clone(),
            slot,
            fallback,
        })
    }

    /// Feature ResourcePort uses the same retained relation as FN31. None means
    /// this module never issued that ID, so its ordinary reader may resolve it.
    /// Pending/stale/tampered issued IDs fail rather than falling through.
    pub fn read_catalog_resource(
        &self,
        slot: &RequestContextSlot,
        context: &Value,
        resource: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
        max_bytes: u64,
    ) -> AppResult<Option<CatalogResourceBytes>> {
        let (authenticated, actual_budget) = slot.current().map_err(service_app)?;
        if actual_budget.deadline() != budget.deadline() {
            return Err(forbidden());
        }
        let Some((call, receipt)) = self.authorize_generated_resource(
            &authenticated,
            &actual_budget,
            context,
            resource,
            store,
        )?
        else {
            return Ok(None);
        };
        let rpc = call.rpc()?;
        let bytes = read_issued_resource(
            store,
            &rpc,
            &call.installed.project,
            &receipt.resource,
            max_bytes.min(MAX_SOURCE_BYTES),
        )?;
        call.source(&receipt.source)?;
        call.fresh()?;
        Ok(Some(CatalogResourceBytes {
            bytes,
            source: receipt.source,
        }))
    }

    fn authorize_generated_resource(
        &self,
        authenticated: &AuthenticatedPrincipal,
        budget: &RequestBudget,
        context: &Value,
        resource: &Value,
        store: &DurableStore,
    ) -> AppResult<Option<(CatalogCall, CapturedResourceReceipt)>> {
        validate("ResourceRef", resource)?;
        let resource_id = text(resource, "resourceId")?;
        let known = {
            let state = self.state.try_borrow().map_err(|_| busy())?;
            state
                .captures
                .values()
                .chain(state.pending_captures.values())
                .any(|capture| {
                    capture
                        .source_resources
                        .iter()
                        .any(|r| r.resource["resourceId"].as_str() == Some(resource_id))
                })
        };
        if !known {
            return Ok(None);
        }
        let id = context_id(context)?;
        let installed = self.environment(authenticated, &id)?;
        if installed.registration.context != *context {
            return Err(forbidden());
        }
        let candidate = {
            let state = self.state.try_borrow().map_err(|_| busy())?;
            state
                .captures
                .iter()
                .find_map(|(snapshot_id, capture)| {
                    if capture.context != id
                        || capture.binding_revision != installed.revision
                        || capture.context_digest != context["contextDigest"]
                    {
                        return None;
                    }
                    capture
                        .source_resources
                        .iter()
                        .find(|r| r.resource == *resource)
                        .map(|r| (snapshot_id.clone(), capture.clone(), r.clone()))
                })
                .ok_or_else(forbidden)?
        };
        let (snapshot_id, capture, receipt) = candidate;
        let call = CatalogCall {
            sources: self.clone(),
            authenticated: authenticated.clone(),
            budget: budget.clone(),
            installed,
            read_principal: self.read_principal(authenticated, &id)?,
            native_checkpoint: None,
        };
        call.fresh()?;
        self.verify_capture_manifest(&call, &snapshot_id, &capture, store)?;
        let source = call.source(&receipt.source)?;
        if source.approved.rights_witness != receipt.rights_witness {
            return Err(forbidden());
        }
        let rpc = call.rpc()?;
        let bytes = read_issued_resource(
            store,
            &rpc,
            &call.installed.project,
            &receipt.source_manifest,
            MAX_DOCUMENT_BYTES,
        )?;
        let evidence = parse_controlled(&bytes, budget)?;
        if evidence["format"] != "mmmm.catalog-source-evidence/1"
            || evidence["principal"] != authenticated.principal().as_str()
            || evidence["project"] != call.installed.project.as_str()
            || evidence["snapshotId"] != snapshot_id.as_str()
            || evidence["sourceBindingRevision"] != call.installed.revision.as_str()
            || evidence["contextDigest"] != context["contextDigest"]
            || evidence["retainedScope"] != context["scope"]
            || evidence["source"] != receipt.source
            || evidence["resource"] != receipt.resource
            || evidence["rightsWitness"] != receipt.rights_witness.as_str()
            || evidence["backing"] != backing_identity(&source.backing)
            || receipt.source["sha256"] != resource["sha256"]
        {
            return Err(forbidden());
        }
        call.fresh()?;
        Ok(Some((call, receipt)))
    }

    fn environment(
        &self,
        authenticated: &AuthenticatedPrincipal,
        id: &ContextId,
    ) -> AppResult<InstalledEnvironment> {
        if !authenticated.is_current() || !authenticated.permits_context(id.as_str()) {
            return Err(forbidden());
        }
        self.state
            .try_borrow()
            .map_err(|_| busy())?
            .environments
            .get(&(authenticated.principal().clone(), id.clone()))
            .cloned()
            .ok_or_else(|| {
                error(
                    "SOURCE_UNAVAILABLE",
                    "No authenticated catalog source binding is installed",
                )
            })
    }
    fn planning_access(
        &self,
        authenticated: AuthenticatedPrincipal,
        budget: RequestBudget,
    ) -> AppResult<LocalPlanningAccess> {
        LocalPlanningAccess::new(
            authenticated,
            self.authority.clone(),
            self.hosts.clone(),
            budget,
            self.contexts.clone(),
        )
    }
}

#[derive(Clone)]
struct CatalogCall {
    sources: RegisteredCatalogSources,
    authenticated: AuthenticatedPrincipal,
    budget: RequestBudget,
    installed: InstalledEnvironment,
    read_principal: ReadPrincipal,
    native_checkpoint: Option<Rc<dyn NativeCatalogCheckpoint>>,
}
impl CatalogCall {
    fn check_native_source(&self, store: &PlanningStore<'_>) -> AppResult<()> {
        self.local()?;
        match self
            .sources
            .native_admission_state(&self.authenticated, &self.installed.registration.context)?
        {
            NativeCatalogAdmissionState::Explicit => Ok(()),
            NativeCatalogAdmissionState::Missing => Err(forbidden()),
            NativeCatalogAdmissionState::Native(_) => {
                let checkpoint = self.native_checkpoint.as_ref().ok_or_else(forbidden)?;
                // This is an immutable short Store borrow, not a transaction.
                // It ends before any host/native transport call is issued.
                store.with_read(|store| checkpoint.check(store))
            }
        }
    }
    /// Pure current ACL checks are also used after cancellation. They never
    /// restart a read or call a host. The active source binding is independent
    /// from source evidence and is checked on each hit/read/final return.
    fn local(&self) -> AppResult<()> {
        let id = context_id(&self.installed.registration.context)?;
        if !self.authenticated.is_current() || !self.authenticated.permits_context(id.as_str()) {
            return Err(forbidden());
        }
        // This call already holds a previously approved binding. Its removal
        // withdraws authority for retained records; it is not initial source
        // discovery failing to find a backend. Keep registry busy failures
        // distinct, and never use the cached binding after current removal.
        let current = self
            .sources
            .state
            .try_borrow()
            .map_err(|_| busy())?
            .environments
            .get(&(self.authenticated.principal().clone(), id.clone()))
            .cloned()
            .ok_or_else(forbidden)?;
        if current.revision != self.installed.revision
            || current.principal != self.installed.principal
        {
            return Err(forbidden());
        }
        self.sources.authority.authorize_retained_scope(
            self.authenticated.principal(),
            &self.installed.project,
            &id,
            &digest_field(&self.installed.registration.context, "policyRevision")?,
            &self.installed.registration.context["scope"],
        )
    }
    fn fresh(&self) -> AppResult<()> {
        self.budget.check().map_err(service_app)?;
        self.local()?;
        self.sources
            .planning_access(self.authenticated.clone(), self.budget.clone())?
            .authorize_project(
                self.authenticated.principal(),
                &self.installed.project,
                Some(&self.installed.registration.context),
                Access::ReadProject,
            )?;
        self.budget.check().map_err(service_app)
    }
    fn principal(&self, principal: &ReadPrincipal) -> Result<(), CatalogError> {
        if principal.principal_id != self.read_principal.principal_id
            || principal.permission_scope_digest != self.read_principal.permission_scope_digest
        {
            return Err(CatalogError::PermissionRequired);
        }
        self.local().map_err(app_catalog)
    }
    fn source(&self, source: &Value) -> AppResult<InstalledSource> {
        self.local()?;
        validate("SourceRef", source)?;
        let id = source_id(source)?;
        let approved = self
            .installed
            .sources
            .get(&id)
            .cloned()
            .ok_or_else(forbidden)?;
        for key in ["sourceId", "kind", "locator", "rights"] {
            if source[key] != approved.approved.source[key] {
                return Err(forbidden());
            }
        }
        if !source["sha256"].is_null()
            && !approved.approved.source["sha256"].is_null()
            && source["sha256"] != approved.approved.source["sha256"]
        {
            return Err(error(
                "SOURCE_CONFLICT",
                "Actual source hash differs from installed registration",
            ));
        }
        match &approved.backing {
            CatalogSourceBacking::ProjectResource(resource) => {
                self.source_scope("resourceIds", text(&resource.resource, "resourceId")?)?
            }
            CatalogSourceBacking::ArchiveMember { archive, .. } => {
                self.source_scope("resourceIds", text(&archive.resource, "resourceId")?)?
            }
            CatalogSourceBacking::OwnedDocument(pin) => {
                self.source_scope("objectIds", pin.object_id.as_str())?
            }
            CatalogSourceBacking::NativeRegistry => {}
        }
        Ok(approved)
    }
    fn source_scope(&self, kind: &str, id: &str) -> AppResult<()> {
        let scope = self
            .sources
            .authority
            .project_scope(self.authenticated.principal(), &self.installed.project)?;
        if !scope[kind]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|value| value.as_str() == Some(id)))
            || !self.installed.registration.context["scope"][kind]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|value| value.as_str() == Some(id)))
        {
            return Err(forbidden());
        }
        Ok(())
    }
    fn rpc(&self) -> AppResult<CatalogRpc> {
        CatalogRpc::new(
            self.authenticated.clone(),
            self.budget.clone(),
            self.sources.authority.clone(),
            &self.installed.registration.context,
        )
    }
}

struct CatalogAccess(CatalogCall, bool);
impl AccessControl for CatalogAccess {
    fn authorize_snapshot(
        &self,
        principal: &ReadPrincipal,
        snapshot: &Value,
    ) -> Result<(), CatalogError> {
        self.0.principal(principal)?;
        if !(self.0.authenticated.permits("catalog.capture")
            || self.0.authenticated.permits("catalog.search")
            || self.0.authenticated.permits("catalog.describe"))
        {
            return Err(CatalogError::PermissionRequired);
        }
        let id = SnapshotId::new(
            snapshot["snapshotId"]
                .as_str()
                .ok_or(CatalogError::PermissionRequired)?,
        )
        .map_err(|_| CatalogError::PermissionRequired)?;
        let receipt = {
            let state = self.0.sources.state.try_borrow().map_err(|_| {
                CatalogError::SourceUnavailable("Catalog registry is in use".into())
            })?;
            state
                .captures
                .get(&id)
                .or_else(|| self.1.then(|| state.pending_captures.get(&id)).flatten())
                .cloned()
                .ok_or(CatalogError::PermissionRequired)?
        };
        if receipt.context
            != context_id(&self.0.installed.registration.context).map_err(app_catalog)?
            || receipt.binding_revision != self.0.installed.revision
            || receipt.context_digest != self.0.installed.registration.context["contextDigest"]
            || receipt.retained_manifest.is_null()
            || canonical_digest(snapshot).map_err(|_| CatalogError::PermissionRequired)?
                != receipt.snapshot_digest
            || snapshot["environment"] != self.0.installed.registration.context["environment"]
        {
            return Err(CatalogError::PermissionRequired);
        }
        for source in snapshot["sources"]
            .as_array()
            .ok_or(CatalogError::PermissionRequired)?
        {
            self.authorize_source(principal, source)?;
        }
        Ok(())
    }
    fn can_read_record(
        &self,
        principal: &ReadPrincipal,
        snapshot: &Value,
        record: &Value,
        context: Option<&ContextId>,
    ) -> bool {
        if self.authorize_snapshot(principal, snapshot).is_err()
            || context.is_some_and(|id| {
                Some(id.as_str()) != self.0.installed.registration.context["contextId"].as_str()
            })
            || record["scopeDigest"] != self.0.installed.registration.context["contextDigest"]
        {
            return false;
        }
        record["sources"].as_array().is_some_and(|sources| {
            sources
                .iter()
                .all(|s| self.authorize_source(principal, s).is_ok())
        })
    }
    fn authorize_capture(
        &self,
        principal: &ReadPrincipal,
        request: &Value,
    ) -> Result<(), CatalogError> {
        self.0.principal(principal)?;
        if !self.0.authenticated.permits("catalog.capture")
            || request["contextId"] != self.0.installed.registration.context["contextId"]
            || request["environment"] != self.0.installed.registration.context["environment"]
        {
            return Err(CatalogError::PermissionRequired);
        }
        self.0.fresh().map_err(app_catalog)
    }
    fn authorize_source(
        &self,
        principal: &ReadPrincipal,
        source: &Value,
    ) -> Result<(), CatalogError> {
        self.0.principal(principal)?;
        self.0.source(source).map(|_| ()).map_err(app_catalog)
    }
}

struct CaptureAttempt {
    grant: CaptureGrant,
    project_revision: Sha256Digest,
    source_facts: Option<Value>,
}
pub struct BorrowedCatalogBackend<'a> {
    store: PlanningStore<'a>,
    call: CatalogCall,
    attempt: Option<CaptureAttempt>,
    retained_sources: Vec<CapturedResourceReceipt>,
}
impl CatalogCaptureBackend for BorrowedCatalogBackend<'_> {
    fn resolve_capture(
        &mut self,
        principal: &ReadPrincipal,
        request: &Value,
        control: &CaptureControl<'_>,
        budget: &CaptureBudget,
    ) -> Result<CaptureGrant, CatalogError> {
        self.call.principal(principal)?;
        stopped(control)?;
        self.call.fresh().map_err(app_catalog)?;
        if self.attempt.is_some() {
            return Err(CatalogError::SourceUnavailable(
                "A capture backend cannot be reused across attempts".into(),
            ));
        }
        let rpc = self.call.rpc().map_err(app_catalog)?;
        let project = self
            .store
            .with_read(|store| current_project(store, &rpc, &self.call.installed.project))
            .map_err(app_catalog)?;
        let project_revision = digest_field(&project, "revision").map_err(app_catalog)?;
        if self.call.installed.sources.len() > budget.max_sources {
            return Err(CatalogError::InputLimit);
        }
        let registration = &self.call.installed.registration;
        let mut grant = CaptureGrant {
            execution_context: registration.context.clone(),
            snapshot_id: allocate_snapshot()?,
            game_version: registration.game_version.clone(),
            locale: registration.locale.clone(),
            created_at: now().map_err(app_catalog)?,
            artifact_source: registration.artifact_source.clone(),
            server_pack_sources: registration.server_pack_sources.clone(),
            client_pack_sources: registration.client_pack_sources.clone(),
            mod_sources: registration.mod_sources.clone(),
            registry_generation: registration.registry_generation.clone(),
            sources: self
                .call
                .installed
                .sources
                .values()
                .map(|s| s.approved.clone())
                .collect(),
        };
        let source_facts = if registration.context["environment"]["kind"] == "game" {
            // A registered, currently authorized native source is mandatory
            // before any registry/source-facts host read.
            let native = grant
                .sources
                .iter()
                .find(|s| matches!(s.codec, CatalogSourceCodec::NativeRegistry))
                .ok_or_else(|| {
                    CatalogError::SourceUnavailable(
                        "No actual native registry source is approved".into(),
                    )
                })?;
            self.call.source(&native.source).map_err(app_catalog)?;
            let facts = host_inspection(&self.store, &self.call, "runtime_sources", control)?;
            validate_source_facts(&facts, &registration.context).map_err(app_catalog)?;
            apply_actual_source_identity(&mut grant, &self.call.installed, &facts)
                .map_err(app_catalog)?;
            Some(facts)
        } else {
            None
        };
        if request["contextId"] != grant.execution_context["contextId"] {
            return Err(CatalogError::PermissionRequired);
        }
        self.attempt = Some(CaptureAttempt {
            grant: grant.clone(),
            project_revision,
            source_facts,
        });
        Ok(grant)
    }
    fn revalidate_capture(
        &mut self,
        principal: &ReadPrincipal,
        _request: &Value,
        grant: &CaptureGrant,
        observed: Option<&RegistryCaptureWitness>,
        interrupted: bool,
        control: &CaptureControl<'_>,
    ) -> Result<(), CatalogError> {
        self.call.principal(principal)?;
        let attempt = self.attempt.as_ref().ok_or_else(|| {
            CatalogError::SourceUnavailable("No capture source attempt exists".into())
        })?;
        if attempt.grant.snapshot_id != grant.snapshot_id
            || attempt.grant.execution_context != grant.execution_context
        {
            return Err(CatalogError::PermissionRequired);
        }
        for source in &grant.sources {
            self.call.source(&source.source).map_err(app_catalog)?;
        }
        if !interrupted {
            stopped(control)?;
            self.call.fresh().map_err(app_catalog)?;
            let rpc = self.call.rpc().map_err(app_catalog)?;
            let current = self
                .store
                .with_read(|store| current_project(store, &rpc, &self.call.installed.project))
                .map_err(app_catalog)?;
            if digest_field(&current, "revision").map_err(app_catalog)? != attempt.project_revision
            {
                return Err(CatalogError::SourceUnavailable(
                    "Current Project changed during source capture".into(),
                ));
            }
            if let Some(original) = &attempt.source_facts {
                let current = host_inspection(&self.store, &self.call, "runtime_sources", control)?;
                validate_source_facts(&current, &grant.execution_context).map_err(app_catalog)?;
                if source_facts_pin(original).map_err(app_catalog)?
                    != source_facts_pin(&current).map_err(app_catalog)?
                    || observed
                        .is_none_or(|w| current["registryGeneration"] != w.registry_generation)
                {
                    return Err(CatalogError::SourceUnavailable(
                        "Actual archive, pack or registry observation changed during capture"
                            .into(),
                    ));
                }
            }
            stopped(control)?;
        } else {
            // No request budget, host or content read here. The authentic
            // session and current complete Project/source scope remain required.
            self.call.local().map_err(app_catalog)?;
        }
        Ok(())
    }
    fn read_approved_source(
        &mut self,
        principal: &ReadPrincipal,
        grant: &CaptureGrant,
        approved: &ApprovedCatalogSource,
        max_bytes: usize,
        control: &CaptureControl<'_>,
    ) -> Result<CapturedSourceBytes, CatalogError> {
        self.call.principal(principal)?;
        stopped(control)?;
        self.call.fresh().map_err(app_catalog)?;
        let installed = self.call.source(&approved.source).map_err(app_catalog)?;
        if installed.approved.rights_witness != approved.rights_witness {
            return Err(CatalogError::PermissionRequired);
        }
        let attempt = self.attempt.as_ref().ok_or_else(|| {
            CatalogError::SourceUnavailable("Source capture has no resolved binding".into())
        })?;
        if attempt.grant.snapshot_id != grant.snapshot_id || max_bytes == 0 {
            return Err(CatalogError::InputLimit);
        }
        let rpc = self.call.rpc().map_err(app_catalog)?;
        let bytes = match &installed.backing {
            CatalogSourceBacking::ProjectResource(resource) => {
                let bytes = self
                    .store
                    .with_read(|store| {
                        read_resource(
                            store,
                            &rpc,
                            &self.call.installed.project,
                            &attempt.project_revision,
                            resource,
                            (max_bytes as u64).min(MAX_SOURCE_BYTES),
                        )
                    })
                    .map_err(app_catalog)?;
                if matches!(
                    approved.role,
                    CatalogSourceRole::GameArtifact
                        | CatalogSourceRole::ServerPack
                        | CatalogSourceRole::ClientPack
                        | CatalogSourceRole::Mod(_)
                ) {
                    archive_type(&resource.resource).map_err(app_catalog)?;
                    archive_header(&bytes)?;
                }
                bytes
            }
            CatalogSourceBacking::ArchiveMember {
                archive,
                member,
                member_sha256,
                member_bytes,
                limits,
            } => {
                if *member_bytes > max_bytes as u64 {
                    return Err(CatalogError::InputLimit);
                }
                let raw = self
                    .store
                    .with_read(|store| {
                        read_resource(
                            store,
                            &rpc,
                            &self.call.installed.project,
                            &attempt.project_revision,
                            archive,
                            limits.max_archive_bytes.min(MAX_SOURCE_BYTES),
                        )
                    })
                    .map_err(app_catalog)?;
                let mut contents =
                    read_zip_with_cancel(&raw, *limits, &mut || control.should_stop()).map_err(
                        |e| {
                            if e.code == "CANCELLED" {
                                CatalogError::Cancelled
                            } else {
                                CatalogError::SourceUnavailable(e.to_string())
                            }
                        },
                    )?;
                let bytes = contents.remove(member).ok_or_else(|| {
                    CatalogError::SourceUnavailable("Approved archive member is absent".into())
                })?;
                if bytes.len() as u64 != *member_bytes || raw_digest(&bytes) != *member_sha256 {
                    return Err(CatalogError::SourceUnavailable(
                        "Archive member differs from its approved exact pin".into(),
                    ));
                }
                bytes
            }
            CatalogSourceBacking::OwnedDocument(pin) => {
                let mut reader = OwnedDocumentReader::new(
                    Box::new(CatalogReadAuthority(rpc.clone())),
                    (max_bytes as u64).min(MAX_DOCUMENT_BYTES),
                )
                .map_err(storage_catalog)?;
                self.store
                    .with_read(|store| {
                        reader
                            .read_known_history_bytes(
                                store,
                                &rpc,
                                &self.call.installed.project,
                                &attempt.project_revision,
                                pin,
                            )
                            .map_err(|e| rpc.storage_error(e))
                    })
                    .map_err(app_catalog)?
                    .bytes
            }
            CatalogSourceBacking::NativeRegistry => {
                return Err(CatalogError::SourceUnavailable(
                    "Native registry uses the actual host transport".into(),
                ));
            }
        };
        self.call.fresh().map_err(app_catalog)?;
        self.call.source(&approved.source).map_err(app_catalog)?;
        stopped(control)?;
        Ok(CapturedSourceBytes {
            bytes,
            verified_at: now().map_err(app_catalog)?,
            rights_witness: installed.approved.rights_witness,
        })
    }
    fn retain_source_evidence(
        &mut self,
        principal: &ReadPrincipal,
        grant: &CaptureGrant,
        source: &Value,
        bytes: &[u8],
        media_type: &str,
    ) -> Result<Value, CatalogError> {
        self.call.principal(principal)?;
        let installed = self.call.source(source).map_err(app_catalog)?;
        let attempt = self.attempt.as_ref().ok_or_else(|| {
            CatalogError::SourceUnavailable("Source evidence has no resolved capture".into())
        })?;
        if attempt.grant.snapshot_id != grant.snapshot_id
            || bytes.len() as u64 > MAX_SOURCE_BYTES
            || source["sha256"] != raw_digest(bytes).as_str()
        {
            return Err(CatalogError::SourceUnavailable(
                "Source evidence differs from its actual acquired bytes".into(),
            ));
        }
        let resource = retain_bytes(&self.store, &self.call.installed.project, bytes, media_type)
            .map_err(app_catalog)?;
        let manifest = json!({"format":"mmmm.catalog-source-evidence/1","principal":principal.principal_id,"project":self.call.installed.project,
            "source":source,"rightsWitness":installed.approved.rights_witness,"sourceBindingRevision":self.call.installed.revision,"backing":backing_identity(&installed.backing),
            "contextDigest":grant.execution_context["contextDigest"],"retainedScope":grant.execution_context["scope"],"snapshotId":grant.snapshot_id,"resource":resource});
        let source_manifest = retain_json(
            &self.store,
            &self.call.installed.project,
            &manifest,
            SOURCE_EVIDENCE_MEDIA,
        )
        .map_err(app_catalog)?;
        self.call.local().map_err(app_catalog)?;
        if self.retained_sources.len() >= MAX_SOURCES {
            return Err(CatalogError::InputLimit);
        }
        self.retained_sources.push(CapturedResourceReceipt {
            resource: resource.clone(),
            source_manifest,
            source: source.clone(),
            rights_witness: installed.approved.rights_witness,
        });
        Ok(resource)
    }
}

pub struct PairedCatalogRegistry<'a> {
    store: PlanningStore<'a>,
    call: CatalogCall,
}
impl HostRegistryTransport for PairedCatalogRegistry<'_> {
    fn inspect_registry(
        &mut self,
        context: &Value,
        control: &CaptureControl<'_>,
        max_raw_bytes: usize,
    ) -> Result<Value, CatalogError> {
        stopped(control)?;
        if *context != self.call.installed.registration.context
            || max_raw_bytes > MAX_NATIVE_REGISTRY_BYTES
        {
            return Err(CatalogError::PermissionRequired);
        }
        let native = self
            .call
            .installed
            .sources
            .values()
            .find(|s| matches!(s.backing, CatalogSourceBacking::NativeRegistry))
            .ok_or_else(|| {
                CatalogError::SourceUnavailable("No native registry source is approved".into())
            })?;
        self.call
            .source(&native.approved.source)
            .map_err(app_catalog)?;
        let payload = host_inspection(&self.store, &self.call, "native_registry", control)?;
        if payload.as_object().is_none_or(|o| o.len() != 10)
            || payload["observationBytesHex"]
                .as_str()
                .is_none_or(|s| s.len() > max_raw_bytes.saturating_mul(2))
        {
            return Err(CatalogError::InputLimit);
        }
        Ok(payload)
    }
}

struct RetainedCatalogCapture<'a> {
    inner: VerifiedSnapshotSource<PairedCatalogRegistry<'a>, BorrowedCatalogBackend<'a>>,
    store: PlanningStore<'a>,
    call: CatalogCall,
}
impl SnapshotSource for RetainedCatalogCapture<'_> {
    fn capture(
        &mut self,
        request: &Value,
        control: &CaptureControl<'_>,
        budget: &CaptureBudget,
        access: &CaptureSourceAccess<'_>,
    ) -> Result<CaptureResult, CatalogError> {
        let result = self.inner.capture(request, control, budget, access)?;
        self.call.local().map_err(app_catalog)?;
        prevalidate_capture(&result, request, control, budget)?;
        let source_resources = self.inner.backend.retained_sources.clone();
        let records=result.snapshot.records.iter().map(|entry|json!({"record":entry.record,"terms":entry.terms,"contexts":entry.contexts})).collect::<Vec<_>>();
        let missing=result.snapshot.missing_records.iter().map(|entry|json!({"contextId":entry.context_id,"kind":entry.kind,"scopeDigest":entry.scope_digest,
            "status":entry.status,"valueType":entry.value_type,"unit":entry.unit,"sources":entry.sources,"provenance":entry.provenance,"coverage":entry.coverage,"reason":entry.reason})).collect::<Vec<_>>();
        let manifest = json!({"format":"mmmm.catalog-capture-evidence/1","principal":self.call.authenticated.principal(),"project":self.call.installed.project,
            "sourceBindingRevision":self.call.installed.revision,"retainedScope":self.call.installed.registration.context["scope"],"snapshot":result.snapshot.snapshot,
            "identity":result.snapshot.identity,"records":records,"missingRecords":missing,"interrupted":result.interrupted,
            "sourceEvidence":source_resources.iter().map(source_receipt_value).collect::<Vec<_>>()});
        let bytes = encode_json(&manifest).map_err(|_| CatalogError::InputLimit)?;
        if bytes.len() > budget.max_snapshot_bytes {
            return Err(CatalogError::InputLimit);
        }
        let retained = retain_bytes(
            &self.store,
            &self.call.installed.project,
            &bytes,
            CAPTURE_EVIDENCE_MEDIA,
        )
        .map_err(app_catalog)?;
        self.call.local().map_err(app_catalog)?;
        let id = SnapshotId::new(
            result.snapshot.snapshot["snapshotId"]
                .as_str()
                .ok_or(CatalogError::PermissionRequired)?,
        )
        .map_err(|_| CatalogError::PermissionRequired)?;
        let mut state =
            self.call.sources.state.try_borrow_mut().map_err(|_| {
                CatalogError::SourceUnavailable("Catalog registry is in use".into())
            })?;
        let retained_count = state
            .captures
            .values()
            .chain(state.pending_captures.values())
            .try_fold(source_resources.len(), |sum, capture| {
                sum.checked_add(capture.source_resources.len())
            })
            .ok_or(CatalogError::InputLimit)?;
        if state.captures.len() + state.pending_captures.len() >= MAX_CAPTURE_RECEIPTS
            || state.captures.contains_key(&id)
            || state.pending_captures.contains_key(&id)
            || retained_count > MAX_CAPTURED_RESOURCES
        {
            return Err(CatalogError::InputLimit);
        }
        state.pending_captures.insert(
            id,
            CaptureAuthorityReceipt {
                context: context_id(&self.call.installed.registration.context)
                    .map_err(app_catalog)?,
                binding_revision: self.call.installed.revision.clone(),
                context_digest: self.call.installed.registration.context["contextDigest"].clone(),
                retained_manifest: retained,
                source_resources,
                snapshot_digest: canonical_digest(&result.snapshot.snapshot)
                    .map_err(|_| CatalogError::InputLimit)?,
            },
        );
        Ok(result)
    }
}

fn host_inspection(
    store: &PlanningStore<'_>,
    call: &CatalogCall,
    selector: &str,
    control: &CaptureControl<'_>,
) -> Result<Value, CatalogError> {
    stopped(control)?;
    call.fresh().map_err(app_catalog)?;
    call.check_native_source(store).map_err(app_catalog)?;
    let output = observed_host_inspection(store, call, selector, control);
    finish_native_inspection(output, call.check_native_source(store))
}

/// Both immutable causes survive without changing the original catalog
/// classification or printing a response body or native ownership details.
pub(crate) struct NativeCatalogInspectionFailure {
    pub(crate) primary: Arc<CatalogError>,
    pub(crate) checkpoint: AppError,
}
impl std::fmt::Debug for NativeCatalogInspectionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeCatalogInspectionFailure")
            .field("primary_code", &self.primary.code())
            .field("checkpoint_code", &self.checkpoint.code)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for NativeCatalogInspectionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Native catalog inspection and current source checkpoint both failed")
    }
}
impl std::error::Error for NativeCatalogInspectionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.primary.as_ref())
    }
}
fn finish_native_inspection<T>(
    output: Result<T, CatalogError>,
    checkpoint: AppResult<()>,
) -> Result<T, CatalogError> {
    match (output, checkpoint) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cause)) => Err(app_catalog(cause)),
        (Err(primary), Err(checkpoint)) => {
            let primary = Arc::new(primary);
            Err(CatalogError::Causal {
                primary: primary.clone(),
                source: Box::new(NativeCatalogInspectionFailure {
                    primary,
                    checkpoint,
                }),
            })
        }
    }
}

fn observed_host_inspection(
    store: &PlanningStore<'_>,
    call: &CatalogCall,
    selector: &str,
    control: &CaptureControl<'_>,
) -> Result<Value, CatalogError> {
    let id = context_id(&call.installed.registration.context).map_err(app_catalog)?;
    let response = call
        .sources
        .hosts
        .inspect_response_with_deadline(
            call.authenticated.principal(),
            &id,
            json!({"kind":selector}),
            control.deadline.min(call.budget.deadline()),
        )
        .map_err(app_catalog)?;
    // Retain the complete validated original HostResponse before mapping an
    // error. Host-specific code/message/retryability/data remain in private CAS.
    let evidence = json!({"format":"mmmm.host-inspection-evidence/1","principal":call.authenticated.principal(),"project":call.installed.project,
        "contextDigest":call.installed.registration.context["contextDigest"],"retainedScope":call.installed.registration.context["scope"],"selector":selector,"response":response});
    retain_json(
        store,
        &call.installed.project,
        &evidence,
        HOST_EVIDENCE_MEDIA,
    )
    .map_err(app_catalog)?;
    if response["status"] != "ok" {
        let code = response["error"]["code"]
            .as_str()
            .unwrap_or("HOST_REQUEST_FAILED");
        let primary = if code == "CANCELLED" {
            CatalogError::Cancelled
        } else if code == "PERMISSION_REQUIRED" {
            CatalogError::PermissionRequired
        } else {
            CatalogError::SourceUnavailable(format!(
                "Original host inspection failed: {code}; complete response retained"
            ))
        };
        return Err(CatalogError::caused_by(
            primary,
            NativeCatalogHostFailure { response },
        ));
    }
    stopped(control)?;
    response
        .get("payload")
        .cloned()
        .ok_or_else(|| CatalogError::SourceUnavailable("Host inspection payload is absent".into()))
}

pub(crate) fn validate_source_facts(facts: &Value, context: &Value) -> AppResult<()> {
    if encode_json(facts).map_err(json_app)?.len() > MAX_NATIVE_REGISTRY_BYTES {
        return Err(budget_error());
    }
    if facts["format"] != "mmmm.native.source-facts/1"
        || facts["environment"] != context["environment"]
        || facts["registryGeneration"]
            .as_str()
            .is_none_or(|s| s.is_empty() || s.len() > 256)
        || facts["archiveReceiptScope"] != "container_input_bytes"
        || facts["transformedClassBytes"] != "not_observed"
        || facts["resourceContentEnumeration"] != "not_performed"
    {
        return Err(error(
            "SOURCE_INVALID",
            "Native source receipt contract or installed environment differs",
        ));
    }
    for field in ["archives", "mods", "originalInputGameJars", "serverPacks"] {
        if facts[field]
            .as_array()
            .is_none_or(|a| a.len() > MAX_SOURCES)
        {
            return Err(error(
                "SOURCE_INVALID",
                "Native source receipt collection is absent or unbounded",
            ));
        }
    }
    if !facts["clientPacks"].is_null() {
        return Err(error(
            "SOURCE_INVALID",
            "Current native source codec has no verified client pack observation",
        ));
    }
    let mut ids = BTreeMap::new();
    for receipt in facts["archives"].as_array().unwrap() {
        let id = text(receipt, "sourceId")?;
        let hash = digest_field(receipt, "sha256")?;
        if receipt["status"] != "observed"
            || receipt["scope"] != "container_input_bytes"
            || id != format!("archive-sha256-{hash}")
            || receipt["sizeBytes"]
                .as_u64()
                .is_none_or(|n| !(4..=128 * 1024 * 1024).contains(&n))
            || ids.insert(id.to_owned(), receipt).is_some()
        {
            return Err(error(
                "SOURCE_INVALID",
                "Native archive receipt is inconsistent",
            ));
        }
    }
    for (index, pack) in facts["serverPacks"].as_array().unwrap().iter().enumerate() {
        if pack["packIndex"].as_u64() != Some(index as u64)
            || pack["packSourceCompleteness"] != "unknown"
            || pack["resourceContentObservation"] != "not_enumerated"
        {
            return Err(error(
                "SOURCE_INVALID",
                "Current native pack codec does not attest exhaustive content",
            ));
        }
    }
    Ok(())
}

fn apply_actual_source_identity(
    grant: &mut CaptureGrant,
    installed: &InstalledEnvironment,
    facts: &Value,
) -> AppResult<()> {
    grant.registry_generation = Some(text(facts, "registryGeneration")?.into());
    // Current native packs are observations of manager order/container linkage,
    // not exhaustive content fingerprints. Setup expectations cannot fill them.
    grant.server_pack_sources = None;
    grant.client_pack_sources = None;
    let original = facts["originalInputGameJars"]
        .as_array()
        .ok_or_else(forbidden)?;
    grant.artifact_source = if original.len() == 1 && original[0]["status"] == "observed" {
        installed
            .registration
            .artifact_source
            .as_ref()
            .filter(|id| {
                installed.sources.get(*id).is_some_and(|s| {
                    receipt_matches(
                        &original[0],
                        &s.approved.source,
                        &s.backing,
                        "original_game_input_container",
                    )
                })
            })
            .cloned()
    } else {
        None
    };
    let observed_mods = facts["mods"].as_array().ok_or_else(forbidden)?;
    let expected = installed.registration.mod_sources.as_ref();
    grant.mod_sources = if let Some(expected) = expected {
        if observed_mods.len() != expected.len()
            || installed.registration.native_mod_ids.len() != expected.len()
        {
            None
        } else {
            let all_match = expected.iter().all(|(mod_id, source_id)| {
                let Some(native_id) = installed.registration.native_mod_ids.get(mod_id) else {
                    return false;
                };
                let matching = observed_mods
                    .iter()
                    .filter(|m| m["modId"].as_str() == Some(native_id.as_str()))
                    .collect::<Vec<_>>();
                let Some(source) = installed.sources.get(source_id) else {
                    return false;
                };
                matching.len() == 1
                    && matching[0]["runtimeRoots"].as_array().is_some_and(|roots| {
                        roots.len() == 1
                            && receipt_matches(
                                &roots[0],
                                &source.approved.source,
                                &source.backing,
                                "container_input_bytes",
                            )
                    })
            });
            all_match.then(|| expected.clone())
        }
    } else {
        None
    };
    Ok(())
}
fn receipt_matches(
    receipt: &Value,
    source: &Value,
    backing: &CatalogSourceBacking,
    scope: &str,
) -> bool {
    let CatalogSourceBacking::ProjectResource(resource) = backing else {
        return false;
    };
    receipt["status"] == "observed"
        && receipt["scope"] == scope
        && receipt["sha256"] == source["sha256"]
        && receipt["sha256"] == resource.resource["sha256"]
        && receipt["sizeBytes"] == resource.resource["sizeBytes"]
}
/// Private source-facts observation pin shared with target resolution. Only
/// observation time is excluded; byte counts and all original report fields
/// remain identity-bearing. This is not a wire/version-profile projection.
pub(crate) fn source_facts_pin(facts: &Value) -> AppResult<Sha256Digest> {
    let mut stable = facts.clone();
    let object = stable.as_object_mut().ok_or_else(forbidden)?;
    object.remove("observedAt");
    canonical_digest(&stable).map_err(digest_app)
}

#[derive(Clone)]
pub(crate) struct CatalogRpc {
    authenticated: AuthenticatedPrincipal,
    budget: RequestBudget,
    authority: LocalAuthority,
    context_id: ContextId,
    context: Value,
    project: ProjectId,
}
impl CatalogRpc {
    pub(crate) fn storage_error(&self, error: StorageError) -> AppError {
        // Readers use StorageError for their cooperative callback. Preserve the
        // actual current budget reason without parsing diagnostic strings.
        if let Err(stopped) = self.budget.check() {
            return AppError::storage(stopped.code, error);
        }
        storage_app(error)
    }
    pub(crate) fn new(
        authenticated: AuthenticatedPrincipal,
        budget: RequestBudget,
        authority: LocalAuthority,
        context: &Value,
    ) -> AppResult<Self> {
        Ok(Self {
            authenticated,
            budget,
            authority,
            context_id: context_id(context)?,
            context: context.clone(),
            project: project_id(context)?,
        })
    }
    pub(crate) fn project_acl(
        &self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
    ) -> Result<(), StorageError> {
        self.check()?;
        if principal != self.authenticated.principal()
            || project != &self.project
            || context != Some(&self.context_id)
        {
            return Err(storage_forbidden());
        }
        self.authority
            .authorize_retained_scope(
                principal,
                project,
                &self.context_id,
                &digest_field(&self.context, "policyRevision").map_err(app_storage)?,
                &self.context["scope"],
            )
            .map_err(app_storage)
    }
    pub(crate) fn source_scope(
        &self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        kind: &str,
        id: &str,
    ) -> Result<(), StorageError> {
        self.project_acl(principal, context, project)?;
        let scope = self
            .authority
            .project_scope(principal, project)
            .map_err(app_storage)?;
        if !scope[kind]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|v| v.as_str() == Some(id)))
            || !self.context["scope"][kind]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|v| v.as_str() == Some(id)))
        {
            return Err(storage_forbidden());
        }
        self.check()
    }
}
impl ProjectSourceRpcContext for CatalogRpc {
    fn check(&self) -> Result<(), StorageError> {
        self.budget
            .check()
            .map_err(|e| app_storage(service_app(e)))?;
        if !self.authenticated.is_current()
            || !self.authenticated.permits_context(self.context_id.as_str())
        {
            return Err(storage_forbidden());
        }
        Ok(())
    }
    fn authenticated_principal(&self) -> Result<PrincipalId, StorageError> {
        self.check()?;
        Ok(self.authenticated.principal().clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        Some(&self.context_id)
    }
}
struct CatalogReadAuthority(CatalogRpc);
/// Private actual issuance can read only the exact immutable resource provided
/// from an in-memory completed/pending receipt, within the current Project
/// context grant. Persisted manifests alone never construct this authority.
struct CaptureManifestAuthority {
    rpc: CatalogRpc,
    resource: Value,
}
impl ProjectResourceAuthority for CaptureManifestAuthority {
    fn authorize_project_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        _revision: &Sha256Digest,
    ) -> Result<(), StorageError> {
        self.rpc.project_acl(principal, context, project)
    }
    fn authorize_resource_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> Result<(), StorageError> {
        self.rpc.project_acl(principal, context, project)?;
        if resource.owner != ResourceOwner::Project(project.clone())
            || resource.resource != self.resource
        {
            return Err(storage_forbidden());
        }
        self.rpc.check()
    }
}

struct CatalogResourceAuthority {
    sources: RegisteredCatalogSources,
    slot: RequestContextSlot,
    fallback: LocalAuthority,
}
impl ResourceAuthority for CatalogResourceAuthority {
    fn authorize_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: &ContextId,
        owner: &ResourceOwner,
        resource: &Value,
    ) -> ArtifactResult<()> {
        let (authenticated, budget) = self
            .slot
            .current()
            .map_err(|e| ArtifactError::new(e.code, e.message))?;
        if principal != authenticated.principal()
            || !authenticated.permits("artifact.read")
            || !authenticated.permits_context(context.as_str())
        {
            return Err(ArtifactError::forbidden());
        }
        let known = {
            let state = self.sources.state.try_borrow().map_err(|_| {
                ArtifactError::new("RESOURCE_UNAVAILABLE", "Catalog authority is in use")
            })?;
            state
                .captures
                .values()
                .chain(state.pending_captures.values())
                .any(|capture| {
                    capture
                        .source_resources
                        .iter()
                        .any(|r| r.resource["resourceId"] == resource["resourceId"])
                })
        };
        if !known {
            return self
                .fallback
                .authorize_read(store, principal, context, owner, resource);
        }
        let installed = self
            .sources
            .environment(&authenticated, context)
            .map_err(app_artifact)?;
        if *owner != ResourceOwner::Project(installed.project.clone()) {
            return Err(ArtifactError::forbidden());
        }
        self.sources
            .authorize_generated_resource(
                &authenticated,
                &budget,
                &installed.registration.context,
                resource,
                store,
            )
            .map_err(app_artifact)?
            .ok_or_else(ArtifactError::forbidden)?;
        Ok(())
    }
}

fn read_issued_resource(
    store: &DurableStore,
    rpc: &CatalogRpc,
    project: &ProjectId,
    resource: &Value,
    max_bytes: u64,
) -> AppResult<Vec<u8>> {
    let current = current_project(store, rpc, project)?;
    let revision = digest_field(&current, "revision")?;
    let query = ProjectResourceQuery::RegisteredImmutable {
        resource_id: ResourceId::new(text(resource, "resourceId")?).map_err(|_| forbidden())?,
    };
    let mut reader = ProjectResourceReader::new(
        Box::new(CaptureManifestAuthority {
            rpc: rpc.clone(),
            resource: resource.clone(),
        }),
        MAX_SOURCE_BYTES,
    )
    .map_err(|e| rpc.storage_error(e))?;
    reader
        .read(
            store,
            rpc,
            &ProjectResourceRequest {
                project,
                current_project_revision: &revision,
                query: &query,
                expected: Some(resource),
            },
            max_bytes,
        )
        .map(|read| read.bytes)
        .map_err(|e| rpc.storage_error(e))
}
impl ProjectResourceAuthority for CatalogReadAuthority {
    fn authorize_project_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        _revision: &Sha256Digest,
    ) -> Result<(), StorageError> {
        self.0.project_acl(principal, context, project)
    }
    fn authorize_resource_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> Result<(), StorageError> {
        if resource.owner != ResourceOwner::Project(project.clone()) {
            return Err(storage_forbidden());
        }
        self.0.source_scope(
            principal,
            context,
            project,
            "resourceIds",
            text(&resource.resource, "resourceId").map_err(app_storage)?,
        )
    }
}
impl OwnedDocumentAuthority for CatalogReadAuthority {
    fn authorize_read(
        &mut self,
        principal: &PrincipalId,
        context: &ContextId,
        project: &ProjectId,
        _revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> Result<(), StorageError> {
        self.0.source_scope(
            principal,
            Some(context),
            project,
            "objectIds",
            pin.object_id.as_str(),
        )
    }
    fn authorize_project_read(
        &mut self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        _revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> Result<(), StorageError> {
        self.0.source_scope(
            principal,
            context,
            project,
            "objectIds",
            pin.object_id.as_str(),
        )
    }
}

pub(crate) fn current_project(
    store: &DurableStore,
    rpc: &CatalogRpc,
    project: &ProjectId,
) -> AppResult<Value> {
    let mut reader = ProjectResourceReader::new(
        Box::new(CatalogReadAuthority(rpc.clone())),
        MAX_SOURCE_BYTES,
    )
    .map_err(|e| rpc.storage_error(e))?;
    reader
        .current_project(store, rpc, project, MAX_DOCUMENT_BYTES)
        .map_err(|e| rpc.storage_error(e))
}
fn verify_resource_metadata(
    store: &DurableStore,
    rpc: &CatalogRpc,
    project: &ProjectId,
    revision: &Sha256Digest,
    resource: &RegisteredCatalogResource,
) -> AppResult<RegisteredProjectResource> {
    validate("ResourceRef", &resource.resource)?;
    let mut reader = ProjectResourceReader::new(
        Box::new(CatalogReadAuthority(rpc.clone())),
        MAX_SOURCE_BYTES,
    )
    .map_err(|e| rpc.storage_error(e))?;
    reader
        .metadata(
            store,
            rpc,
            &ProjectResourceRequest {
                project,
                current_project_revision: revision,
                query: &resource.query,
                expected: Some(&resource.resource),
            },
        )
        .map_err(|e| rpc.storage_error(e))
}
fn read_resource(
    store: &DurableStore,
    rpc: &CatalogRpc,
    project: &ProjectId,
    revision: &Sha256Digest,
    resource: &RegisteredCatalogResource,
    max_bytes: u64,
) -> AppResult<Vec<u8>> {
    let mut reader = ProjectResourceReader::new(
        Box::new(CatalogReadAuthority(rpc.clone())),
        MAX_SOURCE_BYTES,
    )
    .map_err(|e| rpc.storage_error(e))?;
    reader
        .read(
            store,
            rpc,
            &ProjectResourceRequest {
                project,
                current_project_revision: revision,
                query: &resource.query,
                expected: Some(&resource.resource),
            },
            max_bytes,
        )
        .map(|read| read.bytes)
        .map_err(|e| rpc.storage_error(e))
}
fn retain_bytes(
    store: &PlanningStore<'_>,
    project: &ProjectId,
    bytes: &[u8],
    media_type: &str,
) -> AppResult<Value> {
    if bytes.len() as u64 > MAX_SOURCE_BYTES || media_type.is_empty() || media_type.len() > 256 {
        return Err(budget_error());
    }
    let digest = raw_digest(bytes);
    let identity = canonical_digest(
        &json!({"project":project,"sha256":digest,"sizeBytes":bytes.len(),"mediaType":media_type}),
    )
    .map_err(digest_app)?;
    let resource = json!({"resourceId":format!("catalog-evidence-{identity}"),"sha256":digest,"sizeBytes":bytes.len(),"mediaType":media_type});
    store.with_write(|store| {
        let blob = store.put_blob(bytes).map_err(storage_app)?;
        if blob.digest != digest || blob.byte_length != bytes.len() as u64 {
            return Err(error("SOURCE_CORRUPT", "Retained bytes changed"));
        }
        register_resource(store, &resource, ResourceOwner::Project(project.clone()))
            .map_err(|e| error(e.code, e.message))?;
        Ok(())
    })?;
    Ok(resource)
}
fn retain_json(
    store: &PlanningStore<'_>,
    project: &ProjectId,
    value: &Value,
    media_type: &str,
) -> AppResult<Value> {
    retain_bytes(
        store,
        project,
        &encode_json(value).map_err(json_app)?,
        media_type,
    )
}

fn backing_identity(backing: &CatalogSourceBacking) -> Value {
    match backing {
        CatalogSourceBacking::ProjectResource(r) => {
            json!({"kind":"project_resource","resource":r.resource,"query":query_identity(&r.query)})
        }
        CatalogSourceBacking::ArchiveMember {
            archive,
            member,
            member_sha256,
            member_bytes,
            limits,
        } => {
            json!({"kind":"archive_member","archive":archive.resource,"query":query_identity(&archive.query),"member":member,"sha256":member_sha256,"sizeBytes":member_bytes,
            "limits":{"archiveBytes":limits.max_archive_bytes,"memberBytes":limits.max_member_bytes,"totalBytes":limits.max_total_bytes,"members":limits.max_members,"ratio":limits.max_ratio,"pathBytes":limits.max_path_bytes}})
        }
        CatalogSourceBacking::OwnedDocument(pin) => json!({"kind":"owned_document","pin":pin}),
        CatalogSourceBacking::NativeRegistry => json!({"kind":"native_registry"}),
    }
}
fn query_identity(query: &ProjectResourceQuery) -> Value {
    match query {
        ProjectResourceQuery::Current { resource_id } => {
            json!({"kind":"current","resourceId":resource_id})
        }
        ProjectResourceQuery::Exact {
            resource_id,
            digest,
        } => json!({"kind":"exact","resourceId":resource_id,"digest":digest}),
        ProjectResourceQuery::Historical {
            project_revision,
            resource_id,
            digest,
        } => {
            json!({"kind":"historical","projectRevision":project_revision,"resourceId":resource_id,"digest":digest})
        }
        ProjectResourceQuery::RegisteredImmutable { resource_id } => {
            json!({"kind":"registered_immutable","resourceId":resource_id})
        }
    }
}
fn role_identity(role: &CatalogSourceRole) -> Value {
    match role {
        CatalogSourceRole::GameArtifact => json!({"kind":"game_artifact"}),
        CatalogSourceRole::ServerPack => json!({"kind":"server_pack"}),
        CatalogSourceRole::ClientPack => json!({"kind":"client_pack"}),
        CatalogSourceRole::Mod(id) => json!({"kind":"mod","id":id}),
        CatalogSourceRole::CatalogData => json!({"kind":"catalog_data"}),
    }
}
fn codec_identity(codec: &CatalogSourceCodec) -> Value {
    match codec {
        CatalogSourceCodec::FingerprintOnly { media_type } => {
            json!({"kind":"fingerprint_only","mediaType":media_type})
        }
        CatalogSourceCodec::NativeRegistry => json!({"kind":"native_registry"}),
        CatalogSourceCodec::JsonAsset {
            kind,
            resource_id,
            value_type,
            unit,
        } => {
            json!({"kind":"json_asset","recordKind":kind,"resourceId":resource_id,"valueType":value_type,"unit":unit})
        }
        CatalogSourceCodec::BinaryAsset {
            kind,
            resource_id,
            media_type,
        } => {
            json!({"kind":"binary_asset","recordKind":kind,"resourceId":resource_id,"mediaType":media_type})
        }
    }
}
fn archive_type(resource: &Value) -> AppResult<()> {
    if !matches!(
        resource["mediaType"].as_str(),
        Some("application/java-archive" | "application/zip")
    ) {
        return Err(error(
            "SOURCE_INVALID",
            "Fingerprint source is not an approved archive container",
        ));
    }
    Ok(())
}
fn validate_source_registration(source: &CatalogSourceRegistration) -> AppResult<()> {
    if !matches!(source.codec, CatalogSourceCodec::FingerprintOnly { .. })
        && source.role != CatalogSourceRole::CatalogData
    {
        return Err(error(
            "SOURCE_INVALID",
            "Decoded data cannot be an archive identity source",
        ));
    }
    if matches!(source.codec, CatalogSourceCodec::NativeRegistry)
        != matches!(source.backing, CatalogSourceBacking::NativeRegistry)
    {
        return Err(error(
            "SOURCE_INVALID",
            "Native codec and actual native binding differ",
        ));
    }
    if matches!(source.backing, CatalogSourceBacking::NativeRegistry)
        && (source.layer != CatalogLayer::EnvironmentSnapshot
            || source.source["kind"] != "runtime_observation")
    {
        return Err(error(
            "SOURCE_INVALID",
            "Native observation belongs only to the environment layer",
        ));
    }
    if matches!(
        source.codec,
        CatalogSourceCodec::JsonAsset { .. } | CatalogSourceCodec::BinaryAsset { .. }
    ) && source.layer == CatalogLayer::EnvironmentSnapshot
    {
        return Err(error(
            "SOURCE_INVALID",
            "Runtime facts require the closed actual native decoder",
        ));
    }
    if source.role != CatalogSourceRole::CatalogData {
        let CatalogSourceBacking::ProjectResource(resource) = &source.backing else {
            return Err(error(
                "SOURCE_INVALID",
                "Artifact, pack and mod facts require actual whole container bytes",
            ));
        };
        archive_type(&resource.resource)?;
    }
    Ok(())
}
fn archive_header(bytes: &[u8]) -> Result<(), CatalogError> {
    if ![
        b"PK\x03\x04".as_slice(),
        b"PK\x05\x06".as_slice(),
        b"PK\x07\x08".as_slice(),
    ]
    .iter()
    .any(|magic| bytes.starts_with(magic))
    {
        return Err(CatalogError::SourceUnavailable(
            "Fingerprint container is not an actual ZIP archive input".into(),
        ));
    }
    // This proves container input type only; it is not a content enumeration or
    // transformed-class, effective-pack or redistribution approval.
    Ok(())
}
fn scope_contains(allowed: &Value, requested: &Value) -> bool {
    if allowed["projectId"] != requested["projectId"] {
        return false;
    }
    for key in ["resourceIds", "objectIds", "externalTargetIds"] {
        let (Some(allowed), Some(requested)) = (allowed[key].as_array(), requested[key].as_array())
        else {
            return false;
        };
        if requested.iter().any(|id| !allowed.contains(id)) {
            return false;
        }
    }
    let (Some(regions), Some(allowed_regions)) = (
        requested["regions"].as_array(),
        allowed["regions"].as_array(),
    ) else {
        return false;
    };
    regions.iter().all(|r| {
        allowed_regions.iter().any(|a| {
            a["contextId"] == r["contextId"]
                && a["worldId"] == r["worldId"]
                && a["dimension"] == r["dimension"]
                && (0..3).all(|axis| {
                    match (
                        a["min"][axis].as_i64(),
                        a["maxExclusive"][axis].as_i64(),
                        r["min"][axis].as_i64(),
                        r["maxExclusive"][axis].as_i64(),
                    ) {
                        (Some(min), Some(max), Some(rmin), Some(rmax)) => {
                            min <= rmin && rmin < rmax && rmax <= max
                        }
                        _ => false,
                    }
                })
        })
    })
}
fn allocate_snapshot() -> Result<SnapshotId, CatalogError> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|_| CatalogError::SourceUnavailable("Snapshot entropy is unavailable".into()))?;
    let suffix = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
    SnapshotId::new(format!("snapshot-{suffix}")).map_err(|_| CatalogError::InputLimit)
}
fn now() -> AppResult<String> {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| error("SOURCE_UNAVAILABLE", "Observation time is unavailable"))
}
fn stopped(control: &CaptureControl<'_>) -> Result<(), CatalogError> {
    if control.should_stop() {
        Err(CatalogError::Cancelled)
    } else {
        Ok(())
    }
}
fn context_id(v: &Value) -> AppResult<ContextId> {
    ContextId::new(text(v, "contextId")?).map_err(|_| forbidden())
}
fn project_id(v: &Value) -> AppResult<ProjectId> {
    ProjectId::new(text(v, "projectId")?).map_err(|_| forbidden())
}
fn source_id(v: &Value) -> AppResult<SourceId> {
    SourceId::new(text(v, "sourceId")?).map_err(|_| forbidden())
}
fn digest_field(v: &Value, key: &str) -> AppResult<Sha256Digest> {
    Sha256Digest::new(text(v, key)?)
        .map_err(|_| error("SOURCE_INVALID", "Source digest is invalid"))
}
fn text<'a>(v: &'a Value, key: &str) -> AppResult<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| error("SOURCE_INVALID", "Required source field is absent"))
}
fn validate(definition: &str, v: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .and_then(|validator| validator.validate(definition, v))
        .map_err(|_| error("SOURCE_INVALID", "Source violates original contract"))
}
fn error(code: &'static str, message: &'static str) -> AppError {
    AppError::new(code, message)
}
fn forbidden() -> AppError {
    error(
        "PERMISSION_REQUIRED",
        "Current authenticated source authority is required",
    )
}
fn budget_error() -> AppError {
    error("INPUT_LIMIT", "Catalog source exceeds its finite budget")
}
fn busy() -> AppError {
    error("SOURCE_BUSY", "Catalog source registry is in use")
}
fn storage_forbidden() -> StorageError {
    StorageError::InvalidTransition("Current catalog source authority is required".into())
}
fn service_app(e: ServiceError) -> AppError {
    error(e.code, e.message)
}
fn app_service(e: AppError) -> ServiceError {
    ServiceError::new(e.code, "Authenticated catalog source could not be resolved")
}
fn service_forbidden() -> ServiceError {
    ServiceError::new(
        "PERMISSION_REQUIRED",
        "Current authenticated catalog source authority is required",
    )
}
fn service_unavailable() -> ServiceError {
    ServiceError::new(
        "SOURCE_UNAVAILABLE",
        "Catalog source has no installed execution context",
    )
}
fn app_catalog(e: AppError) -> CatalogError {
    let primary = match e.code {
        "PERMISSION_REQUIRED" => CatalogError::PermissionRequired,
        "CANCELLED" | "TIME_BUDGET_EXCEEDED" => CatalogError::Cancelled,
        "INPUT_LIMIT" => CatalogError::InputLimit,
        _ => CatalogError::SourceUnavailable(e.to_string()),
    };
    CatalogError::caused_by(primary, e)
}
fn app_storage(e: AppError) -> StorageError {
    StorageError::InvalidTransition(e.to_string())
}
fn storage_app(e: StorageError) -> AppError {
    let code = match &e {
        StorageError::Conflict(_) => "SOURCE_CONFLICT",
        StorageError::InvalidInput(_) => "INPUT_LIMIT",
        StorageError::InvalidTransition(_) => "PERMISSION_REQUIRED",
        _ => "SOURCE_UNAVAILABLE",
    };
    AppError::storage(code, e)
}
fn app_artifact(e: AppError) -> ArtifactError {
    match e.code {
        "PERMISSION_REQUIRED" => ArtifactError::forbidden(),
        "CANCELLED" | "TIME_BUDGET_EXCEEDED" => ArtifactError::new(e.code, e.message),
        _ => ArtifactError::new(
            "RESOURCE_UNAVAILABLE",
            "Captured resource authority could not be resolved",
        ),
    }
}
fn parse_controlled(bytes: &[u8], budget: &RequestBudget) -> AppResult<Value> {
    mmmm_contracts::strict_json::parse_json_with_control(
        bytes,
        mmmm_contracts::JsonLimits::default(),
        || budget.check(),
    )
    .map_err(|e| match e {
        mmmm_contracts::strict_json::ControlledJsonError::Json(e) => json_app(e),
        mmmm_contracts::strict_json::ControlledJsonError::Control(e) => service_app(e),
    })
}
fn source_receipt_value(receipt: &CapturedResourceReceipt) -> Value {
    json!({"resource":receipt.resource,"sourceManifest":receipt.source_manifest,"source":receipt.source,"rightsWitness":receipt.rights_witness})
}

fn prevalidate_capture(
    result: &CaptureResult,
    request: &Value,
    control: &CaptureControl<'_>,
    budget: &CaptureBudget,
) -> Result<(), CatalogError> {
    let mut sources = BTreeMap::new();
    let mut total = 0usize;
    for evidence in &result.sources {
        total = total
            .checked_add(evidence.observed_bytes.len())
            .ok_or(CatalogError::InputLimit)?;
        if total > budget.max_source_bytes
            || evidence.source["sha256"] != raw_digest(&evidence.observed_bytes).as_str()
            || sources
                .insert(
                    evidence.source["sourceId"].clone().to_string(),
                    &evidence.source,
                )
                .is_some()
        {
            return Err(CatalogError::InputLimit);
        }
    }
    for requested in request["sources"]
        .as_array()
        .ok_or(CatalogError::PermissionRequired)?
    {
        let Some(actual) = sources.get(&requested["sourceId"].clone().to_string()) else {
            if result.interrupted || control.should_stop() {
                continue;
            }
            return Err(CatalogError::SourceUnavailable(
                "Requested source was not actually captured".into(),
            ));
        };
        let mut expected = requested.clone();
        if expected["sha256"].is_null() {
            expected["sha256"] = actual["sha256"].clone();
        }
        expected["verifiedAt"] = actual["verifiedAt"].clone();
        if expected != **actual {
            return Err(CatalogError::SourceUnavailable(
                "Requested source claims were not confirmed".into(),
            ));
        }
    }
    // Use the owning catalog's semantic builder before retaining an authority
    // candidate. This temporary validation catalog is never exposed as a
    // facade, cursor source, operation ledger or game-verification result.
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|_| {
        CatalogError::SourceUnavailable("Catalog validation entropy is unavailable".into())
    })?;
    let limits = CatalogLimits {
        max_snapshots: 1,
        max_records_per_snapshot: budget.max_records,
        max_snapshot_bytes: budget.max_snapshot_bytes,
        max_total_bytes: budget.max_snapshot_bytes,
        max_capture_evidence_bytes: budget.max_source_bytes,
        ..CatalogLimits::default()
    };
    Catalog::new(key, limits)?.insert_snapshot(result.snapshot.clone())?;
    Ok(())
}
fn storage_catalog(e: StorageError) -> CatalogError {
    app_catalog(storage_app(e))
}
fn json_app(_e: mmmm_contracts::JsonError) -> AppError {
    error(
        "INPUT_LIMIT",
        "Catalog source JSON exceeds its finite codec",
    )
}
fn digest_app(_e: mmmm_contracts::DigestError) -> AppError {
    error(
        "SOURCE_INVALID",
        "Catalog source canonical identity is invalid",
    )
}

#[cfg(test)]
#[path = "catalog_source_tests.rs"]
mod tests;

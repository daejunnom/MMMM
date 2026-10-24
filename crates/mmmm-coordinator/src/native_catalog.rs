//! One current completed native pairing may issue a local-only registry read
//! source. Raw game/mod/pack receipts remain observations, never source grants
//! or a complete target identity. No wire input constructs this admission.

use crate::{
    auth::AuthenticatedPrincipal,
    authority::LocalAuthority,
    bootstrap::NativeWorkspacePermit,
    catalog_source::{
        CatalogEnvironmentRegistration, CatalogRpc, CatalogSourceBacking,
        CatalogSourceRegistration, NativeCatalogAdmissionState, NativeCatalogPublication,
        RegisteredCatalogResource, RegisteredCatalogSources, current_project, source_facts_pin,
        validate_source_facts,
    },
    host::{CompletedPairingWitness, HostBridge, NativePairingOwnerFailure},
    service::{RequestBudget, RequestContextSlot, RequestContextWitness},
    workspace_bootstrap::NativeOwnerWitness,
};
use mmmm_application::{AppError, AppResult};
use mmmm_contracts::{
    ContextId, ContractValidator, PrincipalId, ProjectId, ResourceId, Sha256Digest, SourceId,
    canonical_digest, encode_json, parse_json,
};
use mmmm_reference::{
    CatalogLayer, CatalogSourceCodec, CatalogSourceRole, MAX_NATIVE_REGISTRY_BYTES,
    NATIVE_REGISTRY_FORMAT, RegistryCaptureWitness,
};
use mmmm_runtime::storage::{
    DurableStore, StorageError, StorageResult,
    artifact::ResourceOwner,
    bootstrap::POLICY_MEDIA_TYPE,
    catalog_source_use::{
        self, CatalogSourceUseAction, CatalogSourceUseCurrent, CatalogSourceUsePermit,
        CatalogSourceUseRole, CatalogSourceUseSnapshot,
    },
    host_setup::HostReadPolicyRecord,
    project_resources::{
        ProjectResourceAuthority, ProjectResourceQuery, ProjectResourceReader,
        ProjectResourceRequest, ProjectSourceRpcContext, RegisteredProjectResource,
    },
};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

/// A hook belongs only to the current borrowed CatalogCall. Absence denies
/// native source I/O; explicit source publishers never invoke this port.
pub(crate) trait NativeCatalogCheckpoint {
    fn check(&self, store: &DurableStore) -> AppResult<()>;
}
struct CurrentNativeCatalogCheckpoint {
    request: RequestContextWitness,
    principal: AuthenticatedPrincipal,
    context: Value,
    budget: RequestBudget,
    pairing: Rc<CompletedPairingWitness>,
    authority: LocalAuthority,
    sources: RegisteredCatalogSources,
    publication: NativeCatalogPublication,
}
impl NativeCatalogCheckpoint for CurrentNativeCatalogCheckpoint {
    fn check(&self, store: &DurableStore) -> AppResult<()> {
        let result = (|| {
            check_read_request(&self.request, &self.principal, &self.context, &self.budget)?;
            self.pairing
                .with_current_native_owner(store, &self.authority, |owner| {
                    let current = owner.read_host_policy()?;
                    if !current.policy().native_observation_user_local_only()
                        || current.policy_digest() != self.publication.read_policy()
                    {
                        return Err(denied());
                    }
                    owner.check_current()
                })?;
            let selected = read_source_uses(
                &self.request,
                &self.principal,
                &self.context,
                &self.budget,
                &self.pairing,
                &self.authority,
                self.publication.read_policy(),
                store,
            )?;
            if source_use_pin(&selected)? != *self.publication.source_use() {
                return Err(drift());
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(()),
            Err(primary) => combine(
                Err(primary),
                self.sources.retire_native_publication(&self.publication),
            ),
        }
    }
}

/// Private construction retains the result of the real consumer's complete
/// checks. A policy record, source descriptor or matching digest is not this
/// type. The registry accepts it only through its separate native publisher.
pub(crate) struct NativeCatalogObservation {
    registration: CatalogEnvironmentRegistration,
    proof: Sha256Digest,
    read_policy: Sha256Digest,
    source_use: Sha256Digest,
    method: String,
}
impl NativeCatalogObservation {
    pub(crate) fn into_parts(
        self,
    ) -> (
        CatalogEnvironmentRegistration,
        Sha256Digest,
        Sha256Digest,
        Sha256Digest,
        String,
    ) {
        (
            self.registration,
            self.proof,
            self.read_policy,
            self.source_use,
            self.method,
        )
    }
}

pub(crate) struct NativeCatalogAdmission<'a> {
    pub(crate) request: &'a RequestContextSlot,
    pub(crate) authority: &'a LocalAuthority,
    pub(crate) hosts: &'a HostBridge,
    pub(crate) sources: &'a RegisteredCatalogSources,
}

/// 원 요청 안에서만 보유하는 입력 사실이다. owner/request witness는 담지 않고
/// 저장된 JSON으로 생성하거나 읽기 권한으로 사용할 수 없다.
pub(crate) struct NativeInputArchivePins {
    pub(crate) publication: NativeCatalogPublication,
    pub(crate) policy: HostReadPolicyRecord,
    pub(crate) selected: CatalogSourceUseSnapshot,
    pub(crate) revision: Sha256Digest,
}
impl NativeCatalogAdmission<'_> {
    pub(crate) fn selected_input_archive_pins(
        &self,
        principal: &AuthenticatedPrincipal,
        context: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> AppResult<Option<NativeInputArchivePins>> {
        let publication = match self.sources.native_admission_state(principal, context)? {
            NativeCatalogAdmissionState::Explicit => return Ok(None),
            NativeCatalogAdmissionState::Missing => return Err(denied()),
            NativeCatalogAdmissionState::Native(publication) => publication,
        };
        let result = (|| {
            let request = self
                .request
                .current_witness("catalog.capture")
                .map_err(service_error)?;
            check_request(&request, principal, context, budget)?;
            let id = ContextId::new(text(context, "contextId")?).map_err(|_| invalid())?;
            let pairing = Rc::new(self.hosts.completed_pairing_witness(
                &request,
                self.authority,
                &id,
            )?);
            let policy = pairing.with_current_native_owner(store, self.authority, |owner| {
                owner.read_host_policy()
            })?;
            if policy.policy_digest() != publication.read_policy()
                || !policy.policy().native_observation_user_local_only()
            {
                return Err(denied());
            }
            let selected = read_source_uses(
                &request,
                principal,
                context,
                budget,
                &pairing,
                self.authority,
                policy.policy_digest(),
                store,
            )?;
            if source_use_pin(&selected)? != *publication.source_use() {
                return Err(drift());
            }
            let rpc = CatalogRpc::new(
                principal.clone(),
                budget.clone(),
                self.authority.clone(),
                context,
            )?;
            let revision = Sha256Digest::new(text(
                &current_project(store, &rpc, pairing.project())?,
                "revision",
            )?)
            .map_err(|_| invalid())?;
            check_request(&request, principal, context, budget)?;
            Ok(Some(NativeInputArchivePins {
                publication: publication.clone(),
                policy,
                selected,
                revision,
            }))
        })();
        match result {
            Ok(pins) => Ok(pins),
            Err(primary) => combine(
                Err(primary),
                self.sources.retire_native_publication(&publication),
            ),
        }
    }

    /// 한 입력의 bytes만 반환한다. 기존 실제 owner/Store/game ACL callback과
    /// same-handle 전체 hash 검증을 유지하고 witness는 이 읽기 뒤 폐기한다.
    pub(crate) fn read_selected_input_archive(
        &self,
        principal: &AuthenticatedPrincipal,
        context: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
        pins: &NativeInputArchivePins,
        index: usize,
    ) -> AppResult<Vec<u8>> {
        let request = self
            .request
            .current_witness("catalog.capture")
            .map_err(service_error)?;
        check_request(&request, principal, context, budget)?;
        let current = self.sources.native_admission_state(principal, context)?;
        if !matches!(current, NativeCatalogAdmissionState::Native(ref current)
            if current.same_issuance(&pins.publication))
        {
            return Err(denied());
        }
        let id = ContextId::new(text(context, "contextId")?).map_err(|_| invalid())?;
        let pairing = Rc::new(self.hosts.completed_pairing_witness(
            &request,
            self.authority,
            &id,
        )?);
        if pairing.context() != context {
            return Err(drift());
        }
        let boundary = || {
            pairing.with_current_native_owner(store, self.authority, |owner| {
                if owner.read_host_policy()? != pins.policy {
                    return Err(drift());
                }
                check_request(&request, principal, context, budget)?;
                owner.check_current()
            })
        };
        boundary()?;
        let output = (|| {
            let permit = source_use_reader(
                &request,
                principal,
                context,
                budget,
                &pairing,
                self.authority,
                store,
            )?;
            if permit.revision != pins.revision {
                return Err(drift());
            }
            let selected = pins.selected.selections().get(index).ok_or_else(invalid)?;
            let mut reader = permit
                .resource_reader(64 * 1024 * 1024)
                .map_err(|cause| permit.release(cause))?;
            let query = ProjectResourceQuery::Current {
                resource_id: selected.selection().resource_id.clone(),
            };
            let result = reader
                .read(
                    store,
                    &permit,
                    &ProjectResourceRequest {
                        project: &permit.project,
                        current_project_revision: &permit.revision,
                        query: &query,
                        expected: Some(selected.resource()),
                    },
                    64 * 1024 * 1024,
                )
                .map_err(|cause| permit.release(cause))?;
            if result.registered.blob != *selected.blob()
                || result.registered.owner != ResourceOwner::Project(permit.project.clone())
            {
                return Err(drift());
            }
            Ok(result.bytes)
        })();
        combine(output, boundary())
    }

    /// Capture obtains a fresh call-scoped hook after access admission. The
    /// long-lived source registry retains only its origin proof and receipt.
    pub(crate) fn checkpoint(
        &self,
        principal: &AuthenticatedPrincipal,
        context: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> AppResult<Option<Rc<dyn NativeCatalogCheckpoint>>> {
        let publication = match self.sources.native_admission_state(principal, context)? {
            NativeCatalogAdmissionState::Explicit => return Ok(None),
            NativeCatalogAdmissionState::Missing => return Err(denied()),
            NativeCatalogAdmissionState::Native(publication) => publication,
        };
        let result = (|| {
            let request = self.request.occupied_witness().map_err(service_error)?;
            check_read_request(&request, principal, context, budget)?;
            let id = ContextId::new(text(context, "contextId")?).map_err(|_| denied())?;
            let pairing = Rc::new(self.hosts.completed_pairing_witness(
                &request,
                self.authority,
                &id,
            )?);
            if pairing.context() != context {
                return Err(denied());
            }
            pairing.with_current_native_owner(store, self.authority, |owner| {
                let record = owner.read_host_policy()?;
                if !record.policy().native_observation_user_local_only()
                    || record.policy_digest() != publication.read_policy()
                {
                    return Err(denied());
                }
                Ok(())
            })?;
            let checkpoint: Rc<dyn NativeCatalogCheckpoint> =
                Rc::new(CurrentNativeCatalogCheckpoint {
                    request,
                    principal: principal.clone(),
                    context: context.clone(),
                    budget: budget.clone(),
                    pairing,
                    authority: self.authority.clone(),
                    sources: self.sources.clone(),
                    publication: publication.clone(),
                });
            checkpoint.check(store)?;
            Ok(Some(checkpoint))
        })();
        match result {
            Ok(checkpoint) => Ok(checkpoint),
            Err(primary) => combine(
                Err(primary),
                self.sources.retire_native_publication(&publication),
            ),
        }
    }

    pub(crate) fn ensure(
        &self,
        principal: &AuthenticatedPrincipal,
        context: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        let request = self.request.occupied_witness().map_err(service_error)?;
        check_request(&request, principal, context, budget)?;
        let mut publication = match self.sources.native_admission_state(principal, context)? {
            // Explicit composition has its own source/rights authority. It is
            // neither replaced nor forced through native local-owner policy.
            NativeCatalogAdmissionState::Explicit => return Ok(()),
            NativeCatalogAdmissionState::Missing if request.method() != "catalog.capture" => {
                return Ok(());
            }
            NativeCatalogAdmissionState::Missing => None,
            NativeCatalogAdmissionState::Native(publication) => Some(publication),
        };
        let result = (|| {
            let id = ContextId::new(text(context, "contextId")?).map_err(|_| denied())?;
            let pairing = Rc::new(self.hosts.completed_pairing_witness(
                &request,
                self.authority,
                &id,
            )?);
            if pairing.context() != context {
                return Err(denied());
            }
            pairing.with_current_native_owner(store, self.authority, |owner| {
                let policy = owner.read_host_policy()?;
                if !policy.policy().native_observation_user_local_only() {
                    return Err(denied());
                }
                let selected = read_source_uses(
                    &request,
                    principal,
                    context,
                    budget,
                    &pairing,
                    self.authority,
                    policy.policy_digest(),
                    store,
                )?;
                let source_use = source_use_pin(&selected)?;
                if publication.as_ref().is_some_and(|original| {
                    original.read_policy() != policy.policy_digest()
                        || original.source_use() != &source_use
                }) {
                    return Err(drift());
                }
                let checkpoint = || {
                    check_request(&request, principal, context, budget)?;
                    owner.check_current()?;
                    let current = owner.read_host_policy()?;
                    if current != policy || !current.policy().native_observation_user_local_only() {
                        return Err(denied());
                    }
                    owner.check_current()?;
                    let current = read_source_uses(
                        &request,
                        principal,
                        context,
                        budget,
                        &pairing,
                        self.authority,
                        policy.policy_digest(),
                        store,
                    )?;
                    if source_use_pin(&current)? != source_use {
                        return Err(drift());
                    }
                    owner.check_current()
                };
                let hello = checked(
                    || {
                        self.hosts.hello_with_deadline(
                            principal.principal(),
                            &id,
                            budget.deadline(),
                        )
                    },
                    checkpoint,
                )?;
                let facts = checked(
                    || self.inspection(principal, &id, "runtime_sources", budget),
                    checkpoint,
                )?;
                let registry = checked(
                    || self.inspection(principal, &id, "native_registry", budget),
                    checkpoint,
                )?;
                let final_facts = checked(
                    || self.inspection(principal, &id, "runtime_sources", budget),
                    checkpoint,
                )?;
                let final_hello = checked(
                    || {
                        self.hosts.hello_with_deadline(
                            principal.principal(),
                            &id,
                            budget.deadline(),
                        )
                    },
                    checkpoint,
                )?;
                let final_context = checked(
                    || {
                        self.hosts.context_with_deadline(
                            principal.principal(),
                            &id,
                            budget.deadline(),
                        )
                    },
                    checkpoint,
                )?;
                checkpoint()?;
                let witness = validate_observation(context, &hello, &facts, &registry)?;
                validate_source_facts(&final_facts, context)?;
                if hello != final_hello
                    || final_context != *context
                    || hello["hostBuild"] != policy.host_artifact_digest().as_str()
                    || source_facts_pin(&facts)? != source_facts_pin(&final_facts)?
                {
                    return Err(drift());
                }
                let proof = canonical_digest(&json!({
                    "format":"mmmm.native-catalog-source-admission/2",
                    "principal":principal.principal(), "context":context,
                    "completedOffer":pairing.offer_digest(),
                    "nativeOwner":pairing.native_owner(), "readPolicy":policy.policy_digest(),
                    "sourceUse":source_use,
                    "hello":hello, "sourceFacts":source_facts_pin(&facts)?,
                    "registryDigest":witness.registry_digest,
                    "generation":witness.registry_generation, "locale":witness.locale,
                }))
                .map_err(|_| invalid())?;
                let source = json!({
                    "sourceId":"native-registry-observation", "kind":"runtime_observation",
                    "locator":format!("mmmm-host://catalog/{}/native_registry", id.as_str()),
                    "sha256":null, "rights":"user_local_only", "verifiedAt":witness.observed_at,
                });
                let mut registration = CatalogEnvironmentRegistration {
                    context: context.clone(),
                    game_version: Some(witness.game_version),
                    locale: Some(witness.locale),
                    artifact_source: None,
                    server_pack_sources: None,
                    client_pack_sources: None,
                    mod_sources: None,
                    registry_generation: Some(witness.registry_generation),
                    native_mod_ids: BTreeMap::new(),
                    sources: vec![CatalogSourceRegistration {
                        source,
                        layer: CatalogLayer::EnvironmentSnapshot,
                        role: CatalogSourceRole::CatalogData,
                        codec: CatalogSourceCodec::NativeRegistry,
                        backing: CatalogSourceBacking::NativeRegistry,
                    }],
                };
                merge_source_uses(&mut registration, &selected, &witness.observed_at)?;
                checkpoint()?;
                publication = Some(self.sources.register_native_observation(
                    principal,
                    budget,
                    store,
                    NativeCatalogObservation {
                        registration,
                        proof,
                        read_policy: policy.policy_digest().clone(),
                        source_use: source_use.clone(),
                        method: request.method().to_owned(),
                    },
                )?);
                checkpoint()
            })
        })();
        match result {
            Ok(()) => Ok(()),
            Err(primary) => {
                let retired = publication.as_ref().map_or(Ok(()), |publication| {
                    self.sources.retire_native_publication(publication)
                });
                combine(Err(primary), retired)
            }
        }
    }

    fn inspection(
        &self,
        principal: &AuthenticatedPrincipal,
        context: &ContextId,
        kind: &'static str,
        budget: &RequestBudget,
    ) -> AppResult<Value> {
        let response = self
            .hosts
            .inspect_acquired_with_deadline(
                principal.principal(),
                context,
                json!({"kind":kind}),
                budget.deadline(),
            )?
            .into_response()?;
        if response["status"] != "ok" {
            return Err(AppError::caused_by(
                "HOST_REQUEST_FAILED",
                "Actual native catalog inspection failed",
                NativeCatalogHostFailure { response },
            ));
        }
        response.get("payload").cloned().ok_or_else(invalid)
    }
}

/// This reader retains the actual game RPC identity. Only the exact Policy
/// selected by the checked current Project has an internal native validation
/// path; every selected container still requires the ordinary game scope.
/// Neither this adapter nor its factual result is exposed as a read RPC grant.
#[derive(Clone)]
struct NativeSourceUseRead {
    request: RequestContextWitness,
    principal: AuthenticatedPrincipal,
    context: Value,
    budget: RequestBudget,
    pairing: Rc<CompletedPairingWitness>,
    owner: NativeOwnerWitness,
    rpc: CatalogRpc,
    project: ProjectId,
    revision: Sha256Digest,
    document: Value,
    policy_id: ResourceId,
    failure: Rc<RefCell<Option<AppError>>>,
}
impl NativeSourceUseRead {
    fn native_store(&self, store: &DurableStore) -> StorageResult<()> {
        self.check()?;
        let registered = self.owner.check_project(store, &self.project)?;
        if &registered != self.pairing.native_owner() {
            return Err(self.reject(denied()));
        }
        self.check()
    }
    fn reject(&self, cause: AppError) -> StorageError {
        if let Ok(mut failure) = self.failure.try_borrow_mut()
            && failure.is_none()
        {
            *failure = Some(cause);
        }
        StorageError::Conflict("Current native catalog source use authority")
    }
    fn release(&self, cause: StorageError) -> AppError {
        self.failure
            .borrow_mut()
            .take()
            .unwrap_or_else(|| self.rpc.storage_error(cause))
    }
}
impl ProjectSourceRpcContext for NativeSourceUseRead {
    fn check(&self) -> StorageResult<()> {
        check_read_request(&self.request, &self.principal, &self.context, &self.budget)
            .map_err(|cause| self.reject(cause))?;
        self.owner.check()?;
        self.rpc.check()
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.principal.principal().clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        self.rpc.context_id()
    }
}
impl CatalogSourceUsePermit for NativeSourceUseRead {
    fn check_store(&self, store: &DurableStore) -> StorageResult<()> {
        self.native_store(store)?;
        self.rpc
            .project_acl(self.principal.principal(), self.context_id(), &self.project)?;
        self.check()
    }
    fn authenticated_native_owner(
        &self,
        store: &DurableStore,
        project: &ProjectId,
    ) -> StorageResult<PrincipalId> {
        self.check_store(store)?;
        if project != &self.project {
            return Err(self.reject(denied()));
        }
        Ok(self.pairing.native_owner().clone())
    }
    fn authorize_current(
        &self,
        store: &DurableStore,
        current: &CatalogSourceUseCurrent<'_>,
    ) -> StorageResult<()> {
        self.check_store(store)?;
        if current.action != CatalogSourceUseAction::Read
            || current.native_owner != self.pairing.native_owner()
            || current.project != &self.document
            || current.policy_resource.owner != ResourceOwner::Project(self.project.clone())
            || current.policy_resource.resource["resourceId"] != self.policy_id.as_str()
            || current.policy_resource.resource["mediaType"] != POLICY_MEDIA_TYPE
        {
            return Err(self.reject(denied()));
        }
        for selected in current.selections {
            self.rpc.source_scope(
                self.principal.principal(),
                self.context_id(),
                &self.project,
                "resourceIds",
                selected.resource_id.as_str(),
            )?;
            // runtimeMods constrains the delivered map, not authoring-host
            // observation. The actual current mod-use switch still applies.
            if matches!(selected.role, CatalogSourceUseRole::Mod { .. })
                && current.policy["modUseEnabled"] != true
            {
                return Err(self.reject(denied()));
            }
        }
        self.check_store(store)
    }
    fn resource_reader(&self, ceiling: u64) -> StorageResult<ProjectResourceReader> {
        self.check()?;
        ProjectResourceReader::new(Box::new(NativeSourceUseAuthority(self.clone())), ceiling)
    }
}
struct NativeSourceUseAuthority(NativeSourceUseRead);
impl ProjectResourceAuthority for NativeSourceUseAuthority {
    fn authorize_project_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        revision: &Sha256Digest,
    ) -> StorageResult<()> {
        self.0.native_store(store)?;
        if revision != &self.0.revision {
            return Err(self.0.reject(drift()));
        }
        self.0.rpc.project_acl(principal, context, project)
    }
    fn authorize_resource_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> StorageResult<()> {
        self.0.native_store(store)?;
        self.0.rpc.project_acl(principal, context, project)?;
        if resource.owner != ResourceOwner::Project(project.clone()) {
            return Err(self.0.reject(denied()));
        }
        if resource.resource["resourceId"] == self.0.policy_id.as_str()
            && resource.resource["mediaType"] == POLICY_MEDIA_TYPE
        {
            return self.0.check();
        }
        self.0.rpc.source_scope(
            principal,
            context,
            project,
            "resourceIds",
            text(&resource.resource, "resourceId").map_err(|cause| self.0.reject(cause))?,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn read_source_uses(
    request: &RequestContextWitness,
    principal: &AuthenticatedPrincipal,
    context: &Value,
    budget: &RequestBudget,
    pairing: &Rc<CompletedPairingWitness>,
    authority: &LocalAuthority,
    read_policy: &Sha256Digest,
    store: &DurableStore,
) -> AppResult<CatalogSourceUseSnapshot> {
    // D032 and the completed route are fresh around this entire bounded local
    // read. Reader callbacks below recheck the same native owner/Store and game
    // ACL, without recursively reopening the D032 reader for each metadata pin.
    let boundary = || {
        check_read_request(request, principal, context, budget)?;
        if pairing.context() != context {
            return Err(denied());
        }
        pairing.with_current_native_owner(store, authority, |owner| {
            let policy = owner.read_host_policy()?;
            if !policy.policy().native_observation_user_local_only()
                || policy.policy_digest() != read_policy
            {
                return Err(denied());
            }
            owner.check_current()
        })
    };
    boundary()?;
    let output = (|| {
        let permit = source_use_reader(
            request, principal, context, budget, pairing, authority, store,
        )?;
        let selected = catalog_source_use::read_catalog_source_uses(
            store,
            &permit,
            &permit.project,
            &permit.revision,
        )
        .map_err(|cause| permit.release(cause))?;
        if selected.native_owner() != pairing.native_owner()
            || selected.project_id() != pairing.project()
            || selected.rights() != "user_local_only"
        {
            return Err(denied());
        }
        check_read_request(request, principal, context, budget)?;
        Ok(selected)
    })();
    combine(output, boundary())
}

#[allow(clippy::too_many_arguments)]
fn source_use_reader(
    request: &RequestContextWitness,
    principal: &AuthenticatedPrincipal,
    context: &Value,
    budget: &RequestBudget,
    pairing: &Rc<CompletedPairingWitness>,
    authority: &LocalAuthority,
    store: &DurableStore,
) -> AppResult<NativeSourceUseRead> {
    let owner = NativeOwnerWitness::capture(store, budget.deadline())
        .map_err(|cause| AppError::storage("PERMISSION_REQUIRED", cause))?;
    if owner.principal() != pairing.native_owner() {
        return Err(denied());
    }
    let rpc = CatalogRpc::new(
        principal.clone(),
        budget.clone(),
        authority.clone(),
        context,
    )?;
    let project = pairing.project().clone();
    let document = current_project(store, &rpc, &project)?;
    let revision = Sha256Digest::new(text(&document, "revision")?).map_err(|_| invalid())?;
    let policy_id = ResourceId::new(text(&document, "policyResourceId")?).map_err(|_| invalid())?;
    Ok(NativeSourceUseRead {
        request: request.clone(),
        principal: principal.clone(),
        context: context.clone(),
        budget: budget.clone(),
        pairing: pairing.clone(),
        owner,
        rpc,
        project,
        revision,
        document,
        policy_id,
        failure: Rc::new(RefCell::new(None)),
    })
}

fn source_use_pin(selected: &CatalogSourceUseSnapshot) -> AppResult<Sha256Digest> {
    // Includes monotonic generation/tombstone, original approval Project and
    // Policy pins, exact role/native-ID/resource/BlobRef pins and owner/Store
    // provenance validated above. It is retained factual identity, not a grant.
    canonical_digest(&json!({"format":"mmmm.native-catalog-source-use/1", "snapshot":selected}))
        .map_err(|_| invalid())
}

fn merge_source_uses(
    registration: &mut CatalogEnvironmentRegistration,
    selected: &CatalogSourceUseSnapshot,
    observed_at: &str,
) -> AppResult<()> {
    let mut mods = BTreeMap::new();
    for (index, pin) in selected.selections().iter().enumerate() {
        // IDs describe this bounded protected set. No caller SourceRef or hash
        // constructs the registration or grants resource access.
        let id = SourceId::new(format!("native-container-{index}")).map_err(|_| invalid())?;
        let role = match &pin.selection().role {
            CatalogSourceUseRole::GameArtifact => {
                registration.artifact_source = Some(id.clone());
                CatalogSourceRole::GameArtifact
            }
            CatalogSourceUseRole::Mod {
                canonical_id,
                native_id,
            } => {
                mods.insert(canonical_id.clone(), id.clone());
                registration
                    .native_mod_ids
                    .insert(canonical_id.clone(), native_id.clone());
                CatalogSourceRole::Mod(canonical_id.clone())
            }
        };
        registration.sources.push(CatalogSourceRegistration {
            source: json!({"sourceId":id, "kind":"user_file", "locator":"mmmm-source://selected-container",
                "sha256":pin.blob().digest, "rights":"user_local_only", "verifiedAt":observed_at}),
            layer: CatalogLayer::LocalArtifact, role,
            codec: CatalogSourceCodec::FingerprintOnly {
                media_type: text(pin.resource(), "mediaType")?.to_owned(),
            },
            backing: CatalogSourceBacking::ProjectResource(RegisteredCatalogResource {
                query: ProjectResourceQuery::Current { resource_id: pin.selection().resource_id.clone() },
                resource: pin.resource().clone(),
            }),
        });
    }
    // Absence carries no assertion of an empty native mod set. An actual Mod
    // selection can identify only the complete independently observed mapping.
    if !mods.is_empty() {
        registration.mod_sources = Some(mods);
    }
    Ok(())
}

fn check_request(
    request: &RequestContextWitness,
    principal: &AuthenticatedPrincipal,
    context: &Value,
    budget: &RequestBudget,
) -> AppResult<()> {
    if !matches!(
        request.method(),
        "catalog.capture" | "catalog.search" | "catalog.describe"
    ) {
        return Err(denied());
    }
    check_read_request(request, principal, context, budget)
}

/// 원 publication만 소비하는 FN23/FN31도 같은 실제 요청·source-use 검사를 쓴다.
/// 발행자는 위 catalog-only check_request를 계속 사용한다.
fn check_read_request(
    request: &RequestContextWitness,
    principal: &AuthenticatedPrincipal,
    context: &Value,
    budget: &RequestBudget,
) -> AppResult<()> {
    request.check_local().map_err(service_error)?;
    if !matches!(
        request.method(),
        "catalog.capture"
            | "catalog.search"
            | "catalog.describe"
            | "world.shape_query"
            | "artifact.read"
    ) || !request.authenticated().same_session(principal)
        || !principal.is_current()
        || !principal.permits(request.method())
        || !principal.permits_context(text(context, "contextId")?)
        || request.budget().deadline() != budget.deadline()
        || !std::ptr::eq(request.budget().cancellation(), budget.cancellation())
        || context["environment"]["kind"] != "game"
        || context["principalRef"] != principal.principal().as_str()
    {
        return Err(denied());
    }
    Ok(())
}

fn checked<T>(
    work: impl FnOnce() -> AppResult<T>,
    checkpoint: impl Fn() -> AppResult<()>,
) -> AppResult<T> {
    checkpoint()?;
    let output = work();
    combine(output, checkpoint())
}
fn combine<T>(output: AppResult<T>, checkpoint: AppResult<()>) -> AppResult<T> {
    match (output, checkpoint) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(cause), Ok(())) | (Ok(_), Err(cause)) => Err(cause),
        (Err(primary), Err(checkpoint)) => Err(AppError::caused_by(
            primary.code,
            primary.message,
            NativePairingOwnerFailure {
                primary,
                checkpoint,
            },
        )),
    }
}

/// This binds the raw registry envelope to the actual route and source facts.
/// The existing capture decoder still owns semantic registry record decoding.
fn validate_observation(
    context: &Value,
    hello: &Value,
    facts: &Value,
    registry: &Value,
) -> AppResult<RegistryCaptureWitness> {
    let validator = ContractValidator::shared().map_err(|_| invalid())?;
    validator
        .validate("HostHello", hello)
        .map_err(|_| invalid())?;
    validate_source_facts(facts, context)?;
    if hello["environment"] != context["environment"]
        || encode_json(registry).map_err(|_| invalid())?.len()
            > MAX_NATIVE_REGISTRY_BYTES.saturating_mul(2) + 16 * 1024
        || registry.as_object().is_none_or(|o| o.len() != 10)
    {
        return Err(invalid());
    }
    let hex = text(registry, "observationBytesHex")?;
    if hex.len() > MAX_NATIVE_REGISTRY_BYTES.saturating_mul(2) || hex.len() % 2 != 0 {
        return Err(invalid());
    }
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(invalid()),
    };
    let bytes = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|p| Ok(digit(p[0])? * 16 + digit(p[1])?))
        .collect::<AppResult<Vec<_>>>()?;
    let mut metadata = registry.clone();
    metadata
        .as_object_mut()
        .ok_or_else(invalid)?
        .remove("observationBytesHex");
    let witness: RegistryCaptureWitness =
        serde_json::from_value(metadata).map_err(|_| invalid())?;
    let valid_tick = |s: &str| {
        !s.is_empty()
            && s.len() <= 128
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s == "0" || !s.starts_with('0'))
    };
    if witness.context_digest.as_str() != text(context, "contextDigest")?
        || witness.environment != context["environment"]
        || witness.registry_digest.as_str() != text(hello, "registryDigest")?
        || witness.registry_generation != text(facts, "registryGeneration")?
        || witness.game_version != text(hello, "gameVersion")?
        || witness.locale.is_empty()
        || witness.locale.len() > 256
        || !valid_tick(&witness.observed_from_tick)
        || !valid_tick(&witness.observed_to_tick)
        || (
            witness.observed_from_tick.len(),
            &witness.observed_from_tick,
        ) > (witness.observed_to_tick.len(), &witness.observed_to_tick)
    {
        return Err(drift());
    }
    validator
        .validate(
            "SourceRef",
            &json!({
                "sourceId":"registry-witness", "kind":"runtime_observation",
                "locator":"mmmm-host://registry/witness", "sha256":null,
                "rights":"user_local_only", "verifiedAt":witness.observed_at,
            }),
        )
        .map_err(|_| invalid())?;
    let raw = parse_json(&bytes).map_err(|_| invalid())?;
    if raw.as_object().is_none_or(|o| o.len() != 4)
        || raw["format"] != NATIVE_REGISTRY_FORMAT
        || ["blocks", "items", "entityTypes"]
            .iter()
            .any(|field| raw[*field].as_array().is_none_or(|a| a.len() > 100_000))
        || canonical_digest(&raw).map_err(|_| invalid())? != witness.registry_digest
    {
        return Err(invalid());
    }
    Ok(witness)
}

/// A real validated failure response remains private and typed even when no
/// source grant exists yet. Formatting never prints its original body.
pub(crate) struct NativeCatalogHostFailure {
    pub(crate) response: Value,
}
impl std::fmt::Debug for NativeCatalogHostFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeCatalogHostFailure")
            .field("has_response", &self.response.is_object())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for NativeCatalogHostFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Opaque original native catalog failure response retained")
    }
}
impl std::error::Error for NativeCatalogHostFailure {}
fn text<'a>(value: &'a Value, field: &str) -> AppResult<&'a str> {
    value.get(field).and_then(Value::as_str).ok_or_else(invalid)
}
fn service_error(cause: crate::service::ServiceError) -> AppError {
    AppError::caused_by(cause.code, cause.message, cause)
}
fn denied() -> AppError {
    AppError::new(
        "PERMISSION_REQUIRED",
        "Current explicit native observation source authority required",
    )
}
fn invalid() -> AppError {
    AppError::new(
        "SOURCE_INVALID",
        "Actual native catalog observation is invalid",
    )
}
fn drift() -> AppError {
    AppError::new("TARGET_DRIFT", "Actual native catalog observation changed")
}

#[cfg(test)]
#[path = "native_catalog_tests.rs"]
mod tests;

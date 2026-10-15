//! Native-owner approval and current host inspection converge on the adapter's
//! one compatibility binder. Protected facts never become a cached execution
//! grant, a second planner, or a second operation ledger.

use crate::{
    auth::AuthenticatedPrincipal,
    authority::LocalAuthority,
    bootstrap::NativeWorkspacePermit,
    host::{HostBridge, NativePairingOwnerFailure},
    service::{RequestBudget, RequestContextSlot},
    workspace_bootstrap::{NativeOwnerWitness, native_owner_resource_reader},
};
use mmmm_adapters::{
    ActionReadiness, Availability, Binding, BindingSupport, BindingValue, CompatibilityBindRequest,
    CompatibilityEvidence, CompatibilityProfile, Completion, Effect, EnvironmentRef,
    InterfaceObservation, JavaResultCodec, JavaSignature, Loader, OriginKind, ProfileApproval,
    ProviderDescriptor, ProviderRegistry, Receiver, RegistrationMode, RouteContext, Side,
    ThreadAffinity,
};
use mmmm_application::{Access, AppError, AppResult};
use mmmm_contracts::{
    ContextId, ContractValidator, JsonLimits, PrincipalId, ProjectId, ResourceId, Sha256Digest,
    canonical_digest, encode_json, projected_digest,
    strict_json::{ControlledJsonError, parse_json_with_control},
};
use mmmm_runtime::storage::{
    DurableStore, StorageError, StorageResult,
    bootstrap::POLICY_MEDIA_TYPE,
    compatibility_approval::{
        CompatibilityApprovalAuthority, CompatibilityApprovalRecord,
        CompatibilityApprovalRegistration, CompatibilityApprovalRpcContext,
        MAX_COMPATIBILITY_PROFILE_BYTES, compatibility_approval, compatibility_approval_references,
        register_compatibility_approval,
    },
    project_resources::{
        ProjectHeadPin, ProjectResourceQuery, ProjectResourceRequest, ProjectSourceRpcContext,
        current_project_head_pin,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{cell::RefCell, collections::BTreeSet, rc::Rc};

const MAX_POLICY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PROJECT_BYTES: usize = 8 * 1024 * 1024;
const MAX_INTERFACE_BYTES: usize = 128 * 1024;
const MAX_BOOTSTRAP_PROFILE_BYTES: usize = 256 * 1024;
const MAX_BOOTSTRAP_METADATA_BYTES: usize = 1024 * 1024;

/// Explicit native management selects a registered source. These locators and
/// expectations contain no owner, rights flag or caller-created approval body.
#[derive(Clone, Debug)]
pub struct NativeCompatibilityApprovalSelection {
    pub project_id: ProjectId,
    pub expected_project_revision: Sha256Digest,
    pub approved_profile_ref: String,
    pub profile_resource_id: ResourceId,
    pub profile_resource_sha256: Sha256Digest,
    pub artifact_digest: Sha256Digest,
    pub allowed_interface_digest: Sha256Digest,
}

/// An exact protected read for native bootstrap. No serde constructor, reusable
/// owner witness or execution permission escapes this finite checked operation.
pub struct NativeApprovedCompatibilityProfile {
    record: CompatibilityApprovalRecord,
    profile: CompatibilityProfile,
    bytes: Vec<u8>,
}
impl std::fmt::Debug for NativeApprovedCompatibilityProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeApprovedCompatibilityProfile")
            .finish_non_exhaustive()
    }
}
impl NativeApprovedCompatibilityProfile {
    pub fn record(&self) -> &CompatibilityApprovalRecord {
        &self.record
    }
    pub fn profile(&self) -> &CompatibilityProfile {
        &self.profile
    }
    pub fn profile_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// This native-only operation is the explicit local-use approval action. It
/// neither approves redistribution nor executes Java. The one held Store keeps
/// its existing native-owner lock and transaction/fence rules.
pub fn approve_native_compatibility_profile(
    store: &mut DurableStore,
    owner: &NativeOwnerWitness,
    budget: &RequestBudget,
    selected: &NativeCompatibilityApprovalSelection,
) -> AppResult<CompatibilityApprovalRecord> {
    let source = ApprovalSource::new(store, owner, &selected.project_id, budget, None)?;
    if source.revision != selected.expected_project_revision {
        return Err(stale());
    }
    let resource = source.profile_metadata(store, &selected.profile_resource_id)?;
    if resource["sha256"] != selected.profile_resource_sha256.as_str() {
        return Err(untrusted());
    }
    let (_, profile) = source.profile(store, &resource)?;
    let profile_digest = projected_digest(
        "CompatibilityProfile",
        &serde_json::to_value(&profile).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    check_profile_pins(&profile, &profile_digest, &selected.artifact_digest)?;
    let policy_revision = source.policy_digest(store)?;
    let registration = CompatibilityApprovalRegistration {
        project_id: selected.project_id.clone(),
        approved_profile_ref: selected.approved_profile_ref.clone(),
        profile_resource: resource.clone(),
        profile_digest,
        artifact_digest: selected.artifact_digest.clone(),
        allowed_interface_digest: selected.allowed_interface_digest.clone(),
        policy_revision,
        scope_digest: local_use_scope(&selected.project_id, &resource)?,
    };
    let mut authority = ApprovalAuthority {
        source: &source,
        registration: Some(&registration),
    };
    // Runtime returns its committed receipt directly. No fallible post-commit
    // check reclassifies a completed approval as rollback or a safe retry.
    register_compatibility_approval(store, &source, &mut authority, &registration)
        .map_err(|cause| source.release(cause))
}

/// Native bootstrap uses the same protected read as FN19. Passing a reference
/// or importing an identical CAS/JSON body never issues this result by itself.
pub fn read_native_compatibility_profile(
    store: &DurableStore,
    owner: &NativeOwnerWitness,
    budget: &RequestBudget,
    project: &ProjectId,
    approved_profile_ref: &str,
) -> AppResult<NativeApprovedCompatibilityProfile> {
    let source = ApprovalSource::new(store, owner, project, budget, None)?;
    source.approved(store, approved_profile_ref)
}

/// References originate only in the protected native-owner journal. This
/// bounded all-or-error batch performs no host call or class lookup; native
/// bootstrap decides how an unavailable optional compatibility batch is shown.
/// Its outer private transport must also enforce its actual 1MiB frame cap.
pub fn read_native_compatibility_profiles(
    store: &DurableStore,
    owner: &NativeOwnerWitness,
    budget: &RequestBudget,
    project: &ProjectId,
) -> AppResult<Vec<NativeApprovedCompatibilityProfile>> {
    let source = ApprovalSource::new(store, owner, project, budget, None)?;
    let references = compatibility_approval_references(store, &source, project)
        .map_err(|cause| source.release(cause))?;
    if references.len() > 128 {
        return Err(bounded());
    }
    let mut profiles = Vec::new();
    let mut raw_bytes = 0_usize;
    let mut metadata_bytes = 0_usize;
    for reference in references {
        let approved = source.approved(store, &reference)?;
        raw_bytes = raw_bytes
            .checked_add(approved.bytes.len())
            .ok_or_else(bounded)?;
        let utf8 = std::str::from_utf8(&approved.bytes).map_err(|_| invalid())?;
        // Include escaping overhead and all source pins, never secret paths or
        // witness/authority state. The caller retains the original raw bytes.
        let encoded = encode_json(&json!({
            "approvedProfileRef":approved.record.approved_profile_ref(),
            "profileBytesUtf8":utf8,"profileResource":approved.record.profile_resource(),
            "profileDigest":approved.record.profile_digest(),"artifactDigest":approved.record.artifact_digest(),
            "allowedInterfaceDigest":approved.record.allowed_interface_digest(),
            "policyRevision":approved.record.policy_revision(),"scopeDigest":approved.record.scope_digest(),
            "localUseOnly":true,
        })).map_err(|_| invalid())?;
        metadata_bytes = metadata_bytes
            .checked_add(encoded.len())
            .and_then(|n| n.checked_add(1))
            .ok_or_else(bounded)?;
        if raw_bytes > MAX_BOOTSTRAP_PROFILE_BYTES
            || metadata_bytes > MAX_BOOTSTRAP_METADATA_BYTES - 2
        {
            return Err(bounded());
        }
        profiles.push(approved);
    }
    source.check_store(store)?;
    Ok(profiles)
}

struct ApprovalSource<'a> {
    store: *const DurableStore,
    root: std::path::PathBuf,
    owner: &'a NativeOwnerWitness,
    project: ProjectId,
    project_value: Value,
    project_head: ProjectHeadPin,
    revision: Sha256Digest,
    budget: &'a RequestBudget,
    current: Option<&'a dyn Fn() -> AppResult<()>>,
    first_failure: RefCell<Option<AppError>>,
}
impl<'a> ApprovalSource<'a> {
    fn new(
        store: &DurableStore,
        owner: &'a NativeOwnerWitness,
        project: &ProjectId,
        budget: &'a RequestBudget,
        current: Option<&'a dyn Fn() -> AppResult<()>>,
    ) -> AppResult<Self> {
        source_checkpoint(owner, budget, current)?;
        owner.check_project(store, project).map_err(storage_error)?;
        let project_head = combine(
            current_project_head_pin(store, owner, project).map_err(storage_error),
            source_checkpoint(owner, budget, current),
        )?;
        admit_project_head(&project_head)?;
        let mut source = Self {
            store: store as *const DurableStore,
            root: store.data_root().to_path_buf(),
            owner,
            project: project.clone(),
            // Only the original request RPC is used during this bounded read;
            // no partially read source is returned or passed to an approval.
            project_value: Value::Null,
            revision: project_head.revision.clone(),
            project_head,
            budget,
            current,
            first_failure: RefCell::new(None),
        };
        let mut reader = source.reader(BTreeSet::new(), MAX_PROJECT_BYTES as u64)?;
        source.project_value = reader
            .read_project(
                store,
                &source,
                project,
                &source.revision,
                MAX_PROJECT_BYTES as u64,
            )
            .map_err(|cause| source.release(cause))?;
        source.check_store(store)?;
        Ok(source)
    }
    fn check_local(&self) -> AppResult<()> {
        source_checkpoint(self.owner, self.budget, self.current)
    }
    fn check_store(&self, store: &DurableStore) -> AppResult<()> {
        self.check_local()?;
        if !std::ptr::eq(store, self.store) || store.data_root() != self.root {
            return Err(denied());
        }
        self.owner
            .check_project(store, &self.project)
            .map_err(storage_error)?;
        let actual = current_project_head_pin(store, self, &self.project)
            .map_err(|cause| self.release(cause))?;
        same_project_head(&self.project_head, &actual)?;
        self.check_local()
    }
    fn reject(&self, cause: AppError) -> StorageError {
        let mut first = self.first_failure.borrow_mut();
        if first.is_none() {
            *first = Some(cause);
        }
        StorageError::Conflict("Current compatibility source authority required")
    }
    fn release(&self, cause: StorageError) -> AppError {
        self.first_failure
            .borrow_mut()
            .take()
            .unwrap_or_else(|| storage_error(cause))
    }
    fn reader(
        &self,
        ids: BTreeSet<ResourceId>,
        ceiling: u64,
    ) -> AppResult<mmmm_runtime::storage::project_resources::ProjectResourceReader> {
        native_owner_resource_reader(self.owner, &self.project, &self.revision, ids, ceiling)
            .map_err(storage_error)
    }
    fn profile_metadata(&self, store: &DurableStore, id: &ResourceId) -> AppResult<Value> {
        self.check_store(store)?;
        let mut reader = self.reader(
            BTreeSet::from([id.clone()]),
            MAX_COMPATIBILITY_PROFILE_BYTES,
        )?;
        let query = ProjectResourceQuery::RegisteredImmutable {
            resource_id: id.clone(),
        };
        let actual = reader
            .metadata(
                store,
                self,
                &ProjectResourceRequest {
                    project: &self.project,
                    current_project_revision: &self.revision,
                    query: &query,
                    expected: None,
                },
            )
            .map_err(|cause| self.release(cause))?;
        self.check_store(store)?;
        Ok(actual.resource)
    }
    fn profile(
        &self,
        store: &DurableStore,
        resource: &Value,
    ) -> AppResult<(Vec<u8>, CompatibilityProfile)> {
        self.check_store(store)?;
        let id: ResourceId = decode(&resource["resourceId"])?;
        let mut reader = self.reader(
            BTreeSet::from([id.clone()]),
            MAX_COMPATIBILITY_PROFILE_BYTES,
        )?;
        let query = ProjectResourceQuery::RegisteredImmutable { resource_id: id };
        let actual = reader
            .read(
                store,
                self,
                &ProjectResourceRequest {
                    project: &self.project,
                    current_project_revision: &self.revision,
                    query: &query,
                    expected: Some(resource),
                },
                MAX_COMPATIBILITY_PROFILE_BYTES,
            )
            .map_err(|cause| self.release(cause))?;
        let value = self.parse(&actual.bytes, MAX_COMPATIBILITY_PROFILE_BYTES as usize)?;
        validate("CompatibilityProfile", &value)?;
        let profile: CompatibilityProfile = decode(&value)?;
        supported_read(&profile)?;
        self.check_store(store)?;
        Ok((actual.bytes, profile))
    }
    fn policy_digest(&self, store: &DurableStore) -> AppResult<Sha256Digest> {
        self.check_store(store)?;
        let id: ResourceId = decode(&self.project_value["policyResourceId"])?;
        let mut reader = self.reader(BTreeSet::from([id.clone()]), MAX_POLICY_BYTES)?;
        let query = ProjectResourceQuery::Current { resource_id: id };
        let request = ProjectResourceRequest {
            project: &self.project,
            current_project_revision: &self.revision,
            query: &query,
            expected: None,
        };
        let metadata = reader
            .metadata(store, self, &request)
            .map_err(|cause| self.release(cause))?;
        if metadata.resource["mediaType"] != POLICY_MEDIA_TYPE {
            return Err(denied());
        }
        let bytes = reader
            .read(
                store,
                self,
                &ProjectResourceRequest {
                    expected: Some(&metadata.resource),
                    ..request
                },
                MAX_POLICY_BYTES,
            )
            .map_err(|cause| self.release(cause))?
            .bytes;
        let policy = self.parse(&bytes, MAX_POLICY_BYTES as usize)?;
        validate("Policy", &policy)?;
        let digest = projected_digest("Policy", &policy).map_err(|_| invalid())?;
        self.check_store(store)?;
        Ok(digest)
    }
    fn parse(&self, bytes: &[u8], ceiling: usize) -> AppResult<Value> {
        parse_json_with_control(
            bytes,
            JsonLimits {
                max_bytes: ceiling,
                max_depth: 64,
                max_nodes: 100_000,
            },
            || self.check_local(),
        )
        .map_err(|cause| match cause {
            ControlledJsonError::Control(cause) => cause,
            ControlledJsonError::Json(_) => invalid(),
        })
    }
    fn validate_pins(
        &self,
        store: &DurableStore,
        pins: &CompatibilityApprovalRegistration,
    ) -> AppResult<()> {
        self.check_store(store)?;
        if pins.project_id != self.project
            || pins.policy_revision != self.policy_digest(store)?
            || pins.scope_digest != local_use_scope(&self.project, &pins.profile_resource)?
        {
            return Err(untrusted());
        }
        let (_, profile) = self.profile(store, &pins.profile_resource)?;
        check_profile_pins(&profile, &pins.profile_digest, &pins.artifact_digest)?;
        self.check_store(store)
    }
    fn approved(
        &self,
        store: &DurableStore,
        reference: &str,
    ) -> AppResult<NativeApprovedCompatibilityProfile> {
        let mut authority = ApprovalAuthority {
            source: self,
            registration: None,
        };
        let record = compatibility_approval(store, self, &mut authority, &self.project, reference)
            .map_err(|cause| self.release(cause))?
            .ok_or_else(untrusted)?;
        let (bytes, profile) = self.profile(store, record.profile_resource())?;
        self.check_store(store)?;
        Ok(NativeApprovedCompatibilityProfile {
            record,
            profile,
            bytes,
        })
    }
}
fn source_checkpoint(
    owner: &NativeOwnerWitness,
    budget: &RequestBudget,
    current: Option<&dyn Fn() -> AppResult<()>>,
) -> AppResult<()> {
    budget.check().map_err(service_error)?;
    if let Some(current) = current {
        current()?;
    }
    owner.check().map_err(storage_error)?;
    budget.check().map_err(service_error)
}
fn admit_project_head(head: &ProjectHeadPin) -> AppResult<()> {
    if head.blob.byte_length == 0 || head.blob.byte_length > MAX_PROJECT_BYTES as u64 {
        return Err(bounded());
    }
    Ok(())
}
fn same_project_head(expected: &ProjectHeadPin, actual: &ProjectHeadPin) -> AppResult<()> {
    if expected != actual {
        return Err(stale());
    }
    Ok(())
}
impl CompatibilityApprovalRpcContext for ApprovalSource<'_> {
    fn check(&self) -> StorageResult<()> {
        self.check_local().map_err(|cause| self.reject(cause))
    }
    fn authenticated_local_owner(&self) -> StorageResult<PrincipalId> {
        CompatibilityApprovalRpcContext::check(self)?;
        Ok(self.owner.principal().clone())
    }
}
impl ProjectSourceRpcContext for ApprovalSource<'_> {
    fn check(&self) -> StorageResult<()> {
        CompatibilityApprovalRpcContext::check(self)
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        CompatibilityApprovalRpcContext::authenticated_local_owner(self)
    }
    fn context_id(&self) -> Option<&ContextId> {
        None
    }
}
struct ApprovalAuthority<'a, 'b> {
    source: &'a ApprovalSource<'b>,
    registration: Option<&'a CompatibilityApprovalRegistration>,
}
impl CompatibilityApprovalAuthority for ApprovalAuthority<'_, '_> {
    fn authorize_registration(
        &mut self,
        store: &DurableStore,
        owner: &PrincipalId,
        request: &CompatibilityApprovalRegistration,
    ) -> StorageResult<()> {
        let result = (|| {
            let selected = self.registration.ok_or_else(denied)?;
            if owner != self.source.owner.principal() || !same_registration(selected, request) {
                return Err(denied());
            }
            self.source.validate_pins(store, request)
        })();
        result.map_err(|cause| self.source.reject(cause))
    }
    fn authorize_read(
        &mut self,
        store: &DurableStore,
        owner: &PrincipalId,
        record: &CompatibilityApprovalRecord,
    ) -> StorageResult<()> {
        let result = (|| {
            if owner != self.source.owner.principal()
                || record.native_owner() != owner
                || record.project_id() != &self.source.project
                || !record.local_use_only()
            {
                return Err(denied());
            }
            self.source.validate_pins(store, &registration(record))
        })();
        result.map_err(|cause| self.source.reject(cause))
    }
}
fn registration(record: &CompatibilityApprovalRecord) -> CompatibilityApprovalRegistration {
    CompatibilityApprovalRegistration {
        project_id: record.project_id().clone(),
        approved_profile_ref: record.approved_profile_ref().into(),
        profile_resource: record.profile_resource().clone(),
        profile_digest: record.profile_digest().clone(),
        artifact_digest: record.artifact_digest().clone(),
        allowed_interface_digest: record.allowed_interface_digest().clone(),
        policy_revision: record.policy_revision().clone(),
        scope_digest: record.scope_digest().clone(),
    }
}
fn same_registration(
    a: &CompatibilityApprovalRegistration,
    b: &CompatibilityApprovalRegistration,
) -> bool {
    a.project_id == b.project_id
        && a.approved_profile_ref == b.approved_profile_ref
        && a.profile_resource == b.profile_resource
        && a.profile_digest == b.profile_digest
        && a.artifact_digest == b.artifact_digest
        && a.allowed_interface_digest == b.allowed_interface_digest
        && a.policy_revision == b.policy_revision
        && a.scope_digest == b.scope_digest
}
fn local_use_scope(project: &ProjectId, resource: &Value) -> AppResult<Sha256Digest> {
    canonical_digest(&json!({"kind":"mmmm.compatibility-local-profile-use/1",
        "projectId":project,"profileResource":resource,"localUseOnly":true}))
    .map_err(|_| invalid())
}
fn check_profile_pins(
    profile: &CompatibilityProfile,
    digest: &Sha256Digest,
    artifact: &Sha256Digest,
) -> AppResult<()> {
    supported_read(profile)?;
    let value = serde_json::to_value(profile).map_err(|_| invalid())?;
    if projected_digest("CompatibilityProfile", &value).map_err(|_| invalid())? != *digest
        || &profile.action.implementation_digest != artifact
    {
        return Err(untrusted());
    }
    Ok(())
}
fn supported_read(profile: &CompatibilityProfile) -> AppResult<()> {
    if profile.action.effect != Effect::Read
        || profile.action.side != Side::Server
        || profile.action.completion != Completion::Synchronous
        || profile.applicability.loader != Loader::Fabric
        || profile.applicability.side != Side::Server
        || profile.applicability.supported_game_versions.len() != 1
        || profile
            .applicability
            .supported_game_versions
            .first()
            .map(String::as_str)
            != Some("26.3")
    {
        return Err(unsupported());
    }
    match &profile.binding {
        Binding::PublicJava {
            receiver: Receiver::Static,
            receiver_handle_type: None,
            result_codec: JavaResultCodec::Scalar,
            arguments,
            ..
        } if !arguments
            .iter()
            .any(|value| matches!(value, BindingValue::Handle { .. })) =>
        {
            Ok(())
        }
        _ => Err(unsupported()),
    }
}

/// One actual composition handle serves FN19 and inventory. It retains channel
/// and request registries, never an approval body, owner witness, stale profile,
/// descriptor, readiness result or long-lived source grant.
#[derive(Clone)]
pub struct RegisteredCompatibilityProfiles(Rc<CompatibilityComposition>);
struct CompatibilityComposition {
    request: RequestContextSlot,
    authority: LocalAuthority,
    hosts: HostBridge,
}
impl RegisteredCompatibilityProfiles {
    pub fn new(request: RequestContextSlot, authority: LocalAuthority, hosts: HostBridge) -> Self {
        Self(Rc::new(CompatibilityComposition {
            request,
            authority,
            hosts,
        }))
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "One held Store, authenticated route, permissions, exact input and original budget are separate authorities"
    )]
    pub fn bind(
        &self,
        store: &DurableStore,
        principal: &AuthenticatedPrincipal,
        context: &Value,
        permissions: &BTreeSet<String>,
        input: &Value,
        budget: &RequestBudget,
    ) -> AppResult<ProviderDescriptor> {
        let mut registry = ProviderRegistry::new();
        self.bind_into(
            store,
            principal,
            context,
            permissions,
            input,
            &mut registry,
            budget,
        )
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Existing inventory supplies its own canonical registry while every current authority remains explicit"
    )]
    pub fn bind_into(
        &self,
        store: &DurableStore,
        principal: &AuthenticatedPrincipal,
        context: &Value,
        permissions: &BTreeSet<String>,
        input: &Value,
        registry: &mut ProviderRegistry,
        budget: &RequestBudget,
    ) -> AppResult<ProviderDescriptor> {
        validate("CompatibilityBindRequest", input)?;
        let request: CompatibilityBindRequest = decode(input)?;
        self.with_approved(
            store,
            principal,
            context,
            budget,
            &request.approved_profile_ref,
            |approved| {
                let profile = serde_json::to_value(&approved.profile).map_err(|_| invalid())?;
                if input["profile"] != profile
                    || request.profile_digest != *approved.record.profile_digest()
                {
                    return Err(untrusted());
                }
                self.bind_current(
                    context,
                    permissions,
                    input,
                    approved,
                    None,
                    registry,
                    budget,
                )
            },
        )
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "The shared approval reader must compare an actual host descriptor inside the existing inventory registry"
    )]
    pub fn bind_registered_into(
        &self,
        store: &DurableStore,
        principal: &AuthenticatedPrincipal,
        context: &Value,
        permissions: &BTreeSet<String>,
        provider: &ProviderDescriptor,
        registry: &mut ProviderRegistry,
        budget: &RequestBudget,
    ) -> AppResult<ProviderDescriptor> {
        if provider.registration_mode != RegistrationMode::Compatibility
            || provider.origin.kind != OriginKind::LocalProfile
        {
            return Err(untrusted());
        }
        self.with_approved(store, principal, context, budget, &provider.origin.source_id, |approved| {
            let input = json!({"profile":approved.profile,"profileDigest":approved.record.profile_digest(),
                "approvedProfileRef":approved.record.approved_profile_ref(),
                "contextId":context["contextId"],"environment":context["environment"]});
            self.bind_current(context, permissions, &input, approved, Some(provider), registry, budget)
        })
    }
    fn with_approved<T>(
        &self,
        store: &DurableStore,
        principal: &AuthenticatedPrincipal,
        context: &Value,
        budget: &RequestBudget,
        reference: &str,
        bind: impl FnOnce(&NativeApprovedCompatibilityProfile) -> AppResult<T>,
    ) -> AppResult<T> {
        let request = self.0.request.occupied_witness().map_err(service_error)?;
        if !request.authenticated().same_session(principal)
            || request.budget().deadline() != budget.deadline()
            || !std::ptr::eq(request.budget().cancellation(), budget.cancellation())
        {
            return Err(denied());
        }
        let id: ContextId = decode(&context["contextId"])?;
        let project: ProjectId = decode(&context["projectId"])?;
        let pairing = self
            .0
            .hosts
            .completed_pairing_witness(&request, &self.0.authority, &id)?;
        let checkpoint = || -> AppResult<()> {
            request.check_local().map_err(service_error)?;
            pairing.check_current(&self.0.authority)?;
            if pairing.project() != &project || pairing.context() != context {
                return Err(stale());
            }
            self.0.authority.authorize_with_deadline(
                principal.principal(),
                &project,
                Access::ReadProject,
                Some(context),
                None,
                budget.deadline(),
            )?;
            request.check_local().map_err(service_error)
        };
        checkpoint()?;
        pairing.with_current_native_owner(store, &self.0.authority, |current| {
            current.check_current()?;
            // Capture remains inside the guarded request, under its original
            // deadline, and is never stored in the shared registry or returned.
            let owner =
                NativeOwnerWitness::capture(store, budget.deadline()).map_err(storage_error)?;
            if owner.principal() != pairing.native_owner() {
                return Err(denied());
            }
            let source = ApprovalSource::new(store, &owner, &project, budget, Some(&checkpoint))?;
            let result = source
                .approved(store, reference)
                .and_then(|approved| bind(&approved));
            combine(result, source.check_store(store))
        })
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Host inventory comparison is distinct from the canonical input, current route and destination registry"
    )]
    fn bind_current(
        &self,
        context: &Value,
        permissions: &BTreeSet<String>,
        input: &Value,
        approved: &NativeApprovedCompatibilityProfile,
        expected: Option<&ProviderDescriptor>,
        registry: &mut ProviderRegistry,
        budget: &RequestBudget,
    ) -> AppResult<ProviderDescriptor> {
        budget.check().map_err(service_error)?;
        let principal: PrincipalId = decode(&context["principalRef"])?;
        let id: ContextId = decode(&context["contextId"])?;
        let reply = self.0.hosts.inspect_with_deadline(&principal, &id, json!({
            "kind":"compatibility_interface","approvedProfileRef":approved.record.approved_profile_ref(),
            "profileDigest":approved.record.profile_digest(),
        }), budget.deadline())?;
        if encode_json(&reply).map_err(|_| invalid())?.len() > MAX_INTERFACE_BYTES {
            return Err(bounded());
        }
        validate("ProviderDescriptor", &reply["registeredProvider"])?;
        let reply: InterfaceReply = decode(&reply)?;
        if reply.profile_digest != *approved.record.profile_digest() {
            return Err(untrusted());
        }
        let observation = reply.interface.observation()?;
        if observation.implementation_digest != *approved.record.artifact_digest()
            || observation.interface_digest().map_err(adapter_error)?
                != *approved.record.allowed_interface_digest()
        {
            return Err(untrusted());
        }
        let route = RouteContext::from_execution_context(context, permissions.clone())
            .map_err(adapter_error)?;
        let approval = ProfileApproval {
            reference: approved.record.approved_profile_ref().into(),
            source_id: approved.record.approved_profile_ref().into(),
            profile_digest: approved.record.profile_digest().clone(),
            allowed_interface_digest: approved.record.allowed_interface_digest().clone(),
        };
        // Validate the full host descriptor before publishing to the caller's
        // registry. A failed host comparison leaves no partial registration.
        let mut checked = ProviderRegistry::new();
        let descriptor = checked
            .bind_compatibility(input, &route, &approval, &observation)
            .map_err(adapter_error)?;
        if serde_json::to_value(&descriptor).map_err(|_| invalid())?
            != serde_json::to_value(reply.registered_provider).map_err(|_| invalid())?
        {
            return Err(untrusted());
        }
        if let Some(expected) = expected
            && serde_json::to_value(&descriptor).map_err(|_| invalid())?
                != serde_json::to_value(expected).map_err(|_| invalid())?
        {
            return Err(untrusted());
        }
        budget.check().map_err(service_error)?;
        registry
            .bind_compatibility(input, &route, &approval, &observation)
            .map_err(adapter_error)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InterfaceReply {
    profile_digest: Sha256Digest,
    registered_provider: ProviderDescriptor,
    interface: JavaInterfaceFacts,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JavaInterfaceFacts {
    environment: EnvironmentRef,
    loader: Loader,
    target_game_version: String,
    #[serde(deserialize_with = "present_nullable")]
    mod_id: Option<String>,
    mod_version: String,
    host_protocol_version: String,
    implementation_digest: Sha256Digest,
    loaded: bool,
    connected: bool,
    availability: Availability,
    readiness: ReadinessFacts,
    support: JavaSupportFacts,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadinessFacts {
    ready: bool,
    #[serde(deserialize_with = "present_nullable")]
    possible_loss_codes: Option<BTreeSet<String>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JavaSupportFacts {
    kind: String,
    signature: SignatureFacts,
    public_lookup_checked: bool,
    initialization_performed: bool,
    thread_affinity: String,
    #[serde(deserialize_with = "present_nullable")]
    receiver_resolver: Option<String>,
    scoped_handle_types: BTreeSet<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignatureFacts {
    owner_class: String,
    method_name: String,
    parameter_types: Vec<String>,
    return_type: String,
    receiver: Receiver,
}
impl JavaInterfaceFacts {
    fn observation(self) -> AppResult<InterfaceObservation> {
        let support = self.support;
        if support.kind != "public_java"
            || !support.public_lookup_checked
            || support.initialization_performed
            || support.thread_affinity != "server_main"
            || support.signature.receiver != Receiver::Static
            || support.receiver_resolver.is_some()
            || !support.scoped_handle_types.is_empty()
            || self.loader != Loader::Fabric
            || self.environment.execution_side() != Some(Side::Server)
            || self.target_game_version != "26.3"
        {
            return Err(unsupported());
        }
        Ok(InterfaceObservation {
            environment: self.environment,
            loader: self.loader,
            target_game_version: self.target_game_version,
            mod_id: self.mod_id,
            mod_version: self.mod_version,
            host_protocol_version: self.host_protocol_version,
            implementation_digest: self.implementation_digest,
            loaded: self.loaded,
            connected: self.connected,
            availability: self.availability,
            evidence: CompatibilityEvidence::InterfaceChecked,
            readiness: ActionReadiness {
                ready: self.readiness.ready,
                possible_loss_codes: self.readiness.possible_loss_codes,
            },
            support: BindingSupport::PublicJava {
                signature: JavaSignature {
                    owner_class: support.signature.owner_class,
                    method_name: support.signature.method_name,
                    parameter_types: support.signature.parameter_types,
                    return_type: support.signature.return_type,
                    receiver: support.signature.receiver,
                },
                public_lookup_checked: true,
                initialization_performed: false,
                thread_affinity: ThreadAffinity::ServerMain,
                receiver_resolver: None,
                scoped_handle_types: BTreeSet::new(),
            },
        })
    }
}
fn combine<T>(result: AppResult<T>, checkpoint: AppResult<()>) -> AppResult<T> {
    match (result, checkpoint) {
        (Ok(value), Ok(())) => Ok(value),
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
fn validate(definition: &str, value: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .map_err(|_| invalid())?
        .validate(definition, value)
        .map_err(|_| invalid())
}
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> AppResult<T> {
    serde_json::from_value(value.clone()).map_err(|_| invalid())
}
fn present_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
fn service_error(cause: crate::service::ServiceError) -> AppError {
    AppError::caused_by(cause.code, cause.message, cause)
}
fn storage_error(cause: StorageError) -> AppError {
    AppError::storage("PROFILE_UNTRUSTED", cause)
}
fn adapter_error(cause: mmmm_adapters::AdapterError) -> AppError {
    AppError::caused_by(cause.code, "Compatibility binding failed", cause)
}
fn invalid() -> AppError {
    AppError::new("INVALID_INPUT", "Compatibility input is invalid")
}
fn denied() -> AppError {
    AppError::new(
        "PERMISSION_REQUIRED",
        "Current native owner and Project source access required",
    )
}
fn untrusted() -> AppError {
    AppError::new(
        "PROFILE_UNTRUSTED",
        "Exact protected profile approval required",
    )
}
fn stale() -> AppError {
    AppError::new(
        "STALE_CONTEXT",
        "Compatibility context or Project source changed",
    )
}
fn bounded() -> AppError {
    AppError::new(
        "BUDGET_EXCEEDED",
        "Compatibility metadata exceeds its finite budget",
    )
}
fn unsupported() -> AppError {
    AppError::new(
        "CAPABILITY_UNAVAILABLE",
        "Compatibility interface is unsupported",
    )
}

#[cfg(test)]
#[path = "compatibility_registration_tests.rs"]
mod tests;

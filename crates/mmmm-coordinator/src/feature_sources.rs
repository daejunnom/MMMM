//! Production feature sources share the authenticated request, live authority
//! and one borrowed store. Public DTOs name sources; they do not register them.
use crate::{
    auth::AuthenticatedPrincipal,
    authority::LocalAuthority,
    catalog_source::RegisteredCatalogSources,
    features::{
        CaptureInputs, FeatureAccess, FeatureResourcePort, FeatureSources, ManualSceneInputs,
        MathInputs, PackInputs,
    },
    host::HostBridge,
    planning_context::{SharedRegisteredPlanningContexts, checked_current_project_catalog},
    planning_source::{
        BorrowedProjectSource, ConcretePlanningEnvironment, LocalPlanningAccess,
        ObservedStateSnapshot, PlanningDataPort, PlanningStore, SharedPlanningBackend,
        SharedPlanningContexts, SharedPlanningData, SharedPlanningDependencies,
    },
    production_factory::RegisteredCompatibilityProfiles,
    service::{RequestBudget, RequestContextSlot, ServiceError},
};
use mmmm_adapters::{InventorySnapshot, ProviderDescriptor};
use mmmm_application::{Access, AppError, AppResult};
use mmmm_compiler::ResolvedSymbols;
use mmmm_contracts::strict_json::{ControlledJsonError, parse_json_with_control};
use mmmm_contracts::{
    ContextId, ContractValidator, JsonLimits, PrincipalId, ProjectId, ResourceId, Sha256Digest,
    SnapshotId, TargetProfileId, canonical_digest, encode_json, raw_digest,
};
use mmmm_domain::types::ResourceRef;
use mmmm_exchange::{
    ExchangeError, ExchangeResult,
    patch::{DeltaPolicy, SceneEdit, diff_scene_edits},
    resources::{AuthorizedBytes, Redistribution, ResourcePort, ResourcePurpose, verify_resource},
    selection::{ObjectNode, Selection},
};
use mmmm_planner::{
    ObjectPin, OwnedKind, PlanningEnvironmentPort, ProjectCatalog, ProjectSourcePort, SceneSource,
};
use mmmm_reference::{AccessControl, ReadPrincipal};
use mmmm_runtime::{
    artifact::{
        ArtifactError, ArtifactResult, ResourceAuthority, ResourceOwner, register_resource,
    },
    storage::{
        DurableStore, StorageError, StorageResult,
        owned_documents::{
            OwnedDocumentAuthority, OwnedDocumentKind, OwnedDocumentPin, OwnedDocumentReader,
        },
        project_resources::{
            ProjectResourceAuthority, ProjectResourceQuery, ProjectResourceReader,
            ProjectResourceRequest, ProjectSourceRpcContext, RegisteredProjectResource,
        },
    },
};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

#[path = "feature_shapes.rs"]
mod shape_source;

const MAX_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CODEC_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REGISTRATIONS: usize = 4096;
const MAX_REGISTRY_BYTES: usize = 64 * 1024 * 1024;

/// Implemented only by the native owner from an actual active pairing record.
/// Required permissions in profiles or public JSON cannot populate this port.
pub trait FeaturePermissionPort {
    fn current(
        &self,
        principal: &AuthenticatedPrincipal,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<BTreeSet<String>>;
}
pub type SharedFeaturePermissions = Rc<dyn FeaturePermissionPort>;

/// Symbol payloads have no original public wire schema. The registered codec
/// receives exact authorized bytes and must verify current origin/NBT types.
pub trait FeatureSymbolPort {
    fn resolve(
        &mut self,
        principal: &AuthenticatedPrincipal,
        project: &ProjectCatalog,
        context: &Value,
        resource: &ResourceRef,
        bytes: &[u8],
        budget: &RequestBudget,
    ) -> AppResult<ResolvedSymbols>;
}
pub type SharedFeatureSymbols = Rc<RefCell<Box<dyn FeatureSymbolPort>>>;

/// A SourceRef's rights label is a declaration. This trusted verifier must
/// check an actual owner/license approval against the exact source and evidence
/// bytes. No default verifier or public approve-rights RPC exists.
pub trait SourceRightsVerifier {
    #[allow(
        clippy::too_many_arguments,
        reason = "Authenticated authority, exact source and resource pins, trusted source and evidence bytes, context and budget are independent verification inputs"
    )]
    fn verify(
        &mut self,
        principal: &AuthenticatedPrincipal,
        context: &Value,
        source: &Value,
        resource: &ResourceRef,
        bytes: &[u8],
        evidence: &ResourceRef,
        evidence_bytes: &[u8],
        budget: &RequestBudget,
    ) -> AppResult<Redistribution>;
}
pub struct ResourceRightsRegistration {
    pub source: Value,
    pub resource: ResourceRef,
    pub approval_evidence: ResourceRef,
}
#[derive(Clone)]
struct SourceBinding {
    principal: AuthenticatedPrincipal,
    project: ProjectId,
    project_revision: Sha256Digest,
    context: Value,
    policy: Sha256Digest,
    scope: Sha256Digest,
}
impl SourceBinding {
    fn capture(
        principal: &AuthenticatedPrincipal,
        project: &ProjectCatalog,
        context: &Value,
        authority: &LocalAuthority,
    ) -> AppResult<Self> {
        Ok(Self {
            principal: principal.clone(),
            project: project.project_id().clone(),
            project_revision: project.revision().clone(),
            context: context.clone(),
            policy: authority.policy_revision(principal.principal(), project.project_id())?,
            scope: canonical_digest(
                &authority.project_scope(principal.principal(), project.project_id())?,
            )
            .map_err(|_| invalid())?,
        })
    }
    fn matches(
        &self,
        principal: &AuthenticatedPrincipal,
        project: &ProjectCatalog,
        context: &Value,
        authority: &LocalAuthority,
    ) -> AppResult<bool> {
        Ok(self.principal.is_current()
            && principal.is_current()
            && self.principal.same_session(principal)
            && &self.project == project.project_id()
            && &self.project_revision == project.revision()
            && self.context == *context
            && self.policy
                == authority.policy_revision(principal.principal(), project.project_id())?
            && self.scope
                == canonical_digest(
                    &authority.project_scope(principal.principal(), project.project_id())?,
                )
                .map_err(|_| invalid())?)
    }
}
#[derive(Clone)]
struct RightsRecord {
    binding: SourceBinding,
    resource: ResourceRef,
    evidence: ResourceRef,
    source: Value,
    redistribution: Redistribution,
    weight: usize,
}
/// Exact server-owned rights observations. Project ownership and a retained
/// evidence blob alone never populate this map, including after restart.
#[derive(Default)]
pub struct ResourceRightsRegistry {
    records: BTreeMap<(ProjectId, ResourceId), RightsRecord>,
    bytes: usize,
}
pub type SharedResourceRights = Rc<RefCell<ResourceRightsRegistry>>;
impl ResourceRightsRegistry {
    #[allow(
        clippy::too_many_arguments,
        reason = "Current authenticated authority, durable source, Project and context, exact registration pins and trusted rights verifier remain separate"
    )]
    pub fn register(
        &mut self,
        principal: &AuthenticatedPrincipal,
        source: &mut BorrowedProjectSource<'_>,
        project: &ProjectCatalog,
        context: &Value,
        authority: &LocalAuthority,
        registration: ResourceRightsRegistration,
        verifier: &mut dyn SourceRightsVerifier,
    ) -> AppResult<()> {
        source.access().check()?;
        if !principal.is_current() || principal.principal() != source.access().principal() {
            return Err(forbidden());
        }
        validate("SourceRef", &registration.source)?;
        if encode_json(&registration.source)
            .map_err(|_| limit())?
            .len()
            > 64 * 1024
            || registration.resource.media_type.len() > 1024
            || registration.approval_evidence.media_type.len() > 1024
        {
            return Err(limit());
        }
        if registration.source["sha256"] != registration.resource.sha256.as_str()
            || registration.source["rights"] == "unknown"
        {
            return Err(forbidden());
        }
        let read = source.resource_bytes(
            principal.principal(),
            project,
            &registration.resource,
            Some(context),
            MAX_SOURCE_BYTES,
        )?;
        let evidence = source.resource_bytes(
            principal.principal(),
            project,
            &registration.approval_evidence,
            Some(context),
            MAX_CODEC_BYTES,
        )?;
        let redistribution = verifier.verify(
            principal,
            context,
            &registration.source,
            &read.resource,
            &read.bytes,
            &evidence.resource,
            &evidence.bytes,
            source.access().budget(),
        )?;
        if redistribution == Redistribution::Unknown {
            return Err(forbidden());
        }
        source.access().authorize_project(
            principal.principal(),
            project.project_id(),
            Some(context),
            Access::ReadProject,
        )?;
        let key = (
            project.project_id().clone(),
            registration.resource.resource_id.clone(),
        );
        if self.records.len() >= MAX_REGISTRATIONS && !self.records.contains_key(&key) {
            return Err(limit());
        }
        if let Some(old) = self.records.get(&key)
            && (!same_resource(&old.resource, &registration.resource)
                || !same_resource(&old.evidence, &registration.approval_evidence)
                || old.source != registration.source)
        {
            return Err(conflict());
        }
        let weight = record_cost(
            context,
            &registration.source,
            &[&registration.resource, &registration.approval_evidence],
        )?;
        let previous = self.records.get(&key).map_or(0, |old| old.weight);
        let total = self
            .bytes
            .checked_sub(previous)
            .and_then(|bytes| bytes.checked_add(weight))
            .ok_or_else(limit)?;
        if total > MAX_REGISTRY_BYTES {
            return Err(limit());
        }
        let record = RightsRecord {
            binding: SourceBinding::capture(principal, project, context, authority)?,
            resource: registration.resource,
            evidence: registration.approval_evidence,
            source: registration.source,
            redistribution,
            weight,
        };
        source.access().check()?;
        self.records.insert(key, record);
        self.bytes = total;
        source.access().check()
    }
    fn lookup(
        &self,
        principal: &AuthenticatedPrincipal,
        project: &ProjectCatalog,
        context: &Value,
        resource: &ResourceRef,
        authority: &LocalAuthority,
    ) -> AppResult<Redistribution> {
        let Some(record) = self
            .records
            .get(&(project.project_id().clone(), resource.resource_id.clone()))
        else {
            return Ok(Redistribution::Unknown);
        };
        if !same_resource(&record.resource, resource)
            || !record
                .binding
                .matches(principal, project, context, authority)?
        {
            return Ok(Redistribution::Unknown);
        }
        Ok(record.redistribution)
    }
}

/// Explicit canonical ScenePatch payload codec. Its source map must map each
/// /entries/index to the same qualified instance/node. No omitted node deletes.
#[derive(Clone)]
pub enum ManualSceneCodec {
    CanonicalScenePatch,
}
#[derive(Clone)]
pub struct ManualSceneRegistration {
    pub context_id: ContextId,
    pub source_artifact: ResourceRef,
    pub source_bundle: ResourceRef,
    pub source_request: ResourceRef,
    pub selection: ResourceRef,
    pub source_map: ResourceRef,
    pub edit_payload: ResourceRef,
    pub codec: ManualSceneCodec,
    pub policy: DeltaPolicy,
}
#[derive(Clone)]
struct ManualRecord {
    binding: SourceBinding,
    artifact: Value,
    selection_digest: Sha256Digest,
    selection: Value,
    source_map: Value,
    registration: ManualSceneRegistration,
    weight: usize,
}
#[derive(Default)]
pub struct ManualSceneRegistry {
    records: BTreeMap<(PrincipalId, String), ManualRecord>,
    bytes: usize,
}
pub type SharedManualScenes = Rc<RefCell<ManualSceneRegistry>>;

/// The planner and features consume the same native-installed manual record.
/// The delegate retains independent state/bake codecs; a public patch cannot
/// populate this registry or turn a manual scene into a sealed baked clip.
pub fn manual_data_adapter(
    delegate: SharedPlanningData,
    request: RequestContextSlot,
    authority: LocalAuthority,
    manual: SharedManualScenes,
) -> SharedPlanningData {
    Rc::new(RefCell::new(Box::new(ManualSceneData {
        delegate,
        request,
        authority,
        manual,
    })))
}
struct ManualSceneData {
    delegate: SharedPlanningData,
    request: RequestContextSlot,
    authority: LocalAuthority,
    manual: SharedManualScenes,
}
impl ManualSceneData {
    fn record(
        &self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<Option<ManualRecord>> {
        let (authenticated, actual_budget) = self
            .request
            .current()
            .map_err(|error| AppError::new(error.code, error.message))?;
        if authenticated.principal() != principal
            || actual_budget.deadline() != budget.deadline()
            || !std::ptr::eq(actual_budget.cancellation(), budget.cancellation())
        {
            return Err(forbidden());
        }
        manual_record_for_patch(
            &self.manual,
            &authenticated,
            project,
            patch,
            context,
            &self.authority,
            budget,
        )
    }
}
impl PlanningDataPort for ManualSceneData {
    #[allow(
        clippy::too_many_arguments,
        reason = "Forward the actual Store and unchanged authenticated state-source inputs to the delegate"
    )]
    fn state_snapshot_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        instance: &Value,
        definition: &Value,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<ObservedStateSnapshot> {
        self.delegate
            .try_borrow_mut()
            .map_err(|_| busy())?
            .state_snapshot_with_store(
                store, principal, project, instance, definition, context, budget,
            )
    }
    fn scene_source_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<SceneSource> {
        if self
            .record(principal, project, patch, context, budget)?
            .is_some()
        {
            return self.scene_source(principal, project, patch, context, budget);
        }
        self.delegate
            .try_borrow_mut()
            .map_err(|_| busy())?
            .scene_source_with_store(store, principal, project, patch, context, budget)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Forward the original decoded source and current authorization with the same Store"
    )]
    fn validate_scene_provenance_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        source: &SceneSource,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        if self
            .record(principal, project, patch, context, budget)?
            .is_some()
        {
            return self
                .validate_scene_provenance(principal, project, patch, source, context, budget);
        }
        self.delegate
            .try_borrow_mut()
            .map_err(|_| busy())?
            .validate_scene_provenance_with_store(
                store, principal, project, patch, source, context, budget,
            )
    }
    fn state_snapshot(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        instance: &Value,
        definition: &Value,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<ObservedStateSnapshot> {
        self.delegate
            .try_borrow_mut()
            .map_err(|_| busy())?
            .state_snapshot(principal, project, instance, definition, context, budget)
    }
    fn scene_source(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<SceneSource> {
        if let Some(record) = self.record(principal, project, patch, context, budget)? {
            let selection = Selection::from_value(&record.selection).map_err(exchange_app)?;
            mmmm_exchange::patch::validate_scene_patch(
                patch,
                &selection,
                &record.registration.policy,
            )
            .map_err(exchange_app)?;
            budget_check(budget)?;
            return Ok(SceneSource {
                selection,
                delta_policy: record.registration.policy,
                artifact: record.artifact,
                source_map: record.source_map,
                ingested_bake: None,
            });
        }
        self.delegate
            .try_borrow_mut()
            .map_err(|_| busy())?
            .scene_source(principal, project, patch, context, budget)
    }
    fn validate_scene_provenance(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        source: &SceneSource,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        if let Some(record) = self.record(principal, project, patch, context, budget)? {
            if source.selection.value() != &record.selection
                || source.artifact != record.artifact
                || source.source_map != record.source_map
                || source.ingested_bake.is_some()
            {
                return Err(conflict());
            }
            mmmm_exchange::patch::validate_scene_patch(
                patch,
                &source.selection,
                &record.registration.policy,
            )
            .map_err(exchange_app)?;
            return budget_check(budget);
        }
        self.delegate
            .try_borrow_mut()
            .map_err(|_| busy())?
            .validate_scene_provenance(principal, project, patch, source, context, budget)
    }
}

#[derive(Clone)]
struct ProductRecord {
    binding: SourceBinding,
    resource: ResourceRef,
    producer: Sha256Digest,
    origin: FeatureOrigin,
    shape: Option<shape_source::ShapeGeometryReceipt>,
    weight: usize,
}
#[derive(Default)]
pub struct FeatureProductRegistry {
    records: BTreeMap<(ProjectId, ResourceId), ProductRecord>,
    bytes: usize,
}
pub type SharedFeatureProducts = Rc<RefCell<FeatureProductRegistry>>;

/// The native daemon supplies these explicit server-owned composition inputs.
/// None of the registries or witnesses can be installed by feature RPC input.
pub struct FeatureSourceComposition {
    pub request: RequestContextSlot,
    pub authority: LocalAuthority,
    pub hosts: HostBridge,
    pub contexts: SharedPlanningContexts,
    pub context_locator: SharedRegisteredPlanningContexts,
    pub data: SharedPlanningData,
    pub backend: SharedPlanningBackend,
    pub dependencies: SharedPlanningDependencies,
    pub project_id: ProjectId,
    pub default_context: Option<ContextId>,
    pub rights: SharedResourceRights,
    pub manual: SharedManualScenes,
    pub products: SharedFeatureProducts,
    pub catalog: Option<RegisteredCatalogSources>,
    pub permissions: Option<SharedFeaturePermissions>,
    pub symbols: Option<SharedFeatureSymbols>,
    pub compatibility: RegisteredCompatibilityProfiles,
}
#[derive(Clone, Default)]
struct FeatureOrigin {
    resources: BTreeMap<ResourceId, ResourceRef>,
    objects: Vec<ObjectPin>,
}
pub struct LocalFeatureSources {
    composition: FeatureSourceComposition,
    origin: FeatureOrigin,
    pending_shape: Option<shape_source::ShapeGeometryReceipt>,
}
impl LocalFeatureSources {
    pub fn new(composition: FeatureSourceComposition) -> Self {
        Self {
            composition,
            origin: FeatureOrigin::default(),
            pending_shape: None,
        }
    }
    /// FN31 and canonical feature reads share this exact issuance registry.
    /// The fallback keeps the existing operation/paired-resource authority.
    pub fn artifact_authority(
        &self,
        fallback: Box<dyn ResourceAuthority>,
    ) -> Box<dyn ResourceAuthority> {
        Box::new(FeatureArtifactAuthority {
            request: self.composition.request.clone(),
            authority: self.composition.authority.clone(),
            hosts: self.composition.hosts.clone(),
            contexts: self.composition.contexts.clone(),
            locator: self.composition.context_locator.clone(),
            data: self.composition.data.clone(),
            project_id: self.composition.project_id.clone(),
            products: self.composition.products.clone(),
            catalog: self.composition.catalog.clone(),
            fallback,
        })
    }
    fn local(
        &self,
        principal: AuthenticatedPrincipal,
        budget: RequestBudget,
    ) -> AppResult<LocalPlanningAccess> {
        LocalPlanningAccess::new(
            principal,
            self.composition.authority.clone(),
            self.composition.hosts.clone(),
            budget,
            self.composition.contexts.clone(),
        )
    }
    fn resolve(
        &self,
        principal: &AuthenticatedPrincipal,
        id: &ContextId,
        budget: &RequestBudget,
    ) -> AppResult<Value> {
        self.composition
            .context_locator
            .try_borrow_mut()
            .map_err(|_| busy())?
            .resolve(
                principal,
                &mut self.composition.authority.clone(),
                &self.composition.hosts,
                id,
                Access::ReadProject,
                budget,
            )
    }
    fn current(
        &self,
        access: &FeatureAccess,
        budget: &RequestBudget,
    ) -> Result<(AuthenticatedPrincipal, LocalPlanningAccess), ServiceError> {
        let (principal, actual) = self.composition.request.current()?;
        if principal.principal() != &access.read_principal.principal_id
            || actual.deadline() != budget.deadline()
            || !std::ptr::eq(actual.cancellation(), budget.cancellation())
        {
            return Err(service(forbidden()));
        }
        let local = self.local(principal.clone(), actual).map_err(service)?;
        if let Some(context) = access.context.as_ref() {
            let id = context_id(context).map_err(service)?;
            if self.resolve(&principal, &id, budget).map_err(service)? != *context {
                return Err(service(stale()));
            }
        }
        Ok((principal, local))
    }
    fn source<'a>(
        &self,
        access: &FeatureAccess,
        store: PlanningStore<'a>,
        budget: &RequestBudget,
    ) -> Result<
        (
            AuthenticatedPrincipal,
            BorrowedProjectSource<'a>,
            ProjectCatalog,
        ),
        ServiceError,
    > {
        let (principal, local) = self.current(access, budget)?;
        let project = checked_current_project_catalog(
            &store,
            &local,
            principal.principal(),
            &self.composition.project_id,
            access.context.as_ref(),
        )
        .map_err(service)?;
        let source = BorrowedProjectSource::new(store, local, self.composition.data.clone());
        if access.project.as_ref() != Some(project.project()) {
            return Err(service(conflict()));
        }
        Ok((principal, source, project))
    }

    fn shape_admission(
        &self,
        access: &FeatureAccess,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> Result<shape_source::ShapeReadAdmission, ServiceError> {
        let (principal, _) = self.current(access, budget)?;
        let context = access
            .context
            .as_ref()
            .ok_or_else(|| service(unavailable()))?;
        let catalog = self
            .composition
            .catalog
            .as_ref()
            .ok_or_else(|| service(unavailable()))?;
        let snapshot_access =
            catalog.shape_snapshot_access(&self.composition.request, access, budget)?;
        let native = crate::native_catalog::NativeCatalogAdmission {
            request: &self.composition.request,
            authority: &self.composition.authority,
            hosts: &self.composition.hosts,
            sources: catalog,
        }
        .checkpoint(&principal, context, store, budget)
        .map_err(shape_source::service_error)?;
        Ok(shape_source::ShapeReadAdmission::new(
            snapshot_access,
            native,
        ))
    }
    /// Called by trusted native/file ingress only after bytes were placed in
    /// registered Project CAS. This does not fabricate a completed BakeArtifact.
    pub fn register_manual(
        &self,
        principal: &AuthenticatedPrincipal,
        store: &DurableStore,
        budget: &RequestBudget,
        registration: ManualSceneRegistration,
    ) -> AppResult<()> {
        let local = self.local(principal.clone(), budget.clone())?;
        let context = self.resolve(principal, &registration.context_id, budget)?;
        let shared = PlanningStore::read(store);
        let project = checked_current_project_catalog(
            &shared,
            &local,
            principal.principal(),
            &self.composition.project_id,
            Some(&context),
        )?;
        let mut source =
            BorrowedProjectSource::new(shared.clone(), local, self.composition.data.clone());
        let bundle_bytes = source.resource_bytes(
            principal.principal(),
            &project,
            &registration.source_bundle,
            Some(&context),
            MAX_SOURCE_BYTES,
        )?;
        let artifact = read_json(
            &mut source,
            principal,
            &project,
            &context,
            &registration.source_artifact,
            "BakeArtifact",
        )?;
        let request = read_json(
            &mut source,
            principal,
            &project,
            &context,
            &registration.source_request,
            "BakeRequest",
        )?;
        let selection = read_json(
            &mut source,
            principal,
            &project,
            &context,
            &registration.selection,
            "SceneSelectionSnapshot",
        )?;
        verify_manual_request(&project, &artifact, &request, &registration)?;
        verify_selection(&mut source, principal, &project, &context, &selection)?;
        let map = read_json(
            &mut source,
            principal,
            &project,
            &context,
            &registration.source_map,
            "SourceMap",
        )?;
        let payload = read_json(
            &mut source,
            principal,
            &project,
            &context,
            &registration.edit_payload,
            "ScenePatch",
        )?;
        let mut resource_port = LocalFeatureResources {
            source,
            store: shared,
            principal: principal.clone(),
            project: project.clone(),
            context: context.clone(),
            authority: self.composition.authority.clone(),
            rights: self.composition.rights.clone(),
            products: self.composition.products.clone(),
            budget: budget.clone(),
            origin: FeatureOrigin::default(),
        };
        let bundle = mmmm_exchange::manifest::inspect_resource(
            text(&context, "contextId")?,
            &bundle_bytes.bytes,
            &bundle_bytes.resource.media_type,
            &mut resource_port,
            mmmm_exchange::archive::ArchiveLimits::default(),
        )
        .map_err(exchange_app)?;
        if bundle.selection().value() != &selection {
            return Err(conflict());
        }
        mmmm_exchange::bake::validate_source_pins(&request, &bundle).map_err(exchange_app)?;
        let typed = decode_manual(&selection, &artifact, &registration, &map, &payload, budget)?;
        // The owned diff validates graph effects and the explicit typed policy.
        diff_scene_edits(
            &typed.selection,
            &typed.edits,
            &typed.source_artifact,
            &typed.source_map,
            &typed.losses,
            "manual-registration",
            &typed.policy,
        )
        .map_err(exchange_app)?;
        resource_port.source.access().authorize_project(
            principal.principal(),
            project.project_id(),
            Some(&context),
            Access::ReadProject,
        )?;
        let key = (
            principal.principal().clone(),
            text(&artifact, "artifactId")?.to_owned(),
        );
        let payload_proof = json!({"artifact":artifact,"selection":selection,"sourceMap":map});
        let weight = record_cost(
            &context,
            &payload_proof,
            &[
                &registration.source_artifact,
                &registration.source_bundle,
                &registration.source_request,
                &registration.selection,
                &registration.source_map,
                &registration.edit_payload,
            ],
        )?;
        let record = ManualRecord {
            binding: SourceBinding::capture(
                principal,
                &project,
                &context,
                &self.composition.authority,
            )?,
            artifact,
            selection_digest: canonical_digest(&selection).map_err(|_| invalid())?,
            selection,
            source_map: map,
            registration,
            weight,
        };
        let mut registry = self
            .composition
            .manual
            .try_borrow_mut()
            .map_err(|_| busy())?;
        if registry.records.len() >= 128 && !registry.records.contains_key(&key) {
            return Err(limit());
        }
        if let Some(old) = registry.records.get(&key)
            && (old.artifact != record.artifact
                || old.selection_digest != record.selection_digest
                || !same_resource(
                    &old.registration.source_artifact,
                    &record.registration.source_artifact,
                )
                || !same_resource(
                    &old.registration.edit_payload,
                    &record.registration.edit_payload,
                )
                || !same_resource(
                    &old.registration.source_bundle,
                    &record.registration.source_bundle,
                )
                || !same_resource(
                    &old.registration.source_request,
                    &record.registration.source_request,
                )
                || !same_resource(&old.registration.selection, &record.registration.selection)
                || !same_resource(
                    &old.registration.source_map,
                    &record.registration.source_map,
                ))
        {
            return Err(conflict());
        }
        let previous = registry.records.get(&key).map_or(0, |old| old.weight);
        let total = registry
            .bytes
            .checked_sub(previous)
            .and_then(|bytes| bytes.checked_add(weight))
            .ok_or_else(limit)?;
        if total > MAX_REGISTRY_BYTES {
            return Err(limit());
        }
        budget_check(budget)?;
        registry.records.insert(key, record);
        registry.bytes = total;
        Ok(())
    }
}

impl FeatureSources for LocalFeatureSources {
    fn compatibility_bind(
        &mut self,
        access: &FeatureAccess,
        input: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> Result<ProviderDescriptor, ServiceError> {
        let (principal, _) = self.current(access, budget)?;
        let context = access
            .context
            .as_ref()
            .ok_or_else(|| service(unavailable()))?;
        let result = self.composition.compatibility.bind(
            store,
            &principal,
            context,
            &access.granted_permissions,
            input,
            budget,
        );
        // Preserve the native/host/storage cause if the original entered call
        // also loses its local request authority after the bounded observation.
        let current = self
            .current(access, budget)
            .map(|_| ())
            .map_err(|cause| AppError::caused_by(cause.code, cause.message, cause));
        match (result, current) {
            (Ok(descriptor), Ok(())) => Ok(descriptor),
            (Err(cause), Ok(())) | (Ok(_), Err(cause)) => {
                Err(ServiceError::caused_by(cause.code, cause.message, cause))
            }
            (Err(primary), Err(checkpoint)) => Err(ServiceError::caused_by(
                primary.code,
                primary.message,
                crate::host::NativePairingOwnerFailure {
                    primary,
                    checkpoint,
                },
            )),
        }
    }
    fn access(
        &mut self,
        principal: &AuthenticatedPrincipal,
        method: &str,
        input: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> Result<FeatureAccess, ServiceError> {
        let (actual, actual_budget) = self.composition.request.current()?;
        if !actual.same_session(principal)
            || !principal.is_current()
            || !principal.permits(method)
            || actual_budget.deadline() != budget.deadline()
            || !std::ptr::eq(actual_budget.cancellation(), budget.cancellation())
        {
            return Err(service(forbidden()));
        }
        self.origin = FeatureOrigin::default();
        self.pending_shape = None;
        let local = self.local(actual.clone(), actual_budget).map_err(service)?;
        let id = input
            .get("contextId")
            .map(|v| serde_json::from_value::<ContextId>(v.clone()).map_err(|_| service(invalid())))
            .transpose()?
            .or_else(|| self.composition.default_context.clone());
        let context = id
            .as_ref()
            .map(|id| self.resolve(&actual, id, budget))
            .transpose()
            .map_err(service)?;
        let shared = PlanningStore::read(store);
        let project = checked_current_project_catalog(
            &shared,
            &local,
            actual.principal(),
            &self.composition.project_id,
            context.as_ref(),
        )
        .map_err(service)?;
        let scope = self
            .composition
            .authority
            .project_scope(actual.principal(), project.project_id())
            .map_err(service)?;
        let policy = self
            .composition
            .authority
            .policy_revision(actual.principal(), project.project_id())
            .map_err(service)?;
        let read_principal = if method.starts_with("catalog.") || method == "world.shape_query" {
            if method.starts_with("catalog.")
                && let Some(context) = context.as_ref()
                && context["environment"]["kind"] == "game"
            {
                crate::native_catalog::NativeCatalogAdmission {
                    request: &self.composition.request,
                    authority: &self.composition.authority,
                    hosts: &self.composition.hosts,
                    sources: self
                        .composition
                        .catalog
                        .as_ref()
                        .ok_or_else(|| service(unavailable()))?,
                }
                .ensure(&actual, context, store, budget)
                .map_err(|cause| ServiceError::caused_by(cause.code, cause.message, cause))?;
            }
            self.composition
                .catalog
                .as_ref()
                .ok_or_else(|| service(unavailable()))?
                .read_principal(&actual, id.as_ref().ok_or_else(|| service(unavailable()))?)
                .map_err(service)?
        } else {
            ReadPrincipal { principal_id: actual.principal().clone(), permission_scope_digest:
            canonical_digest(&json!({"format":"mmmm.feature-read-authority/1", "principal":actual.principal(),
                "project":project.project_id(),"projectRevision":project.revision(),"currentScope":scope,
                "currentPolicy":policy,"context":context.as_ref().map(|v|&v["contextDigest"])})).map_err(|_| service(invalid()))? }
        };
        let granted_permissions = match (&self.composition.permissions, &context) {
            (Some(port), Some(context)) => {
                port.current(&actual, context, budget).map_err(service)?
            }
            _ => BTreeSet::new(),
        };
        budget.check()?;
        Ok(FeatureAccess {
            read_principal,
            context,
            project: Some(project.project().clone()),
            granted_permissions,
        })
    }
    fn resources<'a>(
        &'a mut self,
        access: &'a FeatureAccess,
        store: &'a mut DurableStore,
        budget: &'a RequestBudget,
    ) -> Result<Box<dyn FeatureResourcePort + 'a>, ServiceError> {
        let shared = PlanningStore::write(store);
        let (principal, source, project) = self.source(access, shared.clone(), budget)?;
        let context = access
            .context
            .clone()
            .ok_or_else(|| service(unavailable()))?;
        Ok(Box::new(LocalFeatureResources {
            source,
            store: shared,
            principal,
            project,
            context,
            authority: self.composition.authority.clone(),
            rights: self.composition.rights.clone(),
            products: self.composition.products.clone(),
            budget: budget.clone(),
            origin: self.origin.clone(),
        }))
    }
    fn inventory(
        &mut self,
        access: &FeatureAccess,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> Result<InventorySnapshot, ServiceError> {
        let (principal, local) = self.current(access, budget)?;
        let context = access
            .context
            .as_ref()
            .ok_or_else(|| service(unavailable()))?;
        let mut environment = ConcretePlanningEnvironment::new(
            PlanningStore::read(store),
            local,
            self.composition.data.clone(),
            self.composition.backend.clone(),
            self.composition.dependencies.clone(),
        );
        environment
            .inventory(principal.principal(), context)
            .map_err(service)
    }
    fn shape_query_with_catalog(
        &mut self,
        access: &FeatureAccess,
        input: &Value,
        catalog: &mmmm_reference::Catalog,
        store: &mut DurableStore,
        budget: &RequestBudget,
    ) -> Result<Value, ServiceError> {
        let ports =
            shape_source::ShapeReadPorts::features(self).map_err(shape_source::service_error)?;
        let admission = self.shape_admission(access, store, budget)?;
        let output = shape_source::query_current_shape(
            ports, access, input, catalog, store, budget, admission,
        )
        .map_err(shape_source::service_error)?;
        budget.check()?;
        self.pending_shape = output.geometry;
        Ok(output.result)
    }
    fn shape_finished(
        &mut self,
        access: &FeatureAccess,
        result: &Result<Value, ServiceError>,
        catalog: &mmmm_reference::Catalog,
        store: &mut DurableStore,
        budget: &RequestBudget,
    ) -> Result<(), ServiceError> {
        // 실패·취소 때 새 I/O 없이 이 호출의 미발행 자료만 폐기한다.
        let pending = self.pending_shape.take();
        let Ok(output) = result else {
            return Ok(());
        };
        if let Some(receipt) = pending {
            if output.get("geometryRef")
                != Some(&serde_json::to_value(receipt.resource()).map_err(|_| service(invalid()))?)
            {
                return Err(service(invalid()));
            }
            let (principal, _, project) =
                self.source(access, PlanningStore::read(store), budget)?;
            let context = access
                .context
                .as_ref()
                .ok_or_else(|| service(unavailable()))?;
            let resource = receipt.resource().clone();
            let weight = record_cost(context, &receipt.snapshot().snapshot, &[&resource])
                .map_err(service)?;
            let binding =
                SourceBinding::capture(&principal, &project, context, &self.composition.authority)
                    .map_err(service)?;
            let admission = self.shape_admission(access, store, budget)?;
            let id: SnapshotId =
                serde_json::from_value(receipt.snapshot().snapshot["snapshotId"].clone())
                    .map_err(|_| service(invalid()))?;
            let pin = catalog
                .snapshot_pin(&id, &access.read_principal, admission.snapshot_access())
                .map_err(|_| service(forbidden()))?;
            if pin.revision != receipt.snapshot().revision {
                return Err(service(forbidden()));
            }
            let ports = shape_source::ShapeReadPorts::features(self)
                .map_err(shape_source::service_error)?;
            // 마지막 실제 host I/O 및 그 후 source/CAS/D032 확인은 발행 전에 끝난다.
            receipt
                .authorize_publication(ports, access, store, budget, admission)
                .map_err(shape_source::service_error)?;
            let mut products = self
                .composition
                .products
                .try_borrow_mut()
                .map_err(|_| service(busy()))?;
            let key = (project.project_id().clone(), resource.resource_id.clone());
            if products.records.len() >= 128 && !products.records.contains_key(&key) {
                return Err(service(limit()));
            }
            if products
                .records
                .get(&key)
                .is_some_and(|old| !same_resource(&old.resource, &resource))
            {
                return Err(service(conflict()));
            }
            let previous = products.records.get(&key).map_or(0, |old| old.weight);
            let bytes = products
                .bytes
                .checked_sub(previous)
                .and_then(|bytes| bytes.checked_add(weight))
                .ok_or_else(|| service(limit()))?;
            if bytes > MAX_REGISTRY_BYTES {
                return Err(service(limit()));
            }
            self.composition
                .request
                .current_witness("world.shape_query")?
                .check_local()?;
            products.records.insert(
                key,
                ProductRecord {
                    binding,
                    resource,
                    producer: raw_digest(include_bytes!("features.rs")),
                    origin: FeatureOrigin::default(),
                    shape: Some(receipt),
                    weight,
                },
            );
            products.bytes = bytes;
        }
        Ok(())
    }
    fn math_inputs(
        &mut self,
        access: &FeatureAccess,
        input: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> Result<MathInputs, ServiceError> {
        let (principal, mut source, project) =
            self.source(access, PlanningStore::read(store), budget)?;
        let context = access
            .context
            .as_ref()
            .ok_or_else(|| service(unsupported_target()))?;
        let profile: TargetProfileId = serde_json::from_value(input["targetProfileId"].clone())
            .map_err(|_| service(invalid()))?;
        let mut environment = ConcretePlanningEnvironment::new(
            PlanningStore::read(store),
            source.access().clone(),
            self.composition.data.clone(),
            self.composition.backend.clone(),
            self.composition.dependencies.clone(),
        );
        let target = environment
            .compiler_target(principal.principal(), &profile, context)
            .map_err(target_service)?;
        let resource: ResourceRef =
            serde_json::from_value(input["symbolTable"].clone()).map_err(|_| service(invalid()))?;
        let read = source
            .resource_bytes(
                principal.principal(),
                &project,
                &resource,
                Some(context),
                MAX_CODEC_BYTES,
            )
            .map_err(service)?;
        let symbols = self
            .composition
            .symbols
            .as_ref()
            .ok_or_else(|| service(unavailable()))?
            .try_borrow_mut()
            .map_err(|_| service(busy()))?
            .resolve(
                &principal,
                &project,
                context,
                &read.resource,
                &read.bytes,
                budget,
            )
            .map_err(service)?;
        source
            .access()
            .authorize_project(
                principal.principal(),
                project.project_id(),
                Some(context),
                Access::ReadProject,
            )
            .map_err(service)?;
        self.origin
            .resources
            .insert(read.resource.resource_id.clone(), read.resource);
        Ok(MathInputs { target, symbols })
    }
    fn pack_inputs_with_store(
        &mut self,
        access: &FeatureAccess,
        input: &Value,
        store: &mut DurableStore,
        budget: &RequestBudget,
    ) -> Result<PackInputs, ServiceError> {
        let frame = PlanningStore::write(store);
        let (principal, mut source, project) = self.source(access, frame.clone(), budget)?;
        let context = access
            .context
            .as_ref()
            .ok_or_else(|| service(unsupported_target()))?;
        if input["projectId"] != project.project_id().as_str()
            || input["expectedRevision"] != project.revision().as_str()
            || input["targetProfileId"] != project.target_profile_id().as_str()
        {
            return Err(service(conflict()));
        }
        let profile = project.target_profile_id();
        let mut environment = ConcretePlanningEnvironment::new(
            frame,
            source.access().clone(),
            self.composition.data.clone(),
            self.composition.backend.clone(),
            self.composition.dependencies.clone(),
        );
        let target = environment
            .compiler_target(principal.principal(), profile, context)
            .map_err(target_service)?;
        let owned = source
            .inspect_owned(principal.principal(), &project, 32 * 1024 * 1024)
            .map_err(service)?;
        self.origin.objects = owned.iter().map(|(pin, _)| pin.clone()).collect();
        let values = owned
            .into_iter()
            .map(|(_, value)| value)
            .collect::<Vec<_>>();
        let inputs = environment
            .pack_inputs(principal.principal(), &project, &values, context)
            .map_err(service)?;
        for value in &values {
            gather_resources(value, &mut self.origin.resources, budget, 0).map_err(service)?;
        }
        Ok(PackInputs { target, inputs })
    }
    fn catalog_access<'a>(
        &'a mut self,
        access: &FeatureAccess,
        _store: &'a DurableStore,
        budget: &'a RequestBudget,
    ) -> Result<Box<dyn AccessControl + 'a>, ServiceError> {
        self.composition
            .catalog
            .as_ref()
            .ok_or_else(|| service(unavailable()))?
            .catalog_access(&self.composition.request, access, budget)
    }
    fn capture<'a>(
        &'a mut self,
        access: &FeatureAccess,
        input: &Value,
        store: &'a mut DurableStore,
        budget: &'a RequestBudget,
    ) -> Result<CaptureInputs<'a>, ServiceError> {
        self.composition
            .catalog
            .as_ref()
            .ok_or_else(|| service(unavailable()))?
            .capture_inputs(&self.composition.request, access, input, store, budget)
    }
    fn capture_completed(
        &mut self,
        access: &FeatureAccess,
        snapshot: &Value,
        catalog: &mmmm_reference::Catalog,
        store: &mut DurableStore,
        budget: &RequestBudget,
    ) -> Result<(), ServiceError> {
        self.composition
            .catalog
            .as_ref()
            .ok_or_else(|| service(unavailable()))?
            .complete_capture(
                &self.composition.request,
                access,
                snapshot,
                catalog,
                store,
                budget,
            )
            .map_err(service)
    }
    fn authorize_exchange_prepare(
        &mut self,
        access: &FeatureAccess,
        input: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> Result<(), ServiceError> {
        let (principal, mut source, project) =
            self.source(access, PlanningStore::read(store), budget)?;
        let context = access
            .context
            .as_ref()
            .ok_or_else(|| service(unavailable()))?;
        verify_selection(
            &mut source,
            &principal,
            &project,
            context,
            &input["selection"],
        )
        .map_err(service)?;
        if let Some(physics) = input.get("physics") {
            verify_owned(
                &mut source,
                &principal,
                &project,
                context,
                OwnedKind::PhysicsDefinition,
                physics,
            )
            .map_err(service)?;
            let revision = serde_json::from_value(physics["revision"].clone())
                .map_err(|_| service(invalid()))?;
            let pin = project
                .authorize_pin(
                    OwnedKind::PhysicsDefinition,
                    text(physics, "physicsId").map_err(service)?,
                    &revision,
                )
                .map_err(service)?;
            if !self.origin.objects.contains(&pin) {
                self.origin.objects.push(pin);
            }
        }
        let snapshot: SnapshotId = serde_json::from_value(input["dataSnapshotId"].clone())
            .map_err(|_| service(invalid()))?;
        self.composition
            .catalog
            .as_ref()
            .ok_or_else(|| service(unavailable()))?
            .authorize_exchange_snapshot(
                &self.composition.request,
                context,
                &snapshot,
                store,
                budget,
            )
            .map_err(service)
    }
    fn manual_scene(
        &mut self,
        access: &FeatureAccess,
        input: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> Result<ManualSceneInputs, ServiceError> {
        let (principal, mut source, project) =
            self.source(access, PlanningStore::read(store), budget)?;
        let context = access
            .context
            .as_ref()
            .ok_or_else(|| service(unavailable()))?;
        let registry = self
            .composition
            .manual
            .try_borrow()
            .map_err(|_| service(busy()))?;
        let record = registry
            .records
            .get(&(
                principal.principal().clone(),
                text(&input["artifact"], "artifactId")
                    .map_err(service)?
                    .to_owned(),
            ))
            .ok_or_else(|| service(unavailable()))?;
        if !record
            .binding
            .matches(&principal, &project, context, &self.composition.authority)
            .map_err(service)?
            || record.artifact != input["artifact"]
            || record.selection_digest
                != canonical_digest(&input["selection"]).map_err(|_| service(invalid()))?
            || serde_json::to_value(&record.registration.source_map)
                .map_err(|_| service(invalid()))?
                != input["sourceMap"]
        {
            return Err(service(conflict()));
        }
        let record = record.clone();
        drop(registry);
        let decoded = load_manual(&mut source, &principal, &project, context, &record, budget)
            .map_err(service)?;
        origin_selection(&mut self.origin, &project, &record.selection, budget).map_err(service)?;
        for resource in [
            &record.registration.source_artifact,
            &record.registration.source_bundle,
            &record.registration.source_request,
            &record.registration.selection,
            &record.registration.source_map,
            &record.registration.edit_payload,
        ] {
            merge_resource(&mut self.origin.resources, resource, budget).map_err(service)?;
        }
        Ok(decoded)
    }
    fn scene_selection(
        &mut self,
        access: &FeatureAccess,
        input: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> Result<Selection, ServiceError> {
        let (principal, mut source, project) =
            self.source(access, PlanningStore::read(store), budget)?;
        let context = access
            .context
            .as_ref()
            .ok_or_else(|| service(unavailable()))?;
        if let Some(record) = manual_record_for_patch(
            &self.composition.manual,
            &principal,
            &project,
            &input["patch"],
            context,
            &self.composition.authority,
            budget,
        )
        .map_err(service)?
        {
            let decoded = load_manual(&mut source, &principal, &project, context, &record, budget)
                .map_err(service)?;
            mmmm_exchange::patch::validate_scene_patch(
                &input["patch"],
                &decoded.selection,
                &decoded.policy,
            )
            .map_err(exchange_app)
            .map_err(service)?;
            return Ok(decoded.selection);
        }
        source
            .scene_source(principal.principal(), &project, &input["patch"], context)
            .map(|scene| scene.selection)
            .map_err(service)
    }
    fn delta_policy(
        &mut self,
        access: &FeatureAccess,
        input: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> Result<DeltaPolicy, ServiceError> {
        if input.get("patch").is_none() {
            return self
                .manual_scene(access, input, store, budget)
                .map(|scene| scene.policy);
        }
        let (principal, mut source, project) =
            self.source(access, PlanningStore::read(store), budget)?;
        let context = access
            .context
            .as_ref()
            .ok_or_else(|| service(unavailable()))?;
        source
            .scene_source(principal.principal(), &project, &input["patch"], context)
            .map(|scene| scene.delta_policy)
            .map_err(service)
    }
}

struct LocalFeatureResources<'a> {
    source: BorrowedProjectSource<'a>,
    store: PlanningStore<'a>,
    principal: AuthenticatedPrincipal,
    project: ProjectCatalog,
    context: Value,
    authority: LocalAuthority,
    rights: SharedResourceRights,
    products: SharedFeatureProducts,
    budget: RequestBudget,
    origin: FeatureOrigin,
}
impl LocalFeatureResources<'_> {
    fn fresh(&self, context: &str) -> AppResult<()> {
        if self.context["contextId"] != context {
            return Err(forbidden());
        }
        self.source.access().authorize_project(
            self.principal.principal(),
            self.project.project_id(),
            Some(&self.context),
            Access::ReadProject,
        )
    }
    fn product(&mut self, resource: &ResourceRef) -> AppResult<Option<ProductRecord>> {
        let records = self.products.try_borrow().map_err(|_| busy())?;
        let Some(record) = records.records.get(&(
            self.project.project_id().clone(),
            resource.resource_id.clone(),
        )) else {
            return Ok(None);
        };
        if !same_resource(&record.resource, resource)
            || record.producer != raw_digest(include_bytes!("features.rs"))
            || !record.binding.matches(
                &self.principal,
                &self.project,
                &self.context,
                &self.authority,
            )?
        {
            return Ok(None);
        }
        let record = record.clone();
        drop(records);
        // Shape geometry는 원 snapshot/source와 현재 FN31 요청을 검사하는
        // 아래 FeatureArtifactAuthority 전용 경로에서만 소비한다.
        if record.shape.is_some() {
            return Err(forbidden());
        }
        let mut document_remaining = 32 * 1024 * 1024;
        let rpc = ProductRpc {
            access: self.source.access().clone(),
            context: context_id(&self.context)?,
        };
        for pin in &record.origin.objects {
            budget_check(&self.budget)?;
            if document_remaining == 0 {
                return Err(limit());
            }
            let mut reader = OwnedDocumentReader::new(
                Box::new(FeatureOwnedAuthority {
                    access: self.source.access().clone(),
                    authority: self.authority.clone(),
                    context: self.context.clone(),
                    project: self.project.project_id().clone(),
                }),
                document_remaining.min(MAX_CODEC_BYTES),
            )
            .map_err(storage_app)?;
            let actual = self.store.with_read(|store| {
                reader
                    .read_known_history_bytes(
                        store,
                        &rpc,
                        self.project.project_id(),
                        self.project.revision(),
                        &owned_pin(pin),
                    )
                    .map_err(storage_app)
            })?;
            document_remaining = document_remaining
                .checked_sub(actual.bytes.len() as u64)
                .ok_or_else(limit)?;
        }
        let mut remaining = MAX_SOURCE_BYTES;
        for pin in record.origin.resources.values() {
            budget_check(&self.budget)?;
            if pin.size_bytes > remaining || remaining == 0 {
                return Err(limit());
            }
            let actual = self.source.resource_bytes(
                self.principal.principal(),
                &self.project,
                pin,
                Some(&self.context),
                remaining,
            )?;
            if !same_resource(&actual.resource, pin) {
                return Err(conflict());
            }
            remaining = remaining
                .checked_sub(actual.bytes.len() as u64)
                .ok_or_else(limit)?;
        }
        Ok(Some(record))
    }
    fn rights(&self, resource: &ResourceRef) -> AppResult<Redistribution> {
        // A producer receipt allows only this session's exact private read.
        // It cannot supply redistribution rights for its output or inputs.
        self.rights.try_borrow().map_err(|_| busy())?.lookup(
            &self.principal,
            &self.project,
            &self.context,
            resource,
            &self.authority,
        )
    }
}
impl ResourcePort for LocalFeatureResources<'_> {
    fn authorize_selection(&mut self, context: &str, selection: &Value) -> ExchangeResult<()> {
        self.fresh(context).map_err(app_exchange)?;
        verify_selection(
            &mut self.source,
            &self.principal,
            &self.project,
            &self.context,
            selection,
        )
        .map_err(app_exchange)?;
        for (field, kind) in [
            ("instances", OwnedKind::Instance),
            ("prefabs", OwnedKind::Prefab),
        ] {
            for value in selection[field]
                .as_array()
                .ok_or_else(|| app_exchange(invalid()))?
            {
                let revision = serde_json::from_value(value["revision"].clone())
                    .map_err(|_| app_exchange(invalid()))?;
                let pin = self
                    .project
                    .authorize_pin(
                        kind,
                        text(value, kind.id_field()).map_err(app_exchange)?,
                        &revision,
                    )
                    .map_err(app_exchange)?;
                if !self.origin.objects.contains(&pin) {
                    self.origin.objects.push(pin);
                }
            }
        }
        Ok(())
    }
    fn read(
        &mut self,
        context: &str,
        resource: &Value,
        purpose: ResourcePurpose,
        max_bytes: u64,
    ) -> ExchangeResult<AuthorizedBytes> {
        self.fresh(context).map_err(app_exchange)?;
        let pin: ResourceRef =
            serde_json::from_value(resource.clone()).map_err(|_| app_exchange(invalid()))?;
        if pin.media_type.len() > 1024 {
            return Err(app_exchange(limit()));
        }
        if max_bytes == 0 || pin.size_bytes > max_bytes || max_bytes > MAX_SOURCE_BYTES {
            return Err(app_exchange(limit()));
        }
        let redistribution = self.rights(&pin).map_err(app_exchange)?;
        if purpose == ResourcePurpose::Redistribute && redistribution != Redistribution::Allowed {
            return Err(app_exchange(forbidden()));
        }
        let product = self.product(&pin).map_err(app_exchange)?;
        let is_product = product.is_some();
        let bytes = if let Some(product) = product {
            let rpc = ProductRpc {
                access: self.source.access().clone(),
                context: context_id(&self.context).map_err(app_exchange)?,
            };
            let mut reader = ProjectResourceReader::new(
                Box::new(ProductAuthority {
                    access: self.source.access().clone(),
                    principal: self.principal.clone(),
                    project: self.project.clone(),
                    context: self.context.clone(),
                    authority: self.authority.clone(),
                    product,
                }),
                MAX_SOURCE_BYTES,
            )
            .map_err(storage_exchange)?;
            let query = ProjectResourceQuery::RegisteredImmutable {
                resource_id: pin.resource_id.clone(),
            };
            self.store
                .with_read(|store| {
                    reader
                        .read(
                            store,
                            &rpc,
                            &ProjectResourceRequest {
                                project: self.project.project_id(),
                                current_project_revision: self.project.revision(),
                                query: &query,
                                expected: Some(resource),
                            },
                            max_bytes,
                        )
                        .map(|read| read.bytes)
                        .map_err(storage_app)
                })
                .map_err(app_exchange)?
        } else {
            self.source
                .resource_bytes(
                    self.principal.principal(),
                    &self.project,
                    &pin,
                    Some(&self.context),
                    max_bytes,
                )
                .map_err(app_exchange)?
                .bytes
        };
        self.fresh(context).map_err(app_exchange)?;
        if is_product {
            let current = self
                .product(&pin)
                .map_err(app_exchange)?
                .ok_or_else(|| app_exchange(forbidden()))?;
            merge_origin(&mut self.origin, &current.origin, &self.budget).map_err(app_exchange)?;
        } else {
            merge_resource(&mut self.origin.resources, &pin, &self.budget).map_err(app_exchange)?;
        }
        Ok(AuthorizedBytes {
            bytes,
            redistribution,
        })
    }
    fn embedded_rights(
        &mut self,
        context: &str,
        resource: &Value,
    ) -> ExchangeResult<Redistribution> {
        self.fresh(context).map_err(app_exchange)?;
        let pin = serde_json::from_value(resource.clone()).map_err(|_| app_exchange(invalid()))?;
        let rights = self.rights(&pin).map_err(app_exchange)?;
        self.fresh(context).map_err(app_exchange)?;
        Ok(rights)
    }
}
impl FeatureResourcePort for LocalFeatureResources<'_> {
    fn stage(&mut self, resource: &Value, bytes: &[u8]) -> ExchangeResult<()> {
        let context = text(&self.context, "contextId")
            .map_err(app_exchange)?
            .to_owned();
        self.fresh(&context).map_err(app_exchange)?;
        verify_resource(resource, bytes, MAX_SOURCE_BYTES)?;
        let pin: ResourceRef =
            serde_json::from_value(resource.clone()).map_err(|_| app_exchange(invalid()))?;
        if pin.media_type.len() > 1024 {
            return Err(app_exchange(limit()));
        }
        // Existing authored/source assets keep their actual rights. Only a new
        // Rust-produced output obtains a producer witness through this port.
        let current_scope = self
            .authority
            .project_scope(self.principal.principal(), self.project.project_id())
            .map_err(app_exchange)?;
        let already_source = self
            .rights
            .try_borrow()
            .map_err(|_| app_exchange(busy()))?
            .records
            .contains_key(&(self.project.project_id().clone(), pin.resource_id.clone()))
            || self.origin.resources.contains_key(&pin.resource_id)
            || current_scope["resourceIds"]
                .as_array()
                .is_some_and(|ids| ids.contains(&resource["resourceId"]));
        self.store
            .with_write(|store| {
                self.source.access().check()?;
                let blob = store.put_blob(bytes).map_err(storage_app)?;
                if blob.digest != pin.sha256 || blob.byte_length != pin.size_bytes {
                    return Err(invalid());
                }
                register_resource(
                    store,
                    resource,
                    ResourceOwner::Project(self.project.project_id().clone()),
                )
                .map_err(|e| AppError::new(e.code, e.message))?;
                self.source.access().check()
            })
            .map_err(app_exchange)?;
        self.fresh(&context).map_err(app_exchange)?;
        if !already_source {
            let mut products = self
                .products
                .try_borrow_mut()
                .map_err(|_| app_exchange(busy()))?;
            let key = (self.project.project_id().clone(), pin.resource_id.clone());
            if products.records.len() >= 128 && !products.records.contains_key(&key) {
                return Err(app_exchange(limit()));
            }
            if products
                .records
                .get(&key)
                .is_some_and(|old| !same_resource(&old.resource, &pin))
            {
                return Err(app_exchange(conflict()));
            }
            if self.origin.resources.len() > 256 || self.origin.objects.len() > 4096 {
                return Err(app_exchange(limit()));
            }
            let provenance =
                json!({"objects":self.origin.objects,"resources":self.origin.resources});
            let weight = record_cost(&self.context, &provenance, &[&pin]).map_err(app_exchange)?;
            let previous = products.records.get(&key).map_or(0, |old| old.weight);
            let total = products
                .bytes
                .checked_sub(previous)
                .and_then(|bytes| bytes.checked_add(weight))
                .ok_or_else(|| app_exchange(limit()))?;
            if total > MAX_REGISTRY_BYTES {
                return Err(app_exchange(limit()));
            }
            let record = ProductRecord {
                binding: SourceBinding::capture(
                    &self.principal,
                    &self.project,
                    &self.context,
                    &self.authority,
                )
                .map_err(app_exchange)?,
                resource: pin,
                producer: raw_digest(include_bytes!("features.rs")),
                origin: self.origin.clone(),
                shape: None,
                weight,
            };
            self.budget
                .check()
                .map_err(|e| ExchangeError::new(e.code, e.message))?;
            products.records.insert(key, record);
            products.bytes = total;
        }
        self.budget
            .check()
            .map_err(|e| ExchangeError::new(e.code, e.message))
    }
}
struct ProductRpc {
    access: LocalPlanningAccess,
    context: ContextId,
}
impl ProjectSourceRpcContext for ProductRpc {
    fn check(&self) -> StorageResult<()> {
        self.access.check().map_err(storage_from_app)
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.access.principal().clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        Some(&self.context)
    }
}
struct FeatureOwnedAuthority {
    access: LocalPlanningAccess,
    authority: LocalAuthority,
    context: Value,
    project: ProjectId,
}
impl OwnedDocumentAuthority for FeatureOwnedAuthority {
    fn authorize_read(
        &mut self,
        principal: &PrincipalId,
        context: &ContextId,
        project: &ProjectId,
        revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> StorageResult<()> {
        self.authorize_project_read(principal, Some(context), project, revision, pin)
    }
    fn authorize_project_read(
        &mut self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        _revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> StorageResult<()> {
        if principal != self.access.principal()
            || project != &self.project
            || context.map(ContextId::as_str) != self.context["contextId"].as_str()
        {
            return Err(storage_from_app(forbidden()));
        }
        let scope = self
            .authority
            .project_scope(principal, project)
            .map_err(storage_from_app)?;
        let id = serde_json::to_value(&pin.object_id).map_err(|_| storage_from_app(invalid()))?;
        if !scope["objectIds"]
            .as_array()
            .is_some_and(|ids| ids.contains(&id))
            || !self.context["scope"]["objectIds"]
                .as_array()
                .is_some_and(|ids| ids.contains(&id))
        {
            return Err(storage_from_app(forbidden()));
        }
        self.access
            .authorize_project(principal, project, Some(&self.context), Access::ReadProject)
            .map_err(storage_from_app)
    }
}
fn owned_pin(pin: &ObjectPin) -> OwnedDocumentPin {
    OwnedDocumentPin {
        kind: match pin.kind {
            OwnedKind::Prefab => OwnedDocumentKind::Prefab,
            OwnedKind::Instance => OwnedDocumentKind::Instance,
            OwnedKind::CommandModule => OwnedDocumentKind::CommandModule,
            OwnedKind::Clip => OwnedDocumentKind::AnimationClip,
            OwnedKind::Asset => OwnedDocumentKind::Asset,
            OwnedKind::PhysicsDefinition => OwnedDocumentKind::PhysicsDefinition,
        },
        object_id: pin.object_id.clone(),
        revision: pin.revision.clone(),
    }
}
struct ProductAuthority {
    access: LocalPlanningAccess,
    principal: AuthenticatedPrincipal,
    project: ProjectCatalog,
    context: Value,
    authority: LocalAuthority,
    product: ProductRecord,
}
impl ProjectResourceAuthority for ProductAuthority {
    fn authorize_project_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        revision: &Sha256Digest,
    ) -> StorageResult<()> {
        if principal != self.principal.principal()
            || project != self.project.project_id()
            || revision != self.project.revision()
            || context.map(ContextId::as_str) != self.context["contextId"].as_str()
            || !self
                .product
                .binding
                .matches(
                    &self.principal,
                    &self.project,
                    &self.context,
                    &self.authority,
                )
                .map_err(storage_from_app)?
        {
            return Err(storage_from_app(forbidden()));
        }
        self.access
            .authorize_project(principal, project, Some(&self.context), Access::ReadProject)
            .map_err(storage_from_app)
    }
    fn authorize_resource_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> StorageResult<()> {
        if principal != self.principal.principal()
            || project != self.project.project_id()
            || context.map(ContextId::as_str) != self.context["contextId"].as_str()
            || resource.owner != ResourceOwner::Project(project.clone())
            || resource.resource
                != serde_json::to_value(&self.product.resource)
                    .map_err(|_| storage_from_app(invalid()))?
            || !self
                .product
                .binding
                .matches(
                    &self.principal,
                    &self.project,
                    &self.context,
                    &self.authority,
                )
                .map_err(storage_from_app)?
        {
            return Err(storage_from_app(forbidden()));
        }
        self.access
            .authorize_project(principal, project, Some(&self.context), Access::ReadProject)
            .map_err(storage_from_app)
    }
}

struct FeatureArtifactAuthority {
    request: RequestContextSlot,
    authority: LocalAuthority,
    hosts: HostBridge,
    contexts: SharedPlanningContexts,
    locator: SharedRegisteredPlanningContexts,
    data: SharedPlanningData,
    project_id: ProjectId,
    products: SharedFeatureProducts,
    fallback: Box<dyn ResourceAuthority>,
    catalog: Option<RegisteredCatalogSources>,
}
impl ResourceAuthority for FeatureArtifactAuthority {
    fn authorize_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        id: &ContextId,
        owner: &ResourceOwner,
        resource: &Value,
    ) -> ArtifactResult<()> {
        let (authenticated, budget) = self
            .request
            .current()
            .map_err(|e| ArtifactError::new(e.code, e.message))?;
        if authenticated.principal() != principal
            || !authenticated.permits("artifact.read")
            || !authenticated.permits_context(id.as_str())
        {
            return Err(ArtifactError::forbidden());
        }
        let context = self
            .locator
            .try_borrow_mut()
            .map_err(|_| ArtifactError::new("SOURCE_BUSY", "Registered context is busy"))?
            .resolve(
                &authenticated,
                &mut self.authority.clone(),
                &self.hosts,
                id,
                Access::ReadProject,
                &budget,
            )
            .map_err(artifact_app)?;
        let local = LocalPlanningAccess::new(
            authenticated.clone(),
            self.authority.clone(),
            self.hosts.clone(),
            budget.clone(),
            self.contexts.clone(),
        )
        .map_err(artifact_app)?;
        let shared = PlanningStore::read(store);
        let project = checked_current_project_catalog(
            &shared,
            &local,
            principal,
            &self.project_id,
            Some(&context),
        )
        .map_err(artifact_app)?;
        if owner != &ResourceOwner::Project(project.project_id().clone()) {
            return self
                .fallback
                .authorize_read(store, principal, id, owner, resource);
        }
        let pin: ResourceRef =
            serde_json::from_value(resource.clone()).map_err(|_| ArtifactError::forbidden())?;
        let source = BorrowedProjectSource::new(shared.clone(), local, self.data.clone());
        let mut issued = LocalFeatureResources {
            source,
            store: shared,
            principal: authenticated.clone(),
            project: project.clone(),
            context: context.clone(),
            authority: self.authority.clone(),
            rights: Rc::new(RefCell::new(ResourceRightsRegistry::default())),
            products: self.products.clone(),
            budget: budget.clone(),
            origin: FeatureOrigin::default(),
        };
        // 명시적인 현재 raw resource ACL은 파생 receipt의 존재·현재성과 별개다.
        // ArtifactReader가 원 owner/version/metadata/CAS와 전후 ACL을 검사하며,
        // 이 경로는 receipt를 복원하거나 배포 권한을 발급하지 않는다.
        let scope = self
            .authority
            .project_scope(principal, project.project_id())
            .map_err(artifact_app)?;
        if scope["resourceIds"]
            .as_array()
            .is_some_and(|ids| ids.contains(&resource["resourceId"]))
            && context["scope"]["resourceIds"]
                .as_array()
                .is_some_and(|ids| ids.contains(&resource["resourceId"]))
        {
            return issued.fresh(id.as_str()).map_err(artifact_app);
        }
        let geometry = self
            .products
            .try_borrow()
            .map_err(|_| ArtifactError::new("SOURCE_BUSY", "Issued product registry is busy"))?
            .records
            .get(&(project.project_id().clone(), pin.resource_id.clone()))
            .cloned()
            .filter(|record| record.shape.is_some());
        if let Some(record) = geometry {
            if !same_resource(&record.resource, &pin)
                || record.producer != raw_digest(include_bytes!("features.rs"))
                || !record
                    .binding
                    .matches(&authenticated, &project, &context, &self.authority)
                    .map_err(artifact_app)?
            {
                return Err(ArtifactError::forbidden());
            }
            let catalog = self.catalog.as_ref().ok_or_else(ArtifactError::forbidden)?;
            let access = FeatureAccess {
                read_principal: catalog
                    .read_principal(&authenticated, id)
                    .map_err(artifact_app)?,
                context: Some(context.clone()),
                project: Some(project.project().clone()),
                granted_permissions: BTreeSet::new(),
            };
            let snapshot_access = catalog
                .shape_snapshot_access(&self.request, &access, &budget)
                .map_err(|error| ArtifactError::new(error.code, error.message))?;
            let native = crate::native_catalog::NativeCatalogAdmission {
                request: &self.request,
                authority: &self.authority,
                hosts: &self.hosts,
                sources: catalog,
            }
            .checkpoint(&authenticated, &context, store, &budget)
            .map_err(artifact_app)?;
            let receipt = record.shape.as_ref().ok_or_else(ArtifactError::forbidden)?;
            receipt
                .authorize_read(
                    shape_source::ShapeReadPorts::artifacts(self).map_err(artifact_app)?,
                    &access,
                    &pin,
                    store,
                    &budget,
                    shape_source::ShapeReadAdmission::new(snapshot_access, native),
                )
                .map_err(artifact_app)?;
            return Ok(());
        }
        if issued.product(&pin).map_err(artifact_app)?.is_some() {
            issued.fresh(id.as_str()).map_err(artifact_app)?;
            return Ok(());
        }
        if let Some(catalog) = &self.catalog
            && catalog
                .read_catalog_resource(
                    &self.request,
                    &context,
                    resource,
                    store,
                    &budget,
                    MAX_SOURCE_BYTES,
                )
                .map_err(artifact_app)?
                .is_some()
        {
            issued.fresh(id.as_str()).map_err(artifact_app)?;
            return Ok(());
        }
        Err(ArtifactError::forbidden())
    }
}

fn manual_record_for_patch(
    manual: &SharedManualScenes,
    principal: &AuthenticatedPrincipal,
    project: &ProjectCatalog,
    patch: &Value,
    context: &Value,
    authority: &LocalAuthority,
    budget: &RequestBudget,
) -> AppResult<Option<ManualRecord>> {
    budget_check(budget)?;
    validate("ScenePatch", patch)?;
    if patch["projectId"] != project.project_id().as_str()
        || patch["baseRevision"] != project.revision().as_str()
        || !principal.is_current()
        || !principal.permits_context(context_id(context)?.as_str())
    {
        return Err(conflict());
    }
    let registry = manual.try_borrow().map_err(|_| busy())?;
    for ((owner, _), record) in &registry.records {
        budget_check(budget)?;
        if owner != principal.principal()
            || patch["sourceArtifact"]
                != serde_json::to_value(&record.registration.source_artifact)
                    .map_err(|_| invalid())?
        {
            continue;
        }
        if !record
            .binding
            .matches(principal, project, context, authority)?
            || patch["sourceMap"]
                != serde_json::to_value(&record.registration.source_map).map_err(|_| invalid())?
        {
            return Err(conflict());
        }
        let policy =
            serde_json::from_value(context["policyRevision"].clone()).map_err(|_| invalid())?;
        authority.authorize_retained_scope(
            principal.principal(),
            project.project_id(),
            &context_id(context)?,
            &policy,
            &context["scope"],
        )?;
        return Ok(Some(record.clone()));
    }
    Ok(None)
}
fn verify_manual_request(
    project: &ProjectCatalog,
    artifact: &Value,
    request: &Value,
    registration: &ManualSceneRegistration,
) -> AppResult<()> {
    mmmm_exchange::bake::validate_bake_request(request).map_err(exchange_app)?;
    if request["projectId"] != project.project_id().as_str()
        || request["projectRevision"] != project.revision().as_str()
        || artifact["sourceProjectRevision"] != project.revision().as_str()
        || artifact["representation"] != request["representation"]
        || request["sourceBundle"]
            != serde_json::to_value(&registration.source_bundle).map_err(|_| invalid())?
        || artifact["inputDigest"]
            != mmmm_contracts::projected_digest("BakeRequest", request)
                .map_err(|_| invalid())?
                .as_str()
        || artifact["requestId"] != request["requestId"]
    {
        return Err(conflict());
    }
    Ok(())
}
fn load_manual(
    source: &mut BorrowedProjectSource<'_>,
    principal: &AuthenticatedPrincipal,
    project: &ProjectCatalog,
    context: &Value,
    record: &ManualRecord,
    budget: &RequestBudget,
) -> AppResult<ManualSceneInputs> {
    let registration = &record.registration;
    // Immutable registration proves the codec relation; every use still reads
    // each exact source through current resource ACL and the original budget.
    source.resource_bytes(
        principal.principal(),
        project,
        &registration.source_bundle,
        Some(context),
        MAX_SOURCE_BYTES,
    )?;
    let artifact = read_json(
        source,
        principal,
        project,
        context,
        &registration.source_artifact,
        "BakeArtifact",
    )?;
    let request = read_json(
        source,
        principal,
        project,
        context,
        &registration.source_request,
        "BakeRequest",
    )?;
    let selection = read_json(
        source,
        principal,
        project,
        context,
        &registration.selection,
        "SceneSelectionSnapshot",
    )?;
    let map = read_json(
        source,
        principal,
        project,
        context,
        &registration.source_map,
        "SourceMap",
    )?;
    let payload = read_json(
        source,
        principal,
        project,
        context,
        &registration.edit_payload,
        "ScenePatch",
    )?;
    verify_manual_request(project, &artifact, &request, registration)?;
    if artifact != record.artifact
        || selection != record.selection
        || map != record.source_map
        || canonical_digest(&selection).map_err(|_| invalid())? != record.selection_digest
    {
        return Err(conflict());
    }
    verify_selection(source, principal, project, context, &selection)?;
    let decoded = decode_manual(&selection, &artifact, registration, &map, &payload, budget)?;
    source.access().authorize_project(
        principal.principal(),
        project.project_id(),
        Some(context),
        Access::ReadProject,
    )?;
    Ok(decoded)
}
fn merge_resource(
    resources: &mut BTreeMap<ResourceId, ResourceRef>,
    pin: &ResourceRef,
    budget: &RequestBudget,
) -> AppResult<()> {
    budget_check(budget)?;
    if resources
        .get(&pin.resource_id)
        .is_some_and(|old| !same_resource(old, pin))
    {
        return Err(conflict());
    }
    if resources.len() >= 256 && !resources.contains_key(&pin.resource_id) {
        return Err(limit());
    }
    resources.insert(pin.resource_id.clone(), pin.clone());
    Ok(())
}
fn origin_selection(
    origin: &mut FeatureOrigin,
    project: &ProjectCatalog,
    selection: &Value,
    budget: &RequestBudget,
) -> AppResult<()> {
    for (field, kind) in [
        ("instances", OwnedKind::Instance),
        ("prefabs", OwnedKind::Prefab),
    ] {
        for value in selection[field].as_array().ok_or_else(invalid)? {
            budget_check(budget)?;
            let revision =
                serde_json::from_value(value["revision"].clone()).map_err(|_| invalid())?;
            let pin = project.authorize_pin(kind, text(value, kind.id_field())?, &revision)?;
            if !origin.objects.contains(&pin) {
                if origin.objects.len() >= 4096 {
                    return Err(limit());
                }
                origin.objects.push(pin);
            }
        }
    }
    Ok(())
}
fn merge_origin(
    origin: &mut FeatureOrigin,
    upstream: &FeatureOrigin,
    budget: &RequestBudget,
) -> AppResult<()> {
    for pin in upstream.resources.values() {
        merge_resource(&mut origin.resources, pin, budget)?;
    }
    for pin in &upstream.objects {
        budget_check(budget)?;
        if !origin.objects.contains(pin) {
            if origin.objects.len() >= 4096 {
                return Err(limit());
            }
            origin.objects.push(pin.clone());
        }
    }
    Ok(())
}
fn verify_selection(
    source: &mut BorrowedProjectSource<'_>,
    principal: &AuthenticatedPrincipal,
    project: &ProjectCatalog,
    context: &Value,
    selection: &Value,
) -> AppResult<Selection> {
    budget_check(source.access().budget())?;
    let typed = Selection::from_value(selection).map_err(exchange_app)?;
    if selection["projectId"] != project.project_id().as_str()
        || selection["projectRevision"] != project.revision().as_str()
    {
        return Err(conflict());
    }
    for (field, kind) in [
        ("instances", OwnedKind::Instance),
        ("prefabs", OwnedKind::Prefab),
    ] {
        for value in selection[field].as_array().ok_or_else(invalid)? {
            budget_check(source.access().budget())?;
            verify_owned(source, principal, project, context, kind, value)?;
        }
    }
    source.access().authorize_project(
        principal.principal(),
        project.project_id(),
        Some(context),
        Access::ReadProject,
    )?;
    Ok(typed)
}
fn verify_owned(
    source: &mut BorrowedProjectSource<'_>,
    principal: &AuthenticatedPrincipal,
    project: &ProjectCatalog,
    context: &Value,
    kind: OwnedKind,
    value: &Value,
) -> AppResult<()> {
    let revision = serde_json::from_value(value["revision"].clone()).map_err(|_| invalid())?;
    let pin = project.authorize_pin(kind, text(value, kind.id_field())?, &revision)?;
    let actual = source.owned_object(
        principal.principal(),
        project,
        &pin,
        Some(context),
        MAX_CODEC_BYTES,
    )?;
    if actual != *value {
        return Err(conflict());
    }
    Ok(())
}
fn read_json(
    source: &mut BorrowedProjectSource<'_>,
    principal: &AuthenticatedPrincipal,
    project: &ProjectCatalog,
    context: &Value,
    resource: &ResourceRef,
    definition: &str,
) -> AppResult<Value> {
    let read = source.resource_bytes(
        principal.principal(),
        project,
        resource,
        Some(context),
        MAX_CODEC_BYTES,
    )?;
    let budget = source.access().budget();
    for _ in read.bytes.chunks(16 * 1024) {
        budget_check(budget)?;
    }
    let value = parse_json_with_control(
        &read.bytes,
        JsonLimits {
            max_bytes: MAX_CODEC_BYTES as usize,
            max_depth: 64,
            max_nodes: 100_000,
        },
        || budget_check(budget),
    )
    .map_err(|error| match error {
        ControlledJsonError::Json(_) => invalid(),
        ControlledJsonError::Control(error) => error,
    })?;
    budget_check(budget)?;
    validate(definition, &value)?;
    budget_check(budget)?;
    Ok(value)
}
fn gather_resources(
    value: &Value,
    resources: &mut BTreeMap<ResourceId, ResourceRef>,
    budget: &RequestBudget,
    depth: usize,
) -> AppResult<()> {
    budget_check(budget)?;
    if depth > 64 || resources.len() > 256 {
        return Err(limit());
    }
    if value.get("resourceId").is_some()
        && value.get("sha256").is_some()
        && value.get("mediaType").is_some()
        && value.get("sizeBytes").is_some()
    {
        let pin: ResourceRef = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        if resources
            .get(&pin.resource_id)
            .is_some_and(|old| !same_resource(old, &pin))
        {
            return Err(conflict());
        }
        resources.insert(pin.resource_id.clone(), pin);
    } else {
        match value {
            Value::Array(values) => {
                for value in values {
                    gather_resources(value, resources, budget, depth + 1)?;
                }
            }
            Value::Object(values) => {
                for value in values.values() {
                    gather_resources(value, resources, budget, depth + 1)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}
fn record_cost(context: &Value, payload: &Value, resources: &[&ResourceRef]) -> AppResult<usize> {
    let context = encode_json(context).map_err(|_| limit())?.len();
    let payload = encode_json(payload).map_err(|_| limit())?.len();
    let pins = resources.iter().try_fold(0_usize, |size, pin| {
        size.checked_add(pin.media_type.len() + 512)
            .ok_or_else(limit)
    })?;
    context
        .checked_add(payload)
        .and_then(|size| size.checked_add(pins))
        .and_then(|size| size.checked_mul(4))
        .ok_or_else(limit)
}
fn decode_manual(
    selection: &Value,
    artifact: &Value,
    registration: &ManualSceneRegistration,
    map: &Value,
    payload: &Value,
    budget: &RequestBudget,
) -> AppResult<ManualSceneInputs> {
    budget_check(budget)?;
    match &registration.codec {
        ManualSceneCodec::CanonicalScenePatch => {}
    }
    validate("BakeArtifact", artifact)?;
    validate("ScenePatch", payload)?;
    validate("SourceMap", map)?;
    let source_artifact =
        serde_json::to_value(&registration.source_artifact).map_err(|_| invalid())?;
    let source_map = serde_json::to_value(&registration.source_map).map_err(|_| invalid())?;
    if payload["projectId"] != selection["projectId"]
        || payload["baseRevision"] != selection["projectRevision"]
        || artifact["sourceProjectRevision"] != selection["projectRevision"]
        || map["inputRevision"] != selection["projectRevision"]
        || payload["sourceArtifact"] != source_artifact
        || payload["sourceMap"] != source_map
    {
        return Err(conflict());
    }
    let entries = payload["entries"].as_array().ok_or_else(invalid)?;
    let mappings = map["entries"].as_array().ok_or_else(invalid)?;
    if entries.len() > 4096 || mappings.len() != entries.len() {
        return Err(mapping_error());
    }
    let mut confirmed = BTreeSet::new();
    for mapping in mappings {
        budget_check(budget)?;
        if mapping["outputResourceId"] != registration.edit_payload.resource_id.as_str() {
            return Err(mapping_error());
        }
        let locator = text(mapping, "locator")?;
        let suffix = locator
            .strip_prefix("/entries/")
            .ok_or_else(mapping_error)?;
        let index: usize = suffix.parse().map_err(|_| mapping_error())?;
        if suffix != index.to_string() || !confirmed.insert(index) {
            return Err(mapping_error());
        }
        let entry = entries.get(index).ok_or_else(mapping_error)?;
        if mapping["sourceObjectId"] != entry["instanceId"]
            || mapping["sourceNodeId"] != entry["nodeId"]
        {
            return Err(mapping_error());
        }
    }
    let mut existing: BTreeMap<ObjectNode, (Option<Value>, Option<Value>)> = BTreeMap::new();
    let mut edits = Vec::new();
    for entry in entries {
        budget_check(budget)?;
        let target = ObjectNode {
            instance_id: text(entry, "instanceId")?.to_owned(),
            node_id: text(entry, "nodeId")?.to_owned(),
        };
        match text(entry, "kind")? {
            "update_transform" => {
                let fields = existing.entry(target).or_default();
                if fields.0.replace(entry["transform"].clone()).is_some() {
                    return Err(mapping_error());
                }
            }
            "update_display" => {
                let fields = existing.entry(target).or_default();
                if fields.1.replace(entry["display"].clone()).is_some() {
                    return Err(mapping_error());
                }
            }
            "create_node" => edits.push(SceneEdit::Create {
                target,
                node: entry["node"].clone(),
            }),
            "delete_node" => edits.push(SceneEdit::Delete { target }),
            // Attaching an animation requires its independently verified codec,
            // not a static pose extracted from its first or last sample.
            _ => {
                return Err(AppError::new(
                    "UNSUPPORTED_FORMAT",
                    "Manual static ScenePatch codec cannot attach a clip",
                ));
            }
        }
    }
    for (target, (transform, display)) in existing {
        budget_check(budget)?;
        edits.push(SceneEdit::Existing {
            target,
            transform,
            display,
        });
    }
    let losses = payload["losses"].as_array().ok_or_else(invalid)?.clone();
    budget_check(budget)?;
    Ok(ManualSceneInputs {
        selection: Selection::from_value(selection).map_err(exchange_app)?,
        edits,
        artifact: artifact.clone(),
        source_artifact,
        source_map,
        losses,
        policy: registration.policy.clone(),
    })
}
fn same_resource(left: &ResourceRef, right: &ResourceRef) -> bool {
    left.resource_id == right.resource_id
        && left.sha256 == right.sha256
        && left.media_type == right.media_type
        && left.size_bytes == right.size_bytes
}
fn validate(definition: &str, value: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .and_then(|v| v.validate(definition, value))
        .map_err(|_| invalid())
}
fn text<'a>(value: &'a Value, key: &str) -> AppResult<&'a str> {
    value[key].as_str().ok_or_else(invalid)
}
fn context_id(value: &Value) -> AppResult<ContextId> {
    ContextId::new(text(value, "contextId")?).map_err(|_| invalid())
}
fn budget_check(budget: &RequestBudget) -> AppResult<()> {
    budget.check().map_err(|e| AppError::new(e.code, e.message))
}
fn service(error: AppError) -> ServiceError {
    ServiceError::new(
        error.code,
        "The actual registered feature source rejected the request",
    )
}
fn target_service(error: AppError) -> ServiceError {
    if error.code == "TARGET_UNVERIFIED" {
        service(unsupported_target())
    } else {
        service(error)
    }
}
fn app_exchange(error: AppError) -> ExchangeError {
    ExchangeError::new(error.code, error.message)
}
fn exchange_app(error: ExchangeError) -> AppError {
    AppError::caused_by(
        error.code,
        "The actual registered exchange source rejected the request",
        error,
    )
}
fn storage_app(error: StorageError) -> AppError {
    let code = match &error {
        StorageError::NotFound(_) => "NOT_FOUND",
        StorageError::Conflict(_) => "REVISION_CONFLICT",
        StorageError::InvalidInput(_) => "BUDGET_EXCEEDED",
        StorageError::Corrupt(_) => "SOURCE_CORRUPT",
        StorageError::InvalidTransition(message) if message.starts_with("CANCELLED: ") => {
            "CANCELLED"
        }
        StorageError::InvalidTransition(message)
            if message.starts_with("TIME_BUDGET_EXCEEDED: ") =>
        {
            "TIME_BUDGET_EXCEEDED"
        }
        StorageError::InvalidTransition(message)
            if message.starts_with("PERMISSION_REQUIRED: ") =>
        {
            "PERMISSION_REQUIRED"
        }
        _ => "SOURCE_UNAVAILABLE",
    };
    AppError::storage(code, error)
}
fn storage_exchange(error: StorageError) -> ExchangeError {
    app_exchange(storage_app(error))
}
fn storage_from_app(error: AppError) -> StorageError {
    StorageError::InvalidTransition(format!("{}: {}", error.code, error.message))
}
fn artifact_app(error: AppError) -> ArtifactError {
    ArtifactError::new(
        error.code,
        "The current exact feature resource authority rejected the read",
    )
}
fn forbidden() -> AppError {
    AppError::new(
        "PERMISSION_REQUIRED",
        "No current exact source/resource/rights permission exists",
    )
}
fn invalid() -> AppError {
    AppError::new(
        "SCHEMA_INVALID",
        "The actual source bytes or identity violate the original contract",
    )
}
fn conflict() -> AppError {
    AppError::new(
        "REVISION_CONFLICT",
        "The source differs from the registered exact Project or artifact revision",
    )
}
fn mapping_error() -> AppError {
    AppError::new(
        "OBJECT_MAPPING_AMBIGUOUS",
        "Manual codec mapping is incomplete, duplicate or differs from qualified identities",
    )
}
fn stale() -> AppError {
    AppError::new(
        "STALE_CONTEXT",
        "The current server-owned source context changed",
    )
}
fn busy() -> AppError {
    AppError::new(
        "SOURCE_BUSY",
        "A scoped source registry is already borrowed",
    )
}
fn limit() -> AppError {
    AppError::new(
        "BUDGET_EXCEEDED",
        "The finite feature source limit was exceeded",
    )
}
fn unavailable() -> AppError {
    AppError::new(
        "SOURCE_UNAVAILABLE",
        "No actual source registration or codec is installed",
    )
}
fn unsupported_target() -> AppError {
    AppError::new(
        "UNSUPPORTED_TARGET_VERSION",
        "No actual verified target evidence is installed",
    )
}

#[cfg(test)]
#[path = "feature_source_tests.rs"]
mod tests;

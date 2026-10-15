//! Concrete planning over one paired host, one request generation and the
//! application's call-scoped Store. Compilation does not dispatch a command.
//! Every world batch is an exact changed phase subset; exporting a scene never
//! implicitly schedules its activate/cleanup functions.

use crate::{
    auth::AuthenticatedPrincipal,
    authority::LocalAuthority,
    feature_sources::SharedFeaturePermissions,
    host::HostBridge,
    native_targets::{NativeObservation, NativeSelector, NativeTargetError, NativeTargetReader},
    planning_source::{
        BorrowedProjectSource, LocalPlanningAccess, PlanningBackendPort, PlanningStore,
        SharedPlanningContexts, SharedPlanningData, VerifiedPlanningTarget,
    },
    production_factory::RegisteredCompatibilityProfiles,
    service::{RequestBudget, RequestContextSlot},
    target_profile::{RegisteredTargetProfiles, ResolvedTargetProfile},
};
use mmmm_adapters::{
    ActionDescriptor, ActionReadiness, Availability, CompatibilityEvidence, Effect,
    InventorySnapshot, ProviderInventory, ProviderRegistry, RegistrationMode,
    RegistrationObservation, RouteContext,
};
use mmmm_application::{Access, AppError, AppResult, AuthorityPort, RecoveryPreparation};
use mmmm_compiler::{
    PackBuildInputs, VerifiedTarget,
    scene::{
        Native26_3SceneCodec, NativeSceneInstruction, NativeSceneStep, SceneBuildInputs,
        SceneDraft, SceneLifecyclePhase, SceneRegistryVerifier, SceneResource, scene_lower,
    },
};
use mmmm_contracts::{
    BindingId, ContextId, ContractValidator, InstanceId, ModuleId, ObjectId, PrincipalId,
    ProjectId, ResourceId, Sha256Digest, TargetProfileId, WorldId, canonical_digest, encode_json,
    raw_digest,
};
use mmmm_domain::{
    commands::{CommandLayoutSupport, CommandModule, CommandStateRules, ParseStatus},
    types::ResourceRef,
};
use mmmm_planner::{
    InstanceProjection, NativeActionRoute, NativeKind, NativeTargetSnapshot, OwnedKind,
    PlanningEnvironmentPort, PreparedNativeChange, ProjectCatalog, ProjectSourcePort,
    ProjectionCoverage, RegisteredActionFootprint, TargetBeforeImage,
};
use mmmm_runtime::storage::{
    DurableStore, RegionScope, StorageError, WriteScope,
    artifact::ResourceOwner,
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

#[path = "native_block_footprint.rs"]
mod block_footprint;

const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_DOCUMENT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ITEMS: usize = 4096;
const MAX_NATIVE_TARGETS: usize = 256;
type ReadinessActionKey = (PrincipalId, ContextId, BindingId, String);
type ReadinessActions = BTreeMap<ReadinessActionKey, ReadinessRecord>;

/// Known loss coverage is installed by an actual provider/source owner. A
/// missing record keeps loss coverage unknown and cannot select a mutation.
/// This is an in-process registry; no public DTO or facade writes it.
#[derive(Default, Clone)]
pub struct NativeReadinessRegistry {
    entries: Rc<RefCell<ReadinessActions>>,
}
#[derive(Clone)]
struct ReadinessRecord {
    authenticated: AuthenticatedPrincipal,
    context_digest: Sha256Digest,
    implementation: Sha256Digest,
    loss_codes: BTreeSet<String>,
}
impl NativeReadinessRegistry {
    pub fn register_known_losses(
        &self,
        authenticated: &AuthenticatedPrincipal,
        context: &Value,
        binding: BindingId,
        action: &ActionDescriptor,
        loss_codes: BTreeSet<String>,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        check_budget(budget)?;
        let id = context_id(context)?;
        if !authenticated.is_current()
            || !authenticated.permits_context(id.as_str())
            || context["principalRef"] != authenticated.principal().as_str()
            || loss_codes.len() > 256
            || loss_codes.iter().any(|s| s.is_empty() || s.len() > 128)
        {
            return Err(forbidden());
        }
        validate("ExecutionContext", context)?;
        mmmm_contracts::verify_projected_digest("ExecutionContext", context)
            .map_err(|_| stale())?;
        let key = (
            authenticated.principal().clone(),
            id,
            binding,
            action.action_id.to_string(),
        );
        let entry = ReadinessRecord {
            authenticated: authenticated.clone(),
            context_digest: field_digest(context, "contextDigest")?,
            implementation: action.implementation_digest.clone(),
            loss_codes,
        };
        let mut entries = self.entries.try_borrow_mut().map_err(|_| busy())?;
        entries.retain(|_, entry| entry.authenticated.is_current());
        if entries.len() >= MAX_ITEMS || entries.contains_key(&key) {
            return Err(error(
                "REGISTRATION_CONFLICT",
                "Provider loss coverage already exists or exceeds its finite capacity",
            ));
        }
        entries.insert(key, entry);
        check_budget(budget)
    }
    fn losses(
        &self,
        authenticated: &AuthenticatedPrincipal,
        context: &Value,
        binding: &BindingId,
        action: &ActionDescriptor,
    ) -> AppResult<Option<BTreeSet<String>>> {
        let entries = self.entries.try_borrow().map_err(|_| busy())?;
        let key = (
            authenticated.principal().clone(),
            context_id(context)?,
            binding.clone(),
            action.action_id.to_string(),
        );
        Ok(entries
            .get(&key)
            .filter(|record| {
                record.authenticated.same_session(authenticated)
                    && record.context_digest.as_str()
                        == context["contextDigest"].as_str().unwrap_or("")
                    && record.implementation == action.implementation_digest
            })
            .map(|record| record.loss_codes.clone()))
    }
}

/// The native scene registry owns actual target codec, source symbol, media and
/// state witnesses. It is a typed mandatory dependency, never profile flags.
/// Animation, physics and unsupported source kinds need their owning codecs;
/// this backend rejects them rather than dropping an authored object.
#[derive(Clone)]
pub struct NativeBackendComposition {
    pub request: RequestContextSlot,
    pub authority: LocalAuthority,
    pub hosts: HostBridge,
    pub contexts: SharedPlanningContexts,
    pub data: SharedPlanningData,
    pub targets: RegisteredTargetProfiles,
    pub permissions: Option<SharedFeaturePermissions>,
    pub readiness: NativeReadinessRegistry,
    pub compatibility: RegisteredCompatibilityProfiles,
    pub scene_registry: Rc<dyn SceneRegistryVerifier>,
    /// A registered Rust provider supplies metadata routes independently of
    /// Java. Absent registration leaves those routes unavailable.
    pub owned_inventory: Option<Rc<dyn OwnedNativeInventory>>,
}
pub trait OwnedNativeInventory {
    fn append_actual(
        &self,
        authenticated: &AuthenticatedPrincipal,
        context: &Value,
        registry: &mut ProviderRegistry,
        budget: &RequestBudget,
    ) -> AppResult<()>;
    fn route(
        &self,
        authenticated: &AuthenticatedPrincipal,
        kind: NativeKind,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<NativeActionRoute>;
}
#[derive(Clone)]
pub struct HostNativeBackend {
    composition: NativeBackendComposition,
}
impl HostNativeBackend {
    pub fn new(composition: NativeBackendComposition) -> Self {
        Self { composition }
    }
    fn current(
        &self,
        principal: &PrincipalId,
        context: &Value,
    ) -> AppResult<(AuthenticatedPrincipal, RequestBudget, LocalPlanningAccess)> {
        let (authenticated, budget) = self.composition.request.current().map_err(service_error)?;
        if authenticated.principal() != principal {
            return Err(forbidden());
        }
        let access = LocalPlanningAccess::new(
            authenticated.clone(),
            self.composition.authority.clone(),
            self.composition.hosts.clone(),
            budget.clone(),
            self.composition.contexts.clone(),
        )?;
        let project = ProjectId::new(text(context, "projectId")?).map_err(|_| invalid())?;
        access.authorize_project(principal, &project, Some(context), Access::Plan)?;
        Ok((authenticated, budget, access))
    }
    fn resolved(
        &self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        profile: &TargetProfileId,
        context: &Value,
    ) -> AppResult<ResolvedTargetProfile> {
        let (authenticated, budget, _) = self.current(principal, context)?;
        let hello = self.composition.hosts.hello_with_deadline(
            principal,
            &context_id(context)?,
            budget.deadline(),
        )?;
        self.composition.targets.resolve_live(
            store,
            &authenticated,
            profile,
            context,
            &hello,
            &budget,
        )
    }
    fn source<'a>(
        &self,
        store: &PlanningStore<'a>,
        access: LocalPlanningAccess,
    ) -> BorrowedProjectSource<'a> {
        BorrowedProjectSource::new(store.clone(), access, self.composition.data.clone())
    }
    fn lower_sources(
        &self,
        project: &Value,
        owned: &[Value],
        resources: &[SceneResource],
        target: &VerifiedTarget,
    ) -> AppResult<SceneDraft> {
        let catalog = ProjectCatalog::from_project(project)?;
        let mut groups: BTreeMap<OwnedKind, Vec<Value>> = BTreeMap::new();
        let mut seen = BTreeSet::new();
        if owned.len() > MAX_ITEMS || resources.len() > MAX_ITEMS {
            return Err(budget_error());
        }
        for value in owned {
            let pin = catalog
                .pins()
                .iter()
                .find(|pin| value[pin.kind.id_field()].as_str() == Some(pin.object_id.as_str()))
                .ok_or_else(|| {
                    error(
                        "REFERENCE_UNRESOLVED",
                        "Owned lowering source is not an exact Project pin",
                    )
                })?;
            validate(pin.kind.definition(), value)?;
            if !seen.insert((pin.kind, pin.object_id.clone()))
                || mmmm_contracts::verify_projected_digest(pin.kind.definition(), value)
                    .ok()
                    .as_ref()
                    != Some(&pin.revision)
            {
                return Err(stale());
            }
            if matches!(pin.kind, OwnedKind::Clip | OwnedKind::PhysicsDefinition) {
                return Err(error(
                    "UNOWNED_REQUIRED_CAPABILITY",
                    "Animation or physics source needs its independently verified complete lowering codec",
                ));
            }
            groups.entry(pin.kind).or_default().push(value.clone());
        }
        if catalog
            .pins()
            .iter()
            .any(|pin| !seen.contains(&(pin.kind, pin.object_id.clone())))
        {
            return Err(error(
                "REFERENCE_UNRESOLVED",
                "Pack lowering would omit an owned Project source",
            ));
        }
        scene_lower(
            target,
            SceneBuildInputs::new(
                project.clone(),
                groups.remove(&OwnedKind::Prefab).unwrap_or_default(),
                groups.remove(&OwnedKind::Instance).unwrap_or_default(),
                groups.remove(&OwnedKind::CommandModule).unwrap_or_default(),
                groups.remove(&OwnedKind::Asset).unwrap_or_default(),
                resources.to_vec(),
            ),
            &Native26_3SceneCodec,
            self.composition.scene_registry.as_ref(),
        )
        .map_err(domain_error)
    }
    /// Same exact before/after closure used by both snapshot planning and the
    /// composite's sealed execution codec. It performs read/private staging
    /// only and returns no transport endpoint or permission grant.
    pub fn prepare_native_batch(
        &self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        change: &PreparedNativeChange,
        context: &Value,
    ) -> AppResult<PreparedNativeBatch> {
        let (_, budget, access) = self.current(principal, context)?;
        if !change.kind.world_effect()
            || change.project_id != *project.project_id()
            || change.project_base_revision != *project.revision()
            || change.target_profile_id != *project.target_profile_id()
        {
            return Err(invalid());
        }
        change.to_arguments()?;
        let target = self.resolved(store, principal, project.target_profile_id(), context)?;
        let proof = target.planning_target()?;
        if !proof.native_kinds.contains(&change.kind) {
            return Err(error(
                "TARGET_UNVERIFIED",
                "Selected world kind has no independently admitted complete runtime codec evidence",
            ));
        }
        let compiler_target = proof.compiler;
        let mut source = self.source(store, access.clone());
        let actual = source.inspect_owned(principal, project, MAX_BYTES)?;
        verify_projection_sources(change, &actual)?;
        let before_values: Vec<_> = actual.iter().map(|(_, value)| value.clone()).collect();
        let after_values = apply_document_changes(project, change, &actual)?;
        let mut bytes_left = MAX_BYTES;
        let before_resources = read_scene_resources(
            &mut source,
            principal,
            project,
            &before_values,
            context,
            &budget,
            &mut bytes_left,
        )?;
        let after_resources = read_scene_resources(
            &mut source,
            principal,
            project,
            &after_values,
            context,
            &budget,
            &mut bytes_left,
        )?;
        let before = self.lower_sources(
            project.project(),
            &before_values,
            &before_resources,
            &compiler_target,
        )?;
        let after = self.lower_sources(
            &change.project_after,
            &after_values,
            &after_resources,
            &compiler_target,
        )?;
        if !before.losses().is_empty() || !after.losses().is_empty() {
            return Err(error(
                "LOSS_APPROVAL_REQUIRED",
                "Native delta lowering has losses not frozen in its source approval",
            ));
        }
        let selected = select_stage_delta(&before, &after, &change.affected_instances())?;
        self.composition
            .targets
            .verify_scene_steps(store, &target, &selected)?;
        // Observe the full old/new projection, including unchanged subjects.
        // A complete projection witness cannot be inferred from the subset of
        // subjects this phase actually changes.
        let affected = change.affected_instances();
        let observation_steps: Vec<_> = before
            .native_steps()
            .iter()
            .chain(after.native_steps())
            .filter(|step| {
                step.phase() == SceneLifecyclePhase::Stage && affected.contains(step.instance_id())
            })
            .cloned()
            .collect();
        let selectors = selectors_for_steps(&observation_steps)?;
        let before_tags = compiled_before_tags(&before, &change.affected_instances())?;
        let profile_evidence = target.profile_evidence()?;
        let scope = complete_scope(change, context, &selectors)?;
        self.composition.authority.authorize_retained_scope(
            principal,
            project.project_id(),
            &context_id(context)?,
            &field_digest(context, "policyRevision")?,
            &serde_json::to_value(&scope).map_err(|_| invalid())?,
        )?;
        access.authorize_project(principal, project.project_id(), Some(context), Access::Plan)?;
        Ok(PreparedNativeBatch {
            steps: selected,
            selectors,
            before_tags,
            scope,
            profile_evidence,
            context_digest: field_digest(context, "contextDigest")?,
            prepared_digest: raw_digest(
                &encode_json(&change.to_arguments()?).map_err(|_| invalid())?,
            ),
            projection_steps: observation_steps,
            before_digests: BTreeMap::new(),
            compiler_digest: after.compiler_digest().clone(),
            codec_digest: after.codec_digest().clone(),
        })
    }
    fn snapshot(
        &self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        change: &PreparedNativeChange,
        context: &Value,
    ) -> AppResult<NativeTargetSnapshot> {
        let (authenticated, budget, access) = self.current(principal, context)?;
        if change.project_id != *project.project_id()
            || change.project_base_revision != *project.revision()
            || change.target_profile_id != *project.target_profile_id()
        {
            return Err(stale());
        }
        change.to_arguments()?;
        let rpc = BackendReadRpc {
            authenticated,
            budget: budget.clone(),
            authority: self.composition.authority.clone(),
            project: project.project_id().clone(),
            context: context.clone(),
            context_id: context_id(context)?,
        };
        let mut targets = capture_authoring_before(store, &rpc, project, change)?;
        let batch = if change.kind.world_effect() {
            Some(self.prepare_native_batch(store, principal, project, change, context)?)
        } else {
            None
        };
        let scope = if let Some(batch) = &batch {
            batch.scope.clone()
        } else {
            metadata_scope(change)?
        };
        if let Some(batch) = &batch {
            let native = NativeTargetReader::new(
                self.composition.hosts.clone(),
                self.composition.authority.clone(),
                self.composition.request.clone(),
            );
            let generation = text(&batch.profile_evidence, "registryGeneration")?;
            let read = store.with_write(|store| {
                native
                    .observe_retained(store, context, &batch.selectors, generation)
                    .map_err(native_error)
            })?;
            if read.retained_resource().is_none() {
                return Err(unverified());
            }
            for observation in read.into_targets() {
                targets.push(native_before_image(&observation, &batch.before_tags)?);
            }
        }
        let footprint = canonical_digest(&serde_json::to_value(&scope).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        let mut coverage = Vec::new();
        for projection in &change.world_projection {
            let batch = batch.as_ref().ok_or_else(invalid)?;
            let subjects = projection_subjects(projection, batch, &targets)?;
            if subjects.is_empty() {
                return Err(unverified());
            }
            coverage.push(ProjectionCoverage {
                instance_id: projection.after.instance_id.clone(),
                projection_digest: canonical_digest(
                    &serde_json::to_value(projection).map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?,
                footprint_digest: footprint.clone(),
                target_subjects: subjects,
            });
        }
        self.composition.authority.authorize_retained_scope(
            principal,
            project.project_id(),
            &context_id(context)?,
            &field_digest(context, "policyRevision")?,
            &serde_json::to_value(&scope).map_err(|_| invalid())?,
        )?;
        access.authorize_project(principal, project.project_id(), Some(context), Access::Plan)?;
        Ok(NativeTargetSnapshot {
            context_digest: field_digest(context, "contextDigest")?,
            scope,
            targets,
            projection_coverage: coverage,
        })
    }
    pub fn capture_authored_before(
        &self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        change: &PreparedNativeChange,
        context: &Value,
    ) -> AppResult<Vec<TargetBeforeImage>> {
        let (authenticated, budget, access) = self.current(principal, context)?;
        if change.project_id != *project.project_id()
            || change.project_base_revision != *project.revision()
            || change.target_profile_id != *project.target_profile_id()
        {
            return Err(stale());
        }
        change.to_arguments()?;
        let rpc = BackendReadRpc {
            authenticated,
            budget,
            authority: self.composition.authority.clone(),
            project: project.project_id().clone(),
            context: context.clone(),
            context_id: context_id(context)?,
        };
        let output = capture_authoring_before(store, &rpc, project, change)?;
        access.authorize_project(principal, project.project_id(), Some(context), Access::Plan)?;
        Ok(output)
    }
}

/// Private immutable source projection. Only actual lowering above constructs
/// it. Fields cannot be deserialized from an intent or a provider result.
#[derive(Clone)]
pub struct PreparedNativeBatch {
    steps: Vec<NativeSceneStep>,
    selectors: Vec<NativeSelector>,
    before_tags: BTreeMap<String, String>,
    scope: WriteScope,
    profile_evidence: Value,
    context_digest: Sha256Digest,
    prepared_digest: Sha256Digest,
    compiler_digest: Sha256Digest,
    codec_digest: Sha256Digest,
    projection_steps: Vec<NativeSceneStep>,
    before_digests: BTreeMap<Sha256Digest, Sha256Digest>,
}
impl PreparedNativeBatch {
    pub fn steps(&self) -> &[NativeSceneStep] {
        &self.steps
    }
    pub fn selectors(&self) -> &[NativeSelector] {
        &self.selectors
    }
    pub fn scope(&self) -> &WriteScope {
        &self.scope
    }
    pub fn profile_evidence(&self) -> &Value {
        &self.profile_evidence
    }
    pub fn context_digest(&self) -> &Sha256Digest {
        &self.context_digest
    }
    pub fn prepared_digest(&self) -> &Sha256Digest {
        &self.prepared_digest
    }
    pub fn compiler_digest(&self) -> &Sha256Digest {
        &self.compiler_digest
    }
    pub fn codec_digest(&self) -> &Sha256Digest {
        &self.codec_digest
    }
    pub fn phase(&self) -> SceneLifecyclePhase {
        SceneLifecyclePhase::Stage
    }
    pub fn before_owner_tag(&self, selector: &NativeSelector) -> Option<&str> {
        self.before_tags
            .get(selector.value()["uuid"].as_str()?)
            .map(String::as_str)
    }
    pub fn before_image(&self, observation: &NativeObservation) -> AppResult<TargetBeforeImage> {
        native_before_image(observation, &self.before_tags)
    }
    /// Bind independently read actual bytes at the dispatch boundary. Caller
    /// expected values and compiler desired payload cannot seed these hashes.
    pub fn seal_before(mut self, observations: &[NativeObservation]) -> AppResult<Self> {
        let map = observation_map(&self.selectors, observations)?;
        for (key, observation) in map {
            self.before_image(observation)?;
            self.before_digests
                .insert(key, observation.digest().clone());
        }
        Ok(self)
    }
    /// The admitted direct block-state path verifies the exact desired state,
    /// complete absence of a block entity, and all unchanged captured subjects.
    /// Other generated instructions need their complete expected-NBT/state
    /// codec; a provider's return or desired JSON cannot substitute for it.
    pub fn verify_after(&self, observations: &[NativeObservation]) -> AppResult<bool> {
        let map = observation_map(&self.selectors, observations)?;
        if self.before_digests.len() != self.selectors.len() {
            return Err(unverified());
        }
        let mut changed = BTreeMap::new();
        for step in &self.steps {
            let NativeSceneInstruction::Block {
                dimension,
                position,
                state,
            } = step.instruction()
            else {
                return Err(error(
                    "NATIVE_EXPECTATION_CODEC_REQUIRED",
                    "Complete expected persisted target bytes are not implemented for this native instruction",
                ));
            };
            let state_value = serde_json::to_value(state).map_err(|_| invalid())?;
            for kind in ["block_state", "block_entity"] {
                let selector = json!({"kind":kind,"dimension":dimension,"position":position});
                let key = canonical_digest(&selector).map_err(|_| invalid())?;
                if let Some(old) = changed.insert(key, (kind, state_value.clone()))
                    && old.1 != state_value
                {
                    return Err(invalid());
                }
            }
        }
        for (key, actual) in map {
            if !actual.full_target() {
                return Err(unverified());
            }
            if let Some((kind, state)) = changed.get(&key) {
                if actual.raw()["payload"]["blockState"] != *state {
                    return Ok(false);
                }
                if (*kind == "block_state"
                    && (actual.presence() != "present"
                        || actual.raw()["payload"]["hasBlockEntity"] != false))
                    || (*kind == "block_entity" && actual.presence() != "absent")
                {
                    return Ok(false);
                }
            } else if self.before_digests.get(&key) != Some(actual.digest()) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn observation_map<'a>(
    selectors: &[NativeSelector],
    observations: &'a [NativeObservation],
) -> AppResult<BTreeMap<Sha256Digest, &'a NativeObservation>> {
    if selectors.len() != observations.len() || selectors.len() > MAX_NATIVE_TARGETS {
        return Err(unverified());
    }
    let expected = selectors
        .iter()
        .map(|selector| canonical_digest(selector.value()).map_err(|_| invalid()))
        .collect::<AppResult<BTreeSet<_>>>()?;
    let mut result = BTreeMap::new();
    for observation in observations {
        let key = canonical_digest(observation.selector().value()).map_err(|_| invalid())?;
        if !expected.contains(&key) || result.insert(key, observation).is_some() {
            return Err(unverified());
        }
    }
    Ok(result)
}

impl PlanningBackendPort for HostNativeBackend {
    fn inventory_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        context: &Value,
    ) -> AppResult<InventorySnapshot> {
        self.observed_inventory(Some(store), principal, context)
    }
    fn verify_live_target(
        &mut self,
        _principal: &PrincipalId,
        _profile: &TargetProfileId,
        _context: &Value,
        _hello: &Value,
        _budget: &RequestBudget,
    ) -> AppResult<VerifiedPlanningTarget> {
        Err(store_required())
    }
    fn verify_live_target_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        profile: &TargetProfileId,
        context: &Value,
        hello: &Value,
        budget: &RequestBudget,
    ) -> AppResult<VerifiedPlanningTarget> {
        let (authenticated, current_budget, _) = self.current(principal, context)?;
        if current_budget.deadline() != budget.deadline()
            || !std::ptr::eq(current_budget.cancellation(), budget.cancellation())
        {
            return Err(forbidden());
        }
        self.composition
            .targets
            .resolve_live(store, &authenticated, profile, context, hello, budget)?
            .planning_target()
    }
    fn lower_owned_pack(
        &mut self,
        _principal: &PrincipalId,
        _project: &ProjectCatalog,
        _owned: &[Value],
        _resources: &[SceneResource],
        _context: &Value,
        _budget: &RequestBudget,
    ) -> AppResult<PackBuildInputs> {
        Err(store_required())
    }
    fn lower_owned_pack_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        owned: &[Value],
        resources: &[SceneResource],
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<PackBuildInputs> {
        check_budget(budget)?;
        let (_, current_budget, access) = self.current(principal, context)?;
        if current_budget.deadline() != budget.deadline()
            || !std::ptr::eq(current_budget.cancellation(), budget.cancellation())
        {
            return Err(forbidden());
        }
        let target = self
            .resolved(store, principal, project.target_profile_id(), context)?
            .planning_target()?
            .compiler;
        let mut all_resources = resources.to_vec();
        let mut included = BTreeMap::new();
        let mut left = MAX_BYTES;
        for resource in &all_resources {
            insert_resource(&mut included, resource.reference.clone())?;
            left = left
                .checked_sub(resource.bytes.len() as u64)
                .ok_or_else(budget_error)?;
        }
        let mut source = self.source(store, access.clone());
        for id in project.project()["resourceIds"]
            .as_array()
            .ok_or_else(invalid)?
        {
            check_budget(budget)?;
            let id = id.as_str().ok_or_else(invalid)?;
            let pin = source.resource_pin(principal, project, id, Some(context))?;
            let present = included.contains_key(&pin.resource_id);
            insert_resource(&mut included, pin.clone())?;
            if !present {
                let read = source.resource_bytes(principal, project, &pin, Some(context), left)?;
                left = left
                    .checked_sub(read.bytes.len() as u64)
                    .ok_or_else(budget_error)?;
                all_resources.push(SceneResource {
                    reference: read.resource,
                    bytes: read.bytes,
                });
            }
        }
        let draft = self.lower_sources(project.project(), owned, &all_resources, &target)?;
        if !draft.required_clip_ids().is_empty() {
            return Err(error(
                "UNOWNED_REQUIRED_CAPABILITY",
                "Pack needs complete instance-qualified animation lowering",
            ));
        }
        access.authorize_project(principal, project.project_id(), Some(context), Access::Plan)?;
        check_budget(budget)?;
        Ok(PackBuildInputs::new(
            project.project().clone(),
            vec![],
            BTreeMap::new(),
            BTreeSet::new(),
        )
        .with_scene(draft))
    }
    fn snapshot_native_targets_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        change: &PreparedNativeChange,
        context: &Value,
    ) -> AppResult<NativeTargetSnapshot> {
        self.snapshot(store, principal, project, change, context)
    }
    fn registered_action_footprint_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        request: &Value,
        action: &ActionDescriptor,
        context: &Value,
    ) -> AppResult<RegisteredActionFootprint> {
        self.owned_block_footprint(store, principal, project, request, action, context)
    }
    fn verify_projection_references_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        projection: &InstanceProjection,
        context: &Value,
    ) -> AppResult<Vec<Value>> {
        let (_, budget, access) = self.current(principal, context)?;
        let target = self
            .resolved(store, principal, project.target_profile_id(), context)?
            .planning_target()?
            .compiler;
        // The actual typed source resolver supplies command syntax and complete
        // external implementation pins, rather than preserving unresolved text.
        let transforms = mmmm_domain::graph::world_transforms(
            &projection.definition,
            &projection.after.placement,
            &projection.after.overrides,
        )
        .map_err(domain_error)?;
        for module in &projection.command_modules {
            let matrix = transforms
                .get(&module.local_origin_node_id)
                .ok_or_else(invalid)?;
            for command in &module.commands {
                check_budget(&budget)?;
                let resolved = self
                    .composition
                    .scene_registry
                    .resolve_command(
                        &target,
                        module,
                        command,
                        &projection.definition,
                        &projection.after,
                        matrix,
                        &BTreeMap::new(),
                    )
                    .map_err(domain_error)?;
                if !resolved.state_reads.is_empty() || !resolved.state_writes.is_empty() {
                    return Err(error(
                        "REFERENCE_UNRESOLVED",
                        "Command state references need exact registered qualified state bindings",
                    ));
                }
                if !resolved.external_functions.is_empty() {
                    return Err(error(
                        "DEPENDENCY_UNVERIFIED",
                        "External function source digest lacks its actual registered component identity and provenance",
                    ));
                }
            }
        }
        access.authorize_project(principal, project.project_id(), Some(context), Access::Plan)?;
        Ok(vec![])
    }
    fn command_layout_support_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        module: &Value,
        context: &Value,
    ) -> AppResult<CommandLayoutSupport> {
        self.current(principal, context)?;
        validate("CommandModule", module)?;
        if module["layout"] != "embedded" {
            return Err(error(
                "OPAQUE_RELOCATION",
                "Rack layout requires an independently registered parser/context relocation witness",
            ));
        }
        let target = self.resolved(store, principal, project.target_profile_id(), context)?;
        let compiler = target.planning_target()?.compiler;
        let capabilities = self
            .composition
            .scene_registry
            .verify_codec(
                &compiler,
                &mmmm_compiler::scene::SceneTargetCodec::codec_digest(&Native26_3SceneCodec),
            )
            .map_err(domain_error)?;
        if !capabilities.staged_command_blocks {
            return Err(unverified());
        }
        let profile = target.profile_evidence()?["profile"].clone();
        CommandLayoutSupport::from_verified_profile(
            &profile,
            CommandStateRules::SixAxisAdjacentChainConditionBehind,
            BTreeMap::new(),
        )
        .map_err(domain_error)
    }
}

impl HostNativeBackend {
    fn observed_inventory(
        &mut self,
        store: Option<&PlanningStore<'_>>,
        principal: &PrincipalId,
        context: &Value,
    ) -> AppResult<InventorySnapshot> {
        let (authenticated, budget, access) = self.current(principal, context)?;
        let call = self
            .composition
            .request
            .occupied_witness()
            .map_err(service_error)?;
        let permissions = match &self.composition.permissions {
            Some(port) => port.current(&authenticated, context, &budget)?,
            None => BTreeSet::new(),
        };
        let mut registry = ProviderRegistry::new();
        if context["environment"]["kind"] == "game" {
            // Only the same-Store path may advertise the built-in direct codec.
            // Its current actual host artifact is source identity, never a
            // numeric target/profile or a generic provider readiness grant.
            let owned_hello = if store.is_some() {
                let hello = self.composition.hosts.hello_with_deadline(
                    principal,
                    &context_id(context)?,
                    budget.deadline(),
                );
                let hello = block_footprint::finish(
                    hello,
                    (|| {
                        call.check_local().map_err(service_error)?;
                        self.current(principal, context).map(|_| ())
                    })(),
                )?;
                Some(hello)
            } else {
                None
            };
            call.check_local().map_err(service_error)?;
            let raw = self.composition.hosts.inventory_with_deadline(
                principal,
                &context_id(context)?,
                budget.deadline(),
            );
            let raw = block_footprint::finish(
                raw,
                (|| {
                    call.check_local().map_err(service_error)?;
                    self.current(principal, context).map(|_| ())
                })(),
            )?;
            validate("ProviderInventory", &raw)?;
            let inventory: ProviderInventory =
                serde_json::from_value(raw).map_err(|_| invalid())?;
            for provider in inventory.providers {
                if provider.environment
                    != serde_json::from_value(context["environment"].clone())
                        .map_err(|_| invalid())?
                {
                    return Err(stale());
                }
                // Host interface declarations stay interface_checked. Neither
                // readiness nor a numeric target suite promotes world evidence.
                let mut provider = provider;
                provider.compatibility_evidence = provider
                    .compatibility_evidence
                    .min(CompatibilityEvidence::InterfaceChecked);
                for action in &mut provider.actions {
                    action.version_evidence = action
                        .version_evidence
                        .min(mmmm_adapters::VersionEvidence::InterfaceChecked);
                }
                if provider.registration_mode == RegistrationMode::Compatibility {
                    let store = store.ok_or_else(store_required)?;
                    store.with_read(|store| {
                        self.composition.compatibility.bind_registered_into(
                            store,
                            &authenticated,
                            context,
                            &permissions,
                            &provider,
                            &mut registry,
                            &budget,
                        )
                    })?;
                    continue;
                }
                let action_readiness = provider
                    .actions
                    .iter()
                    .map(|action| {
                        Ok((
                            action.action_id.clone(),
                            ActionReadiness {
                                ready: provider.availability == Availability::Available,
                                possible_loss_codes: match owned_hello.as_ref().and_then(|hello| {
                                    block_footprint::known_losses(&provider, action, hello, context)
                                }) {
                                    Some(losses) => Some(losses),
                                    None => self.composition.readiness.losses(
                                        &authenticated,
                                        context,
                                        &provider.binding_id,
                                        action,
                                    )?,
                                },
                            },
                        ))
                    })
                    .collect::<AppResult<BTreeMap<_, _>>>()?;
                let observation = RegistrationObservation {
                    environment: provider.environment.clone(),
                    origin: provider.origin.clone(),
                    host_protocol_version: provider.host_protocol_version.clone(),
                    loaded: true,
                    connected: true,
                    availability: provider.availability,
                    evidence: provider.compatibility_evidence,
                    implementation_digests: provider
                        .actions
                        .iter()
                        .map(|a| (a.action_id.clone(), a.implementation_digest.clone()))
                        .collect(),
                    action_readiness,
                };
                registry
                    .register_observed_provider(
                        &serde_json::to_value(provider).map_err(|_| invalid())?,
                        observation,
                    )
                    .map_err(adapter_error)?;
            }
        }
        if let Some(owned) = &self.composition.owned_inventory {
            owned.append_actual(&authenticated, context, &mut registry, &budget)?;
        }
        let snapshot = registry
            .snapshot(
                RouteContext::from_execution_context(context, permissions)
                    .map_err(adapter_error)?,
                field_digest(context, "policyRevision")?,
            )
            .map_err(adapter_error)?;
        access.authorize_project(
            principal,
            &ProjectId::new(text(context, "projectId")?).map_err(|_| invalid())?,
            Some(context),
            Access::Plan,
        )?;
        call.check_local().map_err(service_error)?;
        Ok(snapshot)
    }
}
impl PlanningEnvironmentPort for HostNativeBackend {
    fn execution_budget_ms(&mut self, principal: &PrincipalId, context: &Value) -> AppResult<u64> {
        let (_, budget, _) = self.current(principal, context)?;
        let remaining = budget
            .deadline()
            .saturating_duration_since(std::time::Instant::now())
            .as_millis();
        let milliseconds = u64::try_from(remaining.min(3_600_000)).map_err(|_| budget_error())?;
        if milliseconds == 0 {
            Err(budget_error())
        } else {
            Ok(milliseconds)
        }
    }
    fn inventory(
        &mut self,
        principal: &PrincipalId,
        context: &Value,
    ) -> AppResult<InventorySnapshot> {
        self.observed_inventory(None, principal, context)
    }
    fn binding_dependency(
        &mut self,
        _principal: &PrincipalId,
        _binding: &BindingId,
        _digest: &Sha256Digest,
        _context: &Value,
    ) -> AppResult<Value> {
        Err(error(
            "DEPENDENCY_UNVERIFIED",
            "ConcretePlanningEnvironment owns the exact separately registered source dependency lookup",
        ))
    }
    fn native_route(
        &mut self,
        principal: &PrincipalId,
        kind: NativeKind,
        context: &Value,
    ) -> AppResult<NativeActionRoute> {
        let (authenticated, budget, _) = self.current(principal, context)?;
        if !kind.world_effect() {
            return self
                .composition
                .owned_inventory
                .as_ref()
                .ok_or_else(|| {
                    error(
                        "CAPABILITY_UNAVAILABLE",
                        "This Rust metadata implementation has not been registered",
                    )
                })?
                .route(&authenticated, kind, context, &budget);
        }
        let inventory = self.inventory(principal, context)?;
        let (action_id, semantic) = world_route(kind).ok_or_else(invalid)?;
        let candidates: Vec<_> = inventory
            .inventory()
            .providers
            .iter()
            .flat_map(|provider| {
                provider
                    .actions
                    .iter()
                    .map(move |action| (provider, action))
            })
            .filter(|(_, action)| {
                action.action_id.as_str() == action_id && action.semantic_kind.as_str() == semantic
            })
            .collect();
        if candidates.len() != 1 {
            return Err(error(
                "CAPABILITY_UNAVAILABLE",
                "Exact paired authored action is absent or ambiguous",
            ));
        }
        let (provider, action) = candidates[0];
        if action.effect != Effect::Write {
            return Err(invalid());
        }
        Ok(NativeActionRoute {
            binding_id: provider.binding_id.clone(),
            action_id: action.action_id.clone(),
            semantic_kind: action.semantic_kind.clone(),
            required_guarantees: BTreeSet::from([
                "authenticated_context".into(),
                "server_main_thread".into(),
            ]),
            acceptable_loss_codes: BTreeSet::new(),
        })
    }
    fn verified_native_target(
        &mut self,
        _principal: &PrincipalId,
        _profile: &TargetProfileId,
        _kind: NativeKind,
        _context: &Value,
    ) -> AppResult<mmmm_planner::VerifiedNativeTarget> {
        Err(store_required())
    }
    fn snapshot_native_targets(
        &mut self,
        _principal: &PrincipalId,
        _project: &ProjectCatalog,
        _change: &PreparedNativeChange,
        _context: &Value,
    ) -> AppResult<NativeTargetSnapshot> {
        Err(store_required())
    }
    fn registered_action_footprint(
        &mut self,
        principal: &PrincipalId,
        _project: &ProjectCatalog,
        _request: &Value,
        _action: &ActionDescriptor,
        context: &Value,
    ) -> AppResult<RegisteredActionFootprint> {
        self.current(principal, context)?;
        // An effect declaration says nothing about the complete resources read,
        // external inputs, dynamic locators or indirect effects. A registered
        // owner must supply its typed argument/footprint codec before planning.
        Err(error(
            "CAPABILITY_UNAVAILABLE",
            "Registered action has no complete authenticated argument and footprint codec",
        ))
    }
    fn relocatable_modules(
        &mut self,
        principal: &PrincipalId,
        _project: &ProjectCatalog,
        modules: &[Value],
        context: &Value,
    ) -> AppResult<BTreeSet<ModuleId>> {
        let (_, budget, _) = self.current(principal, context)?;
        let mut ids = BTreeSet::new();
        for value in modules {
            check_budget(&budget)?;
            validate("CommandModule", value)?;
            let module: CommandModule =
                serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            if module.commands.iter().any(|command| {
                command.parse_status == ParseStatus::Opaque || !command.references.is_empty()
            }) {
                return Err(error(
                    "OPAQUE_RELOCATION",
                    "Module relocation needs parser-owned exact symbol/context relocation evidence",
                ));
            }
            if !ids.insert(module.module_id) {
                return Err(invalid());
            }
        }
        // Empty/no-reference commands do not imply that absolute/relative text
        // was reviewed. Require the independently verified layout adapter below.
        if ids.is_empty() {
            Ok(ids)
        } else {
            Err(error(
                "OPAQUE_RELOCATION",
                "Command text has no complete registered relocation witness",
            ))
        }
    }
    fn command_layout_support(
        &mut self,
        _principal: &PrincipalId,
        _project: &ProjectCatalog,
        _module: &Value,
        _context: &Value,
    ) -> AppResult<CommandLayoutSupport> {
        Err(store_required())
    }
    fn command_layout_request(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        _instance: &Value,
        module: &Value,
        context: &Value,
    ) -> AppResult<Value> {
        self.current(principal, context)?;
        validate("CommandModule", module)?;
        // Embedded preserves authored context. Rack relocation requires its
        // explicit source/layout registration and is not inferred from origin.
        if module["layout"] != "embedded" {
            return Err(error(
                "OPAQUE_RELOCATION",
                "Rack layout has no registered explicit placement policy",
            ));
        }
        let value = json!({"module":module,"targetProfileId":project.target_profile_id(),"rackOrigin":[0,0,0],"gapBlocks":1,"activation":"staged_disabled"});
        validate("CommandLayoutRequest", &value)?;
        Ok(value)
    }
    fn verify_projection_references(
        &mut self,
        _principal: &PrincipalId,
        _project: &ProjectCatalog,
        _projection: &InstanceProjection,
        _context: &Value,
    ) -> AppResult<Vec<Value>> {
        Err(store_required())
    }
    fn compiler_target(
        &mut self,
        _principal: &PrincipalId,
        _profile: &TargetProfileId,
        _context: &Value,
    ) -> AppResult<VerifiedTarget> {
        Err(store_required())
    }
    fn pack_inputs(
        &mut self,
        _principal: &PrincipalId,
        _project: &ProjectCatalog,
        _owned: &[Value],
        _context: &Value,
    ) -> AppResult<PackBuildInputs> {
        Err(store_required())
    }
    fn recovery_route(
        &mut self,
        principal: &PrincipalId,
        _recovery: &RecoveryPreparation,
        context: &Value,
    ) -> AppResult<NativeActionRoute> {
        self.native_route(principal, NativeKind::Recovery, context)
    }
    fn recovery_scope(
        &mut self,
        principal: &PrincipalId,
        recovery: &RecoveryPreparation,
        _project: &ProjectCatalog,
        context: &Value,
    ) -> AppResult<WriteScope> {
        self.current(principal, context)?;
        if recovery.context_id != context_id(context)? {
            return Err(stale());
        }
        Err(error(
            "UNOWNED_REQUIRED_CAPABILITY",
            "Recovery requires the exact retained original full scope and supported target restore codec",
        ))
    }
    fn project_bindings_available(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
    ) -> AppResult<bool> {
        let (authenticated, budget) = self.composition.request.current().map_err(service_error)?;
        if authenticated.principal() != principal {
            return Err(forbidden());
        }
        check_budget(&budget)?;
        let mut authority = self.composition.authority.clone();
        authority.authorize(
            principal,
            project.project_id(),
            Access::ReadProject,
            None,
            None,
        )?;
        // This inspection port has no context or call-scoped Store with which
        // to obtain complete, current target and authored-binding evidence.
        // Offline metadata registration, a connected host's interface inventory
        // and numeric/parser admission cannot prove runtime binding readiness.
        // Keep the result unavailable until its owning typed evidence is wired.
        check_budget(&budget)?;
        Ok(false)
    }
}

pub(crate) fn world_route(kind: NativeKind) -> Option<(&'static str, &'static str)> {
    Some(match kind {
        NativeKind::Instantiate => ("mmmm:authored/instantiate", "mmmm:prefab_instantiate"),
        NativeKind::Clone => ("mmmm:authored/clone", "mmmm:instance_clone"),
        NativeKind::Relocate => ("mmmm:authored/relocate", "mmmm:instance_relocate"),
        NativeKind::DisplayPatch => ("mmmm:authored/display_patch", "mmmm:display_patch"),
        NativeKind::CommandPatch => ("mmmm:authored/command_patch", "mmmm:command_module_patch"),
        NativeKind::ScenePatch => ("mmmm:authored/scene_patch", "mmmm:scene_import_patch"),
        _ => return None,
    })
}
fn verify_projection_sources(
    change: &PreparedNativeChange,
    actual: &[(mmmm_planner::ObjectPin, Value)],
) -> AppResult<()> {
    for projection in &change.world_projection {
        if let Some(before) = &projection.before {
            let value = actual
                .iter()
                .find(|(pin, _)| {
                    pin.kind == OwnedKind::Instance
                        && pin.object_id.as_str() == before.instance_id.as_str()
                })
                .map(|(_, value)| value)
                .ok_or_else(stale)?;
            if canonical_digest(&serde_json::to_value(before).map_err(|_| invalid())?).ok()
                != canonical_digest(value).ok()
            {
                return Err(stale());
            }
            let definition = projection.before_definition.as_ref().ok_or_else(stale)?;
            let value = actual
                .iter()
                .find(|(pin, _)| {
                    pin.kind == OwnedKind::Prefab
                        && pin.object_id.as_str() == definition.prefab_id.as_str()
                })
                .map(|(_, value)| value)
                .ok_or_else(stale)?;
            if canonical_digest(&serde_json::to_value(definition).map_err(|_| invalid())?).ok()
                != canonical_digest(value).ok()
            {
                return Err(stale());
            }
        } else if actual.iter().any(|(pin, _)| {
            pin.kind == OwnedKind::Instance
                && pin.object_id.as_str() == projection.after.instance_id.as_str()
        }) {
            return Err(stale());
        }
    }
    Ok(())
}
fn apply_document_changes(
    project: &ProjectCatalog,
    change: &PreparedNativeChange,
    actual: &[(mmmm_planner::ObjectPin, Value)],
) -> AppResult<Vec<Value>> {
    let mut values: BTreeMap<_, _> = actual
        .iter()
        .map(|(pin, value)| ((pin.kind, pin.object_id.to_string()), value.clone()))
        .collect();
    for document in &change.document_changes {
        let key = (document.kind, document.object_id.clone());
        let current = values.get(&key);
        if current.and_then(|value| value["revision"].as_str())
            != document.before_revision.as_ref().map(Sha256Digest::as_str)
        {
            return Err(stale());
        }
        validate(document.kind.definition(), &document.after)?;
        if document.after[document.kind.id_field()] != document.object_id
            || mmmm_contracts::verify_projected_digest(document.kind.definition(), &document.after)
                .ok()
                .as_ref()
                != Some(&document.after_revision)
        {
            return Err(stale());
        }
        values.insert(key, document.after.clone());
    }
    let after = ProjectCatalog::from_project(&change.project_after)?;
    if after.project_id() != project.project_id()
        || after.target_profile_id() != project.target_profile_id()
        || after.pins().len() != values.len()
        || after.pins().iter().any(|pin| {
            values
                .get(&(pin.kind, pin.object_id.to_string()))
                .is_none_or(|value| value["revision"] != pin.revision.as_str())
        })
    {
        return Err(stale());
    }
    Ok(values.into_values().collect())
}
fn read_scene_resources(
    source: &mut dyn ProjectSourcePort,
    principal: &PrincipalId,
    project: &ProjectCatalog,
    owned: &[Value],
    context: &Value,
    budget: &RequestBudget,
    left: &mut u64,
) -> AppResult<Vec<SceneResource>> {
    let mut pins = BTreeMap::new();
    for value in owned {
        collect_resources(value, &mut pins, 0)?;
    }
    for id in project.project()["resourceIds"]
        .as_array()
        .ok_or_else(invalid)?
    {
        let pin = source.resource_pin(
            principal,
            project,
            id.as_str().ok_or_else(invalid)?,
            Some(context),
        )?;
        insert_resource(&mut pins, pin)?;
    }
    let mut resources = Vec::new();
    for resource in pins.into_values() {
        check_budget(budget)?;
        let read = source.resource_bytes(principal, project, &resource, Some(context), *left)?;
        *left = left
            .checked_sub(read.bytes.len() as u64)
            .ok_or_else(budget_error)?;
        resources.push(SceneResource {
            reference: read.resource,
            bytes: read.bytes,
        });
    }
    Ok(resources)
}
fn collect_resources(
    value: &Value,
    pins: &mut BTreeMap<ResourceId, ResourceRef>,
    depth: usize,
) -> AppResult<()> {
    if depth > 64 {
        return Err(budget_error());
    }
    match value {
        Value::Object(object)
            if object.len() == 4
                && ["resourceId", "sha256", "mediaType", "sizeBytes"]
                    .iter()
                    .all(|field| object.contains_key(*field)) =>
        {
            validate("ResourceRef", value)?;
            let mut typed = value.clone();
            if let Some(size) = value["sizeBytes"].as_f64() {
                typed["sizeBytes"] = json!(size as u64);
            }
            insert_resource(pins, serde_json::from_value(typed).map_err(|_| invalid())?)
        }
        Value::Object(object) => {
            for child in object.values() {
                collect_resources(child, pins, depth + 1)?;
            }
            Ok(())
        }
        Value::Array(array) => {
            for child in array {
                collect_resources(child, pins, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
fn insert_resource(
    pins: &mut BTreeMap<ResourceId, ResourceRef>,
    resource: ResourceRef,
) -> AppResult<()> {
    if pins.len() >= MAX_ITEMS {
        return Err(budget_error());
    }
    if let Some(old) = pins.get(&resource.resource_id) {
        if old.sha256 != resource.sha256
            || old.size_bytes != resource.size_bytes
            || old.media_type != resource.media_type
        {
            return Err(stale());
        }
    } else {
        pins.insert(resource.resource_id.clone(), resource);
    }
    Ok(())
}

/// Select changed Stage instructions by their stable typed source locator.
/// Removed targets need Cleanup; activation drift needs its separate proof.
fn select_stage_delta(
    before: &SceneDraft,
    after: &SceneDraft,
    affected: &BTreeSet<InstanceId>,
) -> AppResult<Vec<NativeSceneStep>> {
    let previous = phase_map(before.native_steps(), affected, SceneLifecyclePhase::Stage)?;
    let next = phase_map(after.native_steps(), affected, SceneLifecyclePhase::Stage)?;
    if previous.keys().any(|key| !next.contains_key(key)) {
        return Err(error(
            "NATIVE_CLEANUP_REQUIRED",
            "Delta removes a former target and needs a separately approved Cleanup phase",
        ));
    }
    let old_activate = active_phase_map(before.native_steps(), affected)?;
    let new_activate = active_phase_map(after.native_steps(), affected)?;
    if old_activate != new_activate {
        return Err(error(
            "NATIVE_ACTIVATION_REQUIRED",
            "Delta changes command activation and needs its exact indirect-effect closure",
        ));
    }
    let mut selected = Vec::new();
    for step in after.native_steps() {
        if step.phase() != SceneLifecyclePhase::Stage || !affected.contains(step.instance_id()) {
            continue;
        }
        let key = step_key(step)?;
        let value = serde_json::to_value(step).map_err(|_| invalid())?;
        if previous.get(&key) != Some(&value) {
            selected.push(step.clone());
        }
    }
    if selected
        .iter()
        .any(|step| matches!(step.instruction(), NativeSceneInstruction::Display { .. }))
    {
        return Err(error(
            "NATIVE_ENTITY_PATCH_UNSUPPORTED",
            "Display create needs proven persistent absence; replacement needs a separately fenced native patch codec",
        ));
    }
    if selected
        .iter()
        .any(|step| !matches!(step.instruction(), NativeSceneInstruction::Block { .. }))
    {
        return Err(error(
            "NATIVE_EXPECTATION_CODEC_REQUIRED",
            "Native instruction lacks its complete independent persisted after-state expectation codec",
        ));
    }
    if selected.is_empty() || selected.len() > MAX_NATIVE_TARGETS {
        return Err(error(
            "NATIVE_DELTA_UNSUPPORTED",
            "Native change has no finite nonempty directly executable Stage delta",
        ));
    }
    Ok(selected)
}
fn active_phase_map(
    steps: &[NativeSceneStep],
    affected: &BTreeSet<InstanceId>,
) -> AppResult<BTreeMap<Sha256Digest, Value>> {
    let mut result = BTreeMap::new();
    for step in steps.iter().filter(|step| {
        affected.contains(step.instance_id()) && step.phase() == SceneLifecyclePhase::Activate
    }) {
        if matches!(
            step.instruction(),
            NativeSceneInstruction::CommandActivation { auto: true, .. }
        ) && result
            .insert(
                step_key(step)?,
                serde_json::to_value(step).map_err(|_| invalid())?,
            )
            .is_some()
        {
            return Err(invalid());
        }
    }
    Ok(result)
}
fn phase_map(
    steps: &[NativeSceneStep],
    affected: &BTreeSet<InstanceId>,
    phase: SceneLifecyclePhase,
) -> AppResult<BTreeMap<Sha256Digest, Value>> {
    let mut result = BTreeMap::new();
    for step in steps
        .iter()
        .filter(|step| step.phase() == phase && affected.contains(step.instance_id()))
    {
        let key = step_key(step)?;
        if result
            .insert(key, serde_json::to_value(step).map_err(|_| invalid())?)
            .is_some()
        {
            return Err(invalid());
        }
    }
    Ok(result)
}
fn step_key(step: &NativeSceneStep) -> AppResult<Sha256Digest> {
    let mut instruction = serde_json::to_value(step.instruction()).map_err(|_| invalid())?;
    let object = instruction.as_object_mut().ok_or_else(invalid)?;
    // Retain exact target identity; remove only desired payload. A coordinate
    // change is consequently a remove+create, never an in-place update.
    match step.instruction() {
        NativeSceneInstruction::Display { .. } => {
            for key in ["tag", "position", "matrix", "payload"] {
                object.remove(key);
            }
        }
        NativeSceneInstruction::Block { .. } => {
            object.remove("state");
        }
        NativeSceneInstruction::CommandShell { .. } => {
            for key in ["command_kind", "facing", "conditional"] {
                object.remove(key);
            }
        }
        NativeSceneInstruction::CommandData { .. } => {
            object.remove("source");
        }
        NativeSceneInstruction::CommandActivation { .. } => {
            object.remove("auto");
        }
        NativeSceneInstruction::StateInitialize { .. } => {
            for key in ["value", "state_type", "lifecycle"] {
                object.remove(key);
            }
        }
        NativeSceneInstruction::StateRemove { .. }
        | NativeSceneInstruction::DisplayRemove { .. } => {}
        NativeSceneInstruction::DisplayPose { .. } => {
            return Err(error(
                "NATIVE_DELTA_UNSUPPORTED",
                "Display pose activation needs its sealed current animation dispatch path",
            ));
        }
    }
    canonical_digest(&json!({"instance":step.instance_id(),"object":step.source_object_id(),"node":step.source_node_id(),"instruction":instruction})).map_err(|_| invalid())
}
fn selectors_for_steps(steps: &[NativeSceneStep]) -> AppResult<Vec<NativeSelector>> {
    let mut result = BTreeMap::new();
    for step in steps {
        for value in instruction_selectors(step.instruction())? {
            let selector = NativeSelector::from_value(&value).map_err(native_error)?;
            result.insert(canonical_digest(&value).map_err(|_| invalid())?, selector);
        }
    }
    if result.is_empty() || result.len() > MAX_NATIVE_TARGETS {
        return Err(budget_error());
    }
    Ok(result.into_values().collect())
}
fn instruction_selectors(instruction: &NativeSceneInstruction) -> AppResult<Vec<Value>> {
    Ok(match instruction {
        NativeSceneInstruction::Block {
            dimension,
            position,
            ..
        } => vec![
            json!({"kind":"block_state","dimension":dimension,"position":position}),
            json!({"kind":"block_entity","dimension":dimension,"position":position}),
        ],
        NativeSceneInstruction::CommandShell {
            dimension,
            position,
            ..
        } => vec![
            json!({"kind":"block_state","dimension":dimension,"position":position}),
            json!({"kind":"block_entity","dimension":dimension,"position":position}),
        ],
        NativeSceneInstruction::CommandData {
            dimension,
            position,
            ..
        }
        | NativeSceneInstruction::CommandActivation {
            dimension,
            position,
            ..
        } => vec![
            json!({"kind":"block_state","dimension":dimension,"position":position}),
            json!({"kind":"block_entity","dimension":dimension,"position":position}),
        ],
        NativeSceneInstruction::Display {
            dimension,
            uuid,
            entity_kind,
            ..
        }
        | NativeSceneInstruction::DisplayRemove {
            dimension,
            uuid,
            entity_kind,
        } => vec![
            json!({"kind":"entity","dimension":dimension,"uuid":uuid_text(uuid),"expectedType":format!("minecraft:{entity_kind}_display")}),
        ],
        NativeSceneInstruction::StateInitialize { .. }
        | NativeSceneInstruction::StateRemove { .. } => {
            return Err(error(
                "NATIVE_SOURCE_MAPPING_REQUIRED",
                "State storage/score selectors need a registered exact ResourceID mapping",
            ));
        }
        NativeSceneInstruction::DisplayPose { .. } => {
            return Err(error(
                "NATIVE_DELTA_UNSUPPORTED",
                "Display pose activation has no registered scene snapshot codec",
            ));
        }
    })
}
fn compiled_before_tags(
    draft: &SceneDraft,
    affected: &BTreeSet<InstanceId>,
) -> AppResult<BTreeMap<String, String>> {
    let mut tags = BTreeMap::new();
    for step in draft
        .native_steps()
        .iter()
        .filter(|step| affected.contains(step.instance_id()))
    {
        if let NativeSceneInstruction::Display { uuid, tag, .. } = step.instruction()
            && tags.insert(uuid_text(uuid), tag.clone()).is_some()
        {
            return Err(invalid());
        }
    }
    Ok(tags)
}
fn native_before_image(
    observation: &NativeObservation,
    tags: &BTreeMap<String, String>,
) -> AppResult<TargetBeforeImage> {
    if !observation.full_target() {
        return Err(error(
            "TARGET_MEMBERSHIP_UNKNOWN",
            "Native subject lacks complete independently observed current membership and bytes",
        ));
    }
    let subject = if observation.selector().kind() == "entity" {
        let uuid = text(observation.selector().value(), "uuid")?;
        let tag = tags.get(uuid).ok_or_else(|| {
            error(
                "TARGET_OWNERSHIP_UNVERIFIED",
                "Native entity has no exact compiled BEFORE source ownership tag",
            )
        })?;
        if observation.presence() != "present"
            || observation.raw()["payload"]["tags"]
                .as_array()
                .is_none_or(|actual| !actual.iter().any(|value| value.as_str() == Some(tag)))
        {
            return Err(error(
                "TARGET_OWNERSHIP_UNVERIFIED",
                "Actual loaded entity does not retain the exact compiled BEFORE ownership tag",
            ));
        }
        // Current encoder summons a new entity. Existing entity replacement
        // needs an explicit independently fenced patch/cleanup codec.
        format!("owned-entity:{uuid}:{tag}")
    } else {
        format!(
            "native:{}",
            canonical_digest(observation.selector().value()).map_err(|_| invalid())?
        )
    };
    Ok(TargetBeforeImage {
        kind: "region_snapshot",
        subject,
        bytes: observation.bytes().to_vec(),
        digest: observation.digest().clone(),
        coverage: "full_target",
    })
}
fn metadata_scope(change: &PreparedNativeChange) -> AppResult<WriteScope> {
    Ok(WriteScope {
        project_id: change.project_id.clone(),
        resource_ids: change.resource_ids().into_iter().collect(),
        object_ids: change
            .object_ids()
            .into_iter()
            .map(|id| ObjectId::new(id).map_err(|_| invalid()))
            .collect::<AppResult<_>>()?,
        regions: vec![],
        external_target_ids: vec![],
    })
}
fn complete_scope(
    change: &PreparedNativeChange,
    context: &Value,
    selectors: &[NativeSelector],
) -> AppResult<WriteScope> {
    let mut scope = metadata_scope(change)?;
    let id = context_id(context)?;
    let world = WorldId::new(text(&context["environment"], "worldId")?).map_err(|_| invalid())?;
    let mut regions = BTreeMap::new();
    for selector in selectors {
        if matches!(selector.kind(), "block_state" | "block_entity") {
            let position = selector.value()["position"]
                .as_array()
                .ok_or_else(invalid)?;
            let min = std::array::from_fn(|axis| position[axis].as_i64().unwrap_or(i64::MIN));
            let max_exclusive = min.map(|value| value + 1);
            let dimension = serde_json::from_value(selector.value()["dimension"].clone())
                .map_err(|_| invalid())?;
            let region = RegionScope {
                dimension,
                min,
                max_exclusive,
                context_id: id.clone(),
                world_id: world.clone(),
            };
            regions.insert(
                canonical_digest(&serde_json::to_value(&region).map_err(|_| invalid())?)
                    .map_err(|_| invalid())?,
                region,
            );
        }
    }
    for projection in &change.world_projection {
        for (instance, definition) in projection
            .before
            .iter()
            .zip(projection.before_definition.iter())
            .chain(std::iter::once((&projection.after, &projection.definition)))
        {
            if instance.world_id != world || context["dimension"] != instance.dimension.as_str() {
                return Err(stale());
            }
            let transforms = mmmm_domain::graph::world_transforms(
                definition,
                &instance.placement,
                &instance.overrides,
            )
            .map_err(domain_error)?;
            for node in &definition.nodes {
                if node.physics_binding.is_some() || !node.colliders.is_empty() {
                    return Err(error(
                        "UNOWNED_REQUIRED_CAPABILITY",
                        "Complete physical carrier footprint has no admitted codec",
                    ));
                }
                let Some(geometry) = &node.block_geometry else {
                    continue;
                };
                let matrix = transforms.get(&node.node_id).ok_or_else(invalid)?;
                let mut low = [f64::INFINITY; 3];
                let mut high = [f64::NEG_INFINITY; 3];
                for corner in 0..8 {
                    let local = std::array::from_fn(|axis| {
                        f64::from(if corner & (1 << axis) == 0 {
                            geometry.bounds.min[axis]
                        } else {
                            geometry.bounds.max_exclusive[axis]
                        })
                    });
                    let point = matrix.transform_point(local).map_err(|_| {
                        error(
                            "UNSUPPORTED_TRANSFORM",
                            "Native footprint does not have finite exact world bounds",
                        )
                    })?;
                    for axis in 0..3 {
                        low[axis] = low[axis].min(point[axis]);
                        high[axis] = high[axis].max(point[axis]);
                    }
                }
                let mut min = [0; 3];
                let mut max_exclusive = [0; 3];
                for axis in 0..3 {
                    if !low[axis].is_finite()
                        || !high[axis].is_finite()
                        || low[axis] < i32::MIN as f64
                        || high[axis] > i32::MAX as f64 + 1.0
                    {
                        return Err(budget_error());
                    }
                    min[axis] = low[axis].floor() as i64;
                    max_exclusive[axis] = high[axis].ceil() as i64;
                }
                let region = RegionScope {
                    dimension: instance.dimension.clone(),
                    min,
                    max_exclusive,
                    context_id: id.clone(),
                    world_id: world.clone(),
                };
                regions.insert(
                    canonical_digest(&serde_json::to_value(&region).map_err(|_| invalid())?)
                        .map_err(|_| invalid())?,
                    region,
                );
            }
        }
    }
    scope.regions = regions.into_values().collect();
    scope.validate().map_err(storage_error)?;
    Ok(scope)
}
fn projection_subjects(
    projection: &InstanceProjection,
    batch: &PreparedNativeBatch,
    targets: &[TargetBeforeImage],
) -> AppResult<BTreeSet<String>> {
    let mut subjects = BTreeSet::new();
    for step in batch
        .projection_steps
        .iter()
        .filter(|step| step.instance_id() == &projection.after.instance_id)
    {
        for selector in instruction_selectors(step.instruction())? {
            let subject = if selector["kind"] == "entity" {
                let uuid = text(&selector, "uuid")?;
                let tag = batch.before_tags.get(uuid).ok_or_else(unverified)?;
                format!("owned-entity:{uuid}:{tag}")
            } else {
                format!(
                    "native:{}",
                    canonical_digest(&selector).map_err(|_| invalid())?
                )
            };
            if !targets
                .iter()
                .any(|target| target.subject == subject && target.coverage == "full_target")
            {
                return Err(unverified());
            }
            subjects.insert(subject);
        }
    }
    Ok(subjects)
}

#[derive(Clone)]
struct BackendReadRpc {
    authenticated: AuthenticatedPrincipal,
    budget: RequestBudget,
    authority: LocalAuthority,
    project: ProjectId,
    context: Value,
    context_id: ContextId,
}
impl BackendReadRpc {
    fn authorize(
        &self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        kind: &str,
        source: &str,
    ) -> Result<(), StorageError> {
        self.check()?;
        if principal != self.authenticated.principal()
            || context != Some(&self.context_id)
            || project != &self.project
        {
            return Err(app_storage(forbidden()));
        }
        self.authority
            .authorize_retained_scope(
                principal,
                project,
                &self.context_id,
                &field_digest(&self.context, "policyRevision").map_err(app_storage)?,
                &self.context["scope"],
            )
            .map_err(app_storage)?;
        if self.context["scope"][kind]
            .as_array()
            .is_none_or(|ids| !ids.iter().any(|value| value.as_str() == Some(source)))
        {
            return Err(app_storage(forbidden()));
        }
        self.check()
    }
}
impl ProjectSourceRpcContext for BackendReadRpc {
    fn check(&self) -> Result<(), StorageError> {
        check_budget(&self.budget).map_err(app_storage)?;
        if !self.authenticated.is_current()
            || !self.authenticated.permits_context(self.context_id.as_str())
        {
            return Err(app_storage(forbidden()));
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
struct BackendDocumentAuthority(BackendReadRpc);
impl OwnedDocumentAuthority for BackendDocumentAuthority {
    fn authorize_read(
        &mut self,
        principal: &PrincipalId,
        context: &ContextId,
        project: &ProjectId,
        _revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> Result<(), StorageError> {
        self.0.authorize(
            principal,
            Some(context),
            project,
            "objectIds",
            pin.object_id.as_str(),
        )
    }
}
struct BackendResourceAuthority(BackendReadRpc);
impl ProjectResourceAuthority for BackendResourceAuthority {
    fn authorize_project_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        _revision: &Sha256Digest,
    ) -> Result<(), StorageError> {
        self.0.check()?;
        if principal != self.0.authenticated.principal()
            || context != Some(&self.0.context_id)
            || project != &self.0.project
        {
            return Err(app_storage(forbidden()));
        }
        self.0
            .authority
            .authorize_retained_scope(
                principal,
                project,
                &self.0.context_id,
                &field_digest(&self.0.context, "policyRevision").map_err(app_storage)?,
                &self.0.context["scope"],
            )
            .map_err(app_storage)
    }
    fn authorize_resource_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> Result<(), StorageError> {
        self.authorize_project_read(
            store,
            principal,
            context,
            project,
            &field_digest(&self.0.context, "policyRevision").map_err(app_storage)?,
        )?;
        if resource.owner != ResourceOwner::Project(project.clone()) {
            return Err(app_storage(forbidden()));
        }
        self.0.authorize(
            principal,
            context,
            project,
            "resourceIds",
            text(&resource.resource, "resourceId").map_err(app_storage)?,
        )
    }
}
fn capture_authoring_before(
    store: &PlanningStore<'_>,
    rpc: &BackendReadRpc,
    project: &ProjectCatalog,
    change: &PreparedNativeChange,
) -> AppResult<Vec<TargetBeforeImage>> {
    let mut output = Vec::new();
    let mut left = MAX_BYTES;
    for document in &change.document_changes {
        check_budget(&rpc.budget)?;
        let Some(before) = &document.before_revision else {
            continue;
        };
        let pin = project.owned_pin(document.kind, &document.object_id)?;
        if pin.revision != *before {
            return Err(stale());
        }
        let original = OwnedDocumentPin {
            kind: owned_kind(document.kind),
            object_id: pin.object_id.clone(),
            revision: pin.revision.clone(),
        };
        let loaded = store.with_read(|store| {
            let mut reader = OwnedDocumentReader::new(
                Box::new(BackendDocumentAuthority(rpc.clone())),
                MAX_DOCUMENT_BYTES.min(left),
            )
            .map_err(storage_error)?;
            reader
                .read_known_history_bytes(
                    store,
                    rpc,
                    project.project_id(),
                    project.revision(),
                    &original,
                )
                .map_err(storage_error)
        })?;
        left = left
            .checked_sub(loaded.bytes.len() as u64)
            .ok_or_else(budget_error)?;
        output.push(TargetBeforeImage {
            kind: "resource_hash",
            subject: format!("authored:{}:{}", original.kind.as_str(), original.object_id),
            bytes: loaded.bytes,
            digest: loaded.blob.digest,
            coverage: "full_target",
        });
    }
    // Resource replacement captures exact current bytes via the ordinary
    // authenticated ProjectResourceReader path (same call-scoped Store).
    for replacement in &change.resource_replacements {
        rpc.authorize(
            rpc.authenticated.principal(),
            Some(&rpc.context_id),
            project.project_id(),
            "resourceIds",
            replacement.target_resource_id.as_str(),
        )
        .map_err(storage_error)?;
        let expected = serde_json::to_value(&replacement.before).map_err(|_| invalid())?;
        let query = ProjectResourceQuery::Current {
            resource_id: replacement.target_resource_id.clone(),
        };
        let (bytes, digest) = store.with_read(|store| {
            let mut reader = ProjectResourceReader::new(
                Box::new(BackendResourceAuthority(rpc.clone())),
                MAX_BYTES,
            )
            .map_err(storage_error)?;
            let read = reader
                .read(
                    store,
                    rpc,
                    &ProjectResourceRequest {
                        project: project.project_id(),
                        current_project_revision: project.revision(),
                        query: &query,
                        expected: Some(&expected),
                    },
                    left,
                )
                .map_err(storage_error)?;
            Ok((read.bytes, read.registered.blob.digest))
        })?;
        left = left
            .checked_sub(bytes.len() as u64)
            .ok_or_else(budget_error)?;
        output.push(TargetBeforeImage {
            kind: "resource_hash",
            subject: format!("resource:{}", replacement.target_resource_id),
            bytes,
            digest,
            coverage: "full_target",
        });
    }
    Ok(output)
}
fn owned_kind(kind: OwnedKind) -> OwnedDocumentKind {
    match kind {
        OwnedKind::Prefab => OwnedDocumentKind::Prefab,
        OwnedKind::Instance => OwnedDocumentKind::Instance,
        OwnedKind::CommandModule => OwnedDocumentKind::CommandModule,
        OwnedKind::Clip => OwnedDocumentKind::AnimationClip,
        OwnedKind::Asset => OwnedDocumentKind::Asset,
        OwnedKind::PhysicsDefinition => OwnedDocumentKind::PhysicsDefinition,
    }
}
fn uuid_text(uuid: &[u8; 16]) -> String {
    let hex: String = uuid.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}
fn validate(definition: &str, value: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .and_then(|validator| validator.validate(definition, value))
        .map_err(|_| invalid())
}
fn text<'a>(value: &'a Value, field: &str) -> AppResult<&'a str> {
    value[field].as_str().ok_or_else(invalid)
}
fn context_id(value: &Value) -> AppResult<ContextId> {
    ContextId::new(text(value, "contextId")?).map_err(|_| invalid())
}
fn field_digest(value: &Value, field: &str) -> AppResult<Sha256Digest> {
    Sha256Digest::new(text(value, field)?).map_err(|_| invalid())
}
fn check_budget(budget: &RequestBudget) -> AppResult<()> {
    budget.check().map_err(service_error)
}
fn service_error(error_value: crate::service::ServiceError) -> AppError {
    AppError::new(error_value.code, error_value.message)
}
fn adapter_error(error_value: mmmm_adapters::AdapterError) -> AppError {
    AppError::caused_by(
        error_value.code,
        "Actual provider observation violates its registered interface",
        error_value,
    )
}
fn domain_error(error_value: mmmm_domain::DomainError) -> AppError {
    AppError::caused_by(
        error_value.code,
        "Exact immutable authored sources could not be lowered with the registered native codec",
        error_value,
    )
}
fn storage_error(error_value: StorageError) -> AppError {
    AppError::storage("NATIVE_SOURCE_UNAVAILABLE", error_value)
}
fn native_error(error_value: NativeTargetError) -> AppError {
    match error_value {
        NativeTargetError::Authority(error) => error,
        NativeTargetError::Storage(error) => storage_error(error),
        NativeTargetError::Retention(error) => {
            AppError::caused_by(error.code, error.message, error)
        }
        NativeTargetError::Invalid => unverified(),
        NativeTargetError::Host(failure) => AppError::caused_by(
            "NATIVE_OBSERVATION_FAILED",
            "Native observation failed; its original response remains in the same CAS",
            failure.causal_snapshot(),
        ),
    }
}
fn app_storage(error_value: AppError) -> StorageError {
    StorageError::InvalidTransition(format!("{}: {}", error_value.code, error_value.message))
}
fn error(code: &'static str, message: &'static str) -> AppError {
    AppError::new(code, message)
}
fn invalid() -> AppError {
    error(
        "INVALID_INPUT",
        "Native planning source violates its closed canonical contract",
    )
}
fn stale() -> AppError {
    error(
        "STALE_CONTEXT",
        "Actual source, context or immutable revision changed",
    )
}
fn forbidden() -> AppError {
    error(
        "PERMISSION_REQUIRED",
        "Current opaque principal and full exact scope authority are required",
    )
}
fn busy() -> AppError {
    error("SOURCE_BUSY", "Native source registration is being used")
}
fn budget_error() -> AppError {
    error(
        "BUDGET_EXCEEDED",
        "Native planning exceeds its finite source or target budget",
    )
}
fn unverified() -> AppError {
    error(
        "TARGET_UNVERIFIED",
        "Exact original source, native membership and complete footprint evidence are required",
    )
}
fn store_required() -> AppError {
    error(
        "STORE_REQUIRED",
        "Native backend must be called with the service's one call-scoped Store",
    )
}

#[cfg(test)]
#[path = "native_backend_tests.rs"]
mod tests;

//! Authenticated planning composition borrows the service's one store only for
//! one call. Neither a catalog, ResourceRef nor host/profile JSON creates source
//! ownership, a component registration, or a verified target capability.

use crate::{
    auth::AuthenticatedPrincipal, authority::LocalAuthority, host::HostBridge,
    service::RequestBudget,
};
use mmmm_adapters::{ActionDescriptor, InventorySnapshot};
use mmmm_application::{
    Access, AppError, AppResult, AuthorityPort, Clock, PlanningPort, PreparedPlan,
    ProjectInspection, RecoveryPreparation,
};
use mmmm_compiler::{PackBuildInputs, VerifiedTarget, scene::SceneResource};
use mmmm_contracts::{
    BindingId, ContextId, InstanceId, ModuleId, PrincipalId, ProjectId, ResourceId, Sha256Digest,
    TargetProfileId, canonical_digest, encode_json, raw_digest,
};
use mmmm_domain::{
    commands::CommandLayoutSupport,
    instance::ResolvedStateSnapshot,
    types::{ResourceRef, ScalarValue},
};
use mmmm_planner::{
    InstanceProjection, NativeActionRoute, NativeKind, NativePlanner, NativeTargetSnapshot,
    ObjectPin, OwnedKind, PinnedResourceBytes, PinnedStateSnapshot, PlannerOptions,
    PlanningEnvironmentPort, PreparedNativeChange, ProjectCatalog, ProjectSourcePort,
    RegisteredActionFootprint, SceneSource, VerifiedNativeTarget,
};
use mmmm_runtime::storage::{DurableStore, StorageError, WriteScope};
use mmmm_runtime::storage::{
    artifact::{ResourceOwner, register_resource},
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

const MAX_SOURCE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_DOCUMENT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_COMPONENTS: usize = 128;

enum BorrowedStore<'a> {
    Read(&'a DurableStore),
    Write(&'a mut DurableStore),
}

/// The two planner ports share this safe, call-scoped borrow. A conflicting
/// recursive borrow returns SOURCE_BUSY; it never panics or opens a DB.
#[derive(Clone)]
pub struct PlanningStore<'a> {
    store: Rc<RefCell<BorrowedStore<'a>>>,
    issued: SharedIssuedSources,
}
#[derive(Clone)]
struct IssuedSource {
    project: ProjectId,
    principal: PrincipalId,
    context: ContextId,
    context_digest: Sha256Digest,
    resource: Value,
}
type SharedIssuedSources = Rc<RefCell<BTreeMap<ResourceId, IssuedSource>>>;
impl<'a> PlanningStore<'a> {
    pub fn read(store: &'a DurableStore) -> Self {
        Self {
            store: Rc::new(RefCell::new(BorrowedStore::Read(store))),
            issued: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }
    pub fn write(store: &'a mut DurableStore) -> Self {
        Self {
            store: Rc::new(RefCell::new(BorrowedStore::Write(store))),
            issued: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }
    pub fn with_read<T>(&self, call: impl FnOnce(&DurableStore) -> AppResult<T>) -> AppResult<T> {
        let guard = self.store.try_borrow().map_err(|_| source_busy())?;
        match &*guard {
            BorrowedStore::Read(store) => call(store),
            BorrowedStore::Write(store) => call(store),
        }
    }
    pub fn with_write<T>(
        &self,
        call: impl FnOnce(&mut DurableStore) -> AppResult<T>,
    ) -> AppResult<T> {
        let mut guard = self.store.try_borrow_mut().map_err(|_| source_busy())?;
        match &mut *guard {
            BorrowedStore::Read(_) => Err(error(
                "READ_ONLY_SOURCE",
                "Project inspection cannot stage or mutate private source records",
            )),
            BorrowedStore::Write(store) => call(store),
        }
    }
    /// Issuance is confined to this planner call and populated only after actual
    /// staging. It grants no restart authority and cannot be installed by a DTO.
    fn record_issued(
        &self,
        principal: &PrincipalId,
        project: &ProjectId,
        context: &Value,
        resource: &ResourceRef,
    ) -> AppResult<()> {
        let mut issued = self.issued.try_borrow_mut().map_err(|_| source_busy())?;
        if issued.len() >= 4096 && !issued.contains_key(&resource.resource_id) {
            return Err(source_budget());
        }
        let witness = IssuedSource {
            project: project.clone(),
            principal: principal.clone(),
            context: context_id(context)?,
            context_digest: context_digest(context)?,
            resource: serde_json::to_value(resource).map_err(|_| source_budget())?,
        };
        if let Some(existing) = issued.get(&resource.resource_id) {
            if existing.project != witness.project
                || existing.principal != witness.principal
                || existing.context != witness.context
                || existing.context_digest != witness.context_digest
                || existing.resource != witness.resource
            {
                return Err(forbidden());
            }
        } else {
            issued.insert(resource.resource_id.clone(), witness);
        }
        Ok(())
    }
}

/// Only the authenticated service dispatch installs this request source. It is
/// not a DTO and its values are never recovered from a PrincipalId string.
pub trait PlanningRequestSource {
    fn current(
        &self,
        principal: &PrincipalId,
    ) -> AppResult<(AuthenticatedPrincipal, RequestBudget)>;
}
impl PlanningRequestSource for crate::service::RequestContextSlot {
    fn current(
        &self,
        principal: &PrincipalId,
    ) -> AppResult<(AuthenticatedPrincipal, RequestBudget)> {
        let (authenticated, budget) = crate::service::RequestContextSlot::current(self)
            .map_err(|e| error(e.code, e.message))?;
        if authenticated.principal() != principal {
            return Err(forbidden());
        }
        Ok((authenticated, budget))
    }
}

/// Explicit offline composition can implement this from a server-owned
/// workspace-context registry. Returning the argument itself is not validation.
pub trait PlanningContextPort {
    fn authorize(
        &mut self,
        principal: &AuthenticatedPrincipal,
        authority: &mut LocalAuthority,
        hosts: &HostBridge,
        project: &ProjectId,
        context: &Value,
        access: Access,
        budget: &RequestBudget,
    ) -> AppResult<()>;
}

/// Actual paired game path. Workspace planning requires an explicitly installed
/// workspace context adapter; no game context is synthesized for inspection.
pub struct PairedPlanningContext;
impl PlanningContextPort for PairedPlanningContext {
    fn authorize(
        &mut self,
        principal: &AuthenticatedPrincipal,
        authority: &mut LocalAuthority,
        hosts: &HostBridge,
        project: &ProjectId,
        context: &Value,
        access: Access,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        budget_check(budget)?;
        let id = context_id(context)?;
        if !principal.permits_context(id.as_str()) {
            return Err(forbidden());
        }
        let live = hosts.context_with_deadline(principal.principal(), &id, budget.deadline())?;
        if live != *context || live["projectId"] != project.as_str() {
            return Err(error(
                "STALE_CONTEXT",
                "Planning context changed at the paired host",
            ));
        }
        authority.authorize_with_deadline(
            principal.principal(),
            project,
            access,
            Some(&live),
            None,
            budget.deadline(),
        )?;
        budget_check(budget)
    }
}

/// Explicit trusted workspace setup registers a canonical context only after
/// an active Project grant already exists. This registry creates no grant and
/// has no public RPC parser; callers cannot adopt arbitrary offline JSON.
#[derive(Default)]
pub struct RegisteredWorkspaceContexts {
    records: BTreeMap<(PrincipalId, ContextId), Value>,
}
impl RegisteredWorkspaceContexts {
    pub fn register(
        &mut self,
        principal: &AuthenticatedPrincipal,
        authority: &LocalAuthority,
        context: Value,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        budget_check(budget)?;
        let mut live_authority = authority.clone();
        workspace_authority(principal, &mut live_authority, &context, Access::Plan)?;
        let id = context_id(&context)?;
        let key = (principal.principal().clone(), id);
        if self.records.len() >= 128 && !self.records.contains_key(&key) {
            return Err(source_budget());
        }
        if let Some(old) = self.records.get(&key) {
            if old != &context {
                return Err(error(
                    "CONTEXT_CONFLICT",
                    "Workspace context identity is immutable",
                ));
            }
        } else {
            self.records.insert(key, context);
        }
        budget_check(budget)
    }
    pub fn authorize_registered(
        &self,
        principal: &AuthenticatedPrincipal,
        authority: &mut LocalAuthority,
        project: &ProjectId,
        context: &Value,
        access: Access,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        budget_check(budget)?;
        if context["projectId"] != project.as_str()
            || self
                .records
                .get(&(principal.principal().clone(), context_id(context)?))
                != Some(context)
        {
            return Err(error(
                "CONTEXT_UNKNOWN",
                "Workspace context has no exact server-owned registration",
            ));
        }
        workspace_authority(principal, authority, context, access)?;
        budget_check(budget)
    }
}
pub struct RegisteredPlanningContexts {
    pub workspace: RegisteredWorkspaceContexts,
    paired: PairedPlanningContext,
}
impl RegisteredPlanningContexts {
    pub fn new(workspace: RegisteredWorkspaceContexts) -> Self {
        Self {
            workspace,
            paired: PairedPlanningContext,
        }
    }
}
impl PlanningContextPort for RegisteredPlanningContexts {
    fn authorize(
        &mut self,
        principal: &AuthenticatedPrincipal,
        authority: &mut LocalAuthority,
        hosts: &HostBridge,
        project: &ProjectId,
        context: &Value,
        access: Access,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        if context["environment"]["kind"] == "offline" {
            self.workspace
                .authorize_registered(principal, authority, project, context, access, budget)
        } else {
            self.paired.authorize(
                principal, authority, hosts, project, context, access, budget,
            )
        }
    }
}
fn workspace_authority(
    principal: &AuthenticatedPrincipal,
    authority: &mut LocalAuthority,
    context: &Value,
    access: Access,
) -> AppResult<()> {
    validate("ExecutionContext", context)?;
    mmmm_contracts::verify_projected_digest("ExecutionContext", context)
        .map_err(|_| error("STALE_CONTEXT", "Workspace context digest is invalid"))?;
    let project = ProjectId::new(text(context, "projectId")?).map_err(|_| forbidden())?;
    let id = context_id(context)?;
    if !principal.is_current()
        || !principal.permits_context(id.as_str())
        || context["principalRef"] != principal.principal().as_str()
        || context["environment"]["kind"] != "offline"
        || context["environment"]["side"] != "offline"
        || [
            "dimension",
            "executorHandle",
            "origin",
            "rotationDegrees",
            "anchor",
        ]
        .iter()
        .any(|key| context.get(*key).is_some())
        || !authority
            .current_context_ids(principal.principal())?
            .contains(&id)
        || context["policyRevision"]
            != authority
                .policy_revision(principal.principal(), &project)?
                .as_str()
    {
        return Err(forbidden());
    }
    let granted: WriteScope =
        serde_json::from_value(authority.project_scope(principal.principal(), &project)?)
            .map_err(|_| forbidden())?;
    let requested: WriteScope =
        serde_json::from_value(context["scope"].clone()).map_err(|_| forbidden())?;
    if !scope_contains(&granted, &requested) || !requested.regions.is_empty() {
        return Err(forbidden());
    }
    // Apply needs an approved durable plan; this port only supplies read/plan
    // source contexts. It cannot grant write execution from offline metadata.
    if access == Access::Apply {
        return Err(forbidden());
    }
    authority.authorize(principal.principal(), &project, access, None, None)
}
fn scope_contains(granted: &WriteScope, requested: &WriteScope) -> bool {
    granted.validate().is_ok()
        && requested.validate().is_ok()
        && granted.project_id == requested.project_id
        && requested
            .object_ids
            .iter()
            .all(|id| granted.object_ids.contains(id))
        && requested
            .resource_ids
            .iter()
            .all(|id| granted.resource_ids.contains(id))
        && requested
            .external_target_ids
            .iter()
            .all(|id| granted.external_target_ids.contains(id))
        && requested.regions.iter().all(|region| {
            granted.regions.iter().any(|outer| {
                outer.context_id == region.context_id
                    && outer.world_id == region.world_id
                    && outer.dimension == region.dimension
                    && (0..3).all(|axis| {
                        outer.min[axis] <= region.min[axis]
                            && region.max_exclusive[axis] <= outer.max_exclusive[axis]
                    })
            })
        })
}

pub type SharedPlanningContexts = Rc<RefCell<Box<dyn PlanningContextPort>>>;

/// A live authenticated request witness, shared only in process. ACL checks run
/// outside the store borrow so host calls cannot reenter a held SQLite borrow.
#[derive(Clone)]
pub struct LocalPlanningAccess {
    principal: AuthenticatedPrincipal,
    authority: LocalAuthority,
    hosts: HostBridge,
    budget: RequestBudget,
    contexts: SharedPlanningContexts,
}
impl LocalPlanningAccess {
    pub fn new(
        principal: AuthenticatedPrincipal,
        authority: LocalAuthority,
        hosts: HostBridge,
        budget: RequestBudget,
        contexts: SharedPlanningContexts,
    ) -> AppResult<Self> {
        let access = Self {
            principal,
            authority,
            hosts,
            budget,
            contexts,
        };
        access.check()?;
        Ok(access)
    }
    pub fn check(&self) -> AppResult<()> {
        budget_check(&self.budget)?;
        if !self.principal.is_current() {
            return Err(forbidden());
        }
        Ok(())
    }
    pub fn principal(&self) -> &PrincipalId {
        self.principal.principal()
    }
    pub fn budget(&self) -> &RequestBudget {
        &self.budget
    }
    pub fn authorize_project(
        &self,
        principal: &PrincipalId,
        project: &ProjectId,
        context: Option<&Value>,
        access: Access,
    ) -> AppResult<()> {
        self.check()?;
        if principal != self.principal() {
            return Err(forbidden());
        }
        let mut authority = self.authority.clone();
        match context {
            Some(context) => self
                .contexts
                .try_borrow_mut()
                .map_err(|_| source_busy())?
                .authorize(
                    &self.principal,
                    &mut authority,
                    &self.hosts,
                    project,
                    context,
                    access,
                    &self.budget,
                )?,
            None => authority.authorize(principal, project, access, None, None)?,
        }
        self.check()
    }
    fn authorize_context(&self, principal: &PrincipalId, context: &Value) -> AppResult<()> {
        let project = ProjectId::new(text(context, "projectId")?).map_err(|_| forbidden())?;
        self.authorize_project(principal, &project, Some(context), Access::Plan)
    }
}

/// Independent state observations bind raw codec bytes to exact authored pins.
/// They are produced by the registered state codec/actual observer, not a user
/// ChangeIntent field or ProviderResult.beforeState.
pub struct ObservedStateSnapshot {
    pub context_digest: Sha256Digest,
    pub source_instance_id: InstanceId,
    pub prefab_revision: Sha256Digest,
    pub bytes: Vec<u8>,
    pub values: BTreeMap<mmmm_contracts::StateId, ScalarValue>,
}

/// Concrete trusted data adapters own source rights, bake witnesses and live
/// state codecs. They cannot open a second store: all durable reads use the
/// BorrowedProjectSource passed by the coordinator composition.
pub trait PlanningDataPort {
    fn state_snapshot(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        instance: &Value,
        definition: &Value,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<ObservedStateSnapshot>;
    fn scene_source(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<SceneSource>;
    fn validate_scene_provenance(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        source: &SceneSource,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<()>;
}
pub type SharedPlanningData = Rc<RefCell<Box<dyn PlanningDataPort>>>;

/// Backend implementations consume actual registered source bindings and an
/// approved artifact/profile evidence registry. The inherited typed methods
/// deliberately cannot be implemented by parsing verification flags in JSON.
pub trait PlanningBackendPort: PlanningEnvironmentPort {
    /// Match the independently queried hello/epoch against approved profile and
    /// artifact bytes plus the actual case evidence in the server registry.
    /// The sealed compiler target alone does not attest the connected host.
    fn verify_live_target(
        &mut self,
        principal: &PrincipalId,
        profile: &TargetProfileId,
        context: &Value,
        actual_hello: &Value,
        budget: &RequestBudget,
    ) -> AppResult<VerifiedPlanningTarget>;
    /// Sealed lowering gets only bytes read from exact authorized source pins.
    /// It must invoke the owned scene/animation/compiler codecs with separately
    /// registered grammar, registry, shape and runtime evidence verifiers.
    fn lower_owned_pack(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        owned_values: &[Value],
        resources: &[SceneResource],
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<PackBuildInputs>;
}
pub type SharedPlanningBackend = Rc<RefCell<Box<dyn PlanningBackendPort>>>;

/// Typed in-process evidence returned by the actual server registry adapter.
/// Public profiles and RPC input cannot deserialize this capability.
pub struct VerifiedPlanningTarget {
    pub compiler: VerifiedTarget,
    pub native_kinds: BTreeSet<NativeKind>,
    pub evidence_resource_pins: Vec<ResourceRef>,
    pub hello_digest: Sha256Digest,
    pub environment_digest: Sha256Digest,
}

/// Rust source digests are computed from the actual compiled source inputs.
/// A Java host jar can only be an independently registered platform component.
#[derive(Clone, Copy)]
pub enum OwnedPlanningComponent {
    Domain,
    Planner,
    Compiler,
}
impl OwnedPlanningComponent {
    pub fn component_id(self) -> &'static str {
        match self {
            Self::Domain => "mmmm-domain",
            Self::Planner => "mmmm-planner",
            Self::Compiler => "mmmm-compiler",
        }
    }
    pub fn digest(self) -> Sha256Digest {
        match self {
            Self::Domain => mmmm_planner::domain_digest(),
            Self::Planner => mmmm_planner::planner_digest(),
            Self::Compiler => mmmm_compiler::compiler_digest(),
        }
    }
}
pub struct RegisteredPlanningDependency {
    binding: BindingId,
    component: String,
    digest: Sha256Digest,
    provenance: &'static str,
    action_ids: BTreeSet<String>,
    contract_ids: BTreeSet<String>,
}
impl RegisteredPlanningDependency {
    pub fn owned(
        binding: BindingId,
        component: OwnedPlanningComponent,
        action_ids: BTreeSet<String>,
        contract_ids: BTreeSet<String>,
    ) -> AppResult<Self> {
        registration_sets(&action_ids, &contract_ids)?;
        Ok(Self {
            binding,
            component: component.component_id().into(),
            digest: component.digest(),
            provenance: "owned_domain",
            action_ids,
            contract_ids,
        })
    }
    /// A trusted artifact verifier calls this with its actual observed jar hash.
    /// This constructor never assigns owned Rust implementation provenance.
    pub fn host_artifact(
        binding: BindingId,
        component: String,
        artifact_digest: Sha256Digest,
        action_ids: BTreeSet<String>,
        contract_ids: BTreeSet<String>,
    ) -> AppResult<Self> {
        mmmm_contracts::ComponentId::new(&component).map_err(|_| forbidden())?;
        if ["mmmm-domain", "mmmm-planner", "mmmm-compiler"].contains(&component.as_str()) {
            return Err(forbidden());
        }
        registration_sets(&action_ids, &contract_ids)?;
        Ok(Self {
            binding,
            component,
            digest: artifact_digest,
            provenance: "platform_shim",
            action_ids,
            contract_ids,
        })
    }
}
#[derive(Default)]
pub struct PlanningDependencyRegistry {
    entries: BTreeMap<BindingId, Vec<RegisteredPlanningDependency>>,
}
impl PlanningDependencyRegistry {
    pub fn register(&mut self, dependency: RegisteredPlanningDependency) -> AppResult<()> {
        if self.entries.values().map(Vec::len).sum::<usize>() >= MAX_COMPONENTS {
            return Err(source_budget());
        }
        let entries = self.entries.entry(dependency.binding.clone()).or_default();
        if entries.iter().any(|entry| {
            entry.digest == dependency.digest || entry.component == dependency.component
        }) {
            return Err(error(
                "DEPENDENCY_CONFLICT",
                "Planning component registration conflicts",
            ));
        }
        entries.push(dependency);
        Ok(())
    }
    fn pin(
        &self,
        binding: &BindingId,
        digest: &Sha256Digest,
        selected: &[&ActionDescriptor],
    ) -> AppResult<Value> {
        let entry = self
            .entries
            .get(binding)
            .and_then(|entries| entries.iter().find(|entry| &entry.digest == digest))
            .ok_or_else(|| {
                error(
                    "DEPENDENCY_UNVERIFIED",
                    "Selected implementation has no exact registered source provenance",
                )
            })?;
        let ids: BTreeSet<_> = selected
            .iter()
            .filter(|action| action.implementation_digest == *digest)
            .map(|action| action.action_id.as_str().to_owned())
            .collect();
        if ids.is_empty() || !ids.is_subset(&entry.action_ids) {
            return Err(forbidden());
        }
        let mut contracts = entry.contract_ids.clone();
        contracts.extend(ids);
        let pin = json!({"componentId":entry.component,"implementationDigest":entry.digest,"contractIds":contracts,"provenanceClass":entry.provenance});
        validate("DependencyPin", &pin)?;
        Ok(pin)
    }
}
pub type SharedPlanningDependencies = Rc<RefCell<PlanningDependencyRegistry>>;

pub struct BorrowedProjectSource<'a> {
    store: PlanningStore<'a>,
    access: LocalPlanningAccess,
    data: SharedPlanningData,
}
impl<'a> BorrowedProjectSource<'a> {
    pub fn new(
        store: PlanningStore<'a>,
        access: LocalPlanningAccess,
        data: SharedPlanningData,
    ) -> Self {
        Self {
            store,
            access,
            data,
        }
    }
    pub fn access(&self) -> &LocalPlanningAccess {
        &self.access
    }
    fn authorize(
        &self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        context: Option<&Value>,
    ) -> AppResult<()> {
        self.access.authorize_project(
            principal,
            project.project_id(),
            context,
            Access::ReadProject,
        )?;
        let rpc = SourceRequest::new(self.access.clone(), context, self.store.issued.clone())?;
        let mut reader = resource_reader(&rpc)?;
        self.store.with_read(|store| {
            let actual = reader
                .read_project(
                    store,
                    &rpc,
                    project.project_id(),
                    project.revision(),
                    MAX_DOCUMENT_BYTES,
                )
                .map_err(storage_error)?;
            if actual != *project.project() {
                return Err(revision_conflict());
            }
            Ok(())
        })?;
        self.access.authorize_project(
            principal,
            project.project_id(),
            context,
            Access::ReadProject,
        )
    }
}

#[derive(Clone)]
struct SourceRequest {
    access: LocalPlanningAccess,
    context_id: Option<ContextId>,
    context: Option<Value>,
    issued: SharedIssuedSources,
}
impl SourceRequest {
    fn new(
        access: LocalPlanningAccess,
        context: Option<&Value>,
        issued: SharedIssuedSources,
    ) -> AppResult<Self> {
        Ok(Self {
            access,
            context_id: context.map(context_id).transpose()?,
            context: context.cloned(),
            issued,
        })
    }
}
impl ProjectSourceRpcContext for SourceRequest {
    fn check(&self) -> Result<(), StorageError> {
        self.access.check().map_err(source_storage_error)
    }
    fn authenticated_principal(&self) -> Result<PrincipalId, StorageError> {
        self.check()?;
        Ok(self.access.principal().clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        self.context_id.as_ref()
    }
}
/// These callbacks reload actual ACL without host I/O while the store is
/// borrowed. Paired/offline context revalidation is done immediately outside
/// the borrow both before and after each public source method.
struct SourceReadAuthority(SourceRequest);
impl SourceReadAuthority {
    fn project_acl(
        &self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
    ) -> Result<(), StorageError> {
        self.0.check()?;
        if principal != self.0.access.principal() || context != self.0.context_id.as_ref() {
            return Err(source_storage_error(forbidden()));
        }
        self.0
            .access
            .authorize_project(principal, project, None, Access::ReadProject)
            .map_err(source_storage_error)
    }
    fn source_scope(
        &self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        kind: &str,
        source_id: &str,
    ) -> Result<(), StorageError> {
        self.project_acl(principal, context, project)?;
        let live = self
            .0
            .access
            .authority
            .project_scope(principal, project)
            .map_err(source_storage_error)?;
        if !source_scope_contains(&live, kind, source_id)
            || self
                .0
                .context
                .as_ref()
                .is_some_and(|context| !source_scope_contains(&context["scope"], kind, source_id))
        {
            return Err(source_storage_error(forbidden()));
        }
        self.0.check()
    }
    fn issued_resource(
        &self,
        principal: &PrincipalId,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> Result<bool, StorageError> {
        let Some(context) = self.0.context.as_ref() else {
            return Ok(false);
        };
        let id =
            ResourceId::new(text(&resource.resource, "resourceId").map_err(source_storage_error)?)
                .map_err(|_| source_storage_error(forbidden()))?;
        let issued = self
            .0
            .issued
            .try_borrow()
            .map_err(|_| source_storage_error(source_busy()))?;
        let context_digest = context_digest(context).map_err(source_storage_error)?;
        Ok(issued.get(&id).is_some_and(|witness| {
            &witness.project == project
                && &witness.principal == principal
                && Some(&witness.context) == self.0.context_id.as_ref()
                && witness.context_digest == context_digest
                && witness.resource == resource.resource
        }))
    }
}
impl ProjectResourceAuthority for SourceReadAuthority {
    fn authorize_project_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        _current_revision: &Sha256Digest,
    ) -> Result<(), StorageError> {
        self.project_acl(principal, context, project)
    }
    fn authorize_resource_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> Result<(), StorageError> {
        self.project_acl(principal, context, project)?;
        if resource.owner != ResourceOwner::Project(project.clone()) {
            return Err(source_storage_error(forbidden()));
        }
        // Knowledge of a private immutable CAS ID is not permission. Only the
        // actual current resource scope or this call's trusted producer witness
        // admits it; a restarted reader must obtain a fresh actual grant.
        if self.issued_resource(principal, project, resource)? {
            return self.0.check();
        }
        self.source_scope(
            principal,
            context,
            project,
            "resourceIds",
            text(&resource.resource, "resourceId").map_err(source_storage_error)?,
        )
    }
}
impl OwnedDocumentAuthority for SourceReadAuthority {
    fn authorize_read(
        &mut self,
        principal: &PrincipalId,
        context: &ContextId,
        project: &ProjectId,
        _revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> Result<(), StorageError> {
        self.source_scope(
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
        self.source_scope(
            principal,
            context,
            project,
            "objectIds",
            pin.object_id.as_str(),
        )
    }
}
fn resource_reader(request: &SourceRequest) -> AppResult<ProjectResourceReader> {
    ProjectResourceReader::new(
        Box::new(SourceReadAuthority(request.clone())),
        256 * 1024 * 1024,
    )
    .map_err(storage_error)
}
fn document_pin(pin: &ObjectPin) -> OwnedDocumentPin {
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
fn decode_resource(value: &Value) -> AppResult<ResourceRef> {
    validate("ResourceRef", value)?;
    let mut typed = value.clone();
    if let Some(size) = typed["sizeBytes"]
        .as_f64()
        .filter(|size| size.fract() == 0.0 && *size >= 0.0 && *size <= 9_007_199_254_740_991.0)
    {
        typed["sizeBytes"] = Value::from(size as u64);
    }
    serde_json::from_value(typed)
        .map_err(|_| error("INVALID_INPUT", "Registered ResourceRef cannot be decoded"))
}

impl ProjectSourcePort for BorrowedProjectSource<'_> {
    fn inspect_owned(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        max_bytes: u64,
    ) -> AppResult<Vec<(ObjectPin, Value)>> {
        if max_bytes == 0 || max_bytes > 256 * 1024 * 1024 {
            return Err(source_budget());
        }
        self.authorize(principal, project, None)?;
        let mut remaining = max_bytes;
        let mut values = Vec::with_capacity(project.pins().len());
        for pin in project.pins() {
            let value = self.owned_object(principal, project, pin, None, remaining)?;
            let count = encode_json(&value).map_err(|_| source_budget())?.len() as u64;
            remaining = remaining.checked_sub(count).ok_or_else(source_budget)?;
            values.push((pin.clone(), value));
        }
        self.authorize(principal, project, None)?;
        Ok(values)
    }
    fn owned_object(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        pin: &ObjectPin,
        context: Option<&Value>,
        max_bytes: u64,
    ) -> AppResult<Value> {
        if max_bytes == 0 {
            return Err(source_budget());
        }
        self.authorize(principal, project, context)?;
        project.owned_pin(pin.kind, pin.object_id.as_str())?;
        let request = SourceRequest::new(self.access.clone(), context, self.store.issued.clone())?;
        let mut reader = OwnedDocumentReader::new(
            Box::new(SourceReadAuthority(request.clone())),
            max_bytes.min(MAX_DOCUMENT_BYTES),
        )
        .map_err(storage_error)?;
        let pin = document_pin(pin);
        let value = self.store.with_read(|store| {
            reader
                .read_known_history(
                    store,
                    &request,
                    project.project_id(),
                    project.revision(),
                    &pin,
                )
                .map_err(storage_error)
        })?;
        self.authorize(principal, project, context)?;
        Ok(value)
    }
    fn resource_pin(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        resource_id: &str,
        context: Option<&Value>,
    ) -> AppResult<ResourceRef> {
        self.authorize(principal, project, context)?;
        let id = ResourceId::new(resource_id).map_err(|_| forbidden())?;
        let query = if project.resource_ids().contains(&id) {
            ProjectResourceQuery::Current { resource_id: id }
        } else {
            ProjectResourceQuery::RegisteredImmutable { resource_id: id }
        };
        let rpc = SourceRequest::new(self.access.clone(), context, self.store.issued.clone())?;
        let mut reader = resource_reader(&rpc)?;
        let registered = self.store.with_read(|store| {
            reader
                .metadata(
                    store,
                    &rpc,
                    &ProjectResourceRequest {
                        project: project.project_id(),
                        current_project_revision: project.revision(),
                        query: &query,
                        expected: None,
                    },
                )
                .map_err(storage_error)
        })?;
        self.authorize(principal, project, context)?;
        decode_resource(&registered.resource)
    }
    fn resource_bytes(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        resource: &ResourceRef,
        context: Option<&Value>,
        max_bytes: u64,
    ) -> AppResult<PinnedResourceBytes> {
        if max_bytes == 0 || resource.size_bytes > max_bytes {
            return Err(source_budget());
        }
        self.authorize(principal, project, context)?;
        let expected = serde_json::to_value(resource).map_err(|_| source_budget())?;
        let query = if project.resource_ids().contains(&resource.resource_id) {
            ProjectResourceQuery::Exact {
                resource_id: resource.resource_id.clone(),
                digest: resource.sha256.clone(),
            }
        } else {
            ProjectResourceQuery::RegisteredImmutable {
                resource_id: resource.resource_id.clone(),
            }
        };
        let rpc = SourceRequest::new(self.access.clone(), context, self.store.issued.clone())?;
        let mut reader = resource_reader(&rpc)?;
        let read = self.store.with_read(|store| {
            reader
                .read(
                    store,
                    &rpc,
                    &ProjectResourceRequest {
                        project: project.project_id(),
                        current_project_revision: project.revision(),
                        query: &query,
                        expected: Some(&expected),
                    },
                    max_bytes.min(256 * 1024 * 1024),
                )
                .map_err(storage_error)
        })?;
        self.authorize(principal, project, context)?;
        Ok(PinnedResourceBytes {
            resource: decode_resource(&read.registered.resource)?,
            bytes: read.bytes,
        })
    }
    fn stage_private(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        desired_resource_id: Option<&ResourceId>,
        bytes: &[u8],
        media_type: &str,
        context: &Value,
    ) -> AppResult<ResourceRef> {
        if bytes.len() as u64 > MAX_SOURCE_BYTES || media_type.is_empty() || media_type.len() > 1024
        {
            return Err(source_budget());
        }
        self.authorize(principal, project, Some(context))?;
        let digest = raw_digest(bytes);
        let resource_id = match desired_resource_id {
            Some(id) => id.clone(),
            None => {
                let identity = canonical_digest(&json!({"projectId":project.project_id(),"sha256":digest,"mediaType":media_type,"sizeBytes":bytes.len()}))
                .map_err(|_| source_budget())?;
                ResourceId::new(format!("private-{}", identity.as_str()))
                    .map_err(|_| source_budget())?
            }
        };
        let resource = ResourceRef {
            resource_id,
            sha256: digest,
            media_type: media_type.into(),
            size_bytes: bytes.len() as u64,
        };
        let value = serde_json::to_value(&resource).map_err(|_| source_budget())?;
        self.store.with_write(|store| {
            self.access.check()?;
            let blob = store.put_blob(bytes).map_err(storage_error)?;
            if blob.digest != resource.sha256 || blob.byte_length != resource.size_bytes {
                return Err(error("SOURCE_CORRUPT", "Private staging bytes changed"));
            }
            register_resource(
                store,
                &value,
                ResourceOwner::Project(project.project_id().clone()),
            )
            .map_err(|e| error(e.code, e.message))?;
            self.access.check()
        })?;
        // The registered CAS pin is preserved if authority is revoked here;
        // private staging has not changed authored state or a world target.
        self.authorize(principal, project, Some(context))?;
        self.store
            .record_issued(principal, project.project_id(), context, &resource)?;
        Ok(resource)
    }
    fn allocate_instance_id(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        used: &BTreeSet<InstanceId>,
    ) -> AppResult<InstanceId> {
        self.authorize(principal, project, None)?;
        for _ in 0..8 {
            self.access.check()?;
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).map_err(|_| {
                error(
                    "SOURCE_UNAVAILABLE",
                    "Instance allocation entropy is unavailable",
                )
            })?;
            let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let id = InstanceId::new(format!("instance-{suffix}")).map_err(|_| source_budget())?;
            if !used.contains(&id)
                && !project.project()["instanceIds"]
                    .as_array()
                    .is_some_and(|ids| ids.contains(&json!(id)))
            {
                self.authorize(principal, project, None)?;
                return Ok(id);
            }
        }
        Err(error(
            "ID_COLLISION",
            "Finite instance allocation attempts collided",
        ))
    }
    fn state_snapshot(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        instance: &Value,
        definition: &Value,
        context: &Value,
    ) -> AppResult<PinnedStateSnapshot> {
        self.authorize(principal, project, Some(context))?;
        let snapshot = self
            .data
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .state_snapshot(
                principal,
                project,
                instance,
                definition,
                context,
                self.access.budget(),
            )?;
        if snapshot.context_digest.as_str() != text(context, "contextDigest")?
            || snapshot.source_instance_id.as_str() != text(instance, "instanceId")?
            || snapshot.prefab_revision.as_str() != text(definition, "revision")?
            || instance["prefabRevision"] != definition["revision"]
            || snapshot.bytes.len() as u64 > MAX_DOCUMENT_BYTES
        {
            return Err(error(
                "STATE_SNAPSHOT_REQUIRED",
                "Actual state observation does not bind the selected source pins",
            ));
        }
        let expected_codec = json!({"format":"mmmm.state.snapshot/1","contextDigest":snapshot.context_digest,
            "sourceInstanceId":snapshot.source_instance_id,"prefabRevision":snapshot.prefab_revision,"values":snapshot.values});
        if mmmm_contracts::parse_json(&snapshot.bytes).map_err(|_| source_budget())?
            != expected_codec
        {
            return Err(error(
                "STATE_SNAPSHOT_REQUIRED",
                "Observed values differ from their closed state codec bytes",
            ));
        }
        let resource = self.stage_private(
            principal,
            project,
            None,
            &snapshot.bytes,
            "application/vnd.mmmm.state-snapshot+json",
            context,
        )?;
        let typed = ResolvedStateSnapshot::from_verified_blob(
            resource.clone(),
            &snapshot.bytes,
            snapshot.source_instance_id,
            snapshot.prefab_revision,
            snapshot.values,
        )
        .map_err(|e| error(e.code, "State codec proof could not be retained"))?;
        self.authorize(principal, project, Some(context))?;
        Ok(PinnedStateSnapshot {
            resource,
            snapshot: typed,
        })
    }
    fn scene_source(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        context: &Value,
    ) -> AppResult<SceneSource> {
        self.authorize(principal, project, Some(context))?;
        validate("ScenePatch", patch)?;
        let artifact = decode_resource(&patch["sourceArtifact"])?;
        let map = decode_resource(&patch["sourceMap"])?;
        let artifact_bytes = self.resource_bytes(
            principal,
            project,
            &artifact,
            Some(context),
            MAX_SOURCE_BYTES,
        )?;
        let map_bytes =
            self.resource_bytes(principal, project, &map, Some(context), MAX_DOCUMENT_BYTES)?;
        let source = self
            .data
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .scene_source(principal, project, patch, context, self.access.budget())?;
        if mmmm_contracts::parse_json(&artifact_bytes.bytes).map_err(|_| source_budget())?
            != source.artifact
            || mmmm_contracts::parse_json(&map_bytes.bytes).map_err(|_| source_budget())?
                != source.source_map
        {
            return Err(error(
                "SOURCE_PROVENANCE_INVALID",
                "Scene decoder replaced the registered artifact or source map",
            ));
        }
        self.validate_scene_provenance(principal, project, patch, &source, context)?;
        Ok(source)
    }
    fn validate_scene_provenance(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        source: &SceneSource,
        context: &Value,
    ) -> AppResult<()> {
        self.authorize(principal, project, Some(context))?;
        source
            .selection
            .check_revision(project.project_id().as_str(), project.revision().as_str())
            .map_err(|e| {
                error(
                    e.code,
                    "Scene selection does not match actual Project source",
                )
            })?;
        self.data
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .validate_scene_provenance(
                principal,
                project,
                patch,
                source,
                context,
                self.access.budget(),
            )?;
        self.authorize(principal, project, Some(context))
    }
}

/// Final source and environment construction is in the methods below. Only the
/// store-aware entry points are executable; façade callers use the one common
/// application algorithm and cannot construct a parallel plan/apply ledger.
pub struct StoreAwarePlanner {
    request: Box<dyn PlanningRequestSource>,
    authority: LocalAuthority,
    hosts: HostBridge,
    contexts: SharedPlanningContexts,
    data: SharedPlanningData,
    backend: SharedPlanningBackend,
    dependencies: SharedPlanningDependencies,
    clock: Box<dyn Clock>,
    options: PlannerOptions,
}
pub struct PlanningComposition {
    pub request: Box<dyn PlanningRequestSource>,
    pub authority: LocalAuthority,
    pub hosts: HostBridge,
    pub contexts: SharedPlanningContexts,
    pub data: SharedPlanningData,
    pub backend: SharedPlanningBackend,
    pub dependencies: SharedPlanningDependencies,
    pub clock: Box<dyn Clock>,
    pub options: PlannerOptions,
}
impl StoreAwarePlanner {
    pub fn new(composition: PlanningComposition) -> AppResult<Self> {
        if composition.options.max_source_bytes == 0
            || composition.options.max_source_bytes > 256 * 1024 * 1024
            || !(1..=3_600_000).contains(&composition.options.time_budget_ms)
            || !(1..=3600).contains(&composition.options.expiry_seconds)
        {
            return Err(source_budget());
        }
        Ok(Self {
            request: composition.request,
            authority: composition.authority,
            hosts: composition.hosts,
            contexts: composition.contexts,
            data: composition.data,
            backend: composition.backend,
            dependencies: composition.dependencies,
            clock: composition.clock,
            options: composition.options,
        })
    }
    fn access_for(&self, principal: &PrincipalId) -> AppResult<LocalPlanningAccess> {
        let (authenticated, budget) = self.request.current(principal)?;
        if authenticated.principal() != principal {
            return Err(forbidden());
        }
        LocalPlanningAccess::new(
            authenticated,
            self.authority.clone(),
            self.hosts.clone(),
            budget,
            self.contexts.clone(),
        )
    }
}
struct BorrowedClock<'a>(&'a mut dyn Clock);
impl Clock for BorrowedClock<'_> {
    fn unix_nanos(&self) -> i128 {
        self.0.unix_nanos()
    }
}

pub struct ConcretePlanningEnvironment<'a> {
    store: PlanningStore<'a>,
    access: LocalPlanningAccess,
    data: SharedPlanningData,
    backend: SharedPlanningBackend,
    dependencies: SharedPlanningDependencies,
}
impl<'a> ConcretePlanningEnvironment<'a> {
    pub fn new(
        store: PlanningStore<'a>,
        access: LocalPlanningAccess,
        data: SharedPlanningData,
        backend: SharedPlanningBackend,
        dependencies: SharedPlanningDependencies,
    ) -> Self {
        Self {
            store,
            access,
            data,
            backend,
            dependencies,
        }
    }
    fn before(&self, principal: &PrincipalId, context: &Value) -> AppResult<()> {
        self.access.authorize_context(principal, context)
    }
    fn after<T>(
        &self,
        principal: &PrincipalId,
        context: &Value,
        result: AppResult<T>,
    ) -> AppResult<T> {
        // Preserve the original meaningful backend error. A successful result
        // is never released under stale authority or a completed request budget.
        let value = result?;
        self.access.authorize_context(principal, context)?;
        Ok(value)
    }
    fn source(&self) -> BorrowedProjectSource<'a> {
        BorrowedProjectSource::new(self.store.clone(), self.access.clone(), self.data.clone())
    }
    fn target(
        &self,
        principal: &PrincipalId,
        profile: &TargetProfileId,
        context: &Value,
    ) -> AppResult<VerifiedPlanningTarget> {
        self.before(principal, context)?;
        if context["environment"]["kind"] != "game" {
            return Err(error(
                "TARGET_UNVERIFIED",
                "A compiler target requires actual connected game evidence",
            ));
        }
        let hello = self.access.hosts.hello_with_deadline(
            principal,
            &context_id(context)?,
            self.access.budget().deadline(),
        )?;
        if hello["hostProtocolVersion"] != "0.2.0"
            || hello["gameVersion"] != "26.3"
            || hello["javaMajor"] != 25
            || hello["environment"] != context["environment"]
        {
            return Err(error(
                "TARGET_UNVERIFIED",
                "Actual paired host differs from the supported target tuple",
            ));
        }
        let target = self
            .backend
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .verify_live_target(principal, profile, context, &hello, self.access.budget())?;
        if target.compiler.profile_id() != profile
            || target.evidence_resource_pins.is_empty()
            || target.evidence_resource_pins.len() > 4096
            || target.hello_digest != canonical_digest(&hello).map_err(|_| source_budget())?
            || target.environment_digest
                != canonical_digest(&context["environment"]).map_err(|_| source_budget())?
        {
            return Err(error(
                "TARGET_UNVERIFIED",
                "Registry target proof does not bind the actual host generation",
            ));
        }
        let mut remaining = MAX_SOURCE_BYTES;
        let project_id = ProjectId::new(text(context, "projectId")?).map_err(|_| forbidden())?;
        let project = self.checked_project(principal, &project_id, context)?;
        let mut source = self.source();
        for resource in &target.evidence_resource_pins {
            let read =
                source.resource_bytes(principal, &project, resource, Some(context), remaining)?;
            remaining = remaining
                .checked_sub(read.bytes.len() as u64)
                .ok_or_else(source_budget)?;
        }
        self.after(principal, context, Ok(target))
    }
    fn checked_project(
        &self,
        principal: &PrincipalId,
        project_id: &ProjectId,
        context: &Value,
    ) -> AppResult<ProjectCatalog> {
        self.access
            .authorize_project(principal, project_id, Some(context), Access::ReadProject)?;
        let rpc = SourceRequest::new(
            self.access.clone(),
            Some(context),
            self.store.issued.clone(),
        )?;
        let mut reader = resource_reader(&rpc)?;
        let project = self.store.with_read(|store| {
            reader
                .current_project(store, &rpc, project_id, MAX_DOCUMENT_BYTES)
                .map_err(storage_error)
        })?;
        let catalog = ProjectCatalog::from_project(&project)?;
        let source = self.source();
        source.authorize(principal, &catalog, Some(context))?;
        Ok(catalog)
    }
}

impl PlanningEnvironmentPort for ConcretePlanningEnvironment<'_> {
    fn execution_budget_ms(&mut self, principal: &PrincipalId, context: &Value) -> AppResult<u64> {
        self.before(principal, context)?;
        let result = self
            .backend
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .execution_budget_ms(principal, context);
        let milliseconds = self.after(principal, context, result)?;
        if milliseconds == 0 || milliseconds > 3_600_000 {
            return Err(source_budget());
        }
        Ok(milliseconds)
    }
    fn inventory(
        &mut self,
        principal: &PrincipalId,
        context: &Value,
    ) -> AppResult<InventorySnapshot> {
        self.before(principal, context)?;
        let result = self
            .backend
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .inventory(principal, context);
        let inventory = self.after(principal, context, result)?;
        if inventory.context().context_id().as_str() != text(context, "contextId")?
            || inventory.context().context_digest().as_str() != text(context, "contextDigest")?
            || inventory.policy_revision().as_str() != text(context, "policyRevision")?
        {
            return Err(error(
                "INVENTORY_STALE",
                "Registered source inventory belongs to another context or policy",
            ));
        }
        Ok(inventory)
    }
    fn binding_dependency(
        &mut self,
        principal: &PrincipalId,
        binding: &BindingId,
        implementation_digest: &Sha256Digest,
        context: &Value,
    ) -> AppResult<Value> {
        let inventory = self.inventory(principal, context)?;
        let selected: Vec<_> = inventory
            .inventory()
            .providers
            .iter()
            .filter(|provider| &provider.binding_id == binding)
            .flat_map(|provider| &provider.actions)
            .filter(|action| &action.implementation_digest == implementation_digest)
            .collect();
        let pin = self
            .dependencies
            .try_borrow()
            .map_err(|_| source_busy())?
            .pin(binding, implementation_digest, &selected)?;
        self.after(principal, context, Ok(pin))
    }
    fn native_route(
        &mut self,
        principal: &PrincipalId,
        kind: NativeKind,
        context: &Value,
    ) -> AppResult<NativeActionRoute> {
        self.before(principal, context)?;
        let result = self
            .backend
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .native_route(principal, kind, context);
        self.after(principal, context, result)
    }
    fn verified_native_target(
        &mut self,
        principal: &PrincipalId,
        profile: &TargetProfileId,
        kind: NativeKind,
        context: &Value,
    ) -> AppResult<VerifiedNativeTarget> {
        let proof = self.target(principal, profile, context)?;
        if !proof.native_kinds.contains(&kind) {
            return Err(error(
                "TARGET_UNVERIFIED",
                "Selected native kind has no exact runtime target evidence",
            ));
        }
        Ok(VerifiedNativeTarget {
            profile_id: proof.compiler.profile_id().clone(),
            profile_digest: proof.compiler.profile_digest().clone(),
            artifact_digest: proof.compiler.artifact_digest().clone(),
            evidence_resource_pins: proof.evidence_resource_pins,
            supported_kinds: proof.native_kinds,
        })
    }
    fn snapshot_native_targets(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        change: &PreparedNativeChange,
        context: &Value,
    ) -> AppResult<NativeTargetSnapshot> {
        self.source().authorize(principal, project, Some(context))?;
        let result = self
            .backend
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .snapshot_native_targets(principal, project, change, context);
        let snapshot = self.after(principal, context, result)?;
        if snapshot.context_digest.as_str() != text(context, "contextDigest")?
            || snapshot.scope.project_id != *project.project_id()
        {
            return Err(error(
                "OBSERVATION_INVALID",
                "Native observer snapshot belongs to a different source authority",
            ));
        }
        verify_before_images(&snapshot.targets)?;
        Ok(snapshot)
    }
    fn registered_action_footprint(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        request: &Value,
        action: &ActionDescriptor,
        context: &Value,
    ) -> AppResult<RegisteredActionFootprint> {
        self.source().authorize(principal, project, Some(context))?;
        let result = self
            .backend
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .registered_action_footprint(principal, project, request, action, context);
        let footprint = self.after(principal, context, result)?;
        if footprint.scope.project_id != *project.project_id() {
            return Err(forbidden());
        }
        verify_before_images(&footprint.targets)?;
        Ok(footprint)
    }
    fn relocatable_modules(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        modules: &[Value],
        context: &Value,
    ) -> AppResult<BTreeSet<ModuleId>> {
        self.source().authorize(principal, project, Some(context))?;
        let result = self
            .backend
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .relocatable_modules(principal, project, modules, context);
        self.after(principal, context, result)
    }
    fn command_layout_support(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        module: &Value,
        context: &Value,
    ) -> AppResult<CommandLayoutSupport> {
        self.source().authorize(principal, project, Some(context))?;
        let result = self
            .backend
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .command_layout_support(principal, project, module, context);
        self.after(principal, context, result)
    }
    fn command_layout_request(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        instance: &Value,
        module: &Value,
        context: &Value,
    ) -> AppResult<Value> {
        self.source().authorize(principal, project, Some(context))?;
        let result = self
            .backend
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .command_layout_request(principal, project, instance, module, context);
        self.after(principal, context, result)
    }
    fn verify_projection_references(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        projection: &InstanceProjection,
        context: &Value,
    ) -> AppResult<Vec<Value>> {
        self.source().authorize(principal, project, Some(context))?;
        let result = self
            .backend
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .verify_projection_references(principal, project, projection, context);
        let pins = self.after(principal, context, result)?;
        if pins.len() > 4096 {
            return Err(source_budget());
        }
        for pin in &pins {
            validate("DependencyPin", pin)?;
        }
        Ok(pins)
    }
    fn compiler_target(
        &mut self,
        principal: &PrincipalId,
        profile: &TargetProfileId,
        context: &Value,
    ) -> AppResult<VerifiedTarget> {
        Ok(self.target(principal, profile, context)?.compiler)
    }
    fn pack_inputs(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        owned_values: &[Value],
        context: &Value,
    ) -> AppResult<PackBuildInputs> {
        self.before(principal, context)?;
        let mut source = self.source();
        let actual = source.inspect_owned(principal, project, MAX_SOURCE_BYTES)?;
        if actual.len() != owned_values.len() {
            return Err(revision_conflict());
        }
        let mut supplied = BTreeMap::new();
        for value in owned_values {
            let encoded = canonical_digest(value).map_err(|_| source_budget())?;
            if supplied.insert(encoded, value).is_some() {
                return Err(revision_conflict());
            }
        }
        for (_, value) in &actual {
            let digest = canonical_digest(value).map_err(|_| source_budget())?;
            if supplied.get(&digest).copied() != Some(value) {
                return Err(revision_conflict());
            }
        }
        let mut pins = BTreeMap::new();
        for (_, value) in &actual {
            gather_resource_pins(value, &mut pins, 0)?;
        }
        let mut resources = Vec::with_capacity(pins.len());
        let mut remaining = MAX_SOURCE_BYTES;
        for resource in pins.into_values() {
            let read =
                source.resource_bytes(principal, project, &resource, Some(context), remaining)?;
            remaining = remaining
                .checked_sub(read.bytes.len() as u64)
                .ok_or_else(source_budget)?;
            resources.push(SceneResource {
                reference: read.resource,
                bytes: read.bytes,
            });
        }
        let result = self
            .backend
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .lower_owned_pack(
                principal,
                project,
                owned_values,
                &resources,
                context,
                self.access.budget(),
            );
        source.authorize(principal, project, Some(context))?;
        self.after(principal, context, result)
    }
    fn recovery_route(
        &mut self,
        principal: &PrincipalId,
        recovery: &RecoveryPreparation,
        context: &Value,
    ) -> AppResult<NativeActionRoute> {
        self.before(principal, context)?;
        let result = self
            .backend
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .recovery_route(principal, recovery, context);
        self.after(principal, context, result)
    }
    fn recovery_scope(
        &mut self,
        principal: &PrincipalId,
        recovery: &RecoveryPreparation,
        project: &ProjectCatalog,
        context: &Value,
    ) -> AppResult<WriteScope> {
        self.source().authorize(principal, project, Some(context))?;
        let result = self
            .backend
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .recovery_scope(principal, recovery, project, context);
        self.after(principal, context, result)
    }
    fn project_bindings_available(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
    ) -> AppResult<bool> {
        self.source().authorize(principal, project, None)?;
        let result = self
            .backend
            .try_borrow_mut()
            .map_err(|_| source_busy())?
            .project_bindings_available(principal, project);
        let result = result?;
        self.source().authorize(principal, project, None)?;
        Ok(result)
    }
}

fn gather_resource_pins(
    value: &Value,
    pins: &mut BTreeMap<(String, Sha256Digest), ResourceRef>,
    depth: usize,
) -> AppResult<()> {
    if depth > 64 {
        return Err(source_budget());
    }
    match value {
        Value::Array(values) => {
            for child in values {
                gather_resource_pins(child, pins, depth + 1)?;
            }
        }
        Value::Object(values) => {
            if values.len() == 4
                && ["resourceId", "sha256", "mediaType", "sizeBytes"]
                    .iter()
                    .all(|key| values.contains_key(*key))
            {
                let resource = decode_resource(value)?;
                let key = (
                    resource.resource_id.as_str().to_owned(),
                    resource.sha256.clone(),
                );
                if let Some(prior) = pins.get(&key) {
                    if prior.media_type != resource.media_type
                        || prior.size_bytes != resource.size_bytes
                    {
                        return Err(revision_conflict());
                    }
                } else {
                    if pins.len() >= 4096 {
                        return Err(source_budget());
                    }
                    pins.insert(key, resource);
                }
            } else {
                for child in values.values() {
                    gather_resource_pins(child, pins, depth + 1)?;
                }
            }
        }
        _ => (),
    }
    Ok(())
}
fn verify_before_images(images: &[mmmm_planner::TargetBeforeImage]) -> AppResult<()> {
    if images.len() > 4096 {
        return Err(source_budget());
    }
    let mut total = 0u64;
    let mut identities = BTreeSet::new();
    for image in images {
        total = total
            .checked_add(image.bytes.len() as u64)
            .ok_or_else(source_budget)?;
        if total > MAX_SOURCE_BYTES
            || image.subject.is_empty()
            || image.subject.len() > 2048
            || !identities.insert(&image.subject)
            || raw_digest(&image.bytes) != image.digest
        {
            return Err(error(
                "OBSERVATION_INVALID",
                "Independent native before images are incomplete, duplicated or changed",
            ));
        }
    }
    Ok(())
}

impl PlanningPort for StoreAwarePlanner {
    fn inspect_project(
        &mut self,
        _principal: &PrincipalId,
        _project: &Value,
    ) -> AppResult<ProjectInspection> {
        Err(store_required())
    }
    fn prepare(
        &mut self,
        _principal: &PrincipalId,
        _request: &Value,
        _project: &Value,
        _context: &Value,
    ) -> AppResult<PreparedPlan> {
        Err(store_required())
    }
    fn prepare_recovery(
        &mut self,
        _principal: &PrincipalId,
        _recovery: &RecoveryPreparation,
        _project: &Value,
        _context: &Value,
    ) -> AppResult<PreparedPlan> {
        Err(store_required())
    }
    fn inspect_project_with_store(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        project: &Value,
    ) -> AppResult<ProjectInspection> {
        let access = self.access_for(principal)?;
        let shared = PlanningStore::read(store);
        let source = BorrowedProjectSource::new(shared.clone(), access.clone(), self.data.clone());
        let environment = ConcretePlanningEnvironment::new(
            shared,
            access,
            self.data.clone(),
            self.backend.clone(),
            self.dependencies.clone(),
        );
        let mut planner = NativePlanner::new(
            Box::new(source),
            Box::new(environment),
            Box::new(BorrowedClock(&mut *self.clock)),
            self.options.clone(),
        )?;
        planner.inspect_project(principal, project)
    }
    fn prepare_with_store(
        &mut self,
        store: &mut DurableStore,
        principal: &PrincipalId,
        request: &Value,
        project: &Value,
        context: &Value,
    ) -> AppResult<PreparedPlan> {
        let access = self.access_for(principal)?;
        let shared = PlanningStore::write(store);
        let source = BorrowedProjectSource::new(shared.clone(), access.clone(), self.data.clone());
        let environment = ConcretePlanningEnvironment::new(
            shared,
            access,
            self.data.clone(),
            self.backend.clone(),
            self.dependencies.clone(),
        );
        let mut planner = NativePlanner::new(
            Box::new(source),
            Box::new(environment),
            Box::new(BorrowedClock(&mut *self.clock)),
            self.options.clone(),
        )?;
        planner.prepare(principal, request, project, context)
    }
    fn prepare_recovery_with_store(
        &mut self,
        store: &mut DurableStore,
        principal: &PrincipalId,
        recovery: &RecoveryPreparation,
        project: &Value,
        context: &Value,
    ) -> AppResult<PreparedPlan> {
        let access = self.access_for(principal)?;
        let shared = PlanningStore::write(store);
        let source = BorrowedProjectSource::new(shared.clone(), access.clone(), self.data.clone());
        let environment = ConcretePlanningEnvironment::new(
            shared,
            access,
            self.data.clone(),
            self.backend.clone(),
            self.dependencies.clone(),
        );
        let mut planner = NativePlanner::new(
            Box::new(source),
            Box::new(environment),
            Box::new(BorrowedClock(&mut *self.clock)),
            self.options.clone(),
        )?;
        planner.prepare_recovery(principal, recovery, project, context)
    }
}
fn store_required() -> AppError {
    error(
        "STORE_BORROW_REQUIRED",
        "Native planning requires the application's unique call-scoped durable store",
    )
}

fn source_busy() -> AppError {
    error(
        "SOURCE_BUSY",
        "Planning source is already borrowed by this request",
    )
}
fn source_budget() -> AppError {
    error(
        "BUDGET_EXCEEDED",
        "Planning source exceeds its finite byte or item budget",
    )
}
fn forbidden() -> AppError {
    error(
        "PERMISSION_REQUIRED",
        "Current authenticated source authority is required",
    )
}
fn revision_conflict() -> AppError {
    error(
        "REVISION_CONFLICT",
        "Planning source differs from the current durable Project",
    )
}
fn error(code: &'static str, message: &'static str) -> AppError {
    AppError::new(code, message)
}
fn budget_check(budget: &RequestBudget) -> AppResult<()> {
    budget.check().map_err(|e| error(e.code, e.message))
}
fn storage_error(error_value: StorageError) -> AppError {
    let code = match &error_value {
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
    AppError::storage(code, error_value)
}
fn source_storage_error(error_value: AppError) -> StorageError {
    StorageError::InvalidTransition(format!("{}: {}", error_value.code, error_value.message))
}
fn context_id(context: &Value) -> AppResult<ContextId> {
    ContextId::new(text(context, "contextId")?).map_err(|_| forbidden())
}
fn context_digest(context: &Value) -> AppResult<Sha256Digest> {
    Sha256Digest::new(text(context, "contextDigest")?).map_err(|_| forbidden())
}
fn source_scope_contains(scope: &Value, kind: &str, id: &str) -> bool {
    scope[kind]
        .as_array()
        .is_some_and(|ids| ids.iter().any(|candidate| candidate.as_str() == Some(id)))
}
fn text<'a>(value: &'a Value, key: &str) -> AppResult<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| error("INVALID_INPUT", "Planning source field is absent"))
}
fn validate(definition: &str, value: &Value) -> AppResult<()> {
    mmmm_contracts::ContractValidator::shared()
        .and_then(|validator| validator.validate(definition, value))
        .map_err(|_| {
            error(
                "INVALID_INPUT",
                "Planning source violates its canonical contract",
            )
        })
}
fn registration_sets(actions: &BTreeSet<String>, contracts: &BTreeSet<String>) -> AppResult<()> {
    if actions.is_empty()
        || actions.len() > 256
        || contracts.is_empty()
        || contracts.len() > 64
        || contracts
            .iter()
            .chain(actions.iter())
            .any(|id| id.is_empty() || id.len() > 256)
    {
        return Err(source_budget());
    }
    Ok(())
}

#[cfg(test)]
#[path = "planning_source_tests.rs"]
mod tests;

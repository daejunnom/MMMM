//! One server-owned workspace locator is shared by planning, provider and
//! feature adapters. A ContextId only selects a registered source; neither
//! a context DTO nor a public scope can install a record or a Project grant.

use crate::{
    auth::AuthenticatedPrincipal,
    authority::{LocalAuthority, WorkspaceContextResolver},
    host::HostBridge,
    planning_source::{
        LocalPlanningAccess, PlanningContextPort, PlanningStore, SharedPlanningContexts,
    },
    service::RequestBudget,
    workspace_bootstrap::NativeOwnerWitness,
};
use mmmm_application::{Access, AppError, AppResult, AuthorityPort};
use mmmm_contracts::{
    ContextId, ContractValidator, PrincipalId, ProjectId, verify_projected_digest,
};
use mmmm_planner::ProjectCatalog;
use mmmm_runtime::storage::{
    DurableStore, StorageError,
    project_resources::{
        ProjectResourceAuthority, ProjectResourceReader, ProjectSourceRpcContext,
        RegisteredProjectResource,
    },
};
use serde_json::Value;
use std::time::Instant;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

const MAX_CONTEXTS: usize = 128;
const MAX_PROJECT_BYTES: u64 = 8 * 1024 * 1024;

/// This is the production registry, not a second facade ledger. Both lookup
/// and the legacy PlanningContextPort adapter read these same private records.
#[derive(Default)]
pub struct RegisteredContextLocator {
    records: BTreeMap<(PrincipalId, ContextId), Value>,
}
pub type SharedRegisteredPlanningContexts = Rc<RefCell<RegisteredContextLocator>>;

impl RegisteredContextLocator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Trusted authenticated source setup only. No RPC dispatch exposes this
    /// registration, and the existing exact Project grant must precede it.
    pub fn register_workspace(
        &mut self,
        principal: &AuthenticatedPrincipal,
        authority: &LocalAuthority,
        context: Value,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        check_request(principal, &context_id(&context)?, budget)?;
        workspace_grant(authority, principal.principal(), &context)?;
        self.insert(principal.principal(), context.clone())?;
        workspace_grant(authority, principal.principal(), &context)?;
        check_request(principal, &context_id(&context)?, budget)
    }

    /// Native daemon setup has a kernel owner/same-store witness before its
    /// Coordinator session exists. It does not fabricate an authenticated RPC
    /// principal or open a temporary SessionAuthority to populate this registry.
    pub fn register_native_owner(
        &mut self,
        witness: &NativeOwnerWitness,
        store: &DurableStore,
        authority: &LocalAuthority,
        context: Value,
    ) -> AppResult<()> {
        witness.check_store(store).map_err(storage_error)?;
        workspace_grant(authority, witness.principal(), &context)?;
        self.insert(witness.principal(), context.clone())?;
        workspace_grant(authority, witness.principal(), &context)?;
        witness.check_store(store).map_err(storage_error)
    }

    fn insert(&mut self, principal: &PrincipalId, context: Value) -> AppResult<()> {
        let key = (principal.clone(), context_id(&context)?);
        if self.records.len() >= MAX_CONTEXTS && !self.records.contains_key(&key) {
            return Err(error(
                "BUDGET_EXCEEDED",
                "Registered context capacity is exhausted",
            ));
        }
        if let Some(previous) = self.records.get(&key) {
            if previous != &context {
                return Err(error(
                    "CONTEXT_CONFLICT",
                    "Registered context identity is immutable",
                ));
            }
        } else {
            self.records.insert(key, context);
        }
        Ok(())
    }

    /// Resolve only from the actual private workspace registry or the current
    /// paired host, then revalidate the same actual principal/context/ACL before
    /// releasing its canonical context. Public JSON is never adopted as source.
    pub fn resolve(
        &mut self,
        principal: &AuthenticatedPrincipal,
        authority: &mut LocalAuthority,
        hosts: &HostBridge,
        id: &ContextId,
        access: Access,
        budget: &RequestBudget,
    ) -> AppResult<Value> {
        check_request(principal, id, budget)?;
        let key = (principal.principal().clone(), id.clone());
        if let Some(context) = self.records.get(&key).cloned() {
            if access == Access::Apply {
                return Err(denied());
            }
            workspace_grant(authority, principal.principal(), &context)?;
            let project = project_id(&context)?;
            authority.authorize(principal.principal(), &project, access, None, None)?;
            check_request(principal, id, budget)?;
            workspace_grant(authority, principal.principal(), &context)?;
            return Ok(context);
        }
        let context = hosts.context_with_deadline(principal.principal(), id, budget.deadline())?;
        let project = project_id(&context)?;
        // Do not recursively ask authority to resolve Some(context) while its
        // shared locator is borrowed. Bind this independent host observation
        // to the atomic exact grant, then use the common permission check.
        context_grant(authority, principal.principal(), &context)?;
        authority.authorize(principal.principal(), &project, access, None, None)?;
        let current = hosts.context_with_deadline(principal.principal(), id, budget.deadline())?;
        if current != context {
            return Err(error(
                "STALE_CONTEXT",
                "Paired context changed during lookup",
            ));
        }
        context_grant(authority, principal.principal(), &current)?;
        check_request(principal, id, budget)?;
        Ok(context)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Authenticated identity, current authority and paired host, exact Project and context, access scope and original budget are independent authorization inputs"
    )]
    fn authorize_registered_or_paired(
        &mut self,
        principal: &AuthenticatedPrincipal,
        authority: &mut LocalAuthority,
        hosts: &HostBridge,
        project: &ProjectId,
        context: &Value,
        access: Access,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        let actual = self.resolve(
            principal,
            authority,
            hosts,
            &context_id(context)?,
            access,
            budget,
        )?;
        if actual != *context || actual["projectId"] != project.as_str() {
            return Err(error(
                "STALE_CONTEXT",
                "Context differs from its actual registered source",
            ));
        }
        check_request(principal, &context_id(&actual)?, budget)
    }
}

struct SharedContextAdapter(SharedRegisteredPlanningContexts);
impl PlanningContextPort for SharedContextAdapter {
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
        self.0
            .try_borrow_mut()
            .map_err(|_| busy())?
            .authorize_registered_or_paired(
                principal, authority, hosts, project, context, access, budget,
            )
    }
}

/// Provider/feature resolution and planning authorization share this exact Rc.
/// A reentrant lookup fails with SOURCE_BUSY instead of a RefCell panic.
pub fn planning_context_adapter(
    shared: SharedRegisteredPlanningContexts,
) -> SharedPlanningContexts {
    Rc::new(RefCell::new(Box::new(SharedContextAdapter(shared))))
}

struct SharedWorkspaceResolver(SharedRegisteredPlanningContexts);
impl WorkspaceContextResolver for SharedWorkspaceResolver {
    fn resolve_workspace(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        deadline: Instant,
    ) -> AppResult<Option<Value>> {
        if Instant::now() >= deadline {
            return Err(error(
                "TIME_BUDGET_EXCEEDED",
                "Registered context lookup deadline reached",
            ));
        }
        let source = self.0.try_borrow().map_err(|_| busy())?;
        let value = source
            .records
            .get(&(principal.clone(), id.clone()))
            .cloned();
        if Instant::now() >= deadline {
            return Err(error(
                "TIME_BUDGET_EXCEEDED",
                "Registered context lookup deadline reached",
            ));
        }
        Ok(value)
    }
}

/// The authority's private lookup reads the same records and performs no
/// recursive authority call. LocalAuthority validates the active exact grant
/// after lookup, while public feature resolution requires the opaque session.
pub fn workspace_context_resolver(
    shared: SharedRegisteredPlanningContexts,
) -> Rc<dyn WorkspaceContextResolver> {
    Rc::new(SharedWorkspaceResolver(shared))
}

fn check_request(
    principal: &AuthenticatedPrincipal,
    id: &ContextId,
    budget: &RequestBudget,
) -> AppResult<()> {
    budget
        .check()
        .map_err(|error| self::error(error.code, error.message))?;
    if !principal.is_current() || !principal.permits_context(id.as_str()) {
        return Err(denied());
    }
    Ok(())
}

fn workspace_grant(
    authority: &LocalAuthority,
    principal: &PrincipalId,
    context: &Value,
) -> AppResult<()> {
    ContractValidator::shared()
        .and_then(|validator| validator.validate("ExecutionContext", context))
        .map_err(|_| {
            error(
                "INVALID_INPUT",
                "Workspace source violates its context contract",
            )
        })?;
    verify_projected_digest("ExecutionContext", context)
        .map_err(|_| error("STALE_CONTEXT", "Workspace source digest is invalid"))?;
    project_id(context)?;
    context_id(context)?;
    if context["principalRef"] != principal.as_str()
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
        || context["scope"]["regions"]
            .as_array()
            .is_none_or(|regions| !regions.is_empty())
    {
        return Err(denied());
    }
    context_grant(authority, principal, context)
}
fn context_grant(
    authority: &LocalAuthority,
    principal: &PrincipalId,
    context: &Value,
) -> AppResult<()> {
    if context["principalRef"] != principal.as_str() {
        return Err(denied());
    }
    let project = project_id(context)?;
    let id = context_id(context)?;
    // Policy generation, context membership and scope are checked together
    // against one live Project grant. Another Project's context is insufficient.
    let policy = mmmm_contracts::Sha256Digest::new(text(context, "policyRevision")?)
        .map_err(|_| denied())?;
    authority.authorize_retained_scope(principal, &project, &id, &policy, &context["scope"])
}

/// The configured server ProjectId is explicit even when a feature wire input
/// omits a context or Project locator. The helper reads its real current head
/// through the bounded runtime reader, not store.project or caller JSON.
pub fn checked_current_project_catalog(
    store: &PlanningStore<'_>,
    access: &LocalPlanningAccess,
    principal: &PrincipalId,
    project: &ProjectId,
    context: Option<&Value>,
) -> AppResult<ProjectCatalog> {
    access.authorize_project(principal, project, context, Access::ReadProject)?;
    let rpc = CurrentProjectRequest {
        access: access.clone(),
        context: context.map(context_id).transpose()?,
        project: project.clone(),
    };
    let mut reader = ProjectResourceReader::new(
        Box::new(CurrentProjectAuthority(rpc.clone())),
        MAX_PROJECT_BYTES,
    )
    .map_err(storage_error)?;
    let actual = store.with_read(|store| {
        reader
            .current_project(store, &rpc, project, MAX_PROJECT_BYTES)
            .map_err(storage_error)
    })?;
    let catalog = ProjectCatalog::from_project(&actual)?;
    access.authorize_project(principal, project, context, Access::ReadProject)?;
    Ok(catalog)
}

#[derive(Clone)]
struct CurrentProjectRequest {
    access: LocalPlanningAccess,
    context: Option<ContextId>,
    project: ProjectId,
}
impl ProjectSourceRpcContext for CurrentProjectRequest {
    fn check(&self) -> Result<(), StorageError> {
        self.access.check().map_err(source_storage_error)
    }
    fn authenticated_principal(&self) -> Result<PrincipalId, StorageError> {
        self.check()?;
        Ok(self.access.principal().clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        self.context.as_ref()
    }
}
struct CurrentProjectAuthority(CurrentProjectRequest);
impl ProjectResourceAuthority for CurrentProjectAuthority {
    fn authorize_project_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        _revision: &mmmm_contracts::Sha256Digest,
    ) -> Result<(), StorageError> {
        self.0.check()?;
        if principal != self.0.access.principal()
            || context != self.0.context.as_ref()
            || project != &self.0.project
        {
            return Err(source_storage_error(denied()));
        }
        // No host I/O is performed while the unique Store borrow is held.
        self.0
            .access
            .authorize_project(principal, project, None, Access::ReadProject)
            .map_err(source_storage_error)
    }
    fn authorize_resource_read(
        &mut self,
        _store: &DurableStore,
        _principal: &PrincipalId,
        _context: Option<&ContextId>,
        _project: &ProjectId,
        _resource: &RegisteredProjectResource,
    ) -> Result<(), StorageError> {
        Err(source_storage_error(denied()))
    }
}

fn context_id(context: &Value) -> AppResult<ContextId> {
    ContextId::new(text(context, "contextId")?).map_err(|_| denied())
}
fn project_id(context: &Value) -> AppResult<ProjectId> {
    ProjectId::new(text(context, "projectId")?).map_err(|_| denied())
}
fn text<'a>(value: &'a Value, field: &str) -> AppResult<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| error("INVALID_INPUT", "Registered source field is absent"))
}
fn denied() -> AppError {
    error(
        "PERMISSION_REQUIRED",
        "Actual Project and context authority is required",
    )
}
fn busy() -> AppError {
    error(
        "SOURCE_BUSY",
        "Registered context source is already borrowed",
    )
}
fn error(code: &'static str, message: &'static str) -> AppError {
    AppError::new(code, message)
}
fn source_storage_error(error: AppError) -> StorageError {
    StorageError::InvalidTransition(format!("{}: {}", error.code, error.message))
}
fn storage_error(cause: StorageError) -> AppError {
    let code = match &cause {
        StorageError::NotFound(_) => "NOT_FOUND",
        StorageError::Conflict(_) => "REVISION_CONFLICT",
        StorageError::Corrupt(_) => "SOURCE_CORRUPT",
        StorageError::InvalidInput(_) => "BUDGET_EXCEEDED",
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
    AppError::storage(code, cause)
}

#[cfg(test)]
#[path = "planning_context_tests.rs"]
mod tests;

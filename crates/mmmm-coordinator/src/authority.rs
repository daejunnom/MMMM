//! Server-owned local ACL and explicit plan approvals. Public setup and request
//! JSON provide locators only; neither can create these live authority records.

use crate::host::HostBridge;
use mmmm_application::{Access, AppError, AppResult, AuthorityPort};
use mmmm_contracts::{
    ContextId, ContractValidator, PrincipalId, ProjectId, Sha256Digest, canonical_digest,
    verify_projected_digest,
};
use mmmm_runtime::{
    artifact::{ArtifactError, ArtifactResult, ResourceAuthority, ResourceOwner},
    storage::{DurableStore, OperationRecord},
};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct LocalAuthority {
    state: Arc<Mutex<AuthorityState>>,
    hosts: HostBridge,
    workspace: Rc<RefCell<Option<Rc<dyn WorkspaceContextResolver>>>>,
}
/// Trusted composition shares one private workspace registry with planning,
/// features and the Provider context lookup. A resolver returns registered
/// immutable records; it neither mints grants nor accepts request JSON.
pub trait WorkspaceContextResolver {
    fn resolve_workspace(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        deadline: Instant,
    ) -> AppResult<Option<Value>>;
}
#[derive(Default)]
struct AuthorityState {
    projects: BTreeMap<(PrincipalId, ProjectId), ProjectGrant>,
    approvals: BTreeMap<(PrincipalId, ProjectId, Sha256Digest), PlanApproval>,
}
struct ProjectGrant {
    scope: Value,
    contexts: BTreeSet<ContextId>,
    revision: Sha256Digest,
    expires: Instant,
    active: bool,
}
struct PlanApproval {
    contexts: BTreeSet<ContextId>,
    policy: Sha256Digest,
    expires: Instant,
}
impl LocalAuthority {
    pub fn new(hosts: HostBridge) -> Self {
        Self {
            state: Arc::new(Mutex::new(AuthorityState::default())),
            hosts,
            workspace: Rc::new(RefCell::new(None)),
        }
    }
    pub fn install_workspace_resolver(
        &self,
        resolver: Rc<dyn WorkspaceContextResolver>,
    ) -> AppResult<()> {
        let mut slot = self.workspace.try_borrow_mut().map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Workspace context resolver is in use",
            )
        })?;
        if slot.is_some() {
            return Err(error(
                "AUTHORITY_CONFLICT",
                "Workspace context resolver is already installed",
            ));
        }
        *slot = Some(resolver);
        Ok(())
    }
    pub fn current_context_with_deadline(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        deadline: Instant,
    ) -> AppResult<Value> {
        if Instant::now() >= deadline {
            return Err(error(
                "TIME_BUDGET_EXCEEDED",
                "Context authority deadline reached",
            ));
        }
        let resolver = self
            .workspace
            .try_borrow()
            .map_err(|_| {
                error(
                    "AUTHORITY_UNAVAILABLE",
                    "Workspace context resolver is in use",
                )
            })?
            .clone();
        let context = match resolver {
            Some(resolver) => resolver.resolve_workspace(principal, id, deadline)?,
            None => None,
        };
        let context = match context {
            Some(context) => {
                if context["environment"]["kind"] != "offline" {
                    return Err(error(
                        "STALE_CONTEXT",
                        "Registered workspace context is not offline",
                    ));
                }
                context
            }
            None => self.hosts.context_with_deadline(principal, id, deadline)?,
        };
        validate("ExecutionContext", &context)?;
        verify_projected_digest("ExecutionContext", &context)
            .map_err(|_| error("STALE_CONTEXT", "Current context digest is invalid"))?;
        if Instant::now() >= deadline
            || context["contextId"] != id.as_str()
            || context["principalRef"] != principal.as_str()
        {
            return Err(error(
                "STALE_CONTEXT",
                "Current registered context identity is stale",
            ));
        }
        Ok(context)
    }
    /// Called by authenticated native/bootstrap composition after administrator
    /// and local project ownership checks. It grants no Apply permission.
    pub fn install_project_access(
        &self,
        principal: PrincipalId,
        project: ProjectId,
        scope: Value,
        contexts: BTreeSet<ContextId>,
        lifetime: Duration,
    ) -> AppResult<Sha256Digest> {
        let revision = self.stage_project_access(
            principal.clone(),
            project.clone(),
            scope,
            contexts,
            lifetime,
        )?;
        self.activate_staged_project(&principal, &project, &revision)?;
        Ok(revision)
    }
    /// Preparation reserves an immutable context policy without granting any
    /// read, plan, Apply, cancel or recovery access before native delivery.
    pub fn stage_project_access(
        &self,
        principal: PrincipalId,
        project: ProjectId,
        scope: Value,
        contexts: BTreeSet<ContextId>,
        lifetime: Duration,
    ) -> AppResult<Sha256Digest> {
        validate("Scope", &scope)?;
        if scope["projectId"] != project.as_str()
            || contexts.is_empty()
            || contexts.len() > 64
            || lifetime.is_zero()
            || lifetime > Duration::from_secs(24 * 60 * 60)
        {
            return Err(error(
                "PERMISSION_REQUIRED",
                "Project authority scope or lifetime is invalid",
            ));
        }
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Authority generation is unavailable",
            )
        })?;
        let generation: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let revision = canonical_digest(&json!({"principal":principal,"project":project,"scope":scope,"contexts":contexts,
            "permissions":["read_project","read_plan","plan","observe_operation","cancel","recovery"],"generation":generation}))
            .map_err(|_| error("AUTHORITY_UNAVAILABLE", "Current authority revision cannot be derived"))?;
        let mut state = self.state.lock().map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Current authority state is unavailable",
            )
        })?;
        state
            .projects
            .retain(|_, grant| Instant::now() < grant.expires);
        if state.projects.len() >= 128
            || state
                .projects
                .contains_key(&(principal.clone(), project.clone()))
        {
            return Err(error(
                "AUTHORITY_CONFLICT",
                "Project authority is already installed or capacity is exhausted",
            ));
        }
        state.projects.insert(
            (principal, project),
            ProjectGrant {
                scope,
                contexts,
                revision: revision.clone(),
                expires: Instant::now() + lifetime,
                active: false,
            },
        );
        Ok(revision)
    }
    pub fn validate_staged_project(
        &self,
        principal: &PrincipalId,
        project: &ProjectId,
        revision: &Sha256Digest,
    ) -> AppResult<()> {
        let state = self.state.lock().map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Current authority state is unavailable",
            )
        })?;
        state
            .projects
            .get(&(principal.clone(), project.clone()))
            .filter(|grant| {
                !grant.active && Instant::now() < grant.expires && &grant.revision == revision
            })
            .ok_or_else(|| {
                error(
                    "PERMISSION_REQUIRED",
                    "No exact pending bootstrap policy exists",
                )
            })?;
        Ok(())
    }
    pub fn activate_staged_project(
        &self,
        principal: &PrincipalId,
        project: &ProjectId,
        revision: &Sha256Digest,
    ) -> AppResult<()> {
        let mut state = self.state.lock().map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Current authority state is unavailable",
            )
        })?;
        let pending = state
            .projects
            .get_mut(&(principal.clone(), project.clone()))
            .filter(|grant| {
                !grant.active && Instant::now() < grant.expires && &grant.revision == revision
            })
            .ok_or_else(|| {
                error(
                    "PERMISSION_REQUIRED",
                    "No exact pending bootstrap policy exists",
                )
            })?;
        pending.active = true;
        Ok(())
    }
    pub fn policy_revision(
        &self,
        principal: &PrincipalId,
        project: &ProjectId,
    ) -> AppResult<Sha256Digest> {
        let state = self.state.lock().map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Current authority state is unavailable",
            )
        })?;
        Ok(grant(&state, principal, project)?.revision.clone())
    }
    /// Exact current server-owned scope for trusted workspace composition.
    /// The caller cannot use an older policy or public scope as this grant.
    pub fn project_scope(&self, principal: &PrincipalId, project: &ProjectId) -> AppResult<Value> {
        let state = self.state.lock().map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Current authority state is unavailable",
            )
        })?;
        Ok(grant(&state, principal, project)?.scope.clone())
    }
    pub fn project_context_ids(
        &self,
        principal: &PrincipalId,
        project: &ProjectId,
    ) -> AppResult<BTreeSet<ContextId>> {
        let state = self.state.lock().map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Current authority state is unavailable",
            )
        })?;
        Ok(grant(&state, principal, project)?.contexts.clone())
    }
    /// One atomic retained-record admission check. Old policy/context/scope
    /// fragments cannot be combined across grants or different Projects.
    pub fn authorize_retained_scope(
        &self,
        principal: &PrincipalId,
        project: &ProjectId,
        context: &ContextId,
        policy: &Sha256Digest,
        scope: &Value,
    ) -> AppResult<()> {
        validate("Scope", scope)?;
        let state = self.state.lock().map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Current authority state is unavailable",
            )
        })?;
        let current = grant(&state, principal, project)?;
        if &current.revision != policy
            || !current.contexts.contains(context)
            || !scope_contains(&current.scope, scope)
        {
            return Err(error(
                "PERMISSION_REQUIRED",
                "Retained record exceeds the current exact Project grant",
            ));
        }
        Ok(())
    }
    /// Local-only writer checkpoint for a previously observed immutable paired
    /// context and an actual stored frozen plan. Native freshness belongs to a
    /// pre-transaction witness/SDK mutation guard; this does not perform I/O or
    /// infer approval from the public plan hash.
    pub fn authorize_retained_apply(
        &self,
        principal: &PrincipalId,
        context: &Value,
        plan: &Value,
    ) -> AppResult<()> {
        validate("ExecutionContext", context)?;
        validate("ExecutionPlan", plan)?;
        verify_projected_digest("ExecutionContext", context)
            .map_err(|_| error("STALE_CONTEXT", "Retained context digest is invalid"))?;
        let hash = verify_projected_digest("ExecutionPlan", plan)
            .map_err(|_| error("STALE_PLAN", "Stored frozen plan digest is invalid"))?;
        let project = ProjectId::new(text(context, "projectId")?)
            .map_err(|_| error("STALE_CONTEXT", "Retained context Project is invalid"))?;
        let id = ContextId::new(text(context, "contextId")?)
            .map_err(|_| error("STALE_CONTEXT", "Retained context identity is invalid"))?;
        let state = self.state.lock().map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Current authority state is unavailable",
            )
        })?;
        let current = grant(&state, principal, &project)?;
        let approval = state
            .approvals
            .get(&(principal.clone(), project.clone(), hash))
            .filter(|approval| {
                Instant::now() < approval.expires && approval.policy == current.revision
            })
            .ok_or_else(|| {
                error(
                    "PERMISSION_REQUIRED",
                    "No current explicit approval exists for the stored frozen plan",
                )
            })?;
        if context["principalRef"] != principal.as_str()
            || context["policyRevision"] != current.revision.as_str()
            || plan["projectId"] != project.as_str()
            || plan["policyRevision"] != current.revision.as_str()
            || !current.contexts.contains(&id)
            || !approval.contexts.contains(&id)
            || !scope_contains(&current.scope, &context["scope"])
            || !scope_contains(&current.scope, &plan["scope"])
        {
            return Err(error(
                "PERMISSION_REQUIRED",
                "Stored Apply exceeds current context, scope or explicit approval",
            ));
        }
        Ok(())
    }
    pub fn revoke_project(&self, principal: &PrincipalId, project: &ProjectId) -> AppResult<()> {
        let mut state = self.state.lock().map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Current authority state is unavailable",
            )
        })?;
        state.projects.remove(&(principal.clone(), project.clone()));
        state
            .approvals
            .retain(|(p, id, _), _| p != principal || id != project);
        Ok(())
    }
    /// Rollback may retire only the exact staged bootstrap generation. A failed
    /// handshake cannot remove a newer grant or another project's authority.
    pub fn revoke_staged_project(
        &self,
        principal: &PrincipalId,
        project: &ProjectId,
        revision: &Sha256Digest,
    ) -> AppResult<()> {
        let mut state = self.state.lock().map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Current authority state is unavailable",
            )
        })?;
        let key = (principal.clone(), project.clone());
        if state
            .projects
            .get(&key)
            .is_some_and(|grant| &grant.revision == revision)
        {
            state.projects.remove(&key);
            state
                .approvals
                .retain(|(p, id, _), _| p != principal || id != project);
        }
        Ok(())
    }
    pub fn current_context_ids(&self, principal: &PrincipalId) -> AppResult<BTreeSet<ContextId>> {
        let state = self.state.lock().map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Current authority state is unavailable",
            )
        })?;
        Ok(state
            .projects
            .iter()
            .filter(|((p, _), grant)| {
                p == principal && grant.active && Instant::now() < grant.expires
            })
            .flat_map(|(_, grant)| grant.contexts.iter().cloned())
            .collect())
    }
    /// An explicitly invoked native user-approval composition loads the exact
    /// durable plan before calling this. Models/facade ApplyRequest cannot call
    /// it. Plan hash binds losses, scope, preconditions and all context pins.
    pub fn approve_plan(
        &self,
        principal: &PrincipalId,
        plan: &Value,
        lifetime: Duration,
    ) -> AppResult<()> {
        self.approve_plan_bounded(principal, plan, lifetime, None, &|| Ok(()))
    }
    /// 원 native 요청의 절대 기한을 모든 context 조회와 마지막 승인 검사에 전달한다.
    pub fn approve_plan_with_deadline(
        &self,
        principal: &PrincipalId,
        plan: &Value,
        lifetime: Duration,
        deadline: Instant,
    ) -> AppResult<()> {
        self.approve_plan_with_control(principal, plan, lifetime, deadline, &|| Ok(()))
    }
    /// 현재 요청의 취소 검사만 빌려 쓰며 callback이나 bootstrap 수명을 보관하지 않는다.
    /// checkpoint는 authority state를 재진입하거나 별도 host I/O를 수행하지 않는다.
    pub fn approve_plan_with_control(
        &self,
        principal: &PrincipalId,
        plan: &Value,
        lifetime: Duration,
        deadline: Instant,
        checkpoint: &dyn Fn() -> AppResult<()>,
    ) -> AppResult<()> {
        self.approve_plan_bounded(principal, plan, lifetime, Some(deadline), checkpoint)
    }
    fn approve_plan_bounded(
        &self,
        principal: &PrincipalId,
        plan: &Value,
        lifetime: Duration,
        deadline: Option<Instant>,
        checkpoint: &dyn Fn() -> AppResult<()>,
    ) -> AppResult<()> {
        let check = || {
            checkpoint()?;
            if deadline.is_some_and(|until| Instant::now() >= until) {
                return Err(error(
                    "TIME_BUDGET_EXCEEDED",
                    "Original plan approval deadline reached",
                ));
            }
            Ok(())
        };
        check()?;
        validate("ExecutionPlan", plan)?;
        let hash = verify_projected_digest("ExecutionPlan", plan)
            .map_err(|_| error("STALE_PLAN", "Approved plan digest is invalid"))?;
        let project = ProjectId::new(text(plan, "projectId")?)
            .map_err(|_| error("STALE_PLAN", "Approved project identity is invalid"))?;
        if lifetime.is_zero() || lifetime > Duration::from_secs(30 * 60) {
            return Err(error(
                "PERMISSION_REQUIRED",
                "Explicit approval lifetime is outside its finite range",
            ));
        }
        let mut contexts = BTreeSet::new();
        for pin in plan["contextPins"]
            .as_array()
            .ok_or_else(|| error("STALE_PLAN", "Plan contexts are absent"))?
        {
            let id = ContextId::new(text(pin, "contextId")?)
                .map_err(|_| error("STALE_CONTEXT", "Plan context identity is invalid"))?;
            check()?;
            let observed = match deadline {
                Some(until) => self.hosts.context_with_deadline(principal, &id, until),
                None => self.hosts.context(principal, &id),
            };
            let context = match (observed, check()) {
                (Ok(context), Ok(())) => context,
                (Err(cause), Ok(())) | (Ok(_), Err(cause)) => return Err(cause),
                (Err(primary), Err(checkpoint)) => {
                    return Err(AppError::caused_by(
                        primary.code,
                        primary.message,
                        crate::host::NativePairingOwnerFailure {
                            primary,
                            checkpoint,
                        },
                    ));
                }
            };
            if context["contextDigest"] != pin["contextDigest"]
                || context["environment"] != pin["environment"]
            {
                return Err(error(
                    "STALE_CONTEXT",
                    "Current approved context differs from the frozen plan",
                ));
            }
            contexts.insert(id);
        }
        check()?;
        let mut state = self.state.lock().map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Current authority state is unavailable",
            )
        })?;
        check()?;
        let project_grant = grant(&state, principal, &project)?;
        if contexts.is_empty()
            || !contexts.is_subset(&project_grant.contexts)
            || plan["policyRevision"] != project_grant.revision.as_str()
            || !scope_contains(&project_grant.scope, &plan["scope"])
        {
            return Err(error(
                "PERMISSION_REQUIRED",
                "Plan exceeds current project or context authority",
            ));
        }
        let revision = project_grant.revision.clone();
        let expires = (Instant::now() + lifetime).min(project_grant.expires);
        state
            .approvals
            .retain(|_, approval| Instant::now() < approval.expires);
        if state.approvals.len() >= 1024
            && !state
                .approvals
                .contains_key(&(principal.clone(), project.clone(), hash.clone()))
        {
            return Err(error(
                "AUTHORITY_CAPACITY",
                "Explicit approval capacity is exhausted",
            ));
        }
        check()?;
        state.approvals.insert(
            (principal.clone(), project, hash),
            PlanApproval {
                contexts,
                policy: revision,
                expires,
            },
        );
        Ok(())
    }
    fn authorize_current(
        &self,
        principal: &PrincipalId,
        project: &ProjectId,
        access: Access,
        context: Option<&Value>,
        plan: Option<&Value>,
    ) -> AppResult<()> {
        self.authorize_current_bounded(principal, project, access, context, plan, None)
    }
    pub fn authorize_with_deadline(
        &self,
        principal: &PrincipalId,
        project: &ProjectId,
        access: Access,
        context: Option<&Value>,
        plan: Option<&Value>,
        deadline: Instant,
    ) -> AppResult<()> {
        if Instant::now() >= deadline {
            return Err(error(
                "TIME_BUDGET_EXCEEDED",
                "Authority request deadline reached",
            ));
        }
        self.authorize_current_bounded(principal, project, access, context, plan, Some(deadline))?;
        if Instant::now() >= deadline {
            return Err(error(
                "TIME_BUDGET_EXCEEDED",
                "Authority request deadline reached",
            ));
        }
        Ok(())
    }
    fn authorize_current_bounded(
        &self,
        principal: &PrincipalId,
        project: &ProjectId,
        access: Access,
        context: Option<&Value>,
        plan: Option<&Value>,
        deadline: Option<Instant>,
    ) -> AppResult<()> {
        let live = match context {
            Some(context) => {
                let id = ContextId::new(text(context, "contextId")?)
                    .map_err(|_| error("STALE_CONTEXT", "Context identity is invalid"))?;
                let live = self.current_context_with_deadline(
                    principal,
                    &id,
                    deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(10)),
                )?;
                if live != *context || live["projectId"] != project.as_str() {
                    return Err(error(
                        "STALE_CONTEXT",
                        "Current host context differs from authority request",
                    ));
                }
                Some((id, live))
            }
            None => None,
        };
        let state = self.state.lock().map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Current authority state is unavailable",
            )
        })?;
        let project_grant = grant(&state, principal, project)?;
        if let Some((id, context)) = &live {
            if !project_grant.contexts.contains(id)
                || !scope_contains(&project_grant.scope, &context["scope"])
            {
                return Err(error(
                    "PERMISSION_REQUIRED",
                    "Context exceeds current project authority",
                ));
            }
            // Observation/recovery use a current read grant. They do not reuse
            // the old write grant or require an obsolete invocation policy.
            if matches!(access, Access::Plan | Access::Apply)
                && context["policyRevision"] != project_grant.revision.as_str()
            {
                return Err(error(
                    "STALE_CONTEXT",
                    "Planning or dispatch policy has changed",
                ));
            }
        }
        if access == Access::Apply {
            let plan = plan.ok_or_else(|| {
                error(
                    "PERMISSION_REQUIRED",
                    "Apply requires an explicitly approved frozen plan",
                )
            })?;
            let hash = verify_projected_digest("ExecutionPlan", plan)
                .map_err(|_| error("STALE_PLAN", "Frozen plan digest is invalid"))?;
            let approval = state
                .approvals
                .get(&(principal.clone(), project.clone(), hash))
                .filter(|approval| {
                    Instant::now() < approval.expires && approval.policy == project_grant.revision
                })
                .ok_or_else(|| {
                    error(
                        "PERMISSION_REQUIRED",
                        "No current explicit approval exists for this plan hash",
                    )
                })?;
            if live
                .as_ref()
                .is_none_or(|(id, _)| !approval.contexts.contains(id))
                || plan["projectId"] != project.as_str()
                || plan["policyRevision"] != project_grant.revision.as_str()
                || !scope_contains(&project_grant.scope, &plan["scope"])
            {
                return Err(error(
                    "PERMISSION_REQUIRED",
                    "Apply exceeds its current explicit approval",
                ));
            }
        }
        Ok(())
    }
}
impl AuthorityPort for LocalAuthority {
    fn authorize(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectId,
        access: Access,
        context: Option<&Value>,
        plan: Option<&Value>,
    ) -> AppResult<()> {
        self.authorize_current(principal, project, access, context, plan)
    }
    fn authorize_operation(
        &mut self,
        principal: &PrincipalId,
        operation: &OperationRecord,
        access: Access,
    ) -> AppResult<()> {
        if principal != &operation.principal {
            return Err(error(
                "PERMISSION_REQUIRED",
                "Operation belongs to a different principal",
            ));
        }
        // Journal reports survive a host restart, but never a current scope
        // reduction. Cancel and recovery retain this complete operation ACL;
        // their actual native reads separately require the original host epoch.
        let scope = serde_json::to_value(&operation.scope)
            .map_err(|_| error("PERMISSION_REQUIRED", "Operation scope is invalid"))?;
        let state = self.state.lock().map_err(|_| {
            error(
                "AUTHORITY_UNAVAILABLE",
                "Current authority state is unavailable",
            )
        })?;
        let project_grant = grant(&state, principal, &operation.project_id)?;
        if !scope_contains(&project_grant.scope, &scope) {
            return Err(error(
                "PERMISSION_REQUIRED",
                "Operation exceeds current complete project scope",
            ));
        }
        drop(state);
        self.authorize_current(principal, &operation.project_id, access, None, None)
    }
}
impl ResourceAuthority for LocalAuthority {
    fn authorize_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: &ContextId,
        owner: &ResourceOwner,
        resource: &Value,
    ) -> ArtifactResult<()> {
        let live = self
            .current_context_with_deadline(
                principal,
                context,
                Instant::now() + Duration::from_secs(10),
            )
            .map_err(|_| ArtifactError::forbidden())?;
        let project = ProjectId::new(
            live["projectId"]
                .as_str()
                .ok_or_else(ArtifactError::forbidden)?,
        )
        .map_err(|_| ArtifactError::forbidden())?;
        match owner {
            ResourceOwner::Operation(id) => {
                let operation = store
                    .operation(id)
                    .map_err(|_| ArtifactError::forbidden())?;
                if operation.principal != *principal || operation.project_id != project {
                    return Err(ArtifactError::forbidden());
                }
                self.authorize_operation(principal, &operation, Access::ObserveOperation)
                    .map_err(|_| ArtifactError::forbidden())?;
                self.authorize_current(
                    principal,
                    &project,
                    Access::ObserveOperation,
                    Some(&live),
                    None,
                )
                .map_err(|_| ArtifactError::forbidden())?;
            }
            ResourceOwner::Project(id) => {
                if id != &project {
                    return Err(ArtifactError::forbidden());
                }
                self.authorize_current(principal, &project, Access::ReadProject, Some(&live), None)
                    .map_err(|_| ArtifactError::forbidden())?;
                if !live["scope"]["resourceIds"]
                    .as_array()
                    .is_some_and(|ids| ids.contains(&resource["resourceId"]))
                {
                    return Err(ArtifactError::forbidden());
                }
            }
            ResourceOwner::Principal(id) => {
                if id != principal {
                    return Err(ArtifactError::forbidden());
                }
                self.authorize_current(principal, &project, Access::ReadProject, Some(&live), None)
                    .map_err(|_| ArtifactError::forbidden())?;
            }
        }
        // Confirm the authoring project actually exists in this unique ledger.
        store
            .project(&project)
            .map_err(|_| ArtifactError::forbidden())?;
        Ok(())
    }
}

fn grant<'a>(
    state: &'a AuthorityState,
    principal: &PrincipalId,
    project: &ProjectId,
) -> AppResult<&'a ProjectGrant> {
    state
        .projects
        .get(&(principal.clone(), project.clone()))
        .filter(|g| g.active && Instant::now() < g.expires)
        .ok_or_else(|| {
            error(
                "PERMISSION_REQUIRED",
                "No current local project grant exists",
            )
        })
}
pub(crate) fn scope_contains(allowed: &Value, requested: &Value) -> bool {
    if allowed["projectId"] != requested["projectId"] {
        return false;
    }
    for key in ["resourceIds", "objectIds", "externalTargetIds"] {
        let (Some(allow), Some(request)) = (allowed[key].as_array(), requested[key].as_array())
        else {
            return false;
        };
        if request.iter().any(|id| !allow.contains(id)) {
            return false;
        }
    }
    let (Some(allowed_regions), Some(regions)) = (
        allowed["regions"].as_array(),
        requested["regions"].as_array(),
    ) else {
        return false;
    };
    regions.iter().all(|region| {
        allowed_regions.iter().any(|allowed| {
            allowed["contextId"] == region["contextId"]
                && allowed["worldId"] == region["worldId"]
                && allowed["dimension"] == region["dimension"]
                && (0..3).all(|axis| {
                    match (
                        allowed["min"][axis].as_i64(),
                        allowed["maxExclusive"][axis].as_i64(),
                        region["min"][axis].as_i64(),
                        region["maxExclusive"][axis].as_i64(),
                    ) {
                        (Some(min), Some(max), Some(request_min), Some(request_max)) => {
                            min <= request_min && request_min < request_max && request_max <= max
                        }
                        _ => false,
                    }
                })
        })
    })
}
fn text<'a>(value: &'a Value, key: &str) -> AppResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| error("INVALID_INPUT", "Required authority field is absent"))
}
fn validate(definition: &str, value: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .and_then(|v| v.validate(definition, value))
        .map_err(|_| {
            error(
                "INVALID_INPUT",
                "Authority value violates the canonical contract",
            )
        })
}
fn error(code: &'static str, message: &'static str) -> AppError {
    AppError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mmmm_contracts::{OperationId, PlanId};
    use mmmm_runtime::storage::{OperationState, WriteScope};

    fn scope(project: &ProjectId, resources: &[&str]) -> Value {
        json!({"projectId":project,"resourceIds":resources,"objectIds":[],"externalTargetIds":[],"regions":[]})
    }
    #[test]
    fn staged_pairing_grant_has_no_access_before_exact_terminal_activation() {
        let authority = LocalAuthority::new(HostBridge::default());
        let principal = PrincipalId::new("native-player").unwrap();
        let project = ProjectId::new("project-local").unwrap();
        let revision = authority
            .stage_project_access(
                principal.clone(),
                project.clone(),
                scope(&project, &[]),
                [ContextId::new("ctx-one").unwrap()].into(),
                Duration::from_secs(10),
            )
            .unwrap();
        authority
            .validate_staged_project(&principal, &project, &revision)
            .unwrap();
        assert!(authority.policy_revision(&principal, &project).is_err());
        assert!(
            authority
                .authorize_current(&principal, &project, Access::ReadProject, None, None)
                .is_err()
        );
        assert!(
            authority
                .current_context_ids(&principal)
                .unwrap()
                .is_empty()
        );
        let different = canonical_digest(&json!("another actual policy")).unwrap();
        assert!(
            authority
                .activate_staged_project(&principal, &project, &different)
                .is_err()
        );
        authority
            .activate_staged_project(&principal, &project, &revision)
            .unwrap();
        assert_eq!(
            authority.policy_revision(&principal, &project).unwrap(),
            revision
        );
        assert!(
            authority
                .activate_staged_project(&principal, &project, &revision)
                .is_err()
        );
    }
    #[test]
    fn journal_report_uses_current_full_scope_without_requiring_the_old_host() {
        let mut authority = LocalAuthority::new(HostBridge::default());
        let principal = PrincipalId::new("native-player").unwrap();
        let project = ProjectId::new("project-local").unwrap();
        authority
            .install_project_access(
                principal.clone(),
                project.clone(),
                scope(&project, &["resource-one"]),
                [ContextId::new("ctx-current").unwrap()].into(),
                Duration::from_secs(10),
            )
            .unwrap();
        let mut operation = OperationRecord {
            operation_id: OperationId::new("op-retained").unwrap(),
            principal: principal.clone(),
            project_id: project.clone(),
            idempotency_key: "request-once".into(),
            plan_id: PlanId::new("plan-retained").unwrap(),
            plan_hash: canonical_digest(&json!("actual frozen plan")).unwrap(),
            context_id: ContextId::new("ctx-old-unavailable").unwrap(),
            state: OperationState::OutcomeUnknown,
            cancellation_requested: false,
            reconciliation_required: true,
            scope: serde_json::from_value::<WriteScope>(scope(&project, &["resource-one"]))
                .unwrap(),
            whole_project_fence: false,
            steps: vec![],
        };
        authority
            .authorize_operation(&principal, &operation, Access::ObserveOperation)
            .unwrap();
        operation.scope =
            serde_json::from_value(scope(&project, &["resource-one", "resource-two"])).unwrap();
        for access in [Access::ObserveOperation, Access::Cancel, Access::Recovery] {
            assert!(
                authority
                    .authorize_operation(&principal, &operation, access)
                    .is_err()
            );
        }
    }
    #[test]
    fn retained_scope_cannot_mix_project_context_policy_or_expired_grant() {
        let authority = LocalAuthority::new(HostBridge::default());
        let principal = PrincipalId::new("native-player").unwrap();
        let project = ProjectId::new("project-first").unwrap();
        let other_project = ProjectId::new("project-second").unwrap();
        let context = ContextId::new("ctx-first").unwrap();
        let other_context = ContextId::new("ctx-second").unwrap();
        let policy = authority
            .install_project_access(
                principal.clone(),
                project.clone(),
                scope(&project, &["resource-first"]),
                [context.clone()].into(),
                Duration::from_secs(10),
            )
            .unwrap();
        let other_policy = authority
            .install_project_access(
                principal.clone(),
                other_project.clone(),
                scope(&other_project, &["resource-second"]),
                [other_context.clone()].into(),
                Duration::from_secs(10),
            )
            .unwrap();
        assert_eq!(
            authority.project_context_ids(&principal, &project).unwrap(),
            BTreeSet::from([context.clone()])
        );
        authority
            .authorize_retained_scope(
                &principal,
                &project,
                &context,
                &policy,
                &scope(&project, &[]),
            )
            .unwrap();
        assert!(
            authority
                .authorize_retained_scope(
                    &principal,
                    &project,
                    &other_context,
                    &policy,
                    &scope(&project, &[])
                )
                .is_err()
        );
        assert!(
            authority
                .authorize_retained_scope(
                    &principal,
                    &project,
                    &context,
                    &other_policy,
                    &scope(&project, &[])
                )
                .is_err()
        );
        assert!(
            authority
                .authorize_retained_scope(
                    &principal,
                    &project,
                    &context,
                    &policy,
                    &scope(&project, &["resource-second"])
                )
                .is_err()
        );
        authority
            .state
            .lock()
            .unwrap()
            .projects
            .get_mut(&(principal.clone(), project.clone()))
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        assert!(authority.project_context_ids(&principal, &project).is_err());
        assert!(
            authority
                .authorize_retained_scope(
                    &principal,
                    &project,
                    &context,
                    &policy,
                    &scope(&project, &[])
                )
                .is_err()
        );
    }
    #[test]
    fn private_offline_context_still_requires_current_exact_project_grant() {
        struct FixedWorkspace(Value);
        impl WorkspaceContextResolver for FixedWorkspace {
            fn resolve_workspace(
                &self,
                principal: &PrincipalId,
                id: &ContextId,
                deadline: Instant,
            ) -> AppResult<Option<Value>> {
                if Instant::now() >= deadline
                    || self.0["principalRef"] != principal.as_str()
                    || self.0["contextId"] != id.as_str()
                {
                    return Err(error("STALE_CONTEXT", "Workspace locator is stale"));
                }
                Ok(Some(self.0.clone()))
            }
        }
        let authority = LocalAuthority::new(HostBridge::default());
        let principal = PrincipalId::new("native-owner").unwrap();
        let project = ProjectId::new("project-workspace").unwrap();
        let id = ContextId::new("context-workspace").unwrap();
        let policy = authority
            .install_project_access(
                principal.clone(),
                project.clone(),
                scope(&project, &[]),
                [id.clone()].into(),
                Duration::from_secs(10),
            )
            .unwrap();
        let mut context = json!({"contractVersion":mmmm_contracts::CONTRACT_VERSION,"contextId":id,"principalRef":principal,"projectId":project,
            "environment":{"kind":"offline","workspaceId":"native-workspace","side":"offline"},"policyRevision":policy,"scope":scope(&project,&[]),"contextDigest":"0".repeat(64)});
        context["contextDigest"] =
            json!(mmmm_contracts::projected_digest("ExecutionContext", &context).unwrap());
        authority
            .install_workspace_resolver(Rc::new(FixedWorkspace(context.clone())))
            .unwrap();
        authority
            .authorize_with_deadline(
                &principal,
                &project,
                Access::Plan,
                Some(&context),
                None,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert!(
            authority
                .authorize_with_deadline(
                    &principal,
                    &project,
                    Access::Apply,
                    Some(&context),
                    None,
                    Instant::now() + Duration::from_secs(1)
                )
                .is_err()
        );
        assert!(
            authority
                .current_context_with_deadline(
                    &principal,
                    &id,
                    Instant::now() - Duration::from_secs(1)
                )
                .is_err()
        );
        authority.revoke_project(&principal, &project).unwrap();
        assert!(
            authority
                .authorize_with_deadline(
                    &principal,
                    &project,
                    Access::ReadProject,
                    Some(&context),
                    None,
                    Instant::now() + Duration::from_secs(1)
                )
                .is_err()
        );
    }
}

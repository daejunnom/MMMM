//! Native peer의 실제 연결 자료를 단일 Coordinator 원장 아래에서 처리한다.
//! 공개 설정/offer는 기존 승인을 찾는 자료이며 별도 권한 생성 API가 아니다.

use crate::{
    auth::SessionPolicy,
    authority::LocalAuthority,
    client::HostRpcClient,
    credential::{SecretToken, local_owner_principal},
    endpoint::EndpointRecord,
    host::{HostBridge, HostRouteOwner},
    peer_management::{
        BootstrapBudget, BootstrapWitness, CompletedBootstrap, HostOffer, ManagementError,
        ManagementKind, ManagementRequest, PublicFrame,
    },
    setup::PublicHostSetup,
};
use mmmm_contracts::{
    ContextId, ContractValidator, PrincipalId, ProjectId, RequestId, SessionEpoch, Sha256Digest,
    canonical_digest, projected_digest,
};
use mmmm_runtime::storage::{
    DurableStore, StorageError, StorageResult, WriteScope,
    host_setup::{
        HostReadPolicy, HostReadPolicyRecord, HostSetupAuthority, HostSetupRecord,
        HostSetupRegistration, HostSetupRpcContext, host_setup, register_host_setup,
        register_host_setup_with_read_policy,
    },
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

const SESSION_LIFETIME: Duration = Duration::from_secs(60 * 60);
const MAX_PENDING: usize = 8;
const MAX_REJECTED_COMPLETIONS: usize = 8;
const MAX_REJECTED_ENCODED_BYTES: usize = 8 * 1024 * 1024;
const COMPLETION_METADATA_BYTES: usize = 1024;
const NATIVE_SOURCE_ID: &str = "mmmm_host";
const READ_PERMISSIONS: [&str; 3] = [
    "mmmm:world_read",
    "mmmm:command_complete",
    "mmmm:provider_inventory",
];

/// 현재 OS 소유자와 이미 보호되어 잠긴 원장으로만 만든다. 공개 JSON에서
/// deserialize하거나 principal 문자열을 주입하는 생성자는 제공하지 않는다.
pub struct OwnerSetupRpcContext {
    owner: PrincipalId,
    data_root: PathBuf,
    deadline: Instant,
    budget: Option<BootstrapBudget>,
}
impl OwnerSetupRpcContext {
    fn for_store(store: &DurableStore, budget: Option<&BootstrapBudget>) -> StorageResult<Self> {
        let deadline = budget
            .map(BootstrapBudget::deadline)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(10));
        Self::capture(store, deadline, budget.cloned())
    }
    fn capture(
        store: &DurableStore,
        deadline: Instant,
        budget: Option<BootstrapBudget>,
    ) -> StorageResult<Self> {
        let owner = local_owner_principal().map_err(|_| owner_error())?;
        let context = Self {
            owner,
            data_root: store.data_root().to_path_buf(),
            deadline,
            budget,
        };
        context.check()?;
        Ok(context)
    }
    fn check_store(&self, store: &DurableStore) -> StorageResult<()> {
        self.check()?;
        if store.data_root() != self.data_root {
            return Err(StorageError::Conflict("Authenticated setup data root"));
        }
        Ok(())
    }
}
impl HostSetupRpcContext for OwnerSetupRpcContext {
    fn check(&self) -> StorageResult<()> {
        if Instant::now() >= self.deadline || crate::peer::fatal_stop_requested() {
            return Err(owner_error());
        }
        if let Some(budget) = &self.budget {
            budget.check().map_err(|_| owner_error())?;
        }
        if local_owner_principal().map_err(|_| owner_error())? != self.owner {
            return Err(owner_error());
        }
        Ok(())
    }
    fn authenticated_local_owner(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.owner.clone())
    }
}

/// 등록 허용 증인은 실제 파일을 선택한 explicit CLI setup 경로에서만 만든다.
/// 페어링 처리기는 read-only 형태를 사용하여 registry를 새로 만들지 않는다.
struct OwnerSetupAuthority {
    owner: PrincipalId,
    data_root: PathBuf,
    registration: Option<HostSetupRegistration>,
    selected_read_policy: Option<HostReadPolicy>,
}
impl OwnerSetupAuthority {
    fn for_read(rpc: &OwnerSetupRpcContext) -> Self {
        Self {
            owner: rpc.owner.clone(),
            data_root: rpc.data_root.clone(),
            registration: None,
            selected_read_policy: None,
        }
    }
    fn check_current(
        &self,
        store: &DurableStore,
        principal: &PrincipalId,
        project: &ProjectId,
    ) -> StorageResult<()> {
        if principal != &self.owner
            || local_owner_principal().map_err(|_| owner_error())? != self.owner
            || store.data_root() != self.data_root
            || crate::peer::fatal_stop_requested()
        {
            return Err(owner_error());
        }
        // The protected single local ledger is the owner ACL boundary. A
        // project locator must still identify actual canonical retained bytes.
        store.project(project)?;
        Ok(())
    }
}
impl HostSetupAuthority for OwnerSetupAuthority {
    fn authorize_registration(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        request: &HostSetupRegistration,
    ) -> StorageResult<()> {
        self.check_current(store, principal, &request.project_id)?;
        let approved = self.registration.as_ref().ok_or(owner_error())?;
        if approved.project_id != request.project_id
            || approved.host_artifact_digest != request.host_artifact_digest
            || approved.approved_scope != request.approved_scope
        {
            return Err(owner_error());
        }
        Ok(())
    }
    fn authorize_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        record: &HostSetupRecord,
    ) -> StorageResult<()> {
        self.check_current(store, principal, &record.project_id)?;
        if record.principal != *principal {
            return Err(owner_error());
        }
        Ok(())
    }
    fn authorize_read_policy_registration(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        request: &HostSetupRegistration,
        policy: &HostReadPolicy,
    ) -> StorageResult<()> {
        self.authorize_registration(store, principal, request)?;
        if self.selected_read_policy.as_ref() != Some(policy)
            || mmmm_runtime::storage::bootstrap::registered_native_project_owner(
                store,
                &request.project_id,
            )? != *principal
        {
            return Err(owner_error());
        }
        self.check_current(store, principal, &request.project_id)
    }
    // The setup writer never serves policy reads to a paired request. That
    // consumer supplies its actual current owner/route/request adapter instead.
}

/// Explicitly invoked local CLI setup computes actual ordinary executable/JAR
/// hashes before retaining the finite immutable approval in this unique Store.
/// This does not create a game grant, policy revision, token or new project.
pub fn register_explicit_host_setup(
    store: &mut DurableStore,
    executable: &Path,
    installed_host_jar: &Path,
    project: ProjectId,
    scope: Value,
) -> StorageResult<PublicHostSetup> {
    let rpc = OwnerSetupRpcContext::for_store(store, None)?;
    rpc.check_store(store)?;
    store.project(&project)?;
    let setup = PublicHostSetup::create(
        executable,
        installed_host_jar,
        store.data_root(),
        project,
        scope,
    )
    .map_err(|_| StorageError::InvalidInput("Explicit host setup verification failed".into()))?;
    rpc.check()?;
    let registration = HostSetupRegistration {
        project_id: setup.project_id.clone(),
        host_artifact_digest: setup.host_artifact_digest.clone(),
        approved_scope: serde_json::from_value(setup.scope.clone())
            .map_err(|_| StorageError::InvalidInput("Host setup scope is invalid".into()))?,
    };
    let mut authority = OwnerSetupAuthority::for_read(&rpc);
    authority.registration = Some(registration.clone());
    register_host_setup(store, &rpc, &mut authority, &registration)?;
    Ok(setup)
}

/// Explicit native selection only. Its original caller deadline survives file
/// verification, registration and every transaction checkpoint. The returned
/// policy is a confirmed durable receipt, not an observation/source capability.
pub(crate) fn register_explicit_host_setup_with_read_policy(
    store: &mut DurableStore,
    executable: &Path,
    installed_host_jar: &Path,
    project: ProjectId,
    scope: Value,
    policy: &HostReadPolicy,
    deadline: Instant,
) -> StorageResult<(PublicHostSetup, HostReadPolicyRecord)> {
    let rpc = OwnerSetupRpcContext::capture(store, deadline, None)?;
    rpc.check_store(store)?;
    if mmmm_runtime::storage::bootstrap::registered_native_project_owner(store, &project)?
        != rpc.owner
    {
        return Err(owner_error());
    }
    store.project(&project)?;
    let setup = PublicHostSetup::create(
        executable,
        installed_host_jar,
        store.data_root(),
        project,
        scope,
    )
    .map_err(|_| StorageError::InvalidInput("Explicit host setup verification failed".into()))?;
    rpc.check_store(store)?;
    let request = HostSetupRegistration {
        project_id: setup.project_id.clone(),
        host_artifact_digest: setup.host_artifact_digest.clone(),
        approved_scope: serde_json::from_value(setup.scope.clone())
            .map_err(|_| StorageError::InvalidInput("Host setup scope is invalid".into()))?,
    };
    let mut authority = OwnerSetupAuthority::for_read(&rpc);
    authority.registration = Some(request.clone());
    authority.selected_read_policy = Some(policy.clone());
    let (_, retained) =
        register_host_setup_with_read_policy(store, &rpc, &mut authority, &request, policy)?;
    // Do not discard this receipt by performing a fallible post-commit check.
    // The local wrapper retains it around all remaining owner/output checks.
    Ok((setup, retained))
}

struct PendingBootstrap {
    original_offer: Arc<PublicFrame>,
    witness: BootstrapWitness,
    budget: BootstrapBudget,
    principal: PrincipalId,
    project: ProjectId,
    context_id: ContextId,
    policy: Sha256Digest,
    context: Value,
    hello: Value,
    token: Option<SecretToken>,
    route_owner: Option<HostRouteOwner>,
    complete_issued: bool,
    completion: Option<Arc<CompletedBootstrap>>,
    rollback_observation: RollbackObservation,
    publication_failure: Option<Arc<mmmm_application::AppError>>,
    first_rollback_failure: Option<Arc<mmmm_application::AppError>>,
    retained_encoded_bytes: usize,
    lease_expires: Instant,
}

#[derive(Clone, Copy)]
enum RollbackObservation {
    NotAttempted,
    Uncertain {
        first_failure: ManagementError,
    },
    Completed {
        prior_failure: Option<ManagementError>,
    },
}
struct RejectedPairingCompletion {
    // Retention only: these records are never looked up by a source witness.
    // Explicit diagnostic/export policy owns their later lifecycle. The
    // aggregate encoded-data budget is distinct from a process RSS guarantee.
    _observation: Arc<CompletedPairingObservation>,
    _rollback: RollbackObservation,
    _publication_failure: Option<Arc<mmmm_application::AppError>>,
    _first_rollback_failure: Option<Arc<mmmm_application::AppError>>,
}

/// A factual native delivery observation. Only `finish` constructs it from
/// the original bounded offer and opaque ACK/EOF receipt. It grants no source
/// rights, game mode, target readiness or permission. No Debug/serde surface
/// exposes the original offer's local path, nonce or private pairing details.
pub(crate) struct CompletedPairingObservation {
    original_offer: Arc<PublicFrame>,
    completion: Arc<CompletedBootstrap>,
    native_owner: PrincipalId,
    principal: PrincipalId,
    project: ProjectId,
    context: Value,
    policy: Sha256Digest,
    original_deadline: Instant,
    lease_expires: Instant,
}
impl CompletedPairingObservation {
    fn from_pending(
        pending: &PendingBootstrap,
        completion: Arc<CompletedBootstrap>,
        native_owner: &PrincipalId,
    ) -> Self {
        Self {
            original_offer: pending.original_offer.clone(),
            completion,
            native_owner: native_owner.clone(),
            principal: pending.principal.clone(),
            project: pending.project.clone(),
            context: pending.context.clone(),
            policy: pending.policy.clone(),
            original_deadline: pending.budget.deadline(),
            lease_expires: pending.lease_expires,
        }
    }
    pub(crate) fn principal(&self) -> &PrincipalId {
        &self.principal
    }
    pub(crate) fn project(&self) -> &ProjectId {
        &self.project
    }
    pub(crate) fn context(&self) -> &Value {
        &self.context
    }
    pub(crate) fn policy(&self) -> &Sha256Digest {
        &self.policy
    }
    pub(crate) fn native_owner(&self) -> &PrincipalId {
        &self.native_owner
    }
    pub(crate) fn completed_at(&self) -> Instant {
        self.completion.completed_at()
    }
    pub(crate) fn original_deadline(&self) -> Instant {
        self.original_deadline
    }
    pub(crate) fn lease_expires(&self) -> Instant {
        self.lease_expires
    }
    pub(crate) fn offer_digest(&self) -> &Sha256Digest {
        self.completion.witness().offer_digest()
    }
    pub(crate) fn original_offer(&self) -> &Value {
        self.original_offer.value()
    }
    pub(crate) fn check_delivery(&self) -> bool {
        self.completion.delivered()
            && self.completed_at() < self.original_deadline
            && Instant::now() < self.lease_expires
    }
}
struct ActiveBootstrap {
    principal: PrincipalId,
    project: ProjectId,
    policy: Sha256Digest,
    context_id: ContextId,
    route_owner: Option<HostRouteOwner>,
    expires: Instant,
}

pub(crate) mod workspace_seal {
    pub trait Sealed {}
}
/// Only this crate's captured kernel-owner witness implements the sealed port.
/// Public setup values and PrincipalId strings cannot install a workspace.
pub trait NativeWorkspacePermit: workspace_seal::Sealed {
    fn check_project(
        &self,
        store: &DurableStore,
        project: &ProjectId,
    ) -> StorageResult<PrincipalId>;
}
struct OwnerWorkspace {
    context: Value,
    ownership: ActiveBootstrap,
}

/// Main-loop owned. Neither the native I/O worker nor public facade requests
/// obtain this object, the mutable Store, or the authority installation methods.
pub struct HostBootstrapProcessor {
    owner: PrincipalId,
    hosts: HostBridge,
    authority: LocalAuthority,
    pending: BTreeMap<RequestId, PendingBootstrap>,
    active: BTreeMap<ContextId, ActiveBootstrap>,
    workspace: BTreeMap<ContextId, OwnerWorkspace>,
    rejected_completions: BTreeMap<RequestId, RejectedPairingCompletion>,
    rejected_encoded_bytes: usize,
}
impl HostBootstrapProcessor {
    pub fn new(hosts: HostBridge, authority: LocalAuthority) -> Result<Self, ManagementError> {
        Ok(Self {
            owner: local_owner_principal().map_err(|_| ManagementError::InvalidFrame)?,
            hosts,
            authority,
            pending: BTreeMap::new(),
            active: BTreeMap::new(),
            workspace: BTreeMap::new(),
            rejected_completions: BTreeMap::new(),
            rejected_encoded_bytes: 0,
        })
    }
    /// Trusted composition has independently verified this Project's current
    /// sources and installed a read-only grant before publishing any endpoint.
    /// This method records only its exact already-granted immutable context.
    pub fn install_workspace_context(
        &mut self,
        permit: &dyn NativeWorkspacePermit,
        store: &DurableStore,
        context: &Value,
    ) -> Result<(), ManagementError> {
        ContractValidator::shared()
            .and_then(|v| v.validate("ExecutionContext", context))
            .map_err(|_| ManagementError::InvalidFrame)?;
        mmmm_contracts::verify_projected_digest("ExecutionContext", context)
            .map_err(|_| ManagementError::InvalidFrame)?;
        let project = ProjectId::new(text(context, "projectId")?)
            .map_err(|_| ManagementError::InvalidFrame)?;
        let owner = permit
            .check_project(store, &project)
            .map_err(|_| ManagementError::InvalidFrame)?;
        let id = ContextId::new(text(context, "contextId")?)
            .map_err(|_| ManagementError::InvalidFrame)?;
        let policy = Sha256Digest::new(text(context, "policyRevision")?)
            .map_err(|_| ManagementError::InvalidFrame)?;
        if owner != self.owner
            || context["principalRef"] != owner.as_str()
            || context["environment"]["kind"] != "offline"
            || context["scope"]["projectId"] != project.as_str()
            || !context["scope"]["regions"]
                .as_array()
                .is_some_and(Vec::is_empty)
            || !context["scope"]["externalTargetIds"]
                .as_array()
                .is_some_and(Vec::is_empty)
            || self.workspace.len() >= 64
            || self.workspace.contains_key(&id)
        {
            return Err(ManagementError::InvalidFrame);
        }
        self.authority
            .authorize_retained_scope(&owner, &project, &id, &policy, &context["scope"])
            .map_err(|_| ManagementError::InvalidFrame)?;
        permit
            .check_project(store, &project)
            .map_err(|_| ManagementError::InvalidFrame)?;
        self.workspace.insert(
            id.clone(),
            OwnerWorkspace {
                context: context.clone(),
                ownership: ActiveBootstrap {
                    principal: owner,
                    project,
                    policy,
                    context_id: id,
                    route_owner: None,
                    expires: Instant::now() + Duration::from_secs(1800),
                },
            },
        );
        Ok(())
    }
    /// The envelope's native budget must be passed unchanged by composition.
    /// Finished is consumed even when that budget has expired or been cancelled.
    pub fn handle_with_budget(
        &mut self,
        store: &mut DurableStore,
        request: ManagementRequest,
        coordinator_epoch: &SessionEpoch,
        budget: &BootstrapBudget,
    ) -> Result<Option<PublicFrame>, ManagementError> {
        self.handle_with_reply_deadline(
            store,
            request,
            coordinator_epoch,
            budget,
            budget
                .deadline()
                .min(Instant::now() + Duration::from_secs(10)),
        )
    }
    /// Production composition passes ManagementResponder::deadline(), whose
    /// enqueue-time bound includes time already spent waiting for the main loop.
    pub fn handle_with_reply_deadline(
        &mut self,
        store: &mut DurableStore,
        request: ManagementRequest,
        coordinator_epoch: &SessionEpoch,
        budget: &BootstrapBudget,
        reply_deadline: Instant,
    ) -> Result<Option<PublicFrame>, ManagementError> {
        match request {
            ManagementRequest::Finished(receipt) => {
                self.finish(receipt)?;
                Ok(None)
            }
            ManagementRequest::Offer(offer) => {
                self.cleanup_expired()?;
                budget.check()?;
                if Instant::now() >= reply_deadline {
                    return Err(ManagementError::Deadline);
                }
                self.offer(store, offer, budget).map(Some)
            }
            ManagementRequest::Installed { public, witness } => self
                .installed(
                    store,
                    public,
                    witness,
                    coordinator_epoch,
                    budget,
                    reply_deadline,
                )
                .map(Some),
        }
    }
    pub fn handle(
        &mut self,
        store: &mut DurableStore,
        request: ManagementRequest,
        coordinator_epoch: &SessionEpoch,
    ) -> Result<Option<PublicFrame>, ManagementError> {
        self.handle_with_budget(store, request, coordinator_epoch, &BootstrapBudget::new())
    }
    pub fn current_session_policy(&self) -> Result<SessionPolicy, ManagementError> {
        if local_owner_principal().map_err(|_| ManagementError::InvalidFrame)? != self.owner {
            return Err(ManagementError::InvalidFrame);
        }
        let now = Instant::now();
        let current = self.active.values().filter(|active| now < active.expires);
        let mut principal = None;
        let mut contexts = BTreeSet::new();
        let mut lifetime = SESSION_LIFETIME;
        for active in current {
            if self
                .authority
                .policy_revision(&active.principal, &active.project)
                .ok()
                .as_ref()
                != Some(&active.policy)
            {
                continue;
            }
            if principal.as_ref().is_some_and(|id| id != &active.principal) {
                return Err(ManagementError::WrongReply);
            }
            principal = Some(active.principal.clone());
            contexts.insert(active.context_id.clone());
            lifetime = lifetime.min(active.expires.saturating_duration_since(now));
        }
        let selected = principal.clone().unwrap_or_else(|| self.owner.clone());
        for workspace in self.workspace.values() {
            let owned = &workspace.ownership;
            if owned.principal == selected
                && now < owned.expires
                && self
                    .authority
                    .authorize_retained_scope(
                        &owned.principal,
                        &owned.project,
                        &owned.context_id,
                        &owned.policy,
                        &workspace.context["scope"],
                    )
                    .is_ok()
            {
                contexts.insert(owned.context_id.clone());
                lifetime = lifetime.min(owned.expires.saturating_duration_since(now));
            }
        }
        let methods = ContractValidator::shared()
            .map_err(|_| ManagementError::InvalidFrame)?
            .functions()
            .iter()
            .map(|function| function.name.clone())
            .collect();
        Ok(SessionPolicy {
            principal: selected,
            allowed_methods: methods,
            allowed_contexts: contexts,
            lifetime,
        })
    }
    fn offer(
        &mut self,
        store: &DurableStore,
        offer: HostOffer,
        budget: &BootstrapBudget,
    ) -> Result<PublicFrame, ManagementError> {
        if self.pending.len() >= MAX_PENDING {
            return Err(ManagementError::Busy);
        }
        let (public, token, witness) = offer.into_parts();
        let offer_bytes = public.encode()?.payload().len();
        let retained_encoded_bytes = offer_bytes
            .checked_add(COMPLETION_METADATA_BYTES)
            .ok_or(ManagementError::FrameTooLarge)?;
        let public = Arc::new(public);
        let value = public.value();
        if Path::new(text(value, "dataRoot")?) != store.data_root()
            || canonical_digest(value).map_err(|_| ManagementError::InvalidFrame)?
                != *witness.offer_digest()
            || self.pending.contains_key(witness.id())
        {
            return Err(ManagementError::WrongReply);
        }
        let rpc = OwnerSetupRpcContext::for_store(store, Some(budget))
            .map_err(|_| ManagementError::InvalidFrame)?;
        if rpc.owner != self.owner {
            return Err(ManagementError::InvalidFrame);
        }
        let principal = PrincipalId::new(text(value, "principalId")?)
            .map_err(|_| ManagementError::InvalidFrame)?;
        let now = Instant::now();
        if self
            .active
            .values()
            .any(|active| now < active.expires && active.principal != principal)
            || self
                .pending
                .values()
                .any(|pending| pending.principal != principal)
        {
            // One native CLI capability cannot silently become another game
            // player's principal while the old generation remains current.
            return Err(ManagementError::Busy);
        }
        let project =
            ProjectId::new(text(value, "projectId")?).map_err(|_| ManagementError::InvalidFrame)?;
        let artifact = Sha256Digest::new(text(value, "hostArtifactDigest")?)
            .map_err(|_| ManagementError::InvalidFrame)?;
        let scope: WriteScope = serde_json::from_value(value["scope"].clone())
            .map_err(|_| ManagementError::InvalidFrame)?;
        let mut setup_authority = OwnerSetupAuthority::for_read(&rpc);
        host_setup(
            store,
            &rpc,
            &mut setup_authority,
            &project,
            &artifact,
            Some(&scope),
        )
        .map_err(|_| ManagementError::InvalidFrame)?;
        validate_live_offer(value, &artifact)?;
        let context_id = new_context_id()?;
        let scope = rebound_scope(scope, &context_id, &value["hostHello"]["environment"])?;
        let policy = self
            .authority
            .stage_project_access(
                principal.clone(),
                project.clone(),
                scope.clone(),
                BTreeSet::from([context_id.clone()]),
                SESSION_LIFETIME,
            )
            .map_err(|_| ManagementError::Busy)?;
        let mut pending = PendingBootstrap {
            original_offer: public.clone(),
            witness,
            budget: budget.clone(),
            principal,
            project,
            context_id,
            policy,
            context: Value::Null,
            hello: value["hostHello"].clone(),
            token: Some(token),
            route_owner: None,
            complete_issued: false,
            completion: None,
            rollback_observation: RollbackObservation::NotAttempted,
            publication_failure: None,
            first_rollback_failure: None,
            retained_encoded_bytes,
            lease_expires: now + SESSION_LIFETIME,
        };
        let prepared = (|| {
            let value = pending.original_offer.value();
            pending.context = build_context(value, &pending, scope)?;
            pending.retained_encoded_bytes = pending
                .retained_encoded_bytes
                .checked_add(
                    mmmm_contracts::encode_json(&pending.context)
                        .map_err(|_| ManagementError::FrameTooLarge)?
                        .len(),
                )
                .filter(|bytes| *bytes <= MAX_REJECTED_ENCODED_BYTES)
                .ok_or(ManagementError::FrameTooLarge)?;
            let actions = value["nativeActions"]
                .as_array()
                .ok_or(ManagementError::InvalidFrame)?
                .iter()
                .map(|action| canonical_digest(action).map_err(|_| ManagementError::InvalidFrame))
                .collect::<Result<Vec<_>, _>>()?;
            let reply = PublicFrame::from_value(json!({
                "kind":"host_pairing_authority", "protocolVersion":mmmm_contracts::CONTRACT_VERSION,
                "nonce":pending.witness.nonce(), "contexts":[pending.context],
                "approvedSources":{(NATIVE_SOURCE_ID):artifact}, "approvedActions":actions,
                "permissions":READ_PERMISSIONS, "writeProfileVerified":false,
            }))?;
            budget.check()?;
            Ok(reply)
        })();
        match prepared {
            Ok(reply) => {
                self.pending.insert(pending.witness.id().clone(), pending);
                Ok(reply)
            }
            Err(error) => {
                if self.rollback(&pending).is_err() {
                    self.pending.insert(pending.witness.id().clone(), pending);
                    return Err(ManagementError::TransportUncertain);
                }
                Err(error)
            }
        }
    }
    fn installed(
        &mut self,
        store: &DurableStore,
        public: PublicFrame,
        witness: BootstrapWitness,
        coordinator_epoch: &SessionEpoch,
        budget: &BootstrapBudget,
        reply_deadline: Instant,
    ) -> Result<PublicFrame, ManagementError> {
        let mut pending = self
            .pending
            .remove(witness.id())
            .ok_or(ManagementError::WrongReply)?;
        if !same_witness(&pending.witness, &witness) {
            self.pending.insert(pending.witness.id().clone(), pending);
            return Err(ManagementError::WrongReply);
        }
        let result = (|| {
            budget.check()?;
            pending.budget.check()?;
            let deadline = budget
                .deadline()
                .min(pending.budget.deadline())
                .min(reply_deadline);
            if Instant::now() >= deadline {
                return Err(ManagementError::Deadline);
            }
            if public.kind() != ManagementKind::Installed
                || public.nonce() != pending.witness.nonce()
                || pending.complete_issued
            {
                return Err(ManagementError::WrongReply);
            }
            let rpc = OwnerSetupRpcContext::for_store(store, Some(&pending.budget))
                .map_err(|_| ManagementError::InvalidFrame)?;
            rpc.check_store(store)
                .map_err(|_| ManagementError::InvalidFrame)?;
            store
                .project(&pending.project)
                .map_err(|_| ManagementError::InvalidFrame)?;
            self.authority
                .validate_staged_project(&pending.principal, &pending.project, &pending.policy)
                .map_err(|_| ManagementError::WrongReply)?;
            let endpoint = &public.value()["hostEndpoint"];
            let epoch = text(endpoint, "hostEpoch")?;
            if pending.hello["environment"]["sessionEpoch"] != epoch {
                return Err(ManagementError::WrongReply);
            }
            let address: SocketAddr = text(endpoint, "address")?
                .parse()
                .map_err(|_| ManagementError::InvalidFrame)?;
            let record = EndpointRecord {
                schema_version: 1,
                contract_version: mmmm_contracts::CONTRACT_VERSION.into(),
                address,
                path: text(endpoint, "path")?.into(),
                coordinator_epoch: epoch.into(),
                // Internal token-bearing client needs a valid public lookup
                // name; no native credential is created by host attachment.
                credential_ref: format!("MMMM.coordinator.host-{}", pending.witness.id()),
            };
            let token = pending.token.take().ok_or(ManagementError::WrongReply)?;
            let client =
                HostRpcClient::paired(record, token).map_err(|_| ManagementError::InvalidFrame)?;
            let lease = pending
                .lease_expires
                .saturating_duration_since(Instant::now());
            let route_owner = self
                .hosts
                .attach_owned_with_deadline(
                    client,
                    pending.principal.clone(),
                    pending.context.clone(),
                    pending.hello.clone(),
                    lease,
                    deadline,
                )
                .map_err(|_| ManagementError::Disconnected)?;
            pending.route_owner = Some(route_owner);
            // Actual independent HostHello and ExecutionContext were checked
            // by attach; only after those calls can Complete be issued.
            budget.check()?;
            pending.budget.check()?;
            if Instant::now() >= deadline {
                return Err(ManagementError::Deadline);
            }
            let complete = PublicFrame::from_value(json!({
                "kind":"host_pairing_complete", "protocolVersion":mmmm_contracts::CONTRACT_VERSION,
                "nonce":pending.witness.nonce(), "ready":true,
                "coordinatorEpoch":coordinator_epoch, "hostEpoch":epoch,
                "contextId":pending.context_id,
            }))?;
            pending.complete_issued = true;
            Ok(complete)
        })();
        match result {
            Ok(reply) => {
                self.pending.insert(pending.witness.id().clone(), pending);
                Ok(reply)
            }
            Err(error) => {
                if self.rollback(&pending).is_err() {
                    self.pending.insert(pending.witness.id().clone(), pending);
                    return Err(ManagementError::TransportUncertain);
                }
                Err(error)
            }
        }
    }
    /// This receipt has no wire constructor. The native worker supplies true
    /// only after Complete write, terminal ACK and EOF/disconnect have drained.
    pub fn finish(&mut self, receipt: CompletedBootstrap) -> Result<(), ManagementError> {
        let Some(mut pending) = self.pending.remove(receipt.witness().id()) else {
            // A late failure after exact expiry cleanup cannot retire any new
            // context or grant. A duplicated receipt never activates a session.
            return Ok(());
        };
        if !same_witness(&pending.witness, receipt.witness()) {
            self.pending.insert(pending.witness.id().clone(), pending);
            return Err(ManagementError::WrongReply);
        }
        // Preserve the actual opaque delivery truth before attempting current
        // grant/route publication. An uncertain rollback retains this same
        // receipt; a retry cannot replace its observed timestamp or outcome.
        if let Some(observed) = &pending.completion {
            if observed.completed_at() != receipt.completed_at()
                || observed.delivered() != receipt.delivered()
            {
                self.pending.insert(pending.witness.id().clone(), pending);
                return Err(ManagementError::WrongReply);
            }
        } else {
            pending.completion = Some(Arc::new(receipt));
        }
        let receipt = pending
            .completion
            .as_ref()
            .ok_or(ManagementError::WrongReply)?;
        if !matches!(
            pending.rollback_observation,
            RollbackObservation::NotAttempted
        ) {
            let delivered = receipt.delivered();
            self.rollback_and_retain_completion(pending)?;
            return if delivered {
                Err(ManagementError::WrongReply)
            } else {
                Ok(())
            };
        }
        if receipt.delivered()
            && pending.complete_issued
            && pending.route_owner.is_some()
            && receipt.completed_at() < pending.budget.deadline()
            && Instant::now() < pending.lease_expires
            && !crate::peer::fatal_stop_requested()
            && local_owner_principal().ok().as_ref() == Some(&self.owner)
        {
            // The private native completion timestamp proves delivery occurred
            // before the original deadline. Main-loop scheduling delay does
            // not rewrite that observation into a timeout or a new deadline.
            let published = (|| {
                self.authority.activate_staged_project(
                    &pending.principal,
                    &pending.project,
                    &pending.policy,
                )?;
                let observation = Arc::new(CompletedPairingObservation::from_pending(
                    &pending,
                    receipt.clone(),
                    &self.owner,
                ));
                self.hosts.record_completed_pairing(
                    pending.route_owner.as_ref().ok_or_else(|| {
                        mmmm_application::AppError::new(
                            "STALE_CONTEXT",
                            "Original native route is unavailable",
                        )
                    })?,
                    observation,
                    &self.authority,
                )
            })();
            if let Err(cause) = published {
                pending.publication_failure = Some(Arc::new(cause));
                self.rollback_and_retain_completion(pending)?;
                return Err(ManagementError::WrongReply);
            }
            self.active.insert(
                pending.context_id.clone(),
                ActiveBootstrap {
                    principal: pending.principal,
                    project: pending.project,
                    policy: pending.policy,
                    context_id: pending.context_id,
                    route_owner: pending.route_owner,
                    expires: pending.lease_expires,
                },
            );
            return Ok(());
        }
        let delivered = receipt.delivered();
        self.rollback_and_retain_completion(pending)?;
        if delivered {
            Err(ManagementError::WrongReply)
        } else {
            Ok(())
        }
    }
    pub fn cleanup_expired(&mut self) -> Result<(), ManagementError> {
        // Only this processor's exact expired grant/context generation is
        // retired. Durable operations, CAS, fences and principal ownership
        // remain intact; an unsuccessful cleanup keeps its ownership entry.
        let expired_active = self
            .active
            .iter()
            .filter(|(_, active)| Instant::now() >= active.expires)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in expired_active {
            if let Some(active) = self.active.remove(&id)
                && self.retire_active(&active).is_err()
            {
                self.active.insert(id, active);
                return Err(ManagementError::TransportUncertain);
            }
        }
        let expired_workspace = self
            .workspace
            .iter()
            .filter(|(_, w)| {
                Instant::now() >= w.ownership.expires
                    || self
                        .authority
                        .authorize_retained_scope(
                            &w.ownership.principal,
                            &w.ownership.project,
                            &w.ownership.context_id,
                            &w.ownership.policy,
                            &w.context["scope"],
                        )
                        .is_err()
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in expired_workspace {
            if let Some(workspace) = self.workspace.remove(&id)
                && self.retire_active(&workspace.ownership).is_err()
            {
                self.workspace.insert(id, workspace);
                return Err(ManagementError::TransportUncertain);
            }
        }
        let expired = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.budget.check().is_err())
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in expired {
            if let Some(pending) = self.pending.remove(&id) {
                self.rollback_and_retain_completion(pending)?;
            }
        }
        Ok(())
    }
    /// Composition calls this after native workers drain and their Finished
    /// observations are consumed. Cleanup is fallible and is never hidden in
    /// Drop. A failed record remains owned for a retry/report; discovery must
    /// be retained by composition whenever this method returns an error.
    pub fn shutdown(&mut self) -> Result<(), ManagementError> {
        let mut failed = false;
        let pending_ids = self.pending.keys().cloned().collect::<Vec<_>>();
        for id in pending_ids {
            if let Some(pending) = self.pending.remove(&id)
                && self.rollback_and_retain_completion(pending).is_err()
            {
                failed = true;
            }
        }
        let active_ids = self.active.keys().cloned().collect::<Vec<_>>();
        for id in active_ids {
            if let Some(active) = self.active.remove(&id)
                && self.retire_active(&active).is_err()
            {
                self.active.insert(id, active);
                failed = true;
            }
        }
        let workspace_ids = self.workspace.keys().cloned().collect::<Vec<_>>();
        for id in workspace_ids {
            if let Some(workspace) = self.workspace.remove(&id)
                && self.retire_active(&workspace.ownership).is_err()
            {
                self.workspace.insert(id, workspace);
                failed = true;
            }
        }
        if failed {
            Err(ManagementError::TransportUncertain)
        } else {
            Ok(())
        }
    }
    /// After Complete is issued, composition defers fresh HTTP admission until
    /// the finite native ACK/EOF receipt or expiry has been processed. Starting
    /// another long application call cannot starve the final authority commit.
    pub fn has_pending_completion(&self) -> bool {
        self.pending.values().any(|pending| pending.complete_issued)
    }
    /// Exact rollback observations and native completion truth have distinct
    /// lifetimes. Neither successful cleanup nor capacity pressure discards a
    /// completed exchange. A full diagnostic budget keeps its pending record
    /// and prevents reporting settled ownership while retention is unresolved.
    fn rollback_and_retain_completion(
        &mut self,
        mut pending: PendingBootstrap,
    ) -> Result<(), ManagementError> {
        let prior_failure = match pending.rollback_observation {
            RollbackObservation::Uncertain { first_failure } => Some(first_failure),
            RollbackObservation::Completed { prior_failure } => prior_failure,
            RollbackObservation::NotAttempted => None,
        };
        if !matches!(
            pending.rollback_observation,
            RollbackObservation::Completed { .. }
        ) {
            if let Err(cause) = self.rollback_with_cause(&pending) {
                if pending.first_rollback_failure.is_none() {
                    pending.first_rollback_failure = Some(Arc::new(cause));
                }
                pending.rollback_observation = RollbackObservation::Uncertain {
                    first_failure: prior_failure.unwrap_or(ManagementError::TransportUncertain),
                };
                self.pending.insert(pending.witness.id().clone(), pending);
                return Err(ManagementError::TransportUncertain);
            }
            pending.rollback_observation = RollbackObservation::Completed { prior_failure };
        }
        let Some(completion) = pending.completion.as_ref() else {
            return Ok(());
        };
        let total = self
            .rejected_encoded_bytes
            .checked_add(pending.retained_encoded_bytes)
            .filter(|bytes| *bytes <= MAX_REJECTED_ENCODED_BYTES);
        if self.rejected_completions.len() >= MAX_REJECTED_COMPLETIONS
            || total.is_none()
            || self.rejected_completions.contains_key(pending.witness.id())
        {
            self.pending.insert(pending.witness.id().clone(), pending);
            return Err(ManagementError::TransportUncertain);
        }
        let observation = Arc::new(CompletedPairingObservation::from_pending(
            &pending,
            completion.clone(),
            &self.owner,
        ));
        self.rejected_encoded_bytes = total.ok_or(ManagementError::TransportUncertain)?;
        self.rejected_completions.insert(
            pending.witness.id().clone(),
            RejectedPairingCompletion {
                _observation: observation,
                _rollback: pending.rollback_observation,
                _publication_failure: pending.publication_failure,
                _first_rollback_failure: pending.first_rollback_failure,
            },
        );
        Ok(())
    }
    fn rollback(&self, pending: &PendingBootstrap) -> Result<(), ManagementError> {
        self.rollback_with_cause(pending)
            .map_err(|_| ManagementError::TransportUncertain)
    }
    fn rollback_with_cause(&self, pending: &PendingBootstrap) -> mmmm_application::AppResult<()> {
        self.authority.revoke_staged_project(
            &pending.principal,
            &pending.project,
            &pending.policy,
        )?;
        if let Some(route_owner) = &pending.route_owner {
            self.hosts.detach_owned(route_owner)?;
        }
        Ok(())
    }
    fn retire_active(&self, active: &ActiveBootstrap) -> Result<(), ManagementError> {
        self.authority
            .revoke_staged_project(&active.principal, &active.project, &active.policy)
            .map_err(|_| ManagementError::TransportUncertain)?;
        if let Some(route_owner) = &active.route_owner {
            self.hosts
                .detach_owned(route_owner)
                .map_err(|_| ManagementError::TransportUncertain)?;
        }
        Ok(())
    }
}

fn validate_live_offer(value: &Value, artifact: &Sha256Digest) -> Result<(), ManagementError> {
    let hello = &value["hostHello"];
    if hello["hostProtocolVersion"] != mmmm_contracts::CONTRACT_VERSION
        || hello["environment"]["kind"] != "game"
        || hello["environment"]["side"] != "server"
        || hello["loader"]["id"] == "fixture"
        || hello["environment"]["worldId"].as_str().is_none()
    {
        return Err(ManagementError::InvalidFrame);
    }
    let actions = value["nativeActions"]
        .as_array()
        .ok_or(ManagementError::InvalidFrame)?;
    if actions.is_empty() || actions.len() > 64 {
        return Err(ManagementError::InvalidFrame);
    }
    let mut digests = BTreeSet::new();
    for action in actions {
        if action["implementationDigest"] != artifact.as_str()
            || action["side"] != "server"
            || !digests.insert(canonical_digest(action).map_err(|_| ManagementError::InvalidFrame)?)
        {
            return Err(ManagementError::InvalidFrame);
        }
    }
    Ok(())
}
fn rebound_scope(
    mut scope: WriteScope,
    context_id: &ContextId,
    environment: &Value,
) -> Result<Value, ManagementError> {
    let world = mmmm_contracts::WorldId::new(text(environment, "worldId")?)
        .map_err(|_| ManagementError::InvalidFrame)?;
    for region in &mut scope.regions {
        region.context_id = context_id.clone();
        region.world_id = world.clone();
    }
    scope
        .validate()
        .map_err(|_| ManagementError::InvalidFrame)?;
    serde_json::to_value(scope).map_err(|_| ManagementError::InvalidFrame)
}
fn build_context(
    offer: &Value,
    pending: &PendingBootstrap,
    scope: Value,
) -> Result<Value, ManagementError> {
    let player = &offer["playerContext"];
    let mut context = json!({
        "contractVersion":mmmm_contracts::CONTRACT_VERSION, "contextId":pending.context_id,
        "principalRef":pending.principal, "projectId":pending.project,
        "environment":pending.hello["environment"], "policyRevision":pending.policy,
        "scope":scope, "contextDigest":"0".repeat(64),
        "dimension":player["dimension"], "executorHandle":player["executorHandle"],
        "origin":player["origin"], "rotationDegrees":player["rotationDegrees"],
        "anchor":player["anchor"],
    });
    context["contextDigest"] = json!(
        projected_digest("ExecutionContext", &context)
            .map_err(|_| ManagementError::InvalidFrame)?
    );
    ContractValidator::shared()
        .and_then(|validator| validator.validate("ExecutionContext", &context))
        .map_err(|_| ManagementError::InvalidFrame)?;
    Ok(context)
}
fn new_context_id() -> Result<ContextId, ManagementError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| ManagementError::EntropyUnavailable)?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    ContextId::new(format!("context-{suffix}")).map_err(|_| ManagementError::EntropyUnavailable)
}
fn same_witness(expected: &BootstrapWitness, actual: &BootstrapWitness) -> bool {
    expected.id() == actual.id()
        && expected.nonce() == actual.nonce()
        && expected.offer_digest() == actual.offer_digest()
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ManagementError> {
    value[key].as_str().ok_or(ManagementError::InvalidFrame)
}
fn owner_error() -> StorageError {
    StorageError::Conflict("Current authenticated local setup owner")
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod tests;

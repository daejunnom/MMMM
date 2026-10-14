//! Concrete paired Java host calls. Installation consumes an opaque capability
//! from an authenticated local bootstrap; public function DTOs cannot install
//! a host, principal, context, authority or replacement binding.

use crate::{
    authority::LocalAuthority,
    bootstrap::{CompletedPairingObservation, NativeWorkspacePermit},
    client::{ClientError, HostClientReply, HostRpcClient},
    service::RequestContextWitness,
    workspace_bootstrap::NativeOwnerWitness,
};
use mmmm_application::{AppError, AppResult, ProviderPort};
use mmmm_contracts::{
    ActionId, BindingId, ContextId, ContractValidator, InvocationId, OperationId, PrincipalId,
    ProjectId, Sha256Digest, StepId, encode_json, raw_digest, verify_projected_digest,
};
use mmmm_runtime::storage::DurableStore;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Default)]
pub struct HostBridge {
    state: Arc<Mutex<BridgeState>>,
}
#[derive(Default)]
struct BridgeState {
    hosts: BTreeMap<ContextId, PairedHost>,
    retained_routes: BTreeMap<[u8; 16], PairedHost>,
    invocations: BTreeMap<OriginalInvocationKey, [u8; 16]>,
    verified_dependencies: BTreeMap<String, VerifiedDependency>,
}
/// Actual source/build verification installs the complete dependency metadata.
/// A matching digest never authorizes a caller-selected provenance or contract.
pub struct VerifiedDependency {
    component: String,
    digest: Sha256Digest,
    provenance: DependencyProvenance,
    contracts: BTreeSet<String>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DependencyProvenance {
    OwnedDomain,
    TemporaryDomainVendor,
    InfrastructureDependency,
    PlatformShim,
    UserExternalTool,
}
impl DependencyProvenance {
    fn wire(self) -> &'static str {
        match self {
            Self::OwnedDomain => "owned_domain",
            Self::TemporaryDomainVendor => "temporary_domain_vendor",
            Self::InfrastructureDependency => "infrastructure_dependency",
            Self::PlatformShim => "platform_shim",
            Self::UserExternalTool => "user_external_tool",
        }
    }
}
impl VerifiedDependency {
    pub fn new(
        component: String,
        digest: Sha256Digest,
        provenance: DependencyProvenance,
        contracts: BTreeSet<String>,
    ) -> AppResult<Self> {
        mmmm_contracts::ComponentId::new(&component)
            .map_err(|_| error("INVALID_INPUT", "Dependency identity is invalid"))?;
        if contracts.is_empty()
            || contracts.len() > 64
            || contracts
                .iter()
                .any(|contract| contract.is_empty() || contract.len() > 256)
        {
            return Err(error(
                "INVALID_INPUT",
                "Dependency contracts exceed their finite range",
            ));
        }
        Ok(Self {
            component,
            digest,
            provenance,
            contracts,
        })
    }
    fn matches(&self, pin: &Value) -> bool {
        pin["implementationDigest"] == self.digest.as_str()
            && pin["provenanceClass"] == self.provenance.wire()
            && pin["contractIds"].as_array().is_some_and(|contracts| {
                !contracts.is_empty()
                    && contracts.iter().all(|contract| {
                        contract
                            .as_str()
                            .is_some_and(|id| self.contracts.contains(id))
                    })
            })
    }
}
#[derive(Clone)]
struct PairedHost {
    client: Arc<HostRpcClient>,
    principal: PrincipalId,
    context: Value,
    hello: Value,
    expires: Instant,
    generation: [u8; 16],
    completed_pairing: Option<Arc<CompletedPairingObservation>>,
}
const MAX_RETAINED_ROUTES: usize = 8;
const MAX_RETAINED_INVOCATIONS: usize = 1024;
const MAX_ORIGINAL_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OriginalInvocationKey {
    data_root: PathBuf,
    operation: OperationId,
    step: StepId,
    invocation: InvocationId,
    digest: Sha256Digest,
}

/// A complete response actually received from one authenticated paired route.
/// Receiving bytes does not extend permission, lease or the request deadline.
/// Only a typed adapter may retain its validated reply as private truth before
/// checking whether it may still release or use that truth for the caller.
pub struct HostReplyAcquisition {
    reply: HostClientReply,
    deadline: Instant,
    generation: [u8; 16],
}
impl HostReplyAcquisition {
    pub fn validated_response(&self) -> Option<&Value> {
        self.reply.response()
    }
    pub fn failure(&self) -> Option<&ClientError> {
        self.reply.failure()
    }
    pub fn deadline_reached(&self) -> bool {
        Instant::now() >= self.deadline
    }
    pub fn received_byte_length(&self) -> usize {
        self.reply.received_bytes()
    }
    pub fn matches_witness(&self, witness: &HostContextWitness) -> bool {
        self.generation == witness.generation
    }
    /// Internal received-truth consumption only. This never authorizes release
    /// to a caller or a usable resource marker; those require fresh checks.
    pub fn into_acquired_response(self) -> AppResult<Value> {
        if self.reply.failure().is_some() {
            return Err(AppError::caused_by(
                "HOST_RESULT_UNKNOWN",
                "Authenticated host response was not validated",
                self,
            ));
        }
        self.reply.into_response().map_err(|cause| {
            AppError::caused_by(
                "HOST_RESULT_UNKNOWN",
                "Authenticated host response was not validated",
                cause,
            )
        })
    }
    pub fn check_normal_deadline(&self) -> AppResult<()> {
        if self.reply.failure().is_some() {
            return Err(error(
                "HOST_RESULT_UNKNOWN",
                "Authenticated host response was not validated",
            ));
        }
        bounded_host_deadline(self.deadline).map(|_| ())
    }
    pub fn into_response(self) -> AppResult<Value> {
        if self.reply.failure().is_some() {
            return Err(AppError::caused_by(
                "HOST_RESULT_UNKNOWN",
                "Authenticated host response was not validated",
                self,
            ));
        }
        if self.deadline_reached() {
            return Err(AppError::caused_by(
                "TIME_BUDGET_EXCEEDED",
                "Host response was acquired after the request budget ended",
                self,
            ));
        }
        self.reply.into_response().map_err(|cause| {
            AppError::caused_by(
                "HOST_RESULT_UNKNOWN",
                "Authenticated host response was not validated",
                cause,
            )
        })
    }
}
impl std::fmt::Debug for HostReplyAcquisition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostReplyAcquisition")
            .field("received_bytes", &self.received_byte_length())
            .field("validated", &self.reply.response().is_some())
            .field("deadline_reached", &self.deadline_reached())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for HostReplyAcquisition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Opaque actual paired host reply; body is private diagnostic evidence")
    }
}
impl std::error::Error for HostReplyAcquisition {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.reply.failure_source()
    }
}
/// Opaque in-process ownership of one actual attached route. Public context
/// JSON and a reused context ID cannot remove a later route generation.
pub struct HostRouteOwner {
    context_id: ContextId,
    generation: [u8; 16],
}
/// Factual delivery provenance for one currently entered request and exact
/// route generation. It grants no read/source/target permission and cannot be
/// constructed from a DTO, a matching digest or a host response. Consumers
/// still acquire fresh kernel-owner/same-Store/Project-owner authority and
/// source/mode rights before using this provenance to issue any source grant.
pub struct CompletedPairingWitness {
    state: Arc<Mutex<BridgeState>>,
    request: RequestContextWitness,
    context_id: ContextId,
    generation: [u8; 16],
    observation: Arc<CompletedPairingObservation>,
}
/// Request-scoped owner/provenance check over one already opened and locked
/// Store borrow. No raw NativeOwnerWitness, Clone, serde or authority constructor
/// is exposed. Source rights, game modes and target readiness remain separate.
/// Same-store checking reuses the held Store's existing opening guarantees;
/// it does not refresh live filesystem ACL or lock-file namespace identity.
pub(crate) struct CurrentCompletedPairingOwner<'a> {
    pairing: &'a CompletedPairingWitness,
    store: &'a DurableStore,
    authority: &'a LocalAuthority,
    owner: NativeOwnerWitness,
}
impl CurrentCompletedPairingOwner<'_> {
    pub(crate) fn check_current(&self) -> AppResult<()> {
        self.pairing.check_current(self.authority)?;
        if Path::new(text(self.pairing.observation.original_offer(), "dataRoot")?)
            != self.store.data_root()
            || self.owner.principal() != self.pairing.native_owner()
        {
            return Err(error(
                "PERMISSION_REQUIRED",
                "Current native owner or held Store differs from completed pairing",
            ));
        }
        self.owner
            .check_store(self.store)
            .map_err(|cause| self.pairing.native_owner_failure(cause))?;
        let registered = self
            .owner
            .check_project(self.store, self.pairing.project())
            .map_err(|cause| self.pairing.native_owner_failure(cause))?;
        if &registered != self.pairing.native_owner() {
            return Err(error(
                "PERMISSION_REQUIRED",
                "Registered native Project owner differs from completed pairing",
            ));
        }
        // NativeOwnerWitness itself has no cancellation/session generation.
        // The exact entered request is therefore checked after every metadata
        // pass and again around the callback, without resetting its deadline.
        self.pairing.check_current(self.authority)
    }
}
/// Both immutable errors survive when native/DB/callback failure and a current
/// request checkpoint fail together. No request, owner witness, Store or body is kept
/// in this diagnostic snapshot, so it can cross the local error boundary.
pub(crate) struct NativePairingOwnerFailure {
    pub(crate) primary: AppError,
    pub(crate) checkpoint: AppError,
}
impl std::fmt::Debug for NativePairingOwnerFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativePairingOwnerFailure")
            .field("primary_code", &self.primary.code)
            .field("checkpoint_code", &self.checkpoint.code)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for NativePairingOwnerFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Native pairing owner work and current request checks both failed")
    }
}
impl std::error::Error for NativePairingOwnerFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
impl std::fmt::Debug for CompletedPairingWitness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompletedPairingWitness")
            .finish_non_exhaustive()
    }
}
impl CompletedPairingWitness {
    /// Observe only the already entered request after a native/DB failure.
    /// This adds no kernel/Store I/O or new deadline and never replaces the
    /// first native cause with a later cancellation/deadline observation.
    fn native_owner_failure(&self, cause: mmmm_runtime::storage::StorageError) -> AppError {
        let primary = AppError::storage("PERMISSION_REQUIRED", cause);
        match self.request.check_local() {
            Ok(()) => primary,
            Err(cause) => {
                let checkpoint = AppError::caused_by(cause.code, cause.message, cause);
                AppError::caused_by(
                    primary.code,
                    primary.message,
                    NativePairingOwnerFailure {
                        primary,
                        checkpoint,
                    },
                )
            }
        }
    }
    /// Capture current kernel ownership under this entered request's original
    /// deadline, then check exact original root, completion owner, registered
    /// native Project owner, route and policy around a bounded local callback.
    /// This never renews setup authority or opens another Store. The callback
    /// receives a non-clonable borrow guard and cannot retain the raw owner
    /// permit as a longer-lived source/permission capability.
    #[allow(
        dead_code,
        reason = "The explicit source-rights consumer is composed separately from this owner/provenance slice"
    )]
    pub(crate) fn with_current_native_owner<T>(
        &self,
        store: &DurableStore,
        authority: &LocalAuthority,
        inspect: impl FnOnce(&CurrentCompletedPairingOwner<'_>) -> AppResult<T>,
    ) -> AppResult<T> {
        self.check_current(authority)?;
        if Path::new(text(self.observation.original_offer(), "dataRoot")?) != store.data_root() {
            return Err(error(
                "PERMISSION_REQUIRED",
                "Completed native pairing belongs to another held Store",
            ));
        }
        let owner = NativeOwnerWitness::capture(store, self.request.budget().deadline())
            .map_err(|cause| self.native_owner_failure(cause))?;
        let current = CurrentCompletedPairingOwner {
            pairing: self,
            store,
            authority,
            owner,
        };
        current.check_current()?;
        let output = inspect(&current);
        let checked = current.check_current();
        match (output, checked) {
            (Ok(output), Ok(())) => Ok(output),
            (Err(cause), Ok(())) | (Ok(_), Err(cause)) => Err(cause),
            (Err(callback), Err(postcheck)) => Err(AppError::caused_by(
                callback.code,
                callback.message,
                NativePairingOwnerFailure {
                    primary: callback,
                    checkpoint: postcheck,
                },
            )),
        }
    }
    pub fn check_current(&self, authority: &LocalAuthority) -> AppResult<()> {
        self.request
            .check_local()
            .map_err(|cause| AppError::caused_by(cause.code, cause.message, cause))?;
        let principal = self.request.authenticated().principal();
        if principal != self.observation.principal()
            || !self
                .request
                .authenticated()
                .permits_context(self.context_id.as_str())
            || !self.observation.check_delivery()
        {
            return Err(error(
                "PERMISSION_REQUIRED",
                "Completed native pairing is no longer current",
            ));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, &self.context_id, Some(principal))?;
        if host.generation != self.generation
            || host.context != *self.observation.context()
            || host
                .completed_pairing
                .as_ref()
                .is_none_or(|actual| !Arc::ptr_eq(actual, &self.observation))
        {
            return Err(error(
                "SESSION_ROUTE_CHANGED",
                "Original completed pairing route was replaced",
            ));
        }
        authority.authorize_retained_scope(
            principal,
            self.observation.project(),
            &self.context_id,
            self.observation.policy(),
            &self.observation.context()["scope"],
        )?;
        self.request
            .check_local()
            .map_err(|cause| AppError::caused_by(cause.code, cause.message, cause))
    }
    pub fn principal(&self) -> &PrincipalId {
        self.observation.principal()
    }
    pub fn project(&self) -> &ProjectId {
        self.observation.project()
    }
    pub fn context(&self) -> &Value {
        self.observation.context()
    }
    pub fn native_owner(&self) -> &PrincipalId {
        self.observation.native_owner()
    }
    pub fn offer_digest(&self) -> &Sha256Digest {
        self.observation.offer_digest()
    }
    pub fn completed_at(&self) -> Instant {
        self.observation.completed_at()
    }
    pub fn original_deadline(&self) -> Instant {
        self.observation.original_deadline()
    }
    pub fn lease_expires(&self) -> Instant {
        self.observation.lease_expires()
    }

    /// Only a trusted source consumer may inspect the original bounded offer.
    /// This private borrow never belongs in RPC output, Debug or diagnostics.
    /// Same-Store and refreshed native owner checks remain consumer duties.
    #[allow(
        dead_code,
        reason = "The real source-registration consumer is composed separately from this delivery producer"
    )]
    pub(crate) fn with_current_original_offer<T>(
        &self,
        authority: &LocalAuthority,
        inspect: impl FnOnce(&Value) -> AppResult<T>,
    ) -> AppResult<T> {
        self.check_current(authority)?;
        let output = inspect(self.observation.original_offer())?;
        self.check_current(authority)?;
        Ok(output)
    }
}
/// An actual bounded native context observation bound to this exact installed
/// route. Runtime transaction checkpoints may validate this witness locally;
/// they must not perform another transport/native call while SQLite is locked.
#[derive(Clone)]
pub struct HostContextWitness {
    state: Arc<Mutex<BridgeState>>,
    context_id: ContextId,
    principal: PrincipalId,
    context: Value,
    generation: [u8; 16],
}
impl HostContextWitness {
    pub fn context(&self) -> &Value {
        &self.context
    }
    /// No native or transport I/O: exact route ownership, finite lease and
    /// immutable paired identity are checked under one local lock.
    pub fn check_local(&self) -> AppResult<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, &self.context_id, Some(&self.principal))?;
        if host.generation != self.generation || host.context != self.context {
            return Err(error(
                "SESSION_ROUTE_CHANGED",
                "Original paired context generation is no longer current",
            ));
        }
        Ok(())
    }
}
impl HostBridge {
    /// Bootstrap alone can construct this actual completion observation.
    /// Publication checks route ownership and active grant under the same
    /// route lock, so a replacement cannot inherit another exchange's receipt.
    /// This performs local checks only and creates no new acquisition budget.
    pub(crate) fn record_completed_pairing(
        &self,
        owner: &HostRouteOwner,
        observation: Arc<CompletedPairingObservation>,
        authority: &LocalAuthority,
    ) -> AppResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, &owner.context_id, Some(observation.principal()))?;
        if host.generation != owner.generation
            || host.context != *observation.context()
            || host.hello != observation.original_offer()["hostHello"]
            || observation.context()["contextId"] != owner.context_id.as_str()
            || observation.context()["projectId"] != observation.project().as_str()
            || observation.context()["policyRevision"] != observation.policy().as_str()
            || !observation.check_delivery()
            || host.completed_pairing.is_some()
        {
            return Err(error(
                "SESSION_ROUTE_CHANGED",
                "Completed native pairing differs from the exact installed route",
            ));
        }
        authority.authorize_retained_scope(
            observation.principal(),
            observation.project(),
            &owner.context_id,
            observation.policy(),
            &observation.context()["scope"],
        )?;
        state
            .hosts
            .get_mut(&owner.context_id)
            .ok_or_else(|| error("STALE_CONTEXT", "Original native route is unavailable"))?
            .completed_pairing = Some(observation);
        Ok(())
    }
    /// Resolve only the currently installed route, never retained invocation
    /// routes. The exact entered request supplies its original cancellation
    /// and deadline; this query does not refresh native owner or source rights.
    pub fn completed_pairing_witness(
        &self,
        request: &RequestContextWitness,
        authority: &LocalAuthority,
        id: &ContextId,
    ) -> AppResult<CompletedPairingWitness> {
        request
            .check_local()
            .map_err(|cause| AppError::caused_by(cause.code, cause.message, cause))?;
        let witness = {
            let state = self
                .state
                .lock()
                .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
            let host = checked_host(&state, id, Some(request.authenticated().principal()))?;
            let observation = host.completed_pairing.clone().ok_or_else(|| {
                error(
                    "SOURCE_UNAVAILABLE",
                    "No actual completed native pairing is recorded for this route",
                )
            })?;
            CompletedPairingWitness {
                state: self.state.clone(),
                request: request.clone(),
                context_id: id.clone(),
                generation: host.generation,
                observation,
            }
        };
        witness.check_current(authority)?;
        Ok(witness)
    }
    /// Trusted bootstrap only. The host is independently queried before this
    /// exact immutable context becomes routable. An approval may rotate the
    /// same actual context/runtime; original dispatch routes remain read-only.
    pub fn attach(
        &self,
        client: HostRpcClient,
        principal: PrincipalId,
        expected_context: Value,
        expected_hello: Value,
        lease: Duration,
    ) -> AppResult<()> {
        self.attach_with_deadline(
            client,
            principal,
            expected_context,
            expected_hello,
            lease,
            Instant::now() + Duration::from_secs(10),
        )
    }
    /// Both actual host observations share one finite native bootstrap deadline.
    /// The second observation does not receive a fresh per-call time budget.
    pub fn attach_with_deadline(
        &self,
        client: HostRpcClient,
        principal: PrincipalId,
        expected_context: Value,
        expected_hello: Value,
        lease: Duration,
        deadline: Instant,
    ) -> AppResult<()> {
        self.attach_owned_with_deadline(
            client,
            principal,
            expected_context,
            expected_hello,
            lease,
            deadline,
        )
        .map(|_| ())
    }
    pub fn attach_owned_with_deadline(
        &self,
        client: HostRpcClient,
        principal: PrincipalId,
        expected_context: Value,
        expected_hello: Value,
        lease: Duration,
        deadline: Instant,
    ) -> AppResult<HostRouteOwner> {
        if lease.is_zero() || lease > Duration::from_secs(24 * 60 * 60) {
            return Err(error(
                "INVALID_INPUT",
                "Host lease is outside its finite range",
            ));
        }
        let lease_expires = Instant::now() + lease;
        validate("ExecutionContext", &expected_context)?;
        validate("HostHello", &expected_hello)?;
        verify_projected_digest("ExecutionContext", &expected_context)
            .map_err(|_| error("STALE_CONTEXT", "Host context digest is invalid"))?;
        let id = context_id(&expected_context)?;
        if expected_context["principalRef"] != principal.as_str()
            || expected_context["environment"] != expected_hello["environment"]
            || expected_hello["hostProtocolVersion"] != "0.2.0"
        {
            return Err(error(
                "STALE_CONTEXT",
                "Host principal or environment differs from bootstrap authority",
            ));
        }
        let hello_deadline = bounded_host_deadline(deadline)?;
        let actual_hello = exchange(&client, "hello", None, json!({}), Some(&hello_deadline))?;
        validate("HostHello", &actual_hello)?;
        if actual_hello != expected_hello {
            return Err(error(
                "STALE_CONTEXT",
                "Actual host hello differs from the approved pairing offer",
            ));
        }
        let context_deadline = bounded_host_deadline(deadline)?;
        let actual_context = exchange(
            &client,
            "inspect",
            Some(&id),
            json!({"kind":"execution_context"}),
            Some(&context_deadline),
        )?;
        validate("ExecutionContext", &actual_context)?;
        if actual_context != expected_context {
            return Err(error(
                "STALE_CONTEXT",
                "Actual installed host context differs from server authority",
            ));
        }
        bounded_host_deadline(deadline)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        state.hosts.retain(|_, host| Instant::now() < host.expires);
        if state.hosts.get(&id).is_some_and(|old| {
            old.principal != principal || old.context != actual_context || old.hello != actual_hello
        }) || (!state.hosts.contains_key(&id) && state.hosts.len() >= 64)
        {
            return Err(error(
                "HOST_CAPACITY",
                "Host context replacement differs or capacity is exhausted",
            ));
        }
        let mut generation = [0u8; 16];
        getrandom::fill(&mut generation)
            .map_err(|_| error("HOST_UNAVAILABLE", "Host route identity is unavailable"))?;
        let owner = HostRouteOwner {
            context_id: id.clone(),
            generation,
        };
        state.hosts.insert(
            id,
            PairedHost {
                client: Arc::new(client),
                principal,
                context: actual_context,
                hello: actual_hello,
                expires: lease_expires,
                generation,
                completed_pairing: None,
            },
        );
        Ok(owner)
    }
    pub fn detach_owned(&self, owner: &HostRouteOwner) -> AppResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        if state
            .hosts
            .get(&owner.context_id)
            .is_some_and(|host| host.generation == owner.generation)
        {
            state.hosts.remove(&owner.context_id);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn contains_route_for_test(&self, id: &ContextId) -> AppResult<bool> {
        Ok(self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?
            .hosts
            .contains_key(id))
    }
    pub fn detach(&self, id: &ContextId) -> AppResult<()> {
        self.state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?
            .hosts
            .remove(id);
        Ok(())
    }
    /// A build/source verifier supplies actual local component digests. This
    /// method is neither serialized nor reachable through a facade function.
    pub fn register_verified_dependency(&self, dependency: VerifiedDependency) -> AppResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        if state.verified_dependencies.len() >= 128
            || state
                .verified_dependencies
                .contains_key(&dependency.component)
        {
            return Err(error(
                "DEPENDENCY_CONFLICT",
                "Owned dependency registration conflicts",
            ));
        }
        state
            .verified_dependencies
            .insert(dependency.component.clone(), dependency);
        Ok(())
    }
    pub fn context(&self, principal: &PrincipalId, id: &ContextId) -> AppResult<Value> {
        self.context_with_deadline(principal, id, Instant::now() + Duration::from_secs(10))
    }
    pub fn context_with_deadline(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        deadline: Instant,
    ) -> AppResult<Value> {
        let state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, id, Some(principal))?;
        let expires = bounded_host_deadline(deadline)?;
        let context = exchange(
            &host.client,
            "inspect",
            Some(id),
            json!({"kind":"execution_context"}),
            Some(&expires),
        )?;
        validate("ExecutionContext", &context)?;
        verify_projected_digest("ExecutionContext", &context)
            .map_err(|_| error("STALE_CONTEXT", "Live host context digest is invalid"))?;
        if context["contextId"] != id.as_str()
            || context["principalRef"] != principal.as_str()
            || context["projectId"] != host.context["projectId"]
            || context["environment"] != host.hello["environment"]
        {
            return Err(error(
                "STALE_CONTEXT",
                "Live host identity differs from its paired generation",
            ));
        }
        bounded_host_deadline(deadline)?;
        Ok(context)
    }
    /// Fresh native observation happens before a writer transaction. The local
    /// route lock prevents replacing the observed generation while issuing it.
    pub fn observe_context_witness(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        deadline: Instant,
    ) -> AppResult<HostContextWitness> {
        let state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, id, Some(principal))?;
        let expires = bounded_host_deadline(deadline)?;
        let context = exchange(
            &host.client,
            "inspect",
            Some(id),
            json!({"kind":"execution_context"}),
            Some(&expires),
        )?;
        validate("ExecutionContext", &context)?;
        verify_projected_digest("ExecutionContext", &context)
            .map_err(|_| error("STALE_CONTEXT", "Live host context digest is invalid"))?;
        if context != host.context
            || context["principalRef"] != principal.as_str()
            || context["environment"] != host.hello["environment"]
        {
            return Err(error(
                "STALE_CONTEXT",
                "Actual native context differs from its immutable paired route",
            ));
        }
        bounded_host_deadline(deadline)?;
        Ok(HostContextWitness {
            state: self.state.clone(),
            context_id: id.clone(),
            principal: principal.clone(),
            context,
            generation: host.generation,
        })
    }
    pub fn inspect(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        selector: Value,
    ) -> AppResult<Value> {
        self.inspect_with_deadline(
            principal,
            id,
            selector,
            Instant::now() + Duration::from_secs(10),
        )
    }
    pub fn inspect_with_deadline(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        selector: Value,
        deadline: Instant,
    ) -> AppResult<Value> {
        let response = self.inspect_response_with_deadline(principal, id, selector, deadline)?;
        if response["status"] != "ok" {
            return Err(error(
                "HOST_REQUEST_FAILED",
                "The original host rejected or could not complete the request",
            ));
        }
        response
            .get("payload")
            .cloned()
            .ok_or_else(|| error("HOST_RESPONSE_INVALID", "Host response payload is absent"))
    }
    pub fn inventory(&self, principal: &PrincipalId, id: &ContextId) -> AppResult<Value> {
        self.inventory_with_deadline(principal, id, Instant::now() + Duration::from_secs(10))
    }
    pub fn inventory_with_deadline(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        deadline: Instant,
    ) -> AppResult<Value> {
        self.context_with_deadline(principal, id, deadline)?;
        let state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, id, Some(principal))?;
        let expires = bounded_host_deadline(deadline)?;
        let inventory = exchange(
            &host.client,
            "inventory",
            Some(id),
            json!({}),
            Some(&expires),
        )?;
        validate("ProviderInventory", &inventory)?;
        if inventory["providers"].as_array().is_none_or(|providers| {
            providers
                .iter()
                .any(|p| p["environment"] != host.hello["environment"])
        }) {
            return Err(error(
                "STALE_CONTEXT",
                "Host inventory contains a foreign environment",
            ));
        }
        bounded_host_deadline(deadline)?;
        Ok(inventory)
    }
    /// Verify real in-process source registrations. Only platform/external
    /// provider pins need current native inventory. Offline owned-domain pins
    /// never invent a host merely to check their actual Rust source identity.
    pub fn verify_registered_dependencies_with_deadline(
        &self,
        pins: &[Value],
        context: &Value,
        deadline: Instant,
    ) -> AppResult<()> {
        if pins.len() > 128 {
            return Err(error(
                "BUDGET_EXCEEDED",
                "Dependency pin count exceeds its budget",
            ));
        }
        validate("ExecutionContext", context)?;
        bounded_host_deadline(deadline)?;
        let needs_host = {
            let state = self
                .state
                .lock()
                .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
            let mut needs_host = false;
            for pin in pins {
                validate("DependencyPin", pin)?;
                let approved = state
                    .verified_dependencies
                    .get(text(pin, "componentId")?)
                    .filter(|source| source.matches(pin))
                    .ok_or_else(|| {
                        error(
                            "STALE_DEPENDENCY",
                            "Pinned dependency metadata has no approved source registration",
                        )
                    })?;
                needs_host |= matches!(
                    approved.provenance,
                    DependencyProvenance::PlatformShim | DependencyProvenance::UserExternalTool
                );
            }
            needs_host
        };
        if needs_host {
            if context["environment"]["kind"] != "game" {
                return Err(error(
                    "STALE_DEPENDENCY",
                    "Native dependency has no actual paired game context",
                ));
            }
            let principal = PrincipalId::new(text(context, "principalRef")?)
                .map_err(|_| error("STALE_CONTEXT", "Context principal is invalid"))?;
            let inventory =
                self.inventory_with_deadline(&principal, &context_id(context)?, deadline)?;
            let state = self
                .state
                .lock()
                .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
            for pin in pins {
                let approved = state
                    .verified_dependencies
                    .get(text(pin, "componentId")?)
                    .filter(|source| source.matches(pin))
                    .ok_or_else(|| {
                        error("STALE_DEPENDENCY", "Pinned source registration changed")
                    })?;
                if matches!(
                    approved.provenance,
                    DependencyProvenance::PlatformShim | DependencyProvenance::UserExternalTool
                ) && !inventory["providers"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|provider| provider["bindingId"] == pin["componentId"])
                    .flat_map(|provider| provider["actions"].as_array().into_iter().flatten())
                    .any(|action| action["implementationDigest"] == pin["implementationDigest"])
                {
                    return Err(error(
                        "STALE_DEPENDENCY",
                        "Pinned implementation has no current approved native registration",
                    ));
                }
            }
        }
        bounded_host_deadline(deadline)?;
        Ok(())
    }
    pub fn hello(&self, principal: &PrincipalId, id: &ContextId) -> AppResult<Value> {
        self.hello_with_deadline(principal, id, Instant::now() + Duration::from_secs(10))
    }
    pub fn hello_with_deadline(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        deadline: Instant,
    ) -> AppResult<Value> {
        self.context_with_deadline(principal, id, deadline)?;
        let state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, id, Some(principal))?;
        let expires = bounded_host_deadline(deadline)?;
        let hello = exchange(&host.client, "hello", None, json!({}), Some(&expires))?;
        if hello != host.hello {
            return Err(error(
                "STALE_CONTEXT",
                "Current host hello differs from its paired epoch",
            ));
        }
        bounded_host_deadline(deadline)?;
        Ok(hello)
    }
    /// The complete original response can be retained as private CAS evidence
    /// by a catalog/shape adapter before it maps an error to its own API.
    pub fn inspect_response(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        selector: Value,
    ) -> AppResult<Value> {
        self.inspect_response_with_deadline(
            principal,
            id,
            selector,
            Instant::now() + Duration::from_secs(10),
        )
    }
    pub fn inspect_response_with_deadline(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        selector: Value,
        deadline: Instant,
    ) -> AppResult<Value> {
        self.inspect_acquired_with_deadline(principal, id, selector, deadline)?
            .into_response()
    }
    pub fn inspect_acquired_with_deadline(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        selector: Value,
        deadline: Instant,
    ) -> AppResult<HostReplyAcquisition> {
        self.context_with_deadline(principal, id, deadline)?;
        let state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, id, Some(principal))?;
        let expires = bounded_host_deadline(deadline)?;
        exchange_acquired(host, "inspect", Some(id), selector, &expires, deadline)
    }
    /// Full original HostResponse, including actual host failure diagnostics.
    pub fn describe_response_with_deadline(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        binding: &BindingId,
        action: &ActionId,
        deadline: Instant,
    ) -> AppResult<Value> {
        self.describe_acquired_with_deadline(principal, id, binding, action, deadline)?
            .into_response()
    }
    pub fn describe_acquired_with_deadline(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        binding: &BindingId,
        action: &ActionId,
        deadline: Instant,
    ) -> AppResult<HostReplyAcquisition> {
        self.context_with_deadline(principal, id, deadline)?;
        let state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, id, Some(principal))?;
        let expires = bounded_host_deadline(deadline)?;
        exchange_acquired(
            host,
            "describe",
            Some(id),
            json!({"bindingId":binding,"actionId":action}),
            &expires,
            deadline,
        )
    }
    /// The supplied store must contain this exact intent. Current observation
    /// permission is checked by trusted application composition before entry;
    /// the old Invocation is identity only and never an old Apply capability.
    pub fn inspect_original_acquired_with_deadline(
        &self,
        store: &DurableStore,
        principal: &PrincipalId,
        original: &Value,
        current_context: &Value,
        selector: Value,
        deadline: Instant,
    ) -> AppResult<HostReplyAcquisition> {
        validate_original_selector(&selector, original)?;
        let key = durable_invocation_key(store, original, deadline)?;
        self.original_acquired(
            principal,
            original,
            current_context,
            &key,
            "inspect",
            selector,
            deadline,
        )
    }
    #[allow(clippy::too_many_arguments)] // Both actual intent and current observation context are required.
    pub fn describe_original_acquired_with_deadline(
        &self,
        store: &DurableStore,
        principal: &PrincipalId,
        original: &Value,
        current_context: &Value,
        binding: &BindingId,
        action: &ActionId,
        deadline: Instant,
    ) -> AppResult<HostReplyAcquisition> {
        if original["bindingId"] != binding.as_str() || original["actionId"] != action.as_str() {
            return Err(error(
                "STALE_CONTEXT",
                "Original description route differs from its durable intent",
            ));
        }
        let key = durable_invocation_key(store, original, deadline)?;
        self.original_acquired(
            principal,
            original,
            current_context,
            &key,
            "describe",
            json!({"bindingId":binding,"actionId":action}),
            deadline,
        )
    }
    #[allow(clippy::too_many_arguments)] // Original identity must remain distinct from current read authority.
    fn original_acquired(
        &self,
        principal: &PrincipalId,
        original: &Value,
        current_context: &Value,
        key: &OriginalInvocationKey,
        method: &str,
        payload: Value,
        deadline: Instant,
    ) -> AppResult<HostReplyAcquisition> {
        validate("ExecutionContext", current_context)?;
        let current_id = context_id(current_context)?;
        let live = self.context_with_deadline(principal, &current_id, deadline)?;
        if live != *current_context
            || current_context["principalRef"] != principal.as_str()
            || original["context"]["principalRef"] != principal.as_str()
            || original["context"]["projectId"] != current_context["projectId"]
            || original["context"]["environment"] != current_context["environment"]
        {
            return Err(error(
                "STALE_CONTEXT",
                "Current observation does not identify the original runtime",
            ));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        checked_host(&state, &current_id, Some(principal))?;
        let host = retained_host(&state, key, original)?;
        let original_id = context_id(&original["context"])?;
        let expires = bounded_host_deadline(deadline)?;
        exchange_acquired(
            host,
            method,
            Some(&original_id),
            payload,
            &expires,
            deadline,
        )
    }
    pub(crate) fn job_observation_with_store_and_deadline(
        &self,
        store: &DurableStore,
        principal: &PrincipalId,
        original: &Value,
        current_context: &Value,
        deadline: Instant,
    ) -> AppResult<Value> {
        let key = durable_invocation_key(store, original, deadline)?;
        let response = self.original_acquired(
            principal,
            original,
            current_context,
            &key,
            "operation.get",
            json!({"invocationId":original["invocationId"]}),
            deadline,
        )?;
        response_payload(response.into_response()?)
    }
    fn dispatch_durable(
        &self,
        store: &mut DurableStore,
        invocation: &Value,
        deadline: Instant,
    ) -> AppResult<Value> {
        let key = durable_invocation_key(store, invocation, deadline)?;
        let record = store
            .operation(&key.operation)
            .map_err(|cause| AppError::storage("STALE_CONTEXT", cause))?;
        let step = record
            .steps
            .iter()
            .find(|step| step.step_id == key.step)
            .ok_or_else(|| error("STALE_CONTEXT", "Original durable step is absent"))?;
        if record.state != mmmm_runtime::storage::OperationState::Running
            || record.reconciliation_required
            || record.cancellation_requested
            || step.finished
            || step.dispatch != mmmm_runtime::storage::DispatchEvidence::IntentDurable
        {
            return Err(error(
                "DISPATCH_ALREADY_ATTEMPTED",
                "Durable step cannot admit a first host dispatch",
            ));
        }
        let acquired = self.invocation_acquired_with_deadline(
            "dispatch",
            invocation,
            invocation.clone(),
            true,
            deadline,
            &key,
        )?;
        let acquired = retain_acquired_operation_truth(store, &key, acquired)?;
        response_payload(acquired.into_response()?)
    }
    fn invocation_acquired_with_deadline(
        &self,
        method: &str,
        invocation: &Value,
        payload: Value,
        preserve_deadline: bool,
        deadline: Instant,
        durable_key: &OriginalInvocationKey,
    ) -> AppResult<HostReplyAcquisition> {
        validate("Invocation", invocation)?;
        let id = context_id(&invocation["context"])?;
        let principal = PrincipalId::new(text(&invocation["context"], "principalRef")?)
            .map_err(|_| error("STALE_CONTEXT", "Stored invocation principal is invalid"))?;
        let current = self.context_with_deadline(&principal, &id, deadline)?;
        if current["environment"] != invocation["context"]["environment"] {
            return Err(error(
                "STALE_CONTEXT",
                "Original invocation belongs to a different host epoch",
            ));
        }
        if preserve_deadline
            && (current["contextDigest"] != invocation["contextDigest"]
                || current["policyRevision"] != invocation["context"]["policyRevision"])
        {
            return Err(error(
                "STALE_CONTEXT",
                "New dispatch differs from its frozen context or policy",
            ));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let active = checked_host(&state, &id, Some(&principal))?;
        let bounded = bounded_host_deadline(deadline)?;
        let bound_at =
            time::OffsetDateTime::parse(&bounded, &time::format_description::well_known::Rfc3339)
                .map_err(|_| error("HOST_UNAVAILABLE", "Bounded host deadline is unavailable"))?;
        let requested = if preserve_deadline {
            let original = text(invocation, "deadlineAt")?;
            let at = time::OffsetDateTime::parse(
                original,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| error("INVALID_INPUT", "Frozen invocation deadline is invalid"))?;
            if at < bound_at { original } else { &bounded }
        } else {
            &bounded
        };
        if preserve_deadline {
            let actual = active.clone();
            // This association is installed before any consuming request byte.
            // It is sticky even if transport subsequently becomes ambiguous.
            retain_first_dispatch(&mut state, durable_key.clone(), actual)?;
        }
        let host = retained_host(&state, durable_key, invocation)?;
        exchange_acquired(host, method, Some(&id), payload, requested, deadline)
    }
}

fn bounded_host_deadline(deadline: Instant) -> AppResult<String> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| error("TIME_BUDGET_EXCEEDED", "Host bootstrap deadline reached"))?;
    let remaining = remaining.min(Duration::from_secs(10));
    let nanoseconds = i64::try_from(remaining.as_nanos())
        .map_err(|_| error("TIME_BUDGET_EXCEEDED", "Host bootstrap deadline is invalid"))?;
    (time::OffsetDateTime::now_utc() + time::Duration::nanoseconds(nanoseconds))
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| error("HOST_UNAVAILABLE", "Host deadline is unavailable"))
}

pub struct HttpProviderPort {
    bridge: HostBridge,
    deadline: Option<Instant>,
}
impl HttpProviderPort {
    pub fn new(bridge: HostBridge) -> Self {
        Self {
            bridge,
            deadline: None,
        }
    }
    /// Construct per actual application request, never with a refreshed budget.
    pub fn with_deadline(bridge: HostBridge, deadline: Instant) -> Self {
        Self {
            bridge,
            deadline: Some(deadline),
        }
    }
    fn deadline(&self) -> Instant {
        self.deadline
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(10))
    }
    /// Current Cancel admission remains the composition's responsibility. The
    /// actual store proves which old route receives this cancellation request.
    pub fn request_cancel_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        _receipt: Option<&str>,
    ) -> AppResult<()> {
        let key = durable_invocation_key(store, invocation, self.deadline())?;
        let acquired = self.bridge.invocation_acquired_with_deadline(
            "operation.cancel",
            invocation,
            json!({"invocationId":invocation["invocationId"]}),
            false,
            self.deadline(),
            &key,
        )?;
        let acquired = retain_acquired_operation_truth(store, &key, acquired)?;
        let response = response_payload(acquired.into_response()?)?;
        if response["invocationId"] != invocation["invocationId"]
            || response["cancellationRequested"] != true
        {
            return Err(error(
                "CANCEL_UNCONFIRMED",
                "Original host did not acknowledge the cancellation request",
            ));
        }
        Ok(())
    }
}
impl ProviderPort for HttpProviderPort {
    fn registered_read_with_store(
        &mut self,
        _store: &mmmm_runtime::storage::DurableStore,
        request: &Value,
        context: &Value,
    ) -> AppResult<Value> {
        validate("RegisteredActionRequest", request)?;
        let id = context_id(context)?;
        let principal = PrincipalId::new(text(context, "principalRef")?)
            .map_err(|_| error("STALE_CONTEXT", "Context principal is invalid"))?;
        if request["contextId"] != id.as_str()
            || self
                .bridge
                .context_with_deadline(&principal, &id, self.deadline())?
                != *context
        {
            return Err(error("STALE_CONTEXT", "Registered read context changed"));
        }
        let result = self.bridge.inspect_with_deadline(
            &principal,
            &id,
            json!({"kind":"registered_read","request":request}),
            self.deadline(),
        )?;
        validate_registered_read_result(&result)?;
        Ok(result)
    }
    fn context(&mut self, principal: &PrincipalId, id: &ContextId) -> AppResult<Value> {
        self.bridge
            .context_with_deadline(principal, id, self.deadline())
    }
    fn action_descriptor(&mut self, step: &Value, context: &Value) -> AppResult<Value> {
        let id = context_id(context)?;
        let principal = PrincipalId::new(text(context, "principalRef")?)
            .map_err(|_| error("STALE_CONTEXT", "Context principal is invalid"))?;
        let live = self
            .bridge
            .context_with_deadline(&principal, &id, self.deadline())?;
        if live != *context {
            return Err(error("STALE_CONTEXT", "Action descriptor context changed"));
        }
        let binding = BindingId::new(text(step, "bindingId")?)
            .map_err(|_| error("INVALID_INPUT", "Action binding is invalid"))?;
        let action = ActionId::new(text(step, "actionId")?)
            .map_err(|_| error("INVALID_INPUT", "Action identity is invalid"))?;
        let response = self.bridge.describe_response_with_deadline(
            &principal,
            &id,
            &binding,
            &action,
            self.deadline(),
        )?;
        let descriptor = response_payload(response)?;
        validate("ActionDescriptor", &descriptor)?;
        Ok(descriptor)
    }
    fn observe_precondition(
        &mut self,
        precondition: &Value,
        context: &Value,
    ) -> AppResult<Sha256Digest> {
        validate("Precondition", precondition)?;
        let id = context_id(context)?;
        let principal = PrincipalId::new(text(context, "principalRef")?)
            .map_err(|_| error("STALE_CONTEXT", "Context principal is invalid"))?;
        let observed = self.bridge.inspect_with_deadline(
            &principal,
            &id,
            json!({"kind":"precondition", "precondition":precondition}),
            self.deadline(),
        )?;
        Sha256Digest::new(text(&observed, "observedDigest")?)
            .map_err(|_| error("OBSERVATION_INVALID", "Host precondition digest is invalid"))
    }
    fn verify_dependencies(&mut self, pins: &[Value], context: &Value) -> AppResult<()> {
        self.bridge
            .verify_registered_dependencies_with_deadline(pins, context, self.deadline())
    }
    fn dispatch(&mut self, _invocation: &Value) -> AppResult<Value> {
        Err(error(
            "STORE_REQUIRED",
            "Host dispatch requires the actual durable intent",
        ))
    }
    fn dispatch_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
    ) -> AppResult<Value> {
        let result = self
            .bridge
            .dispatch_durable(store, invocation, self.deadline())?;
        validate("ProviderResult", &result)?;
        Ok(result)
    }
    fn poll_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        receipt: Option<&str>,
    ) -> AppResult<Option<Value>> {
        let key = durable_invocation_key(store, invocation, self.deadline())?;
        let acquired = self.bridge.invocation_acquired_with_deadline(
            "operation.get",
            invocation,
            json!({"invocationId":invocation["invocationId"]}),
            false,
            self.deadline(),
            &key,
        )?;
        let acquired = retain_acquired_operation_truth(store, &key, acquired)?;
        let observed = response_payload(acquired.into_response()?)?;
        validate_job_observation(invocation, receipt, observed)
    }
    fn poll(&mut self, _invocation: &Value, _receipt: Option<&str>) -> AppResult<Option<Value>> {
        Err(error(
            "STORE_REQUIRED",
            "Original host polling requires its actual product store",
        ))
    }
    fn request_cancel(&mut self, _invocation: &Value, _receipt: Option<&str>) -> AppResult<()> {
        Err(error(
            "STORE_REQUIRED",
            "Original host cancellation requires its actual product store",
        ))
    }
    fn request_cancel_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        receipt: Option<&str>,
    ) -> AppResult<()> {
        HttpProviderPort::request_cancel_with_store(self, store, invocation, receipt)
    }
}

fn checked_host<'a>(
    state: &'a BridgeState,
    id: &ContextId,
    principal: Option<&PrincipalId>,
) -> AppResult<&'a PairedHost> {
    let host = state
        .hosts
        .get(id)
        .ok_or_else(|| error("CONTEXT_UNKNOWN", "No host is paired for this context"))?;
    if Instant::now() >= host.expires || principal.is_some_and(|p| p != &host.principal) {
        return Err(error(
            "PERMISSION_REQUIRED",
            "Paired host lease or principal is invalid",
        ));
    }
    Ok(host)
}
fn durable_invocation_key(
    store: &DurableStore,
    invocation: &Value,
    deadline: Instant,
) -> AppResult<OriginalInvocationKey> {
    validate("Invocation", invocation)?;
    let bytes = encode_json(invocation).map_err(|cause| {
        AppError::caused_by(
            "INVALID_INPUT",
            "Original Invocation cannot be encoded",
            cause,
        )
    })?;
    if bytes.len() as u64 > MAX_ORIGINAL_BYTES {
        return Err(error(
            "INVALID_INPUT",
            "Original Invocation exceeds the finite byte limit",
        ));
    }
    let operation = OperationId::new(text(invocation, "operationId")?)
        .map_err(|_| error("INVALID_INPUT", "Original operation identity is invalid"))?;
    let step = StepId::new(text(invocation, "stepId")?)
        .map_err(|_| error("INVALID_INPUT", "Original step identity is invalid"))?;
    let id = InvocationId::new(text(invocation, "invocationId")?)
        .map_err(|_| error("INVALID_INPUT", "Original invocation identity is invalid"))?;
    let actual = store
        .stored_invocation_checked(&operation, &step, MAX_ORIGINAL_BYTES, || {
            if Instant::now() >= deadline || crate::peer::fatal_stop_requested() {
                return Err(mmmm_runtime::storage::StorageError::InvalidTransition(
                    "Original host route admission budget ended".into(),
                ));
            }
            Ok(())
        })
        .map_err(|cause| AppError::storage("STALE_CONTEXT", cause))?;
    let blob = store
        .stored_invocation_blob(&operation, &step)
        .map_err(|cause| AppError::storage("STALE_CONTEXT", cause))?;
    if actual != *invocation
        || blob.digest != raw_digest(&bytes)
        || blob.byte_length != bytes.len() as u64
    {
        return Err(error(
            "STALE_CONTEXT",
            "Supplied Invocation differs from its retained durable bytes",
        ));
    }
    bounded_host_deadline(deadline)?;
    Ok(OriginalInvocationKey {
        data_root: store.data_root().to_path_buf(),
        operation,
        step,
        invocation: id,
        digest: blob.digest,
    })
}
fn retain_first_dispatch(
    state: &mut BridgeState,
    key: OriginalInvocationKey,
    host: PairedHost,
) -> AppResult<()> {
    if state.invocations.contains_key(&key) {
        return Err(error(
            "DISPATCH_ALREADY_ATTEMPTED",
            "Original host dispatch association is already retained",
        ));
    }
    if state.invocations.len() >= MAX_RETAINED_INVOCATIONS
        || (!state.retained_routes.contains_key(&host.generation)
            && state.retained_routes.len() >= MAX_RETAINED_ROUTES)
    {
        return Err(error(
            "HOST_CAPACITY",
            "Original host route retention capacity is exhausted",
        ));
    }
    let generation = host.generation;
    state.retained_routes.entry(generation).or_insert(host);
    state.invocations.insert(key, generation);
    Ok(())
}
/// Received truth may be retained after caller revocation or deadline. This
/// narrow operation pin creates no ResourceRef, grant, result acceptance or
/// effect-state transition. Its authority is the actual first-dispatch route
/// and immutable intent already checked before the consuming request.
fn retain_acquired_operation_truth(
    store: &mut DurableStore,
    key: &OriginalInvocationKey,
    acquired: HostReplyAcquisition,
) -> AppResult<HostReplyAcquisition> {
    let Some(response) = acquired.validated_response() else {
        // Unclassified raw bytes remain private zeroizing error evidence.
        return Ok(acquired);
    };
    let retained = (|| -> mmmm_runtime::storage::StorageResult<()> {
        if store.data_root() != key.data_root {
            return Err(mmmm_runtime::storage::StorageError::Conflict(
                "Acquired reply product store",
            ));
        }
        let original = store.stored_invocation_blob(&key.operation, &key.step)?;
        if original.digest != key.digest {
            return Err(mmmm_runtime::storage::StorageError::Conflict(
                "Acquired reply original intent digest",
            ));
        }
        // Only the validated public HostResponse body is encoded. Bearer
        // headers and malformed/unclassified HTTP bodies are never CAS input.
        let bytes = encode_json(response)
            .map_err(|cause| mmmm_runtime::storage::StorageError::Contract(cause.to_string()))?;
        if bytes.len() > crate::rpc::MAX_CONTROL_BYTES {
            return Err(mmmm_runtime::storage::StorageError::InvalidInput(
                "Acquired host reply exceeds the finite byte limit".into(),
            ));
        }
        let blob = store.put_blob(&bytes)?;
        store.append_operation_evidence(&key.operation, &blob)
    })();
    match retained {
        Ok(()) => Ok(acquired),
        Err(cause) => Err(AppError::caused_by(
            "EVIDENCE_RETENTION_FAILED",
            "Actual host reply could not be durably retained",
            HostTruthRetentionFailure { acquired, cause },
        )),
    }
}
struct HostTruthRetentionFailure {
    acquired: HostReplyAcquisition,
    cause: mmmm_runtime::storage::StorageError,
}
impl std::fmt::Debug for HostTruthRetentionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostTruthRetentionFailure")
            .field("acquired", &self.acquired)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for HostTruthRetentionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Original acquired host response and storage failure are preserved privately")
    }
}
impl std::error::Error for HostTruthRetentionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
fn retained_host<'a>(
    state: &'a BridgeState,
    key: &OriginalInvocationKey,
    invocation: &Value,
) -> AppResult<&'a PairedHost> {
    let generation = state.invocations.get(key).ok_or_else(|| {
        error(
            "ORIGINAL_ROUTE_UNAVAILABLE",
            "Original durable intent has no retained first-dispatch route",
        )
    })?;
    let host = state.retained_routes.get(generation).ok_or_else(|| {
        error(
            "ORIGINAL_ROUTE_UNAVAILABLE",
            "Original paired generation is unavailable",
        )
    })?;
    if host.generation != *generation
        || host.context != invocation["context"]
        || host.principal.as_str() != text(&invocation["context"], "principalRef")?
    {
        return Err(error(
            "STALE_CONTEXT",
            "Retained route differs from the immutable original Invocation",
        ));
    }
    // The old Apply lease is deliberately not reused. Current composition
    // grants the observation/cancellation; the actual old host also checks it.
    Ok(host)
}
fn validate_original_selector(selector: &Value, original: &Value) -> AppResult<()> {
    let object = selector
        .as_object()
        .ok_or_else(|| error("INVALID_INPUT", "Original inspection selector is invalid"))?;
    if selector["kind"] == "block_read" {
        // The actual legacy host's closed wire selector has no Invocation ID.
        // Its route is still selected from the exact same-store durable key;
        // its subject must equal the registered original action's native target.
        if original["actionId"] != "mmmm:block_patch"
            || object.len() != 3
            || ["kind", "dimension", "position"]
                .iter()
                .any(|key| !object.contains_key(*key))
        {
            return Err(error(
                "INVALID_INPUT",
                "Original block read is outside its registered action",
            ));
        }
        let source = crate::observer::BlockTarget::from_arguments(&original["arguments"])?;
        let selected = crate::observer::BlockTarget::from_arguments(selector)?;
        if selected != source {
            return Err(error(
                "PERMISSION_REQUIRED",
                "Original block read target differs from its durable action",
            ));
        }
        return Ok(());
    }
    let (allowed, identity_field) = match selector["kind"].as_str() {
        Some("undo_material") => (
            ["kind", "sourceInvocationId"].as_slice(),
            "sourceInvocationId",
        ),
        Some("native_targets") => (
            ["kind", "targets", "sourceInvocationId"].as_slice(),
            "sourceInvocationId",
        ),
        Some("undo_job") => (["kind", "invocationId"].as_slice(), "invocationId"),
        _ => {
            return Err(error(
                "INVALID_INPUT",
                "Original inspection kind is not registered",
            ));
        }
    };
    if object.len() != allowed.len()
        || allowed.iter().any(|key| !object.contains_key(*key))
        || selector[identity_field] != original["invocationId"]
    {
        return Err(error(
            "INVALID_INPUT",
            "Original inspection does not identify the exact durable Invocation",
        ));
    }
    Ok(())
}
fn exchange_acquired(
    host: &PairedHost,
    method: &str,
    id: Option<&ContextId>,
    payload: Value,
    deadline_at: &str,
    deadline: Instant,
) -> AppResult<HostReplyAcquisition> {
    let request = host_request(method, id, payload, deadline_at)?;
    let reply = host.client.call_acquired(&request).map_err(|cause| {
        AppError::caused_by(
            "HOST_RESULT_UNKNOWN",
            "Authenticated host call did not yield a complete response",
            cause,
        )
    })?;
    // No renewed grant or post-acquisition timeout can erase this received
    // reply. Normal public success calls consume it through into_response.
    Ok(HostReplyAcquisition {
        reply,
        deadline,
        generation: host.generation,
    })
}
fn response_payload(response: Value) -> AppResult<Value> {
    if response["status"] != "ok" {
        return Err(AppError::caused_by(
            "HOST_REQUEST_FAILED",
            "The original host rejected or could not complete the request",
            HostRequestFailure { response },
        ));
    }
    response
        .get("payload")
        .cloned()
        .ok_or_else(|| error("HOST_RESPONSE_INVALID", "Host response payload is absent"))
}
struct HostRequestFailure {
    response: Value,
}
impl std::fmt::Debug for HostRequestFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostRequestFailure")
            .field("status", &self.response["status"])
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for HostRequestFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Original bounded host failure response is retained privately")
    }
}
impl std::error::Error for HostRequestFailure {}
fn exchange(
    client: &HostRpcClient,
    method: &str,
    id: Option<&ContextId>,
    payload: Value,
    deadline: Option<&str>,
) -> AppResult<Value> {
    let response = exchange_response(client, method, id, payload, deadline)?;
    response_payload(response)
}
fn exchange_response(
    client: &HostRpcClient,
    method: &str,
    id: Option<&ContextId>,
    payload: Value,
    deadline: Option<&str>,
) -> AppResult<Value> {
    let deadline = match deadline {
        Some(deadline) => deadline.to_owned(),
        None => (time::OffsetDateTime::now_utc() + time::Duration::seconds(10))
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| error("HOST_UNAVAILABLE", "Host deadline is unavailable"))?,
    };
    let request = host_request(method, id, payload, &deadline)?;
    let acquired = client.call_acquired(&request).map_err(|cause| {
        AppError::caused_by(
            "HOST_RESULT_UNKNOWN",
            "Authenticated host call did not yield a validated response",
            cause,
        )
    })?;
    let response = acquired.into_preserved_response().map_err(|cause| {
        AppError::caused_by(
            "HOST_RESULT_UNKNOWN",
            "Authenticated host call did not yield a validated response",
            cause,
        )
    })?;
    Ok(response)
}
fn host_request(
    method: &str,
    id: Option<&ContextId>,
    payload: Value,
    deadline: &str,
) -> AppResult<Value> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|_| error("HOST_UNAVAILABLE", "Request identity is unavailable"))?;
    let request_id: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    Ok(
        json!({"protocolVersion":"0.2.0","requestId":request_id,"method":method,"contextId":id.map(ContextId::as_str),"payload":payload,"deadlineAt":deadline}),
    )
}
fn context_id(context: &Value) -> AppResult<ContextId> {
    ContextId::new(text(context, "contextId")?)
        .map_err(|_| error("STALE_CONTEXT", "Context identity is invalid"))
}
fn text<'a>(value: &'a Value, key: &str) -> AppResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| error("HOST_RESPONSE_INVALID", "Required host field is absent"))
}
fn validate(definition: &str, value: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .and_then(|v| v.validate(definition, value))
        .map_err(|_| {
            error(
                "HOST_CONTRACT_INVALID",
                "Host value violates its canonical contract",
            )
        })
}
fn error(code: &'static str, message: &'static str) -> AppError {
    AppError::new(code, message)
}
fn validate_registered_read_result(result: &Value) -> AppResult<()> {
    validate("ProviderResult", result)?;
    if result["status"] == "job_accepted"
        || result["effects"] != "none"
        || result.get("jobHandle").is_some()
    {
        return Err(error(
            "OBSERVATION_INVALID",
            "Registered read returned a job or write-effect claim",
        ));
    }
    // A valid failed read preserves its original diagnostics and error status.
    Ok(())
}
fn validate_job_observation(
    invocation: &Value,
    receipt: Option<&str>,
    observed: Value,
) -> AppResult<Option<Value>> {
    if observed["invocationId"] != invocation["invocationId"]
        || !observed["providerCompleted"].is_boolean()
    {
        return Err(error(
            "OBSERVATION_INVALID",
            "Host job observation does not identify the original invocation",
        ));
    }
    let Some(result) = observed.get("result") else {
        return Ok(None);
    };
    validate("ProviderResult", result)?;
    if receipt.is_some_and(|expected| {
        result["jobHandle"]
            .as_str()
            .is_some_and(|actual| actual != expected)
    }) {
        return Err(error(
            "OBSERVATION_INVALID",
            "Host job handle differs from the retained receipt",
        ));
    }
    Ok(Some(result.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_pairing_provenance_keeps_host_bridge_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HostBridge>();
        assert_send_sync::<CompletedPairingObservation>();
    }
    fn local_route_witness() -> (HostBridge, HostContextWitness) {
        // This fixture checks local transaction fencing only. No listener or
        // native game is started, and no native observation is claimed.
        let bridge = HostBridge::default();
        let context: Value =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/execution-context.json"))
                .unwrap();
        let hello: Value =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/host-hello.json"))
                .unwrap();
        let id = context_id(&context).unwrap();
        let principal = PrincipalId::new(text(&context, "principalRef").unwrap()).unwrap();
        let client = HostRpcClient::paired(
            crate::endpoint::EndpointRecord {
                schema_version: 1,
                contract_version: "0.2.0".into(),
                address: "127.0.0.1:9".parse().unwrap(),
                path: "/rpc".into(),
                coordinator_epoch: "host-fixture-epoch".into(),
                credential_ref: "MMMM.coordinator.peer-fixture".into(),
            },
            crate::credential::SecretToken::generate().unwrap(),
        )
        .unwrap();
        let mut generation = [0; 16];
        getrandom::fill(&mut generation).unwrap();
        bridge.state.lock().unwrap().hosts.insert(
            id.clone(),
            PairedHost {
                client: Arc::new(client),
                principal: principal.clone(),
                context: context.clone(),
                hello,
                expires: Instant::now() + Duration::from_secs(30),
                generation,
                completed_pairing: None,
            },
        );
        let witness = HostContextWitness {
            state: bridge.state.clone(),
            context_id: id,
            principal,
            context,
            generation,
        };
        (bridge, witness)
    }
    #[test]
    fn local_checkpoint_accepts_exact_route_without_transport() {
        let (_bridge, witness) = local_route_witness();
        witness.check_local().unwrap();
        witness.clone().check_local().unwrap();
    }
    #[test]
    fn same_context_and_principal_do_not_revive_a_replaced_route() {
        let (bridge, witness) = local_route_witness();
        bridge
            .state
            .lock()
            .unwrap()
            .hosts
            .get_mut(&witness.context_id)
            .unwrap()
            .generation[0] ^= 1;
        assert_eq!(
            witness.check_local().unwrap_err().code,
            "SESSION_ROUTE_CHANGED"
        );
        bridge.detach(&witness.context_id).unwrap();
        assert!(witness.check_local().is_err());
    }
    #[test]
    fn local_checkpoint_rejects_expired_route_and_changed_epoch() {
        let (bridge, witness) = local_route_witness();
        {
            let mut state = bridge.state.lock().unwrap();
            let host = state.hosts.get_mut(&witness.context_id).unwrap();
            host.context["environment"]["sessionEpoch"] = json!("new-host-epoch");
        }
        assert_eq!(
            witness.check_local().unwrap_err().code,
            "SESSION_ROUTE_CHANGED"
        );
        {
            let mut state = bridge.state.lock().unwrap();
            let host = state.hosts.get_mut(&witness.context_id).unwrap();
            host.context = witness.context.clone();
            host.expires = Instant::now();
        }
        assert!(witness.check_local().is_err());
    }
    #[test]
    fn dependency_pin_cannot_change_provenance_or_claim_an_unimplemented_contract() {
        let digest = mmmm_contracts::raw_digest(b"actual owned implementation source");
        let dependency = VerifiedDependency::new(
            "mmmm.planner".into(),
            digest.clone(),
            DependencyProvenance::OwnedDomain,
            ["FN09".to_owned(), "FN15".to_owned()].into(),
        )
        .unwrap();
        let mut pin = json!({"componentId":"mmmm.planner","implementationDigest":digest,"provenanceClass":"owned_domain","contractIds":["FN09"]});
        assert!(dependency.matches(&pin));
        pin["provenanceClass"] = json!("platform_shim");
        assert!(!dependency.matches(&pin));
        pin["provenanceClass"] = json!("owned_domain");
        pin["contractIds"] = json!(["FN18"]);
        assert!(!dependency.matches(&pin));
    }
    #[test]
    fn valid_failed_registered_read_preserves_native_reason_without_resending() {
        // The ordinary example contains a successful read only; this negative
        // report checks the status/diagnostic boundary rather than native game.
        let failed = json!({"contractVersion":"0.2.0","status":"failed","data":{},"effects":"none","diagnostics":[{"severity":"error","code":"ACTUAL_NATIVE_READ_DENIED","message":"Current native read permission ended"}],"artifacts":[]});
        validate_registered_read_result(&failed).unwrap();
        assert_eq!(
            failed["diagnostics"][0]["code"],
            "ACTUAL_NATIVE_READ_DENIED"
        );
        let mut unsupported = failed.clone();
        unsupported["effects"] = json!("unknown");
        assert!(validate_registered_read_result(&unsupported).is_err());
    }
    fn route_fixture_invocation() -> Value {
        mmmm_contracts::parse_json(include_bytes!("../../../examples/invocation.json")).unwrap()
    }
    fn route_fixture_key(invocation: &Value) -> OriginalInvocationKey {
        // This local-map fixture does not assert durable admission or game
        // effects. Production keys are issued only by actual stored intent.
        OriginalInvocationKey {
            data_root: std::env::temp_dir().join("mmmm-route-map-only-fixture"),
            operation: OperationId::new(text(invocation, "operationId").unwrap()).unwrap(),
            step: StepId::new(text(invocation, "stepId").unwrap()).unwrap(),
            invocation: InvocationId::new(text(invocation, "invocationId").unwrap()).unwrap(),
            digest: raw_digest(&encode_json(invocation).unwrap()),
        }
    }
    #[test]
    fn retained_original_generation_survives_rotation_without_new_dispatch() {
        let (bridge, witness) = local_route_witness();
        let original = route_fixture_invocation();
        let key = route_fixture_key(&original);
        let mut state = bridge.state.lock().unwrap();
        let host = state.hosts[&witness.context_id].clone();
        retain_first_dispatch(&mut state, key.clone(), host).unwrap();
        state.hosts.get_mut(&witness.context_id).unwrap().generation[0] ^= 1;
        let active = state.hosts[&witness.context_id].clone();
        assert_eq!(
            retained_host(&state, &key, &original).unwrap().generation,
            witness.generation
        );
        assert_eq!(
            retain_first_dispatch(&mut state, key.clone(), active)
                .unwrap_err()
                .code,
            "DISPATCH_ALREADY_ATTEMPTED"
        );
        // An old Apply lease does not grant a new dispatch or erase received
        // operation identity. Fresh observation permission is separate.
        state
            .retained_routes
            .get_mut(&witness.generation)
            .unwrap()
            .expires = Instant::now();
        assert!(retained_host(&state, &key, &original).is_ok());
        drop(state);
        assert_eq!(
            witness.check_local().unwrap_err().code,
            "SESSION_ROUTE_CHANGED"
        );
    }
    #[test]
    fn retained_route_rejects_another_store_and_changed_original_context() {
        let (bridge, witness) = local_route_witness();
        let mut original = route_fixture_invocation();
        let key = route_fixture_key(&original);
        let mut state = bridge.state.lock().unwrap();
        let host = state.hosts[&witness.context_id].clone();
        retain_first_dispatch(&mut state, key.clone(), host).unwrap();
        let mut other_store = key.clone();
        other_store.data_root = other_store.data_root.join("different-product-store");
        assert_eq!(
            retained_host(&state, &other_store, &original)
                .err()
                .unwrap()
                .code,
            "ORIGINAL_ROUTE_UNAVAILABLE"
        );
        original["context"]["environment"]["sessionEpoch"] = json!("different-host-epoch");
        assert_eq!(
            retained_host(&state, &key, &original).err().unwrap().code,
            "STALE_CONTEXT"
        );
    }
    #[test]
    fn retained_generation_capacity_preserves_all_old_routes() {
        let (bridge, witness) = local_route_witness();
        let mut original = route_fixture_invocation();
        let mut state = bridge.state.lock().unwrap();
        let first = state.hosts[&witness.context_id].clone();
        for index in 0..MAX_RETAINED_ROUTES {
            original["invocationId"] = json!(format!("route-capacity-{index}"));
            let key = route_fixture_key(&original);
            let mut route = first.clone();
            route.generation[0] = index as u8;
            retain_first_dispatch(&mut state, key, route).unwrap();
        }
        let mut ninth = first;
        ninth.generation[0] = MAX_RETAINED_ROUTES as u8;
        original["invocationId"] = json!("route-capacity-overflow");
        assert_eq!(
            retain_first_dispatch(&mut state, route_fixture_key(&original), ninth)
                .unwrap_err()
                .code,
            "HOST_CAPACITY"
        );
        assert_eq!(state.retained_routes.len(), MAX_RETAINED_ROUTES);
        assert_eq!(state.invocations.len(), MAX_RETAINED_ROUTES);
    }
    #[test]
    fn original_selector_cannot_select_a_different_job_or_mutation() {
        let original = route_fixture_invocation();
        validate_original_selector(
            &json!({"kind":"undo_job","invocationId":original["invocationId"]}),
            &original,
        )
        .unwrap();
        validate_original_selector(
            &json!({"kind":"undo_material","sourceInvocationId":original["invocationId"]}),
            &original,
        )
        .unwrap();
        assert!(
            validate_original_selector(
                &json!({"kind":"undo_job","invocationId":"another-job"}),
                &original
            )
            .is_err()
        );
        assert!(
            validate_original_selector(
                &json!({"kind":"dispatch","sourceInvocationId":original["invocationId"]}),
                &original
            )
            .is_err()
        );
        assert!(validate_original_selector(&json!({"kind":"undo_material","sourceInvocationId":original["invocationId"],"authority":true}), &original).is_err());
    }
    #[test]
    fn storeless_write_poll_and_cancel_fail_before_transport() {
        let mut provider = HttpProviderPort::new(HostBridge::default());
        let original = route_fixture_invocation();
        assert_eq!(
            provider.dispatch(&original).unwrap_err().code,
            "STORE_REQUIRED"
        );
        assert_eq!(
            provider.poll(&original, None).unwrap_err().code,
            "STORE_REQUIRED"
        );
        assert_eq!(
            provider.request_cancel(&original, None).unwrap_err().code,
            "STORE_REQUIRED"
        );
    }
    #[test]
    fn legacy_original_block_read_requires_the_exact_registered_subject() {
        let mut original = route_fixture_invocation();
        original["actionId"] = json!("mmmm:block_patch");
        original["arguments"] = json!({"dimension":"minecraft:overworld","position":[1,2,3],"desiredState":"minecraft:stone"});
        let selector =
            json!({"kind":"block_read","dimension":"minecraft:overworld","position":[1,2,3]});
        validate_original_selector(&selector, &original).unwrap();
        let mut other_position = selector.clone();
        other_position["position"] = json!([1, 2, 4]);
        assert!(validate_original_selector(&other_position, &original).is_err());
        let mut extra_identity = selector.clone();
        extra_identity["sourceInvocationId"] = original["invocationId"].clone();
        assert!(validate_original_selector(&extra_identity, &original).is_err());
        original["actionId"] = json!("mmmm:unregistered_action");
        assert!(validate_original_selector(&selector, &original).is_err());
    }
    fn received_loopback_reply() -> HostReplyAcquisition {
        // Static handoff examples cannot exercise acquisition after validation.
        // This bounded loopback protocol fixture receives real framed bytes;
        // it neither pairs a native game nor issues an observation marker.
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(cause) if cause.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "bounded reply fixture accept");
                        std::thread::yield_now();
                    }
                    Err(cause) => panic!("reply fixture accept: {cause}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let raw = crate::http::read_header(
                &mut stream,
                deadline,
                &std::sync::atomic::AtomicBool::new(false),
            )
            .unwrap();
            let (_, headers) =
                crate::http::parse_headers(std::str::from_utf8(&raw).unwrap()).unwrap();
            let length = crate::http::content_length(&headers).unwrap();
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            let request = mmmm_contracts::parse_json(&body).unwrap();
            let response = json!({"protocolVersion":"0.2.0","requestId":request["params"]["requestId"],
                "status":"ok","eventSequence":"0","payload":{"privateReceivedMarker":"received-fixture-truth"}});
            let bytes = encode_json(&json!({"jsonrpc":"2.0","id":request["id"],"result":response}))
                .unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            );
            stream.write_all(header.as_bytes()).unwrap();
            stream.write_all(&bytes).unwrap();
            stream.shutdown(std::net::Shutdown::Both).unwrap();
        });
        let client = HostRpcClient::paired(
            crate::endpoint::EndpointRecord {
                schema_version: 1,
                contract_version: "0.2.0".into(),
                address,
                path: "/rpc".into(),
                coordinator_epoch: "received-reply-fixture".into(),
                credential_ref: "MMMM.coordinator.received-fixture".into(),
            },
            crate::credential::SecretToken::generate().unwrap(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let request = host_request(
            "hello",
            None,
            json!({}),
            &bounded_host_deadline(deadline).unwrap(),
        )
        .unwrap();
        let reply = client.call_acquired(&request).unwrap();
        server.join().unwrap();
        // The receipt is now at its normal consumption checkpoint. An elapsed
        // outer budget cannot erase bytes acquired and validated just above.
        HostReplyAcquisition {
            reply,
            deadline: Instant::now(),
            generation: [1; 16],
        }
    }
    #[test]
    fn elapsed_budget_preserves_received_reply_for_internal_truth_consumption() {
        let acquired = received_loopback_reply();
        assert!(acquired.received_byte_length() > 0);
        assert_eq!(
            acquired.check_normal_deadline().unwrap_err().code,
            "TIME_BUDGET_EXCEEDED"
        );
        let response = acquired.into_acquired_response().unwrap();
        assert_eq!(
            response["payload"]["privateReceivedMarker"],
            "received-fixture-truth"
        );
    }
    #[test]
    fn normal_deadline_error_owns_the_received_reply_without_printing_it() {
        let error = received_loopback_reply().into_response().unwrap_err();
        assert_eq!(error.code, "TIME_BUDGET_EXCEEDED");
        let source = std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<HostReplyAcquisition>()
            .unwrap();
        assert_eq!(
            source.validated_response().unwrap()["payload"]["privateReceivedMarker"],
            "received-fixture-truth"
        );
        assert!(!format!("{error:?}").contains("received-fixture-truth"));
    }
}

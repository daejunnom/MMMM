use crate::{
    auth::{AuthError, SessionAuthority, SessionHandle, SessionPolicy},
    bootstrap::HostBootstrapProcessor,
    credential::{CredentialRef, CredentialStore},
    endpoint::{EndpointError, EndpointRecord, RuntimeDirectory},
    http::LoopbackServer,
    peer_management::{
        BootstrapBudget, BootstrapWitness, CompletedBootstrap, ManagementError, ManagementReceiver,
        ManagementRequest, PublicFrame, management_channel,
    },
    service::{ApplicationService, RequestBudget, ServiceError},
};
use mmmm_contracts::{PlanId, ProjectId, RequestId, SessionEpoch, Sha256Digest};
use std::{
    collections::BTreeMap,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

#[derive(Debug)]
pub enum CoordinatorError {
    Endpoint(EndpointError),
    Authentication(AuthError),
    Credential,
    Listener(io::Error),
    Cleanup,
}
impl std::fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Endpoint(e) => write!(f, "Coordinator discovery failed: {e}"),
            Self::Authentication(e) => {
                let code = match e {
                    AuthError::InvalidCapability => "AUTHENTICATION_REQUIRED",
                    AuthError::SessionLimit => "SESSION_LIMIT",
                    AuthError::InvalidPolicy => "INVALID_SESSION_POLICY",
                };
                write!(f, "Coordinator session failed ({code}): {e}")
            }
            Self::Credential => f.write_str("Native local credential API is unavailable"),
            Self::Listener(_) => f.write_str("Coordinator loopback listener failed"),
            Self::Cleanup => f.write_str(
                "Coordinator shutdown left unresolved local discovery or credential cleanup",
            ),
        }
    }
}
impl std::error::Error for CoordinatorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Endpoint(error) => Some(error),
            Self::Authentication(error) => Some(error),
            Self::Listener(error) => Some(error),
            Self::Credential | Self::Cleanup => None,
        }
    }
}

/// The service has acquired its DurableStore lock before start() can publish
/// anything. Runtime discovery is fixed beneath that same root, preventing a
/// second data root from replacing another Coordinator's discovery metadata.
pub struct Coordinator {
    service: ApplicationService,
    server: LoopbackServer,
    authority: SessionAuthority,
    runtime: RuntimeDirectory,
    credentials: Option<Box<dyn CredentialStore>>,
    peer: Option<crate::peer::PeerBootstrap>,
    reference: CredentialRef,
    record: EndpointRecord,
    stop: Arc<AtomicBool>,
    management: Option<HostManagement>,
}
struct HostManagement {
    processor: HostBootstrapProcessor,
    receiver: ManagementReceiver,
    session: SessionHandle,
    installed_policy: SessionPolicy,
    calibration_plans: BTreeMap<RequestId, CalibrationPlanAttempt>,
}
const MAX_RETAINED_CALIBRATION_PLANS: usize = 32;
/// These process-local diagnostics retain the original typed service failure
/// and native delivery outcome. The immutable saved plan lives in the Store;
/// this record is neither a second ledger nor a recoverable execution grant.
struct CalibrationPlanAttempt {
    witness: BootstrapWitness,
    original_witness: BootstrapWitness,
    owner: Option<crate::auth::AuthenticatedPrincipal>,
    committed: Option<(PlanId, Sha256Digest)>,
    failure: Option<ServiceError>,
    delivery_failure: Option<ManagementError>,
    native_failure: Option<crate::peer::PeerError>,
    original_completion: Option<(bool, Instant)>,
    delivery_completed: bool,
}
impl CalibrationPlanAttempt {
    fn allow_receipt_redelivery(&self) -> Result<(), ManagementError> {
        if self.delivery_completed {
            Ok(())
        } else {
            Err(ManagementError::Busy)
        }
    }
    fn begin_receipt_redelivery(
        &mut self,
        witness: &BootstrapWitness,
    ) -> Result<(), ManagementError> {
        self.allow_receipt_redelivery()?;
        self.witness = witness.clone();
        self.delivery_completed = false;
        Ok(())
    }
    /// Returns true only for an originally successful saved result whose one
    /// native delivery completed without a retained failure. Later receipt
    /// delivery cannot erase an earlier source/native failure or completion.
    fn observe_completion(
        &mut self,
        finished: &CompletedBootstrap,
        budget: &BootstrapBudget,
    ) -> bool {
        if self.witness.id() != finished.witness().id()
            || self.witness.nonce() != finished.witness().nonce()
            || self.witness.offer_digest() != finished.witness().offer_digest()
        {
            self.delivery_failure
                .get_or_insert(ManagementError::WrongReply);
            return false;
        }
        self.delivery_completed = true;
        self.original_completion
            .get_or_insert((finished.delivered(), finished.completed_at()));
        if let Some(failure) = finished.failure() {
            self.native_failure.get_or_insert(failure);
        }
        if !finished.delivered() && self.delivery_failure.is_none() {
            self.delivery_failure = Some(
                budget
                    .check()
                    .err()
                    .unwrap_or(ManagementError::Disconnected),
            );
        }
        finished.delivered()
            && self.committed.is_some()
            && self.failure.is_none()
            && self.delivery_failure.is_none()
            && self.native_failure.is_none()
    }
}
fn committed_calibration_plan(error: &ServiceError) -> Option<(PlanId, Sha256Digest)> {
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(error);
    for _ in 0..8 {
        let current = cause?;
        if let Some(saved) = current.downcast_ref::<mmmm_application::SetupCommittedPlanFailure>() {
            return Some((saved.plan_id().clone(), saved.plan_hash().clone()));
        }
        cause = current.source();
    }
    None
}
impl HostManagement {
    fn prepare_calibration_plan(
        &mut self,
        service: &mut ApplicationService,
        authority: &SessionAuthority,
        offer: crate::peer_management::HostOffer,
        budget: &BootstrapBudget,
    ) -> Result<PublicFrame, ManagementError> {
        let witness = offer.witness().clone();
        let frame = offer.public().value();
        let selection = mmmm_application::SetupSelection {
            project_id: ProjectId::new(
                frame["projectId"]
                    .as_str()
                    .ok_or(ManagementError::InvalidFrame)?,
            )
            .map_err(|_| ManagementError::InvalidFrame)?,
            expected_revision: Sha256Digest::new(
                frame["expectedRevision"]
                    .as_str()
                    .ok_or(ManagementError::InvalidFrame)?,
            )
            .map_err(|_| ManagementError::InvalidFrame)?,
            context_id: mmmm_contracts::ContextId::new(
                frame["contextId"]
                    .as_str()
                    .ok_or(ManagementError::InvalidFrame)?,
            )
            .map_err(|_| ManagementError::InvalidFrame)?,
        };
        if frame["dataRoot"].as_str().map(std::path::Path::new) != Some(service.data_root()) {
            return Err(ManagementError::InvalidFrame);
        }
        // The CLI derives this public nonce from the Project/revision/context
        // locators; the exact data root also remains bound by the offer digest. If result
        // delivery was lost, the same live OS owner can recover the retained
        // immutable locator without planning again or replaying an effect.
        let previous = self.calibration_plans.iter().find_map(|(id, attempt)| {
            (attempt.original_witness.nonce() == witness.nonce()
                && attempt.original_witness.offer_digest() == witness.offer_digest()
                && attempt.committed.is_some())
            .then(|| id.clone())
        });
        if let Some(previous) = previous {
            budget.check()?;
            self.calibration_plans
                .get(&previous)
                .ok_or(ManagementError::WrongReply)?
                .allow_receipt_redelivery()?;
            let principal = authority
                .installed_principal(&self.session)
                .map_err(|_| ManagementError::InvalidFrame)?;
            if !principal.permits("plan.create")
                || !principal.permits_context(selection.context_id.as_str())
            {
                return Err(ManagementError::InvalidFrame);
            }
            if !self
                .calibration_plans
                .get(&previous)
                .and_then(|attempt| attempt.owner.as_ref())
                .is_some_and(|owner| owner.same_session(&principal))
            {
                return Err(ManagementError::InvalidFrame);
            }
            self.calibration_plans
                .get_mut(&previous)
                .ok_or(ManagementError::WrongReply)?
                .begin_receipt_redelivery(&witness)?;
            let attempt = self
                .calibration_plans
                .remove(&previous)
                .ok_or(ManagementError::WrongReply)?;
            let reply = calibration_plan_reply(
                &witness,
                &selection.project_id,
                attempt.committed.as_ref(),
                attempt.failure.is_some(),
            );
            self.calibration_plans.insert(witness.id().clone(), attempt);
            return reply;
        }
        // Reserve retention capacity before the helper can freeze anything.
        if self.calibration_plans.len() >= MAX_RETAINED_CALIBRATION_PLANS {
            return Err(ManagementError::Busy);
        }
        let principal = authority.installed_principal(&self.session);
        let owner = principal.as_ref().ok().cloned();
        let result = (|| {
            let request = RequestBudget::from_bootstrap(budget)?;
            let principal = principal.map_err(|error| {
                ServiceError::caused_by(
                    "AUTHENTICATION_REQUIRED",
                    "Current installed native owner session is unavailable",
                    error,
                )
            })?;
            let hosts = self.processor.calibration_planning_hosts();
            service.prepare_calibration_plan(&principal, &selection, &request, &hosts)
        })();
        let (committed, failure) = match result {
            Ok(receipt) => (
                Some((receipt.plan_id().clone(), receipt.plan_hash().clone())),
                None,
            ),
            Err(error) => (committed_calibration_plan(&error), Some(error)),
        };
        let reply = calibration_plan_reply(
            &witness,
            &selection.project_id,
            committed.as_ref(),
            failure.is_some(),
        );
        self.calibration_plans.insert(
            witness.id().clone(),
            CalibrationPlanAttempt {
                original_witness: witness.clone(),
                witness,
                owner,
                committed,
                failure,
                delivery_failure: reply.as_ref().err().copied(),
                native_failure: None,
                original_completion: None,
                delivery_completed: false,
            },
        );
        reply
    }
    fn finish_calibration_plan(
        &mut self,
        finished: &CompletedBootstrap,
        budget: &BootstrapBudget,
    ) -> bool {
        let Some(attempt) = self.calibration_plans.get_mut(finished.witness().id()) else {
            return false;
        };
        if attempt.observe_completion(finished, budget) {
            self.calibration_plans.remove(finished.witness().id());
        }
        true
    }
}
fn calibration_plan_reply(
    witness: &BootstrapWitness,
    project: &ProjectId,
    committed: Option<&(PlanId, Sha256Digest)>,
    checkpoint_failed: bool,
) -> Result<PublicFrame, ManagementError> {
    let (plan, hash) = committed.ok_or(ManagementError::InvalidFrame)?;
    PublicFrame::from_value(serde_json::json!({
        "kind":"native_calibration_plan_prepared", "protocolVersion":mmmm_contracts::CONTRACT_VERSION,
        "nonce":witness.nonce(), "purpose":crate::peer_management::CALIBRATION_PLAN_PURPOSE,
        "projectId":project, "planId":plan, "planHash":hash,
        "outcome":if checkpoint_failed { "committed_checkpoint_failed" } else { "prepared" }
    }))
}
impl Coordinator {
    pub fn start(
        service: ApplicationService,
        policy: SessionPolicy,
    ) -> Result<Self, CoordinatorError> {
        Self::start_internal(service, policy, None)
    }
    /// Host attachment uses the existing singleton and OS-authenticated peer
    /// listener. Its capacity-one worker never opens SQLite or grants authority.
    pub fn start_with_bootstrap(
        service: ApplicationService,
        processor: HostBootstrapProcessor,
    ) -> Result<Self, CoordinatorError> {
        let policy = processor
            .current_session_policy()
            .map_err(|_| CoordinatorError::Credential)?;
        Self::start_internal(service, policy, Some(processor))
    }
    fn start_internal(
        service: ApplicationService,
        policy: SessionPolicy,
        processor: Option<HostBootstrapProcessor>,
    ) -> Result<Self, CoordinatorError> {
        let runtime = RuntimeDirectory::open(&service.data_root().join("runtime"))
            .map_err(CoordinatorError::Endpoint)?;
        let server = LoopbackServer::bind().map_err(CoordinatorError::Listener)?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| CoordinatorError::Credential)?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let reference = CredentialRef::new(&format!("MMMM.coordinator.peer-{suffix}"))
            .map_err(|_| CoordinatorError::Credential)?;
        let mut authority = SessionAuthority::new(64).map_err(CoordinatorError::Authentication)?;
        let installed_policy = policy.clone();
        let (token, session) = authority
            .install_with_handle(policy)
            .map_err(CoordinatorError::Authentication)?;
        match runtime.load() {
            Ok(previous) => {
                let old = CredentialRef::new(&previous.credential_ref)
                    .map_err(|_| CoordinatorError::Credential)?;
                // The default mode cannot claim cleanup of an optional native
                // store that was supplied by a different trusted composition.
                // Preserve its exact discovery record for explicit resolution.
                if !old.as_str().starts_with("MMMM.coordinator.peer-") {
                    return Err(CoordinatorError::Cleanup);
                }
                crate::peer::PeerBootstrap::cleanup_stale(runtime.path(), &old)
                    .map_err(|_| CoordinatorError::Cleanup)?;
                runtime
                    .remove_if_epoch(&previous.coordinator_epoch)
                    .map_err(CoordinatorError::Endpoint)?;
            }
            Err(EndpointError::Missing) => (),
            Err(error) => return Err(CoordinatorError::Endpoint(error)),
        }
        let (peer, management) = match processor {
            Some(processor) => {
                let (sender, receiver) = management_channel();
                let peer = crate::peer::PeerBootstrap::start_with_management(
                    &runtime, &reference, token, sender,
                )
                .map_err(|_| CoordinatorError::Credential)?;
                (
                    peer,
                    Some(HostManagement {
                        processor,
                        receiver,
                        session,
                        installed_policy,
                        calibration_plans: BTreeMap::new(),
                    }),
                )
            }
            None => (
                crate::peer::PeerBootstrap::start(&runtime, &reference, token)
                    .map_err(|_| CoordinatorError::Credential)?,
                None,
            ),
        };
        let record = EndpointRecord {
            schema_version: 1,
            contract_version: mmmm_contracts::CONTRACT_VERSION.to_owned(),
            address: server.address(),
            path: "/rpc".to_owned(),
            coordinator_epoch: server.epoch().to_owned(),
            credential_ref: reference.as_str().to_owned(),
        };
        if let Err(error) = runtime.publish(&record) {
            authority.revoke_all();
            if peer.shutdown().is_err() {
                return Err(CoordinatorError::Cleanup);
            }
            return Err(CoordinatorError::Endpoint(error));
        }
        Ok(Self {
            service,
            server,
            authority,
            runtime,
            credentials: None,
            peer: Some(peer),
            reference,
            record,
            stop: Arc::new(AtomicBool::new(false)),
            management,
        })
    }
    /// Explicit native-store composition is available for deployments that have
    /// independently verified its platform availability. It is never a fallback
    /// after peer authentication fails, and is not required by the default CLI.
    pub fn start_with_native(
        service: ApplicationService,
        policy: SessionPolicy,
        credentials: Box<dyn CredentialStore>,
    ) -> Result<Self, CoordinatorError> {
        let runtime = RuntimeDirectory::open(&service.data_root().join("runtime"))
            .map_err(CoordinatorError::Endpoint)?;
        let server = LoopbackServer::bind().map_err(CoordinatorError::Listener)?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| CoordinatorError::Credential)?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let epoch = server.epoch().to_owned();
        let reference = CredentialRef::new(&format!("MMMM.coordinator.native-{suffix}"))
            .map_err(|_| CoordinatorError::Credential)?;
        let mut authority = SessionAuthority::new(64).map_err(CoordinatorError::Authentication)?;
        let token = authority
            .install(policy)
            .map_err(CoordinatorError::Authentication)?;
        credentials
            .put(&reference, &token)
            .map_err(|_| CoordinatorError::Credential)?;
        // Exact stale record cleanup is permissible only after the singleton
        // data-root lock. Malformed or unknown discovery is preserved for a
        // diagnostic; no port scan, lease stealing, or broad directory cleanup.
        let publication = (|| {
            match runtime.load() {
                Ok(previous) => {
                    let prior_ref = CredentialRef::new(&previous.credential_ref)
                        .map_err(|_| CoordinatorError::Credential)?;
                    if prior_ref.as_str().starts_with("MMMM.coordinator.peer-") {
                        crate::peer::PeerBootstrap::cleanup_stale(runtime.path(), &prior_ref)
                            .map_err(|_| CoordinatorError::Cleanup)?;
                    } else if prior_ref.as_str().starts_with("MMMM.coordinator.native-") {
                        credentials
                            .remove(&prior_ref)
                            .map_err(|_| CoordinatorError::Credential)?;
                    } else {
                        return Err(CoordinatorError::Cleanup);
                    }
                    runtime
                        .remove_if_epoch(&previous.coordinator_epoch)
                        .map_err(CoordinatorError::Endpoint)?;
                }
                Err(EndpointError::Missing) => (),
                Err(error) => return Err(CoordinatorError::Endpoint(error)),
            }
            let record = EndpointRecord {
                schema_version: 1,
                contract_version: mmmm_contracts::CONTRACT_VERSION.to_owned(),
                address: server.address(),
                path: "/rpc".to_owned(),
                coordinator_epoch: epoch,
                credential_ref: reference.as_str().to_owned(),
            };
            runtime
                .publish(&record)
                .map_err(CoordinatorError::Endpoint)?;
            Ok(record)
        })();
        let record = match publication {
            Ok(record) => record,
            Err(error) => {
                authority.revoke_all();
                // A failed native cleanup remains an error, not a successful
                // unpublished startup; the secret is never logged or returned.
                if credentials.remove(&reference).is_err() {
                    return Err(CoordinatorError::Cleanup);
                }
                return Err(error);
            }
        };
        Ok(Self {
            service,
            server,
            authority,
            runtime,
            credentials: Some(credentials),
            peer: None,
            reference,
            record,
            stop: Arc::new(AtomicBool::new(false)),
            management: None,
        })
    }
    pub fn endpoint(&self) -> &EndpointRecord {
        &self.record
    }
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }
    pub fn serve(&mut self) -> Result<(), CoordinatorError> {
        self.serve_bounded(None)
    }
    /// Native daemon ownership supplies one original finite lifetime. Ingress,
    /// application budgets and response delivery all share its remaining bound.
    /// Expiration stops new admission; explicit shutdown still drains peer owners
    /// and retains unresolved operation/discovery evidence on cleanup failure.
    pub fn serve_until(&mut self, deadline: Instant) -> Result<(), CoordinatorError> {
        self.serve_bounded(Some(deadline))
    }
    fn serve_bounded(&mut self, lifetime: Option<Instant>) -> Result<(), CoordinatorError> {
        while !self.stop.load(Ordering::Acquire) && !crate::peer::fatal_stop_requested() {
            if lifetime.is_some_and(|deadline| Instant::now() >= deadline) {
                self.request_shutdown();
                break;
            }
            self.process_management()?;
            if self
                .management
                .as_ref()
                .is_some_and(|management| management.processor.has_pending_completion())
            {
                // Only the issued Complete's bounded native terminal exchange
                // defers new calls. An already executing operation is never
                // interrupted by a pairing exchange.
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            let admitted = match lifetime {
                Some(deadline) => self.server.serve_one_until(
                    &self.authority,
                    &mut self.service,
                    &self.stop,
                    deadline,
                ),
                None => self
                    .server
                    .serve_one(&self.authority, &mut self.service, &self.stop),
            }
            .map_err(CoordinatorError::Listener)?;
            if !admitted {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        if crate::peer::fatal_stop_requested() {
            Err(CoordinatorError::Cleanup)
        } else {
            Ok(())
        }
    }
    fn process_management(&mut self) -> Result<(), CoordinatorError> {
        let Some(management) = &mut self.management else {
            return Ok(());
        };
        if let Some(envelope) = management
            .receiver
            .try_receive()
            .map_err(|_| CoordinatorError::Cleanup)?
        {
            let budget = envelope.budget().clone();
            let epoch = SessionEpoch::new(&self.record.coordinator_epoch)
                .map_err(|_| CoordinatorError::Credential)?;
            // A cancelled queued Offer/Installed is discarded before borrowing
            // the Store. Its native owner still delivers Finished for rollback.
            if let Ok((request, responder)) = envelope.into_parts() {
                let reply_deadline = responder
                    .as_ref()
                    .map(|responder| responder.deadline())
                    .unwrap_or(budget.deadline());
                let witness_id = request.witness().id().clone();
                let reply = match request {
                    ManagementRequest::Offer(offer) if offer.public().is_calibration_plan() => {
                        management
                            .prepare_calibration_plan(
                                &mut self.service,
                                &self.authority,
                                offer,
                                &budget,
                            )
                            .map(Some)
                    }
                    ManagementRequest::Finished(finished)
                        if finished.witness().is_calibration_plan() =>
                    {
                        management.finish_calibration_plan(&finished, &budget);
                        Ok(None)
                    }
                    request => management.processor.handle_with_reply_deadline(
                        self.service.management_store(),
                        request,
                        &epoch,
                        &budget,
                        reply_deadline,
                    ),
                };
                if let Some(responder) = responder {
                    // Delivery is not activation. The subsequent actual native
                    // ACK and EOF observation activates or rolls back its grant.
                    let wire_reply = reply.and_then(|frame| {
                        frame.ok_or(crate::peer_management::ManagementError::WrongReply)
                    });
                    if let Err(error) = responder.respond(wire_reply)
                        && let Some(attempt) = management.calibration_plans.get_mut(&witness_id)
                    {
                        attempt.delivery_failure.get_or_insert(error);
                    }
                } else {
                    reply.map_err(|_| CoordinatorError::Cleanup)?;
                }
            }
        }
        // Drain the native terminal receipt before retiring its pending state:
        // actual completion time, not main-loop scheduling, binds its deadline.
        management
            .processor
            .cleanup_expired()
            .map_err(|_| CoordinatorError::Cleanup)?;
        let policy = management
            .processor
            .current_session_policy()
            .map_err(|_| CoordinatorError::Credential)?;
        if !same_policy_identity(&management.installed_policy, &policy) {
            self.authority
                .replace(&management.session, policy.clone())
                .map_err(CoordinatorError::Authentication)?;
            management.installed_policy = policy;
        }
        Ok(())
    }
    pub fn request_shutdown(&self) {
        self.stop.store(true, Ordering::Release);
    }
    /// Explicit shutdown reports cleanup errors to composition. No Drop hook
    /// silently converts an unresolved cleanup into successful lifecycle evidence.
    pub fn shutdown(mut self) -> Result<(), CoordinatorError> {
        self.request_shutdown();
        self.authority.revoke_all();
        let credential_failed = self
            .credentials
            .as_ref()
            .is_some_and(|store| store.remove(&self.reference).is_err());
        let peer_failed = self
            .peer
            .take()
            .is_some_and(|peer| peer.shutdown().is_err());
        let management_failed = self.management.as_mut().is_some_and(|management| {
            // The native owner is now drained or has explicitly reported
            // uncertainty. No terminal receipt may activate authority during
            // shutdown; retire its queue and exact owned generations instead.
            if let Ok(Some(envelope)) = management.receiver.try_receive() {
                envelope.budget().cancel();
                drop(envelope);
            }
            management.processor.shutdown().is_err()
        });
        if credential_failed || peer_failed || management_failed {
            // A record is tokenless, but identifies the exact native resource
            // and generation still requiring cleanup. Retain it on failure.
            return Err(CoordinatorError::Cleanup);
        }
        self.runtime
            .remove_if_epoch(&self.record.coordinator_epoch)
            .map_err(|_| CoordinatorError::Cleanup)?;
        Ok(())
    }
}
fn same_policy_identity(left: &SessionPolicy, right: &SessionPolicy) -> bool {
    left.principal == right.principal
        && left.allowed_methods == right.allowed_methods
        && left.allowed_contexts == right.allowed_contexts
}

#[cfg(test)]
mod calibration_delivery_tests {
    use super::*;
    use crate::peer_management::HostOffer;

    // Reuses the bounded management channel and closed public locator frame;
    // no Store/host fixture is introduced for this delivery-only state test.
    #[test]
    fn receipt_redelivery_preserves_original_typed_failure_and_native_completion() {
        let public = PublicFrame::from_value(serde_json::json!({
            "kind":"native_calibration_plan_offer", "protocolVersion":"0.2.0", "nonce":"retained-plan",
            "purpose":crate::peer_management::CALIBRATION_PLAN_PURPOSE,
            "dataRoot":std::env::temp_dir(), "projectId":"project-fixture",
            "expectedRevision":"a".repeat(64), "contextId":"context-fixture"
        })).unwrap();
        let offer = HostOffer::calibration_plan(public).unwrap();
        let witness = offer.witness().clone();
        let saved = (
            PlanId::new("plan-fixture").unwrap(),
            Sha256Digest::new("b".repeat(64)).unwrap(),
        );
        let cause = ServiceError::caused_by(
            "SETUP_PLAN_COMMITTED",
            "Saved before checkpoint failure",
            io::Error::from_raw_os_error(123),
        );
        let mut attempt = CalibrationPlanAttempt {
            witness: witness.clone(),
            original_witness: witness.clone(),
            owner: None,
            committed: Some(saved.clone()),
            failure: Some(cause),
            delivery_failure: None,
            native_failure: None,
            original_completion: None,
            delivery_completed: false,
        };
        let (sender, receiver) = management_channel();
        let original = BootstrapBudget::new();
        // A second exchange cannot move the original witness while its native
        // ACK/EOF and Finished observation are still pending.
        assert_eq!(
            attempt.allow_receipt_redelivery(),
            Err(ManagementError::Busy)
        );
        sender
            .notify_finished_with_failure(
                &witness,
                false,
                &original,
                Some(crate::peer::PeerError::Native(456)),
            )
            .unwrap();
        let (request, _) = receiver
            .try_receive()
            .unwrap()
            .unwrap()
            .into_parts()
            .unwrap();
        let ManagementRequest::Finished(finished) = request else {
            unreachable!()
        };
        assert!(finished.witness().is_calibration_plan());
        assert!(!attempt.observe_completion(&finished, &original));
        assert!(attempt.allow_receipt_redelivery().is_ok());
        let first_completion = attempt.original_completion.unwrap();
        assert_eq!(
            attempt.native_failure,
            Some(crate::peer::PeerError::Native(456))
        );
        assert_eq!(attempt.committed, Some(saved.clone()));
        assert_eq!(
            std::error::Error::source(attempt.failure.as_ref().unwrap())
                .unwrap()
                .downcast_ref::<io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(123)
        );
        let recovered = calibration_plan_reply(
            &witness,
            &ProjectId::new("project-fixture").unwrap(),
            attempt.committed.as_ref(),
            true,
        )
        .unwrap();
        assert_eq!(recovered.value()["outcome"], "committed_checkpoint_failed");
        assert_eq!(recovered.value()["planId"], saved.0.as_str());
        let later = BootstrapBudget::new();
        let retry_offer = HostOffer::calibration_plan(
            PublicFrame::from_value(offer.public().value().clone()).unwrap(),
        )
        .unwrap();
        let retry_witness = retry_offer.witness().clone();
        attempt.begin_receipt_redelivery(&retry_witness).unwrap();
        assert_eq!(attempt.original_completion, Some(first_completion));
        assert_eq!(
            attempt.allow_receipt_redelivery(),
            Err(ManagementError::Busy)
        );
        assert!(attempt.begin_receipt_redelivery(&witness).is_err());
        assert_eq!(attempt.witness.id(), retry_witness.id());
        sender
            .notify_finished(&retry_witness, true, &later)
            .unwrap();
        let (request, _) = receiver
            .try_receive()
            .unwrap()
            .unwrap()
            .into_parts()
            .unwrap();
        let ManagementRequest::Finished(finished) = request else {
            unreachable!()
        };
        assert!(!attempt.observe_completion(&finished, &later));
        assert!(attempt.allow_receipt_redelivery().is_ok());
        assert_eq!(attempt.original_completion, Some(first_completion));
        assert_eq!(
            attempt.native_failure,
            Some(crate::peer::PeerError::Native(456))
        );
        assert_eq!(
            attempt.failure.as_ref().unwrap().code,
            "SETUP_PLAN_COMMITTED"
        );
        assert_eq!(attempt.committed, Some(saved));
    }
}

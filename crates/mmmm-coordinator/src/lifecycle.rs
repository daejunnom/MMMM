use crate::{
    auth::{AuthError, SessionAuthority, SessionHandle, SessionPolicy},
    bootstrap::HostBootstrapProcessor,
    credential::{CredentialRef, CredentialStore},
    endpoint::{EndpointError, EndpointRecord, RuntimeDirectory},
    http::LoopbackServer,
    peer_management::{ManagementReceiver, management_channel},
    service::ApplicationService,
};
use mmmm_contracts::SessionEpoch;
use std::{
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
                let reply = management.processor.handle_with_reply_deadline(
                    self.service.management_store(),
                    request,
                    &epoch,
                    &budget,
                    reply_deadline,
                );
                if let Some(responder) = responder {
                    // Delivery is not activation. The subsequent actual native
                    // ACK and EOF observation activates or rolls back its grant.
                    let wire_reply = reply.and_then(|frame| {
                        frame.ok_or(crate::peer_management::ManagementError::WrongReply)
                    });
                    let _ = responder.respond(wire_reply);
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

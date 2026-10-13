use crate::credential::SecretToken;
use mmmm_contracts::{ContextId, PrincipalId};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// Constructed only by trusted local composition/pairing, never deserialized
/// from request JSON. Authentication proves identity; application policy still
/// checks current project/action grants and actual host permissions.
#[derive(Clone, Debug)]
pub struct SessionPolicy {
    pub principal: PrincipalId,
    pub allowed_methods: BTreeSet<String>,
    pub allowed_contexts: BTreeSet<ContextId>,
    pub lifetime: Duration,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedPrincipal {
    principal: PrincipalId,
    methods: BTreeSet<String>,
    contexts: BTreeSet<ContextId>,
    expires_at: Instant,
    active: Arc<AtomicBool>,
}
impl AuthenticatedPrincipal {
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }
    pub fn permits(&self, method: &str) -> bool {
        self.is_current() && self.methods.contains(method)
    }
    /// A context identifier is a locator. Pairing restricts which locators may
    /// be requested; the actual context and permissions are loaded by the host
    /// and application's AuthorityPort, never copied out of request data.
    pub fn permits_context(&self, context: &str) -> bool {
        self.is_current() && self.contexts.iter().any(|id| id.as_str() == context)
    }
    pub fn is_current(&self) -> bool {
        self.active.load(Ordering::Acquire) && Instant::now() < self.expires_at
    }
    /// Identity equality alone cannot authorize a session-issued source receipt.
    /// Two live sessions for one principal have distinct private generations.
    pub fn same_session(&self, other: &Self) -> bool {
        self.is_current() && other.is_current() && Arc::ptr_eq(&self.active, &other.active)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    InvalidCapability,
    SessionLimit,
    InvalidPolicy,
}
impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidCapability => "Local authentication is required",
            Self::SessionLimit => "Local session capacity is exhausted",
            Self::InvalidPolicy => "Local session policy is invalid",
        })
    }
}
impl std::error::Error for AuthError {}

/// Opaque capability hashes live only in this Coordinator generation. A restart
/// creates a new authority, so a stale discovery record cannot revive a session.
pub struct SessionAuthority {
    sessions: BTreeMap<[u8; 32], AuthenticatedPrincipal>,
    maximum: usize,
}
/// An in-process authority handle, separate from the secret capability. It is
/// never serialized or accepted from a public request.
pub struct SessionHandle {
    digest: [u8; 32],
}
impl SessionAuthority {
    pub fn new(maximum: usize) -> Result<Self, AuthError> {
        if !(1..=256).contains(&maximum) {
            return Err(AuthError::InvalidPolicy);
        }
        Ok(Self {
            sessions: BTreeMap::new(),
            maximum,
        })
    }
    pub fn install(&mut self, policy: SessionPolicy) -> Result<SecretToken, AuthError> {
        self.install_with_handle(policy).map(|(token, _)| token)
    }
    pub fn install_with_handle(
        &mut self,
        policy: SessionPolicy,
    ) -> Result<(SecretToken, SessionHandle), AuthError> {
        self.sessions
            .retain(|_, session| Instant::now() < session.expires_at);
        if self.sessions.len() >= self.maximum {
            return Err(AuthError::SessionLimit);
        }
        validate_policy(&policy)?;
        let token = SecretToken::generate().map_err(|_| AuthError::InvalidCapability)?;
        let digest = capability_digest(&token);
        if self.sessions.contains_key(&digest) {
            return Err(AuthError::InvalidCapability);
        }
        self.sessions.insert(digest, authenticated(policy));
        Ok((token, SessionHandle { digest }))
    }
    /// Only the trusted main loop can replace a pairing generation. Existing
    /// authenticated clones are revoked before future calls see the new policy.
    /// This does not approve a plan or copy authority from a facade DTO.
    pub fn replace(
        &mut self,
        handle: &SessionHandle,
        policy: SessionPolicy,
    ) -> Result<(), AuthError> {
        validate_policy(&policy)?;
        let old = self
            .sessions
            .get_mut(&handle.digest)
            .ok_or(AuthError::InvalidCapability)?;
        // This handle is private trusted composition, separate from the bearer.
        // A freshly authenticated native pairing may replace an expired epoch
        // policy; it cannot revive a removed or explicitly revoked handle.
        if !old.active.load(Ordering::Acquire) {
            return Err(AuthError::InvalidCapability);
        }
        old.active.store(false, Ordering::Release);
        *old = authenticated(policy);
        Ok(())
    }
    pub fn authenticate(&self, bearer: &str) -> Result<AuthenticatedPrincipal, AuthError> {
        let token = SecretToken::parse(bearer).map_err(|_| AuthError::InvalidCapability)?;
        self.authenticate_token(&token)
    }
    pub fn authenticate_token(
        &self,
        token: &SecretToken,
    ) -> Result<AuthenticatedPrincipal, AuthError> {
        let digest = capability_digest(token);
        self.sessions
            .get(&digest)
            .filter(|s| s.is_current())
            .cloned()
            .ok_or(AuthError::InvalidCapability)
    }
    pub fn revoke(&mut self, token: &SecretToken) {
        if let Some(session) = self.sessions.remove(&capability_digest(token)) {
            session.active.store(false, Ordering::Release);
        }
    }
    pub fn revoke_all(&mut self) {
        for session in self.sessions.values() {
            session.active.store(false, Ordering::Release);
        }
        self.sessions.clear();
    }
}
fn validate_policy(policy: &SessionPolicy) -> Result<(), AuthError> {
    if policy.allowed_methods.is_empty()
        || policy.allowed_methods.len() > 64
        || policy.allowed_contexts.len() > 256
        || policy.lifetime.is_zero()
        || policy.lifetime > Duration::from_secs(24 * 60 * 60)
        || policy.allowed_methods.iter().any(|m| {
            m.is_empty()
                || m.len() > 96
                || !m
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.')
        })
    {
        return Err(AuthError::InvalidPolicy);
    }
    Ok(())
}
fn authenticated(policy: SessionPolicy) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        principal: policy.principal,
        methods: policy.allowed_methods,
        contexts: policy.allowed_contexts,
        expires_at: Instant::now() + policy.lifetime,
        active: Arc::new(AtomicBool::new(true)),
    }
}
impl Drop for SessionAuthority {
    fn drop(&mut self) {
        self.revoke_all();
    }
}

fn capability_digest(token: &SecretToken) -> [u8; 32] {
    Sha256::digest(token.expose_secret()).into()
}

#[cfg(test)]
mod replacement_tests {
    use super::*;
    #[test]
    fn private_pairing_handle_replaces_expired_policy_without_reviving_old_clone() {
        let mut authority = SessionAuthority::new(1).unwrap();
        let policy = SessionPolicy {
            principal: PrincipalId::new("native-owner").unwrap(),
            allowed_methods: ["project.inspect".into()].into(),
            allowed_contexts: BTreeSet::new(),
            lifetime: Duration::from_secs(10),
        };
        let (token, handle) = authority.install_with_handle(policy.clone()).unwrap();
        let original = authority.sessions.get_mut(&handle.digest).unwrap();
        original.expires_at = Instant::now() - Duration::from_secs(1);
        let expired = original.clone();
        assert!(authority.authenticate_token(&token).is_err());
        authority.replace(&handle, policy.clone()).unwrap();
        assert!(authority.authenticate_token(&token).is_ok());
        assert!(!expired.is_current());
        authority.revoke_all();
        assert!(authority.replace(&handle, policy).is_err());
    }
    #[test]
    fn source_receipt_session_identity_rejects_concurrent_and_replaced_generations() {
        let mut authority = SessionAuthority::new(3).unwrap();
        let policy = SessionPolicy {
            principal: PrincipalId::new("native-owner").unwrap(),
            allowed_methods: ["artifact.read".into()].into(),
            allowed_contexts: BTreeSet::new(),
            lifetime: Duration::from_secs(10),
        };
        let (first, handle) = authority.install_with_handle(policy.clone()).unwrap();
        let second = authority.install(policy.clone()).unwrap();
        let issued = authority.authenticate_token(&first).unwrap();
        let same = authority.authenticate_token(&first).unwrap();
        let other = authority.authenticate_token(&second).unwrap();
        assert!(issued.same_session(&same));
        assert_eq!(issued.principal(), other.principal());
        assert!(!issued.same_session(&other));
        authority.replace(&handle, policy).unwrap();
        let replaced = authority.authenticate_token(&first).unwrap();
        assert!(!issued.same_session(&same));
        assert!(!issued.same_session(&replaced));
        assert!(replaced.same_session(&replaced.clone()));
        authority.revoke(&first);
        assert!(!replaced.same_session(&replaced));
    }
}

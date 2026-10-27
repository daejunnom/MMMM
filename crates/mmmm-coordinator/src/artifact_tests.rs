//! The original examples do not exercise a live capability revoked between
//! CAS admission and final slice delivery. These fixtures use real registered
//! CAS bytes and the production session/reader adapters; no game is simulated.
use super::*;
use crate::artifacts::ArtifactCallContext;
use mmmm_runtime::artifact::{
    ArtifactReader, ArtifactResult, ResourceAuthority, ResourceOwner, register_resource,
};
use std::sync::atomic::AtomicUsize;

struct TestReadAuthority {
    calls: Arc<AtomicUsize>,
    revoke_on: usize,
    session: Option<(SessionAuthority, SecretToken)>,
}
impl ResourceAuthority for TestReadAuthority {
    fn authorize_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        _context: &ContextId,
        owner: &ResourceOwner,
        _resource: &Value,
    ) -> ArtifactResult<()> {
        assert_eq!(owner, &ResourceOwner::Principal(principal.clone()));
        let call = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        if call == self.revoke_on {
            let (authority, token) = self.session.as_mut().unwrap();
            authority.revoke(token);
        }
        Ok(())
    }
}
fn resource(store: &mut DurableStore, principal: &PrincipalId) -> Value {
    let bytes = b"actual retained artifact bytes";
    let blob = store.put_blob(bytes).unwrap();
    let resource = json!({"resourceId":"resource-artifact-test", "sha256":blob.digest,
        "mediaType":"text/plain", "sizeBytes":blob.byte_length});
    register_resource(
        store,
        &resource,
        ResourceOwner::Principal(principal.clone()),
    )
    .unwrap();
    resource
}
fn read_request() -> Value {
    json!({"contextId":"context-artifact-test", "resourceId":"resource-artifact-test", "offset":"0", "limitBytes":65536})
}

#[test]
fn artifact_reader_uses_live_authenticated_principal_and_actual_registered_cas() {
    let root = TestRoot::new();
    let (authority, _token, principal) = session(&["artifact.read"], &["context-artifact-test"]);
    let mut store = DurableStore::open(root.config()).unwrap();
    let expected = resource(&mut store, principal.principal());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut reader = ArtifactReader::new(
        Box::new(TestReadAuthority {
            calls: calls.clone(),
            revoke_on: 0,
            session: None,
        }),
        1024,
    )
    .unwrap();
    let budget = budget();
    let rpc = ArtifactCallContext {
        principal: &principal,
        budget: &budget,
    };
    let result = reader.read(&store, &rpc, &read_request()).unwrap();
    assert_eq!(result["resource"], expected);
    assert_eq!(result["data"], "actual retained artifact bytes");
    assert_eq!(calls.load(Ordering::Acquire), 2);
    drop(authority);
    assert_eq!(
        reader.read(&store, &rpc, &read_request()).unwrap_err().code,
        "RESOURCE_FORBIDDEN"
    );
    assert_eq!(calls.load(Ordering::Acquire), 2);
}

#[test]
fn artifact_slice_is_withheld_after_revocation_at_either_authority_checkpoint() {
    for revoke_on in [1, 2] {
        let root = TestRoot::new();
        let (authority, token, principal) = session(&["artifact.read"], &["context-artifact-test"]);
        let mut store = DurableStore::open(root.config()).unwrap();
        resource(&mut store, principal.principal());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut reader = ArtifactReader::new(
            Box::new(TestReadAuthority {
                calls: calls.clone(),
                revoke_on,
                session: Some((authority, token)),
            }),
            1024,
        )
        .unwrap();
        let budget = budget();
        let rpc = ArtifactCallContext {
            principal: &principal,
            budget: &budget,
        };
        assert_eq!(
            reader.read(&store, &rpc, &read_request()).unwrap_err().code,
            "RESOURCE_FORBIDDEN"
        );
        assert_eq!(calls.load(Ordering::Acquire), revoke_on);
        assert!(!principal.is_current());
    }
}

#[test]
fn expired_authenticated_clone_cannot_start_an_artifact_read() {
    let root = TestRoot::new();
    let mut authority = SessionAuthority::new(1).unwrap();
    let mut installed = policy(&["artifact.read"], &["context-artifact-test"]);
    installed.lifetime = Duration::from_millis(1);
    let token = authority.install(installed).unwrap();
    let principal = authority.authenticate_token(&token).unwrap();
    let mut store = DurableStore::open(root.config()).unwrap();
    resource(&mut store, principal.principal());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut reader = ArtifactReader::new(
        Box::new(TestReadAuthority {
            calls: calls.clone(),
            revoke_on: 0,
            session: None,
        }),
        1024,
    )
    .unwrap();
    thread::sleep(Duration::from_millis(5));
    let budget = budget();
    let rpc = ArtifactCallContext {
        principal: &principal,
        budget: &budget,
    };
    assert_eq!(
        reader.read(&store, &rpc, &read_request()).unwrap_err().code,
        "RESOURCE_FORBIDDEN"
    );
    assert_eq!(calls.load(Ordering::Acquire), 0);
}

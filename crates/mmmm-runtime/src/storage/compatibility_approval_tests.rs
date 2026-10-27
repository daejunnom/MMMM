//! 기존 native-owned-source SQLite/CAS/bootstrap/Batch fixture와 정본 Java
//! compatibility 예제를 재사용한다. 이 trusted test port는 storage의 승인
//! 보존/원자성/current-source 경계를 검사하며 native Java 관측을 만들지 않는다.

use super::*;
use crate::storage::compatibility_approval::{
    CompatibilityApprovalAuthority, CompatibilityApprovalRecord, CompatibilityApprovalRegistration,
    CompatibilityApprovalRpcContext, MAX_COMPATIBILITY_PROFILE_BYTES, compatibility_approval,
    compatibility_approval_references, register_compatibility_approval,
};

struct Rpc {
    state: Rc<ScopeState>,
    claimed: Option<PrincipalId>,
}
impl CompatibilityApprovalRpcContext for Rpc {
    fn check(&self) -> StorageResult<()> {
        self.state.check()
    }
    fn authenticated_local_owner(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.claimed.as_ref().unwrap_or(&self.state.owner).clone())
    }
}
#[derive(Clone, Copy)]
enum Failure {
    None,
    ExplicitApproval,
    Policy,
    Source,
    CancelPublished,
    OwnerPublished,
}
struct Authority {
    permit: TestPermit,
    project_revision: Sha256Digest,
    policy_resource: Value,
    expected: CompatibilityApprovalRegistration,
    failure: Failure,
}
impl Authority {
    fn check(
        &mut self,
        store: &DurableStore,
        owner: &PrincipalId,
        request: &CompatibilityApprovalRegistration,
        registering: bool,
    ) -> StorageResult<()> {
        self.permit.check_store(store)?;
        if owner != &self.permit.0.owner
            || request.project_id != self.expected.project_id
            || request.approved_profile_ref != self.expected.approved_profile_ref
            || request.profile_resource != self.expected.profile_resource
            || request.profile_digest != self.expected.profile_digest
            || request.artifact_digest != self.expected.artifact_digest
            || request.allowed_interface_digest != self.expected.allowed_interface_digest
            || request.policy_revision != self.expected.policy_revision
            || request.scope_digest != self.expected.scope_digest
        {
            return Err(StorageError::Conflict("Fixture exact approval pins"));
        }
        if registering && matches!(self.failure, Failure::ExplicitApproval) {
            return Err(StorageError::Conflict(
                "Fixture explicit native approval absent",
            ));
        }
        let mut reader = self
            .permit
            .resource_reader(MAX_COMPATIBILITY_PROFILE_BYTES)?;
        reader.read_project(
            store,
            &self.permit,
            &request.project_id,
            &self.project_revision,
            8 * 1024 * 1024,
        )?;
        if matches!(self.failure, Failure::Policy) {
            return Err(StorageError::Conflict("Fixture current Policy ACL revoked"));
        }
        let policy_query = ProjectResourceQuery::Current {
            resource_id: serde_json::from_value(self.policy_resource["resourceId"].clone())
                .unwrap(),
        };
        let policy = reader.read(
            store,
            &self.permit,
            &ProjectResourceRequest {
                project: &request.project_id,
                current_project_revision: &self.project_revision,
                query: &policy_query,
                expected: Some(&self.policy_resource),
            },
            MAX_COMPATIBILITY_PROFILE_BYTES,
        )?;
        if policy.registered.blob.digest != request.policy_revision {
            return Err(StorageError::Conflict(
                "Fixture current exact Policy differs",
            ));
        }
        if matches!(self.failure, Failure::Source) {
            return Err(StorageError::Conflict(
                "Fixture current source rights revoked",
            ));
        }
        let query = ProjectResourceQuery::Current {
            resource_id: serde_json::from_value(request.profile_resource["resourceId"].clone())
                .unwrap(),
        };
        let loaded = reader.read(
            store,
            &self.permit,
            &ProjectResourceRequest {
                project: &request.project_id,
                current_project_revision: &self.project_revision,
                query: &query,
                expected: Some(&request.profile_resource),
            },
            MAX_COMPATIBILITY_PROFILE_BYTES,
        )?;
        let profile = store
            .validator
            .parse_and_validate("CompatibilityProfile", &loaded.bytes)
            .map_err(|e| StorageError::Contract(e.to_string()))?;
        if projected_digest("CompatibilityProfile", &profile).unwrap() != request.profile_digest
            || profile["action"]["implementationDigest"] != request.artifact_digest.as_str()
        {
            return Err(StorageError::Conflict(
                "Fixture actual profile and implementation differ",
            ));
        }
        // 실제 provisional row로 publication을 확인하며 callback 횟수를 가정하지 않는다.
        let table: bool = store.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='compatibility_approvals')",
            [],
            |r| r.get(0),
        )?;
        let published: bool = table && store.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM compatibility_approvals WHERE native_owner=?1 AND project_id=?2 AND approved_profile_ref=?3)",
            params![owner.as_str(), request.project_id.as_str(), request.approved_profile_ref], |r| r.get(0))?;
        if registering && published {
            match self.failure {
                Failure::CancelPublished => self.permit.0.cancelled.set(true),
                Failure::OwnerPublished => {
                    store.connection.execute(
                    "UPDATE native_project_owners SET owner_principal='revoked-approval-test-owner' WHERE project_id=?1",
                    [request.project_id.as_str()])?;
                }
                _ => (),
            }
        }
        self.permit.check_store(store)
    }
}
impl CompatibilityApprovalAuthority for Authority {
    fn authorize_registration(
        &mut self,
        store: &DurableStore,
        owner: &PrincipalId,
        request: &CompatibilityApprovalRegistration,
    ) -> StorageResult<()> {
        self.check(store, owner, request, true)
    }
    fn authorize_read(
        &mut self,
        store: &DurableStore,
        owner: &PrincipalId,
        record: &CompatibilityApprovalRecord,
    ) -> StorageResult<()> {
        let request = CompatibilityApprovalRegistration {
            project_id: record.project_id().clone(),
            approved_profile_ref: record.approved_profile_ref().into(),
            profile_resource: record.profile_resource().clone(),
            profile_digest: record.profile_digest().clone(),
            artifact_digest: record.artifact_digest().clone(),
            allowed_interface_digest: record.allowed_interface_digest().clone(),
            policy_revision: record.policy_revision().clone(),
            scope_digest: record.scope_digest().clone(),
        };
        self.check(store, owner, &request, false)
    }
}
fn seed() -> (TestRoot, DurableStore, Rpc, Authority) {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    let profile = example("compat-public-java.json");
    let bytes = raw_json(&profile);
    let resource = json!({"resourceId":"compatibility-profile-source", "sha256":raw_digest(&bytes),
        "mediaType":"application/vnd.mmmm.compatibility-profile+json", "sizeBytes":bytes.len()});
    let batch = Batch::from_sources(&base, vec![], vec![(resource.clone(), bytes)]);
    let committed = batch
        .commit(&mut store, &TestPermit::new(&root, &initial), &base)
        .unwrap();
    let permit = TestPermit::new(&root, &initial);
    let rpc = Rpc {
        state: permit.0.clone(),
        claimed: None,
    };
    let expected = CompatibilityApprovalRegistration {
        project_id: initial.project_id.clone(),
        approved_profile_ref: "approval-fixture".into(),
        profile_resource: resource,
        profile_digest: projected_digest("CompatibilityProfile", &profile).unwrap(),
        artifact_digest: serde_json::from_value(profile["action"]["implementationDigest"].clone())
            .unwrap(),
        allowed_interface_digest: canonical_digest(&json!({"fixtureInterface":"public_java"}))
            .unwrap(),
        policy_revision: serde_json::from_value(initial.policy_resource["sha256"].clone()).unwrap(),
        scope_digest: canonical_digest(
            &json!({"projectId":initial.project_id,"fixtureScope":"native_source_read"}),
        )
        .unwrap(),
    };
    let authority = Authority {
        permit,
        project_revision: committed.project_revision,
        policy_resource: initial.policy_resource,
        expected,
        failure: Failure::None,
    };
    (root, store, rpc, authority)
}
fn rows(store: &DurableStore) -> Vec<String> {
    let exists: bool = store
        .connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='compatibility_approvals')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    if !exists {
        return vec![];
    }
    store.connection.prepare("SELECT record_json FROM compatibility_approvals ORDER BY native_owner,project_id,approved_profile_ref")
        .unwrap().query_map([], |r| r.get(0)).unwrap().collect::<Result<_,_>>().unwrap()
}
fn read(
    store: &DurableStore,
    rpc: &Rpc,
    authority: &mut Authority,
) -> StorageResult<Option<CompatibilityApprovalRecord>> {
    let request = authority.expected.clone();
    compatibility_approval(
        store,
        rpc,
        authority,
        &request.project_id,
        &request.approved_profile_ref,
    )
}

#[test]
fn imported_cas_and_caller_approval_labels_do_not_create_a_registry_or_native_authority() {
    let (_root, mut store, rpc, mut authority) = seed();
    store
        .put_blob(
            br#"{"approvedProfileRef":"approval-fixture","localUseOnly":true,"approved":true}"#,
        )
        .unwrap();
    assert!(read(&store, &rpc, &mut authority).unwrap().is_none());
    assert!(
        compatibility_approval_references(&store, &rpc, &authority.expected.project_id)
            .unwrap()
            .is_empty()
    );
    let exists: bool = store
        .connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='compatibility_approvals')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!exists);
    let request = authority.expected.clone();
    authority.failure = Failure::ExplicitApproval;
    assert!(register_compatibility_approval(&mut store, &rpc, &mut authority, &request).is_err());
    authority.failure = Failure::None;
    let forged = Rpc {
        state: rpc.state.clone(),
        claimed: Some(PrincipalId::new("caller-claimed-owner").unwrap()),
    };
    assert!(
        register_compatibility_approval(&mut store, &forged, &mut authority, &request).is_err()
    );
    assert!(rows(&store).is_empty());
    assert!(compatibility_approval_references(&store, &forged, &request.project_id).is_err());
}

#[test]
fn exact_approval_survives_restart_and_replay_never_rebinds_the_interface_or_scope() {
    let (root, mut store, rpc, mut authority) = seed();
    let request = authority.expected.clone();
    let record =
        register_compatibility_approval(&mut store, &rpc, &mut authority, &request).unwrap();
    assert!(record.local_use_only());
    assert_ne!(
        record.profile_resource()["sha256"],
        record.profile_digest().as_str()
    );
    assert_eq!(
        register_compatibility_approval(&mut store, &rpc, &mut authority, &request).unwrap(),
        record
    );
    let baseline = rows(&store);
    for scope in [false, true] {
        let mut changed = request.clone();
        if scope {
            changed.scope_digest = raw_digest(b"changed approved scope");
        } else {
            changed.allowed_interface_digest = raw_digest(b"changed approved interface");
        }
        authority.expected = changed.clone();
        assert!(matches!(
            register_compatibility_approval(&mut store, &rpc, &mut authority, &changed),
            Err(StorageError::Conflict("Immutable compatibility approval"))
        ));
        assert_eq!(rows(&store), baseline);
    }
    authority.expected = request;
    drop(store);
    let store = root.store();
    assert_eq!(read(&store, &rpc, &mut authority).unwrap(), Some(record));
}

#[test]
fn every_read_rechecks_current_policy_source_scope_and_protected_record_identity() {
    let (_root, mut store, rpc, mut authority) = seed();
    let request = authority.expected.clone();
    let record =
        register_compatibility_approval(&mut store, &rpc, &mut authority, &request).unwrap();
    for denied in [Failure::Policy, Failure::Source] {
        authority.failure = denied;
        assert!(read(&store, &rpc, &mut authority).is_err());
    }
    authority.failure = Failure::None;
    authority.expected.scope_digest = raw_digest(b"current scope changed");
    assert!(read(&store, &rpc, &mut authority).is_err());
    authority.expected = request;
    let encoded = rows(&store)[0].clone();
    for field in [
        "nativeOwner",
        "projectId",
        "approvedProfileRef",
        "localUseOnly",
        "unexpectedCallerGrant",
    ] {
        let mut forged = parse_json(encoded.as_bytes()).unwrap();
        forged[field] = if field == "localUseOnly" {
            json!(false)
        } else {
            json!("caller-forged-value")
        };
        store
            .connection
            .execute(
                "UPDATE compatibility_approvals SET record_json=?1",
                [String::from_utf8(canonical_bytes(&forged).unwrap()).unwrap()],
            )
            .unwrap();
        assert!(read(&store, &rpc, &mut authority).is_err());
        store
            .connection
            .execute(
                "UPDATE compatibility_approvals SET record_json=?1",
                [&encoded],
            )
            .unwrap();
    }
    assert_eq!(read(&store, &rpc, &mut authority).unwrap(), Some(record));
}

#[test]
fn provisional_cancel_or_owner_change_rolls_back_the_row_and_its_blob_pin() {
    for failure in [Failure::CancelPublished, Failure::OwnerPublished] {
        let (_root, mut store, rpc, mut authority) = seed();
        let baseline = metadata_snapshot(&store);
        let request = authority.expected.clone();
        authority.failure = failure;
        assert!(
            register_compatibility_approval(&mut store, &rpc, &mut authority, &request).is_err()
        );
        assert!(store.connection.is_autocommit());
        assert_eq!(metadata_snapshot(&store), baseline);
        assert!(rows(&store).is_empty());
        rpc.state.cancelled.set(false);
        assert_eq!(
            registered_native_project_owner(&store, &request.project_id).unwrap(),
            rpc.state.owner
        );
    }
}

#[test]
fn damaged_actual_profile_bytes_and_oversized_sources_never_register_an_approval() {
    let (_root, mut store, rpc, mut authority) = seed();
    let request = authority.expected.clone();
    let mut oversized = request.clone();
    oversized.profile_resource["sizeBytes"] = json!(MAX_COMPATIBILITY_PROFILE_BYTES + 1);
    assert!(register_compatibility_approval(&mut store, &rpc, &mut authority, &oversized).is_err());
    let blob = BlobRef {
        digest: serde_json::from_value(request.profile_resource["sha256"].clone()).unwrap(),
        byte_length: request.profile_resource["sizeBytes"].as_u64().unwrap(),
    };
    let path = store.cas.path(&blob.digest);
    let original = fs::read(&path).unwrap();
    fs::write(&path, vec![0; original.len()]).unwrap();
    assert!(register_compatibility_approval(&mut store, &rpc, &mut authority, &request).is_err());
    assert!(rows(&store).is_empty());
    fs::write(path, original).unwrap();
}

#[test]
fn project_capacity_rejects_new_approval_without_blocking_an_exact_replay() {
    let (_root, mut store, rpc, mut authority) = seed();
    let request = authority.expected.clone();
    let record =
        register_compatibility_approval(&mut store, &rpc, &mut authority, &request).unwrap();
    let encoded = rows(&store)[0].clone();
    // 같은 실제 등록/profile FK를 재사용하여 상한 직전의 보호 DB 상태를 구성한다.
    // 실제 native 승인이나 별도의 fixture/게임 관측을 생성하는 경로가 아니다.
    for index in 1..128 {
        let reference = format!("approval-budget-{index}");
        let mut stored = parse_json(encoded.as_bytes()).unwrap();
        stored["approvedProfileRef"] = json!(reference);
        store.connection.execute(
            "INSERT INTO compatibility_approvals(native_owner,project_id,approved_profile_ref,profile_resource_id,profile_resource_digest,record_json) VALUES(?1,?2,?3,?4,?5,?6)",
            params![record.native_owner().as_str(), request.project_id.as_str(), reference,
                request.profile_resource["resourceId"].as_str().unwrap(),
                request.profile_resource["sha256"].as_str().unwrap(),
                String::from_utf8(canonical_bytes(&stored).unwrap()).unwrap()],
        ).unwrap();
    }
    let baseline = rows(&store);
    assert_eq!(baseline.len(), 128);
    let references = compatibility_approval_references(&store, &rpc, &request.project_id).unwrap();
    assert_eq!(references.len(), 128);
    assert!(references.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(references.contains(&request.approved_profile_ref));
    let mut next = request.clone();
    next.approved_profile_ref = "approval-over-capacity".into();
    authority.expected = next.clone();
    assert!(matches!(
        register_compatibility_approval(&mut store, &rpc, &mut authority, &next),
        Err(StorageError::InvalidInput(_))
    ));
    assert_eq!(rows(&store), baseline);
    authority.expected = request.clone();
    assert_eq!(
        register_compatibility_approval(&mut store, &rpc, &mut authority, &request).unwrap(),
        record
    );
}

//! Existing canonical examples provide the source documents. These tests need
//! actual external SQLite/CAS storage to check provenance, restart and failure;
//! no additional repository fixture or real game acceptance is implied.

use super::*;
use mmmm_contracts::{parse_json, projected_digest};
use std::{
    cell::Cell,
    fs,
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        assert!(parent.is_absolute());
        let root = parent.join(format!(
            "mmmm-owned-documents-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed),
        ));
        assert!(!root.exists());
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let root = fs::canonicalize(root).unwrap();
        let checkout =
            fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        assert!(!root.starts_with(checkout));
        fs::write(root.join("test-owner.txt"), b"mmmm-owned-document-tests\n").unwrap();
        Self(root)
    }
    fn store(&self) -> DurableStore {
        DurableStore::open(super::super::StoreConfig::new(self.0.clone())).unwrap()
    }
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        // The resolved absolute target is the exact directory created by this
        // test, has its own marker, and has no link/reparse boundary.
        if fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0)
            && super::super::cas::verify_plain_path(&self.0).is_ok()
            && fs::read(self.0.join("test-owner.txt")).ok().as_deref()
                == Some(b"mmmm-owned-document-tests\n")
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn example(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name);
    parse_json(&fs::read(path).unwrap()).unwrap()
}
fn source_documents() -> Vec<(OwnedDocumentPin, Value)> {
    [
        (OwnedDocumentKind::Prefab, "prefab.json"),
        (OwnedDocumentKind::Instance, "instance.json"),
        (OwnedDocumentKind::CommandModule, "command-module.json"),
        (OwnedDocumentKind::AnimationClip, "animation-clip.json"),
        (OwnedDocumentKind::Asset, "asset.json"),
        (
            OwnedDocumentKind::PhysicsDefinition,
            "physics-definition.json",
        ),
    ]
    .into_iter()
    .map(|(kind, name)| {
        let document = example(name);
        let pin = OwnedDocumentPin {
            kind,
            object_id: ObjectId::new(document[kind.identity_field()].as_str().unwrap()).unwrap(),
            revision: serde_json::from_value(document["revision"].clone()).unwrap(),
        };
        (pin, document)
    })
    .collect()
}
fn project_for(documents: &[(OwnedDocumentPin, Value)]) -> Value {
    let mut project = example("project.json");
    project["ownedResources"] = json!(documents.iter().map(|(pin, _)| pin).collect::<Vec<_>>());
    project["revision"] = json!(projected_digest("Project", &project).unwrap());
    project
}
fn project_id(project: &Value) -> ProjectId {
    ProjectId::new(project["projectId"].as_str().unwrap()).unwrap()
}
fn project_revision(project: &Value) -> Sha256Digest {
    serde_json::from_value(project["revision"].clone()).unwrap()
}

#[test]
fn all_canonical_document_kinds_survive_registration_gc_and_restart() {
    let root = TestRoot::new();
    let documents = source_documents();
    let project = project_for(&documents);
    let id = project_id(&project);
    let revision = project_revision(&project);
    let mut store = root.store();
    store.save_project(&project, None).unwrap();
    for (pin, document) in &documents {
        register_owned_document(&mut store, &id, &revision, pin, document).unwrap();
        register_owned_document(&mut store, &id, &revision, pin, document).unwrap();
        assert_eq!(
            read_owned_document(&store, &id, &revision, pin).unwrap(),
            *document
        );
    }
    let count: i64 = store
        .connection
        .query_row("SELECT count(*) FROM owned_documents", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 6);
    store
        .put_blob(b"unreferenced owned-document test orphan")
        .unwrap();
    assert_eq!(store.collect_orphan_blobs(100).unwrap().removed_blobs, 1);
    drop(store);
    let store = root.store();
    for (pin, document) in &documents {
        assert_eq!(
            read_owned_document(&store, &id, &revision, pin).unwrap(),
            *document
        );
    }
}

#[test]
fn registration_rejects_unstored_or_unowned_project_and_wrong_definition_identity() {
    let root = TestRoot::new();
    let documents = source_documents();
    let project = project_for(&documents);
    let id = project_id(&project);
    let revision = project_revision(&project);
    let (pin, document) = &documents[0];
    let mut store = root.store();
    assert!(matches!(
        register_owned_document(&mut store, &id, &revision, pin, document),
        Err(StorageError::NotFound("Project revision")),
    ));
    store.save_project(&project, None).unwrap();
    let other_project = ProjectId::new("other-project").unwrap();
    assert!(register_owned_document(&mut store, &other_project, &revision, pin, document).is_err());
    let mut changed_id = document.clone();
    changed_id["prefabId"] = json!("prefab-other");
    changed_id["revision"] = json!(projected_digest("Prefab", &changed_id).unwrap());
    assert!(register_owned_document(&mut store, &id, &revision, pin, &changed_id).is_err());
    let mut changed_body = document.clone();
    changed_body["name"] = json!("Body does not match the declared revision");
    assert!(register_owned_document(&mut store, &id, &revision, pin, &changed_body).is_err());
    assert!(register_owned_document(&mut store, &id, &revision, pin, &documents[1].1).is_err());
    let mut unowned = pin.clone();
    unowned.object_id = ObjectId::new("unowned-prefab").unwrap();
    assert!(matches!(
        register_owned_document(&mut store, &id, &revision, &unowned, document),
        Err(StorageError::Conflict(
            "Document pin is not owned by this Project revision"
        )),
    ));
    assert!(read_owned_document(&store, &id, &revision, pin).is_err());
}

#[test]
fn historical_membership_does_not_follow_the_mutable_project_head() {
    let root = TestRoot::new();
    let documents = source_documents();
    let old_project = project_for(&documents);
    let id = project_id(&old_project);
    let old_revision = project_revision(&old_project);
    let (old_pin, old_document) = &documents[0];
    let mut store = root.store();
    store.save_project(&old_project, None).unwrap();
    register_owned_document(&mut store, &id, &old_revision, old_pin, old_document).unwrap();
    let mut new_document = old_document.clone();
    new_document["name"] = json!("New independently pinned source revision");
    new_document["revision"] = json!(projected_digest("Prefab", &new_document).unwrap());
    let new_pin = OwnedDocumentPin {
        revision: serde_json::from_value(new_document["revision"].clone()).unwrap(),
        ..old_pin.clone()
    };
    let mut new_project = old_project.clone();
    new_project["ownedResources"][0] = json!(new_pin);
    new_project["revision"] = json!(projected_digest("Project", &new_project).unwrap());
    let new_revision = project_revision(&new_project);
    store
        .save_project(&new_project, Some(&old_revision))
        .unwrap();
    assert!(read_owned_document(&store, &id, &new_revision, old_pin).is_err());
    assert!(read_owned_document(&store, &id, &new_revision, &new_pin).is_err());
    register_owned_document(&mut store, &id, &new_revision, &new_pin, &new_document).unwrap();
    assert_eq!(
        read_owned_document(&store, &id, &old_revision, old_pin).unwrap(),
        *old_document
    );
    assert_eq!(
        read_owned_document(&store, &id, &new_revision, &new_pin).unwrap(),
        new_document
    );
    drop(store);
    let mut store = root.store();
    assert_eq!(
        read_owned_document(&store, &id, &old_revision, old_pin).unwrap(),
        *old_document
    );
    assert!(
        register_owned_document(&mut store, &id, &old_revision, &new_pin, &new_document).is_err()
    );
}

#[test]
fn ambiguous_owned_resources_and_excessive_project_ownership_are_rejected() {
    let root = TestRoot::new();
    let documents = source_documents();
    let (pin, document) = &documents[0];
    let mut ambiguous = project_for(&documents);
    ambiguous["ownedResources"]
        .as_array_mut()
        .unwrap()
        .push(json!(pin));
    ambiguous["revision"] = json!(projected_digest("Project", &ambiguous).unwrap());
    let id = project_id(&ambiguous);
    let revision = project_revision(&ambiguous);
    let mut store = root.store();
    store.save_project(&ambiguous, None).unwrap();
    assert!(matches!(
        register_owned_document(&mut store, &id, &revision, pin, document),
        Err(StorageError::Corrupt(_)),
    ));
    let mut oversized = project_for(&documents);
    while oversized["ownedResources"].as_array().unwrap().len() <= MAX_OWNED_DOCUMENTS_PER_PROJECT {
        let next = oversized["ownedResources"].as_array().unwrap().len();
        oversized["ownedResources"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "kind":"prefab", "objectId":format!("extra-prefab-{next}"), "revision":pin.revision,
            }));
    }
    oversized["revision"] = json!(projected_digest("Project", &oversized).unwrap());
    let oversized_revision = project_revision(&oversized);
    store.save_project(&oversized, Some(&revision)).unwrap();
    assert!(matches!(
        register_owned_document(&mut store, &id, &oversized_revision, pin, document),
        Err(StorageError::InvalidInput(_)),
    ));
}

#[test]
fn registration_capacity_is_atomic_and_idempotent_existing_pins_still_work() {
    let root = TestRoot::new();
    let documents = source_documents();
    let project = project_for(&documents);
    let id = project_id(&project);
    let revision = project_revision(&project);
    let (pin, document) = &documents[0];
    let mut store = root.store();
    store.save_project(&project, None).unwrap();
    register_owned_document(&mut store, &id, &revision, pin, document).unwrap();
    let (digest, length): (String, i64) = store
        .connection
        .query_row(
            "SELECT blob_digest,byte_length FROM owned_documents",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    // Capacity metadata is preseeded below the trusted API solely to avoid
    // generating 4096 redundant on-disk source fixtures for this failure test.
    let transaction = store.connection.transaction().unwrap();
    for index in 1..MAX_OWNED_DOCUMENTS_PER_PROJECT {
        transaction.execute(
            "INSERT INTO owned_documents(project_id,kind,object_id,revision,blob_digest,byte_length) VALUES(?1,'prefab',?2,?3,?4,?5)",
            params![id.as_str(),format!("capacity-only-{index}"),pin.revision.as_str(),digest,length],
        ).unwrap();
    }
    transaction.commit().unwrap();
    register_owned_document(&mut store, &id, &revision, pin, document).unwrap();
    let (second_pin, second_document) = &documents[1];
    assert!(
        register_owned_document(&mut store, &id, &revision, second_pin, second_document).is_err()
    );
    let retained: i64 = store
        .connection
        .query_row(
            "SELECT count(*) FROM owned_document_provenance WHERE kind='instance'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(retained, 0);
    assert_eq!(
        read_owned_document(&store, &id, &revision, pin).unwrap(),
        *document
    );
}

#[test]
fn corrupt_cas_or_rebound_mapping_is_not_returned_as_a_valid_source() {
    let root = TestRoot::new();
    let documents = source_documents();
    let project = project_for(&documents);
    let id = project_id(&project);
    let revision = project_revision(&project);
    let (pin, document) = &documents[0];
    let mut store = root.store();
    store.save_project(&project, None).unwrap();
    register_owned_document(&mut store, &id, &revision, pin, document).unwrap();
    let (digest, length): (String, i64) = store
        .connection
        .query_row(
            "SELECT blob_digest,byte_length FROM owned_documents",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let original = BlobRef {
        digest: Sha256Digest::new(digest).unwrap(),
        byte_length: length as u64,
    };
    let mut replacement = document.clone();
    replacement["name"] = json!("Corrupt index points at another valid source revision");
    replacement["revision"] = json!(projected_digest("Prefab", &replacement).unwrap());
    let alternate = store.put_blob(&encode_json(&replacement).unwrap()).unwrap();
    store
        .pin_artifact("owned-document-corruption-test", &alternate)
        .unwrap();
    store
        .connection
        .execute(
            "UPDATE owned_documents SET blob_digest=?1,byte_length=?2",
            params![alternate.digest.as_str(), alternate.byte_length as i64],
        )
        .unwrap();
    assert!(matches!(
        read_owned_document(&store, &id, &revision, pin),
        Err(StorageError::Corrupt(_))
    ));
    assert!(matches!(
        register_owned_document(&mut store, &id, &revision, pin, document),
        Err(StorageError::Conflict("Immutable owned-document pin")),
    ));
    store
        .connection
        .execute(
            "UPDATE owned_documents SET blob_digest=?1,byte_length=?2",
            params![original.digest.as_str(), original.byte_length as i64],
        )
        .unwrap();
    let mut damaged = encode_json(document).unwrap();
    damaged[0] = b'[';
    fs::write(store.cas.path(&original.digest), damaged).unwrap();
    assert!(matches!(
        read_owned_document(&store, &id, &revision, pin),
        Err(StorageError::Corrupt(_))
    ));
}

struct RpcContext {
    permitted_context: ContextId,
    checks: Cell<usize>,
    cancel_after: Option<usize>,
    principal_lookups: Cell<usize>,
    change_principal_on_return: bool,
}
impl RpcContext {
    fn allowed() -> Self {
        Self {
            permitted_context: ContextId::new("context-owned-document-test").unwrap(),
            checks: Cell::new(0),
            cancel_after: None,
            principal_lookups: Cell::new(0),
            change_principal_on_return: false,
        }
    }
}
impl OwnedDocumentRpcContext for RpcContext {
    fn check(&self) -> StorageResult<()> {
        let count = self.checks.get() + 1;
        self.checks.set(count);
        if self.cancel_after.is_some_and(|limit| count >= limit) {
            return Err(StorageError::InvalidTransition(
                "RPC request cancelled".into(),
            ));
        }
        Ok(())
    }
    fn principal_for_context(&self, context: &ContextId) -> StorageResult<PrincipalId> {
        if context != &self.permitted_context {
            return Err(StorageError::Conflict("Context is not paired"));
        }
        let count = self.principal_lookups.get() + 1;
        self.principal_lookups.set(count);
        PrincipalId::new(if self.change_principal_on_return && count > 1 {
            "different-principal"
        } else {
            "owned-document-principal"
        })
        .map_err(|e| StorageError::InvalidInput(e.to_string()))
    }
}
struct Authority {
    calls: Rc<Cell<usize>>,
    deny_first: bool,
    deny_return: bool,
}
impl OwnedDocumentAuthority for Authority {
    fn authorize_read(
        &mut self,
        _principal: &PrincipalId,
        _context: &ContextId,
        project: &ProjectId,
        _revision: &Sha256Digest,
        _pin: &OwnedDocumentPin,
    ) -> StorageResult<()> {
        assert_eq!(project.as_str(), "project-fixture");
        let count = self.calls.get() + 1;
        self.calls.set(count);
        if self.deny_first || (self.deny_return && count > 1) {
            return Err(StorageError::Conflict(
                "Current document ACL forbids reading",
            ));
        }
        Ok(())
    }
}

#[test]
fn reader_rechecks_current_acl_identity_and_document_byte_budget() {
    let root = TestRoot::new();
    let documents = source_documents();
    let project = project_for(&documents);
    let id = project_id(&project);
    let revision = project_revision(&project);
    let (pin, document) = &documents[0];
    let mut store = root.store();
    store.save_project(&project, None).unwrap();
    register_owned_document(&mut store, &id, &revision, pin, document).unwrap();
    let rpc = RpcContext::allowed();
    let calls = Rc::new(Cell::new(0));
    let mut reader = OwnedDocumentReader::new(
        Box::new(Authority {
            calls: calls.clone(),
            deny_first: false,
            deny_return: false,
        }),
        MAX_OWNED_DOCUMENT_BYTES,
    )
    .unwrap();
    assert_eq!(
        reader
            .read(&store, &rpc, &rpc.permitted_context, &id, &revision, pin)
            .unwrap(),
        *document
    );
    assert_eq!(calls.get(), 2);
    let calls = Rc::new(Cell::new(0));
    let mut denied = OwnedDocumentReader::new(
        Box::new(Authority {
            calls: calls.clone(),
            deny_first: true,
            deny_return: false,
        }),
        MAX_OWNED_DOCUMENT_BYTES,
    )
    .unwrap();
    assert!(
        denied
            .read(&store, &rpc, &rpc.permitted_context, &id, &revision, pin)
            .is_err()
    );
    assert_eq!(calls.get(), 1);
    let calls = Rc::new(Cell::new(0));
    let mut revoked = OwnedDocumentReader::new(
        Box::new(Authority {
            calls: calls.clone(),
            deny_first: false,
            deny_return: true,
        }),
        MAX_OWNED_DOCUMENT_BYTES,
    )
    .unwrap();
    assert!(
        revoked
            .read(&store, &rpc, &rpc.permitted_context, &id, &revision, pin)
            .is_err()
    );
    assert_eq!(calls.get(), 2);
    let other = ContextId::new("unpaired-context").unwrap();
    assert!(
        reader
            .read(&store, &rpc, &other, &id, &revision, pin)
            .is_err()
    );
    let mut changed = RpcContext::allowed();
    changed.change_principal_on_return = true;
    assert!(
        reader
            .read(
                &store,
                &changed,
                &changed.permitted_context,
                &id,
                &revision,
                pin
            )
            .is_err()
    );
    let mut tiny = OwnedDocumentReader::new(
        Box::new(Authority {
            calls: Rc::new(Cell::new(0)),
            deny_first: false,
            deny_return: false,
        }),
        1,
    )
    .unwrap();
    assert!(
        tiny.read(&store, &rpc, &rpc.permitted_context, &id, &revision, pin)
            .is_err()
    );
}

#[test]
fn reader_checks_cancellation_during_large_document_verification() {
    let root = TestRoot::new();
    let mut documents = source_documents();
    documents[0].1["name"] = json!("x".repeat(200_000));
    documents[0].1["revision"] = json!(projected_digest("Prefab", &documents[0].1).unwrap());
    documents[0].0.revision = serde_json::from_value(documents[0].1["revision"].clone()).unwrap();
    let project = project_for(&documents);
    let id = project_id(&project);
    let revision = project_revision(&project);
    let (pin, document) = &documents[0];
    let mut store = root.store();
    store.save_project(&project, None).unwrap();
    register_owned_document(&mut store, &id, &revision, pin, document).unwrap();
    let mut rpc = RpcContext::allowed();
    rpc.cancel_after = Some(18);
    let calls = Rc::new(Cell::new(0));
    let mut reader = OwnedDocumentReader::new(
        Box::new(Authority {
            calls: calls.clone(),
            deny_first: false,
            deny_return: false,
        }),
        MAX_OWNED_DOCUMENT_BYTES,
    )
    .unwrap();
    assert!(
        reader
            .read(&store, &rpc, &rpc.permitted_context, &id, &revision, pin)
            .is_err()
    );
    assert!(rpc.checks.get() >= 18);
    assert_eq!(calls.get(), 1);
    assert_eq!(
        read_owned_document(&store, &id, &revision, pin).unwrap(),
        *document
    );
}

struct ProjectRpc {
    context: Option<ContextId>,
    checks: Cell<usize>,
    cancel_after: Option<usize>,
    principal_lookups: Cell<usize>,
    change_principal_on_return: bool,
}
impl ProjectRpc {
    fn offline() -> Self {
        Self {
            context: None,
            checks: Cell::new(0),
            cancel_after: None,
            principal_lookups: Cell::new(0),
            change_principal_on_return: false,
        }
    }
    fn online() -> Self {
        Self {
            context: Some(ContextId::new("context-owned-document-test").unwrap()),
            ..Self::offline()
        }
    }
}
impl ProjectSourceRpcContext for ProjectRpc {
    fn check(&self) -> StorageResult<()> {
        let count = self.checks.get() + 1;
        self.checks.set(count);
        if self.cancel_after.is_some_and(|limit| count >= limit) {
            return Err(StorageError::InvalidTransition(
                "Source request cancelled".into(),
            ));
        }
        Ok(())
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        let count = self.principal_lookups.get() + 1;
        self.principal_lookups.set(count);
        PrincipalId::new(if self.change_principal_on_return && count > 1 {
            "changed-source-principal"
        } else {
            "owned-document-principal"
        })
        .map_err(|e| StorageError::InvalidInput(e.to_string()))
    }
    fn context_id(&self) -> Option<&ContextId> {
        self.context.as_ref()
    }
}
struct OfflineProjectAuthority {
    current_revision: Sha256Digest,
    calls: Rc<Cell<usize>>,
    deny_return: bool,
}
impl OwnedDocumentAuthority for OfflineProjectAuthority {
    fn authorize_read(
        &mut self,
        _principal: &PrincipalId,
        _context: &ContextId,
        _project: &ProjectId,
        _revision: &Sha256Digest,
        _pin: &OwnedDocumentPin,
    ) -> StorageResult<()> {
        Err(StorageError::InvalidTransition(
            "Fixture offline source has no game authority".into(),
        ))
    }
    fn authorize_project_read(
        &mut self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        revision: &Sha256Digest,
        _pin: &OwnedDocumentPin,
    ) -> StorageResult<()> {
        assert!(context.is_none());
        assert_eq!(project.as_str(), "project-fixture");
        assert_eq!(principal.as_str(), "owned-document-principal");
        assert_eq!(revision, &self.current_revision);
        let count = self.calls.get() + 1;
        self.calls.set(count);
        if self.deny_return && count > 1 {
            return Err(StorageError::Conflict(
                "Current offline Project ACL revoked",
            ));
        }
        Ok(())
    }
}
fn context_source_reader(calls: Rc<Cell<usize>>, max_bytes: u64) -> OwnedDocumentReader {
    OwnedDocumentReader::new(
        Box::new(Authority {
            calls,
            deny_first: false,
            deny_return: false,
        }),
        max_bytes,
    )
    .unwrap()
}

#[test]
fn checked_history_reads_exact_old_pin_after_head_changes_with_multiple_valid_provenance() {
    let root = TestRoot::new();
    let documents = source_documents();
    let old_project = project_for(&documents);
    let id = project_id(&old_project);
    let old_revision = project_revision(&old_project);
    let (old_pin, old_document) = &documents[0];
    let mut store = root.store();
    store.save_project(&old_project, None).unwrap();
    register_owned_document(&mut store, &id, &old_revision, old_pin, old_document).unwrap();
    // A controlled registry fixture retains an equivalent JSON representation
    // with distinct whitespace. The source reader must preserve that raw CAS
    // representation rather than serialize its validated Value again.
    let mut source_bytes = b" \n".to_vec();
    source_bytes.extend(encode_json(old_document).unwrap());
    source_bytes.push(b'\n');
    let source_blob = store.put_blob(&source_bytes).unwrap();
    let owner = canonical_digest(&json!({"projectId":id,"kind":old_pin.kind,"objectId":old_pin.object_id,"revision":old_pin.revision})).unwrap();
    let transaction = store.connection.transaction().unwrap();
    pin_blob(&transaction, "owned_document", owner.as_str(), &source_blob).unwrap();
    transaction.execute(
        "UPDATE owned_documents SET blob_digest=?1,byte_length=?2 WHERE project_id=?3 AND kind=?4 AND object_id=?5 AND revision=?6",
        params![source_blob.digest.as_str(),source_blob.byte_length as i64,id.as_str(),old_pin.kind.as_str(),old_pin.object_id.as_str(),old_pin.revision.as_str()],
    ).unwrap();
    transaction.commit().unwrap();
    let mut another_project = old_project.clone();
    another_project["name"] = json!("Another real Project history with the same source pin");
    another_project["revision"] = json!(projected_digest("Project", &another_project).unwrap());
    let another_revision = project_revision(&another_project);
    store
        .save_project(&another_project, Some(&old_revision))
        .unwrap();
    // A second historical Project owns the exact same immutable document pin;
    // add only its provenance so the original raw representation is unchanged.
    store.connection.execute(
        "INSERT INTO owned_document_provenance(project_id,project_revision,kind,object_id,revision) VALUES(?1,?2,?3,?4,?5)",
        params![id.as_str(),another_revision.as_str(),old_pin.kind.as_str(),old_pin.object_id.as_str(),old_pin.revision.as_str()],
    ).unwrap();
    let mut current_documents = documents.clone();
    current_documents[0].1["name"] =
        json!("Current revision differs from the requested immutable source");
    current_documents[0].1["revision"] =
        json!(projected_digest("Prefab", &current_documents[0].1).unwrap());
    current_documents[0].0.revision =
        serde_json::from_value(current_documents[0].1["revision"].clone()).unwrap();
    let current_project = project_for(&current_documents);
    let current_revision = project_revision(&current_project);
    store
        .save_project(&current_project, Some(&another_revision))
        .unwrap();
    register_owned_document(
        &mut store,
        &id,
        &current_revision,
        &current_documents[0].0,
        &current_documents[0].1,
    )
    .unwrap();
    let candidates: i64 = store.connection.query_row(
        "SELECT count(*) FROM owned_document_provenance WHERE project_id=?1 AND kind=?2 AND object_id=?3 AND revision=?4",
        params![id.as_str(),old_pin.kind.as_str(),old_pin.object_id.as_str(),old_pin.revision.as_str()], |r| r.get(0),
    ).unwrap();
    assert_eq!(candidates, 2);
    assert!(read_owned_document(&store, &id, &current_revision, old_pin).is_err());
    let calls = Rc::new(Cell::new(0));
    let mut reader = context_source_reader(calls.clone(), MAX_OWNED_DOCUMENT_BYTES);
    let rpc = ProjectRpc::online();
    assert_eq!(
        reader
            .read_known_history(&store, &rpc, &id, &current_revision, old_pin)
            .unwrap(),
        *old_document
    );
    assert_eq!(calls.get(), 2);
    let loaded = reader
        .read_known_history_bytes(&store, &rpc, &id, &current_revision, old_pin)
        .unwrap();
    assert_eq!(loaded.document, *old_document);
    assert_eq!(loaded.bytes, source_bytes);
    assert_eq!(loaded.blob, source_blob);
    assert_eq!(
        mmmm_contracts::raw_digest(&loaded.bytes),
        loaded.blob.digest
    );
    assert_ne!(
        loaded.bytes,
        mmmm_contracts::canonical_bytes(old_document).unwrap()
    );
    let revoked_calls = Rc::new(Cell::new(0));
    let mut revoked = OwnedDocumentReader::new(
        Box::new(Authority {
            calls: revoked_calls.clone(),
            deny_first: false,
            deny_return: true,
        }),
        MAX_OWNED_DOCUMENT_BYTES,
    )
    .unwrap();
    assert!(
        revoked
            .read_known_history_bytes(&store, &rpc, &id, &current_revision, old_pin)
            .is_err()
    );
    assert_eq!(revoked_calls.get(), 2);
    drop(store);
    let store = root.store();
    assert_eq!(
        reader
            .read_known_history(&store, &rpc, &id, &current_revision, old_pin)
            .unwrap(),
        *old_document
    );
    let loaded = reader
        .read_known_history_bytes(&store, &rpc, &id, &current_revision, old_pin)
        .unwrap();
    assert_eq!(loaded.bytes, source_bytes);
    assert_eq!(loaded.blob, source_blob);
    assert_eq!(store.project(&id).unwrap(), current_project);
}

#[test]
fn checked_history_requires_current_membership_acl_identity_and_explicit_offline_authority() {
    let root = TestRoot::new();
    let documents = source_documents();
    let project = project_for(&documents);
    let id = project_id(&project);
    let revision = project_revision(&project);
    let (pin, document) = &documents[0];
    let mut store = root.store();
    store.save_project(&project, None).unwrap();
    register_owned_document(&mut store, &id, &revision, pin, document).unwrap();
    let offline = ProjectRpc::offline();
    let calls = Rc::new(Cell::new(0));
    let mut default_reader = context_source_reader(calls.clone(), MAX_OWNED_DOCUMENT_BYTES);
    assert!(
        default_reader
            .read_known_history(&store, &offline, &id, &revision, pin)
            .is_err()
    );
    assert_eq!(calls.get(), 0);
    let calls = Rc::new(Cell::new(0));
    let mut allowed = OwnedDocumentReader::new(
        Box::new(OfflineProjectAuthority {
            current_revision: revision.clone(),
            calls: calls.clone(),
            deny_return: false,
        }),
        MAX_OWNED_DOCUMENT_BYTES,
    )
    .unwrap();
    assert_eq!(
        allowed
            .read_known_history(&store, &offline, &id, &revision, pin)
            .unwrap(),
        *document
    );
    assert_eq!(calls.get(), 2);
    let calls = Rc::new(Cell::new(0));
    let mut revoked = OwnedDocumentReader::new(
        Box::new(OfflineProjectAuthority {
            current_revision: revision.clone(),
            calls: calls.clone(),
            deny_return: true,
        }),
        MAX_OWNED_DOCUMENT_BYTES,
    )
    .unwrap();
    assert!(
        revoked
            .read_known_history(&store, &offline, &id, &revision, pin)
            .is_err()
    );
    assert_eq!(calls.get(), 2);
    let mut changed = ProjectRpc::offline();
    changed.change_principal_on_return = true;
    assert!(
        allowed
            .read_known_history(&store, &changed, &id, &revision, pin)
            .is_err()
    );
    let mut tiny = OwnedDocumentReader::new(
        Box::new(OfflineProjectAuthority {
            current_revision: revision.clone(),
            calls: Rc::new(Cell::new(0)),
            deny_return: false,
        }),
        1,
    )
    .unwrap();
    assert!(matches!(
        tiny.read_known_history(&store, &offline, &id, &revision, pin),
        Err(StorageError::InvalidInput(_))
    ));
    let mut no_longer_owned = project.clone();
    no_longer_owned["ownedResources"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    no_longer_owned["prefabIds"] = json!([]);
    no_longer_owned["revision"] = json!(projected_digest("Project", &no_longer_owned).unwrap());
    let current_revision = project_revision(&no_longer_owned);
    store
        .save_project(&no_longer_owned, Some(&revision))
        .unwrap();
    let online = ProjectRpc::online();
    let mut reader = context_source_reader(Rc::new(Cell::new(0)), MAX_OWNED_DOCUMENT_BYTES);
    assert!(matches!(
        reader.read_known_history(&store, &online, &id, &revision, pin),
        Err(StorageError::Conflict("Current Project source revision"))
    ));
    assert!(matches!(
        reader.read_known_history(&store, &online, &id, &current_revision, pin),
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(
        read_owned_document(&store, &id, &revision, pin).unwrap(),
        *document
    );
}

#[test]
fn checked_history_is_bounded_cancellable_and_does_not_skip_corrupt_provenance() {
    let root = TestRoot::new();
    let mut documents = source_documents();
    documents[0].1["name"] = json!("h".repeat(200_000));
    documents[0].1["revision"] = json!(projected_digest("Prefab", &documents[0].1).unwrap());
    documents[0].0.revision = serde_json::from_value(documents[0].1["revision"].clone()).unwrap();
    let project = project_for(&documents);
    let id = project_id(&project);
    let revision = project_revision(&project);
    let (pin, document) = &documents[0];
    let mut store = root.store();
    store.save_project(&project, None).unwrap();
    register_owned_document(&mut store, &id, &revision, pin, document).unwrap();
    let calls = Rc::new(Cell::new(0));
    let mut reader = context_source_reader(calls.clone(), MAX_OWNED_DOCUMENT_BYTES);
    let mut cancelled = ProjectRpc::online();
    cancelled.cancel_after = Some(24);
    assert!(
        reader
            .read_known_history(&store, &cancelled, &id, &revision, pin)
            .is_err()
    );
    assert!(cancelled.checks.get() >= 24);
    assert_eq!(calls.get(), 1);
    let project_blob: String = store
        .connection
        .query_row(
            "SELECT blob_digest FROM project_heads WHERE project_id=?1",
            [id.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    // This adversarial metadata points at a real Project CAS object under a
    // false self-digest. There is also genuine provenance; falling back would
    // hide corruption in the deterministic first historical candidate.
    let false_revision = Sha256Digest::new("0".repeat(64)).unwrap();
    store.connection.execute(
        "INSERT INTO documents(definition,document_id,content_hash,blob_digest) VALUES('Project',?1,?2,?3)",
        params![id.as_str(),false_revision.as_str(),project_blob],
    ).unwrap();
    store.connection.execute(
        "INSERT INTO owned_document_provenance(project_id,project_revision,kind,object_id,revision) VALUES(?1,?2,?3,?4,?5)",
        params![id.as_str(),false_revision.as_str(),pin.kind.as_str(),pin.object_id.as_str(),pin.revision.as_str()],
    ).unwrap();
    let rpc = ProjectRpc::online();
    assert!(matches!(
        reader.read_known_history(&store, &rpc, &id, &revision, pin),
        Err(StorageError::Corrupt(_))
    ));
    // Capacity is a metadata-only gate. Reusing the existing CAS bytes avoids
    // generating thousands of files for rows that must never be dereferenced.
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    for index in 0..MAX_OWNED_DOCUMENTS_PER_PROJECT {
        let historical = canonical_digest(&json!({"ownedDocumentHistoryCapacity":index})).unwrap();
        transaction.execute(
            "INSERT INTO documents(definition,document_id,content_hash,blob_digest) VALUES('Project',?1,?2,?3)",
            params![id.as_str(),historical.as_str(),project_blob],
        ).unwrap();
        transaction.execute(
            "INSERT INTO owned_document_provenance(project_id,project_revision,kind,object_id,revision) VALUES(?1,?2,?3,?4,?5)",
            params![id.as_str(),historical.as_str(),pin.kind.as_str(),pin.object_id.as_str(),pin.revision.as_str()],
        ).unwrap();
    }
    transaction.commit().unwrap();
    assert!(matches!(
        reader.read_known_history(&store, &rpc, &id, &revision, pin),
        Err(StorageError::InvalidInput(_))
    ));
    assert_eq!(
        read_owned_document(&store, &id, &revision, pin).unwrap(),
        *document
    );
}

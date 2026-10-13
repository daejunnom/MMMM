//! Canonical source examples are mutated into local composite invocations.
//! The echo example cannot cover a world/document phase boundary or partial
//! SQLite failure. Real external SQLite/CAS roots exercise those boundaries;
//! observer fixtures are not evidence of actual game acceptance.

use super::super::{
    EffectEvidence, ReserveOperation, StepObservation, StoreConfig,
    artifact::{ResourceOwner, register_resource},
    owned_documents::{read_owned_document, register_owned_document},
};
use super::*;
use mmmm_contracts::{PlanId, projected_digest};
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
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = parent.join(format!(
            "mmmm-authored-projection-{}-{nonce}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
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
        fs::write(
            root.join("test-owner.txt"),
            b"mmmm-authored-projection-tests\n",
        )
        .unwrap();
        Self(root)
    }
    fn store(&self) -> DurableStore {
        DurableStore::open(StoreConfig::new(self.0.clone())).unwrap()
    }
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        if fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0)
            && super::super::cas::verify_plain_path(&self.0).is_ok()
            && fs::read(self.0.join("test-owner.txt")).ok().as_deref()
                == Some(b"mmmm-authored-projection-tests\n")
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
fn example(name: &str) -> Value {
    parse_json(
        &fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples")
                .join(name),
        )
        .unwrap(),
    )
    .unwrap()
}
fn project_id(project: &Value) -> ProjectId {
    field(project, "projectId").unwrap()
}
fn revision(project: &Value) -> Sha256Digest {
    field(project, "revision").unwrap()
}
fn resource_ref(store: &DurableStore, id: &str, bytes: &[u8]) -> Value {
    let blob = store.put_blob(bytes).unwrap();
    json!({"resourceId":id,"sha256":blob.digest,"sizeBytes":blob.byte_length,"mediaType":"application/octet-stream"})
}
fn seed(store: &mut DurableStore) -> (Value, Value) {
    let project = example("project.json");
    store.save_project(&project, None).unwrap();
    for (kind, name) in [
        (OwnedDocumentKind::Prefab, "prefab.json"),
        (OwnedDocumentKind::Instance, "instance.json"),
        (OwnedDocumentKind::AnimationClip, "animation-clip.json"),
        (OwnedDocumentKind::CommandModule, "command-module.json"),
        (OwnedDocumentKind::Asset, "asset.json"),
    ] {
        let document = example(name);
        let pin = OwnedDocumentPin {
            kind,
            object_id: field(&document, kind.identity_field()).unwrap(),
            revision: revision(&document),
        };
        register_owned_document(
            store,
            &project_id(&project),
            &revision(&project),
            &pin,
            &document,
        )
        .unwrap();
    }
    let resource = resource_ref(store, "resource-wall-blocks", b"original resource bytes");
    register_resource(
        store,
        &resource,
        ResourceOwner::Project(project_id(&project)),
    )
    .unwrap();
    (project, resource)
}
fn blank_change(project: &Value, kind: &str) -> Value {
    json!({"format":"mmmm-native-change/1", "kind":kind,
        "projectId":project["projectId"], "projectBaseRevision":project["revision"],
        "targetProfileId":project["targetProfileId"], "projectAfter":project,
        "documentChanges":[], "worldProjection":[], "resourceReplacements":[], "recoveryReplacements":[],
        "sourceObjectPins":[], "sourceResourcePins":[], "stagedResources":[],
        "scenePatch":null, "packManifest":null, "lossRecords":[]})
}
fn clip_change(project: &Value) -> Value {
    let before = example("animation-clip.json");
    let mut after = before.clone();
    after["loop"] = json!(!before["loop"].as_bool().unwrap());
    after["revision"] = json!(projected_digest("AnimationClip", &after).unwrap());
    let mut change = blank_change(project, "clip.retime");
    change["documentChanges"] = json!([{"kind":"clip", "objectId":after["clipId"],
        "beforeRevision":before["revision"], "afterRevision":after["revision"], "after":after}]);
    change["sourceObjectPins"] =
        json!([{"kind":"clip", "objectId":before["clipId"], "revision":before["revision"]}]);
    let after_revision = change["documentChanges"][0]["afterRevision"].clone();
    let pins = change["projectAfter"]["ownedResources"]
        .as_array_mut()
        .unwrap();
    pins.iter_mut().find(|p| p["kind"] == "clip").unwrap()["revision"] = after_revision;
    change["projectAfter"]["revision"] =
        json!(projected_digest("Project", &change["projectAfter"]).unwrap());
    change
}
fn replacement_change(project: &Value, before: &Value, replacement: &Value) -> Value {
    let mut change = blank_change(project, "resource.patch");
    change["sourceResourcePins"] = json!([before, replacement]);
    change["resourceReplacements"] = json!([{"targetResourceId":before["resourceId"], "before":before, "replacementSource":replacement}]);
    change
}
struct Rpc {
    cancelled: Rc<Cell<bool>>,
    principal: PrincipalId,
}
impl Rpc {
    fn new() -> Self {
        Self {
            cancelled: Rc::new(Cell::new(false)),
            principal: PrincipalId::new("principal-fixture").unwrap(),
        }
    }
}
impl ProjectionRpcContext for Rpc {
    fn check(&self) -> StorageResult<()> {
        if self.cancelled.get() {
            Err(invalid("Fixture RPC was cancelled"))
        } else {
            Ok(())
        }
    }
    fn principal_for_context(&self, context: &ContextId) -> StorageResult<PrincipalId> {
        self.check()?;
        if context.as_str() != "context-fixture-01" {
            return Err(invalid("Unpaired fixture context"));
        }
        Ok(self.principal.clone())
    }
}
struct Observer {
    evidence: BlobRef,
    authorizations: usize,
    observations: usize,
    deny_authorization: Option<usize>,
    wrong_binding: bool,
    still_running: bool,
    fresh_evidence: bool,
    cancel_at_second_observation: Option<Rc<Cell<bool>>>,
}
impl Observer {
    fn new(evidence: BlobRef) -> Self {
        Self {
            evidence,
            authorizations: 0,
            observations: 0,
            deny_authorization: None,
            wrong_binding: false,
            still_running: false,
            fresh_evidence: false,
            cancel_at_second_observation: None,
        }
    }
}
impl ProjectionAuthority for Observer {
    fn authorize_operation(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        operation: &OperationRecord,
        request: &ProjectionCommitRequest,
        _replay: bool,
    ) -> StorageResult<()> {
        if principal != &operation.principal || operation.operation_id != request.operation_id {
            return Err(invalid("Fixture operation authorization denied"));
        }
        Ok(())
    }
    fn authorize_projection(
        &mut self,
        _store: &DurableStore,
        _input: &ProjectionInput<'_>,
        _replay: bool,
    ) -> StorageResult<()> {
        self.authorizations += 1;
        if self.deny_authorization == Some(self.authorizations) {
            Err(invalid("Current fixture project ACL denied"))
        } else {
            Ok(())
        }
    }
    fn observe_settled_world_phase(
        &mut self,
        store: &DurableStore,
        input: &ProjectionInput<'_>,
    ) -> StorageResult<WorldPhaseObservation> {
        self.observations += 1;
        if self.fresh_evidence {
            self.evidence = store.put_blob(
                format!("fresh fixture world observation {}", self.observations).as_bytes(),
            )?;
        }
        if self.observations == 2 {
            if let Some(cancelled) = &self.cancel_at_second_observation {
                cancelled.set(true);
            }
        }
        Ok(WorldPhaseObservation {
            invocation_id: if self.wrong_binding {
                InvocationId::new("wrong-invocation").unwrap()
            } else {
                field(input.invocation, "invocationId")?
            },
            invocation_digest: input.invocation_digest.clone(),
            change_digest: input.change_digest.clone(),
            context_digest: field(input.invocation, "contextDigest")?,
            scope_digest: digest(&serde_json::to_value(&input.operation.scope).unwrap())?,
            world_phase_complete: !self.still_running,
            further_world_effects_possible: self.still_running,
            evidence: vec![self.evidence.clone()],
        })
    }
}
struct Prepared {
    request: ProjectionCommitRequest,
    evidence: BlobRef,
    payload: BlobRef,
}
fn prepare(store: &mut DurableStore, project: &Value, change: &Value, name: &str) -> Prepared {
    let bytes = mmmm_contracts::canonical_bytes(&json!({"change":change})).unwrap();
    let payload = store.put_blob(&bytes).unwrap();
    let reference = json!({"resourceId":format!("prepared-{name}"), "sha256":payload.digest,
        "sizeBytes":payload.byte_length,"mediaType":"application/vnd.mmmm.prepared-change+json"});
    register_resource(
        store,
        &reference,
        ResourceOwner::Project(project_id(project)),
    )
    .unwrap();
    let arguments = json!({"preparedChange":reference});
    let mut plan = example("execution-plan.json");
    plan["planId"] = json!(format!("plan-{name}"));
    plan["projectBaseRevision"] = project["revision"].clone();
    let object_ids: Vec<Value> = change["documentChanges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["objectId"].clone())
        .chain(std::iter::once(project["projectId"].clone()))
        .collect();
    let resource_ids: Vec<Value> = change["resourceReplacements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["targetResourceId"].clone())
        .chain(
            change["stagedResources"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["resourceId"].clone()),
        )
        .collect();
    plan["scope"]["objectIds"] = json!(object_ids);
    plan["scope"]["resourceIds"] = json!(resource_ids);
    plan["steps"][0]["actionId"] = json!("fixture:composite_projection");
    plan["steps"][0]["arguments"] = arguments.clone();
    plan["steps"][0]["effect"] = json!("write");
    plan["steps"][0]["verificationRequirement"] = json!("independent_readback");
    plan["steps"][0]["resourcesWritten"] = json!([]);
    let mut invocation = example("invocation.json");
    invocation["operationId"] = json!(format!("operation-{name}"));
    invocation["invocationId"] = json!(format!("invocation-{name}"));
    invocation["actionId"] = plan["steps"][0]["actionId"].clone();
    invocation["arguments"] = arguments;
    invocation["argumentsDigest"] = json!(digest(&invocation["arguments"]).unwrap());
    invocation["context"]["scope"] = plan["scope"].clone();
    let context_digest = projected_digest("ExecutionContext", &invocation["context"]).unwrap();
    invocation["context"]["contextDigest"] = json!(context_digest);
    invocation["contextDigest"] = json!(context_digest);
    plan["contextPins"][0]["contextDigest"] = json!(context_digest);
    plan["planHash"] = json!(projected_digest("ExecutionPlan", &plan).unwrap());
    store.save_plan(&plan).unwrap();
    let request = ProjectionCommitRequest {
        operation_id: field(&invocation, "operationId").unwrap(),
        step_id: field(&invocation, "stepId").unwrap(),
        invocation_id: field(&invocation, "invocationId").unwrap(),
        invocation_digest: mmmm_contracts::raw_digest(&encode_json(&invocation).unwrap()),
    };
    store
        .reserve_operation(ReserveOperation {
            operation_id: request.operation_id.clone(),
            principal: PrincipalId::new("principal-fixture").unwrap(),
            project_id: project_id(project),
            idempotency_key: format!("key-{name}"),
            plan_id: PlanId::new(plan["planId"].as_str().unwrap()).unwrap(),
            plan_hash: field(&plan, "planHash").unwrap(),
            context_id: ContextId::new("context-fixture-01").unwrap(),
        })
        .unwrap();
    store
        .dispatch_intent(&request.operation_id, &request.step_id, &invocation)
        .unwrap();
    let evidence = store
        .put_blob(format!("independent fixture world readback {name}").as_bytes())
        .unwrap();
    store
        .append_operation_evidence(&request.operation_id, &evidence)
        .unwrap();
    // The world phase is observed, but the whole composite step has remaining
    // document effects. Aggregate evidence must remain some_confirmed here.
    store
        .record_observation(
            &request.operation_id,
            &request.step_id,
            StepObservation {
                dispatch: DispatchEvidence::Observed,
                effect: EffectEvidence::SomeConfirmed,
                further_effects_possible: true,
                provider_receipt: Some(format!("world-receipt-{name}")),
                observation_refs: vec![evidence.clone()],
                finished: false,
            },
        )
        .unwrap();
    Prepared {
        request,
        evidence,
        payload,
    }
}
fn commit(
    store: &mut DurableStore,
    rpc: &Rpc,
    observer: &mut Observer,
    prepared: &Prepared,
) -> StorageResult<ProjectionCommitResult> {
    commit_authored_projection(store, rpc, observer, &prepared.request)
}
fn finish(store: &mut DurableStore, prepared: &Prepared) {
    store
        .record_observation(
            &prepared.request.operation_id,
            &prepared.request.step_id,
            StepObservation {
                dispatch: DispatchEvidence::Observed,
                effect: EffectEvidence::CompleteConfirmed,
                further_effects_possible: false,
                provider_receipt: None,
                observation_refs: vec![prepared.evidence.clone()],
                finished: true,
            },
        )
        .unwrap();
    store
        .finish_operation(&prepared.request.operation_id, OperationState::Succeeded)
        .unwrap();
}
fn new_clip_pin(change: &Value) -> OwnedDocumentPin {
    OwnedDocumentPin {
        kind: OwnedDocumentKind::AnimationClip,
        object_id: field(&change["documentChanges"][0], "objectId").unwrap(),
        revision: field(&change["documentChanges"][0], "afterRevision").unwrap(),
    }
}

#[test]
fn document_phase_atomically_promotes_sources_and_replays_after_restart_without_observer() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (project, _) = seed(&mut store);
    let change = clip_change(&project);
    let prepared = prepare(&mut store, &project, &change, "promote");
    let before_operation = store.operation(&prepared.request.operation_id).unwrap();
    let rpc = Rpc::new();
    let mut observer = Observer::new(prepared.evidence.clone());
    let result = commit(&mut store, &rpc, &mut observer, &prepared).unwrap();
    assert!(!result.replayed);
    assert_eq!(observer.observations, 2);
    assert_eq!(
        store.operation(&prepared.request.operation_id).unwrap(),
        before_operation
    );
    assert_eq!(
        store.project(&project_id(&project)).unwrap(),
        change["projectAfter"]
    );
    assert_eq!(
        read_owned_document(
            &store,
            &project_id(&project),
            &revision(&change["projectAfter"]),
            &new_clip_pin(&change)
        )
        .unwrap(),
        change["documentChanges"][0]["after"]
    );
    let old_pin: OwnedDocumentPin =
        serde_json::from_value(change["sourceObjectPins"][0].clone()).unwrap();
    assert_eq!(
        read_owned_document(&store, &project_id(&project), &revision(&project), &old_pin).unwrap(),
        example("animation-clip.json")
    );
    finish(&mut store, &prepared);
    store.collect_orphan_blobs(1000).unwrap();
    drop(store);
    let mut store = root.store();
    let mut observer = Observer::new(prepared.evidence.clone());
    observer.still_running = true; // Replay must never call the world observer.
    let replay = commit(&mut store, &rpc, &mut observer, &prepared).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.receipt, result.receipt);
    assert_eq!(observer.observations, 0);
    let events: i64 = store
        .connection
        .query_row(
            "SELECT count(*) FROM events WHERE kind='authored_projection_committed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(events, 1);
}

#[test]
fn final_journal_failure_rolls_back_every_metadata_table_and_restart_preserves_world_effects() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (project, _) = seed(&mut store);
    let change = clip_change(&project);
    let prepared = prepare(&mut store, &project, &change, "rollback");
    let before_operation = store.operation(&prepared.request.operation_id).unwrap();
    store.connection.execute_batch("CREATE TRIGGER fail_projection_event BEFORE INSERT ON events WHEN NEW.kind='authored_projection_committed' BEGIN SELECT RAISE(ABORT,'injected projection event failure'); END;").unwrap();
    let rpc = Rpc::new();
    let mut observer = Observer::new(prepared.evidence.clone());
    assert!(matches!(
        commit(&mut store, &rpc, &mut observer, &prepared),
        Err(StorageError::Sqlite(_))
    ));
    assert_eq!(store.project(&project_id(&project)).unwrap(), project);
    assert_eq!(
        store.operation(&prepared.request.operation_id).unwrap(),
        before_operation
    );
    assert!(!receipt_exists(&store, &prepared.request).unwrap());
    let count: i64 = store
        .connection
        .query_row(
            "SELECT count(*) FROM owned_documents WHERE revision=?1",
            [new_clip_pin(&change).revision.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    assert!(!has_table(&store.connection, "project_resource_versions").unwrap());
    store
        .connection
        .execute_batch("DROP TRIGGER fail_projection_event;")
        .unwrap();
    drop(store);
    let mut store = root.store();
    let recovered = store.operation(&prepared.request.operation_id).unwrap();
    assert!(recovered.reconciliation_required);
    assert_eq!(recovered.steps[0].effect, EffectEvidence::SomeConfirmed);
    assert!(recovered.steps[0].further_effects_possible);
    assert!(store.read_blob(&prepared.evidence).is_ok());
    let mut observer = Observer::new(prepared.evidence.clone());
    assert!(matches!(
        commit(&mut store, &rpc, &mut observer, &prepared),
        Err(StorageError::InvalidTransition(_))
    ));
    assert_eq!(observer.observations, 0);
    assert_eq!(store.project(&project_id(&project)).unwrap(), project);
}

#[test]
fn trusted_fresh_observer_bytes_are_verified_and_pinned_atomically_then_replay_requires_retention()
{
    let root = TestRoot::new();
    let mut store = root.store();
    let (project, _) = seed(&mut store);
    let change = clip_change(&project);
    let prepared = prepare(&mut store, &project, &change, "fresh-observer");
    let rpc = Rpc::new();
    let mut observer = Observer::new(prepared.evidence.clone());
    observer.fresh_evidence = true;
    let result = commit(&mut store, &rpc, &mut observer, &prepared).unwrap();
    assert_ne!(result.receipt.world_evidence[0], prepared.evidence);
    let latest = &result.receipt.world_evidence[0];
    let retained: i64 = store.connection.query_row(
        "SELECT count(*) FROM blob_refs WHERE owner_kind='operation' AND owner_id=?1 AND digest=?2",
        params![prepared.request.operation_id.as_str(), latest.digest.as_str()], |r| r.get(0),
    ).unwrap();
    assert_eq!(retained, 1);
    store.collect_orphan_blobs(1000).unwrap();
    assert!(store.read_blob(latest).is_ok());
    store
        .connection
        .execute(
            "DELETE FROM blob_refs WHERE owner_id=?1 AND digest=?2",
            params![
                prepared.request.operation_id.as_str(),
                latest.digest.as_str()
            ],
        )
        .unwrap();
    let mut observer = Observer::new(prepared.evidence.clone());
    assert!(commit(&mut store, &rpc, &mut observer, &prepared).is_err());
    assert_eq!(observer.observations, 0);
}

#[test]
fn revoked_acl_or_rpc_cancel_during_final_observation_rolls_back_project_and_receipt() {
    for cancel in [false, true] {
        let root = TestRoot::new();
        let mut store = root.store();
        let (project, _) = seed(&mut store);
        let change = clip_change(&project);
        let prepared = prepare(
            &mut store,
            &project,
            &change,
            if cancel { "rpc-cancel" } else { "acl-deny" },
        );
        let rpc = Rpc::new();
        let mut observer = Observer::new(prepared.evidence.clone());
        if cancel {
            observer.cancel_at_second_observation = Some(rpc.cancelled.clone());
        } else {
            observer.deny_authorization = Some(2);
        }
        assert!(commit(&mut store, &rpc, &mut observer, &prepared).is_err());
        assert_eq!(store.project(&project_id(&project)).unwrap(), project);
        assert!(!receipt_exists(&store, &prepared.request).unwrap());
        assert_eq!(
            store
                .operation(&prepared.request.operation_id)
                .unwrap()
                .steps[0]
                .effect,
            EffectEvidence::SomeConfirmed
        );
    }
}

#[test]
fn world_observer_must_bind_exact_invocation_and_settled_phase() {
    for wrong_binding in [false, true] {
        let root = TestRoot::new();
        let mut store = root.store();
        let (project, _) = seed(&mut store);
        let change = clip_change(&project);
        let prepared = prepare(&mut store, &project, &change, "world-invalid");
        let rpc = Rpc::new();
        let mut observer = Observer::new(prepared.evidence.clone());
        observer.wrong_binding = wrong_binding;
        observer.still_running = !wrong_binding;
        assert!(matches!(
            commit(&mut store, &rpc, &mut observer, &prepared),
            Err(StorageError::Conflict(_))
        ));
        assert_eq!(store.project(&project_id(&project)).unwrap(), project);
        assert_eq!(observer.observations, 1);
    }
}

#[test]
fn actual_prepared_cas_digest_and_registered_project_owner_are_required() {
    for wrong_owner in [false, true] {
        let root = TestRoot::new();
        let mut store = root.store();
        let (project, _) = seed(&mut store);
        let change = clip_change(&project);
        let prepared = prepare(&mut store, &project, &change, "payload-invalid");
        if wrong_owner {
            store.connection.execute("UPDATE artifact_resources SET owner_json=?1 WHERE resource_id='prepared-payload-invalid'",
                [encode(&json!({"kind":"principal","id":"principal-fixture"})).unwrap()]).unwrap();
        } else {
            fs::write(
                store.cas.path(&prepared.payload.digest),
                b"replaced native payload bytes",
            )
            .unwrap();
        }
        let rpc = Rpc::new();
        let mut observer = Observer::new(prepared.evidence.clone());
        assert!(commit(&mut store, &rpc, &mut observer, &prepared).is_err());
        assert_eq!(observer.observations, 0);
        assert_eq!(store.project(&project_id(&project)).unwrap(), project);
    }
}

#[test]
fn project_base_conflict_preserves_actual_head_and_known_world_effects() {
    let root = TestRoot::new();
    let mut store = root.store();
    let (project, _) = seed(&mut store);
    let change = clip_change(&project);
    let prepared = prepare(&mut store, &project, &change, "base-conflict");
    let mut concurrent = project.clone();
    concurrent["name"] = json!("Independent authored edit");
    concurrent["revision"] = json!(projected_digest("Project", &concurrent).unwrap());
    store
        .save_project(&concurrent, Some(&revision(&project)))
        .unwrap();
    let rpc = Rpc::new();
    let mut observer = Observer::new(prepared.evidence.clone());
    assert!(matches!(
        commit(&mut store, &rpc, &mut observer, &prepared),
        Err(StorageError::Conflict("Project base revision"))
    ));
    assert_eq!(store.project(&project_id(&project)).unwrap(), concurrent);
    assert_eq!(
        store
            .operation(&prepared.request.operation_id)
            .unwrap()
            .steps[0]
            .effect,
        EffectEvidence::SomeConfirmed
    );
    assert!(!receipt_exists(&store, &prepared.request).unwrap());
}

#[test]
fn cancelled_or_unknown_composite_cannot_create_a_new_metadata_receipt() {
    for cancellation in [false, true] {
        let root = TestRoot::new();
        let mut store = root.store();
        let (project, _) = seed(&mut store);
        let change = clip_change(&project);
        let prepared = prepare(&mut store, &project, &change, "blocked-state");
        if cancellation {
            store
                .request_cancel(&prepared.request.operation_id)
                .unwrap();
        } else {
            store
                .mark_outcome_unknown(&prepared.request.operation_id, &prepared.request.step_id)
                .unwrap();
        }
        let rpc = Rpc::new();
        let mut observer = Observer::new(prepared.evidence.clone());
        assert!(matches!(
            commit(&mut store, &rpc, &mut observer, &prepared),
            Err(StorageError::InvalidTransition(_))
        ));
        assert_eq!(observer.observations, 0);
        assert_eq!(store.project(&project_id(&project)).unwrap(), project);
        assert!(!receipt_exists(&store, &prepared.request).unwrap());
        assert_eq!(
            store
                .operation(&prepared.request.operation_id)
                .unwrap()
                .steps[0]
                .effect,
            EffectEvidence::SomeConfirmed
        );
    }
}

#[test]
fn resource_sha_promotion_keeps_project_revision_and_immutable_artifact_then_rejects_stale_before()
{
    let root = TestRoot::new();
    let mut store = root.store();
    let (project, before) = seed(&mut store);
    let source = resource_ref(&store, "source-replacement-a", b"replacement version A");
    register_resource(
        &mut store,
        &source,
        ResourceOwner::Project(project_id(&project)),
    )
    .unwrap();
    let change = replacement_change(&project, &before, &source);
    let prepared = prepare(&mut store, &project, &change, "resource-a");
    let rpc = Rpc::new();
    let mut observer = Observer::new(prepared.evidence.clone());
    let result = commit(&mut store, &rpc, &mut observer, &prepared).unwrap();
    assert_eq!(
        result.receipt.project_base_revision,
        result.receipt.project_revision
    );
    assert_eq!(store.project(&project_id(&project)).unwrap(), project);
    let head: String = store
        .connection
        .query_row(
            "SELECT digest FROM project_resource_heads WHERE resource_id='resource-wall-blocks'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(head, source["sha256"].as_str().unwrap());
    let immutable: String = store
        .connection
        .query_row(
            "SELECT resource_json FROM artifact_resources WHERE resource_id='resource-wall-blocks'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(parse_json(immutable.as_bytes()).unwrap(), before);
    let versions: i64 = store.connection.query_row("SELECT count(*) FROM project_resource_versions WHERE resource_id='resource-wall-blocks'", [], |r| r.get(0)).unwrap();
    assert_eq!(versions, 2);
    let histories: i64 = store.connection.query_row("SELECT count(*) FROM project_resource_provenance WHERE resource_id='resource-wall-blocks' AND project_revision=?1", [revision(&project).as_str()], |r| r.get(0)).unwrap();
    assert_eq!(histories, 2);
    finish(&mut store, &prepared);
    let source_b = resource_ref(&store, "source-replacement-b", b"replacement version B");
    register_resource(
        &mut store,
        &source_b,
        ResourceOwner::Project(project_id(&project)),
    )
    .unwrap();
    let stale = replacement_change(&project, &before, &source_b);
    let stale_prepared = prepare(&mut store, &project, &stale, "resource-stale");
    let mut observer = Observer::new(stale_prepared.evidence.clone());
    assert!(matches!(
        commit(&mut store, &rpc, &mut observer, &stale_prepared),
        Err(StorageError::Conflict(
            "Current project resource before-image"
        ))
    ));
    assert!(!receipt_exists(&store, &stale_prepared.request).unwrap());
    let head: String = store
        .connection
        .query_row(
            "SELECT digest FROM project_resource_heads WHERE resource_id='resource-wall-blocks'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(head, source["sha256"].as_str().unwrap());
    assert_eq!(
        store
            .operation(&stale_prepared.request.operation_id)
            .unwrap()
            .steps[0]
            .effect,
        EffectEvidence::SomeConfirmed
    );
    store.collect_orphan_blobs(1000).unwrap();
    assert!(
        store
            .read_blob(&validate_resource(&store, &before).unwrap().blob)
            .is_ok()
    );
    assert!(
        store
            .read_blob(&validate_resource(&store, &source).unwrap().blob)
            .is_ok()
    );
    drop(store);
    let mut store = root.store();
    let mut observer = Observer::new(prepared.evidence.clone());
    assert!(
        commit(&mut store, &rpc, &mut observer, &prepared)
            .unwrap()
            .replayed
    );
    assert_eq!(observer.observations, 0);
}

#[test]
fn missing_replacement_cas_or_wrong_source_metadata_cannot_promote_resource_head() {
    for missing in [false, true] {
        let root = TestRoot::new();
        let mut store = root.store();
        let (project, before) = seed(&mut store);
        let source = resource_ref(&store, "source-negative", b"negative source bytes");
        register_resource(
            &mut store,
            &source,
            ResourceOwner::Project(project_id(&project)),
        )
        .unwrap();
        let mut change = replacement_change(&project, &before, &source);
        if !missing {
            change["sourceResourcePins"][1]["mediaType"] = json!("text/plain");
            change["resourceReplacements"][0]["replacementSource"]["mediaType"] =
                json!("text/plain");
        }
        let prepared = prepare(&mut store, &project, &change, "resource-negative");
        if missing {
            fs::remove_file(
                store
                    .cas
                    .path(&validate_resource(&store, &source).unwrap().blob.digest),
            )
            .unwrap();
        }
        let rpc = Rpc::new();
        let mut observer = Observer::new(prepared.evidence.clone());
        assert!(commit(&mut store, &rpc, &mut observer, &prepared).is_err());
        assert_eq!(store.project(&project_id(&project)).unwrap(), project);
        assert!(!has_table(&store.connection, "project_resource_heads").unwrap());
        assert!(!receipt_exists(&store, &prepared.request).unwrap());
    }
}

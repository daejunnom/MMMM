//! The handoff's read-only echo fixture cannot exercise uncertain writes,
//! recovery or GC. These tests modify its effect/scope and recompute its pins;
//! the mutations are test inputs, never evidence of real game application.

use super::*;
use mmmm_contracts::{ContextId, OperationId, PlanId, PrincipalId, ProjectId, StepId,
    encode_json, parse_json, projected_digest};
use serde_json::{Value, json};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64,Ordering}};

static NEXT:AtomicU64=AtomicU64::new(0);
struct TestRoot(PathBuf);
impl TestRoot {
    fn new()->Self {
        let parent=std::env::var_os("MMMM_TEST_DATA_ROOT").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let root=parent.join(format!("mmmm-runtime-storage-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed)));
        assert!(root.is_absolute());
        assert!(!root.starts_with(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")));
        fs::create_dir(&root).expect("fresh external test data root");
        fs::write(root.join("test-owner.txt"),b"mmmm-runtime-storage-test\n").unwrap();
        Self(root)
    }
    fn store(&self)->DurableStore { DurableStore::open(StoreConfig::new(self.0.clone())).unwrap() }
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        // Only the exact root created above is removed, after its own marker and
        // final absolute/link boundary are verified. Runtime data GC is separate.
        if fs::read(self.0.join("test-owner.txt")).ok().as_deref()==Some(b"mmmm-runtime-storage-test\n")
            && super::cas::verify_plain_path(&self.0).is_ok() {
            let _=fs::remove_dir_all(&self.0);
        }
    }
}
fn example(name:&str)->Value {
    let path=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples").join(name);
    parse_json(&fs::read(path).unwrap()).unwrap()
}
fn frozen_write(plan_name:&str,resource:&str)->Value {
    let mut plan=example("execution-plan.json");
    plan["planId"]=json!(plan_name);
    plan["scope"]["resourceIds"]=json!([resource]);
    plan["steps"][0]["effect"]=json!("write");
    plan["steps"][0]["verificationRequirement"]=json!("independent_readback");
    plan["steps"][0]["resourcesWritten"]=json!([resource]);
    plan["planHash"]=json!(projected_digest("ExecutionPlan",&plan).unwrap());
    plan
}
fn reserve(store:&mut DurableStore,plan:&Value,op:&str,key:&str)->Reservation {
    store.reserve_operation(request(plan,op,key)).unwrap()
}
fn request(plan:&Value,op:&str,key:&str)->ReserveOperation {
    ReserveOperation { operation_id:OperationId::new(op).unwrap(),principal:PrincipalId::new("principal-fixture").unwrap(),
        project_id:ProjectId::new("project-fixture").unwrap(),idempotency_key:key.into(),
        plan_id:PlanId::new(plan["planId"].as_str().unwrap()).unwrap(),plan_hash:serde_json::from_value(plan["planHash"].clone()).unwrap(),
        context_id:ContextId::new("context-fixture-01").unwrap() }
}
fn invocation(op:&str,id:&str)->Value {
    let mut value=example("invocation.json");
    value["operationId"]=json!(op);
    value["invocationId"]=json!(id);
    value
}
fn step()->StepId { StepId::new("echo-step").unwrap() }
fn op(id:&str)->OperationId { OperationId::new(id).unwrap() }

#[test]
fn root_is_exclusive_and_sqlite_pragmas_are_verified() {
    let root=TestRoot::new();
    let store=root.store();
    assert!(matches!(DurableStore::open(StoreConfig::new(root.0.clone())),Err(StorageError::Busy)));
    assert_eq!(store.connection.pragma_query_value(None,"foreign_keys",|r|r.get::<_,i64>(0)).unwrap(),1);
    assert_eq!(store.connection.pragma_query_value(None,"synchronous",|r|r.get::<_,i64>(0)).unwrap(),2);
    assert_eq!(store.connection.pragma_query_value(None,"journal_mode",|r|r.get::<_,String>(0)).unwrap(),"wal");
    drop(store);
    assert!(DurableStore::open(StoreConfig::new(root.0.clone())).is_ok());
}

#[test]
fn cas_checks_existing_bytes_and_published_refs_before_commit() {
    let root=TestRoot::new();
    let mut store=root.store();
    let blob=store.put_blob(b"flushed bytes").unwrap();
    assert_eq!(store.put_blob(b"flushed bytes").unwrap(),blob);
    assert_eq!(store.read_blob(&blob).unwrap(),b"flushed bytes");
    store.pin_artifact("artifact-a",&blob).unwrap();
    let orphan=store.put_blob(b"unreferenced orphan").unwrap();
    let gc=store.collect_orphan_blobs(100).unwrap();
    assert_eq!(gc.removed_blobs,1);
    assert!(store.read_blob(&orphan).is_err());
    assert!(store.read_blob(&blob).is_ok());
    fs::write(store.cas.path(&blob.digest),b"corrupted").unwrap();
    assert!(matches!(store.put_blob(b"flushed bytes"),Err(StorageError::Corrupt(_))));
    assert!(store.pin_artifact("artifact-b",&blob).is_err());
    let count:i64=store.connection.query_row("SELECT count(*) FROM blob_refs WHERE owner_id='artifact-b'",[],|r|r.get(0)).unwrap();
    assert_eq!(count,0);
}

#[test]
fn reservations_bind_exactly_one_operation_across_reopen() {
    let root=TestRoot::new();
    let plan=frozen_write("plan-a","resource-a");
    let mut store=root.store();
    store.save_plan(&plan).unwrap();
    assert!(matches!(reserve(&mut store,&plan,"operation-a","key-a"),Reservation::Created(_)));
    let replay=reserve(&mut store,&plan,"unused-operation-b","key-a");
    assert!(matches!(replay,Reservation::Existing(_)));
    assert_eq!(replay.record().operation_id,op("operation-a"));
    let mut different=request(&plan,"operation-b","key-a");
    different.plan_hash=mmmm_contracts::raw_digest(b"different plan");
    assert!(matches!(store.reserve_operation(different),Err(StorageError::Conflict("Idempotency key"))));
    drop(store);
    let mut store=root.store();
    assert_eq!(reserve(&mut store,&plan,"unused-operation-c","key-a").record().operation_id,op("operation-a"));
    assert!(store.unresolved_dispatches().unwrap().is_empty());
}

#[test]
fn restart_after_intent_never_resends_and_keeps_scoped_fence() {
    let root=TestRoot::new();
    let plan=frozen_write("plan-a","resource-a");
    let mut store=root.store();
    store.save_plan(&plan).unwrap();
    reserve(&mut store,&plan,"operation-a","key-a");
    let intent=invocation("operation-a","invocation-a");
    store.dispatch_intent(&op("operation-a"),&step(),&intent).unwrap();
    assert!(matches!(store.dispatch_intent(&op("operation-a"),&step(),&intent),Err(StorageError::Conflict(_))));
    drop(store);
    let store=root.store();
    let records=store.unresolved_dispatches().unwrap();
    assert_eq!(records.len(),1);
    assert_eq!(records[0].state,OperationState::OutcomeUnknown);
    assert_eq!(records[0].steps[0].dispatch,DispatchEvidence::IntentDurable);
    assert!(records[0].steps[0].further_effects_possible);
    assert_eq!(store.stored_invocation(&op("operation-a"),&step()).unwrap(),intent);
    let scope:WriteScope=serde_json::from_value(plan["scope"].clone()).unwrap();
    assert!(matches!(store.check_write_scope(&scope,false,None),Err(StorageError::Fenced(_))));
    let mut disjoint=scope.clone();
    disjoint.resource_ids=vec![mmmm_contracts::ResourceId::new("resource-b").unwrap()];
    assert!(store.check_write_scope(&disjoint,false,None).is_ok());
    assert!(store.plan(&request(&plan,"unused","unused").plan_id,&request(&plan,"unused","unused").plan_hash).is_ok());
}

#[test]
fn partial_changes_uncertainty_recovery_and_gc_survive_restart() {
    let root=TestRoot::new();
    let plan=frozen_write("plan-a","resource-a");
    let mut store=root.store();
    store.save_plan(&plan).unwrap();
    reserve(&mut store,&plan,"operation-a","key-a");
    store.dispatch_intent(&op("operation-a"),&step(),&invocation("operation-a","invocation-a")).unwrap();
    let evidence=store.put_blob(b"independent observed partial after-state").unwrap();
    let record=store.record_observation(&op("operation-a"),&step(),StepObservation {
        dispatch:DispatchEvidence::Observed,effect:EffectEvidence::SomeConfirmed,further_effects_possible:true,
        provider_receipt:Some("receipt-a".into()),observation_refs:vec![evidence.clone()],finished:false }).unwrap();
    assert_eq!(record.steps[0].effect,EffectEvidence::SomeConfirmed);
    assert_eq!(store.mark_outcome_unknown(&op("operation-a"),&step()).unwrap().state,OperationState::Partial);
    let before=store.put_blob(b"direct before").unwrap();
    let after=store.put_blob(b"direct after").unwrap();
    let snapshot=RecoverySnapshot { operation_id:op("operation-a"),target:"file:one".into(),
        context_id:ContextId::new("context-fixture-01").unwrap(),binding_id:"binding-fixture-01".into(),epoch:"epoch-fixture-01".into(),before:before.clone(),after:after.clone() };
    store.save_recovery_snapshot(snapshot.clone()).unwrap();
    store.put_blob(b"safe orphan").unwrap();
    assert_eq!(store.collect_orphan_blobs(100).unwrap().removed_blobs,1);
    assert!(store.read_blob(&before).is_ok() && store.read_blob(&after).is_ok() && store.read_blob(&evidence).is_ok());
    drop(store);
    let store=root.store();
    let record=store.operation(&op("operation-a")).unwrap();
    assert_eq!(record.state,OperationState::Partial);
    assert_eq!(record.steps[0].effect,EffectEvidence::SomeConfirmed);
    assert_eq!(record.steps[0].provider_receipt.as_deref(),Some("receipt-a"));
    assert!(record.steps[0].further_effects_possible);
    assert_eq!(store.recovery_snapshot(&op("operation-a"),"file:one",&snapshot.context_id,&snapshot.binding_id,&snapshot.epoch,&after).unwrap(),snapshot);
    let changed=store.put_blob(b"person edited after").unwrap();
    assert!(matches!(store.recovery_snapshot(&op("operation-a"),"file:one",&snapshot.context_id,&snapshot.binding_id,&snapshot.epoch,&changed),Err(StorageError::Conflict("Recovery after-state"))));
    assert!(store.recovery_snapshot(&op("operation-a"),"file:one",&snapshot.context_id,&snapshot.binding_id,"new-epoch",&after).is_err());
}

#[test]
fn acknowledgement_cannot_satisfy_readback_and_cancel_keeps_effects() {
    let root=TestRoot::new();
    let plan=frozen_write("plan-a","resource-a");
    let mut store=root.store();
    store.save_plan(&plan).unwrap();
    reserve(&mut store,&plan,"operation-queued","queued-key");
    assert_eq!(store.request_cancel(&op("operation-queued")).unwrap().state,OperationState::Cancelled);
    assert!(store.dispatch_intent(&op("operation-queued"),&step(),&invocation("operation-queued","invocation-q")).is_err());
    reserve(&mut store,&plan,"operation-a","key-a");
    store.dispatch_intent(&op("operation-a"),&step(),&invocation("operation-a","invocation-a")).unwrap();
    assert_eq!(store.request_cancel(&op("operation-a")).unwrap().state,OperationState::CancelRequested);
    assert!(store.finish_operation(&op("operation-a"),OperationState::Cancelled).is_err());
    store.record_observation(&op("operation-a"),&step(),StepObservation {
        dispatch:DispatchEvidence::Acknowledged,effect:EffectEvidence::CompleteConfirmed,further_effects_possible:false,
        provider_receipt:Some("receipt-a".into()),observation_refs:vec![],finished:false }).unwrap();
    assert!(store.finish_operation(&op("operation-a"),OperationState::Succeeded).is_err());
    let observed=store.put_blob(b"independent final target readback").unwrap();
    store.record_observation(&op("operation-a"),&step(),StepObservation {
        dispatch:DispatchEvidence::Observed,effect:EffectEvidence::CompleteConfirmed,further_effects_possible:false,
        provider_receipt:Some("receipt-a".into()),observation_refs:vec![observed],finished:true }).unwrap();
    assert_eq!(store.finish_operation(&op("operation-a"),OperationState::Succeeded).unwrap().state,OperationState::Succeeded);
    let scope:WriteScope=serde_json::from_value(plan["scope"].clone()).unwrap();
    assert!(store.check_write_scope(&scope,false,None).is_ok());
}

#[test]
fn changed_arguments_or_context_cannot_cross_frozen_dispatch_boundary() {
    let root=TestRoot::new();
    let plan=frozen_write("plan-a","resource-a");
    let mut store=root.store();
    store.save_plan(&plan).unwrap();
    reserve(&mut store,&plan,"operation-a","key-a");
    let mut inv=invocation("operation-a","invocation-a");
    inv["arguments"]["text"]=json!("changed");
    inv["argumentsDigest"]=json!(mmmm_contracts::canonical_digest(&inv["arguments"]).unwrap());
    assert!(matches!(store.dispatch_intent(&op("operation-a"),&step(),&inv),Err(StorageError::Conflict("Frozen invocation arguments"))));
    inv=invocation("operation-a","invocation-a");
    inv["context"]["origin"][0]=json!(100);
    assert!(store.dispatch_intent(&op("operation-a"),&step(),&inv).is_err());
    assert_eq!(store.operation(&op("operation-a")).unwrap().steps[0].dispatch,DispatchEvidence::NotSent);
}

#[test]
fn project_revision_conflict_preserves_previous_head() {
    let root=TestRoot::new();
    let mut store=root.store();
    let project=example("project.json");
    store.save_project(&project,None).unwrap();
    let mut changed=project.clone();
    changed["name"]=json!("Updated project");
    changed["revision"]=json!(projected_digest("Project",&changed).unwrap());
    assert!(matches!(store.save_project(&changed,None),Err(StorageError::Conflict("Project revision"))));
    let id=ProjectId::new("project-fixture").unwrap();
    assert_eq!(store.project(&id).unwrap(),project);
    let old=serde_json::from_value(project["revision"].clone()).unwrap();
    store.save_project(&changed,Some(&old)).unwrap();
    assert_eq!(store.project(&id).unwrap(),changed);
    assert!(encode_json(&changed).is_ok());
}

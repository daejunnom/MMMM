//! Original echo examples are read-only and have no recoverable target bytes.
//! These fixtures adapt their descriptor/step and recompute the canonical pins
//! so real durable writes, independent readback, and recovery can be exercised.
//! A successful fake-target check is never evidence of actual game acceptance.

use crate::*;
use mmmm_contracts::{
    BindingId, ContextId, InvocationId, OperationId, PlanId, Sha256Digest, canonical_digest,
    parse_json, projected_digest, raw_digest,
};
use mmmm_runtime::storage::{
    DispatchEvidence, EffectEvidence, Reservation, ReserveOperation, StoreConfig, WriteScope,
};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

const TARGET: &str = "resource-wall-blocks";
const ROOT_MARKER: &[u8] = b"mmmm-application-test\n";
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).expect("managed temporary root");
        let root = parent.join(format!(
            "mmmm-application-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let checkout = fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .expect("source checkout");
        assert!(root.is_absolute() && !root.starts_with(checkout));
        fs::create_dir(&root).expect("fresh owned data root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(root.join("test-owner.txt"), ROOT_MARKER).unwrap();
        Self(root)
    }
}

fn owned_plain_tree(path: &Path, root: &Path) -> bool {
    if !path.is_absolute() || !path.starts_with(root) {
        return false;
    }
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    if metadata.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return false;
        };
        entries
            .into_iter()
            .all(|entry| entry.is_ok_and(|entry| owned_plain_tree(&entry.path(), root)))
    } else {
        metadata.is_file()
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        // The Fixture explicitly closes SQLite before this cleanup. Only its
        // freshly created, marked, absolute tree with no links is removed.
        if owned_plain_tree(&self.0, &self.0)
            && fs::read(self.0.join("test-owner.txt")).ok().as_deref() == Some(ROOT_MARKER)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn example(bytes: &[u8]) -> Value {
    parse_json(bytes).unwrap()
}
fn project_example() -> Value {
    example(include_bytes!("../../../examples/project.json"))
}
fn context_example() -> Value {
    example(include_bytes!("../../../examples/execution-context.json"))
}
fn write_descriptor() -> Value {
    let provider = example(include_bytes!("../../../examples/provider-supported.json"));
    let mut descriptor = provider["actions"][0].clone();
    descriptor["effect"] = json!("write");
    descriptor["recovery"] = json!("explicit_patch");
    descriptor["cancellation"] = json!("cooperative");
    descriptor["idempotency"] = json!("coordinator_only");
    descriptor["verificationRequirement"] = json!("independent_readback");
    descriptor["implementationDigest"] = json!(raw_digest(b"application-target-fixture-v1"));
    descriptor["summary"] =
        json!("Mutates the owned test target; independent observer verifies actual bytes.");
    descriptor
}
fn write_step(descriptor: &Value, id: &str, text: &str, dependencies: Vec<&str>) -> Value {
    let plan = example(include_bytes!("../../../examples/execution-plan.json"));
    let mut step = plan["steps"][0].clone();
    step["stepId"] = json!(id);
    step["arguments"] = json!({"text":text});
    step["dependsOn"] = json!(dependencies);
    for field in [
        "effect",
        "recovery",
        "verificationRequirement",
        "implementationDigest",
    ] {
        step[field] = descriptor[field].clone();
    }
    step["actionDigest"] = json!(canonical_digest(descriptor).unwrap());
    step["resourcesWritten"] = json!([TARGET]);
    step
}

#[derive(Clone)]
struct TargetChange {
    before: Vec<u8>,
    after: Vec<u8>,
}
struct TargetState {
    targets: BTreeMap<String, Vec<u8>>,
    invocations: BTreeMap<String, TargetChange>,
    dispatches: usize,
    write_dispatches: usize,
    polls: usize,
    cancel_requests: usize,
    readbacks: usize,
    apply_grant: bool,
    revoke_after_dispatch: bool,
    lose_response: bool,
    malformed_response: bool,
    observer_available: bool,
    edit_after_first_readback: bool,
    fail_read: bool,
}
impl TargetState {
    fn new() -> Self {
        Self {
            targets: BTreeMap::from([(TARGET.to_owned(), b"before".to_vec())]),
            invocations: BTreeMap::new(),
            dispatches: 0,
            write_dispatches: 0,
            polls: 0,
            cancel_requests: 0,
            readbacks: 0,
            apply_grant: true,
            revoke_after_dispatch: false,
            lose_response: false,
            malformed_response: false,
            observer_available: true,
            edit_after_first_readback: false,
            fail_read: false,
        }
    }
}
type SharedTarget = Rc<RefCell<TargetState>>;

struct Authority {
    target: SharedTarget,
}
impl AuthorityPort for Authority {
    fn authorize(
        &mut self,
        _principal: &PrincipalId,
        _project: &ProjectId,
        access: Access,
        _context: Option<&Value>,
        _plan: Option<&Value>,
    ) -> AppResult<()> {
        if access == Access::Apply && !self.target.borrow().apply_grant {
            Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Test grant was revoked",
            ))
        } else {
            Ok(())
        }
    }
}

struct Planner {
    prepared: PreparedPlan,
    preparations: usize,
    recovery_preparations: usize,
    last_recovery_source_count: usize,
}
impl PlanningPort for Planner {
    fn inspect_project(
        &mut self,
        _principal: &PrincipalId,
        _project: &Value,
    ) -> AppResult<ProjectInspection> {
        Ok(ProjectInspection {
            diagnostics: vec![],
            unresolved_references: vec![],
            runtime_bindings_available: false,
        })
    }
    fn prepare(
        &mut self,
        _principal: &PrincipalId,
        _request: &Value,
        _project: &Value,
        _context: &Value,
    ) -> AppResult<PreparedPlan> {
        self.preparations += 1;
        Ok(self.prepared.clone())
    }
    fn prepare_recovery(
        &mut self,
        _principal: &PrincipalId,
        recovery: &RecoveryPreparation,
        _project: &Value,
        context: &Value,
    ) -> AppResult<PreparedPlan> {
        self.recovery_preparations += 1;
        assert_eq!(recovery.targets.len(), 1);
        let target = &recovery.targets[0];
        self.last_recovery_source_count = target.source_snapshots.len();
        let mut prepared = self.prepared.clone();
        prepared.contexts = vec![context.clone()];
        prepared.steps.truncate(1);
        prepared.steps[0]["arguments"] =
            json!({"text":String::from_utf8(target.before_bytes.clone()).unwrap()});
        prepared.preconditions = vec![json!({
            "kind":"resource_hash", "subject":target.snapshot.target,
            "expected":target.snapshot.after.digest, "coverage":"full_target"
        })];
        Ok(prepared)
    }
}

struct Provider {
    target: SharedTarget,
    live_context: Value,
    descriptor: Value,
    extra_descriptors: BTreeMap<String, Value>,
}
impl ProviderPort for Provider {
    fn context(&mut self, _principal: &PrincipalId, _context: &ContextId) -> AppResult<Value> {
        Ok(self.live_context.clone())
    }
    fn action_descriptor(&mut self, step: &Value, _context: &Value) -> AppResult<Value> {
        Ok(self
            .extra_descriptors
            .get(step["actionId"].as_str().unwrap())
            .unwrap_or(&self.descriptor)
            .clone())
    }
    fn observe_precondition(
        &mut self,
        precondition: &Value,
        _context: &Value,
    ) -> AppResult<Sha256Digest> {
        let target = self.target.borrow();
        let bytes = target
            .targets
            .get(precondition["subject"].as_str().unwrap())
            .unwrap();
        Ok(raw_digest(bytes))
    }
    fn verify_dependencies(&mut self, pins: &[Value], _context: &Value) -> AppResult<()> {
        assert!(pins.is_empty());
        Ok(())
    }
    fn dispatch(&mut self, invocation: &Value) -> AppResult<Value> {
        let is_read = self
            .extra_descriptors
            .get(invocation["actionId"].as_str().unwrap())
            .unwrap_or(&self.descriptor)["effect"]
            == "read";
        let mut target = self.target.borrow_mut();
        let id = invocation["invocationId"].as_str().unwrap().to_owned();
        assert!(
            !target.invocations.contains_key(&id),
            "invocation cannot be retransmitted"
        );
        let before = target.targets[TARGET].clone();
        let after = if is_read {
            before.clone()
        } else {
            invocation["arguments"]["text"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec()
        };
        if !is_read {
            target.targets.insert(TARGET.into(), after.clone());
            target.write_dispatches += 1;
        }
        target
            .invocations
            .insert(id, TargetChange { before, after });
        target.dispatches += 1;
        if target.revoke_after_dispatch {
            target.apply_grant = false;
        }
        if is_read && target.fail_read {
            Ok(
                json!({"contractVersion":"0.2.0","status":"failed","data":{},
                "effects":"none","diagnostics":[],"artifacts":[]}),
            )
        } else if target.lose_response {
            Err(AppError::new(
                "OUTCOME_UNKNOWN",
                "The dispatched response was lost",
            ))
        } else {
            Ok(json!({
                "contractVersion":"0.2.0", "status":"complete", "data":if target.malformed_response { json!({"text":42}) } else { invocation["arguments"].clone() },
                "effects":"recorded", "diagnostics":[], "artifacts":[]
            }))
        }
    }
    fn poll(&mut self, invocation: &Value, _receipt: Option<&str>) -> AppResult<Option<Value>> {
        let mut target = self.target.borrow_mut();
        target.polls += 1;
        assert!(
            target
                .invocations
                .contains_key(invocation["invocationId"].as_str().unwrap())
        );
        // The original invocation is queried; it is never dispatched again.
        // A retained valid complete response is distinct from target readback.
        Ok(Some(json!({
            "contractVersion":"0.2.0", "status":"complete", "data":invocation["arguments"],
            "effects":"recorded", "diagnostics":[], "artifacts":[]
        })))
    }
    fn request_cancel(&mut self, invocation: &Value, _receipt: Option<&str>) -> AppResult<()> {
        let mut target = self.target.borrow_mut();
        assert!(
            target
                .invocations
                .contains_key(invocation["invocationId"].as_str().unwrap())
        );
        target.cancel_requests += 1;
        // An acknowledgment deliberately does not change bytes or settle work.
        Ok(())
    }
}

struct Observer {
    target: SharedTarget,
}
impl IndependentObserverPort for Observer {
    fn readback(&mut self, invocation: &Value, _scope: &WriteScope) -> AppResult<ReadbackEvidence> {
        let mut target = self.target.borrow_mut();
        target.readbacks += 1;
        if !target.observer_available {
            return Err(AppError::new(
                "RECONCILIATION_INSUFFICIENT",
                "Target observer is unavailable",
            ));
        }
        let change = target.invocations[invocation["invocationId"].as_str().unwrap()].clone();
        let actual = target.targets[TARGET].clone();
        if actual != change.after {
            return Err(AppError::new(
                "TARGET_DRIFT",
                "Actual bytes differ from this invocation's target",
            ));
        }
        let evidence = ReadbackEvidence {
            invocation_id: decode::<InvocationId>(&invocation["invocationId"]).unwrap(),
            binding_id: decode::<BindingId>(&invocation["bindingId"]).unwrap(),
            context_digest: decode(&invocation["contextDigest"]).unwrap(),
            implementation_digest: decode(&invocation["implementationDigest"]).unwrap(),
            arguments_digest: decode(&invocation["argumentsDigest"]).unwrap(),
            effect: EffectEvidence::CompleteConfirmed,
            settled: true,
            evidence: json!({"target":TARGET,"actualDigest":raw_digest(&actual)}),
            direct_changes: vec![DirectChange {
                target: TARGET.into(),
                before: change.before,
                after: actual,
            }],
        };
        if target.edit_after_first_readback && target.readbacks == 1 {
            // The retained observation describes the actual bytes at its read.
            // A later edit must be detected by the successor's own preflight.
            target
                .targets
                .insert(TARGET.into(), b"manual-between-steps".to_vec());
        }
        Ok(evidence)
    }
    fn read_target(&mut self, _invocation: &Value, target: &str) -> AppResult<Vec<u8>> {
        Ok(self.target.borrow().targets[target].clone())
    }
}

struct Ids(u64);
impl IdSource for Ids {
    fn next_id(&mut self, kind: IdKind) -> AppResult<String> {
        self.0 += 1;
        let prefix = match kind {
            IdKind::Plan => "plan",
            IdKind::Operation => "operation",
            IdKind::Invocation => "invocation",
        };
        Ok(format!("{prefix}-application-test-{}", self.0))
    }
}
struct TestClock(Cell<i128>);
impl Clock for TestClock {
    fn unix_nanos(&self) -> i128 {
        self.0.get()
    }
}

struct Fixture {
    // Declared first so the actual database lock closes before the owned root.
    store: DurableStore,
    root: TestRoot,
    principal: PrincipalId,
    project: Value,
    target: SharedTarget,
    authority: Authority,
    planner: Planner,
    provider: Provider,
    observer: Observer,
    ids: Ids,
    clock: TestClock,
}
impl Fixture {
    fn new(steps: usize) -> Self {
        let root = TestRoot::new();
        let mut store = DurableStore::open(StoreConfig::new(root.0.clone())).unwrap();
        let mut project = project_example();
        project["revision"] = json!(projected_digest("Project", &project).unwrap());
        store.save_project(&project, None).unwrap();
        let target = Rc::new(RefCell::new(TargetState::new()));
        let mut context = context_example();
        context["scope"]["resourceIds"] = json!([TARGET]);
        context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
        let descriptor = write_descriptor();
        let mut plan_steps = vec![write_step(
            &descriptor,
            "write-first",
            "after-first",
            vec![],
        )];
        if steps == 2 {
            plan_steps.push(write_step(
                &descriptor,
                "write-second",
                "after-second",
                vec!["write-first"],
            ));
        }
        let prepared = PreparedPlan {
            contexts: vec![context.clone()],
            scope: decode(&context["scope"]).unwrap(),
            preconditions: vec![
                json!({"kind":"resource_hash","subject":TARGET,"expected":raw_digest(b"before"),"coverage":"full_target"}),
            ],
            steps: plan_steps,
            atomicity: "none".into(),
            losses: vec![],
            diagnostics: vec![],
            approval_requirement: "within_existing_grant".into(),
            dependency_pins: vec![],
            expires_at: "2099-01-01T00:00:00Z".into(),
            time_budget_ms: 10_000,
        };
        Self {
            store,
            root,
            principal: PrincipalId::new("principal-fixture").unwrap(),
            project,
            authority: Authority {
                target: target.clone(),
            },
            planner: Planner {
                prepared,
                preparations: 0,
                recovery_preparations: 0,
                last_recovery_source_count: 0,
            },
            provider: Provider {
                target: target.clone(),
                live_context: context,
                descriptor,
                extra_descriptors: BTreeMap::new(),
            },
            observer: Observer {
                target: target.clone(),
            },
            target,
            ids: Ids(0),
            clock: TestClock(Cell::new(0)),
        }
    }
    fn app(&mut self) -> Application<'_> {
        Application {
            store: &mut self.store,
            authority: &mut self.authority,
            planner: &mut self.planner,
            provider: &mut self.provider,
            observer: &mut self.observer,
            ids: &mut self.ids,
            clock: &self.clock,
        }
    }
    fn plan(&mut self) -> Value {
        let principal = self.principal.clone();
        let request = json!({
            "projectId":self.project["projectId"], "expectedRevision":self.project["revision"],
            "contextId":self.provider.live_context["contextId"],
            "intent":example(include_bytes!("../../../examples/change-intent.json"))
        });
        self.app().plan_create(&principal, &request).unwrap()
    }
    fn apply(&mut self, plan: &Value, key: &str) -> AppResult<Value> {
        let principal = self.principal.clone();
        self.app().plan_apply(
            &principal,
            &json!({
                "contractVersion":"0.2.0", "planId":plan["planId"], "planHash":plan["planHash"],
                "contextId":plan["contextId"], "idempotencyKey":key
            }),
        )
    }
    fn query(report: &Value) -> Value {
        json!({"operationId":report["operationId"],"contextId":"context-fixture-01"})
    }
    fn reconcile(&mut self, report: &Value) -> Value {
        let principal = self.principal.clone();
        self.app()
            .operation_reconcile(&principal, &Self::query(report))
            .unwrap()
    }
    fn cancel(&mut self, report: &Value) -> Value {
        let principal = self.principal.clone();
        self.app()
            .operation_cancel(&principal, &Self::query(report))
            .unwrap()
    }
    fn recovery(&mut self, report: &Value) -> AppResult<Value> {
        let principal = self.principal.clone();
        let mut request = Self::query(report);
        request["mode"] = json!("recorded_direct");
        self.app().recovery_plan(&principal, &request)
    }
}

fn has_diagnostic(report: &Value, code: &str) -> bool {
    report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["code"] == code)
}

#[test]
fn planning_has_no_target_effects_and_apply_twice_retains_one_durable_dispatch() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    assert_eq!(fixture.planner.preparations, 1);
    assert_eq!(fixture.target.borrow().dispatches, 0);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"before");
    let first = fixture.apply(&plan, "same-key").unwrap();
    assert_eq!(first["state"], "succeeded");
    assert_eq!(first["verification"], "independent_readback");
    assert_eq!(first["completedStepIds"], json!(["write-first"]));
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
    // Expiry/revocation cannot turn a retrieval of the original operation into
    // another write. Its durable idempotency identity remains unchanged.
    fixture.target.borrow_mut().apply_grant = false;
    fixture.clock.0.set(i128::MAX);
    let repeated = fixture.apply(&plan, "same-key").unwrap();
    assert_eq!(repeated, first);
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().readbacks, 1);
    let id: OperationId = decode(&first["operationId"]).unwrap();
    let record = fixture.store.operation(&id).unwrap();
    assert_eq!(record.steps[0].dispatch, DispatchEvidence::Observed);
    assert!(record.steps[0].finished);
    assert_eq!(fixture.store.recovery_snapshots(&id).unwrap().len(), 1);
    assert!(fixture.root.0.is_absolute());
}

#[test]
fn unknown_dispatch_is_never_retried_and_reconcile_observes_the_original_target() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture.target.borrow_mut().lose_response = true;
    fixture.target.borrow_mut().observer_available = false;
    let unknown = fixture.apply(&plan, "unknown-key").unwrap();
    assert_eq!(unknown["state"], "outcome_unknown");
    assert_eq!(unknown["nextAction"], "reconcile");
    assert_eq!(unknown["completedStepIds"], json!([]));
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
    assert_eq!(fixture.apply(&plan, "unknown-key").unwrap(), unknown);
    assert_eq!(fixture.target.borrow().dispatches, 1);
    fixture.target.borrow_mut().observer_available = true;
    let resolved = fixture.reconcile(&unknown);
    assert_eq!(resolved["state"], "succeeded");
    assert_eq!(resolved["verification"], "independent_readback");
    assert_eq!(resolved["completedStepIds"], json!(["write-first"]));
    assert!(
        has_diagnostic(&resolved, "OUTCOME_UNKNOWN"),
        "failure history is retained"
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().polls, 1);
}

#[test]
fn actual_target_drift_before_dispatch_preserves_bytes_and_has_zero_provider_calls() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture
        .target
        .borrow_mut()
        .targets
        .insert(TARGET.into(), b"manual-before-apply".to_vec());
    let report = fixture.apply(&plan, "drift-key").unwrap();
    assert_eq!(report["state"], "failed_before_effects");
    assert!(has_diagnostic(&report, "TARGET_DRIFT"));
    assert_eq!(report["dispatchEvidence"], "not_dispatched");
    assert_eq!(fixture.target.borrow().dispatches, 0);
    assert_eq!(
        fixture.target.borrow().targets[TARGET],
        b"manual-before-apply"
    );
}

#[test]
fn malformed_complete_output_cannot_succeed_even_when_actual_target_change_is_confirmed() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture.target.borrow_mut().malformed_response = true;
    let unverified = fixture.apply(&plan, "malformed-key").unwrap();
    assert_ne!(unverified["state"], "succeeded");
    assert_eq!(unverified["completedStepIds"], json!([]));
    assert_eq!(unverified["unverifiedStepIds"], json!(["write-first"]));
    assert!(has_diagnostic(&unverified, "INVALID_PROVIDER_OUTPUT"));
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
    assert_eq!(fixture.target.borrow().dispatches, 1);
    let resolved = fixture.reconcile(&unverified);
    assert_eq!(resolved["state"], "succeeded");
    assert_eq!(resolved["completedStepIds"], json!(["write-first"]));
    assert!(has_diagnostic(&resolved, "INVALID_PROVIDER_OUTPUT"));
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().polls, 1);
}

#[test]
fn grant_revocation_after_verified_first_step_blocks_the_successor() {
    let mut fixture = Fixture::new(2);
    let plan = fixture.plan();
    fixture.target.borrow_mut().revoke_after_dispatch = true;
    let report = fixture.apply(&plan, "revoked-key").unwrap();
    assert_eq!(report["state"], "partial");
    assert!(has_diagnostic(&report, "PERMISSION_REQUIRED"));
    assert_eq!(report["completedStepIds"], json!(["write-first"]));
    assert_eq!(report["pendingStepIds"], json!(["write-second"]));
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-first");
    let repeated = fixture.apply(&plan, "revoked-key").unwrap();
    assert_eq!(repeated["operationId"], report["operationId"]);
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

#[test]
fn ordered_same_target_writes_preserve_the_exact_independent_before_after_chain() {
    let mut fixture = Fixture::new(2);
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "ordered-key").unwrap();
    assert_eq!(report["state"], "succeeded");
    assert_eq!(
        report["completedStepIds"],
        json!(["write-first", "write-second"])
    );
    assert_eq!(fixture.target.borrow().targets[TARGET], b"after-second");
    assert_eq!(fixture.target.borrow().dispatches, 2);
    assert_eq!(fixture.target.borrow().readbacks, 2);
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let snapshots = fixture.store.recovery_snapshots(&operation).unwrap();
    assert_eq!(snapshots.len(), 2);
    let first = snapshots
        .iter()
        .find(|s| s.step_id.as_str() == "write-first")
        .unwrap();
    let second = snapshots
        .iter()
        .find(|s| s.step_id.as_str() == "write-second")
        .unwrap();
    assert_eq!(fixture.store.read_blob(&first.before).unwrap(), b"before");
    assert_eq!(
        fixture.store.read_blob(&first.after).unwrap(),
        b"after-first"
    );
    assert_eq!(second.before.digest, first.after.digest);
    assert_eq!(
        fixture.store.read_blob(&second.before).unwrap(),
        b"after-first"
    );
    assert_eq!(
        fixture.store.read_blob(&second.after).unwrap(),
        b"after-second"
    );
    let frozen = fixture
        .store
        .plan(
            &decode(&plan["planId"]).unwrap(),
            &decode(&plan["planHash"]).unwrap(),
        )
        .unwrap();
    assert_eq!(
        frozen, plan,
        "execution evidence never rewrites the frozen plan"
    );
    assert_eq!(
        frozen["preconditions"][0]["expected"],
        json!(raw_digest(b"before"))
    );
    let recovery = fixture.recovery(&report).unwrap();
    assert_ne!(recovery["planId"], plan["planId"]);
    assert_eq!(recovery["steps"][0]["arguments"]["text"], "before");
    assert_eq!(
        recovery["preconditions"][0]["expected"],
        json!(raw_digest(b"after-second"))
    );
    assert_eq!(fixture.planner.last_recovery_source_count, 2);
    assert_eq!(
        fixture.target.borrow().dispatches,
        2,
        "aggregated recovery planning is pure"
    );
}

#[test]
fn manual_edit_after_first_readback_blocks_the_ordered_same_target_successor() {
    let mut fixture = Fixture::new(2);
    let plan = fixture.plan();
    fixture.target.borrow_mut().edit_after_first_readback = true;
    let report = fixture.apply(&plan, "intervening-edit-key").unwrap();
    assert_eq!(report["state"], "partial");
    assert!(has_diagnostic(&report, "TARGET_DRIFT"));
    assert_eq!(report["completedStepIds"], json!(["write-first"]));
    assert_eq!(report["pendingStepIds"], json!(["write-second"]));
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().readbacks, 1);
    assert_eq!(
        fixture.target.borrow().targets[TARGET],
        b"manual-between-steps"
    );
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let snapshots = fixture.store.recovery_snapshots(&operation).unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(
        fixture.store.read_blob(&snapshots[0].after).unwrap(),
        b"after-first"
    );
}

#[test]
fn project_inspect_resolves_retained_historical_revision_after_the_head_advances() {
    let mut fixture = Fixture::new(1);
    let original = fixture.project.clone();
    let previous: Sha256Digest = decode(&original["revision"]).unwrap();
    let mut updated = original.clone();
    updated["name"] = json!("Updated authoring project");
    updated["revision"] = json!(projected_digest("Project", &updated).unwrap());
    fixture
        .store
        .save_project(&updated, Some(&previous))
        .unwrap();
    let principal = fixture.principal.clone();
    let historical = fixture
        .app()
        .project_inspect(
            &principal,
            &json!({
                "projectId":original["projectId"], "expectedRevision":original["revision"]
            }),
        )
        .unwrap();
    assert_eq!(historical["project"], original);
    assert_eq!(historical["runtimeBindingsAvailable"], false);
    let current = fixture
        .app()
        .project_inspect(
            &principal,
            &json!({
                "projectId":original["projectId"], "expectedRevision":null
            }),
        )
        .unwrap();
    assert_eq!(current["project"], updated);
    let missing = fixture.app().project_inspect(&principal, &json!({
        "projectId":original["projectId"], "expectedRevision":raw_digest(b"unretained-project-revision")
    })).unwrap_err();
    assert_eq!(missing.code, "REVISION_CONFLICT");
    assert_eq!(fixture.target.borrow().dispatches, 0);
}

#[test]
fn changed_session_with_a_valid_new_digest_still_rejects_the_frozen_context() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture.provider.live_context["environment"]["sessionEpoch"] = json!("epoch-fixture-new");
    fixture.provider.live_context["contextDigest"] =
        json!(projected_digest("ExecutionContext", &fixture.provider.live_context).unwrap());
    let report = fixture.apply(&plan, "stale-context-key").unwrap();
    assert_eq!(report["state"], "failed_before_effects");
    assert!(has_diagnostic(&report, "STALE_CONTEXT"));
    assert_eq!(fixture.target.borrow().dispatches, 0);
}

#[test]
fn changed_implementation_rejects_the_frozen_route_before_dispatch() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture.provider.descriptor["implementationDigest"] =
        json!(raw_digest(b"replacement-implementation"));
    let report = fixture.apply(&plan, "stale-implementation-key").unwrap();
    assert_eq!(report["state"], "failed_before_effects");
    assert!(has_diagnostic(&report, "STALE_PLAN"));
    assert_eq!(fixture.target.borrow().dispatches, 0);
}

#[test]
fn queued_cancel_is_terminal_but_dispatched_cancel_acknowledgment_is_not() {
    let mut queued = Fixture::new(1);
    let plan = queued.plan();
    let reservation = queued
        .store
        .reserve_operation(ReserveOperation {
            operation_id: OperationId::new("operation-queued-test").unwrap(),
            principal: queued.principal.clone(),
            project_id: decode(&plan["projectId"]).unwrap(),
            idempotency_key: "queued-key".into(),
            plan_id: decode::<PlanId>(&plan["planId"]).unwrap(),
            plan_hash: decode(&plan["planHash"]).unwrap(),
            context_id: decode(&plan["contextId"]).unwrap(),
        })
        .unwrap();
    assert!(matches!(reservation, Reservation::Created(_)));
    let cancelled = queued.cancel(&json!({"operationId":"operation-queued-test"}));
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(queued.target.borrow().dispatches, 0);
    assert_eq!(queued.target.borrow().cancel_requests, 0);
    assert_eq!(
        queued.apply(&plan, "queued-key").unwrap()["state"],
        "cancelled"
    );

    let mut dispatched = Fixture::new(1);
    let plan = dispatched.plan();
    dispatched.target.borrow_mut().observer_available = false;
    let unknown = dispatched.apply(&plan, "running-key").unwrap();
    let requested = dispatched.cancel(&unknown);
    assert_eq!(requested["state"], "cancel_requested");
    assert_eq!(requested["nextAction"], "reconcile");
    assert_eq!(dispatched.target.borrow().cancel_requests, 1);
    assert_eq!(dispatched.target.borrow().targets[TARGET], b"after-first");
    let id: OperationId = decode(&requested["operationId"]).unwrap();
    assert!(
        dispatched
            .store
            .operation(&id)
            .unwrap()
            .cancellation_requested
    );
    dispatched.cancel(&requested);
    assert_eq!(dispatched.target.borrow().cancel_requests, 1);
    dispatched.target.borrow_mut().observer_available = true;
    let resolved = dispatched.reconcile(&requested);
    assert_eq!(resolved["state"], "succeeded");
    assert!(
        dispatched
            .store
            .operation(&id)
            .unwrap()
            .cancellation_requested
    );
    assert_eq!(dispatched.target.borrow().dispatches, 1);
}

#[test]
fn recorded_recovery_is_a_new_pinned_plan_and_never_erases_a_manual_edit() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "original-key").unwrap();
    let recovery = fixture.recovery(&report).unwrap();
    assert_ne!(recovery["planId"], plan["planId"]);
    assert_eq!(
        recovery["preconditions"][0]["expected"],
        json!(raw_digest(b"after-first"))
    );
    assert_eq!(
        fixture.target.borrow().dispatches,
        1,
        "recovery planning stays pure"
    );
    fixture
        .target
        .borrow_mut()
        .targets
        .insert(TARGET.into(), b"manual-after-apply".to_vec());
    let conflict = fixture.recovery(&report).unwrap_err();
    assert_eq!(conflict.code, "RECOVERY_CONFLICT");
    assert_eq!(
        fixture.planner.recovery_preparations, 1,
        "conflicting bytes never reach recovery compilation"
    );
    let rejected = fixture.apply(&recovery, "recovery-key").unwrap();
    assert_eq!(rejected["state"], "failed_before_effects");
    assert!(has_diagnostic(&rejected, "TARGET_DRIFT"));
    assert_eq!(
        fixture.target.borrow().targets[TARGET],
        b"manual-after-apply"
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

#[test]
fn same_idempotency_key_cannot_select_a_different_frozen_plan() {
    let mut fixture = Fixture::new(1);
    let first = fixture.plan();
    let second = fixture.plan();
    fixture.apply(&first, "bound-key").unwrap();
    assert_eq!(
        fixture.apply(&second, "bound-key").unwrap_err().code,
        "IDEMPOTENCY_CONFLICT"
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

#[test]
fn failed_read_predecessor_never_authorizes_its_dependent_target_write() {
    let mut fixture = Fixture::new(2);
    let mut descriptor = fixture.provider.descriptor.clone();
    descriptor["actionId"] = json!("fixture:read_text");
    descriptor["effect"] = json!("read");
    descriptor["recovery"] = json!("none");
    descriptor["cancellation"] = json!("none");
    descriptor["idempotency"] = json!("read");
    descriptor["verificationRequirement"] = json!("provider_completion");
    descriptor["summary"] = json!("Reads the owned target without mutating it.");
    let first = &mut fixture.planner.prepared.steps[0];
    first["actionId"] = descriptor["actionId"].clone();
    for field in [
        "effect",
        "recovery",
        "verificationRequirement",
        "implementationDigest",
    ] {
        first[field] = descriptor[field].clone();
    }
    first["actionDigest"] = json!(canonical_digest(&descriptor).unwrap());
    first["resourcesWritten"] = json!([]);
    first["resourcesRead"] = json!([TARGET]);
    fixture
        .provider
        .extra_descriptors
        .insert("fixture:read_text".into(), descriptor);
    fixture.target.borrow_mut().fail_read = true;
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "failed-read-key").unwrap();
    assert_eq!(report["state"], "failed_before_effects");
    assert!(has_diagnostic(&report, "PROVIDER_FAILED"));
    assert_eq!(report["completedStepIds"], json!([]));
    assert_eq!(
        fixture.target.borrow().dispatches,
        1,
        "only the read is called"
    );
    assert_eq!(fixture.target.borrow().write_dispatches, 0);
    assert_eq!(fixture.target.borrow().targets[TARGET], b"before");
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let record = fixture.store.operation(&operation).unwrap();
    assert!(
        !record.steps[0].finished,
        "a failed read is not a verified dependency"
    );
    assert_eq!(record.steps[1].dispatch, DispatchEvidence::NotSent);
    assert!(
        fixture
            .store
            .recovery_snapshots(&operation)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn current_observe_grant_can_reconcile_original_job_after_apply_policy_revocation() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    fixture.target.borrow_mut().lose_response = true;
    fixture.target.borrow_mut().observer_available = false;
    let unknown = fixture.apply(&plan, "policy-change-key").unwrap();
    let operation: OperationId = decode(&unknown["operationId"]).unwrap();
    let step = decode(&plan["steps"][0]["stepId"]).unwrap();
    let original_invocation = fixture.store.stored_invocation(&operation, &step).unwrap();
    fixture.target.borrow_mut().apply_grant = false;
    fixture.target.borrow_mut().observer_available = true;
    fixture.provider.live_context["policyRevision"] =
        json!(raw_digest(b"revoked-apply-current-observe-policy"));
    fixture.provider.live_context["contextDigest"] =
        json!(projected_digest("ExecutionContext", &fixture.provider.live_context).unwrap());
    assert_ne!(
        fixture.provider.live_context["contextDigest"],
        original_invocation["contextDigest"]
    );
    let resolved = fixture.reconcile(&unknown);
    assert_eq!(resolved["state"], "succeeded");
    assert_eq!(resolved["verification"], "independent_readback");
    assert_eq!(fixture.target.borrow().dispatches, 1);
    assert_eq!(fixture.target.borrow().polls, 1);
    assert_eq!(
        fixture.store.stored_invocation(&operation, &step).unwrap(),
        original_invocation,
        "a current Observe grant never replaces the original durable invocation"
    );
    assert_eq!(
        fixture.apply(&plan, "policy-change-key").unwrap()["operationId"],
        resolved["operationId"]
    );
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

#[test]
fn retained_readback_envelope_pins_exact_recovery_bytes_across_orphan_collection() {
    let mut fixture = Fixture::new(1);
    let plan = fixture.plan();
    let report = fixture.apply(&plan, "retained-snapshot-key").unwrap();
    let operation: OperationId = decode(&report["operationId"]).unwrap();
    let record = fixture.store.operation(&operation).unwrap();
    assert!(record.steps[0].finished);
    let envelopes: Vec<_> = record.steps[0]
        .observation_refs
        .iter()
        .map(|blob| parse_json(&fixture.store.read_blob(blob).unwrap()).unwrap())
        .filter(|value| value["kind"] == "independent_readback")
        .collect();
    assert!(!envelopes.is_empty());
    let direct = envelopes.last().unwrap()["directChanges"]
        .as_array()
        .unwrap();
    assert_eq!(direct.len(), 1);
    let retained: mmmm_runtime::storage::RecoverySnapshot = decode(&direct[0]).unwrap();
    assert_eq!(retained.operation_id, operation);
    assert_eq!(retained.before.digest, raw_digest(b"before"));
    assert_eq!(retained.after.digest, raw_digest(b"after-first"));
    assert_eq!(
        fixture.store.read_blob(&retained.before).unwrap(),
        b"before"
    );
    assert_eq!(
        fixture.store.read_blob(&retained.after).unwrap(),
        b"after-first"
    );
    assert_eq!(
        fixture.store.recovery_snapshots(&operation).unwrap(),
        vec![retained.clone()]
    );
    let orphan = fixture
        .store
        .put_blob(b"unreferenced application test blob")
        .unwrap();
    assert!(
        fixture
            .store
            .collect_orphan_blobs(100)
            .unwrap()
            .removed_blobs
            >= 1
    );
    assert!(fixture.store.read_blob(&orphan).is_err());
    assert_eq!(
        fixture.store.read_blob(&retained.before).unwrap(),
        b"before"
    );
    assert_eq!(
        fixture.store.read_blob(&retained.after).unwrap(),
        b"after-first"
    );
    for blob in record.steps[0].observation_refs.iter() {
        assert!(
            fixture.store.read_blob(blob).is_ok(),
            "operation evidence remains pinned"
        );
    }
    assert_eq!(fixture.target.borrow().dispatches, 1);
}

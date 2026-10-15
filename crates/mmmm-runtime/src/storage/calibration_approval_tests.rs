//! 기존 native-owned-source의 외부 SQLite/CAS/bootstrap fixture를 재사용한다.
//! 47개의 작은 자체 command는 승인/원장 경계만 검사하며 실제 normative
//! compiler, ADMIN pairing 또는 게임 효과를 검증했다고 주장하지 않는다.

use super::*;
use crate::storage::calibration_approval::*;
use crate::storage::{
    DispatchEvidence, EffectEvidence, OperationState, Reservation, ReserveOperation,
    StepObservation, StepRecord,
};

struct Rpc {
    permit: TestPermit,
    completed: Rc<Cell<bool>>,
    generation: Cell<u64>,
    cancel_on_claim: Cell<bool>,
}
impl CalibrationApprovalRpcContext for Rpc {
    fn check(&self) -> StorageResult<()> {
        self.permit.0.check()
    }
    fn authenticated_local_owner(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.permit.0.owner.clone())
    }
    fn check_current_approval(
        &self,
        store: &DurableStore,
        approval: &CalibrationApprovalRecord,
    ) -> StorageResult<()> {
        self.permit.check_store(store)?;
        if !self.completed.get()
            || approval.confirmation().registry_generation != self.generation.get().to_string()
        {
            return Err(StorageError::Conflict(
                "Fixture current completed ADMIN generation",
            ));
        }
        if self.cancel_on_claim.get() {
            let exists: bool = store.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM calibration_operation_claims WHERE approval_ref=?1)",
                [approval.selection().approval_ref()],
                |r| r.get(0),
            )?;
            if exists {
                self.permit.0.cancelled.set(true);
            }
        }
        self.check()
    }
}
struct Authority {
    permit: TestPermit,
    expected: CalibrationSelectionRequest,
    policy: Value,
    completed: Rc<Cell<bool>>,
    fail_dispatch_and_cancel: bool,
    fail_published_selection: bool,
}
impl CalibrationApprovalAuthority for Authority {
    fn authorize_selection(
        &mut self,
        store: &DurableStore,
        owner: &PrincipalId,
        request: &CalibrationSelectionRequest,
    ) -> StorageResult<()> {
        self.permit.check_store(store)?;
        if owner != &self.permit.0.owner || request != &self.expected {
            return Err(StorageError::Conflict("Fixture exact native selection"));
        }
        let mut reader = self.permit.resource_reader(MAX_CALIBRATION_RECIPE_BYTES)?;
        reader.read_project(
            store,
            &self.permit,
            &request.project_id,
            &request.project_base_revision,
            8 * 1024 * 1024,
        )?;
        let query = ProjectResourceQuery::Current {
            resource_id: serde_json::from_value(self.policy["resourceId"].clone()).unwrap(),
        };
        let loaded = reader.read(
            store,
            &self.permit,
            &ProjectResourceRequest {
                project: &request.project_id,
                current_project_revision: &request.project_base_revision,
                query: &query,
                expected: Some(&self.policy),
            },
            MAX_CALIBRATION_RECIPE_BYTES,
        )?;
        let policy = store
            .validator
            .parse_and_validate("Policy", &loaded.bytes)
            .unwrap();
        if projected_digest("Policy", &policy).unwrap() != request.policy_digest {
            return Err(StorageError::Conflict(
                "Fixture actual Policy semantic digest",
            ));
        }
        if self.fail_published_selection {
            let table: bool = store.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='calibration_selections')",
                [],
                |r| r.get(0),
            )?;
            if table {
                let published: bool = store.connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM calibration_selections WHERE approval_ref=?1)",
                    [&request.approval_ref],
                    |r| r.get(0),
                )?;
                if published {
                    self.permit.0.cancelled.set(true);
                    return Err(StorageError::Conflict(
                        "Fixture source changed after provisional selection",
                    ));
                }
            }
        }
        Ok(())
    }
    fn authorize_confirmation(
        &mut self,
        store: &DurableStore,
        selection: &CalibrationSelectionRecord,
        confirmation: &CalibrationConfirmationRequest,
    ) -> StorageResult<()> {
        self.authorize_selection(store, selection.native_owner(), selection.pins())?;
        if !self.completed.get()
            || confirmation.original_offer_digest != raw_digest(b"fixture-original-offer")
            || confirmation.manifest_digest != raw_digest(b"fixture-manifest")
        {
            return Err(StorageError::Conflict(
                "Fixture actual completed bootstrap absent",
            ));
        }
        Ok(())
    }
    fn authorize_dispatch(
        &mut self,
        store: &DurableStore,
        approval: &CalibrationApprovalRecord,
        invocation: &Value,
    ) -> StorageResult<()> {
        self.authorize_confirmation(store, approval.selection(), approval.confirmation())?;
        if self.fail_dispatch_and_cancel {
            self.permit.0.cancelled.set(true);
            return Err(StorageError::Conflict("Fixture runtime source revoked"));
        }
        if invocation["actionId"] != "mmmm:command_execute" {
            return Err(StorageError::Conflict("Fixture original command route"));
        }
        Ok(())
    }
}

fn seed() -> (TestRoot, DurableStore, Rpc, Authority, Value, Value) {
    let root = TestRoot::new();
    let mut store = root.store();
    let (project, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-calibration");
    let permit = TestPermit::new(&root, &initial);
    let completed = Rc::new(Cell::new(false));
    let rpc = Rpc {
        permit: TestPermit(permit.0.clone()),
        completed: completed.clone(),
        generation: Cell::new(1),
        cancel_on_claim: Cell::new(false),
    };
    let mut context = example("execution-context.json");
    let grant_revision = canonical_digest(&json!({"fixtureGrant":"session"})).unwrap();
    context["policyRevision"] = json!(grant_revision);
    context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
    let mut plan = example("execution-plan.json");
    plan["planId"] = json!("plan-calibration-storage");
    plan["projectBaseRevision"] = json!(revision(&project));
    plan["policyRevision"] = json!(grant_revision);
    plan["scope"]["resourceIds"] = json!(["calibration-target"]);
    plan["contextPins"][0]["contextDigest"] = context["contextDigest"].clone();
    let original = plan["steps"][0].clone();
    let steps: Vec<Value> = (0..47)
        .map(|index| {
            let mut step = original.clone();
            step["stepId"] = json!(format!("calibration-step-{index:02}"));
            step["actionId"] = json!("mmmm:command_execute");
            step["arguments"] =
                json!({"command":format!("function mmmm:storage_fixture/case_{index:02}")});
            step["effect"] = json!("write");
            step["verificationRequirement"] = json!("independent_readback");
            step["resourcesWritten"] = json!(["calibration-target"]);
            step["dependsOn"] = if index == 0 {
                json!([])
            } else {
                json!([format!("calibration-step-{:02}", index - 1)])
            };
            step
        })
        .collect();
    plan["steps"] = json!(steps);
    plan["planHash"] = json!(projected_digest("ExecutionPlan", &plan).unwrap());
    store.save_plan(&plan).unwrap();
    let recipe = store
        .put_blob(b"small storage-only recipe fixture")
        .unwrap();
    let expected = CalibrationSelectionRequest {
        approval_ref: "calibration-fixture".into(),
        project_id: initial.project_id,
        project_base_revision: revision(&project),
        plan_id: serde_json::from_value(plan["planId"].clone()).unwrap(),
        plan_hash: serde_json::from_value(plan["planHash"].clone()).unwrap(),
        policy_revision: grant_revision,
        policy_digest: projected_digest("Policy", &example("policy.json")).unwrap(),
        suite_digest: recipe.digest.clone(),
        recipe,
        host_artifact_digest: raw_digest(b"fixture-host-artifact"),
        scope_digest: canonical_digest(&plan["scope"]).unwrap(),
        context_pins: plan["contextPins"].clone(),
        expires_at: plan["expiresAt"].as_str().unwrap().into(),
    };
    assert_ne!(expected.policy_revision, expected.policy_digest);
    let authority = Authority {
        permit,
        expected,
        policy: initial.policy_resource,
        completed,
        fail_dispatch_and_cancel: false,
        fail_published_selection: false,
    };
    (root, store, rpc, authority, plan, context)
}
fn confirm(
    store: &mut DurableStore,
    rpc: &Rpc,
    authority: &mut Authority,
    selection: &CalibrationSelectionRecord,
) -> StorageResult<CalibrationApprovalRecord> {
    let confirmation = CalibrationConfirmationRequest {
        selection_digest: selection.selection_digest().clone(),
        principal_id: PrincipalId::new("principal-fixture").unwrap(),
        player_id: "00000000-0000-0000-0000-000000000001".into(),
        original_offer_digest: raw_digest(b"fixture-original-offer"),
        nonce: "fixture-nonce".into(),
        host_epoch: "epoch-fixture-01".into(),
        registry_generation: "1".into(),
        runtime_source_facts_digest: raw_digest(b"fixture-runtime-facts"),
        manifest_digest: raw_digest(b"fixture-manifest"),
    };
    confirm_calibration_approval(store, rpc, authority, selection, &confirmation)
}
fn reserve(store: &mut DurableStore, plan: &Value, operation: &str, key: &str) -> Reservation {
    store
        .reserve_operation(ReserveOperation {
            operation_id: OperationId::new(operation).unwrap(),
            principal: PrincipalId::new("principal-fixture").unwrap(),
            project_id: ProjectId::new("project-fixture").unwrap(),
            idempotency_key: key.into(),
            plan_id: serde_json::from_value(plan["planId"].clone()).unwrap(),
            plan_hash: serde_json::from_value(plan["planHash"].clone()).unwrap(),
            context_id: ContextId::new("context-fixture-01").unwrap(),
        })
        .unwrap()
}
fn invocation(plan: &Value, context: &Value, operation: &str, index: usize, id: &str) -> Value {
    let step = &plan["steps"][index];
    let mut invocation = example("invocation.json");
    invocation["operationId"] = json!(operation);
    invocation["invocationId"] = json!(id);
    invocation["stepId"] = step["stepId"].clone();
    for field in [
        "bindingId",
        "actionId",
        "actionContractVersion",
        "actionDigest",
        "implementationDigest",
        "arguments",
    ] {
        invocation[field] = step[field].clone();
    }
    invocation["argumentsDigest"] = json!(canonical_digest(&invocation["arguments"]).unwrap());
    invocation["context"] = context.clone();
    invocation["contextDigest"] = context["contextDigest"].clone();
    invocation
}
fn dispatch(
    store: &mut DurableStore,
    rpc: &Rpc,
    authority: &mut Authority,
    invocation: &Value,
) -> StorageResult<StepRecord> {
    dispatch_calibration_intent(
        store,
        rpc,
        authority,
        &CalibrationDispatchRequest {
            approval_ref: "calibration-fixture",
            operation_id: &serde_json::from_value(invocation["operationId"].clone()).unwrap(),
            step_id: &serde_json::from_value(invocation["stepId"].clone()).unwrap(),
            invocation,
        },
    )
}
fn count(store: &DurableStore, table: &str) -> i64 {
    // Test-only closed table names; production queries never interpolate a locator.
    assert!(
        [
            "calibration_operation_claims",
            "calibration_step_claims",
            "invocations",
            "write_fences"
        ]
        .contains(&table)
    );
    store
        .connection
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn selection_is_not_confirmation_and_public_dispatch_cannot_borrow_it() {
    let (_root, mut store, rpc, mut authority, plan, context) = seed();
    let request = authority.expected.clone();
    let selection =
        register_calibration_selection(&mut store, &rpc, &mut authority, &request).unwrap();
    assert_eq!(selection.purpose(), CALIBRATION_PURPOSE);
    assert!(confirm(&mut store, &rpc, &mut authority, &selection).is_err());
    assert!(
        calibration_approval(&store, &rpc, &request.project_id, &request.approval_ref)
            .unwrap()
            .is_none()
    );
    reserve(&mut store, &plan, "calibration-op", "calibration-key");
    let original = invocation(
        &plan,
        &context,
        "calibration-op",
        0,
        "invocation-calibration-00",
    );
    assert!(
        store
            .dispatch_intent(
                &OperationId::new("calibration-op").unwrap(),
                &StepId::new("calibration-step-00").unwrap(),
                &original
            )
            .is_err()
    );
    assert_eq!(count(&store, "invocations"), 0);
    rpc.completed.set(true);
    let approved = confirm(&mut store, &rpc, &mut authority, &selection).unwrap();
    assert_eq!(approved.selection(), &selection);
    let mut changed = original.clone();
    changed["arguments"]["command"] = json!("function mmmm:unapproved");
    changed["argumentsDigest"] = json!(canonical_digest(&changed["arguments"]).unwrap());
    assert!(dispatch(&mut store, &rpc, &mut authority, &changed).is_err());
    assert_eq!(count(&store, "calibration_operation_claims"), 0);
    assert_eq!(count(&store, "invocations"), 0);
    let mut reissue = request.clone();
    reissue.approval_ref = "different-ref-same-plan".into();
    authority.expected = reissue.clone();
    assert!(register_calibration_selection(&mut store, &rpc, &mut authority, &reissue).is_err());
    assert_eq!(
        calibration_approval(&store, &rpc, &request.project_id, &request.approval_ref)
            .unwrap()
            .unwrap(),
        approved
    );
}

#[test]
fn ordinary_dispatch_on_an_existing_store_needs_no_calibration_schema_or_selection() {
    let (root, mut store, rpc, mut authority, _plan, _context) = seed();
    let ordinary = example("execution-plan.json");
    let context = example("execution-context.json");
    store.save_plan(&ordinary).unwrap();
    let table_exists = |store: &DurableStore| -> bool {
        store
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='calibration_selections')",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert!(!table_exists(&store));
    reserve(
        &mut store,
        &ordinary,
        "ordinary-before-selection",
        "ordinary-before",
    );
    let original = invocation(
        &ordinary,
        &context,
        "ordinary-before-selection",
        0,
        "invocation-ordinary-before",
    );
    store
        .dispatch_intent(
            &OperationId::new("ordinary-before-selection").unwrap(),
            &StepId::new("echo-step").unwrap(),
            &original,
        )
        .unwrap();
    assert!(!table_exists(&store));
    drop(store);
    let mut store = root.store();
    assert!(!table_exists(&store));
    let request = authority.expected.clone();
    register_calibration_selection(&mut store, &rpc, &mut authority, &request).unwrap();
    reserve(
        &mut store,
        &ordinary,
        "ordinary-after-selection",
        "ordinary-after",
    );
    let original = invocation(
        &ordinary,
        &context,
        "ordinary-after-selection",
        0,
        "invocation-ordinary-after",
    );
    store
        .dispatch_intent(
            &OperationId::new("ordinary-after-selection").unwrap(),
            &StepId::new("echo-step").unwrap(),
            &original,
        )
        .unwrap();
    assert_eq!(count(&store, "calibration_operation_claims"), 0);
}

#[test]
fn forty_seven_original_claims_survive_restart_and_never_change_operation() {
    let (root, mut store, rpc, mut authority, plan, context) = seed();
    let request = authority.expected.clone();
    let selection =
        register_calibration_selection(&mut store, &rpc, &mut authority, &request).unwrap();
    rpc.completed.set(true);
    let approval = confirm(&mut store, &rpc, &mut authority, &selection).unwrap();
    reserve(&mut store, &plan, "calibration-op", "calibration-key");
    let observation = store
        .put_blob(b"independent storage-only readback fixture")
        .unwrap();
    for index in 0..47 {
        let original = invocation(
            &plan,
            &context,
            "calibration-op",
            index,
            &format!("invocation-calibration-{index:02}"),
        );
        let step = dispatch(&mut store, &rpc, &mut authority, &original).unwrap();
        assert_eq!(step.dispatch, DispatchEvidence::IntentDurable);
        verify_calibration_intent_claim(
            &store,
            &approval,
            &OperationId::new("calibration-op").unwrap(),
            &step.step_id,
            &original,
            &|| rpc.check(),
        )
        .unwrap();
        assert!(dispatch(&mut store, &rpc, &mut authority, &original).is_err());
        store
            .record_observation(
                &OperationId::new("calibration-op").unwrap(),
                &step.step_id,
                StepObservation {
                    dispatch: DispatchEvidence::Observed,
                    effect: EffectEvidence::CompleteConfirmed,
                    further_effects_possible: false,
                    provider_receipt: Some(format!("fixture-receipt-{index}")),
                    observation_refs: vec![observation.clone()],
                    finished: true,
                },
            )
            .unwrap();
    }
    store
        .finish_operation(
            &OperationId::new("calibration-op").unwrap(),
            OperationState::Succeeded,
        )
        .unwrap();
    assert_eq!(count(&store, "calibration_operation_claims"), 1);
    assert_eq!(count(&store, "calibration_step_claims"), 47);
    drop(store);
    let mut store = root.store();
    assert!(
        matches!(reserve(&mut store, &plan, "ignored-new-operation", "calibration-key"), Reservation::Existing(record) if record.operation_id.as_str()=="calibration-op")
    );
    reserve(&mut store, &plan, "another-operation", "another-key");
    let another = invocation(
        &plan,
        &context,
        "another-operation",
        0,
        "invocation-another-calibration",
    );
    assert!(matches!(
        dispatch(&mut store, &rpc, &mut authority, &another),
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(count(&store, "calibration_step_claims"), 47);
    for index in 0..47 {
        let expected = invocation(
            &plan,
            &context,
            "calibration-op",
            index,
            &format!("invocation-calibration-{index:02}"),
        );
        let digest: String = store.connection.query_row("SELECT invocation_digest FROM calibration_step_claims WHERE approval_ref=?1 AND step_id=?2", params![request.approval_ref,format!("calibration-step-{index:02}")], |r| r.get(0)).unwrap();
        assert_eq!(
            digest,
            raw_digest(&mmmm_contracts::encode_json(&expected).unwrap()).as_str()
        );
        verify_calibration_intent_claim(
            &store,
            &approval,
            &OperationId::new("calibration-op").unwrap(),
            &StepId::new(format!("calibration-step-{index:02}")).unwrap(),
            &expected,
            &|| rpc.check(),
        )
        .unwrap();
    }
}

#[test]
fn original_claim_query_is_factual_and_rejects_unclaimed_or_rewritten_intent() {
    let (_root, mut store, rpc, mut authority, plan, context) = seed();
    let request = authority.expected.clone();
    let selection =
        register_calibration_selection(&mut store, &rpc, &mut authority, &request).unwrap();
    rpc.completed.set(true);
    let approval = confirm(&mut store, &rpc, &mut authority, &selection).unwrap();
    reserve(&mut store, &plan, "calibration-op", "calibration-key");
    let operation = OperationId::new("calibration-op").unwrap();
    let step = StepId::new("calibration-step-00").unwrap();
    let original = invocation(&plan, &context, operation.as_str(), 0, "invocation-query");
    assert!(matches!(
        verify_calibration_intent_claim(&store, &approval, &operation, &step, &original, &|| rpc
            .check()),
        Err(StorageError::NotFound(_))
    ));
    assert_eq!(count(&store, "calibration_step_claims"), 0);
    dispatch(&mut store, &rpc, &mut authority, &original).unwrap();
    verify_calibration_intent_claim(&store, &approval, &operation, &step, &original, &|| {
        rpc.check()
    })
    .unwrap();
    let (_other_root, other_store, other_rpc, _other_authority, _other_plan, _other_context) =
        seed();
    assert!(matches!(
        verify_calibration_intent_claim(
            &other_store,
            &approval,
            &operation,
            &step,
            &original,
            &|| other_rpc.check()
        ),
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(count(&other_store, "invocations"), 0);
    let mut rewritten = original.clone();
    rewritten["arguments"]["command"] = json!("function mmmm:storage_fixture/other");
    rewritten["argumentsDigest"] = json!(canonical_digest(&rewritten["arguments"]).unwrap());
    assert!(matches!(
        verify_calibration_intent_claim(&store, &approval, &operation, &step, &rewritten, &|| rpc
            .check()),
        Err(StorageError::Conflict(_))
    ));
    // A claim-row/index mismatch cannot borrow an otherwise valid durable
    // Invocation. This uses the existing SQLite fixture, not another ledger.
    store.connection.execute("UPDATE calibration_step_claims SET invocation_digest=?1 WHERE approval_ref=?2 AND step_id=?3",
        params!["a".repeat(64),selection.approval_ref(),step.as_str()]).unwrap();
    assert!(matches!(
        verify_calibration_intent_claim(&store, &approval, &operation, &step, &original, &|| rpc
            .check()),
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(count(&store, "calibration_step_claims"), 1);
    assert_eq!(count(&store, "invocations"), 1);
    // Preserve a primary wrong-original failure together with the original
    // checkpoint's concurrent cancellation; neither becomes a safe retry.
    let mut wrong = original.clone();
    wrong["operationId"] = json!("another-operation");
    let calls = Cell::new(0);
    let failure =
        verify_calibration_intent_claim(&store, &approval, &operation, &step, &wrong, &|| {
            calls.set(calls.get() + 1);
            if calls.get() > 1 {
                Err(StorageError::Conflict("Fixture original request cancelled"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert!(matches!(
        failure.primary_failure(),
        StorageError::Conflict("Calibration original claim operation identity")
    ));
    assert!(matches!(
        failure.checkpoint_failure(),
        Some(StorageError::Conflict("Fixture original request cancelled"))
    ));
}

#[test]
fn failed_intent_transaction_never_leaves_partial_claim_invocation_or_fence() {
    let (_root, mut store, rpc, mut authority, plan, context) = seed();
    let request = authority.expected.clone();
    let selection =
        register_calibration_selection(&mut store, &rpc, &mut authority, &request).unwrap();
    rpc.completed.set(true);
    let approved = confirm(&mut store, &rpc, &mut authority, &selection).unwrap();
    reserve(&mut store, &plan, "calibration-op", "calibration-key");
    store.connection.execute_batch("CREATE TEMP TRIGGER fail_calibration_intent BEFORE INSERT ON events WHEN NEW.kind='dispatch_intent' BEGIN SELECT RAISE(ABORT,'fixture intent publication failure'); END;").unwrap();
    let original = invocation(
        &plan,
        &context,
        "calibration-op",
        0,
        "invocation-calibration-00",
    );
    let failure = dispatch(&mut store, &rpc, &mut authority, &original).unwrap_err();
    assert!(matches!(failure.primary_failure(), StorageError::Sqlite(_)));
    for table in [
        "calibration_operation_claims",
        "calibration_step_claims",
        "invocations",
        "write_fences",
    ] {
        assert_eq!(count(&store, table), 0);
    }
    assert_eq!(
        store
            .operation(&OperationId::new("calibration-op").unwrap())
            .unwrap()
            .steps[0]
            .dispatch,
        DispatchEvidence::NotSent
    );
    assert_eq!(
        calibration_approval(&store, &rpc, &request.project_id, &request.approval_ref)
            .unwrap()
            .unwrap(),
        approved
    );
}

#[test]
fn source_and_original_checkpoint_failures_both_survive_without_a_claim() {
    let (_root, mut store, rpc, mut authority, plan, context) = seed();
    let request = authority.expected.clone();
    let selection =
        register_calibration_selection(&mut store, &rpc, &mut authority, &request).unwrap();
    rpc.completed.set(true);
    confirm(&mut store, &rpc, &mut authority, &selection).unwrap();
    reserve(&mut store, &plan, "calibration-op", "calibration-key");
    authority.fail_dispatch_and_cancel = true;
    let original = invocation(
        &plan,
        &context,
        "calibration-op",
        0,
        "invocation-calibration-00",
    );
    let failure = dispatch(&mut store, &rpc, &mut authority, &original).unwrap_err();
    assert!(matches!(
        failure.primary_failure(),
        StorageError::Conflict("Fixture runtime source revoked")
    ));
    assert!(matches!(
        failure.checkpoint_failure(),
        Some(StorageError::InvalidTransition(_))
    ));
    assert!(std::error::Error::source(&failure).is_some());
    assert_eq!(count(&store, "calibration_operation_claims"), 0);
    assert_eq!(count(&store, "invocations"), 0);
}

#[test]
fn provisional_selection_cancellation_and_stale_generation_never_publish_authority() {
    let (_root, mut store, rpc, mut authority, plan, context) = seed();
    let request = authority.expected.clone();
    authority.fail_published_selection = true;
    let failure =
        register_calibration_selection(&mut store, &rpc, &mut authority, &request).unwrap_err();
    assert!(matches!(
        failure.primary_failure(),
        StorageError::Conflict("Fixture source changed after provisional selection")
    ));
    assert!(failure.checkpoint_failure().is_some());
    rpc.permit.0.cancelled.set(false);
    authority.fail_published_selection = false;
    assert!(
        calibration_selection(
            &store,
            &rpc,
            &mut authority,
            &request.project_id,
            &request.approval_ref
        )
        .unwrap()
        .is_none()
    );
    let selection =
        register_calibration_selection(&mut store, &rpc, &mut authority, &request).unwrap();
    rpc.completed.set(true);
    confirm(&mut store, &rpc, &mut authority, &selection).unwrap();
    rpc.generation.set(2);
    assert!(
        calibration_approval(&store, &rpc, &request.project_id, &request.approval_ref).is_err()
    );
    assert_eq!(count(&store, "calibration_operation_claims"), 0);
    rpc.generation.set(1);
    rpc.cancel_on_claim.set(true);
    reserve(&mut store, &plan, "calibration-op", "calibration-key");
    let original = invocation(
        &plan,
        &context,
        "calibration-op",
        0,
        "invocation-calibration-00",
    );
    let failure = dispatch(&mut store, &rpc, &mut authority, &original).unwrap_err();
    assert!(matches!(
        failure.primary_failure(),
        StorageError::InvalidTransition(_)
    ));
    for table in [
        "calibration_operation_claims",
        "calibration_step_claims",
        "invocations",
        "write_fences",
    ] {
        assert_eq!(count(&store, table), 0);
    }
}

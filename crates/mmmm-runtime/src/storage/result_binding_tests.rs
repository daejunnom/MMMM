//! Stateful temporary-disk fixtures are required because the static echo
//! example has no DAG result binding, restart or false-summary association.
//! Passing these checks does not prove a real provider or game has run.

use super::*;
use crate::storage::{
    DispatchEvidence, EffectEvidence, ReserveOperation, StepObservation, StoreConfig,
};
use mmmm_contracts::{ContextId, PlanId, PrincipalId, ProjectId, projected_digest};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = parent.join(format!(
            "mmmm-result-binding-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(path.is_absolute());
        assert!(!path.starts_with(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(path.join("test-owner.txt"), b"mmmm-result-binding-test\n").unwrap();
        Self(path)
    }
    fn open(&self) -> DurableStore {
        DurableStore::open(StoreConfig::new(self.0.clone())).unwrap()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        if fs::read(self.0.join("test-owner.txt")).ok().as_deref()
            == Some(b"mmmm-result-binding-test\n")
            && super::super::cas::verify_plain_path(&self.0).is_ok()
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
fn blob(store: &DurableStore, value: &Value) -> BlobRef {
    store.put_blob(&encode_json(value).unwrap()).unwrap()
}
struct Fixture {
    consumer: Value,
    witness: ResultResolutionWitness,
    codec: RegisteredResultCodec,
    operation: OperationId,
    consumer_step: StepId,
}
fn fixture(store: &mut DurableStore, finished: bool) -> Fixture {
    let action = example("provider-supported.json")["actions"][0].clone();
    let action_digest = digest(&action).unwrap();
    let binding = BindingId::new("binding-fixture-01").unwrap();
    let action_blob = store.register_result_action(&binding, &action).unwrap();
    let codec = RegisteredResultCodec {
        codec_id: ObjectId::new("codec-identity-test").unwrap(),
        implementation: ResultCodecImplementation::JsonIdentityV1,
        input_schema: json!({"type":"string"}),
        output_schema: json!({"type":"string"}),
        allowed_slots: vec![ResultArgumentSlot {
            action_digest: action_digest.clone(),
            argument_pointer: "/text".into(),
        }],
    };
    let codec_blob = store.register_result_codec(&codec).unwrap();
    let mut plan = example("execution-plan.json");
    plan["planId"] = json!("result-plan");
    plan["steps"][0]["actionDigest"] = json!(action_digest);
    let step_binding = ResultStepBinding {
        argument_pointer: "/text".into(),
        source_step_id: StepId::new("echo-step").unwrap(),
        output_pointer: "/text".into(),
        expected_schema_digest: digest(&action["outputSchema"]).unwrap(),
        codec_id: codec.codec_id.clone(),
        codec_digest: codec.metadata_digest().unwrap(),
    };
    let mut consumer_step = plan["steps"][0].clone();
    consumer_step["stepId"] = json!("consumer-step");
    consumer_step["dependsOn"] = json!(["echo-step"]);
    consumer_step["arguments"] = json!({"text":"frozen-template"});
    consumer_step["resultBindings"] = json!([step_binding]);
    plan["steps"].as_array_mut().unwrap().push(consumer_step);
    plan["planHash"] = json!(projected_digest("ExecutionPlan", &plan).unwrap());
    store.save_plan(&plan).unwrap();
    let operation = OperationId::new("result-operation").unwrap();
    store
        .reserve_operation(ReserveOperation {
            operation_id: operation.clone(),
            principal: PrincipalId::new("principal-fixture").unwrap(),
            project_id: ProjectId::new("project-fixture").unwrap(),
            idempotency_key: "result-key".into(),
            plan_id: PlanId::new("result-plan").unwrap(),
            plan_hash: serde_json::from_value(plan["planHash"].clone()).unwrap(),
            context_id: ContextId::new("context-fixture-01").unwrap(),
        })
        .unwrap();
    let mut source = example("invocation.json");
    source["operationId"] = json!(operation);
    source["invocationId"] = json!("source-invocation");
    source["actionDigest"] = json!(action_digest);
    let source_record = store
        .dispatch_intent(&operation, &step_binding.source_step_id, &source)
        .unwrap();
    let result = json!({"contractVersion":"0.2.0","status":"complete","data":{"text":"resolved-data"},"effects":"none","diagnostics":[],"artifacts":[]});
    let result_blob = blob(store, &result);
    let summary = json!({"kind":"provider_result","stepId":"echo-step","invocationId":"source-invocation","actionDigest":action_digest,"outputSchemaDigest":step_binding.expected_schema_digest,"outputValidated":true,
        "value":{"status":"complete"},"resultBlob":result_blob,"sourceRefs":[result_blob]});
    let summary_blob = blob(store, &summary);
    store
        .append_operation_summary(
            &operation,
            &summary_blob,
            std::slice::from_ref(&result_blob),
        )
        .unwrap();
    store
        .record_observation(
            &operation,
            &step_binding.source_step_id,
            StepObservation {
                dispatch: DispatchEvidence::Acknowledged,
                effect: EffectEvidence::NoneConfirmed,
                further_effects_possible: false,
                provider_receipt: None,
                observation_refs: vec![summary_blob.clone()],
                finished,
            },
        )
        .unwrap();
    let mut consumer = source.clone();
    consumer["stepId"] = json!("consumer-step");
    consumer["invocationId"] = json!("consumer-invocation");
    consumer["arguments"] = json!({"text":"resolved-data"});
    consumer["argumentsDigest"] = json!(digest(&consumer["arguments"]).unwrap());
    let arguments_blob = blob(store, &consumer["arguments"]);
    let witness = ResultResolutionWitness {
        kind: "result_resolution_witness".into(),
        version: 1,
        operation_id: operation.clone(),
        plan_hash: serde_json::from_value(plan["planHash"].clone()).unwrap(),
        step_id: StepId::new("consumer-step").unwrap(),
        template_arguments_digest: digest(&plan["steps"][1]["arguments"]).unwrap(),
        arguments_blob,
        arguments_digest: digest(&consumer["arguments"]).unwrap(),
        context_digest: serde_json::from_value(consumer["contextDigest"].clone()).unwrap(),
        action_digest: action_digest.clone(),
        implementation_digest: serde_json::from_value(consumer["implementationDigest"].clone())
            .unwrap(),
        resolved_footprint: ResultFootprint {
            resources_read: vec![],
            resources_written: vec![],
        },
        bindings: vec![ResultBindingWitness {
            binding: step_binding,
            source_invocation_id: InvocationId::new("source-invocation").unwrap(),
            source_invocation_digest: source_record.invocation_digest.unwrap(),
            source_result: result_blob,
            source_result_summary: summary_blob,
            source_action: action_blob,
            codec: codec_blob,
            selected_value_digest: digest(&json!("resolved-data")).unwrap(),
            resolved_value_digest: digest(&json!("resolved-data")).unwrap(),
        }],
    };
    Fixture {
        consumer,
        witness,
        codec,
        operation,
        consumer_step: StepId::new("consumer-step").unwrap(),
    }
}
fn witness_blob(store: &DurableStore, witness: &ResultResolutionWitness) -> BlobRef {
    blob(store, &serde_json::to_value(witness).unwrap())
}

#[test]
fn registered_identity_resolves_exact_slot_and_pins_same_intent_across_restart() {
    let root = Root::new();
    let mut store = root.open();
    let fixture = fixture(&mut store, true);
    let witness = witness_blob(&store, &fixture.witness);
    assert!(
        store
            .dispatch_intent(
                &fixture.operation,
                &fixture.consumer_step,
                &fixture.consumer
            )
            .is_err()
    );
    let result = store
        .dispatch_resolved_intent(
            &fixture.operation,
            &fixture.consumer_step,
            &fixture.consumer,
            &witness,
        )
        .unwrap();
    assert_eq!(result.dispatch, DispatchEvidence::IntentDurable);
    assert_eq!(
        store
            .stored_invocation(&fixture.operation, &fixture.consumer_step)
            .unwrap(),
        fixture.consumer
    );
    assert_eq!(
        serde_json::to_value(
            store
                .stored_resolution_witness(&fixture.operation, &fixture.consumer_step)
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(&fixture.witness).unwrap(),
    );
    assert!(
        store
            .dispatch_resolved_intent(
                &fixture.operation,
                &fixture.consumer_step,
                &fixture.consumer,
                &witness
            )
            .is_err()
    );
    let retained: i64 = store
        .connection
        .query_row(
            "SELECT count(*) FROM blob_refs WHERE owner_kind='result_resolution' AND owner_id=?1",
            ["consumer-invocation"],
            |r| r.get(0),
        )
        .unwrap();
    assert!(retained >= 6);
    store.collect_orphan_blobs(100).unwrap();
    assert!(store.read_blob(&witness).is_ok());
    drop(store);
    let mut store = root.open();
    assert_eq!(
        store
            .stored_invocation(&fixture.operation, &fixture.consumer_step)
            .unwrap(),
        fixture.consumer
    );
    assert_eq!(
        store
            .result_codec(
                &fixture.codec.codec_id,
                &fixture.codec.metadata_digest().unwrap()
            )
            .unwrap()
            .0
            .metadata()
            .unwrap(),
        fixture.codec.metadata().unwrap()
    );
    assert!(store.read_blob(&witness).is_ok());
    assert!(
        store
            .dispatch_resolved_intent(
                &fixture.operation,
                &fixture.consumer_step,
                &fixture.consumer,
                &witness
            )
            .is_err()
    );
}

#[test]
fn unfinished_or_failed_sources_never_dispatch_or_rewrite_known_source_truth() {
    let root = Root::new();
    let mut store = root.open();
    let fixture = fixture(&mut store, false);
    let witness = witness_blob(&store, &fixture.witness);
    let before = store.operation(&fixture.operation).unwrap();
    assert!(
        store
            .dispatch_resolved_intent(
                &fixture.operation,
                &fixture.consumer_step,
                &fixture.consumer,
                &witness
            )
            .is_err()
    );
    assert_eq!(store.operation(&fixture.operation).unwrap(), before);
    drop(store);
    let root = Root::new();
    let mut store = root.open();
    let fixture = self::fixture(&mut store, true);
    let result = blob(
        &store,
        &json!({"contractVersion":"0.2.0","status":"failed","data":{},"effects":"none","diagnostics":[],"artifacts":[]}),
    );
    let summary = blob(
        &store,
        &json!({"kind":"provider_result","stepId":"echo-step","invocationId":"source-invocation","value":{"status":"failed"},"sourceRefs":[result]}),
    );
    store
        .append_operation_summary(&fixture.operation, &summary, std::slice::from_ref(&result))
        .unwrap();
    let before = store.operation(&fixture.operation).unwrap();
    let witness = witness_blob(&store, &fixture.witness);
    assert!(
        store
            .dispatch_resolved_intent(
                &fixture.operation,
                &fixture.consumer_step,
                &fixture.consumer,
                &witness
            )
            .is_err()
    );
    assert_eq!(store.operation(&fixture.operation).unwrap(), before);
}

#[test]
fn legacy_failed_observation_or_raw_marker_blocks_a_later_complete_resolution() {
    for raw_marker in [false, true] {
        for summary_association in [false, true] {
            for labels in ["original", "wrong-step", "stale-invocation"] {
                let root = Root::new();
                let mut store = root.open();
                let mut fixture = fixture(&mut store, false);
                let failed = json!({"contractVersion":"0.2.0","status":"failed","data":{},"effects":"none","diagnostics":[],"artifacts":[]});
                let body = blob(&store, &failed);
                let mut legacy = if raw_marker {
                    store
                        .append_operation_evidence(&fixture.operation, &body)
                        .unwrap();
                    json!({"kind":"unvalidated_provider_result","stepId":"echo-step","invocationId":"source-invocation","resultBlob":body})
                } else {
                    json!({"kind":"provider_result","stepId":"echo-step","invocationId":"source-invocation","value":failed,"resultBlob":body})
                };
                match labels {
                    "wrong-step" => legacy["stepId"] = json!("consumer-step"),
                    "stale-invocation" => legacy["invocationId"] = json!("old-source-invocation"),
                    _ => {}
                }
                let legacy = blob(&store, &legacy);
                if summary_association {
                    store
                        .append_operation_summary(
                            &fixture.operation,
                            &legacy,
                            std::slice::from_ref(&body),
                        )
                        .unwrap();
                } else {
                    store
                        .record_observation(
                            &fixture.operation,
                            &StepId::new("echo-step").unwrap(),
                            StepObservation {
                                dispatch: DispatchEvidence::Acknowledged,
                                effect: EffectEvidence::NoneConfirmed,
                                further_effects_possible: false,
                                provider_receipt: None,
                                observation_refs: vec![legacy],
                                finished: false,
                            },
                        )
                        .unwrap();
                }
                // Commit a distinct complete marker after the failed evidence and use
                // that exact association in the successor witness. Neither its order
                // nor mismatched legacy labels may erase the original failure.
                let source_result = fixture.witness.bindings[0].source_result.clone();
                let original_summary = fixture.witness.bindings[0].source_result_summary.clone();
                let mut complete =
                    read_json(&store.cas, &original_summary, MAX_WITNESS_BYTES).unwrap();
                complete["value"]["effects"] = json!("none");
                let later_complete = blob(&store, &complete);
                assert_ne!(later_complete.digest, original_summary.digest);
                store
                    .append_operation_summary(
                        &fixture.operation,
                        &later_complete,
                        std::slice::from_ref(&source_result),
                    )
                    .unwrap();
                store
                    .record_observation(
                        &fixture.operation,
                        &StepId::new("echo-step").unwrap(),
                        StepObservation {
                            dispatch: DispatchEvidence::Acknowledged,
                            effect: EffectEvidence::NoneConfirmed,
                            further_effects_possible: false,
                            provider_receipt: None,
                            observation_refs: vec![later_complete.clone()],
                            finished: true,
                        },
                    )
                    .unwrap();
                fixture.witness.bindings[0].source_result_summary = later_complete;
                let witness = witness_blob(&store, &fixture.witness);
                let before = store.operation(&fixture.operation).unwrap();
                assert!(
                    store
                        .dispatch_resolved_intent(
                            &fixture.operation,
                            &fixture.consumer_step,
                            &fixture.consumer,
                            &witness
                        )
                        .is_err()
                );
                assert_eq!(store.operation(&fixture.operation).unwrap(), before);
                let intents: i64 = store
                    .connection
                    .query_row(
                        "SELECT count(*) FROM invocations WHERE operation_id=?1",
                        [fixture.operation.as_str()],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(intents, 1);
            }
        }
    }
}

#[test]
fn forged_witness_pins_schema_source_and_footprint_roll_back_consumer_intent() {
    let root = Root::new();
    let mut store = root.open();
    let fixture = fixture(&mut store, true);
    let original = serde_json::to_value(&fixture.witness).unwrap();
    let before = store.operation(&fixture.operation).unwrap();
    for changed in [
        ("/planHash", json!("b".repeat(64))),
        ("/templateArgumentsDigest", json!("b".repeat(64))),
        ("/bindings/0/sourceInvocationDigest", json!("b".repeat(64))),
        (
            "/bindings/0/binding/expectedSchemaDigest",
            json!("b".repeat(64)),
        ),
        ("/bindings/0/selectedValueDigest", json!("b".repeat(64))),
        ("/resolvedFootprint/resourcesWritten", json!(["new-target"])),
    ] {
        let mut value = original.clone();
        *value.pointer_mut(changed.0).unwrap() = changed.1;
        let witness = blob(&store, &value);
        assert!(
            store
                .dispatch_resolved_intent(
                    &fixture.operation,
                    &fixture.consumer_step,
                    &fixture.consumer,
                    &witness
                )
                .is_err(),
            "{}",
            changed.0
        );
        assert_eq!(store.operation(&fixture.operation).unwrap(), before);
    }
    let mut invocation = fixture.consumer.clone();
    invocation["arguments"]["extra"] = json!("not-planned");
    invocation["argumentsDigest"] = json!(digest(&invocation["arguments"]).unwrap());
    let mut witness = fixture.witness.clone();
    witness.arguments_digest = digest(&invocation["arguments"]).unwrap();
    witness.arguments_blob = blob(&store, &invocation["arguments"]);
    let witness = witness_blob(&store, &witness);
    assert!(
        store
            .dispatch_resolved_intent(
                &fixture.operation,
                &fixture.consumer_step,
                &invocation,
                &witness
            )
            .is_err()
    );
    let intents: i64 = store
        .connection
        .query_row(
            "SELECT count(*) FROM invocations WHERE operation_id=?1",
            [fixture.operation.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(intents, 1);
}

#[test]
fn summary_or_result_bytes_alone_cannot_replace_actual_source_association() {
    let root = Root::new();
    let mut store = root.open();
    let fixture = fixture(&mut store, true);
    let result = blob(
        &store,
        &json!({"contractVersion":"0.2.0","status":"complete","data":{"text":"other"},"effects":"none","diagnostics":[],"artifacts":[]}),
    );
    store
        .append_operation_evidence(&fixture.operation, &result)
        .unwrap();
    let mut witness = fixture.witness.clone();
    witness.bindings[0].source_result = result;
    let witness = witness_blob(&store, &witness);
    assert!(
        store
            .dispatch_resolved_intent(
                &fixture.operation,
                &fixture.consumer_step,
                &fixture.consumer,
                &witness
            )
            .is_err()
    );
    store.connection.execute("DELETE FROM blob_refs WHERE owner_kind='application_evidence' AND owner_id=?1 AND digest=?2",params![fixture.operation.as_str(),fixture.witness.bindings[0].source_result.digest.as_str()]).unwrap();
    let witness = witness_blob(&store, &fixture.witness);
    assert!(
        store
            .dispatch_resolved_intent(
                &fixture.operation,
                &fixture.consumer_step,
                &fixture.consumer,
                &witness
            )
            .is_err()
    );
}

#[test]
fn closed_registry_rejects_codec_rebinding_unreviewed_slots_and_external_schemas() {
    let root = Root::new();
    let mut store = root.open();
    let fixture = fixture(&mut store, true);
    let mut codec = fixture.codec.clone();
    codec.input_schema = json!({"type":"integer"});
    assert!(store.register_result_codec(&codec).is_err());
    for pointer in [
        "/endpoint",
        "/nested/executorHandle",
        "/position",
        "/costBudget",
        "/preparedChange",
        "/text/child",
    ] {
        let mut codec = fixture.codec.clone();
        codec.codec_id = ObjectId::new("other-codec").unwrap();
        codec.allowed_slots[0].argument_pointer = pointer.into();
        if pointer == "/text/child" {
            codec
                .allowed_slots
                .push(fixture.codec.allowed_slots[0].clone());
        }
        assert!(store.register_result_codec(&codec).is_err());
    }
    let mut codec = fixture.codec.clone();
    codec.codec_id = ObjectId::new("external-schema").unwrap();
    codec.input_schema = json!({"$ref":"file:///unavailable-schema"});
    assert!(store.register_result_codec(&codec).is_err());
    let mut witness = fixture.witness.clone();
    witness.bindings[0].codec = blob(
        &store,
        &json!({"codecId":"codec-identity-test","implementation":"arbitrary-command"}),
    );
    let witness = witness_blob(&store, &witness);
    assert!(
        store
            .dispatch_resolved_intent(
                &fixture.operation,
                &fixture.consumer_step,
                &fixture.consumer,
                &witness
            )
            .is_err()
    );
}

#[test]
fn pointers_use_token_boundaries_canonical_array_indexes_and_existing_slots() {
    assert_eq!(
        result_pointer_tokens("/a~1b/~0x").unwrap(),
        vec!["a/b", "~x"]
    );
    for pointer in ["", "/", "text", "/~2", "/-", "/text//child"] {
        assert!(result_pointer_tokens(pointer).is_err());
    }
    let value = json!({"a":[10,20],"a/b":{"~x":true}});
    assert_eq!(
        selected(&value, &result_pointer_tokens("/a/1").unwrap()).unwrap(),
        &json!(20)
    );
    assert!(selected(&value, &result_pointer_tokens("/a/01").unwrap()).is_err());
    assert!(selected(&value, &result_pointer_tokens("/a/2").unwrap()).is_err());
    assert!(check_data_subtree(&json!({"payload":{"targetId":"expanded"}})).is_err());
    let mut value = value;
    assert!(
        replace(
            &mut value,
            &result_pointer_tokens("/new").unwrap(),
            json!(0)
        )
        .is_err()
    );
}

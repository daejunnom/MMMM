//! 원본 예제를 재사용한다. 이 집중 검사는 새 geometry ID의 snapshot/context
//! 결합과 private 오류 보존을 다룬다. 실제 Store/request/pairing 경로는 기존
//! native_catalog_tests의 TCP·SQLite fixture를 확장하여 중복 fixture를 피한다.
//! 아래 예제 값은 게임 관측, source 권한 또는 VerifiedTarget 발급 자료가 아니다.

use super::*;
use mmmm_contracts::parse_json;
use mmmm_reference::SnapshotIdentity;
use std::collections::BTreeMap;

fn example(bytes: &[u8]) -> Value {
    parse_json(bytes).unwrap()
}
fn inputs() -> (ProjectId, Value, SnapshotPin, Value) {
    let context = example(include_bytes!("../../../examples/execution-context.json"));
    let snapshot = example(include_bytes!("../../../examples/data-snapshot.json"));
    let pin = SnapshotPin {
        revision: canonical_digest(&snapshot).unwrap(),
        snapshot,
        identity: SnapshotIdentity {
            registry_generation: "fixture-generation".into(),
            mod_fingerprints: BTreeMap::new(),
            query_context_digest: raw_digest(b"fixture-query"),
            observation_window: None,
        },
    };
    (
        ProjectId::new("project-fixture").unwrap(),
        context,
        pin,
        example(include_bytes!("../../../examples/shape-query.json")),
    )
}

#[test]
fn geometry_identity_includes_original_snapshot_context_and_query() {
    let (project, mut context, mut snapshot, mut query) = inputs();
    let bytes = b"bounded geometry identity fixture";
    let first = geometry_resource(&project, &context, &snapshot, &query, bytes).unwrap();
    assert_eq!(first.sha256, raw_digest(bytes));
    assert!(super::super::same_resource(
        &first,
        &geometry_resource(&project, &context, &snapshot, &query, bytes).unwrap()
    ));
    context["contextDigest"] = json!(raw_digest(b"other-context"));
    let other_context = geometry_resource(&project, &context, &snapshot, &query, bytes).unwrap();
    assert_ne!(first.resource_id, other_context.resource_id);
    snapshot.revision = raw_digest(b"other-original-snapshot");
    let other_snapshot = geometry_resource(&project, &context, &snapshot, &query, bytes).unwrap();
    assert_ne!(other_context.resource_id, other_snapshot.resource_id);
    query["shapeKind"] = json!("outline");
    assert_ne!(
        other_snapshot.resource_id,
        geometry_resource(&project, &context, &snapshot, &query, bytes)
            .unwrap()
            .resource_id
    );
}

#[test]
fn geometry_resource_rejects_empty_and_excessive_bytes() {
    let (project, context, snapshot, query) = inputs();
    assert_eq!(
        geometry_resource(&project, &context, &snapshot, &query, &[])
            .unwrap_err()
            .code,
        "INPUT_LIMIT"
    );
    let bytes = vec![0; MAX_GEOMETRY_BYTES + 1];
    assert_eq!(
        geometry_resource(&project, &context, &snapshot, &query, &bytes)
            .unwrap_err()
            .code,
        "INPUT_LIMIT"
    );
}

#[test]
fn later_checkpoint_failure_preserves_the_original_failure_and_both_causes() {
    let error = finish::<()>(
        Err(AppError::new("ORIGINAL_SHAPE_FAILURE", "original")),
        Err(AppError::new("SOURCE_REVOKED", "current")),
    )
    .unwrap_err();
    assert_eq!(error.code, "ORIGINAL_SHAPE_FAILURE");
    let cause = error
        .source()
        .unwrap()
        .downcast_ref::<ShapeCheckpointFailure>()
        .unwrap();
    assert_eq!(cause.primary.code, "ORIGINAL_SHAPE_FAILURE");
    assert_eq!(cause.checkpoint.code, "SOURCE_REVOKED");
    assert_eq!(
        cause.source().unwrap().to_string(),
        "ORIGINAL_SHAPE_FAILURE: original"
    );
}

#[test]
fn library_error_mapping_preserves_fn23_context_side_and_deadline() {
    for (error, code) in [
        (ShapeError::StaleContext, "STALE_CONTEXT"),
        (ShapeError::SideMismatch, "SIDE_MISMATCH"),
        (ShapeError::DeadlineExceeded, "DEADLINE_EXCEEDED"),
        (ShapeError::Cancelled, "CANCELLED"),
    ] {
        let error = shape_app(error);
        assert_eq!(error.code, code);
        assert!(error.source().is_some());
    }
}

#[test]
fn a_later_port_failure_cannot_erase_the_first_received_failure() {
    let failure = Rc::new(RefCell::new(None));
    record_failure::<()>(Err(AppError::new("FIRST_HOST_ERROR", "first")), &failure).unwrap_err();
    record_failure::<()>(Err(AppError::new("LATER_CURRENT_ERROR", "later")), &failure).unwrap_err();
    assert_eq!(failure.borrow().as_ref().unwrap().code, "FIRST_HOST_ERROR");
}

#[test]
fn raw_host_error_stays_in_the_private_cause_without_public_body_printing() {
    let response = json!({"status":"error","error":{"code":"FIXTURE_HOST_REJECTED",
        "message":"fixture original message","retry":"never"}});
    let cause = ShapeHostFailure {
        response: response.clone(),
    };
    assert!(!cause.to_string().contains("fixture original message"));
    let public = service_error(AppError::caused_by("HOST_REQUEST_FAILED", "public", cause));
    let original = public
        .source()
        .unwrap()
        .downcast_ref::<AppError>()
        .unwrap()
        .source()
        .unwrap()
        .downcast_ref::<ShapeHostFailure>()
        .unwrap();
    assert_eq!(original.response, response);
}

#[test]
fn host_rejection_is_preserved_when_the_after_io_checkpoint_also_rejects() {
    let response = json!({"status":"error","error":{"code":"UNSUPPORTED","message":"original"}});
    let error = finish(host_payload(response.clone()), Err(denied())).unwrap_err();
    assert_eq!(error.code, "UNSUPPORTED");
    let pair = error
        .source()
        .unwrap()
        .downcast_ref::<ShapeCheckpointFailure>()
        .unwrap();
    let host = pair
        .primary
        .source()
        .unwrap()
        .downcast_ref::<ShapeHostFailure>()
        .unwrap();
    assert_eq!(host.response, response);
    assert_eq!(pair.checkpoint.code, "PERMISSION_REQUIRED");
}

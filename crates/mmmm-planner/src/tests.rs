//! Pure source/plan invariants. Fixtures never become host/runtime acceptance.
use crate::preparation::{document, empty_change, update_project};
use crate::*;
use mmmm_contracts::{parse_json, projected_digest};
use serde_json::json;

#[test]
fn authored_clip_change_promotes_one_pin_and_preserves_original_project() {
    let original = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
    let catalog = ProjectCatalog::from_project(&original).unwrap();
    let before = parse_json(include_bytes!("../../../examples/animation-clip.json")).unwrap();
    let after=mmmm_domain::clip_retime(&json!({"clip":before,"duration":{"numerator":"4","denominator":"1"},"eventPolicy":"scale_with_clip"})).unwrap();
    let mut change = empty_change(&catalog, NativeKind::ClipRetime);
    change.document_changes.push(
        document(
            OwnedKind::Clip,
            Some(
                catalog
                    .owned_pin(OwnedKind::Clip, "clip-door")
                    .unwrap()
                    .revision
                    .clone(),
            ),
            after.clone(),
        )
        .unwrap(),
    );
    update_project(&mut change).unwrap();
    let changed = ProjectCatalog::from_project(&change.project_after).unwrap();
    assert_eq!(
        changed
            .owned_pin(OwnedKind::Clip, "clip-door")
            .unwrap()
            .revision
            .as_str(),
        after["revision"].as_str().unwrap()
    );
    assert_eq!(catalog.project(), &original);
    assert_ne!(changed.revision(), catalog.revision());
    assert_eq!(changed.used_instance_ids(), catalog.used_instance_ids());
    let payload = change.to_arguments().unwrap();
    let decoded = PreparedNativeChange::from_payload(&payload).unwrap();
    assert_eq!(decoded.project_after, change.project_after);
    let mut injected = payload;
    injected["change"]["endpoint"] = json!("unregistered-target");
    assert_eq!(
        PreparedNativeChange::from_payload(&injected)
            .unwrap_err()
            .code,
        "INVALID_INPUT"
    );
}

#[test]
fn prepared_document_pin_cannot_lie_about_after_id_or_revision() {
    let original = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
    let catalog = ProjectCatalog::from_project(&original).unwrap();
    let clip = parse_json(include_bytes!("../../../examples/animation-clip.json")).unwrap();
    let mut change = empty_change(&catalog, NativeKind::ClipRetime);
    let mut changed = document(
        OwnedKind::Clip,
        Some(
            catalog
                .owned_pin(OwnedKind::Clip, "clip-door")
                .unwrap()
                .revision
                .clone(),
        ),
        clip,
    )
    .unwrap();
    changed.object_id = "other-clip".into();
    change.document_changes.push(changed);
    assert_eq!(change.to_arguments().unwrap_err().code, "REVISION_CONFLICT");
    change.document_changes[0].object_id = "clip-door".into();
    change.document_changes[0].after["duration"] = json!({"numerator":"8","denominator":"1"});
    assert_eq!(change.to_arguments().unwrap_err().code, "REVISION_CONFLICT");
}

#[test]
fn content_revision_is_recomputed_after_authoring_index_promotion() {
    let original = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
    let catalog = ProjectCatalog::from_project(&original).unwrap();
    let mut instance = parse_json(include_bytes!("../../../examples/instance.json")).unwrap();
    instance["instanceId"] = json!("instance-new");
    instance["revision"] = json!(projected_digest("Instance", &instance).unwrap());
    let mut change = empty_change(&catalog, NativeKind::Clone);
    change
        .document_changes
        .push(document(OwnedKind::Instance, None, instance).unwrap());
    update_project(&mut change).unwrap();
    assert_eq!(
        change.project_after["revision"],
        json!(projected_digest("Project", &change.project_after).unwrap())
    );
    assert_eq!(
        change.project_after["instanceIds"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(original["instanceIds"].as_array().unwrap().len(), 1);
}

#[test]
fn default_plan_budget_fits_observed_host_admission_without_deadline_rewrite() {
    let options = PlannerOptions::default();
    options.validate().unwrap();
    assert_eq!(options.time_budget_ms, 30_000);
    let mut invalid = options;
    invalid.time_budget_ms = 0;
    assert_eq!(invalid.validate().unwrap_err().code, "BUDGET_EXCEEDED");
}

#[test]
fn typed_and_cas_codecs_preserve_large_finite_float_wire_spelling() {
    let mut prefab = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
    prefab["nodes"][0]["transform"]["translation"][0] = json!(9_007_199_254_740_992.0f64);
    prefab["revision"] = json!(projected_digest("Prefab", &prefab).unwrap());
    let typed: mmmm_domain::Prefab = decode("Prefab", &prefab).unwrap();
    let encoded = mmmm_contracts::encode_json(&wire("Prefab", &typed).unwrap()).unwrap();
    parse_json(&encoded).unwrap();

    let project = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    let mut clip = parse_json(include_bytes!("../../../examples/animation-clip.json")).unwrap();
    clip["tracks"][0]["keys"][0]["transform"]["translation"][0] = json!(9_007_199_254_740_992.0f64);
    clip["revision"] = json!(projected_digest("AnimationClip", &clip).unwrap());
    let mut change = empty_change(&catalog, NativeKind::ClipRetime);
    change.document_changes.push(
        document(
            OwnedKind::Clip,
            Some(
                catalog
                    .owned_pin(OwnedKind::Clip, "clip-door")
                    .unwrap()
                    .revision
                    .clone(),
            ),
            clip,
        )
        .unwrap(),
    );
    update_project(&mut change).unwrap();
    let payload = change.to_arguments().unwrap();
    let bytes = mmmm_contracts::encode_json(&payload).unwrap();
    let read = parse_json(&bytes).unwrap();
    let decoded = PreparedNativeChange::from_payload(&read).unwrap();
    assert_eq!(
        decoded.document_changes[0].after["tracks"][0]["keys"][0]["transform"]["translation"][0],
        json!(9_007_199_254_740_992.0f64)
    );

    let resource = json!({"resourceId":"typed-size","sha256":"0".repeat(64),"mediaType":"application/json","sizeBytes":1.0});
    let typed: mmmm_domain::types::ResourceRef = decode("ResourceRef", &resource).unwrap();
    assert_eq!(typed.size_bytes, 1);
}

#[test]
fn prefab_comparison_preserves_original_and_value_only_requires_integer_lengths() {
    let original = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
    require_value_only_prefab_integer_lengths(&original).unwrap();
    let resource_length = original["resources"][0]["sizeBytes"].as_u64().unwrap();
    let mut decimal = original.clone();
    decimal["resources"][0]["sizeBytes"] = json!(resource_length as f64);
    assert_eq!(
        require_value_only_prefab_integer_lengths(&decimal)
            .unwrap_err()
            .code,
        "CAPABILITY_UNAVAILABLE"
    );
    let before = decimal.clone();
    let typed = decode_prefab_scoped(&decimal, || Ok(())).unwrap();
    assert_eq!(typed.resources[0].size_bytes, resource_length);
    assert_eq!(decimal, before);
    let mut calls = 0;
    let error = decode_prefab_scoped(&original, || {
        calls += 1;
        if calls == 2 {
            Err(AppError::new("CANCELLED", "test cancellation"))
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert_eq!(error.code, "CANCELLED");
}

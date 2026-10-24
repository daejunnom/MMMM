//! Existing handoff examples cover the basic wire shapes. These small in-memory
//! mutations cover missing pagination/permission/partial-capture boundaries.

use crate::*;
use mmmm_contracts::{
    ContextId, PrincipalId, ResourceLocation, Sha256Digest, SnapshotId, parse_json, raw_digest,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

fn example_snapshot() -> Value {
    parse_json(include_bytes!("../../../examples/data-snapshot.json")).unwrap()
}
fn example_record() -> Value {
    parse_json(include_bytes!("../../../examples/data-record-known.json")).unwrap()
}
fn context() -> ContextId {
    ContextId::new("context-fixture").unwrap()
}
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(character.to_string().repeat(64)).unwrap()
}
fn principal() -> ReadPrincipal {
    ReadPrincipal {
        principal_id: PrincipalId::new("principal-fixture").unwrap(),
        permission_scope_digest: digest('1'),
    }
}
fn identity() -> SnapshotIdentity {
    SnapshotIdentity {
        registry_generation: "generation-1".into(),
        mod_fingerprints: BTreeMap::new(),
        query_context_digest: digest('2'),
        observation_window: None,
    }
}
fn indexed(record: Value) -> IndexedRecord {
    IndexedRecord {
        record,
        terms: SearchTerms::default(),
        contexts: BTreeSet::from([context()]),
    }
}
fn input(records: Vec<IndexedRecord>) -> SnapshotInput {
    SnapshotInput {
        snapshot: example_snapshot(),
        identity: identity(),
        records,
        missing_records: vec![],
    }
}
fn fixture_catalog(input: SnapshotInput) -> Catalog {
    let mut catalog = Catalog::new([7; 32], CatalogLimits::default()).unwrap();
    catalog.insert_snapshot(input).unwrap();
    catalog
}
fn query(needle: &str, limit: i32) -> Value {
    json!({"snapshotId":"snapshot-fixture","query":needle,"kinds":[],"locale":"ko_kr","cursor":null,"limit":limit})
}
fn record_query(kind: &str, resource: &str) -> Value {
    json!({"snapshotId":"snapshot-fixture","kind":kind,"resourceId":resource,"contextId":"context-fixture"})
}

#[derive(Default)]
struct Access {
    denied_ids: BTreeSet<String>,
    deny_all: bool,
    deny_sources: bool,
}
impl AccessControl for Access {
    fn authorize_snapshot(&self, _: &ReadPrincipal, _: &Value) -> Result<(), CatalogError> {
        if self.deny_all {
            Err(CatalogError::PermissionRequired)
        } else {
            Ok(())
        }
    }
    fn can_read_record(
        &self,
        _: &ReadPrincipal,
        _: &Value,
        record: &Value,
        _: Option<&ContextId>,
    ) -> bool {
        !self.deny_all
            && !self
                .denied_ids
                .contains(record["recordId"].as_str().unwrap())
    }
    fn authorize_capture(&self, _: &ReadPrincipal, _: &Value) -> Result<(), CatalogError> {
        if self.deny_all {
            Err(CatalogError::PermissionRequired)
        } else {
            Ok(())
        }
    }
    fn authorize_source(&self, _: &ReadPrincipal, _: &Value) -> Result<(), CatalogError> {
        if self.deny_sources {
            Err(CatalogError::PermissionRequired)
        } else {
            Ok(())
        }
    }
}

fn numbered_records(count: usize) -> Vec<IndexedRecord> {
    (0..count)
        .map(|index| {
            let mut record = example_record();
            record["recordId"] = json!(format!("record-{index}"));
            record["resourceId"] = json!(format!("minecraft:stone_{index:03}"));
            indexed(record)
        })
        .collect()
}

#[test]
fn id_alias_tag_and_type_search_preserve_canonical_identity() {
    let mut record = indexed(example_record());
    record.terms.aliases = BTreeMap::from([
        ("ko_kr".into(), vec!["돌".into()]),
        ("en_us".into(), vec!["Stone".into()]),
    ]);
    record.terms.tags =
        BTreeSet::from([ResourceLocation::new("minecraft:mineable/pickaxe").unwrap()]);
    record.terms.type_terms = BTreeSet::from(["solid block".into()]);
    let catalog = fixture_catalog(input(vec![record]));
    for needle in [
        "minecraft:stone",
        "minecraft:st",
        "돌",
        "stone",
        "#minecraft:mineable/pickaxe",
        "solid block",
        "minecraft:block",
    ] {
        let page = catalog
            .search(&query(needle, 20), &principal(), &Access::default())
            .unwrap();
        assert_eq!(page["records"].as_array().unwrap().len(), 1, "{needle}");
        assert_eq!(page["records"][0]["resourceId"], "minecraft:stone");
        assert_eq!(page["records"][0]["sources"], example_record()["sources"]);
    }
    let mut filtered = query("돌", 20);
    filtered["kinds"] = json!(["minecraft:item"]);
    assert!(
        catalog
            .search(&filtered, &principal(), &Access::default())
            .unwrap()["records"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn exact_id_precedes_prefix_and_alias_and_order_is_stable() {
    let exact = indexed(example_record());
    let mut prefix = indexed(example_record());
    prefix.record["recordId"] = json!("record-stone-brick");
    prefix.record["resourceId"] = json!("minecraft:stone_bricks");
    let mut alias = indexed(example_record());
    alias.record["recordId"] = json!("record-mod-stone");
    alias.record["resourceId"] = json!("fixture:rock");
    alias
        .terms
        .aliases
        .insert("en_us".into(), vec!["minecraft:stone".into()]);
    let first = fixture_catalog(input(vec![alias.clone(), prefix.clone(), exact.clone()]));
    let second = fixture_catalog(input(vec![exact, prefix, alias]));
    let a = first
        .search(
            &query("minecraft:stone", 20),
            &principal(),
            &Access::default(),
        )
        .unwrap();
    let b = second
        .search(
            &query("minecraft:stone", 20),
            &principal(),
            &Access::default(),
        )
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(a["records"][0]["resourceId"], "minecraft:stone");
    assert_eq!(a["records"][1]["resourceId"], "minecraft:stone_bricks");
    assert_eq!(a["records"][2]["resourceId"], "fixture:rock");
}

#[test]
fn pagination_pins_conditions_scope_and_current_authority() {
    let catalog = fixture_catalog(input(numbered_records(5)));
    let first = catalog
        .search(&query("", 2), &principal(), &Access::default())
        .unwrap();
    let mut next = query("", 2);
    next["cursor"] = first["nextCursor"].clone();
    let second = catalog
        .search(&next, &principal(), &Access::default())
        .unwrap();
    assert_eq!(second["records"][0]["resourceId"], "minecraft:stone_002");
    assert_eq!(first["queryDigest"], second["queryDigest"]);
    for (field, value) in [
        ("query", json!("stone")),
        ("limit", json!(3)),
        ("locale", json!("en_us")),
        ("kinds", json!(["minecraft:block"])),
    ] {
        let mut changed = next.clone();
        changed[field] = value;
        assert!(
            matches!(
                catalog.search(&changed, &principal(), &Access::default()),
                Err(CatalogError::StaleCursor)
            ),
            "{field}"
        );
    }
    let mut changed = principal();
    changed.principal_id = PrincipalId::new("principal-other").unwrap();
    assert!(matches!(
        catalog.search(&next, &changed, &Access::default()),
        Err(CatalogError::StaleCursor)
    ));
    changed = principal();
    changed.permission_scope_digest = digest('3');
    assert!(matches!(
        catalog.search(&next, &changed, &Access::default()),
        Err(CatalogError::StaleCursor)
    ));
    let restricted = Access {
        denied_ids: BTreeSet::from(["record-0".into()]),
        ..Default::default()
    };
    assert!(matches!(
        catalog.search(&next, &principal(), &restricted),
        Err(CatalogError::StaleCursor)
    ));
}

#[test]
fn cursor_authentication_and_size_limit_fail_closed() {
    let catalog = fixture_catalog(input(numbered_records(3)));
    let page = catalog
        .search(&query("", 1), &principal(), &Access::default())
        .unwrap();
    let mut next = query("", 1);
    let mut token = page["nextCursor"].as_str().unwrap().to_owned();
    token.replace_range(0..1, if &token[..1] == "0" { "1" } else { "0" });
    next["cursor"] = json!(token);
    assert!(matches!(
        catalog.search(&next, &principal(), &Access::default()),
        Err(CatalogError::StaleCursor)
    ));
    next["cursor"] = json!("a".repeat(4097));
    assert!(matches!(
        catalog.search(&next, &principal(), &Access::default()),
        Err(CatalogError::StaleCursor)
    ));
}

#[test]
fn permissions_apply_to_every_direct_and_cached_page() {
    let catalog = fixture_catalog(input(numbered_records(4)));
    let restricted = Access {
        denied_ids: BTreeSet::from(["record-0".into()]),
        ..Default::default()
    };
    let page = catalog
        .search(&query("", 2), &principal(), &restricted)
        .unwrap();
    assert_eq!(page["coverage"]["status"], "partial");
    assert!(
        page["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record["recordId"] != "record-0")
    );
    let denied = Access {
        deny_all: true,
        ..Default::default()
    };
    assert!(matches!(
        catalog.search(&query("", 2), &principal(), &denied),
        Err(CatalogError::PermissionRequired)
    ));
    assert!(matches!(
        catalog.describe(
            &record_query("minecraft:block", "minecraft:stone_000"),
            &principal(),
            &restricted
        ),
        Err(CatalogError::PermissionRequired)
    ));
    assert!(matches!(
        catalog.snapshot_pin(
            &SnapshotId::new("snapshot-fixture").unwrap(),
            &principal(),
            &denied
        ),
        Err(CatalogError::PermissionRequired)
    ));
}

#[test]
fn immutable_snapshot_rejects_scope_generation_and_pack_order_replacement() {
    let original = input(vec![indexed(example_record())]);
    let mut catalog = fixture_catalog(original.clone());
    assert_eq!(
        catalog.insert_snapshot(original.clone()).unwrap(),
        catalog
            .snapshot_pin(
                &SnapshotId::new("snapshot-fixture").unwrap(),
                &principal(),
                &Access::default()
            )
            .unwrap()
            .revision
    );
    let mut changed = original.clone();
    changed.identity.registry_generation = "generation-2".into();
    assert!(matches!(
        catalog.insert_snapshot(changed),
        Err(CatalogError::SnapshotConflict)
    ));
    let mut changed = original.clone();
    changed.snapshot["environmentFingerprint"] = json!(digest('4'));
    assert!(matches!(
        catalog.insert_snapshot(changed),
        Err(CatalogError::SnapshotConflict)
    ));
    let mut changed = original.clone();
    changed.snapshot["serverPackStack"] = json!([digest('1'), digest('2')]);
    let a = catalog::Catalog::new([7; 32], CatalogLimits::default())
        .unwrap()
        .insert_snapshot(changed.clone())
        .unwrap();
    changed.snapshot["serverPackStack"] = json!([digest('2'), digest('1')]);
    let b = catalog::Catalog::new([7; 32], CatalogLimits::default())
        .unwrap()
        .insert_snapshot(changed)
        .unwrap();
    assert_ne!(a, b);
    let mut changed = original;
    changed
        .identity
        .mod_fingerprints
        .insert(ResourceLocation::new("fixture:mod").unwrap(), digest('5'));
    assert!(matches!(
        catalog.insert_snapshot(changed),
        Err(CatalogError::SnapshotConflict)
    ));
}

fn claim(status: &str, coverage: Value) -> MissingRecordClaim {
    MissingRecordClaim {
        context_id: context(),
        kind: ResourceLocation::new("minecraft:block").unwrap(),
        scope_digest: digest('6'),
        status: status.into(),
        value_type: "block_definition".into(),
        unit: "unitless".into(),
        sources: example_record()["sources"].as_array().unwrap().clone(),
        provenance: "documented".into(),
        coverage,
        reason: "Source coverage explicitly describes the requested kind and context".into(),
    }
}

#[test]
fn missing_records_need_specific_source_coverage_without_fabricated_values() {
    let mut data = input(vec![indexed(example_record())]);
    data.missing_records
        .push(claim("absent", example_snapshot()["coverage"].clone()));
    let catalog = fixture_catalog(data);
    let absent = catalog
        .describe(
            &record_query("minecraft:block", "fixture:missing"),
            &principal(),
            &Access::default(),
        )
        .unwrap();
    assert_eq!(absent["status"], "absent");
    assert!(absent.get("value").is_none());
    assert!(matches!(
        catalog.describe(
            &record_query("mmmm:mass_density", "minecraft:stone"),
            &principal(),
            &Access::default()
        ),
        Err(CatalogError::SourceUnavailable(_))
    ));
    let mut other_context = record_query("minecraft:block", "minecraft:stone");
    other_context["contextId"] = json!("context-other");
    assert!(matches!(
        catalog.describe(&other_context, &principal(), &Access::default()),
        Err(CatalogError::SourceUnavailable(_))
    ));
    let mut partial = example_snapshot()["coverage"].clone();
    partial["status"] = json!("partial");
    partial["exclusions"] = json!(["Unloaded regions"]);
    let mut data = input(vec![]);
    data.missing_records.push(claim("absent", partial.clone()));
    assert!(matches!(
        Catalog::new([7; 32], CatalogLimits::default())
            .unwrap()
            .insert_snapshot(data),
        Err(CatalogError::SchemaUnsupported(_))
    ));
    let mut data = input(vec![]);
    data.missing_records.push(claim("unknown", partial));
    let unknown = fixture_catalog(data)
        .describe(
            &record_query("minecraft:block", "fixture:missing"),
            &principal(),
            &Access::default(),
        )
        .unwrap();
    assert_eq!(unknown["status"], "unknown");
    assert!(unknown.get("value").is_none());
}

#[test]
fn original_statuses_and_known_null_are_preserved() {
    let unknown = parse_json(include_bytes!("../../../examples/data-record-unknown.json")).unwrap();
    let catalog = fixture_catalog(input(vec![
        indexed(example_record()),
        indexed(unknown.clone()),
    ]));
    assert_eq!(
        catalog
            .describe(
                &record_query("mmmm:mass_density", "minecraft:stone"),
                &principal(),
                &Access::default()
            )
            .unwrap(),
        unknown
    );
    for status in ["absent", "unknown", "unsupported", "requires_runtime"] {
        let mut record = example_record();
        record.as_object_mut().unwrap().remove("value");
        record["status"] = json!(status);
        record["reason"] = json!("Explicit source status");
        let result = fixture_catalog(input(vec![indexed(record.clone())]))
            .describe(
                &record_query("minecraft:block", "minecraft:stone"),
                &principal(),
                &Access::default(),
            )
            .unwrap();
        assert_eq!(result, record);
        assert!(result.get("value").is_none());
    }
    let mut record = example_record();
    record["value"] = Value::Null;
    assert_eq!(
        fixture_catalog(input(vec![indexed(record)]))
            .describe(
                &record_query("minecraft:block", "minecraft:stone"),
                &principal(),
                &Access::default()
            )
            .unwrap()["value"],
        Value::Null
    );
}

#[test]
fn duplicate_context_key_source_mismatch_and_budgets_are_rejected() {
    let first = indexed(example_record());
    let mut second = first.clone();
    second.record["recordId"] = json!("record-duplicate");
    assert!(matches!(
        Catalog::new([7; 32], CatalogLimits::default())
            .unwrap()
            .insert_snapshot(input(vec![first, second])),
        Err(CatalogError::SchemaUnsupported(_))
    ));
    let mut bad = indexed(example_record());
    bad.record["sources"][0]["locator"] = json!("unapproved-source");
    assert!(matches!(
        Catalog::new([7; 32], CatalogLimits::default())
            .unwrap()
            .insert_snapshot(input(vec![bad])),
        Err(CatalogError::SourceUnavailable(_))
    ));
    let limits = CatalogLimits {
        max_records_per_snapshot: 1,
        ..Default::default()
    };
    assert!(matches!(
        Catalog::new([7; 32], limits)
            .unwrap()
            .insert_snapshot(input(numbered_records(2))),
        Err(CatalogError::InputLimit)
    ));
    let mut bad = indexed(example_record());
    bad.terms
        .aliases
        .insert("ko_kr".into(), vec!["a".repeat(257)]);
    assert!(matches!(
        Catalog::new([7; 32], CatalogLimits::default())
            .unwrap()
            .insert_snapshot(input(vec![bad])),
        Err(CatalogError::InputLimit)
    ));
}

#[test]
fn observation_windows_preserve_multi_tick_consistency_and_side() {
    let mut data = input(vec![indexed(example_record())]);
    data.snapshot["layers"] = json!(["world_observation"]);
    data.snapshot["coverage"]["consistency"] = json!("provider_atomic");
    data.identity.observation_window = Some(ObservationWindow {
        first_tick: "10".into(),
        last_tick: "11".into(),
    });
    assert!(matches!(
        Catalog::new([7; 32], CatalogLimits::default())
            .unwrap()
            .insert_snapshot(data.clone()),
        Err(CatalogError::SchemaUnsupported(_))
    ));
    data.snapshot["coverage"]["consistency"] = json!("per_item_observed");
    let catalog = fixture_catalog(data.clone());
    let pin = catalog
        .snapshot_pin(
            &SnapshotId::new("snapshot-fixture").unwrap(),
            &principal(),
            &Access::default(),
        )
        .unwrap();
    assert_eq!(
        pin.identity.observation_window,
        data.identity.observation_window
    );
    assert_eq!(pin.identity.registry_generation, "generation-1");
    data.identity.observation_window = None;
    assert!(matches!(
        Catalog::new([7; 32], CatalogLimits::default())
            .unwrap()
            .insert_snapshot(data),
        Err(CatalogError::SchemaUnsupported(_))
    ));
    let mut data = input(vec![]);
    data.snapshot["side"] = json!("server");
    assert!(matches!(
        Catalog::new([7; 32], CatalogLimits::default())
            .unwrap()
            .insert_snapshot(data),
        Err(CatalogError::SchemaUnsupported(_))
    ));
}

#[test]
fn response_byte_budget_shortens_pages_without_losing_records() {
    let mut records = numbered_records(4);
    for record in &mut records {
        record.record["value"]["description"] = json!("x".repeat(3000));
    }
    let limits = CatalogLimits {
        max_page_bytes: 10_000,
        ..Default::default()
    };
    let mut catalog = Catalog::new([7; 32], limits).unwrap();
    catalog.insert_snapshot(input(records)).unwrap();
    let mut request = query("", 200);
    let mut ids = Vec::new();
    loop {
        let page = catalog
            .search(&request, &principal(), &Access::default())
            .unwrap();
        assert_eq!(page["records"].as_array().unwrap().len(), 1);
        assert!(mmmm_contracts::encode_json(&page).unwrap().len() <= 10_000);
        ids.push(page["records"][0]["resourceId"].clone());
        assert!(
            ids.len() <= 4,
            "Continuation repeated records instead of completing"
        );
        if page["nextCursor"].is_null() {
            break;
        }
        request["cursor"] = page["nextCursor"].clone();
    }
    assert_eq!(
        ids,
        json!([
            "minecraft:stone_000",
            "minecraft:stone_001",
            "minecraft:stone_002",
            "minecraft:stone_003"
        ])
        .as_array()
        .unwrap()
        .clone()
    );
    // Each original record is below the common node limit, but composing two
    // 50,000-value payloads must still produce bounded pages.
    let mut records = numbered_records(2);
    for record in &mut records {
        record.record["value"] = json!(vec![Value::Null; 50_000]);
    }
    let catalog = fixture_catalog(input(records));
    let page = catalog
        .search(&query("", 2), &principal(), &Access::default())
        .unwrap();
    assert_eq!(page["records"].as_array().unwrap().len(), 1);
    let mut next = query("", 2);
    next["cursor"] = page["nextCursor"].clone();
    let second = catalog
        .search(&next, &principal(), &Access::default())
        .unwrap();
    assert_eq!(second["records"].as_array().unwrap().len(), 1);
    assert!(second["nextCursor"].is_null());
}

#[test]
fn direct_absence_record_cannot_claim_partial_coverage_is_complete() {
    let mut record = example_record();
    record.as_object_mut().unwrap().remove("value");
    record["status"] = json!("absent");
    record["reason"] = json!("Source did not enumerate the complete region");
    record["coverage"]["status"] = json!("partial");
    record["coverage"]["exclusions"] = json!(["Unloaded region"]);
    assert!(matches!(
        Catalog::new([7; 32], CatalogLimits::default())
            .unwrap()
            .insert_snapshot(input(vec![indexed(record)])),
        Err(CatalogError::SchemaUnsupported(_))
    ));
}

struct Port {
    result: Option<CaptureResult>,
    calls: usize,
}
impl SnapshotSource for Port {
    fn capture(
        &mut self,
        _: &Value,
        _: &CaptureControl<'_>,
        budget: &CaptureBudget,
        source_access: &CaptureSourceAccess<'_>,
    ) -> Result<CaptureResult, CatalogError> {
        source_access.authorize_before_read(&self.result.as_ref().unwrap().sources[0].source)?;
        self.calls += 1;
        assert!(budget.max_source_bytes > 0);
        Ok(self.result.take().unwrap())
    }
}
fn captured(interrupted: bool) -> (Value, CaptureResult) {
    let bytes = b"owned minimal reference input".to_vec();
    let mut data = input(vec![indexed(example_record())]);
    let mut source = data.snapshot["sources"][0].clone();
    source["sha256"] = json!(raw_digest(&bytes));
    data.snapshot["sources"] = json!([source.clone()]);
    data.records[0].record["sources"] = json!([source.clone()]);
    if interrupted {
        data.snapshot["coverage"]["status"] = json!("partial");
        data.snapshot["coverage"]["exclusions"] =
            json!(["Capture stopped before remaining source enumeration"]);
    }
    let request = json!({"contextId":"context-fixture","sources":[source.clone()],"environment":data.snapshot["environment"],"kind":"version_reference","loadPolicy":"no_implicit_runtime_mutation"});
    (
        request,
        CaptureResult {
            snapshot: data,
            sources: vec![CaptureSourceEvidence {
                source,
                observed_bytes: bytes,
            }],
            interrupted,
        },
    )
}
fn control(flag: &AtomicBool) -> CaptureControl<'_> {
    CaptureControl {
        cancellation: flag,
        deadline: Instant::now() + Duration::from_secs(10),
    }
}

#[test]
fn capture_hashes_real_port_bytes_once_and_registers_immutable_result() {
    let (request, result) = captured(false);
    let mut port = Port {
        result: Some(result),
        calls: 0,
    };
    let mut catalog = Catalog::new([7; 32], CatalogLimits::default()).unwrap();
    let flag = AtomicBool::new(false);
    let snapshot = catalog
        .capture(
            &request,
            &principal(),
            &Access::default(),
            &mut port,
            &control(&flag),
        )
        .unwrap();
    assert_eq!(port.calls, 1);
    assert_eq!(
        snapshot["sources"][0]["sha256"],
        request["sources"][0]["sha256"]
    );
    assert!(
        catalog
            .snapshot_pin(
                &SnapshotId::new("snapshot-fixture").unwrap(),
                &principal(),
                &Access::default()
            )
            .is_ok()
    );
    let (_, result) = captured(false);
    let mut repeated = Port {
        result: Some(result),
        calls: 0,
    };
    assert!(matches!(
        catalog.capture(
            &request,
            &principal(),
            &Access::default(),
            &mut repeated,
            &control(&flag)
        ),
        Err(CatalogError::SnapshotConflict)
    ));
    assert_eq!(repeated.calls, 1);
    let (request, mut result) = captured(false);
    result.sources[0].observed_bytes.push(0);
    let mut port = Port {
        result: Some(result),
        calls: 0,
    };
    let mut catalog = Catalog::new([7; 32], CatalogLimits::default()).unwrap();
    assert!(matches!(
        catalog.capture(
            &request,
            &principal(),
            &Access::default(),
            &mut port,
            &control(&flag)
        ),
        Err(CatalogError::SourceUnavailable(_))
    ));
    assert!(matches!(
        catalog.snapshot_pin(
            &SnapshotId::new("snapshot-fixture").unwrap(),
            &principal(),
            &Access::default()
        ),
        Err(CatalogError::SnapshotNotFound)
    ));
}

#[test]
fn source_authorization_and_pre_cancel_stop_before_external_port() {
    let (request, result) = captured(false);
    let mut port = Port {
        result: Some(result),
        calls: 0,
    };
    let mut catalog = Catalog::new([7; 32], CatalogLimits::default()).unwrap();
    let flag = AtomicBool::new(false);
    let denied = Access {
        deny_sources: true,
        ..Default::default()
    };
    assert!(matches!(
        catalog.capture(&request, &principal(), &denied, &mut port, &control(&flag)),
        Err(CatalogError::PermissionRequired)
    ));
    assert_eq!(port.calls, 0);
    let flag = AtomicBool::new(true);
    assert!(matches!(
        catalog.capture(
            &request,
            &principal(),
            &Access::default(),
            &mut port,
            &control(&flag)
        ),
        Err(CatalogError::Cancelled)
    ));
    assert_eq!(port.calls, 0);
}

#[test]
fn partial_capture_preserves_actual_sources_but_complete_requires_all_sources() {
    let (mut request, result) = captured(true);
    let mut pending = request["sources"][0].clone();
    pending["sourceId"] = json!("source-pending");
    request["sources"].as_array_mut().unwrap().push(pending);
    let mut port = Port {
        result: Some(result),
        calls: 0,
    };
    let mut catalog = Catalog::new([7; 32], CatalogLimits::default()).unwrap();
    let flag = AtomicBool::new(false);
    let output = catalog
        .capture(
            &request,
            &principal(),
            &Access::default(),
            &mut port,
            &control(&flag),
        )
        .unwrap();
    assert_eq!(output["coverage"]["status"], "partial");
    assert_eq!(output["sources"].as_array().unwrap().len(), 1);
    let (_, result) = captured(false);
    let mut port = Port {
        result: Some(result),
        calls: 0,
    };
    let mut catalog = Catalog::new([7; 32], CatalogLimits::default()).unwrap();
    assert!(matches!(
        catalog.capture(
            &request,
            &principal(),
            &Access::default(),
            &mut port,
            &control(&flag)
        ),
        Err(CatalogError::SourceUnavailable(_))
    ));
    let (request, mut result) = captured(false);
    result.interrupted = true;
    let mut port = Port {
        result: Some(result),
        calls: 0,
    };
    let mut catalog = Catalog::new([7; 32], CatalogLimits::default()).unwrap();
    assert!(matches!(
        catalog.capture(
            &request,
            &principal(),
            &Access::default(),
            &mut port,
            &control(&flag)
        ),
        Err(CatalogError::SchemaUnsupported(_))
    ));
}

#[test]
fn schema_mathematical_integer_limit_does_not_truncate_or_reject_integral_float() {
    let catalog = fixture_catalog(input(numbered_records(3)));
    let mut request = query("", 1);
    request["limit"] = json!(1.0);
    assert_eq!(
        catalog
            .search(&request, &principal(), &Access::default())
            .unwrap()["records"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    request["limit"] = json!(1.5);
    assert!(matches!(
        catalog.search(&request, &principal(), &Access::default()),
        Err(CatalogError::Contract(_))
    ));
}

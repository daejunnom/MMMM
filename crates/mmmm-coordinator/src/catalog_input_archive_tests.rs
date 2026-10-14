//! 기존 empty ZIP는 page/합계 경계를 넘지 않는다. 아래 생성 자료는 payload가
//! 없는 자체 작성 classic ZIP이며 실제 game·pack·source/읽기 권한을 발급하지 않는다.
//! 실제 Store/owner 경로는 기존 native_catalog_tests의 fixture를 재사용한다.

use super::*;
use std::{
    cell::Cell,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

fn u16_bytes(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn u32_bytes(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn empty_entries(names: &[String]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut directory = Vec::new();
    for name in names {
        let offset = bytes.len() as u32;
        let mut local = vec![0u8; 30];
        u32_bytes(&mut local, 0, 0x0403_4b50);
        u16_bytes(&mut local, 4, 20);
        u16_bytes(&mut local, 6, 1 << 11);
        u16_bytes(&mut local, 26, name.len() as u16);
        bytes.extend_from_slice(&local);
        bytes.extend_from_slice(name.as_bytes());
        let mut central = vec![0u8; 46];
        u32_bytes(&mut central, 0, 0x0201_4b50);
        u16_bytes(&mut central, 4, 20);
        u16_bytes(&mut central, 6, 20);
        u16_bytes(&mut central, 8, 1 << 11);
        u16_bytes(&mut central, 28, name.len() as u16);
        u32_bytes(&mut central, 42, offset);
        directory.extend_from_slice(&central);
        directory.extend_from_slice(name.as_bytes());
    }
    let offset = bytes.len() as u32;
    let length = directory.len() as u32;
    bytes.extend_from_slice(&directory);
    let mut end = vec![0u8; 22];
    u32_bytes(&mut end, 0, 0x0605_4b50);
    u16_bytes(&mut end, 8, names.len() as u16);
    u16_bytes(&mut end, 10, names.len() as u16);
    u32_bytes(&mut end, 12, length);
    u32_bytes(&mut end, 16, offset);
    bytes.extend_from_slice(&end);
    bytes
}
fn budget() -> RequestBudget {
    RequestBudget::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false))).unwrap()
}
fn inventory(names: &[String]) -> InputArchiveInventory {
    let request = budget();
    inventory_input_archive(
        &empty_entries(names),
        InputArchiveLimits::default(),
        &CaptureControl {
            cancellation: request.cancellation(),
            deadline: request.deadline(),
        },
    )
    .unwrap()
}

#[test]
fn member_pages_preserve_order_directory_kind_and_both_page_bounds() {
    for long in [false, true] {
        let mut names = vec!["directory/".to_owned()];
        names.extend((0..1025).map(|index| {
            if long {
                format!(
                    "{}/{}/{}/entry-{index:05}.json",
                    "a".repeat(220),
                    "b".repeat(220),
                    "c".repeat(220)
                )
            } else {
                format!("entry-{index:05}.json")
            }
        }));
        let inventory = inventory(&names);
        let mut seen = Vec::new();
        let mut pages = 0;
        // 이 callback은 JSON을 관찰할 뿐 ResourceRef나 producer receipt를 만들지 않는다.
        member_pages(
            &inventory,
            &json!({"fixture":"page-observation-only"}),
            || Ok(()),
            |page| {
                assert!(encode_json(page).unwrap().len() <= PAGE_BYTES);
                assert!(page["members"].as_array().unwrap().len() <= PAGE_ENTRIES);
                if pages == 0 {
                    assert_eq!(page["members"][0]["kind"], "directory");
                }
                seen.extend(
                    page["members"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|member| member["name"].as_str().unwrap().to_owned()),
                );
                pages += 1;
                Ok(json!({"observedPage":pages}))
            },
        )
        .unwrap();
        assert!(pages >= 2);
        assert_eq!(seen, names);
    }
}

#[test]
fn parser_failure_consumes_the_reserved_request_allowance_without_retry_amplification() {
    let mut work = WorkBudget::new(2).unwrap();
    work.entries = 1;
    let limits = work.reserve_parse().unwrap();
    let request = budget();
    let error = inventory_input_archive(
        &empty_entries(&["one".into(), "two".into()]),
        limits,
        &CaptureControl {
            cancellation: request.cancellation(),
            deadline: request.deadline(),
        },
    )
    .unwrap_err();
    assert_eq!(error.code(), "INPUT_ARCHIVE_ENTRY_LIMIT");
    assert_eq!(work.decoded, 0);
    assert_eq!(work.entries, 0);
    assert_eq!(
        work.reserve_parse().unwrap_err().code,
        "INPUT_ARCHIVE_AGGREGATE_LIMIT"
    );
    let mut work = WorkBudget::new(2).unwrap();
    work.charge_input(MAX_SOURCE_BYTES).unwrap();
    assert_eq!(
        work.charge_input(1).unwrap_err().code,
        "INPUT_ARCHIVE_AGGREGATE_LIMIT"
    );
    let limits = work.reserve_parse().unwrap();
    let observed = inventory(&["one".into()]);
    work.refund_parse(limits, &observed).unwrap();
    assert_eq!(work.entries, 65_534);
    assert_eq!(work.decoded, 256 * 1024 * 1024);
}

#[test]
fn encoded_work_reserves_actual_rejection_manifests_and_registry_cost_includes_existing_sources() {
    // 기존 짧은 selector는 4 KiB 예약의 부족을 드러내지 못한다. 이 자료는
    // 유효한 긴 canonical ID의 인코딩만 검사하며 실제 source 권한을 만들지 않는다.
    let selected = |role: Value| {
        serde_json::from_value::<PinnedCatalogSourceUse>(json!({
            "selection":{"resourceId":"archive-fact-only","role":role},
            "resource":{"resourceId":"archive-fact-only","sha256":raw_digest(b""),
                "sizeBytes":0,"mediaType":"application/java-archive"},
            "blob":{"digest":raw_digest(b""),"byteLength":0}
        }))
        .unwrap()
    };
    let long = selected(
        json!({"kind":"mod","canonicalId":format!("example:{}", "a".repeat(6000)),
        "nativeId":"fixture_mod"}),
    );
    let short = selected(json!({"kind":"game_artifact"}));
    let selection_bytes = encode_json(&json!([long.selection(), short.selection()]))
        .unwrap()
        .len();
    assert!(selection_bytes > 4096 && selection_bytes < 65_536);
    let provenance = json!({"resourceId":"factual-locator"});
    let long_manifest = rejection_manifest(&long, &provenance);
    let short_manifest = rejection_manifest(&short, &provenance);
    let long_bytes = encode_json(&long_manifest).unwrap().len();
    let short_bytes = encode_json(&short_manifest).unwrap().len();
    assert!(long_bytes > 4096 && long_bytes <= PAGE_BYTES);
    assert!(long_bytes > short_bytes);
    assert_eq!(long_manifest["selection"], json!(long.selection()));
    assert_eq!(long_manifest["limits"], Value::Null);
    let mut work = WorkBudget::new(2).unwrap();
    let long_reservation = work.reserve_manifest(&long_manifest).unwrap();
    let short_reservation = work.reserve_manifest(&short_manifest).unwrap();
    work.charge_encoded(ENCODED_BYTES - long_bytes - short_bytes)
        .unwrap();
    assert_eq!(
        work.charge_encoded(1).unwrap_err().code,
        "INPUT_ARCHIVE_ENCODE_LIMIT"
    );
    work.finish_input(long_reservation).unwrap();
    work.charge_encoded(long_bytes).unwrap();
    assert_eq!(
        work.charge_encoded(1).unwrap_err().code,
        "INPUT_ARCHIVE_ENCODE_LIMIT"
    );
    work.finish_input(short_reservation).unwrap();
    work.charge_encoded(short_bytes).unwrap();
    assert_eq!(work.encoded, ENCODED_BYTES);
    assert_eq!(work.reserved_manifests, 0);
    let summaries = [json!({"manifest":"factual-locator","inventory":{"status":"complete"}})];
    let cost = registry_values_cost(0, &provenance, &summaries).unwrap();
    assert_eq!(
        registry_values_cost(REGISTRY_BYTES - cost, &provenance, &summaries).unwrap(),
        REGISTRY_BYTES
    );
    assert_eq!(
        registry_values_cost(REGISTRY_BYTES - cost + 1, &provenance, &summaries)
            .unwrap_err()
            .code,
        "INPUT_ARCHIVE_ENCODE_LIMIT"
    );
}

#[test]
fn original_request_cancellation_stops_between_pages_without_a_new_deadline() {
    let inventory = inventory(
        &(0..1025)
            .map(|index| format!("entry-{index}"))
            .collect::<Vec<_>>(),
    );
    let request = budget();
    let pages = Cell::new(0);
    let error = member_pages(
        &inventory,
        &Value::Null,
        || request.check().map_err(budget_error),
        |_| {
            pages.set(pages.get() + 1);
            request.cancellation().store(true, Ordering::Release);
            Ok(Value::Null)
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "CANCELLED");
    assert_eq!(pages.get(), 1);
}

#[test]
fn producer_failure_and_current_boundary_failure_keep_both_typed_causes() {
    let request = budget();
    request.cancellation().store(true, Ordering::Release);
    let error = inventory_input_archive(
        b"not parsed",
        InputArchiveLimits::default(),
        &CaptureControl {
            cancellation: request.cancellation(),
            deadline: request.deadline(),
        },
    )
    .unwrap_err();
    let code = error.code();
    let combined = finish::<()>(
        Err(AppError::caused_by(code, "original", error)),
        Err(AppError::new("PERMISSION_REQUIRED", "current ACL changed")),
    )
    .unwrap_err();
    let causes = combined
        .source()
        .unwrap()
        .downcast_ref::<InventoryBoundaryFailure>()
        .unwrap();
    assert_eq!(causes.primary.code, "CANCELLED");
    assert_eq!(causes.checkpoint.code, "PERMISSION_REQUIRED");
    assert!(
        causes
            .primary
            .source()
            .unwrap()
            .is::<mmmm_reference::input_archive::InputArchiveError>()
    );
}

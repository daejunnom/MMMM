// 기존 native entry의 실제 ImportRoot/초기화/import fixture를 재사용한다.
// cold native owner/동일 Store/argv/전달 경계를 검사하며 게임 검증은 수행하지 않는다.

use super::*;
use mmmm_contracts::{encode_json, raw_digest};

fn selectors() -> Vec<CatalogSourceUseSelection> {
    vec![CatalogSourceUseSelection {
        resource_id: ResourceId::new("catalog-entry-container").unwrap(),
        role: CatalogSourceUseRole::GameArtifact,
    }]
}
fn prepared_project() -> (
    ImportRoot,
    ProjectBootstrapReceipt,
    NativeOwnedSourceCommitReceipt,
) {
    let root = ImportRoot::new();
    let initialized = root.initialize();
    let (budget, _) = import_budget();
    let mut bytes = b"PK\x05\x06".to_vec();
    bytes.extend_from_slice(&[0; 18]);
    let metadata = encode_json(
        &json!({"resourceId":"catalog-entry-container", "sha256":raw_digest(&bytes),
        "mediaType":"application/java-archive", "sizeBytes":bytes.len()}),
    )
    .unwrap();
    let prepared = root.prepare(&initialized.project_id, &budget);
    let receipt = prepared
        .import_native_sources(&NativeSourceInput {
            project: &initialized.project_id,
            expected_revision: &initialized.project_revision,
            documents: &[],
            retained_resources: &[],
            raw_resources: &[NativeRawSourceResource {
                metadata: &metadata,
                bytes: &bytes,
            }],
        })
        .unwrap();
    (root, initialized, receipt)
}
fn inspect(
    root: &ImportRoot,
    receipt: &NativeOwnedSourceCommitReceipt,
) -> CatalogSourceUseSnapshot {
    let (budget, _) = import_budget();
    manage_catalog_source_use(
        StoreConfig::new(root.0.clone()),
        &receipt.project_id,
        &receipt.project_revision,
        LocalCatalogSourceUseAction::Inspect,
        &budget,
    )
    .unwrap()
}
fn replace(
    root: &ImportRoot,
    receipt: &NativeOwnedSourceCommitReceipt,
    state: &Sha256Digest,
    selected: Vec<CatalogSourceUseSelection>,
) -> mmmm_application::AppResult<CatalogSourceUseSnapshot> {
    let (budget, _) = import_budget();
    manage_catalog_source_use(
        StoreConfig::new(root.0.clone()),
        &receipt.project_id,
        &receipt.project_revision,
        LocalCatalogSourceUseAction::Replace {
            expected_state_digest: state.clone(),
            selections: selected,
        },
        &budget,
    )
}
fn command_args(mode: &str) -> Vec<String> {
    let mut result = args(&[
        "catalog-source-use",
        "--data-root",
        root(),
        "--project",
        "project-test",
        "--expected-revision",
    ]);
    result.push("a".repeat(64));
    result.extend(args(&["--mode", mode]));
    result
}

#[test]
fn catalog_source_use_parser_requires_closed_mode_state_and_explicit_empty_withdrawal() {
    assert!(matches!(
        parse(&command_args("inspect")).unwrap(),
        Some(Command::CatalogSourceUse {
            action: LocalCatalogSourceUseAction::Inspect,
            ..
        })
    ));
    let mut input = command_args("replace");
    assert!(parse(&input).is_err());
    input.extend(args(&["--expected-state-digest", &"b".repeat(64)]));
    assert!(parse(&input).is_err());
    input.extend(args(&[
        "--game-artifact",
        "catalog-entry-container",
        "--mod",
        "example:fixture,fixture_mod,catalog-mod-container",
    ]));
    let Some(Command::CatalogSourceUse {
        action: LocalCatalogSourceUseAction::Replace { selections, .. },
        ..
    }) = parse(&input).unwrap()
    else {
        panic!("explicit full source set missing");
    };
    assert_eq!(selections.len(), 2);
    let mut clear = command_args("replace");
    clear.extend(args(&[
        "--expected-state-digest",
        &"b".repeat(64),
        "--withdraw",
        "true",
    ]));
    assert!(
        matches!(parse(&clear).unwrap(), Some(Command::CatalogSourceUse {
        action: LocalCatalogSourceUseAction::Replace { selections, .. }, .. }) if selections.is_empty())
    );
    clear.extend(args(&["--game-artifact", "catalog-entry-container"]));
    assert!(parse(&clear).is_err());
    for (mode, fields) in [
        ("inspect", vec!["--expected-state-digest", "unused"]),
        ("inspect", vec!["--withdraw", "true"]),
        ("inspect", vec!["--game-artifact", "resource"]),
        ("other", Vec::new()),
        ("replace", vec!["--withdraw", "false"]),
    ] {
        let mut input = command_args(mode);
        input.extend(args(&fields));
        assert!(parse(&input).is_err());
    }
}

#[test]
fn catalog_source_use_parser_never_accepts_source_refs_principals_or_unbounded_mod_selectors() {
    for extra in [
        ["--principal", "native-owner"],
        ["--context", "game-context"],
        ["--policy-revision", "claimed"],
        ["--rights", "licensed"],
        ["--source-ref", "{}"],
        ["--blob", "{}"],
        ["--source-file", "unselected.jar"],
    ] {
        let mut input = command_args("inspect");
        input.extend(args(&extra));
        assert!(parse(&input).is_err());
    }
    for selector in [
        "missing",
        "example:fixture,fixture",
        "example:fixture,fixture,res,extra",
        "example:fixture,,res",
        "Not:Canonical,fixture,res",
        "example:fixture,white space,res",
    ] {
        assert!(catalog_mod_selector(selector).is_err());
    }
    let mut input = command_args("replace");
    input.extend(args(&["--expected-state-digest", &"b".repeat(64)]));
    for _ in 0..257 {
        input.extend(args(&["--mod", "example:fixture,fixture,res"]));
    }
    assert!(parse(&input).is_err());
}

#[test]
fn actual_cold_inspect_replace_retry_and_withdrawal_keep_one_protected_ledger() {
    let (root, _, receipt) = prepared_project();
    let before = inspect(&root, &receipt);
    assert_eq!(before.generation(), 0);
    let selected = replace(&root, &receipt, before.state_digest(), selectors()).unwrap();
    assert_eq!(selected.generation(), 1);
    assert_eq!(selected.selections().len(), 1);
    assert_eq!(
        replace(&root, &receipt, before.state_digest(), selectors()).unwrap(),
        selected
    );
    let withdrawn = replace(&root, &receipt, selected.state_digest(), Vec::new()).unwrap();
    assert_eq!(withdrawn.generation(), 2);
    assert!(withdrawn.selections().is_empty());
    assert!(replace(&root, &receipt, before.state_digest(), selectors()).is_err());
    assert_eq!(inspect(&root, &receipt), withdrawn);
    let stored = root.open();
    assert_eq!(
        stored.project(&receipt.project_id).unwrap()["revision"],
        receipt.project_revision.as_str()
    );
    drop(stored);
    assert!(!root.0.join("runtime").exists());
}

#[test]
fn active_store_and_stale_project_are_rejected_without_creating_a_second_journal_or_context() {
    let (root, initialized, receipt) = prepared_project();
    let before = inspect(&root, &receipt);
    let held = root.open();
    let (budget, _) = import_budget();
    let error = manage_catalog_source_use(
        StoreConfig::new(root.0.clone()),
        &receipt.project_id,
        &receipt.project_revision,
        LocalCatalogSourceUseAction::Inspect,
        &budget,
    )
    .unwrap_err();
    assert_eq!(error.code, "SOURCE_BUSY");
    assert!(matches!(
        std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<StorageError>(),
        Some(StorageError::Busy)
    ));
    drop(held);
    let (budget, _) = import_budget();
    assert!(
        manage_catalog_source_use(
            StoreConfig::new(root.0.clone()),
            &receipt.project_id,
            &initialized.project_revision,
            LocalCatalogSourceUseAction::Inspect,
            &budget
        )
        .is_err()
    );
    assert_eq!(inspect(&root, &receipt), before);
    assert!(!root.0.join("runtime").exists());
}

#[test]
fn corrupt_previously_selected_source_does_not_trigger_a_full_workspace_scan_before_withdrawal() {
    let (root, _, receipt) = prepared_project();
    let before = inspect(&root, &receipt);
    let selected = replace(&root, &receipt, before.state_digest(), selectors()).unwrap();
    let pin = selected.selections()[0].blob();
    // 이 fixture의 고정 CAS layout을 소스에서 확인했다. 알려진 exact 파일만 바꾼다.
    let path = root
        .0
        .join("blobs")
        .join(&pin.digest.as_str()[..2])
        .join(&pin.digest.as_str()[2..]);
    let path = fs::canonicalize(path).unwrap();
    assert!(path.starts_with(&root.0));
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        assert_eq!(metadata.file_attributes() & 0x400, 0);
    }
    let bytes = fs::read(&path).unwrap();
    assert_eq!(raw_digest(&bytes), pin.digest);
    fs::write(path, vec![0; bytes.len()]).unwrap();
    assert_eq!(inspect(&root, &receipt), selected);
    assert!(replace(&root, &receipt, selected.state_digest(), selectors()).is_err());
    let withdrawn = replace(&root, &receipt, selected.state_digest(), Vec::new()).unwrap();
    assert_eq!(withdrawn.generation(), 2);
    assert!(withdrawn.selections().is_empty());
    assert_eq!(inspect(&root, &receipt), withdrawn);
}

#[test]
fn cancellation_and_missing_initialization_preserve_original_typed_failures_and_no_approval() {
    let (root, _, receipt) = prepared_project();
    let before = inspect(&root, &receipt);
    let (budget, cancellation) = import_budget();
    cancellation.store(true, Ordering::Release);
    let error = manage_catalog_source_use(
        StoreConfig::new(root.0.clone()),
        &receipt.project_id,
        &receipt.project_revision,
        LocalCatalogSourceUseAction::Replace {
            expected_state_digest: before.state_digest().clone(),
            selections: selectors(),
        },
        &budget,
    )
    .unwrap_err();
    assert_eq!(error.code, "CANCELLED");
    assert!(
        std::error::Error::source(&error)
            .unwrap()
            .is::<ServiceError>()
    );
    assert_eq!(inspect(&root, &receipt), before);
    let absent = ImportRoot::new();
    let (budget, _) = import_budget();
    assert!(
        manage_catalog_source_use(
            StoreConfig::new(absent.0.clone()),
            &receipt.project_id,
            &receipt.project_revision,
            LocalCatalogSourceUseAction::Inspect,
            &budget
        )
        .is_err()
    );
    assert!(!absent.0.join("journal.sqlite3").exists());
    assert!(!absent.0.join("blobs").exists());
    assert!(!absent.0.join("runtime").exists());
}

#[test]
fn confirmed_source_use_receipt_survives_delivery_failure_and_later_cancellation() {
    for cancel in [false, true] {
        let (root, _, receipt) = prepared_project();
        let before = inspect(&root, &receipt);
        let selected = replace(&root, &receipt, before.state_digest(), selectors()).unwrap();
        let (budget, cancellation) = import_budget();
        if cancel {
            cancellation.store(true, Ordering::Release);
        }
        let error = deliver_catalog_source_uses(
            selected.clone(),
            &receipt.project_revision,
            &budget,
            |_, _| Err(EntryError::OutputInvalid),
        )
        .unwrap_err();
        let EntryError::CatalogSourceUsesCommitted { snapshot, delivery } = error else {
            panic!("confirmed receipt lost");
        };
        assert_eq!(*snapshot, selected);
        if cancel {
            assert!(
                matches!(*delivery, EntryError::SourceRequest(ref cause) if cause.code == "CANCELLED")
            );
        } else {
            assert!(matches!(*delivery, EntryError::OutputInvalid));
        }
        assert_eq!(inspect(&root, &receipt), selected);
        let value = catalog_source_use_value(&selected, &receipt.project_revision, true);
        assert_eq!(value["stateDigest"], selected.state_digest().as_str());
        assert!(value.get("nativeOwner").is_none());
        assert!(value.get("policy").is_none());
        assert!(value.get("dataRoot").is_none());
    }
}

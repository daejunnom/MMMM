use super::*;

struct Fixture {
    root: PathBuf,
    checkout: PathBuf,
    config: StorageConfig,
}

impl Fixture {
    fn new(purpose: &str) -> Self {
        // The supervised test runner maps temp_dir to its owned scratch slot.
        let temp = fs::canonicalize(std::env::temp_dir()).expect("physical managed temp root");
        let root = temp.join(format!("mmmm-storage-test-{}", new_token()));
        fs::create_dir(&root).unwrap();
        let checkout = root.join("checkout");
        fs::create_dir(&checkout).unwrap();
        Self {
            checkout,
            config: StorageConfig {
                output_root: Some(root.join("output")),
                evidence_root: root.join("evidence"),
                purpose: purpose.into(),
                budgets: Budgets::default(),
            },
            root,
        }
    }
    fn acquire(&self) -> ManagedBuild {
        ManagedBuild::acquire(self.config.clone(), &self.checkout).unwrap()
    }
    fn catalog(&self) -> PathBuf {
        self.config
            .output_root
            .as_ref()
            .unwrap()
            .join("build/managed-v1")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // This root was newly created and solely owns authored test data.
        // Never remove an escaped root or a replaced junction.
        let parent = fs::canonicalize(std::env::temp_dir()).expect("temp root still resolves");
        if let Ok(resolved) = fs::canonicalize(&self.root)
            && resolved.parent() == Some(parent.as_path())
            && reject_link(&self.root).is_ok()
        {
            fs::remove_dir_all(&self.root).expect("remove owned test fixture");
        }
    }
}

fn outcome(exit: i32) -> FinishOutcome {
    FinishOutcome {
        command_exit: Some(exit),
        supervisor_errors: Vec::new(),
        drained: true,
        evidence_exported: true,
    }
}

fn error_kind<T>(result: Result<T, StorageError>) -> &'static str {
    match result {
        Err(error) => error.kind,
        Ok(_) => panic!("expected storage failure"),
    }
}

#[test]
fn successful_finish_removes_scratch_preserves_cache_and_command_failure() {
    let fixture = Fixture::new("test");
    let build = fixture.acquire();
    let paths = build.paths().clone();
    fs::write(paths.scratch.join("temporary"), b"scratch").unwrap();
    fs::write(paths.cargo_target.join("compiled"), b"cache").unwrap();
    let receipt = build.finish(outcome(23)).unwrap();
    assert_eq!(receipt.command_exit, Some(23));
    assert!(receipt.scratch_removed && receipt.lease_released);
    assert!(receipt.cleanup_errors.is_empty());
    assert!(!paths.scratch.exists());
    assert_eq!(
        fs::read(paths.cargo_target.join("compiled")).unwrap(),
        b"cache"
    );
    assert!(!paths.catalog.join("lease.json").exists());
    let persisted: serde_json::Value =
        serde_json::from_slice(&fs::read(paths.evidence.join("finish.json")).unwrap()).unwrap();
    assert_eq!(persisted["command_exit"], 23);
    assert_eq!(persisted["lease_released"], true);
    assert!(
        !persisted
            .to_string()
            .contains(&fixture.checkout.to_string_lossy().to_string())
    );
}

#[test]
fn fixed_slot_is_reused_without_timestamp_or_pid_directory_growth() {
    let fixture = Fixture::new("test");
    let first = fixture.acquire();
    let first_path = first.paths().slot.clone();
    fs::write(first.paths().cargo_target.join("compiled"), b"cache").unwrap();
    first.finish(outcome(0)).unwrap();
    let second = fixture.acquire();
    assert_eq!(second.paths().slot, first_path);
    assert_eq!(
        fs::read(second.paths().cargo_target.join("compiled")).unwrap(),
        b"cache"
    );
    assert_eq!(
        fs::read_dir(second.paths().catalog.join("slots"))
            .unwrap()
            .count(),
        1
    );
    second.finish(outcome(0)).unwrap();
}

#[test]
fn absent_drain_or_export_proof_preserves_exact_active_lease_and_files() {
    for (drained, evidence_exported, expected) in
        [(false, true, "undrained"), (true, false, "evidence")]
    {
        let fixture = Fixture::new("proof");
        let build = fixture.acquire();
        let paths = build.paths().clone();
        let before = fs::read(paths.catalog.join("lease.json")).unwrap();
        fs::write(paths.scratch.join("diagnostic"), b"preserve").unwrap();
        assert_eq!(
            error_kind(build.finish(FinishOutcome {
                command_exit: Some(9),
                supervisor_errors: vec!["failure".into()],
                drained,
                evidence_exported,
            })),
            expected
        );
        assert_eq!(fs::read(paths.catalog.join("lease.json")).unwrap(), before);
        assert_eq!(
            fs::read(paths.scratch.join("diagnostic")).unwrap(),
            b"preserve"
        );
    }
}

#[test]
fn disappeared_owner_process_does_not_authorize_busy_lease_adoption() {
    let fixture = Fixture::new("busy");
    let build = fixture.acquire();
    let paths = build.paths().clone();
    let mut interrupted = build.lease.clone();
    interrupted.pid = u32::MAX;
    fs::write(
        paths.catalog.join("lease.json"),
        record_bytes(&interrupted).unwrap(),
    )
    .unwrap();
    drop(build);
    let before = fs::read(paths.catalog.join("lease.json")).unwrap();
    assert_eq!(
        error_kind(ManagedBuild::acquire(
            fixture.config.clone(),
            &fixture.checkout
        )),
        "busy"
    );
    assert_eq!(fs::read(paths.catalog.join("lease.json")).unwrap(), before);
    assert!(paths.slot.join("owner.json").exists());
}

#[test]
fn changed_slot_or_catalog_token_blocks_cleanup() {
    for catalog_change in [false, true] {
        let fixture = Fixture::new("ownership");
        let build = fixture.acquire();
        let paths = build.paths().clone();
        fs::write(paths.scratch.join("keep"), b"original").unwrap();
        if catalog_change {
            let mut changed = build.catalog.clone();
            changed.catalog_id = new_token();
            fs::write(
                paths.catalog.join("catalog.json"),
                record_bytes(&changed).unwrap(),
            )
            .unwrap();
        } else {
            let mut changed = build.slot.clone();
            changed.token = new_token();
            fs::write(
                paths.slot.join("owner.json"),
                record_bytes(&changed).unwrap(),
            )
            .unwrap();
        }
        assert_eq!(error_kind(build.finish(outcome(0))), "ownership");
        assert_eq!(fs::read(paths.scratch.join("keep")).unwrap(), b"original");
        assert!(paths.catalog.join("lease.json").exists());
    }
}

#[test]
fn unknown_slot_data_is_not_renamed_registered_or_removed() {
    let fixture = Fixture::new("unknown");
    let build = fixture.acquire();
    let paths = build.paths().clone();
    let unknown = paths.slot.join("user-original");
    fs::write(&unknown, b"user").unwrap();
    assert_eq!(error_kind(build.finish(outcome(0))), "unknown");
    assert_eq!(fs::read(unknown).unwrap(), b"user");
    assert!(paths.catalog.join("lease.json").exists());
}

#[test]
fn existing_unowned_catalog_is_never_adopted() {
    let fixture = Fixture::new("unknown");
    let catalog = fixture.catalog();
    fs::create_dir_all(&catalog).unwrap();
    fs::write(catalog.join("user.sqlite"), b"database").unwrap();
    assert_eq!(
        error_kind(ManagedBuild::acquire(
            fixture.config.clone(),
            &fixture.checkout
        )),
        "unknown"
    );
    assert_eq!(fs::read(catalog.join("user.sqlite")).unwrap(), b"database");
    assert!(!catalog.join("catalog.json").exists());
}

#[test]
fn stale_active_slot_without_lease_is_preserved() {
    let fixture = Fixture::new("interrupted");
    let build = fixture.acquire();
    let paths = build.paths().clone();
    fs::write(paths.scratch.join("keep"), b"interrupted").unwrap();
    fs::remove_file(paths.catalog.join("lease.json")).unwrap();
    drop(build);
    assert_eq!(
        error_kind(ManagedBuild::acquire(
            fixture.config.clone(),
            &fixture.checkout
        )),
        "interrupted"
    );
    assert_eq!(
        fs::read(paths.scratch.join("keep")).unwrap(),
        b"interrupted"
    );
    assert!(paths.slot.join("owner.json").exists());
}

#[test]
fn completed_slot_with_unexplained_scratch_is_not_silently_reused() {
    let fixture = Fixture::new("residual");
    let build = fixture.acquire();
    let scratch = build.paths().scratch.clone();
    build.finish(outcome(0)).unwrap();
    fs::create_dir(&scratch).unwrap();
    fs::write(scratch.join("unexplained"), b"preserve").unwrap();
    assert_eq!(
        error_kind(ManagedBuild::acquire(
            fixture.config.clone(),
            &fixture.checkout
        )),
        "interrupted"
    );
    assert_eq!(fs::read(scratch.join("unexplained")).unwrap(), b"preserve");
}

#[test]
fn additional_active_slot_even_with_copied_token_is_preserved_and_blocks_finish() {
    let mut fixture = Fixture::new("completed");
    let completed = fixture.acquire();
    let previous = completed.paths().slot.clone();
    completed.finish(outcome(0)).unwrap();
    fixture.config.purpose = "active".into();
    let build = fixture.acquire();
    let mut changed: SlotRecord = read_record(&previous.join("owner.json")).unwrap();
    changed.state = SlotState::Active;
    changed.completed_ms = None;
    changed.token = build.lease.token.clone();
    changed.pid = build.lease.pid;
    fs::write(previous.join("owner.json"), record_bytes(&changed).unwrap()).unwrap();
    let scratch = build.paths().scratch.clone();
    fs::write(scratch.join("keep"), b"diagnostic").unwrap();
    assert_eq!(error_kind(build.measure()), "interrupted");
    assert_eq!(error_kind(build.finish(outcome(0))), "interrupted");
    assert!(previous.join("owner.json").exists());
    assert_eq!(fs::read(scratch.join("keep")).unwrap(), b"diagnostic");
    assert!(fixture.catalog().join("lease.json").exists());
}

#[test]
fn zero_completed_retention_evicts_only_owned_cache_after_successful_drain() {
    let mut fixture = Fixture::new("eviction");
    fixture.config.budgets.completed_slots = 0;
    let product = fixture
        .config
        .output_root
        .as_ref()
        .unwrap()
        .join("product-state");
    fs::create_dir_all(&product).unwrap();
    fs::write(product.join("state.sqlite"), b"persistent").unwrap();
    let build = fixture.acquire();
    let slot = build.paths().slot.clone();
    fs::write(build.paths().cargo_target.join("cache"), b"compiled").unwrap();
    let evidence = build.paths().evidence.clone();
    let receipt = build.finish(outcome(0)).unwrap();
    assert!(receipt.slot_evicted && receipt.lease_released);
    assert!(!slot.exists());
    assert_eq!(
        fs::read(product.join("state.sqlite")).unwrap(),
        b"persistent"
    );
    assert!(evidence.join("finish.json").exists());
}

#[test]
fn completed_count_eviction_keeps_newest_and_preserves_other_output_data() {
    let mut fixture = Fixture::new("first");
    fixture.config.budgets.completed_slots = 1;
    let first = fixture.acquire();
    let older_slot = first.paths().slot.clone();
    first.finish(outcome(0)).unwrap();
    fixture.config.purpose = "second".into();
    let second = fixture.acquire();
    let newer_slot = second.paths().slot.clone();
    let receipt = second.finish(outcome(0)).unwrap();
    assert!(!older_slot.exists());
    assert!(newer_slot.exists());
    assert_eq!(receipt.evicted_completed_slots.len(), 1);
    assert!(receipt.lease_released);
}

#[test]
fn size_measurement_detects_growth_and_completed_oversized_slot_is_evicted() {
    let mut fixture = Fixture::new("size");
    fixture.config.budgets.slot_bytes = 4096;
    fixture.config.budgets.catalog_bytes = 8192;
    let build = fixture.acquire();
    let paths = build.paths().clone();
    fs::write(paths.cargo_target.join("large"), vec![0u8; 8192]).unwrap();
    let measurement = build.measure().unwrap();
    assert!(!measurement.within_budget && measurement.slot_bytes >= 8192);
    let receipt = build.finish(outcome(4)).unwrap();
    assert_eq!(receipt.command_exit, Some(4));
    assert!(receipt.slot_evicted && receipt.lease_released);
    assert!(!paths.slot.exists());
}

#[test]
fn supervisor_parent_slot_and_cargo_hardlink_survive_admission_and_finish_eviction() {
    let mut fixture = Fixture::new("parent-image");
    let parent = fixture.acquire();
    let parent_paths = parent.paths().clone();
    let parent_id = parent.slot.slot_id.clone();
    let image = parent_paths.cargo_target.join("supervisor-image");
    fs::write(&image, b"actual fixture image").unwrap();
    // 기존 작은 regular-file fixture로 Cargo의 top-level/deps hardlink만 재현한다.
    let alias = fixture.root.join("image-alias");
    fs::hard_link(&image, &alias).unwrap();
    parent.finish(outcome(0)).unwrap();
    fixture.config.purpose = "other-cache".into();
    let other = fixture.acquire();
    let other_path = other.paths().slot.clone();
    other.finish(outcome(0)).unwrap();

    fixture.config.purpose = "candidate-image".into();
    fixture.config.budgets.completed_slots = 1;
    let build = ManagedBuild::acquire_with_image(
        fixture.config.clone(),
        &fixture.checkout,
        SupervisorImagePin::open(&image).unwrap(),
    )
    .unwrap();
    assert_eq!(
        build.supervisor_image.slot_id.as_deref(),
        Some(parent_id.as_str())
    );
    assert!(parent_paths.slot.is_dir());
    assert!(
        !other_path.exists(),
        "admission must reclaim the unprotected completed slot"
    );
    let candidate_path = build.paths().slot.clone();
    let receipt = build.finish(outcome(0)).unwrap();
    assert!(receipt.lease_released && receipt.slot_evicted);
    assert!(
        !candidate_path.exists(),
        "the protected parent still counts against completed retention"
    );
    assert!(parent_paths.slot.is_dir());
    assert_eq!(fs::read(&image).unwrap(), b"actual fixture image");
    assert_eq!(fs::read(alias).unwrap(), b"actual fixture image");
}

#[test]
fn supervisor_current_slot_is_preserved_and_unaffordable_limits_keep_the_lease() {
    for limit in [None, Some(false), Some(true)] {
        let fixture = Fixture::new("current-image");
        let first = fixture.acquire();
        let paths = first.paths().clone();
        let image = paths.cargo_target.join("supervisor-image");
        fs::write(&image, b"image").unwrap();
        first.finish(outcome(0)).unwrap();
        let mut build = ManagedBuild::acquire_with_image(
            fixture.config.clone(),
            &fixture.checkout,
            SupervisorImagePin::open(&image).unwrap(),
        )
        .unwrap();
        assert_eq!(
            build.supervisor_image.slot_id.as_deref(),
            Some(build.slot.slot_id.as_str())
        );
        if limit == Some(true) {
            build.config.budgets.slot_bytes = 4096;
            fs::write(paths.cargo_target.join("growth"), vec![0; 8192]).unwrap();
        } else if limit == Some(false) {
            build.config.budgets.completed_slots = 0;
        }
        let lease = fs::read(paths.catalog.join("lease.json")).unwrap();
        let receipt = build.finish(outcome(23)).unwrap();
        assert_eq!(receipt.command_exit, Some(23));
        assert!(receipt.scratch_removed && !receipt.slot_evicted);
        if limit.is_none() {
            assert!(receipt.lease_released && receipt.cleanup_errors.is_empty());
        } else {
            assert!(!receipt.lease_released);
            assert!(
                receipt
                    .cleanup_errors
                    .iter()
                    .any(|error| error.starts_with("eviction_blocked:"))
            );
            assert_eq!(fs::read(paths.catalog.join("lease.json")).unwrap(), lease);
        }
        assert_eq!(fs::read(image).unwrap(), b"image");
        assert!(paths.slot.join("owner.json").is_file());
    }
}

#[test]
fn protected_oversized_parent_blocks_admission_before_any_other_cache_is_removed() {
    let mut fixture = Fixture::new("large-parent");
    let parent = fixture.acquire();
    let image = parent.paths().cargo_target.join("supervisor-image");
    fs::write(&image, vec![0; 8192]).unwrap();
    parent.finish(outcome(0)).unwrap();
    fixture.config.purpose = "other-cache".into();
    let other = fixture.acquire();
    let other_path = other.paths().slot.clone();
    other.finish(outcome(0)).unwrap();
    let before = fs::read(other_path.join("owner.json")).unwrap();
    fixture.config.purpose = "blocked-candidate".into();
    fixture.config.budgets.slot_bytes = 4096;
    assert_eq!(
        error_kind(ManagedBuild::acquire_with_image(
            fixture.config.clone(),
            &fixture.checkout,
            SupervisorImagePin::open(&image).unwrap(),
        )),
        "eviction_blocked"
    );
    assert_eq!(fs::read(other_path.join("owner.json")).unwrap(), before);
    assert_eq!(fs::metadata(image).unwrap().len(), 8192);
    assert!(fixture.catalog().join("lease.json").is_file());

    let mut aggregate = Fixture::new("aggregate-parent");
    let parent = aggregate.acquire();
    let parent_id = parent.slot.slot_id.clone();
    let image = parent.paths().cargo_target.join("supervisor-image");
    fs::write(&image, b"parent image").unwrap();
    parent.finish(outcome(0)).unwrap();
    aggregate.config.purpose = "reclaimable".into();
    let other = aggregate.acquire();
    let other_path = other.paths().slot.clone();
    other.finish(outcome(0)).unwrap();
    aggregate.config.purpose = "active-child".into();
    let mut active = ManagedBuild::acquire_with_image(
        aggregate.config.clone(),
        &aggregate.checkout,
        SupervisorImagePin::open(&image).unwrap(),
    )
    .unwrap();
    let parent_size = tree_bytes(
        &active.paths().catalog.join("slots").join(parent_id),
        &active.paths().catalog,
    )
    .unwrap();
    let active_size = tree_bytes(&active.paths().slot, &active.paths().catalog).unwrap();
    active.config.budgets.slot_bytes = parent_size.max(active_size);
    active.config.budgets.catalog_bytes = parent_size + active_size - 1;
    assert_eq!(error_kind(active.evict_completed(true)), "eviction_blocked");
    assert!(
        other_path.join("owner.json").is_file(),
        "a doomed aggregate plan must delete no eligible cache"
    );
    assert!(active.paths().catalog.join("lease.json").is_file());
}

#[test]
fn external_supervisor_image_does_not_exempt_a_cache_from_existing_eviction() {
    let mut fixture = Fixture::new("external-image");
    let image = fixture.root.join("external-supervisor");
    fs::write(&image, b"outside catalog").unwrap();
    fixture.config.budgets.completed_slots = 0;
    let build = ManagedBuild::acquire_with_image(
        fixture.config.clone(),
        &fixture.checkout,
        SupervisorImagePin::open(&image).unwrap(),
    )
    .unwrap();
    assert!(build.supervisor_image.slot_id.is_none());
    let slot = build.paths().slot.clone();
    let receipt = build.finish(outcome(0)).unwrap();
    assert!(receipt.lease_released && receipt.slot_evicted);
    assert!(!slot.exists());
    assert_eq!(fs::read(image).unwrap(), b"outside catalog");
}

#[test]
fn unknown_or_scratch_supervisor_image_is_rejected_without_unprotected_fallback() {
    let mut fixture = Fixture::new("image-boundary");
    assert_eq!(
        error_kind(SupervisorImagePin::open(
            &fixture.root.join("missing-image")
        )),
        "io"
    );
    let original = fixture.acquire();
    let paths = original.paths().clone();
    original.finish(outcome(0)).unwrap();
    fs::create_dir(&paths.scratch).unwrap();
    let scratch_image = paths.scratch.join("supervisor-image");
    fs::write(&scratch_image, b"scratch image").unwrap();
    fixture.config.purpose = "rejected-image".into();
    assert_eq!(
        error_kind(ManagedBuild::acquire_with_image(
            fixture.config.clone(),
            &fixture.checkout,
            SupervisorImagePin::open(&scratch_image).unwrap(),
        )),
        "supervisor_image"
    );
    assert!(!fixture.catalog().join("lease.json").exists());
    assert_eq!(fs::read(scratch_image).unwrap(), b"scratch image");

    let source = fixture.root.join("image-directory");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("image"), b"source image").unwrap();
    let link = fixture.root.join("image-directory-link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&source, &link).unwrap();
    #[cfg(windows)]
    create_junction(&link, &source);
    #[cfg(any(unix, windows))]
    {
        assert_eq!(
            error_kind(SupervisorImagePin::open(&link.join("image"))),
            "link"
        );
        #[cfg(unix)]
        fs::remove_file(link).unwrap();
        #[cfg(windows)]
        fs::remove_dir(link).unwrap();
    }
}

#[test]
fn supervisor_path_replacement_cannot_fall_back_to_unprotected_eviction() {
    let fixture = Fixture::new("image-currentness");
    let image = fixture.root.join("external-supervisor");
    fs::write(&image, b"original image").unwrap();
    let build = ManagedBuild::acquire_with_image(
        fixture.config.clone(),
        &fixture.checkout,
        SupervisorImagePin::open(&image).unwrap(),
    )
    .unwrap();
    let paths = build.paths().clone();
    fs::write(paths.scratch.join("diagnostic"), b"must remain").unwrap();
    let moved = fixture.root.join("moved-image");
    #[cfg(unix)]
    {
        fs::rename(&image, &moved).unwrap();
        fs::write(&image, b"replacement image").unwrap();
        assert_eq!(error_kind(build.finish(outcome(23))), "supervisor_image");
        assert_eq!(
            fs::read(paths.scratch.join("diagnostic")).unwrap(),
            b"must remain"
        );
        assert!(paths.catalog.join("lease.json").is_file());
    }
    #[cfg(windows)]
    {
        assert!(
            fs::rename(&image, &moved).is_err(),
            "held image denies delete sharing"
        );
        assert!(
            OpenOptions::new().write(true).open(&image).is_err(),
            "held image denies write sharing"
        );
        assert!(build.finish(outcome(23)).unwrap().lease_released);
    }
}

#[test]
fn checkout_and_evidence_overlap_is_rejected_before_creation() {
    let mut fixture = Fixture::new("overlap");
    fixture.config.output_root = Some(fixture.checkout.join("generated"));
    assert_eq!(
        error_kind(ManagedBuild::acquire(
            fixture.config.clone(),
            &fixture.checkout
        )),
        "overlap"
    );
    assert!(!fixture.checkout.join("generated").exists());
    fixture.config.output_root = Some(fixture.root.join("output"));
    fixture.config.evidence_root = fixture.checkout.join("reports");
    assert_eq!(
        error_kind(ManagedBuild::acquire(
            fixture.config.clone(),
            &fixture.checkout
        )),
        "overlap"
    );
    assert!(!fixture.checkout.join("reports").exists());
}

#[test]
fn secret_named_selected_tree_is_rejected_before_metadata_or_removal() {
    let fixture = Fixture::new("names");
    let build = fixture.acquire();
    let scratch = build.paths().scratch.clone();
    // This is a lexical selector only. Creating a rejected directory inside a
    // supervised scratch tree races the outer observer and can strand its lease.
    // No protected file or directory is created, probed, opened or removed.
    let selected = scratch.join(".env.test");
    let mut metadata_reached = false;
    assert_eq!(
        error_kind(tree_bytes_observed(&selected, &scratch, &[], |_| {
            metadata_reached = true;
        })),
        "secret_path"
    );
    assert!(!metadata_reached);
    assert_eq!(
        error_kind(remove_tree(
            &selected,
            &scratch,
            &build.paths().slot.join("owner.json"),
            &[],
            &|| panic!("secret selector must be rejected before lease or filesystem access"),
        )),
        "secret_path"
    );
    build.finish(outcome(0)).unwrap();
}

#[test]
fn public_api_source_namespace_is_not_misclassified_as_a_credential_file() {
    let fixture = Fixture::new("source-names");
    let build = fixture.acquire();
    let namespace = build
        .paths()
        .cargo_home
        .join("registry/source/Security/Credentials");
    fs::create_dir_all(&namespace).unwrap();
    fs::write(namespace.join("mod.rs"), b"pub struct PublicApi;").unwrap();
    assert!(build.measure().unwrap().within_budget);
    assert!(
        build
            .measure_with_progress_and_diagnostics(
                &mut || Ok(()),
                &mut ObservationRetryLog::default()
            )
            .unwrap()
            .within_budget
    );
    let receipt = build.finish(outcome(0)).unwrap();
    assert!(receipt.lease_released);
}

// Actual owned roots/files retain the production ownership and ancestry
// checks. Only the selected metadata call and retry clock/wait are injected;
// no scheduler timing, ACL relaxation or secret fixture is required.
fn retry_measurement(
    build: &ManagedBuild,
    diagnostics: &mut ObservationRetryLog,
    metadata: &mut dyn FnMut(&Path) -> std::io::Result<fs::Metadata>,
    wait: &mut dyn FnMut(Duration),
    progress: &mut dyn FnMut() -> Result<(), String>,
) -> Result<Measurement, StorageError> {
    let owner = || build.verify_ownership();
    let now = Instant::now();
    let clock = || now;
    let mut retry = MetadataReobservation::new(diagnostics, &owner, metadata, wait, true, &clock);
    build.measure_observed_retry(|_| {}, progress, Some(&mut retry))
}

#[test]
fn running_metadata_recovery_retains_first_native_error_and_verified_present_or_missing() {
    use std::cell::Cell;
    for remove in [false, true] {
        let fixture = Fixture::new("metadata-recovery");
        let build = fixture.acquire();
        let leaf = build.paths().cargo_target.join("transient-output");
        fs::write(&leaf, b"bounded output").unwrap();
        let calls = Cell::new(0);
        let mut metadata = |path: &Path| {
            if path == leaf {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    return Err(std::io::Error::from_raw_os_error(5));
                }
            }
            fs::symlink_metadata(path)
        };
        let mut delays = Vec::new();
        let mut wait = |delay| {
            delays.push(delay);
            if remove {
                fs::remove_file(&leaf).unwrap();
            }
        };
        let mut diagnostics = ObservationRetryLog::default();
        assert!(
            retry_measurement(
                &build,
                &mut diagnostics,
                &mut metadata,
                &mut wait,
                &mut || Ok(())
            )
            .unwrap()
            .within_budget
        );
        assert_eq!(calls.get(), 2);
        assert_eq!(delays, [Duration::from_millis(2)]);
        let record = &diagnostics.records[0];
        assert_eq!(record.first.raw_os_error, Some(5));
        assert_eq!(record.attempts, 2);
        assert!(
            !record
                .generated_relative
                .contains(fixture.root.to_string_lossy().as_ref())
        );
        if remove {
            assert!(matches!(
                record.final_observation,
                RetryFinalObservation::MissingValidated { .. }
            ));
        } else {
            assert!(matches!(
                record.final_observation,
                RetryFinalObservation::Present {
                    byte_length: 14,
                    ..
                }
            ));
        }
        build.finish(outcome(0)).unwrap();
    }
}

#[test]
fn vanished_ancestry_recovery_remeasures_present_target_and_proves_missing() {
    use std::cell::Cell;
    for remove in [false, true] {
        let fixture = Fixture::new("vanished-ancestry-recovery");
        let build = fixture.acquire();
        let nested = build.paths().cargo_target.join("nested");
        let leaf = nested.join("transient-output");
        fs::create_dir(&nested).unwrap();
        fs::write(&leaf, b"old").unwrap();
        let triggered = Cell::new(false);
        let component_calls = Cell::new(0);
        let mut metadata = |path: &Path| {
            if path == leaf && !triggered.replace(true) {
                return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
            }
            if path == nested && triggered.get() {
                component_calls.set(component_calls.get() + 1);
                if component_calls.get() == 1 {
                    return Err(std::io::Error::from_raw_os_error(5));
                }
            }
            fs::symlink_metadata(path)
        };
        let mut delays = Vec::new();
        let mut wait = |delay| {
            delays.push(delay);
            if remove {
                fs::remove_file(&leaf).unwrap();
                fs::remove_dir(&nested).unwrap();
            } else {
                fs::write(&leaf, b"the present target has a new actual byte length").unwrap();
            }
        };
        let mut diagnostics = ObservationRetryLog::default();
        let measured = retry_measurement(
            &build,
            &mut diagnostics,
            &mut metadata,
            &mut wait,
            &mut || Ok(()),
        )
        .unwrap();
        assert_eq!(measured.slot_bytes, build.measure().unwrap().slot_bytes);
        assert_eq!(delays, [Duration::from_millis(2)]);
        assert_eq!(component_calls.get(), 2);
        assert_eq!(diagnostics.records.len(), 1);
        let record = &diagnostics.records[0];
        assert_eq!(record.stage, "vanished_ancestry_metadata");
        assert_eq!(record.first.raw_os_error, Some(5));
        assert_eq!(record.attempts, 2);
        assert!(record.generated_relative.ends_with("nested"));
        let trigger = record.not_found_trigger.as_ref().unwrap();
        assert_eq!(trigger.stage, "entry_metadata");
        assert_eq!(trigger.first.kind, "NotFound");
        assert!(trigger.generated_relative.ends_with("transient-output"));
        let encoded = String::from_utf8(diagnostics.encoded_evidence().unwrap()).unwrap();
        assert!(!encoded.contains(fixture.root.to_string_lossy().as_ref()));
        if remove {
            assert!(matches!(
                record.final_observation,
                RetryFinalObservation::MissingValidated { .. }
            ));
        } else {
            assert!(matches!(
                record.final_observation,
                RetryFinalObservation::Present {
                    file_type: "directory",
                    ..
                }
            ));
        }
        build.finish(outcome(0)).unwrap();
    }
}

#[test]
fn vanished_ancestry_denial_preserves_trigger_component_and_final_native_error() {
    use std::cell::Cell;
    for last in [5, 32] {
        let fixture = Fixture::new("vanished-ancestry-denial");
        let build = fixture.acquire();
        let nested = build.paths().scratch.join("nested");
        let leaf = nested.join("ordinary-output");
        fs::create_dir(&nested).unwrap();
        fs::write(&leaf, b"unchanged").unwrap();
        let triggered = Cell::new(false);
        let component_calls = Cell::new(0);
        let mut metadata = |path: &Path| {
            if path == leaf && !triggered.replace(true) {
                return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
            }
            if path == nested && triggered.get() {
                component_calls.set(component_calls.get() + 1);
                return Err(std::io::Error::from_raw_os_error(
                    if component_calls.get() == 1 { 5 } else { last },
                ));
            }
            fs::symlink_metadata(path)
        };
        let mut delays = Vec::new();
        let mut diagnostics = ObservationRetryLog::default();
        let error = retry_measurement(
            &build,
            &mut diagnostics,
            &mut metadata,
            &mut |delay| delays.push(delay),
            &mut || Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.kind, "io");
        assert!(error.message.contains("first_raw_os_error=Some(5)"));
        assert!(
            error
                .message
                .contains(&format!("final_raw_os_error=Some({last})"))
        );
        assert!(error.message.contains("not_found_kind=NotFound"));
        assert!(std::error::Error::source(&error).is_some());
        assert_eq!(component_calls.get(), if last == 5 { 3 } else { 2 });
        assert_eq!(delays.len(), component_calls.get() - 1);
        assert_eq!(
            diagnostics.records[0]
                .not_found_trigger
                .as_ref()
                .unwrap()
                .first
                .kind,
            "NotFound"
        );
        assert_eq!(fs::read(&leaf).unwrap(), b"unchanged");
        build.finish(outcome(0)).unwrap();
    }
}

#[test]
fn vanished_ancestry_recovery_cannot_reset_the_running_retry_budget() {
    use std::cell::Cell;
    let fixture = Fixture::new("vanished-shared-budget");
    let build = fixture.acquire();
    let direct = build.paths().scratch.join("direct-output");
    let nested = build.paths().scratch.join("nested");
    let leaf = nested.join("ordinary-output");
    fs::create_dir(&nested).unwrap();
    fs::write(&direct, b"direct").unwrap();
    fs::write(&leaf, b"nested").unwrap();
    let deny_direct = Cell::new(false);
    let missing_target = Cell::new(false);
    let deny_component = Cell::new(false);
    let mut metadata = |path: &Path| {
        if path == direct && deny_direct.replace(false) {
            return Err(std::io::Error::from_raw_os_error(5));
        }
        if path == leaf && missing_target.replace(false) {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        }
        if path == nested && deny_component.replace(false) {
            return Err(std::io::Error::from_raw_os_error(5));
        }
        fs::symlink_metadata(path)
    };
    let owner = || build.verify_ownership();
    let now = Instant::now();
    let clock = || now;
    let mut diagnostics = ObservationRetryLog::default();
    let mut delays = Vec::new();
    let mut wait = |delay| delays.push(delay);
    let mut retry = MetadataReobservation::new(
        &mut diagnostics,
        &owner,
        &mut metadata,
        &mut wait,
        true,
        &clock,
    );
    for _ in 0..MAX_EXTRA_METADATA_CALLS {
        deny_direct.set(true);
        assert!(
            retry
                .observe(
                    &direct,
                    &build.paths().slot,
                    &build.observation_roots(),
                    &mut || Ok(())
                )
                .unwrap()
                .is_some()
        );
    }
    missing_target.set(true);
    deny_component.set(true);
    let error = retry
        .observe(
            &leaf,
            &build.paths().slot,
            &build.observation_roots(),
            &mut || Ok(()),
        )
        .unwrap_err();
    assert_eq!(error.kind, "retry_budget");
    assert_eq!(retry.extra_calls, MAX_EXTRA_METADATA_CALLS);
    assert_eq!(retry.planned_wait, MAX_RETRY_WAIT);
    assert_eq!(delays.len(), MAX_EXTRA_METADATA_CALLS);
    assert_eq!(diagnostics.records.len(), MAX_EXTRA_METADATA_CALLS + 1);
    let last = diagnostics.records.last().unwrap();
    assert_eq!(last.attempts, 1);
    assert!(last.not_found_trigger.is_some());
    assert!(matches!(
        last.final_observation,
        RetryFinalObservation::Failed {
            category: "retry_budget",
            ..
        }
    ));
    build.finish(outcome(0)).unwrap();
}

#[test]
fn repeated_native5_and_other_errno_remain_fatal_with_first_and_final_codes() {
    use std::cell::Cell;
    for last in [5, 32] {
        let fixture = Fixture::new("metadata-denial");
        let build = fixture.acquire();
        let leaf = build.paths().scratch.join("transient-output");
        fs::write(&leaf, b"unchanged").unwrap();
        let calls = Cell::new(0);
        let mut metadata = |path: &Path| {
            if path == leaf {
                calls.set(calls.get() + 1);
                return Err(std::io::Error::from_raw_os_error(if calls.get() == 1 {
                    5
                } else {
                    last
                }));
            }
            fs::symlink_metadata(path)
        };
        let mut delays = Vec::new();
        let mut diagnostics = ObservationRetryLog::default();
        let error = retry_measurement(
            &build,
            &mut diagnostics,
            &mut metadata,
            &mut |delay| delays.push(delay),
            &mut || Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.kind, "io");
        assert!(error.message.contains("first_raw_os_error=Some(5)"));
        assert!(
            error
                .message
                .contains(&format!("final_raw_os_error=Some({last})"))
        );
        assert_eq!(calls.get(), if last == 5 { 3 } else { 2 });
        assert_eq!(delays.len(), calls.get() - 1);
        assert!(std::error::Error::source(&error).is_some());
        assert_eq!(fs::read(&leaf).unwrap(), b"unchanged");
        build.finish(outcome(0)).unwrap();
    }
}

#[test]
fn retry_wait_checkpoint_failure_keeps_original_native5_and_original_cause() {
    use std::cell::Cell;
    for missing_trigger in [false, true] {
        let fixture = Fixture::new("metadata-cancel");
        let build = fixture.acquire();
        let nested = build.paths().scratch.join("nested");
        fs::create_dir(&nested).unwrap();
        let leaf = nested.join("transient-output");
        fs::write(&leaf, b"unchanged").unwrap();
        let stopped = Cell::new(false);
        let calls = Cell::new(0);
        let mut metadata = |path: &Path| {
            if path == leaf {
                calls.set(calls.get() + 1);
                return Err(if missing_trigger {
                    std::io::Error::from(std::io::ErrorKind::NotFound)
                } else {
                    std::io::Error::from_raw_os_error(5)
                });
            }
            if missing_trigger && path == nested && calls.get() != 0 {
                return Err(std::io::Error::from_raw_os_error(5));
            }
            fs::symlink_metadata(path)
        };
        let mut diagnostics = ObservationRetryLog::default();
        let error = retry_measurement(
            &build,
            &mut diagnostics,
            &mut metadata,
            &mut |_| stopped.set(true),
            &mut || {
                if stopped.get() {
                    Err("original managed deadline expired".into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert_eq!(calls.get(), 1);
        assert_eq!(error.kind, "observation_failed");
        assert!(error.message.contains("first_raw_os_error=Some(5)"));
        assert_eq!(
            diagnostics.records[0].not_found_trigger.is_some(),
            missing_trigger
        );
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            "observation_failed: original managed deadline expired"
        );
        assert!(matches!(
            diagnostics.records[0].final_observation,
            RetryFinalObservation::Failed {
                category: "observation_failed",
                ..
            }
        ));
        build.finish(outcome(0)).unwrap();
    }
}

#[test]
fn retry_global_call_wait_wall_and_record_budgets_fail_without_unbounded_work() {
    use std::cell::Cell;
    for two_retries in [false, true] {
        let fixture = Fixture::new("metadata-budget");
        let build = fixture.acquire();
        let leaf = build.paths().scratch.join("transient-output");
        fs::write(&leaf, b"owned").unwrap();
        let calls = Cell::new(0usize);
        let period = if two_retries { 3 } else { 2 };
        let mut metadata = |path: &Path| {
            calls.set(calls.get() + 1);
            if calls.get().is_multiple_of(period) {
                fs::symlink_metadata(path)
            } else {
                Err(std::io::Error::from_raw_os_error(5))
            }
        };
        let owner = || build.verify_ownership();
        let now = Instant::now();
        let clock = || now;
        let mut wait = |_| {};
        let mut diagnostics = ObservationRetryLog::default();
        let mut retry = MetadataReobservation::new(
            &mut diagnostics,
            &owner,
            &mut metadata,
            &mut wait,
            true,
            &clock,
        );
        let mut failure = None;
        for _ in 0..18 {
            if let Err(error) = retry.observe(
                &leaf,
                &build.paths().slot,
                &build.observation_roots(),
                &mut || Ok(()),
            ) {
                failure = Some(error);
                break;
            }
        }
        assert_eq!(failure.unwrap().kind, "retry_budget");
        assert_eq!(retry.planned_wait, MAX_RETRY_WAIT);
        assert!(retry.extra_calls <= MAX_EXTRA_METADATA_CALLS);
        if !two_retries {
            assert_eq!(retry.extra_calls, MAX_EXTRA_METADATA_CALLS);
        }
        let record = diagnostics.records[0].clone();
        let mut byte_limited = ObservationRetryLog::default();
        let mut oversized = record.clone();
        oversized.generated_relative = "x".repeat(MAX_RETRY_LOG_BYTES);
        assert!(byte_limited.retain(oversized).is_err());
        assert!(byte_limited.records.is_empty());
        while diagnostics.records.len() < MAX_RETRY_RECORDS {
            diagnostics.retain(record.clone()).unwrap();
        }
        let before = diagnostics.evidence().unwrap();
        assert!(diagnostics.retain(record).is_err());
        assert_eq!(diagnostics.evidence().unwrap(), before);
        calls.set(0);
        let mut retry = MetadataReobservation::new(
            &mut diagnostics,
            &owner,
            &mut metadata,
            &mut wait,
            true,
            &clock,
        );
        let error = retry
            .observe(
                &leaf,
                &build.paths().slot,
                &build.observation_roots(),
                &mut || Ok(()),
            )
            .unwrap_err();
        assert_eq!(error.kind, "retry_evidence");
        assert_eq!(retry.extra_calls, 0);
        assert_eq!(diagnostics.records.len(), MAX_RETRY_RECORDS);
        build.finish(outcome(0)).unwrap();
    }
    let fixture = Fixture::new("metadata-wall");
    let build = fixture.acquire();
    let leaf = build.paths().scratch.join("transient-output");
    fs::write(&leaf, b"owned").unwrap();
    let now = Cell::new(Instant::now());
    let clock = || now.get();
    let owner = || build.verify_ownership();
    let mut metadata = |_: &Path| Err(std::io::Error::from_raw_os_error(5));
    let mut wait = |_| now.set(now.get() + MAX_RETRY_WALL);
    let mut diagnostics = ObservationRetryLog::default();
    let mut retry = MetadataReobservation::new(
        &mut diagnostics,
        &owner,
        &mut metadata,
        &mut wait,
        true,
        &clock,
    );
    let error = retry
        .observe(
            &leaf,
            &build.paths().slot,
            &build.observation_roots(),
            &mut || Ok(()),
        )
        .unwrap_err();
    assert_eq!(error.kind, "retry_budget");
    assert_eq!(retry.extra_calls, 0);
    build.finish(outcome(0)).unwrap();
}

#[test]
fn retry_refuses_fixed_foreign_disabled_and_secret_selectors() {
    use std::cell::Cell;
    let fixture = Fixture::new("metadata-selector");
    let build = fixture.acquire();
    let owner = || build.verify_ownership();
    let calls = Cell::new(0);
    let mut metadata = |_: &Path| {
        calls.set(calls.get() + 1);
        Err(std::io::Error::from_raw_os_error(5))
    };
    let now = Instant::now();
    let clock = || now;
    let mut wait = |_| panic!("non-admitted selector must not wait or retry");
    let mut diagnostics = ObservationRetryLog::default();
    for path in [
        build.paths().scratch.clone(),
        build.paths().slot.join("owner.json"),
        fixture.checkout.join("ordinary-original"),
    ] {
        let mut retry = MetadataReobservation::new(
            &mut diagnostics,
            &owner,
            &mut metadata,
            &mut wait,
            true,
            &clock,
        );
        assert!(
            retry
                .observe(
                    &path,
                    &build.paths().slot,
                    &build.observation_roots(),
                    &mut || Ok(())
                )
                .is_err()
        );
        assert_eq!(retry.extra_calls, 0);
    }
    let leaf = build.paths().scratch.join("ordinary-output");
    let mut disabled = MetadataReobservation::new(
        &mut diagnostics,
        &owner,
        &mut metadata,
        &mut wait,
        false,
        &clock,
    );
    assert!(
        disabled
            .observe(
                &leaf,
                &build.paths().slot,
                &build.observation_roots(),
                &mut || Ok(())
            )
            .is_err()
    );
    let before = calls.get();
    // Pure selectors only: never create, probe, hash or remove secret paths.
    for name in [
        ".env",
        ".env.test",
        "service-account.json",
        "api-key.json",
        ".ssh/id_rsa",
    ] {
        let selected = build.paths().scratch.join(name);
        let mut retry = MetadataReobservation::new(
            &mut diagnostics,
            &owner,
            &mut metadata,
            &mut wait,
            true,
            &clock,
        );
        assert_eq!(
            error_kind(retry.observe(
                &selected,
                &build.paths().slot,
                &build.observation_roots(),
                &mut || Ok(())
            )),
            "secret_path"
        );
    }
    assert_eq!(calls.get(), before);
    assert!(diagnostics.records.is_empty());
    build.finish(outcome(0)).unwrap();
}

#[test]
fn retry_rechecks_owner_and_rejects_parent_link_before_another_target_lookup() {
    use std::cell::Cell;
    for missing_trigger in [false, true] {
        for (owner_removed, owner_replaced) in [(false, false), (true, false), (false, true)] {
            let fixture = Fixture::new("metadata-boundary");
            let build = fixture.acquire();
            let nested = build.paths().scratch.join("nested");
            let moved = build.paths().scratch.join("original-nested");
            fs::create_dir(&nested).unwrap();
            let leaf = nested.join("ordinary-output");
            fs::write(&leaf, b"owned original").unwrap();
            let outside = fixture.root.join("outside-original");
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("keep"), b"unchanged outside").unwrap();
            let calls = Cell::new(0);
            let component_calls = Cell::new(0);
            let mut metadata = |path: &Path| {
                if path == leaf {
                    calls.set(calls.get() + 1);
                    return Err(if missing_trigger {
                        std::io::Error::from(std::io::ErrorKind::NotFound)
                    } else {
                        std::io::Error::from_raw_os_error(5)
                    });
                }
                if missing_trigger && path == nested && calls.get() != 0 {
                    component_calls.set(component_calls.get() + 1);
                    if component_calls.get() == 1 {
                        return Err(std::io::Error::from_raw_os_error(5));
                    }
                }
                fs::symlink_metadata(path)
            };
            let mut wait = |_| {
                if owner_removed {
                    fs::remove_file(build.paths().slot.join("owner.json")).unwrap();
                } else if owner_replaced {
                    fs::write(build.paths().slot.join("owner.json"), b"changed owner").unwrap();
                } else {
                    fs::rename(&nested, &moved).unwrap();
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(&outside, &nested).unwrap();
                    #[cfg(windows)]
                    create_junction(&nested, &outside);
                }
            };
            let mut diagnostics = ObservationRetryLog::default();
            let error = retry_measurement(
                &build,
                &mut diagnostics,
                &mut metadata,
                &mut wait,
                &mut || Ok(()),
            )
            .unwrap_err();
            assert_eq!(calls.get(), 1);
            assert_eq!(
                error.kind,
                if owner_removed {
                    "io"
                } else if owner_replaced {
                    "ownership"
                } else if missing_trigger {
                    "file_type"
                } else {
                    "link"
                }
            );
            assert!(error.message.contains("first_raw_os_error=Some(5)"));
            assert_eq!(
                diagnostics.records[0].not_found_trigger.is_some(),
                missing_trigger
            );
            assert_eq!(
                fs::read(outside.join("keep")).unwrap(),
                b"unchanged outside"
            );
            assert!(build.paths().catalog.join("lease.json").exists());
            if !owner_removed && !owner_replaced {
                #[cfg(windows)]
                fs::remove_dir(&nested).unwrap();
                #[cfg(unix)]
                fs::remove_file(&nested).unwrap();
                build.finish(outcome(0)).unwrap();
            }
        }
    }
}

#[test]
fn retry_rejects_reparse_leaf_even_after_a_successful_metadata_call() {
    use std::cell::Cell;
    let fixture = Fixture::new("metadata-leaf-type");
    let build = fixture.acquire();
    let leaf = build.paths().scratch.join("ordinary-output");
    let moved = build.paths().scratch.join("original-output");
    let outside = fixture.root.join("outside-directory");
    fs::create_dir(&outside).unwrap();
    fs::write(&leaf, b"owned original").unwrap();
    let calls = Cell::new(0);
    let mut metadata = |path: &Path| {
        if path == leaf {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                return Err(std::io::Error::from_raw_os_error(5));
            }
        }
        fs::symlink_metadata(path)
    };
    let mut wait = |_| {
        fs::rename(&leaf, &moved).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &leaf).unwrap();
        #[cfg(windows)]
        create_junction(&leaf, &outside);
    };
    let mut diagnostics = ObservationRetryLog::default();
    let error = retry_measurement(
        &build,
        &mut diagnostics,
        &mut metadata,
        &mut wait,
        &mut || Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.kind, "file_type");
    assert_eq!(calls.get(), 2);
    assert!(error.message.contains("first_raw_os_error=Some(5)"));
    assert_eq!(fs::read(&moved).unwrap(), b"owned original");
    #[cfg(windows)]
    fs::remove_dir(&leaf).unwrap();
    #[cfg(unix)]
    fs::remove_file(&leaf).unwrap();
    build.finish(outcome(0)).unwrap();
}

#[test]
fn bounded_walk_rejects_overdeep_tree_without_removing_it() {
    let fixture = Fixture::new("depth");
    let build = fixture.acquire();
    let paths = build.paths().clone();
    let owner = paths.slot.join("owner.json");
    let lease = paths.catalog.join("lease.json");
    let owner_before = fs::read(&owner).unwrap();
    let lease_before = fs::read(&lease).unwrap();
    let sentinel = paths.scratch.join("preserve");
    let sentinel_bytes = b"owned depth sentinel";
    fs::write(&sentinel, sentinel_bytes).unwrap();
    let limits = WalkLimits {
        max_depth: 4,
        ..MANAGED_WALK_LIMITS
    };
    assert_eq!(MANAGED_WALK_LIMITS.max_depth, 64);
    assert_eq!(MANAGED_WALK_LIMITS.max_entries, 100_000);
    let mut deepest = paths.scratch.clone();
    for _ in 0..limits.max_depth {
        deepest.push("d");
        fs::create_dir(&deepest).unwrap();
    }
    let metadata_calls = std::cell::Cell::new(0usize);
    let measure_with_limits = |walk_limits| {
        metadata_calls.set(0);
        tree_bytes_observed_with_retry_and_limits(
            &paths.scratch,
            &paths.scratch,
            &[],
            |_| metadata_calls.set(metadata_calls.get() + 1),
            &mut || Ok(()),
            None,
            walk_limits,
        )
    };
    assert_eq!(
        measure_with_limits(limits).unwrap(),
        sentinel_bytes.len() as u64
    );
    deepest.push("d");
    fs::create_dir(&deepest).unwrap();
    let depth_error = measure_with_limits(limits).unwrap_err();
    let walk_pops = metadata_calls.get() + 1;
    let total_authored_entries = limits.max_depth + 3; // root, sentinel and five directories
    assert!((total_authored_entries - 1..=total_authored_entries).contains(&walk_pops));
    assert!(depth_error.message.contains(&format!(
        "reason=depth; depth=5; walk_pops={walk_pops}; pending_count={}; max_depth=4; max_entries=100000; generated_relative=d",
        total_authored_entries - walk_pops,
    )));
    let visited_error = measure_with_limits(WalkLimits {
        max_entries: 0,
        ..limits
    })
    .unwrap_err();
    assert_eq!(metadata_calls.get(), 0);
    assert!(visited_error.message.contains(
        "reason=visited_entries; depth=0; walk_pops=1; pending_count=0; max_depth=4; max_entries=0; generated_relative=."
    ));
    let queued_error = measure_with_limits(WalkLimits {
        max_entries: 2,
        ..limits
    })
    .unwrap_err();
    assert_eq!(metadata_calls.get(), 1);
    assert!(queued_error.message.contains(
        "reason=queued_entries; depth=0; walk_pops=1; pending_count=1; max_depth=4; max_entries=2; generated_relative=."
    ));
    for error in [&depth_error, &visited_error, &queued_error] {
        assert_eq!(error.kind, "walk_limit");
        assert!(error.message.len() <= 512);
        assert!(
            !error
                .message
                .contains(fixture.root.to_string_lossy().as_ref())
        );
    }
    assert!(deepest.is_dir());
    assert_eq!(fs::read(&sentinel).unwrap(), sentinel_bytes);
    assert!(build.measure().unwrap().within_budget);
    assert_eq!(fs::read(&owner).unwrap(), owner_before);
    assert_eq!(fs::read(&lease).unwrap(), lease_before);
    let receipt = build.finish(outcome(0)).unwrap();
    assert!(receipt.scratch_removed && receipt.lease_released);
    assert!(receipt.cleanup_errors.is_empty());
}

#[test]
fn ownership_record_length_limit_is_checked_before_reading() {
    let fixture = Fixture::new("record");
    let build = fixture.acquire();
    let owner = build.paths().slot.join("owner.json");
    fs::write(&owner, vec![b' '; RECORD_LIMIT as usize + 1]).unwrap();
    assert_eq!(error_kind(build.measure()), "record");
    assert_eq!(fs::metadata(owner).unwrap().len(), RECORD_LIMIT + 1);
}

#[test]
fn multiply_linked_owner_record_is_not_opened_as_valid_ownership() {
    let fixture = Fixture::new("record-links");
    let build = fixture.acquire();
    let owner = build.paths().slot.join("owner.json");
    fs::hard_link(&owner, fixture.root.join("record-alias")).unwrap();
    assert_eq!(error_kind(build.measure()), "link");
    assert!(owner.exists());
    assert!(build.paths().catalog.join("lease.json").exists());
}

#[test]
fn tiny_budget_rejects_command_admission_and_preserves_owned_lease() {
    let mut fixture = Fixture::new("tiny-budget");
    fixture.config.budgets.slot_bytes = 16;
    fixture.config.budgets.catalog_bytes = 32;
    assert_eq!(
        error_kind(ManagedBuild::acquire(
            fixture.config.clone(),
            &fixture.checkout
        )),
        "budget"
    );
    assert!(fixture.catalog().join("lease.json").exists());
}

#[test]
fn explicit_managed_environment_override_must_match_owned_path() {
    let fixture = Fixture::new("env");
    let build = fixture.acquire();
    let expected = build.environment();
    assert_eq!(
        expected["CARGO_HOME"],
        build.paths().cargo_home.to_string_lossy()
    );
    assert!(build.validate_explicit_overrides(&expected).is_ok());
    let mut wrong = expected;
    wrong.insert(
        "TMP".into(),
        fixture
            .root
            .join("user-temp")
            .to_string_lossy()
            .into_owned(),
    );
    assert_eq!(
        error_kind(build.validate_explicit_overrides(&wrong)),
        "override"
    );
    build.finish(outcome(0)).unwrap();
}

#[test]
fn measurement_progress_failure_preserves_exact_cause_and_active_lease() {
    let fixture = Fixture::new("progress-failure");
    let build = fixture.acquire();
    let lease = fs::read(build.paths().catalog.join("lease.json")).unwrap();
    let expected = build.measure().unwrap();
    let mut calls = 0;
    let error = build
        .measure_with_progress(&mut || {
            calls += 1;
            Err("native resource observation failed at owned pid".into())
        })
        .unwrap_err();
    assert_eq!(calls, 1);
    assert_eq!(error.kind, "observation_failed");
    assert_eq!(
        error.message,
        "native resource observation failed at owned pid"
    );
    assert_eq!(
        fs::read(build.paths().catalog.join("lease.json")).unwrap(),
        lease
    );
    let mut successful_calls = 0;
    let measured = build
        .measure_with_progress(&mut || {
            successful_calls += 1;
            Ok(())
        })
        .unwrap();
    assert!(successful_calls > 0);
    assert_eq!(measured.slot_bytes, expected.slot_bytes);
    assert_eq!(measured.catalog_bytes, expected.catalog_bytes);
    build.finish(outcome(0)).unwrap();
}

#[test]
fn tree_measurement_checkpoints_enumeration_and_delayed_metadata() {
    use std::cell::Cell;
    let fixture = Fixture::new("progress-cadence");
    let directory = fixture.root.join("authored-tree");
    fs::create_dir(&directory).unwrap();
    for index in 0..128 {
        fs::write(directory.join(format!("entry-{index}")), b"data").unwrap();
    }
    let elapsed_ms = Cell::new(0u64);
    let last_checkpoint_ms = Cell::new(0u64);
    let maximum_gap_ms = Cell::new(0u64);
    let checkpoint_count = Cell::new(0usize);
    let metadata_count = Cell::new(0usize);
    let bytes = tree_bytes_observed_with_progress(
        &directory,
        &directory,
        &[],
        |path| {
            if path != directory && metadata_count.get() == 1 {
                // The first child is visited after all entries are enumerated.
                // Checkpoints during that enumeration cannot be supplied by
                // metadata callbacks alone.
                assert!(checkpoint_count.get() >= 2 * 128);
            }
            metadata_count.set(metadata_count.get() + 1);
            // Model a bounded slow metadata operation without sleeping or
            // asserting scheduling behavior on the machine running this test.
            elapsed_ms.set(elapsed_ms.get() + 25);
        },
        &mut || {
            maximum_gap_ms.set(
                maximum_gap_ms
                    .get()
                    .max(elapsed_ms.get() - last_checkpoint_ms.get()),
            );
            last_checkpoint_ms.set(elapsed_ms.get());
            checkpoint_count.set(checkpoint_count.get() + 1);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(bytes, 128 * 4);
    assert_eq!(metadata_count.get(), 129);
    assert_eq!(elapsed_ms.get(), 3225);
    assert_eq!(maximum_gap_ms.get(), 25);
}

#[test]
fn progress_error_during_enumeration_stops_before_pending_metadata() {
    use std::cell::Cell;
    let fixture = Fixture::new("progress-stop");
    let directory = fixture.root.join("authored-tree");
    fs::create_dir(&directory).unwrap();
    for index in 0..16 {
        fs::write(directory.join(format!("entry-{index}")), b"data").unwrap();
    }
    let metadata_count = Cell::new(0usize);
    let checkpoints_after_root = Cell::new(0usize);
    let error = tree_bytes_observed_with_progress(
        &directory,
        &directory,
        &[],
        |path| {
            assert_eq!(path, directory);
            metadata_count.set(metadata_count.get() + 1);
        },
        &mut || {
            if metadata_count.get() != 0 {
                let count = checkpoints_after_root.get() + 1;
                checkpoints_after_root.set(count);
                // Fail immediately after the first directory.next(), before
                // its entry is pushed and before any child metadata is read.
                if count == 5 {
                    return Err("owned resource sample exceeded its deadline".into());
                }
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(metadata_count.get(), 1);
    assert_eq!(checkpoints_after_root.get(), 5);
    assert_eq!(error.kind, "observation_failed");
    assert_eq!(error.message, "owned resource sample exceeded its deadline");
}

#[test]
fn measurement_tolerates_only_owned_ephemeral_entries_deleted_by_concurrent_worker() {
    use std::sync::mpsc;
    use std::time::Duration;
    let fixture = Fixture::new("concurrent-churn");
    let build = fixture.acquire();
    for directory in [false, true] {
        for _ in 0..8 {
            let ephemeral = build.paths().cargo_target.join("compiler-churn");
            if directory {
                fs::create_dir(&ephemeral).unwrap();
                fs::write(ephemeral.join("compiler-output"), b"temporary").unwrap();
            } else {
                fs::write(&ephemeral, b"temporary").unwrap();
            }
            let (enumerated_tx, enumerated_rx) = mpsc::channel();
            let (deleted_tx, deleted_rx) = mpsc::channel();
            let worker_path = ephemeral.clone();
            let parent = fs::canonicalize(&build.paths().cargo_target).unwrap();
            let worker = std::thread::spawn(move || {
                enumerated_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("measurement enumerates authored entry");
                let physical = fs::canonicalize(&worker_path).unwrap();
                assert_eq!(physical.parent(), Some(parent.as_path()));
                if directory {
                    fs::remove_dir_all(&worker_path).unwrap();
                } else {
                    fs::remove_file(&worker_path).unwrap();
                }
                deleted_tx.send(()).unwrap();
            });
            let mut saw_entry = false;
            let measured = build
                .measure_with(|path| {
                    if path == ephemeral {
                        saw_entry = true;
                        enumerated_tx.send(()).unwrap();
                        deleted_rx
                            .recv_timeout(Duration::from_secs(5))
                            .expect("concurrent compiler churn is bounded");
                    }
                })
                .unwrap();
            worker.join().unwrap();
            assert!(saw_entry && measured.within_budget);
            assert!(!ephemeral.exists());
        }
    }
    assert!(build.paths().slot.join("owner.json").exists());
    assert!(build.paths().catalog.join("lease.json").exists());
    assert!(build.finish(outcome(0)).unwrap().lease_released);
}

#[test]
fn measurement_rejects_disappeared_fixed_root_and_owner_during_observation() {
    for remove_owner in [false, true] {
        let fixture = Fixture::new("critical-disappearance");
        let build = fixture.acquire();
        let critical = if remove_owner {
            build.paths().slot.join("owner.json")
        } else {
            build.paths().cargo_target.clone()
        };
        let mut removed = false;
        let error = build.measure_with(|path| {
            if path == critical && !removed {
                if remove_owner {
                    fs::remove_file(path).unwrap();
                } else {
                    fs::remove_dir(path).unwrap();
                }
                removed = true;
            }
        });
        assert!(removed);
        assert_eq!(error_kind(error), "io");
        assert!(build.paths().catalog.join("lease.json").exists());
        assert!(build.paths().scratch.exists());
    }
}

#[test]
fn missing_owner_before_measurement_is_never_treated_as_ephemeral_churn() {
    let fixture = Fixture::new("missing-owner");
    let build = fixture.acquire();
    fs::remove_file(build.paths().slot.join("owner.json")).unwrap();
    assert_eq!(error_kind(build.measure()), "io");
    assert!(build.paths().catalog.join("lease.json").exists());
}

#[test]
fn generated_entry_diagnostic_keeps_relative_labels_bounded_and_private() {
    let fixture = Fixture::new("entry-diagnostic");
    let build = fixture.acquire();
    let prefix = "special filesystem entry is preserved; stage=measurement; native_kind=other_special; generated_relative=";
    let long_path = build
        .paths()
        .scratch
        .join(format!("runtime\n{}", "한".repeat(1024)));
    let long = generated_entry_context(prefix.into(), &long_path, &build.paths().slot);
    assert!(long.len() <= 512 && long.ends_with("..."));
    assert!(long.contains("generated_relative=scratch"));
    assert!(long.contains("runtime\\n") && !long.contains('\n'));
    assert!(!long.contains(fixture.root.to_string_lossy().as_ref()));
    let walk_limits = WalkLimits {
        max_depth: 4,
        ..MANAGED_WALK_LIMITS
    };
    let walk_message = |path: &Path| {
        walk_limit_error(
            WalkLimitReason::Depth,
            path,
            &build.paths().slot,
            5,
            7,
            0,
            walk_limits,
        )
        .message
    };
    let long_walk = walk_message(&long_path);
    assert!(long_walk.len() <= 512 && long_walk.ends_with("..."));
    assert!(long_walk.contains("reason=depth; depth=5; walk_pops=7; pending_count=0;"));
    assert!(long_walk.contains("runtime\\n") && !long_walk.contains('\n'));
    assert!(!long_walk.contains(fixture.root.to_string_lossy().as_ref()));

    // These are labels only: no protected path is created, inspected or read.
    for leaf in [
        ".env",
        "credential",
        "service-account.json",
        "private-key",
        ".env.private/nested-placeholder",
    ] {
        let withheld = generated_entry_context(
            prefix.into(),
            &build.paths().scratch.join(leaf),
            &build.paths().slot,
        );
        assert!(withheld.ends_with("<withheld by path policy>"));
        assert!(!withheld.contains(leaf));
        let withheld_walk = walk_message(&build.paths().scratch.join(leaf));
        assert!(withheld_walk.ends_with("<withheld by path policy>"));
        assert!(!withheld_walk.contains(leaf));
        assert!(!withheld_walk.contains("nested-placeholder"));
        assert!(withheld_walk.len() <= 512);
    }
    let outside = generated_entry_context(
        prefix.into(),
        &fixture.checkout.join("private-original"),
        &build.paths().slot,
    );
    assert!(outside.ends_with("<outside generated boundary>"));
    assert!(!outside.contains("private-original"));
    assert!(!outside.contains(fixture.root.to_string_lossy().as_ref()));
    let outside_walk = walk_message(&fixture.checkout.join("private-original"));
    assert!(outside_walk.ends_with("<outside generated boundary>"));
    assert!(!outside_walk.contains("private-original"));
    assert!(!outside_walk.contains(fixture.root.to_string_lossy().as_ref()));
    assert!(
        generated_entry_context(prefix.into(), &build.paths().slot, &build.paths().slot)
            .ends_with("generated_relative=.")
    );
    build.finish(outcome(0)).unwrap();
}

#[cfg(unix)]
#[test]
fn native_socket_kind_uses_owned_descriptor_metadata_without_opening_a_path() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixDatagram;

    // An unbound descriptor avoids platform-specific Unix socket pathname
    // limits in the deeply nested managed scratch root. Only fstat is used.
    let socket = UnixDatagram::unbound().unwrap();
    let descriptor: OwnedFd = socket.into();
    let socket_file = File::from(descriptor);
    assert_eq!(
        native_file_kind(&socket_file.metadata().unwrap()),
        "unix_socket"
    );
}

#[cfg(unix)]
#[test]
fn actual_fifo_blocks_measurement_and_cleanup_with_native_relative_diagnostic() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileTypeExt;

    let fixture = Fixture::new("native-special-entry");
    let build = fixture.acquire();
    let paths = build.paths().clone();
    let fifo = paths.scratch.join("owned-runtime-fifo");
    let native_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: this terminated path names a newly created fixture's owned
    // scratch entry. mkfifo does not open it or access another process.
    assert_eq!(unsafe { libc::mkfifo(native_path.as_ptr(), 0o600) }, 0);
    let sentinel = paths.scratch.join("retained-original");
    fs::write(&sentinel, b"keep authored fixture").unwrap();

    let error = build.measure().unwrap_err();
    assert_eq!(error.kind, "file_type");
    assert!(error.message.contains("stage=measurement"));
    assert!(error.message.contains("native_kind=unix_fifo"));
    assert!(
        error
            .message
            .contains("generated_relative=scratch/owned-runtime-fifo")
    );
    assert!(
        !error
            .message
            .contains(fixture.root.to_string_lossy().as_ref())
    );
    assert!(error.message.len() <= 512);

    let preflight = unlink_internal_links(
        &paths.scratch,
        &paths.slot,
        &paths.slot.join("owner.json"),
        &build.slot_bytes,
        &|| Ok(()),
    )
    .unwrap_err();
    assert_eq!(preflight.kind, "file_type");
    assert!(preflight.message.contains("stage=link_preflight"));
    assert!(preflight.message.contains("native_kind=unix_fifo"));
    assert_eq!(error_kind(build.remove_owned_scratch()), "file_type");
    assert_eq!(error_kind(build.finish(outcome(0))), "file_type");
    assert!(fs::symlink_metadata(&fifo).unwrap().file_type().is_fifo());
    assert_eq!(fs::read(&sentinel).unwrap(), b"keep authored fixture");
    assert!(paths.catalog.join("lease.json").is_file());
    assert!(paths.slot.join("owner.json").is_file());
}

#[test]
fn churn_allowance_does_not_apply_to_completed_slot_or_other_error_kinds() {
    let fixture = Fixture::new("strict-observation");
    let build = fixture.acquire();
    let ephemeral = build.paths().cargo_target.join("vanishing");
    fs::write(&ephemeral, b"temporary").unwrap();
    let mut progress_calls = 0;
    let result = tree_bytes_observed_with_progress(
        &build.paths().slot,
        &build.paths().slot,
        &[],
        |path| {
            if path == ephemeral {
                fs::remove_file(path).unwrap();
            }
        },
        &mut || {
            progress_calls += 1;
            Ok(())
        },
    );
    assert!(progress_calls > 0);
    let error = result.unwrap_err();
    assert_eq!(error.kind, "io");
    assert!(error.message.contains("managed entry metadata"));
    assert!(error.message.contains("raw_os_error=Some("));
    assert!(error.message.contains("generated_relative=cache"));
    assert!(error.message.contains("vanishing"));
    assert!(
        !error
            .message
            .contains(fixture.root.to_string_lossy().as_ref())
    );
    // Reuse this failure-boundary fixture to prove native denial remains
    // fatal, diagnostics stay bounded and escaped, and private roots or
    // policy-protected path names cannot enter the shared context.
    let native_denial = std::io::Error::from_raw_os_error(5);
    let native_cause = native_denial.to_string();
    let diagnostic = measurement_io_error(
        "managed entry metadata",
        &build
            .paths()
            .scratch
            .join(format!("compiler\n{}", "한".repeat(1024))),
        &build.paths().slot,
        native_denial,
    );
    assert_eq!(diagnostic.kind, "io");
    assert!(diagnostic.message.contains("raw_os_error=Some(5)"));
    assert!(diagnostic.message.contains("compiler\\n"));
    assert!(!diagnostic.message.contains('\n'));
    assert!(diagnostic.message.ends_with(&native_cause));
    let context = diagnostic
        .message
        .strip_suffix(&format!(": {native_cause}"))
        .unwrap();
    assert!(context.len() <= 512 && context.ends_with("..."));
    assert!(
        !diagnostic
            .message
            .contains(fixture.root.to_string_lossy().as_ref())
    );
    let protected = measurement_io_error(
        "directory open",
        &build.paths().scratch.join(".env"),
        &build.paths().slot,
        std::io::Error::from_raw_os_error(5),
    );
    assert!(protected.message.contains("<withheld by path policy>"));
    assert!(!protected.message.contains(".env"));
    let outside = measurement_io_error(
        "directory enumeration",
        &fixture.checkout.join("private-original"),
        &build.paths().slot,
        std::io::Error::from_raw_os_error(5),
    );
    assert!(outside.message.contains("<outside generated boundary>"));
    assert!(!outside.message.contains("private-original"));
    assert!(
        !outside
            .message
            .contains(fixture.root.to_string_lossy().as_ref())
    );
    let roots = build.observation_roots();
    let not_found = std::io::Error::from(std::io::ErrorKind::NotFound);
    let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    assert!(vanished_ephemeral_entry(&ephemeral, &not_found, &roots).unwrap());
    assert!(!vanished_ephemeral_entry(&ephemeral, &denied, &roots).unwrap());
    assert!(!vanished_ephemeral_entry(&build.paths().cargo_target, &not_found, &roots).unwrap());
    assert!(
        !vanished_ephemeral_entry(&build.paths().slot.join("owner.json"), &not_found, &roots)
            .unwrap()
    );
    build.finish(outcome(0)).unwrap();
}

#[test]
fn vanished_ancestry_prefix_diagnostic_never_authorizes_a_mismatch() {
    #[cfg(windows)]
    let (root, exact, case_only, sibling, prefix_trick) = (
        PathBuf::from(concat!("C:", r"\fixture\Owned")),
        PathBuf::from(concat!("C:", r"\fixture\Owned\child")),
        PathBuf::from(concat!("C:", r"\fixture\owned\child")),
        PathBuf::from(concat!("C:", r"\fixture\Other\child")),
        PathBuf::from(concat!("C:", r"\fixture\OwnedSibling\child")),
    );
    #[cfg(not(windows))]
    let (root, exact, case_only, sibling, prefix_trick) = (
        PathBuf::from("/fixture/Owned"),
        PathBuf::from("/fixture/Owned/child"),
        PathBuf::from("/fixture/owned/child"),
        PathBuf::from("/fixture/Other/child"),
        PathBuf::from("/fixture/OwnedSibling/child"),
    );
    assert_eq!(physical_prefix_diagnostic(&root, &exact), "exact");
    for (candidate, expected) in [
        (&case_only, "ascii_fold_match"),
        (&sibling, "ascii_fold_mismatch"),
        (&prefix_trick, "ascii_fold_mismatch"),
    ] {
        assert!(!candidate.starts_with(&root));
        assert_eq!(physical_prefix_diagnostic(&root, candidate), expected);
        let error = vanished_ancestry_escape(
            &root,
            candidate,
            1,
            2,
            &std::io::Error::from(std::io::ErrorKind::NotFound),
        );
        assert_eq!(error.kind, "link_escape");
        assert!(error.message.contains(&format!("prefix_class={expected}")));
        assert!(
            error
                .message
                .contains("component_depth_1based=1; total_components=2")
        );
        assert!(error.message.contains("first_not_found_errno=None"));
        for private_component in ["fixture", "Owned", "Other", "child"] {
            assert!(!error.message.contains(private_component));
        }
        assert!(!error.message.contains(root.to_str().unwrap()));
        assert!(!error.message.contains(candidate.to_str().unwrap()));
    }
    assert_eq!(
        physical_prefix_diagnostic(Path::new("relative"), Path::new("relative/child")),
        "unknown"
    );
}

#[cfg(windows)]
#[test]
fn vanished_ancestry_prefix_diagnostic_handles_unc_as_diagnostic_only() {
    let root = Path::new(r"\\server\share\Owned");
    let case_only = Path::new(r"\\server\share\owned\child");
    let other_share = Path::new(r"\\server\other\Owned\child");
    assert_eq!(
        physical_prefix_diagnostic(root, case_only),
        "ascii_fold_match"
    );
    assert_eq!(
        physical_prefix_diagnostic(root, other_share),
        "ascii_fold_mismatch"
    );
    assert_eq!(
        physical_prefix_diagnostic(
            Path::new(concat!("C:", r"\fixture\Owned")),
            Path::new(concat!(r"\\?\C:", r"\fixture\Owned\child")),
        ),
        "unknown"
    );
    assert_eq!(
        physical_prefix_diagnostic(
            Path::new(r"\\.\device\Owned"),
            Path::new(r"\\.\device\Owned\child"),
        ),
        "unknown"
    );
    let error = vanished_ancestry_escape(
        root,
        case_only,
        1,
        1,
        &std::io::Error::from(std::io::ErrorKind::NotFound),
    );
    assert_eq!(error.kind, "link_escape");
    assert!(!error.message.contains("server"));
    assert!(!error.message.contains("share"));
}

#[cfg(any(unix, windows))]
#[test]
fn vanished_ancestry_diagnostic_records_only_native_not_found_number() {
    #[cfg(windows)]
    let (root, candidate, errno) = (
        Path::new(concat!("C:", r"\fixture\Owned")),
        Path::new(concat!("C:", r"\fixture\Other\child")),
        3,
    );
    #[cfg(unix)]
    let (root, candidate, errno) = (
        Path::new("/fixture/Owned"),
        Path::new("/fixture/Other/child"),
        2,
    );
    let first = std::io::Error::from_raw_os_error(errno);
    assert_eq!(first.kind(), std::io::ErrorKind::NotFound);
    let error = vanished_ancestry_escape(root, candidate, 1, 2, &first);
    assert_eq!(error.kind, "link_escape");
    assert!(
        error
            .message
            .contains(&format!("first_not_found_errno=Some({errno})"))
    );
    assert!(!error.message.contains("fixture"));
    assert!(!error.message.contains("Other"));
}

#[cfg(any(unix, windows))]
#[test]
fn vanished_ancestry_prefix_diagnostic_does_not_render_non_utf8() {
    #[cfg(unix)]
    let invalid = {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(vec![0xff])
    };
    #[cfg(windows)]
    let invalid = {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&[0xd800])
    };
    #[cfg(unix)]
    let root = PathBuf::from("/fixture").join(invalid);
    #[cfg(windows)]
    let root = PathBuf::from(concat!("C:", r"\fixture")).join(invalid);
    let candidate = root.join("child");
    assert_eq!(physical_prefix_diagnostic(&root, &candidate), "unknown");
    let error = vanished_ancestry_escape(
        &root,
        &candidate,
        1,
        1,
        &std::io::Error::from(std::io::ErrorKind::NotFound),
    );
    assert_eq!(error.kind, "link_escape");
    assert!(error.message.contains("prefix_class=unknown"));
    assert!(!error.message.contains("fixture"));
    assert!(!error.message.contains("child"));
}

#[test]
fn vanished_entry_allowance_rejects_nested_parent_replaced_by_external_link() {
    let fixture = Fixture::new("churn-link-boundary");
    let build = fixture.acquire();
    let nested = build.paths().cargo_target.join("nested");
    let moved = build.paths().cargo_target.join("original-nested");
    let leaf = nested.join("compiler-output");
    fs::create_dir(&nested).unwrap();
    fs::write(&leaf, b"temporary").unwrap();
    let outside = fixture.root.join("outside-original");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("keep"), b"user original").unwrap();
    let mut replaced = false;
    let result = build.measure_with(|path| {
        if path == leaf && !replaced {
            fs::rename(&nested, &moved).unwrap();
            #[cfg(unix)]
            std::os::unix::fs::symlink(&outside, &nested).unwrap();
            #[cfg(windows)]
            create_junction(&nested, &outside);
            replaced = true;
        }
    });
    assert!(replaced);
    assert_eq!(error_kind(result), "link");
    assert_eq!(fs::read(outside.join("keep")).unwrap(), b"user original");
    assert_eq!(
        fs::read(moved.join("compiler-output")).unwrap(),
        b"temporary"
    );
    assert!(build.paths().catalog.join("lease.json").exists());
    #[cfg(windows)]
    fs::remove_dir(&nested).unwrap();
}

#[test]
fn vanished_entry_guard_inspects_surviving_errored_leaf_itself() {
    let fixture = Fixture::new("churn-leaf-boundary");
    let build = fixture.acquire();
    let leaf = build.paths().scratch.join("directory-leaf");
    let outside = fixture.root.join("outside-empty");
    fs::create_dir(&outside).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, &leaf).unwrap();
    #[cfg(windows)]
    create_junction(&leaf, &outside);
    let roots = build.observation_roots();
    let synthetic_directory_race = std::io::Error::from(std::io::ErrorKind::NotFound);
    assert_eq!(
        error_kind(vanished_ephemeral_entry(
            &leaf,
            &synthetic_directory_race,
            &roots
        )),
        "link"
    );
    assert!(build.paths().catalog.join("lease.json").exists());
    #[cfg(windows)]
    fs::remove_dir(&leaf).unwrap();
}

#[test]
fn bootstrap_adoption_requires_exact_identity_and_drain_then_updates_owner() {
    let fixture = Fixture::new("bootstrap");
    let original = fixture.acquire();
    let paths = original.paths().clone();
    let identity = BootstrapOwnership {
        schema: SCHEMA.into(),
        catalog_id: original.catalog.catalog_id.clone(),
        slot_id: original.slot.slot_id.clone(),
        checkout_digest: original.slot.checkout_digest.clone(),
        os: original.slot.os.clone(),
        arch: original.slot.arch.clone(),
        purpose: original.slot.purpose.clone(),
        token: original.slot.token.clone(),
        pid: original.slot.pid,
        started_ms: original.lease.started_ms,
    };
    let old = fs::read(paths.catalog.join("lease.json")).unwrap();
    drop(original);
    assert_eq!(
        error_kind(ManagedBuild::adopt_bootstrap(
            fixture.config.clone(),
            &fixture.checkout,
            identity.clone(),
            false,
            true
        )),
        "bootstrap_proof"
    );
    let mut wrong = identity.clone();
    wrong.token = new_token();
    assert_eq!(
        error_kind(ManagedBuild::adopt_bootstrap(
            fixture.config.clone(),
            &fixture.checkout,
            wrong,
            true,
            true
        )),
        "bootstrap_identity"
    );
    assert_eq!(fs::read(paths.catalog.join("lease.json")).unwrap(), old);
    let mut wrong_record: SlotRecord = read_record(&paths.slot.join("owner.json")).unwrap();
    let replacement = if wrong_record.checkout_digest.ends_with('a') {
        'b'
    } else {
        'a'
    };
    wrong_record.checkout_digest.pop();
    wrong_record.checkout_digest.push(replacement);
    fs::write(
        paths.slot.join("owner.json"),
        record_bytes(&wrong_record).unwrap(),
    )
    .unwrap();
    assert_eq!(
        error_kind(ManagedBuild::adopt_bootstrap(
            fixture.config.clone(),
            &fixture.checkout,
            identity.clone(),
            true,
            true
        )),
        "bootstrap_identity"
    );
    wrong_record.checkout_digest = identity.checkout_digest.clone();
    fs::write(
        paths.slot.join("owner.json"),
        record_bytes(&wrong_record).unwrap(),
    )
    .unwrap();
    let adopted = ManagedBuild::adopt_bootstrap(
        fixture.config.clone(),
        &fixture.checkout,
        identity.clone(),
        true,
        true,
    )
    .unwrap();
    assert_ne!(adopted.lease.token, identity.token);
    assert_eq!(adopted.lease.token, adopted.slot.token);
    assert_eq!(adopted.paths().slot, paths.slot);
    adopted.finish(outcome(0)).unwrap();
}

#[cfg(unix)]
#[test]
fn external_link_is_preserved_with_its_target_and_blocks_finish() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new("link");
    let build = fixture.acquire();
    let outside = fixture.root.join("user-original");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("keep"), b"user").unwrap();
    let link = build.paths().scratch.join("escape");
    symlink(&outside, &link).unwrap();
    assert_eq!(error_kind(build.measure()), "link_escape");
    assert_eq!(error_kind(build.finish(outcome(0))), "link_escape");
    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(fs::read(outside.join("keep")).unwrap(), b"user");
}

#[cfg(unix)]
#[test]
fn internal_link_to_retained_cache_is_removed_without_following_target() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new("internal-link");
    let build = fixture.acquire();
    let cache = build.paths().cargo_target.clone();
    fs::write(cache.join("keep"), b"compiled").unwrap();
    symlink(&cache, build.paths().scratch.join("link")).unwrap();
    let receipt = build.finish(outcome(0)).unwrap();
    assert!(receipt.scratch_removed && receipt.lease_released);
    assert_eq!(fs::read(cache.join("keep")).unwrap(), b"compiled");
}

#[cfg(unix)]
#[test]
fn cross_subtree_internal_links_are_unlinked_before_eviction_removes_targets() {
    use std::os::unix::fs::symlink;
    let mut fixture = Fixture::new("cross-links");
    fixture.config.budgets.completed_slots = 0;
    let build = fixture.acquire();
    let slot = build.paths().slot.clone();
    let source = build.paths().cargo_target.join("a-source");
    let target = build.paths().cargo_target.join("z-target");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&target).unwrap();
    fs::write(target.join("compiled"), b"cache").unwrap();
    symlink(&target, source.join("target-link")).unwrap();
    symlink(
        source.join("target-link"),
        build.paths().cargo_target.join("chain-link"),
    )
    .unwrap();
    let receipt = build.finish(outcome(0)).unwrap();
    assert!(receipt.slot_evicted && receipt.lease_released);
    assert!(receipt.cleanup_errors.is_empty());
    assert!(!slot.exists());
}

#[cfg(unix)]
#[test]
fn replaced_catalog_ancestor_link_is_rejected_before_cleanup() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new("ancestor");
    let build = fixture.acquire();
    let parent = fixture.config.output_root.as_ref().unwrap().join("build");
    let renamed = fixture.root.join("moved-owned-build");
    fs::rename(&parent, &renamed).unwrap();
    symlink(&renamed, &parent).unwrap();
    assert_eq!(error_kind(build.finish(outcome(0))), "link");
    assert!(renamed.join("managed-v1/lease.json").exists());
}

#[cfg(windows)]
#[test]
fn windows_forward_slash_overlap_is_rejected_before_creation() {
    let mut fixture = Fixture::new("slash-overlap");
    let checkout = fixture.checkout.to_string_lossy().replace('\\', "/");
    fixture.config.output_root = Some(PathBuf::from(format!("{checkout}/generated")));
    assert_eq!(
        error_kind(ManagedBuild::acquire(
            fixture.config.clone(),
            &fixture.checkout
        )),
        "overlap"
    );
    assert!(!fixture.checkout.join("generated").exists());
}

#[cfg(windows)]
#[test]
fn windows_junction_escape_is_preserved_and_target_is_never_deleted() {
    let fixture = Fixture::new("junction");
    let build = fixture.acquire();
    let outside = fixture.root.join("user-original");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("keep"), b"user").unwrap();
    let junction = build.paths().scratch.join("escape");
    create_junction(&junction, &outside);
    assert_eq!(error_kind(build.measure()), "link_escape");
    assert_eq!(error_kind(build.finish(outcome(0))), "link_escape");
    assert!(junction.exists());
    assert_eq!(fs::read(outside.join("keep")).unwrap(), b"user");
    fs::remove_dir(&junction).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_internal_junction_is_unlinked_without_following_cache_target() {
    let fixture = Fixture::new("internal-junction");
    let build = fixture.acquire();
    let cache = build.paths().cargo_target.clone();
    fs::write(cache.join("compiled"), b"cache").unwrap();
    create_junction(&build.paths().scratch.join("cache-link"), &cache);
    let receipt = build.finish(outcome(0)).unwrap();
    assert!(receipt.lease_released && receipt.cleanup_errors.is_empty());
    assert_eq!(fs::read(cache.join("compiled")).unwrap(), b"cache");
}

#[cfg(windows)]
fn create_junction(link: &Path, target: &Path) {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    fs::create_dir(link).unwrap();
    let target = fs::canonicalize(target).unwrap();
    let target_text = target.to_string_lossy();
    let substitute = format!(r"\??\{}", target_text.trim_start_matches(r"\\?\"));
    let substitute: Vec<u16> = substitute.encode_utf16().collect();
    let printable: Vec<u16> = target.as_os_str().encode_wide().collect();
    let substitute_bytes = u16::try_from(substitute.len() * 2).unwrap();
    let print_bytes = u16::try_from(printable.len() * 2).unwrap();
    let data_len = 8u16
        .checked_add(substitute_bytes)
        .unwrap()
        .checked_add(2)
        .unwrap()
        .checked_add(print_bytes)
        .unwrap()
        .checked_add(2)
        .unwrap();
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&0xA0000003u32.to_le_bytes()); // IO_REPARSE_TAG_MOUNT_POINT
    buffer.extend_from_slice(&data_len.to_le_bytes());
    buffer.extend_from_slice(&0u16.to_le_bytes());
    for value in [0u16, substitute_bytes, substitute_bytes + 2, print_bytes] {
        buffer.extend_from_slice(&value.to_le_bytes());
    }
    for value in substitute
        .into_iter()
        .chain([0])
        .chain(printable)
        .chain([0])
    {
        buffer.extend_from_slice(&value.to_le_bytes());
    }
    let path: Vec<u16> = link.as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: path is NUL-terminated and lives through the call. The directory
    // was freshly created as owned test data; no shared handles are inherited.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(
        handle,
        INVALID_HANDLE_VALUE,
        "{}",
        std::io::Error::last_os_error()
    );
    // SAFETY: successful CreateFileW returned an owned handle and this File
    // takes sole responsibility for closing it after the fixture operation.
    let directory = unsafe { File::from_raw_handle(handle) };
    let mut returned = 0u32;
    // SAFETY: the bounded reparse buffer follows MOUNT_POINT layout. The
    // input and returned-byte pointers live for this synchronous native call.
    let ok = unsafe {
        DeviceIoControl(
            directory.as_raw_handle(),
            0x000900A4,
            buffer.as_ptr().cast(),
            u32::try_from(buffer.len()).unwrap(),
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
}

//! Authored policy fixtures test completeness, pinning and denial decisions.
//! They are not real dependency admissions or product/game release evidence.
//! A fixture verifier deliberately simulates authenticated observations so an
//! eligible path can be exercised without publishing any success claim.

use crate::*;
use mmmm_contracts::{ContractValidator, canonical_digest, raw_digest};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

struct FixtureVerifier(EvidenceOrigin);
impl TrustedEvidenceVerifier for FixtureVerifier {
    fn verify(
        &self,
        subject: &ProofSubject,
        material: &ProofMaterial,
    ) -> Result<EvidenceOrigin, PolicyError> {
        if material.bytes == subject.claim_sha256.as_bytes() {
            Ok(self.0)
        } else {
            Err(PolicyError::new(
                "EVIDENCE_MISSING",
                "Authored fixture proof is not bound to the complete claim",
            ))
        }
    }
}

fn material<T: Serialize>(reference: &str, claim: &T) -> ProofMaterial {
    let bytes = canonical_digest(&serde_json::to_value(claim).unwrap())
        .unwrap()
        .into_string()
        .into_bytes();
    ProofMaterial {
        reference: reference.into(),
        sha256: raw_digest(&bytes).into_string(),
        bytes,
    }
}

fn candidate(classification: DependencyClassification) -> DependencyDisposition {
    let temporary = classification == DependencyClassification::TemporaryDomainVendor;
    DependencyDisposition {
        component_id: "policy-fixture".into(),
        classification,
        language: "Rust".into(),
        source_locator: "fixture:synthetic-source".into(),
        source_revision: "authored-fixture-1".into(),
        source_sha256: "1".repeat(64),
        license_expression: "MIT".into(),
        target_game_versions: vec!["26.3".into()],
        contract_ids: vec!["FN30".into()],
        implementation_digest: "2".repeat(64),
        phase: VendorPhase::Candidate,
        owner: "fixture-owner".into(),
        replacement_module: temporary.then(|| "mmmm-exchange::fixture-port".into()),
        evidence_refs: vec!["fixture-admission-proof".into()],
        production_reachable: true,
        retire_before: if temporary { "v1" } else { "not_domain_vendor" }.into(),
    }
}

fn budget() -> WorkerBudget {
    WorkerBudget {
        timeout_milliseconds: 60_000,
        memory_bytes: 268_435_456,
        input_bytes: 1_048_576,
        output_bytes: 1_048_576,
        max_processes: 2,
    }
}

fn admission() -> AdmissionAttestation {
    let request = AdmissionRequest {
        candidate: candidate(DependencyClassification::TemporaryDomainVendor),
        project_target_profile_id: "java-26.3".into(),
        needed_contract_ids: vec!["FN30".into()],
    };
    AdmissionAttestation {
        requirements: required_admission_checks(&request.candidate.classification)
            .into_iter()
            .map(|item| (item, EvidenceResult::Passed))
            .collect(),
        request,
        contract_version: "0.2.0".into(),
        target_game_version: "26.3".into(),
        rights: RightsDisposition::RedistributionAndModificationAllowed,
        target_compatibility: TargetCompatibility::Exact,
        worker: WorkerDisposition::BoundedSubprocess {
            budget: budget(),
            executable_sha256: "3".repeat(64),
            argv_template_registered: true,
            workspace_scoped: true,
            environment_allowlisted: true,
            network_scoped: true,
            direct_live_access: false,
        },
        platform_boundary_only: true,
        known_unmitigated_vulnerabilities: vec![],
    }
}

fn verified_admission(attestation: AdmissionAttestation) -> VerifiedAdmissionEvidence {
    let proof = material("fixture-admission-proof", &attestation);
    VerifiedAdmissionEvidence::verify(
        attestation,
        &proof,
        &FixtureVerifier(EvidenceOrigin::Actual),
    )
    .unwrap()
}

fn decide(attestation: AdmissionAttestation) -> AdmissionDecision {
    let input = serde_json::to_value(&attestation.request).unwrap();
    let verified = verified_admission(attestation);
    serde_json::from_value(dependency_admit_verified(&input, Some(&verified)).unwrap()).unwrap()
}

#[test]
fn wire_claims_do_not_admit_dependencies_or_mutate_original_registry() {
    let mut request = admission().request;
    request.candidate.phase = VendorPhase::Admitted;
    let result: AdmissionDecision =
        serde_json::from_value(dependency_admit(&serde_json::to_value(request).unwrap()).unwrap())
            .unwrap();
    assert_eq!(result.decision, AdmissionOutcome::Defer);
    assert!(!result.missing_evidence.is_empty());
    assert!(embedded_vendor_registry().unwrap().is_empty());
    assert_eq!(
        embedded_default_policy().unwrap()["newInstallPolicy"],
        "manual_only"
    );
}

#[test]
fn pinned_vendor_can_be_admitted_without_language_translation() {
    let mut fixture = admission();
    fixture.request.candidate.language = "Python".into();
    assert_eq!(decide(fixture).decision, AdmissionOutcome::Admit);
}

#[test]
fn rust_language_has_no_target_semantics_or_broad_fork_exception() {
    for mismatch in [
        TargetCompatibility::DomainSemanticsMismatch,
        TargetCompatibility::BroadVendorChangesRequired,
    ] {
        let mut fixture = admission();
        fixture.target_compatibility = mismatch;
        let result = decide(fixture);
        assert_eq!(result.decision, AdmissionOutcome::RustOwn);
        assert!(result.owned_implementation_module.is_some());
    }
}

#[test]
fn rights_denial_and_missing_licenses_are_never_implicit_mit_permission() {
    let mut denied = admission();
    denied.rights = RightsDisposition::Denied;
    assert_eq!(decide(denied).decision, AdmissionOutcome::Reject);
    let mut missing = admission();
    missing
        .requirements
        .remove(&AdmissionRequirement::FileLicenses);
    let result = decide(missing);
    assert_eq!(result.decision, AdmissionOutcome::Defer);
    assert!(result.missing_evidence.contains(&"FileLicenses".into()));
}

#[test]
fn failed_admission_and_not_run_admission_are_distinct() {
    let mut missing = admission();
    missing.requirements.insert(
        AdmissionRequirement::TransitiveDependencies,
        EvidenceResult::NotRun,
    );
    assert_eq!(decide(missing).decision, AdmissionOutcome::Defer);
    let mut failed = admission();
    failed.requirements.insert(
        AdmissionRequirement::TransitiveDependencies,
        EvidenceResult::Failed {
            reason: "fixture transitive rights conflict".into(),
        },
    );
    let result = decide(failed);
    assert_eq!(result.decision, AdmissionOutcome::Reject);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("rights conflict"))
    );
}

#[test]
fn worker_has_pinned_finite_scoped_execution_and_no_direct_live_access() {
    for change in 0..3 {
        let mut fixture = admission();
        if let WorkerDisposition::BoundedSubprocess {
            budget,
            direct_live_access,
            environment_allowlisted,
            ..
        } = &mut fixture.worker
        {
            match change {
                0 => budget.timeout_milliseconds = 0,
                1 => *direct_live_access = true,
                _ => *environment_allowlisted = false,
            }
        }
        assert_eq!(decide(fixture).decision, AdmissionOutcome::Reject);
    }
}

#[test]
fn external_only_requires_independent_user_selection_and_manual_install() {
    let mut fixture = admission();
    fixture.request.candidate = candidate(DependencyClassification::UserExternalTool);
    fixture.rights = RightsDisposition::UserExternalUseOnly;
    fixture.worker = WorkerDisposition::UserInstalledTool {
        budget: budget(),
        selected_independently: true,
        automatic_install: false,
        execution_scoped: true,
    };
    assert_eq!(
        decide(fixture.clone()).decision,
        AdmissionOutcome::ExternalOnly
    );
    fixture.worker = WorkerDisposition::UserInstalledTool {
        budget: budget(),
        selected_independently: false,
        automatic_install: false,
        execution_scoped: true,
    };
    assert_eq!(decide(fixture.clone()).decision, AdmissionOutcome::Reject);
    fixture.worker = WorkerDisposition::UserInstalledTool {
        budget: budget(),
        selected_independently: true,
        automatic_install: true,
        execution_scoped: true,
    };
    assert_eq!(decide(fixture).decision, AdmissionOutcome::Reject);
}

#[test]
fn installed_tool_path_cannot_conceal_product_worker_or_silent_reclassification() {
    for classification in [
        DependencyClassification::TemporaryDomainVendor,
        DependencyClassification::OwnedDomain,
        DependencyClassification::InfrastructureDependency,
    ] {
        let mut fixture = admission();
        fixture.request.candidate = candidate(classification.clone());
        fixture.requirements = required_admission_checks(&classification)
            .into_iter()
            .map(|item| (item, EvidenceResult::Passed))
            .collect();
        fixture.worker = WorkerDisposition::UserInstalledTool {
            budget: budget(),
            selected_independently: true,
            automatic_install: false,
            execution_scoped: true,
        };
        assert_eq!(decide(fixture).decision, AdmissionOutcome::Reject);
    }
}

#[test]
fn admission_evidence_cannot_be_reused_for_new_digest_or_target_scope() {
    let attestation = admission();
    let mut request = attestation.request.clone();
    let evidence = verified_admission(attestation);
    request.candidate.source_sha256 = "4".repeat(64);
    let result: AdmissionDecision = serde_json::from_value(
        dependency_admit_verified(&serde_json::to_value(request).unwrap(), Some(&evidence))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(result.decision, AdmissionOutcome::Reject);
}

#[test]
fn admission_requires_authentication_of_complete_claim_and_original_bytes() {
    let mut fixture = admission();
    let proof = material("fixture-admission-proof", &fixture);
    fixture.request.candidate.source_revision = "changed".into();
    assert!(
        VerifiedAdmissionEvidence::verify(
            fixture,
            &proof,
            &FixtureVerifier(EvidenceOrigin::Actual)
        )
        .is_err()
    );
    let fixture = admission();
    let mut proof = material("fixture-admission-proof", &fixture);
    proof.bytes.push(0);
    assert!(
        VerifiedAdmissionEvidence::verify(
            fixture,
            &proof,
            &FixtureVerifier(EvidenceOrigin::Actual)
        )
        .is_err()
    );
}

fn artifact(path: &str, digit: &str, role: ArtifactRole) -> ReleaseArtifact {
    ReleaseArtifact {
        path: path.into(),
        sha256: digit.repeat(64),
        bytes: 100,
        role,
    }
}

fn inventory() -> Vec<ReleaseArtifact> {
    vec![
        artifact("mmmm-0.1.0.zip", "a", ArtifactRole::ReleaseArchive),
        artifact(
            "windows/mmmm.zip",
            "b",
            ArtifactRole::PlatformBundle {
                os: ReleaseOs::WindowsX64,
            },
        ),
        artifact(
            "linux/mmmm.tar",
            "c",
            ArtifactRole::PlatformBundle {
                os: ReleaseOs::LinuxX64,
            },
        ),
        artifact(
            "macos/mmmm.tar",
            "d",
            ArtifactRole::PlatformBundle {
                os: ReleaseOs::MacosArm64,
            },
        ),
        artifact("SBOM.json", "e", ArtifactRole::Sbom),
        artifact("NOTICE.txt", "f", ArtifactRole::Notice),
        artifact(
            "vanilla/pack.zip",
            "1",
            ArtifactRole::VanillaOutput {
                target_profile_id: "java-26.3".into(),
            },
        ),
    ]
}

fn binding() -> ReleaseBinding {
    ReleaseBinding {
        frozen_source_sha: "9".repeat(40),
        contract_version: "0.2.0".into(),
        product_version: "0.1.0".into(),
        bundle_sha256: "a".repeat(64),
        inventory_sha256: artifact_inventory_digest(&inventory()).unwrap(),
        targets: BTreeMap::from([(
            "java-26.3".into(),
            TargetArtifactBinding {
                game_version: "26.3".into(),
                profile_sha256: "2".repeat(64),
                game_artifact_sha256: "3".repeat(64),
                loader_artifact_sha256: "4".repeat(64),
                host_artifact_sha256: "5".repeat(64),
            },
        )]),
    }
}

fn released_components() -> Vec<DependencyDisposition> {
    let mut domain = candidate(DependencyClassification::OwnedDomain);
    domain.phase = VendorPhase::Characterised;
    let mut host = candidate(DependencyClassification::PlatformShim);
    host.component_id = "fixture-jvm-host".into();
    host.language = "Java".into();
    host.phase = VendorPhase::Characterised;
    vec![domain, host]
}

fn proof(binding: &ReleaseBinding, kind: ReleaseProofKind) -> ReleaseProofClaim {
    ReleaseProofClaim {
        binding: binding.clone(),
        kind,
        result: EvidenceResult::Passed,
        runner: "authored-policy-fixture".into(),
        timestamp: "2026-10-14T00:00:00Z".into(),
        independent_oracle: true,
        tested_artifact_sha256: ["a", "b", "c", "d", "e", "f", "1", "2", "3", "4", "5"]
            .into_iter()
            .map(|digit| digit.repeat(64))
            .collect(),
        result_artifact_sha256: BTreeSet::from(["6".repeat(64)]),
        limitations: vec![],
        inventory: vec![],
        components: vec![],
        unresolved_operations: vec![],
    }
}

fn release_fixture() -> (ReleaseEvidence, ReleaseBinding, Vec<ReleaseProofClaim>) {
    let binding = binding();
    let required = mvp_required_test_ids().unwrap();
    let evidence = ReleaseEvidence {
        contract_version: "0.2.0".into(),
        product_version: "0.1.0".into(),
        stage: ReleaseStage::Mvp,
        target_profiles: vec!["java-26.3".into()],
        required_test_ids: required.iter().cloned().collect(),
        passed_test_ids: required.iter().cloned().collect(),
        failed_test_ids: vec![],
        not_run_test_ids: vec![],
        domain_vendors_remaining: vec![],
        non_rust_domain_runtimes: vec![],
        unresolved_operations: vec![],
        approved_platform_shims: vec!["fixture-jvm-host".into()],
        bundle_sha256: Some(binding.bundle_sha256.clone()),
        claim: ReleaseClaim::ReleaseCandidate,
    };
    let mut proofs: Vec<_> = required
        .into_iter()
        .map(|test_id| proof(&binding, ReleaseProofKind::Acceptance { test_id }))
        .collect();
    for os in [
        ReleaseOs::WindowsX64,
        ReleaseOs::LinuxX64,
        ReleaseOs::MacosArm64,
    ] {
        proofs.push(proof(
            &binding,
            ReleaseProofKind::ActualServer {
                os,
                target_profile_id: "java-26.3".into(),
            },
        ));
        proofs.push(proof(
            &binding,
            ReleaseProofKind::ManualClientBasic {
                os,
                target_profile_id: "java-26.3".into(),
            },
        ));
    }
    for kind in [
        ReleaseProofKind::WindowsVisualInteractionMultiplayer {
            target_profile_id: "java-26.3".into(),
        },
        ReleaseProofKind::VanillaOutput {
            target_profile_id: "java-26.3".into(),
        },
        ReleaseProofKind::ArtifactInventory,
        ReleaseProofKind::Sbom,
        ReleaseProofKind::Notice,
        ReleaseProofKind::RightsReview,
        ReleaseProofKind::DependencyGraphReview,
        ReleaseProofKind::OperationJournalReview,
    ] {
        let mut item = proof(&binding, kind.clone());
        match kind {
            ReleaseProofKind::ArtifactInventory => item.inventory = inventory(),
            ReleaseProofKind::RightsReview | ReleaseProofKind::DependencyGraphReview => {
                item.components = released_components()
            }
            _ => {}
        }
        proofs.push(item);
    }
    (evidence, binding, proofs)
}

fn index(
    binding: ReleaseBinding,
    claims: Vec<ReleaseProofClaim>,
    origin: EvidenceOrigin,
) -> Result<VerifiedEvidenceIndex, PolicyError> {
    let records = claims
        .into_iter()
        .enumerate()
        .map(|(i, claim)| {
            let material = material(&format!("fixture-release-{i}"), &claim);
            (claim, material)
        })
        .collect();
    VerifiedEvidenceIndex::verify(binding, records, &FixtureVerifier(origin))
}

fn evaluate(evidence: &ReleaseEvidence, index: Option<&VerifiedEvidenceIndex>) -> GateReport {
    serde_json::from_value(
        release_evaluate_verified(&serde_json::to_value(evidence).unwrap(), index).unwrap(),
    )
    .unwrap()
}

fn has(report: &GateReport, code: &str) -> bool {
    report.diagnostics.iter().any(|item| item.code == code)
}

#[test]
fn caller_pass_arrays_and_release_approved_claim_never_authorize_a_release() {
    let (mut evidence, _, _) = release_fixture();
    evidence.claim = ReleaseClaim::ReleaseApproved;
    let report = evaluate(&evidence, None);
    assert!(!report.eligible);
    assert_eq!(report.missing_test_ids.len(), 82);
    assert!(has(&report, "VERIFIED_EVIDENCE_MISSING"));
}

#[test]
fn original_specification_only_example_remains_ineligible() {
    let value =
        mmmm_contracts::parse_json(include_bytes!("../../../examples/release-spec-only.json"))
            .unwrap();
    let report: GateReport = serde_json::from_value(release_evaluate(&value).unwrap()).unwrap();
    assert!(!report.eligible);
    assert!(has(&report, "SPECIFICATION_ONLY"));
    assert_eq!(mvp_required_test_ids().unwrap().len(), 82);
    assert!(
        mvp_required_test_ids()
            .unwrap()
            .iter()
            .all(|id| !id.starts_with("V1"))
    );
}

#[test]
fn complete_simulated_authenticated_index_exercises_positive_evaluator_path() {
    let (evidence, binding, claims) = release_fixture();
    let index = index(binding, claims, EvidenceOrigin::Actual).unwrap();
    let report = evaluate(&evidence, Some(&index));
    assert!(report.eligible, "{:?}", report.diagnostics);
    ContractValidator::shared()
        .unwrap()
        .validate("GateReport", &serde_json::to_value(report).unwrap())
        .unwrap();
}

#[test]
fn synthetic_index_cannot_become_actual_release_authority() {
    let (evidence, binding, claims) = release_fixture();
    let index = index(binding, claims, EvidenceOrigin::Synthetic).unwrap();
    let report = evaluate(&evidence, Some(&index));
    assert!(!report.eligible);
    assert!(has(&report, "SYNTHETIC_EVIDENCE"));
}

#[test]
fn same_source_sha_and_exact_artifact_bytes_are_required_for_every_proof() {
    for mismatch in 0..4 {
        let (_, binding, mut claims) = release_fixture();
        match mismatch {
            0 => claims[0].binding.frozen_source_sha = "8".repeat(40),
            1 => claims[0].binding.bundle_sha256 = "8".repeat(64),
            2 => claims[0].binding.inventory_sha256 = "8".repeat(64),
            _ => {
                claims[0]
                    .binding
                    .targets
                    .get_mut("java-26.3")
                    .unwrap()
                    .game_artifact_sha256 = "8".repeat(64)
            }
        }
        assert!(index(binding, claims, EvidenceOrigin::Actual).is_err());
    }
}

#[test]
fn caller_cannot_remove_failed_or_not_run_required_acceptance() {
    let (mut evidence, binding, mut claims) = release_fixture();
    evidence.required_test_ids.remove(0);
    let target = &mut claims[0];
    target.result = EvidenceResult::Failed {
        reason: "actual fixture oracle mismatch".into(),
    };
    let index = index(binding, claims, EvidenceOrigin::Actual).unwrap();
    let report = evaluate(&evidence, Some(&index));
    assert!(!report.eligible);
    assert!(has(&report, "REQUIRED_ACCEPTANCE_SCOPE_MISMATCH"));
    assert!(has(&report, "ACCEPTANCE_FAILED"));
    assert!(has(&report, "TEST_RESULT_CLAIM_MISMATCH"));
    assert_eq!(report.missing_test_ids.len(), 1);
}

#[test]
fn actual_failed_and_not_run_results_remain_distinct() {
    // The existing verifier simulates authenticated policy inputs only. These
    // fixtures do not issue actual game observations or production authority.
    for untested in [false, true] {
        let (evidence, binding, mut claims) = release_fixture();
        claims[0].result = EvidenceResult::Failed {
            reason: "fixture failure".into(),
        };
        claims[1].result = EvidenceResult::NotRun;
        if untested {
            claims[1].tested_artifact_sha256.clear();
        }
        let index = index(binding, claims, EvidenceOrigin::Actual).unwrap();
        let report = evaluate(&evidence, Some(&index));
        assert!(!report.eligible);
        assert!(has(&report, "ACCEPTANCE_FAILED"));
        assert!(has(&report, "ACCEPTANCE_NOT_RUN"));
        assert_eq!(report.missing_test_ids.len(), 2);
    }
    for result in [
        EvidenceResult::Passed,
        EvidenceResult::Failed {
            reason: "fixture failure".into(),
        },
    ] {
        let (_, binding, mut claims) = release_fixture();
        claims[0].result = result;
        claims[0].tested_artifact_sha256.clear();
        assert!(index(binding, claims, EvidenceOrigin::Actual).is_err());
    }
    for invalid in 0..3 {
        let (_, binding, mut claims) = release_fixture();
        claims[0].result = EvidenceResult::NotRun;
        claims[0].tested_artifact_sha256.clear();
        match invalid {
            0 => claims[0].result_artifact_sha256.clear(),
            1 => claims[0].binding.frozen_source_sha = "8".repeat(40),
            _ => {
                claims[0].tested_artifact_sha256.insert("8".repeat(64));
            }
        }
        assert!(index(binding, claims, EvidenceOrigin::Actual).is_err());
    }
    let (_, binding, mut claims) = release_fixture();
    let mut claim = claims.remove(0);
    let original = material("fixture-original-claim", &claim);
    claim.result = EvidenceResult::NotRun;
    claim.tested_artifact_sha256.clear();
    assert!(
        VerifiedEvidenceIndex::verify(
            binding,
            vec![(claim, original)],
            &FixtureVerifier(EvidenceOrigin::Actual),
        )
        .is_err()
    );
}

#[test]
fn each_actual_server_basic_manual_client_and_windows_full_scope_is_mandatory() {
    for missing in [
        ReleaseProofKind::ActualServer {
            os: ReleaseOs::MacosArm64,
            target_profile_id: "java-26.3".into(),
        },
        ReleaseProofKind::ManualClientBasic {
            os: ReleaseOs::LinuxX64,
            target_profile_id: "java-26.3".into(),
        },
        ReleaseProofKind::WindowsVisualInteractionMultiplayer {
            target_profile_id: "java-26.3".into(),
        },
        ReleaseProofKind::VanillaOutput {
            target_profile_id: "java-26.3".into(),
        },
    ] {
        let (evidence, binding, mut claims) = release_fixture();
        claims.retain(|claim| claim.kind != missing);
        let index = index(binding, claims, EvidenceOrigin::Actual).unwrap();
        let report = evaluate(&evidence, Some(&index));
        assert!(!report.eligible);
        assert!(has(&report, "RELEASE_CHECK_NOT_RUN"));
    }
}

#[test]
fn runtime_proof_must_use_os_release_bytes_and_independent_oracle() {
    let (evidence, binding, mut claims) = release_fixture();
    let claim = claims
        .iter_mut()
        .find(|claim| {
            matches!(
                claim.kind,
                ReleaseProofKind::ActualServer {
                    os: ReleaseOs::WindowsX64,
                    ..
                }
            )
        })
        .unwrap();
    claim.tested_artifact_sha256.remove(&"b".repeat(64));
    claim.independent_oracle = false;
    let index = index(binding, claims, EvidenceOrigin::Actual).unwrap();
    let report = evaluate(&evidence, Some(&index));
    assert!(has(&report, "TESTED_PLATFORM_BYTES_MISMATCH"));
    assert!(has(&report, "RELEASE_CHECK_SCOPE_INCOMPLETE"));
}

#[test]
fn runtime_pin_labels_without_actually_tested_game_and_host_bytes_are_insufficient() {
    let (evidence, binding, mut claims) = release_fixture();
    let claim = claims
        .iter_mut()
        .find(|claim| {
            matches!(
                claim.kind,
                ReleaseProofKind::ActualServer {
                    os: ReleaseOs::LinuxX64,
                    ..
                }
            )
        })
        .unwrap();
    claim.tested_artifact_sha256.remove(&"5".repeat(64));
    let index = index(binding, claims, EvidenceOrigin::Actual).unwrap();
    let report = evaluate(&evidence, Some(&index));
    assert!(!report.eligible);
    assert!(has(&report, "TARGET_TESTED_BYTES_MISMATCH"));
}

#[test]
fn vanilla_sbom_and_notice_proofs_must_exercise_exact_shipped_files() {
    for (kind, digest) in [
        (ReleaseProofKind::Sbom, "e"),
        (ReleaseProofKind::Notice, "f"),
        (
            ReleaseProofKind::VanillaOutput {
                target_profile_id: "java-26.3".into(),
            },
            "1",
        ),
    ] {
        let (evidence, binding, mut claims) = release_fixture();
        claims
            .iter_mut()
            .find(|claim| claim.kind == kind)
            .unwrap()
            .tested_artifact_sha256
            .remove(&digest.repeat(64));
        let index = index(binding, claims, EvidenceOrigin::Actual).unwrap();
        let report = evaluate(&evidence, Some(&index));
        assert!(!report.eligible);
        assert!(has(&report, "INVENTORY_REVIEW_BYTES_MISMATCH"));
    }
}

#[test]
fn first_release_has_one_exact_profile_and_real_utc_observation_time() {
    let (_, mut binding, claims) = release_fixture();
    binding.targets.insert(
        "second-profile".into(),
        binding.targets["java-26.3"].clone(),
    );
    assert!(index(binding, claims, EvidenceOrigin::Actual).is_err());
    for timestamp in [
        "2026-02-30T00:00:00Z",
        "2026-10-14T24:00:00Z",
        "not-an-actual-T-timestamp",
    ] {
        let (_, binding, mut claims) = release_fixture();
        claims[0].timestamp = timestamp.into();
        assert!(index(binding, claims, EvidenceOrigin::Actual).is_err());
    }
}

#[test]
fn unresolved_operation_cannot_be_erased_by_caller() {
    let (evidence, binding, mut claims) = release_fixture();
    claims
        .iter_mut()
        .find(|claim| claim.kind == ReleaseProofKind::OperationJournalReview)
        .unwrap()
        .unresolved_operations
        .push("fixture-pending-operation".into());
    let index = index(binding, claims, EvidenceOrigin::Actual).unwrap();
    let report = evaluate(&evidence, Some(&index));
    assert!(has(&report, "UNRESOLVED_OPERATIONS"));
    assert!(has(&report, "OPERATION_CLAIM_MISMATCH"));
}

#[test]
fn rights_audit_covers_actual_transitive_components_and_assets() {
    let (evidence, binding, mut claims) = release_fixture();
    claims
        .iter_mut()
        .find(|claim| claim.kind == ReleaseProofKind::RightsReview)
        .unwrap()
        .components
        .pop();
    let index = index(binding, claims, EvidenceOrigin::Actual).unwrap();
    let report = evaluate(&evidence, Some(&index));
    assert!(!report.eligible);
    assert!(has(&report, "RIGHTS_INVENTORY_MISMATCH"));
}

#[test]
fn mvp_vendor_original_runtime_is_allowed_but_must_be_disclosed() {
    let (mut evidence, binding, mut claims) = release_fixture();
    let mut vendor = candidate(DependencyClassification::TemporaryDomainVendor);
    vendor.component_id = "fixture-temporary-vendor".into();
    vendor.language = "Python".into();
    vendor.phase = VendorPhase::Characterised;
    for claim in &mut claims {
        if matches!(
            claim.kind,
            ReleaseProofKind::RightsReview | ReleaseProofKind::DependencyGraphReview
        ) {
            claim.components.push(vendor.clone());
        }
    }
    evidence
        .domain_vendors_remaining
        .push(vendor.component_id.clone());
    let index = index(binding, claims, EvidenceOrigin::Actual).unwrap();
    let undisclosed = evaluate(&evidence, Some(&index));
    assert!(!undisclosed.eligible);
    assert!(has(&undisclosed, "COMPONENT_CLAIM_MISMATCH"));
    evidence.non_rust_domain_runtimes.push(vendor.component_id);
    assert!(evaluate(&evidence, Some(&index)).eligible);
}

#[test]
fn empty_audit_and_self_claimed_candidate_components_block_release() {
    for mode in 0..2 {
        let (evidence, binding, mut claims) = release_fixture();
        for claim in &mut claims {
            if matches!(
                claim.kind,
                ReleaseProofKind::RightsReview | ReleaseProofKind::DependencyGraphReview
            ) {
                if mode == 0 {
                    claim.components.clear();
                } else {
                    claim.components[0].phase = VendorPhase::Candidate;
                }
            }
        }
        let index = index(binding, claims, EvidenceOrigin::Actual).unwrap();
        let report = evaluate(&evidence, Some(&index));
        assert!(!report.eligible);
        assert!(has(
            &report,
            if mode == 0 {
                "DEPENDENCY_INVENTORY_EMPTY"
            } else {
                "COMPONENT_ADMISSION_UNVERIFIED"
            }
        ));
    }
}

#[test]
fn artifact_paths_sizes_collisions_and_inventory_digest_are_checked() {
    for path in [
        "../escape",
        "C:/escape",
        "x\\escape",
        "CON.txt",
        "x//escape",
        "x/escape.",
    ] {
        let mut entries = inventory();
        entries[0].path = path.into();
        assert!(artifact_inventory_digest(&entries).is_err(), "{path}");
    }
    let mut entries = inventory();
    let mut collision = entries[0].clone();
    collision.path = collision.path.to_uppercase();
    entries.push(collision);
    assert!(artifact_inventory_digest(&entries).is_err());
    let (_, binding, mut claims) = release_fixture();
    claims
        .iter_mut()
        .find(|claim| claim.kind == ReleaseProofKind::ArtifactInventory)
        .unwrap()
        .inventory[0]
        .sha256 = "8".repeat(64);
    assert!(index(binding, claims, EvidenceOrigin::Actual).is_err());
}

#[test]
fn inventory_path_preflight_shares_contract_and_file_roster_checks_ancestors() {
    let entries = inventory();
    let paths: Vec<&str> = entries.iter().map(|entry| entry.path.as_str()).collect();
    assert!(validate_artifact_inventory_paths(&paths).is_ok());
    assert!(validate_artifact_file_roster(&paths).is_ok());
    assert!(validate_artifact_file_roster(&["build/output.zip"]).is_ok());
    assert!(validate_artifact_file_roster(&["a", "ab/child"]).is_ok());
    assert!(validate_artifact_file_roster(&["a/one", "a/two"]).is_ok());

    for paths in [
        vec!["../escape"],
        vec!["same", "same"],
        vec!["windows/file", "WINDOWS/FILE"],
        vec!["caf\u{e9}", "cafe\u{301}"],
    ] {
        assert!(validate_artifact_inventory_paths(&paths).is_err());
        assert!(validate_artifact_file_roster(&paths).is_err());
    }
    assert!(validate_artifact_inventory_paths(&[]).is_err());
    assert!(validate_artifact_inventory_paths(&vec!["file"; 4097]).is_err());

    for paths in [
        ["a", "a/child"],
        ["A", "a/child"],
        ["caf\u{e9}", "CAFE\u{301}/child"],
    ] {
        assert!(validate_artifact_inventory_paths(&paths).is_ok());
        assert!(validate_artifact_file_roster(&paths).is_err());
        let mut existing = inventory();
        existing.truncate(2);
        existing[0].path = paths[0].into();
        existing[1].path = paths[1].into();
        assert!(artifact_inventory_digest(&existing).is_ok());
    }
}

#[test]
fn contradictory_duplicate_proofs_are_rejected_without_last_writer_wins() {
    let (_, binding, mut claims) = release_fixture();
    let mut duplicate = claims[0].clone();
    duplicate.result = EvidenceResult::NotRun;
    claims.push(duplicate);
    assert!(index(binding, claims, EvidenceOrigin::Actual).is_err());
}

#[test]
fn wire_enum_unknown_field_and_overlapping_result_claims_fail_closed() {
    let (evidence, _, _) = release_fixture();
    let mut bad = serde_json::to_value(&evidence).unwrap();
    bad["stage"] = json!("v2");
    assert!(release_evaluate(&bad).is_err());
    bad = serde_json::to_value(&evidence).unwrap();
    bad["verified"] = Value::Bool(true);
    assert!(release_evaluate(&bad).is_err());
    let mut evidence = evidence;
    evidence
        .not_run_test_ids
        .push(evidence.passed_test_ids[0].clone());
    assert!(has(&evaluate(&evidence, None), "RELEASE_EVIDENCE_INVALID"));
}

#[test]
fn future_v1_scope_is_deferred_and_domain_vendors_are_explicitly_blocked() {
    let (mut evidence, _, _) = release_fixture();
    evidence.stage = ReleaseStage::V1;
    evidence
        .domain_vendors_remaining
        .push("fixture-temporary-vendor".into());
    let report = evaluate(&evidence, None);
    assert!(!report.eligible);
    assert!(has(&report, "RELEASE_STAGE_DEFERRED"));
    assert!(has(&report, "V1_DOMAIN_VENDOR_REMAINS"));
    assert_eq!(report.blocking_components, vec!["fixture-temporary-vendor"]);
}

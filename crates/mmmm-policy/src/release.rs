use crate::{
    DependencyClassification, DependencyDisposition, Diagnostic, EvidenceDomain, EvidenceOrigin,
    EvidenceResult, GateReport, PolicyError, ProofMaterial, ReleaseClaim, ReleaseEvidence,
    ReleaseStage, TrustedEvidenceVerifier, VendorPhase, decode,
    evidence::{authenticate, sha256, source_sha, stable_id},
    wire,
};
use mmmm_contracts::{CONTRACT_VERSION, canonical_digest, parse_json};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseOs {
    WindowsX64,
    LinuxX64,
    MacosArm64,
}

const RELEASE_OSES: [ReleaseOs; 3] = [
    ReleaseOs::WindowsX64,
    ReleaseOs::LinuxX64,
    ReleaseOs::MacosArm64,
];

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TargetArtifactBinding {
    pub game_version: String,
    pub profile_sha256: String,
    pub game_artifact_sha256: String,
    pub loader_artifact_sha256: String,
    pub host_artifact_sha256: String,
}

/// Internal immutable release input. The collector obtains these pins from the
/// actual frozen source and output bytes, never from the wire claim arrays.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseBinding {
    pub frozen_source_sha: String,
    pub contract_version: String,
    pub product_version: String,
    pub bundle_sha256: String,
    pub inventory_sha256: String,
    pub targets: BTreeMap<String, TargetArtifactBinding>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum ArtifactRole {
    ReleaseArchive,
    PlatformBundle { os: ReleaseOs },
    Sbom,
    Notice,
    VanillaOutput { target_profile_id: String },
    Other,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseArtifact {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub role: ArtifactRole,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReleaseProofKind {
    Acceptance {
        test_id: String,
    },
    ActualServer {
        os: ReleaseOs,
        target_profile_id: String,
    },
    ManualClientBasic {
        os: ReleaseOs,
        target_profile_id: String,
    },
    WindowsVisualInteractionMultiplayer {
        target_profile_id: String,
    },
    VanillaOutput {
        target_profile_id: String,
    },
    ArtifactInventory,
    Sbom,
    Notice,
    RightsReview,
    DependencyGraphReview,
    OperationJournalReview,
}

/// An evidence claim is authenticated as a whole, including all actual result
/// artifacts, limitations, source/target bindings and the result status.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseProofClaim {
    pub binding: ReleaseBinding,
    pub kind: ReleaseProofKind,
    pub result: EvidenceResult,
    pub runner: String,
    pub timestamp: String,
    pub independent_oracle: bool,
    pub tested_artifact_sha256: BTreeSet<String>,
    pub result_artifact_sha256: BTreeSet<String>,
    pub limitations: Vec<String>,
    /// Present only on the inventory proof; exact inventory digest is checked.
    pub inventory: Vec<ReleaseArtifact>,
    /// Present only on the actual dependency graph/rights review. Components
    /// include all native/transitive components and output assets/templates.
    pub components: Vec<DependencyDisposition>,
    /// Present only on the journal review. Empty is an authenticated observation,
    /// not an inference from the caller's unresolvedOperations array.
    pub unresolved_operations: Vec<String>,
}

/// An authenticated index has no Deserialize or unchecked constructor. The
/// application's collector/verifier owns evidence authenticity and actual game
/// observation, this pure evaluator owns completeness and binding consistency.
pub struct VerifiedEvidenceIndex {
    binding: ReleaseBinding,
    proofs: BTreeMap<ReleaseProofKind, ReleaseProofClaim>,
    synthetic: bool,
}

impl VerifiedEvidenceIndex {
    pub fn verify(
        expected: ReleaseBinding,
        records: Vec<(ReleaseProofClaim, ProofMaterial)>,
        verifier: &dyn TrustedEvidenceVerifier,
    ) -> Result<Self, PolicyError> {
        validate_binding(&expected)?;
        if records.len() > 1024
            || records
                .iter()
                .map(|(_, material)| material.bytes.len())
                .sum::<usize>()
                > 16_777_216
        {
            return Err(invalid(
                "Evidence index exceeds its finite record/byte limit",
            ));
        }
        let mut proofs = BTreeMap::new();
        let mut references = BTreeSet::new();
        let mut synthetic = false;
        for (claim, material) in records {
            if claim.binding != expected {
                return Err(invalid(
                    "Evidence is not bound to the exact frozen source, bundle bytes, inventory and target artifacts",
                ));
            }
            validate_claim(&claim)?;
            if !references.insert(material.reference.clone()) || proofs.contains_key(&claim.kind) {
                return Err(invalid(
                    "Duplicate proof kind or evidence reference; conflicting evidence cannot be overwritten",
                ));
            }
            synthetic |= authenticate(EvidenceDomain::Release, &claim, &material, verifier)
                .map_err(|error| invalid(error.message))?
                == EvidenceOrigin::Synthetic;
            proofs.insert(claim.kind.clone(), claim);
        }
        Ok(Self {
            binding: expected,
            proofs,
            synthetic,
        })
    }

    pub fn binding(&self) -> &ReleaseBinding {
        &self.binding
    }
}

fn invalid(message: impl Into<String>) -> PolicyError {
    PolicyError::new("RELEASE_EVIDENCE_INVALID", message)
}

fn validate_binding(binding: &ReleaseBinding) -> Result<(), PolicyError> {
    if !source_sha(&binding.frozen_source_sha)
        || binding.contract_version != CONTRACT_VERSION
        || binding.product_version != "0.1.0"
        || !sha256(&binding.bundle_sha256)
        || !sha256(&binding.inventory_sha256)
        || binding.targets.len() != 1
    {
        return Err(invalid(
            "Release binding requires exact frozen SHA, product 0.1.0, contract, bundle, inventory and targets",
        ));
    }
    for (id, target) in &binding.targets {
        if !stable_id(id)
            || target.game_version != "26.3"
            || ![
                &target.profile_sha256,
                &target.game_artifact_sha256,
                &target.loader_artifact_sha256,
                &target.host_artifact_sha256,
            ]
            .iter()
            .all(|digest| sha256(digest))
        {
            return Err(invalid(
                "A target must pin the actual Java 26.3 profile, game, loader and host artifact digests",
            ));
        }
    }
    Ok(())
}

fn validate_claim(claim: &ReleaseProofClaim) -> Result<(), PolicyError> {
    // A retained not-run result does not claim that any artifact was tested.
    // Its frozen binding, result bytes and producer authentication still apply.
    let untested_not_run =
        matches!(&claim.result, EvidenceResult::NotRun) && claim.tested_artifact_sha256.is_empty();
    if claim.runner.trim().is_empty()
        || claim.runner.len() > 256
        || !timestamp_utc(&claim.timestamp)
        || claim.limitations.len() > 128
        || claim
            .limitations
            .iter()
            .any(|item| item.is_empty() || item.len() > 4096)
        || (!untested_not_run && claim.tested_artifact_sha256.is_empty())
        || claim.tested_artifact_sha256.len() > 128
        || claim.result_artifact_sha256.is_empty()
        || claim.result_artifact_sha256.len() > 128
        || !claim
            .tested_artifact_sha256
            .iter()
            .chain(&claim.result_artifact_sha256)
            .all(|digest| sha256(digest))
        || (!untested_not_run
            && !claim
                .tested_artifact_sha256
                .contains(&claim.binding.bundle_sha256))
        || claim.inventory.len() > 4096
        || claim.components.len() > 4096
        || claim.unresolved_operations.len() > 1024
    {
        return Err(invalid(
            "Proof lacks bounded runner, timestamp, exact tested bundle bytes or result artifact digests",
        ));
    }
    if let EvidenceResult::Failed { reason } = &claim.result
        && (reason.trim().is_empty() || reason.len() > 4096)
    {
        return Err(invalid("A failed proof requires its actual bounded reason"));
    }
    match &claim.kind {
        ReleaseProofKind::Acceptance { test_id } => {
            if !mvp_required_test_ids()?.contains(test_id) {
                return Err(invalid(
                    "Acceptance proof is outside the current 82 MVP requirements",
                ));
            }
        }
        ReleaseProofKind::ActualServer {
            target_profile_id, ..
        }
        | ReleaseProofKind::ManualClientBasic {
            target_profile_id, ..
        }
        | ReleaseProofKind::WindowsVisualInteractionMultiplayer { target_profile_id }
        | ReleaseProofKind::VanillaOutput { target_profile_id }
            if !claim.binding.targets.contains_key(target_profile_id) =>
        {
            return Err(invalid("Runtime proof targets an unbound profile"));
        }
        _ => {}
    }
    if matches!(claim.kind, ReleaseProofKind::ArtifactInventory) {
        if artifact_inventory_digest(&claim.inventory)? != claim.binding.inventory_sha256 {
            return Err(invalid(
                "Actual artifact inventory differs from frozen inventory digest",
            ));
        }
    } else if !claim.inventory.is_empty() {
        return Err(invalid(
            "Artifact inventory is only valid on its designated proof",
        ));
    }
    if matches!(
        claim.kind,
        ReleaseProofKind::DependencyGraphReview | ReleaseProofKind::RightsReview
    ) {
        let mut ids = BTreeSet::new();
        for component in &claim.components {
            wire("DependencyDisposition", component)?;
            if !ids.insert(&component.component_id) {
                return Err(invalid("Component audit repeats an ID"));
            }
        }
    } else if !claim.components.is_empty() {
        return Err(invalid(
            "Component audit data is only valid on dependency/rights review proofs",
        ));
    }
    if !matches!(claim.kind, ReleaseProofKind::OperationJournalReview)
        && !claim.unresolved_operations.is_empty()
    {
        return Err(invalid(
            "Unresolved operation observations are only valid on the journal review",
        ));
    }
    if !claim.unresolved_operations.iter().all(|id| stable_id(id))
        || claim
            .unresolved_operations
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != claim.unresolved_operations.len()
    {
        return Err(invalid(
            "Journal proof contains invalid or duplicate operation IDs",
        ));
    }
    Ok(())
}

// Evidence time is an exact UTC observation, not an arbitrary nonempty label.
// Keep the admitted format deterministic and locale independent.
fn timestamp_utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || !bytes
            .iter()
            .enumerate()
            .all(|(i, b)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || b.is_ascii_digit())
    {
        return false;
    }
    let parse = |start, end| value[start..end].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        parse(0, 4),
        parse(5, 7),
        parse(8, 10),
        parse(11, 13),
        parse(14, 16),
        parse(17, 19),
    ) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    year >= 1970 && day > 0 && day <= days && hour < 24 && minute < 60 && second < 60
}

/// Canonical digest of sorted inventory entries; no filesystem is read here.
/// The collector verifies all actual bytes, including archive extraction, rights
/// and inventory closure, before its trusted verifier authenticates the proof.
pub fn artifact_inventory_digest(artifacts: &[ReleaseArtifact]) -> Result<String, PolicyError> {
    validate_inventory_paths(
        artifacts.len(),
        artifacts.iter().map(|entry| entry.path.as_str()),
    )?;
    let mut sorted = artifacts.to_vec();
    sorted.sort_by(|left, right| left.path.cmp(&right.path));
    for artifact in &sorted {
        if !sha256(&artifact.sha256) || artifact.bytes == 0 || artifact.bytes > 8_589_934_592 {
            return Err(invalid(
                "Inventory has a traversal/link-like path, collision, unknown bytes or invalid digest",
            ));
        }
    }
    let value = serde_json::to_value(sorted).map_err(|error| invalid(error.to_string()))?;
    canonical_digest(&value)
        .map(|digest| digest.into_string())
        .map_err(|error| invalid(error.to_string()))
}

/// Check only the explicit path roster against the inventory path contract.
/// This does not inspect files, links, permissions, bytes, or release evidence.
/// The contract permits a path that is an ancestor of another path; a collector
/// must separately reject that conflict before treating both as files.
pub fn validate_artifact_inventory_paths(paths: &[&str]) -> Result<(), PolicyError> {
    validate_inventory_paths(paths.len(), paths.iter().copied())
}

/// Validate a roster whose entries will each be collected as files.
/// This adds an ancestor conflict check to the inventory path contract, but
/// does not inspect the filesystem or establish any release evidence.
pub fn validate_artifact_file_roster(paths: &[&str]) -> Result<(), PolicyError> {
    validate_artifact_inventory_paths(paths)?;
    let names: BTreeSet<String> = paths.iter().map(|path| portable_key(path)).collect();
    for name in &names {
        for (index, _) in name.match_indices('/') {
            if names.contains(&name[..index]) {
                return Err(invalid("Inventory file path has a file ancestor"));
            }
        }
    }
    Ok(())
}

fn validate_inventory_paths<'a>(
    count: usize,
    paths: impl Iterator<Item = &'a str>,
) -> Result<(), PolicyError> {
    if count == 0 || count > 4096 {
        return Err(invalid("Inventory must be nonempty and bounded"));
    }
    let mut names = BTreeSet::new();
    for path in paths {
        if !portable_path(path) || !names.insert(portable_key(path)) {
            return Err(invalid(
                "Inventory has a traversal/link-like path, collision, unknown bytes or invalid digest",
            ));
        }
    }
    Ok(())
}

fn portable_key(path: &str) -> String {
    path.nfc()
        .flat_map(char::to_lowercase)
        .flat_map(char::to_uppercase)
        .collect::<String>()
        .nfc()
        .collect()
}

fn portable_path(path: &str) -> bool {
    if path.is_empty()
        || path.len() > 1024
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .chars()
            .any(|ch| ch.is_control() || "<>:\"|?*".contains(ch))
    {
        return false;
    }
    path.split('/').all(|part| {
        if part.is_empty()
            || matches!(part, "." | "..")
            || part.ends_with('.')
            || part.ends_with(' ')
        {
            return false;
        }
        let base = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        !matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            && !(base.len() == 4
                && (base.starts_with("COM") || base.starts_with("LPT"))
                && matches!(base.as_bytes()[3], b'1'..=b'9'))
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AcceptanceIndex {
    status: String,
    test_ids: Vec<String>,
    passed_in_this_package: Vec<String>,
}

/// The handoff's planned IDs are requirements only. Its empty pass list is
/// deliberately not imported as an evidence index.
pub fn mvp_required_test_ids() -> Result<BTreeSet<String>, PolicyError> {
    let value = parse_json(include_bytes!("../../../tests/acceptance-index.json"))
        .map_err(|error| invalid(error.to_string()))?;
    let index: AcceptanceIndex =
        serde_json::from_value(value).map_err(|error| invalid(error.to_string()))?;
    if index.status != "planned_product_tests"
        || !index.passed_in_this_package.is_empty()
        || index.test_ids.len() != 94
    {
        return Err(invalid(
            "Original acceptance index scope/status changed; review required",
        ));
    }
    let mut all = BTreeSet::new();
    let mut required = BTreeSet::new();
    for id in index.test_ids {
        if !all.insert(id.clone()) {
            return Err(invalid("Original acceptance index repeats an ID"));
        }
        if !id.starts_with("V1") {
            required.insert(id);
        }
    }
    if required.len() != 82 {
        return Err(invalid(
            "MVP acceptance scope must contain the original 82 A-G requirements",
        ));
    }
    Ok(required)
}

pub fn release_evaluate(input: &Value) -> Result<Value, PolicyError> {
    release_evaluate_verified(input, None)
}

pub fn release_evaluate_verified(
    input: &Value,
    index: Option<&VerifiedEvidenceIndex>,
) -> Result<Value, PolicyError> {
    let evidence: ReleaseEvidence =
        decode("ReleaseEvidence", input).map_err(|error| invalid(error.message))?;
    wire("GateReport", &evaluate_release(&evidence, index)?)
}

fn evaluate_release(
    evidence: &ReleaseEvidence,
    index: Option<&VerifiedEvidenceIndex>,
) -> Result<GateReport, PolicyError> {
    let required = mvp_required_test_ids()?;
    let mut report = GateReport {
        eligible: false,
        missing_test_ids: Vec::new(),
        blocking_components: Vec::new(),
        diagnostics: Vec::new(),
    };
    let supplied: BTreeSet<_> = evidence.required_test_ids.iter().cloned().collect();
    if supplied != required {
        report.diagnostics.push(Diagnostic::error("REQUIRED_ACCEPTANCE_SCOPE_MISMATCH", "requiredTestIds must equal the original 82 MVP requirements; callers cannot reduce the release scope"));
    }
    if evidence.claim == ReleaseClaim::SpecificationOnly {
        report.diagnostics.push(Diagnostic::error(
            "SPECIFICATION_ONLY",
            "Specification-only evidence never authorizes a release",
        ));
    }
    if evidence.stage == ReleaseStage::V1 {
        report.diagnostics.push(Diagnostic::error(
            "RELEASE_STAGE_DEFERRED",
            "v1/G5/G6 evaluation remains outside the current MVP and v0.1.0 release scope",
        ));
        report
            .blocking_components
            .extend(evidence.domain_vendors_remaining.iter().cloned());
        if !evidence.domain_vendors_remaining.is_empty()
            || !evidence.non_rust_domain_runtimes.is_empty()
        {
            report.diagnostics.push(Diagnostic::error(
                "V1_DOMAIN_VENDOR_REMAINS",
                "v1 cannot retain active domain vendors or non-Rust domain runtimes",
            ));
        }
    }
    if evidence.product_version != "0.1.0" {
        report.diagnostics.push(Diagnostic::error(
            "PRODUCT_VERSION_MISMATCH",
            "The current release gate is bound to product 0.1.0",
        ));
    }
    if !evidence.unresolved_operations.is_empty() {
        report.diagnostics.push(Diagnostic::error(
            "UNRESOLVED_OPERATIONS_CLAIMED",
            "The caller reports unresolved writes; release remains blocked",
        ));
    }
    let mut claimed_results = BTreeMap::new();
    for (ids, status) in [
        (&evidence.passed_test_ids, "passed"),
        (&evidence.failed_test_ids, "failed"),
        (&evidence.not_run_test_ids, "not_run"),
    ] {
        for id in ids {
            if !required.contains(id) || claimed_results.insert(id.clone(), status).is_some() {
                report.diagnostics.push(Diagnostic::error(
                    "RELEASE_EVIDENCE_INVALID",
                    format!("Unknown or overlapping test result claim: {id}"),
                ));
            }
        }
    }
    let Some(index) = index else {
        report.missing_test_ids = required.into_iter().collect();
        report.diagnostics.push(Diagnostic::error("VERIFIED_EVIDENCE_MISSING", "Caller pass arrays, bundle digest, CI dispatch, and PR existence do not supply authenticated actual release evidence"));
        if !evidence.failed_test_ids.is_empty() {
            report.diagnostics.push(Diagnostic::error(
                "TEST_FAILED_CLAIMED",
                "The caller reports failed tests; failure is distinct from not_run",
            ));
        }
        if !evidence.not_run_test_ids.is_empty() {
            report.diagnostics.push(Diagnostic::error(
                "TEST_NOT_RUN_CLAIMED",
                "The caller reports tests not run; no success evidence exists",
            ));
        }
        return Ok(report);
    };
    if index.synthetic {
        report.diagnostics.push(Diagnostic::error(
            "SYNTHETIC_EVIDENCE",
            "Synthetic fixtures do not authorize an actual product release",
        ));
    }
    let binding = &index.binding;
    if evidence.contract_version != binding.contract_version
        || evidence.product_version != binding.product_version
        || evidence.bundle_sha256.as_ref() != Some(&binding.bundle_sha256)
        || evidence
            .target_profiles
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != binding.targets.keys().cloned().collect()
    {
        report.diagnostics.push(Diagnostic::error("RELEASE_BINDING_MISMATCH", "Wire evidence differs from the authenticated frozen release bundle and exact target profiles"));
    }
    for id in &required {
        let kind = ReleaseProofKind::Acceptance {
            test_id: id.clone(),
        };
        let status = match index.proofs.get(&kind).map(|proof| &proof.result) {
            Some(EvidenceResult::Passed) => "passed",
            Some(EvidenceResult::Failed { .. }) => "failed",
            Some(EvidenceResult::NotRun) | None => "not_run",
        };
        if status != "passed" {
            report.missing_test_ids.push(id.clone());
            report.diagnostics.push(Diagnostic::error(
                if status == "failed" {
                    "ACCEPTANCE_FAILED"
                } else {
                    "ACCEPTANCE_NOT_RUN"
                },
                format!("{id}: {status}"),
            ));
        }
        if claimed_results.get(id).copied() != Some(status) {
            report.diagnostics.push(Diagnostic::error(
                "TEST_RESULT_CLAIM_MISMATCH",
                format!("{id}: wire claim differs from authenticated {status} result"),
            ));
        }
        if let Some(proof) = index.proofs.get(&kind)
            && (!proof.independent_oracle || !proof.limitations.is_empty())
        {
            report.diagnostics.push(Diagnostic::error(
                "ACCEPTANCE_SCOPE_INCOMPLETE",
                format!(
                    "{id}: independent expected/actual observation is absent or limitations remain"
                ),
            ));
        }
    }
    let inventory_proof = require_proof(index, &ReleaseProofKind::ArtifactInventory, &mut report);
    let mut platform_digests = BTreeMap::new();
    if let Some(inventory_proof) = inventory_proof {
        validate_inventory_roles(
            &inventory_proof.inventory,
            binding,
            &mut report,
            &mut platform_digests,
        );
        check_inventory_file_proofs(index, &inventory_proof.inventory, &mut report);
    }
    for kind in [
        ReleaseProofKind::Sbom,
        ReleaseProofKind::Notice,
        ReleaseProofKind::RightsReview,
        ReleaseProofKind::DependencyGraphReview,
        ReleaseProofKind::OperationJournalReview,
    ] {
        require_proof(index, &kind, &mut report);
    }
    for target_id in binding.targets.keys() {
        for os in RELEASE_OSES {
            for kind in [
                ReleaseProofKind::ActualServer {
                    os,
                    target_profile_id: target_id.clone(),
                },
                ReleaseProofKind::ManualClientBasic {
                    os,
                    target_profile_id: target_id.clone(),
                },
            ] {
                if let Some(proof) = require_proof(index, &kind, &mut report) {
                    check_target_tested_bytes(proof, target_id, true, &mut report);
                    if platform_digests
                        .get(&os)
                        .is_none_or(|digest| !proof.tested_artifact_sha256.contains(digest))
                    {
                        report.diagnostics.push(Diagnostic::error("TESTED_PLATFORM_BYTES_MISMATCH", format!("{kind:?}: actual tested platform bundle bytes differ from release inventory")));
                    }
                }
            }
        }
        let visual = ReleaseProofKind::WindowsVisualInteractionMultiplayer {
            target_profile_id: target_id.clone(),
        };
        if let Some(proof) = require_proof(index, &visual, &mut report) {
            check_target_tested_bytes(proof, target_id, true, &mut report);
            if platform_digests
                .get(&ReleaseOs::WindowsX64)
                .is_none_or(|digest| !proof.tested_artifact_sha256.contains(digest))
            {
                report.diagnostics.push(Diagnostic::error("WINDOWS_TESTED_BYTES_MISMATCH", "Windows visual, interaction and multiplayer proof must exercise the actual Windows release bundle"));
            }
        }
        if let Some(proof) = require_proof(
            index,
            &ReleaseProofKind::VanillaOutput {
                target_profile_id: target_id.clone(),
            },
            &mut report,
        ) {
            check_target_tested_bytes(proof, target_id, false, &mut report);
        }
    }
    check_audits(evidence, index, &mut report);
    report.blocking_components.sort();
    report.blocking_components.dedup();
    report.eligible = report.diagnostics.is_empty()
        && report.missing_test_ids.is_empty()
        && report.blocking_components.is_empty();
    Ok(report)
}

fn check_target_tested_bytes(
    proof: &ReleaseProofClaim,
    target_id: &str,
    host_runtime: bool,
    report: &mut GateReport,
) {
    let target = &proof.binding.targets[target_id];
    let mut expected = vec![&target.profile_sha256, &target.game_artifact_sha256];
    if host_runtime {
        expected.extend([&target.loader_artifact_sha256, &target.host_artifact_sha256]);
    }
    if expected
        .iter()
        .any(|digest| !proof.tested_artifact_sha256.contains(*digest))
    {
        report.diagnostics.push(Diagnostic::error("TARGET_TESTED_BYTES_MISMATCH", format!("{:?}: the actual tested profile/game/loader/host bytes are not the frozen target artifacts", proof.kind)));
    }
}

fn check_inventory_file_proofs(
    index: &VerifiedEvidenceIndex,
    inventory: &[ReleaseArtifact],
    report: &mut GateReport,
) {
    for artifact in inventory {
        let kind = match &artifact.role {
            ArtifactRole::Sbom => ReleaseProofKind::Sbom,
            ArtifactRole::Notice => ReleaseProofKind::Notice,
            ArtifactRole::VanillaOutput { target_profile_id } => ReleaseProofKind::VanillaOutput {
                target_profile_id: target_profile_id.clone(),
            },
            _ => continue,
        };
        if index
            .proofs
            .get(&kind)
            .is_none_or(|proof| !proof.tested_artifact_sha256.contains(&artifact.sha256))
        {
            report.diagnostics.push(Diagnostic::error(
                "INVENTORY_REVIEW_BYTES_MISMATCH",
                format!(
                    "{}: proof does not review or test the exact shipped artifact bytes",
                    artifact.path
                ),
            ));
        }
    }
}

fn require_proof<'a>(
    index: &'a VerifiedEvidenceIndex,
    kind: &ReleaseProofKind,
    report: &mut GateReport,
) -> Option<&'a ReleaseProofClaim> {
    let Some(proof) = index.proofs.get(kind) else {
        report.diagnostics.push(Diagnostic::error(
            "RELEASE_CHECK_NOT_RUN",
            format!("{kind:?}: authenticated actual proof is absent"),
        ));
        return None;
    };
    match &proof.result {
        EvidenceResult::Passed => {}
        EvidenceResult::Failed { reason } => report.diagnostics.push(Diagnostic::error(
            "RELEASE_CHECK_FAILED",
            format!("{kind:?}: {reason}"),
        )),
        EvidenceResult::NotRun => report.diagnostics.push(Diagnostic::error(
            "RELEASE_CHECK_NOT_RUN",
            format!("{kind:?}: not_run"),
        )),
    }
    if !proof.independent_oracle || !proof.limitations.is_empty() {
        report.diagnostics.push(Diagnostic::error(
            "RELEASE_CHECK_SCOPE_INCOMPLETE",
            format!("{kind:?}: independent observation/review missing or limitations remain"),
        ));
    }
    Some(proof)
}

fn validate_inventory_roles(
    inventory: &[ReleaseArtifact],
    binding: &ReleaseBinding,
    report: &mut GateReport,
    platforms: &mut BTreeMap<ReleaseOs, String>,
) {
    let mut archive_count = 0;
    let mut sbom_count = 0;
    let mut notice_count = 0;
    let mut vanilla = BTreeSet::new();
    for artifact in inventory {
        match &artifact.role {
            ArtifactRole::ReleaseArchive => {
                archive_count += 1;
                if artifact.sha256 != binding.bundle_sha256 {
                    report.diagnostics.push(Diagnostic::error(
                        "ARCHIVE_DIGEST_MISMATCH",
                        "Release archive bytes differ from frozen bundle SHA-256",
                    ));
                }
            }
            ArtifactRole::PlatformBundle { os } => {
                if platforms.insert(*os, artifact.sha256.clone()).is_some() {
                    report.diagnostics.push(Diagnostic::error(
                        "DUPLICATE_PLATFORM_ARTIFACT",
                        "Release inventory repeats an OS platform bundle",
                    ));
                }
            }
            ArtifactRole::Sbom => sbom_count += 1,
            ArtifactRole::Notice => notice_count += 1,
            ArtifactRole::VanillaOutput { target_profile_id } => {
                vanilla.insert(target_profile_id.clone());
            }
            ArtifactRole::Other => {}
        }
    }
    if archive_count != 1
        || sbom_count == 0
        || notice_count == 0
        || platforms.len() != 3
        || !RELEASE_OSES.iter().all(|os| platforms.contains_key(os))
        || vanilla != binding.targets.keys().cloned().collect()
    {
        report.diagnostics.push(Diagnostic::error("ARTIFACT_INVENTORY_INCOMPLETE", "Inventory requires one frozen archive, three OS bundles, SBOM, NOTICE and vanilla outputs for every exact target"));
    }
}

fn check_audits(
    evidence: &ReleaseEvidence,
    index: &VerifiedEvidenceIndex,
    report: &mut GateReport,
) {
    if let Some(journal) = index.proofs.get(&ReleaseProofKind::OperationJournalReview) {
        if !journal.unresolved_operations.is_empty() {
            report.diagnostics.push(Diagnostic::error("UNRESOLVED_OPERATIONS", "Authenticated operation journal contains unresolved writes; publication is blocked"));
        }
        if evidence
            .unresolved_operations
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != journal.unresolved_operations.iter().cloned().collect()
        {
            report.diagnostics.push(Diagnostic::error(
                "OPERATION_CLAIM_MISMATCH",
                "Caller operation list differs from authenticated journal observation",
            ));
        }
    }
    let Some(graph) = index.proofs.get(&ReleaseProofKind::DependencyGraphReview) else {
        return;
    };
    let Some(rights) = index.proofs.get(&ReleaseProofKind::RightsReview) else {
        return;
    };
    let graph_components: BTreeMap<_, _> = graph
        .components
        .iter()
        .map(|item| (&item.component_id, item))
        .collect();
    let rights_components: BTreeMap<_, _> = rights
        .components
        .iter()
        .map(|item| (&item.component_id, item))
        .collect();
    if graph_components != rights_components {
        report.diagnostics.push(Diagnostic::error("RIGHTS_INVENTORY_MISMATCH", "Rights review must cover every exact native/transitive dependency and shipped asset/template in the actual dependency inventory"));
    }
    if graph_components.is_empty() {
        report.diagnostics.push(Diagnostic::error(
            "DEPENDENCY_INVENTORY_EMPTY",
            "A Rust/JVM release cannot claim an empty actual dependency and rights inventory",
        ));
    }
    let mut vendors = BTreeSet::new();
    let mut shims = BTreeSet::new();
    let mut non_rust = BTreeSet::new();
    for component in &graph.components {
        if !component.production_reachable {
            continue;
        }
        if matches!(
            component.phase,
            VendorPhase::Candidate | VendorPhase::Retired
        ) || component.evidence_refs.is_empty()
        {
            report
                .blocking_components
                .push(component.component_id.clone());
            report.diagnostics.push(Diagnostic::error(
                "COMPONENT_ADMISSION_UNVERIFIED",
                format!(
                    "{}: actual production component lacks current admission evidence",
                    component.component_id
                ),
            ));
        }
        match component.classification {
            DependencyClassification::TemporaryDomainVendor => {
                vendors.insert(component.component_id.clone());
                if !component.language.eq_ignore_ascii_case("rust") {
                    non_rust.insert(component.component_id.clone());
                }
            }
            DependencyClassification::PlatformShim => {
                shims.insert(component.component_id.clone());
            }
            DependencyClassification::OwnedDomain
                if !component.language.eq_ignore_ascii_case("rust") =>
            {
                non_rust.insert(component.component_id.clone());
                report
                    .blocking_components
                    .push(component.component_id.clone());
                report.diagnostics.push(Diagnostic::error(
                    "NON_RUST_OWNED_DOMAIN",
                    "Owned domain responsibilities must be Rust in the current product",
                ));
            }
            DependencyClassification::TestOnlyReference => {
                report
                    .blocking_components
                    .push(component.component_id.clone());
                report.diagnostics.push(Diagnostic::error(
                    "TEST_REFERENCE_SHIPPED",
                    "Test-only reference is reachable in the shipped product",
                ));
            }
            _ => {}
        }
    }
    if evidence
        .domain_vendors_remaining
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        != vendors
        || evidence
            .approved_platform_shims
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != shims
        || evidence
            .non_rust_domain_runtimes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != non_rust
    {
        report.diagnostics.push(Diagnostic::error("COMPONENT_CLAIM_MISMATCH", "Wire component classifications differ from authenticated actual dependency graph and function-ownership review"));
    }
}

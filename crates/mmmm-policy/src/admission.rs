use crate::{
    AdmissionDecision, AdmissionOutcome, AdmissionRequest, DependencyClassification,
    DependencyDisposition, EvidenceDomain, EvidenceOrigin, PolicyError, ProofMaterial,
    TrustedEvidenceVerifier, VendorPhase, decode, evidence::authenticate, wire,
};
use mmmm_contracts::{CONTRACT_VERSION, parse_json};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionRequirement {
    SourceSnapshot,
    FileLicenses,
    TransitiveDependencies,
    Provenance,
    ContractCoverage,
    TargetCompatibility,
    BuildRun,
    IndependentBaseline,
    RightsReview,
    Permissions,
    OwnerReview,
    WorkerIsolation,
    ReplacementAcceptance,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EvidenceResult {
    Passed,
    Failed { reason: String },
    NotRun,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RightsDisposition {
    RedistributionAndModificationAllowed,
    UserExternalUseOnly,
    Denied,
    Unknown,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetCompatibility {
    Exact,
    IndependentContractSubset,
    ValidatedFormatConversion,
    DomainSemanticsMismatch,
    BroadVendorChangesRequired,
    Unknown,
}

/// Finite runtime ceilings are part of the reviewed worker evidence. These are
/// not installed/configured by the admission decision itself.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkerBudget {
    pub timeout_milliseconds: u32,
    pub memory_bytes: u64,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub max_processes: u32,
}

impl WorkerBudget {
    fn bounded(&self) -> bool {
        self.timeout_milliseconds > 0
            && self.timeout_milliseconds <= 3_600_000
            && self.memory_bytes > 0
            && self.memory_bytes <= 8_589_934_592
            && self.input_bytes > 0
            && self.input_bytes <= 1_073_741_824
            && self.output_bytes > 0
            && self.output_bytes <= 1_073_741_824
            && self.max_processes > 0
            && self.max_processes <= 64
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum WorkerDisposition {
    BoundedInProcess {
        budget: WorkerBudget,
    },
    BoundedSubprocess {
        budget: WorkerBudget,
        executable_sha256: String,
        argv_template_registered: bool,
        workspace_scoped: bool,
        environment_allowlisted: bool,
        network_scoped: bool,
        direct_live_access: bool,
    },
    UserInstalledTool {
        budget: WorkerBudget,
        selected_independently: bool,
        automatic_install: bool,
        execution_scoped: bool,
    },
    NotApplicable,
    Unknown,
}

/// This is an internal assertion to be authenticated as a whole. The verifier
/// must check source bytes, all file/transitive licenses, provenance and actual
/// build/characterisation evidence; strings in the candidate are not that proof.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionAttestation {
    pub request: AdmissionRequest,
    pub contract_version: String,
    pub target_game_version: String,
    pub requirements: BTreeMap<AdmissionRequirement, EvidenceResult>,
    pub rights: RightsDisposition,
    pub target_compatibility: TargetCompatibility,
    pub worker: WorkerDisposition,
    pub platform_boundary_only: bool,
    pub known_unmitigated_vulnerabilities: Vec<String>,
}

/// No Deserialize and no public field/unchecked constructor. A wire caller
/// cannot confer trust by claiming admitted/verified status.
pub struct VerifiedAdmissionEvidence {
    attestation: AdmissionAttestation,
    origin: EvidenceOrigin,
}

impl VerifiedAdmissionEvidence {
    pub fn verify(
        attestation: AdmissionAttestation,
        material: &ProofMaterial,
        verifier: &dyn TrustedEvidenceVerifier,
    ) -> Result<Self, PolicyError> {
        wire("AdmissionRequest", &attestation.request)?;
        if attestation.contract_version != CONTRACT_VERSION
            || !attestation
                .request
                .candidate
                .evidence_refs
                .contains(&material.reference)
            || attestation.requirements.len() > 13
            || attestation.known_unmitigated_vulnerabilities.len() > 128
            || attestation.target_game_version.is_empty()
        {
            return Err(PolicyError::new(
                "EVIDENCE_MISSING",
                "Admission proof is not bound to candidate evidence refs and contract",
            ));
        }
        let origin = authenticate(
            EvidenceDomain::DependencyAdmission,
            &attestation,
            material,
            verifier,
        )?;
        Ok(Self {
            attestation,
            origin,
        })
    }
}

pub fn dependency_admit(input: &Value) -> Result<Value, PolicyError> {
    dependency_admit_verified(input, None)
}

pub fn dependency_admit_verified(
    input: &Value,
    evidence: Option<&VerifiedAdmissionEvidence>,
) -> Result<Value, PolicyError> {
    let request: AdmissionRequest = decode("AdmissionRequest", input)?;
    wire("AdmissionDecision", &evaluate_admission(&request, evidence))
}

fn decision(
    outcome: AdmissionOutcome,
    reason: impl Into<String>,
    candidate: &DependencyDisposition,
) -> AdmissionDecision {
    AdmissionDecision {
        owned_implementation_module: if outcome == AdmissionOutcome::RustOwn {
            candidate.replacement_module.clone()
        } else {
            None
        },
        decision: outcome,
        reasons: vec![reason.into()],
        missing_evidence: Vec::new(),
    }
}

fn evaluate_admission(
    request: &AdmissionRequest,
    evidence: Option<&VerifiedAdmissionEvidence>,
) -> AdmissionDecision {
    let candidate = &request.candidate;
    let Some(evidence) = evidence.filter(|evidence| evidence.origin == EvidenceOrigin::Actual)
    else {
        let mut result = decision(
            AdmissionOutcome::Defer,
            "EVIDENCE_MISSING: authenticated actual admission evidence is required",
            candidate,
        );
        result
            .missing_evidence
            .push("source/license/transitive/provenance/target/worker evidence".into());
        return result;
    };
    let actual = &evidence.attestation;
    if actual.request != *request {
        return decision(
            AdmissionOutcome::Reject,
            "EVIDENCE_MISMATCH: evidence belongs to another component, scope, revision, digest or target",
            candidate,
        );
    }
    if request.needed_contract_ids.is_empty()
        || request.needed_contract_ids.len() > 256
        || request
            .needed_contract_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != request.needed_contract_ids.len()
    {
        return decision(
            AdmissionOutcome::Reject,
            "CONTRACT_SCOPE_INVALID: needed contract scope must be nonempty, bounded and unique",
            candidate,
        );
    }
    if !request
        .needed_contract_ids
        .iter()
        .all(|id| candidate.contract_ids.contains(id))
    {
        return decision(
            AdmissionOutcome::RustOwn,
            "CONTRACT_COVERAGE_MISMATCH: the upstream does not implement the required contract subset",
            candidate,
        );
    }
    if candidate.phase == VendorPhase::Retired {
        return decision(
            AdmissionOutcome::Reject,
            "COMPONENT_RETIRED: re-adoption requires a new reviewed candidate",
            candidate,
        );
    }
    if actual.rights == RightsDisposition::Denied {
        return decision(
            AdmissionOutcome::Reject,
            "RIGHTS_DENIED: language translation does not remove original rights or notices",
            candidate,
        );
    }
    if !actual.known_unmitigated_vulnerabilities.is_empty() {
        return decision(
            AdmissionOutcome::Reject,
            "UNMITIGATED_VULNERABILITY: unsafe source cannot be admitted",
            candidate,
        );
    }
    if candidate.classification == DependencyClassification::OwnedDomain
        && !candidate.language.eq_ignore_ascii_case("rust")
    {
        return decision(
            AdmissionOutcome::RustOwn,
            "OWNED_DOMAIN_REQUIRES_RUST: domain responsibilities belong to the Rust implementation",
            candidate,
        );
    }
    if candidate.classification == DependencyClassification::PlatformShim
        && !actual.platform_boundary_only
    {
        return decision(
            AdmissionOutcome::RustOwn,
            "PLATFORM_BOUNDARY_VIOLATION: geometry, compilation and durable operations belong to Rust",
            candidate,
        );
    }
    if candidate.classification == DependencyClassification::TestOnlyReference
        && candidate.production_reachable
    {
        return decision(
            AdmissionOutcome::Reject,
            "TEST_REFERENCE_PRODUCTION_REACHABLE: a test reference cannot enter the product path",
            candidate,
        );
    }
    let required = required_admission_checks(&candidate.classification);
    let mut missing = Vec::new();
    let mut failed = Vec::new();
    for item in required {
        match actual.requirements.get(&item) {
            Some(EvidenceResult::Passed) => {}
            Some(EvidenceResult::Failed { reason }) => failed.push(format!("{item:?}: {reason}")),
            Some(EvidenceResult::NotRun) | None => missing.push(format!("{item:?}")),
        }
    }
    if !failed.is_empty() {
        let mut result = decision(
            AdmissionOutcome::Reject,
            "ADMISSION_EVIDENCE_FAILED: required checks failed",
            candidate,
        );
        result.reasons.extend(failed);
        result.missing_evidence = missing;
        return result;
    }
    if actual.rights == RightsDisposition::Unknown {
        missing.push("RightsDisposition".into());
    }
    if actual.target_compatibility == TargetCompatibility::Unknown {
        missing.push("TargetCompatibility".into());
    }
    if matches!(actual.worker, WorkerDisposition::Unknown) {
        missing.push("WorkerDisposition".into());
    }
    if !missing.is_empty() {
        let mut result = decision(
            AdmissionOutcome::Defer,
            "EVIDENCE_MISSING: failed and not-run checks are not admission success",
            candidate,
        );
        result.missing_evidence = missing;
        return result;
    }
    if matches!(
        actual.target_compatibility,
        TargetCompatibility::DomainSemanticsMismatch
            | TargetCompatibility::BroadVendorChangesRequired
    ) {
        return decision(
            AdmissionOutcome::RustOwn,
            "TARGET_SEMANTICS_MISMATCH: implement the required Rust port instead of changing manifest version or making a broad vendor fork",
            candidate,
        );
    }
    if actual.target_compatibility == TargetCompatibility::Exact
        && !candidate
            .target_game_versions
            .contains(&actual.target_game_version)
    {
        return decision(
            AdmissionOutcome::RustOwn,
            "TARGET_VERSION_MISMATCH: exact tested game version is absent from candidate scope",
            candidate,
        );
    }
    if !worker_valid(&candidate.classification, &actual.worker) {
        return decision(
            AdmissionOutcome::Reject,
            "WORKER_SCOPE_INVALID: finite budget, pinned executable and reviewed execution scope are required",
            candidate,
        );
    }
    if candidate.classification == DependencyClassification::UserExternalTool
        || actual.rights == RightsDisposition::UserExternalUseOnly
    {
        if candidate.classification != DependencyClassification::UserExternalTool
            || !matches!(
                actual.worker,
                WorkerDisposition::UserInstalledTool {
                    selected_independently: true,
                    automatic_install: false,
                    execution_scoped: true,
                    ..
                }
            )
        {
            return decision(
                AdmissionOutcome::Reject,
                "EXTERNAL_TOOL_BOUNDARY_INVALID: external use must be independently selected and never automatically installed",
                candidate,
            );
        }
        return decision(
            AdmissionOutcome::ExternalOnly,
            "EXTERNAL_ONLY: reviewed installed-tool use confers no redistribution or code-copy rights",
            candidate,
        );
    }
    decision(
        AdmissionOutcome::Admit,
        "ADMISSION_CHECKS_VERIFIED: only the pinned contract and target scope is admitted; no installation, registry mutation or v1 release approval is performed",
        candidate,
    )
}

pub fn required_admission_checks(
    classification: &DependencyClassification,
) -> Vec<AdmissionRequirement> {
    use AdmissionRequirement::*;
    let mut checks = vec![
        SourceSnapshot,
        FileLicenses,
        TransitiveDependencies,
        Provenance,
        ContractCoverage,
        TargetCompatibility,
        BuildRun,
        IndependentBaseline,
        RightsReview,
        Permissions,
        OwnerReview,
        WorkerIsolation,
    ];
    if *classification == DependencyClassification::TemporaryDomainVendor {
        checks.push(ReplacementAcceptance);
    }
    checks
}

fn worker_valid(classification: &DependencyClassification, worker: &WorkerDisposition) -> bool {
    if *classification == DependencyClassification::UserExternalTool
        && !matches!(worker, WorkerDisposition::UserInstalledTool { .. })
    {
        return false;
    }
    match worker {
        WorkerDisposition::BoundedInProcess { budget } => budget.bounded(),
        WorkerDisposition::BoundedSubprocess {
            budget,
            executable_sha256,
            argv_template_registered,
            workspace_scoped,
            environment_allowlisted,
            network_scoped,
            direct_live_access,
        } => {
            budget.bounded()
                && crate::evidence::sha256(executable_sha256)
                && *argv_template_registered
                && *workspace_scoped
                && *environment_allowlisted
                && *network_scoped
                && !*direct_live_access
        }
        WorkerDisposition::UserInstalledTool {
            budget,
            selected_independently,
            automatic_install,
            execution_scoped,
        } => {
            *classification == DependencyClassification::UserExternalTool
                && budget.bounded()
                && *selected_independently
                && !*automatic_install
                && *execution_scoped
        }
        WorkerDisposition::NotApplicable => matches!(
            classification,
            DependencyClassification::PlatformShim | DependencyClassification::TestOnlyReference
        ),
        WorkerDisposition::Unknown => false,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VendorRegistry {
    contract_version: String,
    entries: Vec<DependencyDisposition>,
    scope: String,
}

/// Importing the registry is read-only. Its empty baseline does not adopt any
/// library or surveyed upstream; infrastructure dependencies need actual audits.
pub fn embedded_vendor_registry() -> Result<Vec<DependencyDisposition>, PolicyError> {
    let value = parse_json(include_bytes!("../../../policies/vendor-registry.json"))
        .map_err(|error| PolicyError::new("EVIDENCE_MISSING", error.to_string()))?;
    let registry: VendorRegistry = serde_json::from_value(value)
        .map_err(|error| PolicyError::new("EVIDENCE_MISSING", error.to_string()))?;
    if registry.contract_version != CONTRACT_VERSION
        || registry.scope != "actual_admissions_only"
        || registry.entries.len() > 1024
    {
        return Err(PolicyError::new(
            "EVIDENCE_MISSING",
            "Vendor registry version, scope or finite entry limit is invalid",
        ));
    }
    let mut ids = BTreeSet::new();
    for entry in &registry.entries {
        wire("DependencyDisposition", entry)?;
        if !ids.insert(&entry.component_id) {
            return Err(PolicyError::new(
                "EVIDENCE_MISSING",
                "Vendor registry repeats a component",
            ));
        }
    }
    Ok(registry.entries)
}

/// The original policy has no automatic installer. Expose the original value
/// for runtime configuration without treating it as proof of enforcement.
pub fn embedded_default_policy() -> Result<Value, PolicyError> {
    let value = parse_json(include_bytes!("../../../policies/default-policy.json"))
        .map_err(|error| PolicyError::new("EVIDENCE_MISSING", error.to_string()))?;
    if value.get("contractVersion").and_then(Value::as_str) != Some(CONTRACT_VERSION)
        || value.get("newInstallPolicy").and_then(Value::as_str) != Some("manual_only")
    {
        return Err(PolicyError::new(
            "EVIDENCE_MISSING",
            "Unexpected default policy contract or install boundary",
        ));
    }
    Ok(value)
}

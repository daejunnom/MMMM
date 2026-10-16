use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DependencyClassification {
    OwnedDomain,
    TemporaryDomainVendor,
    InfrastructureDependency,
    PlatformShim,
    UserExternalTool,
    TestOnlyReference,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VendorPhase {
    Candidate,
    Admitted,
    Wrapped,
    Characterised,
    RustImplemented,
    EquivalenceVerified,
    Switched,
    Retired,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DependencyDisposition {
    pub component_id: String,
    pub classification: DependencyClassification,
    pub language: String,
    pub source_locator: String,
    pub source_revision: String,
    pub source_sha256: String,
    pub license_expression: String,
    pub target_game_versions: Vec<String>,
    pub contract_ids: Vec<String>,
    pub implementation_digest: String,
    pub phase: VendorPhase,
    pub owner: String,
    pub replacement_module: Option<String>,
    pub evidence_refs: Vec<String>,
    pub production_reachable: bool,
    pub retire_before: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdmissionRequest {
    pub candidate: DependencyDisposition,
    pub project_target_profile_id: String,
    pub needed_contract_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionOutcome {
    Admit,
    RustOwn,
    ExternalOnly,
    Defer,
    Reject,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdmissionDecision {
    pub decision: AdmissionOutcome,
    pub reasons: Vec<String>,
    pub missing_evidence: Vec<String>,
    pub owned_implementation_module: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStage {
    Mvp,
    V0,
    V1,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseClaim {
    SpecificationOnly,
    ReleaseCandidate,
    ReleaseApproved,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReleaseEvidence {
    pub contract_version: String,
    pub product_version: String,
    pub stage: ReleaseStage,
    pub target_profiles: Vec<String>,
    pub required_test_ids: Vec<String>,
    pub passed_test_ids: Vec<String>,
    pub failed_test_ids: Vec<String>,
    pub not_run_test_ids: Vec<String>,
    pub domain_vendors_remaining: Vec<String>,
    pub non_rust_domain_runtimes: Vec<String>,
    pub unresolved_operations: Vec<String>,
    pub approved_platform_shims: Vec<String>,
    pub bundle_sha256: Option<String>,
    pub claim: ReleaseClaim,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Diagnostic {
    pub code: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl Diagnostic {
    pub(crate) fn error(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity: "error".into(),
            message: message.into(),
            object_id: None,
            path: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GateReport {
    pub eligible: bool,
    pub missing_test_ids: Vec<String>,
    pub blocking_components: Vec<String>,
    pub diagnostics: Vec<Diagnostic>,
}

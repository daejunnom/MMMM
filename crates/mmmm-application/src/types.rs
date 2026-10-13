use mmmm_contracts::{BindingId, ContextId, InvocationId, OperationId, Sha256Digest};
use mmmm_runtime::storage::{EffectEvidence, RecoverySnapshot, StorageError, WriteScope};
use serde_json::Value;
use std::fmt;

pub type AppResult<T> = Result<T, AppError>;

/// Public errors carry bounded, non-secret explanations. The source is retained
/// for local diagnostics and must not be serialized into a public error body.
#[derive(Debug)]
pub struct AppError {
    pub code: &'static str,
    pub message: &'static str,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}
impl AppError {
    pub fn new(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            source: None,
        }
    }
    pub fn storage(code: &'static str, error: StorageError) -> Self {
        Self {
            code,
            message: "Durable state could not satisfy the requested operation",
            source: Some(Box::new(error)),
        }
    }
    pub(crate) fn contract(error: mmmm_contracts::ContractError) -> Self {
        Self {
            code: "INVALID_INPUT",
            message: "Canonical contract validation failed",
            source: Some(Box::new(error)),
        }
    }
    pub(crate) fn json(error: mmmm_contracts::JsonError) -> Self {
        Self {
            code: "INVALID_INPUT",
            message: "Strict JSON validation failed",
            source: Some(Box::new(error)),
        }
    }
    pub(crate) fn digest(error: mmmm_contracts::DigestError) -> Self {
        Self {
            code: "INVALID_INPUT",
            message: "Canonical digest validation failed",
            source: Some(Box::new(error)),
        }
    }
}
impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|s| s as &(dyn std::error::Error + 'static))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    ReadProject,
    ReadPlan,
    ReadAction,
    Plan,
    Apply,
    ObserveOperation,
    Cancel,
    Recovery,
}

#[derive(Clone, Debug)]
pub struct ProjectInspection {
    pub diagnostics: Vec<Value>,
    pub unresolved_references: Vec<String>,
    /// Authoring data alone cannot make this true.
    pub runtime_bindings_available: bool,
}

/// A trusted compiler/adapter prepares this with no target mutation. Application
/// allocates identities and derives pins/hash from these exact original fields.
#[derive(Clone, Debug)]
pub struct PreparedPlan {
    pub contexts: Vec<Value>,
    pub scope: WriteScope,
    pub preconditions: Vec<Value>,
    pub steps: Vec<Value>,
    pub atomicity: String,
    pub losses: Vec<Value>,
    pub diagnostics: Vec<Value>,
    pub approval_requirement: String,
    pub dependency_pins: Vec<Value>,
    pub expires_at: String,
    pub time_budget_ms: u64,
}

#[derive(Clone, Debug)]
pub struct DirectChange {
    pub target: String,
    /// Retained for adapter compatibility; post-dispatch before bytes do not
    /// authorize recovery. Application loads independently captured durable
    /// before images and combines them with these fresh after bytes.
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct BeforeImage {
    pub target: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct BeforeCapture {
    pub invocation_id: InvocationId,
    pub binding_id: BindingId,
    pub context_digest: Sha256Digest,
    pub implementation_digest: Sha256Digest,
    pub arguments_digest: Sha256Digest,
    pub images: Vec<BeforeImage>,
}

#[derive(Clone, Debug)]
pub struct ReadbackEvidence {
    pub invocation_id: InvocationId,
    pub binding_id: BindingId,
    pub context_digest: Sha256Digest,
    pub implementation_digest: Sha256Digest,
    pub arguments_digest: Sha256Digest,
    pub effect: EffectEvidence,
    /// True only after the actual job/target observation excludes further effects.
    pub settled: bool,
    pub evidence: Value,
    pub direct_changes: Vec<DirectChange>,
}

#[derive(Clone, Debug)]
pub struct RecoveryTarget {
    /// Retained final pair supplies the latest after/binding/epoch identity.
    pub snapshot: RecoverySnapshot,
    /// Frozen DAG order, exact contiguous direct pairs for this same target.
    /// before_bytes belongs to the first pair; current_after to the last pair.
    pub source_snapshots: Vec<RecoverySnapshot>,
    pub before_bytes: Vec<u8>,
    pub current_after_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RecoveryPreparation {
    pub operation_id: OperationId,
    pub context_id: ContextId,
    pub targets: Vec<RecoveryTarget>,
}

#[derive(Clone, Copy, Debug)]
pub enum IdKind {
    Plan,
    Operation,
    Invocation,
}

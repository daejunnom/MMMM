use mmmm_contracts::{
    ContextId, InvocationId, ObjectId, OperationId, PlanId, PrincipalId, ProjectId, ResourceId,
    ResourceLocation, Sha256Digest, StepId, TargetId, WorldId,
};
use serde::{Deserialize, Serialize};
use std::{fmt, io, path::PathBuf};

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    Sqlite(rusqlite::Error),
    Contract(String),
    /// Raw numeric token capture could not be bounded or matched to its parse.
    /// This is an operational failure, not malformed input or stored corruption.
    RawExactCaptureUnavailable,
    InvalidInput(String),
    Busy,
    NonLocalFilesystem,
    UnsafePath,
    Corrupt(String),
    NotFound(&'static str),
    Conflict(&'static str),
    Fenced(Vec<OperationId>),
    InvalidTransition(String),
    /// Calibration work and its original request checkpoint both failed.
    /// Inspect primary_failure() for the original classification; neither
    /// cause grants retry, rollback completion or release of a durable claim.
    CalibrationCheckpointFailure {
        primary: Box<StorageError>,
        checkpoint: Box<StorageError>,
    },
    /// A read-only journal snapshot and its original request checkpoint both
    /// failed. Neither failure is converted into a complete or empty snapshot.
    JournalSnapshotCheckpointFailure {
        primary: Box<StorageError>,
        checkpoint: Box<StorageError>,
    },
    /// Preserve failed read-transaction finalization alongside the original
    /// snapshot error. No rollback completion is inferred from dropping a value.
    JournalSnapshotRollbackFailure {
        primary: Box<StorageError>,
        rollback: Box<StorageError>,
    },
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "Storage I/O failed: {e}"),
            Self::Sqlite(e) => write!(f, "Durable journal failed: {e}"),
            Self::Contract(e) => write!(f, "Invalid storage contract: {e}"),
            Self::RawExactCaptureUnavailable => {
                f.write_str("Raw exact-integer capture is unavailable")
            }
            Self::InvalidInput(e) => write!(f, "Invalid storage input: {e}"),
            Self::Busy => f.write_str("A Coordinator already owns this data root"),
            Self::NonLocalFilesystem => {
                f.write_str("A local filesystem is required for the WAL journal")
            }
            Self::UnsafePath => f.write_str(
                "Data root paths must be absolute and contain no links or reparse points",
            ),
            Self::Corrupt(e) => write!(f, "Stored data is corrupt: {e}"),
            Self::NotFound(kind) => write!(f, "{kind} was not found"),
            Self::Conflict(kind) => write!(f, "{kind} conflicts with the durable record"),
            Self::Fenced(ops) => write!(
                f,
                "Write scope is held by {} unresolved operation(s)",
                ops.len()
            ),
            Self::InvalidTransition(e) => write!(f, "Invalid operation transition: {e}"),
            Self::CalibrationCheckpointFailure { .. } => {
                f.write_str("Calibration approval work and its original checkpoint both failed")
            }
            Self::JournalSnapshotCheckpointFailure { .. } => {
                f.write_str("Journal snapshot and its original checkpoint both failed")
            }
            Self::JournalSnapshotRollbackFailure { .. } => {
                f.write_str("Journal snapshot and its read transaction rollback both failed")
            }
        }
    }
}
impl StorageError {
    /// Preserve typed classification without treating a concurrent checkpoint
    /// failure as a generic I/O error or replacing the original failure.
    pub fn primary_failure(&self) -> &Self {
        let mut current = self;
        while let Self::CalibrationCheckpointFailure { primary, .. }
        | Self::JournalSnapshotCheckpointFailure { primary, .. }
        | Self::JournalSnapshotRollbackFailure { primary, .. } = current
        {
            current = primary;
        }
        current
    }
    pub fn checkpoint_failure(&self) -> Option<&Self> {
        match self {
            Self::CalibrationCheckpointFailure { checkpoint, .. }
            | Self::JournalSnapshotCheckpointFailure { checkpoint, .. } => Some(checkpoint),
            Self::JournalSnapshotRollbackFailure { primary, .. } => primary.checkpoint_failure(),
            _ => None,
        }
    }
    pub fn rollback_failure(&self) -> Option<&Self> {
        match self {
            Self::JournalSnapshotRollbackFailure { rollback, .. } => Some(rollback),
            Self::CalibrationCheckpointFailure { primary, .. }
            | Self::JournalSnapshotCheckpointFailure { primary, .. } => primary.rollback_failure(),
            _ => None,
        }
    }
}
impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CalibrationCheckpointFailure { primary, .. }
            | Self::JournalSnapshotCheckpointFailure { primary, .. }
            | Self::JournalSnapshotRollbackFailure { primary, .. } => Some(primary.as_ref()),
            _ => None,
        }
    }
}
impl From<io::Error> for StorageError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<rusqlite::Error> for StorageError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}
pub type StorageResult<T> = Result<T, StorageError>;

#[derive(Clone, Debug)]
pub struct StoreConfig {
    pub data_root: PathBuf,
    pub max_blob_bytes: u64,
}
impl StoreConfig {
    pub fn new(data_root: PathBuf) -> Self {
        Self {
            data_root,
            max_blob_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BlobRef {
    pub digest: Sha256Digest,
    /// SQLite lengths are bounded signed 64-bit integers, never JSON doubles.
    pub byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegionScope {
    pub dimension: ResourceLocation,
    pub min: [i64; 3],
    pub max_exclusive: [i64; 3],
    pub context_id: ContextId,
    pub world_id: WorldId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WriteScope {
    pub project_id: ProjectId,
    pub resource_ids: Vec<ResourceId>,
    pub object_ids: Vec<ObjectId>,
    pub regions: Vec<RegionScope>,
    pub external_target_ids: Vec<TargetId>,
}
impl WriteScope {
    pub fn validate(&self) -> StorageResult<()> {
        fn unique<T: Ord>(v: &[T]) -> bool {
            v.iter().collect::<std::collections::BTreeSet<_>>().len() == v.len()
        }
        if !unique(&self.resource_ids)
            || !unique(&self.object_ids)
            || !unique(&self.external_target_ids)
            || self
                .regions
                .iter()
                .any(|r| (0..3).any(|axis| r.min[axis] >= r.max_exclusive[axis]))
        {
            return Err(StorageError::InvalidInput(
                "Duplicate identifiers or empty/inverted region scope".into(),
            ));
        }
        Ok(())
    }
    pub fn is_empty(&self) -> bool {
        self.resource_ids.is_empty()
            && self.object_ids.is_empty()
            && self.regions.is_empty()
            && self.external_target_ids.is_empty()
    }
    pub fn overlaps(&self, other: &Self, whole_project: bool, other_whole_project: bool) -> bool {
        let project = self.project_id == other.project_id;
        if project && (whole_project || other_whole_project) {
            return true;
        }
        (project
            && (self
                .resource_ids
                .iter()
                .any(|id| other.resource_ids.contains(id))
                || self
                    .object_ids
                    .iter()
                    .any(|id| other.object_ids.contains(id))))
            || self
                .external_target_ids
                .iter()
                .any(|id| other.external_target_ids.contains(id))
            || self.regions.iter().any(|a| {
                other.regions.iter().any(|b| {
                    // A new executor/context cannot bypass a fence on the same world.
                    a.world_id == b.world_id
                        && a.dimension == b.dimension
                        && (0..3)
                            .all(|i| a.min[i] < b.max_exclusive[i] && b.min[i] < a.max_exclusive[i])
                })
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Queued,
    Running,
    CancelRequested,
    Succeeded,
    FailedBeforeEffects,
    Partial,
    OutcomeUnknown,
    Cancelled,
}
impl OperationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::CancelRequested => "cancel_requested",
            Self::Succeeded => "succeeded",
            Self::FailedBeforeEffects => "failed_before_effects",
            Self::Partial => "partial",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::FailedBeforeEffects | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchEvidence {
    NotSent,
    IntentDurable,
    Sent,
    Acknowledged,
    Observed,
}
impl DispatchEvidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotSent => "not_sent",
            Self::IntentDurable => "intent_durable",
            Self::Sent => "sent",
            Self::Acknowledged => "acknowledged",
            Self::Observed => "observed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectEvidence {
    NoneConfirmed,
    SomeConfirmed,
    CompleteConfirmed,
    Unknown,
}
impl EffectEvidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoneConfirmed => "none_confirmed",
            Self::SomeConfirmed => "some_confirmed",
            Self::CompleteConfirmed => "complete_confirmed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationRequirement {
    SchemaOnly,
    ProviderCompletion,
    IndependentReadback,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StepRecord {
    pub step_id: StepId,
    pub write_effect: bool,
    pub verification_requirement: VerificationRequirement,
    pub dispatch: DispatchEvidence,
    pub effect: EffectEvidence,
    pub further_effects_possible: bool,
    pub provider_receipt: Option<String>,
    pub invocation_id: Option<InvocationId>,
    pub invocation_digest: Option<Sha256Digest>,
    pub observation_refs: Vec<BlobRef>,
    pub finished: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OperationRecord {
    pub operation_id: OperationId,
    pub principal: PrincipalId,
    pub project_id: ProjectId,
    pub idempotency_key: String,
    pub plan_id: PlanId,
    pub plan_hash: Sha256Digest,
    pub context_id: ContextId,
    pub state: OperationState,
    /// Sticky even when later observations report partial or unknown effects.
    pub cancellation_requested: bool,
    /// Internal restart/finalization gate, independent of observed effect truth.
    pub reconciliation_required: bool,
    pub scope: WriteScope,
    pub whole_project_fence: bool,
    pub steps: Vec<StepRecord>,
}

/// Trusted local observations of one complete, bounded journal read transaction.
/// This Rust-only value is neither an access grant nor a release attestation.
/// Its facts describe the read transaction, not writes submitted afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalSnapshot {
    pub(crate) operations: Vec<OperationRecord>,
    pub(crate) write_fences: Vec<WriteFenceSnapshot>,
}
impl JournalSnapshot {
    pub fn operations(&self) -> &[OperationRecord] {
        &self.operations
    }
    pub fn write_fences(&self) -> &[WriteFenceSnapshot] {
        &self.write_fences
    }
    /// Include queued/unsent and already-observed nonterminal writes. The
    /// restart-only unresolved_dispatches helper has different semantics.
    pub fn unresolved_writes(&self) -> impl Iterator<Item = &OperationRecord> {
        self.operations.iter().filter(|record| {
            !record.state.terminal() && record.steps.iter().any(|s| s.write_effect)
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteFenceSnapshot {
    pub(crate) operation_id: OperationId,
    pub(crate) scope: WriteScope,
    pub(crate) whole_project: bool,
}
impl WriteFenceSnapshot {
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }
    pub fn scope(&self) -> &WriteScope {
        &self.scope
    }
    pub fn whole_project(&self) -> bool {
        self.whole_project
    }
}

#[derive(Clone, Debug)]
pub struct ReserveOperation {
    pub operation_id: OperationId,
    /// Authenticated by the caller's transport; not taken from request JSON.
    pub principal: PrincipalId,
    pub project_id: ProjectId,
    pub idempotency_key: String,
    pub plan_id: PlanId,
    pub plan_hash: Sha256Digest,
    pub context_id: ContextId,
}

#[derive(Clone, Debug)]
pub enum Reservation {
    Created(OperationRecord),
    Existing(OperationRecord),
}
impl Reservation {
    pub fn record(&self) -> &OperationRecord {
        match self {
            Self::Created(r) | Self::Existing(r) => r,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StepObservation {
    pub dispatch: DispatchEvidence,
    pub effect: EffectEvidence,
    pub further_effects_possible: bool,
    pub provider_receipt: Option<String>,
    /// These must already exist in CAS. They are retained with the operation.
    pub observation_refs: Vec<BlobRef>,
    pub finished: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecoverySnapshot {
    pub operation_id: OperationId,
    pub step_id: StepId,
    pub target: String,
    pub context_id: ContextId,
    pub binding_id: String,
    pub epoch: Option<String>,
    pub before: BlobRef,
    pub after: BlobRef,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcReport {
    pub removed_blobs: usize,
    pub removed_bytes: u64,
    pub preserved_referenced: usize,
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
//! 실제 reload callback의 관계와 소비한 원문을 기록하는, VM 호출 없는 코어.
//!
//! ObjectId는 JNI 발급자가 strong reference와 IsSameObject로 등록한 값이다.
//! Java 숫자/JSON/포인터 주소/identityHashCode를 이 입력으로 사용할 수 없다.
//! 각 event는 명시된 실제 call-site 인수/반환 관측 뒤에만 호출한다. 이 코어가
//! 참조 번호만 비교하는 것은 JNI 발급자의 실제 객체 join을 대체하지 않는다.
//! 완성된 기록도 historical source facts이며 target/쓰기/SourceAdmission이 아니다.

use mmmm_compiler::{
    calibration::{CalibrationPackProgram, CalibrationSourceKind},
    calibration_dispatch::CalibrationDispatchPlan,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_CAPTURES: usize = 8;
const MAX_FUNCTIONS: usize = 47;
const MAX_SOURCE_BYTES: usize = 64 * 1024;
const MAX_TOTAL_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_FAILURES: usize = 16;
const MAX_PACK_RUN_EVENTS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ObjectId(u64);
impl ObjectId {
    /// JNI integration only: the actual global-reference registry issues this
    /// number after IsSameObject. There is deliberately no wire deserializer.
    pub(super) fn from_issuer(value: u64) -> Result<Self, Failure> {
        if value == 0 {
            Err(Failure::Identity)
        } else {
            Ok(Self(value))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct CaptureId(u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContinuationTicket {
    capture: CaptureId,
    serial: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FunctionTicket {
    capture: CaptureId,
    serial: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Failure {
    Identity,
    UnexpectedOrder,
    Duplicate,
    InvalidTicket,
    ResourceLimit,
    SourceMismatch,
    MissingEof,
    ReadFailed,
    CloseFailed,
    NonlinearRead,
    ParseFailed,
    MissingFunction,
    ReloadFailed,
    Retired,
    Deadline,
    ClockRegressed,
    GenerationChanged,
    AdmissionClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReloadOutcome {
    Completed,
    Failed,
}

/// The VM-side binding contains no authority callback or JNIEnv. The native
/// integration separately verifies every actual Class/loader generation.
#[derive(Clone, Debug)]
pub(crate) struct CaptureBinding {
    pub server: ObjectId,
    pub attempt: ObjectId,
    pub invocation: ObjectId,
    pub bundle: ObjectId,
    pub root_anchor: ObjectId,
    pub selection: ObjectId,
    /// Issued by the native-held completed root; never selected by a Java DTO.
    pub source_kind: CalibrationSourceKind,
    /// Read from the native-held original root record, not Java JSON. This
    /// binds the complete paths/pack.mcmeta/bytes canonical bundle to the same
    /// compiler dispatch recipe used by the original owned-file consumer.
    pub bundle_digest: [u8; 32],
    /// Native definition/issuer epoch, NOT the host registry generation that
    /// intentionally changes during reload. JNI checks actual Classes too.
    pub generation: u64,
    /// Independent bounded observation clock. This is not an original
    /// request/Attempt authority lease, nor a permission to repeat its checks.
    pub started_ms: u64,
    pub deadline_ms: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Checkpoint {
    pub generation: u64,
    pub now_ms: u64,
}

/// Actual identities and selected entries read from the installed server view.
pub(crate) struct InstalledSourceView<'a> {
    pub server: ObjectId,
    pub manager: ObjectId,
    pub resources: ObjectId,
    pub library: ObjectId,
    pub published_map: ObjectId,
    pub entries: &'a [(String, ObjectId)],
}

/// Native-only historical source witness. It is neither a serialized receipt
/// nor a run permission. JNI must still join the fresh root/current objects and
/// keep the issuing classes current for the complete consuming frame.
pub(super) struct PackSourceWitness {
    capture: CaptureId,
    binding: CaptureBinding,
    source_pack: ObjectId,
    manager: ObjectId,
    resources: ObjectId,
    library: ObjectId,
    map: ObjectId,
    functions: [PackFunctionSource; 2],
}

/// Roles are issued from the two actual retained PlainTextFunction objects.
/// Their order deliberately does not follow the source BTreeMap's order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PackRunRole {
    Entry,
    Dependency,
}
impl PackRunRole {
    fn slot(self) -> usize {
        match self {
            Self::Entry => 0,
            Self::Dependency => 1,
        }
    }
    fn entries(self) -> usize {
        match self {
            Self::Entry => 3,
            Self::Dependency => 2,
        }
    }
    fn identifier(self) -> &'static str {
        match self {
            Self::Entry => "mmmm_calibration:pack/entry",
            Self::Dependency => "mmmm_calibration:pack/dependency",
        }
    }
}

/// JNI derives index from the actual bounded callee entries/provider traversal.
/// It is never a Java supplied stage number. Different positions may contain
/// the same actual entry object (both normative functions contain `return 1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PackRunEntry {
    pub role: PackRunRole,
    pub index: usize,
    pub entry: ObjectId,
}

/// Every field is an actual call-site object joined by the native issuer.
/// Captured provider/action closure recipes, actual class generations and each
/// fresh owner/deadline/cancellation frame are verified before issuing events.
/// These values have no serde/public constructor and convey no run permission.
#[derive(Clone, Debug)]
pub(super) enum PackRunEvent {
    Instantiated {
        role: PackRunRole,
        plain: ObjectId,
        instantiated: ObjectId,
        entries: Vec<ObjectId>,
        trigger_entry: Option<ObjectId>,
        parent_frame: Option<ObjectId>,
        source: ObjectId,
    },
    FunctionCall {
        role: PackRunRole,
        call: ObjectId,
        instantiated: ObjectId,
        context: ObjectId,
        parent_frame: ObjectId,
        source: ObjectId,
    },
    Schedule {
        role: PackRunRole,
        call: ObjectId,
        context: ObjectId,
        parent_frame: ObjectId,
        child_frame: ObjectId,
        provider: ObjectId,
    },
    TaskCreated {
        position: PackRunEntry,
        provider: ObjectId,
        frame: ObjectId,
        queue_entry: ObjectId,
        action: ObjectId,
    },
    QueueEnter {
        context: ObjectId,
        frame: ObjectId,
        queue_entry: ObjectId,
        action: ObjectId,
    },
    QueueExit {
        context: ObjectId,
        frame: ObjectId,
        queue_entry: ObjectId,
        action: ObjectId,
    },
    EntryBegin {
        position: PackRunEntry,
        source: ObjectId,
        context: ObjectId,
        frame: ObjectId,
    },
    HandlerEnter {
        position: PackRunEntry,
        handler: ObjectId,
        source: ObjectId,
        context: ObjectId,
        frame: ObjectId,
    },
    HandlerReturn {
        position: PackRunEntry,
        handler: ObjectId,
        source: ObjectId,
        context: ObjectId,
        frame: ObjectId,
    },
    CustomEnter {
        position: PackRunEntry,
        custom: ObjectId,
        source: ObjectId,
        context: ObjectId,
        frame: ObjectId,
    },
    CustomExit {
        position: PackRunEntry,
        custom: ObjectId,
        source: ObjectId,
        context: ObjectId,
        frame: ObjectId,
    },
    FrameReturn {
        role: PackRunRole,
        frame: ObjectId,
        returned: Option<i32>,
    },
    QueueTerminal {
        context: ObjectId,
        quota: i64,
        overflow: bool,
        queued: usize,
        new_top: usize,
    },
    Complete,
    Failed {
        failure: Failure,
        cause: Option<ObjectId>,
    },
}

/// Descriptive bounded facts, not a reusable witness or operation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PackRunFacts {
    pub load_invocation: ObjectId,
    pub run_invocation: ObjectId,
    pub event_count: usize,
    pub source_bound: bool,
    pub instantiations: usize,
    pub function_calls: usize,
    pub scheduled_functions: usize,
    pub tasks_created: usize,
    pub entries_executed: usize,
    pub task_provider_bindings_verified: usize,
    pub entry_action_bindings_verified: usize,
    pub frames_returned: usize,
    pub queue_terminal: bool,
    pub queue_remaining_quota: Option<i64>,
    pub queue_overflow: Option<bool>,
    pub queued_entries: Option<usize>,
    pub new_top_entries: Option<usize>,
    pub completed: bool,
    pub failure: Option<Failure>,
    pub first_native_cause: Option<ObjectId>,
}

/// Read-only actual-object routing for the JNI adapter. Returning a binding
/// does not reserve a stage or issue authority; TaskCreated alone advances the
/// provider traversal and each event must still pass a fresh native frame.
pub(super) struct PackScheduleBinding {
    pub plain: ObjectId,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Retained actual instantiate result for pending PACK body proof; native phase 48 remains unavailable."
        )
    )]
    pub instantiated: ObjectId,
    pub source: ObjectId,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Retained actual execution context for pending PACK body proof; native phase 48 remains unavailable."
        )
    )]
    pub context: ObjectId,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Retained actual caller frame for pending PACK callsite proof; native phase 48 remains unavailable."
        )
    )]
    pub parent_frame: ObjectId,
    pub child_frame: ObjectId,
    pub provider: ObjectId,
    pub entries: Vec<ObjectId>,
}
pub(super) struct PackTaskBinding {
    pub position: PackRunEntry,
    pub frame: ObjectId,
    pub queue_entry: ObjectId,
    pub action: ObjectId,
}

#[derive(Clone, Copy)]
struct PackRunTask {
    position: PackRunEntry,
    queue_entry: ObjectId,
    action: ObjectId,
}
#[derive(Default)]
struct PackRunFunction {
    plain: Option<ObjectId>,
    instantiated: Option<ObjectId>,
    source: Option<ObjectId>,
    entries: Vec<ObjectId>,
    parent_frame: Option<ObjectId>,
    call: Option<ObjectId>,
    child_frame: Option<ObjectId>,
    provider: Option<ObjectId>,
    tasks: Vec<PackRunTask>,
    returned: bool,
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct PackQueueLease {
    context: ObjectId,
    frame: ObjectId,
    queue_entry: ObjectId,
    action: ObjectId,
    position: PackRunEntry,
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct PackDispatch {
    custom: bool,
    receiver: ObjectId,
    source: ObjectId,
    context: ObjectId,
    frame: ObjectId,
    position: PackRunEntry,
}
struct PackActiveEntry {
    position: PackRunEntry,
    source: ObjectId,
    dispatch: Vec<PackDispatch>,
    dispatch_seen: bool,
    handler_seen: bool,
    custom_seen: bool,
}
struct PackRun {
    invocation: ObjectId,
    load_invocation: ObjectId,
    source_bound: bool,
    functions: [PackRunFunction; 2],
    context: Option<ObjectId>,
    queue: Option<PackQueueLease>,
    active_entry: Option<PackActiveEntry>,
    next_entry: usize,
    terminal: bool,
    terminal_state: Option<(i64, bool, usize, usize)>,
    completed: bool,
    events: usize,
    failure: Option<Failure>,
    first_native_cause: Option<ObjectId>,
}
pub(super) struct PackFunctionSource {
    pub identifier: String,
    pub resource: String,
    pub sha256: [u8; 32],
    pub function: ObjectId,
}
impl PackSourceWitness {
    pub(super) fn binding(&self) -> &CaptureBinding {
        &self.binding
    }
    pub(super) fn functions(&self) -> &[PackFunctionSource; 2] {
        &self.functions
    }
    pub(super) fn matches_current(&self, current: &InstalledSourceView<'_>) -> bool {
        current.server == self.binding.server
            && current.manager == self.manager
            && current.resources == self.resources
            && current.library == self.library
            && current.published_map == self.map
            && current.entries.len() == self.functions.len()
            && self.functions.iter().all(|expected| {
                current
                    .entries
                    .iter()
                    .filter(|(name, object)| {
                        *name == expected.identifier && *object == expected.function
                    })
                    .count()
                    == 1
            })
    }
    pub(super) fn source_pack(&self) -> ObjectId {
        self.source_pack
    }
}

#[derive(Clone, Debug)]
struct ExpectedFunction {
    resource: String,
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

/// Only the existing Rust normative constructor populates this expected set.
/// It is a comparison input, never an observation. Each closed kind has its
/// own exact corpus; numeric47 source is never treated as PACK_CASE source.
#[derive(Clone, Debug)]
pub(crate) struct ExpectedSources {
    kind: CalibrationSourceKind,
    functions: BTreeMap<String, ExpectedFunction>,
    bundle_digest: [u8; 32],
}
impl ExpectedSources {
    pub(crate) fn for_kind(kind: CalibrationSourceKind) -> Result<Self, Failure> {
        match kind {
            CalibrationSourceKind::Numeric47 => Self::numeric47(),
            CalibrationSourceKind::PackCase => Self::pack_case(),
        }
    }
    pub(crate) fn numeric47() -> Result<Self, Failure> {
        let suite = CalibrationDispatchPlan::normative47().map_err(|_| Failure::SourceMismatch)?;
        if suite.programs().len() != MAX_FUNCTIONS
            || suite.source_entries().len() != MAX_FUNCTIONS + 1
        {
            return Err(Failure::SourceMismatch);
        }
        let mut canonical = Vec::with_capacity(MAX_FUNCTIONS + 1);
        let mut total = 0usize;
        for (path, bytes) in suite.source_entries() {
            total = total
                .checked_add(bytes.len())
                .ok_or(Failure::ResourceLimit)?;
            if total > MAX_TOTAL_SOURCE_BYTES || bytes.is_empty() || bytes.len() > MAX_SOURCE_BYTES
            {
                return Err(Failure::ResourceLimit);
            }
            canonical.push(json!({"path":path,"rawSha256":hex(&Sha256::digest(bytes)),
                "byteLength":bytes.len(),"rawBytesHex":hex(bytes)}));
        }
        let bundle_digest = mmmm_contracts::canonical_digest(&Value::Array(canonical))
            .map_err(|_| Failure::SourceMismatch)?
            .to_bytes();
        let mut functions = BTreeMap::new();
        for expected in suite
            .loaded_source_expectations()
            .map_err(|_| Failure::SourceMismatch)?
        {
            let source = ExpectedFunction {
                resource: expected.resource_id().as_str().to_owned(),
                bytes: expected.source_bytes().to_vec(),
                sha256: expected.source_sha256().to_bytes(),
            };
            if functions
                .insert(expected.function_id().as_str().to_owned(), source)
                .is_some()
            {
                return Err(Failure::Duplicate);
            }
        }
        let result = Self {
            kind: CalibrationSourceKind::Numeric47,
            functions,
            bundle_digest,
        };
        result.validate()?;
        if result.functions.len() != MAX_FUNCTIONS {
            return Err(Failure::SourceMismatch);
        }
        Ok(result)
    }
    pub(crate) fn pack_case() -> Result<Self, Failure> {
        let kind = CalibrationSourceKind::PackCase;
        let program = CalibrationPackProgram::java_26_3().map_err(|_| Failure::SourceMismatch)?;
        if program.source_entries().len() != kind.entry_count()
            || program.function_ids().len() != kind.function_count()
        {
            return Err(Failure::SourceMismatch);
        }
        let mut canonical = Vec::with_capacity(kind.entry_count());
        let mut total = 0usize;
        for (path, bytes) in program.source_entries() {
            total = total
                .checked_add(bytes.len())
                .ok_or(Failure::ResourceLimit)?;
            if total > MAX_TOTAL_SOURCE_BYTES || bytes.is_empty() || bytes.len() > MAX_SOURCE_BYTES
            {
                return Err(Failure::ResourceLimit);
            }
            canonical.push(json!({"path":path,"rawSha256":hex(&Sha256::digest(bytes)),
                "byteLength":bytes.len(),"rawBytesHex":hex(bytes)}));
        }
        let bundle_digest = mmmm_contracts::canonical_digest(&Value::Array(canonical))
            .map_err(|_| Failure::SourceMismatch)?
            .to_bytes();
        let mut functions = BTreeMap::new();
        for identifier in program.function_ids() {
            let (namespace, function) =
                identifier.split_once(':').ok_or(Failure::SourceMismatch)?;
            let path = format!("data/{namespace}/function/{function}.mcfunction");
            let bytes = program
                .source_entries()
                .get(&path)
                .ok_or(Failure::SourceMismatch)?;
            let expected = ExpectedFunction {
                resource: format!("{namespace}:function/{function}.mcfunction"),
                bytes: bytes.clone(),
                sha256: Sha256::digest(bytes).into(),
            };
            if functions.insert(identifier.clone(), expected).is_some() {
                return Err(Failure::Duplicate);
            }
        }
        let result = Self {
            kind,
            functions,
            bundle_digest,
        };
        result.validate()?;
        Ok(result)
    }
    pub(crate) fn selected_resources(&self) -> BTreeMap<String, String> {
        self.functions
            .iter()
            .map(|(identifier, source)| (identifier.clone(), source.resource.clone()))
            .collect()
    }
    fn validate(&self) -> Result<(), Failure> {
        if self.functions.is_empty() || self.functions.len() > MAX_FUNCTIONS {
            return Err(Failure::ResourceLimit);
        }
        let mut total = 0usize;
        let mut resources = BTreeSet::new();
        for (id, source) in &self.functions {
            if id.is_empty()
                || id.len() > 1024
                || source.resource.len() > 1024
                || source.bytes.len() > MAX_SOURCE_BYTES
                || !resources.insert(&source.resource)
                || source.sha256 != <[u8; 32]>::from(Sha256::digest(&source.bytes))
            {
                return Err(Failure::SourceMismatch);
            }
            total = total
                .checked_add(source.bytes.len())
                .ok_or(Failure::ResourceLimit)?;
            if total > MAX_TOTAL_SOURCE_BYTES {
                return Err(Failure::ResourceLimit);
            }
        }
        Ok(())
    }
}

struct FunctionRecord {
    serial: u64,
    id: String,
    resource: Option<ObjectId>,
    supplier: ObjectId,
    stream: Option<ObjectId>,
    reader: Option<ObjectId>,
    lines: Option<ObjectId>,
    function: Option<ObjectId>,
    read_bytes: usize,
    hash: Sha256,
    hashed_bytes: usize,
    hash_complete: bool,
    eof: bool,
    close_attempted: bool,
    closed: bool,
    parse_succeeded: bool,
    entry_future: Option<ObjectId>,
    entry_completed: bool,
    entry_failure: Option<ObjectId>,
}

struct Capture {
    binding: CaptureBinding,
    expected: ExpectedSources,
    last_ms: u64,
    supplier: Option<(ObjectId, ObjectId)>,
    supplier_future: Option<ObjectId>,
    opened: Option<ObjectId>,
    opened_pack: Option<ObjectId>,
    continuation: Option<ObjectId>,
    continuation_serial: Option<u64>,
    manager: Option<ObjectId>,
    resources: Option<ObjectId>,
    library: Option<ObjectId>,
    records: Vec<FunctionRecord>,
    published_map: Option<ObjectId>,
    published_functions: usize,
    server_installed: bool,
    reload_future: Option<ObjectId>,
    reload_outcome: Option<ReloadOutcome>,
    failures: Vec<Failure>,
    failure_causes: Vec<Option<ObjectId>>,
    first_native_cause: Option<(Failure, ObjectId)>,
    failures_omitted: usize,
    retired: bool,
    pack_run: Option<PackRun>,
}

/// Cloneable facts contain no replay token, VM reference or permission grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FunctionFacts {
    pub function_id: String,
    pub resource_id: String,
    pub expected_sha256: [u8; 32],
    /// Prefix facts are explicitly distinct from a completed source digest.
    pub prefix_sha256: [u8; 32],
    pub hashed_bytes: usize,
    pub observed_sha256: Option<[u8; 32]>,
    pub read_bytes: usize,
    pub eof_observed: bool,
    pub close_attempted: bool,
    pub close_completed: bool,
    pub parsed: bool,
    pub entry_completed: bool,
    pub entry_failed: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CaptureFacts {
    pub source_kind: CalibrationSourceKind,
    pub numeric47_bootstrap: bool,
    pub original_bundle_digest: [u8; 32],
    pub functions: Vec<FunctionFacts>,
    pub expected_functions: usize,
    pub published_functions: usize,
    pub server_installed: bool,
    pub reload_outcome: Option<ReloadOutcome>,
    pub failures: Vec<Failure>,
    pub failure_causes: Vec<Option<ObjectId>>,
    /// Repeated clock/checkpoint failures cannot consume the slot needed for
    /// the first actual VM/engine Throwable identity.
    pub first_native_cause: Option<(Failure, ObjectId)>,
    pub failures_omitted: usize,
    pub retired: bool,
    pub consumed_parse_publication_observed: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionFacts {
    pub closed: bool,
    pub retained_captures: usize,
    pub first_failure: Option<(Failure, u64)>,
}

/// No automatic eviction or reuse: retired and failed records occupy their
/// original capacity until VM teardown, independently of Runtime journal/CAS.
pub(crate) struct RecordingCore {
    captures: BTreeMap<CaptureId, Capture>,
    next: u64,
    closed: bool,
    first_admission_failure: Option<(Failure, u64)>,
}
impl RecordingCore {
    pub(crate) fn new() -> Self {
        Self {
            captures: BTreeMap::new(),
            next: 1,
            closed: false,
            first_admission_failure: None,
        }
    }

    /// Only the original retained capture can issue this witness. In particular
    /// neither current assessment booleans nor re-decoded receipt bytes enter
    /// this factory. Exact compiler comparison data is checked again here.
    pub(super) fn pack_source_witness(&self, id: CaptureId) -> Result<PackSourceWitness, Failure> {
        if self.closed {
            return Err(Failure::AdmissionClosed);
        }
        let capture = self.captures.get(&id).ok_or(Failure::InvalidTicket)?;
        if capture.retired {
            return Err(Failure::Retired);
        }
        let expected = ExpectedSources::pack_case()?;
        if capture.binding.source_kind != CalibrationSourceKind::PackCase
            || capture.expected.kind != CalibrationSourceKind::PackCase
            || capture.binding.bundle_digest != expected.bundle_digest
            || capture.expected.bundle_digest != expected.bundle_digest
            || capture.expected.functions.len() != 2
            || !capture.complete()
        {
            return Err(Failure::SourceMismatch);
        }
        let mut functions = Vec::with_capacity(2);
        for (identifier, source) in &expected.functions {
            let retained = capture
                .expected
                .functions
                .get(identifier)
                .ok_or(Failure::MissingFunction)?;
            if retained.resource != source.resource
                || retained.bytes != source.bytes
                || retained.sha256 != source.sha256
            {
                return Err(Failure::SourceMismatch);
            }
            let record = capture
                .records
                .iter()
                .find(|record| &record.id == identifier)
                .ok_or(Failure::MissingFunction)?;
            if !record.hash_complete
                || record.read_bytes != source.bytes.len()
                || record.hashed_bytes != source.bytes.len()
                || <[u8; 32]>::from(record.hash.clone().finalize()) != source.sha256
            {
                return Err(Failure::SourceMismatch);
            }
            functions.push(PackFunctionSource {
                identifier: identifier.clone(),
                resource: source.resource.clone(),
                sha256: source.sha256,
                function: record.function.ok_or(Failure::MissingFunction)?,
            });
        }
        Ok(PackSourceWitness {
            capture: id,
            binding: capture.binding.clone(),
            source_pack: capture.opened_pack.ok_or(Failure::Identity)?,
            manager: capture.manager.ok_or(Failure::Identity)?,
            resources: capture.resources.ok_or(Failure::Identity)?,
            library: capture.library.ok_or(Failure::Identity)?,
            map: capture.published_map.ok_or(Failure::Identity)?,
            functions: functions.try_into().map_err(|_| Failure::MissingFunction)?,
        })
    }

    /// One actual normative run may be attached to a capture. Even a failed
    /// begin consumes that slot; neither a new Invocation nor a copied witness
    /// quietly retries it. Current native owner/class/root checks are separate
    /// from the historical load clock and remain required at every JNI frame.
    pub(super) fn begin_pack_run(
        &mut self,
        id: CaptureId,
        actual_run: ObjectId,
        witness: &PackSourceWitness,
    ) -> Result<(), Failure> {
        let closed = self.closed;
        // JNI issues ObjectId from one VM-wide strong-reference registry and
        // reuses it only after actual IsSameObject, including across captures.
        let duplicate_invocation = self.captures.values().any(|capture| {
            capture
                .pack_run
                .as_ref()
                .is_some_and(|run| run.invocation == actual_run)
        });
        let capture = self.captures.get_mut(&id).ok_or(Failure::InvalidTicket)?;
        if let Some(run) = &mut capture.pack_run {
            run.fail(Failure::Duplicate, None);
            return Err(Failure::Duplicate);
        }
        let mut run = PackRun::new(actual_run, capture.binding.invocation);
        let result = (|| {
            if closed {
                return Err(Failure::AdmissionClosed);
            }
            if capture.retired {
                return Err(Failure::Retired);
            }
            if duplicate_invocation {
                return Err(Failure::Duplicate);
            }
            if witness.capture != id
                || !capture.complete()
                || capture.binding.source_kind != CalibrationSourceKind::PackCase
                || actual_run == capture.binding.invocation
                || witness.binding.server != capture.binding.server
                || witness.binding.attempt != capture.binding.attempt
                || witness.binding.invocation != capture.binding.invocation
                || witness.binding.bundle != capture.binding.bundle
                || witness.binding.root_anchor != capture.binding.root_anchor
                || witness.binding.selection != capture.binding.selection
                || witness.binding.generation != capture.binding.generation
                || witness.binding.bundle_digest != capture.binding.bundle_digest
                || witness.binding.source_kind != CalibrationSourceKind::PackCase
                || Some(witness.source_pack) != capture.opened_pack
                || Some(witness.manager) != capture.manager
                || Some(witness.resources) != capture.resources
                || Some(witness.library) != capture.library
                || Some(witness.map) != capture.published_map
            {
                return Err(Failure::SourceMismatch);
            }
            for role in [PackRunRole::Entry, PackRunRole::Dependency] {
                let source = witness
                    .functions
                    .iter()
                    .find(|source| source.identifier == role.identifier())
                    .ok_or(Failure::MissingFunction)?;
                let expected = capture
                    .expected
                    .functions
                    .get(role.identifier())
                    .ok_or(Failure::MissingFunction)?;
                let record = capture
                    .records
                    .iter()
                    .find(|record| record.id == role.identifier())
                    .ok_or(Failure::MissingFunction)?;
                if source.resource != expected.resource
                    || source.sha256 != expected.sha256
                    || Some(source.function) != record.function
                {
                    return Err(Failure::SourceMismatch);
                }
                run.functions[role.slot()].plain = Some(source.function);
            }
            run.source_bound = true;
            Ok(())
        })();
        if let Err(failure) = result {
            run.fail(failure, None);
        }
        capture.pack_run = Some(run);
        result
    }

    pub(super) fn pack_run_event(
        &mut self,
        id: CaptureId,
        actual_run: ObjectId,
        event: PackRunEvent,
    ) -> Result<(), Failure> {
        let closed = self.closed;
        let capture = self.captures.get_mut(&id).ok_or(Failure::InvalidTicket)?;
        let source_complete = capture.complete();
        let run = capture.pack_run.as_mut().ok_or(Failure::InvalidTicket)?;
        if run.invocation != actual_run {
            run.fail(Failure::Identity, None);
            return Err(Failure::Identity);
        }
        // Reserve the first actual cause even if the event budget was already
        // consumed by earlier invalid/deadline callbacks.
        if let PackRunEvent::Failed {
            cause: Some(cause), ..
        } = &event
        {
            run.first_native_cause.get_or_insert(*cause);
        }
        let result = if closed {
            Err(Failure::AdmissionClosed)
        } else if capture.retired {
            Err(Failure::Retired)
        } else if !source_complete {
            Err(Failure::SourceMismatch)
        } else {
            run.event(event)
        };
        if let Err(failure) = result {
            run.fail(failure, None);
        }
        result
    }

    pub(super) fn pack_run_facts(&self, id: CaptureId) -> Result<Option<PackRunFacts>, Failure> {
        let capture = self.captures.get(&id).ok_or(Failure::InvalidTicket)?;
        Ok(capture.pack_run.as_ref().map(PackRun::facts))
    }

    fn retained_pack_run(&self, id: CaptureId, actual_run: ObjectId) -> Result<&PackRun, Failure> {
        if self.closed {
            return Err(Failure::AdmissionClosed);
        }
        let capture = self.captures.get(&id).ok_or(Failure::InvalidTicket)?;
        if capture.retired {
            return Err(Failure::Retired);
        }
        if !capture.complete() {
            return Err(Failure::SourceMismatch);
        }
        let run = capture.pack_run.as_ref().ok_or(Failure::InvalidTicket)?;
        if run.invocation != actual_run || !run.source_bound {
            return Err(Failure::Identity);
        }
        Ok(run)
    }
    pub(super) fn pack_plain_role(
        &self,
        id: CaptureId,
        plain: ObjectId,
    ) -> Result<PackRunRole, Failure> {
        let witness = self.pack_source_witness(id)?;
        let mut matched = None;
        for role in [PackRunRole::Entry, PackRunRole::Dependency] {
            if witness
                .functions
                .iter()
                .any(|source| source.identifier == role.identifier() && source.function == plain)
            {
                if matched.is_some() {
                    return Err(Failure::Identity);
                }
                matched = Some(role);
            }
        }
        matched.ok_or(Failure::MissingFunction)
    }
    pub(super) fn pack_instantiated_role(
        &self,
        id: CaptureId,
        actual_run: ObjectId,
        callee: ObjectId,
    ) -> Result<PackRunRole, Failure> {
        let run = self.retained_pack_run(id, actual_run)?;
        let mut matched = None;
        for role in [PackRunRole::Entry, PackRunRole::Dependency] {
            if run.functions[role.slot()].instantiated == Some(callee) {
                if matched.is_some() {
                    return Err(Failure::Identity);
                }
                matched = Some(role);
            }
        }
        matched.ok_or(Failure::MissingFunction)
    }
    pub(super) fn pack_instantiated_entries(
        &self,
        id: CaptureId,
        actual_run: ObjectId,
        role: PackRunRole,
    ) -> Result<Vec<ObjectId>, Failure> {
        let run = self.retained_pack_run(id, actual_run)?;
        let function = &run.functions[role.slot()];
        if function.instantiated.is_none() {
            return Err(Failure::MissingFunction);
        }
        Ok(function.entries.clone())
    }
    pub(super) fn pack_schedule_binding(
        &self,
        id: CaptureId,
        actual_run: ObjectId,
        role: PackRunRole,
    ) -> Result<PackScheduleBinding, Failure> {
        let run = self.retained_pack_run(id, actual_run)?;
        let function = &run.functions[role.slot()];
        Ok(PackScheduleBinding {
            plain: function.plain.ok_or(Failure::MissingFunction)?,
            instantiated: function.instantiated.ok_or(Failure::MissingFunction)?,
            source: function.source.ok_or(Failure::Identity)?,
            context: run.context.ok_or(Failure::Identity)?,
            parent_frame: function.parent_frame.ok_or(Failure::Identity)?,
            child_frame: function.child_frame.ok_or(Failure::UnexpectedOrder)?,
            provider: function.provider.ok_or(Failure::UnexpectedOrder)?,
            entries: function.entries.clone(),
        })
    }
    /// Complete-time recheck input, not a second task registry. Incomplete
    /// task sets cannot stand for the exact five captured provider results.
    pub(super) fn pack_task_bindings(
        &self,
        id: CaptureId,
        actual_run: ObjectId,
    ) -> Result<Vec<PackTaskBinding>, Failure> {
        let run = self.retained_pack_run(id, actual_run)?;
        if run.functions[0].tasks.len() != PackRunRole::Entry.entries()
            || run.functions[1].tasks.len() != PackRunRole::Dependency.entries()
        {
            return Err(Failure::UnexpectedOrder);
        }
        let mut result = Vec::with_capacity(5);
        for function in &run.functions {
            let frame = function.child_frame.ok_or(Failure::UnexpectedOrder)?;
            for task in &function.tasks {
                result.push(PackTaskBinding {
                    position: task.position,
                    frame,
                    queue_entry: task.queue_entry,
                    action: task.action,
                });
            }
        }
        Ok(result)
    }
    pub(super) fn pack_provider_position(
        &self,
        id: CaptureId,
        actual_run: ObjectId,
        provider: ObjectId,
        frame: ObjectId,
        entry: ObjectId,
    ) -> Result<PackRunEntry, Failure> {
        let run = self.retained_pack_run(id, actual_run)?;
        let mut matched = None;
        for role in [PackRunRole::Entry, PackRunRole::Dependency] {
            let function = &run.functions[role.slot()];
            let index = function.tasks.len();
            if function.provider == Some(provider)
                && function.child_frame == Some(frame)
                && function.entries.get(index) == Some(&entry)
            {
                if matched.is_some() {
                    return Err(Failure::Identity);
                }
                matched = Some(PackRunEntry { role, index, entry });
            }
        }
        matched.ok_or(Failure::Identity)
    }
    pub(super) fn pack_queue_position(
        &self,
        id: CaptureId,
        actual_run: ObjectId,
        queue_entry: ObjectId,
        frame: ObjectId,
        action: ObjectId,
    ) -> Result<PackRunEntry, Failure> {
        let run = self.retained_pack_run(id, actual_run)?;
        let mut matched = None;
        for function in &run.functions {
            if function.child_frame != Some(frame) {
                continue;
            }
            for task in &function.tasks {
                if task.queue_entry == queue_entry && task.action == action {
                    if matched.is_some() {
                        return Err(Failure::Identity);
                    }
                    matched = Some(task.position);
                }
            }
        }
        matched.ok_or(Failure::Identity)
    }
    pub(super) fn pack_active_position(
        &self,
        id: CaptureId,
        actual_run: ObjectId,
        entry: ObjectId,
        frame: ObjectId,
    ) -> Result<PackRunEntry, Failure> {
        let run = self.retained_pack_run(id, actual_run)?;
        let queue = run.queue.as_ref().ok_or(Failure::UnexpectedOrder)?;
        if queue.position.entry != entry || queue.frame != frame {
            return Err(Failure::Identity);
        }
        Ok(queue.position)
    }

    fn reject_arm<T>(&mut self, failure: Failure, generation: u64) -> Result<T, Failure> {
        self.first_admission_failure
            .get_or_insert((failure, generation));
        Err(failure)
    }

    fn serial(&mut self) -> Result<u64, Failure> {
        let value = self.next;
        self.next = self.next.checked_add(1).ok_or(Failure::ResourceLimit)?;
        Ok(value)
    }

    pub(crate) fn arm(
        &mut self,
        binding: CaptureBinding,
        expected: ExpectedSources,
    ) -> Result<CaptureId, Failure> {
        if self.closed {
            return self.reject_arm(Failure::AdmissionClosed, binding.generation);
        }
        if self.captures.len() == MAX_CAPTURES {
            return self.reject_arm(Failure::ResourceLimit, binding.generation);
        }
        if let Err(failure) = expected.validate() {
            return self.reject_arm(failure, binding.generation);
        }
        if binding.source_kind != expected.kind || binding.bundle_digest != expected.bundle_digest {
            return self.reject_arm(Failure::SourceMismatch, binding.generation);
        }
        if binding.generation == 0 || binding.deadline_ms <= binding.started_ms {
            return self.reject_arm(Failure::Identity, binding.generation);
        }
        if self.captures.values().any(|capture| {
            capture.binding.selection == binding.selection
                || capture.binding.attempt == binding.attempt
                || capture.binding.invocation == binding.invocation
        }) {
            return self.reject_arm(Failure::Duplicate, binding.generation);
        }
        let id = CaptureId(self.serial()?);
        self.captures.insert(
            id,
            Capture {
                last_ms: binding.started_ms,
                binding,
                expected,
                supplier: None,
                supplier_future: None,
                opened: None,
                opened_pack: None,
                continuation: None,
                continuation_serial: None,
                manager: None,
                resources: None,
                library: None,
                records: Vec::new(),
                published_map: None,
                published_functions: 0,
                server_installed: false,
                reload_future: None,
                reload_outcome: None,
                failures: Vec::new(),
                failure_causes: Vec::new(),
                first_native_cause: None,
                failures_omitted: 0,
                retired: false,
                pack_run: None,
            },
        );
        Ok(id)
    }

    /// Preserve an actual bounded callback even after the observation clock
    /// expires. Its failed checkpoint stays sticky,
    /// so these historical effect facts cannot turn into successful admission.
    /// A retired or changed native issuer cannot supply new trusted facts.
    fn with_fact<T>(
        &mut self,
        id: CaptureId,
        check: Checkpoint,
        body: impl FnOnce(&mut Capture) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        let capture = self.captures.get_mut(&id).ok_or(Failure::InvalidTicket)?;
        let checkpoint = capture.check(check);
        if let Err(failure) = checkpoint {
            capture.fail(failure, None);
            if !matches!(failure, Failure::Deadline | Failure::ClockRegressed) {
                return Err(failure);
            }
        }
        let result = body(capture);
        if let Err(failure) = &result {
            capture.fail(*failure, None);
        }
        match (result, checkpoint) {
            (Err(body), _) => Err(body),
            (Ok(_), Err(checkpoint)) => Err(checkpoint),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    /// A relation ticket routes later factual callbacks; it is not an
    /// admission token. Retain and return that bounded relation after a clock
    /// failure so later physical effects can still be recorded. The failure
    /// is sticky and complete() remains false for the entire capture.
    fn with_relation<T>(
        &mut self,
        id: CaptureId,
        check: Checkpoint,
        body: impl FnOnce(&mut Capture) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        let capture = self.captures.get_mut(&id).ok_or(Failure::InvalidTicket)?;
        if let Err(failure) = capture.check(check) {
            capture.fail(failure, None);
            if !matches!(failure, Failure::Deadline | Failure::ClockRegressed) {
                return Err(failure);
            }
        }
        let result = body(capture);
        if let Err(failure) = &result {
            capture.fail(*failure, None);
        }
        result
    }

    pub(crate) fn supplier_submitted(
        &mut self,
        id: CaptureId,
        selection: ObjectId,
        supplier: ObjectId,
        executor: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(id, check, |capture| {
            if selection != capture.binding.selection {
                return Err(Failure::Identity);
            }
            once(&mut capture.supplier, (supplier, executor))
        })
    }
    pub(crate) fn supplier_returned(
        &mut self,
        id: CaptureId,
        supplier: ObjectId,
        opened: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        // A fast Executor may run this BEFORE supplyAsync returns its future.
        self.with_fact(id, check, |capture| {
            if capture.supplier.map(|value| value.0) != Some(supplier) {
                return Err(Failure::Identity);
            }
            once(&mut capture.opened, opened)
        })
    }
    pub(crate) fn supplier_future_bound(
        &mut self,
        id: CaptureId,
        supplier: ObjectId,
        future: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(id, check, |capture| {
            if capture.supplier.map(|value| value.0) != Some(supplier) {
                return Err(Failure::Identity);
            }
            once(&mut capture.supplier_future, future)
        })
    }
    pub(crate) fn continuation_bound(
        &mut self,
        id: CaptureId,
        receiver_future: ObjectId,
        continuation: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(id, check, |capture| {
            if capture.supplier_future != Some(receiver_future) {
                return Err(Failure::Identity);
            }
            once(&mut capture.continuation, continuation)
        })
    }
    pub(crate) fn continuation_entered(
        &mut self,
        id: CaptureId,
        continuation: ObjectId,
        opened: ObjectId,
        check: Checkpoint,
    ) -> Result<ContinuationTicket, Failure> {
        let serial = self.serial()?;
        self.with_relation(id, check, |capture| {
            if capture.continuation != Some(continuation) || capture.opened != Some(opened) {
                return Err(Failure::Identity);
            }
            once(&mut capture.continuation_serial, serial)?;
            Ok(ContinuationTicket {
                capture: id,
                serial,
            })
        })
    }
    /// Called only after JNI joins actual opened-list membership AND the
    /// actual Resource.source PackResources root to the existing native root.
    /// A packId string or matching root path cannot call this in its place.
    pub(crate) fn opened_pack_root_joined(
        &mut self,
        ticket: ContinuationTicket,
        opened: ObjectId,
        source_pack: ObjectId,
        root_anchor: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(ticket.capture, check, |capture| {
            capture.continuation_ticket(ticket)?;
            if capture.opened != Some(opened) || capture.binding.root_anchor != root_anchor {
                return Err(Failure::Identity);
            }
            once(&mut capture.opened_pack, source_pack)
        })
    }
    pub(crate) fn manager_bound(
        &mut self,
        ticket: ContinuationTicket,
        server: ObjectId,
        opened: ObjectId,
        manager: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(ticket.capture, check, |capture| {
            capture.continuation_ticket(ticket)?;
            if capture.binding.server != server || capture.opened != Some(opened) {
                return Err(Failure::Identity);
            }
            once(&mut capture.manager, manager)
        })
    }
    pub(crate) fn library_bound(
        &mut self,
        id: CaptureId,
        manager: ObjectId,
        resources: ObjectId,
        library: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(id, check, |capture| {
            if capture.manager != Some(manager) {
                return Err(Failure::Identity);
            }
            if capture.resources.is_some() || capture.library.is_some() {
                return Err(Failure::Duplicate);
            }
            capture.resources = Some(resources);
            capture.library = Some(library);
            Ok(())
        })
    }
    pub(crate) fn function_submitted(
        &mut self,
        id: CaptureId,
        library: ObjectId,
        manager: ObjectId,
        function_id: &str,
        actual_supplier: ObjectId,
        check: Checkpoint,
    ) -> Result<FunctionTicket, Failure> {
        let serial = self.serial()?;
        self.with_relation(id, check, |capture| {
            if capture.library != Some(library) || capture.manager != Some(manager) {
                return Err(Failure::Identity);
            }
            if !capture.expected.functions.contains_key(function_id) {
                return Err(Failure::SourceMismatch);
            }
            if capture.records.len() == MAX_FUNCTIONS
                || capture
                    .records
                    .iter()
                    .any(|record| record.id == function_id || record.supplier == actual_supplier)
            {
                return Err(Failure::Duplicate);
            }
            capture.records.push(FunctionRecord {
                serial,
                id: function_id.to_owned(),
                resource: None,
                supplier: actual_supplier,
                stream: None,
                reader: None,
                lines: None,
                function: None,
                read_bytes: 0,
                hash: Sha256::new(),
                hashed_bytes: 0,
                hash_complete: true,
                eof: false,
                close_attempted: false,
                closed: false,
                parse_succeeded: false,
                entry_future: None,
                entry_completed: false,
                entry_failure: None,
            });
            Ok(FunctionTicket {
                capture: id,
                serial,
            })
        })
    }
    /// The actual lambda$reload$3 Entry.getValue result, not a submission-time
    /// Entry snapshot. Future binding and this callback can arrive either way.
    pub(crate) fn resource_bound(
        &mut self,
        ticket: FunctionTicket,
        resource_id: &str,
        resource: ObjectId,
        source_pack: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(ticket.capture, check, |capture| {
            let position = capture.position(ticket)?;
            if capture.opened_pack != Some(source_pack) {
                return Err(Failure::Identity);
            }
            if capture.expected.functions[&capture.records[position].id].resource != resource_id {
                return Err(Failure::SourceMismatch);
            }
            if capture
                .records
                .iter()
                .any(|record| record.resource == Some(resource))
            {
                return Err(Failure::Duplicate);
            }
            once(&mut capture.records[position].resource, resource)
        })
    }
    pub(crate) fn stream_opened(
        &mut self,
        ticket: FunctionTicket,
        resource: ObjectId,
        stream: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(ticket.capture, check, |capture| {
            let record = capture.function(ticket)?;
            if record.resource != Some(resource) {
                return Err(Failure::Identity);
            }
            once(&mut record.stream, stream)
        })
    }
    pub(crate) fn reader_bound(
        &mut self,
        ticket: FunctionTicket,
        stream: ObjectId,
        reader: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(ticket.capture, check, |capture| {
            let record = capture.function(ticket)?;
            if record.stream != Some(stream) {
                return Err(Failure::Identity);
            }
            once(&mut record.reader, reader)
        })
    }
    pub(crate) fn bytes_read(
        &mut self,
        ticket: FunctionTicket,
        stream: ObjectId,
        actual_bytes: &[u8],
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(ticket.capture, check, |capture| {
            let position = capture.position(ticket)?;
            let record = &mut capture.records[position];
            if record.stream != Some(stream) {
                return Err(Failure::Identity);
            }
            if record.eof || record.close_attempted || actual_bytes.is_empty() {
                return Err(Failure::UnexpectedOrder);
            }
            let expected = &capture.expected.functions[&record.id];
            let start = record.read_bytes;
            let end = start.saturating_add(actual_bytes.len());
            record.read_bytes = end;
            if end > MAX_SOURCE_BYTES {
                record.hash_complete = false;
                return Err(Failure::ResourceLimit);
            }
            record.hash.update(actual_bytes);
            record.hashed_bytes = record.hashed_bytes.saturating_add(actual_bytes.len());
            if end > expected.bytes.len() || expected.bytes[start..end] != *actual_bytes {
                return Err(Failure::SourceMismatch);
            }
            Ok(())
        })
    }
    pub(crate) fn eof(
        &mut self,
        ticket: FunctionTicket,
        stream: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(ticket.capture, check, |capture| {
            let position = capture.position(ticket)?;
            let record = &mut capture.records[position];
            if record.stream != Some(stream) {
                return Err(Failure::Identity);
            }
            if record.eof || record.close_attempted {
                return Err(Failure::Duplicate);
            }
            record.eof = true;
            let expected = &capture.expected.functions[&record.id];
            if !record.hash_complete
                || record.read_bytes != expected.bytes.len()
                || <[u8; 32]>::from(record.hash.clone().finalize()) != expected.sha256
            {
                return Err(Failure::SourceMismatch);
            }
            Ok(())
        })
    }
    pub(crate) fn stream_closed(
        &mut self,
        ticket: FunctionTicket,
        stream: ObjectId,
        succeeded: bool,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(ticket.capture, check, |capture| {
            let record = capture.function(ticket)?;
            if record.stream != Some(stream) {
                return Err(Failure::Identity);
            }
            if record.close_attempted {
                return Err(Failure::Duplicate);
            }
            // Preserve the actual close even if EOF or another fact failed.
            record.close_attempted = true;
            record.closed = succeeded;
            if !succeeded {
                return Err(Failure::CloseFailed);
            }
            if !record.eof {
                return Err(Failure::MissingEof);
            }
            Ok(())
        })
    }
    pub(crate) fn lines_returned(
        &mut self,
        ticket: FunctionTicket,
        reader: ObjectId,
        lines: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(ticket.capture, check, |capture| {
            let record = capture.function(ticket)?;
            if record.reader != Some(reader) {
                return Err(Failure::Identity);
            }
            if !record.eof || !record.closed {
                return Err(Failure::MissingEof);
            }
            once(&mut record.lines, lines)
        })
    }
    pub(crate) fn function_returned(
        &mut self,
        ticket: FunctionTicket,
        lines: ObjectId,
        function: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(ticket.capture, check, |capture| {
            let position = capture.position(ticket)?;
            if capture
                .records
                .iter()
                .any(|record| record.function == Some(function))
            {
                return Err(Failure::Duplicate);
            }
            let record = &mut capture.records[position];
            if record.lines != Some(lines) {
                return Err(Failure::Identity);
            }
            once(&mut record.function, function)?;
            record.parse_succeeded = true;
            Ok(())
        })
    }
    pub(crate) fn function_future_bound(
        &mut self,
        ticket: FunctionTicket,
        supplier: ObjectId,
        future: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(ticket.capture, check, |capture| {
            let record = capture.function(ticket)?;
            if record.supplier != supplier {
                return Err(Failure::Identity);
            }
            once(&mut record.entry_future, future)
        })
    }
    /// Observe the actual per-entry handle callback, not allOf/reload success.
    /// It may be delivered after the map publication observation. No event
    /// arrival ordering is substituted for the original future's identity.
    pub(crate) fn entry_completed(
        &mut self,
        ticket: FunctionTicket,
        future: ObjectId,
        returned_function: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(ticket.capture, check, |capture| {
            let record = capture.function(ticket)?;
            if record.entry_future != Some(future) || record.function != Some(returned_function) {
                return Err(Failure::Identity);
            }
            if record.entry_completed {
                return Err(Failure::Duplicate);
            }
            if record.entry_failure.is_some() {
                return Err(Failure::Duplicate);
            }
            record.entry_completed = true;
            Ok(())
        })
    }
    pub(crate) fn entry_failed(
        &mut self,
        ticket: FunctionTicket,
        future: ObjectId,
        original_throwable: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(ticket.capture, check, |capture| {
            let record = capture.function(ticket)?;
            if record.entry_future != Some(future) {
                return Err(Failure::Identity);
            }
            if record.entry_completed {
                return Err(Failure::Duplicate);
            }
            once(&mut record.entry_failure, original_throwable)?;
            capture.fail(Failure::ParseFailed, Some(original_throwable));
            Ok(())
        })
    }
    /// Selected entries only; do not enumerate or force a 47-entry global map.
    /// JNI obtains these exact values from the actual newly published map.
    pub(crate) fn functions_published(
        &mut self,
        id: CaptureId,
        library: ObjectId,
        actual_map: ObjectId,
        entries: &[(String, ObjectId)],
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(id, check, |capture| {
            if capture.library != Some(library) {
                return Err(Failure::Identity);
            }
            once(&mut capture.published_map, actual_map)?;
            capture.published_functions = entries.len();
            capture.match_functions(entries)
        })
    }
    pub(crate) fn server_installed(
        &mut self,
        id: CaptureId,
        view: InstalledSourceView<'_>,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        let InstalledSourceView {
            server,
            manager,
            resources,
            library,
            published_map: actual_map,
            entries,
        } = view;
        self.with_fact(id, check, |capture| {
            if capture.binding.server != server
                || capture.manager != Some(manager)
                || capture.resources != Some(resources)
                || capture.library != Some(library)
                || capture.published_map != Some(actual_map)
            {
                return Err(Failure::Identity);
            }
            if capture.server_installed {
                return Err(Failure::Duplicate);
            }
            // This effect fact survives a later failure of unrelated reload work.
            capture.server_installed = true;
            capture.match_functions(entries)
        })
    }
    pub(crate) fn reload_future_bound(
        &mut self,
        id: CaptureId,
        future: ObjectId,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(id, check, |capture| {
            once(&mut capture.reload_future, future)
        })
    }
    pub(crate) fn reload_terminal(
        &mut self,
        id: CaptureId,
        future: ObjectId,
        outcome: ReloadOutcome,
        check: Checkpoint,
    ) -> Result<(), Failure> {
        self.with_fact(id, check, |capture| {
            if capture.reload_future != Some(future) {
                return Err(Failure::Identity);
            }
            once(&mut capture.reload_outcome, outcome)?;
            if outcome == ReloadOutcome::Failed {
                return Err(Failure::ReloadFailed);
            }
            Ok(())
        })
    }
    /// Native observer/reader/parse errors are sticky. Recording an error never
    /// cancels the engine future, rolls back an effect, or grants a retry.
    pub(crate) fn observed_failure(
        &mut self,
        id: CaptureId,
        failure: Failure,
    ) -> Result<(), Failure> {
        let capture = self.captures.get_mut(&id).ok_or(Failure::InvalidTicket)?;
        capture.fail(failure, None);
        Ok(())
    }
    pub(crate) fn observed_native_failure(
        &mut self,
        id: CaptureId,
        failure: Failure,
        original_throwable: ObjectId,
    ) -> Result<(), Failure> {
        let capture = self.captures.get_mut(&id).ok_or(Failure::InvalidTicket)?;
        capture.fail(failure, Some(original_throwable));
        Ok(())
    }
    pub(crate) fn retire(&mut self, id: CaptureId) -> Result<(), Failure> {
        let capture = self.captures.get_mut(&id).ok_or(Failure::InvalidTicket)?;
        if capture.retired {
            return Err(Failure::Retired);
        }
        if !capture.complete() {
            capture.fail(Failure::Retired, None);
        }
        if let Some(run) = &mut capture.pack_run
            && !run.completed
        {
            run.fail(Failure::Retired, None);
        }
        capture.retired = true;
        Ok(())
    }
    pub(crate) fn close_admission(&mut self, reason: Failure, generation: u64) {
        self.closed = true;
        self.first_admission_failure
            .get_or_insert((reason, generation));
        for capture in self.captures.values_mut() {
            if let Some(run) = &mut capture.pack_run
                && !run.completed
            {
                run.fail(reason, None);
            }
        }
    }
    pub(crate) fn admission_facts(&self) -> AdmissionFacts {
        AdmissionFacts {
            closed: self.closed,
            retained_captures: self.captures.len(),
            first_failure: self.first_admission_failure,
        }
    }
    pub(crate) fn facts(&self, id: CaptureId) -> Result<CaptureFacts, Failure> {
        let capture = self.captures.get(&id).ok_or(Failure::InvalidTicket)?;
        let mut functions = Vec::with_capacity(capture.records.len());
        for record in &capture.records {
            let expected = &capture.expected.functions[&record.id];
            functions.push(FunctionFacts {
                function_id: record.id.clone(),
                resource_id: expected.resource.clone(),
                expected_sha256: expected.sha256,
                prefix_sha256: record.hash.clone().finalize().into(),
                hashed_bytes: record.hashed_bytes,
                observed_sha256: (record.eof && record.hash_complete)
                    .then(|| record.hash.clone().finalize().into()),
                read_bytes: record.read_bytes,
                eof_observed: record.eof,
                close_attempted: record.close_attempted,
                close_completed: record.closed,
                parsed: record.parse_succeeded,
                entry_completed: record.entry_completed,
                entry_failed: record.entry_failure.is_some(),
            });
        }
        functions.sort_by(|left, right| left.function_id.cmp(&right.function_id));
        Ok(CaptureFacts {
            source_kind: capture.expected.kind,
            numeric47_bootstrap: capture.expected.kind == CalibrationSourceKind::Numeric47,
            original_bundle_digest: capture.binding.bundle_digest,
            functions,
            expected_functions: capture.expected.functions.len(),
            published_functions: capture.published_functions,
            server_installed: capture.server_installed,
            reload_outcome: capture.reload_outcome,
            failures: capture.failures.clone(),
            failure_causes: capture.failure_causes.clone(),
            first_native_cause: capture.first_native_cause,
            failures_omitted: capture.failures_omitted,
            retired: capture.retired,
            consumed_parse_publication_observed: capture.complete(),
        })
    }
}

impl PackRun {
    fn new(invocation: ObjectId, load_invocation: ObjectId) -> Self {
        Self {
            invocation,
            load_invocation,
            source_bound: false,
            functions: [PackRunFunction::default(), PackRunFunction::default()],
            context: None,
            queue: None,
            active_entry: None,
            next_entry: 0,
            terminal: false,
            terminal_state: None,
            completed: false,
            events: 0,
            failure: None,
            first_native_cause: None,
        }
    }
    fn fail(&mut self, failure: Failure, cause: Option<ObjectId>) {
        self.failure.get_or_insert(failure);
        if let Some(cause) = cause {
            self.first_native_cause.get_or_insert(cause);
        }
        self.completed = false;
    }
    fn facts(&self) -> PackRunFacts {
        PackRunFacts {
            load_invocation: self.load_invocation,
            run_invocation: self.invocation,
            event_count: self.events,
            source_bound: self.source_bound,
            instantiations: self
                .functions
                .iter()
                .filter(|function| function.instantiated.is_some())
                .count(),
            function_calls: self
                .functions
                .iter()
                .filter(|function| function.call.is_some())
                .count(),
            scheduled_functions: self
                .functions
                .iter()
                .filter(|function| function.child_frame.is_some())
                .count(),
            tasks_created: self
                .functions
                .iter()
                .map(|function| function.tasks.len())
                .sum(),
            entries_executed: self.next_entry,
            task_provider_bindings_verified: self
                .functions
                .iter()
                .filter(|function| function.provider.is_some())
                .count(),
            entry_action_bindings_verified: self
                .functions
                .iter()
                .map(|function| function.tasks.len())
                .sum(),
            frames_returned: self
                .functions
                .iter()
                .filter(|function| function.returned)
                .count(),
            queue_terminal: self.terminal,
            completed: self.completed,
            queue_remaining_quota: self.terminal_state.map(|value| value.0),
            queue_overflow: self.terminal_state.map(|value| value.1),
            queued_entries: self.terminal_state.map(|value| value.2),
            new_top_entries: self.terminal_state.map(|value| value.3),
            failure: self.failure,
            first_native_cause: self.first_native_cause,
        }
    }
    fn expected_position(&self) -> Option<(PackRunRole, usize)> {
        match self.next_entry {
            0 => Some((PackRunRole::Entry, 0)),
            1 => Some((PackRunRole::Entry, 1)),
            2 => Some((PackRunRole::Dependency, 0)),
            3 => Some((PackRunRole::Dependency, 1)),
            4 => Some((PackRunRole::Entry, 2)),
            _ => None,
        }
    }
    fn check_position(&self, position: PackRunEntry) -> Result<(), Failure> {
        let function = &self.functions[position.role.slot()];
        if function.entries.get(position.index) != Some(&position.entry) {
            return Err(Failure::Identity);
        }
        Ok(())
    }
    fn check_context(&self, context: ObjectId) -> Result<(), Failure> {
        if self.context != Some(context) {
            Err(Failure::Identity)
        } else {
            Ok(())
        }
    }
    fn check_active(
        &self,
        position: PackRunEntry,
        source: ObjectId,
        context: ObjectId,
        frame: ObjectId,
    ) -> Result<(), Failure> {
        self.check_position(position)?;
        self.check_context(context)?;
        let active = self.active_entry.as_ref().ok_or(Failure::UnexpectedOrder)?;
        let queue = self.queue.as_ref().ok_or(Failure::UnexpectedOrder)?;
        if active.position != position
            || active.source != source
            || queue.position != position
            || queue.frame != frame
            || queue.context != context
        {
            return Err(Failure::Identity);
        }
        Ok(())
    }
    fn dispatch(&mut self, value: PackDispatch, entering: bool) -> Result<(), Failure> {
        self.check_active(value.position, value.source, value.context, value.frame)?;
        if entering && self.functions[value.position.role.slot()].returned {
            return Err(Failure::UnexpectedOrder);
        }
        let active = self.active_entry.as_mut().ok_or(Failure::UnexpectedOrder)?;
        if entering {
            // An actual entry may expose a handler/custom nested pair. This
            // small lexical stack does not model later queued dependency work.
            if active.dispatch.len() == 2 {
                return Err(Failure::ResourceLimit);
            }
            if if value.custom {
                active.custom_seen
            } else {
                active.handler_seen
            } {
                return Err(Failure::Duplicate);
            }
            if value.custom {
                active.custom_seen = true;
            } else {
                active.handler_seen = true;
            }
            active.dispatch.push(value);
            active.dispatch_seen = true;
        } else if active.dispatch.last() != Some(&value) {
            return Err(Failure::Identity);
        } else {
            active.dispatch.pop();
        }
        Ok(())
    }
    fn event(&mut self, event: PackRunEvent) -> Result<(), Failure> {
        if self.events == MAX_PACK_RUN_EVENTS {
            return Err(Failure::ResourceLimit);
        }
        self.events += 1;
        if let PackRunEvent::Failed { failure, cause } = event {
            self.fail(failure, cause);
            return Err(failure);
        }
        if !self.source_bound {
            return Err(Failure::SourceMismatch);
        }
        if self.completed {
            return Err(Failure::Duplicate);
        }
        if self.terminal && !matches!(&event, PackRunEvent::Complete) {
            return Err(Failure::UnexpectedOrder);
        }
        match event {
            PackRunEvent::Instantiated {
                role,
                plain,
                instantiated,
                entries,
                trigger_entry,
                parent_frame,
                source,
            } => {
                let slot = role.slot();
                if self.functions[slot].plain != Some(plain) {
                    return Err(Failure::Identity);
                }
                if self.functions[slot].instantiated.is_some() {
                    return Err(Failure::Duplicate);
                }
                if entries.len() != role.entries() {
                    return Err(Failure::SourceMismatch);
                }
                match role {
                    PackRunRole::Entry => {
                        if trigger_entry.is_some()
                            || self.next_entry != 0
                            || self.functions[0].call.is_some()
                        {
                            return Err(Failure::UnexpectedOrder);
                        }
                    }
                    PackRunRole::Dependency => {
                        let active = self.active_entry.as_ref().ok_or(Failure::UnexpectedOrder)?;
                        let queue = self.queue.as_ref().ok_or(Failure::UnexpectedOrder)?;
                        let root = &self.functions[0];
                        if active.position.role != PackRunRole::Entry
                            || active.position.index != 1
                            || trigger_entry != Some(active.position.entry)
                            || source != active.source
                            || parent_frame != root.child_frame
                            || parent_frame != Some(queue.frame)
                            || !active.dispatch.iter().any(|dispatch| {
                                dispatch.custom
                                    && dispatch.position == active.position
                                    && dispatch.source == source
                            })
                        {
                            return Err(Failure::Identity);
                        }
                    }
                }
                let function = &mut self.functions[slot];
                function.instantiated = Some(instantiated);
                function.entries = entries;
                function.source = Some(source);
                function.parent_frame = parent_frame;
                Ok(())
            }
            PackRunEvent::FunctionCall {
                role,
                call,
                instantiated,
                context,
                parent_frame,
                source,
            } => {
                let slot = role.slot();
                let function = &self.functions[slot];
                if function.instantiated != Some(instantiated)
                    || function.source != Some(source)
                    || function
                        .parent_frame
                        .is_some_and(|frame| frame != parent_frame)
                {
                    return Err(Failure::Identity);
                }
                if function.call.is_some() {
                    return Err(Failure::Duplicate);
                }
                match role {
                    PackRunRole::Entry => {
                        if self.next_entry != 0 || self.context.is_some() {
                            return Err(Failure::UnexpectedOrder);
                        }
                        self.context = Some(context);
                    }
                    PackRunRole::Dependency => {
                        self.check_context(context)?;
                        if !(1..=2).contains(&self.next_entry)
                            || self.functions[0].child_frame != Some(parent_frame)
                        {
                            return Err(Failure::UnexpectedOrder);
                        }
                    }
                }
                self.functions[slot].call = Some(call);
                self.functions[slot].parent_frame = Some(parent_frame);
                Ok(())
            }
            PackRunEvent::Schedule {
                role,
                call,
                context,
                parent_frame,
                child_frame,
                provider,
            } => {
                self.check_context(context)?;
                let slot = role.slot();
                let function = &self.functions[slot];
                if function.call != Some(call)
                    || function.parent_frame != Some(parent_frame)
                    || child_frame == parent_frame
                    || self
                        .functions
                        .iter()
                        .any(|other| other.child_frame == Some(child_frame))
                    || self
                        .functions
                        .iter()
                        .any(|other| other.parent_frame == Some(child_frame))
                {
                    return Err(Failure::Identity);
                }
                if function.child_frame.is_some() {
                    return Err(Failure::Duplicate);
                }
                self.functions[slot].child_frame = Some(child_frame);
                self.functions[slot].provider = Some(provider);
                Ok(())
            }
            PackRunEvent::TaskCreated {
                position,
                provider,
                frame,
                queue_entry,
                action,
            } => {
                self.check_position(position)?;
                let slot = position.role.slot();
                let function = &self.functions[slot];
                if function.provider != Some(provider) || function.child_frame != Some(frame) {
                    return Err(Failure::Identity);
                }
                if position.index != function.tasks.len() {
                    return Err(Failure::UnexpectedOrder);
                }
                if self
                    .functions
                    .iter()
                    .flat_map(|function| &function.tasks)
                    .any(|task| task.queue_entry == queue_entry)
                {
                    return Err(Failure::Duplicate);
                }
                self.functions[slot].tasks.push(PackRunTask {
                    position,
                    queue_entry,
                    action,
                });
                Ok(())
            }
            PackRunEvent::QueueEnter {
                context,
                frame,
                queue_entry,
                action,
            } => {
                self.check_context(context)?;
                if self.queue.is_some() || self.active_entry.is_some() {
                    return Err(Failure::UnexpectedOrder);
                }
                let (role, index) = self.expected_position().ok_or(Failure::UnexpectedOrder)?;
                let function = &self.functions[role.slot()];
                let task = function.tasks.get(index).ok_or(Failure::UnexpectedOrder)?;
                if function.child_frame != Some(frame)
                    || task.queue_entry != queue_entry
                    || task.action != action
                {
                    return Err(Failure::Identity);
                }
                if role == PackRunRole::Entry && index == 2 && !self.functions[1].returned {
                    return Err(Failure::UnexpectedOrder);
                }
                self.queue = Some(PackQueueLease {
                    context,
                    frame,
                    queue_entry,
                    action,
                    position: task.position,
                });
                Ok(())
            }
            PackRunEvent::EntryBegin {
                position,
                source,
                context,
                frame,
            } => {
                self.check_position(position)?;
                self.check_context(context)?;
                if self.active_entry.is_some() {
                    return Err(Failure::Duplicate);
                }
                let queue = self.queue.as_ref().ok_or(Failure::UnexpectedOrder)?;
                if queue.position != position
                    || queue.context != context
                    || queue.frame != frame
                    || self.functions[position.role.slot()].source != Some(source)
                {
                    return Err(Failure::Identity);
                }
                self.active_entry = Some(PackActiveEntry {
                    position,
                    source,
                    dispatch: Vec::with_capacity(2),
                    dispatch_seen: false,
                    handler_seen: false,
                    custom_seen: false,
                });
                Ok(())
            }
            PackRunEvent::HandlerEnter {
                position,
                handler,
                source,
                context,
                frame,
            } => self.dispatch(
                PackDispatch {
                    custom: false,
                    receiver: handler,
                    source,
                    context,
                    frame,
                    position,
                },
                true,
            ),
            PackRunEvent::HandlerReturn {
                position,
                handler,
                source,
                context,
                frame,
            } => self.dispatch(
                PackDispatch {
                    custom: false,
                    receiver: handler,
                    source,
                    context,
                    frame,
                    position,
                },
                false,
            ),
            PackRunEvent::CustomEnter {
                position,
                custom,
                source,
                context,
                frame,
            } => self.dispatch(
                PackDispatch {
                    custom: true,
                    receiver: custom,
                    source,
                    context,
                    frame,
                    position,
                },
                true,
            ),
            PackRunEvent::CustomExit {
                position,
                custom,
                source,
                context,
                frame,
            } => self.dispatch(
                PackDispatch {
                    custom: true,
                    receiver: custom,
                    source,
                    context,
                    frame,
                    position,
                },
                false,
            ),
            PackRunEvent::FrameReturn {
                role,
                frame,
                returned,
            } => {
                let function = &self.functions[role.slot()];
                if function.child_frame != Some(frame) {
                    return Err(Failure::Identity);
                }
                if function.returned {
                    return Err(Failure::Duplicate);
                }
                let active = self.active_entry.as_ref().ok_or(Failure::UnexpectedOrder)?;
                if active.position.role != role
                    || active.position.index + 1 != role.entries()
                    || returned != Some(1)
                    || active.dispatch.is_empty()
                {
                    return Err(Failure::UnexpectedOrder);
                }
                self.functions[role.slot()].returned = true;
                Ok(())
            }
            PackRunEvent::QueueExit {
                context,
                frame,
                queue_entry,
                action,
            } => {
                let queue = self.queue.as_ref().ok_or(Failure::UnexpectedOrder)?;
                let active = self.active_entry.as_ref().ok_or(Failure::UnexpectedOrder)?;
                if queue.context != context
                    || queue.frame != frame
                    || queue.queue_entry != queue_entry
                    || queue.action != action
                    || active.position != queue.position
                {
                    return Err(Failure::Identity);
                }
                if !active.dispatch_seen || !active.dispatch.is_empty() {
                    return Err(Failure::UnexpectedOrder);
                }
                if active.position.index + 1 == active.position.role.entries()
                    && !self.functions[active.position.role.slot()].returned
                {
                    return Err(Failure::UnexpectedOrder);
                }
                if active.position.role == PackRunRole::Entry
                    && active.position.index == 1
                    && self.functions[1].instantiated.is_none()
                {
                    return Err(Failure::MissingFunction);
                }
                self.next_entry += 1;
                self.active_entry = None;
                self.queue = None;
                Ok(())
            }
            PackRunEvent::QueueTerminal {
                context,
                quota,
                overflow,
                queued,
                new_top,
            } => {
                self.check_context(context)?;
                self.terminal_state = Some((quota, overflow, queued, new_top));
                if self.next_entry != 5
                    || self.queue.is_some()
                    || self.active_entry.is_some()
                    || quota <= 0
                    || overflow
                    || queued != 0
                    || new_top != 0
                    || self.functions.iter().any(|function| !function.returned)
                {
                    return Err(Failure::UnexpectedOrder);
                }
                self.terminal = true;
                Ok(())
            }
            PackRunEvent::Complete => {
                if !self.terminal
                    || self.next_entry != 5
                    || self.queue.is_some()
                    || self.active_entry.is_some()
                    || self.failure.is_some()
                    || self.first_native_cause.is_some()
                    || self.functions.iter().enumerate().any(|(slot, function)| {
                        function.instantiated.is_none()
                            || function.call.is_none()
                            || function.child_frame.is_none()
                            || function.provider.is_none()
                            || function.tasks.len() != (if slot == 0 { 3 } else { 2 })
                            || !function.returned
                    })
                {
                    return Err(Failure::UnexpectedOrder);
                }
                self.completed = true;
                Ok(())
            }
            PackRunEvent::Failed { failure, .. } => Err(failure),
        }
    }
}

impl Capture {
    fn fail(&mut self, failure: Failure, cause: Option<ObjectId>) {
        if let Some(cause) = cause {
            self.first_native_cause.get_or_insert((failure, cause));
        }
        if self.failures.len() < MAX_FAILURES {
            self.failures.push(failure);
            self.failure_causes.push(cause);
        } else {
            self.failures_omitted = self.failures_omitted.saturating_add(1);
        }
    }
    fn check(&mut self, check: Checkpoint) -> Result<(), Failure> {
        if self.retired {
            return Err(Failure::Retired);
        }
        if check.generation != self.binding.generation {
            return Err(Failure::GenerationChanged);
        }
        if check.now_ms < self.last_ms {
            return Err(Failure::ClockRegressed);
        }
        self.last_ms = check.now_ms;
        if check.now_ms >= self.binding.deadline_ms {
            return Err(Failure::Deadline);
        }
        Ok(())
    }
    fn continuation_ticket(&self, ticket: ContinuationTicket) -> Result<(), Failure> {
        if self.continuation_serial != Some(ticket.serial) {
            Err(Failure::InvalidTicket)
        } else {
            Ok(())
        }
    }
    fn position(&self, ticket: FunctionTicket) -> Result<usize, Failure> {
        self.records
            .iter()
            .position(|record| record.serial == ticket.serial)
            .ok_or(Failure::InvalidTicket)
    }
    fn function(&mut self, ticket: FunctionTicket) -> Result<&mut FunctionRecord, Failure> {
        let index = self.position(ticket)?;
        Ok(&mut self.records[index])
    }
    fn match_functions(&self, entries: &[(String, ObjectId)]) -> Result<(), Failure> {
        if entries.len() != self.expected.functions.len() || entries.len() > MAX_FUNCTIONS {
            return Err(Failure::MissingFunction);
        }
        let mut seen = BTreeSet::new();
        for (id, object) in entries {
            if !seen.insert(id) {
                return Err(Failure::Duplicate);
            }
            let record = self
                .records
                .iter()
                .find(|record| &record.id == id)
                .ok_or(Failure::MissingFunction)?;
            if record.function != Some(*object) || !record.parse_succeeded {
                return Err(Failure::Identity);
            }
        }
        Ok(())
    }
    fn complete(&self) -> bool {
        self.failures.is_empty()
            && self.failures_omitted == 0
            && self.reload_outcome == Some(ReloadOutcome::Completed)
            && self.server_installed
            && self.published_map.is_some()
            && self.published_functions == self.expected.functions.len()
            && self.records.len() == self.expected.functions.len()
            && self.records.iter().all(|record| {
                record.eof
                    && record.closed
                    && record.parse_succeeded
                    && record.entry_future.is_some()
                    && record.entry_completed
                    && record.entry_failure.is_none()
            })
    }
}

fn once<T>(slot: &mut Option<T>, value: T) -> Result<(), Failure> {
    if slot.is_some() {
        return Err(Failure::Duplicate);
    }
    *slot = Some(value);
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(DIGITS[(byte >> 4) as usize] as char);
        text.push(DIGITS[(byte & 15) as usize] as char);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    fn object(value: u64) -> ObjectId {
        ObjectId::from_issuer(value).unwrap()
    }
    fn check() -> Checkpoint {
        Checkpoint {
            generation: 1,
            now_ms: 1,
        }
    }
    fn expected() -> ExpectedSources {
        let bytes = b"return 1\n".to_vec();
        ExpectedSources {
            kind: CalibrationSourceKind::Numeric47,
            functions: BTreeMap::from([(
                "mmmm_calibration:test".into(),
                ExpectedFunction {
                    resource: "mmmm_calibration:function/test.mcfunction".into(),
                    sha256: Sha256::digest(&bytes).into(),
                    bytes,
                },
            )]),
            bundle_digest: [7; 32],
        }
    }
    fn arm(core: &mut RecordingCore, offset: u64) -> CaptureId {
        core.arm(
            CaptureBinding {
                server: object(1 + offset),
                attempt: object(2 + offset),
                invocation: object(3 + offset),
                bundle: object(4 + offset),
                root_anchor: object(5 + offset),
                selection: object(6 + offset),
                source_kind: CalibrationSourceKind::Numeric47,
                bundle_digest: [7; 32],
                generation: 1,
                started_ms: 0,
                deadline_ms: 100,
            },
            expected(),
        )
        .unwrap()
    }
    fn library_prepared(core: &mut RecordingCore, id: CaptureId) {
        core.supplier_submitted(id, object(6), object(10), object(11), check())
            .unwrap();
        core.supplier_returned(id, object(10), object(12), check())
            .unwrap();
        core.supplier_future_bound(id, object(10), object(13), check())
            .unwrap();
        core.continuation_bound(id, object(13), object(14), check())
            .unwrap();
        let ticket = core
            .continuation_entered(id, object(14), object(12), check())
            .unwrap();
        core.opened_pack_root_joined(ticket, object(12), object(15), object(5), check())
            .unwrap();
        core.manager_bound(ticket, object(1), object(12), object(16), check())
            .unwrap();
        core.library_bound(id, object(16), object(17), object(18), check())
            .unwrap();
    }
    fn submitted(core: &mut RecordingCore, id: CaptureId) -> FunctionTicket {
        library_prepared(core, id);
        core.function_submitted(
            id,
            object(18),
            object(16),
            "mmmm_calibration:test",
            object(20),
            check(),
        )
        .unwrap()
    }
    fn prepared(core: &mut RecordingCore, id: CaptureId) -> FunctionTicket {
        let function = submitted(core, id);
        core.resource_bound(
            function,
            "mmmm_calibration:function/test.mcfunction",
            object(19),
            object(15),
            check(),
        )
        .unwrap();
        function
    }
    fn parsed_until_future(core: &mut RecordingCore, ticket: FunctionTicket) {
        core.stream_opened(ticket, object(19), object(21), check())
            .unwrap();
        core.reader_bound(ticket, object(21), object(22), check())
            .unwrap();
        core.bytes_read(ticket, object(21), b"return ", check())
            .unwrap();
        core.bytes_read(ticket, object(21), b"1\n", check())
            .unwrap();
        core.eof(ticket, object(21), check()).unwrap();
        core.stream_closed(ticket, object(21), true, check())
            .unwrap();
        core.lines_returned(ticket, object(22), object(23), check())
            .unwrap();
        core.function_returned(ticket, object(23), object(24), check())
            .unwrap();
        core.function_future_bound(ticket, object(20), object(27), check())
            .unwrap();
    }
    fn parsed(core: &mut RecordingCore, ticket: FunctionTicket) {
        parsed_until_future(core, ticket);
        core.entry_completed(ticket, object(27), object(24), check())
            .unwrap();
    }
    fn entries() -> Vec<(String, ObjectId)> {
        vec![("mmmm_calibration:test".into(), object(24))]
    }

    fn completed_pack_source() -> (RecordingCore, CaptureId, PackSourceWitness) {
        let mut core = RecordingCore::new();
        let expected = ExpectedSources::pack_case().unwrap();
        let binding = CaptureBinding {
            server: object(1),
            attempt: object(2),
            invocation: object(3),
            bundle: object(4),
            root_anchor: object(5),
            selection: object(6),
            source_kind: CalibrationSourceKind::PackCase,
            bundle_digest: expected.bundle_digest,
            generation: 1,
            started_ms: 0,
            deadline_ms: 100,
        };
        let sources = expected.functions.clone();
        let id = core.arm(binding, expected).unwrap();
        library_prepared(&mut core, id);
        let mut published = Vec::new();
        for (index, (identifier, expected)) in sources.iter().enumerate() {
            let base = 100 + index as u64 * 20;
            let function = if identifier == PackRunRole::Entry.identifier() {
                object(60)
            } else {
                object(61)
            };
            let ticket = core
                .function_submitted(
                    id,
                    object(18),
                    object(16),
                    identifier,
                    object(base),
                    check(),
                )
                .unwrap();
            core.resource_bound(
                ticket,
                &expected.resource,
                object(base + 1),
                object(15),
                check(),
            )
            .unwrap();
            core.stream_opened(ticket, object(base + 1), object(base + 2), check())
                .unwrap();
            core.reader_bound(ticket, object(base + 2), object(base + 3), check())
                .unwrap();
            core.bytes_read(ticket, object(base + 2), &expected.bytes, check())
                .unwrap();
            core.eof(ticket, object(base + 2), check()).unwrap();
            core.stream_closed(ticket, object(base + 2), true, check())
                .unwrap();
            core.lines_returned(ticket, object(base + 3), object(base + 4), check())
                .unwrap();
            core.function_returned(ticket, object(base + 4), function, check())
                .unwrap();
            core.function_future_bound(ticket, object(base), object(base + 5), check())
                .unwrap();
            core.entry_completed(ticket, object(base + 5), function, check())
                .unwrap();
            published.push((identifier.clone(), function));
        }
        core.functions_published(id, object(18), object(25), &published, check())
            .unwrap();
        core.server_installed(
            id,
            InstalledSourceView {
                server: object(1),
                manager: object(16),
                resources: object(17),
                library: object(18),
                published_map: object(25),
                entries: &published,
            },
            check(),
        )
        .unwrap();
        core.reload_future_bound(id, object(26), check()).unwrap();
        core.reload_terminal(id, object(26), ReloadOutcome::Completed, check())
            .unwrap();
        let witness = core.pack_source_witness(id).unwrap();
        (core, id, witness)
    }
    fn pack_position(role: PackRunRole, index: usize) -> PackRunEntry {
        let value = match (role, index) {
            (PackRunRole::Entry, 0) => 920,
            (PackRunRole::Entry, 1) => 921,
            (PackRunRole::Entry, 2) | (PackRunRole::Dependency, 1) => 922,
            (PackRunRole::Dependency, 0) => 923,
            _ => panic!("not a normative PACK position"),
        };
        PackRunEntry {
            role,
            index,
            entry: object(value),
        }
    }
    fn pack_task(role: PackRunRole, index: usize) -> (ObjectId, ObjectId, ObjectId) {
        match role {
            PackRunRole::Entry => (
                object(906),
                object(930 + index as u64),
                object(940 + index as u64),
            ),
            PackRunRole::Dependency => (
                object(910),
                object(933 + index as u64),
                object(if index == 0 { 943 } else { 942 }),
            ),
        }
    }
    fn pack_stage(events: &mut Vec<PackRunEvent>, role: PackRunRole, index: usize) {
        let position = pack_position(role, index);
        let (frame, queue_entry, action) = pack_task(role, index);
        let context = object(902);
        let source = object(901);
        events.push(PackRunEvent::QueueEnter {
            context,
            frame,
            queue_entry,
            action,
        });
        events.push(PackRunEvent::EntryBegin {
            position,
            source,
            context,
            frame,
        });
        let custom = !(index == 0);
        if custom {
            events.push(PackRunEvent::CustomEnter {
                position,
                custom: object(951),
                source,
                context,
                frame,
            });
        } else {
            events.push(PackRunEvent::HandlerEnter {
                position,
                handler: object(950),
                source,
                context,
                frame,
            });
        }
        if role == PackRunRole::Entry && index == 1 {
            events.push(PackRunEvent::Instantiated {
                role: PackRunRole::Dependency,
                plain: object(61),
                instantiated: object(908),
                entries: vec![object(923), object(922)],
                trigger_entry: Some(position.entry),
                parent_frame: Some(frame),
                source,
            });
        }
        if index + 1 == role.entries() {
            events.push(PackRunEvent::FrameReturn {
                role,
                frame,
                returned: Some(1),
            });
        }
        if custom {
            events.push(PackRunEvent::CustomExit {
                position,
                custom: object(951),
                source,
                context,
                frame,
            });
        } else {
            events.push(PackRunEvent::HandlerReturn {
                position,
                handler: object(950),
                source,
                context,
                frame,
            });
        }
        events.push(PackRunEvent::QueueExit {
            context,
            frame,
            queue_entry,
            action,
        });
    }
    fn pack_run_events() -> Vec<PackRunEvent> {
        let mut events = vec![
            PackRunEvent::Instantiated {
                role: PackRunRole::Entry,
                plain: object(60),
                instantiated: object(904),
                entries: vec![object(920), object(921), object(922)],
                trigger_entry: None,
                parent_frame: None,
                source: object(901),
            },
            PackRunEvent::FunctionCall {
                role: PackRunRole::Entry,
                call: object(905),
                instantiated: object(904),
                context: object(902),
                parent_frame: object(903),
                source: object(901),
            },
            PackRunEvent::Schedule {
                role: PackRunRole::Entry,
                call: object(905),
                context: object(902),
                parent_frame: object(903),
                child_frame: object(906),
                provider: object(907),
            },
        ];
        for index in 0..3 {
            let (frame, queue_entry, action) = pack_task(PackRunRole::Entry, index);
            events.push(PackRunEvent::TaskCreated {
                position: pack_position(PackRunRole::Entry, index),
                provider: object(907),
                frame,
                queue_entry,
                action,
            });
        }
        pack_stage(&mut events, PackRunRole::Entry, 0);
        pack_stage(&mut events, PackRunRole::Entry, 1);
        // The actual dependency call/child work occurs after root stage 1's
        // lexical custom and queue lease have returned, not inside that scope.
        events.push(PackRunEvent::FunctionCall {
            role: PackRunRole::Dependency,
            call: object(909),
            instantiated: object(908),
            context: object(902),
            parent_frame: object(906),
            source: object(901),
        });
        events.push(PackRunEvent::Schedule {
            role: PackRunRole::Dependency,
            call: object(909),
            context: object(902),
            parent_frame: object(906),
            child_frame: object(910),
            provider: object(907),
        });
        for index in 0..2 {
            let (frame, queue_entry, action) = pack_task(PackRunRole::Dependency, index);
            events.push(PackRunEvent::TaskCreated {
                position: pack_position(PackRunRole::Dependency, index),
                provider: object(907),
                frame,
                queue_entry,
                action,
            });
        }
        pack_stage(&mut events, PackRunRole::Dependency, 0);
        pack_stage(&mut events, PackRunRole::Dependency, 1);
        pack_stage(&mut events, PackRunRole::Entry, 2);
        events.push(PackRunEvent::QueueTerminal {
            context: object(902),
            quota: 123,
            overflow: false,
            queued: 0,
            new_top: 0,
        });
        events.push(PackRunEvent::Complete);
        events
    }
    fn recorded_pack_run(
        events: impl IntoIterator<Item = PackRunEvent>,
    ) -> (RecordingCore, CaptureId) {
        let (mut core, id, witness) = completed_pack_source();
        core.begin_pack_run(id, object(900), &witness).unwrap();
        for event in events {
            let _ = core.pack_run_event(id, object(900), event);
        }
        (core, id)
    }

    #[test]
    fn pack_run_accepts_deferred_dependency_and_shared_entry_provider_action_objects() {
        let (core, id) = recorded_pack_run(pack_run_events());
        let facts = core.pack_run_facts(id).unwrap().unwrap();
        assert!(facts.completed && facts.source_bound && facts.queue_terminal);
        assert_eq!(facts.failure, None);
        assert_eq!(facts.instantiations, 2);
        assert_eq!(facts.function_calls, 2);
        assert_eq!(facts.scheduled_functions, 2);
        assert_eq!(facts.task_provider_bindings_verified, 2);
        assert_eq!(facts.entry_action_bindings_verified, 5);
        assert_eq!(facts.tasks_created, 5);
        assert_eq!(facts.entries_executed, 5);
        assert_eq!(facts.frames_returned, 2);
        assert_eq!(facts.queue_remaining_quota, Some(123));
        assert_eq!(facts.queue_overflow, Some(false));
        assert_eq!(facts.queued_entries, Some(0));
        assert_eq!(facts.new_top_entries, Some(0));
        let tasks = core.pack_task_bindings(id, object(900)).unwrap();
        assert_eq!(tasks.len(), 5);
        for task in tasks {
            let (frame, queue_entry, action) = pack_task(task.position.role, task.position.index);
            assert_eq!(
                (task.frame, task.queue_entry, task.action),
                (frame, queue_entry, action)
            );
        }
        // The load witness's BTree order starts with dependency; roles are not
        // selected by that order and marker/readback/settled is not issued.
        assert!(core.facts(id).unwrap().consumed_parse_publication_observed);
    }
    #[test]
    fn pack_run_rejects_each_missing_required_event_without_synthesizing_completion() {
        let events = pack_run_events();
        for omitted in 0..events.len() {
            let kept = events
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != omitted)
                .map(|(_, event)| event.clone());
            let (core, id) = recorded_pack_run(kept);
            assert!(
                !core.pack_run_facts(id).unwrap().unwrap().completed,
                "omitted event {omitted}"
            );
        }
    }
    #[test]
    fn pack_run_rejects_foreign_plain_callee_child_task_and_final_queue_state() {
        let good = pack_run_events();
        let cases: Vec<(usize, PackRunEvent)> = good
            .iter()
            .enumerate()
            .filter_map(|(index, event)| {
                let bad = match event {
                    PackRunEvent::Instantiated {
                        role: PackRunRole::Entry,
                        instantiated,
                        entries,
                        ..
                    } => PackRunEvent::Instantiated {
                        role: PackRunRole::Entry,
                        plain: object(61),
                        instantiated: *instantiated,
                        entries: entries.clone(),
                        trigger_entry: None,
                        parent_frame: None,
                        source: object(901),
                    },
                    PackRunEvent::FunctionCall {
                        role: PackRunRole::Dependency,
                        call,
                        context,
                        parent_frame,
                        source,
                        ..
                    } => PackRunEvent::FunctionCall {
                        role: PackRunRole::Dependency,
                        call: *call,
                        instantiated: object(904),
                        context: *context,
                        parent_frame: *parent_frame,
                        source: *source,
                    },
                    PackRunEvent::Schedule {
                        role: PackRunRole::Dependency,
                        call,
                        context,
                        parent_frame,
                        provider,
                        ..
                    } => PackRunEvent::Schedule {
                        role: PackRunRole::Dependency,
                        call: *call,
                        context: *context,
                        parent_frame: *parent_frame,
                        child_frame: *parent_frame,
                        provider: *provider,
                    },
                    PackRunEvent::TaskCreated {
                        position,
                        provider,
                        frame,
                        queue_entry,
                        ..
                    } if position.index == 0 => PackRunEvent::TaskCreated {
                        position: PackRunEntry {
                            entry: object(999),
                            ..*position
                        },
                        provider: *provider,
                        frame: *frame,
                        queue_entry: *queue_entry,
                        action: object(999),
                    },
                    PackRunEvent::QueueTerminal { context, .. } => PackRunEvent::QueueTerminal {
                        context: *context,
                        quota: 0,
                        overflow: true,
                        queued: 1,
                        new_top: 1,
                    },
                    _ => return None,
                };
                Some((index, bad))
            })
            .collect();
        for (index, bad) in cases {
            let mut events = good.clone();
            events[index] = bad;
            let (core, id) = recorded_pack_run(events);
            let facts = core.pack_run_facts(id).unwrap().unwrap();
            assert!(
                !facts.completed && facts.failure.is_some(),
                "substituted event {index}"
            );
        }
    }
    #[test]
    fn pack_run_failed_begin_consumes_slot_and_source_retirement_cannot_be_retried() {
        let (mut core, id, witness) = completed_pack_source();
        assert_eq!(
            core.begin_pack_run(id, object(3), &witness),
            Err(Failure::SourceMismatch)
        );
        assert_eq!(
            core.begin_pack_run(id, object(900), &witness),
            Err(Failure::Duplicate)
        );
        let facts = core.pack_run_facts(id).unwrap().unwrap();
        assert_eq!(facts.run_invocation, object(3));
        assert!(!facts.source_bound && !facts.completed);
        assert_eq!(facts.failure, Some(Failure::SourceMismatch));
        let (mut core, id, witness) = completed_pack_source();
        core.retire(id).unwrap();
        assert_eq!(
            core.begin_pack_run(id, object(900), &witness),
            Err(Failure::Retired)
        );
    }
    #[test]
    fn pack_run_actual_invocation_cannot_bind_to_two_retained_captures() {
        let (mut core, first, witness) = completed_pack_source();
        core.begin_pack_run(first, object(900), &witness).unwrap();
        let (mut another, original_id, _) = completed_pack_source();
        let mut capture = another.captures.remove(&original_id).unwrap();
        capture.binding.attempt = object(202);
        capture.binding.invocation = object(203);
        capture.binding.selection = object(206);
        let second = CaptureId(700);
        assert!(core.captures.insert(second, capture).is_none());
        let witness = core.pack_source_witness(second).unwrap();
        assert_eq!(
            core.begin_pack_run(second, object(900), &witness),
            Err(Failure::Duplicate)
        );
        assert_eq!(
            core.begin_pack_run(second, object(901), &witness),
            Err(Failure::Duplicate)
        );
        let failed = core.pack_run_facts(second).unwrap().unwrap();
        assert!(!failed.source_bound && !failed.completed);
        assert_eq!(failed.run_invocation, object(900));
    }
    #[test]
    fn pack_run_failure_lane_keeps_source_facts_and_first_actual_cause_after_budget() {
        let (mut core, id, witness) = completed_pack_source();
        core.begin_pack_run(id, object(900), &witness).unwrap();
        for _ in 0..MAX_PACK_RUN_EVENTS {
            assert_eq!(
                core.pack_run_event(
                    id,
                    object(900),
                    PackRunEvent::Failed {
                        failure: Failure::Deadline,
                        cause: None
                    }
                ),
                Err(Failure::Deadline)
            );
        }
        assert_eq!(
            core.pack_run_event(
                id,
                object(900),
                PackRunEvent::Failed {
                    failure: Failure::ReadFailed,
                    cause: Some(object(999))
                }
            ),
            Err(Failure::ResourceLimit)
        );
        let facts = core.pack_run_facts(id).unwrap().unwrap();
        assert_eq!(facts.event_count, MAX_PACK_RUN_EVENTS);
        assert_eq!(facts.failure, Some(Failure::Deadline));
        assert_eq!(facts.first_native_cause, Some(object(999)));
        assert!(!facts.completed);
        let source = core.facts(id).unwrap();
        assert!(source.consumed_parse_publication_observed);
        assert!(source.failures.is_empty());
    }
    #[test]
    fn pack_run_null_frame_return_and_wrong_dispatch_pair_never_become_complete() {
        let good = pack_run_events();
        for (index, event) in good.iter().enumerate() {
            let bad = match event {
                PackRunEvent::FrameReturn { role, frame, .. } => PackRunEvent::FrameReturn {
                    role: *role,
                    frame: *frame,
                    returned: None,
                },
                PackRunEvent::CustomExit {
                    position,
                    source,
                    context,
                    frame,
                    ..
                } => PackRunEvent::CustomExit {
                    position: *position,
                    custom: object(999),
                    source: *source,
                    context: *context,
                    frame: *frame,
                },
                _ => continue,
            };
            let mut events = good.clone();
            events[index] = bad;
            let (core, id) = recorded_pack_run(events);
            assert!(!core.pack_run_facts(id).unwrap().unwrap().completed);
        }
    }
    #[test]
    fn pack_run_rejects_sequential_repeated_handler_or_custom_execution() {
        let good = pack_run_events();
        for (index, event) in good.iter().enumerate() {
            if !matches!(
                event,
                PackRunEvent::HandlerReturn { .. } | PackRunEvent::CustomExit { .. }
            ) {
                continue;
            }
            let mut events = good[..=index].to_vec();
            let repeat_enter = match event {
                PackRunEvent::HandlerReturn {
                    position,
                    handler,
                    source,
                    context,
                    frame,
                } => PackRunEvent::HandlerEnter {
                    position: *position,
                    handler: *handler,
                    source: *source,
                    context: *context,
                    frame: *frame,
                },
                PackRunEvent::CustomExit {
                    position,
                    custom,
                    source,
                    context,
                    frame,
                } => PackRunEvent::CustomEnter {
                    position: *position,
                    custom: *custom,
                    source: *source,
                    context: *context,
                    frame: *frame,
                },
                _ => unreachable!(),
            };
            events.push(repeat_enter);
            events.push(event.clone());
            events.extend_from_slice(&good[index + 1..]);
            let (core, id) = recorded_pack_run(events);
            assert!(!core.pack_run_facts(id).unwrap().unwrap().completed);
        }
    }
    #[test]
    fn pack_run_foreign_invocation_cannot_occupy_first_actual_cause_slot() {
        let (mut core, id, witness) = completed_pack_source();
        core.begin_pack_run(id, object(900), &witness).unwrap();
        assert_eq!(
            core.pack_run_event(
                id,
                object(999),
                PackRunEvent::Failed {
                    failure: Failure::ReadFailed,
                    cause: Some(object(998))
                }
            ),
            Err(Failure::Identity)
        );
        assert_eq!(
            core.pack_run_facts(id).unwrap().unwrap().first_native_cause,
            None
        );
        assert_eq!(
            core.pack_run_event(
                id,
                object(900),
                PackRunEvent::Failed {
                    failure: Failure::ReadFailed,
                    cause: Some(object(997))
                }
            ),
            Err(Failure::ReadFailed)
        );
        assert_eq!(
            core.pack_run_facts(id).unwrap().unwrap().first_native_cause,
            Some(object(997))
        );
    }
    #[test]
    fn pack_run_readonly_routes_are_bound_to_actual_run_frame_and_provider_cursor() {
        let (mut core, id, witness) = completed_pack_source();
        assert_eq!(
            core.pack_plain_role(id, object(60)).unwrap(),
            PackRunRole::Entry
        );
        assert_eq!(
            core.pack_plain_role(id, object(61)).unwrap(),
            PackRunRole::Dependency
        );
        core.begin_pack_run(id, object(900), &witness).unwrap();
        assert_eq!(
            core.pack_instantiated_entries(id, object(900), PackRunRole::Entry),
            Err(Failure::MissingFunction)
        );
        for (index, event) in pack_run_events().into_iter().take(3).enumerate() {
            core.pack_run_event(id, object(900), event).unwrap();
            if index == 0 {
                assert_eq!(
                    core.pack_instantiated_entries(id, object(900), PackRunRole::Entry)
                        .unwrap(),
                    vec![object(920), object(921), object(922)]
                );
            }
        }
        let binding = core
            .pack_schedule_binding(id, object(900), PackRunRole::Entry)
            .unwrap();
        assert_eq!(binding.plain, object(60));
        assert_eq!(binding.instantiated, object(904));
        assert_eq!(binding.source, object(901));
        assert_eq!(binding.context, object(902));
        assert_eq!(binding.parent_frame, object(903));
        assert_eq!(binding.child_frame, object(906));
        assert_eq!(binding.provider, object(907));
        assert_eq!(binding.entries, vec![object(920), object(921), object(922)]);
        assert_eq!(
            core.pack_instantiated_role(id, object(900), object(904))
                .unwrap(),
            PackRunRole::Entry
        );
        let first = core
            .pack_provider_position(id, object(900), object(907), object(906), object(920))
            .unwrap();
        assert_eq!(first, pack_position(PackRunRole::Entry, 0));
        assert_eq!(
            core.pack_provider_position(id, object(900), object(907), object(906), object(920))
                .unwrap(),
            first
        );
        assert!(
            core.pack_provider_position(id, object(900), object(907), object(910), object(920))
                .is_err()
        );
        assert!(
            core.pack_provider_position(id, object(999), object(907), object(906), object(920))
                .is_err()
        );
        core.pack_run_event(
            id,
            object(900),
            PackRunEvent::TaskCreated {
                position: first,
                provider: object(907),
                frame: object(906),
                queue_entry: object(930),
                action: object(940),
            },
        )
        .unwrap();
        assert!(core.pack_task_bindings(id, object(900)).is_err());
        assert!(
            core.pack_provider_position(id, object(900), object(907), object(906), object(920))
                .is_err()
        );
        assert_eq!(
            core.pack_queue_position(id, object(900), object(930), object(906), object(940))
                .unwrap(),
            first
        );
        assert!(
            core.pack_queue_position(id, object(900), object(930), object(910), object(940))
                .is_err()
        );
        core.pack_run_event(
            id,
            object(900),
            PackRunEvent::QueueEnter {
                context: object(902),
                frame: object(906),
                queue_entry: object(930),
                action: object(940),
            },
        )
        .unwrap();
        assert_eq!(
            core.pack_active_position(id, object(900), object(920), object(906))
                .unwrap(),
            first
        );
        assert!(
            core.pack_active_position(id, object(900), object(921), object(906))
                .is_err()
        );
    }
    #[test]
    fn pack_run_admission_close_and_late_load_failure_cannot_complete_a_run() {
        let (mut core, id, witness) = completed_pack_source();
        core.begin_pack_run(id, object(900), &witness).unwrap();
        core.close_admission(Failure::GenerationChanged, 2);
        assert!(
            core.pack_instantiated_role(id, object(900), object(904))
                .is_err()
        );
        assert_eq!(
            core.pack_run_facts(id).unwrap().unwrap().failure,
            Some(Failure::GenerationChanged)
        );
        assert!(core.facts(id).unwrap().consumed_parse_publication_observed);
        let (mut core, id, witness) = completed_pack_source();
        core.begin_pack_run(id, object(900), &witness).unwrap();
        core.observed_failure(id, Failure::ReadFailed).unwrap();
        assert_eq!(
            core.pack_run_event(id, object(900), pack_run_events().remove(0)),
            Err(Failure::SourceMismatch)
        );
        assert_eq!(
            core.pack_run_facts(id).unwrap().unwrap().failure,
            Some(Failure::SourceMismatch)
        );
    }

    #[test]
    fn normative_expected_set_is_comparison_data_and_not_pack_case() {
        let expected = ExpectedSources::numeric47().unwrap();
        assert_eq!(expected.kind, CalibrationSourceKind::Numeric47);
        assert_eq!(expected.functions.len(), 47);
        assert!(
            !expected
                .functions
                .contains_key("mmmm_calibration:pack/entry")
        );
    }
    #[test]
    fn pack_comparison_has_two_functions_and_never_claims_numeric_bootstrap() {
        let expected = ExpectedSources::pack_case().unwrap();
        assert_eq!(expected.kind, CalibrationSourceKind::PackCase);
        assert_eq!(expected.functions.len(), 2);
        assert_eq!(
            expected.selected_resources(),
            BTreeMap::from([
                (
                    "mmmm_calibration:pack/entry".into(),
                    "mmmm_calibration:function/pack/entry.mcfunction".into()
                ),
                (
                    "mmmm_calibration:pack/dependency".into(),
                    "mmmm_calibration:function/pack/dependency.mcfunction".into()
                ),
            ])
        );
        let binding = CaptureBinding {
            server: object(1),
            attempt: object(2),
            invocation: object(3),
            bundle: object(4),
            root_anchor: object(5),
            selection: object(6),
            source_kind: CalibrationSourceKind::PackCase,
            bundle_digest: expected.bundle_digest,
            generation: 1,
            started_ms: 0,
            deadline_ms: 100,
        };
        let mut mismatch = binding.clone();
        mismatch.source_kind = CalibrationSourceKind::Numeric47;
        let mut core = RecordingCore::new();
        assert_eq!(
            core.arm(mismatch, expected.clone()),
            Err(Failure::SourceMismatch)
        );
        let id = core.arm(binding, expected).unwrap();
        let facts = core.facts(id).unwrap();
        assert_eq!(facts.source_kind, CalibrationSourceKind::PackCase);
        assert!(!facts.numeric47_bootstrap);
        assert_eq!(facts.expected_functions, 2);
        assert_eq!(facts.published_functions, 0);
        assert!(!facts.consumed_parse_publication_observed);
    }
    #[test]
    fn early_supplier_result_and_complete_identity_chain_are_recorded_as_facts_only() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        let ticket = prepared(&mut core, id);
        parsed(&mut core, ticket);
        core.functions_published(id, object(18), object(25), &entries(), check())
            .unwrap();
        core.server_installed(
            id,
            InstalledSourceView {
                server: object(1),
                manager: object(16),
                resources: object(17),
                library: object(18),
                published_map: object(25),
                entries: &entries(),
            },
            check(),
        )
        .unwrap();
        core.reload_future_bound(id, object(26), check()).unwrap();
        core.reload_terminal(id, object(26), ReloadOutcome::Completed, check())
            .unwrap();
        assert!(core.facts(id).unwrap().consumed_parse_publication_observed);
        core.retire(id).unwrap();
        let facts = core.facts(id).unwrap();
        assert!(facts.retired && facts.consumed_parse_publication_observed);
    }
    #[test]
    fn same_server_or_same_contents_cannot_select_another_future_or_list() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        core.supplier_submitted(id, object(6), object(10), object(11), check())
            .unwrap();
        core.supplier_returned(id, object(10), object(12), check())
            .unwrap();
        core.supplier_future_bound(id, object(10), object(13), check())
            .unwrap();
        assert_eq!(
            core.continuation_bound(id, object(999), object(14), check()),
            Err(Failure::Identity)
        );
        core.continuation_bound(id, object(13), object(14), check())
            .unwrap();
        assert_eq!(
            core.continuation_entered(id, object(14), object(999), check()),
            Err(Failure::Identity)
        );
        assert!(!core.facts(id).unwrap().consumed_parse_publication_observed);
    }
    #[test]
    fn bytes_without_original_eof_and_close_cannot_become_lines() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        let ticket = prepared(&mut core, id);
        core.stream_opened(ticket, object(19), object(21), check())
            .unwrap();
        core.reader_bound(ticket, object(21), object(22), check())
            .unwrap();
        core.bytes_read(ticket, object(21), b"return 1\n", check())
            .unwrap();
        assert_eq!(
            core.lines_returned(ticket, object(22), object(23), check()),
            Err(Failure::MissingEof)
        );
        assert_eq!(
            core.stream_closed(ticket, object(21), true, check()),
            Err(Failure::MissingEof)
        );
        let facts = core.facts(id).unwrap();
        assert!(facts.functions[0].close_completed);
        assert!(!facts.functions[0].eof_observed);
    }
    #[test]
    fn read_failure_and_later_close_failure_are_both_retained() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        let ticket = prepared(&mut core, id);
        core.stream_opened(ticket, object(19), object(21), check())
            .unwrap();
        core.observed_failure(id, Failure::ReadFailed).unwrap();
        assert_eq!(
            core.stream_closed(ticket, object(21), false, check()),
            Err(Failure::CloseFailed)
        );
        assert_eq!(
            core.facts(id).unwrap().failures,
            vec![Failure::ReadFailed, Failure::CloseFailed]
        );
    }
    #[test]
    fn swallowed_per_function_failure_does_not_approve_partial_publication() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        let _ = prepared(&mut core, id);
        assert_eq!(
            core.functions_published(id, object(18), object(25), &[], check()),
            Err(Failure::MissingFunction)
        );
        core.reload_future_bound(id, object(26), check()).unwrap();
        core.reload_terminal(id, object(26), ReloadOutcome::Completed, check())
            .unwrap();
        assert_eq!(core.facts(id).unwrap().published_functions, 0);
        assert!(!core.facts(id).unwrap().consumed_parse_publication_observed);
    }
    #[test]
    fn installed_functions_survive_a_later_reload_failure_as_partial_facts() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        let ticket = prepared(&mut core, id);
        parsed(&mut core, ticket);
        core.functions_published(id, object(18), object(25), &entries(), check())
            .unwrap();
        core.server_installed(
            id,
            InstalledSourceView {
                server: object(1),
                manager: object(16),
                resources: object(17),
                library: object(18),
                published_map: object(25),
                entries: &entries(),
            },
            check(),
        )
        .unwrap();
        core.reload_future_bound(id, object(26), check()).unwrap();
        assert_eq!(
            core.reload_terminal(id, object(26), ReloadOutcome::Failed, check()),
            Err(Failure::ReloadFailed)
        );
        let facts = core.facts(id).unwrap();
        assert!(facts.server_installed);
        assert_eq!(facts.published_functions, 1);
        assert!(!facts.consumed_parse_publication_observed);
    }
    #[test]
    fn retired_capacity_is_not_reclaimed_or_rebound() {
        let mut core = RecordingCore::new();
        for index in 0..MAX_CAPTURES {
            let id = arm(&mut core, (index as u64) * 100);
            core.retire(id).unwrap();
        }
        let binding = CaptureBinding {
            server: object(1001),
            attempt: object(1002),
            invocation: object(1003),
            bundle: object(1004),
            root_anchor: object(1005),
            selection: object(1006),
            source_kind: CalibrationSourceKind::Numeric47,
            bundle_digest: [7; 32],
            generation: 1,
            started_ms: 0,
            deadline_ms: 100,
        };
        assert_eq!(core.arm(binding, expected()), Err(Failure::ResourceLimit));
        assert_eq!(
            core.admission_facts().first_failure,
            Some((Failure::ResourceLimit, 1))
        );
    }
    #[test]
    fn generation_and_original_deadline_errors_cannot_become_success() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        assert_eq!(
            core.supplier_submitted(
                id,
                object(6),
                object(10),
                object(11),
                Checkpoint {
                    generation: 2,
                    now_ms: 1
                }
            ),
            Err(Failure::GenerationChanged)
        );
        assert_eq!(
            core.supplier_submitted(
                id,
                object(6),
                object(10),
                object(11),
                Checkpoint {
                    generation: 1,
                    now_ms: 100
                }
            ),
            Err(Failure::Deadline)
        );
        assert_eq!(
            core.facts(id).unwrap().failures,
            vec![Failure::GenerationChanged, Failure::Deadline]
        );
    }
    #[test]
    fn actual_mismatched_prefix_and_completed_raw_digest_remain_distinct_from_expected() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        let ticket = prepared(&mut core, id);
        core.stream_opened(ticket, object(19), object(21), check())
            .unwrap();
        assert_eq!(
            core.bytes_read(ticket, object(21), b"return 2\n", check()),
            Err(Failure::SourceMismatch)
        );
        let partial = core.facts(id).unwrap();
        assert_eq!(partial.functions[0].hashed_bytes, 9);
        assert_eq!(
            partial.functions[0].prefix_sha256,
            <[u8; 32]>::from(Sha256::digest(b"return 2\n"))
        );
        assert_eq!(partial.functions[0].observed_sha256, None);
        assert_eq!(
            core.eof(ticket, object(21), check()),
            Err(Failure::SourceMismatch)
        );
        core.stream_closed(ticket, object(21), true, check())
            .unwrap();
        let facts = core.facts(id).unwrap();
        assert_ne!(
            facts.functions[0].observed_sha256,
            Some(facts.functions[0].expected_sha256)
        );
        assert!(!facts.consumed_parse_publication_observed);
    }
    #[test]
    fn original_deadline_failure_keeps_later_actual_read_eof_close_and_parse_facts() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        let ticket = prepared(&mut core, id);
        core.stream_opened(ticket, object(19), object(21), check())
            .unwrap();
        core.reader_bound(ticket, object(21), object(22), check())
            .unwrap();
        core.bytes_read(ticket, object(21), b"return ", check())
            .unwrap();
        let expired = Checkpoint {
            generation: 1,
            now_ms: 100,
        };
        assert_eq!(
            core.bytes_read(ticket, object(21), b"1\n", expired),
            Err(Failure::Deadline)
        );
        assert_eq!(
            core.eof(ticket, object(21), expired),
            Err(Failure::Deadline)
        );
        assert_eq!(
            core.stream_closed(ticket, object(21), true, expired),
            Err(Failure::Deadline)
        );
        assert_eq!(
            core.lines_returned(ticket, object(22), object(23), expired),
            Err(Failure::Deadline)
        );
        assert_eq!(
            core.function_returned(ticket, object(23), object(24), expired),
            Err(Failure::Deadline)
        );
        let facts = core.facts(id).unwrap();
        assert!(
            facts.functions[0].eof_observed
                && facts.functions[0].close_completed
                && facts.functions[0].parsed
        );
        assert_eq!(facts.functions[0].read_bytes, 9);
        assert!(!facts.consumed_parse_publication_observed);
    }
    #[test]
    fn actual_entry_completion_can_follow_publication_and_reload_observation() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        let ticket = prepared(&mut core, id);
        parsed_until_future(&mut core, ticket);
        core.functions_published(id, object(18), object(25), &entries(), check())
            .unwrap();
        core.server_installed(
            id,
            InstalledSourceView {
                server: object(1),
                manager: object(16),
                resources: object(17),
                library: object(18),
                published_map: object(25),
                entries: &entries(),
            },
            check(),
        )
        .unwrap();
        core.reload_future_bound(id, object(26), check()).unwrap();
        core.reload_terminal(id, object(26), ReloadOutcome::Completed, check())
            .unwrap();
        assert!(!core.facts(id).unwrap().consumed_parse_publication_observed);
        core.entry_completed(ticket, object(27), object(24), check())
            .unwrap();
        assert!(core.facts(id).unwrap().consumed_parse_publication_observed);
    }
    #[test]
    fn per_entry_future_can_bind_before_resource_is_read_on_another_executor() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        let ticket = submitted(&mut core, id);
        core.function_future_bound(ticket, object(20), object(27), check())
            .unwrap();
        core.resource_bound(
            ticket,
            "mmmm_calibration:function/test.mcfunction",
            object(19),
            object(15),
            check(),
        )
        .unwrap();
        core.stream_opened(ticket, object(19), object(21), check())
            .unwrap();
        core.reader_bound(ticket, object(21), object(22), check())
            .unwrap();
        core.bytes_read(ticket, object(21), b"return 1\n", check())
            .unwrap();
        core.eof(ticket, object(21), check()).unwrap();
        core.stream_closed(ticket, object(21), true, check())
            .unwrap();
        core.lines_returned(ticket, object(22), object(23), check())
            .unwrap();
        core.function_returned(ticket, object(23), object(24), check())
            .unwrap();
        core.entry_completed(ticket, object(27), object(24), check())
            .unwrap();
        assert!(core.facts(id).unwrap().functions[0].entry_completed);
    }
    #[test]
    fn failed_per_entry_future_keeps_actual_cause_even_without_a_resource() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        let ticket = submitted(&mut core, id);
        core.function_future_bound(ticket, object(20), object(27), check())
            .unwrap();
        core.entry_failed(ticket, object(27), object(90), check())
            .unwrap();
        let facts = core.facts(id).unwrap();
        assert!(facts.functions[0].entry_failed && !facts.functions[0].parsed);
        assert_eq!(facts.failure_causes, vec![Some(object(90))]);
        assert!(!facts.consumed_parse_publication_observed);
    }
    #[test]
    fn same_path_or_pack_name_cannot_replace_actual_source_pack_identity() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        let ticket = submitted(&mut core, id);
        assert_eq!(
            core.resource_bound(
                ticket,
                "mmmm_calibration:function/test.mcfunction",
                object(19),
                object(999),
                check()
            ),
            Err(Failure::Identity)
        );
        assert!(!core.facts(id).unwrap().consumed_parse_publication_observed);
    }
    #[test]
    fn actual_native_cause_and_later_close_failure_are_not_replaced() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        let ticket = prepared(&mut core, id);
        core.stream_opened(ticket, object(19), object(21), check())
            .unwrap();
        core.observed_native_failure(id, Failure::ReadFailed, object(90))
            .unwrap();
        assert_eq!(
            core.stream_closed(ticket, object(21), false, check()),
            Err(Failure::CloseFailed)
        );
        let facts = core.facts(id).unwrap();
        assert_eq!(facts.failure_causes, vec![Some(object(90)), None]);
        assert!(facts.functions[0].close_attempted && !facts.functions[0].close_completed);
    }
    #[test]
    fn expired_observation_keeps_bounded_relation_tickets_and_first_actual_cause() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        let ticket = submitted(&mut core, id);
        let expired = Checkpoint {
            generation: 1,
            now_ms: 100,
        };
        assert_eq!(
            core.function_future_bound(ticket, object(20), object(27), expired),
            Err(Failure::Deadline)
        );
        assert_eq!(
            core.resource_bound(
                ticket,
                "mmmm_calibration:function/test.mcfunction",
                object(19),
                object(15),
                expired
            ),
            Err(Failure::Deadline)
        );
        assert_eq!(
            core.stream_opened(ticket, object(19), object(21), expired),
            Err(Failure::Deadline)
        );
        for _ in 0..MAX_FAILURES {
            core.observed_failure(id, Failure::Deadline).unwrap();
        }
        assert_eq!(
            core.entry_failed(ticket, object(27), object(90), expired),
            Err(Failure::Deadline)
        );
        let facts = core.facts(id).unwrap();
        assert!(facts.functions[0].entry_failed && facts.failures_omitted > 0);
        assert_eq!(
            facts.first_native_cause,
            Some((Failure::ParseFailed, object(90)))
        );
        assert!(!facts.consumed_parse_publication_observed);
    }
    #[test]
    fn actual_submission_after_deadline_returns_a_factual_ticket_without_admission() {
        let mut core = RecordingCore::new();
        let id = arm(&mut core, 0);
        library_prepared(&mut core, id);
        let expired = Checkpoint {
            generation: 1,
            now_ms: 100,
        };
        let ticket = core
            .function_submitted(
                id,
                object(18),
                object(16),
                "mmmm_calibration:test",
                object(20),
                expired,
            )
            .unwrap();
        assert_eq!(
            core.function_future_bound(ticket, object(20), object(27), expired),
            Err(Failure::Deadline)
        );
        assert_eq!(
            core.entry_failed(ticket, object(27), object(90), expired),
            Err(Failure::Deadline)
        );
        assert!(core.facts(id).unwrap().functions[0].entry_failed);
        // Expiration never relaxes the original expected-source boundary.
        assert_eq!(
            core.function_submitted(
                id,
                object(18),
                object(16),
                "mmmm_calibration:other",
                object(30),
                expired
            ),
            Err(Failure::SourceMismatch)
        );
        assert!(!core.facts(id).unwrap().consumed_parse_publication_observed);
    }
}

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
        capture.retired = true;
        Ok(())
    }
    pub(crate) fn close_admission(&mut self, reason: Failure, generation: u64) {
        self.closed = true;
        self.first_admission_failure
            .get_or_insert((reason, generation));
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

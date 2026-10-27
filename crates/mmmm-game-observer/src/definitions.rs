// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors

//! 네이티브 정의 경계가 관측한 사실만 보관하는, VM 호출 없는 기록 코어.
//!
//! 이 모듈의 정수 식별자는 JNI 전역 참조 등록부가 발급한다. 포인터 값,
//! 클래스 이름, 호출자가 제출한 receipt를 객체 동일성의 근거로 쓰지 않는다.
//! 각 native define 호출은 thread별 stack의 독립 토큰을 갖는다. 실패한 호출이
//! 남긴 클래스 효과는 tombstone으로 남기며 다음 호출에 넘기지 않는다.

use std::collections::{HashMap, HashSet};

pub(crate) const MAX_CLASSES: usize = 4096;
pub(crate) const MAX_METHODS: usize = 4096;
pub(crate) const MAX_CLASS_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_ATTEMPT_DEPTH: usize = 64;
const MAX_ACTIVE_ATTEMPTS: usize = MAX_CLASSES;
const MAGIC: &[u8; 8] = b"MMMMDEF1";
// 길이 접두사와 빈 필드까지 포함한 frame 고정 크기. 메서드당 17바이트를 추가한다.
const WIRE_FIXED_BYTES: usize = 96;
const WIRE_METHOD_BYTES: usize = 17;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DefinitionKind {
    Ordinary,
    Hidden,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MethodCode {
    Bytecodes(Vec<u8>),
    Native,
    Abstract,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MethodSnapshot {
    pub name_mutf8: Vec<u8>,
    pub descriptor_mutf8: Vec<u8>,
    pub modifiers: i32,
    pub code: MethodCode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecutableSnapshot {
    pub constant_pool_count: u32,
    pub constant_pool: Vec<u8>,
    pub methods: Vec<MethodSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HiddenRecipe {
    pub input: Vec<u8>,
    pub flags: i32,
    pub initialize: bool,
    pub lookup_class_id: u64,
    pub defining_loader_id: u64,
    pub requested_name_mutf8: Vec<u8>,
}

/// 필드는 비공개다. JNI 경계는 begin이 발급한 토큰만 finish에 돌려준다.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AttemptId(u64);

impl AttemptId {
    pub(crate) fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RecordingError {
    InputContract,
    NoActiveAttempt,
    InvalidToken,
    HookMismatch,
    DuplicateHook,
    UnexpectedHiddenHook,
    ExistingClass,
    ClassMismatch,
    MetadataMismatch,
    MissingHook,
    MissingClassObservation,
    MissingHiddenSnapshot,
    NativeException { class_effect: Option<u64> },
    NativeReturnedNull { class_effect: Option<u64> },
    NotPrepared,
    Unavailable,
    Invalidated,
    ResourceLimit,
}

impl RecordingError {
    pub(crate) fn is_resource_limit(&self) -> bool {
        matches!(self, Self::ResourceLimit)
    }
}

struct Attempt {
    id: AttemptId,
    kind: DefinitionKind,
    loader_id: u64,
    requested_name: Option<Vec<u8>>,
    hidden_recipe: Option<HiddenRecipe>,
    controlled_recipe_interposition: bool,
    terminal_bytes: Option<Vec<u8>>,
    actual_class_id: Option<u64>,
    actual_name_utf8: Option<Vec<u8>>,
    load_seen: bool,
    prepared: bool,
    snapshot: Option<ExecutableSnapshot>,
    error: Option<RecordingError>,
    bytes: usize,
}

struct DefinitionRecord {
    id: u64,
    generation: u64,
    attempt_id: AttemptId,
    kind: DefinitionKind,
    name_utf8: Vec<u8>,
    loader_id: u64,
    terminal_bytes: Vec<u8>,
    hidden_recipe: Option<HiddenRecipe>,
    controlled_recipe_interposition: bool,
    prepared: bool,
    snapshot: Option<ExecutableSnapshot>,
    invalidated: bool,
    bytes: usize,
}

/// 현재 prepared ordinary 기록을 core 잠금 안에서만 빌리는 내부 source다.
/// JNI 참조나 실행 권한을 담지 않으며 terminal 입력과 VM snapshot을 복제하지 않는다.
pub(crate) struct OrdinarySourceView<'source> {
    issuer_epoch: u64,
    class_id: u64,
    generation: u64,
    loader_id: u64,
    name_utf8: &'source [u8],
    terminal_bytes: &'source [u8],
    snapshot: &'source ExecutableSnapshot,
}

impl OrdinarySourceView<'_> {
    pub(crate) fn identity(&self) -> (u64, u64, u64, u64) {
        (
            self.issuer_epoch,
            self.class_id,
            self.generation,
            self.loader_id,
        )
    }

    pub(crate) fn name_utf8(&self) -> &[u8] {
        self.name_utf8
    }

    pub(crate) fn terminal_bytes(&self) -> &[u8] {
        self.terminal_bytes
    }

    pub(crate) fn snapshot(&self) -> &ExecutableSnapshot {
        self.snapshot
    }
}

/// 같은 잠금 안에서 인코딩한 실제 기록에만 결합되는 비공개 발급 표식이다.
/// 외부 정수나 디코딩한 frame으로 생성하지 않으며 실행 권한을 부여하지 않는다.
pub(crate) struct EvidenceStamp {
    issuer_epoch: u64,
    class_id: u64,
    generation: u64,
    attempt_id: AttemptId,
    loader_id: u64,
    kind: DefinitionKind,
}

pub(crate) struct RecordingCore {
    issuer_epoch: u64,
    next_attempt: u64,
    stacks: HashMap<u64, Vec<Attempt>>,
    seen_classes: HashSet<u64>,
    invalidated_classes: HashSet<u64>,
    records: HashMap<u64, DefinitionRecord>,
    active_attempts: usize,
    retained_bytes: usize,
    exhausted: bool,
    #[cfg(test)]
    force_record_reservation_failure: bool,
}

impl RecordingCore {
    pub(crate) fn new(issuer_epoch: u64) -> Self {
        Self {
            issuer_epoch,
            next_attempt: 1,
            stacks: HashMap::new(),
            seen_classes: HashSet::new(),
            invalidated_classes: HashSet::new(),
            records: HashMap::new(),
            active_attempts: 0,
            retained_bytes: 0,
            exhausted: issuer_epoch == 0,
            #[cfg(test)]
            force_record_reservation_failure: false,
        }
    }

    /// 요청 이름은 CFLH와 같은 internal-name 표기여야 한다. 실제 클래스의
    /// getName() 값은 class_load/class_prepare에서 별도로 받는다.
    pub(crate) fn begin(
        &mut self,
        thread_id: u64,
        defining_loader_id: u64,
        requested_name_mutf8: Option<Vec<u8>>,
        kind: DefinitionKind,
        hidden_recipe: Option<HiddenRecipe>,
        controlled_recipe_interposition: bool,
    ) -> Result<AttemptId, RecordingError> {
        self.check_available()?;
        if thread_id == 0 {
            return Err(RecordingError::InputContract);
        }
        match (kind, hidden_recipe.as_ref()) {
            (DefinitionKind::Ordinary, None) => {}
            (DefinitionKind::Hidden, Some(recipe))
                if controlled_recipe_interposition
                    && recipe.lookup_class_id != 0
                    && recipe.defining_loader_id == defining_loader_id
                    && recipe.flags & 0x2 != 0
                    && !recipe.input.is_empty() => {}
            _ => return Err(RecordingError::InputContract),
        }
        let bytes = checked_sum([
            WIRE_FIXED_BYTES,
            requested_name_mutf8.as_ref().map_or(0, Vec::len),
            hidden_recipe.as_ref().map_or(0, recipe_bytes),
        ])?;
        if self.active_attempts >= MAX_ACTIVE_ATTEMPTS
            || self.stacks.get(&thread_id).map_or(0, Vec::len) >= MAX_ATTEMPT_DEPTH
            || self.next_attempt == u64::MAX
        {
            return self.exhaust();
        }
        self.charge(bytes, bytes)?;
        if self.stacks.try_reserve(1).is_err()
            || self
                .stacks
                .entry(thread_id)
                .or_default()
                .try_reserve(1)
                .is_err()
        {
            return self.exhaust();
        }
        let id = AttemptId(self.next_attempt);
        self.next_attempt += 1;
        self.active_attempts += 1;
        self.stacks.entry(thread_id).or_default().push(Attempt {
            id,
            kind,
            loader_id: defining_loader_id,
            requested_name: requested_name_mutf8,
            hidden_recipe,
            controlled_recipe_interposition,
            terminal_bytes: None,
            actual_class_id: None,
            actual_name_utf8: None,
            load_seen: false,
            prepared: false,
            snapshot: None,
            error: None,
            bytes,
        });
        Ok(id)
    }

    /// launcher가 별도로 닫은 terminal pipeline의 해당 환경 입력을 받는다.
    /// 코어 자체는 다른 agent의 후속 변환이 없다는 사실을 증명하지 않는다.
    pub(crate) fn terminal_hook(
        &mut self,
        thread_id: u64,
        loader_id: u64,
        name: Option<&[u8]>,
        bytes: Vec<u8>,
    ) -> Result<(), RecordingError> {
        self.check_available()?;
        let attempt = self.current(thread_id)?;
        let error = if attempt.kind == DefinitionKind::Hidden {
            Some(RecordingError::UnexpectedHiddenHook)
        } else if attempt.terminal_bytes.is_some() {
            Some(RecordingError::DuplicateHook)
        } else if attempt.loader_id != loader_id
            || attempt
                .requested_name
                .as_deref()
                .is_some_and(|expected| Some(expected) != name)
            || bytes.is_empty()
        {
            Some(RecordingError::HookMismatch)
        } else {
            None
        };
        if let Some(error) = error {
            return self.reject_current(thread_id, error);
        }
        let added = bytes.len();
        let total = checked_sum([attempt.bytes, added])?;
        self.charge(added, total)?;
        let attempt = self.current_mut(thread_id)?;
        attempt.bytes = total;
        attempt.terminal_bytes = Some(bytes);
        Ok(())
    }

    /// 모든 ClassLoad에서 호출한다. 관측 경계 밖의 정의도 seen에 남겨
    /// 기존 클래스의 후속 initiating-loader 통지를 새 정의로 취급하지 않는다.
    pub(crate) fn class_load(
        &mut self,
        thread_id: u64,
        actual_class_id: u64,
        defining_loader_id: u64,
        actual_name_utf8: Vec<u8>,
    ) -> Result<(), RecordingError> {
        self.observe_class(
            thread_id,
            actual_class_id,
            defining_loader_id,
            actual_name_utf8,
            false,
            None,
        )
    }

    /// 일반 클래스의 prepare가 native 복귀보다 늦어도 보관한 동일 실제
    /// identity만 갱신한다. hidden은 VM에서 얻은 snapshot이 필요하다.
    pub(crate) fn class_prepare(
        &mut self,
        thread_id: u64,
        actual_class_id: u64,
        defining_loader_id: u64,
        actual_name_utf8: Vec<u8>,
        snapshot: Option<ExecutableSnapshot>,
    ) -> Result<(), RecordingError> {
        self.check_available()?;
        if self.records.contains_key(&actual_class_id) {
            return self.prepare_record(
                actual_class_id,
                defining_loader_id,
                actual_name_utf8,
                snapshot,
            );
        }
        self.observe_class(
            thread_id,
            actual_class_id,
            defining_loader_id,
            actual_name_utf8,
            true,
            snapshot,
        )
    }

    fn observe_class(
        &mut self,
        thread_id: u64,
        actual_class_id: u64,
        defining_loader_id: u64,
        actual_name_utf8: Vec<u8>,
        prepared: bool,
        snapshot: Option<ExecutableSnapshot>,
    ) -> Result<(), RecordingError> {
        self.check_available()?;
        if actual_class_id == 0 || actual_name_utf8.is_empty() {
            return Err(RecordingError::InputContract);
        }
        let already_seen = self.seen_classes.contains(&actual_class_id);
        if !already_seen {
            if self.seen_classes.len() >= MAX_CLASSES {
                return self.exhaust();
            }
            if self.seen_classes.try_reserve(1).is_err() {
                return self.exhaust();
            }
            self.seen_classes.insert(actual_class_id);
        }
        let Some(attempt) = self.stacks.get(&thread_id).and_then(|stack| stack.last()) else {
            return Ok(());
        };
        let error = if self.invalidated_classes.contains(&actual_class_id) {
            Some(RecordingError::Invalidated)
        } else if attempt.loader_id != defining_loader_id {
            Some(RecordingError::MetadataMismatch)
        } else if attempt
            .actual_class_id
            .is_some_and(|id| id != actual_class_id)
        {
            Some(RecordingError::ClassMismatch)
        } else if already_seen && attempt.actual_class_id != Some(actual_class_id) {
            Some(RecordingError::ExistingClass)
        } else if attempt
            .actual_name_utf8
            .as_ref()
            .is_some_and(|name| name != &actual_name_utf8)
        {
            Some(RecordingError::MetadataMismatch)
        } else if (!prepared && attempt.load_seen) || (prepared && attempt.prepared) {
            Some(RecordingError::ExistingClass)
        } else {
            None
        };
        if let Some(error) = error {
            return self.reject_current(thread_id, error);
        }
        if let Some(snapshot) = snapshot.as_ref()
            && let Err(error) = validate_snapshot(snapshot)
        {
            if error.is_resource_limit() {
                return self.exhaust();
            }
            return self.reject_current(thread_id, error);
        }
        let added = checked_sum([
            if attempt.actual_name_utf8.is_none() {
                actual_name_utf8.len()
            } else {
                0
            },
            snapshot.as_ref().map_or(0, snapshot_bytes),
        ])?;
        let total = checked_sum([attempt.bytes, added])?;
        self.charge(added, total)?;
        let attempt = self.current_mut(thread_id)?;
        attempt.bytes = total;
        attempt.actual_class_id = Some(actual_class_id);
        if attempt.actual_name_utf8.is_none() {
            attempt.actual_name_utf8 = Some(actual_name_utf8);
        }
        if prepared {
            attempt.prepared = true;
            attempt.snapshot = snapshot;
        } else {
            attempt.load_seen = true;
        }
        Ok(())
    }

    /// 원래 native 호출의 반환값에 관해 판단하지 않고 관측만 포기한다.
    /// 메타데이터/전역 참조 실패 뒤 사용하며, 알려진 클래스 효과는 seen에
    /// 남긴다. 전역 자원 실패 상태에서도 소유한 임시 기록은 해제할 수 있다.
    pub(crate) fn abort_observation(
        &mut self,
        thread_id: u64,
        token: AttemptId,
    ) -> Result<(), RecordingError> {
        if self.current(thread_id)?.id != token {
            self.discard_thread(thread_id);
            return Err(RecordingError::InvalidToken);
        }
        let attempt = self
            .stacks
            .get_mut(&thread_id)
            .and_then(Vec::pop)
            .ok_or(RecordingError::NoActiveAttempt)?;
        self.active_attempts -= 1;
        self.retained_bytes -= attempt.bytes;
        if self.stacks.get(&thread_id).is_some_and(Vec::is_empty) {
            self.stacks.remove(&thread_id);
        }
        Ok(())
    }

    pub(crate) fn finish(
        &mut self,
        thread_id: u64,
        token: AttemptId,
        returned_class_id: Option<u64>,
        exception_pending: bool,
    ) -> Result<(), RecordingError> {
        if self.exhausted {
            self.abort_observation(thread_id, token)?;
            return Err(RecordingError::ResourceLimit);
        }
        if self.current(thread_id)?.id != token {
            self.discard_thread(thread_id);
            return Err(RecordingError::InvalidToken);
        }
        let attempt = self
            .stacks
            .get_mut(&thread_id)
            .and_then(Vec::pop)
            .ok_or(RecordingError::NoActiveAttempt)?;
        self.active_attempts -= 1;
        if self.stacks.get(&thread_id).is_some_and(Vec::is_empty) {
            self.stacks.remove(&thread_id);
        }
        let effect = attempt.actual_class_id;
        let error = if exception_pending {
            Some(RecordingError::NativeException {
                class_effect: effect,
            })
        } else if returned_class_id.is_none() {
            Some(RecordingError::NativeReturnedNull {
                class_effect: effect,
            })
        } else if let Some(error) = attempt.error.clone() {
            Some(error)
        } else if returned_class_id != effect {
            Some(RecordingError::ClassMismatch)
        } else if !attempt.load_seen && !attempt.prepared {
            Some(RecordingError::MissingClassObservation)
        } else if attempt.kind == DefinitionKind::Ordinary && attempt.terminal_bytes.is_none() {
            Some(RecordingError::MissingHook)
        } else if attempt.kind == DefinitionKind::Hidden
            && (!attempt.prepared || attempt.snapshot.is_none())
        {
            Some(RecordingError::MissingHiddenSnapshot)
        } else if effect.is_some_and(|id| self.records.contains_key(&id)) {
            Some(RecordingError::ExistingClass)
        } else {
            None
        };
        if let Some(error) = error {
            self.retained_bytes -= attempt.bytes;
            return Err(error);
        }
        // 위 동일성 검사로 두 값은 Some이고, ID는 native의 강참조에 결합된다.
        let id = effect.ok_or(RecordingError::MissingClassObservation)?;
        let name_utf8 = attempt
            .actual_name_utf8
            .ok_or(RecordingError::MissingClassObservation)?;
        let reservation_failed = self.records.try_reserve(1).is_err();
        // 실제 allocator OOM을 유발하지 않고 정리 경로만 검사하는 내부 test hook.
        #[cfg(test)]
        let reservation_failed = reservation_failed || self.force_record_reservation_failure;
        if reservation_failed {
            self.retained_bytes -= attempt.bytes;
            return self.exhaust();
        }
        self.records.insert(
            id,
            DefinitionRecord {
                id,
                generation: 1,
                attempt_id: attempt.id,
                kind: attempt.kind,
                name_utf8,
                loader_id: attempt.loader_id,
                terminal_bytes: attempt.terminal_bytes.unwrap_or_default(),
                hidden_recipe: attempt.hidden_recipe,
                controlled_recipe_interposition: attempt.controlled_recipe_interposition,
                prepared: attempt.prepared,
                snapshot: attempt.snapshot,
                invalidated: false,
                bytes: attempt.bytes,
            },
        );
        Ok(())
    }

    fn prepare_record(
        &mut self,
        id: u64,
        loader_id: u64,
        name: Vec<u8>,
        snapshot: Option<ExecutableSnapshot>,
    ) -> Result<(), RecordingError> {
        let record = self.records.get(&id).ok_or(RecordingError::Unavailable)?;
        if record.invalidated {
            return Err(RecordingError::Invalidated);
        }
        if record.loader_id != loader_id || record.name_utf8 != name {
            self.invalidate_class(id);
            return Err(RecordingError::MetadataMismatch);
        }
        if record.prepared {
            return Err(RecordingError::ExistingClass);
        }
        if let Some(snapshot) = snapshot.as_ref()
            && let Err(error) = validate_snapshot(snapshot)
        {
            if error.is_resource_limit() {
                return self.exhaust();
            }
            self.invalidate_class(id);
            return Err(error);
        }
        let added = snapshot.as_ref().map_or(0, snapshot_bytes);
        let total = checked_sum([record.bytes, added])?;
        self.charge(added, total)?;
        let record = self
            .records
            .get_mut(&id)
            .ok_or(RecordingError::Unavailable)?;
        record.bytes = total;
        record.snapshot = snapshot;
        record.prepared = true;
        Ok(())
    }

    /// 재정의/재변환이 시작되면 초기 정의 증거를 무효화한다. 실패한
    /// 재정의도 VM의 현재 상태를 별도로 관측하지 않고 초기 바이트로 인증하지 않는다.
    pub(crate) fn invalidate_class(&mut self, actual_class_id: u64) {
        if actual_class_id == 0 {
            return;
        }
        // 다른 callback의 lock 획득보다 재정의 통지가 빠를 수 있다. 아직
        // 현재 시도에 연결되지 않은 identity도 영구 tombstone으로 남긴다.
        if !self.seen_classes.contains(&actual_class_id) {
            if self.seen_classes.len() >= MAX_CLASSES || self.seen_classes.try_reserve(1).is_err() {
                self.exhausted = true;
                return;
            }
            self.seen_classes.insert(actual_class_id);
        }
        if !self.invalidated_classes.contains(&actual_class_id) {
            if self.invalidated_classes.try_reserve(1).is_err() {
                self.exhausted = true;
                return;
            }
            self.invalidated_classes.insert(actual_class_id);
        }
        if let Some(record) = self.records.get_mut(&actual_class_id) {
            record.generation = record.generation.saturating_add(1);
            record.invalidated = true;
        }
        for stack in self.stacks.values_mut() {
            for attempt in stack {
                if attempt.actual_class_id == Some(actual_class_id) {
                    attempt.error.get_or_insert(RecordingError::Invalidated);
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn contains_class(&self, actual_class_id: u64) -> bool {
        self.records.contains_key(&actual_class_id)
    }

    pub(crate) fn is_resource_exhausted(&self) -> bool {
        self.exhausted
    }

    /// 보관 payload 길이와 wire overhead의 보수적 합계다. Vec capacity와
    /// allocator heap 전체를 합산한 물리적 64 MiB 상한을 뜻하지 않는다.
    pub(crate) fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub(crate) fn ordinary_generation(&self, actual_class_id: u64) -> Option<u64> {
        self.current_record(actual_class_id)
            .filter(|record| record.kind == DefinitionKind::Ordinary)
            .map(|record| record.generation)
    }

    pub(crate) fn class_generation(&self, actual_class_id: u64) -> Option<u64> {
        self.current_record(actual_class_id)
            .map(|record| record.generation)
    }

    /// 외부 정수로 context를 만들지 않는다. native는 조회에 사용한 실제
    /// jclass 강참조와 이 내부 값들을 결합해 sealed context를 발급한다.
    pub(crate) fn hidden_context(&self, actual_class_id: u64) -> Option<(u64, u64, u64)> {
        let record = self.current_record(actual_class_id)?;
        if record.kind != DefinitionKind::Hidden
            || !record.controlled_recipe_interposition
            || record.snapshot.is_none()
        {
            return None;
        }
        let recipe = record.hidden_recipe.as_ref()?;
        Some((
            record.generation,
            recipe.lookup_class_id,
            recipe.defining_loader_id,
        ))
    }

    /// core lock 안에서 순수 matcher가 사용하는 내부 포트다. operation은
    /// JNI를 호출하지 않고, 결과 T는 인자로 빌린 recipe/snapshot의 수명과
    /// 독립적이다. SAM이 없는 hidden 기록도 보관 상태를 바꾸지 않는다.
    pub(crate) fn with_hidden_source<T>(
        &self,
        actual_class_id: u64,
        expected_generation: u64,
        operation: impl FnOnce(&HiddenRecipe, &ExecutableSnapshot) -> T,
    ) -> Option<T> {
        if self.issuer_epoch == 0 {
            return None;
        }
        let (generation, _, _) = self.hidden_context(actual_class_id)?;
        if generation != expected_generation {
            return None;
        }
        let record = self.current_record(actual_class_id)?;
        let recipe = record.hidden_recipe.as_ref()?;
        let snapshot = record.snapshot.as_ref()?;
        Some(operation(recipe, snapshot))
    }

    /// 실제 native stamp의 issuer/class/loader/generation을 모두 비교한다.
    /// operation은 잠금 안에서 순수 Rust만 실행하며 반환 T는 빌린 source의
    /// 수명과 독립적이다. source가 없거나 거절되어도 기록을 변경하지 않는다.
    pub(crate) fn with_ordinary_source<T>(
        &self,
        expected_issuer: u64,
        actual_class_id: u64,
        expected_generation: u64,
        expected_loader: u64,
        operation: impl for<'source> FnOnce(OrdinarySourceView<'source>) -> T,
    ) -> Option<T> {
        if expected_issuer == 0 || self.issuer_epoch != expected_issuer {
            return None;
        }
        let record = self.current_record(actual_class_id)?;
        if record.id != actual_class_id
            || record.kind != DefinitionKind::Ordinary
            || record.generation != expected_generation
            || record.loader_id != expected_loader
            || record.terminal_bytes.is_empty()
        {
            return None;
        }
        let snapshot = record.snapshot.as_ref()?;
        Some(operation(OrdinarySourceView {
            issuer_epoch: self.issuer_epoch,
            class_id: record.id,
            generation: record.generation,
            loader_id: record.loader_id,
            name_utf8: &record.name_utf8,
            terminal_bytes: &record.terminal_bytes,
            snapshot,
        }))
    }

    fn current_record(&self, actual_class_id: u64) -> Option<&DefinitionRecord> {
        if self.exhausted {
            return None;
        }
        self.records
            .get(&actual_class_id)
            .filter(|record| record.prepared && !record.invalidated)
    }

    pub(crate) fn active_kind(&self, thread_id: u64) -> Option<DefinitionKind> {
        if self.exhausted {
            return None;
        }
        self.stacks
            .get(&thread_id)
            .and_then(|stack| stack.last())
            .map(|attempt| attempt.kind)
    }

    pub(crate) fn needs_snapshot(&self, actual_class_id: u64) -> bool {
        if self.exhausted {
            return false;
        }
        self.records
            .get(&actual_class_id)
            .is_some_and(|record| !record.prepared && !record.invalidated)
            || self.stacks.values().flatten().any(|attempt| {
                attempt.actual_class_id == Some(actual_class_id)
                    && !attempt.prepared
                    && attempt.error.is_none()
            })
    }

    /// 반환한 표식은 JNI 배열 생성 뒤 같은 현재 기록인지 재확인할 때만 쓴다.
    pub(crate) fn encode_evidence_with_stamp(
        &self,
        actual_class_id: u64,
    ) -> Result<(Vec<u8>, EvidenceStamp), RecordingError> {
        let bytes = self.encode_evidence(actual_class_id)?;
        let record = self
            .current_record(actual_class_id)
            .ok_or(RecordingError::Unavailable)?;
        let stamp = EvidenceStamp {
            issuer_epoch: self.issuer_epoch,
            class_id: record.id,
            generation: record.generation,
            attempt_id: record.attempt_id,
            loader_id: record.loader_id,
            kind: record.kind,
        };
        Ok((bytes, stamp))
    }

    pub(crate) fn evidence_stamp_is_current(&self, stamp: &EvidenceStamp) -> bool {
        self.issuer_epoch == stamp.issuer_epoch
            && self.current_record(stamp.class_id).is_some_and(|record| {
                record.id == stamp.class_id
                    && record.generation == stamp.generation
                    && record.attempt_id == stamp.attempt_id
                    && record.loader_id == stamp.loader_id
                    && record.kind == stamp.kind
            })
    }

    /// 내부 JNI bridge가 호출한다. SHA나 caller receipt를 받지 않고
    /// 저장한 실제 버퍼를 반환한다. target profile의 권한을 부여하지 않는다.
    pub(crate) fn encode_evidence(&self, actual_class_id: u64) -> Result<Vec<u8>, RecordingError> {
        self.check_available()?;
        let record = self
            .records
            .get(&actual_class_id)
            .ok_or(RecordingError::Unavailable)?;
        if record.invalidated {
            return Err(RecordingError::Invalidated);
        }
        if !record.prepared {
            return Err(RecordingError::NotPrepared);
        }
        if record.kind == DefinitionKind::Hidden && record.snapshot.is_none() {
            return Err(RecordingError::MissingHiddenSnapshot);
        }
        let mut writer = EvidenceWriter(Vec::new());
        writer.raw(MAGIC)?;
        writer.u8(match record.kind {
            DefinitionKind::Ordinary => 1,
            DefinitionKind::Hidden => 2,
        })?;
        writer.u8(
            u8::from(record.prepared) | (u8::from(record.controlled_recipe_interposition) << 1)
        )?;
        writer.raw(&[0, 0])?;
        for value in [
            record.id,
            record.generation,
            record.attempt_id.raw(),
            self.issuer_epoch,
        ] {
            writer.raw(&value.to_be_bytes())?;
        }
        writer.sized(&record.name_utf8)?;
        writer.sized(&record.terminal_bytes)?;
        let recipe = record.hidden_recipe.as_ref();
        writer.sized(recipe.map_or(&[], |recipe| recipe.input.as_slice()))?;
        writer.raw(&recipe.map_or(0, |recipe| recipe.flags).to_be_bytes())?;
        writer.u8(u8::from(recipe.is_some_and(|recipe| recipe.initialize)))?;
        writer.raw(&[0, 0, 0])?;
        writer.raw(
            &recipe
                .map_or(0, |recipe| recipe.lookup_class_id)
                .to_be_bytes(),
        )?;
        // 일반/hidden 모두 실제 정의 시도와 Class 관측에서 대조한 loader다.
        // 0은 실제 bootstrap loader이며 recipe 부재를 나타내는 값이 아니다.
        writer.raw(&record.loader_id.to_be_bytes())?;
        writer.sized(recipe.map_or(&[], |recipe| recipe.requested_name_mutf8.as_slice()))?;
        let snapshot = record.snapshot.as_ref();
        writer.raw(
            &snapshot
                .map_or(0, |snapshot| snapshot.constant_pool_count)
                .to_be_bytes(),
        )?;
        writer.sized(snapshot.map_or(&[], |snapshot| snapshot.constant_pool.as_slice()))?;
        writer
            .raw(&(snapshot.map_or(0, |snapshot| snapshot.methods.len()) as u32).to_be_bytes())?;
        if let Some(snapshot) = snapshot {
            for method in &snapshot.methods {
                writer.sized(&method.name_mutf8)?;
                writer.sized(&method.descriptor_mutf8)?;
                writer.raw(&method.modifiers.to_be_bytes())?;
                let (kind, code): (u8, &[u8]) = match &method.code {
                    MethodCode::Bytecodes(bytes) => (0, bytes),
                    MethodCode::Native => (1, &[]),
                    MethodCode::Abstract => (2, &[]),
                };
                writer.u8(kind)?;
                writer.sized(code)?;
            }
        }
        Ok(writer.0)
    }

    fn current(&self, thread_id: u64) -> Result<&Attempt, RecordingError> {
        self.stacks
            .get(&thread_id)
            .and_then(|stack| stack.last())
            .ok_or(RecordingError::NoActiveAttempt)
    }

    fn current_mut(&mut self, thread_id: u64) -> Result<&mut Attempt, RecordingError> {
        self.stacks
            .get_mut(&thread_id)
            .and_then(|stack| stack.last_mut())
            .ok_or(RecordingError::NoActiveAttempt)
    }

    fn reject_current<T>(
        &mut self,
        thread_id: u64,
        error: RecordingError,
    ) -> Result<T, RecordingError> {
        self.current_mut(thread_id)?
            .error
            .get_or_insert(error.clone());
        Err(error)
    }

    fn check_available(&self) -> Result<(), RecordingError> {
        if self.exhausted {
            Err(RecordingError::ResourceLimit)
        } else {
            Ok(())
        }
    }

    fn charge(&mut self, added: usize, class_total: usize) -> Result<(), RecordingError> {
        let total = self.retained_bytes.checked_add(added);
        if class_total > MAX_CLASS_BYTES || total.is_none_or(|total| total > MAX_TOTAL_BYTES) {
            return self.exhaust();
        }
        self.retained_bytes = total.ok_or(RecordingError::ResourceLimit)?;
        Ok(())
    }

    fn exhaust<T>(&mut self) -> Result<T, RecordingError> {
        self.exhausted = true;
        Err(RecordingError::ResourceLimit)
    }

    fn discard_thread(&mut self, thread_id: u64) {
        if let Some(stack) = self.stacks.remove(&thread_id) {
            self.active_attempts -= stack.len();
            for attempt in stack {
                self.retained_bytes -= attempt.bytes;
            }
        }
    }
}

fn checked_sum<const N: usize>(values: [usize; N]) -> Result<usize, RecordingError> {
    values.into_iter().try_fold(0usize, |sum, value| {
        sum.checked_add(value).ok_or(RecordingError::ResourceLimit)
    })
}

fn recipe_bytes(recipe: &HiddenRecipe) -> usize {
    recipe
        .input
        .len()
        .saturating_add(recipe.requested_name_mutf8.len())
}

fn snapshot_bytes(snapshot: &ExecutableSnapshot) -> usize {
    snapshot
        .methods
        .iter()
        .fold(snapshot.constant_pool.len(), |sum, method| {
            sum.saturating_add(WIRE_METHOD_BYTES)
                .saturating_add(method.name_mutf8.len())
                .saturating_add(method.descriptor_mutf8.len())
                .saturating_add(match &method.code {
                    MethodCode::Bytecodes(bytes) => bytes.len(),
                    _ => 0,
                })
        })
}

fn validate_snapshot(snapshot: &ExecutableSnapshot) -> Result<(), RecordingError> {
    if snapshot.methods.len() > MAX_METHODS || snapshot_bytes(snapshot) > MAX_CLASS_BYTES {
        return Err(RecordingError::ResourceLimit);
    }
    if snapshot.constant_pool_count == 0
        || snapshot.constant_pool_count > 65535
        || snapshot.constant_pool.is_empty()
        || snapshot.methods.iter().any(|method| {
            method.name_mutf8.is_empty()
                || method.descriptor_mutf8.is_empty()
                || match &method.code {
                    MethodCode::Bytecodes(bytes) => {
                        bytes.is_empty() || method.modifiers & (0x100 | 0x400) != 0
                    }
                    MethodCode::Native => {
                        method.modifiers & 0x100 == 0 || method.modifiers & 0x400 != 0
                    }
                    MethodCode::Abstract => {
                        method.modifiers & 0x400 == 0 || method.modifiers & 0x100 != 0
                    }
                }
        })
    {
        return Err(RecordingError::InputContract);
    }
    Ok(())
}

struct EvidenceWriter(Vec<u8>);

impl EvidenceWriter {
    fn raw(&mut self, bytes: &[u8]) -> Result<(), RecordingError> {
        let end = self
            .0
            .len()
            .checked_add(bytes.len())
            .ok_or(RecordingError::ResourceLimit)?;
        if end > MAX_CLASS_BYTES {
            return Err(RecordingError::ResourceLimit);
        }
        self.0
            .try_reserve(bytes.len())
            .map_err(|_| RecordingError::ResourceLimit)?;
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), RecordingError> {
        self.raw(&[value])
    }

    fn sized(&mut self, bytes: &[u8]) -> Result<(), RecordingError> {
        let len = u32::try_from(bytes.len()).map_err(|_| RecordingError::ResourceLimit)?;
        self.raw(&len.to_be_bytes())?;
        self.raw(bytes)
    }
}

#[cfg(test)]
#[path = "definitions_tests.rs"]
mod tests;

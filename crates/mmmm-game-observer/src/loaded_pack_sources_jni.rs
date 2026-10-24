// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
//! Actual loader callback objects and consumed bytes, without replay authority.
//!
//! Only this attached JNI frame borrows an env, a NativeCall, or a fresh current
//! port. Retained ObjectIds are issued after a strong global and IsSameObject.
//! Receipt bytes describe bounded historical observations; they grant nothing.

use crate::{
    ffi::{self, JNIEnv, jclass, jint, jmethodID, jobject},
    library_lifetime,
    loaded_pack_sources::{
        self as core, CaptureBinding, CaptureId, Checkpoint, ContinuationTicket, ExpectedSources,
        Failure, FunctionTicket, ObjectId, RecordingCore, ReloadOutcome,
    },
    native_producer::{
        self, ObservedClassStamp, ReadReceiverStamp, SourceCaptureStamp, SourceCaptureToken,
    },
    owned_pack_files::{self, SourceRootObjects},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::CStr,
    path::PathBuf,
    ptr,
    sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock},
    thread::ThreadId,
    time::{Duration, Instant},
};

const CAPTURES: usize = 8;
// Independent observer admission policy, not a Java thread or executor bound.
// At most 64 outer Locals sets and the sole Turn owner's current inner set exist.
const ACTIVE_FRAMES: usize = 64;
const OBJECTS: usize = 512;
const OPENED_PACKS: usize = 256;
const FUNCTIONS: usize = 47;
const EVENTS: u64 = 200_000;
const OBSERVATION_MS: u64 = 120_000;
const SOURCE_BYTES: usize = 64 * 1024;
const TOTAL_BYTES: usize = 1024 * 1024;
const RECEIPT_BYTES: usize = 64 * 1024;
const FRAME_LOCALS: usize = 1024;
const NATIVE_CAUSES: usize = 16;
const PHASES: usize = 47;
fn object_limit(first_cause: bool, historical_cause_present: bool) -> usize {
    if first_cause && !historical_cause_present {
        OBJECTS
    } else {
        OBJECTS - 1
    }
}
fn object_slot(
    retained: usize,
    first_cause: bool,
    historical_cause_present: bool,
) -> std::result::Result<(), Failure> {
    if retained < object_limit(first_cause, historical_cause_present) {
        Ok(())
    } else {
        Err(Failure::ResourceLimit)
    }
}

enum Error {
    Ffi(ffi::FfiError),
    Fact(Failure),
    Gap(&'static str),
    Root(owned_pack_files::Failure),
    Post(Box<Error>, Box<Error>),
}
impl From<ffi::FfiError> for Error {
    fn from(value: ffi::FfiError) -> Self {
        Self::Ffi(value)
    }
}
impl From<Failure> for Error {
    fn from(value: Failure) -> Self {
        Self::Fact(value)
    }
}
type Result<T> = std::result::Result<T, Error>;
impl owned_pack_files::CurrentRootError for Error {
    fn root(failure: owned_pack_files::Failure) -> Self {
        Self::Root(failure)
    }
    fn post(primary: Self, post: owned_pack_files::Failure) -> Self {
        Self::Post(Box::new(primary), Box::new(Self::Root(post)))
    }
}

struct Global {
    id: Option<ObjectId>,
    reference: usize,
}
struct EntryFunction {
    name: String,
    identifier: ObjectId,
    supplier: ObjectId,
    ticket: FunctionTicket,
    compiled: Option<ObjectId>,
}
struct SelectedEntry {
    name: String,
    function: ObjectId,
    resource: ObjectId,
    entry: ObjectId,
    supplier: ObjectId,
}
struct Preparation {
    library: ObjectId,
    receiver_future: ObjectId,
    function: ObjectId,
    input_map: Option<ObjectId>,
    invocation: Option<ObjectId>,
    entered: bool,
    terminal: bool,
    returned_stage: Option<ObjectId>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum RelationKind {
    Consumer,
    Operation,
}
struct Relation {
    kind: RelationKind,
    owner: ObjectId,
    callback: ObjectId,
    input: Option<ObjectId>,
    entered: bool,
    terminal: bool,
}
enum NativeCause {
    Io(std::io::Error),
    RetainedIo(Arc<owned_pack_files::RetainedCloseCause>),
    Lifetime(&'static library_lifetime::LibraryLifetimeError),
    Throwable(Option<ObjectId>),
    Post(Box<NativeCause>, Box<NativeCause>),
    Boundary(&'static str),
    Ffi(ffi::FfiError),
    Fact(Failure),
}
struct Capture {
    id: Option<CaptureId>,
    // All six fields are compared against actual interned callback objects.
    binding: Option<CaptureBinding>,
    original: Option<[ObjectId; 6]>,
    selection: Option<ObjectId>,
    stamp: [(u64, u64); 4],
    class_stamps: Vec<ObservedClassStamp>,
    read_stamps: Vec<ReadReceiverStamp>,
    objects: Vec<ObjectId>,
    functions: Vec<EntryFunction>,
    selected: Vec<SelectedEntry>,
    preparation: Option<Preparation>,
    relations: Vec<Relation>,
    continuation: Option<ContinuationTicket>,
    continuation_function: Option<ObjectId>,
    continuation_future: Option<ObjectId>,
    root_supplier: Option<ObjectId>,
    opened: Option<ObjectId>,
    manager: Option<ObjectId>,
    resources: Option<ObjectId>,
    library: Option<ObjectId>,
    source_pack: Option<ObjectId>,
    published_map: Option<ObjectId>,
    installed_function_manager: Option<ObjectId>,
    library_replacement_observed: bool,
    reload_future: Option<ObjectId>,
    first_observation_throwable: Option<ObjectId>,
    first_throwable: Option<ObjectId>,
    native_causes: Vec<NativeCause>,
    native_causes_omitted: usize,
    unissued_refs: usize,
    events: u64,
    phases: [u64; PHASES],
    total_bytes: usize,
    started_ms: u64,
    last_ms: u64,
    deadline: Instant,
    current_root_observed: bool,
    current_resources_observed: bool,
    current_functions_observed: bool,
    current_error: Option<&'static str>,
    current_causes: Vec<NativeCause>,
    current_causes_omitted: usize,
    last_gap: Option<&'static str>,
    last_scalars: [i64; 3],
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FrameLimitRejections {
    // This count saturates; a value of u64::MAX is a lower bound, not a wrap.
    count: u64,
    first_raw_phase: Option<jint>,
}
impl FrameLimitRejections {
    fn record(&mut self, raw_phase: jint) {
        self.count = self.count.saturating_add(1);
        self.first_raw_phase.get_or_insert(raw_phase);
    }
}

fn frame_entry_open(producer_status: jint, closed: bool) -> Result<()> {
    if producer_status < 0 || closed {
        return Err(Failure::AdmissionClosed.into());
    }
    Ok(())
}

struct Registry {
    core: RecordingCore,
    captures: Vec<Capture>,
    globals: Vec<Global>,
    next_object: u64,
    origin: Instant,
    closed: bool,
    active: usize,
    historical_frame_rejections: FrameLimitRejections,
    current_frame_rejections: FrameLimitRejections,
    turn: Option<ThreadId>,
    vm_owned_refs: usize,
}
impl Registry {
    fn new() -> Self {
        Self {
            core: RecordingCore::new(),
            captures: Vec::new(),
            globals: Vec::new(),
            next_object: 1,
            origin: Instant::now(),
            closed: false,
            active: 0,
            historical_frame_rejections: FrameLimitRejections::default(),
            current_frame_rejections: FrameLimitRejections::default(),
            turn: None,
            vm_owned_refs: 0,
        }
    }
    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
    fn admit_frame(&mut self, raw_phase: jint, producer_status: jint) -> Result<()> {
        frame_entry_open(producer_status, self.closed)?;
        if self.active >= ACTIVE_FRAMES {
            // No port/class/capture admission has occurred. Only the raw input
            // category is recorded; this cannot name or fail a capture.
            if raw_phase == 43 {
                self.current_frame_rejections.record(raw_phase);
            } else {
                self.historical_frame_rejections.record(raw_phase);
            }
            return Err(Failure::ResourceLimit.into());
        }
        self.active = self.active.checked_add(1).ok_or(Failure::ResourceLimit)?;
        Ok(())
    }
    fn release_frame(&mut self) {
        self.active = self.active.saturating_sub(1);
    }
    fn take_turn(&mut self, thread: ThreadId) -> Result<bool> {
        if self.closed {
            return Err(Failure::AdmissionClosed.into());
        }
        if self.turn.is_none() {
            self.turn = Some(thread);
            return Ok(true);
        }
        if self.turn == Some(thread) {
            return Err(Error::Gap("reentrant_native_event"));
        }
        Ok(false)
    }
    fn release_turn(&mut self, thread: ThreadId) {
        if self.turn == Some(thread) {
            self.turn = None;
        }
    }
    fn reference(&self, id: ObjectId) -> Result<jobject> {
        self.globals
            .iter()
            .find(|global| global.id == Some(id))
            .map(|global| global.reference as jobject)
            .ok_or(Error::Fact(Failure::Identity))
    }
    fn note(&mut self, index: usize, failure: Failure, cause: Option<ObjectId>) {
        if let Some(id) = self.captures[index].id {
            match cause {
                Some(cause) => {
                    let _ = self.core.observed_native_failure(id, failure, cause);
                }
                None => {
                    let _ = self.core.observed_failure(id, failure);
                }
            }
        }
    }
    unsafe fn register(
        &mut self,
        env: *mut JNIEnv,
        index: usize,
        object: jobject,
        first_cause: bool,
        source: Option<SourceCaptureStamp>,
    ) -> Result<ObjectId> {
        if self.closed {
            return Err(Failure::AdmissionClosed.into());
        }
        if object.is_null() {
            return Err(Failure::Identity.into());
        }
        let existing = self
            .globals
            .iter()
            .find_map(|global| {
                if source.is_some_and(|source| !source.is_current()) {
                    return Some(Err(Error::Fact(Failure::GenerationChanged)));
                }
                match unsafe { ffi::same_object(env, object, global.reference as jobject) } {
                    Ok(_) if source.is_some_and(|source| !source.is_current()) => {
                        Some(Err(Error::Fact(Failure::GenerationChanged)))
                    }
                    Ok(true) => global.id.map(Ok),
                    Ok(false) => None,
                    Err(error) => Some(Err(Error::Ffi(error))),
                }
            })
            .transpose()?;
        if let Some(id) = existing {
            if !self.captures[index].objects.contains(&id) {
                object_slot(
                    self.captures[index].objects.len() + self.captures[index].unissued_refs,
                    first_cause,
                    self.captures[index].first_throwable.is_some(),
                )?;
                self.captures[index].objects.push(id);
            }
            return Ok(id);
        }
        object_slot(
            self.captures[index].objects.len() + self.captures[index].unissued_refs,
            first_cause,
            self.captures[index].first_throwable.is_some(),
        )?;
        if self.globals.len() == CAPTURES * OBJECTS {
            return Err(Failure::ResourceLimit.into());
        }
        // These reservations precede the actual NewGlobalRef side effect.
        self.globals
            .try_reserve_exact(CAPTURES * OBJECTS - self.globals.len())
            .map_err(|_| Error::Fact(Failure::ResourceLimit))?;
        let remaining_objects = OBJECTS - self.captures[index].objects.len();
        self.captures[index]
            .objects
            .try_reserve_exact(remaining_objects)
            .map_err(|_| Error::Fact(Failure::ResourceLimit))?;
        let next = self
            .next_object
            .checked_add(1)
            .ok_or(Failure::ResourceLimit)?;
        if source.is_some_and(|source| !source.is_current()) {
            return Err(Failure::GenerationChanged.into());
        }
        let reference = unsafe { ffi::new_global(env, object)? };
        let verified = if source.is_some_and(|source| !source.is_current()) {
            Err(Error::Fact(Failure::GenerationChanged))
        } else {
            unsafe { ffi::same_object(env, object, reference) }.map_err(Error::Ffi)
        };
        let verified = if verified.is_ok() && source.is_some_and(|source| !source.is_current()) {
            Err(Error::Fact(Failure::GenerationChanged))
        } else {
            verified
        };
        match verified {
            Ok(true) => {}
            other => {
                // Keep the actual global even when validation failed; no issued
                // identity and no late Drop JNI. It occupies original capacity.
                self.globals.push(Global {
                    id: None,
                    reference: reference as usize,
                });
                self.captures[index].unissued_refs += 1;
                return match other {
                    Err(error) => Err(error),
                    _ => Err(Failure::Identity.into()),
                };
            }
        }
        let id = ObjectId::from_issuer(self.next_object)?;
        self.next_object = next;
        self.globals.push(Global {
            id: Some(id),
            reference: reference as usize,
        });
        self.captures[index].objects.push(id);
        Ok(id)
    }
}
struct Shared {
    state: Mutex<Registry>,
    wake: Condvar,
}
static SHARED: OnceLock<Shared> = OnceLock::new();
fn shared() -> &'static Shared {
    SHARED.get_or_init(|| Shared {
        state: Mutex::new(Registry::new()),
        wake: Condvar::new(),
    })
}
fn state() -> Result<MutexGuard<'static, Registry>> {
    shared()
        .state
        .lock()
        .map_err(|_| Error::Gap("native_registry_poisoned"))
}

// Only direct JNI operations without Java callbacks may run here. The module
// VMDeath/Unload close is serialized with the operation; producer status is
// sampled after locking because its negative publication precedes that close.
// This does not serialize every producer-status transition or Java getter.
fn with_cleanup_lifetime<T>(
    registry: &Mutex<Registry>,
    producer_status: impl FnOnce() -> jint,
    operation: impl FnOnce() -> std::result::Result<T, ffi::FfiError>,
) -> std::result::Result<Option<T>, ffi::FfiError> {
    let Ok(registry) = registry.lock() else {
        return Ok(None);
    };
    if frame_entry_open(producer_status(), registry.closed).is_err() {
        return Ok(None);
    }
    let result = operation().map(Some);
    drop(registry);
    result
}

fn cleanup_jni<T>(
    operation: impl FnOnce() -> std::result::Result<T, ffi::FfiError>,
) -> std::result::Result<Option<T>, ffi::FfiError> {
    let Some(shared) = SHARED.get() else {
        return Ok(None);
    };
    with_cleanup_lifetime(&shared.state, native_producer::status, operation)
}

struct Active;
impl Active {
    fn enter(raw_phase: jint) -> Result<Self> {
        // Producer VMDeath/Unload publishes its negative status before these
        // module hooks. A late entry must not initialize SHARED or use JNI.
        frame_entry_open(native_producer::status(), false)?;
        let mut state = state()?;
        state.admit_frame(raw_phase, native_producer::status())?;
        Ok(Self)
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        if let Ok(mut state) = shared().state.lock() {
            state.release_frame();
            // No JNI here: a frame surviving VMDeath leaves refs VM-owned.
        }
        shared().wake.notify_all();
    }
}
struct Turn(ThreadId);
impl Turn {
    fn enter(deadline: Instant) -> Result<Self> {
        let thread = std::thread::current().id();
        let mut registry = state()?;
        loop {
            if registry.take_turn(thread)? {
                return Ok(Self(thread));
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(Failure::Deadline)?;
            let (next, timeout) = shared()
                .wake
                .wait_timeout(registry, remaining)
                .map_err(|_| Error::Gap("native_registry_poisoned"))?;
            registry = next;
            if timeout.timed_out() && registry.turn.is_some() {
                return Err(Failure::Deadline.into());
            }
        }
    }
}
impl Drop for Turn {
    fn drop(&mut self) {
        if let Ok(mut state) = shared().state.lock() {
            state.release_turn(self.0);
        }
        shared().wake.notify_all();
    }
}

// This owner never leaves its current attached frame. Global owners have no
// JNI Drop, and neither a NativeCall nor an env is retained in Registry.
struct Locals<'a> {
    env: *mut JNIEnv,
    values: Vec<jobject>,
    observed: Vec<ObservedClassStamp>,
    read_observed: Vec<ReadReceiverStamp>,
    control: Option<&'a dyn owned_pack_files::CurrentObservationCheck>,
    source: Option<SourceCaptureStamp>,
    observer: Option<usize>,
    deadline: Instant,
    started_ms: u64,
}
impl<'a> Locals<'a> {
    fn live(&self) -> Result<()> {
        if state()?.closed {
            return Err(Failure::AdmissionClosed.into());
        }
        if self.source.is_some_and(|source| !source.is_current()) {
            state()?.core.close_admission(Failure::GenerationChanged, 1);
            return Err(Failure::GenerationChanged.into());
        }
        if self.observed.iter().any(|stamp| !stamp.is_current())
            || self.read_observed.iter().any(|stamp| !stamp.is_current())
        {
            state()?.core.close_admission(Failure::GenerationChanged, 1);
            return Err(Failure::GenerationChanged.into());
        }
        let Some(pending) = cleanup_jni(|| unsafe {
            if ffi::exception(self.env)? {
                ffi::take_exception(self.env).map(Some)
            } else {
                Ok(None)
            }
        })?
        else {
            return Err(Failure::AdmissionClosed.into());
        };
        if let Some(actual) = pending {
            return if actual.is_null() {
                Err(Error::Ffi(ffi::FfiError::PendingException))
            } else {
                Err(Error::Root(owned_pack_files::Failure::Checkpoint(actual)))
            };
        }
        if let Some(control) = self.control {
            control.check().map_err(Error::Root)?;
        }
        if Instant::now() >= self.deadline {
            if let Some(index) = self.observer.filter(|_| self.control.is_none()) {
                // A sticky observation failure does not erase an actual bounded
                // EOF/close/parse/publication already delivered by the engine.
                state()?.note(index, Failure::Deadline, None);
            } else {
                return Err(Failure::Deadline.into());
            }
        }
        if let Some(index) = self.observer {
            check_class_stamps(index, 1)?;
        }
        Ok(())
    }
    fn finish<T>(&self, primary: Result<T>) -> Result<T> {
        match (primary, self.live()) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(post)) => Err(post),
            (Err(primary), Err(post)) => Err(Error::Post(Box::new(primary), Box::new(post))),
        }
    }
    fn new(env: *mut JNIEnv) -> Result<Self> {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(OBSERVATION_MS))
            .ok_or(Failure::ResourceLimit)?;
        let started_ms = state()?.now_ms();
        let mut values = Vec::new();
        let mut observed = Vec::new();
        let mut read_observed = Vec::new();
        values
            .try_reserve_exact(FRAME_LOCALS)
            .map_err(|_| Failure::ResourceLimit)?;
        observed
            .try_reserve_exact(64)
            .map_err(|_| Failure::ResourceLimit)?;
        read_observed
            .try_reserve_exact(16)
            .map_err(|_| Failure::ResourceLimit)?;
        Ok(Self {
            env,
            values,
            observed,
            read_observed,
            control: None,
            source: None,
            observer: None,
            deadline,
            started_ms,
        })
    }
    fn with_control(
        env: *mut JNIEnv,
        control: &'a dyn owned_pack_files::CurrentObservationCheck,
        deadline: Instant,
        source: SourceCaptureStamp,
        index: usize,
    ) -> Result<Self> {
        let mut locals = Self::new(env)?;
        locals.control = Some(control);
        locals.deadline = deadline;
        locals.source = Some(source);
        locals.observer = Some(index);
        Ok(locals)
    }
    fn adopt(&mut self, value: jobject) -> Result<jobject> {
        if value.is_null() {
            return Err(Failure::Identity.into());
        }
        if self.values.len() == FRAME_LOCALS {
            // A rejected local stays VM-owned if shutdown has been observed.
            cleanup_jni(|| unsafe { ffi::delete_local(self.env, value) })?;
            return Err(Failure::ResourceLimit.into());
        }
        self.values.push(value);
        Ok(value)
    }
    fn optional(&mut self, value: Option<jobject>) -> Result<Option<jobject>> {
        value.map(|value| self.adopt(value)).transpose()
    }
    fn class(&mut self, object: jobject) -> Result<jclass> {
        self.live()?;
        let result = unsafe { ffi::object_class(self.env, object) }
            .map_err(Error::Ffi)
            .and_then(|class| self.adopt(class));
        self.finish(result)
    }
    fn method(&mut self, object: jobject, name: &CStr, signature: &CStr) -> Result<jmethodID> {
        let class = self.class(object)?;
        self.live()?;
        self.finish(unsafe { ffi::method_id(self.env, class, name, signature) }.map_err(Error::Ffi))
    }
    fn zero(&mut self, object: jobject, name: &CStr, signature: &CStr) -> Result<Option<jobject>> {
        self.live()?;
        let method = self.method(object, name, signature)?;
        let result = unsafe { ffi::call_object_zero_optional(self.env, object, method) }
            .map_err(Error::Ffi)
            .and_then(|value| self.optional(value));
        self.finish(result)
    }
    fn required_zero(&mut self, object: jobject, name: &CStr, signature: &CStr) -> Result<jobject> {
        self.zero(object, name, signature)?
            .ok_or(Error::Fact(Failure::Identity))
    }
    fn text(&mut self, string: jobject, cap: usize) -> Result<String> {
        self.live()?;
        let result = unsafe { ffi::string_utf16(self.env, string, cap) }
            .map_err(Error::Ffi)
            .and_then(|units| {
                String::from_utf16(&units).map_err(|_| Error::Fact(Failure::Identity))
            });
        self.finish(result)
    }
    fn same(&self, left: jobject, right: jobject) -> Result<bool> {
        self.live()?;
        self.finish(unsafe { ffi::same_object(self.env, left, right) }.map_err(Error::Ffi))
    }
    fn bytes(&self, array: jobject, cap: usize) -> Result<Vec<u8>> {
        self.live()?;
        self.finish(unsafe { ffi::whole_byte_array(self.env, array, cap) }.map_err(Error::Ffi))
    }
    fn units(&self, string: jobject, cap: usize) -> Result<Vec<u16>> {
        self.live()?;
        self.finish(unsafe { ffi::string_utf16(self.env, string, cap) }.map_err(Error::Ffi))
    }
    fn array_values(&mut self, array: jobject, cap: usize) -> Result<Vec<jobject>> {
        self.live()?;
        let values = match unsafe { ffi::object_array_values(self.env, array, cap) } {
            Ok(values) => values,
            Err(error) => return self.finish(Err(Error::Ffi(error))),
        };
        if values.len() > FRAME_LOCALS - self.values.len() {
            let mut first = None;
            for value in values {
                if let Err(error) = cleanup_jni(|| unsafe { ffi::delete_local(self.env, value) }) {
                    first.get_or_insert(error);
                }
            }
            return Err(first
                .map(Error::Ffi)
                .unwrap_or(Error::Fact(Failure::ResourceLimit)));
        }
        self.values.extend(values.iter().copied());
        self.finish(Ok(values))
    }
    fn collection_method(
        &mut self,
        token: &SourceCaptureToken,
        object: jobject,
        name: &CStr,
        signature: &CStr,
        list: bool,
    ) -> Result<jmethodID> {
        let actual = self.class(object)?;
        self.live()?;
        let class_signature = self.finish(
            unsafe { ffi::class_signature(native_producer::owned_files_vm(), actual) }
                .map_err(Error::Ffi),
        )?;
        let expected: &'static [u8] = match (list, class_signature.as_slice()) {
            (true, b"Lcom/google/common/collect/RegularImmutableList;") => {
                b"Lcom/google/common/collect/RegularImmutableList;"
            }
            (true, b"Lcom/google/common/collect/SingletonImmutableList;") => {
                b"Lcom/google/common/collect/SingletonImmutableList;"
            }
            (false, b"Lcom/google/common/collect/RegularImmutableMap;") => {
                b"Lcom/google/common/collect/RegularImmutableMap;"
            }
            _ => return Err(Error::Gap("unsupported_actual_collection_shape")),
        };
        let concrete = unsafe {
            native_producer::actual_read_receiver_class(self.env, token, actual, expected)
        }
        .map_err(|_| Error::Gap("collection_class_metadata_failed"))?
        .ok_or(Error::Gap("collection_class_unavailable"))?;
        let class = concrete
            .actual_class(token)
            .ok_or(Failure::GenerationChanged)?;
        self.live()?;
        let method = self.finish(
            unsafe { ffi::method_id(self.env, class, name, signature) }.map_err(Error::Ffi),
        )?;
        self.live()?;
        let declaring =
            unsafe { ffi::method_declaring_class(native_producer::owned_files_vm(), method)? };
        let declaring = self.adopt(declaring)?;
        self.live()?;
        let owner_signature = self.finish(
            unsafe { ffi::class_signature(native_producer::owned_files_vm(), declaring) }
                .map_err(Error::Ffi),
        )?;
        let owner: &'static [u8] = if list && name == c"toArray" {
            if owner_signature != b"Lcom/google/common/collect/ImmutableCollection;" {
                return Err(Error::Gap("unsupported_collection_method_owner"));
            }
            b"Lcom/google/common/collect/ImmutableCollection;"
        } else {
            if owner_signature != expected {
                return Err(Error::Gap("unsupported_collection_method_owner"));
            }
            expected
        };
        let owner = unsafe {
            native_producer::actual_read_receiver_class(self.env, token, declaring, owner)
        }
        .map_err(|_| Error::Gap("collection_owner_metadata_failed"))?
        .ok_or(Error::Gap("collection_owner_unavailable"))?;
        if concrete.loader() == 0 || concrete.loader() != owner.loader() {
            return Err(Failure::Identity.into());
        }
        for stamp in [concrete, owner] {
            if !stamp.is_current() {
                return Err(Failure::GenerationChanged.into());
            }
            if let Some(prior) = self
                .read_observed
                .iter()
                .find(|prior| prior.signature() == stamp.signature())
            {
                if prior.stamp() != stamp.stamp() || prior.loader() != stamp.loader() {
                    return Err(Failure::GenerationChanged.into());
                }
            } else {
                if self.read_observed.len() == 16 {
                    return Err(Failure::ResourceLimit.into());
                }
                self.read_observed.push(stamp);
            }
        }
        self.live()?;
        Ok(method)
    }
    fn collection_size(&mut self, token: &SourceCaptureToken, object: jobject) -> Result<jint> {
        let method = self.collection_method(token, object, c"size", c"()I", true)?;
        self.live()?;
        self.finish(unsafe { ffi::call_int_zero(self.env, object, method) }.map_err(Error::Ffi))
    }
    fn collection_array(&mut self, token: &SourceCaptureToken, object: jobject) -> Result<jobject> {
        let method =
            self.collection_method(token, object, c"toArray", c"()[Ljava/lang/Object;", true)?;
        self.live()?;
        let result = unsafe { ffi::call_object_zero_optional(self.env, object, method) }
            .map_err(Error::Ffi)
            .and_then(|value| value.ok_or(Error::Fact(Failure::Identity)))
            .and_then(|value| self.adopt(value));
        self.finish(result)
    }
    fn map_get(
        &mut self,
        token: &SourceCaptureToken,
        object: jobject,
        key: jobject,
    ) -> Result<jobject> {
        let method = self.collection_method(
            token,
            object,
            c"get",
            c"(Ljava/lang/Object;)Ljava/lang/Object;",
            false,
        )?;
        self.live()?;
        let result = unsafe { ffi::call_object_one_optional(self.env, object, method, key) }
            .map_err(Error::Ffi)
            .and_then(|value| value.ok_or(Error::Fact(Failure::MissingFunction)))
            .and_then(|value| self.adopt(value));
        self.finish(result)
    }
    fn observe_class(
        &mut self,
        token: &SourceCaptureToken,
        object: jobject,
        expected: &'static [u8],
    ) -> Result<ObservedClassStamp> {
        let actual = self.class(object)?;
        let stamp =
            unsafe { native_producer::actual_source_class(self.env, token, actual, expected) }
                .map_err(|_| Error::Gap("observed_class_metadata_failed"))?
                .ok_or(Error::Gap("observed_class_unavailable"))?;
        if !token.is_current() || !stamp.is_current() {
            return Err(Failure::GenerationChanged.into());
        }
        if let Some(prior) = self
            .observed
            .iter()
            .find(|prior| prior.signature() == stamp.signature())
        {
            if prior.stamp() != stamp.stamp() || prior.loader() != stamp.loader() {
                return Err(Failure::GenerationChanged.into());
            }
        } else {
            if self.observed.len() == 64 {
                return Err(Failure::ResourceLimit.into());
            }
            self.observed.push(stamp);
        }
        self.finish(Ok(stamp))
    }
    fn identifier(&mut self, object: jobject, token: &SourceCaptureToken) -> Result<String> {
        self.exact_class(object, b"Lnet/minecraft/resources/Identifier;")?;
        self.observe_class(token, object, b"Lnet/minecraft/resources/Identifier;")?;
        let string = self.required_zero(object, c"toString", c"()Ljava/lang/String;")?;
        self.text(string, 1024)
    }
    fn exact_class(&mut self, object: jobject, signature: &[u8]) -> Result<()> {
        let class = self.class(object)?;
        self.live()?;
        let actual = self.finish(
            unsafe { ffi::class_signature(native_producer::owned_files_vm(), class) }
                .map_err(Error::Ffi),
        )?;
        if actual == signature {
            Ok(())
        } else {
            Err(Failure::Identity.into())
        }
    }
    fn close(&mut self) -> std::result::Result<(), ffi::FfiError> {
        let mut first = None;
        for value in self.values.drain(..).rev() {
            // Each no-callback deletion holds the module lifetime lock and
            // resamples producer status. Skipped actual refs remain VM-owned.
            if let Err(error) = cleanup_jni(|| unsafe { ffi::delete_local(self.env, value) }) {
                first.get_or_insert(error);
            }
        }
        first.map_or(Ok(()), Err)
    }
}
impl Drop for Locals<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[derive(Clone, Copy)]
#[repr(usize)]
enum Field {
    Server,
    Attempt,
    Invocation,
    Bundle,
    Anchor,
    Selection,
    Owner,
    Supplier,
    Executor,
    Future,
    Function,
    Consumer,
    Operation,
    Input,
    Result,
    Manager,
    Library,
    FunctionId,
    ResourceId,
    Resource,
    Stream,
    Reader,
    SourcePack,
    Entry,
}
const GETTERS: [&CStr; 24] = [
    c"nativeServer",
    c"nativeAttempt",
    c"nativeInvocation",
    c"nativeSealedFiles",
    c"nativeHeldRootAnchor",
    c"nativeSelection",
    c"nativeOwner",
    c"nativeSupplier",
    c"nativeExecutor",
    c"nativeFuture",
    c"nativeFunction",
    c"nativeConsumer",
    c"nativeOperation",
    c"nativeInput",
    c"nativeResult",
    c"nativeManager",
    c"nativeLibrary",
    c"nativeFunctionId",
    c"nativeResourceId",
    c"nativeResource",
    c"nativeStream",
    c"nativeReader",
    c"nativeSourcePack",
    c"nativeEntry",
];
struct Frame {
    objects: [Option<jobject>; 24],
    fresh: Option<jobject>,
    throwable: Option<jobject>,
    observation_throwable: Option<jobject>,
    reason: Option<String>,
    observation_reason: Option<String>,
    selected: Option<PathBuf>,
    phase: jint,
    amount: i64,
    requested: i64,
    original_offset: jint,
    payload_array: jobject,
    payload_length: usize,
}
impl Frame {
    fn object(&self, field: Field) -> Result<jobject> {
        self.objects[field as usize].ok_or(Error::Fact(Failure::Identity))
    }
    fn optional(&self, field: Field) -> Option<jobject> {
        self.objects[field as usize]
    }
    fn roots(&self) -> Result<SourceRootObjects> {
        Ok(SourceRootObjects {
            server: self.object(Field::Server)?,
            attempt: self.object(Field::Attempt)?,
            invocation: self.object(Field::Invocation)?,
            bundle: self.object(Field::Bundle)?,
            anchor: self.object(Field::Anchor)?,
        })
    }
}
fn path(units: Vec<u16>) -> Result<PathBuf> {
    if units.is_empty() || units.contains(&0) {
        return Err(Failure::Identity.into());
    }
    #[cfg(windows)]
    let path = {
        use std::os::windows::ffi::OsStringExt;
        PathBuf::from(std::ffi::OsString::from_wide(&units))
    };
    #[cfg(not(windows))]
    let path = PathBuf::from(String::from_utf16(&units).map_err(|_| Failure::Identity)?);
    if !path.is_absolute() {
        return Err(Failure::Identity.into());
    }
    Ok(path)
}
fn read_frame(
    locals: &mut Locals,
    port: jobject,
    bytes: jobject,
    offset: jint,
    length: jint,
    phase: jint,
) -> Result<Frame> {
    if !(0..PHASES as jint).contains(&phase)
        || offset != 0
        || length < 0
        || length as usize > SOURCE_BYTES
    {
        return Err(Failure::Identity.into());
    }
    let mut objects = [None; 24];
    for (slot, getter) in objects.iter_mut().zip(GETTERS) {
        *slot = locals.zero(port, getter, c"()Ljava/lang/Object;")?;
    }
    let scalar_array = locals.required_zero(port, c"nativeScalars", c"()[B")?;
    let scalar = locals.bytes(scalar_array, 24)?;
    if scalar.len() != 24 {
        return Err(Failure::Identity.into());
    }
    let scalar_phase = jint::from_be_bytes(scalar[0..4].try_into().map_err(|_| Failure::Identity)?);
    let amount = i64::from_be_bytes(scalar[4..12].try_into().map_err(|_| Failure::Identity)?);
    let requested = i64::from_be_bytes(scalar[12..20].try_into().map_err(|_| Failure::Identity)?);
    let original_offset =
        jint::from_be_bytes(scalar[20..24].try_into().map_err(|_| Failure::Identity)?);
    if scalar_phase != phase {
        return Err(Failure::Identity.into());
    }
    let fresh = locals.zero(port, c"nativeFreshCurrentPort", c"()Ljava/lang/Object;")?;
    if (phase == 43) != fresh.is_some() {
        return Err(Failure::Identity.into());
    }
    let throwable = locals.zero(port, c"nativeThrowable", c"()Ljava/lang/Throwable;")?;
    let observation_throwable = locals.zero(
        port,
        c"nativeObservationFailure",
        c"()Ljava/lang/Throwable;",
    )?;
    let reason = match locals.zero(port, c"nativeReason", c"()Ljava/lang/String;")? {
        Some(string) => Some(locals.text(string, 128)?),
        None => None,
    };
    let observation_reason = match locals.zero(
        port,
        c"nativeObservationFailureReason",
        c"()Ljava/lang/String;",
    )? {
        Some(string) => Some(locals.text(string, 128)?),
        None => None,
    };
    let selected = if phase == 19 {
        match locals.zero(port, c"nativeSelectedRoot", c"()Ljava/lang/String;")? {
            Some(string) => Some(path(locals.units(string, 32768)?)?),
            None => None,
        }
    } else {
        None
    };
    match phase {
        21 if amount > 0
            && amount == i64::from(length)
            && requested >= amount
            && original_offset >= 0 => {}
        22 if amount == -1 && requested > 0 && length == 0 && original_offset >= 0 => {}
        21 | 22 => return Err(Failure::ReadFailed.into()),
        _ if length != 0 => return Err(Failure::Identity.into()),
        _ => {}
    }
    Ok(Frame {
        objects,
        fresh,
        throwable,
        observation_throwable,
        reason,
        observation_reason,
        selected,
        phase,
        amount,
        requested,
        original_offset,
        payload_array: bytes,
        payload_length: length as usize,
    })
}

fn find_capture(locals: &mut Locals, frame: &Frame) -> Result<Option<usize>> {
    let selection = frame.object(Field::Selection)?;
    let references = {
        let registry = state()?;
        registry
            .captures
            .iter()
            .enumerate()
            .filter_map(|(index, capture)| {
                capture
                    .selection
                    .map(|id| registry.reference(id).map(|reference| (index, reference)))
            })
            .collect::<Result<Vec<_>>>()?
    };
    for (index, reference) in references {
        if locals.same(selection, reference)? {
            return Ok(Some(index));
        }
    }
    Ok(None)
}
fn reserve_capture(stamp: [(u64, u64); 4], deadline: Instant, started_ms: u64) -> Result<usize> {
    let mut registry = state()?;
    if registry.closed || registry.core.admission_facts().closed {
        return Err(Failure::AdmissionClosed.into());
    }
    if registry.captures.len() == CAPTURES {
        return Err(Failure::ResourceLimit.into());
    }
    registry
        .captures
        .try_reserve_exact(CAPTURES)
        .map_err(|_| Failure::ResourceLimit)?;
    let mut objects = Vec::new();
    let mut functions = Vec::new();
    let mut selected = Vec::new();
    let mut relations = Vec::new();
    let mut native_causes = Vec::new();
    let mut current_causes = Vec::new();
    let mut class_stamps = Vec::new();
    let mut read_stamps = Vec::new();
    objects
        .try_reserve_exact(OBJECTS)
        .map_err(|_| Failure::ResourceLimit)?;
    functions
        .try_reserve_exact(FUNCTIONS)
        .map_err(|_| Failure::ResourceLimit)?;
    selected
        .try_reserve_exact(FUNCTIONS)
        .map_err(|_| Failure::ResourceLimit)?;
    relations
        .try_reserve_exact(OBJECTS)
        .map_err(|_| Failure::ResourceLimit)?;
    native_causes
        .try_reserve_exact(NATIVE_CAUSES)
        .map_err(|_| Failure::ResourceLimit)?;
    current_causes
        .try_reserve_exact(NATIVE_CAUSES)
        .map_err(|_| Failure::ResourceLimit)?;
    class_stamps
        .try_reserve_exact(64)
        .map_err(|_| Failure::ResourceLimit)?;
    read_stamps
        .try_reserve_exact(16)
        .map_err(|_| Failure::ResourceLimit)?;
    let index = registry.captures.len();
    registry.captures.push(Capture {
        id: None,
        binding: None,
        original: None,
        selection: None,
        stamp,
        class_stamps,
        read_stamps,
        objects,
        functions,
        selected,
        preparation: None,
        relations,
        continuation: None,
        continuation_function: None,
        continuation_future: None,
        root_supplier: None,
        opened: None,
        manager: None,
        resources: None,
        library: None,
        source_pack: None,
        published_map: None,
        installed_function_manager: None,
        library_replacement_observed: false,
        reload_future: None,
        first_observation_throwable: None,
        first_throwable: None,
        native_causes,
        native_causes_omitted: 0,
        unissued_refs: 0,
        events: 0,
        phases: [0; PHASES],
        total_bytes: 0,
        started_ms,
        last_ms: started_ms,
        deadline,
        current_root_observed: false,
        current_resources_observed: false,
        current_functions_observed: false,
        current_error: None,
        current_causes,
        current_causes_omitted: 0,
        last_gap: None,
        last_scalars: [0; 3],
    });
    Ok(index)
}
fn intern(locals: &mut Locals, index: usize, object: jobject) -> Result<ObjectId> {
    locals.live()?;
    let result = unsafe { state()?.register(locals.env, index, object, false, locals.source) };
    locals.finish(result)
}
fn existing_id(locals: &mut Locals, object: jobject) -> Result<ObjectId> {
    let references = {
        let registry = state()?;
        if registry.closed || object.is_null() {
            return Err(Failure::Identity.into());
        }
        registry
            .globals
            .iter()
            .filter_map(|global| global.id.map(|id| (id, global.reference)))
            .collect::<Vec<_>>()
    };
    for (id, reference) in references {
        if locals.same(object, reference as jobject)? {
            return Ok(id);
        }
    }
    Err(Failure::Identity.into())
}
fn cause_object(locals: &mut Locals, index: usize, object: jobject) -> Result<ObjectId> {
    let mut registry = state()?;
    frame_entry_open(native_producer::status(), registry.closed)?;
    let cause = unsafe { registry.register(locals.env, index, object, true, None)? };
    registry.captures[index]
        .first_throwable
        .get_or_insert(cause);
    Ok(cause)
}
fn current_cause_object(locals: &mut Locals, index: usize, object: jobject) -> Result<ObjectId> {
    // Current read failures never consume the source's reserved first-cause
    // slot or set its first_throwable. Full general capacity stays explicit.
    let mut registry = state()?;
    frame_entry_open(native_producer::status(), registry.closed)?;
    unsafe { registry.register(locals.env, index, object, false, None) }
}
fn field_id(locals: &mut Locals, index: usize, frame: &Frame, field: Field) -> Result<ObjectId> {
    intern(locals, index, frame.object(field)?)
}
fn optional_id(
    locals: &mut Locals,
    index: usize,
    object: Option<jobject>,
) -> Result<Option<ObjectId>> {
    object
        .map(|object| intern(locals, index, object))
        .transpose()
}
fn common_ids(locals: &mut Locals, index: usize, frame: &Frame) -> Result<[ObjectId; 6]> {
    // Selection is first, so a failed arm still has a routable preserved slot.
    let selection = field_id(locals, index, frame, Field::Selection)?;
    state()?.captures[index].selection = Some(selection);
    Ok([
        field_id(locals, index, frame, Field::Server)?,
        field_id(locals, index, frame, Field::Attempt)?,
        field_id(locals, index, frame, Field::Invocation)?,
        field_id(locals, index, frame, Field::Bundle)?,
        field_id(locals, index, frame, Field::Anchor)?,
        selection,
    ])
}
fn check_class_stamps(index: usize, generation: u64) -> Result<()> {
    let (stamps, read) = {
        let registry = state()?;
        (
            registry.captures[index].class_stamps.clone(),
            registry.captures[index].read_stamps.clone(),
        )
    };
    if stamps.iter().any(|stamp| !stamp.is_current())
        || read.iter().any(|stamp| !stamp.is_current())
    {
        state()?
            .core
            .close_admission(Failure::GenerationChanged, generation);
        return Err(Failure::GenerationChanged.into());
    }
    Ok(())
}
fn retain_read_stamps(index: usize, locals: &Locals) -> Result<()> {
    for stamp in &locals.read_observed {
        if !stamp.is_current() {
            return Err(Failure::GenerationChanged.into());
        }
        let mut registry = state()?;
        let capture = &mut registry.captures[index];
        if let Some(prior) = capture
            .read_stamps
            .iter()
            .find(|prior| prior.signature() == stamp.signature())
        {
            if prior.stamp() != stamp.stamp() || prior.loader() != stamp.loader() {
                return Err(Failure::GenerationChanged.into());
            }
        } else {
            if capture.read_stamps.len() == 16 {
                return Err(Failure::ResourceLimit.into());
            }
            capture.read_stamps.push(*stamp);
        }
    }
    Ok(())
}
fn retain_class_stamp(
    index: usize,
    token: &SourceCaptureToken,
    stamp: ObservedClassStamp,
) -> Result<()> {
    if !token.is_current() || !stamp.is_current() {
        state()?
            .core
            .close_admission(Failure::GenerationChanged, token.generation());
        return Err(Failure::GenerationChanged.into());
    }
    let mut registry = state()?;
    if let Some(existing) = registry.captures[index]
        .class_stamps
        .iter()
        .find(|existing| existing.signature() == stamp.signature())
    {
        if existing.stamp() != stamp.stamp() || existing.loader() != stamp.loader() {
            registry
                .core
                .close_admission(Failure::GenerationChanged, token.generation());
            return Err(Failure::GenerationChanged.into());
        }
        return Ok(());
    }
    if registry.captures[index].class_stamps.len() == 64 {
        return Err(Failure::ResourceLimit.into());
    }
    registry.captures[index].class_stamps.push(stamp);
    Ok(())
}
fn stamp_named(
    locals: &mut Locals,
    index: usize,
    token: &SourceCaptureToken,
    expected: &'static [u8],
) -> Result<ObservedClassStamp> {
    locals.live()?;
    let stamp = unsafe { native_producer::source_class_by_name(locals.env, token, expected) }
        .map_err(|_| Error::Gap("observed_class_metadata_failed"))?
        .ok_or(Error::Gap("observed_class_unavailable"))?;
    retain_class_stamp(index, token, stamp)?;
    locals.finish(Ok(stamp))
}
fn stamp_object(
    locals: &mut Locals,
    index: usize,
    token: &SourceCaptureToken,
    object: jobject,
    expected: &'static [u8],
) -> Result<ObservedClassStamp> {
    let stamp = locals.observe_class(token, object, expected)?;
    retain_class_stamp(index, token, stamp)?;
    Ok(stamp)
}
fn stamp_event_classes(
    locals: &mut Locals,
    index: usize,
    frame: &Frame,
    token: &SourceCaptureToken,
) -> Result<()> {
    check_class_stamps(index, token.generation())?;
    stamp_named(
        locals,
        index,
        token,
        b"Lio/github/daejunnom/mmmm/fabric/NativeFunctionLoadObservation;",
    )?;
    if matches!(frame.phase, 1..=4) {
        stamp_named(
            locals,
            index,
            token,
            b"Lio/github/daejunnom/mmmm/fabric/NativeFunctionLoadObservation$TrackedSupplier;",
        )?;
    }
    if matches!(frame.phase, 5..=8 | 17) {
        stamp_named(
            locals,
            index,
            token,
            b"Lio/github/daejunnom/mmmm/fabric/NativeFunctionLoadObservation$TrackedFunction;",
        )?;
    }
    if matches!(frame.phase, 19..=32 | 39 | 41 | 42 | 44) {
        stamp_object(
            locals,
            index,
            token,
            frame.object(Field::Owner)?,
            b"Lio/github/daejunnom/mmmm/fabric/NativeFunctionLoadObservation$Read;",
        )?;
    }
    if let Some(library) = frame.optional(Field::Library) {
        stamp_object(
            locals,
            index,
            token,
            library,
            b"Lnet/minecraft/server/ServerFunctionLibrary;",
        )?;
    }
    if frame.phase == 17 {
        stamp_object(
            locals,
            index,
            token,
            frame.object(Field::Manager)?,
            b"Lnet/minecraft/server/packs/resources/MultiPackResourceManager;",
        )?;
    }
    if frame.phase == 18 {
        stamp_object(
            locals,
            index,
            token,
            frame.object(Field::Input)?,
            b"Lnet/minecraft/server/ReloadableServerResources;",
        )?;
    }
    Ok(())
}
fn check_common(
    locals: &mut Locals,
    index: usize,
    frame: &Frame,
    token: &SourceCaptureToken,
) -> Result<Checkpoint> {
    if !token.is_current() {
        state()?
            .core
            .close_admission(Failure::GenerationChanged, token.generation());
        return Err(Failure::GenerationChanged.into());
    }
    let ids = if frame.phase == 43 {
        let (ids, references) = {
            let registry = state()?;
            let binding = registry.captures[index]
                .binding
                .as_ref()
                .ok_or(Failure::Identity)?;
            let ids = [
                binding.server,
                binding.attempt,
                binding.invocation,
                binding.bundle,
                binding.root_anchor,
                binding.selection,
            ];
            let references = ids
                .iter()
                .map(|id| registry.reference(*id))
                .collect::<Result<Vec<_>>>()?;
            (ids, references)
        };
        for (field, reference) in [
            Field::Server,
            Field::Attempt,
            Field::Invocation,
            Field::Bundle,
            Field::Anchor,
            Field::Selection,
        ]
        .into_iter()
        .zip(references)
        {
            if !locals.same(frame.object(field)?, reference)? {
                return Err(Failure::Identity.into());
            }
        }
        ids
    } else {
        common_ids(locals, index, frame)?
    };
    let mut registry = state()?;
    let now_ms = registry.now_ms();
    let capture = &mut registry.captures[index];
    if capture.stamp != token.stamp() {
        registry
            .core
            .close_admission(Failure::GenerationChanged, token.generation());
        return Err(Failure::GenerationChanged.into());
    }
    let binding = capture
        .binding
        .as_ref()
        .ok_or(Error::Gap("original_arm_incomplete"))?;
    let expected = [
        binding.server,
        binding.attempt,
        binding.invocation,
        binding.bundle,
        binding.root_anchor,
        binding.selection,
    ];
    if capture.original != Some(ids) || expected != ids {
        registry
            .core
            .close_admission(Failure::Identity, token.generation());
        return Err(Failure::Identity.into());
    }
    if matches!(frame.phase, 38 | 43) {
        // Retirement is a lifecycle fact; a fresh read is a new bounded frame.
        // Neither rewrites a previously completed observation's clock/work.
        return Ok(Checkpoint {
            generation: token.generation(),
            now_ms,
        });
    }
    if capture.events == EVENTS {
        return Err(Failure::ResourceLimit.into());
    }
    capture.events += 1;
    capture.phases[frame.phase as usize] += 1;
    capture.last_scalars = [
        frame.amount,
        frame.requested,
        i64::from(frame.original_offset),
    ];
    let time_failure = if now_ms < capture.last_ms {
        Some(Failure::ClockRegressed)
    } else if now_ms >= binding.deadline_ms {
        Some(Failure::Deadline)
    } else {
        None
    };
    capture.last_ms = now_ms;
    if let Some(failure) = time_failure {
        registry.note(index, failure, None);
    }
    Ok(Checkpoint {
        generation: token.generation(),
        now_ms,
    })
}
fn arm(locals: &mut Locals, index: usize, frame: &Frame, token: &SourceCaptureToken) -> Result<()> {
    let original = common_ids(locals, index, frame)?;
    state()?.captures[index].original = Some(original);
    let deadline = state()?.captures[index].deadline;
    let root =
        owned_pack_files::observe_source_root(locals.env, token, frame.roots()?, None, deadline)
            .map_err(Error::Root)?;
    if !token.is_current() {
        return Err(Failure::GenerationChanged.into());
    }
    let expected = ExpectedSources::numeric47()?;
    let mut registry = state()?;
    let started_ms = registry.captures[index].started_ms;
    let binding = CaptureBinding {
        server: original[0],
        attempt: original[1],
        invocation: original[2],
        bundle: original[3],
        root_anchor: original[4],
        selection: original[5],
        bundle_digest: root.bundle_digest,
        generation: token.generation(),
        started_ms,
        deadline_ms: started_ms
            .checked_add(OBSERVATION_MS)
            .ok_or(Failure::ResourceLimit)?,
    };
    registry.captures[index].binding = Some(binding.clone());
    registry.captures[index].id = Some(registry.core.arm(binding, expected)?);
    Ok(())
}
fn capture_id(index: usize) -> Result<CaptureId> {
    state()?.captures[index]
        .id
        .ok_or(Error::Gap("original_arm_incomplete"))
}
fn ticket(index: usize, identifier: ObjectId) -> Result<FunctionTicket> {
    state()?.captures[index]
        .functions
        .iter()
        .find(|entry| entry.identifier == identifier)
        .map(|entry| entry.ticket)
        .ok_or(Error::Fact(Failure::InvalidTicket))
}
fn entry_for_supplier(index: usize, supplier: ObjectId) -> Result<Option<FunctionTicket>> {
    Ok(state()?.captures[index]
        .functions
        .iter()
        .find(|entry| entry.supplier == supplier)
        .map(|entry| entry.ticket))
}
fn native_cause(
    locals: &mut Locals,
    index: usize,
    failure: Failure,
    actual: jobject,
) -> Result<ObjectId> {
    let cause = cause_object(locals, index, actual)?;
    state()?.note(index, failure, Some(cause));
    Ok(cause)
}
fn observation_failure(locals: &mut Locals, index: usize, frame: &Frame) -> Result<()> {
    if let Some(actual) = frame.observation_throwable {
        let id = cause_object(locals, index, actual)?;
        let mut registry = state()?;
        if registry.captures[index].first_observation_throwable != Some(id) {
            registry.captures[index].first_observation_throwable = Some(id);
            let failure = reason_failure(frame.observation_reason.as_deref());
            registry.note(index, failure, Some(id));
        }
    }
    Ok(())
}
fn reason_failure(reason: Option<&str>) -> Failure {
    match reason {
        Some("ACTUAL_IO_FAILED" | "INVALID_READ_RESULT") => Failure::ReadFailed,
        Some("NONLINEAR_IO" | "UNSUPPORTED_IO" | "CONCURRENT_IO") => Failure::NonlinearRead,
        Some("DUPLICATE_CALLBACK") => Failure::Duplicate,
        Some("RETIRED") => Failure::Retired,
        _ => Failure::Identity,
    }
}
fn root_cause(
    locals: &mut Locals,
    index: usize,
    error: owned_pack_files::Failure,
    history: bool,
) -> NativeCause {
    use owned_pack_files::Failure as Root;
    match error {
        Root::Post(primary, post) => NativeCause::Post(
            Box::new(root_cause(locals, index, *primary, history)),
            Box::new(root_cause(locals, index, *post, history)),
        ),
        Root::Checkpoint(actual) => {
            let cause = locals.adopt(actual).ok().and_then(|actual| {
                if history {
                    native_cause(locals, index, Failure::Identity, actual).ok()
                } else {
                    current_cause_object(locals, index, actual).ok()
                }
            });
            NativeCause::Throwable(cause)
        }
        native @ (Root::Io(_) | Root::RetainedIo(_) | Root::Lifetime(_)) => {
            let native = match native {
                Root::Io(error) => NativeCause::Io(error),
                Root::RetainedIo(error) => NativeCause::RetainedIo(error),
                Root::Lifetime(error) => NativeCause::Lifetime(error),
                _ => NativeCause::Boundary("invalid"),
            };
            if history && let Ok(mut registry) = state() {
                registry.note(index, Failure::Identity, None);
            }
            native
        }
        Root::ObservationDeadline => {
            if history && let Ok(mut registry) = state() {
                registry.note(index, Failure::Deadline, None);
            }
            NativeCause::Boundary("observation_deadline")
        }
        boundary @ (Root::Changed
        | Root::Invalid
        | Root::Unavailable
        | Root::Busy
        | Root::Panic) => {
            if history && let Ok(mut registry) = state() {
                registry.note(index, Failure::Identity, None);
            }
            NativeCause::Boundary(match boundary {
                Root::Changed => "changed",
                Root::Invalid => "invalid",
                Root::Unavailable => "unavailable",
                Root::Busy => "busy",
                Root::Panic => "panic",
                _ => "invalid",
            })
        }
    }
}
fn retain_native_cause(index: usize, cause: NativeCause, current: bool) {
    if let Ok(mut registry) = state() {
        let capture = &mut registry.captures[index];
        if current {
            if capture.current_causes.len() < NATIVE_CAUSES {
                capture.current_causes.push(cause);
            } else {
                capture.current_causes_omitted = capture.current_causes_omitted.saturating_add(1);
            }
        } else {
            if capture.native_causes.len() < NATIVE_CAUSES {
                capture.native_causes.push(cause);
            } else {
                capture.native_causes_omitted = capture.native_causes_omitted.saturating_add(1);
            }
        }
    }
}
fn error_cause(locals: &mut Locals, index: usize, error: Error, current: bool) -> NativeCause {
    match error {
        Error::Root(root) => root_cause(locals, index, root, !current),
        Error::Post(primary, post) => NativeCause::Post(
            Box::new(error_cause(locals, index, *primary, current)),
            Box::new(error_cause(locals, index, *post, current)),
        ),
        Error::Fact(failure) => {
            if let Ok(mut registry) = state() {
                if failure == Failure::GenerationChanged {
                    registry.core.close_admission(failure, 1);
                }
                if !current {
                    registry.note(index, failure, None);
                }
            }
            NativeCause::Fact(failure)
        }
        Error::Ffi(error) => {
            if !current && let Ok(mut registry) = state() {
                registry.note(index, Failure::Identity, None);
            }
            NativeCause::Ffi(error)
        }
        Error::Gap(code) => {
            if !current && let Ok(mut registry) = state() {
                registry.note(index, Failure::Identity, None);
            }
            NativeCause::Boundary(code)
        }
    }
}
fn record_error(
    locals: &mut Locals,
    index: Option<usize>,
    error: Error,
    phase: jint,
) -> &'static str {
    let code = error_code(&error);
    let current = phase == 43;
    if let Some(index) = index {
        if let Ok(mut registry) = state() {
            if current {
                registry.captures[index].current_error = Some(code);
            } else {
                registry.captures[index].last_gap = Some(code);
            }
        }
        let cause = error_cause(locals, index, error, current);
        retain_native_cause(index, cause, current);
        if let Ok(Some(pending)) = cleanup_jni(|| unsafe { ffi::take_exception(locals.env) })
            && !pending.is_null()
            && let Ok(actual) = locals.adopt(pending)
        {
            if current {
                let cause = current_cause_object(locals, index, actual).ok();
                retain_native_cause(index, NativeCause::Throwable(cause), true);
            } else {
                let _ = native_cause(locals, index, Failure::Identity, actual);
            }
        }
    }
    code
}
fn error_code(error: &Error) -> &'static str {
    match error {
        Error::Ffi(ffi::FfiError::PendingException) => "actual_jni_throwable",
        Error::Ffi(_) => "jni_observation_failed",
        Error::Fact(failure) => failure_name(*failure),
        Error::Gap(code) => code,
        Error::Root(_) => "native_root_observation_failed",
        Error::Post(_, _) => "observation_and_post_failed",
    }
}
fn failure_name(failure: Failure) -> &'static str {
    match failure {
        Failure::Identity => "identity",
        Failure::UnexpectedOrder => "unexpected_order",
        Failure::Duplicate => "duplicate",
        Failure::InvalidTicket => "invalid_ticket",
        Failure::ResourceLimit => "resource_limit",
        Failure::SourceMismatch => "source_mismatch",
        Failure::MissingEof => "missing_eof",
        Failure::ReadFailed => "read_failed",
        Failure::CloseFailed => "close_failed",
        Failure::NonlinearRead => "nonlinear_read",
        Failure::ParseFailed => "parse_failed",
        Failure::MissingFunction => "missing_function",
        Failure::ReloadFailed => "reload_failed",
        Failure::Retired => "retired",
        Failure::Deadline => "deadline",
        Failure::ClockRegressed => "clock_regressed",
        Failure::GenerationChanged => "generation_changed",
        Failure::AdmissionClosed => "admission_closed",
    }
}

fn fact(result: std::result::Result<(), Failure>) -> Result<()> {
    // The core already preserved the physical effect and sticky clock failure.
    match result {
        Ok(()) | Err(Failure::Deadline | Failure::ClockRegressed) => Ok(()),
        Err(error) => Err(error.into()),
    }
}
fn selected_function(name: &str) -> Result<bool> {
    Ok(normative_resources()?.contains_key(name))
}
fn normative_resources() -> Result<&'static BTreeMap<String, String>> {
    static EXPECTED: OnceLock<std::result::Result<BTreeMap<String, String>, Failure>> =
        OnceLock::new();
    let expected = EXPECTED.get_or_init(|| {
        let suite = mmmm_compiler::calibration_dispatch::CalibrationDispatchPlan::normative47()
            .map_err(|_| Failure::SourceMismatch)?;
        let functions = suite
            .loaded_source_expectations()
            .map_err(|_| Failure::SourceMismatch)?;
        Ok(functions
            .iter()
            .map(|function| {
                (
                    function.function_id().as_str().to_owned(),
                    function.resource_id().as_str().to_owned(),
                )
            })
            .collect())
    });
    match expected {
        Ok(expected) => Ok(expected),
        Err(failure) => Err((*failure).into()),
    }
}
fn resource_join(
    locals: &mut Locals,
    index: usize,
    frame: &Frame,
    token: &SourceCaptureToken,
    check: Checkpoint,
) -> Result<ObjectId> {
    let resource = frame.object(Field::Resource)?;
    let source = frame.object(Field::SourcePack)?;
    locals.exact_class(resource, b"Lnet/minecraft/server/packs/resources/Resource;")?;
    locals.exact_class(
        source,
        b"Lnet/minecraft/server/packs/FixedPathPackResources;",
    )?;
    stamp_object(
        locals,
        index,
        token,
        resource,
        b"Lnet/minecraft/server/packs/resources/Resource;",
    )?;
    stamp_object(
        locals,
        index,
        token,
        source,
        b"Lnet/minecraft/server/packs/FixedPathPackResources;",
    )?;
    stamp_named(
        locals,
        index,
        token,
        b"Lio/github/daejunnom/mmmm/fabric/mixin/FixedPathPackReadAccess;",
    )?;
    let actual_source = locals.required_zero(
        resource,
        c"source",
        c"()Lnet/minecraft/server/packs/PackResources;",
    )?;
    if !locals.same(source, actual_source)? {
        return Err(Failure::Identity.into());
    }
    let source_id = locals.required_zero(resource, c"sourcePackId", c"()Ljava/lang/String;")?;
    let pack_id = locals.required_zero(source, c"packId", c"()Ljava/lang/String;")?;
    if locals.text(source_id, 1024)? != "mmmm-calibration-normative47"
        || locals.text(pack_id, 1024)? != "mmmm-calibration-normative47"
    {
        return Err(Failure::SourceMismatch.into());
    }
    let selected = frame
        .selected
        .as_deref()
        .ok_or(Error::Gap("unsupported_actual_pack_root_shape"))?;
    let (opened, continuation, prior, deadline, anchor) = {
        let registry = state()?;
        let capture = &registry.captures[index];
        (
            capture.opened.ok_or(Failure::UnexpectedOrder)?,
            capture.continuation.ok_or(Failure::InvalidTicket)?,
            capture.source_pack,
            capture.deadline,
            capture
                .binding
                .as_ref()
                .ok_or(Failure::Identity)?
                .root_anchor,
        )
    };
    let opened_ref = state()?.reference(opened)?;
    let size = locals.collection_size(token, opened_ref)?;
    if !(1..=OPENED_PACKS as jint).contains(&size) {
        return Err(Failure::ResourceLimit.into());
    }
    let array = locals.collection_array(token, opened_ref)?;
    let values = locals.array_values(array, OPENED_PACKS)?;
    if values.len() != size as usize {
        return Err(Failure::Identity.into());
    }
    let mut matches = 0usize;
    for actual in values {
        if locals.same(source, actual)? {
            matches += 1;
        }
    }
    let size_after = locals.collection_size(token, opened_ref)?;
    if matches != 1 || size_after != size {
        return Err(Failure::Identity.into());
    }
    let source_id = intern(locals, index, source)?;
    if let Some(prior) = prior {
        if prior != source_id {
            return Err(Failure::Identity.into());
        }
    } else {
        let roots = owned_pack_files::observe_source_root(
            locals.env,
            token,
            frame.roots()?,
            Some(selected),
            deadline,
        )
        .map_err(Error::Root)?;
        let expected = state()?.captures[index]
            .binding
            .as_ref()
            .ok_or(Failure::Identity)?
            .bundle_digest;
        if roots.bundle_digest != expected {
            return Err(Failure::SourceMismatch.into());
        }
        if !token.is_current() {
            return Err(Failure::GenerationChanged.into());
        }
        let mut registry = state()?;
        fact(registry.core.opened_pack_root_joined(
            continuation,
            opened,
            source_id,
            anchor,
            check,
        ))?;
        registry.captures[index].source_pack = Some(source_id);
    }
    // Re-read the actual winner. This is bounded identity evidence, not a claim
    // that an arbitrary mutable pack set was atomically snapshotted.
    let after = locals.required_zero(
        resource,
        c"source",
        c"()Lnet/minecraft/server/packs/PackResources;",
    )?;
    if !locals.same(after, source)? {
        return Err(Failure::Identity.into());
    }
    Ok(source_id)
}
fn selected_entries(
    locals: &mut Locals,
    index: usize,
    actual_map: jobject,
    token: &SourceCaptureToken,
) -> Result<Vec<(String, ObjectId)>> {
    let keys = {
        let registry = state()?;
        let functions = &registry.captures[index].functions;
        if functions.len() != FUNCTIONS {
            return Err(Failure::MissingFunction.into());
        }
        functions
            .iter()
            .map(|entry| (entry.name.clone(), entry.identifier))
            .collect::<Vec<_>>()
    };
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(FUNCTIONS)
        .map_err(|_| Failure::ResourceLimit)?;
    for (name, key) in &keys {
        let key = state()?.reference(*key)?;
        let value = locals.map_get(token, actual_map, key)?;
        entries.push((name.clone(), existing_id(locals, value)?));
    }
    for ((_, key), (_, value)) in keys.iter().zip(&entries) {
        let key = state()?.reference(*key)?;
        let after = locals.map_get(token, actual_map, key)?;
        let expected = state()?.reference(*value)?;
        if !locals.same(after, expected)? {
            return Err(Failure::Identity.into());
        }
    }
    Ok(entries)
}
fn relation_event(locals: &mut Locals, index: usize, frame: &Frame) -> Result<()> {
    let kind = if frame.phase <= 12 {
        RelationKind::Consumer
    } else {
        RelationKind::Operation
    };
    let callback = field_id(
        locals,
        index,
        frame,
        if kind == RelationKind::Consumer {
            Field::Consumer
        } else {
            Field::Operation
        },
    )?;
    let owner = field_id(locals, index, frame, Field::Owner)?;
    let input = optional_id(locals, index, frame.optional(Field::Input))?;
    // Retain actual returned values, but never invent a core publication stage.
    let _result = optional_id(locals, index, frame.optional(Field::Result))?;
    let mut registry = state()?;
    let relations = &mut registry.captures[index].relations;
    let bound = matches!(frame.phase, 9 | 13);
    if bound {
        if relations.len() == OBJECTS {
            return Err(Failure::ResourceLimit.into());
        }
        if relations
            .iter()
            .any(|relation| relation.kind == kind && relation.callback == callback)
        {
            return Err(Failure::Duplicate.into());
        }
        relations.push(Relation {
            kind,
            owner,
            callback,
            input,
            entered: false,
            terminal: false,
        });
    } else {
        let relation = relations
            .iter_mut()
            .find(|relation| relation.kind == kind && relation.callback == callback)
            .ok_or(Failure::UnexpectedOrder)?;
        if relation.owner != owner {
            return Err(Failure::Identity.into());
        }
        if matches!(frame.phase, 10 | 14) {
            if relation.entered {
                return Err(Failure::Duplicate.into());
            }
            relation.entered = true;
            relation.input = input;
        } else {
            if !relation.entered || relation.terminal {
                return Err(Failure::UnexpectedOrder.into());
            }
            if kind == RelationKind::Consumer && relation.input != input {
                return Err(Failure::Identity.into());
            }
            relation.terminal = true;
        }
    }
    drop(registry);
    if matches!(frame.phase, 12 | 16) {
        let actual = frame.throwable.ok_or(Failure::Identity)?;
        native_cause(locals, index, Failure::ReloadFailed, actual)?;
    }
    Ok(())
}
fn preparation_event(
    locals: &mut Locals,
    index: usize,
    frame: &Frame,
    token: &SourceCaptureToken,
) -> Result<()> {
    let library = existing_id(locals, frame.object(Field::Library)?)?;
    let owner = existing_id(locals, frame.object(Field::Owner)?)?;
    if state()?.captures[index].library != Some(library) || owner != library {
        return Err(Failure::Identity.into());
    }
    stamp_event_classes(locals, index, frame, token)?;
    if frame.phase == 5 {
        if state()?.captures[index].preparation.is_some() {
            return Err(Failure::Duplicate.into());
        }
        let receiver_future = field_id(locals, index, frame, Field::Future)?;
        let function = field_id(locals, index, frame, Field::Function)?;
        state()?.captures[index].preparation = Some(Preparation {
            library,
            receiver_future,
            function,
            input_map: None,
            invocation: None,
            entered: false,
            terminal: false,
            returned_stage: None,
        });
        return locals.finish(Ok(()));
    }
    let future = existing_id(locals, frame.object(Field::Future)?)?;
    let function = existing_id(locals, frame.object(Field::Function)?)?;
    {
        let registry = state()?;
        let prep = registry.captures[index]
            .preparation
            .as_ref()
            .ok_or(Failure::UnexpectedOrder)?;
        if prep.library != library || prep.receiver_future != future || prep.function != function {
            return Err(Failure::Identity.into());
        }
        if prep.terminal || (frame.phase == 6 && prep.entered) {
            return Err(Failure::Duplicate.into());
        }
        if frame.phase != 6 && !prep.entered {
            return Err(Failure::UnexpectedOrder.into());
        }
    }
    let (input, invocation) = if frame.phase == 6 {
        (
            field_id(locals, index, frame, Field::Input)?,
            field_id(locals, index, frame, Field::Operation)?,
        )
    } else {
        (
            existing_id(locals, frame.object(Field::Input)?)?,
            existing_id(locals, frame.object(Field::Operation)?)?,
        )
    };
    if frame.phase == 6 {
        let mut registry = state()?;
        let prep = registry.captures[index]
            .preparation
            .as_mut()
            .ok_or(Failure::UnexpectedOrder)?;
        prep.input_map = Some(input);
        prep.invocation = Some(invocation);
        prep.entered = true;
        return Ok(());
    }
    {
        let registry = state()?;
        let prep = registry.captures[index]
            .preparation
            .as_ref()
            .ok_or(Failure::UnexpectedOrder)?;
        if prep.input_map != Some(input) || prep.invocation != Some(invocation) {
            return Err(Failure::Identity.into());
        }
    }
    let returned_stage = if frame.phase == 7 {
        Some(field_id(locals, index, frame, Field::Result)?)
    } else if frame.phase == 8 {
        native_cause(
            locals,
            index,
            Failure::ParseFailed,
            frame.throwable.ok_or(Failure::Identity)?,
        )?;
        None
    } else {
        return Err(Failure::UnexpectedOrder.into());
    };
    let mut registry = state()?;
    let prep = registry.captures[index]
        .preparation
        .as_mut()
        .ok_or(Failure::UnexpectedOrder)?;
    prep.returned_stage = returned_stage;
    prep.terminal = true;
    Ok(())
}
fn select_entry(
    locals: &mut Locals,
    index: usize,
    frame: &Frame,
    token: &SourceCaptureToken,
) -> Result<u8> {
    let actual_function = frame.object(Field::FunctionId)?;
    let name = locals.identifier(actual_function, token)?;
    let expected_resource = match normative_resources()?.get(&name) {
        Some(resource) => resource,
        None => return Ok(0),
    };
    let actual_resource = frame.object(Field::ResourceId)?;
    if locals.identifier(actual_resource, token)? != *expected_resource {
        return Err(Failure::SourceMismatch.into());
    }
    let library = existing_id(locals, frame.object(Field::Library)?)?;
    let future = existing_id(locals, frame.object(Field::Future)?)?;
    let function = existing_id(locals, frame.object(Field::Function)?)?;
    let input = existing_id(locals, frame.object(Field::Input)?)?;
    let invocation = existing_id(locals, frame.object(Field::Operation)?)?;
    {
        let registry = state()?;
        let capture = &registry.captures[index];
        let prep = capture
            .preparation
            .as_ref()
            .ok_or(Failure::UnexpectedOrder)?;
        if capture.library != Some(library)
            || prep.library != library
            || prep.receiver_future != future
            || prep.function != function
            || prep.input_map != Some(input)
            || prep.invocation != Some(invocation)
        {
            return Err(Failure::Identity.into());
        }
        if !prep.entered || prep.terminal {
            return Err(Failure::UnexpectedOrder.into());
        }
        if capture.selected.len() == FUNCTIONS {
            return Err(Failure::ResourceLimit.into());
        }
        if capture.selected.iter().any(|entry| entry.name == name) {
            return Err(Failure::Duplicate.into());
        }
    }
    stamp_event_classes(locals, index, frame, token)?;
    let function = intern(locals, index, actual_function)?;
    let resource = intern(locals, index, actual_resource)?;
    let entry = field_id(locals, index, frame, Field::Entry)?;
    if !locals.same(frame.object(Field::Entry)?, frame.object(Field::Owner)?)? {
        return Err(Failure::Identity.into());
    }
    let supplier = field_id(locals, index, frame, Field::Supplier)?;
    let mut registry = state()?;
    let capture = &mut registry.captures[index];
    if capture.selected.iter().any(|selected| {
        selected.function == function
            || selected.resource == resource
            || selected.entry == entry
            || selected.supplier == supplier
    }) {
        return Err(Failure::Duplicate.into());
    }
    capture.selected.push(SelectedEntry {
        name,
        function,
        resource,
        entry,
        supplier,
    });
    Ok(1)
}

// Both classes are actual local references from this same admitted callback.
// They carry JNI transport metadata and never leave the attached frame.
#[derive(Clone, Copy)]
struct CallbackClasses {
    bridge: jclass,
    port: jclass,
}

fn dispatch(
    locals: &mut Locals,
    index: usize,
    frame: &Frame,
    token: &SourceCaptureToken,
    classes: CallbackClasses,
    check: Checkpoint,
    selection_reply: &mut u8,
) -> Result<()> {
    if frame.phase == 46 {
        *selection_reply = select_entry(locals, index, frame, token)?;
        return Ok(());
    }
    if matches!(frame.phase, 5..=8) && frame.optional(Field::Library).is_some() {
        return preparation_event(locals, index, frame, token);
    }
    let id = capture_id(index)?;
    let selected = match frame.optional(Field::FunctionId) {
        Some(actual) => {
            let name = locals.identifier(actual, token)?;
            if !selected_function(&name)? {
                return Ok(());
            }
            Some((name, intern(locals, index, actual)?))
        }
        None => None,
    };
    stamp_event_classes(locals, index, frame, token)?;
    if matches!(frame.phase, 19..=32 | 39 | 41 | 42 | 44) {
        let library = field_id(locals, index, frame, Field::Library)?;
        if state()?.captures[index].library != Some(library) {
            return Err(Failure::Identity.into());
        }
    }
    if matches!(frame.phase, 2..=8) {
        let supplier = field_id(locals, index, frame, Field::Supplier)?;
        if let Some((_, identifier)) = &selected {
            let registry = state()?;
            if !registry.captures[index]
                .functions
                .iter()
                .any(|entry| entry.identifier == *identifier && entry.supplier == supplier)
            {
                return Err(Failure::Identity.into());
            }
        } else if state()?.captures[index].root_supplier != Some(supplier) {
            return Err(Failure::Identity.into());
        }
    }
    match frame.phase {
        0 => return Err(Failure::Duplicate.into()),
        1 => {
            let supplier = field_id(locals, index, frame, Field::Supplier)?;
            if let Some((name, identifier)) = selected {
                let library = field_id(locals, index, frame, Field::Owner)?;
                {
                    let registry = state()?;
                    if registry.captures[index].library != Some(library)
                        || !registry.captures[index].selected.iter().any(|entry| {
                            entry.name == name
                                && entry.function == identifier
                                && entry.supplier == supplier
                        })
                    {
                        return Err(Failure::Identity.into());
                    }
                }
                let manager = state()?.captures[index]
                    .manager
                    .ok_or(Failure::UnexpectedOrder)?;
                let ticket = state()?
                    .core
                    .function_submitted(id, library, manager, &name, supplier, check)?;
                state()?.captures[index].functions.push(EntryFunction {
                    name,
                    identifier,
                    supplier,
                    ticket,
                    compiled: None,
                });
            } else {
                let owner = field_id(locals, index, frame, Field::Owner)?;
                let binding = state()?.captures[index]
                    .binding
                    .clone()
                    .ok_or(Failure::Identity)?;
                if owner != binding.server {
                    return Err(Failure::Identity.into());
                }
                let selection = field_id(locals, index, frame, Field::Selection)?;
                let executor = field_id(locals, index, frame, Field::Executor)?;
                fact(
                    state()?
                        .core
                        .supplier_submitted(id, selection, supplier, executor, check),
                )?;
                state()?.captures[index].root_supplier = Some(supplier);
            }
        }
        2 => {
            let supplier = field_id(locals, index, frame, Field::Supplier)?;
            if let Some((_, identifier)) = selected {
                let result = existing_id(locals, frame.object(Field::Result)?)?;
                if !state()?.captures[index].functions.iter().any(|entry| {
                    entry.identifier == identifier
                        && entry.supplier == supplier
                        && entry.compiled == Some(result)
                }) {
                    return Err(Failure::Identity.into());
                }
            } else {
                let result = field_id(locals, index, frame, Field::Result)?;
                fact(state()?.core.supplier_returned(id, supplier, result, check))?;
                state()?.captures[index].opened = Some(result);
            }
            // Entry supplier returns are not parse evidence. Phase31 is the
            // actual compiler return and phase33 is its actual future effect.
        }
        3 => {
            native_cause(
                locals,
                index,
                if selected.is_some() {
                    Failure::ParseFailed
                } else {
                    Failure::ReloadFailed
                },
                frame.throwable.ok_or(Failure::Identity)?,
            )?;
        }
        4 => {
            let supplier = field_id(locals, index, frame, Field::Supplier)?;
            let future = field_id(locals, index, frame, Field::Future)?;
            if let Some((_, identifier)) = selected {
                let ticket = ticket(index, identifier)?;
                fact(
                    state()?
                        .core
                        .function_future_bound(ticket, supplier, future, check),
                )?;
            } else {
                fact(
                    state()?
                        .core
                        .supplier_future_bound(id, supplier, future, check),
                )?;
            }
        }
        5 => {
            let owner = field_id(locals, index, frame, Field::Owner)?;
            if state()?.captures[index]
                .binding
                .as_ref()
                .ok_or(Failure::Identity)?
                .server
                != owner
            {
                return Err(Failure::Identity.into());
            }
            let supplier = field_id(locals, index, frame, Field::Supplier)?;
            if entry_for_supplier(index, supplier)?.is_some() {
                return Err(Failure::UnexpectedOrder.into());
            }
            let future = field_id(locals, index, frame, Field::Future)?;
            let function = field_id(locals, index, frame, Field::Function)?;
            fact(
                state()?
                    .core
                    .continuation_bound(id, future, function, check),
            )?;
            let mut registry = state()?;
            registry.captures[index].continuation_function = Some(function);
            registry.captures[index].continuation_future = Some(future);
        }
        6 => {
            let owner = field_id(locals, index, frame, Field::Owner)?;
            if state()?.captures[index]
                .binding
                .as_ref()
                .ok_or(Failure::Identity)?
                .server
                != owner
            {
                return Err(Failure::Identity.into());
            }
            let function = field_id(locals, index, frame, Field::Function)?;
            let future = field_id(locals, index, frame, Field::Future)?;
            let opened = field_id(locals, index, frame, Field::Input)?;
            {
                let registry = state()?;
                let capture = &registry.captures[index];
                if capture.continuation_function != Some(function)
                    || capture.continuation_future != Some(future)
                {
                    return Err(Failure::Identity.into());
                }
            }
            let continuation = state()?
                .core
                .continuation_entered(id, function, opened, check)?;
            state()?.captures[index].continuation = Some(continuation);
        }
        7 => {
            let _ = field_id(locals, index, frame, Field::Result)?;
        }
        8 => {
            native_cause(
                locals,
                index,
                Failure::ReloadFailed,
                frame.throwable.ok_or(Failure::Identity)?,
            )?;
        }
        9..=16 => relation_event(locals, index, frame)?,
        17 => {
            let function = field_id(locals, index, frame, Field::Function)?;
            let future = field_id(locals, index, frame, Field::Future)?;
            let manager = field_id(locals, index, frame, Field::Manager)?;
            let opened = field_id(locals, index, frame, Field::Input)?;
            let server = field_id(locals, index, frame, Field::Server)?;
            let continuation = state()?.captures[index]
                .continuation
                .ok_or(Failure::InvalidTicket)?;
            if state()?.captures[index].continuation_function != Some(function) {
                return Err(Failure::Identity.into());
            }
            if state()?.captures[index].continuation_future != Some(future) {
                return Err(Failure::Identity.into());
            }
            fact(
                state()?
                    .core
                    .manager_bound(continuation, server, opened, manager, check),
            )?;
            state()?.captures[index].manager = Some(manager);
        }
        18 => {
            let manager = field_id(locals, index, frame, Field::Manager)?;
            let resources = field_id(locals, index, frame, Field::Input)?;
            let library = field_id(locals, index, frame, Field::Library)?;
            fact(
                state()?
                    .core
                    .library_bound(id, manager, resources, library, check),
            )?;
            let mut registry = state()?;
            registry.captures[index].resources = Some(resources);
            registry.captures[index].library = Some(library);
        }
        19 => {
            let (_, identifier) = selected.ok_or(Failure::Identity)?;
            let entry = existing_id(locals, frame.object(Field::Entry)?)?;
            let supplier = existing_id(locals, frame.object(Field::Supplier)?)?;
            let resource_identifier = existing_id(locals, frame.object(Field::ResourceId)?)?;
            if !state()?.captures[index].selected.iter().any(|selected| {
                selected.function == identifier
                    && selected.entry == entry
                    && selected.supplier == supplier
                    && selected.resource == resource_identifier
            }) {
                return Err(Failure::Identity.into());
            }
            let source = resource_join(locals, index, frame, token, check)?;
            let resource_name = locals.identifier(frame.object(Field::ResourceId)?, token)?;
            let resource = field_id(locals, index, frame, Field::Resource)?;
            let ticket = ticket(index, identifier)?;
            fact(
                state()?
                    .core
                    .resource_bound(ticket, &resource_name, resource, source, check),
            )?;
        }
        20 => {
            let (_, identifier) = selected.ok_or(Failure::Identity)?;
            let resource = field_id(locals, index, frame, Field::Resource)?;
            let stream = field_id(locals, index, frame, Field::Stream)?;
            let ticket = ticket(index, identifier)?;
            fact(state()?.core.stream_opened(ticket, resource, stream, check))?;
        }
        21 => {
            let (_, identifier) = selected.ok_or(Failure::Identity)?;
            let stream = field_id(locals, index, frame, Field::Stream)?;
            let payload = locals.bytes(frame.payload_array, SOURCE_BYTES)?;
            if payload.len() != frame.payload_length {
                return Err(Failure::ReadFailed.into());
            }
            let mut registry = state()?;
            let capture = &mut registry.captures[index];
            capture.total_bytes = capture
                .total_bytes
                .checked_add(payload.len())
                .ok_or(Failure::ResourceLimit)?;
            if capture.total_bytes > TOTAL_BYTES {
                return Err(Failure::ResourceLimit.into());
            }
            drop(registry);
            let ticket = ticket(index, identifier)?;
            fact(state()?.core.bytes_read(ticket, stream, &payload, check))?;
        }
        22 => {
            let (_, identifier) = selected.ok_or(Failure::Identity)?;
            let stream = field_id(locals, index, frame, Field::Stream)?;
            let ticket = ticket(index, identifier)?;
            fact(state()?.core.eof(ticket, stream, check))?;
        }
        23 | 42 => {
            native_cause(
                locals,
                index,
                Failure::ReadFailed,
                frame.throwable.ok_or(Failure::Identity)?,
            )?;
        }
        24 | 25 => {
            let (_, identifier) = selected.ok_or(Failure::Identity)?;
            let stream = field_id(locals, index, frame, Field::Stream)?;
            if frame.phase == 25 {
                native_cause(
                    locals,
                    index,
                    Failure::CloseFailed,
                    frame.throwable.ok_or(Failure::Identity)?,
                )?;
            }
            let ticket = ticket(index, identifier)?;
            fact(
                state()?
                    .core
                    .stream_closed(ticket, stream, frame.phase == 24, check),
            )?;
        }
        26..=30 | 39 => {
            if let Some(actual) = frame.throwable {
                native_cause(locals, index, Failure::NonlinearRead, actual)?;
            } else {
                state()?.note(index, Failure::NonlinearRead, None);
            }
        }
        31 => {
            let (_, identifier) = selected.ok_or(Failure::Identity)?;
            let lines = field_id(locals, index, frame, Field::Input)?;
            let function = field_id(locals, index, frame, Field::Result)?;
            let ticket = ticket(index, identifier)?;
            fact(
                state()?
                    .core
                    .function_returned(ticket, lines, function, check),
            )?;
            let mut registry = state()?;
            let entry = registry.captures[index]
                .functions
                .iter_mut()
                .find(|entry| entry.identifier == identifier)
                .ok_or(Failure::InvalidTicket)?;
            entry.compiled = Some(function);
        }
        32 => {
            native_cause(
                locals,
                index,
                Failure::ParseFailed,
                frame.throwable.ok_or(Failure::Identity)?,
            )?;
        }
        33 => {
            let (_, identifier) = selected.ok_or(Failure::Identity)?;
            let future = field_id(locals, index, frame, Field::Future)?;
            let ticket = ticket(index, identifier)?;
            if let Some(actual) = frame.throwable {
                let cause = cause_object(locals, index, actual)?;
                fact(state()?.core.entry_failed(ticket, future, cause, check))?;
            } else {
                let function = field_id(locals, index, frame, Field::Result)?;
                fact(
                    state()?
                        .core
                        .entry_completed(ticket, future, function, check),
                )?;
            }
        }
        34 => {
            let library = field_id(locals, index, frame, Field::Library)?;
            let actual_map = frame.object(Field::Result)?;
            let map = intern(locals, index, actual_map)?;
            let entries = selected_entries(locals, index, actual_map, token)?;
            fact(
                state()?
                    .core
                    .functions_published(id, library, map, &entries, check),
            )?;
            state()?.captures[index].published_map = Some(map);
        }
        35 => observe_installation(locals, index, frame, token, check)?,
        36 | 37 => {
            let future = field_id(locals, index, frame, Field::Future)?;
            if state()?.captures[index].reload_future != Some(future) {
                return Err(Failure::UnexpectedOrder.into());
            }
            if frame.phase == 37 {
                native_cause(
                    locals,
                    index,
                    Failure::ReloadFailed,
                    frame.throwable.ok_or(Failure::Identity)?,
                )?;
            }
            fact(state()?.core.reload_terminal(
                id,
                future,
                if frame.phase == 36 {
                    ReloadOutcome::Completed
                } else {
                    ReloadOutcome::Failed
                },
                check,
            ))?;
        }
        38 => {
            state()?.core.retire(id)?;
        }
        40 => {
            let failure = reason_failure(frame.reason.as_deref());
            if let Some(actual) = frame.throwable {
                native_cause(locals, index, failure, actual)?;
            } else {
                state()?.note(index, failure, None);
            }
        }
        41 => {
            let (_, identifier) = selected.ok_or(Failure::Identity)?;
            let reader = field_id(locals, index, frame, Field::Reader)?;
            let lines = field_id(locals, index, frame, Field::Result)?;
            let ticket = ticket(index, identifier)?;
            fact(state()?.core.lines_returned(ticket, reader, lines, check))?;
        }
        43 => observe_current(locals, index, frame, token, classes.bridge, classes.port)?,
        44 => {
            let (_, identifier) = selected.ok_or(Failure::Identity)?;
            let stream = field_id(locals, index, frame, Field::Stream)?;
            let reader = field_id(locals, index, frame, Field::Reader)?;
            let returned = frame.object(Field::Result)?;
            if !locals.same(returned, frame.object(Field::Reader)?)? {
                return Err(Failure::Identity.into());
            }
            let ticket = ticket(index, identifier)?;
            fact(state()?.core.reader_bound(ticket, stream, reader, check))?;
        }
        45 => {
            let future = field_id(locals, index, frame, Field::Future)?;
            let owner = field_id(locals, index, frame, Field::Owner)?;
            if future != owner {
                return Err(Failure::Identity.into());
            }
            fact(state()?.core.reload_future_bound(id, future, check))?;
            state()?.captures[index].reload_future = Some(future);
        }
        _ => return Err(Failure::UnexpectedOrder.into()),
    }
    Ok(())
}

// Root's selected-field admission supplies the issuer-held base server Class.
// No subclass field lookup or arbitrary name/descriptor field import is used.
fn installed_resources(
    locals: &mut Locals,
    index: usize,
    server: jobject,
    token: &SourceCaptureToken,
) -> Result<(jobject, jobject, jobject)> {
    let base = stamp_named(
        locals,
        index,
        token,
        b"Lnet/minecraft/server/MinecraftServer;",
    )?;
    let class = base.actual_class(token).ok_or(Failure::GenerationChanged)?;
    locals.live()?;
    let instance = locals
        .finish(unsafe { ffi::is_instance_of(locals.env, server, class) }.map_err(Error::Ffi))?;
    if !instance {
        return Err(Failure::Identity.into());
    }
    locals.live()?;
    let field = unsafe {
        ffi::field_id(
            locals.env,
            class,
            c"resources",
            c"Lnet/minecraft/server/MinecraftServer$ReloadableResources;",
        )
    }
    .map_err(Error::Ffi);
    let field = locals.finish(field)?;
    locals.live()?;
    let holder = unsafe { ffi::object_field(locals.env, server, field) }.map_err(Error::Ffi);
    let holder = holder
        .and_then(|value| value.ok_or(Error::Fact(Failure::Identity)))
        .and_then(|value| locals.adopt(value));
    let holder = locals.finish(holder)?;
    stamp_object(
        locals,
        index,
        token,
        holder,
        b"Lnet/minecraft/server/MinecraftServer$ReloadableResources;",
    )?;
    let manager = locals.required_zero(
        holder,
        c"resourceManager",
        c"()Lnet/minecraft/server/packs/resources/CloseableResourceManager;",
    )?;
    let resources = locals.required_zero(
        holder,
        c"managers",
        c"()Lnet/minecraft/server/ReloadableServerResources;",
    )?;
    stamp_object(
        locals,
        index,
        token,
        resources,
        b"Lnet/minecraft/server/ReloadableServerResources;",
    )?;
    if !base.is_current() || !token.is_current() {
        return Err(Failure::GenerationChanged.into());
    }
    Ok((holder, manager, resources))
}
struct ServerSnapshot {
    function_manager: ObjectId,
    manager: ObjectId,
    resources: ObjectId,
    library: ObjectId,
    map: ObjectId,
    entries: Vec<(String, ObjectId)>,
}
fn server_snapshot(
    locals: &mut Locals,
    index: usize,
    frame: &Frame,
    token: &SourceCaptureToken,
) -> Result<ServerSnapshot> {
    if !token.is_current() {
        return Err(Failure::GenerationChanged.into());
    }
    let server = frame.object(Field::Server)?;
    stamp_object(
        locals,
        index,
        token,
        server,
        b"Lnet/minecraft/server/dedicated/DedicatedServer;",
    )?;
    let base = stamp_named(
        locals,
        index,
        token,
        b"Lnet/minecraft/server/MinecraftServer;",
    )?;
    locals.live()?;
    let instance = locals.finish(
        unsafe {
            ffi::is_instance_of(
                locals.env,
                server,
                base.actual_class(token).ok_or(Failure::GenerationChanged)?,
            )
        }
        .map_err(Error::Ffi),
    )?;
    if !instance {
        return Err(Failure::Identity.into());
    }
    let manager = locals.required_zero(
        server,
        c"getResourceManager",
        c"()Lnet/minecraft/server/packs/resources/ResourceManager;",
    )?;
    let functions = locals.required_zero(
        server,
        c"getFunctions",
        c"()Lnet/minecraft/server/ServerFunctionManager;",
    )?;
    locals.exact_class(functions, b"Lnet/minecraft/server/ServerFunctionManager;")?;
    stamp_object(
        locals,
        index,
        token,
        functions,
        b"Lnet/minecraft/server/ServerFunctionManager;",
    )?;
    stamp_named(
        locals,
        index,
        token,
        b"Lio/github/daejunnom/mmmm/fabric/mixin/ServerFunctionManagerLibraryReadAccess;",
    )?;
    let library = locals.required_zero(
        functions,
        c"mmmm$library",
        c"()Lnet/minecraft/server/ServerFunctionLibrary;",
    )?;
    locals.exact_class(library, b"Lnet/minecraft/server/ServerFunctionLibrary;")?;
    stamp_object(
        locals,
        index,
        token,
        library,
        b"Lnet/minecraft/server/ServerFunctionLibrary;",
    )?;
    let (holder, holder_manager, resources) = installed_resources(locals, index, server, token)?;
    if !locals.same(manager, holder_manager)? {
        return Err(Failure::Identity.into());
    }
    let function_manager = if frame.phase == 35 {
        if !locals.same(server, frame.object(Field::Result)?)?
            || !locals.same(holder, frame.object(Field::Input)?)?
            || !locals.same(functions, frame.object(Field::Owner)?)?
            || !locals.same(library, frame.object(Field::Library)?)?
        {
            return Err(Failure::Identity.into());
        }
        let consumer = existing_id(locals, frame.object(Field::Consumer)?)?;
        let input = existing_id(locals, holder)?;
        let server_id = existing_id(locals, server)?;
        if !state()?.captures[index].relations.iter().any(|relation| {
            relation.kind == RelationKind::Consumer
                && relation.callback == consumer
                && relation.owner == server_id
                && relation.input == Some(input)
                && relation.entered
                && !relation.terminal
        }) {
            return Err(Failure::Identity.into());
        }
        let manager_id = intern(locals, index, functions)?;
        let mut registry = state()?;
        registry.captures[index].installed_function_manager = Some(manager_id);
        registry.captures[index].library_replacement_observed = true;
        manager_id
    } else {
        existing_id(locals, functions)?
    };
    let map = locals.required_zero(library, c"getFunctions", c"()Ljava/util/Map;")?;
    let entries = selected_entries(locals, index, map, token)?;
    let after_functions = locals.required_zero(
        server,
        c"getFunctions",
        c"()Lnet/minecraft/server/ServerFunctionManager;",
    )?;
    let after_library = locals.required_zero(
        functions,
        c"mmmm$library",
        c"()Lnet/minecraft/server/ServerFunctionLibrary;",
    )?;
    let after_map = locals.required_zero(library, c"getFunctions", c"()Ljava/util/Map;")?;
    let after_manager = locals.required_zero(
        server,
        c"getResourceManager",
        c"()Lnet/minecraft/server/packs/resources/ResourceManager;",
    )?;
    let (after_holder, after_holder_manager, after_resources) =
        installed_resources(locals, index, server, token)?;
    for (left, right) in [
        (functions, after_functions),
        (library, after_library),
        (map, after_map),
        (manager, after_manager),
        (holder, after_holder),
        (holder_manager, after_holder_manager),
        (resources, after_resources),
    ] {
        if !locals.same(left, right)? {
            return Err(Failure::Identity.into());
        }
    }
    if frame.phase == 35
        && (!locals.same(functions, frame.object(Field::Owner)?)?
            || !locals.same(library, frame.object(Field::Library)?)?)
    {
        return Err(Failure::Identity.into());
    }
    if !token.is_current() {
        return Err(Failure::GenerationChanged.into());
    }
    Ok(ServerSnapshot {
        function_manager,
        manager: existing_id(locals, manager)?,
        resources: existing_id(locals, resources)?,
        library: existing_id(locals, library)?,
        map: existing_id(locals, map)?,
        entries,
    })
}
fn observe_installation(
    locals: &mut Locals,
    index: usize,
    frame: &Frame,
    token: &SourceCaptureToken,
    check: Checkpoint,
) -> Result<()> {
    let actual = server_snapshot(locals, index, frame, token)?;
    let id = capture_id(index)?;
    let server = field_id(locals, index, frame, Field::Server)?;
    fact(state()?.core.server_installed(
        id,
        core::InstalledSourceView {
            server,
            manager: actual.manager,
            resources: actual.resources,
            library: actual.library,
            published_map: actual.map,
            entries: &actual.entries,
        },
        check,
    ))
}
fn observe_current(
    locals: &mut Locals,
    index: usize,
    frame: &Frame,
    token: &SourceCaptureToken,
    bridge: jclass,
    port_class: jclass,
) -> Result<()> {
    {
        let mut registry = state()?;
        registry.captures[index].current_root_observed = false;
        registry.captures[index].current_resources_observed = false;
        registry.captures[index].current_functions_observed = false;
    }
    let fresh = frame.fresh.ok_or(Failure::Identity)?;
    let fresh_class = locals.class(fresh)?;
    let current = unsafe {
        native_producer::current_source_root_port(locals.env, bridge, port_class, fresh_class)
    }
    .map_err(|_| Error::Gap("current_source_port_admission_failed"))?
    .ok_or(Error::Fact(Failure::GenerationChanged))?;
    if !current.is_current() || current.generation() != token.generation() {
        return Err(Failure::GenerationChanged.into());
    }
    let current_stamp = current.stamp();
    let source_stamp = token.stamp();
    if current_stamp[0] != source_stamp[0]
        || current_stamp[1] != source_stamp[1]
        || current_stamp[3] != source_stamp[2]
        || current_stamp[4] != source_stamp[3]
    {
        return Err(Failure::GenerationChanged.into());
    }
    let env = locals.env;
    let deadline = locals.deadline;
    owned_pack_files::with_current_source_root::<(), Error>(
        env,
        current,
        fresh,
        frame.roots()?,
        deadline,
        |control, facts| {
            let mut current_locals =
                Locals::with_control(env, control, deadline, token.snapshot(), index)?;
            let result = (|| {
                current_locals.live()?;
                let binding = state()?.captures[index]
                    .binding
                    .clone()
                    .ok_or(Failure::Identity)?;
                if facts.bundle_digest != binding.bundle_digest {
                    return Err(Failure::SourceMismatch.into());
                }
                state()?.captures[index].current_root_observed = true;
                let actual = server_snapshot(&mut current_locals, index, frame, token)?;
                let mut registry = state()?;
                let capture = &mut registry.captures[index];
                if capture.manager != Some(actual.manager)
                    || capture.resources != Some(actual.resources)
                    || capture.library != Some(actual.library)
                    || capture.published_map != Some(actual.map)
                    || capture.installed_function_manager != Some(actual.function_manager)
                {
                    return Err(Failure::Identity.into());
                }
                capture.current_resources_observed = true;
                if actual.entries.len() != FUNCTIONS
                    || actual.entries.iter().any(|(name, function)| {
                        !capture
                            .functions
                            .iter()
                            .any(|entry| entry.name == *name && entry.compiled == Some(*function))
                    })
                {
                    return Err(Failure::MissingFunction.into());
                }
                capture.current_functions_observed = true;
                drop(registry);
                for stamp in current_locals.observed.clone() {
                    retain_class_stamp(index, token, stamp)?;
                }
                retain_read_stamps(index, &current_locals)?;
                current_locals.live()?;
                Ok(())
            })();
            let close = current_locals.close().map_err(Error::Ffi);
            match (result, close) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
                (Err(primary), Err(post)) => Err(Error::Post(Box::new(primary), Box::new(post))),
            }
        },
    )
}

fn native_cause_json(cause: &NativeCause) -> Value {
    match cause {
        NativeCause::Io(error) => {
            json!({"kind":"io","osError":error.raw_os_error(),"errorKind":format!("{:?}",error.kind())})
        }
        NativeCause::RetainedIo(error) => {
            json!({"kind":"retained_close_io","osError":error.error.raw_os_error(),
            "errorKind":format!("{:?}",error.error.kind()),"pinPresent":error.pin.is_some()})
        }
        NativeCause::Lifetime(error) => match error {
            library_lifetime::LibraryLifetimeError::UnsupportedTarget => {
                json!({"kind":"image_lifetime","failure":"unsupported_target"})
            }
            library_lifetime::LibraryLifetimeError::NativeFailure {
                operation,
                status,
                source,
            } => {
                json!({"kind":"image_lifetime","operation":operation,"status":status,"osError":source.as_ref().and_then(std::io::Error::raw_os_error)})
            }
            library_lifetime::LibraryLifetimeError::InvalidObservation { operation, reason } => {
                json!({"kind":"image_lifetime","operation":operation,"failure":reason})
            }
        },
        NativeCause::Throwable(cause) => {
            json!({"kind":"actual_throwable","causeRetained":cause.is_some()})
        }
        NativeCause::Post(primary, post) => {
            json!({"kind":"post","primary":native_cause_json(primary),"post":native_cause_json(post)})
        }
        NativeCause::Boundary(kind) => json!({"kind":"root_boundary","failure":kind}),
        NativeCause::Ffi(error) => json!({"kind":"jni","failure":format!("{error:?}")}),
        NativeCause::Fact(failure) => {
            json!({"kind":"fact_boundary","failure":failure_name(*failure)})
        }
    }
}
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 15) as usize] as char);
    }
    result
}
fn capture_json(facts: core::CaptureFacts) -> Value {
    let functions = facts.functions.into_iter().map(|fact| json!({
        "functionId":fact.function_id,"resourceId":fact.resource_id,
        "expectedSha256":hex(&fact.expected_sha256),"prefixSha256":hex(&fact.prefix_sha256),
        "hashedBytes":fact.hashed_bytes,"observedSha256":fact.observed_sha256.map(|digest|hex(&digest)),
        "readBytes":fact.read_bytes,"eofObserved":fact.eof_observed,"closeAttempted":fact.close_attempted,
        "closeCompleted":fact.close_completed,"parsed":fact.parsed,"entryCompleted":fact.entry_completed,
        "entryFailed":fact.entry_failed})).collect::<Vec<_>>();
    json!({"numeric47Bootstrap":facts.numeric47_bootstrap,"originalBundleDigest":hex(&facts.original_bundle_digest),
        "functions":functions,"expectedFunctions":facts.expected_functions,"publishedFunctions":facts.published_functions,
        "serverInstalled":facts.server_installed,"reloadOutcome":facts.reload_outcome.map(|outcome|match outcome {
            ReloadOutcome::Completed=>"completed",ReloadOutcome::Failed=>"failed"}),
        "failures":facts.failures.into_iter().map(failure_name).collect::<Vec<_>>(),
        "failureCausesRetained":facts.failure_causes.into_iter().map(|cause|cause.is_some()).collect::<Vec<_>>(),
        "firstNativeCause":facts.first_native_cause.map(|(failure,_)|failure_name(failure)),
        "failuresOmitted":facts.failures_omitted,"retired":facts.retired,
        "consumedParsePublicationObserved":facts.consumed_parse_publication_observed})
}
fn frame_rejections_json(rejections: FrameLimitRejections) -> Value {
    json!({"reason":rejections.first_raw_phase.map(|_|failure_name(Failure::ResourceLimit)),
        "count":rejections.count,"firstRawPhase":rejections.first_raw_phase})
}

fn receipt(index: Option<usize>, phase: jint, error: Option<&'static str>) -> Vec<u8> {
    let value = match state() {
        Ok(registry) => {
            let admission = registry.core.admission_facts();
            let capture = index.and_then(|index| registry.captures.get(index));
            let facts = capture
                .and_then(|capture| capture.id)
                .and_then(|id| registry.core.facts(id).ok())
                .map(capture_json);
            let native = capture.map(|capture|json!({"objectsRetained":capture.objects.len(),
                "unissuedGlobalsRetained":capture.unissued_refs,"eventsObserved":capture.events,
                "firstActualThrowableRetained":capture.first_throwable.is_some(),
                "phasesObserved":capture.phases.as_slice(),"totalSourceBytes":capture.total_bytes,
                "lastScalars":capture.last_scalars,"lastGap":capture.last_gap,
                "currentRootObserved":capture.current_root_observed,"currentFunctionsObserved":capture.current_functions_observed,
                "currentResourcesObserved":capture.current_resources_observed,
                "currentAssessmentComplete":capture.current_root_observed && capture.current_resources_observed
                    && capture.current_functions_observed && capture.current_error.is_none(),
                "libraryReplacementObserved":capture.library_replacement_observed,
                "currentError":capture.current_error,
                "currentAssessmentCauses":capture.current_causes.iter().map(native_cause_json).collect::<Vec<_>>(),
                "currentAssessmentCausesOmitted":capture.current_causes_omitted,
                "consumerOperationRelations":capture.relations.len(),
                "preparationObserved":capture.preparation.is_some(),
                "preparationEntered":capture.preparation.as_ref().is_some_and(|prep|prep.entered),
                "preparationTerminal":capture.preparation.as_ref().is_some_and(|prep|prep.terminal),
                "preparationReturnedStageObserved":capture.preparation.as_ref().is_some_and(|prep|prep.returned_stage.is_some()),
                "preparationObservationScope":"actual_library_receiver_future_binding_and_callback_only",
                "nativeCauses":capture.native_causes.iter().map(native_cause_json).collect::<Vec<_>>(),
                "nativeCausesOmitted":capture.native_causes_omitted}));
            json!({"schema":"mmmm-loaded-pack-source-facts/1","phase":phase,"error":error,
                "historicalFacts":facts,"nativeFacts":native,
                "admissionClosed":admission.closed,"coreCapturesRetained":admission.retained_captures,
                "nativeCaptureSlotsRetained":registry.captures.len(),"vmOwnedRefs":registry.vm_owned_refs,
                "frameAdmissionRejections":{
                    "historical":frame_rejections_json(registry.historical_frame_rejections),
                    "current":frame_rejections_json(registry.current_frame_rejections)},
                "firstAdmissionFailure":admission.first_failure.map(|(failure,_)|failure_name(failure))})
        }
        Err(_) => {
            json!({"schema":"mmmm-loaded-pack-source-facts/1","phase":phase,"error":"native_registry_poisoned"})
        }
    };
    let bytes = serde_json::to_vec(&value).unwrap_or_else(|_|b"{\"schema\":\"mmmm-loaded-pack-source-facts/1\",\"error\":\"receipt_encoding_failed\"}".to_vec());
    if bytes.len() <= RECEIPT_BYTES {
        bytes
    } else {
        b"{\"schema\":\"mmmm-loaded-pack-source-facts/1\",\"error\":\"receipt_bound_exceeded\"}"
            .to_vec()
    }
}

// Raw inputs of one nativeObserve call; no object identity or authority is
// issued by grouping these already-existing JNI arguments.
#[derive(Clone, Copy)]
struct CallbackInputs {
    bridge: jclass,
    port: jobject,
    bytes: jobject,
    offset: jint,
    length: jint,
    phase: jint,
}

fn run(
    locals: &mut Locals,
    input: CallbackInputs,
    index: &mut Option<usize>,
    turn: &mut Option<Turn>,
    selection_reply: &mut u8,
) -> Result<()> {
    let CallbackInputs {
        bridge,
        port,
        bytes,
        offset,
        length,
        phase,
    } = input;
    let port_class = locals.class(port)?;
    let token = unsafe { native_producer::source_capture_port(locals.env, bridge, port_class) }
        .map_err(|_| Error::Gap("source_port_admission_failed"))?;
    let Some(token) = token else {
        state()?.core.close_admission(Failure::GenerationChanged, 1);
        return Err(Failure::GenerationChanged.into());
    };
    locals.source = Some(token.snapshot());
    let frame = read_frame(locals, port, bytes, offset, length, phase)?;
    *index = find_capture(locals, &frame)?;
    if phase == 43
        && let Some(index) = *index
    {
        let mut registry = state()?;
        registry.captures[index].current_root_observed = false;
        registry.captures[index].current_resources_observed = false;
        registry.captures[index].current_functions_observed = false;
        registry.captures[index].current_error = None;
    }
    let wait_deadline = locals.deadline;
    *turn = Some(Turn::enter(wait_deadline)?);
    library_lifetime::ensure()
        .map_err(|error| Error::Root(owned_pack_files::Failure::Lifetime(error)))?;
    // A competing ARM may have completed while this frame waited for its turn.
    *index = find_capture(locals, &frame)?;
    if phase == 0 {
        if index.is_some() {
            return Err(Failure::Duplicate.into());
        }
        let capture = reserve_capture(token.stamp(), wait_deadline, locals.started_ms)?;
        *index = Some(capture);
        stamp_event_classes(locals, capture, &frame, &token)?;
        arm(locals, capture, &frame, &token)?;
    }
    let capture = index.ok_or(Error::Gap("original_capture_not_armed"))?;
    if phase != 43 {
        locals.observer = Some(capture);
        locals.deadline = state()?.captures[capture].deadline;
    }
    let check = check_common(locals, capture, &frame, &token)?;
    check_class_stamps(capture, token.generation())?;
    if !matches!(phase, 43 | 46) {
        observation_failure(locals, capture, &frame)?;
    }
    if phase != 0 {
        dispatch(
            locals,
            capture,
            &frame,
            &token,
            CallbackClasses {
                bridge,
                port: port_class,
            },
            check,
            selection_reply,
        )?;
    }
    for stamp in locals.observed.clone() {
        retain_class_stamp(capture, &token, stamp)?;
    }
    retain_read_stamps(capture, locals)?;
    check_class_stamps(capture, token.generation())?;
    if !token.is_current() {
        state()?
            .core
            .close_admission(Failure::GenerationChanged, token.generation());
        return Err(Failure::GenerationChanged.into());
    }
    Ok(())
}

pub(crate) unsafe fn call(
    env: *mut JNIEnv,
    bridge: jclass,
    port: jobject,
    bytes: jobject,
    offset: jint,
    length: jint,
    phase: jint,
) -> jobject {
    let Ok(_active) = Active::enter(phase) else {
        // No attached active lifetime was admitted. In particular VMDeath or
        // AgentUnload must never trigger a fresh reply allocation on this env.
        return ptr::null_mut();
    };
    let Ok(mut locals) = Locals::new(env) else {
        return ptr::null_mut();
    };
    let mut index = None;
    let mut turn = None;
    let mut selection_reply = 2;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run(
            &mut locals,
            CallbackInputs {
                bridge,
                port,
                bytes,
                offset,
                length,
                phase,
            },
            &mut index,
            &mut turn,
            &mut selection_reply,
        )
    }))
    .unwrap_or_else(|_| {
        if let Ok(mut registry) = state() {
            registry.core.close_admission(Failure::AdmissionClosed, 1);
        }
        Err(Error::Gap("native_observer_panicked"))
    });
    let mut error = result
        .err()
        .map(|error| record_error(&mut locals, index, error, phase));
    if let Err(cleanup) = locals.close() {
        error = Some(record_error(&mut locals, index, Error::Ffi(cleanup), phase));
    }
    let bytes = if phase == 46 {
        vec![1, if error.is_some() { 2 } else { selection_reply }]
    } else {
        receipt(index, phase, error)
    };
    // Drop only the scoped turn; a waiting attached callback may now proceed.
    drop(turn);
    let Ok(registry) = state() else {
        return ptr::null_mut();
    };
    if frame_entry_open(native_producer::status(), registry.closed).is_err() {
        return ptr::null_mut();
    }
    // Direct JNI allocation is bounded; no Java callback runs under this lock.
    unsafe { ffi::byte_array(env, &bytes) }.unwrap_or(ptr::null_mut())
}

/// Only the actual VMDeath callback supplies an attached event env. If any
/// frame is still active, retained refs stay VM-owned until VM destruction.
pub(crate) unsafe fn vm_death(env: *mut JNIEnv) {
    let Some(shared) = SHARED.get() else {
        return;
    };
    if let Ok(mut registry) = shared.state.lock() {
        registry.closed = true;
        registry.core.close_admission(Failure::GenerationChanged, 1);
        if registry.active == 0 {
            let mut remaining = 0usize;
            for global in &mut registry.globals {
                if global.reference == 0 {
                    continue;
                }
                match unsafe { ffi::delete_global(env, global.reference as jobject) } {
                    Ok(()) => global.reference = 0,
                    Err(_) => {
                        remaining += 1;
                    }
                }
            }
            registry.vm_owned_refs = remaining;
        } else {
            registry.vm_owned_refs = registry
                .globals
                .iter()
                .filter(|global| global.reference != 0)
                .count();
        }
    }
    shared.wake.notify_all();
}
/// AgentUnload may run after VM destruction. No env, JNI, or Java callback.
pub(crate) fn on_unload() {
    let Some(shared) = SHARED.get() else {
        return;
    };
    if let Ok(mut registry) = shared.state.lock() {
        registry.closed = true;
        registry.core.close_admission(Failure::GenerationChanged, 1);
        registry.vm_owned_refs = registry
            .globals
            .iter()
            .filter(|global| global.reference != 0)
            .count();
    }
    shared.wake.notify_all();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_uses_compiler_function_ids_and_ignores_unrelated_ids() {
        let expected =
            normative_resources().unwrap_or_else(|_| panic!("normative47 source contract"));
        assert_eq!(expected.len(), FUNCTIONS);
        for (function, resource) in expected {
            assert!(selected_function(function).unwrap_or(false));
            assert!(!selected_function(resource).unwrap_or(true));
        }
        for unrelated in ["other:load", "minecraft:tick", "mmmm:unrelated", ""] {
            assert!(!selected_function(unrelated).unwrap_or(true));
        }
    }

    #[test]
    fn first_historical_throwable_slot_is_unavailable_to_current_causes() {
        for retained in 0..OBJECTS - 1 {
            assert!(object_slot(retained, false, false).is_ok());
        }
        assert!(matches!(
            object_slot(OBJECTS - 1, false, false),
            Err(Failure::ResourceLimit)
        ));
        assert!(object_slot(OBJECTS - 1, true, false).is_ok());
        assert!(matches!(
            object_slot(OBJECTS - 1, true, true),
            Err(Failure::ResourceLimit)
        ));
        for first in [false, true] {
            for historical_present in [false, true] {
                assert!(matches!(
                    object_slot(OBJECTS, first, historical_present),
                    Err(Failure::ResourceLimit)
                ));
            }
        }
    }

    #[test]
    fn normal_numeric47_roles_leave_room_for_first_historical_cause() {
        // Entry/F/R/S, entry future, resource/stream/reader/lines/compiled.
        let selected_entry_roles = FUNCTIONS * 10;
        // Original six plus root supplier/executor/opened/prior-future/function,
        // resource manager/resources/library/source-pack/published-map/reload-future.
        let shared_bound_roles = 17;
        // Root returned stage, consumer, holder, installed function manager,
        // and preparation receiver-future/function/map/invocation/returned-stage.
        let additional_shared_roles = 1 + 1 + 1 + 1 + 5;
        let normal = selected_entry_roles + shared_bound_roles + additional_shared_roles;
        assert_eq!(normal, 496);
        assert!(object_slot(normal, false, false).is_ok());
        assert_eq!(OBJECTS - 1 - normal, 15);
        assert!(object_slot(OBJECTS - 1, true, false).is_ok());
    }

    fn full_frame_registry() -> Registry {
        let mut registry = Registry::new();
        for _ in 0..ACTIVE_FRAMES {
            // Nonnegative status is only the lifetime input to this budget,
            // never JVM/class/source admission or an actual attached frame.
            assert!(registry.admit_frame(1, 0).is_ok());
        }
        registry
    }

    #[test]
    fn frame_limit_is_64_and_only_admitted_owners_release_capacity() {
        let mut registry = full_frame_registry();
        assert_eq!(registry.active, 64);
        assert!(matches!(
            registry.admit_frame(43, 0),
            Err(Error::Fact(Failure::ResourceLimit))
        ));
        assert_eq!(registry.active, 64);
        assert_eq!(registry.current_frame_rejections.count, 1);
        assert_eq!(registry.historical_frame_rejections.count, 0);
        registry.release_frame();
        assert!(registry.admit_frame(43, 0).is_ok());
        assert_eq!(registry.active, 64);
        assert_eq!(registry.current_frame_rejections.count, 1);
        for _ in 0..ACTIVE_FRAMES {
            registry.release_frame();
        }
        assert_eq!(registry.active, 0);
    }

    #[test]
    fn frame_rejection_categories_preserve_first_raw_phase_without_capture_facts() {
        let mut registry = full_frame_registry();
        for phase in [46, -17, 43, 43] {
            assert!(matches!(
                registry.admit_frame(phase, 0),
                Err(Error::Fact(Failure::ResourceLimit))
            ));
        }
        assert_eq!(registry.historical_frame_rejections.count, 2);
        assert_eq!(
            registry.historical_frame_rejections.first_raw_phase,
            Some(46)
        );
        assert_eq!(registry.current_frame_rejections.count, 2);
        assert_eq!(registry.current_frame_rejections.first_raw_phase, Some(43));
        assert!(registry.captures.is_empty());
        assert!(registry.globals.is_empty());
        assert_eq!(registry.next_object, 1);
        assert!(!registry.core.admission_facts().closed);
        assert!(registry.core.admission_facts().first_failure.is_none());
        let mut saturated = FrameLimitRejections {
            count: u64::MAX,
            first_raw_phase: Some(19),
        };
        saturated.record(21);
        assert_eq!(saturated.count, u64::MAX);
        assert_eq!(saturated.first_raw_phase, Some(19));
    }

    #[test]
    fn closed_or_negative_producer_entry_does_not_change_frame_diagnostics() {
        let mut registry = full_frame_registry();
        let historical = registry.historical_frame_rejections;
        let current = registry.current_frame_rejections;
        for status in [-1, -5, jint::MIN] {
            assert!(matches!(
                frame_entry_open(status, false),
                Err(Error::Fact(Failure::AdmissionClosed))
            ));
            assert!(matches!(
                registry.admit_frame(43, status),
                Err(Error::Fact(Failure::AdmissionClosed))
            ));
        }
        registry.closed = true;
        assert!(matches!(
            registry.admit_frame(19, 0),
            Err(Error::Fact(Failure::AdmissionClosed))
        ));
        assert_eq!(registry.active, ACTIVE_FRAMES);
        assert_eq!(registry.historical_frame_rejections, historical);
        assert_eq!(registry.current_frame_rejections, current);
        // These are bookkeeping checks, not a synthetic JNI/VMDeath run.
        for _ in 0..ACTIVE_FRAMES {
            registry.release_frame();
        }
        assert_eq!(registry.active, 0);
        assert_eq!(registry.historical_frame_rejections, historical);
        assert_eq!(registry.current_frame_rejections, current);
    }

    #[test]
    fn cleanup_lifetime_skips_closed_negative_and_poisoned_without_jni() {
        use std::cell::Cell;

        let registry = Mutex::new(Registry::new());
        let calls = Cell::new(0);
        for status in [-1, -5, jint::MIN] {
            let result = with_cleanup_lifetime(
                &registry,
                || status,
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
            );
            assert!(matches!(result, Ok(None)));
        }
        registry.lock().expect("test registry").closed = true;
        let result = with_cleanup_lifetime(
            &registry,
            || 0,
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
        );
        assert!(matches!(result, Ok(None)));
        assert_eq!(calls.get(), 0);
        let state = registry.lock().expect("test registry");
        assert!(state.captures.is_empty());
        assert!(state.globals.is_empty());
        assert_eq!(state.next_object, 1);
        assert_eq!(
            state.historical_frame_rejections,
            FrameLimitRejections::default()
        );
        assert_eq!(
            state.current_frame_rejections,
            FrameLimitRejections::default()
        );
        assert!(state.core.admission_facts().first_failure.is_none());
        drop(state);

        let poisoned = Mutex::new(Registry::new());
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = poisoned.lock().expect("unpoisoned test registry");
            panic!("test-only registry poison");
        }));
        assert!(panic.is_err());
        let result = with_cleanup_lifetime(
            &poisoned,
            || 0,
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
        );
        assert!(matches!(result, Ok(None)));
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn cleanup_lifetime_holds_close_lock_and_preserves_operation_result() {
        let registry = Mutex::new(Registry::new());
        // The operation is a pure stand-in, not JNI or a synthetic VM event.
        let success = with_cleanup_lifetime(
            &registry,
            || 0,
            || {
                assert!(matches!(
                    registry.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ));
                Ok(17u8)
            },
        );
        assert!(matches!(success, Ok(Some(17))));
        let no_pending = with_cleanup_lifetime(&registry, || 0, || Ok(None::<u8>));
        // Live query with no pending value differs from a skipped query.
        assert!(matches!(no_pending, Ok(Some(None))));
        let failure = with_cleanup_lifetime(
            &registry,
            || 0,
            || {
                assert!(matches!(
                    registry.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ));
                Err::<(), _>(ffi::FfiError::PendingException)
            },
        );
        assert!(matches!(failure, Err(ffi::FfiError::PendingException)));
        // The action's guard is gone before adopt/cause retention may relock.
        assert!(registry.try_lock().is_ok());
    }

    #[test]
    fn concurrent_frame_admission_remains_bounded_and_closed_owners_can_drain() {
        use std::sync::mpsc;

        let registry = Arc::new(Mutex::new(Registry::new()));
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let mut releases = Vec::new();
            let mut workers = Vec::new();
            for _ in 0..4 {
                let registry = Arc::clone(&registry);
                let done = done_tx.clone();
                let (release_tx, release_rx) = mpsc::channel();
                releases.push(release_tx);
                workers.push(scope.spawn(move || {
                    let mut admitted = 0;
                    for _ in 0..17 {
                        let result = registry.lock().expect("test registry").admit_frame(21, 0);
                        match result {
                            Ok(()) => admitted += 1,
                            Err(Error::Fact(Failure::ResourceLimit)) => {}
                            Err(_) => panic!("unexpected frame admission failure"),
                        }
                    }
                    done.send((std::thread::current().id(), admitted))
                        .expect("test channel");
                    let released = release_rx.recv_timeout(Duration::from_secs(5)).is_ok();
                    let mut state = registry.lock().expect("test registry");
                    for _ in 0..admitted {
                        state.release_frame();
                    }
                    assert!(released, "bounded owner-release signal");
                    admitted
                }));
            }
            let owners = (0..4)
                .map(|_| {
                    done_rx
                        .recv_timeout(Duration::from_secs(5))
                        .expect("bounded admission signal")
                })
                .collect::<Vec<_>>();
            assert_eq!(
                owners.iter().map(|(_, count)| count).sum::<usize>(),
                ACTIVE_FRAMES
            );
            {
                let mut state = registry.lock().expect("test registry");
                assert_eq!(state.active, ACTIVE_FRAMES);
                assert_eq!(state.historical_frame_rejections.count, 4);
                assert_eq!(state.current_frame_rejections.count, 0);
                assert!(matches!(state.take_turn(owners[0].0), Ok(true)));
                assert!(matches!(state.take_turn(owners[1].0), Ok(false)));
                assert!(matches!(
                    state.take_turn(owners[0].0),
                    Err(Error::Gap("reentrant_native_event"))
                ));
                state.release_turn(owners[1].0);
                assert_eq!(state.turn, Some(owners[0].0));
                state.closed = true;
                assert!(matches!(
                    state.take_turn(owners[1].0),
                    Err(Error::Fact(Failure::AdmissionClosed))
                ));
                assert!(matches!(
                    state.admit_frame(43, 0),
                    Err(Error::Fact(Failure::AdmissionClosed))
                ));
                assert_eq!(state.active, ACTIVE_FRAMES);
                assert_eq!(state.current_frame_rejections.count, 0);
                state.release_turn(owners[0].0);
                assert!(state.turn.is_none());
            }
            for release in releases {
                release.send(()).expect("test release channel");
            }
            for worker in workers {
                assert!(worker.join().is_ok());
            }
        });
        let state = registry.lock().expect("test registry");
        assert_eq!(state.active, 0);
        assert!(state.closed);
        assert_eq!(state.historical_frame_rejections.count, 4);
        assert_eq!(state.current_frame_rejections.count, 0);
    }
}

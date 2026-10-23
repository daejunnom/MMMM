// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
//! Native VM producer: references, opaque definition attempts, and callbacks.
//!
//! No Rust mutex is held across JNI, JVMTI, or Java calls. Registry insertion uses
//! a bounded optimistic version check; references stay strong until VMDeath.
//! ClassLoader native declarations and implementation:
//! https://github.com/openjdk/jdk/blob/jdk-25-ga/src/java.base/share/native/libjava/ClassLoader.c
//! https://github.com/openjdk/jdk/blob/jdk-25-ga/src/java.base/share/classes/java/lang/ClassLoader.java
//! https://github.com/openjdk/jdk/blob/jdk-25-ga/src/hotspot/share/prims/jvm.cpp

use std::cell::RefCell;
use std::ffi::{c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicPtr, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::classfile::{HiddenForwarder, match_hidden_forwarder};
use crate::definitions::{
    AttemptId, DefinitionKind, ExecutableSnapshot, HiddenRecipe, MAX_CLASS_BYTES, MAX_METHODS,
    MAX_TOTAL_BYTES, MethodCode, MethodSnapshot, RecordingCore, RecordingError,
};
use crate::ffi::{
    self, FfiError, JNIEnv, JavaVM, JvmtiEnv, jboolean, jbyteArray, jclass, jint, jmethodID,
    jobject, jstring, jthread,
};

const INSTALLED: jint = 1;
const BOUND_1: jint = 2;
const BOUND_2: jint = 4;
const BOUND_0: jint = 8;
const HOOK_ENABLED: jint = 16;
const PREPARE_ENABLED: jint = 32;
const SNAPSHOT_CAPABILITIES: jint = 64;
const VM_LIVE: jint = 128;
const UNSUPPORTED_ABI: jint = -1;
const UNSUPPORTED_CAPABILITIES: jint = -2;
const EVENT_SETUP_FAILED: jint = -3;
const RECORDING_FAILED: jint = -4;
const VM_DEAD: jint = -5;
const MAX_REFERENCES: usize = 16384;
const MAX_EARLY_BINDS: usize = 8192;
const MAX_REGISTRY_RETRIES: usize = 8;
// Reservations cover overlapping copies: metadata only 2 MiB; CP/evidence
// 18 MiB (two 8 MiB regions); selected definitions 26 MiB (raw recipe, private
// JNI clone, original native copy). Retaining a Vec atomically transfers its
// charge out of the current operation's reservation into the core. JVMTI
// allocates before returning its size, so this is not a hard limit on the VM's
// internal allocator or whole-process memory; oversize results are rejected and
// deallocated immediately. Native activation must retain that distinction.
// Core charges recorded payload length plus wire overhead. Vec.capacity,
// allocator rounding, Rust container storage and VM heaps are separate; these
// logical budgets are not a hard bound on the Rust heap either.
const METADATA_RESERVATION: usize = 2 * 1024 * 1024;
const SNAPSHOT_RESERVATION: usize = 18 * 1024 * 1024;
const DEFINITION_RESERVATION: usize = 26 * 1024 * 1024;
const MAX_FORWARDER_FRAME_BYTES: usize = 1024 * 1024;
const MAX_FORWARDER_TEXT_BYTES: usize = 4096;
const MAX_FORWARDER_REFERENCES: usize = 256;
const CLASS_LOADER_SIGNATURE: &[u8] = b"Ljava/lang/ClassLoader;";
const DESC_1: &[u8] = b"(Ljava/lang/ClassLoader;Ljava/lang/String;[BIILjava/security/ProtectionDomain;Ljava/lang/String;)Ljava/lang/Class;\0";
const DESC_2: &[u8] = b"(Ljava/lang/ClassLoader;Ljava/lang/String;Ljava/nio/ByteBuffer;IILjava/security/ProtectionDomain;Ljava/lang/String;)Ljava/lang/Class;\0";
const DESC_0: &[u8] = b"(Ljava/lang/ClassLoader;Ljava/lang/Class;Ljava/lang/String;[BIILjava/security/ProtectionDomain;ZILjava/lang/Object;)Ljava/lang/Class;\0";
const ROSTER: &[&[u8]] = &[
    b"com/mojang/brigadier/",
    b"net/minecraft/commands/",
    b"net/minecraft/server/commands/",
    // Actual game-loader anchor for the narrow private owned-file platform port.
    b"net/minecraft/server/MinecraftServer",
    b"net/minecraft/world/scores/",
    b"net/minecraft/nbt/",
    b"net/minecraft/world/level/storage/",
    b"net/minecraft/world/level/saveddata/",
    b"io/github/daejunnom/mmmm/observer/",
    b"io/github/daejunnom/mmmm/fabric/",
];
// Exact source-observation receivers only. This is not a Minecraft namespace
// prefix, and it does not admit unspecified JDK collection implementations.
const SOURCE_CLASS_ROSTER: &[&[u8]] = &[
    b"net/minecraft/server/packs/resources/Resource",
    b"net/minecraft/server/packs/FixedPathPackResources",
    b"net/minecraft/server/packs/resources/MultiPackResourceManager",
    b"net/minecraft/server/packs/resources/ResourceManager",
    b"net/minecraft/server/packs/resources/CloseableResourceManager",
    b"net/minecraft/server/ServerFunctionLibrary",
    b"net/minecraft/server/ServerFunctionManager",
    b"net/minecraft/server/ReloadableServerResources",
    b"net/minecraft/server/MinecraftServer$ReloadableResources",
    b"net/minecraft/resources/Identifier",
    b"net/minecraft/server/MinecraftServer",
    b"net/minecraft/server/dedicated/DedicatedServer",
    b"io/github/daejunnom/mmmm/fabric/NativeFunctionLoadObservation",
    b"io/github/daejunnom/mmmm/fabric/NativeFunctionLoadObservation$NativeCall",
    b"io/github/daejunnom/mmmm/fabric/NativeFunctionLoadObservation$TrackedSupplier",
    b"io/github/daejunnom/mmmm/fabric/NativeFunctionLoadObservation$TrackedFunction",
    b"io/github/daejunnom/mmmm/fabric/NativeFunctionLoadObservation$Read",
    b"io/github/daejunnom/mmmm/fabric/mixin/ServerFunctionManagerLibraryReadAccess",
    b"io/github/daejunnom/mmmm/fabric/mixin/FixedPathPackReadAccess",
];
// Exact actual read receivers and their inherited-method owners. Their existing
// defining loader must be nonzero; it is not inferred to be the game loader.
const READ_RECEIVER_ROSTER: &[&[u8]] = &[
    b"com/google/common/collect/RegularImmutableList",
    b"com/google/common/collect/SingletonImmutableList",
    b"com/google/common/collect/RegularImmutableMap",
    b"com/google/common/collect/ImmutableCollection",
    b"com/google/common/collect/ImmutableList",
    b"com/google/common/collect/ImmutableMap",
];

static STATUS: AtomicI32 = AtomicI32::new(UNSUPPORTED_ABI);
static JVMTI: AtomicPtr<JvmtiEnv> = AtomicPtr::new(ptr::null_mut());
static NAME_METHOD: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static ORIGINALS: [AtomicPtr<c_void>; 3] = [
    AtomicPtr::new(ptr::null_mut()),
    AtomicPtr::new(ptr::null_mut()),
    AtomicPtr::new(ptr::null_mut()),
];
static STATE: OnceLock<Mutex<State>> = OnceLock::new();
static CORE: OnceLock<Mutex<RecordingCore>> = OnceLock::new();

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReferenceKind {
    Class,
    Loader,
    Thread,
}
#[derive(Clone, Copy)]
struct Reference {
    id: u64,
    handle: usize,
    kind: ReferenceKind,
}
// handle is a VM-issued strong global jobject, never a native identity hash.
// usize only permits storing the address in a Send Rust container; equality is
// exclusively established through JNI IsSameObject outside the mutex.
struct State {
    closed: bool,
    active_operations: usize,
    pending_globals: usize,
    reserved_bytes: usize,
    next_operation: u64,
    operation_reservations: Vec<(u64, usize)>,
    next_reference: u64,
    registry_version: u64,
    references: Vec<Reference>,
    early_binds: Vec<(usize, usize)>,
    pending_bind_registration: bool,
}
impl State {
    fn new() -> Self {
        Self {
            closed: false,
            active_operations: 0,
            pending_globals: 0,
            reserved_bytes: 0,
            next_operation: 1,
            operation_reservations: Vec::new(),
            next_reference: 1,
            registry_version: 1,
            references: Vec::new(),
            early_binds: Vec::new(),
            pending_bind_registration: false,
        }
    }
}
struct Operation {
    id: u64,
}
struct LocalOperations {
    ids: [u64; 64],
    count: usize,
}
thread_local! {
    static OPERATIONS: RefCell<LocalOperations> = const { RefCell::new(LocalOperations { ids: [0; 64], count: 0 }) };
}
fn current_operation() -> Option<u64> {
    OPERATIONS.with(|operations| {
        let operations = operations.try_borrow().ok()?;
        operations
            .count
            .checked_sub(1)
            .map(|index| operations.ids[index])
    })
}
struct PendingGlobal {
    env: *mut JNIEnv,
    handle: jobject,
    reserved: bool,
}
impl Drop for PendingGlobal {
    fn drop(&mut self) {
        // DeleteGlobalRef is permitted with a pending JNI exception. No mutex is
        // held. A VM already closing retains bounded refs until VM destruction.
        if !self.handle.is_null() && status() != VM_DEAD {
            let _ = unsafe { ffi::delete_global(self.env, self.handle) };
        }
        if self.reserved
            && let Some(state) = STATE.get()
            && let Ok(mut state) = state.lock()
        {
            state.pending_globals = state.pending_globals.saturating_sub(1);
        }
    }
}
impl Operation {
    fn acquire(reservation: usize) -> Option<Self> {
        let mut state = STATE.get()?.lock().ok()?;
        if state.closed || status() < 0 {
            return None;
        }
        let retained = CORE.get()?.lock().ok()?.retained_bytes();
        if state
            .reserved_bytes
            .checked_add(reservation)?
            .checked_add(retained)?
            > MAX_TOTAL_BYTES
            || state.next_operation == u64::MAX
            || state.operation_reservations.try_reserve(1).is_err()
        {
            fail(RECORDING_FAILED);
            return None;
        }
        let id = state.next_operation;
        state.next_operation += 1;
        state.active_operations = state.active_operations.checked_add(1)?;
        state.reserved_bytes += reservation;
        state.operation_reservations.push((id, reservation));
        drop(state);
        let inserted = OPERATIONS.with(|operations| {
            let Ok(mut operations) = operations.try_borrow_mut() else {
                return false;
            };
            if operations.count >= operations.ids.len() {
                return false;
            }
            let index = operations.count;
            operations.ids[index] = id;
            operations.count += 1;
            true
        });
        let operation = Self { id };
        if inserted {
            Some(operation)
        } else {
            fail(RECORDING_FAILED);
            drop(operation);
            None
        }
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        OPERATIONS.with(|operations| {
            if let Ok(mut operations) = operations.try_borrow_mut()
                && let Some(index) = operations.ids[..operations.count]
                    .iter()
                    .position(|id| *id == self.id)
            {
                let count = operations.count;
                operations.ids.copy_within(index + 1..count, index);
                operations.count -= 1;
            }
        });
        if let Some(state) = STATE.get()
            && let Ok(mut state) = state.lock()
        {
            state.active_operations = state.active_operations.saturating_sub(1);
            if let Some(index) = state
                .operation_reservations
                .iter()
                .position(|entry| entry.0 == self.id)
            {
                let (_, amount) = state.operation_reservations.swap_remove(index);
                state.reserved_bytes = state.reserved_bytes.saturating_sub(amount);
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum ProducerError {
    Ffi(FfiError),
    Core(RecordingError),
    StateUnavailable,
}
impl From<FfiError> for ProducerError {
    fn from(value: FfiError) -> Self {
        Self::Ffi(value)
    }
}
impl From<RecordingError> for ProducerError {
    fn from(value: RecordingError) -> Self {
        Self::Core(value)
    }
}
type Result<T> = std::result::Result<T, ProducerError>;

pub(crate) fn status() -> jint {
    STATUS.load(Ordering::Acquire)
}
// Borrowed only inside an attached, current JNI call. This is an installed-VM
// observation, not executable/source approval or permission to select a path.
pub(crate) fn owned_files_vm() -> *mut JvmtiEnv {
    JVMTI.load(Ordering::Acquire)
}

/// An actual issuer-held Class/loader join, scoped to one owned-file JNI call.
/// It does not turn observed definitions into source or write approval.
pub(crate) struct OwnedFilePortToken {
    _operation: Operation,
    status: jint,
    classes: [(u64, u64); 4],
}
impl OwnedFilePortToken {
    pub(crate) fn is_current(&self) -> bool {
        status() == self.status
            && self.status >= 0
            && self.status & VM_LIVE != 0
            && core(|core| {
                Ok(self
                    .classes
                    .iter()
                    .all(|(id, generation)| core.ordinary_generation(*id) == Some(*generation)))
            })
            .unwrap_or(false)
    }
}
/// Exact actual Classes, never names or loader IDs supplied in JSON. A second
/// observed definition with one of these names makes this acquisition ambiguous.
/// The operation lease pins issuer globals across all following native I/O.
pub(crate) unsafe fn owned_file_port(
    env: *mut JNIEnv,
    bridge: jclass,
    port: jclass,
    checkpoint: &impl Fn() -> ffi::Result<()>,
) -> Result<Option<OwnedFilePortToken>> {
    let operation =
        Operation::acquire(METADATA_RESERVATION).ok_or(ProducerError::StateUnavailable)?;
    let initial = status();
    let ti = owned_files_vm();
    if initial < 0 || ti.is_null() || unsafe { ffi::exception(env)? } {
        return Ok(None);
    }
    let mut actual = [bridge, port, ptr::null_mut(), ptr::null_mut()];
    let names: [&[u8]; 4] = [
        b"Lio/github/daejunnom/mmmm/observer/DefinitionOwnedPackFilesBridge;",
        b"Lio/github/daejunnom/mmmm/fabric/NativeCalibrationPackFiles$NativeCall;",
        b"Lio/github/daejunnom/mmmm/fabric/MmmmFabricHost;",
        b"Lnet/minecraft/server/MinecraftServer;",
    ];
    let references = {
        let state = STATE
            .get()
            .ok_or(ProducerError::StateUnavailable)?
            .lock()
            .map_err(|_| ProducerError::StateUnavailable)?;
        if state.closed {
            return Ok(None);
        }
        state
            .references
            .iter()
            .filter(|reference| reference.kind == ReferenceKind::Class)
            .copied()
            .collect::<Vec<_>>()
    };
    let mut joined = [(0, 0); 4];
    let mut counts = [0usize; 4];
    // This bounded metadata-only scan invokes no caller method. The host/game
    // anchors come from issuer-held actual Classes, never port-provided Classes.
    for reference in references {
        let class = reference.handle as jclass;
        let signature = unsafe { ffi::class_signature(ti, class)? };
        for index in 0..4 {
            if signature != names[index] {
                continue;
            }
            counts[index] += 1;
            if index < 2 && !unsafe { ffi::same_object(env, class, actual[index])? } {
                return Ok(None);
            }
            if index >= 2 {
                actual[index] = class;
            }
            let Some(generation) = core(|core| Ok(core.ordinary_generation(reference.id)))? else {
                return Ok(None);
            };
            if !unsafe { ffi::class_prepared(ti, class)? } {
                return Ok(None);
            }
            joined[index] = (reference.id, generation);
        }
    }
    if counts != [1; 4] {
        return Ok(None);
    }
    let loaders = unsafe {
        [
            actual_loader(env, ti, actual[0])?,
            actual_loader(env, ti, actual[1])?,
            actual_loader(env, ti, actual[2])?,
            actual_loader(env, ti, actual[3])?,
        ]
    };
    if loaders[0] != 0 || loaders[1] == 0 || loaders[1] != loaders[2] || loaders[2] != loaders[3] {
        return Ok(None);
    }
    checkpoint()?;
    let token = OwnedFilePortToken {
        _operation: operation,
        status: initial,
        classes: joined,
    };
    Ok(token.is_current().then_some(token))
}

/// Actual source-callback Classes pinned by one issuer operation lease.
/// This token cannot authorize access to a fresh owned-file NativeCall.
pub(crate) struct SourceCaptureToken {
    _operation: Operation,
    status: jint,
    classes: [(u64, u64); 4],
}
impl SourceCaptureToken {
    pub(crate) fn is_current(&self) -> bool {
        source_port_current(self.status, &self.classes)
    }
    pub(crate) fn stamp(&self) -> [(u64, u64); 4] {
        self.classes
    }
    pub(crate) fn snapshot(&self) -> SourceCaptureStamp {
        SourceCaptureStamp {
            status: self.status,
            classes: self.classes,
        }
    }
    /// Native issuer epoch; callers must also check the current token/stamp.
    pub(crate) fn generation(&self) -> u64 {
        1
    }
}

/// Pure metadata, never a frame lease or renewed observation authority.
/// The current JNI frame must separately keep its SourceCaptureToken alive.
#[derive(Clone, Copy)]
pub(crate) struct SourceCaptureStamp {
    status: jint,
    classes: [(u64, u64); 4],
}
impl SourceCaptureStamp {
    pub(crate) fn is_current(&self) -> bool {
        source_port_current(self.status, &self.classes)
    }
}

/// Retainable metadata only: no operation/TLS lease, JNI env or local ref.
/// The issuer owns held_class; accessing it requires a current frame token.
#[derive(Clone, Copy)]
pub(crate) struct ObservedClassStamp {
    class_id: u64,
    definition_generation: u64,
    loader: u64,
    held_class: usize,
    signature: &'static [u8],
}
impl ObservedClassStamp {
    pub(crate) fn is_current(&self) -> bool {
        self.held_class != 0
            && status() >= 0
            && status() & VM_LIVE != 0
            && core(|core| {
                Ok(core.ordinary_generation(self.class_id) == Some(self.definition_generation))
            })
            .unwrap_or(false)
    }
    pub(crate) fn stamp(&self) -> (u64, u64) {
        (self.class_id, self.definition_generation)
    }
    pub(crate) fn signature(&self) -> &'static [u8] {
        self.signature
    }
    pub(crate) fn loader(&self) -> u64 {
        self.loader
    }
    /// This borrowed Class must not escape token's current attached JNI frame.
    pub(crate) fn actual_class(&self, token: &SourceCaptureToken) -> Option<jclass> {
        (token.is_current() && self.is_current()).then_some(self.held_class as jclass)
    }
}

/// Pure issuer-held read-class metadata; no JNI frame or operation lease.
/// A current SourceCaptureToken must separately pin every actual Class use.
#[derive(Clone, Copy)]
pub(crate) struct ReadReceiverStamp {
    class: ObservedClassStamp,
}
impl ReadReceiverStamp {
    pub(crate) fn is_current(&self) -> bool {
        self.class.is_current()
    }
    pub(crate) fn stamp(&self) -> (u64, u64) {
        self.class.stamp()
    }
    pub(crate) fn signature(&self) -> &'static [u8] {
        self.class.signature()
    }
    pub(crate) fn loader(&self) -> u64 {
        self.class.loader()
    }
    pub(crate) fn actual_class(&self, token: &SourceCaptureToken) -> Option<jclass> {
        self.class.actual_class(token)
    }
}

/// Join object_class's actual Class to one exact issuer-held definition.
pub(crate) unsafe fn actual_source_class(
    env: *mut JNIEnv,
    token: &SourceCaptureToken,
    actual_class: jclass,
    expected: &'static [u8],
) -> Result<Option<ObservedClassStamp>> {
    if actual_class.is_null() {
        return Ok(None);
    }
    unsafe { source_class_stamp(env, token, Some(actual_class), expected) }
}

/// Resolve a fixed issuer-held base Class, without FindClass/Class.forName or
/// using the actual server's subclass to select inherited-field metadata.
pub(crate) unsafe fn source_class_by_name(
    env: *mut JNIEnv,
    token: &SourceCaptureToken,
    expected: &'static [u8],
) -> Result<Option<ObservedClassStamp>> {
    unsafe { source_class_stamp(env, token, None, expected) }
}

unsafe fn source_class_stamp(
    env: *mut JNIEnv,
    token: &SourceCaptureToken,
    actual_class: Option<jclass>,
    expected: &'static [u8],
) -> Result<Option<ObservedClassStamp>> {
    unsafe { retained_class_stamp(env, token, actual_class, expected, ClassStampPolicy::Source) }
}

/// Join an actual read receiver or declaring Class to its exact held definition.
pub(crate) unsafe fn actual_read_receiver_class(
    env: *mut JNIEnv,
    token: &SourceCaptureToken,
    actual_class: jclass,
    expected: &'static [u8],
) -> Result<Option<ReadReceiverStamp>> {
    if actual_class.is_null() {
        return Ok(None);
    }
    unsafe {
        retained_class_stamp(
            env,
            token,
            Some(actual_class),
            expected,
            ClassStampPolicy::ReadReceiver,
        )
    }
    .map(|stamp| stamp.map(|class| ReadReceiverStamp { class }))
}

#[derive(Clone, Copy)]
enum ClassStampPolicy {
    Source,
    ReadReceiver,
}

unsafe fn retained_class_stamp(
    env: *mut JNIEnv,
    token: &SourceCaptureToken,
    actual_class: Option<jclass>,
    expected: &'static [u8],
    policy: ClassStampPolicy,
) -> Result<Option<ObservedClassStamp>> {
    let Some(name) = class_internal(expected) else {
        return Ok(None);
    };
    let roster = match policy {
        ClassStampPolicy::Source => SOURCE_CLASS_ROSTER,
        ClassStampPolicy::ReadReceiver => READ_RECEIVER_ROSTER,
    };
    if !roster.contains(&name) || env.is_null() || !token.is_current() {
        return Ok(None);
    }
    if unsafe { ffi::exception(env)? } {
        return Err(FfiError::PendingException.into());
    }
    let ti = owned_files_vm();
    if ti.is_null() {
        return Ok(None);
    }
    let references = {
        let state = STATE
            .get()
            .ok_or(ProducerError::StateUnavailable)?
            .lock()
            .map_err(|_| ProducerError::StateUnavailable)?;
        if state.closed {
            return Ok(None);
        }
        state
            .references
            .iter()
            .filter(|reference| reference.kind == ReferenceKind::Class)
            .copied()
            .collect::<Vec<_>>()
    };
    let references = match policy {
        ClassStampPolicy::Source => references,
        ClassStampPolicy::ReadReceiver => {
            let Some(actual) = actual_class else {
                return Ok(None);
            };
            // Select the actual held Class before inspecting its name or loader.
            // An unrelated same-named Class in another loader is no candidate.
            let mut matched = None;
            for reference in references {
                if !token.is_current() {
                    return Ok(None);
                }
                if unsafe { ffi::same_object(env, actual, reference.handle as jclass)? } {
                    if matched.is_some() {
                        return Ok(None);
                    }
                    matched = Some(reference);
                }
            }
            let Some(reference) = matched else {
                return Ok(None);
            };
            vec![reference]
        }
    };
    let game_loader = match policy {
        ClassStampPolicy::Source => {
            // The token's fourth exact Class is the held MinecraftServer base.
            let Some(game_class) = references
                .iter()
                .find(|reference| reference.id == token.classes[3].0)
            else {
                return Ok(None);
            };
            if !token.is_current() {
                return Ok(None);
            }
            let Some(loader) =
                (unsafe { existing_source_loader(env, ti, game_class.handle as jclass)? })
            else {
                return Ok(None);
            };
            if loader == 0 {
                return Ok(None);
            }
            Some(loader)
        }
        ClassStampPolicy::ReadReceiver => None,
    };
    let mut found = None;
    for reference in references {
        if !token.is_current() {
            return Ok(None);
        }
        let class = reference.handle as jclass;
        if unsafe { ffi::class_signature(ti, class)? } != expected {
            continue;
        }
        if found.is_some() {
            return Ok(None);
        }
        if let Some(actual) = actual_class
            && !unsafe { ffi::same_object(env, actual, class)? }
        {
            return Ok(None);
        }
        let Some(generation) = core(|core| Ok(core.ordinary_generation(reference.id)))? else {
            return Ok(None);
        };
        if !token.is_current() || !unsafe { ffi::class_prepared(ti, class)? } {
            return Ok(None);
        }
        let Some(loader) = (unsafe { existing_source_loader(env, ti, class)? }) else {
            return Ok(None);
        };
        if loader == 0 || game_loader.is_some_and(|expected| expected != loader) {
            return Ok(None);
        }
        found = Some(ObservedClassStamp {
            class_id: reference.id,
            definition_generation: generation,
            loader,
            held_class: reference.handle,
            signature: expected,
        });
    }
    Ok(found.filter(|stamp| token.is_current() && stamp.is_current()))
}

/// A separately joined actual fresh owned-file port, never a capture conversion.
pub(crate) struct CurrentSourceRootToken {
    _operation: Operation,
    status: jint,
    classes: [(u64, u64); 5],
}
impl CurrentSourceRootToken {
    pub(crate) fn is_current(&self) -> bool {
        source_port_current(self.status, &self.classes)
    }
    pub(crate) fn stamp(&self) -> [(u64, u64); 5] {
        self.classes
    }
    /// Native issuer epoch; callers must also check the current token/stamp.
    pub(crate) fn generation(&self) -> u64 {
        1
    }
}

fn source_port_current<const N: usize>(initial: jint, classes: &[(u64, u64); N]) -> bool {
    status() == initial
        && initial >= 0
        && initial & VM_LIVE != 0
        && core(|core| {
            Ok(classes
                .iter()
                .all(|(id, generation)| core.ordinary_generation(*id) == Some(*generation)))
        })
        .unwrap_or(false)
}

/// Resolve an already issuer-held loader; this metadata port creates no globals.
unsafe fn existing_source_loader(
    env: *mut JNIEnv,
    ti: *mut JvmtiEnv,
    class: jclass,
) -> Result<Option<u64>> {
    let loader = unsafe { ffi::class_loader(ti, class)? };
    if loader.is_null() {
        return Ok(Some(0));
    }
    let result = unsafe { existing_identity(env, loader, ReferenceKind::Loader) };
    let closed = unsafe { ffi::delete_local(env, loader) };
    match (result, closed) {
        (Ok(loader), Ok(())) => Ok(loader),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
    }
}

/// Names are fixed by the private callers below. Actual Classes come from JNI
/// object_class, never from a Java name/id/Class getter or a caller's receipt.
unsafe fn source_port_classes<const N: usize>(
    env: *mut JNIEnv,
    initial: jint,
    names: [&[u8]; N],
    supplied: &[jclass],
) -> Result<Option<[(u64, u64); N]>> {
    let ti = owned_files_vm();
    if env.is_null()
        || initial < 0
        || initial & VM_LIVE == 0
        || ti.is_null()
        || supplied.len() + 2 != N
        || supplied.iter().any(|class| class.is_null())
        || unsafe { ffi::exception(env)? }
    {
        return Ok(None);
    }
    let references = {
        let state = STATE
            .get()
            .ok_or(ProducerError::StateUnavailable)?
            .lock()
            .map_err(|_| ProducerError::StateUnavailable)?;
        if state.closed {
            return Ok(None);
        }
        state
            .references
            .iter()
            .filter(|reference| reference.kind == ReferenceKind::Class)
            .copied()
            .collect::<Vec<_>>()
    };
    let mut actual = [ptr::null_mut(); N];
    actual[..supplied.len()].copy_from_slice(supplied);
    let mut joined = [(0, 0); N];
    let mut counts = [0usize; N];
    for reference in references {
        let class = reference.handle as jclass;
        let signature = unsafe { ffi::class_signature(ti, class)? };
        for index in 0..N {
            if signature != names[index] {
                continue;
            }
            counts[index] += 1;
            if index < supplied.len() && !unsafe { ffi::same_object(env, class, actual[index])? } {
                return Ok(None);
            }
            if index >= supplied.len() {
                actual[index] = class;
            }
            let Some(generation) = core(|core| Ok(core.ordinary_generation(reference.id)))? else {
                return Ok(None);
            };
            if !unsafe { ffi::class_prepared(ti, class)? } {
                return Ok(None);
            }
            joined[index] = (reference.id, generation);
        }
    }
    if counts != [1; N] {
        return Ok(None);
    }
    let mut game_loader = None;
    for (index, class) in actual.into_iter().enumerate() {
        let Some(loader) = (unsafe { existing_source_loader(env, ti, class)? }) else {
            return Ok(None);
        };
        if index == 0 {
            if loader != 0 {
                return Ok(None);
            }
        } else if loader == 0 || game_loader.is_some_and(|expected| expected != loader) {
            return Ok(None);
        } else {
            game_loader = Some(loader);
        }
    }
    Ok(source_port_current(initial, &joined).then_some(joined))
}

pub(crate) unsafe fn source_capture_port(
    env: *mut JNIEnv,
    implicit_bridge: jclass,
    actual_load_port_class: jclass,
) -> Result<Option<SourceCaptureToken>> {
    let operation =
        Operation::acquire(METADATA_RESERVATION).ok_or(ProducerError::StateUnavailable)?;
    let initial = status();
    let names: [&[u8]; 4] = [
        b"Lio/github/daejunnom/mmmm/observer/DefinitionPackLoadBridge;",
        b"Lio/github/daejunnom/mmmm/fabric/NativeFunctionLoadObservation$NativeCall;",
        b"Lio/github/daejunnom/mmmm/fabric/MmmmFabricHost;",
        b"Lnet/minecraft/server/MinecraftServer;",
    ];
    let Some(classes) = (unsafe {
        source_port_classes(
            env,
            initial,
            names,
            &[implicit_bridge, actual_load_port_class],
        )?
    }) else {
        return Ok(None);
    };
    let token = SourceCaptureToken {
        _operation: operation,
        status: initial,
        classes,
    };
    Ok(token.is_current().then_some(token))
}

pub(crate) unsafe fn current_source_root_port(
    env: *mut JNIEnv,
    implicit_bridge: jclass,
    actual_load_port_class: jclass,
    actual_fresh_native_call_class: jclass,
) -> Result<Option<CurrentSourceRootToken>> {
    let operation =
        Operation::acquire(METADATA_RESERVATION).ok_or(ProducerError::StateUnavailable)?;
    let initial = status();
    let names: [&[u8]; 5] = [
        b"Lio/github/daejunnom/mmmm/observer/DefinitionPackLoadBridge;",
        b"Lio/github/daejunnom/mmmm/fabric/NativeFunctionLoadObservation$NativeCall;",
        b"Lio/github/daejunnom/mmmm/fabric/NativeCalibrationPackFiles$NativeCall;",
        b"Lio/github/daejunnom/mmmm/fabric/MmmmFabricHost;",
        b"Lnet/minecraft/server/MinecraftServer;",
    ];
    let Some(classes) = (unsafe {
        source_port_classes(
            env,
            initial,
            names,
            &[
                implicit_bridge,
                actual_load_port_class,
                actual_fresh_native_call_class,
            ],
        )?
    }) else {
        return Ok(None);
    };
    let token = CurrentSourceRootToken {
        _operation: operation,
        status: initial,
        classes,
    };
    Ok(token.is_current().then_some(token))
}

/// Actual observed bootstrap anchor Class generation. An anchor's name or
/// Java constructor is not registration; this joins the exact prepared Class
/// object to the installed initial-definition producer for each current call.
pub(crate) unsafe fn owned_root_anchor_class(
    env: *mut JNIEnv,
    class: jclass,
) -> Result<Option<(u64, u64)>> {
    let ti = owned_files_vm();
    if ti.is_null() || status() < 0 || unsafe { ffi::exception(env)? } {
        return Ok(None);
    }
    if unsafe { ffi::class_signature(ti, class)? }
        != b"Lio/github/daejunnom/mmmm/observer/DefinitionOwnedPackFilesBridge$RootAnchor;"
        || unsafe { actual_loader(env, ti, class)? } != 0
        || !unsafe { ffi::class_prepared(ti, class)? }
    {
        return Ok(None);
    }
    let references = {
        let state = STATE
            .get()
            .ok_or(ProducerError::StateUnavailable)?
            .lock()
            .map_err(|_| ProducerError::StateUnavailable)?;
        if state.closed {
            return Ok(None);
        }
        state
            .references
            .iter()
            .filter(|reference| reference.kind == ReferenceKind::Class)
            .copied()
            .collect::<Vec<_>>()
    };
    let mut found = None;
    for reference in references {
        if unsafe { ffi::same_object(env, class, reference.handle as jobject)? } {
            if found.is_some() {
                return Ok(None);
            }
            let Some(generation) = core(|core| Ok(core.ordinary_generation(reference.id)))? else {
                return Ok(None);
            };
            found = Some((reference.id, generation));
        }
    }
    Ok(found)
}

/// One active consumer's actual observed anchor generation remains current.
/// The caller already holds OwnedFilePortToken's operation lease.
pub(crate) fn owned_root_anchor_current(class: (u64, u64)) -> bool {
    status() >= 0
        && core(|core| Ok(core.ordinary_generation(class.0) == Some(class.1))).unwrap_or(false)
}
fn fail(code: jint) {
    let mut prior = status();
    while prior >= 0 {
        match STATUS.compare_exchange_weak(prior, code, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(current) => prior = current,
        }
    }
}
fn report(error: ProducerError) {
    // Attempt-level rejection is evidence unavailability, not a made-up success.
    match error {
        ProducerError::Core(error) if !error.is_resource_limit() => {}
        ProducerError::Ffi(FfiError::PendingException) => fail(RECORDING_FAILED),
        _ => fail(RECORDING_FAILED),
    }
}
fn core<T>(
    action: impl FnOnce(&mut RecordingCore) -> std::result::Result<T, RecordingError>,
) -> Result<T> {
    // The only two-lock order is STATE -> CORE. These closures execute pure Rust
    // and never call back into the VM. JNI/JVMTI calls always occur afterwards.
    let mut budget = STATE
        .get()
        .ok_or(ProducerError::StateUnavailable)?
        .lock()
        .map_err(|_| ProducerError::StateUnavailable)?;
    let mut state = CORE
        .get()
        .ok_or(ProducerError::StateUnavailable)?
        .lock()
        .map_err(|_| ProducerError::StateUnavailable)?;
    let before = state.retained_bytes();
    let result = action(&mut state).map_err(Into::into);
    let added = state.retained_bytes().saturating_sub(before);
    if added > 0 {
        let transfer = current_operation().and_then(|id| {
            budget
                .operation_reservations
                .iter_mut()
                .find(|entry| entry.0 == id)
        });
        match transfer {
            Some(entry) if entry.1 >= added => {
                entry.1 -= added;
                budget.reserved_bytes -= added;
            }
            _ => {
                fail(RECORDING_FAILED);
                return Err(FfiError::BoundExceeded.into());
            }
        }
    }
    if budget
        .reserved_bytes
        .checked_add(state.retained_bytes())
        .is_none_or(|total| total > MAX_TOTAL_BYTES)
    {
        fail(RECORDING_FAILED);
        return Err(FfiError::BoundExceeded.into());
    }
    if state.is_resource_exhausted() {
        fail(RECORDING_FAILED);
    }
    result
}
fn callback(action: impl FnOnce() -> Result<()>) {
    match catch_unwind(AssertUnwindSafe(action)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => report(error),
        Err(_) => fail(RECORDING_FAILED),
    }
}
fn selected(name: &[u8]) -> bool {
    ROSTER.iter().any(|prefix| name.starts_with(prefix))
        || SOURCE_CLASS_ROSTER
            .iter()
            .chain(READ_RECEIVER_ROSTER.iter())
            .any(|expected| *expected == name)
}
fn selected_prefix(prefix: &[u16]) -> bool {
    ROSTER.iter().any(|expected| {
        expected.len() <= prefix.len()
            && expected.iter().zip(prefix).all(|(expected, actual)| {
                let actual = if *actual == u16::from(b'.') {
                    u16::from(b'/')
                } else {
                    *actual
                };
                actual == u16::from(*expected)
            })
    }) || (prefix.len() < 64
        && SOURCE_CLASS_ROSTER
            .iter()
            .chain(READ_RECEIVER_ROSTER.iter())
            .any(|expected| {
                // string_prefix returns min(full length, 64); exactly 64 is not a
                // complete-name witness. Existing MMMM prefix selection stays above.
                expected.len() == prefix.len()
                    && expected.iter().zip(prefix).all(|(expected, actual)| {
                        let actual = if *actual == u16::from(b'.') {
                            u16::from(b'/')
                        } else {
                            *actual
                        };
                        actual == u16::from(*expected)
                    })
            }))
}
fn normalize(name: &[u8]) -> Vec<u8> {
    name.iter()
        .map(|byte| if *byte == b'.' { b'/' } else { *byte })
        .collect()
}
fn class_internal(signature: &[u8]) -> Option<&[u8]> {
    signature.strip_prefix(b"L")?.strip_suffix(b";")
}

/// No object reference or JNI environment is retained from a callback without a
/// strong global-reference conversion. The operation lease prevents VMDeath
/// cleanup while these outside-lock identity checks use registry references.
unsafe fn identity(env: *mut JNIEnv, object: jobject, kind: ReferenceKind) -> Result<u64> {
    if object.is_null() {
        return if kind == ReferenceKind::Loader {
            Ok(0)
        } else {
            Err(FfiError::InvalidResult.into())
        };
    }
    let state_mutex = STATE.get().ok_or(ProducerError::StateUnavailable)?;
    for _ in 0..MAX_REGISTRY_RETRIES {
        let (version, references) = {
            let state = state_mutex
                .lock()
                .map_err(|_| ProducerError::StateUnavailable)?;
            if state.closed {
                return Err(ProducerError::StateUnavailable);
            }
            (
                state.registry_version,
                state
                    .references
                    .iter()
                    .filter(|r| r.kind == kind)
                    .copied()
                    .collect::<Vec<_>>(),
            )
        };
        for reference in references {
            if unsafe { ffi::same_object(env, reference.handle as jobject, object)? } {
                return Ok(reference.id);
            }
        }
        {
            let mut state = state_mutex
                .lock()
                .map_err(|_| ProducerError::StateUnavailable)?;
            if state
                .references
                .len()
                .checked_add(state.pending_globals)
                .is_none_or(|n| n >= MAX_REFERENCES)
            {
                return Err(FfiError::BoundExceeded.into());
            }
            state.pending_globals += 1;
        }
        let mut allocation = PendingGlobal {
            env,
            handle: ptr::null_mut(),
            reserved: true,
        };
        allocation.handle = unsafe { ffi::new_global(env, object)? };
        let global = allocation.handle;
        let outcome = (|| -> Result<Option<Result<u64>>> {
            let mut state = state_mutex
                .lock()
                .map_err(|_| ProducerError::StateUnavailable)?;
            let outcome = if state.closed {
                Some(Err(ProducerError::StateUnavailable))
            } else if state.registry_version != version {
                None
            } else if state.references.len() >= MAX_REFERENCES
                || state.next_reference == u64::MAX
                || state.references.try_reserve(1).is_err()
            {
                Some(Err(FfiError::BoundExceeded.into()))
            } else {
                let id = state.next_reference;
                state.next_reference += 1;
                state.registry_version += 1;
                // Commit transfers one reserved global to the committed set in
                // the same Rust critical section. Discard releases its slot only
                // AFTER DeleteGlobalRef in PendingGlobal::drop.
                state.pending_globals = state.pending_globals.saturating_sub(1);
                state.references.push(Reference {
                    id,
                    handle: global as usize,
                    kind,
                });
                allocation.handle = ptr::null_mut();
                allocation.reserved = false;
                return Ok(Some(Ok(id)));
            };
            Ok(outcome)
        })();
        match outcome? {
            Some(Ok(id)) => return Ok(id),
            Some(Err(error)) => return Err(error),
            None => {}
        }
    }
    Err(FfiError::BoundExceeded.into())
}
unsafe fn existing_identity(
    env: *mut JNIEnv,
    object: jobject,
    kind: ReferenceKind,
) -> Result<Option<u64>> {
    let references = {
        let state = STATE
            .get()
            .ok_or(ProducerError::StateUnavailable)?
            .lock()
            .map_err(|_| ProducerError::StateUnavailable)?;
        if state.closed {
            return Err(ProducerError::StateUnavailable);
        }
        state
            .references
            .iter()
            .filter(|r| r.kind == kind)
            .copied()
            .collect::<Vec<_>>()
    };
    for reference in references {
        if unsafe { ffi::same_object(env, reference.handle as jobject, object)? } {
            return Ok(Some(reference.id));
        }
    }
    Ok(None)
}
unsafe fn thread_identity(env: *mut JNIEnv, ti: *mut JvmtiEnv) -> Result<u64> {
    let thread = unsafe { ffi::current_thread(ti)? };
    let result = unsafe { identity(env, thread, ReferenceKind::Thread) };
    unsafe { ffi::delete_local(env, thread)? };
    result
}
unsafe fn actual_loader(env: *mut JNIEnv, ti: *mut JvmtiEnv, class: jclass) -> Result<u64> {
    let loader = unsafe { ffi::class_loader(ti, class)? };
    let result = unsafe { identity(env, loader, ReferenceKind::Loader) };
    unsafe { ffi::delete_local(env, loader)? };
    result
}
unsafe fn actual_name(env: *mut JNIEnv, class: jclass) -> Result<Vec<u8>> {
    let method = NAME_METHOD.load(Ordering::Acquire);
    if method.is_null() {
        return Err(ProducerError::StateUnavailable);
    }
    Ok(unsafe { ffi::class_name(env, class, method)? })
}

pub(crate) fn on_load(vm: *mut JavaVM, options: *mut c_char) -> jint {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<()> {
        let Some(abi) = ffi::STARTUP_ABI else {
            return Err(ProducerError::StateUnavailable);
        };
        // This exact startup option is a configuration marker, never source or
        // runtime authority. Arbitrary prefixes and late enablement are rejected.
        let option = unsafe { ffi::c_string(options, 128)? };
        if !abi.accepts_options(&option) {
            return Err(ProducerError::StateUnavailable);
        }
        if STATE.set(Mutex::new(State::new())).is_err()
            || CORE.set(Mutex::new(RecordingCore::new(1))).is_err()
        {
            return Err(ProducerError::StateUnavailable);
        }
        let ti = unsafe { ffi::get_jvmti(vm)? };
        // API major is checked. It does not prove the VM vendor/build source pin.
        if unsafe { ffi::version(ti)? } != ffi::JVMTI_VERSION_25 {
            return Err(ProducerError::StateUnavailable);
        }
        JVMTI.store(ti, Ordering::Release);
        let required = ffi::Capabilities::required();
        if !unsafe { ffi::capabilities(ti, true)? }.contains(&required) {
            STATUS.store(UNSUPPORTED_CAPABILITIES, Ordering::Release);
            return Err(ProducerError::StateUnavailable);
        }
        unsafe { ffi::add_capabilities(ti, &required)? };
        if !unsafe { ffi::capabilities(ti, false)? }.contains(&required) {
            STATUS.store(UNSUPPORTED_CAPABILITIES, Ordering::Release);
            return Err(ProducerError::StateUnavailable);
        }
        let mut callbacks = ffi::EventCallbacks::default();
        callbacks.slots[0] = vm_init as *const c_void;
        callbacks.slots[1] = vm_death as *const c_void;
        callbacks.slots[4] = class_file_load_hook as *const c_void;
        callbacks.slots[5] = class_load as *const c_void;
        callbacks.slots[6] = class_prepare as *const c_void;
        callbacks.slots[17] = native_method_bind as *const c_void;
        STATUS.store(EVENT_SETUP_FAILED, Ordering::Release);
        unsafe { ffi::set_callbacks(ti, &callbacks)? };
        // Retransformation capability is acquired BEFORE first hook activation.
        // This observer supplies no transformed array, so each callback remains
        // observational. Only the launcher can approve terminal ordering.
        for event in [50, 51, 54, 55, 56, 67] {
            unsafe { ffi::set_event(ti, event, true)? };
        }
        STATUS.store(
            INSTALLED | HOOK_ENABLED | PREPARE_ENABLED | SNAPSHOT_CAPABILITIES,
            Ordering::Release,
        );
        Ok(())
    }));
    if !matches!(result, Ok(Ok(()))) && status() >= 0 {
        fail(RECORDING_FAILED);
    }
    // Keeping this unsupported library loaded permits a truthful nativeStatus.
    // The launcher and bridge must refuse producer use when status is negative.
    ffi::JNI_OK
}
pub(crate) fn on_unload() {
    STATUS.store(VM_DEAD, Ordering::Release);
    crate::owned_pack_files::on_unload();
    crate::loaded_pack_sources_jni::on_unload();
    JVMTI.store(ptr::null_mut(), Ordering::Release);
    // Agent_OnUnload may occur after VM destruction. No JNI calls are permitted.
}

unsafe extern "C" fn vm_init(ti: *mut JvmtiEnv, env: *mut JNIEnv, _thread: jthread) {
    callback(|| {
        let _operation =
            Operation::acquire(METADATA_RESERVATION).ok_or(ProducerError::StateUnavailable)?;
        if unsafe { ffi::exception(env)? } {
            return Err(FfiError::PendingException.into());
        }
        let class = unsafe { ffi::find_class(env, b"java/lang/Class\0")? };
        let method = unsafe { ffi::class_name_method(env, class) };
        if method.is_err() {
            unsafe { ffi::delete_local(env, class)? };
            return Err(method.err().ok_or(ProducerError::StateUnavailable)?.into());
        }
        let held = unsafe { identity(env, class, ReferenceKind::Class) };
        // Warm this exact bootstrap metadata accessor before selected calls;
        // first getName0 native binding can otherwise reenter during ClassLoad.
        let warm_name = unsafe { ffi::class_name(env, class, method?) };
        unsafe { ffi::delete_local(env, class)? };
        held?;
        warm_name?;
        NAME_METHOD.store(method?, Ordering::Release);
        let early = {
            let mut state = STATE
                .get()
                .ok_or(ProducerError::StateUnavailable)?
                .lock()
                .map_err(|_| ProducerError::StateUnavailable)?;
            std::mem::take(&mut state.early_binds)
        };
        for (method, address) in early {
            if let Some(target) = unsafe { identify_native(ti, env, method as jmethodID)? } {
                unsafe { install_binding(target, address as *mut c_void, ptr::null_mut())? };
                let class = unsafe { ffi::method_declaring_class(ti, method as jmethodID)? };
                let (name, descriptor) = native_description(target);
                {
                    let mut state = STATE
                        .get()
                        .ok_or(ProducerError::StateUnavailable)?
                        .lock()
                        .map_err(|_| ProducerError::StateUnavailable)?;
                    state.pending_bind_registration = true;
                }
                let registration = ffi::NativeMethod {
                    name: name.as_ptr() as *mut c_char,
                    signature: descriptor.as_ptr() as *mut c_char,
                    function: trampoline(target),
                };
                let result = unsafe { ffi::register_native(env, class, &registration) };
                {
                    let mut state = STATE
                        .get()
                        .ok_or(ProducerError::StateUnavailable)?
                        .lock()
                        .map_err(|_| ProducerError::StateUnavailable)?;
                    state.pending_bind_registration = false;
                }
                unsafe { ffi::delete_local(env, class)? };
                result?;
            }
        }
        if status() >= 0 {
            STATUS.fetch_or(VM_LIVE, Ordering::AcqRel);
        }
        Ok(())
    });
}
unsafe extern "C" fn vm_death(_ti: *mut JvmtiEnv, env: *mut JNIEnv) {
    STATUS.store(VM_DEAD, Ordering::Release);
    // This actual VMDeath callback supplies the still-valid event environment.
    // Registry drains no active file lease and invokes no Java callback here.
    unsafe { crate::owned_pack_files::vm_death(env) };
    unsafe { crate::loaded_pack_sources_jni::vm_death(env) };
    let references = match STATE.get().and_then(|state| state.lock().ok()) {
        Some(mut state) => {
            state.closed = true;
            // Do not invalidate in-flight native object handles. Normally there
            // are no Java operations at VMDeath. If another native participant
            // still owns a lease, bounded refs remain VM-owned until destruction.
            if state.active_operations == 0 {
                std::mem::take(&mut state.references)
            } else {
                Vec::new()
            }
        }
        None => Vec::new(),
    };
    for reference in references {
        let _ = unsafe { ffi::delete_global(env, reference.handle as jobject) };
    }
    JVMTI.store(ptr::null_mut(), Ordering::Release);
    NAME_METHOD.store(ptr::null_mut(), Ordering::Release);
}

fn native_description(target: usize) -> (&'static [u8], &'static [u8]) {
    match target {
        0 => (b"defineClass1\0", DESC_1),
        1 => (b"defineClass2\0", DESC_2),
        _ => (b"defineClass0\0", DESC_0),
    }
}
fn trampoline(target: usize) -> *mut c_void {
    match target {
        0 => define_class_1 as *mut c_void,
        1 => define_class_2 as *mut c_void,
        _ => define_class_0 as *mut c_void,
    }
}
unsafe fn identify_native(
    ti: *mut JvmtiEnv,
    env: *mut JNIEnv,
    method: jmethodID,
) -> Result<Option<usize>> {
    let (name, descriptor) = unsafe { ffi::method_name(ti, method)? };
    let target = (0..3).find(|index| {
        let (expected_name, expected_descriptor) = native_description(*index);
        name == expected_name[..expected_name.len() - 1]
            && descriptor == expected_descriptor[..expected_descriptor.len() - 1]
    });
    let Some(target) = target else {
        return Ok(None);
    };
    if unsafe { ffi::method_modifiers(ti, method)? } & (ffi::ACC_STATIC | ffi::ACC_NATIVE)
        != ffi::ACC_STATIC | ffi::ACC_NATIVE
    {
        return Err(FfiError::InvalidResult.into());
    }
    let class = unsafe { ffi::method_declaring_class(ti, method)? };
    let result = (|| -> Result<bool> {
        if unsafe { ffi::class_signature(ti, class)? } != CLASS_LOADER_SIGNATURE {
            return Ok(false);
        }
        let loader = unsafe { ffi::class_loader(ti, class)? };
        let bootstrap = loader.is_null();
        unsafe { ffi::delete_local(env, loader)? };
        if !bootstrap {
            return Ok(false);
        }
        // Name plus bootstrap authority is checked against actual FindClass
        // mirror identity. This never invokes a game class loader.
        let expected = unsafe { ffi::find_class(env, b"java/lang/ClassLoader\0")? };
        let same = unsafe { ffi::same_object(env, class, expected) };
        unsafe { ffi::delete_local(env, expected)? };
        Ok(same?)
    })();
    unsafe { ffi::delete_local(env, class)? };
    Ok(if result? { Some(target) } else { None })
}
unsafe fn install_binding(
    target: usize,
    address: *mut c_void,
    new_address: *mut *mut c_void,
) -> Result<()> {
    if address.is_null() {
        return Err(FfiError::InvalidResult.into());
    }
    let wrapper = trampoline(target);
    let old = ORIGINALS[target].load(Ordering::Acquire);
    if address == wrapper {
        let own_registration = STATE
            .get()
            .and_then(|state| state.lock().ok())
            .is_some_and(|state| state.pending_bind_registration);
        if old.is_null() || !own_registration {
            return Err(FfiError::InvalidResult.into());
        }
    } else if old.is_null() {
        if ORIGINALS[target]
            .compare_exchange(
                ptr::null_mut(),
                address,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(FfiError::InvalidResult.into());
        }
    } else if old != address {
        // A later foreign native replacement invalidates the producer. No new
        // address is adopted as an allegedly closed pipeline.
        fail(RECORDING_FAILED);
        return Err(FfiError::InvalidResult.into());
    }
    if !new_address.is_null() {
        unsafe { *new_address = wrapper };
    }
    if status() >= 0 {
        STATUS.fetch_or([BOUND_1, BOUND_2, BOUND_0][target], Ordering::AcqRel);
    }
    Ok(())
}
unsafe extern "C" fn native_method_bind(
    ti: *mut JvmtiEnv,
    env: *mut JNIEnv,
    _thread: jthread,
    method: jmethodID,
    address: *mut c_void,
    new_address: *mut *mut c_void,
) {
    callback(|| {
        if status() < 0 {
            return Ok(());
        }
        let phase = unsafe { ffi::phase(ti)? };
        if env.is_null() || (phase != ffi::PHASE_START && phase != ffi::PHASE_LIVE) {
            let mut state = STATE
                .get()
                .ok_or(ProducerError::StateUnavailable)?
                .lock()
                .map_err(|_| ProducerError::StateUnavailable)?;
            if state.early_binds.len() >= MAX_EARLY_BINDS {
                return Err(FfiError::BoundExceeded.into());
            }
            state.early_binds.push((method as usize, address as usize));
            return Ok(());
        }
        let _operation =
            Operation::acquire(METADATA_RESERVATION).ok_or(ProducerError::StateUnavailable)?;
        if unsafe { ffi::exception(env)? } {
            return Err(FfiError::PendingException.into());
        }
        if let Some(target) = unsafe { identify_native(ti, env, method)? } {
            unsafe { install_binding(target, address, new_address)? };
        }
        Ok(())
    });
}

unsafe extern "C" fn class_file_load_hook(
    ti: *mut JvmtiEnv,
    env: *mut JNIEnv,
    redefined: jclass,
    loader: jobject,
    name: *const c_char,
    _pd: jobject,
    size: jint,
    bytes: *const u8,
    _new_size: *mut jint,
    _new_bytes: *mut *mut u8,
) {
    callback(|| {
        if status() < 0 {
            return Ok(());
        }
        let _operation =
            Operation::acquire(SNAPSHOT_RESERVATION).ok_or(ProducerError::StateUnavailable)?;
        if env.is_null() {
            return Ok(());
        }
        if unsafe { ffi::exception(env)? } {
            return Err(FfiError::PendingException.into());
        }
        if !redefined.is_null() {
            if let Some(id) = unsafe { existing_identity(env, redefined, ReferenceKind::Class)? } {
                core(|core| {
                    core.invalidate_class(id);
                    Ok(())
                })?;
                fail(RECORDING_FAILED);
            }
            return Ok(());
        }
        if name.is_null() {
            return Ok(());
        }
        let name = unsafe { ffi::c_string(name, 65535)? };
        if !selected(&name) {
            return Ok(());
        }
        if status() & VM_LIVE == 0 || env.is_null() {
            return Err(ProducerError::StateUnavailable);
        }
        if unsafe { ffi::exception(env)? } {
            return Err(FfiError::PendingException.into());
        }
        let thread = unsafe { thread_identity(env, ti)? };
        let loader = unsafe { identity(env, loader, ReferenceKind::Loader)? };
        let bytes = unsafe { ffi::copy_buffer(bytes, size, MAX_CLASS_BYTES)? };
        core(|core| core.terminal_hook(thread, loader, Some(&name), bytes))?;
        Ok(())
    });
}
unsafe fn snapshot(ti: *mut JvmtiEnv, class: jclass) -> Result<ExecutableSnapshot> {
    if !unsafe { ffi::class_prepared(ti, class)? } {
        return Err(FfiError::InvalidResult.into());
    }
    let (constant_pool_count, constant_pool) =
        unsafe { ffi::constant_pool(ti, class, MAX_CLASS_BYTES)? };
    let methods = unsafe { ffi::class_methods(ti, class)? };
    if methods.len() > MAX_METHODS {
        return Err(FfiError::BoundExceeded.into());
    }
    let mut size = constant_pool.len();
    let mut snapshots = Vec::with_capacity(methods.len());
    for method in methods {
        let (name_mutf8, descriptor_mutf8) = unsafe { ffi::method_name(ti, method)? };
        let modifiers = unsafe { ffi::method_modifiers(ti, method)? };
        let code = if modifiers & ffi::ACC_NATIVE != 0 {
            MethodCode::Native
        } else if modifiers & ffi::ACC_ABSTRACT != 0 {
            MethodCode::Abstract
        } else {
            MethodCode::Bytecodes(unsafe {
                ffi::bytecodes(ti, method, MAX_CLASS_BYTES.saturating_sub(size))?
            })
        };
        let code_size = match &code {
            MethodCode::Bytecodes(bytes) => bytes.len(),
            _ => 0,
        };
        size = size
            .checked_add(name_mutf8.len())
            .and_then(|n| n.checked_add(descriptor_mutf8.len()))
            .and_then(|n| n.checked_add(code_size))
            .ok_or(FfiError::BoundExceeded)?;
        if size > MAX_CLASS_BYTES {
            return Err(FfiError::BoundExceeded.into());
        }
        snapshots.push(MethodSnapshot {
            name_mutf8,
            descriptor_mutf8,
            modifiers,
            code,
        });
    }
    Ok(ExecutableSnapshot {
        constant_pool_count,
        constant_pool,
        methods: snapshots,
    })
}
unsafe fn class_event(
    ti: *mut JvmtiEnv,
    env: *mut JNIEnv,
    thread: jthread,
    class: jclass,
    prepared: bool,
) -> Result<()> {
    if status() < 0 {
        return Ok(());
    }
    let _operation = Operation::acquire(if prepared {
        SNAPSHOT_RESERVATION
    } else {
        METADATA_RESERVATION
    })
    .ok_or(ProducerError::StateUnavailable)?;
    if env.is_null() {
        return Ok(());
    }
    // Callback metadata is read only. No filesystem or global class/heap scan.
    let signature = unsafe { ffi::class_signature(ti, class)? };
    let Some(internal) = class_internal(&signature) else {
        return Ok(());
    };
    if !selected(internal) {
        return Ok(());
    }
    if status() & VM_LIVE == 0 {
        return Err(ProducerError::StateUnavailable);
    }
    if unsafe { ffi::exception(env)? } {
        return Err(FfiError::PendingException.into());
    }
    let thread = unsafe { identity(env, thread, ReferenceKind::Thread)? };
    let id = unsafe { identity(env, class, ReferenceKind::Class)? };
    let loader = unsafe { actual_loader(env, ti, class)? };
    let name = unsafe { actual_name(env, class)? };
    if prepared {
        let needs_snapshot =
            core(|core| Ok(core.active_kind(thread).is_some() || core.needs_snapshot(id)))?;
        let snapshot = if needs_snapshot {
            Some(unsafe { snapshot(ti, class)? })
        } else {
            None
        };
        core(|core| core.class_prepare(thread, id, loader, name, snapshot))?;
    } else {
        core(|core| core.class_load(thread, id, loader, name))?;
    }
    Ok(())
}
unsafe extern "C" fn class_load(
    ti: *mut JvmtiEnv,
    env: *mut JNIEnv,
    thread: jthread,
    class: jclass,
) {
    callback(|| unsafe { class_event(ti, env, thread, class, false) });
}
unsafe extern "C" fn class_prepare(
    ti: *mut JvmtiEnv,
    env: *mut JNIEnv,
    thread: jthread,
    class: jclass,
) {
    callback(|| unsafe { class_event(ti, env, thread, class, true) });
}

struct SelectedCall {
    _operation: Operation,
    thread: u64,
    token: AttemptId,
    clone: jbyteArray,
}
/// The actual ClassLoader native inputs for the current JNI frame's selected
/// slice and recipe. These pointers are not caller-issued evidence or tokens.
/// ProtectionDomain/source remain unchanged in the original trampoline call.
struct SelectedDefinitionInput {
    loader: jobject,
    lookup: jclass,
    name: jstring,
    data: jbyteArray,
    offset: jint,
    size: jint,
    initialize: jboolean,
    flags: jint,
    class_data: jobject,
    kind: DefinitionKind,
}
unsafe fn begin_selected(
    env: *mut JNIEnv,
    input: SelectedDefinitionInput,
) -> Result<Option<SelectedCall>> {
    let SelectedDefinitionInput {
        loader,
        lookup,
        name,
        data,
        offset,
        size,
        initialize,
        flags,
        class_data,
        kind,
    } = input;
    let hidden = kind == DefinitionKind::Hidden;
    if status() < 0 || status() & VM_LIVE == 0 || name.is_null() {
        return Ok(None);
    }
    if unsafe { ffi::exception(env)? } {
        return Ok(None);
    }
    if hidden && (!class_data.is_null() || flags & ffi::HIDDEN_CLASS == 0) {
        return Ok(None);
    }
    // Generic definitions do not acquire a buffer reservation, copy a full
    // name, allocate a JNI string copy, clone an array, or create an attempt.
    // This bounded primitive prefix probe preserves the actual original args.
    let (prefix, size_prefix) = unsafe { ffi::string_prefix(env, name)? };
    if !selected_prefix(&prefix[..size_prefix]) {
        return Ok(None);
    }
    let Some(operation) = Operation::acquire(DEFINITION_RESERVATION) else {
        return Ok(None);
    };
    let requested = unsafe { ffi::string_mutf8(env, name)? };
    let internal = normalize(&requested);
    if !selected(&internal) || (hidden && (!class_data.is_null() || flags & ffi::HIDDEN_CLASS == 0))
    {
        return Ok(None);
    }
    let ti = JVMTI.load(Ordering::Acquire);
    let thread = unsafe { thread_identity(env, ti)? };
    let loader_id = if hidden {
        unsafe { actual_loader(env, ti, lookup)? }
    } else {
        unsafe { identity(env, loader, ReferenceKind::Loader)? }
    };
    let lookup_id = if hidden {
        unsafe { identity(env, lookup, ReferenceKind::Class)? }
    } else {
        0
    };
    let bytes = unsafe { ffi::selected_array(env, data, offset, size, MAX_CLASS_BYTES)? };
    // Controlled recipe interposition: original native consumes this private
    // exact selected slice, offset zero, same length. No content is transformed.
    let clone = unsafe { ffi::byte_array(env, &bytes)? };
    let recipe = if hidden {
        Some(HiddenRecipe {
            input: bytes,
            flags,
            initialize: initialize != 0,
            lookup_class_id: lookup_id,
            defining_loader_id: loader_id,
            requested_name_mutf8: requested,
        })
    } else {
        None
    };
    let token = core(|core| core.begin(thread, loader_id, Some(internal), kind, recipe, true));
    match token {
        Ok(token) => Ok(Some(SelectedCall {
            _operation: operation,
            thread,
            token,
            clone,
        })),
        Err(error) => {
            unsafe { ffi::delete_local(env, clone)? };
            Err(error)
        }
    }
}
unsafe fn finish_selected(env: *mut JNIEnv, call: SelectedCall, returned: jclass) -> Result<()> {
    let pending = unsafe { ffi::exception(env) };
    // With a pending exception, only allowed JNI reference/exception functions
    // run; no metadata upcall or global-reference allocation occurs.
    let identity_result = match pending {
        Ok(false) if !returned.is_null() => {
            unsafe { identity(env, returned, ReferenceKind::Class) }.map(Some)
        }
        Ok(_) => Ok(None),
        Err(error) => Err(error.into()),
    };
    let cleanup = unsafe { ffi::delete_local(env, call.clone) };
    match (pending, identity_result, cleanup) {
        (Ok(pending), Ok(returned_id), Ok(())) => {
            core(|core| core.finish(call.thread, call.token, returned_id, pending))
        }
        (_, identity, cleanup) => {
            // A producer metadata failure is not the VM returning null or
            // throwing. Abandon only recording, preserve the actual returned
            // jclass/exception, and let the wrapper return that original result.
            let abort = core(|core| core.abort_observation(call.thread, call.token));
            identity?;
            if let Err(error) = cleanup {
                return Err(error.into());
            }
            abort?;
            Err(ProducerError::StateUnavailable)
        }
    }
}
fn prepare_call(action: impl FnOnce() -> Result<Option<SelectedCall>>) -> Option<SelectedCall> {
    match catch_unwind(AssertUnwindSafe(action)) {
        Ok(Ok(call)) => call,
        Ok(Err(error)) => {
            report(error);
            None
        }
        Err(_) => {
            fail(RECORDING_FAILED);
            None
        }
    }
}
unsafe extern "C" fn define_class_1(
    env: *mut JNIEnv,
    cls: jclass,
    loader: jobject,
    name: jstring,
    data: jbyteArray,
    offset: jint,
    size: jint,
    pd: jobject,
    source: jstring,
) -> jclass {
    let address = ORIGINALS[0].load(Ordering::Acquire);
    if address.is_null() {
        fail(RECORDING_FAILED);
        return ptr::null_mut();
    }
    let original: ffi::DefineClass1 = unsafe { std::mem::transmute(address) };
    let call = prepare_call(|| unsafe {
        begin_selected(
            env,
            SelectedDefinitionInput {
                loader,
                lookup: ptr::null_mut(),
                name,
                data,
                offset,
                size,
                initialize: 0,
                flags: 0,
                class_data: ptr::null_mut(),
                kind: DefinitionKind::Ordinary,
            },
        )
    });
    // A clone/JNI pre-boundary failure retains the actual pending exception.
    // It performs zero original calls; there is no fallback invocation with a
    // pending exception. Every normal path below calls original exactly once.
    if unsafe { ffi::exception(env) }.unwrap_or(true) {
        if let Some(call) = call {
            callback(|| unsafe { finish_selected(env, call, ptr::null_mut()) });
        }
        return ptr::null_mut();
    }
    let (input, off) = call.as_ref().map_or((data, offset), |call| (call.clone, 0));
    let returned = unsafe { original(env, cls, loader, name, input, off, size, pd, source) };
    if let Some(call) = call {
        callback(|| unsafe { finish_selected(env, call, returned) });
    }
    returned
}
unsafe extern "C" fn define_class_2(
    env: *mut JNIEnv,
    cls: jclass,
    loader: jobject,
    name: jstring,
    data: jobject,
    offset: jint,
    size: jint,
    pd: jobject,
    source: jstring,
) -> jclass {
    let address = ORIGINALS[1].load(Ordering::Acquire);
    if address.is_null() {
        fail(RECORDING_FAILED);
        return ptr::null_mut();
    }
    let original: ffi::DefineClass2 = unsafe { std::mem::transmute(address) };
    // DirectByteBuffer interposition is not approved in this source profile.
    // No attempt token means subsequent callbacks cannot issue its evidence.
    unsafe { original(env, cls, loader, name, data, offset, size, pd, source) }
}
unsafe extern "C" fn define_class_0(
    env: *mut JNIEnv,
    cls: jclass,
    loader: jobject,
    lookup: jclass,
    name: jstring,
    data: jbyteArray,
    offset: jint,
    size: jint,
    pd: jobject,
    initialize: jboolean,
    flags: jint,
    class_data: jobject,
) -> jclass {
    let address = ORIGINALS[2].load(Ordering::Acquire);
    if address.is_null() {
        fail(RECORDING_FAILED);
        return ptr::null_mut();
    }
    let original: ffi::DefineClass0 = unsafe { std::mem::transmute(address) };
    // Only hidden recipes are admitted here. Non-hidden Lookup definitions pass
    // through and have no evidence; the loader argument is preserved verbatim.
    let call = if flags & ffi::HIDDEN_CLASS != 0 {
        prepare_call(|| unsafe {
            begin_selected(
                env,
                SelectedDefinitionInput {
                    loader,
                    lookup,
                    name,
                    data,
                    offset,
                    size,
                    initialize,
                    flags,
                    class_data,
                    kind: DefinitionKind::Hidden,
                },
            )
        })
    } else {
        None
    };
    if unsafe { ffi::exception(env) }.unwrap_or(true) {
        if let Some(call) = call {
            callback(|| unsafe { finish_selected(env, call, ptr::null_mut()) });
        }
        return ptr::null_mut();
    }
    let (input, off) = call.as_ref().map_or((data, offset), |call| (call.clone, 0));
    let returned = unsafe {
        original(
            env, cls, loader, lookup, name, input, off, size, pd, initialize, flags, class_data,
        )
    };
    if let Some(call) = call {
        callback(|| unsafe { finish_selected(env, call, returned) });
    }
    returned
}

pub(crate) fn evidence(env: *mut JNIEnv, actual: jclass) -> jbyteArray {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<jbyteArray> {
        let initial_status = status();
        if actual.is_null() || initial_status < 0 || initial_status & VM_LIVE == 0 {
            return Ok(ptr::null_mut());
        }
        let _operation =
            Operation::acquire(SNAPSHOT_RESERVATION).ok_or(ProducerError::StateUnavailable)?;
        if unsafe { ffi::exception(env)? } {
            return Ok(ptr::null_mut());
        }
        let Some(id) = (unsafe { existing_identity(env, actual, ReferenceKind::Class)? }) else {
            return Ok(ptr::null_mut());
        };
        // The exact incoming actual Class is compared to issuer-held globals;
        // no resource lookup, caller source, caller digest, or integer receipt.
        let (bytes, stamp) = core(|core| core.encode_evidence_with_stamp(id))?;
        if !core(|core| Ok(core.evidence_stamp_is_current(&stamp) && status() == initial_status))? {
            return Ok(ptr::null_mut());
        }
        let output = unsafe { ffi::byte_array(env, &bytes)? };
        // 배열 생성 중 재정의나 VM 전이가 있었으면 이 발급 참조만 폐기한다.
        // 마지막 JNI 호출 뒤 현재 기록/status를 순수 Rust로 대조한다.
        let current = (|| -> Result<bool> {
            if unsafe { ffi::exception(env)? } {
                return Err(FfiError::PendingException.into());
            }
            core(|core| Ok(core.evidence_stamp_is_current(&stamp) && status() == initial_status))
        })();
        match current {
            Ok(true) => Ok(output),
            Ok(false) => {
                unsafe { ffi::delete_local(env, output)? };
                Ok(ptr::null_mut())
            }
            Err(error) => {
                unsafe { ffi::delete_local(env, output)? };
                Err(error)
            }
        }
    }));
    match result {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            report(error);
            ptr::null_mut()
        }
        Err(_) => {
            fail(RECORDING_FAILED);
            ptr::null_mut()
        }
    }
}

/// Issuer-only loaded method identity. It cannot be made from a caller integer,
/// classfile symbolic name, snapshot, request digest, or Java receipt.
pub(crate) struct ResolvedMethodToken {
    class_id: u64,
    target_class_handle: usize,
    method_handle: usize,
    issuer_epoch: u64,
    definition_generation: u64,
    class_status_at_resolution: jint,
    hidden_source_class_id: u64,
    hidden_source_generation: u64,
}
impl ResolvedMethodToken {
    pub(crate) fn class_id(&self) -> u64 {
        self.class_id
    }
    pub(crate) fn issuer_epoch(&self) -> u64 {
        self.issuer_epoch
    }
    pub(crate) fn definition_generation(&self) -> u64 {
        self.definition_generation
    }
    pub(crate) fn class_status_at_resolution(&self) -> jint {
        self.class_status_at_resolution
    }
    pub(crate) fn is_current(&self) -> bool {
        self.method_handle != 0
            && self.issuer_epoch == 1
            && status() >= 0
            && status() & VM_LIVE != 0
            && core(|core| {
                Ok(core.ordinary_generation(self.class_id) == Some(self.definition_generation))
            })
            .unwrap_or(false)
            && core(|core| {
                Ok(core.class_generation(self.hidden_source_class_id)
                    == Some(self.hidden_source_generation))
            })
            .unwrap_or(false)
    }
    unsafe fn has_current_class_status(&self, env: *mut JNIEnv) -> Result<bool> {
        if unsafe { ffi::exception(env)? } {
            return Err(FfiError::PendingException.into());
        }
        if !self.is_current() {
            return Ok(false);
        }
        let ti = JVMTI.load(Ordering::Acquire);
        let observed = unsafe { ffi::class_status(ti, self.target_class_handle as jclass)? };
        // The VM query can coincide with a redefinition or producer transition.
        // Its equality is useful only after both source generations are current.
        Ok(observed == self.class_status_at_resolution && self.is_current())
    }
}
/// The actual returned hidden Class, not a decoded integer from the evidence
/// frame, selects this producer-owned context. No public constructor exists.
pub(crate) struct NativeResolutionContext {
    hidden_class_id: u64,
    generation: u64,
    lookup_class_id: u64,
    defining_loader_id: u64,
    issuer_epoch: u64,
}
impl NativeResolutionContext {
    pub(crate) fn is_current(&self) -> bool {
        self.issuer_epoch == 1
            && status() >= 0
            && status() & VM_LIVE != 0
            && core(|core| {
                Ok(core.hidden_context(self.hidden_class_id)
                    == Some((
                        self.generation,
                        self.lookup_class_id,
                        self.defining_loader_id,
                    )))
            })
            .unwrap_or(false)
    }
}
pub(crate) unsafe fn resolution_context(
    env: *mut JNIEnv,
    actual_hidden: jclass,
) -> Result<Option<NativeResolutionContext>> {
    let _operation =
        Operation::acquire(METADATA_RESERVATION).ok_or(ProducerError::StateUnavailable)?;
    if actual_hidden.is_null() {
        return Ok(None);
    }
    if unsafe { ffi::exception(env)? } {
        return Err(FfiError::PendingException.into());
    }
    let Some(id) = (unsafe { existing_identity(env, actual_hidden, ReferenceKind::Class)? }) else {
        return Ok(None);
    };
    let Some((generation, lookup_class_id, defining_loader_id)) =
        core(|core| Ok(core.hidden_context(id)))?
    else {
        return Ok(None);
    };
    let context = NativeResolutionContext {
        hidden_class_id: id,
        generation,
        lookup_class_id,
        defining_loader_id,
        issuer_epoch: 1,
    };
    if !context.is_current() {
        return Ok(None);
    }
    Ok(Some(context))
}
/// Resolve only already event-observed classes held by this issuer. There is no
/// Class.forName, resource lookup, arbitrary class-loader invocation, or scan.
pub(crate) unsafe fn resolve_static_target(
    env: *mut JNIEnv,
    context: &NativeResolutionContext,
    owner_internal_mutf8: &[u8],
    name_mutf8: &[u8],
    descriptor_mutf8: &[u8],
) -> Result<Option<ResolvedMethodToken>> {
    let _operation =
        Operation::acquire(METADATA_RESERVATION).ok_or(ProducerError::StateUnavailable)?;
    if unsafe { ffi::exception(env)? } {
        return Err(FfiError::PendingException.into());
    }
    if !context.is_current() {
        return Ok(None);
    }
    let ti = JVMTI.load(Ordering::Acquire);
    let references = {
        let state = STATE
            .get()
            .ok_or(ProducerError::StateUnavailable)?
            .lock()
            .map_err(|_| ProducerError::StateUnavailable)?;
        state
            .references
            .iter()
            .filter(|r| r.kind == ReferenceKind::Class)
            .copied()
            .collect::<Vec<_>>()
    };
    let mut resolved = None;
    for reference in references {
        let class = reference.handle as jclass;
        let signature = unsafe { ffi::class_signature(ti, class)? };
        if class_internal(&signature) != Some(owner_internal_mutf8) {
            continue;
        }
        if unsafe { actual_loader(env, ti, class)? } != context.defining_loader_id {
            continue;
        }
        let generation = core(|core| Ok(core.ordinary_generation(reference.id)))?;
        let Some(generation) = generation else {
            continue;
        };
        if !unsafe { ffi::class_prepared(ti, class)? } {
            continue;
        }
        let class_status = unsafe { ffi::class_status(ti, class)? };
        for method in unsafe { ffi::class_methods(ti, class)? } {
            let (name, descriptor) = unsafe { ffi::method_name(ti, method)? };
            if name != name_mutf8 || descriptor != descriptor_mutf8 {
                continue;
            }
            if unsafe { ffi::method_modifiers(ti, method)? } & ffi::ACC_STATIC == 0 {
                continue;
            }
            let declaring = unsafe { ffi::method_declaring_class(ti, method)? };
            let same = unsafe { ffi::same_object(env, declaring, class) };
            unsafe { ffi::delete_local(env, declaring)? };
            if !same? || resolved.is_some() {
                return Ok(None);
            }
            resolved = Some(ResolvedMethodToken {
                class_id: reference.id,
                target_class_handle: reference.handle,
                method_handle: method as usize,
                issuer_epoch: 1,
                definition_generation: generation,
                class_status_at_resolution: class_status,
                hidden_source_class_id: context.hidden_class_id,
                hidden_source_generation: context.generation,
            });
        }
    }
    let Some(token) = resolved else {
        return Ok(None);
    };
    if !token.is_current() || !context.is_current() {
        return Ok(None);
    }
    // This token establishes a loaded declaring method identity only. The
    // Coordinator must independently admit initialization/source policy and the
    // actual SAM interface/dispatch closure before considering a handler proved.
    Ok(Some(token))
}

/// Optional description from the native owner's current hidden source. A match
/// and loaded static method identity do not admit SAM selection, reference
/// linkage, access, source, initialization policy, or the startup pipeline.
pub(crate) fn hidden_forwarder(env: *mut JNIEnv, actual: jclass) -> jbyteArray {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<jbyteArray> {
        let initial_status = status();
        if actual.is_null() || initial_status < 0 || initial_status & VM_LIVE == 0 {
            return Ok(ptr::null_mut());
        }
        // The outer lease retains registry globals across matching, native
        // resolution, encoding and the final JNI array/status recheck.
        let _operation =
            Operation::acquire(SNAPSHOT_RESERVATION).ok_or(ProducerError::StateUnavailable)?;
        let Some(context) = (unsafe { resolution_context(env, actual)? }) else {
            return Ok(ptr::null_mut());
        };
        let matched = core(|core| {
            // Both buffers are borrowed from the producer's authenticated
            // current record. This pure Rust matcher performs no VM calls.
            Ok(core.with_hidden_source(
                context.hidden_class_id,
                context.generation,
                match_hidden_forwarder,
            ))
        })?;
        let Some(Ok(matched)) = matched else {
            // Unsupported recipes, including the owned SAMless startup probe,
            // do not change or invalidate the raw definition observation.
            return Ok(ptr::null_mut());
        };
        if status() != initial_status || !context.is_current() {
            return Ok(ptr::null_mut());
        }
        let target = matched.target();
        let Some(token) = (unsafe {
            resolve_static_target(
                env,
                &context,
                target.owner().as_bytes(),
                target.name().as_bytes(),
                target.descriptor().as_bytes(),
            )?
        }) else {
            return Ok(ptr::null_mut());
        };
        if status() != initial_status
            || token.issuer_epoch() != context.issuer_epoch
            || !context.is_current()
            || !unsafe { token.has_current_class_status(env)? }
        {
            return Ok(ptr::null_mut());
        }
        let Some(bytes) = encode_hidden_forwarder(&context, &token, &matched) else {
            return Ok(ptr::null_mut());
        };
        if status() != initial_status
            || !context.is_current()
            || !unsafe { token.has_current_class_status(env)? }
        {
            return Ok(ptr::null_mut());
        }
        let output = unsafe { ffi::byte_array(env, &bytes)? };
        // A Java array creation may expose an asynchronous exception or a
        // concurrent VM change. Delete only this output, preserve any exception.
        let current = (|| -> Result<bool> {
            if unsafe { ffi::exception(env)? } {
                return Err(FfiError::PendingException.into());
            }
            let target_current = unsafe { token.has_current_class_status(env)? };
            // These pure Rust checks follow the final VM call, so a producer
            // transition during that call cannot issue a normal output frame.
            Ok(target_current && context.is_current() && status() == initial_status)
        })();
        match current {
            Ok(true) => Ok(output),
            Ok(false) => {
                unsafe { ffi::delete_local(env, output)? };
                Ok(ptr::null_mut())
            }
            Err(error) => {
                unsafe { ffi::delete_local(env, output)? };
                Err(error)
            }
        }
    }));
    match result {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            report(error);
            ptr::null_mut()
        }
        Err(_) => {
            fail(RECORDING_FAILED);
            ptr::null_mut()
        }
    }
}

struct ForwarderWriter(Vec<u8>);
impl ForwarderWriter {
    fn raw(&mut self, bytes: &[u8]) -> Option<()> {
        let end = self.0.len().checked_add(bytes.len())?;
        if end > MAX_FORWARDER_FRAME_BYTES || self.0.try_reserve(bytes.len()).is_err() {
            return None;
        }
        self.0.extend_from_slice(bytes);
        Some(())
    }
    fn text(&mut self, text: &str) -> Option<()> {
        if text.len() > MAX_FORWARDER_TEXT_BYTES {
            return None;
        }
        self.raw(&u32::try_from(text.len()).ok()?.to_be_bytes())?;
        self.raw(text.as_bytes())
    }
}
fn encode_hidden_forwarder(
    context: &NativeResolutionContext,
    token: &ResolvedMethodToken,
    matched: &HiddenForwarder,
) -> Option<Vec<u8>> {
    let references = matched.reference_classes();
    if references.len() > MAX_FORWARDER_REFERENCES {
        return None;
    }
    let mut writer = ForwarderWriter(Vec::new());
    writer.raw(b"MMMMSAM1")?;
    writer.raw(&1_u16.to_be_bytes())?;
    writer.raw(&0_u16.to_be_bytes())?;
    writer.raw(&token.issuer_epoch().to_be_bytes())?;
    writer.raw(&context.hidden_class_id.to_be_bytes())?;
    writer.raw(&context.generation.to_be_bytes())?;
    writer.raw(&token.class_id().to_be_bytes())?;
    writer.raw(&token.definition_generation().to_be_bytes())?;
    writer.raw(&token.class_status_at_resolution().to_be_bytes())?;
    for text in [
        matched.class_name(),
        matched.interface_name(),
        matched.sam_name(),
        matched.sam_descriptor(),
        matched.target().owner(),
        matched.target().name(),
        matched.target().descriptor(),
    ] {
        writer.text(text)?;
    }
    writer.raw(&[u8::from(matched.target().is_interface()), 0])?;
    writer.raw(&0_u16.to_be_bytes())?;
    writer.raw(&u32::try_from(references.len()).ok()?.to_be_bytes())?;
    for reference in references {
        writer.text(reference)?;
    }
    Some(writer.0)
}

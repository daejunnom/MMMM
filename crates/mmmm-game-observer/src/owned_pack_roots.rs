//! Native-owned roots survive a retired game route, never its authority. There
//! are at most eight registry entries, eight JNI global anchors and one active
//! consumer call. The one anchor's immutable Java fields strongly retain the
//! actual server/Attempt/Invocation/bundle; all joins use IsSameObject. A Java
//! constructor, numeric key, path or SHA cannot register a filesystem identity.

use super::{Checks, Failure, Result, finish};
use crate::ffi::{self, JNIEnv, jobject};
use mmmm_owned_files::{Control, DirectoryIdentityEvidence, HeldDirectory, RetainedCloseStage};
use std::{
    ffi::CStr,
    io,
    path::Path,
    ptr,
    sync::{Arc, Mutex, MutexGuard},
};

const MAX_ROOTS: usize = 8;
static ROOTS: Mutex<Registry> = Mutex::new(Registry {
    closed: false,
    active: 0,
    draining: false,
    next: 1,
    entries: Vec::new(),
});

struct Registry {
    closed: bool,
    active: usize,
    draining: bool,
    next: u64,
    entries: Vec<Record>,
}
/// Recover only to preserve or retire already-owned values. A poisoned state
/// closes admission; it never issues a new identity or operation permission.
fn preservation_state() -> (MutexGuard<'static, Registry>, bool) {
    match ROOTS.lock() {
        Ok(state) => (state, false),
        Err(error) => {
            let mut state = error.into_inner();
            state.closed = true;
            (state, true)
        }
    }
}
struct Record {
    serial: u64,
    anchor: usize,
    class: (u64, u64),
    correlation: [[u8; 32]; 3],
    root: Option<Arc<HeldDirectory>>,
    facts: HeldFacts,
    // Only native typed causes live beyond the frame. Local Throwable refs,
    // JNIEnv, Checks, callbacks and OwnedFilePortToken never enter this record.
    close_errors: Vec<Arc<RetainedCloseCause>>,
    global_release_error: Option<ffi::FfiError>,
}

pub(super) struct RetainedCloseCause {
    pub pin: Option<usize>,
    pub stage: RetainedCloseStage,
    pub error: io::Error,
}

#[derive(Clone, Copy, Default)]
pub(super) struct HeldFacts {
    pub state: u8,
    pub grade: u8,
    pub identity: u8,
    pub pins: u16,
    pub closed: u16,
    pub shared: u16,
    pub uncertain: u16,
}
impl HeldFacts {
    pub fn encode(self, operation: u8, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(b"MMMMPKH1");
        bytes.extend_from_slice(&[operation, self.state, self.grade, self.identity]);
        for count in [self.pins, self.closed, self.shared, self.uncertain] {
            bytes.extend_from_slice(&count.to_be_bytes());
        }
    }
}

pub(super) struct CallGuard;
pub(super) fn enter() -> Result<CallGuard> {
    let mut state = ROOTS.lock().map_err(|_| Failure::Unavailable)?;
    if state.closed {
        return Err(Failure::Unavailable);
    }
    // owned_pack_files::ACTIVE serializes all caller frames. This separate
    // lease prevents VMDeath from deleting a global during an identity join.
    if state.active != 0 {
        return Err(Failure::Busy);
    }
    state.active = 1;
    Ok(CallGuard)
}
impl Drop for CallGuard {
    fn drop(&mut self) {
        let drain = if let Ok(mut state) = ROOTS.lock() {
            state.active = state.active.saturating_sub(1);
            state.closed && state.active == 0
        } else {
            false
        };
        if drain {
            drain_native(None);
        }
    }
}

pub(super) struct Bindings {
    anchor: jobject,
    objects: [jobject; 4],
    class: (u64, u64),
    correlation: [[u8; 32]; 3],
}
fn object(checks: &Checks, owner: jobject, name: &CStr) -> Result<jobject> {
    // SAFETY: all owners and returned refs belong to this original attached
    // JNI frame. No mutex is held while resolving or invoking Java methods.
    let class = unsafe { ffi::object_class(checks.env, owner) }.map_err(|e| checks.ffi(e))?;
    let call = (|| {
        let method = unsafe { ffi::method_id(checks.env, class, name, c"()Ljava/lang/Object;") }
            .map_err(|e| checks.ffi(e))?;
        unsafe { ffi::call_object_zero(checks.env, owner, method) }.map_err(|e| checks.ffi(e))
    })();
    finish(
        call,
        unsafe { ffi::delete_local(checks.env, class) }.map_err(|e| checks.ffi(e)),
    )
}
fn text(checks: &Checks, name: &CStr) -> Result<[u8; 32]> {
    let class = unsafe { ffi::object_class(checks.env, checks.port) }.map_err(|e| checks.ffi(e))?;
    let call = (|| {
        let method = unsafe { ffi::method_id(checks.env, class, name, c"()Ljava/lang/String;") }
            .map_err(|e| checks.ffi(e))?;
        let units = checks.text(method)?;
        if units.len() != 64 {
            return Err(Failure::Invalid);
        }
        let mut digest = [0u8; 32];
        for (index, pair) in units.chunks_exact(2).enumerate() {
            let digit = |unit| match unit {
                48..=57 => Ok((unit - 48) as u8),
                97..=102 => Ok((unit - 97 + 10) as u8),
                _ => Err(Failure::Invalid),
            };
            digest[index] = digit(pair[0])? * 16 + digit(pair[1])?;
        }
        Ok(digest)
    })();
    finish(
        call,
        unsafe { ffi::delete_local(checks.env, class) }.map_err(|e| checks.ffi(e)),
    )
}
impl Bindings {
    pub fn load(checks: &Checks) -> Result<Self> {
        let anchor = object(checks, checks.port, c"nativeAnchor")?;
        let mut objects = [ptr::null_mut(); 4];
        let result = (|| {
            let class =
                unsafe { ffi::object_class(checks.env, anchor) }.map_err(|e| checks.ffi(e))?;
            let stamp =
                unsafe { crate::native_producer::owned_root_anchor_class(checks.env, class) }
                    .map_err(|_| Failure::Unavailable)
                    .and_then(|stamp| stamp.ok_or(Failure::Unavailable));
            let stamp = finish(
                stamp,
                unsafe { ffi::delete_local(checks.env, class) }.map_err(|e| checks.ffi(e)),
            )?;
            for (index, method) in [
                c"nativeServer",
                c"nativeAttempt",
                c"nativeInvocation",
                c"nativeBundle",
            ]
            .into_iter()
            .enumerate()
            {
                objects[index] = object(checks, checks.port, method)?;
                let anchored = object(checks, anchor, method)?;
                let same = unsafe { ffi::same_object(checks.env, objects[index], anchored) }
                    .map_err(|e| checks.ffi(e));
                let same = finish(
                    same,
                    unsafe { ffi::delete_local(checks.env, anchored) }.map_err(|e| checks.ffi(e)),
                )?;
                if !same {
                    return Err(Failure::Changed);
                }
            }
            let correlation = [
                text(checks, c"nativeInvocationDigest")?,
                text(checks, c"nativeBundleDigest")?,
                text(checks, c"nativeManifestDigest")?,
            ];
            checks.bind_anchor(stamp)?;
            Ok((stamp, correlation))
        })();
        match result {
            Ok((class, correlation)) => Ok(Self {
                anchor,
                objects,
                class,
                correlation,
            }),
            Err(mut error) => {
                for local in objects.into_iter().chain([anchor]) {
                    if !local.is_null()
                        && let Err(post) = unsafe { ffi::delete_local(checks.env, local) }
                            .map_err(|e| checks.ffi(e))
                    {
                        error = Failure::Post(Box::new(error), Box::new(post));
                    }
                }
                Err(error)
            }
        }
    }
    pub fn close(self, checks: &Checks) -> Result<()> {
        let mut result = Ok(());
        for local in self.objects.into_iter().chain([self.anchor]) {
            result = finish(
                result,
                unsafe { ffi::delete_local(checks.env, local) }.map_err(|e| checks.ffi(e)),
            );
        }
        result
    }
    fn lookup(&self, checks: &Checks) -> Result<u64> {
        let candidates = {
            let state = ROOTS.lock().map_err(|_| Failure::Unavailable)?;
            if state.closed || state.active != 1 {
                return Err(Failure::Unavailable);
            }
            state
                .entries
                .iter()
                .filter(|entry| entry.anchor != 0)
                .map(|entry| (entry.serial, entry.anchor, entry.class, entry.correlation))
                .collect::<Vec<_>>()
        };
        let mut selected = None;
        for (serial, anchor, class, correlation) in candidates {
            if unsafe { ffi::same_object(checks.env, self.anchor, anchor as jobject) }
                .map_err(|e| checks.ffi(e))?
            {
                if selected.is_some() || class != self.class || correlation != self.correlation {
                    return Err(Failure::Changed);
                }
                selected = Some(serial);
            }
        }
        selected.ok_or(Failure::Unavailable)
    }
}

/// Slot reservation precedes even creation of the pack directory. The actual
/// root is later moved into this slot; an empty slot is no identity evidence.
pub(super) struct Reservation {
    serial: u64,
}
impl Reservation {
    pub fn reserve(checks: &Checks, bindings: &Bindings, bundle: &[u8; 32]) -> Result<Self> {
        if &bindings.correlation[1] != bundle {
            return Err(Failure::Changed);
        }
        // Verify the loader image before retaining any object or filesystem
        // effect. The single process pin is distinct from eight root anchors.
        crate::library_lifetime::ensure().map_err(Failure::Lifetime)?;
        let serial = {
            let mut state = ROOTS.lock().map_err(|_| Failure::Unavailable)?;
            if state.closed || state.active != 1 || state.entries.len() >= MAX_ROOTS {
                return Err(Failure::Busy);
            }
            let serial = state.next;
            state.next = state.next.checked_add(1).ok_or(Failure::Unavailable)?;
            state.entries.push(Record {
                serial,
                anchor: 0,
                class: bindings.class,
                correlation: bindings.correlation,
                root: None,
                facts: HeldFacts {
                    state: 1,
                    ..HeldFacts::default()
                },
                close_errors: Vec::new(),
                global_release_error: None,
            });
            serial
        };
        let global =
            unsafe { ffi::new_global(checks.env, bindings.anchor) }.map_err(|e| checks.ffi(e));
        // A poisoned registry still owns this exact reservation. Preserve the
        // actual global there before reporting rejection; never lose it into a
        // local integer or delete it while VMDeath may own its lifetime.
        let (mut state, poisoned) = preservation_state();
        let record = state
            .entries
            .iter_mut()
            .find(|entry| entry.serial == serial)
            .ok_or(Failure::Unavailable)?;
        match global {
            Ok(global) => {
                record.anchor = global as usize;
            }
            Err(error) => {
                state.entries.retain(|entry| entry.serial != serial);
                return Err(error);
            }
        }
        if state.closed || poisoned {
            return Err(Failure::Unavailable);
        }
        Ok(Self { serial })
    }
    pub fn install(
        &self,
        root: HeldDirectory,
        checks: &Checks,
        bindings: &Bindings,
    ) -> Result<Arc<HeldDirectory>> {
        let grade = match root.identity_evidence() {
            DirectoryIdentityEvidence::WindowsCreateReturnedHandle => 1,
            DirectoryIdentityEvidence::PosixCooperative => 2,
            DirectoryIdentityEvidence::WindowsOpenedHandle => 0,
        };
        let root = Arc::new(root);
        let poisoned = {
            let (mut state, poisoned) = preservation_state();
            let record = state
                .entries
                .iter_mut()
                .find(|entry| entry.serial == self.serial)
                .ok_or(Failure::Unavailable)?;
            if record.root.is_some() {
                return Err(Failure::Changed);
            }
            record.root = Some(root.clone());
            record.facts = HeldFacts {
                state: 2,
                grade,
                ..HeldFacts::default()
            };
            poisoned
        };
        if poisoned {
            return Err(Failure::Unavailable);
        }
        if grade == 0 {
            return Err(Failure::Changed);
        }
        // Root ownership is already native-retained if either Java callback or
        // response allocation fails. No descendant is written until the actual
        // original Attempt field is read back as this exact registered object.
        let class =
            unsafe { ffi::object_class(checks.env, checks.port) }.map_err(|e| checks.ffi(e))?;
        let publish = (|| {
            let method = unsafe { ffi::method_id(checks.env, class, c"onRootHeld", c"()V") }
                .map_err(|e| checks.ffi(e))?;
            unsafe { ffi::call_void_zero(checks.env, checks.port, method) }
                .map_err(|e| checks.ffi(e))?;
            let held = object(checks, checks.port, c"nativeHeldAnchor")?;
            let same = unsafe { ffi::same_object(checks.env, held, bindings.anchor) }
                .map_err(|e| checks.ffi(e));
            let same = finish(
                same,
                unsafe { ffi::delete_local(checks.env, held) }.map_err(|e| checks.ffi(e)),
            )?;
            if !same {
                return Err(Failure::Changed);
            }
            checks.check()
        })();
        finish(
            publish,
            unsafe { ffi::delete_local(checks.env, class) }.map_err(|e| checks.ffi(e)),
        )?;
        let mut state = ROOTS.lock().map_err(|_| Failure::Unavailable)?;
        if state.closed {
            return Err(Failure::Unavailable);
        }
        let record = state
            .entries
            .iter_mut()
            .find(|entry| entry.serial == self.serial)
            .ok_or(Failure::Unavailable)?;
        record.facts.state = 3;
        Ok(root)
    }
    pub fn completed(&self) -> Result<()> {
        let (mut state, _poisoned) = preservation_state();
        if state.closed {
            return Err(Failure::Unavailable);
        }
        let record = state
            .entries
            .iter_mut()
            .find(|entry| entry.serial == self.serial)
            .ok_or(Failure::Unavailable)?;
        if record.facts.state != 3 {
            return Err(Failure::Changed);
        }
        record.facts.state = 4;
        Ok(())
    }
}

pub(super) fn observe(
    checks: &Checks,
    bindings: &Bindings,
    selected: &Path,
    facts: &mut HeldFacts,
) -> Result<()> {
    let serial = bindings.lookup(checks)?;
    let root = {
        let state = ROOTS.lock().map_err(|_| Failure::Unavailable)?;
        let record = state
            .entries
            .iter()
            .find(|entry| entry.serial == serial)
            .ok_or(Failure::Unavailable)?;
        *facts = record.facts;
        record.root.clone().ok_or(Failure::Unavailable)?
    };
    checks.check()?;
    let same = root.matches_selected_root(selected, checks)?;
    checks.check()?;
    facts.identity = if same { 1 } else { 2 };
    if same { Ok(()) } else { Err(Failure::Changed) }
}

// This control closes only already-owned descriptors. It grants no path read,
// write, callback or source authority and cannot be cancelled into Drop-only
// cleanup. Native close errors remain their original typed io::Error values.
struct NativeClose;
impl Control for NativeClose {
    type Error = io::Error;
    fn check(&self) -> io::Result<()> {
        Ok(())
    }
    fn io_error(&self, error: io::Error) -> io::Error {
        error
    }
    fn unsafe_selection(&self) -> io::Error {
        io::Error::other("native root close selection unavailable")
    }
    fn changed(&self) -> io::Error {
        io::Error::other("native root close ownership changed")
    }
    fn with_post_failure(&self, primary: io::Error, _post: io::Error) -> io::Error {
        // No check fails in NativeClose and no operation invokes io(). The
        // shared drain API reports each individual close error independently.
        primary
    }
}

fn close_record(serial: u64) -> Result<HeldFacts> {
    let (root, prior, initial_poisoned) = {
        let (mut state, poisoned) = preservation_state();
        let record = state
            .entries
            .iter_mut()
            .find(|entry| entry.serial == serial)
            .ok_or(Failure::Unavailable)?;
        if matches!(record.facts.state, 6..=8) {
            return Ok(record.facts);
        }
        // Another drain owns the taken root until its complete close report is
        // stored. An empty slot in that interval proves no physical close.
        if record.facts.state == 5 {
            return Err(Failure::Busy);
        }
        let prior = record.facts.state;
        record.facts.state = 5;
        (record.root.take(), prior, poisoned)
    };
    let Some(root) = root else {
        let (mut state, poisoned) = preservation_state();
        let record = state
            .entries
            .iter_mut()
            .find(|entry| entry.serial == serial)
            .ok_or(Failure::Unavailable)?;
        record.facts.state = 6;
        return if initial_poisoned || poisoned {
            Err(Failure::Unavailable)
        } else {
            Ok(record.facts)
        };
    };
    let root = match Arc::try_unwrap(root) {
        Ok(root) => root,
        Err(root) => {
            let (mut state, _poisoned) = preservation_state();
            let record = state
                .entries
                .iter_mut()
                .find(|entry| entry.serial == serial)
                .ok_or(Failure::Unavailable)?;
            record.root = Some(root);
            record.facts.state = prior;
            return Err(Failure::Busy);
        }
    };
    let report = root.close_retained(&NativeClose);
    let closed = report.all_pins_closed();
    let (mut state, poisoned) = preservation_state();
    let record = state
        .entries
        .iter_mut()
        .find(|entry| entry.serial == serial)
        .ok_or(Failure::Unavailable)?;
    record.facts = HeldFacts {
        state: if closed { 6 } else { 7 },
        grade: record.facts.grade,
        identity: 0,
        pins: report.pins as u16,
        closed: report.closed as u16,
        shared: report.shared as u16,
        uncertain: report.native_close_uncertain as u16,
    };
    record
        .close_errors
        .extend(report.failures.into_iter().map(|failure| {
            Arc::new(RetainedCloseCause {
                pin: failure.pin,
                stage: failure.stage,
                error: failure.error,
            })
        }));
    if initial_poisoned || poisoned {
        Err(Failure::Unavailable)
    } else {
        Ok(record.facts)
    }
}
pub(super) fn retire(checks: &Checks, bindings: &Bindings, facts: &mut HeldFacts) -> Result<()> {
    let serial = bindings.lookup(checks)?;
    let initial = checks.check();
    let result = close_record(serial);
    let mut result = match result {
        Ok(observed) => {
            *facts = observed;
            Ok(())
        }
        Err(error) => Err(error),
    };
    let (errors, post) = {
        let (state, poisoned) = preservation_state();
        match state.entries.iter().find(|entry| entry.serial == serial) {
            Some(record) => {
                *facts = record.facts;
                (
                    record.close_errors.clone(),
                    if poisoned {
                        Err(Failure::Unavailable)
                    } else {
                        Ok(())
                    },
                )
            }
            None => (Vec::new(), Err(Failure::Unavailable)),
        }
    };
    for error in errors {
        result = finish(result, Err(Failure::RetainedIo(error)));
    }
    result = finish(result, post);
    let result = finish(initial, result);
    finish(result, checks.check())
}

/// Called from the actual VMDeath event while its event env is valid. Active
/// native frames keep all eight anchors VM-owned until destruction; no JNI is
/// attempted by their later Drop. No Java callback is executed here.
pub(super) unsafe fn vm_death(env: *mut JNIEnv) {
    let drain = if let Ok(mut state) = ROOTS.lock() {
        state.closed = true;
        state.active == 0
    } else {
        false
    };
    if drain {
        drain_native(Some(env));
    }
}
/// AgentUnload may follow VM destruction. This path uses native close only.
pub(super) fn on_unload() {
    let drain = if let Ok(mut state) = ROOTS.lock() {
        state.closed = true;
        state.active == 0
    } else {
        false
    };
    if drain {
        drain_native(None);
    }
}
fn drain_native(env: Option<*mut JNIEnv>) {
    let serials = match ROOTS.lock() {
        Ok(mut state) if state.active == 0 && !state.draining => {
            state.draining = true;
            state
                .entries
                .iter()
                .map(|entry| entry.serial)
                .collect::<Vec<_>>()
        }
        _ => return,
    };
    for serial in serials {
        let _actual = close_record(serial);
        let anchor = if let Ok(mut state) = ROOTS.lock() {
            let Some(record) = state
                .entries
                .iter_mut()
                .find(|entry| entry.serial == serial)
            else {
                continue;
            };
            if env.is_none() || record.global_release_error.is_some() {
                record.facts.state = 8;
                0
            } else {
                record.anchor
            }
        } else {
            0
        };
        if anchor != 0 {
            // SAFETY: only the actual VMDeath event supplies this event env.
            // The registry owns this one actual NewGlobalRef and has no reader.
            if let Some(env) = env {
                let actual = unsafe { ffi::delete_global(env, anchor as jobject) };
                if let Ok(mut state) = ROOTS.lock()
                    && let Some(record) = state
                        .entries
                        .iter_mut()
                        .find(|entry| entry.serial == serial)
                {
                    match actual {
                        Ok(()) => record.anchor = 0,
                        Err(error) => {
                            // ffi::delete_global rejects before the void JNI
                            // call when its table entry cannot be acquired.
                            // Keep the actual ref VM-owned, never claim release.
                            record.global_release_error = Some(error);
                            record.facts.state = 8;
                        }
                    }
                }
            }
        }
    }
    if let Ok(mut state) = ROOTS.lock() {
        state.draining = false;
    }
}

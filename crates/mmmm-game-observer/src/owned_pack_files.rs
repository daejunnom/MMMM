//! Actual platform-issued, one-call owned-file consumer. No path is accepted in
//! the source bundle. Filesystem selection comes only from the private Fabric
//! port, under its original request/context checks. No grant or reload is issued.

use crate::{
    ffi::{self, JNIEnv, jmethodID, jobject},
    native_producer,
};
use mmmm_compiler::calibration_dispatch::CalibrationDispatchPlan;
use mmmm_owned_files::{Control, FileFacts, HeldDirectory};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    collections::BTreeMap,
    ffi::OsStr,
    io,
    path::PathBuf,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

const PACK: &str = "mmmm-calibration-normative47";
const MAX_BYTES: usize = 1024 * 1024;
const MAX_FRAME: usize = MAX_BYTES + 48 * 280 + 42;
const REQUIRED_STATUS: i32 = 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128;
static ACTIVE: AtomicBool = AtomicBool::new(false);

enum Failure {
    Invalid,
    Unavailable,
    Busy,
    Changed,
    Io(io::Error),
    Checkpoint(jobject),
    Post(Box<Failure>, Box<Failure>),
    Panic,
}
type Result<T> = std::result::Result<T, Failure>;
struct Active;
impl Drop for Active {
    fn drop(&mut self) {
        ACTIVE.store(false, Ordering::Release);
    }
}

struct Checks {
    env: *mut JNIEnv,
    port: jobject,
    method: jmethodID,
    status: i32,
    token: native_producer::OwnedFilePortToken,
    effects: Cell<bool>,
}
impl Checks {
    fn ffi(&self, error: ffi::FfiError) -> Failure {
        // SAFETY: only this JNI frame's actual pending Throwable is cleared and
        // retained as a local ref. It is returned to Java in the same call.
        let actual = unsafe { ffi::take_exception(self.env) }.unwrap_or(ptr::null_mut());
        if !actual.is_null() {
            Failure::Checkpoint(actual)
        } else {
            let _ = error;
            Failure::Unavailable
        }
    }
    fn text(&self, method: jmethodID) -> Result<Vec<u16>> {
        // SAFETY: exact private zero-argument String method on this live port.
        let string = unsafe { ffi::call_object_zero(self.env, self.port, method) }
            .map_err(|e| self.ffi(e))?;
        // SAFETY: returned String local reference belongs to this frame.
        let result = unsafe { ffi::string_utf16(self.env, string, 4096) }.map_err(|e| self.ffi(e));
        // SAFETY: releases only this local reference, after the original result.
        let close = unsafe { ffi::delete_local(self.env, string) }.map_err(|e| self.ffi(e));
        finish(result, close)
    }
}
impl Control for Checks {
    type Error = Failure;
    fn check(&self) -> Result<()> {
        if !self.token.is_current()
            || native_producer::status() != self.status
            || self.status < 0
            || self.status & REQUIRED_STATUS != REQUIRED_STATUS
            || native_producer::owned_files_vm().is_null()
        {
            return Err(Failure::Unavailable);
        }
        // SAFETY: the original private Fabric port and method remain local and
        // live. No Rust mutex is held while the original Java check executes.
        unsafe { ffi::call_void_zero(self.env, self.port, self.method) }
            .map_err(|e| self.ffi(e))?;
        if !self.token.is_current() || native_producer::status() != self.status {
            return Err(Failure::Unavailable);
        }
        Ok(())
    }
    fn io_error(&self, error: io::Error) -> Failure {
        Failure::Io(error)
    }
    fn unsafe_selection(&self) -> Failure {
        Failure::Invalid
    }
    fn changed(&self) -> Failure {
        Failure::Changed
    }
    fn with_post_failure(&self, primary: Failure, post: Failure) -> Failure {
        Failure::Post(Box::new(primary), Box::new(post))
    }
}
fn finish<T>(primary: Result<T>, after: Result<()>) -> Result<T> {
    match (primary, after) {
        (Err(primary), Err(after)) => Err(Failure::Post(Box::new(primary), Box::new(after))),
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

struct Entry {
    path: String,
    bytes: Vec<u8>,
    sha256: [u8; 32],
}
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(size)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(Failure::Invalid)?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<usize> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| Failure::Invalid)?) as usize)
    }
    fn u32(&mut self) -> Result<usize> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| Failure::Invalid)?) as usize)
    }
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}
fn entries(frame: &[u8], checks: &Checks) -> Result<Vec<Entry>> {
    decode_entries(frame, &|| checks.check())
}
fn decode_entries(frame: &[u8], check: &impl Fn() -> Result<()>) -> Result<Vec<Entry>> {
    check()?;
    let mut read = Cursor {
        bytes: frame,
        offset: 0,
    };
    if read.take(8)? != b"MMMMPK01" {
        return Err(Failure::Invalid);
    }
    let digest: [u8; 32] = read.take(32)?.try_into().map_err(|_| Failure::Invalid)?;
    if read.u16()? != 48 {
        return Err(Failure::Invalid);
    }
    let expected = CalibrationDispatchPlan::normative47().map_err(|_| Failure::Invalid)?;
    if expected.source_entries().len() != 48 {
        return Err(Failure::Invalid);
    }
    let mut total = 0usize;
    let mut result = Vec::with_capacity(48);
    let mut canonical = Vec::<Value>::with_capacity(48);
    for (expected_path, expected_bytes) in expected.source_entries() {
        check()?;
        let length = read.u16()?;
        if length == 0 || length > 240 {
            return Err(Failure::Invalid);
        }
        let path = std::str::from_utf8(read.take(length)?)
            .map_err(|_| Failure::Invalid)?
            .to_owned();
        let size = read.u32()?;
        total = total
            .checked_add(size)
            .filter(|v| *v <= MAX_BYTES)
            .ok_or(Failure::Invalid)?;
        if size == 0 || size > 65536 {
            return Err(Failure::Invalid);
        }
        let sha256: [u8; 32] = read.take(32)?.try_into().map_err(|_| Failure::Invalid)?;
        let bytes = read.take(size)?.to_vec();
        // Comparing a received bundle to the sealed recipe is not generating a
        // replacement. Only the received, exactly matched original bytes write.
        if &path != expected_path
            || &bytes != expected_bytes
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != sha256
        {
            return Err(Failure::Invalid);
        }
        canonical.push(json!({"path":path,"rawSha256":hex(&sha256),"byteLength":size,"rawBytesHex":hex(&bytes)}));
        result.push(Entry {
            path,
            bytes,
            sha256,
        });
    }
    if read.offset != frame.len()
        || mmmm_contracts::canonical_digest(&Value::Array(canonical))
            .map_err(|_| Failure::Invalid)?
            .to_bytes()
            != digest
    {
        return Err(Failure::Invalid);
    }
    check()?;
    Ok(result)
}

fn path(units: Vec<u16>) -> Result<PathBuf> {
    if units.contains(&0) {
        return Err(Failure::Invalid);
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        Ok(std::ffi::OsString::from_wide(&units).into())
    }
    #[cfg(not(windows))]
    {
        Ok(PathBuf::from(
            String::from_utf16(&units).map_err(|_| Failure::Invalid)?,
        ))
    }
}
fn create(
    root: &HeldDirectory,
    entries: &[Entry],
    checks: &Checks,
) -> Result<Vec<(String, FileFacts)>> {
    // All acquired children are consumed/closed in reverse dependency order.
    // Failed or partial creations are preserved; Drop never deletes a child.
    checks.effects.set(true);
    let pack = root.create_directory_new(OsStr::new(PACK), checks)?;
    let mut directories = BTreeMap::<String, HeldDirectory>::new();
    let mut facts = Vec::with_capacity(48);
    let result = (|| {
        for entry in entries {
            checks.check()?;
            let components = entry.path.split('/').collect::<Vec<_>>();
            let mut parent = String::new();
            for component in &components[..components.len() - 1] {
                let key = if parent.is_empty() {
                    (*component).to_owned()
                } else {
                    format!("{parent}/{component}")
                };
                if !directories.contains_key(&key) {
                    if directories.len() >= 64 {
                        return Err(Failure::Invalid);
                    }
                    let holder = if parent.is_empty() {
                        &pack
                    } else {
                        directories.get(&parent).ok_or(Failure::Invalid)?
                    };
                    let created = holder.create_directory_new(OsStr::new(component), checks)?;
                    directories.insert(key.clone(), created);
                }
                parent = key;
            }
            let holder = if parent.is_empty() {
                &pack
            } else {
                directories.get(&parent).ok_or(Failure::Invalid)?
            };
            let mut file = holder.create_file_new(
                OsStr::new(components.last().ok_or(Failure::Invalid)?),
                entry.bytes.len() as u64,
                checks,
            )?;
            let observed = (|| {
                file.write_all(&entry.bytes, checks)?;
                let value = file.verify_original(&entry.bytes, checks)?;
                if value.sha256 != entry.sha256 {
                    return Err(Failure::Changed);
                }
                Ok(value)
            })();
            let value = finish(observed, file.close(checks))?;
            facts.push((entry.path.clone(), value));
        }
        pack.revalidate(checks)?;
        root.revalidate(checks)?;
        Ok(facts)
    })();
    let mut result = result;
    for (_, directory) in directories.into_iter().rev() {
        result = finish(result, directory.close(checks));
    }
    finish(result, pack.close(checks))
}

fn run(
    env: *mut JNIEnv,
    bridge: jobject,
    port: jobject,
    frame: jobject,
    operation: i32,
    effects: &Cell<bool>,
) -> Result<Vec<(String, FileFacts)>> {
    if !(0..=2).contains(&operation) || port.is_null() {
        return Err(Failure::Invalid);
    }
    if ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(Failure::Busy);
    }
    let _active = Active;
    let status = native_producer::status();
    let vm = native_producer::owned_files_vm();
    if status < 0 || status & REQUIRED_STATUS != REQUIRED_STATUS || vm.is_null() {
        return Err(Failure::Unavailable);
    }
    // SAFETY: all references and methods are used within the original JNI call.
    let class = unsafe { ffi::object_class(env, port) }.map_err(|_| Failure::Unavailable)?;
    let setup = (|| {
        if unsafe { ffi::class_signature(vm, class) }.map_err(|_| Failure::Unavailable)?
            != b"Lio/github/daejunnom/mmmm/fabric/NativeCalibrationPackFiles$NativeCall;"
        {
            return Err(Failure::Invalid);
        }
        let method = unsafe { ffi::method_id(env, class, c"checkpoint", c"()V") }
            .map_err(|_| Failure::Unavailable)?;
        let root = unsafe { ffi::method_id(env, class, c"nativeRoot", c"()Ljava/lang/String;") }
            .map_err(|_| Failure::Unavailable)?;
        let relative =
            unsafe { ffi::method_id(env, class, c"nativeRelative", c"()Ljava/lang/String;") }
                .map_err(|_| Failure::Unavailable)?;
        let checkpoint = || {
            // SAFETY: invoked only after the producer has joined this exact
            // actual port to its original host/game loader and current Classes.
            unsafe { ffi::call_void_zero(env, port, method) }
        };
        let token = unsafe { native_producer::owned_file_port(env, bridge, class, &checkpoint) }
            .map_err(|_| Failure::Unavailable)?
            .ok_or(Failure::Unavailable)?;
        Ok((method, root, relative, token))
    })();
    // SAFETY: this is only the acquired local Class reference.
    let release = unsafe { ffi::delete_local(env, class) }.map_err(|_| Failure::Unavailable);
    let (method, root_method, relative_method, token) = finish(setup, release)?;
    let checks = Checks {
        env,
        port,
        method,
        status,
        token,
        effects: Cell::new(false),
    };
    let result = (|| {
        checks.check()?;
        let data =
            unsafe { ffi::whole_byte_array(env, frame, MAX_FRAME) }.map_err(|e| checks.ffi(e))?;
        let entries = if operation == 2 {
            if !data.is_empty() {
                return Err(Failure::Invalid);
            }
            Vec::new()
        } else {
            entries(&data, &checks)?
        };
        let selected = path(checks.text(root_method)?)?;
        let relative =
            String::from_utf16(&checks.text(relative_method)?).map_err(|_| Failure::Invalid)?;
        if operation != 2 && relative != PACK {
            return Err(Failure::Invalid);
        }
        let root = HeldDirectory::open_root(&selected, &checks)?;
        let result = if operation == 1 {
            create(&root, &entries, &checks)
        } else {
            // Storage's caller is the actual private SavedDataStorage issuer.
            // Nested existing-parent walking is supplied by the shared kernel.
            if relative.contains('\\') {
                Err(Failure::Invalid)
            } else {
                let components = relative.split('/').map(OsStr::new).collect::<Vec<_>>();
                root.require_descendant_absent(&components, &checks)
                    .map(|()| Vec::new())
            }
        };
        finish(result, root.close(&checks))
    })();
    effects.set(checks.effects.get());
    finish(result, checks.check())
}

fn encode_failure(error: Failure, bytes: &mut Vec<u8>, refs: &mut Vec<jobject>) {
    match error {
        Failure::Post(primary, post) => {
            bytes.push(7);
            encode_failure(*primary, bytes, refs);
            encode_failure(*post, bytes, refs);
        }
        Failure::Io(error) => {
            bytes.push(5);
            optional_i32(bytes, mmmm_owned_files::native_os_error(&error));
            #[cfg(windows)]
            let native = error
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<mmmm_owned_files::NativeCreateFailure>());
            #[cfg(windows)]
            if let Some(native) = native {
                bytes.push(1);
                bytes.extend_from_slice(&native.nt_status().to_be_bytes());
                optional_i32(bytes, native.completion_status());
                bytes.push(u8::from(native.information().is_some()));
                if let Some(value) = native.information() {
                    bytes.extend_from_slice(&(value as u64).to_be_bytes());
                }
                optional_i32(
                    bytes,
                    native.close_error().and_then(io::Error::raw_os_error),
                );
            } else {
                bytes.push(0);
            }
            #[cfg(not(windows))]
            bytes.push(0);
        }
        Failure::Checkpoint(actual) => {
            bytes.push(6);
            bytes.extend_from_slice(&(refs.len() as u16).to_be_bytes());
            refs.push(actual);
        }
        Failure::Invalid => bytes.push(1),
        Failure::Unavailable => bytes.push(2),
        Failure::Busy => bytes.push(3),
        Failure::Changed => bytes.push(4),
        Failure::Panic => bytes.push(8),
    }
}

fn optional_i32(bytes: &mut Vec<u8>, value: Option<i32>) {
    bytes.push(u8::from(value.is_some()));
    if let Some(value) = value {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
}

/// Returns a bounded binary receipt plus the original Java Throwable localrefs.
/// No native filesystem handle or request witness is retained after this call.
pub(crate) unsafe fn call(
    env: *mut JNIEnv,
    bridge: jobject,
    port: jobject,
    frame: jobject,
    operation: i32,
) -> jobject {
    let effects = Cell::new(false);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run(env, bridge, port, frame, operation, &effects)
    }))
    .unwrap_or_else(|_| {
        effects.set(true);
        Err(Failure::Panic)
    });
    let mut bytes = b"MMMMPKR1".to_vec();
    bytes.push(u8::from(effects.get()));
    let mut refs = Vec::new();
    let failed = result.is_err();
    match result {
        Ok(facts) => {
            bytes.push(0);
            bytes.extend_from_slice(&(facts.len() as u16).to_be_bytes());
            for (path, fact) in facts {
                bytes.extend_from_slice(&(path.len() as u16).to_be_bytes());
                bytes.extend_from_slice(path.as_bytes());
                bytes.extend_from_slice(&fact.length.to_be_bytes());
                bytes.extend_from_slice(&fact.sha256);
            }
        }
        Err(error) => {
            bytes.push(1);
            encode_failure(error, &mut bytes, &mut refs);
        }
    }
    // Preserve a setup JNI failure as its actual Throwable too. A failed reply
    // allocation leaves the VM's exception pending and cannot become success.
    let pending = unsafe { ffi::take_exception(env) }.unwrap_or(ptr::null_mut());
    if !pending.is_null() {
        let primary = bytes.split_off(10);
        bytes[9] = 1;
        bytes.push(7);
        if failed {
            bytes.extend_from_slice(&primary);
        } else {
            bytes.push(2);
        }
        bytes.push(6);
        bytes.extend_from_slice(&(refs.len() as u16).to_be_bytes());
        refs.push(pending);
    }
    let array = unsafe { ffi::byte_array(env, &bytes) };
    let Ok(array) = array else {
        return ptr::null_mut();
    };
    let mut values = Vec::with_capacity(refs.len() + 1);
    values.push(array);
    values.extend(refs);
    unsafe { ffi::object_array(env, &values) }.unwrap_or(ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reuses the actual sealed compiler recipe. This is a pure transport test,
    // not an installed JVM, game, path authority or filesystem effect fixture.
    fn source_frame() -> Vec<u8> {
        let plan = CalibrationDispatchPlan::normative47().expect("sealed recipe");
        let projection = Value::Array(plan.source_entries().iter().map(|(path, bytes)| {
            json!({"path":path,"rawSha256":hex(&Sha256::digest(bytes)),"byteLength":bytes.len(),"rawBytesHex":hex(bytes)})
        }).collect());
        let mut frame = b"MMMMPK01".to_vec();
        frame.extend_from_slice(
            &mmmm_contracts::canonical_digest(&projection)
                .expect("canonical entries")
                .to_bytes(),
        );
        frame.extend_from_slice(&48u16.to_be_bytes());
        for (path, bytes) in plan.source_entries() {
            frame.extend_from_slice(&(path.len() as u16).to_be_bytes());
            frame.extend_from_slice(path.as_bytes());
            frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            frame.extend_from_slice(&Sha256::digest(bytes));
            frame.extend_from_slice(bytes);
        }
        frame
    }
    #[test]
    fn only_original_sealed_48_entry_bundle_decodes() {
        let frame = source_frame();
        let entries =
            decode_entries(&frame, &|| Ok(())).unwrap_or_else(|_| panic!("original sealed frame"));
        let plan = CalibrationDispatchPlan::normative47().expect("sealed recipe");
        assert_eq!(entries.len(), 48);
        for (actual, (path, bytes)) in entries.iter().zip(plan.source_entries()) {
            assert_eq!(&actual.path, path);
            assert_eq!(&actual.bytes, bytes);
        }
        for length in [0, 8, 40, 41, frame.len() - 1] {
            assert!(matches!(
                decode_entries(&frame[..length], &|| Ok(())),
                Err(Failure::Invalid)
            ));
        }
        let mut extra = frame.clone();
        extra.push(0);
        assert!(matches!(
            decode_entries(&extra, &|| Ok(())),
            Err(Failure::Invalid)
        ));
    }
    #[test]
    fn changed_digest_roster_source_and_oversize_do_not_receive_facts() {
        let original = source_frame();
        for index in [8, 41, 44, original.len() - 1] {
            let mut changed = original.clone();
            changed[index] ^= 1;
            assert!(matches!(
                decode_entries(&changed, &|| Ok(())),
                Err(Failure::Invalid)
            ));
        }
        let path_length = u16::from_be_bytes([original[42], original[43]]) as usize;
        let mut oversized = original;
        oversized[44 + path_length..48 + path_length].copy_from_slice(&65537u32.to_be_bytes());
        assert!(matches!(
            decode_entries(&oversized, &|| Ok(())),
            Err(Failure::Invalid)
        ));
    }
    #[test]
    fn original_checkpoint_aborts_bundle_before_any_filesystem_port() {
        let count = Cell::new(0);
        let result = decode_entries(&source_frame(), &|| {
            count.set(count.get() + 1);
            if count.get() == 4 {
                Err(Failure::Changed)
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(Failure::Changed)));
        assert_eq!(count.get(), 4);
    }
    #[test]
    fn primary_io_and_original_post_checkpoint_keep_separate_typed_causes() {
        let actual = ptr::dangling_mut::<std::ffi::c_void>();
        let result: Result<()> = finish(
            Err(Failure::Io(io::Error::from_raw_os_error(5))),
            Err(Failure::Checkpoint(actual)),
        );
        let Err(Failure::Post(primary, post)) = result else {
            panic!("both original causes required");
        };
        assert!(matches!(*primary, Failure::Io(ref error) if error.raw_os_error() == Some(5)));
        assert!(matches!(*post, Failure::Checkpoint(value) if value == actual));
        let mut bytes = Vec::new();
        let mut references = Vec::new();
        encode_failure(Failure::Post(primary, post), &mut bytes, &mut references);
        assert_eq!(bytes[0], 7);
        assert_eq!(bytes[1], 5);
        assert_eq!(references, [actual]);
    }
    #[test]
    fn path_transport_rejects_embedded_nul_without_lossy_decoding() {
        assert!(matches!(
            path(vec![b'C' as u16, 0, b'x' as u16]),
            Err(Failure::Invalid)
        ));
        #[cfg(not(windows))]
        assert!(matches!(path(vec![0xd800]), Err(Failure::Invalid)));
    }
}

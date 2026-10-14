// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
//! JDK 25 JNI/JVMTI ABI subset with three explicit 64-bit little-endian targets.
//!
//! Source declarations are independently expressed, not a bundled generated header.
//! Functional ABI facts are referenced; no upstream implementation or generated
//! header is copied. jni.h and platform jni_md.h carry GPLv2 + Classpath exception;
//! jvmti.xml and jvmtiH.xsl source headers carry GPLv2 (generated jvmti.h's
//! template uses GPL_CP_Header). Those upstream files are not bundled here.
//! Primary definitions:
//! https://github.com/openjdk/jdk/blob/jdk-25-ga/src/java.base/share/native/include/jni.h
//! https://github.com/openjdk/jdk/blob/jdk-25-ga/src/java.base/windows/native/include/jni_md.h
//! https://github.com/openjdk/jdk/blob/jdk-25-ga/src/java.base/unix/native/include/jni_md.h
//! https://github.com/openjdk/jdk/blob/jdk-25-ga/src/hotspot/share/prims/jvmti.xml
//! https://github.com/adoptium/jdk25u/blob/jdk-25.0.4.1%2B1/src/java.base/share/native/include/jni.h
//! https://docs.oracle.com/en/java/javase/25/docs/specs/jni/functions.html
//! https://docs.oracle.com/en/java/javase/25/docs/specs/jvmti.html#FunctionTable
//!
//! JNI indices are zero based. JVMTI positions are one based and are explicitly
//! decremented below. JDK 25's JNICALL is empty; these functions use the C ABI.
//! No legacy Windows stdcall assumption is made.

#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_void};
use std::ptr;

pub(crate) type jint = i32;
pub(crate) type jboolean = u8;
pub(crate) type jbyte = i8;
pub(crate) type jobject = *mut c_void;
pub(crate) type jclass = jobject;
pub(crate) type jthread = jobject;
pub(crate) type jstring = jobject;
pub(crate) type jbyteArray = jobject;
pub(crate) type jmethodID = *mut c_void;

#[repr(C)]
pub(crate) struct JNIEnv {
    pub(crate) functions: *const *const c_void,
}
#[repr(C)]
pub(crate) struct JavaVM {
    pub(crate) functions: *const *const c_void,
}
#[repr(C)]
pub(crate) struct JvmtiEnv {
    pub(crate) functions: *const *const c_void,
}

/// A compile-target calling convention, never a VM source or target-policy grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartupAbi {
    WindowsX64Msvc,
    LinuxX64Gnu,
    MacOsArm64Darwin,
}
impl StartupAbi {
    pub(crate) const fn startup_options(self) -> &'static [u8] {
        match self {
            Self::WindowsX64Msvc => b"jdk25-windows-x64-msvc-controlled-startup-v1",
            Self::LinuxX64Gnu => b"jdk25-linux-x64-gnu-controlled-startup-v1",
            Self::MacOsArm64Darwin => b"jdk25-macos-arm64-darwin-controlled-startup-v1",
        }
    }

    pub(crate) fn accepts_options(self, options: &[u8]) -> bool {
        options == self.startup_options()
    }
}

// These layout properties are necessary but not an exact target identity.
// arm64e-apple-darwin shares Darwin ARM64's ordinary Rust cfg tuple. The Cargo
// target captured by the owned build script must independently match below.
const COMPILED_LAYOUT_ABI: Option<StartupAbi> = if cfg!(all(
    target_os = "windows",
    target_vendor = "pc",
    target_arch = "x86_64",
    target_env = "msvc",
    target_abi = "",
    target_pointer_width = "64",
    target_endian = "little"
)) {
    Some(StartupAbi::WindowsX64Msvc)
} else if cfg!(all(
    target_os = "linux",
    target_vendor = "unknown",
    target_arch = "x86_64",
    target_env = "gnu",
    target_abi = "",
    target_pointer_width = "64",
    target_endian = "little"
)) {
    Some(StartupAbi::LinuxX64Gnu)
} else if cfg!(all(
    target_os = "macos",
    target_vendor = "apple",
    target_arch = "aarch64",
    target_env = "",
    target_abi = "",
    target_pointer_width = "64",
    target_endian = "little"
)) {
    Some(StartupAbi::MacOsArm64Darwin)
} else {
    None
};

const fn target_name_is(target: &str, expected: &str) -> bool {
    let target = target.as_bytes();
    let expected = expected.as_bytes();
    if target.len() != expected.len() {
        return false;
    }
    let mut index = 0;
    while index < target.len() {
        if target[index] != expected[index] {
            return false;
        }
        index += 1;
    }
    true
}

const fn select_startup_abi(
    target: Option<&str>,
    layout: Option<StartupAbi>,
) -> Option<StartupAbi> {
    let Some(target) = target else {
        return None;
    };
    match layout {
        Some(StartupAbi::WindowsX64Msvc) if target_name_is(target, "x86_64-pc-windows-msvc") => {
            Some(StartupAbi::WindowsX64Msvc)
        }
        Some(StartupAbi::LinuxX64Gnu) if target_name_is(target, "x86_64-unknown-linux-gnu") => {
            Some(StartupAbi::LinuxX64Gnu)
        }
        Some(StartupAbi::MacOsArm64Darwin) if target_name_is(target, "aarch64-apple-darwin") => {
            Some(StartupAbi::MacOsArm64Darwin)
        }
        _ => None,
    }
}

// This build context permits table use only. VM build/source pins, startup
// ordering, capability acquisition and current generations remain separate.
pub(crate) const STARTUP_ABI: Option<StartupAbi> = select_startup_abi(
    option_env!("MMMM_OBSERVER_BUILD_TARGET"),
    COMPILED_LAYOUT_ABI,
);
pub(crate) const ABI_SUPPORTED: bool = STARTUP_ABI.is_some();
pub(crate) const JVMTI_VERSION_25: jint = 0x3019_0000;
pub(crate) const JNI_VERSION_24: jint = 0x0018_0000;
pub(crate) const JNI_OK: jint = 0;
pub(crate) const JNI_ERR: jint = -1;
pub(crate) const PHASE_START: jint = 6;
pub(crate) const PHASE_LIVE: jint = 4;
pub(crate) const ACC_STATIC: jint = 0x0008;
pub(crate) const ACC_NATIVE: jint = 0x0100;
pub(crate) const ACC_ABSTRACT: jint = 0x0400;
pub(crate) const HIDDEN_CLASS: jint = 0x0002;
pub(crate) const CLASS_PREPARED: jint = 0x0002;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FfiError {
    NullInterface,
    MissingFunction,
    Jvmti(jint),
    PendingException,
    BoundExceeded,
    InvalidResult,
}
pub(crate) type Result<T> = std::result::Result<T, FfiError>;

/// The admitted MSVC x64, SysV x64 and Darwin ARM64 ABIs place these unsigned-int
/// fields low-bit first in 32-bit allocation units. 45 one-bit fields + three
/// reserved bits + five unsigned 16-bit fields end at bit 128 without straddling
/// an allocation unit: four uint32 units, alignment 4, size 16. This is a layout
/// declaration; each actual JDK/compiler pair still needs its native ABI check.
/// https://learn.microsoft.com/en-us/cpp/c-language/storage-of-bit-fields
/// https://learn.microsoft.com/en-us/cpp/c-language/c-bit-fields
/// https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions
/// https://gitlab.com/x86-psABIs/x86-64-ABI/-/raw/master/x86-64-ABI/low-level-sys-info.tex
/// https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms
/// https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst#bit-fields-no-larger-than-their-container
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Capabilities {
    words: [u32; 4],
}
impl Capabilities {
    pub(crate) fn required() -> Self {
        let mut value = Self::default();
        // Declaration ordinals, not JVMTI function-table positions.
        for ordinal in [3, 26, 30, 35, 37, 42] {
            value.words[ordinal / 32] |= 1 << (ordinal % 32);
        }
        value
    }
    pub(crate) fn contains(&self, requested: &Self) -> bool {
        self.words
            .iter()
            .zip(requested.words)
            .all(|(a, b)| a & b == b)
    }
}
const _: [(); 16] = [(); std::mem::size_of::<Capabilities>()];
const _: [(); 4] = [(); std::mem::align_of::<Capabilities>()];

/// jvmtiEventCallbacks includes reserved events 50 through 88: 39 pointer slots.
#[repr(C)]
pub(crate) struct EventCallbacks {
    pub(crate) slots: [*const c_void; 39],
}
impl Default for EventCallbacks {
    fn default() -> Self {
        Self {
            slots: [ptr::null(); 39],
        }
    }
}
#[repr(C)]
pub(crate) struct NativeMethod {
    pub(crate) name: *mut c_char,
    pub(crate) signature: *mut c_char,
    pub(crate) function: *mut c_void,
}

// Validate Rust's chosen layout only for the closed ABI set. These assertions
// neither read the selected VM's headers nor establish native execution.
const _: () = {
    if ABI_SUPPORTED {
        assert!(std::mem::size_of::<*const c_void>() == 8);
        assert!(std::mem::align_of::<*const c_void>() == 8);
        assert!(std::mem::size_of::<JNIEnv>() == 8);
        assert!(std::mem::size_of::<JavaVM>() == 8);
        assert!(std::mem::size_of::<JvmtiEnv>() == 8);
        assert!(std::mem::size_of::<EventCallbacks>() == 312);
        assert!(std::mem::align_of::<EventCallbacks>() == 8);
        assert!(std::mem::size_of::<NativeMethod>() == 24);
        assert!(std::mem::align_of::<NativeMethod>() == 8);
        assert!(std::mem::offset_of!(NativeMethod, name) == 0);
        assert!(std::mem::offset_of!(NativeMethod, signature) == 8);
        assert!(std::mem::offset_of!(NativeMethod, function) == 16);
    }
};

pub(crate) type DefineClass1 = unsafe extern "C" fn(
    *mut JNIEnv,
    jclass,
    jobject,
    jstring,
    jbyteArray,
    jint,
    jint,
    jobject,
    jstring,
) -> jclass;
pub(crate) type DefineClass2 = unsafe extern "C" fn(
    *mut JNIEnv,
    jclass,
    jobject,
    jstring,
    jobject,
    jint,
    jint,
    jobject,
    jstring,
) -> jclass;
pub(crate) type DefineClass0 = unsafe extern "C" fn(
    *mut JNIEnv,
    jclass,
    jobject,
    jclass,
    jstring,
    jbyteArray,
    jint,
    jint,
    jobject,
    jboolean,
    jint,
    jobject,
) -> jclass;

unsafe fn slot(table: *const *const c_void, index: usize) -> Result<*const c_void> {
    if table.is_null() {
        return Err(FfiError::NullInterface);
    }
    // SAFETY: callers only supply a VM-owned interface with the pinned table ABI.
    let function = unsafe { *table.add(index) };
    if function.is_null() {
        Err(FfiError::MissingFunction)
    } else {
        Ok(function)
    }
}
unsafe fn jni(env: *mut JNIEnv, index: usize) -> Result<*const c_void> {
    if env.is_null() {
        return Err(FfiError::NullInterface);
    }
    unsafe { slot((*env).functions, index) }
}
unsafe fn ti(env: *mut JvmtiEnv, position: usize) -> Result<*const c_void> {
    if env.is_null() {
        return Err(FfiError::NullInterface);
    }
    unsafe { slot((*env).functions, position - 1) }
}
fn checked(error: jint) -> Result<()> {
    if error == 0 {
        Ok(())
    } else {
        Err(FfiError::Jvmti(error))
    }
}
macro_rules! jni_fn {
    ($env:expr, $index:expr, $signature:ty) => {
        std::mem::transmute::<*const c_void, $signature>(jni($env, $index)?)
    };
}
macro_rules! ti_fn {
    ($env:expr, $position:expr, $signature:ty) => {
        std::mem::transmute::<*const c_void, $signature>(ti($env, $position)?)
    };
}

pub(crate) unsafe fn get_jvmti(vm: *mut JavaVM) -> Result<*mut JvmtiEnv> {
    if !ABI_SUPPORTED || vm.is_null() {
        return Err(FfiError::NullInterface);
    }
    let function = unsafe { slot((*vm).functions, 6)? };
    let function: unsafe extern "C" fn(*mut JavaVM, *mut *mut c_void, jint) -> jint =
        unsafe { std::mem::transmute(function) };
    let mut out = ptr::null_mut();
    if unsafe { function(vm, &mut out, JVMTI_VERSION_25) } != JNI_OK || out.is_null() {
        return Err(FfiError::InvalidResult);
    }
    Ok(out.cast())
}
pub(crate) unsafe fn version(env: *mut JvmtiEnv) -> Result<jint> {
    let function = unsafe {
        ti_fn!(
            env,
            88,
            unsafe extern "C" fn(*mut JvmtiEnv, *mut jint) -> jint
        )
    };
    let mut value = 0;
    checked(unsafe { function(env, &mut value) })?;
    Ok(value)
}
pub(crate) unsafe fn phase(env: *mut JvmtiEnv) -> Result<jint> {
    let function = unsafe {
        ti_fn!(
            env,
            133,
            unsafe extern "C" fn(*mut JvmtiEnv, *mut jint) -> jint
        )
    };
    let mut value = 0;
    checked(unsafe { function(env, &mut value) })?;
    Ok(value)
}
pub(crate) unsafe fn capabilities(env: *mut JvmtiEnv, potential: bool) -> Result<Capabilities> {
    let position = if potential { 140 } else { 89 };
    let function = unsafe {
        ti_fn!(
            env,
            position,
            unsafe extern "C" fn(*mut JvmtiEnv, *mut Capabilities) -> jint
        )
    };
    let mut value = Capabilities::default();
    checked(unsafe { function(env, &mut value) })?;
    Ok(value)
}
pub(crate) unsafe fn add_capabilities(env: *mut JvmtiEnv, value: &Capabilities) -> Result<()> {
    let function = unsafe {
        ti_fn!(
            env,
            142,
            unsafe extern "C" fn(*mut JvmtiEnv, *const Capabilities) -> jint
        )
    };
    checked(unsafe { function(env, value) })
}
pub(crate) unsafe fn set_callbacks(env: *mut JvmtiEnv, value: &EventCallbacks) -> Result<()> {
    let function = unsafe {
        ti_fn!(
            env,
            122,
            unsafe extern "C" fn(*mut JvmtiEnv, *const EventCallbacks, jint) -> jint
        )
    };
    checked(unsafe { function(env, value, std::mem::size_of::<EventCallbacks>() as jint) })
}
pub(crate) unsafe fn set_event(env: *mut JvmtiEnv, event: jint, enabled: bool) -> Result<()> {
    let function = unsafe {
        ti_fn!(
            env,
            2,
            unsafe extern "C" fn(*mut JvmtiEnv, jint, jint, jthread, ...) -> jint
        )
    };
    checked(unsafe { function(env, i32::from(enabled), event, ptr::null_mut()) })
}
pub(crate) unsafe fn exception(env: *mut JNIEnv) -> Result<bool> {
    let function = unsafe { jni_fn!(env, 228, unsafe extern "C" fn(*mut JNIEnv) -> jboolean) };
    Ok(unsafe { function(env) } != 0)
}
pub(crate) unsafe fn new_global(env: *mut JNIEnv, object: jobject) -> Result<jobject> {
    if object.is_null() {
        return Ok(ptr::null_mut());
    }
    if unsafe { exception(env)? } {
        return Err(FfiError::PendingException);
    }
    let function = unsafe {
        jni_fn!(
            env,
            21,
            unsafe extern "C" fn(*mut JNIEnv, jobject) -> jobject
        )
    };
    let value = unsafe { function(env, object) };
    if unsafe { exception(env)? } {
        if !value.is_null() {
            unsafe { delete_global(env, value)? };
        }
        Err(FfiError::PendingException)
    } else if value.is_null() {
        Err(FfiError::InvalidResult)
    } else {
        Ok(value)
    }
}
pub(crate) unsafe fn delete_global(env: *mut JNIEnv, object: jobject) -> Result<()> {
    let function = unsafe { jni_fn!(env, 22, unsafe extern "C" fn(*mut JNIEnv, jobject)) };
    unsafe { function(env, object) };
    Ok(())
}
pub(crate) unsafe fn delete_local(env: *mut JNIEnv, object: jobject) -> Result<()> {
    let function = unsafe { jni_fn!(env, 23, unsafe extern "C" fn(*mut JNIEnv, jobject)) };
    unsafe { function(env, object) };
    Ok(())
}
pub(crate) unsafe fn same_object(env: *mut JNIEnv, a: jobject, b: jobject) -> Result<bool> {
    if unsafe { exception(env)? } {
        return Err(FfiError::PendingException);
    }
    let function = unsafe {
        jni_fn!(
            env,
            24,
            unsafe extern "C" fn(*mut JNIEnv, jobject, jobject) -> jboolean
        )
    };
    Ok(unsafe { function(env, a, b) } != 0)
}
pub(crate) unsafe fn current_thread(env: *mut JvmtiEnv) -> Result<jthread> {
    let function = unsafe {
        ti_fn!(
            env,
            18,
            unsafe extern "C" fn(*mut JvmtiEnv, *mut jthread) -> jint
        )
    };
    let mut value = ptr::null_mut();
    checked(unsafe { function(env, &mut value) })?;
    if value.is_null() {
        Err(FfiError::InvalidResult)
    } else {
        Ok(value)
    }
}
pub(crate) unsafe fn class_loader(env: *mut JvmtiEnv, class: jclass) -> Result<jobject> {
    let function = unsafe {
        ti_fn!(
            env,
            57,
            unsafe extern "C" fn(*mut JvmtiEnv, jclass, *mut jobject) -> jint
        )
    };
    let mut value = ptr::null_mut();
    checked(unsafe { function(env, class, &mut value) })?;
    Ok(value) // null is the actual bootstrap loader.
}
pub(crate) unsafe fn deallocate(env: *mut JvmtiEnv, memory: *mut u8) -> Result<()> {
    if memory.is_null() {
        return Ok(());
    }
    let function = unsafe {
        ti_fn!(
            env,
            47,
            unsafe extern "C" fn(*mut JvmtiEnv, *mut u8) -> jint
        )
    };
    checked(unsafe { function(env, memory) })
}
pub(crate) unsafe fn c_string(value: *const c_char, cap: usize) -> Result<Vec<u8>> {
    if value.is_null() {
        return Err(FfiError::InvalidResult);
    }
    let mut result = Vec::new();
    for index in 0..=cap {
        let byte = unsafe { *value.add(index) } as u8;
        if byte == 0 {
            return Ok(result);
        }
        if index == cap {
            return Err(FfiError::BoundExceeded);
        }
        result.push(byte);
    }
    Err(FfiError::BoundExceeded)
}
pub(crate) unsafe fn class_signature(env: *mut JvmtiEnv, class: jclass) -> Result<Vec<u8>> {
    let function = unsafe {
        ti_fn!(
            env,
            48,
            unsafe extern "C" fn(*mut JvmtiEnv, jclass, *mut *mut c_char, *mut *mut c_char) -> jint
        )
    };
    let mut value = ptr::null_mut();
    checked(unsafe { function(env, class, &mut value, ptr::null_mut()) })?;
    let result = unsafe { c_string(value, 65535) };
    let cleanup = unsafe { deallocate(env, value.cast()) };
    cleanup?;
    result
}
pub(crate) unsafe fn method_name(
    env: *mut JvmtiEnv,
    method: jmethodID,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let function = unsafe {
        ti_fn!(
            env,
            64,
            unsafe extern "C" fn(
                *mut JvmtiEnv,
                jmethodID,
                *mut *mut c_char,
                *mut *mut c_char,
                *mut *mut c_char,
            ) -> jint
        )
    };
    let (mut name, mut signature) = (ptr::null_mut(), ptr::null_mut());
    checked(unsafe { function(env, method, &mut name, &mut signature, ptr::null_mut()) })?;
    let result = unsafe {
        c_string(name, 65535)
            .and_then(|name| c_string(signature, 65535).map(|signature| (name, signature)))
    };
    let first = unsafe { deallocate(env, name.cast()) };
    let second = unsafe { deallocate(env, signature.cast()) };
    first?;
    second?;
    result
}
pub(crate) unsafe fn method_declaring_class(
    env: *mut JvmtiEnv,
    method: jmethodID,
) -> Result<jclass> {
    let function = unsafe {
        ti_fn!(
            env,
            65,
            unsafe extern "C" fn(*mut JvmtiEnv, jmethodID, *mut jclass) -> jint
        )
    };
    let mut value = ptr::null_mut();
    checked(unsafe { function(env, method, &mut value) })?;
    if value.is_null() {
        Err(FfiError::InvalidResult)
    } else {
        Ok(value)
    }
}
pub(crate) unsafe fn method_modifiers(env: *mut JvmtiEnv, method: jmethodID) -> Result<jint> {
    let function = unsafe {
        ti_fn!(
            env,
            66,
            unsafe extern "C" fn(*mut JvmtiEnv, jmethodID, *mut jint) -> jint
        )
    };
    let mut value = 0;
    checked(unsafe { function(env, method, &mut value) })?;
    Ok(value)
}
pub(crate) unsafe fn class_prepared(env: *mut JvmtiEnv, class: jclass) -> Result<bool> {
    Ok(unsafe { class_status(env, class)? } & CLASS_PREPARED != 0)
}
pub(crate) unsafe fn class_status(env: *mut JvmtiEnv, class: jclass) -> Result<jint> {
    let function = unsafe {
        ti_fn!(
            env,
            49,
            unsafe extern "C" fn(*mut JvmtiEnv, jclass, *mut jint) -> jint
        )
    };
    let mut value = 0;
    checked(unsafe { function(env, class, &mut value) })?;
    Ok(value)
}
pub(crate) unsafe fn class_methods(env: *mut JvmtiEnv, class: jclass) -> Result<Vec<jmethodID>> {
    let function = unsafe {
        ti_fn!(
            env,
            52,
            unsafe extern "C" fn(*mut JvmtiEnv, jclass, *mut jint, *mut *mut jmethodID) -> jint
        )
    };
    let (mut count, mut data) = (0, ptr::null_mut());
    checked(unsafe { function(env, class, &mut count, &mut data) })?;
    let result = if !(0..=4096).contains(&count) || (count != 0 && data.is_null()) {
        Err(FfiError::BoundExceeded)
    } else if count == 0 {
        Ok(Vec::new())
    } else {
        Ok(unsafe { std::slice::from_raw_parts(data, count as usize) }.to_vec())
    };
    unsafe { deallocate(env, data.cast()) }?;
    result
}
pub(crate) unsafe fn bytecodes(
    env: *mut JvmtiEnv,
    method: jmethodID,
    cap: usize,
) -> Result<Vec<u8>> {
    let function = unsafe {
        ti_fn!(
            env,
            75,
            unsafe extern "C" fn(*mut JvmtiEnv, jmethodID, *mut jint, *mut *mut u8) -> jint
        )
    };
    let (mut count, mut data) = (0, ptr::null_mut());
    checked(unsafe { function(env, method, &mut count, &mut data) })?;
    let result = unsafe { copy_buffer(data, count, cap) };
    unsafe { deallocate(env, data) }?;
    result
}
pub(crate) unsafe fn constant_pool(
    env: *mut JvmtiEnv,
    class: jclass,
    cap: usize,
) -> Result<(u32, Vec<u8>)> {
    let function = unsafe {
        ti_fn!(
            env,
            146,
            unsafe extern "C" fn(*mut JvmtiEnv, jclass, *mut jint, *mut jint, *mut *mut u8) -> jint
        )
    };
    let (mut count, mut size, mut data) = (0, 0, ptr::null_mut());
    checked(unsafe { function(env, class, &mut count, &mut size, &mut data) })?;
    let result = if !(1..=65535).contains(&count) {
        Err(FfiError::InvalidResult)
    } else {
        unsafe { copy_buffer(data, size, cap) }.map(|bytes| (count as u32, bytes))
    };
    unsafe { deallocate(env, data) }?;
    result
}
pub(crate) unsafe fn copy_buffer(data: *const u8, size: jint, cap: usize) -> Result<Vec<u8>> {
    if size < 0 || size as usize > cap {
        return Err(FfiError::BoundExceeded);
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    if data.is_null() {
        return Err(FfiError::InvalidResult);
    }
    Ok(unsafe { std::slice::from_raw_parts(data, size as usize) }.to_vec())
}
pub(crate) unsafe fn string_mutf8(env: *mut JNIEnv, string: jstring) -> Result<Vec<u8>> {
    if string.is_null() {
        return Err(FfiError::InvalidResult);
    }
    if unsafe { exception(env)? } {
        return Err(FfiError::PendingException);
    }
    let length = unsafe { jni_fn!(env, 164, unsafe extern "C" fn(*mut JNIEnv, jstring) -> jint) };
    let units = unsafe { length(env, string) };
    if unsafe { exception(env)? } {
        return Err(FfiError::PendingException);
    }
    if !(0..=65535).contains(&units) {
        return Err(FfiError::BoundExceeded);
    }
    let get = unsafe {
        jni_fn!(
            env,
            169,
            unsafe extern "C" fn(*mut JNIEnv, jstring, *mut jboolean) -> *const c_char
        )
    };
    let release = unsafe {
        jni_fn!(
            env,
            170,
            unsafe extern "C" fn(*mut JNIEnv, jstring, *const c_char)
        )
    };
    let bytes = unsafe { get(env, string, ptr::null_mut()) };
    if bytes.is_null() {
        return Err(FfiError::PendingException);
    }
    let result = unsafe { c_string(bytes, 65535 * 3) };
    unsafe { release(env, string, bytes) };
    if unsafe { exception(env)? } {
        Err(FfiError::PendingException)
    } else {
        result
    }
}
/// Fixed stack prefix probe; it creates no Rust String/Vec or JNI string copy.
/// Index 220 is GetStringRegion(JNIEnv*, jstring, jsize, jsize, jchar*).
/// https://docs.oracle.com/en/java/javase/25/docs/specs/jni/functions.html#getstringregion
pub(crate) unsafe fn string_prefix(
    env: *mut JNIEnv,
    string: jstring,
) -> Result<([u16; 64], usize)> {
    if string.is_null() || unsafe { exception(env)? } {
        return Err(FfiError::PendingException);
    }
    let length = unsafe { jni_fn!(env, 164, unsafe extern "C" fn(*mut JNIEnv, jstring) -> jint) };
    let size = unsafe { length(env, string) };
    if unsafe { exception(env)? } {
        return Err(FfiError::PendingException);
    }
    if size < 0 {
        return Err(FfiError::InvalidResult);
    }
    let amount = size.min(64);
    let mut prefix = [0u16; 64];
    if amount != 0 {
        let region = unsafe {
            jni_fn!(
                env,
                220,
                unsafe extern "C" fn(*mut JNIEnv, jstring, jint, jint, *mut u16)
            )
        };
        // Pinned HotSpot accepts end == length; its range check is
        // start > string_length - len, so full short-string copying is valid.
        // https://github.com/openjdk/jdk/blob/jdk-25-ga/src/hotspot/share/prims/jni.cpp
        unsafe { region(env, string, 0, amount, prefix.as_mut_ptr()) };
        if unsafe { exception(env)? } {
            return Err(FfiError::PendingException);
        }
    }
    Ok((prefix, amount as usize))
}
pub(crate) unsafe fn find_class(env: *mut JNIEnv, name: &'static [u8]) -> Result<jclass> {
    if unsafe { exception(env)? } {
        return Err(FfiError::PendingException);
    }
    let function = unsafe {
        jni_fn!(
            env,
            6,
            unsafe extern "C" fn(*mut JNIEnv, *const c_char) -> jclass
        )
    };
    let value = unsafe { function(env, name.as_ptr().cast()) };
    if unsafe { exception(env)? } {
        if !value.is_null() {
            unsafe { delete_local(env, value)? };
        }
        Err(FfiError::PendingException)
    } else if value.is_null() {
        Err(FfiError::InvalidResult)
    } else {
        Ok(value)
    }
}
pub(crate) unsafe fn class_name_method(env: *mut JNIEnv, class: jclass) -> Result<jmethodID> {
    if unsafe { exception(env)? } {
        return Err(FfiError::PendingException);
    }
    let function = unsafe {
        jni_fn!(
            env,
            33,
            unsafe extern "C" fn(*mut JNIEnv, jclass, *const c_char, *const c_char) -> jmethodID
        )
    };
    let value = unsafe {
        function(
            env,
            class,
            c"getName".as_ptr(),
            c"()Ljava/lang/String;".as_ptr(),
        )
    };
    if value.is_null() || unsafe { exception(env)? } {
        Err(FfiError::PendingException)
    } else {
        Ok(value)
    }
}
pub(crate) unsafe fn class_name(
    env: *mut JNIEnv,
    class: jclass,
    method: jmethodID,
) -> Result<Vec<u8>> {
    if unsafe { exception(env)? } {
        return Err(FfiError::PendingException);
    }
    let function = unsafe {
        jni_fn!(
            env,
            36,
            unsafe extern "C" fn(*mut JNIEnv, jobject, jmethodID, *const c_void) -> jobject
        )
    };
    // getName has zero parameters, so no jvalue storage is necessary.
    let value = unsafe { function(env, class, method, ptr::null()) };
    if unsafe { exception(env)? } {
        if !value.is_null() {
            unsafe { delete_local(env, value)? };
        }
        return Err(FfiError::PendingException);
    }
    if value.is_null() {
        return Err(FfiError::InvalidResult);
    }
    let result = unsafe { string_mutf8(env, value) };
    unsafe { delete_local(env, value) }?;
    // Closed roster names are ASCII. This is standard UTF-8 only when checked;
    // hidden '/0x...' suffixes are preserved rather than slash-replaced.
    let value = result?;
    if !value.is_ascii() {
        return Err(FfiError::InvalidResult);
    }
    Ok(value)
}
pub(crate) unsafe fn register_native(
    env: *mut JNIEnv,
    class: jclass,
    method: &NativeMethod,
) -> Result<()> {
    if unsafe { exception(env)? } {
        return Err(FfiError::PendingException);
    }
    let function = unsafe {
        jni_fn!(
            env,
            215,
            unsafe extern "C" fn(*mut JNIEnv, jclass, *const NativeMethod, jint) -> jint
        )
    };
    if unsafe { function(env, class, method, 1) } != JNI_OK || unsafe { exception(env)? } {
        Err(FfiError::PendingException)
    } else {
        Ok(())
    }
}
pub(crate) unsafe fn selected_array(
    env: *mut JNIEnv,
    data: jbyteArray,
    offset: jint,
    size: jint,
    cap: usize,
) -> Result<Vec<u8>> {
    if unsafe { exception(env)? } {
        return Err(FfiError::PendingException);
    }
    if data.is_null() || offset < 0 || size < 0 || size as usize > cap {
        return Err(FfiError::BoundExceeded);
    }
    let length = unsafe { jni_fn!(env, 171, unsafe extern "C" fn(*mut JNIEnv, jobject) -> jint) };
    let total = unsafe { length(env, data) };
    if unsafe { exception(env)? } {
        return Err(FfiError::PendingException);
    }
    if total < 0 || offset.checked_add(size).is_none_or(|end| end > total) {
        return Err(FfiError::InvalidResult);
    }
    let get = unsafe {
        jni_fn!(
            env,
            200,
            unsafe extern "C" fn(*mut JNIEnv, jbyteArray, jint, jint, *mut jbyte)
        )
    };
    let mut bytes = vec![0u8; size as usize];
    unsafe { get(env, data, offset, size, bytes.as_mut_ptr().cast()) };
    if unsafe { exception(env)? } {
        Err(FfiError::PendingException)
    } else {
        Ok(bytes)
    }
}
pub(crate) unsafe fn byte_array(env: *mut JNIEnv, bytes: &[u8]) -> Result<jbyteArray> {
    if unsafe { exception(env)? } {
        return Err(FfiError::PendingException);
    }
    let size = jint::try_from(bytes.len()).map_err(|_| FfiError::BoundExceeded)?;
    let new = unsafe {
        jni_fn!(
            env,
            176,
            unsafe extern "C" fn(*mut JNIEnv, jint) -> jbyteArray
        )
    };
    let set = unsafe {
        jni_fn!(
            env,
            208,
            unsafe extern "C" fn(*mut JNIEnv, jbyteArray, jint, jint, *const jbyte)
        )
    };
    let value = unsafe { new(env, size) };
    if unsafe { exception(env)? } {
        if !value.is_null() {
            unsafe { delete_local(env, value)? };
        }
        return Err(FfiError::PendingException);
    }
    if value.is_null() {
        return Err(FfiError::InvalidResult);
    }
    unsafe { set(env, value, 0, size, bytes.as_ptr().cast()) };
    if unsafe { exception(env)? } {
        unsafe { delete_local(env, value) }?;
        Err(FfiError::PendingException)
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ABI_SUPPORTED, Capabilities, EventCallbacks, JNIEnv, JavaVM, JvmtiEnv, NativeMethod,
        STARTUP_ABI, StartupAbi, jboolean, jbyte, jint, select_startup_abi,
    };
    use std::ffi::c_void;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn required_capabilities_match_the_jdk25_declared_field_ordinals() {
        assert_eq!(
            Capabilities::required().words,
            [0x4400_0008, 0x0000_0428, 0, 0]
        );
        assert_eq!(size_of::<Capabilities>(), 16);
        assert_eq!(align_of::<Capabilities>(), 4);
    }

    #[test]
    fn every_required_capability_is_necessary_even_with_all_other_bits_set() {
        let requested = Capabilities::required();
        assert!(requested.contains(&requested));
        assert!(!Capabilities::default().contains(&requested));
        for ordinal in [3, 26, 30, 35, 37, 42] {
            let mut observed = Capabilities {
                words: [u32::MAX; 4],
            };
            assert!(observed.contains(&requested));
            observed.words[ordinal / 32] &= !(1 << (ordinal % 32));
            assert!(!observed.contains(&requested), "required ordinal {ordinal}");
        }
    }

    #[test]
    fn supported_rust_table_layout_matches_the_declared_64bit_subset() {
        // Rust layout evidence only. This does not stand in for the selected
        // native JDK header/compiler witness or an actual callback invocation.
        assert_eq!(size_of::<jint>(), 4);
        assert_eq!(size_of::<jboolean>(), 1);
        assert_eq!(size_of::<jbyte>(), 1);
        if ABI_SUPPORTED {
            assert_eq!(size_of::<*const c_void>(), 8);
            assert_eq!(align_of::<*const c_void>(), 8);
            assert_eq!(size_of::<JNIEnv>(), 8);
            assert_eq!(size_of::<JavaVM>(), 8);
            assert_eq!(size_of::<JvmtiEnv>(), 8);
            assert_eq!(size_of::<EventCallbacks>(), 312);
            assert_eq!(align_of::<EventCallbacks>(), 8);
            assert_eq!(size_of::<NativeMethod>(), 24);
            assert_eq!(align_of::<NativeMethod>(), 8);
            assert_eq!(offset_of!(NativeMethod, name), 0);
            assert_eq!(offset_of!(NativeMethod, signature), 8);
            assert_eq!(offset_of!(NativeMethod, function), 16);
        }
    }

    #[test]
    fn each_startup_marker_is_exact_bounded_and_target_specific() {
        let markers: [(StartupAbi, &[u8]); 3] = [
            (
                StartupAbi::WindowsX64Msvc,
                b"jdk25-windows-x64-msvc-controlled-startup-v1",
            ),
            (
                StartupAbi::LinuxX64Gnu,
                b"jdk25-linux-x64-gnu-controlled-startup-v1",
            ),
            (
                StartupAbi::MacOsArm64Darwin,
                b"jdk25-macos-arm64-darwin-controlled-startup-v1",
            ),
        ];
        for (abi, marker) in markers {
            assert_eq!(abi.startup_options(), marker);
            assert!(abi.accepts_options(marker));
            assert!(marker.is_ascii());
            assert!(marker.len() <= 128);
            assert!(!marker.contains(&0));
            for (other, other_marker) in markers {
                assert_eq!(abi.accepts_options(other_marker), abi == other);
            }
        }
    }

    #[test]
    fn partial_extended_and_malformed_startup_options_are_rejected() {
        for abi in [
            StartupAbi::WindowsX64Msvc,
            StartupAbi::LinuxX64Gnu,
            StartupAbi::MacOsArm64Darwin,
        ] {
            let marker = abi.startup_options();
            assert!(!abi.accepts_options(&[]));
            assert!(!abi.accepts_options(&marker[..marker.len() - 1]));
            for extra in [b'x', b'\0', 0xff] {
                let mut extended = marker.to_vec();
                extended.push(extra);
                assert!(!abi.accepts_options(&extended));
            }
            let mut prefixed = vec![b'x'];
            prefixed.extend_from_slice(marker);
            assert!(!abi.accepts_options(&prefixed));
        }
    }

    #[test]
    fn an_exact_target_requires_its_matching_layout_and_build_identity() {
        let targets = [
            ("x86_64-pc-windows-msvc", StartupAbi::WindowsX64Msvc),
            ("x86_64-unknown-linux-gnu", StartupAbi::LinuxX64Gnu),
            ("aarch64-apple-darwin", StartupAbi::MacOsArm64Darwin),
        ];
        for (target, expected) in targets {
            assert_eq!(
                select_startup_abi(Some(target), Some(expected)),
                Some(expected)
            );
            assert_eq!(select_startup_abi(Some(target), None), None);
            for (_, other_layout) in targets {
                if other_layout != expected {
                    assert_eq!(select_startup_abi(Some(target), Some(other_layout)), None);
                }
            }
        }
        assert_eq!(ABI_SUPPORTED, STARTUP_ABI.is_some());
    }

    #[test]
    fn similar_or_missing_target_identities_never_admit_a_matching_layout() {
        for layout in [
            StartupAbi::WindowsX64Msvc,
            StartupAbi::LinuxX64Gnu,
            StartupAbi::MacOsArm64Darwin,
        ] {
            assert_eq!(select_startup_abi(None, Some(layout)), None);
            for rejected in [
                "unsupported",
                "",
                "x86_64-pc-windows-gnu",
                "arm64ec-pc-windows-msvc",
                "i686-pc-windows-msvc",
                "x86_64-unknown-linux-musl",
                "x86_64-unknown-linux-gnux32",
                "aarch64-unknown-linux-gnu",
                "s390x-unknown-linux-gnu",
                "x86_64-apple-darwin",
                "arm64e-apple-darwin",
                "arm64_32-apple-watchos",
                "aarch64-apple-darwin-extra",
                "targets/custom.json",
            ] {
                assert_eq!(select_startup_abi(Some(rejected), Some(layout)), None);
            }
        }
    }
}

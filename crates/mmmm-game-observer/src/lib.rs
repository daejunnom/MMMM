// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
//! Bounded JDK 25 startup definition producer with explicit target ABI selection.
//!
//! The table subset admits Windows x64 MSVC, Linux x64 GNU and macOS ARM64
//! Darwin, each 64-bit and little-endian. Compile-target selection does not
//! replace the actual JDK/compiler ABI check or native startup verification.
//!
//! Crate registration, compilation and tests do not grant a target profile.
//! A launcher must independently admit a closed startup agent roster,
//! pinned VM binary/profile, final CFLH ordering, and no later transformers or
//! definition changes. Native status reports installed capabilities/events only.
//! JVM attach is deliberately rejected. Final bytes are never read from JARs,
//! class resources, retransform initial buffers, caller hashes, or receipts.

#![deny(unsafe_op_in_unsafe_fn)]

mod classfile;
mod definitions;
mod ffi;
mod native_producer;

use std::ffi::{c_char, c_void};

// Foreign entry pointers stay opaque at the public C boundary. The exact
// private JNI/JVMTI table types are applied only inside the producer.

/// Standard JVMTI startup entry. Unsupported startup keeps the producer
/// unavailable so the Java boundary can report a negative status; it never
/// installs guessed ABI callbacks. No JNI operation runs in OnLoad.
///
/// # Safety
/// `vm` and the NUL-terminated startup `options` must be the live VM-provided
/// Agent_OnLoad arguments. The VM must use the pinned JDK 25 table ABI for the
/// compiled Windows x64 MSVC, Linux x64 GNU or macOS ARM64 Darwin target.
/// The caller must invoke this at VM startup, never emulate attach.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Agent_OnLoad(
    vm: *mut c_void,
    options: *mut c_char,
    _reserved: *mut c_void,
) -> i32 {
    native_producer::on_load(vm.cast(), options)
}

#[unsafe(no_mangle)]
pub extern "C" fn Agent_OnAttach(
    _vm: *mut c_void,
    _options: *mut c_char,
    _reserved: *mut c_void,
) -> i32 {
    // Live attach cannot retrospectively establish initial definition coverage.
    ffi::JNI_ERR
}

#[unsafe(no_mangle)]
pub extern "C" fn Agent_OnUnload(_vm: *mut c_void) {
    native_producer::on_unload();
}

#[unsafe(no_mangle)]
pub extern "C" fn JNI_OnLoad(_vm: *mut c_void, _reserved: *mut c_void) -> i32 {
    // Does not substitute JNI library loading for the Agent_OnLoad startup path.
    ffi::JNI_VERSION_24
}

#[unsafe(no_mangle)]
pub extern "C" fn Java_io_github_daejunnom_mmmm_observer_DefinitionObserverBridge_nativeStatus(
    _env: *mut c_void,
    _bridge: *mut c_void,
) -> i32 {
    native_producer::status()
}

#[unsafe(no_mangle)]
/// Query the producer using the original actual Class reference.
///
/// # Safety
/// `env` must be the calling attached thread's live JNI environment. `actual`
/// must be null or a valid local/global jclass in that VM and its current frame.
/// The environment must use the pinned JDK 25 JNI table ABI for this compiled
/// target, and references must belong to that same VM and attached thread.
pub unsafe extern "C" fn Java_io_github_daejunnom_mmmm_observer_DefinitionObserverBridge_nativeEvidence(
    env: *mut c_void,
    _bridge: *mut c_void,
    actual: *mut c_void,
) -> *mut c_void {
    native_producer::evidence(env.cast(), actual)
}

/// Describe a narrow producer-observed hidden forwarding recipe and the current
/// already observed static target identity. This grants no SAM or source policy.
///
/// # Safety
/// `env` must be the calling attached thread's live JNI environment. `actual`
/// must be null or a valid local/global jclass in that VM and its current frame.
/// The environment must use the pinned JDK 25 JNI table ABI for this compiled
/// target, and references must belong to that same VM and attached thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_io_github_daejunnom_mmmm_observer_DefinitionObserverBridge_nativeHiddenForwarder(
    env: *mut c_void,
    _bridge: *mut c_void,
    actual: *mut c_void,
) -> *mut c_void {
    native_producer::hidden_forwarder(env.cast(), actual)
}

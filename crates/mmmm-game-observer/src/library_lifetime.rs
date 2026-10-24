// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
//! Actual process-lifetime retention of this already loaded native image.
//!
//! Call `ensure` before creating any filesystem effect whose native state can
//! outlive the JNI call. The opaque proof establishes loaded-code lifetime only;
//! it grants no artifact, source, hash, filesystem, game or invocation authority.
//! No Java/JDK unload guarantee is assumed. No filesystem path is opened here.
//!
//! There is one native attempt and at most one retained loader reference. A
//! reference obtained before a later identity-check failure is deliberately kept:
//! releasing it while retained state or native calls can exist would be unsafe.
//! There is no unload/close operation, retry, or route-generation reset here.

use std::{error::Error, fmt, io, sync::OnceLock};

static ATTEMPT: OnceLock<Result<LibraryLifetimeProof, LibraryLifetimeError>> = OnceLock::new();

/// Constructed only after this module's actual native retention succeeds.
/// The handle stays private and is never returned to Java or serialized.
pub(crate) struct LibraryLifetimeProof {
    _retained_image: usize,
}

/// A bounded diagnosis without image paths, native addresses, or loader strings.
/// POSIX loader calls do not specify an errno result; their actual failure
/// status is retained without mislabelling the ambient errno as their cause.
#[derive(Debug)]
pub(crate) enum LibraryLifetimeError {
    UnsupportedTarget,
    NativeFailure {
        operation: &'static str,
        status: i32,
        source: Option<io::Error>,
    },
    InvalidObservation {
        operation: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for LibraryLifetimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedTarget => {
                formatter.write_str("native image lifetime retention is unsupported on this target")
            }
            Self::NativeFailure {
                operation,
                status,
                source,
            } => {
                write!(
                    formatter,
                    "native image lifetime {operation} failed (status {status})"
                )?;
                if let Some(source) = source {
                    write!(formatter, ": {source}")?;
                }
                Ok(())
            }
            Self::InvalidObservation { operation, reason } => {
                write!(
                    formatter,
                    "native image lifetime {operation} was not proven: {reason}"
                )
            }
        }
    }
}

impl Error for LibraryLifetimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::NativeFailure {
                source: Some(source),
                ..
            } => Some(source),
            _ => None,
        }
    }
}

/// Return the original native result; failure never authorizes a retained effect.
/// Later calls neither repeat the loader operation nor replace its first error.
pub(crate) fn ensure() -> Result<&'static LibraryLifetimeProof, &'static LibraryLifetimeError> {
    ATTEMPT
        .get_or_init(|| {
            if cfg!(any(
                all(
                    target_os = "windows",
                    target_arch = "x86_64",
                    target_env = "msvc",
                    target_pointer_width = "64",
                    target_endian = "little"
                ),
                all(
                    target_os = "linux",
                    target_arch = "x86_64",
                    target_env = "gnu",
                    target_pointer_width = "64",
                    target_endian = "little"
                ),
                all(
                    target_os = "macos",
                    target_arch = "aarch64",
                    target_pointer_width = "64",
                    target_endian = "little"
                )
            )) {
                platform::pin_actual_image()
            } else {
                Err(LibraryLifetimeError::UnsupportedTarget)
            }
        })
        .as_ref()
}

#[cfg(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod platform {
    use super::{LibraryLifetimeError, LibraryLifetimeProof};
    use std::{ffi::c_void, io, ptr, sync::atomic::AtomicU8};

    // Writable static storage has its own actual address in this linked image;
    // it cannot be redirected through an imported/exported function trampoline.
    static OWN_IMAGE_MARKER: AtomicU8 = AtomicU8::new(0);

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleExW(
            flags: u32,
            module_address: *const u16,
            module: *mut *mut c_void,
        ) -> i32;
    }

    pub(super) fn pin_actual_image() -> Result<LibraryLifetimeProof, LibraryLifetimeError> {
        // Microsoft libloaderapi.h: FROM_ADDRESS interprets the second argument
        // as an image address; PIN keeps that image until process termination,
        // regardless of later FreeLibrary calls. Do not call FreeLibrary here.
        // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexw
        const FROM_ADDRESS_AND_PIN: u32 = 0x0000_0004 | 0x0000_0001;
        let mut image = ptr::null_mut();
        // SAFETY: the marker is static storage in this currently executing image;
        // FROM_ADDRESS does not dereference it as a UTF-16 string. The output
        // points to an actual writable HMODULE-sized local value.
        let status = unsafe {
            GetModuleHandleExW(
                FROM_ADDRESS_AND_PIN,
                (&raw const OWN_IMAGE_MARKER).cast(),
                &mut image,
            )
        };
        if status == 0 {
            // Capture the actual thread-local error before any other OS call.
            let source = io::Error::last_os_error();
            return Err(LibraryLifetimeError::NativeFailure {
                operation: "GetModuleHandleExW(FROM_ADDRESS|PIN)",
                status,
                source: Some(source),
            });
        }
        if image.is_null() {
            return Err(LibraryLifetimeError::InvalidObservation {
                operation: "GetModuleHandleExW(FROM_ADDRESS|PIN)",
                reason: "the successful call returned no image handle",
            });
        }
        Ok(LibraryLifetimeProof {
            _retained_image: image as usize,
        })
    }
}

#[cfg(any(
    all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64",
        target_endian = "little"
    ),
    all(
        target_os = "macos",
        target_arch = "aarch64",
        target_pointer_width = "64",
        target_endian = "little"
    )
))]
mod platform {
    use super::{LibraryLifetimeError, LibraryLifetimeProof};
    use std::{
        ffi::{c_char, c_int, c_void},
        ptr,
        sync::atomic::{AtomicU8, AtomicUsize, Ordering},
    };

    static OWN_IMAGE_MARKER: AtomicU8 = AtomicU8::new(0);
    // Native loader ownership is retained even if symbol validation fails.
    // ATTEMPT serializes the only writer. No handle is ever exposed or closed.
    static RETAINED_HANDLE: AtomicUsize = AtomicUsize::new(0);
    const MAX_LOADER_PATH_BYTES: usize = 4096;
    const OWN_EXPORTED_ENTRY: &[u8] =
        b"Java_io_github_daejunnom_mmmm_observer_DefinitionOwnedPackFilesBridge_nativeCall\0";

    #[repr(C)]
    struct DlInfo {
        file_name: *const c_char,
        image_base: *mut c_void,
        symbol_name: *const c_char,
        symbol_address: *mut c_void,
    }

    impl DlInfo {
        const fn empty() -> Self {
            Self {
                file_name: ptr::null(),
                image_base: ptr::null_mut(),
                symbol_name: ptr::null(),
                symbol_address: ptr::null_mut(),
            }
        }
    }

    // Linux's public dlfcn ABI is supplied by libdl (including the GNU libc
    // compatibility library after its implementation moved into libc).
    // Darwin's public dlfcn ABI is supplied by libSystem.
    #[cfg_attr(target_os = "linux", link(name = "dl"))]
    #[cfg_attr(target_os = "macos", link(name = "System"))]
    unsafe extern "C" {
        fn dladdr(address: *const c_void, information: *mut DlInfo) -> c_int;
        fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn dlerror() -> *mut c_char;
    }

    #[cfg(target_os = "linux")]
    // GNU public bits/dlfcn.h: NOW=2, NOLOAD=4, NODELETE=0x1000, LOCAL=0.
    // https://raw.githubusercontent.com/bminor/glibc/master/bits/dlfcn.h
    const OPEN_MODE: c_int = 0x00002 | 0x00004 | 0x01000;

    #[cfg(target_os = "macos")]
    // Apple's public dlfcn.h: NOW=2, LOCAL=4, NOLOAD=0x10, NODELETE=0x80,
    // FIRST=0x100. FIRST restricts dlsym to this selected image.
    // https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/include/dlfcn.h
    // Apple's dlopen(3) specifies that NODELETE prevents address-space removal
    // even after all clients dlclose, and that a NOLOAD handle is ref-counted.
    // https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dlopen.3.html
    const OPEN_MODE: c_int = 0x2 | 0x4 | 0x10 | 0x80 | 0x100;

    fn loader_failure(operation: &'static str, status: c_int) -> LibraryLifetimeError {
        LibraryLifetimeError::NativeFailure {
            operation,
            status,
            source: None,
        }
    }

    fn unproven(operation: &'static str, reason: &'static str) -> LibraryLifetimeError {
        LibraryLifetimeError::InvalidObservation { operation, reason }
    }

    pub(super) fn pin_actual_image() -> Result<LibraryLifetimeProof, LibraryLifetimeError> {
        let mut own_image = DlInfo::empty();
        // SAFETY: the marker is actual static storage in this executing image;
        // own_image has the public platform Dl_info layout and writable storage.
        let status = unsafe { dladdr((&raw const OWN_IMAGE_MARKER).cast(), &mut own_image) };
        if status == 0 {
            return Err(loader_failure("dladdr(own marker)", status));
        }
        if own_image.file_name.is_null() || own_image.image_base.is_null() {
            return Err(unproven(
                "dladdr(own marker)",
                "no loader image name or base",
            ));
        }

        // Copy only the loader's own NUL-terminated image name. This is not a
        // filesystem read, canonicalization, caller path or hash observation.
        // The bounded local copy is never included in an error or result.
        let mut path = [0 as c_char; MAX_LOADER_PATH_BYTES + 1];
        let mut terminated = false;
        for (index, output) in path.iter_mut().enumerate() {
            // SAFETY: successful dladdr supplies a loader-owned C string. Read
            // one byte at a time and stop immediately at its terminator; never
            // create a slice extending past the string's actual allocation.
            let byte = unsafe { own_image.file_name.add(index).read() };
            *output = byte;
            if byte == 0 {
                if index == 0 {
                    return Err(unproven("dladdr(own marker)", "empty loader image name"));
                }
                terminated = true;
                break;
            }
        }
        if !terminated {
            return Err(unproven(
                "dladdr(own marker)",
                "loader image name exceeds the bound",
            ));
        }

        // SAFETY: discards only this thread's previous loader diagnostic. The
        // string contents can contain paths and are never read or printed.
        unsafe { dlerror() };
        // SAFETY: the bounded local array contains the observed image C string;
        // NOLOAD prevents mapping a new file. This is the single loader attempt.
        let handle = unsafe { dlopen(path.as_ptr(), OPEN_MODE) };
        if !handle.is_null() {
            // Keep this actual reference before any subsequent validation. No
            // error path or destructor can dlclose or replace it.
            RETAINED_HANDLE.store(handle as usize, Ordering::Release);
        }
        // SAFETY: inspect only whether the immediately preceding loader call
        // reported an error; do not dereference its private diagnostic string.
        let reported_error = unsafe { !dlerror().is_null() };
        if handle.is_null() {
            return Err(loader_failure("dlopen(NOW|NOLOAD|NODELETE)", 0));
        }
        if reported_error {
            return Err(unproven(
                "dlopen(NOW|NOLOAD|NODELETE)",
                "loader also reported an error",
            ));
        }

        // SAFETY: the actual retained handle is live; the fixed native entry
        // name is a static NUL-terminated byte string. It is never invoked here.
        let entry = unsafe { dlsym(handle, OWN_EXPORTED_ENTRY.as_ptr().cast()) };
        // SAFETY: read only the presence of this thread's dlsym diagnostic.
        let reported_error = unsafe { !dlerror().is_null() };
        if entry.is_null() {
            return Err(loader_failure("dlsym(own JNI entry)", 0));
        }
        if reported_error {
            return Err(unproven(
                "dlsym(own JNI entry)",
                "loader also reported an error",
            ));
        }
        let mut entry_image = DlInfo::empty();
        // SAFETY: the entry came from the retained live loader reference and
        // the output has the exact writable public Dl_info layout.
        let status = unsafe { dladdr(entry.cast_const(), &mut entry_image) };
        if status == 0 {
            return Err(loader_failure("dladdr(own JNI entry)", status));
        }
        if entry_image.image_base != own_image.image_base {
            return Err(unproven(
                "dladdr(own JNI entry)",
                "the selected image base differs",
            ));
        }
        Ok(LibraryLifetimeProof {
            _retained_image: handle as usize,
        })
    }
}

#[cfg(not(any(
    all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc",
        target_pointer_width = "64",
        target_endian = "little"
    ),
    all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64",
        target_endian = "little"
    ),
    all(
        target_os = "macos",
        target_arch = "aarch64",
        target_pointer_width = "64",
        target_endian = "little"
    )
)))]
mod platform {
    use super::{LibraryLifetimeError, LibraryLifetimeProof};

    pub(super) fn pin_actual_image() -> Result<LibraryLifetimeProof, LibraryLifetimeError> {
        Err(LibraryLifetimeError::UnsupportedTarget)
    }
}

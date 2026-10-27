//! Native storage for coordinator-issued, epoch-scoped bearer credentials.
//!
//! Endpoint records contain only [`CredentialRef`], never token bytes. Windows
//! uses a logon-session generic credential, Linux uses the current UID's kernel
//! user keyring, and macOS uses a non-synchronizing generic-password Data
//! Protection Keychain item. These stores have different lifetimes; the coordinator must remove its
//! reference when its epoch ends. An unavailable native store is an error: this
//! module has no plaintext, environment-variable, or file fallback.
//!
//! Rust-owned token and bearer buffers are erased on drop. That does not promise
//! to erase compiler copies, operating-system copies, swap, or crash dumps.
//! Native calls are synchronous; callers must use their bounded worker path.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::fmt;
use zeroize::{Zeroize, Zeroizing};

#[path = "credential_owner.rs"]
mod owner;
pub use owner::local_owner_principal;

const TOKEN_BYTES: usize = 32;
const TOKEN_HEX_BYTES: usize = TOKEN_BYTES * 2;
const REFERENCE_PREFIX: &str = "MMMM.coordinator.";
const MAX_REFERENCE_BYTES: usize = 128;

/// An opaque token. Deliberately has no Debug, Display, Serialize, Clone or Copy.
pub struct SecretToken([u8; TOKEN_BYTES]);

impl SecretToken {
    pub fn generate() -> Result<Self, CredentialError> {
        let mut token = Self([0; TOKEN_BYTES]);
        getrandom::fill(&mut token.0).map_err(|_| CredentialError::RandomUnavailable)?;
        Ok(token)
    }

    /// Accept only the canonical 64-character lowercase hexadecimal encoding.
    /// Invalid input is never included in an error message.
    pub fn parse(value: &str) -> Result<Self, CredentialError> {
        if value.len() != TOKEN_HEX_BYTES {
            return Err(CredentialError::InvalidToken);
        }
        let mut token = Self([0; TOKEN_BYTES]);
        for (destination, pair) in token.0.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            *destination = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Ok(token)
    }

    pub(crate) fn expose_secret(&self) -> &[u8; TOKEN_BYTES] {
        &self.0
    }

    pub(crate) fn bearer(&self) -> Zeroizing<String> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = Zeroizing::new(String::with_capacity(TOKEN_HEX_BYTES));
        for &byte in &self.0 {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 15)]));
        }
        encoded
    }
}

impl Drop for SecretToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn hex_nibble(byte: u8) -> Result<u8, CredentialError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(CredentialError::InvalidToken),
    }
}

/// A public native-store lookup name, not a token or an authorization grant.
/// Lowercase suffixes avoid aliases in Windows' case-insensitive target names.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CredentialRef(String);

impl CredentialRef {
    pub fn new(value: &str) -> Result<Self, CredentialError> {
        if value.len() > MAX_REFERENCE_BYTES || !value.is_ascii() {
            return Err(CredentialError::InvalidReference);
        }
        let suffix = value
            .strip_prefix(REFERENCE_PREFIX)
            .ok_or(CredentialError::InvalidReference)?;
        let bytes = suffix.as_bytes();
        if bytes.is_empty()
            || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(CredentialError::InvalidReference);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialOperation {
    Put,
    Get,
    Remove,
    RestrictPermissions,
    Validate,
    Identity,
}

/// Errors contain operation and numeric status only, never input or token data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialError {
    InvalidReference,
    InvalidToken,
    RandomUnavailable,
    NotFound,
    InvalidStoredCredential,
    UnsupportedPlatform,
    UnsupportedIdentity,
    Native {
        operation: CredentialOperation,
        code: i64,
    },
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidReference => formatter.write_str("invalid credential reference"),
            Self::InvalidToken => formatter.write_str("invalid bearer token encoding"),
            Self::RandomUnavailable => formatter.write_str("system randomness is unavailable"),
            Self::NotFound => formatter.write_str("credential was not found"),
            Self::InvalidStoredCredential => formatter.write_str("native credential is invalid"),
            Self::UnsupportedPlatform => {
                formatter.write_str("native credential store is unavailable")
            }
            Self::UnsupportedIdentity => {
                formatter.write_str("credential store identity is unsupported")
            }
            Self::Native { operation, code } => {
                write!(
                    formatter,
                    "native credential {operation:?} failed with status {code}"
                )
            }
        }
    }
}

impl std::error::Error for CredentialError {}

/// Credential storage boundary. A test implementation must be injected
/// explicitly; production never substitutes one after a native-store error.
pub trait CredentialStore: Send + Sync {
    fn put(&self, reference: &CredentialRef, token: &SecretToken) -> Result<(), CredentialError>;
    fn get(&self, reference: &CredentialRef) -> Result<SecretToken, CredentialError>;
    /// Removal is idempotent when the credential does not exist.
    fn remove(&self, reference: &CredentialRef) -> Result<(), CredentialError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NativeCredentialStore;

impl NativeCredentialStore {
    pub fn put(&self, reference: &str, token: &SecretToken) -> Result<(), CredentialError> {
        CredentialStore::put(self, &CredentialRef::new(reference)?, token)
    }

    pub fn get(&self, reference: &str) -> Result<SecretToken, CredentialError> {
        CredentialStore::get(self, &CredentialRef::new(reference)?)
    }

    pub fn remove(&self, reference: &str) -> Result<(), CredentialError> {
        CredentialStore::remove(self, &CredentialRef::new(reference)?)
    }
}

impl CredentialStore for NativeCredentialStore {
    fn put(&self, reference: &CredentialRef, token: &SecretToken) -> Result<(), CredentialError> {
        native::put(reference, token)
    }

    fn get(&self, reference: &CredentialRef) -> Result<SecretToken, CredentialError> {
        native::get(reference)
    }

    fn remove(&self, reference: &CredentialRef) -> Result<(), CredentialError> {
        native::remove(reference)
    }
}

#[cfg(target_os = "windows")]
mod native {
    use super::*;
    use std::ptr;
    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
    use windows_sys::Win32::Security::Credentials::{
        CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_PERSIST_SESSION, CRED_TYPE_GENERIC, CREDENTIALW,
        CredDeleteW, CredFree, CredReadW, CredWriteW,
    };

    // https://learn.microsoft.com/windows/win32/api/wincred/ns-wincred-credentialw
    // Generic application blobs are arbitrary bytes. SESSION prevents roaming
    // and visibility in another logon session of the same Windows account.
    pub(super) fn put(
        reference: &CredentialRef,
        token: &SecretToken,
    ) -> Result<(), CredentialError> {
        let mut name = wide(reference.as_str());
        let mut username = wide("MMMM coordinator");
        // The API field is mutable but CredWriteW is documented as an input.
        // Use a separately owned wiped buffer rather than cast an immutable borrow.
        let mut blob = Zeroizing::new([0_u8; TOKEN_BYTES]);
        blob.copy_from_slice(token.expose_secret());
        // SAFETY: all-zero numeric/pointer fields are valid in CREDENTIALW;
        // required fields below point to buffers live through the synchronous call.
        let mut credential: CREDENTIALW = unsafe { std::mem::zeroed() };
        credential.Type = CRED_TYPE_GENERIC;
        credential.TargetName = name.as_mut_ptr();
        credential.CredentialBlobSize = TOKEN_BYTES as u32;
        credential.CredentialBlob = blob.as_mut_ptr();
        credential.Persist = CRED_PERSIST_SESSION;
        credential.UserName = username.as_mut_ptr();
        // SAFETY: credential and all nested buffers remain valid until return.
        if unsafe { CredWriteW(&credential, 0) } == 0 {
            return Err(last_error(CredentialOperation::Put));
        }
        Ok(())
    }

    pub(super) fn get(reference: &CredentialRef) -> Result<SecretToken, CredentialError> {
        let name = wide(reference.as_str());
        let mut credential = ptr::null_mut();
        // SAFETY: name is NUL-terminated; the out pointer belongs to this call.
        if unsafe { CredReadW(name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) } == 0 {
            return Err(last_error(CredentialOperation::Get));
        }
        if credential.is_null() {
            return Err(CredentialError::InvalidStoredCredential);
        }
        let allocation = CredentialAllocation(credential);
        // SAFETY: success returned a valid CREDENTIALW allocation owned by guard.
        let entry = unsafe { &*allocation.0 };
        if entry.Type != CRED_TYPE_GENERIC
            || entry.Persist != CRED_PERSIST_SESSION
            || entry.CredentialBlobSize != TOKEN_BYTES as u32
            || entry.CredentialBlob.is_null()
        {
            return Err(CredentialError::InvalidStoredCredential);
        }
        let mut token = SecretToken([0; TOKEN_BYTES]);
        // SAFETY: verified 32-byte non-null API allocation is live during copying.
        token.0.copy_from_slice(unsafe {
            std::slice::from_raw_parts(entry.CredentialBlob, TOKEN_BYTES)
        });
        Ok(token)
    }

    pub(super) fn remove(reference: &CredentialRef) -> Result<(), CredentialError> {
        let name = wide(reference.as_str());
        // SAFETY: name is NUL-terminated and live through the call.
        if unsafe { CredDeleteW(name.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            let error = last_error(CredentialOperation::Remove);
            if error != CredentialError::NotFound {
                return Err(error);
            }
        }
        Ok(())
    }

    struct CredentialAllocation(*mut CREDENTIALW);

    impl Drop for CredentialAllocation {
        fn drop(&mut self) {
            // SAFETY: guard owns the successful CredReadW allocation exclusively.
            // The API guarantees its blob length; cap malformed values before
            // forming a mutable slice, then always release with CredFree.
            unsafe {
                let entry = &mut *self.0;
                if !entry.CredentialBlob.is_null()
                    && entry.CredentialBlobSize <= CRED_MAX_CREDENTIAL_BLOB_SIZE
                {
                    std::slice::from_raw_parts_mut(
                        entry.CredentialBlob,
                        entry.CredentialBlobSize as usize,
                    )
                    .zeroize();
                }
                CredFree(self.0.cast());
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn last_error(operation: CredentialOperation) -> CredentialError {
        // SAFETY: reads this thread's last status immediately after a failed API.
        let code = unsafe { GetLastError() };
        if code == ERROR_NOT_FOUND {
            CredentialError::NotFound
        } else {
            CredentialError::Native {
                operation,
                code: i64::from(code),
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use std::ffi::CString;

    // UAPI constants and ABI are documented in the kernel key retention service:
    // https://www.kernel.org/doc/html/latest/security/keys/core.html
    const USER_KEYRING: libc::c_long = -4;
    const KEYCTL_UPDATE: libc::c_long = 2;
    const KEYCTL_REVOKE: libc::c_long = 3;
    const KEYCTL_SETPERM: libc::c_long = 5;
    const KEYCTL_DESCRIBE: libc::c_long = 6;
    const KEYCTL_UNLINK: libc::c_long = 9;
    const KEYCTL_SEARCH: libc::c_long = 10;
    const KEYCTL_READ: libc::c_long = 11;
    // Owner UID only: view/read/write/search/link/setattr. No possessor, group,
    // or other permissions, even when a key has been linked into another ring.
    const USER_ONLY_PERMISSIONS: libc::c_long = 0x003f_0000;

    pub(super) fn put(
        reference: &CredentialRef,
        token: &SecretToken,
    ) -> Result<(), CredentialError> {
        check_identity()?;
        let description = description(reference)?;
        // User keys reject an empty payload. First create/update a non-secret
        // one-byte sentinel, then restrict it before introducing secret bytes.
        // The sentinel cannot pass get's exact 32-byte token-length check.
        // Thus default possessor rights never expose a new token.
        let sentinel = [0_u8; 1];
        // SAFETY: syscall arguments have the documented native-word ABI; the
        // strings are NUL-terminated and the one-byte payload is live for the call.
        let serial = unsafe {
            libc::syscall(
                libc::SYS_add_key,
                c"user".as_ptr(),
                description.as_ptr(),
                sentinel.as_ptr(),
                sentinel.len(),
                USER_KEYRING,
            )
        };
        let serial = checked_serial(serial, CredentialOperation::Put)?;
        if let Err(error) = keyctl(
            KEYCTL_SETPERM,
            serial,
            USER_ONLY_PERMISSIONS,
            0,
            0,
            CredentialOperation::RestrictPermissions,
        ) {
            let _ = keyctl(KEYCTL_REVOKE, serial, 0, 0, 0, CredentialOperation::Remove);
            return Err(error);
        }
        validate(serial, reference)?;
        if let Err(error) = keyctl(
            KEYCTL_UPDATE,
            serial,
            token.expose_secret().as_ptr() as libc::c_long,
            TOKEN_BYTES as libc::c_long,
            0,
            CredentialOperation::Put,
        ) {
            let _ = keyctl(KEYCTL_REVOKE, serial, 0, 0, 0, CredentialOperation::Remove);
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn get(reference: &CredentialRef) -> Result<SecretToken, CredentialError> {
        check_identity()?;
        let serial = find(reference)?;
        validate(serial, reference)?;
        let mut token = SecretToken([0; TOKEN_BYTES]);
        let length = keyctl(
            KEYCTL_READ,
            serial,
            token.0.as_mut_ptr() as libc::c_long,
            TOKEN_BYTES as libc::c_long,
            0,
            CredentialOperation::Get,
        )?;
        if length != TOKEN_BYTES as libc::c_long {
            return Err(CredentialError::InvalidStoredCredential);
        }
        validate(serial, reference)?;
        Ok(token)
    }

    pub(super) fn remove(reference: &CredentialRef) -> Result<(), CredentialError> {
        check_identity()?;
        let serial = match find(reference) {
            Ok(serial) => serial,
            Err(CredentialError::NotFound) => return Ok(()),
            Err(error) => return Err(error),
        };
        validate(serial, reference)?;
        // Revoke first: unlinked copies of the same key must stop being readable.
        match keyctl(KEYCTL_REVOKE, serial, 0, 0, 0, CredentialOperation::Remove) {
            Ok(_) | Err(CredentialError::NotFound) => {}
            Err(error) => return Err(error),
        }
        match keyctl(
            KEYCTL_UNLINK,
            serial,
            USER_KEYRING,
            0,
            0,
            CredentialOperation::Remove,
        ) {
            Ok(_) | Err(CredentialError::NotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn check_identity() -> Result<(), CredentialError> {
        // SAFETY: these scalar identity queries take no pointers or arguments.
        if unsafe { libc::getuid() != libc::geteuid() } {
            return Err(CredentialError::UnsupportedIdentity);
        }
        Ok(())
    }

    fn description(reference: &CredentialRef) -> Result<CString, CredentialError> {
        CString::new(reference.as_str()).map_err(|_| CredentialError::InvalidReference)
    }

    fn find(reference: &CredentialRef) -> Result<libc::c_long, CredentialError> {
        let description = description(reference)?;
        let serial = keyctl(
            KEYCTL_SEARCH,
            USER_KEYRING,
            c"user".as_ptr() as libc::c_long,
            description.as_ptr() as libc::c_long,
            0,
            CredentialOperation::Get,
        )?;
        checked_serial(serial, CredentialOperation::Get)
    }

    fn validate(serial: libc::c_long, reference: &CredentialRef) -> Result<(), CredentialError> {
        let mut metadata = [0_u8; 256];
        let length = keyctl(
            KEYCTL_DESCRIBE,
            serial,
            metadata.as_mut_ptr() as libc::c_long,
            metadata.len() as libc::c_long,
            0,
            CredentialOperation::Validate,
        )?;
        if length <= 0 || length as usize > metadata.len() || metadata[length as usize - 1] != 0 {
            return Err(CredentialError::InvalidStoredCredential);
        }
        let text = std::str::from_utf8(&metadata[..length as usize - 1])
            .map_err(|_| CredentialError::InvalidStoredCredential)?;
        let fields: Vec<_> = text.splitn(5, ';').collect();
        // SAFETY: scalar current-user query, used only to verify native metadata.
        let uid = unsafe { libc::geteuid() };
        if fields.len() != 5
            || fields[0] != "user"
            || fields[1].parse::<u32>().ok() != Some(uid)
            || u32::from_str_radix(fields[3], 16).ok() != Some(USER_ONLY_PERMISSIONS as u32)
            || fields[4] != reference.as_str()
        {
            return Err(CredentialError::InvalidStoredCredential);
        }
        Ok(())
    }

    fn checked_serial(
        serial: libc::c_long,
        operation: CredentialOperation,
    ) -> Result<libc::c_long, CredentialError> {
        if serial == -1 {
            return Err(last_error(operation));
        }
        if serial <= 0 || serial > i32::MAX as libc::c_long {
            return Err(CredentialError::InvalidStoredCredential);
        }
        Ok(serial)
    }

    fn keyctl(
        command: libc::c_long,
        a: libc::c_long,
        b: libc::c_long,
        c: libc::c_long,
        d: libc::c_long,
        operation: CredentialOperation,
    ) -> Result<libc::c_long, CredentialError> {
        // SAFETY: each call above supplies the documented keyctl native-word ABI;
        // pointed-to buffers are bounded and live through this synchronous call.
        let result = unsafe { libc::syscall(libc::SYS_keyctl, command, a, b, c, d) };
        if result == -1 {
            Err(last_error(operation))
        } else {
            Ok(result)
        }
    }

    fn last_error(operation: CredentialOperation) -> CredentialError {
        let code = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if matches!(
            code,
            libc::ENOKEY | libc::EKEYEXPIRED | libc::EKEYREVOKED | libc::ENOENT
        ) {
            CredentialError::NotFound
        } else {
            CredentialError::Native {
                operation,
                code: i64::from(code),
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::ffi::c_void;
    use std::ptr;

    type CfRef = *const c_void;
    const SUCCESS: i32 = 0;
    const NOT_FOUND: i32 = -25300;
    const UTF8: u32 = 0x0800_0100;

    // CoreFoundation's callback structs contain one CFIndex then function pointers.
    // We use the framework's constant callbacks; these declarations give the FFI
    // symbols their documented C layout without constructing custom callbacks.
    #[repr(C)]
    struct DictionaryKeyCallbacks {
        version: isize,
        retain: Option<unsafe extern "C" fn(CfRef, CfRef) -> CfRef>,
        release: Option<unsafe extern "C" fn(CfRef, CfRef)>,
        copy_description: Option<unsafe extern "C" fn(CfRef) -> CfRef>,
        equal: Option<unsafe extern "C" fn(CfRef, CfRef) -> u8>,
        hash: Option<unsafe extern "C" fn(CfRef) -> usize>,
    }

    #[repr(C)]
    struct DictionaryValueCallbacks {
        version: isize,
        retain: Option<unsafe extern "C" fn(CfRef, CfRef) -> CfRef>,
        release: Option<unsafe extern "C" fn(CfRef, CfRef)>,
        copy_description: Option<unsafe extern "C" fn(CfRef) -> CfRef>,
        equal: Option<unsafe extern "C" fn(CfRef, CfRef) -> u8>,
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFTypeDictionaryKeyCallBacks: DictionaryKeyCallbacks;
        static kCFTypeDictionaryValueCallBacks: DictionaryValueCallbacks;
        static kCFBooleanTrue: CfRef;
        static kCFBooleanFalse: CfRef;
        fn CFDictionaryCreateMutable(
            allocator: CfRef,
            capacity: isize,
            key_callbacks: *const DictionaryKeyCallbacks,
            value_callbacks: *const DictionaryValueCallbacks,
        ) -> *mut c_void;
        fn CFDictionarySetValue(dictionary: *mut c_void, key: CfRef, value: CfRef);
        fn CFStringCreateWithBytes(
            allocator: CfRef,
            bytes: *const u8,
            count: isize,
            encoding: u32,
            external: u8,
        ) -> CfRef;
        fn CFDataCreate(allocator: CfRef, bytes: *const u8, count: isize) -> CfRef;
        fn CFDataGetLength(data: CfRef) -> isize;
        fn CFDataGetBytePtr(data: CfRef) -> *const u8;
        fn CFDataGetTypeID() -> usize;
        fn CFGetTypeID(value: CfRef) -> usize;
        fn CFRelease(value: CfRef);
    }

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecClass: CfRef;
        static kSecClassGenericPassword: CfRef;
        static kSecAttrService: CfRef;
        static kSecAttrAccount: CfRef;
        static kSecAttrSynchronizable: CfRef;
        static kSecAttrAccessible: CfRef;
        static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CfRef;
        static kSecUseDataProtectionKeychain: CfRef;
        static kSecUseAuthenticationUI: CfRef;
        static kSecUseAuthenticationUIFail: CfRef;
        static kSecValueData: CfRef;
        static kSecReturnData: CfRef;
        static kSecMatchLimit: CfRef;
        static kSecMatchLimitOne: CfRef;
        fn SecItemAdd(attributes: CfRef, result: *mut CfRef) -> i32;
        fn SecItemUpdate(query: CfRef, attributes: CfRef) -> i32;
        fn SecItemCopyMatching(query: CfRef, result: *mut CfRef) -> i32;
        fn SecItemDelete(query: CfRef) -> i32;
    }

    // https://developer.apple.com/documentation/security/secitemadd(_:_:)
    // https://developer.apple.com/documentation/security/ksecuseauthenticationui
    // Explicitly select Data Protection Keychain: the legacy implementation
    // ignores the per-query no-UI attribute, and an unspecified query can merge
    // results from both stores. Signing/entitlement, lock or availability errors
    // are reported without a legacy fallback or global interaction mutation.
    pub(super) fn put(
        reference: &CredentialRef,
        token: &SecretToken,
    ) -> Result<(), CredentialError> {
        let query = query(reference)?;
        // SAFETY: source bytes are valid for the bounded synchronous copy.
        let data = Owned::new(unsafe {
            CFDataCreate(
                ptr::null(),
                token.expose_secret().as_ptr(),
                TOKEN_BYTES as isize,
            )
        })?;
        let attributes = dictionary()?;
        // SAFETY: live CF dictionary and framework constants have valid types;
        // dictionaries retain data through the framework's CFType callbacks.
        unsafe {
            CFDictionarySetValue(attributes.mutable(), kSecValueData, data.0);
            CFDictionarySetValue(
                attributes.mutable(),
                kSecAttrAccessible,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            );
        }
        // SAFETY: query and attributes are owned and live until return.
        let update = unsafe { SecItemUpdate(query.0, attributes.0) };
        if update == SUCCESS {
            return Ok(());
        }
        if update != NOT_FOUND {
            return Err(status(CredentialOperation::Put, update));
        }
        // SAFETY: dictionary retains the data; null result requests no copy.
        let add = unsafe {
            CFDictionarySetValue(query.mutable(), kSecValueData, data.0);
            CFDictionarySetValue(
                query.mutable(),
                kSecAttrAccessible,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            );
            SecItemAdd(query.0, ptr::null_mut())
        };
        if add == SUCCESS {
            Ok(())
        } else {
            // A duplicate from a concurrent creator is an error too. Do not
            // retry the write after ownership has become uncertain.
            Err(status(CredentialOperation::Put, add))
        }
    }

    pub(super) fn get(reference: &CredentialRef) -> Result<SecretToken, CredentialError> {
        let query = query(reference)?;
        // SAFETY: valid CF dictionary/constants; only one bounded item is returned.
        unsafe {
            CFDictionarySetValue(query.mutable(), kSecReturnData, kCFBooleanTrue);
            CFDictionarySetValue(query.mutable(), kSecMatchLimit, kSecMatchLimitOne);
        }
        let mut result = ptr::null();
        // SAFETY: query is live; output ownership transfers to this call on success.
        let code = unsafe { SecItemCopyMatching(query.0, &mut result) };
        if code != SUCCESS {
            return Err(status(CredentialOperation::Get, code));
        }
        let data = Owned::new(result)?;
        // SAFETY: CFGetTypeID accepts a live CF object. Only use CFData APIs after
        // verifying the returned object is CFData and has exactly 32 bytes.
        if unsafe {
            CFGetTypeID(data.0) != CFDataGetTypeID()
                || CFDataGetLength(data.0) != TOKEN_BYTES as isize
        } {
            return Err(CredentialError::InvalidStoredCredential);
        }
        // SAFETY: data has the verified CFData type and is still owned.
        let bytes = unsafe { CFDataGetBytePtr(data.0) };
        if bytes.is_null() {
            return Err(CredentialError::InvalidStoredCredential);
        }
        let mut token = SecretToken([0; TOKEN_BYTES]);
        // SAFETY: CFData guarantees a live byte buffer of the verified size.
        token
            .0
            .copy_from_slice(unsafe { std::slice::from_raw_parts(bytes, TOKEN_BYTES) });
        // CFData is framework-owned immutable storage; release it normally.
        // Do not cast away immutability to claim erasure of an OS-owned copy.
        Ok(token)
    }

    pub(super) fn remove(reference: &CredentialRef) -> Result<(), CredentialError> {
        let query = query(reference)?;
        // SAFETY: query is a live retained dictionary with exact class/service/account.
        let code = unsafe { SecItemDelete(query.0) };
        if matches!(code, SUCCESS | NOT_FOUND) {
            Ok(())
        } else {
            Err(status(CredentialOperation::Remove, code))
        }
    }

    fn query(reference: &CredentialRef) -> Result<Owned, CredentialError> {
        let query = dictionary()?;
        let service = string("MMMM.coordinator")?;
        let account = string(reference.as_str())?;
        // SAFETY: framework symbols are live CF objects of documented types.
        // Builtin callbacks retain the service/account after their local guards drop.
        unsafe {
            CFDictionarySetValue(query.mutable(), kSecClass, kSecClassGenericPassword);
            CFDictionarySetValue(query.mutable(), kSecAttrService, service.0);
            CFDictionarySetValue(query.mutable(), kSecAttrAccount, account.0);
            CFDictionarySetValue(query.mutable(), kSecAttrSynchronizable, kCFBooleanFalse);
            CFDictionarySetValue(
                query.mutable(),
                kSecUseDataProtectionKeychain,
                kCFBooleanTrue,
            );
            CFDictionarySetValue(
                query.mutable(),
                kSecUseAuthenticationUI,
                kSecUseAuthenticationUIFail,
            );
        }
        Ok(query)
    }

    fn dictionary() -> Result<Owned, CredentialError> {
        // SAFETY: callbacks are framework-provided immutable C-layout constants;
        // a null allocator selects the default allocator.
        Owned::new(unsafe {
            CFDictionaryCreateMutable(
                ptr::null(),
                0,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            )
            .cast_const()
        })
    }

    fn string(value: &str) -> Result<Owned, CredentialError> {
        // SAFETY: byte buffer is valid for the declared length; the API copies it.
        Owned::new(unsafe {
            CFStringCreateWithBytes(ptr::null(), value.as_ptr(), value.len() as isize, UTF8, 0)
        })
    }

    struct Owned(CfRef);

    impl Owned {
        fn new(value: CfRef) -> Result<Self, CredentialError> {
            if value.is_null() {
                Err(CredentialError::InvalidStoredCredential)
            } else {
                Ok(Self(value))
            }
        }

        fn mutable(&self) -> *mut c_void {
            // Used only for objects created by CFDictionaryCreateMutable.
            self.0.cast_mut()
        }
    }

    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: this guard owns one non-null Create/Copy reference.
            unsafe { CFRelease(self.0) };
        }
    }

    fn status(operation: CredentialOperation, code: i32) -> CredentialError {
        if code == NOT_FOUND {
            CredentialError::NotFound
        } else {
            CredentialError::Native {
                operation,
                code: i64::from(code),
            }
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
mod native {
    use super::*;

    pub(super) fn put(_: &CredentialRef, _: &SecretToken) -> Result<(), CredentialError> {
        Err(CredentialError::UnsupportedPlatform)
    }
    pub(super) fn get(_: &CredentialRef) -> Result<SecretToken, CredentialError> {
        Err(CredentialError::UnsupportedPlatform)
    }
    pub(super) fn remove(_: &CredentialRef) -> Result<(), CredentialError> {
        Err(CredentialError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_encoding_is_canonical_and_errors_do_not_echo_input() {
        // Authored synthetic bytes: no native store or actual credential is read.
        let encoded = "0123456789abcdef".repeat(4);
        let token = SecretToken::parse(&encoded).expect("synthetic token");
        assert_eq!(&**token.bearer(), encoded);
        for malformed in [
            "",
            "a",
            &"a".repeat(63),
            &"a".repeat(65),
            &"A".repeat(64),
            &"g".repeat(64),
            &"é".repeat(32),
        ] {
            assert!(matches!(
                SecretToken::parse(malformed),
                Err(CredentialError::InvalidToken)
            ));
        }
        assert_eq!(
            CredentialError::InvalidToken.to_string(),
            "invalid bearer token encoding"
        );
    }

    #[test]
    fn public_reference_is_bounded_and_has_no_case_or_path_aliases() {
        let exact = format!(
            "{REFERENCE_PREFIX}{}",
            "a".repeat(MAX_REFERENCE_BYTES - REFERENCE_PREFIX.len())
        );
        assert_eq!(
            CredentialRef::new(&exact)
                .expect("bounded reference")
                .as_str(),
            exact
        );
        assert!(CredentialRef::new(&format!("{exact}a")).is_err());
        for invalid in [
            "",
            "other.coordinator.abc",
            "MMMM.coordinator.",
            "MMMM.coordinator.ABC",
            "MMMM.coordinator.-abc",
            "MMMM.coordinator.abc_",
            "MMMM.coordinator.abc/def",
            "MMMM.coordinator.abc\\def",
            "MMMM.coordinator.abc\0",
            "MMMM.coordinator.é",
            "MMMM.coordinator.a b",
        ] {
            assert!(matches!(
                CredentialRef::new(invalid),
                Err(CredentialError::InvalidReference)
            ));
        }
        assert!(CredentialRef::new("MMMM.coordinator.epoch-0_1.2").is_ok());
    }
}

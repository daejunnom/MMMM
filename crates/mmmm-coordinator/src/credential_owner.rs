//! OS 소유 계정을 공개 principal로 변환한다. 이 값은 권한이나 bearer가 아니다.
//! 서버가 검증한 로컬 계정 경계에서만 사용하며 사용자 JSON으로 대체하지 않는다.
//! 이름, 홈 경로, SID 문자열과 원래 UID를 저장하거나 출력하지 않는다.

#![forbid(unsafe_op_in_unsafe_fn)]

use super::CredentialError;
use mmmm_contracts::PrincipalId;
use sha2::{Digest, Sha256};

/// Same-account native peer 인증 경계의 현재 프로세스 소유 계정이다.
/// 해시는 익명성이나 전역 계정 유일성의 증명이 아니다. OS 계정 삭제/UID 재사용,
/// 다른 기기와 다른 OS의 계정 정책은 해당 OS 보안 경계의 수명을 따른다.
pub fn local_owner_principal() -> Result<PrincipalId, CredentialError> {
    platform::current()
}

fn principal(os: &[u8], identity: &[u8]) -> Result<PrincipalId, CredentialError> {
    let mut digest = Sha256::new();
    digest.update(b"MMMM.local-owner-principal.v1\0");
    digest.update((os.len() as u32).to_be_bytes());
    digest.update(os);
    digest.update((identity.len() as u32).to_be_bytes());
    digest.update(identity);
    PrincipalId::new(format!("local-{:x}", digest.finalize()))
        .map_err(|_| CredentialError::UnsupportedIdentity)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use super::*;
    pub(super) fn current() -> Result<PrincipalId, CredentialError> {
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getuid.html
        // SAFETY: scalar process identity queries; no allocation or file access.
        let (real, effective) = unsafe { (libc::getuid(), libc::geteuid()) };
        if real != effective || real == libc::uid_t::MAX {
            return Err(CredentialError::UnsupportedIdentity);
        }
        #[cfg(target_os = "linux")]
        let os = b"linux".as_slice();
        #[cfg(target_os = "macos")]
        let os = b"macos".as_slice();
        principal(os, &u64::from(real).to_be_bytes())
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::super::CredentialOperation;
    use super::*;
    use std::{
        ffi::c_void,
        mem,
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{GetLastError, INVALID_HANDLE_VALUE},
        Security::{GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_USER, TokenUser},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    fn failed() -> CredentialError {
        // SAFETY: immediate failed native query's thread-local numeric status.
        CredentialError::Native {
            operation: CredentialOperation::Identity,
            code: i64::from(unsafe { GetLastError() }),
        }
    }
    pub(super) fn current() -> Result<PrincipalId, CredentialError> {
        const TOKEN_QUERY: u32 = 8;
        const INSUFFICIENT_BUFFER: u32 = 122;
        let mut token = ptr::null_mut();
        // https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        // SAFETY: current-process pseudo handle is valid; token output transfers
        // one non-inherited read-only owned native handle on success.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(failed());
        }
        if token.is_null() || token == INVALID_HANDLE_VALUE {
            return Err(CredentialError::UnsupportedIdentity);
        }
        // SAFETY: OpenProcessToken returned a newly owned handle exactly once.
        let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
        let mut required = 0_u32;
        // https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
        // SAFETY: documented size query; requests TokenUser, never credentials.
        let queried = unsafe {
            GetTokenInformation(
                token.as_raw_handle().cast(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut required,
            )
        };
        if queried != 0 || unsafe { GetLastError() } != INSUFFICIENT_BUFFER {
            return Err(failed());
        }
        if required < mem::size_of::<TOKEN_USER>() as u32 || required > 65_536 {
            return Err(CredentialError::UnsupportedIdentity);
        }
        let mut storage = vec![0_usize; (required as usize).div_ceil(mem::size_of::<usize>())];
        let capacity = storage.len() * mem::size_of::<usize>();
        // SAFETY: aligned and bounded allocation covers the complete structure.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle().cast(),
                TokenUser,
                storage.as_mut_ptr().cast(),
                capacity as u32,
                &mut required,
            )
        } == 0
        {
            return Err(failed());
        }
        if required < mem::size_of::<TOKEN_USER>() as u32 || required as usize > capacity {
            return Err(CredentialError::UnsupportedIdentity);
        }
        // SAFETY: TokenUser success initialized a live properly aligned prefix.
        let sid = unsafe { (*storage.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let begin = storage.as_ptr() as usize;
        let end = begin + required as usize;
        let address = sid as usize;
        if address < begin || address.checked_add(8).is_none_or(|limit| limit > end) {
            return Err(CredentialError::UnsupportedIdentity);
        }
        // SAFETY: bounded SID header includes SubAuthorityCount at offset one.
        let subauthorities = unsafe { *sid.cast::<u8>().add(1) } as usize;
        let expected = 8 + 4 * subauthorities;
        if subauthorities > 15
            || address
                .checked_add(expected)
                .is_none_or(|limit| limit > end)
        {
            return Err(CredentialError::UnsupportedIdentity);
        }
        // SAFETY: full SID representation lies inside this live owned allocation.
        if unsafe { IsValidSid(sid.cast::<c_void>()) } == 0
            || unsafe { GetLengthSid(sid) } as usize != expected
        {
            return Err(CredentialError::UnsupportedIdentity);
        }
        // SAFETY: validated exact binary SID bytes remain live through hashing.
        principal(b"windows", unsafe {
            std::slice::from_raw_parts(sid.cast::<u8>(), expected)
        })
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
mod platform {
    use super::*;
    pub(super) fn current() -> Result<PrincipalId, CredentialError> {
        Err(CredentialError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opaque_owner_id_is_stable_and_domain_separated() {
        let identity = 42_u64.to_be_bytes();
        let first = principal(b"linux", &identity).unwrap();
        assert_eq!(first, principal(b"linux", &identity).unwrap());
        assert_ne!(first, principal(b"macos", &identity).unwrap());
        assert_ne!(first, principal(b"linux", &43_u64.to_be_bytes()).unwrap());
        assert!(first.as_str().starts_with("local-"));
        assert_eq!(first.as_str().len(), 70);
    }
}

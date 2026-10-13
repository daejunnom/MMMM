//! User-private discovery metadata. This file contains a credential reference,
//! never the capability secret. The caller must already hold the data-root lock.
//! Existing unsafe directories and malformed/stale files are preserved, not
//! silently repaired or adopted.

use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

const RECORD_LIMIT: usize = 4096;
const RECORD_NAME: &str = "coordinator-endpoint.json";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointRecord {
    pub schema_version: u32,
    pub contract_version: String,
    pub address: SocketAddr,
    pub path: String,
    pub coordinator_epoch: String,
    pub credential_ref: String,
}

impl EndpointRecord {
    pub fn validate(&self) -> Result<(), EndpointError> {
        if self.schema_version != 1
            || self.contract_version != "0.2.0"
            || self.address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST)
            || self.address.port() == 0
            || self.path != "/rpc"
            || mmmm_contracts::SessionEpoch::new(&self.coordinator_epoch).is_err()
            || !safe_credential_ref(&self.credential_ref)
        {
            return Err(EndpointError::InvalidRecord);
        }
        Ok(())
    }
}

fn safe_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn safe_credential_ref(value: &str) -> bool {
    value
        .strip_prefix("MMMM.coordinator.")
        .is_some_and(|suffix| {
            value.len() <= 128
                && safe_id(suffix, 111)
                && suffix.bytes().all(|byte| !byte.is_ascii_uppercase())
        })
}

#[derive(Debug)]
pub enum EndpointError {
    UnsafePath,
    UnsafePermissions,
    Missing,
    InvalidRecord,
    RecordTooLarge,
    EpochConflict,
    Busy,
    Io(io::Error),
}

impl fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafePath => "endpoint path is not an ordinary absolute local path",
            Self::UnsafePermissions => "endpoint storage is not private to the current user",
            Self::Missing => "coordinator endpoint metadata is absent",
            Self::InvalidRecord => "coordinator endpoint metadata is invalid",
            Self::RecordTooLarge => "coordinator endpoint metadata exceeds its byte limit",
            Self::EpochConflict => "existing endpoint belongs to a different coordinator epoch",
            Self::Busy => "endpoint metadata is already being updated",
            Self::Io(_) => "endpoint metadata I/O failed",
        })
    }
}

impl Error for EndpointError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for EndpointError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::NotFound {
            Self::Missing
        } else {
            Self::Io(error)
        }
    }
}

/// Only discovery metadata lives here; product state and credentials have other
/// owners. Opening a runtime directory does not authorize opening a data root.
pub struct RuntimeDirectory {
    inner: platform::Directory,
    transaction: Mutex<()>,
}

impl fmt::Debug for RuntimeDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeDirectory")
            .finish_non_exhaustive()
    }
}

impl RuntimeDirectory {
    pub fn open(path: &Path) -> Result<Self, EndpointError> {
        Ok(Self {
            inner: platform::Directory::open(path)?,
            transaction: Mutex::new(()),
        })
    }

    /// Verified private runtime path for the OS peer bootstrap transport. This
    /// is local configuration, never a client-supplied path or a log field.
    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    pub fn publish(&self, record: &EndpointRecord) -> Result<(), EndpointError> {
        record.validate()?;
        let bytes = serde_json::to_vec(record).map_err(|_| EndpointError::InvalidRecord)?;
        if bytes.len() > RECORD_LIMIT {
            return Err(EndpointError::RecordTooLarge);
        }
        let _transaction = self
            .transaction
            .try_lock()
            .map_err(|_| EndpointError::Busy)?;
        let _platform_lock = self.inner.lock()?;
        match self.inner.load() {
            Ok(existing) if existing.coordinator_epoch != record.coordinator_epoch => {
                return Err(EndpointError::EpochConflict);
            }
            Ok(_) | Err(EndpointError::Missing) => (),
            Err(error) => return Err(error),
        }
        self.inner.publish(&bytes)
    }

    pub fn load(&self) -> Result<EndpointRecord, EndpointError> {
        let _transaction = self
            .transaction
            .try_lock()
            .map_err(|_| EndpointError::Busy)?;
        let _platform_lock = self.inner.lock()?;
        self.inner.load()
    }

    /// Returns false for an absent file or a different *valid* epoch. Malformed
    /// files return an error and are retained for diagnosis.
    pub fn remove_if_epoch(&self, epoch: &str) -> Result<bool, EndpointError> {
        if mmmm_contracts::SessionEpoch::new(epoch).is_err() {
            return Err(EndpointError::InvalidRecord);
        }
        let _transaction = self
            .transaction
            .try_lock()
            .map_err(|_| EndpointError::Busy)?;
        let _platform_lock = self.inner.lock()?;
        self.inner.remove_if_epoch(epoch)
    }
}

fn read_record(file: &mut std::fs::File) -> Result<EndpointRecord, EndpointError> {
    if file.metadata()?.len() > RECORD_LIMIT as u64 {
        return Err(EndpointError::RecordTooLarge);
    }
    let mut bytes = Vec::with_capacity(RECORD_LIMIT + 1);
    file.take((RECORD_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > RECORD_LIMIT {
        return Err(EndpointError::RecordTooLarge);
    }
    // Struct deserialization rejects duplicate and unknown fields as well as
    // malformed JSON. No untyped intermediary discards duplicate fields.
    let record: EndpointRecord =
        serde_json::from_slice(&bytes).map_err(|_| EndpointError::InvalidRecord)?;
    record.validate()?;
    Ok(record)
}

fn temporary_name() -> String {
    format!(
        "endpoint-{}-{}.tmp",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::{
        ffi::{CString, OsStr},
        fs::File,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
        path::{Component, PathBuf},
    };

    pub(super) struct Directory {
        file: File,
        path: PathBuf,
    }

    fn name(value: &OsStr) -> Result<CString, EndpointError> {
        CString::new(value.as_bytes()).map_err(|_| EndpointError::UnsafePath)
    }

    fn open_at(
        parent: &File,
        name: &CString,
        flags: i32,
        mode: libc::mode_t,
    ) -> Result<File, EndpointError> {
        // SAFETY: name is NUL-terminated; parent is a live directory handle.
        // O_NOFOLLOW is always requested, and FromRawFd owns the successful fd.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: fd is new, valid, and transferred exactly once.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn private(file: &File, directory: bool) -> Result<(), EndpointError> {
        let metadata = file.metadata()?;
        if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
            return Err(EndpointError::UnsafePath);
        }
        // SAFETY: geteuid takes no pointers or arguments.
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
            || (!directory && metadata.nlink() != 1)
        {
            return Err(EndpointError::UnsafePermissions);
        }
        Ok(())
    }

    pub(super) struct Lock<'a>(&'a File);
    impl Drop for Lock<'_> {
        fn drop(&mut self) {
            // SAFETY: this lock is attached to a live directory descriptor.
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }

    impl Directory {
        pub(super) fn open(path: &Path) -> Result<Self, EndpointError> {
            if !path.is_absolute() {
                return Err(EndpointError::UnsafePath);
            }
            let components: Vec<_> = path.components().collect();
            if components.len() < 2
                || components.len() > 65
                || !matches!(components[0], Component::RootDir)
                || components[1..]
                    .iter()
                    .any(|part| !matches!(part, Component::Normal(_)))
            {
                return Err(EndpointError::UnsafePath);
            }
            let root = CString::new("/").map_err(|_| EndpointError::UnsafePath)?;
            // SAFETY: literal path and fixed directory/no-follow flags.
            let fd = unsafe {
                libc::open(
                    root.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error().into());
            }
            // SAFETY: new fd is transferred exactly once.
            let mut parent = unsafe { File::from_raw_fd(fd) };
            for (index, part) in components[1..].iter().enumerate() {
                let Component::Normal(part) = part else {
                    return Err(EndpointError::UnsafePath);
                };
                let child = name(part)?;
                let last = index + 2 == components.len();
                let next = match open_at(&parent, &child, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
                    Ok(file) => file,
                    Err(EndpointError::Missing) if last => {
                        // SAFETY: anchored parent and one validated child name;
                        // no recursive mkdir or adoption of a different path.
                        if unsafe { libc::mkdirat(parent.as_raw_fd(), child.as_ptr(), 0o700) } != 0
                        {
                            return Err(io::Error::last_os_error().into());
                        }
                        parent.sync_all()?;
                        open_at(&parent, &child, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
                    }
                    Err(error) => return Err(error),
                };
                parent = next;
            }
            private(&parent, true)?;
            Ok(Self {
                file: parent,
                path: path.to_path_buf(),
            })
        }

        pub(super) fn path(&self) -> &Path {
            &self.path
        }

        pub(super) fn lock(&self) -> Result<Lock<'_>, EndpointError> {
            private(&self.file, true)?;
            // SAFETY: live directory descriptor; nonblocking prevents an
            // unbounded startup/shutdown wait on another metadata operation.
            if unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    return Err(EndpointError::Busy);
                }
                return Err(error.into());
            }
            Ok(Lock(&self.file))
        }

        fn record_file(&self) -> Result<File, EndpointError> {
            let file = open_at(
                &self.file,
                &name(OsStr::new(RECORD_NAME))?,
                libc::O_RDONLY | libc::O_NONBLOCK,
                0,
            )?;
            private(&file, false)?;
            Ok(file)
        }

        pub(super) fn load(&self) -> Result<EndpointRecord, EndpointError> {
            read_record(&mut self.record_file()?)
        }

        pub(super) fn publish(&self, bytes: &[u8]) -> Result<(), EndpointError> {
            let pending = name(OsStr::new(&temporary_name()))?;
            let mut file = open_at(
                &self.file,
                &pending,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            private(&file, false)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            let final_name = name(OsStr::new(RECORD_NAME))?;
            // SAFETY: both names are single ordinary entries in the same
            // pinned directory. The directory flock covers all our writers.
            if unsafe {
                libc::renameat(
                    self.file.as_raw_fd(),
                    pending.as_ptr(),
                    self.file.as_raw_fd(),
                    final_name.as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error().into());
            }
            self.file.sync_all()?;
            Ok(())
        }

        pub(super) fn remove_if_epoch(&self, epoch: &str) -> Result<bool, EndpointError> {
            let record = match self.load() {
                Ok(record) => record,
                Err(EndpointError::Missing) => return Ok(false),
                Err(error) => return Err(error),
            };
            if record.coordinator_epoch != epoch {
                return Ok(false);
            }
            let entry = name(OsStr::new(RECORD_NAME))?;
            // SAFETY: only the validated ordinary file in this directory is
            // removed; flock prevents our old/new epoch writers from racing.
            if unsafe { libc::unlinkat(self.file.as_raw_fd(), entry.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            self.file.sync_all()?;
            Ok(true)
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        ffi::{OsStr, c_void},
        fs::File,
        mem::{MaybeUninit, offset_of, size_of},
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle},
        },
        path::{Component, PathBuf, Prefix},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree},
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, AddAccessAllowedAceEx,
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation,
            InitializeAcl, InitializeSecurityDescriptor, IsValidAcl, IsValidSid,
            SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
            SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FileDispositionInfo,
            FileRenameInfo, GetFileInformationByHandle, SetFileInformationByHandle,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    // Win32 access/attribute/control constants, scoped here to the native
    // boundary. No permission inference is made from Rust path metadata.
    const READ_CONTROL: u32 = 0x0002_0000;
    const DELETE: u32 = 0x0001_0000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
    const OPEN_EXISTING: u32 = 3;
    const CREATE_NEW: u32 = 1;
    const SHARE_READ: u32 = 1;
    const DIRECTORY: u32 = 0x10;
    const REPARSE_POINT: u32 = 0x400;
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const DACL_PROTECTED: u16 = 0x1000;
    const DACL_PRESENT: u16 = 0x0004;
    const TOKEN_QUERY: u32 = 0x0008;
    const OWNER_SECURITY_INFORMATION: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 4;

    struct UserSid {
        storage: Vec<usize>,
    }
    impl UserSid {
        fn current() -> Result<Self, EndpointError> {
            let mut token = ptr::null_mut();
            // SAFETY: pseudo process handle is valid; token receives an owned
            // handle which is closed on every path below.
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
                return Err(io::Error::last_os_error().into());
            }
            let result = (|| {
                let mut required = 0;
                // SAFETY: documented size-query call with null output buffer.
                unsafe {
                    GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut required);
                }
                if required < size_of::<TOKEN_USER>() as u32 || required > 65_536 {
                    return Err(EndpointError::UnsafePermissions);
                }
                let mut storage = vec![0usize; (required as usize).div_ceil(size_of::<usize>())];
                // SAFETY: usize-aligned writable buffer covers required bytes.
                if unsafe {
                    GetTokenInformation(
                        token,
                        TokenUser,
                        storage.as_mut_ptr().cast(),
                        required,
                        &mut required,
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error().into());
                }
                Ok(Self { storage })
            })();
            // SAFETY: token is the owned successful OpenProcessToken result.
            unsafe {
                CloseHandle(token);
            }
            result
        }

        fn pointer(&self) -> *mut c_void {
            // SAFETY: GetTokenInformation initialized a TOKEN_USER at this
            // aligned address; its SID remains inside the unchanged buffer.
            unsafe { (*(self.storage.as_ptr().cast::<TOKEN_USER>())).User.Sid }
        }
    }

    struct PrivateSecurity {
        descriptor: Box<SECURITY_DESCRIPTOR>,
        _acl: Vec<u32>,
    }
    impl PrivateSecurity {
        fn new(user: &UserSid, directory: bool) -> Result<Self, EndpointError> {
            // SAFETY: the token-provided SID is valid for this buffer lifetime.
            let sid_length = unsafe { GetLengthSid(user.pointer()) } as usize;
            if sid_length == 0 || sid_length > 1024 {
                return Err(EndpointError::UnsafePermissions);
            }
            let acl_length =
                size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid_length;
            let mut acl = vec![0u32; acl_length.div_ceil(size_of::<u32>())];
            let mut descriptor =
                Box::new(unsafe { MaybeUninit::<SECURITY_DESCRIPTOR>::zeroed().assume_init() });
            let descriptor_pointer: *mut c_void =
                (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast();
            // SAFETY: ACL/descriptor are correctly aligned and fully sized;
            // one owner SID ACE is installed before either object is exposed.
            // https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-operations
            let success = unsafe {
                InitializeAcl(acl.as_mut_ptr().cast(), acl_length as u32, 2) != 0
                    && AddAccessAllowedAceEx(
                        acl.as_mut_ptr().cast(),
                        2,
                        if directory { 3 } else { 0 },
                        FILE_ALL_ACCESS,
                        user.pointer(),
                    ) != 0
                    && InitializeSecurityDescriptor(descriptor_pointer, 1) != 0
                    && SetSecurityDescriptorOwner(descriptor_pointer, user.pointer(), 0) != 0
                    && SetSecurityDescriptorDacl(descriptor_pointer, 1, acl.as_mut_ptr().cast(), 0)
                        != 0
                    && SetSecurityDescriptorControl(
                        descriptor_pointer,
                        DACL_PROTECTED,
                        DACL_PROTECTED,
                    ) != 0
            };
            if !success {
                return Err(io::Error::last_os_error().into());
            }
            Ok(Self {
                descriptor,
                _acl: acl,
            })
        }

        fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: (&mut *self.descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                bInheritHandle: 0,
            }
        }
    }

    struct SecurityAllocation(*mut c_void);
    impl Drop for SecurityAllocation {
        fn drop(&mut self) {
            // SAFETY: GetSecurityInfo allocates this buffer with LocalAlloc.
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    fn private(file: &File, user: &UserSid, directory: bool) -> Result<(), EndpointError> {
        plain(file, directory)?;
        let mut owner = ptr::null_mut();
        let mut acl: *mut ACL = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        // SAFETY: handle is live; all output pointers are writable. The returned
        // owner/ACL are borrowed from the allocation retained through this call.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut acl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32).into());
        }
        let _allocation = SecurityAllocation(descriptor);
        if owner.is_null() || acl.is_null() || descriptor.is_null() {
            return Err(EndpointError::UnsafePermissions);
        }
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: pointers were returned by successful GetSecurityInfo.
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
            || control & (DACL_PROTECTED | DACL_PRESENT) != DACL_PROTECTED | DACL_PRESENT
            || unsafe { IsValidAcl(acl) } == 0
            || unsafe { IsValidSid(owner) } == 0
            || unsafe { EqualSid(owner, user.pointer()) } == 0
            || unsafe { (*acl).AceCount } != 1
        {
            return Err(EndpointError::UnsafePermissions);
        }
        let mut ace = ptr::null_mut();
        // SAFETY: ACL has exactly one ACE; GetAce returns a borrowed ACE pointer.
        if unsafe { GetAce(acl, 0, &mut ace) } == 0 || ace.is_null() {
            return Err(EndpointError::UnsafePermissions);
        }
        // SAFETY: native ACL validation occurred in GetSecurityInfo/GetAce. We
        // additionally require the ordinary allowed-ACE form and bounded size
        // before consulting its SID, never accepting null/shared/inherited ACLs.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType != 0
            || header.AceFlags != if directory { 3 } else { 0 }
            || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(EndpointError::UnsafePermissions);
        }
        // SAFETY: header form and size were checked before this wider view.
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        if allowed.Mask != FILE_ALL_ACCESS {
            return Err(EndpointError::UnsafePermissions);
        }
        let ace_sid: *mut c_void = (&allowed.SidStart as *const u32).cast_mut().cast();
        let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if usize::from(header.AceSize) < sid_offset + 8 {
            return Err(EndpointError::UnsafePermissions);
        }
        // SAFETY: the SID's initial 8 bytes fit in this validated ACE. Bound the
        // subauthority array before allowing any native SID parser to read it.
        let subauthority_count = unsafe { *ace_sid.cast::<u8>().add(1) } as usize;
        if subauthority_count > 15
            || usize::from(header.AceSize) < sid_offset + 8 + 4 * subauthority_count
        {
            return Err(EndpointError::UnsafePermissions);
        }
        // SAFETY: the complete SID fits in the standard allowed ACE.
        if unsafe { IsValidSid(ace_sid) } == 0 || unsafe { EqualSid(ace_sid, user.pointer()) } == 0
        {
            return Err(EndpointError::UnsafePermissions);
        }
        Ok(())
    }

    fn plain(file: &File, directory: bool) -> Result<(), EndpointError> {
        let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
        // SAFETY: writable native structure and live file/directory handle.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) }
            == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: successful API call initialized this structure.
        let information = unsafe { information.assume_init() };
        if information.dwFileAttributes & REPARSE_POINT != 0
            || (information.dwFileAttributes & DIRECTORY != 0) != directory
            || (!directory && information.nNumberOfLinks != 1)
        {
            return Err(EndpointError::UnsafePath);
        }
        Ok(())
    }

    fn wide(path: &Path) -> Result<Vec<u16>, EndpointError> {
        let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
        if encoded.contains(&0) {
            return Err(EndpointError::UnsafePath);
        }
        encoded.push(0);
        Ok(encoded)
    }

    fn ordinary_component(component: &OsStr) -> bool {
        let Some(value) = component.to_str() else {
            return false;
        };
        if value.is_empty()
            || value.encode_utf16().count() > 255
            || value.ends_with('.')
            || value.ends_with(' ')
            || value.chars().any(|character| {
                character.is_control()
                    || matches!(
                        character,
                        ':' | '/' | '\\' | '<' | '>' | '"' | '|' | '?' | '*'
                    )
            })
        {
            return false;
        }
        let stem = value
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$") {
            return false;
        }
        if let Some(suffix) = stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
        {
            if matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            ) {
                return false;
            }
        }
        true
    }

    fn open_file(
        path: &Path,
        access: u32,
        share: u32,
        creation: u32,
        security: Option<&mut PrivateSecurity>,
    ) -> Result<File, EndpointError> {
        let encoded = wide(path)?;
        let attributes = security.map(PrivateSecurity::attributes);
        // SAFETY: encoded is NUL-terminated; optional descriptor/ACL stay live
        // through this synchronous call. OPEN_REPARSE_POINT avoids traversal.
        let handle = unsafe {
            CreateFileW(
                encoded.as_ptr(),
                access,
                share,
                attributes
                    .as_ref()
                    .map_or(ptr::null(), |value| value as *const SECURITY_ATTRIBUTES),
                creation,
                BACKUP_SEMANTICS | OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: the new handle is owned and transferred exactly once.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    pub(super) struct Directory {
        path: PathBuf,
        pins: Vec<File>,
        user: UserSid,
    }
    pub(super) struct Lock;
    impl Directory {
        pub(super) fn open(path: &Path) -> Result<Self, EndpointError> {
            if !path.is_absolute() {
                return Err(EndpointError::UnsafePath);
            }
            let components: Vec<_> = path.components().collect();
            if components.len() < 3
                || components.len() > 66
                || !matches!(components[0], Component::Prefix(prefix) if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
                || !matches!(components[1], Component::RootDir)
                || components[2..].iter().any(
                    |part| !matches!(part, Component::Normal(name) if ordinary_component(name)),
                )
            {
                return Err(EndpointError::UnsafePath);
            }
            let user = UserSid::current()?;
            let mut current = PathBuf::new();
            current.push(components[0]);
            current.push(components[1]);
            let mut pins = vec![open_file(
                &current,
                READ_CONTROL,
                SHARE_READ,
                OPEN_EXISTING,
                None,
            )?];
            plain(&pins[0], true)?;
            for (index, part) in components[2..].iter().enumerate() {
                current.push(part.as_os_str());
                let last = index + 3 == components.len();
                let file = match open_file(&current, READ_CONTROL, SHARE_READ, OPEN_EXISTING, None)
                {
                    Ok(file) => file,
                    Err(EndpointError::Missing) if last => {
                        let mut security = PrivateSecurity::new(&user, true)?;
                        let attributes = security.attributes();
                        let encoded = wide(&current)?;
                        // SAFETY: all ancestors are pinned without write/delete
                        // sharing; explicit protected user-only DACL is supplied
                        // atomically to creation, before another user can enter.
                        if unsafe { CreateDirectoryW(encoded.as_ptr(), &attributes) } == 0 {
                            return Err(io::Error::last_os_error().into());
                        }
                        open_file(&current, READ_CONTROL, SHARE_READ, OPEN_EXISTING, None)?
                    }
                    Err(error) => return Err(error),
                };
                plain(&file, true)?;
                pins.push(file);
            }
            private(pins.last().ok_or(EndpointError::UnsafePath)?, &user, true)?;
            Ok(Self {
                path: current,
                pins,
                user,
            })
        }

        pub(super) fn path(&self) -> &Path {
            &self.path
        }

        pub(super) fn lock(&self) -> Result<Lock, EndpointError> {
            // Data-root exclusivity is the cross-process authority. The outer
            // mutex handles same-instance concurrency, while file handles deny
            // replacement during epoch comparison/deletion. Ancestors stay
            // pinned against rename and are rechecked for reparse transitions.
            for pin in &self.pins {
                plain(pin, true)?;
            }
            private(
                self.pins.last().ok_or(EndpointError::UnsafePath)?,
                &self.user,
                true,
            )?;
            Ok(Lock)
        }

        fn record_file(&self, delete: bool) -> Result<File, EndpointError> {
            let file = open_file(
                &self.path.join(RECORD_NAME),
                GENERIC_READ | READ_CONTROL | if delete { DELETE } else { 0 },
                SHARE_READ,
                OPEN_EXISTING,
                None,
            )?;
            private(&file, &self.user, false)?;
            Ok(file)
        }

        pub(super) fn load(&self) -> Result<EndpointRecord, EndpointError> {
            read_record(&mut self.record_file(false)?)
        }

        pub(super) fn publish(&self, bytes: &[u8]) -> Result<(), EndpointError> {
            let mut security = PrivateSecurity::new(&self.user, false)?;
            let mut file = open_file(
                &self.path.join(temporary_name()),
                GENERIC_WRITE | READ_CONTROL | DELETE,
                SHARE_READ,
                CREATE_NEW,
                Some(&mut security),
            )?;
            private(&file, &self.user, false)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            // FILE_RENAME_INFO's initial BOOLEAN/Flags union occupies a DWORD.
            // The variable filename buffer is usize-aligned and uses the SDK
            // layout, including its pointer-alignment padding on Windows x64.
            // https://learn.microsoft.com/windows/win32/api/winbase/ns-winbase-file_rename_info
            #[repr(C)]
            struct RenameInfo {
                flags: u32,
                root: HANDLE,
                name_bytes: u32,
                name: [u16; 1],
            }
            // SetFileInformationByHandle's Win32 rename boundary receives a
            // full DOS/verbatim-DOS destination and a null RootDirectory. Keep
            // all no-write/delete-share ancestor pins live so resolving this
            // absolute name cannot adopt a replaced directory. Reserve the SDK
            // structure size plus the complete NUL-terminated filename, rather
            // than passing only a truncated trailing-array prefix to Win32.
            let name = wide(&self.path.join(RECORD_NAME))?;
            let name_bytes = (name.len() - 1) * size_of::<u16>();
            let byte_length = size_of::<RenameInfo>() + name.len() * size_of::<u16>();
            let mut storage = vec![0usize; byte_length.div_ceil(size_of::<usize>())];
            let information = storage.as_mut_ptr().cast::<RenameInfo>();
            // SAFETY: storage covers the complete SDK-layout structure and
            // filename including its terminator. Destination is exactly the
            // fixed endpoint name under the still-pinned runtime directory.
            unsafe {
                ptr::addr_of_mut!((*information).flags).write(1);
                ptr::addr_of_mut!((*information).root).write(ptr::null_mut());
                ptr::addr_of_mut!((*information).name_bytes).write(name_bytes as u32);
                ptr::copy_nonoverlapping(
                    name.as_ptr(),
                    ptr::addr_of_mut!((*information).name).cast::<u16>(),
                    name.len(),
                );
            }
            // SAFETY: valid rename structure and source handle opened DELETE.
            if unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle(),
                    FileRenameInfo,
                    information.cast(),
                    byte_length as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error().into());
            }
            Ok(())
        }

        pub(super) fn remove_if_epoch(&self, epoch: &str) -> Result<bool, EndpointError> {
            let mut file = match self.record_file(true) {
                Ok(file) => file,
                Err(EndpointError::Missing) => return Ok(false),
                Err(error) => return Err(error),
            };
            if read_record(&mut file)?.coordinator_epoch != epoch {
                return Ok(false);
            }
            #[repr(C)]
            struct Disposition {
                delete: i32,
            }
            let information = Disposition { delete: 1 };
            // SAFETY: removal attaches to this verified, delete-opened handle,
            // never a path reopened after checking the epoch. No write/delete
            // sharing permits a different epoch to replace it in between.
            if unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle(),
                    FileDispositionInfo,
                    (&information as *const Disposition).cast(),
                    size_of::<Disposition>() as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error().into());
            }
            drop(file);
            Ok(true)
        }
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!("MMMM coordinator endpoint storage requires Unix or Windows security primitives");

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn record(epoch: &str) -> EndpointRecord {
        EndpointRecord {
            schema_version: 1,
            contract_version: "0.2.0".into(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32123),
            path: "/rpc".into(),
            coordinator_epoch: epoch.into(),
            credential_ref: "MMMM.coordinator.fixture-001".into(),
        }
    }

    struct Fixture {
        parent: PathBuf,
        runtime: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let parent = std::env::temp_dir().join(format!(
                "mmmm-endpoint-fixture-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&parent).expect("new uniquely owned fixture parent");
            let parent = fs::canonicalize(parent).expect("physical fixture parent");
            let runtime = parent.join("runtime");
            Self { parent, runtime }
        }
        fn cleanup(self) {
            // Only exact fixture files/directories are removed; no recursion,
            // wildcard traversal, or cleanup of unknown diagnostic entries.
            fs::remove_dir(&self.runtime).expect("empty fixture runtime");
            fs::remove_dir(&self.parent).expect("empty fixture parent");
        }
    }

    #[test]
    fn endpoint_record_rejects_untrusted_destinations_and_refs() {
        assert!(record("epoch-001").validate().is_ok());
        assert!(record("epoch:001-").validate().is_ok());
        assert!(matches!(
            record("Epoch-001").validate(),
            Err(EndpointError::InvalidRecord)
        ));
        let mut candidate = record("epoch-001");
        candidate.address = "127.0.0.2:32123".parse().unwrap();
        assert!(matches!(
            candidate.validate(),
            Err(EndpointError::InvalidRecord)
        ));
        candidate = record("epoch-001");
        candidate.credential_ref = "MMMM.coordinator.../secret".into();
        assert!(matches!(
            candidate.validate(),
            Err(EndpointError::InvalidRecord)
        ));
        candidate = record("epoch-001");
        candidate.credential_ref = "MMMM.coordinator.UPPER".into();
        assert!(matches!(
            candidate.validate(),
            Err(EndpointError::InvalidRecord)
        ));
        candidate = record("epoch-001");
        candidate.path = "/rpc/other".into();
        assert!(matches!(
            candidate.validate(),
            Err(EndpointError::InvalidRecord)
        ));
    }

    #[test]
    fn old_epoch_shutdown_cannot_delete_new_endpoint() {
        let fixture = Fixture::new();
        let directory = RuntimeDirectory::open(&fixture.runtime).unwrap();
        assert!(matches!(directory.load(), Err(EndpointError::Missing)));
        directory.publish(&record("epoch-001")).unwrap();
        assert_eq!(directory.load().unwrap(), record("epoch-001"));
        let reopened = RuntimeDirectory::open(&fixture.runtime).unwrap();
        assert_eq!(reopened.load().unwrap(), record("epoch-001"));
        drop(reopened);
        assert!(matches!(
            directory.publish(&record("epoch-002")),
            Err(EndpointError::EpochConflict)
        ));
        assert!(!directory.remove_if_epoch("epoch-002").unwrap());
        assert!(directory.remove_if_epoch("epoch-001").unwrap());
        directory.publish(&record("epoch-002")).unwrap();
        assert!(!directory.remove_if_epoch("epoch-001").unwrap());
        assert_eq!(directory.load().unwrap().coordinator_epoch, "epoch-002");
        assert!(directory.remove_if_epoch("epoch-002").unwrap());
        assert!(!directory.remove_if_epoch("epoch-002").unwrap());
        drop(directory);
        fixture.cleanup();
    }

    #[test]
    fn relative_or_parent_traversal_path_is_rejected() {
        assert!(matches!(
            RuntimeDirectory::open(Path::new("runtime")),
            Err(EndpointError::UnsafePath)
        ));
        #[cfg(windows)]
        for path in [
            r"C:runtime",
            r"\\fixture.invalid\share\runtime",
            r"\\?\UNC\fixture.invalid\share\runtime",
            r"\\.\pipe\MMMM.fixture",
            r"\\?\GLOBALROOT\Device\MMMM.fixture",
        ] {
            // All are rejected lexically before a native file/network/device
            // lookup; they are synthetic selectors, not real host locations.
            assert!(matches!(
                RuntimeDirectory::open(Path::new(path)),
                Err(EndpointError::UnsafePath)
            ));
        }
        let fixture = Fixture::new();
        #[cfg(windows)]
        let traversal = {
            // PathBuf::join normalizes ParentDir under VerbatimDisk prefixes.
            // Preserve the actual lexical input so the validator, rather than
            // the fixture builder, decides whether traversal is permitted.
            let mut raw = fixture.parent.as_os_str().to_os_string();
            raw.push("\\..\\runtime");
            PathBuf::from(raw)
        };
        #[cfg(not(windows))]
        let traversal = fixture.parent.join("..").join("runtime");
        assert!(matches!(
            RuntimeDirectory::open(&traversal),
            Err(EndpointError::UnsafePath)
        ));
        fs::remove_dir(&fixture.parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn existing_shared_directory_and_symbolic_link_are_not_adopted() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let fixture = Fixture::new();
        fs::create_dir(&fixture.runtime).unwrap();
        fs::set_permissions(&fixture.runtime, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            RuntimeDirectory::open(&fixture.runtime),
            Err(EndpointError::UnsafePermissions)
        ));
        fs::remove_dir(&fixture.runtime).unwrap();
        symlink(&fixture.parent, &fixture.runtime).unwrap();
        assert!(RuntimeDirectory::open(&fixture.runtime).is_err());
        fs::remove_file(&fixture.runtime).unwrap();
        fs::remove_dir(&fixture.parent).unwrap();
    }

    #[test]
    fn malformed_endpoint_is_preserved_until_diagnosed() {
        let fixture = Fixture::new();
        let directory = RuntimeDirectory::open(&fixture.runtime).unwrap();
        directory
            .inner
            .publish(br#"{"schemaVersion":1,"schemaVersion":1}"#)
            .unwrap();
        assert!(matches!(
            directory.load(),
            Err(EndpointError::InvalidRecord)
        ));
        assert!(matches!(
            directory.publish(&record("epoch-001")),
            Err(EndpointError::InvalidRecord)
        ));
        assert!(matches!(
            directory.remove_if_epoch("epoch-001"),
            Err(EndpointError::InvalidRecord)
        ));
        // Exact generated fixture metadata, never a credential, is cleared by
        // its test owner only after all preservation checks.
        fs::remove_file(fixture.runtime.join(RECORD_NAME)).unwrap();
        drop(directory);
        fixture.cleanup();
    }

    #[cfg(windows)]
    #[test]
    fn inherited_windows_directory_acl_is_not_adopted() {
        let fixture = Fixture::new();
        fs::create_dir(&fixture.runtime).unwrap();
        assert!(matches!(
            RuntimeDirectory::open(&fixture.runtime),
            Err(EndpointError::UnsafePermissions)
        ));
        fixture.cleanup();
    }
}

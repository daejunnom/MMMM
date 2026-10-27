use super::*;
use std::{
    fs::OpenOptions,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::PathBuf,
};
use windows_sys::Win32::Foundation::SetLastError;
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, FILE_TYPE_UNKNOWN, GetDriveTypeW,
    GetFileAttributesW, GetFileInformationByHandle, GetFileType, INVALID_FILE_ATTRIBUTES,
};
#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    volume: u32,
    index: u64,
    length: u64,
    attributes: u32,
    links: u32,
    created: u64,
    written: u64,
}
fn identity<C: Control>(file: &File, checks: &C) -> Result<Identity, C::Error> {
    checks.io(|| {
        // SAFETY: actual owned File handle and SDK-sized output. A native
        // failure remains its original io::Error without selected path text.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Identity {
            volume: info.dwVolumeSerialNumber,
            index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            length: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
            attributes: info.dwFileAttributes,
            links: info.nNumberOfLinks,
            created: (u64::from(info.ftCreationTime.dwHighDateTime) << 32)
                | u64::from(info.ftCreationTime.dwLowDateTime),
            written: (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
                | u64::from(info.ftLastWriteTime.dwLowDateTime),
        })
    })
}
fn open_with_share<C: Control>(
    path: &Path,
    directory: bool,
    share: u32,
    checks: &C,
) -> Result<(File, Identity), C::Error> {
    let file = checks.io(|| {
        OpenOptions::new()
            .read(true)
            .share_mode(share)
            .custom_flags(
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if directory {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        0
                    },
            )
            .open(path)
    })?;
    inspect(file, directory, checks)
}

struct Directory {
    path: PathBuf,
    file: File,
    identity: Identity,
    created_handle: bool,
}
pub struct Selected {
    path: PathBuf,
    file: File,
    identity: Identity,
    parents: Vec<Arc<Directory>>,
    created: bool,
}
impl Selected {
    pub fn open_selected<C: Control>(path: &Path, checks: &C) -> Result<Self, C::Error> {
        if !is_ordinary_absolute_path(path) {
            return Err(checks.unsafe_selection());
        }
        let parents = open_directories(
            path.parent().ok_or_else(|| checks.unsafe_selection())?,
            checks,
        )?;
        let (file, actual) = open(path, false, checks)?;
        let selected = Self {
            path: path.to_owned(),
            file,
            identity: actual,
            parents,
            created: false,
        };
        selected.revalidate(checks)?;
        Ok(selected)
    }
    pub fn length(&self) -> u64 {
        self.identity.length
    }
    pub fn file(&mut self) -> &mut File {
        &mut self.file
    }
    pub fn revalidate<C: Control>(&self, checks: &C) -> Result<(), C::Error> {
        revalidate_directories(&self.parents, checks)?;
        let (_fresh, named) = open_with_share(
            &self.path,
            false,
            if self.created {
                FILE_SHARE_READ | FILE_SHARE_WRITE
            } else {
                FILE_SHARE_READ
            },
            checks,
        )?;
        if identity(&self.file, checks)? != self.identity || named != self.identity {
            return Err(checks.changed());
        }
        Ok(())
    }
}

fn open<C: Control>(
    path: &Path,
    directory: bool,
    checks: &C,
) -> Result<(File, Identity), C::Error> {
    open_with_share(path, directory, FILE_SHARE_READ, checks)
}
fn inspect<C: Control>(
    file: File,
    directory: bool,
    checks: &C,
) -> Result<(File, Identity), C::Error> {
    let actual = identity(&file, checks)?;
    let kind = checks.io(|| {
        // SAFETY: clear this thread's error slot immediately before using
        // the same live File handle. UNKNOWN may mean either a valid
        // unknown type or failure; capture that error before checkpoints
        // perform any native calls that could overwrite it.
        unsafe { SetLastError(0) };
        let kind = unsafe { GetFileType(file.as_raw_handle()) };
        if kind == FILE_TYPE_UNKNOWN {
            let error = io::Error::last_os_error();
            if error.raw_os_error().is_some_and(|code| code != 0) {
                return Err(error);
            }
        }
        Ok(kind)
    })?;
    if kind != FILE_TYPE_DISK
        || actual.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (actual.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && actual.links != 1)
    {
        return Err(checks.unsafe_selection());
    }
    Ok((file, actual))
}
fn open_directories<C: Control>(path: &Path, checks: &C) -> Result<Vec<Arc<Directory>>, C::Error> {
    let drive = match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            std::path::Prefix::Disk(drive) => drive,
            _ => return Err(checks.unsafe_selection()),
        },
        _ => return Err(checks.unsafe_selection()),
    };
    let drive_root = [u16::from(drive), u16::from(b':'), u16::from(b'\\'), 0];
    checks.check()?;
    // SAFETY: fixed live drive root is NUL terminated. Mapped network,
    // removable and unrecognized volumes do not enter this cold seam.
    let drive_kind = unsafe { GetDriveTypeW(drive_root.as_ptr()) };
    checks.check()?;
    if drive_kind != 3 {
        return Err(checks.unsafe_selection());
    }
    let mut paths: Vec<_> = path.ancestors().collect();
    paths.reverse();
    let mut parents = Vec::new();
    for parent in paths {
        let (file, actual) = open(parent, true, checks)?;
        parents.push(Arc::new(Directory {
            path: parent.to_owned(),
            file,
            identity: actual,
            created_handle: false,
        }));
    }

    Ok(parents)
}
fn revalidate_directories<C: Control>(
    parents: &[Arc<Directory>],
    checks: &C,
) -> Result<(), C::Error> {
    for held in parents {
        let current = identity(&held.file, checks)?;
        let (_fresh, named) = open(&held.path, true, checks)?;
        let same = |actual: Identity| {
            actual.volume == held.identity.volume
                && actual.index == held.identity.index
                && actual.attributes == held.identity.attributes
        };
        // Directory content times/length may change for siblings. The
        // held no-delete handle and exact namespace identity remain.
        if !same(current) || !same(named) {
            return Err(checks.changed());
        }
    }

    Ok(())
}
fn wide<C: Control>(path: &Path, checks: &C) -> Result<Vec<u16>, C::Error> {
    use std::os::windows::ffi::OsStrExt;
    let mut text: Vec<u16> = path.as_os_str().encode_wide().collect();
    if text.len() > 32766 || text.contains(&0) {
        return Err(checks.unsafe_selection());
    }
    text.push(0);
    Ok(text)
}
pub struct HeldDirectory {
    parents: Vec<Arc<Directory>>,
}
impl HeldDirectory {
    pub(crate) fn shared(&self) -> Self {
        Self {
            parents: self.parents.clone(),
        }
    }
    /// Check the complete root-relative spelling and ancestry bound before
    /// opening any component. Only already-held path metadata is consulted.
    pub(crate) fn descendant_fits(&self, components: &[&std::ffi::OsStr]) -> bool {
        if components.is_empty()
            || self
                .parents
                .len()
                .checked_add(components.len())
                .is_none_or(|count| count > 66)
        {
            return false;
        }
        let Some(parent) = self.parents.last() else {
            return false;
        };
        let mut path = parent.path.clone();
        for child in components {
            if !ordinary_child(child) {
                return false;
            }
            path.push(child);
            if !is_ordinary_absolute_path(&path) {
                return false;
            }
        }
        true
    }
    pub(crate) fn existing_child_directory<C: Control>(
        &self,
        child: &std::ffi::OsStr,
        checks: &C,
    ) -> Result<Option<Self>, C::Error> {
        let path = self.child_path(child, checks)?;
        let text = wide(&path, checks)?;
        self.revalidate(checks)?;
        let found = checks.io(|| {
            // SAFETY: one ordinary child under held ancestors, no content open.
            let attributes = unsafe { GetFileAttributesW(text.as_ptr()) };
            if attributes != INVALID_FILE_ATTRIBUTES {
                return Ok(Some(attributes));
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(2) {
                Ok(None)
            } else {
                Err(error)
            }
        })?;
        let Some(before) = found else {
            self.revalidate(checks)?;
            return Ok(None);
        };
        if before & FILE_ATTRIBUTE_REPARSE_POINT != 0 || before & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(checks.unsafe_selection());
        }
        let (file, actual) = open(&path, true, checks)?;
        if actual.attributes != before {
            return Err(checks.changed());
        }
        let mut parents = self.parents.clone();
        parents.push(Arc::new(Directory {
            path,
            file,
            identity: actual,
            created_handle: false,
        }));
        let directory = Self { parents };
        directory.revalidate(checks)?;
        Ok(Some(directory))
    }
    /// Open one existing regular leaf under this held ancestry. The caller
    /// validates the complete relative component list before any I/O.
    ///
    /// Windows still opens the child's absolute spelling, but every ancestor
    /// is held without delete sharing and checked before and after the open.
    /// This is not a claim of an atomic namespace snapshot or that a writer
    /// which preceded selection cannot mutate the object.
    pub(crate) fn existing_child_file<C: Control>(
        &self,
        child: &std::ffi::OsStr,
        checks: &C,
    ) -> Result<Selected, C::Error> {
        let path = self.child_path(child, checks)?;
        self.revalidate(checks)?;
        let (file, actual) = match open(&path, false, checks) {
            Ok(opened) => opened,
            Err(error) => return followup(Err(error), self.revalidate(checks), checks),
        };
        let selected = Selected {
            path,
            file,
            identity: actual,
            parents: self.parents.clone(),
            created: false,
        };
        let result = followup(selected.revalidate(checks), self.revalidate(checks), checks);
        match result {
            Ok(()) => Ok(selected),
            Err(error) => followup(Err(error), selected.close(checks), checks),
        }
    }
    pub fn open_root<C: Control>(path: &Path, checks: &C) -> Result<Self, C::Error> {
        if !is_ordinary_absolute_path(path) {
            return Err(checks.unsafe_selection());
        }
        let root = Self {
            parents: open_directories(path, checks)?,
        };
        root.revalidate(checks)?;
        Ok(root)
    }
    pub fn revalidate<C: Control>(&self, checks: &C) -> Result<(), C::Error> {
        revalidate_directories(&self.parents, checks)
    }
    pub fn identity_evidence(&self) -> DirectoryIdentityEvidence {
        if self.parents.last().is_some_and(|leaf| leaf.created_handle) {
            DirectoryIdentityEvidence::WindowsCreateReturnedHandle
        } else {
            DirectoryIdentityEvidence::WindowsOpenedHandle
        }
    }
    pub(crate) fn same_leaf_identity<C: Control>(
        &self,
        selected: &Self,
        checks: &C,
    ) -> Result<bool, C::Error> {
        let held = self.parents.last().ok_or_else(|| checks.changed())?;
        let selected = selected.parents.last().ok_or_else(|| checks.changed())?;
        let held = identity(&held.file, checks)?;
        let selected = identity(&selected.file, checks)?;
        Ok(held.volume == selected.volume
            && held.index == selected.index
            && held.attributes == selected.attributes)
    }
    fn child_path<C: Control>(
        &self,
        child: &std::ffi::OsStr,
        checks: &C,
    ) -> Result<PathBuf, C::Error> {
        if !ordinary_child(child) || self.parents.len() >= 66 {
            return Err(checks.unsafe_selection());
        }
        let path = self
            .parents
            .last()
            .ok_or_else(|| checks.changed())?
            .path
            .join(child);
        if !is_ordinary_absolute_path(&path) {
            return Err(checks.unsafe_selection());
        }
        Ok(path)
    }
    pub fn require_child_absent<C: Control>(
        &self,
        child: &std::ffi::OsStr,
        checks: &C,
    ) -> Result<(), C::Error> {
        let path = self.child_path(child, checks)?;
        let text = wide(&path, checks)?;
        self.revalidate(checks)?;
        let absent = checks.io(|| {
            // SAFETY: bounded NUL-terminated ordinary path under no-delete held
            // ancestors; no file content is opened or read.
            if unsafe { GetFileAttributesW(text.as_ptr()) } != INVALID_FILE_ATTRIBUTES {
                return Ok(false);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(2) {
                Ok(true)
            } else {
                Err(error)
            }
        })?;
        self.revalidate(checks)?;
        if !absent {
            return Err(checks.unsafe_selection());
        }
        Ok(())
    }
    pub fn create_directory_new<C: Control>(
        &self,
        child: &std::ffi::OsStr,
        checks: &C,
    ) -> Result<Self, C::Error> {
        let path = self.child_path(child, checks)?;
        self.revalidate(checks)?;
        let file = create_directory_handle(&self.parents, child, checks)?;
        let (file, actual) = inspect(file, true, checks)?;
        let mut parents = self.parents.clone();
        parents.push(Arc::new(Directory {
            path,
            file,
            identity: actual,
            created_handle: true,
        }));
        let created = Self { parents };
        created.revalidate(checks)?;
        Ok(created)
    }
    pub fn create_file_new<C: Control>(
        &self,
        child: &std::ffi::OsStr,
        expected_length: u64,
        checks: &C,
    ) -> Result<CreatedFile, C::Error> {
        let path = self.child_path(child, checks)?;
        self.revalidate(checks)?;
        let file = checks.io(|| {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path)
        })?;
        let (file, actual) = inspect(file, false, checks)?;
        if actual.length != 0 {
            return Err(checks.changed());
        }
        let selected = Selected {
            path,
            file,
            identity: actual,
            parents: self.parents.clone(),
            created: true,
        };
        selected.revalidate(checks)?;
        Ok(CreatedFile::new(selected, expected_length))
    }
    /// Releases this reference; actual CloseHandle is checked for each last pin.
    pub fn close<C: Control>(self, checks: &C) -> Result<(), C::Error> {
        release_pins(self.parents, checks, |directory| directory.file)
    }
    /// Consume this ancestry reference and observe every last-owned native close.
    /// A shared reference, including pending-create ancestry, is not full close.
    pub fn close_retained<C: Control>(self, checks: &C) -> RetainedCloseReport<C::Error> {
        release_retained_pins(self.parents, checks, |directory| directory.file)
    }
}
impl Selected {
    pub(crate) fn seal_created<C: Control>(&mut self, checks: &C) -> Result<(), C::Error> {
        let current = identity(&self.file, checks)?;
        if current.volume != self.identity.volume
            || current.index != self.identity.index
            || current.attributes != self.identity.attributes
            || current.created != self.identity.created
            || current.links != 1
        {
            return Err(checks.changed());
        }
        self.identity = current;
        self.revalidate(checks)
    }
    pub fn close<C: Control>(self, checks: &C) -> Result<(), C::Error> {
        close_file(self.file, checks)?;
        release_pins(self.parents, checks, |directory| directory.file)
    }
}

// Independently expressed user-mode ABI from Microsoft:
// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes
// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block
// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-rtlntstatustodoserror
// Only FILE_CREATE is used. No backup intent, delete, overwrite or OPEN_IF.
#[repr(C)]
struct NtUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct NtObjectAttributes {
    length: u32,
    root_directory: *mut std::ffi::c_void,
    object_name: *mut NtUnicodeString,
    attributes: u32,
    security_descriptor: *mut std::ffi::c_void,
    security_quality_of_service: *mut std::ffi::c_void,
}
#[repr(C)]
union NtIoResult {
    status: i32,
    pointer: *mut std::ffi::c_void,
}
#[repr(C)]
struct NtIoStatus {
    result: NtIoResult,
    information: usize,
}
#[repr(C)]
struct NtOutputs {
    handle: *mut std::ffi::c_void,
    io: NtIoStatus,
}
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(std::mem::size_of::<NtUnicodeString>() == 16);
    assert!(std::mem::offset_of!(NtUnicodeString, buffer) == 8);
    assert!(std::mem::size_of::<NtObjectAttributes>() == 48);
    assert!(std::mem::offset_of!(NtObjectAttributes, root_directory) == 8);
    assert!(std::mem::offset_of!(NtObjectAttributes, object_name) == 16);
    assert!(std::mem::offset_of!(NtObjectAttributes, attributes) == 24);
    assert!(std::mem::offset_of!(NtObjectAttributes, security_descriptor) == 32);
    assert!(std::mem::offset_of!(NtObjectAttributes, security_quality_of_service) == 40);
    assert!(std::mem::size_of::<NtIoStatus>() == 16);
    assert!(std::mem::offset_of!(NtIoStatus, information) == 8);
};
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut *mut std::ffi::c_void,
        desired_access: u32,
        attributes: *mut NtObjectAttributes,
        io_status: *mut NtIoStatus,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        disposition: u32,
        options: u32,
        ea_buffer: *const std::ffi::c_void,
        ea_length: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

/// Closed causal facts; no path, native handle or native identity is exposed.
#[derive(Debug)]
pub struct NativeCreateFailure {
    status: i32,
    completion: Option<i32>,
    information: Option<usize>,
    dos: Option<io::Error>,
    close: Option<io::Error>,
}
impl NativeCreateFailure {
    pub fn nt_status(&self) -> i32 {
        self.status
    }
    pub fn completion_status(&self) -> Option<i32> {
        self.completion
    }
    pub fn information(&self) -> Option<usize> {
        self.information
    }
    pub fn dos_error(&self) -> Option<i32> {
        self.dos.as_ref().and_then(io::Error::raw_os_error)
    }
    pub fn close_error(&self) -> Option<&io::Error> {
        self.close.as_ref()
    }
}
impl std::fmt::Display for NativeCreateFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native directory creation failed or returned an unconfirmed disposition")
    }
}
impl std::error::Error for NativeCreateFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.dos
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}
fn native_create_error(
    status: i32,
    completion: Option<i32>,
    information: Option<usize>,
    close: Option<io::Error>,
) -> io::Error {
    let failed_status = if status != 0 {
        Some(status)
    } else {
        completion.filter(|value| *value != 0)
    };
    let dos = failed_status.map(|status| {
        // SAFETY: pure NTSTATUS-to-DOS conversion with no object pointers.
        io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
    });
    let kind = dos
        .as_ref()
        .map_or(io::ErrorKind::InvalidData, io::Error::kind);
    io::Error::new(
        kind,
        NativeCreateFailure {
            status,
            completion,
            information,
            dos,
            close,
        },
    )
}

struct NativeDirectoryCall {
    // No Java object, callback, request, token or authority is retained here.
    _parents: Vec<Arc<Directory>>,
    _text: Vec<u16>,
    name: NtUnicodeString,
    attributes: NtObjectAttributes,
    outputs: NtOutputs,
}
// Serialize the one native create capability. One unexpected pending result
// closes it for process lifetime; there is no unbounded quarantine map/retry.
static DIRECTORY_CREATE_GATE: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

fn create_directory_handle<C: Control>(
    parents: &[Arc<Directory>],
    child: &std::ffi::OsStr,
    checks: &C,
) -> Result<File, C::Error> {
    use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
    checks.check()?;
    let mut gate = DIRECTORY_CREATE_GATE.lock().map_err(|_| {
        checks.io_error(io::Error::other(
            "native directory creation gate is unavailable",
        ))
    })?;
    // A borrowed checkpoint must not reenter this native creation gate. It is
    // never stored; check the original deadline again after the lock wait.
    checks.check()?;
    if *gate {
        return Err(checks.io_error(io::Error::new(
            io::ErrorKind::WouldBlock,
            "native directory creation is quarantined after an unresolved request",
        )));
    }
    let result = (|| {
        let mut text: Vec<u16> = child.encode_wide().collect();
        let bytes = u16::try_from(
            text.len()
                .checked_mul(2)
                .ok_or(io::ErrorKind::InvalidInput)?,
        )
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let parent = parents.last().ok_or(io::ErrorKind::InvalidInput)?;
        // Moving the Vec does not move or reallocate its UTF16 allocation.
        // No slice reference is materialized or retained for the native call.
        let text_buffer = text.as_mut_ptr();
        let call = Box::into_raw(Box::new(NativeDirectoryCall {
            _parents: parents.to_vec(),
            _text: text,
            name: NtUnicodeString {
                length: bytes,
                maximum_length: bytes,
                buffer: text_buffer,
            },
            attributes: NtObjectAttributes {
                length: std::mem::size_of::<NtObjectAttributes>() as u32,
                root_directory: parent.file.as_raw_handle(),
                object_name: std::ptr::null_mut(),
                attributes: 0x40, // OBJ_CASE_INSENSITIVE; no inheritance/elevation.
                security_descriptor: std::ptr::null_mut(),
                security_quality_of_service: std::ptr::null_mut(),
            },
            outputs: NtOutputs {
                handle: std::ptr::null_mut(),
                io: NtIoStatus {
                    result: NtIoResult {
                        pointer: std::ptr::null_mut(),
                    },
                    information: 0,
                },
            },
        }));
        // The allocation has raw ownership BEFORE deriving any self/output
        // pointers. Only raw projections are used until completion: no Box or
        // field reference may retag this memory while the OS can still write.
        // SAFETY: live uniquely allocated object; projections create no refs.
        let (attributes, handle, io_status) = unsafe {
            let name = std::ptr::addr_of_mut!((*call).name);
            let attributes = std::ptr::addr_of_mut!((*call).attributes);
            std::ptr::addr_of_mut!((*attributes).object_name).write(name);
            (
                attributes,
                std::ptr::addr_of_mut!((*call).outputs.handle),
                std::ptr::addr_of_mut!((*call).outputs.io),
            )
        };
        // SAFETY: exact native ABI, held ordinary RootDirectory, validated one
        // component, and all inputs/outputs live in stable owned heap storage.
        // Synchronous directory creation returns the same newly opened object.
        let status = unsafe {
            NtCreateFile(
                handle,
                0x0010_00a0, // SYNCHRONIZE | READ_ATTRIBUTES | TRAVERSE
                attributes,
                io_status,
                std::ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ,
                2,           // FILE_CREATE
                0x0020_0021, // OPEN_REPARSE_POINT | SYNCHRONOUS_IO_NONALERT | DIRECTORY
                std::ptr::null(),
                0,
            )
        };
        if status == 0x103 {
            *gate = true;
            // STATUS_PENDING may still own any input/output pointer. Preserve
            // this ONE bounded call and its parent ancestry for process lifetime.
            // No wait/retry, invented handle identity, full-close or success claim.
            // Keep the already-raw allocation untouched. Even reconstructing
            // its Box here could conflict with outstanding native writes.
            return Err(native_create_error(status, None, None, None));
        }
        // SAFETY: non-pending return completed the synchronous request. The OS
        // no longer owns input/output pointers, so unique Box ownership can be
        // restored exactly once. The raw projections above are never used again.
        let call = unsafe { Box::from_raw(call) };
        let valid = !call.outputs.handle.is_null()
            && call.outputs.handle != (-1isize as *mut std::ffi::c_void);
        let completion = if status == 0 {
            // SAFETY: successful synchronous call initialized the status union.
            Some(unsafe { call.outputs.io.result.status })
        } else {
            None
        };
        let information = (status == 0).then_some(call.outputs.io.information);
        if status != 0 || completion != Some(0) || information != Some(2) || !valid {
            let close = if valid && status == 0 {
                // SAFETY: consume the returned native output handle once, even
                // on unexpected disposition. Namespace content is never deleted.
                if unsafe { windows_sys::Win32::Foundation::CloseHandle(call.outputs.handle) } == 0
                {
                    Some(io::Error::last_os_error())
                } else {
                    None
                }
            } else {
                None
            };
            return Err(native_create_error(status, completion, information, close));
        }
        // SAFETY: FILE_CREATE/FILE_CREATED returned the same new live handle.
        let file = unsafe { File::from_raw_handle(call.outputs.handle) };
        Ok(file)
    })()
    .map_err(|error| checks.io_error(error));
    drop(gate);
    followup(result, checks.check(), checks)
}

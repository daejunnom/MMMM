//! Explicitly selected native authoring files. This is not a directory import
//! or a file finder: lexical classification precedes every filesystem lookup.
//! Held handles, namespace checks and a second bounded digest pass reject
//! observed replacement/modification. POSIX provides no regular-file snapshot
//! or write exclusion here; its cooperative deadline cannot interrupt a blocked
//! kernel read. These checks are not a claim to discover every secret alias.

use crate::{service::RequestBudget, workspace_bootstrap::NativeOwnerWitness};
use sha2::{Digest, Sha256};
use std::{
    collections::TryReserveError,
    error::Error,
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Component, Path},
};

const DOCUMENT_LIMIT: u64 = 8 * 1024 * 1024;
const DESCRIPTOR_LIMIT: u64 = 16 * 1024;
const DOCUMENT_TOTAL: u64 = 32 * 1024 * 1024;
const RESOURCE_TOTAL: u64 = 128 * 1024 * 1024;
const SELECTED_FILE_LIMIT: usize = 512;
const CHUNK: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InputRole {
    Document,
    ResourceDescriptor,
    ResourceBytes,
}
impl InputRole {
    fn limit(self) -> u64 {
        match self {
            Self::Document => DOCUMENT_LIMIT,
            Self::ResourceDescriptor => DESCRIPTOR_LIMIT,
            Self::ResourceBytes => RESOURCE_TOTAL,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Document => "Selected source document",
            Self::ResourceDescriptor => "Selected resource descriptor",
            Self::ResourceBytes => "Selected resource bytes",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ErrorKind {
    UnsafeSelection,
    Limit,
    Changed,
    Io,
    Authority,
    Request,
    Allocation,
}

/// The public wrapper preserves original native/request causes privately.
/// Neither Display nor any error field contains a selected path or its bytes.
#[derive(Debug)]
pub struct ImportFileError {
    kind: ErrorKind,
    role: Option<InputRole>,
    cause: Option<Box<dyn Error + Send + Sync>>,
    checkpoint: Option<Box<ImportFileError>>,
}
impl ImportFileError {
    fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            role: None,
            cause: None,
            checkpoint: None,
        }
    }
    fn caused(kind: ErrorKind, cause: impl Error + Send + Sync + 'static) -> Self {
        Self {
            kind,
            role: None,
            cause: Some(Box::new(cause)),
            checkpoint: None,
        }
    }
    fn for_role(mut self, role: InputRole) -> Self {
        self.role = Some(role);
        self
    }
    /// A checkpoint may fail immediately after the actual I/O has failed. The
    /// primary native cause remains Error::source; this preserves both facts
    /// for internal diagnostics without exposing a selected path or its bytes.
    pub fn checkpoint_failure(&self) -> Option<&Self> {
        self.checkpoint.as_deref()
    }
}
impl fmt::Display for ImportFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let role = self
            .role
            .map(InputRole::label)
            .unwrap_or("Selected source file");
        let detail = match self.kind {
            ErrorKind::UnsafeSelection => "requires an absolute ordinary non-secret local file",
            ErrorKind::Limit => "exceeds the finite source input budget",
            ErrorKind::Changed => "changed during checked source acquisition",
            ErrorKind::Io => "could not be acquired through its checked local handle",
            ErrorKind::Authority => "lost the original native owner authorization",
            ErrorKind::Request => "could not continue within the original request budget",
            ErrorKind::Allocation => "could not reserve its finite input buffer",
        };
        write!(f, "{role} {detail}")
    }
}
impl Error for ImportFileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause
            .as_ref()
            .map(|cause| cause.as_ref() as &(dyn Error + 'static))
    }
}

/// Metadata/document allowance includes the original inline argv documents.
/// Reservations survive a failed read; callers stop the batch on any failure.
/// A resource item selects two files, so the parser's 256-item bound permits
/// at most 512 selected files. This independent bound also protects direct use.
pub(crate) struct ImportReadBudget {
    documents: u64,
    resources: u64,
    selected_files: usize,
}
impl ImportReadBudget {
    pub(crate) fn new(initial_document_bytes: usize) -> Result<Self, ImportFileError> {
        let documents = u64::try_from(initial_document_bytes)
            .map_err(|_| ImportFileError::new(ErrorKind::Limit))?;
        if documents > DOCUMENT_TOTAL {
            return Err(ImportFileError::new(ErrorKind::Limit));
        }
        Ok(Self {
            documents,
            resources: 0,
            selected_files: 0,
        })
    }
    fn reserve(&mut self, role: InputRole, length: u64) -> Result<usize, ImportFileError> {
        let count = self
            .selected_files
            .checked_add(1)
            .filter(|count| *count <= SELECTED_FILE_LIMIT)
            .ok_or_else(|| ImportFileError::new(ErrorKind::Limit))?;
        if length > role.limit() {
            return Err(ImportFileError::new(ErrorKind::Limit));
        }
        let (total, cap) = if role == InputRole::ResourceBytes {
            (&mut self.resources, RESOURCE_TOTAL)
        } else {
            (&mut self.documents, DOCUMENT_TOTAL)
        };
        let next = total
            .checked_add(length)
            .filter(|value| *value <= cap)
            .ok_or_else(|| ImportFileError::new(ErrorKind::Limit))?;
        let allocation =
            usize::try_from(length).map_err(|_| ImportFileError::new(ErrorKind::Limit))?;
        *total = next;
        self.selected_files = count;
        Ok(allocation)
    }
}

/// Pure lexical policy: no exists/canonicalize/metadata/open/hash occurs here.
pub(crate) fn validate_selection(path: &Path, role: InputRole) -> Result<(), ImportFileError> {
    validate_lexical(path, role).map_err(|error| error.for_role(role))
}
fn validate_lexical(path: &Path, role: InputRole) -> Result<(), ImportFileError> {
    let unsafe_path = || ImportFileError::new(ErrorKind::UnsafeSelection);
    let text = path.to_str().ok_or_else(unsafe_path)?;
    if text.len() > 4096
        || !path.is_absolute()
        || text.chars().any(char::is_control)
        || path.components().count() > 66
        || path.file_name().is_none()
    {
        return Err(unsafe_path());
    }
    // components() normalizes interior '.', so inspect the original spelling.
    #[cfg(windows)]
    let parts = {
        let bytes = text.as_bytes();
        if bytes.len() < 4
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || !matches!(bytes[2], b'/' | b'\\')
            || text[2..].contains(':')
            || !matches!(path.components().next(), Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), std::path::Prefix::Disk(_)))
        {
            return Err(unsafe_path());
        }
        text[3..].split(['/', '\\']).collect::<Vec<_>>()
    };
    #[cfg(not(windows))]
    let parts = {
        if !text.starts_with('/') || text.contains('\\') {
            return Err(unsafe_path());
        }
        text[1..].split('/').collect::<Vec<_>>()
    };
    if parts.is_empty()
        || parts
            .last()
            .is_some_and(|part| part.eq_ignore_ascii_case("environ"))
        || parts
            .iter()
            .any(|part| part.is_empty() || matches!(*part, "." | "..") || secret_selector(part))
    {
        return Err(unsafe_path());
    }
    #[cfg(windows)]
    for part in &parts {
        let stem = part
            .split('.')
            .next()
            .unwrap_or_default()
            .trim_end_matches(' ')
            .to_ascii_lowercase();
        if part.encode_utf16().count() > 255
            || part.ends_with(['.', ' '])
            || part.contains('~')
            || part
                .chars()
                .any(|character| matches!(character, '<' | '>' | '"' | '|' | '?' | '*'))
            || matches!(stem.as_str(), "con" | "prn" | "aux" | "nul" | "clock$")
            || stem
                .strip_prefix("com")
                .or_else(|| stem.strip_prefix("lpt"))
                .is_some_and(|suffix| {
                    matches!(
                        suffix,
                        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                    )
                })
        {
            return Err(unsafe_path());
        }
    }
    if role != InputRole::ResourceBytes && path.extension() != Some(std::ffi::OsStr::new("json")) {
        return Err(unsafe_path());
    }
    Ok(())
}
fn secret_selector(component: &str) -> bool {
    let lower = component.to_ascii_lowercase();
    let compact: String = lower.chars().filter(char::is_ascii_alphanumeric).collect();
    lower.starts_with(".env")
        || matches!(
            lower.as_str(),
            ".ssh"
                | ".aws"
                | ".azure"
                | ".kube"
                | ".gnupg"
                | ".docker"
                | "gh"
                | "gcloud"
                | ".git-credentials"
                | ".npmrc"
                | ".pypirc"
                | ".netrc"
        )
        || [
            "credential",
            "serviceaccount",
            "apikey",
            "privatekey",
            "sshkey",
        ]
        .iter()
        .any(|word| compact.contains(*word))
        || lower.split(['.', '-', '_', ' ']).any(|word| {
            matches!(
                word,
                "secret" | "secrets" | "token" | "tokens" | "key" | "keys"
            )
        })
        || [
            "id_rsa",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
            "id_ecdsa_sk",
            "id_ed25519_sk",
            "id_xmss",
            "ssh_host_rsa_key",
            "ssh_host_dsa_key",
            "ssh_host_ecdsa_key",
            "ssh_host_ed25519_key",
        ]
        .iter()
        .any(|stem| {
            lower
                .strip_prefix(*stem)
                .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('.'))
        })
        || lower.rsplit_once('.').is_some_and(|(_, extension)| {
            matches!(
                extension,
                "pem" | "key" | "p8" | "p12" | "pfx" | "ppk" | "jks" | "keystore" | "kdbx"
            )
        })
}

struct Checks<'a> {
    owner: &'a NativeOwnerWitness,
    budget: &'a RequestBudget,
}
impl Checks<'_> {
    fn check(&self) -> Result<(), ImportFileError> {
        self.owner
            .check()
            .map_err(|error| ImportFileError::caused(ErrorKind::Authority, error))?;
        self.budget
            .check()
            .map_err(|error| ImportFileError::caused(ErrorKind::Request, error))
    }
    fn io<T>(&self, operation: impl FnOnce() -> io::Result<T>) -> Result<T, ImportFileError> {
        self.check()?;
        let result = operation().map_err(|error| ImportFileError::caused(ErrorKind::Io, error));
        let after = self.check();
        match (result, after) {
            (Err(mut primary), Err(checkpoint)) => {
                primary.checkpoint = Some(Box::new(checkpoint));
                Err(primary)
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }
}

pub(crate) fn read_selected(
    path: &Path,
    role: InputRole,
    owner: &NativeOwnerWitness,
    budget: &RequestBudget,
    totals: &mut ImportReadBudget,
) -> Result<Vec<u8>, ImportFileError> {
    read_selected_inner(path, role, owner, budget, totals, |_, _| {})
        .map_err(|error| error.for_role(role))
}

fn read_selected_inner(
    path: &Path,
    role: InputRole,
    owner: &NativeOwnerWitness,
    budget: &RequestBudget,
    totals: &mut ImportReadBudget,
    mut checkpoint: impl FnMut(usize, bool),
) -> Result<Vec<u8>, ImportFileError> {
    validate_selection(path, role)?;
    let checks = Checks { owner, budget };
    checks.check()?;
    let mut selected = platform::Selected::open(path, &checks)?;
    let length = selected.length();
    let capacity = totals.reserve(role, length)?;
    checks.check()?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|error: TryReserveError| ImportFileError::caused(ErrorKind::Allocation, error))?;
    let mut first_digest = Sha256::new();
    read_pass(
        selected.file(),
        length,
        &checks,
        |chunk| {
            first_digest.update(chunk);
            bytes.extend_from_slice(chunk);
        },
        |length| checkpoint(length, false),
    )?;
    selected.revalidate(&checks)?;
    checks.io(|| selected.file().seek(SeekFrom::Start(0)))?;
    let mut second_digest = Sha256::new();
    read_pass(
        selected.file(),
        length,
        &checks,
        |chunk| second_digest.update(chunk),
        |length| checkpoint(length, true),
    )?;
    selected.revalidate(&checks)?;
    checks.check()?;
    if first_digest.finalize() != second_digest.finalize() {
        return Err(ImportFileError::new(ErrorKind::Changed));
    }
    checks.check()?;
    Ok(bytes)
}
fn read_pass(
    file: &mut File,
    expected: u64,
    checks: &Checks<'_>,
    mut consume: impl FnMut(&[u8]),
    mut checkpoint: impl FnMut(usize),
) -> Result<(), ImportFileError> {
    let mut total = 0u64;
    let mut buffer = [0u8; CHUNK];
    loop {
        let remaining = expected
            .checked_sub(total)
            .ok_or_else(|| ImportFileError::new(ErrorKind::Changed))?;
        // One extra byte proves EOF without growing the reserved allocation.
        let take = usize::try_from(remaining.saturating_add(1).min(CHUNK as u64))
            .map_err(|_| ImportFileError::new(ErrorKind::Limit))?;
        let count = checks.io(|| file.read(&mut buffer[..take]))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .filter(|total| *total <= expected)
            .ok_or_else(|| ImportFileError::new(ErrorKind::Changed))?;
        consume(&buffer[..count]);
        checkpoint(total as usize);
        checks.check()?;
    }
    if total != expected {
        return Err(ImportFileError::new(ErrorKind::Changed));
    }
    Ok(())
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::{
        ffi::{CString, OsStr, OsString},
        fs::{Metadata, OpenOptions},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, OpenOptionsExt},
            },
        },
    };

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Identity {
        device: u64,
        inode: u64,
        mode: u32,
        links: u64,
        uid: u32,
        gid: u32,
        size: u64,
        mtime: i64,
        mtime_ns: i64,
        ctime: i64,
        ctime_ns: i64,
    }
    impl Identity {
        fn from(metadata: &Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                links: metadata.nlink(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                size: metadata.size(),
                mtime: metadata.mtime(),
                mtime_ns: metadata.mtime_nsec(),
                ctime: metadata.ctime(),
                ctime_ns: metadata.ctime_nsec(),
            }
        }
        fn same_directory(self, current: Self) -> bool {
            // Sibling creation may change directory times/length/link count.
            // It does not change this held directory or its anchored name.
            self.device == current.device
                && self.inode == current.inode
                && self.mode == current.mode
                && self.uid == current.uid
                && self.gid == current.gid
                && current.mode & mode(libc::S_IFMT) == mode(libc::S_IFDIR)
        }
    }
    struct Directory {
        file: File,
        identity: Identity,
        name: Option<OsString>,
    }
    pub(super) struct Selected {
        file: File,
        identity: Identity,
        parents: Vec<Directory>,
        name: OsString,
    }
    fn name(value: &OsStr) -> Result<CString, ImportFileError> {
        CString::new(value.as_bytes()).map_err(|_| ImportFileError::new(ErrorKind::UnsafeSelection))
    }
    fn open_at(
        parent: &File,
        child: &OsStr,
        directory: bool,
        checks: &Checks<'_>,
    ) -> Result<File, ImportFileError> {
        let child = name(child)?;
        checks.io(|| {
            // SAFETY: one live directory descriptor and one validated child
            // component. No creation flags or variadic mode argument are used.
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    child.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK
                        | if directory { libc::O_DIRECTORY } else { 0 },
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: ownership of this successful new descriptor transfers once.
            Ok(unsafe { File::from_raw_fd(fd) })
        })
    }
    fn stat_at(
        parent: &File,
        child: &OsStr,
        checks: &Checks<'_>,
    ) -> Result<libc::stat, ImportFileError> {
        let child = name(child)?;
        checks.io(|| {
            // SAFETY: stat output has its native layout and the anchored child
            // name is a live NUL-terminated buffer; no symlink is followed.
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    parent.as_raw_fd(),
                    child.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(stat)
        })
    }
    fn named_object(stat: &libc::stat, identity: Identity, directory: bool) -> bool {
        unsigned(stat.st_dev) == Some(identity.device)
            && unsigned(stat.st_ino) == Some(identity.inode)
            && unsigned(stat.st_mode) == Some(u64::from(identity.mode))
            && unsigned(stat.st_uid) == Some(u64::from(identity.uid))
            && unsigned(stat.st_gid) == Some(u64::from(identity.gid))
            && stat.st_mode & libc::S_IFMT
                == if directory {
                    libc::S_IFDIR
                } else {
                    libc::S_IFREG
                }
            && (directory
                || (unsigned(stat.st_nlink) == Some(1)
                    && unsigned(stat.st_size) == Some(identity.size)))
    }
    fn unsigned<T: TryInto<u64>>(value: T) -> Option<u64> {
        value.try_into().ok()
    }
    fn mode<T: Into<u32>>(value: T) -> u32 {
        value.into()
    }
    impl Selected {
        pub(super) fn open(path: &Path, checks: &Checks<'_>) -> Result<Self, ImportFileError> {
            let root = checks.io(|| {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                    )
                    .open("/")
            })?;
            let root_identity = Identity::from(&checks.io(|| root.metadata())?);
            let mut parents = vec![Directory {
                file: root,
                identity: root_identity,
                name: None,
            }];
            let components: Vec<_> = path.components().collect();
            for component in &components[1..components.len() - 1] {
                let Component::Normal(child) = component else {
                    return Err(ImportFileError::new(ErrorKind::UnsafeSelection));
                };
                let parent = parents
                    .last()
                    .ok_or_else(|| ImportFileError::new(ErrorKind::UnsafeSelection))?;
                let file = open_at(&parent.file, child, true, checks)?;
                let metadata = checks.io(|| file.metadata())?;
                if !metadata.is_dir() {
                    return Err(ImportFileError::new(ErrorKind::UnsafeSelection));
                }
                parents.push(Directory {
                    file,
                    identity: Identity::from(&metadata),
                    name: Some(child.to_os_string()),
                });
            }
            let child = path
                .file_name()
                .ok_or_else(|| ImportFileError::new(ErrorKind::UnsafeSelection))?
                .to_owned();
            let parent = &parents
                .last()
                .ok_or_else(|| ImportFileError::new(ErrorKind::UnsafeSelection))?
                .file;
            let before = stat_at(parent, &child, checks)?;
            if before.st_mode & libc::S_IFMT != libc::S_IFREG || before.st_nlink != 1 {
                return Err(ImportFileError::new(ErrorKind::UnsafeSelection));
            }
            let file = open_at(parent, &child, false, checks)?;
            let metadata = checks.io(|| file.metadata())?;
            let identity = Identity::from(&metadata);
            if !metadata.is_file() || identity.links != 1 || !named_object(&before, identity, false)
            {
                return Err(ImportFileError::new(ErrorKind::UnsafeSelection));
            }
            let selected = Self {
                file,
                identity,
                parents,
                name: child,
            };
            selected.revalidate(checks)?;
            Ok(selected)
        }
        pub(super) fn length(&self) -> u64 {
            self.identity.size
        }
        pub(super) fn file(&mut self) -> &mut File {
            &mut self.file
        }
        pub(super) fn revalidate(&self, checks: &Checks<'_>) -> Result<(), ImportFileError> {
            for (index, held) in self.parents.iter().enumerate() {
                let actual = Identity::from(&checks.io(|| held.file.metadata())?);
                if !held.identity.same_directory(actual) {
                    return Err(ImportFileError::new(ErrorKind::Changed));
                }
                if index > 0 {
                    let parent = &self.parents[index - 1];
                    let child = held
                        .name
                        .as_ref()
                        .ok_or_else(|| ImportFileError::new(ErrorKind::Changed))?;
                    if !named_object(&stat_at(&parent.file, child, checks)?, held.identity, true) {
                        return Err(ImportFileError::new(ErrorKind::Changed));
                    }
                }
            }
            let parent = &self
                .parents
                .last()
                .ok_or_else(|| ImportFileError::new(ErrorKind::Changed))?
                .file;
            if !named_object(&stat_at(parent, &self.name, checks)?, self.identity, false)
                || Identity::from(&checks.io(|| self.file.metadata())?) != self.identity
            {
                return Err(ImportFileError::new(ErrorKind::Changed));
            }
            Ok(())
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        fs::OpenOptions,
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        path::PathBuf,
    };
    use windows_sys::Win32::Foundation::SetLastError;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_TYPE_DISK,
        FILE_TYPE_UNKNOWN, GetDriveTypeW, GetFileInformationByHandle, GetFileType,
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
    fn identity(file: &File, checks: &Checks<'_>) -> Result<Identity, ImportFileError> {
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
    fn open(
        path: &Path,
        directory: bool,
        checks: &Checks<'_>,
    ) -> Result<(File, Identity), ImportFileError> {
        let file = checks.io(|| {
            OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
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
            return Err(ImportFileError::new(ErrorKind::UnsafeSelection));
        }
        Ok((file, actual))
    }
    struct Directory {
        path: PathBuf,
        file: File,
        identity: Identity,
    }
    pub(super) struct Selected {
        path: PathBuf,
        file: File,
        identity: Identity,
        parents: Vec<Directory>,
    }
    impl Selected {
        pub(super) fn open(path: &Path, checks: &Checks<'_>) -> Result<Self, ImportFileError> {
            let drive = match path.components().next() {
                Some(Component::Prefix(prefix)) => match prefix.kind() {
                    std::path::Prefix::Disk(drive) => drive,
                    _ => return Err(ImportFileError::new(ErrorKind::UnsafeSelection)),
                },
                _ => return Err(ImportFileError::new(ErrorKind::UnsafeSelection)),
            };
            let drive_root = [u16::from(drive), u16::from(b':'), u16::from(b'\\'), 0];
            checks.check()?;
            // SAFETY: fixed live drive root is NUL terminated. Mapped network,
            // removable and unrecognized volumes do not enter this cold seam.
            let drive_kind = unsafe { GetDriveTypeW(drive_root.as_ptr()) };
            checks.check()?;
            if drive_kind != 3 {
                return Err(ImportFileError::new(ErrorKind::UnsafeSelection));
            }
            let mut paths: Vec<_> = path.ancestors().skip(1).collect();
            paths.reverse();
            let mut parents = Vec::new();
            for parent in paths {
                let (file, actual) = open(parent, true, checks)?;
                parents.push(Directory {
                    path: parent.to_owned(),
                    file,
                    identity: actual,
                });
            }
            let (file, actual) = open(path, false, checks)?;
            let selected = Self {
                path: path.to_owned(),
                file,
                identity: actual,
                parents,
            };
            selected.revalidate(checks)?;
            Ok(selected)
        }
        pub(super) fn length(&self) -> u64 {
            self.identity.length
        }
        pub(super) fn file(&mut self) -> &mut File {
            &mut self.file
        }
        pub(super) fn revalidate(&self, checks: &Checks<'_>) -> Result<(), ImportFileError> {
            for held in &self.parents {
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
                    return Err(ImportFileError::new(ErrorKind::Changed));
                }
            }
            let (_fresh, named) = open(&self.path, false, checks)?;
            if identity(&self.file, checks)? != self.identity || named != self.identity {
                return Err(ImportFileError::new(ErrorKind::Changed));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "native_import_files_tests.rs"]
mod tests;

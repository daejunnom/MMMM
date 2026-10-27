// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
//! POSIX developer input observations, not a write-excluding source lock.
//!
//! Held descriptors, anchored namespace checks, file ctime/mtime and before/
//! after SHA can detect observed changes. POSIX does not deny another writer or
//! atomically bind the JVM's later pathname lookup to our descriptor. A changed
//! input may already have executed; rejecting this observation does not undo
//! that execution. These pins are distinct from the JVM's observed class bytes
//! and never issue a loaded-source closure, agent roster or target admission.
//!
//! Filesystem calls remain cooperative. O_NONBLOCK rejects blocking special
//! leaves together with fstat checks; it does not preempt regular-file I/O.

use super::*;
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr};
use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::rc::Rc;

const MAX_DIRECTORY_HANDLES: usize = 128;
const MAX_HELD_HANDLES: usize = MAX_DIRECTORY_HANDLES + MAX_INPUTS;
// This is a bounded allocation margin against the observed soft limit, not a
// claim that other already-open descriptors leave 64 actually available.
const NATIVE_HANDLE_MARGIN: u64 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileKind {
    Regular,
    Directory,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    kind: FileKind,
}
impl Identity {
    fn from_metadata(value: &Metadata) -> Result<Self, DefinitionStartupError> {
        let identity = Self {
            device: value.dev(),
            inode: value.ino(),
            mode: value.mode(),
            links: value.nlink(),
            size: value.size(),
            modified: (value.mtime(), value.mtime_nsec()),
            changed: (value.ctime(), value.ctime_nsec()),
            kind: if value.file_type().is_file() {
                FileKind::Regular
            } else if value.file_type().is_dir() {
                FileKind::Directory
            } else {
                FileKind::Other
            },
        };
        if identity.inode == 0
            || identity.links == 0
            || !(0..1_000_000_000).contains(&identity.modified.1)
            || !(0..1_000_000_000).contains(&identity.changed.1)
        {
            return Err(DefinitionStartupError::new("INPUT_IDENTITY"));
        }
        Ok(identity)
    }
    fn directory(self) -> bool {
        self.kind == FileKind::Directory
    }
    fn regular(self) -> bool {
        self.kind == FileKind::Regular
    }
    fn same_directory(self, other: Self) -> bool {
        // Directory timestamps, size and link count change with other entries.
        // They are observed in metadata, but are not a stable version counter.
        self.device == other.device
            && self.inode == other.inode
            && self.mode == other.mode
            && self.directory()
            && other.directory()
    }
}

fn io_error(kind: &'static str, error: std::io::Error) -> DefinitionStartupError {
    let mut result = DefinitionStartupError::new(kind);
    result.native_os_code = error.raw_os_error();
    result
}

fn owned_check(
    build: &storage::ManagedBuild,
    check: &Deadline<'_>,
) -> Result<(), DefinitionStartupError> {
    check.check()?;
    build.check_current_ownership().map_err(|original| {
        let mut error = DefinitionStartupError::new("OWNERSHIP");
        error.storage_error = Some(Box::new(original));
        error
    })?;
    check.check()
}

fn information(
    file: &File,
    progress: &mut impl FnMut() -> Result<(), DefinitionStartupError>,
) -> Result<Identity, DefinitionStartupError> {
    progress()?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("FILE_INFORMATION", error))?;
    progress()?;
    Identity::from_metadata(&metadata)
}

fn open_at(
    parent: Option<&File>,
    name: &OsStr,
    directory: bool,
    progress: &mut impl FnMut() -> Result<(), DefinitionStartupError>,
) -> Result<File, DefinitionStartupError> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.contains(&0)
        || parent.is_some() && (bytes.contains(&b'/') || bytes == b"." || bytes == b"..")
    {
        return Err(DefinitionStartupError::new("INPUT_PATH"));
    }
    let name = CString::new(bytes).map_err(|_| DefinitionStartupError::new("INPUT_PATH"))?;
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    progress()?;
    // SAFETY: name is a live NUL-terminated single component (or the fixed "/"
    // root), and the parent descriptor is held for the entire openat call.
    // No full pathname fallback follows unchecked intermediate components.
    let fd = unsafe {
        libc::openat(
            parent.map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd),
            name.as_ptr(),
            flags,
        )
    };
    if fd < 0 {
        return Err(io_error("OPEN_INPUT", std::io::Error::last_os_error()));
    }
    // SAFETY: successful openat returned one new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    progress()?;
    Ok(file)
}

struct LeafSample {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    size: u64,
}
impl LeafSample {
    fn matches(&self, value: Identity) -> bool {
        self.device == value.device
            && self.inode == value.inode
            && self.mode == value.mode
            && self.links == value.links
            && self.size == value.size
    }
}
fn unsigned<T: TryInto<u64>>(value: T) -> Result<u64, DefinitionStartupError> {
    value
        .try_into()
        .map_err(|_| DefinitionStartupError::new("INPUT_IDENTITY"))
}
fn mode_value<T: TryInto<u32>>(value: T) -> Result<u32, DefinitionStartupError> {
    value
        .try_into()
        .map_err(|_| DefinitionStartupError::new("INPUT_IDENTITY"))
}
fn precheck_leaf(
    parent: &File,
    name: &OsStr,
    role: DefinitionSourceRole,
    remaining: u64,
    progress: &mut impl FnMut() -> Result<(), DefinitionStartupError>,
) -> Result<LeafSample, DefinitionStartupError> {
    let encoded =
        CString::new(name.as_bytes()).map_err(|_| DefinitionStartupError::new("INPUT_PATH"))?;
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    progress()?;
    // SAFETY: the held parent descriptor and live leaf string identify exactly
    // one anchored component. NOFOLLOW observes the leaf without opening a
    // FIFO/device or reading contents. A subsequent swap remains a POSIX race,
    // checked by actual descriptor identity; this is not write exclusion.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            encoded.as_ptr(),
            &mut value,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io_error(
            "FILE_INFORMATION",
            std::io::Error::last_os_error(),
        ));
    }
    progress()?;
    if value.st_mode & libc::S_IFMT != libc::S_IFREG
        || value.st_nlink != 1
        || value.st_size <= 0
        || role == DefinitionSourceRole::JavaExecutable && value.st_mode & 0o111 == 0
    {
        return Err(DefinitionStartupError::new("INPUT_FILE"));
    }
    let sample = LeafSample {
        device: unsigned(value.st_dev)?,
        inode: unsigned(value.st_ino)?,
        mode: mode_value(value.st_mode)?,
        links: unsigned(value.st_nlink)?,
        size: unsigned(value.st_size)?,
    };
    if sample.size > role.max_bytes() || sample.size > remaining {
        return Err(DefinitionStartupError::new("INPUT_FILE"));
    }
    Ok(sample)
}

fn handle_budget(soft_limit: u64) -> Result<usize, DefinitionStartupError> {
    let available = soft_limit.saturating_sub(NATIVE_HANDLE_MARGIN);
    let budget = available.min(MAX_HELD_HANDLES as u64) as usize;
    if budget == 0 {
        return Err(DefinitionStartupError::new("INPUT_HANDLE_BUDGET"));
    }
    Ok(budget)
}

fn native_handle_budget(
    progress: &mut impl FnMut() -> Result<(), DefinitionStartupError>,
) -> Result<usize, DefinitionStartupError> {
    progress()?;
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: this is a correctly sized output structure for the current process.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io_error(
            "INPUT_HANDLE_LIMIT",
            std::io::Error::last_os_error(),
        ));
    }
    progress()?;
    handle_budget(limit.rlim_cur)
}

struct DirectoryPin {
    path: PathBuf,
    file: File,
    identity: Identity,
}
#[derive(Default)]
pub(super) struct PinContext {
    directories: BTreeMap<PathBuf, Rc<DirectoryPin>>,
    files: usize,
    max_handles: Option<usize>,
}
impl PinContext {
    fn room(
        &mut self,
        directory: bool,
        progress: &mut impl FnMut() -> Result<(), DefinitionStartupError>,
    ) -> Result<(), DefinitionStartupError> {
        let budget = match self.max_handles {
            Some(value) => value,
            None => {
                let value = native_handle_budget(progress)?;
                self.max_handles = Some(value);
                value
            }
        };
        if self.directories.len() + self.files >= budget
            || directory && self.directories.len() >= MAX_DIRECTORY_HANDLES
            || !directory && self.files >= MAX_INPUTS
        {
            return Err(DefinitionStartupError::new("INPUT_HANDLE_BUDGET"));
        }
        Ok(())
    }
}

struct InputPin {
    path: PathBuf,
    file: File,
    identity: Identity,
    directories: Vec<Rc<DirectoryPin>>,
    report: DefinitionSourcePin,
}

fn namespace(
    path: &Path,
    context: &mut PinContext,
    progress: &mut impl FnMut() -> Result<(), DefinitionStartupError>,
) -> Result<Vec<Rc<DirectoryPin>>, DefinitionStartupError> {
    validate_input_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| DefinitionStartupError::new("INPUT_PATH"))?;
    let mut held = Vec::new();
    let mut current = PathBuf::from("/");
    for component in
        std::iter::once(OsStr::new("/")).chain(parent.components().filter_map(|component| {
            if let Component::Normal(name) = component {
                Some(name)
            } else {
                None
            }
        }))
    {
        if component != OsStr::new("/") {
            current.push(component);
        }
        let previous = held.last().map(|pin: &Rc<DirectoryPin>| &pin.file);
        if !context.directories.contains_key(&current) {
            context.room(true, progress)?;
        }
        let file = open_at(previous, component, true, progress)?;
        let identity = information(&file, progress)?;
        if !identity.directory() {
            return Err(DefinitionStartupError::new("INPUT_ANCESTRY"));
        }
        let pin = match context.directories.get(&current) {
            Some(existing) => {
                let existing_identity = information(&existing.file, progress)?;
                if !identity.same_directory(existing.identity)
                    || !existing_identity.same_directory(existing.identity)
                {
                    return Err(DefinitionStartupError::new("SOURCE_CHANGED"));
                }
                Rc::clone(existing)
            }
            None => {
                let pin = Rc::new(DirectoryPin {
                    path: current.clone(),
                    file,
                    identity,
                });
                context.directories.insert(current.clone(), Rc::clone(&pin));
                pin
            }
        };
        held.push(pin);
    }
    Ok(held)
}

fn recheck_namespace(
    directories: &[Rc<DirectoryPin>],
    progress: &mut impl FnMut() -> Result<(), DefinitionStartupError>,
) -> Result<File, DefinitionStartupError> {
    let mut current = None;
    for directory in directories {
        let held = information(&directory.file, progress)?;
        let name = if current.is_none() {
            OsStr::new("/")
        } else {
            directory
                .path
                .file_name()
                .ok_or_else(|| DefinitionStartupError::new("INPUT_PATH"))?
        };
        let file = open_at(current.as_ref(), name, true, progress)?;
        let observed = information(&file, progress)?;
        if !held.same_directory(directory.identity) || !observed.same_directory(directory.identity)
        {
            return Err(DefinitionStartupError::new("SOURCE_CHANGED"));
        }
        current = Some(file);
    }
    current.ok_or_else(|| DefinitionStartupError::new("INPUT_ANCESTRY"))
}

fn hash(
    file: &mut File,
    limit: u64,
    progress: &mut impl FnMut() -> Result<(), DefinitionStartupError>,
) -> Result<(u64, String), DefinitionStartupError> {
    progress()?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("READ_INPUT", error))?;
    progress()?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        progress()?;
        let count = file
            .read(&mut buffer)
            .map_err(|error| io_error("READ_INPUT", error))?;
        progress()?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| DefinitionStartupError::new("INPUT_SIZE"))?;
        if total > limit {
            return Err(DefinitionStartupError::new("INPUT_SIZE"));
        }
        digest.update(&buffer[..count]);
    }
    if total == 0 {
        return Err(DefinitionStartupError::new("INPUT_SIZE"));
    }
    let result = (total, format!("{:x}", digest.finalize()));
    progress()?;
    Ok(result)
}

impl InputPin {
    fn acquire_checked(
        context: &mut PinContext,
        role: DefinitionSourceRole,
        path: &Path,
        remaining: u64,
        progress: &mut impl FnMut() -> Result<(), DefinitionStartupError>,
    ) -> Result<Self, DefinitionStartupError> {
        let directories = namespace(path, context, progress)?;
        context.room(false, progress)?;
        let parent = directories
            .last()
            .ok_or_else(|| DefinitionStartupError::new("INPUT_ANCESTRY"))?;
        let name = path
            .file_name()
            .ok_or_else(|| DefinitionStartupError::new("INPUT_PATH"))?;
        let before = precheck_leaf(&parent.file, name, role, remaining, progress)?;
        let mut file = open_at(Some(&parent.file), name, false, progress)?;
        let identity = information(&file, progress)?;
        if !before.matches(identity) {
            return Err(DefinitionStartupError::new("SOURCE_CHANGED"));
        }
        if !identity.regular()
            || identity.links != 1
            || identity.size == 0
            || identity.size > role.max_bytes()
            || identity.size > remaining
            || role == DefinitionSourceRole::JavaExecutable && identity.mode & 0o111 == 0
        {
            return Err(DefinitionStartupError::new("INPUT_FILE"));
        }
        let (size, sha256) = hash(&mut file, role.max_bytes().min(remaining), progress)?;
        if size != identity.size || information(&file, progress)? != identity {
            return Err(DefinitionStartupError::new("SOURCE_CHANGED"));
        }
        context.files += 1;
        let mut result = Self {
            path: path.to_owned(),
            file,
            identity,
            directories,
            report: DefinitionSourcePin { role, size, sha256 },
        };
        result.recheck_checked(progress)?;
        Ok(result)
    }
    fn recheck_checked(
        &mut self,
        progress: &mut impl FnMut() -> Result<(), DefinitionStartupError>,
    ) -> Result<(), DefinitionStartupError> {
        let parent = recheck_namespace(&self.directories, progress)?;
        let name = self
            .path
            .file_name()
            .ok_or_else(|| DefinitionStartupError::new("INPUT_PATH"))?;
        let before = precheck_leaf(
            &parent,
            name,
            self.report.role,
            self.report.role.max_bytes(),
            progress,
        )?;
        let current = open_at(Some(&parent), name, false, progress)?;
        if information(&self.file, progress)? != self.identity
            || information(&current, progress)? != self.identity
            || !before.matches(self.identity)
        {
            return Err(DefinitionStartupError::new("SOURCE_CHANGED"));
        }
        let (size, sha256) = hash(&mut self.file, self.report.role.max_bytes(), progress)?;
        if size != self.report.size
            || sha256 != self.report.sha256
            || information(&self.file, progress)? != self.identity
            || information(&current, progress)? != self.identity
        {
            return Err(DefinitionStartupError::new("SOURCE_CHANGED"));
        }
        // Hashing the held descriptor does not itself revalidate namespace
        // changes during that read. Reconnect from root after hashing too.
        let after_parent = recheck_namespace(&self.directories, progress)?;
        let after = precheck_leaf(
            &after_parent,
            name,
            self.report.role,
            self.report.role.max_bytes(),
            progress,
        )?;
        let after_file = open_at(Some(&after_parent), name, false, progress)?;
        if !after.matches(self.identity) || information(&after_file, progress)? != self.identity {
            return Err(DefinitionStartupError::new("SOURCE_CHANGED"));
        }
        progress()
    }
}

impl StartupInputPin for InputPin {
    type Context = PinContext;
    fn acquire(
        context: &mut Self::Context,
        role: DefinitionSourceRole,
        path: &Path,
        build: &storage::ManagedBuild,
        check: &Deadline<'_>,
        remaining: u64,
    ) -> Result<Self, DefinitionStartupError> {
        Self::acquire_checked(context, role, path, remaining, &mut || {
            owned_check(build, check)
        })
    }
    fn source_identity(&self) -> (u64, u64) {
        (self.identity.device, self.identity.inode)
    }
    fn report(&self) -> &DefinitionSourcePin {
        &self.report
    }
    fn recheck(
        &mut self,
        build: &storage::ManagedBuild,
        check: &Deadline<'_>,
    ) -> Result<(), DefinitionStartupError> {
        self.recheck_checked(&mut || owned_check(build, check))
    }
}

pub(super) fn run(
    build: &storage::ManagedBuild,
    selection: &DefinitionStartupSelection,
    cancellation: &AtomicBool,
) -> Result<DefinitionStartupRun, DefinitionStartupError> {
    run_with_pins::<InputPin>(build, selection, cancellation)
}

#[cfg(test)]
#[path = "definition_startup_unix_tests.rs"]
mod tests;

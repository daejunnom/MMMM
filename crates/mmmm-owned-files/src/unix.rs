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
pub struct Selected {
    file: File,
    identity: Identity,
    parents: Vec<Arc<Directory>>,
    name: OsString,
}
fn name<C: Control>(value: &OsStr, checks: &C) -> Result<CString, C::Error> {
    CString::new(value.as_bytes()).map_err(|_| checks.unsafe_selection())
}
fn open_at<C: Control>(
    parent: &File,
    child: &OsStr,
    directory: bool,
    checks: &C,
) -> Result<File, C::Error> {
    let child = name(child, checks)?;
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
fn stat_at<C: Control>(parent: &File, child: &OsStr, checks: &C) -> Result<libc::stat, C::Error> {
    let child = name(child, checks)?;
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
    pub fn open_selected<C: Control>(path: &Path, checks: &C) -> Result<Self, C::Error> {
        if !is_ordinary_absolute_path(path) {
            return Err(checks.unsafe_selection());
        }
        let parents = open_directories(
            path.parent().ok_or_else(|| checks.unsafe_selection())?,
            checks,
        )?;
        let child = path
            .file_name()
            .ok_or_else(|| checks.unsafe_selection())?
            .to_owned();
        let parent = &parents
            .last()
            .ok_or_else(|| checks.unsafe_selection())?
            .file;
        let before = stat_at(parent, &child, checks)?;
        if before.st_mode & libc::S_IFMT != libc::S_IFREG || before.st_nlink != 1 {
            return Err(checks.unsafe_selection());
        }
        let file = open_at(parent, &child, false, checks)?;
        let metadata = checks.io(|| file.metadata())?;
        let identity = Identity::from(&metadata);
        if !metadata.is_file() || identity.links != 1 || !named_object(&before, identity, false) {
            return Err(checks.unsafe_selection());
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
    pub fn length(&self) -> u64 {
        self.identity.size
    }
    pub fn file(&mut self) -> &mut File {
        &mut self.file
    }
    pub fn revalidate<C: Control>(&self, checks: &C) -> Result<(), C::Error> {
        revalidate_directories(&self.parents, checks)?;
        let parent = &self.parents.last().ok_or_else(|| checks.changed())?.file;
        if !named_object(&stat_at(parent, &self.name, checks)?, self.identity, false)
            || Identity::from(&checks.io(|| self.file.metadata())?) != self.identity
        {
            return Err(checks.changed());
        }
        Ok(())
    }
}

fn open_directories<C: Control>(path: &Path, checks: &C) -> Result<Vec<Arc<Directory>>, C::Error> {
    let root = checks.io(|| {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open("/")
    })?;
    let root_identity = Identity::from(&checks.io(|| root.metadata())?);
    let mut parents = vec![Arc::new(Directory {
        file: root,
        identity: root_identity,
        name: None,
    })];
    let components: Vec<_> = path.components().collect();
    for component in &components[1..] {
        let Component::Normal(child) = component else {
            return Err(checks.unsafe_selection());
        };
        let parent = parents.last().ok_or_else(|| checks.unsafe_selection())?;
        let file = open_at(&parent.file, child, true, checks)?;
        let metadata = checks.io(|| file.metadata())?;
        if !metadata.is_dir() {
            return Err(checks.unsafe_selection());
        }
        parents.push(Arc::new(Directory {
            file,
            identity: Identity::from(&metadata),
            name: Some(child.to_os_string()),
        }));
    }

    Ok(parents)
}
fn revalidate_directories<C: Control>(
    parents: &[Arc<Directory>],
    checks: &C,
) -> Result<(), C::Error> {
    for (index, held) in parents.iter().enumerate() {
        let actual = Identity::from(&checks.io(|| held.file.metadata())?);
        if !held.identity.same_directory(actual) {
            return Err(checks.changed());
        }
        if index > 0 {
            let parent = &parents[index - 1];
            let child = held.name.as_ref().ok_or_else(|| checks.changed())?;
            if !named_object(&stat_at(&parent.file, child, checks)?, held.identity, true) {
                return Err(checks.changed());
            }
        }
    }
    Ok(())
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
    pub(crate) fn existing_child_directory<C: Control>(
        &self,
        child: &OsStr,
        checks: &C,
    ) -> Result<Option<Self>, C::Error> {
        if !ordinary_child(child) || self.parents.len() >= 66 {
            return Err(checks.unsafe_selection());
        }
        self.revalidate(checks)?;
        let parent = &self.parents.last().ok_or_else(|| checks.changed())?.file;
        let native = name(child, checks)?;
        let found = checks.io(|| {
            // SAFETY: one held parent, closed child and native-sized output.
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    parent.as_raw_fd(),
                    native.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0
            {
                return Ok(Some(stat));
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                Ok(None)
            } else {
                Err(error)
            }
        })?;
        let Some(before) = found else {
            self.revalidate(checks)?;
            return Ok(None);
        };
        if before.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(checks.unsafe_selection());
        }
        let file = open_at(parent, child, true, checks)?;
        let actual = Identity::from(&checks.io(|| file.metadata())?);
        if !named_object(&before, actual, true) {
            return Err(checks.changed());
        }
        let mut parents = self.parents.clone();
        parents.push(Arc::new(Directory {
            file,
            identity: actual,
            name: Some(child.to_owned()),
        }));
        let directory = Self { parents };
        directory.revalidate(checks)?;
        Ok(Some(directory))
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
    pub fn require_child_absent<C: Control>(
        &self,
        child: &OsStr,
        checks: &C,
    ) -> Result<(), C::Error> {
        if !ordinary_child(child) {
            return Err(checks.unsafe_selection());
        }
        self.revalidate(checks)?;
        let parent = &self.parents.last().ok_or_else(|| checks.changed())?.file;
        let child = name(child, checks)?;
        let absent = checks.io(|| {
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: live held parent, one closed child component and native output.
            if unsafe {
                libc::fstatat(
                    parent.as_raw_fd(),
                    child.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0
            {
                return Ok(false);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
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
        child: &OsStr,
        checks: &C,
    ) -> Result<Self, C::Error> {
        if !ordinary_child(child) || self.parents.len() >= 66 {
            return Err(checks.unsafe_selection());
        }
        self.revalidate(checks)?;
        let parent = &self.parents.last().ok_or_else(|| checks.changed())?.file;
        let native = name(child, checks)?;
        checks.io(|| {
            // SAFETY: one held parent and closed component. EEXIST is an error,
            // even for an empty directory. mkdirat does not return an inode pin;
            // POSIX replacement between mkdir/open remains cooperative.
            if unsafe { libc::mkdirat(parent.as_raw_fd(), native.as_ptr(), 0o700) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })?;
        checks.io(|| parent.sync_all())?;
        let file = open_at(parent, child, true, checks)?;
        let actual = Identity::from(&checks.io(|| file.metadata())?);
        let named = stat_at(parent, child, checks)?;
        if !named_object(&named, actual, true) {
            return Err(checks.changed());
        }
        let mut parents = self.parents.clone();
        parents.push(Arc::new(Directory {
            file,
            identity: actual,
            name: Some(child.to_owned()),
        }));
        let created = Self { parents };
        created.revalidate(checks)?;
        Ok(created)
    }
    pub fn create_file_new<C: Control>(
        &self,
        child: &OsStr,
        expected_length: u64,
        checks: &C,
    ) -> Result<CreatedFile, C::Error> {
        if !ordinary_child(child) || self.parents.len() >= 66 {
            return Err(checks.unsafe_selection());
        }
        self.revalidate(checks)?;
        let parent = &self.parents.last().ok_or_else(|| checks.changed())?.file;
        let native = name(child, checks)?;
        let file = checks.io(|| {
            // SAFETY: O_EXCL/O_NOFOLLOW creation of one previously absent child;
            // the successful descriptor has one new owner. No overwrite fallback.
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    native.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC
                        | libc::O_NONBLOCK,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { File::from_raw_fd(fd) })
        })?;
        checks.io(|| parent.sync_all())?;
        let metadata = checks.io(|| file.metadata())?;
        let actual = Identity::from(&metadata);
        if !metadata.is_file()
            || actual.links != 1
            || actual.size != 0
            || !named_object(&stat_at(parent, child, checks)?, actual, false)
        {
            return Err(checks.unsafe_selection());
        }
        let selected = Selected {
            file,
            identity: actual,
            parents: self.parents.clone(),
            name: child.to_owned(),
        };
        selected.revalidate(checks)?;
        Ok(CreatedFile::new(selected, expected_length))
    }
    /// Releases owned references, checking actual close only for each last pin.
    /// No namespace deletion occurs; a shared pin remains owned by its child.
    pub fn close<C: Control>(self, checks: &C) -> Result<(), C::Error> {
        release_pins(self.parents, checks, |directory| directory.file)
    }
}
impl Selected {
    pub(crate) fn seal_created<C: Control>(&mut self, checks: &C) -> Result<(), C::Error> {
        let current = Identity::from(&checks.io(|| self.file.metadata())?);
        if current.device != self.identity.device
            || current.inode != self.identity.inode
            || current.mode != self.identity.mode
            || current.uid != self.identity.uid
            || current.gid != self.identity.gid
            || current.links != 1
        {
            return Err(checks.changed());
        }
        let parent = &self.parents.last().ok_or_else(|| checks.changed())?.file;
        if !named_object(&stat_at(parent, &self.name, checks)?, current, false) {
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

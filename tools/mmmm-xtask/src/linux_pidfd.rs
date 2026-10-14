//! Private process-lifetime witnesses for already identified Linux members.
//!
//! A pathname error is never a witness. The only producer holds a flags=0
//! pidfd, verifies its positive Pid through the original procfs namespace, and
//! rereads the original stat FD before accepting a single nonblocking poll.
use super::Identity;

const FDINFO_BYTES: usize = 4096;
const POLL_IN: i16 = 0x0001;
const POLL_RDNORM: i16 = 0x0040;
const POLL_HUP: i16 = 0x0010;

/// This type is neither serialized nor a signal/drain authority. Only the
/// private native producer can construct one outside this module's tests.
pub(super) struct TerminalWitness {
    identity: Identity,
}

impl TerminalWitness {
    pub(super) fn matches(&self, before: Identity, after: Identity) -> bool {
        self.identity == before && self.identity == after
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PollObservation {
    Terminal,
    NotReady,
    Unknown,
}

fn classify_poll(result: i32, events: i16) -> PollObservation {
    if result == 0 && events == 0 {
        return PollObservation::NotReady;
    }
    // POLLIN is the process-lifetime event. Known accompanying read/hangup
    // bits are allowed; ERR, NVAL, unrelated and future bits are never proof.
    if result == 1 && events & POLL_IN != 0 && events & !(POLL_IN | POLL_RDNORM | POLL_HUP) == 0 {
        PollObservation::Terminal
    } else {
        PollObservation::Unknown
    }
}

fn canonical_positive_pid(bytes: &[u8]) -> Option<i32> {
    if bytes.is_empty()
        || bytes[0] == b'0'
        || bytes.len() > 10
        || !bytes.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    std::str::from_utf8(bytes)
        .ok()?
        .parse::<i32>()
        .ok()
        .filter(|pid| *pid > 0)
}

fn fdinfo_pid(bytes: &[u8]) -> Option<i32> {
    if bytes.len() > FDINFO_BYTES {
        return None;
    }
    let mut pid = None;
    for line in bytes.split(|byte| *byte == b'\n') {
        if let Some(value) = line.strip_prefix(b"Pid:") {
            if pid.is_some() {
                return None;
            }
            pid = Some(canonical_positive_pid(super::trim(value))?);
        }
    }
    pid
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BindingUnavailable {
    Unsupported,
    DescriptorFailure,
    ProcfsBoundary,
    Namespace,
    MetadataUnavailable,
}

#[cfg(target_os = "linux")]
pub(super) enum Binding {
    Bound(BoundPidfd),
    Unavailable(BindingUnavailable),
    // Only the original stat FD's existing ESRCH rule can produce this case.
    OriginalGone,
}

#[cfg(target_os = "linux")]
pub(super) struct BoundPidfd {
    descriptor: std::os::fd::OwnedFd,
    identity: Identity,
}

#[cfg(target_os = "linux")]
impl BoundPidfd {
    pub(super) fn terminal_after(&self, after: Identity) -> Option<TerminalWitness> {
        if self.identity != after {
            return None;
        }
        match native::poll_once(&self.descriptor) {
            PollObservation::Terminal => Some(TerminalWitness {
                identity: self.identity,
            }),
            PollObservation::NotReady | PollObservation::Unknown => None,
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn bind(
    root: &std::fs::File,
    directory: &std::fs::File,
    original_stat: &mut std::fs::File,
    before: super::Stat,
    read_original: impl FnOnce(&mut std::fs::File) -> Result<Option<super::Stat>, super::ProcessError>,
) -> Result<Binding, super::ProcessError> {
    native::bind(root, directory, original_stat, before, read_original)
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const PROC_MAGIC: libc::c_long = 0x9fa0;
    const READ_CALLS: usize = 8;
    const SELF_BYTES: usize = 64;
    // Linux v6.8 include/uapi/linux/openat2.h. No general openat fallback.
    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    // Keep every namespace handle alive through the original stat reread.
    // They refer only to the supervisor's own fixed procfs metadata.
    struct NamespaceFiles {
        _self_link: File,
        _self_directory: File,
        _fdinfo_directory: File,
        fdinfo: File,
    }

    pub(super) fn bind(
        root: &File,
        directory: &File,
        original_stat: &mut File,
        before: super::super::Stat,
        read_original: impl FnOnce(
            &mut File,
        )
            -> Result<Option<super::super::Stat>, super::super::ProcessError>,
    ) -> Result<Binding, super::super::ProcessError> {
        let prepared = prepare(root, directory, original_stat, before.identity);
        let (descriptor, namespace_files) = match prepared {
            Ok(prepared) => prepared,
            Err(reason) => return Ok(Binding::Unavailable(reason)),
        };
        // All partial binding handles remain owned while the original stat
        // FD, never a reopened numeric pathname, checks full identity again.
        let after = read_original(original_stat)?;
        let Some(after) = after else {
            return Ok(Binding::OriginalGone);
        };
        super::super::verify_identity(before, after)?;
        drop(namespace_files);
        Ok(Binding::Bound(BoundPidfd {
            descriptor,
            identity: before.identity,
        }))
    }

    fn prepare(
        root: &File,
        directory: &File,
        original_stat: &File,
        identity: Identity,
    ) -> Result<(OwnedFd, NamespaceFiles), BindingUnavailable> {
        if identity.pid <= 0 {
            return Err(BindingUnavailable::Namespace);
        }
        let root_mount = proc_mount(root, libc::S_IFDIR)?;
        if proc_mount(directory, libc::S_IFDIR)? != root_mount
            || proc_mount(original_stat, libc::S_IFREG)? != root_mount
        {
            return Err(BindingUnavailable::ProcfsBoundary);
        }
        // flags=0 binds a whole thread group. PIDFD_THREAD is deliberately
        // unavailable here; a single thread's exit cannot settle an RSS error.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, identity.pid, 0u32) };
        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            return Err(if unsupported(&error) {
                BindingUnavailable::Unsupported
            } else {
                BindingUnavailable::DescriptorFailure
            });
        }
        // Successful Linux FD syscalls return an int. Owning it immediately
        // ensures every later failure closes the actual kernel handle.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor as libc::c_int) };
        let mut files = own_fdinfo(root, root_mount, &descriptor)?;
        let bytes = read_fdinfo(&mut files.fdinfo)?;
        if fdinfo_pid(&bytes) != Some(identity.pid) {
            return Err(BindingUnavailable::Namespace);
        }
        Ok((descriptor, files))
    }

    fn own_fdinfo(
        root: &File,
        root_mount: u64,
        descriptor: &OwnedFd,
    ) -> Result<NamespaceFiles, BindingUnavailable> {
        // O_PATH|O_NOFOLLOW pins the actual final self symlink. openat2's
        // NO_SYMLINKS permits this explicit final-link handle without following
        // it; NO_XDEV forbids replacing it with another procfs bind mount.
        let self_link = open_component(
            root,
            c"self",
            libc::O_PATH | libc::O_NOFOLLOW,
            libc::S_IFLNK,
            root_mount,
        )?;
        let mut target = [0u8; SELF_BYTES];
        let length = unsafe {
            libc::syscall(
                libc::SYS_readlinkat,
                self_link.as_raw_fd(),
                c"".as_ptr(),
                target.as_mut_ptr(),
                target.len(),
            )
        };
        if length <= 0 || length as usize >= target.len() {
            return Err(BindingUnavailable::MetadataUnavailable);
        }
        // Kernel proc/self reports the caller TGID in this procfs namespace.
        let self_pid = canonical_positive_pid(&target[..length as usize])
            .ok_or(BindingUnavailable::Namespace)?;
        let self_name =
            CString::new(self_pid.to_string()).map_err(|_| BindingUnavailable::Namespace)?;
        let self_directory = open_component(
            root,
            &self_name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            libc::S_IFDIR,
            root_mount,
        )?;
        let fdinfo_directory = open_component(
            &self_directory,
            c"fdinfo",
            libc::O_RDONLY | libc::O_DIRECTORY,
            libc::S_IFDIR,
            root_mount,
        )?;
        let fd_name = CString::new(descriptor.as_raw_fd().to_string())
            .map_err(|_| BindingUnavailable::DescriptorFailure)?;
        let fdinfo = open_component(
            &fdinfo_directory,
            &fd_name,
            libc::O_RDONLY,
            libc::S_IFREG,
            root_mount,
        )?;
        Ok(NamespaceFiles {
            _self_link: self_link,
            _self_directory: self_directory,
            _fdinfo_directory: fdinfo_directory,
            fdinfo,
        })
    }

    fn open_component(
        directory: &File,
        name: &CStr,
        flags: libc::c_int,
        kind: libc::mode_t,
        root_mount: u64,
    ) -> Result<File, BindingUnavailable> {
        let how = OpenHow {
            flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLVE_NO_XDEV
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_SYMLINKS
                | RESOLVE_BENEATH,
        };
        let descriptor = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                directory.as_raw_fd(),
                name.as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            return Err(if unsupported(&error) {
                BindingUnavailable::Unsupported
            } else if matches!(error.raw_os_error(), Some(libc::EXDEV) | Some(libc::ELOOP)) {
                BindingUnavailable::ProcfsBoundary
            } else {
                BindingUnavailable::MetadataUnavailable
            });
        }
        let file = unsafe { File::from_raw_fd(descriptor as libc::c_int) };
        if proc_mount(&file, kind)? != root_mount {
            return Err(BindingUnavailable::ProcfsBoundary);
        }
        Ok(file)
    }

    fn proc_mount(file: &File, kind: libc::mode_t) -> Result<u64, BindingUnavailable> {
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0 {
            return Err(BindingUnavailable::MetadataUnavailable);
        }
        if filesystem.f_type != PROC_MAGIC {
            return Err(BindingUnavailable::ProcfsBoundary);
        }
        let mut attributes: libc::statx = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::syscall(
                libc::SYS_statx,
                file.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_MNT_ID | libc::STATX_TYPE,
                &mut attributes,
            )
        };
        if result != 0 {
            return Err(if unsupported(&std::io::Error::last_os_error()) {
                BindingUnavailable::Unsupported
            } else {
                BindingUnavailable::MetadataUnavailable
            });
        }
        if attributes.stx_mask & (libc::STATX_MNT_ID | libc::STATX_TYPE)
            != (libc::STATX_MNT_ID | libc::STATX_TYPE)
        {
            return Err(BindingUnavailable::Unsupported);
        }
        if libc::mode_t::from(attributes.stx_mode) & libc::S_IFMT != kind
            || attributes.stx_mnt_id == 0
        {
            return Err(BindingUnavailable::ProcfsBoundary);
        }
        Ok(attributes.stx_mnt_id)
    }

    fn read_fdinfo(file: &mut File) -> Result<Vec<u8>, BindingUnavailable> {
        let mut bytes = Vec::with_capacity(FDINFO_BYTES);
        for _ in 0..READ_CALLS {
            let mut buffer = [0u8; 1024];
            let remaining = (FDINFO_BYTES + 1 - bytes.len()).min(buffer.len());
            match file.read(&mut buffer[..remaining]) {
                Ok(0) => return Ok(bytes),
                Ok(read) => {
                    bytes.extend_from_slice(&buffer[..read]);
                    if bytes.len() > FDINFO_BYTES {
                        return Err(BindingUnavailable::MetadataUnavailable);
                    }
                }
                // No new retry clock or EINTR retry authority for the witness.
                Err(_) => return Err(BindingUnavailable::MetadataUnavailable),
            }
        }
        Err(BindingUnavailable::MetadataUnavailable)
    }

    fn unsupported(error: &std::io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS) | Some(libc::EINVAL)
        )
    }

    pub(super) fn poll_once(descriptor: &OwnedFd) -> PollObservation {
        let mut descriptor = libc::pollfd {
            fd: descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Linux v6.8 pidfd_poll reports readable only once the whole group
        // exits. One syscall with timeout=0; no wait, signal, retry, or reap.
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        classify_poll(result, descriptor.revents)
    }
}

#[cfg(test)]
#[path = "linux_pidfd_tests.rs"]
mod tests;

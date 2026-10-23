//! Held ordinary files and CreateNew-only children shared by native consumers.
//!
//! This is a physical I/O kernel, not a source, request or write grant. Consumers
//! supply their original authority/deadline checkpoints and limits. On POSIX,
//! held descriptors and named pre/post checks do not atomically exclude a
//! same-UID namespace replacement/ABA or concurrent content writer. A regular
//! filesystem call is cooperative and cannot be interrupted by these checks.
//! No operation adopts, overwrites, renames, deletes or cleans a partial child.

use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path},
    sync::Arc,
};

#[cfg(unix)]
#[path = "unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "windows.rs"]
mod platform;
#[cfg(windows)]
pub use platform::NativeCreateFailure;
pub use platform::{HeldDirectory, Selected as HeldFile};

/// Includes the DOS mapping retained alongside a native NT create failure.
pub fn native_os_error(error: &io::Error) -> Option<i32> {
    #[cfg(windows)]
    if let Some(native) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<NativeCreateFailure>())
    {
        return native.dos_error();
    }
    error.raw_os_error()
}

pub const CHUNK_BYTES: usize = 64 * 1024;

/// The acquisition strength of the held leaf, not a content or loaded-use claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryIdentityEvidence {
    /// The exact synchronous NtCreateFile FILE_CREATED output handle is held.
    WindowsCreateReturnedHandle,
    /// An existing ordinary directory was opened; no creation is asserted.
    WindowsOpenedHandle,
    /// mkdirat/openat and named checks do not atomically exclude POSIX ABA.
    PosixCooperative,
}
impl DirectoryIdentityEvidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WindowsCreateReturnedHandle => "windows_create_returned_handle",
            Self::WindowsOpenedHandle => "windows_opened_handle",
            Self::PosixCooperative => "posix_cooperative_held_descriptor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetainedCloseStage {
    BeforeClose,
    NativeClose,
    AfterClose,
}

/// A cause remains the consumer's original typed error, including native errors.
#[derive(Debug)]
pub struct RetainedCloseFailure<E> {
    /// Root-to-leaf ancestry index; None denotes a whole-release checkpoint.
    pub pin: Option<usize>,
    pub stage: RetainedCloseStage,
    pub error: E,
}

/// A release observation, not an assertion that every process handle is closed.
/// Constructors bound ancestry to 66 pins, hence at most 200 retained causes.
/// Shared pins can include ancestry retained by an unresolved native create.
#[derive(Debug)]
pub struct RetainedCloseReport<E> {
    pub pins: usize,
    /// Native close returned success, even if its surrounding checkpoint failed.
    pub closed: usize,
    /// Another Arc existed at try_unwrap; its eventual close was not observed.
    pub shared: usize,
    /// Native close failed. It was consumed once and is never retried.
    pub native_close_uncertain: usize,
    pub failures: Vec<RetainedCloseFailure<E>>,
}
impl<E> RetainedCloseReport<E> {
    pub fn all_pins_closed(&self) -> bool {
        self.closed == self.pins && self.shared == 0 && self.native_close_uncertain == 0
    }
}

/// Borrowed per-operation checks. No callback, request or authority is retained.
/// The consumer owns its closed error taxonomy and both original causal errors.
pub trait Control {
    type Error;
    fn check(&self) -> Result<(), Self::Error>;
    fn io_error(&self, error: io::Error) -> Self::Error;
    fn unsafe_selection(&self) -> Self::Error;
    fn changed(&self) -> Self::Error;
    /// Retain existing causes as well as this additional post-operation failure.
    fn with_post_failure(&self, primary: Self::Error, post: Self::Error) -> Self::Error;
    fn io<T>(&self, operation: impl FnOnce() -> io::Result<T>) -> Result<T, Self::Error> {
        self.check()?;
        let result = operation().map_err(|error| self.io_error(error));
        let after = self.check();
        match (result, after) {
            (Err(primary), Err(post)) => Err(self.with_post_failure(primary, post)),
            (Err(error), _) | (_, Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }
}

/// Only byte length and SHA from actual same-handle original-byte verification.
/// This contains no native identity, path, authority, loaded-source or use claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileFacts {
    pub length: u64,
    pub sha256: [u8; 32],
}

pub struct CreatedFile {
    selected: HeldFile,
    expected_length: u64,
    written: u64,
    failed: bool,
}

impl HeldDirectory {
    /// Compare the actual held leaf with a newly opened ordinary selection.
    /// Both ancestry chains are checked around the native identity reads. A
    /// successful match carries only identity_evidence()'s platform strength.
    /// No path spelling, hash, file roster or loaded-source causality is proof.
    pub fn matches_selected_root<C: Control>(
        &self,
        selected: &Path,
        control: &C,
    ) -> Result<bool, C::Error> {
        if !is_ordinary_absolute_path(selected) {
            return Err(control.unsafe_selection());
        }
        self.revalidate(control)?;
        let current = match Self::open_root(selected, control) {
            Ok(current) => current,
            Err(error) => return followup(Err(error), self.revalidate(control), control),
        };
        let result = self.same_leaf_identity(&current, control);
        let result = followup(result, current.revalidate(control), control);
        let mut result = followup(result, self.revalidate(control), control);
        let report = current.close_retained(control);
        // Fresh selection pins have no borrower. Do not silently treat an
        // unexpected shared pin as a successful release or identity observation.
        if report.shared != 0 {
            result = followup(result, Err(control.changed()), control);
        }
        for failure in report.failures {
            result = followup(result, Err(failure.error), control);
        }
        followup(result, self.revalidate(control), control)
    }

    /// Historical metadata-only absence below this held root. Every component
    /// is checked before any I/O; an existing file/link or final leaf is fatal.
    /// First native missing-name observation is not future write permission.
    pub fn require_descendant_absent<C: Control>(
        &self,
        components: &[&std::ffi::OsStr],
        control: &C,
    ) -> Result<(), C::Error> {
        if components.is_empty()
            || components.len() > 64
            || components.iter().any(|name| !ordinary_child(name))
        {
            return Err(control.unsafe_selection());
        }
        let mut held = self.shared();
        let result = (|| {
            self.revalidate(control)?;
            for (index, component) in components.iter().enumerate() {
                if index + 1 == components.len() {
                    return held.require_child_absent(component, control);
                }
                match held.existing_child_directory(component, control)? {
                    Some(child) => held = child,
                    None => return Ok(()),
                }
            }
            Err(control.unsafe_selection())
        })();
        // Preserve original native failure and every following check/close cause.
        let result = followup(result, self.revalidate(control), control);
        followup(result, held.close(control), control)
    }
}

fn followup<T, C: Control>(
    primary: Result<T, C::Error>,
    after: Result<(), C::Error>,
    control: &C,
) -> Result<T, C::Error> {
    match (primary, after) {
        (Err(primary), Err(after)) => Err(control.with_post_failure(primary, after)),
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}
impl CreatedFile {
    pub(crate) fn new(selected: HeldFile, expected_length: u64) -> Self {
        Self {
            selected,
            expected_length,
            written: 0,
            failed: false,
        }
    }
    /// Writes only the caller's already bounded original bytes, in finite chunks.
    pub fn write_all<C: Control>(&mut self, bytes: &[u8], control: &C) -> Result<(), C::Error> {
        if self.failed {
            return Err(control.changed());
        }
        self.failed = true;
        let result = self.write_original_chunk(bytes, control);
        if result.is_ok() {
            self.failed = false;
        }
        result
    }
    fn write_original_chunk<C: Control>(
        &mut self,
        bytes: &[u8],
        control: &C,
    ) -> Result<(), C::Error> {
        control.check()?;
        let next = self
            .written
            .checked_add(bytes.len() as u64)
            .filter(|next| *next <= self.expected_length)
            .ok_or_else(|| control.unsafe_selection())?;
        for chunk in bytes.chunks(CHUNK_BYTES) {
            control.io(|| self.selected.file().write_all(chunk))?;
        }
        self.written = next;
        control.check()?;
        Ok(())
    }
    pub fn verify_original<C: Control>(
        &mut self,
        original: &[u8],
        control: &C,
    ) -> Result<FileFacts, C::Error> {
        if self.failed {
            return Err(control.changed());
        }
        self.failed = true;
        let result = self.verify_original_inner(original, control);
        if result.is_ok() {
            self.failed = false;
        }
        result
    }
    fn verify_original_inner<C: Control>(
        &mut self,
        original: &[u8],
        control: &C,
    ) -> Result<FileFacts, C::Error> {
        if original.len() as u64 != self.expected_length || self.written != self.expected_length {
            return Err(control.changed());
        }
        control.io(|| self.selected.file().sync_all())?;
        // Record content metadata only after our own writes, retaining the exact
        // originally created object and anchored name. Never accept another file.
        self.selected.seal_created(control)?;
        let mut digest = Sha256::new();
        for pass in 0..2 {
            control.io(|| self.selected.file().seek(SeekFrom::Start(0)))?;
            let mut offset = 0usize;
            let mut buffer = [0u8; CHUNK_BYTES];
            loop {
                let take = (original.len() - offset).saturating_add(1).min(CHUNK_BYTES);
                let count = control.io(|| self.selected.file().read(&mut buffer[..take]))?;
                if count == 0 {
                    break;
                }
                let end = offset
                    .checked_add(count)
                    .filter(|end| *end <= original.len())
                    .ok_or_else(|| control.changed())?;
                if buffer[..count] != original[offset..end] {
                    return Err(control.changed());
                }
                if pass == 0 {
                    digest.update(&buffer[..count]);
                }
                offset = end;
            }
            if offset != original.len() {
                return Err(control.changed());
            }
            self.selected.revalidate(control)?;
        }
        control.check()?;
        Ok(FileFacts {
            length: self.expected_length,
            sha256: digest.finalize().into(),
        })
    }
    /// Releases this file and its ancestry references. Partial files stay intact.
    /// A failed native close is uncertain and is never retried.
    pub fn close<C: Control>(self, control: &C) -> Result<(), C::Error> {
        self.selected.close(control)
    }
}

fn ordinary_child(value: &std::ffi::OsStr) -> bool {
    let Some(text) = value.to_str() else {
        return false;
    };
    if text.is_empty()
        || text.len() > 255
        || text.chars().any(char::is_control)
        || text.contains(['/', '\\', ':'])
        || matches!(text, "." | "..")
        || secret_selector(text)
        || text.eq_ignore_ascii_case("environ")
    {
        return false;
    }
    // Apply the same absolute-path component policy without any filesystem I/O.
    #[cfg(windows)]
    {
        is_ordinary_absolute_path(&Path::new("C:\\").join(value))
    }
    #[cfg(not(windows))]
    {
        is_ordinary_absolute_path(&Path::new("/").join(value))
    }
}

fn release_pins<T, C: Control>(
    pins: Vec<Arc<T>>,
    control: &C,
    file: impl Fn(T) -> File,
) -> Result<(), C::Error> {
    control.check()?;
    for pin in pins.into_iter().rev() {
        if let Ok(owned) = Arc::try_unwrap(pin) {
            close_file(file(owned), control)?;
        }
    }
    control.check()
}

fn release_retained_pins<T, C: Control>(
    pins: Vec<Arc<T>>,
    control: &C,
    file: impl Fn(T) -> File,
) -> RetainedCloseReport<C::Error> {
    release_retained_pins_with(pins, control, |owned| close_file_native(file(owned)))
}

fn release_retained_pins_with<T, C: Control>(
    pins: Vec<Arc<T>>,
    control: &C,
    mut close: impl FnMut(T) -> io::Result<()>,
) -> RetainedCloseReport<C::Error> {
    let mut report = RetainedCloseReport {
        pins: pins.len(),
        closed: 0,
        shared: 0,
        native_close_uncertain: 0,
        failures: Vec::with_capacity(pins.len() * 3 + 2),
    };
    if let Err(error) = control.check() {
        report.failures.push(RetainedCloseFailure {
            pin: None,
            stage: RetainedCloseStage::BeforeClose,
            error,
        });
    }
    for (index, pin) in pins.into_iter().enumerate().rev() {
        let owned = match Arc::try_unwrap(pin) {
            Ok(owned) => owned,
            Err(shared) => {
                report.shared += 1;
                drop(shared);
                continue;
            }
        };
        if let Err(error) = control.check() {
            report.failures.push(RetainedCloseFailure {
                pin: Some(index),
                stage: RetainedCloseStage::BeforeClose,
                error,
            });
        }
        // Cleanup owns this last reference. Cancellation is recorded above,
        // but never prevents its one physical close attempt or later closes.
        match close(owned) {
            Ok(()) => report.closed += 1,
            Err(error) => {
                report.native_close_uncertain += 1;
                report.failures.push(RetainedCloseFailure {
                    pin: Some(index),
                    stage: RetainedCloseStage::NativeClose,
                    error: control.io_error(error),
                });
            }
        }
        if let Err(error) = control.check() {
            report.failures.push(RetainedCloseFailure {
                pin: Some(index),
                stage: RetainedCloseStage::AfterClose,
                error,
            });
        }
    }
    if let Err(error) = control.check() {
        report.failures.push(RetainedCloseFailure {
            pin: None,
            stage: RetainedCloseStage::AfterClose,
            error,
        });
    }
    report
}

fn close_file<C: Control>(file: File, control: &C) -> Result<(), C::Error> {
    // Drop still releases the uniquely owned handle if the pre-check fails.
    control.io(|| close_file_native(file))
}

fn close_file_native(file: File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::IntoRawFd;
        let fd = file.into_raw_fd();
        // SAFETY: consumes exactly one owned descriptor; EINTR/other failure
        // is not retried because ownership after close may be uncertain.
        if unsafe { libc::close(fd) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::IntoRawHandle;
        let handle = file.into_raw_handle();
        // SAFETY: consumes exactly one owned live Windows file handle.
        if unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn is_ordinary_absolute_path(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    if text.len() > 4096
        || !path.is_absolute()
        || text.chars().any(char::is_control)
        || path.components().count() > 66
        || path.file_name().is_none()
    {
        return false;
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
            return false;
        }
        text[3..].split(['/', '\\']).collect::<Vec<_>>()
    };
    #[cfg(not(windows))]
    let parts = {
        if !text.starts_with('/') || text.contains('\\') {
            return false;
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
        return false;
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
            return false;
        }
    }
    true
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

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

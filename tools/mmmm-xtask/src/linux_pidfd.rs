//! Private process-lifetime witnesses for already identified Linux members.
//!
//! A pathname error is never a witness. The only producer holds a flags=0
//! pidfd, verifies its positive Pid through the original procfs namespace, and
//! rereads the original stat FD before accepting a single nonblocking poll.
use super::Identity;
#[cfg(any(target_os = "linux", test))]
use super::Stat;
use serde::Serialize;
use std::fmt;

const FDINFO_BYTES: usize = 4096;
const POLL_IN: i16 = 0x0001;
const POLL_RDNORM: i16 = 0x0040;
const POLL_HUP: i16 = 0x0010;

/// Closed secondary observations. These carry no process, path, fdinfo or
/// process-lifetime authority, and never replace an original metadata error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(in super::super) struct Diagnostic {
    phase: DiagnosticPhase,
    category: DiagnosticCategory,
    native_errno: Option<i32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum DiagnosticPhase {
    InputIdentity,
    ProcRootFilesystem,
    ProcRootMetadata,
    ProcessDirectoryFilesystem,
    ProcessDirectoryMetadata,
    OriginalStatFilesystem,
    OriginalStatMetadata,
    PidfdOpen,
    SelfLinkOpen,
    SelfLinkFilesystem,
    SelfLinkMetadata,
    SelfLinkRead,
    SelfLinkParse,
    SelfDirectoryOpen,
    SelfDirectoryFilesystem,
    SelfDirectoryMetadata,
    FdinfoDirectoryOpen,
    FdinfoDirectoryFilesystem,
    FdinfoDirectoryMetadata,
    FdinfoOpen,
    FdinfoFilesystem,
    FdinfoMetadata,
    FdinfoRead,
    FdinfoParse,
    FdinfoPidMatch,
    TerminalIdentity,
    TerminalPoll,
}

impl DiagnosticPhase {
    const fn label(self) -> &'static str {
        match self {
            Self::InputIdentity => "input_identity",
            Self::ProcRootFilesystem => "proc_root_filesystem",
            Self::ProcRootMetadata => "proc_root_metadata",
            Self::ProcessDirectoryFilesystem => "process_directory_filesystem",
            Self::ProcessDirectoryMetadata => "process_directory_metadata",
            Self::OriginalStatFilesystem => "original_stat_filesystem",
            Self::OriginalStatMetadata => "original_stat_metadata",
            Self::PidfdOpen => "pidfd_open",
            Self::SelfLinkOpen => "self_link_open",
            Self::SelfLinkFilesystem => "self_link_filesystem",
            Self::SelfLinkMetadata => "self_link_metadata",
            Self::SelfLinkRead => "self_link_read",
            Self::SelfLinkParse => "self_link_parse",
            Self::SelfDirectoryOpen => "self_directory_open",
            Self::SelfDirectoryFilesystem => "self_directory_filesystem",
            Self::SelfDirectoryMetadata => "self_directory_metadata",
            Self::FdinfoDirectoryOpen => "fdinfo_directory_open",
            Self::FdinfoDirectoryFilesystem => "fdinfo_directory_filesystem",
            Self::FdinfoDirectoryMetadata => "fdinfo_directory_metadata",
            Self::FdinfoOpen => "fdinfo_open",
            Self::FdinfoFilesystem => "fdinfo_filesystem",
            Self::FdinfoMetadata => "fdinfo_metadata",
            Self::FdinfoRead => "fdinfo_read",
            Self::FdinfoParse => "fdinfo_parse",
            Self::FdinfoPidMatch => "fdinfo_pid_match",
            Self::TerminalIdentity => "terminal_identity",
            Self::TerminalPoll => "terminal_poll",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum DiagnosticCategory {
    Terminal,
    NotReady,
    Unsupported,
    NativeFailure,
    ProcfsMismatch,
    MountMismatch,
    FileTypeMismatch,
    MissingMetadata,
    InvalidSelfLink,
    InvalidFdinfo,
    NamespaceMismatch,
    InvalidIdentity,
    ReadByteBound,
    ReadCallBound,
    IdentityMismatch,
    UnexpectedPollResult,
    UnexpectedPollEvents,
}

impl DiagnosticCategory {
    const fn label(self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
            Self::NotReady => "not_ready",
            Self::Unsupported => "unsupported",
            Self::NativeFailure => "native_failure",
            Self::ProcfsMismatch => "procfs_mismatch",
            Self::MountMismatch => "mount_mismatch",
            Self::FileTypeMismatch => "file_type_mismatch",
            Self::MissingMetadata => "missing_metadata",
            Self::InvalidSelfLink => "invalid_self_link",
            Self::InvalidFdinfo => "invalid_fdinfo",
            Self::NamespaceMismatch => "namespace_mismatch",
            Self::InvalidIdentity => "invalid_identity",
            Self::ReadByteBound => "read_byte_bound",
            Self::ReadCallBound => "read_call_bound",
            Self::IdentityMismatch => "identity_mismatch",
            Self::UnexpectedPollResult => "unexpected_poll_result",
            Self::UnexpectedPollEvents => "unexpected_poll_events",
        }
    }
}

impl Diagnostic {
    pub(super) fn terminal_not_ready(self) -> bool {
        self.phase == DiagnosticPhase::TerminalPoll
            && self.category == DiagnosticCategory::NotReady
            && self.native_errno.is_none()
    }

    pub(in super::super) const fn new(
        phase: DiagnosticPhase,
        category: DiagnosticCategory,
        native_errno: Option<i32>,
    ) -> Self {
        Self {
            phase,
            category,
            native_errno,
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pidfd_observation(phase={}; category={}; native_errno={:?})",
            self.phase.label(),
            self.category.label(),
            self.native_errno,
        )
    }
}

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

struct PollCheck {
    observation: PollObservation,
    diagnostic: Diagnostic,
}

fn classify_poll_with_diagnostic(result: i32, events: i16, native_errno: Option<i32>) -> PollCheck {
    let observation = classify_poll(result, events);
    let category = match observation {
        PollObservation::Terminal => DiagnosticCategory::Terminal,
        PollObservation::NotReady => DiagnosticCategory::NotReady,
        PollObservation::Unknown if result < 0 => DiagnosticCategory::NativeFailure,
        PollObservation::Unknown if result != 1 => DiagnosticCategory::UnexpectedPollResult,
        PollObservation::Unknown => DiagnosticCategory::UnexpectedPollEvents,
    };
    PollCheck {
        observation,
        diagnostic: Diagnostic::new(
            DiagnosticPhase::TerminalPoll,
            category,
            if result < 0 { native_errno } else { None },
        ),
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
    Unsupported(Diagnostic),
    DescriptorFailure(Diagnostic),
    ProcfsBoundary(Diagnostic),
    Namespace(Diagnostic),
    MetadataUnavailable(Diagnostic),
}

#[cfg(target_os = "linux")]
impl BindingUnavailable {
    pub(super) fn diagnostic(self) -> Diagnostic {
        match self {
            Self::Unsupported(diagnostic)
            | Self::DescriptorFailure(diagnostic)
            | Self::ProcfsBoundary(diagnostic)
            | Self::Namespace(diagnostic)
            | Self::MetadataUnavailable(diagnostic) => diagnostic,
        }
    }
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
pub(super) struct TerminalCheck {
    pub(super) witness: Option<TerminalWitness>,
    pub(super) diagnostic: Diagnostic,
}

/// A single stack-scoped observation of the original lifetime. It cannot be
/// cloned, serialized or rebound to another retained descriptor.
#[cfg(target_os = "linux")]
pub(super) struct OriginalLifetimeRetirementProof<'fd> {
    binding: &'fd BoundPidfd,
    before: Stat,
    after: Stat,
}

#[cfg(target_os = "linux")]
impl OriginalLifetimeRetirementProof<'_> {
    pub(super) fn matches(&self, binding: &BoundPidfd, before: Stat, after: Stat) -> bool {
        std::ptr::eq(self.binding, binding)
            && retirement_transition(binding.identity, before, after)
            && same_stat(self.before, before)
            && same_stat(self.after, after)
    }
}

#[cfg(target_os = "linux")]
pub(super) struct RetirementCheck<'fd> {
    pub(super) proof: Option<OriginalLifetimeRetirementProof<'fd>>,
    pub(super) diagnostic: Diagnostic,
}

#[cfg(any(target_os = "linux", test))]
fn retirement_transition(original: Identity, before: Stat, after: Stat) -> bool {
    original.pid > 0
        && original.group > 0
        && original.group == original.session
        && original.pid != original.group
        && before.identity == original
        && before.state == b'Z'
        && before.threads == 2
        && after.state == b'X'
        && after.threads == 0
        && after.identity.pid == original.pid
        && after.identity.start_ticks == original.start_ticks
        && after.identity.group == -1
        && after.identity.session == -1
}

#[cfg(target_os = "linux")]
fn same_stat(left: Stat, right: Stat) -> bool {
    left.identity == right.identity
        && left.state == right.state
        && left.threads == right.threads
        && left.virtual_bytes == right.virtual_bytes
        && left.exiting == right.exiting
}

#[cfg(target_os = "linux")]
impl BoundPidfd {
    pub(super) fn poll_original_retirement<'fd>(
        &'fd self,
        before: Stat,
        after: Stat,
        control: &mut super::ObservationControl<'_>,
    ) -> Result<RetirementCheck<'fd>, super::ProcessError> {
        control.check("original_lifetime_retirement_before")?;
        if !retirement_transition(self.identity, before, after) {
            let diagnostic = Diagnostic::new(
                DiagnosticPhase::TerminalIdentity,
                DiagnosticCategory::IdentityMismatch,
                None,
            );
            return control.finish(Err(super::ProcessError::new(
                "process_identity", "original lifetime retirement does not match its retained owned-member transition",
            ).with_linux_pidfd_diagnostic(diagnostic)), "original_lifetime_retirement_after");
        }
        let check = native::poll_once(&self.descriptor);
        if let Err(post) = control.check("original_lifetime_retirement_after") {
            return Err(if check.observation == PollObservation::Unknown {
                append_error(diagnostic_error(check.diagnostic), post)
            } else {
                post.with_linux_pidfd_diagnostic(check.diagnostic)
            });
        }
        Ok(RetirementCheck {
            proof: match check.observation {
                PollObservation::Terminal => Some(OriginalLifetimeRetirementProof {
                    binding: self,
                    before,
                    after,
                }),
                PollObservation::NotReady | PollObservation::Unknown => None,
            },
            diagnostic: check.diagnostic,
        })
    }

    /// Close is consuming and always attempted once, even after cancellation.
    /// Linux close errors are observed; this never retries the numeric FD.
    pub(super) fn close(
        self,
        control: &mut super::ObservationControl<'_>,
    ) -> Result<(), super::ProcessError> {
        native::close_descriptor(self.descriptor, control, "original_lifetime_close")
    }

    pub(super) fn check_terminal_after(&self, after: Identity) -> TerminalCheck {
        if self.identity != after {
            return TerminalCheck {
                witness: None,
                diagnostic: Diagnostic::new(
                    DiagnosticPhase::TerminalIdentity,
                    DiagnosticCategory::IdentityMismatch,
                    None,
                ),
            };
        }
        let check = native::poll_once(&self.descriptor);
        let witness = match check.observation {
            PollObservation::Terminal => Some(TerminalWitness {
                identity: self.identity,
            }),
            PollObservation::NotReady | PollObservation::Unknown => None,
        };
        TerminalCheck {
            witness,
            diagnostic: check.diagnostic,
        }
    }

    #[cfg(test)]
    pub(super) fn terminal_after(&self, after: Identity) -> Option<TerminalWitness> {
        self.check_terminal_after(after).witness
    }
}

#[cfg(all(target_os = "linux", test))]
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
pub(super) fn bind_controlled(
    root: &std::fs::File,
    directory: &std::fs::File,
    original_stat: &mut std::fs::File,
    before: Stat,
    read_original: impl FnOnce(
        &mut std::fs::File,
        &mut super::ObservationControl<'_>,
    ) -> Result<Option<Stat>, super::ProcessError>,
    control: &mut super::ObservationControl<'_>,
) -> Result<Binding, super::ProcessError> {
    native::bind_controlled(
        root,
        directory,
        original_stat,
        before,
        read_original,
        control,
    )
}

#[cfg(target_os = "linux")]
fn diagnostic_error(diagnostic: Diagnostic) -> super::ProcessError {
    super::ProcessError::new(
        "process_lifetime",
        format!("original lifetime metadata failed; {diagnostic}"),
    )
    .with_linux_pidfd_diagnostic(diagnostic)
}

#[cfg(target_os = "linux")]
fn append_error(
    mut original: super::ProcessError,
    following: super::ProcessError,
) -> super::ProcessError {
    original
        .message
        .push_str(&format!("; linux_lifetime_following={following}"));
    original
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

    // A control failure is never downgraded to optional metadata unavailability.
    enum NativeBindingFailure {
        Unsupported(Diagnostic),
        DescriptorFailure(Diagnostic),
        ProcfsBoundary(Diagnostic),
        Namespace(Diagnostic),
        MetadataUnavailable(Diagnostic),
        Control(super::super::ProcessError),
    }
    use NativeBindingFailure as BindingUnavailable;

    impl NativeBindingFailure {
        fn into_binding(self) -> Result<super::BindingUnavailable, super::super::ProcessError> {
            Ok(match self {
                Self::Unsupported(value) => super::BindingUnavailable::Unsupported(value),
                Self::DescriptorFailure(value) => {
                    super::BindingUnavailable::DescriptorFailure(value)
                }
                Self::ProcfsBoundary(value) => super::BindingUnavailable::ProcfsBoundary(value),
                Self::Namespace(value) => super::BindingUnavailable::Namespace(value),
                Self::MetadataUnavailable(value) => {
                    super::BindingUnavailable::MetadataUnavailable(value)
                }
                Self::Control(error) => return Err(error),
            })
        }

        fn into_error(self) -> super::super::ProcessError {
            match self.into_binding() {
                Ok(reason) => diagnostic_error(reason.diagnostic()),
                Err(error) => error,
            }
        }
    }

    fn checkpoint(
        control: &mut super::super::ObservationControl<'_>,
        phase: &'static str,
    ) -> Result<(), BindingUnavailable> {
        control.check(phase).map_err(BindingUnavailable::Control)
    }

    fn step<T>(
        control: &mut super::super::ObservationControl<'_>,
        phase: &'static str,
        action: impl FnOnce() -> Result<T, BindingUnavailable>,
    ) -> Result<T, BindingUnavailable> {
        checkpoint(control, phase)?;
        match (action(), control.check(phase)) {
            (result, Ok(())) => result,
            (Ok(_), Err(post)) => Err(BindingUnavailable::Control(post)),
            (Err(original), Err(post)) => Err(BindingUnavailable::Control(append_error(
                original.into_error(),
                post,
            ))),
        }
    }

    fn finish_close<T>(
        result: Result<T, super::super::ProcessError>,
        close: Result<(), super::super::ProcessError>,
    ) -> Result<T, super::super::ProcessError> {
        match (result, close) {
            (result, Ok(())) => result,
            (Ok(_), Err(close)) => Err(close),
            (Err(original), Err(close)) => Err(append_error(original, close)),
        }
    }

    pub(super) fn close_descriptor(
        descriptor: OwnedFd,
        control: &mut super::super::ObservationControl<'_>,
        phase: &'static str,
    ) -> Result<(), super::super::ProcessError> {
        let before = control.check(phase);
        // Consume ownership before the one native close. An EINTR error must
        // not cause either a retry or a later OwnedFd drop of the reused number.
        let raw = descriptor.into_raw_fd();
        let closed = if unsafe { libc::close(raw) } == 0 {
            Ok(())
        } else {
            let error = std::io::Error::last_os_error();
            Err(super::super::ProcessError::new(
                "process_lifetime_close",
                format!(
                    "original lifetime descriptor close failed; phase={phase}; native_errno={:?}",
                    error.raw_os_error()
                ),
            ))
        };
        let observed = finish_close(before, closed);
        control.finish(observed, phase)
    }

    fn close_binding_failure(
        descriptor: OwnedFd,
        failure: BindingUnavailable,
        control: &mut super::super::ObservationControl<'_>,
        phase: &'static str,
    ) -> BindingUnavailable {
        match close_descriptor(descriptor, control, phase) {
            Ok(()) => failure,
            Err(close) => BindingUnavailable::Control(append_error(failure.into_error(), close)),
        }
    }

    fn opened(
        control: &mut super::super::ObservationControl<'_>,
        phase: &'static str,
        action: impl FnOnce() -> Result<OwnedFd, BindingUnavailable>,
    ) -> Result<OwnedFd, BindingUnavailable> {
        checkpoint(control, phase)?;
        match (action(), control.check(phase)) {
            (result, Ok(())) => result,
            (Ok(descriptor), Err(post)) => Err(close_binding_failure(
                descriptor,
                BindingUnavailable::Control(post),
                control,
                "pidfd_open_cleanup",
            )),
            (Err(original), Err(post)) => Err(BindingUnavailable::Control(append_error(
                original.into_error(),
                post,
            ))),
        }
    }

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
        files: Vec<File>,
    }

    impl NamespaceFiles {
        fn close(
            self,
            control: &mut super::super::ObservationControl<'_>,
        ) -> Result<(), super::super::ProcessError> {
            let mut result = Ok(());
            for file in self.files.into_iter().rev() {
                result = finish_close(
                    result,
                    close_descriptor(file.into(), control, "pidfd_namespace_close"),
                );
            }
            result
        }
    }

    #[derive(Clone, Copy)]
    enum NamespaceComponent {
        SelfLink,
        SelfDirectory,
        FdinfoDirectory,
        Fdinfo,
    }

    impl NamespaceComponent {
        fn phases(self) -> (DiagnosticPhase, DiagnosticPhase, DiagnosticPhase) {
            match self {
                Self::SelfLink => (
                    DiagnosticPhase::SelfLinkOpen,
                    DiagnosticPhase::SelfLinkFilesystem,
                    DiagnosticPhase::SelfLinkMetadata,
                ),
                Self::SelfDirectory => (
                    DiagnosticPhase::SelfDirectoryOpen,
                    DiagnosticPhase::SelfDirectoryFilesystem,
                    DiagnosticPhase::SelfDirectoryMetadata,
                ),
                Self::FdinfoDirectory => (
                    DiagnosticPhase::FdinfoDirectoryOpen,
                    DiagnosticPhase::FdinfoDirectoryFilesystem,
                    DiagnosticPhase::FdinfoDirectoryMetadata,
                ),
                Self::Fdinfo => (
                    DiagnosticPhase::FdinfoOpen,
                    DiagnosticPhase::FdinfoFilesystem,
                    DiagnosticPhase::FdinfoMetadata,
                ),
            }
        }
    }

    #[cfg(test)]
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
        let mut checkpoint = |_: &'static str| Ok(());
        let mut control = super::super::ObservationControl::new(&mut checkpoint, true);
        bind_controlled(
            root,
            directory,
            original_stat,
            before,
            |file, _control| read_original(file),
            &mut control,
        )
    }

    pub(super) fn bind_controlled(
        root: &File,
        directory: &File,
        original_stat: &mut File,
        before: Stat,
        read_original: impl FnOnce(
            &mut File,
            &mut super::super::ObservationControl<'_>,
        ) -> Result<Option<Stat>, super::super::ProcessError>,
        control: &mut super::super::ObservationControl<'_>,
    ) -> Result<Binding, super::super::ProcessError> {
        control.check("pidfd_binding_before")?;
        if !control.allow_new_bindings() {
            return Err(super::super::ProcessError::new(
                "process_lifetime",
                "the original observation phase forbids new lifetime bindings",
            ));
        }
        let prepared = prepare(root, directory, original_stat, before.identity, control);
        let (descriptor, namespace_files) = match prepared {
            Ok(prepared) => prepared,
            Err(reason) => {
                let reason = match control.check("pidfd_binding_unavailable_after") {
                    Ok(()) => reason,
                    Err(post) => {
                        BindingUnavailable::Control(append_error(reason.into_error(), post))
                    }
                };
                return reason.into_binding().map(Binding::Unavailable);
            }
        };
        // All partial binding handles remain owned while the original stat
        // FD, never a reopened numeric pathname, checks full identity again.
        let observation: Result<Option<Stat>, super::super::ProcessError> = (|| {
            control.check("pidfd_original_stat_before")?;
            let result = read_original(original_stat, control);
            let after = control.finish(result, "pidfd_original_stat_after")?;
            if let Some(after) = after {
                super::super::verify_identity(before, after)?;
            }
            Ok(after)
        })();
        let observation = finish_close(observation, namespace_files.close(control));
        let after = match observation {
            Ok(after) => after,
            Err(error) => {
                return finish_close(
                    Err(error),
                    close_descriptor(descriptor, control, "pidfd_binding_failure_close"),
                );
            }
        };
        if after.is_none() {
            close_descriptor(descriptor, control, "pidfd_original_gone_close")?;
            return Ok(Binding::OriginalGone);
        }
        if let Err(error) = control.check("pidfd_binding_final") {
            return finish_close(
                Err(error),
                close_descriptor(descriptor, control, "pidfd_binding_failure_close"),
            );
        }
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
        control: &mut super::super::ObservationControl<'_>,
    ) -> Result<(OwnedFd, NamespaceFiles), BindingUnavailable> {
        if identity.pid <= 0 {
            return Err(BindingUnavailable::Namespace(Diagnostic::new(
                DiagnosticPhase::InputIdentity,
                DiagnosticCategory::InvalidIdentity,
                None,
            )));
        }
        let root_mount = proc_mount(
            root,
            libc::S_IFDIR,
            DiagnosticPhase::ProcRootFilesystem,
            DiagnosticPhase::ProcRootMetadata,
            control,
        )?;
        if proc_mount(
            directory,
            libc::S_IFDIR,
            DiagnosticPhase::ProcessDirectoryFilesystem,
            DiagnosticPhase::ProcessDirectoryMetadata,
            control,
        )? != root_mount
        {
            return Err(BindingUnavailable::ProcfsBoundary(Diagnostic::new(
                DiagnosticPhase::ProcessDirectoryMetadata,
                DiagnosticCategory::MountMismatch,
                None,
            )));
        }
        if proc_mount(
            original_stat,
            libc::S_IFREG,
            DiagnosticPhase::OriginalStatFilesystem,
            DiagnosticPhase::OriginalStatMetadata,
            control,
        )? != root_mount
        {
            return Err(BindingUnavailable::ProcfsBoundary(Diagnostic::new(
                DiagnosticPhase::OriginalStatMetadata,
                DiagnosticCategory::MountMismatch,
                None,
            )));
        }
        // flags=0 binds a whole thread group. PIDFD_THREAD is deliberately
        // unavailable here; a single thread's exit cannot settle an RSS error.
        let descriptor = opened(control, "pidfd_open", || {
            let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, identity.pid, 0u32) };
            if descriptor < 0 {
                let error = std::io::Error::last_os_error();
                let diagnostic = Diagnostic::new(
                    DiagnosticPhase::PidfdOpen,
                    if unsupported(&error) {
                        DiagnosticCategory::Unsupported
                    } else {
                        DiagnosticCategory::NativeFailure
                    },
                    error.raw_os_error(),
                );
                return Err(if unsupported(&error) {
                    BindingUnavailable::Unsupported(diagnostic)
                } else {
                    BindingUnavailable::DescriptorFailure(diagnostic)
                });
            }
            // Owning a successful FD immediately covers every later failure.
            Ok(unsafe { OwnedFd::from_raw_fd(descriptor as libc::c_int) })
        })?;
        let mut files = match own_fdinfo(root, root_mount, &descriptor, control) {
            Ok(files) => files,
            Err(error) => {
                return Err(close_binding_failure(
                    descriptor,
                    error,
                    control,
                    "pidfd_prepare_failure_close",
                ));
            }
        };
        let parsed: Result<(), BindingUnavailable> = (|| {
            let bytes = read_fdinfo(&mut files.files[3], control)?;
            match fdinfo_pid(&bytes) {
                Some(actual) if actual == identity.pid => {}
                Some(_) => {
                    return Err(BindingUnavailable::Namespace(Diagnostic::new(
                        DiagnosticPhase::FdinfoPidMatch,
                        DiagnosticCategory::NamespaceMismatch,
                        None,
                    )));
                }
                None => {
                    return Err(BindingUnavailable::Namespace(Diagnostic::new(
                        DiagnosticPhase::FdinfoParse,
                        DiagnosticCategory::InvalidFdinfo,
                        None,
                    )));
                }
            }
            Ok(())
        })();
        if let Err(error) = parsed {
            let error = match files.close(control) {
                Ok(()) => error,
                Err(close) => BindingUnavailable::Control(append_error(error.into_error(), close)),
            };
            return Err(close_binding_failure(
                descriptor,
                error,
                control,
                "pidfd_prepare_failure_close",
            ));
        }
        Ok((descriptor, files))
    }

    fn own_fdinfo(
        root: &File,
        root_mount: u64,
        descriptor: &OwnedFd,
        control: &mut super::super::ObservationControl<'_>,
    ) -> Result<NamespaceFiles, BindingUnavailable> {
        let mut files = NamespaceFiles {
            files: Vec::with_capacity(4),
        };
        let result: Result<(), BindingUnavailable> = (|| {
            // O_PATH|O_NOFOLLOW pins the actual final self symlink. openat2's
            // NO_SYMLINKS permits this explicit final-link handle without following
            // it; NO_XDEV forbids replacing it with another procfs bind mount.
            files.files.push(open_component(
                root,
                c"self",
                libc::O_PATH | libc::O_NOFOLLOW,
                libc::S_IFLNK,
                root_mount,
                NamespaceComponent::SelfLink,
                control,
            )?);
            let mut target = [0u8; SELF_BYTES];
            let length = step(control, "pidfd_self_link_read", || {
                let length = unsafe {
                    libc::syscall(
                        libc::SYS_readlinkat,
                        files.files[0].as_raw_fd(),
                        c"".as_ptr(),
                        target.as_mut_ptr(),
                        target.len(),
                    )
                };
                if length <= 0 || length as usize >= target.len() {
                    let native_errno = if length < 0 {
                        std::io::Error::last_os_error().raw_os_error()
                    } else {
                        None
                    };
                    return Err(BindingUnavailable::MetadataUnavailable(Diagnostic::new(
                        DiagnosticPhase::SelfLinkRead,
                        if length < 0 {
                            DiagnosticCategory::NativeFailure
                        } else {
                            DiagnosticCategory::InvalidSelfLink
                        },
                        native_errno,
                    )));
                }
                Ok(length)
            })?;
            // Kernel proc/self reports the caller TGID in this procfs namespace.
            let self_pid = canonical_positive_pid(&target[..length as usize]).ok_or(
                BindingUnavailable::Namespace(Diagnostic::new(
                    DiagnosticPhase::SelfLinkParse,
                    DiagnosticCategory::InvalidSelfLink,
                    None,
                )),
            )?;
            let self_name = CString::new(self_pid.to_string()).map_err(|_| {
                BindingUnavailable::Namespace(Diagnostic::new(
                    DiagnosticPhase::SelfLinkParse,
                    DiagnosticCategory::InvalidSelfLink,
                    None,
                ))
            })?;
            files.files.push(open_component(
                root,
                &self_name,
                libc::O_RDONLY | libc::O_DIRECTORY,
                libc::S_IFDIR,
                root_mount,
                NamespaceComponent::SelfDirectory,
                control,
            )?);
            let fdinfo_directory = open_component(
                &files.files[1],
                c"fdinfo",
                libc::O_RDONLY | libc::O_DIRECTORY,
                libc::S_IFDIR,
                root_mount,
                NamespaceComponent::FdinfoDirectory,
                control,
            )?;
            files.files.push(fdinfo_directory);
            let fd_name = CString::new(descriptor.as_raw_fd().to_string()).map_err(|_| {
                BindingUnavailable::DescriptorFailure(Diagnostic::new(
                    DiagnosticPhase::FdinfoOpen,
                    DiagnosticCategory::InvalidIdentity,
                    None,
                ))
            })?;
            let fdinfo = open_component(
                &files.files[2],
                &fd_name,
                libc::O_RDONLY,
                libc::S_IFREG,
                root_mount,
                NamespaceComponent::Fdinfo,
                control,
            )?;
            files.files.push(fdinfo);
            Ok(())
        })();
        match result {
            Ok(()) => Ok(files),
            Err(error) => Err(match files.close(control) {
                Ok(()) => error,
                Err(close) => BindingUnavailable::Control(append_error(error.into_error(), close)),
            }),
        }
    }

    fn open_component(
        directory: &File,
        name: &CStr,
        flags: libc::c_int,
        kind: libc::mode_t,
        root_mount: u64,
        component: NamespaceComponent,
        control: &mut super::super::ObservationControl<'_>,
    ) -> Result<File, BindingUnavailable> {
        let (open_phase, filesystem_phase, metadata_phase) = component.phases();
        let how = OpenHow {
            flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLVE_NO_XDEV
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_SYMLINKS
                | RESOLVE_BENEATH,
        };
        let descriptor = opened(control, open_phase.label(), || {
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
                    BindingUnavailable::Unsupported(Diagnostic::new(
                        open_phase,
                        DiagnosticCategory::Unsupported,
                        error.raw_os_error(),
                    ))
                } else if matches!(error.raw_os_error(), Some(libc::EXDEV) | Some(libc::ELOOP)) {
                    BindingUnavailable::ProcfsBoundary(Diagnostic::new(
                        open_phase,
                        DiagnosticCategory::ProcfsMismatch,
                        error.raw_os_error(),
                    ))
                } else {
                    BindingUnavailable::MetadataUnavailable(Diagnostic::new(
                        open_phase,
                        DiagnosticCategory::NativeFailure,
                        error.raw_os_error(),
                    ))
                });
            }
            Ok(unsafe { OwnedFd::from_raw_fd(descriptor as libc::c_int) })
        })?;
        let file = File::from(descriptor);
        let inspected = proc_mount(&file, kind, filesystem_phase, metadata_phase, control)
            .and_then(|mount| {
                if mount != root_mount {
                    Err(BindingUnavailable::ProcfsBoundary(Diagnostic::new(
                        metadata_phase,
                        DiagnosticCategory::MountMismatch,
                        None,
                    )))
                } else {
                    Ok(())
                }
            });
        if let Err(error) = inspected {
            return Err(close_binding_failure(
                file.into(),
                error,
                control,
                "pidfd_component_failure_close",
            ));
        }
        Ok(file)
    }

    fn proc_mount(
        file: &File,
        kind: libc::mode_t,
        filesystem_phase: DiagnosticPhase,
        metadata_phase: DiagnosticPhase,
        control: &mut super::super::ObservationControl<'_>,
    ) -> Result<u64, BindingUnavailable> {
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        step(control, filesystem_phase.label(), || {
            if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0 {
                let error = std::io::Error::last_os_error();
                return Err(BindingUnavailable::MetadataUnavailable(Diagnostic::new(
                    filesystem_phase,
                    DiagnosticCategory::NativeFailure,
                    error.raw_os_error(),
                )));
            }
            if filesystem.f_type != PROC_MAGIC {
                return Err(BindingUnavailable::ProcfsBoundary(Diagnostic::new(
                    filesystem_phase,
                    DiagnosticCategory::ProcfsMismatch,
                    None,
                )));
            }
            Ok(())
        })?;
        let mut attributes: libc::statx = unsafe { std::mem::zeroed() };
        step(control, metadata_phase.label(), || {
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
                let error = std::io::Error::last_os_error();
                return Err(if unsupported(&error) {
                    BindingUnavailable::Unsupported(Diagnostic::new(
                        metadata_phase,
                        DiagnosticCategory::Unsupported,
                        error.raw_os_error(),
                    ))
                } else {
                    BindingUnavailable::MetadataUnavailable(Diagnostic::new(
                        metadata_phase,
                        DiagnosticCategory::NativeFailure,
                        error.raw_os_error(),
                    ))
                });
            }
            if attributes.stx_mask & (libc::STATX_MNT_ID | libc::STATX_TYPE)
                != (libc::STATX_MNT_ID | libc::STATX_TYPE)
            {
                return Err(BindingUnavailable::Unsupported(Diagnostic::new(
                    metadata_phase,
                    DiagnosticCategory::MissingMetadata,
                    None,
                )));
            }
            if libc::mode_t::from(attributes.stx_mode) & libc::S_IFMT != kind {
                return Err(BindingUnavailable::ProcfsBoundary(Diagnostic::new(
                    metadata_phase,
                    DiagnosticCategory::FileTypeMismatch,
                    None,
                )));
            }
            if attributes.stx_mnt_id == 0 {
                return Err(BindingUnavailable::ProcfsBoundary(Diagnostic::new(
                    metadata_phase,
                    DiagnosticCategory::MissingMetadata,
                    None,
                )));
            }
            Ok(attributes.stx_mnt_id)
        })
    }

    fn read_fdinfo(
        file: &mut File,
        control: &mut super::super::ObservationControl<'_>,
    ) -> Result<Vec<u8>, BindingUnavailable> {
        let mut bytes = Vec::with_capacity(FDINFO_BYTES);
        for _ in 0..READ_CALLS {
            let mut buffer = [0u8; 1024];
            let remaining = (FDINFO_BYTES + 1 - bytes.len()).min(buffer.len());
            let read = step(control, "pidfd_fdinfo_read", || {
                file.read(&mut buffer[..remaining]).map_err(|error| {
                    BindingUnavailable::MetadataUnavailable(Diagnostic::new(
                        DiagnosticPhase::FdinfoRead,
                        DiagnosticCategory::NativeFailure,
                        error.raw_os_error(),
                    ))
                })
            })?;
            match read {
                0 => return Ok(bytes),
                read => {
                    bytes.extend_from_slice(&buffer[..read]);
                    if bytes.len() > FDINFO_BYTES {
                        return Err(BindingUnavailable::MetadataUnavailable(Diagnostic::new(
                            DiagnosticPhase::FdinfoRead,
                            DiagnosticCategory::ReadByteBound,
                            None,
                        )));
                    }
                }
            }
        }
        Err(BindingUnavailable::MetadataUnavailable(Diagnostic::new(
            DiagnosticPhase::FdinfoRead,
            DiagnosticCategory::ReadCallBound,
            None,
        )))
    }

    fn unsupported(error: &std::io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS) | Some(libc::EINVAL)
        )
    }

    pub(super) fn poll_once(descriptor: &OwnedFd) -> PollCheck {
        let mut descriptor = libc::pollfd {
            fd: descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Linux v6.8 pidfd_poll reports readable only once the whole group
        // exits. One syscall with timeout=0; no wait, signal, retry, or reap.
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        let native_errno = if result < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        classify_poll_with_diagnostic(result, descriptor.revents, native_errno)
    }
}

#[cfg(test)]
#[path = "linux_pidfd_tests.rs"]
mod tests;

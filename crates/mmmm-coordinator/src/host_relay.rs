//! Anonymous host stdio is consumed by an isolated finite helper. This relay
//! opens no Store: an existing authenticated native peer performs attachment.
//! Endpoint startup ownership is provided by the same daemon composition.

use crate::{
    credential::CredentialRef,
    endpoint::{EndpointRecord, RuntimeDirectory},
    peer::{PeerError, PeerHostAttach, PendingHostCompletion},
    peer_management::{HOST_MAGIC, HostOffer, ManagementKind, PublicFrame, public_length},
    stdio_io::{NativeStdioPort, StdioError, StdioLimits},
};
use mmmm_contracts::ProjectId;
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    task::Poll,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const SESSION: Duration = Duration::from_secs(30);
const EXCHANGE: Duration = Duration::from_secs(28);
const POLL: Duration = Duration::from_millis(5);
const PUBLIC_LIMIT: u64 = 1024 * 1024;

#[derive(Debug)]
pub enum RelayError {
    Protocol,
    Deadline,
    CoordinatorUnavailable,
    Native(PeerError),
    Stdio(StdioError),
    DrainUncertain,
}
impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol => f.write_str("Host anonymous bootstrap protocol is invalid"),
            Self::Deadline => f.write_str("Host anonymous bootstrap deadline reached"),
            Self::CoordinatorUnavailable => {
                f.write_str("The authenticated local Coordinator is unavailable")
            }
            Self::Native(error) => error.fmt(f),
            Self::Stdio(error) => error.fmt(f),
            Self::DrainUncertain => {
                f.write_str("Owned host bootstrap stdio helper termination is unconfirmed")
            }
        }
    }
}
impl std::error::Error for RelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Native(error) => Some(error),
            Self::Stdio(error) => Some(error),
            _ => None,
        }
    }
}
impl From<PeerError> for RelayError {
    fn from(error: PeerError) -> Self {
        Self::Native(error)
    }
}
impl From<StdioError> for RelayError {
    fn from(error: StdioError) -> Self {
        Self::Stdio(error)
    }
}

/// Trusted local composition starts only its own approved daemon when absent.
/// The returned metadata is tokenless; this relay never starts another Store.
pub trait CoordinatorLocator {
    fn ensure_endpoint(
        &mut self,
        root: &Path,
        project: &ProjectId,
        deadline: Instant,
    ) -> Result<EndpointRecord, RelayError>;
}

pub struct ExistingCoordinator;
impl CoordinatorLocator for ExistingCoordinator {
    fn ensure_endpoint(
        &mut self,
        root: &Path,
        _project: &ProjectId,
        deadline: Instant,
    ) -> Result<EndpointRecord, RelayError> {
        check(deadline)?;
        let runtime = RuntimeDirectory::open(&root.join("runtime"))
            .map_err(|_| RelayError::CoordinatorUnavailable)?;
        let record = runtime
            .load()
            .map_err(|_| RelayError::CoordinatorUnavailable)?;
        check(deadline)?;
        Ok(record)
    }
}

/// stdout belongs to the protocol helper, including actual flush ACK. Public
/// diagnostics must go to bounded stderr and contain no frame or token bytes.
pub fn run_stdio(locator: &mut dyn CoordinatorLocator) -> Result<(), RelayError> {
    run_stdio_mode(locator, false)
}

pub fn run_approval_stdio(locator: &mut dyn CoordinatorLocator) -> Result<(), RelayError> {
    run_stdio_mode(locator, true)
}

fn run_stdio_mode(locator: &mut dyn CoordinatorLocator, approval: bool) -> Result<(), RelayError> {
    let started = Instant::now();
    let whole_deadline = started + SESSION;
    let exchange_deadline = started + EXCHANGE;
    let native = NativeStdioPort::spawn_current_raw_with_deadline(
        StdioLimits {
            session: SESSION,
            startup: Duration::from_secs(5),
            max_frames: 24,
            max_input_bytes: 2 * PUBLIC_LIMIT + 64,
            max_output_bytes: 2 * PUBLIC_LIMIT + 16,
        },
        whole_deadline,
    )?;
    let cancel = AtomicBool::new(false);
    let pending = exchange(&native, locator, exchange_deadline, &cancel, approval);
    // Reserve two seconds inside the original session bound. Terminal drain
    // proves native helper death even after partial output or clean input EOF.
    let drained = drain(&native, whole_deadline);
    match (pending, drained) {
        // Only the end-to-end Java delivery and isolated helper termination
        // allow the native acknowledgement. Until then the exact pending peer
        // connection owns a staged generation and its server's failure cleanup.
        (Ok(pending), Ok(())) => pending.complete_delivery().map_err(RelayError::from),
        (Err(error), Ok(())) => Err(error),
        (pending, Err(error)) => {
            // Dropping the pending connection sends no success acknowledgement.
            // The Coordinator retains its record until Finished(false), expiry,
            // or explicit fallible shutdown proves exact-generation retirement.
            drop(pending);
            Err(error)
        }
    }
}

fn exchange(
    native: &NativeStdioPort,
    locator: &mut dyn CoordinatorLocator,
    deadline: Instant,
    cancel: &AtomicBool,
    approval: bool,
) -> Result<PendingHostCompletion, RelayError> {
    let magic = read_exact(native, HOST_MAGIC.len(), deadline, cancel)?;
    if magic.as_slice() != HOST_MAGIC {
        return Err(RelayError::Protocol);
    }
    let public = PublicFrame::decode_owned(read_public_bytes(native, deadline, cancel)?)
        .map_err(|_| RelayError::Protocol)?;
    if public.kind() != ManagementKind::Offer {
        return Err(RelayError::Protocol);
    }
    if public.value()["kind"]
        != if approval {
            "host_apply_approval_offer"
        } else {
            "host_pairing_offer"
        }
    {
        return Err(RelayError::Protocol);
    }
    let capability = read_exact(native, 32, deadline, cancel)?;
    let mut raw = Zeroizing::new([0u8; 32]);
    raw.copy_from_slice(&capability);
    drop(capability);
    let offer = HostOffer::from_raw(public, raw).map_err(|_| RelayError::Protocol)?;
    let root = PathBuf::from(
        offer.public().value()["dataRoot"]
            .as_str()
            .ok_or(RelayError::Protocol)?,
    );
    if !root.is_absolute() {
        return Err(RelayError::Protocol);
    }
    let project = ProjectId::new(
        offer.public().value()["projectId"]
            .as_str()
            .ok_or(RelayError::Protocol)?,
    )
    .map_err(|_| RelayError::Protocol)?;
    let endpoint = locator.ensure_endpoint(&root, &project, deadline)?;
    endpoint.validate().map_err(|_| RelayError::Protocol)?;
    let reference =
        CredentialRef::new(&endpoint.credential_ref).map_err(|_| RelayError::Protocol)?;
    check(deadline)?;
    // The native peer budget must use this original relay deadline, including
    // bytes already read and daemon discovery time. It never receives a reset.
    let (attached, authority) =
        PeerHostAttach::offer_with_deadline(&root.join("runtime"), &reference, offer, deadline)?;
    write_public(native, &authority, deadline, cancel)?;
    let installed = PublicFrame::decode_owned(read_public_bytes(native, deadline, cancel)?)
        .map_err(|_| RelayError::Protocol)?;
    let (pending, complete) = attached.installed_staged(installed)?;
    check(deadline)?;
    write_public(native, &complete, deadline, cancel)?;
    // Java closes anonymous stdin after validating Complete. Extra data and
    // partial EOF are errors; capability bytes are never captured speculatively.
    loop {
        check(deadline)?;
        match native.poll_read_exact(1, deadline, cancel)? {
            Poll::Ready(None) => return Ok(pending),
            Poll::Ready(Some(_)) => return Err(RelayError::Protocol),
            Poll::Pending => std::thread::sleep(POLL),
        }
    }
}

fn read_public_bytes(
    native: &NativeStdioPort,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Zeroizing<Vec<u8>>, RelayError> {
    let prefix = read_exact(native, 4, deadline, cancel)?;
    let mut fixed = [0u8; 4];
    fixed.copy_from_slice(&prefix);
    let length = public_length(fixed).map_err(|_| RelayError::Protocol)?;
    read_exact(native, length, deadline, cancel)
}
fn read_exact(
    native: &NativeStdioPort,
    size: usize,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Zeroizing<Vec<u8>>, RelayError> {
    loop {
        check(deadline)?;
        match native.poll_read_exact(size, deadline, cancel)? {
            Poll::Ready(Some(bytes)) if bytes.len() == size => return Ok(bytes),
            Poll::Ready(_) => return Err(RelayError::Protocol),
            Poll::Pending => std::thread::sleep(POLL),
        }
    }
}
fn write_public(
    native: &NativeStdioPort,
    frame: &PublicFrame,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<(), RelayError> {
    let bytes = frame.encode().map_err(|_| RelayError::Protocol)?;
    write_raw(native, &bytes.length_prefix(), deadline, cancel)?;
    write_raw(native, bytes.payload(), deadline, cancel)
}
fn write_raw(
    native: &NativeStdioPort,
    bytes: &[u8],
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<(), RelayError> {
    loop {
        check(deadline)?;
        match native.poll_write_raw(bytes, deadline, cancel)? {
            Poll::Ready(()) => return Ok(()),
            Poll::Pending => std::thread::sleep(POLL),
        }
    }
}
fn drain(native: &NativeStdioPort, deadline: Instant) -> Result<(), RelayError> {
    loop {
        if Instant::now() >= deadline {
            return Err(RelayError::DrainUncertain);
        }
        match native
            .poll_cancel_and_drain(deadline)
            .map_err(|_| RelayError::DrainUncertain)?
        {
            Poll::Ready(result) if result.terminated && result.exit_code.is_some() => return Ok(()),
            Poll::Ready(_) => return Err(RelayError::DrainUncertain),
            Poll::Pending => std::thread::sleep(POLL),
        }
    }
}
fn check(deadline: Instant) -> Result<(), RelayError> {
    if Instant::now() >= deadline {
        Err(RelayError::Deadline)
    } else {
        Ok(())
    }
}

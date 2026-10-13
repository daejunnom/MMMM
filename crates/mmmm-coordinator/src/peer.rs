//! Bounded, same-OS-user delivery of an already-issued control token.
//!
//! This channel neither grants a new capability nor invokes application code.
//! Discovery metadata carries only the public credential reference. The server
//! owns the token in memory; no token file, argv or environment fallback exists.
//! Native peer credentials are checked in addition to filesystem/pipe security.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::credential::{CredentialRef, SecretToken};
use crate::endpoint::RuntimeDirectory;
use std::{
    fmt,
    path::Path,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[path = "peer_management_transport.rs"]
mod management_transport;
use crate::peer_management::{
    BootstrapBudget, HostOffer, ManagementError, ManagementSender, PublicFrame,
};
use management_transport::{ExchangeError, HostAttachClient, ManagementIo};

const MAGIC: &[u8; 8] = b"MMMMIPC1";
const ACK: u8 = 1;
const REFERENCE_LIMIT: usize = 128;
const MESSAGE_LIMIT: usize = 2048;
const IO_BUDGET: Duration = Duration::from_secs(5);
const POLL_SLICE: Duration = Duration::from_millis(20);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerError {
    UnsafePath,
    UnsafePermissions,
    Busy,
    PeerDenied,
    Protocol,
    UnexpectedEof { expected: usize, received: usize },
    UnexpectedBytesAfterAck,
    Timeout,
    Stopped,
    UncertainDrain,
    WorkerPanicked,
    Unsupported,
    Native(i32),
    Poll(i16),
    Management(ManagementError),
}

impl fmt::Display for PeerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafePath => formatter.write_str("peer runtime path is unsafe"),
            Self::UnsafePermissions => formatter.write_str("peer channel permissions are unsafe"),
            Self::Busy => formatter.write_str("peer channel is already occupied"),
            Self::PeerDenied => formatter.write_str("native peer identity is denied"),
            Self::Protocol => formatter.write_str("peer bootstrap protocol is invalid"),
            Self::UnexpectedEof { expected, received } => write!(
                formatter,
                "peer message ended after {received} of {expected} bytes"
            ),
            Self::UnexpectedBytesAfterAck => {
                formatter.write_str("peer sent unexpected bytes after acknowledgement")
            }
            Self::Timeout => formatter.write_str("peer bootstrap deadline expired"),
            Self::Stopped => formatter.write_str("peer bootstrap stopped"),
            Self::UncertainDrain => {
                formatter.write_str("peer native I/O completion is unconfirmed")
            }
            Self::WorkerPanicked => formatter.write_str("peer bootstrap worker failed"),
            Self::Unsupported => formatter.write_str("native peer bootstrap is unavailable"),
            Self::Native(code) => {
                write!(formatter, "peer native operation failed with status {code}")
            }
            Self::Poll(flags) => write!(formatter, "peer socket poll failed with flags {flags}"),
            Self::Management(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PeerError {}

impl From<std::io::Error> for PeerError {
    fn from(error: std::io::Error) -> Self {
        Self::Native(error.raw_os_error().unwrap_or(-1))
    }
}
impl From<ExchangeError> for PeerError {
    fn from(error: ExchangeError) -> Self {
        match error {
            ExchangeError::Native(error) => error,
            ExchangeError::Management(error) => match error {
                ManagementError::TransportUncertain => Self::UncertainDrain,
                ManagementError::Deadline => Self::Timeout,
                ManagementError::Cancelled => Self::Stopped,
                _ => Self::Management(error),
            },
        }
    }
}
fn management_budget(
    deadline: Instant,
    stop: &std::sync::atomic::AtomicBool,
    exchange: Option<&BootstrapBudget>,
) -> Result<(), PeerError> {
    if let Some(exchange) = exchange {
        exchange.check().map_err(|error| match error {
            ManagementError::Deadline => PeerError::Timeout,
            ManagementError::Cancelled => PeerError::Stopped,
            ManagementError::TransportUncertain => PeerError::UncertainDrain,
            _ => PeerError::Management(error),
        })?;
    }
    if stop.load(std::sync::atomic::Ordering::Acquire) {
        Err(PeerError::Stopped)
    } else if Instant::now() >= deadline {
        Err(PeerError::Timeout)
    } else {
        Ok(())
    }
}

pub struct PeerBootstrap {
    inner: platform::Server,
}

// Native fixture diagnostics contain only closed stages and typed status. They
// never retain a credential reference, request, token byte or runtime path.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeerNativeStage {
    Accept,
    SetNonblocking,
    ConfigureStream,
    PeerIdentity,
    RequestMagic,
    RequestLength,
    RequestReference,
    RequestValidation,
    TokenWrite,
    AckRead,
    AckValue,
    HostExchange,
    Complete,
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
type PeerNativeExchange = (PeerNativeStage, Result<(), PeerError>);

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PeerNativeTestState {
    pub last_exchange: Option<PeerNativeExchange>,
    pub worker_finished: bool,
}

/// 기존 private peer에서 두 단계 호스트 연결을 수행한다. 새 daemon/작업 원장이나
/// capability를 만들지 않으며 실제 서버의 same-account 검증 핸들을 계속 소유한다.
pub struct PeerHostAttach {
    inner: platform::HostClient,
}
/// Complete 수신 후에도 검증한 연결과 native guard를 계속 소유한다.
/// 외부 relay의 실제 flush/EOF/helper drain 이후에만 완료를 요청해야 한다.
/// Drop/abort는 ACK를 보내지 않는다. 반대편 rollback 완료의 증인은 아니다.
#[must_use = "Complete 전달과 native drain 뒤 complete_delivery를 호출하거나 취소해야 합니다"]
pub struct PendingHostCompletion {
    inner: platform::HostClient,
}
impl PendingHostCompletion {
    pub fn deadline(&self) -> Instant {
        self.inner.deadline()
    }
    /// 원래 절대 마감 안에서 ACK를 한 번 보내고 실제 native EOF를 확인한다.
    /// ACK 시도 뒤 실패는 상대의 수신 여부가 불확실할 수 있어 재전송하지 않는다.
    pub fn complete_delivery(self) -> Result<(), PeerError> {
        self.inner.complete_delivery()
    }
    pub fn abort(self) {
        self.inner.abort();
    }
}
/// actual kernel peer PID와 same-account 검증 후에만 생성하는 불투명 결과다.
/// caller가 제공한 PID/label로 이 witness를 생성하는 공개 생성자는 없다.
pub struct AuthenticatedPeerToken {
    token: SecretToken,
    server_pid: u32,
}
impl AuthenticatedPeerToken {
    pub fn server_pid(&self) -> u32 {
        self.server_pid
    }
    pub fn into_token(self) -> SecretToken {
        self.token
    }
}
impl PeerHostAttach {
    pub fn offer(
        runtime: &Path,
        reference: &CredentialRef,
        offer: HostOffer,
    ) -> Result<(Self, PublicFrame), PeerError> {
        Self::offer_with_deadline(
            runtime,
            reference,
            offer,
            Instant::now() + crate::peer_management::BOOTSTRAP_LIMIT,
        )
    }
    pub fn offer_with_deadline(
        runtime: &Path,
        reference: &CredentialRef,
        offer: HostOffer,
        deadline: Instant,
    ) -> Result<(Self, PublicFrame), PeerError> {
        let budget = BootstrapBudget::with_deadline(deadline);
        budget
            .check()
            .map_err(|error| PeerError::from(ExchangeError::from(error)))?;
        let (inner, authority) = platform::offer_host(runtime, reference, offer, budget)?;
        Ok((Self { inner }, authority))
    }
    pub fn installed_staged(
        self,
        public: PublicFrame,
    ) -> Result<(PendingHostCompletion, PublicFrame), PeerError> {
        let (inner, complete) = self.inner.installed_staged(public)?;
        Ok((PendingHostCompletion { inner }, complete))
    }
    pub fn installed(self, public: PublicFrame) -> Result<PublicFrame, PeerError> {
        let (pending, complete) = self.installed_staged(public)?;
        pending.complete_delivery()?;
        Ok(complete)
    }
}

pub fn fatal_stop_requested() -> bool {
    platform::fatal_stop_requested()
}

impl fmt::Debug for PeerBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerBootstrap")
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::{
        cell::UnsafeCell,
        ffi::c_void,
        mem::{self, MaybeUninit},
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        ptr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        thread::{self, JoinHandle},
    };
    use windows_sys::Win32::{
        Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE},
        Security::{
            ACCESS_ALLOWED_ACE, ACL, EqualSid, GetLengthSid, GetTokenInformation, InitializeAcl,
            InitializeSecurityDescriptor, IsValidSid, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
            SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
            TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::{CreateFileW, ReadFile, WriteFile},
        System::{
            IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
                GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, PeekNamedPipe,
            },
            Threading::{
                CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, WaitForSingleObject,
            },
        },
    };

    const IO_PENDING: u32 = 997;
    const IO_INCOMPLETE: u32 = 996;
    const PIPE_CONNECTED: u32 = 535;
    const PIPE_NOT_CONNECTED: u32 = 233;
    const NO_DATA: u32 = 232;
    const BROKEN_PIPE: u32 = 109;
    const WAIT_TIMEOUT: u32 = 258;
    const WAIT_OBJECT: u32 = 0;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const PIPE_ACCESS_DUPLEX: u32 = 3;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 8;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const OPEN_EXISTING: u32 = 3;
    const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
    const TOKEN_QUERY: u32 = 8;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
    const DACL_PROTECTED: u16 = 0x1000;
    const CANCEL_DRAIN: Duration = Duration::from_secs(1);

    // One server and one try-locked client channel per process bound the maximum
    // retained pending owners to two 2-KiB buffers, two events and two pipe handles.
    // No later call can create I/O once fatal completion uncertainty is observed.
    static SERVER_ACTIVE: AtomicBool = AtomicBool::new(false);
    static FATAL_STOP: AtomicBool = AtomicBool::new(false);
    static CLIENT_CHANNEL: Mutex<()> = Mutex::new(());

    #[cfg(test)]
    static TEST_CANCEL_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    #[cfg(test)]
    static TEST_RETAINED_OWNERS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    #[cfg(test)]
    static TEST_FORCE_UNKNOWN_AFTER_CANCEL: AtomicBool = AtomicBool::new(false);
    #[cfg(test)]
    static TEST_UNKNOWN_COMPLETION: AtomicBool = AtomicBool::new(false);

    pub(super) fn fatal_stop_requested() -> bool {
        FATAL_STOP.load(Ordering::Acquire)
    }

    struct Reservation;
    impl Reservation {
        fn acquire() -> Result<Self, PeerError> {
            if fatal_stop_requested() {
                return Err(PeerError::UncertainDrain);
            }
            SERVER_ACTIVE
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| PeerError::Busy)?;
            if fatal_stop_requested() {
                SERVER_ACTIVE.store(false, Ordering::Release);
                return Err(PeerError::UncertainDrain);
            }
            Ok(Self)
        }
    }
    impl Drop for Reservation {
        fn drop(&mut self) {
            SERVER_ACTIVE.store(false, Ordering::Release);
        }
    }

    struct UserSid {
        storage: Vec<usize>,
    }
    impl UserSid {
        fn current() -> Result<Self, PeerError> {
            // SAFETY: current-process pseudo handle is valid and not closed.
            Self::process(unsafe { GetCurrentProcess() })
        }
        fn process(process: HANDLE) -> Result<Self, PeerError> {
            let mut token = ptr::null_mut();
            // SAFETY: process is a held live process handle; output transfers once.
            if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
                return Err(native_error());
            }
            let token = owned(token)?;
            let mut required = 0;
            // SAFETY: documented size-query call; no token secret is requested.
            unsafe {
                GetTokenInformation(raw(&token), TokenUser, ptr::null_mut(), 0, &mut required);
            }
            if required < mem::size_of::<TOKEN_USER>() as u32 || required > 65_536 {
                return Err(PeerError::PeerDenied);
            }
            let mut storage = vec![0_usize; (required as usize).div_ceil(mem::size_of::<usize>())];
            let capacity = storage.len() * mem::size_of::<usize>();
            // SAFETY: aligned buffer covers the complete queried structure.
            if unsafe {
                GetTokenInformation(
                    raw(&token),
                    TokenUser,
                    storage.as_mut_ptr().cast(),
                    capacity as u32,
                    &mut required,
                )
            } == 0
            {
                return Err(native_error());
            }
            if required as usize > capacity {
                return Err(PeerError::PeerDenied);
            }
            let user = Self { storage };
            user.validate()?;
            Ok(user)
        }
        fn pointer(&self) -> *mut c_void {
            // SAFETY: TokenUser initialized a properly aligned TOKEN_USER prefix.
            unsafe { (*self.storage.as_ptr().cast::<TOKEN_USER>()).User.Sid }
        }
        fn validate(&self) -> Result<(), PeerError> {
            let pointer = self.pointer();
            let begin = self.storage.as_ptr() as usize;
            let end = begin + self.storage.len() * mem::size_of::<usize>();
            let address = pointer as usize;
            if address < begin || address.checked_add(8).is_none_or(|limit| limit > end) {
                return Err(PeerError::PeerDenied);
            }
            // SAFETY: the SID header lies inside the owned TokenUser buffer.
            let count = unsafe { *pointer.cast::<u8>().add(1) } as usize;
            if count > 15
                || address
                    .checked_add(8 + 4 * count)
                    .is_none_or(|limit| limit > end)
            {
                return Err(PeerError::PeerDenied);
            }
            // SAFETY: full bounded SID representation fits in the owned buffer.
            if unsafe { IsValidSid(pointer) } == 0 {
                return Err(PeerError::PeerDenied);
            }
            Ok(())
        }
        fn matches(&self, other: &Self) -> bool {
            // SAFETY: both constructor-validated SID buffers remain live.
            unsafe { EqualSid(self.pointer(), other.pointer()) != 0 }
        }
    }

    struct PrivateSecurity {
        descriptor: Box<SECURITY_DESCRIPTOR>,
        _acl: Vec<u32>,
    }
    impl PrivateSecurity {
        fn new(user: &UserSid) -> Result<Self, PeerError> {
            // SAFETY: current TokenUser SID has already been fully bounded/validated.
            let length = unsafe { GetLengthSid(user.pointer()) } as usize;
            if length == 0 || length > 68 {
                return Err(PeerError::UnsafePermissions);
            }
            let size = mem::size_of::<ACL>() + mem::size_of::<ACCESS_ALLOWED_ACE>() - 4 + length;
            let mut acl = vec![0_u32; size.div_ceil(4)];
            // SAFETY: all-zero pointer/scalar representation is valid before init.
            let mut descriptor =
                Box::new(unsafe { MaybeUninit::<SECURITY_DESCRIPTOR>::zeroed().assume_init() });
            let pointer = (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast();
            // SAFETY: live aligned ACL/SD buffers, one current-user allow ACE,
            // explicit owner and protected DACL; never a null/default DACL.
            if unsafe {
                InitializeAcl(acl.as_mut_ptr().cast(), size as u32, 2) == 0
                    || AddAccessAllowedAceEx(
                        acl.as_mut_ptr().cast(),
                        2,
                        0,
                        FILE_ALL_ACCESS,
                        user.pointer(),
                    ) == 0
                    || InitializeSecurityDescriptor(pointer, 1) == 0
                    || SetSecurityDescriptorOwner(pointer, user.pointer(), 0) == 0
                    || SetSecurityDescriptorDacl(pointer, 1, acl.as_mut_ptr().cast(), 0) == 0
                    || SetSecurityDescriptorControl(pointer, DACL_PROTECTED, DACL_PROTECTED) == 0
            } {
                return Err(native_error());
            }
            Ok(Self {
                descriptor,
                _acl: acl,
            })
        }
        fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: (&mut *self.descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                bInheritHandle: 0,
            }
        }
    }
    use windows_sys::Win32::Security::AddAccessAllowedAceEx;

    fn raw(handle: &OwnedHandle) -> HANDLE {
        handle.as_raw_handle().cast()
    }
    fn owned(handle: HANDLE) -> Result<OwnedHandle, PeerError> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(native_error());
        }
        // SAFETY: caller transfers one successful newly owned native handle.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle.cast()) })
    }
    fn native_error() -> PeerError {
        // SAFETY: reads this thread's immediately preceding failed API status.
        PeerError::Native(unsafe { GetLastError() } as i32)
    }
    fn pipe_name(reference: &CredentialRef) -> Vec<u16> {
        format!("\\\\.\\pipe\\MMMM.coordinator.{}", channel_name(reference))
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }
    /// Native open 첫 접촉에만 사용한다. 성공한 핸들을 얻으면 이 반복을
    /// 끝내고 PID/SID 검사 및 단 한 번의 교환으로 진행한다. Read/Write/ACK나
    /// 불확실한 completion 오류를 이 함수로 되돌려 재생하지 않는다.
    fn open_before_io<T>(
        deadline: Instant,
        stop: &AtomicBool,
        exchange: Option<&BootstrapBudget>,
        mut open: impl FnMut() -> Result<T, PeerError>,
    ) -> Result<T, PeerError> {
        loop {
            budget(deadline, stop)?;
            management_budget(deadline, stop, exchange)?;
            match open() {
                Ok(opened) => {
                    // Native open이 늦게 끝나도 원래 마감이 늘어나지 않는다.
                    // 만료 시 opened 소유자는 여기서 Drop하며 어떤 byte도 보내지 않는다.
                    budget(deadline, stop)?;
                    management_budget(deadline, stop, exchange)?;
                    return Ok(opened);
                }
                Err(PeerError::Native(2 | 231)) => {
                    // ERROR_FILE_NOT_FOUND 또는 ERROR_PIPE_BUSY만 아직 핸들이
                    // 없는 첫 접촉에서 재시도한다. 다른 native 오류는 그대로 반환한다.
                    budget(deadline, stop)?;
                    management_budget(deadline, stop, exchange)?;
                    thread::sleep(
                        POLL_SLICE.min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Err(error) => return Err(error),
            }
        }
    }
    fn open_client_pipe(
        name: &[u16],
        deadline: Instant,
        stop: &AtomicBool,
        exchange: Option<&BootstrapBudget>,
    ) -> Result<Arc<OwnedHandle>, PeerError> {
        open_before_io(deadline, stop, exchange, || {
            // SAFETY: canonical local NUL-terminated name remains live through
            // synchronous CreateFile, non-inheritance and identification-only
            // SQOS. This closure performs no consuming pipe I/O or token delivery.
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                return Err(native_error());
            }
            owned(handle).map(Arc::new)
        })
    }
    fn runtime_guard(path: &Path) -> Result<RuntimeDirectory, PeerError> {
        // Metadata guards absence before RuntimeDirectory::open, which otherwise
        // permits creation. Its native path/owner/DACL pins remain held throughout.
        if !std::fs::symlink_metadata(path)
            .map_err(PeerError::from)?
            .is_dir()
        {
            return Err(PeerError::UnsafePath);
        }
        RuntimeDirectory::open(path).map_err(|_| PeerError::UnsafePermissions)
    }

    pub(super) struct Server {
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<Result<(), PeerError>>>,
        _runtime: RuntimeDirectory,
        _reservation: Reservation,
    }
    impl Server {
        pub(super) fn start(
            runtime: &Path,
            reference: CredentialRef,
            token: SecretToken,
        ) -> Result<Self, PeerError> {
            Self::start_with_management(runtime, reference, token, None)
        }
        pub(super) fn start_with_management(
            runtime: &Path,
            reference: CredentialRef,
            token: SecretToken,
            management: Option<ManagementSender>,
        ) -> Result<Self, PeerError> {
            let reservation = Reservation::acquire()?;
            let runtime = runtime_guard(runtime)?;
            let user = UserSid::current()?;
            let mut security = PrivateSecurity::new(&user)?;
            let attributes = security.attributes();
            let name = pipe_name(&reference);
            // SAFETY: canonical local name, explicit live protected user-only SD,
            // non-inherited handle and OVERLAPPED byte-mode local-only pipe.
            let pipe = owned(unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    MESSAGE_LIMIT as u32,
                    MESSAGE_LIMIT as u32,
                    5000,
                    &attributes,
                )
            })?;
            let pipe = Arc::new(pipe);
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stop);
            let worker = thread::Builder::new()
                .name("mmmm-peer".to_owned())
                .spawn(move || {
                    while !worker_stop.load(Ordering::Acquire) && !fatal_stop_requested() {
                        let deadline = Instant::now() + IO_BUDGET;
                        let connected = accept_before_protocol(
                            deadline,
                            &worker_stop,
                            || {
                                native_operation(
                                    &pipe,
                                    IoKind::Connect,
                                    &[],
                                    0,
                                    deadline,
                                    &worker_stop,
                                    None,
                                )
                                .map(|_| ())
                            },
                            || disconnect_after_terminal(&pipe),
                        );
                        match connected {
                            Err(PeerError::Timeout) => continue,
                            Err(PeerError::Stopped) => break,
                            Err(error) => return Err(error),
                            Ok(_) => {}
                        }
                        let deadline = Instant::now() + IO_BUDGET;
                        let result = serve(
                            &pipe,
                            &user,
                            &reference,
                            &token,
                            deadline,
                            &worker_stop,
                            management.as_ref(),
                        );
                        if result == Err(PeerError::UncertainDrain) {
                            return result;
                        }
                        // No pending I/O remains here. Never FlushFileBuffers: that
                        // synchronous operation can wait indefinitely for a client.
                        disconnect_after_terminal(&pipe)?;
                    }
                    if fatal_stop_requested() {
                        Err(PeerError::UncertainDrain)
                    } else {
                        Ok(())
                    }
                })?;
            Ok(Self {
                stop,
                worker: Some(worker),
                _runtime: runtime,
                _reservation: reservation,
            })
        }
        pub(super) fn stop_and_join(&mut self) -> Result<(), PeerError> {
            self.stop.store(true, Ordering::Release);
            let joined = match self.worker.take() {
                Some(worker) => worker
                    .join()
                    .map_err(|_| PeerError::WorkerPanicked)
                    .and_then(|result| result),
                None => Ok(()),
            };
            if fatal_stop_requested() {
                Err(PeerError::UncertainDrain)
            } else {
                joined
            }
        }
    }
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.stop_and_join();
        }
    }

    pub(super) fn cleanup_stale(
        runtime: &Path,
        reference: &CredentialRef,
    ) -> Result<(), PeerError> {
        if fatal_stop_requested() {
            return Err(PeerError::UncertainDrain);
        }
        let _single = CLIENT_CHANNEL.try_lock().map_err(|_| PeerError::Busy)?;
        let _runtime = runtime_guard(runtime)?;
        let name = pipe_name(reference);
        // Named-pipe objects disappear when their last native handle closes.
        // An existing object is live/ambiguous and never overwritten or deleted.
        // SAFETY: canonical local name and non-inherited identification-only open.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
            let _live = owned(handle)?;
            return Err(PeerError::Busy);
        }
        let error = unsafe { GetLastError() };
        match error {
            2 | 3 => Ok(()),
            231 => Err(PeerError::Busy),
            code => Err(PeerError::Native(code as i32)),
        }
    }

    pub(super) fn connect(
        runtime: &Path,
        reference: &CredentialRef,
        expected_server_pid: Option<u32>,
        deadline: Instant,
    ) -> Result<AuthenticatedPeerToken, PeerError> {
        if fatal_stop_requested() {
            return Err(PeerError::UncertainDrain);
        }
        let _single = CLIENT_CHANNEL.try_lock().map_err(|_| PeerError::Busy)?;
        let _runtime = runtime_guard(runtime)?;
        let user = UserSid::current()?;
        let stop = AtomicBool::new(false);
        budget(deadline, &stop)?;
        let name = pipe_name(reference);
        let pipe = open_client_pipe(&name, deadline, &stop, None)?;
        let server_process = verify_process(&pipe, &user, true, expected_server_pid)?;
        write_all(&pipe, &request(reference), deadline, &stop)?;
        let mut response = Zeroizing::new([0_u8; 32]);
        read_exact(&pipe, &mut *response, deadline, &stop)?;
        write_all(&pipe, &[ACK], deadline, &stop)?;
        // Wait for server disconnect after its ACK read. Write completion alone
        // does not prove that the other end consumed the buffered acknowledgement.
        match operation(&pipe, IoKind::Read, &[], 1, deadline, &stop) {
            Err(PeerError::Native(code))
                if matches!(code as u32, BROKEN_PIPE | PIPE_NOT_CONNECTED | 232) => {}
            Err(error) => return Err(error),
            _ => return Err(PeerError::Protocol),
        }
        budget(deadline, &stop)?;
        Ok(AuthenticatedPeerToken {
            token: response_token(&response)?,
            server_pid: server_process.pid,
        })
    }

    struct PipeIo {
        pipe: Arc<OwnedHandle>,
        stop: Arc<AtomicBool>,
        server: bool,
    }
    impl ManagementIo for PipeIo {
        fn read_chunk(
            &mut self,
            destination: &mut [u8],
            deadline: Instant,
            exchange: &BootstrapBudget,
        ) -> Result<usize, PeerError> {
            let bytes = Zeroizing::new(operation_with_budget(
                &self.pipe,
                IoKind::Read,
                &[],
                destination.len(),
                deadline,
                &self.stop,
                Some(exchange),
            )?);
            if bytes.len() > destination.len() {
                return Err(PeerError::Protocol);
            }
            destination[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
        fn write_chunk(
            &mut self,
            source: &[u8],
            deadline: Instant,
            exchange: &BootstrapBudget,
        ) -> Result<usize, PeerError> {
            let count = operation_with_budget(
                &self.pipe,
                IoKind::Write,
                source,
                0,
                deadline,
                &self.stop,
                Some(exchange),
            )?;
            Ok(u32::from_be_bytes(
                count
                    .as_slice()
                    .try_into()
                    .map_err(|_| PeerError::Protocol)?,
            ) as usize)
        }
        fn wait_readable(
            &mut self,
            deadline: Instant,
            exchange: &BootstrapBudget,
        ) -> Result<(), PeerError> {
            loop {
                budget(deadline, &self.stop)?;
                management_budget(deadline, &self.stop, Some(exchange))?;
                let mut available = 0_u32;
                // https://learn.microsoft.com/windows/win32/api/namedpipeapi/nf-namedpipeapi-peeknamedpipe
                // SAFETY: exclusively used FILE_FLAG_OVERLAPPED connected handle;
                // no synchronous handle, read buffer or pending native read here.
                if unsafe {
                    PeekNamedPipe(
                        raw(&self.pipe),
                        ptr::null_mut(),
                        0,
                        ptr::null_mut(),
                        &mut available,
                        ptr::null_mut(),
                    )
                } == 0
                {
                    return Err(native_error());
                }
                if available != 0 {
                    return Ok(());
                }
                thread::sleep(POLL_SLICE);
            }
        }
        fn disconnect(&mut self, exchange: &BootstrapBudget) -> Result<(), PeerError> {
            if !self.server {
                return Err(PeerError::Protocol);
            }
            management_budget(exchange.deadline(), &self.stop, Some(exchange))?;
            // SAFETY: all read/write owners have proven terminal completion.
            if unsafe { DisconnectNamedPipe(raw(&self.pipe)) } == 0 {
                return Err(native_error());
            }
            Ok(())
        }
        fn wait_disconnect(
            &mut self,
            deadline: Instant,
            exchange: &BootstrapBudget,
        ) -> Result<(), PeerError> {
            if self.server {
                return Err(PeerError::Protocol);
            }
            match operation_with_budget(
                &self.pipe,
                IoKind::Read,
                &[],
                1,
                deadline,
                &self.stop,
                Some(exchange),
            ) {
                Err(PeerError::Native(code))
                    if matches!(code as u32, BROKEN_PIPE | PIPE_NOT_CONNECTED | 232) =>
                {
                    Ok(())
                }
                Err(error) => Err(error),
                Ok(_) => Err(PeerError::Protocol),
            }
        }
    }
    pub(super) struct HostClient {
        inner: HostAttachClient<PipeIo>,
        _runtime: RuntimeDirectory,
        _server_process: VerifiedProcess,
        _reservation: std::sync::MutexGuard<'static, ()>,
    }
    impl HostClient {
        pub(super) fn deadline(&self) -> Instant {
            self.inner.deadline()
        }
        pub(super) fn installed_staged(
            mut self,
            public: PublicFrame,
        ) -> Result<(Self, PublicFrame), PeerError> {
            let complete = self
                .inner
                .installed_staged(public)
                .map_err(PeerError::from)?;
            Ok((self, complete))
        }
        pub(super) fn complete_delivery(mut self) -> Result<(), PeerError> {
            self.inner.complete_delivery().map_err(PeerError::from)
        }
        pub(super) fn abort(self) {
            self.inner.abort();
        }
    }
    pub(super) fn offer_host(
        runtime: &Path,
        reference: &CredentialRef,
        offer: HostOffer,
        exchange: BootstrapBudget,
    ) -> Result<(HostClient, PublicFrame), PeerError> {
        if fatal_stop_requested() {
            return Err(PeerError::UncertainDrain);
        }
        let reservation = CLIENT_CHANNEL.try_lock().map_err(|_| PeerError::Busy)?;
        let runtime = runtime_guard(runtime)?;
        let user = UserSid::current()?;
        let stop = Arc::new(AtomicBool::new(false));
        let deadline = exchange
            .native_io_deadline()
            .map_err(|error| PeerError::from(ExchangeError::from(error)))?;
        let name = pipe_name(reference);
        let pipe = open_client_pipe(&name, deadline, &stop, Some(&exchange))?;
        let server_process = verify_process(&pipe, &user, true, None)?;
        let io = PipeIo {
            pipe,
            stop,
            server: false,
        };
        let (inner, authority) =
            HostAttachClient::offer(io, offer, exchange).map_err(PeerError::from)?;
        Ok((
            HostClient {
                inner,
                _runtime: runtime,
                _server_process: server_process,
                _reservation: reservation,
            },
            authority,
        ))
    }

    struct VerifiedProcess {
        _handle: OwnedHandle,
        pid: u32,
    }
    fn verify_process(
        pipe: &OwnedHandle,
        expected: &UserSid,
        server: bool,
        expected_pid: Option<u32>,
    ) -> Result<VerifiedProcess, PeerError> {
        let mut pid = 0;
        // SAFETY: connected live pipe handle; PID is kernel-provided, not payload.
        let result = unsafe {
            if server {
                GetNamedPipeServerProcessId(raw(pipe), &mut pid)
            } else {
                GetNamedPipeClientProcessId(raw(pipe), &mut pid)
            }
        };
        if result == 0 || pid == 0 || expected_pid.is_some_and(|expected| expected != pid) {
            return Err(PeerError::PeerDenied);
        }
        // SAFETY: read-only process identity rights and non-inherited handle.
        let process =
            owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) })?;
        // SAFETY: zero-time liveness query on held process; no unbounded wait.
        if unsafe { WaitForSingleObject(raw(&process), 0) } != WAIT_TIMEOUT {
            return Err(PeerError::PeerDenied);
        }
        let actual = UserSid::process(raw(&process))?;
        if !expected.matches(&actual) {
            return Err(PeerError::PeerDenied);
        }
        // Kept through the exchange to fence PID reuse. This is primary OS-account
        // identity, not proof of a last-message thread impersonation context.
        Ok(VerifiedProcess {
            _handle: process,
            pid,
        })
    }

    fn serve(
        pipe: &Arc<OwnedHandle>,
        user: &UserSid,
        reference: &CredentialRef,
        token: &SecretToken,
        deadline: Instant,
        stop: &Arc<AtomicBool>,
        management: Option<&ManagementSender>,
    ) -> Result<(), PeerError> {
        let _client_process = verify_process(pipe, user, false, None)?;
        let started = Instant::now();
        let mut magic = [0_u8; 8];
        read_exact(pipe, &mut magic, deadline, stop)?;
        if &magic == crate::peer_management::HOST_MAGIC {
            let sender = management.ok_or(PeerError::Protocol)?;
            let budget = BootstrapBudget::for_peer(started, Arc::clone(stop));
            let mut io = PipeIo {
                pipe: Arc::clone(pipe),
                stop: Arc::clone(stop),
                server: true,
            };
            return management_transport::serve_host_exchange(&mut io, sender, &budget)
                .map_err(PeerError::from);
        }
        if &magic != MAGIC {
            return Err(PeerError::Protocol);
        }
        let mut header = [0_u8; 10];
        header[..8].copy_from_slice(&magic);
        read_exact(pipe, &mut header[8..], deadline, stop)?;
        let length = usize::from(u16::from_be_bytes([header[8], header[9]]));
        if &header[..8] != MAGIC || length == 0 || length > REFERENCE_LIMIT {
            return Err(PeerError::Protocol);
        }
        let mut bytes = [0_u8; REFERENCE_LIMIT];
        read_exact(pipe, &mut bytes[..length], deadline, stop)?;
        validate_request(&header, reference, &bytes[..length])?;
        write_all(pipe, token.expose_secret(), deadline, stop)?;
        let mut acknowledgement = [0_u8; 1];
        read_exact(pipe, &mut acknowledgement, deadline, stop)?;
        if acknowledgement != [ACK] {
            return Err(PeerError::Protocol);
        }
        Ok(())
    }

    #[derive(Clone, Copy)]
    enum IoKind {
        Connect,
        Read,
        Write,
    }
    #[derive(Debug, PartialEq, Eq)]
    enum OperationFailure {
        Error(PeerError),
        // Only an immediate non-pending ConnectNamedPipe error or a proven
        // terminal Connect completion may produce this tag. A cancellation
        // reason or a Read/Write error with the same numeric code cannot do so.
        ClosedBeforeProtocol,
    }
    impl From<PeerError> for OperationFailure {
        fn from(error: PeerError) -> Self {
            Self::Error(error)
        }
    }
    impl OperationFailure {
        fn into_peer_error(self) -> PeerError {
            match self {
                Self::Error(error) => error,
                Self::ClosedBeforeProtocol => PeerError::Native(NO_DATA as i32),
            }
        }
    }

    fn terminal_operation_result(
        kind: IoKind,
        result: Result<u32, PeerError>,
    ) -> Result<u32, OperationFailure> {
        match (kind, result) {
            (IoKind::Connect, Err(PeerError::Native(code))) if code == NO_DATA as i32 => {
                Err(OperationFailure::ClosedBeforeProtocol)
            }
            (_, result) => result.map_err(OperationFailure::from),
        }
    }

    fn accept_before_protocol(
        deadline: Instant,
        stop: &AtomicBool,
        mut accept: impl FnMut() -> Result<(), OperationFailure>,
        mut disconnect: impl FnMut() -> Result<(), PeerError>,
    ) -> Result<(), PeerError> {
        loop {
            budget(deadline, stop)?;
            match accept() {
                Ok(()) => return budget(deadline, stop),
                Err(OperationFailure::ClosedBeforeProtocol) => {
                    // No protocol bytes were read or delivered. The previous
                    // client is terminal; reset this exact instance before the
                    // next accept, without creating a new absolute deadline.
                    budget(deadline, stop)?;
                    disconnect()?;
                    budget(deadline, stop)?;
                }
                Err(OperationFailure::Error(error)) => return Err(error),
            }
        }
    }

    fn disconnect_after_terminal(pipe: &Arc<OwnedHandle>) -> Result<(), PeerError> {
        // SAFETY: caller has proven terminal completion for this exact instance;
        // no pending native I/O or borrowed protocol buffer remains.
        if unsafe { DisconnectNamedPipe(raw(pipe)) } == 0 {
            let code = unsafe { GetLastError() };
            if !matches!(code, PIPE_NOT_CONNECTED | BROKEN_PIPE) {
                return Err(PeerError::Native(code as i32));
            }
        }
        Ok(())
    }
    struct IoState {
        pipe: Arc<OwnedHandle>,
        event: OwnedHandle,
        // Kernel I/O writes this native status while Rust waits. Never create
        // an immutable Rust reference to concurrently mutable OVERLAPPED fields.
        overlapped: UnsafeCell<OVERLAPPED>,
        bytes: Zeroizing<Vec<u8>>,
    }
    struct IoOwner {
        state: Option<Box<IoState>>,
        pending: bool,
    }
    impl IoOwner {
        fn retain(&mut self) {
            FATAL_STOP.store(true, Ordering::Release);
            if let Some(state) = self.state.take() {
                // Deliberately retain the COMPLETE pinned owner until process
                // exit. The kernel may still address OVERLAPPED and bytes; neither
                // close, zeroize, reuse nor unsafe Drop is allowed before completion.
                let _ = Box::leak(state);
                #[cfg(test)]
                TEST_RETAINED_OWNERS.fetch_add(1, Ordering::Relaxed);
            }
            self.pending = false;
        }
    }
    impl Drop for IoOwner {
        fn drop(&mut self) {
            if self.pending {
                self.retain();
            }
        }
    }

    fn operation(
        pipe: &Arc<OwnedHandle>,
        kind: IoKind,
        input: &[u8],
        output_length: usize,
        deadline: Instant,
        stop: &AtomicBool,
    ) -> Result<Vec<u8>, PeerError> {
        operation_with_budget(pipe, kind, input, output_length, deadline, stop, None)
    }
    fn operation_with_budget(
        pipe: &Arc<OwnedHandle>,
        kind: IoKind,
        input: &[u8],
        output_length: usize,
        deadline: Instant,
        stop: &AtomicBool,
        exchange: Option<&BootstrapBudget>,
    ) -> Result<Vec<u8>, PeerError> {
        native_operation(pipe, kind, input, output_length, deadline, stop, exchange)
            .map_err(OperationFailure::into_peer_error)
    }
    fn native_operation(
        pipe: &Arc<OwnedHandle>,
        kind: IoKind,
        input: &[u8],
        output_length: usize,
        deadline: Instant,
        stop: &AtomicBool,
        exchange: Option<&BootstrapBudget>,
    ) -> Result<Vec<u8>, OperationFailure> {
        budget(deadline, stop)?;
        management_budget(deadline, stop, exchange)?;
        if input.len() > MESSAGE_LIMIT || output_length > MESSAGE_LIMIT {
            return Err(PeerError::Protocol.into());
        }
        // SAFETY: unnamed manual-reset non-inherited event, initially unsignaled.
        let event = owned(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })?;
        // SAFETY: OVERLAPPED's all-zero numeric/pointer fields are valid initial state.
        let mut overlapped: OVERLAPPED = unsafe { mem::zeroed() };
        overlapped.hEvent = raw(&event);
        let mut owner = IoOwner {
            state: Some(Box::new(IoState {
                pipe: Arc::clone(pipe),
                event,
                overlapped: UnsafeCell::new(overlapped),
                bytes: Zeroizing::new(vec![0; MESSAGE_LIMIT]),
            })),
            pending: false,
        };
        let state = owner.state.as_mut().ok_or(PeerError::Protocol)?;
        state.bytes[..input.len()].copy_from_slice(input);
        // SAFETY: boxed owner pins OVERLAPPED and buffer for the entire operation;
        // pipe/event are held by that owner, even during exceptional retention.
        let started = unsafe {
            match kind {
                IoKind::Connect => ConnectNamedPipe(raw(pipe), state.overlapped.get()),
                IoKind::Read => ReadFile(
                    raw(pipe),
                    state.bytes.as_mut_ptr(),
                    output_length as u32,
                    ptr::null_mut(),
                    state.overlapped.get(),
                ),
                IoKind::Write => WriteFile(
                    raw(pipe),
                    state.bytes.as_ptr(),
                    input.len() as u32,
                    ptr::null_mut(),
                    state.overlapped.get(),
                ),
            }
        };
        if started == 0 {
            let code = unsafe { GetLastError() };
            if matches!(kind, IoKind::Connect) && code == PIPE_CONNECTED {
                budget(deadline, stop)?;
                management_budget(deadline, stop, exchange)?;
                return Ok(Vec::new());
            }
            if code != IO_PENDING {
                return terminal_operation_result(kind, Err(PeerError::Native(code as i32)))
                    .map(|_| Vec::new());
            }
            owner.pending = true;
        }
        let transferred = wait_completion(&mut owner, kind, deadline, stop, exchange)?;
        owner.pending = false;
        budget(deadline, stop)?;
        management_budget(deadline, stop, exchange)?;
        let state = owner.state.as_ref().ok_or(PeerError::UncertainDrain)?;
        // The byte count is explicitly undefined for ConnectNamedPipe.
        if matches!(kind, IoKind::Connect) {
            return Ok(Vec::new());
        }
        let expected = match kind {
            IoKind::Read => output_length,
            IoKind::Write => input.len(),
            IoKind::Connect => 0,
        };
        if transferred as usize > expected {
            return Err(PeerError::Protocol.into());
        }
        // This vector is public framing for writes/connects, secret response for
        // reads. The caller immediately wraps/clears its owned copy below.
        match kind {
            IoKind::Read => Ok(state.bytes[..transferred as usize].to_vec()),
            _ => Ok(transferred.to_be_bytes().to_vec()),
        }
    }

    fn wait_completion(
        owner: &mut IoOwner,
        kind: IoKind,
        deadline: Instant,
        stop: &AtomicBool,
        exchange: Option<&BootstrapBudget>,
    ) -> Result<u32, OperationFailure> {
        loop {
            let state = owner.state.as_ref().ok_or(PeerError::UncertainDrain)?;
            let query_error = match completion(state) {
                Completion::Terminal(result) => {
                    owner.pending = false;
                    return terminal_operation_result(kind, result);
                }
                Completion::Unproven(error) => error,
            };
            owner.pending = true;
            if let Some(error) = query_error
                .or_else(|| budget(deadline, stop).err())
                .or_else(|| management_budget(deadline, stop, exchange).err())
            {
                return cancel_and_drain(owner, error).map_err(OperationFailure::from);
            }
            // SAFETY: private event is held by this pending owner's fixed box.
            let wait =
                unsafe { WaitForSingleObject(raw(&state.event), POLL_SLICE.as_millis() as u32) };
            if !matches!(wait, WAIT_OBJECT | WAIT_TIMEOUT) {
                return cancel_and_drain(owner, native_error()).map_err(OperationFailure::from);
            }
        }
    }

    enum Completion {
        Terminal(Result<u32, PeerError>),
        Unproven(Option<PeerError>),
    }

    fn completion(state: &IoState) -> Completion {
        #[cfg(test)]
        if TEST_UNKNOWN_COMPLETION.load(Ordering::Acquire) {
            // Test subprocess only: inject an unknown classification, not a
            // native kernel failure. The actual targeted CancelIoEx ran first.
            return Completion::Unproven(None);
        }
        let mut count = 0;
        // SAFETY: pinned native status inside UnsafeCell; FALSE never waits.
        if unsafe { GetOverlappedResult(raw(&state.pipe), state.overlapped.get(), &mut count, 0) }
            != 0
        {
            return Completion::Terminal(Ok(count));
        }
        let first = unsafe { GetLastError() };
        if first == IO_INCOMPLETE {
            return Completion::Unproven(None);
        }
        // A query error (invalid handle/parameter, for example) alone is not
        // completion proof. Require this operation's private manual-reset event
        // to be signaled AND a stable terminal result before releasing ownership.
        if unsafe { WaitForSingleObject(raw(&state.event), 0) } != WAIT_OBJECT {
            return Completion::Unproven(Some(PeerError::Native(first as i32)));
        }
        if unsafe { GetOverlappedResult(raw(&state.pipe), state.overlapped.get(), &mut count, 0) }
            != 0
        {
            return Completion::Terminal(Ok(count));
        }
        let second = unsafe { GetLastError() };
        if second == first && second != IO_INCOMPLETE {
            Completion::Terminal(Err(PeerError::Native(second as i32)))
        } else {
            Completion::Unproven(Some(PeerError::Native(second as i32)))
        }
    }

    fn cancel_and_drain(owner: &mut IoOwner, reason: PeerError) -> Result<u32, PeerError> {
        let state = owner.state.as_ref().ok_or(PeerError::UncertainDrain)?;
        // SAFETY: target only the held pinned operation. Cancellation success or
        // ERROR_NOT_FOUND is a request/race, never substituted for completion proof.
        unsafe {
            CancelIoEx(raw(&state.pipe), state.overlapped.get());
        }
        #[cfg(test)]
        {
            TEST_CANCEL_CALLS.fetch_add(1, Ordering::Relaxed);
            if TEST_FORCE_UNKNOWN_AFTER_CANCEL.load(Ordering::Acquire) {
                TEST_UNKNOWN_COMPLETION.store(true, Ordering::Release);
            }
        }
        let deadline = Instant::now() + CANCEL_DRAIN;
        loop {
            let state = owner.state.as_ref().ok_or(PeerError::UncertainDrain)?;
            if matches!(completion(state), Completion::Terminal(_)) {
                owner.pending = false;
                return Err(reason);
            }
            if Instant::now() >= deadline {
                owner.retain();
                return Err(PeerError::UncertainDrain);
            }
            // SAFETY: finite drain query while retaining all native I/O ownership.
            unsafe {
                WaitForSingleObject(raw(&state.event), POLL_SLICE.as_millis() as u32);
            }
        }
    }

    fn budget(deadline: Instant, stop: &AtomicBool) -> Result<(), PeerError> {
        if fatal_stop_requested() {
            Err(PeerError::UncertainDrain)
        } else if stop.load(Ordering::Acquire) {
            Err(PeerError::Stopped)
        } else if Instant::now() >= deadline {
            Err(PeerError::Timeout)
        } else {
            Ok(())
        }
    }

    fn read_exact(
        pipe: &Arc<OwnedHandle>,
        mut destination: &mut [u8],
        deadline: Instant,
        stop: &AtomicBool,
    ) -> Result<(), PeerError> {
        while !destination.is_empty() {
            let bytes = Zeroizing::new(operation(
                pipe,
                IoKind::Read,
                &[],
                destination.len(),
                deadline,
                stop,
            )?);
            if bytes.is_empty() {
                return Err(PeerError::Protocol);
            }
            destination[..bytes.len()].copy_from_slice(&bytes);
            destination = &mut destination[bytes.len()..];
        }
        budget(deadline, stop)
    }
    fn write_all(
        pipe: &Arc<OwnedHandle>,
        mut source: &[u8],
        deadline: Instant,
        stop: &AtomicBool,
    ) -> Result<(), PeerError> {
        while !source.is_empty() {
            let bytes = operation(pipe, IoKind::Write, source, 0, deadline, stop)?;
            let count = u32::from_be_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| PeerError::Protocol)?,
            ) as usize;
            if count == 0 || count > source.len() {
                return Err(PeerError::Protocol);
            }
            source = &source[count..];
        }
        budget(deadline, stop)
    }

    #[cfg(test)]
    pub(crate) mod test_support {
        use super::*;

        pub(crate) const ISOLATED_TEST: &str =
            "tests::peer_tests::isolated_unconfirmed_drain_child";

        // 기존 native fixture는 실제 prewrite close를 반복하지만 232의
        // 관측 위치를 고정하지 않는다. 이 검사는 native 호출 없이 terminal
        // Connect 결과와 취소/소비 오류의 분류 경계를 확인한다.
        #[test]
        fn only_terminal_connect_no_data_allows_prewrite_reset() {
            assert_eq!(
                terminal_operation_result(IoKind::Connect, Err(PeerError::Native(232))),
                Err(OperationFailure::ClosedBeforeProtocol)
            );
            for kind in [IoKind::Read, IoKind::Write] {
                assert_eq!(
                    terminal_operation_result(kind, Err(PeerError::Native(232))),
                    Err(OperationFailure::Error(PeerError::Native(232)))
                );
            }
            for error in [
                PeerError::Native(5),
                PeerError::Native(995),
                PeerError::Timeout,
                PeerError::Stopped,
                PeerError::UncertainDrain,
                // A preserved cancellation/query reason is intentionally not
                // transformed into a confirmed terminal Connect result.
                PeerError::Native(232),
            ] {
                let mut accepts = 0;
                let mut disconnects = 0;
                let result = accept_before_protocol(
                    Instant::now() + IO_BUDGET,
                    &AtomicBool::new(false),
                    || {
                        accepts += 1;
                        Err(OperationFailure::from(error))
                    },
                    || {
                        disconnects += 1;
                        Ok(())
                    },
                );
                assert_eq!(result, Err(error));
                assert_eq!(accepts, 1);
                assert_eq!(disconnects, 0);
            }
        }

        #[test]
        fn prewrite_reset_preserves_deadline_stop_and_disconnect_failure() {
            let stop = AtomicBool::new(false);
            let deadline = Instant::now() + IO_BUDGET;
            let mut accepts = 0;
            let mut disconnects = 0;
            let result = accept_before_protocol(
                deadline,
                &stop,
                || {
                    accepts += 1;
                    if accepts < 3 {
                        Err(OperationFailure::ClosedBeforeProtocol)
                    } else {
                        Ok(())
                    }
                },
                || {
                    disconnects += 1;
                    Ok(())
                },
            );
            assert_eq!(result, Ok(()));
            assert_eq!(accepts, 3);
            assert_eq!(disconnects, 2);

            let result = accept_before_protocol(
                Instant::now(),
                &stop,
                || panic!("expired accept must not reopen"),
                || panic!("expired accept must not disconnect"),
            );
            assert_eq!(result, Err(PeerError::Timeout));

            let mut accepts = 0;
            let result = accept_before_protocol(
                deadline,
                &stop,
                || {
                    accepts += 1;
                    Err(OperationFailure::ClosedBeforeProtocol)
                },
                || {
                    stop.store(true, Ordering::Release);
                    Ok(())
                },
            );
            assert_eq!(result, Err(PeerError::Stopped));
            assert_eq!(accepts, 1);

            let stop = AtomicBool::new(false);
            let mut accepts = 0;
            let result = accept_before_protocol(
                deadline,
                &stop,
                || {
                    accepts += 1;
                    Err(OperationFailure::ClosedBeforeProtocol)
                },
                || Err(PeerError::Native(5)),
            );
            assert_eq!(result, Err(PeerError::Native(5)));
            assert_eq!(accepts, 1);
        }

        // 현재 handshake 자료에는 첫 open의 일시적 부재와 오류 분류를
        // 제어하는 사례가 없다. Native 호출 없이 open 단계만 주입하여
        // permission/EOF/unknown 오류가 교환 재생으로 바뀌지 않는지 확인한다.
        #[test]
        fn first_contact_retries_only_missing_or_busy_and_returns_one_owner() {
            let stop = AtomicBool::new(false);
            let deadline = Instant::now() + IO_BUDGET;
            let mut attempts = 0;
            let opened = open_before_io(deadline, &stop, None, || {
                attempts += 1;
                match attempts {
                    1 => Err(PeerError::Native(2)),
                    2 => Err(PeerError::Native(231)),
                    _ => Ok(17_u8),
                }
            });
            assert_eq!(opened, Ok(17));
            assert_eq!(attempts, 3);

            for error in [
                PeerError::Native(5),
                PeerError::Native(109),
                PeerError::Native(232),
                PeerError::Native(233),
                PeerError::Native(995),
                PeerError::Native(997),
                PeerError::PeerDenied,
                PeerError::UncertainDrain,
            ] {
                let mut attempts = 0;
                let result = open_before_io(deadline, &stop, None, || {
                    attempts += 1;
                    Err::<u8, _>(error)
                });
                assert_eq!(result, Err(error));
                assert_eq!(attempts, 1);
            }
        }

        #[test]
        fn first_contact_never_refreshes_original_deadline_or_reopens_after_cancel() {
            let stop = AtomicBool::new(false);
            let mut attempts = 0;
            let result = open_before_io(Instant::now(), &stop, None, || {
                attempts += 1;
                Ok(17_u8)
            });
            assert_eq!(result, Err(PeerError::Timeout));
            assert_eq!(attempts, 0);

            let exchange = BootstrapBudget::new();
            exchange.cancel();
            let result = open_before_io(exchange.deadline(), &stop, Some(&exchange), || {
                attempts += 1;
                Ok(17_u8)
            });
            assert_eq!(result, Err(PeerError::Stopped));
            assert_eq!(attempts, 0);

            let deadline = Instant::now() + IO_BUDGET;
            let result = open_before_io(deadline, &stop, None, || {
                attempts += 1;
                stop.store(true, Ordering::Release);
                Err::<u8, _>(PeerError::Native(2))
            });
            assert_eq!(result, Err(PeerError::Stopped));
            assert_eq!(attempts, 1);
        }

        pub(crate) fn cancel_calls() -> usize {
            TEST_CANCEL_CALLS.load(Ordering::Acquire)
        }
        pub(crate) fn retained_owners() -> usize {
            TEST_RETAINED_OWNERS.load(Ordering::Acquire)
        }
        pub(crate) fn force_unknown_after_actual_cancel() {
            assert!(
                std::env::args().any(|arg| arg == ISOLATED_TEST),
                "fault classification requires its isolated exact child test"
            );
            assert!(!fatal_stop_requested());
            TEST_FORCE_UNKNOWN_AFTER_CANCEL.store(true, Ordering::Release);
        }

        pub(crate) struct UnacknowledgedConnection {
            pipe: Arc<OwnedHandle>,
            _server_process: VerifiedProcess,
            opened: Instant,
        }
        impl UnacknowledgedConnection {
            pub(crate) fn wait_for_disconnect(self) -> Result<Duration, PeerError> {
                // This bounded observer waits for the server's 5-second deadline
                // plus finite terminal drain. Production exchanges stay at 5 s.
                let deadline = self.opened + Duration::from_secs(8);
                match operation(
                    &self.pipe,
                    IoKind::Read,
                    &[],
                    1,
                    deadline,
                    &AtomicBool::new(false),
                ) {
                    Err(PeerError::Native(code))
                        if matches!(code as u32, BROKEN_PIPE | PIPE_NOT_CONNECTED | 232) =>
                    {
                        Ok(self.opened.elapsed())
                    }
                    Err(error) => Err(error),
                    Ok(_) => Err(PeerError::Protocol),
                }
            }
        }

        pub(crate) fn open_without_ack(
            runtime: &Path,
            reference: &CredentialRef,
            expected: &[u8; 32],
        ) -> Result<UnacknowledgedConnection, PeerError> {
            if fatal_stop_requested() {
                return Err(PeerError::UncertainDrain);
            }
            let _runtime = runtime_guard(runtime)?;
            let user = UserSid::current()?;
            let opened = Instant::now();
            let deadline = opened + IO_BUDGET;
            let stop = AtomicBool::new(false);
            let name = pipe_name(reference);
            let pipe = open_client_pipe(&name, deadline, &stop, None)?;
            let server_process = verify_process(&pipe, &user, true, None)?;
            write_all(&pipe, &request(reference), deadline, &stop)?;
            let mut response = Zeroizing::new([0_u8; 32]);
            read_exact(&pipe, &mut *response, deadline, &stop)?;
            if &*response != expected {
                return Err(PeerError::Protocol);
            }
            Ok(UnacknowledgedConnection {
                pipe,
                _server_process: server_process,
                opened,
            })
        }
    }
}

#[cfg(all(test, target_os = "windows"))]
pub(crate) use platform::test_support;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod platform {
    use super::*;
    pub(super) struct Server;
    impl Server {
        pub(super) fn start(_: &Path, _: CredentialRef, _: SecretToken) -> Result<Self, PeerError> {
            Err(PeerError::Unsupported)
        }
        pub(super) fn start_with_management(
            _: &Path,
            _: CredentialRef,
            _: SecretToken,
            _: Option<ManagementSender>,
        ) -> Result<Self, PeerError> {
            Err(PeerError::Unsupported)
        }
        pub(super) fn stop_and_join(&mut self) -> Result<(), PeerError> {
            Err(PeerError::Unsupported)
        }
    }
    pub(super) struct HostClient;
    impl HostClient {
        pub(super) fn deadline(&self) -> Instant {
            Instant::now()
        }
        pub(super) fn installed_staged(
            self,
            _: PublicFrame,
        ) -> Result<(Self, PublicFrame), PeerError> {
            Err(PeerError::Unsupported)
        }
        pub(super) fn complete_delivery(self) -> Result<(), PeerError> {
            Err(PeerError::Unsupported)
        }
        pub(super) fn abort(self) {}
    }
    pub(super) fn offer_host(
        _: &Path,
        _: &CredentialRef,
        _: HostOffer,
        _: BootstrapBudget,
    ) -> Result<(HostClient, PublicFrame), PeerError> {
        Err(PeerError::Unsupported)
    }
    pub(super) fn fatal_stop_requested() -> bool {
        false
    }
    pub(super) fn connect(
        _: &Path,
        _: &CredentialRef,
        _: Option<u32>,
        _: Instant,
    ) -> Result<AuthenticatedPeerToken, PeerError> {
        Err(PeerError::Unsupported)
    }
    pub(super) fn cleanup_stale(_: &Path, _: &CredentialRef) -> Result<(), PeerError> {
        Err(PeerError::Unsupported)
    }
}

impl PeerBootstrap {
    pub fn start(
        runtime: &RuntimeDirectory,
        reference: &CredentialRef,
        token: SecretToken,
    ) -> Result<Self, PeerError> {
        Ok(Self {
            inner: platform::Server::start(runtime.path(), reference.clone(), token)?,
        })
    }

    pub fn connect(runtime: &Path, reference: &CredentialRef) -> Result<SecretToken, PeerError> {
        Self::connect_verified_with_deadline(runtime, reference, None, Instant::now() + IO_BUDGET)
    }
    /// Launcher가 소유한 child를 유지한 상태에서 actual kernel PID를 비교한다.
    /// PID 불일치는 request/token 전송 전에 거부하며 같은 account만으로 우회하지 않는다.
    pub fn connect_verified_with_deadline(
        runtime: &Path,
        reference: &CredentialRef,
        expected_server_pid: Option<u32>,
        deadline: Instant,
    ) -> Result<SecretToken, PeerError> {
        if expected_server_pid == Some(0) {
            return Err(PeerError::PeerDenied);
        }
        let deadline = control_deadline(deadline)?;
        platform::connect(runtime, reference, expected_server_pid, deadline)
            .map(AuthenticatedPeerToken::into_token)
    }
    pub fn connect_authenticated_with_deadline(
        runtime: &Path,
        reference: &CredentialRef,
        deadline: Instant,
    ) -> Result<AuthenticatedPeerToken, PeerError> {
        let deadline = control_deadline(deadline)?;
        platform::connect(runtime, reference, None, deadline)
    }
    pub fn start_with_management(
        runtime: &RuntimeDirectory,
        reference: &CredentialRef,
        token: SecretToken,
        sender: ManagementSender,
    ) -> Result<Self, PeerError> {
        Ok(Self {
            inner: platform::Server::start_with_management(
                runtime.path(),
                reference.clone(),
                token,
                Some(sender),
            )?,
        })
    }

    /// Caller must hold the data-root Coordinator lease. Only the exact previous
    /// valid endpoint reference is eligible; no directory scan or unknown adoption.
    pub fn cleanup_stale(runtime: &Path, reference: &CredentialRef) -> Result<(), PeerError> {
        platform::cleanup_stale(runtime, reference)
    }

    pub fn shutdown(mut self) -> Result<(), PeerError> {
        self.inner.stop_and_join()
    }

    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn native_test_state(&self) -> Result<PeerNativeTestState, PeerError> {
        self.inner.native_test_state()
    }

    /// A pending native I/O allocation may have been retained after a finite
    /// cancellation drain. Stop new admissions and end the process only after
    /// durable in-flight application work has reached its safe stopping point.
    pub fn fatal_stop_requested(&self) -> bool {
        platform::fatal_stop_requested()
    }
}

fn control_deadline(deadline: Instant) -> Result<Instant, PeerError> {
    if fatal_stop_requested() {
        return Err(PeerError::UncertainDrain);
    }
    let now = Instant::now();
    if deadline <= now {
        return Err(PeerError::Timeout);
    }
    Ok(deadline.min(now + IO_BUDGET))
}

fn request(reference: &CredentialRef) -> Vec<u8> {
    let bytes = reference.as_str().as_bytes();
    let mut request = Vec::with_capacity(MAGIC.len() + 2 + bytes.len());
    request.extend_from_slice(MAGIC);
    request.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    request.extend_from_slice(bytes);
    request
}

fn validate_request(
    header: &[u8; 10],
    reference: &CredentialRef,
    bytes: &[u8],
) -> Result<(), PeerError> {
    if &header[..8] != MAGIC
        || usize::from(u16::from_be_bytes([header[8], header[9]])) != bytes.len()
        || bytes.is_empty()
        || bytes.len() > REFERENCE_LIMIT
        || bytes != reference.as_str().as_bytes()
    {
        return Err(PeerError::Protocol);
    }
    Ok(())
}

fn response_token(bytes: &[u8; 32]) -> Result<SecretToken, PeerError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = Zeroizing::new(String::with_capacity(64));
    for &byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 15)]));
    }
    SecretToken::parse(&encoded).map_err(|_| PeerError::Protocol)
}

fn channel_name(reference: &CredentialRef) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    // A fixed-width public reference digest bounds the native name. Include
    // the whole canonical reference, so caller-provided punctuation is not a path.
    let digest = Sha256::digest(reference.as_str().as_bytes());
    let mut name = String::with_capacity(32);
    for byte in &digest[..16] {
        let _ = write!(name, "{byte:02x}");
    }
    name
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use super::*;
    use std::{
        ffi::CString,
        fs::{File, OpenOptions},
        mem::{self, MaybeUninit},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, OpenOptionsExt},
                net::{UnixListener, UnixStream},
            },
        },
        path::{Component, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread::{self, JoinHandle},
    };

    struct Directory {
        file: File,
        path: PathBuf,
        device: u64,
        inode: u64,
    }

    impl Directory {
        fn open(path: &Path) -> Result<Self, PeerError> {
            if !path.is_absolute() {
                return Err(PeerError::UnsafePath);
            }
            let parts: Vec<_> = path.components().collect();
            if parts.len() < 2
                || parts.len() > 65
                || !matches!(parts[0], Component::RootDir)
                || parts[1..]
                    .iter()
                    .any(|part| !matches!(part, Component::Normal(_)))
            {
                return Err(PeerError::UnsafePath);
            }
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/")?;
            for part in &parts[1..] {
                let Component::Normal(part) = part else {
                    return Err(PeerError::UnsafePath);
                };
                let name = CString::new(part.as_bytes()).map_err(|_| PeerError::UnsafePath)?;
                // SAFETY: one ordinary component, live anchored parent and no-follow
                // flags. The successful descriptor is transferred exactly once.
                let fd = unsafe {
                    libc::openat(
                        file.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                // SAFETY: fd is newly owned by this call.
                file = unsafe { File::from_raw_fd(fd) };
            }
            let metadata = file.metadata()?;
            let uid = current_uid()?;
            if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
                return Err(PeerError::UnsafePermissions);
            }
            Ok(Self {
                file,
                path: path.to_owned(),
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }

        fn validate(&self) -> Result<(), PeerError> {
            let handle = self.file.metadata()?;
            let path = std::fs::symlink_metadata(&self.path).map_err(|_| PeerError::UnsafePath)?;
            if !path.is_dir()
                || path.file_type().is_symlink()
                || handle.dev() != self.device
                || handle.ino() != self.inode
                || path.dev() != self.device
                || path.ino() != self.inode
                || handle.uid() != current_uid()?
                || path.uid() != current_uid()?
                || handle.mode() & 0o7777 != 0o700
                || path.mode() & 0o7777 != 0o700
            {
                return Err(PeerError::UnsafePermissions);
            }
            Ok(())
        }

        fn socket(&self, name: &str) -> Result<libc::stat, PeerError> {
            self.socket_entry(name, true)
        }

        fn socket_entry(&self, name: &str, require_private: bool) -> Result<libc::stat, PeerError> {
            self.validate()?;
            let name = CString::new(name).map_err(|_| PeerError::UnsafePath)?;
            let mut stat = MaybeUninit::<libc::stat>::zeroed();
            // SAFETY: anchored live directory, bounded single filename and writable
            // stat buffer; no-follow prevents accepting a replacement symlink.
            if unsafe {
                libc::fstatat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: fstatat initialized the complete structure.
            let stat = unsafe { stat.assume_init() };
            if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK
                || stat.st_uid != current_uid()?
                || (require_private && stat.st_mode & 0o7777 != 0o600)
            {
                return Err(PeerError::UnsafePermissions);
            }
            Ok(stat)
        }
    }

    struct SocketOwner {
        directory: Directory,
        name: String,
        device: libc::dev_t,
        inode: libc::ino_t,
        removed: bool,
    }
    impl SocketOwner {
        fn remove(&mut self) -> Result<(), PeerError> {
            if self.removed {
                return Ok(());
            }
            let stat = self.directory.socket(&self.name)?;
            if stat.st_dev != self.device || stat.st_ino != self.inode {
                return Err(PeerError::UnsafePath);
            }
            let name = CString::new(self.name.as_str()).map_err(|_| PeerError::UnsafePath)?;
            // SAFETY: same pinned directory and verified original socket identity;
            // only this single owned directory entry is removed.
            if unsafe { libc::unlinkat(self.directory.file.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            self.directory.file.sync_all()?;
            self.removed = true;
            Ok(())
        }
    }

    pub(super) struct Server {
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<Result<(), PeerError>>>,
        socket: SocketOwner,
        #[cfg(test)]
        terminal: Arc<std::sync::Mutex<Option<PeerNativeExchange>>>,
    }

    impl Server {
        pub(super) fn start(
            runtime: &Path,
            reference: CredentialRef,
            token: SecretToken,
        ) -> Result<Self, PeerError> {
            Self::start_with_management(runtime, reference, token, None)
        }
        pub(super) fn start_with_management(
            runtime: &Path,
            reference: CredentialRef,
            token: SecretToken,
            management: Option<ManagementSender>,
        ) -> Result<Self, PeerError> {
            let directory = Directory::open(runtime)?;
            let name = format!("pairing-{}.sock", channel_name(&reference));
            let path = directory.path.join(&name);
            validate_socket_path(&path)?;
            directory.validate()?;
            // bind creates a new entry atomically; an existing socket is never adopted.
            let listener = UnixListener::bind(&path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AddrInUse {
                    PeerError::Busy
                } else {
                    error.into()
                }
            })?;
            let before = directory.socket_entry(&name, false)?;
            let native_name = CString::new(name.as_str()).map_err(|_| PeerError::UnsafePath)?;
            // SAFETY: anchored newly created socket entry, single fixed name;
            // refuse symlink traversal instead of chmod of an arbitrary target.
            if unsafe {
                libc::fchmodat(
                    directory.file.as_raw_fd(),
                    native_name.as_ptr(),
                    0o600,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let stat = directory.socket(&name)?;
            if before.st_dev != stat.st_dev || before.st_ino != stat.st_ino {
                return Err(PeerError::UnsafePath);
            }
            let mut socket = SocketOwner {
                directory,
                name,
                device: stat.st_dev,
                inode: stat.st_ino,
                removed: false,
            };
            listener.set_nonblocking(true)?;
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stop);
            #[cfg(test)]
            let terminal = Arc::new(std::sync::Mutex::new(None));
            #[cfg(test)]
            let worker_terminal = Arc::clone(&terminal);
            let worker =
                match thread::Builder::new()
                    .name("mmmm-peer".to_owned())
                    .spawn(move || {
                        while !worker_stop.load(Ordering::Acquire) {
                            match listener.accept() {
                                Ok((stream, _)) => {
                                    let deadline = Instant::now() + IO_BUDGET;
                                    #[cfg(test)]
                                    let mut stage = PeerNativeStage::SetNonblocking;
                                    // Accepted-socket configuration is also connection-local:
                                    // a peer that closed before protocol must not stop the
                                    // listener serving later independently verified peers.
                                    let result: Result<(), PeerError> = (|| {
                                        stream.set_nonblocking(true)?;
                                        #[cfg(test)]
                                        {
                                            stage = PeerNativeStage::ConfigureStream;
                                        }
                                        configure_stream(&stream)?;
                                        serve(
                                            &stream,
                                            &reference,
                                            &token,
                                            deadline,
                                            &worker_stop,
                                            management.as_ref(),
                                            #[cfg(test)]
                                            &mut stage,
                                        )
                                    })(
                                    );
                                    #[cfg(test)]
                                    if let Ok(mut terminal) = worker_terminal.lock() {
                                        *terminal = Some((stage, result));
                                    }
                                    // No application, provider or credential-store action
                                    // is invoked by a rejected bootstrap connection.
                                    let _ = result;
                                }
                                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                    thread::sleep(POLL_SLICE)
                                }
                                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                                Err(error) => {
                                    let error = PeerError::from(error);
                                    #[cfg(test)]
                                    if let Ok(mut terminal) = worker_terminal.lock() {
                                        *terminal = Some((PeerNativeStage::Accept, Err(error)));
                                    }
                                    return Err(error);
                                }
                            }
                        }
                        Ok(())
                    }) {
                    Ok(worker) => worker,
                    Err(error) => {
                        let _ = socket.remove();
                        return Err(error.into());
                    }
                };
            Ok(Self {
                stop,
                worker: Some(worker),
                socket,
                #[cfg(test)]
                terminal,
            })
        }

        #[cfg(test)]
        pub(super) fn native_test_state(&self) -> Result<PeerNativeTestState, PeerError> {
            let last_exchange = *self
                .terminal
                .lock()
                .map_err(|_| PeerError::WorkerPanicked)?;
            Ok(PeerNativeTestState {
                last_exchange,
                worker_finished: self.worker.as_ref().is_none_or(JoinHandle::is_finished),
            })
        }

        pub(super) fn stop_and_join(&mut self) -> Result<(), PeerError> {
            self.stop.store(true, Ordering::Release);
            let joined = match self.worker.take() {
                Some(worker) => worker
                    .join()
                    .map_err(|_| PeerError::WorkerPanicked)
                    .and_then(|result| result),
                None => Ok(()),
            };
            let cleanup = self.socket.remove();
            joined.and(cleanup)
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.stop_and_join();
        }
    }

    pub(super) fn fatal_stop_requested() -> bool {
        false
    }

    struct SocketIo {
        stream: UnixStream,
        stop: Arc<AtomicBool>,
        server: bool,
    }
    impl SocketIo {
        fn ready(
            &self,
            events: i16,
            deadline: Instant,
            exchange: &BootstrapBudget,
        ) -> Result<(), PeerError> {
            loop {
                check_budget(deadline, &self.stop)?;
                management_budget(deadline, &self.stop, Some(exchange))?;
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .ok_or(PeerError::Timeout)?;
                let wait = remaining.min(POLL_SLICE).as_millis().max(1) as i32;
                let mut fd = libc::pollfd {
                    fd: self.stream.as_raw_fd(),
                    events,
                    revents: 0,
                };
                // SAFETY: one live connected nonblocking fd, initialized struct,
                // finite ≤20ms poll; no read or token consumption in readiness.
                let result = unsafe { libc::poll(&mut fd, 1, wait) };
                if result < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error.into());
                }
                if result == 0 {
                    continue;
                }
                if fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                    let mut status = 0_i32;
                    let mut size = mem::size_of::<i32>() as libc::socklen_t;
                    // SAFETY: live socket and correctly sized scalar SO_ERROR.
                    if unsafe {
                        libc::getsockopt(
                            self.stream.as_raw_fd(),
                            libc::SOL_SOCKET,
                            libc::SO_ERROR,
                            (&mut status as *mut i32).cast(),
                            &mut size,
                        )
                    } != 0
                    {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    if size as usize != mem::size_of::<i32>() {
                        return Err(PeerError::Protocol);
                    }
                    if status != 0 {
                        return Err(PeerError::Native(status));
                    }
                    return Err(PeerError::Poll(fd.revents));
                }
                if fd.revents & events != 0 {
                    return Ok(());
                }
                return Err(PeerError::Poll(fd.revents));
            }
        }
    }
    impl ManagementIo for SocketIo {
        fn read_chunk(
            &mut self,
            destination: &mut [u8],
            deadline: Instant,
            exchange: &BootstrapBudget,
        ) -> Result<usize, PeerError> {
            if destination.is_empty() || destination.len() > MESSAGE_LIMIT {
                return Err(PeerError::Protocol);
            }
            loop {
                check_budget(deadline, &self.stop)?;
                management_budget(deadline, &self.stop, Some(exchange))?;
                // SAFETY: live connected nonblocking socket and bounded writable
                // buffer; recv returns synchronously, never retains its pointer.
                let count = unsafe {
                    libc::recv(
                        self.stream.as_raw_fd(),
                        destination.as_mut_ptr().cast(),
                        destination.len(),
                        0,
                    )
                };
                if count >= 0 {
                    return Ok(count as usize);
                }
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if error.kind() != std::io::ErrorKind::WouldBlock {
                    return Err(error.into());
                }
                self.ready(libc::POLLIN, deadline, exchange)?;
            }
        }
        fn write_chunk(
            &mut self,
            source: &[u8],
            deadline: Instant,
            exchange: &BootstrapBudget,
        ) -> Result<usize, PeerError> {
            if source.is_empty() || source.len() > MESSAGE_LIMIT {
                return Err(PeerError::Protocol);
            }
            loop {
                check_budget(deadline, &self.stop)?;
                management_budget(deadline, &self.stop, Some(exchange))?;
                #[cfg(target_os = "linux")]
                let flags = libc::MSG_NOSIGNAL;
                #[cfg(target_os = "macos")]
                let flags = 0;
                // SAFETY: live connected nonblocking socket/bounded source; Linux
                // per-call/macOS configured per-socket SIGPIPE suppression.
                let count = unsafe {
                    libc::send(
                        self.stream.as_raw_fd(),
                        source.as_ptr().cast(),
                        source.len(),
                        flags,
                    )
                };
                if count >= 0 {
                    return Ok(count as usize);
                }
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if error.kind() != std::io::ErrorKind::WouldBlock {
                    return Err(error.into());
                }
                self.ready(libc::POLLOUT, deadline, exchange)?;
            }
        }
        fn wait_readable(
            &mut self,
            deadline: Instant,
            exchange: &BootstrapBudget,
        ) -> Result<(), PeerError> {
            self.ready(libc::POLLIN, deadline, exchange)
        }
        fn disconnect(&mut self, exchange: &BootstrapBudget) -> Result<(), PeerError> {
            if !self.server {
                return Err(PeerError::Protocol);
            }
            management_budget(exchange.deadline(), &self.stop, Some(exchange))?;
            self.stream
                .shutdown(std::net::Shutdown::Both)
                .map_err(PeerError::from)
        }
        fn wait_disconnect(
            &mut self,
            deadline: Instant,
            exchange: &BootstrapBudget,
        ) -> Result<(), PeerError> {
            if self.server {
                return Err(PeerError::Protocol);
            }
            loop {
                check_budget(deadline, &self.stop)?;
                management_budget(deadline, &self.stop, Some(exchange))?;
                let mut byte = 0_u8;
                // SAFETY: one live byte and nonblocking socket; Unix recv 0 on a
                // nonempty request proves EOF, unlike zero-byte Windows writes.
                let count = unsafe {
                    libc::recv(self.stream.as_raw_fd(), (&mut byte as *mut u8).cast(), 1, 0)
                };
                if count == 0 {
                    return Ok(());
                }
                if count > 0 {
                    return Err(PeerError::Protocol);
                }
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if error.kind() != std::io::ErrorKind::WouldBlock {
                    return Err(error.into());
                }
                // HUP readiness is expected here. Keep nonconsuming poll flags
                // and issue exactly recv to prove EOF instead of inferring it.
                match self.ready(libc::POLLIN, deadline, exchange) {
                    Ok(()) => (),
                    Err(PeerError::Poll(flags))
                        if flags & libc::POLLHUP != 0
                            && flags & (libc::POLLERR | libc::POLLNVAL) == 0 => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }
    pub(super) struct HostClient {
        inner: HostAttachClient<SocketIo>,
        _directory: Directory,
    }
    impl HostClient {
        pub(super) fn deadline(&self) -> Instant {
            self.inner.deadline()
        }
        pub(super) fn installed_staged(
            mut self,
            public: PublicFrame,
        ) -> Result<(Self, PublicFrame), PeerError> {
            let complete = self
                .inner
                .installed_staged(public)
                .map_err(PeerError::from)?;
            Ok((self, complete))
        }
        pub(super) fn complete_delivery(mut self) -> Result<(), PeerError> {
            self.inner.complete_delivery().map_err(PeerError::from)
        }
        pub(super) fn abort(self) {
            self.inner.abort();
        }
    }
    pub(super) fn offer_host(
        runtime: &Path,
        reference: &CredentialRef,
        offer: HostOffer,
        exchange: BootstrapBudget,
    ) -> Result<(HostClient, PublicFrame), PeerError> {
        let directory = Directory::open(runtime)?;
        let name = format!("pairing-{}.sock", channel_name(reference));
        let before = directory.socket(&name)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stream = connect_socket(
            &directory.path.join(&name),
            exchange
                .native_io_deadline()
                .map_err(|error| PeerError::from(ExchangeError::from(error)))?,
            &stop,
        )?;
        let after = directory.socket(&name)?;
        if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
            return Err(PeerError::UnsafePath);
        }
        verify_peer(&stream, None)?;
        let io = SocketIo {
            stream,
            stop,
            server: false,
        };
        let (inner, authority) =
            HostAttachClient::offer(io, offer, exchange).map_err(PeerError::from)?;
        Ok((
            HostClient {
                inner,
                _directory: directory,
            },
            authority,
        ))
    }

    pub(super) fn connect(
        runtime: &Path,
        reference: &CredentialRef,
        expected_server_pid: Option<u32>,
        deadline: Instant,
    ) -> Result<AuthenticatedPeerToken, PeerError> {
        let directory = Directory::open(runtime)?;
        let name = format!("pairing-{}.sock", channel_name(reference));
        let before = directory.socket(&name)?;
        let stop = AtomicBool::new(false);
        let stream = connect_socket(&directory.path.join(&name), deadline, &stop)?;
        let after = directory.socket(&name)?;
        if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
            return Err(PeerError::UnsafePath);
        }
        let server_pid = verify_peer(&stream, expected_server_pid)?;
        write_all(&stream, &request(reference), deadline, &stop)?;
        let mut response = Zeroizing::new([0_u8; 32]);
        read_exact(&stream, &mut *response, deadline, &stop)?;
        write_all(&stream, &[ACK], deadline, &stop)?;
        wait_eof(&stream, deadline, &stop)?;
        check_budget(deadline, &stop)?;
        Ok(AuthenticatedPeerToken {
            token: response_token(&response)?,
            server_pid,
        })
    }

    pub(super) fn cleanup_stale(
        runtime: &Path,
        reference: &CredentialRef,
    ) -> Result<(), PeerError> {
        let directory = Directory::open(runtime)?;
        let name = format!("pairing-{}.sock", channel_name(reference));
        let stat = match directory.socket(&name) {
            Ok(stat) => stat,
            Err(PeerError::Native(code)) if code == libc::ENOENT => return Ok(()),
            Err(error) => return Err(error),
        };
        let stop = AtomicBool::new(false);
        match connect_socket(
            &directory.path.join(&name),
            Instant::now() + IO_BUDGET,
            &stop,
        ) {
            Ok(_) => Err(PeerError::Busy),
            Err(PeerError::Native(code)) if code == libc::ECONNREFUSED => {
                let mut owned = SocketOwner {
                    directory,
                    name,
                    device: stat.st_dev,
                    inode: stat.st_ino,
                    removed: false,
                };
                owned.remove()
            }
            // A timeout, permissions failure or any ambiguous error is not proof
            // that a socket is stale. Preserve it for diagnosis.
            Err(error) => Err(error),
        }
    }

    fn current_uid() -> Result<libc::uid_t, PeerError> {
        // SAFETY: scalar identity queries have no pointer arguments.
        let (real, effective) = unsafe { (libc::getuid(), libc::geteuid()) };
        if real != effective {
            Err(PeerError::PeerDenied)
        } else {
            Ok(effective)
        }
    }

    fn validate_socket_path(path: &Path) -> Result<(), PeerError> {
        // SAFETY: zero is valid for sockaddr_un's integer/byte fields.
        let address: libc::sockaddr_un = unsafe { mem::zeroed() };
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
            return Err(PeerError::UnsafePath);
        }
        Ok(())
    }

    fn connect_socket(
        path: &Path,
        deadline: Instant,
        stop: &AtomicBool,
    ) -> Result<UnixStream, PeerError> {
        check_budget(deadline, stop)?;
        validate_socket_path(path)?;
        // SAFETY: documented local stream socket type; ownership transfers below.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: newly owned socket fd transfers exactly once.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        stream.set_nonblocking(true)?;
        // SAFETY: valid live descriptor; preserve existing flags and add close-on-exec.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        configure_stream(&stream)?;
        // SAFETY: fixed native sockaddr structure is fully initialized before use.
        let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (to, &from) in address.sun_path.iter_mut().zip(path.as_os_str().as_bytes()) {
            *to = from as libc::c_char;
        }
        let length =
            mem::offset_of!(libc::sockaddr_un, sun_path) + path.as_os_str().as_bytes().len() + 1;
        #[cfg(target_os = "macos")]
        {
            address.sun_len = length as u8;
        }
        // SAFETY: nonblocking descriptor and complete bounded local address.
        let result = unsafe {
            libc::connect(
                fd,
                (&address as *const libc::sockaddr_un).cast(),
                length as libc::socklen_t,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(error.into());
            }
            poll(&stream, libc::POLLOUT, deadline, stop)?;
            let mut status = 0_i32;
            let mut length = mem::size_of::<i32>() as libc::socklen_t;
            // SAFETY: initialized scalar output and correct socklen pointer.
            if unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut status as *mut i32).cast(),
                    &mut length,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            if status != 0 {
                return Err(PeerError::Native(status));
            }
        }
        check_budget(deadline, stop)?;
        Ok(stream)
    }

    fn configure_stream(stream: &UnixStream) -> Result<(), PeerError> {
        #[cfg(target_os = "macos")]
        {
            let enabled = 1_i32;
            // SAFETY: live socket and correctly sized scalar option; avoids
            // changing the process-global SIGPIPE disposition.
            if unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    (&enabled as *const i32).cast(),
                    mem::size_of::<i32>() as libc::socklen_t,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        let limit = MESSAGE_LIMIT as i32;
        // SAFETY: live socket and bounded scalar receive-buffer request. Kernel
        // accounting may round this size; protocol byte limits remain independent.
        if unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&limit as *const i32).cast(),
                mem::size_of::<i32>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn verify_peer(stream: &UnixStream, expected_pid: Option<u32>) -> Result<u32, PeerError> {
        let expected = current_uid()?;
        #[cfg(target_os = "linux")]
        {
            let mut credentials = MaybeUninit::<libc::ucred>::zeroed();
            let mut length = mem::size_of::<libc::ucred>() as libc::socklen_t;
            // SAFETY: SO_PEERCRED is kernel-provided for this connected socket;
            // output storage and length cover the exact documented structure.
            if unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    credentials.as_mut_ptr().cast(),
                    &mut length,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            if length as usize != mem::size_of::<libc::ucred>() {
                return Err(PeerError::PeerDenied);
            }
            // SAFETY: successful exact-size getsockopt initialized the structure.
            let credentials = unsafe { credentials.assume_init() };
            if credentials.uid != expected || credentials.pid <= 0 {
                return Err(PeerError::PeerDenied);
            }
            let pid = u32::try_from(credentials.pid).map_err(|_| PeerError::PeerDenied)?;
            if expected_pid.is_some_and(|expected| expected != pid) {
                return Err(PeerError::PeerDenied);
            }
            // SO_PEERCRED is the kernel connect/listen snapshot. The launcher
            // must retain its owned child to bind this PID to that generation.
            Ok(pid)
        }
        #[cfg(target_os = "macos")]
        {
            let mut uid = 0;
            let mut gid = 0;
            // SAFETY: live connected socket and scalar writable outputs.
            if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if uid != expected {
                return Err(PeerError::PeerDenied);
            }
            let mut pid: libc::pid_t = 0;
            let mut length = mem::size_of::<libc::pid_t>() as libc::socklen_t;
            // SAFETY: SOL_LOCAL=0 / LOCAL_PEERPID=2 are Apple's native local
            // socket PID option. Exact live pid_t storage and length are provided.
            if unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    0,
                    2,
                    (&mut pid as *mut libc::pid_t).cast(),
                    &mut length,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            if length as usize != mem::size_of::<libc::pid_t>() || pid <= 0 {
                return Err(PeerError::PeerDenied);
            }
            let pid = u32::try_from(pid).map_err(|_| PeerError::PeerDenied)?;
            if expected_pid.is_some_and(|expected| expected != pid) {
                return Err(PeerError::PeerDenied);
            }
            // This socket's kernel PID is not a process generation/liveness pin.
            Ok(pid)
        }
    }

    fn serve(
        stream: &UnixStream,
        reference: &CredentialRef,
        token: &SecretToken,
        deadline: Instant,
        stop: &Arc<AtomicBool>,
        management: Option<&ManagementSender>,
        #[cfg(test)] stage: &mut PeerNativeStage,
    ) -> Result<(), PeerError> {
        #[cfg(test)]
        {
            *stage = PeerNativeStage::PeerIdentity;
        }
        verify_peer(stream, None)?;
        let started = Instant::now();
        let mut magic = [0_u8; 8];
        #[cfg(test)]
        {
            *stage = PeerNativeStage::RequestMagic;
        }
        read_exact(stream, &mut magic, deadline, stop)?;
        if &magic == crate::peer_management::HOST_MAGIC {
            #[cfg(test)]
            {
                *stage = PeerNativeStage::HostExchange;
            }
            let sender = management.ok_or(PeerError::Protocol)?;
            let budget = BootstrapBudget::for_peer(started, Arc::clone(stop));
            let mut io = SocketIo {
                stream: stream.try_clone()?,
                stop: Arc::clone(stop),
                server: true,
            };
            return management_transport::serve_host_exchange(&mut io, sender, &budget)
                .map_err(PeerError::from);
        }
        if &magic != MAGIC {
            return Err(PeerError::Protocol);
        }
        let mut header = [0_u8; 10];
        header[..8].copy_from_slice(&magic);
        #[cfg(test)]
        {
            *stage = PeerNativeStage::RequestLength;
        }
        read_exact(stream, &mut header[8..], deadline, stop)?;
        let length = usize::from(u16::from_be_bytes([header[8], header[9]]));
        if &header[..8] != MAGIC || length == 0 || length > REFERENCE_LIMIT {
            return Err(PeerError::Protocol);
        }
        let mut reference_bytes = [0_u8; REFERENCE_LIMIT];
        #[cfg(test)]
        {
            *stage = PeerNativeStage::RequestReference;
        }
        read_exact(stream, &mut reference_bytes[..length], deadline, stop)?;
        #[cfg(test)]
        {
            *stage = PeerNativeStage::RequestValidation;
        }
        validate_request(&header, reference, &reference_bytes[..length])?;
        #[cfg(test)]
        {
            *stage = PeerNativeStage::TokenWrite;
        }
        write_all(stream, token.expose_secret(), deadline, stop)?;
        let mut acknowledgement = [0_u8; 1];
        #[cfg(test)]
        {
            *stage = PeerNativeStage::AckRead;
        }
        read_exact(stream, &mut acknowledgement, deadline, stop)?;
        #[cfg(test)]
        {
            *stage = PeerNativeStage::AckValue;
        }
        if acknowledgement != [ACK] {
            return Err(PeerError::Protocol);
        }
        #[cfg(test)]
        {
            *stage = PeerNativeStage::Complete;
        }
        Ok(())
    }

    fn wait_eof(
        stream: &UnixStream,
        deadline: Instant,
        stop: &AtomicBool,
    ) -> Result<(), PeerError> {
        loop {
            check_budget(deadline, stop)?;
            let mut byte = 0_u8;
            // SAFETY: one writable byte and a connected nonblocking socket.
            let result =
                unsafe { libc::recv(stream.as_raw_fd(), (&mut byte as *mut u8).cast(), 1, 0) };
            if result == 0 {
                return Ok(());
            }
            if result > 0 {
                return Err(PeerError::UnexpectedBytesAfterAck);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(error.into());
            }
            poll(stream, libc::POLLIN, deadline, stop)?;
        }
    }

    fn check_budget(deadline: Instant, stop: &AtomicBool) -> Result<(), PeerError> {
        if stop.load(Ordering::Acquire) {
            Err(PeerError::Stopped)
        } else if Instant::now() >= deadline {
            Err(PeerError::Timeout)
        } else {
            Ok(())
        }
    }

    fn poll(
        stream: &UnixStream,
        events: i16,
        deadline: Instant,
        stop: &AtomicBool,
    ) -> Result<(), PeerError> {
        loop {
            check_budget(deadline, stop)?;
            let wait = deadline
                .saturating_duration_since(Instant::now())
                .min(POLL_SLICE)
                .as_millis()
                .max(1) as i32;
            let mut descriptor = libc::pollfd {
                fd: stream.as_raw_fd(),
                events,
                revents: 0,
            };
            // SAFETY: one initialized live descriptor; finite timeout.
            let result = unsafe { libc::poll(&mut descriptor, 1, wait) };
            if result > 0 {
                return Ok(());
            }
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error.into());
                }
            }
        }
    }

    fn read_exact(
        stream: &UnixStream,
        mut bytes: &mut [u8],
        deadline: Instant,
        stop: &AtomicBool,
    ) -> Result<(), PeerError> {
        if bytes.len() > MESSAGE_LIMIT {
            return Err(PeerError::Protocol);
        }
        let expected = bytes.len();
        while !bytes.is_empty() {
            check_budget(deadline, stop)?;
            // SAFETY: writable bounded buffer and nonblocking connected socket.
            let count = unsafe {
                libc::recv(
                    stream.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    0,
                )
            };
            if count == 0 {
                return Err(PeerError::UnexpectedEof {
                    expected,
                    received: expected - bytes.len(),
                });
            }
            if count > 0 {
                bytes = &mut bytes[count as usize..];
                continue;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(error.into());
            }
            poll(stream, libc::POLLIN, deadline, stop)?;
        }
        check_budget(deadline, stop)
    }

    fn write_all(
        stream: &UnixStream,
        mut bytes: &[u8],
        deadline: Instant,
        stop: &AtomicBool,
    ) -> Result<(), PeerError> {
        if bytes.len() > MESSAGE_LIMIT {
            return Err(PeerError::Protocol);
        }
        while !bytes.is_empty() {
            check_budget(deadline, stop)?;
            #[cfg(target_os = "linux")]
            let flags = libc::MSG_NOSIGNAL;
            #[cfg(target_os = "macos")]
            let flags = 0;
            // SAFETY: bounded live buffer and nonblocking socket; SIGPIPE is
            // suppressed per-call on Linux and per-socket on macOS.
            let count = unsafe {
                libc::send(
                    stream.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    flags,
                )
            };
            if count == 0 {
                return Err(PeerError::Protocol);
            }
            if count > 0 {
                bytes = &bytes[count as usize..];
                continue;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(error.into());
            }
            poll(stream, libc::POLLOUT, deadline, stop)?;
        }
        check_budget(deadline, stop)
    }

    #[cfg(test)]
    mod native_eof_tests {
        use super::*;

        // The handoff has no local IPC EOF diagnostics fixture. Real socket
        // pairs distinguish partial token reads from forbidden post-ACK bytes
        // without a credential, filesystem entry or framing fault shim.
        #[test]
        fn native_partial_message_and_post_ack_bytes_remain_distinct_failures() {
            let (sender, receiver) = UnixStream::pair().unwrap();
            sender.set_nonblocking(true).unwrap();
            receiver.set_nonblocking(true).unwrap();
            configure_stream(&sender).unwrap();
            configure_stream(&receiver).unwrap();
            let stop = AtomicBool::new(false);
            let deadline = Instant::now() + Duration::from_secs(2);
            write_all(&sender, &[0xa5; 7], deadline, &stop).unwrap();
            sender.shutdown(std::net::Shutdown::Write).unwrap();
            let mut destination = [0_u8; 32];
            assert_eq!(
                read_exact(&receiver, &mut destination, deadline, &stop),
                Err(PeerError::UnexpectedEof {
                    expected: 32,
                    received: 7,
                })
            );

            let (sender, receiver) = UnixStream::pair().unwrap();
            sender.set_nonblocking(true).unwrap();
            receiver.set_nonblocking(true).unwrap();
            configure_stream(&sender).unwrap();
            configure_stream(&receiver).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            write_all(&sender, &[0xa5], deadline, &stop).unwrap();
            assert_eq!(
                wait_eof(&receiver, deadline, &stop),
                Err(PeerError::UnexpectedBytesAfterAck)
            );
        }
    }
}

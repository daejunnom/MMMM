//! Native peer로 확인된 연결에서만 사용하는 호스트 bootstrap framing이다.
//! DB/권한/호스트 설치를 하지 않으며 native 소유자는 매 I/O의 completion을
//! 증명한 뒤에만 반환한다. 각 chunk는 2 KiB, I/O는 5초, 설치 대기는 10초,
//! 첫 magic부터 전체 교환은 30초다. 읽기 timeout 뒤 consuming read를 재전송하지 않는다.

use crate::{
    peer::PeerError,
    peer_management::{
        BootstrapBudget, BootstrapWitness, HOST_MAGIC, HostOffer, ManagementError, ManagementKind,
        ManagementRequest, ManagementSender, NATIVE_CHUNK_BYTES, PublicFrame, public_length,
    },
};
use std::{fmt, time::Instant};
use zeroize::Zeroizing;

const MANAGEMENT_ACK: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExchangeError {
    Native(PeerError),
    Management(ManagementError),
}
impl fmt::Display for ExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(error) => error.fmt(formatter),
            Self::Management(error) => error.fmt(formatter),
        }
    }
}
impl std::error::Error for ExchangeError {}
impl From<PeerError> for ExchangeError {
    fn from(error: PeerError) -> Self {
        Self::Native(error)
    }
}
impl From<ManagementError> for ExchangeError {
    fn from(error: ManagementError) -> Self {
        Self::Management(error)
    }
}

/// 구현은 연결된 actual same UID/SID를 먼저 검증한 native peer 모듈에 한정한다.
/// read/write는 부분 완료 count를 반환할 수 있지만 pending native allocation을
/// 여기로 넘기지 않는다. budget/worker stop을 20 ms마다 함께 확인한다.
pub(crate) trait ManagementIo {
    fn read_chunk(
        &mut self,
        destination: &mut [u8],
        deadline: Instant,
        budget: &BootstrapBudget,
    ) -> Result<usize, PeerError>;
    fn write_chunk(
        &mut self,
        source: &[u8],
        deadline: Instant,
        budget: &BootstrapBudget,
    ) -> Result<usize, PeerError>;
    /// Unix poll / overlapped Windows PeekNamedPipe를 소비 없이 유한하게 확인한다.
    /// POLLERR/HUP/NVAL 및 native 오류는 원래 numeric 원인으로 반환한다.
    fn wait_readable(
        &mut self,
        deadline: Instant,
        budget: &BootstrapBudget,
    ) -> Result<(), PeerError>;
    /// 서버: 모든 native I/O terminal을 확인한 후 연결을 종료한다.
    fn disconnect(&mut self, budget: &BootstrapBudget) -> Result<(), PeerError>;
    /// 클라이언트: ACK write만으로 완료를 추정하지 않고 native EOF를 확인한다.
    /// Windows 성공한 zero-byte ReadFile은 EOF로 분류하지 않는다.
    fn wait_disconnect(
        &mut self,
        deadline: Instant,
        budget: &BootstrapBudget,
    ) -> Result<(), PeerError>;
}

fn read_exact<I: ManagementIo>(
    io: &mut I,
    mut destination: &mut [u8],
    budget: &BootstrapBudget,
) -> Result<(), ExchangeError> {
    while !destination.is_empty() {
        let chunk_len = destination.len().min(NATIVE_CHUNK_BYTES);
        let deadline = budget.native_io_deadline()?;
        let count = io.read_chunk(&mut destination[..chunk_len], deadline, budget)?;
        budget.check()?;
        if count == 0 || count > chunk_len {
            return Err(PeerError::Protocol.into());
        }
        destination = &mut destination[count..];
    }
    Ok(())
}
fn write_all<I: ManagementIo>(
    io: &mut I,
    mut source: &[u8],
    budget: &BootstrapBudget,
) -> Result<(), ExchangeError> {
    while !source.is_empty() {
        let chunk_len = source.len().min(NATIVE_CHUNK_BYTES);
        let deadline = budget.native_io_deadline()?;
        let count = io.write_chunk(&source[..chunk_len], deadline, budget)?;
        budget.check()?;
        if count == 0 || count > chunk_len {
            return Err(PeerError::Protocol.into());
        }
        source = &source[count..];
    }
    Ok(())
}
fn read_public<I: ManagementIo>(
    io: &mut I,
    budget: &BootstrapBudget,
) -> Result<PublicFrame, ExchangeError> {
    let mut prefix = [0_u8; 4];
    read_exact(io, &mut prefix, budget)?;
    let length = public_length(prefix)?;
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    read_exact(io, &mut bytes, budget)?;
    let frame = PublicFrame::decode_owned(bytes)?;
    budget.check()?;
    Ok(frame)
}
fn write_public<I: ManagementIo>(
    io: &mut I,
    frame: &PublicFrame,
    budget: &BootstrapBudget,
) -> Result<(), ExchangeError> {
    let encoded = frame.encode()?;
    budget.check()?;
    write_all(io, &encoded.length_prefix(), budget)?;
    for chunk in encoded.chunks() {
        write_all(io, chunk, budget)?;
    }
    Ok(())
}

struct NativeFinish<'a> {
    sender: &'a ManagementSender,
    witness: BootstrapWitness,
    budget: &'a BootstrapBudget,
    delivered: bool,
}
impl NativeFinish<'_> {
    fn delivered(mut self) -> Result<(), ExchangeError> {
        self.budget.check()?;
        self.sender
            .notify_finished(&self.witness, true, self.budget)?;
        self.delivered = true;
        Ok(())
    }
}
impl Drop for NativeFinish<'_> {
    fn drop(&mut self) {
        if !self.delivered {
            self.budget.cancel();
            // Failure notification carries no new native I/O. If capacity is
            // occupied or the main loop stopped, the main loop's exact pending
            // expiry or explicit fallible processor shutdown retires the staged
            // grant and route. Dropping the processor is not cleanup evidence.
            let _ = self
                .sender
                .notify_finished(&self.witness, false, self.budget);
        }
    }
}

/// caller는 첫 magic==MMMMHST1 및 actual UID/SID를 이미 검사해야 한다.
/// 이 함수에서 raw token을 받기 전에 public Offer 전체를 먼저 검증한다.
pub(crate) fn serve_host_exchange<I: ManagementIo>(
    io: &mut I,
    sender: &ManagementSender,
    budget: &BootstrapBudget,
) -> Result<(), ExchangeError> {
    let public = read_public(io, budget)?;
    if public.kind() != ManagementKind::Offer {
        return Err(ManagementError::InvalidFrame.into());
    }
    let mut raw_token = Zeroizing::new([0_u8; 32]);
    read_exact(io, &mut *raw_token, budget)?;
    let offer = HostOffer::from_raw(public, raw_token)?;
    let witness = offer.witness().clone();
    let finish = NativeFinish {
        sender,
        witness: witness.clone(),
        budget,
        delivered: false,
    };
    let authority = sender
        .submit(ManagementRequest::Offer(offer), budget)?
        .wait()?;
    write_public(io, &authority, budget)?;
    // Java installs authority on its game task with a 10-second budget. Do not
    // issue then timeout/retry a consuming native read while that task is busy.
    io.wait_readable(budget.application_wait_deadline()?, budget)?;
    let installed = read_public(io, budget)?;
    let complete = sender
        .submit(ManagementRequest::installed(installed, witness)?, budget)?
        .wait()?;
    write_public(io, &complete, budget)?;
    let mut acknowledgement = [0_u8; 1];
    read_exact(io, &mut acknowledgement, budget)?;
    if acknowledgement != [MANAGEMENT_ACK] {
        return Err(PeerError::Protocol.into());
    }
    io.disconnect(budget)?;
    finish.delivered()
}

/// Native client의 두 단계 사이에는 공개 authority를 Java에 전달하고 Installed
/// 공개 프레임을 받는다. 32-byte token은 offer write 후 여기서 즉시 Drop한다.
/// OS 핸들과 verification witness를 소유한 IO는 native peer 모듈에서만 생성한다.
pub(crate) struct HostAttachClient<I: ManagementIo> {
    io: I,
    nonce: String,
    budget: BootstrapBudget,
    completed: bool,
}
impl<I: ManagementIo> HostAttachClient<I> {
    pub(crate) fn offer(
        io: I,
        offer: HostOffer,
        budget: BootstrapBudget,
    ) -> Result<(Self, PublicFrame), ExchangeError> {
        let (public, token, _) = offer.into_parts();
        let mut pending = Self {
            io,
            nonce: public.nonce().to_owned(),
            budget,
            completed: false,
        };
        write_all(&mut pending.io, HOST_MAGIC, &pending.budget)?;
        write_public(&mut pending.io, &public, &pending.budget)?;
        write_all(&mut pending.io, token.expose_secret(), &pending.budget)?;
        drop(token);
        pending
            .io
            .wait_readable(pending.budget.application_wait_deadline()?, &pending.budget)?;
        let authority = read_public(&mut pending.io, &pending.budget)?;
        if authority.kind() != ManagementKind::Authority || authority.nonce() != pending.nonce {
            return Err(ManagementError::WrongReply.into());
        }
        Ok((pending, authority))
    }
    pub(crate) fn installed(mut self, public: PublicFrame) -> Result<PublicFrame, ExchangeError> {
        if public.kind() != ManagementKind::Installed || public.nonce() != self.nonce {
            return Err(ManagementError::WrongReply.into());
        }
        write_public(&mut self.io, &public, &self.budget)?;
        self.io
            .wait_readable(self.budget.application_wait_deadline()?, &self.budget)?;
        let complete = read_public(&mut self.io, &self.budget)?;
        if complete.kind() != ManagementKind::Complete || complete.nonce() != self.nonce {
            return Err(ManagementError::WrongReply.into());
        }
        write_all(&mut self.io, &[MANAGEMENT_ACK], &self.budget)?;
        self.io
            .wait_disconnect(self.budget.native_io_deadline()?, &self.budget)?;
        self.budget.check()?;
        self.completed = true;
        Ok(complete)
    }
}
impl<I: ManagementIo> Drop for HostAttachClient<I> {
    fn drop(&mut self) {
        if !self.completed {
            self.budget.cancel();
        }
    }
}

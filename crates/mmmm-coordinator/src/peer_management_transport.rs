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
    // Complete를 외부 Java stdout에 flush하고 stdin EOF 및 stdio helper의
    // 실제 native drain을 관측하는 동안 consuming read를 발행하지 않는다.
    // 대기는 원래 전체 마감, 준비된 뒤 actual native ACK read는 최대 5초다.
    io.wait_readable(budget.deadline(), budget)?;
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
    phase: ClientPhase,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum ClientPhase {
    Offered,
    CompleteReceived,
    DeliveryAttempted,
    Completed,
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
            phase: ClientPhase::Offered,
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
    pub(crate) fn deadline(&self) -> Instant {
        self.budget.deadline()
    }
    pub(crate) fn installed_staged(
        &mut self,
        public: PublicFrame,
    ) -> Result<PublicFrame, ExchangeError> {
        self.budget.check()?;
        if self.phase != ClientPhase::Offered
            || public.kind() != ManagementKind::Installed
            || public.nonce() != self.nonce
        {
            return Err(ManagementError::WrongReply.into());
        }
        write_public(&mut self.io, &public, &self.budget)?;
        self.io
            .wait_readable(self.budget.application_wait_deadline()?, &self.budget)?;
        let complete = read_public(&mut self.io, &self.budget)?;
        if complete.kind() != ManagementKind::Complete || complete.nonce() != self.nonce {
            return Err(ManagementError::WrongReply.into());
        }
        self.phase = ClientPhase::CompleteReceived;
        Ok(complete)
    }
    pub(crate) fn complete_delivery(&mut self) -> Result<(), ExchangeError> {
        self.budget.check()?;
        if self.phase != ClientPhase::CompleteReceived {
            return Err(PeerError::Protocol.into());
        }
        // ACK가 일부라도 전달되었을 수 있는 실패를 같은 연결에서 replay하지 않는다.
        self.phase = ClientPhase::DeliveryAttempted;
        write_all(&mut self.io, &[MANAGEMENT_ACK], &self.budget)?;
        self.io
            .wait_disconnect(self.budget.native_io_deadline()?, &self.budget)?;
        self.budget.check()?;
        self.phase = ClientPhase::Completed;
        Ok(())
    }
    pub(crate) fn abort(&self) {
        self.budget.cancel();
    }
}
impl<I: ManagementIo> Drop for HostAttachClient<I> {
    fn drop(&mut self) {
        if self.phase != ClientPhase::Completed {
            self.budget.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        time::Duration,
    };

    // Native store/pipe를 대체하는 production fallback이 아니다. 이번 authored
    // fixture는 기존 자료에 없는 staged ACK 경계와 절대마감의 byte 관측을 검사한다.
    struct ObservedIo {
        input: VecDeque<u8>,
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
        eof_error: Option<PeerError>,
    }
    impl ManagementIo for ObservedIo {
        fn read_chunk(
            &mut self,
            destination: &mut [u8],
            _: Instant,
            _: &BootstrapBudget,
        ) -> Result<usize, PeerError> {
            let count = destination.len().min(self.input.len());
            for byte in &mut destination[..count] {
                *byte = self.input.pop_front().unwrap();
            }
            Ok(count)
        }
        fn write_chunk(
            &mut self,
            source: &[u8],
            _: Instant,
            _: &BootstrapBudget,
        ) -> Result<usize, PeerError> {
            self.writes.lock().unwrap().push(source.to_vec());
            Ok(source.len())
        }
        fn wait_readable(
            &mut self,
            deadline: Instant,
            budget: &BootstrapBudget,
        ) -> Result<(), PeerError> {
            assert!(deadline <= budget.deadline());
            Ok(())
        }
        fn disconnect(&mut self, _: &BootstrapBudget) -> Result<(), PeerError> {
            panic!("client fixture never invokes server disconnect")
        }
        fn wait_disconnect(
            &mut self,
            deadline: Instant,
            budget: &BootstrapBudget,
        ) -> Result<(), PeerError> {
            assert!(deadline <= budget.deadline());
            match self.eof_error {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
    }
    fn installed() -> PublicFrame {
        PublicFrame::from_value(json!({
            "kind":"host_pairing_installed", "protocolVersion":"0.2.0", "nonce":"pair-staged",
            "hostEndpoint":{"address":"127.0.0.1:32123", "path":"/rpc", "hostEpoch":"host-staged"}
        }))
        .unwrap()
    }
    fn complete_bytes() -> VecDeque<u8> {
        let public = PublicFrame::from_value(json!({
            "kind":"host_pairing_complete", "protocolVersion":"0.2.0", "nonce":"pair-staged",
            "ready":true, "coordinatorEpoch":"coordinator-staged", "hostEpoch":"host-staged", "contextId":"context-staged"
        })).unwrap().encode().unwrap();
        public
            .length_prefix()
            .into_iter()
            .chain(public.payload().iter().copied())
            .collect()
    }
    fn client(budget: BootstrapBudget) -> HostAttachClient<ObservedIo> {
        HostAttachClient {
            io: ObservedIo {
                input: complete_bytes(),
                writes: Arc::new(Mutex::new(Vec::new())),
                eof_error: None,
            },
            nonce: "pair-staged".to_owned(),
            budget,
            phase: ClientPhase::Offered,
        }
    }
    fn ack_count(writes: &Arc<Mutex<Vec<Vec<u8>>>>) -> usize {
        writes
            .lock()
            .unwrap()
            .iter()
            .filter(|bytes| bytes.as_slice() == [MANAGEMENT_ACK])
            .count()
    }

    #[test]
    fn complete_receive_is_staged_until_one_terminal_delivery_and_original_deadline() {
        let deadline = Instant::now() + Duration::from_secs(2);
        let budget = BootstrapBudget::with_deadline(deadline);
        let mut client = client(budget.clone());
        let writes = Arc::clone(&client.io.writes);
        let complete = client.installed_staged(installed()).unwrap();
        assert_eq!(complete.kind(), ManagementKind::Complete);
        assert_eq!(client.deadline(), deadline);
        assert_eq!(ack_count(&writes), 0);
        assert!(matches!(
            client.installed_staged(installed()),
            Err(ExchangeError::Management(ManagementError::WrongReply))
        ));
        client.complete_delivery().unwrap();
        assert_eq!(ack_count(&writes), 1);
        assert!(matches!(
            client.complete_delivery(),
            Err(ExchangeError::Native(PeerError::Protocol))
        ));
        assert_eq!(ack_count(&writes), 1);
        drop(client);
        assert!(budget.check().is_ok());
    }

    #[test]
    fn drop_and_expired_original_budget_send_no_terminal_ack() {
        let budget = BootstrapBudget::new();
        let mut abandoned = client(budget.clone());
        let writes = Arc::clone(&abandoned.io.writes);
        abandoned.installed_staged(installed()).unwrap();
        drop(abandoned);
        assert_eq!(ack_count(&writes), 0);
        assert_eq!(budget.check(), Err(ManagementError::Cancelled));

        let budget = BootstrapBudget::with_deadline(Instant::now());
        let mut expired = client(budget);
        let writes = Arc::clone(&expired.io.writes);
        expired.phase = ClientPhase::CompleteReceived;
        assert!(matches!(
            expired.complete_delivery(),
            Err(ExchangeError::Management(ManagementError::Deadline))
        ));
        assert!(writes.lock().unwrap().is_empty());
    }

    #[test]
    fn ack_attempt_then_eof_failure_preserves_uncertainty_and_cancels_on_drop() {
        let budget = BootstrapBudget::new();
        let mut pending = client(budget.clone());
        let writes = Arc::clone(&pending.io.writes);
        pending.installed_staged(installed()).unwrap();
        pending.io.eof_error = Some(PeerError::Timeout);
        assert!(matches!(
            pending.complete_delivery(),
            Err(ExchangeError::Native(PeerError::Timeout))
        ));
        assert_eq!(ack_count(&writes), 1);
        assert!(pending.phase != ClientPhase::Completed);
        assert!(matches!(
            pending.complete_delivery(),
            Err(ExchangeError::Native(PeerError::Protocol))
        ));
        assert_eq!(ack_count(&writes), 1);
        drop(pending);
        assert_eq!(budget.check(), Err(ManagementError::Cancelled));
    }
}

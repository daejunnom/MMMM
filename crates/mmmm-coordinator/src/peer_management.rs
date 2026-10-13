//! 같은 OS 사용자로 확인된 peer의 호스트 연결 자료를 main loop에 전달한다.
//!
//! 이 모듈은 codec과 용량 1 채널만 소유한다. DB, 프로젝트 권한, 게임 관리자
//! 확인과 HostBridge 설치는 Coordinator의 단일 main loop가 수행한다. 공개
//! JSON과 32바이트 토큰은 별도로 전달하며 토큰을 JSON/debug 출력에 넣지 않는다.

use crate::credential::SecretToken;
use mmmm_contracts::{
    ContextId, ContractValidator, JsonLimits, PrincipalId, ProjectId, RequestId, ResourceLocation,
    SessionEpoch, Sha256Digest, SourceId, canonical_digest, parse_json_with_limits,
    verify_projected_digest,
};
use serde_json::{Map, Value};
use std::{
    collections::BTreeSet,
    fmt,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError},
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const HOST_MAGIC: &[u8; 8] = b"MMMMHST1";
pub const MAX_PUBLIC_BYTES: usize = 1024 * 1024;
pub const NATIVE_CHUNK_BYTES: usize = 2048;
pub const BOOTSTRAP_LIMIT: Duration = Duration::from_secs(30);
pub const NATIVE_IO_LIMIT: Duration = Duration::from_secs(5);
pub const APPLICATION_REPLY_LIMIT: Duration = Duration::from_secs(10);
const POLL_SLICE: Duration = Duration::from_millis(20);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementError {
    InvalidFrame,
    FrameTooLarge,
    Busy,
    Disconnected,
    Deadline,
    Cancelled,
    WrongReply,
    TransportUncertain,
    EntropyUnavailable,
}
impl fmt::Display for ManagementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFrame => "host management public frame is invalid",
            Self::FrameTooLarge => "host management public frame exceeds its bound",
            Self::Busy => "host management queue is occupied",
            Self::Disconnected => "host management channel is closed",
            Self::Deadline => "host management deadline expired",
            Self::Cancelled => "host management exchange was cancelled",
            Self::WrongReply => "host management reply differs from its request witness",
            Self::TransportUncertain => "native peer completion remains unresolved",
            Self::EntropyUnavailable => "host management request identity is unavailable",
        })
    }
}
impl std::error::Error for ManagementError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementKind {
    Offer,
    Authority,
    Installed,
    Complete,
}

/// 공개 자료만 담는다. JSON과 계약 오류의 내용을 로그로 되돌리지 않는다.
/// 공개 JSON에도 임의 token 필드를 추가할 수 없도록 각 형태를 정확히 검사한다.
pub struct PublicFrame {
    value: Value,
    kind: ManagementKind,
}
impl PublicFrame {
    pub fn decode(bytes: &[u8]) -> Result<Self, ManagementError> {
        if bytes.is_empty() || bytes.len() > MAX_PUBLIC_BYTES {
            return Err(ManagementError::FrameTooLarge);
        }
        let value =
            parse_json_with_limits(bytes, limits()).map_err(|_| ManagementError::InvalidFrame)?;
        let kind = validate_public(&value)?;
        Ok(Self { value, kind })
    }
    pub fn decode_owned(bytes: Zeroizing<Vec<u8>>) -> Result<Self, ManagementError> {
        Self::decode(&bytes)
    }
    pub fn from_value(value: Value) -> Result<Self, ManagementError> {
        let mut writer = PublicWriter(Zeroizing::new(Vec::new()));
        serde_json::to_writer(&mut writer, &value).map_err(|_| ManagementError::FrameTooLarge)?;
        Self::decode_owned(writer.0)
    }
    pub fn kind(&self) -> ManagementKind {
        self.kind
    }
    pub fn nonce(&self) -> &str {
        // validate_public proves this required nonempty stable identity.
        self.value["nonce"].as_str().unwrap_or("")
    }
    pub fn value(&self) -> &Value {
        &self.value
    }
    pub fn into_value(self) -> Value {
        self.value
    }
    pub fn encode(&self) -> Result<EncodedPublicFrame, ManagementError> {
        let mut writer = PublicWriter(Zeroizing::new(Vec::new()));
        serde_json::to_writer(&mut writer, &self.value)
            .map_err(|_| ManagementError::FrameTooLarge)?;
        Ok(EncodedPublicFrame { bytes: writer.0 })
    }
}

pub struct EncodedPublicFrame {
    bytes: Zeroizing<Vec<u8>>,
}
impl EncodedPublicFrame {
    pub fn length_prefix(&self) -> [u8; 4] {
        (self.bytes.len() as u32).to_be_bytes()
    }
    pub fn payload(&self) -> &[u8] {
        &self.bytes
    }
    /// Native OVERLAPPED 소유자는 기존 2 KiB 상한을 그대로 유지한다.
    pub fn chunks(&self) -> std::slice::Chunks<'_, u8> {
        self.bytes.chunks(NATIVE_CHUNK_BYTES)
    }
}

pub fn public_length(prefix: [u8; 4]) -> Result<usize, ManagementError> {
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_PUBLIC_BYTES {
        Err(ManagementError::FrameTooLarge)
    } else {
        Ok(length)
    }
}

struct PublicWriter(Zeroizing<Vec<u8>>);
impl Write for PublicWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > MAX_PUBLIC_BYTES)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "public frame limit",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn limits() -> JsonLimits {
    JsonLimits {
        max_bytes: MAX_PUBLIC_BYTES,
        max_depth: 64,
        max_nodes: 4096,
    }
}

fn validate_public(value: &Value) -> Result<ManagementKind, ManagementError> {
    let object = value.as_object().ok_or(ManagementError::InvalidFrame)?;
    if text(value, "protocolVersion")? != mmmm_contracts::CONTRACT_VERSION {
        return Err(ManagementError::InvalidFrame);
    }
    RequestId::new(text(value, "nonce")?).map_err(|_| ManagementError::InvalidFrame)?;
    let validator = ContractValidator::shared().map_err(|_| ManagementError::InvalidFrame)?;
    match text(value, "kind")? {
        "host_pairing_offer" => {
            exact(
                object,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "hostHello",
                    "hostArtifactDigest",
                    "principalId",
                    "playerId",
                    "playerContext",
                    "dataRoot",
                    "projectId",
                    "scope",
                    "nativeActions",
                ],
            )?;
            definition(validator, "HostHello", &value["hostHello"])?;
            digest(text(value, "hostArtifactDigest")?)?;
            PrincipalId::new(text(value, "principalId")?)
                .map_err(|_| ManagementError::InvalidFrame)?;
            RequestId::new(text(value, "playerId")?).map_err(|_| ManagementError::InvalidFrame)?;
            ProjectId::new(text(value, "projectId")?).map_err(|_| ManagementError::InvalidFrame)?;
            let data_root = text(value, "dataRoot")?;
            if data_root.len() > 4096
                || data_root.chars().any(char::is_control)
                || !Path::new(data_root).is_absolute()
            {
                return Err(ManagementError::InvalidFrame);
            }
            definition(validator, "Scope", &value["scope"])?;
            if value["scope"]["projectId"] != value["projectId"] {
                return Err(ManagementError::InvalidFrame);
            }
            validate_player_context(&value["playerContext"])?;
            let mut actions = BTreeSet::new();
            for action in array(value, "nativeActions")? {
                definition(validator, "ActionDescriptor", action)?;
                if !actions.insert(text(action, "actionId")?) {
                    return Err(ManagementError::InvalidFrame);
                }
            }
            Ok(ManagementKind::Offer)
        }
        "host_pairing_authority" => {
            exact(
                object,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "contexts",
                    "approvedSources",
                    "approvedActions",
                    "permissions",
                    "writeProfileVerified",
                ],
            )?;
            if value["writeProfileVerified"] != false {
                return Err(ManagementError::InvalidFrame);
            }
            let contexts = array(value, "contexts")?;
            if contexts.is_empty() || contexts.len() > 16 {
                return Err(ManagementError::InvalidFrame);
            }
            let mut ids = BTreeSet::new();
            for context in contexts {
                definition(validator, "ExecutionContext", context)?;
                verify_projected_digest("ExecutionContext", context)
                    .map_err(|_| ManagementError::InvalidFrame)?;
                if !ids.insert(text(context, "contextId")?) {
                    return Err(ManagementError::InvalidFrame);
                }
            }
            let sources = value["approvedSources"]
                .as_object()
                .ok_or(ManagementError::InvalidFrame)?;
            if sources.is_empty() || sources.len() > 128 {
                return Err(ManagementError::InvalidFrame);
            }
            for (id, sha) in sources {
                SourceId::new(id.as_str()).map_err(|_| ManagementError::InvalidFrame)?;
                digest(sha.as_str().ok_or(ManagementError::InvalidFrame)?)?;
            }
            unique_strings(array(value, "approvedActions")?, |value| digest(value))?;
            unique_strings(array(value, "permissions")?, |permission| {
                if matches!(
                    permission,
                    "mmmm:world_read" | "mmmm:command_complete" | "mmmm:provider_inventory"
                ) {
                    Ok(())
                } else {
                    Err(ManagementError::InvalidFrame)
                }
            })?;
            Ok(ManagementKind::Authority)
        }
        "host_pairing_installed" => {
            exact(
                object,
                &["kind", "protocolVersion", "nonce", "hostEndpoint"],
            )?;
            let endpoint = value["hostEndpoint"]
                .as_object()
                .ok_or(ManagementError::InvalidFrame)?;
            exact(endpoint, &["address", "path", "hostEpoch"])?;
            let address: SocketAddr = text(&value["hostEndpoint"], "address")?
                .parse()
                .map_err(|_| ManagementError::InvalidFrame)?;
            if address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST)
                || address.port() == 0
                || text(&value["hostEndpoint"], "path")? != "/rpc"
            {
                return Err(ManagementError::InvalidFrame);
            }
            SessionEpoch::new(text(&value["hostEndpoint"], "hostEpoch")?)
                .map_err(|_| ManagementError::InvalidFrame)?;
            Ok(ManagementKind::Installed)
        }
        "host_pairing_complete" => {
            exact(
                object,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "ready",
                    "coordinatorEpoch",
                    "hostEpoch",
                    "contextId",
                ],
            )?;
            if value["ready"] != true {
                return Err(ManagementError::InvalidFrame);
            }
            SessionEpoch::new(text(value, "coordinatorEpoch")?)
                .map_err(|_| ManagementError::InvalidFrame)?;
            SessionEpoch::new(text(value, "hostEpoch")?)
                .map_err(|_| ManagementError::InvalidFrame)?;
            ContextId::new(text(value, "contextId")?).map_err(|_| ManagementError::InvalidFrame)?;
            Ok(ManagementKind::Complete)
        }
        _ => Err(ManagementError::InvalidFrame),
    }
}

fn definition(
    validator: &ContractValidator,
    name: &str,
    value: &Value,
) -> Result<(), ManagementError> {
    validator
        .validate(name, value)
        .map_err(|_| ManagementError::InvalidFrame)
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ManagementError> {
    value[key].as_str().ok_or(ManagementError::InvalidFrame)
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], ManagementError> {
    value[key]
        .as_array()
        .map(Vec::as_slice)
        .ok_or(ManagementError::InvalidFrame)
}
fn exact(object: &Map<String, Value>, keys: &[&str]) -> Result<(), ManagementError> {
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        Err(ManagementError::InvalidFrame)
    } else {
        Ok(())
    }
}
fn digest(value: &str) -> Result<(), ManagementError> {
    Sha256Digest::new(value)
        .map(|_| ())
        .map_err(|_| ManagementError::InvalidFrame)
}
fn unique_strings(
    values: &[Value],
    check: impl Fn(&str) -> Result<(), ManagementError>,
) -> Result<(), ManagementError> {
    let mut seen = BTreeSet::new();
    for value in values {
        let value = value.as_str().ok_or(ManagementError::InvalidFrame)?;
        check(value)?;
        if !seen.insert(value) {
            return Err(ManagementError::InvalidFrame);
        }
    }
    Ok(())
}
fn validate_player_context(value: &Value) -> Result<(), ManagementError> {
    exact(
        value.as_object().ok_or(ManagementError::InvalidFrame)?,
        &[
            "dimension",
            "executorHandle",
            "origin",
            "rotationDegrees",
            "anchor",
        ],
    )?;
    ResourceLocation::new(text(value, "dimension")?).map_err(|_| ManagementError::InvalidFrame)?;
    RequestId::new(text(value, "executorHandle")?).map_err(|_| ManagementError::InvalidFrame)?;
    for (key, length) in [("origin", 3), ("rotationDegrees", 2)] {
        let vector = array(value, key)?;
        if vector.len() != length
            || vector
                .iter()
                .any(|number| number.as_f64().is_none_or(|number| !number.is_finite()))
        {
            return Err(ManagementError::InvalidFrame);
        }
    }
    if text(value, "anchor")? != "feet" {
        return Err(ManagementError::InvalidFrame);
    }
    Ok(())
}

#[derive(Clone)]
pub struct BootstrapBudget {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    peer_stop: Option<Arc<AtomicBool>>,
}
impl Default for BootstrapBudget {
    fn default() -> Self {
        Self::new()
    }
}
impl BootstrapBudget {
    pub fn new() -> Self {
        Self {
            deadline: Instant::now() + BOOTSTRAP_LIMIT,
            cancelled: Arc::new(AtomicBool::new(false)),
            peer_stop: None,
        }
    }
    /// Native peer가 첫 magic을 받기 시작한 시각부터 전체 상한을 계산한다.
    /// peer stop은 관측만 한다. 개별 교환 실패가 listener 전체를 취소하지 않는다.
    pub(crate) fn for_peer(started: Instant, stop: Arc<AtomicBool>) -> Self {
        Self {
            deadline: started.min(Instant::now()) + BOOTSTRAP_LIMIT,
            cancelled: Arc::new(AtomicBool::new(false)),
            peer_stop: Some(stop),
        }
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn check(&self) -> Result<(), ManagementError> {
        if crate::peer::fatal_stop_requested() {
            Err(ManagementError::TransportUncertain)
        } else if self.cancelled.load(Ordering::Acquire)
            || self
                .peer_stop
                .as_ref()
                .is_some_and(|stop| stop.load(Ordering::Acquire))
        {
            Err(ManagementError::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(ManagementError::Deadline)
        } else {
            Ok(())
        }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    pub fn native_io_deadline(&self) -> Result<Instant, ManagementError> {
        self.check()?;
        Ok(self.deadline.min(Instant::now() + NATIVE_IO_LIMIT))
    }
    pub(crate) fn application_wait_deadline(&self) -> Result<Instant, ManagementError> {
        self.reply_deadline()
    }
    fn reply_deadline(&self) -> Result<Instant, ManagementError> {
        self.check()?;
        Ok(self.deadline.min(Instant::now() + APPLICATION_REPLY_LIMIT))
    }
}

/// wire에 포함하지 않는 서버 생성 증인. nonce만으로 authority를 찾지 않는다.
#[derive(Clone)]
pub struct BootstrapWitness {
    id: RequestId,
    nonce: RequestId,
    offer_digest: Sha256Digest,
}
impl BootstrapWitness {
    pub fn id(&self) -> &RequestId {
        &self.id
    }
    pub fn nonce(&self) -> &str {
        self.nonce.as_str()
    }
    pub fn offer_digest(&self) -> &Sha256Digest {
        &self.offer_digest
    }
}

pub struct HostOffer {
    public: PublicFrame,
    token: SecretToken,
    witness: BootstrapWitness,
}
impl HostOffer {
    pub fn new(public: PublicFrame, token: SecretToken) -> Result<Self, ManagementError> {
        if public.kind() != ManagementKind::Offer {
            return Err(ManagementError::InvalidFrame);
        }
        let witness = BootstrapWitness {
            id: new_request_id()?,
            nonce: RequestId::new(public.nonce()).map_err(|_| ManagementError::InvalidFrame)?,
            offer_digest: canonical_digest(public.value())
                .map_err(|_| ManagementError::InvalidFrame)?,
        };
        Ok(Self {
            public,
            token,
            witness,
        })
    }
    pub fn decode(
        public: Zeroizing<Vec<u8>>,
        raw_token: Zeroizing<[u8; 32]>,
    ) -> Result<Self, ManagementError> {
        let public = PublicFrame::decode_owned(public)?;
        Self::from_raw(public, raw_token)
    }
    pub(crate) fn from_raw(
        public: PublicFrame,
        raw_token: Zeroizing<[u8; 32]>,
    ) -> Result<Self, ManagementError> {
        if public.kind() != ManagementKind::Offer {
            return Err(ManagementError::InvalidFrame);
        }
        let mut encoded = Zeroizing::new(String::with_capacity(64));
        use fmt::Write as _;
        for byte in raw_token.iter() {
            write!(encoded, "{byte:02x}").map_err(|_| ManagementError::InvalidFrame)?;
        }
        let token = SecretToken::parse(&encoded).map_err(|_| ManagementError::InvalidFrame)?;
        Self::new(public, token)
    }
    pub fn public(&self) -> &PublicFrame {
        &self.public
    }
    pub fn witness(&self) -> &BootstrapWitness {
        &self.witness
    }
    pub(crate) fn into_parts(self) -> (PublicFrame, SecretToken, BootstrapWitness) {
        (self.public, self.token, self.witness)
    }
}

pub enum ManagementRequest {
    Offer(HostOffer),
    Installed {
        public: PublicFrame,
        witness: BootstrapWitness,
    },
    /// wire JSON으로 만들 수 없는 native 교환의 내부 완료 관측이다.
    Finished(CompletedBootstrap),
}
pub struct CompletedBootstrap {
    witness: BootstrapWitness,
    delivered: bool,
    completed_at: Instant,
}
impl CompletedBootstrap {
    pub fn witness(&self) -> &BootstrapWitness {
        &self.witness
    }
    pub fn delivered(&self) -> bool {
        self.delivered
    }
    /// wire에 없는 monotonic 관측 시각. main loop의 처리 시각과 구분한다.
    pub fn completed_at(&self) -> Instant {
        self.completed_at
    }
}
impl ManagementRequest {
    pub fn installed(
        public: PublicFrame,
        witness: BootstrapWitness,
    ) -> Result<Self, ManagementError> {
        if public.kind() != ManagementKind::Installed || public.nonce() != witness.nonce() {
            return Err(ManagementError::WrongReply);
        }
        Ok(Self::Installed { public, witness })
    }
    fn witness(&self) -> &BootstrapWitness {
        match self {
            Self::Offer(offer) => offer.witness(),
            Self::Installed { witness, .. } => witness,
            Self::Finished(finished) => finished.witness(),
        }
    }
    fn expected_reply(&self) -> Option<ManagementKind> {
        match self {
            Self::Offer(_) => Some(ManagementKind::Authority),
            Self::Installed { .. } => Some(ManagementKind::Complete),
            Self::Finished(_) => None,
        }
    }
    fn check(&self) -> Result<(), ManagementError> {
        match self {
            Self::Offer(offer) if offer.public().kind() == ManagementKind::Offer => Ok(()),
            Self::Installed { public, witness }
                if public.kind() == ManagementKind::Installed
                    && public.nonce() == witness.nonce() =>
            {
                Ok(())
            }
            _ => Err(ManagementError::WrongReply),
        }
    }
}

fn new_request_id() -> Result<RequestId, ManagementError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ManagementError::EntropyUnavailable)?;
    let mut id = String::with_capacity(32);
    use fmt::Write as _;
    for byte in bytes {
        write!(id, "{byte:02x}").map_err(|_| ManagementError::EntropyUnavailable)?;
    }
    RequestId::new(id).map_err(|_| ManagementError::EntropyUnavailable)
}

#[derive(Clone)]
pub struct ManagementSender(SyncSender<ManagementEnvelope>);
pub struct ManagementReceiver(Receiver<ManagementEnvelope>);

pub fn management_channel() -> (ManagementSender, ManagementReceiver) {
    let (sender, receiver) = mpsc::sync_channel(1);
    (ManagementSender(sender), ManagementReceiver(receiver))
}

pub struct ManagementEnvelope {
    request: ManagementRequest,
    id: RequestId,
    budget: BootstrapBudget,
    responder: Option<ManagementResponder>,
}
impl ManagementEnvelope {
    pub fn id(&self) -> &RequestId {
        &self.id
    }
    pub fn witness(&self) -> &BootstrapWitness {
        self.request.witness()
    }
    pub fn budget(&self) -> &BootstrapBudget {
        &self.budget
    }
    pub fn into_parts(
        self,
    ) -> Result<(ManagementRequest, Option<ManagementResponder>), ManagementError> {
        // Finished is a revocation/retirement observation, not a fresh authority
        // request. Expiry/cancel/fatal must not discard the rollback event.
        if !matches!(self.request, ManagementRequest::Finished(_)) {
            self.responder
                .as_ref()
                .ok_or(ManagementError::InvalidFrame)?
                .check()?;
        }
        Ok((self.request, self.responder))
    }
}

struct ReplyEnvelope {
    id: RequestId,
    witness: RequestId,
    reply: Result<PublicFrame, ManagementError>,
}
pub struct ManagementResponder {
    sender: SyncSender<ReplyEnvelope>,
    id: RequestId,
    witness: BootstrapWitness,
    expected: ManagementKind,
    budget: BootstrapBudget,
    deadline: Instant,
}
impl ManagementResponder {
    /// Enqueue 시 계산한 정확한 application reply deadline이다.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn check(&self) -> Result<(), ManagementError> {
        self.budget.check()?;
        if Instant::now() >= self.deadline {
            Err(ManagementError::Deadline)
        } else {
            Ok(())
        }
    }
    pub fn respond(
        self,
        reply: Result<PublicFrame, ManagementError>,
    ) -> Result<(), ManagementError> {
        self.check()?;
        if reply.as_ref().is_ok_and(|frame| {
            frame.kind() != self.expected || frame.nonce() != self.witness.nonce()
        }) {
            return Err(ManagementError::WrongReply);
        }
        self.sender
            .try_send(ReplyEnvelope {
                id: self.id,
                witness: self.witness.id,
                reply,
            })
            .map_err(|_| ManagementError::Disconnected)
    }
}

pub struct PendingReply {
    receiver: Receiver<ReplyEnvelope>,
    id: RequestId,
    witness: BootstrapWitness,
    expected: ManagementKind,
    budget: BootstrapBudget,
    deadline: Instant,
    completed: bool,
}
impl PendingReply {
    pub fn wait(mut self) -> Result<PublicFrame, ManagementError> {
        loop {
            self.budget.check()?;
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .ok_or(ManagementError::Deadline)?;
            match self.receiver.recv_timeout(remaining.min(POLL_SLICE)) {
                Ok(reply) => {
                    self.budget.check()?;
                    if Instant::now() >= self.deadline {
                        return Err(ManagementError::Deadline);
                    }
                    if reply.id != self.id || reply.witness != self.witness.id {
                        return Err(ManagementError::WrongReply);
                    }
                    let frame = reply.reply?;
                    if frame.kind() != self.expected || frame.nonce() != self.witness.nonce() {
                        return Err(ManagementError::WrongReply);
                    }
                    self.completed = true;
                    return Ok(frame);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(ManagementError::Disconnected),
            }
        }
    }
}
impl Drop for PendingReply {
    fn drop(&mut self) {
        if !self.completed {
            self.budget.cancel();
        }
    }
}

impl ManagementSender {
    pub fn submit(
        &self,
        request: ManagementRequest,
        budget: &BootstrapBudget,
    ) -> Result<PendingReply, ManagementError> {
        if let Err(error) = request.check() {
            budget.cancel();
            return Err(error);
        }
        let deadline = budget.reply_deadline()?;
        let id = new_request_id()?;
        let witness = request.witness().clone();
        let expected = request
            .expected_reply()
            .ok_or(ManagementError::InvalidFrame)?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let responder = ManagementResponder {
            sender,
            id: id.clone(),
            witness: witness.clone(),
            expected,
            budget: budget.clone(),
            deadline,
        };
        match self.0.try_send(ManagementEnvelope {
            request,
            id: id.clone(),
            budget: budget.clone(),
            responder: Some(responder),
        }) {
            Ok(()) => Ok(PendingReply {
                receiver,
                id,
                witness,
                expected,
                budget: budget.clone(),
                deadline,
                completed: false,
            }),
            Err(TrySendError::Full(_)) => {
                budget.cancel();
                Err(ManagementError::Busy)
            }
            Err(TrySendError::Disconnected(_)) => {
                budget.cancel();
                Err(ManagementError::Disconnected)
            }
        }
    }
    /// verified native worker만 호출한다. delivered는 사용자 JSON/stdio의 bool이
    /// 아니며 Complete 전체 write + ACK terminal read + disconnect 관측 결과다.
    /// 통지 누락/Full이면 budget을 취소하여 main loop의 exact pending 만료도 촉진한다.
    pub(crate) fn notify_finished(
        &self,
        witness: &BootstrapWitness,
        delivered: bool,
        budget: &BootstrapBudget,
    ) -> Result<(), ManagementError> {
        // Native worker calls only after Complete whole-write, terminal ACK
        // read and server disconnect; failed paths carry false after their drain.
        let completed_at = Instant::now();
        let delivered = delivered && completed_at < budget.deadline() && budget.check().is_ok();
        if !delivered {
            budget.cancel();
        }
        let id = match new_request_id() {
            Ok(id) => id,
            Err(error) => {
                budget.cancel();
                return Err(error);
            }
        };
        let request = ManagementRequest::Finished(CompletedBootstrap {
            witness: witness.clone(),
            delivered,
            completed_at,
        });
        match self.0.try_send(ManagementEnvelope {
            request,
            id,
            budget: budget.clone(),
            responder: None,
        }) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                budget.cancel();
                Err(ManagementError::Busy)
            }
            Err(TrySendError::Disconnected(_)) => {
                budget.cancel();
                Err(ManagementError::Disconnected)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn offer(nonce: &str) -> HostOffer {
        let context =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/execution-context.json"))
                .unwrap();
        let hello = mmmm_contracts::parse_json(include_bytes!("../../../examples/host-hello.json"))
            .unwrap();
        let public = PublicFrame::from_value(json!({
            "kind":"host_pairing_offer", "protocolVersion":"0.2.0", "nonce":nonce,
            "hostHello":hello, "hostArtifactDigest":"0".repeat(64),
            "principalId":"principal-fixture", "playerId":"player-fixture",
            "playerContext":{
                "dimension":context["dimension"], "executorHandle":context["executorHandle"],
                "origin":context["origin"], "rotationDegrees":context["rotationDegrees"], "anchor":"feet"
            },
            "dataRoot":std::env::temp_dir().to_string_lossy(), "projectId":"project-fixture",
            "scope":context["scope"], "nativeActions":[]
        })).unwrap();
        HostOffer::new(public, SecretToken::parse(&"0".repeat(64)).unwrap()).unwrap()
    }
    fn authority(nonce: &str) -> PublicFrame {
        let context =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/execution-context.json"))
                .unwrap();
        PublicFrame::from_value(json!({
            "kind":"host_pairing_authority", "protocolVersion":"0.2.0", "nonce":nonce,
            "contexts":[context], "approvedSources":{"mmmm_host":"0".repeat(64)},
            "approvedActions":[], "permissions":["mmmm:world_read"], "writeProfileVerified":false
        }))
        .unwrap()
    }

    #[test]
    fn public_frames_reject_unknown_duplicate_secret_and_size_boundaries() {
        let host = offer("pair-fixture");
        let encoded = host.public().encode().unwrap();
        assert_eq!(
            public_length(encoded.length_prefix()).unwrap(),
            encoded.payload().len()
        );
        assert!(
            encoded
                .chunks()
                .all(|chunk| chunk.len() <= NATIVE_CHUNK_BYTES)
        );
        assert_eq!(
            PublicFrame::decode(encoded.payload()).unwrap().nonce(),
            "pair-fixture"
        );
        let mut injection = host.public().value().clone();
        injection["token"] = json!("forbidden-public-field");
        assert!(PublicFrame::from_value(injection).is_err());
        assert!(PublicFrame::decode(br#"{"kind":"host_pairing_installed","protocolVersion":"0.2.0","nonce":"pair-a","nonce":"pair-b","hostEndpoint":{"address":"127.0.0.1:32123","path":"/rpc","hostEpoch":"host-epoch"}}"#).is_err());
        assert_eq!(
            public_length(0_u32.to_be_bytes()),
            Err(ManagementError::FrameTooLarge)
        );
        assert_eq!(
            public_length((MAX_PUBLIC_BYTES as u32 + 1).to_be_bytes()),
            Err(ManagementError::FrameTooLarge)
        );
        let mut authority = authority("pair-fixture").into_value();
        authority["permissions"] = json!(["mmmm:world_write"]);
        assert!(PublicFrame::from_value(authority).is_err());
    }

    #[test]
    fn one_slot_channel_correlates_reply_and_cancels_abandoned_request() {
        let (sender, receiver) = management_channel();
        let budget = BootstrapBudget::new();
        let pending = sender
            .submit(ManagementRequest::Offer(offer("pair-fixture")), &budget)
            .unwrap();
        let busy_budget = BootstrapBudget::new();
        assert!(matches!(
            sender.submit(ManagementRequest::Offer(offer("pair-other")), &busy_budget),
            Err(ManagementError::Busy)
        ));
        assert_eq!(busy_budget.check(), Err(ManagementError::Cancelled));
        let envelope = receiver.try_receive().unwrap().unwrap();
        assert_eq!(envelope.witness().nonce(), "pair-fixture");
        let (_, responder) = envelope.into_parts().unwrap();
        responder
            .unwrap()
            .respond(Ok(authority("pair-fixture")))
            .unwrap();
        assert_eq!(pending.wait().unwrap().kind(), ManagementKind::Authority);
        assert!(budget.check().is_ok());
        let abandoned = sender
            .submit(ManagementRequest::Offer(offer("pair-abandoned")), &budget)
            .unwrap();
        drop(abandoned);
        assert_eq!(budget.check(), Err(ManagementError::Cancelled));
        assert!(
            receiver
                .try_receive()
                .unwrap()
                .unwrap()
                .into_parts()
                .is_err()
        );
    }
    #[test]
    fn internal_finished_is_received_after_cancel_without_a_wire_reply() {
        let (sender, receiver) = management_channel();
        let offered = offer("pair-finished");
        let witness = offered.witness().clone();
        let budget = BootstrapBudget::new();
        sender.notify_finished(&witness, false, &budget).unwrap();
        assert_eq!(budget.check(), Err(ManagementError::Cancelled));
        let (request, responder) = receiver
            .try_receive()
            .unwrap()
            .unwrap()
            .into_parts()
            .unwrap();
        assert!(responder.is_none());
        let ManagementRequest::Finished(finished) = request else {
            panic!("native finish kind differs");
        };
        assert!(!finished.delivered());
        assert_eq!(finished.witness().id(), witness.id());
        assert_eq!(finished.witness().offer_digest(), witness.offer_digest());
    }
}
impl ManagementReceiver {
    pub fn try_receive(&self) -> Result<Option<ManagementEnvelope>, ManagementError> {
        match self.0.try_recv() {
            Ok(envelope) => Ok(Some(envelope)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(ManagementError::Disconnected),
        }
    }
}

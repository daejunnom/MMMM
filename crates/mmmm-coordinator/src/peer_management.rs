//! 같은 OS 사용자로 확인된 peer의 호스트 연결 자료를 main loop에 전달한다.
//!
//! 이 모듈은 codec과 용량 1 채널만 소유한다. DB, 프로젝트 권한, 게임 관리자
//! 확인과 HostBridge 설치는 Coordinator의 단일 main loop가 수행한다. 공개
//! JSON과 32바이트 토큰은 별도로 전달하며 토큰을 JSON/debug 출력에 넣지 않는다.

use crate::credential::SecretToken;
use mmmm_contracts::{
    ContextId, ContractValidator, InstanceId, JsonLimits, NodeId, OperationId, PatchId, PlanId,
    PrincipalId, ProjectId, RequestId, ResourceId, ResourceLocation, SessionEpoch, Sha256Digest,
    SourceId, canonical_digest, parse_json_with_limits, verify_projected_digest,
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
pub(crate) const CALIBRATION_PLAN_PURPOSE: &str = "numeric_calibration_plan_normative47/1";
pub(crate) const MANUAL_SCENE_PURPOSE: &str = "manual_static_scene_import/1";
const POLL_SLICE: Duration = Duration::from_millis(20);
const MAX_COMPATIBILITY_APPROVALS: usize = 128;
const MAX_COMPATIBILITY_PROFILE_BYTES: usize = 65_536;
const MAX_COMPATIBILITY_PROFILE_TOTAL: usize = 256 * 1024;

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
        // Preserve a structured size failure before the strict parser's JSON
        // error is reduced to InvalidFrame. Optional trusted metadata may be
        // omitted only for actual global bounds, never malformed wire fields.
        let boundary = limits();
        let mut pending = vec![(&value, 0usize)];
        let mut nodes = 0usize;
        while let Some((current, depth)) = pending.pop() {
            nodes += 1;
            if nodes > boundary.max_nodes || depth > boundary.max_depth {
                return Err(ManagementError::FrameTooLarge);
            }
            let remaining = boundary.max_nodes - nodes - pending.len();
            match current {
                Value::Array(children) => {
                    if children.len() > remaining {
                        return Err(ManagementError::FrameTooLarge);
                    }
                    pending.extend(children.iter().map(|child| (child, depth + 1)));
                }
                Value::Object(children) => {
                    if children.len() > remaining {
                        return Err(ManagementError::FrameTooLarge);
                    }
                    pending.extend(children.values().map(|child| (child, depth + 1)));
                }
                _ => (),
            }
        }
        let mut writer = PublicWriter(Zeroizing::new(Vec::new()));
        serde_json::to_writer(&mut writer, &value).map_err(|_| ManagementError::FrameTooLarge)?;
        Self::decode_owned(writer.0)
    }
    pub fn kind(&self) -> ManagementKind {
        self.kind
    }
    pub(crate) fn is_calibration_owner_selection(&self) -> bool {
        self.value["kind"] == "native_calibration_owner_offer"
            || self.value["kind"] == "native_calibration_owner_selected"
    }
    pub(crate) fn is_calibration_plan(&self) -> bool {
        self.value["kind"] == "native_calibration_plan_offer"
            || self.value["kind"] == "native_calibration_plan_prepared"
    }
    pub(crate) fn is_manual_scene(&self) -> bool {
        self.value["kind"] == "native_manual_scene_offer"
            || self.value["kind"] == "native_manual_scene_prepared"
    }
    pub(crate) fn is_native_preparation(&self) -> bool {
        self.is_calibration_plan() || self.is_manual_scene()
    }
    pub(crate) fn is_native_owner_command(&self) -> bool {
        self.is_calibration_owner_selection() || self.is_native_preparation()
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
        "native_manual_scene_offer" => {
            exact(
                object,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "purpose",
                    "dataRoot",
                    "projectId",
                    "expectedRevision",
                    "contextId",
                    "selectionResourceId",
                    "sourceMapResourceId",
                    "editPayloadResourceId",
                    "sourceMapFile",
                    "editPayloadFile",
                    "allowedDeltas",
                ],
            )?;
            if text(value, "purpose")? != MANUAL_SCENE_PURPOSE {
                return Err(ManagementError::InvalidFrame);
            }
            // These local selectors are syntax only. The protected importer
            // owns bounded reads and all file/link/secret admission checks.
            for field in ["dataRoot", "sourceMapFile", "editPayloadFile"] {
                let path = text(value, field)?;
                if path.len() > 4096
                    || path.chars().any(char::is_control)
                    || !Path::new(path).is_absolute()
                {
                    return Err(ManagementError::InvalidFrame);
                }
            }
            ProjectId::new(text(value, "projectId")?).map_err(|_| ManagementError::InvalidFrame)?;
            ContextId::new(text(value, "contextId")?).map_err(|_| ManagementError::InvalidFrame)?;
            digest(text(value, "expectedRevision")?)?;
            let mut resources = BTreeSet::new();
            for field in [
                "selectionResourceId",
                "sourceMapResourceId",
                "editPayloadResourceId",
            ] {
                let resource = ResourceId::new(text(value, field)?)
                    .map_err(|_| ManagementError::InvalidFrame)?;
                if !resources.insert(resource) {
                    return Err(ManagementError::InvalidFrame);
                }
            }
            let deltas = array(value, "allowedDeltas")?;
            if deltas.len() > 256 {
                return Err(ManagementError::InvalidFrame);
            }
            let mut targets = BTreeSet::new();
            for delta in deltas {
                exact(
                    delta.as_object().ok_or(ManagementError::InvalidFrame)?,
                    &["instanceId", "nodeId", "kind"],
                )?;
                let instance = InstanceId::new(text(delta, "instanceId")?)
                    .map_err(|_| ManagementError::InvalidFrame)?;
                let node = NodeId::new(text(delta, "nodeId")?)
                    .map_err(|_| ManagementError::InvalidFrame)?;
                let kind = text(delta, "kind")?;
                if !matches!(
                    kind,
                    "create_node" | "update_transform" | "update_display" | "delete_node"
                ) || !targets.insert((instance, node, kind))
                {
                    return Err(ManagementError::InvalidFrame);
                }
            }
            Ok(ManagementKind::Offer)
        }
        "native_manual_scene_prepared" => {
            exact(
                object,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "projectId",
                    "patchId",
                    "resource",
                    "outcome",
                ],
            )?;
            if !matches!(
                text(value, "outcome")?,
                "prepared" | "committed_checkpoint_failed"
            ) {
                return Err(ManagementError::InvalidFrame);
            }
            ProjectId::new(text(value, "projectId")?).map_err(|_| ManagementError::InvalidFrame)?;
            PatchId::new(text(value, "patchId")?).map_err(|_| ManagementError::InvalidFrame)?;
            definition(validator, "ResourceRef", &value["resource"])?;
            Ok(ManagementKind::Authority)
        }
        "native_calibration_plan_offer" => {
            let purpose = text(value, "purpose")?;
            if purpose != CALIBRATION_PLAN_PURPOSE
                && !crate::calibration_bootstrap::is_purpose(purpose)
                && purpose != crate::calibration_pack_run::PURPOSE
            {
                return Err(ManagementError::InvalidFrame);
            }
            let mut fields = vec![
                "kind",
                "protocolVersion",
                "nonce",
                "purpose",
                "dataRoot",
                "projectId",
                "expectedRevision",
                "contextId",
            ];
            if purpose == crate::calibration_pack_run::PURPOSE {
                fields.push("originBootstrapOperation");
                OperationId::new(text(value, "originBootstrapOperation")?)
                    .map_err(|_| ManagementError::InvalidFrame)?;
            }
            exact(object, &fields)?;
            let root = text(value, "dataRoot")?;
            if root.len() > 4096
                || root.chars().any(char::is_control)
                || !Path::new(root).is_absolute()
            {
                return Err(ManagementError::InvalidFrame);
            }
            ProjectId::new(text(value, "projectId")?).map_err(|_| ManagementError::InvalidFrame)?;
            ContextId::new(text(value, "contextId")?).map_err(|_| ManagementError::InvalidFrame)?;
            digest(text(value, "expectedRevision")?)?;
            Ok(ManagementKind::Offer)
        }
        "native_calibration_plan_prepared" => {
            exact(
                object,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "purpose",
                    "projectId",
                    "planId",
                    "planHash",
                    "outcome",
                ],
            )?;
            let purpose = text(value, "purpose")?;
            if (purpose != CALIBRATION_PLAN_PURPOSE
                && !crate::calibration_bootstrap::is_purpose(purpose)
                && purpose != crate::calibration_pack_run::PURPOSE)
                || !matches!(
                    text(value, "outcome")?,
                    "prepared" | "committed_checkpoint_failed"
                )
            {
                return Err(ManagementError::InvalidFrame);
            }
            ProjectId::new(text(value, "projectId")?).map_err(|_| ManagementError::InvalidFrame)?;
            PlanId::new(text(value, "planId")?).map_err(|_| ManagementError::InvalidFrame)?;
            digest(text(value, "planHash")?)?;
            Ok(ManagementKind::Authority)
        }
        "native_calibration_owner_offer"
        | "native_calibration_owner_selected"
        | "host_apply_approval_offer"
        | "host_apply_approval_authority"
        | "host_apply_approval_installed"
        | "host_apply_approval_complete" => {
            if value["purpose"]
                .as_str()
                .is_some_and(crate::calibration_bootstrap::is_purpose)
            {
                crate::bootstrap::calibration_bootstrap_management::validate_frame(value, validator)
            } else {
                crate::bootstrap::calibration_approval::validate_frame(value, validator)
            }
        }
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
                    "compatibilityApprovals",
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
            unique_strings(array(value, "approvedActions")?, digest)?;
            validate_compatibility_approvals(&value["compatibilityApprovals"])?;
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

/// These bounded bytes are authenticated composition inputs to the host, not
/// approval issued by this codec. Native owner, Policy, exact source/CAS and
/// interface checks remain with their existing protected producers/consumers.
fn validate_compatibility_approvals(value: &Value) -> Result<(), ManagementError> {
    exact(
        value.as_object().ok_or(ManagementError::InvalidFrame)?,
        &["status", "reasonCode", "profiles"],
    )?;
    let profiles = array(value, "profiles")?;
    match text(value, "status")? {
        "available" if value["reasonCode"].is_null() => (),
        "unavailable"
            if value["reasonCode"] == "APPROVAL_SOURCE_UNAVAILABLE" && profiles.is_empty() => {}
        _ => return Err(ManagementError::InvalidFrame),
    }
    if profiles.len() > MAX_COMPATIBILITY_APPROVALS {
        return Err(ManagementError::InvalidFrame);
    }
    let mut references = BTreeSet::new();
    let mut bytes = 0usize;
    for profile in profiles {
        exact(
            profile.as_object().ok_or(ManagementError::InvalidFrame)?,
            &[
                "approvedProfileRef",
                "profileBytesHex",
                "profileDigest",
                "artifactDigest",
                "allowedInterfaceDigest",
            ],
        )?;
        let reference = text(profile, "approvedProfileRef")?;
        if reference.is_empty()
            || reference.len() > 256
            || !reference
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
            || !references.insert(reference)
        {
            return Err(ManagementError::InvalidFrame);
        }
        let raw = text(profile, "profileBytesHex")?;
        if raw.is_empty()
            || raw.len() > MAX_COMPATIBILITY_PROFILE_BYTES * 2
            || !raw.len().is_multiple_of(2)
            || !raw
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ManagementError::InvalidFrame);
        }
        bytes = bytes
            .checked_add(raw.len() / 2)
            .filter(|total| *total <= MAX_COMPATIBILITY_PROFILE_TOTAL)
            .ok_or(ManagementError::InvalidFrame)?;
        for key in ["profileDigest", "artifactDigest", "allowedInterfaceDigest"] {
            digest(text(profile, key)?)?;
        }
    }
    Ok(())
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
        Self::with_deadline(Instant::now() + BOOTSTRAP_LIMIT)
    }
    /// 이미 시작한 caller 마감을 유지한다. 생성 시 최대 30초로 한 번만
    /// 제한하며 각 전송/relay/drain 단계에서 전체 예산을 다시 시작하지 않는다.
    pub fn with_deadline(deadline: Instant) -> Self {
        Self {
            deadline: deadline.min(Instant::now() + BOOTSTRAP_LIMIT),
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
    pub(crate) fn cancellation_signal(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
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
    calibration_plan: bool,
    manual_scene: bool,
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
    pub(crate) fn is_calibration_plan(&self) -> bool {
        self.calibration_plan
    }
    pub(crate) fn is_manual_scene(&self) -> bool {
        self.manual_scene
    }
}

pub struct HostOffer {
    public: PublicFrame,
    token: Option<SecretToken>,
    witness: BootstrapWitness,
}
impl HostOffer {
    pub fn new(public: PublicFrame, token: SecretToken) -> Result<Self, ManagementError> {
        if public.kind() != ManagementKind::Offer || public.is_native_owner_command() {
            return Err(ManagementError::InvalidFrame);
        }
        Self::with_token(public, Some(token))
    }
    pub(crate) fn owner_selection(public: PublicFrame) -> Result<Self, ManagementError> {
        if public.kind() != ManagementKind::Offer || !public.is_calibration_owner_selection() {
            return Err(ManagementError::InvalidFrame);
        }
        Self::with_token(public, None)
    }
    pub(crate) fn calibration_plan(public: PublicFrame) -> Result<Self, ManagementError> {
        if public.kind() != ManagementKind::Offer || !public.is_calibration_plan() {
            return Err(ManagementError::InvalidFrame);
        }
        Self::with_token(public, None)
    }
    pub(crate) fn manual_scene(public: PublicFrame) -> Result<Self, ManagementError> {
        if public.kind() != ManagementKind::Offer || !public.is_manual_scene() {
            return Err(ManagementError::InvalidFrame);
        }
        Self::with_token(public, None)
    }
    fn with_token(
        public: PublicFrame,
        token: Option<SecretToken>,
    ) -> Result<Self, ManagementError> {
        let witness = BootstrapWitness {
            id: new_request_id()?,
            nonce: RequestId::new(public.nonce()).map_err(|_| ManagementError::InvalidFrame)?,
            offer_digest: canonical_digest(public.value())
                .map_err(|_| ManagementError::InvalidFrame)?,
            calibration_plan: public.is_calibration_plan(),
            manual_scene: public.is_manual_scene(),
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
    pub(crate) fn into_parts(self) -> (PublicFrame, Option<SecretToken>, BootstrapWitness) {
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
    failure: Option<crate::peer::PeerError>,
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
    pub(crate) fn failure(&self) -> Option<crate::peer::PeerError> {
        self.failure
    }
}
impl ManagementRequest {
    pub fn installed(
        public: PublicFrame,
        witness: BootstrapWitness,
    ) -> Result<Self, ManagementError> {
        if public.kind() != ManagementKind::Installed
            || public.nonce() != witness.nonce()
            || witness.is_manual_scene()
        {
            return Err(ManagementError::WrongReply);
        }
        Ok(Self::Installed { public, witness })
    }
    pub(crate) fn witness(&self) -> &BootstrapWitness {
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
                    && public.nonce() == witness.nonce()
                    && !witness.is_manual_scene() =>
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
        self.notify_finished_with_failure(witness, delivered, budget, None)
    }
    pub(crate) fn notify_finished_with_failure(
        &self,
        witness: &BootstrapWitness,
        delivered: bool,
        budget: &BootstrapBudget,
        failure: Option<crate::peer::PeerError>,
    ) -> Result<(), ManagementError> {
        // Native worker calls only after Complete whole-write, terminal ACK
        // read and server disconnect; failed paths carry false after their drain.
        let completed_at = Instant::now();
        let delivered = delivered
            && failure.is_none()
            && completed_at < budget.deadline()
            && budget.check().is_ok();
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
            failure,
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

impl ManagementReceiver {
    pub fn try_receive(&self) -> Result<Option<ManagementEnvelope>, ManagementError> {
        match self.0.try_recv() {
            Ok(envelope) => Ok(Some(envelope)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(ManagementError::Disconnected),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn calibration_owner_selection_has_closed_locator_grammar_and_no_host_token() {
        for purpose in [
            CALIBRATION_PLAN_PURPOSE,
            crate::calibration_bootstrap::PURPOSE,
            crate::calibration_bootstrap::PACK_PURPOSE,
            crate::calibration_pack_run::PURPOSE,
        ] {
            let mut planning = json!({"kind":"native_calibration_plan_offer","protocolVersion":"0.2.0","nonce":"plan-calibration",
            "purpose":purpose,"dataRoot":std::env::temp_dir(),"projectId":"project-fixture",
            "expectedRevision":"a".repeat(64),"contextId":"context-fixture"});
            if purpose == crate::calibration_pack_run::PURPOSE {
                planning["originBootstrapOperation"] = json!("operation-pack-bootstrap");
                let mut missing = planning.clone();
                missing
                    .as_object_mut()
                    .unwrap()
                    .remove("originBootstrapOperation");
                assert!(PublicFrame::from_value(missing).is_err());
                for origin in [json!(null), json!(true), json!(""), json!("../bootstrap")] {
                    let mut forged = planning.clone();
                    forged["originBootstrapOperation"] = origin;
                    assert!(PublicFrame::from_value(forged).is_err());
                }
                let first =
                    HostOffer::calibration_plan(PublicFrame::from_value(planning.clone()).unwrap())
                        .unwrap();
                let mut changed = planning.clone();
                changed["originBootstrapOperation"] = json!("other-pack-bootstrap");
                let second =
                    HostOffer::calibration_plan(PublicFrame::from_value(changed).unwrap()).unwrap();
                assert_ne!(
                    first.witness().offer_digest(),
                    second.witness().offer_digest()
                );
            } else {
                let mut forged = planning.clone();
                forged["originBootstrapOperation"] = json!("operation-pack-bootstrap");
                assert!(PublicFrame::from_value(forged).is_err());
            }
            let plan_offer =
                HostOffer::calibration_plan(PublicFrame::from_value(planning.clone()).unwrap())
                    .unwrap();
            assert!(plan_offer.into_parts().1.is_none());
            assert!(
                HostOffer::new(
                    PublicFrame::from_value(planning.clone()).unwrap(),
                    SecretToken::generate().unwrap()
                )
                .is_err()
            );
            assert!(
                HostOffer::owner_selection(PublicFrame::from_value(planning.clone()).unwrap())
                    .is_err()
            );
            for field in [
                "principalId",
                "admin",
                "plan",
                "recipe",
                "sources",
                "expectedValues",
                "verifiedWriteProfile",
            ] {
                let mut forged = planning.clone();
                forged[field] = json!(true);
                assert!(PublicFrame::from_value(forged).is_err());
            }
            for (field, replacement) in [
                ("purpose", json!("world_write")),
                ("purpose", json!("pack_calibration_bootstrap/2")),
                ("purpose", json!("pack_calibration_run/2")),
                ("expectedRevision", json!("A".repeat(64))),
                ("dataRoot", json!("relative")),
                ("contextId", json!("")),
                ("protocolVersion", json!("0.1.0")),
            ] {
                let mut forged = planning.clone();
                forged[field] = replacement;
                assert!(PublicFrame::from_value(forged).is_err());
            }
            let mut prepared = json!({"kind":"native_calibration_plan_prepared","protocolVersion":"0.2.0","nonce":"plan-calibration",
            "purpose":purpose,"projectId":"project-fixture","planId":"plan-fixture","planHash":"b".repeat(64),"outcome":"prepared"});
            assert!(
                PublicFrame::from_value(prepared.clone())
                    .unwrap()
                    .is_calibration_plan()
            );
            prepared["outcome"] = json!("committed_checkpoint_failed");
            assert!(PublicFrame::from_value(prepared.clone()).is_ok());
            prepared["outcome"] = json!("rollback_complete");
            assert!(PublicFrame::from_value(prepared).is_err());
        }
        for purpose in [
            crate::bootstrap::calibration_approval::PURPOSE,
            crate::calibration_pack_run::PURPOSE,
        ] {
            let value = json!({"kind":"native_calibration_owner_offer","protocolVersion":"0.2.0","nonce":"owner-calibration",
            "purpose":purpose,"dataRoot":std::env::temp_dir(),
            "projectId":"project-fixture","planId":"plan-fixture","planHash":"a".repeat(64)});
            let owner = HostOffer::owner_selection(PublicFrame::from_value(value.clone()).unwrap())
                .unwrap();
            assert!(owner.into_parts().1.is_none());
            assert!(
                HostOffer::new(
                    PublicFrame::from_value(value.clone()).unwrap(),
                    SecretToken::generate().unwrap()
                )
                .is_err()
            );
            for field in [
                "principalId",
                "admin",
                "verifiedWriteProfile",
                "manifest",
                "capability",
            ] {
                let mut forged = value.clone();
                forged[field] = json!(true);
                assert!(PublicFrame::from_value(forged).is_err());
            }
            let mut wrong = value.clone();
            wrong["purpose"] = json!("world_write");
            assert!(PublicFrame::from_value(wrong).is_err());
            let mut wrong = value.clone();
            wrong["planHash"] = json!("A".repeat(64));
            assert!(PublicFrame::from_value(wrong).is_err());
            let mut wrong = value;
            wrong["dataRoot"] = json!("relative");
            assert!(PublicFrame::from_value(wrong).is_err());
        }
        let duplicate=br#"{"kind":"native_calibration_owner_offer","protocolVersion":"0.2.0","nonce":"one","nonce":"two","purpose":"numeric_calibration_normative47/1","dataRoot":"/tmp","projectId":"project-fixture","planId":"plan-fixture","planHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        assert!(PublicFrame::decode(duplicate).is_err());
    }

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
            "approvedActions":[], "permissions":["mmmm:world_read"], "writeProfileVerified":false,
            "compatibilityApprovals":{"status":"available","reasonCode":null,"profiles":[]}
        }))
        .unwrap()
    }

    #[test]
    fn caller_absolute_deadline_is_kept_and_future_deadline_is_capped_once() {
        let deadline = Instant::now() + Duration::from_secs(2);
        let budget = BootstrapBudget::with_deadline(deadline);
        assert_eq!(budget.deadline(), deadline);
        assert!(budget.native_io_deadline().unwrap() <= deadline);
        assert!(budget.application_wait_deadline().unwrap() <= deadline);
        let before = Instant::now();
        let capped = BootstrapBudget::with_deadline(before + Duration::from_secs(300));
        assert!(capped.deadline() <= Instant::now() + BOOTSTRAP_LIMIT);
        assert!(capped.deadline() < before + Duration::from_secs(300));
        let expired = BootstrapBudget::with_deadline(before);
        assert_eq!(expired.deadline(), before);
        assert_eq!(expired.check(), Err(ManagementError::Deadline));
        assert_eq!(expired.native_io_deadline(), Err(ManagementError::Deadline));
        let stopped = crate::service::RequestBudget::from_bootstrap(&expired)
            .err()
            .unwrap();
        assert_eq!(stopped.code, "TIME_BUDGET_EXCEEDED");
        assert!(matches!(
            std::error::Error::source(&stopped)
                .and_then(|cause| cause.downcast_ref::<ManagementError>()),
            Some(ManagementError::Deadline)
        ));

        let request = crate::service::RequestBudget::from_bootstrap(&budget).unwrap();
        let retained = request.clone();
        assert_eq!(request.deadline(), deadline);
        assert_eq!(retained.deadline(), deadline);
        assert!(std::ptr::eq(
            request.cancellation(),
            budget.cancelled.as_ref()
        ));
        budget.cancel();
        for derived in [&request, &retained] {
            let stopped = derived.check().err().unwrap();
            assert_eq!(stopped.code, "CANCELLED");
            assert!(matches!(
                std::error::Error::source(&stopped)
                    .and_then(|cause| cause.downcast_ref::<ManagementError>()),
                Some(ManagementError::Cancelled)
            ));
        }
        assert!(crate::service::RequestBudget::from_bootstrap(&budget).is_err());

        let stop = Arc::new(AtomicBool::new(false));
        let peer = BootstrapBudget::for_peer(Instant::now(), stop.clone());
        let request = crate::service::RequestBudget::from_bootstrap(&peer).unwrap();
        assert_eq!(request.deadline(), peer.deadline());
        stop.store(true, Ordering::Release);
        assert!(!request.cancellation().load(Ordering::Acquire));
        let stopped = request.check().err().unwrap();
        assert_eq!(stopped.code, "CANCELLED");
        assert!(matches!(
            std::error::Error::source(&stopped)
                .and_then(|cause| cause.downcast_ref::<ManagementError>()),
            Some(ManagementError::Cancelled)
        ));
        assert!(crate::service::RequestBudget::from_bootstrap(&peer).is_err());
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

    fn compatibility_profile(reference: &str, bytes: usize) -> Value {
        // Codec fixture only: these bytes/pins issue no native-owner approval,
        // actual Java observation, registration or execution grant.
        json!({"approvedProfileRef":reference,"profileBytesHex":"00".repeat(bytes),
            "profileDigest":"a".repeat(64),"artifactDigest":"b".repeat(64),
            "allowedInterfaceDigest":"c".repeat(64)})
    }
    fn compatibility_authority(profiles: Vec<Value>) -> Value {
        let mut value = authority("pair-compatibility-fixture").into_value();
        value["compatibilityApprovals"]["profiles"] = json!(profiles);
        value
    }

    #[test]
    fn compatibility_approval_frame_requires_closed_explicit_status_and_profile_fields() {
        let available =
            compatibility_authority(vec![compatibility_profile("approval:Scalar_v1", 1)]);
        assert!(PublicFrame::from_value(available.clone()).is_ok());
        let mut unavailable = compatibility_authority(Vec::new());
        unavailable["compatibilityApprovals"] = json!({"status":"unavailable",
            "reasonCode":"APPROVAL_SOURCE_UNAVAILABLE","profiles":[]});
        assert!(PublicFrame::from_value(unavailable).is_ok());
        for invalid in [
            Value::Null,
            json!([]),
            json!({}),
            json!({"status":"available","profiles":[]}),
            json!({"status":"available","reasonCode":null,"profiles":[],"approved":true}),
            json!({"status":"available","reasonCode":"APPROVAL_SOURCE_UNAVAILABLE","profiles":[]}),
            json!({"status":"unavailable","reasonCode":null,"profiles":[]}),
            json!({"status":"unavailable","reasonCode":"OTHER_REASON","profiles":[]}),
            json!({"status":"unknown","reasonCode":null,"profiles":[]}),
            json!({"status":"unavailable","reasonCode":"APPROVAL_SOURCE_UNAVAILABLE",
                "profiles":[compatibility_profile("approval-one", 1)]}),
        ] {
            let mut value = available.clone();
            value["compatibilityApprovals"] = invalid;
            assert!(PublicFrame::from_value(value).is_err());
        }
        let mut omitted = available.clone();
        omitted
            .as_object_mut()
            .unwrap()
            .remove("compatibilityApprovals");
        assert!(PublicFrame::from_value(omitted).is_err());
        for key in [
            "approvedProfileRef",
            "profileBytesHex",
            "profileDigest",
            "artifactDigest",
            "allowedInterfaceDigest",
        ] {
            let mut value = available.clone();
            value["compatibilityApprovals"]["profiles"][0]
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(PublicFrame::from_value(value).is_err());
        }
        let mut injection = available;
        injection["compatibilityApprovals"]["profiles"][0]["nativeOwner"] = json!("claimed-owner");
        assert!(PublicFrame::from_value(injection).is_err());
    }

    #[test]
    fn compatibility_approval_frame_bounds_unique_references_lower_hex_and_profile_bytes() {
        let profile = compatibility_profile("approval-one", 1);
        assert!(
            PublicFrame::from_value(compatibility_authority(vec![
                profile.clone(),
                profile.clone()
            ]))
            .is_err()
        );
        for invalid in [
            "",
            "approval with space",
            "approval/slash",
            "승인",
            "approval\nline",
        ] {
            let mut changed = profile.clone();
            changed["approvedProfileRef"] = json!(invalid);
            assert!(PublicFrame::from_value(compatibility_authority(vec![changed])).is_err());
        }
        let mut changed = profile.clone();
        changed["approvedProfileRef"] = json!("a".repeat(257));
        assert!(PublicFrame::from_value(compatibility_authority(vec![changed])).is_err());
        for invalid in [
            Value::Null,
            json!(1),
            json!(""),
            json!("0"),
            json!("0A"),
            json!("gg"),
            json!("００"),
        ] {
            let mut changed = profile.clone();
            changed["profileBytesHex"] = invalid;
            assert!(PublicFrame::from_value(compatibility_authority(vec![changed])).is_err());
        }
        for key in ["profileDigest", "artifactDigest", "allowedInterfaceDigest"] {
            for invalid in [
                Value::Null,
                json!(1),
                json!("a".repeat(63)),
                json!("A".repeat(64)),
                json!("g".repeat(64)),
            ] {
                let mut changed = profile.clone();
                changed[key] = invalid;
                assert!(PublicFrame::from_value(compatibility_authority(vec![changed])).is_err());
            }
        }
        let selected = (0..MAX_COMPATIBILITY_APPROVALS)
            .map(|index| compatibility_profile(&format!("approval-{index}"), 1))
            .collect::<Vec<_>>();
        assert!(PublicFrame::from_value(compatibility_authority(selected.clone())).is_ok());
        let mut too_many = selected;
        too_many.push(compatibility_profile("approval-over-limit", 1));
        assert!(PublicFrame::from_value(compatibility_authority(too_many)).is_err());
        assert!(
            PublicFrame::from_value(compatibility_authority(vec![compatibility_profile(
                "approval-max",
                MAX_COMPATIBILITY_PROFILE_BYTES
            )]))
            .is_ok()
        );
        assert!(
            PublicFrame::from_value(compatibility_authority(vec![compatibility_profile(
                "approval-too-large",
                MAX_COMPATIBILITY_PROFILE_BYTES + 1
            )]))
            .is_err()
        );
        let at_limit = (0..4)
            .map(|index| {
                compatibility_profile(
                    &format!("approval-total-{index}"),
                    MAX_COMPATIBILITY_PROFILE_BYTES,
                )
            })
            .collect::<Vec<_>>();
        assert!(PublicFrame::from_value(compatibility_authority(at_limit.clone())).is_ok());
        let mut over_limit = at_limit;
        over_limit.push(compatibility_profile("approval-extra-byte", 1));
        assert!(PublicFrame::from_value(compatibility_authority(over_limit)).is_err());
        assert_eq!(limits().max_bytes, 1024 * 1024);
        assert_eq!(limits().max_nodes, 4096);
        // Every member is individually valid and the basic native reply fits.
        // Adding a valid optional map must retain a typed global node failure
        // so the pairing producer can omit the whole map instead of failing
        // native pairing or masking malformed fields.
        let mut base = compatibility_authority(Vec::new());
        base["contexts"][0]["scope"]["resourceIds"] = json!(
            (0..3300)
                .map(|index| format!("resource-node-{index}"))
                .collect::<Vec<_>>()
        );
        base["contexts"][0]["contextDigest"] = json!(
            mmmm_contracts::projected_digest("ExecutionContext", &base["contexts"][0]).unwrap()
        );
        assert!(PublicFrame::from_value(base.clone()).is_ok());
        base["compatibilityApprovals"]["profiles"] = json!(
            (0..128)
                .map(|index| compatibility_profile(&format!("approval-node-{index}"), 1))
                .collect::<Vec<_>>()
        );
        assert!(matches!(
            PublicFrame::from_value(base),
            Err(ManagementError::FrameTooLarge)
        ));
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

use crate::{
    credential::{CredentialRef, CredentialStore, SecretToken},
    endpoint::{EndpointRecord, RuntimeDirectory},
    http::{content_length, parse_headers, read_header, read_response_body, write_deadline},
    rpc::MAX_CONTROL_BYTES,
};
use mmmm_contracts::{ContractValidator, JsonLimits, encode_json, parse_json_with_limits};
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum ClientError {
    Discovery,
    Authentication,
    InvalidInput,
    InvalidResponse,
    Unavailable,
    LocalTransportUncertain,
    /// Bytes may have reached the service. This never authorizes an automatic
    /// resend, new idempotency key, fallback endpoint, or rollback success.
    DeliveryUnknown,
    Remote {
        code: i64,
        message: String,
        application_code: Option<String>,
    },
}
impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discovery => f.write_str("No valid private Coordinator endpoint is available"),
            Self::Authentication => f.write_str("Local Coordinator authentication failed"),
            Self::InvalidInput => f.write_str("Input violates the canonical function contract"),
            Self::InvalidResponse => f.write_str("Coordinator response violates the expected contract; a write result requires durable operation inspection"),
            Self::Unavailable => f.write_str("The published Coordinator endpoint is unavailable"),
            Self::LocalTransportUncertain => f.write_str("Native local authentication transport completion is unresolved; no new request is admitted"),
            Self::DeliveryUnknown => f.write_str("Request delivery or result is unknown; inspect the durable operation before retrying a write"),
            Self::Remote { application_code, message, .. } => write!(f, "{}: {}", application_code.as_deref().unwrap_or("SERVICE_ERROR"), message),
        }
    }
}
impl std::error::Error for ClientError {}

pub struct CoordinatorClient {
    endpoint: EndpointRecord,
    token: SecretToken,
    timeout: Duration,
}
impl CoordinatorClient {
    pub fn discover(
        runtime_directory: &Path,
        credentials: &dyn CredentialStore,
    ) -> Result<Self, ClientError> {
        let runtime =
            RuntimeDirectory::open(runtime_directory).map_err(|_| ClientError::Discovery)?;
        let endpoint = runtime.load().map_err(|_| ClientError::Discovery)?;
        let reference =
            CredentialRef::new(&endpoint.credential_ref).map_err(|_| ClientError::Discovery)?;
        let token = credentials
            .get(&reference)
            .map_err(|_| ClientError::Authentication)?;
        Self::paired(endpoint, token)
    }
    pub fn discover_peer(runtime_directory: &Path) -> Result<Self, ClientError> {
        let runtime =
            RuntimeDirectory::open(runtime_directory).map_err(|_| ClientError::Discovery)?;
        let endpoint = runtime.load().map_err(|_| ClientError::Discovery)?;
        let reference =
            CredentialRef::new(&endpoint.credential_ref).map_err(|_| ClientError::Discovery)?;
        let token = crate::peer::PeerBootstrap::connect(runtime.path(), &reference)
            .map_err(|_| ClientError::Authentication)?;
        Self::paired(endpoint, token)
    }
    /// Used by trusted out-of-band composition (including a parent-launched
    /// facade). There is no public JSON-RPC method that issues capabilities.
    pub fn paired(endpoint: EndpointRecord, token: SecretToken) -> Result<Self, ClientError> {
        if endpoint.schema_version != 1
            || endpoint.contract_version != mmmm_contracts::CONTRACT_VERSION
            || endpoint.address.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)
            || endpoint.address.port() == 0
            || endpoint.path != "/rpc"
            || mmmm_contracts::SessionEpoch::new(&endpoint.coordinator_epoch).is_err()
            || CredentialRef::new(&endpoint.credential_ref).is_err()
        {
            return Err(ClientError::Discovery);
        }
        Ok(Self {
            endpoint,
            token,
            timeout: Duration::from_secs(35),
        })
    }
    pub fn address(&self) -> SocketAddr {
        self.endpoint.address
    }
    pub fn call(&self, method: &str, input: &Value) -> Result<Value, ClientError> {
        let validator = ContractValidator::shared().map_err(|_| ClientError::InvalidInput)?;
        let function = validator
            .function(method)
            .map_err(|_| ClientError::InvalidInput)?;
        if function.name != method || validator.validate(&function.input, input).is_err() {
            return Err(ClientError::InvalidInput);
        }
        let mut request_nonce = [0u8; 16];
        getrandom::fill(&mut request_nonce).map_err(|_| ClientError::Unavailable)?;
        let id: String = request_nonce.iter().map(|b| format!("{b:02x}")).collect();
        let result = self.raw_call(method, &id, input, self.timeout)?;
        validator
            .validate(&function.output, &result)
            .map_err(|_| ClientError::InvalidResponse)?;
        Ok(result)
    }
    fn raw_call(
        &self,
        method: &str,
        id: &str,
        input: &Value,
        timeout: Duration,
    ) -> Result<Value, ClientError> {
        if crate::peer::fatal_stop_requested() {
            return Err(ClientError::LocalTransportUncertain);
        }
        let request = encode_json(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":input}))
            .map_err(|_| ClientError::InvalidInput)?;
        if request.len() > MAX_CONTROL_BYTES {
            return Err(ClientError::InvalidInput);
        }
        if timeout.is_zero() {
            return Err(ClientError::Unavailable);
        }
        let deadline = Instant::now() + timeout;
        let mut stream =
            TcpStream::connect_timeout(&self.endpoint.address, timeout.min(Duration::from_secs(2)))
                .map_err(|_| ClientError::Unavailable)?;
        stream
            .set_nodelay(true)
            .map_err(|_| ClientError::Unavailable)?;
        let bearer = self.token.bearer();
        let header = Zeroizing::new(format!(
            "POST /rpc HTTP/1.1\r\nHost: {}\r\nX-MMMM-Epoch: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.endpoint.address,
            self.endpoint.coordinator_epoch,
            bearer.as_str(),
            request.len()
        ));
        // From the first write onward, any transport failure is ambiguous.
        if crate::peer::fatal_stop_requested() {
            return Err(ClientError::LocalTransportUncertain);
        }
        write_deadline(&mut stream, header.as_bytes(), deadline)
            .map_err(|_| ClientError::DeliveryUnknown)?;
        write_deadline(&mut stream, &request, deadline)
            .map_err(|_| ClientError::DeliveryUnknown)?;
        let raw_headers = read_header(&mut stream, deadline, &AtomicBool::new(false))
            .map_err(|_| ClientError::DeliveryUnknown)?;
        let text = std::str::from_utf8(&raw_headers).map_err(|_| ClientError::InvalidResponse)?;
        let (status, headers) = parse_headers(text).map_err(|_| ClientError::InvalidResponse)?;
        if status == "HTTP/1.1 401 Unauthorized" {
            return Err(ClientError::Authentication);
        }
        if status != "HTTP/1.1 200 OK"
            || headers.contains_key("transfer-encoding")
            || headers.contains_key("content-encoding")
            || headers.get("content-type").map(|s| s.as_str()) != Some("application/json")
            || headers.get("connection").map(|s| s.as_str()) != Some("close")
        {
            return Err(ClientError::InvalidResponse);
        }
        let length = content_length(&headers).map_err(|_| ClientError::InvalidResponse)?;
        let bytes = read_response_body(&mut stream, length, deadline)
            .map_err(|_| ClientError::DeliveryUnknown)?;
        let response = parse_json_with_limits(
            &bytes,
            JsonLimits {
                max_bytes: MAX_CONTROL_BYTES,
                max_depth: 64,
                max_nodes: 4096,
            },
        )
        .map_err(|_| ClientError::InvalidResponse)?;
        let object = response.as_object().ok_or(ClientError::InvalidResponse)?;
        if object.len() != 3
            || object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || object.get("id").and_then(Value::as_str) != Some(id)
        {
            return Err(ClientError::InvalidResponse);
        }
        if let Some(result) = object.get("result") {
            Ok(result.clone())
        } else if let Some(error) = object.get("error") {
            let error = error.as_object().ok_or(ClientError::InvalidResponse)?;
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .ok_or(ClientError::InvalidResponse)?;
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .filter(|s| s.len() <= 256)
                .ok_or(ClientError::InvalidResponse)?
                .to_owned();
            let application_code = error
                .get("data")
                .and_then(|d| d.get("code"))
                .and_then(Value::as_str)
                .filter(|s| s.len() <= 64)
                .map(str::to_owned);
            Err(ClientError::Remote {
                code,
                message,
                application_code,
            })
        } else {
            Err(ClientError::InvalidResponse)
        }
    }
}

/// Paired Java/tool host calls use the same bounded authenticated HTTP framing,
/// with the original exact HostRequest/HostResponse 0.2.0 contract. This is an
/// outgoing host connection, not a public authoring-facade method registration.
pub struct HostRpcClient(CoordinatorClient);
impl HostRpcClient {
    pub fn paired(endpoint: EndpointRecord, token: SecretToken) -> Result<Self, ClientError> {
        Ok(Self(CoordinatorClient::paired(endpoint, token)?))
    }
    pub fn call(&self, request: &Value) -> Result<Value, ClientError> {
        let validator = ContractValidator::shared().map_err(|_| ClientError::InvalidInput)?;
        validator
            .validate("HostRequest", request)
            .map_err(|_| ClientError::InvalidInput)?;
        let id = request["requestId"]
            .as_str()
            .ok_or(ClientError::InvalidInput)?;
        let expires = time::OffsetDateTime::parse(
            request["deadlineAt"]
                .as_str()
                .ok_or(ClientError::InvalidInput)?,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| ClientError::InvalidInput)?;
        let remaining = (expires - time::OffsetDateTime::now_utc()).whole_nanoseconds();
        if remaining <= 0 {
            return Err(ClientError::Unavailable);
        }
        let timeout = Duration::from_nanos(remaining.min(35_000_000_000) as u64);
        let response = self.0.raw_call("mmmm.host", id, request, timeout)?;
        validator
            .validate("HostResponse", &response)
            .map_err(|_| ClientError::InvalidResponse)?;
        if response["requestId"] != request["requestId"] {
            return Err(ClientError::InvalidResponse);
        }
        Ok(response)
    }
}

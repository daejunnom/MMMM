//! MCP 2025-11-25 facade. rmcp owns protocol dispatch; the canonical contract
//! owns DTO validation and the Coordinator owns every operation and world effect.
//! This module never opens the application store or creates a second journal.
//!
//! Profile references: modelcontextprotocol.io/specification/2025-11-25/
//! {basic/lifecycle,basic/transports,server/tools,server/resources,server/utilities/pagination}.
//! SDK API is pinned to modelcontextprotocol/rust-sdk tag rmcp-v3.5.1.

use mmmm_contracts::{
    CANONICAL_SCHEMA, ContextId, ContractValidator, FUNCTION_INDEX, FunctionContract, JsonLimits,
    ResourceId, ResourceLocation, Sha256Digest, SnapshotId, UnsignedDecimal, encode_json,
    parse_json, parse_json_with_limits, raw_digest,
};
use mmmm_coordinator::{CoordinatorClient, client::ClientError};
use rmcp::{
    ErrorData, ServerHandler, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorCode,
        Implementation, ListResourceTemplatesResult, ListResourcesResult, ListToolsResult,
        PaginatedRequestParams, ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse,
        ReadResourceResult, ResourceContents, ResourceTemplate, ServerCapabilities, ServerConfig,
        Tool,
    },
    service::{RequestContext, RoleServer, RxJsonRpcMessage, TxJsonRpcMessage},
    transport::Transport,
};
use serde_json::{Map, Value, json};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    path::Path,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_FRAME_NODES: usize = 4096;
const MAX_REQUESTS: usize = 4;
const MAX_SESSION_FRAMES: usize = 4096;
const MAX_PAGE_TOOLS: usize = 4;
const MAX_ARTIFACT_SLICE: u64 = 65_536;
const ARTIFACT_URI_PREFIX: &str = "mmmm://artifact/";
const ARTIFACT_URI_TEMPLATE: &str =
    "mmmm://artifact/{+contextId}/{+resourceId}/{sha256}/{offset}/{limitBytes}";
const CATALOG_URI_PREFIX: &str = "mmmm://catalog/";
const CATALOG_URI_TEMPLATE: &str =
    "mmmm://catalog/{+snapshotId}/{kind}/{resourceId}?contextId={+contextId}";
const SESSION_LIFETIME: Duration = Duration::from_secs(30 * 60);
const READ_IDLE: Duration = Duration::from_secs(300);
const WRITE_DEADLINE: Duration = Duration::from_secs(5);
const INITIALIZE_DEADLINE: Duration = Duration::from_secs(30);
const CALL_DEADLINE: Duration = Duration::from_secs(40);
const DRAIN_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FacadeError {
    Io,
    InputFrame,
    OutputFrame,
    Initialization,
    SessionExpired,
    Shutdown,
    Catalog,
    Runtime,
}
impl fmt::Display for FacadeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Io => "MCP standard I/O failed or exceeded its finite deadline",
            Self::InputFrame => "MCP input violated the bounded JSON-RPC profile",
            Self::OutputFrame => "MCP response exceeded the bounded wire profile",
            Self::Initialization => "MCP initialization or local Coordinator authentication failed",
            Self::SessionExpired => "MCP session reached its finite lifetime or frame limit",
            Self::Shutdown => "MCP facade cleanup did not confirm all owned workers stopped",
            Self::Catalog => "The canonical MCP tool catalog could not be prepared",
            Self::Runtime => "The MCP protocol runtime failed",
        })
    }
}
impl std::error::Error for FacadeError {}

pub type IoFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, FacadeError>> + Send + 'a>>;

/// A native port must enforce deadlines, cancellation and bounded buffers itself.
/// Frames exclude the LF terminator; write_line appends exactly one LF. Success
/// from cancel_and_drain proves every owned I/O worker/process/thread is gone.
/// A dropped future must leave its work cancelable by cancel_and_drain.
pub trait FiniteIoPort: Send + Sync + 'static {
    fn read_line(
        &self,
        deadline: Instant,
        cancel: Arc<AtomicBool>,
    ) -> IoFuture<'_, Option<Vec<u8>>>;
    fn write_line(
        &self,
        line: Vec<u8>,
        deadline: Instant,
        cancel: Arc<AtomicBool>,
    ) -> IoFuture<'_, ()>;
    fn cancel_and_drain(&self, deadline: Instant) -> IoFuture<'_, ()>;
    /// Last-resort finite cleanup if the async runtime cannot be constructed.
    fn force_cancel_and_drain(&self, deadline: Instant) -> Result<(), FacadeError>;
}

impl FiniteIoPort for mmmm_coordinator::stdio_io::NativeStdioPort {
    fn read_line(
        &self,
        deadline: Instant,
        cancel: Arc<AtomicBool>,
    ) -> IoFuture<'_, Option<Vec<u8>>> {
        Box::pin(async move {
            loop {
                match self
                    .poll_read_line(deadline, cancel.as_ref())
                    .map_err(|_| FacadeError::Io)?
                {
                    std::task::Poll::Ready(line) => return Ok(line),
                    std::task::Poll::Pending => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        })
    }
    fn write_line(
        &self,
        line: Vec<u8>,
        deadline: Instant,
        cancel: Arc<AtomicBool>,
    ) -> IoFuture<'_, ()> {
        Box::pin(async move {
            loop {
                match self
                    .poll_write_line(&line, deadline, cancel.as_ref())
                    .map_err(|_| FacadeError::Io)?
                {
                    std::task::Poll::Ready(()) => return Ok(()),
                    std::task::Poll::Pending => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        })
    }
    fn cancel_and_drain(&self, deadline: Instant) -> IoFuture<'_, ()> {
        Box::pin(async move {
            loop {
                match self
                    .poll_cancel_and_drain(deadline)
                    .map_err(|_| FacadeError::Shutdown)?
                {
                    std::task::Poll::Ready(_) => return Ok(()),
                    std::task::Poll::Pending => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        })
    }
    fn force_cancel_and_drain(&self, deadline: Instant) -> Result<(), FacadeError> {
        loop {
            if Instant::now() >= deadline {
                return Err(FacadeError::Shutdown);
            }
            match self
                .poll_cancel_and_drain(deadline)
                .map_err(|_| FacadeError::Shutdown)?
            {
                std::task::Poll::Ready(_) => return Ok(()),
                std::task::Poll::Pending => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    }
}

async fn io_read(
    io: &dyn FiniteIoPort,
    deadline: Instant,
    cancel: Arc<AtomicBool>,
) -> Result<Option<Vec<u8>>, FacadeError> {
    tokio::time::timeout_at(deadline.into(), io.read_line(deadline, cancel))
        .await
        .map_err(|_| FacadeError::Io)?
}
async fn io_write(
    io: &dyn FiniteIoPort,
    line: Vec<u8>,
    deadline: Instant,
    cancel: Arc<AtomicBool>,
    output: &Semaphore,
) -> Result<(), FacadeError> {
    // rmcp permits concurrent send futures. The permit covers the entire
    // native OUTPUT transaction, including its post-flush ACK. Queue and write
    // share one absolute deadline, including malformed-input rejection frames.
    let _permit = tokio::time::timeout_at(deadline.into(), output.acquire())
        .await
        .map_err(|_| FacadeError::Io)?
        .map_err(|_| FacadeError::Io)?;
    if cancel.load(Ordering::Acquire) {
        return Err(FacadeError::Io);
    }
    tokio::time::timeout_at(deadline.into(), io.write_line(line, deadline, cancel))
        .await
        .map_err(|_| FacadeError::Io)?
}
async fn io_drain(io: &dyn FiniteIoPort) -> Result<(), FacadeError> {
    let deadline = Instant::now() + DRAIN_DEADLINE;
    tokio::time::timeout_at(deadline.into(), io.cancel_and_drain(deadline))
        .await
        .map_err(|_| FacadeError::Shutdown)?
}

fn limits() -> JsonLimits {
    JsonLimits {
        max_bytes: MAX_FRAME_BYTES,
        max_depth: 64,
        max_nodes: MAX_FRAME_NODES,
    }
}
fn bounded_json(value: &Value) -> Result<Vec<u8>, FacadeError> {
    let bytes = encode_json(value).map_err(|_| FacadeError::OutputFrame)?;
    parse_json_with_limits(&bytes, limits()).map_err(|_| FacadeError::OutputFrame)?;
    Ok(bytes)
}
fn bounded_result(value: &Value) -> Result<(), FacadeError> {
    // A maximum admitted string ID bounds the real envelope, including escaping.
    let envelope = json!({"jsonrpc":"2.0", "id":"\0".repeat(128), "result":value});
    bounded_json(&envelope).map(|_| ())
}

fn references(value: &Value, out: &mut BTreeSet<String>) -> Result<(), FacadeError> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if key == "$ref" {
                    let name = child
                        .as_str()
                        .and_then(|s| s.strip_prefix("#/$defs/"))
                        .filter(|s| !s.is_empty() && !s.contains(['/', '~']))
                        .ok_or(FacadeError::Catalog)?;
                    out.insert(name.to_owned());
                }
                if matches!(
                    key.as_str(),
                    "$id" | "$dynamicRef" | "$recursiveRef" | "$anchor" | "$dynamicAnchor"
                ) {
                    return Err(FacadeError::Catalog);
                }
                references(child, out)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                references(child, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn export_schema(schema: &Value, root: &str) -> Result<Arc<Map<String, Value>>, FacadeError> {
    let definitions = schema
        .get("$defs")
        .and_then(Value::as_object)
        .ok_or(FacadeError::Catalog)?;
    let mut result = definitions
        .get(root)
        .and_then(Value::as_object)
        .cloned()
        .ok_or(FacadeError::Catalog)?;
    if result.get("type").and_then(Value::as_str) != Some("object") {
        return Err(FacadeError::Catalog);
    }
    let mut pending = BTreeSet::new();
    references(&Value::Object(result.clone()), &mut pending)?;
    let mut exported = Map::new();
    while let Some(name) = pending.pop_first() {
        if exported.contains_key(&name) {
            continue;
        }
        let definition = definitions.get(&name).ok_or(FacadeError::Catalog)?;
        // Including root when a future canonical schema references it also
        // preserves a cycle without rewriting its reference semantics.
        let mut children = BTreeSet::new();
        references(definition, &mut children)?;
        exported.insert(name, definition.clone());
        pending.extend(
            children
                .into_iter()
                .filter(|child| !exported.contains_key(child)),
        );
        if exported.len() > definitions.len() {
            return Err(FacadeError::Catalog);
        }
    }
    result.insert(
        "$schema".into(),
        schema.get("$schema").cloned().ok_or(FacadeError::Catalog)?,
    );
    if !exported.is_empty() {
        result.insert("$defs".into(), Value::Object(exported));
    }
    // Each root is a distinct document. Reusing the whole-contract $id would
    // register different schemas under one ID; local references need no $id.
    bounded_result(&Value::Object(result.clone()))?;
    Ok(Arc::new(result))
}

struct Catalog {
    tools: Vec<Tool>,
    pages: Vec<ListToolsResult>,
    cursors: BTreeMap<String, usize>,
}
impl Catalog {
    fn new() -> Result<Self, FacadeError> {
        let validator = ContractValidator::shared().map_err(|_| FacadeError::Catalog)?;
        let schema = parse_json(CANONICAL_SCHEMA).map_err(|_| FacadeError::Catalog)?;
        let mut tools = Vec::new();
        for function in validator.functions() {
            let description = format!(
                "{}; effect={}. Canonical contract {}. Coordinator authorization and operation status apply.",
                function.id,
                function.effect,
                mmmm_contracts::CONTRACT_VERSION
            );
            tools.push(
                Tool::new(
                    function.name.clone(),
                    description,
                    export_schema(&schema, &function.input)?,
                )
                .with_raw_output_schema(export_schema(&schema, &function.output)?),
            );
        }
        if tools.len() != 36
            || tools
                .iter()
                .map(|tool| tool.name.as_ref())
                .collect::<BTreeSet<_>>()
                .len()
                != 36
        {
            return Err(FacadeError::Catalog);
        }
        Self::paginate(tools)
    }
    fn paginate(tools: Vec<Tool>) -> Result<Self, FacadeError> {
        // Static public inventory, not a capability or a server principal.
        // The token binds the actual inventory + original source revision.
        let inventory = serde_json::to_value(&tools).map_err(|_| FacadeError::Catalog)?;
        let mut digest_input = encode_json(&inventory).map_err(|_| FacadeError::Catalog)?;
        digest_input.extend_from_slice(CANONICAL_SCHEMA);
        digest_input.extend_from_slice(FUNCTION_INDEX);
        let revision = raw_digest(&digest_input).to_string();
        let mut pages = Vec::new();
        let mut cursors = BTreeMap::new();
        let mut start = 0;
        while start < tools.len() {
            let mut accepted = None;
            for end in start + 1..=(start + MAX_PAGE_TOOLS).min(tools.len()) {
                let mut page = ListToolsResult {
                    result_type: None,
                    tools: tools[start..end].to_vec(),
                    ..ListToolsResult::default()
                };
                if end < tools.len() {
                    page.next_cursor = Some(format!("mmmm-tools-v1-{revision}-{end}"));
                }
                let value = serde_json::to_value(&page).map_err(|_| FacadeError::Catalog)?;
                if bounded_result(&value).is_err() {
                    break;
                }
                accepted = Some((end, page));
            }
            let (end, page) = accepted.ok_or(FacadeError::Catalog)?;
            if let Some(cursor) = &page.next_cursor {
                cursors.insert(cursor.clone(), pages.len() + 1);
            }
            pages.push(page);
            start = end;
        }
        if pages.is_empty() {
            return Err(FacadeError::Catalog);
        }
        Ok(Self {
            tools,
            pages,
            cursors,
        })
    }
    fn page(&self, cursor: Option<&str>) -> Result<ListToolsResult, ErrorData> {
        let index = match cursor {
            None => 0,
            Some(cursor) if cursor.len() <= 128 => *self
                .cursors
                .get(cursor)
                .ok_or_else(|| ErrorData::invalid_params("Invalid or stale tools cursor", None))?,
            Some(_) => return Err(ErrorData::invalid_params("Invalid tools cursor", None)),
        };
        self.pages
            .get(index)
            .cloned()
            .ok_or_else(|| ErrorData::invalid_params("Invalid tools cursor", None))
    }
}

trait CoordinatorPort: Send + Sync + 'static {
    fn call(&self, method: &str, input: &Value) -> Result<Value, ClientError>;
}
impl CoordinatorPort for CoordinatorClient {
    fn call(&self, method: &str, input: &Value) -> Result<Value, ClientError> {
        CoordinatorClient::call(self, method, input)
    }
}

fn tool_error(code: &str, message: &str, uncertain: bool) -> CallToolResult {
    // Error text is deliberately outside the successful canonical output schema.
    // No input, authentication material or untrusted remote message is echoed.
    let wire = json!({"code":code, "message":message, "automaticRetry":false, "inspectDurableOperation":uncertain});
    let mut result = CallToolResult::error(vec![ContentBlock::text(wire.to_string())]);
    result.result_type = None;
    result
}
/// Static public diagnostics shared by the tool and resource envelopes. The
/// original remote message, request URI and authentication material stay out.
struct CallFailure {
    code: String,
    message: &'static str,
    uncertain: bool,
}
impl CallFailure {
    fn new(code: &str, message: &'static str, uncertain: bool) -> Self {
        Self {
            code: code.into(),
            message,
            uncertain,
        }
    }
    fn tool(self) -> CallToolResult {
        tool_error(&self.code, self.message, self.uncertain)
    }
    fn resource(self) -> ErrorData {
        ErrorData::new(
            ErrorCode::INTERNAL_ERROR,
            "The registered resource could not be read through the Coordinator",
            Some(json!({"code":self.code,"automaticRetry":false})),
        )
    }
}
fn client_failure(error: ClientError) -> CallFailure {
    let (code, message, uncertain) = match error {
        ClientError::Discovery => (
            "COORDINATOR_DISCOVERY",
            "No valid private Coordinator endpoint is available",
            false,
        ),
        ClientError::Authentication => (
            "COORDINATOR_AUTHENTICATION",
            "Local Coordinator authentication failed",
            false,
        ),
        ClientError::InvalidInput => (
            "INVALID_INPUT",
            "Input violates the canonical function contract",
            false,
        ),
        ClientError::InvalidResponse => (
            "INVALID_RESPONSE",
            "Coordinator response is invalid; inspect a durable write before retry",
            true,
        ),
        ClientError::Unavailable => (
            "COORDINATOR_UNAVAILABLE",
            "The Coordinator endpoint is unavailable",
            false,
        ),
        ClientError::LocalTransportUncertain => (
            "LOCAL_TRANSPORT_UNCERTAIN",
            "Native authentication transport completion is unresolved; no new request is admitted",
            true,
        ),
        ClientError::DeliveryUnknown => (
            "DELIVERY_UNKNOWN",
            "Request delivery or result is unknown; inspect the durable operation before retrying a write",
            true,
        ),
        ClientError::Remote {
            code: rpc_code,
            application_code,
            ..
        } => {
            let code = application_code.filter(|code| {
                !code.is_empty()
                    && code.len() <= 64
                    && code
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            });
            let uncertain = rpc_code == -32603
                || matches!(
                    code.as_deref(),
                    Some("OUTCOME_UNKNOWN" | "OUTPUT_SCHEMA_INVALID" | "BUDGET_EXCEEDED")
                );
            return CallFailure::new(
                code.as_deref().unwrap_or("SERVICE_ERROR"),
                if uncertain {
                    "The Coordinator could not return a verified result; inspect the durable operation before retrying a write"
                } else {
                    "The Coordinator rejected the operation; inspect its reported durable status"
                },
                uncertain,
            );
        }
    };
    CallFailure::new(code, message, uncertain)
}
#[cfg(test)]
fn client_error(error: ClientError) -> CallToolResult {
    client_failure(error).tool()
}
fn success_result(output: Value) -> Result<CallToolResult, FacadeError> {
    let text = String::from_utf8(encode_json(&output).map_err(|_| FacadeError::OutputFrame)?)
        .map_err(|_| FacadeError::OutputFrame)?;
    let mut result = CallToolResult::structured(output);
    result.result_type = None;
    result.content = vec![ContentBlock::text(text)];
    bounded_result(&serde_json::to_value(&result).map_err(|_| FacadeError::OutputFrame)?)?;
    Ok(result)
}

/// A public locator, never an authority or a registration. Its lexical forms
/// are the same nominal IDs, lowercase SHA-256 and decimals used by FN31.
struct ArtifactLocator {
    context: ContextId,
    resource: ResourceId,
    digest: Sha256Digest,
    offset: u64,
    limit: u64,
}
impl ArtifactLocator {
    fn parse(uri: &str) -> Result<Self, ErrorData> {
        if uri.len() > 512 {
            return Err(invalid_artifact_uri());
        }
        let mut parts = uri
            .strip_prefix(ARTIFACT_URI_PREFIX)
            .ok_or_else(invalid_artifact_uri)?
            .split('/');
        let context = ContextId::new(parts.next().ok_or_else(invalid_artifact_uri)?)
            .map_err(|_| invalid_artifact_uri())?;
        let resource = ResourceId::new(parts.next().ok_or_else(invalid_artifact_uri)?)
            .map_err(|_| invalid_artifact_uri())?;
        let digest = Sha256Digest::new(parts.next().ok_or_else(invalid_artifact_uri)?)
            .map_err(|_| invalid_artifact_uri())?;
        let offset = artifact_decimal(parts.next().ok_or_else(invalid_artifact_uri)?)
            .ok_or_else(invalid_artifact_uri)?;
        let limit = artifact_decimal(parts.next().ok_or_else(invalid_artifact_uri)?)
            .filter(|limit| (1..=MAX_ARTIFACT_SLICE).contains(limit))
            .ok_or_else(invalid_artifact_uri)?;
        if parts.next().is_some() || offset.checked_add(limit).is_none() {
            return Err(invalid_artifact_uri());
        }
        let locator = Self {
            context,
            resource,
            digest,
            offset,
            limit,
        };
        if locator.uri() != uri {
            return Err(invalid_artifact_uri());
        }
        Ok(locator)
    }
    fn uri(&self) -> String {
        format!(
            "{ARTIFACT_URI_PREFIX}{}/{}/{}/{}/{}",
            self.context, self.resource, self.digest, self.offset, self.limit
        )
    }
    fn request(&self) -> Value {
        // Only original FN31 input fields cross the authenticated transport.
        // The expected digest is checked against its actual verified response.
        json!({"contextId":self.context,"resourceId":self.resource,
            "offset":self.offset.to_string(),"limitBytes":self.limit})
    }
}
fn artifact_decimal(value: &str) -> Option<u64> {
    UnsignedDecimal::new(value).ok()?.as_str().parse().ok()
}
fn invalid_artifact_uri() -> ErrorData {
    ErrorData::invalid_params("Invalid canonical artifact resource locator", None)
}
fn invalid_artifact_response() -> ErrorData {
    ErrorData::internal_error(
        "Artifact slice does not match its verified resource locator",
        None,
    )
}

/// FN21 identifies a catalog record by snapshot, namespaced kind and resource,
/// and an explicit current context. The context query is a locator only; no
/// preceding tool call or facade session can supply or authorize a missing one.
struct CatalogLocator {
    snapshot: SnapshotId,
    kind: ResourceLocation,
    resource: ResourceLocation,
    context: ContextId,
}
impl CatalogLocator {
    fn parse(uri: &str) -> Result<Self, ErrorData> {
        if uri.len() > MAX_FRAME_BYTES || !uri.is_ascii() {
            return Err(invalid_catalog_uri());
        }
        let (path, context) = uri
            .strip_prefix(CATALOG_URI_PREFIX)
            .and_then(|value| value.split_once("?contextId="))
            .ok_or_else(invalid_catalog_uri)?;
        let context = ContextId::new(context).map_err(|_| invalid_catalog_uri())?;
        let mut parts = path.split('/');
        let snapshot = SnapshotId::new(parts.next().ok_or_else(invalid_catalog_uri)?)
            .map_err(|_| invalid_catalog_uri())?;
        let kind = parts
            .next()
            .and_then(catalog_component_decode)
            .and_then(|value| ResourceLocation::new(value).ok())
            .ok_or_else(invalid_catalog_uri)?;
        let resource = parts
            .next()
            .and_then(catalog_component_decode)
            .and_then(|value| ResourceLocation::new(value).ok())
            .ok_or_else(invalid_catalog_uri)?;
        if parts.next().is_some() {
            return Err(invalid_catalog_uri());
        }
        let locator = Self {
            snapshot,
            kind,
            resource,
            context,
        };
        if locator.uri() != uri {
            return Err(invalid_catalog_uri());
        }
        Ok(locator)
    }
    fn uri(&self) -> String {
        format!(
            "{CATALOG_URI_PREFIX}{}/{}/{}?contextId={}",
            self.snapshot,
            catalog_component_encode(self.kind.as_str()),
            catalog_component_encode(self.resource.as_str()),
            self.context
        )
    }
    fn request(&self) -> Value {
        // Namespaced catalog ResourceLocation differs from FN31 ResourceId.
        // No range, digest or context approval fields are added to RecordQuery.
        json!({"snapshotId":self.snapshot,"kind":self.kind,
            "resourceId":self.resource,"contextId":self.context})
    }
}
fn invalid_catalog_uri() -> ErrorData {
    ErrorData::invalid_params(
        "Invalid canonical catalog record locator with explicit context",
        None,
    )
}
fn invalid_catalog_response() -> ErrorData {
    ErrorData::internal_error(
        "Catalog record does not match its snapshot resource locator or output budget",
        None,
    )
}
fn catalog_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}
/// RFC 6570 simple expansion for the two ASCII ResourceLocation path values.
/// Reserved ':' and '/' are encoded independently, preserving segment identity.
fn catalog_component_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::new();
    for byte in value.bytes() {
        if catalog_unreserved(byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    encoded
}
fn catalog_component_decode(value: &str) -> Option<String> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let mut bytes = value.bytes();
    let mut decoded = String::new();
    while let Some(byte) = bytes.next() {
        if catalog_unreserved(byte) {
            decoded.push(char::from(byte));
        } else if byte == b'%' {
            let byte = hex(bytes.next()?)?
                .checked_mul(16)?
                .checked_add(hex(bytes.next()?)?)?;
            if !byte.is_ascii() || catalog_unreserved(byte) {
                return None;
            }
            decoded.push(char::from(byte));
        } else {
            return None;
        }
    }
    Some(decoded)
}
fn catalog_resource_result(
    locator: &CatalogLocator,
    output: Value,
) -> Result<ReadResourceResult, ErrorData> {
    let invalid = invalid_catalog_response;
    let validator = ContractValidator::shared().map_err(|_| invalid())?;
    if validator.validate("DataRecord", &output).is_err()
        || output["snapshotId"].as_str() != Some(locator.snapshot.as_str())
        || output["kind"].as_str() != Some(locator.kind.as_str())
        || output["resourceId"].as_str() != Some(locator.resource.as_str())
    {
        return Err(invalid());
    }
    // The whole DataRecord is the resource: preserve status, absent value,
    // reason, units, provenance, sources and coverage. It is not a tool result,
    // a CAS artifact slice, or a source of new claims about runtime state.
    let bytes = bounded_json(&output).map_err(|_| invalid())?;
    let byte_length = bytes.len();
    let text = String::from_utf8(bytes).map_err(|_| invalid())?;
    let content = ResourceContents::text(text, locator.uri())
        .with_mime_type("application/json")
        .with_meta(
            Map::from_iter([(
                "io.github.daejunnom.mmmm/catalogRecord".into(),
                json!({"contextId":locator.context,"recordBytes":byte_length}),
            )])
            .into(),
        );
    let mut result = ReadResourceResult::new(vec![content]);
    result.result_type = None;
    // JSON text escaping, URI and metadata share the real MCP frame bound.
    // No truncation, hidden staging or FN31 fallback repairs an oversized read.
    bounded_result(&serde_json::to_value(&result).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    Ok(result)
}

/// Validate STANDARD canonical base64 without decoding or allocating another
/// copy of the artifact. Only the actual Coordinator/CAS issues source bytes.
fn artifact_base64_length(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(4) || bytes.len() > 87_384 {
        return None;
    }
    if bytes.is_empty() {
        return Some(0);
    }
    let padding = if bytes.ends_with(b"==") {
        2
    } else {
        usize::from(bytes.ends_with(b"="))
    };
    let payload = &bytes[..bytes.len() - padding];
    fn sextet(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    if !payload.iter().all(|byte| sextet(*byte).is_some()) {
        return None;
    }
    let last = sextet(*payload.last()?)?;
    if (padding == 2 && last & 15 != 0) || (padding == 1 && last & 3 != 0) {
        return None;
    }
    (bytes.len() / 4).checked_mul(3)?.checked_sub(padding)
}

fn artifact_resource_result(
    locator: &ArtifactLocator,
    output: Value,
) -> Result<ReadResourceResult, ErrorData> {
    let invalid = invalid_artifact_response;
    let validator = ContractValidator::shared().map_err(|_| invalid())?;
    if bounded_json(&output).is_err() || validator.validate("ArtifactSlice", &output).is_err() {
        return Err(invalid());
    }
    let resource = &output["resource"];
    let size = resource["sizeBytes"].as_u64().ok_or_else(invalid)?;
    if resource["resourceId"].as_str() != Some(locator.resource.as_str())
        || resource["sha256"].as_str() != Some(locator.digest.as_str())
        || output["offset"].as_str().and_then(artifact_decimal) != Some(locator.offset)
        || locator.offset > size
    {
        return Err(invalid());
    }
    let data = output["data"].as_str().ok_or_else(invalid)?;
    let bytes = match output["encoding"].as_str() {
        Some("utf8") => data.len(),
        Some("base64") => artifact_base64_length(data).ok_or_else(invalid)?,
        _ => return Err(invalid()),
    };
    let expected_length = locator.limit.min(size - locator.offset);
    if u64::try_from(bytes).ok() != Some(expected_length) {
        return Err(invalid());
    }
    let end = locator
        .offset
        .checked_add(expected_length)
        .ok_or_else(invalid)?;
    let next_offset = if end < size {
        json!(end.to_string())
    } else {
        Value::Null
    };
    if output["nextOffset"] != next_offset {
        return Err(invalid());
    }
    let mime = resource["mediaType"].as_str().ok_or_else(invalid)?;
    let uri = locator.uri();
    let content = match output["encoding"].as_str() {
        Some("utf8") => ResourceContents::text(data, uri),
        Some("base64") => ResourceContents::blob(data, uri),
        _ => return Err(invalid()),
    }
    .with_mime_type(mime)
    .with_meta(
        Map::from_iter([(
            "io.github.daejunnom.mmmm/artifactSlice".into(),
            json!({"contextId":locator.context,"resource":resource,
            "offset":output["offset"],"nextOffset":next_offset,"sliceBytes":bytes}),
        )])
        .into(),
    );
    let mut result = ReadResourceResult::new(vec![content]);
    result.result_type = None;
    bounded_result(&serde_json::to_value(&result).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    Ok(result)
}

fn artifact_resource_list(cursor: Option<&str>) -> Result<ListResourcesResult, ErrorData> {
    if cursor.is_some() {
        return Err(ErrorData::invalid_params(
            "No artifact resource index or cursor is available",
            None,
        ));
    }
    // The tool catalog is not a resource ACL index. Do not retain an inventory
    // from past tool calls or invent access to all resources in a Project.
    Ok(ListResourcesResult {
        result_type: None,
        ..ListResourcesResult::default()
    })
}
fn resource_templates(cursor: Option<&str>) -> Result<ListResourceTemplatesResult, ErrorData> {
    if cursor.is_some() {
        return Err(ErrorData::invalid_params(
            "Invalid registered resource template cursor",
            None,
        ));
    }
    let template = ResourceTemplate::new(ARTIFACT_URI_TEMPLATE, "mmmm-artifact-slice")
        .with_description("A bounded slice of an existing registered artifact. Context and resource IDs are locators; each read requires current Coordinator authorization. SHA-256 pins the full resource; offset is a canonical decimal and limitBytes is 1..65536. This template is not a resource inventory or permission grant.");
    let catalog = ResourceTemplate::new(CATALOG_URI_TEMPLATE, "mmmm-catalog-record")
        .with_mime_type("application/json")
        .with_description("One complete DataRecord from an existing immutable snapshot through catalog.describe. Snapshot and current context IDs are explicit locators; kind and resourceId are separately percent-encoded namespaced IDs. Each read requires current snapshot, record and source authorization. This template does not capture or restore snapshots and grants no access.");
    Ok(ListResourceTemplatesResult {
        result_type: None,
        resource_templates: vec![template, catalog],
        ..ListResourceTemplatesResult::default()
    })
}

struct McpFacade {
    catalog: Arc<Catalog>,
    coordinator: Arc<dyn CoordinatorPort>,
    calls: Arc<Semaphore>,
    stopping: Arc<AtomicBool>,
}
impl McpFacade {
    fn prepare_call(
        &self,
        name: &str,
        arguments: Option<Map<String, Value>>,
    ) -> Result<(FunctionContract, Value), ErrorData> {
        let validator = ContractValidator::shared()
            .map_err(|_| ErrorData::internal_error("Canonical validator unavailable", None))?;
        let function = validator.function(name).map_err(|_| {
            ErrorData::new(ErrorCode::METHOD_NOT_FOUND, "Unknown canonical tool", None)
        })?;
        if function.name != name {
            return Err(ErrorData::new(
                ErrorCode::METHOD_NOT_FOUND,
                "Unknown canonical tool",
                None,
            ));
        }
        Ok((
            function.clone(),
            Value::Object(arguments.unwrap_or_default()),
        ))
    }
    async fn execute(
        &self,
        function: FunctionContract,
        input: Value,
        cancel: impl Future<Output = ()> + Send,
    ) -> CallToolResult {
        match self.execute_canonical(function, input, cancel).await {
            Ok(output) => success_result(output).unwrap_or_else(|_| tool_error("OUTPUT_LIMIT", "Result exceeded the MCP wire limit; inspect the durable operation before retrying a write", true)),
            Err(error) => error.tool(),
        }
    }
    /// Every facade operation uses the same authenticated Coordinator client,
    /// sole owned worker and drain permit. Resource reads enter FN21 or FN31;
    /// they cannot create an in-process request witness from their locator.
    async fn execute_canonical(
        &self,
        function: FunctionContract,
        input: Value,
        cancel: impl Future<Output = ()> + Send,
    ) -> Result<Value, CallFailure> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(CallFailure::new(
                "FACADE_STOPPING",
                "The facade is closing; no request was dispatched",
                false,
            ));
        }
        let validator = match ContractValidator::shared() {
            Ok(value) => value,
            Err(_) => {
                return Err(CallFailure::new(
                    "INTERNAL_ERROR",
                    "Canonical validator unavailable",
                    false,
                ));
            }
        };
        if bounded_json(&input).is_err() || validator.validate(&function.input, &input).is_err() {
            return Err(CallFailure::new(
                "INVALID_INPUT",
                "Arguments violate the canonical function contract",
                false,
            ));
        }
        let permit = match self.calls.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return Err(CallFailure::new(
                    "SERVER_BUSY",
                    "One Coordinator call is already running; no request was dispatched",
                    false,
                ));
            }
        };
        let coordinator = self.coordinator.clone();
        let method = function.name.clone();
        let dispatch_cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = dispatch_cancel.clone();
        let worker_stopping = self.stopping.clone();
        let worker = tokio::task::spawn_blocking(move || {
            // The permit stays in the owned worker after timeout/cancellation.
            // A second call cannot race unresolved delivery; no automatic retry.
            let _permit = permit;
            if worker_cancel.load(Ordering::Acquire) || worker_stopping.load(Ordering::Acquire) {
                return Err(ClientError::Unavailable);
            }
            coordinator.call(&method, &input)
        });
        tokio::pin!(cancel);
        let output = tokio::select! {
            biased;
            _ = &mut cancel => {
                dispatch_cancel.store(true, Ordering::Release);
                return Err(CallFailure::new("DELIVERY_UNKNOWN", "Call canceled locally; application effects are not proven stopped. Inspect the durable operation", true));
            }
            result = tokio::time::timeout(CALL_DEADLINE, worker) => match result {
                Ok(Ok(Ok(output))) => output,
                Ok(Ok(Err(error))) => return Err(client_failure(error)),
                _ => return Err(CallFailure::new("DELIVERY_UNKNOWN", "Coordinator call did not return a verified result; inspect the durable operation", true)),
            }
        };
        if validator.validate(&function.output, &output).is_err() {
            return Err(client_failure(ClientError::InvalidResponse));
        }
        Ok(output)
    }
    async fn read_artifact(
        &self,
        request: ReadResourceRequestParams,
        cancel: impl Future<Output = ()> + Send,
    ) -> Result<ReadResourceResult, ErrorData> {
        // Multi-round input negotiation is outside the negotiated 2025 profile.
        if request.input_responses.is_some() || request.request_state.is_some() {
            return Err(ErrorData::invalid_params(
                "Only the MCP 2025-11-25 resources/read profile is supported",
                None,
            ));
        }
        let locator = ArtifactLocator::parse(&request.uri)?;
        let (function, input) =
            self.prepare_call("artifact.read", locator.request().as_object().cloned())?;
        let output = self
            .execute_canonical(function, input, cancel)
            .await
            .map_err(CallFailure::resource)?;
        artifact_resource_result(&locator, output)
    }
    async fn read_catalog(
        &self,
        request: ReadResourceRequestParams,
        cancel: impl Future<Output = ()> + Send,
    ) -> Result<ReadResourceResult, ErrorData> {
        if request.input_responses.is_some() || request.request_state.is_some() {
            return Err(ErrorData::invalid_params(
                "Only the MCP 2025-11-25 resources/read profile is supported",
                None,
            ));
        }
        let locator = CatalogLocator::parse(&request.uri)?;
        let (function, input) =
            self.prepare_call("catalog.describe", locator.request().as_object().cloned())?;
        let output = self
            .execute_canonical(function, input, cancel)
            .await
            .map_err(CallFailure::resource)?;
        catalog_resource_result(&locator, output)
    }
    async fn read_registered_resource(
        &self,
        request: ReadResourceRequestParams,
        cancel: impl Future<Output = ()> + Send,
    ) -> Result<ReadResourceResult, ErrorData> {
        if request.uri.starts_with(ARTIFACT_URI_PREFIX) {
            self.read_artifact(request, cancel).await
        } else if request.uri.starts_with(CATALOG_URI_PREFIX) {
            self.read_catalog(request, cancel).await
        } else {
            Err(ErrorData::invalid_params(
                "Unsupported registered resource locator",
                None,
            ))
        }
    }
}
impl ServerHandler for McpFacade {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().enable_resources().build())
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_server_info(Implementation::new("MMMM", env!("CARGO_PKG_VERSION")))
            .with_instructions("MMMM uses canonical contract 0.2.0 through the shared local Coordinator. This facade supports MCP 2025-11-25 only. Use the canonical function name and DTO. Artifact resources expose bounded text/blob slices through authenticated artifact.read. Catalog resources expose one complete DataRecord through authenticated catalog.describe with an explicit current context. URI templates are locators, not access grants; no snapshot capture or restoration occurs during a read. No resource inventory or subscriptions are provided. Transport success preserves reported operation status; unknown write delivery requires durable operation inspection before retry.")
    }
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Owned(vec![ProtocolVersion::V_2025_11_25])
    }
    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.catalog
            .tools
            .iter()
            .find(|tool| tool.name == name)
            .cloned()
    }
    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.catalog
            .page(request.as_ref().and_then(|params| params.cursor.as_deref()))
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        // 2026 multi-round input negotiation is outside the declared profile.
        if request.input_responses.is_some() || request.request_state.is_some() {
            return Err(ErrorData::invalid_params(
                "Only the MCP 2025-11-25 tools/call profile is supported",
                None,
            ));
        }
        let (function, input) = self.prepare_call(&request.name, request.arguments)?;
        if context.ct.is_cancelled() {
            return Ok(tool_error(
                "CANCELED_BEFORE_DISPATCH",
                "The request was canceled before dispatch",
                false,
            )
            .into());
        }
        Ok(self
            .execute(function, input, context.ct.cancelled())
            .await
            .into())
    }
    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        artifact_resource_list(request.as_ref().and_then(|params| params.cursor.as_deref()))
    }
    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        resource_templates(request.as_ref().and_then(|params| params.cursor.as_deref()))
    }
    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        if context.ct.is_cancelled() {
            return Err(ErrorData::internal_error(
                "Registered resource read was canceled before dispatch",
                None,
            ));
        }
        Ok(self
            .read_registered_resource(request, context.ct.cancelled())
            .await?
            .into())
    }
    async fn on_initialized(&self, _context: rmcp::service::NotificationContext<RoleServer>) {
        // No logging subscriber is installed: standard output is protocol only.
    }
}

#[derive(Default)]
struct Admission {
    phase: u8,
    initialization_written: bool,
    initialization_id: Option<String>,
    seen: BTreeSet<String>,
    pending: BTreeSet<String>,
    frames: usize,
    failure: Option<FacadeError>,
}
impl Admission {
    fn accept(&mut self, value: &Value) -> Result<(), FacadeError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        self.frames += 1;
        if self.frames > MAX_SESSION_FRAMES {
            return Err(FacadeError::SessionExpired);
        }
        let object = value.as_object().ok_or(FacadeError::InputFrame)?;
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || object
                .keys()
                .any(|key| !matches!(key.as_str(), "jsonrpc" | "id" | "method" | "params"))
        {
            return Err(FacadeError::InputFrame);
        }
        let method = object
            .get("method")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 128)
            .ok_or(FacadeError::InputFrame)?;
        let id = if let Some(id) = object.get("id") {
            if !matches!(id, Value::String(s) if !s.is_empty() && s.len() <= 128)
                && id.as_i64().is_none()
            {
                return Err(FacadeError::InputFrame);
            }
            Some(
                String::from_utf8(encode_json(id).map_err(|_| FacadeError::InputFrame)?)
                    .map_err(|_| FacadeError::InputFrame)?,
            )
        } else {
            None
        };
        match self.phase {
            0 if method == "initialize" && id.is_some() => {
                self.phase = 1;
                self.initialization_id = id.clone();
            }
            0 => return Err(FacadeError::InputFrame),
            1 if method == "notifications/initialized"
                && id.is_none()
                && self.initialization_written =>
            {
                self.phase = 2
            }
            1 if method == "ping" && id.is_some() => {}
            1 => return Err(FacadeError::InputFrame),
            2 if matches!(
                method,
                "initialize" | "notifications/initialized" | "discover"
            ) =>
            {
                return Err(FacadeError::InputFrame);
            }
            _ => {}
        }
        if let Some(id) = id {
            if method.starts_with("notifications/")
                || self.pending.len() >= MAX_REQUESTS
                || !self.seen.insert(id.clone())
            {
                return Err(FacadeError::InputFrame);
            }
            self.pending.insert(id);
        } else if !method.starts_with("notifications/") {
            return Err(FacadeError::InputFrame);
        } else if method == "notifications/cancelled" {
            // rmcp suppresses a canceled request's response. Retire its bounded
            // admission slot here rather than waiting for send(), which never
            // occurs for that response. Cancellation is not application rollback.
            let params = object
                .get("params")
                .cloned()
                .ok_or(FacadeError::InputFrame)?;
            let notification: rmcp::model::CancelledNotificationParam =
                serde_json::from_value(params).map_err(|_| FacadeError::InputFrame)?;
            let id = serde_json::to_value(notification.request_id)
                .map_err(|_| FacadeError::InputFrame)?;
            let id = String::from_utf8(encode_json(&id).map_err(|_| FacadeError::InputFrame)?)
                .map_err(|_| FacadeError::InputFrame)?;
            self.pending.remove(&id);
        }
        Ok(())
    }
    fn sent(&mut self, value: &Value) -> Result<(), FacadeError> {
        if let Some(id) = value.get("id") {
            let id = String::from_utf8(encode_json(id).map_err(|_| FacadeError::OutputFrame)?)
                .map_err(|_| FacadeError::OutputFrame)?;
            self.pending.remove(&id);
            if self.initialization_id.as_ref() == Some(&id) && value.get("result").is_some() {
                self.initialization_written = true;
            }
        }
        Ok(())
    }
}

struct BoundedTransport {
    io: Arc<dyn FiniteIoPort>,
    cancel: Arc<AtomicBool>,
    admission: Arc<Mutex<Admission>>,
    output: Arc<Semaphore>,
    deadline: Instant,
}
fn record_failure(state: &Mutex<Admission>, error: FacadeError) {
    if let Ok(mut state) = state.lock() {
        state.failure.get_or_insert(error);
    }
}
impl Transport<RoleServer> for BoundedTransport {
    type Error = FacadeError;
    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let io = self.io.clone();
        let cancel = self.cancel.clone();
        let admission = self.admission.clone();
        let output = self.output.clone();
        let deadline = self.deadline.min(Instant::now() + WRITE_DEADLINE);
        async move {
            let outcome = async {
                let value = serde_json::to_value(item).map_err(|_| FacadeError::OutputFrame)?;
                let bytes = bounded_json(&value)?;
                io_write(
                    io.as_ref(),
                    bytes,
                    deadline,
                    cancel.clone(),
                    output.as_ref(),
                )
                .await?;
                admission
                    .lock()
                    .map_err(|_| FacadeError::Runtime)?
                    .sent(&value)?;
                Ok(())
            }
            .await;
            if let Err(error) = outcome {
                record_failure(&admission, error);
                cancel.store(true, Ordering::Release);
            }
            outcome
        }
    }
    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        let mut rejection = None;
        let result = async {
            if self.cancel.load(Ordering::Acquire) {
                return Ok(None);
            }
            if Instant::now() >= self.deadline {
                return Err(FacadeError::SessionExpired);
            }
            let Some(bytes) = io_read(
                self.io.as_ref(),
                self.deadline.min(Instant::now() + READ_IDLE),
                self.cancel.clone(),
            )
            .await?
            else {
                return Ok(None);
            };
            if self.cancel.load(Ordering::Acquire) { return Ok(None); }
            if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
                rejection = Some(json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Invalid bounded JSON frame"}}));
                return Err(FacadeError::InputFrame);
            }
            let value = parse_json_with_limits(&bytes, limits()).map_err(|_| {
                rejection = Some(json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Invalid bounded JSON frame"}}));
                FacadeError::InputFrame
            })?;
            let reply_id = value.get("id").filter(|id| id.as_i64().is_some() || matches!(id, Value::String(s) if !s.is_empty() && s.len() <= 128)).cloned().unwrap_or(Value::Null);
            let is_notification = value.get("id").is_none() && value.get("method").and_then(Value::as_str).is_some_and(|method| method.starts_with("notifications/"));
            self.admission
                .lock()
                .map_err(|_| FacadeError::Runtime)?
                .accept(&value).inspect_err(|error| {
                    if *error == FacadeError::InputFrame && !is_notification {
                        rejection = Some(json!({"jsonrpc":"2.0","id":reply_id,"error":{"code":-32600,"message":"Invalid bounded JSON-RPC request"}}));
                    }
                })?;
            serde_json::from_value(value)
                .map(Some)
                .map_err(|_| {
                    if !is_notification {
                        rejection = Some(json!({"jsonrpc":"2.0","id":reply_id,"error":{"code":-32602,"message":"Invalid MCP request parameters"}}));
                    }
                    FacadeError::InputFrame
                })
        }
        .await;
        match result {
            Ok(message) => message,
            Err(error) => {
                record_failure(&self.admission, error);
                let was_stopping = self.cancel.swap(true, Ordering::AcqRel);
                if !was_stopping && let Some(rejection) = rejection {
                    // Boundary rejection only; all accepted messages still use
                    // rmcp dispatch. Malformed input cannot authorize a call.
                    if let Ok(bytes) = bounded_json(&rejection) {
                        let deadline = self.deadline.min(Instant::now() + WRITE_DEADLINE);
                        let _ = io_write(
                            self.io.as_ref(),
                            bytes,
                            deadline,
                            Arc::new(AtomicBool::new(false)),
                            self.output.as_ref(),
                        )
                        .await;
                    }
                }
                None
            }
        }
    }
    async fn close(&mut self) -> Result<(), Self::Error> {
        self.cancel.store(true, Ordering::Release);
        let result = io_drain(self.io.as_ref()).await;
        if result.is_err() {
            record_failure(&self.admission, FacadeError::Shutdown);
        }
        result
    }
}

fn checked_quit(
    result: Result<rmcp::service::QuitReason, tokio::task::JoinError>,
) -> Result<(), FacadeError> {
    match result {
        Ok(rmcp::service::QuitReason::Closed | rmcp::service::QuitReason::Cancelled) => Ok(()),
        _ => Err(FacadeError::Runtime),
    }
}
async fn serve_facade(facade: McpFacade, io: Arc<dyn FiniteIoPort>) -> Result<(), FacadeError> {
    let calls = facade.calls.clone();
    let cancel = facade.stopping.clone();
    let admission = Arc::new(Mutex::new(Admission::default()));
    let transport = BoundedTransport {
        io: io.clone(),
        cancel: cancel.clone(),
        admission: admission.clone(),
        output: Arc::new(Semaphore::new(1)),
        deadline: Instant::now() + SESSION_LIFETIME,
    };
    let running = tokio::time::timeout(INITIALIZE_DEADLINE, facade.serve(transport)).await;
    let outcome = match running {
        Ok(Ok(running)) => {
            let token = running.cancellation_token();
            let mut waiting = Box::pin(running.waiting());
            tokio::select! {
                result = &mut waiting => checked_quit(result),
                _ = tokio::time::sleep(SESSION_LIFETIME) => {
                    record_failure(&admission, FacadeError::SessionExpired);
                    token.cancel();
                    match tokio::time::timeout(DRAIN_DEADLINE, &mut waiting).await {
                        Ok(result) => checked_quit(result),
                        Err(_) => Err(FacadeError::Shutdown),
                    }
                }
            }
        }
        _ => Err(FacadeError::Initialization),
    };
    // Cleanup runs for normal EOF, initialization failure and protocol failure.
    // Canceling this facade never requests Coordinator or application shutdown.
    cancel.store(true, Ordering::Release);
    let io_stopped = io_drain(io.as_ref()).await;
    let call_stopped = tokio::time::timeout(CALL_DEADLINE, calls.acquire()).await;
    if io_stopped.is_err() || !matches!(call_stopped, Ok(Ok(_))) {
        return Err(FacadeError::Shutdown);
    }
    if let Some(error) = admission.lock().map_err(|_| FacadeError::Runtime)?.failure {
        return Err(error);
    }
    outcome
}

/// Native standard-I/O construction remains an explicit caller responsibility.
/// The supplied port is drained even when catalog/authentication setup fails.
pub fn run_with_io(runtime_directory: &Path, io: Arc<dyn FiniteIoPort>) -> Result<(), FacadeError> {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            return match io.force_cancel_and_drain(Instant::now() + DRAIN_DEADLINE) {
                Ok(()) => Err(FacadeError::Runtime),
                Err(_) => Err(FacadeError::Shutdown),
            };
        }
    };
    let prepared = Catalog::new().and_then(|catalog| {
        CoordinatorClient::discover_peer(runtime_directory)
            .map(|client| (catalog, client))
            .map_err(|_| FacadeError::Initialization)
    });
    let result = match prepared {
        Ok((catalog, client)) => runtime.block_on(serve_facade(
            McpFacade {
                catalog: Arc::new(catalog),
                coordinator: Arc::new(client),
                calls: Arc::new(Semaphore::new(1)),
                stopping: Arc::new(AtomicBool::new(false)),
            },
            io.clone(),
        )),
        Err(error) => {
            let drained = runtime.block_on(io_drain(io.as_ref()));
            if drained.is_err() {
                Err(FacadeError::Shutdown)
            } else {
                Err(error)
            }
        }
    };
    runtime.shutdown_timeout(Duration::from_secs(2));
    result
}

#[cfg(test)]
mod tests {
    //! These are protocol and source-contract checks with an explicit RAM I/O
    //! port and Coordinator spy. They do not prove native stdio, game effects,
    //! native authentication or release acceptance. Original prefab data is
    //! reused; only malformed envelopes and transport failures are constructed.
    use super::*;
    use std::{collections::VecDeque, sync::atomic::AtomicUsize};

    struct Spy {
        calls: AtomicUsize,
        delivery_unknown: bool,
        invalid_output: bool,
    }
    impl CoordinatorPort for Spy {
        fn call(&self, method: &str, _input: &Value) -> Result<Value, ClientError> {
            assert_eq!(method, "prefab.validate");
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.delivery_unknown {
                Err(ClientError::DeliveryUnknown)
            } else if self.invalid_output {
                Ok(json!({"invented":"success"}))
            } else {
                Ok(json!({"diagnostics":[]}))
            }
        }
    }
    fn facade(spy: Arc<Spy>) -> McpFacade {
        McpFacade {
            catalog: Arc::new(Catalog::new().unwrap()),
            coordinator: spy,
            calls: Arc::new(Semaphore::new(1)),
            stopping: Arc::new(AtomicBool::new(false)),
        }
    }
    fn spy() -> Arc<Spy> {
        Arc::new(Spy {
            calls: AtomicUsize::new(0),
            delivery_unknown: false,
            invalid_output: false,
        })
    }
    fn prefab() -> Value {
        parse_json(include_bytes!("../../../examples/prefab.json")).unwrap()
    }
    fn function(name: &str) -> FunctionContract {
        ContractValidator::shared()
            .unwrap()
            .function(name)
            .unwrap()
            .clone()
    }
    fn error_text(result: &CallToolResult) -> Value {
        let value = serde_json::to_value(result).unwrap();
        parse_json(value["content"][0]["text"].as_str().unwrap().as_bytes()).unwrap()
    }

    #[test]
    fn all_canonical_tools_export_only_original_reachable_constraints() {
        let catalog = Catalog::new().unwrap();
        let validator = ContractValidator::shared().unwrap();
        let schema = parse_json(CANONICAL_SCHEMA).unwrap();
        assert_eq!(catalog.tools.len(), 36);
        for (tool, function) in catalog.tools.iter().zip(validator.functions()) {
            assert_eq!(tool.name, function.name);
            let exported = serde_json::to_value(tool).unwrap();
            for (field, root) in [
                ("inputSchema", &function.input),
                ("outputSchema", &function.output),
            ] {
                let value = &exported[field];
                assert_eq!(value["$schema"], schema["$schema"]);
                assert!(value.get("$id").is_none());
                let mut restored = value.as_object().unwrap().clone();
                restored.remove("$schema");
                restored.remove("$defs");
                assert_eq!(Value::Object(restored), schema["$defs"][root]);
                let mut reachable = BTreeSet::new();
                references(&schema["$defs"][root], &mut reachable).unwrap();
                let mut scanned = BTreeSet::new();
                while let Some(name) = reachable
                    .iter()
                    .find(|name| !scanned.contains(*name))
                    .cloned()
                {
                    scanned.insert(name.clone());
                    references(&schema["$defs"][&name], &mut reachable).unwrap();
                }
                let actual = value
                    .get("$defs")
                    .and_then(Value::as_object)
                    .map(|defs| defs.keys().cloned().collect::<BTreeSet<_>>())
                    .unwrap_or_default();
                assert_eq!(actual, reachable);
                for name in &actual {
                    assert_eq!(value["$defs"][name], schema["$defs"][name]);
                }
                let mut refs = BTreeSet::new();
                references(value, &mut refs).unwrap();
                assert!(refs.iter().all(|name| actual.contains(name)));
            }
        }
    }

    #[test]
    fn pagination_enforces_full_envelope_budget_and_rejects_nonissued_cursors() {
        let catalog = Catalog::new().unwrap();
        let mut cursor = None;
        let mut seen = Vec::new();
        let mut tokens = BTreeSet::new();
        loop {
            let page = catalog.page(cursor.as_deref()).unwrap();
            assert!(!page.tools.is_empty() && page.tools.len() <= MAX_PAGE_TOOLS);
            bounded_result(&serde_json::to_value(&page).unwrap()).unwrap();
            seen.extend(page.tools.iter().map(|tool| tool.name.to_string()));
            match page.next_cursor {
                Some(next) => {
                    assert!(tokens.insert(next.clone()));
                    cursor = Some(next);
                }
                None => break,
            }
        }
        assert_eq!(
            seen,
            catalog
                .tools
                .iter()
                .map(|tool| tool.name.to_string())
                .collect::<Vec<_>>()
        );
        for cursor in ["", "mmmm-tools-v1-fabricated-1", "other-method-1"] {
            assert_eq!(
                catalog.page(Some(cursor)).unwrap_err().code,
                ErrorCode::INVALID_PARAMS
            );
        }
        assert!(catalog.page(Some(&"x".repeat(129))).is_err());
        let selected = catalog
            .tools
            .iter()
            .filter(|tool| {
                matches!(
                    tool.name.as_ref(),
                    "plan.create" | "exchange.prepare" | "scene.diff"
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let selected = Catalog::paginate(selected).unwrap();
        // These three canonical tools exceed 4096 nodes in one envelope.
        assert!(selected.pages.len() >= 2);
        assert_eq!(
            selected
                .pages
                .iter()
                .map(|page| page.tools.len())
                .sum::<usize>(),
            3
        );
        for page in &selected.pages {
            bounded_result(&serde_json::to_value(page).unwrap()).unwrap();
        }
        let stale = catalog.pages[0].next_cursor.as_deref().unwrap();
        assert!(selected.page(Some(stale)).is_err());
    }

    #[test]
    fn sdk_negotiates_only_explicit_2025_profile() {
        let server = facade(spy());
        assert_eq!(
            server.supported_protocol_versions().as_ref(),
            &[ProtocolVersion::V_2025_11_25]
        );
        for requested in ["2025-11-25", "2026-07-28", "2025-06-18"] {
            let request = serde_json::from_value(json!({"protocolVersion":requested,"capabilities":{},"clientInfo":{"name":"protocol-fixture","version":"1"}})).unwrap();
            assert_eq!(
                server
                    .negotiate_initialize(&request)
                    .unwrap()
                    .protocol_version,
                ProtocolVersion::V_2025_11_25
            );
        }
        let info = serde_json::to_value(server.get_info()).unwrap();
        assert!(info["capabilities"]["tools"].is_object());
        assert_eq!(info["capabilities"]["resources"], json!({}));
        assert!(info["capabilities"].get("tasks").is_none());
    }

    fn request(id: Value, method: &str) -> Value {
        json!({"jsonrpc":"2.0","id":id,"method":method})
    }
    fn ready() -> Admission {
        let mut state = Admission::default();
        state.accept(&request(json!("init"), "initialize")).unwrap();
        state
            .sent(&json!({"jsonrpc":"2.0","id":"init","result":{}}))
            .unwrap();
        state
            .accept(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .unwrap();
        state
    }
    #[test]
    fn admission_requires_complete_handshake_unique_ids_and_bounded_inflight() {
        assert!(
            Admission::default()
                .accept(&request(json!(1), "tools/list"))
                .is_err()
        );
        let mut state = Admission::default();
        state.accept(&request(json!("init"), "initialize")).unwrap();
        assert!(
            state
                .accept(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
                .is_err()
        );
        let mut state = ready();
        for id in 0..MAX_REQUESTS {
            state.accept(&request(json!(id), "tools/list")).unwrap();
        }
        assert!(state.accept(&request(json!(99), "tools/list")).is_err());
        state
            .sent(&json!({"jsonrpc":"2.0","id":0,"result":{}}))
            .unwrap();
        assert!(state.accept(&request(json!(0), "tools/list")).is_err());
        for id in 1..MAX_REQUESTS {
            state.accept(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":id}})).unwrap();
        }
        assert!(state.pending.is_empty());
        state.accept(&request(json!(100), "tools/list")).unwrap();
        for value in [
            request(Value::Null, "tools/list"),
            request(json!(1.5), "tools/list"),
            request(json!("x".repeat(129)), "tools/list"),
            request(json!("second"), "initialize"),
            request(json!("new-profile"), "discover"),
            json!([]),
            json!({"jsonrpc":"2.0","method":"tools/call"}),
            json!({"jsonrpc":"2.0","id":90,"method":"tools/list","principal":"administrator"}),
        ] {
            assert!(ready().accept(&value).is_err());
        }
        let mut state = ready();
        state.frames = MAX_SESSION_FRAMES;
        assert_eq!(
            state.accept(&request(json!(9), "ping")),
            Err(FacadeError::SessionExpired)
        );
    }

    #[tokio::test]
    async fn malformed_arguments_and_principal_injection_never_dispatch() {
        let spy = spy();
        let server = facade(spy.clone());
        assert!(server.prepare_call("FN02", Some(Map::new())).is_err());
        assert!(
            server
                .prepare_call("unknown.tool", Some(Map::new()))
                .is_err()
        );
        for mut input in [json!({}), prefab()] {
            input["principal"] = json!("administrator");
            let result = server
                .execute(function("prefab.validate"), input, std::future::pending())
                .await;
            assert_eq!(result.is_error, Some(true));
            assert_eq!(error_text(&result)["code"], "INVALID_INPUT");
        }
        assert_eq!(spy.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn successful_call_uses_one_coordinator_and_equal_structured_text_wire() {
        let spy = spy();
        let server = facade(spy.clone());
        let result = server
            .execute(
                function("prefab.validate"),
                prefab(),
                std::future::pending(),
            )
            .await;
        assert_eq!(result.is_error, Some(false));
        assert_eq!(
            error_text(&result),
            result.structured_content.clone().unwrap()
        );
        assert_eq!(spy.calls.load(Ordering::SeqCst), 1);
        let unknown =
            parse_json(include_bytes!("../../../examples/operation-unknown.json")).unwrap();
        let result = success_result(unknown.clone()).unwrap();
        assert_eq!(result.is_error, Some(false));
        assert_eq!(result.structured_content, Some(unknown));
    }

    #[tokio::test]
    async fn delivery_unknown_and_invalid_response_do_not_resend_or_invent_success() {
        for invalid_output in [false, true] {
            let spy = Arc::new(Spy {
                calls: AtomicUsize::new(0),
                delivery_unknown: !invalid_output,
                invalid_output,
            });
            let server = facade(spy.clone());
            let result = server
                .execute(
                    function("prefab.validate"),
                    prefab(),
                    std::future::pending(),
                )
                .await;
            assert_eq!(result.is_error, Some(true));
            assert!(result.structured_content.is_none());
            let text = error_text(&result);
            assert_eq!(text["automaticRetry"], false);
            assert_eq!(text["inspectDurableOperation"], true);
            assert_eq!(
                text["code"],
                if invalid_output {
                    "INVALID_RESPONSE"
                } else {
                    "DELIVERY_UNKNOWN"
                }
            );
            assert_eq!(spy.calls.load(Ordering::SeqCst), 1);
        }
        let result = client_error(ClientError::Remote {
            code: -32000,
            application_code: Some("INJECT\nsecret".into()),
            message: "untrusted credential=never-echo".into(),
        });
        let encoded = encode_json(&serde_json::to_value(result).unwrap()).unwrap();
        assert!(!String::from_utf8(encoded).unwrap().contains("never-echo"));
        for code in [
            "OUTCOME_UNKNOWN",
            "OUTPUT_SCHEMA_INVALID",
            "BUDGET_EXCEEDED",
        ] {
            let result = client_error(ClientError::Remote {
                code: -32000,
                application_code: Some(code.into()),
                message: "private untrusted message".into(),
            });
            assert_eq!(error_text(&result)["inspectDurableOperation"], true);
        }
    }

    #[tokio::test]
    async fn busy_worker_rejects_dispatch_and_success_checks_combined_wire_size() {
        let spy = spy();
        let server = facade(spy.clone());
        let permit = server.calls.acquire().await.unwrap();
        let result = server
            .execute(
                function("prefab.validate"),
                prefab(),
                std::future::pending(),
            )
            .await;
        assert_eq!(error_text(&result)["code"], "SERVER_BUSY");
        assert_eq!(spy.calls.load(Ordering::SeqCst), 0);
        drop(permit);
        let output = json!({"body":"a".repeat(MAX_FRAME_BYTES / 2 + 512)});
        assert!(bounded_json(&output).is_ok());
        assert!(success_result(output).is_err());
        assert!(bounded_json(&json!(vec![0; MAX_FRAME_NODES])).is_err());
    }

    // Existing artifact reader tests own actual CAS/ACL behavior. These spies
    // exercise only the new URI/protocol projection and shared worker boundary;
    // a returned fixture is not a native authorization or game observation.
    fn artifact_uri(offset: u64, limit: u64) -> String {
        format!(
            "{ARTIFACT_URI_PREFIX}context-artifact-test/resource-artifact-test/{}/{offset}/{limit}",
            raw_digest(b"actual artifact")
        )
    }
    fn artifact_output() -> Value {
        json!({"resource":{"resourceId":"resource-artifact-test","sha256":raw_digest(b"actual artifact"),"mediaType":"text/plain","sizeBytes":15},
            "offset":"0","encoding":"utf8","data":"actual artifact","nextOffset":null})
    }
    struct ArtifactSpy {
        calls: Mutex<Vec<(String, Value)>>,
        output: Value,
        denied: bool,
        gate: Option<Arc<ArtifactWorkerGate>>,
    }
    struct ArtifactWorkerGate {
        entered: AtomicBool,
        released: Mutex<bool>,
        changed: std::sync::Condvar,
    }
    impl CoordinatorPort for ArtifactSpy {
        fn call(&self, method: &str, input: &Value) -> Result<Value, ClientError> {
            self.calls
                .lock()
                .unwrap()
                .push((method.into(), input.clone()));
            if let Some(gate) = &self.gate {
                gate.entered.store(true, Ordering::Release);
                let released = gate.released.lock().unwrap();
                let (released, _) = gate
                    .changed
                    .wait_timeout_while(released, Duration::from_secs(5), |value| !*value)
                    .unwrap();
                if !*released {
                    return Err(ClientError::Unavailable);
                }
            }
            if self.denied {
                Err(ClientError::Remote {
                    code: -32000,
                    application_code: Some("RESOURCE_FORBIDDEN".into()),
                    message: "private untrusted authentication detail".into(),
                })
            } else {
                Ok(self.output.clone())
            }
        }
    }
    fn artifact_spy(output: Value) -> Arc<ArtifactSpy> {
        Arc::new(ArtifactSpy {
            calls: Mutex::new(Vec::new()),
            output,
            denied: false,
            gate: None,
        })
    }
    fn artifact_facade(spy: Arc<ArtifactSpy>) -> McpFacade {
        McpFacade {
            catalog: Arc::new(Catalog::new().unwrap()),
            coordinator: spy,
            calls: Arc::new(Semaphore::new(1)),
            stopping: Arc::new(AtomicBool::new(false)),
        }
    }
    #[test]
    fn artifact_locator_uses_canonical_contract_id_digest_and_decimal_forms() {
        let uri = artifact_uri(0, 65_536);
        let locator = ArtifactLocator::parse(&uri).unwrap();
        assert_eq!(locator.uri(), uri);
        assert_eq!(
            locator.request(),
            json!({"contextId":"context-artifact-test","resourceId":"resource-artifact-test","offset":"0","limitBytes":65_536})
        );
        ContractValidator::shared()
            .unwrap()
            .validate("ArtifactReadRequest", &locator.request())
            .unwrap();
        let digest = raw_digest(b"actual artifact").to_string();
        // Stable IDs admit ':'. RFC 6570 reserved expansion preserves that
        // exact character; simple expansion would introduce rejected aliases.
        let namespaced = format!("{ARTIFACT_URI_PREFIX}context:local/resource:local/{digest}/0/1");
        let namespaced = ArtifactLocator::parse(&namespaced).unwrap();
        assert_eq!(namespaced.context.as_str(), "context:local");
        assert_eq!(namespaced.resource.as_str(), "resource:local");
        assert!(ARTIFACT_URI_TEMPLATE.contains("{+contextId}/{+resourceId}"));
        let invalid = [
            "file:///private/local-artifact".into(),
            uri.replace("mmmm://", "https://"),
            uri.replace("artifact/", "catalog/"),
            uri.replace("context-artifact-test", "Context-artifact-test"),
            uri.replace("context-artifact-test", "context%2fartifact"),
            uri.replace(&digest, &digest.to_ascii_uppercase()),
            format!("{uri}/extra"),
            format!("{uri}?authorization=never-echo"),
            format!("{ARTIFACT_URI_PREFIX}context/resource/{digest}/00/1"),
            format!("{ARTIFACT_URI_PREFIX}context/resource/{digest}/+1/1"),
            format!("{ARTIFACT_URI_PREFIX}context/resource/{digest}/0/0"),
            format!("{ARTIFACT_URI_PREFIX}context/resource/{digest}/0/65537"),
            format!("{ARTIFACT_URI_PREFIX}context/resource/{digest}/18446744073709551616/1"),
            artifact_uri(u64::MAX, 1),
            "x".repeat(513),
        ];
        for uri in invalid {
            let error = match ArtifactLocator::parse(&uri) {
                Err(error) => error,
                Ok(_) => panic!("Invalid locator admitted"),
            };
            assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
            assert_eq!(error.message, "Invalid canonical artifact resource locator");
            assert!(error.data.is_none());
        }
    }
    #[test]
    fn artifact_slice_becomes_actual_mime_text_or_blob_with_exact_range_metadata() {
        let locator = ArtifactLocator::parse(&artifact_uri(0, 65_536)).unwrap();
        let text =
            serde_json::to_value(artifact_resource_result(&locator, artifact_output()).unwrap())
                .unwrap();
        assert_eq!(text["contents"][0]["text"], "actual artifact");
        assert_eq!(text["contents"][0]["mimeType"], "text/plain");
        assert!(text.get("resultType").is_none());
        assert!(text["contents"][0].get("blob").is_none());
        let metadata = &text["contents"][0]["_meta"]["io.github.daejunnom.mmmm/artifactSlice"];
        assert_eq!(metadata["sliceBytes"], 15);
        assert_eq!(metadata["offset"], "0");
        assert!(metadata["nextOffset"].is_null());
        let mut partial = artifact_output();
        partial["data"] = json!("act");
        partial["nextOffset"] = json!("3");
        let locator = ArtifactLocator::parse(&artifact_uri(0, 3)).unwrap();
        let partial =
            serde_json::to_value(artifact_resource_result(&locator, partial).unwrap()).unwrap();
        assert_eq!(
            partial["contents"][0]["_meta"]["io.github.daejunnom.mmmm/artifactSlice"]["nextOffset"],
            "3"
        );
        let mut binary = artifact_output();
        binary["resource"]["mediaType"] = json!("application/octet-stream");
        binary["resource"]["sizeBytes"] = json!(2);
        binary["resource"]["sha256"] = json!(raw_digest(&[255, 0]));
        binary["encoding"] = json!("base64");
        binary["data"] = json!("/wA=");
        let uri = format!(
            "{ARTIFACT_URI_PREFIX}context-artifact-test/resource-artifact-test/{}/0/65536",
            raw_digest(&[255, 0])
        );
        let locator = ArtifactLocator::parse(&uri).unwrap();
        let blob =
            serde_json::to_value(artifact_resource_result(&locator, binary).unwrap()).unwrap();
        assert_eq!(blob["contents"][0]["blob"], "/wA=");
        assert_eq!(blob["contents"][0]["mimeType"], "application/octet-stream");
        assert!(blob["contents"][0].get("text").is_none());
        let mut empty = artifact_output();
        empty["offset"] = json!("15");
        empty["data"] = json!("");
        let locator = ArtifactLocator::parse(&artifact_uri(15, 1)).unwrap();
        assert!(artifact_resource_result(&locator, empty).is_ok());
    }
    #[test]
    fn artifact_slice_withholds_wrong_identity_digest_offset_length_or_next_offset() {
        let locator = ArtifactLocator::parse(&artifact_uri(0, 65_536)).unwrap();
        for field in 0..8 {
            let mut output = artifact_output();
            match field {
                0 => output["resource"]["resourceId"] = json!("another-resource"),
                1 => output["resource"]["sha256"] = json!("a".repeat(64)),
                2 => output["offset"] = json!("1"),
                3 => output["data"] = json!("short"),
                4 => output["data"] = json!("too long for the actual resource"),
                5 => output["nextOffset"] = json!("15"),
                6 => output["resource"]["mediaType"] = json!(""),
                _ => output["resource"]["sizeBytes"] = json!(14),
            }
            assert!(artifact_resource_result(&locator, output).is_err());
        }
        let mut oversized = artifact_output();
        oversized["resource"]["mediaType"] = json!("x".repeat(MAX_FRAME_BYTES));
        assert!(artifact_resource_result(&locator, oversized).is_err());
        let locator = ArtifactLocator::parse(&artifact_uri(16, 1)).unwrap();
        assert!(artifact_resource_result(&locator, artifact_output()).is_err());
    }
    #[test]
    fn artifact_base64_is_standard_canonical_and_bounded() {
        for (value, bytes) in [("", 0), ("/w==", 1), ("/wA=", 2), ("YWJj", 3)] {
            assert_eq!(artifact_base64_length(value), Some(bytes));
        }
        for value in [
            "/x==", "/wB=", "YW=J", "====", "YWJj\n", "_w==", "YQ", "YQ===",
        ] {
            assert_eq!(artifact_base64_length(value), None);
        }
        assert!(artifact_base64_length(&"A".repeat(87_388)).is_none());
        let locator = ArtifactLocator::parse(&artifact_uri(0, 65_536)).unwrap();
        let mut invalid = artifact_output();
        invalid["resource"]["sizeBytes"] = json!(1);
        invalid["encoding"] = json!("base64");
        for data in ["/x==", "/wA=", "YQ", "\n/w=="] {
            invalid["data"] = json!(data);
            assert!(artifact_resource_result(&locator, invalid.clone()).is_err());
        }
    }
    #[test]
    fn artifact_resource_inventory_is_empty_and_template_is_only_a_locator() {
        let list = serde_json::to_value(artifact_resource_list(None).unwrap()).unwrap();
        assert_eq!(list["resources"], json!([]));
        assert!(list.get("nextCursor").is_none());
        assert!(list.get("resultType").is_none());
        let templates = serde_json::to_value(resource_templates(None).unwrap()).unwrap();
        assert_eq!(templates["resourceTemplates"].as_array().unwrap().len(), 2);
        assert_eq!(
            templates["resourceTemplates"][0]["uriTemplate"],
            ARTIFACT_URI_TEMPLATE
        );
        assert!(templates.get("resultType").is_none());
        for cursor in ["", "invented-cursor"] {
            assert!(artifact_resource_list(Some(cursor)).is_err());
            assert!(resource_templates(Some(cursor)).is_err());
        }
    }
    #[tokio::test]
    async fn artifact_read_calls_original_fn31_once_and_preserves_coordinator_denial() {
        let spy = artifact_spy(artifact_output());
        let server = artifact_facade(spy.clone());
        server
            .read_artifact(
                ReadResourceRequestParams::new(artifact_uri(0, 65_536)),
                std::future::pending(),
            )
            .await
            .unwrap();
        assert_eq!(
            *spy.calls.lock().unwrap(),
            vec![(
                "artifact.read".into(),
                json!({"contextId":"context-artifact-test","resourceId":"resource-artifact-test","offset":"0","limitBytes":65_536})
            )]
        );
        let denied = Arc::new(ArtifactSpy {
            calls: Mutex::new(Vec::new()),
            output: artifact_output(),
            denied: true,
            gate: None,
        });
        let server = artifact_facade(denied.clone());
        let error = server
            .read_artifact(
                ReadResourceRequestParams::new(artifact_uri(0, 65_536)),
                std::future::pending(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.data.as_ref().unwrap()["code"], "RESOURCE_FORBIDDEN");
        assert!(
            !serde_json::to_string(&error)
                .unwrap()
                .contains("private untrusted")
        );
        assert_eq!(denied.calls.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn artifact_invalid_locator_mrtr_and_busy_state_do_not_dispatch() {
        let spy = artifact_spy(artifact_output());
        let server = artifact_facade(spy.clone());
        assert!(
            server
                .read_artifact(
                    ReadResourceRequestParams::new("file:///never-echo"),
                    std::future::pending()
                )
                .await
                .is_err()
        );
        for field in ["requestState", "inputResponses"] {
            let mut request = json!({"uri":artifact_uri(0,65_536)});
            request[field] = if field == "requestState" {
                json!("unsupported")
            } else {
                json!({})
            };
            let request = serde_json::from_value(request).unwrap();
            assert!(
                server
                    .read_artifact(request, std::future::pending())
                    .await
                    .is_err()
            );
        }
        let permit = server.calls.acquire().await.unwrap();
        let error = server
            .read_artifact(
                ReadResourceRequestParams::new(artifact_uri(0, 65_536)),
                std::future::pending(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.data.as_ref().unwrap()["code"], "SERVER_BUSY");
        assert!(spy.calls.lock().unwrap().is_empty());
        drop(permit);
    }
    #[tokio::test]
    async fn canceled_registered_resource_worker_keeps_shared_tool_and_drain_permit_until_actual_return()
     {
        for (uri, output) in [
            (artifact_uri(0, 65_536), artifact_output()),
            (catalog_uri().to_owned(), catalog_record(false)),
        ] {
            let gate = Arc::new(ArtifactWorkerGate {
                entered: AtomicBool::new(false),
                released: Mutex::new(false),
                changed: std::sync::Condvar::new(),
            });
            let spy = Arc::new(ArtifactSpy {
                calls: Mutex::new(Vec::new()),
                output,
                denied: false,
                gate: Some(gate.clone()),
            });
            let server = Arc::new(artifact_facade(spy.clone()));
            let (cancel, cancelled) = tokio::sync::oneshot::channel::<()>();
            let reader = server.clone();
            let running = tokio::spawn(async move {
                reader
                    .read_registered_resource(ReadResourceRequestParams::new(uri), async {
                        let _ = cancelled.await;
                    })
                    .await
            });
            tokio::time::timeout(Duration::from_secs(3), async {
                while !gate.entered.load(Ordering::Acquire) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .unwrap();
            cancel.send(()).unwrap();
            assert!(
                tokio::time::timeout(Duration::from_secs(3), running)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
            assert_eq!(server.calls.available_permits(), 0);
            let tool = server
                .execute(
                    function("prefab.validate"),
                    prefab(),
                    std::future::pending(),
                )
                .await;
            assert_eq!(error_text(&tool)["code"], "SERVER_BUSY");
            *gate.released.lock().unwrap() = true;
            gate.changed.notify_all();
            let permit = tokio::time::timeout(Duration::from_secs(3), server.calls.acquire())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(spy.calls.lock().unwrap().len(), 1);
            drop(permit);
        }
    }

    fn catalog_record(unknown: bool) -> Value {
        let bytes: &[u8] = if unknown {
            include_bytes!("../../../examples/data-record-unknown.json")
        } else {
            include_bytes!("../../../examples/data-record-known.json")
        };
        parse_json(bytes).unwrap()
    }
    fn catalog_uri() -> &'static str {
        "mmmm://catalog/snapshot-fixture/minecraft%3Ablock/minecraft%3Astone?contextId=context-fixture"
    }
    #[test]
    fn catalog_locator_is_exact_fn21_with_explicit_context_and_encoded_namespaced_segments() {
        let locator = CatalogLocator::parse(catalog_uri()).unwrap();
        assert_eq!(locator.uri(), catalog_uri());
        assert_eq!(
            locator.request(),
            json!({"snapshotId":"snapshot-fixture","kind":"minecraft:block","resourceId":"minecraft:stone","contextId":"context-fixture"})
        );
        ContractValidator::shared()
            .unwrap()
            .validate("RecordQuery", &locator.request())
            .unwrap();
        let uri = "mmmm://catalog/snapshot:local/mmmm%3Ablock%2Fdefinition/minecraft%3Apath%2Fname?contextId=context:local";
        let locator = CatalogLocator::parse(uri).unwrap();
        assert_eq!(locator.uri(), uri);
        assert_eq!(
            locator.request(),
            json!({"snapshotId":"snapshot:local","kind":"mmmm:block/definition","resourceId":"minecraft:path/name","contextId":"context:local"})
        );
        assert_eq!(
            CATALOG_URI_TEMPLATE,
            "mmmm://catalog/{+snapshotId}/{kind}/{resourceId}?contextId={+contextId}"
        );
        // Query and record catalog IDs are ResourceLocation, not FN31 opaque IDs.
        assert!(ResourceId::new("minecraft:path/name").is_err());
        assert_eq!(
            catalog_component_encode("minecraft:path/name"),
            "minecraft%3Apath%2Fname"
        );
    }
    #[test]
    fn catalog_locator_rejects_missing_guessed_context_aliases_and_extra_query_fields() {
        let invalid = [
            catalog_uri().replace("?contextId=context-fixture", ""),
            catalog_uri().replace("context-fixture", ""),
            catalog_uri().replace("snapshot-fixture", "Snapshot-fixture"),
            catalog_uri().replace("snapshot-fixture", "snapshot%3Afixture"),
            catalog_uri().replace("context-fixture", "context%3Afixture"),
            catalog_uri().replace("%3A", ":"),
            catalog_uri().replace("%3A", "%3a"),
            catalog_uri().replace("minecraft%3Astone", "minecraft%253Astone"),
            catalog_uri().replace("minecraft%3Astone", "%6Dinecraft%3Astone"),
            catalog_uri().replace("minecraft%3Astone", "minecraft%3Apath/name"),
            catalog_uri().replace("minecraft%3Astone", "minecraft%3Astone%"),
            catalog_uri().replace("minecraft%3Astone", "minecraft%3Astone%A"),
            catalog_uri().replace("minecraft%3Astone", "minecraft%3Astone%ZZ"),
            catalog_uri().replace("minecraft%3Astone", "minecraft%3A%ED%95%9C"),
            catalog_uri().replace("mmmm://catalog/", "file:///"),
            format!("{}&contextId=context-other", catalog_uri()),
            format!("{}&offset=0", catalog_uri()),
            format!("{}#never-echo", catalog_uri()),
            "x".repeat(MAX_FRAME_BYTES + 1),
        ];
        for uri in invalid {
            let error = match CatalogLocator::parse(&uri) {
                Err(error) => error,
                Ok(_) => panic!("Invalid catalog locator admitted"),
            };
            assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
            assert_eq!(
                error.message,
                "Invalid canonical catalog record locator with explicit context"
            );
            assert!(error.data.is_none());
        }
    }
    #[test]
    fn catalog_resource_preserves_complete_known_unknown_record_and_utf8_byte_count() {
        for unknown in [false, true] {
            let record = catalog_record(unknown);
            let uri = if unknown {
                catalog_uri().replace("minecraft%3Ablock", "mmmm%3Amass_density")
            } else {
                catalog_uri().into()
            };
            let locator = CatalogLocator::parse(&uri).unwrap();
            let result =
                serde_json::to_value(catalog_resource_result(&locator, record.clone()).unwrap())
                    .unwrap();
            let content = &result["contents"][0];
            assert_eq!(content["mimeType"], "application/json");
            assert_eq!(content["uri"], uri);
            let text = content["text"].as_str().unwrap();
            assert_eq!(parse_json(text.as_bytes()).unwrap(), record);
            assert_eq!(
                content["_meta"]["io.github.daejunnom.mmmm/catalogRecord"]["recordBytes"],
                text.len()
            );
            assert_eq!(
                content["_meta"]["io.github.daejunnom.mmmm/catalogRecord"]["contextId"],
                "context-fixture"
            );
            assert!(content.get("blob").is_none());
            assert!(result.get("resultType").is_none());
            if unknown {
                assert!(record.get("value").is_none());
                assert!(record.get("reason").is_some());
            }
        }
    }
    #[test]
    fn catalog_resource_rejects_wrong_snapshot_kind_resource_schema_and_escaped_output_budget() {
        let locator = CatalogLocator::parse(catalog_uri()).unwrap();
        for field in 0..6 {
            let mut record = catalog_record(false);
            match field {
                0 => record["snapshotId"] = json!("snapshot-other"),
                1 => record["kind"] = json!("minecraft:item"),
                2 => record["resourceId"] = json!("minecraft:dirt"),
                3 => record["valueType"] = json!(""),
                4 => record["contractVersion"] = json!("0.3.0"),
                _ => record["unknownField"] = json!(true),
            }
            assert!(catalog_resource_result(&locator, record).is_err());
        }
        let mut oversized = catalog_record(false);
        oversized["value"] = json!("\"".repeat(MAX_FRAME_BYTES / 3));
        assert!(bounded_json(&oversized).is_ok());
        assert!(catalog_resource_result(&locator, oversized).is_err());
        let mut too_many_nodes = catalog_record(false);
        too_many_nodes["value"] = json!(vec![0; MAX_FRAME_NODES]);
        assert!(catalog_resource_result(&locator, too_many_nodes).is_err());
    }
    #[tokio::test]
    async fn catalog_resource_routes_once_to_original_fn21_and_preserves_denial() {
        let spy = artifact_spy(catalog_record(false));
        let server = artifact_facade(spy.clone());
        server
            .read_registered_resource(
                ReadResourceRequestParams::new(catalog_uri()),
                std::future::pending(),
            )
            .await
            .unwrap();
        assert_eq!(
            *spy.calls.lock().unwrap(),
            vec![(
                "catalog.describe".into(),
                json!({"snapshotId":"snapshot-fixture","kind":"minecraft:block","resourceId":"minecraft:stone","contextId":"context-fixture"})
            )]
        );
        let denied = Arc::new(ArtifactSpy {
            calls: Mutex::new(Vec::new()),
            output: catalog_record(false),
            denied: true,
            gate: None,
        });
        let server = artifact_facade(denied.clone());
        let error = server
            .read_registered_resource(
                ReadResourceRequestParams::new(catalog_uri()),
                std::future::pending(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.data.as_ref().unwrap()["code"], "RESOURCE_FORBIDDEN");
        assert!(
            !serde_json::to_string(&error)
                .unwrap()
                .contains("private untrusted")
        );
        assert_eq!(denied.calls.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn catalog_uri_mrtr_busy_and_wrong_return_do_not_fall_back_capture_or_stage() {
        let spy = artifact_spy(catalog_record(false));
        let server = artifact_facade(spy.clone());
        for uri in [
            catalog_uri().replace("?contextId=context-fixture", ""),
            "file:///never-echo".into(),
        ] {
            assert!(
                server
                    .read_registered_resource(
                        ReadResourceRequestParams::new(uri),
                        std::future::pending()
                    )
                    .await
                    .is_err()
            );
        }
        for field in ["inputResponses", "requestState"] {
            let mut request = json!({"uri":catalog_uri()});
            request[field] = if field == "requestState" {
                json!("unsupported")
            } else {
                json!({})
            };
            assert!(
                server
                    .read_registered_resource(
                        serde_json::from_value(request).unwrap(),
                        std::future::pending()
                    )
                    .await
                    .is_err()
            );
        }
        let permit = server.calls.acquire().await.unwrap();
        let error = server
            .read_registered_resource(
                ReadResourceRequestParams::new(catalog_uri()),
                std::future::pending(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.data.as_ref().unwrap()["code"], "SERVER_BUSY");
        assert!(spy.calls.lock().unwrap().is_empty());
        drop(permit);
        let mut wrong = catalog_record(false);
        wrong["snapshotId"] = json!("snapshot-other");
        let spy = artifact_spy(wrong);
        let server = artifact_facade(spy.clone());
        assert!(
            server
                .read_registered_resource(
                    ReadResourceRequestParams::new(catalog_uri()),
                    std::future::pending()
                )
                .await
                .is_err()
        );
        assert_eq!(spy.calls.lock().unwrap().len(), 1);
        assert_eq!(spy.calls.lock().unwrap()[0].0, "catalog.describe");
    }

    #[derive(Default)]
    struct RamIo {
        incoming: Mutex<VecDeque<Vec<u8>>>,
        written: Mutex<Vec<Vec<u8>>>,
        eof_after_writes: usize,
        drained: AtomicUsize,
        fail_write: bool,
        write_delay: Duration,
        active_writes: AtomicUsize,
        maximum_writes: AtomicUsize,
    }
    impl FiniteIoPort for RamIo {
        fn read_line(
            &self,
            deadline: Instant,
            cancel: Arc<AtomicBool>,
        ) -> IoFuture<'_, Option<Vec<u8>>> {
            Box::pin(async move {
                loop {
                    if cancel.load(Ordering::Acquire) {
                        return Ok(None);
                    }
                    if let Some(frame) = self.incoming.lock().unwrap().pop_front() {
                        return Ok(Some(frame));
                    }
                    if self.written.lock().unwrap().len() >= self.eof_after_writes {
                        return Ok(None);
                    }
                    if Instant::now() >= deadline {
                        return Err(FacadeError::Io);
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
        }
        fn write_line(
            &self,
            line: Vec<u8>,
            _deadline: Instant,
            _cancel: Arc<AtomicBool>,
        ) -> IoFuture<'_, ()> {
            Box::pin(async move {
                if self.fail_write {
                    return Err(FacadeError::Io);
                }
                struct WriteGuard<'a>(&'a AtomicUsize);
                impl Drop for WriteGuard<'_> {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::SeqCst);
                    }
                }
                let active = self.active_writes.fetch_add(1, Ordering::SeqCst) + 1;
                self.maximum_writes.fetch_max(active, Ordering::SeqCst);
                let _guard = WriteGuard(&self.active_writes);
                tokio::time::sleep(self.write_delay).await;
                assert!(!line.contains(&b'\n'));
                self.written.lock().unwrap().push(line);
                Ok(())
            })
        }
        fn cancel_and_drain(&self, _deadline: Instant) -> IoFuture<'_, ()> {
            Box::pin(async move {
                self.drained.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
        fn force_cancel_and_drain(&self, _deadline: Instant) -> Result<(), FacadeError> {
            self.drained.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    #[tokio::test]
    async fn rmcp_roundtrip_initialization_and_list_use_bounded_finite_port() {
        let frames = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"RAM protocol fixture","version":"1"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        ];
        let io = Arc::new(RamIo {
            incoming: Mutex::new(
                frames
                    .iter()
                    .map(|value| encode_json(value).unwrap())
                    .collect(),
            ),
            eof_after_writes: 2,
            ..RamIo::default()
        });
        let spy = spy();
        tokio::time::timeout(
            Duration::from_secs(3),
            serve_facade(facade(spy.clone()), io.clone()),
        )
        .await
        .unwrap()
        .unwrap();
        let frames = io.written.lock().unwrap();
        assert_eq!(frames.len(), 2);
        let init = parse_json_with_limits(&frames[0], limits()).unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-11-25");
        let list = parse_json_with_limits(&frames[1], limits()).unwrap();
        assert!(list["result"]["tools"].as_array().unwrap().len() <= MAX_PAGE_TOOLS);
        assert!(list["result"].get("resultType").is_none());
        assert!(io.drained.load(Ordering::SeqCst) >= 1);
        assert_eq!(spy.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn rmcp_artifact_resources_roundtrip_uses_empty_index_template_and_real_slice_shape() {
        let uri = artifact_uri(0, 65_536);
        let frames = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"RAM artifact protocol fixture","version":"1"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"resources/list"}),
            json!({"jsonrpc":"2.0","id":3,"method":"resources/templates/list"}),
            json!({"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":uri}}),
        ];
        let io = Arc::new(RamIo {
            incoming: Mutex::new(
                frames
                    .iter()
                    .map(|frame| encode_json(frame).unwrap())
                    .collect(),
            ),
            eof_after_writes: 4,
            ..RamIo::default()
        });
        let spy = artifact_spy(artifact_output());
        tokio::time::timeout(
            Duration::from_secs(3),
            serve_facade(artifact_facade(spy.clone()), io.clone()),
        )
        .await
        .unwrap()
        .unwrap();
        let written = io.written.lock().unwrap();
        assert_eq!(written.len(), 4);
        let frames: BTreeMap<_, _> = written
            .iter()
            .map(|frame| {
                let value = parse_json_with_limits(frame, limits()).unwrap();
                (value["id"].as_i64().unwrap(), value)
            })
            .collect();
        assert_eq!(frames[&1]["result"]["capabilities"]["resources"], json!({}));
        assert_eq!(frames[&2]["result"]["resources"], json!([]));
        assert_eq!(
            frames[&3]["result"]["resourceTemplates"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            frames[&4]["result"]["contents"][0]["text"],
            "actual artifact"
        );
        assert_eq!(
            frames[&4]["result"]["contents"][0]["mimeType"],
            "text/plain"
        );
        assert_eq!(frames[&4]["result"]["contents"][0]["uri"], uri);
        for frame in frames.values() {
            assert!(frame["result"].get("resultType").is_none());
        }
        assert_eq!(spy.calls.lock().unwrap().len(), 1);
        assert!(io.drained.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn rmcp_catalog_resource_roundtrip_is_one_original_record_and_one_fn21_call() {
        let frames = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"RAM catalog protocol check","version":"1"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":catalog_uri()}}),
        ];
        let io = Arc::new(RamIo {
            incoming: Mutex::new(
                frames
                    .iter()
                    .map(|frame| encode_json(frame).unwrap())
                    .collect(),
            ),
            eof_after_writes: 2,
            ..RamIo::default()
        });
        let record = catalog_record(false);
        let spy = artifact_spy(record.clone());
        tokio::time::timeout(
            Duration::from_secs(3),
            serve_facade(artifact_facade(spy.clone()), io.clone()),
        )
        .await
        .unwrap()
        .unwrap();
        let written = io.written.lock().unwrap();
        assert_eq!(written.len(), 2);
        let response = written
            .iter()
            .map(|frame| parse_json_with_limits(frame, limits()).unwrap())
            .find(|frame| frame["id"] == 2)
            .unwrap();
        let content = &response["result"]["contents"][0];
        assert_eq!(content["uri"], catalog_uri());
        assert_eq!(content["mimeType"], "application/json");
        assert_eq!(
            parse_json(content["text"].as_str().unwrap().as_bytes()).unwrap(),
            record
        );
        assert!(response["result"].get("resultType").is_none());
        assert_eq!(spy.calls.lock().unwrap().len(), 1);
        assert_eq!(spy.calls.lock().unwrap()[0].0, "catalog.describe");
        assert!(io.drained.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn malformed_frames_stop_before_sdk_or_coordinator_dispatch() {
        for bytes in [
            br#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"initialize"}"#.to_vec(),
            br#"[{"jsonrpc":"2.0","id":1,"method":"initialize"}]"#.to_vec(),
            b"{\"jsonrpc\":\"2.0\",\n\"id\":1}".to_vec(),
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"x":"\ud800"}}"#.to_vec(),
        ] {
            let io = Arc::new(RamIo {
                incoming: Mutex::new(VecDeque::from([bytes])),
                ..RamIo::default()
            });
            let state = Arc::new(Mutex::new(Admission::default()));
            let mut transport = BoundedTransport {
                io: io.clone(),
                cancel: Arc::new(AtomicBool::new(false)),
                admission: state.clone(),
                output: Arc::new(Semaphore::new(1)),
                deadline: Instant::now() + Duration::from_secs(1),
            };
            assert!(transport.receive().await.is_none());
            assert_eq!(state.lock().unwrap().failure, Some(FacadeError::InputFrame));
            transport.close().await.unwrap();
            assert_eq!(io.drained.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn failed_output_immediately_closes_ingress_and_nested_sdk_failure_is_not_success() {
        let io = Arc::new(RamIo {
            incoming: Mutex::new(VecDeque::from([encode_json(&request(
                json!(9),
                "tools/list",
            ))
            .unwrap()])),
            fail_write: true,
            ..RamIo::default()
        });
        let cancel = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(ready()));
        let mut transport = BoundedTransport {
            io: io.clone(),
            cancel: cancel.clone(),
            admission: state.clone(),
            output: Arc::new(Semaphore::new(1)),
            deadline: Instant::now() + Duration::from_secs(1),
        };
        let response =
            serde_json::from_value(json!({"jsonrpc":"2.0","id":"init","result":{}})).unwrap();
        assert_eq!(transport.send(response).await, Err(FacadeError::Io));
        assert!(cancel.load(Ordering::Acquire));
        assert!(transport.receive().await.is_none());
        assert_eq!(io.incoming.lock().unwrap().len(), 1);
        let failure = tokio::spawn(async { panic!("explicit protocol-worker panic fixture") })
            .await
            .unwrap_err();
        assert_eq!(
            checked_quit(Ok(rmcp::service::QuitReason::JoinError(failure))),
            Err(FacadeError::Runtime)
        );
        transport.close().await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_sdk_sends_and_rejection_share_one_output_transaction() {
        let io = Arc::new(RamIo {
            write_delay: Duration::from_millis(15),
            ..RamIo::default()
        });
        let cancel = Arc::new(AtomicBool::new(false));
        let output = Arc::new(Semaphore::new(1));
        let mut state = ready();
        state.accept(&request(json!(41), "ping")).unwrap();
        state.accept(&request(json!(42), "ping")).unwrap();
        let mut transport = BoundedTransport {
            io: io.clone(),
            cancel: cancel.clone(),
            admission: Arc::new(Mutex::new(state)),
            output: output.clone(),
            deadline: Instant::now() + Duration::from_secs(1),
        };
        let first = transport
            .send(serde_json::from_value(json!({"jsonrpc":"2.0","id":41,"result":{}})).unwrap());
        let second = transport
            .send(serde_json::from_value(json!({"jsonrpc":"2.0","id":42,"result":{}})).unwrap());
        let rejection = io_write(io.as_ref(), encode_json(&json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Invalid JSON"}})).unwrap(), Instant::now() + Duration::from_secs(1), cancel, output.as_ref());
        let results = tokio::join!(first, second, rejection);
        assert!(results.0.is_ok() && results.1.is_ok() && results.2.is_ok());
        assert_eq!(io.maximum_writes.load(Ordering::SeqCst), 1);
        assert_eq!(io.active_writes.load(Ordering::SeqCst), 0);
        {
            let written = io.written.lock().unwrap();
            assert_eq!(written.len(), 3);
            for frame in written.iter() {
                parse_json_with_limits(frame, limits()).unwrap();
            }
        }
        transport.close().await.unwrap();
    }
}

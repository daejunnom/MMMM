//! MCP 2025-11-25 facade. rmcp owns protocol dispatch; the canonical contract
//! owns DTO validation and the Coordinator owns every operation and world effect.
//! This module never opens the application store or creates a second journal.
//!
//! Profile references: modelcontextprotocol.io/specification/2025-11-25/
//! {basic/lifecycle,basic/transports,server/tools,server/utilities/pagination}.
//! SDK API is pinned to modelcontextprotocol/rust-sdk tag rmcp-v3.5.1.

use mmmm_contracts::{
    CANONICAL_SCHEMA, ContractValidator, FUNCTION_INDEX, FunctionContract, JsonLimits, encode_json,
    parse_json, parse_json_with_limits, raw_digest,
};
use mmmm_coordinator::{CoordinatorClient, client::ClientError};
use rmcp::{
    ErrorData, ServerHandler, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorCode,
        Implementation, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
        ServerCapabilities, ServerConfig, Tool,
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
                let mut page = ListToolsResult::default();
                page.result_type = None;
                page.tools = tools[start..end].to_vec();
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
fn client_error(error: ClientError) -> CallToolResult {
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
            return tool_error(
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
    tool_error(code, message, uncertain)
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
        if self.stopping.load(Ordering::Acquire) {
            return tool_error(
                "FACADE_STOPPING",
                "The facade is closing; no request was dispatched",
                false,
            );
        }
        let validator = match ContractValidator::shared() {
            Ok(value) => value,
            Err(_) => {
                return tool_error("INTERNAL_ERROR", "Canonical validator unavailable", false);
            }
        };
        if bounded_json(&input).is_err() || validator.validate(&function.input, &input).is_err() {
            return tool_error(
                "INVALID_INPUT",
                "Arguments violate the canonical function contract",
                false,
            );
        }
        let permit = match self.calls.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return tool_error(
                    "SERVER_BUSY",
                    "One Coordinator call is already running; no request was dispatched",
                    false,
                );
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
                return tool_error("DELIVERY_UNKNOWN", "Call canceled locally; application effects are not proven stopped. Inspect the durable operation", true);
            }
            result = tokio::time::timeout(CALL_DEADLINE, worker) => match result {
                Ok(Ok(Ok(output))) => output,
                Ok(Ok(Err(error))) => return client_error(error),
                _ => return tool_error("DELIVERY_UNKNOWN", "Coordinator call did not return a verified result; inspect the durable operation", true),
            }
        };
        if validator.validate(&function.output, &output).is_err() {
            return client_error(ClientError::InvalidResponse);
        }
        success_result(output).unwrap_or_else(|_| tool_error("OUTPUT_LIMIT", "Result exceeded the MCP wire limit; inspect the durable operation before retrying a write", true))
    }
}
impl ServerHandler for McpFacade {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_server_info(Implementation::new("MMMM", env!("CARGO_PKG_VERSION")))
            .with_instructions("MMMM uses canonical contract 0.2.0 through the shared local Coordinator. This facade supports MCP 2025-11-25 only. Use the canonical function name and DTO. Transport success preserves reported operation status; unknown write delivery requires durable operation inspection before retry.")
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
                .accept(&value).map_err(|error| {
                    if error == FacadeError::InputFrame && !is_notification {
                        rejection = Some(json!({"jsonrpc":"2.0","id":reply_id,"error":{"code":-32600,"message":"Invalid bounded JSON-RPC request"}}));
                    }
                    error
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
        let written = io.written.lock().unwrap();
        assert_eq!(written.len(), 3);
        for frame in written.iter() {
            parse_json_with_limits(frame, limits()).unwrap();
        }
        drop(written);
        transport.close().await.unwrap();
    }
}

//! CLI JSON and output use the same isolated native stdio owner as MCP. A held
//! external stdin or stdout cannot leave a blocked thread in the CLI process.
use mmmm_contracts::{JsonLimits, encode_json, parse_json_with_limits};
use mmmm_coordinator::{
    CoordinatorClient,
    client::ClientError,
    stdio_io::{NativeStdioPort, StdioError, StdioLimits, StdioOutput},
};
use serde_json::Value;
use std::{
    fmt::{self, Write as _},
    path::Path,
    sync::atomic::AtomicBool,
    task::Poll,
    time::{Duration, Instant},
};

const MAX_BYTES: usize = 1024 * 1024;
const WHOLE: Duration = Duration::from_secs(70);
const INPUT: Duration = Duration::from_secs(10);
const OUTPUT: Duration = Duration::from_secs(5);
const DRAIN: Duration = Duration::from_secs(5);
const PEER: Duration = Duration::from_secs(5);
const RPC: Duration = Duration::from_secs(35);
const PUBLIC_BYTES: usize = 64 * 1024;
const DIAGNOSTIC_BYTES: usize = 4 * 1024;
const DIAGNOSTIC_WHOLE: Duration = Duration::from_secs(3);
const DIAGNOSTIC_DRAIN: Duration = Duration::from_secs(1);
const POLL: Duration = Duration::from_millis(5);

#[derive(Debug)]
pub enum CommandIoError {
    Input,
    Output,
    Deadline,
    Client(ClientError),
    Stdio(StdioError),
    DrainUncertain,
    Cleanup {
        primary: Option<Box<CommandIoError>>,
        cleanup: Box<CommandIoError>,
    },
}
impl std::fmt::Display for CommandIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input => f.write_str("CLI input is not one bounded canonical JSON request"),
            Self::Output => f.write_str("CLI public output exceeds its bounded profile"),
            Self::Deadline => f.write_str("CLI input or output deadline reached"),
            Self::Client(ClientError::Remote { code, .. }) => {
                write!(f, "Coordinator rejected the request (RPC code {code})")
            }
            Self::Client(error) => error.fmt(f),
            Self::Stdio(error) => error.fmt(f),
            Self::DrainUncertain => {
                f.write_str("CLI native stdio owner termination is unconfirmed")
            }
            Self::Cleanup { primary, cleanup } => {
                if let Some(primary) = primary {
                    write!(f, "{primary}; ")?;
                }
                write!(f, "CLI stdio cleanup failed: {cleanup}")
            }
        }
    }
}
impl std::error::Error for CommandIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::Stdio(error) => Some(error),
            Self::Cleanup { cleanup, .. } => Some(cleanup.as_ref()),
            Self::Input | Self::Output | Self::Deadline | Self::DrainUncertain => None,
        }
    }
}

/// One explicit JSON function request. The helper owns only external stdio;
/// authentication and dispatch still go through the singleton Coordinator.
/// A lost result never causes a resend or a new idempotency identity.
pub fn call(method: &str, root: &Path, summary: bool) -> Result<(), CommandIoError> {
    let deadline = Instant::now() + WHOLE;
    let work_deadline = deadline - DRAIN;
    let native = NativeStdioPort::spawn_current_with_deadline(
        StdioLimits {
            session: WHOLE,
            startup: Duration::from_secs(5),
            max_frames: 65_536,
            max_input_bytes: MAX_BYTES as u64,
            max_output_bytes: MAX_BYTES as u64 + 1,
        },
        deadline,
    )
    .map_err(CommandIoError::Stdio)?;
    let cancel = AtomicBool::new(false);
    let result = execute(&native, method, root, summary, work_deadline, &cancel);
    // Both success and error must prove owned native death. A response may
    // already have been flushed, so failed drain cannot be claimed as success.
    match drain(&native, deadline.min(Instant::now() + DRAIN)) {
        Ok(()) => result,
        Err(cleanup) => Err(CommandIoError::Cleanup {
            primary: result.err().map(Box::new),
            cleanup: Box::new(cleanup),
        }),
    }
}
fn execute(
    native: &NativeStdioPort,
    method: &str,
    root: &Path,
    summary: bool,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<(), CommandIoError> {
    let input_deadline = deadline.min(Instant::now() + INPUT);
    let mut input = Vec::new();
    loop {
        check(input_deadline)?;
        match native
            .poll_read_line(input_deadline, cancel)
            .map_err(CommandIoError::Stdio)?
        {
            Poll::Ready(Some(line)) => append_line(&mut input, &line)?,
            Poll::Ready(None) => break,
            Poll::Pending => std::thread::sleep(POLL),
        }
    }
    let value = parse_json_with_limits(
        &input,
        JsonLimits {
            max_bytes: MAX_BYTES,
            max_depth: 64,
            max_nodes: 4096,
        },
    )
    .map_err(|_| CommandIoError::Input)?;
    // These existing client APIs have independent fixed maxima. Do not enter
    // them unless the original command can cover peer discovery, RPC, output
    // and the separately reserved native-owner drain without a reset.
    if deadline.saturating_duration_since(Instant::now()) < PEER + RPC + OUTPUT {
        return Err(CommandIoError::Deadline);
    }
    let client =
        CoordinatorClient::discover_peer(&root.join("runtime")).map_err(CommandIoError::Client)?;
    let output = client
        .call(method, &value)
        .map_err(CommandIoError::Client)?;
    check(deadline)?;
    let bytes = if summary {
        summary_bytes(method, &output)
    } else {
        encode_json(&output).map_err(|_| CommandIoError::Input)?
    };
    if bytes.len() > MAX_BYTES {
        return Err(CommandIoError::Input);
    }
    let output_deadline = deadline.min(Instant::now() + OUTPUT);
    loop {
        check(output_deadline)?;
        match native
            .poll_write_line(&bytes, output_deadline, cancel)
            .map_err(CommandIoError::Stdio)?
        {
            Poll::Ready(()) => return Ok(()), // actual external stdout flush ACK
            Poll::Pending => std::thread::sleep(POLL),
        }
    }
}
fn append_line(input: &mut Vec<u8>, line: &[u8]) -> Result<(), CommandIoError> {
    let length = input
        .len()
        .checked_add(line.len())
        .and_then(|n| n.checked_add(1))
        .ok_or(CommandIoError::Input)?;
    if length > MAX_BYTES {
        return Err(CommandIoError::Input);
    }
    input.extend_from_slice(line);
    // Line separators occur outside a valid JSON string. Reconstructing them
    // preserves JSON whitespace and prevents concatenating adjacent tokens.
    input.push(b'\n');
    Ok(())
}
fn summary_bytes(method: &str, output: &Value) -> Vec<u8> {
    let method = method.escape_debug();
    if let Some(status) = output.get("status").and_then(Value::as_str) {
        format!("{method}: {}", status.escape_debug()).into_bytes()
    } else if let Some(state) = output.get("state").and_then(Value::as_str) {
        format!("{method}: {}", state.escape_debug()).into_bytes()
    } else {
        format!("{method}: 응답을 받았습니다. 전체 결과는 --json으로 확인하세요.").into_bytes()
    }
}

/// Output-only raw mode never speculatively consumes inherited stdin.
pub fn public_output(bytes: &[u8]) -> Result<(), CommandIoError> {
    if bytes.is_empty() || bytes.len() > PUBLIC_BYTES {
        return Err(CommandIoError::Output);
    }
    let started = Instant::now();
    let deadline = started + OUTPUT + DRAIN;
    let output_deadline = started + OUTPUT;
    let native = NativeStdioPort::spawn_current_raw_with_deadline(
        StdioLimits {
            session: OUTPUT + DRAIN,
            startup: Duration::from_secs(2),
            max_frames: 1,
            max_input_bytes: 1,
            max_output_bytes: PUBLIC_BYTES as u64,
        },
        deadline,
    )
    .map_err(CommandIoError::Stdio)?;
    write_raw_and_drain(&native, bytes, output_deadline, deadline)
}

/// Only main's sanitized public Display is accepted. Formatting is capped
/// before allocation; neither Debug nor the source chain is serialized.
pub fn diagnostic(error: &impl fmt::Display) -> Result<(), CommandIoError> {
    let mut text = BoundedDiagnostic(String::with_capacity(DIAGNOSTIC_BYTES));
    let _ = write!(&mut text, "{error}");
    text.0.push('\n');
    let started = Instant::now();
    let deadline = started + DIAGNOSTIC_WHOLE;
    let output_deadline = deadline - DIAGNOSTIC_DRAIN;
    let native = NativeStdioPort::spawn_current_raw_output_with_deadline(
        StdioLimits {
            session: DIAGNOSTIC_WHOLE,
            startup: Duration::from_millis(500),
            max_frames: 1,
            max_input_bytes: 1,
            max_output_bytes: DIAGNOSTIC_BYTES as u64,
        },
        StdioOutput::Stderr,
        deadline,
    )
    .map_err(CommandIoError::Stdio)?;
    write_raw_and_drain(&native, text.0.as_bytes(), output_deadline, deadline)
}

struct BoundedDiagnostic(String);
impl fmt::Write for BoundedDiagnostic {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let remaining = (DIAGNOSTIC_BYTES - 1).saturating_sub(self.0.len());
        if text.len() <= remaining {
            self.0.push_str(text);
            return Ok(());
        }
        let mut end = remaining.min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        self.0.push_str(&text[..end]);
        Err(fmt::Error)
    }
}

fn write_raw_and_drain(
    native: &NativeStdioPort,
    bytes: &[u8],
    output_deadline: Instant,
    drain_deadline: Instant,
) -> Result<(), CommandIoError> {
    let cancel = AtomicBool::new(false);
    let result = (|| loop {
        check(output_deadline)?;
        match native
            .poll_write_raw(bytes, output_deadline, &cancel)
            .map_err(CommandIoError::Stdio)?
        {
            Poll::Ready(()) => return Ok(()),
            Poll::Pending => std::thread::sleep(POLL),
        }
    })();
    match drain(native, drain_deadline) {
        Ok(()) => result,
        Err(cleanup) => Err(CommandIoError::Cleanup {
            primary: result.err().map(Box::new),
            cleanup: Box::new(cleanup),
        }),
    }
}
fn check(deadline: Instant) -> Result<(), CommandIoError> {
    if Instant::now() >= deadline {
        Err(CommandIoError::Deadline)
    } else {
        Ok(())
    }
}
fn drain(native: &NativeStdioPort, deadline: Instant) -> Result<(), CommandIoError> {
    loop {
        if Instant::now() >= deadline {
            return Err(CommandIoError::DrainUncertain);
        }
        match native
            .poll_cancel_and_drain(deadline)
            .map_err(CommandIoError::Stdio)?
        {
            Poll::Ready(result) if result.terminated && result.exit_code.is_some() => return Ok(()),
            Poll::Ready(_) => return Err(CommandIoError::DrainUncertain),
            Poll::Pending => std::thread::sleep(POLL),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multiline_json_keeps_token_separators_and_rejects_extra_objects() {
        let mut input = Vec::new();
        for line in [b"{".as_slice(), b"\"value\": [1, 2]", b"}"] {
            append_line(&mut input, line).unwrap();
        }
        assert!(parse_json_with_limits(&input, JsonLimits::default()).is_ok());
        append_line(&mut input, b"{}").unwrap();
        assert!(parse_json_with_limits(&input, JsonLimits::default()).is_err());
        let mut split = Vec::new();
        append_line(&mut split, b"1").unwrap();
        append_line(&mut split, b"2").unwrap();
        assert!(parse_json_with_limits(&split, JsonLimits::default()).is_err());
    }
    #[test]
    fn aggregate_limit_and_summary_preserve_outcome_unknown() {
        let mut input = vec![b' '; MAX_BYTES - 1];
        assert!(append_line(&mut input, b"{}").is_err());
        assert_eq!(input.len(), MAX_BYTES - 1);
        let summary = summary_bytes(
            "operation.get",
            &serde_json::json!({"state":"outcome_unknown"}),
        );
        assert_eq!(summary, b"operation.get: outcome_unknown");
    }
}

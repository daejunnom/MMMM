//! Deliberately narrow HTTP/1.1 framing for local JSON-RPC. No redirect, proxy,
//! chunking, compression, CORS, upgrade, keep-alive, or pipelined request path.
use crate::{
    auth::SessionAuthority,
    rpc::{MAX_CONTROL_BYTES, handle_rpc},
    service::{RequestBudget, ServiceDispatcher},
};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_HEADERS: usize = 32;

pub(crate) struct HttpRequest {
    pub bearer: Zeroizing<String>,
    pub body: Vec<u8>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    Malformed,
    Unauthorized,
    Budget,
    Origin,
    Io,
}
impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "Invalid local HTTP request",
            Self::Unauthorized => "Local authentication required",
            Self::Budget => "Local transport budget reached",
            Self::Origin => "Local origin is not allowed",
            Self::Io => "Local transport I/O failed",
        })
    }
}
impl std::error::Error for HttpError {}

pub struct LoopbackServer {
    listener: TcpListener,
    address: SocketAddr,
    epoch: String,
    ingress_timeout: Duration,
    request_timeout: Duration,
}
impl LoopbackServer {
    pub fn bind() -> io::Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let mut random = [0; 16];
        getrandom::fill(&mut random)
            .map_err(|_| io::Error::other("Local generation randomness unavailable"))?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            listener,
            address,
            epoch: format!("coordinator-{suffix}"),
            ingress_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
        })
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn epoch(&self) -> &str {
        &self.epoch
    }
    /// Only one service call can mutate the store. The OS backlog is not an
    /// application work queue; no unbounded threads or request tasks are spawned.
    pub fn serve(
        &self,
        authority: &SessionAuthority,
        dispatcher: &mut dyn ServiceDispatcher,
        stop: Arc<AtomicBool>,
    ) -> io::Result<()> {
        while !stop.load(Ordering::Acquire) && !crate::peer::fatal_stop_requested() {
            if !self.serve_one(authority, dispatcher, &stop)? {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if crate::peer::fatal_stop_requested() {
            Err(io::Error::other(
                "Local bootstrap native completion is unresolved",
            ))
        } else {
            Ok(())
        }
    }
    /// One finite admission/call cycle. Native management composition uses the
    /// gaps between cycles to borrow the same store; no application call is
    /// interrupted or executed concurrently with a pairing authority change.
    pub(crate) fn serve_one(
        &self,
        authority: &SessionAuthority,
        dispatcher: &mut dyn ServiceDispatcher,
        stop: &Arc<AtomicBool>,
    ) -> io::Result<bool> {
        self.serve_one_bounded(authority, dispatcher, stop, None)
    }
    pub(crate) fn serve_one_until(
        &self,
        authority: &SessionAuthority,
        dispatcher: &mut dyn ServiceDispatcher,
        stop: &Arc<AtomicBool>,
        deadline: Instant,
    ) -> io::Result<bool> {
        self.serve_one_bounded(authority, dispatcher, stop, Some(deadline))
    }
    fn serve_one_bounded(
        &self,
        authority: &SessionAuthority,
        dispatcher: &mut dyn ServiceDispatcher,
        stop: &Arc<AtomicBool>,
        lifetime: Option<Instant>,
    ) -> io::Result<bool> {
        let cap = |deadline: Instant| lifetime.map_or(deadline, |limit| deadline.min(limit));
        if lifetime.is_some_and(|deadline| Instant::now() >= deadline) {
            return Ok(false);
        }
        if stop.load(Ordering::Acquire) {
            return Ok(false);
        }
        if crate::peer::fatal_stop_requested() {
            return Err(io::Error::other(
                "Local bootstrap native completion is unresolved",
            ));
        }
        match self.listener.accept() {
            Ok((mut stream, peer)) => {
                if !peer.ip().is_loopback() {
                    return Ok(true);
                }
                stream.set_nodelay(true)?;
                let deadline = cap(Instant::now() + self.ingress_timeout);
                let request = read_request(&mut stream, self.address, &self.epoch, deadline, &stop);
                match request {
                    Ok(request) => {
                        // Authentication occurs before parsing function DTOs,
                        // touching SQLite, or acquiring any application queue.
                        match authority.authenticate(&request.bearer) {
                            Ok(principal) => {
                                if crate::peer::fatal_stop_requested() {
                                    return Err(io::Error::other(
                                        "Local bootstrap native completion is unresolved",
                                    ));
                                }
                                let request_deadline = cap(Instant::now() + self.request_timeout);
                                if Instant::now() >= request_deadline {
                                    return Ok(true);
                                }
                                let budget =
                                    RequestBudget::until(request_deadline, Arc::clone(stop))
                                        .map_err(|_| {
                                            io::Error::other("Invalid server request budget")
                                        })?;
                                let response =
                                    handle_rpc(dispatcher, &principal, &request.body, &budget);
                                // Failure to deliver this response does not
                                // cancel, replay, or overwrite a durable result.
                                let _ = write_response(
                                    &mut stream,
                                    200,
                                    &response,
                                    cap(Instant::now() + self.ingress_timeout),
                                );
                            }
                            Err(_) => {
                                let _ = reject(
                                    &mut stream,
                                    401,
                                    cap(Instant::now() + self.ingress_timeout),
                                );
                            }
                        }
                    }
                    Err(error) => {
                        let status = match error {
                            HttpError::Unauthorized => 401,
                            HttpError::Budget => 408,
                            HttpError::Origin => 403,
                            _ => 400,
                        };
                        let _ = reject(
                            &mut stream,
                            status,
                            cap(Instant::now() + self.ingress_timeout),
                        );
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) => return Err(e),
        }
        Ok(true)
    }
}

pub(crate) fn read_request(
    stream: &mut TcpStream,
    expected: SocketAddr,
    expected_epoch: &str,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<HttpRequest, HttpError> {
    let header = read_header(stream, deadline, cancel)?;
    let text = std::str::from_utf8(&header).map_err(|_| HttpError::Malformed)?;
    let (first, headers) = parse_headers(text)?;
    if first != "POST /rpc HTTP/1.1" {
        return Err(HttpError::Malformed);
    }
    if headers.get("host").map(|v| v.as_str()) != Some(expected.to_string().as_str()) {
        return Err(HttpError::Origin);
    }
    if headers.get("x-mmmm-epoch").map(|v| v.as_str()) != Some(expected_epoch) {
        return Err(HttpError::Origin);
    }
    if headers.contains_key("origin")
        || headers.contains_key("referer")
        || headers.contains_key("sec-fetch-site")
    {
        return Err(HttpError::Origin);
    }
    if headers.keys().any(|k| {
        !matches!(
            k.as_str(),
            "host"
                | "authorization"
                | "content-type"
                | "content-length"
                | "connection"
                | "accept"
                | "x-mmmm-epoch"
        )
    }) {
        return Err(HttpError::Malformed);
    }
    if headers.get("content-type").map(|v| v.as_str()) != Some("application/json")
        || headers
            .get("connection")
            .is_some_and(|v| !v.eq_ignore_ascii_case("close"))
    {
        return Err(HttpError::Malformed);
    }
    let length = content_length(&headers)?;
    let authorization = headers
        .get("authorization")
        .ok_or(HttpError::Unauthorized)?;
    let bearer = authorization
        .strip_prefix("Bearer ")
        .ok_or(HttpError::Unauthorized)?;
    if bearer.len() != 64
        || !bearer
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(HttpError::Unauthorized);
    }
    let bearer = Zeroizing::new(bearer.to_owned());
    let mut body = vec![0; length];
    read_exact_deadline(stream, &mut body, deadline, cancel)?;
    Ok(HttpRequest { bearer, body })
}

pub(crate) fn read_header(
    stream: &mut TcpStream,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Zeroizing<Vec<u8>>, HttpError> {
    let mut header = Zeroizing::new(Vec::with_capacity(1024));
    loop {
        if header.len() >= MAX_HEADER_BYTES {
            return Err(HttpError::Budget);
        }
        let mut byte = [0];
        read_exact_deadline(stream, &mut byte, deadline, cancel)?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
}
fn read_exact_deadline(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<(), HttpError> {
    let mut offset = 0;
    while offset < bytes.len() {
        if cancel.load(Ordering::Acquire) {
            return Err(HttpError::Budget);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(HttpError::Budget)?;
        stream
            .set_read_timeout(Some(remaining.min(Duration::from_millis(250))))
            .map_err(|_| HttpError::Io)?;
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => return Err(HttpError::Malformed),
            Ok(count) => offset += count,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                ()
            }
            Err(_) => return Err(HttpError::Io),
        }
    }
    Ok(())
}

pub(crate) fn parse_headers(
    text: &str,
) -> Result<(&str, BTreeMap<String, Zeroizing<String>>), HttpError> {
    if !text.ends_with("\r\n\r\n") || !text.is_ascii() {
        return Err(HttpError::Malformed);
    }
    let mut lines = text[..text.len() - 4].split("\r\n");
    let first = lines.next().ok_or(HttpError::Malformed)?;
    let mut headers = BTreeMap::new();
    for line in lines {
        if headers.len() >= MAX_HEADERS || line.starts_with([' ', '\t']) {
            return Err(HttpError::Malformed);
        }
        let (name, value) = line.split_once(':').ok_or(HttpError::Malformed)?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(HttpError::Malformed);
        }
        let value = value.trim_matches(' ');
        if value.is_empty() || value.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(HttpError::Malformed);
        }
        if headers
            .insert(name.to_ascii_lowercase(), Zeroizing::new(value.to_owned()))
            .is_some()
        {
            return Err(HttpError::Malformed);
        }
    }
    Ok((first, headers))
}
pub(crate) fn content_length(
    headers: &BTreeMap<String, Zeroizing<String>>,
) -> Result<usize, HttpError> {
    let value = headers.get("content-length").ok_or(HttpError::Malformed)?;
    if value.len() > 8
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(HttpError::Malformed);
    }
    let length = value.parse::<usize>().map_err(|_| HttpError::Malformed)?;
    if length > MAX_CONTROL_BYTES {
        return Err(HttpError::Budget);
    }
    Ok(length)
}
pub(crate) fn write_response(
    stream: &mut TcpStream,
    status: u16,
    body: &[u8],
    deadline: Instant,
) -> Result<(), HttpError> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        408 => "Request Timeout",
        _ => "Internal Server Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    );
    write_deadline(stream, header.as_bytes(), deadline)?;
    write_deadline(stream, body, deadline)
}
pub(crate) fn write_deadline(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), HttpError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(HttpError::Budget)?;
        stream
            .set_write_timeout(Some(remaining.min(Duration::from_millis(250))))
            .map_err(|_| HttpError::Io)?;
        match stream.write(&bytes[offset..]) {
            Ok(0) => return Err(HttpError::Io),
            Ok(count) => offset += count,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                ()
            }
            Err(_) => return Err(HttpError::Io),
        }
    }
    Ok(())
}
fn reject(stream: &mut TcpStream, status: u16, deadline: Instant) -> Result<(), HttpError> {
    write_response(
        stream,
        status,
        br#"{"error":"Local request rejected"}"#,
        deadline,
    )
}
pub(crate) fn read_response_body(
    stream: &mut TcpStream,
    length: usize,
    deadline: Instant,
) -> Result<Vec<u8>, HttpError> {
    let mut body = vec![0; length];
    read_exact_deadline(stream, &mut body, deadline, &AtomicBool::new(false))?;
    Ok(body)
}

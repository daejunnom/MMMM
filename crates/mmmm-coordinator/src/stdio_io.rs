//! Finite MCP stdio boundary. Blocking external stdio belongs exclusively to
//! an owned helper process; the Coordinator polls a private nonblocking socket.
//! Output is acknowledged only after the helper flushed the actual stdout.
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fs::File,
    io::{self, BufRead, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::{Duration, Instant},
};
use zeroize::Zeroize;

#[cfg(windows)]
#[path = "stdio_io_windows.rs"]
mod native;
#[cfg(unix)]
#[path = "stdio_io_unix.rs"]
mod native;

pub const WORKER_COMMAND: &str = "--mmmm-stdio-worker";
const MAGIC: &[u8; 8] = b"MMMMIO01";
const FRAME_LIMIT: usize = 1_048_576;
const WORK_BATCH: usize = 65_536;
const QUEUE_LIMIT: usize = 4 * FRAME_LIMIT;
const HEADER: usize = 13;
const INPUT: u8 = 1;
const EOF: u8 = 2;
const ACK: u8 = 3;
const FAULT: u8 = 4;
const OUTPUT: u8 = 5;
const RAW_OUTPUT: u8 = 6;
const READ_EXACT: u8 = 7;
const RAW_INPUT: u8 = 8;
const TRUNCATED: u8 = 9;
const RAW_EOF: u8 = 10;
const RAW_MODE_FLAG: u64 = 1 << 63;
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Lines,
    Raw,
}

/// Deployment policy supplies finite limits; callers cannot expand them past
/// the supported product maxima. There is no background unbounded I/O task.
#[derive(Clone, Copy, Debug)]
pub struct StdioLimits {
    pub session: Duration,
    pub startup: Duration,
    pub max_frames: u64,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
}
impl Default for StdioLimits {
    fn default() -> Self {
        Self {
            session: Duration::from_secs(1800),
            startup: Duration::from_secs(5),
            max_frames: 4096,
            max_input_bytes: 64 * 1024 * 1024,
            max_output_bytes: 64 * 1024 * 1024,
        }
    }
}
impl StdioLimits {
    fn validate(self) -> Result<Self, StdioError> {
        if self.session < Duration::from_millis(1)
            || self.session > Duration::from_secs(3600)
            || self.startup.is_zero()
            || self.startup > Duration::from_secs(10)
            || self.max_frames == 0
            || self.max_frames > 65_536
            || self.max_input_bytes == 0
            || self.max_input_bytes > 256 * 1024 * 1024
            || self.max_output_bytes == 0
            || self.max_output_bytes > 256 * 1024 * 1024
        {
            return Err(StdioError::new("limits"));
        }
        Ok(self)
    }
}

/// Contains static safe diagnostics only: no capability, frame, path, command,
/// inherited environment, or OS message is included in public errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdioError {
    pub code: &'static str,
    pub drained: bool,
    pub native_code: Option<i32>,
}
impl StdioError {
    fn new(code: &'static str) -> Self {
        Self {
            code,
            drained: false,
            native_code: None,
        }
    }
    fn io(code: &'static str, error: io::Error) -> Self {
        Self {
            code,
            drained: false,
            native_code: error.raw_os_error(),
        }
    }
}
impl std::fmt::Display for StdioError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "finite stdio: {}", self.code)
    }
}
impl std::error::Error for StdioError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdioDrain {
    pub exit_code: Option<i32>,
    pub terminated: bool,
}

struct Executable {
    path: PathBuf,
    file: File,
    digest: [u8; 32],
}
impl Executable {
    fn current() -> Result<Self, StdioError> {
        let path = std::env::current_exe().map_err(|_| StdioError::new("executable"))?;
        let path = path
            .canonicalize()
            .map_err(|_| StdioError::new("executable"))?;
        let mut file = native::open_executable(&path)?;
        let metadata = file.metadata().map_err(|_| StdioError::new("executable"))?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 256 * 1024 * 1024 {
            return Err(StdioError::new("executable"));
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; WORK_BATCH];
        let mut bytes = 0u64;
        loop {
            let n = file
                .read(&mut buffer)
                .map_err(|_| StdioError::new("executable"))?;
            if n == 0 {
                break;
            }
            bytes += n as u64;
            if bytes > metadata.len() {
                return Err(StdioError::new("executable_changed"));
            }
            hasher.update(&buffer[..n]);
        }
        if bytes != metadata.len() || !native::same_file(&file, &path)? {
            return Err(StdioError::new("executable_changed"));
        }
        Ok(Self {
            path,
            file,
            digest: hasher.finalize().into(),
        })
    }
}

struct PendingWrite {
    id: u64,
    frame: zeroize::Zeroizing<Vec<u8>>,
    sent: usize,
    acknowledged: bool,
}
struct PendingRead {
    id: u64,
    size: usize,
    frame: Vec<u8>,
    sent: usize,
    response: Option<Option<zeroize::Zeroizing<Vec<u8>>>>,
}
struct Bridge {
    process: native::Process,
    _executable: Executable,
    socket: TcpStream,
    limits: StdioLimits,
    mode: Mode,
    expires: Instant,
    receive: zeroize::Zeroizing<Vec<u8>>,
    lines: VecDeque<Vec<u8>>,
    queued: usize,
    input_count: u64,
    input_bytes: u64,
    output_count: u64,
    output_bytes: u64,
    input_eof: bool,
    pending: Option<PendingWrite>,
    pending_read: Option<PendingRead>,
    failure: Option<StdioError>,
    draining: bool,
    empty_observed: Option<Instant>,
    drained: Option<StdioDrain>,
}

/// Poll methods perform bounded nonblocking work. The async facade schedules
/// the next poll and owns its deadline/cancellation; no Tokio stdin is used.
pub struct NativeStdioPort {
    bridge: Mutex<Bridge>,
}
impl NativeStdioPort {
    pub fn spawn_current(limits: StdioLimits) -> Result<Self, StdioError> {
        Self::spawn(limits, Mode::Lines)
    }
    /// Raw stdio uses pull-based exact reads and writes with no terminator or
    /// Unicode transformation. Capability bytes never enter public JSON.
    pub fn spawn_current_raw(limits: StdioLimits) -> Result<Self, StdioError> {
        Self::spawn(limits, Mode::Raw)
    }
    fn spawn(limits: StdioLimits, mode: Mode) -> Result<Self, StdioError> {
        let limits = limits.validate()?;
        let executable = Executable::current()?;
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| StdioError::new("channel"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| StdioError::new("channel"))?;
        let address = listener
            .local_addr()
            .map_err(|_| StdioError::new("channel"))?;
        let mut capability = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut capability[..]).map_err(|_| StdioError::new("random"))?;
        let mut packet = zeroize::Zeroizing::new(Vec::with_capacity(96));
        packet.extend_from_slice(&capability[..]);
        packet.extend_from_slice(&executable.digest);
        for value in [
            limits.session.as_millis() as u64 | if mode == Mode::Raw { RAW_MODE_FLAG } else { 0 },
            limits.max_frames,
            limits.max_input_bytes,
            limits.max_output_bytes,
        ] {
            packet.extend_from_slice(&value.to_be_bytes());
        }
        let spawned = native::Process::spawn(&executable, address, &packet);
        packet.zeroize();
        let mut process = match spawned {
            Ok(p) => p,
            Err(e) => {
                capability.zeroize();
                return Err(e);
            }
        };
        let deadline = Instant::now() + limits.startup;
        let result = authenticate_worker(
            &listener,
            &mut process,
            &capability,
            &executable.digest,
            deadline,
        );
        capability.zeroize();
        let socket = match result {
            Ok(socket) => socket,
            Err(mut error) => {
                error.drained = process
                    .drain_blocking(Instant::now() + Duration::from_secs(5))
                    .is_ok();
                return Err(error);
            }
        };
        Ok(Self {
            bridge: Mutex::new(Bridge {
                process,
                _executable: executable,
                socket,
                limits,
                mode,
                expires: Instant::now() + limits.session,
                receive: zeroize::Zeroizing::new(Vec::with_capacity(WORK_BATCH)),
                lines: VecDeque::new(),
                queued: 0,
                input_count: 0,
                input_bytes: 0,
                output_count: 0,
                output_bytes: 0,
                input_eof: false,
                pending: None,
                pending_read: None,
                failure: None,
                draining: false,
                empty_observed: None,
                drained: None,
            }),
        })
    }
    pub fn poll_read_line(
        &self,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Poll<Option<Vec<u8>>>, StdioError> {
        let mut bridge = self
            .bridge
            .lock()
            .map_err(|_| StdioError::new("poisoned"))?;
        if bridge.mode != Mode::Lines {
            return bridge.fail("mode");
        }
        bridge.check(deadline, cancel)?;
        bridge.pump()?;
        bridge.check(deadline, cancel)?;
        if let Some(line) = bridge.lines.pop_front() {
            bridge.queued -= line.len();
            return Ok(Poll::Ready(Some(line)));
        }
        if bridge.input_eof {
            return Ok(Poll::Ready(None));
        }
        Ok(Poll::Pending)
    }
    /// Repeated polls must supply the identical line while it is pending.
    /// Ready means stdout write AND flush completed, not socket acceptance.
    pub fn poll_write_line(
        &self,
        line: &[u8],
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Poll<()>, StdioError> {
        validate_line(line, false)?;
        self.poll_write(line, true, deadline, cancel)
    }
    pub fn poll_write_raw(
        &self,
        bytes: &[u8],
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Poll<()>, StdioError> {
        if bytes.is_empty() || bytes.len() > FRAME_LIMIT {
            return Err(StdioError::new("output_frame"));
        }
        self.poll_write(bytes, false, deadline, cancel)
    }
    fn poll_write(
        &self,
        line: &[u8],
        newline: bool,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Poll<()>, StdioError> {
        let mut bridge = self
            .bridge
            .lock()
            .map_err(|_| StdioError::new("poisoned"))?;
        if (bridge.mode == Mode::Lines) != newline {
            return bridge.fail("mode");
        }
        bridge.check(deadline, cancel)?;
        if bridge.pending_read.is_some() {
            return Ok(Poll::Pending);
        }
        if bridge.pending.is_none() {
            if bridge.output_count >= bridge.limits.max_frames
                || bridge
                    .output_bytes
                    .checked_add(line.len() as u64 + u64::from(newline))
                    .is_none_or(|n| n > bridge.limits.max_output_bytes)
            {
                return bridge.fail("output_budget");
            }
            bridge.output_count += 1;
            bridge.output_bytes += line.len() as u64 + u64::from(newline);
            let id = bridge.output_count;
            bridge.pending = Some(PendingWrite {
                id,
                frame: zeroize::Zeroizing::new(frame(
                    if newline { OUTPUT } else { RAW_OUTPUT },
                    id,
                    line,
                )),
                sent: 0,
                acknowledged: false,
            });
        }
        if bridge
            .pending
            .as_ref()
            .is_some_and(|p| p.frame[HEADER..] != *line)
        {
            return bridge.fail("concurrent_output");
        }
        bridge.pump()?;
        let mut pending = bridge
            .pending
            .take()
            .ok_or_else(|| StdioError::new("output_state"))?;
        if pending.acknowledged {
            bridge.check(deadline, cancel)?;
            return Ok(Poll::Ready(()));
        }
        if pending.sent == pending.frame.len() {
            // The helper can be blocked in external stdout while its socket
            // accepted the whole frame. Never treat an empty write as EOF or
            // completion: continue waiting for the actual flush ACK.
            bridge.pending = Some(pending);
            return Ok(Poll::Pending);
        }
        let end = pending.frame.len().min(pending.sent + WORK_BATCH);
        match bridge.socket.write(&pending.frame[pending.sent..end]) {
            Ok(0) => {
                bridge.pending = Some(pending);
                return bridge.fail("worker_channel");
            }
            Ok(n) => pending.sent += n,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                bridge.pending = Some(pending);
                return bridge.fail("worker_channel");
            }
        }
        bridge.pending = Some(pending);
        Ok(Poll::Pending)
    }
    /// Only a requested range is captured. A partial EOF is input_truncated;
    /// None is EOF before any byte. Successful buffers zeroize on caller Drop.
    pub fn poll_read_exact(
        &self,
        size: usize,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Poll<Option<zeroize::Zeroizing<Vec<u8>>>>, StdioError> {
        if size == 0 || size > FRAME_LIMIT {
            return Err(StdioError::new("input_frame"));
        }
        let mut bridge = self
            .bridge
            .lock()
            .map_err(|_| StdioError::new("poisoned"))?;
        if bridge.mode != Mode::Raw {
            return bridge.fail("mode");
        }
        bridge.check(deadline, cancel)?;
        if bridge.pending.is_some() {
            return Ok(Poll::Pending);
        }
        if bridge.pending_read.is_none() {
            if bridge.input_eof {
                return Ok(Poll::Ready(None));
            }
            if bridge.input_count >= bridge.limits.max_frames
                || bridge
                    .input_bytes
                    .checked_add(size as u64)
                    .is_none_or(|n| n > bridge.limits.max_input_bytes)
            {
                return bridge.fail("input_budget");
            }
            bridge.input_count += 1;
            bridge.input_bytes += size as u64;
            let id = bridge.input_count;
            bridge.pending_read = Some(PendingRead {
                id,
                size,
                frame: frame(READ_EXACT, id, &(size as u32).to_be_bytes()),
                sent: 0,
                response: None,
            });
        }
        if bridge.pending_read.as_ref().is_some_and(|p| p.size != size) {
            return bridge.fail("concurrent_input");
        }
        bridge.pump()?;
        bridge.check(deadline, cancel)?;
        let mut pending = bridge
            .pending_read
            .take()
            .ok_or_else(|| StdioError::new("input_state"))?;
        if let Some(response) = pending.response.take() {
            return Ok(Poll::Ready(response));
        }
        if pending.sent < pending.frame.len() {
            match bridge.socket.write(&pending.frame[pending.sent..]) {
                Ok(0) => {
                    bridge.pending_read = Some(pending);
                    return bridge.fail("worker_channel");
                }
                Ok(n) => pending.sent += n,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    bridge.pending_read = Some(pending);
                    return bridge.fail("worker_channel");
                }
            }
        }
        bridge.pending_read = Some(pending);
        Ok(Poll::Pending)
    }
    pub fn poll_cancel_and_drain(&self, deadline: Instant) -> Result<Poll<StdioDrain>, StdioError> {
        let mut bridge = self
            .bridge
            .lock()
            .map_err(|_| StdioError::new("poisoned"))?;
        if let Some(done) = &bridge.drained {
            return Ok(Poll::Ready(done.clone()));
        }
        if !bridge.draining {
            bridge.draining = true;
            bridge.receive.zeroize();
            bridge.pending.take();
            bridge.pending_read.take();
            for line in &mut bridge.lines {
                line.zeroize();
            }
            bridge.lines.clear();
            bridge.queued = 0;
            let _ = bridge.socket.shutdown(Shutdown::Both);
            bridge.process.terminate()?;
        }
        let exited = bridge.process.exit_code()?;
        let empty = bridge.process.scope_empty()?;
        if empty && exited.is_some() {
            if let Some(observed) = bridge.empty_observed {
                if observed.elapsed() >= Duration::from_millis(10) {
                    if Instant::now() >= deadline {
                        return Err(StdioError::new("drain_uncertain"));
                    }
                    let code = bridge.process.reap()?;
                    let done = StdioDrain {
                        exit_code: code,
                        terminated: true,
                    };
                    bridge.drained = Some(done.clone());
                    if Instant::now() >= deadline {
                        return Err(StdioError {
                            code: "drain_deadline",
                            drained: true,
                            native_code: None,
                        });
                    }
                    return Ok(Poll::Ready(done));
                }
            } else {
                bridge.empty_observed = Some(Instant::now());
            }
        } else {
            bridge.empty_observed = None;
        }
        if Instant::now() >= deadline {
            return Err(StdioError::new("drain_uncertain"));
        }
        Ok(Poll::Pending)
    }
}
impl Drop for NativeStdioPort {
    fn drop(&mut self) {
        // Drop is an emergency finite drain, never a success report. Callers
        // explicitly poll_cancel_and_drain and preserve its result first.
        if let Ok(bridge) = self.bridge.get_mut() {
            let _ = bridge.socket.shutdown(Shutdown::Both);
            if bridge.drained.is_none() {
                let _ = bridge
                    .process
                    .drain_blocking(Instant::now() + Duration::from_secs(5));
            }
        }
    }
}
impl Bridge {
    fn fail<T>(&mut self, code: &'static str) -> Result<T, StdioError> {
        let error = StdioError::new(code);
        self.failure = Some(error.clone());
        Err(error)
    }
    fn check(&mut self, deadline: Instant, cancel: &AtomicBool) -> Result<(), StdioError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if self.draining {
            return Err(StdioError::new("shutdown"));
        }
        if cancel.load(Ordering::Acquire) {
            return self.fail("cancelled");
        }
        if Instant::now() >= deadline || Instant::now() >= self.expires {
            return self.fail("deadline");
        }
        if self.process.exit_code()?.is_some() {
            return self.fail("worker_exit");
        }
        Ok(())
    }
    fn pump(&mut self) -> Result<(), StdioError> {
        let mut processed = 0;
        loop {
            self.decode()?;
            if processed >= WORK_BATCH {
                return Ok(());
            }
            let mut buffer = zeroize::Zeroizing::new([0u8; 8192]);
            let available = buffer.len().min(FRAME_LIMIT + HEADER - self.receive.len());
            if available == 0 {
                return self.fail("input_frame");
            }
            match self.socket.read(&mut buffer[..available]) {
                Ok(0) => return self.fail("worker_channel"),
                Ok(n) => {
                    processed += n;
                    if self.receive.len() + n > FRAME_LIMIT + HEADER {
                        return self.fail("input_frame");
                    }
                    self.receive.extend_from_slice(&buffer[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(()),
                Err(_) => return self.fail("worker_channel"),
            }
        }
    }
    fn decode(&mut self) -> Result<(), StdioError> {
        let mut consumed = 0;
        while self.receive.len() - consumed >= HEADER {
            let header = &self.receive[consumed..consumed + HEADER];
            let tag = header[0];
            let id = u64::from_be_bytes(
                header[1..9]
                    .try_into()
                    .map_err(|_| StdioError::new("channel_frame"))?,
            );
            let n = u32::from_be_bytes(
                header[9..13]
                    .try_into()
                    .map_err(|_| StdioError::new("channel_frame"))?,
            ) as usize;
            if n > FRAME_LIMIT {
                return self.fail("input_frame");
            }
            if self.receive.len() - consumed < HEADER + n {
                break;
            }
            let payload = &self.receive[consumed + HEADER..consumed + HEADER + n];
            match tag {
                INPUT
                    if self.mode == Mode::Lines
                        && !self.input_eof
                        && id == self.input_count + 1 =>
                {
                    validate_line(payload, true)?;
                    if self.input_count >= self.limits.max_frames
                        || self
                            .input_bytes
                            .checked_add(n as u64 + 1)
                            .is_none_or(|v| v > self.limits.max_input_bytes)
                        || self.lines.len() >= 32
                        || self.queued + n > QUEUE_LIMIT
                    {
                        return self.fail("input_budget");
                    }
                    self.input_count += 1;
                    self.input_bytes += n as u64 + 1;
                    self.queued += n;
                    self.lines.push_back(payload.to_vec());
                }
                EOF if self.mode == Mode::Lines
                    && !self.input_eof
                    && n == 0
                    && id == self.input_count =>
                {
                    self.input_eof = true
                }
                RAW_INPUT if self.mode == Mode::Raw => {
                    let Some(pending) = self.pending_read.as_mut() else {
                        return self.fail("channel_frame");
                    };
                    if pending.id != id
                        || pending.size != n
                        || pending.sent != pending.frame.len()
                        || pending.response.is_some()
                    {
                        return self.fail("channel_frame");
                    }
                    pending.response = Some(Some(zeroize::Zeroizing::new(payload.to_vec())));
                }
                RAW_EOF if self.mode == Mode::Raw && n == 0 => {
                    let Some(pending) = self.pending_read.as_mut() else {
                        return self.fail("channel_frame");
                    };
                    if pending.id != id
                        || pending.sent != pending.frame.len()
                        || pending.response.is_some()
                    {
                        return self.fail("channel_frame");
                    }
                    pending.response = Some(None);
                    self.input_eof = true;
                }
                TRUNCATED if self.mode == Mode::Raw && n == 0 => {
                    if self.pending_read.as_ref().is_none_or(|p| {
                        p.id != id || p.sent != p.frame.len() || p.response.is_some()
                    }) {
                        return self.fail("channel_frame");
                    }
                    return self.fail("input_truncated");
                }
                ACK if n == 0 => {
                    if let Some(pending) = self.pending.as_mut() {
                        if pending.id != id
                            || pending.sent != pending.frame.len()
                            || pending.acknowledged
                        {
                            return self.fail("output_ack");
                        }
                        pending.acknowledged = true;
                    } else {
                        return self.fail("output_ack");
                    }
                }
                FAULT if n == 0 => return self.fail("worker_io"),
                _ => return self.fail("channel_frame"),
            }
            consumed += HEADER + n;
        }
        if consumed > 0 {
            // Move the remainder, then wipe every vacated byte before reducing
            // length. Vec::drain alone can leave a copied raw capability behind.
            let remaining = self.receive.len() - consumed;
            self.receive.copy_within(consumed.., 0);
            self.receive[remaining..].zeroize();
            self.receive.truncate(remaining);
        }
        Ok(())
    }
}
fn validate_line(line: &[u8], input: bool) -> Result<(), StdioError> {
    if line.is_empty()
        || line.len() > FRAME_LIMIT
        || line.iter().any(|b| matches!(b, b'\n' | b'\r'))
        || std::str::from_utf8(line).is_err()
    {
        return Err(StdioError::new(if input {
            "input_frame"
        } else {
            "output_frame"
        }));
    }
    Ok(())
}
fn frame(tag: u8, id: u64, data: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(HEADER + data.len());
    value.push(tag);
    value.extend_from_slice(&id.to_be_bytes());
    value.extend_from_slice(&(data.len() as u32).to_be_bytes());
    value.extend_from_slice(data);
    value
}
fn authenticate_worker(
    listener: &TcpListener,
    process: &mut native::Process,
    capability: &[u8; 32],
    digest: &[u8; 32],
    deadline: Instant,
) -> Result<TcpStream, StdioError> {
    let mut attempts = 0;
    loop {
        if Instant::now() >= deadline {
            return Err(StdioError::new("startup_deadline"));
        }
        if process.exit_code()?.is_some() {
            return Err(StdioError::new("worker_exit"));
        }
        match listener.accept() {
            Ok((mut socket, address)) if address.ip().is_loopback() => {
                attempts += 1;
                if attempts > 4 {
                    return Err(StdioError::new("channel_auth"));
                }
                socket
                    .set_nonblocking(true)
                    .map_err(|_| StdioError::new("channel"))?;
                let mut hello = zeroize::Zeroizing::new([0u8; 80]);
                let mut n = 0;
                while n < hello.len() && Instant::now() < deadline {
                    match socket.read(&mut hello[n..]) {
                        Ok(0) => break,
                        Ok(read) => n += read,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
                let matches = n == hello.len()
                    && hello[..8] == MAGIC[..]
                    && hello[8..40]
                        .iter()
                        .zip(capability)
                        .fold(0u8, |v, (a, b)| v | (a ^ b))
                        == 0
                    && hello[40..72] == digest[..]
                    && u64::from_be_bytes(
                        hello[72..80]
                            .try_into()
                            .map_err(|_| StdioError::new("channel_auth"))?,
                    ) == process.id();
                hello.zeroize();
                if matches {
                    socket
                        .set_nodelay(true)
                        .map_err(|_| StdioError::new("channel"))?;
                    return Ok(socket);
                }
            }
            Ok(_) => return Err(StdioError::new("channel_auth")),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(StdioError::new("channel")),
        }
    }
}

/// Hidden app entry. No secret is accepted in args: only loopback address and
/// one inherited bootstrap handle/fd. The app must immediately exit afterwards.
pub fn worker_entry(args: &[String]) -> Result<(), StdioError> {
    if args.len() != 2 {
        return Err(StdioError::new("worker_arguments"));
    }
    let address: SocketAddr = args[0]
        .parse()
        .map_err(|_| StdioError::new("worker_arguments"))?;
    if address.ip() != Ipv4Addr::LOCALHOST || address.port() == 0 {
        return Err(StdioError::new("worker_arguments"));
    }
    let handle = args[1]
        .parse::<usize>()
        .map_err(|_| StdioError::new("worker_arguments"))?;
    let mut packet = native::read_bootstrap(handle)?;
    let executable = Executable::current()?;
    if packet[32..64] != executable.digest {
        packet.zeroize();
        return Err(StdioError::new("executable_changed"));
    }
    let values: Vec<u64> = packet[64..]
        .chunks_exact(8)
        .map(|c| u64::from_be_bytes(c.try_into().expect("fixed bootstrap field")))
        .collect();
    let mode = if values[0] & RAW_MODE_FLAG != 0 {
        Mode::Raw
    } else {
        Mode::Lines
    };
    let limits = StdioLimits {
        session: Duration::from_millis(values[0] & !RAW_MODE_FLAG),
        startup: Duration::from_secs(5),
        max_frames: values[1],
        max_input_bytes: values[2],
        max_output_bytes: values[3],
    }
    .validate()?;
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(5))
        .map_err(|_| StdioError::new("channel"))?;
    let mut hello = zeroize::Zeroizing::new(Vec::with_capacity(80));
    hello.extend_from_slice(MAGIC);
    hello.extend_from_slice(&packet[..32]);
    hello.extend_from_slice(&executable.digest);
    hello.extend_from_slice(&(std::process::id() as u64).to_be_bytes());
    packet.zeroize();
    let sent = socket.write_all(&hello);
    hello.zeroize();
    sent.map_err(|_| StdioError::new("channel"))?;
    let mut receiver = socket.try_clone().map_err(|_| StdioError::new("channel"))?;
    let sender = std::sync::Arc::new(Mutex::new(socket));
    let output_sender = sender.clone();
    // All three helper threads belong to this owned process. The watchdog
    // enforces the session even if the parent disappears while stdin blocks.
    let _watchdog = std::thread::Builder::new()
        .name("mmmm-stdio-watchdog".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            let expires = Instant::now() + limits.session;
            loop {
                if Instant::now() >= expires {
                    std::process::exit(124);
                }
                std::thread::sleep(
                    Duration::from_millis(100)
                        .min(expires.saturating_duration_since(Instant::now())),
                );
            }
        })
        .map_err(|_| StdioError::new("worker_thread"))?;
    if mode == Mode::Raw {
        // Rust's global Stdin uses a BufReader and can capture a capability
        // past the requested public prefix. Raw mode owns unbuffered native
        // handles so each read requests exactly the caller's remaining range.
        let (mut input, mut output) = native::worker_stdio()?;
        return worker_raw(&mut receiver, &sender, &mut input, &mut output, limits);
    }
    let output = std::thread::Builder::new()
        .name("mmmm-stdio-output".into())
        .stack_size(2 * 1024 * 1024)
        .spawn(move || -> Result<(), StdioError> {
            let result = worker_output(receiver, output_sender, limits);
            // EOF or output failure terminates the whole owned helper, including
            // an input thread currently blocked in external stdin.
            std::process::exit(if result.is_ok() { 0 } else { 3 });
        })
        .map_err(|_| StdioError::new("worker_thread"))?;
    worker_input(&mut io::stdin().lock(), &sender, limits)?;
    // EOF waits for the parent to close its channel. If external stdout blocks,
    // the parent deadline kills the owned process including this entire thread.
    output
        .join()
        .map_err(|_| StdioError::new("worker_thread"))?
}
fn worker_send(sender: &Mutex<TcpStream>, tag: u8, id: u64, line: &[u8]) -> Result<(), StdioError> {
    sender
        .lock()
        .map_err(|_| StdioError::new("worker_thread"))?
        .write_all(&zeroize::Zeroizing::new(frame(tag, id, line)))
        .map_err(|_| StdioError::new("channel"))
}
fn worker_raw(
    receiver: &mut TcpStream,
    sender: &Mutex<TcpStream>,
    input: &mut impl Read,
    output: &mut impl Write,
    limits: StdioLimits,
) -> Result<(), StdioError> {
    let mut input_count = 0u64;
    let mut input_bytes = 0u64;
    let mut output_count = 0u64;
    let mut output_bytes = 0u64;
    let mut input_eof = false;
    let mut failed = false;
    loop {
        let mut header = [0u8; HEADER];
        match receiver.read(&mut header[..1]) {
            Ok(0) => return Ok(()),
            Ok(1) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            _ => return Err(StdioError::new("channel")),
        }
        receiver
            .read_exact(&mut header[1..])
            .map_err(|_| StdioError::new("channel"))?;
        let tag = header[0];
        let id = u64::from_be_bytes(
            header[1..9]
                .try_into()
                .map_err(|_| StdioError::new("channel_frame"))?,
        );
        let size = u32::from_be_bytes(
            header[9..13]
                .try_into()
                .map_err(|_| StdioError::new("channel_frame"))?,
        ) as usize;
        if size == 0
            || size > FRAME_LIMIT
            || (tag == READ_EXACT && size != 4)
            || !matches!(tag, READ_EXACT | RAW_OUTPUT)
        {
            return Err(StdioError::new("channel_frame"));
        }
        let mut payload = zeroize::Zeroizing::new(vec![0u8; size]);
        receiver
            .read_exact(&mut payload)
            .map_err(|_| StdioError::new("channel"))?;
        if failed {
            worker_send(sender, FAULT, 0, &[])?;
            continue;
        }
        if tag == RAW_OUTPUT {
            if id != output_count + 1
                || output_count >= limits.max_frames
                || output_bytes
                    .checked_add(size as u64)
                    .is_none_or(|n| n > limits.max_output_bytes)
            {
                return Err(StdioError::new("output_budget"));
            }
            output_count += 1;
            output_bytes += size as u64;
            if output
                .write_all(&payload)
                .and_then(|_| output.flush())
                .is_err()
            {
                payload.zeroize();
                worker_send(sender, FAULT, 0, &[])?;
                failed = true;
                continue;
            }
            payload.zeroize();
            worker_send(sender, ACK, id, &[])?;
        } else {
            let n = u32::from_be_bytes(
                payload[..]
                    .try_into()
                    .map_err(|_| StdioError::new("channel_frame"))?,
            ) as usize;
            if n == 0
                || n > FRAME_LIMIT
                || id != input_count + 1
                || input_count >= limits.max_frames
                || input_bytes
                    .checked_add(n as u64)
                    .is_none_or(|v| v > limits.max_input_bytes)
            {
                return Err(StdioError::new("input_budget"));
            }
            input_count += 1;
            input_bytes += n as u64;
            if input_eof {
                worker_send(sender, RAW_EOF, id, &[])?;
                continue;
            }
            let mut data = zeroize::Zeroizing::new(vec![0u8; n]);
            let mut read = 0;
            while read < n {
                match input.read(&mut data[read..]) {
                    Ok(0) => {
                        input_eof = true;
                        break;
                    }
                    Ok(count) => read += count,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        data.zeroize();
                        worker_send(sender, FAULT, 0, &[])?;
                        failed = true;
                        break;
                    }
                }
            }
            if failed {
                continue;
            }
            if read == 0 && input_eof {
                worker_send(sender, RAW_EOF, id, &[])?;
            } else if read < n {
                data.zeroize();
                worker_send(sender, TRUNCATED, id, &[])?;
                failed = true;
            } else {
                worker_send(sender, RAW_INPUT, id, &data)?;
            }
            data.zeroize();
        }
    }
}
fn worker_input(
    input: &mut impl BufRead,
    sender: &Mutex<TcpStream>,
    limits: StdioLimits,
) -> Result<(), StdioError> {
    let mut id = 0;
    let mut bytes = 0u64;
    loop {
        let mut line = Vec::new();
        loop {
            let buffer = input.fill_buf().map_err(|_| StdioError::new("worker_io"))?;
            if buffer.is_empty() {
                if !line.is_empty() {
                    let _ = worker_send(sender, FAULT, 0, &[]);
                    return Err(StdioError::new("input_frame"));
                }
                worker_send(sender, EOF, id, &[])?;
                return Ok(());
            }
            let n = buffer
                .iter()
                .position(|b| *b == b'\n')
                .map_or(buffer.len(), |n| n + 1);
            if line.len() + n > FRAME_LIMIT + 2 {
                let _ = worker_send(sender, FAULT, 0, &[]);
                return Err(StdioError::new("input_frame"));
            }
            let finished = buffer[n - 1] == b'\n';
            line.extend_from_slice(&buffer[..n]);
            input.consume(n);
            if finished {
                break;
            }
        }
        bytes = bytes
            .checked_add(line.len() as u64)
            .ok_or_else(|| StdioError::new("input_budget"))?;
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        validate_line(&line, true)?;
        if id >= limits.max_frames || bytes > limits.max_input_bytes {
            let _ = worker_send(sender, FAULT, 0, &[]);
            return Err(StdioError::new("input_budget"));
        }
        id += 1;
        worker_send(sender, INPUT, id, &line)?;
    }
}
fn worker_output(
    mut receiver: TcpStream,
    sender: std::sync::Arc<Mutex<TcpStream>>,
    limits: StdioLimits,
) -> Result<(), StdioError> {
    worker_output_to(&mut receiver, &sender, limits, &mut io::stdout().lock())
}
fn worker_output_to(
    receiver: &mut TcpStream,
    sender: &Mutex<TcpStream>,
    limits: StdioLimits,
    output: &mut impl Write,
) -> Result<(), StdioError> {
    let mut id = 0;
    let mut bytes = 0u64;
    loop {
        let mut header = [0u8; HEADER];
        match receiver.read(&mut header[..1]) {
            Ok(0) => return Ok(()),
            Ok(1) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            _ => return Err(StdioError::new("channel")),
        }
        receiver
            .read_exact(&mut header[1..])
            .map_err(|_| StdioError::new("channel"))?;
        let next = u64::from_be_bytes(
            header[1..9]
                .try_into()
                .map_err(|_| StdioError::new("channel_frame"))?,
        );
        let n = u32::from_be_bytes(
            header[9..13]
                .try_into()
                .map_err(|_| StdioError::new("channel_frame"))?,
        ) as usize;
        if header[0] != OUTPUT || next != id + 1 || id >= limits.max_frames || n > FRAME_LIMIT {
            let _ = worker_send(sender, FAULT, 0, &[]);
            return Err(StdioError::new("output_frame"));
        }
        bytes = bytes
            .checked_add(n as u64 + 1)
            .ok_or_else(|| StdioError::new("output_budget"))?;
        if bytes > limits.max_output_bytes {
            let _ = worker_send(sender, FAULT, 0, &[]);
            return Err(StdioError::new("output_budget"));
        }
        let mut line = vec![0u8; n];
        receiver
            .read_exact(&mut line)
            .map_err(|_| StdioError::new("channel"))?;
        validate_line(&line, false)?;
        if output
            .write_all(&line)
            .and_then(|_| output.write_all(b"\n"))
            .and_then(|_| output.flush())
            .is_err()
        {
            let _ = worker_send(sender, FAULT, 0, &[]);
            return Err(StdioError::new("worker_io"));
        }
        id = next;
        worker_send(sender, ACK, id, &[])?;
    }
}

#[cfg(test)]
#[path = "stdio_io_tests.rs"]
mod tests;

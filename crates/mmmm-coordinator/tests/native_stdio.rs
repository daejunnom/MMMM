//! Actual native stdio acceptance. A harness-free executable can run its own
//! hidden worker without adding a product CLI probe or an unrelated driver.
//! Small contract fixtures cannot prove blocked kernel pipe cancellation.
use mmmm_coordinator::stdio_io::{
    NativeStdioPort, StdioDrain, StdioError, StdioLimits, WORKER_COMMAND, worker_entry,
};
use std::{
    fs::File,
    io::{Read, Write},
    sync::atomic::{AtomicBool, Ordering},
    task::Poll,
    time::{Duration, Instant},
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|v| v == WORKER_COMMAND) {
        let status = if worker_entry(&args[1..]).is_ok() {
            0
        } else {
            3
        };
        std::process::exit(status);
    }
    // Cargo forwards normal libtest options to harness-free targets too. This
    // fixture stays serial because only its own std handles are redirected.
    assert!(
        args.iter().all(
            |arg| matches!(arg.as_str(), "--nocapture" | "--quiet" | "--show-output")
                || arg
                    .strip_prefix("--test-threads=")
                    .is_some_and(|v| v.parse::<usize>().is_ok())
        ),
        "unsupported native fixture test option"
    );
    roundtrip_and_clean_eof();
    held_stdin_deadline();
    held_stdin_cancel();
    blocked_stdout_never_acknowledges();
    raw_framed_roundtrip_and_capability_eof();
    truncated_raw_capability_is_failure();
    held_raw_payload_deadline();
    blocked_raw_stdout_never_acknowledges();
    eprintln!(
        "native stdio acceptance: line and raw roundtrip, EOF, truncated raw capability, held input deadline/cancel, blocked output and verified drain passed"
    );
}
struct Scenario {
    port: NativeStdioPort,
    input: Option<File>,
    output: File,
}
impl Scenario {
    fn start() -> Self {
        Self::start_mode(false)
    }
    fn start_raw() -> Self {
        Self::start_mode(true)
    }
    fn start_mode(raw: bool) -> Self {
        let (port, input, output) = redirect::spawn(
            StdioLimits {
                session: Duration::from_secs(15),
                ..StdioLimits::default()
            },
            raw,
        )
        .expect("native fixture must start real hidden worker");
        Self {
            port,
            input: Some(input),
            output,
        }
    }
    fn drain(&self) -> StdioDrain {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self
                .port
                .poll_cancel_and_drain(deadline)
                .expect("native ownership drain must be confirmed")
            {
                Poll::Ready(proof) => {
                    assert!(proof.terminated);
                    assert_eq!(
                        self.port.poll_cancel_and_drain(deadline).unwrap(),
                        Poll::Ready(proof.clone()),
                        "drain must be idempotent"
                    );
                    return proof;
                }
                Poll::Pending => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    }
}
fn read(
    port: &NativeStdioPort,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<Option<Vec<u8>>, StdioError> {
    let deadline = Instant::now() + timeout;
    loop {
        match port.poll_read_line(deadline, cancel)? {
            Poll::Ready(value) => return Ok(value),
            Poll::Pending => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}
fn write(port: &NativeStdioPort, line: &[u8], timeout: Duration) -> Result<(), StdioError> {
    let deadline = Instant::now() + timeout;
    let cancel = AtomicBool::new(false);
    loop {
        match port.poll_write_line(line, deadline, &cancel)? {
            Poll::Ready(()) => return Ok(()),
            Poll::Pending => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}
fn output_exact(output: &mut File, bytes: &mut [u8]) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut offset = 0;
    while offset < bytes.len() {
        assert!(Instant::now() < deadline, "actual stdout read deadline");
        match redirect::poll_read(output, &mut bytes[offset..]).unwrap() {
            Some(0) => panic!("actual stdout was truncated"),
            Some(n) => offset += n,
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}
fn output_eof(output: &mut File, bytes: &mut Vec<u8>) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut buffer = zeroize::Zeroizing::new([0u8; 8192]);
    loop {
        assert!(Instant::now() < deadline, "actual stdout EOF deadline");
        match redirect::poll_read(output, &mut buffer[..]).unwrap() {
            Some(0) => return,
            Some(n) => {
                assert!(bytes.len() + n <= 1_048_577, "actual stdout byte budget");
                bytes.extend_from_slice(&buffer[..n]);
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}
fn roundtrip_and_clean_eof() {
    let mut scenario = Scenario::start();
    let cancel = AtomicBool::new(false);
    // Fresh anonymous pipe, twelve bytes below its minimum native capacity;
    // no unrelated writer or reader participates in this fixture.
    scenario
        .input
        .as_mut()
        .unwrap()
        .write_all(b"{\"id\":1}\r\n")
        .unwrap();
    assert_eq!(
        read(&scenario.port, Duration::from_secs(2), &cancel).unwrap(),
        Some(b"{\"id\":1}".to_vec())
    );
    write(&scenario.port, b"{\"ok\":true}", Duration::from_secs(2)).unwrap();
    // ACK must prove these bytes and the LF were flushed. A bounded native
    // read also catches an incorrect ACK without hanging the test driver.
    let mut bytes = [0; 12];
    output_exact(&mut scenario.output, &mut bytes);
    assert_eq!(&bytes, b"{\"ok\":true}\n");
    drop(scenario.input.take());
    assert_eq!(
        read(&scenario.port, Duration::from_secs(2), &cancel).unwrap(),
        None
    );
    scenario.drain();
}
fn held_stdin_deadline() {
    let scenario = Scenario::start();
    let started = Instant::now();
    let error = read(
        &scenario.port,
        Duration::from_millis(150),
        &AtomicBool::new(false),
    )
    .unwrap_err();
    assert_eq!(error.code, "deadline");
    scenario.drain();
    assert!(started.elapsed() < Duration::from_secs(6));
}
fn held_stdin_cancel() {
    let scenario = Scenario::start();
    let cancel = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(2);
    assert_eq!(
        scenario.port.poll_read_line(deadline, &cancel).unwrap(),
        Poll::Pending
    );
    cancel.store(true, Ordering::Release);
    assert_eq!(
        scenario
            .port
            .poll_read_line(deadline, &cancel)
            .unwrap_err()
            .code,
        "cancelled"
    );
    scenario.drain();
}
fn blocked_stdout_never_acknowledges() {
    let mut scenario = Scenario::start();
    let line = format!("{{\"padding\":\"{}\"}}", "x".repeat(1_048_576 - 32));
    // Keep the read end open but unread. The helper fills the small actual
    // stdout pipe and blocks; private TCP acceptance must not become Ready.
    let started = Instant::now();
    let error = write(&scenario.port, line.as_bytes(), Duration::from_millis(700)).unwrap_err();
    assert_eq!(error.code, "deadline");
    scenario.drain();
    assert!(started.elapsed() < Duration::from_secs(6));
    // Every writer is now gone, so a bounded read reaches EOF. Positive bytes
    // prove the worker entered the external write before its cancellation.
    let mut delivered = Vec::new();
    output_eof(&mut scenario.output, &mut delivered);
    assert!(!delivered.is_empty());
    assert!(delivered.len() < line.len() + 1);
    assert_eq!(&line.as_bytes()[..delivered.len()], delivered.as_slice());
}

fn raw_read(
    port: &NativeStdioPort,
    n: usize,
    timeout: Duration,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, StdioError> {
    let deadline = Instant::now() + timeout;
    let cancel = AtomicBool::new(false);
    loop {
        match port.poll_read_exact(n, deadline, &cancel)? {
            Poll::Ready(bytes) => return Ok(bytes),
            Poll::Pending => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}
fn raw_write(port: &NativeStdioPort, bytes: &[u8], timeout: Duration) -> Result<(), StdioError> {
    let deadline = Instant::now() + timeout;
    let cancel = AtomicBool::new(false);
    loop {
        match port.poll_write_raw(bytes, deadline, &cancel)? {
            Poll::Ready(()) => return Ok(()),
            Poll::Pending => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}
fn raw_framed_roundtrip_and_capability_eof() {
    let mut scenario = Scenario::start_raw();
    let public = b"{}";
    // This authored byte pattern is not a real capability. It protects raw
    // binary fidelity separately from the public JSON. No secret fixture is
    // read, saved or printed, and no capability appears in assert diagnostics.
    let mut capability = [0xA5; 32];
    capability[..4].copy_from_slice(&[0, 255, 10, 13]);
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    bytes.extend_from_slice(b"MMMMPAIR");
    bytes.extend_from_slice(&(public.len() as u32).to_be_bytes());
    bytes.extend_from_slice(public);
    bytes.extend_from_slice(&capability);
    scenario.input.as_mut().unwrap().write_all(&bytes).unwrap();
    assert_eq!(
        raw_read(&scenario.port, 8, Duration::from_secs(2))
            .unwrap()
            .unwrap()
            .as_slice(),
        b"MMMMPAIR"
    );
    assert_eq!(
        raw_read(&scenario.port, 4, Duration::from_secs(2))
            .unwrap()
            .unwrap()
            .as_slice(),
        &(public.len() as u32).to_be_bytes()
    );
    assert_eq!(
        raw_read(&scenario.port, public.len(), Duration::from_secs(2))
            .unwrap()
            .unwrap()
            .as_slice(),
        public
    );
    assert!(
        raw_read(&scenario.port, 32, Duration::from_secs(2))
            .unwrap()
            .unwrap()
            .as_slice()
            == capability
    );
    raw_write(&scenario.port, &bytes, Duration::from_secs(2)).unwrap();
    let mut delivered = zeroize::Zeroizing::new(vec![0; bytes.len()]);
    output_exact(&mut scenario.output, &mut delivered);
    assert!(delivered.as_slice() == bytes.as_slice());
    drop(scenario.input.take());
    assert!(
        raw_read(&scenario.port, 1, Duration::from_secs(2))
            .unwrap()
            .is_none()
    );
    scenario.drain();
    zeroize::Zeroize::zeroize(&mut capability);
}
fn truncated_raw_capability_is_failure() {
    let mut scenario = Scenario::start_raw();
    scenario
        .input
        .as_mut()
        .unwrap()
        .write_all(&[0xA5; 16])
        .unwrap();
    drop(scenario.input.take());
    assert_eq!(
        raw_read(&scenario.port, 32, Duration::from_secs(2))
            .unwrap_err()
            .code,
        "input_truncated"
    );
    scenario.drain();
}
fn held_raw_payload_deadline() {
    let mut scenario = Scenario::start_raw();
    let mut prefix = Vec::from(&b"MMMMPAIR"[..]);
    prefix.extend_from_slice(&4096u32.to_be_bytes());
    scenario.input.as_mut().unwrap().write_all(&prefix).unwrap();
    assert!(
        raw_read(&scenario.port, 8, Duration::from_secs(2))
            .unwrap()
            .is_some()
    );
    assert!(
        raw_read(&scenario.port, 4, Duration::from_secs(2))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        raw_read(&scenario.port, 4096, Duration::from_millis(150))
            .unwrap_err()
            .code,
        "deadline"
    );
    scenario.drain();
}
fn blocked_raw_stdout_never_acknowledges() {
    let mut scenario = Scenario::start_raw();
    let bytes = zeroize::Zeroizing::new(vec![0xA5; 1_048_576]);
    assert_eq!(
        raw_write(&scenario.port, &bytes, Duration::from_millis(700))
            .unwrap_err()
            .code,
        "deadline"
    );
    scenario.drain();
    let mut delivered = zeroize::Zeroizing::new(Vec::new());
    output_eof(&mut scenario.output, &mut delivered);
    assert!(!delivered.is_empty() && delivered.len() < bytes.len());
    assert!(delivered.iter().all(|b| *b == 0xA5));
}

#[cfg(unix)]
mod redirect {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};
    fn pipe() -> (File, File) {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read = unsafe { File::from_raw_fd(fds[0]) };
        let write = unsafe { File::from_raw_fd(fds[1]) };
        for fd in fds {
            assert_ne!(
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                -1
            );
        }
        (read, write)
    }
    struct Restore {
        input: File,
        output: File,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            assert_ne!(unsafe { libc::dup2(self.input.as_raw_fd(), 0) }, -1);
            assert_ne!(unsafe { libc::dup2(self.output.as_raw_fd(), 1) }, -1);
        }
    }
    pub(super) fn poll_read(output: &mut File, bytes: &mut [u8]) -> std::io::Result<Option<usize>> {
        match output.read(bytes) {
            Ok(n) => Ok(Some(n)),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
    pub(super) fn spawn(
        limits: StdioLimits,
        raw: bool,
    ) -> Result<(NativeStdioPort, File, File), StdioError> {
        let (input_read, input_write) = pipe();
        let (output_read, output_write) = pipe();
        let output_flags = unsafe { libc::fcntl(output_read.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(output_flags, -1);
        assert_ne!(
            unsafe {
                libc::fcntl(
                    output_read.as_raw_fd(),
                    libc::F_SETFL,
                    output_flags | libc::O_NONBLOCK,
                )
            },
            -1
        );
        let input = unsafe { libc::dup(0) };
        let output = unsafe { libc::dup(1) };
        assert!(input >= 0 && output >= 0);
        let restore = Restore {
            input: unsafe { File::from_raw_fd(input) },
            output: unsafe { File::from_raw_fd(output) },
        };
        assert_ne!(unsafe { libc::dup2(input_read.as_raw_fd(), 0) }, -1);
        assert_ne!(unsafe { libc::dup2(output_write.as_raw_fd(), 1) }, -1);
        let result = if raw {
            NativeStdioPort::spawn_current_raw(limits)
        } else {
            NativeStdioPort::spawn_current(limits)
        };
        drop(restore);
        drop(input_read);
        drop(output_write);
        Ok((result?, input_write, output_read))
    }
}
#[cfg(windows)]
mod redirect {
    use super::*;
    use std::{
        os::windows::io::{AsRawHandle, FromRawHandle},
        ptr::null_mut,
    };
    use windows_sys::Win32::{
        Foundation::{ERROR_BROKEN_PIPE, HANDLE, INVALID_HANDLE_VALUE},
        System::{
            Console::{GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle},
            Pipes::{CreatePipe, PeekNamedPipe},
        },
    };
    fn pipe() -> (File, File) {
        let mut read = null_mut();
        let mut write = null_mut();
        assert_ne!(
            unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 4096) },
            0
        );
        (unsafe { File::from_raw_handle(read) }, unsafe {
            File::from_raw_handle(write)
        })
    }
    struct Restore {
        input: HANDLE,
        output: HANDLE,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            assert_ne!(unsafe { SetStdHandle(STD_INPUT_HANDLE, self.input) }, 0);
            assert_ne!(unsafe { SetStdHandle(STD_OUTPUT_HANDLE, self.output) }, 0);
        }
    }
    pub(super) fn poll_read(output: &mut File, bytes: &mut [u8]) -> std::io::Result<Option<usize>> {
        let mut available = 0u32;
        if unsafe {
            PeekNamedPipe(
                output.as_raw_handle().cast(),
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        } == 0
        {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                Ok(Some(0))
            } else {
                Err(error)
            };
        }
        if available == 0 {
            return Ok(None);
        }
        // This fresh pipe has exactly one reader owned by the fixture. The
        // requested range is already present, so this synchronous read cannot
        // wait for another writer or steal data from another reader.
        let n = bytes.len().min(available as usize);
        output.read(&mut bytes[..n]).map(Some)
    }
    pub(super) fn spawn(
        limits: StdioLimits,
        raw: bool,
    ) -> Result<(NativeStdioPort, File, File), StdioError> {
        let (input_read, input_write) = pipe();
        let (output_read, output_write) = pipe();
        let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        assert!(
            !input.is_null()
                && input != INVALID_HANDLE_VALUE
                && !output.is_null()
                && output != INVALID_HANDLE_VALUE
        );
        let restore = Restore { input, output };
        assert_ne!(
            unsafe { SetStdHandle(STD_INPUT_HANDLE, input_read.as_raw_handle().cast()) },
            0
        );
        assert_ne!(
            unsafe { SetStdHandle(STD_OUTPUT_HANDLE, output_write.as_raw_handle().cast()) },
            0
        );
        let result = if raw {
            NativeStdioPort::spawn_current_raw(limits)
        } else {
            NativeStdioPort::spawn_current(limits)
        };
        drop(restore);
        drop(input_read);
        drop(output_write);
        Ok((result?, input_write, output_read))
    }
}

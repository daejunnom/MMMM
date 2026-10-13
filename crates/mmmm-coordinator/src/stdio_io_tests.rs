use super::*;
use std::io::Cursor;

// Existing contract fixtures cannot exercise native worker startup/drain or
// distinguish socket acceptance from a successful stdout flush. These small
// in-memory frames and loopback sockets specifically protect that boundary.
fn sockets() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (local, _) = listener.accept().unwrap();
    for socket in [&local, &peer] {
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
    }
    (local, peer)
}
fn receive(peer: &mut TcpStream) -> (u8, u64, Vec<u8>) {
    let mut header = [0u8; HEADER];
    peer.read_exact(&mut header).unwrap();
    let size = u32::from_be_bytes(header[9..13].try_into().unwrap()) as usize;
    assert!(size <= FRAME_LIMIT);
    let mut data = vec![0; size];
    peer.read_exact(&mut data).unwrap();
    (
        header[0],
        u64::from_be_bytes(header[1..9].try_into().unwrap()),
        data,
    )
}
#[test]
fn input_lf_and_crlf_preserve_json_and_explicit_eof() {
    let (local, mut peer) = sockets();
    worker_input(
        &mut Cursor::new(b"{\"a\":1}\n{\"b\":2}\r\n"),
        &Mutex::new(local),
        StdioLimits::default(),
    )
    .unwrap();
    assert_eq!(receive(&mut peer), (INPUT, 1, b"{\"a\":1}".to_vec()));
    assert_eq!(receive(&mut peer), (INPUT, 2, b"{\"b\":2}".to_vec()));
    assert_eq!(receive(&mut peer), (EOF, 2, Vec::new()));
}
#[test]
fn unterminated_input_and_frame_budget_are_not_clean_eof() {
    let (local, mut peer) = sockets();
    assert_eq!(
        worker_input(
            &mut Cursor::new(b"{}"),
            &Mutex::new(local),
            StdioLimits::default()
        )
        .unwrap_err()
        .code,
        "input_frame"
    );
    assert_eq!(receive(&mut peer).0, FAULT);
    let (local, mut peer) = sockets();
    let limits = StdioLimits {
        max_frames: 1,
        ..StdioLimits::default()
    };
    assert_eq!(
        worker_input(&mut Cursor::new(b"{}\n{}\n"), &Mutex::new(local), limits)
            .unwrap_err()
            .code,
        "input_budget"
    );
    assert_eq!(receive(&mut peer).0, INPUT);
    assert_eq!(receive(&mut peer).0, FAULT);
}
#[test]
fn large_frame_invalid_utf8_raw_newline_and_limit_expansion_rejected() {
    assert!(validate_line(&vec![b'x'; FRAME_LIMIT], true).is_ok());
    for data in [&[255][..], b"a\nb", b"a\rb", b""] {
        assert!(validate_line(data, true).is_err());
    }
    assert!(validate_line(&vec![b'x'; FRAME_LIMIT + 1], true).is_err());
    assert!(
        StdioLimits {
            session: Duration::from_secs(3601),
            ..StdioLimits::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        StdioLimits {
            max_frames: 0,
            ..StdioLimits::default()
        }
        .validate()
        .is_err()
    );
}
#[test]
fn original_expired_deadline_rejects_before_executable_or_native_startup() {
    let deadline = Instant::now();
    for output in [StdioOutput::Stdout, StdioOutput::Stderr] {
        let error = match NativeStdioPort::spawn_current_raw_output_with_deadline(
            StdioLimits::default(),
            output,
            deadline,
        ) {
            Ok(_) => panic!("expired original budget must not create an owner"),
            Err(error) => error,
        };
        assert_eq!(error.code, "deadline");
        assert!(!error.drained);
        assert!(error.cleanup.is_none());
    }
    let limits = StdioLimits {
        session: Duration::MAX,
        ..StdioLimits::default()
    };
    let error = match NativeStdioPort::spawn_current_raw(limits) {
        Ok(_) => panic!("invalid duration must not create an owner"),
        Err(error) => error,
    };
    assert_eq!(error.code, "limits");
}
#[derive(Default)]
struct Output {
    bytes: Vec<u8>,
    flushed: bool,
    fail_flush: bool,
    max_write: Option<usize>,
    fail_after: Option<usize>,
    writes: usize,
}
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.max_write.is_some_and(|n| bytes.len() > n)
            || self.fail_after.is_some_and(|n| self.writes >= n)
        {
            return Err(io::Error::other("bounded output fixture"));
        }
        self.writes += 1;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.fail_flush {
            Err(io::Error::other("fixture"))
        } else {
            self.flushed = true;
            Ok(())
        }
    }
}
#[test]
fn external_line_and_raw_writes_are_bounded_and_mid_write_failure_never_acknowledges() {
    // A Vec sink and flush failure cannot expose an oversized native write.
    // This strict sink accepts only a pipe-sized write and can fail after one
    // completed chunk, preserving the partial-effect/no-ACK distinction.
    for raw in [false, true] {
        for fail_after in [None, Some(1)] {
            let (mut local, mut peer) = sockets();
            let sender = Mutex::new(local.try_clone().unwrap());
            let data = vec![b'x'; EXTERNAL_WRITE_CHUNK * 2 + 1];
            peer.write_all(&frame(if raw { RAW_OUTPUT } else { OUTPUT }, 1, &data))
                .unwrap();
            peer.shutdown(Shutdown::Write).unwrap();
            let mut output = Output {
                max_write: Some(EXTERNAL_WRITE_CHUNK),
                fail_after,
                ..Output::default()
            };
            let result = if raw {
                worker_raw(
                    &mut local,
                    &sender,
                    &mut Cursor::new([]),
                    &mut output,
                    StdioLimits::default(),
                )
            } else {
                worker_output_to(&mut local, &sender, StdioLimits::default(), &mut output)
            };
            if fail_after.is_some() {
                if raw {
                    result.unwrap();
                } else {
                    assert_eq!(result.unwrap_err().code, "worker_io");
                }
                assert_eq!(output.bytes.len(), EXTERNAL_WRITE_CHUNK);
                assert_eq!(output.bytes.as_slice(), &data[..EXTERNAL_WRITE_CHUNK]);
                assert!(!output.flushed);
                assert_eq!(receive(&mut peer), (FAULT, 0, Vec::new()));
            } else {
                result.unwrap();
                assert!(output.flushed);
                assert_eq!(output.bytes.len(), data.len() + usize::from(!raw));
                assert_eq!(&output.bytes[..data.len()], data.as_slice());
                if !raw {
                    assert_eq!(output.bytes.last(), Some(&b'\n'));
                }
                assert_eq!(receive(&mut peer), (ACK, 1, Vec::new()));
            }
            drop(sender);
            drop(local);
            let mut trailing = [0];
            assert_eq!(peer.read(&mut trailing).unwrap(), 0, "unexpected extra ACK");
        }
    }
}
#[test]
fn output_ack_follows_actual_lf_write_and_flush() {
    let (mut local, mut peer) = sockets();
    let sender = Mutex::new(local.try_clone().unwrap());
    peer.write_all(&frame(OUTPUT, 1, b"{}")).unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    let mut output = Output::default();
    worker_output_to(&mut local, &sender, StdioLimits::default(), &mut output).unwrap();
    assert_eq!(output.bytes, b"{}\n");
    assert!(output.flushed);
    assert_eq!(receive(&mut peer), (ACK, 1, Vec::new()));
}
#[test]
fn failed_stdout_flush_emits_fault_and_never_acknowledges() {
    let (mut local, mut peer) = sockets();
    let sender = Mutex::new(local.try_clone().unwrap());
    peer.write_all(&frame(OUTPUT, 1, b"{}")).unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    let mut output = Output {
        fail_flush: true,
        ..Output::default()
    };
    assert_eq!(
        worker_output_to(&mut local, &sender, StdioLimits::default(), &mut output)
            .unwrap_err()
            .code,
        "worker_io"
    );
    assert_eq!(receive(&mut peer), (FAULT, 0, Vec::new()));
    assert!(!output.flushed);
}
#[test]
fn output_sequence_and_budget_fail_before_external_write() {
    for (wire, limits, code) in [
        (
            frame(OUTPUT, 2, b"{}"),
            StdioLimits::default(),
            "output_frame",
        ),
        (
            frame(OUTPUT, 1, b"{}"),
            StdioLimits {
                max_output_bytes: 2,
                ..StdioLimits::default()
            },
            "output_budget",
        ),
    ] {
        let (mut local, mut peer) = sockets();
        let sender = Mutex::new(local.try_clone().unwrap());
        peer.write_all(&wire).unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
        let mut output = Output::default();
        assert_eq!(
            worker_output_to(&mut local, &sender, limits, &mut output)
                .unwrap_err()
                .code,
            code
        );
        assert!(output.bytes.is_empty());
        assert_eq!(receive(&mut peer).0, FAULT);
    }
}
#[test]
fn actual_native_startup_failure_is_finite_and_drains_worker() {
    // The Rust test executable deliberately has no hidden app entry. Its actual
    // child fails instead of completing the capability handshake. This protects
    // native startup failure cleanup; app integration separately exercises a
    // real hidden worker with externally blocked stdin/stdout.
    let started = Instant::now();
    let error = match NativeStdioPort::spawn_current(StdioLimits::default()) {
        Ok(_) => panic!("test helper unexpectedly understood hidden app entry"),
        Err(error) => error,
    };
    assert!(
        matches!(error.code, "worker_exit" | "startup_deadline"),
        "unexpected native startup rejection: {error}; drained={}",
        error.drained
    );
    assert!(
        error.drained,
        "native failure must preserve a verified drain result"
    );
    assert!(started.elapsed() < Duration::from_secs(12));
}
#[test]
fn hidden_worker_rejects_nonloopback_and_non_numeric_bootstrap() {
    for args in [
        vec!["192.0.2.1:1".into(), "4".into()],
        vec!["127.0.0.1:1".into(), "not-a-handle".into()],
        Vec::new(),
    ] {
        assert_eq!(worker_entry(&args).unwrap_err().code, "worker_arguments");
    }
}

#[test]
fn raw_exact_bytes_output_flush_and_clean_eof_are_separate_frames() {
    let (mut local, mut peer) = sockets();
    let sender = Mutex::new(local.try_clone().unwrap());
    // Authored binary bytes exercise NUL, invalid UTF-8 and CR/LF without
    // introducing a real capability or printing payloads in diagnostics.
    let bytes = [0, 255, 10, 13];
    peer.write_all(&frame(READ_EXACT, 1, &4u32.to_be_bytes()))
        .unwrap();
    peer.write_all(&frame(RAW_OUTPUT, 1, &bytes)).unwrap();
    peer.write_all(&frame(READ_EXACT, 2, &1u32.to_be_bytes()))
        .unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    let mut output = Output::default();
    worker_raw(
        &mut local,
        &sender,
        &mut Cursor::new(bytes),
        &mut output,
        StdioLimits::default(),
    )
    .unwrap();
    let (tag, id, received) = receive(&mut peer);
    assert_eq!((tag, id), (RAW_INPUT, 1));
    assert!(received.as_slice() == bytes);
    assert!(output.bytes.as_slice() == bytes);
    assert!(output.flushed);
    assert_eq!(receive(&mut peer), (ACK, 1, Vec::new()));
    assert_eq!(receive(&mut peer), (RAW_EOF, 2, Vec::new()));
}

#[test]
fn raw_partial_eof_reports_truncation_without_partial_bytes() {
    let (mut local, mut peer) = sockets();
    let sender = Mutex::new(local.try_clone().unwrap());
    peer.write_all(&frame(READ_EXACT, 1, &32u32.to_be_bytes()))
        .unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    let mut output = Output::default();
    worker_raw(
        &mut local,
        &sender,
        &mut Cursor::new([0xA5; 16]),
        &mut output,
        StdioLimits::default(),
    )
    .unwrap();
    assert_eq!(receive(&mut peer), (TRUNCATED, 1, Vec::new()));
    assert!(output.bytes.is_empty());
}

#[test]
fn raw_failed_flush_emits_fault_without_ack_or_terminator() {
    let (mut local, mut peer) = sockets();
    let sender = Mutex::new(local.try_clone().unwrap());
    peer.write_all(&frame(RAW_OUTPUT, 1, &[0, 255, 10, 13]))
        .unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    let mut output = Output {
        fail_flush: true,
        ..Output::default()
    };
    worker_raw(
        &mut local,
        &sender,
        &mut Cursor::new([]),
        &mut output,
        StdioLimits::default(),
    )
    .unwrap();
    assert!(output.bytes.as_slice() == [0, 255, 10, 13]);
    assert!(!output.flushed);
    assert_eq!(receive(&mut peer), (FAULT, 0, Vec::new()));
}

#[test]
fn raw_budget_is_checked_before_external_io() {
    for (wire, limits, code) in [
        (
            frame(RAW_OUTPUT, 1, &[0xA5; 4]),
            StdioLimits {
                max_output_bytes: 3,
                ..StdioLimits::default()
            },
            "output_budget",
        ),
        (
            frame(READ_EXACT, 1, &4u32.to_be_bytes()),
            StdioLimits {
                max_input_bytes: 3,
                ..StdioLimits::default()
            },
            "input_budget",
        ),
    ] {
        let (mut local, mut peer) = sockets();
        let sender = Mutex::new(local.try_clone().unwrap());
        peer.write_all(&wire).unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
        let mut input = Cursor::new([0xA5; 4]);
        let mut output = Output::default();
        assert_eq!(
            worker_raw(&mut local, &sender, &mut input, &mut output, limits)
                .unwrap_err()
                .code,
            code
        );
        assert_eq!(input.position(), 0);
        assert!(output.bytes.is_empty());
    }
}

#[test]
fn worker_failure_status_preserves_stage_and_marks_native_overflow_unknown() {
    for native in [None, Some(5), Some(i32::MAX), Some(-1)] {
        let mut error = StdioError::new("bootstrap_peek");
        error.native_code = native;
        let decoded = worker_exit_error(worker_failure_exit(&error));
        assert_eq!(decoded.code, "bootstrap_peek");
        assert!(!decoded.drained, "exit status cannot prove native drain");
        #[cfg(windows)]
        {
            assert_eq!(
                decoded.native_code,
                native.filter(|n| (0..=65_533).contains(n))
            );
            assert_eq!(
                decoded.native_code_unknown,
                native.is_some_and(|n| !(0..=65_533).contains(&n))
            );
        }
        #[cfg(unix)]
        {
            assert_eq!(decoded.native_code, None);
            assert_eq!(decoded.native_code_unknown, native.is_some());
        }
    }
    let unexpected = worker_exit_error(3);
    assert_eq!(unexpected.code, "worker_exit");
    assert_eq!(unexpected.native_code, Some(3));
    assert!(!unexpected.native_code_unknown);
    let signal = worker_exit_error(-11);
    assert_eq!(signal.code, "worker_exit");
    assert_eq!(signal.native_code, Some(-11));
    #[cfg(windows)]
    {
        let invalid_stage = worker_exit_error(0x4DFF_0005);
        assert_eq!(invalid_stage.code, "worker_exit");
        assert_eq!(invalid_stage.native_code, Some(0x4DFF_0005));
    }
}

#[cfg(windows)]
#[test]
fn windows_worker_environment_has_only_os_root_keys_and_no_injection() {
    let directory: Vec<u16> = "X:\\Windows".encode_utf16().collect();
    let block = native::minimal_environment(&directory).unwrap();
    let expected: Vec<u16> = "SystemRoot=X:\\Windows\0windir=X:\\Windows\0\0"
        .encode_utf16()
        .collect();
    assert_eq!(block, expected);
    for invalid in [
        "",
        "relative",
        "X:\\Windows\0OTHER=value",
        "\\\\host\\Windows",
    ] {
        assert_eq!(
            native::minimal_environment(&invalid.encode_utf16().collect::<Vec<_>>())
                .unwrap_err()
                .code,
            "system_directory"
        );
    }
}

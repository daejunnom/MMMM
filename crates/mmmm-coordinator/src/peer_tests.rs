//! Native peer fixtures use a newly owned external root and the real default
//! Coordinator path. The handoff has no local IPC lifecycle fixtures, so these
//! authored cases cover token delivery, precise cleanup and shared-store use.
//! Register this file as a child module of `tests` to reuse its read-only ports.
//! Faults that latch process-global fatal state require a separate subprocess.

use super::*;
use crate::peer::{PeerBootstrap, PeerError};
use zeroize::Zeroizing;

const PEER_OWNER: &[u8] = b"mmmm-owned-native-peer-test-root-v1\n";

struct PeerTestRoot(PathBuf);
impl PeerTestRoot {
    fn new() -> Self {
        // macOS's default TMPDIR can exceed sockaddr_un's fixed length. This
        // public /tmp location is canonicalized; the owned child stays short.
        #[cfg(unix)]
        let parent = fs::canonicalize("/tmp").expect("physical short temp parent");
        #[cfg(windows)]
        let parent = fs::canonicalize(std::env::temp_dir()).expect("physical temp parent");
        Self::under(&parent)
    }
    #[cfg(windows)]
    fn new_persistent() -> Self {
        let parent = persistent_evidence_parent("native-peer-fixtures")
            .expect("external persistent native fixture parent");
        Self::under(&parent)
    }
    fn under(parent: &Path) -> Self {
        let mut nonce = [0_u8; 4];
        getrandom::fill(&mut nonce).expect("fixture public ownership nonce");
        let root = parent.join(format!(
            "mp-{:x}-{:08x}",
            std::process::id(),
            u32::from_be_bytes(nonce)
        ));
        let checkout = fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .expect("physical checkout");
        assert!(root.is_absolute() && !root.starts_with(checkout));
        fs::create_dir(&root).expect("exclusive new fixture root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("private fixture root");
        }
        let mut marker = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("test-owner.txt"))
            .expect("new public fixture owner marker");
        marker.write_all(PEER_OWNER).expect("public owner marker");
        marker.sync_all().expect("durable fixture marker");
        Self(root)
    }
    fn config(&self) -> StoreConfig {
        StoreConfig::new(self.0.clone())
    }
    fn runtime(&self) -> PathBuf {
        self.0.join("runtime")
    }
}
impl Drop for PeerTestRoot {
    fn drop(&mut self) {
        // Special files, symlinks/reparse points or a changed physical root
        // keep the exact fixture for diagnosis. No other task root is scanned.
        if fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0)
            && owned_plain_tree(&self.0)
            && fs::read(self.0.join("test-owner.txt")).ok().as_deref() == Some(PEER_OWNER)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

struct RunningCoordinator {
    stop: Option<Arc<AtomicBool>>,
    worker: Option<JoinHandle<Result<(), String>>>,
}
impl RunningCoordinator {
    fn finish(mut self) {
        self.stop.as_ref().unwrap().store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap().unwrap();
    }
}
impl Drop for RunningCoordinator {
    fn drop(&mut self) {
        if let Some(stop) = &self.stop {
            stop.store(true, Ordering::Release);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn retry_prewrite_peer_busy<T>(
    deadline: Instant,
    mut attempt: impl FnMut() -> Result<T, PeerError>,
) -> Result<T, PeerError> {
    loop {
        match attempt() {
            Err(PeerError::Busy) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            #[cfg(windows)]
            Err(PeerError::Native(231)) if Instant::now() < deadline => {
                // This control path reports PIPE_BUSY only from CreateFile,
                // before any request/token byte. Keep the same absolute deadline.
                thread::sleep(Duration::from_millis(20));
            }
            result => return result,
        }
    }
}

// One test deliberately owns both stages: Windows has one process-wide peer
// server reservation. Parallel global-fatal fault injection is not registered.
#[test]
fn native_peer_delivery_cleanup_and_default_coordinator_lifecycle() {
    assert!(!crate::peer::fatal_stop_requested());
    {
        let root = PeerTestRoot::new();
        // Exact stale cleanup is authorized only while the data-root lease is held.
        let store = DurableStore::open(root.config()).unwrap();
        let runtime = RuntimeDirectory::open(&root.runtime()).unwrap();
        let reference = CredentialRef::new("MMMM.coordinator.peer-native-fixture").unwrap();
        let wrong = CredentialRef::new("MMMM.coordinator.peer-other-fixture").unwrap();
        let token = SecretToken::generate().unwrap();
        let expected = Zeroizing::new(*token.expose_secret());
        let peer = PeerBootstrap::start(&runtime, &reference, token).unwrap();

        assert!(matches!(
            PeerBootstrap::connect_verified_with_deadline(
                runtime.path(),
                &reference,
                None,
                Instant::now()
            ),
            Err(PeerError::Timeout)
        ));
        assert!(matches!(
            PeerBootstrap::connect_verified_with_deadline(
                runtime.path(),
                &reference,
                Some(0),
                Instant::now() + Duration::from_secs(3)
            ),
            Err(PeerError::PeerDenied)
        ));
        let wrong_pid = std::process::id().checked_add(1).unwrap();
        // PID verification denies the opened client before any request/token
        // byte. Repeat that exact close -> accept -> authenticated delivery
        // transition within this one owned server; never replay a delivered
        // request or label a native timing gap as an observed cause.
        for _ in 0..3 {
            let deadline = Instant::now() + Duration::from_secs(3);
            assert!(matches!(
                retry_prewrite_peer_busy(deadline, || {
                    PeerBootstrap::connect_verified_with_deadline(
                        runtime.path(),
                        &reference,
                        Some(wrong_pid),
                        deadline,
                    )
                }),
                Err(PeerError::PeerDenied)
            ));
            let deadline = Instant::now() + Duration::from_secs(3);
            let witnessed = retry_prewrite_peer_busy(deadline, || {
                PeerBootstrap::connect_authenticated_with_deadline(
                    runtime.path(),
                    &reference,
                    deadline,
                )
            })
            .unwrap();
            assert_eq!(witnessed.server_pid(), std::process::id());
            let received = witnessed.into_token();
            assert!(
                received.expose_secret() == &*expected,
                "authenticated native token differs"
            );
            drop(received);
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        let verified = retry_prewrite_peer_busy(deadline, || {
            PeerBootstrap::connect_verified_with_deadline(
                runtime.path(),
                &reference,
                Some(std::process::id()),
                deadline,
            )
        })
        .unwrap();
        assert!(
            verified.expose_secret() == &*expected,
            "PID-bound native token differs"
        );
        drop(verified);

        assert!(PeerBootstrap::connect(runtime.path(), &wrong).is_err());
        let received = PeerBootstrap::connect(runtime.path(), &reference).unwrap();
        // Boolean comparison avoids ever printing either secret on assertion failure.
        assert!(
            received.expose_secret() == &*expected,
            "native token differs"
        );
        drop(received);
        assert_eq!(
            PeerBootstrap::cleanup_stale(runtime.path(), &reference),
            Err(PeerError::Busy)
        );
        #[cfg(windows)]
        let open_peer =
            crate::peer::test_support::open_without_ack(runtime.path(), &reference, &expected)
                .unwrap();
        let shutdown_started = Instant::now();
        peer.shutdown().unwrap();
        assert!(shutdown_started.elapsed() < Duration::from_secs(3));
        #[cfg(windows)]
        {
            drop(open_peer);
            assert!(!crate::peer::fatal_stop_requested());
            // Real ReadFile pending on the missing ACK reaches the actual
            // server deadline and targeted cancellation, without a fault shim.
            let deadline_reference =
                CredentialRef::new("MMMM.coordinator.peer-deadline-fixture").unwrap();
            let token = SecretToken::generate().unwrap();
            let expected = Zeroizing::new(*token.expose_secret());
            let peer = PeerBootstrap::start(&runtime, &deadline_reference, token).unwrap();
            let connection = crate::peer::test_support::open_without_ack(
                runtime.path(),
                &deadline_reference,
                &expected,
            )
            .unwrap();
            let cancellation_before = crate::peer::test_support::cancel_calls();
            let elapsed = connection.wait_for_disconnect().unwrap();
            assert!(elapsed >= Duration::from_secs(4) && elapsed < Duration::from_secs(8));
            assert!(crate::peer::test_support::cancel_calls() > cancellation_before);
            assert!(!crate::peer::fatal_stop_requested());
            peer.shutdown().unwrap();

            let eof_reference = CredentialRef::new("MMMM.coordinator.peer-eof-fixture").unwrap();
            let token = SecretToken::generate().unwrap();
            let expected = Zeroizing::new(*token.expose_secret());
            let peer = PeerBootstrap::start(&runtime, &eof_reference, token).unwrap();
            let connection = crate::peer::test_support::open_without_ack(
                runtime.path(),
                &eof_reference,
                &expected,
            )
            .unwrap();
            // Closing the actual client endpoint gives the server EOF while it
            // awaits ACK; explicit shutdown still joins the worker promptly.
            drop(connection);
            let shutdown_started = Instant::now();
            peer.shutdown().unwrap();
            assert!(shutdown_started.elapsed() < Duration::from_secs(3));
            assert!(!crate::peer::fatal_stop_requested());
            assert_eq!(crate::peer::test_support::retained_owners(), 0);
        }
        assert!(PeerBootstrap::connect(runtime.path(), &reference).is_err());
        PeerBootstrap::cleanup_stale(runtime.path(), &reference).unwrap();
        assert_eq!(fs::read_dir(runtime.path()).unwrap().count(), 0);
        drop(runtime);
        drop(store);
    }

    let root = PeerTestRoot::new();
    let config = root.config();
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let (admit_sender, admit_receiver) = mpsc::sync_channel(0);
    let mut running = RunningCoordinator {
        stop: None,
        worker: Some(thread::spawn(move || {
            let startup = ApplicationService::open(config, ports(Seen::default()))
                .map_err(|error| format!("{error:?}"))
                .and_then(|service| {
                    crate::Coordinator::start(service, policy(&["prefab.validate"], &[]))
                        .map_err(|error| format!("{error:?}"))
                });
            let mut coordinator = match startup {
                Ok(coordinator) => coordinator,
                Err(error) => {
                    let _ = ready_sender.send(Err(error.clone()));
                    return Err(error);
                }
            };
            let ready = (coordinator.endpoint().clone(), coordinator.stop_handle());
            // The worker never begins serving if readiness is not accepted.
            // This also gives assertion unwinding a bounded startup exit.
            if ready_sender.send(Ok(ready)).is_err()
                || admit_receiver.recv_timeout(Duration::from_secs(5)).is_err()
            {
                return coordinator.shutdown().map_err(|error| error.to_string());
            }
            let served = coordinator.serve().map_err(|error| error.to_string());
            let cleanup = coordinator.shutdown().map_err(|error| error.to_string());
            served.and(cleanup)
        })),
    };
    let (record, stop) = ready_receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("Coordinator worker returned before publishing startup result")
        .unwrap();
    running.stop = Some(stop);
    admit_sender.send(()).unwrap();

    let runtime = RuntimeDirectory::open(&root.runtime()).unwrap();
    assert_eq!(runtime.load().unwrap(), record);
    assert!(record.credential_ref.starts_with("MMMM.coordinator.peer-"));
    let reference = CredentialRef::new(&record.credential_ref).unwrap();
    let client = CoordinatorClient::discover_peer(runtime.path()).unwrap();
    let input = prefab();
    let expected = mmmm_domain::prefab_validate(&input).unwrap();
    assert_eq!(client.call("prefab.validate", &input).unwrap(), expected);
    assert!(matches!(
        DurableStore::open(root.config()),
        Err(StorageError::Busy)
    ));
    drop(client);
    running.finish();
    // Explicit shutdown releases the actual SQLite/data-root ownership too;
    // keep the reopened lease for the final exact stale-resource verification.
    let reopened_store = DurableStore::open(root.config()).unwrap();

    assert!(matches!(
        runtime.load(),
        Err(crate::endpoint::EndpointError::Missing)
    ));
    assert!(PeerBootstrap::connect(runtime.path(), &reference).is_err());
    PeerBootstrap::cleanup_stale(runtime.path(), &reference).unwrap();
    assert_eq!(fs::read_dir(runtime.path()).unwrap().count(), 0);
    drop(runtime);
    drop(reopened_store);
    assert!(!crate::peer::fatal_stop_requested());
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug)]
enum ChildFailureWitness {
    Deadline,
    Observation(Option<i32>),
}

#[cfg(windows)]
#[derive(Debug)]
struct ChildStopFailure {
    witness: ChildFailureWitness,
    terminal_status: Option<std::process::ExitStatus>,
    kill_error: Option<i32>,
    drain_error: Option<i32>,
}

#[cfg(windows)]
fn wait_owned_leaf_child(
    child: &mut std::process::Child,
    limit: Duration,
) -> Result<std::process::ExitStatus, ChildStopFailure> {
    // This exact ignored test starts threads only; it never creates descendant
    // processes. The directly owned child is therefore the complete test tree.
    let deadline = Instant::now() + limit;
    let witness = loop {
        match child.try_wait() {
            Ok(Some(status)) if Instant::now() < deadline => return Ok(status),
            Ok(Some(status)) => {
                return Err(ChildStopFailure {
                    witness: ChildFailureWitness::Deadline,
                    terminal_status: Some(status),
                    kill_error: None,
                    drain_error: None,
                });
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => break ChildFailureWitness::Deadline,
            Err(error) => break ChildFailureWitness::Observation(error.raw_os_error()),
        }
    };
    let kill_error = child.kill().err().and_then(|error| error.raw_os_error());
    let drain_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            // A later exit, including exit 0, cannot erase the first deadline or
            // observation failure. It proves only that cleanup is now allowed.
            Ok(Some(status)) => {
                return Err(ChildStopFailure {
                    witness,
                    terminal_status: Some(status),
                    kill_error,
                    drain_error: None,
                });
            }
            Ok(None) if Instant::now() < drain_deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                return Err(ChildStopFailure {
                    witness,
                    terminal_status: None,
                    kill_error,
                    drain_error: None,
                });
            }
            Err(error) => {
                return Err(ChildStopFailure {
                    witness,
                    terminal_status: None,
                    kill_error,
                    drain_error: error.raw_os_error(),
                });
            }
        }
    }
}

#[cfg(windows)]
fn persistent_evidence_parent(kind: &str) -> std::io::Result<PathBuf> {
    use std::mem::{MaybeUninit, size_of};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use std::path::{Component, Prefix};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };
    type DirectoryIdentity = (u64, [u8; 16]);
    let reject = |stage: &'static str| {
        std::io::Error::other(format!(
            "native evidence directory boundary rejected at {stage}"
        ))
    };
    let observe_error = |stage: &'static str, error: std::io::Error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "native evidence directory observation failed at {stage}; OS code {:?}",
                error.raw_os_error()
            ),
        )
    };
    let ordinary = |path: &Path, stage: &'static str| -> std::io::Result<()> {
        let metadata = fs::symlink_metadata(path).map_err(|error| observe_error(stage, error))?;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(reject(stage));
        }
        Ok(())
    };
    let pin =
        |path: &Path, stage: &'static str| -> std::io::Result<(fs::File, DirectoryIdentity)> {
            ordinary(path, stage)?;
            // Attributes-only access and no DELETE sharing keep this exact ordinary
            // directory alive through parent/child verification without content I/O.
            let file = fs::OpenOptions::new()
                .read(true)
                .access_mode(0x80)
                .share_mode(3)
                .custom_flags(0x0200_0000 | 0x0020_0000)
                .open(path)
                .map_err(|error| observe_error(stage, error))?;
            let metadata = file
                .metadata()
                .map_err(|error| observe_error(stage, error))?;
            if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
                return Err(reject(stage));
            }
            let mut information = MaybeUninit::<FILE_ID_INFO>::uninit();
            // SAFETY: a live owned directory handle, exact FileIdInfo output class,
            // properly aligned structure storage and its precise native byte size.
            if unsafe {
                GetFileInformationByHandleEx(
                    file.as_raw_handle(),
                    FileIdInfo,
                    information.as_mut_ptr().cast(),
                    size_of::<FILE_ID_INFO>() as u32,
                )
            } == 0
            {
                return Err(observe_error(stage, std::io::Error::last_os_error()));
            }
            // SAFETY: successful native call initialized the entire FILE_ID_INFO.
            let information = unsafe { information.assume_init() };
            Ok((
                file,
                (
                    information.VolumeSerialNumber,
                    information.FileId.Identifier,
                ),
            ))
        };
    let resolve = |path: &Path, stage: &'static str| -> std::io::Result<PathBuf> {
        ordinary(path, stage)?;
        let resolved = fs::canonicalize(path).map_err(|error| observe_error(stage, error))?;
        if !resolved.is_absolute()
            || !matches!(resolved.components().next(), Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        {
            return Err(reject(stage));
        }
        Ok(resolved)
    };
    if !matches!(
        kind,
        "native-peer-fixtures" | "native-peer-unconfirmed-drain"
    ) {
        return Err(reject("kind"));
    }
    let app_data = std::env::var_os("APPDATA").ok_or_else(|| reject("appdata_missing"))?;
    let app_data = PathBuf::from(app_data);
    if !app_data.is_absolute()
        || !matches!(app_data.components().next(), Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
    {
        return Err(reject("appdata_prefix"));
    }
    // 정확히 지정된 APPDATA ancestry만 검사한다. Junction을 따라 다른
    // evidence root를 채택하거나 다른 directory를 열거하지 않는다.
    let mut ancestry = PathBuf::new();
    let mut pins = Vec::new();
    for component in app_data.components() {
        ancestry.push(component.as_os_str());
        if !matches!(component, Component::Prefix(_)) {
            if pins.len() >= 64 {
                return Err(reject("appdata_ancestry_budget"));
            }
            pins.push(pin(&ancestry, "appdata_ancestry")?.0);
        }
    }
    let mut path = resolve(&app_data, "appdata")?;
    let checkout = resolve(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."),
        "checkout",
    )?;
    let scratch = resolve(&std::env::temp_dir(), "scratch")?;
    if path.starts_with(&checkout) || path.starts_with(&scratch) {
        return Err(reject("appdata_overlap"));
    }
    for name in ["MMMM", "evidence", "development", kind] {
        let stage = match name {
            "MMMM" => "mmmm_parent",
            "evidence" => "evidence_parent",
            "development" => "development_parent",
            "native-peer-fixtures" => "fixture_parent",
            "native-peer-unconfirmed-drain" => "export_parent",
            _ => return Err(reject("kind")),
        };
        let (parent_pin, parent_identity) = pin(&path, "parent_pin")?;
        pins.push(parent_pin);
        let candidate = path.join(name);
        match fs::create_dir(&candidate) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(observe_error(stage, error)),
        }
        let (child_pin, child_identity) = pin(&candidate, stage)?;
        pins.push(child_pin);
        let resolved = resolve(&candidate, stage)?;
        let (resolved_child_pin, resolved_child_identity) = pin(&resolved, "resolved_child")?;
        pins.push(resolved_child_pin);
        let (resolved_parent_pin, resolved_parent_identity) = pin(
            resolved
                .parent()
                .ok_or_else(|| reject("child_parent_missing"))?,
            "resolved_parent",
        )?;
        pins.push(resolved_parent_pin);
        let (reopened_parent_pin, reopened_parent_identity) = pin(&path, "parent_recheck")?;
        pins.push(reopened_parent_pin);
        // Windows 경로 casing/VerbatimDisk 문자열 대신 열린 객체의 실제
        // volume serial + 128-bit file ID를 비교한다. 고정 부모와 자식 핸들을
        // 유지하므로 문자열 차이를 허용해도 물리적 경계는 완화하지 않는다.
        if resolved_parent_identity != parent_identity
            || reopened_parent_identity != parent_identity
            || resolved_child_identity != child_identity
            || !resolved
                .file_name()
                .and_then(|leaf| leaf.to_str())
                .is_some_and(|leaf| leaf.eq_ignore_ascii_case(name))
        {
            return Err(reject("child_parent_identity"));
        }
        path = resolved;
    }
    if path.starts_with(&checkout)
        || checkout.starts_with(&path)
        || path.starts_with(&scratch)
        || scratch.starts_with(&path)
    {
        return Err(reject("evidence_overlap"));
    }
    Ok(path)
}

#[cfg(windows)]
fn print_child_public_diagnostics(root: &Path) {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    if fs::canonicalize(root).ok().as_deref() != Some(root)
        || !owned_plain_tree(root)
        || fs::read(root.join("test-owner.txt")).ok().as_deref() != Some(PEER_OWNER)
    {
        println!("Isolated native peer diagnostics withheld: source ownership boundary changed");
        return;
    }
    // This exact child has no credential-file writer or secret Debug types.
    // These are only its public Rust test harness diagnostics, bounded in total.
    for name in ["child-stdout.log", "child-stderr.log"] {
        let result = fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x0020_0000)
            .open(root.join(name))
            .and_then(|file| {
                let metadata = file.metadata()?;
                if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
                    return Err(std::io::Error::other(
                        "public diagnostic is not an ordinary file",
                    ));
                }
                let mut bytes = Vec::new();
                file.take(32 * 1024).read_to_end(&mut bytes)?;
                Ok(bytes)
            });
        match result {
            Ok(bytes) => println!(
                "Isolated native peer public {name} (at most 32768 bytes):\n{}",
                String::from_utf8_lossy(&bytes)
            ),
            Err(error) => println!(
                "Isolated native peer public diagnostic unavailable: {name}, OS code {:?}",
                error.raw_os_error()
            ),
        }
    }
}

#[cfg(windows)]
fn child_assertions_witness(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > 4096 {
        return false;
    }
    let Ok(value) = parse_json(bytes) else {
        return false;
    };
    let keys = [
        "schemaVersion",
        "kind",
        "fault",
        "targetedCancelCalls",
        "retainedOwners",
        "operationStatePreserved",
        "invocationPreserved",
        "casEvidencePreserved",
        "endpointPreserved",
        "clientAndServiceAdmissionRejected",
        "newNativeIoRejected",
    ];
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    }) && value["schemaVersion"] == 1
        && value["kind"] == "native_peer_child_assertions_passed"
        && value["fault"] == "test_only_unknown_completion_after_actual_targeted_cancel"
        && value["targetedCancelCalls"]
            .as_u64()
            .is_some_and(|count| count > 0)
        && value["retainedOwners"] == 1
        && value["operationStatePreserved"] == "outcome_unknown"
        && [
            "invocationPreserved",
            "casEvidencePreserved",
            "endpointPreserved",
            "clientAndServiceAdmissionRejected",
            "newNativeIoRejected",
        ]
        .iter()
        .all(|key| value[*key] == true)
}

#[cfg(windows)]
fn export_child_public_evidence(
    root: &Path,
    outcome: &Result<std::process::ExitStatus, ChildStopFailure>,
) -> std::io::Result<PathBuf> {
    use sha2::{Digest, Sha256};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_LIMIT: u64 = 8 * 1024 * 1024;
    const TOTAL_LIMIT: u64 = 64 * 1024 * 1024;
    let invalid = || {
        std::io::Error::other(
            "native evidence export ownership, size or public-file boundary failed",
        )
    };
    if fs::canonicalize(root)? != root
        || !owned_plain_tree(root)
        || fs::read(root.join("test-owner.txt"))? != PEER_OWNER
    {
        return Err(invalid());
    }
    let parent = persistent_evidence_parent("native-peer-unconfirmed-drain")?;
    let mut nonce = [0_u8; 8];
    getrandom::fill(&mut nonce)
        .map_err(|_| std::io::Error::other("public evidence ownership nonce unavailable"))?;
    let destination = parent.join(format!(
        "e-{:x}-{:016x}",
        std::process::id(),
        u64::from_be_bytes(nonce)
    ));
    fs::create_dir(&destination)?;
    // This final evidence root intentionally has no automatic Drop cleanup.
    // Partial export is retained and never reported as a completed receipt.
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    let mut nodes = 0_usize;
    let mut total = 0_u64;
    let mut entries = Vec::new();
    let mut assertions_verified = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while let Some((path, depth)) = pending.pop() {
        nodes += 1;
        if nodes > 512 || depth > 8 || Instant::now() >= deadline || !path.starts_with(root) {
            return Err(invalid());
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid());
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                pending.push((entry?.path(), depth + 1));
            }
            continue;
        }
        if !metadata.is_file() {
            return Err(invalid());
        }
        let relative = path.strip_prefix(root).map_err(|_| invalid())?;
        let parts: Vec<_> = relative
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect();
        let public_name = parts.join("/");
        let cas_digest = if parts.len() == 4 && parts[0] == "data" && parts[1] == "blobs" {
            let digest = format!("{}{}", parts[2], parts[3]);
            (parts[2].len() == 2
                && parts[3].len() == 62
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
            .then_some(digest)
        } else {
            None
        };
        let allowed = matches!(
            public_name.as_str(),
            "test-owner.txt"
                | "child-stdout.log"
                | "child-stderr.log"
                | "child-success.json"
                | "data/journal.sqlite3"
                | "data/journal.sqlite3-wal"
                | "data/journal.sqlite3-shm"
                | "data/runtime/coordinator-endpoint.json"
        ) || cas_digest.is_some();
        if !allowed {
            // Store lock files, unused additional-service state, incoming scratch
            // and any other file are excluded. No credential/auth files are read.
            continue;
        }
        if metadata.len() > FILE_LIMIT
            || total
                .checked_add(metadata.len())
                .is_none_or(|size| size > TOTAL_LIMIT)
        {
            return Err(invalid());
        }
        let mut input = fs::OpenOptions::new()
            .read(true)
            .custom_flags(OPEN_REPARSE_POINT)
            .open(&path)?;
        let pinned = input.metadata()?;
        if !pinned.is_file()
            || pinned.file_attributes() & 0x400 != 0
            || pinned.len() != metadata.len()
        {
            return Err(invalid());
        }
        if public_name == "data/runtime/coordinator-endpoint.json"
            || public_name == "child-success.json"
        {
            if pinned.len() > 4096 {
                return Err(invalid());
            }
            let mut bytes = Vec::new();
            (&mut input).take(4097).read_to_end(&mut bytes)?;
            if public_name == "child-success.json" {
                if !child_assertions_witness(&bytes) {
                    return Err(invalid());
                }
                assertions_verified = true;
            } else {
                let value = parse_json(&bytes).map_err(|_| invalid())?;
                let record: EndpointRecord =
                    serde_json::from_value(value).map_err(|_| invalid())?;
                record.validate().map_err(|_| invalid())?;
            }
            use std::io::{Seek, SeekFrom};
            input.seek(SeekFrom::Start(0))?;
        }
        let target = destination.join(relative);
        fs::create_dir_all(target.parent().ok_or_else(invalid)?)?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        let mut digest = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = [0_u8; 4096];
        loop {
            if Instant::now() >= deadline {
                return Err(invalid());
            }
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copied += count as u64;
            if copied > pinned.len() {
                return Err(invalid());
            }
            output.write_all(&buffer[..count])?;
            digest.update(&buffer[..count]);
        }
        if copied != pinned.len() || input.metadata()?.len() != copied {
            return Err(invalid());
        }
        output.sync_all()?;
        let digest = format!("{:x}", digest.finalize());
        if cas_digest
            .as_ref()
            .is_some_and(|expected| expected != &digest)
        {
            return Err(invalid());
        }
        let mut verify = fs::File::open(&target)?.take(FILE_LIMIT + 1);
        let mut verify_digest = Sha256::new();
        let mut verified = 0_u64;
        loop {
            let count = verify.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            verified += count as u64;
            verify_digest.update(&buffer[..count]);
        }
        if verified != copied || format!("{:x}", verify_digest.finalize()) != digest {
            return Err(invalid());
        }
        total += copied;
        entries.push(json!({"path":public_name,"byteLength":copied,"sha256":digest}));
    }
    entries.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    // A mistyped --exact filter can exit 0 after executing zero tests. Require
    // the fresh child's strict witness plus actual exported recovery material.
    if outcome.as_ref().is_ok_and(|status| status.success())
        && (!assertions_verified
            || !entries
                .iter()
                .any(|entry| entry["path"] == "data/journal.sqlite3")
            || !entries
                .iter()
                .any(|entry| entry["path"] == "data/runtime/coordinator-endpoint.json")
            || !entries.iter().any(|entry| {
                entry["path"]
                    .as_str()
                    .is_some_and(|path| path.starts_with("data/blobs/"))
            }))
    {
        return Err(invalid());
    }
    let child_result = match outcome {
        Ok(status) => {
            json!({"observedBeforeDeadline":true,"success":status.success(),"exitCode":status.code()})
        }
        Err(error) => {
            let (kind, code) = match error.witness {
                ChildFailureWitness::Deadline => ("deadline", None),
                ChildFailureWitness::Observation(code) => ("observation", code),
            };
            json!({"observedBeforeDeadline":false,"firstFailure":kind,"observationOsCode":code,"terminalExitCode":error.terminal_status.and_then(|status| status.code()),"killOsCode":error.kill_error,"drainOsCode":error.drain_error})
        }
    };
    let receipt = json!({"schemaVersion":1,"kind":"native_peer_child_public_evidence","childResult":child_result,"nativeFault":"test_only_unknown_completion_after_actual_targeted_cancel","assertionsWitnessVerified":assertions_verified,"files":entries,"totalByteLength":total,"copyReadbackVerified":true});
    let bytes = serde_json::to_vec_pretty(&receipt).map_err(|_| invalid())?;
    let mut receipt_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination.join("receipt.json"))?;
    receipt_file.write_all(&bytes)?;
    receipt_file.sync_all()?;
    Ok(destination)
}

#[cfg(windows)]
#[test]
fn unconfirmed_drain_is_isolated_and_preserves_recovery_material() {
    // This source fixture also lives outside the managed scratch root, so a
    // failed export or uncertain child stop cannot be erased by runner cleanup.
    let root = PeerTestRoot::new_persistent();
    let stdout = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.0.join("child-stdout.log"))
        .unwrap();
    let stderr = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.0.join("child-stderr.log"))
        .unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            crate::peer::test_support::ISOLATED_TEST,
            "--ignored",
            "--nocapture",
        ])
        // Public test-owned root only. No token, credential or secret uses env,
        // files or argv; all bootstrap secrets remain in child memory.
        .env("MMMM_PEER_TEST_ROOT", &root.0)
        .stdin(std::process::Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .unwrap();
    let outcome = wait_owned_leaf_child(&mut child, Duration::from_secs(30));
    let terminal = match &outcome {
        Ok(_) => true,
        Err(error) => error.terminal_status.is_some(),
    };
    if !terminal {
        std::mem::forget(root);
        panic!(
            "isolated native child stop is unconfirmed; persistent fixture retained: {outcome:?}"
        );
    }
    print_child_public_diagnostics(&root.0);
    let exported = match export_child_public_evidence(&root.0, &outcome) {
        Ok(exported) => exported,
        Err(error) => {
            std::mem::forget(root);
            panic!("native child evidence export failed; persistent fixture retained: {error}");
        }
    };
    println!(
        "Native peer evidence exported to MMMM/evidence/development/native-peer-unconfirmed-drain/{}/receipt.json",
        exported.file_name().unwrap().to_string_lossy()
    );
    // The child's terminal status and durable export receipt are both observed
    // before the exact source fixture becomes eligible for its guarded Drop.
    let source = root.0.clone();
    drop(root);
    assert!(
        !source.exists(),
        "exported native fixture cleanup was not confirmed"
    );
    let status = outcome.expect("isolated child exceeded deadline or observation failed");
    assert!(status.success(), "isolated child failed: {status}");
    assert!(!crate::peer::fatal_stop_requested());
}

#[cfg(windows)]
#[test]
#[ignore = "only invoked by its bounded exact parent subprocess"]
fn isolated_unconfirmed_drain_child() {
    use mmmm_contracts::{OperationId, PlanId, StepId, projected_digest};
    use mmmm_runtime::storage::{OperationState, ReserveOperation};

    assert!(std::env::args().any(|arg| arg == crate::peer::test_support::ISOLATED_TEST));
    let root = fs::canonicalize(
        std::env::var_os("MMMM_PEER_TEST_ROOT").expect("public parent-owned test root"),
    )
    .unwrap();
    let persistent = persistent_evidence_parent("native-peer-fixtures").unwrap();
    let checkout =
        fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    assert!(root.parent() == Some(persistent.as_path()) && !root.starts_with(checkout));
    assert!(
        root.file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.starts_with("mp-"))
    );
    assert!(owned_plain_tree(&root));
    assert!(fs::read(root.join("test-owner.txt")).unwrap() == PEER_OWNER);

    let data_root = root.join("data");
    let config = StoreConfig::new(data_root.clone());
    let operation = OperationId::new("peer-fault-operation").unwrap();
    let step = StepId::new("echo-step").unwrap();
    let mut plan = parse_json(include_bytes!("../../../examples/execution-plan.json")).unwrap();
    plan["planId"] = json!("peer-fault-plan");
    plan["scope"]["resourceIds"] = json!(["peer-fault-resource"]);
    plan["steps"][0]["effect"] = json!("write");
    plan["steps"][0]["verificationRequirement"] = json!("independent_readback");
    plan["steps"][0]["resourcesWritten"] = json!(["peer-fault-resource"]);
    plan["planHash"] = json!(projected_digest("ExecutionPlan", &plan).unwrap());
    let mut invocation = parse_json(include_bytes!("../../../examples/invocation.json")).unwrap();
    invocation["operationId"] = json!(operation.as_str());
    invocation["invocationId"] = json!("peer-fault-invocation");
    let evidence_bytes = b"durable peer-fault recovery evidence\n";
    let (before, evidence) = {
        let mut store = DurableStore::open(config.clone()).unwrap();
        store.save_project(&project(), None).unwrap();
        store.save_plan(&plan).unwrap();
        store
            .reserve_operation(ReserveOperation {
                operation_id: operation.clone(),
                principal: PrincipalId::new("principal-fixture").unwrap(),
                project_id: ProjectId::new("project-fixture").unwrap(),
                idempotency_key: "peer-fault-idempotency".to_owned(),
                plan_id: PlanId::new("peer-fault-plan").unwrap(),
                plan_hash: serde_json::from_value(plan["planHash"].clone()).unwrap(),
                context_id: ContextId::new("context-fixture-01").unwrap(),
            })
            .unwrap();
        store
            .dispatch_intent(&operation, &step, &invocation)
            .unwrap();
        store.mark_outcome_unknown(&operation, &step).unwrap();
        let evidence = store.put_blob(evidence_bytes).unwrap();
        store.pin_operation_artifact(&operation, &evidence).unwrap();
        (store.operation(&operation).unwrap(), evidence)
    };
    assert_eq!(before.state, OperationState::OutcomeUnknown);
    assert!(before.steps[0].further_effects_possible);

    let seen = Seen::default();
    let service = ApplicationService::open(config.clone(), ports(seen.clone())).unwrap();
    let mut coordinator =
        crate::Coordinator::start(service, policy(&["prefab.validate"], &[])).unwrap();
    let runtime = RuntimeDirectory::open(&data_root.join("runtime")).unwrap();
    let record = runtime.load().unwrap();
    let reference = CredentialRef::new(&record.credential_ref).unwrap();
    let client = CoordinatorClient::discover_peer(runtime.path()).unwrap();
    let (_authority, _token, principal) = session(&["prefab.validate"], &[]);
    let additional_seen = Seen::default();
    let mut additional_service = ApplicationService::open(
        StoreConfig::new(root.join("additional-service")),
        ports(additional_seen.clone()),
    )
    .unwrap();

    crate::peer::test_support::force_unknown_after_actual_cancel();
    let deadline = Instant::now() + Duration::from_secs(12);
    while !crate::peer::fatal_stop_requested() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(crate::peer::fatal_stop_requested());
    assert!(crate::peer::test_support::cancel_calls() > 0);
    assert_eq!(crate::peer::test_support::retained_owners(), 1);
    assert!(matches!(
        client.call("prefab.validate", &prefab()),
        Err(crate::client::ClientError::LocalTransportUncertain)
    ));
    assert_eq!(
        additional_service
            .call(&principal, "prefab.validate", &prefab(), &budget())
            .unwrap_err()
            .code,
        "LOCAL_TRANSPORT_UNCERTAIN"
    );
    assert!(additional_seen.values().is_empty());
    assert!(coordinator.serve().is_err());
    assert!(seen.values().is_empty());
    assert!(matches!(
        PeerBootstrap::connect(runtime.path(), &reference),
        Err(PeerError::UncertainDrain)
    ));
    assert!(matches!(
        PeerBootstrap::start(&runtime, &reference, SecretToken::generate().unwrap()),
        Err(PeerError::UncertainDrain)
    ));
    assert!(matches!(
        coordinator.shutdown(),
        Err(crate::lifecycle::CoordinatorError::Cleanup)
    ));
    assert_eq!(runtime.load().unwrap(), record);
    assert_eq!(
        PeerBootstrap::cleanup_stale(runtime.path(), &reference),
        Err(PeerError::UncertainDrain)
    );
    let store = DurableStore::open(config).unwrap();
    assert_eq!(store.operation(&operation).unwrap(), before);
    assert_eq!(
        store.stored_invocation(&operation, &step).unwrap(),
        invocation
    );
    assert_eq!(store.read_blob(&evidence).unwrap(), evidence_bytes);
    assert_eq!(
        store
            .project(&ProjectId::new("project-fixture").unwrap())
            .unwrap(),
        project()
    );
    assert!(matches!(
        store.check_write_scope(&before.scope, before.whole_project_fence, None),
        Err(StorageError::Fenced(_))
    ));
    assert_eq!(crate::peer::test_support::retained_owners(), 1);
    let success = json!({
        "schemaVersion":1,
        "kind":"native_peer_child_assertions_passed",
        "fault":"test_only_unknown_completion_after_actual_targeted_cancel",
        "targetedCancelCalls":crate::peer::test_support::cancel_calls(),
        "retainedOwners":1,
        "operationStatePreserved":"outcome_unknown",
        "invocationPreserved":true,
        "casEvidencePreserved":true,
        "endpointPreserved":true,
        "clientAndServiceAdmissionRejected":true,
        "newNativeIoRejected":true
    });
    let mut success_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("child-success.json"))
        .unwrap();
    success_file
        .write_all(&serde_json::to_vec_pretty(&success).unwrap())
        .unwrap();
    success_file.sync_all().unwrap();
    // The retained native owner is intentionally never reclaimed in this child.
    // The exact parent waits for process exit before fixture cleanup is allowed.
}

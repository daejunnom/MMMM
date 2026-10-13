//! Concrete native entrypoints reuse the one protected daemon composition.
//! Arguments are public locators and requested metadata; capabilities remain
//! in the authenticated peer or anonymous host exchange, never in argv.

use crate::{
    CoordinatorClient,
    daemon::{DaemonError, PreparedDaemon},
    daemon_launch::{self, DaemonLaunchError, NativeDaemonLocator},
    host_relay::{self, RelayError},
    lifecycle::{Coordinator, CoordinatorError},
    local_setup::{LocalHostSetup, LocalSetupError, register_local_host_setup},
    production_factory::ProductionFactory,
    stdio_io::{NativeStdioPort, StdioError, StdioLimits},
};
use mmmm_contracts::{JsonLimits, ProjectId, TargetProfileId, encode_json, parse_json_with_limits};
use mmmm_runtime::storage::StoreConfig;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::atomic::AtomicBool,
    task::Poll,
    time::{Duration, Instant},
};

const OUTPUT: Duration = Duration::from_secs(5);
const DRAIN: Duration = Duration::from_secs(3);
const POLL: Duration = Duration::from_millis(5);
const MAX_OUTPUT: usize = 64 * 1024;

#[derive(Debug)]
pub enum EntryError {
    Arguments,
    Deadline,
    Daemon(DaemonError),
    Launch(DaemonLaunchError),
    Setup(LocalSetupError),
    Relay(RelayError),
    Client(crate::client::ClientError),
    Peer(crate::peer::PeerError),
    Output(StdioError),
    OutputInvalid,
    DrainUncertain,
    Initialized {
        project: ProjectId,
        revision: mmmm_contracts::Sha256Digest,
        delivery: Box<EntryError>,
    },
    Shutdown {
        primary: Option<Box<EntryError>>,
        cleanup: CoordinatorError,
    },
}
impl std::fmt::Display for EntryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Arguments => f.write_str("Native command arguments are invalid"),
            Self::Deadline => f.write_str("Native command startup or delivery deadline reached"),
            Self::Daemon(error) => error.fmt(f),
            Self::Launch(error) => error.fmt(f),
            Self::Setup(error) => error.fmt(f),
            Self::Relay(error) => error.fmt(f),
            Self::Client(_) => f.write_str("Selected Project could not be inspected through the authenticated Coordinator"),
            Self::Peer(_) => f.write_str("The exact selected Coordinator generation could not be authenticated"),
            Self::Output(_) | Self::OutputInvalid => f.write_str("Native command result delivery failed; confirmed durable data is retained"),
            Self::DrainUncertain => f.write_str("Native command output owner termination is unconfirmed"),
            Self::Initialized { project, revision, delivery } => write!(f,
                "Project {project} at revision {revision} was initialized and retained; result delivery failed: {delivery}"),
            Self::Shutdown { .. } => f.write_str("Coordinator shutdown is unresolved; durable data and discovery requiring cleanup are retained"),
        }
    }
}
impl std::error::Error for EntryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Daemon(e) => Some(e),
            Self::Launch(e) => Some(e),
            Self::Setup(e) => Some(e),
            Self::Relay(e) => Some(e),
            Self::Client(e) => Some(e),
            Self::Peer(e) => Some(e),
            Self::Output(e) => Some(e),
            Self::Initialized { delivery, .. } => Some(delivery.as_ref()),
            Self::Shutdown { cleanup, .. } => Some(cleanup),
            _ => None,
        }
    }
}

enum Command {
    Init {
        root: PathBuf,
        name: String,
        target: TargetProfileId,
    },
    Foreground {
        root: PathBuf,
        project: ProjectId,
        lifetime: Duration,
    },
    Start {
        root: PathBuf,
        project: ProjectId,
    },
    Setup {
        root: PathBuf,
        project: ProjectId,
        jar: PathBuf,
        destination: PathBuf,
        scope: Value,
    },
    HostBridge,
    Owned(Vec<String>),
}

/// Returns false only for a command owned by the ordinary CLI/MCP facade.
/// The caller dispatches the existing isolated-stdio worker before this API.
pub fn dispatch(args: &[String]) -> Result<bool, EntryError> {
    let Some(command) = parse(args)? else {
        return Ok(false);
    };
    match command {
        Command::HostBridge => {
            host_relay::run_stdio(&mut NativeDaemonLocator).map_err(EntryError::Relay)?;
        }
        Command::Owned(args) => {
            let mut owner = daemon_launch::adopt_child(&args).map_err(EntryError::Launch)?;
            let digest = daemon_launch::current_executable_digest(owner.startup_deadline())
                .map_err(EntryError::Launch)?;
            let mut factory = ProductionFactory::offline_owned(digest);
            let prepared = PreparedDaemon::open(
                StoreConfig::new(owner.data_root().to_path_buf()),
                Some(owner.project_id().clone()),
                &mut factory,
            )
            .map_err(EntryError::Daemon)?;
            check(owner.startup_deadline())?;
            let mut coordinator = prepared.start().map_err(EntryError::Daemon)?;
            let primary = match owner.ready(coordinator.endpoint()) {
                Ok(()) => coordinator
                    .serve_until(owner.lifetime_deadline())
                    .map_err(|e| EntryError::Daemon(DaemonError::Coordinator(e))),
                Err(error) => Err(EntryError::Launch(error)),
            };
            finish(coordinator, primary)?;
            // Keep the native Job/session owner through explicit shutdown.
            drop(owner);
        }
        Command::Init { root, name, target } => {
            let digest =
                daemon_launch::current_executable_digest(Instant::now() + Duration::from_secs(10))
                    .map_err(EntryError::Launch)?;
            let mut factory = ProductionFactory::offline_owned(digest);
            let (prepared, receipt) =
                PreparedDaemon::initialize(StoreConfig::new(root), &name, &target, &mut factory)
                    .map_err(EntryError::Daemon)?;
            let result = json!({"kind":"project_initialized","projectId":receipt.project_id,
                "revision":receipt.project_revision,"policyResource":receipt.policy_resource});
            // The one locked Store has committed both documents. No listener
            // or Apply grant was published; a later daemon selects this ID.
            drop(prepared);
            output(&result, Instant::now() + OUTPUT).map_err(|delivery| {
                EntryError::Initialized {
                    project: receipt.project_id,
                    revision: receipt.project_revision,
                    delivery: Box::new(delivery),
                }
            })?;
        }
        Command::Foreground {
            root,
            project,
            lifetime,
        } => {
            let deadline = Instant::now() + lifetime;
            let digest = daemon_launch::current_executable_digest(
                deadline.min(Instant::now() + Duration::from_secs(10)),
            )
            .map_err(EntryError::Launch)?;
            let mut factory = ProductionFactory::offline_owned(digest);
            let prepared =
                PreparedDaemon::open(StoreConfig::new(root), Some(project.clone()), &mut factory)
                    .map_err(EntryError::Daemon)?;
            check(deadline)?;
            let mut coordinator = prepared.start().map_err(EntryError::Daemon)?;
            let primary = match output(
                &json!({"kind":"coordinator_started","projectId":project,
                "address":coordinator.endpoint().address,"coordinatorEpoch":coordinator.endpoint().coordinator_epoch}),
                deadline,
            ) {
                Ok(()) => coordinator
                    .serve_until(deadline)
                    .map_err(|e| EntryError::Daemon(DaemonError::Coordinator(e))),
                Err(error) => Err(error),
            };
            finish(coordinator, primary)?;
        }
        Command::Start { root, project } => {
            let endpoint = NativeDaemonLocator
                .ensure(&root, &project, Instant::now() + Duration::from_secs(30))
                .map_err(EntryError::Launch)?;
            // Existing endpoint identity alone does not authorize a different
            // selected Project. The common service verifies its current ACL.
            let reference = crate::credential::CredentialRef::new(&endpoint.credential_ref)
                .map_err(|_| EntryError::Arguments)?;
            let token = crate::peer::PeerBootstrap::connect(&root.join("runtime"), &reference)
                .map_err(EntryError::Peer)?;
            let client =
                CoordinatorClient::paired(endpoint.clone(), token).map_err(EntryError::Client)?;
            client
                .call(
                    "project.inspect",
                    &json!({"projectId":project,"expectedRevision":null}),
                )
                .map_err(EntryError::Client)?;
            output(
                &json!({"kind":"coordinator_ready","projectId":project,
                "address":endpoint.address,"coordinatorEpoch":endpoint.coordinator_epoch}),
                Instant::now() + OUTPUT,
            )?;
        }
        Command::Setup {
            root,
            project,
            jar,
            destination,
            scope,
        } => {
            let executable = std::env::current_exe().map_err(|_| EntryError::Arguments)?;
            let setup = register_local_host_setup(
                StoreConfig::new(root),
                LocalHostSetup {
                    executable: &executable,
                    installed_host_jar: &jar,
                    destination: &destination,
                    project,
                    scope,
                },
            )
            .map_err(EntryError::Setup)?;
            // Confirmation contains public pins only. Capability issuance is
            // still the actual game admin's private host pairing transition.
            output(
                &json!({"kind":"host_setup_registered","projectId":setup.project_id,
                "executableSha256":setup.executable_sha256,"hostArtifactDigest":setup.host_artifact_digest}),
                Instant::now() + OUTPUT,
            )?;
        }
    }
    Ok(true)
}

fn finish(coordinator: Coordinator, primary: Result<(), EntryError>) -> Result<(), EntryError> {
    match coordinator.shutdown() {
        Ok(()) => primary,
        Err(cleanup) => Err(EntryError::Shutdown {
            primary: primary.err().map(Box::new),
            cleanup,
        }),
    }
}

fn parse(args: &[String]) -> Result<Option<Command>, EntryError> {
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(None);
    };
    if command == daemon_launch::DAEMON_CHILD_COMMAND {
        return Ok(Some(Command::Owned(args[1..].to_vec())));
    }
    if command == "host-bridge" {
        return if args.len() == 2 && args[1] == "--stdio-bootstrap" {
            Ok(Some(Command::HostBridge))
        } else {
            Err(EntryError::Arguments)
        };
    }
    if !matches!(command, "init" | "daemon" | "start" | "host-setup") {
        return Ok(None);
    }
    let mut options = std::collections::BTreeMap::new();
    for pair in args[1..].chunks(2) {
        if pair.len() != 2 || options.insert(pair[0].as_str(), pair[1].as_str()).is_some() {
            return Err(EntryError::Arguments);
        }
    }
    let root = PathBuf::from(options.remove("--data-root").ok_or(EntryError::Arguments)?);
    if !root.is_absolute() {
        return Err(EntryError::Arguments);
    }
    let parsed = match command {
        "init" => Command::Init {
            root,
            name: options
                .remove("--name")
                .filter(|v| !v.is_empty() && v.len() <= 1024 && !v.chars().any(char::is_control))
                .ok_or(EntryError::Arguments)?
                .to_owned(),
            target: TargetProfileId::new(
                options
                    .remove("--target-profile")
                    .ok_or(EntryError::Arguments)?,
            )
            .map_err(|_| EntryError::Arguments)?,
        },
        "daemon" | "start" => {
            let project = ProjectId::new(options.remove("--project").ok_or(EntryError::Arguments)?)
                .map_err(|_| EntryError::Arguments)?;
            if command == "start" {
                Command::Start { root, project }
            } else {
                let seconds = match options.remove("--lifetime-seconds") {
                    None => daemon_launch::DEFAULT_DAEMON_LIFETIME.as_secs(),
                    Some(raw) if raw.bytes().all(|b| b.is_ascii_digit()) => {
                        raw.parse::<u64>().map_err(|_| EntryError::Arguments)?
                    }
                    _ => return Err(EntryError::Arguments),
                };
                if !(1..=1800).contains(&seconds) {
                    return Err(EntryError::Arguments);
                }
                Command::Foreground {
                    root,
                    project,
                    lifetime: Duration::from_secs(seconds),
                }
            }
        }
        "host-setup" => {
            let project = ProjectId::new(options.remove("--project").ok_or(EntryError::Arguments)?)
                .map_err(|_| EntryError::Arguments)?;
            let jar = PathBuf::from(options.remove("--host-jar").ok_or(EntryError::Arguments)?);
            let destination =
                PathBuf::from(options.remove("--output").ok_or(EntryError::Arguments)?);
            let scope = parse_json_with_limits(
                options
                    .remove("--scope-json")
                    .ok_or(EntryError::Arguments)?
                    .as_bytes(),
                JsonLimits {
                    max_bytes: 16 * 1024,
                    max_depth: 32,
                    max_nodes: 4096,
                },
            )
            .map_err(|_| EntryError::Arguments)?;
            if !jar.is_absolute() || !destination.is_absolute() {
                return Err(EntryError::Arguments);
            }
            Command::Setup {
                root,
                project,
                jar,
                destination,
                scope,
            }
        }
        _ => return Err(EntryError::Arguments),
    };
    if !options.is_empty() {
        return Err(EntryError::Arguments);
    }
    Ok(Some(parsed))
}

fn check(deadline: Instant) -> Result<(), EntryError> {
    if Instant::now() >= deadline {
        Err(EntryError::Deadline)
    } else {
        Ok(())
    }
}
fn output(value: &Value, caller_deadline: Instant) -> Result<(), EntryError> {
    let mut bytes = encode_json(value).map_err(|_| EntryError::OutputInvalid)?;
    if bytes.len() > MAX_OUTPUT {
        return Err(EntryError::OutputInvalid);
    }
    bytes.push(b'\n');
    let started = Instant::now();
    let deadline = caller_deadline.min(started + OUTPUT + DRAIN);
    let output_deadline = deadline.checked_sub(DRAIN).ok_or(EntryError::Deadline)?;
    check(output_deadline)?;
    let remaining = output_deadline.saturating_duration_since(started);
    // Raw mode performs only requested transactions. An output-only helper
    // never speculatively consumes the caller's inherited stdin or credentials.
    let native = NativeStdioPort::spawn_current_raw_with_deadline(
        StdioLimits {
            session: deadline.saturating_duration_since(started),
            startup: Duration::from_secs(2).min(remaining),
            max_frames: 2,
            max_input_bytes: 1,
            max_output_bytes: MAX_OUTPUT as u64 + 1,
        },
        deadline,
    )
    .map_err(EntryError::Output)?;
    let cancel = AtomicBool::new(false);
    let result = (|| loop {
        check(output_deadline)?;
        match native
            .poll_write_raw(&bytes, output_deadline, &cancel)
            .map_err(EntryError::Output)?
        {
            Poll::Ready(()) => return Ok(()),
            Poll::Pending => std::thread::sleep(POLL),
        }
    })();
    loop {
        if Instant::now() >= deadline {
            return Err(EntryError::DrainUncertain);
        }
        match native
            .poll_cancel_and_drain(deadline)
            .map_err(|_| EntryError::DrainUncertain)?
        {
            Poll::Ready(report) if report.terminated && report.exit_code.is_some() => {
                return result;
            }
            Poll::Ready(_) => return Err(EntryError::DrainUncertain),
            Poll::Pending => std::thread::sleep(POLL),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }
    fn root() -> &'static str {
        if cfg!(windows) {
            "C:\\mmmm-test-root"
        } else {
            "/mmmm-test-root"
        }
    }
    #[test]
    fn locator_selection_never_accepts_authority_fields() {
        for fields in [
            vec!["--principal", "owner"],
            vec!["--grant", "apply"],
            vec!["--token", "secret"],
            vec!["--policy-revision", "0"],
        ] {
            let mut input = args(&["start", "--data-root", root(), "--project", "project-test"]);
            input.extend(args(&fields));
            assert!(matches!(parse(&input), Err(EntryError::Arguments)));
        }
        assert!(matches!(
            parse(&args(&[
                "start",
                "--data-root",
                root(),
                "--project",
                "project-test"
            ])),
            Ok(Some(Command::Start { .. }))
        ));
    }
    #[test]
    fn native_protocol_mode_and_finite_lifetime_are_closed() {
        assert!(matches!(
            parse(&args(&["host-bridge", "--stdio-bootstrap"])),
            Ok(Some(Command::HostBridge))
        ));
        assert!(
            parse(&args(&[
                "host-bridge",
                "--stdio-bootstrap",
                "--data-root",
                root()
            ]))
            .is_err()
        );
        for seconds in ["0", "1801", "+1", "infinite"] {
            assert!(
                parse(&args(&[
                    "daemon",
                    "--data-root",
                    root(),
                    "--project",
                    "project-test",
                    "--lifetime-seconds",
                    seconds
                ]))
                .is_err()
            );
        }
        assert!(
            parse(&args(&[
                "init",
                "--data-root",
                root(),
                "--data-root",
                root(),
                "--name",
                "First",
                "--target-profile",
                "profile-test"
            ]))
            .is_err()
        );
    }
    #[test]
    fn committed_locator_survives_failed_delivery_and_expired_startup_is_rejected() {
        let error = EntryError::Initialized {
            project: ProjectId::new("committed-project").unwrap(),
            revision: mmmm_contracts::Sha256Digest::new("0".repeat(64)).unwrap(),
            delivery: Box::new(EntryError::DrainUncertain),
        };
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("committed-project"));
        assert!(diagnostic.contains("initialized and retained"));
        assert!(diagnostic.contains("termination is unconfirmed"));
        assert!(matches!(check(Instant::now()), Err(EntryError::Deadline)));
    }
}

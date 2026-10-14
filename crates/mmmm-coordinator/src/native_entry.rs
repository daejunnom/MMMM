//! Concrete native entrypoints reuse the one protected daemon composition.
//! Arguments select locators, metadata and explicit authored contract bytes; capabilities remain
//! in the authenticated peer or anonymous host exchange, never in argv.

use crate::{
    CoordinatorClient,
    catalog_source_use::{LocalCatalogSourceUseAction, manage_catalog_source_use},
    daemon::{DaemonError, PreparedDaemon},
    daemon_launch::{self, DaemonLaunchError, NativeDaemonLocator},
    host_read_policy::selected_host_read_policy,
    host_relay::{self, RelayError},
    lifecycle::{Coordinator, CoordinatorError},
    local_setup::{
        LocalHostSetup, LocalReadPolicySetupError, LocalSetupError, register_local_host_setup,
        register_local_host_setup_with_read_policy,
    },
    native_import_files::{ImportReadBudget, InputRole, read_selected, validate_selection},
    native_source_ingress::{
        NativeRawSourceResource, NativeSourceDocument, NativeSourceInput, NativeSourceKind,
    },
    production_factory::ProductionFactory,
    service::{RequestBudget, ServiceError},
    stdio_io::{NativeStdioPort, StdioError, StdioLimits},
};
use mmmm_contracts::{
    ContextId, JsonLimits, ProjectId, ResourceId, ResourceLocation, Sha256Digest, TargetProfileId,
    encode_json, parse_json_with_limits,
};
use mmmm_runtime::storage::{
    StoreConfig,
    catalog_source_use::{
        CatalogSourceUseRole, CatalogSourceUseSelection, CatalogSourceUseSnapshot,
    },
    host_setup::{HostReadPolicy, HostReadPolicyRecord},
    native_owned_sources::NativeOwnedSourceCommitReceipt,
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
    task::Poll,
    time::{Duration, Instant},
};

pub use crate::native_import_files::ImportFileError;

const OUTPUT: Duration = Duration::from_secs(5);
const DRAIN: Duration = Duration::from_secs(3);
const POLL: Duration = Duration::from_millis(5);
const MAX_OUTPUT: usize = 64 * 1024;
const MAX_SOURCE_OUTPUT: usize = 256 * 1024;
const SOURCE_IMPORT: Duration = Duration::from_secs(30);
const MAX_SOURCE_DOCUMENT: usize = 8 * 1024 * 1024;
const MAX_SOURCE_TOTAL: usize = 32 * 1024 * 1024;
const MAX_SOURCE_DOCUMENTS: usize = 256;

#[derive(Debug)]
pub enum EntryError {
    Arguments,
    HostReadPolicyArguments,
    SourceArguments,
    CatalogSourceArguments,
    CatalogSourceRequest(mmmm_application::AppError),
    SourceRequest(ServiceError),
    SourceFile(ImportFileError),
    Deadline,
    Daemon(DaemonError),
    Launch(DaemonLaunchError),
    Setup(LocalSetupError),
    ReadPolicySetup(LocalReadPolicySetupError),
    Relay(RelayError),
    Client(crate::client::ClientError),
    Peer(crate::peer::PeerError),
    Output(StdioError),
    OutputInvalid,
    DrainUncertain,
    OutputDrain {
        primary: Box<EntryError>,
        cleanup: Box<EntryError>,
    },
    Initialized {
        project: ProjectId,
        revision: mmmm_contracts::Sha256Digest,
        delivery: Box<EntryError>,
    },
    /// Actual committed facts survive output, cancellation and drain failures.
    /// The receipt is retained metadata, never a reusable authoring authority.
    SourcesCommitted {
        receipt: Box<NativeOwnedSourceCommitReceipt>,
        delivery: Box<EntryError>,
    },
    HostReadPolicyCommitted {
        record: Box<HostReadPolicyRecord>,
        delivery: Box<EntryError>,
    },
    CatalogSourceUsesCommitted {
        snapshot: Box<CatalogSourceUseSnapshot>,
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
            Self::HostReadPolicyArguments => f.write_str("Host setup read policy requires unique --shape-mode survival|creative|adventure|spectator selections and optional --native-observation user_local_only; absent selections grant no corresponding source access"),
            Self::SourceArguments => f.write_str("Native source import requires at least one document or raw resource pair and at most 256 combined document/resource inputs: --document <kind>:<JSON>, --document-file <kind>:<absolute JSON path>, and adjacent --resource-descriptor-file/--resource-bytes-file paths; kinds are prefab|instance|clip and OS argv limits may be smaller"),
            Self::CatalogSourceArguments => f.write_str("Catalog source use requires --mode inspect or replace; replace needs --expected-state-digest and a complete set selected by --game-artifact <resourceId>/repeated --mod <canonicalId>,<nativeId>,<resourceId>, or explicit --withdraw true with no selections; <=256 selections, <=64 KiB selector metadata, user_local_only only"),
            Self::CatalogSourceRequest(error) => write!(f, "{}: Cold native catalog source use could not continue", error.code),
            Self::SourceRequest(error) => write!(f, "{}: Native source request could not continue", error.code),
            Self::SourceFile(error) => error.fmt(f),
            Self::Deadline => f.write_str("Native command startup or delivery deadline reached"),
            Self::Daemon(error) => error.fmt(f),
            Self::Launch(error) => error.fmt(f),
            Self::Setup(error) => error.fmt(f),
            Self::ReadPolicySetup(error) => error.fmt(f),
            Self::Relay(error) => error.fmt(f),
            Self::Client(_) => f.write_str("Selected Project could not be inspected through the authenticated Coordinator"),
            Self::Peer(_) => f.write_str("The exact selected Coordinator generation could not be authenticated"),
            Self::Output(_) | Self::OutputInvalid => f.write_str("Native command result delivery failed; confirmed durable data is retained"),
            Self::DrainUncertain => f.write_str("Native command output owner termination is unconfirmed"),
            Self::OutputDrain { primary, cleanup } => write!(f,
                "Native result output failed: {primary}; output drain failed: {cleanup}"),
            Self::Initialized { project, revision, delivery } => write!(f,
                "Project {project} at revision {revision} was initialized and retained; result delivery failed: {delivery}"),
            Self::SourcesCommitted { receipt, delivery } => write!(f,
                "Project {} advanced from {} to {} with committed sources retained; result delivery failed: {delivery}",
                receipt.project_id, receipt.base_revision, receipt.project_revision),
            Self::HostReadPolicyCommitted { record, delivery } => write!(f,
                "Host read policy {} for Project {} was committed and retained; result delivery failed: {delivery}",
                record.policy_digest(), record.project_id()),
            Self::CatalogSourceUsesCommitted { snapshot, delivery } => write!(f,
                "Catalog source use {} at generation {} for Project {} was committed and retained; result delivery failed: {delivery}",
                snapshot.state_digest(), snapshot.generation(), snapshot.project_id()),
            Self::Shutdown { .. } => f.write_str("Coordinator shutdown is unresolved; durable data and discovery requiring cleanup are retained"),
        }
    }
}
impl std::error::Error for EntryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Daemon(e) => Some(e),
            Self::SourceRequest(e) => Some(e),
            Self::CatalogSourceRequest(e) => Some(e),
            Self::SourceFile(e) => Some(e),
            Self::Launch(e) => Some(e),
            Self::Setup(e) => Some(e),
            Self::ReadPolicySetup(e) => Some(e),
            Self::Relay(e) => Some(e),
            Self::Client(e) => Some(e),
            Self::Peer(e) => Some(e),
            Self::Output(e) => Some(e),
            Self::OutputDrain { primary, .. } => Some(primary.as_ref()),
            Self::Initialized { delivery, .. } => Some(delivery.as_ref()),
            Self::SourcesCommitted { delivery, .. } => Some(delivery.as_ref()),
            Self::HostReadPolicyCommitted { delivery, .. } => Some(delivery.as_ref()),
            Self::CatalogSourceUsesCommitted { delivery, .. } => Some(delivery.as_ref()),
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
        read_policy: Option<HostReadPolicy>,
    },
    SourceImport {
        root: PathBuf,
        project: ProjectId,
        expected_revision: Sha256Digest,
        documents: Vec<CommandDocument>,
        document_files: Vec<CommandDocumentFile>,
        raw_resources: Vec<CommandRawFiles>,
    },
    CatalogSourceUse {
        root: PathBuf,
        project: ProjectId,
        expected_revision: Sha256Digest,
        action: LocalCatalogSourceUseAction,
    },
    HostBridge,
    Owned(Vec<String>),
}

struct CommandDocument {
    kind: NativeSourceKind,
    // Prefix removal is the only transformation. Strict parse/domain checks
    // and projected/raw pin separation remain owned by the existing ingress.
    source: String,
}

struct CommandDocumentFile {
    kind: NativeSourceKind,
    path: PathBuf,
}
struct CommandRawFiles {
    descriptor: PathBuf,
    bytes: PathBuf,
}
struct LoadedDocument {
    kind: NativeSourceKind,
    bytes: Vec<u8>,
}
struct LoadedRawResource {
    metadata: Vec<u8>,
    bytes: Vec<u8>,
}
struct LoadedNativeInputs {
    documents: Vec<LoadedDocument>,
    resources: Vec<LoadedRawResource>,
}

/// Returns false only for a command owned by the ordinary CLI/MCP facade.
/// The caller dispatches the existing isolated-stdio worker before this API.
pub fn dispatch(args: &[String]) -> Result<bool, EntryError> {
    let started = Instant::now();
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
            // Return the installed workspace locator only after listener startup
            // succeeds. A caller cannot supply or reuse a different context ID.
            let workspace_context = prepared
                .handles()
                .workspace
                .as_ref()
                .and_then(|workspace| workspace.context.get("contextId"))
                .and_then(Value::as_str)
                .and_then(|id| ContextId::new(id).ok())
                .ok_or_else(|| {
                    EntryError::Daemon(DaemonError::Composition(ServiceError::new(
                        "WORKSPACE_UNAVAILABLE",
                        "The installed native workspace has no valid context locator",
                    )))
                })?;
            let mut coordinator = prepared.start().map_err(EntryError::Daemon)?;
            let primary = match output(
                &json!({"kind":"coordinator_started","projectId":project,
                "address":coordinator.endpoint().address,"coordinatorEpoch":coordinator.endpoint().coordinator_epoch,
                "workspaceContextId":workspace_context}),
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
            read_policy,
        } => {
            let executable = std::env::current_exe().map_err(|_| EntryError::Arguments)?;
            let request = LocalHostSetup {
                executable: &executable,
                installed_host_jar: &jar,
                destination: &destination,
                project,
                scope,
            };
            if let Some(policy) = read_policy {
                let deadline = started + Duration::from_secs(15);
                let (setup, record) = register_local_host_setup_with_read_policy(
                    StoreConfig::new(root),
                    request,
                    &policy,
                    deadline,
                )
                .map_err(EntryError::ReadPolicySetup)?;
                let confirmation = json!({"kind":"host_setup_registered","projectId":setup.project_id,
                    "executableSha256":setup.executable_sha256,"hostArtifactDigest":setup.host_artifact_digest,
                    "readPolicyDigest":record.policy_digest()});
                deliver_host_read_policy(record, || output(&confirmation, deadline))?;
            } else {
                let setup = register_local_host_setup(StoreConfig::new(root), request)
                    .map_err(EntryError::Setup)?;
                output(
                    &json!({"kind":"host_setup_registered","projectId":setup.project_id,
                    "executableSha256":setup.executable_sha256,"hostArtifactDigest":setup.host_artifact_digest}),
                    Instant::now() + OUTPUT,
                )?;
            }
        }
        Command::CatalogSourceUse {
            root,
            project,
            expected_revision,
            action,
        } => {
            let budget =
                RequestBudget::until(started + SOURCE_IMPORT, Arc::new(AtomicBool::new(false)))
                    .map_err(EntryError::SourceRequest)?;
            let replaces = matches!(&action, LocalCatalogSourceUseAction::Replace { .. });
            let snapshot = manage_catalog_source_use(
                StoreConfig::new(root),
                &project,
                &expected_revision,
                action,
                &budget,
            )
            .map_err(EntryError::CatalogSourceRequest)?;
            if replaces {
                deliver_catalog_source_uses(
                    snapshot,
                    &expected_revision,
                    &budget,
                    |value, deadline| {
                        output_with_limit(value, deadline, MAX_SOURCE_OUTPUT, budget.cancellation())
                    },
                )?;
            } else {
                let value = catalog_source_use_value(&snapshot, &expected_revision, false);
                budget.check().map_err(EntryError::SourceRequest)?;
                output_with_limit(
                    &value,
                    budget.deadline(),
                    MAX_SOURCE_OUTPUT,
                    budget.cancellation(),
                )?;
                budget.check().map_err(EntryError::SourceRequest)?;
            }
        }
        Command::SourceImport {
            root,
            project,
            expected_revision,
            documents,
            document_files,
            raw_resources,
        } => {
            let deadline = started + SOURCE_IMPORT;
            let budget = RequestBudget::until(deadline, Arc::new(AtomicBool::new(false)))
                .map_err(EntryError::SourceRequest)?;
            let digest = daemon_launch::current_executable_digest(
                deadline.min(Instant::now() + Duration::from_secs(10)),
            )
            .map_err(EntryError::Launch)?;
            budget.check().map_err(EntryError::SourceRequest)?;
            let mut factory = ProductionFactory::offline_owned(digest);
            let prepared = PreparedDaemon::open_for_native_source_import(
                StoreConfig::new(root),
                project.clone(),
                &mut factory,
                &budget,
            )
            .map_err(EntryError::Daemon)?;
            // The original Store is already locked and its actual native owner
            // and Project/head are verified before any selected source opens.
            let loaded = load_native_inputs(
                &prepared,
                &project,
                &expected_revision,
                documents,
                &document_files,
                &raw_resources,
                &budget,
            )?;
            let raw_documents = loaded
                .documents
                .iter()
                .map(|document| NativeSourceDocument {
                    kind: document.kind,
                    bytes: &document.bytes,
                })
                .collect::<Vec<_>>();
            let raw_resources = loaded
                .resources
                .iter()
                .map(|resource| NativeRawSourceResource {
                    metadata: &resource.metadata,
                    bytes: &resource.bytes,
                })
                .collect::<Vec<_>>();
            let receipt = prepared
                .import_native_sources(&NativeSourceInput {
                    project: &project,
                    expected_revision: &expected_revision,
                    documents: &raw_documents,
                    retained_resources: &[],
                    raw_resources: &raw_resources,
                })
                .map_err(EntryError::Daemon)?;
            deliver_sources(receipt, &budget, |value, deadline| {
                output_with_limit(value, deadline, MAX_SOURCE_OUTPUT, budget.cancellation())
            })?;
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
    if !matches!(
        command,
        "init" | "daemon" | "start" | "host-setup" | "source-import" | "catalog-source-use"
    ) {
        return Ok(None);
    }
    let mut options = std::collections::BTreeMap::new();
    let mut documents = Vec::new();
    let mut document_files = Vec::new();
    let mut raw_resources = Vec::new();
    let mut pending_descriptor = None;
    let mut source_total = 0usize;
    let mut shape_modes = Vec::new();
    let mut catalog_mods = Vec::new();
    let mut catalog_selector_bytes = 0usize;
    for pair in args[1..].chunks(2) {
        if pair.len() != 2 {
            return Err(EntryError::Arguments);
        }
        if command == "host-setup" && pair[0] == "--shape-mode" {
            if shape_modes.len() >= 4 || pair[1].len() > 16 || shape_modes.contains(&pair[1]) {
                return Err(EntryError::HostReadPolicyArguments);
            }
            shape_modes.push(pair[1].clone());
            continue;
        }
        if command == "catalog-source-use" && pair[0] == "--mod" {
            catalog_selector_bytes = catalog_selector_bytes
                .checked_add(pair[1].len())
                .filter(|size| *size <= 65_536)
                .ok_or(EntryError::CatalogSourceArguments)?;
            if catalog_mods.len() >= 256 {
                return Err(EntryError::CatalogSourceArguments);
            }
            catalog_mods.push(catalog_mod_selector(&pair[1])?);
            continue;
        }
        if command == "source-import" {
            if let Some(descriptor) = pending_descriptor.take() {
                if pair[0] != "--resource-bytes-file" {
                    return Err(EntryError::SourceArguments);
                }
                let bytes = selected_path(&pair[1], InputRole::ResourceBytes)?;
                raw_resources.push(CommandRawFiles { descriptor, bytes });
                continue;
            }
            let count =
                source_input_count(documents.len(), document_files.len(), raw_resources.len())?;
            match pair[0].as_str() {
                "--document" => {
                    let (kind, source) = document_selector(&pair[1])?;
                    source_total = checked_source_total(count, source_total, source.len())?;
                    documents.push(CommandDocument {
                        kind,
                        source: source.to_owned(),
                    });
                    continue;
                }
                "--document-file" => {
                    checked_source_count(count)?;
                    let (kind, name) = document_selector(&pair[1])?;
                    let path = selected_path(name, InputRole::Document)?;
                    document_files.push(CommandDocumentFile { kind, path });
                    continue;
                }
                "--resource-descriptor-file" => {
                    checked_source_count(count)?;
                    pending_descriptor =
                        Some(selected_path(&pair[1], InputRole::ResourceDescriptor)?);
                    continue;
                }
                "--resource-bytes-file" => return Err(EntryError::SourceArguments),
                _ => (),
            }
        }
        if options.insert(pair[0].as_str(), pair[1].as_str()).is_some() {
            return Err(EntryError::Arguments);
        }
    }
    if pending_descriptor.is_some() {
        return Err(EntryError::SourceArguments);
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
            let observation = options.remove("--native-observation");
            if observation.is_some_and(|value| value != "user_local_only") {
                return Err(EntryError::HostReadPolicyArguments);
            }
            let read_policy = if shape_modes.is_empty() && observation.is_none() {
                None
            } else {
                Some(
                    selected_host_read_policy(&shape_modes, observation.is_some())
                        .map_err(|_| EntryError::HostReadPolicyArguments)?,
                )
            };
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
                read_policy,
            }
        }
        "source-import" => {
            if documents.is_empty() && document_files.is_empty() && raw_resources.is_empty() {
                return Err(EntryError::SourceArguments);
            }
            Command::SourceImport {
                root,
                project: ProjectId::new(options.remove("--project").ok_or(EntryError::Arguments)?)
                    .map_err(|_| EntryError::Arguments)?,
                expected_revision: Sha256Digest::new(
                    options
                        .remove("--expected-revision")
                        .ok_or(EntryError::Arguments)?,
                )
                .map_err(|_| EntryError::Arguments)?,
                documents,
                document_files,
                raw_resources,
            }
        }
        "catalog-source-use" => {
            let project = ProjectId::new(options.remove("--project").ok_or(EntryError::Arguments)?)
                .map_err(|_| EntryError::Arguments)?;
            let expected_revision = Sha256Digest::new(
                options
                    .remove("--expected-revision")
                    .ok_or(EntryError::Arguments)?,
            )
            .map_err(|_| EntryError::Arguments)?;
            let mode = options
                .remove("--mode")
                .ok_or(EntryError::CatalogSourceArguments)?;
            let expected_state = options.remove("--expected-state-digest");
            let withdraw = options.remove("--withdraw");
            let game = options.remove("--game-artifact");
            let action = match mode {
                "inspect"
                    if expected_state.is_none()
                        && withdraw.is_none()
                        && game.is_none()
                        && catalog_mods.is_empty() =>
                {
                    LocalCatalogSourceUseAction::Inspect
                }
                "replace" => {
                    let expected_state_digest = Sha256Digest::new(
                        expected_state.ok_or(EntryError::CatalogSourceArguments)?,
                    )
                    .map_err(|_| EntryError::CatalogSourceArguments)?;
                    if withdraw.is_some() {
                        if withdraw != Some("true") || game.is_some() || !catalog_mods.is_empty() {
                            return Err(EntryError::CatalogSourceArguments);
                        }
                    } else {
                        if let Some(game) = game {
                            catalog_mods.push(CatalogSourceUseSelection {
                                resource_id: ResourceId::new(game)
                                    .map_err(|_| EntryError::CatalogSourceArguments)?,
                                role: CatalogSourceUseRole::GameArtifact,
                            });
                        }
                        if catalog_mods.is_empty() || catalog_mods.len() > 256 {
                            return Err(EntryError::CatalogSourceArguments);
                        }
                    }
                    LocalCatalogSourceUseAction::Replace {
                        expected_state_digest,
                        selections: catalog_mods,
                    }
                }
                _ => return Err(EntryError::CatalogSourceArguments),
            };
            Command::CatalogSourceUse {
                root,
                project,
                expected_revision,
                action,
            }
        }
        _ => return Err(EntryError::Arguments),
    };
    if !options.is_empty() {
        return Err(EntryError::Arguments);
    }
    Ok(Some(parsed))
}

fn catalog_mod_selector(value: &str) -> Result<CatalogSourceUseSelection, EntryError> {
    if value.len() > 1024 {
        return Err(EntryError::CatalogSourceArguments);
    }
    let mut fields = value.split(',');
    let canonical = fields.next().ok_or(EntryError::CatalogSourceArguments)?;
    let native = fields.next().ok_or(EntryError::CatalogSourceArguments)?;
    let resource = fields.next().ok_or(EntryError::CatalogSourceArguments)?;
    if fields.next().is_some()
        || native.is_empty()
        || native.len() > 128
        || !native
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
    {
        return Err(EntryError::CatalogSourceArguments);
    }
    Ok(CatalogSourceUseSelection {
        resource_id: ResourceId::new(resource).map_err(|_| EntryError::CatalogSourceArguments)?,
        role: CatalogSourceUseRole::Mod {
            canonical_id: ResourceLocation::new(canonical)
                .map_err(|_| EntryError::CatalogSourceArguments)?,
            native_id: native.to_owned(),
        },
    })
}

fn catalog_source_use_value(
    snapshot: &CatalogSourceUseSnapshot,
    revision: &Sha256Digest,
    replaced: bool,
) -> Value {
    let selected = snapshot
        .selections()
        .iter()
        .map(|pin| {
            json!({
                "resourceId":pin.selection().resource_id,"role":pin.selection().role,
                "resource":pin.resource(),"blob":pin.blob(),
            })
        })
        .collect::<Vec<_>>();
    json!({"kind":if replaced {"catalog_source_uses_replaced"} else {"catalog_source_use_state"},
        "projectId":snapshot.project_id(),"currentProjectRevision":revision,
        "approvedProjectRevision":snapshot.approved_project_revision(),
        "generation":snapshot.generation(),"stateDigest":snapshot.state_digest(),
        "rights":snapshot.rights(),"selectionCount":selected.len(),"selections":selected})
}

fn deliver_catalog_source_uses(
    snapshot: CatalogSourceUseSnapshot,
    revision: &Sha256Digest,
    budget: &RequestBudget,
    deliver: impl FnOnce(&Value, Instant) -> Result<(), EntryError>,
) -> Result<(), EntryError> {
    let result = budget
        .check()
        .map_err(EntryError::SourceRequest)
        .and_then(|()| {
            deliver(
                &catalog_source_use_value(&snapshot, revision, true),
                budget.deadline(),
            )
        })
        .and_then(|()| budget.check().map_err(EntryError::SourceRequest));
    result.map_err(|delivery| EntryError::CatalogSourceUsesCommitted {
        snapshot: Box::new(snapshot),
        delivery: Box::new(delivery),
    })
}

fn deliver_host_read_policy(
    record: HostReadPolicyRecord,
    deliver: impl FnOnce() -> Result<(), EntryError>,
) -> Result<(), EntryError> {
    deliver().map_err(|delivery| EntryError::HostReadPolicyCommitted {
        record: Box::new(record),
        delivery: Box::new(delivery),
    })
}

fn document_selector(value: &str) -> Result<(NativeSourceKind, &str), EntryError> {
    let (kind, source) = value.split_once(':').ok_or(EntryError::SourceArguments)?;
    let kind = match kind {
        "prefab" => NativeSourceKind::Prefab,
        "instance" => NativeSourceKind::Instance,
        "clip" => NativeSourceKind::Clip,
        _ => return Err(EntryError::SourceArguments),
    };
    Ok((kind, source))
}

fn selected_path(value: &str, role: InputRole) -> Result<PathBuf, EntryError> {
    let path = PathBuf::from(value);
    validate_selection(&path, role).map_err(EntryError::SourceFile)?;
    Ok(path)
}

fn checked_source_count(count: usize) -> Result<(), EntryError> {
    if count >= MAX_SOURCE_DOCUMENTS {
        return Err(EntryError::SourceArguments);
    }
    Ok(())
}

fn source_input_count(inline: usize, files: usize, resources: usize) -> Result<usize, EntryError> {
    inline
        .checked_add(files)
        .and_then(|count| count.checked_add(resources))
        .ok_or(EntryError::SourceArguments)
}

fn checked_source_total(count: usize, total: usize, length: usize) -> Result<usize, EntryError> {
    checked_source_count(count)?;
    if length == 0 || length > MAX_SOURCE_DOCUMENT {
        return Err(EntryError::SourceArguments);
    }
    let next = total
        .checked_add(length)
        .ok_or(EntryError::SourceArguments)?;
    if next > MAX_SOURCE_TOTAL {
        return Err(EntryError::SourceArguments);
    }
    Ok(next)
}

fn load_native_inputs(
    prepared: &PreparedDaemon,
    project: &ProjectId,
    expected_revision: &Sha256Digest,
    documents: Vec<CommandDocument>,
    document_files: &[CommandDocumentFile],
    raw_resources: &[CommandRawFiles],
    budget: &RequestBudget,
) -> Result<LoadedNativeInputs, EntryError> {
    budget.check().map_err(EntryError::SourceRequest)?;
    let handles = prepared.handles();
    let workspace = handles.workspace.as_ref().ok_or_else(|| {
        EntryError::Daemon(DaemonError::Composition(ServiceError::new(
            "WORKSPACE_UNAVAILABLE",
            "Native source file import requires its verified workspace",
        )))
    })?;
    if handles.configured_project.as_ref() != Some(project)
        || &workspace.project_revision != expected_revision
    {
        return Err(EntryError::Daemon(DaemonError::Composition(
            ServiceError::new(
                "PLAN_STALE",
                "Native source file import Project or expected revision differs from its workspace",
            ),
        )));
    }
    let initial_bytes = documents.iter().try_fold(0usize, |total, document| {
        total
            .checked_add(document.source.len())
            .ok_or(EntryError::SourceArguments)
    })?;
    let mut totals = ImportReadBudget::new(initial_bytes).map_err(EntryError::SourceFile)?;
    let mut loaded = LoadedNativeInputs {
        documents: documents
            .into_iter()
            .map(|document| LoadedDocument {
                kind: document.kind,
                bytes: document.source.into_bytes(),
            })
            .collect(),
        resources: Vec::new(),
    };
    for document in document_files {
        loaded.documents.push(LoadedDocument {
            kind: document.kind,
            bytes: read_selected(
                &document.path,
                InputRole::Document,
                &workspace.witness,
                budget,
                &mut totals,
            )
            .map_err(EntryError::SourceFile)?,
        });
    }
    for resource in raw_resources {
        let metadata = read_selected(
            &resource.descriptor,
            InputRole::ResourceDescriptor,
            &workspace.witness,
            budget,
            &mut totals,
        )
        .map_err(EntryError::SourceFile)?;
        let bytes = read_selected(
            &resource.bytes,
            InputRole::ResourceBytes,
            &workspace.witness,
            budget,
            &mut totals,
        )
        .map_err(EntryError::SourceFile)?;
        loaded.resources.push(LoadedRawResource { metadata, bytes });
    }
    budget.check().map_err(EntryError::SourceRequest)?;
    Ok(loaded)
}

fn source_receipt_value(receipt: &NativeOwnedSourceCommitReceipt) -> Value {
    let documents = receipt
        .documents
        .iter()
        .map(|(pin, blob)| json!({"pin":pin,"blob":blob}))
        .collect::<Vec<_>>();
    let resources = receipt
        .resources
        .iter()
        .map(|(id, blob)| json!({"resourceId":id,"blob":blob}))
        .collect::<Vec<_>>();
    json!({
        "kind":"native_sources_committed","projectId":receipt.project_id,
        "baseRevision":receipt.base_revision,"revision":receipt.project_revision,
        "projectBlob":receipt.project_blob,"documents":documents,"resources":resources
    })
}

fn deliver_sources(
    receipt: NativeOwnedSourceCommitReceipt,
    budget: &RequestBudget,
    deliver: impl FnOnce(&Value, Instant) -> Result<(), EntryError>,
) -> Result<(), EntryError> {
    let delivery = budget
        .check()
        .map_err(EntryError::SourceRequest)
        .and_then(|()| deliver(&source_receipt_value(&receipt), budget.deadline()))
        .and_then(|()| budget.check().map_err(EntryError::SourceRequest));
    delivery.map_err(|delivery| EntryError::SourcesCommitted {
        receipt: Box::new(receipt),
        delivery: Box::new(delivery),
    })
}

fn check(deadline: Instant) -> Result<(), EntryError> {
    if Instant::now() >= deadline {
        Err(EntryError::Deadline)
    } else {
        Ok(())
    }
}
fn output(value: &Value, caller_deadline: Instant) -> Result<(), EntryError> {
    output_with_limit(value, caller_deadline, MAX_OUTPUT, &AtomicBool::new(false))
}
fn output_with_limit(
    value: &Value,
    caller_deadline: Instant,
    maximum: usize,
    cancel: &AtomicBool,
) -> Result<(), EntryError> {
    let mut bytes = encode_json(value).map_err(|_| EntryError::OutputInvalid)?;
    if bytes.len() > maximum {
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
            max_output_bytes: maximum as u64 + 1,
        },
        deadline,
    )
    .map_err(EntryError::Output)?;
    let result = (|| loop {
        check(output_deadline)?;
        match native
            .poll_write_raw(&bytes, output_deadline, cancel)
            .map_err(EntryError::Output)?
        {
            Poll::Ready(()) => return Ok(()),
            Poll::Pending => std::thread::sleep(POLL),
        }
    })();
    loop {
        if Instant::now() >= deadline {
            return finish_output(result, Err(EntryError::DrainUncertain));
        }
        match native.poll_cancel_and_drain(deadline) {
            Ok(Poll::Ready(report)) if report.terminated && report.exit_code.is_some() => {
                return finish_output(result, Ok(()));
            }
            Ok(Poll::Ready(_)) => return finish_output(result, Err(EntryError::DrainUncertain)),
            Err(error) => return finish_output(result, Err(EntryError::Output(error))),
            Ok(Poll::Pending) => std::thread::sleep(POLL),
        }
    }
}

fn finish_output(
    primary: Result<(), EntryError>,
    cleanup: Result<(), EntryError>,
) -> Result<(), EntryError> {
    match (primary, cleanup) {
        (result, Ok(())) => result,
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(EntryError::OutputDrain {
            primary: Box::new(primary),
            cleanup: Box::new(cleanup),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mmmm_contracts::{parse_json, projected_digest, raw_digest};
    use mmmm_runtime::storage::{DurableStore, StorageError, bootstrap::ProjectBootstrapReceipt};
    use std::{
        fs,
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
    };
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
    fn host_setup_policy_flags_are_explicit_closed_and_leave_old_commands_unchanged() {
        let base = || {
            args(&[
                "host-setup",
                "--data-root",
                root(),
                "--project",
                "project-test",
                "--host-jar",
                &PathBuf::from(root()).join("selected.jar").to_string_lossy(),
                "--output",
                &PathBuf::from(root())
                    .join("mmmm-host.json")
                    .to_string_lossy(),
                "--scope-json",
                "{}",
            ])
        };
        assert!(matches!(
            parse(&base()),
            Ok(Some(Command::Setup {
                read_policy: None,
                ..
            }))
        ));
        let mut selected = base();
        selected.extend(args(&[
            "--shape-mode",
            "survival",
            "--shape-mode",
            "adventure",
        ]));
        let Some(Command::Setup {
            read_policy: Some(shape),
            ..
        }) = parse(&selected).unwrap()
        else {
            panic!("Explicit modes must retain a selected policy");
        };
        assert_eq!(
            shape
                .shape_modes()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["adventure", "survival"]
        );
        assert!(!shape.native_observation_user_local_only());
        selected.extend(args(&["--native-observation", "user_local_only"]));
        let Some(Command::Setup {
            read_policy: Some(both),
            ..
        }) = parse(&selected).unwrap()
        else {
            panic!("Explicit observation opt-in must remain independent");
        };
        assert!(both.native_observation_user_local_only());
        let mut observation = base();
        observation.extend(args(&["--native-observation", "user_local_only"]));
        let Some(Command::Setup {
            read_policy: Some(observation),
            ..
        }) = parse(&observation).unwrap()
        else {
            panic!("Observation-only policy must parse");
        };
        assert!(observation.shape_modes().is_empty());
        for extra in [
            vec!["--shape-mode", "all"],
            vec!["--shape-mode", "Survival"],
            vec!["--shape-mode", "survival", "--shape-mode", "survival"],
            vec!["--native-observation", "deny"],
            vec!["--native-observation", "owned"],
            vec![
                "--native-observation",
                "user_local_only",
                "--native-observation",
                "user_local_only",
            ],
        ] {
            let mut invalid = base();
            invalid.extend(args(&extra));
            assert!(parse(&invalid).is_err());
        }
        let mut other_command =
            args(&["start", "--data-root", root(), "--project", "project-test"]);
        other_command.extend(args(&["--shape-mode", "survival"]));
        assert!(parse(&other_command).is_err());
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

    fn import_args() -> Vec<String> {
        args(&[
            "source-import",
            "--data-root",
            root(),
            "--project",
            "project-import",
            "--expected-revision",
            &"0".repeat(64),
        ])
    }

    #[test]
    fn source_batch_parser_preserves_original_bytes_and_closed_kinds() {
        let original = " \n{\"name\":\"a:b\",\"duplicate\":1,\"duplicate\":2}\n ";
        let mut input = import_args();
        for (kind, source) in [("clip", "{}"), ("prefab", original), ("instance", "{}")] {
            input.extend(["--document".into(), format!("{kind}:{source}")]);
        }
        let Some(Command::SourceImport { documents, .. }) = parse(&input).unwrap() else {
            panic!("exact native source batch was not selected");
        };
        assert_eq!(documents.len(), 3);
        assert_eq!(documents[0].kind, NativeSourceKind::Clip);
        assert_eq!(documents[1].kind, NativeSourceKind::Prefab);
        assert_eq!(documents[2].kind, NativeSourceKind::Instance);
        assert_eq!(documents[1].source.as_bytes(), original.as_bytes());
        // The CLI must not silently parse/normalize the duplicate key away;
        // the original strict ingress owns its actual semantic rejection.
        assert!(parse_json(documents[1].source.as_bytes()).is_err());
    }

    #[test]
    fn source_batch_rejects_authority_options_and_invalid_size_or_shape() {
        assert!(matches!(
            parse(&import_args()),
            Err(EntryError::SourceArguments)
        ));
        for document in ["prefab", "prefab:", "asset:{}", "Prefab:{}", "clip :{}"] {
            let mut input = import_args();
            input.extend(args(&["--document", document]));
            assert!(matches!(parse(&input), Err(EntryError::SourceArguments)));
        }
        for extra in [
            ["--principal", "native-owner"],
            ["--grant", "write"],
            ["--policy-revision", "claimed"],
            ["--source-file", "unselected.json"],
            ["--project", "another-project"],
        ] {
            let mut input = import_args();
            input.extend(args(&["--document", "prefab:{}"]));
            input.extend(args(&extra));
            assert!(matches!(parse(&input), Err(EntryError::Arguments)));
        }
        let mut count = import_args();
        for _ in 0..=MAX_SOURCE_DOCUMENTS {
            count.extend(args(&["--document", "prefab:{}"]));
        }
        assert!(matches!(parse(&count), Err(EntryError::SourceArguments)));
        assert_eq!(
            checked_source_total(255, MAX_SOURCE_TOTAL - 1, 1).unwrap(),
            MAX_SOURCE_TOTAL
        );
        for (count, total, length) in [
            (256, 0, 1),
            (0, 0, 0),
            (0, 0, MAX_SOURCE_DOCUMENT + 1),
            (0, MAX_SOURCE_TOTAL, 1),
            (0, usize::MAX, 1),
        ] {
            assert!(matches!(
                checked_source_total(count, total, length),
                Err(EntryError::SourceArguments)
            ));
        }
        let mut invalid_digest = import_args();
        invalid_digest[6] = "invalid-digest".into();
        invalid_digest.extend(args(&["--document", "prefab:{}"]));
        assert!(matches!(parse(&invalid_digest), Err(EntryError::Arguments)));
    }

    // Actual protected Store fixtures are needed here: parser-only tests cannot
    // prove that a consumed daemon shares the real native owner, CAS and head.
    // Reuse original authored Nodes/Clip shapes; no game/proof fixture is made.
    static NEXT_IMPORT_ROOT: AtomicU64 = AtomicU64::new(0);
    const IMPORT_ROOT_MARKER: &[u8] = b"mmmm-native-source-entry-test-v1\n";
    struct ImportRoot(PathBuf);
    impl ImportRoot {
        fn new() -> Self {
            let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let parent = fs::canonicalize(parent).unwrap();
            let path = parent.join(format!(
                "mmmm-native-source-entry-{}-{}",
                std::process::id(),
                NEXT_IMPORT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            let checkout =
                fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
            assert!(path.is_absolute() && !path.starts_with(checkout) && !path.exists());
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let path = fs::canonicalize(path).unwrap();
            assert_eq!(path.parent(), Some(parent.as_path()));
            fs::write(path.join("test-owner.txt"), IMPORT_ROOT_MARKER).unwrap();
            Self(path)
        }
        fn open(&self) -> DurableStore {
            DurableStore::open(StoreConfig::new(self.0.clone())).unwrap()
        }
        fn selection(&self, name: &str) -> PathBuf {
            // The native file selector accepts ordinary drive paths. The test
            // root retains its canonical spelling for ownership/cleanup only.
            #[cfg(windows)]
            let selected_root = {
                let canonical = self.0.to_str().unwrap();
                PathBuf::from(canonical.strip_prefix("\\\\?\\").unwrap_or(canonical))
            };
            #[cfg(not(windows))]
            let selected_root = self.0.clone();
            assert_eq!(fs::canonicalize(&selected_root).unwrap(), self.0);
            selected_root.join(name)
        }
        fn initialize(&self) -> ProjectBootstrapReceipt {
            crate::native_project::create_native_project(
                &mut self.open(),
                "Native authoring entry fixture",
                &TargetProfileId::new("target-unverified").unwrap(),
                Instant::now() + SOURCE_IMPORT,
            )
            .unwrap()
        }
        fn prepare(&self, project: &ProjectId, budget: &RequestBudget) -> PreparedDaemon {
            let digest = daemon_launch::current_executable_digest(budget.deadline()).unwrap();
            let mut factory = ProductionFactory::offline_owned(digest);
            PreparedDaemon::open_for_native_source_import(
                StoreConfig::new(self.0.clone()),
                project.clone(),
                &mut factory,
                budget,
            )
            .unwrap()
        }
    }
    impl Drop for ImportRoot {
        fn drop(&mut self) {
            let mut entries = 0;
            if fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0)
                && fs::read(self.0.join("test-owner.txt")).ok().as_deref()
                    == Some(IMPORT_ROOT_MARKER)
                && plain_import_tree(&self.0, &self.0, 0, &mut entries)
            {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }
    fn plain_import_tree(path: &Path, root: &Path, depth: usize, entries: &mut usize) -> bool {
        if !path.starts_with(root) || depth > 16 || *entries >= 1024 {
            return false;
        }
        *entries += 1;
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return false;
        };
        if metadata.file_type().is_symlink() {
            return false;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return false;
            }
        }
        if metadata.is_dir() {
            let Ok(children) = fs::read_dir(path) else {
                return false;
            };
            for child in children {
                let Ok(child) = child else { return false };
                if !plain_import_tree(&child.path(), root, depth + 1, entries) {
                    return false;
                }
            }
        }
        metadata.is_dir() || metadata.is_file()
    }
    fn import_budget() -> (RequestBudget, Arc<AtomicBool>) {
        let cancelled = Arc::new(AtomicBool::new(false));
        (
            RequestBudget::until(Instant::now() + SOURCE_IMPORT, cancelled.clone()).unwrap(),
            cancelled,
        )
    }
    fn import_prefab() -> Value {
        let original = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
        let mut prefab = json!({
            "contractVersion":mmmm_contracts::CONTRACT_VERSION,"prefabId":"prefab-entry",
            "revision":"0".repeat(64),"name":"Native entry source",
            "nodes":[original["nodes"][0].clone()],"ports":[],"state":[],"references":[],
            "commandModuleIds":[],"clipIds":[],"resources":[]
        });
        prefab["revision"] = json!(projected_digest("Prefab", &prefab).unwrap());
        prefab
    }
    fn import_file_io_kind(error: &ImportFileError, kind: std::io::ErrorKind) -> bool {
        let mut current: &(dyn std::error::Error + 'static) = error;
        for _ in 0..8 {
            if let Some(error) = current.downcast_ref::<std::io::Error>() {
                return error.kind() == kind;
            }
            let Some(source) = current.source() else {
                return false;
            };
            current = source;
        }
        false
    }

    #[test]
    fn cold_native_batch_commits_actual_clip_sources_and_retains_delivery_failure() {
        let root = ImportRoot::new();
        let initialized = root.initialize();
        let (budget, cancelled) = import_budget();
        let mut prefab = import_prefab();
        let mut clip = parse_json(include_bytes!("../../../examples/animation-clip.json")).unwrap();
        clip["clipId"] = json!("clip-entry");
        clip["ownerPrefabId"] = prefab["prefabId"].clone();
        clip["tracks"][0]["nodeId"] = prefab["nodes"][0]["nodeId"].clone();
        for key in clip["tracks"][0]["keys"].as_array_mut().unwrap() {
            key["transform"] = prefab["nodes"][0]["transform"].clone();
        }
        clip["revision"] = json!(projected_digest("AnimationClip", &clip).unwrap());
        prefab["clipIds"] = json!([clip["clipId"]]);
        prefab["revision"] = json!(projected_digest("Prefab", &prefab).unwrap());
        let prefab_bytes = [b" \n".as_slice(), &encode_json(&prefab).unwrap(), b"\n "].concat();
        let clip_bytes = encode_json(&clip).unwrap();
        let mut input = args(&[
            "source-import",
            "--data-root",
            root.0.to_str().unwrap(),
            "--project",
            initialized.project_id.as_str(),
            "--expected-revision",
            initialized.project_revision.as_str(),
        ]);
        // The Clip comes first so this crosses the real order-independent batch
        // boundary instead of relying on CLI ordering to repair references.
        input.extend([
            "--document".into(),
            format!("clip:{}", String::from_utf8(clip_bytes.clone()).unwrap()),
        ]);
        input.extend([
            "--document".into(),
            format!(
                "prefab:{}",
                String::from_utf8(prefab_bytes.clone()).unwrap()
            ),
        ]);
        let Some(Command::SourceImport {
            project,
            expected_revision,
            documents,
            ..
        }) = parse(&input).unwrap()
        else {
            panic!("source batch not selected");
        };
        let raw_documents = documents
            .iter()
            .map(|document| NativeSourceDocument {
                kind: document.kind,
                bytes: document.source.as_bytes(),
            })
            .collect::<Vec<_>>();
        let receipt = root
            .prepare(&project, &budget)
            .import_native_sources(&NativeSourceInput {
                project: &project,
                expected_revision: &expected_revision,
                documents: &raw_documents,
                retained_resources: &[],
                raw_resources: &[],
            })
            .unwrap();
        assert_eq!(receipt.base_revision, initialized.project_revision);
        assert_ne!(receipt.project_revision, receipt.base_revision);
        assert_eq!(receipt.documents.len(), 2);
        let stored = root.open();
        assert_eq!(
            stored.project(&project).unwrap()["revision"],
            receipt.project_revision.as_str()
        );
        assert_eq!(
            stored
                .project_revision(&project, &receipt.base_revision)
                .unwrap()["ownedResources"],
            json!([])
        );
        for (pin, blob) in &receipt.documents {
            let expected = match pin.kind {
                mmmm_runtime::storage::owned_documents::OwnedDocumentKind::Prefab => &prefab_bytes,
                mmmm_runtime::storage::owned_documents::OwnedDocumentKind::AnimationClip => {
                    &clip_bytes
                }
                _ => panic!("unexpected admitted document kind"),
            };
            assert_eq!(blob.digest, raw_digest(expected));
            assert_eq!(stored.read_blob(blob).unwrap(), *expected);
            if pin.kind == mmmm_runtime::storage::owned_documents::OwnedDocumentKind::Prefab {
                assert_eq!(pin.revision.as_str(), prefab["revision"].as_str().unwrap());
                assert_ne!(pin.revision, blob.digest);
            }
        }
        assert!(!root.0.join("runtime").exists());
        let visible = source_receipt_value(&receipt);
        assert!(visible.get("source").is_none());
        assert!(encode_json(&visible).unwrap().len() <= MAX_SOURCE_OUTPUT);
        let failed = deliver_sources(receipt.clone(), &budget, |value, actual_deadline| {
            assert_eq!(value, &visible);
            assert_eq!(actual_deadline, budget.deadline());
            finish_output(
                Err(EntryError::OutputInvalid),
                Err(EntryError::DrainUncertain),
            )
        })
        .unwrap_err();
        let EntryError::SourcesCommitted {
            receipt: retained,
            delivery,
        } = failed
        else {
            panic!("committed source receipt was discarded");
        };
        assert_eq!(*retained, receipt);
        let EntryError::OutputDrain { primary, cleanup } = *delivery else {
            panic!("write and drain causes were not retained together");
        };
        assert!(matches!(*primary, EntryError::OutputInvalid));
        assert!(matches!(*cleanup, EntryError::DrainUncertain));
        cancelled.store(true, Ordering::Release);
        let failed = deliver_sources(receipt.clone(), &budget, |_, _| {
            panic!("cancelled delivery ran")
        });
        assert!(
            matches!(failed, Err(EntryError::SourcesCommitted { receipt: retained, delivery })
            if *retained == receipt && matches!(*delivery, EntryError::SourceRequest(ref error) if error.code == "CANCELLED"))
        );
        assert_eq!(
            stored.project(&project).unwrap()["revision"],
            receipt.project_revision.as_str()
        );
    }

    #[test]
    fn cold_native_import_keeps_original_cancellation_and_rejects_stale_head() {
        let root = ImportRoot::new();
        let initialized = root.initialize();
        let source = encode_json(&import_prefab()).unwrap();
        let documents = [NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &source,
        }];
        let (budget, cancelled) = import_budget();
        let prepared = root.prepare(&initialized.project_id, &budget);
        cancelled.store(true, Ordering::Release);
        let result = prepared.import_native_sources(&NativeSourceInput {
            project: &initialized.project_id,
            expected_revision: &initialized.project_revision,
            documents: &documents,
            retained_resources: &[],
            raw_resources: &[],
        });
        assert!(
            matches!(result, Err(DaemonError::Composition(ref error)) if error.code == "CANCELLED")
        );
        let (budget, _) = import_budget();
        let wrong = Sha256Digest::new("0".repeat(64)).unwrap();
        let result = root
            .prepare(&initialized.project_id, &budget)
            .import_native_sources(&NativeSourceInput {
                project: &initialized.project_id,
                expected_revision: &wrong,
                documents: &documents,
                retained_resources: &[],
                raw_resources: &[],
            });
        assert!(
            matches!(result, Err(DaemonError::Composition(ref error)) if error.code == "PLAN_STALE")
        );
        assert_eq!(
            root.open().project(&initialized.project_id).unwrap()["revision"],
            initialized.project_revision.as_str()
        );
    }

    #[test]
    fn cold_native_import_preserves_busy_and_cannot_publish_a_listener() {
        let root = ImportRoot::new();
        let initialized = root.initialize();
        let (budget, _) = import_budget();
        let prepared = root.prepare(&initialized.project_id, &budget);
        let digest = daemon_launch::current_executable_digest(budget.deadline()).unwrap();
        let mut factory = ProductionFactory::offline_owned(digest);
        let second = PreparedDaemon::open_for_native_source_import(
            StoreConfig::new(root.0.clone()),
            initialized.project_id.clone(),
            &mut factory,
            &budget,
        );
        assert!(matches!(
            second,
            Err(DaemonError::Storage(StorageError::Busy))
        ));
        assert!(
            matches!(prepared.start(), Err(DaemonError::Composition(ref error)) if error.code == "SOURCE_IMPORT_ONLY")
        );
        assert!(!root.0.join("runtime").exists());
        assert_eq!(
            root.open().project(&initialized.project_id).unwrap()["revision"],
            initialized.project_revision.as_str()
        );
    }

    #[test]
    fn cold_native_import_does_not_create_missing_or_uninitialized_stores() {
        let root = ImportRoot::new();
        let (budget, _) = import_budget();
        let digest = daemon_launch::current_executable_digest(budget.deadline()).unwrap();
        let mut factory = ProductionFactory::offline_owned(digest);
        let project = ProjectId::new("project-not-initialized").unwrap();
        let missing = root.0.join("absent-native-data");
        let result = PreparedDaemon::open_for_native_source_import(
            StoreConfig::new(missing.clone()),
            project.clone(),
            &mut factory,
            &budget,
        );
        assert!(
            matches!(result, Err(DaemonError::Storage(StorageError::Io(ref error)))
            if error.kind() == std::io::ErrorKind::NotFound)
        );
        assert!(!missing.exists());
        let result = PreparedDaemon::open_for_native_source_import(
            StoreConfig::new(root.0.clone()),
            project,
            &mut factory,
            &budget,
        );
        assert!(
            matches!(result, Err(DaemonError::Storage(StorageError::Io(ref error)))
            if error.kind() == std::io::ErrorKind::NotFound)
        );
        assert!(!root.0.join("journal.sqlite3").exists());
        assert!(!root.0.join("coordinator.lock").exists());
        assert!(!root.0.join("blobs").exists());
        assert!(!root.0.join("runtime").exists());
    }

    #[test]
    fn cold_native_import_keeps_wrong_existing_schema_and_original_store_unchanged() {
        let root = ImportRoot::new();
        let initialized = root.initialize();
        let database = root.0.join("journal.sqlite3");
        // This is the already closed fixture's own database. Its invalid input
        // is explicit and bounded; the existing-only API must not recreate it.
        let invalid = b"MMMM native import invalid SQLite fixture\n";
        fs::write(&database, invalid).unwrap();
        let (budget, _) = import_budget();
        let digest = daemon_launch::current_executable_digest(budget.deadline()).unwrap();
        let mut factory = ProductionFactory::offline_owned(digest);
        let result = PreparedDaemon::open_for_native_source_import(
            StoreConfig::new(root.0.clone()),
            initialized.project_id,
            &mut factory,
            &budget,
        );
        assert!(matches!(
            result,
            Err(DaemonError::Storage(StorageError::Sqlite(_)))
        ));
        assert_eq!(fs::read(database).unwrap(), invalid);
        assert!(!root.0.join("runtime").exists());
    }

    #[test]
    fn native_source_import_requires_private_preparation_and_keeps_strict_duplicate_rejection() {
        let root = ImportRoot::new();
        let initialized = root.initialize();
        let (budget, _) = import_budget();
        let source = encode_json(&import_prefab()).unwrap();
        let documents = [NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &source,
        }];
        let digest = daemon_launch::current_executable_digest(budget.deadline()).unwrap();
        let mut factory = ProductionFactory::offline_owned(digest);
        let ordinary = PreparedDaemon::open(
            StoreConfig::new(root.0.clone()),
            Some(initialized.project_id.clone()),
            &mut factory,
        )
        .unwrap();
        let result = ordinary.import_native_sources(&NativeSourceInput {
            project: &initialized.project_id,
            expected_revision: &initialized.project_revision,
            documents: &documents,
            retained_resources: &[],
            raw_resources: &[],
        });
        assert!(
            matches!(result, Err(DaemonError::Composition(ref error)) if error.code == "SOURCE_IMPORT_UNAVAILABLE")
        );
        let canonical = String::from_utf8(source).unwrap();
        let duplicate = format!("{{\"prefabId\":\"prefab-entry\",{}", &canonical[1..]);
        let documents = [NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: duplicate.as_bytes(),
        }];
        let result = root
            .prepare(&initialized.project_id, &budget)
            .import_native_sources(&NativeSourceInput {
                project: &initialized.project_id,
                expected_revision: &initialized.project_revision,
                documents: &documents,
                retained_resources: &[],
                raw_resources: &[],
            });
        assert!(
            matches!(result, Err(DaemonError::Application(ref error)) if error.code == "INVALID_INPUT")
        );
        assert_eq!(
            root.open().project(&initialized.project_id).unwrap()["revision"],
            initialized.project_revision.as_str()
        );
        assert!(!root.0.join("runtime").exists());
    }

    #[test]
    fn selected_file_parser_preserves_drive_colons_and_requires_adjacent_raw_pairs() {
        let document = PathBuf::from(root()).join("selected-prefab.json");
        let descriptor = PathBuf::from(root()).join("resource-reference.json");
        let bytes = PathBuf::from(root()).join("selected-content.bin");
        let mut input = import_args();
        input.extend([
            "--document-file".into(),
            format!("prefab:{}", document.display()),
        ]);
        input.extend([
            "--resource-descriptor-file".into(),
            descriptor.to_string_lossy().into_owned(),
        ]);
        input.extend([
            "--resource-bytes-file".into(),
            bytes.to_string_lossy().into_owned(),
        ]);
        let Some(Command::SourceImport {
            documents,
            document_files,
            raw_resources,
            ..
        }) = parse(&input).unwrap()
        else {
            panic!("explicit file batch not selected");
        };
        assert!(documents.is_empty());
        assert_eq!(document_files.len(), 1);
        assert_eq!(document_files[0].kind, NativeSourceKind::Prefab);
        assert_eq!(document_files[0].path, document);
        assert_eq!(raw_resources.len(), 1);
        assert_eq!(raw_resources[0].descriptor, descriptor);
        assert_eq!(raw_resources[0].bytes, bytes);
        // These are lexical paths and need not exist: the parser must not open,
        // hash, create a Store or acquire a native owner to accept a selector.
        for options in [
            vec!["--resource-descriptor-file", descriptor.to_str().unwrap()],
            vec!["--resource-bytes-file", bytes.to_str().unwrap()],
            vec![
                "--resource-descriptor-file",
                descriptor.to_str().unwrap(),
                "--document",
                "prefab:{}",
            ],
            vec![
                "--resource-descriptor-file",
                descriptor.to_str().unwrap(),
                "--resource-descriptor-file",
                descriptor.to_str().unwrap(),
            ],
        ] {
            let mut invalid = import_args();
            invalid.extend(args(&options));
            assert!(matches!(parse(&invalid), Err(EntryError::SourceArguments)));
        }
        let mut many = import_args();
        for _ in 0..MAX_SOURCE_DOCUMENTS {
            many.extend([
                "--document-file".into(),
                format!("prefab:{}", document.display()),
            ]);
        }
        many.extend([
            "--resource-descriptor-file".into(),
            descriptor.to_string_lossy().into_owned(),
        ]);
        many.extend([
            "--resource-bytes-file".into(),
            bytes.to_string_lossy().into_owned(),
        ]);
        assert!(matches!(parse(&many), Err(EntryError::SourceArguments)));
        let mut raw_only = import_args();
        raw_only.extend([
            "--resource-descriptor-file".into(),
            descriptor.to_string_lossy().into_owned(),
        ]);
        raw_only.extend([
            "--resource-bytes-file".into(),
            bytes.to_string_lossy().into_owned(),
        ]);
        let Some(Command::SourceImport {
            documents,
            document_files,
            raw_resources,
            ..
        }) = parse(&raw_only).unwrap()
        else {
            panic!("resource-only source batch not selected");
        };
        assert!(documents.is_empty() && document_files.is_empty());
        assert_eq!(raw_resources.len(), 1);
        assert_eq!(raw_resources[0].descriptor, descriptor);
        assert_eq!(raw_resources[0].bytes, bytes);
    }

    #[test]
    fn cold_resource_only_files_commit_without_catalog_or_game_grants() {
        let root = ImportRoot::new();
        let initialized = root.initialize();
        let before = root.open().project(&initialized.project_id).unwrap();
        let (budget, _) = import_budget();
        let raw_bytes = b"whole selected container bytes remain opaque\n";
        let descriptor = json!({"resourceId":"resource-container-only","sha256":raw_digest(raw_bytes),
            "mediaType":"application/octet-stream","sizeBytes":raw_bytes.len()});
        let descriptor_bytes = encode_json(&descriptor).unwrap();
        let descriptor_file = root.selection("container-reference.json");
        let content_file = root.selection("selected-container.bin");
        fs::write(&descriptor_file, &descriptor_bytes).unwrap();
        fs::write(&content_file, raw_bytes).unwrap();
        let digest = daemon_launch::current_executable_digest(budget.deadline()).unwrap();
        let mut factory = ProductionFactory::offline_owned(digest);
        let prepared = PreparedDaemon::open_for_native_source_import(
            StoreConfig::new(root.0.clone()),
            initialized.project_id.clone(),
            &mut factory,
            &budget,
        )
        .unwrap();
        // Retain the actual composition's shared registry across consumption
        // of its sole Store. A separate empty registry would prove nothing.
        let registries = factory.registries().unwrap().clone();
        let handles = prepared.handles().clone();
        let workspace = handles.workspace.as_ref().unwrap();
        let context_id = ContextId::new(workspace.context["contextId"].as_str().unwrap()).unwrap();
        let principal = workspace.witness.principal().clone();
        assert_eq!(workspace.context["environment"]["kind"], "offline");
        // Authentication gives this assertion method/context access only; no
        // source, host route, pairing or rights registration is installed.
        let mut sessions = crate::auth::SessionAuthority::new(1).unwrap();
        let token = sessions
            .install(crate::auth::SessionPolicy {
                principal: principal.clone(),
                allowed_methods: ["catalog.capture".into()].into(),
                allowed_contexts: [context_id.clone()].into(),
                lifetime: SOURCE_IMPORT,
            })
            .unwrap();
        let authenticated = sessions.authenticate_token(&token).unwrap();
        let loaded = load_native_inputs(
            &prepared,
            &initialized.project_id,
            &initialized.project_revision,
            Vec::new(),
            &[],
            &[CommandRawFiles {
                descriptor: descriptor_file.clone(),
                bytes: content_file.clone(),
            }],
            &budget,
        )
        .unwrap();
        assert!(loaded.documents.is_empty());
        assert_eq!(loaded.resources.len(), 1);
        assert_eq!(loaded.resources[0].metadata, descriptor_bytes);
        assert_eq!(loaded.resources[0].bytes, raw_bytes);
        let resources = [NativeRawSourceResource {
            metadata: &loaded.resources[0].metadata,
            bytes: &loaded.resources[0].bytes,
        }];
        let receipt = prepared
            .import_native_sources(&NativeSourceInput {
                project: &initialized.project_id,
                expected_revision: &initialized.project_revision,
                documents: &[],
                retained_resources: &[],
                raw_resources: &resources,
            })
            .unwrap();
        assert!(receipt.documents.is_empty());
        assert_eq!(receipt.resources.len(), 1);
        assert_eq!(receipt.base_revision, initialized.project_revision);
        assert_ne!(receipt.project_revision, receipt.base_revision);
        let stored = root.open();
        let mut expected = before.clone();
        expected["resourceIds"]
            .as_array_mut()
            .unwrap()
            .push(descriptor["resourceId"].clone());
        expected["revision"] = json!(receipt.project_revision);
        assert_eq!(stored.project(&initialized.project_id).unwrap(), expected);
        assert_eq!(
            stored
                .project_revision(&initialized.project_id, &receipt.base_revision)
                .unwrap(),
            before
        );
        assert_eq!(
            stored.read_blob(&receipt.resources[0].1).unwrap(),
            raw_bytes
        );
        assert_eq!(receipt.resources[0].1.digest, raw_digest(raw_bytes));
        assert_eq!(
            registries
                .catalog
                .read_principal(&authenticated, &context_id)
                .unwrap_err()
                .code,
            "SOURCE_UNAVAILABLE"
        );
        assert_eq!(
            handles.authority.current_context_ids(&principal).unwrap(),
            std::collections::BTreeSet::from([context_id.clone()])
        );
        assert!(handles.hosts.context(&principal, &context_id).is_err());
        assert!(source_receipt_value(&receipt).get("source").is_none());
        assert_eq!(fs::read(descriptor_file).unwrap(), descriptor_bytes);
        assert_eq!(fs::read(content_file).unwrap(), raw_bytes);
        assert!(!root.0.join("runtime").exists());
    }

    #[test]
    fn selected_large_document_and_raw_content_share_the_actual_atomic_import() {
        let root = ImportRoot::new();
        let initialized = root.initialize();
        let (budget, _) = import_budget();
        let raw_bytes = (0..128 * 1024)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        let descriptor = json!({"resourceId":"resource-file-entry","sha256":raw_digest(&raw_bytes),
            "mediaType":"application/octet-stream","sizeBytes":raw_bytes.len()});
        let descriptor_bytes = [
            b" \n".as_slice(),
            &encode_json(&descriptor).unwrap(),
            b"\n ",
        ]
        .concat();
        let mut prefab = import_prefab();
        prefab["resources"] = json!([descriptor]);
        prefab["revision"] = json!(projected_digest("Prefab", &prefab).unwrap());
        let mut original = vec![b' '; 96 * 1024];
        original.extend(encode_json(&prefab).unwrap());
        original.push(b'\n');
        assert!(original.len() > 64 * 1024);
        let document_file = root.selection("large-prefab.json");
        let descriptor_file = root.selection("resource-reference.json");
        let content_file = root.selection("selected-content.bin");
        fs::write(&document_file, &original).unwrap();
        fs::write(&descriptor_file, &descriptor_bytes).unwrap();
        fs::write(&content_file, &raw_bytes).unwrap();
        let prepared = root.prepare(&initialized.project_id, &budget);
        let loaded = load_native_inputs(
            &prepared,
            &initialized.project_id,
            &initialized.project_revision,
            Vec::new(),
            &[CommandDocumentFile {
                kind: NativeSourceKind::Prefab,
                path: document_file.clone(),
            }],
            &[CommandRawFiles {
                descriptor: descriptor_file.clone(),
                bytes: content_file.clone(),
            }],
            &budget,
        )
        .unwrap();
        assert_eq!(loaded.documents[0].bytes, original);
        assert_eq!(loaded.resources[0].metadata, descriptor_bytes);
        assert_eq!(loaded.resources[0].bytes, raw_bytes);
        let documents = loaded
            .documents
            .iter()
            .map(|document| NativeSourceDocument {
                kind: document.kind,
                bytes: &document.bytes,
            })
            .collect::<Vec<_>>();
        let resources = loaded
            .resources
            .iter()
            .map(|resource| NativeRawSourceResource {
                metadata: &resource.metadata,
                bytes: &resource.bytes,
            })
            .collect::<Vec<_>>();
        let receipt = prepared
            .import_native_sources(&NativeSourceInput {
                project: &initialized.project_id,
                expected_revision: &initialized.project_revision,
                documents: &documents,
                retained_resources: &[],
                raw_resources: &resources,
            })
            .unwrap();
        let stored = root.open();
        assert_eq!(receipt.documents.len(), 1);
        assert_eq!(receipt.resources.len(), 1);
        assert_eq!(stored.read_blob(&receipt.documents[0].1).unwrap(), original);
        assert_eq!(receipt.documents[0].1.digest, raw_digest(&original));
        assert_eq!(
            receipt.documents[0].0.revision.as_str(),
            prefab["revision"].as_str().unwrap()
        );
        assert_eq!(
            stored.read_blob(&receipt.resources[0].1).unwrap(),
            raw_bytes
        );
        assert_eq!(receipt.resources[0].1.digest, raw_digest(&raw_bytes));
        assert_eq!(
            stored.project(&initialized.project_id).unwrap()["revision"],
            receipt.project_revision.as_str()
        );
        assert_eq!(fs::read(document_file).unwrap(), original);
        assert_eq!(fs::read(descriptor_file).unwrap(), descriptor_bytes);
        assert_eq!(fs::read(content_file).unwrap(), raw_bytes);
        assert!(!root.0.join("runtime").exists());
    }

    #[test]
    fn a_later_selected_file_failure_does_not_publish_the_earlier_document() {
        let root = ImportRoot::new();
        let initialized = root.initialize();
        let (budget, _) = import_budget();
        let original = encode_json(&import_prefab()).unwrap();
        let selected = root.selection("selected-prefab.json");
        fs::write(&selected, &original).unwrap();
        let before = root.open().project(&initialized.project_id).unwrap();
        let prepared = root.prepare(&initialized.project_id, &budget);
        let result = load_native_inputs(
            &prepared,
            &initialized.project_id,
            &initialized.project_revision,
            Vec::new(),
            &[
                CommandDocumentFile {
                    kind: NativeSourceKind::Prefab,
                    path: selected.clone(),
                },
                CommandDocumentFile {
                    kind: NativeSourceKind::Clip,
                    path: root.selection("missing-clip.json"),
                },
            ],
            &[],
            &budget,
        );
        assert!(matches!(result, Err(EntryError::SourceFile(ref error))
            if import_file_io_kind(error, std::io::ErrorKind::NotFound)));
        drop(prepared);
        let stored = root.open();
        assert_eq!(stored.project(&initialized.project_id).unwrap(), before);
        assert_eq!(
            stored
                .project_revision(&initialized.project_id, &initialized.project_revision)
                .unwrap(),
            before
        );
        let unstaged_blob = mmmm_runtime::storage::BlobRef {
            digest: raw_digest(&original),
            byte_length: original.len() as u64,
        };
        assert!(
            matches!(stored.read_blob(&unstaged_blob), Err(StorageError::Io(ref error))
            if error.kind() == std::io::ErrorKind::NotFound)
        );
        assert_eq!(fs::read(selected).unwrap(), original);
        assert!(!root.0.join("missing-clip.json").exists());
        assert!(!root.0.join("runtime").exists());
    }

    // Cold source 사용 관리는 같은 실제 보호 Project/import fixture를 재사용한다.
    mod catalog_source_use_tests {
        include!("catalog_source_use_tests.rs");
    }
}

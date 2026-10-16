//! Concrete native entrypoints reuse the one protected daemon composition.
//! Arguments select locators, metadata and explicit authored contract bytes; capabilities remain
//! in the authenticated peer or anonymous host exchange, never in argv.

use crate::{
    CoordinatorClient,
    bootstrap::NativeWorkspacePermit,
    catalog_source_use::{LocalCatalogSourceUseAction, manage_catalog_source_use},
    daemon::{DaemonError, PreparedDaemon},
    daemon_launch::{self, DaemonLaunchError, NativeDaemonLocator},
    host_read_policy::selected_host_read_policy,
    host_relay::{self, RelayError},
    lifecycle::{Coordinator, CoordinatorError},
    local_setup::{
        LocalHostSetup, LocalReadPolicySetupError, LocalSetupError, register_local_host_setup,
        register_local_host_setup_with_calibration_scope,
        register_local_host_setup_with_read_policy, validate_calibration_base_scope,
    },
    native_import_files::{ImportReadBudget, InputRole, read_selected, validate_selection},
    native_source_ingress::{
        NativeRawSourceResource, NativeSourceDocument, NativeSourceInput, NativeSourceKind,
    },
    production_factory::{
        NativeCompatibilityApprovalSelection, ProductionFactory,
        approve_native_compatibility_profile,
    },
    service::{RequestBudget, ServiceError},
    stdio_io::{NativeStdioPort, StdioError, StdioLimits},
    workspace_bootstrap::NativeOwnerWitness,
};
use mmmm_contracts::{
    ContextId, JsonLimits, PlanId, ProjectId, ResourceId, ResourceLocation, Sha256Digest,
    TargetProfileId, encode_json, parse_json_with_limits,
};
use mmmm_runtime::storage::{
    DurableStore, StorageError, StoreConfig,
    catalog_source_use::{
        CatalogSourceUseRole, CatalogSourceUseSelection, CatalogSourceUseSnapshot,
    },
    compatibility_approval::CompatibilityApprovalRecord,
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

fn random_suffix() -> Result<String, EntryError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| EntryError::OutputInvalid)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[derive(Debug)]
pub enum EntryError {
    Arguments,
    HostReadPolicyArguments,
    SourceArguments,
    ManualArguments,
    CatalogSourceArguments,
    CatalogSourceRequest(mmmm_application::AppError),
    CompatibilityProfileArguments,
    CompatibilityProfileRequest(mmmm_application::AppError),
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
    HostSetupCommitted {
        project: ProjectId,
        scope_digest: Sha256Digest,
        delivery: Box<EntryError>,
    },
    CatalogSourceUsesCommitted {
        snapshot: Box<CatalogSourceUseSnapshot>,
        delivery: Box<EntryError>,
    },
    CompatibilityProfileCommitted {
        record: Box<CompatibilityApprovalRecord>,
        delivery: Box<EntryError>,
    },
    CalibrationSelectionCommitted {
        selection_digest: Sha256Digest,
        delivery: Box<EntryError>,
    },
    CalibrationPlanCommitted {
        project: ProjectId,
        plan: PlanId,
        hash: Sha256Digest,
        checkpoint_failed: bool,
        delivery: Option<Box<EntryError>>,
    },
    ManualSceneCommitted {
        receipt: Box<crate::native_manual_exchange::ManualSceneReceipt>,
        checkpoint_failed: bool,
        delivery: Option<Box<EntryError>>,
    },
    Shutdown {
        primary: Option<Box<EntryError>>,
        cleanup: CoordinatorError,
    },
}
impl std::fmt::Display for EntryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ManualSceneCommitted { receipt, checkpoint_failed, delivery } => {
                write!(f, "Manual ScenePatch {} for Project {} was staged as {} ({}); its original resource is retained", receipt.patch_id, receipt.project_id, receipt.resource.resource_id, receipt.resource.sha256)?;
                if *checkpoint_failed { f.write_str("; final source checkpoint failed (MANUAL_SCENE_COMMITTED); the Coordinator retains the original cause")?; }
                if let Some(error) = delivery { write!(f, "; result delivery failed: {error}")?; }
                Ok(())
            }
            Self::Arguments => f.write_str("Native command arguments are invalid"),
            Self::HostReadPolicyArguments => f.write_str("Host setup read policy requires unique --shape-mode survival|creative|adventure|spectator selections and optional --native-observation user_local_only; absent selections grant no corresponding source access"),
            Self::SourceArguments => f.write_str("Native source import requires at least one document or raw resource pair and at most 256 combined document/resource inputs: --document <kind>:<JSON>, --document-file <kind>:<absolute JSON path>, and adjacent --resource-descriptor-file/--resource-bytes-file paths; kinds are prefab|instance|clip and OS argv limits may be smaller"),
            Self::ManualArguments => f.write_str("Manual import requires an existing Coordinator, exact Project/head/context, an original exchange selection resource, selected absolute SourceMap/ScenePatch JSON files with unique resource IDs, and repeated --allow-delta kind,instanceId,nodeId static choices; no source rights or game-write grant is created"),
            Self::CatalogSourceArguments => f.write_str("Catalog source use requires --mode inspect or replace; replace needs --expected-state-digest and a complete set selected by --game-artifact <resourceId>/repeated --mod <canonicalId>,<nativeId>,<resourceId>, or explicit --withdraw true with no selections; <=256 selections, <=64 KiB selector metadata, user_local_only only"),
            Self::CatalogSourceRequest(error) => write!(f, "{}: Cold native catalog source use could not continue", error.code),
            Self::CompatibilityProfileArguments => f.write_str("Compatibility profile approval requires one initialized Project revision and exact existing profile resource ID/raw SHA-256, a bounded approval reference, separate artifact and interface SHA-256 selections; no profile JSON or authority options are accepted"),
            Self::CompatibilityProfileRequest(error) => write!(f, "{}: Cold native compatibility profile approval could not continue", error.code),
            Self::CalibrationSelectionCommitted { selection_digest, delivery } => write!(f,
                "Calibration owner selection {selection_digest} was committed and retained; result delivery failed: {delivery}"),
            Self::CalibrationPlanCommitted { project, plan, hash, checkpoint_failed, delivery } => {
                write!(f, "Calibration plan {plan} ({hash}) for Project {project} was saved and retained")?;
                if *checkpoint_failed { f.write_str("; its final source checkpoint failed (SETUP_PLAN_COMMITTED); the Coordinator retains the original cause")?; }
                if let Some(delivery) = delivery { write!(f, "; result delivery failed: {delivery}")?; }
                Ok(())
            }
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
            Self::HostSetupCommitted { project, scope_digest, delivery } => write!(f,
                "Host setup scope {scope_digest} for Project {project} was committed and retained; result delivery failed: {delivery}"),
            Self::CatalogSourceUsesCommitted { snapshot, delivery } => write!(f,
                "Catalog source use {} at generation {} for Project {} was committed and retained; result delivery failed: {delivery}",
                snapshot.state_digest(), snapshot.generation(), snapshot.project_id()),
            Self::CompatibilityProfileCommitted { record, delivery } => write!(f,
                "Compatibility profile approval {} for profile {} in Project {} was committed and retained; result delivery failed: {delivery}",
                record.approved_profile_ref(), record.profile_digest(), record.project_id()),
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
            Self::CompatibilityProfileRequest(e) => Some(e),
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
            Self::HostSetupCommitted { delivery, .. } => Some(delivery.as_ref()),
            Self::CatalogSourceUsesCommitted { delivery, .. } => Some(delivery.as_ref()),
            Self::CompatibilityProfileCommitted { delivery, .. } => Some(delivery.as_ref()),
            Self::CalibrationSelectionCommitted { delivery, .. } => Some(delivery.as_ref()),
            Self::CalibrationPlanCommitted { delivery, .. } => delivery
                .as_deref()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            Self::Shutdown { cleanup, .. } => Some(cleanup),
            _ => None,
        }
    }
}

enum Command {
    ManualImport {
        root: PathBuf,
        selection: crate::native_manual_exchange::NativeManualSelection,
    },
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
        calibration_revision: Option<Sha256Digest>,
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
    CompatibilityProfileApprove {
        root: PathBuf,
        selection: NativeCompatibilityApprovalSelection,
    },
    CalibrationApprove {
        root: PathBuf,
        project: ProjectId,
        plan: PlanId,
        hash: Sha256Digest,
    },
    CalibrationPlan {
        root: PathBuf,
        selection: mmmm_application::SetupSelection,
        bootstrap: bool,
    },
    HostBridge {
        approval: bool,
    },
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
        Command::ManualImport { root, selection } => {
            use crate::{
                credential::CredentialRef,
                host_relay::CoordinatorLocator,
                peer::PeerHostAttach,
                peer_management::{HostOffer, PublicFrame},
            };
            let deadline = started + crate::peer_management::BOOTSTRAP_LIMIT;
            let endpoint = host_relay::ExistingCoordinator
                .ensure_endpoint(&root, &selection.project_id, deadline)
                .map_err(EntryError::Relay)?;
            let mut frame = selection.locators();
            frame["kind"] = json!("native_manual_scene_offer");
            frame["protocolVersion"] = json!(mmmm_contracts::CONTRACT_VERSION);
            frame["purpose"] = json!(crate::peer_management::MANUAL_SCENE_PURPOSE);
            frame["dataRoot"] = json!(root);
            frame["nonce"] = json!(format!(
                "manual-scene-{}",
                mmmm_contracts::canonical_digest(&frame).map_err(|_| EntryError::Arguments)?
            ));
            let offer = HostOffer::manual_scene(
                PublicFrame::from_value(frame).map_err(|_| EntryError::Arguments)?,
            )
            .map_err(|_| EntryError::OutputInvalid)?;
            let reference = CredentialRef::new(&endpoint.credential_ref)
                .map_err(|_| EntryError::OutputInvalid)?;
            let (pending, prepared) = PeerHostAttach::offer_with_deadline(
                &root.join("runtime"),
                &reference,
                offer,
                deadline,
            )
            .map_err(EntryError::Peer)?;
            if !prepared.is_manual_scene()
                || prepared.value()["projectId"] != selection.project_id.as_str()
            {
                return Err(EntryError::OutputInvalid);
            }
            let value = prepared.value();
            let receipt = crate::native_manual_exchange::ManualSceneReceipt {
                project_id: selection.project_id,
                patch_id: value["patchId"]
                    .as_str()
                    .ok_or(EntryError::OutputInvalid)?
                    .to_owned(),
                resource: serde_json::from_value(value["resource"].clone())
                    .map_err(|_| EntryError::OutputInvalid)?,
            };
            let checkpoint_failed = value["outcome"] == "committed_checkpoint_failed";
            let result = json!({"kind":"manual_scene_prepared","projectId":receipt.project_id,"patchId":receipt.patch_id,"resource":receipt.resource,"outcome":value["outcome"]});
            let delivery = pending
                .complete_manual_scene()
                .map_err(EntryError::Peer)
                .and_then(|()| output(&result, deadline.min(Instant::now() + OUTPUT)))
                .err()
                .map(Box::new);
            if checkpoint_failed || delivery.is_some() {
                return Err(EntryError::ManualSceneCommitted {
                    receipt: Box::new(receipt),
                    checkpoint_failed,
                    delivery,
                });
            }
        }
        Command::CalibrationPlan {
            root,
            selection,
            bootstrap,
        } => {
            use crate::{
                credential::CredentialRef,
                host_relay::CoordinatorLocator,
                peer::PeerHostAttach,
                peer_management::{HostOffer, PublicFrame},
            };
            let deadline = started + crate::peer_management::BOOTSTRAP_LIMIT;
            let endpoint = host_relay::ExistingCoordinator
                .ensure_endpoint(&root, &selection.project_id, deadline)
                .map_err(EntryError::Relay)?;
            let purpose = if bootstrap {
                crate::calibration_bootstrap::PURPOSE
            } else {
                crate::peer_management::CALIBRATION_PLAN_PURPOSE
            };
            let nonce = format!("calibration-plan-{}", mmmm_contracts::canonical_digest(&json!({
                "purpose":purpose,"projectId":selection.project_id,"expectedRevision":selection.expected_revision,"contextId":selection.context_id
            })).map_err(|_| EntryError::Arguments)?);
            let offer = PublicFrame::from_value(json!({
                "kind":"native_calibration_plan_offer", "protocolVersion":mmmm_contracts::CONTRACT_VERSION,
                "nonce":nonce,
                "purpose":purpose, "dataRoot":root,
                "projectId":selection.project_id, "expectedRevision":selection.expected_revision, "contextId":selection.context_id
            })).map_err(|_| EntryError::Arguments)?;
            let offer =
                HostOffer::calibration_plan(offer).map_err(|_| EntryError::OutputInvalid)?;
            let reference = CredentialRef::new(&endpoint.credential_ref)
                .map_err(|_| EntryError::OutputInvalid)?;
            let (pending, prepared) = PeerHostAttach::offer_with_deadline(
                &root.join("runtime"),
                &reference,
                offer,
                deadline,
            )
            .map_err(EntryError::Peer)?;
            if !prepared.is_calibration_plan()
                || prepared.value()["projectId"] != selection.project_id.as_str()
                || prepared.value()["purpose"] != purpose
                || prepared.value()["nonce"] != nonce
            {
                return Err(EntryError::OutputInvalid);
            }
            let plan = PlanId::new(
                prepared.value()["planId"]
                    .as_str()
                    .ok_or(EntryError::OutputInvalid)?,
            )
            .map_err(|_| EntryError::OutputInvalid)?;
            let hash = Sha256Digest::new(
                prepared.value()["planHash"]
                    .as_str()
                    .ok_or(EntryError::OutputInvalid)?,
            )
            .map_err(|_| EntryError::OutputInvalid)?;
            let checkpoint_failed = prepared.value()["outcome"] == "committed_checkpoint_failed";
            let result = json!({"kind":if bootstrap {"calibration_bootstrap_plan_prepared"} else {"calibration_plan_prepared"},
                "purpose":purpose,"projectId":selection.project_id,
                "planId":plan,"planHash":hash,"outcome":prepared.value()["outcome"]});
            let delivery = pending
                .complete_calibration_plan()
                .map_err(EntryError::Peer)
                .and_then(|()| output(&result, deadline.min(Instant::now() + OUTPUT)))
                .err()
                .map(Box::new);
            if checkpoint_failed || delivery.is_some() {
                return Err(EntryError::CalibrationPlanCommitted {
                    project: selection.project_id,
                    plan,
                    hash,
                    checkpoint_failed,
                    delivery,
                });
            }
        }
        Command::HostBridge { approval } => {
            if approval {
                host_relay::run_approval_stdio(&mut NativeDaemonLocator)
            } else {
                host_relay::run_stdio(&mut NativeDaemonLocator)
            }
            .map_err(EntryError::Relay)?;
        }
        Command::CalibrationApprove {
            root,
            project,
            plan,
            hash,
        } => {
            use crate::{
                credential::CredentialRef,
                host_relay::CoordinatorLocator,
                peer::PeerHostAttach,
                peer_management::{HostOffer, PublicFrame},
            };
            let deadline = started + Duration::from_secs(30);
            let endpoint = host_relay::ExistingCoordinator
                .ensure_endpoint(&root, &project, deadline)
                .map_err(EntryError::Relay)?;
            let nonce = format!("calibration-{}", random_suffix()?);
            let offer = PublicFrame::from_value(json!({"kind":"native_calibration_owner_offer",
                "protocolVersion":mmmm_contracts::CONTRACT_VERSION,"nonce":nonce,
                "purpose":crate::bootstrap::calibration_approval::PURPOSE,
                "dataRoot":root,"projectId":project,"planId":plan,"planHash":hash}))
            .map_err(|_| EntryError::Arguments)?;
            let offer = HostOffer::owner_selection(offer).map_err(|_| EntryError::OutputInvalid)?;
            let reference = CredentialRef::new(&endpoint.credential_ref)
                .map_err(|_| EntryError::OutputInvalid)?;
            let (pending, selected) = PeerHostAttach::offer_with_deadline(
                &root.join("runtime"),
                &reference,
                offer,
                deadline,
            )
            .map_err(EntryError::Peer)?;
            let selection_digest = Sha256Digest::new(
                selected.value()["selectionDigest"]
                    .as_str()
                    .ok_or(EntryError::OutputInvalid)?,
            )
            .map_err(|_| EntryError::OutputInvalid)?;
            let result = json!({"kind":"calibration_owner_selected","projectId":project,"planId":plan,"planHash":hash,
                "selectionDigest":selection_digest,"approvalRef":selected.value()["approvalRef"],"expiresAt":selected.value()["expiresAt"]});
            let delivered = pending
                .complete_owner_selection()
                .map_err(EntryError::Peer)
                .and_then(|()| output(&result, deadline.min(Instant::now() + OUTPUT)));
            delivered.map_err(|delivery| EntryError::CalibrationSelectionCommitted {
                selection_digest,
                delivery: Box::new(delivery),
            })?;
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
            calibration_revision,
        } => {
            let executable = std::env::current_exe().map_err(|_| EntryError::Arguments)?;
            let request = LocalHostSetup {
                executable: &executable,
                installed_host_jar: &jar,
                destination: &destination,
                project,
                scope,
            };
            if let Some(expected_revision) = calibration_revision {
                let deadline = started + Duration::from_secs(15);
                let (setup, record, scope_digest) =
                    register_local_host_setup_with_calibration_scope(
                        StoreConfig::new(root),
                        request,
                        &expected_revision,
                        read_policy.as_ref(),
                        deadline,
                    )
                    .map_err(EntryError::ReadPolicySetup)?;
                let confirmation = json!({"kind":"host_setup_registered","projectId":setup.project_id,
                    "executableSha256":setup.executable_sha256,"hostArtifactDigest":setup.host_artifact_digest,
                    "scopeDigest":scope_digest,"expectedProjectRevision":expected_revision,
                    "readPolicyDigest":record.as_ref().map(HostReadPolicyRecord::policy_digest)});
                let delivered = if let Some(record) = record {
                    deliver_host_read_policy(record, || output(&confirmation, deadline))
                } else {
                    output(&confirmation, deadline)
                };
                delivered.map_err(|delivery| EntryError::HostSetupCommitted {
                    project: setup.project_id,
                    scope_digest,
                    delivery: Box::new(delivery),
                })?;
            } else if let Some(policy) = read_policy {
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
        Command::CompatibilityProfileApprove { root, selection } => {
            let budget =
                RequestBudget::until(started + SOURCE_IMPORT, Arc::new(AtomicBool::new(false)))
                    .map_err(EntryError::SourceRequest)?;
            let record =
                approve_compatibility_profile(StoreConfig::new(root), &selection, &budget)?;
            deliver_compatibility_profile(
                record,
                &selection.expected_project_revision,
                &budget,
                |value, deadline| {
                    output_with_limit(value, deadline, MAX_OUTPUT, budget.cancellation())
                },
            )?;
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

fn parse_manual_import(args: &[String]) -> Result<Command, EntryError> {
    if args.len() < 21
        || args.len() > 531
        || args.iter().any(|arg| arg.len() > 4096)
        || args
            .iter()
            .try_fold(0usize, |size, arg| size.checked_add(arg.len()))
            .is_none_or(|size| size > 65_536)
    {
        return Err(EntryError::ManualArguments);
    }
    let mut options = std::collections::BTreeMap::new();
    let mut deltas = Vec::new();
    for pair in args[1..].chunks(2) {
        if pair.len() != 2 {
            return Err(EntryError::ManualArguments);
        }
        if pair[0] == "--allow-delta" {
            if deltas.len() >= 256 {
                return Err(EntryError::ManualArguments);
            }
            let values = pair[1].split(',').collect::<Vec<_>>();
            if values.len() != 3 {
                return Err(EntryError::ManualArguments);
            }
            deltas.push(json!({"kind":values[0],"instanceId":values[1],"nodeId":values[2]}));
        } else if !matches!(
            pair[0].as_str(),
            "--data-root"
                | "--project"
                | "--expected-revision"
                | "--context"
                | "--selection-resource"
                | "--source-map-file"
                | "--source-map-resource"
                | "--edit-payload-file"
                | "--edit-payload-resource"
        ) || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err(EntryError::ManualArguments);
        }
    }
    let mut take = |key| options.remove(key).ok_or(EntryError::ManualArguments);
    let root = PathBuf::from(take("--data-root")?);
    if !root.is_absolute() {
        return Err(EntryError::ManualArguments);
    }
    let map = selected_path(take("--source-map-file")?, InputRole::Document)
        .map_err(|_| EntryError::ManualArguments)?;
    let payload = selected_path(take("--edit-payload-file")?, InputRole::Document)
        .map_err(|_| EntryError::ManualArguments)?;
    let selection = crate::native_manual_exchange::NativeManualSelection::from_frame(&json!({
        "projectId":take("--project")?,"expectedRevision":take("--expected-revision")?,"contextId":take("--context")?,
        "selectionResourceId":take("--selection-resource")?,"sourceMapResourceId":take("--source-map-resource")?,"editPayloadResourceId":take("--edit-payload-resource")?,
        "sourceMapFile":map,"editPayloadFile":payload,"allowedDeltas":deltas,
    })).map_err(|_| EntryError::ManualArguments)?;
    Ok(Command::ManualImport { root, selection })
}
fn parse(args: &[String]) -> Result<Option<Command>, EntryError> {
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(None);
    };
    if command == "manual-import" {
        return parse_manual_import(args).map(Some);
    }
    if command == daemon_launch::DAEMON_CHILD_COMMAND {
        return Ok(Some(Command::Owned(args[1..].to_vec())));
    }
    if command == "host-bridge" {
        return if args.len() == 2
            && matches!(args[1].as_str(), "--stdio-bootstrap" | "--stdio-approval")
        {
            Ok(Some(Command::HostBridge {
                approval: args[1] == "--stdio-approval",
            }))
        } else {
            Err(EntryError::Arguments)
        };
    }
    if !matches!(
        command,
        "init"
            | "daemon"
            | "start"
            | "host-setup"
            | "source-import"
            | "catalog-source-use"
            | "compatibility-profile-approve"
            | "calibration-approve"
            | "calibration-plan"
            | "calibration-bootstrap-plan"
    ) {
        return Ok(None);
    }
    if matches!(
        command,
        "calibration-approve" | "calibration-plan" | "calibration-bootstrap-plan"
    ) && (args.len() != 9 || args.iter().any(|arg| arg.len() > 4096))
    {
        return Err(EntryError::Arguments);
    }
    // Eight required selector pairs are the complete cold approval surface.
    // Bound the argument collection before cloning or parsing any selector.
    if command == "compatibility-profile-approve"
        && (args.len() != 17 || args.iter().any(|arg| arg.len() > 65_536))
    {
        return Err(EntryError::CompatibilityProfileArguments);
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
    let mut calibration_bootstrap_scope = false;
    let mut index = 1;
    while index < args.len() {
        if command == "host-setup" && args[index] == "--calibration-bootstrap-scope" {
            if calibration_bootstrap_scope {
                return Err(EntryError::Arguments);
            }
            calibration_bootstrap_scope = true;
            index += 1;
            continue;
        }
        let pair = args.get(index..index + 2).ok_or(EntryError::Arguments)?;
        index += 2;
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
        "calibration-plan" | "calibration-bootstrap-plan" => Command::CalibrationPlan {
            root,
            bootstrap: command == "calibration-bootstrap-plan",
            selection: mmmm_application::SetupSelection {
                project_id: ProjectId::new(
                    options.remove("--project").ok_or(EntryError::Arguments)?,
                )
                .map_err(|_| EntryError::Arguments)?,
                expected_revision: Sha256Digest::new(
                    options
                        .remove("--expected-revision")
                        .ok_or(EntryError::Arguments)?,
                )
                .map_err(|_| EntryError::Arguments)?,
                context_id: ContextId::new(
                    options.remove("--context").ok_or(EntryError::Arguments)?,
                )
                .map_err(|_| EntryError::Arguments)?,
            },
        },
        "calibration-approve" => Command::CalibrationApprove {
            root,
            project: ProjectId::new(options.remove("--project").ok_or(EntryError::Arguments)?)
                .map_err(|_| EntryError::Arguments)?,
            plan: PlanId::new(options.remove("--plan-id").ok_or(EntryError::Arguments)?)
                .map_err(|_| EntryError::Arguments)?,
            hash: Sha256Digest::new(options.remove("--plan-hash").ok_or(EntryError::Arguments)?)
                .map_err(|_| EntryError::Arguments)?,
        },
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
            let calibration_revision = match (
                calibration_bootstrap_scope,
                options.remove("--expected-revision"),
            ) {
                (true, Some(revision)) => {
                    Some(Sha256Digest::new(revision).map_err(|_| EntryError::Arguments)?)
                }
                (false, None) => None,
                _ => return Err(EntryError::Arguments),
            };
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
            if calibration_revision.is_some() {
                validate_calibration_base_scope(&scope, &project)
                    .map_err(|_| EntryError::Arguments)?;
            }
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
                calibration_revision,
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
        "compatibility-profile-approve" => {
            let invalid = || EntryError::CompatibilityProfileArguments;
            let project_id = ProjectId::new(options.remove("--project").ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
            let expected_project_revision =
                Sha256Digest::new(options.remove("--expected-revision").ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            let profile_resource_id = ResourceId::new(
                options
                    .remove("--profile-resource-id")
                    .ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?;
            let profile_resource_sha256 = Sha256Digest::new(
                options
                    .remove("--profile-resource-sha256")
                    .ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?;
            let approved_profile_ref = options
                .remove("--approved-profile-ref")
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= 256
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
                })
                .ok_or_else(invalid)?
                .to_owned();
            let artifact_digest =
                Sha256Digest::new(options.remove("--artifact-sha256").ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            let allowed_interface_digest =
                Sha256Digest::new(options.remove("--interface-sha256").ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            Command::CompatibilityProfileApprove {
                root,
                selection: NativeCompatibilityApprovalSelection {
                    project_id,
                    expected_project_revision,
                    profile_resource_id,
                    profile_resource_sha256,
                    approved_profile_ref,
                    artifact_digest,
                    allowed_interface_digest,
                },
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

/// Open the existing protected ledger once. This cold owner operation publishes
/// no listener, host context or Apply grant and never creates an empty Store.
fn approve_compatibility_profile(
    config: StoreConfig,
    selection: &NativeCompatibilityApprovalSelection,
    budget: &RequestBudget,
) -> Result<CompatibilityApprovalRecord, EntryError> {
    budget.check().map_err(EntryError::SourceRequest)?;
    let mut store = DurableStore::open_existing(config).map_err(compatibility_storage_error)?;
    let owner = NativeOwnerWitness::capture(&store, budget.deadline())
        .map_err(compatibility_storage_error)?;
    owner
        .check_project(&store, &selection.project_id)
        .map_err(compatibility_storage_error)?;
    budget.check().map_err(EntryError::SourceRequest)?;
    // The shared approval composition owns current Policy, exact CAS/raw and
    // projected profile pins, source rights and the journal's pre-commit checks.
    // Do not perform a fallible check after its confirmed committed receipt.
    approve_native_compatibility_profile(&mut store, &owner, budget, selection)
        .map_err(EntryError::CompatibilityProfileRequest)
}

fn compatibility_storage_error(cause: StorageError) -> EntryError {
    let code = match &cause {
        StorageError::Busy => "SOURCE_BUSY",
        StorageError::Fenced(_) => "WRITE_SCOPE_FENCED",
        StorageError::Conflict(_) => "REVISION_CONFLICT",
        StorageError::Corrupt(_) => "INVALID_STORED_EVIDENCE",
        StorageError::InvalidInput(_) | StorageError::Contract(_) => "INVALID_INPUT",
        _ => "SOURCE_UNAVAILABLE",
    };
    EntryError::CompatibilityProfileRequest(mmmm_application::AppError::caused_by(
        code,
        "Native compatibility approval could not verify its protected Store",
        cause,
    ))
}

fn compatibility_profile_value(
    record: &CompatibilityApprovalRecord,
    revision: &Sha256Digest,
) -> Value {
    // Publish typed locators and digests only. The full source, native owner,
    // actual Policy, source rights and data-root path remain in protected state.
    json!({"kind":"compatibility_profile_approved","projectId":record.project_id(),
        "currentProjectRevision":revision,"approvedProfileRef":record.approved_profile_ref(),
        "profileResourceId":record.profile_resource()["resourceId"],
        "profileResourceSha256":record.profile_resource()["sha256"],
        "profileDigest":record.profile_digest(),"artifactSha256":record.artifact_digest(),
        "interfaceSha256":record.allowed_interface_digest(),"policyDigest":record.policy_revision(),
        "scopeDigest":record.scope_digest(),"localUseOnly":record.local_use_only()})
}

fn deliver_compatibility_profile(
    record: CompatibilityApprovalRecord,
    revision: &Sha256Digest,
    budget: &RequestBudget,
    deliver: impl FnOnce(&Value, Instant) -> Result<(), EntryError>,
) -> Result<(), EntryError> {
    let result = budget
        .check()
        .map_err(EntryError::SourceRequest)
        .and_then(|()| {
            deliver(
                &compatibility_profile_value(&record, revision),
                budget.deadline(),
            )
        })
        .and_then(|()| budget.check().map_err(EntryError::SourceRequest));
    result.map_err(|delivery| EntryError::CompatibilityProfileCommitted {
        record: Box::new(record),
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
    fn manual_import_accepts_only_explicit_static_files_and_delta_selectors() {
        // This parser-only check opens no files. Use the already selected plain
        // absolute locator; a managed temp root may have a Windows verbatim
        // prefix, which the real file-selection boundary intentionally rejects.
        let map = Path::new(root()).join("mmmm-manual-map.json");
        let payload = Path::new(root()).join("mmmm-manual-patch.json");
        let hash = "a".repeat(64);
        let input = args(&[
            "manual-import",
            "--data-root",
            root(),
            "--project",
            "project-test",
            "--expected-revision",
            &hash,
            "--context",
            "context-test",
            "--selection-resource",
            "selection-input",
            "--source-map-file",
            map.to_str().unwrap(),
            "--source-map-resource",
            "manual-map",
            "--edit-payload-file",
            payload.to_str().unwrap(),
            "--edit-payload-resource",
            "manual-patch",
            "--allow-delta",
            "update_transform,instance-test,node-test",
        ]);
        assert!(matches!(
            parse(&input),
            Ok(Some(Command::ManualImport { .. }))
        ));
        for rejected in [
            "attach_clip,instance-test,node-test",
            "update_transform,instance-test",
            "update_transform,instance-test,node-test,extra",
        ] {
            let mut changed = input.clone();
            *changed.last_mut().unwrap() = rejected.to_owned();
            assert!(matches!(parse(&changed), Err(EntryError::ManualArguments)));
        }
        let mut duplicate = input.clone();
        duplicate.extend(args(&[
            "--allow-delta",
            "update_transform,instance-test,node-test",
        ]));
        assert!(matches!(
            parse(&duplicate),
            Err(EntryError::ManualArguments)
        ));
        let mut injected = input;
        injected.extend(args(&["--rights", "owned"]));
        assert!(matches!(parse(&injected), Err(EntryError::ManualArguments)));
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
            Ok(Some(Command::HostBridge { approval: false }))
        ));
        assert!(matches!(
            parse(&args(&["host-bridge", "--stdio-approval"])),
            Ok(Some(Command::HostBridge { approval: true }))
        ));
        let hash = "a".repeat(64);
        let planning = args(&[
            "calibration-plan",
            "--data-root",
            root(),
            "--project",
            "project-test",
            "--expected-revision",
            &hash,
            "--context",
            "context-test",
        ]);
        assert!(matches!(
            parse(&planning),
            Ok(Some(Command::CalibrationPlan {
                bootstrap: false,
                ..
            }))
        ));
        let mut bootstrap_planning = planning.clone();
        bootstrap_planning[0] = "calibration-bootstrap-plan".into();
        assert!(matches!(
            parse(&bootstrap_planning),
            Ok(Some(Command::CalibrationPlan {
                bootstrap: true,
                ..
            }))
        ));
        for extra in [
            ["--purpose", "numeric_calibration_bootstrap/1"],
            ["--admin", "true"],
        ] {
            let mut forged = bootstrap_planning.clone();
            forged.extend(args(&extra));
            assert!(parse(&forged).is_err());
        }
        for (position, replacement) in [
            (1, "--principal"),
            (3, "--plan-json"),
            (5, "--admin"),
            (7, "--verified-write-profile"),
        ] {
            let mut forged = planning.clone();
            forged[position] = replacement.into();
            assert!(matches!(parse(&forged), Err(EntryError::Arguments)));
        }
        let mut relative_plan = planning.clone();
        relative_plan[2] = "relative".into();
        assert!(matches!(parse(&relative_plan), Err(EntryError::Arguments)));
        let mut duplicate_plan = planning;
        duplicate_plan[7] = "--project".into();
        assert!(matches!(parse(&duplicate_plan), Err(EntryError::Arguments)));
        let mut duplicate_bootstrap = bootstrap_planning;
        duplicate_bootstrap[7] = "--project".into();
        assert!(matches!(
            parse(&duplicate_bootstrap),
            Err(EntryError::Arguments)
        ));
        let calibration = args(&[
            "calibration-approve",
            "--data-root",
            root(),
            "--project",
            "project-test",
            "--plan-id",
            "plan-test",
            "--plan-hash",
            &hash,
        ]);
        assert!(matches!(
            parse(&calibration),
            Ok(Some(Command::CalibrationApprove { .. }))
        ));
        for field in [
            "--principal",
            "--admin",
            "--verified-write-profile",
            "--manifest",
            "--expected-revision",
        ] {
            let mut forged = calibration.clone();
            forged.extend(args(&[field, "true"]));
            assert!(matches!(parse(&forged), Err(EntryError::Arguments)));
        }
        let mut duplicate = calibration.clone();
        duplicate[7] = "--project".into();
        assert!(matches!(parse(&duplicate), Err(EntryError::Arguments)));
        let mut relative = calibration;
        relative[2] = "relative".into();
        assert!(matches!(parse(&relative), Err(EntryError::Arguments)));
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
                calibration_revision: None,
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
        let revision = "a".repeat(64);
        let mut bootstrap = base();
        bootstrap[10] = json!({"projectId":"project-test","resourceIds":[],"objectIds":[],"regions":[],"externalTargetIds":[]}).to_string();
        bootstrap.push("--calibration-bootstrap-scope".into());
        bootstrap.extend(args(&["--expected-revision", &revision]));
        let Some(Command::Setup {
            scope,
            calibration_revision: Some(selected),
            read_policy: None,
            ..
        }) = parse(&bootstrap).unwrap()
        else {
            panic!("explicit bootstrap scope must keep a selected Project revision");
        };
        assert_eq!(selected.as_str(), revision);
        assert_eq!(scope["externalTargetIds"], json!([]));
        for extra in [
            vec!["--calibration-bootstrap-scope"],
            vec!["--calibration-bootstrap-scope", "true"],
            vec!["--expected-revision", &revision],
        ] {
            let mut invalid = bootstrap.clone();
            invalid.extend(args(&extra));
            assert!(parse(&invalid).is_err());
        }
        let mut no_revision = bootstrap.clone();
        no_revision.truncate(no_revision.len() - 2);
        assert!(parse(&no_revision).is_err());
        let mut no_flag = bootstrap.clone();
        no_flag.remove(11);
        assert!(parse(&no_flag).is_err());
        for (field, values) in [
            ("externalTargetIds", json!(["outside-target"])),
            (
                "externalTargetIds",
                json!(["duplicate-target", "duplicate-target"]),
            ),
            (
                "resourceIds",
                json!(["duplicate-resource", "duplicate-resource"]),
            ),
        ] {
            let mut invalid = bootstrap.clone();
            let mut scope: Value = mmmm_contracts::parse_json(invalid[10].as_bytes()).unwrap();
            scope[field] = values;
            invalid[10] = scope.to_string();
            assert!(parse(&invalid).is_err());
        }
        let mut other_command =
            args(&["start", "--data-root", root(), "--project", "project-test"]);
        other_command.push("--calibration-bootstrap-scope".into());
        assert!(parse(&other_command).is_err());
        let error = EntryError::HostSetupCommitted {
            project: ProjectId::new("project-test").unwrap(),
            scope_digest: Sha256Digest::new(revision).unwrap(),
            delivery: Box::new(EntryError::OutputInvalid),
        };
        assert!(error.to_string().contains("committed and retained"));
        assert!(
            std::error::Error::source(&error)
                .unwrap()
                .is::<EntryError>()
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

    fn compatibility_approval_args() -> Vec<String> {
        args(&[
            "compatibility-profile-approve",
            "--data-root",
            root(),
            "--project",
            "project-compatibility",
            "--expected-revision",
            &"a".repeat(64),
            "--profile-resource-id",
            "resource-compatibility-profile",
            "--profile-resource-sha256",
            &"b".repeat(64),
            "--approved-profile-ref",
            "approval:legacy.public.v1",
            "--artifact-sha256",
            &"c".repeat(64),
            "--interface-sha256",
            &"d".repeat(64),
        ])
    }

    #[test]
    fn compatibility_approval_parser_keeps_raw_artifact_interface_and_revision_pins_separate() {
        let Some(Command::CompatibilityProfileApprove {
            root: selected_root,
            selection,
        }) = parse(&compatibility_approval_args()).unwrap()
        else {
            panic!("cold profile selector missing");
        };
        assert_eq!(selected_root, PathBuf::from(root()));
        assert_eq!(selection.project_id.as_str(), "project-compatibility");
        assert_eq!(selection.expected_project_revision.as_str(), "a".repeat(64));
        assert_eq!(
            selection.profile_resource_id.as_str(),
            "resource-compatibility-profile"
        );
        assert_eq!(selection.profile_resource_sha256.as_str(), "b".repeat(64));
        assert_eq!(selection.approved_profile_ref, "approval:legacy.public.v1");
        assert_eq!(selection.artifact_digest.as_str(), "c".repeat(64));
        assert_eq!(selection.allowed_interface_digest.as_str(), "d".repeat(64));
    }

    #[test]
    fn compatibility_approval_parser_rejects_omitted_duplicate_unknown_or_unbounded_selections() {
        for pair in 0..8 {
            let mut omitted = compatibility_approval_args();
            omitted.drain(1 + pair * 2..3 + pair * 2);
            assert!(parse(&omitted).is_err());
        }
        for (index, invalid) in [
            (2, "relative-root"),
            (4, "bad project"),
            (6, "claimed revision"),
            (8, "bad/resource"),
            (10, "claimed digest"),
            (12, ""),
            (12, "approval with space"),
            (12, "approval\nline"),
            (14, "claimed artifact"),
            (16, "claimed interface"),
        ] {
            let mut input = compatibility_approval_args();
            input[index] = invalid.into();
            assert!(parse(&input).is_err());
        }
        for (index, length) in [(12, 257), (2, 65_537)] {
            let mut input = compatibility_approval_args();
            input[index] = "x".repeat(length);
            assert!(parse(&input).is_err());
        }
        for (option, value) in [
            ("--project", "duplicate-project"),
            ("--profile-json", "{}"),
            ("--profile-digest", &"0".repeat(64)),
            ("--native-owner", "claimed-owner"),
            ("--policy-revision", "claimed-policy"),
            ("--scope-json", "{}"),
            ("--approved", "true"),
        ] {
            let mut extra = compatibility_approval_args();
            extra.extend(args(&[option, value]));
            assert!(parse(&extra).is_err());
            // Replacing a required selector must also reject a same-size argv.
            let mut replaced = compatibility_approval_args();
            replaced[7] = option.into();
            replaced[8] = value.into();
            assert!(parse(&replaced).is_err());
        }
        let mut odd = compatibility_approval_args();
        odd.push("--unexpected".into());
        assert!(parse(&odd).is_err());
        assert!(parse(&args(&["--version"])).unwrap().is_none());
    }

    #[test]
    fn compatibility_request_diagnostics_keep_static_code_without_untrusted_causes() {
        let failure =
            EntryError::CompatibilityProfileRequest(mmmm_application::AppError::caused_by(
                "PROFILE_UNTRUSTED",
                "untrusted profile message must stay private",
                std::io::Error::other("private selected path and source bytes"),
            ));
        let public = failure.to_string();
        assert!(public.contains("PROFILE_UNTRUSTED"));
        assert!(!public.contains("untrusted profile message"));
        assert!(!public.contains("private selected path"));
        let retained = std::error::Error::source(&failure).unwrap();
        assert!(retained.is::<mmmm_application::AppError>());
        assert!(
            std::error::Error::source(retained)
                .unwrap()
                .is::<std::io::Error>()
        );
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

    // Reuse the existing protected Store/import fixture and the canonical
    // public-Java example. The scalar-only variation tests the narrower initial
    // read slice; neither variant supplies a Java observation or game evidence.
    fn compatibility_approval_fixture(
        scalar: bool,
    ) -> (
        ImportRoot,
        ProjectBootstrapReceipt,
        NativeOwnedSourceCommitReceipt,
        NativeCompatibilityApprovalSelection,
    ) {
        let root = ImportRoot::new();
        let initialized = root.initialize();
        let mut profile =
            parse_json(include_bytes!("../../../examples/compat-public-java.json")).unwrap();
        let bytes = if scalar {
            profile["binding"]["resultCodec"] = json!("scalar");
            profile["binding"]["returnType"] = json!("java.lang.String");
            profile["action"]["outputSchema"] = json!({"type":"object",
                "properties":{"value":{"type":"string"}},"required":["value"],
                "additionalProperties":false});
            [b" \n".as_slice(), &encode_json(&profile).unwrap(), b"\n "].concat()
        } else {
            include_bytes!("../../../examples/compat-public-java.json").to_vec()
        };
        let resource_id = ResourceId::new("resource-native-compatibility-profile").unwrap();
        let metadata = encode_json(&json!({"resourceId":resource_id,
            "sha256":raw_digest(&bytes),"mediaType":"application/vnd.mmmm.compatibility-profile+json",
            "sizeBytes":bytes.len()})).unwrap();
        let (budget, _) = import_budget();
        let prepared = root.prepare(&initialized.project_id, &budget);
        let receipt = prepared
            .import_native_sources(&NativeSourceInput {
                project: &initialized.project_id,
                expected_revision: &initialized.project_revision,
                documents: &[],
                retained_resources: &[],
                raw_resources: &[NativeRawSourceResource {
                    metadata: &metadata,
                    bytes: &bytes,
                }],
            })
            .unwrap();
        let selection = NativeCompatibilityApprovalSelection {
            project_id: receipt.project_id.clone(),
            expected_project_revision: receipt.project_revision.clone(),
            profile_resource_id: resource_id,
            profile_resource_sha256: raw_digest(&bytes),
            approved_profile_ref: "approval:native.scalar.v1".into(),
            artifact_digest: serde_json::from_value(
                profile["action"]["implementationDigest"].clone(),
            )
            .unwrap(),
            allowed_interface_digest: Sha256Digest::new("d".repeat(64)).unwrap(),
        };
        (root, initialized, receipt, selection)
    }

    fn approve_profile_fixture(
        root: &ImportRoot,
        selection: &NativeCompatibilityApprovalSelection,
    ) -> Result<CompatibilityApprovalRecord, EntryError> {
        let (budget, _) = import_budget();
        approve_compatibility_profile(StoreConfig::new(root.0.clone()), selection, &budget)
    }

    #[test]
    fn cold_compatibility_approval_retains_exact_source_and_replays_only_immutable_pins() {
        let (root, _, receipt, selection) = compatibility_approval_fixture(true);
        let before = root.open().project(&receipt.project_id).unwrap();
        {
            let store = root.open();
            let (budget, _) = import_budget();
            let owner = NativeOwnerWitness::capture(&store, budget.deadline()).unwrap();
            let failure = crate::production_factory::read_native_compatibility_profile(
                &store,
                &owner,
                &budget,
                &selection.project_id,
                &selection.approved_profile_ref,
            );
            assert!(matches!(failure, Err(ref error) if error.code == "PROFILE_UNTRUSTED"));
        }
        let approved = approve_profile_fixture(&root, &selection).unwrap();
        assert_eq!(
            approve_profile_fixture(&root, &selection).unwrap(),
            approved
        );
        assert_eq!(approved.project_id(), &receipt.project_id);
        assert_eq!(
            approved.profile_resource()["resourceId"],
            selection.profile_resource_id.as_str()
        );
        assert_eq!(
            approved.profile_resource()["sha256"],
            selection.profile_resource_sha256.as_str()
        );
        assert_ne!(
            approved.profile_digest(),
            &selection.profile_resource_sha256
        );
        assert!(approved.local_use_only());
        let mut changed = selection.clone();
        changed.allowed_interface_digest = Sha256Digest::new("e".repeat(64)).unwrap();
        assert!(approve_profile_fixture(&root, &changed).is_err());
        assert_eq!(
            approve_profile_fixture(&root, &selection).unwrap(),
            approved
        );
        assert_eq!(root.open().project(&receipt.project_id).unwrap(), before);
        {
            let store = root.open();
            let (budget, _) = import_budget();
            let owner = NativeOwnerWitness::capture(&store, budget.deadline()).unwrap();
            let actual = crate::production_factory::read_native_compatibility_profile(
                &store,
                &owner,
                &budget,
                &selection.project_id,
                &selection.approved_profile_ref,
            )
            .unwrap();
            assert_eq!(actual.record(), &approved);
            assert_eq!(
                raw_digest(actual.profile_bytes()),
                selection.profile_resource_sha256
            );
            assert_eq!(
                projected_digest(
                    "CompatibilityProfile",
                    &parse_json(actual.profile_bytes()).unwrap()
                )
                .unwrap(),
                *approved.profile_digest()
            );
        }
        let value = compatibility_profile_value(&approved, &receipt.project_revision);
        assert_eq!(value["profileDigest"], approved.profile_digest().as_str());
        for excluded in [
            "nativeOwner",
            "policy",
            "profile",
            "dataRoot",
            "sourceRights",
        ] {
            assert!(value.get(excluded).is_none());
        }
        assert!(!root.0.join("runtime").exists());
    }

    #[test]
    fn cold_compatibility_approval_requires_existing_unlocked_current_project_and_raw_source() {
        let (root, initialized, receipt, selection) = compatibility_approval_fixture(true);
        let held = root.open();
        let failure = approve_profile_fixture(&root, &selection).unwrap_err();
        assert!(
            matches!(failure, EntryError::CompatibilityProfileRequest(ref error)
            if error.code == "SOURCE_BUSY"
                && matches!(std::error::Error::source(error)
                    .and_then(|cause| cause.downcast_ref::<StorageError>()), Some(StorageError::Busy)))
        );
        drop(held);
        for replacement in [
            initialized.project_revision,
            Sha256Digest::new("f".repeat(64)).unwrap(),
        ] {
            let mut stale = selection.clone();
            stale.expected_project_revision = replacement;
            assert!(approve_profile_fixture(&root, &stale).is_err());
        }
        let mut wrong_raw = selection.clone();
        wrong_raw.profile_resource_sha256 = Sha256Digest::new("0".repeat(64)).unwrap();
        assert!(approve_profile_fixture(&root, &wrong_raw).is_err());
        let mut wrong_project = selection.clone();
        wrong_project.project_id = ProjectId::new("project-unregistered-compatibility").unwrap();
        assert!(approve_profile_fixture(&root, &wrong_project).is_err());
        let mut missing_resource = selection.clone();
        missing_resource.profile_resource_id =
            ResourceId::new("resource-unregistered-profile").unwrap();
        assert!(approve_profile_fixture(&root, &missing_resource).is_err());
        let absent = ImportRoot::new();
        assert!(approve_profile_fixture(&absent, &selection).is_err());
        assert!(!absent.0.join("journal.sqlite3").exists());
        assert!(!absent.0.join("blobs").exists());
        assert!(!absent.0.join("runtime").exists());
        let approved = approve_profile_fixture(&root, &selection).unwrap();
        assert_eq!(approved.project_id(), &receipt.project_id);
        assert!(!root.0.join("runtime").exists());
    }

    #[test]
    fn cold_compatibility_approval_rejects_original_map_codec_and_preserves_cancellation() {
        let (unsupported, _, _, selection) = compatibility_approval_fixture(false);
        assert!(matches!(approve_profile_fixture(&unsupported, &selection),
            Err(EntryError::CompatibilityProfileRequest(ref error))
                if error.code == "CAPABILITY_UNAVAILABLE"));
        let (root, _, _, selection) = compatibility_approval_fixture(true);
        let (budget, cancellation) = import_budget();
        cancellation.store(true, Ordering::Release);
        let failure =
            approve_compatibility_profile(StoreConfig::new(root.0.clone()), &selection, &budget)
                .unwrap_err();
        assert!(matches!(failure, EntryError::SourceRequest(ref error)
            if error.code == "CANCELLED"));
        let expired = RequestBudget::until(
            Instant::now() + Duration::from_millis(50),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(60));
        let failure =
            approve_compatibility_profile(StoreConfig::new(root.0.clone()), &selection, &expired)
                .unwrap_err();
        assert!(matches!(failure, EntryError::SourceRequest(ref error)
            if error.code == "TIME_BUDGET_EXCEEDED"));
        assert!(!root.0.join("runtime").exists());
        assert!(approve_profile_fixture(&root, &selection).is_ok());
    }

    #[test]
    fn confirmed_compatibility_approval_survives_delivery_failure_or_later_cancellation() {
        for phase in 0..3 {
            let (root, _, receipt, selection) = compatibility_approval_fixture(true);
            let approved = approve_profile_fixture(&root, &selection).unwrap();
            let (budget, cancellation) = import_budget();
            if phase == 1 {
                cancellation.store(true, Ordering::Release);
            }
            let failure = deliver_compatibility_profile(
                approved.clone(),
                &receipt.project_revision,
                &budget,
                |value, _| {
                    assert_eq!(value["kind"], "compatibility_profile_approved");
                    if phase == 2 {
                        cancellation.store(true, Ordering::Release);
                        Ok(())
                    } else {
                        Err(EntryError::OutputInvalid)
                    }
                },
            )
            .unwrap_err();
            let EntryError::CompatibilityProfileCommitted { record, delivery } = failure else {
                panic!("confirmed compatibility approval receipt lost");
            };
            assert_eq!(*record, approved);
            if phase == 0 {
                assert!(matches!(*delivery, EntryError::OutputInvalid));
            } else {
                assert!(matches!(*delivery, EntryError::SourceRequest(ref error)
                if error.code == "CANCELLED"));
            }
            assert_eq!(
                approve_profile_fixture(&root, &selection).unwrap(),
                approved
            );
            let diagnostic =
                EntryError::CompatibilityProfileCommitted { record, delivery }.to_string();
            assert!(diagnostic.contains("committed and retained"));
            assert!(diagnostic.contains(approved.profile_digest().as_str()));
            assert!(!root.0.join("runtime").exists());
        }
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

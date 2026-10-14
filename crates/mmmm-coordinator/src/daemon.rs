//! One concrete service composition, shared by the foreground daemon and its
//! privately launched native owner. Source/profile factories are installed in
//! process; this module accepts no wire authority or readiness assertions.

use crate::{
    artifacts::ArtifactExtension,
    authority::LocalAuthority,
    bootstrap::HostBootstrapProcessor,
    features::{FEATURE_METHODS, FeatureExtension, FeatureSources},
    host::HostBridge,
    lifecycle::{Coordinator, CoordinatorError},
    native_source_ingress::{NativeSourceInput, prepare_native_sources},
    planning_source::{
        PlanningComposition, SharedPlanningBackend, SharedPlanningContexts, SharedPlanningData,
        SharedPlanningDependencies, StoreAwarePlanner,
    },
    service::{
        ApplicationPorts, ApplicationService, ExtensionRouter, RequestBudget, RequestContextSlot,
        ServiceError,
    },
    workspace_bootstrap::{WorkspaceBootstrap, prepare_workspace},
};
use mmmm_application::{
    Access, AppError, AppResult, AuthorityPort, IdKind, IdSource, IndependentObserverPort,
    ProviderPort, SystemClock,
};
use mmmm_contracts::{PrincipalId, ProjectId, TargetProfileId};
use mmmm_planner::PlannerOptions;
use mmmm_runtime::{
    artifact::ResourceAuthority,
    storage::{
        DurableStore, OperationRecord, StoreConfig,
        native_owned_sources::NativeOwnedSourceCommitReceipt,
    },
};
use serde_json::Value;
use std::time::{Duration, Instant};

/// The same live handles are supplied to every source/target adapter. A factory
/// must install actual runtime/source evidence; a target locator does not create
/// a VerifiedTarget, redistribution permission, or independent readback.
#[derive(Clone)]
pub struct DaemonHandles {
    pub hosts: HostBridge,
    pub authority: LocalAuthority,
    pub request: RequestContextSlot,
    /// Explicit daemon setup locator, checked against the protected Store.
    /// Per-call sources still require current principal/project authority.
    pub configured_project: Option<ProjectId>,
    /// A native same-store owner witness and exact verified read context.
    /// A factory registers it in its sole shared private context locator.
    pub workspace: Option<WorkspaceBootstrap>,
}

pub struct DaemonSourceParts {
    pub contexts: SharedPlanningContexts,
    pub data: SharedPlanningData,
    pub backend: SharedPlanningBackend,
    pub dependencies: SharedPlanningDependencies,
    pub features: Box<dyn FeatureSources>,
    /// The feature receipt authority is constructed before features are moved;
    /// it shares their exact issuer generation and delegates retained resources
    /// to the actual current resource/operation authority.
    pub artifacts: Box<dyn ResourceAuthority>,
    pub provider: Box<dyn ProviderPort>,
    pub observer: Box<dyn IndependentObserverPort>,
    pub planner_options: PlannerOptions,
}

/// This is an internal Rust composition factory, never a plugin/wire registry.
/// Its provider/observer must use these same hosts, current authority and request
/// slot, and only the short Store borrow provided by Application. No second DB
/// or facade-owned plan/apply implementation is permitted.
pub trait DaemonSourceFactory {
    fn compose(
        &mut self,
        handles: &DaemonHandles,
        store: &DurableStore,
    ) -> Result<DaemonSourceParts, ServiceError>;
}

pub struct PreparedDaemon {
    service: ApplicationService,
    processor: HostBootstrapProcessor,
    handles: DaemonHandles,
    // Only the explicit cold native import constructor installs this original
    // budget. Public source DTOs cannot replace its deadline/cancellation Arc.
    native_source_budget: Option<RequestBudget>,
}

impl PreparedDaemon {
    /// Opens the one protected Store. Its native singleton lock is acquired
    /// before any listener/discovery publication or trusted management request.
    pub fn open(
        config: StoreConfig,
        configured_project: Option<ProjectId>,
        factory: &mut dyn DaemonSourceFactory,
    ) -> Result<Self, DaemonError> {
        if !config.data_root.is_absolute() {
            return Err(DaemonError::Composition(ServiceError::new(
                "UNSAFE_DATA_ROOT",
                "Daemon data root must be an absolute protected local path",
            )));
        }
        // This is the only SQLite/CAS open. A live daemon causes Busy before
        // database open, instead of constructing another application ledger.
        let store = DurableStore::open(config).map_err(DaemonError::Storage)?;
        Self::from_store(store, configured_project, factory)
    }

    /// Explicit cold native authoring retains the original request deadline
    /// through protected Store open, workspace verification and composition.
    /// A live owner returns Busy before another SQLite ledger can be opened.
    pub fn open_for_native_source_import(
        config: StoreConfig,
        project: ProjectId,
        factory: &mut dyn DaemonSourceFactory,
        budget: &RequestBudget,
    ) -> Result<Self, DaemonError> {
        budget.check().map_err(DaemonError::Composition)?;
        if !config.data_root.is_absolute() {
            return Err(DaemonError::Composition(ServiceError::new(
                "UNSAFE_DATA_ROOT",
                "Native source import requires an absolute protected local path",
            )));
        }
        let store = DurableStore::open_existing(config).map_err(DaemonError::Storage)?;
        budget.check().map_err(DaemonError::Composition)?;
        let mut prepared =
            Self::from_store_until(store, Some(project), factory, budget.deadline())?;
        budget.check().map_err(DaemonError::Composition)?;
        prepared.native_source_budget = Some(budget.clone());
        Ok(prepared)
    }

    /// The explicit cold-start native init path creates the actual Project and
    /// canonical Policy in this locked Store, then moves that same Store into
    /// the daemon. An active owner returns Busy before a second database opens.
    pub fn initialize(
        config: StoreConfig,
        name: &str,
        target: &TargetProfileId,
        factory: &mut dyn DaemonSourceFactory,
    ) -> Result<
        (
            Self,
            mmmm_runtime::storage::bootstrap::ProjectBootstrapReceipt,
        ),
        DaemonError,
    > {
        if !config.data_root.is_absolute() {
            return Err(DaemonError::Composition(ServiceError::new(
                "UNSAFE_DATA_ROOT",
                "Daemon data root must be an absolute protected local path",
            )));
        }
        let mut store = DurableStore::open(config).map_err(DaemonError::Storage)?;
        let receipt = crate::native_project::create_native_project(
            &mut store,
            name,
            target,
            Instant::now() + Duration::from_secs(30),
        )
        .map_err(DaemonError::Storage)?;
        let prepared = Self::from_store(store, Some(receipt.project_id.clone()), factory).map_err(
            |source| DaemonError::AfterInitialization {
                project: receipt.project_id.clone(),
                revision: receipt.project_revision.clone(),
                source: Box::new(source),
            },
        )?;
        Ok((prepared, receipt))
    }

    /// Trusted native management transfers ownership of the already protected
    /// Store; it does not reopen SQLite, issue a facade-owned journal or infer a
    /// configured Project from a request DTO.
    pub fn from_store(
        store: DurableStore,
        configured_project: Option<ProjectId>,
        factory: &mut dyn DaemonSourceFactory,
    ) -> Result<Self, DaemonError> {
        Self::from_store_until(
            store,
            configured_project,
            factory,
            Instant::now() + Duration::from_secs(30),
        )
    }

    fn from_store_until(
        store: DurableStore,
        configured_project: Option<ProjectId>,
        factory: &mut dyn DaemonSourceFactory,
        deadline: Instant,
    ) -> Result<Self, DaemonError> {
        composition_deadline(deadline)?;
        if let Some(project) = &configured_project {
            store.project(project).map_err(DaemonError::Storage)?;
        }
        let hosts = HostBridge::default();
        let authority = LocalAuthority::new(hosts.clone());
        let request = RequestContextSlot::default();
        let workspace = configured_project
            .as_ref()
            .map(|project| prepare_workspace(&store, &authority, project, deadline))
            .transpose()
            .map_err(DaemonError::Storage)?;
        let handles = DaemonHandles {
            hosts,
            authority,
            request,
            configured_project,
            workspace,
        };
        let parts = factory
            .compose(&handles, &store)
            .map_err(DaemonError::Composition)?;
        composition_deadline(deadline)?;
        let planner = StoreAwarePlanner::new(PlanningComposition {
            request: Box::new(handles.request.clone()),
            authority: handles.authority.clone(),
            hosts: handles.hosts.clone(),
            contexts: parts.contexts,
            data: parts.data,
            backend: parts.backend,
            dependencies: parts.dependencies,
            clock: Box::new(SystemClock),
            options: parts.planner_options,
        })
        .map_err(DaemonError::Application)?;
        let ports = ApplicationPorts {
            authority: Box::new(RequestAuthority {
                current: handles.authority.clone(),
                request: handles.request.clone(),
            }),
            planner: Box::new(planner),
            provider: parts.provider,
            observer: parts.observer,
            ids: Box::new(RandomIds),
            clock: Box::new(SystemClock),
        };
        let mut extensions = ExtensionRouter::default();
        extensions
            .register(
                ["artifact.read"],
                Box::new(
                    ArtifactExtension::new(parts.artifacts, 256 * 1024 * 1024).map_err(
                        |error| {
                            DaemonError::Composition(ServiceError::new(error.code, error.message))
                        },
                    )?,
                ),
            )
            .map_err(DaemonError::Composition)?;
        extensions
            .register(
                FEATURE_METHODS,
                Box::new(
                    FeatureExtension::new(parts.features, handles.hosts.clone())
                        .map_err(DaemonError::Composition)?,
                ),
            )
            .map_err(DaemonError::Composition)?;
        let mut service = ApplicationService::from_store(store, ports);
        service.bind_request_context(handles.request.clone());
        service
            .bind_undo_execution(handles.authority.clone(), handles.hosts.clone())
            .map_err(DaemonError::Composition)?;
        service.set_extensions(extensions);
        let mut processor =
            HostBootstrapProcessor::new(handles.hosts.clone(), handles.authority.clone()).map_err(
                |_| {
                    DaemonError::Composition(ServiceError::new(
                        "LOCAL_OWNER_UNAVAILABLE",
                        "Current native local owner cannot be authenticated",
                    ))
                },
            )?;
        if let Some(workspace) = &handles.workspace {
            processor.install_workspace_context(&workspace.witness, service.management_store(), &workspace.context)
                .map_err(|_| DaemonError::Composition(ServiceError::new("WORKSPACE_UNAVAILABLE", "Verified native workspace could not be installed in the current session policy")))?;
        }
        composition_deadline(deadline)?;
        Ok(Self {
            service,
            processor,
            handles,
            native_source_budget: None,
        })
    }

    /// Consumes the sole protected Store composition without starting a
    /// listener. No stale workspace or newly generated budget can be reused
    /// after the one atomic source/head commit. The receipt describes facts,
    /// not a source, game, world or Apply grant.
    pub fn import_native_sources(
        mut self,
        input: &NativeSourceInput<'_>,
    ) -> Result<NativeOwnedSourceCommitReceipt, DaemonError> {
        let budget = self
            .native_source_budget
            .as_ref()
            .ok_or_else(|| {
                DaemonError::Composition(ServiceError::new(
                    "SOURCE_IMPORT_UNAVAILABLE",
                    "Native source import requires its original cold request composition",
                ))
            })?
            .clone();
        budget.check().map_err(DaemonError::Composition)?;
        let workspace = self.handles.workspace.as_ref().ok_or_else(|| {
            DaemonError::Composition(ServiceError::new(
                "WORKSPACE_UNAVAILABLE",
                "Native source import requires its verified selected workspace",
            ))
        })?;
        if self.handles.configured_project.as_ref() != Some(input.project)
            || &workspace.project_revision != input.expected_revision
        {
            return Err(DaemonError::Composition(ServiceError::new(
                "PLAN_STALE",
                "Native source import Project or expected revision differs from its workspace",
            )));
        }
        let owner = workspace.witness.clone();
        let authority = self.handles.authority.clone();
        let store = self.service.management_store();
        let prepared = prepare_native_sources(store, &owner, &authority, &budget, input)
            .map_err(DaemonError::Application)?;
        // commit() preserves a completed SQLite receipt even if cancellation
        // arrives immediately afterwards. Entry delivery handles that separately.
        prepared.commit(store).map_err(DaemonError::Application)
    }

    pub fn handles(&self) -> &DaemonHandles {
        &self.handles
    }

    /// Ownership bootstrap must call this before emitting its READY receipt;
    /// the returned Coordinator then owns the locked Store and native listeners.
    pub fn start(self) -> Result<Coordinator, DaemonError> {
        if self.native_source_budget.is_some() {
            return Err(DaemonError::Composition(ServiceError::new(
                "SOURCE_IMPORT_ONLY",
                "Native source import composition cannot publish a listener",
            )));
        }
        Coordinator::start_with_bootstrap(self.service, self.processor)
            .map_err(DaemonError::Coordinator)
    }
}

fn composition_deadline(deadline: Instant) -> Result<(), DaemonError> {
    if Instant::now() >= deadline {
        return Err(DaemonError::Composition(ServiceError::new(
            "TIME_BUDGET_EXCEEDED",
            "Native daemon composition deadline reached",
        )));
    }
    Ok(())
}

struct RandomIds;
impl IdSource for RandomIds {
    fn next_id(&mut self, kind: IdKind) -> AppResult<String> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| {
            AppError::new(
                "ID_UNAVAILABLE",
                "A durable request identity cannot be generated",
            )
        })?;
        let prefix = match kind {
            IdKind::Plan => "plan",
            IdKind::Operation => "operation",
            IdKind::Invocation => "invocation",
        };
        let suffix: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(format!("{prefix}-{suffix}"))
    }
}

/// Application authorizes against the actual service request's absolute budget.
/// No JSON PrincipalId/context/policy can fill the private request slot.
struct RequestAuthority {
    current: LocalAuthority,
    request: RequestContextSlot,
}
impl RequestAuthority {
    fn check(&self, principal: &PrincipalId) -> AppResult<crate::service::RequestBudget> {
        let (authenticated, budget) = self
            .request
            .current()
            .map_err(|error| AppError::new(error.code, error.message))?;
        if authenticated.principal() != principal {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Application principal differs from its current authenticated request",
            ));
        }
        Ok(budget)
    }
}
impl AuthorityPort for RequestAuthority {
    fn authorize(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectId,
        access: Access,
        context: Option<&Value>,
        plan: Option<&Value>,
    ) -> AppResult<()> {
        let budget = self.check(principal)?;
        self.current.authorize_with_deadline(
            principal,
            project,
            access,
            context,
            plan,
            budget.deadline(),
        )?;
        budget
            .check()
            .map_err(|error| AppError::new(error.code, error.message))
    }
    fn authorize_operation(
        &mut self,
        principal: &PrincipalId,
        operation: &OperationRecord,
        access: Access,
    ) -> AppResult<()> {
        let budget = self.check(principal)?;
        self.current
            .authorize_operation(principal, operation, access)?;
        budget
            .check()
            .map_err(|error| AppError::new(error.code, error.message))
    }
}

#[derive(Debug)]
pub enum DaemonError {
    Composition(ServiceError),
    Application(AppError),
    Storage(mmmm_runtime::storage::StorageError),
    Coordinator(CoordinatorError),
    /// Project and Policy are already committed. Preserve their exact public
    /// locator if later service composition fails; no implicit create retry.
    AfterInitialization {
        project: ProjectId,
        revision: mmmm_contracts::Sha256Digest,
        source: Box<DaemonError>,
    },
}
impl std::fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Native paths and caller DTOs are not public diagnostics.
        match self {
            Self::Composition(error) => error.fmt(formatter),
            Self::Application(error) => write!(formatter, "{}: {}", error.code, error.message),
            Self::Storage(mmmm_runtime::storage::StorageError::Busy) => {
                formatter.write_str("Daemon protected durable Store is already owned (Busy)")
            }
            Self::Storage(_) => {
                formatter.write_str("Daemon protected durable store could not be opened")
            }
            Self::Coordinator(error) => error.fmt(formatter),
            Self::AfterInitialization {
                project,
                revision,
                source,
            } => write!(
                formatter,
                "Project {project} at revision {revision} was initialized and retained; daemon composition failed: {source}"
            ),
        }
    }
}
impl std::error::Error for DaemonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Composition(error) => Some(error),
            Self::Application(error) => Some(error),
            Self::Storage(error) => Some(error),
            Self::Coordinator(error) => Some(error),
            Self::AfterInitialization { source, .. } => Some(source.as_ref()),
        }
    }
}

use crate::auth::AuthenticatedPrincipal;
use mmmm_application::{
    Application, AuthorityPort, Clock, IdSource, IndependentObserverPort, PlanningPort,
    ProviderPort,
};
use mmmm_runtime::storage::{DurableStore, StorageError, StoreConfig};
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::BTreeSet,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct ServiceError {
    pub code: &'static str,
    pub message: &'static str,
    // Internal diagnostic causes are never included in the public RPC body.
    // Authority/session witnesses are not Send + Sync and cannot enter here.
    source: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

/// Trusted composition shares this slot with store-aware ports. Public request
/// values cannot populate it; the authenticated service call owns its lifetime.
#[derive(Clone, Default)]
pub struct RequestContextSlot {
    state: Rc<RefCell<Option<OccupiedRequest>>>,
}
struct OccupiedRequest {
    principal: AuthenticatedPrincipal,
    budget: RequestBudget,
    method: Box<str>,
    generation: Rc<()>,
}
/// An in-process witness for one exact service call. A session capability or a
/// copied budget cannot recreate its private per-enter generation. Checkpoints
/// inspect only local state and never perform host/native or storage I/O.
#[derive(Clone)]
pub struct RequestContextWitness {
    slot: RequestContextSlot,
    principal: AuthenticatedPrincipal,
    budget: RequestBudget,
    method: Box<str>,
    generation: Rc<()>,
}
impl RequestContextWitness {
    pub fn authenticated(&self) -> &AuthenticatedPrincipal {
        &self.principal
    }
    pub fn budget(&self) -> &RequestBudget {
        &self.budget
    }
    pub fn method(&self) -> &str {
        &self.method
    }
    pub fn check_local(&self) -> Result<(), ServiceError> {
        let occupied = self.slot.state.try_borrow().map_err(|_| {
            ServiceError::new("REQUEST_BUSY", "Authenticated request context is in use")
        })?;
        let current = occupied.as_ref().ok_or_else(request_retired)?;
        if !Rc::ptr_eq(&current.generation, &self.generation)
            || current.method != self.method
            || !current.principal.same_session(&self.principal)
            || current.budget.deadline() != self.budget.deadline()
            || !std::ptr::eq(current.budget.cancellation(), self.budget.cancellation())
            || !current.principal.permits(&self.method)
        {
            return Err(request_retired());
        }
        self.budget.check()
    }
}
impl RequestContextSlot {
    pub fn current(&self) -> Result<(AuthenticatedPrincipal, RequestBudget), ServiceError> {
        self.snapshot(true)
    }
    /// Historical interruption finalization only: observe the actual still-live
    /// request identity without extending or clearing its cancelled/expired
    /// budget. This grants no source/host I/O; retained full-scope ACL checks are
    /// still required before publishing previously acquired partial evidence.
    pub fn current_retained(
        &self,
    ) -> Result<(AuthenticatedPrincipal, RequestBudget), ServiceError> {
        self.snapshot(false)
    }
    /// The requested method must be the actual occupied dispatcher method.
    /// This creates no authority and cannot be deserialized from a request.
    pub fn current_witness(&self, method: &str) -> Result<RequestContextWitness, ServiceError> {
        let witness = self.occupied_witness()?;
        if witness.method() != method {
            return Err(request_retired());
        }
        Ok(witness)
    }
    /// Read the actual dispatcher method and private generation, rather than
    /// accepting a caller-supplied method as an authorization claim.
    pub fn occupied_witness(&self) -> Result<RequestContextWitness, ServiceError> {
        let occupied = self.state.try_borrow().map_err(|_| {
            ServiceError::new("REQUEST_BUSY", "Authenticated request context is in use")
        })?;
        let current = occupied.as_ref().ok_or_else(request_retired)?;
        let witness = RequestContextWitness {
            slot: self.clone(),
            principal: current.principal.clone(),
            budget: current.budget.clone(),
            method: current.method.clone(),
            generation: current.generation.clone(),
        };
        drop(occupied);
        witness.check_local()?;
        Ok(witness)
    }
    fn snapshot(
        &self,
        check_budget: bool,
    ) -> Result<(AuthenticatedPrincipal, RequestBudget), ServiceError> {
        let current = self.state.try_borrow().map_err(|_| {
            ServiceError::new("REQUEST_BUSY", "Authenticated request context is in use")
        })?;
        let occupied = current.as_ref().ok_or_else(|| {
            ServiceError::new(
                "AUTHENTICATION_REQUIRED",
                "No authenticated service call is active",
            )
        })?;
        if check_budget {
            occupied.budget.check()?;
        }
        if !occupied.principal.is_current() {
            return Err(ServiceError::new(
                "PERMISSION_REQUIRED",
                "Authenticated request session is no longer current",
            ));
        }
        Ok((occupied.principal.clone(), occupied.budget.clone()))
    }
    fn enter(
        &self,
        principal: &AuthenticatedPrincipal,
        budget: &RequestBudget,
        method: &str,
    ) -> Result<RequestContextGuard, ServiceError> {
        let mut current = self.state.try_borrow_mut().map_err(|_| {
            ServiceError::new("REQUEST_BUSY", "Authenticated request context is in use")
        })?;
        if current.is_some() {
            return Err(ServiceError::new(
                "REQUEST_BUSY",
                "An authenticated service call is already active",
            ));
        }
        if method.is_empty() || method.len() > 128 || !principal.permits(method) {
            return Err(request_retired());
        }
        budget.check()?;
        let generation = Rc::new(());
        *current = Some(OccupiedRequest {
            principal: principal.clone(),
            budget: budget.clone(),
            method: method.into(),
            generation: generation.clone(),
        });
        Ok(RequestContextGuard {
            slot: self.clone(),
            generation,
        })
    }
}
struct RequestContextGuard {
    slot: RequestContextSlot,
    generation: Rc<()>,
}
impl Drop for RequestContextGuard {
    fn drop(&mut self) {
        // A port cannot keep a public RefCell borrow: current() returns clones.
        // If this invariant is broken internally, retaining the occupied slot
        // denies subsequent calls rather than exposing an earlier principal.
        if let Ok(mut current) = self.slot.state.try_borrow_mut()
            && current
                .as_ref()
                .is_some_and(|occupied| Rc::ptr_eq(&occupied.generation, &self.generation))
        {
            *current = None;
        }
    }
}
fn request_retired() -> ServiceError {
    ServiceError::new(
        "PERMISSION_REQUIRED",
        "The original authenticated service call is no longer current",
    )
}
impl ServiceError {
    pub fn new(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            source: None,
        }
    }
    pub fn caused_by(
        code: &'static str,
        message: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            code,
            message,
            source: Some(Arc::new(source)),
        }
    }
}
impl PartialEq for ServiceError {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.message == other.message
    }
}
impl Eq for ServiceError {}
impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source.as_ref() as &(dyn std::error::Error + 'static))
    }
}

/// A synchronous port must cooperatively honor this budget and its own frozen
/// operation deadline. The transport cannot safely preempt an in-progress write;
/// connection loss never discards or retries the durable operation.
#[derive(Clone)]
pub struct RequestBudget {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}
impl RequestBudget {
    pub fn new(duration: Duration, cancelled: Arc<AtomicBool>) -> Result<Self, ServiceError> {
        if duration.is_zero() || duration > Duration::from_secs(1200) {
            return Err(ServiceError::new(
                "INVALID_BUDGET",
                "Request duration is outside its finite range",
            ));
        }
        Ok(Self {
            deadline: Instant::now() + duration,
            cancelled,
        })
    }
    pub(crate) fn until(
        deadline: Instant,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self, ServiceError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || remaining > Duration::from_secs(1200) {
            return Err(ServiceError::new(
                "INVALID_BUDGET",
                "Request deadline is outside its finite range",
            ));
        }
        Ok(Self {
            deadline,
            cancelled,
        })
    }
    pub fn check(&self) -> Result<(), ServiceError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(ServiceError::new("CANCELLED", "Request was cancelled"));
        }
        if Instant::now() >= self.deadline {
            return Err(ServiceError::new(
                "TIME_BUDGET_EXCEEDED",
                "Request deadline reached",
            ));
        }
        Ok(())
    }
    pub fn remaining(&self) -> Option<Duration> {
        (!self.cancelled.load(Ordering::Acquire))
            .then(|| self.deadline.checked_duration_since(Instant::now()))
            .flatten()
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn cancellation(&self) -> &AtomicBool {
        &self.cancelled
    }
}

pub trait ServiceDispatcher {
    fn call(
        &mut self,
        principal: &AuthenticatedPrincipal,
        method: &str,
        input: &Value,
        budget: &RequestBudget,
    ) -> Result<Value, ServiceError>;
}

pub struct ApplicationPorts {
    pub authority: Box<dyn AuthorityPort>,
    pub planner: Box<dyn PlanningPort>,
    pub provider: Box<dyn ProviderPort>,
    pub observer: Box<dyn IndependentObserverPort>,
    pub ids: Box<dyn IdSource>,
    pub clock: Box<dyn Clock>,
}

/// Trusted, in-process composition only. It borrows the already locked store
/// and the same authority/host ports used by Application; it is not a wire DTO
/// or an alternate engine. A handler must use current authority for live reads.
pub struct ServiceExtensionContext<'a> {
    pub principal: &'a AuthenticatedPrincipal,
    pub budget: &'a RequestBudget,
    pub store: &'a mut DurableStore,
    pub ports: &'a mut ApplicationPorts,
}
impl ServiceExtensionContext<'_> {
    pub fn check(&self, method: &str) -> Result<(), ServiceError> {
        self.budget.check()?;
        if !self.principal.permits(method) {
            return Err(ServiceError::new(
                "PERMISSION_REQUIRED",
                "Function is not permitted for this session",
            ));
        }
        if crate::peer::fatal_stop_requested() {
            return Err(ServiceError::new(
                "LOCAL_TRANSPORT_UNCERTAIN",
                "Native local authentication transport completion is unresolved",
            ));
        }
        Ok(())
    }
}

pub trait ServiceExtension {
    fn call(
        &mut self,
        method: &str,
        input: &Value,
        context: &mut ServiceExtensionContext<'_>,
    ) -> Result<Value, ServiceError>;
}

/// Exact canonical function registrations, bounded by the original 36-function
/// index. Multiple methods may share one typed owner without cloning its state.
#[derive(Default)]
pub struct ExtensionRouter {
    groups: Vec<(BTreeSet<String>, Box<dyn ServiceExtension>)>,
    methods: BTreeSet<String>,
}
impl ExtensionRouter {
    pub fn register<I, S>(
        &mut self,
        methods: I,
        handler: Box<dyn ServiceExtension>,
    ) -> Result<(), ServiceError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let validator = mmmm_contracts::ContractValidator::shared().map_err(|_| {
            ServiceError::new(
                "CONTRACT_UNAVAILABLE",
                "Canonical function index is unavailable",
            )
        })?;
        let mut group = BTreeSet::new();
        for method in methods {
            let method = method.as_ref();
            let function = validator.function(method).map_err(|_| {
                ServiceError::new(
                    "INVALID_REGISTRATION",
                    "Function registration is not canonical",
                )
            })?;
            if function.name != method
                || builtin_method(method)
                || self.methods.contains(method)
                || !group.insert(method.to_owned())
                || self.methods.len() + group.len() > 36
            {
                return Err(ServiceError::new(
                    "INVALID_REGISTRATION",
                    "Function registration conflicts with the service",
                ));
            }
        }
        if group.is_empty() {
            return Err(ServiceError::new(
                "INVALID_REGISTRATION",
                "Function registration is empty",
            ));
        }
        self.methods.extend(group.iter().cloned());
        self.groups.push((group, handler));
        Ok(())
    }
    fn call(
        &mut self,
        method: &str,
        input: &Value,
        context: &mut ServiceExtensionContext<'_>,
    ) -> Result<Value, ServiceError> {
        context.check(method)?;
        for (methods, handler) in &mut self.groups {
            if methods.contains(method) {
                return handler.call(method, input, context);
            }
        }
        Err(ServiceError::new(
            "IMPLEMENTATION_UNAVAILABLE",
            "This function has no installed implementation",
        ))
    }
}

fn builtin_method(method: &str) -> bool {
    matches!(
        method,
        "project.inspect"
            | "plan.create"
            | "plan.inspect"
            | "plan.apply"
            | "operation.get"
            | "operation.cancel"
            | "operation.reconcile"
            | "recovery.plan"
            | "action.read"
            | "action.plan"
            | "prefab.validate"
            | "instance.instantiate"
            | "instance.clone"
            | "instance.relocate"
            | "command.layout"
            | "clip.retime"
    )
}

/// Exactly one store opens and holds the native data-root lock for this service's
/// lifetime. Facades do not receive access to it or construct another Application.
pub struct ApplicationService {
    store: DurableStore,
    ports: ApplicationPorts,
    extensions: ExtensionRouter,
    request_context: Option<RequestContextSlot>,
    undo_execution: Option<UndoServiceComposition>,
}
#[derive(Clone)]
struct UndoServiceComposition {
    authority: crate::authority::LocalAuthority,
    hosts: crate::host::HostBridge,
}
impl ApplicationService {
    pub fn open(config: StoreConfig, ports: ApplicationPorts) -> Result<Self, StorageError> {
        Ok(Self::from_store(DurableStore::open(config)?, ports))
    }
    /// Trusted composition moves the already locked unique Store into the
    /// service after source registration. No extra SQLite connection is opened.
    pub fn from_store(store: DurableStore, ports: ApplicationPorts) -> Self {
        Self {
            store,
            ports,
            extensions: ExtensionRouter::default(),
            request_context: None,
            undo_execution: None,
        }
    }
    pub fn data_root(&self) -> &std::path::Path {
        self.store.data_root()
    }
    /// Native management owns no Store handle; it receives this short borrow
    /// only in the Coordinator gaps between completed application calls.
    pub(crate) fn management_store(&mut self) -> &mut DurableStore {
        &mut self.store
    }
    /// Other domain/catalog/compiler owners supply typed service adapters here.
    /// The shared boundary still validates canonical input/output and principal.
    pub fn set_extensions(&mut self, dispatcher: ExtensionRouter) {
        self.extensions = dispatcher;
    }
    pub fn bind_request_context(&mut self, context: RequestContextSlot) {
        self.request_context = Some(context);
    }
    /// Install trusted lazy ports over this service's occupied request and
    /// unique Store. Binding performs no native observation or SQL operation.
    pub(crate) fn bind_undo_execution(
        &mut self,
        authority: crate::authority::LocalAuthority,
        hosts: crate::host::HostBridge,
    ) -> Result<(), ServiceError> {
        if self.request_context.is_none() || self.undo_execution.is_some() {
            return Err(ServiceError::new(
                "INVALID_COMPOSITION",
                "Undo execution requires one installed authenticated request slot",
            ));
        }
        self.undo_execution = Some(UndoServiceComposition { authority, hosts });
        Ok(())
    }
    /// Authenticated bootstrap composition may persist initial authoring data;
    /// this is intentionally not exposed as a JSON-RPC escape hatch.
    pub fn bootstrap_project(&mut self, project: &Value) -> Result<(), StorageError> {
        self.store.save_project(project, None).map(|_| ())
    }
}
impl ServiceDispatcher for ApplicationService {
    fn call(
        &mut self,
        principal: &AuthenticatedPrincipal,
        method: &str,
        input: &Value,
        budget: &RequestBudget,
    ) -> Result<Value, ServiceError> {
        budget.check()?;
        if crate::peer::fatal_stop_requested() {
            return Err(ServiceError::new(
                "LOCAL_TRANSPORT_UNCERTAIN",
                "Native local authentication transport completion is unresolved",
            ));
        }
        if !principal.permits(method) {
            return Err(ServiceError::new(
                "PERMISSION_REQUIRED",
                "Function is not permitted for this session",
            ));
        }
        let _request_scope = self
            .request_context
            .as_ref()
            .map(|slot| slot.enter(principal, budget, method))
            .transpose()?;
        let domain = match method {
            "prefab.validate" => Some(mmmm_domain::prefab_validate(input)),
            "instance.instantiate" => Some(mmmm_domain::instantiate(input)),
            "instance.clone" => Some(mmmm_domain::clone_instance(input)),
            "instance.relocate" => Some(mmmm_domain::relocate(input)),
            "command.layout" => Some(mmmm_domain::command_layout(input)),
            "clip.retime" => Some(mmmm_domain::clip_retime(input)),
            _ => None,
        };
        if let Some(result) = domain {
            return result.map_err(|error| {
                ServiceError::caused_by(
                    error.code,
                    "Domain validation rejected the requested transformation",
                    error,
                )
            });
        }
        if !builtin_method(method) {
            let mut context = ServiceExtensionContext {
                principal,
                budget,
                store: &mut self.store,
                ports: &mut self.ports,
            };
            return self.extensions.call(method, input, &mut context);
        }
        let undo_method = match method {
            "plan.create" => Some("plan.create"),
            "plan.apply" => Some("plan.apply"),
            "operation.reconcile" => Some("operation.reconcile"),
            "recovery.plan" => Some("recovery.plan"),
            "action.plan" => Some("action.plan"),
            _ => None,
        };
        let mut undo_ports = match (
            undo_method,
            self.undo_execution.as_ref(),
            self.request_context.as_ref(),
        ) {
            (Some(method), Some(composition), Some(request)) => Some((
                crate::undo_context::CurrentUndoContextFactory::new(
                    request.clone(),
                    composition.authority.clone(),
                    composition.hosts.clone(),
                    method,
                )
                .map_err(|error| ServiceError::caused_by(error.code, error.message, error))?,
                crate::undo_material::HostUndoMaterialAdapter::new(
                    request.clone(),
                    composition.authority.clone(),
                    composition.hosts.clone(),
                    method,
                ),
            )),
            _ => None,
        };
        let mut undo = undo_ports.as_mut().map(|(contexts, material)| {
            mmmm_application::undo_context::UndoExecutionContext { contexts, material }
        });
        let mut provider = GuardedProvider {
            inner: self.ports.provider.as_mut(),
            budget,
            principal,
            method,
        };
        let mut observer = GuardedObserver {
            inner: self.ports.observer.as_mut(),
            budget,
            principal,
            method,
        };
        let mut application = Application {
            store: &mut self.store,
            authority: self.ports.authority.as_mut(),
            planner: self.ports.planner.as_mut(),
            provider: &mut provider,
            observer: &mut observer,
            ids: self.ports.ids.as_mut(),
            clock: self.ports.clock.as_ref(),
        };
        let result = match method {
            "project.inspect" => application.project_inspect(principal.principal(), input),
            "plan.create" => {
                application.plan_create_with_undo(principal.principal(), input, undo.as_mut())
            }
            "plan.inspect" => application.plan_inspect(principal.principal(), input),
            "plan.apply" => {
                application.plan_apply_with_undo(principal.principal(), input, undo.as_mut())
            }
            "operation.get" => application.operation_get(principal.principal(), input),
            "operation.cancel" => application.operation_cancel(principal.principal(), input),
            "operation.reconcile" => application.operation_reconcile_with_undo(
                principal.principal(),
                input,
                undo.as_mut(),
            ),
            "recovery.plan" => {
                application.recovery_plan_with_undo(principal.principal(), input, undo.as_mut())
            }
            "action.read" => application.action_read(principal.principal(), input),
            "action.plan" => {
                application.action_plan_with_undo(principal.principal(), input, undo.as_mut())
            }
            _ => {
                return Err(ServiceError::new(
                    "IMPLEMENTATION_UNAVAILABLE",
                    "This function has no installed implementation",
                ));
            }
        };
        // Do not replace a truthful durable write result with a transport timeout.
        // Runtime/host budgets determine actual effect completion and uncertainty.
        result.map_err(|error| ServiceError::caused_by(error.code, error.message, error))
    }
}

struct GuardedProvider<'a> {
    inner: &'a mut dyn ProviderPort,
    budget: &'a RequestBudget,
    principal: &'a AuthenticatedPrincipal,
    method: &'a str,
}
impl GuardedProvider<'_> {
    fn admission(&self) -> mmmm_application::AppResult<()> {
        self.budget
            .check()
            .map_err(|e| mmmm_application::AppError::new(e.code, e.message))?;
        if !self.principal.permits(self.method) {
            return Err(mmmm_application::AppError::new(
                "PERMISSION_REQUIRED",
                "Authenticated local session has expired",
            ));
        }
        if crate::peer::fatal_stop_requested() {
            return Err(mmmm_application::AppError::new(
                "LOCAL_TRANSPORT_UNCERTAIN",
                "Native local bootstrap completion is unresolved",
            ));
        }
        Ok(())
    }
}
impl ProviderPort for GuardedProvider<'_> {
    fn registered_read_with_store(
        &mut self,
        store: &DurableStore,
        request: &Value,
        context: &Value,
    ) -> mmmm_application::AppResult<Value> {
        self.admission()?;
        self.inner
            .registered_read_with_store(store, request, context)
    }
    fn context(
        &mut self,
        p: &mmmm_contracts::PrincipalId,
        id: &mmmm_contracts::ContextId,
    ) -> mmmm_application::AppResult<Value> {
        self.admission()?;
        self.inner.context(p, id)
    }
    fn action_descriptor(
        &mut self,
        step: &Value,
        context: &Value,
    ) -> mmmm_application::AppResult<Value> {
        self.admission()?;
        self.inner.action_descriptor(step, context)
    }
    fn observe_precondition(
        &mut self,
        precondition: &Value,
        context: &Value,
    ) -> mmmm_application::AppResult<mmmm_contracts::Sha256Digest> {
        self.admission()?;
        self.inner.observe_precondition(precondition, context)
    }
    fn observe_precondition_with_store(
        &mut self,
        store: &DurableStore,
        precondition: &Value,
        context: &Value,
    ) -> mmmm_application::AppResult<mmmm_contracts::Sha256Digest> {
        self.admission()?;
        self.inner
            .observe_precondition_with_store(store, precondition, context)
    }
    fn observe_plan_precondition_with_store(
        &mut self,
        store: &DurableStore,
        plan: &Value,
        step: &Value,
        precondition: &Value,
        context: &Value,
    ) -> mmmm_application::AppResult<mmmm_contracts::Sha256Digest> {
        self.admission()?;
        self.inner
            .observe_plan_precondition_with_store(store, plan, step, precondition, context)
    }
    fn observe_plan_precondition_retained_with_store(
        &mut self,
        store: &mut DurableStore,
        plan: &Value,
        step: &Value,
        precondition: &Value,
        context: &Value,
    ) -> mmmm_application::AppResult<mmmm_contracts::Sha256Digest> {
        self.admission()?;
        self.inner.observe_plan_precondition_retained_with_store(
            store,
            plan,
            step,
            precondition,
            context,
        )
    }
    fn verify_dependencies(
        &mut self,
        pins: &[Value],
        context: &Value,
    ) -> mmmm_application::AppResult<()> {
        self.admission()?;
        self.inner.verify_dependencies(pins, context)
    }
    fn dispatch(&mut self, invocation: &Value) -> mmmm_application::AppResult<Value> {
        self.admission()?;
        self.inner.dispatch(invocation)
    }
    fn dispatch_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
    ) -> mmmm_application::AppResult<Value> {
        self.admission()?;
        self.inner.dispatch_with_store(store, invocation)
    }
    fn poll(
        &mut self,
        invocation: &Value,
        receipt: Option<&str>,
    ) -> mmmm_application::AppResult<Option<Value>> {
        self.admission()?;
        self.inner.poll(invocation, receipt)
    }
    fn poll_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        receipt: Option<&str>,
    ) -> mmmm_application::AppResult<Option<Value>> {
        self.admission()?;
        self.inner.poll_with_store(store, invocation, receipt)
    }
    fn request_cancel(
        &mut self,
        invocation: &Value,
        receipt: Option<&str>,
    ) -> mmmm_application::AppResult<()> {
        self.admission()?;
        self.inner.request_cancel(invocation, receipt)
    }
    fn request_cancel_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        receipt: Option<&str>,
    ) -> mmmm_application::AppResult<()> {
        self.admission()?;
        self.inner
            .request_cancel_with_store(store, invocation, receipt)
    }
}
struct GuardedObserver<'a> {
    inner: &'a mut dyn IndependentObserverPort,
    budget: &'a RequestBudget,
    principal: &'a AuthenticatedPrincipal,
    method: &'a str,
}
impl GuardedObserver<'_> {
    fn admission(&self) -> mmmm_application::AppResult<()> {
        self.budget
            .check()
            .map_err(|e| mmmm_application::AppError::new(e.code, e.message))?;
        if !self.principal.permits(self.method) {
            return Err(mmmm_application::AppError::new(
                "PERMISSION_REQUIRED",
                "Authenticated observation session is no longer current",
            ));
        }
        if crate::peer::fatal_stop_requested() {
            return Err(mmmm_application::AppError::new(
                "LOCAL_TRANSPORT_UNCERTAIN",
                "Native local bootstrap completion is unresolved",
            ));
        }
        Ok(())
    }
}
impl IndependentObserverPort for GuardedObserver<'_> {
    fn validate_capture_target(
        &mut self,
        invocation: &Value,
        scope: &mmmm_runtime::storage::WriteScope,
        target: &str,
    ) -> mmmm_application::AppResult<()> {
        self.admission()?;
        self.inner
            .validate_capture_target(invocation, scope, target)
    }
    fn capture_before(
        &mut self,
        invocation: &Value,
        scope: &mmmm_runtime::storage::WriteScope,
    ) -> mmmm_application::AppResult<Option<mmmm_application::BeforeCapture>> {
        self.admission()?;
        self.inner.capture_before(invocation, scope)
    }
    fn capture_before_with_store(
        &mut self,
        store: &DurableStore,
        invocation: &Value,
        scope: &mmmm_runtime::storage::WriteScope,
    ) -> mmmm_application::AppResult<Option<mmmm_application::BeforeCapture>> {
        self.admission()?;
        self.inner
            .capture_before_with_store(store, invocation, scope)
    }
    fn capture_before_retained_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        scope: &mmmm_runtime::storage::WriteScope,
    ) -> mmmm_application::AppResult<Option<mmmm_application::BeforeCapture>> {
        self.admission()?;
        self.inner
            .capture_before_retained_with_store(store, invocation, scope)
    }
    fn readback(
        &mut self,
        invocation: &Value,
        scope: &mmmm_runtime::storage::WriteScope,
    ) -> mmmm_application::AppResult<mmmm_application::ReadbackEvidence> {
        self.admission()?;
        self.inner.readback(invocation, scope)
    }
    fn readback_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        scope: &mmmm_runtime::storage::WriteScope,
    ) -> mmmm_application::AppResult<mmmm_application::ReadbackEvidence> {
        self.admission()?;
        self.inner.readback_with_store(store, invocation, scope)
    }
    fn read_target(
        &mut self,
        invocation: &Value,
        target: &str,
    ) -> mmmm_application::AppResult<Vec<u8>> {
        self.admission()?;
        self.inner.read_target(invocation, target)
    }
    fn read_target_with_store(
        &mut self,
        store: &DurableStore,
        invocation: &Value,
        target: &str,
    ) -> mmmm_application::AppResult<Vec<u8>> {
        self.admission()?;
        self.inner.read_target_with_store(store, invocation, target)
    }
    fn read_target_retained_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        target: &str,
    ) -> mmmm_application::AppResult<Vec<u8>> {
        self.admission()?;
        self.inner
            .read_target_retained_with_store(store, invocation, target)
    }
}

#[cfg(test)]
mod request_context_tests {
    use super::*;
    use crate::auth::{SessionAuthority, SessionPolicy};
    use mmmm_contracts::PrincipalId;
    #[test]
    fn service_error_preserves_original_cause_without_changing_public_identity() {
        use std::error::Error;
        let original = mmmm_application::AppError::caused_by(
            "OBSERVATION_INVALID",
            "Original public message",
            std::io::Error::other("Original local acquisition failure"),
        );
        let error = ServiceError::caused_by(original.code, original.message, original);
        let clone = error.clone();
        assert_eq!(error, ServiceError::new(error.code, error.message));
        assert_eq!(
            error.to_string(),
            "OBSERVATION_INVALID: Original public message"
        );
        let original = clone
            .source()
            .unwrap()
            .downcast_ref::<mmmm_application::AppError>()
            .unwrap();
        let acquisition = original
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(
            acquisition.to_string(),
            "Original local acquisition failure"
        );
        assert!(std::ptr::eq(
            error.source().unwrap(),
            clone.source().unwrap()
        ));
    }
    #[test]
    fn actual_request_slot_retires_on_return_and_rejects_revoked_clones() {
        let mut authority = SessionAuthority::new(1).unwrap();
        let token = authority
            .install(SessionPolicy {
                principal: PrincipalId::new("native-owner").unwrap(),
                allowed_methods: ["project.inspect".to_owned()].into(),
                allowed_contexts: BTreeSet::new(),
                lifetime: Duration::from_secs(10),
            })
            .unwrap();
        let bearer = token.bearer();
        let principal = authority.authenticate(bearer.as_str()).unwrap();
        let budget =
            RequestBudget::new(Duration::from_secs(5), Arc::new(AtomicBool::new(false))).unwrap();
        let slot = RequestContextSlot::default();
        assert!(slot.current().is_err());
        let guard = slot.enter(&principal, &budget, "project.inspect").unwrap();
        assert_eq!(slot.current().unwrap().0.principal(), principal.principal());
        assert!(slot.enter(&principal, &budget, "project.inspect").is_err());
        authority.revoke_all();
        assert!(slot.current().is_err());
        drop(guard);
        assert!(slot.current().is_err());
    }
    #[test]
    fn interruption_retained_identity_does_not_revive_budget_or_revoked_session() {
        let mut authority = SessionAuthority::new(1).unwrap();
        let token = authority
            .install(SessionPolicy {
                principal: PrincipalId::new("native-owner").unwrap(),
                allowed_methods: ["reference.capture".to_owned()].into(),
                allowed_contexts: BTreeSet::new(),
                lifetime: Duration::from_secs(10),
            })
            .unwrap();
        let principal = authority.authenticate_token(&token).unwrap();
        let budget =
            RequestBudget::new(Duration::from_secs(5), Arc::new(AtomicBool::new(false))).unwrap();
        let slot = RequestContextSlot::default();
        let guard = slot
            .enter(&principal, &budget, "reference.capture")
            .unwrap();
        budget.cancellation().store(true, Ordering::Release);
        assert!(slot.current().is_err());
        let (retained, interrupted) = slot.current_retained().unwrap();
        assert!(retained.same_session(&principal));
        assert_eq!(interrupted.deadline(), budget.deadline());
        assert!(interrupted.check().is_err());
        assert!(slot.current().is_err());
        authority.revoke_all();
        assert!(slot.current_retained().is_err());
        drop(guard);
        assert!(slot.current_retained().is_err());
    }
    #[test]
    fn call_witness_rejects_another_method_and_reused_session_budget() {
        // Existing session fixtures cannot distinguish calls with an identical
        // budget. This regression exercises the actual slot's per-enter owner.
        let mut authority = SessionAuthority::new(1).unwrap();
        let token = authority
            .install(SessionPolicy {
                principal: PrincipalId::new("native-owner").unwrap(),
                allowed_methods: ["project.inspect".to_owned(), "plan.inspect".to_owned()].into(),
                allowed_contexts: BTreeSet::new(),
                lifetime: Duration::from_secs(10),
            })
            .unwrap();
        let principal = authority.authenticate_token(&token).unwrap();
        let budget =
            RequestBudget::new(Duration::from_secs(5), Arc::new(AtomicBool::new(false))).unwrap();
        let slot = RequestContextSlot::default();
        let first = slot.enter(&principal, &budget, "project.inspect").unwrap();
        assert!(slot.current_witness("plan.inspect").is_err());
        let old = slot.current_witness("project.inspect").unwrap();
        old.check_local().unwrap();
        drop(first);
        assert!(old.check_local().is_err());
        let second = slot.enter(&principal, &budget, "project.inspect").unwrap();
        assert!(old.check_local().is_err());
        let fresh = slot.current_witness("project.inspect").unwrap();
        fresh.check_local().unwrap();
        authority.revoke_all();
        assert!(fresh.check_local().is_err());
        drop(second);
    }
}

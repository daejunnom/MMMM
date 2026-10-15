//! One original native Invocation owns both the world and authored phases.
//! Ports retain bounded immutable source witnesses, never a Store or a second
//! journal. A failed local promotion cannot enter the world dispatch again.

use crate::{
    auth::AuthenticatedPrincipal,
    authority::LocalAuthority,
    calibration_execution::{CalibrationAccess, CalibrationRegistry, EnteredCalibration},
    host::{
        DependencyProvenance, HostBridge, HostContextWitness, HttpProviderPort, VerifiedDependency,
    },
    native_backend::{HostNativeBackend, OwnedNativeInventory, PreparedNativeBatch},
    native_targets::NativeTargetReader,
    observer::{NativeObserver, finish_native_observation},
    planning_source::PlanningStore,
    service::{RequestBudget, RequestContextSlot, RequestContextWitness},
};
use mmmm_adapters::{
    ActionDescriptor, ActionReadiness, Availability, CompatibilityEvidence, EnvironmentRef, Origin,
    OriginKind, ProviderRegistry, RegistrationObservation,
};
use mmmm_application::{
    Access, AppError, AppResult, AuthorityPort, BeforeCapture, BeforeImage, DirectChange,
    IndependentObserverPort, ProviderPort, ReadbackEvidence,
};
use mmmm_contracts::{
    BindingId, ContextId, InvocationId, ObjectId, OperationId, PrincipalId, ProjectId, ResourceId,
    Sha256Digest, StepId, canonical_digest, encode_json, parse_json, projected_digest, raw_digest,
};
use mmmm_planner::{
    NativeActionRoute, NativeKind, OwnedKind, PreparedNativeChange, ProjectCatalog,
};
use mmmm_runtime::storage::{
    BlobRef, DispatchEvidence, DurableStore, EffectEvidence, OperationRecord, OperationState,
    StorageError, StorageResult, WriteScope,
    artifact::ResourceOwner,
    authored_projection::{
        self, ProjectionAuthority, ProjectionCommitRequest, ProjectionCommitResult,
        ProjectionInput, ProjectionRpcContext, WorldPhaseObservation,
    },
    owned_documents::{
        OwnedDocumentAuthority, OwnedDocumentKind, OwnedDocumentPin, OwnedDocumentReader,
    },
    project_resources::{
        ProjectResourceAuthority, ProjectResourceQuery, ProjectResourceReader,
        ProjectResourceRequest, ProjectSourceRpcContext, RegisteredProjectResource,
    },
};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_DOCUMENT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PHASES: usize = 128;
const MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const METADATA_BINDING: &str = "mmmm-rust-authored-projection";
const METADATA_CONTRACTS: &[&str] = &["FN08", "FN09", "FN11", "FN12", "FN14", "FN30"];

/// The caller pins the actual approved Rust executable. A Java host JAR digest
/// cannot construct this registration or substitute for its implementation.
#[derive(Clone)]
pub struct RustMetadataRegistry {
    implementation: Sha256Digest,
    authority: LocalAuthority,
}
impl RustMetadataRegistry {
    pub fn new(implementation: Sha256Digest, authority: LocalAuthority) -> Self {
        Self {
            implementation,
            authority,
        }
    }
    pub fn dependency(&self) -> AppResult<VerifiedDependency> {
        VerifiedDependency::new(
            METADATA_BINDING.into(),
            self.implementation.clone(),
            DependencyProvenance::OwnedDomain,
            self.contract_ids(),
        )
    }
    pub fn binding_id(&self) -> AppResult<BindingId> {
        BindingId::new(METADATA_BINDING).map_err(|_| invalid())
    }
    pub fn implementation_digest(&self) -> &Sha256Digest {
        &self.implementation
    }
    pub fn contract_ids(&self) -> BTreeSet<String> {
        METADATA_CONTRACTS
            .iter()
            .map(|s| (*s).to_owned())
            .chain(self.action_ids())
            .collect()
    }
    pub fn action_ids(&self) -> Vec<String> {
        metadata_kinds()
            .into_iter()
            .filter_map(metadata_route)
            .map(|(action, _)| action.to_owned())
            .collect()
    }
    pub fn action_descriptors(&self, context: &Value) -> AppResult<Vec<Value>> {
        metadata_kinds()
            .into_iter()
            .map(|kind| self.descriptor(kind, context))
            .collect()
    }
    fn descriptor(&self, kind: NativeKind, context: &Value) -> AppResult<Value> {
        let (action, semantic) = metadata_route(kind).ok_or_else(unavailable)?;
        let side = match context["environment"]["side"].as_str() {
            Some("client") => "client",
            Some("server" | "offline") => "server",
            Some("external") => "external",
            _ => return Err(invalid()),
        };
        let value = json!({"actionId":action,"contractVersion":mmmm_contracts::CONTRACT_VERSION,
            "title":kind.wire(),"summary":"Commit an exact prepared authored projection in the original operation",
            "semanticKind":semantic,"inputSchema":mmmm_planner::native_action_input_schema(),
            "outputSchema":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object",
                "additionalProperties":false,"required":["projectRevision","projectionReceiptDigest","replayed"],
                "properties":{"projectRevision":{"type":"string","pattern":"^[a-f0-9]{64}$"},
                    "projectionReceiptDigest":{"type":"string","pattern":"^[a-f0-9]{64}$"},"replayed":{"type":"boolean"}}},
            "side":side,"requiredContext":["project"],"effect":"write","planning":"pure",
            "completion":"synchronous","cancellation":"queued_only","recovery":"none",
            "idempotency":"coordinator_only","guarantees":["authenticated_context","atomic_authored_projection"],
            "limitations":["no_world_execution","no_automatic_retry_after_durable_intent"],
            "requiredPermissions":[],"verificationRequirement":"independent_readback",
            "implementationDigest":self.implementation,"versionEvidence":"interface_checked"});
        validate("ActionDescriptor", &value)?;
        Ok(value)
    }
    fn authorize(
        &self,
        authenticated: &AuthenticatedPrincipal,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        check_session(authenticated, budget, &context_id(context)?)?;
        if context["principalRef"] != authenticated.principal().as_str() {
            return Err(forbidden());
        }
        self.authority.authorize_with_deadline(
            authenticated.principal(),
            &project_id(context)?,
            Access::Plan,
            Some(context),
            None,
            budget.deadline(),
        )
    }
}
impl OwnedNativeInventory for RustMetadataRegistry {
    fn append_actual(
        &self,
        authenticated: &AuthenticatedPrincipal,
        context: &Value,
        registry: &mut ProviderRegistry,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        self.authorize(authenticated, context, budget)?;
        if context["environment"]["kind"] == "offline" {
            // The original adapter contract does not register an executable
            // Provider in an offline workspace. Keep inventory truthful; this
            // source observation cannot fabricate a game or external route.
            return Ok(());
        }
        let actions: Vec<Value> = metadata_kinds()
            .into_iter()
            .map(|kind| self.descriptor(kind, context))
            .collect::<AppResult<_>>()?;
        let environment: EnvironmentRef = decode(&context["environment"])?;
        let origin = Origin {
            kind: OriginKind::Builtin,
            source_id: METADATA_BINDING.into(),
            source_digest: Some(self.implementation.clone()),
        };
        let action_values: Vec<ActionDescriptor> =
            actions.iter().map(decode).collect::<AppResult<_>>()?;
        let observation = RegistrationObservation {
            environment: environment.clone(),
            origin: origin.clone(),
            host_protocol_version: mmmm_adapters::HOST_PROTOCOL_VERSION.into(),
            loaded: true,
            connected: true,
            availability: Availability::Available,
            evidence: CompatibilityEvidence::InterfaceChecked,
            implementation_digests: action_values
                .iter()
                .map(|a| (a.action_id.clone(), a.implementation_digest.clone()))
                .collect(),
            action_readiness: action_values
                .iter()
                .map(|a| {
                    (
                        a.action_id.clone(),
                        ActionReadiness {
                            ready: true,
                            possible_loss_codes: Some(BTreeSet::new()),
                        },
                    )
                })
                .collect(),
        };
        let descriptor = json!({"contractVersion":mmmm_contracts::CONTRACT_VERSION,
            "providerId":"mmmm:rust_authored","bindingId":METADATA_BINDING,
            "providerVersion":"0.1.0","environment":environment,"registrationMode":"provider",
            "origin":origin,"hostProtocolVersion":mmmm_adapters::HOST_PROTOCOL_VERSION,"actions":actions,
            "compatibilityEvidence":"interface_checked","availability":"available"});
        registry
            .register_observed_provider(&descriptor, observation)
            .map_err(|_| invalid())?;
        self.authorize(authenticated, context, budget)
    }
    fn route(
        &self,
        authenticated: &AuthenticatedPrincipal,
        kind: NativeKind,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<NativeActionRoute> {
        self.authorize(authenticated, context, budget)?;
        let (action, semantic) = metadata_route(kind).ok_or_else(unavailable)?;
        Ok(NativeActionRoute {
            binding_id: BindingId::new(METADATA_BINDING).map_err(|_| invalid())?,
            action_id: decode(&json!(action))?,
            semantic_kind: decode(&json!(semantic))?,
            required_guarantees: BTreeSet::from([
                "authenticated_context".into(),
                "atomic_authored_projection".into(),
            ]),
            acceptable_loss_codes: BTreeSet::new(),
        })
    }
}
fn metadata_kinds() -> [NativeKind; 3] {
    [
        NativeKind::ClipRetime,
        NativeKind::PackBuild,
        NativeKind::ResourcePatch,
    ]
}
fn metadata_route(kind: NativeKind) -> Option<(&'static str, &'static str)> {
    match kind {
        NativeKind::ClipRetime => Some(("mmmm:authored_clip_retime", "mmmm:clip.retime")),
        NativeKind::PackBuild => Some(("mmmm:authored_pack_build", "mmmm:pack.build")),
        NativeKind::ResourcePatch => Some(("mmmm:authored_resource_patch", "mmmm:resource.patch")),
        _ => None,
    }
}

/// This chooses a codec, never authority. Its consumers still require the
/// exact same-Store saved plan/step and current original invocation admission.
fn registered_direct_block(value: &Value) -> bool {
    value["actionId"] == "mmmm:block_patch"
        && value["arguments"]
            .get("expectedRegistryGeneration")
            .is_some()
}

pub struct CompositeComposition {
    pub hosts: HostBridge,
    pub authority: LocalAuthority,
    pub request: RequestContextSlot,
    pub backend: Rc<HostNativeBackend>,
    pub metadata: RustMetadataRegistry,
    pub calibration: CalibrationRegistry,
}
#[derive(Clone)]
struct Shared {
    hosts: HostBridge,
    authority: LocalAuthority,
    request: RequestContextSlot,
    backend: Rc<HostNativeBackend>,
    metadata: RustMetadataRegistry,
    calibration: CalibrationRegistry,
    phases: Rc<RefCell<BTreeMap<InvocationId, Rc<FrozenPhase>>>>,
}
struct FrozenPhase {
    authenticated: AuthenticatedPrincipal,
    invocation: Value,
    invocation_digest: Sha256Digest,
    change: PreparedNativeChange,
    batch: Option<PreparedNativeBatch>,
    before: BTreeMap<String, Vec<u8>>,
    native_subjects: BTreeMap<Sha256Digest, String>,
    memory_bytes: usize,
    attempted: Cell<bool>,
}
pub struct CompositeProvider {
    shared: Shared,
}
pub struct CompositeObserver {
    shared: Shared,
}
impl CompositeProvider {
    pub fn new(composition: CompositeComposition) -> AppResult<Self> {
        composition
            .hosts
            .register_verified_dependency(composition.metadata.dependency()?)?;
        Ok(Self {
            shared: Shared {
                hosts: composition.hosts,
                authority: composition.authority,
                request: composition.request,
                backend: composition.backend,
                metadata: composition.metadata,
                calibration: composition.calibration,
                phases: Rc::new(RefCell::new(BTreeMap::new())),
            },
        })
    }
    pub fn observer(&self) -> CompositeObserver {
        CompositeObserver {
            shared: self.shared.clone(),
        }
    }
    fn cancel_original_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        receipt: Option<&str>,
    ) -> AppResult<()> {
        let request = self.shared.calibration_request()?;
        if let Some(entered) =
            self.shared
                .enter_calibration(store, &request, invocation, CalibrationAccess::Cancel)?
        {
            entered.verify_claim(store, invocation)?;
            let result = entered
                .route()
                .cancel_with_store(store, &request, invocation, &|store| {
                    entered.check_local(store)
                });
            return finish_native_observation(result, entered.check_local(store));
        }
        durable_original(&self.shared, store, invocation, Access::Cancel)?;
        let call = self.shared.call(&invocation["context"])?;
        self.shared.authority.authorize_with_deadline(
            call.authenticated.principal(),
            &call.project,
            Access::Cancel,
            Some(&call.context),
            None,
            call.budget.deadline(),
        )?;
        if invocation["bindingId"] == METADATA_BINDING {
            return Ok(());
        }
        HttpProviderPort::with_deadline(self.shared.hosts.clone(), call.budget.deadline())
            .request_cancel_with_store(store, invocation, receipt)
    }
}
impl Shared {
    fn calibration_request(&self) -> AppResult<RequestContextWitness> {
        self.request
            .occupied_witness()
            .map_err(|cause| AppError::caused_by(cause.code, cause.message, cause))
    }
    fn enter_calibration<'a>(
        &'a self,
        store: &DurableStore,
        request: &'a RequestContextWitness,
        original: &Value,
        access: CalibrationAccess,
    ) -> AppResult<Option<EnteredCalibration<'a>>> {
        let operation: OperationId = decode(&original["operationId"])?;
        self.calibration.enter(
            store,
            request,
            &self.authority,
            &operation,
            original,
            access,
        )
    }
    fn block_observer(&self) -> NativeObserver {
        NativeObserver::authenticated(
            self.hosts.clone(),
            self.authority.clone(),
            self.request.clone(),
        )
    }
    fn direct_checkpoint<'a>(
        &self,
        call: &'a Call,
        operation: &'a OperationRecord,
        plan: &'a Value,
        access: Access,
    ) -> AppResult<DirectCallCheckpoint<'a>> {
        let request = self.request.occupied_witness().map_err(service_cause)?;
        if !request.authenticated().same_session(&call.authenticated)
            || request.budget().deadline() != call.budget.deadline()
            || !std::ptr::eq(request.budget().cancellation(), call.budget.cancellation())
        {
            return Err(forbidden());
        }
        call.check()?;
        authorize_direct_retained(
            &call.authority,
            call.authenticated.principal(),
            &call.context,
            operation,
            plan,
            access,
        )?;
        let host = self.hosts.observe_context_witness(
            call.authenticated.principal(),
            &call.id,
            request.budget().deadline(),
        );
        let host = finish_native_observation(
            host,
            (|| {
                request.check_local().map_err(service_cause)?;
                call.check()?;
                authorize_direct_retained(
                    &call.authority,
                    call.authenticated.principal(),
                    &call.context,
                    operation,
                    plan,
                    access,
                )
            })(),
        )?;
        if host.context() != &call.context {
            return Err(stale());
        }
        let checkpoint = DirectCallCheckpoint {
            call,
            operation,
            plan,
            access,
            request,
            host,
        };
        checkpoint.check()?;
        Ok(checkpoint)
    }
    fn call(&self, context: &Value) -> AppResult<Call> {
        let (authenticated, budget) = self
            .request
            .current()
            .map_err(|e| AppError::new(e.code, e.message))?;
        let id = context_id(context)?;
        check_session(&authenticated, &budget, &id)?;
        if context["principalRef"] != authenticated.principal().as_str() {
            return Err(forbidden());
        }
        let current = self.authority.current_context_with_deadline(
            authenticated.principal(),
            &id,
            budget.deadline(),
        )?;
        // Historical policy is never adopted as authority. Actual native epoch
        // is immutable for this original route; current grants are checked below.
        if current["environment"] != context["environment"]
            || current["projectId"] != context["projectId"]
        {
            return Err(stale());
        }
        Ok(Call {
            authenticated,
            budget,
            authority: self.authority.clone(),
            context: current,
            id,
            project: project_id(context)?,
            allowed_resources: BTreeMap::new(),
            local_witness: None,
            local_only: false,
        })
    }
    fn phase(&self, invocation: &Value) -> AppResult<Rc<FrozenPhase>> {
        let phases = self.phases.try_borrow().map_err(|_| busy())?;
        let id: InvocationId = decode(&invocation["invocationId"])?;
        let phase = phases
            .get(&id)
            .ok_or_else(|| {
                error(
                    "NATIVE_PHASE_UNAVAILABLE",
                    "The exact original source phase is not retained in this service generation",
                )
            })?
            .clone();
        if phase.invocation != *invocation {
            return Err(stale());
        }
        Ok(phase)
    }
    fn prune_terminal_phases(&self, store: &DurableStore) -> AppResult<()> {
        let mut phases = self.phases.try_borrow_mut().map_err(|_| busy())?;
        let mut remove = Vec::new();
        for (id, phase) in phases.iter() {
            let operation: OperationId = decode(&phase.invocation["operationId"])?;
            let record = store.operation(&operation).map_err(storage)?;
            if record.state.terminal() && !record.reconciliation_required {
                remove.push(id.clone());
            }
        }
        // The original journal/CAS remain the recovery owner. Pruning only
        // releases ephemeral source witnesses after its operation is terminal.
        for id in remove {
            phases.remove(&id);
        }
        Ok(())
    }
    fn retain_phase(&self, phase: FrozenPhase) -> AppResult<Rc<FrozenPhase>> {
        let mut phases = self.phases.try_borrow_mut().map_err(|_| busy())?;
        let id: InvocationId = decode(&phase.invocation["invocationId"])?;
        if phases.contains_key(&id) {
            return Err(error(
                "DISPATCH_ALREADY_PREPARED",
                "Original invocation already has a frozen phase",
            ));
        }
        let bytes = phases
            .values()
            .try_fold(phase.memory_bytes, |n, p| n.checked_add(p.memory_bytes))
            .ok_or_else(limit)?;
        if phases.len() >= MAX_PHASES || bytes > MAX_RETAINED_BYTES {
            return Err(limit());
        }
        let phase = Rc::new(phase);
        phases.insert(id, phase.clone());
        Ok(phase)
    }
    fn reader(&self) -> NativeTargetReader {
        NativeTargetReader::new(
            self.hosts.clone(),
            self.authority.clone(),
            self.request.clone(),
        )
    }
    fn projection(
        &self,
        store: &mut DurableStore,
        invocation: &Value,
        allow_new: bool,
    ) -> AppResult<ProjectionCommitResult> {
        let (record, blob) = durable_original(self, store, invocation, Access::ObserveOperation)?;
        let (_, plan, _, call) = frozen_plan(
            self,
            store,
            invocation,
            if allow_new {
                Access::Apply
            } else {
                Access::ObserveOperation
            },
        )?;
        let (change, mut call, change_digest) = load_change(self, store, &call, &plan, invocation)?;
        verify_change_scope(&change, &record.scope)?;
        verify_sources(store, &call, &change)?;
        let request = ProjectionCommitRequest {
            operation_id: record.operation_id.clone(),
            step_id: decode(&invocation["stepId"])?,
            invocation_id: decode(&invocation["invocationId"])?,
            invocation_digest: blob.digest,
        };
        let world = if allow_new {
            let phase = self.phase(invocation)?;
            if !phase.attempted.get() || phase.change.to_arguments()? != change.to_arguments()? {
                return Err(stale());
            }
            let mut evidence = Vec::new();
            let observed = self.world(store, invocation, &phase, &mut evidence);
            for blob in &evidence {
                store
                    .append_operation_evidence(&record.operation_id, blob)
                    .map_err(storage)?;
            }
            let observed = observed?;
            if !observed.complete || !observed.settled {
                return Err(error(
                    "WORLD_PHASE_UNVERIFIED",
                    "Original world phase has not independently completed and stopped",
                ));
            }
            Some(WorldPhaseObservation {
                invocation_id: decode(&invocation["invocationId"])?,
                invocation_digest: request.invocation_digest.clone(),
                change_digest,
                context_digest: field_digest(invocation, "contextDigest")?,
                scope_digest: canonical_digest(
                    &serde_json::to_value(&record.scope).map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?,
                world_phase_complete: true,
                further_world_effects_possible: false,
                evidence: observed.evidence,
            })
        } else {
            None
        };
        // Native observations and their acquired bytes are retained before the
        // writer transaction. Its checkpoints only inspect local route/ACL
        // ownership and immutable stored inputs; no transport I/O is allowed.
        if call.context["environment"]["kind"] == "game" {
            let witness = self.hosts.observe_context_witness(
                call.authenticated.principal(),
                &call.id,
                call.budget.deadline(),
            )?;
            if witness.context() != &call.context {
                return Err(stale());
            }
            call.local_witness = Some(witness);
        }
        call.local_only = true;
        call.check()?;
        let mut authority = CommitAuthority {
            shared: self.clone(),
            call: call.clone(),
            allow_new,
            invocation: invocation.clone(),
            plan,
            change,
            world,
        };
        authored_projection::commit_authored_projection(store, &call, &mut authority, &request)
            .map_err(storage)
    }
}

impl Shared {
    fn seal(
        &self,
        store: &mut DurableStore,
        invocation: &Value,
        scope: &WriteScope,
    ) -> AppResult<Rc<FrozenPhase>> {
        self.prune_terminal_phases(store)?;
        let (record, plan, _, call) = frozen_plan(self, store, invocation, Access::Apply)?;
        let step = record
            .steps
            .iter()
            .find(|step| step.step_id.as_str() == invocation["stepId"].as_str().unwrap_or(""))
            .ok_or_else(invalid)?;
        if &record.scope != scope
            || !matches!(
                record.state,
                OperationState::Queued | OperationState::Running
            )
            || step.finished
            || step.dispatch != DispatchEvidence::NotSent
            || record.cancellation_requested
            || record.reconciliation_required
        {
            return Err(stale());
        }
        let (change, rpc, _) = load_change(self, store, &call, &plan, invocation)?;
        let project =
            ProjectCatalog::from_project(&store.project(&call.project).map_err(storage)?)?;
        if project.revision() != &change.project_base_revision {
            return Err(stale());
        }
        verify_change_scope(&change, scope)?;
        let (authored, prepared) = {
            let planning = PlanningStore::write(store);
            let authored = self.backend.capture_authored_before(
                &planning,
                call.authenticated.principal(),
                &project,
                &change,
                &call.context,
            )?;
            let prepared = if change.kind.world_effect() {
                Some(self.backend.prepare_native_batch(
                    &planning,
                    call.authenticated.principal(),
                    &project,
                    &change,
                    &call.context,
                )?)
            } else {
                None
            };
            (authored, prepared)
        };
        let mut before = BTreeMap::new();
        for image in authored {
            insert_image(&mut before, image.subject, image.bytes)?;
        }
        let mut native_subjects = BTreeMap::new();
        let batch = if let Some(batch) = prepared {
            if batch.scope() != scope
                || batch.context_digest() != &field_digest(invocation, "contextDigest")?
                || batch.prepared_digest()
                    != &field_digest(&invocation["arguments"]["preparedChange"], "sha256")?
                || batch.phase() != mmmm_compiler::scene::SceneLifecyclePhase::Stage
            {
                return Err(stale());
            }
            let read = self
                .reader()
                .observe_retained(
                    store,
                    &call.context,
                    batch.selectors(),
                    text(batch.profile_evidence(), "registryGeneration")?,
                )
                .map_err(native_error)?;
            if read.retained_resource().is_none() {
                return Err(stale());
            }
            for observation in read.targets() {
                let image = batch.before_image(observation)?;
                native_subjects.insert(
                    canonical_digest(observation.selector().value()).map_err(|_| invalid())?,
                    image.subject.clone(),
                );
                insert_image(&mut before, image.subject, image.bytes)?;
            }
            Some(batch.seal_before(read.targets())?)
        } else {
            if !change.world_projection.is_empty()
                || metadata_route(change.kind).is_none()
                || invocation["bindingId"] != METADATA_BINDING
            {
                return Err(unavailable());
            }
            None
        };
        let batch_bytes = if let Some(batch) = &batch {
            let value = json!({"steps":batch.steps(),"profile":batch.profile_evidence(),
                "selectors":batch.selectors().iter().map(|selector|selector.value()).collect::<Vec<_>>()});
            encode_json(&value)
                .map_err(|_| limit())?
                .len()
                .checked_mul(4)
                .ok_or_else(limit)?
        } else {
            0
        };
        let memory_bytes = encode_json(invocation)
            .map_err(|_| limit())?
            .len()
            .checked_add(
                encode_json(&change.to_arguments()?)
                    .map_err(|_| limit())?
                    .len(),
            )
            .and_then(|n| before.values().try_fold(n, |n, b| n.checked_add(b.len())))
            .and_then(|n| n.checked_add(batch_bytes))
            .and_then(|n| n.checked_add(native_subjects.len().checked_mul(1024)?))
            .ok_or_else(limit)?;
        rpc.check()?;
        self.retain_phase(FrozenPhase {
            authenticated: call.authenticated,
            invocation: invocation.clone(),
            invocation_digest: raw_digest(&encode_json(invocation).map_err(|_| invalid())?),
            change,
            batch,
            before,
            native_subjects,
            memory_bytes,
            attempted: Cell::new(false),
        })
    }
    fn world(
        &self,
        store: &mut DurableStore,
        invocation: &Value,
        phase: &FrozenPhase,
        retained: &mut Vec<BlobRef>,
    ) -> AppResult<WorldRead> {
        let (record, blob) = durable_original(self, store, invocation, Access::ObserveOperation)?;
        let call = self.call(&invocation["context"])?;
        if blob.digest != phase.invocation_digest {
            return Err(stale());
        }
        let Some(batch) = &phase.batch else {
            if phase.change.kind.world_effect() || !phase.change.world_projection.is_empty() {
                return Err(invalid());
            }
            let proof=store.put_blob(&encode_json(&json!({"kind":"typed_no_world_phase",
                "invocationDigest":blob.digest,"preparedChangeSha256":invocation["arguments"]["preparedChange"]["sha256"],
                "nativeKind":phase.change.kind,"worldProjectionCount":0})).map_err(|_|invalid())?).map_err(storage)?;
            retain_ref(retained, proof.clone())?;
            return Ok(WorldRead {
                complete: true,
                settled: true,
                any_change: false,
                all_before: true,
                evidence: vec![proof],
                targets: BTreeMap::new(),
            });
        };
        let job = self.hosts.job_observation_with_store_and_deadline(
            store,
            call.authenticated.principal(),
            invocation,
            &call.context,
            call.budget.deadline(),
        )?;
        let job_blob = store
            .put_blob(&encode_json(&job).map_err(|_| invalid())?)
            .map_err(storage)?;
        retain_ref(retained, job_blob.clone())?;
        if job["invocationId"] != invocation["invocationId"]
            || !job["providerCompleted"].is_boolean()
            || !job["dispatched"].is_boolean()
            || !job["effectObservations"].is_array()
        {
            return Err(invalid());
        }
        let read = match self.reader().observe_original_retained_in_context(
            store,
            &record.operation_id,
            &decode(&invocation["stepId"])?,
            &call.context,
            batch.selectors(),
            text(batch.profile_evidence(), "registryGeneration")?,
        ) {
            Ok(read) => read,
            Err(error) => {
                if let crate::native_targets::NativeTargetError::Host(failure) = &error {
                    retain_ref(retained, failure.response().clone())?;
                }
                return Err(native_error(error));
            }
        };
        if read.retained_resource().is_none() {
            return Err(stale());
        }
        retain_ref(retained, read.response().clone())?;
        let complete = batch.verify_after(read.targets())?;
        let mut targets = BTreeMap::new();
        let mut any_change = false;
        let mut all_before = true;
        for observation in read.targets() {
            // Raw observation bytes came from observationBytesHex. Never encode
            // raw() to construct a before/after image or compare native SHA.
            let selector_digest =
                canonical_digest(observation.selector().value()).map_err(|_| invalid())?;
            let subject = phase
                .native_subjects
                .get(&selector_digest)
                .ok_or_else(stale)?;
            let old = phase.before.get(subject).ok_or_else(stale)?;
            if !observation.full_target() {
                all_before = false;
            } else if old.as_slice() != observation.bytes() {
                any_change = true;
                all_before = false;
            }
            targets.insert(subject.clone(), observation.bytes().to_vec());
        }
        call.check()?;
        Ok(WorldRead {
            complete,
            settled: job["providerCompleted"] == true,
            any_change,
            all_before,
            evidence: vec![job_blob, read.response().clone()],
            targets,
        })
    }
}
struct WorldRead {
    complete: bool,
    settled: bool,
    any_change: bool,
    all_before: bool,
    evidence: Vec<BlobRef>,
    targets: BTreeMap<String, Vec<u8>>,
}
fn retain_ref(retained: &mut Vec<BlobRef>, blob: BlobRef) -> AppResult<()> {
    if !retained.iter().any(|old| old.digest == blob.digest) {
        if retained.len() >= 64 {
            return Err(limit());
        }
        retained.push(blob);
    }
    Ok(())
}
fn insert_image(
    images: &mut BTreeMap<String, Vec<u8>>,
    target: String,
    bytes: Vec<u8>,
) -> AppResult<()> {
    if target.is_empty()
        || target.len() > 512
        || images.len() >= 4096
        || images.contains_key(&target)
        || bytes.len() as u64 > MAX_BYTES
    {
        return Err(limit());
    }
    let total = images
        .values()
        .try_fold(bytes.len(), |n, b| n.checked_add(b.len()))
        .ok_or_else(limit)?;
    if total as u64 > MAX_BYTES {
        return Err(limit());
    }
    images.insert(target, bytes);
    Ok(())
}
fn verify_change_scope(change: &PreparedNativeChange, scope: &WriteScope) -> AppResult<()> {
    scope.validate().map_err(storage)?;
    if scope.project_id != change.project_id
        || change
            .object_ids()
            .iter()
            .any(|id| !scope.object_ids.iter().any(|actual| actual.as_str() == id))
        || change
            .resource_ids()
            .iter()
            .any(|id| !scope.resource_ids.contains(id))
    {
        return Err(forbidden());
    }
    Ok(())
}

struct CommitAuthority {
    shared: Shared,
    call: Call,
    allow_new: bool,
    invocation: Value,
    plan: Value,
    change: PreparedNativeChange,
    world: Option<WorldPhaseObservation>,
}
impl ProjectionAuthority for CommitAuthority {
    fn authorize_operation(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        operation: &OperationRecord,
        _request: &ProjectionCommitRequest,
        replay: bool,
    ) -> StorageResult<()> {
        self.call.check().map_err(app_storage)?;
        if !replay && !self.allow_new {
            return Err(StorageError::NotFound(
                "Original authored projection receipt",
            ));
        }
        if principal != self.call.authenticated.principal() || principal != &operation.principal {
            return Err(app_storage(forbidden()));
        }
        let mut authority = self.shared.authority.clone();
        authority
            .authorize_operation(principal, operation, Access::ObserveOperation)
            .map_err(app_storage)
    }
    fn authorize_projection(
        &mut self,
        store: &DurableStore,
        input: &ProjectionInput<'_>,
        replay: bool,
    ) -> StorageResult<()> {
        self.call.check().map_err(app_storage)?;
        if input.invocation != &self.invocation
            || input.principal != self.call.authenticated.principal()
            || store.plan(&input.operation.plan_id, &input.operation.plan_hash)? != self.plan
        {
            return Err(app_storage(stale()));
        }
        let mut authority = self.shared.authority.clone();
        authority
            .authorize_operation(input.principal, input.operation, Access::ObserveOperation)
            .map_err(app_storage)?;
        if !replay {
            if !self.allow_new || self.call.context != input.invocation["context"] {
                return Err(app_storage(stale()));
            }
            self.shared
                .authority
                .authorize_retained_apply(input.principal, &self.call.context, &self.plan)
                .map_err(app_storage)?;
        }
        let change = &self.change;
        if PreparedNativeChange::from_payload(&json!({"change":input.change}))
            .map_err(app_storage)?
            .to_arguments()
            .map_err(app_storage)?
            != change.to_arguments().map_err(app_storage)?
            || canonical_digest(input.change).map_err(|_| app_storage(invalid()))?
                != *input.change_digest
        {
            return Err(app_storage(stale()));
        }
        verify_change_scope(change, &input.operation.scope).map_err(app_storage)?;
        if !replay {
            let phase = self.shared.phase(input.invocation).map_err(app_storage)?;
            if !phase.attempted.get()
                || phase.change.to_arguments().map_err(app_storage)?
                    != change.to_arguments().map_err(app_storage)?
            {
                return Err(app_storage(stale()));
            }
        }
        verify_sources(store, &self.call, change).map_err(app_storage)?;
        self.call.check().map_err(app_storage)
    }
    fn observe_settled_world_phase(
        &mut self,
        _store: &DurableStore,
        input: &ProjectionInput<'_>,
    ) -> StorageResult<WorldPhaseObservation> {
        if !self.allow_new {
            return Err(StorageError::NotFound(
                "Original authored projection receipt",
            ));
        }
        self.call.check().map_err(app_storage)?;
        let world = self.world.as_ref().ok_or_else(|| app_storage(stale()))?;
        if input.invocation != &self.invocation
            || &world.invocation_digest != input.invocation_digest
            || &world.change_digest != input.change_digest
        {
            return Err(app_storage(stale()));
        }
        Ok(world.clone())
    }
}

fn verify_sources(
    store: &DurableStore,
    call: &Call,
    change: &PreparedNativeChange,
) -> AppResult<()> {
    let project = store.project(&change.project_id).map_err(storage)?;
    let revision: Sha256Digest = decode(&project["revision"])?;
    let mut document_reader =
        OwnedDocumentReader::new(Box::new(SourceAuthority(call.clone())), MAX_DOCUMENT_BYTES)
            .map_err(storage)?;
    let mut left = MAX_BYTES;
    for pin in &change.source_object_pins {
        let loaded = document_reader
            .read_known_history_bytes(
                store,
                call,
                &change.project_id,
                &revision,
                &OwnedDocumentPin {
                    kind: owned_kind(pin.kind),
                    object_id: pin.object_id.clone(),
                    revision: pin.revision.clone(),
                },
            )
            .map_err(storage)?;
        left = left
            .checked_sub(loaded.bytes.len() as u64)
            .ok_or_else(limit)?;
    }
    let mut reader = resource_reader(call)?;
    for reference in change
        .source_resource_pins
        .iter()
        .chain(&change.staged_resources)
        .chain(
            change
                .resource_replacements
                .iter()
                .map(|r| &r.replacement_source),
        )
    {
        let expected = serde_json::to_value(reference).map_err(|_| invalid())?;
        let query =
            if change.source_resource_pins.iter().any(|pin| {
                pin.resource_id == reference.resource_id && pin.sha256 == reference.sha256
            }) {
                ProjectResourceQuery::Exact {
                    resource_id: reference.resource_id.clone(),
                    digest: reference.sha256.clone(),
                }
            } else {
                ProjectResourceQuery::RegisteredImmutable {
                    resource_id: reference.resource_id.clone(),
                }
            };
        let loaded = reader
            .read(
                store,
                call,
                &ProjectResourceRequest {
                    project: &change.project_id,
                    current_project_revision: &revision,
                    query: &query,
                    expected: Some(&expected),
                },
                left,
            )
            .map_err(storage)?;
        left = left
            .checked_sub(loaded.bytes.len() as u64)
            .ok_or_else(limit)?;
    }
    call.check()
}

impl ProviderPort for CompositeProvider {
    fn context(&mut self, principal: &PrincipalId, id: &ContextId) -> AppResult<Value> {
        let (actual, budget) = self
            .shared
            .request
            .current()
            .map_err(|e| AppError::new(e.code, e.message))?;
        check_session(&actual, &budget, id)?;
        if actual.principal() != principal {
            return Err(forbidden());
        }
        self.shared
            .authority
            .current_context_with_deadline(principal, id, budget.deadline())
    }
    fn action_descriptor(&mut self, step: &Value, context: &Value) -> AppResult<Value> {
        let call = self.shared.call(context)?;
        call.check()?;
        if step["bindingId"] == METADATA_BINDING {
            let kind = metadata_kinds()
                .into_iter()
                .find(|kind| metadata_route(*kind).is_some_and(|(id, _)| step["actionId"] == id))
                .ok_or_else(unavailable)?;
            self.shared.metadata.descriptor(kind, context)
        } else {
            HttpProviderPort::with_deadline(self.shared.hosts.clone(), call.budget.deadline())
                .action_descriptor(step, context)
        }
    }
    fn observe_precondition(
        &mut self,
        _condition: &Value,
        _context: &Value,
    ) -> AppResult<Sha256Digest> {
        Err(store_required())
    }
    fn observe_precondition_with_store(
        &mut self,
        store: &DurableStore,
        condition: &Value,
        context: &Value,
    ) -> AppResult<Sha256Digest> {
        validate("Precondition", condition)?;
        let call = self.shared.call(context)?;
        if call.context != *context {
            return Err(stale());
        }
        let subject = text(condition, "subject")?;
        if let Some(id) = subject.strip_prefix("project:") {
            if id != call.project.as_str() {
                return Err(forbidden());
            }
            call.project_acl(
                call.authenticated.principal(),
                Some(&call.id),
                &call.project,
            )
            .map_err(storage)?;
            return field_digest(&store.project(&call.project).map_err(storage)?, "revision");
        }
        if let Some(id) = subject.strip_prefix("policy:") {
            if id != call.project.as_str() {
                return Err(forbidden());
            }
            return field_digest(&call.context, "policyRevision");
        }
        if let Some(id) = subject.strip_prefix("inventory:") {
            if id != call.id.as_str() {
                return Err(forbidden());
            }
            let mut backend = (*self.shared.backend).clone();
            return crate::planning_source::PlanningBackendPort::inventory_with_store(
                &mut backend,
                &PlanningStore::read(store),
                call.authenticated.principal(),
                context,
            )
            .map(|inventory| inventory.revision().clone());
        }
        if let Some(subject) = subject.strip_prefix("owned:") {
            let parts: Vec<_> = subject.split(':').collect();
            if parts.len() != 3 {
                return Err(invalid());
            }
            let kind: OwnedKind = decode(&json!(parts[0]))?;
            let pin = OwnedDocumentPin {
                kind: owned_kind(kind),
                object_id: ObjectId::new(parts[1]).map_err(|_| invalid())?,
                revision: Sha256Digest::new(parts[2]).map_err(|_| invalid())?,
            };
            let project = store.project(&call.project).map_err(storage)?;
            let catalog = ProjectCatalog::from_project(&project)?;
            let current = catalog.owned_pin(kind, parts[1])?;
            let mut reader = OwnedDocumentReader::new(
                Box::new(SourceAuthority(call.clone())),
                MAX_DOCUMENT_BYTES,
            )
            .map_err(storage)?;
            let actual = reader
                .read_known_history_bytes(
                    store,
                    &call,
                    &call.project,
                    catalog.revision(),
                    &OwnedDocumentPin {
                        revision: current.revision.clone(),
                        ..pin
                    },
                )
                .map_err(storage)?;
            return field_digest(&actual.document, "revision");
        }
        // An arbitrary CAS digest grants no private staged-resource read. The
        // application supplies a durable plan/step-bound path separately.
        if subject.starts_with("cas:")
            || subject.starts_with("native:")
            || subject.starts_with("authored:")
            || subject.starts_with("resource:")
            || subject.starts_with("owned-entity:")
        {
            return observe_scoped_target(&self.shared, store, &call, subject, condition);
        }
        Err(unavailable())
    }
    fn observe_plan_precondition_with_store(
        &mut self,
        store: &DurableStore,
        plan: &Value,
        step: &Value,
        condition: &Value,
        context: &Value,
    ) -> AppResult<Sha256Digest> {
        if self.shared.calibration.matches_plan(plan)? {
            // No original Invocation exists at this phase. A locator cannot
            // authorize prepare or substitute an independent factual read.
            return Err(error(
                "CALIBRATION_PRECONDITION_UNAVAILABLE",
                "Independent calibration plan precondition producer is unavailable",
            ));
        }
        if registered_direct_block(step) {
            let (call, scope) =
                admit_plan_step(&self.shared, store, plan, step, condition, context)?;
            NativeObserver::validate_direct_block_step(step, context, &scope)?;
            if text(condition, "subject")?.starts_with("native:") {
                return Err(store_required());
            }
            call.check()?;
            return self.observe_precondition_with_store(store, condition, context);
        }
        let admitted =
            admit_plan_precondition(&self.shared, store, plan, step, condition, context)?;
        let subject = text(condition, "subject")?;
        let reference = &step["arguments"]["preparedChange"];
        if subject == admitted.prepared_subject {
            if condition["kind"] != "resource_hash" || condition["expected"] != reference["sha256"]
            {
                return Err(stale());
            }
            return field_digest(reference, "sha256");
        }
        if subject.starts_with("native:") || subject.starts_with("owned-entity:") {
            return Err(store_required());
        }
        self.observe_precondition_with_store(store, condition, context)
    }
    fn observe_plan_precondition_retained_with_store(
        &mut self,
        store: &mut DurableStore,
        plan: &Value,
        step: &Value,
        condition: &Value,
        context: &Value,
    ) -> AppResult<Sha256Digest> {
        if self.shared.calibration.matches_plan(plan)? {
            return Err(error(
                "CALIBRATION_PRECONDITION_UNAVAILABLE",
                "Independent calibration plan precondition producer is unavailable",
            ));
        }
        let subject = text(condition, "subject")?;
        if registered_direct_block(step) && subject.starts_with("native:") {
            let (call, scope) =
                admit_plan_step(&self.shared, store, plan, step, condition, context)?;
            NativeObserver::validate_direct_block_step(step, context, &scope)?;
            let request = self
                .shared
                .request
                .occupied_witness()
                .map_err(|error| AppError::caused_by(error.code, error.message, error))?;
            let result = self
                .shared
                .block_observer()
                .observe_direct_plan_precondition(store, step, condition, context, &scope);
            return finish_native_observation(
                result,
                (|| {
                    request
                        .check_local()
                        .map_err(|error| AppError::caused_by(error.code, error.message, error))?;
                    call.check()
                })(),
            );
        }
        if !subject.starts_with("native:") && !subject.starts_with("owned-entity:") {
            return self
                .observe_plan_precondition_with_store(store, plan, step, condition, context);
        }
        let admitted =
            admit_plan_precondition(&self.shared, store, plan, step, condition, context)?;
        let project =
            ProjectCatalog::from_project(&store.project(&admitted.call.project).map_err(storage)?)?;
        if project.revision() != &admitted.change.project_base_revision {
            return Err(stale());
        }
        let batch = {
            let planning = PlanningStore::write(store);
            self.shared.backend.prepare_native_batch(
                &planning,
                admitted.call.authenticated.principal(),
                &project,
                &admitted.change,
                context,
            )?
        };
        if batch.scope() != &admitted.scope {
            return Err(stale());
        }
        let read = self
            .shared
            .reader()
            .observe_retained(
                store,
                context,
                batch.selectors(),
                text(batch.profile_evidence(), "registryGeneration")?,
            )
            .map_err(native_error)?;
        if read.retained_resource().is_none() {
            return Err(stale());
        }
        for observation in read.targets() {
            let image = batch.before_image(observation)?;
            if image.subject == subject {
                admitted.call.check()?;
                return Ok(image.digest);
            }
        }
        Err(forbidden())
    }
    fn verify_dependencies(&mut self, pins: &[Value], context: &Value) -> AppResult<()> {
        let call = self.shared.call(context)?;
        call.check()?;
        // The bridge requires exact registered provenance and contract coverage,
        // including this Rust executable's separately installed source pin.
        self.shared
            .hosts
            .verify_registered_dependencies_with_deadline(pins, context, call.budget.deadline())
    }
    fn dispatch(&mut self, _invocation: &Value) -> AppResult<Value> {
        Err(store_required())
    }
    fn persist_dispatch_intent_with_store(
        &mut self,
        store: &mut DurableStore,
        operation: &OperationId,
        step: &StepId,
        invocation: &Value,
        resolution: Option<&BlobRef>,
    ) -> AppResult<mmmm_runtime::storage::StepRecord> {
        let request = self.shared.calibration_request()?;
        if let Some(entered) =
            self.shared
                .enter_calibration(store, &request, invocation, CalibrationAccess::Apply)?
        {
            if &entered.operation().operation_id != operation {
                return Err(stale());
            }
            return entered.persist_intent(
                store,
                step,
                invocation,
                resolution,
                &mut |route, request, original, store| {
                    route.prepare(request, original, &|| entered.check_local(store))
                },
            );
        }
        // Preserve the ordinary Runtime transaction for all other routes.
        match resolution {
            Some(resolution) => {
                store.dispatch_resolved_intent(operation, step, invocation, resolution)
            }
            None => store.dispatch_intent(operation, step, invocation),
        }
        .map_err(|cause| AppError::storage("DISPATCH_REJECTED", cause))
    }
    fn dispatch_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
    ) -> AppResult<Value> {
        let request = self.shared.calibration_request()?;
        if let Some(entered) =
            self.shared
                .enter_calibration(store, &request, invocation, CalibrationAccess::Apply)?
        {
            entered.verify_claim(store, invocation)?;
            let result =
                entered
                    .route()
                    .dispatch_with_store(store, &request, invocation, &|store| {
                        entered.check_local(store)
                    });
            return finish_native_observation(result, entered.check_local(store));
        }
        let (record, blob) = durable_original(&self.shared, store, invocation, Access::Apply)?;
        let call = self.shared.call(&invocation["context"])?;
        let step = record
            .steps
            .iter()
            .find(|s| s.step_id.as_str() == invocation["stepId"].as_str().unwrap_or(""))
            .ok_or_else(invalid)?;
        if registered_direct_block(invocation) {
            let (_, plan, actual, _) = frozen_plan(&self.shared, store, invocation, Access::Apply)?;
            NativeObserver::validate_direct_block_step(&actual, &call.context, &record.scope)?;
            if record.state != OperationState::Running
                || record.reconciliation_required
                || record.cancellation_requested
                || step.finished
                || step.dispatch != DispatchEvidence::IntentDurable
            {
                return Err(error(
                    "DISPATCH_ALREADY_ATTEMPTED",
                    "The exact direct block durable intent is no longer dispatchable",
                ));
            }
            let checkpoint = self
                .shared
                .direct_checkpoint(&call, &record, &plan, Access::Apply)?;
            let result =
                HttpProviderPort::with_deadline(self.shared.hosts.clone(), call.budget.deadline())
                    .dispatch_with_store(store, invocation);
            return finish_native_observation(result, checkpoint.check());
        }
        let phase = self.shared.phase(invocation)?;
        if record.state != OperationState::Running
            || record.reconciliation_required
            || record.cancellation_requested
            || step.finished
            || step.dispatch != DispatchEvidence::IntentDurable
            || phase.invocation_digest != blob.digest
            || !phase.authenticated.same_session(&call.authenticated)
            || phase.attempted.replace(true)
        {
            return Err(error(
                "DISPATCH_ALREADY_ATTEMPTED",
                "Original composite cannot be dispatched again",
            ));
        }
        if phase.change.kind.world_effect() {
            // Java selects only the exact nativeExecutions privately installed
            // for the approved plan. No command or successor is added here.
            let result =
                HttpProviderPort::with_deadline(self.shared.hosts.clone(), call.budget.deadline())
                    .dispatch_with_store(store, invocation)?;
            let result_blob = store
                .put_blob(&encode_json(&result).map_err(|_| invalid())?)
                .map_err(storage)?;
            store
                .append_operation_evidence(&record.operation_id, &result_blob)
                .map_err(storage)?;
            if result["status"] == "complete" {
                self.shared.projection(store, invocation, true)?;
            }
            Ok(result)
        } else {
            let committed = self.shared.projection(store, invocation, true)?;
            metadata_result(&committed)
        }
    }
    fn poll(&mut self, _invocation: &Value, _receipt: Option<&str>) -> AppResult<Option<Value>> {
        Err(store_required())
    }
    fn poll_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        receipt: Option<&str>,
    ) -> AppResult<Option<Value>> {
        let request = self.shared.calibration_request()?;
        if let Some(entered) = self.shared.enter_calibration(
            store,
            &request,
            invocation,
            CalibrationAccess::Observe,
        )? {
            entered.verify_claim(store, invocation)?;
            let result =
                entered
                    .route()
                    .poll_with_store(store, &request, invocation, receipt, &|store| {
                        entered.check_local(store)
                    });
            return finish_native_observation(result, entered.check_local(store));
        }
        let (record, plan, step, call) =
            frozen_plan(&self.shared, store, invocation, Access::ObserveOperation)?;
        durable_original(&self.shared, store, invocation, Access::ObserveOperation)?;
        if registered_direct_block(invocation) {
            NativeObserver::validate_direct_block_step(&step, &call.context, &record.scope)?;
            let checkpoint =
                self.shared
                    .direct_checkpoint(&call, &record, &plan, Access::ObserveOperation)?;
            let result =
                HttpProviderPort::with_deadline(self.shared.hosts.clone(), call.budget.deadline())
                    .poll_with_store(store, invocation, receipt);
            return finish_native_observation(result, checkpoint.check());
        }
        let (change, _, _) = load_change(&self.shared, store, &call, &plan, invocation)?;
        if change.kind.world_effect() {
            let result =
                HttpProviderPort::with_deadline(self.shared.hosts.clone(), call.budget.deadline())
                    .poll_with_store(store, invocation, receipt)?;
            // Even a newly completed host job cannot authorize a missing local
            // phase. Runtime's callback permits only an existing receipt here.
            if result
                .as_ref()
                .is_some_and(|value| value["status"] == "complete")
            {
                self.shared.projection(store, invocation, false)?;
            }
            Ok(result)
        } else {
            self.shared
                .projection(store, invocation, false)
                .and_then(|r| metadata_result(&r))
                .map(Some)
        }
    }
    fn request_cancel(&mut self, _invocation: &Value, _receipt: Option<&str>) -> AppResult<()> {
        Err(store_required())
    }
    fn request_cancel_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        receipt: Option<&str>,
    ) -> AppResult<()> {
        self.cancel_original_with_store(store, invocation, receipt)
    }
    fn registered_read_with_store(
        &mut self,
        store: &DurableStore,
        request: &Value,
        context: &Value,
    ) -> AppResult<Value> {
        let call = self.shared.call(context)?;
        call.check()?;
        HttpProviderPort::with_deadline(self.shared.hosts.clone(), call.budget.deadline())
            .registered_read_with_store(store, request, context)
    }
}
struct AdmittedPrecondition {
    call: Call,
    change: PreparedNativeChange,
    scope: WriteScope,
    prepared_subject: String,
}
fn admit_plan_step(
    shared: &Shared,
    store: &DurableStore,
    plan: &Value,
    step: &Value,
    condition: &Value,
    context: &Value,
) -> AppResult<(Call, WriteScope)> {
    let call = shared.call(context)?;
    validate("ExecutionPlan", plan)?;
    validate("PlanStep", step)?;
    validate("Precondition", condition)?;
    let hash =
        mmmm_contracts::verify_projected_digest("ExecutionPlan", plan).map_err(|_| stale())?;
    let stored = store
        .plan(&decode(&plan["planId"])?, &hash)
        .map_err(storage)?;
    if stored != *plan
        || plan["projectId"] != call.project.as_str()
        || call.context != *context
        || plan["steps"]
            .as_array()
            .is_none_or(|steps| !steps.iter().any(|actual| actual == step))
        || plan["preconditions"]
            .as_array()
            .is_none_or(|conditions| !conditions.iter().any(|actual| actual == condition))
        || step["contextId"] != call.id.as_str()
        || step["effect"] != "write"
        || step["resultBindings"]
            .as_array()
            .is_none_or(|bindings| !bindings.is_empty())
        || plan["contextPins"].as_array().is_none_or(|pins| {
            !pins.iter().any(|pin| {
                pin["contextId"] == call.id.as_str()
                    && pin["contextDigest"] == context["contextDigest"]
            })
        })
    {
        return Err(stale());
    }
    let scope: WriteScope = decode(&plan["scope"])?;
    shared.authority.authorize_with_deadline(
        call.authenticated.principal(),
        &call.project,
        Access::Apply,
        Some(context),
        Some(plan),
        call.budget.deadline(),
    )?;
    shared.authority.authorize_retained_scope(
        call.authenticated.principal(),
        &call.project,
        &call.id,
        &field_digest(context, "policyRevision")?,
        &plan["scope"],
    )?;
    call.check()?;
    Ok((call, scope))
}
fn admit_plan_precondition(
    shared: &Shared,
    store: &DurableStore,
    plan: &Value,
    step: &Value,
    condition: &Value,
    context: &Value,
) -> AppResult<AdmittedPrecondition> {
    let (call, scope) = admit_plan_step(shared, store, plan, step, condition, context)?;
    let reference = &step["arguments"]["preparedChange"];
    let prepared_subject = format!(
        "cas:{}:{}",
        text(reference, "resourceId")?,
        text(reference, "sha256")?
    );
    if step["resourcesRead"]
        .as_array()
        .is_none_or(|reads| !reads.iter().any(|v| v.as_str() == Some(&prepared_subject)))
    {
        return Err(stale());
    }
    let synthetic_arguments = json!({"arguments":step["arguments"],"bindingId":step["bindingId"],
        "actionId":step["actionId"],"actionDigest":step["actionDigest"],
        "implementationDigest":step["implementationDigest"],"context":context});
    let (change, rpc, _) = load_change(shared, store, &call, plan, &synthetic_arguments)?;
    verify_change_scope(&change, &scope)?;
    verify_sources(store, &rpc, &change)?;
    call.check()?;
    Ok(AdmittedPrecondition {
        call,
        change,
        scope,
        prepared_subject,
    })
}
fn metadata_result(result: &ProjectionCommitResult) -> AppResult<Value> {
    let receipt = serde_json::to_value(&result.receipt).map_err(|_| invalid())?;
    let value = json!({"contractVersion":mmmm_contracts::CONTRACT_VERSION,"status":"complete",
        "effects":"recorded","diagnostics":[],"artifacts":[],
        "data":{"projectRevision":result.receipt.project_revision,
        "projectionReceiptDigest":raw_digest(&encode_json(&receipt).map_err(|_|invalid())?),"replayed":result.replayed}});
    validate("ProviderResult", &value)?;
    Ok(value)
}

fn observe_scoped_target(
    _shared: &Shared,
    store: &DurableStore,
    call: &Call,
    subject: &str,
    _condition: &Value,
) -> AppResult<Sha256Digest> {
    if let Some(subject) = subject.strip_prefix("cas:") {
        let (id, sha) = subject.split_once(':').ok_or_else(invalid)?;
        call.source_acl("resourceIds", id).map_err(storage)?;
        let query = ProjectResourceQuery::RegisteredImmutable {
            resource_id: ResourceId::new(id).map_err(|_| invalid())?,
        };
        let revision = field_digest(&store.project(&call.project).map_err(storage)?, "revision")?;
        let actual = resource_reader(call)?
            .metadata(
                store,
                call,
                &ProjectResourceRequest {
                    project: &call.project,
                    current_project_revision: &revision,
                    query: &query,
                    expected: None,
                },
            )
            .map_err(storage)?;
        Sha256Digest::new(sha).map_err(|_| invalid())?;
        return Ok(actual.blob.digest);
    }
    if subject.starts_with("authored:") || subject.starts_with("resource:") {
        return read_authored_target(store, call, subject).map(|bytes| raw_digest(&bytes));
    }
    // Native preflight needs the exact durable Plan/step association and early
    // acquired-response retention; this read-only fallback cannot issue it.
    Err(store_required())
}
fn read_authored_target(store: &DurableStore, call: &Call, target: &str) -> AppResult<Vec<u8>> {
    let project = store.project(&call.project).map_err(storage)?;
    let catalog = ProjectCatalog::from_project(&project)?;
    if let Some(subject) = target.strip_prefix("authored:") {
        let (kind, id) = subject.split_once(':').ok_or_else(invalid)?;
        let kind: OwnedKind = decode(&json!(kind))?;
        let pin = catalog.owned_pin(kind, id)?;
        let mut reader =
            OwnedDocumentReader::new(Box::new(SourceAuthority(call.clone())), MAX_DOCUMENT_BYTES)
                .map_err(storage)?;
        let actual = reader
            .read_known_history_bytes(
                store,
                call,
                &call.project,
                catalog.revision(),
                &OwnedDocumentPin {
                    kind: owned_kind(kind),
                    object_id: pin.object_id.clone(),
                    revision: pin.revision.clone(),
                },
            )
            .map_err(storage)?;
        return Ok(actual.bytes);
    }
    if let Some(id) = target.strip_prefix("resource:") {
        let query = ProjectResourceQuery::Current {
            resource_id: ResourceId::new(id).map_err(|_| invalid())?,
        };
        let mut reader = resource_reader(call)?;
        let request = ProjectResourceRequest {
            project: &call.project,
            current_project_revision: catalog.revision(),
            query: &query,
            expected: None,
        };
        let meta = reader.metadata(store, call, &request).map_err(storage)?;
        let expected = meta.resource;
        return reader
            .read(
                store,
                call,
                &ProjectResourceRequest {
                    expected: Some(&expected),
                    ..request
                },
                MAX_BYTES,
            )
            .map(|read| read.bytes)
            .map_err(storage);
    }
    Err(unavailable())
}
fn final_authored_read(
    store: &DurableStore,
    call: &Call,
    change: &PreparedNativeChange,
    before: &BTreeMap<String, Vec<u8>>,
) -> AppResult<(bool, Vec<DirectChange>, Value)> {
    let mut reader = resource_reader(call)?;
    let project = reader
        .current_project(store, call, &change.project_id, MAX_DOCUMENT_BYTES)
        .map_err(storage)?;
    if project != change.project_after {
        return Ok((
            false,
            Vec::new(),
            json!({"kind":"authored_readback","projectRevision":project["revision"],"matchesPrepared":false}),
        ));
    }
    let revision: Sha256Digest = decode(&project["revision"])?;
    let mut documents =
        OwnedDocumentReader::new(Box::new(SourceAuthority(call.clone())), MAX_DOCUMENT_BYTES)
            .map_err(storage)?;
    let mut direct = Vec::new();
    let mut observed = Vec::new();
    let mut left = MAX_BYTES;
    for change in &change.document_changes {
        let pin = OwnedDocumentPin {
            kind: owned_kind(change.kind),
            object_id: ObjectId::new(&change.object_id).map_err(|_| invalid())?,
            revision: change.after_revision.clone(),
        };
        let loaded = documents
            .read_known_history_bytes(store, call, &call.project, &revision, &pin)
            .map_err(storage)?;
        left = left
            .checked_sub(loaded.bytes.len() as u64)
            .ok_or_else(limit)?;
        if loaded.document != change.after {
            return Err(stale());
        }
        let target = format!("authored:{}:{}", pin.kind.as_str(), pin.object_id);
        if let Some(old) = before.get(&target) {
            direct.push(DirectChange {
                target: target.clone(),
                before: old.clone(),
                after: loaded.bytes,
            });
        }
        observed
            .push(json!({"target":target,"rawSha256":loaded.blob.digest,"revision":pin.revision}));
    }
    for replacement in &change.resource_replacements {
        let query = ProjectResourceQuery::Current {
            resource_id: replacement.target_resource_id.clone(),
        };
        let mut expected =
            serde_json::to_value(&replacement.replacement_source).map_err(|_| invalid())?;
        expected["resourceId"] = json!(replacement.target_resource_id);
        let loaded = reader
            .read(
                store,
                call,
                &ProjectResourceRequest {
                    project: &call.project,
                    current_project_revision: &revision,
                    query: &query,
                    expected: Some(&expected),
                },
                left,
            )
            .map_err(storage)?;
        left = left
            .checked_sub(loaded.bytes.len() as u64)
            .ok_or_else(limit)?;
        let target = format!("resource:{}", replacement.target_resource_id);
        if let Some(old) = before.get(&target) {
            direct.push(DirectChange {
                target: target.clone(),
                before: old.clone(),
                after: loaded.bytes,
            });
        }
        observed.push(json!({"target":target,"rawSha256":loaded.registered.blob.digest}));
    }
    for reference in &change.staged_resources {
        if !project["resourceIds"]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|id| id == reference.resource_id.as_str()))
        {
            continue;
        }
        let query = ProjectResourceQuery::Current {
            resource_id: reference.resource_id.clone(),
        };
        let expected = serde_json::to_value(reference).map_err(|_| invalid())?;
        let metadata = reader
            .metadata(
                store,
                call,
                &ProjectResourceRequest {
                    project: &call.project,
                    current_project_revision: &revision,
                    query: &query,
                    expected: Some(&expected),
                },
            )
            .map_err(storage)?;
        left = left
            .checked_sub(metadata.blob.byte_length)
            .ok_or_else(limit)?;
        observed.push(json!({"target":format!("resource:{}",reference.resource_id),"rawSha256":metadata.blob.digest}));
    }
    call.check()?;
    Ok((
        true,
        direct,
        json!({"kind":"authored_readback","projectRevision":revision,"matchesPrepared":true,"targets":observed}),
    ))
}

impl IndependentObserverPort for CompositeObserver {
    fn validate_capture_target(
        &mut self,
        invocation: &Value,
        scope: &WriteScope,
        target: &str,
    ) -> AppResult<()> {
        self.shared.call(&invocation["context"])?;
        if registered_direct_block(invocation) {
            return self
                .shared
                .block_observer()
                .validate_capture_target(invocation, scope, target);
        }
        let phase = self.shared.phase(invocation)?;
        verify_change_scope(&phase.change, scope)?;
        if !phase.before.contains_key(target) {
            return Err(forbidden());
        }
        Ok(())
    }
    fn capture_before_with_store(
        &mut self,
        store: &DurableStore,
        invocation: &Value,
        scope: &WriteScope,
    ) -> AppResult<Option<BeforeCapture>> {
        let request = self.shared.calibration_request()?;
        if let Some(entered) =
            self.shared
                .enter_calibration(store, &request, invocation, CalibrationAccess::Apply)?
        {
            return calibration_before(&entered, store, scope);
        }
        if registered_direct_block(invocation) {
            let (record, _, step, call) =
                frozen_plan(&self.shared, store, invocation, Access::Apply)?;
            if &record.scope != scope {
                return Err(forbidden());
            }
            NativeObserver::validate_direct_block_step(&step, &call.context, scope)?;
            return self
                .shared
                .block_observer()
                .capture_before_with_store(store, invocation, scope);
        }
        let _ = (store, invocation, scope);
        Err(store_required())
    }
    fn capture_before_retained_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        scope: &WriteScope,
    ) -> AppResult<Option<BeforeCapture>> {
        let request = self.shared.calibration_request()?;
        if let Some(entered) =
            self.shared
                .enter_calibration(store, &request, invocation, CalibrationAccess::Apply)?
        {
            return calibration_before(&entered, store, scope);
        }
        if registered_direct_block(invocation) {
            let (record, _, step, call) =
                frozen_plan(&self.shared, store, invocation, Access::Apply)?;
            if &record.scope != scope {
                return Err(forbidden());
            }
            NativeObserver::validate_direct_block_step(&step, &call.context, scope)?;
            return self
                .shared
                .block_observer()
                .capture_before_retained_with_store(store, invocation, scope);
        }
        let phase = self.shared.seal(store, invocation, scope)?;
        Ok(Some(BeforeCapture {
            invocation_id: decode(&invocation["invocationId"])?,
            binding_id: decode(&invocation["bindingId"])?,
            context_digest: field_digest(invocation, "contextDigest")?,
            implementation_digest: field_digest(invocation, "implementationDigest")?,
            arguments_digest: field_digest(invocation, "argumentsDigest")?,
            images: phase
                .before
                .iter()
                .map(|(target, bytes)| BeforeImage {
                    target: target.clone(),
                    bytes: bytes.clone(),
                })
                .collect(),
        }))
    }
    fn readback(
        &mut self,
        _invocation: &Value,
        _scope: &WriteScope,
    ) -> AppResult<ReadbackEvidence> {
        Err(store_required())
    }
    fn readback_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        scope: &WriteScope,
    ) -> AppResult<ReadbackEvidence> {
        let request = self.shared.calibration_request()?;
        if let Some(entered) = self.shared.enter_calibration(
            store,
            &request,
            invocation,
            CalibrationAccess::Observe,
        )? {
            entered.verify_claim(store, invocation)?;
            let result = if &entered.operation().scope != scope {
                Err(forbidden())
            } else {
                // calibration_run_source requires an actual independent source
                // receipt/digest. Do not synthesize these from invocation args.
                Err(error(
                    "CALIBRATION_READBACK_UNAVAILABLE",
                    "Independent calibration readback source producer is unavailable",
                ))
            };
            return finish_native_observation(result, entered.check_local(store));
        }
        if registered_direct_block(invocation) {
            let (record, _, step, call) =
                frozen_plan(&self.shared, store, invocation, Access::ObserveOperation)?;
            if &record.scope != scope {
                return Err(forbidden());
            }
            durable_original(&self.shared, store, invocation, Access::ObserveOperation)?;
            NativeObserver::validate_direct_block_step(&step, &call.context, scope)?;
            return self
                .shared
                .block_observer()
                .readback_with_store(store, invocation, scope);
        }
        let (record, _, _, call) =
            frozen_plan(&self.shared, store, invocation, Access::ObserveOperation)?;
        if &record.scope != scope {
            return Err(forbidden());
        }
        let (_, plan, _, _) =
            frozen_plan(&self.shared, store, invocation, Access::ObserveOperation)?;
        durable_original(&self.shared, store, invocation, Access::ObserveOperation)?;
        let (change, rpc, _) = load_change(&self.shared, store, &call, &plan, invocation)?;
        let phase = match self.shared.phase(invocation) {
            Ok(phase) => Some(phase),
            Err(error) if error.code == "NATIVE_PHASE_UNAVAILABLE" => None,
            Err(error) => return Err(error),
        };
        let mut evidence = Vec::new();
        let world = if change.kind.world_effect()
            && let Some(phase) = &phase
        {
            let observed = self.shared.world(store, invocation, phase, &mut evidence);
            for blob in &evidence {
                store
                    .append_operation_evidence(&record.operation_id, blob)
                    .map_err(storage)?;
            }
            Some(observed?)
        } else if change.kind.world_effect() {
            // Restart never recreates a batch from a successor Project head.
            // A committed receipt remains actual evidence of authored effects,
            // but its old proof does not establish fresh final world state.
            Some(WorldRead {
                complete: false,
                settled: false,
                any_change: false,
                all_before: false,
                evidence: Vec::new(),
                targets: BTreeMap::new(),
            })
        } else {
            None
        };
        let committed = match self.shared.projection(store, invocation, false) {
            Ok(receipt) => Some(receipt),
            Err(error) if missing_receipt(&error) => None,
            Err(error) => return Err(error),
        };
        let empty = BTreeMap::new();
        let before = phase.as_ref().map(|p| &p.before).unwrap_or(&empty);
        let (docs_complete, mut direct, docs) = if committed.is_some() {
            final_authored_read(store, &rpc, &change, before)?
        } else {
            (
                false,
                Vec::new(),
                json!({"kind":"authored_readback","matchesPrepared":false,"receipt":"absent"}),
            )
        };
        if let Some(world) = &world {
            for (target, after) in &world.targets {
                if let Some(old) = before.get(target) {
                    direct.push(DirectChange {
                        target: target.clone(),
                        before: old.clone(),
                        after: after.clone(),
                    });
                }
            }
        }
        let (effect, settled) =
            composite_effect(world.as_ref(), docs_complete, committed.is_some());
        rpc.check()?;
        Ok(ReadbackEvidence {
            invocation_id: decode(&invocation["invocationId"])?,
            binding_id: decode(&invocation["bindingId"])?,
            context_digest: field_digest(invocation, "contextDigest")?,
            implementation_digest: field_digest(invocation, "implementationDigest")?,
            arguments_digest: field_digest(invocation, "argumentsDigest")?,
            effect,
            settled,
            evidence: json!({"kind":"composite_readback","sourceRefs":evidence,"worldEvidence":evidence,"authored":docs,
                "projectionReceipt":committed.as_ref().map(|r|&r.receipt),"originalInvocationId":invocation["invocationId"]}),
            direct_changes: direct,
        })
    }
    fn read_target(&mut self, _invocation: &Value, _target: &str) -> AppResult<Vec<u8>> {
        Err(store_required())
    }
    fn read_target_with_store(
        &mut self,
        store: &DurableStore,
        invocation: &Value,
        target: &str,
    ) -> AppResult<Vec<u8>> {
        let request = self.shared.calibration_request()?;
        if let Some(entered) = self.shared.enter_calibration(
            store,
            &request,
            invocation,
            CalibrationAccess::Observe,
        )? {
            entered.verify_claim(store, invocation)?;
            return finish_native_observation(
                Err(error(
                    "CALIBRATION_RECOVERY_UNSUPPORTED",
                    "Calibration cannot use an ordinary recovery target route",
                )),
                entered.check_local(store),
            );
        }
        if registered_direct_block(invocation) {
            let (record, _, step, call) =
                frozen_plan(&self.shared, store, invocation, Access::ObserveOperation)?;
            durable_original(&self.shared, store, invocation, Access::ObserveOperation)?;
            NativeObserver::validate_direct_block_step(&step, &call.context, &record.scope)?;
            return self
                .shared
                .block_observer()
                .read_target_with_store(store, invocation, target);
        }
        durable_original(&self.shared, store, invocation, Access::ObserveOperation)?;
        let phase = self.shared.phase(invocation)?;
        if !phase.before.contains_key(target) {
            return Err(forbidden());
        }
        let call = self.shared.call(&invocation["context"])?;
        if target.starts_with("authored:") || target.starts_with("resource:") {
            return read_authored_target(store, &call, target);
        }
        Err(error(
            "NATIVE_RETENTION_REQUIRED",
            "Current native recovery reads require the mutable acquisition boundary",
        ))
    }
    fn read_target_retained_with_store(
        &mut self,
        store: &mut DurableStore,
        invocation: &Value,
        target: &str,
    ) -> AppResult<Vec<u8>> {
        let request = self.shared.calibration_request()?;
        if let Some(entered) = self.shared.enter_calibration(
            store,
            &request,
            invocation,
            CalibrationAccess::Observe,
        )? {
            entered.verify_claim(store, invocation)?;
            return finish_native_observation(
                Err(error(
                    "CALIBRATION_RECOVERY_UNSUPPORTED",
                    "Calibration cannot use an ordinary recovery target route",
                )),
                entered.check_local(store),
            );
        }
        if registered_direct_block(invocation) {
            let (record, _, step, call) =
                frozen_plan(&self.shared, store, invocation, Access::ObserveOperation)?;
            durable_original(&self.shared, store, invocation, Access::ObserveOperation)?;
            NativeObserver::validate_direct_block_step(&step, &call.context, &record.scope)?;
            return self
                .shared
                .block_observer()
                .read_target_retained_with_store(store, invocation, target);
        }
        let (record, _) =
            durable_original(&self.shared, store, invocation, Access::ObserveOperation)?;
        let phase = self.shared.phase(invocation)?;
        if !phase.before.contains_key(target) {
            return Err(forbidden());
        }
        let call = self.shared.call(&invocation["context"])?;
        if target.starts_with("authored:") || target.starts_with("resource:") {
            return read_authored_target(store, &call, target);
        }
        let mut evidence = Vec::new();
        let observed = self.shared.world(store, invocation, &phase, &mut evidence);
        for blob in &evidence {
            store
                .append_operation_evidence(&record.operation_id, blob)
                .map_err(storage)?;
        }
        let world = observed?;
        call.check()?;
        world.targets.get(target).cloned().ok_or_else(forbidden)
    }
}
fn missing_receipt(error: &AppError) -> bool {
    use std::error::Error;
    matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<StorageError>()),
        Some(StorageError::NotFound(
            "Original authored projection receipt"
        ))
    )
}
fn composite_effect(
    world: Option<&WorldRead>,
    docs_complete: bool,
    authored_committed: bool,
) -> (EffectEvidence, bool) {
    match world {
        Some(world) if world.complete && world.settled && docs_complete => {
            (EffectEvidence::CompleteConfirmed, true)
        }
        Some(world) if world.any_change || world.complete => {
            (EffectEvidence::SomeConfirmed, world.settled)
        }
        Some(world) if authored_committed => (EffectEvidence::SomeConfirmed, world.settled),
        Some(world) if world.all_before && world.settled => (EffectEvidence::NoneConfirmed, true),
        Some(_) => (EffectEvidence::Unknown, false),
        None if docs_complete => (EffectEvidence::CompleteConfirmed, true),
        None if authored_committed => (EffectEvidence::SomeConfirmed, true),
        None => (EffectEvidence::Unknown, false),
    }
}
fn native_error(source: crate::native_targets::NativeTargetError) -> AppError {
    use crate::native_targets::NativeTargetError;
    match source {
        NativeTargetError::Authority(error) => error,
        NativeTargetError::Storage(error) => AppError::storage("NATIVE_OBSERVATION_FAILED", error),
        NativeTargetError::Retention(error) => {
            AppError::caused_by(error.code, error.message, error)
        }
        NativeTargetError::Invalid => AppError::new(
            "NATIVE_OBSERVATION_FAILED",
            "Original native observation could not be verified",
        ),
        NativeTargetError::Host(failure) => AppError::caused_by(
            "NATIVE_OBSERVATION_FAILED",
            "Original native observation could not be verified",
            failure.causal_snapshot(),
        ),
    }
}

#[derive(Clone)]
struct Call {
    authenticated: AuthenticatedPrincipal,
    budget: RequestBudget,
    authority: LocalAuthority,
    context: Value,
    id: ContextId,
    project: ProjectId,
    // Only an exact approved durable step may add its own prepared/staged CAS
    // references. This is never populated from an arbitrary precondition.
    allowed_resources: BTreeMap<ResourceId, Value>,
    local_witness: Option<HostContextWitness>,
    local_only: bool,
}

/// Held for exactly one direct SDK RPC. Postchecks use these original local
/// witnesses and current ACL records, without another RPC or a new deadline.
struct DirectCallCheckpoint<'a> {
    call: &'a Call,
    operation: &'a OperationRecord,
    plan: &'a Value,
    access: Access,
    request: RequestContextWitness,
    host: HostContextWitness,
}
impl DirectCallCheckpoint<'_> {
    fn check(&self) -> AppResult<()> {
        self.request.check_local().map_err(service_cause)?;
        self.host.check_local()?;
        self.call.check()?;
        authorize_direct_retained(
            &self.call.authority,
            self.call.authenticated.principal(),
            &self.call.context,
            self.operation,
            self.plan,
            self.access,
        )?;
        self.host.check_local()?;
        self.request.check_local().map_err(service_cause)
    }
}
fn authorize_direct_retained(
    authority: &LocalAuthority,
    principal: &PrincipalId,
    context: &Value,
    operation: &OperationRecord,
    plan: &Value,
    access: Access,
) -> AppResult<()> {
    if !matches!(access, Access::Apply | Access::ObserveOperation)
        || &operation.principal != principal
        || context["principalRef"] != principal.as_str()
        || context["projectId"] != operation.project_id.as_str()
        || context["contextId"] != operation.context_id.as_str()
        || plan["planId"] != operation.plan_id.as_str()
        || plan["planHash"] != operation.plan_hash.as_str()
        || !crate::authority::scope_contains(&context["scope"], &json!(operation.scope))
    {
        return Err(forbidden());
    }
    // Observe uses current full read authority, including after old Apply
    // approval expiry. Dispatch additionally requires the exact live approval.
    let mut current = authority.clone();
    current.authorize_operation(principal, operation, Access::ObserveOperation)?;
    current.authorize_retained_scope(
        principal,
        &operation.project_id,
        &operation.context_id,
        &field_digest(context, "policyRevision")?,
        &json!(operation.scope),
    )?;
    if access == Access::Apply {
        current.authorize_retained_apply(principal, context, plan)?;
    }
    Ok(())
}
impl Call {
    fn check(&self) -> AppResult<()> {
        check_session(&self.authenticated, &self.budget, &self.id)?;
        if let Some(witness) = &self.local_witness {
            witness.check_local()?;
        }
        if self.local_only {
            self.authority.authorize_retained_scope(
                self.authenticated.principal(),
                &self.project,
                &self.id,
                &field_digest(&self.context, "policyRevision")?,
                &self.context["scope"],
            )?;
        }
        Ok(())
    }
    fn project_acl(
        &self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
    ) -> StorageResult<()> {
        self.check().map_err(app_storage)?;
        if principal != self.authenticated.principal()
            || context != Some(&self.id)
            || project != &self.project
        {
            return Err(app_storage(forbidden()));
        }
        if self.local_only {
            // Current permission and grant checks without a native context read.
            let mut authority = self.authority.clone();
            authority
                .authorize(principal, project, Access::ReadProject, None, None)
                .map_err(app_storage)
        } else {
            self.authority
                .authorize_with_deadline(
                    principal,
                    project,
                    Access::ReadProject,
                    Some(&self.context),
                    None,
                    self.budget.deadline(),
                )
                .map_err(app_storage)
        }
    }
    fn source_acl(&self, field: &str, id: &str) -> StorageResult<()> {
        self.project_acl(
            self.authenticated.principal(),
            Some(&self.id),
            &self.project,
        )?;
        if self.context["scope"][field]
            .as_array()
            .is_none_or(|values| !values.iter().any(|v| v.as_str() == Some(id)))
        {
            return Err(app_storage(forbidden()));
        }
        self.check().map_err(app_storage)
    }
}
impl ProjectSourceRpcContext for Call {
    fn check(&self) -> StorageResult<()> {
        self.check().map_err(app_storage)
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check().map_err(app_storage)?;
        Ok(self.authenticated.principal().clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        Some(&self.id)
    }
}
impl ProjectionRpcContext for Call {
    fn check(&self) -> StorageResult<()> {
        self.check().map_err(app_storage)
    }
    fn principal_for_context(&self, id: &ContextId) -> StorageResult<PrincipalId> {
        self.check().map_err(app_storage)?;
        if id != &self.id {
            return Err(app_storage(forbidden()));
        }
        Ok(self.authenticated.principal().clone())
    }
}
struct SourceAuthority(Call);
impl OwnedDocumentAuthority for SourceAuthority {
    fn authorize_read(
        &mut self,
        principal: &PrincipalId,
        context: &ContextId,
        project: &ProjectId,
        _revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> StorageResult<()> {
        self.0.project_acl(principal, Some(context), project)?;
        self.0.source_acl("objectIds", pin.object_id.as_str())
    }
}
impl ProjectResourceAuthority for SourceAuthority {
    fn authorize_project_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        _revision: &Sha256Digest,
    ) -> StorageResult<()> {
        self.0.project_acl(principal, context, project)
    }
    fn authorize_resource_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> StorageResult<()> {
        self.0.project_acl(principal, context, project)?;
        if resource.owner != ResourceOwner::Project(project.clone()) {
            return Err(app_storage(forbidden()));
        }
        let id: ResourceId = serde_json::from_value(resource.resource["resourceId"].clone())
            .map_err(|_| app_storage(invalid()))?;
        if self.0.allowed_resources.get(&id) == Some(&resource.resource) {
            return self.0.check().map_err(app_storage);
        }
        self.0.source_acl("resourceIds", id.as_str())
    }
}

fn calibration_before(
    entered: &EnteredCalibration<'_>,
    store: &DurableStore,
    scope: &WriteScope,
) -> AppResult<Option<BeforeCapture>> {
    let result = (|| {
        if &entered.operation().scope != scope || entered.plan()["scope"] != json!(scope) {
            return Err(forbidden());
        }
        // An actual null runner rejects here, before any durable intent.
        // Readiness alone cannot manufacture an independent before-image.
        entered
            .route()
            .prepare(entered.request(), entered.original(), &|| {
                entered.check_local(store)
            })?;
        Err(error(
            "CALIBRATION_CAPTURE_UNAVAILABLE",
            "Independent calibration before-capture producer is unavailable",
        ))
    })();
    finish_native_observation(result, entered.check_local(store))
}

fn frozen_plan(
    shared: &Shared,
    store: &DurableStore,
    invocation: &Value,
    access: Access,
) -> AppResult<(OperationRecord, Value, Value, Call)> {
    validate("Invocation", invocation)?;
    let operation: OperationId = decode(&invocation["operationId"])?;
    let record = store.operation(&operation).map_err(storage)?;
    let call = shared.call(&invocation["context"])?;
    if record.principal != *call.authenticated.principal()
        || record.project_id != call.project
        || record.context_id != call.id
    {
        return Err(forbidden());
    }
    let plan = store
        .plan(&record.plan_id, &record.plan_hash)
        .map_err(storage)?;
    let step = plan["steps"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .find(|s| s["stepId"] == invocation["stepId"])
        .ok_or_else(invalid)?
        .clone();
    for key in [
        "bindingId",
        "actionId",
        "actionContractVersion",
        "actionDigest",
        "implementationDigest",
        "arguments",
    ] {
        if step[key] != invocation[key] {
            return Err(stale());
        }
    }
    if step["effect"] != "write"
        || step["verificationRequirement"] != "independent_readback"
        || step["contextId"] != call.id.as_str()
        || step["resultBindings"]
            .as_array()
            .is_none_or(|a| !a.is_empty())
        || plan["scope"] != serde_json::to_value(&record.scope).map_err(|_| invalid())?
        || invocation["argumentsDigest"]
            != canonical_digest(&invocation["arguments"])
                .map_err(|_| invalid())?
                .as_str()
        || invocation["contextDigest"] != invocation["context"]["contextDigest"]
    {
        return Err(stale());
    }
    let mut authority = shared.authority.clone();
    if access != Access::Apply {
        authority.authorize_operation(call.authenticated.principal(), &record, access)?;
    }
    if access == Access::Apply {
        if call.context != invocation["context"] {
            return Err(stale());
        }
        shared.authority.authorize_with_deadline(
            call.authenticated.principal(),
            &record.project_id,
            Access::Apply,
            Some(&call.context),
            Some(&plan),
            call.budget.deadline(),
        )?;
        shared.authority.authorize_retained_scope(
            call.authenticated.principal(),
            &record.project_id,
            &record.context_id,
            &field_digest(&call.context, "policyRevision")?,
            &serde_json::to_value(&record.scope).map_err(|_| invalid())?,
        )?;
    }
    call.check()?;
    Ok((record, plan, step, call))
}
fn durable_original(
    shared: &Shared,
    store: &DurableStore,
    invocation: &Value,
    access: Access,
) -> AppResult<(OperationRecord, BlobRef)> {
    let (record, _, _, call) = frozen_plan(shared, store, invocation, access)?;
    let step: StepId = decode(&invocation["stepId"])?;
    let actual = store
        .stored_invocation_checked(&record.operation_id, &step, MAX_DOCUMENT_BYTES, || {
            call.check().map_err(app_storage)
        })
        .map_err(storage)?;
    if actual != *invocation {
        return Err(stale());
    }
    Ok((
        record,
        store
            .stored_invocation_blob(&decode(&invocation["operationId"])?, &step)
            .map_err(storage)?,
    ))
}
fn load_change(
    shared: &Shared,
    store: &DurableStore,
    call: &Call,
    plan: &Value,
    invocation: &Value,
) -> AppResult<(PreparedNativeChange, Call, Sha256Digest)> {
    let arguments = invocation["arguments"].as_object().ok_or_else(invalid)?;
    if arguments.len() != 1 || !arguments.contains_key("preparedChange") {
        return Err(unavailable());
    }
    let reference = &arguments["preparedChange"];
    validate("ResourceRef", reference)?;
    if reference["mediaType"] != mmmm_planner::PREPARED_CHANGE_MEDIA_TYPE {
        return Err(invalid());
    }
    let id: ResourceId = decode(&reference["resourceId"])?;
    let mut rpc = call.clone();
    rpc.allowed_resources.insert(id.clone(), reference.clone());
    let project = store.project(&call.project).map_err(storage)?;
    let revision: Sha256Digest = decode(&project["revision"])?;
    let query = ProjectResourceQuery::RegisteredImmutable { resource_id: id };
    let mut reader = resource_reader(&rpc)?;
    let loaded = reader
        .read(
            store,
            &rpc,
            &ProjectResourceRequest {
                project: &call.project,
                current_project_revision: &revision,
                query: &query,
                expected: Some(reference),
            },
            MAX_DOCUMENT_BYTES,
        )
        .map_err(storage)?;
    let payload = parse_json(&loaded.bytes).map_err(|_| invalid())?;
    let change = PreparedNativeChange::from_payload(&payload)?;
    if change.project_id != call.project
        || plan["projectBaseRevision"] != change.project_base_revision.as_str()
        || reference["sha256"] != raw_digest(&loaded.bytes).as_str()
    {
        return Err(stale());
    }
    if change.kind == NativeKind::Recovery {
        return Err(unavailable());
    }
    verify_change_route(shared, call, &change, invocation)?;
    // This is the actual loaded source value. Typed optional fields may be
    // normalized to null; that normalization cannot change the source proof.
    let change_digest = canonical_digest(&payload["change"]).map_err(|_| invalid())?;
    Ok((change, rpc, change_digest))
}
fn verify_change_route(
    shared: &Shared,
    call: &Call,
    change: &PreparedNativeChange,
    invocation: &Value,
) -> AppResult<()> {
    let descriptor = if let Some((action, _)) = metadata_route(change.kind) {
        if invocation["bindingId"] != METADATA_BINDING
            || invocation["actionId"] != action
            || invocation["implementationDigest"] != shared.metadata.implementation.as_str()
        {
            return Err(stale());
        }
        shared.metadata.descriptor(change.kind, &call.context)?
    } else {
        let (action, semantic) =
            crate::native_backend::world_route(change.kind).ok_or_else(unavailable)?;
        if invocation["actionId"] != action {
            return Err(stale());
        }
        let descriptor =
            HttpProviderPort::with_deadline(shared.hosts.clone(), call.budget.deadline())
                .action_descriptor(invocation, &call.context)?;
        if descriptor["semanticKind"] != semantic {
            return Err(stale());
        }
        descriptor
    };
    if descriptor["implementationDigest"] != invocation["implementationDigest"]
        || projected_digest("ActionDescriptor", &descriptor)
            .map_err(|_| invalid())?
            .as_str()
            != text(invocation, "actionDigest")?
    {
        return Err(stale());
    }
    call.check()
}
fn resource_reader(call: &Call) -> AppResult<ProjectResourceReader> {
    ProjectResourceReader::new(Box::new(SourceAuthority(call.clone())), MAX_BYTES).map_err(storage)
}
fn owned_kind(kind: OwnedKind) -> OwnedDocumentKind {
    match kind {
        OwnedKind::Prefab => OwnedDocumentKind::Prefab,
        OwnedKind::Instance => OwnedDocumentKind::Instance,
        OwnedKind::CommandModule => OwnedDocumentKind::CommandModule,
        OwnedKind::Clip => OwnedDocumentKind::AnimationClip,
        OwnedKind::Asset => OwnedDocumentKind::Asset,
        OwnedKind::PhysicsDefinition => OwnedDocumentKind::PhysicsDefinition,
    }
}

fn validate(definition: &str, value: &Value) -> AppResult<()> {
    mmmm_contracts::ContractValidator::shared()
        .and_then(|v| v.validate(definition, value))
        .map_err(|_| invalid())
}
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> AppResult<T> {
    serde_json::from_value(value.clone()).map_err(|_| invalid())
}
fn context_id(value: &Value) -> AppResult<ContextId> {
    decode(&value["contextId"])
}
fn project_id(value: &Value) -> AppResult<ProjectId> {
    decode(&value["projectId"])
}
fn field_digest(value: &Value, key: &str) -> AppResult<Sha256Digest> {
    decode(&value[key])
}
fn text<'a>(value: &'a Value, key: &str) -> AppResult<&'a str> {
    value[key].as_str().ok_or_else(invalid)
}
fn check_session(
    principal: &AuthenticatedPrincipal,
    budget: &RequestBudget,
    id: &ContextId,
) -> AppResult<()> {
    budget
        .check()
        .map_err(|e| AppError::new(e.code, e.message))?;
    if !principal.is_current() || !principal.permits_context(id.as_str()) {
        return Err(forbidden());
    }
    if crate::peer::fatal_stop_requested() {
        return Err(error(
            "LOCAL_TRANSPORT_UNCERTAIN",
            "Native local transport completion is unresolved",
        ));
    }
    Ok(())
}
fn error(code: &'static str, message: &'static str) -> AppError {
    AppError::new(code, message)
}
fn service_cause(error: crate::service::ServiceError) -> AppError {
    AppError::caused_by(error.code, error.message, error)
}
fn invalid() -> AppError {
    error(
        "INVALID_COMPOSITE",
        "Composite source or binding violates its closed contract",
    )
}
fn forbidden() -> AppError {
    error(
        "PERMISSION_REQUIRED",
        "Current authenticated scope does not authorize the original composite",
    )
}
fn stale() -> AppError {
    error(
        "STALE_COMPOSITE",
        "Original composite source, context or binding changed",
    )
}
fn limit() -> AppError {
    error(
        "BUDGET_EXCEEDED",
        "Composite evidence exceeds its finite capacity",
    )
}
fn busy() -> AppError {
    error("SOURCE_BUSY", "Composite source witness is in use")
}
fn unavailable() -> AppError {
    error(
        "CAPABILITY_UNAVAILABLE",
        "No complete implementation is registered for this exact composite phase",
    )
}
fn store_required() -> AppError {
    error(
        "STORE_REQUIRED",
        "Composite execution requires the original application Store borrow",
    )
}
fn storage(source: StorageError) -> AppError {
    AppError::storage("COMPOSITE_STORAGE_FAILED", source)
}
fn app_storage(source: AppError) -> StorageError {
    StorageError::InvalidTransition(format!("{}: {}", source.code, source.message))
}

#[cfg(test)]
#[path = "composite_tests.rs"]
mod tests;

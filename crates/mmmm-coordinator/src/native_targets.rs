//! Independent native bytes, with exact target and retained invocation identity.
//! JSON status/coverage is interpreted only after paired context, current ACL,
//! wrapper identity and raw SHA validation. Unknown membership stays unknown.
use crate::{
    authority::LocalAuthority,
    host::{HostBridge, HostContextWitness},
    native_payload::{OriginalTargetPins, validate_payload},
    service::{RequestBudget, RequestContextSlot, RequestContextWitness},
};
use mmmm_application::{Access, AppError, AuthorityPort};
use mmmm_contracts::{
    BindingId, ContextId, InvocationId, JsonLimits, OperationId, ProjectId, ResourceId,
    ResourceLocation, Sha256Digest, StepId, canonical_digest, encode_json, parse_json_with_limits,
    raw_digest, verify_projected_digest,
};
use mmmm_runtime::storage::{
    BlobRef, DurableStore, StorageError,
    artifact::{ArtifactError, ResourceOwner, register_resource},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const MAX_TARGETS: usize = 256;
const MAX_SELECTOR_BYTES: usize = 16 * 1024;
const MAX_RAW_BYTES: usize = 256 * 1024;
const MAX_TOTAL_BYTES: usize = 512 * 1024;

#[derive(Debug)]
pub enum NativeTargetError {
    Authority(AppError),
    Storage(StorageError),
    Retention(ArtifactError),
    Invalid,
    /// Original closed HostResponse is retained in the same CAS before mapping.
    /// These source fields are diagnostic data; they cannot authorize a write.
    Host(Box<NativeHostFailure>),
}

/// An acquired failed reply is immutable as a whole. Moving its private owner
/// into a different response or status cannot manufacture a retention receipt.
#[derive(Debug)]
pub struct NativeHostFailure {
    response: BlobRef,
    status: String,
    code: Option<String>,
    rpc_error: Option<Value>,
    owner: ObservationOwner,
}
impl NativeHostFailure {
    pub fn response(&self) -> &BlobRef {
        &self.response
    }
    pub fn status(&self) -> &str {
        &self.status
    }
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }
    /// A local diagnostic copies actual acquired facts, never the request's
    /// authority witness. The original complete response remains in CAS. This
    /// reference cannot construct a NativeRead or a usable resource receipt.
    pub fn causal_snapshot(&self) -> NativeHostCause {
        NativeHostCause {
            response: self.response.clone(),
            status: self.status.clone(),
            code: self.code.clone(),
            rpc_error: self.rpc_error.clone().map(NativeHostRpcCause),
        }
    }
}

/// Sendable local cause produced only from a real acquired host failure.
/// There is no public constructor or deserialization path. Status, error and
/// CAS identity are historical observations, not permission or read grants.
#[derive(Debug)]
pub struct NativeHostCause {
    response: BlobRef,
    status: String,
    code: Option<String>,
    rpc_error: Option<NativeHostRpcCause>,
}
impl NativeHostCause {
    pub fn response(&self) -> &BlobRef {
        &self.response
    }
    pub fn status(&self) -> &str {
        &self.status
    }
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }
    pub fn rpc_error(&self) -> Option<&Value> {
        self.rpc_error.as_ref().map(|error| &error.0)
    }
}
impl std::fmt::Display for NativeHostCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("The original failed native observation response remains in CAS")
    }
}
impl std::error::Error for NativeHostCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.rpc_error
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}
#[derive(Debug)]
struct NativeHostRpcCause(Value);
impl std::fmt::Display for NativeHostRpcCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("The paired host returned its original structured RPC error")
    }
}
impl std::error::Error for NativeHostRpcCause {}
impl std::fmt::Display for NativeTargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authority(error) => write!(f, "{}: {}", error.code, error.message),
            Self::Storage(_) | Self::Retention(_) => {
                f.write_str("Native target evidence could not be retained")
            }
            Self::Invalid => {
                f.write_str("Native target observation identity or coverage is invalid")
            }
            Self::Host(_) => {
                f.write_str("The paired host could not observe the requested native target")
            }
        }
    }
}
impl std::error::Error for NativeTargetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Storage(error) => Some(error),
            Self::Retention(error) => Some(error),
            Self::Invalid | Self::Host(_) => None,
        }
    }
}
type TargetResult<T> = Result<T, NativeTargetError>;

/// Selectors are closed native locators, not file paths or authority records.
#[derive(Clone)]
pub struct NativeSelector(Value);
impl NativeSelector {
    pub fn from_value(value: &Value) -> TargetResult<Self> {
        if encode_json(value)
            .map_err(|_| NativeTargetError::Invalid)?
            .len()
            > MAX_SELECTOR_BYTES
        {
            return Err(NativeTargetError::Invalid);
        }
        let kind = string(value, "kind")?;
        match kind {
            "block_state" | "block_entity" => {
                fields(value, &["kind", "dimension", "position"])?;
                location(value, "dimension")?;
                let p = value["position"]
                    .as_array()
                    .filter(|p| p.len() == 3)
                    .ok_or(NativeTargetError::Invalid)?;
                if p.iter()
                    .any(|v| v.as_i64().and_then(|n| i32::try_from(n).ok()).is_none())
                {
                    return Err(NativeTargetError::Invalid);
                }
            }
            "entity" => {
                fields(value, &["kind", "dimension", "uuid", "expectedType"])?;
                location(value, "dimension")?;
                location(value, "expectedType")?;
                let uuid = string(value, "uuid")?;
                if uuid.len() != 36
                    || uuid.bytes().enumerate().any(|(i, b)| {
                        if [8, 13, 18, 23].contains(&i) {
                            b != b'-'
                        } else {
                            !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b)
                        }
                    })
                {
                    return Err(NativeTargetError::Invalid);
                }
            }
            "storage" => {
                fields(value, &["kind", "storage", "key", "resourceId"])?;
                location(value, "storage")?;
                atom(value, "key", false)?;
                resource(value)?;
            }
            "score" => {
                fields(value, &["kind", "objective", "holder", "resourceId"])?;
                atom(value, "objective", true)?;
                atom(value, "holder", true)?;
                resource(value)?;
            }
            "objective" => {
                fields(value, &["kind", "objective", "resourceId"])?;
                atom(value, "objective", true)?;
                resource(value)?;
            }
            _ => return Err(NativeTargetError::Invalid),
        }
        Ok(Self(value.clone()))
    }
    pub fn value(&self) -> &Value {
        &self.0
    }
    pub fn kind(&self) -> &str {
        self.0["kind"].as_str().unwrap_or("")
    }
}

/// Constructible only from a byte-verified actual observation. Full coverage
/// applies to this exact captured native subject, never a whole UUID namespace,
/// region, prefab, scoreboard or indirect engine effect.
pub struct NativeObservation {
    selector: NativeSelector,
    raw: Value,
    bytes: Vec<u8>,
    digest: Sha256Digest,
}
impl NativeObservation {
    pub fn selector(&self) -> &NativeSelector {
        &self.selector
    }
    pub fn raw(&self) -> &Value {
        &self.raw
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
    pub fn full_target(&self) -> bool {
        self.raw["status"] == "known" && self.raw["coverage"] == "full_target"
    }
    pub fn presence(&self) -> &str {
        self.raw["presence"].as_str().unwrap_or("unknown")
    }
}
pub struct NativeRead {
    response: BlobRef,
    wrapper: Value,
    targets: Vec<NativeObservation>,
    owner: ObservationOwner,
    retained_resource: Option<Value>,
}
impl NativeRead {
    pub fn response(&self) -> &BlobRef {
        &self.response
    }
    pub fn wrapper(&self) -> &Value {
        &self.wrapper
    }
    pub fn targets(&self) -> &[NativeObservation] {
        &self.targets
    }
    pub fn into_targets(self) -> Vec<NativeObservation> {
        self.targets
    }
    /// Issued only after the actual reader has pinned these exact acquired
    /// bytes under the original service generation and current full scope.
    /// The ResourceRef is diagnostic provenance, not a write grant.
    pub fn retained_resource(&self) -> Option<&Value> {
        self.retained_resource.as_ref()
    }
}

/// Issued only by an acquisition in the original protected Store. A DTO,
/// principal string or BlobRef cannot create this received evidence witness.
struct ObservationOwner {
    request: RequestContextWitness,
    paired: HostContextWitness,
    authenticated: crate::auth::AuthenticatedPrincipal,
    budget: RequestBudget,
    context: Value,
    private_pin: bool,
    data_root: std::path::PathBuf,
}

enum AcquisitionStore<'a> {
    Read(&'a DurableStore),
    Write(&'a mut DurableStore),
}
impl AcquisitionStore<'_> {
    fn store(&self) -> &DurableStore {
        match self {
            Self::Read(store) => store,
            Self::Write(store) => store,
        }
    }
    fn pin_acquired(&mut self, blob: &BlobRef, owner: &mut ObservationOwner) -> TargetResult<()> {
        let Self::Write(store) = self else {
            return Ok(());
        };
        owner.check_store(store)?;
        // This callback owns the actual bytes just returned from its bounded
        // paired acquisition. The private pin preserves a fact; it grants no
        // ResourceRef use, read access, source rights or Apply authority. In
        // particular no canceled request is restarted and no host is reread.
        let id = evidence_identity(&owner.context, owner.authenticated.principal(), blob)?;
        store
            .pin_artifact(&format!("native-response-pending-{id}"), blob)
            .map_err(NativeTargetError::Storage)?;
        owner.private_pin = true;
        Ok(())
    }
}
impl ObservationOwner {
    fn check_store(&self, store: &DurableStore) -> TargetResult<()> {
        // DurableStore has already pinned/canonicalized its protected root and
        // holds its singleton lease. This check performs no new native/CAS I/O.
        if self.data_root != store.data_root() {
            return Err(NativeTargetError::Invalid);
        }
        Ok(())
    }
}
impl std::fmt::Debug for ObservationOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObservationOwner(acquired service evidence)")
    }
}

/// This route is built from the actual operation ledger and retained capture,
/// not an ID passed by an inspector caller. Tombstone admission additionally
/// needs the exact originally observed selector, raw digest and owner tag.
struct OriginalRoute {
    invocation: InvocationId,
    original: Value,
    context: Value,
    targets: BTreeMap<Sha256Digest, OriginalTargetPins>,
}
impl OriginalRoute {
    fn load(
        store: &DurableStore,
        invocation: &Value,
        budget: &RequestBudget,
        check: &mut impl FnMut() -> TargetResult<()>,
    ) -> TargetResult<Self> {
        let invocation_id = InvocationId::new(string(invocation, "invocationId")?)
            .map_err(|_| NativeTargetError::Invalid)?;
        let operation = OperationId::new(string(invocation, "operationId")?)
            .map_err(|_| NativeTargetError::Invalid)?;
        let binding = BindingId::new(string(invocation, "bindingId")?)
            .map_err(|_| NativeTargetError::Invalid)?;
        let summaries = store
            .operation_summaries(&operation)
            .map_err(NativeTargetError::Storage)?;
        if summaries.len() > 1024 {
            return Err(NativeTargetError::Invalid);
        }
        let mut remaining = 16 * 1024 * 1024u64;
        let mut targets = BTreeMap::new();
        for summary in summaries {
            let summary = retained_json(store, &summary, &mut remaining, budget, check)?;
            if summary["kind"] != "before_capture_summary"
                || summary["stepId"] != invocation["stepId"]
                || summary["invocationId"] != invocation["invocationId"]
            {
                continue;
            }
            let capture: BlobRef = serde_json::from_value(summary["captureBlob"].clone())
                .map_err(|_| NativeTargetError::Invalid)?;
            let capture = retained_json(store, &capture, &mut remaining, budget, check)?;
            if capture["kind"] != "before_capture"
                || capture["version"] != 1
                || capture["operationId"] != invocation["operationId"]
                || capture["stepId"] != invocation["stepId"]
                || [
                    "invocationId",
                    "bindingId",
                    "contextDigest",
                    "implementationDigest",
                    "argumentsDigest",
                ]
                .iter()
                .any(|key| capture[*key] != invocation[*key])
            {
                return Err(NativeTargetError::Invalid);
            }
            let images = capture["images"]
                .as_array()
                .filter(|a| a.len() <= 4096)
                .ok_or(NativeTargetError::Invalid)?;
            for image in images {
                fields(image, &["target", "before"])?;
                if !string(image, "target")?.starts_with("owned-entity:") {
                    continue;
                }
                let before: BlobRef = serde_json::from_value(image["before"].clone())
                    .map_err(|_| NativeTargetError::Invalid)?;
                let raw = retained_json(store, &before, &mut remaining, budget, check)?;
                // Captures belonging to other native codecs are not interpreted
                // as entity destruction evidence.
                if raw["format"] != "mmmm.native.target/1" || raw["selector"]["kind"] != "entity" {
                    continue;
                }
                let selector = NativeSelector::from_value(&raw["selector"])?;
                validate_coverage(&raw, &selector, None)?;
                if raw["presence"] != "present" || raw["coverage"] != "full_target" {
                    continue;
                }
                let tags = raw["payload"]["tags"]
                    .as_array()
                    .ok_or(NativeTargetError::Invalid)?;
                // The frozen native backend emits this locator only from the
                // sealed compiler's owned UUID/tag pair. A tag prefix guess or
                // an arbitrary observed entity tag grants no owned identity.
                let Some(subject) = string(image, "target")?.strip_prefix("owned-entity:") else {
                    continue;
                };
                let Some((uuid, owner_tag)) = subject.split_once(':') else {
                    return Err(NativeTargetError::Invalid);
                };
                if selector.value()["uuid"] != uuid
                    || owner_tag.is_empty()
                    || owner_tag.len() > 64
                    || owner_tag
                        .bytes()
                        .any(|b| !b.is_ascii_alphanumeric() && ![b'.', b'_', b'-'].contains(&b))
                    || !tags.contains(&json!(owner_tag))
                {
                    return Err(NativeTargetError::Invalid);
                }
                let pin = OriginalTargetPins {
                    invocation_id: invocation_id.clone(),
                    binding_id: binding.clone(),
                    operation_id: operation.clone(),
                    selector: selector.value().clone(),
                    before_sha256: before.digest,
                    owner_tag: owner_tag.to_owned(),
                };
                let key =
                    canonical_digest(selector.value()).map_err(|_| NativeTargetError::Invalid)?;
                if targets.insert(key, pin).is_some() {
                    return Err(NativeTargetError::Invalid);
                }
            }
        }
        Ok(Self {
            invocation: invocation_id,
            original: invocation.clone(),
            context: invocation["context"].clone(),
            targets,
        })
    }
}
fn retained_json(
    store: &DurableStore,
    blob: &BlobRef,
    remaining: &mut u64,
    budget: &RequestBudget,
    check: &mut impl FnMut() -> TargetResult<()>,
) -> TargetResult<Value> {
    *remaining = remaining
        .checked_sub(blob.byte_length)
        .ok_or(NativeTargetError::Invalid)?;
    check()?;
    let mut checkpoint_error = None;
    let result = store.read_blob_checked(blob, 8 * 1024 * 1024, || {
        if let Err(error) = check() {
            checkpoint_error = Some(error);
            return Err(StorageError::InvalidTransition(
                "Current native target evidence authority reached".into(),
            ));
        }
        Ok(())
    });
    if let Some(error) = checkpoint_error {
        return Err(error);
    }
    let bytes = result.map_err(NativeTargetError::Storage)?;
    budget.check().map_err(service_error)?;
    parse_json_with_limits(
        &bytes,
        JsonLimits {
            max_bytes: 8 * 1024 * 1024,
            max_depth: 64,
            max_nodes: 100_000,
        },
    )
    .map_err(|_| NativeTargetError::Invalid)
}

pub struct NativeTargetReader {
    hosts: HostBridge,
    authority: LocalAuthority,
    request: RequestContextSlot,
}
impl NativeTargetReader {
    pub fn new(hosts: HostBridge, authority: LocalAuthority, request: RequestContextSlot) -> Self {
        Self {
            hosts,
            authority,
            request,
        }
    }
    /// Before planning/capture: no native mutation history is selected.
    pub fn observe(
        &self,
        store: &DurableStore,
        context: &Value,
        selectors: &[NativeSelector],
        registry_generation: &str,
    ) -> TargetResult<NativeRead> {
        self.read(
            AcquisitionStore::Read(store),
            context,
            selectors,
            registry_generation,
            None,
        )
    }
    /// Mutable acquisition preserves a private response pin before decoding or
    /// publishing it, then separately verifies current usability authority.
    pub fn observe_retained(
        &self,
        store: &mut DurableStore,
        context: &Value,
        selectors: &[NativeSelector],
        registry_generation: &str,
    ) -> TargetResult<NativeRead> {
        let read = self.read(
            AcquisitionStore::Write(store),
            context,
            selectors,
            registry_generation,
            None,
        )?;
        self.retain(store, read)
    }
    /// Post-dispatch history selects only the actual original durable invocation,
    /// exact operation owner/full scope and original native epoch. A public
    /// invocation ID cannot construct this route or select the newest UUID job.
    /// The composite caller must also match these selectors to the exact frozen
    /// step/approved native footprint; this reader creates no dispatch proof.
    pub fn observe_original(
        &self,
        store: &DurableStore,
        operation: &OperationId,
        step: &StepId,
        selectors: &[NativeSelector],
        registry_generation: &str,
    ) -> TargetResult<NativeRead> {
        let (route, live) = self.original_route(store, operation, step, None)?;
        self.read(
            AcquisitionStore::Read(store),
            &live,
            selectors,
            registry_generation,
            Some(&route),
        )
    }
    pub fn observe_original_retained(
        &self,
        store: &mut DurableStore,
        operation: &OperationId,
        step: &StepId,
        selectors: &[NativeSelector],
        registry_generation: &str,
    ) -> TargetResult<NativeRead> {
        let (route, live) = self.original_route(store, operation, step, None)?;
        let read = self.read(
            AcquisitionStore::Write(store),
            &live,
            selectors,
            registry_generation,
            Some(&route),
        )?;
        self.retain(store, read)
    }
    /// A trusted caller supplies its actual current Observe context locator.
    /// Its JSON is independently reacquired and compared; it never replaces
    /// the immutable original Invocation or its retained source generation.
    pub fn observe_original_retained_in_context(
        &self,
        store: &mut DurableStore,
        operation: &OperationId,
        step: &StepId,
        current_context: &Value,
        selectors: &[NativeSelector],
        registry_generation: &str,
    ) -> TargetResult<NativeRead> {
        let (route, live) = self.original_route(store, operation, step, Some(current_context))?;
        let read = self.read(
            AcquisitionStore::Write(store),
            &live,
            selectors,
            registry_generation,
            Some(&route),
        )?;
        self.retain(store, read)
    }
    fn original_route(
        &self,
        store: &DurableStore,
        operation: &OperationId,
        step: &StepId,
        current_context: Option<&Value>,
    ) -> TargetResult<(OriginalRoute, Value)> {
        let request = self.request.occupied_witness().map_err(service_error)?;
        let principal = request.authenticated().clone();
        let budget = request.budget().clone();
        let record = store
            .operation(operation)
            .map_err(NativeTargetError::Storage)?;
        let mut authority = self.authority.clone();
        authority
            .authorize_operation(principal.principal(), &record, Access::ObserveOperation)
            .map_err(NativeTargetError::Authority)?;
        let invocation = store
            .stored_invocation_checked(operation, step, 8 * 1024 * 1024, || {
                request.check_local().map_err(|_| {
                    StorageError::InvalidTransition(
                        "Original native evidence request is no longer current".into(),
                    )
                })
            })
            .map_err(NativeTargetError::Storage)?;
        if invocation["operationId"] != operation.as_str()
            || invocation["stepId"] != step.as_str()
            || invocation["context"]["principalRef"] != principal.principal().as_str()
        {
            return Err(NativeTargetError::Invalid);
        }
        let locator = current_context.unwrap_or(&invocation["context"]);
        let context_id = ContextId::new(string(locator, "contextId")?)
            .map_err(|_| NativeTargetError::Invalid)?;
        if !principal.permits_context(context_id.as_str()) {
            return Err(NativeTargetError::Invalid);
        }
        let live = self
            .hosts
            .context_with_deadline(principal.principal(), &context_id, budget.deadline())
            .map_err(NativeTargetError::Authority)?;
        if current_context.is_some_and(|expected| *expected != live)
            || live["environment"] != invocation["context"]["environment"]
            || live["projectId"] != invocation["context"]["projectId"]
            || live["principalRef"] != invocation["context"]["principalRef"]
            || !crate::authority::scope_contains(&live["scope"], &json!(record.scope))
        {
            return Err(NativeTargetError::Invalid);
        }
        let mut check = || {
            request.check_local().map_err(service_error)?;
            let (current, current_budget) = self.current()?;
            if !current.same_session(&principal)
                || current_budget.deadline() != budget.deadline()
                || !std::ptr::eq(current_budget.cancellation(), budget.cancellation())
            {
                return Err(NativeTargetError::Invalid);
            }
            authority
                .authorize_operation(current.principal(), &record, Access::ObserveOperation)
                .map_err(NativeTargetError::Authority)
        };
        let route = OriginalRoute::load(store, &invocation, &budget, &mut check)?;
        Ok((route, live))
    }
    /// Register the exact acquired response before a native/source adapter can
    /// use it as provenance. It does not accept a caller ResourceRef or issuer.
    pub fn retain(
        &self,
        store: &mut DurableStore,
        mut read: NativeRead,
    ) -> TargetResult<NativeRead> {
        read.owner.check_store(store)?;
        let project = self.check_owner(&read.owner)?;
        let identity =
            canonical_digest(&json!({"projectId":project,"sha256":read.response.digest}))
                .map_err(|_| NativeTargetError::Invalid)?;
        let resource = json!({"resourceId":format!("native-observation-{identity}"),
            "sha256":read.response.digest,"sizeBytes":read.response.byte_length,
            "mediaType":"application/vnd.mmmm.native-observation+json"});
        register_resource(store, &resource, ResourceOwner::Project(project))
            .map_err(NativeTargetError::Retention)?;
        self.check_owner(&read.owner)?;
        read.retained_resource = Some(resource);
        Ok(read)
    }
    /// Preserve an original failed reply under a private durable pin. This
    /// creates no ResourceRef/usable authority marker and never reissues a host
    /// call. Cancellation or revocation prevents a new usable registration.
    pub fn retain_error(
        &self,
        store: &mut DurableStore,
        error: &NativeTargetError,
    ) -> TargetResult<()> {
        let NativeTargetError::Host(failure) = error else {
            return Ok(());
        };
        let response = &failure.response;
        let owner = &failure.owner;
        owner.check_store(store)?;
        if owner.private_pin {
            // The mutable acquisition already committed this exact pin. This
            // is a pure receipt check even if the request has since canceled;
            // it creates no new pin, CAS read or usable resource authority.
            return Ok(());
        }
        let project = self.check_owner(owner)?;
        let id = canonical_digest(
            &json!({"projectId":project,"contextDigest":owner.context["contextDigest"],
            "principal":owner.authenticated.principal(),"sha256":response.digest}),
        )
        .map_err(|_| NativeTargetError::Invalid)?;
        store
            .pin_artifact(&format!("native-response-pending-{id}"), response)
            .map_err(NativeTargetError::Storage)?;
        self.check_owner(owner)?;
        Ok(())
    }
    fn check_owner(&self, owner: &ObservationOwner) -> TargetResult<ProjectId> {
        owner.request.check_local().map_err(service_error)?;
        owner
            .paired
            .check_local()
            .map_err(NativeTargetError::Authority)?;
        let (current, budget) = self.current()?;
        if !current.same_session(&owner.authenticated)
            || budget.deadline() != owner.budget.deadline()
            || !std::ptr::eq(budget.cancellation(), owner.budget.cancellation())
        {
            return Err(NativeTargetError::Invalid);
        }
        let context = &owner.context;
        let project = ProjectId::new(string(context, "projectId")?)
            .map_err(|_| NativeTargetError::Invalid)?;
        self.authority
            .authorize_with_deadline(
                current.principal(),
                &project,
                Access::ReadProject,
                Some(context),
                None,
                budget.deadline(),
            )
            .map_err(NativeTargetError::Authority)?;
        owner
            .paired
            .check_local()
            .map_err(NativeTargetError::Authority)?;
        owner.request.check_local().map_err(service_error)?;
        Ok(project)
    }
    fn current(&self) -> TargetResult<(crate::auth::AuthenticatedPrincipal, RequestBudget)> {
        self.request
            .current()
            .map_err(|e| NativeTargetError::Authority(AppError::new(e.code, e.message)))
    }
    fn read(
        &self,
        mut acquisition: AcquisitionStore<'_>,
        context: &Value,
        selectors: &[NativeSelector],
        registry_generation: &str,
        original: Option<&OriginalRoute>,
    ) -> TargetResult<NativeRead> {
        let request = self.request.occupied_witness().map_err(service_error)?;
        let principal = request.authenticated().clone();
        let budget = request.budget().clone();
        let id = ContextId::new(string(context, "contextId")?)
            .map_err(|_| NativeTargetError::Invalid)?;
        let project = ProjectId::new(string(context, "projectId")?)
            .map_err(|_| NativeTargetError::Invalid)?;
        if !principal.permits_context(id.as_str())
            || selectors.is_empty()
            || selectors.len() > MAX_TARGETS
            || registry_generation.is_empty()
            || registry_generation.len() > 128
        {
            return Err(NativeTargetError::Invalid);
        }
        verify_projected_digest("ExecutionContext", context)
            .map_err(|_| NativeTargetError::Invalid)?;
        if original.is_some_and(|route| {
            route.context["environment"] != context["environment"]
                || route.context["projectId"] != context["projectId"]
                || route.context["principalRef"] != context["principalRef"]
        }) {
            return Err(NativeTargetError::Invalid);
        }
        let paired = self
            .hosts
            .observe_context_witness(principal.principal(), &id, budget.deadline())
            .map_err(NativeTargetError::Authority)?;
        if paired.context() != context {
            return Err(NativeTargetError::Invalid);
        }
        self.authority
            .authorize_with_deadline(
                principal.principal(),
                &project,
                Access::ReadProject,
                Some(context),
                None,
                budget.deadline(),
            )
            .map_err(NativeTargetError::Authority)?;
        let values: Vec<Value> = selectors.iter().map(|s| s.value().clone()).collect();
        let unique: BTreeSet<Sha256Digest> = values
            .iter()
            .map(|v| mmmm_contracts::canonical_digest(v).map_err(|_| NativeTargetError::Invalid))
            .collect::<TargetResult<_>>()?;
        if unique.len() != selectors.len() {
            return Err(NativeTargetError::Invalid);
        }
        let selector = json!({"kind":"native_targets","targets":values,
            "sourceInvocationId":original.map(|route| &route.invocation)});
        let acquired = match original {
            Some(route) => self.hosts.inspect_original_acquired_with_deadline(
                acquisition.store(),
                principal.principal(),
                &route.original,
                context,
                selector,
                budget.deadline(),
            ),
            None => self.hosts.inspect_acquired_with_deadline(
                principal.principal(),
                &id,
                selector,
                budget.deadline(),
            ),
        }
        .map_err(NativeTargetError::Authority)?;
        // The original source generation is identity only. The separate current
        // Observe witness must remain live; a normal read must also be acquired
        // from that exact generation rather than a newly installed same-ID host.
        let origin_matches = original.is_some() || acquired.matches_witness(&paired);
        // A malformed complete body stays private in the acquisition cause;
        // only an actual validated HostResponse may enter diagnostic CAS.
        let response = acquired
            .into_acquired_response()
            .map_err(NativeTargetError::Authority)?;
        // Retain exact source reply before interpreting native failure/status.
        let blob = acquisition
            .store()
            .put_blob(&encode_json(&response).map_err(|_| NativeTargetError::Invalid)?)
            .map_err(NativeTargetError::Storage)?;
        let mut owner = ObservationOwner {
            request,
            paired,
            authenticated: principal.clone(),
            budget: budget.clone(),
            context: context.clone(),
            private_pin: false,
            data_root: acquisition.store().data_root().to_path_buf(),
        };
        acquisition.pin_acquired(&blob, &mut owner)?;
        if response["status"] != "ok" {
            return Err(NativeTargetError::Host(Box::new(NativeHostFailure {
                response: blob,
                status: string(&response, "status")?.to_owned(),
                code: response["error"]["code"].as_str().map(str::to_owned),
                rpc_error: response
                    .get("error")
                    .filter(|error| !error.is_null())
                    .cloned(),
                owner,
            })));
        }
        // Early private retention creates no usability grant. A received late
        // success must still pass the original call/lease/ACL before decoding
        // or registering a publicly readable provenance ResourceRef.
        owner.request.check_local().map_err(service_error)?;
        owner
            .paired
            .check_local()
            .map_err(NativeTargetError::Authority)?;
        if !origin_matches {
            return Err(NativeTargetError::Invalid);
        }
        let wrapper = response.get("payload").ok_or(NativeTargetError::Invalid)?;
        let targets = decode(
            wrapper,
            original.map(|route| &route.context).unwrap_or(context),
            selectors,
            registry_generation,
            original,
            &budget,
        )?;
        self.authority
            .authorize_with_deadline(
                principal.principal(),
                &project,
                Access::ReadProject,
                Some(context),
                None,
                budget.deadline(),
            )
            .map_err(NativeTargetError::Authority)?;
        owner.request.check_local().map_err(service_error)?;
        owner
            .paired
            .check_local()
            .map_err(NativeTargetError::Authority)?;
        Ok(NativeRead {
            response: blob,
            wrapper: wrapper.clone(),
            targets,
            owner,
            retained_resource: None,
        })
    }
}
fn evidence_identity(
    context: &Value,
    principal: &mmmm_contracts::PrincipalId,
    blob: &BlobRef,
) -> TargetResult<Sha256Digest> {
    canonical_digest(
        &json!({"projectId":context["projectId"],"contextDigest":context["contextDigest"],
        "principal":principal,"sha256":blob.digest}),
    )
    .map_err(|_| NativeTargetError::Invalid)
}
fn service_error(error: crate::service::ServiceError) -> NativeTargetError {
    NativeTargetError::Authority(AppError::new(error.code, error.message))
}

fn decode(
    wrapper: &Value,
    context: &Value,
    selectors: &[NativeSelector],
    generation: &str,
    original: Option<&OriginalRoute>,
    budget: &RequestBudget,
) -> TargetResult<Vec<NativeObservation>> {
    fields(
        wrapper,
        &[
            "protocolVersion",
            "environment",
            "contextId",
            "contextDigest",
            "registryGeneration",
            "observedFromTick",
            "observedToTick",
            "observedAt",
            "targets",
            "sourceInvocationId",
        ],
    )?;
    if wrapper["protocolVersion"] != mmmm_contracts::CONTRACT_VERSION
        || wrapper["environment"] != context["environment"]
        || wrapper["contextId"] != context["contextId"]
        || wrapper["contextDigest"] != context["contextDigest"]
        || wrapper["registryGeneration"] != generation
        || wrapper["sourceInvocationId"] != json!(original.map(|route| &route.invocation))
    {
        return Err(NativeTargetError::Invalid);
    }
    for key in ["observedFromTick", "observedToTick"] {
        let tick = string(wrapper, key)?;
        if tick.parse::<u64>().ok().map(|n| n.to_string()).as_deref() != Some(tick) {
            return Err(NativeTargetError::Invalid);
        }
    }
    if string(wrapper, "observedFromTick")?
        .parse::<u64>()
        .map_err(|_| NativeTargetError::Invalid)?
        > string(wrapper, "observedToTick")?
            .parse::<u64>()
            .map_err(|_| NativeTargetError::Invalid)?
    {
        return Err(NativeTargetError::Invalid);
    }
    let at = string(wrapper, "observedAt")?;
    if time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339).is_err() {
        return Err(NativeTargetError::Invalid);
    }
    let entries = wrapper["targets"]
        .as_array()
        .filter(|a| a.len() == selectors.len())
        .ok_or(NativeTargetError::Invalid)?;
    let mut result = Vec::with_capacity(entries.len());
    let mut total = 0usize;
    for (entry, selector) in entries.iter().zip(selectors) {
        budget
            .check()
            .map_err(|e| NativeTargetError::Authority(AppError::new(e.code, e.message)))?;
        fields(
            entry,
            &["selector", "observationBytesHex", "observationSha256"],
        )?;
        if entry["selector"] != *selector.value() {
            return Err(NativeTargetError::Invalid);
        }
        let bytes = hex(string(entry, "observationBytesHex")?)?;
        total = total
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_TOTAL_BYTES)
            .ok_or(NativeTargetError::Invalid)?;
        let digest = raw_digest(&bytes);
        if entry["observationSha256"] != digest.as_str() {
            return Err(NativeTargetError::Invalid);
        }
        let raw = parse_json_with_limits(
            &bytes,
            JsonLimits {
                max_bytes: MAX_RAW_BYTES,
                max_depth: 64,
                max_nodes: 16_384,
            },
        )
        .map_err(|_| NativeTargetError::Invalid)?;
        fields(
            &raw,
            &[
                "format",
                "selector",
                "status",
                "presence",
                "membershipScope",
                "captureScope",
                "coverage",
                "reason",
                "payload",
            ],
        )?;
        if raw["format"] != "mmmm.native.target/1" || raw["selector"] != *selector.value() {
            return Err(NativeTargetError::Invalid);
        }
        let key = canonical_digest(selector.value()).map_err(|_| NativeTargetError::Invalid)?;
        validate_coverage(
            &raw,
            selector,
            original.and_then(|route| route.targets.get(&key)),
        )?;
        result.push(NativeObservation {
            selector: selector.clone(),
            raw,
            bytes,
            digest,
        });
    }
    Ok(result)
}
fn validate_coverage(
    raw: &Value,
    selector: &NativeSelector,
    original: Option<&OriginalTargetPins>,
) -> TargetResult<()> {
    let status = string(raw, "status")?;
    let presence = string(raw, "presence")?;
    let membership = string(raw, "membershipScope")?;
    let capture = string(raw, "captureScope")?;
    let coverage = string(raw, "coverage")?;
    if !["known", "unknown", "unsupported"].contains(&status)
        || !["present", "absent", "unknown"].contains(&presence)
        || !["full_target", "tracked_changes_only", "best_effort"].contains(&coverage)
        || membership.len() > 128
        || capture.len() > 128
        || !(raw["reason"].is_null() || raw["reason"].as_str().is_some_and(|s| s.len() <= 256))
    {
        return Err(NativeTargetError::Invalid);
    }
    if coverage == "full_target" {
        let admitted = match selector.kind() {
            "block_state" => {
                membership == "loaded_block_position"
                    && capture == "native_block_state"
                    && presence == "present"
                    && raw["payload"]["hasBlockEntity"] == false
            }
            "block_entity" => {
                membership == "loaded_block_position" && capture == "native_persisted_block_entity"
            }
            "entity" => {
                (presence == "present"
                    && membership == "loaded_entity_identity"
                    && capture == "native_persisted_entity")
                    || (presence == "absent"
                        && original.is_some()
                        && membership == "retained_destroyed_native_identity"
                        && capture == "observed_entity_instance")
            }
            "storage" => {
                membership == "current_cached_command_storage" && capture == "native_storage_key"
            }
            "score" => membership == "current_native_scoreboard" && capture == "native_score_entry",
            "objective" => {
                membership == "current_native_scoreboard"
                    && capture == "native_objective_and_all_scores"
            }
            _ => false,
        };
        if status != "known" || presence == "unknown" || !admitted || !raw["payload"].is_object() {
            return Err(NativeTargetError::Invalid);
        }
    }
    validate_payload(raw, selector.value(), original).map_err(|_| NativeTargetError::Invalid)?;
    Ok(())
}
fn fields(value: &Value, keys: &[&str]) -> TargetResult<()> {
    let object = value.as_object().ok_or(NativeTargetError::Invalid)?;
    if object.len() != keys.len() || keys.iter().any(|k| !object.contains_key(*k)) {
        Err(NativeTargetError::Invalid)
    } else {
        Ok(())
    }
}
fn string<'a>(value: &'a Value, key: &str) -> TargetResult<&'a str> {
    value[key].as_str().ok_or(NativeTargetError::Invalid)
}
fn location(value: &Value, key: &str) -> TargetResult<()> {
    ResourceLocation::new(string(value, key)?)
        .map(|_| ())
        .map_err(|_| NativeTargetError::Invalid)
}
fn atom(value: &Value, key: &str, dot: bool) -> TargetResult<()> {
    let s = string(value, key)?;
    if s.is_empty()
        || s.len() > 128
        || s.bytes().any(|b| {
            !b.is_ascii_alphanumeric()
                && b != b'_'
                && b != b'-'
                && !(dot && [b'.', b'#'].contains(&b))
        })
    {
        Err(NativeTargetError::Invalid)
    } else {
        Ok(())
    }
}
fn resource(value: &Value) -> TargetResult<()> {
    ResourceId::new(string(value, "resourceId")?)
        .map(|_| ())
        .map_err(|_| NativeTargetError::Invalid)
}
fn hex(text: &str) -> TargetResult<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(2) || text.len() > 2 * MAX_RAW_BYTES {
        return Err(NativeTargetError::Invalid);
    }
    let mut result = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let digit = |b: u8| -> TargetResult<u8> {
            match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(NativeTargetError::Invalid),
            }
        };
        result.push(digit(pair[0])? * 16 + digit(pair[1])?);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn selector() -> NativeSelector {
        NativeSelector::from_value(&json!({"kind":"entity","dimension":"minecraft:overworld","uuid":"00000000-0000-0000-0000-000000000001","expectedType":"minecraft:block_display"})).unwrap()
    }
    fn raw(selector: &NativeSelector) -> Value {
        json!({"format":"mmmm.native.target/1","selector":selector.value(),"status":"unknown","presence":"unknown","membershipScope":"unknown","captureScope":"native_persisted_entity","coverage":"best_effort","reason":"loaded_uuid_not_observed","payload":null})
    }
    #[test]
    fn loaded_uuid_missing_does_not_prove_global_absence_or_full_target() {
        let selector = selector();
        let mut observation = raw(&selector);
        validate_coverage(&observation, &selector, None).unwrap();
        observation["coverage"] = json!("full_target");
        assert!(validate_coverage(&observation, &selector, None).is_err());
        observation["status"] = json!("known");
        observation["presence"] = json!("absent");
        observation["payload"] = json!({});
        observation["membershipScope"] = json!("global_uuid_absence");
        assert!(validate_coverage(&observation, &selector, None).is_err());
    }
    #[test]
    fn destroyed_identity_full_capture_requires_original_invocation_route() {
        let selector = selector();
        let mut observation = raw(&selector);
        observation["status"] = json!("known");
        observation["presence"] = json!("absent");
        observation["membershipScope"] = json!("retained_destroyed_native_identity");
        observation["captureScope"] = json!("observed_entity_instance");
        observation["coverage"] = json!("full_target");
        observation["payload"] = json!({"retained":true});
        assert!(validate_coverage(&observation, &selector, None).is_err());
        let pins = OriginalTargetPins {
            invocation_id: InvocationId::new("actual-original-invocation").unwrap(),
            binding_id: BindingId::new("original-binding").unwrap(),
            operation_id: OperationId::new("original-operation").unwrap(),
            selector: selector.value().clone(),
            before_sha256: raw_digest(b"actual native before"),
            owner_tag: "actual_compiled_tag".into(),
        };
        assert!(validate_coverage(&observation, &selector, Some(&pins)).is_err());
    }
    #[test]
    fn native_selector_rejects_extra_authority_and_pathlike_state_keys() {
        let mut value = selector().value().clone();
        value["principal"] = json!("caller");
        assert!(NativeSelector::from_value(&value).is_err());
        let mut storage = json!({"kind":"storage","storage":"mmmm:states","key":"state","resourceId":"registered-state"});
        NativeSelector::from_value(&storage).unwrap();
        storage["key"] = json!("state.other");
        assert!(NativeSelector::from_value(&storage).is_err());
        assert!(hex("AA").is_err());
        assert!(hex("a").is_err());
    }
    #[test]
    fn local_diagnostics_preserve_authority_and_storage_causes() {
        use std::error::Error;
        let authority = NativeTargetError::Authority(AppError::new(
            "PERMISSION_REQUIRED",
            "Current Project scope ended",
        ));
        assert!(
            authority
                .source()
                .unwrap()
                .downcast_ref::<AppError>()
                .is_some()
        );
        let storage =
            NativeTargetError::Storage(StorageError::Conflict("Actual original observation pin"));
        assert!(
            storage
                .source()
                .unwrap()
                .downcast_ref::<StorageError>()
                .is_some()
        );
        assert!(NativeTargetError::Invalid.source().is_none());
    }
}

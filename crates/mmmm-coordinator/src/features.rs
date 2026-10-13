//! Canonical feature facades borrow the Coordinator's one store for one call.
//! Sources are installed in process. Wire context/profile/rights/evidence claims
//! never construct a source authority, a verified target, or a release proof.

use crate::{
    auth::AuthenticatedPrincipal,
    host::HostBridge,
    service::{RequestBudget, ServiceError, ServiceExtension, ServiceExtensionContext},
};
use mmmm_adapters::{
    InterfaceObservation, InventorySnapshot, ProfileApproval, ProviderRegistry, RouteContext,
};
use mmmm_application::Application;
use mmmm_compiler::{PackBuildInputs, ResolvedSymbols, VerifiedTarget};
use mmmm_contracts::{
    ContextId, ContractValidator, PrincipalId, Sha256Digest, canonical_digest, projected_digest,
    raw_digest,
};
use mmmm_exchange::{
    ExchangeError, ExchangeResult,
    archive::{ArchiveLimits, write_zip_with_cancel},
    bake::{BakeVerifierPort, IngestedBake, bake_ingest},
    manifest::{exchange_inspect, exchange_prepare},
    patch::{DeltaKind, DeltaPolicy, SceneEdit, diff_scene_edits, scene_diff},
    planning::{bake_plan_request, scene_plan_request},
    resources::{AuthorizedBytes, Redistribution, ResourcePort, ResourcePurpose, verify_resource},
    selection::{ObjectNode, Selection},
};
use mmmm_policy::{VerifiedAdmissionEvidence, VerifiedEvidenceIndex};
use mmmm_reference::{
    AccessControl, CaptureControl, Catalog, CatalogLimits, ReadPrincipal, ShapeAuthority,
    ShapeControl, ShapeGrant, ShapeLimits, ShapePort, ShapeProbe, ShapeService, ShapeSourceResult,
    SnapshotSource,
};
use mmmm_runtime::storage::DurableStore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Builtins and FN31 have separate owners. No extension can replace them.
pub const FEATURE_METHODS: [&str; 19] = [
    "math.compile",
    "providers.discover",
    "route.resolve",
    "provider.invoke",
    "compatibility.bind",
    "catalog.search",
    "catalog.describe",
    "catalog.capture",
    "world.shape_query",
    "exchange.prepare",
    "exchange.inspect",
    "bake.plan",
    "bake.ingest",
    "scene.diff",
    "scene.plan",
    "pack.build",
    "command.complete",
    "dependency.admit",
    "release.evaluate",
];

const MAX_VALUE_NODES: usize = 200_000;
const MAX_VALUE_BYTES: usize = 8 * 1024 * 1024;
const MAX_BAKE_ENTRIES: usize = 16;
const MAX_BAKE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CALL_RESOURCE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CALL_RESOURCE_READS: usize = 8192;

/// Actual current access, produced by the trusted source resolver. The resolver
/// must authorize Project and snapshot access against the current policy, bind
/// the context to the installed host/workspace registry, and read Project from
/// this store. This type is deliberately not deserializable.
pub struct FeatureAccess {
    pub read_principal: ReadPrincipal,
    pub context: Option<Value>,
    pub project: Option<Value>,
    pub granted_permissions: BTreeSet<String>,
}

/// A short store borrow with exact registered-resource ACL checks at admission
/// and completion. `stage` is private generated-product staging, not a file
/// ingress permission or a caller-provided redistribution grant. Implementors
/// must retain immutable ResourceRef metadata and exact-source rights evidence.
pub trait FeatureResourcePort: ResourcePort {
    fn stage(&mut self, resource: &Value, bytes: &[u8]) -> ExchangeResult<()>;
}

pub struct MathInputs {
    pub target: VerifiedTarget,
    pub symbols: ResolvedSymbols,
}
pub struct PackInputs {
    pub target: VerifiedTarget,
    pub inputs: PackBuildInputs,
}
pub struct CompatibilityInputs<'a> {
    pub registry: &'a mut ProviderRegistry,
    pub approval: ProfileApproval,
    pub observation: InterfaceObservation,
}
pub struct CaptureInputs<'a> {
    pub access: Box<dyn AccessControl + 'a>,
    pub source: Box<dyn SnapshotSource + 'a>,
}
pub struct ShapeInputs<'a> {
    pub authority: Box<dyn ShapeAuthority + 'a>,
    pub port: Box<dyn ShapePort + 'a>,
}

/// Manual edit codecs produce this only after reading approved exact CAS bytes
/// and verifying their selection/object-map/source-map pins. Caller JSON cannot
/// instantiate a bake or silently gain create/delete authority through a label.
pub struct ManualSceneInputs {
    pub selection: Selection,
    pub edits: Vec<SceneEdit>,
    pub artifact: Value,
    pub source_artifact: Value,
    pub source_map: Value,
    pub losses: Vec<Value>,
    pub policy: DeltaPolicy,
}

/// Mandatory trusted composition. No generic JSON dispatcher is exposed here:
/// every feature uses its owning Rust algorithm and only typed source inputs.
/// Ports must check the supplied live budget while enumerating or performing IO.
/// Optional missing backends return SOURCE_UNAVAILABLE/CAPABILITY_UNAVAILABLE;
/// they must not infer readiness from provider declarations or fixture claims.
pub trait FeatureSources {
    fn access(
        &mut self,
        principal: &AuthenticatedPrincipal,
        method: &str,
        input: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> Result<FeatureAccess, ServiceError>;

    fn resources<'a>(
        &'a mut self,
        access: &'a FeatureAccess,
        store: &'a mut DurableStore,
        budget: &'a RequestBudget,
    ) -> Result<Box<dyn FeatureResourcePort + 'a>, ServiceError>;

    fn inventory(
        &mut self,
        _access: &FeatureAccess,
        _store: &DurableStore,
        _budget: &RequestBudget,
    ) -> Result<InventorySnapshot, ServiceError> {
        Err(unavailable())
    }
    fn compatibility<'a>(
        &'a mut self,
        _access: &FeatureAccess,
        _input: &Value,
        _store: &DurableStore,
        _budget: &RequestBudget,
    ) -> Result<CompatibilityInputs<'a>, ServiceError> {
        Err(unavailable())
    }
    fn math_inputs(
        &mut self,
        _access: &FeatureAccess,
        _input: &Value,
        _store: &DurableStore,
        _budget: &RequestBudget,
    ) -> Result<MathInputs, ServiceError> {
        Err(profile_unavailable())
    }
    fn pack_inputs(
        &mut self,
        _access: &FeatureAccess,
        _input: &Value,
        _store: &DurableStore,
        _budget: &RequestBudget,
    ) -> Result<PackInputs, ServiceError> {
        Err(profile_unavailable())
    }
    fn catalog_access<'a>(
        &'a mut self,
        _access: &FeatureAccess,
        _store: &'a DurableStore,
        _budget: &'a RequestBudget,
    ) -> Result<Box<dyn AccessControl + 'a>, ServiceError> {
        Err(unavailable())
    }
    fn capture<'a>(
        &'a mut self,
        _access: &FeatureAccess,
        _input: &Value,
        _store: &'a mut DurableStore,
        _budget: &'a RequestBudget,
    ) -> Result<CaptureInputs<'a>, ServiceError> {
        Err(unavailable())
    }
    /// Runs only after the owning Catalog accepted the actual capture. A
    /// retained source adapter must verify its private pending receipt against
    /// this Catalog before publishing issuance to exchange or artifact reads.
    fn capture_completed(
        &mut self,
        _access: &FeatureAccess,
        _snapshot: &Value,
        _catalog: &Catalog,
        _store: &mut DurableStore,
        _budget: &RequestBudget,
    ) -> Result<(), ServiceError> {
        Ok(())
    }
    fn shape<'a>(
        &'a mut self,
        _access: &FeatureAccess,
        _input: &Value,
        _store: &'a mut DurableStore,
        _budget: &'a RequestBudget,
    ) -> Result<ShapeInputs<'a>, ServiceError> {
        Err(unavailable())
    }

    /// In addition to ResourcePort.authorize_selection, verify selected DTOs
    /// against actual authored historical Project pins, dataSnapshotId against
    /// the accessible immutable catalog, and optional physics against its exact
    /// registered owned source. Digest/schema validation alone is insufficient.
    fn authorize_exchange_prepare(
        &mut self,
        _access: &FeatureAccess,
        _input: &Value,
        _store: &DurableStore,
        _budget: &RequestBudget,
    ) -> Result<(), ServiceError> {
        Err(unavailable())
    }
    fn bake_verifier(
        &mut self,
        _access: &FeatureAccess,
        _input: &Value,
        _store: &DurableStore,
        _budget: &RequestBudget,
    ) -> Result<Box<dyn BakeVerifierPort>, ServiceError> {
        Err(capability_unavailable())
    }
    fn delta_policy(
        &mut self,
        _access: &FeatureAccess,
        _input: &Value,
        _store: &DurableStore,
        _budget: &RequestBudget,
    ) -> Result<DeltaPolicy, ServiceError> {
        Err(unavailable())
    }
    fn manual_scene(
        &mut self,
        _access: &FeatureAccess,
        _input: &Value,
        _store: &DurableStore,
        _budget: &RequestBudget,
    ) -> Result<ManualSceneInputs, ServiceError> {
        Err(unavailable())
    }
    fn scene_selection(
        &mut self,
        _access: &FeatureAccess,
        _input: &Value,
        _store: &DurableStore,
        _budget: &RequestBudget,
    ) -> Result<Selection, ServiceError> {
        Err(unavailable())
    }
    fn admission_evidence(
        &mut self,
        _access: &FeatureAccess,
        _input: &Value,
        _store: &DurableStore,
        _budget: &RequestBudget,
    ) -> Result<Option<VerifiedAdmissionEvidence>, ServiceError> {
        Ok(None)
    }
    fn release_evidence(
        &mut self,
        _access: &FeatureAccess,
        _input: &Value,
        _store: &DurableStore,
        _budget: &RequestBudget,
    ) -> Result<Option<VerifiedEvidenceIndex>, ServiceError> {
        Ok(None)
    }
}

struct CachedBake {
    principal: PrincipalId,
    scope_digest: mmmm_contracts::Sha256Digest,
    context: Value,
    project_revision: Value,
    bytes: usize,
    ingested: IngestedBake,
}

pub struct FeatureExtension {
    sources: Box<dyn FeatureSources>,
    hosts: HostBridge,
    catalog: Catalog,
    limits: ArchiveLimits,
    bakes: VecDeque<CachedBake>,
    bake_bytes: usize,
}
impl FeatureExtension {
    /// The cursor key belongs to this Coordinator generation and never comes
    /// from a public query. The registry/source implementation is mandatory.
    pub fn new(sources: Box<dyn FeatureSources>, hosts: HostBridge) -> Result<Self, ServiceError> {
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key).map_err(|_| {
            ServiceError::new(
                "RANDOM_UNAVAILABLE",
                "Catalog cursor identity cannot be generated",
            )
        })?;
        let catalog = Catalog::new(key, CatalogLimits::default()).map_err(catalog_error)?;
        Ok(Self::with_catalog(sources, catalog, hosts))
    }
    pub fn with_catalog(
        sources: Box<dyn FeatureSources>,
        catalog: Catalog,
        hosts: HostBridge,
    ) -> Self {
        Self {
            sources,
            hosts,
            catalog,
            limits: ArchiveLimits::default(),
            bakes: VecDeque::new(),
            bake_bytes: 0,
        }
    }

    fn dispatch(
        &mut self,
        method: &str,
        input: &Value,
        access: &FeatureAccess,
        context: &mut ServiceExtensionContext<'_>,
    ) -> Result<Value, ServiceError> {
        match method {
            "math.compile" => {
                let inputs =
                    self.sources
                        .math_inputs(access, input, context.store, context.budget)?;
                context.check(method)?;
                let draft = mmmm_compiler::math_compile(input, &inputs.target, &inputs.symbols)
                    .map_err(domain_error)?;
                let source = draft.source();
                let reference =
                    serde_json::to_value(&source.reference).map_err(|_| invalid_source())?;
                let mut resources =
                    self.sources
                        .resources(access, context.store, context.budget)?;
                resources
                    .stage(&reference, &source.bytes)
                    .map_err(exchange_error)?;
                draft.to_wire().map_err(domain_error)
            }
            "providers.discover" | "route.resolve" => {
                let inventory = self
                    .sources
                    .inventory(access, context.store, context.budget)?;
                let route = route_context(access)?;
                if inventory.context().context_digest() != route.context_digest()
                    || inventory.context().policy_revision() != route.policy_revision()
                    || inventory.context().context_id() != route.context_id()
                {
                    return Err(ServiceError::new(
                        "STALE_CONTEXT",
                        "Inventory is not bound to the current authorized context",
                    ));
                }
                context.check(method)?;
                if method == "providers.discover" {
                    inventory.discover(input)
                } else {
                    inventory.resolve(input)
                }
                .map_err(adapter_error)
            }
            "compatibility.bind" => {
                let route = route_context(access)?;
                let source =
                    self.sources
                        .compatibility(access, input, context.store, context.budget)?;
                context.check(method)?;
                let descriptor = source
                    .registry
                    .bind_compatibility(input, &route, &source.approval, &source.observation)
                    .map_err(adapter_error)?;
                serde_json::to_value(descriptor).map_err(|_| invalid_source())
            }
            "catalog.search" | "catalog.describe" => {
                let authority =
                    self.sources
                        .catalog_access(access, context.store, context.budget)?;
                context.budget.check()?;
                if method == "catalog.search" {
                    self.catalog
                        .search(input, &access.read_principal, authority.as_ref())
                } else {
                    self.catalog
                        .describe(input, &access.read_principal, authority.as_ref())
                }
                .map_err(catalog_error)
            }
            "catalog.capture" => {
                let mut source =
                    self.sources
                        .capture(access, input, context.store, context.budget)?;
                let control = CaptureControl {
                    cancellation: context.budget.cancellation(),
                    deadline: context.budget.deadline(),
                };
                let snapshot = self
                    .catalog
                    .capture(
                        input,
                        &access.read_principal,
                        source.access.as_ref(),
                        source.source.as_mut(),
                        &control,
                    )
                    .map_err(catalog_error)?;
                drop(source);
                // The owning Catalog can retain an identity-complete partial
                // result on cancellation. Its source adapter may publish only
                // a private already-verified retention receipt against this
                // actual Catalog pin and pure current ACL; it may perform no
                // fresh host/source/CAS IO or extend the stopped budget.
                let stopped = context.budget.check().err();
                if stopped.is_none() {
                    context.check(method)?;
                } else if !context.principal.permits(method) || crate::peer::fatal_stop_requested()
                {
                    return Err(forbidden());
                }
                self.sources.capture_completed(
                    access,
                    &snapshot,
                    &self.catalog,
                    context.store,
                    context.budget,
                )?;
                if let Some(stopped) = stopped {
                    return Err(stopped);
                }
                context.check(method)?;
                Ok(snapshot)
            }
            "world.shape_query" => {
                let source = self
                    .sources
                    .shape(access, input, context.store, context.budget)?;
                let deadline = wire_deadline(context.budget)?;
                let control = ShapeControl {
                    cancellation: context.budget.cancellation(),
                    deadline: context.budget.deadline(),
                    deadline_at: &deadline,
                };
                let mut shape =
                    ShapeService::new(ForwardShape(source.port), ShapeLimits::default())
                        .map_err(shape_error)?;
                shape
                    .query(
                        input,
                        &access.read_principal,
                        source.authority.as_ref(),
                        &control,
                    )
                    .map(|read| read.result)
                    .map_err(shape_error)
            }
            "exchange.prepare" => self.prepare_bundle(input, access, context),
            "exchange.inspect" => {
                let mut resources =
                    self.sources
                        .resources(access, context.store, context.budget)?;
                let mut guarded = BudgetResources::new(resources.as_mut(), context.budget);
                let inspected =
                    exchange_inspect(input, &mut guarded, self.limits).map_err(exchange_error)?;
                bounded_clone(inspected.inspection(), context.budget)
            }
            "bake.plan" => {
                let inventory = self
                    .sources
                    .inventory(access, context.store, context.budget)?;
                let source_query = json!({"contextId": input["contextId"], "resource": input["request"]["sourceBundle"]});
                let plan_request = {
                    let mut resources =
                        self.sources
                            .resources(access, context.store, context.budget)?;
                    let mut guarded = BudgetResources::new(resources.as_mut(), context.budget);
                    let source = exchange_inspect(&source_query, &mut guarded, self.limits)
                        .map_err(exchange_error)?;
                    bake_plan_request(input, &source, &inventory).map_err(exchange_error)?
                };
                common_plan(context, method, &plan_request)
            }
            "bake.ingest" => self.ingest_bake(input, access, context),
            "scene.diff" => self.diff_scene(input, access, context),
            "scene.plan" => {
                let selection =
                    self.sources
                        .scene_selection(access, input, context.store, context.budget)?;
                let policy =
                    self.sources
                        .delta_policy(access, input, context.store, context.budget)?;
                context.check(method)?;
                let request =
                    scene_plan_request(input, &selection, &policy).map_err(exchange_error)?;
                common_plan(context, method, &request)
            }
            "pack.build" => {
                let inputs =
                    self.sources
                        .pack_inputs(access, input, context.store, context.budget)?;
                context.check(method)?;
                let draft = mmmm_compiler::pack_build(input, &inputs.target, inputs.inputs)
                    .map_err(domain_error)?;
                let mut resources =
                    self.sources
                        .resources(access, context.store, context.budget)?;
                for source in draft
                    .resources()
                    .values()
                    .chain(std::iter::once(draft.source_map()))
                {
                    context.budget.check()?;
                    let reference =
                        serde_json::to_value(&source.reference).map_err(|_| invalid_source())?;
                    resources
                        .stage(&reference, &source.bytes)
                        .map_err(exchange_error)?;
                }
                draft.to_wire().map_err(domain_error)
            }
            "command.complete" => self.complete_command(input, access, context),
            "dependency.admit" => {
                let evidence = self.sources.admission_evidence(
                    access,
                    input,
                    context.store,
                    context.budget,
                )?;
                context.check(method)?;
                mmmm_policy::dependency_admit_verified(input, evidence.as_ref())
                    .map_err(policy_error)
            }
            "release.evaluate" => {
                let evidence =
                    self.sources
                        .release_evidence(access, input, context.store, context.budget)?;
                context.check(method)?;
                mmmm_policy::release_evaluate_verified(input, evidence.as_ref())
                    .map_err(policy_error)
            }
            _ => Err(ServiceError::new(
                "IMPLEMENTATION_UNAVAILABLE",
                "Function is not owned by this feature extension",
            )),
        }
    }

    fn complete_command(
        &mut self,
        input: &Value,
        access: &FeatureAccess,
        context: &mut ServiceExtensionContext<'_>,
    ) -> Result<Value, ServiceError> {
        let current = access.context.as_ref().ok_or_else(unavailable)?;
        let id = ContextId::new(text(current, "contextId")?).map_err(|_| invalid_source())?;
        let live = self
            .hosts
            .context_with_deadline(
                context.principal.principal(),
                &id,
                context.budget.deadline(),
            )
            .map_err(|e| ServiceError::new(e.code, e.message))?;
        if live != *current || !access.granted_permissions.contains("mmmm:command_complete") {
            return Err(forbidden());
        }
        context.check("command.complete")?;
        let response = self
            .hosts
            .inspect_response_with_deadline(
                context.principal.principal(),
                &id,
                json!({"kind":"command_complete", "request":bounded_clone(input, context.budget)?}),
                context.budget.deadline(),
            )
            .map_err(|e| ServiceError::new(e.code, e.message))?;
        // Retain the complete original host response, including original error
        // data, rather than converting an error into an empty suggestion list.
        let bytes = mmmm_contracts::encode_json(&response).map_err(|_| limit())?;
        let reference = content_resource(
            "command-completion-evidence",
            "application/vnd.mmmm.host-response+json",
            &bytes,
        );
        {
            let mut resources = self
                .sources
                .resources(access, context.store, context.budget)?;
            resources
                .stage(&reference, &bytes)
                .map_err(exchange_error)?;
        }
        context.check("command.complete")?;
        let after = self
            .hosts
            .context_with_deadline(
                context.principal.principal(),
                &id,
                context.budget.deadline(),
            )
            .map_err(|e| ServiceError::new(e.code, e.message))?;
        if after != *current {
            return Err(ServiceError::new(
                "STALE_CONTEXT",
                "Command completion context changed before delivery",
            ));
        }
        if response["status"] != "ok" {
            return Err(host_error(&response));
        }
        let output = response.get("payload").ok_or_else(invalid_source)?;
        if output["contextDigest"] != current["contextDigest"] {
            return Err(invalid_source());
        }
        bounded_clone(output, context.budget)
    }

    fn prepare_bundle(
        &mut self,
        input: &Value,
        access: &FeatureAccess,
        context: &mut ServiceExtensionContext<'_>,
    ) -> Result<Value, ServiceError> {
        self.sources
            .authorize_exchange_prepare(access, input, context.store, context.budget)?;
        context.check("exchange.prepare")?;
        let mut resources = self
            .sources
            .resources(access, context.store, context.budget)?;
        let mut guarded = BudgetResources::new(resources.as_mut(), context.budget);
        // Resolve actual bytes and source rights once before assigning content
        // identity. A request's policy/right digest cannot enter this witness.
        let bundle = exchange_prepare(input, "bundle-draft", &mut guarded, self.limits)
            .map_err(exchange_error)?;
        let manifest = stable_bundle_manifest(bundle.manifest(), access, context.budget)?;
        stage_bundle(
            &bundle,
            &manifest,
            &mut guarded,
            self.limits,
            context.budget,
        )?;
        Ok(manifest)
    }

    fn ingest_bake(
        &mut self,
        input: &Value,
        access: &FeatureAccess,
        context: &mut ServiceExtensionContext<'_>,
    ) -> Result<Value, ServiceError> {
        let mut verifier =
            self.sources
                .bake_verifier(access, input, context.store, context.budget)?;
        context.check("bake.ingest")?;
        let ingested = {
            let mut resources = self
                .sources
                .resources(access, context.store, context.budget)?;
            let mut guarded = BudgetResources::new(resources.as_mut(), context.budget);
            let ingested = bake_ingest(input, &mut guarded, verifier.as_mut(), self.limits)
                .map_err(exchange_error)?;
            for (reference, bytes) in ingested
                .canonical_clip_resources()
                .map_err(exchange_error)?
            {
                context.budget.check()?;
                guarded.stage(&reference, &bytes).map_err(exchange_error)?;
            }
            ingested
        };
        let output = bounded_clone(ingested.artifact(), context.budget)?;
        let mut bytes = ingested.original_bytes().len();
        for value in std::iter::once(ingested.artifact())
            .chain(std::iter::once(ingested.source_selection()))
            .chain(ingested.canonical_clips())
        {
            bytes = bytes
                .checked_add(value_weight(value, context.budget)?)
                .ok_or_else(limit)?;
        }
        if bytes > MAX_BAKE_BYTES {
            return Err(limit());
        }
        // Complete every fallible source/context clone before changing cache
        // accounting. Cancellation must not reserve bytes for an absent entry.
        let entry = CachedBake {
            principal: access.read_principal.principal_id.clone(),
            scope_digest: access.read_principal.permission_scope_digest.clone(),
            context: bounded_clone(
                access.context.as_ref().ok_or_else(unavailable)?,
                context.budget,
            )?,
            project_revision: access.project.as_ref().ok_or_else(unavailable)?["revision"].clone(),
            bytes,
            ingested,
        };
        while self.bakes.len() >= MAX_BAKE_ENTRIES || self.bake_bytes + bytes > MAX_BAKE_BYTES {
            context.budget.check()?;
            if let Some(old) = self.bakes.pop_front() {
                self.bake_bytes -= old.bytes;
            } else {
                return Err(limit());
            }
        }
        self.bake_bytes += bytes;
        self.bakes.push_back(entry);
        Ok(output)
    }

    fn diff_scene(
        &mut self,
        input: &Value,
        access: &FeatureAccess,
        context: &mut ServiceExtensionContext<'_>,
    ) -> Result<Value, ServiceError> {
        let current_context = access.context.as_ref().ok_or_else(unavailable)?;
        let current_project = access.project.as_ref().ok_or_else(unavailable)?;
        let found = self.bakes.iter().position(|bake| {
            bake.principal == access.read_principal.principal_id
                && bake.scope_digest == access.read_principal.permission_scope_digest
                && bake.context == *current_context
                && bake.project_revision == current_project["revision"]
                && bake.ingested.artifact() == &input["artifact"]
        });
        if let Some(index) = found {
            let policy = self
                .sources
                .delta_policy(access, input, context.store, context.budget)?;
            let mut resources = self
                .sources
                .resources(access, context.store, context.budget)?;
            let mut guarded = BudgetResources::new(resources.as_mut(), context.budget);
            // Reauthorize the original immutable artifact on cache hits. A
            // cached sealed value is provenance, never a current access grant.
            let ingested = &self.bakes[index].ingested;
            guarded
                .read(
                    text(input, "contextId")?,
                    ingested.resource(),
                    ResourcePurpose::Read,
                    self.limits.max_member_bytes,
                )
                .map_err(exchange_error)?;
            let patch = scene_diff(
                input,
                ingested,
                "patch-draft",
                &policy,
                &mut guarded,
                self.limits,
            )
            .map_err(exchange_error)?;
            let selection =
                Selection::from_value(ingested.source_selection()).map_err(exchange_error)?;
            stable_patch(patch, access, &selection, &policy, context.budget)
        } else {
            let manual = self
                .sources
                .manual_scene(access, input, context.store, context.budget)?;
            if manual.selection.value() != &input["selection"]
                || manual.artifact != input["artifact"]
                || manual.source_map != input["sourceMap"]
            {
                return Err(invalid_source());
            }
            context.check("scene.diff")?;
            let patch = diff_scene_edits(
                &manual.selection,
                &manual.edits,
                &manual.source_artifact,
                &manual.source_map,
                &manual.losses,
                "patch-draft",
                &manual.policy,
            )
            .map_err(exchange_error)?;
            stable_patch(
                patch,
                access,
                &manual.selection,
                &manual.policy,
                context.budget,
            )
        }
    }
}

impl ServiceExtension for FeatureExtension {
    fn call(
        &mut self,
        method: &str,
        input: &Value,
        context: &mut ServiceExtensionContext<'_>,
    ) -> Result<Value, ServiceError> {
        context.check(method)?;
        if !FEATURE_METHODS.contains(&method) {
            return Err(ServiceError::new(
                "IMPLEMENTATION_UNAVAILABLE",
                "Function is not owned by this feature extension",
            ));
        }
        // FN18 belongs exclusively to Coordinator-created durable dispatch.
        // Public invocation remains rejected even for a session allowing FN18.
        if method == "provider.invoke" {
            return Err(ServiceError::new(
                "INTERNAL_ENTRY_REQUIRED",
                "Provider invocation requires an internal durable operation entry",
            ));
        }
        check_value(input, context.budget)?;
        let validator = ContractValidator::shared().map_err(|_| invalid_source())?;
        let function = validator.function(method).map_err(|_| invalid_source())?;
        validator.validate(&function.input, input).map_err(|_| {
            ServiceError::new(
                "SCHEMA_INVALID",
                "Feature input does not match the canonical function contract",
            )
        })?;
        if method == "command.complete" {
            validate_cursor(input, context.budget)?;
        }
        let access = self.sources.access(
            context.principal,
            method,
            input,
            context.store,
            context.budget,
        )?;
        check_access(context.principal, input, &access, context.budget)?;
        let output = self.dispatch(method, input, &access, context)?;
        context.check(method)?;
        check_value(&output, context.budget)?;
        validator.validate(&function.output, &output).map_err(|_| {
            ServiceError::new(
                "SCHEMA_INVALID",
                "Feature output does not match the canonical function contract",
            )
        })?;
        Ok(output)
    }
}

fn check_access(
    principal: &AuthenticatedPrincipal,
    input: &Value,
    access: &FeatureAccess,
    budget: &RequestBudget,
) -> Result<(), ServiceError> {
    budget.check()?;
    if principal.principal() != &access.read_principal.principal_id || !principal.is_current() {
        return Err(forbidden());
    }
    if let Some(context) = &access.context {
        check_value(context, budget)?;
        ContractValidator::shared()
            .and_then(|v| v.validate("ExecutionContext", context))
            .map_err(|_| invalid_source())?;
        let id = text(context, "contextId")?;
        if !principal.permits_context(id) {
            return Err(forbidden());
        }
        if let Some(requested) = input.get("contextId").and_then(Value::as_str) {
            if requested != id {
                return Err(ServiceError::new(
                    "STALE_CONTEXT",
                    "Resolved current context differs from the request locator",
                ));
            }
        }
        if access
            .project
            .as_ref()
            .is_none_or(|project| project["projectId"] != context["projectId"])
        {
            return Err(invalid_source());
        }
    } else if input.get("contextId").and_then(Value::as_str).is_some() {
        return Err(unavailable());
    }
    if let Some(project) = &access.project {
        check_value(project, budget)?;
        ContractValidator::shared()
            .and_then(|v| v.validate("Project", project))
            .map_err(|_| invalid_source())?;
        if let Some(requested) = input.get("projectId").and_then(Value::as_str) {
            if project["projectId"].as_str() != Some(requested) {
                return Err(forbidden());
            }
        }
    }
    budget.check()
}

fn route_context(access: &FeatureAccess) -> Result<RouteContext, ServiceError> {
    RouteContext::from_execution_context(
        access.context.as_ref().ok_or_else(unavailable)?,
        access.granted_permissions.clone(),
    )
    .map_err(adapter_error)
}

/// Uses the same plan construction, authority, store and durable ledger as
/// plan.create. It cannot dispatch or create a second feature-specific journal.
fn common_plan(
    context: &mut ServiceExtensionContext<'_>,
    method: &str,
    request: &Value,
) -> Result<Value, ServiceError> {
    context.check(method)?;
    let mut application = Application {
        store: context.store,
        authority: context.ports.authority.as_mut(),
        planner: context.ports.planner.as_mut(),
        provider: context.ports.provider.as_mut(),
        observer: context.ports.observer.as_mut(),
        ids: context.ports.ids.as_mut(),
        clock: context.ports.clock.as_ref(),
    };
    application
        .plan_create(context.principal.principal(), request)
        .map_err(|error| ServiceError::new(error.code, error.message))
}

fn stage_bundle(
    bundle: &mmmm_exchange::manifest::PreparedBundle,
    manifest: &Value,
    resources: &mut BudgetResources<'_>,
    limits: ArchiveLimits,
    budget: &RequestBudget,
) -> Result<(), ServiceError> {
    for payload in manifest["payloads"].as_array().ok_or_else(invalid_source)? {
        budget.check()?;
        if let Some(bytes) = bundle.payload(text(payload, "path")?) {
            if payload["redistribution"] != "allowed" {
                return Err(forbidden());
            }
            verify_resource(&payload["resource"], bytes, limits.max_member_bytes)
                .map_err(exchange_error)?;
            resources
                .stage(&payload["resource"], bytes)
                .map_err(exchange_error)?;
        }
    }
    let manifest_bytes = mmmm_contracts::encode_json(manifest).map_err(|_| limit())?;
    let manifest_ref = content_resource(
        "exchange-manifest",
        "application/vnd.mmmm.exchange+json",
        &manifest_bytes,
    );
    resources
        .stage(&manifest_ref, &manifest_bytes)
        .map_err(exchange_error)?;
    let mut members = BTreeMap::new();
    let mut total = 0_u64;
    for (path, bytes) in bundle.members() {
        budget.check()?;
        let bytes = if path == "mmmm-exchange.json" {
            manifest_bytes.as_slice()
        } else {
            bytes.as_slice()
        };
        total = total.checked_add(bytes.len() as u64).ok_or_else(limit)?;
        if total > limits.max_total_bytes || bytes.len() as u64 > limits.max_member_bytes {
            return Err(limit());
        }
        let mut copied = Vec::new();
        copied.try_reserve_exact(bytes.len()).map_err(|_| limit())?;
        for chunk in bytes.chunks(64 * 1024) {
            budget.check()?;
            copied.extend_from_slice(chunk);
        }
        members.insert(path.clone(), copied);
    }
    let mut cancelled = || budget.check().is_err();
    let zip_bytes =
        write_zip_with_cancel(&members, limits, &mut cancelled).map_err(exchange_error)?;
    let zip_ref = content_resource("exchange-zip", "application/zip", &zip_bytes);
    resources
        .stage(&zip_ref, &zip_bytes)
        .map_err(exchange_error)?;
    // FN24 returns SceneExchangeManifest. ZIP/manifest are retained internal
    // resources; adding a zip field would violate that original wire contract.
    Ok(())
}

fn stable_bundle_manifest(
    draft: &Value,
    access: &FeatureAccess,
    budget: &RequestBudget,
) -> Result<Value, ServiceError> {
    let mut manifest = bounded_clone(draft, budget)?;
    let fields = manifest.as_object_mut().ok_or_else(invalid_source)?;
    fields.remove("bundleId");
    fields.remove("bundleRevision");
    // The payload list contains verified exact source refs and redistribution
    // observations returned by the actual ResourcePort, not the request.
    let id = semantic_id("bundle", &manifest, access, None, budget)?;
    manifest["bundleId"] = json!(id);
    manifest["bundleRevision"] =
        json!(projected_digest("SceneExchangeManifest", &manifest).map_err(|_| invalid_source())?);
    ContractValidator::shared()
        .and_then(|v| v.validate("SceneExchangeManifest", &manifest))
        .map_err(|_| invalid_source())?;
    budget.check()?;
    Ok(manifest)
}

fn stable_patch(
    mut patch: Value,
    access: &FeatureAccess,
    selection: &Selection,
    policy: &DeltaPolicy,
    budget: &RequestBudget,
) -> Result<Value, ServiceError> {
    check_value(&patch, budget)?;
    let policy_digest = delta_policy_digest(selection, &patch, policy, budget)?;
    patch
        .as_object_mut()
        .ok_or_else(invalid_source)?
        .remove("patchId");
    // This content was produced by the owning diff algorithm from actual
    // retained artifact/source-map bytes or the trusted manual codec. It binds
    // raw ResourceRef hashes as well as exact base/qualified object identities.
    let id = semantic_id("patch", &patch, access, Some(&policy_digest), budget)?;
    patch["patchId"] = json!(id);
    ContractValidator::shared()
        .and_then(|v| v.validate("ScenePatch", &patch))
        .map_err(|_| invalid_source())?;
    budget.check()?;
    Ok(patch)
}

fn semantic_id(
    prefix: &str,
    content: &Value,
    access: &FeatureAccess,
    policy: Option<&Sha256Digest>,
    budget: &RequestBudget,
) -> Result<String, ServiceError> {
    check_value(content, budget)?;
    let source = raw_digest(include_bytes!("features.rs"));
    let scope = &access.read_principal.permission_scope_digest;
    let subject = json!({"kind":"mmmm.feature.content-identity/1", "contractVersion":"0.2.0",
        "feature":prefix,"implementationDigest":source,"principal":access.read_principal.principal_id,
        "currentAuthorityScopeDigest":scope,"currentContextDigest":access.context.as_ref().map(|v|&v["contextDigest"]),
        "currentProjectRevision":access.project.as_ref().map(|v|&v["revision"]),"deltaPolicyDigest":policy,"content":content});
    check_value(&subject, budget)?;
    let digest = canonical_digest(&subject).map_err(|_| invalid_source())?;
    budget.check()?;
    Ok(format!("{prefix}-{}", digest.as_str()))
}

fn delta_policy_digest(
    selection: &Selection,
    patch: &Value,
    policy: &DeltaPolicy,
    budget: &RequestBudget,
) -> Result<Sha256Digest, ServiceError> {
    let mut targets = BTreeSet::new();
    for (target, _) in selection.nodes() {
        budget.check()?;
        if selection.selected(target) {
            targets.insert(target.clone());
        }
    }
    for entry in patch["entries"].as_array().ok_or_else(invalid_source)? {
        budget.check()?;
        targets.insert(ObjectNode {
            instance_id: text(entry, "instanceId")?.to_owned(),
            node_id: text(entry, "nodeId")?.to_owned(),
        });
    }
    let mut hash = Sha256::new();
    hash.update(b"mmmm.scene.delta-policy/1\0");
    for target in targets {
        budget.check()?;
        for identity in [&target.instance_id, &target.node_id] {
            hash.update((identity.len() as u64).to_be_bytes());
            hash.update(identity.as_bytes());
        }
        for kind in [
            DeltaKind::CreateNode,
            DeltaKind::UpdateTransform,
            DeltaKind::UpdateDisplay,
            DeltaKind::DeleteNode,
            DeltaKind::AttachClip,
        ] {
            budget.check()?;
            // Read the authoritative typed policy. No public digest/allow flag
            // can replace its actual qualified-node delta permissions.
            hash.update([u8::from(policy.check(&target, kind).is_ok())]);
        }
    }
    check_value(&patch["losses"], budget)?;
    hash.update(
        canonical_digest(&patch["losses"])
            .map_err(|_| invalid_source())?
            .as_str()
            .as_bytes(),
    );
    budget.check()?;
    let digest = hash.finalize();
    Sha256Digest::new(
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .map_err(|_| invalid_source())
}

struct BudgetResources<'a> {
    inner: &'a mut dyn FeatureResourcePort,
    budget: &'a RequestBudget,
    reads: usize,
    bytes: u64,
}
impl<'a> BudgetResources<'a> {
    fn new(inner: &'a mut dyn FeatureResourcePort, budget: &'a RequestBudget) -> Self {
        Self {
            inner,
            budget,
            reads: 0,
            bytes: 0,
        }
    }
    fn check(&self) -> ExchangeResult<()> {
        self.budget
            .check()
            .map_err(|error| ExchangeError::new(error.code, error.message))
    }
    fn account(&mut self, bytes: u64) -> ExchangeResult<()> {
        self.check()?;
        self.reads = self.reads.checked_add(1).ok_or_else(exchange_limit)?;
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(exchange_limit)?;
        if self.reads > MAX_CALL_RESOURCE_READS || self.bytes > MAX_CALL_RESOURCE_BYTES {
            return Err(exchange_limit());
        }
        Ok(())
    }
    fn stage(&mut self, reference: &Value, bytes: &[u8]) -> ExchangeResult<()> {
        self.account(bytes.len() as u64)?;
        verify_resource(reference, bytes, MAX_CALL_RESOURCE_BYTES)?;
        self.inner.stage(reference, bytes)?;
        self.check()
    }
}
impl ResourcePort for BudgetResources<'_> {
    fn authorize_selection(&mut self, context: &str, selection: &Value) -> ExchangeResult<()> {
        self.check()?;
        check_value(selection, self.budget).map_err(|e| ExchangeError::new(e.code, e.message))?;
        self.inner.authorize_selection(context, selection)?;
        self.check()
    }
    fn read(
        &mut self,
        context: &str,
        resource: &Value,
        purpose: ResourcePurpose,
        max_bytes: u64,
    ) -> ExchangeResult<AuthorizedBytes> {
        self.check()?;
        let remaining = MAX_CALL_RESOURCE_BYTES
            .checked_sub(self.bytes)
            .ok_or_else(exchange_limit)?;
        let bytes = self
            .inner
            .read(context, resource, purpose, max_bytes.min(remaining))?;
        verify_resource(resource, &bytes.bytes, max_bytes.min(remaining))?;
        self.account(bytes.bytes.len() as u64)?;
        if purpose == ResourcePurpose::Redistribute
            && bytes.redistribution != Redistribution::Allowed
        {
            return Err(ExchangeError::new(
                "REDISTRIBUTION_FORBIDDEN",
                "Actual source rights do not permit redistribution",
            ));
        }
        self.check()?;
        Ok(bytes)
    }
    fn embedded_rights(
        &mut self,
        context: &str,
        resource: &Value,
    ) -> ExchangeResult<Redistribution> {
        self.check()?;
        let rights = self.inner.embedded_rights(context, resource)?;
        self.check()?;
        Ok(rights)
    }
}

struct ForwardShape<'a>(Box<dyn ShapePort + 'a>);
impl ShapePort for ForwardShape<'_> {
    fn probe_shape(
        &mut self,
        grant: &ShapeGrant,
        query: &Value,
        control: &ShapeControl<'_>,
    ) -> Result<ShapeProbe, mmmm_reference::ShapeError> {
        control.check()?;
        self.0.probe_shape(grant, query, control)
    }
    fn query_shape(
        &mut self,
        principal: &ReadPrincipal,
        grant: &ShapeGrant,
        query: &Value,
        expected: &ShapeProbe,
        control: &ShapeControl<'_>,
    ) -> Result<ShapeSourceResult, mmmm_reference::ShapeError> {
        control.check()?;
        self.0
            .query_shape(principal, grant, query, expected, control)
    }
    fn authorize_geometry(
        &mut self,
        principal: &ReadPrincipal,
        grant: &ShapeGrant,
        resource: &Value,
    ) -> Result<(), mmmm_reference::ShapeError> {
        self.0.authorize_geometry(principal, grant, resource)
    }
}

/// Checked traversal happens before every potentially large clone. The owning
/// compiler/normalization codecs also have finite domain bounds; those codecs
/// still need internal cancellation callbacks to establish mid-CPU cancellation.
fn check_value(value: &Value, budget: &RequestBudget) -> Result<(), ServiceError> {
    value_weight(value, budget).map(|_| ())
}
fn value_weight(value: &Value, budget: &RequestBudget) -> Result<usize, ServiceError> {
    let mut stack = vec![(value, 0_usize)];
    let mut nodes = 0_usize;
    let mut bytes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        budget.check()?;
        nodes = nodes.checked_add(1).ok_or_else(limit)?;
        if depth > 64 || nodes > MAX_VALUE_NODES {
            return Err(limit());
        }
        match value {
            Value::String(text) => bytes = bytes.checked_add(text.len()).ok_or_else(limit)?,
            Value::Array(values) => {
                if values.len() > MAX_VALUE_NODES - nodes {
                    return Err(limit());
                }
                for value in values {
                    budget.check()?;
                    stack.push((value, depth + 1));
                }
            }
            Value::Object(values) => {
                if values.len() > MAX_VALUE_NODES - nodes {
                    return Err(limit());
                }
                for (key, value) in values {
                    budget.check()?;
                    bytes = bytes.checked_add(key.len()).ok_or_else(limit)?;
                    stack.push((value, depth + 1));
                }
            }
            _ => bytes = bytes.checked_add(24).ok_or_else(limit)?,
        }
        if bytes > MAX_VALUE_BYTES || stack.len() > MAX_VALUE_NODES {
            return Err(limit());
        }
    }
    budget.check()?;
    // Conservative cache accounting includes Value/container/map allocation
    // overhead, as well as UTF-8 payload capacity and the retained raw bytes.
    nodes
        .checked_mul(256)
        .and_then(|base| {
            bytes
                .checked_mul(2)
                .and_then(|payload| base.checked_add(payload))
        })
        .ok_or_else(limit)
}
fn validate_cursor(input: &Value, budget: &RequestBudget) -> Result<(), ServiceError> {
    let command = text(input, "command")?;
    let cursor = input["cursorUtf16"]
        .as_u64()
        .or_else(|| {
            input["cursorUtf16"]
                .as_f64()
                .filter(|n| {
                    n.is_finite() && *n >= 0.0 && n.fract() == 0.0 && *n <= 9_007_199_254_740_991.0
                })
                .map(|n| n as u64)
        })
        .ok_or_else(|| {
            ServiceError::new("CURSOR_INVALID", "Cursor is not a finite UTF-16 boundary")
        })?;
    let mut offset = 0_u64;
    for scalar in command.chars() {
        budget.check()?;
        if offset == cursor {
            return Ok(());
        }
        offset += scalar.len_utf16() as u64;
        if offset > cursor {
            return Err(ServiceError::new(
                "CURSOR_INVALID",
                "Cursor splits a UTF-16 surrogate pair",
            ));
        }
    }
    if offset != cursor {
        return Err(ServiceError::new(
            "CURSOR_INVALID",
            "Cursor is outside the UTF-16 command range",
        ));
    }
    budget.check()
}
fn bounded_clone(value: &Value, budget: &RequestBudget) -> Result<Value, ServiceError> {
    check_value(value, budget)?;
    let result = value.clone();
    budget.check()?;
    Ok(result)
}
fn wire_deadline(budget: &RequestBudget) -> Result<String, ServiceError> {
    let remaining = budget
        .remaining()
        .ok_or_else(|| ServiceError::new("TIME_BUDGET_EXCEEDED", "Request deadline reached"))?;
    let duration = time::Duration::try_from(remaining).map_err(|_| limit())?;
    (time::OffsetDateTime::now_utc() + duration)
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| invalid_source())
}
fn content_resource(prefix: &str, media_type: &str, bytes: &[u8]) -> Value {
    let hash = raw_digest(bytes);
    json!({"resourceId":format!("{prefix}-{}", &hash.as_str()[..24]), "sha256":hash, "mediaType":media_type, "sizeBytes":bytes.len()})
}
fn host_error(response: &Value) -> ServiceError {
    let code = match response["error"]["code"].as_str() {
        Some("CONTEXT_INCOMPLETE") => "CONTEXT_INCOMPLETE",
        Some("CONTEXT_INVALID") => "CONTEXT_INVALID",
        Some("CURSOR_UTF16_INVALID") => "CURSOR_UTF16_INVALID",
        Some("SUGGESTION_LIMIT") => "SUGGESTION_LIMIT",
        Some("COMMAND_TREE_LIMIT") => "COMMAND_TREE_LIMIT",
        Some("CONTEXT_SCOPE_MISMATCH") => "CONTEXT_SCOPE_MISMATCH",
        Some("COMPLETION_FAILED") => "COMPLETION_FAILED",
        Some("PERMISSION_REQUIRED") => "PERMISSION_REQUIRED",
        Some("STALE_CONTEXT") => "STALE_CONTEXT",
        Some("SIDE_MISMATCH") => "SIDE_MISMATCH",
        Some("DEADLINE_EXCEEDED") => "DEADLINE_EXCEEDED",
        Some("CANCELLED") => "CANCELLED",
        _ => "HOST_REQUEST_FAILED",
    };
    ServiceError::new(
        code,
        "The original authenticated host rejected command completion; its complete response is retained",
    )
}
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, ServiceError> {
    value[field].as_str().ok_or_else(invalid_source)
}
fn unavailable() -> ServiceError {
    ServiceError::new(
        "SOURCE_UNAVAILABLE",
        "No actual authorized source adapter is installed for this feature",
    )
}
fn profile_unavailable() -> ServiceError {
    ServiceError::new(
        "UNSUPPORTED_TARGET_VERSION",
        "No actual registered target profile and compiler evidence is available",
    )
}
fn capability_unavailable() -> ServiceError {
    ServiceError::new(
        "CAPABILITY_UNAVAILABLE",
        "No actual independently verified capability is installed for this feature",
    )
}
fn invalid_source() -> ServiceError {
    ServiceError::new(
        "SOURCE_INVALID",
        "Trusted source does not match the canonical authorized source pins",
    )
}
fn forbidden() -> ServiceError {
    ServiceError::new(
        "PERMISSION_REQUIRED",
        "Current authenticated source access is required",
    )
}
fn limit() -> ServiceError {
    ServiceError::new(
        "BUDGET_EXCEEDED",
        "Feature work exceeds its finite resource budget",
    )
}
fn exchange_limit() -> ExchangeError {
    ExchangeError::new(
        "BUDGET_EXCEEDED",
        "Feature resource work exceeds its finite aggregate budget",
    )
}
fn exchange_error(error: ExchangeError) -> ServiceError {
    ServiceError::new(
        error.code,
        "Exchange contract, exact source, rights or capability verification rejected the request",
    )
}
fn adapter_error(error: mmmm_adapters::AdapterError) -> ServiceError {
    ServiceError::new(
        error.code,
        "Current adapter inventory, approval or exact route verification rejected the request",
    )
}
fn domain_error(error: mmmm_domain::DomainError) -> ServiceError {
    ServiceError::new(
        error.code,
        "Owned compiler contract or actual source/target verification rejected the request",
    )
}
fn catalog_error(error: mmmm_reference::CatalogError) -> ServiceError {
    ServiceError::new(
        error.code(),
        "Catalog source, current access or immutable snapshot verification rejected the request",
    )
}
fn shape_error(error: mmmm_reference::ShapeError) -> ServiceError {
    let code = match error.code() {
        "CANCELLED" => "CANCELLED",
        "TIME_BUDGET_EXCEEDED" => "TIME_BUDGET_EXCEEDED",
        "PERMISSION_REQUIRED" => "PERMISSION_REQUIRED",
        "SOURCE_UNAVAILABLE" => "SOURCE_UNAVAILABLE",
        "TARGET_DRIFT" => "TARGET_DRIFT",
        "CHUNK_UNLOADED" => "CHUNK_UNLOADED",
        "SNAPSHOT_STALE" => "SNAPSHOT_STALE",
        "CONTEXT_MISSING" => "CONTEXT_MISSING",
        "PROBE_UNSUPPORTED" => "PROBE_UNSUPPORTED",
        "SCHEMA_UNSUPPORTED" => "SCHEMA_UNSUPPORTED",
        _ => "SHAPE_VERIFICATION_FAILED",
    };
    ServiceError::new(
        code,
        "Actual native shape source or current access verification rejected the query",
    )
}
fn policy_error(error: mmmm_policy::PolicyError) -> ServiceError {
    ServiceError::new(
        error.code,
        "Policy contract or trusted authenticated evidence verification rejected the request",
    )
}

#[cfg(test)]
#[path = "feature_tests.rs"]
mod tests;

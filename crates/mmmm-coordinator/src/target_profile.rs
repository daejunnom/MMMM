//! Target admission is a current, authenticated source relation. A profile,
//! source hash, Java authority envelope, or successful parse is not runtime
//! evidence. This adapter reads the one borrowed journal/CAS, original game
//! input registration and actual paired host observations before the compiler
//! can construct its sealed target. No public function installs these records.

use crate::{
    auth::AuthenticatedPrincipal,
    authority::LocalAuthority,
    catalog_source::{
        RegisteredCatalogSourceIdentity, RegisteredCatalogSources, source_facts_pin,
        validate_source_facts,
    },
    host::HostBridge,
    planning_source::{
        LocalPlanningAccess, PlanningStore, SharedPlanningContexts, VerifiedPlanningTarget,
    },
    service::RequestBudget,
};
use mmmm_application::{Access, AppError, AppResult};
use mmmm_compiler::{
    TargetEvidenceVerifier, TargetRuntimeRules, VerifiedTarget,
    calibration::{CalibrationCase, CalibrationPackProgram, CalibrationProgram},
    scene::NativeSceneStep,
};
use mmmm_contracts::{
    ContextId, ContractValidator, Int32, InvocationId, OperationId, PrincipalId, ProjectId,
    Sha256Digest, SourceId, StepId, TargetProfileId, canonical_digest, encode_json, raw_digest,
    strict_json::{ControlledJsonError, JsonLimits, parse_json_with_control},
};
use mmmm_domain::{DomainError, types::ResourceRef};
use mmmm_exchange::archive::{ArchiveLimits, read_zip_with_required_root};
use mmmm_planner::NativeKind;
use mmmm_reference::CatalogSourceRole;
use mmmm_runtime::storage::{
    BlobRef, DispatchEvidence, DurableStore, EffectEvidence, OperationState, StorageError,
    VerificationRequirement,
    artifact::{ResourceOwner, register_resource},
    project_resources::{
        ProjectResourceAuthority, ProjectResourceQuery, ProjectResourceReader,
        ProjectResourceRequest, ProjectSourceRpcContext, RegisteredProjectResource,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    rc::Rc,
};

const MAX_PROFILES: usize = 64;
const MAX_PROFILE_BYTES: u64 = 256 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CASES: usize = 64;
const MAX_DEFINITION_BYTES: u64 = 1024 * 1024;
const HOST_EVIDENCE_MEDIA: &str = "application/vnd.mmmm.target-host-evidence+json";

/// Explicit authenticated setup supplies exact Project resources and command
/// sources. It cannot install a verified flag or decide a case's expected
/// value. This type has no serde constructor and no public dispatch route.
#[derive(Clone, Debug)]
pub struct TargetProfileResource {
    pub resource: Value,
    pub query: ProjectResourceQuery,
}
#[derive(Clone, Debug)]
pub struct RuntimeCaseSource {
    pub source: TargetProfileResource,
    /// Only the fixed compiler-owned pure constructor can create source. Actual
    /// loaded/executed source authority is admitted separately from host-issued
    /// dispatch receipts and independent retained readback.
    pub program: RuntimeCaseProgram,
}
#[derive(Clone, Debug)]
pub enum RuntimeCaseProgram {
    Numeric(CalibrationProgram),
    DataPack(CalibrationPackProgram),
}
impl RuntimeCaseProgram {
    fn case_id(&self) -> &'static str {
        match self {
            Self::Numeric(program) => program.case().case_id(),
            Self::DataPack(_) => PACK_CASE,
        }
    }
    fn invocation_command(&self) -> &str {
        match self {
            Self::Numeric(program) => program.invocation_command(),
            Self::DataPack(program) => program.invocation_command(),
        }
    }
    fn command_stage_index(&self) -> u32 {
        match self {
            Self::Numeric(program) => program.command_stage_index(),
            Self::DataPack(program) => program.command_stage_index(),
        }
    }
    fn preseed_end_index(&self) -> u32 {
        match self {
            Self::Numeric(program) => program.preseed_end_index(),
            Self::DataPack(_) => 0,
        }
    }
    fn commands(&self) -> &[String] {
        match self {
            Self::Numeric(program) => program.commands(),
            Self::DataPack(program) => program.commands(),
        }
    }
    fn program_digest(&self) -> &Sha256Digest {
        match self {
            Self::Numeric(program) => program.source_digest(),
            Self::DataPack(program) => program.program_digest(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct TargetProfileRegistration {
    pub context: Value,
    pub profile: TargetProfileResource,
    pub original_game_source: SourceId,
    pub runtime_suite: TargetProfileResource,
    pub case_sources: BTreeMap<String, RuntimeCaseSource>,
    /// Actual loaded-definition receipts are independent of archive input and
    /// class-resource hashes. The source producer must register acquired raw
    /// definition bytes and the actual private loader identity. Absence leaves
    /// parser/handler admission unsupported; this map has no public installer.
    pub loaded_definition_sources: BTreeMap<String, LoadedDefinitionSource>,
}
#[derive(Clone, Debug)]
pub struct LoadedDefinitionSource {
    pub source_id: SourceId,
    pub loader_id: String,
}

#[derive(Clone)]
struct InstalledTargetProfile {
    authenticated: AuthenticatedPrincipal,
    project: ProjectId,
    profile_id: TargetProfileId,
    registration: TargetProfileRegistration,
    profile_digest: Sha256Digest,
    source_binding_revision: Sha256Digest,
    store_root: PathBuf,
}

type ProfileKey = (PrincipalId, ContextId, TargetProfileId);
type ProfileRegistry = BTreeMap<ProfileKey, InstalledTargetProfile>;

/// The registry is a source-admission index, not another operation ledger.
/// Restart and session replacement require fresh explicit setup. Retained
/// bytes or an equal principal string cannot recreate the issuing session.
#[derive(Clone)]
pub struct RegisteredTargetProfiles {
    state: Rc<RefCell<ProfileRegistry>>,
    authority: LocalAuthority,
    hosts: HostBridge,
    contexts: SharedPlanningContexts,
    sources: RegisteredCatalogSources,
}
impl RegisteredTargetProfiles {
    pub fn new(
        authority: LocalAuthority,
        hosts: HostBridge,
        contexts: SharedPlanningContexts,
        sources: RegisteredCatalogSources,
    ) -> Self {
        Self {
            state: Rc::new(RefCell::new(BTreeMap::new())),
            authority,
            hosts,
            contexts,
            sources,
        }
    }

    pub fn register(
        &self,
        store: &PlanningStore<'_>,
        authenticated: &AuthenticatedPrincipal,
        budget: &RequestBudget,
        registration: TargetProfileRegistration,
    ) -> AppResult<()> {
        let rpc = self.rpc(authenticated.clone(), budget.clone(), &registration.context)?;
        rpc.fresh()?;
        if registration.case_sources.is_empty() || registration.case_sources.len() > MAX_CASES {
            return Err(invalid(
                "Target runtime suite has no finite registered case sources",
            ));
        }
        if registration.loaded_definition_sources.len() > 64
            || registration
                .loaded_definition_sources
                .iter()
                .any(|(class, source)| {
                    class.is_empty()
                        || class.len() > 256
                        || !class.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'$' | b'_')
                        })
                        || source.loader_id.is_empty()
                        || source.loader_id.len() > 256
                })
        {
            return Err(invalid(
                "Loaded definition source registration exceeds its finite identity range",
            ));
        }
        for (case, source) in &registration.case_sources {
            if source.program.case_id() != case
                || source.program.commands().is_empty()
                || source.program.commands().len() > 256
                || source.program.commands().iter().any(|command| {
                    command.is_empty()
                        || command.len() > 16 * 1024
                        || command.contains(['\n', '\r', '\0'])
                })
                || source.program.command_stage_index() as usize >= source.program.commands().len()
            {
                return Err(invalid(
                    "Runtime case source identity, command or stage is invalid",
                ));
            }
        }
        let mut bytes_left = MAX_TOTAL_BYTES;
        let profile = parse(
            &read_resource(
                store,
                &rpc,
                &registration.profile,
                MAX_PROFILE_BYTES,
                &mut bytes_left,
            )?,
            budget,
        )?;
        validate("VersionProfile", &profile)?;
        validate_evidence_resource_ids(&profile, &registration)?;
        let profile_id =
            TargetProfileId::new(text(&profile, "profileId")?).map_err(|_| unverified())?;
        let profile_digest = digest(&profile)?;
        let suite = parse(
            &read_resource(
                store,
                &rpc,
                &registration.runtime_suite,
                MAX_EVIDENCE_BYTES,
                &mut bytes_left,
            )?,
            budget,
        )?;
        let decoded: RuntimeSuite = serde_json::from_value(suite).map_err(|_| unverified())?;
        validate_suite_identity(&decoded, &profile, &registration.context)?;
        validate_case_set(&decoded, &registration.case_sources)?;
        for source in registration.case_sources.values() {
            let source_bytes = read_resource(
                store,
                &rpc,
                &source.source,
                MAX_EVIDENCE_BYTES,
                &mut bytes_left,
            )?;
            verify_normative_source(&source.program, &source_bytes, budget)?;
        }
        let source = store.with_read(|store| {
            self.sources.source_identity(
                authenticated,
                &registration.context,
                &registration.original_game_source,
                store,
                budget,
            )
        })?;
        if source.role != CatalogSourceRole::GameArtifact
            || source.resource["sha256"] != profile["artifactSha256"]
        {
            return Err(unverified());
        }
        rpc.fresh()?;
        let key = (
            authenticated.principal().clone(),
            rpc.context_id.clone(),
            profile_id.clone(),
        );
        let installed = InstalledTargetProfile {
            authenticated: authenticated.clone(),
            project: rpc.project.clone(),
            profile_id,
            registration,
            profile_digest,
            source_binding_revision: source.binding_revision,
            store_root: store.with_read(|store| Ok(store.data_root().to_path_buf()))?,
        };
        let mut state = self.state.try_borrow_mut().map_err(|_| busy())?;
        state.retain(|_, installed| installed.authenticated.is_current());
        if state.len() >= MAX_PROFILES || state.contains_key(&key) {
            return Err(error(
                "TARGET_REGISTRATION_CONFLICT",
                "Target profile generation is already installed or capacity is exhausted",
            ));
        }
        state.insert(key, installed);
        Ok(())
    }

    /// Invoke through the concrete backend using the actual request slot and
    /// this same call-scoped store. PrincipalId is only a locator here.
    pub fn resolve_live(
        &self,
        store: &PlanningStore<'_>,
        authenticated: &AuthenticatedPrincipal,
        profile_id: &TargetProfileId,
        context: &Value,
        actual_hello: &Value,
        budget: &RequestBudget,
    ) -> AppResult<ResolvedTargetProfile> {
        let rpc = self.rpc(authenticated.clone(), budget.clone(), context)?;
        rpc.fresh()?;
        let key = (
            authenticated.principal().clone(),
            rpc.context_id.clone(),
            profile_id.clone(),
        );
        let installed = self
            .state
            .try_borrow()
            .map_err(|_| busy())?
            .get(&key)
            .cloned()
            .ok_or_else(unverified)?;
        if !installed.authenticated.same_session(authenticated)
            || installed.registration.context != *context
            || installed.project != rpc.project
            || installed.profile_id != *profile_id
            || store.with_read(|store| Ok(store.data_root() != installed.store_root))?
        {
            return Err(forbidden());
        }
        let hello = self.hosts.hello_with_deadline(
            authenticated.principal(),
            &rpc.context_id,
            budget.deadline(),
        )?;
        validate("HostHello", &hello)?;
        if hello != *actual_hello || hello["environment"] != context["environment"] {
            return Err(error(
                "STALE_CONTEXT",
                "Target hello differs from the actual paired context",
            ));
        }
        let mut bytes_left = MAX_TOTAL_BYTES;
        let profile = parse(
            &read_resource(
                store,
                &rpc,
                &installed.registration.profile,
                MAX_PROFILE_BYTES,
                &mut bytes_left,
            )?,
            budget,
        )?;
        validate("VersionProfile", &profile)?;
        validate_evidence_resource_ids(&profile, &installed.registration)?;
        if digest(&profile)? != installed.profile_digest {
            return Err(unverified());
        }
        let suite_value = parse(
            &read_resource(
                store,
                &rpc,
                &installed.registration.runtime_suite,
                MAX_EVIDENCE_BYTES,
                &mut bytes_left,
            )?,
            budget,
        )?;
        let suite: RuntimeSuite = serde_json::from_value(suite_value).map_err(|_| unverified())?;
        validate_suite_identity(&suite, &profile, context)?;
        validate_case_set(&suite, &installed.registration.case_sources)?;
        let source = store.with_read(|store| {
            self.sources.source_identity(
                authenticated,
                context,
                &installed.registration.original_game_source,
                store,
                budget,
            )
        })?;
        if source.binding_revision != installed.source_binding_revision
            || source.role != CatalogSourceRole::GameArtifact
        {
            return Err(unverified());
        }
        let facts = self.host_observation(store, &rpc, "runtime_sources")?;
        validate_source_facts(&facts, context)?;
        let source_digest = source_facts_pin(&facts)?;
        verify_live_source(&profile, &hello, &facts, &source.resource, &suite)?;
        let registry = self.host_observation(store, &rpc, "native_registry")?;
        verify_registry(&registry, &hello, context, &suite, budget)?;
        let mut evidence_pins = vec![
            decode_resource(&installed.registration.profile.resource)?,
            decode_resource(&installed.registration.runtime_suite.resource)?,
            decode_resource(&source.resource)?,
        ];
        let mut admitted_runs = BTreeMap::new();
        let mut definition_cache = BTreeMap::new();
        for case in &suite.cases {
            budget_check(budget)?;
            let expected = installed
                .registration
                .case_sources
                .get(&case.case_id)
                .ok_or_else(unverified)?;
            let source_bytes = read_resource(
                store,
                &rpc,
                &expected.source,
                MAX_EVIDENCE_BYTES,
                &mut bytes_left,
            )?;
            if case.source_resource != expected.source.resource
                || raw_digest(&source_bytes).as_str() != text(&case.source_resource, "sha256")?
            {
                return Err(unverified());
            }
            verify_normative_source(&expected.program, &source_bytes, budget)?;
            let durable = verify_durable_case(
                store,
                &rpc,
                case,
                expected,
                &suite,
                &profile,
                &source_bytes,
                &mut bytes_left,
            )?;
            let issued = self.issue_calibration_run_source(
                store,
                &rpc,
                case,
                expected,
                &durable,
                &suite,
                &installed.registration.loaded_definition_sources,
                &mut definition_cache,
                &mut bytes_left,
            )?;
            admitted_runs.insert(case.case_id.clone(), issued);
            evidence_pins.push(decode_resource(&expected.source.resource)?);
        }
        let rules = verified_rules(&suite, &admitted_runs)?;
        let verifier = ResolvedEvidence {
            profile_digest: installed.profile_digest.clone(),
            artifact_digest: suite.artifact_sha256.clone(),
            rules,
        };
        let compiler = VerifiedTarget::verify(&profile, &verifier).map_err(|error_value| {
            AppError::storage(
                error_value.code,
                StorageError::Contract(error_value.to_string()),
            )
        })?;
        // A source container receipt cannot attest transformed classes, complete
        // asset packs, interpolation or a native write codec. No native world
        // kind is promoted from a public list or numeric/pack-only suite.
        let native_kinds = BTreeSet::<NativeKind>::new();
        rpc.fresh()?;
        let final_facts = self.host_observation(store, &rpc, "runtime_sources")?;
        validate_source_facts(&final_facts, context)?;
        if source_facts_pin(&final_facts)? != source_digest {
            return Err(error(
                "STALE_CONTEXT",
                "Native target sources changed during admission",
            ));
        }
        let final_source = store.with_read(|store| {
            self.sources.source_identity(
                authenticated,
                context,
                &installed.registration.original_game_source,
                store,
                budget,
            )
        })?;
        if final_source.binding_revision != source.binding_revision
            || final_source.resource != source.resource
        {
            return Err(unverified());
        }
        self.recheck_definition_cache(store, &rpc, &definition_cache, &mut bytes_left)?;
        for definition in definition_cache.values() {
            evidence_pins.push(decode_resource(&definition.resource)?);
        }
        evidence_pins.sort_by(|left, right| left.resource_id.cmp(&right.resource_id));
        evidence_pins.dedup_by(|left, right| {
            left.resource_id == right.resource_id && left.sha256 == right.sha256
        });
        rpc.fresh()?;
        Ok(ResolvedTargetProfile {
            compiler,
            native_kinds,
            evidence_resource_pins: evidence_pins,
            hello_digest: digest(&hello)?,
            environment_digest: digest(&context["environment"])?,
            profile_evidence: json!({"profile":profile,"runtimeSourceFactsDigest":source_digest,
                "hostArtifactDigest":suite.host_artifact_digest,"registryGeneration":suite.registry_generation}),
            source_facts: facts,
            definitions: installed.registration.loaded_definition_sources,
            rpc,
        })
    }

    /// Read-only parser admission of an already sealed Rust source projection.
    /// A native parse witness attests those exact source commands; it cannot
    /// attest execution, effect completion, independent readback or scene assets.
    pub fn verify_scene_steps(
        &self,
        store: &PlanningStore<'_>,
        target: &ResolvedTargetProfile,
        steps: &[NativeSceneStep],
    ) -> AppResult<NativeSceneParseWitness> {
        target.rpc.fresh()?;
        if steps.is_empty() || steps.len() > 256 {
            return Err(invalid(
                "Native scene parser request needs a finite nonempty sealed instruction set",
            ));
        }
        let mut instructions = Vec::with_capacity(steps.len());
        let mut commands = 0usize;
        let mut request_bytes = 0usize;
        for step in steps {
            budget_check(&target.rpc.budget)?;
            if step.encoded_commands().is_empty() {
                return Err(unverified());
            }
            commands = commands
                .checked_add(step.encoded_commands().len())
                .filter(|count| *count <= 256)
                .ok_or_else(unverified)?;
            let mut value = serde_json::to_value(step).map_err(|_| unverified())?;
            value["commandDigest"] = json!(digest(&json!(step.encoded_commands()))?);
            request_bytes = request_bytes
                .checked_add(encode_json(&value).map_err(|_| unverified())?.len())
                .filter(|bytes| *bytes <= 512 * 1024)
                .ok_or_else(unverified)?;
            instructions.push(value);
        }
        let expected_digest = source_facts_pin(&target.source_facts)?;
        let selector = json!({"kind":"target_admission","instructions":instructions,
            "expectedRuntimeSourceFactsDigest":expected_digest,
            "expectedRegistryGeneration":target.profile_evidence["registryGeneration"]});
        let response = self.hosts.inspect_response_with_deadline(
            target.rpc.authenticated.principal(),
            &target.rpc.context_id,
            selector,
            target.rpc.budget.deadline(),
        )?;
        retain_host_response(store, &target.rpc, "target_admission", &response)?;
        if response["status"] != "ok" {
            return Err(error(
                "NATIVE_PARSER_UNADMITTED",
                "Native parser admission failed; the original response is retained",
            ));
        }
        let payload = response.get("payload").ok_or_else(unverified)?;
        validate_scene_parse_response(payload, &instructions, target, &target.rpc.budget)?;
        let mut definition_count = 0usize;
        let mut definition_cache = BTreeMap::new();
        let mut bytes_left = MAX_TOTAL_BYTES;
        for instruction in payload["instructions"].as_array().ok_or_else(unverified)? {
            for command in instruction["commands"].as_array().ok_or_else(unverified)? {
                for category in ["parserSources", "handlerSources"] {
                    let receipts = command[category].as_array().ok_or_else(unverified)?;
                    for receipt in receipts {
                        definition_count = definition_count
                            .checked_add(1)
                            .filter(|count| *count <= 1024)
                            .ok_or_else(unverified)?;
                        self.verify_current_definition_source(
                            store,
                            &target.rpc,
                            &target.definitions,
                            text(&target.profile_evidence, "registryGeneration")?,
                            receipt,
                            &mut definition_cache,
                            &mut bytes_left,
                        )?;
                    }
                }
            }
        }
        target.rpc.fresh()?;
        let facts = self.host_observation(store, &target.rpc, "runtime_sources")?;
        if source_facts_pin(&facts)? != expected_digest {
            return Err(error(
                "STALE_CONTEXT",
                "Native source facts changed during parser admission",
            ));
        }
        self.recheck_definition_cache(store, &target.rpc, &definition_cache, &mut bytes_left)?;
        target.rpc.fresh()?;
        Ok(NativeSceneParseWitness {
            instructions_digest: digest(&json!(instructions))?,
            receipt_digest: digest(payload)?,
            context_digest: field_digest(&target.rpc.context, "contextDigest")?,
            source_facts_digest: expected_digest,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Current opaque authority, source identity, native receipt, generation and cooperative budgets are independent admission inputs"
    )]
    fn verify_current_definition_source(
        &self,
        store: &PlanningStore<'_>,
        rpc: &TargetRpc,
        definitions: &BTreeMap<String, LoadedDefinitionSource>,
        generation: &str,
        receipt: &Value,
        cache: &mut BTreeMap<SourceId, RegisteredCatalogSourceIdentity>,
        bytes_left: &mut u64,
    ) -> AppResult<()> {
        exact_fields(
            receipt,
            &[
                "className",
                "definitionSha256",
                "containerSha256",
                "sourceKind",
                "admissionEvidenceSha256",
                "loaderId",
                "generation",
            ],
        )?;
        if receipt["sourceKind"] != "loaded_definition_bytes" || receipt["generation"] != generation
        {
            return Err(error(
                "NATIVE_PARSER_UNADMITTED",
                "Native parser source is not an observed current loaded definition",
            ));
        }
        let class = text(receipt, "className")?;
        let registered = definitions.get(class).ok_or_else(|| {
            error(
                "NATIVE_PARSER_UNADMITTED",
                "Actual loaded native definition has no approved exact source registration",
            )
        })?;
        rpc.local_project(
            rpc.authenticated.principal(),
            Some(&rpc.context_id),
            &rpc.project,
        )
        .map_err(|failure| rpc.storage_error(failure))?;
        if !cache.contains_key(&registered.source_id) {
            let identity = store.with_read(|store| {
                self.sources.source_identity_with_limit(
                    &rpc.authenticated,
                    &rpc.context,
                    &registered.source_id,
                    store,
                    &rpc.budget,
                    MAX_DEFINITION_BYTES.min(*bytes_left),
                )
            })?;
            *bytes_left = bytes_left
                .checked_sub(decode_resource(&identity.resource)?.size_bytes)
                .ok_or_else(unverified)?;
            cache.insert(registered.source_id.clone(), identity);
        }
        let identity = cache.get(&registered.source_id).ok_or_else(unverified)?;
        if identity.role != CatalogSourceRole::CatalogData
            || identity.source["kind"] != "runtime_observation"
            || identity.resource["mediaType"] != "application/java-vm"
            || identity.resource["sha256"] != receipt["definitionSha256"]
            || receipt["loaderId"] != registered.loader_id
        {
            return Err(unverified());
        }
        // Both distinct integrity claims must be well formed. The native gate
        // authenticates its loaded-definition provenance before executing any
        // parser/custom argument; this adapter never replaces it with a JAR hash.
        field_digest(receipt, "containerSha256")?;
        field_digest(receipt, "admissionEvidenceSha256")?;
        rpc.local_project(
            rpc.authenticated.principal(),
            Some(&rpc.context_id),
            &rpc.project,
        )
        .map_err(|failure| rpc.storage_error(failure))
    }

    fn recheck_definition_cache(
        &self,
        store: &PlanningStore<'_>,
        rpc: &TargetRpc,
        cache: &BTreeMap<SourceId, RegisteredCatalogSourceIdentity>,
        bytes_left: &mut u64,
    ) -> AppResult<()> {
        for (id, original) in cache {
            let current = store.with_read(|store| {
                self.sources.source_identity_with_limit(
                    &rpc.authenticated,
                    &rpc.context,
                    id,
                    store,
                    &rpc.budget,
                    MAX_DEFINITION_BYTES.min(*bytes_left),
                )
            })?;
            if current.resource != original.resource
                || current.source != original.source
                || current.role != original.role
                || current.binding_revision != original.binding_revision
            {
                return Err(error(
                    "STALE_CONTEXT",
                    "Approved loaded definition source changed during admission",
                ));
            }
            *bytes_left = bytes_left
                .checked_sub(decode_resource(&current.resource)?.size_bytes)
                .ok_or_else(unverified)?;
        }
        rpc.fresh()
    }

    /// The host looks up its actual immutable dispatch-issued receipt by the
    /// original invocation identity. Requested digests are consistency pins;
    /// the host cannot create a receipt from them. Missing real issuer stays
    /// unsupported and its original response is retained in the same CAS.
    #[allow(
        clippy::too_many_arguments,
        reason = "Original durable invocation, sealed program, source suite and current definition authority must remain independently bound"
    )]
    fn issue_calibration_run_source(
        &self,
        store: &PlanningStore<'_>,
        rpc: &TargetRpc,
        case: &RuntimeCaseRecord,
        expected: &RuntimeCaseSource,
        durable: &DurableCaseWitness,
        suite: &RuntimeSuite,
        definitions: &BTreeMap<String, LoadedDefinitionSource>,
        cache: &mut BTreeMap<SourceId, RegisteredCatalogSourceIdentity>,
        bytes_left: &mut u64,
    ) -> AppResult<CalibrationRunSource> {
        rpc.fresh()?;
        let commands = expected.program.commands();
        let commands_digest = digest(&json!(commands))?;
        let selector = json!({"kind":"calibration_run_source","invocationId":case.invocation_id,
            "invocationDigest":durable.invocation_digest,"programDigest":expected.program.program_digest(),
            "sourceResource":expected.source.resource,"commandsDigest":commands_digest,
            "readbackSourceDigest":durable.readback_source_digest,
            "expectedRuntimeSourceFactsDigest":suite.runtime_source_facts_digest,
            "expectedRegistryGeneration":suite.registry_generation});
        let response = self.hosts.inspect_response_with_deadline(
            rpc.authenticated.principal(),
            &rpc.context_id,
            selector,
            rpc.budget.deadline(),
        )?;
        retain_host_response(store, rpc, "calibration_run_source", &response)?;
        if response["status"] != "ok" {
            return Err(error(
                "CALIBRATION_RUN_ISSUER_UNAVAILABLE",
                "Actual immutable calibration dispatch source receipt is unavailable; the original host response is retained",
            ));
        }
        let payload = response.get("payload").ok_or_else(unverified)?;
        exact_fields(
            payload,
            &[
                "format",
                "protocolVersion",
                "environment",
                "contextId",
                "contextDigest",
                "runtimeSourceFactsDigest",
                "hostArtifactDigest",
                "registryGeneration",
                "invocationId",
                "invocationDigest",
                "programDigest",
                "sourceResource",
                "commandsDigest",
                "readbackSourceDigest",
                "preseedEndIndex",
                "commandStageIndex",
                "commands",
                "observedFromTick",
                "observedToTick",
                "observedAt",
            ],
        )?;
        if payload["format"] != "mmmm.native.calibration-run-source/2"
            || payload["protocolVersion"] != "0.2.0"
            || payload["environment"] != rpc.context["environment"]
            || payload["contextId"] != rpc.context["contextId"]
            || payload["contextDigest"] != rpc.context["contextDigest"]
            || payload["runtimeSourceFactsDigest"] != suite.runtime_source_facts_digest.as_str()
            || payload["hostArtifactDigest"] != suite.host_artifact_digest.as_str()
            || payload["registryGeneration"] != suite.registry_generation
            || payload["invocationId"] != case.invocation_id.as_str()
            || payload["invocationDigest"] != durable.invocation_digest.as_str()
            || payload["programDigest"] != expected.program.program_digest().as_str()
            || payload["sourceResource"] != expected.source.resource
            || payload["commandsDigest"] != commands_digest.as_str()
            || payload["readbackSourceDigest"] != durable.readback_source_digest.as_str()
            || integer(&payload["preseedEndIndex"])? != expected.program.preseed_end_index() as i32
            || integer(&payload["commandStageIndex"])?
                != expected.program.command_stage_index() as i32
        {
            return Err(unverified());
        }
        validate_observed_window(payload)?;
        let observed = payload["commands"].as_array().ok_or_else(unverified)?;
        if observed.len() != commands.len() {
            return Err(unverified());
        }
        verify_issued_command_return(
            observed,
            expected.program.command_stage_index(),
            durable.selected_native_return,
        )?;
        let mut count = 0usize;
        for (receipt, source) in observed.iter().zip(commands) {
            budget_check(&rpc.budget)?;
            exact_fields(
                receipt,
                &[
                    "commandDigest",
                    "consumedUtf16",
                    "nativeReturn",
                    "parserSources",
                    "handlerSources",
                ],
            )?;
            if receipt["commandDigest"] != digest(&json!(source))?.as_str()
                || integer(&receipt["consumedUtf16"])? as usize != source.encode_utf16().count()
            {
                return Err(unverified());
            }
            required_nullable_integer(receipt.get("nativeReturn"))?;
            for category in ["parserSources", "handlerSources"] {
                let sources = receipt[category].as_array().ok_or_else(unverified)?;
                if sources.is_empty() || sources.len() > 64 {
                    return Err(unverified());
                }
                for source in sources {
                    count = count
                        .checked_add(1)
                        .filter(|value| *value <= 1024)
                        .ok_or_else(unverified)?;
                    self.verify_current_definition_source(
                        store,
                        rpc,
                        definitions,
                        &suite.registry_generation,
                        source,
                        cache,
                        bytes_left,
                    )?;
                }
            }
        }
        rpc.fresh()?;
        Ok(CalibrationRunSource {
            case_id: case.case_id.clone(),
            invocation_id: case.invocation_id.clone(),
            program_digest: expected.program.program_digest().clone(),
            receipt_digest: digest(payload)?,
        })
    }

    fn rpc(
        &self,
        authenticated: AuthenticatedPrincipal,
        budget: RequestBudget,
        context: &Value,
    ) -> AppResult<TargetRpc> {
        validate("ExecutionContext", context)?;
        if context["environment"]["kind"] != "game" {
            return Err(unverified());
        }
        let access = LocalPlanningAccess::new(
            authenticated.clone(),
            self.authority.clone(),
            self.hosts.clone(),
            budget.clone(),
            self.contexts.clone(),
        )?;
        Ok(TargetRpc {
            authenticated,
            budget,
            authority: self.authority.clone(),
            access,
            context_id: ContextId::new(text(context, "contextId")?).map_err(|_| forbidden())?,
            project: ProjectId::new(text(context, "projectId")?).map_err(|_| forbidden())?,
            context: context.clone(),
        })
    }

    fn host_observation(
        &self,
        store: &PlanningStore<'_>,
        rpc: &TargetRpc,
        selector: &str,
    ) -> AppResult<Value> {
        rpc.fresh()?;
        let response = self.hosts.inspect_response_with_deadline(
            rpc.authenticated.principal(),
            &rpc.context_id,
            json!({"kind":selector}),
            rpc.budget.deadline(),
        )?;
        // Original failure code/message/data are retained before an API error.
        retain_host_response(store, rpc, selector, &response)?;
        if response["status"] != "ok" {
            return Err(error(
                "TARGET_SOURCE_UNAVAILABLE",
                "Original native target inspection failed; its complete response is retained",
            ));
        }
        budget_check(&rpc.budget)?;
        response.get("payload").cloned().ok_or_else(unverified)
    }
}

/// No serde or public constructor: this value exists only after current actual
/// host/source and durable runtime evidence admission. The Java envelope is a
/// source pin, not an additional runtime verification decision.
pub struct ResolvedTargetProfile {
    compiler: VerifiedTarget,
    native_kinds: BTreeSet<NativeKind>,
    evidence_resource_pins: Vec<ResourceRef>,
    hello_digest: Sha256Digest,
    environment_digest: Sha256Digest,
    profile_evidence: Value,
    source_facts: Value,
    definitions: BTreeMap<String, LoadedDefinitionSource>,
    rpc: TargetRpc,
}

/// A complete actual native parse of these sealed commands. This capability is
/// deliberately distinct from VerifiedTarget and VerifiedNativeTarget.
pub struct NativeSceneParseWitness {
    instructions_digest: Sha256Digest,
    receipt_digest: Sha256Digest,
    context_digest: Sha256Digest,
    source_facts_digest: Sha256Digest,
}
impl NativeSceneParseWitness {
    pub fn instructions_digest(&self) -> &Sha256Digest {
        &self.instructions_digest
    }
    pub fn receipt_digest(&self) -> &Sha256Digest {
        &self.receipt_digest
    }
    pub fn context_digest(&self) -> &Sha256Digest {
        &self.context_digest
    }
    pub fn source_facts_digest(&self) -> &Sha256Digest {
        &self.source_facts_digest
    }
}

fn validate_scene_parse_response(
    payload: &Value,
    requested: &[Value],
    target: &ResolvedTargetProfile,
    budget: &RequestBudget,
) -> AppResult<()> {
    exact_fields(
        payload,
        &[
            "protocolVersion",
            "environment",
            "contextId",
            "contextDigest",
            "runtimeSourceFactsDigest",
            "hostArtifactDigest",
            "registryGeneration",
            "observedFromTick",
            "observedToTick",
            "observedAt",
            "instructions",
        ],
    )?;
    validate_observed_window(payload)?;
    if payload["protocolVersion"] != "0.2.0"
        || payload["environment"] != target.rpc.context["environment"]
        || payload["contextId"] != target.rpc.context["contextId"]
        || payload["contextDigest"] != target.rpc.context["contextDigest"]
        || payload["runtimeSourceFactsDigest"]
            != target.profile_evidence["runtimeSourceFactsDigest"]
        || payload["hostArtifactDigest"] != target.profile_evidence["hostArtifactDigest"]
        || payload["registryGeneration"] != target.profile_evidence["registryGeneration"]
    {
        return Err(unverified());
    }
    let observed = payload["instructions"].as_array().ok_or_else(unverified)?;
    if observed.len() != requested.len() {
        return Err(unverified());
    }
    for (actual, expected) in observed.iter().zip(requested) {
        budget_check(budget)?;
        exact_fields(actual, &["stepDigest", "commands"])?;
        if actual["stepDigest"] != digest(expected)?.as_str() {
            return Err(unverified());
        }
        let actual_commands = actual["commands"].as_array().ok_or_else(unverified)?;
        let expected_commands = expected["encoded_commands"]
            .as_array()
            .ok_or_else(unverified)?;
        if actual_commands.len() != expected_commands.len() {
            return Err(unverified());
        }
        for (actual, expected) in actual_commands.iter().zip(expected_commands) {
            exact_fields(
                actual,
                &[
                    "commandDigest",
                    "utf16Length",
                    "consumedUtf16",
                    "parseStatus",
                    "reasonCode",
                    "parserSources",
                    "handlerSources",
                ],
            )?;
            // Seven command fields were agreed with the platform helper. Null
            // sources are honest unavailable observations; they admit no parse.
            let source = expected.as_str().ok_or_else(unverified)?;
            let length = source.encode_utf16().count() as u64;
            if actual["commandDigest"] != digest(expected)?.as_str()
                || actual["utf16Length"].as_u64() != Some(length)
                || actual["consumedUtf16"].as_u64() != Some(length)
                || actual["parseStatus"] != "parsed"
                || !actual["reasonCode"].is_null()
                || ["parserSources", "handlerSources"].iter().any(|field| {
                    actual[*field]
                        .as_array()
                        .is_none_or(|sources| sources.is_empty() || sources.len() > 64)
                })
            {
                return Err(error(
                    "NATIVE_PARSER_UNADMITTED",
                    "Native command lacks a complete current parse and actual source admission",
                ));
            }
        }
    }
    Ok(())
}
impl ResolvedTargetProfile {
    pub fn planning_target(&self) -> AppResult<VerifiedPlanningTarget> {
        self.rpc.fresh()?;
        Ok(VerifiedPlanningTarget {
            compiler: self.compiler.clone(),
            native_kinds: self.native_kinds.clone(),
            evidence_resource_pins: self.evidence_resource_pins.clone(),
            hello_digest: self.hello_digest.clone(),
            environment_digest: self.environment_digest.clone(),
        })
    }
    pub fn profile_evidence(&self) -> AppResult<Value> {
        self.rpc.fresh()?;
        Ok(self.profile_evidence.clone())
    }
    pub fn observed_source_facts(&self) -> AppResult<&Value> {
        self.rpc.fresh()?;
        Ok(&self.source_facts)
    }
}

struct ResolvedEvidence {
    profile_digest: Sha256Digest,
    artifact_digest: Sha256Digest,
    rules: TargetRuntimeRules,
}
impl TargetEvidenceVerifier for ResolvedEvidence {
    fn verify_target(
        &self,
        profile: &Value,
        profile_digest: &Sha256Digest,
        artifact_digest: &Sha256Digest,
    ) -> Result<TargetRuntimeRules, DomainError> {
        if profile_digest != &self.profile_digest
            || artifact_digest != &self.artifact_digest
            || canonical_digest(profile).ok().as_ref() != Some(&self.profile_digest)
        {
            return Err(DomainError::new(
                "TARGET_UNVERIFIED",
                "Resolved runtime evidence belongs to another profile or original game input",
            ));
        }
        Ok(self.rules)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RuntimeSuite {
    format: String,
    profile_digest: Sha256Digest,
    artifact_sha256: Sha256Digest,
    host_artifact_digest: Sha256Digest,
    runtime_source_facts_digest: Sha256Digest,
    registry_digest: Sha256Digest,
    registry_generation: String,
    environment: Value,
    context_digest: Sha256Digest,
    compiler_digest: Sha256Digest,
    loader: Value,
    java_major: Int32,
    cases: Vec<RuntimeCaseRecord>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RuntimeCaseRecord {
    case_id: String,
    source_resource: Value,
    operation_id: OperationId,
    step_id: StepId,
    invocation_id: InvocationId,
    readback_envelope: BlobRef,
}

struct DurableCaseWitness {
    invocation_digest: Sha256Digest,
    readback_source_digest: Sha256Digest,
    selected_native_return: Option<i32>,
}

/// No JSON/public constructor. Only a response from the actual privately
/// paired dispatch issuer, bound to the original journal and approved native
/// definitions, can produce this internal case admission capability.
struct CalibrationRunSource {
    case_id: String,
    invocation_id: InvocationId,
    program_digest: Sha256Digest,
    receipt_digest: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NumericReadback {
    format: String,
    case_id: String,
    source_resource: Value,
    command_stage_index: u32,
    invocation_id: InvocationId,
    runtime_source_facts_digest: Sha256Digest,
    command_success: bool,
    #[serde(deserialize_with = "deserialize_required_nullable_int32")]
    command_return: Option<Int32>,
    ok_score: Int32,
    output: TypedScalar,
    scratch_present: bool,
    stale_output_seeded: bool,
}
fn deserialize_required_nullable_int32<'de, D>(deserializer: D) -> Result<Option<Int32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<Int32>::deserialize(deserializer)
}
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TypedScalar {
    Absent,
    Score { value: Int32 },
    IntTag { value: Int32 },
    FloatTag { bits: String },
}

const NUMERIC_CASES: &[&str] = CalibrationCase::CASE_IDS;

const PACK_CASE: &str = "data_pack_pair_function_dependency_closure";
fn known_case(case: &str) -> bool {
    NUMERIC_CASES.contains(&case) || case == PACK_CASE
}
fn validate_case_set(
    suite: &RuntimeSuite,
    registered: &BTreeMap<String, RuntimeCaseSource>,
) -> AppResult<()> {
    let includes_pack = suite.cases.iter().any(|case| case.case_id == PACK_CASE);
    let expected_count = NUMERIC_CASES.len() + usize::from(includes_pack);
    if suite.cases.len() != expected_count || registered.len() != expected_count {
        return Err(unverified());
    }
    let mut found = BTreeSet::new();
    let mut invocations = BTreeSet::new();
    for case in &suite.cases {
        if !(known_case(&case.case_id) || case.case_id == PACK_CASE)
            || !found.insert(case.case_id.as_str())
            || !invocations.insert(case.invocation_id.clone())
            || !registered.contains_key(&case.case_id)
        {
            return Err(unverified());
        }
    }
    Ok(())
}
fn validate_suite_identity(
    suite: &RuntimeSuite,
    profile: &Value,
    context: &Value,
) -> AppResult<()> {
    if suite.format != "mmmm.target-runtime-evidence/1"
        || suite.profile_digest != digest(profile)?
        || profile["artifactSha256"] != suite.artifact_sha256.as_str()
        || suite.context_digest.as_str() != text(context, "contextDigest")?
        || suite.environment != context["environment"]
        || suite.java_major.get() != 25
        || integer(&profile["javaMajor"])? != 25
        || profile["gameVersion"] != "26.3"
        || profile["validationStatus"] != "runtime_verified"
        || profile["writeSupport"] != "verified"
        || suite.compiler_digest != mmmm_compiler::compiler_digest()
        || suite.registry_generation.is_empty()
        || suite.registry_generation.len() > 19
        || !suite
            .registry_generation
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        || profile["evidenceResourceIds"]
            .as_array()
            .is_none_or(Vec::is_empty)
    {
        return Err(unverified());
    }
    Ok(())
}

fn validate_evidence_resource_ids(
    profile: &Value,
    registration: &TargetProfileRegistration,
) -> AppResult<()> {
    let required = text(&registration.runtime_suite.resource, "resourceId")?;
    let allowed: BTreeSet<&str> = std::iter::once(required)
        .chain(
            registration
                .case_sources
                .values()
                .map(|source| text(&source.source.resource, "resourceId"))
                .collect::<AppResult<Vec<_>>>()?,
        )
        .collect();
    let ids = profile["evidenceResourceIds"]
        .as_array()
        .ok_or_else(unverified)?;
    let mut found = BTreeSet::new();
    if ids.is_empty() || ids.len() > MAX_CASES + 1 {
        return Err(unverified());
    }
    for id in ids {
        let id = id.as_str().ok_or_else(unverified)?;
        if !allowed.contains(id) || !found.insert(id) {
            return Err(unverified());
        }
    }
    if !found.contains(required) {
        return Err(unverified());
    }
    Ok(())
}

fn verify_live_source(
    profile: &Value,
    hello: &Value,
    facts: &Value,
    approved_game: &Value,
    suite: &RuntimeSuite,
) -> AppResult<()> {
    if source_facts_pin(facts)? != suite.runtime_source_facts_digest
        || facts["registryGeneration"] != suite.registry_generation
        || hello["hostBuild"] != suite.host_artifact_digest.as_str()
        || hello["loader"] != suite.loader
        || integer(&hello["javaMajor"])? != suite.java_major.get()
        || hello["gameVersion"] != profile["gameVersion"]
        || facts["environment"] != suite.environment
        || hello["environment"] != suite.environment
        || approved_game["sha256"] != profile["artifactSha256"]
        || !profile["testedLoaders"]
            .as_array()
            .is_some_and(|loaders| loaders.contains(&hello["loader"]["id"]))
        || !facts["originalInputGameJars"]
            .as_array()
            .is_some_and(|inputs| {
                inputs.iter().any(|input| {
                    input["status"] == "observed"
                        && input["scope"] == "original_game_input_container"
                        && input["sha256"] == profile["artifactSha256"]
                        && input["sizeBytes"] == approved_game["sizeBytes"]
                })
            })
    {
        return Err(unverified());
    }
    Ok(())
}
fn verify_registry(
    registry: &Value,
    hello: &Value,
    context: &Value,
    suite: &RuntimeSuite,
    budget: &RequestBudget,
) -> AppResult<()> {
    exact_fields(
        registry,
        &[
            "registryDigest",
            "registryGeneration",
            "observationBytesHex",
            "observedFromTick",
            "observedToTick",
            "observedAt",
            "gameVersion",
            "locale",
            "contextDigest",
            "environment",
        ],
    )?;
    validate_observed_window(registry)?;
    if registry["registryGeneration"] != suite.registry_generation
        || registry["environment"] != suite.environment
        || registry["contextDigest"] != context["contextDigest"]
        || registry["gameVersion"] != "26.3"
        || registry["registryDigest"] != hello["registryDigest"]
        || registry["registryDigest"] != suite.registry_digest.as_str()
    {
        return Err(unverified());
    }
    let raw = decode_hex(
        text(registry, "observationBytesHex")?,
        MAX_PROFILE_BYTES as usize,
        budget,
    )?;
    let observation = parse(&raw, budget)?;
    if digest(&observation)? != suite.registry_digest {
        return Err(unverified());
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "Same-store operation, current authenticated context, original source and expected runtime case are separate evidence roots"
)]
fn verify_durable_case(
    store: &PlanningStore<'_>,
    rpc: &TargetRpc,
    case: &RuntimeCaseRecord,
    expected: &RuntimeCaseSource,
    suite: &RuntimeSuite,
    profile: &Value,
    source_bytes: &[u8],
    bytes_left: &mut u64,
) -> AppResult<DurableCaseWitness> {
    rpc.fresh()?;
    let (observation, invocation_digest, readback_source_digest) = store.with_read(|store| {
        let operation = store.operation(&case.operation_id).map_err(storage_app)?;
        if operation.principal != *rpc.authenticated.principal()
            || operation.project_id != rpc.project
            || operation.context_id != rpc.context_id
            || operation.state != OperationState::Succeeded
            || operation.reconciliation_required
            || operation.cancellation_requested
        {
            return Err(unverified());
        }
        let scope = serde_json::to_value(&operation.scope).map_err(|_| unverified())?;
        if !crate::authority::scope_contains(&rpc.context["scope"], &scope) {
            return Err(forbidden());
        }
        rpc.authority.authorize_retained_scope(
            rpc.authenticated.principal(),
            &rpc.project,
            &rpc.context_id,
            &field_digest(&rpc.context, "policyRevision")?,
            &scope,
        )?;
        let step = operation
            .steps
            .iter()
            .find(|step| step.step_id == case.step_id)
            .ok_or_else(unverified)?;
        if !step.write_effect
            || step.verification_requirement != VerificationRequirement::IndependentReadback
            || step.dispatch != DispatchEvidence::Observed
            || !step.finished
            || step.further_effects_possible
            || step.effect != EffectEvidence::CompleteConfirmed
            || step.invocation_id.as_ref() != Some(&case.invocation_id)
            || !step.observation_refs.contains(&case.readback_envelope)
        {
            return Err(unverified());
        }
        budget_check(&rpc.budget)?;
        let invocation_blob = store
            .stored_invocation_blob(&case.operation_id, &case.step_id)
            .map_err(storage_app)?;
        *bytes_left = bytes_left
            .checked_sub(invocation_blob.byte_length)
            .ok_or_else(unverified)?;
        let invocation = store
            .stored_invocation_checked(&case.operation_id, &case.step_id, 64 * 1024, || rpc.check())
            .map_err(|failure| match rpc.budget.check() {
                Err(stopped) => error(stopped.code, stopped.message),
                Ok(()) => storage_app(failure),
            })?;
        if invocation["invocationId"] != case.invocation_id.as_str()
            || invocation["actionId"] != "mmmm:command_execute"
            || invocation["actionContractVersion"] != "0.2.0"
            || invocation["context"] != rpc.context
            || invocation["context"]["principalRef"] != rpc.authenticated.principal().as_str()
            || invocation["implementationDigest"] != suite.host_artifact_digest.as_str()
            || invocation["arguments"]["command"] != expected.program.invocation_command()
            || step.invocation_digest.as_ref() != Some(&digest(&invocation)?)
        {
            return Err(unverified());
        }
        let envelope = parse(
            &read_operation_blob(store, rpc, &case.readback_envelope, bytes_left)?,
            &rpc.budget,
        )?;
        if envelope["kind"] != "independent_readback"
            || envelope["settled"] != true
            || envelope["stepId"] != case.step_id.as_str()
            || envelope["invocationId"] != case.invocation_id.as_str()
            || envelope["contextDigest"] != rpc.context["contextDigest"]
            || envelope["bindingId"] != invocation["bindingId"]
            || envelope["implementationDigest"] != invocation["implementationDigest"]
            || envelope["effect"] != serde_json::to_value(step.effect).map_err(|_| unverified())?
            || envelope["argumentsDigest"] != digest(&invocation["arguments"])?.as_str()
            || envelope["sourceRefs"]
                .as_array()
                .is_none_or(|sources| sources.len() != 1)
        {
            return Err(unverified());
        }
        let source: BlobRef =
            serde_json::from_value(envelope["sourceRefs"][0].clone()).map_err(|_| unverified())?;
        if !store
            .operation_evidence_refs(&case.operation_id)
            .map_err(storage_app)?
            .contains(&source)
        {
            return Err(unverified());
        }
        let observation = parse(
            &read_operation_blob(store, rpc, &source, bytes_left)?,
            &rpc.budget,
        )?;
        Ok((observation, digest(&invocation)?, source.digest))
    })?;
    if case.case_id == PACK_CASE {
        verify_pack_readback(
            &observation,
            case,
            expected,
            suite,
            profile,
            source_bytes,
            &rpc.budget,
        )?;
        rpc.fresh()?;
        return Ok(DurableCaseWitness {
            invocation_digest,
            readback_source_digest,
            selected_native_return: Some(1),
        });
    }
    let readback: NumericReadback =
        serde_json::from_value(observation).map_err(|_| unverified())?;
    if readback.format != "mmmm.target-case-readback/2"
        || readback.case_id != case.case_id
        || readback.source_resource != expected.source.resource
        || readback.command_stage_index != expected.program.command_stage_index()
        || readback.invocation_id != case.invocation_id
        || readback.runtime_source_facts_digest != suite.runtime_source_facts_digest
    {
        return Err(unverified());
    }
    validate_numeric_readback(&readback)?;
    rpc.fresh()?;
    Ok(DurableCaseWitness {
        invocation_digest,
        readback_source_digest,
        selected_native_return: readback.command_return.map(Int32::get),
    })
}

fn validate_numeric_readback(readback: &NumericReadback) -> AppResult<()> {
    let case = CalibrationCase::from_case_id(&readback.case_id).ok_or_else(unverified)?;
    let program = CalibrationProgram::for_case(case).map_err(domain_app)?;
    let expected = program.expectation();
    let output: TypedScalar = serde_json::from_value(program.expected_readback()["output"].clone())
        .map_err(|_| unverified())?;
    let command_return = readback.command_return.map(Int32::get);
    if readback.format != "mmmm.target-case-readback/2"
        || readback.command_success != expected.command_success
        || readback.ok_score.get() != expected.ok_score
        || readback.output != output
        || readback.scratch_present != expected.scratch_present
        || !readback.stale_output_seeded
        || ((expected.command_success || expected.command_return.is_some())
            && command_return.is_none())
        || expected
            .command_return
            .is_some_and(|value| command_return != Some(value))
    {
        return Err(unverified());
    }
    Ok(())
}

fn verify_issued_command_return(
    observed: &[Value],
    stage: u32,
    independent_return: Option<i32>,
) -> AppResult<()> {
    let selected = observed.get(stage as usize).ok_or_else(unverified)?;
    let actual = required_nullable_integer(selected.get("nativeReturn"))?;
    if actual != independent_return {
        return Err(error(
            "TARGET_RUNTIME_EVIDENCE_CONFLICT",
            "Actual issued command return contradicts its independent retained readback",
        ));
    }
    Ok(())
}

fn verify_normative_source(
    program: &RuntimeCaseProgram,
    bytes: &[u8],
    budget: &RequestBudget,
) -> AppResult<()> {
    budget_check(budget)?;
    let matches = match program {
        RuntimeCaseProgram::Numeric(program) => {
            bytes == program.source_bytes() && raw_digest(bytes) == *program.source_digest()
        }
        RuntimeCaseProgram::DataPack(program) => {
            read_calibration_pack(bytes, budget)? == *program.source_entries()
        }
    };
    if !matches {
        return Err(error(
            "TARGET_RUNTIME_SOURCE_MISMATCH",
            "Registered case bytes are not the sealed normative calibration source",
        ));
    }
    budget_check(budget)
}

fn read_calibration_pack(
    bytes: &[u8],
    budget: &RequestBudget,
) -> AppResult<BTreeMap<String, Vec<u8>>> {
    let limits = ArchiveLimits {
        max_archive_bytes: MAX_EVIDENCE_BYTES,
        max_member_bytes: MAX_EVIDENCE_BYTES,
        max_total_bytes: MAX_EVIDENCE_BYTES,
        max_members: 4096,
        max_ratio: 100,
        max_path_bytes: 1024,
    };
    read_zip_with_required_root(bytes, limits, "pack.mcmeta", || budget.check().is_err()).map_err(
        |failure| match budget.check() {
            Err(stopped) => error(stopped.code, stopped.message),
            Ok(()) => AppError::storage(
                "TARGET_EVIDENCE_INVALID",
                StorageError::Contract(failure.to_string()),
            ),
        },
    )
}
fn verified_rules(
    suite: &RuntimeSuite,
    admitted: &BTreeMap<String, CalibrationRunSource>,
) -> AppResult<TargetRuntimeRules> {
    if admitted.len() != suite.cases.len() {
        return Err(unverified());
    }
    for case in &suite.cases {
        let admission = admitted.get(&case.case_id).ok_or_else(unverified)?;
        if admission.case_id != case.case_id
            || admission.invocation_id != case.invocation_id
            || admission.program_digest.as_str().is_empty()
            || admission.receipt_digest.as_str().is_empty()
        {
            return Err(unverified());
        }
    }
    let numeric = NUMERIC_CASES
        .iter()
        .all(|required| suite.cases.iter().any(|case| case.case_id == *required));
    if !numeric {
        return Err(unverified());
    }
    // Actual numeric chain cases attest numeric compilation only. A distinct
    // real reload/function/codec suite is required before pack_version admits a
    // pack. Its absent proof is not replaced by a profile format number.
    Ok(TargetRuntimeRules {
        native_compute_26_3: numeric,
        checked_numeric_and_success: numeric,
        data_pack_26_3: suite.cases.iter().any(|case| case.case_id == PACK_CASE),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PackReadback {
    format: String,
    case_id: String,
    source_resource: Value,
    command_stage_index: u32,
    invocation_id: InvocationId,
    runtime_source_facts_digest: Sha256Digest,
    min_format: Value,
    max_format: Value,
    installed_function_ids: BTreeSet<String>,
    dispatched_function_id: String,
    marker: Int32,
}
fn verify_pack_readback(
    value: &Value,
    case: &RuntimeCaseRecord,
    expected: &RuntimeCaseSource,
    suite: &RuntimeSuite,
    profile: &Value,
    source_bytes: &[u8],
    budget: &RequestBudget,
) -> AppResult<()> {
    let readback: PackReadback = serde_json::from_value(value.clone()).map_err(|_| unverified())?;
    if readback.format != "mmmm.target-pack-readback/1"
        || readback.case_id != PACK_CASE
        || readback.source_resource != expected.source.resource
        || readback.command_stage_index != expected.program.command_stage_index()
        || readback.invocation_id != case.invocation_id
        || readback.runtime_source_facts_digest != suite.runtime_source_facts_digest
        || format_pair(&readback.min_format)? != profile_format_pair(profile)?
        || format_pair(&readback.max_format)? != profile_format_pair(profile)?
        || readback.marker.get() != 1337
        || expected.program.invocation_command()
            != format!("function {}", readback.dispatched_function_id)
        || readback.installed_function_ids.is_empty()
        || readback.installed_function_ids.len() > 4096
    {
        return Err(unverified());
    }
    let RuntimeCaseProgram::DataPack(program) = &expected.program else {
        return Err(unverified());
    };
    let entries = read_calibration_pack(source_bytes, budget)?;
    if entries != *program.source_entries()
        || readback.installed_function_ids != *program.function_ids()
    {
        return Err(unverified());
    }
    let metadata = parse(entries.get("pack.mcmeta").ok_or_else(unverified)?, budget)?;
    if format_pair(&metadata["pack"]["min_format"])? != profile_format_pair(profile)?
        || format_pair(&metadata["pack"]["max_format"])? != profile_format_pair(profile)?
    {
        return Err(unverified());
    }
    let mut functions = BTreeMap::new();
    for (path, bytes) in &entries {
        budget_check(budget)?;
        let Some(rest) = path.strip_prefix("data/") else {
            continue;
        };
        let Some((namespace, suffix)) = rest.split_once("/function/") else {
            if rest.contains("/functions/") {
                return Err(unverified());
            }
            continue;
        };
        let Some(name) = suffix.strip_suffix(".mcfunction") else {
            continue;
        };
        let id = format!("{namespace}:{name}");
        mmmm_contracts::ResourceLocation::new(&id).map_err(|_| unverified())?;
        let source = std::str::from_utf8(bytes).map_err(|_| unverified())?;
        if source.contains('\0') || source.lines().any(|line| line.starts_with('$')) {
            return Err(unverified());
        }
        functions.insert(id, source);
    }
    if functions.keys().cloned().collect::<BTreeSet<_>>() != readback.installed_function_ids
        || !functions.contains_key(&readback.dispatched_function_id)
    {
        return Err(unverified());
    }
    for source in functions.values() {
        for line in source
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
        {
            budget_check(budget)?;
            let tokens: Vec<_> = line.split_ascii_whitespace().collect();
            for pair in tokens.windows(2) {
                // Registered runtime evidence currently admits an entirely
                // owned, finite function closure. External calls and tag/macros
                // need their separate exact source authority, not a name match.
                if pair[0] == "function" && !functions.contains_key(pair[1]) {
                    return Err(unverified());
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
struct TargetRpc {
    authenticated: AuthenticatedPrincipal,
    budget: RequestBudget,
    authority: LocalAuthority,
    access: LocalPlanningAccess,
    context_id: ContextId,
    project: ProjectId,
    context: Value,
}
impl TargetRpc {
    fn fresh(&self) -> AppResult<()> {
        budget_check(&self.budget)?;
        self.access.authorize_project(
            self.authenticated.principal(),
            &self.project,
            Some(&self.context),
            Access::Plan,
        )
    }
    fn local_project(
        &self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
    ) -> Result<(), StorageError> {
        self.check()?;
        if principal != self.authenticated.principal()
            || context != Some(&self.context_id)
            || project != &self.project
        {
            return Err(storage_forbidden());
        }
        self.authority
            .authorize_retained_scope(
                principal,
                project,
                &self.context_id,
                &field_digest(&self.context, "policyRevision").map_err(app_storage)?,
                &self.context["scope"],
            )
            .map_err(app_storage)
    }
    fn storage_error(&self, error_value: StorageError) -> AppError {
        if let Err(stopped) = self.budget.check() {
            return AppError::storage(stopped.code, error_value);
        }
        storage_app(error_value)
    }
}
impl ProjectSourceRpcContext for TargetRpc {
    fn check(&self) -> Result<(), StorageError> {
        budget_check(&self.budget).map_err(app_storage)?;
        if !self.authenticated.is_current()
            || !self.authenticated.permits_context(self.context_id.as_str())
        {
            return Err(storage_forbidden());
        }
        Ok(())
    }
    fn authenticated_principal(&self) -> Result<PrincipalId, StorageError> {
        self.check()?;
        Ok(self.authenticated.principal().clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        Some(&self.context_id)
    }
}
struct TargetReadAuthority(TargetRpc);
impl ProjectResourceAuthority for TargetReadAuthority {
    fn authorize_project_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        _revision: &Sha256Digest,
    ) -> Result<(), StorageError> {
        self.0.local_project(principal, context, project)
    }
    fn authorize_resource_read(
        &mut self,
        _store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> Result<(), StorageError> {
        self.0.local_project(principal, context, project)?;
        if resource.owner != ResourceOwner::Project(project.clone()) {
            return Err(storage_forbidden());
        }
        let id = text(&resource.resource, "resourceId").map_err(app_storage)?;
        let current = self
            .0
            .authority
            .project_scope(principal, project)
            .map_err(app_storage)?;
        if !has_resource(&current, id) || !has_resource(&self.0.context["scope"], id) {
            return Err(storage_forbidden());
        }
        self.0.check()
    }
}
fn read_resource(
    store: &PlanningStore<'_>,
    rpc: &TargetRpc,
    resource: &TargetProfileResource,
    max_bytes: u64,
    bytes_left: &mut u64,
) -> AppResult<Vec<u8>> {
    validate("ResourceRef", &resource.resource)?;
    let ceiling = max_bytes.min(*bytes_left);
    if ceiling == 0 {
        return Err(error(
            "BUDGET_EXCEEDED",
            "Target evidence cumulative byte limit reached",
        ));
    }
    let bytes = store.with_read(|store| {
        let mut reader =
            ProjectResourceReader::new(Box::new(TargetReadAuthority(rpc.clone())), MAX_TOTAL_BYTES)
                .map_err(|error_value| rpc.storage_error(error_value))?;
        let project = reader
            .current_project(store, rpc, &rpc.project, 8 * 1024 * 1024)
            .map_err(|error_value| rpc.storage_error(error_value))?;
        reader
            .read(
                store,
                rpc,
                &ProjectResourceRequest {
                    project: &rpc.project,
                    current_project_revision: &field_digest(&project, "revision")?,
                    query: &resource.query,
                    expected: Some(&resource.resource),
                },
                ceiling,
            )
            .map(|read| read.bytes)
            .map_err(|error_value| rpc.storage_error(error_value))
    })?;
    *bytes_left = bytes_left
        .checked_sub(bytes.len() as u64)
        .ok_or_else(unverified)?;
    Ok(bytes)
}
fn read_operation_blob(
    store: &DurableStore,
    rpc: &TargetRpc,
    blob: &BlobRef,
    bytes_left: &mut u64,
) -> AppResult<Vec<u8>> {
    if blob.byte_length > MAX_EVIDENCE_BYTES || blob.byte_length > *bytes_left {
        return Err(error(
            "BUDGET_EXCEEDED",
            "Runtime readback evidence exceeds its byte limit",
        ));
    }
    let bytes = store
        .read_blob_checked(blob, MAX_EVIDENCE_BYTES, || rpc.check())
        .map_err(|error_value| rpc.storage_error(error_value))?;
    *bytes_left = bytes_left
        .checked_sub(bytes.len() as u64)
        .ok_or_else(unverified)?;
    Ok(bytes)
}
fn retain_host_response(
    store: &PlanningStore<'_>,
    rpc: &TargetRpc,
    selector: &str,
    response: &Value,
) -> AppResult<()> {
    let bytes = encode_json(&json!({"format":"mmmm.target-host-evidence/1","principal":rpc.authenticated.principal(),
        "projectId":rpc.project,"contextDigest":rpc.context["contextDigest"],"retainedScope":rpc.context["scope"],
        "selector":selector,"response":response})).map_err(|_| unverified())?;
    if bytes.len() as u64 > MAX_EVIDENCE_BYTES {
        return Err(error(
            "BUDGET_EXCEEDED",
            "Native target response evidence exceeds its finite limit",
        ));
    }
    let sha256 = raw_digest(&bytes);
    let identity =
        digest(&json!({"projectId":rpc.project,"sha256":sha256,"mediaType":HOST_EVIDENCE_MEDIA}))?;
    let resource = json!({"resourceId":format!("target-host-{identity}"),"sha256":sha256,"mediaType":HOST_EVIDENCE_MEDIA,"sizeBytes":bytes.len()});
    store.with_write(|store| {
        rpc.check()
            .map_err(|error_value| rpc.storage_error(error_value))?;
        let blob = store.put_blob(&bytes).map_err(storage_app)?;
        if blob.digest != sha256 || blob.byte_length != bytes.len() as u64 {
            return Err(unverified());
        }
        register_resource(
            store,
            &resource,
            ResourceOwner::Project(rpc.project.clone()),
        )
        .map_err(|error_value| error(error_value.code, error_value.message))?;
        Ok(())
    })
}
fn parse(bytes: &[u8], budget: &RequestBudget) -> AppResult<Value> {
    parse_json_with_control(
        bytes,
        JsonLimits {
            max_bytes: MAX_EVIDENCE_BYTES as usize,
            max_depth: 64,
            max_nodes: 100_000,
        },
        || budget_check(budget),
    )
    .map_err(|error_value| match error_value {
        ControlledJsonError::Control(error_value) => error_value,
        ControlledJsonError::Json(error_value) => AppError::storage(
            "TARGET_EVIDENCE_INVALID",
            StorageError::Contract(error_value.to_string()),
        ),
    })
}
fn decode_hex(value: &str, max_bytes: usize, budget: &RequestBudget) -> AppResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) || value.len() / 2 > max_bytes {
        return Err(unverified());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        if index % 4096 == 0 {
            budget_check(budget)?;
        }
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        bytes.push(
            digit(pair[0]).ok_or_else(unverified)? * 16 + digit(pair[1]).ok_or_else(unverified)?,
        );
    }
    budget_check(budget)?;
    Ok(bytes)
}
fn exact_fields(value: &Value, keys: &[&str]) -> AppResult<()> {
    if value.as_object().is_none_or(|object| {
        object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key))
    }) {
        return Err(unverified());
    }
    Ok(())
}
fn validate_observed_window(value: &Value) -> AppResult<()> {
    fn tick(value: &Value, field: &str) -> AppResult<u64> {
        let text = text(value, field)?;
        if text.is_empty()
            || text.len() > 20
            || !text.bytes().all(|byte| byte.is_ascii_digit())
            || (text.len() > 1 && text.starts_with('0'))
        {
            return Err(unverified());
        }
        text.parse::<u64>().map_err(|_| unverified())
    }
    if tick(value, "observedFromTick")? > tick(value, "observedToTick")?
        || value["observedAt"].as_str().is_none_or(|text| {
            text.is_empty() || text.len() > 128 || text.chars().any(char::is_control)
        })
    {
        return Err(unverified());
    }
    Ok(())
}
fn validate(definition: &str, value: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .and_then(|validator| validator.validate(definition, value))
        .map_err(|_| invalid("Target value violates the original canonical contract"))
}
fn decode_resource(value: &Value) -> AppResult<ResourceRef> {
    validate("ResourceRef", value)?;
    serde_json::from_value(value.clone()).map_err(|_| unverified())
}
fn integer(value: &Value) -> AppResult<i32> {
    serde_json::from_value::<Int32>(value.clone())
        .map(Int32::get)
        .map_err(|_| unverified())
}
fn required_nullable_integer(value: Option<&Value>) -> AppResult<Option<i32>> {
    match value {
        Some(Value::Null) => Ok(None),
        Some(value) => integer(value).map(Some),
        None => Err(unverified()),
    }
}
fn format_pair(value: &Value) -> AppResult<[u32; 2]> {
    let values: [Int32; 2] = serde_json::from_value(value.clone()).map_err(|_| unverified())?;
    Ok([
        u32::try_from(values[0].get()).map_err(|_| unverified())?,
        u32::try_from(values[1].get()).map_err(|_| unverified())?,
    ])
}
fn profile_format_pair(profile: &Value) -> AppResult<[u32; 2]> {
    format_pair(&json!([
        profile["dataPackVersion"]["major"],
        profile["dataPackVersion"]["minor"]
    ]))
}
fn has_resource(scope: &Value, id: &str) -> bool {
    scope["resourceIds"]
        .as_array()
        .is_some_and(|ids| ids.iter().any(|value| value.as_str() == Some(id)))
}
fn text<'a>(value: &'a Value, field: &str) -> AppResult<&'a str> {
    value[field].as_str().ok_or_else(unverified)
}
fn field_digest(value: &Value, field: &str) -> AppResult<Sha256Digest> {
    Sha256Digest::new(text(value, field)?).map_err(|_| unverified())
}
fn digest(value: &Value) -> AppResult<Sha256Digest> {
    canonical_digest(value).map_err(|_| unverified())
}
fn budget_check(budget: &RequestBudget) -> AppResult<()> {
    budget
        .check()
        .map_err(|error_value| error(error_value.code, error_value.message))
}
fn error(code: &'static str, message: &'static str) -> AppError {
    AppError::new(code, message)
}
fn unverified() -> AppError {
    error(
        "TARGET_UNVERIFIED",
        "Exact original sources, actual runtime cases and independent readbacks have not been admitted",
    )
}
fn invalid(message: &'static str) -> AppError {
    error("TARGET_EVIDENCE_INVALID", message)
}
fn forbidden() -> AppError {
    error(
        "PERMISSION_REQUIRED",
        "Current authenticated source/context authority is required",
    )
}
fn busy() -> AppError {
    error("SOURCE_BUSY", "Target source registration is in use")
}
fn storage_app(error_value: StorageError) -> AppError {
    AppError::storage("TARGET_SOURCE_UNAVAILABLE", error_value)
}
fn domain_app(error_value: DomainError) -> AppError {
    AppError::storage(
        error_value.code,
        StorageError::Contract(error_value.to_string()),
    )
}
fn app_storage(error_value: AppError) -> StorageError {
    StorageError::InvalidTransition(format!("{}: {}", error_value.code, error_value.message))
}
fn storage_forbidden() -> StorageError {
    app_storage(forbidden())
}

#[cfg(test)]
#[path = "target_profile_tests.rs"]
mod tests;

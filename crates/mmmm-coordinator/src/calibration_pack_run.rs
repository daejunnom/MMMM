//! The closed PACK run uses the existing Store and operation journal. Public
//! locators select retained data; they cannot construct a source or approval.

use crate::{
    authority::LocalAuthority,
    bootstrap::NativeWorkspacePermit,
    calibration_bootstrap::{BootstrapRegistry, PackBootstrapOrigin},
    calibration_execution::CalibrationRegistry,
    calibration_planning::CalibrationPlanReceipt,
    host::{HostBridge, PackRunHostRoute, PackRunReadiness},
    observer::finish_native_observation,
    peer_management::{CompletedBootstrap, ManagementError},
    service::RequestContextWitness,
    workspace_bootstrap::NativeOwnerWitness,
};
use mmmm_application::{Access, AppError, AppResult, Application, AuthorityPort, SetupSelection};
use mmmm_compiler::calibration::CalibrationPackProgram;
use mmmm_contracts::{
    OperationId, Sha256Digest, StepId, TargetId, canonical_bytes, canonical_digest, encode_json,
    raw_digest,
};
use mmmm_exchange::archive::{
    ArchiveLimits, read_zip_with_required_root, write_zip_with_required_root_and_cancel,
};
use mmmm_runtime::storage::{
    BlobRef, DispatchEvidence, DurableStore, OperationRecord, OperationState, StepRecord,
    StorageError, WriteScope,
    artifact::{ResourceOwner, register_resource_with_diagnostics},
};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::BTreeMap, path::PathBuf, rc::Rc, sync::Arc, time::Instant};

pub(crate) const PURPOSE: &str = "pack_calibration_run/1";
pub(crate) const MANIFEST_KIND: &str = "native_pack_calibration_run_approval/1";
pub(crate) const TARGET: &str = "calibration-objective-mcalpack";
pub(crate) const ACTION: &str = "mmmm:command_execute";
pub(crate) const STEP_IDS: [&str; 3] = ["pack-init-objective", "pack-seed-marker", "pack-entry"];
const MAX_RECORDS: usize = 8;
const MAX_SOURCE_BYTES: u64 = 256 * 1024;

pub(crate) struct PreparedPackRunSource {
    store: *const DurableStore,
    store_root: PathBuf,
    selection: SetupSelection,
    context: Value,
    origin: PackBootstrapOrigin,
    program: CalibrationPackProgram,
    target: TargetId,
    zip_resource: Value,
    zip: BlobRef,
    readiness: BlobRef,
    load_invocation_digest: Sha256Digest,
    selected_source_digest: Sha256Digest,
    expected: Vec<(String, BlobRef)>,
    initial_target: BlobRef,
    initial_runtime_source_facts_digest: Sha256Digest,
    initial_host_artifact_digest: Sha256Digest,
    initial_registry_generation: String,
}
impl PreparedPackRunSource {
    pub(crate) fn target(&self) -> &TargetId {
        &self.target
    }
    pub(crate) fn preconditions(&self) -> Vec<Value> {
        let mut conditions = self
            .expected
            .iter()
            .map(|(subject, blob)| {
                json!({"kind":"resource_hash", "subject":subject,
            "expected":blob.digest, "coverage":"full_target"})
            })
            .collect::<Vec<_>>();
        conditions.push(json!({"kind":"resource_hash","subject":TARGET,"expected":self.initial_target.digest,"coverage":"full_target"}));
        conditions
    }
}

/// Authority is borrowed for this request; it is never stored in the source.
#[allow(
    clippy::too_many_arguments,
    reason = "Current request, owner, selected source, host and explicit authority are independent admission inputs"
)]
pub(crate) fn prepare_plan(
    app: &mut Application<'_>,
    request: &RequestContextWitness,
    owner: &NativeOwnerWitness,
    hosts: &HostBridge,
    selection: &SetupSelection,
    calibration: &CalibrationRegistry,
    bootstrap: &BootstrapRegistry,
    origin: &OperationId,
    authority: &LocalAuthority,
) -> AppResult<CalibrationPlanReceipt> {
    request.check_local().map_err(request_error)?;
    if calibration.len().map_err(|cause| {
        AppError::caused_by(
            "PACK_CALIBRATION_UNAVAILABLE",
            "The shared calibration capacity is unavailable",
            cause,
        )
    })? >= MAX_RECORDS
    {
        return Err(unavailable());
    }
    crate::calibration_planning::prepare_pack_run_plan(
        app,
        request,
        owner,
        hosts,
        selection,
        calibration,
        bootstrap,
        origin,
        authority,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "The actual owner, request, source origin and current authority must remain explicit while staging private CAS data"
)]
pub(crate) fn stage_source(
    store: &mut DurableStore,
    request: &RequestContextWitness,
    owner: &NativeOwnerWitness,
    hosts: &HostBridge,
    selection: &SetupSelection,
    context: &Value,
    origin: PackBootstrapOrigin,
    authority: &LocalAuthority,
) -> AppResult<Rc<PreparedPackRunSource>> {
    let current = |store: &DurableStore| origin.check(store, request, owner, selection, authority);
    current(store)?;
    let selector = json!({"kind":"pack_calibration_run_readiness", "invocationId":origin.original()["invocationId"],
        "invocationDigest":canonical_digest(origin.original()).map_err(|_| unavailable())?,
        "sourceBundleDigest":origin.source_bundle_digest(), "frozenManifestDigest":origin.frozen_manifest_digest()});
    let response = hosts.inspect_pack_run_readiness_with_store(
        store,
        PackRunReadiness {
            request,
            authority,
            source_original: origin.original(),
            current_context: context,
        },
        selector,
        &current,
    )?;
    let program = CalibrationPackProgram::java_26_3().map_err(|cause| {
        AppError::caused_by(cause.code, "The closed PACK recipe is unavailable", cause)
    })?;
    let load_invocation_digest = canonical_digest(origin.original()).map_err(|_| unavailable())?;
    let selected_source_digest = verify_load_readiness(
        &response,
        &program,
        origin.source_bundle_digest(),
        &load_invocation_digest,
    )?;
    let initial = crate::calibration_pack_observer::initial_plan_image(
        &response["targetImages"],
        context,
        &|| current(store),
    )?;
    let limits = ArchiveLimits::default();
    let control_failure = RefCell::new(None);
    let zip_result = write_zip_with_required_root_and_cancel(
        program.source_entries(),
        limits,
        "pack.mcmeta",
        || {
            if control_failure.borrow().is_some() {
                return true;
            }
            match current(store) {
                Ok(()) => false,
                Err(cause) => {
                    *control_failure.borrow_mut() = Some(cause);
                    true
                }
            }
        },
    )
    .map_err(|cause| {
        AppError::caused_by(
            "PACK_SOURCE_UNAVAILABLE",
            "The exact PACK source ZIP could not be staged",
            cause,
        )
    });
    let zip_bytes = match (zip_result, control_failure.into_inner()) {
        (Ok(bytes), None) => bytes,
        (Err(cause), None) | (Ok(_), Some(cause)) => return Err(cause),
        (Err(archive), Some(primary)) => {
            return Err(AppError::caused_by(
                primary.code,
                primary.message,
                StorageError::CalibrationCheckpointFailure {
                    primary: Box::new(app_storage(primary)),
                    checkpoint: Box::new(app_storage(archive)),
                },
            ));
        }
    };
    let reread = read_pack_source_zip(&zip_bytes, limits, || current(store))?;
    if reread != *program.source_entries()
        || program.program_digest() != origin.logical_program_digest()
    {
        return Err(unavailable());
    }
    current(store)?;
    let zip = store.put_blob(&zip_bytes).map_err(storage)?;
    let ready_bytes = encode_json(&response).map_err(|_| unavailable())?;
    if ready_bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err(unavailable());
    }
    let readiness = store.put_blob(&ready_bytes).map_err(storage)?;
    let zip_resource = json!({"resourceId":format!("calibration-pack-zip-{}", zip.digest),
        "sha256":zip.digest, "sizeBytes":zip.byte_length, "mediaType":"application/zip"});
    register_resource_with_diagnostics(
        store,
        &zip_resource,
        ResourceOwner::Project(selection.project_id.clone()),
    )
    .map_err(|cause| {
        AppError::caused_by(
            "PACK_SOURCE_UNAVAILABLE",
            "The exact source ZIP registration failed",
            cause,
        )
    })?;
    let ready_resource = json!({"resourceId":format!("calibration-pack-readiness-{}", readiness.digest),
        "sha256":readiness.digest, "sizeBytes":readiness.byte_length, "mediaType":"application/vnd.mmmm.pack-run-readiness+json"});
    register_resource_with_diagnostics(
        store,
        &ready_resource,
        ResourceOwner::Project(selection.project_id.clone()),
    )
    .map_err(|cause| {
        AppError::caused_by(
            "PACK_SOURCE_UNAVAILABLE",
            "The actual readiness registration failed",
            cause,
        )
    })?;
    current(store)?;
    let initial_target = store.put_blob(&initial.image.bytes).map_err(storage)?;
    let initial_resource = json!({"resourceId":format!("calibration-pack-initial-target-{}",initial_target.digest),
        "sha256":initial_target.digest,"sizeBytes":initial_target.byte_length,"mediaType":"application/vnd.mmmm.target-image+json"});
    register_resource_with_diagnostics(
        store,
        &initial_resource,
        ResourceOwner::Project(selection.project_id.clone()),
    )
    .map_err(|cause| {
        AppError::caused_by(
            "PACK_SOURCE_UNAVAILABLE",
            "The actual initial whole objective registration failed",
            cause,
        )
    })?;
    let expected = vec![
        (
            text(&origin.source_bundle()["rawResource"], "resourceId")?.into(),
            origin.source_blob().clone(),
        ),
        (
            format!("pack-logical-recipe-{}", origin.recipe_blob().digest),
            origin.recipe_blob().clone(),
        ),
        (text(&zip_resource, "resourceId")?.into(), zip.clone()),
        (
            text(&ready_resource, "resourceId")?.into(),
            readiness.clone(),
        ),
    ];
    current(store)?;
    Ok(Rc::new(PreparedPackRunSource {
        store: store as *const DurableStore,
        store_root: store.data_root().to_path_buf(),
        selection: selection.clone(),
        context: context.clone(),
        origin,
        program,
        target: TargetId::new(TARGET).map_err(|_| unavailable())?,
        zip_resource,
        zip,
        readiness,
        load_invocation_digest,
        selected_source_digest,
        expected,
        initial_target,
        initial_runtime_source_facts_digest: initial.runtime_source_facts_digest,
        initial_host_artifact_digest: initial.host_artifact_digest,
        initial_registry_generation: initial.registry_generation,
    }))
}

/// Pure strict decoding is not issuance. Only `stage_source` uses the result
/// after acquiring it through the current owned host and retained native attempt.
fn verify_load_readiness(
    value: &Value,
    program: &CalibrationPackProgram,
    bundle: &Sha256Digest,
    load: &Sha256Digest,
) -> AppResult<Sha256Digest> {
    fields(value, &["format", "receiptBytesHex", "targetImages"])?;
    if value["format"] != "mmmm.native.pack-run-readiness/1" {
        return Err(unavailable());
    }
    let bytes = hex_bytes(text(value, "receiptBytesHex")?)?;
    if bytes.len() < 12
        || &bytes[..8] != b"MMMMPR01"
        || bytes[8] != 47
        || bytes[9] != 1
        || usize::from(u16::from_be_bytes([bytes[10], bytes[11]])) != bytes.len() - 12
    {
        return Err(unavailable());
    }
    let payload: Value = serde_json::from_slice(&bytes[12..]).map_err(|_| unavailable())?;
    fields(
        &payload,
        &[
            "format",
            "loadOnly",
            "sourceKind",
            "loadInvocationDigest",
            "sourceBundleDigest",
            "logicalProgramDigest",
            "selectedFunctionSourceDigest",
            "functions",
        ],
    )?;
    if payload["format"] != "mmmm.native.pack-run-readiness/1"
        || payload["loadOnly"] != true
        || payload["sourceKind"] != "pack_case"
        || payload["loadInvocationDigest"] != load.as_str()
        || payload["sourceBundleDigest"] != bundle.as_str()
        || payload["logicalProgramDigest"] != program.program_digest().as_str()
    {
        return Err(unavailable());
    }
    let functions = payload["functions"]
        .as_array()
        .filter(|rows| rows.len() == 2)
        .ok_or_else(unavailable)?;
    for (row, id) in functions.iter().zip(program.function_ids()) {
        fields(row, &["functionId", "resourceId", "rawSha256"])?;
        let (namespace, path) = id.split_once(':').ok_or_else(unavailable)?;
        let source_path = format!("data/{namespace}/function/{path}.mcfunction");
        if row["functionId"] != id.as_str()
            || row["resourceId"] != format!("{namespace}:function/{path}.mcfunction")
            || row["rawSha256"]
                != raw_digest(
                    program
                        .source_entries()
                        .get(&source_path)
                        .ok_or_else(unavailable)?,
                )
                .as_str()
        {
            return Err(unavailable());
        }
    }
    let selected: Sha256Digest = decode(&payload["selectedFunctionSourceDigest"])?;
    if canonical_digest(&payload["functions"]).map_err(|_| unavailable())? != selected {
        return Err(unavailable());
    }
    Ok(selected)
}

struct PreparedPackRun {
    source: Rc<PreparedPackRunSource>,
    plan: Value,
    selected: RefCell<Option<Value>>,
    confirmed: RefCell<Option<Rc<ConfirmedPackRun>>>,
    operation: RefCell<Option<OperationId>>,
    metadata: RefCell<Option<PackRunMetadata>>,
}
#[derive(Clone)]
struct PackRunMetadata {
    context: Value,
    runtime_facts: Value,
    runtime_source_facts_digest: Sha256Digest,
    host_artifact_digest: Sha256Digest,
    registry_generation: String,
}
impl PartialEq for PackRunMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.context == other.context
            && self.runtime_source_facts_digest == other.runtime_source_facts_digest
            && self.host_artifact_digest == other.host_artifact_digest
            && self.registry_generation == other.registry_generation
    }
}
struct ConfirmedPackRun {
    manifest: Value,
    route: PackRunHostRoute,
    completion: Arc<CompletedBootstrap>,
    publication_failure: Option<Arc<AppError>>,
    cleanup_failure: RefCell<Option<Arc<AppError>>>,
}
#[derive(Clone, Default)]
pub(crate) struct PackRunRegistry {
    entries: Rc<RefCell<BTreeMap<String, Rc<PreparedPackRun>>>>,
}

pub(crate) fn retain_plan(
    registry: &CalibrationRegistry,
    store: &DurableStore,
    source: Rc<PreparedPackRunSource>,
    plan: &Value,
) -> AppResult<()> {
    if !std::ptr::eq(source.store, store)
        || source.store_root != store.data_root()
        || plan["projectId"] != source.selection.project_id.as_str()
        || plan["projectBaseRevision"] != source.selection.expected_revision.as_str()
        || plan["preconditions"] != Value::Array(source.preconditions())
        || plan["steps"][0]["implementationDigest"] != source.initial_host_artifact_digest.as_str()
        || plan["contextPins"][0]["contextDigest"] != source.context["contextDigest"]
        || plan["contextPins"][0]["environment"] != source.context["environment"]
    {
        return Err(unavailable());
    }
    validate_plan(plan)?;
    check_expiry(plan)?;
    let id = text(plan, "planHash")?.to_owned();
    let total = registry.len().map_err(|cause| {
        AppError::caused_by(
            "PACK_CALIBRATION_UNAVAILABLE",
            "The shared calibration capacity is unavailable",
            cause,
        )
    })?;
    let mut entries = registry
        .pack_runs()
        .entries
        .try_borrow_mut()
        .map_err(|_| unavailable())?;
    if total >= MAX_RECORDS || entries.contains_key(&id) {
        return Err(unavailable());
    }
    entries.insert(
        id,
        Rc::new(PreparedPackRun {
            source,
            plan: plan.clone(),
            selected: RefCell::new(None),
            confirmed: RefCell::new(None),
            operation: RefCell::new(None),
            metadata: RefCell::new(None),
        }),
    );
    Ok(())
}

impl PackRunRegistry {
    pub(crate) fn len(&self) -> Result<usize, ManagementError> {
        Ok(self
            .entries
            .try_borrow()
            .map_err(|_| ManagementError::TransportUncertain)?
            .len())
    }
    fn prepared(&self, store: &DurableStore, plan: &Value) -> AppResult<Rc<PreparedPackRun>> {
        let entry = self
            .entries
            .try_borrow()
            .map_err(|_| unavailable())?
            .get(text(plan, "planHash")?)
            .cloned()
            .ok_or_else(unavailable)?;
        if !std::ptr::eq(entry.source.store, store)
            || entry.source.store_root != store.data_root()
            || entry.plan != *plan
            || store
                .plan(&decode(&plan["planId"])?, &decode(&plan["planHash"])?)
                .map_err(storage)?
                != *plan
        {
            return Err(unavailable());
        }
        Ok(entry)
    }
    pub(crate) fn check_prepared(
        &self,
        store: &DurableStore,
        plan: &Value,
        current: &dyn Fn() -> AppResult<()>,
    ) -> AppResult<()> {
        current()?;
        let entry = self.prepared(store, plan)?;
        validate_plan(plan)?;
        if store
            .project(&entry.source.selection.project_id)
            .map_err(storage)?["revision"]
            != plan["projectBaseRevision"]
        {
            return Err(unavailable());
        }
        let origin = &entry.source.origin;
        let operation = store.operation(origin.operation()).map_err(storage)?;
        let step: StepId = decode(&origin.original()["stepId"])?;
        let original = store
            .stored_invocation_checked(origin.operation(), &step, 64 * 1024, || {
                current().map_err(app_storage)
            })
            .map_err(storage)?;
        let original_blob = store
            .stored_invocation_blob(origin.operation(), &step)
            .map_err(storage)?;
        let bytes = encode_json(&original).map_err(|_| unavailable())?;
        if original != *origin.original()
            || operation.project_id != entry.source.selection.project_id
            || operation.steps.len() != 1
            || operation.steps[0].step_id != step
            || operation.steps[0].dispatch == DispatchEvidence::NotSent
            || operation.steps[0].invocation_digest.as_ref() != Some(&original_blob.digest)
            || original_blob.digest != raw_digest(&bytes)
            || original_blob.byte_length != bytes.len() as u64
            || canonical_digest(&original).map_err(|_| unavailable())?
                != entry.source.load_invocation_digest
        {
            return Err(unavailable());
        }
        for (_, blob) in &entry.source.expected {
            let bytes = store
                .read_blob_checked(blob, MAX_SOURCE_BYTES, || current().map_err(app_storage))
                .map_err(storage)?;
            if raw_digest(&bytes) != blob.digest || bytes.len() as u64 != blob.byte_length {
                return Err(unavailable());
            }
        }
        let recipe = store
            .read_blob_checked(entry.source.origin.recipe_blob(), MAX_SOURCE_BYTES, || {
                current().map_err(app_storage)
            })
            .map_err(storage)?;
        if recipe != entry.source.program.canonical_recipe_bytes() {
            return Err(unavailable());
        }
        let zip = store
            .read_blob_checked(&entry.source.zip, MAX_SOURCE_BYTES, || {
                current().map_err(app_storage)
            })
            .map_err(storage)?;
        if read_pack_source_zip(&zip, ArchiveLimits::default(), current)?
            != *entry.source.program.source_entries()
        {
            return Err(unavailable());
        }
        let ready = store
            .read_blob_checked(&entry.source.readiness, MAX_SOURCE_BYTES, || {
                current().map_err(app_storage)
            })
            .map_err(storage)?;
        let ready: Value = serde_json::from_slice(&ready).map_err(|_| unavailable())?;
        if verify_load_readiness(
            &ready,
            &entry.source.program,
            entry.source.origin.source_bundle_digest(),
            &entry.source.load_invocation_digest,
        )? != entry.source.selected_source_digest
        {
            return Err(unavailable());
        }
        let initial = crate::calibration_pack_observer::initial_plan_image(
            &ready["targetImages"],
            &entry.source.context,
            current,
        )?;
        let initial_bytes = store
            .read_blob_checked(&entry.source.initial_target, MAX_SOURCE_BYTES, || {
                current().map_err(app_storage)
            })
            .map_err(storage)?;
        if initial.image.bytes != initial_bytes
            || raw_digest(&initial_bytes) != entry.source.initial_target.digest
            || initial.runtime_source_facts_digest
                != entry.source.initial_runtime_source_facts_digest
            || initial.host_artifact_digest != entry.source.initial_host_artifact_digest
            || initial.registry_generation != entry.source.initial_registry_generation
        {
            return Err(unavailable());
        }
        current()
    }
    pub(crate) fn select(&self, store: &DurableStore, plan: &Value) -> AppResult<Value> {
        let entry = self.prepared(store, plan)?;
        check_expiry(plan)?;
        let digest = canonical_digest(&json!({"kind":PURPOSE,"planId":plan["planId"],"planHash":plan["planHash"],
            "sourceBundleDigest":entry.source.origin.source_bundle_digest(),"sourceZipResource":entry.source.zip_resource,
            "loadInvocationDigest":entry.source.load_invocation_digest})).map_err(|_| unavailable())?;
        let value = json!({"approvalRef":format!("pack-run-{digest}"),"selectionDigest":digest,"expiresAt":plan["expiresAt"]});
        let mut selected = entry.selected.try_borrow_mut().map_err(|_| unavailable())?;
        if selected.as_ref().is_some_and(|prior| prior != &value) {
            return Err(unavailable());
        }
        *selected = Some(value.clone());
        Ok(value)
    }
    pub(crate) fn selection(&self, store: &DurableStore, plan: &Value) -> AppResult<Value> {
        self.prepared(store, plan)?
            .selected
            .try_borrow()
            .map_err(|_| unavailable())?
            .clone()
            .ok_or_else(unavailable)
    }
    pub(crate) fn manifest(
        &self,
        store: &DurableStore,
        plan: &Value,
        context: &Value,
        runtime_facts: &Value,
    ) -> AppResult<Value> {
        let entry = self.prepared(store, plan)?;
        check_expiry(plan)?;
        let selected = self.selection(store, plan)?;
        if context["contextId"] != plan["contextPins"][0]["contextId"]
            || context["contextDigest"] != plan["contextPins"][0]["contextDigest"]
            || context["environment"] != plan["contextPins"][0]["environment"]
            || context["projectId"] != plan["projectId"]
            || context["policyRevision"] != plan["policyRevision"]
            || context != &entry.source.context
        {
            return Err(unavailable());
        }
        crate::catalog_source::validate_source_facts(runtime_facts, context)?;
        let facts = crate::catalog_source::source_facts_pin(runtime_facts)?;
        let artifact: Sha256Digest = decode(&plan["steps"][0]["implementationDigest"])?;
        if facts != entry.source.initial_runtime_source_facts_digest
            || artifact != entry.source.initial_host_artifact_digest
            || runtime_facts["registryGeneration"]
                != entry.source.initial_registry_generation.as_str()
        {
            return Err(unavailable());
        }
        let metadata = PackRunMetadata {
            context: context.clone(),
            runtime_facts: runtime_facts.clone(),
            runtime_source_facts_digest: facts.clone(),
            host_artifact_digest: artifact,
            registry_generation: text(runtime_facts, "registryGeneration")?.into(),
        };
        let mut retained = entry.metadata.try_borrow_mut().map_err(|_| unavailable())?;
        if retained.as_ref().is_some_and(|prior| prior != &metadata) {
            return Err(unavailable());
        }
        if retained.is_none() {
            *retained = Some(metadata);
        }
        drop(retained);
        let plan_summary =
            crate::bootstrap::calibration_approval::pack_run_plan_manifest(plan, context)?;
        Ok(
            json!({"kind":MANIFEST_KIND,"purpose":PURPOSE,"selectionDigest":selected["selectionDigest"],
            "hostEpoch":context["environment"]["sessionEpoch"],"registryGeneration":runtime_facts["registryGeneration"],
            "runtimeSourceFactsDigest":facts,"programDigest":entry.source.program.program_digest(),
            "sourceBundleDigest":entry.source.origin.source_bundle_digest(),"sourceZipResource":entry.source.zip_resource,
            "sourceOrigin":{"operationId":entry.source.origin.operation(),"invocationId":entry.source.origin.original()["invocationId"],
                "invocationDigest":entry.source.load_invocation_digest,"frozenManifestDigest":entry.source.origin.frozen_manifest_digest()},
            "plan":plan_summary,"targetId":TARGET,"stepGuards":step_guards()}),
        )
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Retained approval identity, actual private route, completed delivery, publication result and current controls are distinct inputs"
    )]
    pub(crate) fn confirm(
        &self,
        store: &DurableStore,
        plan: &Value,
        manifest: &Value,
        route: PackRunHostRoute,
        completion: Arc<CompletedBootstrap>,
        publication_failure: Option<Arc<AppError>>,
        current: &dyn Fn() -> AppResult<()>,
    ) -> AppResult<()> {
        check_expiry(plan)?;
        self.check_prepared(store, plan, current)?;
        let entry = self.prepared(store, plan)?;
        let metadata = entry
            .metadata
            .try_borrow()
            .map_err(|_| unavailable())?
            .clone()
            .ok_or_else(unavailable)?;
        let expected = self.manifest(store, plan, &metadata.context, &metadata.runtime_facts)?;
        if manifest != &expected
            || route.context() != &metadata.context
            || !completion.delivered()
            || Instant::now() >= route.lease_expires()
        {
            return Err(unavailable());
        }
        current()?;
        let mut confirmed = entry
            .confirmed
            .try_borrow_mut()
            .map_err(|_| unavailable())?;
        if confirmed.is_some() {
            return Err(unavailable());
        }
        *confirmed = Some(Rc::new(ConfirmedPackRun {
            manifest: manifest.clone(),
            route,
            completion,
            publication_failure,
            cleanup_failure: RefCell::new(None),
        }));
        Ok(())
    }
    pub(crate) fn retire_expired(&self, shutdown: bool) -> AppResult<()> {
        let entries: Vec<_> = self
            .entries
            .try_borrow()
            .map_err(|_| unavailable())?
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut failure = None;
        for (key, entry) in entries {
            let expired = time::OffsetDateTime::parse(
                text(&entry.plan, "expiresAt")?,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| unavailable())?
                <= time::OffsetDateTime::now_utc();
            if !shutdown && !expired {
                continue;
            }
            if let Some(confirmed) = entry
                .confirmed
                .try_borrow()
                .map_err(|_| unavailable())?
                .as_ref()
                && let Err(cause) = confirmed.route.retire()
            {
                let cause = Arc::new(cause);
                let mut retained = confirmed
                    .cleanup_failure
                    .try_borrow_mut()
                    .map_err(|_| unavailable())?;
                if retained.is_none() {
                    *retained = Some(cause.clone());
                }
                if failure.is_none() {
                    failure = Some(cause);
                }
                continue;
            }
            self.entries
                .try_borrow_mut()
                .map_err(|_| unavailable())?
                .remove(&key);
        }
        match failure {
            Some(cause) => Err(retained_failure(&cause)),
            None => Ok(()),
        }
    }
    pub(crate) fn matches_plan(&self, plan: &Value) -> AppResult<bool> {
        Ok(self
            .entries
            .try_borrow()
            .map_err(|_| unavailable())?
            .values()
            .any(|entry| entry.plan == *plan))
    }
    pub(crate) fn handles_original(&self, original: &Value) -> AppResult<bool> {
        Ok(self
            .entries
            .try_borrow()
            .map_err(|_| unavailable())?
            .values()
            .any(|entry| original_matches_plan(&entry.plan, original)))
    }

    pub(crate) fn validate_capture_target(
        &self,
        request: &RequestContextWitness,
        authority: &LocalAuthority,
        original: &Value,
        scope: &WriteScope,
        target: &str,
    ) -> AppResult<()> {
        request.check_local().map_err(request_error)?;
        let entries = self.entries.try_borrow().map_err(|_| unavailable())?;
        let operation: OperationId = decode(&original["operationId"])?;
        let mut candidates = Vec::new();
        for entry in entries.values() {
            if original_matches_plan(&entry.plan, original)
                && serde_json::to_value(scope).is_ok_and(|value| value == entry.plan["scope"])
                && entry
                    .operation
                    .try_borrow()
                    .map_err(|_| unavailable())?
                    .as_ref()
                    == Some(&operation)
            {
                candidates.push(entry);
            }
        }
        let mut candidates = candidates.into_iter();
        let entry = candidates.next().ok_or_else(unavailable)?;
        if candidates.next().is_some()
            || request.method() != "plan.apply"
            || target != TARGET
            || scope.external_target_ids.len() != 1
            || scope.external_target_ids[0].as_str() != TARGET
            || original["context"]["principalRef"] != request.authenticated().principal().as_str()
        {
            return Err(unavailable());
        }
        let confirmed = entry
            .confirmed
            .try_borrow()
            .map_err(|_| unavailable())?
            .clone()
            .ok_or_else(unavailable)?;
        check_confirmation(&confirmed)?;
        if confirmed.route.context() != &original["context"] {
            return Err(unavailable());
        }
        check_expiry(&entry.plan)?;
        confirmed.route.check_current(request)?;
        authority.authorize_retained_apply(
            request.authenticated().principal(),
            &original["context"],
            &entry.plan,
        )
    }

    pub(crate) fn precondition(
        &self,
        store: &mut DurableStore,
        request: &RequestContextWitness,
        authority: &LocalAuthority,
        preflight: PackRunPreflight<'_>,
        condition: &Value,
    ) -> AppResult<Sha256Digest> {
        let frozen = preflight.plan["preconditions"]
            .as_array()
            .ok_or_else(unavailable)?;
        let index = frozen
            .iter()
            .position(|value| value == condition)
            .ok_or_else(unavailable)?;
        let conditions = frozen.iter().collect::<Vec<_>>();
        self.preconditions(store, request, authority, preflight, &conditions)?
            .get(index)
            .cloned()
            .ok_or_else(unavailable)
    }

    pub(crate) fn preconditions(
        &self,
        store: &mut DurableStore,
        request: &RequestContextWitness,
        authority: &LocalAuthority,
        preflight: PackRunPreflight<'_>,
        conditions: &[&Value],
    ) -> AppResult<Vec<Sha256Digest>> {
        let PackRunPreflight {
            plan,
            step,
            context,
        } = preflight;
        let entry = self.prepared(store, plan)?;
        let confirmed = entry
            .confirmed
            .try_borrow()
            .map_err(|_| unavailable())?
            .clone()
            .ok_or_else(unavailable)?;
        let metadata = entry
            .metadata
            .try_borrow()
            .map_err(|_| unavailable())?
            .clone()
            .ok_or_else(unavailable)?;
        let owner =
            NativeOwnerWitness::capture(store, request.budget().deadline()).map_err(storage)?;
        let frozen = plan["preconditions"].as_array().ok_or_else(unavailable)?;
        if conditions.len() != frozen.len()
            || conditions
                .iter()
                .zip(frozen)
                .any(|(actual, expected)| *actual != expected)
            || frozen != &entry.source.preconditions()
            || !plan["steps"]
                .as_array()
                .is_some_and(|steps| steps.iter().any(|frozen| frozen == step))
        {
            return Err(unavailable());
        }
        let current = |store: &DurableStore| {
            request.check_local().map_err(request_error)?;
            owner
                .check_project(store, &entry.source.selection.project_id)
                .map_err(storage)?;
            check_confirmation(&confirmed)?;
            check_expiry(plan)?;
            if request.method() != "plan.apply"
                || request.authenticated().principal() != owner.principal()
                || context != confirmed.route.context()
                || context["principalRef"] != owner.principal().as_str()
                || store
                    .project(&entry.source.selection.project_id)
                    .map_err(storage)?["revision"]
                    != plan["projectBaseRevision"]
                || !Rc::ptr_eq(&self.prepared(store, plan)?, &entry)
            {
                return Err(unavailable());
            }
            entry.source.origin.check_for_run(
                store,
                request,
                &owner,
                &entry.source.selection,
                authority,
            )?;
            authority.authorize_retained_scope(
                owner.principal(),
                &entry.source.selection.project_id,
                &entry.source.selection.context_id,
                &decode(&plan["policyRevision"])?,
                &plan["scope"],
            )?;
            authority.authorize_retained_scope(
                owner.principal(),
                &entry.source.selection.project_id,
                &entry.source.selection.context_id,
                &decode(&plan["policyRevision"])?,
                &context["scope"],
            )?;
            authority.authorize_retained_apply(owner.principal(), context, plan)?;
            confirmed.route.check_current(request)
        };
        require_dispatch_capability(PackRunAccess::Apply, || current(store))?;
        self.check_prepared(store, plan, &|| current(store))?;
        let mut observed = Vec::with_capacity(frozen.len());
        for (condition, (subject, blob)) in conditions.iter().zip(&entry.source.expected) {
            current(store)?;
            fields(condition, &["kind", "subject", "expected", "coverage"])?;
            if condition["kind"] != "resource_hash"
                || condition["subject"] != subject.as_str()
                || condition["coverage"] != "full_target"
                || condition["expected"] != blob.digest.as_str()
            {
                return Err(unavailable());
            }
            let bytes = store
                .read_blob_checked(blob, MAX_SOURCE_BYTES, || {
                    current(store).map_err(app_storage)
                })
                .map_err(storage)?;
            observed.push(raw_digest(&bytes));
        }
        let condition = conditions.last().ok_or_else(unavailable)?;
        fields(condition, &["kind", "subject", "expected", "coverage"])?;
        if condition["kind"] != "resource_hash"
            || condition["subject"] != TARGET
            || condition["coverage"] != "full_target"
            || condition["expected"] != entry.source.initial_target.digest.as_str()
        {
            return Err(unavailable());
        }
        let actual = confirmed
            .route
            .inspect_plan_targets_with_store(store, request, plan, &current)?;
        let image = crate::calibration_pack_observer::preflight_plan_image(
            &actual,
            context,
            &metadata.runtime_source_facts_digest,
            &metadata.host_artifact_digest,
            &metadata.registry_generation,
            &|| current(store),
        )?;
        // Application compares this actual digest with its current phase. Its
        // existing independently verified snapshot chain advances the expected
        // value after each step; the original absence is never synthesized.
        observed.push(raw_digest(&image.bytes));
        finish_native_observation(Ok(observed), current(store))
    }

    pub(crate) fn enter<'a>(
        &self,
        store: &DurableStore,
        request: &'a RequestContextWitness,
        authority: &'a LocalAuthority,
        operation: &OperationId,
        original: &Value,
        access: PackRunAccess,
    ) -> AppResult<Option<EnteredPackRun<'a>>> {
        request.check_local().map_err(request_error)?;
        let operation = store.operation(operation).map_err(storage)?;
        let plan = store
            .plan(&operation.plan_id, &operation.plan_hash)
            .map_err(storage)?;
        if !self.matches_plan(&plan)? {
            return Ok(None);
        }
        let entry = self.prepared(store, &plan)?;
        let confirmed = entry
            .confirmed
            .try_borrow()
            .map_err(|_| unavailable())?
            .clone()
            .ok_or_else(unavailable)?;
        let metadata = entry
            .metadata
            .try_borrow()
            .map_err(|_| unavailable())?
            .clone()
            .ok_or_else(unavailable)?;
        let owner =
            NativeOwnerWitness::capture(store, request.budget().deadline()).map_err(storage)?;
        let entered = EnteredPackRun {
            registry: self.clone(),
            entry,
            confirmed,
            metadata,
            request,
            authority,
            owner,
            operation,
            original: original.clone(),
            access,
        };
        let result = (|| {
            entered.check_local(store)?;
            self.check_prepared(store, entered.plan(), &|| entered.check_local(store))
        })();
        finish_native_observation(result, entered.check_local(store))?;
        // BeforeCapture validation is immutable and runs after this entered
        // retained capture. Bind its actual Store-selected operation now, so
        // another plan with the same commands cannot shadow this selection.
        // This local reservation creates neither a journal intent nor a fence.
        if access == PackRunAccess::Apply {
            let mut reserved = entered
                .entry
                .operation
                .try_borrow_mut()
                .map_err(|_| unavailable())?;
            if reserved
                .as_ref()
                .is_some_and(|id| id != &entered.operation.operation_id)
            {
                return Err(unavailable());
            }
            *reserved = Some(entered.operation.operation_id.clone());
        } else if entered
            .entry
            .operation
            .try_borrow()
            .map_err(|_| unavailable())?
            .as_ref()
            != Some(&entered.operation.operation_id)
        {
            return Err(unavailable());
        }
        entered.check_local(store)?;
        Ok(Some(entered))
    }
}

pub(crate) struct PackRunPreflight<'a> {
    pub(crate) plan: &'a Value,
    pub(crate) step: &'a Value,
    pub(crate) context: &'a Value,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackRunAccess {
    Apply,
    Observe,
    Cancel,
}

fn observation_method_allowed(
    method: &str,
    state: &OperationState,
    reconciliation_required: bool,
    cancellation_requested: bool,
) -> bool {
    match method {
        // Planning consumes a completed run; it cannot poll, finish or continue
        // an interrupted operation through this readonly source relationship.
        "plan.create" | "action.plan" | "pack.build" => {
            matches!(state, OperationState::Succeeded)
                && !reconciliation_required
                && !cancellation_requested
        }
        "plan.apply" | "operation.reconcile" | "operation.get" | "operation.cancel" => true,
        _ => false,
    }
}

type FreshPackRunPrepare<'a> = dyn FnMut(&PackRunHostRoute, &RequestContextWitness, &Value, &mut DurableStore) -> AppResult<()>
    + 'a;

/// A current request borrow, never retained in the approval index or rebuilt
/// from a public source DTO. Observation grants cannot dispatch a new step.
pub(crate) struct EnteredPackRun<'a> {
    registry: PackRunRegistry,
    entry: Rc<PreparedPackRun>,
    confirmed: Rc<ConfirmedPackRun>,
    metadata: PackRunMetadata,
    request: &'a RequestContextWitness,
    authority: &'a LocalAuthority,
    owner: NativeOwnerWitness,
    operation: OperationRecord,
    original: Value,
    access: PackRunAccess,
}
impl EnteredPackRun<'_> {
    pub(crate) fn route(&self) -> &PackRunHostRoute {
        &self.confirmed.route
    }
    pub(crate) fn request(&self) -> &RequestContextWitness {
        self.request
    }
    pub(crate) fn original(&self) -> &Value {
        &self.original
    }
    pub(crate) fn operation(&self) -> &OperationRecord {
        &self.operation
    }
    pub(crate) fn plan(&self) -> &Value {
        &self.entry.plan
    }
    pub(crate) fn program(&self) -> &CalibrationPackProgram {
        &self.entry.source.program
    }
    pub(crate) fn program_digest(&self) -> &Sha256Digest {
        self.program().program_digest()
    }
    pub(crate) fn source_bundle_digest(&self) -> &Sha256Digest {
        self.entry.source.origin.source_bundle_digest()
    }
    pub(crate) fn source_zip_resource(&self) -> &Value {
        &self.entry.source.zip_resource
    }
    pub(crate) fn load_invocation_digest(&self) -> &Sha256Digest {
        &self.entry.source.load_invocation_digest
    }
    pub(crate) fn host_artifact_digest(&self) -> &Sha256Digest {
        &self.metadata.host_artifact_digest
    }
    pub(crate) fn runtime_source_facts_digest(&self) -> &Sha256Digest {
        &self.metadata.runtime_source_facts_digest
    }
    pub(crate) fn registry_generation(&self) -> &str {
        &self.metadata.registry_generation
    }

    pub(crate) fn check_local(&self, store: &DurableStore) -> AppResult<()> {
        self.request.check_local().map_err(request_error)?;
        let source = &self.entry.source;
        self.owner
            .check_project(store, &source.selection.project_id)
            .map_err(storage)?;
        let current = store
            .operation(&self.operation.operation_id)
            .map_err(storage)?;
        let plan = self.plan();
        let context = self.route().context();
        let principal = self.request.authenticated().principal();
        check_confirmation(&self.confirmed)?;
        if !std::ptr::eq(store, source.store)
            || store.data_root() != source.store_root
            || !Rc::ptr_eq(&self.registry.prepared(store, plan)?, &self.entry)
            || self
                .entry
                .confirmed
                .try_borrow()
                .map_err(|_| unavailable())?
                .as_ref()
                .is_none_or(|v| !Rc::ptr_eq(v, &self.confirmed))
            || self
                .entry
                .metadata
                .try_borrow()
                .map_err(|_| unavailable())?
                .as_ref()
                != Some(&self.metadata)
            || current.operation_id == *source.origin.operation()
            || current.project_id != source.selection.project_id
            || current.plan_id != self.operation.plan_id
            || current.plan_hash != self.operation.plan_hash
            || current.scope != self.operation.scope
            || current.context_id != source.selection.context_id
            || &current.principal != principal
            || self.owner.principal() != principal
            || context != &self.metadata.context
            || context["principalRef"] != principal.as_str()
            || context["projectId"] != current.project_id.as_str()
            || serde_json::to_value(&current.scope).map_err(|_| unavailable())? != plan["scope"]
            || context["contextDigest"] != plan["contextPins"][0]["contextDigest"]
            || context["environment"] != plan["contextPins"][0]["environment"]
            || context["policyRevision"] != plan["policyRevision"]
            || store.project(&current.project_id).map_err(storage)?["revision"]
                != plan["projectBaseRevision"]
            || self
                .entry
                .operation
                .try_borrow()
                .map_err(|_| unavailable())?
                .as_ref()
                .is_some_and(|id| id != &current.operation_id)
        {
            return Err(unavailable());
        }
        self.check_original(&self.original)?;
        source.origin.check_for_run(
            store,
            self.request,
            &self.owner,
            &source.selection,
            self.authority,
        )?;
        self.route().check_current(self.request)?;
        self.authority.authorize_retained_scope(
            principal,
            &current.project_id,
            &current.context_id,
            &decode(&plan["policyRevision"])?,
            &plan["scope"],
        )?;
        self.authority.authorize_retained_scope(
            principal,
            &current.project_id,
            &current.context_id,
            &decode(&plan["policyRevision"])?,
            &context["scope"],
        )?;
        match self.access {
            PackRunAccess::Apply => {
                if self.request.method() != "plan.apply" {
                    return Err(unavailable());
                }
                check_expiry(plan)?;
                self.authority
                    .authorize_retained_apply(principal, context, plan)?;
                require_dispatch_capability(self.access, || {
                    self.request.check_local().map_err(request_error)?;
                    self.owner.check().map_err(storage)
                })?;
            }
            PackRunAccess::Observe => {
                if !observation_method_allowed(
                    self.request.method(),
                    &current.state,
                    current.reconciliation_required,
                    current.cancellation_requested,
                ) {
                    return Err(unavailable());
                }
                self.authority.clone().authorize_operation(
                    principal,
                    &current,
                    Access::ObserveOperation,
                )?;
            }
            PackRunAccess::Cancel => {
                if self.request.method() != "operation.cancel" {
                    return Err(unavailable());
                }
                self.authority
                    .clone()
                    .authorize_operation(principal, &current, Access::Cancel)?;
            }
        }
        self.request.check_local().map_err(request_error)?;
        self.owner.check().map_err(storage)
    }

    fn check_original(&self, original: &Value) -> AppResult<()> {
        if original != &self.original
            || original["operationId"] != self.operation.operation_id.as_str()
            || original["context"] != *self.route().context()
            || !original_matches_plan(self.plan(), original)
        {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(crate) fn verify_claim(&self, store: &DurableStore, original: &Value) -> AppResult<()> {
        let result = (|| {
            self.check_local(store)?;
            self.check_original(original)?;
            if self
                .entry
                .operation
                .try_borrow()
                .map_err(|_| unavailable())?
                .as_ref()
                != Some(&self.operation.operation_id)
            {
                return Err(unavailable());
            }
            self.read_original(store, &decode(&original["stepId"])?, Some(original))?;
            Ok(())
        })();
        finish_native_observation(result, self.check_local(store))
    }

    fn read_original(
        &self,
        store: &DurableStore,
        step: &StepId,
        expected: Option<&Value>,
    ) -> AppResult<Value> {
        let current = store
            .operation(&self.operation.operation_id)
            .map_err(storage)?;
        let retained = current
            .steps
            .iter()
            .find(|row| &row.step_id == step)
            .ok_or_else(unavailable)?;
        if retained.dispatch == DispatchEvidence::NotSent {
            return Err(unavailable());
        }
        let value = store
            .stored_invocation_checked(&current.operation_id, step, 64 * 1024, || {
                self.check_local(store).map_err(app_storage)
            })
            .map_err(storage)?;
        let blob = store
            .stored_invocation_blob(&current.operation_id, step)
            .map_err(storage)?;
        let bytes = encode_json(&value).map_err(|_| unavailable())?;
        if retained.invocation_digest.as_ref() != Some(&blob.digest)
            || raw_digest(&bytes) != blob.digest
            || bytes.len() as u64 != blob.byte_length
            || value["operationId"] != current.operation_id.as_str()
            || value["stepId"] != step.as_str()
            || value["context"] != *self.route().context()
            || value["invocationId"].as_str()
                != retained.invocation_id.as_ref().map(|id| id.as_str())
            || !original_matches_plan(self.plan(), &value)
            || expected.is_some_and(|expected| expected != &value)
        {
            return Err(unavailable());
        }
        Ok(value)
    }

    pub(crate) fn ordered_originals(&self, store: &DurableStore) -> AppResult<Vec<Value>> {
        self.verify_claim(store, &self.original)?;
        let mut originals = Vec::with_capacity(3);
        for id in STEP_IDS {
            originals.push(self.read_original(
                store,
                &StepId::new(id).map_err(|_| unavailable())?,
                None,
            )?);
        }
        self.check_local(store)?;
        Ok(originals)
    }

    pub(crate) fn persist_intent(
        &self,
        store: &mut DurableStore,
        step: &StepId,
        original: &Value,
        resolution: Option<&BlobRef>,
        fresh_prepare: &mut FreshPackRunPrepare<'_>,
    ) -> AppResult<StepRecord> {
        let result = (|| {
            self.check_local(store)?;
            self.check_original(original)?;
            if self.access != PackRunAccess::Apply
                || resolution.is_some()
                || original["stepId"] != step.as_str()
            {
                return Err(unavailable());
            }
            finish_native_observation(
                fresh_prepare(self.route(), self.request, original, store),
                self.check_local(store),
            )?;
            for (_, blob) in &self.entry.source.expected {
                store
                    .pin_operation_artifact(&self.operation.operation_id, blob)
                    .map_err(storage)?;
            }
            store
                .pin_operation_artifact(
                    &self.operation.operation_id,
                    &self.entry.source.initial_target,
                )
                .map_err(storage)?;
            let manifest = store
                .put_blob(&canonical_bytes(&self.confirmed.manifest).map_err(|_| unavailable())?)
                .map_err(storage)?;
            store
                .pin_operation_artifact(&self.operation.operation_id, &manifest)
                .map_err(storage)?;
            let witness = self.confirmed.completion.witness();
            let receipt = json!({"format":"mmmm.native.pack-run-approval-evidence/1","operationId":self.operation.operation_id,
                "planId":self.operation.plan_id,"planHash":self.operation.plan_hash,"stepId":step,
                "invocationId":original["invocationId"],"invocationDigest":canonical_digest(original).map_err(|_| unavailable())?,
                "manifestSha256":manifest.digest,"selectionDigest":self.confirmed.manifest["selectionDigest"],
                "originalOfferDigest":witness.offer_digest(),"nonce":witness.nonce(),"nativeDeliveryObserved":self.confirmed.completion.delivered()});
            let receipt = store
                .put_blob(&canonical_bytes(&receipt).map_err(|_| unavailable())?)
                .map_err(storage)?;
            store
                .append_operation_evidence(&self.operation.operation_id, &receipt)
                .map_err(storage)?;
            self.check_local(store)?;
            let mut claim = self
                .entry
                .operation
                .try_borrow_mut()
                .map_err(|_| unavailable())?;
            if claim
                .as_ref()
                .is_some_and(|id| id != &self.operation.operation_id)
            {
                return Err(unavailable());
            }
            *claim = Some(self.operation.operation_id.clone());
            drop(claim);
            // The journal transaction enforces the frozen route/arguments,
            // dependencies, one durable Invocation per step, and normal fences.
            store
                .dispatch_intent(&self.operation.operation_id, step, original)
                .map_err(storage)
        })();
        match result {
            Ok(committed) => Ok(committed),
            Err(primary) => finish_native_observation(Err(primary), self.check_local(store)),
        }
    }
}

fn step_guards() -> Value {
    json!({"pack-init-objective":{"kind":"initial_absence"},
    "pack-seed-marker":{"kind":"actual_previous_after","previousStepId":"pack-init-objective"},
    "pack-entry":{"kind":"actual_previous_after","previousStepId":"pack-seed-marker"}})
}

fn validate_plan(plan: &Value) -> AppResult<()> {
    let program = CalibrationPackProgram::java_26_3().map_err(|_| unavailable())?;
    let commands = [
        &program.initialization_commands()[0],
        &program.initialization_commands()[1],
        &program.invocation_command().to_owned(),
    ];
    let steps = plan["steps"]
        .as_array()
        .filter(|steps| steps.len() == 3)
        .ok_or_else(unavailable)?;
    for (index, step) in steps.iter().enumerate() {
        if step["stepId"] != STEP_IDS[index]
            || step["actionId"] != ACTION
            || step["arguments"] != json!({"command":commands[index]})
            || step["resourcesRead"] != json!([TARGET])
            || step["resourcesWritten"] != json!([TARGET])
            || step["completion"] != "synchronous"
            || step["recovery"] != "none"
            || step["verificationRequirement"] != "independent_readback"
            || step["dependsOn"]
                != if index == 0 {
                    json!([])
                } else {
                    json!([STEP_IDS[index - 1]])
                }
        {
            return Err(unavailable());
        }
    }
    let scope: WriteScope = decode(&plan["scope"])?;
    scope.validate().map_err(storage)?;
    if scope.project_id.as_str() != text(plan, "projectId")?
        || scope.external_target_ids.len() != 1
        || scope.external_target_ids[0].as_str() != TARGET
        || !scope.resource_ids.is_empty()
        || !scope.object_ids.is_empty()
        || !scope.regions.is_empty()
    {
        return Err(unavailable());
    }
    if plan["contextPins"]
        .as_array()
        .is_none_or(|pins| pins.len() != 1)
        || steps.iter().any(|step| {
            step["contextId"] != plan["contextPins"][0]["contextId"]
                || step["implementationDigest"] != steps[0]["implementationDigest"]
                || step["bindingId"] != steps[0]["bindingId"]
                || step["actionDigest"] != steps[0]["actionDigest"]
                || !matches!(step["effect"].as_str(), Some("write" | "unknown"))
                || step["resultBindings"]
                    .as_array()
                    .is_none_or(|values| !values.is_empty())
        })
    {
        return Err(unavailable());
    }
    Ok(())
}

fn original_matches_plan(plan: &Value, original: &Value) -> bool {
    let Some(step) = plan["steps"].as_array().and_then(|steps| {
        steps
            .iter()
            .find(|step| step["stepId"] == original["stepId"])
    }) else {
        return false;
    };
    original["actionId"] == ACTION
        && original["context"]["projectId"] == plan["projectId"]
        && original["context"]["contextId"] == plan["contextPins"][0]["contextId"]
        && original["contextDigest"] == plan["contextPins"][0]["contextDigest"]
        && original["context"]["contextDigest"] == original["contextDigest"]
        && original["context"]["environment"] == plan["contextPins"][0]["environment"]
        && original["context"]["policyRevision"] == plan["policyRevision"]
        && canonical_digest(&original["arguments"])
            .is_ok_and(|digest| original["argumentsDigest"] == digest.as_str())
        && [
            "bindingId",
            "actionId",
            "actionContractVersion",
            "actionDigest",
            "implementationDigest",
            "arguments",
        ]
        .iter()
        .all(|field| step[*field] == original[*field])
}

fn check_expiry(plan: &Value) -> AppResult<()> {
    let expires = time::OffsetDateTime::parse(
        text(plan, "expiresAt")?,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| unavailable())?;
    if time::OffsetDateTime::now_utc() >= expires {
        return Err(unavailable());
    }
    Ok(())
}
fn check_confirmation(confirmed: &ConfirmedPackRun) -> AppResult<()> {
    if !confirmed.completion.delivered() {
        return Err(unavailable());
    }
    if let Some(cause) = &confirmed.publication_failure {
        return Err(retained_failure(cause));
    }
    if let Some(cause) = confirmed
        .cleanup_failure
        .try_borrow()
        .map_err(|_| unavailable())?
        .as_ref()
    {
        return Err(retained_failure(cause));
    }
    Ok(())
}
#[derive(Debug)]
struct RetainedPackRunFailure(Arc<AppError>);
impl std::fmt::Display for RetainedPackRunFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("Original PACK run publication or retirement failure is retained")
    }
}
impl std::error::Error for RetainedPackRunFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
fn retained_failure(cause: &Arc<AppError>) -> AppError {
    AppError::caused_by(
        cause.code,
        cause.message,
        RetainedPackRunFailure(cause.clone()),
    )
}
fn request_error(cause: crate::service::ServiceError) -> AppError {
    AppError::caused_by(cause.code, cause.message, cause)
}

fn fields(value: &Value, keys: &[&str]) -> AppResult<()> {
    let object = value.as_object().ok_or_else(unavailable)?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(unavailable());
    }
    Ok(())
}
fn hex_bytes(value: &str) -> AppResult<Vec<u8>> {
    if value.is_empty()
        || value.len() > 128 * 1024
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(unavailable());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            Ok((digit(pair[0]) << 4) | digit(pair[1]))
        })
        .collect()
}
fn text<'a>(value: &'a Value, key: &str) -> AppResult<&'a str> {
    value[key].as_str().ok_or_else(unavailable)
}
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> AppResult<T> {
    serde_json::from_value(value.clone()).map_err(|_| unavailable())
}
fn unavailable() -> AppError {
    AppError::new(
        "PACK_CALIBRATION_UNAVAILABLE",
        "The exact actual PACK run relationship is unavailable",
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackRunDispatchGap {
    OriginalCallsiteBodyUnproven,
}

impl std::fmt::Display for PackRunDispatchGap {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OriginalCallsiteBodyUnproven => {
                out.write_str("pack_original_callsite_body_unproven")
            }
        }
    }
}

impl std::error::Error for PackRunDispatchGap {}

/// The native BEGIN gate currently cannot prove the final ordinary callsite
/// bodies. Reject the whole Apply before init/seed can write; load-only plan
/// preparation and current observation/cancellation gain no execution claim.
/// Current request/authority failures retain priority over this known gap.
fn require_dispatch_capability(
    access: PackRunAccess,
    current: impl FnOnce() -> AppResult<()>,
) -> AppResult<()> {
    current()?;
    if access == PackRunAccess::Apply {
        return Err(AppError::caused_by(
            "CAPABILITY_UNAVAILABLE",
            "Actual PACK execution requires an implemented ordinary callsite body finality issuer",
            PackRunDispatchGap::OriginalCallsiteBodyUnproven,
        ));
    }
    Ok(())
}

fn storage(cause: StorageError) -> AppError {
    AppError::storage("PACK_CALIBRATION_UNAVAILABLE", cause)
}
fn app_storage(cause: AppError) -> StorageError {
    StorageError::Io(std::io::Error::other(cause))
}

/// The PACK root is fixed. Archive cancellation is only a transport for the
/// original request checkpoint; retain its first typed cause and any archive
/// error caused while unwinding that cancellation.
fn read_pack_source_zip(
    bytes: &[u8],
    limits: ArchiveLimits,
    mut current: impl FnMut() -> AppResult<()>,
) -> AppResult<BTreeMap<String, Vec<u8>>> {
    let mut control_failure = None;
    let archive = read_zip_with_required_root(bytes, limits, "pack.mcmeta", || {
        if control_failure.is_some() {
            return true;
        }
        match current() {
            Ok(()) => false,
            Err(cause) => {
                control_failure = Some(cause);
                true
            }
        }
    })
    .map_err(|cause| {
        AppError::caused_by(
            "PACK_SOURCE_UNAVAILABLE",
            "The exact retained PACK source ZIP could not be read",
            cause,
        )
    });
    match (archive, control_failure) {
        (Ok(entries), None) => Ok(entries),
        (Err(cause), None) | (Ok(_), Some(cause)) => Err(cause),
        (Err(archive), Some(primary)) => Err(AppError::caused_by(
            primary.code,
            primary.message,
            StorageError::CalibrationCheckpointFailure {
                primary: Box::new(app_storage(primary)),
                checkpoint: Box::new(app_storage(archive)),
            },
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planning_observation_requires_success_without_reconciliation_or_cancellation() {
        // Access policy only: these values issue no request, Store, origin,
        // approval, route or private completed-run source capability.
        for method in ["plan.create", "action.plan", "pack.build"] {
            assert!(observation_method_allowed(
                method,
                &OperationState::Succeeded,
                false,
                false,
            ));
            for state in [OperationState::Queued, OperationState::Running] {
                for reconciliation in [false, true] {
                    for cancellation in [false, true] {
                        assert!(!observation_method_allowed(
                            method,
                            &state,
                            reconciliation,
                            cancellation,
                        ));
                    }
                }
            }
            for (reconciliation, cancellation) in [(true, false), (false, true), (true, true)] {
                assert!(!observation_method_allowed(
                    method,
                    &OperationState::Succeeded,
                    reconciliation,
                    cancellation,
                ));
            }
        }
        for method in [
            "plan.apply",
            "operation.reconcile",
            "operation.get",
            "operation.cancel",
        ] {
            for state in [OperationState::Queued, OperationState::Succeeded] {
                for reconciliation in [false, true] {
                    for cancellation in [false, true] {
                        assert!(observation_method_allowed(
                            method,
                            &state,
                            reconciliation,
                            cancellation,
                        ));
                    }
                }
            }
        }
        for method in [
            "",
            "Plan.create",
            "plan.create ",
            "action.plan.apply",
            "pack.build/1",
            "project.get",
        ] {
            assert!(!observation_method_allowed(
                method,
                &OperationState::Succeeded,
                false,
                false,
            ));
        }
    }

    #[test]
    fn closed_pack_zip_read_retains_original_checkpoint_and_archive_cancellation() {
        #[derive(Debug)]
        struct CurrentFailure(Arc<()>);
        impl std::fmt::Display for CurrentFailure {
            fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.write_str("original ZIP read checkpoint")
            }
        }
        impl std::error::Error for CurrentFailure {}

        let program =
            CalibrationPackProgram::java_26_3().unwrap_or_else(|_| panic!("fixed PACK recipe"));
        // Reuse the fixed compiler recipe as a pure codec input, not a live
        // request or a source/approval authority fixture.
        let zip = write_zip_with_required_root_and_cancel(
            program.source_entries(),
            ArchiveLimits::default(),
            "pack.mcmeta",
            || false,
        )
        .unwrap_or_else(|_| panic!("fixed PACK ZIP fixture"));
        let mut checkpoints = 0;
        let entries = read_pack_source_zip(&zip, ArchiveLimits::default(), || {
            checkpoints += 1;
            Ok(())
        })
        .unwrap_or_else(|_| panic!("actual ZIP read checkpoints"));
        assert_eq!(entries, *program.source_entries());
        assert!(checkpoints > 1);

        let identity = Arc::new(());
        let mut checkpoints = 0;
        let failed = read_pack_source_zip(&zip, ArchiveLimits::default(), || {
            checkpoints += 1;
            if checkpoints == 1 {
                return Ok(());
            }
            Err(AppError::caused_by(
                "CANCELLED",
                "original ZIP checkpoint cancelled",
                CurrentFailure(identity.clone()),
            ))
        })
        .expect_err("the original request cancellation must stop ZIP verification");
        assert_eq!(checkpoints, 2);
        assert_eq!(failed.code, "CANCELLED");
        assert_eq!(failed.message, "original ZIP checkpoint cancelled");
        let combined = std::error::Error::source(&failed)
            .and_then(|cause| cause.downcast_ref::<StorageError>())
            .unwrap_or_else(|| panic!("both failures must be retained"));
        let StorageError::CalibrationCheckpointFailure {
            primary,
            checkpoint,
        } = combined
        else {
            panic!("missing original checkpoint and archive failure pair");
        };
        let StorageError::Io(primary) = primary.as_ref() else {
            panic!("missing original AppError");
        };
        let primary = primary
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<AppError>())
            .unwrap_or_else(|| panic!("missing original typed AppError"));
        let original = std::error::Error::source(primary)
            .and_then(|cause| cause.downcast_ref::<CurrentFailure>())
            .unwrap_or_else(|| panic!("missing original checkpoint identity"));
        assert!(Arc::ptr_eq(&original.0, &identity));
        let StorageError::Io(checkpoint) = checkpoint.as_ref() else {
            panic!("missing archive AppError");
        };
        let checkpoint = checkpoint
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<AppError>())
            .unwrap_or_else(|| panic!("missing archive checkpoint"));
        let archive = std::error::Error::source(checkpoint)
            .and_then(|cause| cause.downcast_ref::<mmmm_exchange::ExchangeError>())
            .unwrap_or_else(|| panic!("missing actual archive cancellation"));
        assert_eq!(archive.code, "CANCELLED");
    }

    #[test]
    fn closed_pack_zip_read_preserves_archive_failure_without_a_control_failure() {
        let mut checkpoints = 0;
        let failed = read_pack_source_zip(b"invalid ZIP", ArchiveLimits::default(), || {
            checkpoints += 1;
            Ok(())
        })
        .expect_err("malformed archive must remain rejected");
        assert!(checkpoints > 0);
        assert_eq!(failed.code, "PACK_SOURCE_UNAVAILABLE");
        assert!(
            std::error::Error::source(&failed)
                .and_then(|cause| cause.downcast_ref::<mmmm_exchange::ExchangeError>())
                .is_some()
        );
    }

    #[test]
    fn known_dispatch_gap_stops_apply_before_downstream_work_but_not_read_roles() {
        for access in [
            PackRunAccess::Apply,
            PackRunAccess::Observe,
            PackRunAccess::Cancel,
        ] {
            let current_checks = std::cell::Cell::new(0);
            let downstream = std::cell::Cell::new(false);
            let result = (|| -> AppResult<()> {
                require_dispatch_capability(access, || {
                    current_checks.set(current_checks.get() + 1);
                    Ok(())
                })?;
                // Production Apply uses this gate before fresh target work and
                // before entered capture/reservation/journal intent paths.
                downstream.set(true);
                Ok(())
            })();
            assert_eq!(current_checks.get(), 1);
            match access {
                PackRunAccess::Apply => {
                    let cause = result.expect_err("known native gap must stop Apply");
                    assert_eq!(cause.code, "CAPABILITY_UNAVAILABLE");
                    assert_eq!(
                        std::error::Error::source(&cause)
                            .and_then(|source| source.downcast_ref::<PackRunDispatchGap>()),
                        Some(&PackRunDispatchGap::OriginalCallsiteBodyUnproven)
                    );
                    assert!(!downstream.get());
                }
                PackRunAccess::Observe | PackRunAccess::Cancel => {
                    assert!(result.is_ok());
                    assert!(downstream.get());
                }
            }
        }
    }

    #[test]
    fn prewrite_gap_preserves_original_current_failure_and_skips_downstream_work() {
        #[derive(Debug)]
        struct CurrentFailure(Arc<()>);
        impl std::fmt::Display for CurrentFailure {
            fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.write_str("original current checkpoint failure")
            }
        }
        impl std::error::Error for CurrentFailure {}

        for code in [
            "CANCELLED",
            "TIME_BUDGET_EXCEEDED",
            "PERMISSION_REQUIRED",
            "STALE_CONTEXT",
        ] {
            let identity = Arc::new(());
            let downstream = std::cell::Cell::new(false);
            let result = (|| -> AppResult<()> {
                require_dispatch_capability(PackRunAccess::Apply, || {
                    Err(AppError::caused_by(
                        code,
                        "original current checkpoint",
                        CurrentFailure(identity.clone()),
                    ))
                })?;
                downstream.set(true);
                Ok(())
            })();
            let cause = result.expect_err("original current failure must stop Apply");
            assert_eq!(cause.code, code);
            assert_eq!(cause.message, "original current checkpoint");
            let original = std::error::Error::source(&cause)
                .and_then(|source| source.downcast_ref::<CurrentFailure>())
                .unwrap_or_else(|| panic!("original typed checkpoint cause must be retained"));
            assert!(Arc::ptr_eq(&original.0, &identity));
            assert!(!downstream.get());
        }
    }

    // These exercise only the closed codec. A valid packet below creates no
    // owner, host receipt, prepared source or entered execution authority.
    fn load_packet(
        program: &CalibrationPackProgram,
        bundle: &Sha256Digest,
        load: &Sha256Digest,
    ) -> Value {
        let functions = program.function_ids().iter().map(|id| {
            let (namespace,path) = id.split_once(':').unwrap();
            let source = &program.source_entries()[&format!("data/{namespace}/function/{path}.mcfunction")];
            json!({"functionId":id,"resourceId":format!("{namespace}:function/{path}.mcfunction"),"rawSha256":raw_digest(source)})
        }).collect::<Vec<_>>();
        let payload = json!({"format":"mmmm.native.pack-run-readiness/1","loadOnly":true,"sourceKind":"pack_case",
            "loadInvocationDigest":load,"sourceBundleDigest":bundle,"logicalProgramDigest":program.program_digest(),
            "selectedFunctionSourceDigest":canonical_digest(&json!(functions)).unwrap(),"functions":functions});
        encode_packet(&payload)
    }
    fn encode_packet(payload: &Value) -> Value {
        let payload = encode_json(payload).unwrap();
        let mut bytes = b"MMMMPR01".to_vec();
        bytes.extend([47, 1]);
        bytes.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());
        bytes.extend(payload);
        json!({"format":"mmmm.native.pack-run-readiness/1","receiptBytesHex":bytes.iter().map(|byte|format!("{byte:02x}")).collect::<String>(),"targetImages":null})
    }

    #[test]
    fn load_receipt_codec_requires_exact_original_pins_and_actual_function_rows() {
        let program = CalibrationPackProgram::java_26_3().unwrap();
        let bundle = raw_digest(b"bundle");
        let load = raw_digest(b"load");
        let packet = load_packet(&program, &bundle, &load);
        assert!(verify_load_readiness(&packet, &program, &bundle, &load).is_ok());
        assert!(
            verify_load_readiness(&packet, &program, &bundle, &raw_digest(b"other invocation"))
                .is_err()
        );
        let bytes = hex_bytes(packet["receiptBytesHex"].as_str().unwrap()).unwrap();
        let original: Value = serde_json::from_slice(&bytes[12..]).unwrap();
        for key in [
            "loadOnly",
            "sourceKind",
            "logicalProgramDigest",
            "selectedFunctionSourceDigest",
        ] {
            let mut changed = original.clone();
            changed[key] = json!("unproven");
            assert!(
                verify_load_readiness(&encode_packet(&changed), &program, &bundle, &load).is_err()
            );
        }
        let mut changed = original.clone();
        changed["functions"][0]["rawSha256"] = json!(raw_digest(b"different raw bytes"));
        changed["selectedFunctionSourceDigest"] =
            json!(canonical_digest(&changed["functions"]).unwrap());
        assert!(verify_load_readiness(&encode_packet(&changed), &program, &bundle, &load).is_err());
        let mut extra = packet;
        extra["futureInvocation"] = json!({});
        assert!(verify_load_readiness(&extra, &program, &bundle, &load).is_err());
    }
}

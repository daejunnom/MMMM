//! 봉인된 calibration pack의 최초 설치를 기존 계획/작업 원장에 연결한다.
//! 이 모듈의 보호된 source와 실제 ADMIN 완료 자료만 private route를 선택한다.
//! public locator, digest, imported JSON은 승인이나 source 읽기 권한이 아니다.

use crate::{
    authority::LocalAuthority, bootstrap::NativeWorkspacePermit, host::BootstrapHostRoute,
    observer::finish_native_observation, peer_management::CompletedBootstrap,
    service::RequestContextWitness, workspace_bootstrap::NativeOwnerWitness,
};
use mmmm_application::{
    Access, AppError, AppResult, AuthorityPort, BeforeCapture, BeforeImage, SetupSelection,
};
use mmmm_compiler::{
    calibration::{CalibrationPackProgram, CalibrationSourceKind},
    calibration_dispatch::CalibrationDispatchPlan,
};
use mmmm_contracts::{
    OperationId, PlanId, PrincipalId, ProjectId, Sha256Digest, StepId, TargetId, canonical_bytes,
    canonical_digest, raw_digest, verify_projected_digest,
};
use mmmm_runtime::storage::{
    BlobRef, DispatchEvidence, DurableStore, OperationRecord, StorageError, WriteScope,
    artifact::{ResourceOwner, register_resource_with_diagnostics},
};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    rc::Rc,
    sync::Arc,
};

pub(crate) const ACTION: &str = "mmmm:calibration_bootstrap_execute";
pub(crate) const PURPOSE: &str = "numeric_calibration_bootstrap/1";
pub(crate) const MANIFEST_KIND: &str = "native_calibration_bootstrap_approval/1";
pub(crate) const PACK_TARGET: &str = "calibration-bootstrap-pack";
pub(crate) const PACK_PURPOSE: &str = "pack_calibration_bootstrap/1";
pub(crate) const PACK_MANIFEST_KIND: &str = "native_pack_calibration_bootstrap_approval/1";
pub(crate) const PACK_ACTION: &str = "mmmm:command_execute";
pub(crate) const PACK_COMMAND: &str = "function mmmm_calibration:pack/entry";
pub(crate) const PACK_CASE_TARGET: &str = "calibration-pack-case-pack";
pub(crate) fn kind_for_purpose(value: &str) -> Option<CalibrationSourceKind> {
    match value {
        PURPOSE => Some(CalibrationSourceKind::Numeric47),
        PACK_PURPOSE => Some(CalibrationSourceKind::PackCase),
        _ => None,
    }
}
pub(crate) fn is_purpose(value: &str) -> bool {
    kind_for_purpose(value).is_some()
}
pub(crate) fn purpose_for_kind(kind: CalibrationSourceKind) -> &'static str {
    match kind {
        CalibrationSourceKind::Numeric47 => PURPOSE,
        CalibrationSourceKind::PackCase => PACK_PURPOSE,
    }
}
pub(crate) fn manifest_kind_for_kind(kind: CalibrationSourceKind) -> &'static str {
    match kind {
        CalibrationSourceKind::Numeric47 => MANIFEST_KIND,
        CalibrationSourceKind::PackCase => PACK_MANIFEST_KIND,
    }
}
pub(crate) fn action_for_kind(kind: CalibrationSourceKind) -> &'static str {
    match kind {
        CalibrationSourceKind::Numeric47 => ACTION,
        CalibrationSourceKind::PackCase => PACK_ACTION,
    }
}
pub(crate) fn pack_target_for_kind(kind: CalibrationSourceKind) -> &'static str {
    match kind {
        CalibrationSourceKind::Numeric47 => PACK_TARGET,
        CalibrationSourceKind::PackCase => PACK_CASE_TARGET,
    }
}
pub(crate) fn is_candidate(original: &Value) -> bool {
    original["actionId"] == ACTION
        || (original["actionId"] == PACK_ACTION
            && original["arguments"] == json!({"command":PACK_COMMAND}))
}
const MAX_ENTRIES: usize = 8;
const MAX_BUNDLE_BYTES: u64 = 3 * 1024 * 1024;
const MAX_IMAGE_BYTES: usize = 1024 * 1024;
const MAX_ORIGIN_INVOCATION_BYTES: u64 = 64 * 1024;

#[path = "calibration_bootstrap_successor.rs"]
mod successor;

/// Empty construction grants nothing. All entries originate in the actual
/// same-Store setup producer; confirmed entries additionally retain ACK/EOF.
#[derive(Clone, Default)]
pub struct BootstrapRegistry {
    entries: Rc<RefCell<BTreeMap<String, Rc<PreparedBootstrap>>>>,
}

/// Stack-borrowed selection only. These references carry no owner, approval,
/// observation or grant and are not retained by bootstrap execution.
#[derive(Clone, Copy)]
pub(crate) struct BootstrapPreflight<'a> {
    pub(crate) plan: &'a Value,
    pub(crate) step: &'a Value,
    pub(crate) context: &'a Value,
}

pub(crate) struct BootstrapSource {
    pub(crate) kind: CalibrationSourceKind,
    bundle: Value,
    blob: BlobRef,
    recipe: BlobRef,
    programs: Value,
    targets: Vec<TargetId>,
    store_root: PathBuf,
    principal: PrincipalId,
    project: ProjectId,
    expected: Vec<(String, BlobRef)>,
}
impl BootstrapSource {
    pub(crate) fn digest(&self) -> &Value {
        &self.bundle["bundleDigest"]
    }
    pub(crate) fn targets(&self) -> &[TargetId] {
        &self.targets
    }
    pub(crate) fn arguments(&self) -> Value {
        match self.kind {
            CalibrationSourceKind::Numeric47 => json!({"sourceBundleDigest":self.digest()}),
            CalibrationSourceKind::PackCase => json!({"command":PACK_COMMAND}),
        }
    }
    pub(crate) fn preconditions(&self) -> Vec<Value> {
        self.expected
            .iter()
            .map(|(target, blob)| {
                json!({"kind":"resource_hash","subject":target,
            "expected":blob.digest,"coverage":"full_target"})
            })
            .collect()
    }
}

/// Readonly provenance of one actual dispatched PACK preparation. Only the
/// same-Store registry can construct it; bytes and locators cannot recreate it.
/// The old route may have retired during its reload and grants no new Apply.
pub(crate) struct PackBootstrapOrigin {
    registry: BootstrapRegistry,
    entry: Rc<PreparedBootstrap>,
    confirmed: Rc<ConfirmedBootstrap>,
    store: *const DurableStore,
    store_root: PathBuf,
    operation: OperationRecord,
    original: Value,
    bundle_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
    absence: Vec<(String, BlobRef)>,
}

#[derive(Clone, Copy)]
enum PackOriginRole {
    PlanCreate,
    RunObservePlanCreate,
    RunApply,
    RunReconcile,
    RunCancel,
    RunGet,
}
impl PackOriginRole {
    fn for_run(method: &str) -> AppResult<Self> {
        match method {
            "plan.create" => Ok(Self::RunObservePlanCreate),
            "plan.apply" => Ok(Self::RunApply),
            "operation.reconcile" => Ok(Self::RunReconcile),
            "operation.cancel" => Ok(Self::RunCancel),
            "operation.get" => Ok(Self::RunGet),
            _ => Err(denied()),
        }
    }
    fn method(self) -> &'static str {
        match self {
            Self::PlanCreate => "plan.create",
            Self::RunObservePlanCreate => "plan.create",
            Self::RunApply => "plan.apply",
            Self::RunReconcile => "operation.reconcile",
            Self::RunCancel => "operation.cancel",
            Self::RunGet => "operation.get",
        }
    }
}
impl PackBootstrapOrigin {
    pub(crate) fn original(&self) -> &Value {
        &self.original
    }
    pub(crate) fn operation(&self) -> &OperationId {
        &self.operation.operation_id
    }
    pub(crate) fn source_bundle_digest(&self) -> &Sha256Digest {
        &self.bundle_digest
    }
    pub(crate) fn logical_program_digest(&self) -> &Sha256Digest {
        &self.entry.source.recipe.digest
    }
    pub(crate) fn frozen_manifest_digest(&self) -> &Sha256Digest {
        &self.manifest_digest
    }
    pub(crate) fn source_bundle(&self) -> &Value {
        &self.entry.source.bundle
    }
    pub(crate) fn source_blob(&self) -> &BlobRef {
        &self.entry.source.blob
    }
    pub(crate) fn recipe_blob(&self) -> &BlobRef {
        &self.entry.source.recipe
    }
    pub(crate) fn check(
        &self,
        store: &DurableStore,
        request: &RequestContextWitness,
        owner: &NativeOwnerWitness,
        selection: &SetupSelection,
        authority: &LocalAuthority,
    ) -> AppResult<()> {
        self.check_relationship(
            store,
            request,
            owner,
            selection,
            authority,
            PackOriginRole::PlanCreate,
        )
    }
    /// Source provenance remains readonly during a separately entered run.
    /// Its caller must also validate that new operation and typed approval;
    /// plan.create is only the typed completed-run Observe consumer's role.
    pub(crate) fn check_for_run(
        &self,
        store: &DurableStore,
        request: &RequestContextWitness,
        owner: &NativeOwnerWitness,
        selection: &SetupSelection,
        authority: &LocalAuthority,
    ) -> AppResult<()> {
        let role = PackOriginRole::for_run(request.method())?;
        self.check_relationship(store, request, owner, selection, authority, role)
    }
    fn check_relationship(
        &self,
        store: &DurableStore,
        request: &RequestContextWitness,
        owner: &NativeOwnerWitness,
        selection: &SetupSelection,
        authority: &LocalAuthority,
        role: PackOriginRole,
    ) -> AppResult<()> {
        request.check_local().map_err(request_error)?;
        owner
            .check_project(store, &selection.project_id)
            .map_err(storage)?;
        let current = store
            .operation(&self.operation.operation_id)
            .map_err(storage)?;
        let plan = &self.entry.plan;
        let frozen = &plan["steps"][0];
        let step_id: StepId = decode(&frozen["stepId"])?;
        let step = current.steps.first().ok_or_else(denied)?;
        if !std::ptr::eq(store, self.store)
            || store.data_root() != self.store_root
            || request.method() != role.method()
            || request.authenticated().principal() != owner.principal()
            || !request
                .authenticated()
                .permits_context(selection.context_id.as_str())
            || current.principal != *owner.principal()
            || current.principal != self.entry.source.principal
            || current.project_id != selection.project_id
            || current.project_id != self.entry.source.project
            || current.plan_id != self.operation.plan_id
            || current.plan_hash != self.operation.plan_hash
            || current.context_id != self.operation.context_id
            || current.scope != self.operation.scope
            || plan["projectBaseRevision"] != selection.expected_revision.as_str()
            || serde_json::to_value(&current.scope).map_err(|_| unavailable())? != plan["scope"]
            || current.steps.len() != 1
            || step.step_id != step_id
            || step.dispatch == DispatchEvidence::NotSent
            || step.invocation_id.as_ref().map(|id| id.as_str())
                != self.original["invocationId"].as_str()
            || self.original["operationId"] != current.operation_id.as_str()
            || self.original["context"] != *self.confirmed.route.context()
            || self.original["context"]["contextId"] != current.context_id.as_str()
            || self.original["context"]["principalRef"] != current.principal.as_str()
            || self.original["contextDigest"] != self.original["context"]["contextDigest"]
            || self.original["contextDigest"] != plan["contextPins"][0]["contextDigest"]
            || self.original["argumentsDigest"]
                != canonical_digest(&self.original["arguments"])
                    .map_err(|_| unavailable())?
                    .as_str()
            || [
                "stepId",
                "bindingId",
                "actionId",
                "actionContractVersion",
                "actionDigest",
                "implementationDigest",
                "arguments",
            ]
            .iter()
            .any(|field| self.original[*field] != frozen[*field])
            || self.entry.source.kind != CalibrationSourceKind::PackCase
            || self.entry.source.targets.len() != 1
            || self.entry.source.targets[0].as_str() != PACK_CASE_TARGET
            || frozen["actionId"] != PACK_ACTION
            || frozen["arguments"] != json!({"command":PACK_COMMAND})
            || !self.confirmed.completion.delivered()
            || self.confirmed.publication_failure.is_some()
            || self.confirmed.manifest["purpose"] != PACK_PURPOSE
            || self.confirmed.manifest["kind"] != PACK_MANIFEST_KIND
            || self.confirmed.manifest["plan"]["planId"] != current.plan_id.as_str()
            || self.confirmed.manifest["plan"]["planHash"] != current.plan_hash.as_str()
            || self.confirmed.manifest["sourceBundle"] != self.entry.source.bundle
            || self.entry.source.digest() != &json!(self.bundle_digest)
            || canonical_digest(&self.confirmed.manifest).map_err(|_| unavailable())?
                != self.manifest_digest
            || !Rc::ptr_eq(&self.registry.prepared(store, plan)?, &self.entry)
            || self
                .entry
                .operation
                .try_borrow()
                .map_err(|_| unavailable())?
                .as_ref()
                != Some(&current.operation_id)
            || self
                .entry
                .confirmed
                .try_borrow()
                .map_err(|_| unavailable())?
                .as_ref()
                .is_none_or(|value| !Rc::ptr_eq(value, &self.confirmed))
        {
            return Err(denied());
        }
        authority.clone().authorize_operation(
            &current.principal,
            &current,
            Access::ObserveOperation,
        )?;
        let original = store
            .stored_invocation_checked(
                &current.operation_id,
                &step_id,
                MAX_ORIGIN_INVOCATION_BYTES,
                || {
                    request.check_local().map_err(|cause| {
                        StorageError::Io(std::io::Error::other(request_error(cause)))
                    })?;
                    owner.check()
                },
            )
            .map_err(storage)?;
        if original != self.original {
            return Err(denied());
        }
        let blob = store
            .stored_invocation_blob(&current.operation_id, &step_id)
            .map_err(storage)?;
        verify_raw_invocation_pin(&self.original, &blob)?;
        // Journal StepRecord pins encode_json bytes, while wire identity uses
        // the separate canonical digest (including valid native f64 fields).
        if step.invocation_digest.as_ref() != Some(&blob.digest) {
            return Err(denied());
        }
        let key = canonical_digest(&self.original).map_err(|_| unavailable())?;
        if self
            .entry
            .captures
            .try_borrow()
            .map_err(|_| unavailable())?
            .get(key.as_str())
            != Some(&self.absence)
            || self.absence.len() != 1
            || self.absence[0].0 != PACK_CASE_TARGET
            || self.absence != self.entry.source.expected
        {
            return Err(unavailable());
        }
        for (_, image) in &self.absence {
            store
                .read_blob_checked(image, MAX_IMAGE_BYTES as u64, || {
                    request.check_local().map_err(|cause| {
                        StorageError::Io(std::io::Error::other(request_error(cause)))
                    })?;
                    owner.check()
                })
                .map_err(storage)?;
        }
        self.registry.check_source(store, plan, &|| {
            request.check_local().map_err(request_error)?;
            owner
                .check_project(store, &selection.project_id)
                .map_err(storage)?;
            authority.clone().authorize_operation(
                &current.principal,
                &current,
                Access::ObserveOperation,
            )
        })
    }
}

struct PreparedBootstrap {
    source: Rc<BootstrapSource>,
    plan: Value,
    confirmed: RefCell<Option<Rc<ConfirmedBootstrap>>>,
    captures: RefCell<BTreeMap<String, Vec<(String, BlobRef)>>>,
    operation: RefCell<Option<OperationId>>,
}
pub(crate) struct ConfirmedBootstrap {
    pub(crate) route: BootstrapHostRoute,
    pub(crate) completion: Arc<CompletedBootstrap>,
    pub(crate) manifest: Value,
    pub(crate) publication_failure: Option<Arc<AppError>>,
}

/// Only a trusted setup callback with the actual current owner/request may
/// create the source. Every raw source is the compiler's immutable original.
pub(crate) fn stage_source(
    store: &mut DurableStore,
    request: &RequestContextWitness,
    owner: &NativeOwnerWitness,
    selection: &mmmm_application::SetupSelection,
    suite: &CalibrationDispatchPlan,
) -> AppResult<Rc<BootstrapSource>> {
    stage_source_kind(
        store,
        request,
        owner,
        selection,
        suite,
        CalibrationSourceKind::Numeric47,
    )
}

pub(crate) fn stage_pack_source(
    store: &mut DurableStore,
    request: &RequestContextWitness,
    owner: &NativeOwnerWitness,
    selection: &mmmm_application::SetupSelection,
    suite: &CalibrationDispatchPlan,
) -> AppResult<Rc<BootstrapSource>> {
    stage_source_kind(
        store,
        request,
        owner,
        selection,
        suite,
        CalibrationSourceKind::PackCase,
    )
}

fn stage_source_kind(
    store: &mut DurableStore,
    request: &RequestContextWitness,
    owner: &NativeOwnerWitness,
    selection: &mmmm_application::SetupSelection,
    suite: &CalibrationDispatchPlan,
    kind: CalibrationSourceKind,
) -> AppResult<Rc<BootstrapSource>> {
    let check = |store: &DurableStore| {
        request.check_local().map_err(request_error)?;
        owner
            .check_project(store, &selection.project_id)
            .map_err(storage)?;
        if request.method() != "plan.create"
            || request.authenticated().principal() != owner.principal()
            || store.project(&selection.project_id).map_err(storage)?["revision"]
                != selection.expected_revision.as_str()
        {
            return Err(denied());
        }
        Ok(())
    };
    check(store)?;
    let entries = render_source_entries_for_kind(kind, suite, &|| check(store))?;
    let bytes = canonical_bytes(&entries).map_err(|_| unavailable())?;
    if bytes.len() as u64 > MAX_BUNDLE_BYTES {
        return Err(unavailable());
    }
    let blob = store.put_blob(&bytes).map_err(storage)?;
    let digest = canonical_digest(&entries).map_err(|_| unavailable())?;
    let identity = canonical_digest(&json!({"projectId":selection.project_id,"digest":digest}))
        .map_err(|_| unavailable())?;
    let resource = json!({"resourceId":format!("bootstrap-source-{identity}"),"sha256":blob.digest,
        "sizeBytes":blob.byte_length,"mediaType":"application/vnd.mmmm.calibration-bootstrap-source+json"});
    register_resource_with_diagnostics(
        store,
        &resource,
        ResourceOwner::Project(selection.project_id.clone()),
    )
    .map_err(|cause| {
        AppError::caused_by(
            "BOOTSTRAP_SOURCE_UNAVAILABLE",
            "Original bootstrap source could not be retained",
            cause,
        )
    })?;
    check(store)?;
    let recipe_bytes = match kind {
        CalibrationSourceKind::Numeric47 => suite.canonical_recipe_bytes().to_vec(),
        CalibrationSourceKind::PackCase => {
            let pack = CalibrationPackProgram::java_26_3().map_err(|_| unavailable())?;
            if raw_digest(pack.canonical_recipe_bytes()) != *pack.program_digest() {
                return Err(unavailable());
            }
            pack.canonical_recipe_bytes().to_vec()
        }
    };
    let recipe = store.put_blob(&recipe_bytes).map_err(storage)?;
    let recipe_identity =
        canonical_digest(&json!({"projectId":selection.project_id,"recipe":recipe.digest}))
            .map_err(|_| unavailable())?;
    register_resource_with_diagnostics(store,&json!({"resourceId":format!("bootstrap-recipe-{recipe_identity}"),
        "sha256":recipe.digest,"sizeBytes":recipe.byte_length,"mediaType":match kind { CalibrationSourceKind::Numeric47 => "application/vnd.mmmm.calibration-recipe+json", CalibrationSourceKind::PackCase => "application/vnd.mmmm.calibration-pack-recipe" }}),
        ResourceOwner::Project(selection.project_id.clone())).map_err(|cause|AppError::caused_by(
            "BOOTSTRAP_SOURCE_UNAVAILABLE","Original sealed bootstrap recipe could not be retained",cause))?;
    let targets = match kind {
        CalibrationSourceKind::Numeric47 => validated_bootstrap_target_ids(suite)?,
        CalibrationSourceKind::PackCase => {
            vec![TargetId::new(PACK_CASE_TARGET).map_err(|_| unavailable())?]
        }
    };
    let mut programs = Vec::with_capacity(47);
    if kind == CalibrationSourceKind::Numeric47 {
        for program in suite.programs() {
            programs.push(render_program(program)?);
        }
    }
    check(store)?;
    let requirements = absence_requirements_for_kind(kind, &json!(digest))?;
    let mut expected = Vec::with_capacity(95);
    for requirement in requirements {
        check(store)?;
        // These are immutable fresh-only requirements, not observed before
        // evidence. Only native prepare may produce the corresponding facts.
        let bytes = canonical_bytes(&requirement).map_err(|_| unavailable())?;
        let pin = store.put_blob(&bytes).map_err(storage)?;
        let identity =
            canonical_digest(&json!({"projectId":selection.project_id,"requirement":pin.digest}))
                .map_err(|_| unavailable())?;
        let resource = json!({"resourceId":format!("bootstrap-requirement-{identity}"),"sha256":pin.digest,
            "sizeBytes":pin.byte_length,"mediaType":"application/vnd.mmmm.calibration-bootstrap-requirement+json"});
        register_resource_with_diagnostics(
            store,
            &resource,
            ResourceOwner::Project(selection.project_id.clone()),
        )
        .map_err(|cause| {
            AppError::caused_by(
                "BOOTSTRAP_SOURCE_UNAVAILABLE",
                "Fresh-only requirement could not be retained",
                cause,
            )
        })?;
        expected.push((
            requirement["targetId"]
                .as_str()
                .ok_or_else(unavailable)?
                .into(),
            pin,
        ));
    }
    check(store)?;
    let mut bundle = json!({"bundleDigest":digest,"rawResource":resource,"entries":entries});
    if kind == CalibrationSourceKind::PackCase {
        bundle["sourceKind"] = json!(kind.name());
    }
    Ok(Rc::new(BootstrapSource {
        kind,
        bundle,
        blob,
        recipe,
        programs: Value::Array(programs),
        targets,
        store_root: store.data_root().to_path_buf(),
        principal: owner.principal().clone(),
        project: selection.project_id.clone(),
        expected,
    }))
}

/// Pure opt-in scope locators from the exact compiler suite. This projection
/// issues no context, owner, grant, ADMIN receipt, source or registry entry.
pub(crate) fn normative_bootstrap_target_ids() -> AppResult<BTreeSet<String>> {
    let suite = CalibrationDispatchPlan::normative47().map_err(|cause| {
        AppError::caused_by(
            cause.code,
            "Original bootstrap target projection is unavailable",
            cause,
        )
    })?;
    Ok(validated_bootstrap_target_ids(&suite)?
        .into_iter()
        .map(|id| id.as_str().to_owned())
        .collect())
}
fn ordered_bootstrap_target_names(suite: &CalibrationDispatchPlan) -> Vec<String> {
    let mut targets = vec![PACK_TARGET.to_owned()];
    for program in suite.programs() {
        targets.push(format!(
            "calibration-objective-{}",
            program.scope().objective()
        ));
        targets.push(format!(
            "calibration-storage-{}",
            raw_digest(program.scope().storage().as_str().as_bytes())
        ));
    }
    targets
}
fn validated_bootstrap_target_ids(suite: &CalibrationDispatchPlan) -> AppResult<Vec<TargetId>> {
    let names = ordered_bootstrap_target_names(suite);
    let mut unique = BTreeSet::new();
    if suite.programs().len() != 47 || names.len() != 95 {
        return Err(unavailable());
    }
    names
        .into_iter()
        .map(|name| {
            if !unique.insert(name.clone()) {
                return Err(unavailable());
            }
            TargetId::new(name).map_err(|_| unavailable())
        })
        .collect()
}

fn render_source_entries(
    suite: &CalibrationDispatchPlan,
    current: &dyn Fn() -> AppResult<()>,
) -> AppResult<Value> {
    if suite.source_entries().len() != 48 {
        return Err(unavailable());
    }
    let mut total = 0usize;
    let mut entries = Vec::with_capacity(48);
    for (path, bytes) in suite.source_entries() {
        current()?;
        total = total.checked_add(bytes.len()).ok_or_else(unavailable)?;
        if total > CalibrationDispatchPlan::MAX_SOURCE_BYTES
            || (path != "pack.mcmeta"
                && bytes.len() > CalibrationDispatchPlan::MAX_LOADED_FUNCTION_BYTES)
        {
            return Err(unavailable());
        }
        entries.push(json!({"path":path,"rawSha256":raw_digest(bytes),"byteLength":bytes.len(),"rawBytesHex":encode_hex(bytes)}));
    }
    current()?;
    Ok(Value::Array(entries))
}
fn render_program(program: &mmmm_compiler::calibration::CalibrationProgram) -> AppResult<Value> {
    let function = program
        .invocation_command()
        .strip_prefix("function ")
        .ok_or_else(unavailable)?;
    Ok(
        json!({"caseId":program.case().case_id(),"functionId":function,"objective":program.scope().objective(),
        "storage":program.scope().storage(),"initializationCommands":program.initialization_commands()}),
    )
}

fn render_source_entries_for_kind(
    kind: CalibrationSourceKind,
    suite: &CalibrationDispatchPlan,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<Value> {
    if kind == CalibrationSourceKind::Numeric47 {
        return render_source_entries(suite, check);
    }
    let mut rows = Vec::with_capacity(kind.entry_count());
    for (path, bytes) in kind.source_entries().map_err(|_| unavailable())? {
        check()?;
        rows.push(json!({"path":path,"rawSha256":raw_digest(&bytes),"byteLength":bytes.len(),"rawBytesHex":encode_hex(&bytes)}));
    }
    if rows.len() != kind.entry_count() {
        return Err(unavailable());
    }
    Ok(Value::Array(rows))
}

/// Rendering owns no Store, owner, ADMIN receipt or route. Capacity tests can
/// exercise the full current wire projection without issuing an approval.
struct ManifestRendering<'a> {
    kind: CalibrationSourceKind,
    plan: &'a Value,
    context: &'a Value,
    bundle: &'a Value,
    programs: &'a Value,
    recipe: &'a Sha256Digest,
    principal: &'a PrincipalId,
    generation: &'a Value,
    source_facts_digest: &'a Sha256Digest,
}
fn render_manifest(input: ManifestRendering<'_>) -> AppResult<Value> {
    let ManifestRendering {
        kind,
        plan,
        context,
        bundle,
        programs,
        recipe,
        principal,
        generation,
        source_facts_digest,
    } = input;
    let step = &plan["steps"][0];
    let purpose = purpose_for_kind(kind);
    let selection=canonical_digest(&json!({"purpose":purpose,"principal":principal,
        "planId":plan["planId"],"planHash":plan["planHash"],"sourceBundleDigest":bundle["bundleDigest"]})).map_err(|_|unavailable())?;
    Ok(
        json!({"kind":manifest_kind_for_kind(kind),"purpose":purpose,"selectionDigest":selection,
        "hostEpoch":context["environment"]["sessionEpoch"],"registryGeneration":generation,
        "runtimeSourceFactsDigest":source_facts_digest,"suiteDigest":recipe,"recipeSha256":recipe,
        "sourceBundle":bundle,"programs":programs,
        "plan":{"kind":"native_plan_approval","protocolVersion":mmmm_contracts::CONTRACT_VERSION,
            "principalId":context["principalRef"],"projectId":plan["projectId"],"planId":plan["planId"],
            "planHash":plan["planHash"],"policyRevision":plan["policyRevision"],"contextPins":plan["contextPins"],
            "expiresAt":plan["expiresAt"],"nativeExecutions":[],"steps":[{
                "stepId":step["stepId"],"bindingId":step["bindingId"],"actionId":step["actionId"],
                "actionDigest":step["actionDigest"],"implementationDigest":step["implementationDigest"],
                "argumentsDigest":canonical_digest(&step["arguments"]).map_err(|_|unavailable())?,
                "contextId":step["contextId"],"contextDigest":context["contextDigest"],
                "resourcesRead":step["resourcesRead"],"resourcesWritten":step["resourcesWritten"],"preconditions":plan["preconditions"]}]}}),
    )
}

/// Condition specifications only. Actual native state is independently read
/// after ADMIN approval; these deterministic bytes never issue known state.
pub(crate) fn absence_requirements(suite: &CalibrationDispatchPlan, digest: &Value) -> Vec<Value> {
    let targets = ordered_bootstrap_target_names(suite);
    let mut result = vec![
        json!({"format":"mmmm.native.calibration-bootstrap-absence/1",
        "targetId":PACK_TARGET,"status":"known","presence":"absent","coverage":"full_target",
        "captureScope":"native_bootstrap_pack_directory_absence","selector":{"kind":"calibration_pack","sourceBundleDigest":digest}}),
    ];
    for (program, pair) in suite.programs().iter().zip(targets[1..].chunks_exact(2)) {
        result.push(json!({"format":"mmmm.native.calibration-bootstrap-absence/1",
            "targetId":pair[0],"status":"known","presence":"absent","coverage":"full_target",
            "captureScope":"native_bootstrap_objective_absence","selector":{"kind":"objective","objective":program.scope().objective()}}));
        result.push(json!({"format":"mmmm.native.calibration-bootstrap-absence/1",
            "targetId":pair[1],"status":"known","presence":"absent","coverage":"full_target",
            "captureScope":"native_bootstrap_cache_and_backing_absence","selector":{"kind":"owned_storage","storage":program.scope().storage(),"ownedSubtrees":["inputs","invocation"]}}));
    }
    result
}

pub(crate) fn absence_requirements_for_kind(
    kind: CalibrationSourceKind,
    digest: &Value,
) -> AppResult<Vec<Value>> {
    match kind {
        CalibrationSourceKind::Numeric47 => Ok(absence_requirements(
            &CalibrationDispatchPlan::normative47().map_err(|_| unavailable())?,
            digest,
        )),
        CalibrationSourceKind::PackCase => Ok(vec![
            json!({"format":"mmmm.native.calibration-bootstrap-absence/1",
            "targetId":PACK_CASE_TARGET,"status":"known","presence":"absent","coverage":"full_target",
            "captureScope":"native_bootstrap_pack_directory_absence","selector":{"kind":"calibration_pack","sourceBundleDigest":digest}}),
        ]),
    }
}

impl BootstrapRegistry {
    #[allow(
        clippy::too_many_arguments,
        reason = "Readonly origin binds an actual current request, concrete authority, selected context and original journal operation"
    )]
    pub(crate) fn pack_run_origin(
        &self,
        store: &DurableStore,
        request: &RequestContextWitness,
        owner: &NativeOwnerWitness,
        authority: &LocalAuthority,
        selection: &SetupSelection,
        operation_id: &OperationId,
    ) -> AppResult<PackBootstrapOrigin> {
        request.check_local().map_err(request_error)?;
        owner
            .check_project(store, &selection.project_id)
            .map_err(storage)?;
        if request.method() != "plan.create"
            || request.authenticated().principal() != owner.principal()
            || !request
                .authenticated()
                .permits_context(selection.context_id.as_str())
        {
            return Err(denied());
        }
        let operation = store.operation(operation_id).map_err(storage)?;
        authority.clone().authorize_operation(
            owner.principal(),
            &operation,
            Access::ObserveOperation,
        )?;
        let plan = store
            .plan(&operation.plan_id, &operation.plan_hash)
            .map_err(storage)?;
        let entry = self.prepared(store, &plan)?;
        if entry.source.kind != CalibrationSourceKind::PackCase
            || plan["steps"]
                .as_array()
                .is_none_or(|steps| steps.len() != 1)
        {
            return Err(denied());
        }
        let confirmed = entry
            .confirmed
            .try_borrow()
            .map_err(|_| unavailable())?
            .as_ref()
            .cloned()
            .ok_or_else(unavailable)?;
        let step: StepId = decode(&plan["steps"][0]["stepId"])?;
        let original = store
            .stored_invocation_checked(operation_id, &step, MAX_ORIGIN_INVOCATION_BYTES, || {
                request.check_local().map_err(|cause| {
                    StorageError::Io(std::io::Error::other(request_error(cause)))
                })?;
                owner.check()
            })
            .map_err(storage)?;
        let key = canonical_digest(&original).map_err(|_| unavailable())?;
        let absence = entry
            .captures
            .try_borrow()
            .map_err(|_| unavailable())?
            .get(key.as_str())
            .cloned()
            .ok_or_else(unavailable)?;
        let bundle_digest = decode(entry.source.digest())?;
        let manifest_digest = canonical_digest(&confirmed.manifest).map_err(|_| unavailable())?;
        let origin = PackBootstrapOrigin {
            registry: self.clone(),
            entry,
            confirmed,
            store,
            store_root: store.data_root().to_path_buf(),
            operation,
            original,
            bundle_digest,
            manifest_digest,
            absence,
        };
        origin.check(store, request, owner, selection, authority)?;
        Ok(origin)
    }

    pub(crate) fn retire_routes(&self, shutdown: bool) -> AppResult<()> {
        let entries = self.entries.try_borrow().map_err(|_| unavailable())?;
        for entry in entries.values() {
            if let Some(confirmed) = entry
                .confirmed
                .try_borrow()
                .map_err(|_| unavailable())?
                .as_ref()
                && (shutdown || std::time::Instant::now() >= confirmed.route.lease_expires())
            {
                confirmed.route.retire()?;
            }
        }
        Ok(())
    }
    /// Bind the actual just-frozen ordinary plan to its in-process producer.
    /// A plan imported from JSON cannot create this association.
    pub(crate) fn retain_plan(
        &self,
        store: &DurableStore,
        source: Rc<BootstrapSource>,
        plan: &Value,
    ) -> AppResult<()> {
        validate_plan(plan, &source)?;
        if store.data_root() != source.store_root {
            return Err(denied());
        }
        if plan["projectId"] != source.project.as_str() {
            return Err(denied());
        }
        let id: PlanId = decode(&plan["planId"])?;
        let hash: Sha256Digest = decode(&plan["planHash"])?;
        if store.plan(&id, &hash).map_err(storage)? != *plan {
            return Err(denied());
        }
        let mut entries = self.entries.try_borrow_mut().map_err(|_| unavailable())?;
        if entries.len() >= MAX_ENTRIES || entries.contains_key(hash.as_str()) {
            return Err(unavailable());
        }
        entries.insert(
            hash.as_str().into(),
            Rc::new(PreparedBootstrap {
                source,
                plan: plan.clone(),
                confirmed: RefCell::new(None),
                captures: RefCell::new(BTreeMap::new()),
                operation: RefCell::new(None),
            }),
        );
        Ok(())
    }
    fn prepared(&self, store: &DurableStore, plan: &Value) -> AppResult<Rc<PreparedBootstrap>> {
        let entries = self.entries.try_borrow().map_err(|_| unavailable())?;
        let value = entries
            .get(plan["planHash"].as_str().ok_or_else(unavailable)?)
            .cloned()
            .ok_or_else(unavailable)?;
        if value.plan != *plan || value.source.store_root != store.data_root() {
            return Err(denied());
        }
        validate_plan(plan, &value.source)?;
        Ok(value)
    }
    pub(crate) fn matches_plan(&self, plan: &Value) -> AppResult<bool> {
        let entries = self.entries.try_borrow().map_err(|_| unavailable())?;
        Ok(entries.values().any(|entry| entry.plan == *plan))
    }
    /// A routing decision only. Actual source, Store, request and authority
    /// checks still occur in enter/observe_successor. A plain command match
    /// cannot select the private PACK route without its retained exact plan.
    pub(crate) fn handles_original(&self, original: &Value) -> AppResult<bool> {
        if original["actionId"] == ACTION {
            return Ok(true);
        }
        if !is_candidate(original) {
            return Ok(false);
        }
        let entries = self.entries.try_borrow().map_err(|_| unavailable())?;
        Ok(entries.values().any(|entry| {
            entry.source.kind == CalibrationSourceKind::PackCase
                && entry.plan["steps"][0]["stepId"] == original["stepId"]
                && entry.plan["steps"][0]["bindingId"] == original["bindingId"]
                && entry.plan["steps"][0]["actionDigest"] == original["actionDigest"]
                && entry.plan["steps"][0]["arguments"] == original["arguments"]
                && entry.plan["contextPins"][0]["contextDigest"] == original["contextDigest"]
        }))
    }
    pub(crate) fn check_source(
        &self,
        store: &DurableStore,
        plan: &Value,
        current: &dyn Fn() -> AppResult<()>,
    ) -> AppResult<()> {
        let entry = self.prepared(store, plan)?;
        let id = decode(&plan["planId"])?;
        let hash = decode(&plan["planHash"])?;
        if store.plan(&id, &hash).map_err(storage)? != *plan
            || store.project(&entry.source.project).map_err(storage)?["revision"]
                != plan["projectBaseRevision"]
        {
            return Err(denied());
        }
        let check = || current().map_err(|cause| StorageError::Io(std::io::Error::other(cause)));
        current()?;
        let source = store
            .read_blob_checked(&entry.source.blob, MAX_BUNDLE_BYTES, check)
            .map_err(storage)?;
        if source != canonical_bytes(&entry.source.bundle["entries"]).map_err(|_| unavailable())? {
            return Err(unavailable());
        }
        let suite = CalibrationDispatchPlan::normative47().map_err(|cause| {
            AppError::caused_by(
                cause.code,
                "Original bootstrap recipe is unavailable",
                cause,
            )
        })?;
        let recipe = store
            .read_blob_checked(
                &entry.source.recipe,
                CalibrationDispatchPlan::MAX_RECIPE_BYTES as u64,
                check,
            )
            .map_err(storage)?;
        let expected_recipe = match entry.source.kind {
            CalibrationSourceKind::Numeric47 => suite.canonical_recipe_bytes().to_vec(),
            CalibrationSourceKind::PackCase => CalibrationPackProgram::java_26_3()
                .map_err(|_| unavailable())?
                .canonical_recipe_bytes()
                .to_vec(),
        };
        if recipe != expected_recipe {
            return Err(unavailable());
        }
        finish_native_observation(Ok(()), current())
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
        let entry = entries
            .values()
            .find(|entry| {
                entry.plan["steps"][0]["stepId"] == original["stepId"]
                    && entry.plan["contextPins"][0]["contextDigest"] == original["contextDigest"]
                    && entry.plan["steps"][0]["arguments"] == original["arguments"]
                    && entry.plan["steps"][0]["actionDigest"] == original["actionDigest"]
                    && serde_json::to_value(scope).is_ok_and(|value| value == entry.plan["scope"])
            })
            .ok_or_else(unavailable)?;
        if !scope
            .external_target_ids
            .iter()
            .any(|id| id.as_str() == target)
            || !entry.source.targets.iter().any(|id| id.as_str() == target)
            || original["context"]["principalRef"] != request.authenticated().principal().as_str()
        {
            return Err(denied());
        }
        let confirmed = entry
            .confirmed
            .try_borrow()
            .map_err(|_| unavailable())?
            .as_ref()
            .cloned()
            .ok_or_else(unavailable)?;
        confirmed.route.check_current(request)?;
        authority.authorize_retained_apply(
            request.authenticated().principal(),
            &original["context"],
            &entry.plan,
        )
    }
    pub(crate) fn manifest(
        &self,
        store: &DurableStore,
        plan: &Value,
        context: &Value,
        facts: &Value,
    ) -> AppResult<Value> {
        let entry = self.prepared(store, plan)?;
        let source = &entry.source;
        if context["principalRef"] != source.principal.as_str()
            || context["contextDigest"] != plan["contextPins"][0]["contextDigest"]
            || context["environment"] != plan["contextPins"][0]["environment"]
        {
            return Err(denied());
        }
        crate::catalog_source::validate_source_facts(facts, context)?;
        render_manifest(ManifestRendering {
            kind: source.kind,
            plan,
            context,
            bundle: &source.bundle,
            programs: &source.programs,
            recipe: &source.recipe.digest,
            principal: &source.principal,
            generation: &facts["registryGeneration"],
            source_facts_digest: &crate::catalog_source::source_facts_pin(facts)?,
        })
    }
    pub(crate) fn confirm(
        &self,
        store: &DurableStore,
        plan: &Value,
        confirmation: ConfirmedBootstrap,
    ) -> AppResult<()> {
        let entry = self.prepared(store, plan)?;
        if !confirmation.completion.delivered()
            || confirmation.route.kind() != entry.source.kind
            || confirmation.manifest["purpose"] != purpose_for_kind(entry.source.kind)
            || confirmation.manifest["plan"]["planId"] != plan["planId"]
            || confirmation.manifest["plan"]["planHash"] != plan["planHash"]
            || confirmation.manifest["sourceBundle"] != entry.source.bundle
            || confirmation.route.context()["contextDigest"]
                != plan["contextPins"][0]["contextDigest"]
        {
            return Err(denied());
        }
        let mut slot = entry
            .confirmed
            .try_borrow_mut()
            .map_err(|_| unavailable())?;
        if slot.is_some() {
            return Err(unavailable());
        }
        *slot = Some(Rc::new(confirmation));
        Ok(())
    }
    pub(crate) fn precondition(
        &self,
        store: &DurableStore,
        request: &RequestContextWitness,
        authority: &LocalAuthority,
        preflight: BootstrapPreflight<'_>,
        condition: &Value,
    ) -> AppResult<Sha256Digest> {
        let frozen = preflight.plan["preconditions"]
            .as_array()
            .ok_or_else(unavailable)?;
        let index = frozen
            .iter()
            .position(|value| value == condition)
            .ok_or_else(denied)?;
        let conditions = frozen.iter().collect::<Vec<_>>();
        self.preconditions(store, request, authority, preflight, &conditions)?
            .get(index)
            .cloned()
            .ok_or_else(unavailable)
    }
    /// One stack-owned observation per common preflight. No result or witness
    /// survives to another Application call; phase comparison stays there.
    pub(crate) fn preconditions(
        &self,
        store: &DurableStore,
        request: &RequestContextWitness,
        authority: &LocalAuthority,
        preflight: BootstrapPreflight<'_>,
        conditions: &[&Value],
    ) -> AppResult<Vec<Sha256Digest>> {
        let BootstrapPreflight {
            plan,
            step,
            context,
        } = preflight;
        let entry = self.prepared(store, plan)?;
        let frozen = plan["preconditions"].as_array().ok_or_else(unavailable)?;
        validate_precondition_batch(conditions, frozen, &entry.source.targets)?;
        let confirmed = entry
            .confirmed
            .try_borrow()
            .map_err(|_| unavailable())?
            .as_ref()
            .cloned()
            .ok_or_else(unavailable)?;
        let owner =
            NativeOwnerWitness::capture(store, request.budget().deadline()).map_err(storage)?;
        let project = decode(&plan["projectId"])?;
        let id = decode(&plan["planId"])?;
        let hash = decode(&plan["planHash"])?;
        let current = || {
            request.check_local().map_err(request_error)?;
            owner.check_project(store, &project).map_err(storage)?;
            if request.method() != "plan.apply"
                || store.data_root() != entry.source.store_root
                || owner.principal() != &entry.source.principal
                || context != confirmed.route.context()
                || context["principalRef"] != request.authenticated().principal().as_str()
                || step != &plan["steps"][0]
                || store.plan(&id, &hash).map_err(storage)? != *plan
                || store.project(&project).map_err(storage)?["revision"]
                    != plan["projectBaseRevision"]
                || !confirmed.completion.delivered()
                || confirmed.publication_failure.is_some()
            {
                return Err(denied());
            }
            authority.authorize_retained_apply(owner.principal(), context, plan)?;
            confirmed.route.check_current(request)
        };
        for _ in conditions {
            current()?;
        }
        self.check_source(store, plan, &current)?;
        let actual = confirmed
            .route
            .inspect_targets(request, entry.source.digest(), &current);
        let actual = finish_native_observation(actual, self.check_source(store, plan, &current))?;
        let images = decode_preflight_target_images(
            &actual,
            &entry.source.targets,
            context,
            &confirmed.manifest,
            &step["implementationDigest"],
        )?;
        let mut observed = Vec::with_capacity(95);
        for (condition, image) in conditions.iter().zip(images) {
            current()?;
            if condition["subject"] != image.target {
                return Err(unavailable());
            }
            // Return the factual raw digest. Application alone compares it to
            // its current phase expected value and reports TARGET_DRIFT.
            observed.push(raw_digest(&image.bytes));
            current()?;
        }
        Ok(observed)
    }
    pub(crate) fn enter<'a>(
        &self,
        store: &DurableStore,
        request: &'a RequestContextWitness,
        authority: &'a LocalAuthority,
        original: &Value,
        access: BootstrapAccess,
    ) -> AppResult<Option<EnteredBootstrap<'a>>> {
        if !self.handles_original(original)? {
            return Ok(None);
        }
        let operation_id: OperationId = decode(&original["operationId"])?;
        let operation = store.operation(&operation_id).map_err(storage)?;
        let plan = store
            .plan(&operation.plan_id, &operation.plan_hash)
            .map_err(storage)?;
        let entry = self.prepared(store, &plan)?;
        let confirmed = entry
            .confirmed
            .try_borrow()
            .map_err(|_| unavailable())?
            .as_ref()
            .cloned()
            .ok_or_else(unavailable)?;
        let owner =
            NativeOwnerWitness::capture(store, request.budget().deadline()).map_err(storage)?;
        let entered = EnteredBootstrap {
            registry: self.clone(),
            entry,
            confirmed,
            request,
            authority,
            owner,
            operation,
            original: original.clone(),
            access,
        };
        entered.check(store)?;
        Ok(Some(entered))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootstrapAccess {
    Apply,
    Observe,
    Cancel,
}
pub(crate) struct EnteredBootstrap<'a> {
    registry: BootstrapRegistry,
    entry: Rc<PreparedBootstrap>,
    confirmed: Rc<ConfirmedBootstrap>,
    request: &'a RequestContextWitness,
    authority: &'a LocalAuthority,
    owner: NativeOwnerWitness,
    operation: OperationRecord,
    original: Value,
    access: BootstrapAccess,
}
impl EnteredBootstrap<'_> {
    pub(crate) fn check(&self, store: &DurableStore) -> AppResult<()> {
        self.request.check_local().map_err(request_error)?;
        self.owner
            .check_project(store, &self.operation.project_id)
            .map_err(storage)?;
        let current = store
            .operation(&self.operation.operation_id)
            .map_err(storage)?;
        let plan = &self.entry.plan;
        let context = self.confirmed.route.context();
        if !Rc::ptr_eq(&self.registry.prepared(store, plan)?, &self.entry)
            || self
                .entry
                .confirmed
                .try_borrow()
                .map_err(|_| unavailable())?
                .as_ref()
                .is_none_or(|v| !Rc::ptr_eq(v, &self.confirmed))
            || current.principal != *self.request.authenticated().principal()
            || current.principal != self.entry.source.principal
            || self.owner.principal() != &current.principal
            || current.project_id != self.entry.source.project
            || current.context_id.as_str() != context["contextId"].as_str().unwrap_or("")
            || current.plan_id != self.operation.plan_id
            || current.plan_hash != self.operation.plan_hash
            || current.scope != self.operation.scope
            || serde_json::to_value(&current.scope).map_err(|_| unavailable())? != plan["scope"]
            || store.project(&current.project_id).map_err(storage)?["revision"]
                != plan["projectBaseRevision"]
            || context != &self.original["context"]
            || context["contextDigest"] != self.original["contextDigest"]
            || context["principalRef"] != current.principal.as_str()
            || !self.confirmed.completion.delivered()
        {
            return Err(denied());
        }
        if self
            .entry
            .operation
            .try_borrow()
            .map_err(|_| unavailable())?
            .as_ref()
            .is_some_and(|operation| operation != &current.operation_id)
        {
            return Err(denied());
        }
        if let Some(cause) = &self.confirmed.publication_failure {
            return Err(AppError::caused_by(
                cause.code,
                cause.message,
                RetainedFailure(cause.clone()),
            ));
        }
        let step = &plan["steps"][0];
        if self.original["operationId"] != current.operation_id.as_str()
            || self.original["stepId"] != step["stepId"]
            || [
                "bindingId",
                "actionId",
                "actionContractVersion",
                "actionDigest",
                "implementationDigest",
                "arguments",
            ]
            .iter()
            .any(|field| self.original[*field] != step[*field])
            || self.original["argumentsDigest"]
                != canonical_digest(&self.original["arguments"])
                    .map_err(|_| unavailable())?
                    .as_str()
        {
            return Err(denied());
        }
        self.confirmed.route.check_current(self.request)?;
        self.authority.authorize_retained_scope(
            &current.principal,
            &current.project_id,
            &current.context_id,
            &decode(&plan["policyRevision"])?,
            &plan["scope"],
        )?;
        if self.access == BootstrapAccess::Apply {
            if self.request.method() != "plan.apply" {
                return Err(denied());
            }
            self.authority
                .authorize_retained_apply(&current.principal, context, plan)?;
        } else {
            self.authority.clone().authorize_operation(
                &current.principal,
                &current,
                if self.access == BootstrapAccess::Observe {
                    Access::ObserveOperation
                } else {
                    Access::Cancel
                },
            )?;
        }
        let bytes = store
            .read_blob_checked(&self.entry.source.blob, MAX_BUNDLE_BYTES, || {
                self.request
                    .check_local()
                    .map_err(|_| StorageError::Conflict("Original bootstrap request ended"))?;
                self.owner.check()
            })
            .map_err(storage)?;
        if bytes
            != canonical_bytes(&self.entry.source.bundle["entries"]).map_err(|_| unavailable())?
        {
            return Err(unavailable());
        }
        self.request.check_local().map_err(request_error)
    }
    pub(crate) fn scope(&self) -> &WriteScope {
        &self.operation.scope
    }
    pub(crate) fn capture(&self, store: &mut DurableStore) -> AppResult<BeforeCapture> {
        self.check(store)?;
        let observed =
            self.confirmed
                .route
                .prepare_observed(store, self.request, &self.original, &|store| {
                    self.check(store)
                });
        let observed = finish_native_observation(observed, self.check(store))?;
        let images = self.validate_images(&observed)?;
        let key = canonical_digest(&self.original)
            .map_err(|_| unavailable())?
            .as_str()
            .to_owned();
        let mut retained = Vec::with_capacity(images.len());
        for image in &images {
            self.check(store)?;
            let blob = store.put_blob(&image.bytes).map_err(storage)?;
            store
                .pin_operation_artifact(&self.operation.operation_id, &blob)
                .map_err(storage)?;
            retained.push((image.target.clone(), blob));
        }
        let mut captures = self
            .entry
            .captures
            .try_borrow_mut()
            .map_err(|_| unavailable())?;
        if captures.len() >= 8 && !captures.contains_key(&key) {
            return Err(unavailable());
        }
        if let Some(old) = captures.get(&key) {
            if old != &retained {
                return Err(unavailable());
            }
        } else {
            captures.insert(key, retained);
        }
        drop(captures);
        Ok(BeforeCapture {
            invocation_id: decode(&self.original["invocationId"])?,
            binding_id: decode(&self.original["bindingId"])?,
            context_digest: decode(&self.original["contextDigest"])?,
            implementation_digest: decode(&self.original["implementationDigest"])?,
            arguments_digest: decode(&self.original["argumentsDigest"])?,
            images,
        })
    }
    pub(crate) fn persist_intent(
        &self,
        store: &mut DurableStore,
        step: &StepId,
        original: &Value,
        resolution: Option<&BlobRef>,
    ) -> AppResult<mmmm_runtime::storage::StepRecord> {
        self.check(store)?;
        if resolution.is_some() || original != &self.original || original["stepId"] != step.as_str()
        {
            return Err(denied());
        }
        // A fresh private prepare rechecks the exact original before images.
        // Its side-effect-free compare is mandatory before the writer transaction.
        let result =
            self.confirmed
                .route
                .prepare_observed(store, self.request, original, &|store| self.check(store));
        let current = finish_native_observation(result, self.check(store))?;
        let images = self.validate_images(&current)?;
        let key = canonical_digest(original)
            .map_err(|_| unavailable())?
            .as_str()
            .to_owned();
        let captures = self
            .entry
            .captures
            .try_borrow()
            .map_err(|_| unavailable())?;
        let retained = captures
            .get(&key)
            .filter(|v| v.len() == self.entry.source.targets.len())
            .ok_or_else(unavailable)?;
        for (image, (target, blob)) in images.iter().zip(retained) {
            if image.target != *target
                || raw_digest(&image.bytes) != blob.digest
                || store
                    .read_blob_checked(blob, MAX_IMAGE_BYTES as u64, || self.owner.check())
                    .map_err(storage)?
                    != image.bytes
            {
                return Err(unavailable());
            }
        }
        drop(captures);
        self.check(store)?;
        store
            .pin_operation_artifact(&self.operation.operation_id, &self.entry.source.blob)
            .map_err(storage)?;
        store
            .pin_operation_artifact(&self.operation.operation_id, &self.entry.source.recipe)
            .map_err(storage)?;
        let manifest_bytes =
            canonical_bytes(&self.confirmed.manifest).map_err(|_| unavailable())?;
        let manifest = store.put_blob(&manifest_bytes).map_err(storage)?;
        store
            .pin_operation_artifact(&self.operation.operation_id, &manifest)
            .map_err(storage)?;
        let witness = self.confirmed.completion.witness();
        let receipt = json!({"format":"mmmm.native.calibration-bootstrap-approval-evidence/1",
            "operationId":self.operation.operation_id,"planId":self.operation.plan_id,"planHash":self.operation.plan_hash,
            "sourceBundleDigest":self.entry.source.digest(),"manifestSha256":manifest.digest,
            "selectionDigest":self.confirmed.manifest["selectionDigest"],"originalOfferDigest":witness.offer_digest(),
            "nonce":witness.nonce(),"nativeDeliveryObserved":self.confirmed.completion.delivered()});
        let receipt = store
            .put_blob(&canonical_bytes(&receipt).map_err(|_| unavailable())?)
            .map_err(storage)?;
        store
            .append_operation_evidence(&self.operation.operation_id, &receipt)
            .map_err(storage)?;
        self.check(store)?;
        let mut claim = self
            .entry
            .operation
            .try_borrow_mut()
            .map_err(|_| unavailable())?;
        if claim
            .as_ref()
            .is_some_and(|id| id != &self.operation.operation_id)
        {
            return Err(denied());
        }
        *claim = Some(self.operation.operation_id.clone());
        drop(claim);
        store
            .dispatch_intent(&self.operation.operation_id, step, original)
            .map_err(storage)
    }
    pub(crate) fn dispatch(&self, store: &mut DurableStore) -> AppResult<Value> {
        self.verify_intent(store)?;
        self.confirmed
            .route
            .dispatch_with_store(store, self.request, &self.original, &|store| {
                self.check(store)
            })
    }
    pub(crate) fn poll(
        &self,
        store: &mut DurableStore,
        receipt: Option<&str>,
    ) -> AppResult<Option<Value>> {
        self.verify_intent(store)?;
        self.confirmed.route.poll_with_store(
            store,
            self.request,
            &self.original,
            receipt,
            &|store| self.check(store),
        )
    }
    pub(crate) fn cancel(&self, store: &mut DurableStore) -> AppResult<()> {
        self.verify_intent(store)?;
        self.confirmed
            .route
            .cancel_with_store(store, self.request, &self.original, &|store| {
                self.check(store)
            })
    }
    fn verify_intent(&self, store: &DurableStore) -> AppResult<()> {
        self.check(store)?;
        if self
            .entry
            .operation
            .try_borrow()
            .map_err(|_| unavailable())?
            .as_ref()
            != Some(&self.operation.operation_id)
        {
            return Err(denied());
        }
        let original_digest = canonical_digest(&self.original).map_err(|_| unavailable())?;
        if self
            .entry
            .captures
            .try_borrow()
            .map_err(|_| unavailable())?
            .get(original_digest.as_str())
            .is_none_or(|images| images.len() != self.entry.source.targets.len())
        {
            return Err(unavailable());
        }
        let step: StepId = decode(&self.original["stepId"])?;
        let blob = store
            .stored_invocation_blob(&self.operation.operation_id, &step)
            .map_err(storage)?;
        verify_raw_invocation_pin(&self.original, &blob)
    }
    fn validate_images(&self, value: &Value) -> AppResult<Vec<BeforeImage>> {
        exact(
            value,
            &[
                "format",
                "invocationId",
                "invocationDigest",
                "sourceBundleDigest",
                "targetImages",
            ],
        )?;
        if value["format"] != "mmmm.native.calibration-bootstrap-ready/1"
            || value["invocationId"] != self.original["invocationId"]
            || value["invocationDigest"]
                != canonical_digest(&self.original)
                    .map_err(|_| unavailable())?
                    .as_str()
            || value["sourceBundleDigest"] != *self.entry.source.digest()
        {
            return Err(unavailable());
        }
        decode_target_images(
            &value["targetImages"],
            &self.entry.source,
            &self.original["context"],
            &self.confirmed.manifest,
            &self.original["implementationDigest"],
        )
    }
}

fn verify_raw_invocation_pin(original: &Value, blob: &BlobRef) -> AppResult<()> {
    // Runtime retains encode_json bytes. Canonical invocation identity is a
    // separate key: JCS normalizes valid native f64 coordinates such as 0.0.
    let bytes = mmmm_contracts::encode_json(original).map_err(|_| unavailable())?;
    if blob.digest != raw_digest(&bytes) || blob.byte_length != bytes.len() as u64 {
        return Err(denied());
    }
    Ok(())
}

fn validate_precondition_batch(
    conditions: &[&Value],
    frozen: &[Value],
    targets: &[TargetId],
) -> AppResult<()> {
    if !matches!(targets.len(), 1 | 95)
        || (targets.len() == 1 && targets[0].as_str() != PACK_CASE_TARGET)
        || conditions.len() != targets.len()
        || frozen.len() != targets.len()
    {
        return Err(denied());
    }
    let mut subjects = BTreeSet::new();
    for ((condition, original), target) in conditions.iter().zip(frozen).zip(targets) {
        exact(condition, &["kind", "subject", "expected", "coverage"])?;
        if *condition != original
            || condition["kind"] != "resource_hash"
            || condition["coverage"] != "full_target"
            || condition["subject"] != target.as_str()
            || !subjects.insert(target.as_str())
        {
            return Err(denied());
        }
        Sha256Digest::new(condition["expected"].as_str().ok_or_else(unavailable)?)
            .map_err(|_| unavailable())?;
    }
    Ok(())
}

fn decode_target_images(
    envelope: &Value,
    source: &BootstrapSource,
    context: &Value,
    manifest: &Value,
    implementation: &Value,
) -> AppResult<Vec<BeforeImage>> {
    let images = decode_preflight_target_images(
        envelope,
        &source.targets,
        context,
        manifest,
        implementation,
    )?;
    for (image, (target, expected)) in images.iter().zip(&source.expected) {
        if image.target != *target
            || expected.digest != raw_digest(&image.bytes)
            || expected.byte_length != image.bytes.len() as u64
        {
            return Err(unavailable());
        }
    }
    Ok(images)
}

fn decode_preflight_target_images(
    envelope: &Value,
    targets: &[TargetId],
    context: &Value,
    manifest: &Value,
    implementation: &Value,
) -> AppResult<Vec<BeforeImage>> {
    exact(
        envelope,
        &[
            "protocolVersion",
            "environment",
            "contextId",
            "contextDigest",
            "runtimeSourceFactsDigest",
            "hostArtifactDigest",
            "registryGeneration",
            "targets",
            "observedFromTick",
            "observedToTick",
            "observedAt",
        ],
    )?;
    if envelope["protocolVersion"] != mmmm_contracts::CONTRACT_VERSION
        || envelope["environment"] != context["environment"]
        || envelope["contextId"] != context["contextId"]
        || envelope["contextDigest"] != context["contextDigest"]
        || envelope["registryGeneration"] != manifest["registryGeneration"]
        || envelope["runtimeSourceFactsDigest"] != manifest["runtimeSourceFactsDigest"]
        || &envelope["hostArtifactDigest"] != implementation
        || envelope["observedFromTick"].as_u64().is_none()
        || envelope["observedToTick"]
            .as_u64()
            .is_none_or(|end| end < envelope["observedFromTick"].as_u64().unwrap_or(u64::MAX))
        || time::OffsetDateTime::parse(
            envelope["observedAt"].as_str().ok_or_else(unavailable)?,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
    {
        return Err(unavailable());
    }
    if !matches!(targets.len(), 1 | 95)
        || (targets.len() == 1 && targets[0].as_str() != PACK_CASE_TARGET)
        || targets
            .iter()
            .map(TargetId::as_str)
            .collect::<BTreeSet<_>>()
            .len()
            != targets.len()
    {
        return Err(unavailable());
    }
    let values = envelope["targets"]
        .as_array()
        .filter(|v| v.len() == targets.len())
        .ok_or_else(unavailable)?;
    let mut total = 0usize;
    values
        .iter()
        .zip(targets)
        .map(|(image, target)| {
            exact(image, &["targetId", "rawBytesHex", "rawSha256"])?;
            if image["targetId"] != target.as_str() {
                return Err(unavailable());
            }
            let bytes = decode_hex(image["rawBytesHex"].as_str().ok_or_else(unavailable)?)?;
            total = total.checked_add(bytes.len()).ok_or_else(unavailable)?;
            if total > MAX_IMAGE_BYTES || image["rawSha256"] != raw_digest(&bytes).as_str() {
                return Err(unavailable());
            }
            Ok(BeforeImage {
                target: target.as_str().into(),
                bytes,
            })
        })
        .collect()
}

pub(crate) fn validate_plan(plan: &Value, source: &BootstrapSource) -> AppResult<()> {
    verify_projected_digest("ExecutionPlan", plan).map_err(|_| unavailable())?;
    let steps = plan["steps"]
        .as_array()
        .filter(|v| v.len() == 1)
        .ok_or_else(unavailable)?;
    let step = &steps[0];
    if plan["approvalRequirement"] != "explicit_approval"
        || plan["atomicity"] != "none"
        || plan["contextPins"].as_array().is_none_or(|v| v.len() != 1)
        || plan["preconditions"] != json!(source.preconditions())
        || step["actionId"] != action_for_kind(source.kind)
        || step["arguments"] != source.arguments()
        || step["recovery"] != "none"
        || step["completion"] != "synchronous"
        || step["verificationRequirement"] != "independent_readback"
        || !matches!(step["effect"].as_str(), Some("write" | "unknown"))
        || step["resultBindings"]
            .as_array()
            .is_none_or(|v| !v.is_empty())
        || step["dependsOn"].as_array().is_none_or(|v| !v.is_empty())
        || step["resourcesRead"] != json!(source.targets)
        || step["resourcesWritten"] != json!(source.targets)
        || plan["scope"]["externalTargetIds"] != json!(source.targets)
        || ["resourceIds", "objectIds", "regions"].iter().any(|field| {
            plan["scope"][*field]
                .as_array()
                .is_none_or(|v| !v.is_empty())
        })
    {
        return Err(unavailable());
    }
    Ok(())
}
pub(crate) fn exact(value: &Value, fields: &[&str]) -> AppResult<()> {
    if value
        .as_object()
        .is_none_or(|v| v.len() != fields.len() || fields.iter().any(|f| !v.contains_key(*f)))
    {
        return Err(unavailable());
    }
    Ok(())
}
fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn decode_hex(value: &str) -> AppResult<Vec<u8>> {
    if value.len() > MAX_IMAGE_BYTES * 2 || value.len() & 1 != 0 {
        return Err(unavailable());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let digit = |v: u8| match v {
                b'0'..=b'9' => Some(v - b'0'),
                b'a'..=b'f' => Some(v - b'a' + 10),
                _ => None,
            };
            Ok(digit(chunk[0]).ok_or_else(unavailable)? * 16
                + digit(chunk[1]).ok_or_else(unavailable)?)
        })
        .collect()
}
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> AppResult<T> {
    serde_json::from_value(value.clone()).map_err(|_| unavailable())
}
fn storage(cause: StorageError) -> AppError {
    AppError::storage("CALIBRATION_BOOTSTRAP_UNAVAILABLE", cause)
}
fn request_error(cause: crate::service::ServiceError) -> AppError {
    AppError::caused_by(cause.code, cause.message, cause)
}
fn denied() -> AppError {
    AppError::new(
        "PERMISSION_REQUIRED",
        "Original bootstrap owner, plan, scope or request changed",
    )
}
fn unavailable() -> AppError {
    AppError::new(
        "CAPABILITY_UNAVAILABLE",
        "Actual protected bootstrap source, approval or target images are unavailable",
    )
}
#[derive(Debug)]
struct RetainedFailure(Arc<AppError>);
impl std::fmt::Display for RetainedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Original bootstrap approval publication failed")
    }
}
impl std::error::Error for RetainedFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_source_recipe_and_empty_registry_do_not_issue_a_private_route() {
        // Existing numeric capacity fixtures cannot represent this separate
        // closed recipe. Pure bytes and matching command names issue no owner.
        let numeric = CalibrationDispatchPlan::normative47().unwrap();
        let pack = CalibrationPackProgram::java_26_3().unwrap();
        let entries =
            render_source_entries_for_kind(CalibrationSourceKind::PackCase, &numeric, &|| Ok(()))
                .unwrap();
        assert_eq!(entries.as_array().unwrap().len(), 3);
        assert_eq!(
            raw_digest(pack.canonical_recipe_bytes()),
            *pack.program_digest()
        );
        assert_ne!(canonical_digest(&entries).unwrap(), *pack.program_digest());
        let requirements = absence_requirements_for_kind(
            CalibrationSourceKind::PackCase,
            &json!(canonical_digest(&entries).unwrap()),
        )
        .unwrap();
        assert_eq!(requirements.len(), 1);
        assert_eq!(requirements[0]["targetId"], PACK_CASE_TARGET);
        assert!(kind_for_purpose("pack_calibration_bootstrap/2").is_none());
        assert!(
            !BootstrapRegistry::default()
                .handles_original(
                    &json!({"actionId":PACK_ACTION,"arguments":{"command":PACK_COMMAND}})
                )
                .unwrap()
        );
    }
    use mmmm_contracts::{
        ContractValidator, JsonLimits, encode_json, parse_json_with_limits, projected_digest,
    };

    #[test]
    fn durable_invocation_pin_uses_raw_json_bytes_for_valid_f64_coordinates() {
        // Existing wire fixture only. No durable intent, owner, ADMIN receipt
        // or registry is issued by testing this pure byte comparison.
        let original: Value =
            serde_json::from_slice(include_bytes!("../../../examples/invocation.json")).unwrap();
        let mut with_f64 = original.clone();
        with_f64["context"]["origin"] = json!([0.0_f64, 64.0_f64, 0.0_f64]);
        with_f64["context"]["rotationDegrees"] = json!([0.0_f64, 0.0_f64]);
        ContractValidator::shared()
            .unwrap()
            .validate("Invocation", &with_f64)
            .unwrap();
        let canonical = canonical_digest(&with_f64).unwrap();
        assert_eq!(canonical, canonical_digest(&original).unwrap());
        let bytes = encode_json(&with_f64).unwrap();
        let pin = BlobRef {
            digest: raw_digest(&bytes),
            byte_length: bytes.len() as u64,
        };
        assert_ne!(pin.digest, canonical);
        assert!(verify_raw_invocation_pin(&with_f64, &pin).is_ok());
        let canonical_pin = BlobRef {
            digest: canonical,
            byte_length: pin.byte_length,
        };
        assert!(verify_raw_invocation_pin(&with_f64, &canonical_pin).is_err());
        let wrong_length = BlobRef {
            digest: pin.digest,
            byte_length: pin.byte_length + 1,
        };
        assert!(verify_raw_invocation_pin(&with_f64, &wrong_length).is_err());
    }

    fn node_count(value: &Value) -> usize {
        1 + match value {
            Value::Array(values) => values.iter().map(node_count).sum::<usize>(),
            Value::Object(values) => values.values().map(node_count).sum::<usize>(),
            _ => 0,
        }
    }
    fn assert_full_control_frame(value: &Value) -> (usize, usize) {
        let bytes = encode_json(value).unwrap();
        let nodes = node_count(value);
        assert!(
            bytes.len() <= crate::rpc::MAX_CONTROL_BYTES,
            "expanded bytes: {}",
            bytes.len()
        );
        assert!(
            nodes <= crate::rpc::MAX_CONTROL_NODES,
            "expanded nodes: {nodes}"
        );
        assert_eq!(
            parse_json_with_limits(
                &bytes,
                JsonLimits {
                    max_bytes: crate::rpc::MAX_CONTROL_BYTES,
                    max_depth: 64,
                    max_nodes: crate::rpc::MAX_CONTROL_NODES
                }
            )
            .unwrap(),
            *value
        );
        (bytes.len(), nodes)
    }

    fn capacity_failure_tree() -> Value {
        let leaf = || {
            json!({"type":"java.lang.RuntimeException","code":null,
            "cause":null,"suppressed":[],"truncated":false})
        };
        let children = (0..8)
            .map(|index| {
                let mut child = leaf();
                child["suppressed"] = json!(
                    (0..if index == 7 { 2 } else { 3 })
                        .map(|_| leaf())
                        .collect::<Vec<_>>()
                );
                child
            })
            .collect::<Vec<_>>();
        let mut root = leaf();
        root["suppressed"] = json!(children);
        root
    }

    fn successor_capacity_payload(
        context: &Value,
        programs: &Value,
        entries: &Value,
        bundle: &Sha256Digest,
        native_nbt_bytes: usize,
    ) -> Value {
        // Serialization layout only. These bytes do not represent a native
        // objective, a loaded function, an actual attempt or completed pairing.
        // The configurable NBT width prevents a small textual placeholder from
        // hiding its bytesHex -> rawBytesHex double expansion.
        let native_bytes = vec![0u8; native_nbt_bytes];
        let native_nbt = json!({"format":"minecraft.nbt.named-compound/uncompressed",
            "bytesHex":encode_hex(&native_bytes),"sha256":raw_digest(&native_bytes),"rawFloatingBits":[]});
        let mut functions = Vec::new();
        let mut images = Vec::new();
        for program in programs.as_array().unwrap() {
            let function = program["functionId"].as_str().unwrap();
            let suffix = function.strip_prefix("mmmm_calibration:").unwrap();
            let path = format!("data/mmmm_calibration/function/{suffix}.mcfunction");
            let entry = entries
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["path"] == path)
                .unwrap();
            functions.push(json!({"functionId":function,
                "resourceId":format!("mmmm_calibration:function/{suffix}.mcfunction"),
                "sourcePackId":"file/mmmm-calibration-normative47",
                "rawSha256":entry["rawSha256"],"byteLength":entry["byteLength"]}));
            let objective = program["objective"].as_str().unwrap();
            let storage = program["storage"].as_str().unwrap();
            let objective_id = format!("calibration-objective-{objective}");
            let storage_id = format!("calibration-storage-{}", raw_digest(storage.as_bytes()));
            let objective_image = json!({"format":"mmmm.native.calibration-target/1",
                "selector":{"targetId":objective_id,"kind":"objective","objective":objective},
                "status":"known","presence":"present","membershipScope":"current_native_scoreboard",
                "captureScope":"native_objective_and_all_scores","coverage":"full_target","reason":null,
                "payload":{"nativeObjectiveNbt":native_nbt,"scores":[],"displaySlots":[]}});
            let storage_image = json!({"format":"mmmm.native.calibration-target/1",
                "selector":{"targetId":storage_id,"kind":"owned_storage","storage":storage,"ownedSubtrees":["inputs","invocation"]},
                "status":"known","presence":"absent","membershipScope":"current_cached_command_storage",
                "captureScope":"native_owned_storage_subtrees","coverage":"full_target","reason":null,
                "payload":{"storagePresent":false,"inputs":{"presence":"absent","nativeValueNbt":null},
                    "invocation":{"presence":"absent","nativeValueNbt":null}}});
            for (id, image) in [(objective_id, objective_image), (storage_id, storage_image)] {
                let bytes = canonical_bytes(&image).unwrap();
                images.push(json!({"targetId":id,"rawBytesHex":encode_hex(&bytes),"rawSha256":raw_digest(&bytes)}));
            }
        }
        let mut original: Value =
            serde_json::from_slice(include_bytes!("../../../examples/invocation.json")).unwrap();
        original["contextId"] = context["contextId"].clone();
        original["context"] = context.clone();
        original["contextDigest"] = context["contextDigest"].clone();
        original["actionId"] = json!(ACTION);
        original["arguments"] = json!({"sourceBundleDigest":bundle});
        original["argumentsDigest"] = json!(canonical_digest(&original["arguments"]).unwrap());
        let mut successor = context.clone();
        successor["environment"]["sessionEpoch"] = json!("capacity-successor-epoch");
        successor["contextDigest"] =
            json!(projected_digest("ExecutionContext", &successor).unwrap());
        let file_facts = entries.as_array().unwrap().iter().map(|entry| json!({
            "path":entry["path"],"byteLength":entry["byteLength"],"rawSha256":entry["rawSha256"]
        })).collect::<Vec<_>>();
        json!({"format":"mmmm.native.calibration-bootstrap-successor/1",
            "originalInvocation":original,"frozenManifestDigest":raw_digest(b"capacity manifest label only"),
            "sourceBundleDigest":bundle,"currentContext":successor,
            "history":{"originalResult":null,"originalFailure":capacity_failure_tree(),"resultTerminal":true,
                "effectPhase":"reload_future_returned","fileFacts":{"sourceBundleDigest":bundle,"verifiedFileCount":48,"files":file_facts},
                "initializationAttemptedCount":47,"initializationReturns":vec![1;47],"reloadOutcome":"failed",
                "reloadFailure":capacity_failure_tree(),"rootAnchorReserved":false,"rootAnchorRecorded":false,
                "rootRetirement":null,"rootRetirementFailure":null},
            "observation":{"format":"mmmm.native.calibration-bootstrap-observation/2","observedFromTick":"0","observedToTick":"0",
                "pack":{"status":"unknown","reason":"retained_root_not_published","identityContinuity":"unproven",
                    "currentBytes":"not_observed","fullPackMembership":"unproven","retainedRoot":null,"failure":null},
                "loadedSourceTrace":{"format":"mmmm.native.calibration-loaded-source-trace/1","armAttempted":false,
                    "receiptOrigin":"none","receiptBytesHex":null,"failure":null,"currentFailure":null},
                "loadedSources":{"status":"known","causalLink":"unproven","functions":functions,"failure":null},
                "targetImages":{"status":"known","targets":images,"failure":null}}})
    }

    #[test]
    fn normative_bootstrap_full_approval_and_ready_frames_fit_current_control_limits() {
        // Capacity and closed-grammar regression only. The original 48 source
        // bodies, 47 init recipes and all 95 requirement images are expanded.
        // Synthetic context/envelopes issue no Store association, ADMIN receipt,
        // registry entry, known game state, pairing or successful bootstrap.
        let suite = CalibrationDispatchPlan::normative47().unwrap();
        let entries = render_source_entries(&suite, &|| Ok(())).unwrap();
        assert_eq!(entries.as_array().unwrap().len(), 48);
        for (entry, (path, raw)) in entries
            .as_array()
            .unwrap()
            .iter()
            .zip(suite.source_entries())
        {
            assert_eq!(entry["path"], path.as_str());
            assert_eq!(entry["rawBytesHex"], encode_hex(raw));
            assert_eq!(entry["byteLength"], raw.len() as u64);
        }
        let bundle_digest = canonical_digest(&entries).unwrap();
        let raw = canonical_bytes(&entries).unwrap();
        let bundle = json!({"bundleDigest":bundle_digest,"rawResource":{
            "resourceId":"capacity-bootstrap-source","sha256":raw_digest(&raw),"sizeBytes":raw.len(),
            "mediaType":"application/vnd.mmmm.calibration-bootstrap-source+json"},"entries":entries});
        let programs = Value::Array(
            suite
                .programs()
                .iter()
                .map(render_program)
                .collect::<AppResult<Vec<_>>>()
                .unwrap(),
        );
        assert_eq!(programs.as_array().unwrap().len(), 47);
        let requirements = absence_requirements(&suite, &bundle["bundleDigest"]);
        assert_eq!(requirements.len(), 95);
        let ordered_targets = validated_bootstrap_target_ids(&suite).unwrap();
        let targets = ordered_targets
            .iter()
            .map(|id| json!(id))
            .collect::<Vec<_>>();
        assert_eq!(
            requirements
                .iter()
                .map(|value| value["targetId"].clone())
                .collect::<Vec<_>>(),
            targets
        );
        let scope_targets = normative_bootstrap_target_ids().unwrap();
        assert_eq!(scope_targets.len(), 95);
        assert_eq!(
            ordered_targets
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect::<BTreeSet<_>>(),
            scope_targets
        );
        let conditions = requirements
            .iter()
            .map(|value| {
                json!({"kind":"resource_hash","subject":value["targetId"],
            "expected":raw_digest(&canonical_bytes(value).unwrap()),"coverage":"full_target"})
            })
            .collect::<Vec<_>>();
        let condition_refs = conditions.iter().collect::<Vec<_>>();
        assert!(
            validate_precondition_batch(&condition_refs, &conditions, &ordered_targets).is_ok()
        );
        assert!(
            validate_precondition_batch(&condition_refs[..94], &conditions, &ordered_targets)
                .is_err()
        );
        let mut reordered = condition_refs.clone();
        reordered.swap(1, 2);
        assert!(validate_precondition_batch(&reordered, &conditions, &ordered_targets).is_err());
        let mut duplicated = condition_refs.clone();
        duplicated[2] = duplicated[1];
        assert!(validate_precondition_batch(&duplicated, &conditions, &ordered_targets).is_err());
        let mut wrong_distribution = ordered_targets.clone();
        wrong_distribution.swap(1, 2);
        assert!(
            validate_precondition_batch(&condition_refs, &conditions, &wrong_distribution).is_err()
        );
        let mut context: Value =
            serde_json::from_slice(include_bytes!("../../../examples/execution-context.json"))
                .unwrap();
        context["scope"]["externalTargetIds"] = json!(targets);
        context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
        let principal = PrincipalId::new(context["principalRef"].as_str().unwrap()).unwrap();
        let digest = raw_digest(b"capacity labels only; no actual source, host or approval");
        let generation = json!("capacity-generation");
        let plan = json!({"projectId":context["projectId"],"planId":"capacity-bootstrap-plan","planHash":digest,
            "policyRevision":context["policyRevision"],"expiresAt":"2099-01-01T00:00:00Z",
            "contextPins":[{"contextId":context["contextId"],"contextDigest":context["contextDigest"],"environment":context["environment"]}],
            "preconditions":conditions,"steps":[{"stepId":"calibration-bootstrap","bindingId":"capacity-native-binding",
                "actionId":ACTION,"actionDigest":digest,"implementationDigest":digest,"contextId":context["contextId"],
                "arguments":{"sourceBundleDigest":bundle_digest},"resourcesRead":targets,"resourcesWritten":targets}]});
        let manifest = render_manifest(ManifestRendering {
            kind: CalibrationSourceKind::Numeric47,
            plan: &plan,
            context: &context,
            bundle: &bundle,
            programs: &programs,
            recipe: suite.suite_digest(),
            principal: &principal,
            generation: &generation,
            source_facts_digest: &digest,
        })
        .unwrap();
        let authority = json!({"kind":"host_apply_approval_authority","protocolVersion":mmmm_contracts::CONTRACT_VERSION,
            "nonce":"capacity-bootstrap","purpose":PURPOSE,"contexts":[context],"approvedSources":{"mmmm_host":digest},
            "approvedActions":[digest],"permissions":["mmmm:world_read","mmmm:command_complete","mmmm:provider_inventory"],
            "manifest":manifest});
        let approval_frame =
            crate::peer_management::PublicFrame::from_value(authority.clone()).unwrap();
        let encoded = approval_frame.encode().unwrap();
        assert_eq!(
            crate::peer_management::PublicFrame::decode(encoded.payload())
                .unwrap()
                .value(),
            &authority
        );
        let approval_capacity = assert_full_control_frame(&authority);

        let images=requirements.iter().map(|value|{
            let raw=canonical_bytes(value).unwrap();
            json!({"targetId":value["targetId"],"rawBytesHex":encode_hex(&raw),"rawSha256":raw_digest(&raw)})
        }).collect::<Vec<_>>();
        let ready = json!({"format":"mmmm.native.calibration-bootstrap-ready/1","invocationId":"capacity-bootstrap-invocation",
            "invocationDigest":digest,"sourceBundleDigest":bundle_digest,"targetImages":{
                "protocolVersion":mmmm_contracts::CONTRACT_VERSION,"environment":context["environment"],"contextId":context["contextId"],
                "contextDigest":context["contextDigest"],"runtimeSourceFactsDigest":digest,"hostArtifactDigest":digest,
                "registryGeneration":generation,"targets":images,"observedFromTick":0,"observedToTick":0,
                "observedAt":"2026-01-01T00:00:00Z"}});
        // Independent synthetic phases exercise the stateless preflight
        // decoder only. No cache, current-state witness or phase acceptance is
        // issued: Application must decide whether each actual digest fits.
        let first = decode_preflight_target_images(
            &ready["targetImages"],
            &ordered_targets,
            &context,
            &manifest,
            &json!(digest),
        )
        .unwrap();
        let mut second = ready["targetImages"].clone();
        second["observedFromTick"] = json!(1);
        second["observedToTick"] = json!(1);
        let mut changed_observation = requirements[0].clone();
        changed_observation["presence"] = json!("present");
        let changed_raw = canonical_bytes(&changed_observation).unwrap();
        second["targets"][0]["rawBytesHex"] = json!(encode_hex(&changed_raw));
        second["targets"][0]["rawSha256"] = json!(raw_digest(&changed_raw));
        let second = decode_preflight_target_images(
            &second,
            &ordered_targets,
            &context,
            &manifest,
            &json!(digest),
        )
        .unwrap();
        assert_ne!(raw_digest(&first[0].bytes), raw_digest(&second[0].bytes));
        assert_ne!(
            raw_digest(&second[0].bytes).as_str(),
            conditions[0]["expected"].as_str().unwrap()
        );
        let response = json!({"protocolVersion":mmmm_contracts::CONTRACT_VERSION,"requestId":"capacity-bootstrap-response",
            "status":"ok","payload":ready,"eventSequence":"0"});
        ContractValidator::shared()
            .unwrap()
            .validate("HostResponse", &response)
            .unwrap();
        let rpc = json!({"jsonrpc":"2.0","id":"capacity-bootstrap-response","result":response});
        let ready_capacity = assert_full_control_frame(&rpc);
        println!(
            "capacity only: approval={} bytes/{} nodes; ready HostResponse RPC={} bytes/{} nodes",
            approval_capacity.0, approval_capacity.1, ready_capacity.0, ready_capacity.1
        );

        // The earlier approval/absence-ready frames contain neither successor
        // history, its two bounded error trees, the current 47 source rows nor
        // the 94 current target encodings. Cover the whole new wire layout.
        // 256-byte NBT is a representative capacity width, not an observed
        // native Objective.Packed size or proof that all real states fit.
        let successor =
            successor_capacity_payload(&context, &programs, &entries, &bundle_digest, 256);
        assert_eq!(
            successor["observation"]["loadedSources"]["functions"]
                .as_array()
                .unwrap()
                .len(),
            47
        );
        assert_eq!(
            successor["observation"]["targetImages"]["targets"]
                .as_array()
                .unwrap()
                .len(),
            94
        );
        let successor_capacity = assert_full_control_frame(&successor);
        assert!(
            successor_capacity.0 <= 256 * 1024,
            "Java payload: {}",
            successor_capacity.0
        );
        let mut actual_result_layout: Value =
            serde_json::from_slice(include_bytes!("../../../examples/provider-result.json"))
                .unwrap();
        actual_result_layout["effects"] = json!("unknown");
        actual_result_layout["data"] = json!({"completionClaim":"bootstrap_reload_observation_only",
            "sourceBundleDigest":bundle_digest,"installedFileCount":48,"initializedObjectiveCount":47,"reloadOutcome":"completed"});
        ContractValidator::shared()
            .unwrap()
            .validate("ProviderResult", &actual_result_layout)
            .unwrap();
        let mut with_result = successor.clone();
        with_result["history"]["originalResult"] = actual_result_layout;
        with_result["history"]["originalFailure"] = Value::Null;
        with_result["history"]["reloadOutcome"] = json!("completed");
        with_result["history"]["reloadFailure"] = Value::Null;
        assert!(assert_full_control_frame(&with_result).0 <= 256 * 1024);
        let successor_response = json!({"protocolVersion":mmmm_contracts::CONTRACT_VERSION,
            "requestId":"capacity-successor-response","status":"ok","payload":successor,"eventSequence":"0"});
        ContractValidator::shared()
            .unwrap()
            .validate("HostResponse", &successor_response)
            .unwrap();
        let successor_rpc =
            json!({"jsonrpc":"2.0","id":"capacity-successor-response","result":successor_response});
        let successor_rpc_capacity = assert_full_control_frame(&successor_rpc);
        // A raw-target budget alone cannot ensure the stricter Java payload
        // budget: hex doubles the outer bytes, including the inner NBT hex.
        let wider = successor_capacity_payload(&context, &programs, &entries, &bundle_digest, 1024);
        let raw_targets = wider["observation"]["targetImages"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|image| image["rawBytesHex"].as_str().unwrap().len() / 2)
            .sum::<usize>();
        assert!(raw_targets <= 192 * 1024);
        assert!(encode_json(&wider).unwrap().len() > 256 * 1024);
        assert_full_control_frame(&wider);
        println!(
            "capacity only: successor={} bytes/{} nodes; wrapped={} bytes/{} nodes; wider raw={} bytes exceeds Java payload",
            successor_capacity.0,
            successor_capacity.1,
            successor_rpc_capacity.0,
            successor_rpc_capacity.1,
            raw_targets
        );

        // One mutation reuses the same fully expanded input. Digest knowledge
        // and an otherwise fitting frame cannot replace an original body pin.
        let mut changed = authority;
        changed["manifest"]["sourceBundle"]["entries"][0]["rawSha256"] = json!("0".repeat(64));
        assert!(crate::peer_management::PublicFrame::from_value(changed).is_err());
    }
}

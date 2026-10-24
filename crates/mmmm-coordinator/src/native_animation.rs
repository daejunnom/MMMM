//! 실제 요청의 owned Clip을 sealed scene의 인스턴스별 binding과 조합한다.
//! 이 경로는 컴파일 입력만 만들며 재생, target 검증이나 source 권한을 발급하지 않는다.

use crate::{
    auth::AuthenticatedPrincipal,
    planning_source::{
        BorrowedProjectSource, LocalPlanningAccess, PlanningStore, SharedPlanningData,
    },
    service::{RequestBudget, RequestContextWitness},
};
use mmmm_application::{Access, AppError, AppResult};
use mmmm_compiler::{
    PackBuildInputs, VerifiedTarget,
    animation::{
        AnimationBindingVerifier, AnimationBindings, AnimationCompileSettings, AnimationDraft,
        AnimationEventBinding, AnimationEvidenceVerifier, AnimationTargetRules,
        VerifiedAnimationBindings, animation_compile,
    },
    scene::SceneDraft,
};
use mmmm_contracts::{
    ClipId, ContractValidator, RationalTime, ResourceId, Sha256Digest, SymbolId, canonical_digest,
    encode_json, raw_digest, verify_projected_digest,
};
use mmmm_domain::{
    DomainError,
    time::{AnimationClip, validate_clip},
    types::ResourceRef,
};
use mmmm_planner::{OwnedKind, ProjectCatalog, ProjectSourcePort};
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, Write},
};

const MAX_ITEMS: usize = 4096;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_ANIMATION_NODES: usize = 1024;

/// 실제 source/evidence 소유자가 현재 frame을 확인하고 제공하는 call 한 개다.
/// 기본 성공 구현이나 DTO에서 이 port를 등록하는 경로는 없다.
pub trait NativeAnimationCallOwner {
    fn for_call<'call, 'store>(
        &'call self,
        frame: &'call NativeAnimationFrame<'call, 'store>,
    ) -> AppResult<Box<dyn NativeAnimationCall + 'call>>;
}

/// 기존 compiler verifier가 같은 원 Store·요청·target에서 동작하도록 묶는다.
/// binding_snapshot은 실제 불변 snapshot을 보존한 뒤 그 pin을 반환해야 한다.
/// 이벤트는 원 symbol에 해당하는 승인된 함수 bytes와 contract만 제공한다.
pub trait NativeAnimationCall: AnimationBindingVerifier + AnimationEvidenceVerifier {
    fn check_current(&self) -> AppResult<()>;
    fn settings(&self) -> AppResult<AnimationCompileSettings>;
    fn event_bindings(
        &self,
        clip: &AnimationClip,
    ) -> AppResult<BTreeMap<SymbolId, AnimationEventBinding>>;
    fn binding_snapshot(
        &self,
        bindings: &AnimationBindings,
        canonical_bytes: &[u8],
    ) -> AppResult<ResourceRef>;
}

/// constructor는 backend 내부에 한정한다. Store를 reopen하거나 수명을 연장하지
/// 않으며 request의 private generation과 기존 budget/cancellation을 그대로 빌린다.
pub struct NativeAnimationFrame<'call, 'store> {
    store: &'call PlanningStore<'store>,
    request: &'call RequestContextWitness,
    access: &'call LocalPlanningAccess,
    data: &'call SharedPlanningData,
    project: &'call ProjectCatalog,
    context: &'call Value,
    target: &'call VerifiedTarget,
    owned: &'call [Value],
}
impl<'call, 'store> NativeAnimationFrame<'call, 'store> {
    #[allow(
        clippy::too_many_arguments,
        reason = "Actual Store/request, authorized sources, context and independently verified target remain separate borrowed inputs"
    )]
    pub(crate) fn new(
        store: &'call PlanningStore<'store>,
        request: &'call RequestContextWitness,
        access: &'call LocalPlanningAccess,
        data: &'call SharedPlanningData,
        project: &'call ProjectCatalog,
        context: &'call Value,
        target: &'call VerifiedTarget,
        owned: &'call [Value],
    ) -> Self {
        Self {
            store,
            request,
            access,
            data,
            project,
            context,
            target,
            owned,
        }
    }
    pub fn store(&self) -> &PlanningStore<'store> {
        self.store
    }
    pub fn request(&self) -> &RequestContextWitness {
        self.request
    }
    pub fn authenticated(&self) -> &AuthenticatedPrincipal {
        self.request.authenticated()
    }
    pub fn budget(&self) -> &RequestBudget {
        self.request.budget()
    }
    pub fn project(&self) -> &ProjectCatalog {
        self.project
    }
    pub fn context(&self) -> &Value {
        self.context
    }
    pub fn target(&self) -> &VerifiedTarget {
        self.target
    }
    pub fn owned(&self) -> &[Value] {
        self.owned
    }

    pub fn check_local(&self) -> AppResult<()> {
        self.request.check_local().map_err(service_error)?;
        self.access.check()?;
        if self.request.method() != "pack.build"
            || self.authenticated().principal() != self.access.principal()
            || self.budget().deadline() != self.access.budget().deadline()
            || !std::ptr::eq(
                self.budget().cancellation(),
                self.access.budget().cancellation(),
            )
            || self.context["projectId"] != self.project.project_id().as_str()
            || self.context["principalRef"] != self.authenticated().principal().as_str()
            || self.project.target_profile_id() != self.target.profile_id()
        {
            return Err(denied());
        }
        Ok(())
    }

    /// 실제 current ACL과 Project head를 재검사한다. host/ACL I/O 중 SQLite
    /// borrow를 유지하지 않으며 retained source를 현재 권한으로 바꾸지 않는다.
    pub fn check_current(&self) -> AppResult<()> {
        self.check_local()?;
        self.access.authorize_project(
            self.access.principal(),
            self.project.project_id(),
            Some(self.context),
            Access::Plan,
        )?;
        self.store.with_read(|store| {
            let actual = store
                .project(self.project.project_id())
                .map_err(|error| AppError::storage("SOURCE_UNAVAILABLE", error))?;
            if actual != *self.project.project() {
                return Err(conflict());
            }
            Ok(())
        })?;
        self.check_local()
    }

    fn check_owned(&self) -> AppResult<()> {
        self.check_current()?;
        let mut source =
            BorrowedProjectSource::new(self.store.clone(), self.access.clone(), self.data.clone());
        // 기존 reader가 실제 원 bytes/blob, canonical revision 및 source ACL을
        // 검사한다. Value를 재인코딩한 digest만으로 원 bytes 검사를 대체하지 않는다.
        let actual =
            source.inspect_owned(self.access.principal(), self.project, MAX_BYTES as u64)?;
        if actual.len() != self.owned.len() || actual.len() > MAX_ITEMS {
            return Err(conflict());
        }
        let mut supplied = BTreeMap::new();
        for value in self.owned {
            self.check_local()?;
            let digest = canonical_digest(value).map_err(|_| invalid())?;
            if supplied.insert(digest, value).is_some() {
                return Err(conflict());
            }
        }
        for (_, value) in &actual {
            self.check_local()?;
            let digest = canonical_digest(value).map_err(|_| invalid())?;
            if supplied.get(&digest).copied() != Some(value) {
                return Err(conflict());
            }
        }
        self.check_current()
    }
}

pub(crate) fn lower_owned_animations(
    owner: Option<&dyn NativeAnimationCallOwner>,
    frame: &NativeAnimationFrame<'_, '_>,
    scene: SceneDraft,
) -> AppResult<PackBuildInputs> {
    frame.check_owned()?;
    let owner = owner.ok_or_else(unavailable)?;
    let call = checked(|| frame.check_current(), || owner.for_call(frame))?;
    let check = || {
        frame.check_current()?;
        let current = call.check_current();
        finish(current, frame.check_current())
    };
    let result = assemble_owned_animations(
        frame.project,
        frame.owned,
        scene,
        frame.target,
        call.as_ref(),
        &check,
    );
    finish(result, frame.check_owned())
}

/// 순수 조합 자체는 기존 sealed compiler 타입을 소비한다. production 진입은
/// 위 actual frame 경로이며 이 함수는 별도 runtime grant나 ledger를 만들지 않는다.
pub(crate) fn assemble_owned_animations(
    project: &ProjectCatalog,
    owned: &[Value],
    scene: SceneDraft,
    target: &VerifiedTarget,
    call: &dyn NativeAnimationCall,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<PackBuildInputs> {
    check()?;
    if owned.len() > MAX_ITEMS
        || scene.required_animation_bindings().len() > MAX_ITEMS
        || scene.input_revision() != project.revision()
        || scene.target_profile_digest() != target.profile_digest()
        || scene.target_artifact_digest() != target.artifact_digest()
    {
        return Err(conflict());
    }
    let mut clips = BTreeMap::new();
    let mut bytes = 0usize;
    for value in owned.iter().filter(|value| value.get("clipId").is_some()) {
        check()?;
        let encoded = encode_json(value).map_err(|_| invalid())?;
        if encoded.len() > MAX_DOCUMENT_BYTES {
            return Err(budget_error());
        }
        bytes = bytes
            .checked_add(encoded.len())
            .filter(|bytes| *bytes <= MAX_BYTES)
            .ok_or_else(budget_error)?;
        ContractValidator::shared()
            .and_then(|validator| validator.validate("AnimationClip", value))
            .map_err(|_| invalid())?;
        let clip: AnimationClip = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        validate_clip(&clip).map_err(domain_error)?;
        let pin = project.owned_pin(OwnedKind::Clip, clip.clip_id.as_str())?;
        if verify_projected_digest("AnimationClip", value)
            .ok()
            .as_ref()
            != Some(&pin.revision)
            || clip.revision != pin.revision
        {
            return Err(conflict());
        }
        if clips.insert(clip.clip_id.clone(), (clip, value)).is_some() {
            return Err(conflict());
        }
    }
    let pinned: BTreeSet<_> = project
        .pins()
        .iter()
        .filter(|pin| pin.kind == OwnedKind::Clip)
        .map(|pin| pin.object_id.to_string())
        .collect();
    let actual: BTreeSet<_> = clips.keys().map(ToString::to_string).collect();
    let bound: BTreeSet<_> = scene
        .required_animation_bindings()
        .iter()
        .map(|(_, clip)| clip.clone())
        .collect();
    if pinned != actual || scene.required_clip_ids() != &actual || bound != actual {
        return Err(AppError::new(
            "REFERENCE_UNRESOLVED",
            "Every owned and declared clip requires its actual instance-qualified scene binding",
        ));
    }
    let settings = checked(check, || call.settings())?;
    let tps: RationalTime = serde_json::from_value(project.project()["gameTicksPerSecond"].clone())
        .map_err(|_| invalid())?;
    if settings.target_tps != tps {
        return Err(AppError::new(
            "STALE_CONTEXT",
            "Animation settings differ from the exact Project TPS",
        ));
    }
    let verifiers = CompilerVerifiers {
        call,
        check,
        failure: RefCell::new(None),
    };
    let mut drafts: Vec<AnimationDraft> =
        Vec::with_capacity(scene.required_animation_bindings().len());
    let mut output_bytes = 0usize;
    let mut output_functions = 0usize;
    let mut binding_snapshot_bytes = 0usize;
    let mut event_sources = BTreeMap::new();
    let mut event_source_bytes = 0usize;
    for (instance_id, clip_id) in scene.required_animation_bindings() {
        check()?;
        let clip_id = ClipId::new(clip_id).map_err(|_| invalid())?;
        let (clip, value) = clips.get(&clip_id).ok_or_else(conflict)?;
        let projection = scene
            .animation_bindings()
            .values()
            .find(|projection| projection.instance_id.as_str() == instance_id)
            .ok_or_else(conflict)?;
        if projection.owner_prefab_id != clip.owner_prefab_id {
            return Err(conflict());
        }
        if projection.nodes.len() > MAX_ANIMATION_NODES {
            return Err(budget_error());
        }
        let events = checked(check, || call.event_bindings(clip))?;
        if events.len() > MAX_ITEMS {
            return Err(budget_error());
        }
        let expected_events: BTreeSet<_> = clip
            .events
            .iter()
            .map(|event| event.function_symbol_id.clone())
            .collect();
        if events.keys().cloned().collect::<BTreeSet<_>>() != expected_events {
            return Err(AppError::new(
                "REFERENCE_UNRESOLVED",
                "Actual event function bindings do not close the authored symbol set",
            ));
        }
        preflight_event_sources(&events, &mut event_sources, &mut event_source_bytes, check)?;
        let bindings = AnimationBindings {
            instance_id: projection.instance_id.clone(),
            owner_prefab_id: projection.owner_prefab_id.clone(),
            world_id: projection.world_id.clone(),
            dimension: projection.dimension.clone(),
            instance_world: projection.instance_world.clone(),
            nodes: projection.nodes.clone(),
            events,
        };
        preflight_binding_metadata(&bindings)?;
        let binding_bytes = bindings.canonical_bytes().map_err(domain_error)?;
        if binding_bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(budget_error());
        }
        binding_snapshot_bytes = binding_snapshot_bytes
            .checked_add(binding_bytes.len())
            .filter(|size| *size <= MAX_BYTES)
            .ok_or_else(budget_error)?;
        let snapshot = checked(check, || call.binding_snapshot(&bindings, &binding_bytes))?;
        let verified = checked(check, || {
            VerifiedAnimationBindings::verify(bindings, snapshot, &binding_bytes, &verifiers)
                .map_err(domain_error)
        });
        let verified = verifiers.release(verified)?;
        let draft = checked(check, || {
            animation_compile(value, target, &verified, &verifiers, settings.clone())
                .map_err(domain_error)
        });
        let draft = verifiers.release(draft)?;
        if draft.instance_id().as_str() != instance_id
            || draft.clip_id() != &clip_id
            || draft.clip_revision() != &clip.revision
        {
            return Err(conflict());
        }
        for resource in draft.resources().values() {
            output_bytes = output_bytes
                .checked_add(resource.bytes.len())
                .filter(|size| *size <= MAX_BYTES)
                .ok_or_else(budget_error)?;
        }
        output_functions = output_functions
            .checked_add(draft.resources().len())
            .filter(|count| *count <= MAX_ITEMS)
            .ok_or_else(budget_error)?;
        drafts.push(draft);
    }
    let mut covered: BTreeSet<_> = scene
        .covered_owned_sources()
        .iter()
        .map(|source| source.object_id.to_string())
        .collect();
    covered.extend(drafts.iter().map(|draft| draft.clip_id().to_string()));
    let mut inputs =
        PackBuildInputs::new(project.project().clone(), vec![], BTreeMap::new(), covered)
            .with_scene(scene);
    for draft in drafts {
        inputs = inputs.with_animation(draft);
    }
    check()?;
    Ok(inputs)
}

fn preflight_event_sources(
    events: &BTreeMap<SymbolId, AnimationEventBinding>,
    retained: &mut BTreeMap<ResourceId, ResourceRef>,
    total: &mut usize,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<()> {
    let mut binding_bytes = 0usize;
    for event in events.values() {
        check()?;
        let source = &event.source;
        binding_bytes = binding_bytes
            .checked_add(source.bytes.len())
            .filter(|size| *size <= MAX_BYTES)
            .ok_or_else(budget_error)?;
        if source.reference.size_bytes != source.bytes.len() as u64
            || source.reference.sha256 != raw_digest(&source.bytes)
            || std::str::from_utf8(&source.bytes).is_err()
            || source.reference.media_type.len() > 1024
        {
            return Err(AppError::new(
                "RESOURCE_DIGEST_MISMATCH",
                "Actual event source bytes, encoding or immutable pin differs",
            ));
        }
        if let Some(previous) = retained.get(&source.reference.resource_id) {
            if previous.sha256 != source.reference.sha256
                || previous.size_bytes != source.reference.size_bytes
                || previous.media_type != source.reference.media_type
            {
                return Err(conflict());
            }
        } else {
            if retained.len() >= MAX_ITEMS {
                return Err(budget_error());
            }
            *total = total
                .checked_add(source.bytes.len())
                .filter(|size| *size <= MAX_BYTES)
                .ok_or_else(budget_error)?;
            retained.insert(
                source.reference.resource_id.clone(),
                source.reference.clone(),
            );
        }
    }
    Ok(())
}

/// Count borrowed metadata before canonical_bytes clones its JSON projection
/// or the native owner can stage a snapshot. Conservative fixed overhead bounds
/// structural keys; the canonical result is checked again against the same cap.
fn preflight_binding_metadata(bindings: &AnimationBindings) -> AppResult<()> {
    let mut writer = MetadataBudget(0);
    writer.charge(512)?;
    charge_metadata(
        &mut writer,
        &(
            &bindings.instance_id,
            &bindings.owner_prefab_id,
            &bindings.world_id,
            &bindings.dimension,
            &bindings.instance_world,
        ),
    )?;
    for (id, node) in &bindings.nodes {
        writer.charge(256)?;
        charge_metadata(
            &mut writer,
            &(
                id,
                &node.parent,
                &node.rest_local,
                &node.display_uuid,
                node.display_origin,
            ),
        )?;
    }
    for (id, event) in &bindings.events {
        writer.charge(256)?;
        charge_metadata(
            &mut writer,
            &(
                id,
                &event.function,
                &event.source.reference,
                &event.contract,
            ),
        )?;
    }
    Ok(())
}
fn charge_metadata(writer: &mut MetadataBudget, value: &impl serde::Serialize) -> AppResult<()> {
    serde_json::to_writer(writer, value).map_err(|_| budget_error())
}
struct MetadataBudget(usize);
impl MetadataBudget {
    fn charge(&mut self, bytes: usize) -> AppResult<()> {
        self.0 = self
            .0
            .checked_add(bytes)
            .filter(|size| *size <= MAX_DOCUMENT_BYTES)
            .ok_or_else(budget_error)?;
        Ok(())
    }
}
impl Write for MetadataBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.charge(bytes.len())
            .map_err(|_| io::Error::other("Animation metadata budget exceeded"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct CompilerVerifiers<'call> {
    call: &'call dyn NativeAnimationCall,
    check: &'call dyn Fn() -> AppResult<()>,
    failure: RefCell<Option<AppError>>,
}
impl CompilerVerifiers<'_> {
    fn checkpoint(&self) -> Result<(), DomainError> {
        match (self.check)() {
            Ok(()) => Ok(()),
            Err(error) => {
                let reported = DomainError::new(error.code, error.message);
                let mut retained = self.failure.borrow_mut();
                if retained.is_none() {
                    *retained = Some(error);
                }
                Err(reported)
            }
        }
    }
    fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, DomainError>,
    ) -> Result<T, DomainError> {
        self.checkpoint()?;
        let result = operation();
        let checkpoint = self.checkpoint();
        match (result, checkpoint) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }
    fn release<T>(&self, result: AppResult<T>) -> AppResult<T> {
        let checkpoint = self.failure.borrow_mut().take().map_or(Ok(()), Err);
        finish(result, checkpoint)
    }
}
impl AnimationBindingVerifier for CompilerVerifiers<'_> {
    fn verify_animation_bindings(
        &self,
        snapshot: &ResourceRef,
        bytes: &[u8],
        bindings: &AnimationBindings,
    ) -> Result<Sha256Digest, DomainError> {
        self.invoke(|| {
            self.call
                .verify_animation_bindings(snapshot, bytes, bindings)
        })
    }
}
impl AnimationEvidenceVerifier for CompilerVerifiers<'_> {
    fn verify_animation_target(
        &self,
        profile: &Sha256Digest,
        artifact: &Sha256Digest,
    ) -> Result<AnimationTargetRules, DomainError> {
        self.invoke(|| self.call.verify_animation_target(profile, artifact))
    }
    fn verify_event_functions(
        &self,
        profile: &Sha256Digest,
        artifact: &Sha256Digest,
        events: &BTreeMap<SymbolId, AnimationEventBinding>,
        objective: &str,
        prefix: &str,
    ) -> Result<(), DomainError> {
        self.invoke(|| {
            self.call
                .verify_event_functions(profile, artifact, events, objective, prefix)
        })
    }
    fn verify_linear_interval(
        &self,
        target: &VerifiedTarget,
        clip: &Sha256Digest,
        bindings: &Sha256Digest,
        compiler: &Sha256Digest,
        tps: &RationalTime,
    ) -> Result<(), DomainError> {
        self.invoke(|| {
            self.call
                .verify_linear_interval(target, clip, bindings, compiler, tps)
        })
    }
    fn verify_loop_seam(
        &self,
        target: &VerifiedTarget,
        clip: &Sha256Digest,
        bindings: &Sha256Digest,
        compiler: &Sha256Digest,
        tps: &RationalTime,
    ) -> Result<(), DomainError> {
        self.invoke(|| {
            self.call
                .verify_loop_seam(target, clip, bindings, compiler, tps)
        })
    }
}

fn checked<T>(
    check: impl Fn() -> AppResult<()>,
    operation: impl FnOnce() -> AppResult<T>,
) -> AppResult<T> {
    check()?;
    let result = operation();
    finish(result, check())
}
fn finish<T>(result: AppResult<T>, checkpoint: AppResult<()>) -> AppResult<T> {
    match (result, checkpoint) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(checkpoint)) => Err(AppError::caused_by(
            primary.code,
            "Animation source failed and its original request checkpoint also failed",
            SourceFailure {
                primary,
                checkpoint,
            },
        )),
    }
}
#[derive(Debug)]
struct SourceFailure {
    primary: AppError,
    checkpoint: AppError,
}
impl fmt::Display for SourceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; checkpoint: {}",
            self.primary, self.checkpoint
        )
    }
}
impl std::error::Error for SourceFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
fn service_error(error: crate::service::ServiceError) -> AppError {
    AppError::caused_by(error.code, error.message, error)
}
fn domain_error(error: DomainError) -> AppError {
    AppError::caused_by(
        error.code,
        "Animation compiler rejected the exact owned input or evidence",
        error,
    )
}
fn invalid() -> AppError {
    AppError::new("SCHEMA_INVALID", "Animation source contract is invalid")
}
fn conflict() -> AppError {
    AppError::new(
        "REVISION_CONFLICT",
        "Animation source or sealed scene differs from its exact Project pin",
    )
}
fn denied() -> AppError {
    AppError::new(
        "PERMISSION_REQUIRED",
        "Animation source is outside the original authenticated call",
    )
}
fn unavailable() -> AppError {
    AppError::new(
        "SOURCE_UNAVAILABLE",
        "Actual animation binding and target evidence owner is not registered",
    )
}
fn budget_error() -> AppError {
    AppError::new(
        "RESOURCE_BUDGET_EXCEEDED",
        "Animation source or generated output exceeds its finite aggregate budget",
    )
}

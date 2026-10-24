//! 최초 상태 읽기의 저작 소스와 컴파일 결과를 대조한다. 이 검사만으로
//! 게임 별칭, resource association 또는 native codec 권한을 발급하지 않는다.
//! 실제 별칭/코덱 발급자가 없는 현재 구성은 CAPABILITY_UNAVAILABLE이다.

use crate::{
    authority::LocalAuthority,
    host::{HostBridge, HostContextWitness},
    native_targets::NativeSelector,
    owned_planning_data::OwnedStateSource,
    planning_source::PlanningStore,
    service::RequestContextWitness,
};
use mmmm_application::{AppError, AppResult};
use mmmm_compiler::scene::{
    CoveredSceneSource, NativeSceneInstruction, SceneDraft, SceneLifecyclePhase, SceneStateBinding,
};
use mmmm_contracts::{ContextId, Sha256Digest, StateId};
use mmmm_domain::{
    state::{effective_defaults, value_matches_type},
    types::{ResourceRef, ScalarValue, StateScope, StateType, StateVariable},
};
use mmmm_runtime::storage::BlobRef;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAX_STATES: usize = 256;

/// 실제 compiler draft에서 얻은 metadata. Deserialize와 공개 constructor가
/// 없으며 selector, ResourceRef 또는 read capability를 갖지 않는다.
pub struct CheckedStateLowering {
    request: RequestContextWitness,
    host: HostContextWitness,
    project_revision: Sha256Digest,
    instance_blob: BlobRef,
    prefab_blob: BlobRef,
    compiler_digest: Sha256Digest,
    codec_digest: Sha256Digest,
    profile_digest: Sha256Digest,
    artifact_digest: Sha256Digest,
    states: BTreeMap<StateId, SceneStateBinding>,
}

impl CheckedStateLowering {
    pub fn compiler_digest(&self) -> &Sha256Digest {
        &self.compiler_digest
    }
    pub fn codec_digest(&self) -> &Sha256Digest {
        &self.codec_digest
    }
    pub fn profile_digest(&self) -> &Sha256Digest {
        &self.profile_digest
    }
    pub fn artifact_digest(&self) -> &Sha256Digest {
        &self.artifact_digest
    }
    /// 저작/컴파일 metadata 조회이며 native locator 사용 승인과 무관하다.
    pub fn states(&self) -> &BTreeMap<StateId, SceneStateBinding> {
        &self.states
    }
    pub fn check_current(
        &self,
        store: &PlanningStore<'_>,
        source: &OwnedStateSource,
    ) -> AppResult<()> {
        self.request.check_local().map_err(service_error)?;
        self.host.check_local()?;
        source.check_current(store)?;
        if !self
            .request
            .authenticated()
            .same_session(source.request().authenticated())
            || self.host.context() != source.context()
            || &self.project_revision != source.project().revision()
            || &self.instance_blob != source.instance_blob()
            || &self.prefab_blob != source.prefab_blob()
        {
            return Err(stale());
        }
        self.request.check_local().map_err(service_error)?;
        self.host.check_local()
    }
}

/// 실제 runtime alias/resource/native codec 발급자의 결과를 위한 opaque 타입.
/// 현재 소스에는 이 값을 생성하는 발급자나 공개/JSON constructor가 없다.
/// 별칭 문자열, caller ResourceRef 또는 verified 플래그로 구성할 수 없다.
pub struct IssuedStateReadTargets {
    lowering: CheckedStateLowering,
    associations: Vec<StateReadAssociation>,
}
impl IssuedStateReadTargets {
    pub fn lowering(&self) -> &CheckedStateLowering {
        &self.lowering
    }
    pub fn associations(&self) -> &[StateReadAssociation] {
        &self.associations
    }
}

/// 실제 발급자만 생성할 수 있는 association. native selector와 resource 핀은
/// 실제 현재 등록/CAS/codec/source 증명을 확인하기 전에는 존재하지 않는다.
pub struct StateReadAssociation {
    state_id: StateId,
    resource: ResourceRef,
    selector: NativeSelector,
}
impl StateReadAssociation {
    pub fn state_id(&self) -> &StateId {
        &self.state_id
    }
    pub fn resource(&self) -> &ResourceRef {
        &self.resource
    }
    pub fn selector(&self) -> &NativeSelector {
        &self.selector
    }
}

pub(crate) mod state_alias_seal {
    pub trait Sealed {}
}

/// 원장과 실제 source witness를 함께 받는 필수 내부 port. 외부 adapter는
/// 이 sealed port나 opaque 결과를 caller JSON에서 만들 수 없다.
pub trait StateRuntimeAliasPort: state_alias_seal::Sealed {
    fn issue(
        &mut self,
        store: &PlanningStore<'_>,
        source: &OwnedStateSource,
        lowering: CheckedStateLowering,
    ) -> AppResult<IssuedStateReadTargets>;
}

/// 실제 alias/codec/source receipt가 없는 제품 구성을 명시적으로 나타낸다.
/// unknown objective나 global holder는 성공한 초기 읽기로 바뀌지 않는다.
#[derive(Default)]
pub struct UnavailableStateRuntimeAliases;
impl state_alias_seal::Sealed for UnavailableStateRuntimeAliases {}
impl StateRuntimeAliasPort for UnavailableStateRuntimeAliases {
    fn issue(
        &mut self,
        store: &PlanningStore<'_>,
        source: &OwnedStateSource,
        lowering: CheckedStateLowering,
    ) -> AppResult<IssuedStateReadTargets> {
        lowering.check_current(store, source)?;
        Err(unavailable())
    }
}

/// OwnedPlanningData가 같은 Store에서 발급한 source를 받아 실제 draft와
/// 대조한다. 이는 block-only stage 승인 producer와 별도의 상태 소스 검사다.
pub struct NativeStateReadTargetProducer {
    hosts: HostBridge,
    authority: LocalAuthority,
}
impl NativeStateReadTargetProducer {
    pub fn new(hosts: HostBridge, authority: LocalAuthority) -> Self {
        Self { hosts, authority }
    }

    pub fn check_lowering(
        &self,
        store: &PlanningStore<'_>,
        source: &OwnedStateSource,
        draft: &SceneDraft,
        selected: &[StateId],
    ) -> AppResult<CheckedStateLowering> {
        let selected = selected_states(selected)?;
        source.check_current(store)?;
        let request = source.request().clone();
        request.check_local().map_err(service_error)?;
        let context = source.context();
        if context["environment"]["kind"] != "game" {
            return Err(unavailable());
        }
        if context["projectId"] != source.project().project_id().as_str()
            || context["principalRef"] != request.authenticated().principal().as_str()
            || context["environment"]["worldId"] != source.instance().world_id.as_str()
            || context["dimension"] != source.instance().dimension.as_str()
        {
            return Err(stale());
        }
        let context_id = ContextId::new(text(context, "contextId")?).map_err(|_| stale())?;
        let host = self.hosts.observe_context_witness(
            request.authenticated().principal(),
            &context_id,
            request.budget().deadline(),
        )?;
        if host.context() != context {
            return Err(stale());
        }
        self.authority.authorize_retained_scope(
            request.authenticated().principal(),
            source.project().project_id(),
            &context_id,
            &Sha256Digest::new(text(context, "policyRevision")?).map_err(|_| stale())?,
            &context["scope"],
        )?;
        if draft.input_revision() != source.project().revision()
            || draft.target_profile_id() != source.project().target_profile_id()
            || !draft.losses().is_empty()
        {
            return Err(stale());
        }
        require_covered_sources(source, draft)?;
        let bindings = draft
            .state_bindings()
            .get(&source.instance().instance_id)
            .ok_or_else(unavailable)?;
        let defaults = effective_defaults(source.prefab(), &source.instance().overrides)
            .map_err(|_| stale())?;
        let mut states = BTreeMap::new();
        for id in selected {
            request.check_local().map_err(service_error)?;
            let state = source
                .prefab()
                .state
                .iter()
                .find(|state| state.state_id == id)
                .ok_or_else(stale)?;
            let binding = bindings.get(&id).ok_or_else(unavailable)?;
            require_state_metadata(state, binding)?;
            let qualified = match state.scope {
                StateScope::Project => {
                    format!("project/{}/state/{}", source.project().project_id(), id)
                }
                StateScope::Instance => format!(
                    "project/{}/instance/{}/state/{}",
                    source.project().project_id(),
                    source.instance().instance_id,
                    id
                ),
                StateScope::Player | StateScope::Ephemeral => return Err(unavailable()),
            };
            if binding.qualified_state != qualified {
                return Err(stale());
            }
            if !draft.state_symbols().contains(&binding.qualified_state) {
                return Err(stale());
            }
            let value = defaults.get(&id).ok_or_else(stale)?;
            require_original_state_step(source, draft, binding, value)?;
            states.insert(id, binding.clone());
        }
        let checked = CheckedStateLowering {
            request,
            host,
            project_revision: source.project().revision().clone(),
            instance_blob: source.instance_blob().clone(),
            prefab_blob: source.prefab_blob().clone(),
            compiler_digest: draft.compiler_digest().clone(),
            codec_digest: draft.codec_digest().clone(),
            profile_digest: draft.target_profile_digest().clone(),
            artifact_digest: draft.target_artifact_digest().clone(),
            states,
        };
        checked.check_current(store, source)?;
        Ok(checked)
    }

    pub fn issue(
        &self,
        store: &PlanningStore<'_>,
        source: &OwnedStateSource,
        draft: &SceneDraft,
        selected: &[StateId],
        aliases: &mut dyn StateRuntimeAliasPort,
    ) -> AppResult<IssuedStateReadTargets> {
        let checked = self.check_lowering(store, source, draft, selected)?;
        let issued = aliases.issue(store, source, checked)?;
        issued.lowering.check_current(store, source)?;
        Ok(issued)
    }
}

fn selected_states(selected: &[StateId]) -> AppResult<BTreeSet<StateId>> {
    if selected.is_empty() || selected.len() > MAX_STATES {
        return Err(invalid());
    }
    let states: BTreeSet<_> = selected.iter().cloned().collect();
    if states.len() != selected.len() {
        return Err(invalid());
    }
    Ok(states)
}

fn require_covered_sources(source: &OwnedStateSource, draft: &SceneDraft) -> AppResult<()> {
    for covered in [
        CoveredSceneSource {
            kind: "instance".into(),
            object_id: mmmm_contracts::ObjectId::new(source.instance().instance_id.as_str())
                .map_err(|_| stale())?,
            revision: source.instance().revision.clone(),
        },
        CoveredSceneSource {
            kind: "prefab".into(),
            object_id: mmmm_contracts::ObjectId::new(source.prefab().prefab_id.as_str())
                .map_err(|_| stale())?,
            revision: source.prefab().revision.clone(),
        },
    ] {
        if !draft.covered_owned_sources().contains(&covered) {
            return Err(stale());
        }
    }
    Ok(())
}

fn require_state_metadata(state: &StateVariable, binding: &SceneStateBinding) -> AppResult<()> {
    if matches!(state.scope, StateScope::Player | StateScope::Ephemeral)
        || !matches!(state.lifecycle.as_str(), "spawn" | "load_once")
    {
        return Err(unavailable());
    }
    if state.storage != binding.storage_kind
        || state.state_type != binding.state_type
        || state.lifecycle != binding.lifecycle
    {
        return Err(stale());
    }
    Ok(())
}

fn require_original_state_step(
    source: &OwnedStateSource,
    draft: &SceneDraft,
    binding: &SceneStateBinding,
    authored_default: &ScalarValue,
) -> AppResult<()> {
    let mut matched = 0usize;
    for step in draft.native_steps() {
        if step.phase() != SceneLifecyclePhase::Stage
            || step.instance_id() != &source.instance().instance_id
            || step.owner_prefab_id() != &source.prefab().prefab_id
        {
            continue;
        }
        let NativeSceneInstruction::StateInitialize {
            storage,
            key,
            value,
            storage_kind,
            state_type,
            lifecycle,
            objective,
            holder,
        } = step.instruction()
        else {
            continue;
        };
        if storage != &binding.storage || key != &binding.key {
            continue;
        }
        if storage_kind != &binding.storage_kind
            || state_type != &binding.state_type
            || lifecycle != &binding.lifecycle
            || objective != &binding.objective
            || holder != &binding.holder
            || !same_native_scalar(*state_type, value, authored_default)
        {
            return Err(stale());
        }
        matched += 1;
    }
    // 공유 Project state가 다른 실제 instance의 step에 소유된 경우에는 그
    // owner의 추가 source 증인이 필요하다. 다른 instance를 추정하지 않는다.
    if matched != 1 {
        return Err(unavailable());
    }
    Ok(())
}

fn same_native_scalar(state_type: StateType, native: &ScalarValue, authored: &ScalarValue) -> bool {
    if !value_matches_type(native, state_type) || !value_matches_type(authored, state_type) {
        return false;
    }
    match (state_type, native, authored) {
        (StateType::Boolean, ScalarValue::Boolean(left), ScalarValue::Boolean(right)) => {
            left == right
        }
        (StateType::Int32, ScalarValue::Number(left), ScalarValue::Number(right)) => {
            left.as_f64() == right.as_f64()
        }
        (StateType::Float32, ScalarValue::Number(left), ScalarValue::Number(right)) => {
            let (Some(native), Some(authored)) = (left.as_f64(), right.as_f64()) else {
                return false;
            };
            // SceneDraft에 기록된 native 값은 f32의 정확한 f64 확장이며,
            // 저작값 변환 손실은 draft.losses 검사가 별도로 거부한다.
            native == f64::from(native as f32) && native == f64::from(authored as f32)
        }
        _ => false,
    }
}

fn text<'a>(value: &'a Value, field: &str) -> AppResult<&'a str> {
    value[field].as_str().ok_or_else(stale)
}
fn service_error(error: crate::service::ServiceError) -> AppError {
    AppError::new(error.code, error.message)
}
fn unavailable() -> AppError {
    AppError::new(
        "CAPABILITY_UNAVAILABLE",
        "Actual state runtime alias, resource association and native codec source receipts are unavailable",
    )
}
fn stale() -> AppError {
    AppError::new(
        "STALE_DEPENDENCY",
        "State source, current request or sealed compiler lowering differs",
    )
}
fn invalid() -> AppError {
    AppError::new(
        "INVALID_INPUT",
        "A finite unique nonempty state selection is required",
    )
}

#[cfg(test)]
#[path = "native_read_targets_tests.rs"]
mod tests;

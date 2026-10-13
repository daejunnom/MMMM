//! 신뢰된 Coordinator 구성만 setup 계획 준비를 공급한다. 선택 값은 프로젝트와
//! 현재 revision/context의 식별자이며, facade가 실행 계획이나 권한을 넣는 wire가 아니다.

use crate::planning::check_context;
use crate::undo_context::UndoExecutionContext;
use crate::{Access, AppError, AppResult, Application, PreparedPlan};
use mmmm_contracts::{ContextId, PrincipalId, ProjectId, Sha256Digest};
use mmmm_runtime::storage::DurableStore;
use serde_json::Value;

/// 실제 setup 자료의 가용성과 봉인된 원문·증거는 신뢰된 Coordinator가 선택한다.
/// 이 값 자체는 Plan 권한, 준비된 단계 또는 host 검증 완료를 의미하지 않는다.
#[derive(Clone, Debug)]
pub struct SetupSelection {
    pub project_id: ProjectId,
    pub expected_revision: Sha256Digest,
    pub context_id: ContextId,
}

/// Rust 구성에서 주입하는 setup 준비 경계. 실제 프로젝트와 현재 context를 받아
/// 읽기·컴파일·private CAS staging만 수행하며 target mutation이나 별도 원장을 만들지 않는다.
/// 구현은 봉인된 setup 원문과 필요한 증거를 확인한 뒤 정확한 단계와 footprint를 반환한다.
pub trait SetupPlanningPort {
    fn prepare_setup_with_store(
        &mut self,
        store: &mut DurableStore,
        principal: &PrincipalId,
        selection: &SetupSelection,
        project: &Value,
        context: &Value,
    ) -> AppResult<PreparedPlan>;
}

impl Application<'_> {
    /// 신뢰된 준비 구현도 일반 계획과 같은 권한·revision·context 검사를 거친다.
    pub fn prepare_setup(
        &mut self,
        principal: &PrincipalId,
        selection: &SetupSelection,
        setup: &mut dyn SetupPlanningPort,
    ) -> AppResult<Value> {
        self.prepare_setup_with_undo(principal, selection, setup, None)
    }

    /// undo 구성은 공통 계획 freeze의 등록 역할 검사에만 전달한다. setup 준비는
    /// 승인된 Apply, 작업 예약, Invocation 생성 또는 실제 host dispatch를 수행하지 않는다.
    pub fn prepare_setup_with_undo(
        &mut self,
        principal: &PrincipalId,
        selection: &SetupSelection,
        setup: &mut dyn SetupPlanningPort,
        undo: Option<&mut UndoExecutionContext<'_>>,
    ) -> AppResult<Value> {
        self.authority
            .authorize(principal, &selection.project_id, Access::Plan, None, None)?;
        let project = self
            .store
            .project(&selection.project_id)
            .map_err(|error| AppError::storage("NOT_FOUND", error))?;
        if project["revision"].as_str() != Some(selection.expected_revision.as_str()) {
            return Err(AppError::new(
                "REVISION_CONFLICT",
                "Authoring revision changed before setup planning",
            ));
        }
        let context = self.provider.context(principal, &selection.context_id)?;
        check_context(
            principal,
            &selection.project_id,
            &selection.context_id,
            &context,
        )?;
        self.authority.authorize(
            principal,
            &selection.project_id,
            Access::Plan,
            Some(&context),
            None,
        )?;
        let prepared =
            setup.prepare_setup_with_store(self.store, principal, selection, &project, &context)?;
        self.freeze_ordinary_plan(principal, &project, &context, prepared, undo)
    }
}

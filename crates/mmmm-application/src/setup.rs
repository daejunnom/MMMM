//! 신뢰된 Coordinator 구성만 setup 계획 준비를 공급한다. 선택 값은 프로젝트와
//! 현재 revision/context의 식별자이며, facade가 실행 계획이나 권한을 넣는 wire가 아니다.

use crate::planning::check_context;
use crate::undo_context::UndoExecutionContext;
use crate::{Access, AppError, AppResult, Application, PreparedPlan};
use mmmm_contracts::{ContextId, PlanId, PrincipalId, ProjectId, Sha256Digest};
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
    /// Read the actual current Project through an authenticated, bounded source.
    /// The implementation retains its protected head pin and original request.
    fn read_current_project_with_store(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        selection: &SetupSelection,
    ) -> AppResult<Value>;
    /// Recheck the same Store, current owner/head and original request without
    /// replacing the retained head or starting a new budget.
    fn check_current_project_with_store(
        &self,
        store: &DurableStore,
        principal: &PrincipalId,
        selection: &SetupSelection,
    ) -> AppResult<()>;
    fn prepare_setup_with_store(
        &mut self,
        store: &mut DurableStore,
        principal: &PrincipalId,
        selection: &SetupSelection,
        project: &Value,
        context: &Value,
    ) -> AppResult<PreparedPlan>;
}

/// A private plan was saved before its final source checkpoint failed. The
/// immutable locator remains available; this is neither rollback nor approval.
#[derive(Debug)]
pub struct SetupCommittedPlanFailure {
    plan_id: PlanId,
    plan_hash: Sha256Digest,
    checkpoint: AppError,
}
impl SetupCommittedPlanFailure {
    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }
    pub fn plan_hash(&self) -> &Sha256Digest {
        &self.plan_hash
    }
    pub fn checkpoint_failure(&self) -> &AppError {
        &self.checkpoint
    }
}
impl std::fmt::Display for SetupCommittedPlanFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Setup plan committed before its final source checkpoint failed")
    }
}
impl std::error::Error for SetupCommittedPlanFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.checkpoint)
    }
}

#[derive(Debug)]
struct SetupCheckpointFailure {
    primary: AppError,
    checkpoint: AppError,
}
impl std::fmt::Display for SetupCheckpointFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Setup work failed: {}; subsequent source checkpoint failed: {}",
            self.primary, self.checkpoint
        )
    }
}
impl std::error::Error for SetupCheckpointFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
fn checked_source<T>(result: AppResult<T>, checkpoint: AppResult<()>) -> AppResult<T> {
    match (result, checkpoint) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(checkpoint)) => Err(checkpoint),
        (Err(primary), Err(checkpoint)) => Err(AppError::caused_by(
            primary.code,
            primary.message,
            SetupCheckpointFailure {
                primary,
                checkpoint,
            },
        )),
    }
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
        setup.check_current_project_with_store(self.store, principal, selection)?;
        let project = checked_source(
            setup.read_current_project_with_store(self.store, principal, selection),
            setup.check_current_project_with_store(self.store, principal, selection),
        )?;
        crate::validate("Project", &project)?;
        mmmm_contracts::verify_projected_digest("Project", &project).map_err(AppError::digest)?;
        if project["projectId"] != selection.project_id.as_str() {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Setup Project differs from its original selection",
            ));
        }
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
        let prepared = checked_source(
            setup.prepare_setup_with_store(self.store, principal, selection, &project, &context),
            setup.check_current_project_with_store(self.store, principal, selection),
        )?;
        setup.check_current_project_with_store(self.store, principal, selection)?;
        let frozen = self.freeze_ordinary_plan(principal, &project, &context, prepared, undo);
        let checkpoint = setup.check_current_project_with_store(self.store, principal, selection);
        match (frozen, checkpoint) {
            (Ok(plan), Err(checkpoint)) => {
                let plan_id = crate::decode(&plan["planId"])?;
                let plan_hash = crate::decode(&plan["planHash"])?;
                Err(AppError::caused_by(
                    "SETUP_PLAN_COMMITTED",
                    "Setup plan was saved before its source checkpoint failed",
                    SetupCommittedPlanFailure {
                        plan_id,
                        plan_hash,
                        checkpoint,
                    },
                ))
            }
            (result, checkpoint) => checked_source(result, checkpoint),
        }
    }
}

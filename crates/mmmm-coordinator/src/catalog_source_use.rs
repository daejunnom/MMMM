//! 실제 cold native 소유자의 catalog source 사용 선택이다. import와 분리하며
//! workspace listener, game context, D032 선택이나 실행/source grant를 만들지 않는다.

use crate::{
    bootstrap::NativeWorkspacePermit,
    service::{RequestBudget, ServiceError},
    workspace_bootstrap::{NativeOwnerWitness, native_owner_resource_reader},
};
use mmmm_application::{AppError, AppResult};
use mmmm_contracts::{ContextId, PrincipalId, ProjectId, ResourceId, Sha256Digest};
use mmmm_runtime::storage::{
    BlobRef, DurableStore, StorageError, StorageResult, StoreConfig,
    bootstrap::POLICY_MEDIA_TYPE,
    catalog_source_use::{
        self, CatalogSourceUseAction, CatalogSourceUseCurrent, CatalogSourceUsePermit,
        CatalogSourceUseReplace, CatalogSourceUseSelection, CatalogSourceUseSnapshot,
    },
    project_resources::{
        ProjectResourceQuery, ProjectResourceReader, ProjectResourceRequest,
        ProjectSourceRpcContext,
    },
};
use serde_json::Value;
use std::{cell::RefCell, collections::BTreeSet};

const MAX_PROJECT: u64 = 8 * 1024 * 1024;
const MAX_SELECTORS: usize = 256;

#[derive(Clone, Debug)]
pub enum LocalCatalogSourceUseAction {
    Inspect,
    /// 완전한 새 집합이다. 빈 selections는 명시적 철회이며 이전 상태를 삭제하지 않는다.
    Replace {
        expected_state_digest: Sha256Digest,
        selections: Vec<CatalogSourceUseSelection>,
    },
}

/// Native entry의 실제 관리 명령만 이 경로를 호출한다. 원래 budget을 보존하며
/// open_existing의 단일 Store/lock과 실제 UID/SID 소유자를 확인한다. prepare_workspace의
/// 전체 CAS scan을 사용하지 않아 이전 자원 손상도 inspect/철회를 막지 않는다.
pub fn manage_catalog_source_use(
    config: StoreConfig,
    project: &ProjectId,
    expected_revision: &Sha256Digest,
    action: LocalCatalogSourceUseAction,
    budget: &RequestBudget,
) -> AppResult<CatalogSourceUseSnapshot> {
    budget.check().map_err(service_error)?;
    let mut store = DurableStore::open_existing(config).map_err(storage_error)?;
    let owner = NativeOwnerWitness::capture(&store, budget.deadline()).map_err(storage_error)?;
    owner
        .check_project(&store, project)
        .map_err(storage_error)?;
    if let LocalCatalogSourceUseAction::Replace { selections, .. } = &action
        && (selections.len() > MAX_SELECTORS
            || selections
                .iter()
                .try_fold(0usize, |size, selected| {
                    let role = match &selected.role {
                        catalog_source_use::CatalogSourceUseRole::GameArtifact => 0,
                        catalog_source_use::CatalogSourceUseRole::Mod {
                            canonical_id,
                            native_id,
                        } => canonical_id.as_str().len().checked_add(native_id.len())?,
                    };
                    size.checked_add(selected.resource_id.as_str().len())?
                        .checked_add(role)?
                        .checked_add(64)
                })
                .is_none_or(|size| size > 65_536))
    {
        return Err(invalid());
    }
    let mut selections = match &action {
        LocalCatalogSourceUseAction::Inspect => Vec::new(),
        LocalCatalogSourceUseAction::Replace { selections, .. } => selections.clone(),
    };
    if selections.len() > MAX_SELECTORS {
        return Err(invalid());
    }
    selections.sort();
    let failure = RefCell::new(None);
    let rpc = ColdOwnerRpc {
        owner: &owner,
        budget,
        failure: &failure,
    };
    // 처음에는 Project만 검증한다. 전체 resource bytes나 source 권리를 추정하지 않는다.
    let mut reader = native_owner_resource_reader(
        &owner,
        project,
        expected_revision,
        BTreeSet::new(),
        MAX_PROJECT,
    )
    .map_err(storage_error)?;
    let document = reader
        .read_project(&store, &rpc, project, expected_revision, MAX_PROJECT)
        .map_err(|cause| release_storage(&failure, cause))?;
    let policy_id: ResourceId =
        serde_json::from_value(document["policyResourceId"].clone()).map_err(|_| invalid())?;
    let membership: BTreeSet<ResourceId> =
        serde_json::from_value(document["resourceIds"].clone()).map_err(|_| invalid())?;
    let mut allowed = BTreeSet::from([policy_id.clone()]);
    for selected in &selections {
        if !membership.contains(&selected.resource_id) {
            return Err(denied());
        }
        allowed.insert(selected.resource_id.clone());
    }
    let mut reader = native_owner_resource_reader(
        &owner,
        project,
        expected_revision,
        BTreeSet::from([policy_id.clone()]),
        MAX_PROJECT,
    )
    .map_err(storage_error)?;
    let query = ProjectResourceQuery::Current {
        resource_id: policy_id,
    };
    let request = ProjectResourceRequest {
        project,
        current_project_revision: expected_revision,
        query: &query,
        expected: None,
    };
    let policy = reader
        .metadata(&store, &rpc, &request)
        .map_err(|cause| release_storage(&failure, cause))?;
    if policy.resource["mediaType"] != POLICY_MEDIA_TYPE {
        return Err(invalid());
    }
    let request = ProjectResourceRequest {
        expected: Some(&policy.resource),
        ..request
    };
    let bytes = reader
        .read(&store, &rpc, &request, MAX_PROJECT)
        .map_err(|cause| release_storage(&failure, cause))?
        .bytes;
    let value = mmmm_contracts::ContractValidator::shared()
        .map_err(|_| invalid())?
        .parse_and_validate("Policy", &bytes)
        .map_err(|_| invalid())?;
    owner
        .check_project(&store, project)
        .map_err(storage_error)?;
    budget.check().map_err(service_error)?;
    let permit = ColdCatalogSourceUse {
        owner,
        budget: budget.clone(),
        project: project.clone(),
        revision: expected_revision.clone(),
        document,
        policy_resource: policy.resource,
        policy_blob: policy.blob,
        policy: value,
        allowed_resources: allowed,
        selections,
        action: match &action {
            LocalCatalogSourceUseAction::Inspect => CatalogSourceUseAction::Inspect,
            LocalCatalogSourceUseAction::Replace { .. } => CatalogSourceUseAction::Replace,
        },
        failure,
    };
    let result = match action {
        LocalCatalogSourceUseAction::Inspect => {
            catalog_source_use::inspect_catalog_source_use_state(
                &store,
                &permit,
                project,
                expected_revision,
            )
        }
        LocalCatalogSourceUseAction::Replace {
            expected_state_digest,
            ..
        } => catalog_source_use::replace_catalog_source_uses(
            &mut store,
            &permit,
            &CatalogSourceUseReplace {
                project,
                expected_project_revision: expected_revision,
                expected_state_digest: &expected_state_digest,
                selections: &permit.selections,
            },
        ),
    };
    // 확정 receipt 뒤 budget을 검사해 commit을 실패로 바꾸지 않는다. entry가 전달과 분리한다.
    result.map_err(|cause| permit.release(cause))
}

struct ColdOwnerRpc<'a> {
    owner: &'a NativeOwnerWitness,
    budget: &'a RequestBudget,
    failure: &'a RefCell<Option<AppError>>,
}
impl ProjectSourceRpcContext for ColdOwnerRpc<'_> {
    fn check(&self) -> StorageResult<()> {
        if let Err(cause) = self.budget.check() {
            let mut failure = self.failure.borrow_mut();
            if failure.is_none() {
                *failure = Some(service_error(cause));
            }
            return Err(StorageError::Conflict(
                "Current cold native catalog request stopped",
            ));
        }
        self.owner.check()
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.owner.principal().clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        None
    }
}

struct ColdCatalogSourceUse {
    owner: NativeOwnerWitness,
    budget: RequestBudget,
    project: ProjectId,
    revision: Sha256Digest,
    document: Value,
    policy_resource: Value,
    policy_blob: BlobRef,
    policy: Value,
    allowed_resources: BTreeSet<ResourceId>,
    selections: Vec<CatalogSourceUseSelection>,
    action: CatalogSourceUseAction,
    failure: RefCell<Option<AppError>>,
}
impl ColdCatalogSourceUse {
    fn checked(&self) -> AppResult<()> {
        self.budget.check().map_err(service_error)?;
        self.owner.check().map_err(storage_error)
    }
    fn reject(&self, cause: AppError) -> StorageError {
        if let Ok(mut failure) = self.failure.try_borrow_mut()
            && failure.is_none()
        {
            *failure = Some(cause);
        }
        StorageError::Conflict("Current cold native catalog source use authority")
    }
    fn release(&self, cause: StorageError) -> AppError {
        self.failure
            .borrow_mut()
            .take()
            .unwrap_or_else(|| storage_error(cause))
    }
}
impl ProjectSourceRpcContext for ColdCatalogSourceUse {
    fn check(&self) -> StorageResult<()> {
        self.checked().map_err(|cause| self.reject(cause))
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.owner.principal().clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        None
    }
}
impl CatalogSourceUsePermit for ColdCatalogSourceUse {
    fn check_store(&self, store: &DurableStore) -> StorageResult<()> {
        self.check()?;
        self.owner.check_project(store, &self.project)?;
        self.check()
    }
    fn authenticated_native_owner(
        &self,
        store: &DurableStore,
        project: &ProjectId,
    ) -> StorageResult<PrincipalId> {
        self.check_store(store)?;
        if project != &self.project {
            return Err(self.reject(denied()));
        }
        Ok(self.owner.principal().clone())
    }
    fn authorize_current(
        &self,
        store: &DurableStore,
        current: &CatalogSourceUseCurrent<'_>,
    ) -> StorageResult<()> {
        self.check_store(store)?;
        if current.action != self.action
            || current.native_owner != self.owner.principal()
            || current.project != &self.document
            || current.project["revision"] != self.revision.as_str()
            || current.policy_resource.resource != self.policy_resource
            || current.policy_resource.blob != self.policy_blob
            || current.policy != &self.policy
            || current.selections != self.selections.as_slice()
        {
            return Err(self.reject(denied()));
        }
        self.check_store(store)
    }
    fn resource_reader(&self, ceiling: u64) -> StorageResult<ProjectResourceReader> {
        self.check()?;
        native_owner_resource_reader(
            &self.owner,
            &self.project,
            &self.revision,
            self.allowed_resources.clone(),
            ceiling,
        )
    }
}

fn service_error(cause: ServiceError) -> AppError {
    AppError::caused_by(cause.code, cause.message, cause)
}
fn release_storage(failure: &RefCell<Option<AppError>>, cause: StorageError) -> AppError {
    failure
        .borrow_mut()
        .take()
        .unwrap_or_else(|| storage_error(cause))
}
fn storage_error(cause: StorageError) -> AppError {
    let code = match &cause {
        StorageError::Busy => "SOURCE_BUSY",
        StorageError::Fenced(_) => "WRITE_SCOPE_FENCED",
        StorageError::Conflict(_) => "REVISION_CONFLICT",
        StorageError::Corrupt(_) => "INVALID_STORED_EVIDENCE",
        StorageError::InvalidInput(_) | StorageError::Contract(_) => "INVALID_INPUT",
        _ => "SOURCE_UNAVAILABLE",
    };
    AppError::caused_by(
        code,
        "Cold native catalog source use could not verify its protected state",
        cause,
    )
}
fn invalid() -> AppError {
    AppError::new(
        "INVALID_INPUT",
        "Catalog source use requires bounded typed resource selections",
    )
}
fn denied() -> AppError {
    AppError::new(
        "PERMISSION_REQUIRED",
        "Current native owner Project policy and exact catalog resource selection required",
    )
}

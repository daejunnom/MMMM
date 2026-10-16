//! 보호 Store의 native 소유자가 선택한 기존 whole-container 사용 결정이다.
//! 보존/import, 사용자 선언 SourceRef와 게임 runtime 관측은 이 결정을 만들지 않는다.
//! 이 snapshot과 digest는 보호된 사실이며 source/Java/World bearer grant가 아니다.

use super::{
    BlobRef, DurableStore, StorageError, StorageResult, WriteScope,
    artifact::ResourceOwner,
    bootstrap::{POLICY_MEDIA_TYPE, registered_native_project_owner},
    journal::{decode, encode},
    project_resources::{
        ProjectResourceQuery, ProjectResourceReader, ProjectResourceRequest,
        ProjectSourceRpcContext, RegisteredProjectResource,
    },
};
use mmmm_contracts::{
    PrincipalId, ProjectId, ResourceId, ResourceLocation, Sha256Digest, canonical_digest,
    encode_json,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const MAX_SELECTIONS: usize = 256;
const MAX_METADATA: usize = 65_536;
const MAX_SETS: i64 = 4096;
const MAX_GENERATION: u64 = 9_007_199_254_740_991;
// 기존 catalog whole-source 및 Project 문서 한도를 확대하지 않는다.
const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PROJECT_BYTES: u64 = 8 * 1024 * 1024;
const FORMAT: &str = "mmmm.catalog-source-use/1";
const RIGHTS: &str = "user_local_only";
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS catalog_source_uses (
 native_owner TEXT NOT NULL, project_id TEXT NOT NULL REFERENCES native_project_owners(project_id),
 generation INTEGER NOT NULL CHECK(generation>0 AND generation<=9007199254740991),
 state_digest TEXT NOT NULL CHECK(length(state_digest)=64),
 record_json TEXT NOT NULL CHECK(length(CAST(record_json AS BLOB))<=65536),
 PRIMARY KEY(native_owner,project_id)
) STRICT;";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CatalogSourceUseRole {
    GameArtifact,
    Mod {
        canonical_id: ResourceLocation,
        native_id: String,
    },
}

/// 실제 관리 행위가 선택하는 locator/역할뿐이다. ResourceRef/hash/권리/owner를 받지 않는다.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogSourceUseSelection {
    pub resource_id: ResourceId,
    pub role: CatalogSourceUseRole,
}

/// 실제 checked reader에서 도출된 metadata다. 과거 association은 snapshot의
/// approval.project_revision에 묶이며 현재 읽기는 그 원본과 현재 association을 모두 검사한다.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedCatalogSourceUse {
    selection: CatalogSourceUseSelection,
    resource: Value,
    blob: BlobRef,
}
impl PinnedCatalogSourceUse {
    pub fn selection(&self) -> &CatalogSourceUseSelection {
        &self.selection
    }
    pub fn resource(&self) -> &Value {
        &self.resource
    }
    pub fn blob(&self) -> &BlobRef {
        &self.blob
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovalPins {
    project_revision: Sha256Digest,
    project_blob: BlobRef,
    policy_resource: Value,
    policy_blob: BlobRef,
}

/// 재사용 가능한 권한이 아니다. consumer는 read_catalog_source_uses로 매번 현재
/// request/owner/policy/resource를 검사하고 자신의 호출 전후 권한을 별도로 유지한다.
/// generation=0은 부재, generation>0의 빈 selections는 보존된 철회 tombstone이다.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogSourceUseSnapshot {
    format: String,
    native_owner: PrincipalId,
    project_id: ProjectId,
    generation: u64,
    previous_state_digest: Option<Sha256Digest>,
    approval: Option<ApprovalPins>,
    rights: String,
    selections: Vec<PinnedCatalogSourceUse>,
    state_digest: Sha256Digest,
}
impl CatalogSourceUseSnapshot {
    pub fn native_owner(&self) -> &PrincipalId {
        &self.native_owner
    }
    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn state_digest(&self) -> &Sha256Digest {
        &self.state_digest
    }
    pub fn selections(&self) -> &[PinnedCatalogSourceUse] {
        &self.selections
    }
    pub fn rights(&self) -> &str {
        &self.rights
    }
    pub fn approved_project_revision(&self) -> Option<&Sha256Digest> {
        self.approval.as_ref().map(|pins| &pins.project_revision)
    }
    pub fn policy_resource(&self) -> Option<&Value> {
        self.approval.as_ref().map(|pins| &pins.policy_resource)
    }
}

pub struct CatalogSourceUseReplace<'a> {
    pub project: &'a ProjectId,
    pub expected_project_revision: &'a Sha256Digest,
    /// generation을 포함한 상태 digest다. 단순한 selections의 내용 hash가 아니다.
    pub expected_state_digest: &'a Sha256Digest,
    /// 빈 집합은 명시적 철회다. 누락/legacy 상태를 승인으로 승격하지 않는다.
    pub selections: &'a [CatalogSourceUseSelection],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogSourceUseAction {
    Inspect,
    Replace,
    Read,
}

/// 보호 Store에서 방금 읽은 실제 Project/Policy다. producer는 자신의 원래
/// native owner/request, current policy/read scope와 명시적 관리 선택을 확인한다.
pub struct CatalogSourceUseCurrent<'a> {
    pub action: CatalogSourceUseAction,
    pub native_owner: &'a PrincipalId,
    pub project: &'a Value,
    pub project_blob: &'a BlobRef,
    pub policy_resource: &'a RegisteredProjectResource,
    pub policy: &'a Value,
    pub selections: &'a [CatalogSourceUseSelection],
}

/// Coordinator의 실제 native owner/같은 Store/current request adapter가 구현한다.
/// authenticated_native_owner는 caller principal이 아니라 실제 kernel/Project owner다.
/// reader의 RPC principal은 cold owner 또는 현재 game principal일 수 있으며 각자의
/// 현재 Project/resource ACL을 별도로 검사해야 한다. 기본 허용 구현은 없다.
pub trait CatalogSourceUsePermit: ProjectSourceRpcContext {
    fn check_store(&self, store: &DurableStore) -> StorageResult<()>;
    fn authenticated_native_owner(
        &self,
        store: &DurableStore,
        project: &ProjectId,
    ) -> StorageResult<PrincipalId>;
    fn authorize_current(
        &self,
        store: &DurableStore,
        current: &CatalogSourceUseCurrent<'_>,
    ) -> StorageResult<()>;
    fn resource_reader(&self, ceiling: u64) -> StorageResult<ProjectResourceReader>;
}

struct Rpc<'a>(&'a dyn CatalogSourceUsePermit);
impl ProjectSourceRpcContext for Rpc<'_> {
    fn check(&self) -> StorageResult<()> {
        self.0.check()
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.0.authenticated_principal()
    }
    fn context_id(&self) -> Option<&mmmm_contracts::ContextId> {
        self.0.context_id()
    }
}
struct Current {
    owner: PrincipalId,
    project: Value,
    project_blob: BlobRef,
    policy_resource: RegisteredProjectResource,
    policy: Value,
}

/// cold native owner의 사실 조회다. 철회 대상의 옛 resource 권리가 사라져도 현재
/// owner/Project/Policy 관리 권한 아래 optimistic digest를 얻어 철회할 수 있다.
/// 이 경로는 content 읽기나 source 사용을 승인하지 않으며 game context를 거절한다.
pub fn inspect_catalog_source_use_state(
    store: &DurableStore,
    permit: &dyn CatalogSourceUsePermit,
    project: &ProjectId,
    expected_project_revision: &Sha256Digest,
) -> StorageResult<CatalogSourceUseSnapshot> {
    let initial = current(
        store,
        permit,
        project,
        expected_project_revision,
        CatalogSourceUseAction::Inspect,
        &[],
    )?;
    let snapshot = state(store, &initial.owner, project)?;
    let checked = current(
        store,
        permit,
        project,
        expected_project_revision,
        CatalogSourceUseAction::Inspect,
        &[],
    )?;
    same_current(&initial, &checked)?;
    unchanged_state(store, &snapshot)?;
    Ok(snapshot)
}

/// native consumer용 현재 검증이다. 과거 snapshot/공개 DTO/digest만으로 호출 권한이
/// 생기지 않으며, 현재 policy와 원본/현재 resource association 및 전체 CAS를 확인한다.
pub fn read_catalog_source_uses(
    store: &DurableStore,
    permit: &dyn CatalogSourceUsePermit,
    project: &ProjectId,
    expected_project_revision: &Sha256Digest,
) -> StorageResult<CatalogSourceUseSnapshot> {
    let initial = current(
        store,
        permit,
        project,
        expected_project_revision,
        CatalogSourceUseAction::Read,
        &[],
    )?;
    let snapshot = state(store, &initial.owner, project)?;
    let selectors = snapshot
        .selections
        .iter()
        .map(|pin| pin.selection.clone())
        .collect::<Vec<_>>();
    let selected = current(
        store,
        permit,
        project,
        expected_project_revision,
        CatalogSourceUseAction::Read,
        &selectors,
    )?;
    same_current(&initial, &selected)?;
    if !snapshot.selections.is_empty() {
        verify_selected(store, permit, &selected, &snapshot)?;
    }
    let final_current = current(
        store,
        permit,
        project,
        expected_project_revision,
        CatalogSourceUseAction::Read,
        &selectors,
    )?;
    same_current(&initial, &final_current)?;
    unchanged_state(store, &snapshot)?;
    Ok(snapshot)
}

/// 하나의 Immediate transaction에서 선택 집합을 교체한다. 원래 expected Project
/// revision/raw head/policy와 actual resource association은 발행 전후 재검사한다.
/// 같은 집합의 직전 요청 재전송은 idempotent지만 철회 뒤 오래된 digest는 거절한다.
pub fn replace_catalog_source_uses(
    store: &mut DurableStore,
    permit: &dyn CatalogSourceUsePermit,
    request: &CatalogSourceUseReplace<'_>,
) -> StorageResult<CatalogSourceUseSnapshot> {
    let selectors = normalize(request.selections)?;
    let initial = current(
        store,
        permit,
        request.project,
        request.expected_project_revision,
        CatalogSourceUseAction::Replace,
        &selectors,
    )?;
    let selected = prepare_selected(
        store,
        permit,
        &initial,
        request.project,
        request.expected_project_revision,
        &selectors,
    )?;
    let transaction =
        Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA)?;
    let before = state(store, &initial.owner, request.project)?;
    let checked = current(
        store,
        permit,
        request.project,
        request.expected_project_revision,
        CatalogSourceUseAction::Replace,
        &selectors,
    )?;
    same_current(&initial, &checked)?;
    let same_selection = before.approval.as_ref().is_some_and(|pins| {
        pins.policy_resource == initial.policy_resource.resource
            && pins.policy_blob == initial.policy_resource.blob
    }) && before.selections == selected;
    if same_selection
        && (request.expected_state_digest == &before.state_digest
            || before.previous_state_digest.as_ref() == Some(request.expected_state_digest))
    {
        // 현재 입력은 다시 checked reader를 통과했다. 과거 caller receipt는 권한이 아니다.
        if !before.selections.is_empty() {
            verify_selected(store, permit, &initial, &before)?;
        }
        let final_current = current(
            store,
            permit,
            request.project,
            request.expected_project_revision,
            CatalogSourceUseAction::Replace,
            &selectors,
        )?;
        same_current(&initial, &final_current)?;
        unchanged_state(store, &before)?;
        transaction.commit()?;
        return Ok(before);
    }
    if request.expected_state_digest != &before.state_digest {
        return Err(conflict("Catalog source use expected state changed"));
    }
    let generation = before
        .generation
        .checked_add(1)
        .filter(|value| *value <= MAX_GENERATION)
        .ok_or_else(|| invalid("Catalog source use generation exhausted"))?;
    let mut after = CatalogSourceUseSnapshot {
        format: FORMAT.into(),
        native_owner: initial.owner.clone(),
        project_id: request.project.clone(),
        generation,
        previous_state_digest: Some(before.state_digest.clone()),
        approval: Some(ApprovalPins {
            project_revision: request.expected_project_revision.clone(),
            project_blob: initial.project_blob.clone(),
            policy_resource: initial.policy_resource.resource.clone(),
            policy_blob: initial.policy_resource.blob.clone(),
        }),
        rights: RIGHTS.into(),
        selections: selected,
        state_digest: before.state_digest.clone(),
    };
    after.state_digest = digest(&after)?;
    validate_snapshot(store, &after)?;
    let encoded = encode(&after)?;
    if encoded.len() > MAX_METADATA {
        return Err(invalid("Catalog source use metadata budget"));
    }
    if before.generation == 0 {
        let count: i64 = transaction.query_row("SELECT count(*) FROM catalog_source_uses", [], |row| row.get(0))?;
        if count >= MAX_SETS { return Err(invalid("Catalog source use registry budget")); }
        transaction.execute("INSERT INTO catalog_source_uses(native_owner,project_id,generation,state_digest,record_json) VALUES(?1,?2,?3,?4,?5)",
            params![after.native_owner.as_str(),after.project_id.as_str(),generation as i64,after.state_digest.as_str(),encoded])?;
    } else if transaction.execute("UPDATE catalog_source_uses SET generation=?3,state_digest=?4,record_json=?5 WHERE native_owner=?1 AND project_id=?2 AND generation=?6 AND state_digest=?7",
        params![after.native_owner.as_str(),after.project_id.as_str(),generation as i64,after.state_digest.as_str(),encoded,before.generation as i64,before.state_digest.as_str()])? != 1 {
        return Err(conflict("Catalog source use optimistic publication changed"));
    }
    if !after.selections.is_empty() {
        verify_selected(store, permit, &initial, &after)?;
    }
    let final_current = current(
        store,
        permit,
        request.project,
        request.expected_project_revision,
        CatalogSourceUseAction::Replace,
        &selectors,
    )?;
    same_current(&initial, &final_current)?;
    unchanged_state(store, &after)?;
    transaction.commit()?;
    // commit 뒤 취소/전달 실패는 rollback이 아니다. caller가 확정 receipt를 보존한다.
    Ok(after)
}

fn current(
    store: &DurableStore,
    permit: &dyn CatalogSourceUsePermit,
    project: &ProjectId,
    revision: &Sha256Digest,
    action: CatalogSourceUseAction,
    selections: &[CatalogSourceUseSelection],
) -> StorageResult<Current> {
    permit.check()?;
    permit.check_store(store)?;
    if action != CatalogSourceUseAction::Read && permit.context_id().is_some() {
        return Err(conflict(
            "Catalog source use management requires cold native owner",
        ));
    }
    let owner = permit.authenticated_native_owner(store, project)?;
    if registered_native_project_owner(store, project)? != owner {
        return Err(conflict("Catalog source use native Project owner differs"));
    }
    let rpc = Rpc(permit);
    let mut reader = permit.resource_reader(MAX_PROJECT_BYTES)?;
    let document = reader.read_project(store, &rpc, project, revision, MAX_PROJECT_BYTES)?;
    let project_blob = head(store, project, revision)?;
    let policy_id: ResourceId =
        serde_json::from_value(document["policyResourceId"].clone()).map_err(contract)?;
    let query = ProjectResourceQuery::Current {
        resource_id: policy_id,
    };
    let request = ProjectResourceRequest {
        project,
        current_project_revision: revision,
        query: &query,
        expected: None,
    };
    let policy_resource = reader.metadata(store, &rpc, &request)?;
    if policy_resource.owner != ResourceOwner::Project(project.clone())
        || policy_resource.resource["mediaType"] != POLICY_MEDIA_TYPE
    {
        return Err(conflict(
            "Catalog source use current Policy resource differs",
        ));
    }
    let request = ProjectResourceRequest {
        expected: Some(&policy_resource.resource),
        ..request
    };
    let bytes = reader.read(store, &rpc, &request, MAX_PROJECT_BYTES)?.bytes;
    let policy = store
        .validator
        .parse_and_validate("Policy", &bytes)
        .map_err(contract)?;
    let policy_history = ProjectResourceQuery::Historical {
        project_revision: revision.clone(),
        resource_id: serde_json::from_value(policy_resource.resource["resourceId"].clone())
            .map_err(contract)?,
        digest: policy_resource.blob.digest.clone(),
    };
    let historical_request = ProjectResourceRequest {
        query: &policy_history,
        ..request
    };
    let historical_policy = reader.metadata(store, &rpc, &historical_request)?;
    if historical_policy.blob != policy_resource.blob
        || historical_policy.owner != policy_resource.owner
    {
        return Err(conflict(
            "Catalog source use exact current Policy association differs",
        ));
    }
    let scope = WriteScope {
        project_id: project.clone(),
        resource_ids: Vec::new(),
        object_ids: Vec::new(),
        regions: Vec::new(),
        external_target_ids: Vec::new(),
    };
    // 첫 관리 slice는 빈 집합 철회도 기존 full-Project durable-write fence를 지킨다.
    // 미해결 write 중 approval 변경을 허용하는 별도 revocation 의미를 추정하지 않는다.
    if action == CatalogSourceUseAction::Replace {
        store.check_write_scope(&scope, true, None)?;
    }
    permit.authorize_current(
        store,
        &CatalogSourceUseCurrent {
            action,
            native_owner: &owner,
            project: &document,
            project_blob: &project_blob,
            policy_resource: &policy_resource,
            policy: &policy,
            selections,
        },
    )?;
    let after_policy = reader.metadata(store, &rpc, &historical_request)?;
    if after_policy.resource != policy_resource.resource
        || after_policy.blob != policy_resource.blob
        || after_policy.owner != policy_resource.owner
        || after_policy.provenance != historical_policy.provenance
    {
        return Err(conflict(
            "Catalog source use Policy changed during authorization",
        ));
    }
    let current_query = ProjectResourceQuery::Current {
        resource_id: serde_json::from_value(policy_resource.resource["resourceId"].clone())
            .map_err(contract)?,
    };
    let current_request = ProjectResourceRequest {
        query: &current_query,
        ..historical_request
    };
    let still_current = reader.metadata(store, &rpc, &current_request)?;
    if still_current.resource != policy_resource.resource
        || still_current.blob != policy_resource.blob
        || still_current.owner != policy_resource.owner
        || still_current.provenance != policy_resource.provenance
    {
        return Err(conflict(
            "Catalog source use current Policy head changed during authorization",
        ));
    }
    permit.check_store(store)?;
    if registered_native_project_owner(store, project)? != owner
        || head(store, project, revision)? != project_blob
    {
        return Err(conflict("Catalog source use owner or Project changed"));
    }
    permit.check()?;
    Ok(Current {
        owner,
        project: document,
        project_blob,
        policy_resource,
        policy,
    })
}

fn same_current(before: &Current, after: &Current) -> StorageResult<()> {
    if before.owner != after.owner
        || before.project != after.project
        || before.project_blob != after.project_blob
        || before.policy != after.policy
        || before.policy_resource.resource != after.policy_resource.resource
        || before.policy_resource.blob != after.policy_resource.blob
        || before.policy_resource.owner != after.policy_resource.owner
        || before.policy_resource.provenance != after.policy_resource.provenance
    {
        return Err(conflict(
            "Catalog source use current owner Project or Policy changed",
        ));
    }
    Ok(())
}

fn normalize(
    selections: &[CatalogSourceUseSelection],
) -> StorageResult<Vec<CatalogSourceUseSelection>> {
    if selections.len() > MAX_SELECTIONS {
        return Err(invalid("Catalog source use selection budget"));
    }
    let mut selector_bytes = 0usize;
    for selection in selections {
        let role_bytes = match &selection.role {
            CatalogSourceUseRole::GameArtifact => 0,
            CatalogSourceUseRole::Mod {
                canonical_id,
                native_id,
            } => canonical_id
                .as_str()
                .len()
                .checked_add(native_id.len())
                .ok_or_else(|| invalid("Catalog source use selector metadata overflow"))?,
        };
        selector_bytes = selector_bytes
            .checked_add(selection.resource_id.as_str().len())
            .and_then(|size| size.checked_add(role_bytes))
            .and_then(|size| size.checked_add(64))
            .filter(|size| *size <= MAX_METADATA)
            .ok_or_else(|| invalid("Catalog source use selector metadata budget"))?;
    }
    let mut selected = selections.to_vec();
    selected.sort();
    let mut game = false;
    let mut canonical = BTreeSet::new();
    let mut native = BTreeSet::new();
    for selection in &selected {
        match &selection.role {
            CatalogSourceUseRole::GameArtifact => {
                if game {
                    return Err(invalid("Catalog source use repeats game artifact role"));
                }
                game = true;
            }
            CatalogSourceUseRole::Mod {
                canonical_id,
                native_id,
            } => {
                if native_id.is_empty()
                    || native_id.len() > 128
                    || !native_id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
                    || !canonical.insert(canonical_id.clone())
                    || !native.insert(native_id.clone())
                {
                    return Err(invalid(
                        "Catalog source use mod mapping is invalid or duplicated",
                    ));
                }
            }
        }
    }
    Ok(selected)
}

fn prepare_selected(
    store: &DurableStore,
    permit: &dyn CatalogSourceUsePermit,
    current: &Current,
    project: &ProjectId,
    revision: &Sha256Digest,
    selections: &[CatalogSourceUseSelection],
) -> StorageResult<Vec<PinnedCatalogSourceUse>> {
    let rpc = Rpc(permit);
    let mut reader = permit.resource_reader(MAX_SOURCE_BYTES)?;
    let mut sources = BTreeMap::<ResourceId, RegisteredProjectResource>::new();
    let mut remaining = MAX_SOURCE_BYTES;
    let mut selected = Vec::new();
    for selection in selections {
        permit.check_store(store)?;
        if !sources.contains_key(&selection.resource_id) {
            let query = ProjectResourceQuery::Current {
                resource_id: selection.resource_id.clone(),
            };
            let request = ProjectResourceRequest {
                project,
                current_project_revision: revision,
                query: &query,
                expected: None,
            };
            let actual = reader.metadata(store, &rpc, &request)?;
            check_container(&actual.resource, &actual.blob)?;
            if actual.owner != ResourceOwner::Project(project.clone()) {
                return Err(conflict("Catalog source container owner differs"));
            }
            remaining = remaining
                .checked_sub(actual.blob.byte_length)
                .ok_or_else(|| invalid("Catalog source use whole-source byte budget"))?;
            let request = ProjectResourceRequest {
                expected: Some(&actual.resource),
                ..request
            };
            let read = reader.read(store, &rpc, &request, MAX_SOURCE_BYTES)?;
            if ![
                b"PK\x03\x04".as_slice(),
                b"PK\x05\x06".as_slice(),
                b"PK\x07\x08".as_slice(),
            ]
            .iter()
            .any(|magic| read.bytes.starts_with(magic))
            {
                return Err(invalid(
                    "Catalog source use requires whole ZIP container bytes",
                ));
            }
            sources.insert(selection.resource_id.clone(), actual);
        }
        let actual = sources
            .get(&selection.resource_id)
            .ok_or_else(|| invalid("Catalog source selection missing"))?;
        selected.push(PinnedCatalogSourceUse {
            selection: selection.clone(),
            resource: actual.resource.clone(),
            blob: actual.blob.clone(),
        });
    }
    if head(store, project, revision)? != current.project_blob {
        return Err(conflict("Catalog source use prepared Project changed"));
    }
    permit.check()?;
    Ok(selected)
}

fn verify_selected(
    store: &DurableStore,
    permit: &dyn CatalogSourceUsePermit,
    current: &Current,
    snapshot: &CatalogSourceUseSnapshot,
) -> StorageResult<()> {
    let pins = snapshot
        .approval
        .as_ref()
        .ok_or_else(|| invalid("Catalog source use approval pins missing"))?;
    if current.owner != snapshot.native_owner
        || current.policy_resource.resource != pins.policy_resource
        || current.policy_resource.blob != pins.policy_blob
    {
        return Err(conflict(
            "Catalog source use approved Policy no longer current",
        ));
    }
    let project = &snapshot.project_id;
    let revision: Sha256Digest =
        serde_json::from_value(current.project["revision"].clone()).map_err(contract)?;
    let rpc = Rpc(permit);
    let mut reader = permit.resource_reader(MAX_SOURCE_BYTES)?;
    let historical: Option<(String,i64)> = store.connection.query_row("SELECT d.blob_digest,b.byte_length FROM documents d JOIN blobs b ON b.digest=d.blob_digest WHERE d.definition='Project' AND d.document_id=?1 AND d.content_hash=?2", params![project.as_str(),pins.project_revision.as_str()], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
    let (raw, length) = historical.ok_or(StorageError::NotFound(
        "Catalog source use original Project",
    ))?;
    if raw != pins.project_blob.digest.as_str()
        || length <= 0
        || length as u64 != pins.project_blob.byte_length
    {
        return Err(conflict(
            "Catalog source use original Project raw pin changed",
        ));
    }
    store.read_blob_checked(&pins.project_blob, MAX_PROJECT_BYTES, || rpc.check())?;
    let policy_id: ResourceId =
        serde_json::from_value(pins.policy_resource["resourceId"].clone()).map_err(contract)?;
    let query = ProjectResourceQuery::Historical {
        project_revision: pins.project_revision.clone(),
        resource_id: policy_id,
        digest: pins.policy_blob.digest.clone(),
    };
    let request = ProjectResourceRequest {
        project,
        current_project_revision: &revision,
        query: &query,
        expected: Some(&pins.policy_resource),
    };
    let original_policy = reader.metadata(store, &rpc, &request)?;
    if original_policy.blob != pins.policy_blob {
        return Err(conflict(
            "Catalog source use original Policy association changed",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut remaining = MAX_SOURCE_BYTES;
    for selected in &snapshot.selections {
        if !seen.insert(selected.selection.resource_id.clone()) {
            continue;
        }
        permit.check_store(store)?;
        remaining = remaining
            .checked_sub(selected.blob.byte_length)
            .ok_or_else(|| invalid("Catalog source use whole-source byte budget"))?;
        let query = ProjectResourceQuery::Current {
            resource_id: selected.selection.resource_id.clone(),
        };
        let request = ProjectResourceRequest {
            project,
            current_project_revision: &revision,
            query: &query,
            expected: Some(&selected.resource),
        };
        let actual = reader.metadata(store, &rpc, &request)?;
        if actual.owner != ResourceOwner::Project(project.clone()) || actual.blob != selected.blob {
            return Err(conflict("Catalog source use current resource changed"));
        }
        let query = ProjectResourceQuery::Historical {
            project_revision: pins.project_revision.clone(),
            resource_id: selected.selection.resource_id.clone(),
            digest: selected.blob.digest.clone(),
        };
        let request = ProjectResourceRequest {
            query: &query,
            ..request
        };
        let original = reader.metadata(store, &rpc, &request)?;
        if original.owner != actual.owner || original.blob != actual.blob {
            return Err(conflict(
                "Catalog source use original resource association changed",
            ));
        }
    }
    permit.check()
}

fn check_container(resource: &Value, blob: &BlobRef) -> StorageResult<()> {
    if !matches!(
        resource["mediaType"].as_str(),
        Some("application/java-archive" | "application/zip")
    ) || resource["sha256"] != blob.digest.as_str()
        || resource["sizeBytes"].as_u64() != Some(blob.byte_length)
        || !(4..=MAX_SOURCE_BYTES).contains(&blob.byte_length)
    {
        return Err(invalid(
            "Catalog source use requires bounded whole container metadata",
        ));
    }
    Ok(())
}

fn digest(snapshot: &CatalogSourceUseSnapshot) -> StorageResult<Sha256Digest> {
    canonical_digest(
        &json!({ "format":snapshot.format, "nativeOwner":snapshot.native_owner,
        "projectId":snapshot.project_id, "generation":snapshot.generation,
        "previousStateDigest":snapshot.previous_state_digest, "approval":snapshot.approval,
        "rights":snapshot.rights, "selections":snapshot.selections }),
    )
    .map_err(contract)
}
fn absent(owner: &PrincipalId, project: &ProjectId) -> StorageResult<CatalogSourceUseSnapshot> {
    let mut snapshot = CatalogSourceUseSnapshot {
        format: FORMAT.into(),
        native_owner: owner.clone(),
        project_id: project.clone(),
        generation: 0,
        previous_state_digest: None,
        approval: None,
        rights: RIGHTS.into(),
        selections: Vec::new(),
        state_digest: Sha256Digest::new("0".repeat(64)).map_err(contract)?,
    };
    snapshot.state_digest = digest(&snapshot)?;
    Ok(snapshot)
}
fn state(
    store: &DurableStore,
    owner: &PrincipalId,
    project: &ProjectId,
) -> StorageResult<CatalogSourceUseSnapshot> {
    let exists: bool = store.connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='catalog_source_uses')", [], |row| row.get(0))?;
    if !exists {
        return absent(owner, project);
    }
    let row: Option<(i64,String,Option<String>)> = store.connection.query_row("SELECT generation,substr(state_digest,1,65),CASE WHEN length(CAST(record_json AS BLOB))<=65536 THEN record_json ELSE NULL END FROM catalog_source_uses WHERE native_owner=?1 AND project_id=?2", params![owner.as_str(),project.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
    let Some((generation, state_digest, encoded)) = row else {
        return absent(owner, project);
    };
    let encoded = encoded.ok_or_else(|| invalid("Catalog source use stored metadata budget"))?;
    if encoded.len() > MAX_METADATA {
        return Err(invalid("Catalog source use stored metadata budget"));
    }
    let snapshot: CatalogSourceUseSnapshot = decode(&encoded)?;
    if generation <= 0
        || snapshot.generation != generation as u64
        || snapshot.state_digest.as_str() != state_digest
        || &snapshot.native_owner != owner
        || &snapshot.project_id != project
    {
        return Err(conflict("Catalog source use stored identity differs"));
    }
    validate_snapshot(store, &snapshot)?;
    Ok(snapshot)
}
fn validate_snapshot(
    store: &DurableStore,
    snapshot: &CatalogSourceUseSnapshot,
) -> StorageResult<()> {
    if snapshot.format != FORMAT
        || snapshot.rights != RIGHTS
        || snapshot.generation == 0
        || snapshot.generation > MAX_GENERATION
        || snapshot.previous_state_digest.is_none()
        || snapshot.state_digest != digest(snapshot)?
        || encode_json(&json!(snapshot)).map_err(contract)?.len() > MAX_METADATA
    {
        return Err(invalid("Catalog source use stored decision is invalid"));
    }
    let pins = snapshot
        .approval
        .as_ref()
        .ok_or_else(|| invalid("Catalog source use stored approval missing"))?;
    store
        .validator
        .validate("ResourceRef", &pins.policy_resource)
        .map_err(contract)?;
    if pins.policy_resource["mediaType"] != POLICY_MEDIA_TYPE
        || pins.policy_resource["sha256"] != pins.policy_blob.digest.as_str()
        || pins.policy_resource["sizeBytes"].as_u64() != Some(pins.policy_blob.byte_length)
        || pins.policy_blob.byte_length > MAX_PROJECT_BYTES
        || pins.project_blob.byte_length == 0
        || pins.project_blob.byte_length > MAX_PROJECT_BYTES
    {
        return Err(invalid(
            "Catalog source use stored Project/Policy pin is invalid",
        ));
    }
    let selectors = snapshot
        .selections
        .iter()
        .map(|pin| pin.selection.clone())
        .collect::<Vec<_>>();
    if normalize(&selectors)? != selectors {
        return Err(invalid("Catalog source use stored ordering is invalid"));
    }
    let mut resources = BTreeMap::new();
    let mut remaining = MAX_SOURCE_BYTES;
    for selected in &snapshot.selections {
        store
            .validator
            .validate("ResourceRef", &selected.resource)
            .map_err(contract)?;
        check_container(&selected.resource, &selected.blob)?;
        if selected.resource["resourceId"] != selected.selection.resource_id.as_str() {
            return Err(invalid("Catalog source use stored resource ID differs"));
        }
        if let Some(previous) = resources.insert(
            selected.selection.resource_id.clone(),
            (&selected.resource, &selected.blob),
        ) {
            if previous != (&selected.resource, &selected.blob) {
                return Err(invalid(
                    "Catalog source use repeats inconsistent resource pins",
                ));
            }
        } else {
            remaining = remaining
                .checked_sub(selected.blob.byte_length)
                .ok_or_else(|| invalid("Catalog source use stored whole-source budget"))?;
        }
    }
    Ok(())
}
fn unchanged_state(store: &DurableStore, snapshot: &CatalogSourceUseSnapshot) -> StorageResult<()> {
    if state(store, &snapshot.native_owner, &snapshot.project_id)? != *snapshot {
        return Err(conflict(
            "Catalog source use state changed during observation",
        ));
    }
    Ok(())
}
fn head(
    store: &DurableStore,
    project: &ProjectId,
    revision: &Sha256Digest,
) -> StorageResult<BlobRef> {
    let row: Option<(String,String,String,i64)> = store.connection.query_row("SELECT h.revision,h.blob_digest,d.blob_digest,b.byte_length FROM project_heads h JOIN documents d ON d.definition='Project' AND d.document_id=h.project_id AND d.content_hash=h.revision JOIN blobs b ON b.digest=h.blob_digest WHERE h.project_id=?1", [project.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional()?;
    let (actual, raw, history, length) =
        row.ok_or(StorageError::NotFound("Catalog source use current Project"))?;
    if actual != revision.as_str()
        || raw != history
        || length <= 0
        || length as u64 > MAX_PROJECT_BYTES
    {
        return Err(conflict(
            "Catalog source use exact Project raw head differs",
        ));
    }
    Ok(BlobRef {
        digest: Sha256Digest::new(raw).map_err(contract)?,
        byte_length: length as u64,
    })
}
fn invalid(message: &'static str) -> StorageError {
    StorageError::InvalidInput(message.into())
}
fn conflict(message: &'static str) -> StorageError {
    StorageError::Conflict(message)
}
fn contract(cause: impl std::fmt::Display) -> StorageError {
    StorageError::Contract(cause.to_string())
}

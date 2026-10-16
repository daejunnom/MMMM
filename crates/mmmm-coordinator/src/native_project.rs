//! Explicit native-owner Project initialization in the already locked daemon
//! Store. Creation is private management, not a new canonical function or a
//! source of game execution, reflection or redistribution permission.

use crate::workspace_bootstrap::NativeOwnerWitness;
use mmmm_contracts::{
    ContractValidator, PrincipalId, ProjectId, ResourceId, TargetProfileId, projected_digest,
};
use mmmm_runtime::storage::{
    DurableStore, StorageError, StorageResult,
    bootstrap::{self, NativeOwnerCreatePermit, ProjectBootstrapReceipt, ProjectBootstrapRequest},
};
use serde_json::{Value, json};
use std::time::Instant;

/// Private construction retains the actual same-store owner witness and exact
/// generated documents. A caller cannot implement this concrete permit by
/// supplying a principal, root, policy label or public setup JSON.
struct NativeProjectCreatePermit {
    owner: NativeOwnerWitness,
    project: Value,
    policy: Value,
}
impl NativeOwnerCreatePermit for NativeProjectCreatePermit {
    fn check(&self, store: &DurableStore) -> StorageResult<()> {
        self.owner.check_store(store)
    }
    fn authorize_create(
        &mut self,
        store: &DurableStore,
        request: &ProjectBootstrapRequest<'_>,
    ) -> StorageResult<PrincipalId> {
        self.check(store)?;
        if request.project != &self.project || request.policy != &self.policy {
            return Err(StorageError::Conflict(
                "Native Project initialization documents",
            ));
        }
        Ok(self.owner.principal().clone())
    }
}

/// Only the explicit native `init` entry or kernel-authenticated owner
/// management handler calls this. TargetProfileId is an unverified locator;
/// the resulting Project cannot dispatch to a game without actual host and
/// target evidence, current policy, approved scope and a durable plan.
pub fn create_native_project(
    store: &mut DurableStore,
    name: &str,
    target: &TargetProfileId,
    deadline: Instant,
) -> StorageResult<ProjectBootstrapReceipt> {
    let owner = NativeOwnerWitness::capture(store, deadline)?;
    if name.is_empty() || name.len() > 1024 || name.chars().any(char::is_control) {
        return Err(StorageError::InvalidInput(
            "Initial Project name is invalid".into(),
        ));
    }
    let project_id = ProjectId::new(fresh_id("project")?).map_err(|_| invalid())?;
    let policy_id = ResourceId::new(fresh_id("policy")?).map_err(|_| invalid())?;
    let mut project = json!({
        "contractVersion":mmmm_contracts::CONTRACT_VERSION,
        "projectId":project_id,"revision":"0".repeat(64),"name":name,
        "targetProfileId":target,
        "gameTicksPerSecond":{"numerator":"20","denominator":"1"},
        "authoringSpace":"minecraft_xyz_blocks","prefabIds":[],"instanceIds":[],
        "resourceIds":[policy_id],"policyResourceId":policy_id,"ownedResources":[]
    });
    project["revision"] = json!(projected_digest("Project", &project).map_err(|_| invalid())?);
    // These are the original canonical defaults. Their labels select policy
    // behavior; they do not grant Apply, regions or source-copy permission.
    let policy: Value = mmmm_contracts::parse_json(include_bytes!("../../../examples/policy.json"))
        .map_err(|_| invalid())?;
    let validator = ContractValidator::embedded().map_err(|_| invalid())?;
    validator
        .validate("Project", &project)
        .map_err(|_| invalid())?;
    validator
        .validate("Policy", &policy)
        .map_err(|_| invalid())?;
    owner.check_store(store)?;
    let mut permit = NativeProjectCreatePermit {
        owner,
        project: project.clone(),
        policy: policy.clone(),
    };
    bootstrap::create_project(
        store,
        &mut permit,
        &ProjectBootstrapRequest {
            project: &project,
            policy: &policy,
        },
    )
}

fn fresh_id(prefix: &str) -> StorageResult<String> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| invalid())?;
    let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{prefix}-{hex}"))
}
fn invalid() -> StorageError {
    StorageError::InvalidInput("Native Project initialization is unavailable".into())
}

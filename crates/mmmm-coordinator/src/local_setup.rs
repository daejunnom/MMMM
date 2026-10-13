//! Explicit local CLI setup owns the protected root only while no daemon owns
//! it. An active daemon returns Busy before SQLite opens; this path never opens
//! a second application ledger or upgrades a game/read/Apply grant.

use crate::{
    bootstrap::register_explicit_host_setup, credential::local_owner_principal,
    setup::PublicHostSetup,
};
use mmmm_contracts::{PrincipalId, ProjectId};
use mmmm_runtime::storage::{DurableStore, StorageError, StoreConfig};
use serde_json::Value;
use std::{
    path::Path,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub enum LocalSetupError {
    OwnerUnavailable,
    InvalidInput,
    Busy,
    ProjectUnavailable,
    Verification,
    /// The immutable protected registration remains intentionally retained.
    /// No game capability was installed and an existing config was not replaced.
    PublicConfigNotWritten,
    Deadline,
}
impl std::fmt::Display for LocalSetupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::OwnerUnavailable => "Current native local owner could not be authenticated",
            Self::InvalidInput => "Explicit local host setup input is invalid",
            Self::Busy => "The daemon owns this data root; no second ledger was opened",
            Self::ProjectUnavailable => "The selected canonical Project is unavailable",
            Self::Verification => "Selected host executable or installed JAR could not be verified",
            Self::PublicConfigNotWritten => {
                "Protected host approval was retained, but the public config was not written"
            }
            Self::Deadline => "Explicit local host setup deadline reached",
        })
    }
}
impl std::error::Error for LocalSetupError {}

/// Paths come from an explicit local CLI selection. The fixed public config
/// contains only approved executable/JAR digests, root/project locators and
/// requested scope. Neither this struct nor the returned config is authority.
pub struct LocalHostSetup<'a> {
    pub executable: &'a Path,
    pub installed_host_jar: &'a Path,
    pub destination: &'a Path,
    pub project: ProjectId,
    pub scope: Value,
}

pub fn register_local_host_setup(
    config: StoreConfig,
    request: LocalHostSetup<'_>,
) -> Result<PublicHostSetup, LocalSetupError> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let owner = local_owner_principal().map_err(|_| LocalSetupError::OwnerUnavailable)?;
    if !config.data_root.is_absolute()
        || request
            .destination
            .file_name()
            .is_none_or(|name| name != "mmmm-host.json")
        || request.scope["projectId"] != request.project.as_str()
    {
        return Err(LocalSetupError::InvalidInput);
    }
    current_owner(&owner, deadline)?;
    let mut store = DurableStore::open(config).map_err(|error| match error {
        StorageError::Busy => LocalSetupError::Busy,
        _ => LocalSetupError::Verification,
    })?;
    // Actual canonical retained project bytes, not a caller-supplied Project or
    // policyRevision, establish the selected local project before registration.
    store
        .project(&request.project)
        .map_err(|_| LocalSetupError::ProjectUnavailable)?;
    current_owner(&owner, deadline)?;
    let setup = register_explicit_host_setup(
        &mut store,
        request.executable,
        request.installed_host_jar,
        request.project,
        request.scope,
    )
    .map_err(|_| LocalSetupError::Verification)?;
    current_owner(&owner, deadline)?;
    setup
        .write_new(request.destination)
        .map_err(|_| LocalSetupError::PublicConfigNotWritten)?;
    // Retaining either file on a final uncertainty is safer than silently
    // rolling back durable approval or deleting a user-visible config.
    current_owner(&owner, deadline)?;
    Ok(setup)
}

fn current_owner(owner: &PrincipalId, deadline: Instant) -> Result<(), LocalSetupError> {
    if Instant::now() >= deadline {
        return Err(LocalSetupError::Deadline);
    }
    if crate::peer::fatal_stop_requested()
        || local_owner_principal().map_err(|_| LocalSetupError::OwnerUnavailable)? != *owner
    {
        return Err(LocalSetupError::OwnerUnavailable);
    }
    Ok(())
}

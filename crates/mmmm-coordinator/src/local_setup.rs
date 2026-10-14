//! Explicit local CLI setup owns the protected root only while no daemon owns
//! it. An active daemon returns Busy before SQLite opens; this path never opens
//! a second application ledger or upgrades a game/read/Apply grant.

use crate::{
    bootstrap::{
        NativeWorkspacePermit, register_explicit_host_setup,
        register_explicit_host_setup_with_read_policy,
    },
    credential::local_owner_principal,
    setup::PublicHostSetup,
    workspace_bootstrap::NativeOwnerWitness,
};
use mmmm_contracts::{PrincipalId, ProjectId};
use mmmm_runtime::storage::host_setup::{HostReadPolicy, HostReadPolicyRecord};
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
    ReadPolicyState,
    ReadPolicyConflict,
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
            Self::ReadPolicyState => {
                "Current protected host read policy state could not be verified"
            }
            Self::ReadPolicyConflict => {
                "Explicit policy differs from the immutable retained host setup or read policy"
            }
            Self::PublicConfigNotWritten => {
                "Protected host approval was retained, but the public config was not written"
            }
            Self::Deadline => "Explicit local host setup deadline reached",
        })
    }
}
impl std::error::Error for LocalSetupError {}

/// Original local causes remain typed. A confirmed policy receipt survives all
/// later failures; absence of a receipt is not evidence that a failed COMMIT
/// rolled back. Public formatting contains no selected paths or raw SQL text.
#[derive(Debug)]
pub struct LocalReadPolicySetupError {
    pub retained_policy: Option<Box<HostReadPolicyRecord>>,
    pub failure: LocalSetupError,
    cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}
impl LocalReadPolicySetupError {
    fn before(failure: LocalSetupError) -> Self {
        Self {
            retained_policy: None,
            failure,
            cause: None,
        }
    }
    fn storage(cause: StorageError) -> Self {
        let failure = match &cause {
            StorageError::Busy => LocalSetupError::Busy,
            StorageError::Conflict(
                "Immutable approved host read policy" | "Immutable approved host setup",
            ) => LocalSetupError::ReadPolicyConflict,
            _ => LocalSetupError::ReadPolicyState,
        };
        Self {
            retained_policy: None,
            failure,
            cause: Some(Box::new(cause)),
        }
    }
    fn retained(record: &HostReadPolicyRecord, failure: LocalSetupError) -> Self {
        Self {
            retained_policy: Some(Box::new(record.clone())),
            failure,
            cause: None,
        }
    }
    fn with_receipt(mut self, record: &HostReadPolicyRecord) -> Self {
        self.retained_policy = Some(Box::new(record.clone()));
        self
    }
}
impl std::fmt::Display for LocalReadPolicySetupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(record) = &self.retained_policy {
            write!(
                formatter,
                "Host read policy {} for Project {} was committed and retained; ",
                record.policy_digest(),
                record.project_id()
            )?;
        }
        self.failure.fmt(formatter)
    }
}
impl std::error::Error for LocalReadPolicySetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_deref()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or(Some(&self.failure))
    }
}

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

/// Optional explicit policy has no defaults inherited from the public config,
/// legacy setup, HostHello or world_read. The held Store remains unique and an
/// active daemon still returns Busy without opening a second ledger.
pub fn register_local_host_setup_with_read_policy(
    config: StoreConfig,
    request: LocalHostSetup<'_>,
    policy: &HostReadPolicy,
    deadline: Instant,
) -> Result<(PublicHostSetup, HostReadPolicyRecord), LocalReadPolicySetupError> {
    let deadline = deadline.min(Instant::now() + Duration::from_secs(15));
    let owner = local_owner_principal()
        .map_err(|_| LocalReadPolicySetupError::before(LocalSetupError::OwnerUnavailable))?;
    if !config.data_root.is_absolute()
        || request
            .destination
            .file_name()
            .is_none_or(|name| name != "mmmm-host.json")
        || request.scope["projectId"] != request.project.as_str()
    {
        return Err(LocalReadPolicySetupError::before(
            LocalSetupError::InvalidInput,
        ));
    }
    current_owner(&owner, deadline).map_err(LocalReadPolicySetupError::before)?;
    let mut store =
        DurableStore::open_existing(config).map_err(LocalReadPolicySetupError::storage)?;
    store
        .project(&request.project)
        .map_err(LocalReadPolicySetupError::storage)?;
    let witness = NativeOwnerWitness::capture(&store, deadline)
        .map_err(LocalReadPolicySetupError::storage)?;
    if witness.principal() != &owner {
        return Err(LocalReadPolicySetupError::before(
            LocalSetupError::OwnerUnavailable,
        ));
    }
    witness
        .check_project(&store, &request.project)
        .map_err(LocalReadPolicySetupError::storage)?;
    current_owner(&owner, deadline).map_err(LocalReadPolicySetupError::before)?;
    let (setup, record) = register_explicit_host_setup_with_read_policy(
        &mut store,
        request.executable,
        request.installed_host_jar,
        request.project,
        request.scope,
        policy,
        deadline,
    )
    .map_err(LocalReadPolicySetupError::storage)?;
    finish_read_policy_setup(
        &setup,
        &record,
        || {
            current_owner(&owner, deadline).map_err(LocalReadPolicySetupError::before)?;
            witness
                .check_project(&store, record.project_id())
                .map_err(LocalReadPolicySetupError::storage)?;
            Ok(())
        },
        || setup.write_new(request.destination),
    )?;
    Ok((setup, record))
}

fn finish_read_policy_setup(
    setup: &PublicHostSetup,
    record: &HostReadPolicyRecord,
    mut checkpoint: impl FnMut() -> Result<(), LocalReadPolicySetupError>,
    write_config: impl FnOnce() -> Result<(), crate::setup::SetupError>,
) -> Result<(), LocalReadPolicySetupError> {
    checkpoint().map_err(|failure| failure.with_receipt(record))?;
    if let Err(cause) = write_config() {
        let mut error =
            LocalReadPolicySetupError::retained(record, LocalSetupError::PublicConfigNotWritten);
        error.cause = Some(Box::new(cause));
        return Err(error);
    }
    checkpoint().map_err(|failure| failure.with_receipt(record))?;
    // Keep only confirmed locators in failure diagnostics; this also verifies
    // the returned public config still describes the exact committed identity.
    if setup.project_id != *record.project_id()
        || setup.host_artifact_digest != *record.host_artifact_digest()
    {
        return Err(LocalReadPolicySetupError::retained(
            record,
            LocalSetupError::Verification,
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn finish_read_policy_setup_for_test(
    setup: &PublicHostSetup,
    record: &HostReadPolicyRecord,
    mut checkpoint: impl FnMut() -> Result<(), LocalSetupError>,
    write_config: impl FnOnce() -> Result<(), crate::setup::SetupError>,
) -> Result<(), LocalReadPolicySetupError> {
    finish_read_policy_setup(
        setup,
        record,
        || checkpoint().map_err(LocalReadPolicySetupError::before),
        write_config,
    )
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

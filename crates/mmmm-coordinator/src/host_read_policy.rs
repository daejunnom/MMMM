//! Explicit native host read policy. These helpers return protected facts;
//! source installation and Shape grants still require their actual consumers.

use crate::{
    authority::LocalAuthority,
    bootstrap::NativeWorkspacePermit,
    host::{CompletedPairingWitness, NativePairingOwnerFailure},
    workspace_bootstrap::NativeOwnerWitness,
};
use mmmm_application::{AppError, AppResult};
use mmmm_contracts::{PrincipalId, Sha256Digest};
use mmmm_reference::shape::GameMode;
use mmmm_runtime::storage::{
    DurableStore, StorageError, StorageResult, WriteScope,
    host_setup::{
        HostReadPolicy, HostReadPolicyRecord, HostSetupAuthority, HostSetupRecord,
        HostSetupRegistration, HostSetupRpcContext, host_read_policy,
    },
};
use serde_json::Value;
use std::{cell::RefCell, path::Path};

fn denied() -> StorageError {
    StorageError::Conflict("Current native host read policy authority required")
}
fn mode(name: &str) -> StorageResult<GameMode> {
    serde_json::from_value(Value::String(name.to_owned()))
        .map_err(|_| StorageError::InvalidInput("Host read policy mode is invalid".into()))
}

/// CLI parsing validates the actual reference enum. Runtime stores only its
/// finite validated names, avoiding an enum copy or runtime/reference cycle.
pub(crate) fn selected_host_read_policy(
    names: &[String],
    native_observation_user_local_only: bool,
) -> StorageResult<HostReadPolicy> {
    if names.len() > 4 {
        return Err(denied());
    }
    for name in names {
        mode(name)?;
    }
    HostReadPolicy::new(names.iter().cloned(), native_observation_user_local_only)
}

struct PolicyReadAccess<'a> {
    store: &'a DurableStore,
    owner: &'a NativeOwnerWitness,
    pairing: &'a CompletedPairingWitness,
    authority: &'a LocalAuthority,
    first_failure: RefCell<Option<AppError>>,
}
impl PolicyReadAccess<'_> {
    fn current(&self) -> AppResult<()> {
        self.pairing.check_current(self.authority)?;
        self.owner
            .check_store(self.store)
            .map_err(|cause| AppError::storage("PERMISSION_REQUIRED", cause))?;
        if self.owner.principal() != self.pairing.native_owner()
            || self
                .owner
                .check_project(self.store, self.pairing.project())
                .map_err(|cause| AppError::storage("PERMISSION_REQUIRED", cause))?
                != *self.pairing.native_owner()
        {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Native host policy owner differs from completed pairing",
            ));
        }
        self.pairing.check_current(self.authority)
    }
    fn checkpoint(&self) -> StorageResult<()> {
        if let Err(cause) = self.current() {
            let mut failure = self.first_failure.borrow_mut();
            if failure.is_none() {
                *failure = Some(cause);
            }
            return Err(denied());
        }
        Ok(())
    }
    fn translate(&self, cause: StorageError) -> AppError {
        self.first_failure.borrow_mut().take().unwrap_or_else(|| {
            let code = if matches!(&cause, StorageError::NotFound(_)) {
                "SOURCE_UNAVAILABLE"
            } else {
                "PERMISSION_REQUIRED"
            };
            AppError::storage(code, cause)
        })
    }
}
impl HostSetupRpcContext for PolicyReadAccess<'_> {
    fn check(&self) -> StorageResult<()> {
        self.checkpoint()
    }
    fn authenticated_local_owner(&self) -> StorageResult<PrincipalId> {
        self.checkpoint()?;
        Ok(self.owner.principal().clone())
    }
}
struct PolicyReadAuthority<'a, 'b>(&'a PolicyReadAccess<'b>);
impl HostSetupAuthority for PolicyReadAuthority<'_, '_> {
    fn authorize_registration(
        &mut self,
        _: &DurableStore,
        _: &PrincipalId,
        _: &HostSetupRegistration,
    ) -> StorageResult<()> {
        Err(denied())
    }
    fn authorize_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        setup: &HostSetupRecord,
    ) -> StorageResult<()> {
        self.0.checkpoint()?;
        if !std::ptr::eq(store, self.0.store)
            || principal != self.0.owner.principal()
            || &setup.principal != principal
            || &setup.project_id != self.0.pairing.project()
        {
            return Err(denied());
        }
        Ok(())
    }
    fn authorize_read_policy_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        setup: &HostSetupRecord,
        policy: &HostReadPolicyRecord,
    ) -> StorageResult<()> {
        self.authorize_read(store, principal, setup)?;
        if policy.principal() != principal
            || policy.project_id() != &setup.project_id
            || policy.host_artifact_digest() != &setup.host_artifact_digest
        {
            return Err(denied());
        }
        for name in policy.policy().shape_modes() {
            mode(name)?;
        }
        self.0.checkpoint()
    }
}

/// Only CurrentCompletedPairingOwner delegates here with its short raw-owner
/// borrow. No owner is captured/cloned, no new Store opened, and no original
/// bootstrap/request deadline renewed. The result is never a source grant.
pub(crate) fn read_current_host_policy(
    store: &DurableStore,
    owner: &NativeOwnerWitness,
    pairing: &CompletedPairingWitness,
    authority: &LocalAuthority,
) -> AppResult<HostReadPolicyRecord> {
    let access = PolicyReadAccess {
        store,
        owner,
        pairing,
        authority,
        first_failure: RefCell::new(None),
    };
    access.current()?;
    let result = pairing.with_current_original_offer(authority, |offer| {
        if offer.get("dataRoot").and_then(Value::as_str).map(Path::new) != Some(store.data_root())
            || offer.get("projectId").and_then(Value::as_str) != Some(pairing.project().as_str())
        {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Native host policy belongs to another held Store or Project",
            ));
        }
        let artifact: Sha256Digest = serde_json::from_value(offer["hostArtifactDigest"].clone())
            .map_err(|_| {
                AppError::new(
                    "PERMISSION_REQUIRED",
                    "Original host policy artifact is invalid",
                )
            })?;
        let requested: WriteScope =
            serde_json::from_value(offer["scope"].clone()).map_err(|_| {
                AppError::new(
                    "PERMISSION_REQUIRED",
                    "Original host policy scope is invalid",
                )
            })?;
        let mut reader = PolicyReadAuthority(&access);
        host_read_policy(
            store,
            &access,
            &mut reader,
            pairing.project(),
            &artifact,
            &requested,
        )
        .map_err(|cause| access.translate(cause))
    });
    let checked = access.current();
    match (result, checked) {
        (Ok(record), Ok(())) => Ok(record),
        (Err(cause), Ok(())) | (Ok(_), Err(cause)) => Err(cause),
        (Err(primary), Err(checkpoint)) => Err(AppError::caused_by(
            primary.code,
            primary.message,
            NativePairingOwnerFailure {
                primary,
                checkpoint,
            },
        )),
    }
}

#[cfg(test)]
#[path = "host_read_policy_tests.rs"]
mod tests;

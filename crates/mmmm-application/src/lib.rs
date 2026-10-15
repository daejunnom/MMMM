//! Shared use cases for every facade. The durable runtime is the only operation
//! authority. Ports are injected by the authenticated Coordinator composition;
//! request JSON cannot supply an authority, observer, or implementation.
mod before_capture;
mod execution;
mod planning;
pub mod ports;
mod recovery;
mod registered_action;
mod report;
mod result_binding;
mod setup;
pub mod types;
mod undo;
pub mod undo_context;
pub mod undo_provider;

pub use ports::*;
pub use setup::{SetupCommittedPlanFailure, SetupPlanningPort, SetupSelection};
pub use types::*;
pub use undo::{
    HostUndoReceipt, HostUndoRegistration, InspectedHostUndoMaterial, UndoMaterialPort,
};
pub use undo_context::{UndoContextPort, UndoExecutionContext};
pub use undo_provider::{InspectedUndoRoles, UndoActionRole, UndoExecutionPort};

use mmmm_contracts::{ContractValidator, PrincipalId, ProjectId};
use mmmm_runtime::storage::DurableStore;
use serde_json::Value;

pub struct Application<'a> {
    pub store: &'a mut DurableStore,
    pub authority: &'a mut dyn AuthorityPort,
    pub planner: &'a mut dyn PlanningPort,
    pub provider: &'a mut dyn ProviderPort,
    pub observer: &'a mut dyn IndependentObserverPort,
    pub ids: &'a mut dyn IdSource,
    pub clock: &'a dyn Clock,
}

impl Application<'_> {
    pub fn project_inspect(&mut self, principal: &PrincipalId, input: &Value) -> AppResult<Value> {
        validate("ProjectQuery", input)?;
        let project_id: ProjectId = decode(&input["projectId"])?;
        self.authority
            .authorize(principal, &project_id, Access::ReadProject, None, None)?;
        let mut project = self
            .store
            .project(&project_id)
            .map_err(|e| AppError::storage("NOT_FOUND", e))?;
        if !input["expectedRevision"].is_null() && input["expectedRevision"] != project["revision"]
        {
            let revision = decode(&input["expectedRevision"])?;
            project = self
                .store
                .project_revision(&project_id, &revision)
                .map_err(|e| AppError::storage("REVISION_CONFLICT", e))?;
        }
        let inspection = self
            .planner
            .inspect_project_with_store(self.store, principal, &project)?;
        let output = serde_json::json!({
            "project": project,
            "diagnostics": inspection.diagnostics,
            "unresolvedReferences": inspection.unresolved_references,
            "runtimeBindingsAvailable": inspection.runtime_bindings_available
        });
        validate("ProjectView", &output)?;
        Ok(output)
    }
}

pub(crate) fn validate(definition: &str, value: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .map_err(AppError::contract)?
        .validate(definition, value)
        .map_err(AppError::contract)
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> AppResult<T> {
    serde_json::from_value(value.clone()).map_err(|_| {
        AppError::new(
            "INVALID_INPUT",
            "Typed input does not match the canonical contract",
        )
    })
}
pub(crate) fn text<'a>(value: &'a Value, field: &str) -> AppResult<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| AppError::new("INVALID_INPUT", "Required string field is absent"))
}
pub(crate) fn diagnostic(code: &str, message: &str) -> Value {
    serde_json::json!({"code":code,"severity":"error","message":message})
}

#[cfg(test)]
mod tests;

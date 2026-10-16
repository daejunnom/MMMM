//! FN31 adapter borrowing the Coordinator's unique store. Authentication is a
//! live session witness; a previously cloned principal loses permission when
//! its authority is revoked, expires or its Coordinator generation is dropped.

use crate::{
    AuthenticatedPrincipal,
    service::{RequestBudget, ServiceError, ServiceExtension, ServiceExtensionContext},
};
use mmmm_contracts::{ContextId, PrincipalId};
use mmmm_runtime::artifact::{
    ArtifactError, ArtifactReader, ArtifactResult, ArtifactRpcContext, ResourceAuthority,
};
use serde_json::Value;

pub struct ArtifactExtension {
    reader: ArtifactReader,
}
impl ArtifactExtension {
    pub fn new(
        authority: Box<dyn ResourceAuthority>,
        maximum_verification_bytes: u64,
    ) -> ArtifactResult<Self> {
        Ok(Self {
            reader: ArtifactReader::new(authority, maximum_verification_bytes)?,
        })
    }
}
impl ServiceExtension for ArtifactExtension {
    fn call(
        &mut self,
        method: &str,
        input: &Value,
        context: &mut ServiceExtensionContext<'_>,
    ) -> Result<Value, ServiceError> {
        if method != "artifact.read" {
            return Err(ServiceError::new(
                "IMPLEMENTATION_UNAVAILABLE",
                "Artifact owner only implements artifact.read",
            ));
        }
        context.check(method)?;
        let rpc = ArtifactCallContext {
            principal: context.principal,
            budget: context.budget,
        };
        self.reader
            .read(context.store, &rpc, input)
            .map_err(|error| ServiceError::new(error.code, error.message))
    }
}

pub(crate) struct ArtifactCallContext<'a> {
    pub principal: &'a AuthenticatedPrincipal,
    pub budget: &'a RequestBudget,
}
impl ArtifactRpcContext for ArtifactCallContext<'_> {
    fn check(&self) -> ArtifactResult<()> {
        self.budget
            .check()
            .map_err(|error| ArtifactError::new(error.code, error.message))?;
        if crate::peer::fatal_stop_requested() || !self.principal.permits("artifact.read") {
            return Err(ArtifactError::forbidden());
        }
        Ok(())
    }
    fn principal_for_context(&self, id: &ContextId) -> ArtifactResult<PrincipalId> {
        self.check()?;
        if !self.principal.permits_context(id.as_str()) {
            return Err(ArtifactError::forbidden());
        }
        Ok(self.principal.principal().clone())
    }
}

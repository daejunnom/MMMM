//! Registered action facades enter the same authenticated application and
//! planner. A read callback cannot be substituted with a write invocation.
use crate::planning::{check_context, check_descriptor};
use crate::*;
use mmmm_contracts::{ContextId, canonical_digest};
use serde_json::{Value, json};

impl Application<'_> {
    pub fn action_plan(&mut self, principal: &PrincipalId, input: &Value) -> AppResult<Value> {
        validate("RegisteredActionRequest", input)?;
        let (context, project) = self.registered_action_context(principal, input, Access::Plan)?;
        let descriptor = self.provider.action_descriptor(input, &context)?;
        self.check_registered_action(input, &context, &descriptor)?;
        if descriptor["effect"] == "read" {
            return Err(AppError::new(
                "EFFECT_MISMATCH",
                "Registered action planning requires a declared write or unknown effect",
            ));
        }
        let request = json!({"projectId":project["projectId"],"expectedRevision":project["revision"],
            "contextId":context["contextId"],"intent":{"kind":"external.action","request":input}});
        // The existing planner assembles opaque or typed frozen steps without
        // invoking any provider preview or granting permission to apply them.
        self.plan_create(principal, &request)
    }

    pub fn action_read(&mut self, principal: &PrincipalId, input: &Value) -> AppResult<Value> {
        validate("RegisteredActionRequest", input)?;
        let (context, _) = self.registered_action_context(principal, input, Access::ReadAction)?;
        let descriptor = self.provider.action_descriptor(input, &context)?;
        self.check_registered_action(input, &context, &descriptor)?;
        if descriptor["effect"] != "read" {
            return Err(AppError::new(
                "EFFECT_MISMATCH",
                "Registered read rejects actions with write or unknown effects",
            ));
        }
        let output = self
            .provider
            .registered_read_with_store(self.store, input, &context)?;
        validate("ProviderResult", &output).map_err(|_| {
            AppError::new(
                "OUTPUT_INVALID",
                "Registered read response violates its canonical result contract",
            )
        })?;
        if output["effects"] != "none" {
            return Err(AppError::new(
                "EFFECT_MISMATCH",
                "A declared read reported target effects",
            ));
        }
        if output["status"] == "complete" {
            ContractValidator::shared()
                .map_err(AppError::contract)?
                .compile_action_schema(&descriptor["outputSchema"])
                .map_err(AppError::contract)?
                .validate(&output["data"])
                .map_err(|_| {
                    AppError::new(
                        "OUTPUT_INVALID",
                        "Registered read data violates the pinned output schema",
                    )
                })?;
        }
        // Authority is checked again before releasing data; an old provider
        // context is the locator for the read rather than a lasting read grant.
        let (fresh, _) = self.registered_action_context(principal, input, Access::ReadAction)?;
        if fresh["contextDigest"] != context["contextDigest"] {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Registered read context changed before its result was released",
            ));
        }
        Ok(output)
    }

    fn registered_action_context(
        &mut self,
        principal: &PrincipalId,
        input: &Value,
        access: Access,
    ) -> AppResult<(Value, Value)> {
        let context_id: ContextId = decode(&input["contextId"])?;
        let context = self.provider.context(principal, &context_id)?;
        let project_id: ProjectId = decode(&context["projectId"])?;
        check_context(principal, &project_id, &context_id, &context)?;
        if context["scope"]["projectId"] != context["projectId"] {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Registered action context has inconsistent project scope",
            ));
        }
        self.authority
            .authorize(principal, &project_id, access, Some(&context), None)?;
        let project = self
            .store
            .project(&project_id)
            .map_err(|e| AppError::storage("NOT_FOUND", e))?;
        Ok((context, project))
    }

    fn check_registered_action(
        &self,
        request: &Value,
        context: &Value,
        descriptor: &Value,
    ) -> AppResult<()> {
        validate("ActionDescriptor", descriptor)?;
        if canonical_digest(descriptor)
            .map_err(AppError::digest)?
            .as_str()
            != text(request, "actionDigest")?
        {
            return Err(AppError::new(
                "UNKNOWN_CAPABILITY",
                "Requested registered action digest is absent from the current immutable registry",
            ));
        }
        let pins = json!({"bindingId":request["bindingId"],"actionId":request["actionId"],
            "actionDigest":request["actionDigest"],"arguments":request["arguments"],
            "actionContractVersion":descriptor["contractVersion"],"implementationDigest":descriptor["implementationDigest"],
            "effect":descriptor["effect"],"completion":descriptor["completion"],"recovery":descriptor["recovery"],
            "verificationRequirement":descriptor["verificationRequirement"]});
        check_descriptor(&pins, context, descriptor)
    }
}

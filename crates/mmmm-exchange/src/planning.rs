//! FN26/FN29 use the one application plan contract. This facade selects an
//! already observed external binding or submits a typed scene import intent;
//! it owns neither a dispatcher, approval token nor another operation journal.
use crate::bake::{validate_bake_request, validate_source_pins};
use crate::manifest::InspectedBundle;
use crate::patch::{DeltaPolicy, validate_scene_patch};
use crate::selection::Selection;
use crate::{ExchangeError, ExchangeResult, array, validate};
use mmmm_adapters::{Effect, InventorySnapshot, Side, VerificationRequirement, VersionEvidence};
use mmmm_application::Application;
use mmmm_contracts::{ActionId, BindingId, PrincipalId};
use serde_json::{Value, json};

/// Effect-free plan request translation. InventorySnapshot is constructed from
/// authenticated runtime observations; a descriptor or name in input is not an
/// alternative to that snapshot. An absent bake provider remains unavailable.
pub fn bake_plan_request(
    input: &Value,
    source: &InspectedBundle,
    inventory: &InventorySnapshot,
) -> ExchangeResult<Value> {
    validate("BakePlanRequest", input)?;
    let request = &input["request"];
    validate_bake_request(request)?;
    validate_source_pins(request, source)?;
    if input["contextId"].as_str() != Some(inventory.context().context_id().as_str())
        || inventory.context().environment().execution_side() != Some(Side::External)
    {
        return Err(ExchangeError::new(
            "PERMISSION_REQUIRED",
            "Bake needs this observed external context, separately from game installation",
        ));
    }
    let capabilities = array(request, "requiredCapabilities")?;
    if capabilities.len() != 1 {
        return Err(ExchangeError::new(
            "CAPABILITY_UNAVAILABLE",
            "Base bake planning requires one exact solver semantic action; a multi-capability invocation needs an explicitly verified combined action profile",
        ));
    }
    let mut guarantees = vec!["artifact_manifest"];
    if array(source.bundle().manifest(), "preservedFeatures")?
        .iter()
        .any(|feature| feature == crate::normalization::PROFILE)
    {
        // The affine working selection retains canonical intrinsic geometry
        // resources. A runtime must explicitly support this exact profile; a
        // generic scene/bake name cannot promise geometry decode semantics.
        guarantees.push(crate::normalization::PROFILE);
    }
    let route_request = json!({"contextId":input["contextId"],"semanticKind":capabilities[0],"requiredGuarantees":guarantees,"acceptableLossCodes":[],"preferredBindingId":input["preferredBindingId"],"inventoryRevision":inventory.revision()});
    let selected = inventory.resolve(&route_request).map_err(adapter_error)?;
    if selected["status"] != "selected" {
        return Err(ExchangeError::new(
            "CAPABILITY_UNAVAILABLE",
            "No observed solver action satisfies the pinned request; manual exchange remains available",
        ));
    }
    let binding: BindingId =
        serde_json::from_value(selected["bindingId"].clone()).map_err(|_| {
            ExchangeError::new("CAPABILITY_UNAVAILABLE", "Selected binding ID is invalid")
        })?;
    let action_id: ActionId =
        serde_json::from_value(selected["actionId"].clone()).map_err(|_| {
            ExchangeError::new("CAPABILITY_UNAVAILABLE", "Selected action ID is invalid")
        })?;
    let action = inventory
        .action(&binding, &action_id)
        .map_err(adapter_error)?;
    if action.side != Side::External
        || action.effect != Effect::Write
        || action.verification_requirement != VerificationRequirement::IndependentReadback
        || action.version_evidence != VersionEvidence::RuntimeVerified
        || !action
            .required_permissions
            .iter()
            .any(|p| p == "external.workspace.write")
    {
        return Err(ExchangeError::new(
            "CAPABILITY_UNAVAILABLE",
            "Automated bake requires a runtime-verified external action and independent artifact readback",
        ));
    }
    let arguments = json!({"request":request});
    inventory
        .validate_action_input(&binding, &action_id, &arguments)
        .map_err(adapter_error)?;
    let registered = json!({"contextId":input["contextId"],"bindingId":selected["bindingId"],"actionId":selected["actionId"],"actionDigest":selected["actionDigest"],"arguments":arguments});
    validate("RegisteredActionRequest", &registered)?;
    let translated = json!({"projectId":request["projectId"],"expectedRevision":request["projectRevision"],"contextId":input["contextId"],"intent":{"kind":"external.action","request":registered}});
    validate("CreatePlanRequest", &translated)?;
    Ok(translated)
}

pub fn bake_plan(
    application: &mut Application<'_>,
    principal: &PrincipalId,
    input: &Value,
    source: &InspectedBundle,
    inventory: &InventorySnapshot,
) -> ExchangeResult<Value> {
    let translated = bake_plan_request(input, source, inventory)?;
    application
        .plan_create(principal, &translated)
        .map_err(app_error)
}

pub fn scene_plan_request(
    input: &Value,
    base: &Selection,
    policy: &DeltaPolicy,
) -> ExchangeResult<Value> {
    validate("ScenePlanRequest", input)?;
    validate_scene_patch(&input["patch"], base, policy)?;
    let translated = json!({"projectId":input["patch"]["projectId"],"expectedRevision":input["patch"]["baseRevision"],"contextId":input["contextId"],"intent":{"kind":"scene.import_patch","patch":input["patch"]}});
    validate("CreatePlanRequest", &translated)?;
    Ok(translated)
}
pub fn scene_plan(
    application: &mut Application<'_>,
    principal: &PrincipalId,
    input: &Value,
    base: &Selection,
    policy: &DeltaPolicy,
) -> ExchangeResult<Value> {
    let translated = scene_plan_request(input, base, policy)?;
    application
        .plan_create(principal, &translated)
        .map_err(app_error)
}
fn adapter_error(error: mmmm_adapters::AdapterError) -> ExchangeError {
    ExchangeError::new(error.code, error.message)
}
fn app_error(error: mmmm_application::AppError) -> ExchangeError {
    ExchangeError::new(error.code, error.message)
}

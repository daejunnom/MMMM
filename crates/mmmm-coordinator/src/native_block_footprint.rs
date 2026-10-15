//! The one owned SDK block codec captures direct subjects only. The paired
//! host's bounded preflight is observation, not an all-engine effect proof or
//! a caller-installable profile. Every usable pin still needs current authority.
use super::*;
use crate::catalog_source::{source_facts_pin, validate_source_facts};
use crate::service::RequestContextWitness;
use mmmm_adapters::{OriginKind, ProviderDescriptor, VerificationRequirement};
use mmmm_contracts::{ActionId, ResourceLocation, projected_digest};

const PRODUCER: &str = "mmmm:vanilla_air_stone_direct_block_patch/v1";
const LOSS_CODE: &str = "INDIRECT_ENGINE_EFFECTS_EXCLUDED";
const LIMITATIONS: [&str; 4] = [
    "conservative_3x3x3_fence_only",
    "entity_poi_lighting_neighbor_effects_not_observed",
    "indirect_effect_recovery_not_guaranteed",
    "exact_undo_not_supported",
];
const MAX_PREFLIGHT_BYTES: usize = 128 * 1024;
const RECEIPT_FIELDS: [&str; 23] = [
    "format",
    "status",
    "reasonCode",
    "producerId",
    "hostArtifactDigest",
    "implementationDigest",
    "profileDigest",
    "runtimeSourceFactsDigest",
    "registryGeneration",
    "contextDigest",
    "dimension",
    "position",
    "expectedState",
    "desiredState",
    "observedFromTick",
    "observedToTick",
    "cells",
    "conditionsDigest",
    "directCoverage",
    "indirectEffects",
    "exactUndoSupported",
    "lossCode",
    "limitations",
];

/// This fixed codec belongs to the actual built-in SDK artifact. An arbitrary
/// readiness registration, provider/action ID or matching schema is insufficient.
pub(super) fn known_losses(
    provider: &ProviderDescriptor,
    action: &ActionDescriptor,
    hello: &Value,
    context: &Value,
) -> Option<BTreeSet<String>> {
    let host = hello.get("hostBuild")?.as_str()?;
    let input = &action.input_schema;
    let output = &action.output_schema;
    let required: BTreeSet<&str> = input["required"]
        .as_array()?
        .iter()
        .map(Value::as_str)
        .collect::<Option<_>>()?;
    let properties: BTreeSet<&str> = input["properties"]
        .as_object()?
        .keys()
        .map(String::as_str)
        .collect();
    let fields = BTreeSet::from([
        "dimension",
        "position",
        "expectedState",
        "desiredState",
        "expectedRegistryGeneration",
    ]);
    let environment: mmmm_adapters::EnvironmentRef =
        serde_json::from_value(context["environment"].clone()).ok()?;
    let output_required: BTreeSet<&str> = output["required"]
        .as_array()?
        .iter()
        .map(Value::as_str)
        .collect::<Option<_>>()?;
    let output_fields = BTreeSet::from([
        "kind",
        "setBlockReportedSuccess",
        "before",
        "after",
        "indirectEffects",
        "knownProducerId",
        "preflightPin",
        "directCoverage",
        "exactUndoSupported",
        "lossCode",
        "limitations",
    ]);
    if Sha256Digest::new(host).is_err()
        || provider.registration_mode != RegistrationMode::Provider
        || provider.provider_id.as_str() != "mmmm:native"
        || provider.host_protocol_version != mmmm_contracts::CONTRACT_VERSION
        || provider.origin.kind != OriginKind::Builtin
        || provider.origin.source_id != "mmmm_host"
        || provider
            .origin
            .source_digest
            .as_ref()
            .map(Sha256Digest::as_str)
            != Some(host)
        || action.implementation_digest.as_str() != host
        || provider.environment != environment
        || hello["environment"] != context["environment"]
        || hello["gameVersion"] != "26.3"
        || hello["javaMajor"] != 25
        || hello["loader"]["id"] != "fabric"
        || action.action_id.as_str() != "mmmm:block_patch"
        || action.contract_version != mmmm_contracts::CONTRACT_VERSION
        || action.semantic_kind.as_str() != "mmmm:block_state_patch"
        || action.effect != Effect::Write
        || action.verification_requirement != VerificationRequirement::IndependentReadback
        || action.recovery != mmmm_adapters::Recovery::None
        || action.required_permissions.len() != 1
        || action.required_permissions.first().map(String::as_str) != Some("mmmm:world_write")
        || input["type"] != "object"
        || input["additionalProperties"] != false
        || required != fields
        || properties != fields
        || output["type"] != "object"
        || output["additionalProperties"] != false
        || output_required != output_fields
        || output["properties"]["kind"]["const"] != "direct_block_state"
        || output["properties"]["indirectEffects"]["const"] != "not_observed"
        || output["properties"]["knownProducerId"]["const"] != PRODUCER
        || output["properties"]["directCoverage"]["const"] != "block_state_cells"
        || output["properties"]["exactUndoSupported"]["const"] != false
        || output["properties"]["lossCode"]["const"] != LOSS_CODE
        || output["properties"]["limitations"]["const"] != json!(LIMITATIONS)
    {
        return None;
    }
    Some(BTreeSet::from([LOSS_CODE.into()]))
}

pub(super) struct BlockArguments {
    dimension: ResourceLocation,
    position: [i32; 3],
    expected: Value,
    desired: Value,
    generation: String,
}
impl BlockArguments {
    pub(super) fn decode(value: &Value) -> AppResult<Self> {
        closed(
            value,
            &[
                "dimension",
                "position",
                "expectedState",
                "desiredState",
                "expectedRegistryGeneration",
            ],
        )?;
        let dimension = ResourceLocation::new(text(value, "dimension")?).map_err(|_| invalid())?;
        let position = position(&value["position"])?;
        // The conservative fence must also be representable by the host's
        // int32 neighbor selectors. No wrapped boundary can become a locator.
        for coordinate in position {
            coordinate.checked_sub(1).ok_or_else(invalid)?;
            coordinate.checked_add(1).ok_or_else(invalid)?;
        }
        block_state(&value["expectedState"])?;
        block_state(&value["desiredState"])?;
        let generation = text(value, "expectedRegistryGeneration")?;
        decimal(generation)?;
        Ok(Self {
            dimension,
            position,
            expected: value["expectedState"].clone(),
            desired: value["desiredState"].clone(),
            generation: generation.into(),
        })
    }
    fn selector(&self) -> Value {
        json!({"kind":"owned_block_patch_preflight", "dimension":self.dimension,
            "position":self.position,"expectedState":self.expected,
            "desiredState":self.desired,"expectedRegistryGeneration":self.generation})
    }
    fn targets(&self) -> AppResult<Vec<NativeSelector>> {
        ["block_state", "block_entity"]
            .into_iter()
            .map(|kind| {
                NativeSelector::from_value(
                    &json!({"kind":kind,"dimension":self.dimension,"position":self.position}),
                )
                .map_err(native_error)
            })
            .collect()
    }
}
pub(super) struct SourcePins {
    pub(super) host: Sha256Digest,
    pub(super) source_facts: Sha256Digest,
}
pub(super) struct DirectReceipt {
    conditions: Sha256Digest,
    profile: Sha256Digest,
}

impl HostNativeBackend {
    pub(super) fn owned_block_footprint(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        request: &Value,
        action: &ActionDescriptor,
        context: &Value,
    ) -> AppResult<RegisteredActionFootprint> {
        let (_, budget, access) = self.current(principal, context)?;
        if action.action_id.as_str() != "mmmm:block_patch" {
            return Err(unavailable());
        }
        validate("RegisteredActionRequest", request)?;
        if request["contextId"] != context["contextId"]
            || context["projectId"] != project.project_id().as_str()
        {
            return Err(stale());
        }
        let call = self
            .composition
            .request
            .occupied_witness()
            .map_err(service_error)?;
        let args = BlockArguments::decode(&request["arguments"])?;
        let mut remaining = MAX_BYTES;
        let hello = self.block_hello(principal, context, &call)?;
        let result = self.observed_inventory(Some(store), principal, context);
        let inventory = finish(result, self.block_checkpoint(principal, context, &call))?;
        check_action(&inventory, request, action, &hello, context)?;
        let mut evidence = Vec::new();
        let (facts, pin) = self.block_host_evidence(
            store,
            principal,
            project,
            context,
            &call,
            json!({"kind":"runtime_sources"}),
            &mut remaining,
        )?;
        evidence.push(pin);
        let pins = source_pins(&facts, &hello, &args, context)?;
        let (before, pin) = self.block_host_evidence(
            store,
            principal,
            project,
            context,
            &call,
            args.selector(),
            &mut remaining,
        )?;
        evidence.push(pin);
        let before = decode_receipt(&before, &args, &pins, context)?;

        let reader = NativeTargetReader::new(
            self.composition.hosts.clone(),
            self.composition.authority.clone(),
            self.composition.request.clone(),
        );
        let selectors = args.targets()?;
        call.check_local().map_err(service_error)?;
        let result = store.with_write(|store| {
            reader
                .observe_retained(store, context, &selectors, &args.generation)
                .map_err(native_error)
        });
        let observed = finish(result, self.block_checkpoint(principal, context, &call))?;
        let retained = observed.retained_resource().ok_or_else(unverified)?;
        let native_pin: ResourceRef =
            serde_json::from_value(retained.clone()).map_err(|_| invalid())?;
        remaining = remaining
            .checked_sub(native_pin.size_bytes)
            .ok_or_else(budget_error)?;
        evidence.push(native_pin);
        let targets = direct_targets(observed.targets(), &args)?;

        let (after, pin) = self.block_host_evidence(
            store,
            principal,
            project,
            context,
            &call,
            args.selector(),
            &mut remaining,
        )?;
        evidence.push(pin);
        let after = decode_receipt(&after, &args, &pins, context)?;
        if before.conditions != after.conditions || before.profile != after.profile {
            return Err(stale());
        }
        let (facts, pin) = self.block_host_evidence(
            store,
            principal,
            project,
            context,
            &call,
            json!({"kind":"runtime_sources"}),
            &mut remaining,
        )?;
        evidence.push(pin);
        let final_hello = self.block_hello(principal, context, &call)?;
        let final_pins = source_pins(&facts, &final_hello, &args, context)?;
        if pins.host != final_pins.host
            || pins.source_facts != final_pins.source_facts
            || hello != final_hello
        {
            return Err(stale());
        }
        let result = self.observed_inventory(Some(store), principal, context);
        let final_inventory = finish(result, self.block_checkpoint(principal, context, &call))?;
        check_action(&final_inventory, request, action, &final_hello, context)?;
        access.authorize_project(principal, project.project_id(), Some(context), Access::Plan)?;
        call.check_local().map_err(service_error)?;
        check_budget(&budget)?;
        let resources_written: BTreeSet<_> = targets
            .iter()
            .map(|target| target.subject.clone())
            .collect();
        let mut resources_read = resources_written.clone();
        resources_read.extend(evidence.iter().map(|pin| pin.resource_id.to_string()));
        let min = args.position.map(|n| i64::from(n) - 1);
        let max_exclusive = args.position.map(|n| i64::from(n) + 2);
        let scope = WriteScope {
            project_id: project.project_id().clone(),
            resource_ids: vec![],
            object_ids: vec![],
            regions: vec![RegionScope {
                dimension: args.dimension,
                min,
                max_exclusive,
                context_id: context_id(context)?,
                world_id: WorldId::new(text(&context["environment"], "worldId")?)
                    .map_err(|_| invalid())?,
            }],
            external_target_ids: vec![],
        };
        scope.validate().map_err(storage_error)?;
        Ok(RegisteredActionFootprint {
            scope,
            targets,
            resources_read,
            resources_written,
            losses: vec![direct_limitation()],
            dependency_pins: vec![],
        })
    }

    fn block_checkpoint(
        &self,
        principal: &PrincipalId,
        context: &Value,
        call: &RequestContextWitness,
    ) -> AppResult<()> {
        call.check_local().map_err(service_error)?;
        self.current(principal, context).map(|_| ())
    }
    fn block_hello(
        &self,
        principal: &PrincipalId,
        context: &Value,
        call: &RequestContextWitness,
    ) -> AppResult<Value> {
        call.check_local().map_err(service_error)?;
        let (_, budget, _) = self.current(principal, context)?;
        let result = self.composition.hosts.hello_with_deadline(
            principal,
            &context_id(context)?,
            budget.deadline(),
        );
        finish(result, self.block_checkpoint(principal, context, call))
    }

    /// Preserve a validated received reply in this Store before interpreting
    /// failure or currentness. Private retention grants no usable resource.
    #[allow(
        clippy::too_many_arguments,
        reason = "The same Store, actual request witness and unchanged source/authority inputs remain distinct"
    )]
    fn block_host_evidence(
        &self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        context: &Value,
        original_call: &RequestContextWitness,
        selector: Value,
        remaining: &mut u64,
    ) -> AppResult<(Value, ResourceRef)> {
        original_call.check_local().map_err(service_error)?;
        let (_, budget, access) = self.current(principal, context)?;
        let call = self
            .composition
            .request
            .occupied_witness()
            .map_err(service_error)?;
        let paired = self.composition.hosts.observe_context_witness(
            principal,
            &context_id(context)?,
            budget.deadline(),
        );
        let paired = finish(
            paired,
            self.block_checkpoint(principal, context, original_call),
        )?;
        if paired.context() != context {
            return Err(stale());
        }
        let acquired = self.composition.hosts.inspect_acquired_with_deadline(
            principal,
            &context_id(context)?,
            selector,
            budget.deadline(),
        );
        let acquired = match acquired {
            Ok(acquired) => acquired,
            Err(error) => {
                return finish(
                    Err(error),
                    self.block_checkpoint(principal, context, original_call),
                );
            }
        };
        let origin_matches = acquired.matches_witness(&paired);
        let response = match acquired.into_acquired_response() {
            Ok(response) => response,
            Err(error) => {
                return finish(
                    Err(error),
                    self.block_checkpoint(principal, context, original_call),
                );
            }
        };
        let response_result = if response["status"] == "ok" {
            if origin_matches { Ok(()) } else { Err(stale()) }
        } else {
            Err(AppError::caused_by(
                "NATIVE_OBSERVATION_FAILED",
                "The original owned block inspection failed and remains private evidence",
                HostFailure(response.clone()),
            ))
        };
        let retained = (|| {
            let bytes = encode_json(&response).map_err(|_| invalid())?;
            *remaining = remaining
                .checked_sub(bytes.len() as u64)
                .ok_or_else(budget_error)?;
            if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
                return Err(budget_error());
            }
            let identity = canonical_digest(
                &json!({"project":project.project_id(),"principal":principal,
                "contextDigest":context["contextDigest"],"response":raw_digest(&bytes)}),
            )
            .map_err(|_| invalid())?;
            store.with_write(|store| {
                let blob = store.put_blob(&bytes).map_err(storage_error)?;
                store
                    .pin_artifact(&format!("owned-block-response-{identity}"), &blob)
                    .map_err(storage_error)
            })?;
            Ok(bytes)
        })();
        let checked = (|| {
            original_call.check_local().map_err(service_error)?;
            call.check_local().map_err(service_error)?;
            paired.check_local()?;
            self.current(principal, context)?;
            Ok(())
        })();
        let retained = match (response_result, retained) {
            (Ok(()), retained) => retained,
            (Err(original), retained) => {
                let original: AppResult<Vec<u8>> = Err(original);
                finish(original, retained.map(|_| ()))
            }
        };
        let bytes = finish(retained, checked)?;
        let resource = self.source(store, access).stage_private(
            principal,
            project,
            None,
            &bytes,
            "application/vnd.mmmm.owned-block-evidence+json",
            context,
        )?;
        let payload = response.get("payload").cloned().ok_or_else(invalid)?;
        Ok((payload, resource))
    }
}

fn check_action(
    inventory: &InventorySnapshot,
    request: &Value,
    supplied: &ActionDescriptor,
    hello: &Value,
    context: &Value,
) -> AppResult<()> {
    let binding: BindingId =
        serde_json::from_value(request["bindingId"].clone()).map_err(|_| invalid())?;
    let id: ActionId =
        serde_json::from_value(request["actionId"].clone()).map_err(|_| invalid())?;
    let action = inventory.action(&binding, &id).map_err(adapter_error)?;
    let provider = inventory
        .inventory()
        .providers
        .iter()
        .find(|provider| provider.binding_id == binding)
        .ok_or_else(unavailable)?;
    if action != supplied || known_losses(provider, action, hello, context).is_none() {
        return Err(unavailable());
    }
    let digest = projected_digest(
        "ActionDescriptor",
        &serde_json::to_value(action).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    if request["actionDigest"] != digest.as_str() {
        return Err(stale());
    }
    inventory.check_selected_pin(&json!({"status":"selected","bindingId":binding,"actionId":id,
        "actionDigest":digest,"implementationDigest":action.implementation_digest,"diagnostics":[]})).map_err(adapter_error)?;
    inventory
        .validate_action_input(&binding, &id, &request["arguments"])
        .map_err(adapter_error)
}

fn source_pins(
    facts: &Value,
    hello: &Value,
    args: &BlockArguments,
    context: &Value,
) -> AppResult<SourcePins> {
    validate_source_facts(facts, context)?;
    let host = field_digest(hello, "hostBuild")?;
    if facts["registryGeneration"] != args.generation {
        return Err(stale());
    }
    let mods = facts["mods"].as_array().ok_or_else(invalid)?;
    let own: Vec<_> = mods.iter().filter(|m| m["modId"] == "mmmm_host").collect();
    let roots = own
        .first()
        .and_then(|m| m["runtimeRoots"].as_array())
        .ok_or_else(unavailable)?;
    if own.len() != 1
        || roots.len() != 1
        || roots[0]["status"] != "observed"
        || roots[0]["scope"] != "container_input_bytes"
        || roots[0]["sha256"] != host.as_str()
    {
        return Err(unavailable());
    }
    let archive_id = format!("archive-sha256-{host}");
    let archives = facts["archives"].as_array().ok_or_else(invalid)?;
    let matching: Vec<_> = archives
        .iter()
        .filter(|archive| archive["sourceId"] == archive_id)
        .collect();
    if roots[0]["sourceId"] != archive_id
        || matching.len() != 1
        || matching[0]["sha256"] != host.as_str()
        || matching[0]["sizeBytes"] != roots[0]["sizeBytes"]
    {
        return Err(unavailable());
    }
    Ok(SourcePins {
        host,
        source_facts: source_facts_pin(facts)?,
    })
}

pub(super) fn decode_receipt(
    value: &Value,
    args: &BlockArguments,
    pins: &SourcePins,
    context: &Value,
) -> AppResult<DirectReceipt> {
    closed(value, &RECEIPT_FIELDS)?;
    if encode_json(value).map_err(|_| invalid())?.len() > MAX_PREFLIGHT_BYTES {
        return Err(budget_error());
    }
    if value["format"] != "mmmm.owned-block-footprint/1"
        || value["producerId"] != PRODUCER
        || value["hostArtifactDigest"] != pins.host.as_str()
        || value["implementationDigest"] != pins.host.as_str()
        || value["runtimeSourceFactsDigest"] != pins.source_facts.as_str()
        || value["registryGeneration"] != args.generation
        || value["contextDigest"] != context["contextDigest"]
        || value["dimension"] != args.dimension.as_str()
        || value["position"] != json!(args.position)
        || value["expectedState"] != args.expected
        || value["desiredState"] != args.desired
        || value["directCoverage"] != "block_state_cells"
        || value["indirectEffects"] != "not_observed"
        || value["exactUndoSupported"] != false
        || value["lossCode"] != LOSS_CODE
        || value["limitations"] != json!(LIMITATIONS)
    {
        return Err(stale());
    }
    let from = decimal(text(value, "observedFromTick")?)?;
    let to = decimal(text(value, "observedToTick")?)?;
    if from > to {
        return Err(invalid());
    }
    let cells = value["cells"].as_array().ok_or_else(invalid)?;
    if value["status"] == "unsupported" {
        if !cells.is_empty()
            || !value["conditionsDigest"].is_null()
            || !matches!(
                text(value, "reasonCode")?,
                "OWNED_BLOCK_STATE_UNSUPPORTED"
                    | "OWNED_BLOCK_EXPECTED_STATE_CHANGED"
                    | "OWNED_BLOCK_NEIGHBOR_NOT_AIR"
                    | "OWNED_BLOCK_ENTITY_PRESENT"
                    | "OWNED_BLOCK_FLUID_PRESENT"
            )
        {
            return Err(invalid());
        }
        if !value["profileDigest"].is_null()
            && field_digest(value, "profileDigest")? != direct_profile(&pins.host)?
        {
            return Err(invalid());
        }
        return Err(unavailable());
    }
    if value["status"] != "known"
        || !value["reasonCode"].is_null()
        || cells.len() != 27
        || !matches!(
            text(&args.desired, "blockId")?,
            "minecraft:air" | "minecraft:stone"
        )
        || args.desired["properties"] != json!({})
    {
        return Err(invalid());
    }
    let mut index = 0;
    for y in -1..=1 {
        for z in -1..=1 {
            for x in -1..=1 {
                let cell = &cells[index];
                closed(
                    cell,
                    &[
                        "position",
                        "state",
                        "registryIdentity",
                        "blockEntityAbsent",
                        "fluidEmpty",
                    ],
                )?;
                let expected = [
                    args.position[0] + x,
                    args.position[1] + y,
                    args.position[2] + z,
                ];
                if position(&cell["position"])? != expected
                    || cell["blockEntityAbsent"] != true
                    || cell["fluidEmpty"] != true
                {
                    return Err(invalid());
                }
                block_state(&cell["state"])?;
                let identity = text(cell, "registryIdentity")?;
                let block = text(&cell["state"], "blockId")?;
                if !matches!(
                    (identity, block),
                    ("vanilla_air", "minecraft:air") | ("vanilla_stone", "minecraft:stone")
                ) || cell["state"]["properties"] != json!({})
                    || (index != 13 && identity != "vanilla_air")
                    || (index == 13 && cell["state"] != args.expected)
                {
                    return Err(invalid());
                }
                index += 1;
            }
        }
    }
    let conditions = field_digest(value, "conditionsDigest")?;
    let mut stable = value.clone();
    let object = stable.as_object_mut().ok_or_else(invalid)?;
    for key in ["observedFromTick", "observedToTick", "conditionsDigest"] {
        object.remove(key);
    }
    if canonical_digest(&stable).map_err(|_| invalid())? != conditions {
        return Err(invalid());
    }
    let profile = field_digest(value, "profileDigest")?;
    if profile != direct_profile(&pins.host)? {
        return Err(invalid());
    }
    Ok(DirectReceipt {
        conditions,
        profile,
    })
}

pub(super) fn direct_profile(host: &Sha256Digest) -> AppResult<Sha256Digest> {
    canonical_digest(&json!({"format":"mmmm.owned-block-direct-profile/1","producerId":PRODUCER,
        "hostArtifactDigest":host,"implementationDigest":host,"setBlockFlags":2,
        "centerStates":["minecraft:air","minecraft:stone"],"neighborState":"minecraft:air",
        "requireDefaultState":true,"requireBlockEntityAbsent":true,"requireFluidEmpty":true,
        "directCoverage":"block_state_cells","indirectEffects":"not_observed","exactUndoSupported":false,
        "lossCode":LOSS_CODE,"limitations":LIMITATIONS})).map_err(|_| invalid())
}

fn direct_targets(
    observations: &[NativeObservation],
    args: &BlockArguments,
) -> AppResult<Vec<TargetBeforeImage>> {
    let expected = args.targets()?;
    if observations.len() != expected.len() {
        return Err(unverified());
    }
    let mut targets = Vec::new();
    for (index, (observation, selector)) in observations.iter().zip(expected).enumerate() {
        if observation.selector().value() != selector.value()
            || !observation.full_target()
            || observation.raw()["payload"]["blockState"] != args.expected
            || (index == 1 && observation.presence() != "absent")
        {
            return Err(stale());
        }
        targets.push(native_before_image(observation, &BTreeMap::new())?);
    }
    Ok(targets)
}
pub(super) fn direct_limitation() -> Value {
    json!({"code":LOSS_CODE,"severity":"warning","subjectId":"mmmm:block_patch",
        "feature":"mmmm:indirect_engine_effect_recovery","disposition":"dropped","approvalRequired":true,
        "message":"Only direct block-state subjects are captured and independently compared. The conservative 3x3x3 fence is not complete indirect-effect coverage; entity, POI, lighting and neighbor effects and exact undo are not observed or guaranteed to recover."})
}
fn closed(value: &Value, fields: &[&str]) -> AppResult<()> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(invalid());
    }
    Ok(())
}
fn position(value: &Value) -> AppResult<[i32; 3]> {
    let values = value
        .as_array()
        .filter(|v| v.len() == 3)
        .ok_or_else(invalid)?;
    let mut result = [0; 3];
    for (target, value) in result.iter_mut().zip(values) {
        *target = i32::try_from(value.as_i64().ok_or_else(invalid)?).map_err(|_| invalid())?;
    }
    Ok(result)
}
fn block_state(value: &Value) -> AppResult<()> {
    closed(value, &["blockId", "properties"])?;
    ResourceLocation::new(text(value, "blockId")?).map_err(|_| invalid())?;
    let properties = value["properties"]
        .as_object()
        .filter(|p| p.len() <= 256)
        .ok_or_else(invalid)?;
    if properties.iter().any(|(key, value)| {
        key.is_empty()
            || key.len() > 256
            || value
                .as_str()
                .is_none_or(|value| value.is_empty() || value.len() > 256)
    }) {
        return Err(invalid());
    }
    Ok(())
}
fn decimal(value: &str) -> AppResult<u64> {
    let parsed = value.parse::<u64>().map_err(|_| invalid())?;
    if parsed.to_string() != value {
        return Err(invalid());
    }
    Ok(parsed)
}
fn unavailable() -> AppError {
    error(
        "CAPABILITY_UNAVAILABLE",
        "The actual owned direct block codec cannot support this source, target or bounded preflight",
    )
}

struct HostFailure(Value);
impl std::fmt::Debug for HostFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OwnedBlockHostFailure(private retained response)")
    }
}
impl std::fmt::Display for HostFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = &self.0;
        f.write_str("Original paired host failure response is preserved privately")
    }
}
impl std::error::Error for HostFailure {}
#[derive(Debug)]
struct BoundaryFailure {
    original: AppError,
    checkpoint: AppError,
}
impl std::fmt::Display for BoundaryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Original {} and current {} both failed",
            self.original.code, self.checkpoint.code
        )
    }
}
impl std::error::Error for BoundaryFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
pub(super) fn finish<T>(result: AppResult<T>, checkpoint: AppResult<()>) -> AppResult<T> {
    match (result, checkpoint) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(original), Err(checkpoint)) => Err(AppError::caused_by(
            original.code,
            original.message,
            BoundaryFailure {
                original,
                checkpoint,
            },
        )),
    }
}

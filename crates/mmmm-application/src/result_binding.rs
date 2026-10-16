//! Resolve only server-registered pure data slots. The runtime independently
//! verifies this witness in the original durable intent transaction.
use crate::planning::check_descriptor;
use crate::*;
use mmmm_contracts::{BindingId, OperationId, StepId, canonical_digest, encode_json, parse_json};
use mmmm_runtime::storage::{
    BlobRef,
    result_binding::{
        ResultBindingWitness, ResultCodecImplementation, ResultFootprint, ResultResolutionWitness,
        ResultStepBinding, result_pointer_tokens,
    },
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

impl Application<'_> {
    pub(crate) fn check_result_bindings(
        &mut self,
        plan_steps: &[Value],
        descriptors: &BTreeMap<String, Value>,
        step: &Value,
    ) -> AppResult<()> {
        let bindings: Vec<ResultStepBinding> = decode(&step["resultBindings"])?;
        if bindings.len() > 64 {
            return Err(AppError::new(
                "BUDGET_EXCEEDED",
                "Result binding count exceeds its finite budget",
            ));
        }
        let mut slots = Vec::<Vec<String>>::new();
        for binding in bindings {
            let tokens = result_pointer_tokens(&binding.argument_pointer)
                .map_err(|e| AppError::storage("INVALID_INPUT", e))?;
            if slots
                .iter()
                .any(|old| tokens.starts_with(old) || old.starts_with(&tokens))
            {
                return Err(AppError::new(
                    "INVALID_INPUT",
                    "Frozen result argument slots overlap",
                ));
            }
            existing_value(&step["arguments"], &tokens)?;
            slots.push(tokens);
            result_pointer_tokens(&binding.output_pointer)
                .map_err(|e| AppError::storage("INVALID_INPUT", e))?;
            if !ancestors(plan_steps, step)?.contains(binding.source_step_id.as_str()) {
                return Err(AppError::new(
                    "INVALID_INPUT",
                    "Result binding source is not a frozen DAG ancestor",
                ));
            }
            let source_descriptor = descriptors
                .get(binding.source_step_id.as_str())
                .ok_or_else(|| {
                    AppError::new("INVALID_INPUT", "Frozen result source descriptor is absent")
                })?;
            if canonical_digest(&source_descriptor["outputSchema"]).map_err(AppError::digest)?
                != binding.expected_schema_digest
            {
                return Err(AppError::new(
                    "STALE_PLAN",
                    "Result source output schema differs from its frozen binding",
                ));
            }
            let codec = self
                .provider
                .result_codec(&binding.codec_id, &binding.codec_digest)?;
            if codec
                .metadata_digest()
                .map_err(|e| AppError::storage("INVALID_INPUT", e))?
                != binding.codec_digest
                || !codec.allowed_slots.iter().any(|slot| {
                    slot.action_digest.as_str() == step["actionDigest"].as_str().unwrap_or("")
                        && slot.argument_pointer == binding.argument_pointer
                })
            {
                return Err(AppError::new(
                    "CAPABILITY_UNAVAILABLE",
                    "Closed codec does not authorize the exact frozen data slot",
                ));
            }
            self.store
                .register_result_codec(&codec)
                .map_err(|e| AppError::storage("CAPABILITY_UNAVAILABLE", e))?;
        }
        Ok(())
    }

    pub(crate) fn resolve_step_arguments(
        &mut self,
        principal: &PrincipalId,
        plan: &Value,
        step: &Value,
        operation: &OperationId,
        context: &Value,
    ) -> AppResult<(Value, Vec<ResultBindingWitness>)> {
        let bindings: Vec<ResultStepBinding> = decode(&step["resultBindings"])?;
        if bindings.is_empty() {
            return Ok((step["arguments"].clone(), Vec::new()));
        }
        let record = self
            .store
            .operation(operation)
            .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?;
        self.authority
            .authorize_operation(principal, &record, Access::ObserveOperation)?;
        let metadata = self.evidence_values(&record)?;
        let mut arguments = step["arguments"].clone();
        let mut witnesses = Vec::new();
        let mut bytes = 0u64;
        let steps = plan["steps"]
            .as_array()
            .ok_or_else(|| AppError::new("STALE_PLAN", "Result source steps are absent"))?;
        let ancestors = ancestors(steps, step)?;
        for binding in bindings {
            if !ancestors.contains(binding.source_step_id.as_str()) {
                return Err(AppError::new(
                    "STALE_PLAN",
                    "Result source is absent from the frozen ancestor graph",
                ));
            }
            let source = record
                .steps
                .iter()
                .find(|s| s.step_id == binding.source_step_id)
                .ok_or_else(|| {
                    AppError::new("STALE_PLAN", "Durable result source step is absent")
                })?;
            if !crate::report::step_verified(source)
                || metadata
                    .iter()
                    .any(|v| crate::report::failure_blocks_step(v, binding.source_step_id.as_str()))
            {
                return Err(AppError::new(
                    "RECONCILIATION_INSUFFICIENT",
                    "Incomplete or failed source cannot authorize another dispatch",
                ));
            }
            let invocation = self
                .store
                .stored_invocation(operation, &binding.source_step_id)
                .map_err(|e| AppError::storage("STALE_PLAN", e))?;
            let source_step = steps
                .iter()
                .find(|s| s["stepId"] == binding.source_step_id.as_str())
                .ok_or_else(|| AppError::new("STALE_PLAN", "Frozen source step is absent"))?;
            let source_context_id = decode(&source_step["contextId"])?;
            let source_context = self.live_context(principal, plan, &source_context_id)?;
            self.authority.authorize(
                principal,
                &record.project_id,
                Access::ObserveOperation,
                Some(&source_context),
                Some(plan),
            )?;
            let descriptor = self
                .provider
                .action_descriptor(source_step, &source_context)?;
            check_descriptor(source_step, &source_context, &descriptor)?;
            if canonical_digest(&descriptor["outputSchema"]).map_err(AppError::digest)?
                != binding.expected_schema_digest
            {
                return Err(AppError::new(
                    "STALE_PLAN",
                    "Result source output schema differs from its frozen binding",
                ));
            }
            let source_binding: BindingId = decode(&source_step["bindingId"])?;
            let source_action = self
                .store
                .register_result_action(&source_binding, &descriptor)
                .map_err(|e| AppError::storage("STALE_PLAN", e))?;
            let mut selected_marker = None;
            for marker_blob in self
                .store
                .operation_summaries(operation)
                .map_err(|e| AppError::storage("OPERATION_NOT_FOUND", e))?
            {
                let marker = read_json(self.store, &marker_blob)?;
                if marker["kind"] == "provider_result"
                    && marker["stepId"] == binding.source_step_id.as_str()
                    && marker["invocationId"] == invocation["invocationId"]
                    && marker["outputValidated"] == true
                    && marker["value"]["status"] == "complete"
                    && marker["actionDigest"] == source_step["actionDigest"]
                    && marker["outputSchemaDigest"] == binding.expected_schema_digest.as_str()
                {
                    selected_marker = Some((marker, marker_blob));
                }
            }
            let (marker, source_result_summary) = selected_marker.ok_or_else(|| {
                AppError::new(
                    "RECONCILIATION_INSUFFICIENT",
                    "Original validated source result marker is unavailable",
                )
            })?;
            let source_result: BlobRef = decode(&marker["resultBlob"])?;
            bytes = bytes
                .checked_add(source_result.byte_length)
                .filter(|size| *size <= 32 * 1024 * 1024)
                .ok_or_else(|| {
                    AppError::new(
                        "BUDGET_EXCEEDED",
                        "Result bodies exceed their finite resolution budget",
                    )
                })?;
            let result = read_json(self.store, &source_result)?;
            validate("ProviderResult", &result)?;
            if result["status"] != "complete" {
                return Err(AppError::new(
                    "RECONCILIATION_INSUFFICIENT",
                    "Provider result is incomplete",
                ));
            }
            schema(&descriptor["outputSchema"], &result["data"])?;
            let tokens = result_pointer_tokens(&binding.output_pointer)
                .map_err(|e| AppError::storage("INVALID_INPUT", e))?;
            let value = existing_value(&result["data"], &tokens)?.clone();
            let (codec, codec_blob) = self
                .store
                .result_codec(&binding.codec_id, &binding.codec_digest)
                .map_err(|e| AppError::storage("CAPABILITY_UNAVAILABLE", e))?;
            if !codec.allowed_slots.iter().any(|slot| {
                slot.action_digest.as_str() == step["actionDigest"].as_str().unwrap_or("")
                    && slot.argument_pointer == binding.argument_pointer
            }) {
                return Err(AppError::new(
                    "CAPABILITY_UNAVAILABLE",
                    "Registered codec no longer identifies this pinned slot",
                ));
            }
            schema(&codec.input_schema, &value)?;
            let resolved = match codec.implementation {
                ResultCodecImplementation::JsonIdentityV1 => value.clone(),
            };
            schema(&codec.output_schema, &resolved)?;
            let digest = canonical_digest(&value).map_err(AppError::digest)?;
            let resolved_digest = canonical_digest(&resolved).map_err(AppError::digest)?;
            let argument_tokens = result_pointer_tokens(&binding.argument_pointer)
                .map_err(|e| AppError::storage("INVALID_INPUT", e))?;
            replace_existing(&mut arguments, &argument_tokens, resolved)?;
            witnesses.push(ResultBindingWitness {
                binding,
                source_invocation_id: source.invocation_id.clone().ok_or_else(|| {
                    AppError::new("STALE_PLAN", "Source invocation identity is absent")
                })?,
                source_invocation_digest: source.invocation_digest.clone().ok_or_else(|| {
                    AppError::new("STALE_PLAN", "Source invocation bytes are absent")
                })?,
                source_result,
                source_result_summary,
                source_action,
                codec: codec_blob,
                selected_value_digest: digest.clone(),
                resolved_value_digest: resolved_digest,
            });
        }
        let descriptor = self.provider.action_descriptor(step, context)?;
        schema(&descriptor["inputSchema"], &arguments)?;
        self.provider
            .validate_resolved_footprint(step, &arguments, context)?;
        Ok((arguments, witnesses))
    }

    pub(crate) fn retain_resolution_witness(
        &mut self,
        plan: &Value,
        step: &Value,
        operation: &OperationId,
        invocation: &Value,
        bindings: Vec<ResultBindingWitness>,
    ) -> AppResult<BlobRef> {
        let arguments_blob = self
            .store
            .put_blob(&encode_json(&invocation["arguments"]).map_err(AppError::json)?)
            .map_err(|e| AppError::storage("STALE_PLAN", e))?;
        let witness = ResultResolutionWitness {
            kind: "result_resolution_witness".into(),
            version: 1,
            operation_id: operation.clone(),
            plan_hash: decode(&plan["planHash"])?,
            step_id: decode(&step["stepId"])?,
            template_arguments_digest: canonical_digest(&step["arguments"])
                .map_err(AppError::digest)?,
            arguments_blob,
            arguments_digest: decode(&invocation["argumentsDigest"])?,
            context_digest: decode(&invocation["contextDigest"])?,
            action_digest: decode(&invocation["actionDigest"])?,
            implementation_digest: decode(&invocation["implementationDigest"])?,
            resolved_footprint: ResultFootprint {
                resources_read: decode(&step["resourcesRead"])?,
                resources_written: decode(&step["resourcesWritten"])?,
            },
            bindings,
        };
        let bytes = encode_json(&json!(witness)).map_err(AppError::json)?;
        if bytes.len() > 65_536 {
            return Err(AppError::new(
                "BUDGET_EXCEEDED",
                "Result witness exceeds its finite JSON budget",
            ));
        }
        self.store
            .put_blob(&bytes)
            .map_err(|e| AppError::storage("STALE_PLAN", e))
    }
}

fn read_json(store: &mmmm_runtime::storage::DurableStore, blob: &BlobRef) -> AppResult<Value> {
    parse_json(
        &store
            .read_blob(blob)
            .map_err(|e| AppError::storage("RECONCILIATION_INSUFFICIENT", e))?,
    )
    .map_err(AppError::json)
}
fn schema(schema: &Value, value: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .map_err(AppError::contract)?
        .compile_action_schema(schema)
        .map_err(AppError::contract)?
        .validate(value)
        .map_err(AppError::contract)
}
fn ancestors(steps: &[Value], target: &Value) -> AppResult<BTreeSet<String>> {
    let mut found = BTreeSet::new();
    let mut pending: Vec<StepId> = decode(&target["dependsOn"])?;
    while let Some(id) = pending.pop() {
        if !found.insert(id.as_str().to_owned()) {
            continue;
        }
        if found.len() > 4096 {
            return Err(AppError::new(
                "BUDGET_EXCEEDED",
                "Result ancestor graph exceeds its finite budget",
            ));
        }
        let step = steps
            .iter()
            .find(|s| s["stepId"] == id.as_str())
            .ok_or_else(|| AppError::new("STALE_PLAN", "Result ancestor is absent"))?;
        pending.extend(decode::<Vec<StepId>>(&step["dependsOn"])?);
    }
    Ok(found)
}
fn index(token: &str) -> AppResult<usize> {
    if token.is_empty()
        || (token.len() > 1 && token.starts_with('0'))
        || !token.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(AppError::new(
            "INVALID_INPUT",
            "Result array index is not canonical",
        ));
    }
    token
        .parse()
        .map_err(|_| AppError::new("INVALID_INPUT", "Result array index exceeds its range"))
}
fn existing_value<'a>(root: &'a Value, tokens: &[String]) -> AppResult<&'a Value> {
    let mut node = root;
    for token in tokens {
        node = match node {
            Value::Object(map) => map.get(token),
            Value::Array(values) => values.get(index(token)?),
            _ => None,
        }
        .ok_or_else(|| {
            AppError::new(
                "INVALID_INPUT",
                "Result pointer does not select an existing value",
            )
        })?;
    }
    Ok(node)
}
fn replace_existing(root: &mut Value, tokens: &[String], value: Value) -> AppResult<()> {
    let (last, parents) = tokens
        .split_last()
        .ok_or_else(|| AppError::new("INVALID_INPUT", "Result root replacement is forbidden"))?;
    let mut node = root;
    for token in parents {
        node = match node {
            Value::Object(map) => map.get_mut(token),
            Value::Array(values) => values.get_mut(index(token)?),
            _ => None,
        }
        .ok_or_else(|| AppError::new("INVALID_INPUT", "Result argument parent is absent"))?;
    }
    let slot = match node {
        Value::Object(map) => map.get_mut(last),
        Value::Array(values) => values.get_mut(index(last)?),
        _ => None,
    }
    .ok_or_else(|| AppError::new("INVALID_INPUT", "Result argument slot is absent"))?;
    *slot = value;
    Ok(())
}

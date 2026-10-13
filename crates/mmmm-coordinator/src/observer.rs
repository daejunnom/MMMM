//! Native target reads are separate from dispatch and provider result data.
//! Before images come from actual loaded-world observations; after images use
//! fresh read authority and the original job identity, including on reconcile.

use crate::host::HostBridge;
use mmmm_application::{
    AppError, AppResult, BeforeCapture, BeforeImage, DirectChange, IndependentObserverPort,
    ReadbackEvidence,
};
use mmmm_contracts::{
    BindingId, ContextId, ContractValidator, InvocationId, PrincipalId, ResourceLocation,
    Sha256Digest, canonical_bytes, canonical_digest,
};
use mmmm_runtime::storage::{EffectEvidence, WriteScope};
use serde_json::{Value, json};

pub struct NativeObserver {
    bridge: HostBridge,
}
impl NativeObserver {
    pub fn new(bridge: HostBridge) -> Self {
        Self { bridge }
    }
    fn observe(&self, invocation: &Value, target: &BlockTarget) -> AppResult<(Vec<u8>, Value)> {
        validate("Invocation", invocation)?;
        let principal = PrincipalId::new(text(&invocation["context"], "principalRef")?)
            .map_err(|_| failure("STALE_CONTEXT", "Stored principal identity is invalid"))?;
        let context = ContextId::new(text(&invocation["context"], "contextId")?)
            .map_err(|_| failure("STALE_CONTEXT", "Stored context identity is invalid"))?;
        let live = self.bridge.context(&principal, &context)?;
        if live["environment"] != invocation["context"]["environment"] {
            return Err(failure(
                "STALE_CONTEXT",
                "Independent read belongs to another native epoch",
            ));
        }
        let observed = self.bridge.inspect(
            &principal,
            &context,
            json!({"kind":"block_read","dimension":target.dimension,"position":target.position}),
        )?;
        let projection = validate_block_observation(target, &observed)?;
        Ok((
            canonical_bytes(&projection).map_err(|_| {
                failure(
                    "OBSERVATION_INVALID",
                    "Observed native bytes cannot be encoded",
                )
            })?,
            observed,
        ))
    }
}
impl IndependentObserverPort for NativeObserver {
    fn validate_capture_target(
        &mut self,
        invocation: &Value,
        scope: &WriteScope,
        target: &str,
    ) -> AppResult<()> {
        let target = BlockTarget::parse(target)?;
        validate_region(invocation, scope, &target)
    }
    fn capture_before(
        &mut self,
        invocation: &Value,
        scope: &WriteScope,
    ) -> AppResult<Option<BeforeCapture>> {
        if invocation["actionId"] != "mmmm:block_patch" {
            return Ok(None);
        }
        let target = BlockTarget::from_arguments(&invocation["arguments"])?;
        validate_region(invocation, scope, &target)?;
        let (bytes, _) = self.observe(invocation, &target)?;
        Ok(Some(BeforeCapture {
            invocation_id: id::<InvocationId>(invocation, "invocationId")?,
            binding_id: id::<BindingId>(invocation, "bindingId")?,
            context_digest: digest(invocation, "contextDigest")?,
            implementation_digest: digest(invocation, "implementationDigest")?,
            arguments_digest: digest(invocation, "argumentsDigest")?,
            images: vec![BeforeImage {
                target: target.subject(),
                bytes,
            }],
        }))
    }
    fn readback(&mut self, invocation: &Value, scope: &WriteScope) -> AppResult<ReadbackEvidence> {
        if invocation["actionId"] != "mmmm:block_patch" {
            return Err(failure(
                "CAPABILITY_UNAVAILABLE",
                "No native readback codec is installed for this action",
            ));
        }
        let target = BlockTarget::from_arguments(&invocation["arguments"])?;
        validate_region(invocation, scope, &target)?;
        let job = self.bridge.job_observation(invocation)?;
        if job["invocationId"] != invocation["invocationId"]
            || !job["providerCompleted"].is_boolean()
        {
            return Err(failure(
                "OBSERVATION_INVALID",
                "Original native completion identity is absent",
            ));
        }
        let (after, observed) = self.observe(invocation, &target)?;
        let desired = json!({"dimension":target.dimension,"position":target.position,"blockState":invocation["arguments"]["desiredState"]});
        let desired = canonical_bytes(&desired)
            .map_err(|_| failure("INVALID_INPUT", "Desired native state cannot be encoded"))?;
        let settled = job["providerCompleted"] == true;
        let effect = if settled && after == desired {
            EffectEvidence::CompleteConfirmed
        } else {
            EffectEvidence::Unknown
        };
        Ok(ReadbackEvidence {
            invocation_id: id::<InvocationId>(invocation, "invocationId")?,
            binding_id: id::<BindingId>(invocation, "bindingId")?,
            context_digest: digest(invocation, "contextDigest")?,
            implementation_digest: digest(invocation, "implementationDigest")?,
            arguments_digest: digest(invocation, "argumentsDigest")?,
            effect,
            settled,
            evidence: json!({"kind":"native_block_independent_readback","invocationId":invocation["invocationId"],"jobObservation":job,"targetObservation":observed}),
            direct_changes: vec![DirectChange {
                target: target.subject(),
                before: Vec::new(),
                after,
            }],
        })
    }
    fn read_target(&mut self, invocation: &Value, target: &str) -> AppResult<Vec<u8>> {
        let target = BlockTarget::parse(target)?;
        let original = BlockTarget::from_arguments(&invocation["arguments"])?;
        if target != original {
            return Err(failure(
                "PERMISSION_REQUIRED",
                "Recovery target differs from the original native footprint",
            ));
        }
        let scope: WriteScope = serde_json::from_value(invocation["context"]["scope"].clone())
            .map_err(|_| failure("STALE_CONTEXT", "Original invocation scope is invalid"))?;
        validate_region(invocation, &scope, &target)?;
        self.observe(invocation, &target).map(|(bytes, _)| bytes)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct BlockTarget {
    pub dimension: ResourceLocation,
    pub position: [i32; 3],
}
impl BlockTarget {
    pub(crate) fn from_arguments(arguments: &Value) -> AppResult<Self> {
        let dimension = ResourceLocation::new(text(arguments, "dimension")?)
            .map_err(|_| failure("INVALID_INPUT", "Native block dimension is invalid"))?;
        let coordinates = arguments["position"]
            .as_array()
            .filter(|coordinates| coordinates.len() == 3)
            .ok_or_else(|| failure("INVALID_INPUT", "Native block position is invalid"))?;
        let mut position = [0; 3];
        for (index, coordinate) in coordinates.iter().enumerate() {
            position[index] = coordinate
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .ok_or_else(|| {
                    failure("INVALID_INPUT", "Native block position is outside int32")
                })?;
        }
        Ok(Self {
            dimension,
            position,
        })
    }
    pub(crate) fn parse(subject: &str) -> AppResult<Self> {
        let value = subject.strip_prefix("block:").ok_or_else(|| {
            failure(
                "CAPABILITY_UNAVAILABLE",
                "Target is not a native block locator",
            )
        })?;
        let mut parts = value.rsplitn(4, ':');
        let mut position = [0; 3];
        for index in (0..3).rev() {
            let part = parts
                .next()
                .ok_or_else(|| failure("INVALID_INPUT", "Native target locator is incomplete"))?;
            position[index] = part
                .parse::<i32>()
                .map_err(|_| failure("INVALID_INPUT", "Native target coordinate is invalid"))?;
            if position[index].to_string() != part {
                return Err(failure(
                    "INVALID_INPUT",
                    "Native target coordinate is not canonical",
                ));
            }
        }
        let dimension = ResourceLocation::new(
            parts
                .next()
                .ok_or_else(|| failure("INVALID_INPUT", "Native target dimension is absent"))?,
        )
        .map_err(|_| failure("INVALID_INPUT", "Native target dimension is invalid"))?;
        let target = Self {
            dimension,
            position,
        };
        if target.subject() != subject {
            return Err(failure(
                "INVALID_INPUT",
                "Native target locator is not canonical",
            ));
        }
        Ok(target)
    }
    pub(crate) fn subject(&self) -> String {
        format!(
            "block:{}:{}:{}:{}",
            self.dimension.as_str(),
            self.position[0],
            self.position[1],
            self.position[2]
        )
    }
}
pub(crate) fn validate_region(
    invocation: &Value,
    scope: &WriteScope,
    target: &BlockTarget,
) -> AppResult<()> {
    scope
        .validate()
        .map_err(|_| failure("PERMISSION_REQUIRED", "Native scope is invalid"))?;
    if scope.project_id.as_str() != text(&invocation["context"], "projectId")?
        || !scope.regions.iter().any(|region| {
            region.context_id.as_str() == invocation["context"]["contextId"].as_str().unwrap_or("")
                && region.world_id.as_str()
                    == invocation["context"]["environment"]["worldId"]
                        .as_str()
                        .unwrap_or("")
                && region.dimension == target.dimension
                && (0..3).all(|axis| {
                    region.min[axis] <= i64::from(target.position[axis])
                        && i64::from(target.position[axis]) < region.max_exclusive[axis]
                })
        })
    {
        return Err(failure(
            "PERMISSION_REQUIRED",
            "Native target is outside the approved world region",
        ));
    }
    Ok(())
}
fn validate_block_observation(target: &BlockTarget, observed: &Value) -> AppResult<Value> {
    let object = observed
        .as_object()
        .ok_or_else(|| failure("OBSERVATION_INVALID", "Native block observation is absent"))?;
    if object.len() != 5
        || ![
            "dimension",
            "position",
            "blockState",
            "observedTick",
            "snapshotDigest",
        ]
        .iter()
        .all(|key| object.contains_key(*key))
        || observed["dimension"] != target.dimension.as_str()
        || observed["position"] != json!(target.position)
    {
        return Err(failure(
            "OBSERVATION_INVALID",
            "Native observation target differs from the requested target",
        ));
    }
    mmmm_contracts::UnsignedDecimal::new(text(observed, "observedTick")?)
        .map_err(|_| failure("OBSERVATION_INVALID", "Native observation tick is invalid"))?;
    let block = &observed["blockState"];
    let block_object = block
        .as_object()
        .ok_or_else(|| failure("OBSERVATION_INVALID", "Native block state is invalid"))?;
    let properties = block["properties"]
        .as_object()
        .ok_or_else(|| failure("OBSERVATION_INVALID", "Native block properties are absent"))?;
    if block_object.len() != 2
        || properties.len() > 256
        || properties.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > 128
                || value.as_str().is_none_or(|value| value.len() > 128)
        })
    {
        return Err(failure(
            "OBSERVATION_INVALID",
            "Native block state exceeds its codec limits",
        ));
    }
    ResourceLocation::new(text(block, "blockId")?)
        .map_err(|_| failure("OBSERVATION_INVALID", "Native block ID is invalid"))?;
    let projection =
        json!({"dimension":target.dimension,"position":target.position,"blockState":block});
    if canonical_digest(&projection)
        .map_err(|_| {
            failure(
                "OBSERVATION_INVALID",
                "Native observation digest is unavailable",
            )
        })?
        .as_str()
        != text(observed, "snapshotDigest")?
    {
        return Err(failure(
            "OBSERVATION_INVALID",
            "Native observation digest differs from actual raw bytes",
        ));
    }
    Ok(projection)
}
fn id<T: serde::de::DeserializeOwned>(value: &Value, key: &str) -> AppResult<T> {
    serde_json::from_value(value[key].clone())
        .map_err(|_| failure("INVALID_INPUT", "Original invocation identity is invalid"))
}
fn digest(value: &Value, key: &str) -> AppResult<Sha256Digest> {
    Sha256Digest::new(text(value, key)?)
        .map_err(|_| failure("INVALID_INPUT", "Original invocation digest is invalid"))
}
fn text<'a>(value: &'a Value, key: &str) -> AppResult<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| failure("INVALID_INPUT", "Required native field is absent"))
}
fn validate(name: &str, value: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .and_then(|validator| validator.validate(name, value))
        .map_err(|_| failure("INVALID_INPUT", "Original native contract is invalid"))
}
fn failure(code: &'static str, message: &'static str) -> AppError {
    AppError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_block_locator_keeps_dimension_and_signed_coordinates() {
        let target = BlockTarget::parse("block:minecraft:overworld:-1:64:2147483647").unwrap();
        assert_eq!(target.position, [-1, 64, i32::MAX]);
        for value in [
            "block:minecraft:overworld:01:64:0",
            "block:minecraft:overworld:+1:64:0",
            "block:minecraft:overworld:2147483648:64:0",
            "block:minecraft:overworld:0:64",
        ] {
            assert!(BlockTarget::parse(value).is_err());
        }
    }
    #[test]
    fn observation_hash_is_actual_projection_and_tick_is_metadata() {
        let target = BlockTarget::parse("block:minecraft:overworld:0:64:0").unwrap();
        let projection = json!({"dimension":target.dimension,"position":target.position,"blockState":{"blockId":"minecraft:stone","properties":{}}});
        let mut observation = projection.clone();
        observation["observedTick"] = json!("10");
        observation["snapshotDigest"] = json!(canonical_digest(&projection).unwrap());
        assert_eq!(
            validate_block_observation(&target, &observation).unwrap(),
            projection
        );
        observation["observedTick"] = json!("11");
        assert!(validate_block_observation(&target, &observation).is_ok());
        observation["blockState"]["blockId"] = json!("minecraft:dirt");
        assert!(validate_block_observation(&target, &observation).is_err());
    }
}

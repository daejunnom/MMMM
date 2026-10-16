//! Closed DTO validation for the actual Java native target serializer.
//!
//! This module cannot grant authority or establish observation completeness.
//! Native NBT stays opaque: its admitted serializer format, finite bytes and raw
//! digest are checked, but no interpreted UUID, block state or score is invented.
//! The caller must retain the original wire bytes and verify the paired host,
//! exact context, current ACL and admitted serializer/profile evidence first.
use mmmm_contracts::{
    BindingId, InvocationId, OperationId, ResourceId, ResourceLocation, Sha256Digest, raw_digest,
};
use serde_json::{Map, Value};
use std::{cmp::Ordering, collections::BTreeSet};

const MAX_RAW_BYTES: usize = 256 * 1024;
const MAX_SELECTOR_BYTES: usize = 16 * 1024;
const MAX_NATIVE_BYTES: usize = 64 * 1024;
const MAX_NODES: usize = 16_384;
const MAX_DEPTH: usize = 64;
const MAX_TAGS: usize = 128;
const MAX_TAG_BYTES: usize = 16 * 1024;
const MAX_SCORE_HOLDERS: usize = 4096;
const MAX_DISPLAY_SLOTS: usize = 32;
const NAMED_NBT: &str = "minecraft.nbt.named-compound/uncompressed";
const ANY_NBT: &str = "minecraft.nbt.any-tag/uncompressed";

/// Only the caller's durable original invocation and retained before capture
/// may construct these pins. An inspector request is not an original route.
pub(crate) struct OriginalTargetPins {
    pub(crate) invocation_id: InvocationId,
    pub(crate) binding_id: BindingId,
    pub(crate) operation_id: OperationId,
    pub(crate) selector: Value,
    pub(crate) before_sha256: Sha256Digest,
    pub(crate) owner_tag: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativePayloadError;
impl std::fmt::Display for NativePayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Native target payload differs from the admitted DTO or original target pins")
    }
}
impl std::error::Error for NativePayloadError {}
type Result<T> = std::result::Result<T, NativePayloadError>;

/// Validate the exact payload and its advertised local capture scope. Success
/// means a bounded matching DTO; it does not prove native authority, complete
/// enumeration, command delivery, causality, persistence or rollback.
pub(crate) fn validate_payload(
    raw: &Value,
    selector: &Value,
    original: Option<&OriginalTargetPins>,
) -> Result<()> {
    bounded_json(raw, MAX_RAW_BYTES)?;
    bounded_json(selector, MAX_SELECTOR_BYTES)?;
    let kind = validate_selector(selector)?;
    fields(
        raw,
        &[
            "format",
            "selector",
            "status",
            "presence",
            "membershipScope",
            "captureScope",
            "coverage",
            "reason",
            "payload",
        ],
    )?;
    require(raw["format"] == "mmmm.native.target/1" && raw["selector"] == *selector)?;
    let status = text(raw, "status")?;
    if status == "unknown" || status == "unsupported" {
        return validate_unknown(raw, kind);
    }
    require(status == "known")?;
    let payload = &raw["payload"];
    let presence = text(raw, "presence")?;
    match kind {
        "block_state" => {
            require(presence == "present")?;
            fields(payload, &["blockState", "hasBlockEntity"])?;
            block_state(&payload["blockState"])?;
            if boolean(payload, "hasBlockEntity")? {
                scope(
                    raw,
                    "loaded_block_position",
                    "native_block_state",
                    "tracked_changes_only",
                )?;
                require(
                    raw["reason"] == "native_block_entity_payload_requires_separate_full_capture",
                )
            } else {
                full(raw, "loaded_block_position", "native_block_state")
            }
        }
        "block_entity" => {
            full(
                raw,
                "loaded_block_position",
                "native_persisted_block_entity",
            )?;
            match presence {
                "absent" => {
                    fields(payload, &["blockState"])?;
                    block_state(&payload["blockState"])
                }
                "present" => {
                    fields(payload, &["blockState", "blockEntityType", "nativeNbt"])?;
                    block_state(&payload["blockState"])?;
                    location(text(payload, "blockEntityType")?)?;
                    nbt(&payload["nativeNbt"], NAMED_NBT)
                }
                _ => Err(NativePayloadError),
            }
        }
        "entity" => match presence {
            "present" => entity_present(raw, selector),
            "absent" => entity_tombstone(raw, selector, original),
            _ => Err(NativePayloadError),
        },
        "score" => {
            full(raw, "current_native_scoreboard", "native_score_entry")?;
            match presence {
                "absent" => {
                    fields(payload, &["objectivePresent"])?;
                    boolean(payload, "objectivePresent")?;
                    Ok(())
                }
                "present" => {
                    fields(
                        payload,
                        &[
                            "objectivePresent",
                            "value",
                            "locked",
                            "numberFormatPresent",
                            "nativeScoreNbt",
                        ],
                    )?;
                    require(boolean(payload, "objectivePresent")?)?;
                    integer32(&payload["value"])?;
                    boolean(payload, "locked")?;
                    boolean(payload, "numberFormatPresent")?;
                    nbt(&payload["nativeScoreNbt"], NAMED_NBT)
                }
                _ => Err(NativePayloadError),
            }
        }
        "objective" => {
            full(
                raw,
                "current_native_scoreboard",
                "native_objective_and_all_scores",
            )?;
            match presence {
                "absent" => {
                    fields(payload, &[])?;
                    Ok(())
                }
                "present" => objective_present(payload),
                _ => Err(NativePayloadError),
            }
        }
        "storage" => {
            full(raw, "current_cached_command_storage", "native_storage_key")?;
            match presence {
                "absent" => {
                    fields(payload, &["storagePresent", "statesPresent"])?;
                    require(boolean(payload, "storagePresent")?)?;
                    boolean(payload, "statesPresent")?;
                    Ok(())
                }
                "present" => {
                    fields(
                        payload,
                        &["storagePresent", "statesPresent", "nativeValueNbt"],
                    )?;
                    require(
                        boolean(payload, "storagePresent")? && boolean(payload, "statesPresent")?,
                    )?;
                    nbt(&payload["nativeValueNbt"], ANY_NBT)
                }
                _ => Err(NativePayloadError),
            }
        }
        _ => Err(NativePayloadError),
    }
}

fn validate_unknown(raw: &Value, kind: &str) -> Result<()> {
    require(raw["presence"] == "unknown")?;
    let reason = text(raw, "reason")?;
    require(!reason.is_empty() && reason.encode_utf16().count() <= 256)?;
    if kind == "storage"
        && raw["status"] == "unknown"
        && reason == "native_storage_parent_is_not_a_compound"
    {
        scope(
            raw,
            "current_cached_command_storage",
            "native_storage_parent",
            "tracked_changes_only",
        )?;
        let payload = &raw["payload"];
        fields(payload, &["storagePresent", "nativeStatesNbt"])?;
        require(boolean(payload, "storagePresent")?)?;
        return nbt(&payload["nativeStatesNbt"], ANY_NBT);
    }
    // Future unknown reasons remain observable without acquiring full coverage.
    // No arbitrary structured payload is reinterpreted as a known native type.
    require(
        raw["membershipScope"] == "unknown"
            && raw["coverage"] == "best_effort"
            && raw["payload"].is_null(),
    )?;
    let expected = match kind {
        "block_state" => "native_block_state",
        "block_entity" => "native_persisted_block_entity",
        "entity" => "native_persisted_entity",
        "score" => "native_score_entry",
        "objective" => "native_objective_and_all_scores",
        "storage" => "native_storage_key",
        _ => return Err(NativePayloadError),
    };
    require(
        raw["captureScope"] == expected
            || (raw["status"] == "unsupported" && raw["captureScope"] == "unknown"),
    )
}

fn entity_present(raw: &Value, selector: &Value) -> Result<()> {
    full(raw, "loaded_entity_identity", "native_persisted_entity")?;
    let payload = &raw["payload"];
    fields(payload, &["entityType", "position", "tags", "nativeNbt"])?;
    location(text(payload, "entityType")?)?;
    require(payload["entityType"] == selector["expectedType"])?;
    let position = array(&payload["position"], 3)?;
    require(position.len() == 3)?;
    for coordinate in position {
        let coordinate = coordinate.as_f64().ok_or(NativePayloadError)?;
        require(
            coordinate.is_finite()
                && coordinate >= f64::from(i32::MIN)
                && coordinate < f64::from(i32::MAX) + 1.0,
        )?;
    }
    ordered_strings(
        array(&payload["tags"], MAX_TAGS)?,
        MAX_TAG_BYTES / 3,
        MAX_TAG_BYTES,
    )?;
    nbt(&payload["nativeNbt"], NAMED_NBT)
}

fn entity_tombstone(
    raw: &Value,
    selector: &Value,
    original: Option<&OriginalTargetPins>,
) -> Result<()> {
    full(
        raw,
        "retained_destroyed_native_identity",
        "observed_entity_instance",
    )?;
    let original = original.ok_or(NativePayloadError)?;
    require(original.selector == *selector)?;
    let payload = &raw["payload"];
    fields(
        payload,
        &[
            "sourceInvocationId",
            "sourceBindingId",
            "sourceOperationId",
            "beforeSha256",
            "entityUuid",
            "entityType",
            "ownerTag",
            "removalReason",
            "membershipClaim",
        ],
    )?;
    require(
        text(payload, "sourceInvocationId")? == original.invocation_id.as_str()
            && text(payload, "sourceBindingId")? == original.binding_id.as_str()
            && text(payload, "sourceOperationId")? == original.operation_id.as_str()
            && text(payload, "beforeSha256")? == original.before_sha256.as_str()
            && payload["entityUuid"] == selector["uuid"]
            && payload["entityType"] == selector["expectedType"]
            && text(payload, "ownerTag")? == original.owner_tag.as_str()
            && payload["membershipClaim"] == "original_observed_instance_destroyed",
    )?;
    require(!original.owner_tag.is_empty() && original.owner_tag.encode_utf16().count() <= 128)?;
    // Only destructive, non-saving reasons are admitted. Loaded membership loss,
    // chunk unload, dimension change and player removal cannot become absence.
    // The native retained-instance witness must still verify the enum flags.
    require(matches!(
        text(payload, "removalReason")?,
        "KILLED" | "DISCARDED"
    ))
}

fn objective_present(payload: &Value) -> Result<()> {
    objective_present_using(payload, &|value| nbt(value, NAMED_NBT))
}
fn objective_present_using(payload: &Value, native: &dyn Fn(&Value) -> Result<()>) -> Result<()> {
    fields(payload, &["nativeObjectiveNbt", "scores", "displaySlots"])?;
    native(&payload["nativeObjectiveNbt"])?;
    let mut previous: Option<&str> = None;
    let mut holder_bytes = 0usize;
    for entry in array(&payload["scores"], MAX_SCORE_HOLDERS)? {
        fields(entry, &["holder", "value", "locked", "nativeScoreNbt"])?;
        let holder = text(entry, "holder")?;
        require(holder.encode_utf16().count() <= MAX_TAG_BYTES / 3)?;
        holder_bytes = holder_bytes
            .checked_add(holder.len())
            .filter(|n| *n <= MAX_RAW_BYTES / 2)
            .ok_or(NativePayloadError)?;
        if let Some(previous) = previous {
            require(java_string_cmp(previous, holder) == Ordering::Less)?;
        }
        previous = Some(holder);
        integer32(&entry["value"])?;
        boolean(entry, "locked")?;
        native(&entry["nativeScoreNbt"])?;
    }
    // Exhaustiveness comes from the admitted Java enum traversal, not an
    // invented Rust list. Reject ambiguous entries before preserving that list.
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for slot in array(&payload["displaySlots"], MAX_DISPLAY_SLOTS)? {
        fields(slot, &["id", "name"])?;
        let id = integer32(&slot["id"])?;
        let name = text(slot, "name")?;
        require(
            id >= 0
                && !name.is_empty()
                && name.encode_utf16().count() <= 128
                && ids.insert(id)
                && names.insert(name),
        )?;
    }
    Ok(())
}

/// Calibration factual images share the exact full-objective serializer and
/// bounds. This port accepts only the extra raw-bit sidecar in its own codec;
/// ordinary NativeTargets payload grammar and authority stay unchanged.
pub(crate) fn validate_calibration_image(raw: &Value, selector: &Value) -> Result<()> {
    bounded_json(raw, MAX_RAW_BYTES)?;
    fields(
        raw,
        &[
            "format",
            "selector",
            "status",
            "presence",
            "membershipScope",
            "captureScope",
            "coverage",
            "reason",
            "payload",
        ],
    )?;
    require(raw["format"] == "mmmm.native.calibration-target/1" && raw["selector"] == *selector)?;
    match text(selector, "kind")? {
        "objective" => {
            fields(selector, &["targetId", "kind", "objective"])?;
            atom(text(selector, "objective")?, true)?;
            if raw["status"] == "unknown" || raw["status"] == "unsupported" {
                return validate_unknown(raw, "objective");
            }
            require(raw["status"] == "known")?;
            full(
                raw,
                "current_native_scoreboard",
                "native_objective_and_all_scores",
            )?;
            match text(raw, "presence")? {
                "absent" => fields(&raw["payload"], &[]).map(|_| ()),
                "present" => objective_present_using(&raw["payload"], &|value| {
                    calibration_nbt(value, NAMED_NBT)
                }),
                _ => Err(NativePayloadError),
            }
        }
        "owned_storage" => {
            fields(selector, &["targetId", "kind", "storage", "ownedSubtrees"])?;
            location(text(selector, "storage")?)?;
            require(selector["ownedSubtrees"] == serde_json::json!(["inputs", "invocation"]))?;
            if raw["status"] == "unknown" || raw["status"] == "unsupported" {
                require(
                    raw["presence"] == "unknown"
                        && raw["membershipScope"] == "unknown"
                        && raw["coverage"] == "best_effort"
                        && raw["payload"].is_null(),
                )?;
                require(text(raw, "reason")?.len() <= 256 && !text(raw, "reason")?.is_empty())?;
                return Ok(());
            }
            require(raw["status"] == "known")?;
            full(
                raw,
                "current_cached_command_storage",
                "native_owned_storage_subtrees",
            )?;
            let payload = &raw["payload"];
            fields(payload, &["storagePresent", "inputs", "invocation"])?;
            let storage_present = boolean(payload, "storagePresent")?;
            for key in ["inputs", "invocation"] {
                let subtree = &payload[key];
                fields(subtree, &["presence", "nativeValueNbt"])?;
                match text(subtree, "presence")? {
                    "absent" => require(subtree["nativeValueNbt"].is_null())?,
                    "present" => calibration_nbt(&subtree["nativeValueNbt"], ANY_NBT)?,
                    _ => return Err(NativePayloadError),
                }
            }
            let subtrees_absent = payload["inputs"]["presence"] == "absent"
                && payload["invocation"]["presence"] == "absent";
            require(storage_present || subtrees_absent)?;
            require(raw["presence"] == if subtrees_absent { "absent" } else { "present" })?;
            Ok(())
        }
        _ => Err(NativePayloadError),
    }
}
fn calibration_nbt(value: &Value, format: &str) -> Result<()> {
    fields(value, &["format", "bytesHex", "sha256", "rawFloatingBits"])?;
    let mut core = value.clone();
    core.as_object_mut()
        .ok_or(NativePayloadError)?
        .remove("rawFloatingBits");
    nbt(&core, format)?;
    bounded_json(&value["rawFloatingBits"], MAX_NATIVE_BYTES)?;
    // The factual consumer additionally decodes exact NBT paths/types and
    // verifies complete Float/Double coverage against this bounded sidecar.
    array(&value["rawFloatingBits"], MAX_NODES).map(|_| ())
}

fn block_state(value: &Value) -> Result<()> {
    fields(value, &["blockId", "properties"])?;
    location(text(value, "blockId")?)?;
    let properties = value["properties"].as_object().ok_or(NativePayloadError)?;
    require(properties.len() <= 4096)?;
    for (key, value) in properties {
        require(!key.is_empty() && key.len() <= MAX_NATIVE_BYTES)?;
        let value = value.as_str().ok_or(NativePayloadError)?;
        require(!value.is_empty() && value.len() <= MAX_NATIVE_BYTES)?;
    }
    Ok(())
}

fn nbt(value: &Value, expected_format: &str) -> Result<()> {
    fields(value, &["format", "bytesHex", "sha256"])?;
    require(text(value, "format")? == expected_format)?;
    let hex = text(value, "bytesHex")?;
    require(!hex.is_empty() && hex.len() <= MAX_NATIVE_BYTES * 2 && hex.len() % 2 == 0)?;
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        bytes.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
    }
    let digest = Sha256Digest::new(text(value, "sha256")?).map_err(|_| NativePayloadError)?;
    require(raw_digest(&bytes) == digest)
}
fn hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(NativePayloadError),
    }
}

fn validate_selector(value: &Value) -> Result<&str> {
    let kind = text(value, "kind")?;
    match kind {
        "block_state" | "block_entity" => {
            fields(value, &["kind", "dimension", "position"])?;
            location(text(value, "dimension")?)?;
            let position = array(&value["position"], 3)?;
            require(position.len() == 3)?;
            for coordinate in position {
                integer32(coordinate)?;
            }
        }
        "entity" => {
            fields(value, &["kind", "dimension", "uuid", "expectedType"])?;
            location(text(value, "dimension")?)?;
            location(text(value, "expectedType")?)?;
            let uuid = text(value, "uuid")?;
            require(
                uuid.len() == 36
                    && uuid.bytes().enumerate().all(|(i, b)| {
                        if [8, 13, 18, 23].contains(&i) {
                            b == b'-'
                        } else {
                            b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                        }
                    }),
            )?;
        }
        "storage" => {
            fields(value, &["kind", "storage", "key", "resourceId"])?;
            location(text(value, "storage")?)?;
            atom(text(value, "key")?, false)?;
            ResourceId::new(text(value, "resourceId")?).map_err(|_| NativePayloadError)?;
        }
        "score" => {
            fields(value, &["kind", "objective", "holder", "resourceId"])?;
            atom(text(value, "objective")?, true)?;
            atom(text(value, "holder")?, true)?;
            ResourceId::new(text(value, "resourceId")?).map_err(|_| NativePayloadError)?;
        }
        "objective" => {
            fields(value, &["kind", "objective", "resourceId"])?;
            atom(text(value, "objective")?, true)?;
            ResourceId::new(text(value, "resourceId")?).map_err(|_| NativePayloadError)?;
        }
        _ => return Err(NativePayloadError),
    }
    Ok(kind)
}
fn location(value: &str) -> Result<()> {
    require(value.len() <= 256)?;
    ResourceLocation::new(value)
        .map(|_| ())
        .map_err(|_| NativePayloadError)
}
fn atom(value: &str, scoreboard: bool) -> Result<()> {
    require(
        !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'_' | b'-')
                    || (scoreboard && matches!(b, b'.' | b'#'))
            }),
    )
}
fn full(raw: &Value, membership: &str, capture: &str) -> Result<()> {
    scope(raw, membership, capture, "full_target")?;
    require(raw["reason"].is_null())
}
fn scope(raw: &Value, membership: &str, capture: &str, coverage: &str) -> Result<()> {
    require(
        raw["membershipScope"] == membership
            && raw["captureScope"] == capture
            && raw["coverage"] == coverage,
    )
}
fn fields<'a>(value: &'a Value, expected: &[&str]) -> Result<&'a Map<String, Value>> {
    let object = value.as_object().ok_or(NativePayloadError)?;
    require(
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)),
    )?;
    Ok(object)
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(NativePayloadError)
}
fn boolean(value: &Value, key: &str) -> Result<bool> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or(NativePayloadError)
}
fn integer32(value: &Value) -> Result<i32> {
    value
        .as_i64()
        .and_then(|n| i32::try_from(n).ok())
        .ok_or(NativePayloadError)
}
fn array(value: &Value, maximum: usize) -> Result<&[Value]> {
    value
        .as_array()
        .filter(|items| items.len() <= maximum)
        .map(Vec::as_slice)
        .ok_or(NativePayloadError)
}
fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(NativePayloadError)
    }
}
fn java_string_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}
fn ordered_strings(values: &[Value], maximum_utf16: usize, maximum_bytes: usize) -> Result<()> {
    let mut previous: Option<&str> = None;
    let mut bytes = 0usize;
    for value in values {
        let current = value.as_str().ok_or(NativePayloadError)?;
        require(current.encode_utf16().count() <= maximum_utf16)?;
        bytes = bytes
            .checked_add(current.len())
            .filter(|n| *n <= maximum_bytes)
            .ok_or(NativePayloadError)?;
        if let Some(previous) = previous {
            require(java_string_cmp(previous, current) == Ordering::Less)?;
        }
        previous = Some(current);
    }
    Ok(())
}

/// Check structural and serialized-byte budgets before any decode allocation.
/// This is independent of the enclosing wire parser's original byte limit.
fn bounded_json(value: &Value, maximum: usize) -> Result<()> {
    let mut pending = vec![(value, 1usize)];
    let mut nodes = 0usize;
    let mut bytes = 0usize;
    while let Some((current, depth)) = pending.pop() {
        nodes += 1;
        require(nodes <= MAX_NODES && depth <= MAX_DEPTH)?;
        let cost = match current {
            Value::Null => 4,
            Value::Bool(true) => 4,
            Value::Bool(false) => 5,
            Value::Number(number) => number.to_string().len(),
            Value::String(text) => string_cost(text, maximum)?,
            Value::Array(items) => {
                require(
                    items.len() <= MAX_NODES - nodes
                        && pending.len() <= MAX_NODES - nodes - items.len(),
                )?;
                pending.extend(items.iter().map(|item| (item, depth + 1)));
                2 + items.len().saturating_sub(1)
            }
            Value::Object(object) => {
                require(
                    object.len() <= MAX_NODES - nodes
                        && pending.len() <= MAX_NODES - nodes - object.len(),
                )?;
                let mut cost = 2 + object.len().saturating_sub(1) + object.len();
                for (key, child) in object {
                    cost = cost
                        .checked_add(string_cost(key, maximum)?)
                        .filter(|n| *n <= maximum)
                        .ok_or(NativePayloadError)?;
                    pending.push((child, depth + 1));
                }
                cost
            }
        };
        bytes = bytes
            .checked_add(cost)
            .filter(|n| *n <= maximum)
            .ok_or(NativePayloadError)?;
    }
    Ok(())
}
fn string_cost(value: &str, maximum: usize) -> Result<usize> {
    require(value.len() <= maximum)?;
    let mut cost = 2usize;
    for byte in value.bytes() {
        let addition = match byte {
            b'"' | b'\\' | 8 | 9 | 10 | 12 | 13 => 2,
            0..=31 => 6,
            _ => 1,
        };
        cost = cost
            .checked_add(addition)
            .filter(|n| *n <= maximum)
            .ok_or(NativePayloadError)?;
    }
    Ok(cost)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // These are authored DTO fixtures, not real game observation, ownership,
    // codec completeness, retained history or native acceptance evidence.
    fn native_nbt(format: &str, bytes: &[u8]) -> Value {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        json!({"format":format,"bytesHex":hex,"sha256":raw_digest(bytes)})
    }
    fn compound() -> Value {
        native_nbt(NAMED_NBT, &[10, 0, 0, 0])
    }
    fn any_tag() -> Value {
        native_nbt(ANY_NBT, &[3, 0, 0, 0, 42])
    }
    fn selector(kind: &str) -> Value {
        match kind {
            "block_state" | "block_entity" => {
                json!({"kind":kind,"dimension":"minecraft:overworld","position":[0,64,0]})
            }
            "entity" => {
                json!({"kind":kind,"dimension":"minecraft:overworld","uuid":"00000000-0000-0000-0000-000000000001","expectedType":"minecraft:armor_stand"})
            }
            "score" => {
                json!({"kind":kind,"objective":"mmmm.score","holder":"#owned","resourceId":"resource-score"})
            }
            "objective" => {
                json!({"kind":kind,"objective":"mmmm.score","resourceId":"resource-objective"})
            }
            "storage" => {
                json!({"kind":kind,"storage":"mmmm:fixture","key":"owned","resourceId":"resource-storage"})
            }
            _ => unreachable!(),
        }
    }
    fn observed(
        kind: &str,
        presence: &str,
        membership: &str,
        capture: &str,
        payload: Value,
    ) -> Value {
        json!({"format":"mmmm.native.target/1","selector":selector(kind),"status":"known","presence":presence,
            "membershipScope":membership,"captureScope":capture,"coverage":"full_target","reason":null,"payload":payload})
    }
    fn state() -> Value {
        json!({"blockId":"minecraft:stone","properties":{}})
    }
    fn score_entry(holder: &str) -> Value {
        json!({"holder":holder,"value":17,"locked":true,"nativeScoreNbt":compound()})
    }
    fn known_examples() -> Vec<Value> {
        vec![
            observed(
                "block_state",
                "present",
                "loaded_block_position",
                "native_block_state",
                json!({"blockState":state(),"hasBlockEntity":false}),
            ),
            observed(
                "block_entity",
                "absent",
                "loaded_block_position",
                "native_persisted_block_entity",
                json!({"blockState":state()}),
            ),
            observed(
                "block_entity",
                "present",
                "loaded_block_position",
                "native_persisted_block_entity",
                json!({"blockState":state(),"blockEntityType":"minecraft:chest","nativeNbt":compound()}),
            ),
            observed(
                "entity",
                "present",
                "loaded_entity_identity",
                "native_persisted_entity",
                json!({"entityType":"minecraft:armor_stand","position":[0.0,64.5,-0.25],"tags":["mmmm.instance.fixture"],"nativeNbt":compound()}),
            ),
            observed(
                "score",
                "absent",
                "current_native_scoreboard",
                "native_score_entry",
                json!({"objectivePresent":false}),
            ),
            observed(
                "score",
                "absent",
                "current_native_scoreboard",
                "native_score_entry",
                json!({"objectivePresent":true}),
            ),
            observed(
                "score",
                "present",
                "current_native_scoreboard",
                "native_score_entry",
                json!({"objectivePresent":true,"value":i32::MIN,"locked":false,"numberFormatPresent":true,"nativeScoreNbt":compound()}),
            ),
            observed(
                "objective",
                "absent",
                "current_native_scoreboard",
                "native_objective_and_all_scores",
                json!({}),
            ),
            observed(
                "objective",
                "present",
                "current_native_scoreboard",
                "native_objective_and_all_scores",
                json!({"nativeObjectiveNbt":compound(),"scores":[score_entry("#one"),score_entry("player two")],"displaySlots":[{"id":1,"name":"sidebar"}]}),
            ),
            observed(
                "storage",
                "absent",
                "current_cached_command_storage",
                "native_storage_key",
                json!({"storagePresent":true,"statesPresent":false}),
            ),
            observed(
                "storage",
                "absent",
                "current_cached_command_storage",
                "native_storage_key",
                json!({"storagePresent":true,"statesPresent":true}),
            ),
            observed(
                "storage",
                "present",
                "current_cached_command_storage",
                "native_storage_key",
                json!({"storagePresent":true,"statesPresent":true,"nativeValueNbt":any_tag()}),
            ),
        ]
    }
    fn check(raw: &Value) -> Result<()> {
        validate_payload(raw, &raw["selector"], None)
    }
    fn pin() -> OriginalTargetPins {
        OriginalTargetPins {
            invocation_id: InvocationId::new("invocation-original").unwrap(),
            binding_id: BindingId::new("binding-original").unwrap(),
            operation_id: OperationId::new("operation-original").unwrap(),
            selector: selector("entity"),
            before_sha256: raw_digest(b"retained before bytes"),
            owner_tag: "mmmm.instance.fixture".to_owned(),
        }
    }
    fn tombstone(pin: &OriginalTargetPins) -> Value {
        observed(
            "entity",
            "absent",
            "retained_destroyed_native_identity",
            "observed_entity_instance",
            json!({
                "sourceInvocationId":pin.invocation_id,"sourceBindingId":pin.binding_id,"sourceOperationId":pin.operation_id,
                "beforeSha256":pin.before_sha256,"entityUuid":pin.selector["uuid"],"entityType":pin.selector["expectedType"],
                "ownerTag":pin.owner_tag,"removalReason":"KILLED","membershipClaim":"original_observed_instance_destroyed"
            }),
        )
    }

    #[test]
    fn admits_closed_known_native_dto_shapes_including_present_scores_and_objectives() {
        for raw in known_examples() {
            let preserved = raw.clone();
            assert_eq!(
                check(&raw),
                Ok(()),
                "kind {} presence {}",
                raw["selector"]["kind"],
                raw["presence"]
            );
            assert_eq!(raw, preserved);
        }
    }

    #[test]
    fn full_known_payloads_reject_extras_missing_fields_and_scope_substitution() {
        for raw in known_examples() {
            let mut extra = raw.clone();
            extra["payload"]["retained"] = json!(true);
            assert_eq!(check(&extra), Err(NativePayloadError));
            for key in raw["payload"].as_object().unwrap().keys() {
                let mut missing = raw.clone();
                missing["payload"].as_object_mut().unwrap().remove(key);
                assert_eq!(check(&missing), Err(NativePayloadError));
            }
            for key in ["membershipScope", "captureScope", "coverage", "reason"] {
                let mut changed = raw.clone();
                changed[key] = json!("caller-selected");
                assert_eq!(check(&changed), Err(NativePayloadError));
            }
            let mut extra = raw.clone();
            extra["dispatchSucceeded"] = json!(true);
            assert_eq!(check(&extra), Err(NativePayloadError));
        }
    }

    #[test]
    fn block_entity_payload_requires_separate_capture_and_preserves_partial_scope() {
        let mut raw = known_examples().remove(0);
        raw["payload"]["hasBlockEntity"] = json!(true);
        assert_eq!(check(&raw), Err(NativePayloadError));
        raw["coverage"] = json!("tracked_changes_only");
        raw["reason"] = json!("native_block_entity_payload_requires_separate_full_capture");
        assert_eq!(check(&raw), Ok(()));
        raw["payload"]["blockState"]["properties"]["facing"] = json!(7);
        assert_eq!(check(&raw), Err(NativePayloadError));
    }

    #[test]
    fn tombstone_requires_all_actual_original_pins_and_exact_native_selector() {
        let original = pin();
        let raw = tombstone(&original);
        assert_eq!(
            validate_payload(&raw, &original.selector, Some(&original)),
            Ok(())
        );
        assert_eq!(check(&raw), Err(NativePayloadError));
        for key in [
            "sourceInvocationId",
            "sourceBindingId",
            "sourceOperationId",
            "beforeSha256",
            "entityUuid",
            "entityType",
            "ownerTag",
            "membershipClaim",
        ] {
            let mut changed = raw.clone();
            changed["payload"][key] = json!("caller-substituted");
            assert_eq!(
                validate_payload(&changed, &original.selector, Some(&original)),
                Err(NativePayloadError),
                "{key}"
            );
        }
        let mut changed = raw.clone();
        changed["selector"]["dimension"] = json!("minecraft:the_nether");
        assert_eq!(
            validate_payload(&changed, &changed["selector"], Some(&original)),
            Err(NativePayloadError)
        );
        let mut changed = raw.clone();
        changed["payload"] = json!({"retained":true});
        assert_eq!(
            validate_payload(&changed, &original.selector, Some(&original)),
            Err(NativePayloadError)
        );
    }

    #[test]
    fn tombstone_never_converts_membership_loss_or_saving_removal_to_absence() {
        let original = pin();
        let raw = tombstone(&original);
        for reason in [
            "UNLOADED_TO_CHUNK",
            "UNLOADED_WITH_PLAYER",
            "CHANGED_DIMENSION",
            "UNKNOWN",
            "",
            "killed",
        ] {
            let mut changed = raw.clone();
            changed["payload"]["removalReason"] = json!(reason);
            assert_eq!(
                validate_payload(&changed, &original.selector, Some(&original)),
                Err(NativePayloadError)
            );
        }
        let mut discarded = raw;
        discarded["payload"]["removalReason"] = json!("DISCARDED");
        assert_eq!(
            validate_payload(&discarded, &original.selector, Some(&original)),
            Ok(())
        );
    }

    #[test]
    fn native_nbt_rejects_wrong_format_noncanonical_hex_and_digest_mismatch() {
        let valid = compound();
        assert_eq!(nbt(&valid, NAMED_NBT), Ok(()));
        assert_eq!(nbt(&valid, ANY_NBT), Err(NativePayloadError));
        for hex in ["", "0", "0A000000", "0g000000", "0a 00000", "00000000"] {
            let mut changed = valid.clone();
            changed["bytesHex"] = json!(hex);
            assert_eq!(nbt(&changed, NAMED_NBT), Err(NativePayloadError));
        }
        let mut changed = valid.clone();
        changed["sha256"] = json!(raw_digest(b"unrelated bytes"));
        assert_eq!(nbt(&changed, NAMED_NBT), Err(NativePayloadError));
        changed["sha256"] = json!(raw_digest(&[10, 0, 0, 0]).as_str().to_uppercase());
        assert_eq!(nbt(&changed, NAMED_NBT), Err(NativePayloadError));
        let at_limit = native_nbt(ANY_NBT, &vec![0; MAX_NATIVE_BYTES]);
        assert_eq!(nbt(&at_limit, ANY_NBT), Ok(()));
        let beyond = native_nbt(ANY_NBT, &vec![0; MAX_NATIVE_BYTES + 1]);
        assert_eq!(nbt(&beyond, ANY_NBT), Err(NativePayloadError));
        // A matching opaque byte hash is not an interpreted NBT validity test.
        let opaque = native_nbt(ANY_NBT, b"not parsed as a domain object");
        assert_eq!(nbt(&opaque, ANY_NBT), Ok(()));
    }

    #[test]
    fn entity_type_position_and_all_tag_membership_are_exact_and_bounded() {
        let raw = known_examples().remove(3);
        let mut changed = raw.clone();
        changed["payload"]["entityType"] = json!("minecraft:pig");
        assert_eq!(check(&changed), Err(NativePayloadError));
        for coordinate in [json!(2147483648.0), json!(-2147483649.0), json!("0")] {
            let mut changed = raw.clone();
            changed["payload"]["position"][0] = coordinate;
            assert_eq!(check(&changed), Err(NativePayloadError));
        }
        for tags in [
            json!(["same", "same"]),
            json!(["z", "a"]),
            json!([1]),
            json!(vec!["a"; 129]),
        ] {
            let mut changed = raw.clone();
            changed["payload"]["tags"] = tags;
            assert_eq!(check(&changed), Err(NativePayloadError));
        }
        let mut changed = raw;
        changed["payload"]["tags"] = json!([
            "a".repeat(5461),
            "b".repeat(5461),
            "c".repeat(5461),
            "d".repeat(5461)
        ]);
        assert_eq!(check(&changed), Err(NativePayloadError));
    }

    #[test]
    fn metadata_score_flags_and_complete_objective_entry_shapes_are_required() {
        let score = known_examples().remove(6);
        for (field, replacement) in [
            ("objectivePresent", json!(false)),
            ("value", json!(2147483648i64)),
            ("value", json!(1.5)),
            ("locked", json!("false")),
            ("numberFormatPresent", Value::Null),
        ] {
            let mut changed = score.clone();
            changed["payload"][field] = replacement;
            assert_eq!(check(&changed), Err(NativePayloadError));
        }
        let objective = known_examples().remove(8);
        for field in ["holder", "value", "locked", "nativeScoreNbt"] {
            let mut changed = objective.clone();
            changed["payload"]["scores"][0]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert_eq!(check(&changed), Err(NativePayloadError));
        }
        let mut changed = objective.clone();
        changed["payload"]["scores"] = json!([score_entry("same"), score_entry("same")]);
        assert_eq!(check(&changed), Err(NativePayloadError));
        changed["payload"]["scores"] = json!([score_entry("z"), score_entry("a")]);
        assert_eq!(check(&changed), Err(NativePayloadError));
        changed["payload"]["scores"] = json!([score_entry("\u{10000}"), score_entry("\u{e000}")]);
        assert_eq!(
            check(&changed),
            Ok(()),
            "Java UTF-16 ordering is distinct from UTF-8 ordering"
        );
        for slots in [
            json!([{"id":1,"name":"sidebar"},{"id":1,"name":"list"}]),
            json!([{"id":1,"name":"sidebar"},{"id":2,"name":"sidebar"}]),
            json!([{"id":-1,"name":"sidebar"}]),
            json!([{"id":1,"name":"sidebar","objective":"caller"}]),
        ] {
            let mut changed = objective.clone();
            changed["payload"]["displaySlots"] = slots;
            assert_eq!(check(&changed), Err(NativePayloadError));
        }
    }

    #[test]
    fn storage_cached_membership_and_any_tag_format_cannot_be_substituted() {
        let raw = known_examples().remove(11);
        for field in ["storagePresent", "statesPresent"] {
            let mut changed = raw.clone();
            changed["payload"][field] = json!(false);
            assert_eq!(check(&changed), Err(NativePayloadError));
        }
        let mut changed = raw;
        changed["payload"]["nativeValueNbt"] = compound();
        assert_eq!(check(&changed), Err(NativePayloadError));
    }

    #[test]
    fn unknown_and_unsupported_preserve_uncertainty_with_no_full_coverage() {
        for status in ["unknown", "unsupported"] {
            let raw = json!({"format":"mmmm.native.target/1","selector":selector("entity"),"status":status,"presence":"unknown",
                "membershipScope":"unknown","captureScope":"native_persisted_entity","coverage":"best_effort",
                "reason":"future_native_membership_not_observed","payload":null});
            let retained = raw.clone();
            assert_eq!(check(&raw), Ok(()));
            assert_eq!(raw, retained);
            for (key, replacement) in [
                ("coverage", json!("full_target")),
                ("presence", json!("absent")),
                ("payload", json!({"retained":true})),
                ("membershipScope", json!("loaded_entity_identity")),
            ] {
                let mut changed = raw.clone();
                changed[key] = replacement;
                assert_eq!(check(&changed), Err(NativePayloadError));
            }
        }
    }

    #[test]
    fn storage_noncompound_parent_retains_opaque_partial_payload_only() {
        let raw = json!({"format":"mmmm.native.target/1","selector":selector("storage"),"status":"unknown","presence":"unknown",
            "membershipScope":"current_cached_command_storage","captureScope":"native_storage_parent","coverage":"tracked_changes_only",
            "reason":"native_storage_parent_is_not_a_compound","payload":{"storagePresent":true,"nativeStatesNbt":any_tag()}});
        assert_eq!(check(&raw), Ok(()));
        for (key, value) in [
            ("coverage", json!("full_target")),
            ("status", json!("known")),
            ("presence", json!("absent")),
        ] {
            let mut changed = raw.clone();
            changed[key] = value;
            assert_eq!(check(&changed), Err(NativePayloadError));
        }
        let mut changed = raw;
        changed["payload"]["statesPresent"] = json!(true);
        assert_eq!(check(&changed), Err(NativePayloadError));
    }

    #[test]
    fn selectors_are_closed_finite_and_never_arbitrary_nbt_paths() {
        let mut invalid = selector("storage");
        invalid["key"] = json!("owned.child");
        assert_eq!(validate_selector(&invalid), Err(NativePayloadError));
        invalid = selector("score");
        invalid["holder"] = json!("*");
        assert_eq!(validate_selector(&invalid), Err(NativePayloadError));
        invalid = selector("block_state");
        invalid["position"][0] = json!(2147483648i64);
        assert_eq!(validate_selector(&invalid), Err(NativePayloadError));
        invalid = selector("entity");
        invalid["uuid"] = json!("00000000-0000-0000-0000-00000000000A");
        assert_eq!(validate_selector(&invalid), Err(NativePayloadError));
        invalid = selector("entity");
        invalid["expectedType"] = json!(format!("a:{}", "b".repeat(255)));
        assert_eq!(validate_selector(&invalid), Err(NativePayloadError));
        let mut raw = known_examples().remove(0);
        let exact = raw["selector"].clone();
        raw["selector"]["position"][0] = json!(1);
        assert_eq!(
            validate_payload(&raw, &exact, None),
            Err(NativePayloadError)
        );
    }

    #[test]
    fn independent_value_budget_bounds_depth_nodes_bytes_and_escaped_control_text() {
        let mut nested = Value::Null;
        for _ in 0..MAX_DEPTH {
            nested = json!([nested]);
        }
        assert_eq!(
            bounded_json(&nested, MAX_RAW_BYTES),
            Err(NativePayloadError)
        );
        assert_eq!(
            bounded_json(&json!(vec![Value::Null; MAX_NODES]), MAX_RAW_BYTES),
            Err(NativePayloadError)
        );
        assert_eq!(
            bounded_json(&json!("x".repeat(MAX_RAW_BYTES)), MAX_RAW_BYTES),
            Err(NativePayloadError)
        );
        // Every U+0001 serializes to six escape bytes plus two string quotes.
        // The previous fixture was two bytes below the limit, so accepting it
        // was correct. Exercise the inclusive limit and the first excess byte.
        let escaped = "\u{0001}".repeat(MAX_RAW_BYTES / 6);
        assert_eq!(bounded_json(&json!(escaped), MAX_RAW_BYTES), Ok(()));
        assert_eq!(
            bounded_json(&json!(format!("{escaped}xx")), MAX_RAW_BYTES),
            Ok(())
        );
        assert_eq!(
            bounded_json(&json!(format!("{escaped}xxx")), MAX_RAW_BYTES),
            Err(NativePayloadError)
        );
        assert_eq!(
            bounded_json(&json!({"n":[null,true,false,17],"s":"\n\\\"한글"}), 128),
            Ok(())
        );
    }
}

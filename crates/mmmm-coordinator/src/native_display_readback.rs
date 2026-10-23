//! Persisted display meanings, issued only by the current native target reader.
//! Parsing bytes is separate from acquiring a same-Store observation. Neither
//! the parsed values nor the sealed snapshot authorize a scene, pose or write.
use crate::{
    calibration_observer::{Tag, decode_persisted_named_nbt},
    native_targets::{NativeSelector, NativeTargetError},
};
use mmmm_application::{AppError, AppResult};
use mmmm_contracts::{ResourceLocation, Sha256Digest};
use mmmm_runtime::storage::BlobRef;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeDisplayKind {
    Block,
    Item,
    Text,
}
impl NativeDisplayKind {
    pub fn entity_type(self) -> &'static str {
        match self {
            Self::Block => "minecraft:block_display",
            Self::Item => "minecraft:item_display",
            Self::Text => "minecraft:text_display",
        }
    }
}

/// The original finite NBT floating type and bits, without a numeric cast.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeDisplayFloat {
    Float32(u32),
    Float64(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeDisplayTransformation {
    Matrix([NativeDisplayFloat; 16]),
    Decomposed {
        translation: [NativeDisplayFloat; 3],
        left_rotation: [NativeDisplayFloat; 4],
        scale: [NativeDisplayFloat; 3],
        right_rotation: [NativeDisplayFloat; 4],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeDisplayBillboard {
    Fixed,
    Vertical,
    Horizontal,
    Center,
}

/// Omitted persisted fields remain omitted; this is not an effective client
/// interpolation state or a default-filled game entity projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeDisplayInterpolation {
    start: Option<i32>,
    duration: Option<i32>,
    teleport_duration: Option<i32>,
}
impl NativeDisplayInterpolation {
    pub fn start(&self) -> Option<i32> {
        self.start
    }
    pub fn duration(&self) -> Option<i32> {
        self.duration
    }
    pub fn teleport_duration(&self) -> Option<i32> {
        self.teleport_duration
    }
}

/// Java UTF-16 code units remain exact, including unpaired surrogates in
/// otherwise unrelated entity tags. No lossy Rust String is manufactured.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NativeDisplayTag(Vec<u16>);
impl NativeDisplayTag {
    pub fn code_units(&self) -> &[u16] {
        &self.0
    }
}

#[derive(Debug)]
pub struct NativeDisplayState {
    dimension: ResourceLocation,
    uuid: [u8; 16],
    kind: NativeDisplayKind,
    position_bits: [u64; 3],
    rotation: Option<[NativeDisplayFloat; 2]>,
    owner_tag: String,
    tags: Vec<NativeDisplayTag>,
    persisted_entity_type: Option<String>,
    transformation: Option<NativeDisplayTransformation>,
    billboard: Option<NativeDisplayBillboard>,
    interpolation: NativeDisplayInterpolation,
}
impl NativeDisplayState {
    pub fn dimension(&self) -> &ResourceLocation {
        &self.dimension
    }
    pub fn uuid(&self) -> &[u8; 16] {
        &self.uuid
    }
    pub fn kind(&self) -> NativeDisplayKind {
        self.kind
    }
    pub fn position_bits(&self) -> &[u64; 3] {
        &self.position_bits
    }
    /// The two original root Rotation elements, in persisted order and native
    /// floating representation. Absence is not a zero/effective rotation, and
    /// preserving a representation does not admit it as a target pose codec.
    pub fn rotation(&self) -> Option<[NativeDisplayFloat; 2]> {
        self.rotation
    }
    pub fn owner_tag(&self) -> &str {
        &self.owner_tag
    }
    pub fn tags(&self) -> &[NativeDisplayTag] {
        &self.tags
    }
    pub fn persisted_entity_type(&self) -> Option<&str> {
        self.persisted_entity_type.as_deref()
    }
    pub fn transformation(&self) -> Option<&NativeDisplayTransformation> {
        self.transformation.as_ref()
    }
    pub fn billboard(&self) -> Option<NativeDisplayBillboard> {
        self.billboard
    }
    pub fn interpolation(&self) -> NativeDisplayInterpolation {
        self.interpolation
    }
}

/// There is no public constructor or Deserialize implementation. The reader
/// emits this historical factual value after its final current-owner check.
#[derive(Debug)]
pub struct NativeDisplaySnapshot {
    state: NativeDisplayState,
    provenance: DisplayProvenance,
}
#[derive(Debug)]
pub(crate) struct DisplayProvenance {
    pub(crate) response: BlobRef,
    pub(crate) observation_digest: Sha256Digest,
    pub(crate) native_nbt_digest: Sha256Digest,
    pub(crate) context_digest: Sha256Digest,
    pub(crate) current_context_digest: Sha256Digest,
    pub(crate) registry_generation: String,
}
impl NativeDisplaySnapshot {
    pub(crate) fn from_acquired(state: NativeDisplayState, provenance: DisplayProvenance) -> Self {
        Self { state, provenance }
    }
    pub fn state(&self) -> &NativeDisplayState {
        &self.state
    }
    pub fn response(&self) -> &BlobRef {
        &self.provenance.response
    }
    pub fn observation_digest(&self) -> &Sha256Digest {
        &self.provenance.observation_digest
    }
    pub fn native_nbt_digest(&self) -> &Sha256Digest {
        &self.provenance.native_nbt_digest
    }
    pub fn context_digest(&self) -> &Sha256Digest {
        &self.provenance.context_digest
    }
    pub fn current_context_digest(&self) -> &Sha256Digest {
        &self.provenance.current_context_digest
    }
    pub fn registry_generation(&self) -> &str {
        &self.provenance.registry_generation
    }
}

/// A failed interpretation and a later owner/control failure coexist. Neither
/// failure is rewritten into a successful snapshot or a safe retry receipt.
#[derive(Debug)]
pub enum NativeDisplayReadError {
    Native(NativeTargetError),
    Decode(AppError),
    Checkpoint {
        original: Box<NativeDisplayReadError>,
        checkpoint: NativeTargetError,
    },
}
impl From<NativeTargetError> for NativeDisplayReadError {
    fn from(error: NativeTargetError) -> Self {
        Self::Native(error)
    }
}
impl std::fmt::Display for NativeDisplayReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "Actual persisted display state could not be interpreted under the original read",
        )
    }
}
impl std::error::Error for NativeDisplayReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Native(error) => error,
            Self::Decode(error) => error,
            Self::Checkpoint { original, .. } => original.as_ref(),
        })
    }
}
pub(crate) fn finish<T>(
    original: Result<T, NativeDisplayReadError>,
    checkpoint: Result<(), NativeTargetError>,
) -> Result<T, NativeDisplayReadError> {
    match (original, checkpoint) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(NativeDisplayReadError::Native(error)),
        (Err(original), Err(checkpoint)) => Err(NativeDisplayReadError::Checkpoint {
            original: Box::new(original),
            checkpoint,
        }),
    }
}

/// Pure interpretation only. JSON knownness, matching hashes or a caller's
/// owner tag cannot turn this result into a NativeDisplaySnapshot.
pub(crate) fn parse_display(
    raw: &Value,
    selector: &NativeSelector,
    owner_tag: &str,
    check: &dyn Fn() -> AppResult<()>,
) -> AppResult<NativeDisplayState> {
    check()?;
    crate::native_payload::validate_payload(raw, selector.value(), None).map_err(|error| {
        AppError::caused_by(
            "NATIVE_DISPLAY_INVALID",
            "Native display DTO is invalid",
            error,
        )
    })?;
    if selector.kind() != "entity"
        || raw["status"] != "known"
        || raw["presence"] != "present"
        || raw["coverage"] != "full_target"
        || owner_tag.is_empty()
        || owner_tag.len() > 64
        || !owner_tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(invalid());
    }
    let kind = match selector.value()["expectedType"].as_str() {
        Some("minecraft:block_display") => NativeDisplayKind::Block,
        Some("minecraft:item_display") => NativeDisplayKind::Item,
        Some("minecraft:text_display") => NativeDisplayKind::Text,
        _ => return Err(invalid()),
    };
    let tag = decode_persisted_named_nbt(&raw["payload"]["nativeNbt"], check).map_err(|error| {
        AppError::caused_by(
            "NATIVE_DISPLAY_INVALID",
            "Persisted display NBT is invalid",
            error,
        )
    })?;
    let root = compound(&tag)?;
    let uuid = match field(root, "UUID")? {
        Tag::IntArray(words) if words.len() == 4 => {
            let mut bytes = [0u8; 16];
            for (part, word) in bytes.chunks_exact_mut(4).zip(words) {
                part.copy_from_slice(&word.to_be_bytes());
            }
            bytes
        }
        _ => return Err(invalid()),
    };
    if uuid != selector_uuid(selector)? {
        return Err(invalid());
    }
    let persisted_entity_type = optional(root, "id")
        .map(|tag| match tag {
            Tag::String(units) if units.iter().copied().eq(kind.entity_type().encode_utf16()) => {
                Ok(kind.entity_type().to_owned())
            }
            _ => Err(invalid()),
        })
        .transpose()?;
    let position = match field(root, "Pos")? {
        Tag::List(values) if values.len() == 3 => values,
        _ => return Err(invalid()),
    };
    let mut position_bits = [0; 3];
    for (index, value) in position.iter().enumerate() {
        let Tag::Double(bits) = value else {
            return Err(invalid());
        };
        let number = f64::from_bits(*bits);
        if !number.is_finite()
            || number < f64::from(i32::MIN)
            || number >= f64::from(i32::MAX) + 1.0
            || raw["payload"]["position"][index].as_f64() != Some(number)
        {
            return Err(invalid());
        }
        position_bits[index] = *bits;
    }
    let tags = match field(root, "Tags")? {
        Tag::List(values) if values.len() <= 128 => values,
        _ => return Err(invalid()),
    };
    let mut native_tags = BTreeSet::new();
    for tag in tags {
        let Tag::String(units) = tag else {
            return Err(invalid());
        };
        if !native_tags.insert(units.clone()) {
            return Err(invalid());
        }
    }
    let payload_tags = raw["payload"]["tags"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(|s| s.encode_utf16().collect::<Vec<_>>())
                .ok_or_else(invalid)
        })
        .collect::<AppResult<BTreeSet<_>>>()?;
    if native_tags != payload_tags
        || !native_tags.contains(&owner_tag.encode_utf16().collect::<Vec<_>>())
    {
        return Err(invalid());
    }
    let transformation = optional(root, "transformation")
        .map(transform)
        .transpose()?;
    let rotation = optional(root, "Rotation").map(vector::<2>).transpose()?;
    let billboard = optional(root, "billboard")
        .map(|value| match value {
            Tag::String(units) => match String::from_utf16(units).ok().as_deref() {
                Some("fixed") => Ok(NativeDisplayBillboard::Fixed),
                Some("vertical") => Ok(NativeDisplayBillboard::Vertical),
                Some("horizontal") => Ok(NativeDisplayBillboard::Horizontal),
                Some("center") => Ok(NativeDisplayBillboard::Center),
                _ => Err(invalid()),
            },
            _ => Err(invalid()),
        })
        .transpose()?;
    let interpolation = NativeDisplayInterpolation {
        start: optional_int(root, "start_interpolation")?,
        duration: optional_int(root, "interpolation_duration")?,
        teleport_duration: optional_int(root, "teleport_duration")?,
    };
    check()?;
    Ok(NativeDisplayState {
        dimension: serde_json::from_value(selector.value()["dimension"].clone())
            .map_err(|_| invalid())?,
        uuid,
        kind,
        position_bits,
        rotation,
        owner_tag: owner_tag.to_owned(),
        tags: native_tags.into_iter().map(NativeDisplayTag).collect(),
        persisted_entity_type,
        transformation,
        billboard,
        interpolation,
    })
}

fn compound(value: &Tag) -> AppResult<&BTreeMap<Vec<u16>, Tag>> {
    match value {
        Tag::Compound(map) => Ok(map),
        _ => Err(invalid()),
    }
}
fn optional<'a>(map: &'a BTreeMap<Vec<u16>, Tag>, name: &str) -> Option<&'a Tag> {
    map.get(&name.encode_utf16().collect::<Vec<_>>())
}
fn field<'a>(map: &'a BTreeMap<Vec<u16>, Tag>, name: &str) -> AppResult<&'a Tag> {
    optional(map, name).ok_or_else(invalid)
}
fn optional_int(map: &BTreeMap<Vec<u16>, Tag>, name: &str) -> AppResult<Option<i32>> {
    optional(map, name)
        .map(|tag| match tag {
            Tag::Int(value) => Ok(*value),
            _ => Err(invalid()),
        })
        .transpose()
}
fn vector<const N: usize>(tag: &Tag) -> AppResult<[NativeDisplayFloat; N]> {
    let Tag::List(values) = tag else {
        return Err(invalid());
    };
    let values = values
        .iter()
        .map(|tag| match tag {
            Tag::Float(bits) if f32::from_bits(*bits).is_finite() => {
                Ok(NativeDisplayFloat::Float32(*bits))
            }
            Tag::Double(bits) if f64::from_bits(*bits).is_finite() => {
                Ok(NativeDisplayFloat::Float64(*bits))
            }
            _ => Err(invalid()),
        })
        .collect::<AppResult<Vec<_>>>()?;
    values.try_into().map_err(|_| invalid())
}
fn transform(tag: &Tag) -> AppResult<NativeDisplayTransformation> {
    match tag {
        Tag::List(_) => vector(tag).map(NativeDisplayTransformation::Matrix),
        Tag::Compound(map) if map.len() == 4 => Ok(NativeDisplayTransformation::Decomposed {
            translation: vector(field(map, "translation")?)?,
            left_rotation: vector(field(map, "left_rotation")?)?,
            scale: vector(field(map, "scale")?)?,
            right_rotation: vector(field(map, "right_rotation")?)?,
        }),
        _ => Err(invalid()),
    }
}
fn selector_uuid(selector: &NativeSelector) -> AppResult<[u8; 16]> {
    let text = selector.value()["uuid"].as_str().ok_or_else(invalid)?;
    let compact: String = text.chars().filter(|c| *c != '-').collect();
    if compact.len() != 32 {
        return Err(invalid());
    }
    let mut bytes = [0; 16];
    for (target, pair) in bytes.iter_mut().zip(compact.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
        *target = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
    }
    Ok(bytes)
}
fn invalid() -> AppError {
    AppError::new(
        "NATIVE_DISPLAY_INVALID",
        "Actual persisted display fields do not match the selected native display",
    )
}

#[cfg(test)]
#[path = "native_display_readback_tests.rs"]
mod tests;

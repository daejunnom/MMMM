//! Parse before schema validation: duplicate keys must never be overwritten.

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::{
    cell::{Cell, RefCell},
    convert::Infallible,
    error::Error,
    fmt,
    io::{self, Write},
    ops::Range,
};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const CONTROL_BYTE_INTERVAL: usize = 4 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct JsonLimits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_nodes: usize,
}

impl Default for JsonLimits {
    fn default() -> Self {
        Self {
            max_bytes: 8 * 1024 * 1024,
            max_depth: 64,
            max_nodes: 100_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonError {
    pub message: String,
    pub line: usize,
    pub column: usize,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}:{}", self.message, self.line, self.column)
    }
}

impl Error for JsonError {}

/// Preserve a caller's deadline or cancellation error without converting it
/// into a JSON syntax error. The strict parser does not own the caller's policy.
#[derive(Debug, PartialEq, Eq)]
pub enum ControlledJsonError<E> {
    Json(JsonError),
    Control(E),
}

impl<E: fmt::Display> fmt::Display for ControlledJsonError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => error.fmt(f),
            Self::Control(error) => error.fmt(f),
        }
    }
}

impl<E: Error + 'static> Error for ControlledJsonError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(match self {
            Self::Json(error) => error,
            Self::Control(error) => error,
        })
    }
}

impl From<serde_json::Error> for JsonError {
    fn from(error: serde_json::Error) -> Self {
        Self {
            message: error.to_string(),
            line: error.line(),
            column: error.column(),
        }
    }
}

fn boundary_error(message: impl Into<String>) -> JsonError {
    JsonError {
        message: message.into(),
        line: 0,
        column: 0,
    }
}

/// Select the only schema paths whose original decimal integer lexemes are
/// checked by the raw-input validation API. Other numbers are unaffected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExactSelector {
    ResourceRef,
    PhysicsDefinition,
}

/// Position of a ResourceRef whose original Prefab number is not an exact safe
/// integer. Indices refer to the corresponding arrays in that Prefab.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefabExactLocation {
    /// `resources[index].sizeBytes`.
    Resource(usize),
    /// `nodes[index].geometryResource.sizeBytes`.
    Geometry(usize),
}

/// A selected ResourceRef location within a SceneSelectionSnapshot Prefab.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectionExactLocation {
    pub prefab: usize,
    pub location: PrefabExactLocation,
}

#[derive(Clone, Copy)]
enum RawPath {
    Ignore,
    ResourceRoot,
    ResourceSize,
    PhysicsRoot,
    Colliders,
    Collider(usize),
    OuterShape(usize),
    InnerShape(usize),
    Geometry(usize),
    GeometrySize(usize),
    PrefabRoot,
    PrefabResources,
    PrefabResource(usize),
    PrefabResourceSize(usize),
    PrefabNodes,
    PrefabNode(usize),
    PrefabGeometry(usize),
    PrefabGeometrySize(usize),
    SelectionRoot,
    SelectionPrefabs,
    SelectionPrefab(usize),
    SelectionResources(usize),
    SelectionResource(usize, usize),
    SelectionResourceSize(usize, usize),
    SelectionNodes(usize),
    SelectionNode(usize, usize),
    SelectionGeometry(usize, usize),
    SelectionGeometrySize(usize, usize),
}

impl RawPath {
    fn map_child(self, key: &str) -> Self {
        match (self, key) {
            (Self::ResourceRoot, "sizeBytes") => Self::ResourceSize,
            (Self::PhysicsRoot, "colliders") => Self::Colliders,
            (Self::Collider(index), "shape") => Self::OuterShape(index),
            (Self::OuterShape(index), "shape") => Self::InnerShape(index),
            (Self::InnerShape(index), "geometry") => Self::Geometry(index),
            (Self::Geometry(index), "sizeBytes") => Self::GeometrySize(index),
            (Self::PrefabRoot, "resources") => Self::PrefabResources,
            (Self::PrefabRoot, "nodes") => Self::PrefabNodes,
            (Self::PrefabResource(index), "sizeBytes") => Self::PrefabResourceSize(index),
            (Self::PrefabNode(index), "geometryResource") => Self::PrefabGeometry(index),
            (Self::PrefabGeometry(index), "sizeBytes") => Self::PrefabGeometrySize(index),
            (Self::SelectionRoot, "prefabs") => Self::SelectionPrefabs,
            (Self::SelectionPrefab(prefab), "resources") => Self::SelectionResources(prefab),
            (Self::SelectionPrefab(prefab), "nodes") => Self::SelectionNodes(prefab),
            (Self::SelectionResource(prefab, index), "sizeBytes") => {
                Self::SelectionResourceSize(prefab, index)
            }
            (Self::SelectionNode(prefab, index), "geometryResource") => {
                Self::SelectionGeometry(prefab, index)
            }
            (Self::SelectionGeometry(prefab, index), "sizeBytes") => {
                Self::SelectionGeometrySize(prefab, index)
            }
            _ => Self::Ignore,
        }
    }

    fn array_child(self, index: usize) -> Self {
        match self {
            Self::Colliders => Self::Collider(index),
            Self::PrefabResources => Self::PrefabResource(index),
            Self::PrefabNodes => Self::PrefabNode(index),
            Self::SelectionPrefabs => Self::SelectionPrefab(index),
            Self::SelectionResources(prefab) => Self::SelectionResource(prefab, index),
            Self::SelectionNodes(prefab) => Self::SelectionNode(prefab, index),
            _ => Self::Ignore,
        }
    }
}

struct RawCandidate {
    collider: Option<usize>,
    prefab: Option<PrefabExactLocation>,
    selection: Option<SelectionExactLocation>,
    span: Range<usize>,
}

/// A private per-parse capture: spans are never a caller-constructible proof.
/// Malformed input can contain arbitrarily many number-like fragments, so
/// overflow/allocation failure is deferred until strict parsing has succeeded.
struct RawCapture {
    spans: RefCell<Vec<Range<usize>>>,
    candidates: RefCell<Vec<RawCandidate>>,
    maximum: usize,
    cursor: Cell<usize>,
    invalid: Cell<bool>,
}

impl RawCapture {
    fn new(limits: JsonLimits, bytes: usize) -> Self {
        Self {
            spans: RefCell::new(Vec::new()),
            candidates: RefCell::new(Vec::new()),
            maximum: limits
                .max_nodes
                .min(JsonLimits::default().max_nodes)
                .min(bytes),
            cursor: Cell::new(0),
            invalid: Cell::new(false),
        }
    }

    fn add_span(&self, span: Range<usize>) {
        let mut spans = self.spans.borrow_mut();
        if spans.len() >= self.maximum || spans.try_reserve(1).is_err() {
            self.invalid.set(true);
        } else {
            spans.push(span);
        }
    }

    fn consume(&self, path: RawPath) {
        let position = self.cursor.get();
        let Some(next) = position.checked_add(1) else {
            self.invalid.set(true);
            return;
        };
        self.cursor.set(next);
        let Some(span) = self.spans.borrow().get(position).cloned() else {
            self.invalid.set(true);
            return;
        };
        let (collider, prefab, selection) = match path {
            RawPath::ResourceSize => (None, None, None),
            RawPath::GeometrySize(index) => (Some(index), None, None),
            RawPath::PrefabResourceSize(index) => {
                (None, Some(PrefabExactLocation::Resource(index)), None)
            }
            RawPath::PrefabGeometrySize(index) => {
                (None, Some(PrefabExactLocation::Geometry(index)), None)
            }
            RawPath::SelectionResourceSize(prefab, index) => (
                None,
                None,
                Some(SelectionExactLocation {
                    prefab,
                    location: PrefabExactLocation::Resource(index),
                }),
            ),
            RawPath::SelectionGeometrySize(prefab, index) => (
                None,
                None,
                Some(SelectionExactLocation {
                    prefab,
                    location: PrefabExactLocation::Geometry(index),
                }),
            ),
            _ => return,
        };
        let mut candidates = self.candidates.borrow_mut();
        if candidates.len() >= self.maximum || candidates.try_reserve(1).is_err() {
            self.invalid.set(true);
        } else {
            candidates.push(RawCandidate {
                collider,
                prefab,
                selection,
                span,
            });
        }
    }
}

/// Internal immutable pairing of one byte slice and its own strict parse.
/// It is intentionally not an externally transferable witness.
pub(crate) struct RawExactParsed<'a> {
    bytes: &'a [u8],
    value: Value,
    selector: ExactSelector,
    capture: RawCapture,
}

/// Internal raw-validation failures are separate from JSON syntax failures.
#[derive(Debug)]
pub(crate) enum RawExactError<E> {
    CaptureUnavailable,
    ExactInteger { collider: Option<usize> },
    Control(E),
}

impl RawExactParsed<'_> {
    pub(crate) fn value(&self) -> &Value {
        &self.value
    }

    pub(crate) fn into_value(self) -> Value {
        self.value
    }

    /// Call only after schema validation of `value()`. The resulting check is
    /// limited to the selected paths and is bound to this parse's bytes.
    pub(crate) fn validate_exact<E>(
        &self,
        checkpoint: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<(), RawExactError<E>> {
        let capture_error = || RawExactError::CaptureUnavailable;
        if self.capture.invalid.get()
            || self.capture.cursor.get() != self.capture.spans.borrow().len()
        {
            return Err(capture_error());
        }
        let candidates = self.capture.candidates.borrow();
        let mut cursor = 0usize;
        match self.selector {
            ExactSelector::ResourceRef => {
                let candidate = candidates
                    .first()
                    .filter(|candidate| candidate.collider.is_none())
                    .ok_or_else(capture_error)?;
                self.validate_candidate(candidate, checkpoint)?;
                cursor = 1;
            }
            ExactSelector::PhysicsDefinition => {
                let colliders = self
                    .value
                    .get("colliders")
                    .and_then(Value::as_array)
                    .ok_or_else(capture_error)?;
                for (index, collider) in colliders.iter().enumerate() {
                    if index % 128 == 0 {
                        checkpoint().map_err(RawExactError::Control)?;
                    }
                    let shape = collider
                        .get("shape")
                        .and_then(|value| value.get("shape"))
                        .ok_or_else(capture_error)?;
                    if shape.get("kind").and_then(Value::as_str) == Some("mesh") {
                        let candidate = candidates
                            .get(cursor)
                            .filter(|candidate| candidate.collider == Some(index))
                            .ok_or_else(capture_error)?;
                        self.validate_candidate(candidate, checkpoint)?;
                        cursor += 1;
                    }
                }
            }
        }
        if cursor != candidates.len() {
            return Err(capture_error());
        }
        Ok(())
    }

    fn validate_candidate<E>(
        &self,
        candidate: &RawCandidate,
        checkpoint: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<(), RawExactError<E>> {
        let token = self
            .bytes
            .get(candidate.span.clone())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .ok_or(RawExactError::CaptureUnavailable)?;
        let exact = crate::number::exact_safe_u64_json_lexeme_with_control(token, checkpoint)
            .map_err(RawExactError::Control)?;
        if exact.is_none() {
            return Err(RawExactError::ExactInteger {
                collider: candidate.collider,
            });
        }
        Ok(())
    }
}

/// The Prefab capture is bound to the same bytes and strict parse that supplied
/// its Value; callers cannot construct or transfer a witness independently.
pub(crate) struct RawPrefabExactParsed<'a> {
    bytes: &'a [u8],
    value: Value,
    capture: RawCapture,
}

#[derive(Debug)]
pub(crate) enum RawPrefabExactError<E> {
    CaptureUnavailable,
    ExactInteger { location: PrefabExactLocation },
    Control(E),
}

impl RawPrefabExactParsed<'_> {
    pub(crate) fn value(&self) -> &Value {
        &self.value
    }

    pub(crate) fn into_value(self) -> Value {
        self.value
    }

    /// Call only after validating `value()` against Prefab. The two arrays can
    /// occur in either source-key order; each expected location must appear
    /// exactly once, while an unexpected or duplicate capture fails closed.
    pub(crate) fn validate_exact<E>(
        &self,
        checkpoint: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<(), RawPrefabExactError<E>> {
        let unavailable = || RawPrefabExactError::CaptureUnavailable;
        if self.capture.invalid.get()
            || self.capture.cursor.get() != self.capture.spans.borrow().len()
        {
            return Err(unavailable());
        }
        let resources = self
            .value
            .get("resources")
            .and_then(Value::as_array)
            .ok_or_else(unavailable)?;
        let nodes = self
            .value
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or_else(unavailable)?;
        if resources
            .len()
            .checked_add(nodes.len())
            .is_none_or(|count| count > self.capture.maximum)
        {
            return Err(unavailable());
        }
        let candidates = self.capture.candidates.borrow();
        let mut resource_candidates: Vec<Option<&RawCandidate>> = Vec::new();
        let mut geometry_candidates: Vec<Option<&RawCandidate>> = Vec::new();
        resource_candidates
            .try_reserve_exact(resources.len())
            .map_err(|_| unavailable())?;
        geometry_candidates
            .try_reserve_exact(nodes.len())
            .map_err(|_| unavailable())?;
        resource_candidates.resize(resources.len(), None);
        geometry_candidates.resize(nodes.len(), None);
        for (index, candidate) in candidates.iter().enumerate() {
            if index % 128 == 0 {
                checkpoint().map_err(RawPrefabExactError::Control)?;
            }
            let slot = match candidate.prefab {
                Some(PrefabExactLocation::Resource(index)) => resource_candidates.get_mut(index),
                Some(PrefabExactLocation::Geometry(index)) => geometry_candidates.get_mut(index),
                None => None,
            }
            .ok_or_else(unavailable)?;
            if slot.replace(candidate).is_some() {
                return Err(unavailable());
            }
        }
        for (index, candidate) in resource_candidates.into_iter().enumerate() {
            if index % 128 == 0 {
                checkpoint().map_err(RawPrefabExactError::Control)?;
            }
            self.validate_candidate(candidate.ok_or_else(unavailable)?, checkpoint)?;
        }
        for (index, (node, candidate)) in nodes.iter().zip(geometry_candidates).enumerate() {
            if index % 128 == 0 {
                checkpoint().map_err(RawPrefabExactError::Control)?;
            }
            match (node.get("geometryResource"), candidate) {
                (Some(_), Some(candidate)) => self.validate_candidate(candidate, checkpoint)?,
                (None, None) => (),
                _ => return Err(unavailable()),
            }
        }
        Ok(())
    }

    fn validate_candidate<E>(
        &self,
        candidate: &RawCandidate,
        checkpoint: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<(), RawPrefabExactError<E>> {
        let unavailable = || RawPrefabExactError::CaptureUnavailable;
        let location = candidate.prefab.ok_or_else(unavailable)?;
        let token = self
            .bytes
            .get(candidate.span.clone())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .ok_or_else(unavailable)?;
        if crate::number::exact_safe_u64_json_lexeme_with_control(token, checkpoint)
            .map_err(RawPrefabExactError::Control)?
            .is_none()
        {
            return Err(RawPrefabExactError::ExactInteger { location });
        }
        Ok(())
    }
}

/// A Selection capture belongs to its complete original bytes and strict parse.
/// No caller can construct or transfer its internal capture independently.
pub(crate) struct RawSelectionExactParsed<'a> {
    bytes: &'a [u8],
    value: Value,
    capture: RawCapture,
}

#[derive(Debug)]
pub(crate) enum RawSelectionExactError<E> {
    CaptureUnavailable,
    ExactInteger { location: SelectionExactLocation },
    Control(E),
}

struct SelectionCandidateSlots<'a> {
    resources: Vec<Option<&'a RawCandidate>>,
    geometry: Vec<Option<&'a RawCandidate>>,
}

impl RawSelectionExactParsed<'_> {
    pub(crate) fn value(&self) -> &Value {
        &self.value
    }

    pub(crate) fn into_value(self) -> Value {
        self.value
    }

    /// Call after validating the whole Value as SceneSelectionSnapshot.
    /// Field order is immaterial; every selected array location must match
    /// exactly one candidate from this parse and this byte slice.
    pub(crate) fn validate_exact<E>(
        &self,
        checkpoint: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<(), RawSelectionExactError<E>> {
        let unavailable = || RawSelectionExactError::CaptureUnavailable;
        if self.capture.invalid.get()
            || self.capture.cursor.get() != self.capture.spans.borrow().len()
        {
            return Err(unavailable());
        }
        let prefabs = self
            .value
            .get("prefabs")
            .and_then(Value::as_array)
            .ok_or_else(unavailable)?;
        if prefabs.len() > self.capture.maximum {
            return Err(unavailable());
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(prefabs.len())
            .map_err(|_| unavailable())?;
        let mut total = 0_usize;
        for (index, prefab) in prefabs.iter().enumerate() {
            if index % 128 == 0 {
                checkpoint().map_err(RawSelectionExactError::Control)?;
            }
            let resources = prefab
                .get("resources")
                .and_then(Value::as_array)
                .ok_or_else(unavailable)?;
            let nodes = prefab
                .get("nodes")
                .and_then(Value::as_array)
                .ok_or_else(unavailable)?;
            total = total
                .checked_add(resources.len())
                .and_then(|n| n.checked_add(nodes.len()))
                .ok_or_else(unavailable)?;
            if total > self.capture.maximum {
                return Err(unavailable());
            }
            let mut resource_slots = Vec::new();
            let mut geometry_slots = Vec::new();
            resource_slots
                .try_reserve_exact(resources.len())
                .map_err(|_| unavailable())?;
            geometry_slots
                .try_reserve_exact(nodes.len())
                .map_err(|_| unavailable())?;
            resource_slots.resize(resources.len(), None);
            geometry_slots.resize(nodes.len(), None);
            slots.push(SelectionCandidateSlots {
                resources: resource_slots,
                geometry: geometry_slots,
            });
        }
        let candidates = self.capture.candidates.borrow();
        for (index, candidate) in candidates.iter().enumerate() {
            if index % 128 == 0 {
                checkpoint().map_err(RawSelectionExactError::Control)?;
            }
            let location = candidate.selection.ok_or_else(unavailable)?;
            let prefab = slots.get_mut(location.prefab).ok_or_else(unavailable)?;
            let slot = match location.location {
                PrefabExactLocation::Resource(index) => prefab.resources.get_mut(index),
                PrefabExactLocation::Geometry(index) => prefab.geometry.get_mut(index),
            }
            .ok_or_else(unavailable)?;
            if slot.replace(candidate).is_some() {
                return Err(unavailable());
            }
        }
        for (prefab_index, (prefab, slots)) in prefabs.iter().zip(slots).enumerate() {
            if prefab_index % 128 == 0 {
                checkpoint().map_err(RawSelectionExactError::Control)?;
            }
            for (index, candidate) in slots.resources.into_iter().enumerate() {
                if index % 128 == 0 {
                    checkpoint().map_err(RawSelectionExactError::Control)?;
                }
                self.validate_candidate(candidate.ok_or_else(unavailable)?, checkpoint)?;
            }
            let nodes = prefab
                .get("nodes")
                .and_then(Value::as_array)
                .ok_or_else(unavailable)?;
            for (index, (node, candidate)) in nodes.iter().zip(slots.geometry).enumerate() {
                if index % 128 == 0 {
                    checkpoint().map_err(RawSelectionExactError::Control)?;
                }
                match (node.get("geometryResource"), candidate) {
                    (Some(_), Some(candidate)) => self.validate_candidate(candidate, checkpoint)?,
                    (None, None) => (),
                    _ => return Err(unavailable()),
                }
            }
        }
        Ok(())
    }

    fn validate_candidate<E>(
        &self,
        candidate: &RawCandidate,
        checkpoint: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<(), RawSelectionExactError<E>> {
        let unavailable = || RawSelectionExactError::CaptureUnavailable;
        let location = candidate.selection.ok_or_else(unavailable)?;
        let token = self
            .bytes
            .get(candidate.span.clone())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .ok_or_else(unavailable)?;
        if crate::number::exact_safe_u64_json_lexeme_with_control(token, checkpoint)
            .map_err(RawSelectionExactError::Control)?
            .is_none()
        {
            return Err(RawSelectionExactError::ExactInteger { location });
        }
        Ok(())
    }
}

pub(crate) fn parse_selection_json_with_exact_capture<E>(
    bytes: &[u8],
    limits: JsonLimits,
    checkpoint: impl FnMut() -> Result<(), E>,
) -> Result<RawSelectionExactParsed<'_>, ControlledJsonError<E>> {
    let control = ParseControl {
        checkpoint: RefCell::new(checkpoint),
        failure: RefCell::new(None),
    };
    let capture = RawCapture::new(limits, bytes.len());
    let result = parse_json_controlled(
        bytes,
        limits,
        &control,
        Some(&capture),
        RawPath::SelectionRoot,
    );
    match control.failure.into_inner() {
        Some(error) => Err(ControlledJsonError::Control(error)),
        None => result
            .map(|value| RawSelectionExactParsed {
                bytes,
                value,
                capture,
            })
            .map_err(ControlledJsonError::Json),
    }
}

pub(crate) fn parse_prefab_json_with_exact_capture<E>(
    bytes: &[u8],
    limits: JsonLimits,
    checkpoint: impl FnMut() -> Result<(), E>,
) -> Result<RawPrefabExactParsed<'_>, ControlledJsonError<E>> {
    let control = ParseControl {
        checkpoint: RefCell::new(checkpoint),
        failure: RefCell::new(None),
    };
    let capture = RawCapture::new(limits, bytes.len());
    let result =
        parse_json_controlled(bytes, limits, &control, Some(&capture), RawPath::PrefabRoot);
    match control.failure.into_inner() {
        Some(error) => Err(ControlledJsonError::Control(error)),
        None => result
            .map(|value| RawPrefabExactParsed {
                bytes,
                value,
                capture,
            })
            .map_err(ControlledJsonError::Json),
    }
}

pub(crate) fn parse_json_with_exact_capture<E>(
    bytes: &[u8],
    limits: JsonLimits,
    selector: ExactSelector,
    checkpoint: impl FnMut() -> Result<(), E>,
) -> Result<RawExactParsed<'_>, ControlledJsonError<E>> {
    let control = ParseControl {
        checkpoint: RefCell::new(checkpoint),
        failure: RefCell::new(None),
    };
    let capture = RawCapture::new(limits, bytes.len());
    let path = match selector {
        ExactSelector::ResourceRef => RawPath::ResourceRoot,
        ExactSelector::PhysicsDefinition => RawPath::PhysicsRoot,
    };
    let result = parse_json_controlled(bytes, limits, &control, Some(&capture), path);
    match control.failure.into_inner() {
        Some(error) => Err(ControlledJsonError::Control(error)),
        None => result
            .map(|value| RawExactParsed {
                bytes,
                value,
                selector,
                capture,
            })
            .map_err(ControlledJsonError::Json),
    }
}

pub fn parse_json(bytes: &[u8]) -> Result<Value, JsonError> {
    parse_json_with_limits(bytes, JsonLimits::default())
}

/// Encode validated values for wire or durable DTO storage. Digest calculation
/// uses JCS separately: its shortest float output is not a decimal-type tag.
/// serde_json retains an integral f64's fractional/exponent spelling, allowing
/// the strict boundary to distinguish it from a prohibited large integer token.
pub fn encode_json(value: &Value) -> Result<Vec<u8>, JsonError> {
    let limits = JsonLimits::default();
    check_value(value, limits)?;
    let mut writer = LimitedJsonWriter::new(limits.max_bytes);
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.into_bytes())
}

pub(crate) struct LimitedJsonWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl LimitedJsonWriter {
    pub(crate) fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum.min(128)),
            maximum,
        }
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for LimitedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self.bytes.len().checked_add(bytes.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Encoded JSON byte budget exceeded",
            )
        })?;
        if length > self.maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Encoded JSON byte budget exceeded",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn parse_json_with_limits(bytes: &[u8], limits: JsonLimits) -> Result<Value, JsonError> {
    match parse_json_with_control(bytes, limits, || Ok::<(), Infallible>(())) {
        Ok(value) => Ok(value),
        Err(ControlledJsonError::Json(error)) => Err(error),
        Err(ControlledJsonError::Control(error)) => match error {},
    }
}

/// Cooperatively check a caller's budget during the raw integer prepass and
/// before every serde value and collection advance. A checkpoint failure keeps
/// its original type and stops further checkpoints and parsing.
///
/// This is not a preemptive parser: serde can scan a single string, key, number,
/// or whitespace run between checkpoints. The byte budget bounds that work, and
/// a final checkpoint prevents a late cancellation from returning a value.
pub fn parse_json_with_control<E>(
    bytes: &[u8],
    limits: JsonLimits,
    checkpoint: impl FnMut() -> Result<(), E>,
) -> Result<Value, ControlledJsonError<E>> {
    let control = ParseControl {
        checkpoint: RefCell::new(checkpoint),
        failure: RefCell::new(None),
    };
    let result = parse_json_controlled(bytes, limits, &control, None, RawPath::Ignore);
    match control.failure.into_inner() {
        Some(error) => Err(ControlledJsonError::Control(error)),
        None => result.map_err(ControlledJsonError::Json),
    }
}

struct ParseControl<F, E> {
    checkpoint: RefCell<F>,
    failure: RefCell<Option<E>>,
}

impl<F: FnMut() -> Result<(), E>, E> ParseControl<F, E> {
    fn check(&self) -> Result<(), ()> {
        if self.failure.borrow().is_some() {
            return Err(());
        }
        match (self.checkpoint.borrow_mut())() {
            Ok(()) => Ok(()),
            Err(error) => {
                *self.failure.borrow_mut() = Some(error);
                Err(())
            }
        }
    }

    fn check_json(&self) -> Result<(), JsonError> {
        self.check()
            .map_err(|()| boundary_error("JSON parsing interrupted"))
    }

    fn check_serde<D: de::Error>(&self) -> Result<(), D> {
        self.check()
            .map_err(|()| D::custom("JSON parsing interrupted"))
    }
}

fn parse_json_controlled<F: FnMut() -> Result<(), E>, E>(
    bytes: &[u8],
    limits: JsonLimits,
    control: &ParseControl<F, E>,
    capture: Option<&RawCapture>,
    path: RawPath,
) -> Result<Value, JsonError> {
    if bytes.len() > limits.max_bytes {
        return Err(boundary_error("JSON byte budget exceeded"));
    }
    control.check_json()?;
    // Even integer tokens beyond u64 must be rejected before serde can turn them
    // into a rounded f64. Large integer contract fields use decimal strings.
    check_integer_tokens(bytes, control, capture)?;
    let nodes = Cell::new(0);
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = ValueSeed {
        limits,
        nodes: &nodes,
        depth: 0,
        control,
        capture,
        path,
    }
    .deserialize(&mut deserializer)?;
    deserializer.end()?;
    control.check_json()?;
    Ok(value)
}

fn check_integer_tokens<F: FnMut() -> Result<(), E>, E>(
    bytes: &[u8],
    control: &ParseControl<F, E>,
    capture: Option<&RawCapture>,
) -> Result<(), JsonError> {
    let mut index = 0;
    let mut next_checkpoint = CONTROL_BYTE_INTERVAL;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if index >= next_checkpoint {
            control.check_json()?;
            next_checkpoint = index.saturating_add(CONTROL_BYTE_INTERVAL);
        }
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            let mut has_decimal = false;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_digit()
                    || matches!(bytes[index], b'.' | b'e' | b'E' | b'+' | b'-'))
            {
                if index >= next_checkpoint {
                    control.check_json()?;
                    next_checkpoint = index.saturating_add(CONTROL_BYTE_INTERVAL);
                }
                has_decimal |= matches!(bytes[index], b'.' | b'e' | b'E');
                index += 1;
            }
            let token = &bytes[start..index];
            if let Some(capture) = capture {
                capture.add_span(start..index);
            }
            if !has_decimal {
                let digits = token.strip_prefix(b"-").unwrap_or(token);
                let maximum = b"9007199254740991";
                if digits.len() > maximum.len()
                    || (digits.len() == maximum.len() && digits > maximum.as_slice())
                {
                    return Err(boundary_error(
                        "Unsafe JSON integer; use a canonical decimal string",
                    ));
                }
            }
            continue;
        }
        index += 1;
    }
    Ok(())
}

struct ValueSeed<'a, F, E> {
    limits: JsonLimits,
    nodes: &'a Cell<usize>,
    depth: usize,
    control: &'a ParseControl<F, E>,
    capture: Option<&'a RawCapture>,
    path: RawPath,
}

impl<'de, F: FnMut() -> Result<(), E>, E> DeserializeSeed<'de> for ValueSeed<'_, F, E> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        self.control.check_serde::<D::Error>()?;
        if self.depth > self.limits.max_depth {
            return Err(de::Error::custom("JSON nesting budget exceeded"));
        }
        let count = self
            .nodes
            .get()
            .checked_add(1)
            .ok_or_else(|| de::Error::custom("JSON node budget exceeded"))?;
        if count > self.limits.max_nodes {
            return Err(de::Error::custom("JSON node budget exceeded"));
        }
        self.nodes.set(count);
        deserializer.deserialize_any(ValueVisitor(self))
    }
}

struct ValueVisitor<'a, F, E>(ValueSeed<'a, F, E>);

impl<F, E> ValueVisitor<'_, F, E> {
    fn child(&self, path: RawPath) -> ValueSeed<'_, F, E> {
        ValueSeed {
            limits: self.0.limits,
            nodes: self.0.nodes,
            depth: self.0.depth + 1,
            control: self.0.control,
            capture: self.0.capture,
            path,
        }
    }
}

impl<'de, F: FnMut() -> Result<(), E>, E> Visitor<'de> for ValueVisitor<'_, F, E> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict finite JSON")
    }

    fn visit_bool<D: de::Error>(self, value: bool) -> Result<Value, D> {
        Ok(Value::Bool(value))
    }

    fn visit_unit<D: de::Error>(self) -> Result<Value, D> {
        Ok(Value::Null)
    }

    fn visit_i64<D: de::Error>(self, value: i64) -> Result<Value, D> {
        if let Some(capture) = self.0.capture {
            capture.consume(self.0.path);
        }
        if value.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(D::custom(
                "Unsafe JSON integer; use a canonical decimal string",
            ));
        }
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<D: de::Error>(self, value: u64) -> Result<Value, D> {
        if let Some(capture) = self.0.capture {
            capture.consume(self.0.path);
        }
        if value > MAX_SAFE_INTEGER {
            return Err(D::custom(
                "Unsafe JSON integer; use a canonical decimal string",
            ));
        }
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<D: de::Error>(self, value: f64) -> Result<Value, D> {
        if let Some(capture) = self.0.capture {
            capture.consume(self.0.path);
        }
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| D::custom("Non-finite JSON number"))
    }

    fn visit_str<D: de::Error>(self, value: &str) -> Result<Value, D> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<D: de::Error>(self, value: String) -> Result<Value, D> {
        Ok(Value::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut array = Vec::new();
        loop {
            self.0.control.check_serde::<A::Error>()?;
            let Some(value) =
                access.next_element_seed(self.child(self.0.path.array_child(array.len())))?
            else {
                break;
            };
            array.push(value);
        }
        Ok(Value::Array(array))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        loop {
            self.0.control.check_serde::<A::Error>()?;
            let Some(key) = access.next_key::<String>()? else {
                break;
            };
            if object.contains_key(&key) {
                return Err(de::Error::custom("Duplicate JSON object key"));
            }
            let value = access.next_value_seed(self.child(self.0.path.map_child(&key)))?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

/// Check already constructed values before hashing or validating them. The JSON
/// parser performs the same checks before values can enter the boundary.
pub(crate) fn check_value(value: &Value, limits: JsonLimits) -> Result<(), JsonError> {
    let mut pending = vec![(value, 0usize)];
    let mut nodes = 0usize;
    let mut bytes = 0usize;
    while let Some((value, depth)) = pending.pop() {
        nodes = nodes
            .checked_add(1)
            .ok_or_else(|| boundary_error("JSON node budget exceeded"))?;
        if nodes > limits.max_nodes || depth > limits.max_depth {
            return Err(boundary_error("JSON node or nesting budget exceeded"));
        }
        bytes = bytes
            .checked_add(1)
            .ok_or_else(|| boundary_error("JSON byte budget exceeded"))?;
        match value {
            Value::Number(number) => {
                if number
                    .as_i64()
                    .is_some_and(|value| value.unsigned_abs() > MAX_SAFE_INTEGER)
                    || number
                        .as_u64()
                        .is_some_and(|value| value > MAX_SAFE_INTEGER)
                    || number.as_f64().is_none_or(|value| !value.is_finite())
                {
                    return Err(boundary_error("Number is outside the finite JSON contract"));
                }
            }
            Value::String(string) => {
                bytes = bytes
                    .checked_add(string.len())
                    .ok_or_else(|| boundary_error("JSON byte budget exceeded"))?;
            }
            Value::Array(array) => pending.extend(array.iter().map(|value| (value, depth + 1))),
            Value::Object(object) => {
                for (key, value) in object {
                    bytes = bytes
                        .checked_add(key.len())
                        .ok_or_else(|| boundary_error("JSON byte budget exceeded"))?;
                    pending.push((value, depth + 1));
                }
            }
            Value::Bool(_) | Value::Null => {}
        }
        if bytes > limits.max_bytes {
            return Err(boundary_error("JSON byte budget exceeded"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_are_rejected_at_every_depth() {
        for bytes in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"[{"a":1,"\u0061":2}]"#.as_slice(),
        ] {
            assert!(parse_json(bytes).is_err());
        }
    }

    #[test]
    fn invalid_unicode_and_nonfinite_input_are_rejected() {
        for bytes in [
            br#""\ud800""#.as_slice(),
            br#""\udfff""#.as_slice(),
            b"NaN",
            b"Infinity",
            b"1e999",
        ] {
            assert!(parse_json(bytes).is_err());
        }
        assert!(parse_json(br#""\ud83d\ude00""#).is_ok());
    }

    #[test]
    fn large_integers_never_round_into_floats() {
        for bytes in [
            b"9007199254740992".as_slice(),
            b"-9007199254740992",
            b"184467440737095516160",
        ] {
            assert!(parse_json(bytes).is_err());
        }
        assert!(parse_json(b"9007199254740991").is_ok());
        assert!(parse_json(br#""184467440737095516160""#).is_ok());
        assert!(parse_json(b"1e30").is_ok());
    }

    #[test]
    fn bounded_inputs_and_trailing_data_fail() {
        let limits = JsonLimits {
            max_bytes: 16,
            max_depth: 1,
            max_nodes: 3,
        };
        assert!(parse_json_with_limits(b"[[]]", limits).is_ok());
        assert!(parse_json_with_limits(b"[[[0]]]", limits).is_err());
        assert!(parse_json_with_limits(b"[0,1,2]", limits).is_err());
        assert!(parse_json(b"null true").is_err());
    }

    #[test]
    fn cancellation_preserves_the_original_error_in_each_parse_phase() {
        // Existing syntax fixtures cannot cancel a running parse. These small
        // authored inputs cover the raw prepass, nodes and collection advances.
        #[derive(Debug)]
        struct Cancelled {
            at_checkpoint: usize,
            identity: Box<u8>,
        }

        let long_string = format!("\"{}\"", "x".repeat(CONTROL_BYTE_INTERVAL * 2));
        let long_integer = "7".repeat(CONTROL_BYTE_INTERVAL * 2);
        let collection = br#"[{"a":[1,2],"b":3}]"#;
        for (bytes, cancel_at) in [
            (long_string.as_bytes(), 2),
            (long_integer.as_bytes(), 2),
            (collection.as_slice(), 2),
            (collection.as_slice(), 3),
            (collection.as_slice(), 5),
            (collection.as_slice(), 7),
            (collection.as_slice(), 8),
        ] {
            let identity = Box::new(7);
            let pointer = identity.as_ref() as *const u8;
            let mut error = Some(Cancelled {
                at_checkpoint: cancel_at,
                identity,
            });
            let mut calls = 0;
            let result = parse_json_with_control(bytes, JsonLimits::default(), || {
                calls += 1;
                if calls == cancel_at {
                    Err(error.take().unwrap())
                } else {
                    Ok(())
                }
            });
            let Err(ControlledJsonError::Control(error)) = result else {
                panic!("Checkpoint failure must retain its original error");
            };
            assert_eq!(error.at_checkpoint, cancel_at);
            assert_eq!(error.identity.as_ref() as *const u8, pointer);
            assert_eq!(calls, cancel_at);
        }
    }

    #[test]
    fn controlled_parser_keeps_strict_limits_and_final_checkpoint() {
        let limits = JsonLimits {
            max_bytes: 32,
            max_depth: 1,
            max_nodes: 3,
        };
        for bytes in [
            br#"{"a":1,"a":2}"#.as_slice(),
            b"9007199254740992",
            b"[[[0]]]",
            b"[0,1,2]",
            b"null true",
            b"                                 null",
        ] {
            assert!(matches!(
                parse_json_with_control(bytes, limits, || Ok::<(), Infallible>(())),
                Err(ControlledJsonError::Json(_))
            ));
        }
        assert_eq!(
            parse_json_with_control(b"[[]]", limits, || Ok::<(), Infallible>(())).unwrap(),
            parse_json_with_limits(b"[[]]", limits).unwrap()
        );

        let mut calls = 0;
        assert_eq!(
            parse_json_with_control(b"null", limits, || {
                calls += 1;
                if calls == 3 { Err("deadline") } else { Ok(()) }
            }),
            Err(ControlledJsonError::Control("deadline"))
        );
        assert_eq!(calls, 3);
    }

    #[test]
    fn wire_encoding_retains_explicit_float_spelling() {
        let value = parse_json(b"[9007199254740992.0,295147905179352830000.0,1e30]").unwrap();
        assert_eq!(parse_json(&encode_json(&value).unwrap()).unwrap(), value);
    }

    #[test]
    fn raw_capture_follows_decoded_keys_and_number_visit_order() {
        let input =
            br#"{"other":[1,2.5],"\u0073izeBytes":1.0,"nested":{"sizeBytes":1.0000000000000001}}"#;
        let mut old_checks = 0;
        let old = parse_json_with_control(input, JsonLimits::default(), || {
            old_checks += 1;
            Ok::<(), Infallible>(())
        })
        .unwrap();
        let mut raw_checks = 0;
        let parsed = parse_json_with_exact_capture(
            input,
            JsonLimits::default(),
            ExactSelector::ResourceRef,
            || {
                raw_checks += 1;
                Ok::<(), Infallible>(())
            },
        )
        .unwrap();
        assert_eq!(&old, parsed.value());
        assert_eq!(
            old_checks, raw_checks,
            "capture must not change strict parse checkpoints"
        );
        parsed
            .validate_exact(&mut || Ok::<(), Infallible>(()))
            .unwrap();

        let input = br#"{"other":1,"sizeBytes":1.0000000000000001}"#;
        let parsed = parse_json_with_exact_capture(
            input,
            JsonLimits::default(),
            ExactSelector::ResourceRef,
            || Ok::<(), Infallible>(()),
        )
        .unwrap();
        assert!(matches!(
            parsed.validate_exact(&mut || Ok::<(), Infallible>(())),
            Err(RawExactError::ExactInteger { collider: None })
        ));
    }

    #[test]
    fn prefab_capture_rejects_missing_duplicate_and_unexpected_locations() {
        // Exercise impossible capture inconsistencies directly. The public
        // wrapper additionally performs Prefab schema validation first.
        let bytes =
            br#"{"nodes":[{"geometryResource":{"sizeBytes":2}}],"resources":[{"sizeBytes":1}]}"#;
        let parsed = parse_prefab_json_with_exact_capture(bytes, JsonLimits::default(), || {
            Ok::<(), Infallible>(())
        })
        .unwrap();
        parsed
            .validate_exact(&mut || Ok::<(), Infallible>(()))
            .unwrap();

        for fault in 0..3 {
            let parsed = parse_prefab_json_with_exact_capture(bytes, JsonLimits::default(), || {
                Ok::<(), Infallible>(())
            })
            .unwrap();
            {
                let mut candidates = parsed.capture.candidates.borrow_mut();
                match fault {
                    0 => {
                        assert!(candidates.pop().is_some());
                    }
                    1 => {
                        let duplicate = RawCandidate {
                            collider: candidates[0].collider,
                            prefab: candidates[0].prefab,
                            selection: candidates[0].selection,
                            span: candidates[0].span.clone(),
                        };
                        candidates.push(duplicate);
                    }
                    _ => candidates[0].prefab = Some(PrefabExactLocation::Geometry(1)),
                }
            }
            assert!(matches!(
                parsed.validate_exact(&mut || Ok::<(), Infallible>(())),
                Err(RawPrefabExactError::CaptureUnavailable)
            ));
        }
    }

    #[test]
    fn selection_capture_rejects_missing_duplicate_and_unexpected_locations() {
        // Minimal shapes exercise the private capture only; the public wrapper
        // must validate the complete Selection schema before this method.
        let bytes = br#"{"prefabs":[{"nodes":[{"geometryResource":{"sizeBytes":2e0}},{}],"resources":[{"sizeBytes":1.0}]},{"resources":[],"nodes":[]}]}"#;
        let parsed = parse_selection_json_with_exact_capture(bytes, JsonLimits::default(), || {
            Ok::<(), Infallible>(())
        })
        .unwrap();
        parsed
            .validate_exact(&mut || Ok::<(), Infallible>(()))
            .unwrap();

        for fault in 0..5 {
            let parsed =
                parse_selection_json_with_exact_capture(bytes, JsonLimits::default(), || {
                    Ok::<(), Infallible>(())
                })
                .unwrap();
            {
                let mut candidates = parsed.capture.candidates.borrow_mut();
                match fault {
                    0 => assert!(candidates.pop().is_some()),
                    1 => {
                        let duplicate = RawCandidate {
                            collider: candidates[0].collider,
                            prefab: candidates[0].prefab,
                            selection: candidates[0].selection,
                            span: candidates[0].span.clone(),
                        };
                        candidates.push(duplicate);
                    }
                    2 => candidates[0].selection.as_mut().unwrap().prefab = 2,
                    3 => {
                        candidates[0].selection.as_mut().unwrap().location =
                            PrefabExactLocation::Geometry(1)
                    }
                    _ => candidates[0].selection = None,
                }
            }
            assert!(matches!(
                parsed.validate_exact(&mut || Ok::<(), Infallible>(())),
                Err(RawSelectionExactError::CaptureUnavailable)
            ));
        }

        let empty = parse_selection_json_with_exact_capture(
            br#"{"prefabs":[]}"#,
            JsonLimits::default(),
            || Ok::<(), Infallible>(()),
        )
        .unwrap();
        empty
            .validate_exact(&mut || Ok::<(), Infallible>(()))
            .unwrap();
    }

    #[test]
    fn raw_capture_defers_overflow_until_after_original_parse_errors() {
        let limits = JsonLimits {
            max_bytes: 256,
            max_depth: 8,
            max_nodes: 2,
        };
        for input in [
            br#"{"a":1,"a":2}"#.as_slice(),
            b"[1,2,3]",
            b"[1,2] trailing",
        ] {
            let ordinary = parse_json_with_control(input, limits, || Ok::<(), Infallible>(()));
            let captured =
                parse_json_with_exact_capture(input, limits, ExactSelector::ResourceRef, || {
                    Ok::<(), Infallible>(())
                });
            let Err(ControlledJsonError::Json(expected)) = ordinary else {
                panic!("ordinary strict parse must fail");
            };
            let Err(ControlledJsonError::Json(actual)) = captured else {
                panic!("capture must preserve strict failure");
            };
            assert_eq!(actual, expected);
        }
    }
}

//! Parse before schema validation: duplicate keys must never be overwritten.

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::{
    cell::{Cell, RefCell},
    convert::Infallible,
    error::Error,
    fmt,
    io::{self, Write},
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
    let result = parse_json_controlled(bytes, limits, &control);
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
) -> Result<Value, JsonError> {
    if bytes.len() > limits.max_bytes {
        return Err(boundary_error("JSON byte budget exceeded"));
    }
    control.check_json()?;
    // Even integer tokens beyond u64 must be rejected before serde can turn them
    // into a rounded f64. Large integer contract fields use decimal strings.
    check_integer_tokens(bytes, control)?;
    let nodes = Cell::new(0);
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = ValueSeed {
        limits,
        nodes: &nodes,
        depth: 0,
        control,
    }
    .deserialize(&mut deserializer)?;
    deserializer.end()?;
    control.check_json()?;
    Ok(value)
}

fn check_integer_tokens<F: FnMut() -> Result<(), E>, E>(
    bytes: &[u8],
    control: &ParseControl<F, E>,
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
    fn child(&self) -> ValueSeed<'_, F, E> {
        ValueSeed {
            limits: self.0.limits,
            nodes: self.0.nodes,
            depth: self.0.depth + 1,
            control: self.0.control,
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
        if value.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(D::custom(
                "Unsafe JSON integer; use a canonical decimal string",
            ));
        }
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<D: de::Error>(self, value: u64) -> Result<Value, D> {
        if value > MAX_SAFE_INTEGER {
            return Err(D::custom(
                "Unsafe JSON integer; use a canonical decimal string",
            ));
        }
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<D: de::Error>(self, value: f64) -> Result<Value, D> {
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
            let Some(value) = access.next_element_seed(self.child())? else {
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
            let value = access.next_value_seed(self.child())?;
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
}

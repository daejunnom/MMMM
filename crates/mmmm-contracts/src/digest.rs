//! RFC 8785 and raw-byte digests have separate entry points. Projection removes
//! only the listed fields from the root object, never nested revisions.

use crate::{
    DIGEST_PROJECTIONS, Sha256Digest,
    strict_json::{JsonLimits, LimitedJsonWriter, check_value, parse_json},
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, error::Error, fmt, sync::OnceLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestError {
    InvalidValue(String),
    InvalidProjection(String),
    UnknownProjection(String),
    ExpectedObject,
    MissingDigestField(String),
    DigestMismatch {
        expected: Sha256Digest,
        actual: Sha256Digest,
    },
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue(message) => write!(f, "Invalid canonical JSON: {message}"),
            Self::InvalidProjection(message) => {
                write!(f, "Invalid digest projection contract: {message}")
            }
            Self::UnknownProjection(name) => {
                write!(f, "No digest projection registered for {name}")
            }
            Self::ExpectedObject => f.write_str("A projected digest requires an object"),
            Self::MissingDigestField(name) => write!(f, "Missing digest field {name}"),
            Self::DigestMismatch { expected, actual } => {
                write!(f, "Digest mismatch: expected {expected}, actual {actual}")
            }
        }
    }
}

impl Error for DigestError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProjectionContract {
    contract_version: String,
    algorithm: String,
    exclude_top_level_fields: BTreeMap<String, Vec<String>>,
    raw_artifacts: String,
    notes: String,
}

fn projections() -> Result<&'static BTreeMap<String, Vec<String>>, DigestError> {
    static PROJECTIONS: OnceLock<Result<BTreeMap<String, Vec<String>>, DigestError>> =
        OnceLock::new();
    PROJECTIONS
        .get_or_init(|| {
            let value = parse_json(DIGEST_PROJECTIONS)
                .map_err(|error| DigestError::InvalidProjection(error.to_string()))?;
            let contract: ProjectionContract = serde_json::from_value(value)
                .map_err(|error| DigestError::InvalidProjection(error.to_string()))?;
            if contract.contract_version != crate::CONTRACT_VERSION
                || contract.algorithm != "RFC8785+SHA256"
                || contract.raw_artifacts != "sha256(original_bytes)"
                || contract.notes.is_empty()
                || contract.exclude_top_level_fields.values().any(|fields| {
                    fields
                        .iter()
                        .any(|field| field.is_empty() || field.contains('/'))
                        || fields
                            .iter()
                            .collect::<std::collections::BTreeSet<_>>()
                            .len()
                            != fields.len()
                })
            {
                return Err(DigestError::InvalidProjection(
                    "Unsupported or malformed projection contract".into(),
                ));
            }
            Ok(contract.exclude_top_level_fields)
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Digest original bytes, without decoding or normalizing text.
pub fn raw_digest(bytes: &[u8]) -> Sha256Digest {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    Sha256Digest::from_bytes(digest)
}

/// Canonicalize a JSON value which has already crossed the strict parser or was
/// constructed internally. Strings are preserved without Unicode normalization.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, DigestError> {
    check_value(value, JsonLimits::default())
        .map_err(|error| DigestError::InvalidValue(error.to_string()))?;
    let mut writer = LimitedJsonWriter::new(JsonLimits::default().max_bytes);
    serde_jcs::to_writer(&mut writer, value)
        .map_err(|error| DigestError::InvalidValue(error.to_string()))?;
    Ok(writer.into_bytes())
}

pub fn canonical_digest(value: &Value) -> Result<Sha256Digest, DigestError> {
    Ok(raw_digest(&canonical_bytes(value)?))
}

pub fn projected_digest(definition: &str, value: &Value) -> Result<Sha256Digest, DigestError> {
    check_value(value, JsonLimits::default())
        .map_err(|error| DigestError::InvalidValue(error.to_string()))?;
    let fields = projections()?
        .get(definition)
        .ok_or_else(|| DigestError::UnknownProjection(definition.to_owned()))?;
    let mut projected = value
        .as_object()
        .ok_or(DigestError::ExpectedObject)?
        .clone();
    for field in fields {
        projected.remove(field);
    }
    canonical_digest(&Value::Object(projected))
}

/// Verify an existing self-digest. Types with an empty exclusion list have no
/// self-digest field and can be pinned using `projected_digest` directly.
pub fn verify_projected_digest(
    definition: &str,
    value: &Value,
) -> Result<Sha256Digest, DigestError> {
    let fields = projections()?
        .get(definition)
        .ok_or_else(|| DigestError::UnknownProjection(definition.to_owned()))?;
    if fields.len() != 1 {
        return Err(DigestError::InvalidProjection(
            "Type has no single self-digest field".into(),
        ));
    }
    let field = &fields[0];
    let expected = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| DigestError::MissingDigestField(field.clone()))?
        .parse::<Sha256Digest>()
        .map_err(|error| DigestError::InvalidValue(error.to_string()))?;
    let actual = projected_digest(definition, value)?;
    if actual != expected {
        return Err(DigestError::DigestMismatch { expected, actual });
    }
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn projection_never_removes_nested_revision() {
        let a = json!({"revision":"ignored", "nested":{"revision":"retained"}});
        let b = json!({"revision":"other", "nested":{"revision":"retained"}});
        let c = json!({"revision":"other", "nested":{"revision":"changed"}});
        assert_eq!(
            projected_digest("Project", &a).unwrap(),
            projected_digest("Project", &b).unwrap()
        );
        assert_ne!(
            projected_digest("Project", &b).unwrap(),
            projected_digest("Project", &c).unwrap()
        );
        assert!(projected_digest("Unknown", &a).is_err());
    }

    #[test]
    fn utf16_order_and_ecmascript_number_boundaries() {
        let value = json!({"\u{fb33}":0,"😀":0,"€":0,"1":0,"\r":0,"\u{80}":0,"ö":0});
        assert_eq!(
            String::from_utf8(canonical_bytes(&value).unwrap()).unwrap(),
            "{\"\\r\":0,\"1\":0,\"\u{80}\":0,\"ö\":0,\"€\":0,\"😀\":0,\"\u{fb33}\":0}"
        );
        let value = parse_json(b"[-0.0,1e30,1e-7,1e-6,333333333.33333329]").unwrap();
        assert_eq!(
            canonical_bytes(&value).unwrap(),
            b"[0,1e+30,1e-7,0.000001,333333333.3333333]"
        );
    }

    #[test]
    fn raw_artifact_digest_preserves_bytes() {
        assert_ne!(raw_digest(b"{}\n"), raw_digest(b"{}\r\n"));
        assert_eq!(
            raw_digest(b"abc").as_str(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn escaped_output_cannot_exceed_the_byte_budget() {
        let value = Value::String("\0".repeat(1_500_000));
        assert!(canonical_bytes(&value).is_err());
        assert!(crate::encode_json(&value).is_err());
    }

    #[test]
    fn rfc8785_appendix_b_ieee754_vectors() {
        // RFC 8785 Appendix B provides independent serialization expectations,
        // including the notation thresholds absent from the handoff examples.
        let samples = [
            (0x0000000000000000, "0"),
            (0x8000000000000000, "0"),
            (0x0000000000000001, "5e-324"),
            (0x8000000000000001, "-5e-324"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
            (0xffefffffffffffff, "-1.7976931348623157e+308"),
            (0x4340000000000000, "9007199254740992"),
            (0xc340000000000000, "-9007199254740992"),
            (0x4430000000000000, "295147905179352830000"),
            (0x44b52d02c7e14af5, "9.999999999999997e+22"),
            (0x44b52d02c7e14af6, "1e+23"),
            (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
            (0x444b1ae4d6e2ef4e, "999999999999999700000"),
            (0x444b1ae4d6e2ef4f, "999999999999999900000"),
            (0x444b1ae4d6e2ef50, "1e+21"),
            (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
            (0x3eb0c6f7a0b5ed8d, "0.000001"),
            (0x41b3de4355555553, "333333333.3333332"),
            (0x41b3de4355555554, "333333333.33333325"),
            (0x41b3de4355555555, "333333333.3333333"),
            (0x41b3de4355555556, "333333333.3333334"),
            (0x41b3de4355555557, "333333333.33333343"),
            (0xbecbf647612f3696, "-0.0000033333333333333333"),
            (0x43143ff3c1cb0959, "1424953923781206.2"),
        ];
        for (bits, expected) in samples {
            let value = Value::Number(serde_json::Number::from_f64(f64::from_bits(bits)).unwrap());
            assert_eq!(
                canonical_bytes(&value).unwrap(),
                expected.as_bytes(),
                "{bits:016x}"
            );
        }
    }

    #[test]
    fn original_digest_fixture_records_match() {
        let index = parse_json(include_bytes!("../../../tests/digest-fixtures.json")).unwrap();
        for record in index["records"].as_array().unwrap() {
            let file = record["file"].as_str().unwrap();
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples")
                .join(file);
            let value = parse_json(&std::fs::read(path).unwrap()).unwrap();
            let actual = verify_projected_digest(record["type"].as_str().unwrap(), &value).unwrap();
            assert_eq!(
                actual.as_str(),
                record["digest"].as_str().unwrap(),
                "{file}"
            );
        }
    }
}

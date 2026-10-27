//! Schema validation is a format boundary, not authorization or a claim that a
//! referenced object, world, vendor, or release evidence exists.

pub use crate::strict_json::ExactSelector;
use crate::{
    CANONICAL_SCHEMA, CANONICAL_SCHEMA_ID, CONTRACT_VERSION, FUNCTION_INDEX, RationalTime,
    strict_json::{
        ControlledJsonError, JsonError, JsonLimits, RawExactError, check_value, parse_json,
        parse_json_with_exact_capture,
    },
};
use jsonschema::{
    Draft, Keyword, PatternOptions, Registry, ValidationError, ValidationOptions, Validator,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::OnceLock,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContractViolation {
    pub code: String,
    pub instance_path: String,
    pub schema_path: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContractError {
    Json(JsonError),
    InvalidSchema(String),
    InvalidFunctionIndex(String),
    UnknownDefinition(String),
    UnknownFunction(String),
    Violations(Vec<ContractViolation>),
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => error.fmt(f),
            Self::InvalidSchema(message) => write!(f, "Invalid offline schema: {message}"),
            Self::InvalidFunctionIndex(message) => write!(f, "Invalid function index: {message}"),
            Self::UnknownDefinition(name) => write!(f, "Unknown contract definition {name}"),
            Self::UnknownFunction(name) => write!(f, "Unknown function contract {name}"),
            Self::Violations(violations) => write!(f, "{} contract violation(s)", violations.len()),
        }
    }
}

impl Error for ContractError {}

impl From<JsonError> for ContractError {
    fn from(error: JsonError) -> Self {
        Self::Json(error)
    }
}

/// Preserve a caller's original cancellation or deadline failure separately
/// from strict JSON and contract failures at the raw exact-integer boundary.
#[derive(Debug, PartialEq, Eq)]
pub enum ControlledContractError<E> {
    Contract(ContractError),
    /// A schema-valid selected size is not an exact safe JSON integer in the
    /// original bytes. None identifies a root ResourceRef; Some identifies the
    /// selected Physics collider index, without exposing the token itself.
    ExactInteger {
        collider: Option<usize>,
    },
    /// Bounded private capture could not be produced or matched to the parse.
    CaptureUnavailable,
    Control(E),
}

impl<E: fmt::Display> fmt::Display for ControlledContractError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => error.fmt(f),
            Self::ExactInteger { collider: None } => {
                f.write_str("ResourceRef sizeBytes is not an exact safe JSON integer")
            }
            Self::ExactInteger {
                collider: Some(index),
            } => {
                write!(
                    f,
                    "Physics collider {index} mesh sizeBytes is not an exact safe JSON integer"
                )
            }
            Self::CaptureUnavailable => f.write_str("Bounded raw numeric capture is unavailable"),
            Self::Control(error) => error.fmt(f),
        }
    }
}

impl<E: Error + 'static> Error for ControlledContractError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Control(error) => Some(error),
            Self::ExactInteger { .. } | Self::CaptureUnavailable => None,
        }
    }
}

fn controlled_raw_exact_error<E>(error: RawExactError<E>) -> ControlledContractError<E> {
    match error {
        RawExactError::ExactInteger { collider } => {
            ControlledContractError::ExactInteger { collider }
        }
        RawExactError::CaptureUnavailable => ControlledContractError::CaptureUnavailable,
        RawExactError::Control(error) => ControlledContractError::Control(error),
    }
}

fn controlled_contract_error<E>(error: ControlledJsonError<E>) -> ControlledContractError<E> {
    match error {
        ControlledJsonError::Json(error) => ControlledContractError::Contract(error.into()),
        ControlledJsonError::Control(error) => ControlledContractError::Control(error),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FunctionContract {
    pub id: String,
    pub name: String,
    pub input: String,
    pub output: String,
    pub effect: String,
    pub preconditions: Vec<String>,
    pub postconditions: Vec<String>,
    pub errors: Vec<String>,
    pub cancellation: String,
    pub retry: String,
    pub first_gate: String,
    pub owner: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FunctionIndex {
    version: String,
    status: String,
    functions: Vec<FunctionContract>,
}

#[derive(Clone)]
pub struct ContractValidator {
    schema: Value,
    validators: BTreeMap<String, Validator>,
    functions: Vec<FunctionContract>,
}

const REDUCED_RATIONAL_KEYWORD: &str = "mmmmReducedRational";

struct ReducedRationalKeyword;

impl<'instance> Keyword<'instance> for ReducedRationalKeyword {
    fn validate(&self, instance: &'instance Value) -> Result<(), ValidationError<'instance>> {
        serde_json::from_value::<RationalTime>(instance.clone())
            .map(|_| ())
            .map_err(|_| {
                ValidationError::custom(
                    "Rational time must have canonical strings, a positive denominator and gcd one",
                )
            })
    }

    fn is_valid(&self, instance: &'instance Value) -> bool {
        serde_json::from_value::<RationalTime>(instance.clone()).is_ok()
    }
}

fn validation_options<'a>() -> ValidationOptions<'a> {
    jsonschema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .with_pattern_options(PatternOptions::fancy_regex().backtrack_limit(20_000))
        .with_keyword(REDUCED_RATIONAL_KEYWORD, |_, value, _| {
            if value == &Value::Bool(true) {
                Ok(Box::new(ReducedRationalKeyword))
            } else {
                Err(ValidationError::schema(
                    "Reduced rational validation marker must be true",
                ))
            }
        })
        .offline()
}

fn semantic_validation_schema(canonical: &Value) -> Result<Value, ContractError> {
    // This private, transient annotation supplies the documented wire
    // arithmetic invariant; it is never exported, persisted, or a second
    // schema authority. JSON Schema selects the proper union branch itself.
    let mut schema = canonical.clone();
    schema
        .pointer_mut("/$defs/RationalTime")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| ContractError::InvalidSchema("Missing rational definition".into()))?
        .insert(REDUCED_RATIONAL_KEYWORD.into(), Value::Bool(true));
    Ok(schema)
}

impl ContractValidator {
    pub fn embedded() -> Result<Self, ContractError> {
        Self::shared().cloned()
    }

    /// Compile the immutable embedded schema once per process. Consumers may
    /// borrow this validator or use `embedded` for an independently owned view.
    pub fn shared() -> Result<&'static Self, ContractError> {
        static VALIDATOR: OnceLock<Result<ContractValidator, ContractError>> = OnceLock::new();
        VALIDATOR
            .get_or_init(Self::build_embedded)
            .as_ref()
            .map_err(Clone::clone)
    }

    fn build_embedded() -> Result<Self, ContractError> {
        let schema = parse_json(CANONICAL_SCHEMA)?;
        jsonschema::draft202012::meta::validate(&schema)
            .map_err(|error| ContractError::InvalidSchema(error.masked().to_string()))?;
        if schema["$id"] != CANONICAL_SCHEMA_ID
            || schema["$schema"] != "https://json-schema.org/draft/2020-12/schema"
        {
            return Err(ContractError::InvalidSchema(
                "Canonical schema identity changed".into(),
            ));
        }
        let definitions = schema
            .get("$defs")
            .and_then(Value::as_object)
            .ok_or_else(|| ContractError::InvalidSchema("Missing canonical definitions".into()))?;
        let semantic_schema = semantic_validation_schema(&schema)?;
        let mut validators = BTreeMap::new();
        for name in definitions.keys() {
            let mut wrapper = semantic_schema.clone();
            wrapper
                .as_object_mut()
                .ok_or_else(|| ContractError::InvalidSchema("Expected schema object".into()))?
                .insert("$ref".into(), Value::String(format!("#/$defs/{name}")));
            let validator = validation_options()
                .build(&wrapper)
                .map_err(|error| ContractError::InvalidSchema(error.masked().to_string()))?;
            validators.insert(name.clone(), validator);
        }
        let index: FunctionIndex = serde_json::from_value(parse_json(FUNCTION_INDEX)?)
            .map_err(|error| ContractError::InvalidFunctionIndex(error.to_string()))?;
        if index.version != CONTRACT_VERSION || index.status != "implementation_contracts" {
            return Err(ContractError::InvalidFunctionIndex(
                "Unsupported index identity".into(),
            ));
        }
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        for function in &index.functions {
            if !ids.insert(function.id.clone())
                || !names.insert(function.name.clone())
                || !validators.contains_key(&function.input)
                || !validators.contains_key(&function.output)
            {
                return Err(ContractError::InvalidFunctionIndex(
                    "Duplicate function or unresolved DTO definition".into(),
                ));
            }
        }
        Ok(Self {
            schema,
            validators,
            functions: index.functions,
        })
    }

    pub fn definition_names(&self) -> impl Iterator<Item = &str> {
        self.validators.keys().map(String::as_str)
    }

    pub fn definition_schema(&self, name: &str) -> Option<&Value> {
        self.schema.get("$defs")?.get(name)
    }

    pub fn functions(&self) -> &[FunctionContract] {
        &self.functions
    }

    pub fn function(&self, name_or_id: &str) -> Result<&FunctionContract, ContractError> {
        self.functions
            .iter()
            .find(|function| function.name == name_or_id || function.id == name_or_id)
            .ok_or_else(|| ContractError::UnknownFunction(name_or_id.to_owned()))
    }

    pub fn parse_and_validate(
        &self,
        definition: &str,
        bytes: &[u8],
    ) -> Result<Value, ContractError> {
        let value = parse_json(bytes)?;
        self.validate(definition, &value)?;
        Ok(value)
    }

    /// Validate a supported definition and the exact decimal value at its
    /// selected integer paths against the same immutable input bytes. The
    /// returned value is not a transferable witness for another input, any
    /// other field, resource availability, or authorization. Existing
    /// Value-only validation and parsing methods retain their behavior.
    ///
    /// The caller's `limits` bound strict parsing; private numeric capture is
    /// additionally limited to 100,000 number spans. Schema validation also
    /// retains the validator's existing constructed-value budget. Checkpoints
    /// are cooperative and cannot preempt a single schema validation call.
    pub fn parse_validate_exact_with_control<E>(
        &self,
        selector: ExactSelector,
        bytes: &[u8],
        limits: JsonLimits,
        mut checkpoint: impl FnMut() -> Result<(), E>,
    ) -> Result<Value, ControlledContractError<E>> {
        let parsed = parse_json_with_exact_capture(bytes, limits, selector, &mut checkpoint)
            .map_err(controlled_contract_error)?;
        let definition = match selector {
            ExactSelector::ResourceRef => "ResourceRef",
            ExactSelector::PhysicsDefinition => "PhysicsDefinition",
        };
        self.validate(definition, parsed.value())
            .map_err(ControlledContractError::Contract)?;
        checkpoint().map_err(ControlledContractError::Control)?;
        parsed
            .validate_exact(&mut checkpoint)
            .map_err(controlled_raw_exact_error)?;
        checkpoint().map_err(ControlledContractError::Control)?;
        Ok(parsed.into_value())
    }

    pub fn validate(&self, definition: &str, value: &Value) -> Result<(), ContractError> {
        let violations = self.violations(definition, value)?;
        if violations.is_empty() {
            Ok(())
        } else {
            Err(ContractError::Violations(violations))
        }
    }

    pub fn violations(
        &self,
        definition: &str,
        value: &Value,
    ) -> Result<Vec<ContractViolation>, ContractError> {
        check_value(value, JsonLimits::default())?;
        let validator = self
            .validators
            .get(definition)
            .ok_or_else(|| ContractError::UnknownDefinition(definition.to_owned()))?;
        Ok(schema_violations(validator, value))
    }

    pub fn validate_function_input(
        &self,
        function: &str,
        bytes: &[u8],
    ) -> Result<Value, ContractError> {
        self.parse_and_validate(&self.function(function)?.input, bytes)
    }

    pub fn validate_function_output(
        &self,
        function: &str,
        bytes: &[u8],
    ) -> Result<Value, ContractError> {
        self.parse_and_validate(&self.function(function)?.output, bytes)
    }

    /// Action schemas are independently meta-validated, can reference their own
    /// local definitions or the embedded contract, and cannot retrieve a file
    /// or network resource. An unavailable reference is a construction error.
    pub fn compile_action_schema(
        &self,
        schema: &Value,
    ) -> Result<OfflineActionSchema, ContractError> {
        check_value(schema, JsonLimits::default())?;
        if schema
            .get("$schema")
            .is_some_and(|draft| draft != "https://json-schema.org/draft/2020-12/schema")
        {
            return Err(ContractError::InvalidSchema(
                "Action schemas must use Draft 2020-12".into(),
            ));
        }
        jsonschema::draft202012::meta::validate(schema)
            .map_err(|error| ContractError::InvalidSchema(error.masked().to_string()))?;
        let registry = Registry::new()
            .add(
                CANONICAL_SCHEMA_ID,
                semantic_validation_schema(&self.schema)?,
            )
            .map_err(|error| ContractError::InvalidSchema(error.to_string()))?
            .prepare()
            .map_err(|error| ContractError::InvalidSchema(error.to_string()))?;
        let validator = validation_options()
            .with_registry(&registry)
            .build(schema)
            .map_err(|error| ContractError::InvalidSchema(error.masked().to_string()))?;
        Ok(OfflineActionSchema { validator })
    }
}

pub struct OfflineActionSchema {
    validator: Validator,
}

impl OfflineActionSchema {
    pub fn validate(&self, value: &Value) -> Result<(), ContractError> {
        check_value(value, JsonLimits::default())?;
        let violations = schema_violations(&self.validator, value);
        if violations.is_empty() {
            Ok(())
        } else {
            Err(ContractError::Violations(violations))
        }
    }

    pub fn parse_and_validate(&self, bytes: &[u8]) -> Result<Value, ContractError> {
        let value = parse_json(bytes)?;
        self.validate(&value)?;
        Ok(value)
    }
}

fn schema_violations(validator: &Validator, value: &Value) -> Vec<ContractViolation> {
    // A bounded diagnostic count prevents an invalid array from filling logs.
    // Rejection is unchanged when more errors exist than this report can hold.
    validator
        .iter_errors(value)
        .take(64)
        .map(|error| ContractViolation {
            code: "SCHEMA_INVALID".into(),
            instance_path: error.instance_path().to_string(),
            schema_path: error.schema_path().to_string(),
            message: error.masked().to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::Cell;
    use std::sync::OnceLock;

    fn validator() -> &'static ContractValidator {
        static VALIDATOR: OnceLock<ContractValidator> = OnceLock::new();
        VALIDATOR.get_or_init(|| ContractValidator::embedded().unwrap())
    }

    fn exact_resource_wire(size: &str, escaped_key: bool) -> Vec<u8> {
        let key = if escaped_key {
            r#"\u0073izeBytes"#
        } else {
            "sizeBytes"
        };
        format!(
            r#"{{"resourceId":"resource-mesh","sha256":"{}","mediaType":"application/octet-stream","{}":{}}}"#,
            "0".repeat(64),
            key,
            size,
        )
        .into_bytes()
    }

    fn mesh_shape_wire(size: &str, kind_first: bool) -> String {
        let geometry = format!(
            r#"{{"resourceId":"resource-mesh","sha256":"{}","mediaType":"application/octet-stream","sizeBytes":{}}}"#,
            "0".repeat(64),
            size,
        );
        if kind_first {
            format!(
                r#"{{"kind":"mesh","geometry":{},"topologyDigest":"{}"}}"#,
                geometry,
                "1".repeat(64),
            )
        } else {
            format!(
                r#"{{"geometry":{},"topologyDigest":"{}","kind":"mesh"}}"#,
                geometry,
                "1".repeat(64),
            )
        }
    }

    fn physics_wire_with_meshes(first: &str, second: Option<&str>, kind_first: bool) -> Vec<u8> {
        // The original PhysicsDefinition example has a box collider. Derive
        // mesh shapes in memory to exercise ResourceRef paths without adding a
        // fixture or claiming the bytes are valid mesh topology.
        let mut physics =
            parse_json(include_bytes!("../../../examples/physics-definition.json")).unwrap();
        let first_shape = json!({
            "kind": "mesh",
            "geometry": {
                "resourceId": "resource-mesh",
                "sha256": "0".repeat(64),
                "mediaType": "application/octet-stream",
                "sizeBytes": 77
            },
            "topologyDigest": "1".repeat(64)
        });
        physics["colliders"][0]["shape"]["shape"] = first_shape.clone();
        if second.is_some() {
            let mut collider = physics["colliders"][0].clone();
            collider["colliderId"] = json!("collider-second");
            collider["shape"]["shape"]["geometry"]["sizeBytes"] = json!(88);
            physics["colliders"].as_array_mut().unwrap().push(collider);
        }
        let mut encoded = serde_json::to_string(&physics).unwrap();
        let first_needle = serde_json::to_string(&first_shape).unwrap();
        assert_eq!(encoded.matches(&first_needle).count(), 1);
        encoded = encoded.replacen(&first_needle, &mesh_shape_wire(first, kind_first), 1);
        if let Some(second) = second {
            let mut second_shape = first_shape;
            second_shape["geometry"]["sizeBytes"] = json!(88);
            let second_needle = serde_json::to_string(&second_shape).unwrap();
            assert_eq!(encoded.matches(&second_needle).count(), 1);
            encoded = encoded.replacen(&second_needle, &mesh_shape_wire(second, !kind_first), 1);
        }
        encoded.into_bytes()
    }

    fn exact(
        selector: ExactSelector,
        bytes: &[u8],
    ) -> Result<Value, ControlledContractError<std::convert::Infallible>> {
        validator().parse_validate_exact_with_control(
            selector,
            bytes,
            JsonLimits::default(),
            || Ok::<(), std::convert::Infallible>(()),
        )
    }

    #[test]
    fn raw_exact_resource_size_is_checked_without_changing_value_only_validation() {
        for size in ["1", "1.0", "1e0", "100e-2", "-0.0", "9007199254740991"] {
            let bytes = exact_resource_wire(size, size == "1e0");
            let ordinary = validator()
                .parse_and_validate("ResourceRef", &bytes)
                .unwrap();
            let checked = exact(ExactSelector::ResourceRef, &bytes).unwrap();
            assert_eq!(checked, ordinary, "{size}");
            assert_eq!(
                crate::canonical_bytes(&checked).unwrap(),
                crate::canonical_bytes(&ordinary).unwrap()
            );
        }
        let rounded_fraction = exact_resource_wire("1.0000000000000001", false);
        // Existing Value-only validation is intentionally unchanged; it sees
        // the parsed binary64 value and cannot prove the original token.
        assert!(
            validator()
                .parse_and_validate("ResourceRef", &rounded_fraction)
                .is_ok()
        );
        let exact_error = exact(ExactSelector::ResourceRef, &rounded_fraction).unwrap_err();
        assert!(matches!(
            &exact_error,
            ControlledContractError::ExactInteger { collider: None }
        ));
        assert!(!exact_error.to_string().contains("1.0000000000000001"));
        for invalid in [
            "9007199254740991.1",
            "1e-10000",
            "-1e-10000",
            "0.5",
            "9007199254740992",
        ] {
            assert!(
                exact(
                    ExactSelector::ResourceRef,
                    &exact_resource_wire(invalid, false)
                )
                .is_err(),
                "{invalid}"
            );
        }
        // A successful checked call cannot be reused as a witness for another
        // byte sequence: every invocation performs its own parse and checks.
        assert!(exact(ExactSelector::ResourceRef, &exact_resource_wire("1", false)).is_ok());
        assert!(matches!(
            exact(ExactSelector::ResourceRef, &rounded_fraction),
            Err(ControlledContractError::ExactInteger { collider: None })
        ));
    }

    #[test]
    fn raw_exact_physics_checks_each_actual_mesh_geometry_in_either_field_order() {
        for kind_first in [true, false] {
            let valid = physics_wire_with_meshes("1.0", Some("100e-2"), kind_first);
            let ordinary = validator()
                .parse_and_validate("PhysicsDefinition", &valid)
                .unwrap();
            assert_eq!(
                exact(ExactSelector::PhysicsDefinition, &valid).unwrap(),
                ordinary
            );

            for (first, second, index) in [
                ("1.0000000000000001", "1", 0),
                ("1", "1.0000000000000001", 1),
            ] {
                let invalid = physics_wire_with_meshes(first, Some(second), kind_first);
                assert!(
                    validator()
                        .parse_and_validate("PhysicsDefinition", &invalid)
                        .is_ok()
                );
                assert!(matches!(
                    exact(ExactSelector::PhysicsDefinition, &invalid),
                    Err(ControlledContractError::ExactInteger { collider: Some(actual) }) if actual == index
                ));
            }
        }
        // Another schema number and an opaque string containing a same-named
        // key are outside the selected mesh geometry path.
        let mut physics =
            parse_json(include_bytes!("../../../examples/physics-definition.json")).unwrap();
        physics["materials"][0]["semantics"] = json!(r#"{"sizeBytes":1.0000000000000001}"#);
        physics["bodies"][0]["massKg"] = json!(123);
        let encoded = serde_json::to_string(&physics).unwrap();
        let ordinary_float = encoded.replacen("\"massKg\":123", "\"massKg\":1.0000000000000001", 1);
        assert_ne!(ordinary_float, encoded);
        assert!(exact(ExactSelector::PhysicsDefinition, ordinary_float.as_bytes()).is_ok());
    }

    #[test]
    fn raw_exact_preserves_strict_and_schema_failures_before_exact_checks() {
        let duplicate = format!(
            r#"{{"resourceId":"r","sha256":"{}","mediaType":"x","sizeBytes":1.0000000000000001,"\u0073izeBytes":1}}"#,
            "0".repeat(64),
        );
        let strict = parse_json(duplicate.as_bytes()).unwrap_err();
        assert!(strict.message.contains("Duplicate"));
        assert_eq!(
            exact(ExactSelector::ResourceRef, duplicate.as_bytes()),
            Err(ControlledContractError::Contract(ContractError::Json(
                strict
            )))
        );

        let trailing = [
            exact_resource_wire("1.0000000000000001", false),
            b" true".to_vec(),
        ]
        .concat();
        let strict = parse_json(&trailing).unwrap_err();
        assert_eq!(
            exact(ExactSelector::ResourceRef, &trailing),
            Err(ControlledContractError::Contract(ContractError::Json(
                strict
            )))
        );
        let malformed = exact_resource_wire("1e+", false);
        let strict = parse_json(&malformed).unwrap_err();
        assert_eq!(
            exact(ExactSelector::ResourceRef, &malformed),
            Err(ControlledContractError::Contract(ContractError::Json(
                strict
            )))
        );
        let invalid_schema = format!(
            r#"{{"resourceId":"r","sha256":"{}","mediaType":"x","sizeBytes":1.0000000000000001,"extra":true}}"#,
            "0".repeat(64),
        );
        let schema = validator()
            .parse_and_validate("ResourceRef", invalid_schema.as_bytes())
            .unwrap_err();
        assert!(matches!(schema, ContractError::Violations(_)));
        assert_eq!(
            exact(ExactSelector::ResourceRef, invalid_schema.as_bytes()),
            Err(ControlledContractError::Contract(schema))
        );

        let bytes = exact_resource_wire("1", false);
        let limits = JsonLimits {
            max_bytes: bytes.len() - 1,
            ..JsonLimits::default()
        };
        let strict = crate::strict_json::parse_json_with_limits(&bytes, limits).unwrap_err();
        assert_eq!(
            validator().parse_validate_exact_with_control(
                ExactSelector::ResourceRef,
                &bytes,
                limits,
                || Ok::<(), ()>(())
            ),
            Err(ControlledContractError::Contract(ContractError::Json(
                strict
            )))
        );
        for limits in [
            JsonLimits {
                max_depth: 0,
                ..JsonLimits::default()
            },
            JsonLimits {
                max_nodes: 3,
                ..JsonLimits::default()
            },
        ] {
            let strict = crate::strict_json::parse_json_with_limits(&bytes, limits).unwrap_err();
            assert_eq!(
                validator().parse_validate_exact_with_control(
                    ExactSelector::ResourceRef,
                    &bytes,
                    limits,
                    || Ok::<(), ()>(())
                ),
                Err(ControlledContractError::Contract(ContractError::Json(
                    strict
                )))
            );
        }
    }

    #[test]
    fn raw_exact_preserves_control_failure_during_long_token_and_final_checkpoint() {
        let long_integer = format!("1.{}", "0".repeat(16 * 1024));
        let bytes = exact_resource_wire(&long_integer, false);
        let parse_checks = Cell::new(0usize);
        let parsed = parse_json_with_exact_capture(
            &bytes,
            JsonLimits::default(),
            ExactSelector::ResourceRef,
            || {
                parse_checks.set(parse_checks.get() + 1);
                Ok::<(), ()>(())
            },
        )
        .unwrap();
        validator().validate("ResourceRef", parsed.value()).unwrap();
        let checks = Cell::new(0usize);
        validator()
            .parse_validate_exact_with_control(
                ExactSelector::ResourceRef,
                &bytes,
                JsonLimits::default(),
                || {
                    checks.set(checks.get() + 1);
                    Ok::<(), ()>(())
                },
            )
            .unwrap();
        let total = checks.get();
        let mid_token = parse_checks.get() + 3;
        assert!(
            mid_token < total,
            "A long exact token must have a mid-token checkpoint"
        );
        for stop_at in [1usize, mid_token, total] {
            let mut calls = 0usize;
            let mut original = Some(Box::new(stop_at));
            let original_address = original.as_ref().unwrap().as_ref() as *const usize;
            let result = validator().parse_validate_exact_with_control(
                ExactSelector::ResourceRef,
                &bytes,
                JsonLimits::default(),
                || {
                    calls += 1;
                    assert!(
                        calls <= stop_at,
                        "No checkpoints may occur after a control failure"
                    );
                    if calls == stop_at {
                        Err(original.take().unwrap())
                    } else {
                        Ok(())
                    }
                },
            );
            match result {
                Err(ControlledContractError::Control(error)) => {
                    assert_eq!(error.as_ref() as *const usize, original_address);
                }
                other => panic!("Expected original control failure, got {other:?}"),
            }
            assert_eq!(calls, stop_at);
        }
    }

    #[test]
    fn original_positive_examples_validate_against_their_definitions() {
        let index = parse_json(include_bytes!("../../../tests/example-index.json")).unwrap();
        assert_eq!(validator().definition_names().count(), 124);
        assert_eq!(validator().functions().len(), 36);
        assert_eq!(index.as_object().unwrap().len(), 43);
        for (file, definition) in index.as_object().unwrap() {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples")
                .join(file);
            validator()
                .parse_and_validate(definition.as_str().unwrap(), &std::fs::read(path).unwrap())
                .unwrap_or_else(|error| panic!("{file}: {error:?}"));
        }
    }

    const ACTION_DESCRIPTOR_FIELDS: [&str; 21] = [
        "actionId",
        "contractVersion",
        "title",
        "summary",
        "semanticKind",
        "inputSchema",
        "outputSchema",
        "side",
        "requiredContext",
        "effect",
        "planning",
        "completion",
        "cancellation",
        "recovery",
        "idempotency",
        "guarantees",
        "limitations",
        "requiredPermissions",
        "verificationRequirement",
        "implementationDigest",
        "versionEvidence",
    ];

    fn original_action_descriptor() -> Value {
        let provider = validator()
            .parse_and_validate(
                "ProviderDescriptor",
                include_bytes!("../../../examples/provider-supported.json"),
            )
            .unwrap();
        provider["actions"][0].clone()
    }

    #[test]
    fn original_action_descriptor_matches_shared_canonical_bytes() {
        let original = original_action_descriptor();
        validator().validate("ActionDescriptor", &original).unwrap();
        let fields = original.as_object().unwrap();
        assert_eq!(fields.len(), ACTION_DESCRIPTOR_FIELDS.len());
        for name in ACTION_DESCRIPTOR_FIELDS {
            assert!(fields.contains_key(name), "missing original field {name}");
        }

        // The same fixed bytes are consumed by the Java test. This shared
        // reference does not itself execute a Rust/Java process exchange.
        let golden = include_bytes!(
            "../../../jvm/provider-sdk/src/test/resources/action-descriptor-canonical.json"
        );
        let canonical = crate::canonical_bytes(&original).unwrap();
        assert_eq!(canonical.as_slice(), golden.as_slice());
        let reparsed = validator()
            .parse_and_validate("ActionDescriptor", golden)
            .unwrap();
        assert_eq!(reparsed, original);
        assert_eq!(crate::canonical_bytes(&reparsed).unwrap(), canonical);
        assert_eq!(
            crate::projected_digest("ActionDescriptor", &original).unwrap(),
            crate::canonical_digest(&original).unwrap()
        );
        assert_eq!(
            crate::canonical_digest(&original).unwrap(),
            crate::raw_digest(golden)
        );
    }

    #[test]
    fn action_descriptor_required_fields_and_closed_enums_are_enforced() {
        let original = original_action_descriptor();
        for name in ACTION_DESCRIPTOR_FIELDS {
            let mut missing = original.clone();
            missing.as_object_mut().unwrap().remove(name);
            assert!(
                validator().validate("ActionDescriptor", &missing).is_err(),
                "{name}"
            );
            let mut null = original.clone();
            null[name] = Value::Null;
            assert!(
                validator().validate("ActionDescriptor", &null).is_err(),
                "{name}"
            );
        }
        let mut unknown = original.clone();
        unknown["undeclared"] = json!(true);
        assert!(validator().validate("ActionDescriptor", &unknown).is_err());
        for name in [
            "side",
            "effect",
            "planning",
            "completion",
            "cancellation",
            "recovery",
            "idempotency",
            "verificationRequirement",
            "versionEvidence",
        ] {
            let mut invalid = original.clone();
            invalid[name] = json!("unknown_enum_value");
            assert!(
                validator().validate("ActionDescriptor", &invalid).is_err(),
                "{name}"
            );
        }
        let mut unknown_context = original.clone();
        unknown_context["requiredContext"] = json!(["not_a_context"]);
        assert!(
            validator()
                .validate("ActionDescriptor", &unknown_context)
                .is_err()
        );
        let mut invalid_version = original;
        invalid_version["contractVersion"] = json!("1.2");
        assert!(
            validator()
                .validate("ActionDescriptor", &invalid_version)
                .is_err()
        );
    }

    #[test]
    fn action_descriptor_preserves_schema_permitted_arrays_and_nested_values() {
        let original = original_action_descriptor();
        for name in ["requiredContext", "guarantees", "requiredPermissions"] {
            let mut duplicate = original.clone();
            let values = duplicate[name].as_array_mut().unwrap();
            values.push(values.first().unwrap().clone());
            assert!(
                validator()
                    .validate("ActionDescriptor", &duplicate)
                    .is_err(),
                "{name}"
            );
        }

        let mut allowed = original;
        allowed["contractVersion"] = json!("1.2.3");
        allowed["limitations"] = json!(["same limitation", "same limitation"]);
        allowed["inputSchema"]["x-fixture"] = json!({"nested": [1, {"keep": true}]});
        allowed["outputSchema"]["x-fixture"] =
            json!({"description": "preserve unknown schema content"});
        validator().validate("ActionDescriptor", &allowed).unwrap();
        let encoded = crate::canonical_bytes(&allowed).unwrap();
        assert_eq!(
            validator()
                .parse_and_validate("ActionDescriptor", &encoded)
                .unwrap(),
            allowed
        );
    }

    #[test]
    fn unknown_fields_version_drift_and_unreduced_time_are_rejected() {
        assert!(
            validator()
                .validate(
                    "RationalTime",
                    &json!({"numerator":"40", "denominator":"2"})
                )
                .is_err()
        );
        assert!(
            validator()
                .validate("RationalTime", &json!({"numerator":"1", "denominator":"2"}))
                .is_ok()
        );
        assert!(
            validator()
                .validate(
                    "RationalTime",
                    &json!({"numerator":"1", "denominator":"2", "other":1})
                )
                .is_err()
        );
        let mut project = parse_json(include_bytes!("../../../examples/project.json")).unwrap();
        project["contractVersion"] = json!("0.1.0");
        assert!(validator().validate("Project", &project).is_err());
        project["contractVersion"] = json!("0.2.0");
        project["gameTicksPerSecond"] = json!({"numerator":"40", "denominator":"2"});
        assert!(validator().validate("Project", &project).is_err());
    }

    #[test]
    fn unknown_extensions_remain_opaque_and_preserved() {
        let mut prefab = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
        prefab["nodes"][0]["extensions"]["example:future"] =
            json!({"numerator":"40", "denominator":"2"});
        assert!(validator().validate("Prefab", &prefab).is_ok());
        let encoded = serde_json::to_vec(&prefab).unwrap();
        assert_eq!(
            validator().parse_and_validate("Prefab", &encoded).unwrap(),
            prefab
        );
    }

    #[test]
    fn action_schema_meta_validation_and_resolution_are_offline() {
        let invalid = json!({"type":42});
        assert!(validator().compile_action_schema(&invalid).is_err());
        assert!(
            validator()
                .compile_action_schema(&json!({"type":"string", "$defs":{"unused":{"type":42}}}))
                .is_err()
        );
        for reference in [
            "https://example.invalid/schema.json",
            "file:///unavailable.json",
        ] {
            assert!(
                validator()
                    .compile_action_schema(&json!({"$ref":reference}))
                    .is_err()
            );
        }
        let schema = json!({"$ref":"urn:mmmm:contracts:0.2.0#/$defs/RationalTime"});
        let action = validator().compile_action_schema(&schema).unwrap();
        assert!(
            action
                .validate(&json!({"numerator":"1", "denominator":"2"}))
                .is_ok()
        );
        assert!(
            action
                .validate(&json!({"numerator":"2", "denominator":"4"}))
                .is_err()
        );
        let own_defs = json!({"$defs":{"local":{"type":"integer"}}, "$ref":"#/$defs/local"});
        assert!(
            validator()
                .compile_action_schema(&own_defs)
                .unwrap()
                .validate(&json!(1))
                .is_ok()
        );
        let union = json!({"oneOf":[
            {"$ref":"urn:mmmm:contracts:0.2.0#/$defs/RationalTime"},
            {"type":"string"}
        ]});
        assert!(
            validator()
                .compile_action_schema(&union)
                .unwrap()
                .validate(&json!("opaque"))
                .is_ok()
        );
        let formatted = validator()
            .compile_action_schema(&json!({"type":"string", "format":"date-time"}))
            .unwrap();
        assert!(formatted.validate(&json!("not-a-date")).is_err());
        assert!(formatted.validate(&json!("2026-10-13T00:00:00Z")).is_ok());
    }
}

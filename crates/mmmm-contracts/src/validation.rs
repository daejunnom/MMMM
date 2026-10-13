//! Schema validation is a format boundary, not authorization or a claim that a
//! referenced object, world, vendor, or release evidence exists.

use crate::{
    CANONICAL_SCHEMA, CANONICAL_SCHEMA_ID, CONTRACT_VERSION, FUNCTION_INDEX, RationalTime,
    strict_json::{JsonError, JsonLimits, check_value, parse_json},
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
    use std::sync::OnceLock;

    fn validator() -> &'static ContractValidator {
        static VALIDATOR: OnceLock<ContractValidator> = OnceLock::new();
        VALIDATOR.get_or_init(|| ContractValidator::embedded().unwrap())
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

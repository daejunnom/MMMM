//! Bounded data mapping only. Command tokens remain typed for the host parser;
//! mapped strings are never shell commands, endpoints, paths or source code.

use crate::{
    AdapterError, ArgumentCodec, Binding, BindingSupport, BindingValue, MappedContextField,
    compatibility::validate_pointer,
};
use mmmm_contracts::{
    BindingId, ContractValidator, Int32, PrincipalId, Sha256Digest, canonical_digest,
    verify_projected_digest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HandleScope {
    pub binding_id: BindingId,
    pub environment_digest: Sha256Digest,
    pub principal_id: PrincipalId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedHandle {
    pub reference: String,
    pub scope: HandleScope,
    pub handle_type: String,
}

/// Runtime implementation looks up existing opaque handles. It must not create
/// a receiver, reflectively instantiate a class or transfer a handle to a new
/// principal. This pure mapping layer independently checks returned scope/type.
pub trait HandleResolver {
    fn resolve(
        &self,
        reference: &str,
        scope: &HandleScope,
        expected_type: &str,
    ) -> Result<ResolvedHandle, AdapterError>;
}

#[derive(Clone, Debug, PartialEq)]
pub enum MappedValue {
    Literal(Value),
    Argument {
        codec: ArgumentCodec,
        value: Value,
    },
    Context {
        field: MappedContextField,
        value: Value,
    },
    Handle(ResolvedHandle),
}

enum BorrowedMappedValue<'a> {
    Literal(&'a Value),
    Argument {
        codec: ArgumentCodec,
        value: &'a Value,
    },
    Context {
        field: MappedContextField,
        value: &'a Value,
    },
    Handle(ResolvedHandle),
}

impl BorrowedMappedValue<'_> {
    fn into_owned(self) -> MappedValue {
        match self {
            Self::Literal(value) => MappedValue::Literal(value.clone()),
            Self::Argument { codec, value } => MappedValue::Argument {
                codec,
                value: value.clone(),
            },
            Self::Context { field, value } => MappedValue::Context {
                field,
                value: value.clone(),
            },
            Self::Handle(handle) => MappedValue::Handle(handle),
        }
    }

    fn encoded_len(&self) -> Result<usize, AdapterError> {
        match self {
            Self::Literal(value) | Self::Argument { value, .. } | Self::Context { value, .. } => {
                mmmm_contracts::encode_json(value)
                    .map(|bytes| bytes.len())
                    .map_err(|error| AdapterError::new("INPUT_INVALID", error.to_string()))
            }
            Self::Handle(handle) => serde_json::to_vec(&handle.reference)
                .map(|bytes| bytes.len())
                .map_err(|error| AdapterError::new("HANDLE_INVALID", error.to_string())),
        }
    }

    fn into_json(self) -> Value {
        match self {
            Self::Literal(value) | Self::Argument { value, .. } | Self::Context { value, .. } => {
                value.clone()
            }
            Self::Handle(handle) => Value::String(handle.reference),
        }
    }
}

pub fn map_binding_value(
    mapping: &BindingValue,
    arguments: &Value,
    context: &Value,
    handle_scope: &HandleScope,
    handles: &dyn HandleResolver,
) -> Result<MappedValue, AdapterError> {
    validate_mapping_inputs(arguments, context, handle_scope)?;
    Ok(borrow_binding_value(mapping, arguments, context, handle_scope, handles)?.into_owned())
}

fn validate_mapping_inputs(
    arguments: &Value,
    context: &Value,
    handle_scope: &HandleScope,
) -> Result<(), AdapterError> {
    // Bound JSON size/depth and finite-number checks without executing anything.
    mmmm_contracts::encode_json(arguments)
        .map_err(|error| AdapterError::new("INPUT_INVALID", error.to_string()))?;
    ContractValidator::shared()?.validate("ExecutionContext", context)?;
    verify_projected_digest("ExecutionContext", context)?;
    if canonical_digest(&context["environment"])? != handle_scope.environment_digest
        || context["principalRef"].as_str() != Some(handle_scope.principal_id.as_str())
    {
        return Err(AdapterError::new(
            "HANDLE_SCOPE_MISMATCH",
            "Mapping context differs from the handle principal or environment epoch",
        ));
    }
    Ok(())
}

fn borrow_binding_value<'a>(
    mapping: &'a BindingValue,
    arguments: &'a Value,
    context: &'a Value,
    handle_scope: &HandleScope,
    handles: &dyn HandleResolver,
) -> Result<BorrowedMappedValue<'a>, AdapterError> {
    match mapping {
        BindingValue::Literal { value } => {
            if value.is_array() || value.is_object() {
                return Err(AdapterError::new(
                    "INPUT_INVALID",
                    "Literal mapping requires scalar or null",
                ));
            }
            mmmm_contracts::encode_json(value)
                .map_err(|error| AdapterError::new("INPUT_INVALID", error.to_string()))?;
            Ok(BorrowedMappedValue::Literal(value))
        }
        BindingValue::Argument { pointer, codec } => {
            validate_pointer(pointer)?;
            let value = arguments.pointer(pointer).ok_or_else(|| {
                AdapterError::new(
                    "INPUT_MISSING",
                    "Mapped argument is omitted; no null or delete value was synthesized",
                )
            })?;
            validate_codec(*codec, value)?;
            Ok(BorrowedMappedValue::Argument {
                codec: *codec,
                value,
            })
        }
        BindingValue::Context { field } => {
            let key = match field {
                MappedContextField::ExecutorHandle => "executorHandle",
                MappedContextField::Dimension => "dimension",
                MappedContextField::Origin => "origin",
                MappedContextField::RotationDegrees => "rotationDegrees",
                MappedContextField::Anchor => "anchor",
                MappedContextField::SelectionRef => "selectionRef",
                MappedContextField::ProjectId => "projectId",
            };
            let value = context.get(key).ok_or_else(|| {
                AdapterError::new("CONTEXT_MISSING", "Mapped context field is absent")
            })?;
            Ok(BorrowedMappedValue::Context {
                field: *field,
                value,
            })
        }
        BindingValue::Handle {
            argument_pointer,
            expected_type,
        } => {
            validate_pointer(argument_pointer)?;
            let reference = arguments
                .pointer(argument_pointer)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AdapterError::new(
                        "HANDLE_INVALID",
                        "Handle mapping requires an existing opaque string reference",
                    )
                })?;
            let resolved = handles.resolve(reference, handle_scope, expected_type)?;
            if resolved.reference != reference
                || &resolved.scope != handle_scope
                || &resolved.handle_type != expected_type
            {
                return Err(AdapterError::new(
                    "HANDLE_SCOPE_MISMATCH",
                    "Resolved handle changed reference, binding, epoch, principal or type",
                ));
            }
            Ok(BorrowedMappedValue::Handle(resolved))
        }
    }
}

fn validate_codec(codec: ArgumentCodec, value: &Value) -> Result<(), AdapterError> {
    let valid = match codec {
        ArgumentCodec::Integer => serde_json::from_value::<Int32>(value.clone()).is_ok(),
        ArgumentCodec::Float => value.as_f64().is_some_and(f64::is_finite),
        ArgumentCodec::ResourceId => value
            .as_str()
            .is_some_and(|text| mmmm_contracts::ResourceLocation::new(text).is_ok()),
        ArgumentCodec::QuotedText | ArgumentCodec::String => value.is_string(),
        ArgumentCodec::Boolean => value.is_boolean(),
        ArgumentCodec::JsonValue => true,
    };
    if valid {
        Ok(())
    } else {
        Err(AdapterError::new(
            "INPUT_INVALID",
            "Mapped value does not satisfy its registered codec",
        ))
    }
}

/// Check Java's concrete numeric/null boundary before the host converts values.
/// This returns original data and never constructs or resolves a Java object.
pub fn validate_java_argument(
    parameter_type: &str,
    value: &MappedValue,
) -> Result<(), AdapterError> {
    if let MappedValue::Handle(handle) = value {
        return if handle.handle_type == parameter_type {
            Ok(())
        } else {
            Err(AdapterError::new(
                "HANDLE_TYPE_MISMATCH",
                "Handle type differs from the exact Java parameter",
            ))
        };
    }
    let value = match value {
        MappedValue::Literal(value)
        | MappedValue::Argument { value, .. }
        | MappedValue::Context { value, .. } => value,
        MappedValue::Handle(_) => unreachable!(),
    };
    let primitive = matches!(parameter_type, "boolean" | "int" | "float" | "double");
    if !matches!(
        parameter_type,
        "java.lang.String"
            | "boolean"
            | "java.lang.Boolean"
            | "int"
            | "java.lang.Integer"
            | "float"
            | "java.lang.Float"
            | "double"
            | "java.lang.Double"
            | "java.util.List"
            | "java.util.Map"
    ) {
        return Err(AdapterError::new(
            "UNSUPPORTED_BINDING",
            "A non-handle value cannot target an arbitrary Java class",
        ));
    }
    if value.is_null() {
        return if primitive {
            Err(AdapterError::new(
                "INPUT_INVALID",
                "Null cannot map to a Java primitive",
            ))
        } else {
            Ok(())
        };
    }
    let valid = match parameter_type {
        "java.lang.String" => value.is_string(),
        "boolean" | "java.lang.Boolean" => value.is_boolean(),
        "int" | "java.lang.Integer" => serde_json::from_value::<Int32>(value.clone()).is_ok(),
        "float" | "java.lang.Float" => value
            .as_f64()
            .is_some_and(|number| number.is_finite() && (number as f32).is_finite()),
        "double" | "java.lang.Double" => value.as_f64().is_some_and(f64::is_finite),
        "java.util.List" => value.is_array(),
        "java.util.Map" => value.is_object(),
        _ => false,
    };
    if !valid {
        return Err(AdapterError::new(
            "UNSUPPORTED_BINDING",
            "Value is incompatible with the exact supported Java parameter type",
        ));
    }
    mmmm_contracts::encode_json(value)
        .map_err(|error| AdapterError::new("INPUT_INVALID", error.to_string()))?;
    Ok(())
}

/// Construct only the approved registered RPC method's data arguments. This
/// does not resolve an endpoint, connect to a service, or dispatch a request.
/// Public action input validation must precede this mapping in the application.
pub fn prepare_rpc_arguments(
    binding: &Binding,
    support: &BindingSupport,
    arguments: &Value,
    context: &Value,
    handle_scope: &HandleScope,
    handles: &dyn HandleResolver,
) -> Result<Value, AdapterError> {
    prepare_rpc_arguments_with_budget(
        binding,
        support,
        arguments,
        context,
        handle_scope,
        handles,
        mmmm_contracts::JsonLimits::default().max_bytes,
    )
}

// A smaller budget is available only within this crate for focused checks. An
// internal caller can never raise the fixed production contract byte limit.
pub(crate) fn prepare_rpc_arguments_with_budget(
    binding: &Binding,
    support: &BindingSupport,
    arguments: &Value,
    context: &Value,
    handle_scope: &HandleScope,
    handles: &dyn HandleResolver,
    requested_budget: usize,
) -> Result<Value, AdapterError> {
    let (
        Binding::RegisteredRpc {
            target_id,
            method,
            arguments: mappings,
            result_codec,
        },
        BindingSupport::RegisteredRpc {
            target_id: observed_target,
            method: observed_method,
            input_schema,
            result_codec: observed_codec,
            registered_local,
            ..
        },
    ) = (binding, support)
    else {
        return Err(AdapterError::new(
            "UNSUPPORTED_BINDING",
            "RPC mapping requires a registered RPC binding and interface",
        ));
    };
    if !registered_local
        || target_id != observed_target
        || method != observed_method
        || result_codec != observed_codec
        || mappings.len() > 256
    {
        return Err(AdapterError::new(
            "INTERFACE_MISMATCH",
            "RPC mapping does not match the exact registered method",
        ));
    }
    validate_mapping_inputs(arguments, context, handle_scope)?;
    let output_budget = requested_budget.min(mmmm_contracts::JsonLimits::default().max_bytes);
    // Braces, escaped JSON key bytes, colons and commas all count. Measure the
    // borrowed value before cloning it, so duplicate mappings cannot allocate
    // an unbounded object before its final schema validation rejects it.
    let mut output_bytes: usize = 2;
    if output_bytes > output_budget {
        return Err(AdapterError::new(
            "MAPPING_OUTPUT_LIMIT",
            "Mapped RPC output exceeds its encoded byte budget",
        ));
    }
    let mut mapped = serde_json::Map::new();
    for (name, mapping) in mappings {
        if name.len() > 128 {
            return Err(AdapterError::new(
                "INPUT_INVALID",
                "RPC mapping key exceeds its length limit",
            ));
        }
        let borrowed = borrow_binding_value(mapping, arguments, context, handle_scope, handles)?;
        let key_bytes = serde_json::to_vec(name)
            .map_err(|error| AdapterError::new("INPUT_INVALID", error.to_string()))?
            .len();
        let separator_bytes = usize::from(!mapped.is_empty());
        // Preserve actual codec/encoding errors rather than treating an invalid
        // selected value as a mere allocation overflow.
        let value_bytes = borrowed.encoded_len()?;
        let next_bytes = output_bytes
            .checked_add(key_bytes)
            .and_then(|count| count.checked_add(1 + separator_bytes))
            .and_then(|count| count.checked_add(value_bytes));
        let Some(next_bytes) = next_bytes.filter(|count| *count <= output_budget) else {
            return Err(AdapterError::new(
                "MAPPING_OUTPUT_LIMIT",
                "Mapped RPC output exceeds its encoded byte budget",
            ));
        };
        output_bytes = next_bytes;
        mapped.insert(name.clone(), borrowed.into_json());
    }
    let mapped = Value::Object(mapped);
    ContractValidator::shared()?
        .compile_action_schema(input_schema)?
        .validate(&mapped)?;
    Ok(mapped)
}

/// Schema checking precedes registered result-codec interpretation. Failure is
/// OUTPUT_INVALID and cannot erase effects from an already dispatched request.
pub fn validate_rpc_response(
    support: &BindingSupport,
    response: &Value,
) -> Result<(), AdapterError> {
    let BindingSupport::RegisteredRpc {
        output_schema,
        registered_local: true,
        ..
    } = support
    else {
        return Err(AdapterError::new(
            "UNSUPPORTED_BINDING",
            "Response has no registered RPC contract",
        ));
    };
    ContractValidator::shared()?
        .compile_action_schema(output_schema)?
        .validate(response)
        .map_err(|error| AdapterError::new("OUTPUT_INVALID", error.to_string()))
}

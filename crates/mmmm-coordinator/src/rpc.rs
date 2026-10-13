use crate::{
    auth::AuthenticatedPrincipal,
    service::{RequestBudget, ServiceDispatcher, ServiceError},
};
use mmmm_contracts::{ContractValidator, JsonLimits, encode_json, parse_json_with_limits};
use serde_json::{Value, json};

pub const MAX_CONTROL_BYTES: usize = 1024 * 1024;
pub const MAX_CONTROL_NODES: usize = 4096;

pub fn handle_rpc(
    dispatcher: &mut dyn ServiceDispatcher,
    principal: &AuthenticatedPrincipal,
    body: &[u8],
    budget: &RequestBudget,
) -> Vec<u8> {
    let request = match parse_json_with_limits(
        body,
        JsonLimits {
            max_bytes: MAX_CONTROL_BYTES,
            max_depth: 64,
            max_nodes: MAX_CONTROL_NODES,
        },
    ) {
        Ok(value) => value,
        Err(_) => return encode_response(error(Value::Null, -32700, "Invalid JSON", None)),
    };
    let object = match request.as_object() {
        Some(object) => object,
        None => return encode_response(error(Value::Null, -32600, "Invalid request", None)),
    };
    let id = object.get("id").cloned().unwrap_or(Value::Null);
    if object.len() != 4
        || object
            .keys()
            .any(|k| !matches!(k.as_str(), "jsonrpc" | "id" | "method" | "params"))
        || object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || !valid_id(&id)
        || !object.get("params").is_some_and(Value::is_object)
    {
        return encode_response(error(Value::Null, -32600, "Invalid request", None));
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return encode_response(error(id, -32600, "Invalid request", None));
    };
    let validator = match ContractValidator::shared() {
        Ok(v) => v,
        Err(_) => {
            return encode_response(error(id, -32603, "Contract initialization failed", None));
        }
    };
    // The frozen function index is the public API list. Internal/host control
    // endpoints cannot be reached through the authoring facade dispatcher.
    let function = match validator.function(method) {
        Ok(function) if function.name == method => function,
        _ => return encode_response(error(id, -32601, "Method not found", None)),
    };
    if !principal.permits(method) {
        return encode_response(error(
            id,
            -32001,
            "Permission required",
            Some("PERMISSION_REQUIRED"),
        ));
    }
    let input = &object["params"];
    if validator.validate(&function.input, input).is_err() {
        return encode_response(error(
            id,
            -32602,
            "Invalid function input",
            Some("INVALID_INPUT"),
        ));
    }
    if !contexts_allowed(input, principal) {
        return encode_response(error(
            id,
            -32001,
            "Context is not paired",
            Some("PERMISSION_REQUIRED"),
        ));
    }
    if budget.check().is_err() {
        return encode_response(error(
            id,
            -32002,
            "Request deadline or cancellation reached",
            Some("TIME_BUDGET_EXCEEDED"),
        ));
    }
    match dispatcher.call(principal, method, input, budget) {
        Ok(output) => {
            if validator.validate(&function.output, &output).is_err() {
                encode_response(error(
                    id,
                    -32603,
                    "Service output violates the canonical contract",
                    Some("OUTPUT_SCHEMA_INVALID"),
                ))
            } else {
                encode_response(json!({"jsonrpc":"2.0", "id":id, "result":output}))
            }
        }
        Err(ServiceError { code, message, .. }) => {
            encode_response(error(id, -32000, message, Some(code)))
        }
    }
}

fn contexts_allowed(value: &Value, principal: &AuthenticatedPrincipal) -> bool {
    match value {
        Value::Object(map) => map.iter().all(|(key, value)| {
            match key.as_str() {
                "contextId" => value
                    .as_str()
                    .is_some_and(|id| principal.permits_context(id)),
                "contextIds" => value.as_array().is_some_and(|ids| {
                    ids.iter()
                        .all(|v| v.as_str().is_some_and(|id| principal.permits_context(id)))
                }),
                // Imported authoring documents and opaque extension data are
                // not runtime session selectors. Schema validation remains in
                // force; interpreting these as permissions would be unsafe.
                "extensions" => true,
                _ => contexts_allowed(value, principal),
            }
        }),
        Value::Array(values) => values.iter().all(|v| contexts_allowed(v, principal)),
        _ => true,
    }
}
fn valid_id(id: &Value) -> bool {
    id.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 128)
        || id.as_i64().is_some()
        || id.as_u64().is_some()
}
fn error(
    id: Value,
    code: i32,
    message: &'static str,
    application_code: Option<&'static str>,
) -> Value {
    let mut payload = json!({"code":code,"message":message});
    if let Some(code) = application_code {
        payload["data"] = json!({"code":code});
    }
    json!({"jsonrpc":"2.0","id":id,"error":payload})
}
fn encode_response(value: Value) -> Vec<u8> {
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    match encode_json(&value) {
        Ok(bytes) if parse_json_with_limits(&bytes, JsonLimits { max_bytes:MAX_CONTROL_BYTES,
            max_depth:64,max_nodes:MAX_CONTROL_NODES }).is_ok() => bytes,
        _ => encode_json(&error(id,-32603,"Response budget exceeded",Some("BUDGET_EXCEEDED")))
            .unwrap_or_else(|_| br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Response budget exceeded"}}"#.to_vec()),
    }
}

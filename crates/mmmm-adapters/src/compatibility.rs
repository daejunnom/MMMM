use crate::{
    Access, ActionReadiness, AdapterError, Availability, Binding, BindingValue, CommandResultCodec,
    CompatibilityBindRequest, CompatibilityEvidence, Completion, CompletionProbe, EnvironmentRef,
    ExecutionSource, FileOperation, Initialization, JavaResultCodec, Loader, Origin, OriginKind,
    ProviderDescriptor, ProviderRegistry, Receiver, RegistrationMode, RegistrationObservation,
    RouteContext, Side, decode, wire,
};
use mmmm_contracts::{BindingId, Sha256Digest, TargetId, canonical_digest, projected_digest};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Loaded from the runtime's authority policy. The request's approval reference
/// and the profile's provenance never create this approval themselves.
#[derive(Clone, Debug)]
pub struct ProfileApproval {
    pub reference: String,
    pub profile_digest: Sha256Digest,
    pub source_id: String,
    pub allowed_interface_digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadAffinity {
    ServerMain,
    ClientMain,
    External,
}

impl ThreadAffinity {
    fn matches(self, side: Side) -> bool {
        matches!(
            (self, side),
            (Self::ServerMain, Side::Server)
                | (Self::ClientMain, Side::Client)
                | (Self::External, Side::External)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JavaSignature {
    pub owner_class: String,
    pub method_name: String,
    pub parameter_types: Vec<String>,
    pub return_type: String,
    pub receiver: Receiver,
}

/// Metadata inspection outcomes supplied by the host. This crate has no JVM,
/// command parser, process launcher or network probe and cannot initialize a
/// class while detecting a binding. The host must inspect without effects.
#[derive(Clone, Debug, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum BindingSupport {
    Command {
        root_literal: String,
        command_tree_revision: Sha256Digest,
        execution_source: ExecutionSource,
        result_codec: CommandResultCodec,
    },
    File {
        approved_resource_resolver: String,
        codecs: BTreeSet<String>,
        operations: BTreeSet<FileOperation>,
    },
    PublicJava {
        signature: JavaSignature,
        public_lookup_checked: bool,
        initialization_performed: bool,
        thread_affinity: ThreadAffinity,
        receiver_resolver: Option<String>,
        scoped_handle_types: BTreeSet<String>,
    },
    RegisteredRpc {
        target_id: TargetId,
        method: String,
        endpoint_contract_digest: Sha256Digest,
        input_schema: Value,
        output_schema: Value,
        result_codec: String,
        registered_local: bool,
    },
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceObservation {
    pub environment: EnvironmentRef,
    pub loader: Loader,
    /// For an external tool this is its output target's exact game version.
    pub target_game_version: String,
    pub mod_id: Option<String>,
    /// The exact observed mod or tool version; never a range or inferred name.
    pub mod_version: String,
    pub host_protocol_version: String,
    pub implementation_digest: Sha256Digest,
    pub support: BindingSupport,
    pub loaded: bool,
    pub connected: bool,
    pub availability: Availability,
    pub evidence: CompatibilityEvidence,
    pub readiness: ActionReadiness,
}

impl InterfaceObservation {
    /// The approval pins these authenticated interface facts. Readiness and
    /// connection state can change without changing signature identity; both
    /// remain included separately in the inventory revision.
    pub fn interface_digest(&self) -> Result<Sha256Digest, AdapterError> {
        Ok(canonical_digest(&json!({
            "kind": "mmmm-interface-observation/1", "side": self.environment.execution_side(),
            "loader": self.loader, "targetGameVersion": self.target_game_version,
            "modId": self.mod_id, "modVersion": self.mod_version,
            "hostProtocolVersion": self.host_protocol_version,
            "implementationDigest": self.implementation_digest, "support": self.support,
        }))?)
    }
}

impl ProviderRegistry {
    pub fn bind_compatibility(
        &mut self,
        request: &Value,
        context: &RouteContext,
        approval: &ProfileApproval,
        interface: &InterfaceObservation,
    ) -> Result<ProviderDescriptor, AdapterError> {
        let request: CompatibilityBindRequest = decode("CompatibilityBindRequest", request)?;
        let profile = &request.profile;
        let profile_digest = projected_digest(
            "CompatibilityProfile",
            &wire("CompatibilityProfile", profile)?,
        )?;
        if request.profile_digest != profile_digest
            || approval.profile_digest != profile_digest
            || request.approved_profile_ref != approval.reference
            || approval.source_id.is_empty()
            || approval.allowed_interface_digest != interface.interface_digest()?
        {
            return Err(AdapterError::new(
                "PROFILE_UNTRUSTED",
                "Approved reference, profile digest or interface authority pin does not match",
            ));
        }
        if &request.context_id != context.context_id()
            || &request.environment != context.environment()
            || request.environment != interface.environment
            || interface.host_protocol_version != crate::HOST_PROTOCOL_VERSION
        {
            return Err(AdapterError::new(
                "INTERFACE_MISMATCH",
                "Profile binding does not match the current context and environment epoch",
            ));
        }
        let applicability = &profile.applicability;
        if applicability.loader != interface.loader
            || Some(applicability.side) != interface.environment.execution_side()
            || profile.action.side != applicability.side
            || !applicability
                .supported_game_versions
                .contains(&interface.target_game_version)
            || !applicability
                .supported_mod_versions
                .contains(&interface.mod_version)
            || !applicability
                .supported_game_versions
                .iter()
                .all(|version| exact_version(version))
            || !applicability
                .supported_mod_versions
                .iter()
                .all(|version| exact_version(version))
            || !exact_version(&interface.target_game_version)
            || !exact_version(&interface.mod_version)
        {
            return Err(AdapterError::new(
                "INTERFACE_MISMATCH",
                "Loader, side or exact observed version is not applicable",
            ));
        }
        if interface.loader != Loader::External && applicability.mod_id.is_none() {
            return Err(AdapterError::new(
                "INTERFACE_MISMATCH",
                "Game compatibility requires an exact mod identity",
            ));
        }
        if applicability
            .mod_id
            .as_ref()
            .is_some_and(|id| Some(id) != interface.mod_id.as_ref())
        {
            return Err(AdapterError::new(
                "INTERFACE_MISMATCH",
                "Observed mod or tool identity differs",
            ));
        }
        if profile.action.implementation_digest != interface.implementation_digest {
            return Err(AdapterError::new(
                "INTERFACE_MISMATCH",
                "Observed implementation digest differs even if its version name matches",
            ));
        }
        if interface.evidence < CompatibilityEvidence::InterfaceChecked {
            return Err(AdapterError::new(
                "INTERFACE_MISMATCH",
                "Interface inspection has not been confirmed by the host",
            ));
        }
        validate_binding(&profile.binding, &profile.action, &interface.support)?;
        let binding_material = json!({
            "kind": "mmmm-compatibility-binding/1", "profileDigest": profile_digest,
            "environment": request.environment, "interfaceDigest": interface.interface_digest()?,
        });
        let binding_digest = canonical_digest(&binding_material)?;
        let binding_id = BindingId::new(format!("compat-{}", binding_digest.as_str()))
            .map_err(|error| AdapterError::new("INCOMPATIBLE_CONTRACT", error.to_string()))?;
        let provider_id = mmmm_contracts::ProviderId::new(profile.profile_id.as_str())
            .map_err(|error| AdapterError::new("INCOMPATIBLE_CONTRACT", error.to_string()))?;
        let origin = Origin {
            kind: OriginKind::LocalProfile,
            source_id: approval.source_id.clone(),
            source_digest: Some(profile_digest),
        };
        let descriptor = ProviderDescriptor {
            contract_version: mmmm_contracts::CONTRACT_VERSION.into(),
            provider_id,
            binding_id,
            provider_version: profile.profile_version.clone(),
            environment: request.environment,
            registration_mode: RegistrationMode::Compatibility,
            origin: origin.clone(),
            host_protocol_version: interface.host_protocol_version.clone(),
            actions: vec![profile.action.clone()],
            compatibility_evidence: interface.evidence,
            availability: interface.availability,
        };
        let action_id = profile.action.action_id.clone();
        let observation = RegistrationObservation {
            environment: interface.environment.clone(),
            origin,
            host_protocol_version: interface.host_protocol_version.clone(),
            loaded: interface.loaded,
            connected: interface.connected,
            availability: interface.availability,
            evidence: interface.evidence,
            implementation_digests: BTreeMap::from([(
                action_id.clone(),
                interface.implementation_digest.clone(),
            )]),
            action_readiness: BTreeMap::from([(action_id, interface.readiness.clone())]),
        };
        self.insert_observed(descriptor, observation, Some(profile.binding.clone()))
    }
}

fn exact_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
        && version != "latest"
        && version != "main"
}

fn validate_binding(
    binding: &Binding,
    action: &crate::ActionDescriptor,
    support: &BindingSupport,
) -> Result<(), AdapterError> {
    match (binding, support) {
        (
            Binding::Command {
                parts,
                execution_source,
                completion_probe,
                result_codec,
            },
            BindingSupport::Command {
                root_literal,
                execution_source: observed_source,
                result_codec: observed_codec,
                ..
            },
        ) => {
            if !matches!(parts.first(), Some(BindingValue::Literal { value: Value::String(root) }) if root == root_literal && command_atom(root))
                || execution_source != observed_source
                || result_codec != observed_codec
            {
                return Err(AdapterError::new(
                    "INTERFACE_MISMATCH",
                    "Exact command root, source or result codec differs",
                ));
            }
            if (*completion_probe == CompletionProbe::NotObservable
                && action.completion != Completion::Unobservable)
                || (*completion_probe == CompletionProbe::SynchronousReturn
                    && action.completion != Completion::Synchronous)
            {
                return Err(AdapterError::new(
                    "UNSUPPORTED_BINDING",
                    "Command completion policy cannot imply a stronger observable result",
                ));
            }
            for value in parts {
                validate_value(value)?;
            }
        }
        (
            Binding::File {
                operation,
                resource_argument_pointer,
                codec,
                ..
            },
            BindingSupport::File {
                approved_resource_resolver,
                codecs,
                operations,
            },
        ) => {
            validate_pointer(resource_argument_pointer)?;
            if approved_resource_resolver.is_empty()
                || !codecs.contains(codec)
                || !operations.contains(operation)
            {
                return Err(AdapterError::new(
                    "UNSUPPORTED_BINDING",
                    "File operation lacks an approved resource resolver or exact codec",
                ));
            }
            if (*operation == FileOperation::Read && action.effect != crate::Effect::Read)
                || (*operation != FileOperation::Read && action.effect == crate::Effect::Read)
            {
                return Err(AdapterError::new(
                    "UNSUPPORTED_BINDING",
                    "File operation effect differs from the action contract",
                ));
            }
        }
        (
            Binding::PublicJava {
                owner_class,
                method_name,
                parameter_types,
                return_type,
                receiver,
                receiver_handle_type,
                arguments,
                result_codec,
                initialization,
                access,
            },
            BindingSupport::PublicJava {
                signature,
                public_lookup_checked,
                initialization_performed,
                thread_affinity,
                receiver_resolver,
                scoped_handle_types,
            },
        ) => {
            if !public_lookup_checked
                || *initialization_performed
                || *initialization != Initialization::InvokeOnly
                || *access != Access::PublicOnly
                || !thread_affinity.matches(action.side)
                || !java_class(owner_class)
                || !java_identifier(method_name)
            {
                return Err(AdapterError::new(
                    "UNSUPPORTED_BINDING",
                    "Java detection requires exact public metadata without initialization and an observed execution queue",
                ));
            }
            let expected = JavaSignature {
                owner_class: owner_class.clone(),
                method_name: method_name.clone(),
                parameter_types: parameter_types.clone(),
                return_type: return_type.clone(),
                receiver: *receiver,
            };
            if &expected != signature || parameter_types.len() != arguments.len() {
                return Err(AdapterError::new(
                    "INTERFACE_MISMATCH",
                    "Exact Java signature or argument count differs",
                ));
            }
            if *receiver == Receiver::RegisteredHandle
                && (receiver_resolver.as_ref().is_none_or(String::is_empty)
                    || receiver_handle_type
                        .as_ref()
                        .is_none_or(|kind| !scoped_handle_types.contains(kind)))
            {
                return Err(AdapterError::new(
                    "UNSUPPORTED_RECEIVER",
                    "Registered receiver lacks a scoped host resolver",
                ));
            }
            if *receiver == Receiver::Static && receiver_handle_type.is_some() {
                return Err(AdapterError::new(
                    "UNSUPPORTED_BINDING",
                    "A static signature cannot select a receiver handle type",
                ));
            }
            for (parameter, argument) in parameter_types.iter().zip(arguments) {
                validate_value(argument)?;
                if !java_value_type(parameter)
                    && !matches!(argument, BindingValue::Handle { expected_type, .. } if expected_type == parameter && scoped_handle_types.contains(expected_type))
                {
                    return Err(AdapterError::new(
                        "UNSUPPORTED_BINDING",
                        "Java parameter is outside scalar, JSON list/map or registered scoped handle values",
                    ));
                }
            }
            let return_supported = match result_codec {
                JavaResultCodec::Scalar => java_scalar_type(return_type),
                JavaResultCodec::JsonCompatible => {
                    matches!(return_type.as_str(), "java.util.List" | "java.util.Map")
                }
                JavaResultCodec::CompletionStageJson => {
                    return_type == "java.util.concurrent.CompletionStage"
                        && action.completion == Completion::Job
                }
                JavaResultCodec::RegisteredHandle => scoped_handle_types.contains(return_type),
            };
            if !return_supported {
                return Err(AdapterError::new(
                    "UNSUPPORTED_BINDING",
                    "Java return type and result codec are unsupported or inconsistent",
                ));
            }
        }
        (
            Binding::RegisteredRpc {
                target_id,
                method,
                arguments,
                result_codec,
            },
            BindingSupport::RegisteredRpc {
                target_id: observed_target,
                method: observed_method,
                input_schema,
                output_schema,
                result_codec: observed_codec,
                registered_local,
                ..
            },
        ) => {
            if !registered_local
                || target_id != observed_target
                || method != observed_method
                || result_codec != observed_codec
            {
                return Err(AdapterError::new(
                    "INTERFACE_MISMATCH",
                    "RPC target is not registered locally or its exact endpoint contract differs",
                ));
            }
            // Endpoint schemas can differ from the public action schemas: the
            // restricted argument map can rename/select values. The interface
            // approval pins both endpoint schemas and the registered codec.
            mmmm_contracts::ContractValidator::shared()?.compile_action_schema(input_schema)?;
            mmmm_contracts::ContractValidator::shared()?.compile_action_schema(output_schema)?;
            if arguments.len() > 256 || arguments.keys().any(|key| key.len() > 128) {
                return Err(AdapterError::new(
                    "UNSUPPORTED_BINDING",
                    "RPC argument mapping exceeds bounded limits",
                ));
            }
            if method.is_empty() || method.len() > 128 || method.chars().any(char::is_control) {
                return Err(AdapterError::new(
                    "UNSUPPORTED_BINDING",
                    "RPC method has invalid lexical form",
                ));
            }
            for value in arguments.values() {
                validate_value(value)?;
            }
        }
        _ => {
            return Err(AdapterError::new(
                "UNSUPPORTED_BINDING",
                "No approved executor matches this binding kind",
            ));
        }
    }
    Ok(())
}

fn validate_value(value: &BindingValue) -> Result<(), AdapterError> {
    match value {
        BindingValue::Literal { value } if value.is_array() || value.is_object() => {
            Err(AdapterError::new(
                "UNSUPPORTED_BINDING",
                "Profile literal values are scalar or null",
            ))
        }
        BindingValue::Argument { pointer, .. } => validate_pointer(pointer),
        BindingValue::Handle {
            argument_pointer,
            expected_type,
        } => {
            validate_pointer(argument_pointer)?;
            if expected_type.is_empty() {
                return Err(AdapterError::new(
                    "UNSUPPORTED_BINDING",
                    "Handle type is empty",
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(crate) fn validate_pointer(pointer: &str) -> Result<(), AdapterError> {
    if !pointer.starts_with('/') || pointer.len() > 1024 || pointer.split('/').count() > 65 {
        return Err(AdapterError::new(
            "UNSUPPORTED_BINDING",
            "Mapping requires a bounded non-root RFC6901 JSON Pointer",
        ));
    }
    let mut characters = pointer.chars();
    while let Some(character) = characters.next() {
        if character == '~' && !matches!(characters.next(), Some('0' | '1')) {
            return Err(AdapterError::new(
                "UNSUPPORTED_BINDING",
                "JSON Pointer contains an invalid escape",
            ));
        }
    }
    Ok(())
}

fn command_atom(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'-' | b'.'))
}

fn java_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(byte) if byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
}

fn java_class(value: &str) -> bool {
    value.len() <= 256 && value.split('.').all(java_identifier)
}

fn java_scalar_type(value: &str) -> bool {
    matches!(
        value,
        "java.lang.String"
            | "boolean"
            | "java.lang.Boolean"
            | "int"
            | "java.lang.Integer"
            | "float"
            | "java.lang.Float"
            | "double"
            | "java.lang.Double"
    )
}

fn java_value_type(value: &str) -> bool {
    java_scalar_type(value) || matches!(value, "java.util.List" | "java.util.Map")
}

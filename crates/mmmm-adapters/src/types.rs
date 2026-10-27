use mmmm_contracts::{
    ActionId, BindingId, CapabilityId, CompatibilityProfileId, ContextId, GameInstanceId,
    ProviderId, SessionEpoch, Sha256Digest, TargetId, ToolHostId, WorkspaceId, WorldId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

macro_rules! wire_enum {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
    };
}

wire_enum!(Side {
    Server,
    Client,
    External
});
wire_enum!(GameSide { Server, Client });
wire_enum!(RegistrationMode {
    Provider,
    Compatibility
});
wire_enum!(OriginKind {
    Builtin,
    LoaderEntrypoint,
    LocalProfile,
    RegisteredService
});
wire_enum!(Availability {
    Available,
    WorldRequired,
    PermissionRequired,
    Incompatible,
    Disabled,
    Disconnected
});
wire_enum!(CompatibilityEvidence {
    Declared,
    InterfaceChecked,
    FixtureVerified,
    GameVerified
});
wire_enum!(VersionEvidence {
    Declared,
    InterfaceChecked,
    FixtureVerified,
    RuntimeVerified
});
wire_enum!(Effect {
    Read,
    Write,
    Unknown
});
wire_enum!(Planning { Pure, Unsupported });
wire_enum!(Completion {
    Synchronous,
    Job,
    Unobservable
});
wire_enum!(Cancellation {
    None,
    QueuedOnly,
    Cooperative
});
wire_enum!(Recovery {
    None,
    ProviderUndo,
    FileSnapshot,
    ExplicitPatch
});
wire_enum!(Idempotency {
    Read,
    ProviderKeyed,
    CoordinatorOnly,
    None
});
wire_enum!(VerificationRequirement {
    SchemaOnly,
    ProviderCompletion,
    IndependentReadback
});
wire_enum!(ContextField {
    World,
    Dimension,
    Executor,
    Origin,
    Rotation,
    Anchor,
    Selection,
    Project
});
wire_enum!(Loader {
    Fabric,
    Neoforge,
    External
});
wire_enum!(Severity {
    Info,
    Warning,
    Error
});

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnvironmentRef {
    Game {
        #[serde(rename = "gameInstanceId")]
        game_instance_id: GameInstanceId,
        #[serde(rename = "sessionEpoch")]
        session_epoch: SessionEpoch,
        #[serde(rename = "worldId", skip_serializing_if = "Option::is_none")]
        world_id: Option<WorldId>,
        side: GameSide,
    },
    External {
        #[serde(rename = "toolHostId")]
        tool_host_id: ToolHostId,
        #[serde(rename = "sessionEpoch")]
        session_epoch: SessionEpoch,
        side: ExternalSide,
    },
    Offline {
        #[serde(rename = "workspaceId")]
        workspace_id: WorkspaceId,
        side: OfflineSide,
    },
}

wire_enum!(ExternalSide { External });
wire_enum!(OfflineSide { Offline });

impl EnvironmentRef {
    pub fn execution_side(&self) -> Option<Side> {
        match self {
            Self::Game {
                side: GameSide::Server,
                ..
            } => Some(Side::Server),
            Self::Game {
                side: GameSide::Client,
                ..
            } => Some(Side::Client),
            Self::External { .. } => Some(Side::External),
            Self::Offline { .. } => None,
        }
    }

    pub fn world_present(&self) -> bool {
        matches!(
            self,
            Self::Game {
                world_id: Some(_),
                ..
            }
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Origin {
    pub kind: OriginKind,
    pub source_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_digest: Option<Sha256Digest>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActionDescriptor {
    pub action_id: ActionId,
    pub contract_version: String,
    pub title: String,
    pub summary: String,
    // Only these two fields carry extensible JSON, because the contract defines
    // independent action schemas. Both are compiled offline at registration.
    pub semantic_kind: CapabilityId,
    pub input_schema: Value,
    pub output_schema: Value,
    pub side: Side,
    pub required_context: Vec<ContextField>,
    pub effect: Effect,
    pub planning: Planning,
    pub completion: Completion,
    pub cancellation: Cancellation,
    pub recovery: Recovery,
    pub idempotency: Idempotency,
    pub guarantees: Vec<String>,
    pub limitations: Vec<String>,
    pub required_permissions: Vec<String>,
    pub verification_requirement: VerificationRequirement,
    pub implementation_digest: Sha256Digest,
    pub version_evidence: VersionEvidence,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderDescriptor {
    pub contract_version: String,
    pub provider_id: ProviderId,
    pub binding_id: BindingId,
    pub provider_version: String,
    pub environment: EnvironmentRef,
    pub registration_mode: RegistrationMode,
    pub origin: Origin,
    pub host_protocol_version: String,
    pub actions: Vec<ActionDescriptor>,
    pub compatibility_evidence: CompatibilityEvidence,
    pub availability: Availability,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Diagnostic {
    pub code: String,
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<BindingId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl Diagnostic {
    pub(crate) fn warning(
        code: &str,
        message: impl Into<String>,
        binding: Option<BindingId>,
    ) -> Self {
        Self {
            code: code.into(),
            severity: Severity::Warning,
            message: message.into(),
            object_id: binding,
            path: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderInventory {
    pub inventory_revision: Sha256Digest,
    pub providers: Vec<ProviderDescriptor>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DiscoveryRequest {
    pub context_id: ContextId,
    pub environment: EnvironmentRef,
    pub allow_effects: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteRequest {
    pub context_id: ContextId,
    pub semantic_kind: CapabilityId,
    pub required_guarantees: Vec<String>,
    pub acceptable_loss_codes: Vec<String>,
    pub preferred_binding_id: Option<BindingId>,
    pub inventory_revision: Sha256Digest,
}

wire_enum!(RouteStatus {
    Selected,
    Unavailable
});

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteResolution {
    pub status: RouteStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<BindingId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_id: Option<ActionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<Sha256Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementation_digest: Option<Sha256Digest>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Host-side facts authenticated by the runtime, not fields accepted from a
/// provider's descriptor or a CompatibilityProfile. `None` loss information
/// means unknown, while `Some(empty)` explicitly declares no possible loss.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionReadiness {
    pub ready: bool,
    pub possible_loss_codes: Option<BTreeSet<String>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationObservation {
    pub environment: EnvironmentRef,
    pub origin: Origin,
    pub host_protocol_version: String,
    pub loaded: bool,
    pub connected: bool,
    pub availability: Availability,
    pub evidence: CompatibilityEvidence,
    pub implementation_digests: BTreeMap<ActionId, Sha256Digest>,
    pub action_readiness: BTreeMap<ActionId, ActionReadiness>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompatibilityProfile {
    pub contract_version: String,
    pub profile_id: CompatibilityProfileId,
    pub profile_version: String,
    pub provenance: ProfileProvenance,
    #[serde(rename = "match")]
    pub applicability: Applicability,
    pub action: ActionDescriptor,
    pub binding: Binding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProfileProvenance {
    pub author: String,
    pub license_expression: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Applicability {
    pub loader: Loader,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mod_id: Option<String>,
    pub supported_game_versions: Vec<String>,
    pub supported_mod_versions: Vec<String>,
    pub side: Side,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompatibilityBindRequest {
    pub profile: CompatibilityProfile,
    pub profile_digest: Sha256Digest,
    pub context_id: ContextId,
    pub environment: EnvironmentRef,
    pub approved_profile_ref: String,
}

wire_enum!(ArgumentCodec {
    Integer,
    Float,
    ResourceId,
    QuotedText,
    Boolean,
    JsonValue,
    String
});
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MappedContextField {
    ExecutorHandle,
    Dimension,
    Origin,
    RotationDegrees,
    Anchor,
    SelectionRef,
    ProjectId,
}
wire_enum!(ExecutionSource {
    ContextExecutor,
    ExplicitServer
});
wire_enum!(CompletionProbe {
    SynchronousReturn,
    NotObservable
});
wire_enum!(CommandResultCodec { CommandFeedbackV1 });
wire_enum!(FileOperation {
    Read,
    WriteStaged,
    ExportStaged
});
wire_enum!(Reload {
    None,
    SeparateAction
});
wire_enum!(Receiver {
    Static,
    RegisteredHandle
});
wire_enum!(JavaResultCodec {
    Scalar,
    JsonCompatible,
    CompletionStageJson,
    RegisteredHandle
});
wire_enum!(Initialization { InvokeOnly });
wire_enum!(Access { PublicOnly });

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BindingValue {
    Literal {
        value: Value,
    },
    Argument {
        pointer: String,
        codec: ArgumentCodec,
    },
    Context {
        field: MappedContextField,
    },
    Handle {
        #[serde(rename = "argumentPointer")]
        argument_pointer: String,
        #[serde(rename = "expectedType")]
        expected_type: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Binding {
    Command {
        parts: Vec<BindingValue>,
        #[serde(rename = "executionSource")]
        execution_source: ExecutionSource,
        #[serde(rename = "completionProbe")]
        completion_probe: CompletionProbe,
        #[serde(rename = "resultCodec")]
        result_codec: CommandResultCodec,
    },
    File {
        operation: FileOperation,
        #[serde(rename = "resourceArgumentPointer")]
        resource_argument_pointer: String,
        codec: String,
        reload: Reload,
    },
    PublicJava {
        #[serde(rename = "ownerClass")]
        owner_class: String,
        #[serde(rename = "methodName")]
        method_name: String,
        #[serde(rename = "parameterTypes")]
        parameter_types: Vec<String>,
        #[serde(rename = "returnType")]
        return_type: String,
        receiver: Receiver,
        #[serde(rename = "receiverHandleType", skip_serializing_if = "Option::is_none")]
        receiver_handle_type: Option<String>,
        arguments: Vec<BindingValue>,
        #[serde(rename = "resultCodec")]
        result_codec: JavaResultCodec,
        initialization: Initialization,
        access: Access,
    },
    RegisteredRpc {
        #[serde(rename = "targetId")]
        target_id: TargetId,
        method: String,
        arguments: BTreeMap<String, BindingValue>,
        #[serde(rename = "resultCodec")]
        result_codec: String,
    },
}

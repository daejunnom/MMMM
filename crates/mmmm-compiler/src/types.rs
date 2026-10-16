use mmmm_contracts::{ExprId, ResourceId, Sha256Digest, StateId, SymbolId, TargetProfileId};
use mmmm_domain::{Diagnostic, types::ResourceRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumericType {
    Int32,
    Float32,
}

impl NumericType {
    pub(crate) const fn command_name(self) -> &'static str {
        match self {
            Self::Int32 => "integer",
            Self::Float32 => "float",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExprOp {
    Constant,
    State,
    ContextComponent,
    Add,
    Sub,
    Mul,
    Div,
    FloorDiv,
    Min,
    Max,
    Clamp,
    Sin,
    Cos,
    Sqrt,
    ToIntFloor,
    ToIntTrunc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextComponent {
    OriginX,
    OriginY,
    OriginZ,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExprNode {
    pub expr_id: ExprId,
    pub op: ExprOp,
    #[serde(rename = "type")]
    pub numeric_type: NumericType,
    pub unit: String,
    pub inputs: Vec<ExprId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Number>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_id: Option<StateId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_component: Option<ContextComponent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStorage {
    Scoreboard,
    StorageNbt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rounding {
    None,
    Floor,
    Trunc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MathCompileRequest {
    pub nodes: Vec<ExprNode>,
    pub root_expr_id: ExprId,
    pub target_profile_id: TargetProfileId,
    pub output_storage: OutputStorage,
    pub rounding: Rounding,
    pub symbol_table: ResourceRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompileFragment {
    pub source: ResourceRef,
    pub defined_symbols: Vec<SymbolId>,
    pub referenced_symbols: Vec<SymbolId>,
    pub target_profile_id: TargetProfileId,
    pub losses: Vec<Value>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedFunctionContract {
    pub inputs: Vec<SymbolId>,
    pub outputs: Vec<SymbolId>,
    pub state_reads: Vec<String>,
    pub state_writes: Vec<String>,
    pub execution_context: &'static str,
    pub reentrancy: &'static str,
    pub scheduled_callbacks: Vec<String>,
    pub cleanup: Vec<String>,
    pub requirements: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct StagedResource {
    pub reference: ResourceRef,
    pub bytes: Vec<u8>,
}

impl StagedResource {
    pub(crate) fn new(id: ResourceId, media_type: &str, bytes: Vec<u8>) -> Self {
        Self {
            reference: ResourceRef {
                resource_id: id,
                sha256: mmmm_contracts::raw_digest(&bytes),
                media_type: media_type.into(),
                size_bytes: bytes.len() as u64,
            },
            bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerPins {
    pub input_digest: Sha256Digest,
    pub compiler_digest: Sha256Digest,
    pub target_profile_digest: Sha256Digest,
    pub target_artifact_digest: Sha256Digest,
    pub symbol_authority_digest: Sha256Digest,
}

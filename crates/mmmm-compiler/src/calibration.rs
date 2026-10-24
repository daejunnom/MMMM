//! Fixed calibration programs for an explicitly approved copied-world runner.
//!
//! This is normative source construction, not a VerifiedTarget, export draft,
//! execution permission, loaded-function proof, or evidence of an actual run.
//! The runner must authenticate the exact loaded bytes and independently capture
//! the preseed, selected command site, final typed output, and complete scratch.
//! Native providers use the same renderer as ordinary math compilation. Source
//! syntax follows the primary Java 26.3 release; syntax is not runtime evidence.

use crate::{
    BindingAddress, ExprNode, ExprOp, NumericType, OutputStorage, Rounding, SymbolBinding,
};
use mmmm_contracts::{
    ExprId, ResourceLocation, Sha256Digest, SymbolId, canonical_bytes, raw_digest,
};
use mmmm_domain::DomainError;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const MAX_COMMANDS: usize = 128;
const MAX_COMMAND_BYTES: usize = 8192;
const MAX_PROGRAM_BYTES: usize = 64 * 1024;

/// Closed comparison recipes for the private calibration installer. Selecting
/// one does not establish an installed root, loaded source, or run authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalibrationSourceKind {
    Numeric47,
    PackCase,
}

impl CalibrationSourceKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Numeric47 => "numeric47",
            Self::PackCase => "pack_case",
        }
    }
    pub const fn root_basename(self) -> &'static str {
        match self {
            Self::Numeric47 => "mmmm-calibration-normative47",
            Self::PackCase => "mmmm-calibration-pack-case",
        }
    }
    pub const fn entry_count(self) -> usize {
        match self {
            Self::Numeric47 => 48,
            Self::PackCase => 3,
        }
    }
    pub const fn function_count(self) -> usize {
        match self {
            Self::Numeric47 => 47,
            Self::PackCase => 2,
        }
    }
    pub fn source_entries(self) -> Result<BTreeMap<String, Vec<u8>>, DomainError> {
        match self {
            Self::Numeric47 => Ok(
                crate::calibration_dispatch::CalibrationDispatchPlan::normative47()?
                    .source_entries()
                    .clone(),
            ),
            Self::PackCase => Ok(CalibrationPackProgram::java_26_3()?
                .source_entries()
                .clone()),
        }
    }
}

macro_rules! calibration_cases {
    ($($variant:ident => $name:literal),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub enum CalibrationCase { $($variant),+ }
        impl CalibrationCase {
            pub const ALL: &[Self] = &[$(Self::$variant),+];
            pub const CASE_IDS: &[&str] = &[$($name),+];
            pub const fn case_id(self) -> &'static str { match self { $(Self::$variant => $name),+ } }
            pub fn from_case_id(value: &str) -> Option<Self> {
                match value { $($name => Some(Self::$variant)),+, _ => None }
            }
        }
    };
}

calibration_cases! {
    Int32ScoreZero => "int32_score_zero",
    Int32NbtMin => "int32_nbt_min",
    Int32NbtMax => "int32_nbt_max",
    FloatNbtFraction => "float_nbt_fraction",
    FloatBinary32Chain => "float_binary32_chain",
    IntDivNegative => "int_div_negative",
    IntFloorDivNegative => "int_floor_div_negative",
    FloatFromFloatNegative => "float_from_float_negative",
    FloatFloorThenFromFloatNegative => "float_floor_then_from_float_negative",
    IntAddOverflow => "int_add_overflow",
    IntSubOverflow => "int_sub_overflow",
    IntMulOverflow => "int_mul_overflow",
    IntDivOverflow => "int_div_overflow",
    IntFloorDivOverflow => "int_floor_div_overflow",
    IntDivZero => "int_div_zero",
    IntFloorDivZero => "int_floor_div_zero",
    FloatFromFloatUpperRange => "float_from_float_upper_range",
    FloatFromFloatLowerRange => "float_from_float_lower_range",
    FloatDivPositiveZero => "float_div_positive_zero",
    FloatDivZeroZero => "float_div_zero_zero",
    FloatSqrtNegative => "float_sqrt_negative",
    FloatMulOverflow => "float_mul_overflow",
    FloatUndefinedProvider => "float_undefined_provider",
    ScorePresentZeroLazyFallback => "score_present_zero_lazy_fallback",
    FloatStoragePresentFractionLazyFallback => "float_storage_present_fraction_lazy_fallback",
    ScoreAbsentFallback => "score_absent_fallback",
    FloatStorageAbsentFallback => "float_storage_absent_fallback",
    FloatFiniteZeroGuard => "float_finite_zero_guard",
    LaterNodeFailureCleanup => "later_node_failure_cleanup",
    NativeComputeFloatReturnFloorVsNbt => "native_compute_float_return_floor_vs_nbt",
    FloatSignedZero => "float_signed_zero",
    IntAddNormal => "int_add_normal",
    IntSubNormal => "int_sub_normal",
    IntMulNormal => "int_mul_normal",
    IntMinNormal => "int_min_normal",
    IntMaxNormal => "int_max_normal",
    IntClampNormal => "int_clamp_normal",
    FloatAddNormal => "float_add_normal",
    FloatSubNormal => "float_sub_normal",
    FloatMulNormal => "float_mul_normal",
    FloatDivNormal => "float_div_normal",
    FloatMinNormal => "float_min_normal",
    FloatMaxNormal => "float_max_normal",
    FloatClampNormal => "float_clamp_normal",
    FloatSinZero => "float_sin_zero",
    FloatCosZero => "float_cos_zero",
    FloatSqrtFour => "float_sqrt_four",
}

/// Expected native state, never observed state or an authority claim. f32 bits
/// retain tag identity and signed zero without admitting JSON NaN/Infinity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalibrationScalar {
    Absent,
    Score(i32),
    IntTag(i32),
    FloatTag { bits: u32 },
}

impl CalibrationScalar {
    fn to_value(self) -> Value {
        match self {
            Self::Absent => json!({"kind":"absent"}),
            Self::Score(value) => json!({"kind":"score","value":value}),
            Self::IntTag(value) => json!({"kind":"int_tag","value":value}),
            Self::FloatTag { bits } => json!({"kind":"float_tag","bits":format!("{bits:08x}")}),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalibrationExpectation {
    pub command_success: bool,
    /// None means this suite does not assert that selected command's numeric
    /// return. It never substitutes zero for an unavailable actual return.
    pub command_return: Option<i32>,
    pub ok_score: i32,
    pub output: CalibrationScalar,
    pub scratch_present: bool,
    pub preseed_score: i32,
    pub preseed_storage: CalibrationScalar,
}

impl CalibrationExpectation {
    fn to_value(self) -> Value {
        json!({"commandSuccess":self.command_success,"commandReturn":self.command_return,
            "okScore":self.ok_score,"output":self.output.to_value(),
            "scratchPresent":self.scratch_present,"staleOutputSeeded":true})
    }
}

/// A finite address inventory. Ownership must be established independently
/// before any initialization, preseed, evaluation, observation or cleanup.
#[derive(Debug, Clone)]
pub struct CalibrationScope {
    objective: String,
    storage: ResourceLocation,
    result_address: BindingAddress,
    input_addresses: Vec<BindingAddress>,
}

impl CalibrationScope {
    pub fn objective(&self) -> &str {
        &self.objective
    }
    pub fn storage(&self) -> &ResourceLocation {
        &self.storage
    }
    pub const fn scratch_path(&self) -> &'static str {
        "invocation"
    }
    pub fn result_address(&self) -> &BindingAddress {
        &self.result_address
    }
    pub fn input_addresses(&self) -> &[BindingAddress] {
        &self.input_addresses
    }
}

/// Private fields and the fixed enum constructor prevent caller source bytes,
/// source maps, labels and expected-value JSON from creating a program.
#[derive(Debug, Clone)]
pub struct CalibrationProgram {
    case: CalibrationCase,
    bytes: Vec<u8>,
    digest: Sha256Digest,
    invocation_command: String,
    commands: Vec<String>,
    command_stage_index: u32,
    preseed_end_index: u32,
    expectation: CalibrationExpectation,
    expected_readback: Value,
    scope: CalibrationScope,
    initialization_commands: Vec<String>,
    cleanup_commands: Vec<String>,
}

impl CalibrationProgram {
    pub fn for_case(case: CalibrationCase) -> Result<Self, DomainError> {
        let specification = specification(case);
        build(case, specification)
    }
    pub const fn case(&self) -> CalibrationCase {
        self.case
    }
    pub fn source_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn source_digest(&self) -> &Sha256Digest {
        &self.digest
    }
    pub fn invocation_command(&self) -> &str {
        &self.invocation_command
    }
    pub fn commands(&self) -> &[String] {
        &self.commands
    }
    /// Zero-based index in commands(), excluding comments. This names a native
    /// arithmetic/finite-check site, not the whole function's last return.
    pub const fn command_stage_index(&self) -> u32 {
        self.command_stage_index
    }
    /// Number of commands in the preseed prefix. Capture independently after
    /// this prefix and before executing the first evaluation command.
    pub const fn preseed_end_index(&self) -> u32 {
        self.preseed_end_index
    }
    pub fn expected_readback(&self) -> &Value {
        &self.expected_readback
    }
    pub const fn expectation(&self) -> &CalibrationExpectation {
        &self.expectation
    }
    pub fn scope(&self) -> &CalibrationScope {
        &self.scope
    }
    pub fn initialization_commands(&self) -> &[String] {
        &self.initialization_commands
    }
    pub fn cleanup_commands(&self) -> &[String] {
        &self.cleanup_commands
    }
}

/// A fixed calibration pack, not a product export or an installed pack proof.
/// Its native pair codec, singular function path, and owned call closure are
/// compared against independently read and authenticated loaded pack contents.
/// ZIP compression/container bytes remain the runtime's separate source pin.
#[derive(Debug, Clone)]
pub struct CalibrationPackProgram {
    entries: BTreeMap<String, Vec<u8>>,
    recipe_bytes: Vec<u8>,
    digest: Sha256Digest,
    commands: Vec<String>,
    invocation_command: String,
    function_ids: BTreeSet<String>,
    marker_address: BindingAddress,
    initialization_commands: Vec<String>,
    cleanup_commands: Vec<String>,
}

impl CalibrationPackProgram {
    pub const CASE_ID: &str = "data_pack_pair_function_dependency_closure";

    pub fn java_26_3() -> Result<Self, DomainError> {
        let root = "mmmm_calibration:pack/entry";
        let dependency = "mmmm_calibration:pack/dependency";
        let objective = "mcalpack";
        let commands = vec![
            format!("scoreboard players reset #marker {objective}"),
            format!("function {dependency}"),
            "return 1".into(),
        ];
        let dependency_commands = vec![
            format!("scoreboard players set #marker {objective} 1337"),
            "return 1".into(),
        ];
        let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        entries.insert(
            "pack.mcmeta".into(),
            canonical_bytes(&json!({"pack":{"description":"MMMM native calibration/1",
                "min_format":[121,0],"max_format":[121,0]}}))
            .map_err(|error| invalid(error.to_string()))?,
        );
        entries.insert(
            "data/mmmm_calibration/function/pack/entry.mcfunction".into(),
            pack_function_bytes(&commands)?,
        );
        entries.insert(
            "data/mmmm_calibration/function/pack/dependency.mcfunction".into(),
            pack_function_bytes(&dependency_commands)?,
        );
        let mut identity = Vec::new();
        for (path, bytes) in &entries {
            identity.extend_from_slice(&(path.len() as u64).to_le_bytes());
            identity.extend_from_slice(path.as_bytes());
            identity.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            identity.extend_from_slice(bytes);
        }
        let digest = raw_digest(&identity);
        Ok(Self {
            entries,
            recipe_bytes: identity,
            digest,
            commands,
            invocation_command: format!("function {root}"),
            function_ids: [root.into(), dependency.into()].into(),
            marker_address: BindingAddress::Score {
                holder: "#marker".into(),
                objective: objective.into(),
            },
            initialization_commands: vec![
                format!("scoreboard objectives add {objective} dummy"),
                format!("scoreboard players set #marker {objective} 7331"),
            ],
            cleanup_commands: vec![format!("scoreboard objectives remove {objective}")],
        })
    }
    pub fn source_entries(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.entries
    }
    /// Digest of length-framed ordered logical entries, not of a ZIP archive.
    pub fn program_digest(&self) -> &Sha256Digest {
        &self.digest
    }
    /// The original length-framed logical recipe bytes hashed by program_digest.
    /// These are neither the canonical source-bundle JSON nor ZIP bytes.
    pub fn canonical_recipe_bytes(&self) -> &[u8] {
        &self.recipe_bytes
    }
    pub fn commands(&self) -> &[String] {
        &self.commands
    }
    pub fn invocation_command(&self) -> &str {
        &self.invocation_command
    }
    /// The owned dependency dispatch in the root entry, zero-based.
    pub const fn command_stage_index(&self) -> u32 {
        1
    }
    pub fn function_ids(&self) -> &BTreeSet<String> {
        &self.function_ids
    }
    pub fn marker_address(&self) -> &BindingAddress {
        &self.marker_address
    }
    pub fn initialization_commands(&self) -> &[String] {
        &self.initialization_commands
    }
    pub fn cleanup_commands(&self) -> &[String] {
        &self.cleanup_commands
    }
}

fn pack_function_bytes(commands: &[String]) -> Result<Vec<u8>, DomainError> {
    let mut builder = CommandBuilder::default();
    for command in commands {
        builder.push(command.clone())?;
    }
    let header = b"# MMMM native pack calibration/1; requires independent owned objective\n";
    if header.len() + builder.bytes > MAX_PROGRAM_BYTES {
        return Err(invalid("Calibration pack function exceeds its byte budget"));
    }
    let mut bytes = Vec::with_capacity(header.len() + builder.bytes);
    bytes.extend_from_slice(header);
    for command in &builder.commands {
        bytes.extend_from_slice(command.as_bytes());
        bytes.push(b'\n');
    }
    Ok(bytes)
}

#[derive(Clone)]
enum ProbeNode {
    Input {
        scalar: CalibrationScalar,
        numeric: NumericType,
        score: bool,
    },
    Operation {
        op: ExprOp,
        numeric: NumericType,
        inputs: Vec<usize>,
    },
}

struct Specification {
    nodes: Vec<ProbeNode>,
    output: OutputStorage,
    rounding: Rounding,
    expectation: CalibrationExpectation,
    float_return_probe: bool,
}

fn input_int(value: i32) -> ProbeNode {
    ProbeNode::Input {
        scalar: CalibrationScalar::IntTag(value),
        numeric: NumericType::Int32,
        score: false,
    }
}
fn input_float(value: f32) -> ProbeNode {
    ProbeNode::Input {
        scalar: CalibrationScalar::FloatTag {
            bits: value.to_bits(),
        },
        numeric: NumericType::Float32,
        score: false,
    }
}
fn input_score(value: Option<i32>) -> ProbeNode {
    ProbeNode::Input {
        scalar: value.map_or(CalibrationScalar::Absent, CalibrationScalar::Score),
        numeric: NumericType::Int32,
        score: true,
    }
}
fn missing_float() -> ProbeNode {
    ProbeNode::Input {
        scalar: CalibrationScalar::Absent,
        numeric: NumericType::Float32,
        score: false,
    }
}
fn operation(op: ExprOp, numeric: NumericType, inputs: &[usize]) -> ProbeNode {
    ProbeNode::Operation {
        op,
        numeric,
        inputs: inputs.to_vec(),
    }
}
fn expected(output: CalibrationScalar) -> CalibrationExpectation {
    let success = output != CalibrationScalar::Absent;
    CalibrationExpectation {
        command_success: success,
        command_return: None,
        ok_score: i32::from(success),
        output,
        scratch_present: success,
        preseed_score: 7331,
        preseed_storage: CalibrationScalar::FloatTag {
            bits: 7331f32.to_bits(),
        },
    }
}
fn float_output(value: f32) -> CalibrationScalar {
    CalibrationScalar::FloatTag {
        bits: value.to_bits(),
    }
}

fn specification(case: CalibrationCase) -> Specification {
    use CalibrationCase::*;
    use ExprOp::*;
    use NumericType::{Float32, Int32};
    let (nodes, output) = match case {
        Int32ScoreZero | ScorePresentZeroLazyFallback => {
            (vec![input_score(Some(0))], CalibrationScalar::Score(0))
        }
        Int32NbtMin => (
            vec![input_int(i32::MIN)],
            CalibrationScalar::IntTag(i32::MIN),
        ),
        Int32NbtMax => (
            vec![input_int(i32::MAX)],
            CalibrationScalar::IntTag(i32::MAX),
        ),
        FloatNbtFraction | FloatStoragePresentFractionLazyFallback => {
            (vec![input_float(1.25)], float_output(1.25))
        }
        FloatBinary32Chain => (
            vec![
                input_float(16777216.0),
                input_float(1.0),
                operation(Add, Float32, &[0, 1]),
                operation(Sub, Float32, &[2, 0]),
            ],
            float_output(0.0),
        ),
        IntDivNegative => (
            vec![input_int(-7), input_int(2), operation(Div, Int32, &[0, 1])],
            CalibrationScalar::Score(-3),
        ),
        IntFloorDivNegative => (
            vec![
                input_int(-7),
                input_int(2),
                operation(FloorDiv, Int32, &[0, 1]),
            ],
            CalibrationScalar::Score(-4),
        ),
        FloatFromFloatNegative => (
            vec![input_float(-1.5), operation(ToIntTrunc, Int32, &[0])],
            CalibrationScalar::Score(-1),
        ),
        FloatFloorThenFromFloatNegative => (
            vec![input_float(-1.5), operation(ToIntFloor, Int32, &[0])],
            CalibrationScalar::Score(-2),
        ),
        IntAddOverflow => (
            vec![
                input_int(i32::MAX),
                input_int(1),
                operation(Add, Int32, &[0, 1]),
            ],
            CalibrationScalar::Absent,
        ),
        IntSubOverflow => (
            vec![
                input_int(i32::MIN),
                input_int(1),
                operation(Sub, Int32, &[0, 1]),
            ],
            CalibrationScalar::Absent,
        ),
        IntMulOverflow => (
            vec![
                input_int(i32::MAX),
                input_int(2),
                operation(Mul, Int32, &[0, 1]),
            ],
            CalibrationScalar::Absent,
        ),
        IntDivOverflow => (
            vec![
                input_int(i32::MIN),
                input_int(-1),
                operation(Div, Int32, &[0, 1]),
            ],
            CalibrationScalar::Absent,
        ),
        IntFloorDivOverflow => (
            vec![
                input_int(i32::MIN),
                input_int(-1),
                operation(FloorDiv, Int32, &[0, 1]),
            ],
            CalibrationScalar::Absent,
        ),
        IntDivZero => (
            vec![input_int(8), input_int(0), operation(Div, Int32, &[0, 1])],
            CalibrationScalar::Absent,
        ),
        IntFloorDivZero => (
            vec![
                input_int(8),
                input_int(0),
                operation(FloorDiv, Int32, &[0, 1]),
            ],
            CalibrationScalar::Absent,
        ),
        FloatFromFloatUpperRange => (
            vec![
                input_float(2147483648.0),
                operation(ToIntTrunc, Int32, &[0]),
            ],
            CalibrationScalar::Absent,
        ),
        FloatFromFloatLowerRange => (
            vec![
                input_float(-2147483904.0),
                operation(ToIntTrunc, Int32, &[0]),
            ],
            CalibrationScalar::Absent,
        ),
        FloatDivPositiveZero => (
            vec![
                input_float(1.0),
                input_float(0.0),
                operation(Div, Float32, &[0, 1]),
            ],
            CalibrationScalar::Absent,
        ),
        FloatDivZeroZero => (
            vec![
                input_float(0.0),
                input_float(0.0),
                operation(Div, Float32, &[0, 1]),
            ],
            CalibrationScalar::Absent,
        ),
        FloatSqrtNegative => (
            vec![input_float(-1.0), operation(Sqrt, Float32, &[0])],
            CalibrationScalar::Absent,
        ),
        FloatMulOverflow => (
            vec![
                input_float(3.4e38),
                input_float(2.0),
                operation(Mul, Float32, &[0, 1]),
            ],
            CalibrationScalar::Absent,
        ),
        FloatUndefinedProvider | FloatStorageAbsentFallback => {
            (vec![missing_float()], CalibrationScalar::Absent)
        }
        ScoreAbsentFallback => (vec![input_score(None)], CalibrationScalar::Absent),
        FloatFiniteZeroGuard => (vec![input_float(0.0)], float_output(0.0)),
        LaterNodeFailureCleanup => (
            vec![
                input_int(7),
                input_int(0),
                operation(Add, Int32, &[0, 0]),
                operation(Div, Int32, &[2, 1]),
            ],
            CalibrationScalar::Absent,
        ),
        NativeComputeFloatReturnFloorVsNbt => (vec![input_float(-1.5)], float_output(-1.5)),
        FloatSignedZero => (vec![input_float(-0.0)], float_output(-0.0)),
        IntAddNormal => (
            vec![input_int(7), input_int(5), operation(Add, Int32, &[0, 1])],
            CalibrationScalar::Score(12),
        ),
        IntSubNormal => (
            vec![input_int(7), input_int(5), operation(Sub, Int32, &[0, 1])],
            CalibrationScalar::Score(2),
        ),
        IntMulNormal => (
            vec![input_int(-3), input_int(4), operation(Mul, Int32, &[0, 1])],
            CalibrationScalar::Score(-12),
        ),
        IntMinNormal => (
            vec![input_int(-3), input_int(4), operation(Min, Int32, &[0, 1])],
            CalibrationScalar::Score(-3),
        ),
        IntMaxNormal => (
            vec![input_int(-3), input_int(4), operation(Max, Int32, &[0, 1])],
            CalibrationScalar::Score(4),
        ),
        IntClampNormal => (
            vec![
                input_int(8),
                input_int(2),
                input_int(5),
                operation(Clamp, Int32, &[0, 1, 2]),
            ],
            CalibrationScalar::Score(5),
        ),
        FloatAddNormal => (
            vec![
                input_float(1.5),
                input_float(0.25),
                operation(Add, Float32, &[0, 1]),
            ],
            float_output(1.75),
        ),
        FloatSubNormal => (
            vec![
                input_float(1.5),
                input_float(0.25),
                operation(Sub, Float32, &[0, 1]),
            ],
            float_output(1.25),
        ),
        FloatMulNormal => (
            vec![
                input_float(1.5),
                input_float(2.0),
                operation(Mul, Float32, &[0, 1]),
            ],
            float_output(3.0),
        ),
        FloatDivNormal => (
            vec![
                input_float(3.0),
                input_float(2.0),
                operation(Div, Float32, &[0, 1]),
            ],
            float_output(1.5),
        ),
        FloatMinNormal => (
            vec![
                input_float(-1.5),
                input_float(2.0),
                operation(Min, Float32, &[0, 1]),
            ],
            float_output(-1.5),
        ),
        FloatMaxNormal => (
            vec![
                input_float(-1.5),
                input_float(2.0),
                operation(Max, Float32, &[0, 1]),
            ],
            float_output(2.0),
        ),
        FloatClampNormal => (
            vec![
                input_float(8.0),
                input_float(2.0),
                input_float(5.0),
                operation(Clamp, Float32, &[0, 1, 2]),
            ],
            float_output(5.0),
        ),
        FloatSinZero => (
            vec![input_float(0.0), operation(Sin, Float32, &[0])],
            float_output(0.0),
        ),
        FloatCosZero => (
            vec![input_float(0.0), operation(Cos, Float32, &[0])],
            float_output(1.0),
        ),
        FloatSqrtFour => (
            vec![input_float(4.0), operation(Sqrt, Float32, &[0])],
            float_output(2.0),
        ),
    };
    let score_output = matches!(output, CalibrationScalar::Score(_))
        || matches!(
            case,
            IntAddOverflow
                | IntSubOverflow
                | IntMulOverflow
                | IntDivOverflow
                | IntFloorDivOverflow
                | IntDivZero
                | IntFloorDivZero
                | FloatFromFloatUpperRange
                | FloatFromFloatLowerRange
                | ScoreAbsentFallback
                | LaterNodeFailureCleanup
        );
    let mut expectation = expected(output);
    if case == FloatFiniteZeroGuard {
        expectation.command_return = Some(0);
    }
    if case == NativeComputeFloatReturnFloorVsNbt {
        expectation.command_return = Some(-2);
    }
    Specification {
        nodes,
        output: if score_output {
            OutputStorage::Scoreboard
        } else {
            OutputStorage::StorageNbt
        },
        rounding: Rounding::None,
        expectation,
        float_return_probe: case == NativeComputeFloatReturnFloorVsNbt,
    }
}

fn build(
    case: CalibrationCase,
    specification: Specification,
) -> Result<CalibrationProgram, DomainError> {
    let identity = raw_digest(case.case_id().as_bytes());
    let objective = format!("mcal{}", &identity.as_str()[..11]);
    let storage = ResourceLocation::new(format!("mmmm:calibration/{}", case.case_id()))
        .map_err(|error| invalid(error.to_string()))?;
    let result_address = match specification.output {
        OutputStorage::Scoreboard => BindingAddress::Score {
            holder: "#result".into(),
            objective: objective.clone(),
        },
        OutputStorage::StorageNbt => BindingAddress::Storage {
            storage: storage.clone(),
            path: "invocation.result".into(),
        },
    };
    let mut builder = CommandBuilder::default();
    // The objective must already have been allocated under exclusive owner
    // authority. An arbitrary pre-existing objective is never adopted here.
    builder.push(format!("data remove storage {storage} inputs"))?;
    builder.push(format!(
        "scoreboard players set #result {objective} {}",
        specification.expectation.preseed_score
    ))?;
    builder.push(format!(
        "data modify storage {storage} invocation set value {{stale:1b,result:7331f}}"
    ))?;
    let mut bindings = Vec::with_capacity(specification.nodes.len());
    let mut input_addresses = Vec::new();
    for (index, node) in specification.nodes.iter().enumerate() {
        if let ProbeNode::Input {
            scalar,
            numeric,
            score,
        } = node
        {
            let address = if *score {
                BindingAddress::Score {
                    holder: format!("#input{index}"),
                    objective: objective.clone(),
                }
            } else {
                BindingAddress::Storage {
                    storage: storage.clone(),
                    path: format!("inputs.n{index}"),
                }
            };
            seed(&mut builder, &address, *scalar)?;
            let binding = SymbolBinding {
                symbol_id: SymbolId::new(format!("calibration-input-{index}"))
                    .map_err(|error| invalid(error.to_string()))?,
                numeric_type: *numeric,
                unit: "unitless".into(),
                address: address.clone(),
            };
            input_addresses.push(address);
            bindings.push(Some(binding));
        } else {
            bindings.push(None);
        }
    }
    let preseed_end_index = builder.commands.len() as u32;
    builder.push(format!("data remove storage {storage} invocation"))?;
    builder.push(format!("scoreboard players reset #result {objective}"))?;
    builder.push(format!("scoreboard players set #ok {objective} 1"))?;
    let mut stages = Vec::with_capacity(specification.nodes.len());
    let mut last_numeric = NumericType::Int32;
    for (index, node) in specification.nodes.iter().enumerate() {
        let (op, numeric, inputs) = match node {
            ProbeNode::Input { numeric, .. } => (ExprOp::State, *numeric, Vec::new()),
            ProbeNode::Operation {
                op,
                numeric,
                inputs,
            } => (*op, *numeric, inputs.clone()),
        };
        let arguments = inputs
            .iter()
            .map(|input| {
                let ty = node_type(&specification.nodes[*input]);
                storage_read(&storage, &format!("invocation.n{input}"), ty)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let expression = node_expression(index, op, numeric)?;
        let provider = crate::math::provider(&expression, &arguments, bindings[index].as_ref())?;
        let mut stage = builder.commands.len() as u32;
        if op == ExprOp::Div && numeric == NumericType::Int32 {
            let preflight = render(ExprOp::FloorDiv, NumericType::Int32, &arguments)?;
            builder.push(format!("execute if score #ok {objective} matches 1 store success score #ok {objective} run compute default integer {preflight}"))?;
        }
        builder.push(format!("execute if score #ok {objective} matches 1 store success score #ok {objective} run data modify storage {storage} invocation.n{index} set compute default {} {provider}",numeric.command_name()))?;
        if numeric == NumericType::Float32 {
            let read = storage_read(
                &storage,
                &format!("invocation.n{index}"),
                NumericType::Float32,
            )?;
            let product = render(ExprOp::Mul, NumericType::Float32, &[read, "0.0f".into()])?;
            let finite = render(ExprOp::ToIntTrunc, NumericType::Int32, &[product])?;
            stage = builder.commands.len() as u32;
            builder.push(format!("execute if score #ok {objective} matches 1 store success score #ok {objective} run compute default integer {finite}"))?;
        }
        stages.push(stage);
        last_numeric = numeric;
    }
    let root = specification
        .nodes
        .len()
        .checked_sub(1)
        .ok_or_else(|| invalid("Empty calibration graph"))?;
    let root_read = storage_read(&storage, &format!("invocation.n{root}"), last_numeric)?;
    match specification.output {
        OutputStorage::StorageNbt => builder.push(format!("execute if score #ok {objective} matches 1 store success score #ok {objective} run data modify storage {storage} invocation.result set from storage {storage} invocation.n{root}"))?,
        OutputStorage::Scoreboard => {
            let output = match (last_numeric,specification.rounding) {
                (NumericType::Int32,Rounding::None) => root_read.clone(),
                _ => return Err(invalid("Calibration score output requires an explicit integer conversion node")),
            };
            builder.push(format!("execute if score #ok {objective} matches 1 store success score #ok {objective} store result score #result {objective} run compute default integer {output}"))?;
            builder.push(format!("execute unless score #ok {objective} matches 1 run scoreboard players reset #result {objective}"))?;
        }
    }
    let mut command_stage_index = stages[root];
    if specification.float_return_probe {
        command_stage_index = builder.commands.len() as u32;
        builder.push(format!("execute if score #ok {objective} matches 1 store success score #ok {objective} run compute default float {root_read} 1.0"))?;
    }
    builder.push(format!("execute unless score #ok {objective} matches 1 run data remove storage {storage} invocation"))?;
    let bytes = builder.source(case)?;
    let digest = raw_digest(&bytes);
    let entry = ResourceLocation::new(format!(
        "mmmm_calibration:{}/{}",
        case.case_id(),
        &digest.as_str()[..24]
    ))
    .map_err(|error| invalid(error.to_string()))?;
    let initialization_commands = vec![format!("scoreboard objectives add {objective} dummy")];
    let cleanup_commands = vec![
        format!("data remove storage {storage} inputs"),
        format!("data remove storage {storage} invocation"),
        format!("scoreboard objectives remove {objective}"),
    ];
    Ok(CalibrationProgram {
        case,
        bytes,
        digest,
        invocation_command: format!("function {entry}"),
        commands: builder.commands,
        command_stage_index,
        preseed_end_index,
        expected_readback: specification.expectation.to_value(),
        expectation: specification.expectation,
        scope: CalibrationScope {
            objective,
            storage,
            result_address,
            input_addresses,
        },
        initialization_commands,
        cleanup_commands,
    })
}

fn node_type(node: &ProbeNode) -> NumericType {
    match node {
        ProbeNode::Input { numeric, .. } | ProbeNode::Operation { numeric, .. } => *numeric,
    }
}
fn node_expression(
    index: usize,
    op: ExprOp,
    numeric: NumericType,
) -> Result<ExprNode, DomainError> {
    Ok(ExprNode {
        expr_id: ExprId::new(format!("calibration-node-{index}"))
            .map_err(|error| invalid(error.to_string()))?,
        op,
        numeric_type: numeric,
        unit: "unitless".into(),
        inputs: Vec::new(),
        value: None,
        state_id: None,
        context_component: None,
    })
}
fn render(op: ExprOp, numeric: NumericType, inputs: &[String]) -> Result<String, DomainError> {
    crate::math::provider(&node_expression(0, op, numeric)?, inputs, None)
}
fn storage_read(
    storage: &ResourceLocation,
    path: &str,
    numeric: NumericType,
) -> Result<String, DomainError> {
    let binding = SymbolBinding {
        symbol_id: SymbolId::new("calibration-scratch-read")
            .map_err(|error| invalid(error.to_string()))?,
        numeric_type: numeric,
        unit: "unitless".into(),
        address: BindingAddress::Storage {
            storage: storage.clone(),
            path: path.into(),
        },
    };
    crate::math::provider(
        &node_expression(0, ExprOp::State, numeric)?,
        &[],
        Some(&binding),
    )
}
fn seed(
    builder: &mut CommandBuilder,
    address: &BindingAddress,
    scalar: CalibrationScalar,
) -> Result<(), DomainError> {
    match (address, scalar) {
        (BindingAddress::Score { holder, objective }, CalibrationScalar::Score(value)) => builder
            .push(format!(
                "scoreboard players set {holder} {objective} {value}"
            )),
        (BindingAddress::Score { holder, objective }, CalibrationScalar::Absent) => {
            builder.push(format!("scoreboard players reset {holder} {objective}"))
        }
        (BindingAddress::Storage { storage, path }, CalibrationScalar::IntTag(value)) => builder
            .push(format!(
                "data modify storage {storage} {path} set value {value}"
            )),
        (BindingAddress::Storage { storage, path }, CalibrationScalar::FloatTag { bits }) => {
            let value = f32::from_bits(bits);
            if !value.is_finite() {
                return Err(invalid(
                    "Calibration literals must be finite; native operations produce exceptional results",
                ));
            }
            builder.push(format!(
                "data modify storage {storage} {path} set value {value}f"
            ))
        }
        (BindingAddress::Storage { storage, path }, CalibrationScalar::Absent) => {
            builder.push(format!("data remove storage {storage} {path}"))
        }
        _ => Err(invalid(
            "Calibration seed tag does not match its native address",
        )),
    }
}

#[derive(Default)]
struct CommandBuilder {
    commands: Vec<String>,
    bytes: usize,
}
impl CommandBuilder {
    fn push(&mut self, command: String) -> Result<(), DomainError> {
        if command.is_empty()
            || command.len() > MAX_COMMAND_BYTES
            || command.contains(['\r', '\n', '\0'])
            || self.commands.len() >= MAX_COMMANDS
        {
            return Err(invalid(
                "Calibration command exceeds its finite grammar budget",
            ));
        }
        self.bytes = self
            .bytes
            .checked_add(command.len() + 1)
            .filter(|bytes| *bytes <= MAX_PROGRAM_BYTES)
            .ok_or_else(|| invalid("Calibration source exceeds its finite byte budget"))?;
        self.commands.push(command);
        Ok(())
    }
    fn source(&self, case: CalibrationCase) -> Result<Vec<u8>, DomainError> {
        let header = format!(
            "# MMMM native calibration/1 {}\n# requires independently owned storage and dummy objective; serialized copied-world runner\n",
            case.case_id()
        );
        if header.len() + self.bytes > MAX_PROGRAM_BYTES {
            return Err(invalid("Calibration header exceeds its source budget"));
        }
        let mut source = Vec::with_capacity(header.len() + self.bytes);
        source.extend_from_slice(header.as_bytes());
        for command in &self.commands {
            source.extend_from_slice(command.as_bytes());
            source.push(b'\n');
        }
        Ok(source)
    }
}
fn invalid(message: impl Into<String>) -> DomainError {
    DomainError::new("CALIBRATION_SOURCE_INVALID", message)
}

#[cfg(test)]
#[path = "calibration_tests.rs"]
mod tests;

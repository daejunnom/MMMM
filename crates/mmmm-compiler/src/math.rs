//! Native 26.3 syntax follows the final primary release notes:
//! https://www.minecraft.net/en-us/article/minecraft-java-edition-26-3
//! Source investigation does not establish an executable target capability.
//! Each DAG node is evaluated once into a freshly cleared, typed scratch slot.

use crate::{
    BindingAddress, CompileFragment, CompilerPins, ExprNode, ExprOp, GeneratedFunctionContract,
    MathCompileRequest, NumericType, OutputStorage, ResolvedSymbols, Rounding, StagedResource,
    SymbolBinding, VerifiedTarget, compiler_digest, decode, encode,
};
use mmmm_contracts::{
    ExprId, ResourceId, ResourceLocation, SymbolId, canonical_digest, encode_json, raw_digest,
};
use mmmm_domain::DomainError;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAX_NODES: usize = 4096;
const MAX_EDGES: usize = 8192;
const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_COMMAND_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct CompiledFragmentDraft {
    pub(crate) fragment: CompileFragment,
    pub(crate) source: StagedResource,
    pub(crate) pins: CompilerPins,
    pub(crate) contract: GeneratedFunctionContract,
    pub(crate) objective: String,
    pub(crate) scratch_storage: ResourceLocation,
    pub(crate) scratch_path: String,
    pub(crate) result_address: BindingAddress,
    pub(crate) node_lines: BTreeMap<ExprId, usize>,
}

impl CompiledFragmentDraft {
    pub fn fragment(&self) -> &CompileFragment {
        &self.fragment
    }
    pub fn source(&self) -> &StagedResource {
        &self.source
    }
    pub fn pins(&self) -> &CompilerPins {
        &self.pins
    }
    pub fn function_contract(&self) -> &GeneratedFunctionContract {
        &self.contract
    }
    pub fn result_address(&self) -> &BindingAddress {
        &self.result_address
    }
    pub fn private_storage_scope(&self) -> (&ResourceLocation, &str) {
        (&self.scratch_storage, &self.scratch_path)
    }
    pub fn to_wire(&self) -> Result<Value, DomainError> {
        encode("CompileFragment", &self.fragment)
    }
}

#[derive(Debug, Clone, Copy)]
enum Known {
    Integer(i32),
    Float(f32),
}

impl Known {
    fn is_zero(self) -> bool {
        match self {
            Self::Integer(value) => value == 0,
            Self::Float(value) => value == 0.0,
        }
    }
}

/// Pure draft construction after the application has resolved exact target
/// evidence and symbol ACLs. Neither argument is deserialized from FN07 input.
pub fn math_compile(
    value: &Value,
    target: &VerifiedTarget,
    symbols: &ResolvedSymbols,
) -> Result<CompiledFragmentDraft, DomainError> {
    let request: MathCompileRequest = decode("MathCompileRequest", value)?;
    if request.target_profile_id != *target.profile_id() || !symbols.matches(&request.symbol_table)
    {
        return Err(DomainError::new(
            "STALE_CONTEXT",
            "Exact target or symbol-table identity differs",
        ));
    }
    let nodes = validate_graph(&request)?;
    let order = topological_order(&nodes)?;
    let mut known = BTreeMap::new();
    let mut references = BTreeMap::new();
    for id in &order {
        let node = nodes[id];
        let inputs: Vec<_> = node.inputs.iter().map(|input| nodes[input]).collect();
        validate_node(node, &inputs, symbols, &mut references)?;
        let constants: Vec<_> = node.inputs.iter().map(|input| known[input]).collect();
        known.insert(id.clone(), known_result(node, &constants)?);
    }
    let root = nodes[&request.root_expr_id];
    validate_output(root.numeric_type, request.output_storage, request.rounding)?;
    if let Some(Known::Float(value)) = known[&request.root_expr_id]
        && request.output_storage == OutputStorage::Scoreboard
    {
        let converted = if request.rounding == Rounding::Floor {
            value.floor()
        } else {
            value.trunc()
        };
        if f64::from(converted) < f64::from(i32::MIN) || f64::from(converted) > f64::from(i32::MAX)
        {
            return Err(DomainError::new(
                "NUMERIC_RANGE",
                "Known scoreboard conversion exceeds int32",
            ));
        }
    }
    // JCS deliberately identifies +0/-0, while native f32 literal bytes and
    // sign-sensitive operations can distinguish them. This compiler input pin
    // uses the strict durable representation, preserving signed zero, instead
    // of using a semantic JCS pin as an exact generated-source identity.
    let input_digest = raw_digest(
        &encode_json(value)
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?,
    );
    let implementation_digest = compiler_digest();
    let digest_inputs = serde_json::json!({"input": input_digest,
        "compiler": implementation_digest, "target": target.profile_digest(),
        "artifact": target.artifact_digest(), "symbols": symbols.authority_digest()});
    let identity = canonical_digest(&digest_inputs)
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    let suffix = &identity.as_str()[..24];
    let objective = format!("m{}", &identity.as_str()[..15]);
    let scratch_storage = ResourceLocation::new(format!("mmmm:math/{suffix}"))
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    let scratch_path = "invocation".to_owned();
    if references.values().any(|address| {
        address.starts_with(&format!("storage:{scratch_storage}:"))
            || address.ends_with(&format!(":{objective}"))
    }) {
        return Err(DomainError::new(
            "UNOWNED_REQUIRED_CAPABILITY",
            "Source symbol collides with generated private state",
        ));
    }
    let root_path = format!("{scratch_path}.result");
    let result_address = match request.output_storage {
        OutputStorage::Scoreboard => BindingAddress::Score {
            holder: "#result".into(),
            objective: objective.clone(),
        },
        OutputStorage::StorageNbt => BindingAddress::Storage {
            storage: scratch_storage.clone(),
            path: root_path.clone(),
        },
    };
    // Validate every node, but emit only the root's closure. Disconnected valid
    // authoring nodes cannot inject effects or nondeterministic extra commands.
    let reachable = reachable(&request.root_expr_id, &nodes);
    let mut lines = Lines::default();
    lines.push(format!(
        "# MMMM native math {suffix}; requires initialization and serialized invocation"
    ))?;
    lines.push(format!(
        "data remove storage {scratch_storage} {scratch_path}"
    ))?;
    lines.push(format!("scoreboard players reset #result {objective}"))?;
    lines.push(format!("scoreboard players set #ok {objective} 1"))?;
    let mut paths = BTreeMap::new();
    let mut node_lines = BTreeMap::new();
    let mut used_references = BTreeSet::new();
    let mut state_reads = BTreeSet::new();
    for id in order.iter().filter(|id| reachable.contains(*id)) {
        let node = nodes[id];
        let path = format!("{scratch_path}.n{}", paths.len());
        paths.insert(id.clone(), path.clone());
        node_lines.insert(id.clone(), lines.len() + 1);
        let binding = match node.op {
            ExprOp::State => symbols.state(node.state_id.as_ref().expect("validated state")),
            ExprOp::ContextComponent => {
                symbols.context(node.context_component.expect("validated context"))
            }
            _ => None,
        };
        if let Some(binding) = binding {
            used_references.insert(binding.symbol_id.clone());
            state_reads.insert(binding.address.description());
        }
        let inputs: Vec<_> = node
            .inputs
            .iter()
            .map(|input| {
                storage_provider(&scratch_storage, &paths[input], nodes[input].numeric_type)
            })
            .collect();
        let provider = provider(node, &inputs, binding)?;
        // Native div's INT_MIN/-1 behavior is not declared in the release
        // description. Checked floor_div preflight rejects both overflow and
        // zero before executing the separately typed truncating provider.
        if node.op == ExprOp::Div && node.numeric_type == NumericType::Int32 {
            let check = binary_provider("floor_div", &inputs[0], &inputs[1]);
            lines.push(format!("execute if score #ok {objective} matches 1 store success score #ok {objective} run compute default integer {check}"))?;
        }
        lines.push(format!("execute if score #ok {objective} matches 1 store success score #ok {objective} run data modify storage {scratch_storage} {path} set compute default {} {provider}", node.numeric_type.command_name()))?;
        if node.numeric_type == NumericType::Float32 {
            // For finite IEEE f32 values, value*0 is +/-0. Infinity/NaN yields
            // NaN, which the native integer from_float provider rejects. This
            // tests the stored node result before it reaches any public output.
            let read = storage_provider(&scratch_storage, &path, NumericType::Float32);
            let finite = unary_provider(
                "from_float",
                &variadic_provider("mul", &[read, "0.0f".into()]),
            );
            lines.push(format!("execute if score #ok {objective} matches 1 store success score #ok {objective} run compute default integer {finite}"))?;
        }
    }
    let root_provider = storage_provider(
        &scratch_storage,
        &paths[&request.root_expr_id],
        root.numeric_type,
    );
    match request.output_storage {
        OutputStorage::StorageNbt => lines.push(format!("execute if score #ok {objective} matches 1 store success score #ok {objective} run data modify storage {scratch_storage} {root_path} set from storage {scratch_storage} {}", paths[&request.root_expr_id]))?,
        OutputStorage::Scoreboard => {
            let output = match (root.numeric_type, request.rounding) {
                (NumericType::Int32, Rounding::None) => root_provider,
                (NumericType::Float32, Rounding::Floor) => unary_provider("from_float", &unary_provider("floor", &root_provider)),
                (NumericType::Float32, Rounding::Trunc) => unary_provider("from_float", &root_provider),
                _ => unreachable!("validated output mode"),
            };
            lines.push(format!("execute if score #ok {objective} matches 1 store success score #ok {objective} store result score #result {objective} run compute default integer {output}"))?;
            // A failed store-result writes 0. Reset removes that misleading
            // apparent value; callers still require #ok == 1 and readback.
            lines.push(format!("execute unless score #ok {objective} matches 1 run scoreboard players reset #result {objective}"))?;
        }
    }
    lines.push(format!("execute unless score #ok {objective} matches 1 run data remove storage {scratch_storage} {scratch_path}"))?;
    let source = StagedResource::new(
        ResourceId::new(format!("math-source:{suffix}"))
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?,
        "text/x-mcfunction; charset=utf-8",
        lines.finish(),
    );
    let output_symbol = SymbolId::new(format!("math-result:{suffix}"))
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    let cleanup = vec![
        format!("data remove storage {scratch_storage} {scratch_path}"),
        format!("scoreboard players reset #ok {objective}"),
        format!("scoreboard players reset #result {objective}"),
    ];
    let inputs: Vec<_> = used_references.into_iter().collect();
    let fragment = CompileFragment {
        source: source.reference.clone(),
        defined_symbols: vec![output_symbol.clone()],
        referenced_symbols: inputs.clone(),
        target_profile_id: target.profile_id().clone(),
        losses: Vec::new(),
        diagnostics: Vec::new(),
    };
    encode("CompileFragment", &fragment)?;
    let contract = GeneratedFunctionContract { inputs, outputs: vec![output_symbol],
        state_reads: state_reads.into_iter().collect(),
        state_writes: vec![format!("score:#ok:{objective}"), format!("score:#result:{objective}"),
            format!("storage:{scratch_storage}:{scratch_path}")],
        execution_context: "caller_origin_with_authenticated_prepared_context",
        reentrancy: "forbidden_requires_serialized_invocation", scheduled_callbacks: Vec::new(), cleanup,
        requirements: vec![format!("scoreboard objective {objective} must be initialized"),
            "source storage must have the exact declared int or float NBT tag; host rechecks before invocation".into(),
            "context bindings, if present, must come from the same execution origin and invocation".into(),
            format!("publish only when score #ok {objective} is 1 and independently read result"),
            "hold serialized invocation ownership through independent readback and result consumption".into()], };
    Ok(CompiledFragmentDraft {
        fragment,
        source,
        pins: CompilerPins {
            input_digest,
            compiler_digest: implementation_digest,
            target_profile_digest: target.profile_digest().clone(),
            target_artifact_digest: target.artifact_digest().clone(),
            symbol_authority_digest: symbols.authority_digest().clone(),
        },
        contract,
        objective,
        scratch_storage,
        scratch_path,
        result_address,
        node_lines,
    })
}

fn validate_graph(
    request: &MathCompileRequest,
) -> Result<BTreeMap<ExprId, &ExprNode>, DomainError> {
    if request.nodes.is_empty()
        || request.nodes.len() > MAX_NODES
        || request
            .nodes
            .iter()
            .map(|node| node.inputs.len())
            .sum::<usize>()
            > MAX_EDGES
    {
        return Err(DomainError::new(
            "NUMERIC_RANGE",
            "Expression graph exceeds its finite budget",
        ));
    }
    let mut nodes = BTreeMap::new();
    for node in &request.nodes {
        if nodes.insert(node.expr_id.clone(), node).is_some() {
            return Err(DomainError::new(
                "SCHEMA_INVALID",
                "Duplicate expression identifier",
            ));
        }
    }
    if !nodes.contains_key(&request.root_expr_id)
        || nodes
            .values()
            .any(|node| node.inputs.iter().any(|input| !nodes.contains_key(input)))
    {
        return Err(DomainError::new(
            "REFERENCE_UNRESOLVED",
            "Expression reference is absent",
        ));
    }
    Ok(nodes)
}

fn topological_order(nodes: &BTreeMap<ExprId, &ExprNode>) -> Result<Vec<ExprId>, DomainError> {
    // Kahn with lexical tie-breaking; duplicate edges count independently.
    let mut pending: BTreeMap<_, _> = nodes
        .iter()
        .map(|(id, node)| (id.clone(), node.inputs.len()))
        .collect();
    let mut dependents: BTreeMap<ExprId, Vec<ExprId>> = BTreeMap::new();
    for (id, node) in nodes {
        for input in &node.inputs {
            dependents
                .entry(input.clone())
                .or_default()
                .push(id.clone());
        }
    }
    let mut ready: BTreeSet<_> = pending
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut order = Vec::with_capacity(nodes.len());
    while let Some(id) = ready.pop_first() {
        order.push(id.clone());
        for dependent in dependents.get(&id).into_iter().flatten() {
            let count = pending.get_mut(dependent).expect("graph invariant");
            *count -= 1;
            if *count == 0 {
                ready.insert(dependent.clone());
            }
        }
    }
    if order.len() != nodes.len() {
        return Err(DomainError::new(
            "SCHEMA_INVALID",
            "Expression graph contains a cycle",
        ));
    }
    Ok(order)
}

fn reachable(root: &ExprId, nodes: &BTreeMap<ExprId, &ExprNode>) -> BTreeSet<ExprId> {
    let mut found = BTreeSet::new();
    let mut pending = vec![root.clone()];
    while let Some(id) = pending.pop() {
        if found.insert(id.clone()) {
            pending.extend(nodes[&id].inputs.iter().cloned());
        }
    }
    found
}

fn validate_node(
    node: &ExprNode,
    inputs: &[&ExprNode],
    symbols: &ResolvedSymbols,
    references: &mut BTreeMap<SymbolId, String>,
) -> Result<(), DomainError> {
    use ExprOp::*;
    let arity = match node.op {
        Constant | State | ContextComponent => 0,
        Sin | Cos | Sqrt | ToIntFloor | ToIntTrunc => 1,
        Clamp => 3,
        _ => 2,
    };
    if inputs.len() != arity
        || node.unit.is_empty()
        || node.unit.len() > 128
        || (node.value.is_some() != (node.op == Constant))
        || (node.state_id.is_some() != (node.op == State))
        || (node.context_component.is_some() != (node.op == ContextComponent))
    {
        return Err(DomainError::new(
            "SCHEMA_INVALID",
            format!("Invalid payload/arity for {}", node.expr_id),
        ));
    }
    if matches!(node.op, State | ContextComponent) {
        let binding = if node.op == State {
            symbols.state(node.state_id.as_ref().expect("payload"))
        } else {
            symbols.context(node.context_component.expect("payload"))
        }
        .ok_or_else(|| {
            DomainError::new(
                "REFERENCE_UNRESOLVED",
                "Authorized symbol binding is absent",
            )
        })?;
        if binding.numeric_type != node.numeric_type || binding.unit != node.unit {
            return Err(DomainError::new(
                "UNIT_MISMATCH",
                "Declared symbol type/unit differs from expression",
            ));
        }
        if node.op == ContextComponent
            && (node.numeric_type != NumericType::Float32
                || node.unit != "blocks"
                || !matches!(binding.address, BindingAddress::Storage { .. }))
        {
            return Err(DomainError::new(
                "UNSUPPORTED_OPERATOR",
                "Origin requires an exact float NBT context binding in blocks",
            ));
        }
        references.insert(binding.symbol_id.clone(), binding.address.description());
        return Ok(());
    }
    if node.op == Constant {
        return Ok(());
    }
    if matches!(node.op, ToIntFloor | ToIntTrunc) {
        if node.numeric_type != NumericType::Int32
            || inputs[0].numeric_type != NumericType::Float32
            || node.unit != inputs[0].unit
        {
            return Err(DomainError::new(
                "UNIT_MISMATCH",
                "Explicit float-to-int conversion must preserve units",
            ));
        }
        return Ok(());
    }
    if inputs
        .iter()
        .any(|input| input.numeric_type != node.numeric_type)
    {
        return Err(DomainError::new(
            "UNIT_MISMATCH",
            "Implicit numeric type conversion is forbidden",
        ));
    }
    let output_unit = Unit::parse(&node.unit)?;
    let input_units = inputs
        .iter()
        .map(|input| Unit::parse(&input.unit))
        .collect::<Result<Vec<_>, _>>()?;
    let units_match = match node.op {
        Add | Sub | Min | Max | Clamp => input_units.iter().all(|unit| unit == &output_unit),
        Mul => input_units[0].combine(&input_units[1], 1)? == output_unit,
        Div | FloorDiv => input_units[0].combine(&input_units[1], -1)? == output_unit,
        Sin | Cos => {
            input_units[0] == Unit::parse("radians")? && output_unit == Unit::parse("unitless")?
        }
        Sqrt => input_units[0].square_root()? == output_unit,
        _ => unreachable!("non arithmetic operation handled"),
    };
    if !units_match {
        return Err(DomainError::new(
            "UNIT_MISMATCH",
            format!("Unsupported unit relation at {}", node.expr_id),
        ));
    }
    if (matches!(node.op, Sin | Cos | Sqrt) && node.numeric_type != NumericType::Float32)
        || (node.op == FloorDiv && node.numeric_type != NumericType::Int32)
    {
        return Err(DomainError::new(
            "UNSUPPORTED_OPERATOR",
            "Operator has no supported native numeric type",
        ));
    }
    Ok(())
}

/// Dimensional monomials are symbolic; distinct bases such as ticks/seconds and
/// degrees/radians never acquire an implicit conversion. ExprNode's unit is an
/// open string, while StateVariable's predefined vocabulary remains unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Unit(BTreeMap<String, i32>);

impl Unit {
    fn parse(input: &str) -> Result<Self, DomainError> {
        if input.is_empty() || input.len() > 128 {
            return Err(Self::error());
        }
        let mut result = Self(BTreeMap::new());
        let mut start = 0usize;
        let mut sign = 1;
        for (offset, character) in input
            .char_indices()
            .chain(std::iter::once((input.len(), '*')))
        {
            if character != '*' && character != '/' {
                continue;
            }
            let token = &input[start..offset];
            let (base, power) = match token.split_once('^') {
                Some((base, power)) => (base, power.parse::<i32>().map_err(|_| Self::error())?),
                None => (token, 1),
            };
            if base.is_empty()
                || !base
                    .bytes()
                    .all(|byte| byte.is_ascii_alphabetic() || byte == b'_')
                || !(-16..=16).contains(&power)
            {
                return Err(Self::error());
            }
            if base == "blocks_per_tick" {
                result.add("blocks", power * sign)?;
                result.add("ticks", -power * sign)?;
            } else if base != "unitless" {
                result.add(base, power * sign)?;
            }
            start = offset + character.len_utf8();
            // Slash applies to the following factor only, so a/b*c means
            // (a/b)*c. Parentheses and conversion aliases are unsupported.
            sign = if character == '/' { -1 } else { 1 };
        }
        Ok(result)
    }
    fn add(&mut self, base: &str, power: i32) -> Result<(), DomainError> {
        let next = self
            .0
            .get(base)
            .copied()
            .unwrap_or(0)
            .checked_add(power)
            .ok_or_else(Self::error)?;
        if !(-32..=32).contains(&next)
            || (next != 0 && !self.0.contains_key(base) && self.0.len() >= 16)
        {
            return Err(Self::error());
        }
        if next == 0 {
            self.0.remove(base);
        } else {
            self.0.insert(base.into(), next);
        }
        Ok(())
    }
    fn combine(&self, other: &Self, sign: i32) -> Result<Self, DomainError> {
        let mut output = self.clone();
        for (base, power) in &other.0 {
            output.add(base, power * sign)?;
        }
        Ok(output)
    }
    fn square_root(&self) -> Result<Self, DomainError> {
        if self.0.values().any(|power| power % 2 != 0) {
            return Err(Self::error());
        }
        Ok(Self(
            self.0
                .iter()
                .map(|(base, power)| (base.clone(), power / 2))
                .collect(),
        ))
    }
    fn error() -> DomainError {
        DomainError::new(
            "UNIT_MISMATCH",
            "Unit expression is unsupported or has incompatible dimensions",
        )
    }
}

fn known_result(node: &ExprNode, inputs: &[Option<Known>]) -> Result<Option<Known>, DomainError> {
    use ExprOp::*;
    let invalid = || {
        DomainError::new(
            "NUMERIC_RANGE",
            format!("Invalid numeric result at {}", node.expr_id),
        )
    };
    if node.op == Constant {
        let value = node
            .value
            .as_ref()
            .and_then(|value| value.as_f64())
            .ok_or_else(invalid)?;
        return match node.numeric_type {
            NumericType::Int32
                if value.is_finite()
                    && value.fract() == 0.0
                    && value >= f64::from(i32::MIN)
                    && value <= f64::from(i32::MAX) =>
            {
                Ok(Some(Known::Integer(value as i32)))
            }
            NumericType::Float32 if value.is_finite() && (value as f32).is_finite() => {
                Ok(Some(Known::Float(value as f32)))
            }
            _ => Err(invalid()),
        };
    }
    if matches!(node.op, State | ContextComponent) {
        return Ok(None);
    }
    if matches!(node.op, Div | FloorDiv) && inputs[1].is_some_and(Known::is_zero) {
        return Err(invalid());
    }
    if node.op == Sqrt && matches!(inputs[0], Some(Known::Float(value)) if value < 0.0) {
        return Err(invalid());
    }
    if node.op == Clamp {
        match (inputs[1], inputs[2]) {
            (Some(Known::Integer(low)), Some(Known::Integer(high))) if low <= high => {}
            (Some(Known::Float(low)), Some(Known::Float(high))) if low <= high => {}
            (Some(_), Some(_)) => return Err(invalid()),
            _ => {
                return Err(DomainError::new(
                    "UNSUPPORTED_OPERATOR",
                    "Clamp bound order is not statically proven",
                ));
            }
        }
    }
    let Some(values) = inputs.iter().copied().collect::<Option<Vec<_>>>() else {
        return Ok(None);
    };
    if matches!(node.op, ToIntFloor | ToIntTrunc) {
        let Known::Float(value) = values[0] else {
            unreachable!("validated conversion")
        };
        let converted = if node.op == ToIntFloor {
            value.floor()
        } else {
            value.trunc()
        };
        if !converted.is_finite()
            || f64::from(converted) < f64::from(i32::MIN)
            || f64::from(converted) > f64::from(i32::MAX)
        {
            return Err(invalid());
        }
        return Ok(Some(Known::Integer(converted as i32)));
    }
    match node.numeric_type {
        NumericType::Int32 => {
            let int = |index: usize| match values[index] {
                Known::Integer(value) => value,
                _ => unreachable!("types"),
            };
            let left = int(0);
            let right = int(1);
            let result = match node.op {
                Add => left.checked_add(right),
                Sub => left.checked_sub(right),
                Mul => left.checked_mul(right),
                Div => left.checked_div(right),
                FloorDiv => left.checked_div(right).and_then(|trunc| {
                    left.checked_rem(right).and_then(|remainder| {
                        if remainder != 0 && (left < 0) != (right < 0) {
                            trunc.checked_sub(1)
                        } else {
                            Some(trunc)
                        }
                    })
                }),
                Min => Some(left.min(right)),
                Max => Some(left.max(right)),
                Clamp => Some(left.clamp(right, int(2))),
                _ => {
                    return Err(DomainError::new(
                        "UNSUPPORTED_OPERATOR",
                        "Integer operator is unsupported",
                    ));
                }
            }
            .ok_or_else(invalid)?;
            Ok(Some(Known::Integer(result)))
        }
        NumericType::Float32 => {
            let float = |index: usize| match values[index] {
                Known::Float(value) => value,
                _ => unreachable!("types"),
            };
            let left = float(0);
            // Target trig/sqrt algorithms are not folded or asserted equivalent
            // to Rust libm; range failures are handled by emitted native checks.
            if matches!(node.op, Sin | Cos | Sqrt) {
                return Ok(None);
            }
            let right = float(1);
            let result = match node.op {
                Add => left + right,
                Sub => left - right,
                Mul => left * right,
                Div => left / right,
                Min => left.min(right),
                Max => left.max(right),
                Clamp => left.clamp(right, float(2)),
                _ => {
                    return Err(DomainError::new(
                        "UNSUPPORTED_OPERATOR",
                        "Float operator is unsupported",
                    ));
                }
            };
            if !result.is_finite() {
                return Err(invalid());
            }
            Ok(Some(Known::Float(result)))
        }
    }
}

fn validate_output(
    numeric_type: NumericType,
    storage: OutputStorage,
    rounding: Rounding,
) -> Result<(), DomainError> {
    match (numeric_type, storage, rounding) {
        (_, OutputStorage::StorageNbt, Rounding::None)
        | (NumericType::Int32, OutputStorage::Scoreboard, Rounding::None)
        | (NumericType::Float32, OutputStorage::Scoreboard, Rounding::Floor | Rounding::Trunc) => {
            Ok(())
        }
        _ => Err(DomainError::new(
            "UNSUPPORTED_OPERATOR",
            "Output conversion requires an unambiguous explicit rounding mode",
        )),
    }
}

fn quote(value: &str) -> String {
    serde_json::to_string(value).expect("string encoding is infallible")
}
fn unary_provider(op: &str, input: &str) -> String {
    format!("{{type:\"minecraft:{op}\",input:{input}}}")
}
fn binary_provider(op: &str, left: &str, right: &str) -> String {
    format!("{{type:\"minecraft:{op}\",left:{left},right:{right}}}")
}
fn variadic_provider(op: &str, inputs: &[String]) -> String {
    format!("{{type:\"minecraft:{op}\",inputs:[{}]}}", inputs.join(","))
}

fn invalid_fallback(numeric_type: NumericType) -> &'static str {
    match numeric_type {
        NumericType::Int32 => "{type:\"minecraft:div\",left:1,right:0}",
        // from_int of an undefined integer avoids relying on NaN being a legal
        // input literal or on a nonexistent float error provider.
        NumericType::Float32 => {
            "{type:\"minecraft:from_int\",input:{type:\"minecraft:div\",left:1,right:0}}"
        }
    }
}

fn storage_provider(storage: &ResourceLocation, path: &str, numeric_type: NumericType) -> String {
    format!(
        "{{type:\"minecraft:storage\",storage:{},path:{},fallback:{}}}",
        quote(storage.as_str()),
        quote(path),
        invalid_fallback(numeric_type)
    )
}

fn provider(
    node: &ExprNode,
    inputs: &[String],
    binding: Option<&SymbolBinding>,
) -> Result<String, DomainError> {
    use ExprOp::*;
    Ok(match node.op {
        Constant => {
            let value = node
                .value
                .as_ref()
                .and_then(|value| value.as_f64())
                .expect("validated constant");
            match node.numeric_type {
                NumericType::Int32 => (value as i32).to_string(),
                NumericType::Float32 => format!("{}f", value as f32),
            }
        }
        State | ContextComponent => {
            let binding = binding.expect("validated binding");
            match &binding.address {
                BindingAddress::Score { holder, objective } => format!(
                    "{{type:\"minecraft:score\",score:{},target:{{type:\"fixed\",name:{}}},fallback:{}}}",
                    quote(objective),
                    quote(holder),
                    invalid_fallback(NumericType::Int32)
                ),
                BindingAddress::Storage { storage, path } => {
                    storage_provider(storage, path, node.numeric_type)
                }
            }
        }
        Add => variadic_provider("add", inputs),
        Mul => variadic_provider("mul", inputs),
        Min => variadic_provider("min", inputs),
        Max => variadic_provider("max", inputs),
        Sub => binary_provider("sub", &inputs[0], &inputs[1]),
        Div => binary_provider("div", &inputs[0], &inputs[1]),
        FloorDiv => binary_provider("floor_div", &inputs[0], &inputs[1]),
        Clamp => variadic_provider(
            "min",
            &[variadic_provider("max", &inputs[..2]), inputs[2].clone()],
        ),
        Sin => unary_provider("sin", &inputs[0]),
        Cos => unary_provider("cos", &inputs[0]),
        Sqrt => unary_provider("sqrt", &inputs[0]),
        ToIntFloor => unary_provider("from_float", &unary_provider("floor", &inputs[0])),
        ToIntTrunc => unary_provider("from_float", &inputs[0]),
    })
}

#[derive(Default)]
struct Lines {
    bytes: Vec<u8>,
    count: usize,
}
impl Lines {
    fn push(&mut self, line: String) -> Result<(), DomainError> {
        if line.len() > MAX_COMMAND_BYTES
            || self.bytes.len().saturating_add(line.len() + 1) > MAX_SOURCE_BYTES
            || line.contains(['\r', '\n', '\0'])
        {
            return Err(DomainError::new(
                "NUMERIC_RANGE",
                "Generated command/output budget exceeded",
            ));
        }
        self.bytes.extend_from_slice(line.as_bytes());
        self.bytes.push(b'\n');
        self.count += 1;
        Ok(())
    }
    fn len(&self) -> usize {
        self.count
    }
    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

//! FN06 computes an inactive authoring draft, without parsing command text or
//! acquiring chunks. Target and relocation attestations come from application
//! registries, rather than from the public layout request.

use crate::{
    decode, encode,
    types::{DomainError, SymbolReference},
};
use mmmm_contracts::{
    CommandId, ModuleId, NodeId, PrefabId, Sha256Digest, StateId, SymbolId, TargetProfileId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CommandModule {
    pub contract_version: String,
    pub module_id: ModuleId,
    pub owner_prefab_id: PrefabId,
    pub layout: CommandLayout,
    pub local_origin_node_id: NodeId,
    pub commands: Vec<CommandNode>,
    pub input_symbols: Vec<SymbolId>,
    pub output_symbols: Vec<SymbolId>,
    pub shared_state_ids: Vec<StateId>,
    #[serde(deserialize_with = "mmmm_contracts::deserialize_i32")]
    pub physical_clearance_blocks: i32,
    pub logical_isolation: LogicalIsolation,
    pub chunk_policy: ChunkPolicy,
    pub opaque_relocation: String,
    pub revision: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandLayout {
    Rack,
    Embedded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalIsolation {
    InstanceScoped,
    ExplicitShared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkPolicy {
    NearPlayerVerified,
    ExplicitTicket,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CommandNode {
    pub command_id: CommandId,
    pub source: String,
    pub kind: CommandKind,
    pub conditional: bool,
    pub auto: bool,
    #[serde(deserialize_with = "mmmm_contracts::deserialize_i32_vec3")]
    pub local_position: [i32; 3],
    pub facing: Facing,
    pub next_id: Option<CommandId>,
    pub condition_source_id: Option<CommandId>,
    pub references: Vec<SymbolReference>,
    pub parse_status: ParseStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    Impulse,
    Chain,
    Repeating,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseStatus {
    Parsed,
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Facing {
    North,
    South,
    West,
    East,
    Up,
    Down,
}

impl Facing {
    pub const fn direction(self) -> [i64; 3] {
        match self {
            Self::North => [0, 0, -1],
            Self::South => [0, 0, 1],
            Self::West => [-1, 0, 0],
            Self::East => [1, 0, 0],
            Self::Up => [0, 1, 0],
            Self::Down => [0, -1, 0],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CommandLayoutRequest {
    pub module: CommandModule,
    pub target_profile_id: TargetProfileId,
    #[serde(deserialize_with = "mmmm_contracts::deserialize_i32_vec3")]
    pub rack_origin: [i32; 3],
    #[serde(deserialize_with = "mmmm_contracts::deserialize_i32")]
    pub gap_blocks: i32,
    pub activation: String,
}

/// State rules which the application's exact target codec has independently
/// verified: execution follows facing into an adjacent chain block; conditional
/// success checks the adjacent command block behind the conditional node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandStateRules {
    SixAxisAdjacentChainConditionBehind,
}

/// An application-owned witness, never decoded from CommandLayoutRequest.
/// Its profile record is checked here, but this pure crate cannot establish that
/// its claimed evidence exists or belongs to the artifact. The registry must
/// perform that check before constructing or supplying this witness.
#[derive(Debug, Clone)]
pub struct CommandLayoutSupport {
    profile_id: TargetProfileId,
    artifact_sha256: Sha256Digest,
    rules: CommandStateRules,
    relocation_modules: BTreeMap<ModuleId, Sha256Digest>,
}

impl CommandLayoutSupport {
    /// `relocation_modules` maps immutable module IDs to their projected content
    /// digests after parser/context review. It is separate from target state
    /// support, permissions, selector ownership and actual game acceptance.
    pub fn from_verified_profile(
        profile: &Value,
        rules: CommandStateRules,
        relocation_modules: BTreeMap<ModuleId, Sha256Digest>,
    ) -> Result<Self, DomainError> {
        crate::validator()?
            .validate("VersionProfile", profile)
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
        if profile["writeSupport"] != "verified"
            || profile["validationStatus"] != "runtime_verified"
        {
            return Err(DomainError::new(
                "UNSUPPORTED_TARGET_VERSION",
                "Command state rules require a registry-verified exact target profile",
            ));
        }
        let profile_id = serde_json::from_value(profile["profileId"].clone())
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
        let artifact_sha256 = serde_json::from_value(profile["artifactSha256"].clone())
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
        Ok(Self {
            profile_id,
            artifact_sha256,
            rules,
            relocation_modules,
        })
    }
    pub fn profile_id(&self) -> &TargetProfileId {
        &self.profile_id
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }
}

/// A profile name alone is not a verified codec. Applications should route FN06
/// through command_layout_with_support after resolving the exact target record.
pub fn command_layout(value: &Value) -> Result<Value, DomainError> {
    let _: CommandLayoutRequest = decode("CommandLayoutRequest", value)?;
    Err(DomainError::new(
        "UNSUPPORTED_TARGET_VERSION",
        "No verified target command state codec was supplied",
    ))
}

pub fn command_layout_with_support(
    value: &Value,
    support: &CommandLayoutSupport,
) -> Result<Value, DomainError> {
    let request: CommandLayoutRequest = decode("CommandLayoutRequest", value)?;
    let output = layout(request, support)?;
    encode("CommandModule", &output)
}

pub fn layout(
    request: CommandLayoutRequest,
    support: &CommandLayoutSupport,
) -> Result<CommandModule, DomainError> {
    if request.target_profile_id != support.profile_id {
        return Err(DomainError::new(
            "UNSUPPORTED_TARGET_VERSION",
            "The state codec belongs to another exact target profile",
        ));
    }
    if request.gap_blocks < 1
        || request.module.physical_clearance_blocks < 0
        || request.activation != "staged_disabled"
    {
        return Err(DomainError::new(
            "SCHEMA_INVALID",
            "Layout requires positive spacing, nonnegative clearance and disabled staging",
        ));
    }
    let components = validate_command_graph(&request.module, support.rules)?;
    let mut module = request.module;
    if module.layout == CommandLayout::Rack {
        let input = encode("CommandModule", &module)?;
        let input_digest = mmmm_contracts::projected_digest("CommandModule", &input)
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
        let attested = support.relocation_modules.get(&module.module_id) == Some(&input_digest);
        let mut row_z = i64::from(request.rack_origin[2]);
        for component in components {
            let mut minimum = [i64::MAX; 3];
            let mut maximum = [i64::MIN; 3];
            for &index in &component {
                for axis in 0..3 {
                    let value = i64::from(module.commands[index].local_position[axis]);
                    minimum[axis] = minimum[axis].min(value);
                    maximum[axis] = maximum[axis].max(value);
                }
            }
            let anchor = [
                i64::from(request.rack_origin[0]),
                i64::from(request.rack_origin[1]),
                row_z,
            ];
            let delta = std::array::from_fn::<_, 3, _>(|axis| anchor[axis] - minimum[axis]);
            for index in component {
                let command = &mut module.commands[index];
                if delta != [0; 3] && (command.parse_status == ParseStatus::Opaque || !attested) {
                    return Err(DomainError::new(
                        "OPAQUE_RELOCATION",
                        format!(
                            "Command {} has no immutable module relocation attestation",
                            command.command_id
                        ),
                    ));
                }
                for (axis, offset) in delta.into_iter().enumerate() {
                    command.local_position[axis] = i32::try_from(
                        i64::from(command.local_position[axis]) + offset,
                    )
                    .map_err(|_| {
                        DomainError::new(
                            "NUMERIC_RANGE",
                            "Rack coordinates exceed int32 cell bounds",
                        )
                    })?;
                }
            }
            row_z = row_z
                .checked_add(maximum[2] - minimum[2] + 1)
                .and_then(|value| value.checked_add(i64::from(request.gap_blocks)))
                .and_then(|value| {
                    value.checked_add(i64::from(module.physical_clearance_blocks) * 2)
                })
                .ok_or_else(|| DomainError::new("NUMERIC_RANGE", "Rack row spacing overflow"))?;
        }
    }
    // Embedded modules retain their authored origin and relative placement. The
    // request has no executor/dimension/rotation ownership transformation, so
    // rackOrigin cannot silently centralize their button or execution context.
    for command in &mut module.commands {
        command.auto = false;
    }
    validate_command_graph(&module, support.rules)?;
    let output = encode("CommandModule", &module)?;
    module.revision = mmmm_contracts::projected_digest("CommandModule", &output)
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    Ok(module)
}

/// Returns connected components in authored command order. No recursion is used
/// for graph walks, so input chain depth cannot consume the native call stack.
pub fn validate_command_graph(
    module: &CommandModule,
    _rules: CommandStateRules,
) -> Result<Vec<Vec<usize>>, DomainError> {
    if module.commands.is_empty() {
        return Err(DomainError::new(
            "SCHEMA_INVALID",
            "A module requires at least one command",
        ));
    }
    let mut by_id = BTreeMap::new();
    let mut positions = BTreeMap::new();
    for (index, command) in module.commands.iter().enumerate() {
        if by_id.insert(&command.command_id, index).is_some() {
            return Err(DomainError::new(
                "ID_COLLISION",
                "Command stable IDs must be unique",
            ));
        }
        if positions
            .insert(command.local_position.map(i64::from), index)
            .is_some()
        {
            return Err(DomainError::new(
                "COMMAND_POSITION_COLLISION",
                "Two commands occupy the same authored cell",
            ));
        }
    }
    let mut next = vec![None; module.commands.len()];
    let mut neighbors = vec![Vec::new(); module.commands.len()];
    for (index, command) in module.commands.iter().enumerate() {
        if let Some(id) = &command.next_id {
            let target = *by_id.get(id).ok_or_else(|| {
                DomainError::new(
                    "REFERENCE_UNRESOLVED",
                    "nextId has no command in this module",
                )
            })?;
            next[index] = Some(target);
            neighbors[index].push(target);
            neighbors[target].push(index);
        }
        if let Some(id) = &command.condition_source_id {
            let source = *by_id.get(id).ok_or_else(|| {
                DomainError::new(
                    "CONDITION_SOURCE_MISMATCH",
                    "conditionSourceId has no command in this module",
                )
            })?;
            neighbors[index].push(source);
            neighbors[source].push(index);
        } else if command.conditional {
            return Err(DomainError::new(
                "CONDITION_SOURCE_MISMATCH",
                "A conditional command has no authored condition source",
            ));
        }
    }
    let mut color = vec![0u8; next.len()];
    for start in 0..next.len() {
        if color[start] != 0 {
            continue;
        }
        let mut path = Vec::new();
        let mut cursor = Some(start);
        while let Some(index) = cursor {
            match color[index] {
                1 => {
                    return Err(DomainError::new(
                        "CHAIN_CYCLE",
                        "Execution nextId relations contain a cycle",
                    ));
                }
                2 => break,
                _ => {
                    color[index] = 1;
                    path.push(index);
                    cursor = next[index];
                }
            }
        }
        for index in path {
            color[index] = 2;
        }
    }
    for (index, command) in module.commands.iter().enumerate() {
        let direction = command.facing.direction();
        let front = std::array::from_fn::<_, 3, _>(|axis| {
            i64::from(command.local_position[axis]) + direction[axis]
        });
        let physical_next = positions
            .get(&front)
            .copied()
            .filter(|index| module.commands[*index].kind == CommandKind::Chain);
        if physical_next != next[index] {
            return Err(DomainError::new(
                "CHAIN_GRAPH_MISMATCH",
                "nextId does not describe the adjacent chain in the command's facing direction",
            ));
        }
        if let Some(source) = &command.condition_source_id {
            let behind = std::array::from_fn::<_, 3, _>(|axis| {
                i64::from(command.local_position[axis]) - direction[axis]
            });
            if positions.get(&behind).copied() != by_id.get(source).copied() {
                return Err(DomainError::new(
                    "CONDITION_SOURCE_MISMATCH",
                    "conditionSourceId is not the physical command behind this facing",
                ));
            }
        }
    }
    let mut visited = BTreeSet::new();
    let mut components = Vec::new();
    for start in 0..module.commands.len() {
        if !visited.insert(start) {
            continue;
        }
        let mut pending = vec![start];
        let mut component = Vec::new();
        while let Some(index) = pending.pop() {
            component.push(index);
            for &neighbor in &neighbors[index] {
                if visited.insert(neighbor) {
                    pending.push(neighbor);
                }
            }
        }
        component.sort_unstable();
        components.push(component);
    }
    Ok(components)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Value {
        mmmm_contracts::parse_json(include_bytes!("../../../examples/command-module.json")).unwrap()
    }
    fn request(module: Value) -> Value {
        json!({"module":module,"targetProfileId":"fixture-target","rackOrigin":[20,64,30],"gapBlocks":2,"activation":"staged_disabled"})
    }
    // A source-only authored witness exercises the pure branch. It does not
    // establish a target's runtime verification or count as game acceptance.
    fn authored_test_support(module: &Value, attest: bool) -> CommandLayoutSupport {
        let modules = if attest {
            BTreeMap::from([(
                ModuleId::new(module["moduleId"].as_str().unwrap()).unwrap(),
                mmmm_contracts::projected_digest("CommandModule", module).unwrap(),
            )])
        } else {
            BTreeMap::new()
        };
        CommandLayoutSupport {
            profile_id: TargetProfileId::new("fixture-target").unwrap(),
            artifact_sha256: Sha256Digest::from_bytes([7; 32]),
            rules: CommandStateRules::SixAxisAdjacentChainConditionBehind,
            relocation_modules: modules,
        }
    }
    fn node(
        id: &str,
        position: [i32; 3],
        facing: &str,
        next: Option<&str>,
        condition: Option<&str>,
    ) -> Value {
        json!({"commandId":id,"source":"function fixture:command","kind":"chain","conditional":condition.is_some(),"auto":true,
            "localPosition":position,"facing":facing,"nextId":next,"conditionSourceId":condition,"references":[],"parseStatus":"parsed"})
    }
    fn bent_module() -> Value {
        let mut module = fixture();
        module["layout"] = json!("rack");
        // a -> b -> c turns at b. b's condition source d is physically
        // behind b, rather than a, which is the execution predecessor.
        module["commands"] = json!([
            node("a", [0, 0, 0], "east", Some("b"), None),
            node("b", [1, 0, 0], "south", Some("c"), Some("d")),
            node("c", [1, 0, 1], "south", None, None),
            node("d", [1, 0, -1], "up", None, None),
            node("other", [10, 0, 0], "up", None, None)
        ]);
        module["commands"][0]["kind"] = json!("impulse");
        module["sharedStateIds"] = json!(["shared_score"]);
        module["logicalIsolation"] = json!("explicit_shared");
        module
    }

    #[test]
    fn bent_rack_preserves_execution_and_physical_condition_relations_and_disabled_draft() {
        let module = bent_module();
        let support = authored_test_support(&module, true);
        let input = request(module);
        let before = input.clone();
        let result = command_layout_with_support(&input, &support).unwrap();
        assert_eq!(input, before);
        assert_eq!(result["commands"][0]["nextId"], "b");
        assert_eq!(result["commands"][1]["conditionSourceId"], "d");
        assert_eq!(result["commands"][1]["localPosition"], json!([21, 64, 31]));
        assert_eq!(result["commands"][3]["localPosition"], json!([21, 64, 30]));
        assert_eq!(result["commands"][4]["localPosition"], json!([20, 64, 37]));
        for (original, laid_out) in before["module"]["commands"]
            .as_array()
            .unwrap()
            .iter()
            .zip(result["commands"].as_array().unwrap())
        {
            assert_eq!(original["commandId"], laid_out["commandId"]);
            assert_eq!(original["source"], laid_out["source"]);
            assert_eq!(original["facing"], laid_out["facing"]);
            assert_eq!(laid_out["auto"], false);
        }
        assert_eq!(result["logicalIsolation"], "explicit_shared");
        assert_eq!(result["sharedStateIds"], json!(["shared_score"]));
        mmmm_contracts::verify_projected_digest("CommandModule", &result).unwrap();
        assert_eq!(
            result,
            command_layout_with_support(&input, &support).unwrap()
        );
    }

    #[test]
    fn embedded_origin_context_source_and_opaque_text_are_preserved() {
        let mut module = fixture();
        module["commands"][0]["source"] = json!("unparsed @p 120 70 -20");
        module["commands"][0]["parseStatus"] = json!("opaque");
        module["commands"][0]["auto"] = json!(true);
        let support = authored_test_support(&module, false);
        let result = command_layout_with_support(&request(module.clone()), &support).unwrap();
        assert_eq!(result["localOriginNodeId"], module["localOriginNodeId"]);
        assert_eq!(
            result["commands"][0]["localPosition"],
            module["commands"][0]["localPosition"]
        );
        assert_eq!(
            result["commands"][0]["source"],
            module["commands"][0]["source"]
        );
        assert_eq!(
            result["commands"][0]["references"],
            module["commands"][0]["references"]
        );
        assert_eq!(result["commands"][0]["auto"], false);
    }

    #[test]
    fn rack_rejects_missing_stale_or_opaque_relocation_support_without_text_rewrite() {
        let mut module = bent_module();
        let mut support = authored_test_support(&module, false);
        assert_eq!(
            command_layout_with_support(&request(module.clone()), &support)
                .unwrap_err()
                .code,
            "OPAQUE_RELOCATION"
        );
        support = authored_test_support(&module, true);
        module["commands"][0]["source"] = json!("tp @p 120 70 -20");
        assert_eq!(
            command_layout_with_support(&request(module.clone()), &support)
                .unwrap_err()
                .code,
            "OPAQUE_RELOCATION"
        );
        support = authored_test_support(&module, true);
        module["commands"][0]["parseStatus"] = json!("opaque");
        assert_eq!(
            command_layout_with_support(&request(module), &support)
                .unwrap_err()
                .code,
            "OPAQUE_RELOCATION"
        );
    }

    #[test]
    fn cycle_condition_mismatch_dangling_next_and_implicit_edges_are_errors() {
        let mut module = bent_module();
        module["commands"][2]["nextId"] = json!("a");
        let support = authored_test_support(&module, true);
        assert_eq!(
            command_layout_with_support(&request(module), &support)
                .unwrap_err()
                .code,
            "CHAIN_CYCLE"
        );
        module = bent_module();
        module["commands"][1]["conditionSourceId"] = json!("a");
        let support = authored_test_support(&module, true);
        assert_eq!(
            command_layout_with_support(&request(module), &support)
                .unwrap_err()
                .code,
            "CONDITION_SOURCE_MISMATCH"
        );
        module = bent_module();
        module["commands"][0]["nextId"] = json!("missing");
        let support = authored_test_support(&module, true);
        assert_eq!(
            command_layout_with_support(&request(module), &support)
                .unwrap_err()
                .code,
            "REFERENCE_UNRESOLVED"
        );
        module = bent_module();
        module["commands"][0]["nextId"] = Value::Null;
        let support = authored_test_support(&module, true);
        assert_eq!(
            command_layout_with_support(&request(module), &support)
                .unwrap_err()
                .code,
            "CHAIN_GRAPH_MISMATCH"
        );
    }

    #[test]
    fn unknown_target_cannot_become_supported_from_its_name_or_reference_record() {
        let module = fixture();
        let mut input = request(module.clone());
        assert_eq!(
            command_layout(&input).unwrap_err().code,
            "UNSUPPORTED_TARGET_VERSION"
        );
        let support = authored_test_support(&module, false);
        input["targetProfileId"] = json!("different-target");
        assert_eq!(
            command_layout_with_support(&input, &support)
                .unwrap_err()
                .code,
            "UNSUPPORTED_TARGET_VERSION"
        );
        let reference =
            mmmm_contracts::parse_json(include_bytes!("../../../examples/version-profile.json"))
                .unwrap();
        assert_eq!(
            CommandLayoutSupport::from_verified_profile(
                &reference,
                CommandStateRules::SixAxisAdjacentChainConditionBehind,
                BTreeMap::new()
            )
            .unwrap_err()
            .code,
            "UNSUPPORTED_TARGET_VERSION"
        );
    }

    #[test]
    fn coordinate_overflow_and_duplicate_command_cells_are_rejected() {
        let module = bent_module();
        let support = authored_test_support(&module, true);
        let mut input = request(module);
        input["rackOrigin"] = json!([2147483647, 64, 30]);
        assert_eq!(
            command_layout_with_support(&input, &support)
                .unwrap_err()
                .code,
            "NUMERIC_RANGE"
        );
        let mut module = bent_module();
        module["commands"][4]["localPosition"] = module["commands"][0]["localPosition"].clone();
        let support = authored_test_support(&module, true);
        assert_eq!(
            command_layout_with_support(&request(module), &support)
                .unwrap_err()
                .code,
            "COMMAND_POSITION_COLLISION"
        );
    }
}

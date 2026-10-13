//! FN30 constructs bytes and an exact-revision manifest in memory. The resource
//! store owns private staging/CAS admission. Installation/reload are separate
//! planned effects, and visual/multiplayer verification remains independent.

use crate::{
    CompiledFragmentDraft, GeneratedFunctionContract, StagedResource, VerifiedTarget,
    animation::AnimationDraft,
    compiler_digest, decode, encode,
    pack_owned::{prepare_owned, register_private_address},
    scene::SceneDraft,
};
use mmmm_contracts::{
    ManifestId, ProjectId, ResourceId, ResourceLocation, Sha256Digest, TargetProfileId,
    canonical_bytes, canonical_digest, projected_digest, raw_digest,
};
use mmmm_domain::{DomainError, types::ResourceRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAX_FUNCTIONS: usize = 4096;
const MAX_INSTRUCTIONS: usize = 16384;
const MAX_PACK_BYTES: usize = 32 * 1024 * 1024;
const MAX_CONTRACT_ENTRIES: usize = 16384;
const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum PackInstruction {
    Math(Box<CompiledFragmentDraft>),
    /// A concrete function identifier, never a substring replacement in a
    /// user's original command. All internal targets must occur in this draft.
    Call(ResourceLocation),
}

#[derive(Debug, Clone)]
pub struct PackFunction {
    pub id: ResourceLocation,
    pub source_object_id: String,
    pub instructions: Vec<PackInstruction>,
}

/// Owned immutable project snapshot supplied by application, plus generated
/// function IR. The source revision is independently recomputed here. Unknown
/// authored clip/display/resource lowering cannot be silently dropped.
#[derive(Debug, Clone)]
pub struct PackBuildInputs {
    project: Value,
    functions: Vec<PackFunction>,
    entry_points: BTreeMap<String, ResourceLocation>,
    covered_owned_objects: BTreeSet<String>,
    scene: Option<SceneDraft>,
    animations: Vec<AnimationDraft>,
}

impl PackBuildInputs {
    pub fn new(
        project: Value,
        functions: Vec<PackFunction>,
        entry_points: BTreeMap<String, ResourceLocation>,
        covered_owned_objects: BTreeSet<String>,
    ) -> Self {
        Self {
            project,
            functions,
            entry_points,
            covered_owned_objects,
            scene: None,
            animations: Vec::new(),
        }
    }
    /// A sealed scene draft carries independent source/target/codec evidence.
    pub fn with_scene(mut self, scene: SceneDraft) -> Self {
        self.scene = Some(scene);
        self
    }
    /// Every clip is qualified by its bound instance; global clip IDs are not
    /// sufficient coverage for repeated prefab instances.
    pub fn with_animation(mut self, animation: AnimationDraft) -> Self {
        self.animations.push(animation);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BuildRequest {
    context_id: String,
    project_id: ProjectId,
    expected_revision: Sha256Digest,
    target_profile_id: TargetProfileId,
    output_policy: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportFile {
    pub path: String,
    pub resource: ResourceRef,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportManifest {
    pub contract_version: &'static str,
    pub manifest_id: ManifestId,
    pub project_id: ProjectId,
    pub input_revision: Sha256Digest,
    pub target_profile_id: TargetProfileId,
    pub generator_digest: Sha256Digest,
    pub files: Vec<ExportFile>,
    pub defined_functions: Vec<ResourceLocation>,
    pub referenced_functions: Vec<ResourceLocation>,
    pub external_functions: Vec<ResourceLocation>,
    pub entry_points: BTreeMap<String, ResourceLocation>,
    pub state_symbols: Vec<String>,
    pub runtime_dependencies: Vec<String>,
    pub source_map: ResourceRef,
    pub losses: Vec<Value>,
    pub validation_stage: &'static str,
}

#[derive(Debug, Clone)]
pub struct PackDraft {
    manifest: ExportManifest,
    resources: BTreeMap<String, StagedResource>,
    function_contracts: BTreeMap<ResourceLocation, Vec<GeneratedFunctionContract>>,
    source_map: StagedResource,
    target_profile_digest: Sha256Digest,
    target_artifact_digest: Sha256Digest,
}

impl PackDraft {
    pub fn manifest(&self) -> &ExportManifest {
        &self.manifest
    }
    pub fn resources(&self) -> &BTreeMap<String, StagedResource> {
        &self.resources
    }
    pub fn source_map(&self) -> &StagedResource {
        &self.source_map
    }
    pub fn function_contracts(
        &self,
    ) -> &BTreeMap<ResourceLocation, Vec<GeneratedFunctionContract>> {
        &self.function_contracts
    }
    pub fn target_profile_digest(&self) -> &Sha256Digest {
        &self.target_profile_digest
    }
    pub fn target_artifact_digest(&self) -> &Sha256Digest {
        &self.target_artifact_digest
    }
    pub fn to_wire(&self) -> Result<Value, DomainError> {
        encode("ExportManifest", &self.manifest)
    }
}

pub fn pack_build(
    value: &Value,
    target: &VerifiedTarget,
    inputs: PackBuildInputs,
) -> Result<PackDraft, DomainError> {
    let request: BuildRequest = decode("BuildRequest", value)?;
    // The authenticated application validates context_id before invoking the
    // compiler; it is not an authority claim or a principal carried by this IR.
    if request.context_id.is_empty() || request.output_policy != "private_staging_only" {
        return Err(DomainError::new(
            "SCHEMA_INVALID",
            "Private staging context is absent",
        ));
    }
    let _: Value = decode("Project", &inputs.project)?;
    let actual_revision = projected_digest("Project", &inputs.project)
        .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    if actual_revision != request.expected_revision
        || inputs.project["revision"] != request.expected_revision.as_str()
        || inputs.project["projectId"] != request.project_id.as_str()
    {
        return Err(DomainError::new(
            "REVISION_CONFLICT",
            "Project source identity/revision does not match build request",
        ));
    }
    if request.target_profile_id != *target.profile_id()
        || inputs.project["targetProfileId"] != target.profile_id().as_str()
    {
        return Err(DomainError::new(
            "UNSUPPORTED_TARGET_VERSION",
            "Build target differs from immutable project target",
        ));
    }
    let pack_version = target.pack_version()?;
    let instruction_count: usize = inputs
        .functions
        .iter()
        .map(|function| function.instructions.len())
        .sum();
    if (inputs.functions.is_empty() && inputs.scene.is_none() && inputs.animations.is_empty())
        || inputs.functions.len() > MAX_FUNCTIONS
        || instruction_count > MAX_INSTRUCTIONS
    {
        return Err(DomainError::new(
            "NUMERIC_RANGE",
            "Generated function graph exceeds build budget",
        ));
    }
    if inputs.entry_points.len() > MAX_FUNCTIONS {
        return Err(DomainError::new(
            "NUMERIC_RANGE",
            "Entry point count exceeds finite budget",
        ));
    }
    // Bound/validate internal strings before identity JSON clones them.
    for function in &inputs.functions {
        validate_function_id(&function.id)?;
        let _: mmmm_contracts::ObjectId = function.source_object_id.parse().map_err(
            |error: mmmm_contracts::identity::IdentityError| {
                DomainError::new("SCHEMA_INVALID", error.to_string())
            },
        )?;
        for instruction in &function.instructions {
            if let PackInstruction::Call(id) = instruction {
                validate_function_id(id)?;
            }
        }
    }
    for (name, id) in &inputs.entry_points {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(DomainError::new(
                "SCHEMA_INVALID",
                "Invalid bounded entry point name",
            ));
        }
        validate_function_id(id)?;
    }
    let owned = inputs.project["ownedResources"].as_array().ok_or_else(|| {
        DomainError::new("SCHEMA_INVALID", "Project ownership inventory is absent")
    })?;
    let actual_owned: BTreeSet<_> = owned
        .iter()
        .map(|record| record["objectId"].as_str().unwrap_or_default().to_owned())
        .collect();
    if actual_owned != inputs.covered_owned_objects {
        return Err(DomainError::new(
            "UNOWNED_REQUIRED_CAPABILITY",
            "Each project-owned object requires explicit implemented lowering coverage",
        ));
    }
    let implementation = compiler_digest();
    let mut backend = prepare_owned(
        &inputs.project,
        target,
        &implementation,
        inputs.scene.as_ref(),
        &inputs.animations,
    )?;
    if inputs.functions.len().saturating_add(backend.defined.len()) > MAX_FUNCTIONS {
        return Err(DomainError::new(
            "NUMERIC_RANGE",
            "Combined generated function count exceeds finite budget",
        ));
    }
    let identity = canonical_digest(
        &serde_json::json!({"request": value, "target": target.profile_digest(),
        "artifact": target.artifact_digest(), "compiler": implementation,
        "functions": function_identity(&inputs.functions), "entryPoints": inputs.entry_points,
        "ownedLowerings": backend.seals}),
    )
    .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    let suffix = &identity.as_str()[..24];
    let namespace = format!("mmmm_{}", &identity.as_str()[..16]);
    let init_id =
        ResourceLocation::new(format!("{namespace}:initialize")).expect("generated location");
    let cleanup_id =
        ResourceLocation::new(format!("{namespace}:cleanup")).expect("generated location");
    let mut functions = BTreeMap::new();
    let mut references = BTreeSet::new();
    let mut graph = BTreeMap::new();
    let manual_ids: BTreeSet<_> = inputs
        .functions
        .iter()
        .map(|function| function.id.clone())
        .collect();
    for function in inputs.functions {
        validate_function_id(&function.id)?;
        let _: mmmm_contracts::ObjectId = function.source_object_id.parse().map_err(
            |error: mmmm_contracts::identity::IdentityError| {
                DomainError::new("SCHEMA_INVALID", error.to_string())
            },
        )?;
        if function.id == init_id
            || function.id == cleanup_id
            || functions.contains_key(&function.id)
            || backend.defined.contains(&function.id)
        {
            return Err(DomainError::new(
                "SCHEMA_INVALID",
                "Duplicate or reserved generated function",
            ));
        }
        let calls: Vec<_> = function
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let PackInstruction::Call(id) = instruction {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        references.extend(calls.iter().cloned());
        graph.insert(
            function.id.clone(),
            calls
                .iter()
                .filter(|id| manual_ids.contains(*id))
                .cloned()
                .collect(),
        );
        functions.insert(function.id.clone(), function);
    }
    references.extend(backend.referenced.iter().cloned());
    if references.iter().any(|id| {
        !functions.contains_key(id)
            && !backend.defined.contains(id)
            && !backend.external.contains_key(id)
    }) {
        return Err(DomainError::new(
            "REFERENCE_UNRESOLVED",
            "Referenced function has neither generated bytes nor a verified immutable external pin",
        ));
    }
    let mut combined_graph = backend.calls.clone();
    let mut combined_costs = backend.line_costs.clone();
    for id in &backend.defined {
        combined_graph.entry(id.clone()).or_default();
    }
    let all_defined: BTreeSet<_> = functions
        .keys()
        .cloned()
        .chain(backend.defined.iter().cloned())
        .collect();
    for (id, function) in &functions {
        let calls = function
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                PackInstruction::Call(call) if all_defined.contains(call) => Some(call.clone()),
                _ => None,
            })
            .collect();
        combined_graph.insert(id.clone(), calls);
        combined_costs.insert(
            id.clone(),
            function
                .instructions
                .iter()
                .map(|instruction| match instruction {
                    PackInstruction::Call(_) => 1,
                    PackInstruction::Math(fragment) => fragment
                        .source
                        .bytes
                        .iter()
                        .filter(|byte| **byte == b'\n')
                        .count(),
                })
                .sum(),
        );
    }
    for calls in combined_graph.values_mut() {
        calls.retain(|call| all_defined.contains(call));
    }
    validate_expanded_graph(&combined_graph, &combined_costs)?;
    let call_order = validate_call_graph(&graph, &functions)?;
    if inputs.entry_points.keys().any(|key| {
        key.is_empty()
            || key.len() > 64
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    }) || inputs
        .entry_points
        .values()
        .any(|id| !functions.contains_key(id) && !backend.defined.contains(id))
        || inputs.entry_points.contains_key("initialize")
        || inputs.entry_points.contains_key("cleanup")
    {
        return Err(DomainError::new(
            "REFERENCE_UNRESOLVED",
            "Entry point target is missing or reserved",
        ));
    }
    let mut resources = std::mem::take(&mut backend.resources);
    let mut contracts = std::mem::take(&mut backend.contracts);
    let mut source_map_entries = std::mem::take(&mut backend.map_entries);
    let mut objectives = BTreeSet::new();
    let mut cleanup = BTreeSet::new();
    let mut state_symbols = std::mem::take(&mut backend.state);
    let mut private_state_writes = BTreeSet::new();
    let mut losses = std::mem::take(&mut backend.losses);
    let mut loss_bytes_budget = backend.loss_bytes;
    let mut contract_sizes = std::mem::take(&mut backend.contract_sizes);
    let mut contract_bytes_budget = backend.contract_bytes;
    let mut source_map_bytes_budget = backend.map_bytes;
    let mut total_bytes = resources.values().map(|r| r.bytes.len()).sum::<usize>();
    for (id, function) in &functions {
        let mut bytes = Vec::new();
        let mut line = 1usize;
        let mut function_contracts = Vec::new();
        let mut function_contract_bytes = 0usize;
        charge_metadata(&mut contract_bytes_budget, id)?;
        let resource_id = ResourceId::new(format!(
            "pack-function:{}",
            &raw_digest(id.as_str().as_bytes()).as_str()[..24]
        ))
        .expect("generated resource id");
        for instruction in &function.instructions {
            match instruction {
                PackInstruction::Call(target_id) => {
                    let command = format!("function {target_id}\n");
                    bytes.extend_from_slice(command.as_bytes());
                    let entry = serde_json::json!({"sourceObjectId": function.source_object_id,
                        "outputResourceId": resource_id, "locator": format!("line:{line}")});
                    charge_metadata(&mut source_map_bytes_budget, &entry)?;
                    source_map_entries.push(entry);
                    line += 1;
                }
                PackInstruction::Math(fragment) => {
                    if fragment.pins.compiler_digest != implementation
                        || fragment.pins.target_profile_digest != *target.profile_digest()
                        || fragment.pins.target_artifact_digest != *target.artifact_digest()
                        || fragment.fragment.target_profile_id != *target.profile_id()
                        || raw_digest(&fragment.source.bytes) != fragment.source.reference.sha256
                        || fragment.source.bytes.len() as u64
                            != fragment.source.reference.size_bytes
                    {
                        return Err(DomainError::new(
                            "STALE_CONTEXT",
                            "Math fragment implementation/target/resource pin differs",
                        ));
                    }
                    let owner = format!(
                        "math:{}:{}",
                        fragment.pins.input_digest, fragment.pins.symbol_authority_digest
                    );
                    register_private_address(
                        &mut backend.private_addresses,
                        format!("objective:{}", fragment.objective),
                        owner.clone(),
                    )?;
                    let (storage, path) = fragment.private_storage_scope();
                    register_private_address(
                        &mut backend.private_addresses,
                        format!("storage:{storage}:{path}"),
                        owner,
                    )?;
                    objectives.insert(fragment.objective.clone());
                    cleanup.extend(fragment.contract.cleanup.iter().cloned());
                    state_symbols.extend(fragment.contract.state_reads.iter().cloned());
                    state_symbols.extend(fragment.contract.state_writes.iter().cloned());
                    private_state_writes.extend(fragment.contract.state_writes.iter().cloned());
                    for loss in &fragment.fragment.losses {
                        if losses.len() >= 4096 {
                            return Err(DomainError::new(
                                "NUMERIC_RANGE",
                                "Aggregate loss record count exceeds budget",
                            ));
                        }
                        charge_metadata(&mut loss_bytes_budget, loss)?;
                        losses.push(loss.clone());
                    }
                    for expr_line in fragment.node_lines.values() {
                        let entry = serde_json::json!({"sourceObjectId": function.source_object_id,
                            "outputResourceId": resource_id, "locator": format!("line:{}", line + expr_line - 1)});
                        charge_metadata(&mut source_map_bytes_budget, &entry)?;
                        source_map_entries.push(entry);
                    }
                    bytes.extend_from_slice(&fragment.source.bytes);
                    line += fragment
                        .source
                        .bytes
                        .iter()
                        .filter(|byte| **byte == b'\n')
                        .count();
                    let size = charge_metadata(&mut contract_bytes_budget, &fragment.contract)?;
                    function_contract_bytes = function_contract_bytes.saturating_add(size);
                    function_contracts.push(fragment.contract.clone());
                }
            }
            if bytes.len() > MAX_PACK_BYTES {
                return Err(DomainError::new(
                    "NUMERIC_RANGE",
                    "Function output exceeds pack budget",
                ));
            }
        }
        let path = function_path(id);
        insert_resource(
            &mut resources,
            &mut total_bytes,
            path,
            StagedResource::new(resource_id, "text/x-mcfunction; charset=utf-8", bytes),
        )?;
        contracts.insert(id.clone(), function_contracts);
        contract_sizes.insert(id.clone(), function_contract_bytes);
    }
    // A wrapper's contracts include the contracts of its callees. Function
    // metadata cannot become empty merely because its body contains only calls.
    let mut total_contract_entries: usize = contracts.values().map(Vec::len).sum();
    if total_contract_entries > MAX_CONTRACT_ENTRIES.saturating_sub(2) {
        return Err(DomainError::new(
            "NUMERIC_RANGE",
            "Direct contracts leave no budget for required lifecycle metadata",
        ));
    }
    for id in &call_order {
        let mut inherited = Vec::new();
        for call in &graph[id] {
            total_contract_entries = total_contract_entries.saturating_add(contracts[call].len());
            if total_contract_entries > MAX_CONTRACT_ENTRIES.saturating_sub(2) {
                return Err(DomainError::new(
                    "NUMERIC_RANGE",
                    "Expanded function contracts exceed finite metadata budget",
                ));
            }
            let inherited_size = contract_sizes[call];
            reserve_metadata(&mut contract_bytes_budget, inherited_size)?;
            let own_size = contract_sizes.get_mut(id).expect("contract size invariant");
            *own_size = own_size.saturating_add(inherited_size);
            inherited.extend(contracts[call].iter().cloned());
        }
        // Calls into sealed lowerings carry those contracts into wrappers as
        // well; external functions remain separately pinned runtime requirements.
        for call in functions[id]
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                PackInstruction::Call(call) if !functions.contains_key(call) => Some(call),
                _ => None,
            })
        {
            if let Some(callee) = contracts.get(call) {
                total_contract_entries = total_contract_entries.saturating_add(callee.len());
                if total_contract_entries > MAX_CONTRACT_ENTRIES.saturating_sub(2) {
                    return Err(DomainError::new(
                        "NUMERIC_RANGE",
                        "Expanded contracts exceed finite entry budget",
                    ));
                }
                let inherited_size = contract_sizes[call];
                reserve_metadata(&mut contract_bytes_budget, inherited_size)?;
                let previous_size = contract_sizes[id];
                *contract_sizes.get_mut(id).expect("contract size invariant") =
                    previous_size.saturating_add(inherited_size);
                inherited.extend(callee.iter().cloned());
            }
        }
        contracts
            .get_mut(id)
            .expect("generated function contract")
            .extend(inherited);
        if contracts[id].is_empty() {
            total_contract_entries = total_contract_entries.saturating_add(1);
            if total_contract_entries > MAX_CONTRACT_ENTRIES.saturating_sub(2) {
                return Err(DomainError::new(
                    "NUMERIC_RANGE",
                    "Empty-function contract exceeds finite metadata entry budget",
                ));
            }
            let empty = GeneratedFunctionContract {
                inputs: Vec::new(),
                outputs: Vec::new(),
                state_reads: Vec::new(),
                state_writes: Vec::new(),
                execution_context: "caller_origin",
                reentrancy: "serialized_by_application",
                scheduled_callbacks: Vec::new(),
                cleanup: Vec::new(),
                requirements: Vec::new(),
            };
            let size = charge_metadata(&mut contract_bytes_budget, &empty)?;
            *contract_sizes.get_mut(id).expect("contract size invariant") = size;
            contracts
                .get_mut(id)
                .expect("generated function contract")
                .push(empty);
        }
    }
    let initialize: Vec<u8> = objectives
        .iter()
        .map(|objective| format!("scoreboard objectives add {objective} dummy\n"))
        .collect::<String>()
        .into_bytes();
    let cleanup_bytes: Vec<u8> = cleanup
        .iter()
        .map(|command| format!("{command}\n"))
        .chain(
            objectives
                .iter()
                .map(|objective| format!("scoreboard objectives remove {objective}\n")),
        )
        .collect::<String>()
        .into_bytes();
    for (id, role, bytes) in [
        (init_id.clone(), "initialize", initialize),
        (cleanup_id.clone(), "cleanup", cleanup_bytes),
    ] {
        let resource = StagedResource::new(
            ResourceId::new(format!("pack-{role}:{suffix}")).expect("generated resource"),
            "text/x-mcfunction; charset=utf-8",
            bytes,
        );
        let entry = serde_json::json!({"sourceObjectId": request.project_id,
            "outputResourceId": resource.reference.resource_id, "locator": "line:1"});
        charge_metadata(&mut source_map_bytes_budget, &entry)?;
        source_map_entries.push(entry);
        insert_resource(
            &mut resources,
            &mut total_bytes,
            function_path(&id),
            resource,
        )?;
        // Even lifecycle functions carry a tracked function contract.
        let writes = if role == "initialize" {
            objectives
                .iter()
                .map(|objective| format!("objective:{objective}"))
                .collect()
        } else {
            private_state_writes
                .iter()
                .cloned()
                .chain(
                    objectives
                        .iter()
                        .map(|objective| format!("objective:{objective}")),
                )
                .collect()
        };
        let lifecycle = GeneratedFunctionContract { inputs: Vec::new(), outputs: Vec::new(),
            state_reads: Vec::new(), state_writes: writes,
            execution_context: "server_owned_lifecycle", reentrancy: "forbidden_requires_serialized_lifecycle",
            scheduled_callbacks: Vec::new(), cleanup: Vec::new(),
            requirements: vec!["application must check exclusive ownership of every generated score/storage symbol before lifecycle execution".into()] };
        charge_metadata(&mut contract_bytes_budget, &id)?;
        charge_metadata(&mut contract_bytes_budget, &lifecycle)?;
        contracts.insert(id, vec![lifecycle]);
    }
    let metadata = canonical_bytes(
        &serde_json::json!({"pack": {"description": "MMMM generated native content",
        "min_format": pack_version, "max_format": pack_version}}),
    )
    .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    insert_resource(
        &mut resources,
        &mut total_bytes,
        "pack.mcmeta".into(),
        StagedResource::new(
            ResourceId::new(format!("pack-metadata:{suffix}")).expect("generated resource"),
            "application/json",
            metadata,
        ),
    )?;
    let source_map_value = serde_json::json!({"contractVersion": "0.2.0", "generatorVersion": "mmmm-compiler/0.1.0",
        "inputRevision": request.expected_revision, "entries": source_map_entries});
    let _: Value = decode("SourceMap", &source_map_value)?;
    let source_map = StagedResource::new(
        ResourceId::new(format!("pack-source-map:{suffix}")).expect("generated resource"),
        "application/json",
        canonical_bytes(&source_map_value)
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?,
    );
    insert_resource(
        &mut resources,
        &mut total_bytes,
        "mmmm/source-map.json".into(),
        source_map.clone(),
    )?;
    let contract_bytes = canonical_bytes(
        &serde_json::to_value(&contracts)
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?,
    )
    .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
    insert_resource(
        &mut resources,
        &mut total_bytes,
        "mmmm/function-contracts.json".into(),
        StagedResource::new(
            ResourceId::new(format!("pack-function-contracts:{suffix}"))
                .expect("generated resource"),
            "application/json",
            contract_bytes,
        ),
    )?;
    let mut entry_points = inputs.entry_points;
    for (name, id) in backend.entries {
        if entry_points.insert(name, id).is_some() {
            return Err(DomainError::new(
                "ID_COLLISION",
                "Generated entry point name collision",
            ));
        }
    }
    if entry_points.is_empty() || entry_points.len() > MAX_FUNCTIONS {
        return Err(DomainError::new(
            "NUMERIC_RANGE",
            "Generated entry points require finite nonempty inventory",
        ));
    }
    entry_points.insert("initialize".into(), init_id.clone());
    entry_points.insert("cleanup".into(), cleanup_id.clone());
    let mut defined: Vec<_> = functions.keys().cloned().collect();
    defined.extend(backend.defined);
    defined.extend([init_id, cleanup_id]);
    defined.sort();
    // A verified external pin may also resolve to exact generated bytes in
    // this bundle. Conflicting sources remain unresolved instead of shadowing.
    let mut external = Vec::new();
    let mut dependency_pins = Vec::new();
    for (id, pin) in &backend.external {
        if defined.contains(id) {
            if resources
                .get(&function_path(id))
                .is_none_or(|resource| &resource.reference.sha256 != pin)
            {
                return Err(DomainError::new(
                    "REFERENCE_UNRESOLVED",
                    "External source pin conflicts with generated function bytes",
                ));
            }
        } else {
            external.push(id.clone());
            dependency_pins.push(serde_json::json!({"function":id,"sha256":pin}));
        }
    }
    if !dependency_pins.is_empty() {
        let bytes = canonical_bytes(&serde_json::json!({"externalFunctions":dependency_pins}))
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
        insert_resource(
            &mut resources,
            &mut total_bytes,
            "mmmm/dependencies.json".into(),
            StagedResource::new(
                ResourceId::new(format!("pack-dependencies:{suffix}")).expect("generated resource"),
                "application/json",
                bytes,
            ),
        )?;
        backend
            .runtime
            .insert("mmmm:external_function_byte_pins".into());
    }
    if !backend.resource_pack.is_empty() {
        let version = target.resource_pack_version().ok_or_else(|| {
            DomainError::new(
                "UNSUPPORTED_TARGET_VERSION",
                "Resource pack assets require an exact verified resource pack format",
            )
        })?;
        let metadata = canonical_bytes(&serde_json::json!({"pack":{"description":"MMMM generated resource content","min_format":version,"max_format":version}}))
            .map_err(|error|DomainError::new("SCHEMA_INVALID",error.to_string()))?;
        let existing = std::mem::take(&mut resources);
        for (path, resource) in existing {
            resources.insert(format!("data-pack/{path}"), resource);
        }
        for (path, resource) in backend.resource_pack {
            insert_resource(
                &mut resources,
                &mut total_bytes,
                format!("resource-pack/{path}"),
                resource,
            )?;
        }
        insert_resource(
            &mut resources,
            &mut total_bytes,
            "resource-pack/pack.mcmeta".into(),
            StagedResource::new(
                ResourceId::new(format!("resource-pack-metadata:{suffix}"))
                    .expect("generated resource"),
                "application/json",
                metadata,
            ),
        )?;
        backend
            .runtime
            .insert("mmmm:separate_resource_pack_installation".into());
    }
    let manifest = ExportManifest {
        contract_version: "0.2.0",
        manifest_id: ManifestId::new(format!("export:{suffix}")).expect("generated manifest"),
        project_id: request.project_id,
        input_revision: request.expected_revision,
        target_profile_id: request.target_profile_id,
        generator_digest: implementation,
        files: resources
            .iter()
            .map(|(path, resource)| ExportFile {
                path: path.clone(),
                resource: resource.reference.clone(),
            })
            .collect(),
        defined_functions: defined,
        referenced_functions: references.into_iter().collect(),
        external_functions: external,
        entry_points,
        state_symbols: state_symbols.into_iter().collect(),
        runtime_dependencies: backend.runtime.into_iter().collect(),
        source_map: source_map.reference.clone(),
        losses,
        validation_stage: "statically_checked",
    };
    encode("ExportManifest", &manifest)?;
    Ok(PackDraft {
        manifest,
        resources,
        function_contracts: contracts,
        source_map,
        target_profile_digest: target.profile_digest().clone(),
        target_artifact_digest: target.artifact_digest().clone(),
    })
}

fn function_identity(functions: &[PackFunction]) -> Value {
    let mut ordered: Vec<_> = functions.iter().collect();
    ordered.sort_by(|left, right| left.id.cmp(&right.id));
    Value::Array(ordered.into_iter().map(|function| serde_json::json!({"id": function.id,
        "sourceObjectId": function.source_object_id, "instructions": function.instructions.iter().map(|instruction|
        match instruction { PackInstruction::Call(id) => serde_json::json!({"call": id}),
            PackInstruction::Math(fragment) => serde_json::json!({"source": fragment.source.reference,
                "input": fragment.pins.input_digest, "symbols": fragment.pins.symbol_authority_digest}) }).collect::<Vec<_>>() })).collect())
}

pub(crate) fn validate_function_id(id: &ResourceLocation) -> Result<(), DomainError> {
    let (namespace, path) = id
        .as_str()
        .split_once(':')
        .expect("validated resource location");
    if namespace == "minecraft"
        || namespace.len() > 64
        || !portable_component(namespace)
        || path.len() > 160
        || path.split('/').any(|part| !portable_component(part))
    {
        return Err(DomainError::new(
            "SCHEMA_INVALID",
            "Nonportable/reserved function output path",
        ));
    }
    Ok(())
}

fn portable_component(part: &str) -> bool {
    !(part.is_empty()
        || part == "."
        || part == ".."
        || part.ends_with('.')
        || part.len() > 64
        || [
            "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
            "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
        ]
        .contains(&part.split('.').next().unwrap_or_default()))
}

pub(crate) fn function_path(id: &ResourceLocation) -> String {
    let (namespace, path) = id.as_str().split_once(':').expect("validated location");
    format!("data/{namespace}/function/{path}.mcfunction")
}

fn validate_expanded_graph(
    graph: &BTreeMap<ResourceLocation, Vec<ResourceLocation>>,
    base: &BTreeMap<ResourceLocation, usize>,
) -> Result<(), DomainError> {
    let mut pending: BTreeMap<_, _> = graph
        .iter()
        .map(|(id, calls)| (id.clone(), calls.len()))
        .collect();
    let mut inverse: BTreeMap<ResourceLocation, Vec<ResourceLocation>> = BTreeMap::new();
    for (id, calls) in graph {
        for call in calls {
            if !graph.contains_key(call) {
                return Err(DomainError::new(
                    "REFERENCE_UNRESOLVED",
                    "Generated call adjacency target has no sealed body",
                ));
            }
            inverse.entry(call.clone()).or_default().push(id.clone());
        }
    }
    let mut ready: BTreeSet<_> = pending
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut costs: BTreeMap<ResourceLocation, usize> = BTreeMap::new();
    let mut depths: BTreeMap<ResourceLocation, usize> = BTreeMap::new();
    while let Some(id) = ready.pop_first() {
        let mut cost = *base.get(&id).ok_or_else(|| {
            DomainError::new("REFERENCE_UNRESOLVED", "Generated body cost absent")
        })?;
        let mut depth = 1usize;
        for call in &graph[&id] {
            cost = cost.saturating_add(costs[call]);
            depth = depth.max(depths[call].saturating_add(1));
        }
        if cost > 65536 || depth > 64 {
            return Err(DomainError::new(
                "NUMERIC_RANGE",
                "Combined scene/animation/math execution exceeds finite instruction/depth budget",
            ));
        }
        costs.insert(id.clone(), cost);
        depths.insert(id.clone(), depth);
        for caller in inverse.get(&id).into_iter().flatten() {
            let count = pending.get_mut(caller).expect("validated adjacency");
            *count -= 1;
            if *count == 0 {
                ready.insert(caller.clone());
            }
        }
    }
    if costs.len() != graph.len() {
        return Err(DomainError::new(
            "UNSUPPORTED_OPERATOR",
            "Recursive combined generated functions have no finite execution proof",
        ));
    }
    Ok(())
}

fn validate_call_graph(
    graph: &BTreeMap<ResourceLocation, Vec<ResourceLocation>>,
    functions: &BTreeMap<ResourceLocation, PackFunction>,
) -> Result<Vec<ResourceLocation>, DomainError> {
    let mut pending: BTreeMap<_, _> = graph
        .iter()
        .map(|(id, calls)| (id.clone(), calls.len()))
        .collect();
    let mut inverse: BTreeMap<ResourceLocation, Vec<ResourceLocation>> = BTreeMap::new();
    for (id, calls) in graph {
        for call in calls {
            inverse.entry(call.clone()).or_default().push(id.clone());
        }
    }
    let mut ready: BTreeSet<_> = pending
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut order = Vec::new();
    let mut costs: BTreeMap<ResourceLocation, usize> = BTreeMap::new();
    let mut depths: BTreeMap<ResourceLocation, usize> = BTreeMap::new();
    while let Some(id) = ready.pop_first() {
        let mut cost = 0usize;
        let mut depth = 1usize;
        for instruction in &functions[&id].instructions {
            let weight = match instruction {
                PackInstruction::Math(fragment) => fragment
                    .source
                    .bytes
                    .iter()
                    .filter(|byte| **byte == b'\n')
                    .count(),
                PackInstruction::Call(call) => {
                    depth = depth.max(depths.get(call).copied().unwrap_or(1).saturating_add(1));
                    costs.get(call).copied().unwrap_or(1).saturating_add(1)
                }
            };
            cost = cost.saturating_add(weight);
            if cost > 65536 || depth > 64 {
                return Err(DomainError::new(
                    "NUMERIC_RANGE",
                    "Expanded function execution exceeds finite instruction/depth budget",
                ));
            }
        }
        costs.insert(id.clone(), cost);
        depths.insert(id.clone(), depth);
        order.push(id.clone());
        for caller in inverse.get(&id).into_iter().flatten() {
            let count = pending.get_mut(caller).expect("validated call target");
            *count -= 1;
            if *count == 0 {
                ready.insert(caller.clone());
            }
        }
    }
    if order.len() != graph.len() {
        return Err(DomainError::new(
            "UNSUPPORTED_OPERATOR",
            "Recursive generated function calls have no finite execution proof",
        ));
    }
    Ok(order)
}

pub(crate) fn insert_resource(
    resources: &mut BTreeMap<String, StagedResource>,
    total: &mut usize,
    path: String,
    resource: StagedResource,
) -> Result<(), DomainError> {
    let next = total
        .checked_add(resource.bytes.len())
        .ok_or_else(|| DomainError::new("NUMERIC_RANGE", "Pack size overflow"))?;
    if next > MAX_PACK_BYTES
        || resources.contains_key(&path)
        || resources.keys().any(|existing| {
            path.starts_with(&format!("{existing}/")) || existing.starts_with(&format!("{path}/"))
        })
    {
        return Err(DomainError::new(
            "NUMERIC_RANGE",
            "Pack output collision or aggregate byte budget exceeded",
        ));
    }
    *total = next;
    resources.insert(path, resource);
    Ok(())
}

fn reserve_metadata(total: &mut usize, size: usize) -> Result<(), DomainError> {
    let next = total
        .checked_add(size)
        .ok_or_else(|| DomainError::new("NUMERIC_RANGE", "Metadata byte count overflow"))?;
    if next > MAX_METADATA_BYTES {
        return Err(DomainError::new(
            "NUMERIC_RANGE",
            "Aggregate metadata bytes exceed budget before cloning/serialization",
        ));
    }
    *total = next;
    Ok(())
}

pub(crate) fn charge_metadata<T: Serialize>(
    total: &mut usize,
    value: &T,
) -> Result<usize, DomainError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let next = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("Metadata size overflow"))?;
            if next > MAX_METADATA_BYTES {
                return Err(std::io::Error::other("Metadata byte budget exceeded"));
            }
            self.0 = next;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)
        .map_err(|error| DomainError::new("NUMERIC_RANGE", error.to_string()))?;
    // Include array separators and conservative enclosing-key/container bytes.
    let size = counter.0.saturating_add(16);
    reserve_metadata(total, size)?;
    Ok(size)
}

#[cfg(test)]
mod generated_graph_tests {
    use super::*;

    #[test]
    fn small_authored_bodies_cannot_hide_exponential_generated_call_expansion() {
        let ids: Vec<ResourceLocation> = (0..17)
            .map(|index| ResourceLocation::new(format!("fixture:f{index}")).unwrap())
            .collect();
        let mut graph = BTreeMap::new();
        let mut base = BTreeMap::new();
        graph.insert(ids[0].clone(), Vec::new());
        base.insert(ids[0].clone(), 1);
        for index in 1..ids.len() {
            graph.insert(
                ids[index].clone(),
                vec![ids[index - 1].clone(), ids[index - 1].clone()],
            );
            base.insert(ids[index].clone(), 1);
        }
        // The independently derived recurrence C(n)=1+2*C(n-1) gives
        // C(16)=131071, despite only 17 tiny source files being staged.
        assert_eq!((1usize << 17) - 1, 131071);
        assert_eq!(
            validate_expanded_graph(&graph, &base).unwrap_err().code,
            "NUMERIC_RANGE"
        );
        graph.remove(&ids[16]);
        base.remove(&ids[16]);
        assert_eq!((1usize << 16) - 1, 65535);
        validate_expanded_graph(&graph, &base).unwrap();
    }

    #[test]
    fn combined_generated_cycle_and_large_backend_wrapper_are_rejected() {
        let wrapper = ResourceLocation::new("fixture:wrapper").unwrap();
        let backend = ResourceLocation::new("fixture:backend").unwrap();
        let mut graph = BTreeMap::from([
            (wrapper.clone(), vec![backend.clone()]),
            (backend.clone(), Vec::new()),
        ]);
        let base = BTreeMap::from([(wrapper.clone(), 2), (backend.clone(), 65535)]);
        assert_eq!(
            validate_expanded_graph(&graph, &base).unwrap_err().code,
            "NUMERIC_RANGE"
        );
        graph.insert(backend.clone(), vec![wrapper.clone()]);
        let base = BTreeMap::from([(wrapper, 1), (backend, 1)]);
        assert_eq!(
            validate_expanded_graph(&graph, &base).unwrap_err().code,
            "UNSUPPORTED_OPERATOR"
        );
    }
}

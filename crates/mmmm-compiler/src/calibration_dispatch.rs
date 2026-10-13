//! Sealed source recipe for the finite 47-case numeric calibration suite.
//!
//! This module constructs logical pack entries and an ordered dispatch recipe.
//! It does not execute commands, load functions, allocate game ownership, grant
//! writes, issue evidence, or declare a target supported. A host must load these
//! exact sources and invoke each original function entry through its native
//! function dispatcher; flattening the bodies into an inline executor changes
//! the program and cannot produce evidence for this recipe.

use crate::BindingAddress;
use crate::calibration::{CalibrationCase, CalibrationProgram};
use mmmm_contracts::{ResourceLocation, Sha256Digest, canonical_bytes, raw_digest};
use mmmm_domain::DomainError;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Source and observation addresses only. The host must reserve the objective
/// and storage subtrees under its own exclusive scope before initialization.
#[derive(Debug, Clone)]
pub struct CalibrationDispatchAddresses {
    case: CalibrationCase,
    function_id: ResourceLocation,
    objective: String,
    storage: ResourceLocation,
    ok_score: BindingAddress,
    stale_score: BindingAddress,
    stale_storage: BindingAddress,
    result_address: BindingAddress,
    scratch_address: BindingAddress,
    input_addresses: Vec<BindingAddress>,
}

impl CalibrationDispatchAddresses {
    pub const fn case(&self) -> CalibrationCase {
        self.case
    }
    pub fn function_id(&self) -> &ResourceLocation {
        &self.function_id
    }
    pub fn objective(&self) -> &str {
        &self.objective
    }
    pub fn storage(&self) -> &ResourceLocation {
        &self.storage
    }
    pub fn ok_score(&self) -> &BindingAddress {
        &self.ok_score
    }
    pub fn stale_score(&self) -> &BindingAddress {
        &self.stale_score
    }
    pub fn stale_storage(&self) -> &BindingAddress {
        &self.stale_storage
    }
    pub fn result_address(&self) -> &BindingAddress {
        &self.result_address
    }
    /// Complete invocation compound, including stale markers and every node.
    pub fn scratch_address(&self) -> &BindingAddress {
        &self.scratch_address
    }
    pub fn input_addresses(&self) -> &[BindingAddress] {
        &self.input_addresses
    }

    fn recipe(&self) -> Value {
        json!({
            "caseId":self.case.case_id(),
            "function":self.function_id.as_str(),
            "objective":self.objective,
            "storage":self.storage.as_str(),
            "ownedStorageSubtrees":["inputs","invocation"],
            "okScore":address_recipe(&self.ok_score),
            "staleScore":address_recipe(&self.stale_score),
            "staleStorage":address_recipe(&self.stale_storage),
            "result":address_recipe(&self.result_address),
            "scratch":address_recipe(&self.scratch_address),
            "inputs":self.input_addresses.iter().map(address_recipe).collect::<Vec<_>>()
        })
    }
}

/// Counts of the constructed recipe, not measurements of an executed run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalibrationDispatchBudget {
    cases: usize,
    logical_entries: usize,
    source_bytes: usize,
    commands: usize,
    command_bytes: usize,
    recipe_bytes: usize,
    max_command_bytes: usize,
}

impl CalibrationDispatchBudget {
    pub const fn cases(&self) -> usize {
        self.cases
    }
    pub const fn logical_entries(&self) -> usize {
        self.logical_entries
    }
    pub const fn source_bytes(&self) -> usize {
        self.source_bytes
    }
    /// Initialization, native function entries, body sites and cleanup sites.
    /// This is a finite site inventory, not a claimed runtime execution count.
    pub const fn commands(&self) -> usize {
        self.commands
    }
    pub const fn command_bytes(&self) -> usize {
        self.command_bytes
    }
    pub const fn recipe_bytes(&self) -> usize {
        self.recipe_bytes
    }
    pub const fn max_command_bytes(&self) -> usize {
        self.max_command_bytes
    }
}

/// Only normative47() creates this type. Fields are private and there is no
/// Deserialize or caller-command constructor. Getters expose a source recipe,
/// never an issued run, loaded-source token or execution authorization.
///
/// ```compile_fail
/// use mmmm_compiler::calibration_dispatch::CalibrationDispatchPlan;
/// let forged = CalibrationDispatchPlan {
///     programs: Vec::new(),
///     ..CalibrationDispatchPlan::normative47().unwrap()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct CalibrationDispatchPlan {
    programs: Vec<CalibrationProgram>,
    source_entries: BTreeMap<String, Vec<u8>>,
    owned_addresses: Vec<CalibrationDispatchAddresses>,
    initialization_commands: Vec<String>,
    cleanup_commands: Vec<String>,
    canonical_recipe_bytes: Vec<u8>,
    suite_digest: Sha256Digest,
    budget: CalibrationDispatchBudget,
}

impl CalibrationDispatchPlan {
    pub const MAX_CASES: usize = 47;
    pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;
    pub const MAX_COMMANDS: usize = 4096;
    pub const MAX_COMMAND_BYTES: usize = 8192;
    pub const MAX_RECIPE_BYTES: usize = 4 * 1024 * 1024;

    pub fn normative47() -> Result<Self, DomainError> {
        if CalibrationCase::ALL.len() != Self::MAX_CASES {
            return Err(invalid(
                "The normative dispatch suite must contain exactly 47 cases",
            ));
        }
        let programs = CalibrationCase::ALL
            .iter()
            .copied()
            .map(CalibrationProgram::for_case)
            .collect::<Result<Vec<_>, _>>()?;
        let mut source_entries = BTreeMap::new();
        source_entries.insert(
            "pack.mcmeta".into(),
            canonical_bytes(&json!({"pack":{
                "description":"MMMM numeric calibration dispatch/1",
                "min_format":[121,0],"max_format":[121,0]
            }}))
            .map_err(|error| invalid(error.to_string()))?,
        );
        let mut owned_addresses = Vec::with_capacity(programs.len());
        let mut initialization_commands = Vec::new();
        let mut objectives = BTreeSet::new();
        let mut storages = BTreeSet::new();
        let mut functions = BTreeSet::new();
        let mut case_ids = BTreeSet::new();
        let mut body_commands = 0usize;
        let mut body_command_bytes = 0usize;
        let mut max_command_bytes = 0usize;

        for program in &programs {
            verify_program(program)?;
            let function = program
                .invocation_command()
                .strip_prefix("function ")
                .ok_or_else(|| invalid("A calibration entry must use native function dispatch"))?;
            let function_id =
                ResourceLocation::new(function).map_err(|error| invalid(error.to_string()))?;
            let (namespace, path) = function
                .split_once(':')
                .ok_or_else(|| invalid("A calibration function needs a namespace"))?;
            if namespace != "mmmm_calibration"
                || !case_ids.insert(program.case().case_id())
                || !functions.insert(function.to_owned())
                || !objectives.insert(program.scope().objective().to_owned())
                || !storages.insert(program.scope().storage().as_str().to_owned())
            {
                return Err(invalid(
                    "Duplicate or unexpected calibration case ownership",
                ));
            }
            let logical_path = format!("data/{namespace}/function/{path}.mcfunction");
            if source_entries
                .insert(logical_path, program.source_bytes().to_vec())
                .is_some()
            {
                return Err(invalid("Duplicate calibration function source path"));
            }
            initialization_commands.extend_from_slice(program.initialization_commands());
            charge_commands(
                program.commands(),
                &mut body_commands,
                &mut body_command_bytes,
                &mut max_command_bytes,
            )?;
            let objective = program.scope().objective().to_owned();
            let storage = program.scope().storage().clone();
            owned_addresses.push(CalibrationDispatchAddresses {
                case: program.case(),
                function_id,
                ok_score: BindingAddress::Score {
                    holder: "#ok".into(),
                    objective: objective.clone(),
                },
                stale_score: BindingAddress::Score {
                    holder: "#result".into(),
                    objective: objective.clone(),
                },
                stale_storage: BindingAddress::Storage {
                    storage: storage.clone(),
                    path: "invocation.result".into(),
                },
                result_address: program.scope().result_address().clone(),
                scratch_address: BindingAddress::Storage {
                    storage: storage.clone(),
                    path: program.scope().scratch_path().into(),
                },
                input_addresses: program.scope().input_addresses().to_vec(),
                objective,
                storage,
            });
        }
        let cleanup_commands = programs
            .iter()
            .rev()
            .flat_map(|program| program.cleanup_commands().iter().cloned())
            .collect::<Vec<_>>();
        let invocation_commands = programs
            .iter()
            .map(|program| program.invocation_command().to_owned())
            .collect::<Vec<_>>();
        for sequence in [
            &initialization_commands,
            &invocation_commands,
            &cleanup_commands,
        ] {
            charge_commands(
                sequence,
                &mut body_commands,
                &mut body_command_bytes,
                &mut max_command_bytes,
            )?;
        }
        let source_bytes = source_entries.values().try_fold(0usize, |sum, bytes| {
            checked_add(sum, bytes.len(), "Calibration source byte count overflow")
        })?;
        if source_bytes > Self::MAX_SOURCE_BYTES || source_entries.len() != Self::MAX_CASES + 1 {
            return Err(invalid(
                "Calibration logical source inventory exceeds its budget",
            ));
        }
        let mut budget = CalibrationDispatchBudget {
            cases: programs.len(),
            logical_entries: source_entries.len(),
            source_bytes,
            commands: body_commands,
            command_bytes: body_command_bytes,
            recipe_bytes: 0,
            max_command_bytes,
        };
        let recipe = logical_recipe(
            &programs,
            &source_entries,
            &owned_addresses,
            &initialization_commands,
            &cleanup_commands,
            &budget,
        )?;
        let canonical_recipe_bytes =
            canonical_bytes(&recipe).map_err(|error| invalid(error.to_string()))?;
        if canonical_recipe_bytes.len() > Self::MAX_RECIPE_BYTES {
            return Err(invalid(
                "Calibration canonical recipe exceeds its byte budget",
            ));
        }
        budget.recipe_bytes = canonical_recipe_bytes.len();
        let suite_digest = raw_digest(&canonical_recipe_bytes);
        Ok(Self {
            programs,
            source_entries,
            owned_addresses,
            initialization_commands,
            cleanup_commands,
            canonical_recipe_bytes,
            suite_digest,
            budget,
        })
    }

    pub const fn cases(&self) -> &'static [CalibrationCase] {
        CalibrationCase::ALL
    }
    pub fn programs(&self) -> &[CalibrationProgram] {
        &self.programs
    }
    /// Logical entries, never a ZIP digest or proof of installed pack contents.
    pub fn source_entries(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.source_entries
    }
    /// Pins source bytes, ownership inventory, dispatch order and probe sites.
    /// Expected values remain in CalibrationProgram; observations are host data.
    pub fn suite_digest(&self) -> &Sha256Digest {
        &self.suite_digest
    }
    /// Canonical internal recipe bytes; this is not a public wire DTO/schema.
    pub fn canonical_recipe_bytes(&self) -> &[u8] {
        &self.canonical_recipe_bytes
    }
    pub fn owned_addresses(&self) -> &[CalibrationDispatchAddresses] {
        &self.owned_addresses
    }
    /// ALL order. Successful creation and exclusivity need real host evidence.
    pub fn initialization_commands(&self) -> &[String] {
        &self.initialization_commands
    }
    /// Reverse ALL order, preserving each program's internal cleanup order.
    pub fn cleanup_commands(&self) -> &[String] {
        &self.cleanup_commands
    }
    pub const fn budget(&self) -> &CalibrationDispatchBudget {
        &self.budget
    }
}

fn verify_program(program: &CalibrationProgram) -> Result<(), DomainError> {
    if program.source_digest() != &raw_digest(program.source_bytes()) {
        return Err(invalid(
            "Calibration original source digest is inconsistent",
        ));
    }
    let source = std::str::from_utf8(program.source_bytes())
        .map_err(|_| invalid("Calibration function source must be UTF-8"))?;
    let source_commands = source
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();
    if !source.ends_with('\n')
        || source.contains('\r')
        || source_commands.len() != program.commands().len()
        || source_commands
            .iter()
            .zip(program.commands())
            .any(|(a, b)| *a != b.as_str())
        || program.preseed_end_index() == 0
        || program.preseed_end_index() as usize > program.commands().len()
        || program.command_stage_index() < program.preseed_end_index()
        || program.command_stage_index() as usize >= program.commands().len()
    {
        return Err(invalid(
            "Calibration source sites or preseed boundary are inconsistent",
        ));
    }
    Ok(())
}

fn logical_recipe(
    programs: &[CalibrationProgram],
    entries: &BTreeMap<String, Vec<u8>>,
    addresses: &[CalibrationDispatchAddresses],
    initialization: &[String],
    cleanup: &[String],
    budget: &CalibrationDispatchBudget,
) -> Result<Value, DomainError> {
    let logical_entries = entries
        .iter()
        .map(|(path, bytes)| {
            let utf8 = std::str::from_utf8(bytes)
                .map_err(|_| invalid("Calibration logical entry must be UTF-8"))?;
            Ok(json!({"path":path,"rawSha256":raw_digest(bytes).as_str(),"sourceUtf8":utf8}))
        })
        .collect::<Result<Vec<_>, DomainError>>()?;
    let probes = programs
        .iter()
        .zip(addresses)
        .map(|(program, addresses)| {
            json!({
                "caseId":program.case().case_id(),
                "originalProgramSha256":program.source_digest().as_str(),
                "invocationCommand":program.invocation_command(),
                "commands":program.commands(),
                "preseedEndIndex":program.preseed_end_index(),
                "selectedCommandStageIndex":program.command_stage_index(),
                "readbackAddresses":addresses.recipe(),
                "initializationCommands":program.initialization_commands(),
                "cleanupCommands":program.cleanup_commands()
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "recipeKind":"mmmm_numeric_calibration_dispatch",
        "recipeVersion":1,
        "suite":"normative47",
        "nativePackFormat":[121,0],
        "logicalEntries":logical_entries,
        "initializationCommands":initialization,
        "probes":probes,
        "cleanupCommands":cleanup,
        "siteCounts":{
            "cases":budget.cases,"logicalEntries":budget.logical_entries,
            "sourceBytes":budget.source_bytes,"commands":budget.commands,
            "commandBytes":budget.command_bytes,"maxCommandBytes":budget.max_command_bytes
        },
        "limits":{
            "cases":CalibrationDispatchPlan::MAX_CASES,
            "sourceBytes":CalibrationDispatchPlan::MAX_SOURCE_BYTES,
            "commands":CalibrationDispatchPlan::MAX_COMMANDS,
            "commandBytes":CalibrationDispatchPlan::MAX_COMMAND_BYTES,
            "recipeBytes":CalibrationDispatchPlan::MAX_RECIPE_BYTES
        }
    }))
}

fn address_recipe(address: &BindingAddress) -> Value {
    match address {
        BindingAddress::Score { holder, objective } => {
            json!({"kind":"score","holder":holder,"objective":objective})
        }
        BindingAddress::Storage { storage, path } => {
            json!({"kind":"storage","storage":storage.as_str(),"path":path})
        }
    }
}

fn charge_commands(
    sequence: &[String],
    count: &mut usize,
    bytes: &mut usize,
    longest: &mut usize,
) -> Result<(), DomainError> {
    for command in sequence {
        if command.is_empty()
            || command.len() > CalibrationDispatchPlan::MAX_COMMAND_BYTES
            || command
                .bytes()
                .any(|byte| matches!(byte, b'\r' | b'\n' | b'\0'))
            || command.starts_with('#')
        {
            return Err(invalid(
                "Calibration command site is empty, multiline or oversized",
            ));
        }
        *count = checked_add(*count, 1, "Calibration command count overflow")?;
        *bytes = checked_add(
            *bytes,
            command.len(),
            "Calibration command byte count overflow",
        )?;
        *longest = (*longest).max(command.len());
        if *count > CalibrationDispatchPlan::MAX_COMMANDS {
            return Err(invalid(
                "Calibration command site inventory exceeds its budget",
            ));
        }
    }
    Ok(())
}

fn checked_add(value: usize, amount: usize, message: &str) -> Result<usize, DomainError> {
    value.checked_add(amount).ok_or_else(|| invalid(message))
}

fn invalid(message: impl Into<String>) -> DomainError {
    DomainError::new("SCHEMA_INVALID", message)
}

#[cfg(test)]
#[path = "calibration_dispatch_tests.rs"]
mod tests;

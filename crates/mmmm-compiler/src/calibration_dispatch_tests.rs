//! Dispatch recipe fixtures bind the already sealed numeric programs to exact
//! logical entries, addresses and observation sites. They cannot manufacture
//! permission, native execution, loaded-byte proof, or target admission.
//! Program tests alone do not cover aggregate ordering and recipe identity.

use super::CalibrationDispatchPlan;
use crate::{
    BindingAddress,
    calibration::{CalibrationCase, CalibrationProgram},
};
use mmmm_contracts::{canonical_bytes, parse_json, raw_digest};
use serde_json::json;
use std::collections::BTreeSet;

fn plan() -> CalibrationDispatchPlan {
    CalibrationDispatchPlan::normative47().expect("finite sealed calibration dispatch plan")
}

fn assert_recipe_address(value: &serde_json::Value, address: &BindingAddress) {
    assert_eq!(value.as_object().unwrap().len(), 3);
    match address {
        BindingAddress::Score { holder, objective } => {
            assert_eq!(value["kind"], json!("score"));
            assert_eq!(value["holder"], json!(holder));
            assert_eq!(value["objective"], json!(objective));
        }
        BindingAddress::Storage { storage, path } => {
            assert_eq!(value["kind"], json!("storage"));
            assert_eq!(value["storage"], json!(storage.as_str()));
            assert_eq!(value["path"], json!(path));
        }
    }
}

#[test]
fn dispatch_is_exactly_the_closed47_case_corpus_with_distinct_owned_scopes() {
    let dispatch = plan();
    assert_eq!(dispatch.cases(), CalibrationCase::ALL);
    assert_eq!(dispatch.cases().len(), 47);
    assert_eq!(dispatch.programs().len(), 47);
    assert_eq!(dispatch.owned_addresses().len(), 47);
    let mut objectives = BTreeSet::new();
    let mut storages = BTreeSet::new();
    let mut functions = BTreeSet::new();
    for ((case, program), addresses) in dispatch
        .cases()
        .iter()
        .zip(dispatch.programs())
        .zip(dispatch.owned_addresses())
    {
        assert_eq!(program.case(), *case);
        assert_eq!(addresses.case(), *case);
        assert!(objectives.insert(addresses.objective().to_owned()));
        assert!(storages.insert(addresses.storage().as_str().to_owned()));
        assert!(functions.insert(addresses.function_id().as_str().to_owned()));
        assert_eq!(addresses.objective(), program.scope().objective());
        assert_eq!(addresses.storage(), program.scope().storage());
        assert_eq!(addresses.result_address(), program.scope().result_address());
        assert_eq!(
            addresses.input_addresses(),
            program.scope().input_addresses()
        );
        assert_eq!(
            addresses.ok_score(),
            &BindingAddress::Score {
                holder: "#ok".into(),
                objective: addresses.objective().into(),
            }
        );
        assert_eq!(
            addresses.stale_score(),
            &BindingAddress::Score {
                holder: "#result".into(),
                objective: addresses.objective().into(),
            }
        );
        assert_eq!(
            addresses.stale_storage(),
            &BindingAddress::Storage {
                storage: addresses.storage().clone(),
                path: "invocation.result".into(),
            }
        );
        assert_eq!(
            addresses.scratch_address(),
            &BindingAddress::Storage {
                storage: addresses.storage().clone(),
                path: "invocation".into(),
            }
        );
        let invocation = program
            .invocation_command()
            .strip_prefix("function ")
            .unwrap();
        assert_eq!(invocation, addresses.function_id().as_str());
    }
}

#[test]
fn every_logical_function_preserves_original_program_bytes_digest_and_observation_site() {
    let dispatch = plan();
    let loaded = dispatch.loaded_source_expectations().unwrap();
    assert_eq!(loaded.len(), 47);
    assert_eq!(dispatch.source_entries().len(), 48);
    let pack = parse_json(&dispatch.source_entries()["pack.mcmeta"]).unwrap();
    assert_eq!(pack["pack"]["min_format"], json!([121, 0]));
    assert_eq!(pack["pack"]["max_format"], json!([121, 0]));
    assert!(pack["pack"].get("pack_format").is_none());
    let mut expected_paths = BTreeSet::from(["pack.mcmeta".to_owned()]);
    let mut resource_ids = BTreeSet::new();
    for (case, expected) in dispatch.cases().iter().zip(&loaded) {
        let original = CalibrationProgram::for_case(*case).unwrap();
        let invocation = original
            .invocation_command()
            .strip_prefix("function ")
            .unwrap();
        let (namespace, function_path) = invocation.split_once(':').unwrap();
        let logical_path = format!("data/{namespace}/function/{function_path}.mcfunction");
        assert!(expected_paths.insert(logical_path.clone()));
        assert!(!logical_path.contains("/functions/"));
        let bytes = dispatch
            .source_entries()
            .get(&logical_path)
            .expect("exact original entry");
        assert_eq!(bytes, original.source_bytes());
        assert_eq!(&raw_digest(bytes), original.source_digest());
        assert_eq!(expected.function_id().as_str(), invocation);
        assert_eq!(expected.logical_path(), logical_path);
        // Native FileToIdConverter reads the ResourceManager ID, whose path
        // still includes function/ and .mcfunction. Dispatch omits both.
        let logical_resource = logical_path.strip_prefix("data/").unwrap();
        let (resource_namespace, resource_path) = logical_resource.split_once('/').unwrap();
        assert_eq!(
            expected.resource_id().as_str(),
            format!("{resource_namespace}:{resource_path}")
        );
        assert!(resource_ids.insert(expected.resource_id().as_str()));
        assert_eq!(expected.source_bytes(), bytes.as_slice());
        assert!(std::ptr::eq(expected.source_bytes(), bytes.as_slice()));
        assert_eq!(expected.source_sha256(), original.source_digest());
        let matching = dispatch
            .programs()
            .iter()
            .find(|program| program.case() == *case)
            .unwrap();
        assert!(std::ptr::eq(
            expected.source_sha256(),
            matching.source_digest()
        ));
        let addresses = dispatch
            .owned_addresses()
            .iter()
            .find(|value| value.case() == *case)
            .unwrap();
        assert!(std::ptr::eq(
            expected.function_id(),
            addresses.function_id()
        ));
        assert_eq!(matching.commands(), original.commands());
        assert_eq!(
            matching.command_stage_index(),
            original.command_stage_index()
        );
        assert_eq!(matching.preseed_end_index(), original.preseed_end_index());
        let stage = matching.command_stage_index() as usize;
        let preseed = matching.preseed_end_index() as usize;
        assert!(preseed < stage && stage < matching.commands().len());
        assert_eq!(matching.commands()[stage], original.commands()[stage]);
    }
    assert_eq!(
        dispatch
            .source_entries()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        expected_paths
    );
    assert_eq!(resource_ids.len(), 47);
    assert!(
        loaded
            .iter()
            .all(|entry| entry.source_bytes().len() <= 64 * 1024)
    );
    assert!(
        loaded
            .iter()
            .map(|entry| entry.source_bytes().len())
            .sum::<usize>()
            <= 1024 * 1024
    );
}

#[test]
fn initialization_is_case_order_and_cleanup_unwinds_cases_without_reordering_each_program() {
    let dispatch = plan();
    let expected_initialization: Vec<_> = CalibrationCase::ALL
        .iter()
        .flat_map(|case| {
            CalibrationProgram::for_case(*case)
                .unwrap()
                .initialization_commands()
                .to_vec()
        })
        .collect();
    let expected_cleanup: Vec<_> = CalibrationCase::ALL
        .iter()
        .rev()
        .flat_map(|case| {
            CalibrationProgram::for_case(*case)
                .unwrap()
                .cleanup_commands()
                .to_vec()
        })
        .collect();
    assert_eq!(
        dispatch.initialization_commands(),
        expected_initialization.as_slice()
    );
    assert_eq!(dispatch.cleanup_commands(), expected_cleanup.as_slice());
    let first = CalibrationProgram::for_case(CalibrationCase::ALL[0]).unwrap();
    let last = CalibrationProgram::for_case(*CalibrationCase::ALL.last().unwrap()).unwrap();
    assert!(
        dispatch
            .initialization_commands()
            .starts_with(first.initialization_commands())
    );
    assert!(
        dispatch
            .cleanup_commands()
            .starts_with(last.cleanup_commands())
    );
    assert!(
        dispatch
            .cleanup_commands()
            .ends_with(first.cleanup_commands())
    );
}

#[test]
fn canonical_recipe_and_normative_entries_are_deterministic_and_immutable_to_export_copies() {
    let dispatch = plan();
    let repeated = plan();
    assert_eq!(
        dispatch.canonical_recipe_bytes(),
        repeated.canonical_recipe_bytes()
    );
    assert_eq!(dispatch.source_entries(), repeated.source_entries());
    assert_eq!(
        dispatch.initialization_commands(),
        repeated.initialization_commands()
    );
    assert_eq!(dispatch.cleanup_commands(), repeated.cleanup_commands());
    assert_eq!(dispatch.suite_digest(), repeated.suite_digest());
    let recipe = parse_json(dispatch.canonical_recipe_bytes()).unwrap();
    assert_eq!(
        canonical_bytes(&recipe).unwrap(),
        dispatch.canonical_recipe_bytes()
    );
    assert_eq!(
        dispatch.suite_digest(),
        &raw_digest(dispatch.canonical_recipe_bytes())
    );

    let first = &dispatch.programs()[0];
    let (namespace, function_path) = first
        .invocation_command()
        .strip_prefix("function ")
        .unwrap()
        .split_once(':')
        .unwrap();
    let logical_path = format!("data/{namespace}/function/{function_path}.mcfunction");
    let mut exported = dispatch.source_entries().clone();
    exported
        .get_mut(&logical_path)
        .unwrap()
        .extend_from_slice(b"# changed export copy\n");
    assert_ne!(&raw_digest(&exported[&logical_path]), first.source_digest());
    assert_eq!(
        dispatch.source_entries()[&logical_path],
        first.source_bytes()
    );
    assert_eq!(
        dispatch.canonical_recipe_bytes(),
        repeated.canonical_recipe_bytes()
    );
    assert_eq!(dispatch.suite_digest(), repeated.suite_digest());

    // The borrowed projection cannot silently follow a divergent private
    // source map or duplicate a case if future compiler edits break the seal.
    let mut changed_source = dispatch.clone();
    changed_source
        .source_entries
        .get_mut(&logical_path)
        .unwrap()
        .extend_from_slice(b"# changed private source\n");
    assert!(changed_source.loaded_source_expectations().is_err());
    let mut wrong_directory = dispatch.clone();
    let bytes = wrong_directory
        .source_entries
        .remove(&logical_path)
        .unwrap();
    wrong_directory
        .source_entries
        .insert(logical_path.replace("/function/", "/functions/"), bytes);
    assert!(wrong_directory.loaded_source_expectations().is_err());
    let mut duplicate = dispatch.clone();
    duplicate.programs[1] = duplicate.programs[0].clone();
    duplicate.owned_addresses[1] = duplicate.owned_addresses[0].clone();
    assert!(duplicate.loaded_source_expectations().is_err());
    assert_eq!(
        dispatch.loaded_source_expectations().unwrap()[0].source_bytes(),
        first.source_bytes()
    );
}

#[test]
fn recipe_binds_original_entries_dispatch_sites_addresses_and_lifecycle_order() {
    let dispatch = plan();
    let recipe = parse_json(dispatch.canonical_recipe_bytes()).unwrap();
    assert_eq!(
        recipe["recipeKind"],
        json!("mmmm_numeric_calibration_dispatch")
    );
    assert_eq!(recipe["recipeVersion"], json!(1));
    assert_eq!(recipe["suite"], json!("normative47"));
    assert_eq!(recipe["nativePackFormat"], json!([121, 0]));
    let entries = recipe["logicalEntries"].as_array().unwrap();
    assert_eq!(entries.len(), 48);
    for ((path, bytes), entry) in dispatch.source_entries().iter().zip(entries) {
        assert_eq!(entry["path"], json!(path));
        assert_eq!(entry["rawSha256"], json!(raw_digest(bytes).as_str()));
        assert_eq!(entry["sourceUtf8"].as_str().unwrap().as_bytes(), bytes);
    }
    let probes = recipe["probes"].as_array().unwrap();
    assert_eq!(probes.len(), dispatch.programs().len());
    for ((program, addresses), probe) in dispatch
        .programs()
        .iter()
        .zip(dispatch.owned_addresses())
        .zip(probes)
    {
        assert_eq!(probe["caseId"], json!(program.case().case_id()));
        assert_eq!(
            probe["originalProgramSha256"],
            json!(program.source_digest().as_str())
        );
        assert_eq!(
            probe["invocationCommand"],
            json!(program.invocation_command())
        );
        assert_eq!(probe["commands"], json!(program.commands()));
        assert_eq!(probe["preseedEndIndex"], json!(program.preseed_end_index()));
        assert_eq!(
            probe["selectedCommandStageIndex"],
            json!(program.command_stage_index())
        );
        assert_eq!(
            probe["initializationCommands"],
            json!(program.initialization_commands())
        );
        assert_eq!(probe["cleanupCommands"], json!(program.cleanup_commands()));
        let readback = &probe["readbackAddresses"];
        assert_eq!(readback["caseId"], probe["caseId"]);
        assert_eq!(
            readback["function"],
            json!(addresses.function_id().as_str())
        );
        assert_eq!(readback["objective"], json!(addresses.objective()));
        assert_eq!(readback["storage"], json!(addresses.storage().as_str()));
        assert_eq!(
            readback["ownedStorageSubtrees"],
            json!(["inputs", "invocation"])
        );
        assert_eq!(
            readback["scratch"],
            json!({"kind":"storage","storage":addresses.storage().as_str(),"path":"invocation"})
        );
        for (field, address) in [
            ("okScore", addresses.ok_score()),
            ("staleScore", addresses.stale_score()),
            ("staleStorage", addresses.stale_storage()),
            ("result", addresses.result_address()),
            ("scratch", addresses.scratch_address()),
        ] {
            assert_recipe_address(&readback[field], address);
        }
        let inputs = readback["inputs"].as_array().unwrap();
        assert_eq!(inputs.len(), addresses.input_addresses().len());
        for (value, address) in inputs.iter().zip(addresses.input_addresses()) {
            assert_recipe_address(value, address);
        }
        assert!(probe.get("expectedValues").is_none());
        assert!(probe.get("expectedReadback").is_none());
        assert!(probe.get("observations").is_none());
    }
    assert_eq!(
        recipe["initializationCommands"],
        json!(dispatch.initialization_commands())
    );
    assert_eq!(
        recipe["cleanupCommands"],
        json!(dispatch.cleanup_commands())
    );
    assert!(recipe.get("verifiedTarget").is_none());
    assert!(recipe.get("actualRunReceipt").is_none());
}

#[test]
fn recipe_hash_changes_for_exported_source_sites_addresses_and_order_without_rebinding_plan() {
    let dispatch = plan();
    let original = parse_json(dispatch.canonical_recipe_bytes()).unwrap();
    let mut changed_source = original.clone();
    let original_source = changed_source["logicalEntries"][0]["sourceUtf8"]
        .as_str()
        .unwrap();
    let replacement = format!("{original_source}# changed exact source bytes\n");
    // Even a self-consistent new public raw digest is only edited recipe data;
    // this suite constructor never consumes it as dispatch permission.
    changed_source["logicalEntries"][0]["rawSha256"] =
        json!(raw_digest(replacement.as_bytes()).as_str());
    changed_source["logicalEntries"][0]["sourceUtf8"] = json!(replacement);
    let mut changed_initialization = original.clone();
    changed_initialization["initializationCommands"][0] =
        json!("scoreboard objectives add other dummy");
    let mut changed_result = original.clone();
    changed_result["probes"][0]["readbackAddresses"]["result"]["holder"] = json!("#other_result");
    let mut changed_scratch = original.clone();
    changed_scratch["probes"][0]["readbackAddresses"]["scratch"]["path"] =
        json!("invocation.result");
    let mut changed_stage = original.clone();
    changed_stage["probes"][0]["selectedCommandStageIndex"] =
        json!(dispatch.programs()[0].command_stage_index() + 1);
    let mut changed_preseed = original.clone();
    changed_preseed["probes"][0]["preseedEndIndex"] =
        json!(dispatch.programs()[0].preseed_end_index() + 1);
    let mut changed_probe_order = original.clone();
    changed_probe_order["probes"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    let mut changed_initialization_order = original.clone();
    changed_initialization_order["initializationCommands"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    let mut changed_cleanup_order = original.clone();
    changed_cleanup_order["cleanupCommands"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    let mut changed_format_pair = original.clone();
    changed_format_pair["nativePackFormat"] = json!([121, 1]);
    let mut changed_limit = original.clone();
    changed_limit["limits"]["commands"] = json!(0);
    for changed in [
        changed_source,
        changed_initialization,
        changed_result,
        changed_scratch,
        changed_stage,
        changed_preseed,
        changed_probe_order,
        changed_initialization_order,
        changed_cleanup_order,
        changed_format_pair,
        changed_limit,
    ] {
        let changed_bytes = canonical_bytes(&changed).unwrap();
        assert_ne!(&raw_digest(&changed_bytes), dispatch.suite_digest());
    }
    assert_eq!(
        dispatch.canonical_recipe_bytes(),
        canonical_bytes(&original).unwrap()
    );
    assert_eq!(
        dispatch.suite_digest(),
        &raw_digest(dispatch.canonical_recipe_bytes())
    );
}

#[test]
fn budget_counts_all_original_sites_bytes_and_finite_policy_limits() {
    let dispatch = plan();
    let budget = dispatch.budget();
    let bodies = dispatch
        .programs()
        .iter()
        .flat_map(|program| program.commands().iter().map(String::as_str));
    let invocations = dispatch
        .programs()
        .iter()
        .map(CalibrationProgram::invocation_command);
    let initialization = dispatch
        .initialization_commands()
        .iter()
        .map(String::as_str);
    let cleanup = dispatch.cleanup_commands().iter().map(String::as_str);
    let sites: Vec<_> = bodies
        .chain(invocations)
        .chain(initialization)
        .chain(cleanup)
        .collect();
    assert_eq!(budget.cases(), dispatch.programs().len());
    assert_eq!(budget.logical_entries(), dispatch.source_entries().len());
    assert_eq!(
        budget.source_bytes(),
        dispatch
            .source_entries()
            .values()
            .map(Vec::len)
            .sum::<usize>()
    );
    assert_eq!(budget.commands(), sites.len());
    assert_eq!(
        budget.command_bytes(),
        sites.iter().map(|command| command.len()).sum::<usize>()
    );
    assert_eq!(
        budget.max_command_bytes(),
        sites.iter().map(|command| command.len()).max().unwrap()
    );
    assert_eq!(
        budget.recipe_bytes(),
        dispatch.canonical_recipe_bytes().len()
    );
    assert_eq!(CalibrationDispatchPlan::MAX_CASES, 47);
    assert_eq!(CalibrationDispatchPlan::MAX_SOURCE_BYTES, 1024 * 1024);
    assert_eq!(CalibrationDispatchPlan::MAX_COMMANDS, 4096);
    assert_eq!(CalibrationDispatchPlan::MAX_COMMAND_BYTES, 8192);
    assert_eq!(CalibrationDispatchPlan::MAX_RECIPE_BYTES, 4 * 1024 * 1024);
    assert!(budget.cases() <= CalibrationDispatchPlan::MAX_CASES);
    assert!(budget.source_bytes() <= CalibrationDispatchPlan::MAX_SOURCE_BYTES);
    assert!(budget.commands() <= CalibrationDispatchPlan::MAX_COMMANDS);
    assert!(budget.max_command_bytes() <= CalibrationDispatchPlan::MAX_COMMAND_BYTES);
    assert!(budget.recipe_bytes() <= CalibrationDispatchPlan::MAX_RECIPE_BYTES);
    let recipe = parse_json(dispatch.canonical_recipe_bytes()).unwrap();
    assert_eq!(recipe["siteCounts"]["cases"], json!(budget.cases()));
    assert_eq!(
        recipe["siteCounts"]["logicalEntries"],
        json!(budget.logical_entries())
    );
    assert_eq!(
        recipe["siteCounts"]["sourceBytes"],
        json!(budget.source_bytes())
    );
    assert_eq!(recipe["siteCounts"]["commands"], json!(budget.commands()));
    assert_eq!(
        recipe["siteCounts"]["commandBytes"],
        json!(budget.command_bytes())
    );
    assert_eq!(
        recipe["siteCounts"]["maxCommandBytes"],
        json!(budget.max_command_bytes())
    );
    for (field, limit) in [
        ("cases", CalibrationDispatchPlan::MAX_CASES),
        ("sourceBytes", CalibrationDispatchPlan::MAX_SOURCE_BYTES),
        ("commands", CalibrationDispatchPlan::MAX_COMMANDS),
        ("commandBytes", CalibrationDispatchPlan::MAX_COMMAND_BYTES),
        ("recipeBytes", CalibrationDispatchPlan::MAX_RECIPE_BYTES),
    ] {
        assert_eq!(recipe["limits"][field], json!(limit));
    }
}

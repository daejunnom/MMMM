//! These fixtures exercise source admission and evidence rejection. They are
//! authored local SQLite/CAS/codec tests, never a successful game calibration.
use super::*;
use crate::{
    auth::{SessionAuthority, SessionPolicy},
    planning_source::PlanningContextPort,
};
use mmmm_contracts::{ResourceId, parse_json, projected_digest};
use mmmm_runtime::storage::StoreConfig;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

fn budget() -> RequestBudget {
    RequestBudget::new(Duration::from_secs(30), Arc::new(AtomicBool::new(false))).unwrap()
}
fn pin(bytes: &[u8], id: &str) -> Value {
    json!({"resourceId":id,"sha256":raw_digest(bytes),"mediaType":"application/json","sizeBytes":bytes.len()})
}
fn example(name: &str) -> Value {
    parse_json(
        &fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples")
                .join(name),
        )
        .unwrap(),
    )
    .unwrap()
}
fn profile() -> Value {
    let mut profile = example("version-profile.json");
    profile["validationStatus"] = json!("runtime_verified");
    profile["writeSupport"] = json!("verified");
    profile["artifactSha256"] = json!(raw_digest(b"original input archive"));
    profile["javaMajor"] = json!(25);
    profile["testedLoaders"] = json!(["fabric"]);
    profile["evidenceResourceIds"] = json!(["private-runtime-suite"]);
    profile
}
fn suite(profile: &Value, context: &Value) -> RuntimeSuite {
    serde_json::from_value(json!({"format":"mmmm.target-runtime-evidence/1","profileDigest":digest(profile).unwrap(),
        "artifactSha256":profile["artifactSha256"],"hostArtifactDigest":raw_digest(b"host platform shim"),
        "runtimeSourceFactsDigest":raw_digest(b"actual facts"),"registryDigest":raw_digest(b"native registry"),
        "registryGeneration":"7","environment":context["environment"],"contextDigest":context["contextDigest"],
        "compilerDigest":mmmm_compiler::compiler_digest(),"loader":{"id":"fabric","version":"0.19.5"},"javaMajor":25,
        "cases":[]})).unwrap()
}
fn numeric(case: &str, output: Value, success: bool) -> NumericReadback {
    serde_json::from_value(json!({"format":"mmmm.target-case-readback/1","caseId":case,
        "sourceResource":pin(b"generated original case", "case-source"),"commandStageIndex":0,
        "invocationId":"invocation-target-case","runtimeSourceFactsDigest":raw_digest(b"actual facts"),
        "commandSuccess":success,"commandReturn":0,"okScore":if success {1} else {0},
        "output":output,"scratchPresent":success,"staleOutputSeeded":true})).unwrap()
}

#[test]
fn zero_success_and_typed_binary32_are_distinct_from_failure_and_f64() {
    assert!(
        validate_numeric_readback(&numeric(
            "int32_score_zero",
            json!({"kind":"score","value":0}),
            true
        ))
        .is_ok()
    );
    assert!(
        validate_numeric_readback(&numeric(
            "float_finite_zero_guard",
            json!({"kind":"float_tag","bits":"00000000"}),
            true
        ))
        .is_ok()
    );
    assert!(
        validate_numeric_readback(&numeric(
            "float_signed_zero",
            json!({"kind":"float_tag","bits":"80000000"}),
            true
        ))
        .is_ok()
    );
    assert!(
        validate_numeric_readback(&numeric(
            "float_binary32_chain",
            json!({"kind":"float_tag","bits":"3f800000"}),
            true
        ))
        .is_err()
    );
    assert!(
        validate_numeric_readback(&numeric(
            "float_nbt_fraction",
            json!({"kind":"int_tag","value":1}),
            true
        ))
        .is_err()
    );
    assert!(
        serde_json::from_value::<TypedScalar>(
            json!({"kind":"double_tag","bits":"3ff4000000000000"})
        )
        .is_err()
    );
    let mut false_success = numeric("int32_score_zero", json!({"kind":"score","value":0}), true);
    false_success.ok_score = Int32::new(0);
    assert!(validate_numeric_readback(&false_success).is_err());
}

#[test]
fn failure_requires_absent_output_and_complete_stale_scratch_cleanup() {
    for case in [
        "int_add_overflow",
        "int_div_zero",
        "float_from_float_upper_range",
        "float_div_zero_zero",
        "later_node_failure_cleanup",
    ] {
        let mut observed = numeric(case, json!({"kind":"absent"}), false);
        assert!(validate_numeric_readback(&observed).is_ok());
        observed.output = TypedScalar::Score {
            value: Int32::new(0),
        };
        assert!(validate_numeric_readback(&observed).is_err());
        observed.output = TypedScalar::Absent;
        observed.scratch_present = true;
        assert!(validate_numeric_readback(&observed).is_err());
        observed.scratch_present = false;
        observed.stale_output_seeded = false;
        assert!(validate_numeric_readback(&observed).is_err());
    }
}

#[test]
fn lazy_existing_zero_and_fraction_must_succeed_without_the_invalid_fallback() {
    assert!(
        validate_numeric_readback(&numeric(
            "score_present_zero_lazy_fallback",
            json!({"kind":"score","value":0}),
            true
        ))
        .is_ok()
    );
    assert!(
        validate_numeric_readback(&numeric(
            "float_storage_present_fraction_lazy_fallback",
            json!({"kind":"float_tag","bits":"3fa00000"}),
            true
        ))
        .is_ok()
    );
    assert!(
        validate_numeric_readback(&numeric(
            "score_absent_fallback",
            json!({"kind":"absent"}),
            false
        ))
        .is_ok()
    );
    assert!(
        validate_numeric_readback(&numeric(
            "score_present_zero_lazy_fallback",
            json!({"kind":"absent"}),
            false
        ))
        .is_err()
    );
    let mut whole_function_return = numeric(
        "native_compute_float_return_floor_vs_nbt",
        json!({"kind":"float_tag","bits":"bfc00000"}),
        true,
    );
    assert!(validate_numeric_readback(&whole_function_return).is_err());
    whole_function_return.command_return = Int32::new(-2);
    assert!(validate_numeric_readback(&whole_function_return).is_ok());
}

#[test]
fn public_passed_flags_and_reference_only_profiles_do_not_create_runtime_rules() {
    let context = example("execution-context.json");
    let profile = profile();
    let original = suite(&profile, &context);
    assert!(verified_rules(&original, &BTreeMap::new()).is_err());
    let mut value = json!({"format":"mmmm.target-case-readback/1","caseId":"int32_score_zero",
        "sourceResource":pin(b"source", "source"),"commandStageIndex":0,"invocationId":"invocation-case",
        "runtimeSourceFactsDigest":raw_digest(b"facts"),"commandSuccess":true,"commandReturn":0,"okScore":1,
        "output":{"kind":"score","value":0},"scratchPresent":true,"staleOutputSeeded":true});
    value["passed"] = json!(true);
    assert!(serde_json::from_value::<NumericReadback>(value).is_err());
    let reference = example("version-profile.json");
    // The reference-only VersionProfile permits a null artifactSha256. It is
    // compared with the actual non-null runtime suite, not used to fabricate one.
    assert!(validate_suite_identity(&original, &reference, &context).is_err());
}

#[test]
fn fixed_case_set_rejects_duplicate_unknown_missing_and_reused_invocations() {
    let context = example("execution-context.json");
    let mut suite = suite(&profile(), &context);
    let mut registered = BTreeMap::new();
    for (index, case) in NUMERIC_CASES.iter().enumerate() {
        let program =
            CalibrationProgram::for_case(CalibrationCase::from_case_id(case).unwrap()).unwrap();
        let resource = pin(program.source_bytes(), &format!("source-{index}"));
        suite.cases.push(RuntimeCaseRecord {
            case_id: (*case).into(),
            source_resource: resource.clone(),
            operation_id: OperationId::new(format!("operation-{index}")).unwrap(),
            step_id: StepId::new(format!("step-{index}")).unwrap(),
            invocation_id: InvocationId::new(format!("invocation-{index}")).unwrap(),
            readback_envelope: BlobRef {
                digest: raw_digest(case.as_bytes()),
                byte_length: case.len() as u64,
            },
        });
        registered.insert(
            (*case).into(),
            RuntimeCaseSource {
                source: TargetProfileResource {
                    resource,
                    query: ProjectResourceQuery::RegisteredImmutable {
                        resource_id: ResourceId::new(format!("source-{index}")).unwrap(),
                    },
                },
                program: RuntimeCaseProgram::Numeric(program),
            },
        );
    }
    assert!(validate_case_set(&suite, &registered).is_ok());
    // Exact required case IDs and authentic pure generated source still do not
    // grant rules without the actual private dispatch-issued run capability.
    assert!(verified_rules(&suite, &BTreeMap::new()).is_err());
    let old = suite.cases[0].case_id.clone();
    suite.cases[0].case_id = "forged_case".into();
    assert!(validate_case_set(&suite, &registered).is_err());
    suite.cases[0].case_id = suite.cases[1].case_id.clone();
    assert!(validate_case_set(&suite, &registered).is_err());
    suite.cases[0].case_id = old;
    suite.cases[0].invocation_id = suite.cases[1].invocation_id.clone();
    assert!(validate_case_set(&suite, &registered).is_err());
    suite.cases.pop();
    assert!(validate_case_set(&suite, &registered).is_err());
}

#[test]
fn stable_native_pin_omits_only_observation_time_and_retains_unknowns_and_order() {
    let mut facts = json!({"format":"mmmm.native.source-facts/1","observedAt":"2026-10-14T00:00:00Z",
        "bytesRead":1024,"registryGeneration":"7","clientPacks":null,"clientPackObservation":"not_observed",
        "transformedClassBytes":"not_observed","serverPacks":[{"packIndex":0,"packSourceCompleteness":"unknown"},{"packIndex":1,"packSourceCompleteness":"unknown"}]});
    let first = source_facts_pin(&facts).unwrap();
    facts["observedAt"] = json!("2026-10-14T00:00:01Z");
    assert_eq!(first, source_facts_pin(&facts).unwrap());
    facts["bytesRead"] = json!(1025);
    assert_ne!(first, source_facts_pin(&facts).unwrap());
    facts["bytesRead"] = json!(1024);
    facts["serverPacks"].as_array_mut().unwrap().reverse();
    assert_ne!(first, source_facts_pin(&facts).unwrap());
    facts["serverPacks"].as_array_mut().unwrap().reverse();
    facts["clientPacks"] = json!([]);
    assert_ne!(first, source_facts_pin(&facts).unwrap());
}

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const MARKER: &[u8] = b"mmmm-target-profile-tests\n";
struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        assert!(parent.is_absolute());
        let path = parent.join(format!(
            "mmmm-target-profile-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(!path.exists());
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = fs::canonicalize(path).unwrap();
        let checkout =
            fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        assert!(!path.starts_with(checkout));
        fs::write(path.join("test-owner.txt"), MARKER).unwrap();
        Self(path)
    }
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        let mut count = 0;
        if fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0)
            && fs::read(self.0.join("test-owner.txt")).ok().as_deref() == Some(MARKER)
            && plain_tree(&self.0, 0, &mut count)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
fn plain_tree(path: &Path, depth: usize, count: &mut usize) -> bool {
    if depth > 10 || *count >= 512 {
        return false;
    }
    *count += 1;
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    if metadata.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return false;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            if !plain_tree(&entry.path(), depth + 1, count) {
                return false;
            }
        }
    } else if !metadata.is_file() {
        return false;
    }
    true
}
struct TestContext;
impl PlanningContextPort for TestContext {
    fn authorize(
        &mut self,
        principal: &AuthenticatedPrincipal,
        authority: &mut LocalAuthority,
        _hosts: &HostBridge,
        project: &ProjectId,
        context: &Value,
        _access: Access,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        budget_check(budget)?;
        authority.authorize_retained_scope(
            principal.principal(),
            project,
            &ContextId::new(text(context, "contextId")?).unwrap(),
            &field_digest(context, "policyRevision")?,
            &context["scope"],
        )
    }
}
struct RpcFixture {
    sessions: SessionAuthority,
    rpc: TargetRpc,
}
fn rpc_fixture(project: &Value, resources: Vec<ResourceId>) -> RpcFixture {
    let hosts = HostBridge::default();
    let authority = LocalAuthority::new(hosts.clone());
    let principal = PrincipalId::new("principal-target-test").unwrap();
    let project_id = ProjectId::new(project["projectId"].as_str().unwrap()).unwrap();
    let context_id = ContextId::new("context-target-test").unwrap();
    let scope = json!({"projectId":project_id,"resourceIds":resources,"objectIds":[],"regions":[],"externalTargetIds":[]});
    let policy = authority
        .install_project_access(
            principal.clone(),
            project_id.clone(),
            scope.clone(),
            [context_id.clone()].into(),
            Duration::from_secs(30),
        )
        .unwrap();
    let mut sessions = SessionAuthority::new(2).unwrap();
    let token = sessions
        .install(SessionPolicy {
            principal,
            allowed_methods: ["plan.create".into(), "artifact.read".into()].into(),
            allowed_contexts: [context_id.clone()].into(),
            lifetime: Duration::from_secs(30),
        })
        .unwrap();
    let authenticated = sessions.authenticate_token(&token).unwrap();
    let budget = budget();
    let mut context = example("execution-context.json");
    context["contextId"] = json!(context_id);
    context["principalRef"] = json!(authenticated.principal());
    context["projectId"] = json!(project_id);
    context["policyRevision"] = json!(policy);
    context["scope"] = scope;
    context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
    let contexts: SharedPlanningContexts = Rc::new(RefCell::new(Box::new(TestContext)));
    let access = LocalPlanningAccess::new(
        authenticated.clone(),
        authority.clone(),
        hosts,
        budget.clone(),
        contexts,
    )
    .unwrap();
    RpcFixture {
        sessions,
        rpc: TargetRpc {
            authenticated,
            budget,
            authority,
            access,
            context_id,
            project: project_id,
            context,
        },
    }
}

#[test]
fn same_store_exact_cas_source_requires_current_scope_and_live_session() {
    let root = TestRoot::new();
    let mut durable = DurableStore::open(StoreConfig::new(root.0.clone())).unwrap();
    let mut project = example("project.json");
    project["resourceIds"] = json!(["target-source"]);
    project["revision"] = json!(projected_digest("Project", &project).unwrap());
    durable.save_project(&project, None).unwrap();
    let bytes = b"  {\"source\": \"exact raw bytes\"}\n";
    durable.put_blob(bytes).unwrap();
    let resource = pin(bytes, "target-source");
    register_resource(
        &mut durable,
        &resource,
        ResourceOwner::Project(ProjectId::new(project["projectId"].as_str().unwrap()).unwrap()),
    )
    .unwrap();
    let source = TargetProfileResource {
        resource: resource.clone(),
        query: ProjectResourceQuery::Current {
            resource_id: ResourceId::new("target-source").unwrap(),
        },
    };
    let mut fixture = rpc_fixture(&project, vec![ResourceId::new("target-source").unwrap()]);
    let store = PlanningStore::read(&durable);
    let mut left = 128;
    assert_eq!(
        read_resource(&store, &fixture.rpc, &source, 128, &mut left).unwrap(),
        bytes
    );
    assert_eq!(left, 128 - bytes.len() as u64);
    let mut altered = source.clone();
    altered.resource["mediaType"] = json!("text/plain");
    assert!(read_resource(&store, &fixture.rpc, &altered, 128, &mut left).is_err());
    fixture.rpc.context["scope"]["resourceIds"] = json!([]);
    assert!(read_resource(&store, &fixture.rpc, &source, 128, &mut left).is_err());
    fixture.rpc.context["scope"]["resourceIds"] = json!(["target-source"]);
    fixture.sessions.revoke_all();
    assert!(read_resource(&store, &fixture.rpc, &source, 128, &mut left).is_err());
}

#[test]
fn authentic_source_bytes_without_an_original_durable_invocation_are_unverified() {
    let root = TestRoot::new();
    let mut durable = DurableStore::open(StoreConfig::new(root.0.clone())).unwrap();
    let project = example("project.json");
    durable.save_project(&project, None).unwrap();
    let fixture = rpc_fixture(&project, Vec::new());
    let store = PlanningStore::read(&durable);
    let program = CalibrationProgram::for_case(CalibrationCase::Int32ScoreZero).unwrap();
    let source = RuntimeCaseSource {
        source: TargetProfileResource {
            resource: pin(program.source_bytes(), "source"),
            query: ProjectResourceQuery::RegisteredImmutable {
                resource_id: ResourceId::new("source").unwrap(),
            },
        },
        program: RuntimeCaseProgram::Numeric(program.clone()),
    };
    let case = RuntimeCaseRecord {
        case_id: "int32_score_zero".into(),
        source_resource: source.source.resource.clone(),
        operation_id: OperationId::new("operation-unobserved").unwrap(),
        step_id: StepId::new("step-unobserved").unwrap(),
        invocation_id: InvocationId::new("invocation-unobserved").unwrap(),
        readback_envelope: BlobRef {
            digest: raw_digest(b"fabricated record"),
            byte_length: 17,
        },
    };
    let profile = profile();
    let suite = suite(&profile, &fixture.rpc.context);
    let mut left = 128;
    let error = verify_durable_case(
        &store,
        &fixture.rpc,
        &case,
        &source,
        &suite,
        &profile,
        program.source_bytes(),
        &mut left,
    )
    .err()
    .unwrap();
    assert_eq!(error.code, "TARGET_SOURCE_UNAVAILABLE");
    assert_eq!(left, 128);
}

#[test]
fn expected_output_without_the_normative_arithmetic_source_is_rejected() {
    let program = CalibrationProgram::for_case(CalibrationCase::IntAddNormal).unwrap();
    let source = RuntimeCaseProgram::Numeric(program.clone());
    let forged =
        b"scoreboard players set #ok arbitrary 1\nscoreboard players set #result arbitrary 12\n";
    // An expected after value alone looks valid. The sealed producer source
    // comparison rejects a function that merely assigns that same value.
    assert!(
        validate_numeric_readback(&numeric(
            "int_add_normal",
            json!({"kind":"score","value":12}),
            true
        ))
        .is_ok()
    );
    assert_eq!(
        verify_normative_source(&source, forged, &budget())
            .unwrap_err()
            .code,
        "TARGET_RUNTIME_SOURCE_MISMATCH"
    );
    assert!(verify_normative_source(&source, program.source_bytes(), &budget()).is_ok());
    let mut altered = program.source_bytes().to_vec();
    altered.extend_from_slice(b"# different source\n");
    assert!(verify_normative_source(&source, &altered, &budget()).is_err());
}

#[test]
fn issued_native_return_must_agree_with_the_independent_selected_command() {
    let observed = [json!({"nativeReturn":0}), json!({"nativeReturn":-2})];
    assert!(verify_issued_command_return(&observed, 1, Some(-2)).is_ok());
    assert_eq!(
        verify_issued_command_return(&observed, 0, Some(-2))
            .unwrap_err()
            .code,
        "TARGET_RUNTIME_EVIDENCE_CONFLICT"
    );
    assert!(verify_issued_command_return(&observed, 2, Some(-2)).is_err());
    assert!(verify_issued_command_return(&[json!({"nativeReturn":-2.5})], 0, Some(-2)).is_err());
    assert!(verify_issued_command_return(&[json!({"nativeReturn":-2.0})], 0, Some(-2)).is_ok());
}

#[test]
fn actual_pack_producer_pair_and_mathematical_profile_integers_agree() {
    let program = CalibrationPackProgram::java_26_3().unwrap();
    let metadata = parse_json(&program.source_entries()["pack.mcmeta"]).unwrap();
    let mut profile = profile();
    profile["javaMajor"] = parse_json(b"2.5e1").unwrap();
    profile["dataPackVersion"]["major"] = parse_json(b"121.0").unwrap();
    let context = example("execution-context.json");
    assert!(validate_suite_identity(&suite(&profile, &context), &profile, &context).is_ok());
    assert_eq!(
        format_pair(&metadata["pack"]["min_format"]).unwrap(),
        profile_format_pair(&profile).unwrap()
    );
    assert_eq!(
        format_pair(&metadata["pack"]["max_format"]).unwrap(),
        [121, 0]
    );
    assert!(format_pair(&json!([121, 0.5])).is_err());
    assert!(format_pair(&json!([121, -1])).is_err());
}

#[test]
fn observed_window_requires_actual_ordered_canonical_tick_strings() {
    let mut window =
        json!({"observedFromTick":"7","observedToTick":"8","observedAt":"2026-10-14T00:00:00Z"});
    assert!(validate_observed_window(&window).is_ok());
    window["observedToTick"] = json!("6");
    assert!(validate_observed_window(&window).is_err());
    window["observedToTick"] = json!("08");
    assert!(validate_observed_window(&window).is_err());
    window["observedToTick"] = json!(8);
    assert!(validate_observed_window(&window).is_err());
}

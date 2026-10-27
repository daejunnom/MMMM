//! Existing handoff fixtures are reused. Small in-memory mutations exercise
//! missing authority, stale epochs, unsupported mappings and immutable routing
//! boundaries absent from the positive-only original example set.

use crate::*;
use mmmm_contracts::{
    ActionId, BindingId, Sha256Digest, canonical_digest, parse_json, projected_digest,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn digest() -> Sha256Digest {
    serde_json::from_value(context_value()["policyRevision"].clone()).unwrap()
}
fn context_value() -> Value {
    parse_json(include_bytes!("../../../examples/execution-context.json")).unwrap()
}
fn context() -> RouteContext {
    RouteContext::from_execution_context(
        &context_value(),
        BTreeSet::from(["diagnostic.read".into()]),
    )
    .unwrap()
}
fn provider() -> Value {
    parse_json(include_bytes!("../../../examples/provider-supported.json")).unwrap()
}
fn observation(value: &Value) -> RegistrationObservation {
    let descriptor: ProviderDescriptor = decode("ProviderDescriptor", value).unwrap();
    RegistrationObservation {
        environment: descriptor.environment.clone(),
        origin: descriptor.origin.clone(),
        host_protocol_version: descriptor.host_protocol_version.clone(),
        loaded: true,
        connected: true,
        availability: Availability::Available,
        evidence: CompatibilityEvidence::Declared,
        implementation_digests: descriptor
            .actions
            .iter()
            .map(|action| {
                (
                    action.action_id.clone(),
                    action.implementation_digest.clone(),
                )
            })
            .collect(),
        action_readiness: descriptor
            .actions
            .iter()
            .map(|action| {
                (
                    action.action_id.clone(),
                    ActionReadiness {
                        ready: true,
                        possible_loss_codes: Some(BTreeSet::new()),
                    },
                )
            })
            .collect(),
    }
}
fn route(snapshot: &InventorySnapshot, preferred: Option<&str>) -> Value {
    json!({"contextId":context().context_id(),"semanticKind":"mmmm:diagnostic.echo","requiredGuarantees":["returns_input_text"],
        "acceptableLossCodes":[],"preferredBindingId":preferred,"inventoryRevision":snapshot.revision()})
}
fn profile_java() -> Value {
    parse_json(include_bytes!("../../../examples/compat-public-java.json")).unwrap()
}
fn interface_java() -> InterfaceObservation {
    InterfaceObservation {
        environment: context().environment().clone(),
        loader: Loader::Fabric,
        target_game_version: "26.3".into(),
        mod_id: Some("fixture_legacy".into()),
        mod_version: "0.1.0".into(),
        host_protocol_version: "0.2.0".into(),
        implementation_digest: serde_json::from_value(
            profile_java()["action"]["implementationDigest"].clone(),
        )
        .unwrap(),
        support: BindingSupport::PublicJava {
            signature: JavaSignature {
                owner_class: "org.mmmm.fixture.LegacyApi".into(),
                method_name: "echo".into(),
                parameter_types: vec!["java.lang.String".into()],
                return_type: "java.util.Map".into(),
                receiver: Receiver::Static,
            },
            public_lookup_checked: true,
            initialization_performed: false,
            thread_affinity: ThreadAffinity::ServerMain,
            receiver_resolver: None,
            scoped_handle_types: BTreeSet::new(),
        },
        loaded: true,
        connected: true,
        availability: Availability::Available,
        evidence: CompatibilityEvidence::InterfaceChecked,
        readiness: ActionReadiness {
            ready: true,
            possible_loss_codes: Some(BTreeSet::new()),
        },
    }
}
fn approved_request(profile: Value, interface: &InterfaceObservation) -> (Value, ProfileApproval) {
    let profile_digest = projected_digest("CompatibilityProfile", &profile).unwrap();
    let request = json!({"profile":profile,"profileDigest":profile_digest,"contextId":context().context_id(),"environment":context().environment(),"approvedProfileRef":"approval-test"});
    let approval = ProfileApproval {
        reference: "approval-test".into(),
        profile_digest,
        source_id: "approved-fixture-source".into(),
        allowed_interface_digest: interface.interface_digest().unwrap(),
    };
    (request, approval)
}

#[test]
fn fixed_inventory_route_is_deterministic_and_preferred_pin_never_substitutes() {
    let mut a = provider();
    a["bindingId"] = json!("binding-a");
    let mut b = provider();
    b["bindingId"] = json!("binding-b");
    let mut left = ProviderRegistry::new();
    left.register_observed_provider(&b, observation(&b))
        .unwrap();
    left.register_observed_provider(&a, observation(&a))
        .unwrap();
    let mut right = ProviderRegistry::new();
    right
        .register_observed_provider(&a, observation(&a))
        .unwrap();
    right
        .register_observed_provider(&b, observation(&b))
        .unwrap();
    let left = left.snapshot(context(), digest()).unwrap();
    let right = right.snapshot(context(), digest()).unwrap();
    assert_eq!(left.revision(), right.revision());
    assert_eq!(
        left.resolve(&route(&left, None)).unwrap(),
        right.resolve(&route(&right, None)).unwrap()
    );
    let chosen = left.resolve(&route(&left, None)).unwrap();
    assert_eq!(chosen["bindingId"], "binding-a");
    assert_eq!(
        left.resolve(&route(&left, Some("binding-missing")))
            .unwrap()["status"],
        "unavailable"
    );
    left.check_selected_pin(&chosen).unwrap();
}

#[test]
fn capabilities_permissions_unknown_loss_and_disabled_feature_are_not_guessed() {
    let value = provider();
    let mut observed = observation(&value);
    let action_id: ActionId =
        serde_json::from_value(value["actions"][0]["actionId"].clone()).unwrap();
    observed
        .action_readiness
        .get_mut(&action_id)
        .unwrap()
        .possible_loss_codes = None;
    let mut registry = ProviderRegistry::new();
    registry
        .register_observed_provider(&value, observed)
        .unwrap();
    let snapshot = registry.snapshot(context(), digest()).unwrap();
    assert_eq!(
        snapshot.resolve(&route(&snapshot, None)).unwrap()["status"],
        "unavailable"
    );
    let mut registry = ProviderRegistry::new();
    registry
        .register_observed_provider(&value, observation(&value))
        .unwrap();
    let restricted =
        RouteContext::from_execution_context(&context_value(), BTreeSet::new()).unwrap();
    let snapshot = registry.snapshot(restricted, digest()).unwrap();
    assert_eq!(
        snapshot.resolve(&route(&snapshot, None)).unwrap()["status"],
        "unavailable"
    );
    let snapshot = registry.snapshot(context(), digest()).unwrap();
    let mut request = route(&snapshot, None);
    request["requiredGuarantees"] = json!(["unclaimed_feature"]);
    assert_eq!(snapshot.resolve(&request).unwrap()["status"], "unavailable");
    registry
        .set_enabled(&BindingId::new("binding-fixture-01").unwrap(), false)
        .unwrap();
    let disabled = registry.snapshot(context(), digest()).unwrap();
    assert_ne!(snapshot.revision(), disabled.revision());
    assert_eq!(
        disabled.resolve(&route(&disabled, None)).unwrap()["status"],
        "unavailable"
    );
    assert_eq!(
        snapshot.resolve(&route(&snapshot, None)).unwrap()["status"],
        "selected"
    );
}

#[test]
fn lifecycle_refresh_preserves_old_snapshot_and_distinguishes_partial_readiness() {
    let mut value = provider();
    let mut second = value["actions"][0].clone();
    second["actionId"] = json!("fixture:not_ready");
    value["actions"].as_array_mut().unwrap().push(second);
    let mut observed = observation(&value);
    observed
        .action_readiness
        .get_mut(&ActionId::new("fixture:not_ready").unwrap())
        .unwrap()
        .ready = false;
    let mut registry = ProviderRegistry::new();
    registry
        .register_observed_provider(&value, observed.clone())
        .unwrap();
    let old = registry.snapshot(context(), digest()).unwrap();
    assert_eq!(
        old.resolve(&route(&old, None)).unwrap()["status"],
        "selected"
    );
    assert!(
        old.inventory()
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "FEATURE_NOT_READY")
    );
    registry
        .update_lifecycle(
            &BindingId::new("binding-fixture-01").unwrap(),
            true,
            false,
            Availability::Available,
            observed.action_readiness,
        )
        .unwrap();
    let new = registry.snapshot(context(), digest()).unwrap();
    assert_ne!(old.revision(), new.revision());
    assert_eq!(
        new.inventory().providers[0].availability,
        Availability::Disconnected
    );
    assert_eq!(
        new.resolve(&route(&old, None)).unwrap_err().code,
        "INVENTORY_STALE"
    );
    assert_eq!(
        old.resolve(&route(&old, None)).unwrap()["status"],
        "selected"
    );
}

#[test]
fn same_provider_id_in_new_epoch_requires_distinct_binding_and_context() {
    let value = provider();
    let mut registry = ProviderRegistry::new();
    registry
        .register_observed_provider(&value, observation(&value))
        .unwrap();
    let mut next = value.clone();
    next["environment"]["sessionEpoch"] = json!("epoch-next");
    assert_eq!(
        registry
            .register_observed_provider(&next, observation(&next))
            .unwrap_err()
            .code,
        "BINDING_ID_REUSED"
    );
    next["bindingId"] = json!("binding-next");
    registry
        .register_observed_provider(&next, observation(&next))
        .unwrap();
    let old = registry.snapshot(context(), digest()).unwrap();
    assert_eq!(old.inventory().providers.len(), 1);
    let mut context = context_value();
    context["environment"]["sessionEpoch"] = json!("epoch-next");
    context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
    let next_context =
        RouteContext::from_execution_context(&context, BTreeSet::from(["diagnostic.read".into()]))
            .unwrap();
    let next = registry.snapshot(next_context, digest()).unwrap();
    assert_ne!(old.revision(), next.revision());
    assert_eq!(
        next.inventory().providers[0].binding_id.as_str(),
        "binding-next"
    );
}

#[test]
fn registration_rejects_claimed_implementation_and_uncompiled_action_schema() {
    let value = provider();
    let mut observed = observation(&value);
    observed
        .implementation_digests
        .insert(ActionId::new("fixture:echo_text").unwrap(), digest());
    assert_eq!(
        ProviderRegistry::new()
            .register_observed_provider(&value, observed)
            .unwrap_err()
            .code,
        "INTERFACE_MISMATCH"
    );
    let mut invalid = value.clone();
    invalid["actions"][0]["inputSchema"] = json!({"type":"made_up"});
    assert_eq!(
        ProviderRegistry::new()
            .register_observed_provider(&invalid, observation(&invalid))
            .unwrap_err()
            .code,
        "INCOMPATIBLE_CONTRACT"
    );
    let mut elevated = value.clone();
    elevated["actions"][0]["versionEvidence"] = json!("runtime_verified");
    assert_eq!(
        ProviderRegistry::new()
            .register_observed_provider(&elevated, observation(&elevated))
            .unwrap_err()
            .code,
        "INTERFACE_MISMATCH"
    );
}

#[test]
fn bind_preserves_action_and_requires_policy_not_provenance_or_request_claim() {
    let interface = interface_java();
    let profile = profile_java();
    let (request, approval) = approved_request(profile.clone(), &interface);
    let descriptor = ProviderRegistry::new()
        .bind_compatibility(&request, &context(), &approval, &interface)
        .unwrap();
    assert_eq!(
        wire("ActionDescriptor", &descriptor.actions[0]).unwrap(),
        profile["action"]
    );
    assert_eq!(
        descriptor.actions[0].version_evidence,
        VersionEvidence::Declared
    );
    assert_eq!(
        descriptor.compatibility_evidence,
        CompatibilityEvidence::InterfaceChecked
    );
    let mut changed = request.clone();
    changed["profile"]["provenance"]["author"] = json!("trusted administrator");
    assert_eq!(
        ProviderRegistry::new()
            .bind_compatibility(&changed, &context(), &approval, &interface)
            .unwrap_err()
            .code,
        "PROFILE_UNTRUSTED"
    );
    let mut changed = request;
    changed["approvedProfileRef"] = json!("self-approved");
    assert_eq!(
        ProviderRegistry::new()
            .bind_compatibility(&changed, &context(), &approval, &interface)
            .unwrap_err()
            .code,
        "PROFILE_UNTRUSTED"
    );
}

#[test]
fn binding_refuses_changed_signature_initialization_and_unresolved_receiver() {
    let mut interface = interface_java();
    if let BindingSupport::PublicJava {
        initialization_performed,
        ..
    } = &mut interface.support
    {
        *initialization_performed = true;
    }
    let (request, approval) = approved_request(profile_java(), &interface);
    assert_eq!(
        ProviderRegistry::new()
            .bind_compatibility(&request, &context(), &approval, &interface)
            .unwrap_err()
            .code,
        "UNSUPPORTED_BINDING"
    );
    let mut interface = interface_java();
    if let BindingSupport::PublicJava { signature, .. } = &mut interface.support {
        signature.method_name = "another".into();
    }
    let (request, approval) = approved_request(profile_java(), &interface);
    assert_eq!(
        ProviderRegistry::new()
            .bind_compatibility(&request, &context(), &approval, &interface)
            .unwrap_err()
            .code,
        "INTERFACE_MISMATCH"
    );
    let mut profile = profile_java();
    profile["binding"]["receiver"] = json!("registered_handle");
    profile["binding"]["receiverHandleType"] = json!("org.mmmm.fixture.LegacyApi");
    let mut interface = interface_java();
    if let BindingSupport::PublicJava {
        signature,
        scoped_handle_types,
        ..
    } = &mut interface.support
    {
        signature.receiver = Receiver::RegisteredHandle;
        scoped_handle_types.insert("org.mmmm.fixture.LegacyApi".into());
    }
    let (request, approval) = approved_request(profile, &interface);
    assert_eq!(
        ProviderRegistry::new()
            .bind_compatibility(&request, &context(), &approval, &interface)
            .unwrap_err()
            .code,
        "UNSUPPORTED_RECEIVER"
    );
}

#[test]
fn exact_versions_digest_and_pointer_mapping_are_not_widened() {
    let mut profile = profile_java();
    profile["match"]["supportedModVersions"] = json!(["*"]);
    let interface = interface_java();
    let (request, approval) = approved_request(profile, &interface);
    assert_eq!(
        ProviderRegistry::new()
            .bind_compatibility(&request, &context(), &approval, &interface)
            .unwrap_err()
            .code,
        "INTERFACE_MISMATCH"
    );
    let mut interface = interface_java();
    interface.implementation_digest = digest();
    let (request, approval) = approved_request(profile_java(), &interface);
    assert_eq!(
        ProviderRegistry::new()
            .bind_compatibility(&request, &context(), &approval, &interface)
            .unwrap_err()
            .code,
        "INTERFACE_MISMATCH"
    );
    let mut profile = profile_java();
    profile["binding"]["arguments"][0]["pointer"] = json!("/bad~2escape");
    let interface = interface_java();
    let (request, approval) = approved_request(profile, &interface);
    assert_eq!(
        ProviderRegistry::new()
            .bind_compatibility(&request, &context(), &approval, &interface)
            .unwrap_err()
            .code,
        "UNSUPPORTED_BINDING"
    );
}

struct NoHandles;
impl HandleResolver for NoHandles {
    fn resolve(&self, _: &str, _: &HandleScope, _: &str) -> Result<ResolvedHandle, AdapterError> {
        Err(AdapterError::new(
            "HANDLE_INVALID",
            "No handles are registered",
        ))
    }
}
fn scope() -> HandleScope {
    HandleScope {
        binding_id: BindingId::new("binding-fixture-01").unwrap(),
        environment_digest: canonical_digest(&context_value()["environment"]).unwrap(),
        principal_id: mmmm_contracts::PrincipalId::new("principal-fixture").unwrap(),
    }
}

#[test]
fn mapping_preserves_explicit_null_false_zero_and_rejects_omission() {
    let mapping = BindingValue::Argument {
        pointer: "/value".into(),
        codec: ArgumentCodec::JsonValue,
    };
    for value in [Value::Null, json!(false), json!(0)] {
        let result = map_binding_value(
            &mapping,
            &json!({"value":value}),
            &context_value(),
            &scope(),
            &NoHandles,
        )
        .unwrap();
        assert_eq!(
            result,
            MappedValue::Argument {
                codec: ArgumentCodec::JsonValue,
                value
            }
        );
    }
    assert_eq!(
        map_binding_value(&mapping, &json!({}), &context_value(), &scope(), &NoHandles)
            .unwrap_err()
            .code,
        "INPUT_MISSING"
    );
    let field: BindingValue = decode(
        "BindingValue",
        &json!({"kind":"context","field":"executorHandle"}),
    )
    .unwrap();
    assert!(matches!(
        map_binding_value(&field, &json!({}), &context_value(), &scope(), &NoHandles).unwrap(),
        MappedValue::Context { .. }
    ));
}

#[test]
fn java_numeric_conversion_is_finite_integral_and_cannot_construct_a_class() {
    assert!(validate_java_argument("int", &MappedValue::Literal(json!(1.0))).is_ok());
    for value in [json!(2147483648_u64), json!(0.5), Value::Null] {
        assert!(validate_java_argument("int", &MappedValue::Literal(value)).is_err());
    }
    assert!(validate_java_argument("float", &MappedValue::Literal(json!(1e300))).is_err());
    assert!(validate_java_argument("double", &MappedValue::Literal(json!(1e300))).is_ok());
    assert!(validate_java_argument("java.lang.String", &MappedValue::Literal(Value::Null)).is_ok());
    assert!(
        validate_java_argument(
            "org.mmmm.fixture.CustomType",
            &MappedValue::Literal(Value::Null)
        )
        .is_err()
    );
}

#[test]
fn descriptor_output_schema_validation_does_not_become_effect_evidence() {
    let value = provider();
    let mut registry = ProviderRegistry::new();
    registry
        .register_observed_provider(&value, observation(&value))
        .unwrap();
    let snapshot = registry.snapshot(context(), digest()).unwrap();
    let binding = BindingId::new("binding-fixture-01").unwrap();
    let action = ActionId::new("fixture:echo_text").unwrap();
    snapshot
        .validate_action_input(&binding, &action, &json!({"text":"safe"}))
        .unwrap();
    assert!(
        snapshot
            .validate_action_input(&binding, &action, &json!({"text":"safe","extra":true}))
            .is_err()
    );
    assert_eq!(
        snapshot
            .validate_action_output(&binding, &action, &json!({"text":123}))
            .unwrap_err()
            .code,
        "OUTPUT_INVALID"
    );
}

#[test]
fn current_policy_protocol_and_selected_pin_permission_cannot_be_forged() {
    let value = provider();
    let mut registry = ProviderRegistry::new();
    registry
        .register_observed_provider(&value, observation(&value))
        .unwrap();
    let snapshot = registry.snapshot(context(), digest()).unwrap();
    let request = route(&snapshot, None);
    let selected = snapshot.resolve(&request).unwrap();
    snapshot.check_selection(&request, &selected).unwrap();
    let restricted =
        RouteContext::from_execution_context(&context_value(), BTreeSet::new()).unwrap();
    let restricted = registry.snapshot(restricted, digest()).unwrap();
    assert_eq!(
        restricted.check_selected_pin(&selected).unwrap_err().code,
        "CAPABILITY_UNAVAILABLE"
    );
    let wrong_policy = Sha256Digest::new("b".repeat(64)).unwrap();
    assert!(registry.snapshot(context(), wrong_policy).is_err());
    let mut unsupported = provider();
    unsupported["hostProtocolVersion"] = json!("0.3.0");
    assert_eq!(
        ProviderRegistry::new()
            .register_observed_provider(&unsupported, observation(&unsupported))
            .unwrap_err()
            .code,
        "INTERFACE_MISMATCH"
    );
}

#[test]
fn approved_interface_reuses_profile_after_reconnect_while_binding_epoch_changes() {
    let interface = interface_java();
    let (request, approval) = approved_request(profile_java(), &interface);
    let old = ProviderRegistry::new()
        .bind_compatibility(&request, &context(), &approval, &interface)
        .unwrap();
    let mut next_interface = interface.clone();
    if let EnvironmentRef::Game { session_epoch, .. } = &mut next_interface.environment {
        *session_epoch = mmmm_contracts::SessionEpoch::new("epoch-next").unwrap();
    }
    assert_eq!(
        interface.interface_digest().unwrap(),
        next_interface.interface_digest().unwrap()
    );
    let mut next_context = context_value();
    next_context["environment"]["sessionEpoch"] = json!("epoch-next");
    next_context["contextDigest"] =
        json!(projected_digest("ExecutionContext", &next_context).unwrap());
    let next_context = RouteContext::from_execution_context(
        &next_context,
        BTreeSet::from(["diagnostic.read".into()]),
    )
    .unwrap();
    let mut next_request = request;
    next_request["environment"]["sessionEpoch"] = json!("epoch-next");
    let next = ProviderRegistry::new()
        .bind_compatibility(&next_request, &next_context, &approval, &next_interface)
        .unwrap();
    assert_ne!(old.binding_id, next.binding_id);
}

#[test]
fn registered_rpc_data_mapping_validates_distinct_endpoint_schema() {
    let mut profile = profile_java();
    profile["binding"] = json!({"kind":"registered_rpc","targetId":"target-test","method":"echo.run","arguments":{"message":{"kind":"argument","pointer":"/text","codec":"string"}},"resultCodec":"json_echo_v1"});
    let mut interface = interface_java();
    interface.support = BindingSupport::RegisteredRpc {
        target_id: mmmm_contracts::TargetId::new("target-test").unwrap(),
        method: "echo.run".into(),
        endpoint_contract_digest: digest(),
        input_schema: json!({"type":"object","properties":{"message":{"type":"string"}},"required":["message"],"additionalProperties":false}),
        output_schema: json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"],"additionalProperties":false}),
        result_codec: "json_echo_v1".into(),
        registered_local: true,
    };
    let (request, approval) = approved_request(profile, &interface);
    let mut registry = ProviderRegistry::new();
    registry
        .bind_compatibility(&request, &context(), &approval, &interface)
        .unwrap();
    let binding: Binding = decode("RpcBinding", &request["profile"]["binding"]).unwrap();
    assert_eq!(
        prepare_rpc_arguments(
            &binding,
            &interface.support,
            &json!({"text":"mapped"}),
            &context_value(),
            &scope(),
            &NoHandles
        )
        .unwrap(),
        json!({"message":"mapped"})
    );
    assert!(
        prepare_rpc_arguments(
            &binding,
            &interface.support,
            &json!({"text":null}),
            &context_value(),
            &scope(),
            &NoHandles
        )
        .is_err()
    );
    assert_eq!(
        validate_rpc_response(&interface.support, &json!({"text":false}))
            .unwrap_err()
            .code,
        "OUTPUT_INVALID"
    );
}

#[test]
fn rpc_mapping_counts_escaped_keys_syntax_and_repeated_values_before_copying() {
    let payload = "quoted \"text\"\\line\n雪".repeat(4);
    let key = "escaped\"key\\\n";
    let mappings = std::collections::BTreeMap::from([
        (
            key.to_string(),
            BindingValue::Argument {
                pointer: "/payload".into(),
                codec: ArgumentCodec::JsonValue,
            },
        ),
        (
            "second".to_string(),
            BindingValue::Argument {
                pointer: "/payload".into(),
                codec: ArgumentCodec::JsonValue,
            },
        ),
    ]);
    let binding = Binding::RegisteredRpc {
        target_id: mmmm_contracts::TargetId::new("target-test").unwrap(),
        method: "map.run".into(),
        arguments: mappings,
        result_codec: "json_map_v1".into(),
    };
    let support = BindingSupport::RegisteredRpc {
        target_id: mmmm_contracts::TargetId::new("target-test").unwrap(),
        method: "map.run".into(),
        endpoint_contract_digest: digest(),
        input_schema: json!({"type":"object","additionalProperties":{"type":"string"}}),
        output_schema: json!({"type":"object"}),
        result_codec: "json_map_v1".into(),
        registered_local: true,
    };
    let input = json!({"payload":payload});
    let expected = json!({key:payload,"second":payload});
    let exact_budget = mmmm_contracts::encode_json(&expected).unwrap().len();
    let mapped = crate::mapping::prepare_rpc_arguments_with_budget(
        &binding,
        &support,
        &input,
        &context_value(),
        &scope(),
        &NoHandles,
        exact_budget,
    )
    .unwrap();
    assert_eq!(mapped, expected);
    assert_eq!(
        crate::mapping::prepare_rpc_arguments_with_budget(
            &binding,
            &support,
            &input,
            &context_value(),
            &scope(),
            &NoHandles,
            exact_budget - 1,
        )
        .unwrap_err()
        .code,
        "MAPPING_OUTPUT_LIMIT"
    );

    // A small fixed input stands in for repeated large values. Production uses
    // the same counter with 8 MiB; the test keeps allocation inexpensive.
    let mut repeated = binding;
    if let Binding::RegisteredRpc { arguments, .. } = &mut repeated {
        *arguments = (0..64)
            .map(|index| {
                (
                    format!("copy-{index:02}"),
                    BindingValue::Argument {
                        pointer: "/payload".into(),
                        codec: ArgumentCodec::JsonValue,
                    },
                )
            })
            .collect();
    }
    assert_eq!(
        crate::mapping::prepare_rpc_arguments_with_budget(
            &repeated,
            &support,
            &input,
            &context_value(),
            &scope(),
            &NoHandles,
            256,
        )
        .unwrap_err()
        .code,
        "MAPPING_OUTPUT_LIMIT"
    );
}

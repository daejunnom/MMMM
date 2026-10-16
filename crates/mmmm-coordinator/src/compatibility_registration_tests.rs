//! Reuse the canonical public-Java declaration with one documented scalar
//! variant. These pure fixtures issue no protected approval or Java/game proof;
//! native management and runtime tests cover the actual owner/SQLite/CAS path.
use super::*;
use mmmm_contracts::{parse_json, raw_digest};
use std::{
    error::Error,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

fn scalar_profile() -> Value {
    let mut value =
        parse_json(include_bytes!("../../../examples/compat-public-java.json")).unwrap();
    value["binding"]["resultCodec"] = json!("scalar");
    value["binding"]["returnType"] = json!("java.lang.String");
    value["action"]["outputSchema"] = json!({"type":"object","properties":{"value":{"type":"string"}},
        "required":["value"],"additionalProperties":false});
    validate("CompatibilityProfile", &value).unwrap();
    value
}
fn context() -> Value {
    parse_json(include_bytes!("../../../examples/execution-context.json")).unwrap()
}
fn interface_value(profile: &Value) -> Value {
    let context = context();
    json!({"environment":context["environment"],"loader":"fabric","targetGameVersion":"26.3",
        "modId":profile["match"]["modId"],"modVersion":"0.1.0","hostProtocolVersion":mmmm_adapters::HOST_PROTOCOL_VERSION,
        "implementationDigest":profile["action"]["implementationDigest"],
        "loaded":true,"connected":true,"availability":"available",
        "readiness":{"ready":true,"possibleLossCodes":[]},
        "support":{"kind":"public_java","signature":{"ownerClass":profile["binding"]["ownerClass"],
            "methodName":profile["binding"]["methodName"],"parameterTypes":profile["binding"]["parameterTypes"],
            "returnType":profile["binding"]["returnType"],"receiver":"static"},
            "publicLookupChecked":true,"initializationPerformed":false,"threadAffinity":"server_main",
            "receiverResolver":null,"scopedHandleTypes":[]}})
}

#[test]
fn profile_source_digest_and_implementation_pin_are_independent_and_read_only() {
    let value = scalar_profile();
    let profile: CompatibilityProfile = decode(&value).unwrap();
    let semantic = projected_digest("CompatibilityProfile", &value).unwrap();
    let mut original = encode_json(&value).unwrap();
    original.push(b'\n');
    let raw = raw_digest(&original);
    assert_ne!(semantic, raw);
    assert_ne!(semantic, profile.action.implementation_digest);
    check_profile_pins(&profile, &semantic, &profile.action.implementation_digest).unwrap();
    for (profile_pin, implementation) in [
        (&raw, &profile.action.implementation_digest),
        (&semantic, &semantic),
    ] {
        assert_eq!(
            check_profile_pins(&profile, profile_pin, implementation)
                .unwrap_err()
                .code,
            "PROFILE_UNTRUSTED"
        );
    }
    let original: CompatibilityProfile =
        decode(&parse_json(include_bytes!("../../../examples/compat-public-java.json")).unwrap())
            .unwrap();
    assert_eq!(
        supported_read(&original).unwrap_err().code,
        "CAPABILITY_UNAVAILABLE"
    );
    let mut write = value.clone();
    write["action"]["effect"] = json!("write");
    assert_eq!(
        supported_read(&decode(&write).unwrap()).unwrap_err().code,
        "CAPABILITY_UNAVAILABLE"
    );
    let a = local_use_scope(
        &ProjectId::new("project-a").unwrap(),
        &json!({"sha256":raw}),
    )
    .unwrap();
    let b = local_use_scope(
        &ProjectId::new("project-b").unwrap(),
        &json!({"sha256":raw}),
    )
    .unwrap();
    assert_ne!(a, b);
}

#[test]
fn actual_interface_shape_requires_no_initialization_and_explicit_nullable_facts() {
    let profile = scalar_profile();
    let value = interface_value(&profile);
    let observation = decode::<JavaInterfaceFacts>(&value)
        .unwrap()
        .observation()
        .unwrap();
    assert_eq!(
        observation.evidence,
        CompatibilityEvidence::InterfaceChecked
    );
    assert!(matches!(
        &observation.support,
        BindingSupport::PublicJava {
            initialization_performed: false,
            ..
        }
    ));
    let expected = canonical_digest(&json!({"kind":"mmmm-interface-observation/1","side":"server",
        "loader":"fabric","targetGameVersion":"26.3","modId":profile["match"]["modId"],
        "modVersion":"0.1.0","hostProtocolVersion":mmmm_adapters::HOST_PROTOCOL_VERSION,
        "implementationDigest":profile["action"]["implementationDigest"],"support":value["support"]})).unwrap();
    assert_eq!(observation.interface_digest().unwrap(), expected);
    for (field, changed) in [
        ("initializationPerformed", json!(true)),
        ("publicLookupChecked", json!(false)),
        ("receiverResolver", json!("caller-owned")),
        ("scopedHandleTypes", json!(["caller-owned"])),
    ] {
        let mut invalid = value.clone();
        invalid["support"][field] = changed;
        assert_eq!(
            decode::<JavaInterfaceFacts>(&invalid)
                .unwrap()
                .observation()
                .unwrap_err()
                .code,
            "CAPABILITY_UNAVAILABLE"
        );
    }
    for (object, field) in [
        ("support", "receiverResolver"),
        ("readiness", "possibleLossCodes"),
    ] {
        let mut omitted = value.clone();
        omitted[object].as_object_mut().unwrap().remove(field);
        assert!(decode::<JavaInterfaceFacts>(&omitted).is_err());
    }
    let mut omitted = value.clone();
    omitted.as_object_mut().unwrap().remove("modId");
    assert!(decode::<JavaInterfaceFacts>(&omitted).is_err());
    let mut unknown = value;
    unknown["support"]["execute"] = json!(true);
    assert!(decode::<JavaInterfaceFacts>(&unknown).is_err());
}

#[test]
fn canonical_binding_keeps_profile_approval_and_current_environment_epoch_distinct() {
    let profile = scalar_profile();
    let digest = projected_digest("CompatibilityProfile", &profile).unwrap();
    let context = context();
    let route = RouteContext::from_execution_context(&context, BTreeSet::new()).unwrap();
    let interface = decode::<JavaInterfaceFacts>(&interface_value(&profile))
        .unwrap()
        .observation()
        .unwrap();
    let approval = ProfileApproval {
        reference: "native.read-profile".into(),
        source_id: "native.read-profile".into(),
        profile_digest: digest.clone(),
        allowed_interface_digest: interface.interface_digest().unwrap(),
    };
    let input = json!({"profile":profile,"profileDigest":digest,"contextId":context["contextId"],
        "environment":context["environment"],"approvedProfileRef":"native.read-profile"});
    let descriptor = ProviderRegistry::new()
        .bind_compatibility(&input, &route, &approval, &interface)
        .unwrap();
    assert_eq!(
        descriptor.registration_mode,
        RegistrationMode::Compatibility
    );
    assert_eq!(descriptor.origin.kind, OriginKind::LocalProfile);
    assert_eq!(descriptor.origin.source_digest, Some(digest));
    assert_ne!(
        descriptor.origin.source_digest.as_ref(),
        Some(&interface.implementation_digest)
    );
    let mut wrong = input.clone();
    wrong["approvedProfileRef"] = json!("caller.unapproved");
    assert_eq!(
        ProviderRegistry::new()
            .bind_compatibility(&wrong, &route, &approval, &interface)
            .unwrap_err()
            .code,
        "PROFILE_UNTRUSTED"
    );
    wrong = input;
    wrong["environment"]["sessionEpoch"] = json!("different-epoch");
    assert!(
        ProviderRegistry::new()
            .bind_compatibility(&wrong, &route, &approval, &interface)
            .is_err()
    );
}

#[test]
fn source_parse_observes_original_cancellation_and_keeps_both_failure_causes() {
    // Existing Project bytes supply factual pins only. Size admission occurs
    // before read_project; repeated checks compare the whole protected pin and
    // do not deserialize or re-read the Project CAS body.
    let project_bytes = include_bytes!("../../../examples/project.json");
    let project = parse_json(project_bytes).unwrap();
    let head = ProjectHeadPin {
        revision: projected_digest("Project", &project).unwrap(),
        blob: mmmm_runtime::storage::BlobRef {
            digest: raw_digest(project_bytes),
            byte_length: project_bytes.len() as u64,
        },
    };
    admit_project_head(&head).unwrap();
    same_project_head(&head, &head).unwrap();
    let mut ceiling = head.clone();
    ceiling.blob.byte_length = MAX_PROJECT_BYTES as u64;
    admit_project_head(&ceiling).unwrap();
    ceiling.blob.byte_length += 1;
    assert_eq!(
        admit_project_head(&ceiling).unwrap_err().code,
        "BUDGET_EXCEEDED"
    );
    let mut revision_changed = head.clone();
    revision_changed.revision = raw_digest(b"changed project revision");
    let mut blob_changed = head.clone();
    blob_changed.blob.digest = raw_digest(b"changed project blob");
    let mut length_changed = head.clone();
    length_changed.blob.byte_length += 1;
    for changed in [revision_changed, blob_changed, length_changed] {
        assert_eq!(
            same_project_head(&head, &changed).unwrap_err().code,
            "STALE_CONTEXT"
        );
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let budget = RequestBudget::new(Duration::from_secs(1), cancelled.clone()).unwrap();
    cancelled.store(true, std::sync::atomic::Ordering::Release);
    let result = parse_json_with_control(b"{\"value\":1}", JsonLimits::default(), || {
        budget.check().map_err(service_error)
    });
    assert!(matches!(result, Err(ControlledJsonError::Control(_))));
    let error = combine::<()>(
        Err(AppError::new("PROFILE_UNTRUSTED", "native failure")),
        Err(AppError::new("REQUEST_RETIRED", "request retired")),
    )
    .unwrap_err();
    assert_eq!(error.code, "PROFILE_UNTRUSTED");
    let both = error
        .source()
        .unwrap()
        .downcast_ref::<NativePairingOwnerFailure>()
        .unwrap();
    assert_eq!(both.primary.code, "PROFILE_UNTRUSTED");
    assert_eq!(both.checkpoint.code, "REQUEST_RETIRED");
}

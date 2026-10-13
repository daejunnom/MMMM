//! Minimal source-authored bytes cover raw/normalized identity separation,
//! ordered pack fingerprints and native enumeration. Original examples contain
//! no real source decoder/rights/CAS boundary; these are pure port tests.

use super::*;
use crate::{AccessControl, Catalog, CatalogLimits};
use mmmm_contracts::{PrincipalId, projected_digest};
use std::{
    cell::RefCell,
    rc::Rc,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

fn digest(c: char) -> Sha256Digest {
    Sha256Digest::new(c.to_string().repeat(64)).unwrap()
}
fn principal() -> ReadPrincipal {
    ReadPrincipal {
        principal_id: PrincipalId::new("principal-fixture").unwrap(),
        permission_scope_digest: digest('1'),
    }
}
fn approved_source(id: &str, runtime: bool) -> ApprovedCatalogSource {
    ApprovedCatalogSource {
        source: json!({"sourceId":id,"kind":if runtime{"runtime_observation"}else{"user_file"},
        "locator":format!("approved-source://{id}"),"sha256":null,"rights":"user_local_only","verifiedAt":"2026-10-13T00:00:00Z"}),
        layer: if runtime {
            CatalogLayer::EnvironmentSnapshot
        } else {
            CatalogLayer::LocalArtifact
        },
        role: match id {
            "artifact" => CatalogSourceRole::GameArtifact,
            "server-low" | "server-high" => CatalogSourceRole::ServerPack,
            "client-pack" => CatalogSourceRole::ClientPack,
            "mod-source" => CatalogSourceRole::Mod(ResourceLocation::new("fixture:mod").unwrap()),
            _ => CatalogSourceRole::CatalogData,
        },
        rights_witness: digest('2'),
        codec: if runtime {
            CatalogSourceCodec::NativeRegistry
        } else {
            CatalogSourceCodec::FingerprintOnly {
                media_type: "application/octet-stream".into(),
            }
        },
    }
}
fn native() -> Vec<u8> {
    encode_json(&json!({"format":NATIVE_REGISTRY_FORMAT,"blocks":[{"id":"minecraft:fixture_block",
    "defaultState":{"blockId":"minecraft:fixture_block","properties":{"facing":"north"}},"properties":{"facing":["north","south"]}}],
    "items":["minecraft:fixture_item"],"entityTypes":["minecraft:fixture_entity"]})).unwrap()
}
fn grant() -> CaptureGrant {
    let context = parse_json(include_bytes!("../../../examples/execution-context.json")).unwrap();
    let sources = vec![
        approved_source("registry", true),
        approved_source("artifact", false),
        approved_source("server-low", false),
        approved_source("server-high", false),
        approved_source("client-pack", false),
        approved_source("mod-source", false),
    ];
    CaptureGrant {
        execution_context: context,
        snapshot_id: SnapshotId::new("snapshot-captured-1").unwrap(),
        game_version: Some("26.3".into()),
        locale: Some("ko_kr".into()),
        created_at: "2026-10-14T00:00:00Z".into(),
        artifact_source: Some(SourceId::new("artifact").unwrap()),
        server_pack_sources: Some(vec![
            SourceId::new("server-low").unwrap(),
            SourceId::new("server-high").unwrap(),
        ]),
        client_pack_sources: Some(vec![SourceId::new("client-pack").unwrap()]),
        mod_sources: Some(BTreeMap::from([(
            ResourceLocation::new("fixture:mod").unwrap(),
            SourceId::new("mod-source").unwrap(),
        )])),
        registry_generation: None,
        sources,
    }
}
fn request(grant: &CaptureGrant) -> Value {
    json!({"contextId":grant.execution_context["contextId"],"environment":grant.execution_context["environment"],
    "sources":[],"kind":"environment_snapshot","loadPolicy":"no_implicit_runtime_mutation"})
}
struct Allow {
    deny: Option<String>,
}
impl AccessControl for Allow {
    fn authorize_snapshot(&self, _: &ReadPrincipal, _: &Value) -> Result<(), CatalogError> {
        Ok(())
    }
    fn can_read_record(
        &self,
        _: &ReadPrincipal,
        _: &Value,
        _: &Value,
        _: Option<&ContextId>,
    ) -> bool {
        true
    }
    fn authorize_capture(&self, _: &ReadPrincipal, _: &Value) -> Result<(), CatalogError> {
        Ok(())
    }
    fn authorize_source(&self, _: &ReadPrincipal, source: &Value) -> Result<(), CatalogError> {
        if self.deny.as_deref() == source["sourceId"].as_str() {
            Err(CatalogError::PermissionRequired)
        } else {
            Ok(())
        }
    }
}
struct State {
    grant: CaptureGrant,
    raw: Vec<u8>,
    wrapper: Value,
    files: BTreeMap<String, Vec<u8>>,
    reads: usize,
    host_calls: usize,
    retained: Vec<(Value, Vec<u8>)>,
    rights_drift: bool,
    final_drift: bool,
    bad_resource: bool,
    next_id: usize,
    cancel_after_reads: Option<usize>,
}
fn state() -> Rc<RefCell<State>> {
    let grant = grant();
    let raw = native();
    let wrapper = json!({"contextDigest":grant.execution_context["contextDigest"],"environment":grant.execution_context["environment"],
        "registryDigest":canonical_digest(&parse_json(&raw).unwrap()).unwrap(),"registryGeneration":"observed-generation-7","observedFromTick":"10","observedToTick":"12",
        "observedAt":"2026-10-14T00:00:01Z","gameVersion":"26.3","locale":"ko_kr","observationBytesHex":raw.iter().map(|b|format!("{b:02x}")).collect::<String>()});
    let files = BTreeMap::from([
        ("artifact".into(), b"actual fixture artifact bytes".to_vec()),
        (
            "server-low".into(),
            b"low priority actual pack bytes".to_vec(),
        ),
        (
            "server-high".into(),
            b"high priority actual pack bytes".to_vec(),
        ),
        (
            "client-pack".into(),
            b"actual client resource pack bytes".to_vec(),
        ),
        ("mod-source".into(), b"actual mod artifact bytes".to_vec()),
    ]);
    Rc::new(RefCell::new(State {
        grant,
        raw,
        wrapper,
        files,
        reads: 0,
        host_calls: 0,
        retained: vec![],
        rights_drift: false,
        final_drift: false,
        bad_resource: false,
        next_id: 0,
        cancel_after_reads: None,
    }))
}
struct Host(Rc<RefCell<State>>);
impl HostRegistryTransport for Host {
    fn inspect_registry(
        &mut self,
        context: &Value,
        _: &CaptureControl<'_>,
        max_bytes: usize,
    ) -> Result<Value, CatalogError> {
        let mut state = self.0.borrow_mut();
        assert_eq!(
            context["contextId"],
            state.grant.execution_context["contextId"]
        );
        state.host_calls += 1;
        if state.raw.len() > max_bytes {
            return Err(CatalogError::InputLimit);
        }
        Ok(state.wrapper.clone())
    }
}
struct Backend(Rc<RefCell<State>>);
impl CatalogCaptureBackend for Backend {
    fn resolve_capture(
        &mut self,
        caller: &ReadPrincipal,
        _: &Value,
        _: &CaptureControl<'_>,
        _: &CaptureBudget,
    ) -> Result<CaptureGrant, CatalogError> {
        assert_eq!(caller.principal_id, principal().principal_id);
        let mut state = self.0.borrow_mut();
        state.next_id += 1;
        let mut grant = state.grant.clone();
        grant.snapshot_id =
            SnapshotId::new(format!("snapshot-captured-{}", state.next_id)).unwrap();
        Ok(grant)
    }
    fn revalidate_capture(
        &mut self,
        _: &ReadPrincipal,
        _: &Value,
        _: &CaptureGrant,
        observed: Option<&RegistryCaptureWitness>,
        _: bool,
        _: &CaptureControl<'_>,
    ) -> Result<(), CatalogError> {
        if self.0.borrow().final_drift {
            return Err(unavailable("Actual epoch/selected pack authority changed"));
        }
        if let Some(witness) = observed {
            assert_eq!(witness.registry_generation, "observed-generation-7");
        }
        Ok(())
    }
    fn read_approved_source(
        &mut self,
        _: &ReadPrincipal,
        _: &CaptureGrant,
        source: &ApprovedCatalogSource,
        max_bytes: usize,
        control: &CaptureControl<'_>,
    ) -> Result<CapturedSourceBytes, CatalogError> {
        let mut state = self.0.borrow_mut();
        state.reads += 1;
        let bytes = state
            .files
            .get(source.source["sourceId"].as_str().unwrap())
            .unwrap()
            .clone();
        if bytes.len() > max_bytes {
            return Err(CatalogError::InputLimit);
        }
        if state.cancel_after_reads == Some(state.reads) {
            control
                .cancellation
                .store(true, std::sync::atomic::Ordering::Release);
        }
        Ok(CapturedSourceBytes {
            bytes,
            verified_at: "2026-10-14T00:00:01Z".into(),
            rights_witness: if state.rights_drift {
                digest('3')
            } else {
                source.rights_witness.clone()
            },
        })
    }
    fn retain_source_evidence(
        &mut self,
        _: &ReadPrincipal,
        _: &CaptureGrant,
        source: &Value,
        bytes: &[u8],
        media: &str,
    ) -> Result<Value, CatalogError> {
        let mut state = self.0.borrow_mut();
        state.retained.push((source.clone(), bytes.to_vec()));
        Ok(
            json!({"resourceId":format!("source-{}",raw_digest(bytes)),"sha256":if state.bad_resource{digest('4')}else{raw_digest(bytes)},"sizeBytes":bytes.len(),"mediaType":media}),
        )
    }
}
type Source = VerifiedSnapshotSource<Host, Backend>;
fn setup() -> (Catalog, Source, Rc<RefCell<State>>) {
    let state = state();
    (
        Catalog::new([7; 32], CatalogLimits::default()).unwrap(),
        VerifiedSnapshotSource {
            transport: Host(state.clone()),
            backend: Backend(state.clone()),
        },
        state,
    )
}
fn capture(
    catalog: &mut Catalog,
    source: &mut Source,
    request: &Value,
    access: &Allow,
) -> Result<Value, CatalogError> {
    let cancel = AtomicBool::new(false);
    catalog.capture(
        request,
        &principal(),
        access,
        source,
        &CaptureControl {
            cancellation: &cancel,
            deadline: Instant::now() + Duration::from_secs(5),
        },
    )
}

#[test]
fn actual_registry_bytes_and_ordered_pack_artifact_identity_are_separate() {
    let (mut catalog, mut source, state) = setup();
    let input = request(&state.borrow().grant);
    let snapshot = capture(&mut catalog, &mut source, &input, &Allow { deny: None }).unwrap();
    let data = state.borrow();
    assert_eq!(
        snapshot["artifactSha256"],
        raw_digest(&data.files["artifact"]).as_str()
    );
    assert_ne!(snapshot["artifactSha256"], raw_digest(&data.raw).as_str());
    assert_eq!(
        snapshot["serverPackStack"],
        json!([
            raw_digest(&data.files["server-low"]),
            raw_digest(&data.files["server-high"])
        ])
    );
    assert_eq!(
        snapshot["clientPackStack"],
        json!([raw_digest(&data.files["client-pack"])])
    );
    assert_eq!(snapshot["coverage"]["status"], "partial");
    assert_eq!(snapshot["coverage"]["consistency"], "bounded_window");
    assert_eq!(data.retained.len(), 6);
    assert!(
        data.retained
            .iter()
            .all(|(source, bytes)| source["sha256"] == raw_digest(bytes).as_str())
    );
    drop(data);
    let pin = catalog
        .snapshot_pin(
            &SnapshotId::new(snapshot["snapshotId"].as_str().unwrap()).unwrap(),
            &principal(),
            &Allow { deny: None },
        )
        .unwrap();
    assert_eq!(pin.identity.registry_generation, "observed-generation-7");
    assert_eq!(pin.identity.observation_window.unwrap().last_tick, "12");
    let result=catalog.describe(&json!({"snapshotId":snapshot["snapshotId"],"kind":"minecraft:block","resourceId":"minecraft:fixture_block","contextId":"context-fixture-01"}),&principal(),&Allow{deny:None}).unwrap();
    assert_eq!(result["status"], "known");
    assert_eq!(result["valueType"], "block_registry_entry");
    assert_eq!(
        result["value"]["properties"]["facing"],
        json!(["north", "south"])
    );
    let absent=catalog.describe(&json!({"snapshotId":snapshot["snapshotId"],"kind":"minecraft:block","resourceId":"minecraft:missing","contextId":"context-fixture-01"}),&principal(),&Allow{deny:None}).unwrap();
    assert_eq!(absent["status"], "absent");
}
#[test]
fn unknown_metadata_does_not_become_empty_verified_snapshot() {
    for mutation in 0..5 {
        let (mut catalog, mut source, state) = setup();
        match mutation {
            0 => state.borrow_mut().grant.mod_sources = None,
            1 => state.borrow_mut().grant.server_pack_sources = None,
            2 => state.borrow_mut().grant.artifact_source = None,
            3 => state.borrow_mut().grant.game_version = None,
            _ => state.borrow_mut().grant.locale = None,
        };
        let input = request(&state.borrow().grant);
        assert_eq!(
            capture(&mut catalog, &mut source, &input, &Allow { deny: None })
                .unwrap_err()
                .code(),
            "SOURCE_UNAVAILABLE"
        );
        assert_eq!(state.borrow().retained.len(), 6);
        assert!(
            catalog
                .snapshot_pin(
                    &SnapshotId::new("snapshot-captured-1").unwrap(),
                    &principal(),
                    &Allow { deny: None }
                )
                .is_err()
        );
    }
}
#[test]
fn gate_and_installed_source_claims_precede_actual_reads() {
    let (mut catalog, mut source, state) = setup();
    let input = request(&state.borrow().grant);
    assert_eq!(
        capture(
            &mut catalog,
            &mut source,
            &input,
            &Allow {
                deny: Some("registry".into())
            }
        )
        .unwrap_err()
        .code(),
        "PERMISSION_REQUIRED"
    );
    assert_eq!(state.borrow().reads, 0);
    assert_eq!(state.borrow().host_calls, 0);
    let mut input = request(&state.borrow().grant);
    let mut claimed = state.borrow().grant.sources[1].source.clone();
    claimed["rights"] = json!("owned");
    input["sources"] = json!([claimed]);
    assert_eq!(
        capture(&mut catalog, &mut source, &input, &Allow { deny: None })
            .unwrap_err()
            .code(),
        "SOURCE_UNAVAILABLE"
    );
    assert_eq!(state.borrow().reads, 0);
}
#[test]
fn source_witness_raw_digest_and_registry_property_consistency_are_checked() {
    for mutation in 0..4 {
        let (mut catalog, mut source, state) = setup();
        match mutation {
            0 => state.borrow_mut().wrapper["registryDigest"] = json!(digest('5')),
            1 => state.borrow_mut().wrapper["contextDigest"] = json!(digest('6')),
            2 => state.borrow_mut().wrapper["locale"] = json!("en_us"),
            _ => {
                let mut report = parse_json(&state.borrow().raw).unwrap();
                report["blocks"][0]["properties"]["facing"] = json!(["south"]);
                let bytes = encode_json(&report).unwrap();
                let mut state = state.borrow_mut();
                state.raw = bytes.clone();
                state.wrapper["registryDigest"] = json!(canonical_digest(&report).unwrap());
                state.wrapper["observationBytesHex"] =
                    json!(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
            }
        }
        let input = request(&state.borrow().grant);
        assert!(capture(&mut catalog, &mut source, &input, &Allow { deny: None }).is_err());
        assert!(
            catalog
                .snapshot_pin(
                    &SnapshotId::new("snapshot-captured-1").unwrap(),
                    &principal(),
                    &Allow { deny: None }
                )
                .is_err()
        );
    }
}
#[test]
fn actual_source_budget_resource_hash_and_final_authority_are_checked() {
    let (mut catalog, mut source, state) = setup();
    state.borrow_mut().bad_resource = true;
    let input = request(&state.borrow().grant);
    assert_eq!(
        capture(&mut catalog, &mut source, &input, &Allow { deny: None })
            .unwrap_err()
            .code(),
        "SOURCE_UNAVAILABLE"
    );
    let (mut catalog, mut source, state) = setup();
    state.borrow_mut().final_drift = true;
    let input = request(&state.borrow().grant);
    assert_eq!(
        capture(&mut catalog, &mut source, &input, &Allow { deny: None })
            .unwrap_err()
            .code(),
        "SOURCE_UNAVAILABLE"
    );
    assert_eq!(state.borrow().retained.len(), 6);
    let (mut catalog, mut source, state) = setup();
    state.borrow_mut().rights_drift = true;
    let input = request(&state.borrow().grant);
    assert!(capture(&mut catalog, &mut source, &input, &Allow { deny: None }).is_err());
    let mut limits = CatalogLimits::default();
    limits.max_capture_evidence_bytes = native().len();
    catalog = Catalog::new([7; 32], limits).unwrap();
    let (_, mut source, state) = setup();
    let input = request(&state.borrow().grant);
    assert_eq!(
        capture(&mut catalog, &mut source, &input, &Allow { deny: None })
            .unwrap_err()
            .code(),
        "INPUT_LIMIT"
    );
}
#[test]
fn approved_json_binary_assets_preserve_contents_and_do_not_deep_merge() {
    let (mut catalog, mut source, state) = setup();
    let mut asset = approved_source("model-asset", false);
    asset.codec = CatalogSourceCodec::JsonAsset {
        kind: ResourceLocation::new("minecraft:model").unwrap(),
        resource_id: ResourceLocation::new("fixture:offset_model").unwrap(),
        value_type: "model_json".into(),
        unit: "unitless".into(),
    };
    let mut binary = approved_source("texture-asset", false);
    binary.codec = CatalogSourceCodec::BinaryAsset {
        kind: ResourceLocation::new("minecraft:texture").unwrap(),
        resource_id: ResourceLocation::new("fixture:opaque_texture").unwrap(),
        media_type: "application/octet-stream".into(),
    };
    let value = json!({"elements":[{"from":[12,0,0],"to":[16,16,2]}],"unknownExtension":true});
    {
        let mut state = state.borrow_mut();
        state.grant.sources.extend([asset, binary]);
        state
            .files
            .insert("model-asset".into(), encode_json(&value).unwrap());
        state.files.insert("texture-asset".into(), vec![0, 1, 255]);
    }
    let input = request(&state.borrow().grant);
    let snapshot = capture(&mut catalog, &mut source, &input, &Allow { deny: None }).unwrap();
    let result=catalog.describe(&json!({"snapshotId":snapshot["snapshotId"],"kind":"minecraft:model","resourceId":"fixture:offset_model","contextId":"context-fixture-01"}),&principal(),&Allow{deny:None}).unwrap();
    assert_eq!(result["value"], value);
    assert_eq!(result["provenance"], "extracted");
    let texture=catalog.describe(&json!({"snapshotId":snapshot["snapshotId"],"kind":"minecraft:texture","resourceId":"fixture:opaque_texture","contextId":"context-fixture-01"}),&principal(),&Allow{deny:None}).unwrap();
    assert_eq!(
        texture["value"]["sha256"],
        raw_digest(&[0, 1, 255]).as_str()
    );
}
#[test]
fn new_capture_ids_do_not_reuse_immutable_snapshot_revision() {
    let (mut catalog, mut source, state) = setup();
    let input = request(&state.borrow().grant);
    let first = capture(&mut catalog, &mut source, &input, &Allow { deny: None }).unwrap();
    let second = capture(&mut catalog, &mut source, &input, &Allow { deny: None }).unwrap();
    assert_ne!(first["snapshotId"], second["snapshotId"]);
    assert_eq!(
        first["environmentFingerprint"],
        second["environmentFingerprint"]
    );
    state
        .borrow_mut()
        .grant
        .server_pack_sources
        .as_mut()
        .unwrap()
        .reverse();
    let third = capture(&mut catalog, &mut source, &input, &Allow { deny: None }).unwrap();
    assert_ne!(
        first["environmentFingerprint"],
        third["environmentFingerprint"]
    );
}
#[test]
fn offline_asset_identity_keeps_unknown_artifact_null_without_runtime_claim() {
    let (mut catalog, mut port, state) = setup();
    let mut context =
        parse_json(include_bytes!("../../../examples/execution-context.json")).unwrap();
    context["environment"] =
        json!({"kind":"offline","workspaceId":"workspace-fixture","side":"offline"});
    context.as_object_mut().unwrap().remove("dimension");
    context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
    {
        let mut state = state.borrow_mut();
        state.grant.execution_context = context;
        state.grant.artifact_source = None;
        state.grant.registry_generation = Some("source-extraction-7".into());
        state.grant.server_pack_sources = Some(vec![]);
        state.grant.client_pack_sources = Some(vec![]);
        state.grant.mod_sources = Some(BTreeMap::new());
        let mut asset = approved_source("reference", false);
        asset.layer = CatalogLayer::VersionReference;
        asset.codec = CatalogSourceCodec::JsonAsset {
            kind: ResourceLocation::new("mmmm:reference").unwrap(),
            resource_id: ResourceLocation::new("fixture:reference").unwrap(),
            value_type: "source_document".into(),
            unit: "unitless".into(),
        };
        state.grant.sources = vec![asset];
        state
            .files
            .insert("reference".into(), b"{\"declaredFact\":null}".to_vec());
    }
    let mut input = request(&state.borrow().grant);
    input["kind"] = json!("version_reference");
    let snapshot = capture(&mut catalog, &mut port, &input, &Allow { deny: None }).unwrap();
    assert!(snapshot["artifactSha256"].is_null());
    assert_eq!(state.borrow().host_calls, 0);
    assert_eq!(snapshot["side"], "offline");
}

#[test]
fn cancellation_returns_partial_only_when_actual_identity_sources_are_complete() {
    let (mut catalog, mut port, state) = setup();
    let mut asset = approved_source("optional-asset", false);
    asset.codec = CatalogSourceCodec::JsonAsset {
        kind: ResourceLocation::new("minecraft:model").unwrap(),
        resource_id: ResourceLocation::new("fixture:optional_asset").unwrap(),
        value_type: "model_json".into(),
        unit: "unitless".into(),
    };
    {
        let mut state = state.borrow_mut();
        state.grant.sources.push(asset.clone());
        state
            .files
            .insert("optional-asset".into(), b"{\"notYetRead\":true}".to_vec());
        state.cancel_after_reads = Some(5);
    }
    let mut input = request(&state.borrow().grant);
    input["sources"] = json!([asset.source]);
    let snapshot = capture(&mut catalog, &mut port, &input, &Allow { deny: None }).unwrap();
    assert_eq!(snapshot["coverage"]["status"], "partial");
    assert!(
        snapshot["coverage"]["exclusions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason.as_str().unwrap().contains("interrupted"))
    );
    assert_eq!(snapshot["sources"].as_array().unwrap().len(), 6);
    assert_eq!(state.borrow().reads, 5);
    let record=catalog.describe(&json!({"snapshotId":snapshot["snapshotId"],"kind":"minecraft:block","resourceId":"minecraft:fixture_block","contextId":"context-fixture-01"}),&principal(),&Allow{deny:None}).unwrap();
    assert_eq!(record["status"], "known");
    let (mut catalog, mut port, state) = setup();
    state.borrow_mut().cancel_after_reads = Some(1);
    let input = request(&state.borrow().grant);
    assert_eq!(
        capture(&mut catalog, &mut port, &input, &Allow { deny: None })
            .unwrap_err()
            .code(),
        "CANCELLED"
    );
    assert_eq!(state.borrow().retained.len(), 2);
    assert!(
        catalog
            .snapshot_pin(
                &SnapshotId::new("snapshot-captured-1").unwrap(),
                &principal(),
                &Allow { deny: None }
            )
            .is_err()
    );
}

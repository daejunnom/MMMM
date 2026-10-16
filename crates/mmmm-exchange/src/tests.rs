//! Original examples supply contract coverage; small derived fixtures add the
//! adversarial hashes, scopes and completed-job states those examples lack.
//! The injected observer is a component fixture, never actual solver evidence.
use crate::archive::ArchiveLimits;
use crate::bake::{
    BakeCompletion, BakeObservation, BakeVerificationInput, BakeVerifierPort, MeshObservation,
};
use crate::manifest::{exchange_inspect, exchange_prepare};
use crate::patch::{DeltaKind, DeltaPolicy, SceneEdit, diff_scene_edits, scene_diff};
use crate::resources::{
    AuthorizedBytes, Redistribution, ResourcePort, ResourcePurpose, content_resource,
};
use crate::selection::{ObjectNode, Selection};
use crate::*;
use mmmm_contracts::{canonical_digest, parse_json, projected_digest, raw_digest};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

struct FixtureResources {
    bytes: BTreeMap<String, Vec<u8>>,
    rights: Redistribution,
    denied: bool,
}
impl Default for FixtureResources {
    fn default() -> Self {
        Self {
            bytes: BTreeMap::new(),
            rights: Redistribution::Allowed,
            denied: false,
        }
    }
}
impl FixtureResources {
    fn insert(&mut self, resource: &Value, bytes: Vec<u8>) {
        self.bytes
            .insert(resource["sha256"].as_str().unwrap().to_owned(), bytes);
    }
    fn add(&mut self, prefix: &str, media: &str, bytes: Vec<u8>) -> Value {
        let resource = content_resource(prefix, media, &bytes);
        self.insert(&resource, bytes);
        resource
    }
}
impl ResourcePort for FixtureResources {
    fn authorize_selection(&mut self, _context: &str, _selection: &Value) -> ExchangeResult<()> {
        if self.denied {
            Err(ExchangeError::new(
                "PERMISSION_REQUIRED",
                "Fixture selection grant is revoked",
            ))
        } else {
            Ok(())
        }
    }
    fn read(
        &mut self,
        _context: &str,
        resource: &Value,
        _purpose: ResourcePurpose,
        max: u64,
    ) -> ExchangeResult<AuthorizedBytes> {
        if self.denied {
            return Err(ExchangeError::new(
                "PERMISSION_REQUIRED",
                "Fixture read grant is revoked",
            ));
        }
        let bytes = self
            .bytes
            .get(resource["sha256"].as_str().unwrap())
            .ok_or_else(|| {
                ExchangeError::new("REFERENCE_UNRESOLVED", "Fixture CAS resource is absent")
            })?
            .clone();
        if bytes.len() as u64 > max {
            return Err(ExchangeError::new(
                "BUDGET_EXCEEDED",
                "Fixture read exceeds its exact budget",
            ));
        }
        Ok(AuthorizedBytes {
            bytes,
            redistribution: self.rights,
        })
    }
    fn embedded_rights(
        &mut self,
        _context: &str,
        _resource: &Value,
    ) -> ExchangeResult<Redistribution> {
        Ok(self.rights)
    }
}

fn selection() -> Value {
    parse_json(include_bytes!("../../../examples/scene-selection.json")).unwrap()
}
fn physics() -> Value {
    parse_json(include_bytes!("../../../examples/physics-definition.json")).unwrap()
}
fn originals() -> FixtureResources {
    let mut resources = FixtureResources::default();
    for bytes in [
        include_bytes!("../../../examples/source-map.json").as_slice(),
        include_bytes!("../../../examples/blockset.json").as_slice(),
        include_bytes!("../../../examples/physics-definition.json").as_slice(),
    ] {
        resources
            .bytes
            .insert(raw_digest(bytes).to_string(), bytes.to_vec());
    }
    resources
}
fn prepare(resources: &mut FixtureResources) -> manifest::PreparedBundle {
    exchange_prepare(&json!({"contextId":"context-fixture","selection":selection(),"dataSnapshotId":"snapshot-fixture","coordinates":physics()["coordinates"],"physics":physics()}),"bundle-test",resources,ArchiveLimits::default()).unwrap()
}

struct FixtureObserver {
    completion: BakeCompletion,
    verified: bool,
    wrong_topology: bool,
}
impl BakeVerifierPort for FixtureObserver {
    fn observe(&mut self, input: BakeVerificationInput<'_>) -> ExchangeResult<BakeObservation> {
        let mut topologies = BTreeMap::new();
        for sample in input.artifact["surfaceSamples"].as_array().unwrap() {
            topologies.insert(
                serde_json::from_value(sample["mesh"]["sha256"].clone()).unwrap(),
                MeshObservation {
                    topology_digest: if self.wrong_topology {
                        raw_digest(b"different stable vertex ordering")
                    } else {
                        serde_json::from_value(sample["topologyDigest"].clone()).unwrap()
                    },
                    vertex_count: 3,
                    triangle_count: 1,
                },
            );
        }
        let mut poses = BTreeMap::new();
        for clip in input.artifact["clips"].as_array().unwrap() {
            for track in clip["tracks"].as_array().unwrap() {
                poses.insert(
                    (
                        clip["clipId"].as_str().unwrap().to_owned(),
                        track["nodeId"].as_str().unwrap().to_owned(),
                    ),
                    bake::times(&input.request["sampling"]["sampleTimes"]).unwrap(),
                );
            }
        }
        Ok(BakeObservation {
            completion: self.completion,
            artifact_digest: serde_json::from_value(input.artifact_resource["sha256"].clone())
                .unwrap(),
            input_digest: serde_json::from_value(input.artifact["inputDigest"].clone()).unwrap(),
            implementation_digest: serde_json::from_value(
                input.artifact["tool"]["implementationDigest"].clone(),
            )
            .unwrap(),
            provider_id: input.artifact["tool"]["providerId"]
                .as_str()
                .unwrap()
                .to_owned(),
            tool_version: input.artifact["tool"]["version"]
                .as_str()
                .unwrap()
                .to_owned(),
            solver_settings_digest: serde_json::from_value(
                input.artifact["solverSettings"]["sha256"].clone(),
            )
            .unwrap(),
            sampling_digest: canonical_digest(&input.request["sampling"]).unwrap(),
            evaluated_scene_verified: self.verified,
            initial_final_verified: self.verified,
            intermediate_pose_verified: self.verified,
            part_sample_times: poses,
            mesh_topologies: topologies,
            verified_identity_maps: BTreeSet::new(),
            measured_cost: None,
        })
    }
}
fn ingest_input(resources: &mut FixtureResources) -> Value {
    let bundle = prepare(resources);
    let zip = bundle.zip_bytes(ArchiveLimits::default()).unwrap();
    let source = resources.add("source", "application/vnd.mmmm.exchange+zip", zip);
    let mut request = parse_json(include_bytes!("../../../examples/bake-request.json")).unwrap();
    request["sourceBundle"] = source;
    let mut artifact = parse_json(include_bytes!("../../../examples/bake-artifact.json")).unwrap();
    artifact["inputDigest"] = json!(projected_digest("BakeRequest", &request).unwrap());
    let resource = resources.add("bake", "application/json", json_bytes(&artifact).unwrap());
    json!({"contextId":"context-fixture","request":request,"artifactResource":resource})
}
fn artifact_from(input: &Value, resources: &FixtureResources) -> Value {
    parse_json(&resources.bytes[input["artifactResource"]["sha256"].as_str().unwrap()]).unwrap()
}
fn store_artifact(input: &mut Value, artifact: &Value, resources: &mut FixtureResources) {
    input["artifactResource"] =
        resources.add("bake", "application/json", json_bytes(artifact).unwrap());
}
fn observer() -> FixtureObserver {
    FixtureObserver {
        completion: BakeCompletion::Completed,
        verified: false,
        wrong_topology: false,
    }
}
fn door() -> ObjectNode {
    ObjectNode {
        instance_id: "instance-shop-a".into(),
        node_id: "door".into(),
    }
}
fn policy() -> DeltaPolicy {
    let mut policy = DeltaPolicy::default();
    for kind in [
        DeltaKind::UpdateTransform,
        DeltaKind::UpdateDisplay,
        DeltaKind::AttachClip,
        DeltaKind::DeleteNode,
    ] {
        policy.allow(door(), kind).unwrap();
    }
    policy
}

#[test]
fn prepared_neutral_zip_roundtrip_is_deterministic_and_preserves_originals() {
    let source = selection();
    let mut resources = originals();
    let first = prepare(&mut resources);
    let second = prepare(&mut resources);
    let bytes = first.zip_bytes(ArchiveLimits::default()).unwrap();
    assert_eq!(bytes, second.zip_bytes(ArchiveLimits::default()).unwrap());
    let resource = resources.add("bundle", "application/zip", bytes);
    let inspected = exchange_inspect(
        &json!({"contextId":"context-fixture","resource":resource}),
        &mut resources,
        ArchiveLimits::default(),
    )
    .unwrap();
    assert_eq!(inspected.bundle().manifest(), first.manifest());
    assert_eq!(inspected.selection().value(), &source);
    assert_eq!(selection(), source);
}

fn z_up_coordinates() -> Value {
    let mut value = physics()["coordinates"].clone();
    value["basisToMinecraftRowMajor"] = json!([1, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0, 0, 0, 0, 0, 1]);
    value["distanceUnit"] = json!("meters");
    value["metersPerBlock"] = json!(0.5);
    value
}

#[test]
fn external_working_selection_is_rederived_from_preserved_raw_canonical_source() {
    let mut resources = originals();
    let coordinates = z_up_coordinates();
    let request = json!({"contextId":"context-fixture","selection":selection(),"dataSnapshotId":"snapshot-fixture","coordinates":coordinates});
    let raw = include_bytes!("../../../examples/scene-selection.json");
    let bundle = manifest::exchange_prepare_with_canonical_bytes(
        &request,
        "bundle-normalized",
        Some(raw),
        &mut resources,
        ArchiveLimits::default(),
    )
    .unwrap();
    assert_eq!(
        bundle
            .payload(normalization::SOURCE_SELECTION_PATH)
            .unwrap(),
        raw
    );
    let query = json!({"contextId":"context-fixture","resource":resources.add("bundle","application/zip",bundle.zip_bytes(ArchiveLimits::default()).unwrap())});
    let inspected = exchange_inspect(&query, &mut resources, ArchiveLimits::default()).unwrap();
    assert_eq!(inspected.selection().value(), &selection());
    assert_eq!(
        inspected.working_selection().node(&door()).unwrap()["transform"]["translation"],
        json!([1.5, 0.0, 0.5])
    );
    assert_ne!(
        inspected.working_selection().value()["prefabs"][0]["revision"],
        selection()["prefabs"][0]["revision"]
    );
    assert_eq!(
        inspected.working_selection().value()["instances"][0]["prefabRevision"],
        inspected.working_selection().value()["prefabs"][0]["revision"]
    );
    let mut members = bundle.members().clone();
    let mut altered = parse_json(&members[normalization::WORKING_SELECTION_PATH]).unwrap();
    altered["prefabs"][0]["nodes"][3]["transform"]["translation"][0] = json!(9.0);
    altered["prefabs"][0]["revision"] =
        json!(projected_digest("Prefab", &altered["prefabs"][0]).unwrap());
    altered["instances"][0]["prefabRevision"] = altered["prefabs"][0]["revision"].clone();
    altered["instances"][0]["revision"] =
        json!(projected_digest("Instance", &altered["instances"][0]).unwrap());
    let changed_bytes = json_bytes(&altered).unwrap();
    members.insert(
        normalization::WORKING_SELECTION_PATH.into(),
        changed_bytes.clone(),
    );
    let mut manifest = bundle.manifest().clone();
    let payload = manifest["payloads"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|payload| payload["kind"] == "selection")
        .unwrap();
    payload["resource"]["sha256"] = json!(raw_digest(&changed_bytes));
    payload["resource"]["sizeBytes"] = json!(changed_bytes.len());
    manifest["bundleRevision"] =
        json!(projected_digest("SceneExchangeManifest", &manifest).unwrap());
    members.insert("mmmm-exchange.json".into(), json_bytes(&manifest).unwrap());
    let query = json!({"contextId":"context-fixture","resource":resources.add("bundle","application/zip",archive::write_zip(&members,ArchiveLimits::default()).unwrap())});
    assert_eq!(
        exchange_inspect(&query, &mut resources, ArchiveLimits::default())
            .err()
            .unwrap()
            .code,
        "INPUT_DIGEST_MISMATCH"
    );
}

#[test]
fn source_instance_overrides_share_domain_display_reference_and_scope_validation() {
    for display in [
        json!({"kind":"text","payload":{},"resourceRefs":[]}),
        json!({"kind":"text","payload":{"text":"label"},"textRole":"label","resourceRefs":["missing-resource"]}),
    ] {
        let mut source = selection();
        source["instances"][0]["overrides"] =
            json!([{"kind":"display","nodeId":"door","display":display}]);
        source["instances"][0]["revision"] =
            json!(projected_digest("Instance", &source["instances"][0]).unwrap());
        assert_eq!(
            Selection::from_value(&source).unwrap_err().code,
            "SCHEMA_INVALID"
        );
    }
    let mut source = selection();
    source["prefabs"][0]["references"][0] =
        json!({"symbolId":"open_fn","kind":"node","scope":"local","targetId":"door"});
    source["prefabs"][0]["revision"] =
        json!(projected_digest("Prefab", &source["prefabs"][0]).unwrap());
    source["instances"][0]["prefabRevision"] = source["prefabs"][0]["revision"].clone();
    source["instances"][0]["overrides"] =
        json!([{"kind":"reference","symbolId":"open_fn","targetId":"missing-node"}]);
    source["instances"][0]["revision"] =
        json!(projected_digest("Instance", &source["instances"][0]).unwrap());
    assert_eq!(
        Selection::from_value(&source).unwrap_err().code,
        "REFERENCE_UNRESOLVED"
    );
}

#[test]
fn external_bake_ingestion_diff_and_plan_consume_separate_canonical_clip_variant() {
    let mut resources = originals();
    let coordinates = z_up_coordinates();
    let mut authored_physics = physics();
    authored_physics["coordinates"]["metersPerBlock"] = json!(0.5);
    authored_physics["revision"] =
        json!(projected_digest("PhysicsDefinition", &authored_physics).unwrap());
    let build = json!({"contextId":"context-fixture","selection":selection(),"dataSnapshotId":"snapshot-fixture","coordinates":coordinates,"physics":authored_physics});
    let bundle = exchange_prepare(
        &build,
        "bundle-normalized",
        &mut resources,
        ArchiveLimits::default(),
    )
    .unwrap();
    let mut request = parse_json(include_bytes!("../../../examples/bake-request.json")).unwrap();
    request["sourceBundle"] = resources.add(
        "source",
        "application/zip",
        bundle.zip_bytes(ArchiveLimits::default()).unwrap(),
    );
    let physics_payload = bundle.manifest()["payloads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|payload| payload["kind"] == "physics")
        .unwrap();
    let normalized_physics = parse_json(
        bundle
            .payload(physics_payload["path"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    request["physicsRevision"] = normalized_physics["revision"].clone();
    let mut artifact = parse_json(include_bytes!("../../../examples/bake-artifact.json")).unwrap();
    artifact["coordinates"] = coordinates.clone();
    artifact["inputDigest"] = json!(projected_digest("BakeRequest", &request).unwrap());
    let external = coordinates::CoordinateSystem::from_value(&coordinates).unwrap();
    // Producer float lexemes and source manifest integer lexemes are exact
    // semantic pins even though their preserved raw JSON bytes differ.
    artifact["coordinates"] = external.to_value().unwrap();
    let canonical = normalization::minecraft_coordinates(&external).unwrap();
    for clip in artifact["clips"].as_array_mut().unwrap() {
        for track in clip["tracks"].as_array_mut().unwrap() {
            for key in track["keys"].as_array_mut().unwrap() {
                key["transform"] =
                    normalization::transform_between(&key["transform"], &canonical, &external)
                        .unwrap();
            }
        }
        clip["revision"] = json!(projected_digest("AnimationClip", clip).unwrap());
    }
    let raw = json_bytes(&artifact).unwrap();
    let reference = resources.add("bake", "application/json", raw.clone());
    let input =
        json!({"contextId":"context-fixture","request":request,"artifactResource":reference});
    let ingested = bake::bake_ingest(
        &input,
        &mut resources,
        &mut observer(),
        ArchiveLimits::default(),
    )
    .unwrap();
    assert_eq!(ingested.original_bytes(), raw);
    assert_eq!(ingested.artifact(), &artifact);
    let clip = &ingested.canonical_clips()[0];
    assert_ne!(clip["clipId"], artifact["clips"][0]["clipId"]);
    assert_eq!(
        clip["tracks"][0]["keys"][0]["transform"]["translation"],
        json!([3.0, 1.0, 0.0])
    );
    for field in ["duration", "loop", "timeDomain", "sampling", "events"] {
        assert_eq!(clip[field], artifact["clips"][0][field]);
    }
    for (derived, bytes) in ingested.canonical_clip_resources().unwrap() {
        assert_eq!(derived["sha256"], json!(raw_digest(&bytes)));
        assert_ne!(derived["sha256"], reference["sha256"]);
    }
    let map = json!({"contractVersion":"0.2.0","generatorVersion":"component-fixture","inputRevision":selection()["projectRevision"],"entries":[{"sourceObjectId":"instance-shop-a","sourceNodeId":"door","outputResourceId":reference["resourceId"],"locator":"/clips/0/tracks/0"}]});
    let map_resource = resources.add("source-map", "application/json", json_bytes(&map).unwrap());
    let import = json!({"contextId":"context-fixture","artifact":artifact,"selection":selection(),"sourceMap":map_resource});
    let patch = scene_diff(
        &import,
        &ingested,
        "patch-normalized",
        &policy(),
        &mut resources,
        ArchiveLimits::default(),
    )
    .unwrap();
    assert_eq!(patch["sourceArtifact"], reference);
    assert_eq!(patch["entries"][0]["clipId"], clip["clipId"]);
    let translated = planning::scene_plan_request(
        &json!({"contextId":"context-fixture","patch":patch}),
        &Selection::from_value(&selection()).unwrap(),
        &policy(),
    )
    .unwrap();
    assert_eq!(
        translated["intent"]["patch"]["entries"][0]["clipId"],
        clip["clipId"]
    );
    assert_ne!(ingested.normalization_digest().unwrap(), raw_digest(&raw));
    let mut changed_coordinates = ingested.artifact().clone();
    changed_coordinates["coordinates"]["metersPerBlock"] = json!(0.25);
    let mut mismatched = input.clone();
    store_artifact(&mut mismatched, &changed_coordinates, &mut resources);
    assert_eq!(
        bake::bake_ingest(
            &mismatched,
            &mut resources,
            &mut observer(),
            ArchiveLimits::default()
        )
        .err()
        .unwrap()
        .code,
        "UNIT_MISMATCH"
    );
}

#[test]
fn manifest_raw_hash_rights_and_live_authority_are_separate_gates() {
    let mut resources = originals();
    let prepared = prepare(&mut resources);
    let mut members = prepared.members().clone();
    members
        .get_mut("objects/selection.json")
        .unwrap()
        .push(b' ');
    let corrupt = archive::write_zip(&members, ArchiveLimits::default()).unwrap();
    let resource = resources.add("bundle", "application/zip", corrupt);
    let query = json!({"contextId":"context-fixture","resource":resource});
    assert_eq!(
        exchange_inspect(&query, &mut resources, ArchiveLimits::default())
            .err()
            .unwrap()
            .code,
        "BUDGET_EXCEEDED"
    );
    let resource = resources.add(
        "bundle",
        "application/zip",
        prepared.zip_bytes(ArchiveLimits::default()).unwrap(),
    );
    let query = json!({"contextId":"context-fixture","resource":resource});
    resources.rights = Redistribution::Unknown;
    assert_eq!(
        exchange_inspect(&query, &mut resources, ArchiveLimits::default())
            .err()
            .unwrap()
            .code,
        "RESOURCE_FORBIDDEN"
    );
    resources.rights = Redistribution::Allowed;
    resources.denied = true;
    assert_eq!(
        exchange_inspect(&query, &mut resources, ArchiveLimits::default())
            .err()
            .unwrap()
            .code,
        "PERMISSION_REQUIRED"
    );
}

#[test]
fn detached_json_manifest_uses_the_same_exact_payload_semantics() {
    let mut resources = originals();
    let prepared = prepare(&mut resources);
    for payload in prepared.manifest()["payloads"].as_array().unwrap() {
        if let Some(bytes) = prepared.payload(payload["path"].as_str().unwrap()) {
            resources.insert(&payload["resource"], bytes.to_vec());
        }
    }
    let root = prepared.payload("mmmm-exchange.json").unwrap().to_vec();
    let reference = resources.add("manifest", "application/json", root);
    let inspected = exchange_inspect(
        &json!({"contextId":"context-fixture","resource":reference}),
        &mut resources,
        ArchiveLimits::default(),
    )
    .unwrap();
    assert_eq!(inspected.bundle().manifest(), prepared.manifest());
}

#[test]
fn reference_only_assets_are_not_embedded_and_names_are_not_object_ids() {
    let mut resources = originals();
    resources.rights = Redistribution::ReferenceOnly;
    let prepared = prepare(&mut resources);
    assert_eq!(prepared.members().len(), 3);
    for payload in prepared.manifest()["payloads"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["kind"] == "asset" || p["kind"] == "source_map")
    {
        assert_eq!(payload["redistribution"], "reference_only");
        assert!(
            prepared
                .payload(payload["path"].as_str().unwrap())
                .is_none()
        );
    }
    assert_eq!(
        prepared.manifest()["objectMap"][0]["externalId"],
        "instance-shop-a/door"
    );
}

#[test]
fn accepted_partial_bake_is_not_a_completed_manifest() {
    let mut resources = originals();
    let input = ingest_input(&mut resources);
    let mut proof = observer();
    proof.completion = BakeCompletion::JobAccepted;
    assert_eq!(
        bake::bake_ingest(&input, &mut resources, &mut proof, ArchiveLimits::default())
            .err()
            .unwrap()
            .code,
        "INCOMPLETE_OUTPUT"
    );
    let ingested = bake::bake_ingest(
        &input,
        &mut resources,
        &mut observer(),
        ArchiveLimits::default(),
    )
    .unwrap();
    assert_eq!(ingested.artifact()["initialFinalVerified"], false);
    assert_eq!(ingested.artifact()["intermediatePoseVerified"], false);
    let mut empty_input = input.clone();
    let mut empty_artifact = artifact_from(&empty_input, &resources);
    empty_artifact["clips"][0]["tracks"] = json!([]);
    empty_artifact["clips"][0]["revision"] =
        json!(projected_digest("AnimationClip", &empty_artifact["clips"][0]).unwrap());
    store_artifact(&mut empty_input, &empty_artifact, &mut resources);
    assert_eq!(
        bake::bake_ingest(
            &empty_input,
            &mut resources,
            &mut observer(),
            ArchiveLimits::default()
        )
        .err()
        .unwrap()
        .code,
        "INCOMPLETE_OUTPUT"
    );
}

#[test]
fn wire_pose_claims_and_request_hash_cannot_replace_independent_evidence() {
    let mut resources = originals();
    let mut input = ingest_input(&mut resources);
    let mut artifact = artifact_from(&input, &resources);
    artifact["initialFinalVerified"] = json!(true);
    store_artifact(&mut input, &artifact, &mut resources);
    assert_eq!(
        bake::bake_ingest(
            &input,
            &mut resources,
            &mut observer(),
            ArchiveLimits::default()
        )
        .err()
        .unwrap()
        .code,
        "INCOMPLETE_OUTPUT"
    );
    artifact["initialFinalVerified"] = json!(false);
    artifact["inputDigest"] = json!("0".repeat(64));
    store_artifact(&mut input, &artifact, &mut resources);
    assert_eq!(
        bake::bake_ingest(
            &input,
            &mut resources,
            &mut observer(),
            ArchiveLimits::default()
        )
        .err()
        .unwrap()
        .code,
        "INPUT_DIGEST_MISMATCH"
    );
}

#[test]
fn scene_diff_uses_verified_artifact_and_qualified_source_map() {
    let mut resources = originals();
    let input = ingest_input(&mut resources);
    let ingested = bake::bake_ingest(
        &input,
        &mut resources,
        &mut observer(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let map = json!({"contractVersion":"0.2.0","generatorVersion":"component-fixture","inputRevision":selection()["projectRevision"],"entries":[{"sourceObjectId":"instance-shop-a","sourceNodeId":"door","outputResourceId":ingested.resource()["resourceId"],"locator":"/clips/0/tracks/0"}]});
    let source_map = resources.add("source-map", "application/json", json_bytes(&map).unwrap());
    let request = json!({"contextId":"context-fixture","artifact":ingested.artifact(),"selection":selection(),"sourceMap":source_map});
    let patch = scene_diff(
        &request,
        &ingested,
        "patch-test",
        &policy(),
        &mut resources,
        ArchiveLimits::default(),
    )
    .unwrap();
    assert_eq!(
        patch["entries"][0],
        json!({"kind":"attach_clip","instanceId":"instance-shop-a","nodeId":"door","clipId":"clip-door"})
    );
    assert_eq!(patch["absenceMeansDeletion"], false);
    let mut stale = request;
    stale["selection"]["projectRevision"] = json!("a".repeat(64));
    assert_eq!(
        scene_diff(
            &stale,
            &ingested,
            "patch-test",
            &policy(),
            &mut resources,
            ArchiveLimits::default()
        )
        .unwrap_err()
        .code,
        "REVISION_CONFLICT"
    );
}

#[test]
fn omitted_fields_stay_unchanged_and_deletion_requires_a_typed_delta() {
    let base = Selection::from_value(&selection()).unwrap();
    let reference = &selection()["sourceMap"];
    let patch = diff_scene_edits(
        &base,
        &[SceneEdit::Existing {
            target: door(),
            transform: None,
            display: None,
        }],
        reference,
        reference,
        &[],
        "patch-test",
        &DeltaPolicy::default(),
    )
    .unwrap();
    assert_eq!(patch["entries"], json!([]));
    for invalid_display in [
        json!({"kind":"text","payload":{},"resourceRefs":[]}),
        json!({"kind":"text","payload":{"text":"label"},"textRole":"label","resourceRefs":["missing-resource"]}),
    ] {
        assert_eq!(
            diff_scene_edits(
                &base,
                &[SceneEdit::Existing {
                    target: door(),
                    transform: None,
                    display: Some(invalid_display)
                }],
                reference,
                reference,
                &[],
                "patch-test",
                &policy()
            )
            .unwrap_err()
            .code,
            "REFERENCE_UNRESOLVED"
        );
    }
    let patch = diff_scene_edits(
        &base,
        &[SceneEdit::Delete { target: door() }],
        reference,
        reference,
        &[],
        "patch-test",
        &policy(),
    )
    .unwrap();
    assert_eq!(patch["entries"][0]["kind"], "delete_node");
    assert_eq!(
        diff_scene_edits(
            &base,
            &[SceneEdit::Delete { target: door() }],
            reference,
            reference,
            &[],
            "patch-test",
            &DeltaPolicy::default()
        )
        .unwrap_err()
        .code,
        "PERMISSION_REQUIRED"
    );
    let mut changed = base.node(&door()).unwrap()["transform"].clone();
    changed["translation"] = json!([3, 2, 0]);
    let mixed = [
        SceneEdit::Existing {
            target: door(),
            transform: Some(changed),
            display: None,
        },
        SceneEdit::Delete { target: door() },
    ];
    assert_eq!(
        diff_scene_edits(
            &base,
            &mixed,
            reference,
            reference,
            &[],
            "patch-test",
            &policy()
        )
        .unwrap_err()
        .code,
        "OBJECT_MAPPING_AMBIGUOUS"
    );
}

#[test]
fn scene_plan_translates_into_the_common_application_contract() {
    let base = Selection::from_value(&selection()).unwrap();
    let reference = &selection()["sourceMap"];
    let patch = diff_scene_edits(
        &base,
        &[SceneEdit::Delete { target: door() }],
        reference,
        reference,
        &[],
        "patch-test",
        &policy(),
    )
    .unwrap();
    let request = json!({"contextId":"context-fixture","patch":patch});
    let translated = planning::scene_plan_request(&request, &base, &policy()).unwrap();
    assert_eq!(translated["intent"]["kind"], "scene.import_patch");
    assert_eq!(
        translated["expectedRevision"],
        base.value()["projectRevision"]
    );
    assert!(translated.get("endpoint").is_none());
}

#[test]
fn raw_affine_shear_requires_a_declared_affine_interpolation_path() {
    let mut request = parse_json(include_bytes!("../../../examples/bake-request.json")).unwrap();
    request["representation"] = json!("affine_part_tracks");
    let mut artifact = parse_json(include_bytes!("../../../examples/bake-artifact.json")).unwrap();
    artifact["representation"] = request["representation"].clone();
    artifact["inputDigest"] = json!(projected_digest("BakeRequest", &request).unwrap());
    let clip = &mut artifact["clips"][0];
    clip["representation"] = request["representation"].clone();
    clip["tracks"][0]["keys"][0]["transform"] = json!({"kind":"matrix","layout":"row_major_column_vector","values":[1,0.25,0,3,0,1,0,1,0,0,1,0,0,0,0,1]});
    clip["revision"] = json!(projected_digest("AnimationClip", clip).unwrap());
    let base = Selection::from_value(&selection()).unwrap();
    assert_eq!(
        bake::validate_artifact(&artifact, &request, &base)
            .unwrap_err()
            .code,
        "LOSS_APPROVAL_REQUIRED"
    );
    artifact["clips"][0]["tracks"][0]["interpolation"] = json!("step");
    artifact["clips"][0]["revision"] =
        json!(projected_digest("AnimationClip", &artifact["clips"][0]).unwrap());
    bake::validate_artifact(&artifact, &request, &base).unwrap();
}

#[test]
fn equal_triangle_counts_do_not_verify_surface_identity() {
    let mut resources = originals();
    let mut input = ingest_input(&mut resources);
    let mut artifact = artifact_from(&input, &resources);
    input["request"]["representation"] = json!("triangulated_surface_samples");
    artifact["representation"] = input["request"]["representation"].clone();
    artifact["inputDigest"] = json!(projected_digest("BakeRequest", &input["request"]).unwrap());
    artifact["clips"] = json!([]);
    artifact["topologyPolicy"] = json!("stable_verified");
    artifact["topologyDigest"] = json!(raw_digest(b"stable identity ordering A"));
    let mesh = resources.add(
        "mesh",
        "application/x-component-fixture",
        b"fixture mesh codec bytes".to_vec(),
    );
    artifact["surfaceSamples"]=json!(input["request"]["sampling"]["sampleTimes"].as_array().unwrap().iter().map(|at|json!({"at":at,"mesh":mesh,"topologyDigest":artifact["topologyDigest"],"vertexCount":3,"triangleCount":1,"identityMap":null})).collect::<Vec<_>>());
    store_artifact(&mut input, &artifact, &mut resources);
    let mut proof = observer();
    proof.wrong_topology = true;
    assert_eq!(
        bake::bake_ingest(&input, &mut resources, &mut proof, ArchiveLimits::default())
            .err()
            .unwrap()
            .code,
        "TOPOLOGY_CHANGED"
    );
    artifact["cost"]["samples"] = json!(0);
    store_artifact(&mut input, &artifact, &mut resources);
    assert_eq!(
        bake::bake_ingest(
            &input,
            &mut resources,
            &mut observer(),
            ArchiveLimits::default()
        )
        .err()
        .unwrap()
        .code,
        "BUDGET_EXCEEDED"
    );
}

#[test]
fn missing_final_pose_and_multiple_roots_are_rejected() {
    let request = parse_json(include_bytes!("../../../examples/bake-request.json")).unwrap();
    let mut artifact = parse_json(include_bytes!("../../../examples/bake-artifact.json")).unwrap();
    artifact["clips"][0]["tracks"][0]["keys"]
        .as_array_mut()
        .unwrap()
        .pop();
    artifact["clips"][0]["revision"] =
        json!(projected_digest("AnimationClip", &artifact["clips"][0]).unwrap());
    let base = Selection::from_value(&selection()).unwrap();
    assert_eq!(
        bake::validate_artifact(&artifact, &request, &base)
            .unwrap_err()
            .code,
        "INCOMPLETE_OUTPUT"
    );
    let mut node = base.node(&door()).unwrap().clone();
    node["nodeId"] = json!("second-root");
    node["parentId"] = Value::Null;
    let target = ObjectNode {
        instance_id: "instance-shop-a".into(),
        node_id: "second-root".into(),
    };
    let mut allowed = DeltaPolicy::default();
    allowed
        .allow(target.clone(), DeltaKind::CreateNode)
        .unwrap();
    let reference = &selection()["sourceMap"];
    assert_eq!(
        diff_scene_edits(
            &base,
            &[SceneEdit::Create { target, node }],
            reference,
            reference,
            &[],
            "patch-test",
            &allowed
        )
        .unwrap_err()
        .code,
        "REFERENCE_UNRESOLVED"
    );
}

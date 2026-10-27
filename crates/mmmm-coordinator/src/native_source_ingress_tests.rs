//! Real protected Store and native owner bootstrap; no synthetic owner witness,
//! session, target/profile approval, runtime state or source-rights constructor.
//! Preparation success is deliberately separate from source publication; the
//! publication cases use the actual atomic runtime API and checked readers.

use super::*;
use crate::{
    host::HostBridge, native_project::create_native_project, workspace_bootstrap::prepare_workspace,
};
use mmmm_contracts::{TargetProfileId, parse_json};
use mmmm_runtime::storage::{StoreConfig, artifact::register_resource};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const MARKER: &[u8] = b"mmmm-native-source-ingress-fixture-v1\n";
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let parent = fs::canonicalize(parent).unwrap();
        let path = parent.join(format!(
            "mmmm-native-source-ingress-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let checkout =
            fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        assert!(path.is_absolute() && !path.exists() && !path.starts_with(&checkout));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = fs::canonicalize(path).unwrap();
        assert_eq!(path.parent(), Some(parent.as_path()));
        fs::write(path.join("fixture-owner.txt"), MARKER).unwrap();
        Self(path)
    }
    fn open(&self) -> DurableStore {
        DurableStore::open(StoreConfig::new(self.0.clone())).unwrap()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let mut entries = 0;
        if fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0)
            && fs::read(self.0.join("fixture-owner.txt")).ok().as_deref() == Some(MARKER)
            && plain_tree(&self.0, &self.0, 0, &mut entries)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
fn plain_tree(path: &Path, root: &Path, depth: usize, entries: &mut usize) -> bool {
    if !path.starts_with(root) || depth > 16 || *entries >= 1024 {
        return false;
    }
    *entries += 1;
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
        let Ok(children) = fs::read_dir(path) else {
            return false;
        };
        for child in children {
            let Ok(child) = child else {
                return false;
            };
            if !plain_tree(&child.path(), root, depth + 1, entries) {
                return false;
            }
        }
    }
    metadata.is_file() || metadata.is_dir()
}

struct Fixture {
    // Declaration order closes the actual Store before owned-root cleanup.
    store: DurableStore,
    _root: Root,
    authority: LocalAuthority,
    owner: NativeOwnerWitness,
    project: ProjectId,
    revision: Sha256Digest,
    budget: RequestBudget,
    cancelled: Arc<AtomicBool>,
}
impl Fixture {
    fn new() -> Self {
        let root = Root::new();
        let mut store = root.open();
        let deadline = Instant::now() + Duration::from_secs(30);
        let receipt = create_native_project(
            &mut store,
            "Native authored source fixture",
            &TargetProfileId::new("target-unverified").unwrap(),
            deadline,
        )
        .unwrap();
        let authority = LocalAuthority::new(HostBridge::default());
        let workspace =
            prepare_workspace(&store, &authority, &receipt.project_id, deadline).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let budget = RequestBudget::until(deadline, cancelled.clone()).unwrap();
        Self {
            store,
            _root: root,
            authority,
            owner: workspace.witness,
            project: receipt.project_id,
            revision: receipt.project_revision,
            budget,
            cancelled,
        }
    }
    fn prepare(
        &self,
        documents: &[NativeSourceDocument<'_>],
        resources: &[&[u8]],
    ) -> AppResult<PreparedNativeSources> {
        self.prepare_raw(documents, resources, &[])
    }
    fn prepare_raw(
        &self,
        documents: &[NativeSourceDocument<'_>],
        resources: &[&[u8]],
        raw_resources: &[NativeRawSourceResource<'_>],
    ) -> AppResult<PreparedNativeSources> {
        prepare_native_sources(
            &self.store,
            &self.owner,
            &self.authority,
            &self.budget,
            &NativeSourceInput {
                project: &self.project,
                expected_revision: &self.revision,
                documents,
                retained_resources: resources,
                raw_resources,
            },
        )
    }
}
fn prefab() -> Value {
    // Reuse the original root Node rather than inventing geometry/runtime data.
    let original = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
    let mut value = json!({
        "contractVersion":mmmm_contracts::CONTRACT_VERSION,"prefabId":"prefab-local-source",
        "revision":"0".repeat(64),"name":"Local authored source",
        "nodes":[original["nodes"][0].clone()],"ports":[],"state":[],"references":[],
        "commandModuleIds":[],"clipIds":[],"resources":[]
    });
    value["revision"] = json!(projected_digest("Prefab", &value).unwrap());
    value
}
fn instance(prefab: &Value) -> Value {
    // The real pure-domain function creates a planned authored draft. Its world
    // and dimension remain locators and establish no game/target authority.
    mmmm_domain::instantiate(&json!({
        "prefab":prefab,"instanceId":"instance-local-source","worldId":"world-unverified",
        "dimension":"minecraft:overworld","placement":prefab["nodes"][0]["transform"],"statePolicy":"defaults"
    })).unwrap()["instance"].clone()
}
fn clip_owner() -> (Value, Value) {
    // The original authored clip supplies the canonical time/sampling shape.
    // Reuse the actual owner root Node; no display, bake or target proof is
    // fabricated for this source storage fixture.
    let mut owner = prefab();
    let mut clip = parse_json(include_bytes!("../../../examples/animation-clip.json")).unwrap();
    clip["clipId"] = json!("clip-native-source");
    clip["ownerPrefabId"] = owner["prefabId"].clone();
    clip["tracks"][0]["nodeId"] = owner["nodes"][0]["nodeId"].clone();
    for key in clip["tracks"][0]["keys"].as_array_mut().unwrap() {
        key["transform"] = owner["nodes"][0]["transform"].clone();
    }
    clip["revision"] = json!(projected_digest("AnimationClip", &clip).unwrap());
    owner["clipIds"] = json!([clip["clipId"]]);
    owner["revision"] = json!(projected_digest("Prefab", &owner).unwrap());
    (owner, clip)
}

fn command_owner() -> (Value, Value) {
    // Keep the original authored documents and remove only unrelated optional
    // resource and clip dependencies from the Prefab.
    let mut owner = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
    let module = parse_json(include_bytes!("../../../examples/command-module.json")).unwrap();
    owner["clipIds"] = json!([]);
    owner["resources"] = json!([]);
    for node in owner["nodes"].as_array_mut().unwrap() {
        node.as_object_mut().unwrap().remove("blockGeometry");
    }
    owner["revision"] = json!(projected_digest("Prefab", &owner).unwrap());
    (owner, module)
}

fn physics_prefab() -> (Value, Value) {
    // The original Prefab has no physics binding. Derive one from its root
    // Node and the original authored PhysicsDefinition's actual first body.
    // Recompute the Prefab revision because the authored content changed.
    let mut owner = prefab();
    let physics = parse_json(include_bytes!("../../../examples/physics-definition.json")).unwrap();
    owner["nodes"][0]["physicsBinding"] = json!({
        "physicsId": physics["physicsId"],
        "bodyId": physics["bodies"][0]["bodyId"]
    });
    owner["revision"] = json!(projected_digest("Prefab", &owner).unwrap());
    (owner, physics)
}

#[test]
fn same_batch_physics_binding_uses_the_real_body_and_preserves_source_bytes() {
    let (owner, physics) = physics_prefab();
    // Instantiate only after the Prefab revision is recalculated, so the
    // generated Instance's prefabRevision names the exact authored source.
    let instance = instance(&owner);
    let owner_bytes = encode_json(&owner).unwrap();
    let instance_bytes = encode_json(&instance).unwrap();
    let physics_bytes = include_bytes!("../../../examples/physics-definition.json");
    for physics_first in [true, false] {
        let mut fixture = Fixture::new();
        let physics_source = || NativeSourceDocument {
            kind: NativeSourceKind::PhysicsDefinition,
            bytes: physics_bytes,
        };
        let prefab_source = || NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &owner_bytes,
        };
        let instance_source = || NativeSourceDocument {
            kind: NativeSourceKind::Instance,
            bytes: &instance_bytes,
        };
        let documents = if physics_first {
            [physics_source(), instance_source(), prefab_source()]
        } else {
            [prefab_source(), instance_source(), physics_source()]
        };
        let receipt = fixture
            .prepare(&documents, &[])
            .unwrap()
            .commit(&mut fixture.store)
            .unwrap();
        let stored = receipt
            .documents
            .iter()
            .find(|(pin, _)| pin.kind == OwnedDocumentKind::PhysicsDefinition)
            .unwrap();
        assert_eq!(
            stored.0.object_id.as_str(),
            physics["physicsId"].as_str().unwrap()
        );
        assert_eq!(
            stored.0.revision.as_str(),
            physics["revision"].as_str().unwrap()
        );
        assert_eq!(
            fixture.store.read_blob(&stored.1).unwrap().as_slice(),
            physics_bytes.as_slice()
        );
        assert_eq!(
            mmmm_runtime::storage::owned_documents::read_owned_document(
                &fixture.store,
                &fixture.project,
                &receipt.project_revision,
                &stored.0,
            )
            .unwrap(),
            physics
        );
        let project = fixture.store.project(&fixture.project).unwrap();
        assert!(
            project["ownedResources"]
                .as_array()
                .unwrap()
                .iter()
                .any(|pin| pin["objectId"] == physics["physicsId"]
                    && pin["revision"] == physics["revision"])
        );
        assert_eq!(project["prefabIds"], json!([owner["prefabId"]]));
        assert_eq!(project["instanceIds"], json!([instance["instanceId"]]));
    }
}

#[test]
fn standalone_physics_can_be_used_from_retained_actual_store_source() {
    let mut fixture = Fixture::new();
    let (owner, physics) = physics_prefab();
    let physics_bytes = include_bytes!("../../../examples/physics-definition.json");
    let first = [NativeSourceDocument {
        kind: NativeSourceKind::PhysicsDefinition,
        bytes: physics_bytes,
    }];
    let first_receipt = fixture
        .prepare(&first, &[])
        .unwrap()
        .commit(&mut fixture.store)
        .unwrap();
    let retained = first_receipt
        .documents
        .iter()
        .find(|(pin, _)| pin.kind == OwnedDocumentKind::PhysicsDefinition)
        .unwrap();
    let authority = LocalAuthority::new(HostBridge::default());
    let workspace = prepare_workspace(
        &fixture.store,
        &authority,
        &fixture.project,
        fixture.budget.deadline(),
    )
    .unwrap();
    let owner_bytes = encode_json(&owner).unwrap();
    let sources = [NativeSourceDocument {
        kind: NativeSourceKind::Prefab,
        bytes: &owner_bytes,
    }];
    let next = prepare_native_sources(
        &fixture.store,
        &workspace.witness,
        &authority,
        &fixture.budget,
        &NativeSourceInput {
            project: &fixture.project,
            expected_revision: &first_receipt.project_revision,
            documents: &sources,
            retained_resources: &[],
            raw_resources: &[],
        },
    )
    .unwrap()
    .commit(&mut fixture.store)
    .unwrap();
    let carried = mmmm_runtime::storage::owned_documents::read_owned_document(
        &fixture.store,
        &fixture.project,
        &next.project_revision,
        &retained.0,
    )
    .unwrap();
    assert_eq!(carried, physics);
    assert_eq!(
        fixture.store.read_blob(&retained.1).unwrap().as_slice(),
        physics_bytes.as_slice()
    );
}

#[test]
fn physics_binding_rejects_missing_definition_and_missing_body_before_publication() {
    let fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let (owner, _) = physics_prefab();
    let owner_bytes = encode_json(&owner).unwrap();
    let missing = [NativeSourceDocument {
        kind: NativeSourceKind::Prefab,
        bytes: &owner_bytes,
    }];
    assert_eq!(
        fixture.prepare(&missing, &[]).err().unwrap().code,
        "SOURCE_UNAVAILABLE"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);

    let mut invalid = owner;
    invalid["nodes"][0]["physicsBinding"]["bodyId"] = json!("body-unavailable");
    invalid["revision"] = json!(projected_digest("Prefab", &invalid).unwrap());
    let invalid_bytes = encode_json(&invalid).unwrap();
    let documents = [
        NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &invalid_bytes,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::PhysicsDefinition,
            bytes: include_bytes!("../../../examples/physics-definition.json"),
        },
    ];
    assert_eq!(
        fixture.prepare(&documents, &[]).err().unwrap().code,
        "REFERENCE_UNRESOLVED"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
}

#[test]
fn schema_valid_physics_with_invalid_graph_is_rejected_before_publication() {
    let fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let (_, mut physics) = physics_prefab();
    let mut wrong_revision = physics.clone();
    wrong_revision["revision"] = json!("0".repeat(64));
    let wrong_bytes = encode_json(&wrong_revision).unwrap();
    let wrong_pin = [NativeSourceDocument {
        kind: NativeSourceKind::PhysicsDefinition,
        bytes: &wrong_bytes,
    }];
    assert_eq!(
        fixture.prepare(&wrong_pin, &[]).err().unwrap().code,
        "INPUT_DIGEST_MISMATCH"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);

    // Keep the original body and collider while breaking their graph relation.
    // This remains a schema-valid PhysicsDefinition, but its dynamic body asks
    // to derive inertia from an empty collider set.
    physics["bodies"][0]["colliderIds"] = json!([]);
    physics["revision"] = json!(projected_digest("PhysicsDefinition", &physics).unwrap());
    let bytes = encode_json(&physics).unwrap();
    let documents = [NativeSourceDocument {
        kind: NativeSourceKind::PhysicsDefinition,
        bytes: &bytes,
    }];
    assert_eq!(
        fixture.prepare(&documents, &[]).err().unwrap().code,
        "INVALID_PHYSICS"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
}

fn mesh_physics(bytes: &[u8]) -> (Value, Value) {
    // The original PhysicsDefinition's collider is a box. Derive a mesh
    // declaration so this test exercises the actual ResourceRef admission
    // boundary; the arbitrary raw bytes and topology digest make no claim
    // about a supported mesh codec, topology, solver, or game execution.
    let (_, mut physics) = physics_prefab();
    let resource = json!({
        "resourceId":"resource-native-physics-mesh",
        "sha256":raw_digest(bytes),
        "mediaType":"application/octet-stream",
        "sizeBytes":bytes.len()
    });
    physics["colliders"][0]["shape"]["shape"] = json!({
        "kind":"mesh", "geometry":resource,
        "topologyDigest":raw_digest(b"authored topology digest only")
    });
    physics["revision"] = json!(projected_digest("PhysicsDefinition", &physics).unwrap());
    (physics, resource)
}

#[test]
fn physics_mesh_raw_admission_and_retained_source_recheck_the_actual_resource() {
    let mut fixture = Fixture::new();
    let bytes = b"authored opaque mesh bytes\n";
    let (physics, resource) = mesh_physics(bytes);
    let physics_bytes = encode_json(&physics).unwrap();
    let metadata = encode_json(&resource).unwrap();
    let source = [NativeSourceDocument {
        kind: NativeSourceKind::PhysicsDefinition,
        bytes: &physics_bytes,
    }];
    let before = fixture.store.project(&fixture.project).unwrap();

    // Neither a declared digest nor unrelated raw bytes authorizes a resource.
    assert!(fixture.prepare(&source, &[]).is_err());
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
    assert_eq!(
        fixture
            .prepare_raw(
                &source,
                &[],
                &[NativeRawSourceResource {
                    metadata: &metadata,
                    bytes: b"different mesh bytes",
                }]
            )
            .err()
            .unwrap()
            .code,
        "INPUT_DIGEST_MISMATCH"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);

    let first = fixture
        .prepare_raw(
            &source,
            &[],
            &[NativeRawSourceResource {
                metadata: &metadata,
                bytes,
            }],
        )
        .unwrap()
        .commit(&mut fixture.store)
        .unwrap();
    let physics_pin = first
        .documents
        .iter()
        .find(|(pin, _)| pin.kind == OwnedDocumentKind::PhysicsDefinition)
        .unwrap();
    assert_eq!(first.resources.len(), 1);
    let resource_blob = &first.resources[0].1;
    assert_eq!(
        fixture.store.read_blob(resource_blob).unwrap().as_slice(),
        bytes.as_slice()
    );
    let authority = LocalAuthority::new(HostBridge::default());
    let workspace = prepare_workspace(
        &fixture.store,
        &authority,
        &fixture.project,
        fixture.budget.deadline(),
    )
    .unwrap();
    let before_next = fixture.store.project(&fixture.project).unwrap();
    let (owner, _) = physics_prefab();
    let owner_bytes = encode_json(&owner).unwrap();
    let owner_source = [NativeSourceDocument {
        kind: NativeSourceKind::Prefab,
        bytes: &owner_bytes,
    }];

    // The retained physics body declares the real registered ResourceRef.
    // Supplying conflicting metadata for that same ID cannot replace it.
    let mut conflicting = resource.clone();
    conflicting["sha256"] = json!(raw_digest(b"different metadata digest"));
    let conflicting_bytes = encode_json(&conflicting).unwrap();
    let mismatch = prepare_native_sources(
        &fixture.store,
        &workspace.witness,
        &authority,
        &fixture.budget,
        &NativeSourceInput {
            project: &fixture.project,
            expected_revision: &first.project_revision,
            documents: &owner_source,
            retained_resources: &[&conflicting_bytes],
            raw_resources: &[],
        },
    );
    assert!(mismatch.is_err());
    assert_eq!(
        fixture.store.project(&fixture.project).unwrap(),
        before_next
    );

    // The required resource is collected from the retained PhysicsDefinition,
    // then resolved by the current Project reader without caller-authored scope.
    let next = prepare_native_sources(
        &fixture.store,
        &workspace.witness,
        &authority,
        &fixture.budget,
        &NativeSourceInput {
            project: &fixture.project,
            expected_revision: &first.project_revision,
            documents: &owner_source,
            retained_resources: &[],
            raw_resources: &[],
        },
    )
    .unwrap()
    .commit(&mut fixture.store)
    .unwrap();
    let carried = mmmm_runtime::storage::owned_documents::read_owned_document(
        &fixture.store,
        &fixture.project,
        &next.project_revision,
        &physics_pin.0,
    )
    .unwrap();
    assert_eq!(carried, physics);
    assert_eq!(
        fixture.store.read_blob(resource_blob).unwrap().as_slice(),
        bytes.as_slice()
    );
    assert!(
        fixture.store.project(&fixture.project).unwrap()["resourceIds"]
            .as_array()
            .unwrap()
            .contains(&resource["resourceId"])
    );
}

#[test]
fn newly_authored_physics_resolves_a_previously_admitted_mesh_resource() {
    let mut fixture = Fixture::new();
    let bytes = b"already admitted opaque mesh bytes\n";
    let (physics, resource) = mesh_physics(bytes);
    let metadata = encode_json(&resource).unwrap();
    let first = fixture
        .prepare_raw(
            &[],
            &[],
            &[NativeRawSourceResource {
                metadata: &metadata,
                bytes,
            }],
        )
        .unwrap()
        .commit(&mut fixture.store)
        .unwrap();
    assert_eq!(first.resources.len(), 1);
    let authority = LocalAuthority::new(HostBridge::default());
    let workspace = prepare_workspace(
        &fixture.store,
        &authority,
        &fixture.project,
        fixture.budget.deadline(),
    )
    .unwrap();
    let physics_bytes = encode_json(&physics).unwrap();
    let source = [NativeSourceDocument {
        kind: NativeSourceKind::PhysicsDefinition,
        bytes: &physics_bytes,
    }];
    let next = prepare_native_sources(
        &fixture.store,
        &workspace.witness,
        &authority,
        &fixture.budget,
        &NativeSourceInput {
            project: &fixture.project,
            expected_revision: &first.project_revision,
            documents: &source,
            retained_resources: &[],
            raw_resources: &[],
        },
    )
    .unwrap()
    .commit(&mut fixture.store)
    .unwrap();
    let stored = next
        .documents
        .iter()
        .find(|(pin, _)| pin.kind == OwnedDocumentKind::PhysicsDefinition)
        .unwrap();
    assert_eq!(
        stored.0.revision.as_str(),
        physics["revision"].as_str().unwrap()
    );
    assert_eq!(
        fixture
            .store
            .read_blob(&first.resources[0].1)
            .unwrap()
            .as_slice(),
        bytes.as_slice()
    );
    assert!(
        fixture.store.project(&fixture.project).unwrap()["resourceIds"]
            .as_array()
            .unwrap()
            .contains(&resource["resourceId"])
    );
}

fn mesh_physics_with_integral_float_size(bytes: &[u8]) -> (Value, Value, Vec<u8>) {
    // Only the authored PhysicsDefinition's mesh ResourceRef uses the
    // schema-permitted N.0 spelling. The independently registered resource
    // metadata remains the original integer N; this fixture does not claim
    // general ResourceRef metadata accepts floating-point number syntax.
    let (mut physics, resource) = mesh_physics(bytes);
    physics["colliders"][0]["shape"]["shape"]["geometry"]["sizeBytes"] = json!(bytes.len() as f64);
    physics["revision"] = json!(projected_digest("PhysicsDefinition", &physics).unwrap());
    // Preserve the authored numeric spelling rather than a canonical encoder
    // that may represent the same mathematical integer as N without `.0`.
    let encoded = serde_json::to_vec(&physics).unwrap();
    let decoded = parse_json(&encoded).unwrap();
    assert!(decoded["colliders"][0]["shape"]["shape"]["geometry"]["sizeBytes"].is_f64());
    assert_eq!(
        decoded["colliders"][0]["shape"]["shape"]["geometry"]["sizeBytes"].as_f64(),
        Some(bytes.len() as f64)
    );
    let expected_spelling = format!("\"sizeBytes\":{}.0", bytes.len());
    assert!(
        encoded
            .windows(expected_spelling.len())
            .any(|window| window == expected_spelling.as_bytes())
    );
    assert!(resource["sizeBytes"].is_u64());
    (physics, resource, encoded)
}

#[test]
fn physics_mesh_integral_float_size_matches_same_batch_integer_resource_metadata() {
    let mut fixture = Fixture::new();
    let bytes = b"float-sized same batch mesh\n";
    let (physics, resource, physics_bytes) = mesh_physics_with_integral_float_size(bytes);
    let metadata = encode_json(&resource).unwrap();
    let documents = [NativeSourceDocument {
        kind: NativeSourceKind::PhysicsDefinition,
        bytes: &physics_bytes,
    }];
    let receipt = fixture
        .prepare_raw(
            &documents,
            &[],
            &[NativeRawSourceResource {
                metadata: &metadata,
                bytes,
            }],
        )
        .unwrap()
        .commit(&mut fixture.store)
        .unwrap();
    let stored = receipt
        .documents
        .iter()
        .find(|(pin, _)| pin.kind == OwnedDocumentKind::PhysicsDefinition)
        .unwrap();
    assert_eq!(
        stored.0.revision.as_str(),
        physics["revision"].as_str().unwrap()
    );
    assert_eq!(fixture.store.read_blob(&stored.1).unwrap(), physics_bytes);
    assert_eq!(
        mmmm_runtime::storage::owned_documents::read_owned_document(
            &fixture.store,
            &fixture.project,
            &receipt.project_revision,
            &stored.0,
        )
        .unwrap(),
        physics
    );
    assert_eq!(receipt.resources.len(), 1);
    assert_eq!(
        receipt.resources[0].0.as_str(),
        resource["resourceId"].as_str().unwrap()
    );
    assert_eq!(
        fixture
            .store
            .read_blob(&receipt.resources[0].1)
            .unwrap()
            .as_slice(),
        bytes.as_slice()
    );
    assert!(
        fixture.store.project(&fixture.project).unwrap()["resourceIds"]
            .as_array()
            .unwrap()
            .contains(&resource["resourceId"])
    );
}

#[test]
fn physics_mesh_integral_float_size_matches_current_retained_integer_resource() {
    let mut fixture = Fixture::new();
    let bytes = b"float-sized retained mesh\n";
    let (physics, resource, physics_bytes) = mesh_physics_with_integral_float_size(bytes);
    let metadata = encode_json(&resource).unwrap();
    let first = fixture
        .prepare_raw(
            &[],
            &[],
            &[NativeRawSourceResource {
                metadata: &metadata,
                bytes,
            }],
        )
        .unwrap()
        .commit(&mut fixture.store)
        .unwrap();
    assert_eq!(first.resources.len(), 1);
    let authority = LocalAuthority::new(HostBridge::default());
    let workspace = prepare_workspace(
        &fixture.store,
        &authority,
        &fixture.project,
        fixture.budget.deadline(),
    )
    .unwrap();
    assert!(
        workspace.context["scope"]["resourceIds"]
            .as_array()
            .unwrap()
            .contains(&resource["resourceId"])
    );
    let documents = [NativeSourceDocument {
        kind: NativeSourceKind::PhysicsDefinition,
        bytes: &physics_bytes,
    }];
    let prepared = prepare_native_sources(
        &fixture.store,
        &workspace.witness,
        &authority,
        &fixture.budget,
        &NativeSourceInput {
            project: &fixture.project,
            expected_revision: &first.project_revision,
            documents: &documents,
            retained_resources: &[],
            raw_resources: &[],
        },
    )
    .unwrap();
    assert_eq!(prepared.retained_resources.len(), 1);
    let retained = &prepared.retained_resources[0];
    assert_eq!(retained.resource, resource);
    assert_eq!(retained.blob, first.resources[0].1);
    assert!(matches!(
        &retained.provenance,
        mmmm_runtime::storage::project_resources::ProjectResourceProvenance::HistoricalProject { project_revision }
            if project_revision == &first.project_revision
    ));
    let receipt = prepared.commit(&mut fixture.store).unwrap();
    let stored = receipt
        .documents
        .iter()
        .find(|(pin, _)| pin.kind == OwnedDocumentKind::PhysicsDefinition)
        .unwrap();
    assert_eq!(
        stored.0.revision.as_str(),
        physics["revision"].as_str().unwrap()
    );
    assert_eq!(fixture.store.read_blob(&stored.1).unwrap(), physics_bytes);
    assert_eq!(
        mmmm_runtime::storage::owned_documents::read_owned_document(
            &fixture.store,
            &fixture.project,
            &receipt.project_revision,
            &stored.0,
        )
        .unwrap(),
        physics
    );
    // A retained source is not a newly created resource in this receipt.
    assert!(receipt.resources.is_empty());
    assert_eq!(
        first.resources[0].0.as_str(),
        resource["resourceId"].as_str().unwrap()
    );
    assert_eq!(
        fixture
            .store
            .read_blob(&first.resources[0].1)
            .unwrap()
            .as_slice(),
        bytes.as_slice()
    );
    assert!(
        fixture.store.project(&fixture.project).unwrap()["resourceIds"]
            .as_array()
            .unwrap()
            .contains(&resource["resourceId"])
    );
}

// The Prefab source and ResourceRef metadata have independent bytes. The
// single-byte resource makes a nearby decimal fraction round to the same Value
// and projected pin as 1.0; it does not model geometry or game execution.
fn prefab_with_decimal_resource(geometry: bool, token: &str) -> (Value, Value, Vec<u8>) {
    let resource = json!({
        "resourceId":"resource-prefab-decimal",
        "sha256":raw_digest(b"x"),
        "mediaType":"application/octet-stream",
        "sizeBytes":1
    });
    let mut owner = prefab();
    if geometry {
        owner["resources"] = json!([resource]);
        owner["nodes"][0]["geometryResource"] = resource.clone();
        owner["nodes"][0]["geometryResource"]["sizeBytes"] = json!(1.0);
    } else {
        owner["resources"] = json!([resource]);
        owner["resources"][0]["sizeBytes"] = json!(1.0);
    }
    owner["revision"] = json!(projected_digest("Prefab", &owner).unwrap());
    let text = String::from_utf8(serde_json::to_vec(&owner).unwrap()).unwrap();
    let selected = "\"sizeBytes\":1.0";
    assert_eq!(text.matches(selected).count(), 1);
    let bytes = text
        .replacen(selected, &format!("\"sizeBytes\":{token}"), 1)
        .into_bytes();
    assert_eq!(parse_json(&bytes).unwrap(), owner);
    (owner, resource, bytes)
}

#[test]
fn prefab_decimal_resource_prepare_preserves_raw_source_and_projected_pin() {
    for geometry in [false, true] {
        for token in ["1.0", "1e0"] {
            let fixture = Fixture::new();
            let before = fixture.store.project(&fixture.project).unwrap();
            let (owner, resource, bytes) = prefab_with_decimal_resource(geometry, token);
            let metadata = encode_json(&resource).unwrap();
            let documents = [NativeSourceDocument {
                kind: NativeSourceKind::Prefab,
                bytes: &bytes,
            }];
            let raw = [NativeRawSourceResource {
                metadata: &metadata,
                bytes: b"x",
            }];
            let prepared = fixture.prepare_raw(&documents, &[], &raw).unwrap();
            assert_eq!(prepared.documents.len(), 1);
            assert_eq!(prepared.documents[0].original_bytes, bytes);
            assert_eq!(prepared.documents[0].original_digest, raw_digest(&bytes));
            assert_eq!(prepared.documents[0].value, owner);
            assert_eq!(
                prepared.documents[0].pin.revision,
                projected_digest("Prefab", &owner).unwrap()
            );
            prepared.check_current(&fixture.store).unwrap();
            assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
        }
    }
}

#[test]
fn prefab_decimal_resource_rejects_rounded_fraction_and_preserves_request_errors() {
    for geometry in [false, true] {
        let fixture = Fixture::new();
        let before = fixture.store.project(&fixture.project).unwrap();
        let (owner, resource, bytes) = prefab_with_decimal_resource(geometry, "1.0000000000000001");
        let metadata = encode_json(&resource).unwrap();
        let documents = [NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &bytes,
        }];
        let raw = [NativeRawSourceResource {
            metadata: &metadata,
            bytes: b"x",
        }];
        let error = fixture.prepare_raw(&documents, &[], &raw).err().unwrap();
        assert_eq!(error.code, "INVALID_INPUT");
        let location = if geometry {
            mmmm_contracts::validation::PrefabExactLocation::Geometry(0)
        } else {
            mmmm_contracts::validation::PrefabExactLocation::Resource(0)
        };
        assert!(matches!(
            std::error::Error::source(&error).and_then(|cause| {
                cause.downcast_ref::<
                    mmmm_contracts::validation::ControlledPrefabContractError<
                        mmmm_application::AppError,
                    >,
                >()
            }),
            Some(mmmm_contracts::validation::ControlledPrefabContractError::ExactInteger {
                location: actual
            }) if *actual == location
        ));
        assert_eq!(parse_json(&bytes).unwrap(), owner);
        assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);

        let text = String::from_utf8(bytes.clone()).unwrap();
        let revision = owner["revision"].as_str().unwrap();
        assert_eq!(text.matches(revision).count(), 1);
        let bad_pin = text.replacen(revision, &"0".repeat(64), 1).into_bytes();
        let wrong = [NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &bad_pin,
        }];
        assert_eq!(
            fixture.prepare_raw(&wrong, &[], &raw).err().unwrap().code,
            "INPUT_DIGEST_MISMATCH"
        );
        fixture.cancelled.store(true, Ordering::Release);
        assert_eq!(
            fixture
                .prepare_raw(&documents, &[], &raw)
                .err()
                .unwrap()
                .code,
            "CANCELLED"
        );
        assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);

        let revoked = Fixture::new();
        let revoked_before = revoked.store.project(&revoked.project).unwrap();
        revoked
            .authority
            .revoke_project(revoked.owner.principal(), &revoked.project)
            .unwrap();
        assert_eq!(
            revoked
                .prepare_raw(&documents, &[], &raw)
                .err()
                .unwrap()
                .code,
            "PERMISSION_REQUIRED"
        );
        assert_eq!(
            revoked.store.project(&revoked.project).unwrap(),
            revoked_before
        );
    }
}

#[test]
fn retained_integer_prefab_is_read_from_actual_cas_and_keeps_current_authority() {
    let mut fixture = Fixture::new();
    let (mut owner, resource, _) = prefab_with_decimal_resource(false, "1.0");
    // This retained fixture exercises the integer representation. The separate
    // decimal-prefab test covers its own raw bytes and retained source path.
    owner["resources"][0]["sizeBytes"] = json!(1);
    owner["revision"] = json!(projected_digest("Prefab", &owner).unwrap());
    let owner_bytes = encode_json(&owner).unwrap();
    let metadata = encode_json(&resource).unwrap();
    let sources = [NativeSourceDocument {
        kind: NativeSourceKind::Prefab,
        bytes: &owner_bytes,
    }];
    let first = fixture
        .prepare_raw(
            &sources,
            &[],
            &[NativeRawSourceResource {
                metadata: &metadata,
                bytes: b"x",
            }],
        )
        .unwrap()
        .commit(&mut fixture.store)
        .unwrap();
    let retained = first
        .documents
        .iter()
        .find(|(pin, _)| pin.kind == OwnedDocumentKind::Prefab)
        .unwrap();
    assert_eq!(fixture.store.read_blob(&retained.1).unwrap(), owner_bytes);
    assert_eq!(
        retained.0.revision,
        projected_digest("Prefab", &owner).unwrap()
    );

    let authority = LocalAuthority::new(HostBridge::default());
    let workspace = prepare_workspace(
        &fixture.store,
        &authority,
        &fixture.project,
        fixture.budget.deadline(),
    )
    .unwrap();
    let instance_bytes = encode_json(&instance(&owner)).unwrap();
    let instance_source = [NativeSourceDocument {
        kind: NativeSourceKind::Instance,
        bytes: &instance_bytes,
    }];
    let prepared = prepare_native_sources(
        &fixture.store,
        &workspace.witness,
        &authority,
        &fixture.budget,
        &NativeSourceInput {
            project: &fixture.project,
            expected_revision: &first.project_revision,
            documents: &instance_source,
            retained_resources: &[],
            raw_resources: &[],
        },
    )
    .unwrap();
    prepared.check_current(&fixture.store).unwrap();
    let before = fixture.store.project(&fixture.project).unwrap();
    authority
        .revoke_project(workspace.witness.principal(), &fixture.project)
        .unwrap();
    assert_eq!(
        prepared.check_current(&fixture.store).unwrap_err().code,
        "PERMISSION_REQUIRED"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
    assert_eq!(fixture.store.read_blob(&retained.1).unwrap(), owner_bytes);
}

#[test]
fn decimal_prefab_commit_preserves_raw_bytes_and_authorized_retained_source() {
    for geometry in [false, true] {
        for token in ["1.0", "1e0"] {
            let mut fixture = Fixture::new();
            let (owner, resource, bytes) = prefab_with_decimal_resource(geometry, token);
            let metadata = encode_json(&resource).unwrap();
            let source = [NativeSourceDocument {
                kind: NativeSourceKind::Prefab,
                bytes: &bytes,
            }];
            let raw = [NativeRawSourceResource {
                metadata: &metadata,
                bytes: b"x",
            }];
            let prepared = fixture.prepare_raw(&source, &[], &raw).unwrap();
            assert_eq!(prepared.documents[0].original_bytes, bytes);
            assert_eq!(prepared.documents[0].value, owner);
            let expected_revision = projected_digest("Prefab", &owner).unwrap();
            assert_eq!(prepared.documents[0].pin.revision, expected_revision);
            let receipt = prepared.commit(&mut fixture.store).unwrap();
            let (pin, blob) = receipt
                .documents
                .iter()
                .find(|(pin, _)| pin.kind == OwnedDocumentKind::Prefab)
                .unwrap();
            assert_eq!(pin.revision, expected_revision);
            assert_eq!(blob.digest, raw_digest(&bytes));
            assert_eq!(blob.byte_length, bytes.len() as u64);
            assert_eq!(fixture.store.read_blob(blob).unwrap(), bytes);

            let authority = LocalAuthority::new(HostBridge::default());
            let workspace = prepare_workspace(
                &fixture.store,
                &authority,
                &fixture.project,
                fixture.budget.deadline(),
            )
            .unwrap();
            assert_eq!(workspace.project_revision, receipt.project_revision);
            assert!(
                workspace.context["scope"]["objectIds"]
                    .as_array()
                    .unwrap()
                    .contains(&owner["prefabId"])
            );
            assert!(
                workspace.context["scope"]["resourceIds"]
                    .as_array()
                    .unwrap()
                    .contains(&resource["resourceId"])
            );

            // Make an authored draft from the integer fixture, then bind it to
            // the actual original Prefab revision without rewriting the stored
            // source or relying on a Value-only decimal witness.
            let mut authored_instance = instance(&prefab());
            authored_instance["prefabRevision"] = json!(pin.revision.as_str());
            authored_instance["revision"] =
                json!(projected_digest("Instance", &authored_instance).unwrap());
            let instance_bytes = encode_json(&authored_instance).unwrap();
            let instance_source = [NativeSourceDocument {
                kind: NativeSourceKind::Instance,
                bytes: &instance_bytes,
            }];
            let retained = prepare_native_sources(
                &fixture.store,
                &workspace.witness,
                &authority,
                &fixture.budget,
                &NativeSourceInput {
                    project: &fixture.project,
                    expected_revision: &receipt.project_revision,
                    documents: &instance_source,
                    retained_resources: &[],
                    raw_resources: &[],
                },
            )
            .unwrap();
            retained.check_current(&fixture.store).unwrap();
            let before = fixture.store.project(&fixture.project).unwrap();
            authority
                .revoke_project(workspace.witness.principal(), &fixture.project)
                .unwrap();
            assert_eq!(
                retained.check_current(&fixture.store).unwrap_err().code,
                "PERMISSION_REQUIRED"
            );
            assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
            assert_eq!(fixture.store.read_blob(blob).unwrap(), bytes);
        }
    }
}

#[test]
fn prepared_decimal_prefab_rechecks_the_actual_project_head() {
    let mut fixture = Fixture::new();
    let (_, resource, bytes) = prefab_with_decimal_resource(false, "1.0");
    let metadata = encode_json(&resource).unwrap();
    let sources = [NativeSourceDocument {
        kind: NativeSourceKind::Prefab,
        bytes: &bytes,
    }];
    let prepared = fixture
        .prepare_raw(
            &sources,
            &[],
            &[NativeRawSourceResource {
                metadata: &metadata,
                bytes: b"x",
            }],
        )
        .unwrap();
    let other_bytes = encode_json(&prefab()).unwrap();
    let other = [NativeSourceDocument {
        kind: NativeSourceKind::Prefab,
        bytes: &other_bytes,
    }];
    fixture
        .prepare(&other, &[])
        .unwrap()
        .commit(&mut fixture.store)
        .unwrap();
    let current = fixture.store.project(&fixture.project).unwrap();
    assert_eq!(
        prepared.check_current(&fixture.store).unwrap_err().code,
        "REVISION_CONFLICT"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), current);
}

// The authored mesh needs one actual byte so that an exact fraction can round
// to the same parsed Value, projected pin, and valid ResourceRef as 1.0.
// This derives from the original box fixture and asserts nothing about mesh
// topology, selection, a solver, or game behavior.
fn physics_mesh_with_rounded_fraction() -> (Value, Value, Vec<u8>, Vec<u8>) {
    let bytes = b"x";
    let (physics, resource, valid) = mesh_physics_with_integral_float_size(bytes);
    let original = String::from_utf8(valid.clone()).unwrap();
    let target = "\"sizeBytes\":1.0";
    assert_eq!(original.matches(target).count(), 1);
    let invalid = original
        .replacen(target, "\"sizeBytes\":1.0000000000000001", 1)
        .into_bytes();
    let parsed = parse_json(&invalid).unwrap();
    assert_eq!(
        parsed, physics,
        "The existing Value boundary must see the same physics document"
    );
    assert_eq!(
        projected_digest("PhysicsDefinition", &parsed)
            .unwrap()
            .as_str(),
        physics["revision"].as_str().unwrap()
    );
    (physics, resource, valid, invalid)
}

#[test]
fn physics_mesh_raw_fraction_is_rejected_without_rewriting_the_original_pin() {
    let fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let (physics, resource, _, invalid) = physics_mesh_with_rounded_fraction();
    let resource_bytes = b"x";
    let metadata = encode_json(&resource).unwrap();
    let documents = [NativeSourceDocument {
        kind: NativeSourceKind::PhysicsDefinition,
        bytes: &invalid,
    }];
    let raw = [NativeRawSourceResource {
        metadata: &metadata,
        bytes: resource_bytes,
    }];
    let error = fixture.prepare_raw(&documents, &[], &raw).err().unwrap();
    assert_eq!(error.code, "INVALID_INPUT");
    assert!(matches!(
        std::error::Error::source(&error).and_then(|cause| {
            cause.downcast_ref::<
            mmmm_contracts::validation::ControlledContractError<mmmm_application::AppError>
        >()
        }),
        Some(
            mmmm_contracts::validation::ControlledContractError::ExactInteger { collider: Some(0) }
        )
    ));
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
    assert_eq!(parse_json(&invalid).unwrap(), physics);
}

#[test]
fn physics_raw_exact_checks_preserve_original_digest_collision_and_cancel_errors() {
    let fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let (physics, resource, valid, invalid) = physics_mesh_with_rounded_fraction();
    let metadata = encode_json(&resource).unwrap();
    let raw = [NativeRawSourceResource {
        metadata: &metadata,
        bytes: b"x",
    }];

    let original = String::from_utf8(invalid.clone()).unwrap();
    let revision = physics["revision"].as_str().unwrap();
    assert_eq!(original.matches(revision).count(), 1);
    let wrong_pin = original.replacen(revision, &"0".repeat(64), 1).into_bytes();
    let wrong = [NativeSourceDocument {
        kind: NativeSourceKind::PhysicsDefinition,
        bytes: &wrong_pin,
    }];
    assert_eq!(
        fixture.prepare_raw(&wrong, &[], &raw).err().unwrap().code,
        "INPUT_DIGEST_MISMATCH"
    );

    let repeated = [
        NativeSourceDocument {
            kind: NativeSourceKind::PhysicsDefinition,
            bytes: &valid,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::PhysicsDefinition,
            bytes: &invalid,
        },
    ];
    assert_eq!(
        fixture
            .prepare_raw(&repeated, &[], &raw)
            .err()
            .unwrap()
            .code,
        "ID_COLLISION"
    );

    fixture.cancelled.store(true, Ordering::Release);
    let cancelled = [NativeSourceDocument {
        kind: NativeSourceKind::PhysicsDefinition,
        bytes: &invalid,
    }];
    assert_eq!(
        fixture
            .prepare_raw(&cancelled, &[], &raw)
            .err()
            .unwrap()
            .code,
        "CANCELLED"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);

    let revoked = Fixture::new();
    let revoked_before = revoked.store.project(&revoked.project).unwrap();
    revoked
        .authority
        .revoke_project(revoked.owner.principal(), &revoked.project)
        .unwrap();
    assert_eq!(
        revoked
            .prepare_raw(&cancelled, &[], &raw)
            .err()
            .unwrap()
            .code,
        "PERMISSION_REQUIRED"
    );
    assert_eq!(
        revoked.store.project(&revoked.project).unwrap(),
        revoked_before
    );
}

// Resource metadata is kept as authored bytes at the Coordinator boundary.
// The byte content is deliberately not a mesh/topology fixture.
fn rounded_resource_metadata() -> (Value, Vec<u8>, Vec<u8>) {
    let bytes = b"x";
    let resource = json!({
        "resourceId":"resource-rounded-metadata", "sha256":raw_digest(bytes),
        "mediaType":"application/octet-stream", "sizeBytes":bytes.len()
    });
    let valid = encode_json(&resource).unwrap();
    let original = String::from_utf8(valid.clone()).unwrap();
    let target = "\"sizeBytes\":1";
    assert_eq!(original.matches(target).count(), 1);
    let invalid = original
        .replacen(target, "\"sizeBytes\":1.0000000000000001", 1)
        .into_bytes();
    let parsed = parse_json(&invalid).unwrap();
    assert_eq!(parsed["sizeBytes"].as_f64(), Some(1.0));
    assert_eq!(parsed["resourceId"], resource["resourceId"]);
    assert_eq!(parsed["sha256"], resource["sha256"]);
    assert_eq!(parsed["mediaType"], resource["mediaType"]);
    (resource, valid, invalid)
}

#[test]
fn raw_resource_metadata_rejects_rounded_fraction_after_digest_and_id_checks() {
    let fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let (_, valid, invalid) = rounded_resource_metadata();
    let blob = mmmm_runtime::storage::BlobRef {
        digest: raw_digest(b"x"),
        byte_length: 1,
    };
    assert!(matches!(
        fixture.store.read_blob(&blob),
        Err(mmmm_runtime::storage::StorageError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound
    ));
    let raw = [NativeRawSourceResource {
        metadata: &invalid,
        bytes: b"x",
    }];
    let error = fixture.prepare_raw(&[], &[], &raw).err().unwrap();
    assert_eq!(error.code, "INVALID_INPUT");
    assert!(matches!(
        std::error::Error::source(&error).and_then(|cause| {
            cause.downcast_ref::<
            mmmm_contracts::validation::ControlledContractError<mmmm_application::AppError>
        >()
        }),
        Some(mmmm_contracts::validation::ControlledContractError::ExactInteger { collider: None })
    ));

    let wrong = [NativeRawSourceResource {
        metadata: &invalid,
        bytes: b"wrong",
    }];
    assert_eq!(
        fixture.prepare_raw(&[], &[], &wrong).err().unwrap().code,
        "INPUT_DIGEST_MISMATCH"
    );
    let repeated = [
        NativeRawSourceResource {
            metadata: &valid,
            bytes: b"x",
        },
        NativeRawSourceResource {
            metadata: &invalid,
            bytes: b"x",
        },
    ];
    assert_eq!(
        fixture.prepare_raw(&[], &[], &repeated).err().unwrap().code,
        "REVISION_CONFLICT"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
    assert!(matches!(
        fixture.store.read_blob(&blob),
        Err(mmmm_runtime::storage::StorageError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound
    ));
}

#[test]
fn submitted_retained_resource_metadata_rejects_rounded_fraction() {
    let mut fixture = Fixture::new();
    let (_, valid, invalid) = rounded_resource_metadata();
    let first = fixture
        .prepare_raw(
            &[],
            &[],
            &[NativeRawSourceResource {
                metadata: &valid,
                bytes: b"x",
            }],
        )
        .unwrap()
        .commit(&mut fixture.store)
        .unwrap();
    let authority = LocalAuthority::new(HostBridge::default());
    let workspace = prepare_workspace(
        &fixture.store,
        &authority,
        &fixture.project,
        fixture.budget.deadline(),
    )
    .unwrap();
    let before = fixture.store.project(&fixture.project).unwrap();
    let error = prepare_native_sources(
        &fixture.store,
        &workspace.witness,
        &authority,
        &fixture.budget,
        &NativeSourceInput {
            project: &fixture.project,
            expected_revision: &first.project_revision,
            documents: &[],
            retained_resources: &[&invalid],
            raw_resources: &[],
        },
    )
    .err()
    .unwrap();
    // The caller's original bytes reach the exact-integer gate after current
    // Project/resource checks. They do not prove the lexeme of the previously
    // registered Value-only resource.
    assert_eq!(error.code, "INVALID_INPUT");
    assert!(matches!(
        std::error::Error::source(&error).and_then(|cause| {
            cause.downcast_ref::<
                mmmm_contracts::validation::ControlledContractError<mmmm_application::AppError>
            >()
        }),
        Some(mmmm_contracts::validation::ControlledContractError::ExactInteger { collider: None })
    ));
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
    assert_eq!(
        fixture
            .store
            .read_blob(&first.resources[0].1)
            .unwrap()
            .as_slice(),
        b"x"
    );
}

#[test]
fn integral_decimal_resource_metadata_commits_and_rechecks_as_retained_input() {
    let mut fixture = Fixture::new();
    let (resource, integer, invalid) = rounded_resource_metadata();
    let source = String::from_utf8(integer).unwrap();
    assert_eq!(source.matches("\"sizeBytes\":1").count(), 1);
    let decimal = source
        .replacen("\"sizeBytes\":1", "\"sizeBytes\":1.0", 1)
        .into_bytes();
    let raw = [NativeRawSourceResource {
        metadata: &decimal,
        bytes: b"x",
    }];
    let prepared = fixture.prepare_raw(&[], &[], &raw).unwrap();
    assert_eq!(prepared.raw_resources.len(), 1);
    assert_eq!(prepared.raw_resources[0].metadata_bytes, decimal);
    assert_eq!(
        prepared.raw_resources[0].metadata_digest,
        raw_digest(&decimal)
    );
    prepared.check_current(&fixture.store).unwrap();
    let receipt = prepared.commit(&mut fixture.store).unwrap();
    assert_eq!(receipt.resources.len(), 1);
    assert_eq!(
        fixture
            .store
            .read_blob(&receipt.resources[0].1)
            .unwrap()
            .as_slice(),
        b"x"
    );

    let authority = LocalAuthority::new(HostBridge::default());
    let workspace = prepare_workspace(
        &fixture.store,
        &authority,
        &fixture.project,
        fixture.budget.deadline(),
    )
    .unwrap();
    let before = fixture.store.project(&fixture.project).unwrap();
    // Build each input inline: the one-element slice must live through the call.
    let retained = [decimal.as_slice()];
    let candidate = prepare_native_sources(
        &fixture.store,
        &workspace.witness,
        &authority,
        &fixture.budget,
        &NativeSourceInput {
            project: &fixture.project,
            expected_revision: &receipt.project_revision,
            documents: &[],
            retained_resources: &retained,
            raw_resources: &[],
        },
    )
    .unwrap();
    assert_eq!(candidate.retained_resources.len(), 1);
    assert_eq!(candidate.retained_resources[0].resource, resource);
    assert_eq!(candidate.retained_resources[0].blob, receipt.resources[0].1);
    candidate.check_current(&fixture.store).unwrap();

    let bad = [invalid.as_slice()];
    let error = prepare_native_sources(
        &fixture.store,
        &workspace.witness,
        &authority,
        &fixture.budget,
        &NativeSourceInput {
            project: &fixture.project,
            expected_revision: &receipt.project_revision,
            documents: &[],
            retained_resources: &bad,
            raw_resources: &[],
        },
    )
    .err()
    .unwrap();
    assert_eq!(error.code, "INVALID_INPUT");
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);

    authority
        .revoke_project(workspace.witness.principal(), &fixture.project)
        .unwrap();
    let error = prepare_native_sources(
        &fixture.store,
        &workspace.witness,
        &authority,
        &fixture.budget,
        &NativeSourceInput {
            project: &fixture.project,
            expected_revision: &receipt.project_revision,
            documents: &[],
            retained_resources: &bad,
            raw_resources: &[],
        },
    )
    .err()
    .unwrap();
    assert_eq!(error.code, "PERMISSION_REQUIRED");
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
}

#[test]
fn command_module_is_stored_with_its_actual_same_batch_owner_and_original_bytes() {
    let mut fixture = Fixture::new();
    let (owner, module) = command_owner();
    let owner_bytes = encode_json(&owner).unwrap();
    let module_bytes = include_bytes!("../../../examples/command-module.json");
    let sources = [
        NativeSourceDocument {
            kind: NativeSourceKind::CommandModule,
            bytes: module_bytes,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &owner_bytes,
        },
    ];
    let receipt = fixture
        .prepare(&sources, &[])
        .unwrap()
        .commit(&mut fixture.store)
        .unwrap();
    let stored = receipt
        .documents
        .iter()
        .find(|(pin, _)| pin.kind == OwnedDocumentKind::CommandModule)
        .unwrap();
    assert_eq!(
        stored.0.object_id.as_str(),
        module["moduleId"].as_str().unwrap()
    );
    assert_eq!(
        stored.0.revision.as_str(),
        module["revision"].as_str().unwrap()
    );
    assert_eq!(
        fixture.store.read_blob(&stored.1).unwrap().as_slice(),
        module_bytes.as_slice()
    );
    let loaded = mmmm_runtime::storage::owned_documents::read_owned_document(
        &fixture.store,
        &fixture.project,
        &receipt.project_revision,
        &stored.0,
    )
    .unwrap();
    assert_eq!(loaded, module);
    assert_eq!(loaded["commands"][0]["parseStatus"], "parsed");
    let project = fixture.store.project(&fixture.project).unwrap();
    assert_eq!(project["prefabIds"], json!([owner["prefabId"]]));
    assert!(project["instanceIds"].as_array().unwrap().is_empty());
    assert!(
        project["ownedResources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|pin| pin["objectId"] == module["moduleId"]
                && pin["revision"] == module["revision"])
    );
}

#[test]
fn command_module_owner_reciprocal_and_origin_fail_without_publication() {
    let fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let (valid_owner, valid_module) = command_owner();
    for (case, expected) in [
        ("missing_owner", "SOURCE_UNAVAILABLE"),
        ("reciprocal", "REFERENCE_UNRESOLVED"),
        ("origin", "REFERENCE_UNRESOLVED"),
    ] {
        let mut owner = valid_owner.clone();
        let mut module = valid_module.clone();
        match case {
            "missing_owner" => module["ownerPrefabId"] = json!("prefab-unavailable"),
            "reciprocal" => owner["commandModuleIds"] = json!([]),
            "origin" => module["localOriginNodeId"] = json!("node-unavailable"),
            _ => unreachable!(),
        }
        owner["revision"] = json!(projected_digest("Prefab", &owner).unwrap());
        module["revision"] = json!(projected_digest("CommandModule", &module).unwrap());
        let owner_bytes = encode_json(&owner).unwrap();
        let module_bytes = encode_json(&module).unwrap();
        let sources = [
            NativeSourceDocument {
                kind: NativeSourceKind::Prefab,
                bytes: &owner_bytes,
            },
            NativeSourceDocument {
                kind: NativeSourceKind::CommandModule,
                bytes: &module_bytes,
            },
        ];
        assert_eq!(
            fixture.prepare(&sources, &[]).err().unwrap().code,
            expected,
            "{case}"
        );
        assert_eq!(
            fixture.store.project(&fixture.project).unwrap(),
            before,
            "{case}"
        );
    }
}

#[test]
fn prefab_cannot_list_a_module_owned_by_another_prefab() {
    let fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let (owner, module) = command_owner();
    let mut other = owner.clone();
    other["prefabId"] = json!("prefab-other");
    other["revision"] = json!(projected_digest("Prefab", &other).unwrap());
    let owner_bytes = encode_json(&owner).unwrap();
    let other_bytes = encode_json(&other).unwrap();
    let module_bytes = encode_json(&module).unwrap();
    let sources = [
        NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &owner_bytes,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &other_bytes,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::CommandModule,
            bytes: &module_bytes,
        },
    ];
    assert_eq!(
        fixture.prepare(&sources, &[]).err().unwrap().code,
        "REFERENCE_UNRESOLVED"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
}

#[test]
fn retained_actual_owner_rejects_an_unlisted_command_module() {
    let mut fixture = Fixture::new();
    let (owner, mut module) = command_owner();
    let owner_bytes = encode_json(&owner).unwrap();
    let first = [
        NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &owner_bytes,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::CommandModule,
            bytes: include_bytes!("../../../examples/command-module.json"),
        },
    ];
    let receipt = fixture
        .prepare(&first, &[])
        .unwrap()
        .commit(&mut fixture.store)
        .unwrap();
    let before = fixture.store.project(&fixture.project).unwrap();
    let authority = LocalAuthority::new(HostBridge::default());
    let workspace = prepare_workspace(
        &fixture.store,
        &authority,
        &fixture.project,
        fixture.budget.deadline(),
    )
    .unwrap();
    module["moduleId"] = json!("module-unlisted");
    module["revision"] = json!(projected_digest("CommandModule", &module).unwrap());
    let bytes = encode_json(&module).unwrap();
    let sources = [NativeSourceDocument {
        kind: NativeSourceKind::CommandModule,
        bytes: &bytes,
    }];
    let result = prepare_native_sources(
        &fixture.store,
        &workspace.witness,
        &authority,
        &fixture.budget,
        &NativeSourceInput {
            project: &fixture.project,
            expected_revision: &receipt.project_revision,
            documents: &sources,
            retained_resources: &[],
            raw_resources: &[],
        },
    );
    assert_eq!(result.err().unwrap().code, "REFERENCE_UNRESOLVED");
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
}

#[test]
fn owner_prepares_closed_prefab_and_instance_without_publishing_any_membership() {
    let fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let prefab = prefab();
    let instance = instance(&prefab);
    let prefab_bytes = encode_json(&prefab).unwrap();
    let instance_bytes = encode_json(&instance).unwrap();
    let documents = [
        NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &prefab_bytes,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::Instance,
            bytes: &instance_bytes,
        },
    ];
    let candidate = fixture.prepare(&documents, &[]).unwrap();
    assert_eq!(candidate.project_id(), &fixture.project);
    assert_eq!(candidate.base_revision(), &fixture.revision);
    assert_ne!(candidate.proposed_revision().unwrap(), fixture.revision);
    assert_eq!(
        (candidate.document_count(), candidate.resource_count()),
        (2, 0)
    );
    candidate.check_current(&fixture.store).unwrap();
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
    assert!(before["prefabIds"].as_array().unwrap().is_empty());
    let pin = &candidate.documents[0].pin;
    assert!(
        mmmm_runtime::storage::owned_documents::read_owned_document(
            &fixture.store,
            &fixture.project,
            &fixture.revision,
            pin
        )
        .is_err()
    );
}

#[test]
fn identity_collision_follows_the_original_kind_and_id_pair() {
    let fixture = Fixture::new();
    let prefab = prefab();
    let mut instance = instance(&prefab);
    instance["instanceId"] = prefab["prefabId"].clone();
    instance["revision"] = json!(projected_digest("Instance", &instance).unwrap());
    let prefab_bytes = encode_json(&prefab).unwrap();
    let instance_bytes = encode_json(&instance).unwrap();
    let documents = [
        NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &prefab_bytes,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::Instance,
            bytes: &instance_bytes,
        },
    ];
    assert_eq!(
        fixture.prepare(&documents, &[]).unwrap().document_count(),
        2
    );
    let repeated_prefab = [
        NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &prefab_bytes,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &prefab_bytes,
        },
    ];
    assert_eq!(
        fixture.prepare(&repeated_prefab, &[]).err().unwrap().code,
        "ID_COLLISION"
    );
}

#[test]
fn admission_rejects_the_item_budget_before_parsing_repeated_bodies() {
    let fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let documents = (0..=MAX_ITEMS)
        .map(|_| NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: b"malformed body",
        })
        .collect::<Vec<_>>();
    assert_eq!(
        fixture.prepare(&documents, &[]).err().unwrap().code,
        "BUDGET_EXCEEDED"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
}

#[test]
fn duplicate_fields_and_wrong_self_digest_are_rejected_without_writes() {
    let fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let value = prefab();
    let bytes = encode_json(&value).unwrap();
    let duplicate = [
        b"{\"prefabId\":\"caller-replacement\",".as_slice(),
        &bytes[1..],
    ]
    .concat();
    assert_eq!(
        fixture
            .prepare(
                &[NativeSourceDocument {
                    kind: NativeSourceKind::Prefab,
                    bytes: &duplicate
                }],
                &[]
            )
            .err()
            .unwrap()
            .code,
        "INVALID_INPUT"
    );
    let mut altered = value;
    altered["name"] = json!("Altered without changing original pin");
    let altered = encode_json(&altered).unwrap();
    assert_eq!(
        fixture
            .prepare(
                &[NativeSourceDocument {
                    kind: NativeSourceKind::Prefab,
                    bytes: &altered
                }],
                &[]
            )
            .err()
            .unwrap()
            .code,
        "INPUT_DIGEST_MISMATCH"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
}

#[test]
fn candidate_keeps_original_cancellation_and_revoked_current_policy() {
    let fixture = Fixture::new();
    let bytes = encode_json(&prefab()).unwrap();
    let documents = [NativeSourceDocument {
        kind: NativeSourceKind::Prefab,
        bytes: &bytes,
    }];
    let candidate = fixture.prepare(&documents, &[]).unwrap();
    fixture.cancelled.store(true, Ordering::Release);
    assert_eq!(
        candidate.check_current(&fixture.store).err().unwrap().code,
        "CANCELLED"
    );
    let revoked_fixture = Fixture::new();
    let revoked_candidate = revoked_fixture.prepare(&documents, &[]).unwrap();
    revoked_fixture
        .authority
        .revoke_project(revoked_fixture.owner.principal(), &revoked_fixture.project)
        .unwrap();
    assert_eq!(
        revoked_candidate
            .check_current(&revoked_fixture.store)
            .err()
            .unwrap()
            .code,
        "PERMISSION_REQUIRED"
    );
}

#[test]
fn actual_project_owned_blob_and_hash_do_not_create_current_resource_read_scope() {
    let mut fixture = Fixture::new();
    let blob = fixture
        .store
        .put_blob(b"already retained authored bytes")
        .unwrap();
    let resource = json!({"resourceId":"resource-not-admitted","sha256":blob.digest,"mediaType":"text/plain","sizeBytes":blob.byte_length});
    register_resource(
        &mut fixture.store,
        &resource,
        ResourceOwner::Project(fixture.project.clone()),
    )
    .unwrap();
    let metadata = encode_json(&resource).unwrap();
    let bytes = encode_json(&prefab()).unwrap();
    let documents = [NativeSourceDocument {
        kind: NativeSourceKind::Prefab,
        bytes: &bytes,
    }];
    assert_eq!(
        fixture
            .prepare(&documents, &[&metadata])
            .err()
            .unwrap()
            .code,
        "PERMISSION_REQUIRED"
    );
    assert!(
        fixture.store.project(&fixture.project).unwrap()["resourceIds"]
            .as_array()
            .unwrap()
            .iter()
            .all(|id| id != "resource-not-admitted")
    );
}

#[test]
fn absent_prefab_nonplanned_instance_and_cross_store_owner_fail_closed() {
    let fixture = Fixture::new();
    let prefab = prefab();
    let mut instance = instance(&prefab);
    let bytes = encode_json(&instance).unwrap();
    assert!(
        fixture
            .prepare(
                &[NativeSourceDocument {
                    kind: NativeSourceKind::Instance,
                    bytes: &bytes
                }],
                &[]
            )
            .is_err()
    );
    instance["lifecycle"] = json!("applied");
    instance["revision"] = json!(projected_digest("Instance", &instance).unwrap());
    let bytes = encode_json(&instance).unwrap();
    assert_eq!(
        fixture
            .prepare(
                &[NativeSourceDocument {
                    kind: NativeSourceKind::Instance,
                    bytes: &bytes
                }],
                &[]
            )
            .err()
            .unwrap()
            .code,
        "INVALID_INPUT"
    );
    let other = Fixture::new();
    let bytes = encode_json(&prefab).unwrap();
    let documents = [NativeSourceDocument {
        kind: NativeSourceKind::Prefab,
        bytes: &bytes,
    }];
    assert!(
        prepare_native_sources(
            &other.store,
            &fixture.owner,
            &other.authority,
            &other.budget,
            &NativeSourceInput {
                project: &other.project,
                expected_revision: &other.revision,
                documents: &documents,
                retained_resources: &[],
                raw_resources: &[],
            }
        )
        .is_err()
    );
}

#[test]
fn atomic_commit_preserves_raw_sources_and_carries_initial_policy_to_new_head() {
    let mut fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let prefab_value = prefab();
    let instance_value = instance(&prefab_value);
    // Whitespace is valid source syntax. The raw CAS pin must retain these
    // exact bytes instead of silently replacing them with JCS serialization.
    let prefab_bytes = [
        b" \n".as_slice(),
        &encode_json(&prefab_value).unwrap(),
        b"\n ",
    ]
    .concat();
    let instance_bytes = encode_json(&instance_value).unwrap();
    let documents = [
        NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &prefab_bytes,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::Instance,
            bytes: &instance_bytes,
        },
    ];
    let raw_bytes = b"exact owner authored content\n";
    let metadata = json!({"resourceId":"resource-native-raw","sha256":raw_digest(raw_bytes),
        "mediaType":"text/plain","sizeBytes":raw_bytes.len()});
    let metadata_bytes = encode_json(&metadata).unwrap();
    let candidate = fixture
        .prepare_raw(
            &documents,
            &[],
            &[NativeRawSourceResource {
                metadata: &metadata_bytes,
                bytes: raw_bytes,
            }],
        )
        .unwrap();
    let proposed = candidate.proposed_revision().unwrap();
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
    let receipt = candidate.commit(&mut fixture.store).unwrap();
    assert_eq!(receipt.base_revision, fixture.revision);
    assert_eq!(receipt.project_revision, proposed);
    assert_eq!(receipt.documents.len(), 2);
    let prefab_pin = receipt
        .documents
        .iter()
        .find(|(pin, _)| pin.kind == OwnedDocumentKind::Prefab)
        .unwrap();
    assert_eq!(
        fixture.store.read_blob(&prefab_pin.1).unwrap(),
        prefab_bytes
    );
    assert_ne!(
        prefab_pin.1.digest,
        raw_digest(&encode_json(&prefab_value).unwrap())
    );
    assert_eq!(receipt.resources.len(), 1);
    assert_eq!(
        fixture.store.read_blob(&receipt.resources[0].1).unwrap(),
        raw_bytes
    );
    assert_eq!(
        fixture
            .store
            .project_revision(&fixture.project, &fixture.revision)
            .unwrap(),
        before
    );

    // A real renewed native workspace resolves the initial policy by Current
    // at the new Project revision and discovers the actual registered sources.
    // No read_scope JSON is patched to make that possible.
    let renewed_authority = LocalAuthority::new(HostBridge::default());
    let renewed = prepare_workspace(
        &fixture.store,
        &renewed_authority,
        &fixture.project,
        fixture.budget.deadline(),
    )
    .unwrap();
    assert_eq!(renewed.project_revision, receipt.project_revision);
    assert!(renewed.excluded_sources.is_empty());
    assert!(
        renewed.context["scope"]["objectIds"]
            .as_array()
            .unwrap()
            .contains(&prefab_value["prefabId"])
    );
    assert!(
        renewed.context["scope"]["resourceIds"]
            .as_array()
            .unwrap()
            .contains(&before["policyResourceId"])
    );
    assert!(
        renewed.context["scope"]["resourceIds"]
            .as_array()
            .unwrap()
            .contains(&metadata["resourceId"])
    );
}

#[test]
fn commit_rejects_original_cancellation_and_revoked_policy_without_head_change() {
    let bytes = encode_json(&prefab()).unwrap();
    let documents = [NativeSourceDocument {
        kind: NativeSourceKind::Prefab,
        bytes: &bytes,
    }];
    let mut cancelled = Fixture::new();
    let before = cancelled.store.project(&cancelled.project).unwrap();
    let prepared = cancelled.prepare(&documents, &[]).unwrap();
    cancelled.cancelled.store(true, Ordering::Release);
    assert_eq!(
        prepared.commit(&mut cancelled.store).unwrap_err().code,
        "CANCELLED"
    );
    assert_eq!(cancelled.store.project(&cancelled.project).unwrap(), before);

    let mut revoked = Fixture::new();
    let before = revoked.store.project(&revoked.project).unwrap();
    let prepared = revoked.prepare(&documents, &[]).unwrap();
    revoked
        .authority
        .revoke_project(revoked.owner.principal(), &revoked.project)
        .unwrap();
    assert_eq!(
        prepared.commit(&mut revoked.store).unwrap_err().code,
        "PERMISSION_REQUIRED"
    );
    assert_eq!(revoked.store.project(&revoked.project).unwrap(), before);
}

#[test]
fn commit_cannot_move_to_another_store_or_replay_an_old_base_revision() {
    let mut fixture = Fixture::new();
    let bytes = encode_json(&prefab()).unwrap();
    let documents = [NativeSourceDocument {
        kind: NativeSourceKind::Prefab,
        bytes: &bytes,
    }];
    let first = fixture.prepare(&documents, &[]).unwrap();
    let stale = fixture.prepare(&documents, &[]).unwrap();
    let misplaced = fixture.prepare(&documents, &[]).unwrap();
    let mut other = Fixture::new();
    let other_before = other.store.project(&other.project).unwrap();
    assert!(misplaced.commit(&mut other.store).is_err());
    assert_eq!(other.store.project(&other.project).unwrap(), other_before);
    let committed = first.commit(&mut fixture.store).unwrap();
    let before_stale = fixture.store.project(&fixture.project).unwrap();
    assert_eq!(
        stale.commit(&mut fixture.store).unwrap_err().code,
        "REVISION_CONFLICT"
    );
    assert_eq!(
        fixture.store.project(&fixture.project).unwrap(),
        before_stale
    );
    assert_eq!(
        before_stale["revision"],
        committed.project_revision.as_str()
    );
}

#[test]
fn copying_registered_bytes_cannot_bypass_existing_resource_read_authority() {
    let mut fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let bytes = b"pre-existing retained content";
    let blob = fixture.store.put_blob(bytes).unwrap();
    let resource = json!({"resourceId":"resource-existing-unreadable","sha256":blob.digest,
        "mediaType":"text/plain","sizeBytes":blob.byte_length});
    register_resource(
        &mut fixture.store,
        &resource,
        ResourceOwner::Project(fixture.project.clone()),
    )
    .unwrap();
    let metadata = encode_json(&resource).unwrap();
    let source = encode_json(&prefab()).unwrap();
    let documents = [NativeSourceDocument {
        kind: NativeSourceKind::Prefab,
        bytes: &source,
    }];
    // A candidate is not a registration. Actual global identity/newness is
    // checked inside runtime against the same protected Store before commit.
    let prepared = fixture
        .prepare_raw(
            &documents,
            &[],
            &[NativeRawSourceResource {
                metadata: &metadata,
                bytes,
            }],
        )
        .unwrap();
    assert_eq!(
        prepared.commit(&mut fixture.store).unwrap_err().code,
        "REVISION_CONFLICT"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
}

#[test]
fn raw_source_metadata_and_content_are_strict_bounded_and_not_self_authorizing() {
    let fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let bytes = b"actual source content";
    let source = encode_json(&prefab()).unwrap();
    let documents = [NativeSourceDocument {
        kind: NativeSourceKind::Prefab,
        bytes: &source,
    }];
    let metadata = json!({"resourceId":"resource-new-raw","sha256":raw_digest(bytes),
        "mediaType":"text/plain","sizeBytes":bytes.len()});
    let encoded = encode_json(&metadata).unwrap();
    assert_eq!(
        fixture
            .prepare_raw(
                &documents,
                &[],
                &[NativeRawSourceResource {
                    metadata: &encoded,
                    bytes: b"different content",
                }]
            )
            .err()
            .unwrap()
            .code,
        "INPUT_DIGEST_MISMATCH"
    );
    let duplicate = [
        b"{\"resourceId\":\"replacement\",".as_slice(),
        &encoded[1..],
    ]
    .concat();
    assert_eq!(
        fixture
            .prepare_raw(
                &documents,
                &[],
                &[NativeRawSourceResource {
                    metadata: &duplicate,
                    bytes,
                }]
            )
            .err()
            .unwrap()
            .code,
        "INVALID_INPUT"
    );
    let repeated = [
        NativeRawSourceResource {
            metadata: &encoded,
            bytes,
        },
        NativeRawSourceResource {
            metadata: &encoded,
            bytes,
        },
    ];
    assert_eq!(
        fixture
            .prepare_raw(&documents, &[], &repeated)
            .err()
            .unwrap()
            .code,
        "REVISION_CONFLICT"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
}

#[test]
fn resource_only_input_rejects_empty_batch_and_mismatched_raw_bytes() {
    let fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    assert_eq!(
        fixture.prepare(&[], &[]).err().unwrap().code,
        "BUDGET_EXCEEDED"
    );
    let bytes = b"exact retained container input\n";
    let metadata = json!({"resourceId":"resource-only-denied","sha256":raw_digest(bytes),
        "mediaType":"application/octet-stream","sizeBytes":bytes.len()});
    let metadata_bytes = encode_json(&metadata).unwrap();
    let mut altered = bytes.to_vec();
    altered[0] ^= 1;
    assert_eq!(
        fixture
            .prepare_raw(
                &[],
                &[],
                &[NativeRawSourceResource {
                    metadata: &metadata_bytes,
                    bytes: &altered,
                }],
            )
            .err()
            .unwrap()
            .code,
        "INPUT_DIGEST_MISMATCH"
    );
    let mut wrong_length = metadata;
    wrong_length["sizeBytes"] = json!(bytes.len() + 1);
    let wrong_length = encode_json(&wrong_length).unwrap();
    assert_eq!(
        fixture
            .prepare_raw(
                &[],
                &[],
                &[NativeRawSourceResource {
                    metadata: &wrong_length,
                    bytes,
                }],
            )
            .err()
            .unwrap()
            .code,
        "INPUT_DIGEST_MISMATCH"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
}

#[test]
fn same_batch_clip_is_order_independent_preserves_raw_bytes_and_survives_head_carry() {
    let mut fixture = Fixture::new();
    let (owner, clip) = clip_owner();
    let instance_value = instance(&owner);
    let owner_bytes = encode_json(&owner).unwrap();
    let clip_bytes = [b"\n ".as_slice(), &encode_json(&clip).unwrap(), b" \n"].concat();
    let instance_bytes = encode_json(&instance_value).unwrap();
    // Clip precedes both its owner and Instance. All cross references resolve
    // from the same immutable batch, never the supplied array order.
    let sources = [
        NativeSourceDocument {
            kind: NativeSourceKind::Clip,
            bytes: &clip_bytes,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::Instance,
            bytes: &instance_bytes,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &owner_bytes,
        },
    ];
    let receipt = fixture
        .prepare(&sources, &[])
        .unwrap()
        .commit(&mut fixture.store)
        .unwrap();
    let stored_clip = receipt
        .documents
        .iter()
        .find(|(pin, _)| pin.kind == OwnedDocumentKind::AnimationClip)
        .unwrap();
    assert_eq!(
        stored_clip.0.revision.as_str(),
        clip["revision"].as_str().unwrap()
    );
    assert_eq!(fixture.store.read_blob(&stored_clip.1).unwrap(), clip_bytes);
    assert_ne!(stored_clip.1.digest, stored_clip.0.revision);
    let renewed_authority = LocalAuthority::new(HostBridge::default());
    let renewed = prepare_workspace(
        &fixture.store,
        &renewed_authority,
        &fixture.project,
        fixture.budget.deadline(),
    )
    .unwrap();
    assert!(renewed.excluded_sources.is_empty());
    assert!(
        renewed.context["scope"]["objectIds"]
            .as_array()
            .unwrap()
            .contains(&clip["clipId"])
    );

    let mut additional = prefab();
    additional["prefabId"] = json!("prefab-additional-after-clip");
    additional["revision"] = json!(projected_digest("Prefab", &additional).unwrap());
    let additional_bytes = encode_json(&additional).unwrap();
    let additional_source = [NativeSourceDocument {
        kind: NativeSourceKind::Prefab,
        bytes: &additional_bytes,
    }];
    let next = prepare_native_sources(
        &fixture.store,
        &renewed.witness,
        &renewed_authority,
        &fixture.budget,
        &NativeSourceInput {
            project: &fixture.project,
            expected_revision: &receipt.project_revision,
            documents: &additional_source,
            retained_resources: &[],
            raw_resources: &[],
        },
    )
    .unwrap()
    .commit(&mut fixture.store)
    .unwrap();
    let carried = mmmm_runtime::storage::owned_documents::read_owned_document(
        &fixture.store,
        &fixture.project,
        &next.project_revision,
        &stored_clip.0,
    )
    .unwrap();
    assert_eq!(carried, clip);
    assert_eq!(fixture.store.read_blob(&stored_clip.1).unwrap(), clip_bytes);
}

#[test]
fn clip_owner_node_and_event_symbol_require_actual_authored_bindings() {
    let fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let (owner, valid_clip) = clip_owner();
    let owner_bytes = encode_json(&owner).unwrap();
    for (case, expected) in [
        ("owner", "SOURCE_UNAVAILABLE"),
        ("node", "REFERENCE_UNRESOLVED"),
        ("event", "REFERENCE_UNRESOLVED"),
    ] {
        let mut clip = valid_clip.clone();
        match case {
            "owner" => clip["ownerPrefabId"] = json!("prefab-unavailable"),
            "node" => clip["tracks"][0]["nodeId"] = json!("node-unavailable"),
            "event" => {
                clip["events"] = json!([{
                    "eventId":"event-unbound", "at":{"numerator":"0","denominator":"1"},
                    "functionSymbolId":"function-unavailable", "scrubPolicy":"suppress", "authoredSequence":0,
                }])
            }
            _ => unreachable!(),
        }
        clip["revision"] = json!(projected_digest("AnimationClip", &clip).unwrap());
        let bytes = encode_json(&clip).unwrap();
        let sources = [
            NativeSourceDocument {
                kind: NativeSourceKind::Prefab,
                bytes: &owner_bytes,
            },
            NativeSourceDocument {
                kind: NativeSourceKind::Clip,
                bytes: &bytes,
            },
        ];
        assert_eq!(
            fixture.prepare(&sources, &[]).err().unwrap().code,
            expected,
            "{case}"
        );
        assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
    }
}

#[test]
fn clip_rejects_invalid_time_and_wrong_projected_pin_without_publication() {
    let fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let (owner, clip) = clip_owner();
    let owner_bytes = encode_json(&owner).unwrap();
    let mut changed = clip.clone();
    changed["duration"]["numerator"] = json!("3");
    let wrong_pin = encode_json(&changed).unwrap();
    let sources = [
        NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &owner_bytes,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::Clip,
            bytes: &wrong_pin,
        },
    ];
    assert_eq!(
        fixture.prepare(&sources, &[]).err().unwrap().code,
        "INPUT_DIGEST_MISMATCH"
    );
    changed["revision"] = json!(projected_digest("AnimationClip", &changed).unwrap());
    // Its sample endpoint is still the original duration, so a correct digest
    // does not hide the actual authored time inconsistency.
    let invalid_time = encode_json(&changed).unwrap();
    let sources = [
        NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &owner_bytes,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::Clip,
            bytes: &invalid_time,
        },
    ];
    assert_eq!(
        fixture.prepare(&sources, &[]).err().unwrap().code,
        "INVALID_TIME"
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
}

#[test]
fn authored_clip_flags_and_function_declarations_do_not_become_runtime_proofs() {
    let fixture = Fixture::new();
    let before = fixture.store.project(&fixture.project).unwrap();
    let (mut owner, mut clip) = clip_owner();
    owner["references"] = json!([{"symbolId":"function-authored", "kind":"function",
        "scope":"external", "targetId":"unverified:event"}]);
    owner["revision"] = json!(projected_digest("Prefab", &owner).unwrap());
    clip["requiresBake"] = json!(true);
    clip["poseWriter"] = json!("external_physics");
    clip["timeDomain"] = json!("wall_seconds");
    clip["events"] = json!([{"eventId":"event-authored", "at":{"numerator":"0","denominator":"1"},
        "functionSymbolId":"function-authored", "scrubPolicy":"suppress", "authoredSequence":0}]);
    clip["revision"] = json!(projected_digest("AnimationClip", &clip).unwrap());
    let owner_bytes = encode_json(&owner).unwrap();
    let clip_bytes = encode_json(&clip).unwrap();
    let sources = [
        NativeSourceDocument {
            kind: NativeSourceKind::Clip,
            bytes: &clip_bytes,
        },
        NativeSourceDocument {
            kind: NativeSourceKind::Prefab,
            bytes: &owner_bytes,
        },
    ];
    let candidate = fixture.prepare(&sources, &[]).unwrap();
    let original = &candidate
        .documents
        .iter()
        .find(|document| document.pin.kind == OwnedDocumentKind::AnimationClip)
        .unwrap()
        .value;
    assert_eq!(original, &parse_json(&clip_bytes).unwrap());
    assert_eq!(
        candidate
            .documents
            .iter()
            .find(|document| document.pin.kind == OwnedDocumentKind::AnimationClip)
            .unwrap()
            .original_bytes,
        clip_bytes
    );
    assert_eq!(fixture.store.project(&fixture.project).unwrap(), before);
    assert!(
        fixture.store.project(&fixture.project).unwrap()["ownedResources"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

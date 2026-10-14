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

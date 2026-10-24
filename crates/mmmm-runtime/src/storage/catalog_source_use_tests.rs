//! 기존 native_owned_sources의 보호 SQLite/CAS/bootstrap/Batch fixture를 재사용한다.
//! 실제 게임/native kernel admission을 흉내 내지 않고 trusted storage port와
//! 실제 metadata/association/원자적 교체를 검증한다. 별도 fixture 디렉터리는 만들지 않는다.

use super::*;
use crate::storage::catalog_source_use::{
    CatalogSourceUseAction, CatalogSourceUseCurrent, CatalogSourceUsePermit,
    CatalogSourceUseReplace, CatalogSourceUseRole, CatalogSourceUseSelection,
    CatalogSourceUseSnapshot, inspect_catalog_source_use_state, read_catalog_source_uses,
    replace_catalog_source_uses,
};
use std::cell::RefCell;

#[derive(Clone, Copy, PartialEq, Eq)]
enum AfterPublish {
    None,
    Cancel,
    RevokeOwner,
}
struct UsePermit {
    source: TestPermit,
    policy_digest: Sha256Digest,
    denied: Rc<RefCell<Option<ResourceId>>>,
    after_publish: Cell<AfterPublish>,
    game_context: Option<ContextId>,
}
impl UsePermit {
    fn new(root: &TestRoot, initial: &ProjectBootstrapReceipt) -> Self {
        Self {
            source: TestPermit::new(root, initial),
            policy_digest: serde_json::from_value(initial.policy_resource["sha256"].clone())
                .unwrap(),
            denied: Rc::new(RefCell::new(None)),
            after_publish: Cell::new(AfterPublish::None),
            game_context: None,
        }
    }
}
impl ProjectSourceRpcContext for UsePermit {
    fn check(&self) -> StorageResult<()> {
        self.source.check()
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.source.authenticated_principal()
    }
    fn context_id(&self) -> Option<&ContextId> {
        self.game_context.as_ref()
    }
}
struct UseReader {
    original: SqlReadAuthority,
    denied: Rc<RefCell<Option<ResourceId>>>,
}
impl ProjectResourceAuthority for UseReader {
    fn authorize_project_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        revision: &Sha256Digest,
    ) -> StorageResult<()> {
        // 이 test port는 native 관리자용이며 실제 game consumer 구현을 가정하지 않는다.
        ProjectResourceAuthority::authorize_project_read(
            &mut self.original,
            store,
            principal,
            context,
            project,
            revision,
        )
    }
    fn authorize_resource_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> StorageResult<()> {
        ProjectResourceAuthority::authorize_resource_read(
            &mut self.original,
            store,
            principal,
            context,
            project,
            resource,
        )?;
        if self
            .denied
            .borrow()
            .as_ref()
            .is_some_and(|id| resource.resource["resourceId"] == id.as_str())
        {
            return Err(StorageError::Conflict(
                "Catalog fixture resource read revoked",
            ));
        }
        Ok(())
    }
}
impl CatalogSourceUsePermit for UsePermit {
    fn check_store(&self, store: &DurableStore) -> StorageResult<()> {
        NativeOwnedSourceCommitPermit::check_store(&self.source, store)
    }
    fn authenticated_native_owner(
        &self,
        store: &DurableStore,
        project: &ProjectId,
    ) -> StorageResult<PrincipalId> {
        self.check_store(store)?;
        if project != &self.source.0.project {
            return Err(StorageError::Conflict("Catalog fixture Project mismatch"));
        }
        Ok(self.source.0.owner.clone())
    }
    fn authorize_current(
        &self,
        store: &DurableStore,
        current: &CatalogSourceUseCurrent<'_>,
    ) -> StorageResult<()> {
        self.check_store(store)?;
        if current.native_owner != &self.source.0.owner
            || current.policy_resource.blob.digest != self.policy_digest
            || current.policy != &example("policy.json")
        {
            return Err(StorageError::Conflict(
                "Catalog fixture current owner/policy mismatch",
            ));
        }
        let table: bool = store.connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='catalog_source_uses')", [], |row| row.get(0))?;
        let published: bool = if table {
            store.connection.query_row("SELECT EXISTS(SELECT 1 FROM catalog_source_uses WHERE native_owner=?1 AND project_id=?2 AND generation>=2)", params![current.native_owner.as_str(),self.source.0.project.as_str()], |row| row.get(0))?
        } else {
            false
        };
        if current.action == CatalogSourceUseAction::Replace && published {
            match self.after_publish.get() {
                AfterPublish::None => (),
                AfterPublish::Cancel => self.source.0.cancelled.set(true),
                AfterPublish::RevokeOwner => {
                    store.connection.execute("UPDATE native_project_owners SET owner_principal='catalog-revoked-owner' WHERE project_id=?1", [self.source.0.project.as_str()])?;
                }
            }
        }
        self.check_store(store)
    }
    fn resource_reader(&self, ceiling: u64) -> StorageResult<ProjectResourceReader> {
        ProjectResourceReader::new(
            Box::new(UseReader {
                original: SqlReadAuthority(self.source.0.clone()),
                denied: self.denied.clone(),
            }),
            ceiling,
        )
    }
}

fn seed() -> (TestRoot, DurableStore, Value, ProjectBootstrapReceipt) {
    let root = TestRoot::new();
    let mut store = root.store();
    let (base, initial) = bootstrap(&mut store, &root, "project-fixture", "policy-local");
    // 유효한 empty ZIP의 EOCD와 주석이 있는 empty ZIP이다. 별도 game 자산은 없다.
    let mut archive = b"PK\x05\x06".to_vec();
    archive.extend_from_slice(&[0; 18]);
    let mut other = archive.clone();
    other[20] = 1;
    other.push(b'x');
    let resources = [
        ("catalog-game-container", archive),
        ("catalog-mod-container", other),
    ]
    .into_iter()
    .map(|(id, bytes)| {
        (
            json!({"resourceId":id,"sha256":raw_digest(&bytes),
            "mediaType":"application/java-archive","sizeBytes":bytes.len()}),
            bytes,
        )
    })
    .collect();
    let batch = Batch::from_sources(&base, Vec::new(), resources);
    batch
        .commit(&mut store, &TestPermit::new(&root, &initial), &base)
        .unwrap();
    (root, store, batch.next, initial)
}
fn game() -> CatalogSourceUseSelection {
    CatalogSourceUseSelection {
        resource_id: ResourceId::new("catalog-game-container").unwrap(),
        role: CatalogSourceUseRole::GameArtifact,
    }
}
fn mod_source() -> CatalogSourceUseSelection {
    CatalogSourceUseSelection {
        resource_id: ResourceId::new("catalog-mod-container").unwrap(),
        role: CatalogSourceUseRole::Mod {
            canonical_id: "example:fixture".parse().unwrap(),
            native_id: "fixture_mod".into(),
        },
    }
}
fn inspect(store: &DurableStore, permit: &UsePermit, project: &Value) -> CatalogSourceUseSnapshot {
    inspect_catalog_source_use_state(store, permit, &permit.source.0.project, &revision(project))
        .unwrap()
}
fn replace(
    store: &mut DurableStore,
    permit: &UsePermit,
    project: &Value,
    expected: &Sha256Digest,
    selections: &[CatalogSourceUseSelection],
) -> StorageResult<CatalogSourceUseSnapshot> {
    replace_catalog_source_uses(
        store,
        permit,
        &CatalogSourceUseReplace {
            project: &permit.source.0.project,
            expected_project_revision: &revision(project),
            expected_state_digest: expected,
            selections,
        },
    )
}
fn read(
    store: &DurableStore,
    permit: &UsePermit,
    project: &Value,
) -> StorageResult<CatalogSourceUseSnapshot> {
    read_catalog_source_uses(store, permit, &permit.source.0.project, &revision(project))
}

#[test]
fn absent_import_and_restart_do_not_create_source_use_approval() {
    let (root, store, project, initial) = seed();
    let permit = UsePermit::new(&root, &initial);
    let absent = inspect(&store, &permit, &project);
    assert_eq!(absent.generation(), 0);
    assert!(absent.selections().is_empty());
    assert!(absent.approved_project_revision().is_none());
    assert_eq!(read(&store, &permit, &project).unwrap(), absent);
    let created: bool = store
        .connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='catalog_source_uses')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!created);
    drop(store);
    let store = DurableStore::open_existing(StoreConfig::new(root.0.clone())).unwrap();
    assert_eq!(
        read(&store, &UsePermit::new(&root, &initial), &project).unwrap(),
        absent
    );
}

#[test]
fn selected_whole_containers_are_derived_rechecked_and_retained_across_restart() {
    let (root, mut store, project, initial) = seed();
    let permit = UsePermit::new(&root, &initial);
    let before = inspect(&store, &permit, &project);
    let selected = replace(
        &mut store,
        &permit,
        &project,
        before.state_digest(),
        &[mod_source(), game()],
    )
    .unwrap();
    assert_eq!(selected.generation(), 1);
    assert_eq!(selected.rights(), "user_local_only");
    assert_eq!(selected.selections().len(), 2);
    assert_eq!(
        selected.approved_project_revision(),
        Some(&revision(&project))
    );
    for pin in selected.selections() {
        assert_eq!(
            pin.resource()["resourceId"],
            pin.selection().resource_id.as_str()
        );
        assert_eq!(pin.resource()["sha256"], pin.blob().digest.as_str());
        assert_eq!(
            pin.resource()["sizeBytes"].as_u64(),
            Some(pin.blob().byte_length)
        );
    }
    assert_eq!(read(&store, &permit, &project).unwrap(), selected);
    drop(store);
    let store = DurableStore::open_existing(StoreConfig::new(root.0.clone())).unwrap();
    assert_eq!(
        read(&store, &UsePermit::new(&root, &initial), &project).unwrap(),
        selected
    );
}

#[test]
fn carried_current_provenance_preserves_exact_original_approval_but_missing_history_does_not() {
    let (root, mut store, project, initial) = seed();
    let permit = UsePermit::new(&root, &initial);
    let before = inspect(&store, &permit, &project);
    let selected = replace(
        &mut store,
        &permit,
        &project,
        before.state_digest(),
        &[game()],
    )
    .unwrap();
    let bytes = b"unrelated retained authored bytes".to_vec();
    let resource = json!({"resourceId":"catalog-unrelated-resource","sha256":raw_digest(&bytes),
        "mediaType":"application/octet-stream","sizeBytes":bytes.len()});
    let batch = Batch::from_sources(&project, Vec::new(), vec![(resource, bytes)]);
    batch
        .commit(&mut store, &TestPermit::new(&root, &initial), &project)
        .unwrap();
    assert_eq!(read(&store, &permit, &batch.next).unwrap(), selected);
    assert_eq!(
        replace(
            &mut store,
            &permit,
            &batch.next,
            selected.state_digest(),
            &[game()]
        )
        .unwrap(),
        selected
    );
    // 현재 association을 남긴 채 승인 시점의 출처만 지운다. 새 Project로 옛 출처를 복구하지 않는다.
    store.connection.execute("DELETE FROM project_resource_provenance WHERE project_id=?1 AND project_revision=?2 AND resource_id='catalog-game-container'", params![initial.project_id.as_str(),revision(&project).as_str()]).unwrap();
    assert!(read(&store, &permit, &batch.next).is_err());
    assert_eq!(inspect(&store, &permit, &batch.next), selected);
}

#[test]
fn optimistic_retry_withdrawal_and_readdition_never_accept_an_old_generation() {
    let (root, mut store, project, initial) = seed();
    let permit = UsePermit::new(&root, &initial);
    let absent = inspect(&store, &permit, &project);
    let first = replace(
        &mut store,
        &permit,
        &project,
        absent.state_digest(),
        &[game()],
    )
    .unwrap();
    assert_eq!(
        replace(
            &mut store,
            &permit,
            &project,
            absent.state_digest(),
            &[game()]
        )
        .unwrap(),
        first
    );
    assert_eq!(
        replace(
            &mut store,
            &permit,
            &project,
            first.state_digest(),
            &[game()]
        )
        .unwrap(),
        first
    );
    assert!(
        replace(
            &mut store,
            &permit,
            &project,
            absent.state_digest(),
            &[mod_source()]
        )
        .is_err()
    );
    let withdrawn = replace(&mut store, &permit, &project, first.state_digest(), &[]).unwrap();
    assert_eq!(withdrawn.generation(), 2);
    assert!(withdrawn.selections().is_empty());
    assert_ne!(withdrawn.state_digest(), absent.state_digest());
    assert_eq!(
        replace(&mut store, &permit, &project, first.state_digest(), &[]).unwrap(),
        withdrawn
    );
    assert!(
        replace(
            &mut store,
            &permit,
            &project,
            absent.state_digest(),
            &[game()]
        )
        .is_err()
    );
    let readded = replace(
        &mut store,
        &permit,
        &project,
        withdrawn.state_digest(),
        &[game()],
    )
    .unwrap();
    assert_eq!(readded.generation(), 3);
    assert_ne!(first.state_digest(), readded.state_digest());
    assert!(
        replace(
            &mut store,
            &permit,
            &project,
            first.state_digest(),
            &[game()]
        )
        .is_err()
    );
    assert_eq!(read(&store, &permit, &project).unwrap(), readded);
}

#[test]
fn explicit_empty_absent_selection_is_a_durable_tombstone() {
    let (root, mut store, project, initial) = seed();
    let permit = UsePermit::new(&root, &initial);
    let absent = inspect(&store, &permit, &project);
    let withdrawn = replace(&mut store, &permit, &project, absent.state_digest(), &[]).unwrap();
    assert_eq!(withdrawn.generation(), 1);
    assert!(withdrawn.selections().is_empty());
    assert_ne!(withdrawn.state_digest(), absent.state_digest());
    assert_eq!(
        replace(&mut store, &permit, &project, absent.state_digest(), &[]).unwrap(),
        withdrawn
    );
    drop(store);
    let store = DurableStore::open_existing(StoreConfig::new(root.0.clone())).unwrap();
    assert_eq!(
        read(&store, &UsePermit::new(&root, &initial), &project).unwrap(),
        withdrawn
    );
}

#[test]
fn different_store_owner_stale_project_and_current_policy_fail_without_publication() {
    let (root, mut store, project, initial) = seed();
    let permit = UsePermit::new(&root, &initial);
    let absent = inspect(&store, &permit, &project);
    let other_root = TestRoot::new();
    let mut other_store = other_root.store();
    assert!(
        replace(
            &mut other_store,
            &permit,
            &project,
            absent.state_digest(),
            &[game()]
        )
        .is_err()
    );
    let mut other_initial = initial.clone();
    other_initial.owner_principal = PrincipalId::new("another-native-owner").unwrap();
    assert!(
        replace(
            &mut store,
            &UsePermit::new(&root, &other_initial),
            &project,
            absent.state_digest(),
            &[game()]
        )
        .is_err()
    );
    let stale = CatalogSourceUseReplace {
        project: &initial.project_id,
        expected_project_revision: &initial.project_revision,
        expected_state_digest: absent.state_digest(),
        selections: &[game()],
    };
    assert!(replace_catalog_source_uses(&mut store, &permit, &stale).is_err());
    let mut wrong_policy = UsePermit::new(&root, &initial);
    wrong_policy.policy_digest = raw_digest(b"different current policy");
    assert!(
        replace(
            &mut store,
            &wrong_policy,
            &project,
            absent.state_digest(),
            &[game()]
        )
        .is_err()
    );
    assert_eq!(inspect(&store, &permit, &project), absent);
}

#[test]
fn revoked_resource_or_missing_original_association_denies_read_but_allows_owner_withdrawal() {
    for remove_provenance in [false, true] {
        let (root, mut store, project, initial) = seed();
        let permit = UsePermit::new(&root, &initial);
        let absent = inspect(&store, &permit, &project);
        let first = replace(
            &mut store,
            &permit,
            &project,
            absent.state_digest(),
            &[game()],
        )
        .unwrap();
        if remove_provenance {
            store.connection.execute("DELETE FROM project_resource_provenance WHERE project_id=?1 AND project_revision=?2 AND resource_id='catalog-game-container'", params![initial.project_id.as_str(),revision(&project).as_str()]).unwrap();
        } else {
            *permit.denied.borrow_mut() = Some(game().resource_id);
        }
        assert!(read(&store, &permit, &project).is_err());
        assert_eq!(inspect(&store, &permit, &project), first);
        let withdrawn = replace(&mut store, &permit, &project, first.state_digest(), &[]).unwrap();
        assert_eq!(withdrawn.generation(), 2);
        assert!(withdrawn.selections().is_empty());
        assert_eq!(read(&store, &permit, &project).unwrap(), withdrawn);
    }
}

#[test]
fn same_length_cas_corruption_rejects_use_without_losing_the_owner_withdrawal_path() {
    let (root, mut store, project, initial) = seed();
    let permit = UsePermit::new(&root, &initial);
    let absent = inspect(&store, &permit, &project);
    let first = replace(
        &mut store,
        &permit,
        &project,
        absent.state_digest(),
        &[game()],
    )
    .unwrap();
    let blob = first.selections()[0].blob();
    let path = store.cas.path(&blob.digest);
    assert!(path.is_absolute() && path.starts_with(&root.0));
    crate::storage::cas::verify_plain_path(&path).unwrap();
    // 이 fixture의 정확한 CAS 파일만 같은 길이의 다른 bytes로 바꾼다.
    fs::write(path, vec![0; blob.byte_length as usize]).unwrap();
    assert!(read(&store, &permit, &project).is_err());
    assert!(
        replace(
            &mut store,
            &permit,
            &project,
            first.state_digest(),
            &[game()]
        )
        .is_err()
    );
    assert_eq!(inspect(&store, &permit, &project), first);
    let withdrawn = replace(&mut store, &permit, &project, first.state_digest(), &[]).unwrap();
    assert_eq!(withdrawn.generation(), 2);
    assert!(withdrawn.selections().is_empty());
}

#[test]
fn provisional_owner_revocation_or_cancellation_rolls_back_the_exact_prior_state() {
    for failure in [AfterPublish::Cancel, AfterPublish::RevokeOwner] {
        let (root, mut store, project, initial) = seed();
        let permit = UsePermit::new(&root, &initial);
        let absent = inspect(&store, &permit, &project);
        let first = replace(
            &mut store,
            &permit,
            &project,
            absent.state_digest(),
            &[game()],
        )
        .unwrap();
        permit.after_publish.set(failure);
        assert!(
            replace(
                &mut store,
                &permit,
                &project,
                first.state_digest(),
                &[mod_source()]
            )
            .is_err()
        );
        let restored = UsePermit::new(&root, &initial);
        assert_eq!(
            registered_native_project_owner(&store, &initial.project_id).unwrap(),
            initial.owner_principal
        );
        assert_eq!(read(&store, &restored, &project).unwrap(), first);
    }
}

#[test]
fn sql_abort_preserves_prior_selection_and_unrelated_project_metadata() {
    let (root, mut store, project, initial) = seed();
    let permit = UsePermit::new(&root, &initial);
    let absent = inspect(&store, &permit, &project);
    let first = replace(
        &mut store,
        &permit,
        &project,
        absent.state_digest(),
        &[game()],
    )
    .unwrap();
    let baseline = metadata_snapshot(&store);
    store.connection.execute_batch("CREATE TEMP TRIGGER catalog_source_update_fail BEFORE UPDATE ON catalog_source_uses BEGIN SELECT RAISE(ABORT,'catalog source injected commit failure'); END;").unwrap();
    assert!(
        replace(
            &mut store,
            &permit,
            &project,
            first.state_digest(),
            &[mod_source()]
        )
        .is_err()
    );
    store
        .connection
        .execute_batch("DROP TRIGGER catalog_source_update_fail;")
        .unwrap();
    assert_eq!(metadata_snapshot(&store), baseline);
    assert_eq!(read(&store, &permit, &project).unwrap(), first);
}

#[test]
fn closed_roles_mod_mapping_selection_count_and_metadata_budget_are_enforced() {
    let (root, mut store, project, initial) = seed();
    let permit = UsePermit::new(&root, &initial);
    let absent = inspect(&store, &permit, &project);
    assert!(
        replace(
            &mut store,
            &permit,
            &project,
            absent.state_digest(),
            &[game(), game()]
        )
        .is_err()
    );
    assert!(
        replace(
            &mut store,
            &permit,
            &project,
            absent.state_digest(),
            &[mod_source(), mod_source()]
        )
        .is_err()
    );
    assert!(serde_json::from_value::<CatalogSourceUseRole>(json!({"kind":"client_pack"})).is_err());
    let selections = (0..257)
        .map(|index| CatalogSourceUseSelection {
            resource_id: game().resource_id,
            role: CatalogSourceUseRole::Mod {
                canonical_id: format!("example:mod_{index}").parse().unwrap(),
                native_id: format!("mod_{index}"),
            },
        })
        .collect::<Vec<_>>();
    assert!(
        replace(
            &mut store,
            &permit,
            &project,
            absent.state_digest(),
            &selections
        )
        .is_err()
    );
    // 256개는 개수 상한 안이어도 exact metadata 합계가 64 KiB를 넘는다.
    assert!(
        replace(
            &mut store,
            &permit,
            &project,
            absent.state_digest(),
            &selections[..256]
        )
        .is_err()
    );
    assert_eq!(inspect(&store, &permit, &project), absent);
}

#[test]
fn management_with_a_game_context_and_missing_or_noncontainer_resource_are_rejected() {
    let (root, mut store, project, initial) = seed();
    let mut permit = UsePermit::new(&root, &initial);
    let absent = inspect(&store, &permit, &project);
    permit.game_context = Some(ContextId::new("game-context-fixture").unwrap());
    assert!(
        replace(
            &mut store,
            &permit,
            &project,
            absent.state_digest(),
            &[game()]
        )
        .is_err()
    );
    permit.game_context = None;
    let missing = CatalogSourceUseSelection {
        resource_id: ResourceId::new("missing-whole-container").unwrap(),
        role: CatalogSourceUseRole::GameArtifact,
    };
    assert!(
        replace(
            &mut store,
            &permit,
            &project,
            absent.state_digest(),
            &[missing]
        )
        .is_err()
    );
    let policy_as_container = CatalogSourceUseSelection {
        resource_id: ResourceId::new("policy-local").unwrap(),
        role: CatalogSourceUseRole::GameArtifact,
    };
    assert!(
        replace(
            &mut store,
            &permit,
            &project,
            absent.state_digest(),
            &[policy_as_container]
        )
        .is_err()
    );
    assert_eq!(inspect(&store, &permit, &project), absent);
}

#[test]
fn unresolved_project_write_fences_rebinding_and_empty_withdrawal_without_erasing_decision() {
    use crate::storage::ReserveOperation;
    let (root, mut store, project, initial) = seed();
    let permit = UsePermit::new(&root, &initial);
    let absent = inspect(&store, &permit, &project);
    let first = replace(
        &mut store,
        &permit,
        &project,
        absent.state_digest(),
        &[game()],
    )
    .unwrap();
    let mut plan = example("execution-plan.json");
    plan["projectId"] = json!(initial.project_id);
    plan["scope"]["projectId"] = json!(initial.project_id);
    plan["scope"]["resourceIds"] = json!(["unrelated-fenced-resource"]);
    plan["steps"][0]["effect"] = json!("write");
    plan["steps"][0]["resourcesWritten"] = json!(["unrelated-fenced-resource"]);
    plan["steps"][0]["verificationRequirement"] = json!("independent_readback");
    plan["projectBaseRevision"] = json!(revision(&project));
    plan["planHash"] = json!(projected_digest("ExecutionPlan", &plan).unwrap());
    store.save_plan(&plan).unwrap();
    let operation = OperationId::new("catalog-use-fenced-operation").unwrap();
    store
        .reserve_operation(ReserveOperation {
            operation_id: operation.clone(),
            principal: PrincipalId::new("principal-fixture").unwrap(),
            project_id: initial.project_id.clone(),
            idempotency_key: "catalog-use-fence-key".into(),
            plan_id: PlanId::new(plan["planId"].as_str().unwrap()).unwrap(),
            plan_hash: serde_json::from_value(plan["planHash"].clone()).unwrap(),
            context_id: ContextId::new("context-fixture-01").unwrap(),
        })
        .unwrap();
    let mut invocation = example("invocation.json");
    invocation["operationId"] = json!(operation);
    store
        .dispatch_intent(&operation, &StepId::new("echo-step").unwrap(), &invocation)
        .unwrap();
    assert!(
        matches!(replace(&mut store, &permit, &project, first.state_digest(), &[mod_source()]), Err(StorageError::Fenced(operations)) if operations == vec![operation.clone()])
    );
    assert!(
        matches!(replace(&mut store, &permit, &project, first.state_digest(), &[]), Err(StorageError::Fenced(operations)) if operations == vec![operation.clone()])
    );
    // 사실 조회와 이미 허용된 read는 fence를 approval 삭제나 새 권한으로 해석하지 않는다.
    assert_eq!(inspect(&store, &permit, &project), first);
    assert_eq!(read(&store, &permit, &project).unwrap(), first);
}

//! Real protected Store/native Project initialization exercises composition.
//! The original Prefab example is reused for pure-domain behavior; no game,
//! profile approval, permission evidence or redistribution fixture is invented.

use super::*;
use crate::{
    auth::{SessionAuthority, SessionPolicy},
    authority::LocalAuthority,
    features::{FEATURE_METHODS, FeatureExtension},
    host::HostBridge,
    native_project::create_native_project,
    planning_source::{PlanningComposition, StoreAwarePlanner},
    service::{
        ApplicationPorts, ApplicationService, ExtensionRouter, RequestContextSlot,
        ServiceDispatcher,
    },
    workspace_bootstrap::prepare_workspace,
};
use mmmm_application::{IdKind, IdSource, SystemClock};
use mmmm_contracts::{TargetProfileId, parse_json, raw_digest};
use mmmm_runtime::storage::StoreConfig;
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const MARKER: &[u8] = b"mmmm-production-factory-test-v1\n";
struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let parent = fs::canonicalize(parent).unwrap();
        let path = parent.join(format!(
            "mmmm-production-factory-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(path.is_absolute() && !path.exists());
        let checkout =
            fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        assert!(!path.starts_with(checkout));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = fs::canonicalize(path).unwrap();
        assert_eq!(path.parent(), Some(parent.as_path()));
        fs::write(path.join("test-owner.txt"), MARKER).unwrap();
        Self(path)
    }
    fn open(&self) -> DurableStore {
        DurableStore::open(StoreConfig::new(self.0.clone())).unwrap()
    }
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        let mut count = 0;
        if fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0)
            && fs::read(self.0.join("test-owner.txt")).ok().as_deref() == Some(MARKER)
            && plain_tree(&self.0, &self.0, 0, &mut count)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
fn plain_tree(path: &Path, root: &Path, depth: usize, count: &mut usize) -> bool {
    if !path.starts_with(root) || depth > 16 || *count >= 1024 {
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
            if !plain_tree(&entry.path(), root, depth + 1, count) {
                return false;
            }
        }
    } else if !metadata.is_file() {
        return false;
    }
    true
}

fn binary_digest() -> Sha256Digest {
    // Pin this actual running Rust test executable, never a host JAR or
    // fabricated known-good profile/source digest. This is not release evidence.
    let executable = std::env::current_exe().unwrap();
    assert!(fs::metadata(&executable).unwrap().len() <= 256 * 1024 * 1024);
    raw_digest(&fs::read(executable).unwrap())
}
fn handles(store: &mut DurableStore) -> DaemonHandles {
    let created = create_native_project(
        store,
        "Owned offline composition",
        &TargetProfileId::new("unverified-native-target").unwrap(),
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    let hosts = HostBridge::default();
    let authority = LocalAuthority::new(hosts.clone());
    let workspace = prepare_workspace(
        store,
        &authority,
        &created.project_id,
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(workspace.witness.principal(), &created.owner_principal);
    DaemonHandles {
        hosts,
        authority,
        request: RequestContextSlot::default(),
        configured_project: Some(created.project_id),
        workspace: Some(workspace),
    }
}
fn error_code(result: Result<DaemonSourceParts, ServiceError>) -> &'static str {
    match result {
        Ok(_) => panic!("Composition unexpectedly accepted an unavailable source"),
        Err(error) => error.code,
    }
}

#[test]
fn explicit_project_and_actual_workspace_are_required_before_installation() {
    let root = TestRoot::new();
    let mut store = root.open();
    let handles = handles(&mut store);
    let mut factory = ProductionFactory::offline_owned(binary_digest());
    let mut missing = handles.clone();
    missing.configured_project = None;
    assert_eq!(
        error_code(factory.compose(&missing, &store)),
        "COMPOSITION_PROJECT_REQUIRED"
    );
    missing = handles.clone();
    missing.workspace = None;
    assert_eq!(
        error_code(factory.compose(&missing, &store)),
        "COMPOSITION_WORKSPACE_REQUIRED"
    );
    assert!(factory.registries().is_none());
    // Preflight errors did not install a resolver or consume the composition.
    let parts = factory.compose(&handles, &store).unwrap();
    assert!(factory.registries().is_some());
    drop(parts);
    assert_eq!(
        error_code(factory.compose(&handles, &store)),
        "COMPOSITION_ALREADY_USED"
    );
}

#[test]
fn a_native_owner_witness_cannot_be_reused_for_another_store() {
    let root = TestRoot::new();
    let mut store = root.open();
    let local = handles(&mut store);
    let other_root = TestRoot::new();
    let mut other_store = other_root.open();
    let foreign = handles(&mut other_store);
    let mut mismatched = local.clone();
    mismatched.workspace = foreign.workspace;
    let mut factory = ProductionFactory::offline_owned(binary_digest());
    assert_eq!(
        error_code(factory.compose(&mismatched, &store)),
        "PERMISSION_REQUIRED"
    );
    assert!(factory.registries().is_none());
    assert!(factory.compose(&local, &store).is_ok());
}

#[test]
fn stale_project_setup_and_unbounded_options_fail_before_source_installation() {
    let root = TestRoot::new();
    let mut store = root.open();
    let handles = handles(&mut store);
    let mut factory = ProductionFactory::offline_owned(binary_digest());
    let mut stale = handles.clone();
    stale.workspace.as_mut().unwrap().project_revision = raw_digest(b"different-project-revision");
    assert_eq!(error_code(factory.compose(&stale, &store)), "STALE_CONTEXT");
    factory
        .inputs
        .as_mut()
        .unwrap()
        .planner_options
        .time_budget_ms = 0;
    assert_eq!(
        error_code(factory.compose(&handles, &store)),
        "BUDGET_EXCEEDED"
    );
    assert!(factory.registries().is_none());
    factory.inputs.as_mut().unwrap().planner_options = PlannerOptions::default();
    assert!(factory.compose(&handles, &store).is_ok());
}

struct NoGeneratedIds;
impl IdSource for NoGeneratedIds {
    fn next_id(&mut self, _: IdKind) -> AppResult<String> {
        Err(AppError::new(
            "UNEXPECTED_MUTATION",
            "Read and pure functions cannot allocate operation IDs",
        ))
    }
}

#[test]
fn offline_factory_runs_actual_project_inspection_and_pure_prefab_validation() {
    let root = TestRoot::new();
    let mut store = root.open();
    let handles = handles(&mut store);
    let workspace = handles.workspace.as_ref().unwrap();
    let context_id = ContextId::new(workspace.context["contextId"].as_str().unwrap()).unwrap();
    let project = handles.configured_project.as_ref().unwrap().clone();
    let mut factory = ProductionFactory::offline_owned(binary_digest());
    let parts = factory.compose(&handles, &store).unwrap();
    let registries = factory.registries().unwrap();
    assert!(Rc::ptr_eq(&parts.dependencies, &registries.dependencies));
    let actual = handles
        .authority
        .current_context_with_deadline(
            workspace.witness.principal(),
            &context_id,
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
    assert_eq!(actual, workspace.context);
    let planner = StoreAwarePlanner::new(PlanningComposition {
        request: Box::new(handles.request.clone()),
        authority: handles.authority.clone(),
        hosts: handles.hosts.clone(),
        contexts: parts.contexts,
        data: parts.data,
        backend: parts.backend,
        dependencies: parts.dependencies,
        clock: Box::new(SystemClock),
        options: parts.planner_options,
    })
    .unwrap();
    let mut extensions = ExtensionRouter::default();
    extensions
        .register(
            FEATURE_METHODS.iter().copied(),
            Box::new(FeatureExtension::new(parts.features, handles.hosts.clone()).unwrap()),
        )
        .unwrap();
    let mut service = ApplicationService::from_store(
        store,
        ApplicationPorts {
            authority: Box::new(handles.authority.clone()),
            planner: Box::new(planner),
            provider: parts.provider,
            observer: parts.observer,
            ids: Box::new(NoGeneratedIds),
            clock: Box::new(SystemClock),
        },
    );
    service.bind_request_context(handles.request.clone());
    service.set_extensions(extensions);
    let mut sessions = SessionAuthority::new(1).unwrap();
    let token = sessions
        .install(SessionPolicy {
            principal: workspace.witness.principal().clone(),
            allowed_methods: ["project.inspect".to_owned(), "prefab.validate".to_owned()].into(),
            allowed_contexts: [context_id].into(),
            lifetime: Duration::from_secs(30),
        })
        .unwrap();
    let authenticated = sessions.authenticate_token(&token).unwrap();
    let budget =
        RequestBudget::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false))).unwrap();
    let inspected = service
        .call(
            &authenticated,
            "project.inspect",
            &json!({
                "projectId":project, "expectedRevision":null,
            }),
            &budget,
        )
        .unwrap();
    assert_eq!(inspected["project"]["projectId"], project.as_str());
    assert_eq!(
        inspected["project"]["targetProfileId"],
        "unverified-native-target"
    );
    // Actual Rust metadata registration cannot certify current game bindings.
    assert_eq!(inspected["runtimeBindingsAvailable"], false);
    let prefab = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
    let expected = mmmm_domain::prefab_validate(&prefab).unwrap();
    assert_eq!(
        service
            .call(&authenticated, "prefab.validate", &prefab, &budget)
            .unwrap(),
        expected
    );
    // The actual request scope has retired after both common service calls.
    assert!(handles.request.current().is_err());
    sessions.revoke_all();
    assert_eq!(
        service
            .call(
                &authenticated,
                "project.inspect",
                &json!({
                    "projectId":project,"expectedRevision":null,
                }),
                &budget
            )
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
}

#[test]
fn absent_native_data_is_unavailable_and_cancellation_is_preserved() {
    let root = TestRoot::new();
    let mut store = root.open();
    let handles = handles(&mut store);
    let project = store
        .project(handles.configured_project.as_ref().unwrap())
        .unwrap();
    let catalog = ProjectCatalog::from_project(&project).unwrap();
    let workspace = handles.workspace.as_ref().unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let budget = RequestBudget::new(Duration::from_secs(10), cancelled.clone()).unwrap();
    let mut data = UnregisteredPlanningData;
    assert_eq!(
        data.scene_source(
            workspace.witness.principal(),
            &catalog,
            &Value::Null,
            &workspace.context,
            &budget
        )
        .err()
        .unwrap()
        .code,
        "SOURCE_UNAVAILABLE"
    );
    assert_eq!(
        data.state_snapshot(
            workspace.witness.principal(),
            &catalog,
            &Value::Null,
            &Value::Null,
            &workspace.context,
            &budget
        )
        .err()
        .unwrap()
        .code,
        "SOURCE_UNAVAILABLE"
    );
    cancelled.store(true, Ordering::Release);
    let expected = budget.check().unwrap_err().code;
    assert_eq!(
        data.scene_source(
            workspace.witness.principal(),
            &catalog,
            &Value::Null,
            &workspace.context,
            &budget
        )
        .err()
        .unwrap()
        .code,
        expected
    );
}

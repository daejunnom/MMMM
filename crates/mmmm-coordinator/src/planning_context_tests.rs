//! Existing Project examples are reused. Actual registered context lookup and
//! same-store native owner setup require these source authorization tests.
use super::*;
use crate::auth::{SessionAuthority, SessionPolicy};
use mmmm_contracts::{parse_json, projected_digest};
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
const MARKER: &[u8] = b"mmmm-planning-context-tests\n";
struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let parent = std::env::var_os("MMMM_TEST_DATA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        assert!(parent.is_absolute());
        let root = parent.join(format!(
            "mmmm-planning-context-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(!root.exists());
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let root = fs::canonicalize(root).unwrap();
        let checkout =
            fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        assert!(!root.starts_with(checkout));
        fs::write(root.join("test-owner.txt"), MARKER).unwrap();
        Self(root)
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
            && plain_tree(&self.0, 0, &mut count)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
fn plain_tree(path: &Path, depth: usize, count: &mut usize) -> bool {
    if depth > 10 || *count >= 256 {
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
fn project() -> Value {
    parse_json(
        &fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/project.json"))
            .unwrap(),
    )
    .unwrap()
}
fn empty_scope(project: &ProjectId) -> Value {
    json!({"projectId":project,"objectIds":[],"resourceIds":[],"regions":[],"externalTargetIds":[]})
}
fn context(
    principal: &PrincipalId,
    project: &ProjectId,
    id: &ContextId,
    policy: &mmmm_contracts::Sha256Digest,
    scope: &Value,
) -> Value {
    let mut context = json!({"contractVersion":"0.2.0","principalRef":principal,"projectId":project,
        "contextId":id,"policyRevision":policy,"scope":scope,
        "environment":{"kind":"offline","workspaceId":"workspace-context-source-test","side":"offline"},
        "contextDigest":"0".repeat(64)});
    context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
    context
}
struct Fixture {
    sessions: SessionAuthority,
    token: crate::credential::SecretToken,
    principal: AuthenticatedPrincipal,
    authority: LocalAuthority,
    hosts: HostBridge,
    project: ProjectId,
    id: ContextId,
    context: Value,
    budget: RequestBudget,
    cancelled: Arc<AtomicBool>,
    registry: SharedRegisteredPlanningContexts,
}
impl Fixture {
    fn new() -> Self {
        let hosts = HostBridge::default();
        let authority = LocalAuthority::new(hosts.clone());
        let project = ProjectId::new(project()["projectId"].as_str().unwrap()).unwrap();
        let principal_id = PrincipalId::new("principal-context-source").unwrap();
        let id = ContextId::new("context-registered-workspace").unwrap();
        let scope = empty_scope(&project);
        let policy = authority
            .install_project_access(
                principal_id.clone(),
                project.clone(),
                scope.clone(),
                [id.clone()].into(),
                Duration::from_secs(120),
            )
            .unwrap();
        let mut sessions = SessionAuthority::new(2).unwrap();
        let token = sessions
            .install(SessionPolicy {
                principal: principal_id,
                allowed_methods: ["project.inspect".into(), "plan.create".into()].into(),
                allowed_contexts: [id.clone(), ContextId::new("context-other-project").unwrap()]
                    .into(),
                lifetime: Duration::from_secs(120),
            })
            .unwrap();
        let principal = sessions.authenticate_token(&token).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let budget = RequestBudget::new(Duration::from_secs(120), cancelled.clone()).unwrap();
        let context = context(principal.principal(), &project, &id, &policy, &scope);
        let registry = Rc::new(RefCell::new(RegisteredContextLocator::new()));
        registry
            .borrow_mut()
            .register_workspace(&principal, &authority, context.clone(), &budget)
            .unwrap();
        Self {
            sessions,
            token,
            principal,
            authority,
            hosts,
            project,
            id,
            context,
            budget,
            cancelled,
            registry,
        }
    }
    fn access(&self) -> LocalPlanningAccess {
        LocalPlanningAccess::new(
            self.principal.clone(),
            self.authority.clone(),
            self.hosts.clone(),
            self.budget.clone(),
            planning_context_adapter(self.registry.clone()),
        )
        .unwrap()
    }
    fn resolve(&self) -> AppResult<Value> {
        self.registry.borrow_mut().resolve(
            &self.principal,
            &mut self.authority.clone(),
            &self.hosts,
            &self.id,
            Access::ReadProject,
            &self.budget,
        )
    }
}

#[test]
fn lookup_and_planning_authorization_use_the_same_actual_registered_context() {
    let fixture = Fixture::new();
    assert_eq!(fixture.resolve().unwrap(), fixture.context);
    let resolver = workspace_context_resolver(fixture.registry.clone());
    fixture
        .authority
        .install_workspace_resolver(resolver.clone())
        .unwrap();
    assert_eq!(
        resolver
            .resolve_workspace(
                fixture.principal.principal(),
                &fixture.id,
                fixture.budget.deadline()
            )
            .unwrap(),
        Some(fixture.context.clone())
    );
    fixture
        .authority
        .authorize_with_deadline(
            fixture.principal.principal(),
            &fixture.project,
            Access::Plan,
            Some(&fixture.context),
            None,
            fixture.budget.deadline(),
        )
        .unwrap();
    let access = fixture.access();
    access
        .authorize_project(
            fixture.principal.principal(),
            &fixture.project,
            Some(&fixture.context),
            Access::Plan,
        )
        .unwrap();
    let mut caller = fixture.context.clone();
    caller["environment"]["workspaceId"] = json!("caller-workspace");
    caller["contextDigest"] = json!(projected_digest("ExecutionContext", &caller).unwrap());
    assert_eq!(
        access
            .authorize_project(
                fixture.principal.principal(),
                &fixture.project,
                Some(&caller),
                Access::Plan
            )
            .unwrap_err()
            .code,
        "STALE_CONTEXT"
    );
    assert!(
        access
            .authorize_project(
                fixture.principal.principal(),
                &fixture.project,
                Some(&fixture.context),
                Access::Apply
            )
            .is_err()
    );
}

#[test]
fn another_projects_context_id_cannot_register_a_workspace_source() {
    let fixture = Fixture::new();
    let other = ProjectId::new("project-other-context").unwrap();
    let other_id = ContextId::new("context-other-project").unwrap();
    fixture
        .authority
        .install_project_access(
            fixture.principal.principal().clone(),
            other.clone(),
            empty_scope(&other),
            [other_id.clone()].into(),
            Duration::from_secs(120),
        )
        .unwrap();
    let policy = fixture
        .authority
        .policy_revision(fixture.principal.principal(), &fixture.project)
        .unwrap();
    let confused = context(
        fixture.principal.principal(),
        &fixture.project,
        &other_id,
        &policy,
        &empty_scope(&fixture.project),
    );
    assert_eq!(
        fixture
            .registry
            .borrow_mut()
            .register_workspace(
                &fixture.principal,
                &fixture.authority,
                confused,
                &fixture.budget
            )
            .unwrap_err()
            .code,
        "PERMISSION_REQUIRED"
    );
}

#[test]
fn lookup_rechecks_session_current_project_generation_and_cancellation() {
    let mut fixture = Fixture::new();
    fixture.sessions.revoke(&fixture.token);
    assert_eq!(fixture.resolve().unwrap_err().code, "PERMISSION_REQUIRED");
    let fixture = Fixture::new();
    fixture
        .authority
        .revoke_project(fixture.principal.principal(), &fixture.project)
        .unwrap();
    assert_eq!(fixture.resolve().unwrap_err().code, "PERMISSION_REQUIRED");
    fixture
        .authority
        .install_project_access(
            fixture.principal.principal().clone(),
            fixture.project.clone(),
            empty_scope(&fixture.project),
            [fixture.id.clone()].into(),
            Duration::from_secs(120),
        )
        .unwrap();
    assert!(fixture.resolve().is_err());
    let fixture = Fixture::new();
    fixture.cancelled.store(true, Ordering::Release);
    assert_eq!(fixture.resolve().unwrap_err().code, "CANCELLED");
}

#[test]
fn native_owner_workspace_registration_requires_the_actual_same_store_witness() {
    let root = TestRoot::new();
    let mut store = root.open();
    let target =
        mmmm_contracts::TargetProfileId::new(project()["targetProfileId"].as_str().unwrap())
            .unwrap();
    let created = crate::native_project::create_native_project(
        &mut store,
        "Native workspace context source test",
        &target,
        Instant::now() + Duration::from_secs(120),
    )
    .unwrap();
    let hosts = HostBridge::default();
    let authority = LocalAuthority::new(hosts.clone());
    let project_id = created.project_id;
    let native = crate::workspace_bootstrap::prepare_workspace(
        &store,
        &authority,
        &project_id,
        Instant::now() + Duration::from_secs(120),
    )
    .unwrap();
    let mut registry = RegisteredContextLocator::new();
    registry
        .register_native_owner(&native.witness, &store, &authority, native.context.clone())
        .unwrap();
    let other_root = TestRoot::new();
    let other = other_root.open();
    assert!(
        registry
            .register_native_owner(&native.witness, &other, &authority, native.context.clone())
            .is_err()
    );
    let id = context_id(&native.context).unwrap();
    let mut sessions = SessionAuthority::new(1).unwrap();
    let token = sessions
        .install(SessionPolicy {
            principal: native.witness.principal().clone(),
            allowed_methods: ["project.inspect".into()].into(),
            allowed_contexts: [id.clone()].into(),
            lifetime: Duration::from_secs(120),
        })
        .unwrap();
    let principal = sessions.authenticate_token(&token).unwrap();
    let budget =
        RequestBudget::new(Duration::from_secs(120), Arc::new(AtomicBool::new(false))).unwrap();
    assert_eq!(
        registry
            .resolve(
                &principal,
                &mut authority.clone(),
                &hosts,
                &id,
                Access::ReadProject,
                &budget
            )
            .unwrap(),
        native.context
    );
}

#[test]
fn current_project_helper_reads_the_real_head_under_actual_authority() {
    let fixture = Fixture::new();
    let root = TestRoot::new();
    let mut store = root.open();
    let project = project();
    store.save_project(&project, None).unwrap();
    let access = fixture.access();
    let catalog = checked_current_project_catalog(
        &PlanningStore::read(&store),
        &access,
        fixture.principal.principal(),
        &fixture.project,
        Some(&fixture.context),
    )
    .unwrap();
    assert_eq!(catalog.project(), &project);
    let denied_project = ProjectId::new("project-ungranted-locator").unwrap();
    assert!(
        checked_current_project_catalog(
            &PlanningStore::read(&store),
            &access,
            fixture.principal.principal(),
            &denied_project,
            Some(&fixture.context)
        )
        .is_err()
    );
    fixture.cancelled.store(true, Ordering::Release);
    assert_eq!(
        checked_current_project_catalog(
            &PlanningStore::read(&store),
            &access,
            fixture.principal.principal(),
            &fixture.project,
            None
        )
        .expect_err("expected rejection")
        .code,
        "CANCELLED"
    );
}

#[test]
fn shared_context_borrow_conflicts_return_controlled_busy_errors() {
    let fixture = Fixture::new();
    let resolver = workspace_context_resolver(fixture.registry.clone());
    let access = fixture.access();
    let _guard = fixture.registry.borrow_mut();
    assert_eq!(
        resolver
            .resolve_workspace(
                fixture.principal.principal(),
                &fixture.id,
                fixture.budget.deadline()
            )
            .unwrap_err()
            .code,
        "SOURCE_BUSY"
    );
    assert_eq!(
        access
            .authorize_project(
                fixture.principal.principal(),
                &fixture.project,
                Some(&fixture.context),
                Access::Plan
            )
            .unwrap_err()
            .code,
        "SOURCE_BUSY"
    );
}

//! FN23의 private production 어댑터. 이 파일은 feature_sources의 하위 모듈로
//! 연결한다. 실제 Catalog pin과 현재 source ACL은 필수 입력이며 JSON으로
//! snapshot, pairing, mode 또는 geometry 읽기 권한을 등록하는 경로는 없다.

use super::{FeatureAccess, FeatureArtifactAuthority, LocalFeatureSources};
use crate::{
    auth::AuthenticatedPrincipal,
    authority::LocalAuthority,
    catalog_source::{
        CatalogRpc, NativeCatalogAdmissionState, RegisteredCatalogSources, current_project,
    },
    host::{CompletedPairingWitness, HostBridge, HostContextWitness},
    native_catalog::NativeCatalogCheckpoint,
    planning_context::{SharedRegisteredPlanningContexts, checked_current_project_catalog},
    planning_source::{LocalPlanningAccess, PlanningStore, SharedPlanningContexts},
    service::{RequestBudget, RequestContextSlot, RequestContextWitness, ServiceError},
};
use mmmm_application::{Access, AppError, AppResult};
use mmmm_contracts::{
    ContextId, ContractValidator, ProjectId, Sha256Digest, SnapshotId, canonical_digest,
    encode_json, raw_digest,
};
use mmmm_domain::types::ResourceRef;
use mmmm_planner::ProjectCatalog;
use mmmm_reference::{
    AccessControl, Catalog, ReadPrincipal, ShapeAuthority, ShapeControl, ShapeError, ShapeGrant,
    ShapeLimits, ShapeRead, ShapeService, SnapshotPin,
    shape::{
        GameMode, HostShapeTransport, NATIVE_VOXEL_MEDIA_TYPE, PairedShapeSource,
        ShapeGeometryStore, decode_native_observation,
    },
};
use mmmm_runtime::{
    artifact::{ResourceOwner, register_resource},
    storage::{DurableStore, host_setup::HostReadPolicyRecord},
};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::BTreeSet, error::Error, fmt, path::PathBuf, rc::Rc};

const MAX_QUERY_BYTES: usize = 512 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_GEOMETRY_BYTES: usize = 256 * 1024;

/// 기존 composition의 동일한 handles만 복제한다. 별도 Store나 원장은 없다.
#[derive(Clone)]
pub(super) struct ShapeReadPorts {
    request: RequestContextSlot,
    authority: LocalAuthority,
    hosts: HostBridge,
    contexts: SharedPlanningContexts,
    locator: SharedRegisteredPlanningContexts,
    project: ProjectId,
    catalog: RegisteredCatalogSources,
}
impl ShapeReadPorts {
    pub(super) fn features(owner: &LocalFeatureSources) -> AppResult<Self> {
        let composition = &owner.composition;
        Ok(Self {
            request: composition.request.clone(),
            authority: composition.authority.clone(),
            hosts: composition.hosts.clone(),
            contexts: composition.contexts.clone(),
            locator: composition.context_locator.clone(),
            project: composition.project_id.clone(),
            catalog: composition.catalog.clone().ok_or_else(unavailable)?,
        })
    }
    pub(super) fn artifacts(owner: &FeatureArtifactAuthority) -> AppResult<Self> {
        Ok(Self {
            request: owner.request.clone(),
            authority: owner.authority.clone(),
            hosts: owner.hosts.clone(),
            contexts: owner.contexts.clone(),
            locator: owner.locator.clone(),
            project: owner.project_id.clone(),
            catalog: owner.catalog.clone().ok_or_else(unavailable)?,
        })
    }
}

/// 연결 시 catalog_source의 좁은 FN23/FN31 consumer가 만든 현재 ACL을 넘긴다.
/// Native source에는 같은 요청에 속한 실제 publication checkpoint가 필수다.
/// 기존 catalog-only checkpoint의 method 제한을 우회하거나 source를 발행하지 않는다.
#[derive(Clone)]
pub(super) struct ShapeReadAdmission {
    snapshot_access: Rc<dyn AccessControl>,
    native: Option<Rc<dyn NativeCatalogCheckpoint>>,
}
impl ShapeReadAdmission {
    pub(super) fn new(
        snapshot_access: Rc<dyn AccessControl>,
        native: Option<Rc<dyn NativeCatalogCheckpoint>>,
    ) -> Self {
        Self {
            snapshot_access,
            native,
        }
    }
    pub(super) fn snapshot_access(&self) -> &dyn AccessControl {
        self.snapshot_access.as_ref()
    }
}

/// 성공한 ShapeService 호출의 private 결과다. receipt는 wire에 직렬화하지 않고
/// 현재 FeatureProductRegistry에만 보존한다. registry 소실 뒤에는 권한도 복원하지 않는다.
pub(super) struct ShapeQueryOutput {
    pub(super) result: Value,
    pub(super) geometry: Option<ShapeGeometryReceipt>,
}

/// 실제 원자료 보존과 최종 grant 검사 이후에만 이 모듈이 발급한다.
/// artifact 권한은 원 snapshot/source의 현재 ACL과 별도로 매 읽기 재검사한다.
#[derive(Clone)]
pub(super) struct ShapeGeometryReceipt {
    principal: AuthenticatedPrincipal,
    project: ProjectCatalog,
    context: Value,
    snapshot: SnapshotPin,
    read_principal: ReadPrincipal,
    policy: HostReadPolicyRecord,
    route: HostContextWitness,
    store_root: PathBuf,
    resource: ResourceRef,
    query_digest: Sha256Digest,
    source: Value,
    producer: Sha256Digest,
    issuing_request: RequestContextWitness,
}
impl ShapeGeometryReceipt {
    pub(super) fn resource(&self) -> &ResourceRef {
        &self.resource
    }
    pub(super) fn snapshot(&self) -> &SnapshotPin {
        &self.snapshot
    }

    /// 생성물 registry에 발행하기 직전, 실제 FN23 요청이 아직 같은 요청인지 검사한다.
    pub(super) fn authorize_publication(
        &self,
        ports: ShapeReadPorts,
        access: &FeatureAccess,
        store: &mut DurableStore,
        budget: &RequestBudget,
        admission: ShapeReadAdmission,
    ) -> AppResult<()> {
        self.issuing_request.check_local().map_err(service_app)?;
        self.reauthorize(
            ports,
            access,
            PlanningStore::read(store),
            budget,
            admission,
            "world.shape_query",
        )
    }

    /// FN31의 exact immutable resource binding 전후에 호출한다. 이전 요청의
    /// witness는 재사용하지 않고 현재 artifact.read의 witness/pairing을 취득한다.
    pub(super) fn authorize_read(
        &self,
        ports: ShapeReadPorts,
        access: &FeatureAccess,
        resource: &ResourceRef,
        store: &DurableStore,
        budget: &RequestBudget,
        admission: ShapeReadAdmission,
    ) -> AppResult<()> {
        if !super::same_resource(&self.resource, resource) {
            return Err(denied());
        }
        self.reauthorize(
            ports,
            access,
            PlanningStore::read(store),
            budget,
            admission,
            "artifact.read",
        )
    }

    fn reauthorize(
        &self,
        ports: ShapeReadPorts,
        access: &FeatureAccess,
        store: PlanningStore<'_>,
        budget: &RequestBudget,
        admission: ShapeReadAdmission,
        method: &'static str,
    ) -> AppResult<()> {
        self.route.check_local()?;
        let expected = canonical_digest(&json!({"format":"mmmm.shape-geometry-resource/1",
            "projectId":self.project.project_id(),"contextDigest":self.context["contextDigest"],
            "snapshotRevision":self.snapshot.revision,"queryDigest":self.query_digest,
            "sha256":self.resource.sha256,"mediaType":NATIVE_VOXEL_MEDIA_TYPE}))
        .map_err(codec_app)?;
        if self.producer != raw_digest(include_bytes!("feature_shapes.rs"))
            || self.resource.resource_id.as_str() != format!("shape-{expected}")
            || self.resource.media_type != NATIVE_VOXEL_MEDIA_TYPE
            || self.resource.size_bytes == 0
            || self.resource.size_bytes > MAX_GEOMETRY_BYTES as u64
            || self.source["kind"] != "runtime_observation"
            || self.source["sha256"] != self.resource.sha256.as_str()
            || !self.principal.is_current()
        {
            return Err(denied());
        }
        let gate = CurrentShapeGate::new(
            ports,
            access,
            self.snapshot.clone(),
            store,
            budget,
            admission,
            method,
        )?;
        if !gate.request.authenticated().same_session(&self.principal)
            || gate.project.project() != self.project.project()
            || gate.context != self.context
            || gate.read_principal.principal_id != self.read_principal.principal_id
            || gate.read_principal.permission_scope_digest
                != self.read_principal.permission_scope_digest
            || gate.policy != self.policy
            || gate.store_root != self.store_root
        {
            return Err(denied());
        }
        gate.local()
    }
}

/// 실제 owning Catalog에서 pin을 취득하여 기존 ShapeService를 호출한다.
/// 부모의 연결 코드는 성공 후 receipt.authorize_publication을 거쳐 기존
/// product registry에 넣고 result만 반환한다. 미확정 identity에는 receipt가 없다.
pub(super) fn query_current_shape(
    ports: ShapeReadPorts,
    access: &FeatureAccess,
    input: &Value,
    catalog: &Catalog,
    store: &mut DurableStore,
    budget: &RequestBudget,
    admission: ShapeReadAdmission,
) -> AppResult<ShapeQueryOutput> {
    budget.check().map_err(service_app)?;
    ContractValidator::shared()
        .map_err(codec_app)?
        .validate("ShapeQueryContext", input)
        .map_err(codec_app)?;
    if encode_json(input).map_err(codec_app)?.len() > MAX_QUERY_BYTES {
        return Err(limit());
    }
    let id: SnapshotId =
        serde_json::from_value(input["snapshotId"].clone()).map_err(|_| invalid())?;
    let pin = catalog
        .snapshot_pin(
            &id,
            &access.read_principal,
            admission.snapshot_access.as_ref(),
        )
        .map_err(catalog_app)?;
    let gate = Rc::new(CurrentShapeGate::new(
        ports,
        access,
        pin,
        PlanningStore::write(store),
        budget,
        admission,
        "world.shape_query",
    )?);
    let input = input.clone();
    let pending = Rc::new(RefCell::new(None));
    let failure = gate.failure.clone();
    let geometry = CurrentGeometry {
        gate: gate.clone(),
        query: input.clone(),
        pending: pending.clone(),
        failure: failure.clone(),
    };
    let transport = CurrentShapeTransport {
        gate: gate.clone(),
        failure: failure.clone(),
    };
    let source = PairedShapeSource {
        transport,
        geometry,
    };
    let mut service = ShapeService::new(source, ShapeLimits::default()).map_err(shape_app)?;
    let deadline = crate::features::wire_deadline(gate.request.budget()).map_err(service_app)?;
    let control = ShapeControl {
        cancellation: budget.cancellation(),
        deadline: budget.deadline(),
        deadline_at: &deadline,
    };
    let read = service.query(&input, &access.read_principal, gate.as_ref(), &control);
    let checked = gate.local();
    let read = match read {
        Ok(read) => finish(Ok(read), checked)?,
        Err(error) => {
            let primary = failure
                .borrow_mut()
                .take()
                .unwrap_or_else(|| shape_app(error));
            return finish(Err(primary), checked);
        }
    };
    let pending = pending.borrow_mut().take();
    complete_read(&gate, &input, read, pending)
}

struct CurrentShapeGate<'a> {
    ports: ShapeReadPorts,
    request: RequestContextWitness,
    pairing: Rc<CompletedPairingWitness>,
    project: ProjectCatalog,
    context: Value,
    snapshot: SnapshotPin,
    read_principal: ReadPrincipal,
    policy: HostReadPolicyRecord,
    route: HostContextWitness,
    hello: Value,
    allowed_modes: BTreeSet<GameMode>,
    store_root: PathBuf,
    store: PlanningStore<'a>,
    admission: ShapeReadAdmission,
    failure: SharedFailure,
}
impl<'a> CurrentShapeGate<'a> {
    fn new(
        ports: ShapeReadPorts,
        access: &FeatureAccess,
        snapshot: SnapshotPin,
        store: PlanningStore<'a>,
        budget: &RequestBudget,
        admission: ShapeReadAdmission,
        method: &'static str,
    ) -> AppResult<Self> {
        if !matches!(method, "world.shape_query" | "artifact.read") {
            return Err(denied());
        }
        let request = ports.request.current_witness(method).map_err(service_app)?;
        let principal = request.authenticated();
        if request.budget().deadline() != budget.deadline()
            || !std::ptr::eq(request.budget().cancellation(), budget.cancellation())
        {
            return Err(denied());
        }
        let context = access.context.clone().ok_or_else(unavailable)?;
        let id = context_id(&context)?;
        if snapshot.snapshot["side"] != context["environment"]["side"] {
            return Err(AppError::new(
                "SIDE_MISMATCH",
                "원래 shape snapshot과 현재 context의 side가 다릅니다",
            ));
        }
        if context["environment"]["kind"] != "game"
            || context["projectId"] != ports.project.as_str()
            || context["principalRef"] != principal.principal().as_str()
            || snapshot.snapshot["environment"] != context["environment"]
        {
            return Err(stale());
        }
        let expected = ports.catalog.read_principal(principal, &id)?;
        if expected.principal_id != access.read_principal.principal_id
            || expected.permission_scope_digest != access.read_principal.permission_scope_digest
        {
            return Err(denied());
        }
        match ports.catalog.native_admission_state(principal, &context)? {
            NativeCatalogAdmissionState::Native(_) if admission.native.is_none() => {
                return Err(denied());
            }
            NativeCatalogAdmissionState::Missing => return Err(unavailable()),
            _ => {}
        }
        admission
            .snapshot_access
            .authorize_snapshot(&expected, &snapshot.snapshot)
            .map_err(catalog_app)?;
        let local = LocalPlanningAccess::new(
            principal.clone(),
            ports.authority.clone(),
            ports.hosts.clone(),
            budget.clone(),
            ports.contexts.clone(),
        )?;
        let project = checked_current_project_catalog(
            &store,
            &local,
            principal.principal(),
            &ports.project,
            Some(&context),
        )?;
        if access.project.as_ref() != Some(project.project()) {
            return Err(stale());
        }
        let pairing = Rc::new(ports.hosts.completed_pairing_witness(
            &request,
            &ports.authority,
            &id,
        )?);
        if pairing.context() != &context {
            return Err(stale());
        }
        let policy = store.with_read(|store| {
            pairing.with_current_native_owner(store, &ports.authority, |owner| {
                owner.read_host_policy()
            })
        })?;
        let allowed_modes = policy_modes(&policy)?;
        let route =
            ports
                .hosts
                .observe_context_witness(principal.principal(), &id, budget.deadline())?;
        if route.context() != &context {
            return Err(stale());
        }
        let store_root = store.with_read(|store| Ok(store.data_root().to_path_buf()))?;
        let mut gate = Self {
            ports,
            request,
            pairing,
            project,
            context,
            snapshot,
            read_principal: expected,
            policy,
            route,
            hello: Value::Null,
            allowed_modes,
            store_root,
            store,
            admission,
            failure: Rc::new(RefCell::new(None)),
        };
        gate.durable_current()?;
        let hello = gate
            .ports
            .hosts
            .hello_with_deadline(
                gate.request.authenticated().principal(),
                &id,
                budget.deadline(),
            )
            .and_then(|hello| {
                if hello["environment"] != gate.context["environment"]
                    || hello["gameVersion"] != gate.snapshot.snapshot["gameVersion"]
                {
                    return Err(stale());
                }
                Ok(hello)
            });
        // 초기 hello 실패와 동시에 생긴 source/CAS 변경도 함께 보존한다.
        gate.hello = finish(hello, gate.durable_current())?;
        gate.local()?;
        Ok(gate)
    }

    fn local(&self) -> AppResult<()> {
        self.request.check_local().map_err(service_app)?;
        self.route.check_local()?;
        self.pairing.check_current(&self.ports.authority)?;
        self.admission
            .snapshot_access
            .authorize_snapshot(&self.read_principal, &self.snapshot.snapshot)
            .map_err(catalog_app)?;
        let principal = self.request.authenticated();
        let actual = self
            .ports
            .catalog
            .read_principal(principal, &context_id(&self.context)?)?;
        if actual.principal_id != self.read_principal.principal_id
            || actual.permission_scope_digest != self.read_principal.permission_scope_digest
        {
            return Err(denied());
        }
        Ok(())
    }

    fn check(&self) -> AppResult<()> {
        self.local()?;
        let principal = self.request.authenticated();
        let id = context_id(&self.context)?;
        let context = self
            .ports
            .locator
            .try_borrow_mut()
            .map_err(|_| busy())?
            .resolve(
                principal,
                &mut self.ports.authority.clone(),
                &self.ports.hosts,
                &id,
                Access::ReadProject,
                self.request.budget(),
            )?;
        if context != self.context {
            return Err(stale());
        }
        self.durable_current()?;
        // 모든 Store guard는 이 실제 host I/O 전에 해제되어 있다.
        let hello = self
            .ports
            .hosts
            .hello_with_deadline(principal.principal(), &id, self.request.budget().deadline())
            .and_then(|hello| {
                if hello != self.hello {
                    return Err(stale());
                }
                Ok(())
            });
        finish(hello, self.durable_current())
    }

    /// Host I/O 없이 같은 Store의 원 Project/source/CAS/D032를 검사한다.
    /// 하나의 bounded source-use 읽기 전후에만 D032를 확인하며, reader의
    /// metadata/청크 callback 안에 D032 full-read를 중첩하지 않는다.
    fn durable_current(&self) -> AppResult<()> {
        self.local()?;
        self.store.with_read(|store| {
            self.local()?;
            if store.data_root() != self.store_root {
                return Err(denied());
            }
            let rpc = CatalogRpc::new(
                self.request.authenticated().clone(),
                self.request.budget().clone(),
                self.ports.authority.clone(),
                &self.context,
            )?;
            if current_project(store, &rpc, &self.ports.project)? != *self.project.project() {
                return Err(stale());
            }
            if let Some(checkpoint) = &self.admission.native {
                checkpoint.check(store)?;
            }
            self.pairing
                .with_current_native_owner(store, &self.ports.authority, |owner| {
                    if owner.read_host_policy()? != self.policy {
                        return Err(denied());
                    }
                    owner.check_current()
                })
        })?;
        self.local()
    }

    fn control(&self, control: &ShapeControl<'_>) -> AppResult<()> {
        if control.deadline != self.request.budget().deadline()
            || !std::ptr::eq(control.cancellation, self.request.budget().cancellation())
        {
            return Err(denied());
        }
        control.check().map_err(shape_app)?;
        self.check()
    }
}
impl ShapeAuthority for CurrentShapeGate<'_> {
    fn authorize_shape(
        &self,
        principal: &ReadPrincipal,
        query: &Value,
    ) -> Result<ShapeGrant, ShapeError> {
        let result = (|| {
            self.check()?;
            if principal.principal_id != self.read_principal.principal_id
                || principal.permission_scope_digest != self.read_principal.permission_scope_digest
                || query["snapshotId"] != self.snapshot.snapshot["snapshotId"]
                || query["contextId"] != self.context["contextId"]
            {
                return Err(denied());
            }
            Ok(ShapeGrant {
                execution_context: self.context.clone(),
                snapshot: self.snapshot.clone(),
                host_hello: self.hello.clone(),
                allowed_modes: self.allowed_modes.clone(),
            })
        })();
        record_failure(result, &self.failure)
    }
}

type SharedFailure = Rc<RefCell<Option<AppError>>>;
type SharedPending = Rc<RefCell<Option<PendingGeometry>>>;
struct CurrentShapeTransport<'a> {
    gate: Rc<CurrentShapeGate<'a>>,
    failure: SharedFailure,
}
impl HostShapeTransport for CurrentShapeTransport<'_> {
    fn inspect_shape(
        &mut self,
        context: &Value,
        payload: &Value,
        control: &ShapeControl<'_>,
    ) -> Result<Value, ShapeError> {
        let result = (|| {
            self.gate.control(control)?;
            if *context != self.gate.context
                || !matches!(
                    payload["kind"].as_str(),
                    Some("world.shape_probe" | "world.shape_query")
                )
                || payload["query"]["snapshotId"] != self.gate.snapshot.snapshot["snapshotId"]
            {
                return Err(denied());
            }
            if encode_json(payload).map_err(codec_app)?.len() > MAX_QUERY_BYTES {
                return Err(limit());
            }
            let response = self
                .gate
                .ports
                .hosts
                .inspect_response_with_deadline(
                    self.gate.request.authenticated().principal(),
                    &context_id(context)?,
                    payload.clone(),
                    control.deadline,
                )
                .and_then(host_payload);
            finish(response, self.gate.check())
        })();
        record_failure(result, &self.failure)
    }
}

struct PendingGeometry {
    resource: ResourceRef,
    bytes_digest: Sha256Digest,
}
struct CurrentGeometry<'a> {
    gate: Rc<CurrentShapeGate<'a>>,
    query: Value,
    pending: SharedPending,
    failure: SharedFailure,
}
impl ShapeGeometryStore for CurrentGeometry<'_> {
    fn retain_geometry(
        &mut self,
        principal: &ReadPrincipal,
        context: &Value,
        query: &Value,
        bytes: &[u8],
        media_type: &str,
    ) -> Result<Value, ShapeError> {
        let result = (|| {
            self.gate.check()?;
            if principal.principal_id != self.gate.read_principal.principal_id
                || principal.permission_scope_digest
                    != self.gate.read_principal.permission_scope_digest
                || *context != self.gate.context
                || *query != self.query
                || media_type != NATIVE_VOXEL_MEDIA_TYPE
                || bytes.len() > MAX_GEOMETRY_BYTES
            {
                return Err(denied());
            }
            decode_native_observation(bytes, query["shapeKind"].as_str().ok_or_else(invalid)?)
                .map_err(shape_app)?;
            let resource = geometry_resource(
                self.gate.project.project_id(),
                &self.gate.context,
                &self.gate.snapshot,
                query,
                bytes,
            )?;
            let metadata = serde_json::to_value(&resource).map_err(|_| invalid())?;
            self.gate.store.with_write(|store| {
                self.gate.local()?;
                let blob = store.put_blob(bytes).map_err(storage_app)?;
                if blob.digest != resource.sha256 || blob.byte_length != resource.size_bytes {
                    return Err(invalid());
                }
                register_resource(
                    store,
                    &metadata,
                    ResourceOwner::Project(self.gate.project.project_id().clone()),
                )
                .map_err(|error| AppError::new(error.code, error.message))?;
                self.gate.local()
            })?;
            self.gate.check()?;
            if self.pending.borrow().is_some() {
                return Err(invalid());
            }
            *self.pending.borrow_mut() = Some(PendingGeometry {
                resource,
                bytes_digest: raw_digest(bytes),
            });
            Ok(metadata)
        })();
        record_failure(result, &self.failure)
    }
    fn authorize_geometry(
        &mut self,
        principal: &ReadPrincipal,
        context: &Value,
        resource: &Value,
    ) -> Result<(), ShapeError> {
        let result = (|| {
            self.gate.check()?;
            if principal.principal_id != self.gate.read_principal.principal_id
                || principal.permission_scope_digest
                    != self.gate.read_principal.permission_scope_digest
                || *context != self.gate.context
            {
                return Err(denied());
            }
            let expected = self.pending.borrow();
            let expected = expected.as_ref().ok_or_else(denied)?;
            if serde_json::to_value(&expected.resource).map_err(|_| invalid())? != *resource {
                return Err(denied());
            }
            Ok(())
        })();
        record_failure(result, &self.failure)
    }
}

fn complete_read(
    gate: &CurrentShapeGate<'_>,
    query: &Value,
    read: ShapeRead,
    pending: Option<PendingGeometry>,
) -> AppResult<ShapeQueryOutput> {
    gate.local()?;
    let geometry = match (read.result.get("geometryRef"), pending) {
        (None, None) => None,
        (Some(reference), Some(pending)) => {
            if serde_json::to_value(&pending.resource).map_err(|_| invalid())? != *reference
                || raw_digest(&read.evidence.observation_bytes) != pending.bytes_digest
                || pending.resource.sha256 != pending.bytes_digest
                || read.evidence.source["kind"] != "runtime_observation"
                || read.evidence.source["sha256"] != pending.bytes_digest.as_str()
            {
                return Err(invalid());
            }
            Some(ShapeGeometryReceipt {
                principal: gate.request.authenticated().clone(),
                project: gate.project.clone(),
                context: gate.context.clone(),
                snapshot: gate.snapshot.clone(),
                read_principal: gate.read_principal.clone(),
                policy: gate.policy.clone(),
                route: gate.route.clone(),
                store_root: gate.store_root.clone(),
                resource: pending.resource,
                query_digest: canonical_digest(query).map_err(codec_app)?,
                source: read.evidence.source,
                producer: raw_digest(include_bytes!("feature_shapes.rs")),
                issuing_request: gate.request.clone(),
            })
        }
        _ => return Err(invalid()),
    };
    gate.local()?;
    Ok(ShapeQueryOutput {
        result: read.result,
        geometry,
    })
}

fn geometry_resource(
    project: &ProjectId,
    context: &Value,
    snapshot: &SnapshotPin,
    query: &Value,
    bytes: &[u8],
) -> AppResult<ResourceRef> {
    if bytes.is_empty() || bytes.len() > MAX_GEOMETRY_BYTES {
        return Err(limit());
    }
    let bytes_digest = raw_digest(bytes);
    let id = canonical_digest(&json!({"format":"mmmm.shape-geometry-resource/1","projectId":project,
        "contextDigest":context["contextDigest"],"snapshotRevision":snapshot.revision,
        "queryDigest":canonical_digest(query).map_err(codec_app)?,"sha256":bytes_digest,"mediaType":NATIVE_VOXEL_MEDIA_TYPE})).map_err(codec_app)?;
    Ok(ResourceRef {
        resource_id: mmmm_contracts::ResourceId::new(format!("shape-{id}"))
            .map_err(|_| invalid())?,
        sha256: bytes_digest,
        media_type: NATIVE_VOXEL_MEDIA_TYPE.into(),
        size_bytes: bytes.len() as u64,
    })
}
fn policy_modes(policy: &HostReadPolicyRecord) -> AppResult<BTreeSet<GameMode>> {
    let modes = policy
        .policy()
        .shape_modes()
        .iter()
        .map(|name| serde_json::from_value::<GameMode>(json!(name)).map_err(|_| denied()))
        .collect::<AppResult<BTreeSet<_>>>()?;
    if modes.is_empty() {
        return Err(denied());
    }
    Ok(modes)
}
fn record_failure<T>(result: AppResult<T>, failure: &SharedFailure) -> Result<T, ShapeError> {
    result.map_err(|error| {
        let code = error.code.to_owned();
        if failure.borrow().is_none() {
            *failure.borrow_mut() = Some(error);
        }
        ShapeError::Host { code }
    })
}
fn host_payload(response: Value) -> AppResult<Value> {
    if encode_json(&response).map_err(codec_app)?.len() > MAX_RESPONSE_BYTES {
        return Err(limit());
    }
    if response["status"] != "ok" {
        let code = match response["error"]["code"].as_str() {
            Some("UNSUPPORTED") => "UNSUPPORTED",
            Some("STALE_CONTEXT") => "STALE_CONTEXT",
            Some("SIDE_MISMATCH") => "SIDE_MISMATCH",
            Some("TARGET_DRIFT") => "TARGET_DRIFT",
            Some("PERMISSION_REQUIRED") => "PERMISSION_REQUIRED",
            Some("PERMISSION_DENIED") => "PERMISSION_DENIED",
            Some("CANCELLED" | "CANCELLATION_REQUESTED") => "CANCELLED",
            Some("DEADLINE_EXCEEDED") => "DEADLINE_EXCEEDED",
            Some("CHUNK_NOT_LOADED") => "CHUNK_NOT_LOADED",
            Some("SHAPE_LIMIT" | "SHAPE_DEPENDENCY_LIMIT") => "INPUT_LIMIT",
            _ => "HOST_REQUEST_FAILED",
        };
        return Err(AppError::caused_by(
            code,
            "실제 shape 호스트가 조회를 거절했습니다",
            ShapeHostFailure { response },
        ));
    }
    response.get("payload").cloned().ok_or_else(invalid)
}
#[derive(Debug)]
struct ShapeHostFailure {
    response: Value,
}
impl fmt::Display for ShapeHostFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.response;
        f.write_str("원래 인증된 shape HostResponse는 private 원인으로 보존됩니다")
    }
}
impl Error for ShapeHostFailure {}
#[derive(Debug)]
struct ShapeCheckpointFailure {
    primary: AppError,
    checkpoint: AppError,
}
impl fmt::Display for ShapeCheckpointFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.checkpoint;
        f.write_str("원래 shape 실패와 후속 현재성 검사 실패를 함께 보존합니다")
    }
}
impl Error for ShapeCheckpointFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.primary)
    }
}
fn finish<T>(result: AppResult<T>, checked: AppResult<()>) -> AppResult<T> {
    match (result, checked) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(checkpoint)) => Err(AppError::caused_by(
            primary.code,
            primary.message,
            ShapeCheckpointFailure {
                primary,
                checkpoint,
            },
        )),
    }
}
fn context_id(context: &Value) -> AppResult<ContextId> {
    serde_json::from_value(context["contextId"].clone()).map_err(|_| invalid())
}
fn service_app(error: ServiceError) -> AppError {
    AppError::caused_by(error.code, error.message, error)
}
pub(super) fn service_error(error: AppError) -> ServiceError {
    ServiceError::caused_by(error.code, "실제 shape source가 요청을 거절했습니다", error)
}
fn codec_app(error: impl Error + Send + Sync + 'static) -> AppError {
    AppError::caused_by(
        "SCHEMA_UNSUPPORTED",
        "정본 shape 입력 또는 원자료를 검사할 수 없습니다",
        error,
    )
}
fn storage_app(error: mmmm_runtime::storage::StorageError) -> AppError {
    AppError::storage("SHAPE_STORAGE_FAILED", error)
}
fn catalog_app(error: mmmm_reference::CatalogError) -> AppError {
    AppError::caused_by(
        "PERMISSION_REQUIRED",
        "원래 shape snapshot의 현재 source 권한이 없습니다",
        error,
    )
}
fn shape_app(error: ShapeError) -> AppError {
    let code = match error.code() {
        "CANCELLED" => "CANCELLED",
        "DEADLINE_EXCEEDED" => "DEADLINE_EXCEEDED",
        "STALE_CONTEXT" => "STALE_CONTEXT",
        "SIDE_MISMATCH" => "SIDE_MISMATCH",
        "TARGET_DRIFT" => "TARGET_DRIFT",
        "PERMISSION_REQUIRED" => "PERMISSION_REQUIRED",
        "SOURCE_UNAVAILABLE" => "SOURCE_UNAVAILABLE",
        "INPUT_LIMIT" => "INPUT_LIMIT",
        "SCHEMA_UNSUPPORTED" => "SCHEMA_UNSUPPORTED",
        _ => "SHAPE_VERIFICATION_FAILED",
    };
    AppError::caused_by(
        code,
        "실제 shape 관측 또는 현재 권한 검사가 실패했습니다",
        error,
    )
}
fn denied() -> AppError {
    AppError::new(
        "PERMISSION_REQUIRED",
        "현재 shape 요청·원 snapshot·source·정책 권한이 필요합니다",
    )
}
fn stale() -> AppError {
    AppError::new(
        "STALE_CONTEXT",
        "원래 shape context 또는 Project가 변경되었습니다",
    )
}
fn invalid() -> AppError {
    AppError::new(
        "SCHEMA_UNSUPPORTED",
        "실제 shape 관측 또는 immutable geometry 관계가 일치하지 않습니다",
    )
}
fn limit() -> AppError {
    AppError::new(
        "INPUT_LIMIT",
        "shape 입력 또는 원자료가 유한한 상한을 초과했습니다",
    )
}
fn busy() -> AppError {
    AppError::new(
        "SOURCE_BUSY",
        "현재 shape source가 다른 짧은 검사에서 사용 중입니다",
    )
}
fn unavailable() -> AppError {
    AppError::new(
        "SOURCE_UNAVAILABLE",
        "실제 shape snapshot 또는 등록 source가 없습니다",
    )
}

#[cfg(test)]
#[path = "feature_shape_tests.rs"]
mod tests;

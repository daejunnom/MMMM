//! 현재 요청의 실제 Project·owned 문서·CAS에서 순수 계획 자료를 읽는다.
//! 원본 보존과 현재 읽기 권한은 별개이며, 이 모듈은 game target 검증,
//! source 재배포 권한, bake 완료 또는 실행 승인을 발급하지 않는다.

use crate::{
    authority::LocalAuthority,
    host::HostBridge,
    planning_source::{
        LocalPlanningAccess, ObservedStateSnapshot, PlanningDataPort, PlanningStore,
        SharedPlanningContexts,
    },
    service::{RequestBudget, RequestContextSlot, RequestContextWitness},
};
use mmmm_application::{Access, AppError, AppResult};
use mmmm_contracts::{
    ContextId, ContractValidator, PrincipalId, ProjectId, Sha256Digest, StateId, canonical_digest,
    encode_json, parse_json, verify_projected_digest,
};
use mmmm_domain::{
    Instance, Prefab,
    state::{effective_defaults, value_matches_type},
    types::{ResourceRef, ScalarValue, StateScope},
};
use mmmm_exchange::{
    patch::{DeltaKind, DeltaPolicy, validate_scene_patch},
    selection::{ObjectNode, Selection},
};
use mmmm_planner::{OwnedKind, ProjectCatalog, SceneSource};
use mmmm_runtime::storage::{
    BlobRef, DurableStore, StorageError, StorageResult,
    artifact::ResourceOwner,
    owned_documents::{
        OwnedDocumentAuthority, OwnedDocumentBytes, OwnedDocumentKind, OwnedDocumentPin,
        OwnedDocumentReader,
    },
    project_resources::{
        ProjectResourceAuthority, ProjectResourceQuery, ProjectResourceReader,
        ProjectResourceRequest, ProjectSourceRpcContext, RegisteredProjectResource,
    },
};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    rc::Rc,
};

const MAX_DOCUMENT: u64 = 8 * 1024 * 1024;
const MAX_TOTAL: u64 = 32 * 1024 * 1024;
const MAX_TARGETS: usize = 1024;

/// 실제 codec/alias issuer는 이 source와 같은 store를 검사한 뒤 독립적인
/// live 관측을 공급한다. initialValue나 StateDefault는 이 경계를 대체하지 않는다.
pub trait OwnedStateObservationPort {
    fn observe(
        &mut self,
        store: &PlanningStore<'_>,
        source: &OwnedStateSource,
    ) -> AppResult<ObservedStateSnapshot>;
}

pub struct OwnedPlanningData {
    request: RequestContextSlot,
    authority: LocalAuthority,
    hosts: HostBridge,
    contexts: SharedPlanningContexts,
    state: Option<Box<dyn OwnedStateObservationPort>>,
}

impl OwnedPlanningData {
    pub fn new(
        request: RequestContextSlot,
        authority: LocalAuthority,
        hosts: HostBridge,
        contexts: SharedPlanningContexts,
        state: Option<Box<dyn OwnedStateObservationPort>>,
    ) -> Self {
        Self {
            request,
            authority,
            hosts,
            contexts,
            state,
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Actual call/store, immutable source pins and current context/budget are independently checked"
    )]
    fn session(
        &self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<OwnedReadSession> {
        let request = self.request.occupied_witness().map_err(service_error)?;
        request.check_local().map_err(service_error)?;
        if request.authenticated().principal() != principal
            || request.budget().deadline() != budget.deadline()
            || !std::ptr::eq(request.budget().cancellation(), budget.cancellation())
            || context["principalRef"] != principal.as_str()
            || context["projectId"] != project.project_id().as_str()
        {
            return Err(denied());
        }
        validate("ExecutionContext", context)?;
        verify_projected_digest("ExecutionContext", context).map_err(|error| {
            AppError::caused_by(
                "STALE_CONTEXT",
                "Owned source context digest changed",
                error,
            )
        })?;
        let access = LocalPlanningAccess::new(
            request.authenticated().clone(),
            self.authority.clone(),
            self.hosts.clone(),
            budget.clone(),
            self.contexts.clone(),
        )?;
        let session = OwnedReadSession {
            request,
            access,
            authority: self.authority.clone(),
            project: project.clone(),
            context: context.clone(),
            context_id: decode(&context["contextId"])?,
            failures: Rc::new(RefCell::new(None)),
            bytes: Rc::new(Cell::new(0)),
        };
        session.check_context()?;
        session.check_project(store)?;
        Ok(session)
    }

    /// 발급 당시 실제 원문 pin을 보존하는 metadata-only source다. 공개 JSON이나
    /// ResourceRef constructor가 이 타입을 만들지 않으며 native locator도 포함하지 않는다.
    #[allow(
        clippy::too_many_arguments,
        reason = "Exact owned Instance/Prefab and authenticated current request are separate inputs"
    )]
    pub fn read_state_source(
        &self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        instance: &Value,
        definition: &Value,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<OwnedStateSource> {
        let session = self.session(store, principal, project, context, budget)?;
        let instance_pin = owned_pin(project, OwnedKind::Instance, instance)?;
        let prefab_pin = owned_pin(project, OwnedKind::Prefab, definition)?;
        if project
            .owned_pin(OwnedKind::Instance, text(instance, "instanceId")?)?
            .revision
            != instance_pin.revision
            || instance["prefabId"] != definition["prefabId"]
            || instance["prefabRevision"] != definition["revision"]
        {
            return Err(revision_conflict());
        }
        let actual_instance = session.document(store, &instance_pin)?;
        let actual_prefab = session.document(store, &prefab_pin)?;
        if actual_instance.document != *instance || actual_prefab.document != *definition {
            return Err(revision_conflict());
        }
        let typed_instance: Instance = decode(instance)?;
        let typed_prefab: Prefab = decode(definition)?;
        // This validates authored override types without presenting their values
        // as any live state observation.
        effective_defaults(&typed_prefab, &typed_instance.overrides).map_err(domain_error)?;
        session.check_context()?;
        session.check_project(store)?;
        let store_root = store.with_read(|store| Ok(store.data_root().to_path_buf()))?;
        Ok(OwnedStateSource {
            session,
            store_root,
            instance_pin,
            prefab_pin,
            instance: typed_instance,
            prefab: typed_prefab,
            instance_value: instance.clone(),
            prefab_value: definition.clone(),
            instance_blob: actual_instance.blob,
            prefab_blob: actual_prefab.blob,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Store-aware data adapter preserves all existing planning inputs"
    )]
    pub fn state_snapshot_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        instance: &Value,
        definition: &Value,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<ObservedStateSnapshot> {
        let source = self.read_state_source(
            store, principal, project, instance, definition, context, budget,
        )?;
        if context["environment"]["kind"] != "game"
            || instance["worldId"] != context["environment"]["worldId"]
            || instance["dimension"] != context["dimension"]
        {
            return Err(state_unavailable());
        }
        let observer = self.state.as_mut().ok_or_else(state_unavailable)?;
        let observed = observer.observe(store, &source)?;
        let expected: BTreeSet<_> = source
            .prefab
            .state
            .iter()
            .filter(|state| state.scope == StateScope::Instance)
            .map(|state| state.state_id.clone())
            .collect();
        if observed.source_instance_id != source.instance.instance_id
            || observed.prefab_revision != source.prefab.revision
            || observed.context_digest.as_str() != text(context, "contextDigest")?
            || observed.values.keys().cloned().collect::<BTreeSet<_>>() != expected
            || observed.bytes.len() as u64 > MAX_DOCUMENT
        {
            return Err(state_unavailable());
        }
        for state in source
            .prefab
            .state
            .iter()
            .filter(|state| state.scope == StateScope::Instance)
        {
            if !value_matches_type(&observed.values[&state.state_id], state.state_type) {
                return Err(AppError::new(
                    "STATE_TYPE_MISMATCH",
                    "Independent state codec returned a value of another declared type",
                ));
            }
        }
        let codec = json!({"format":"mmmm.state.snapshot/1", "contextDigest":observed.context_digest,
            "sourceInstanceId":observed.source_instance_id,"prefabRevision":observed.prefab_revision,"values":observed.values});
        if parse_json(&observed.bytes).map_err(json_error)? != codec {
            return Err(state_unavailable());
        }
        source.check_current(store)?;
        Ok(observed)
    }

    /// 가장 작은 owned scene 경로: 현재 실제 owned Prefab/Selection의 기존 node
    /// transform/display를 선택한다. 임의 manual 관계·BakeArtifact·create/delete는
    /// 기존 trusted codec을 요구하며 여기서 등록 또는 추정하지 않는다.
    #[allow(
        clippy::too_many_arguments,
        reason = "Canonical patch and same-store source/current request are independently validated"
    )]
    pub fn scene_source_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<SceneSource> {
        validate("ScenePatch", patch)?;
        if patch["projectId"] != project.project_id().as_str()
            || patch["baseRevision"] != project.revision().as_str()
        {
            return Err(revision_conflict());
        }
        let entries = patch["entries"].as_array().ok_or_else(invalid)?;
        if entries.is_empty() || entries.len() > MAX_TARGETS {
            return Err(source_budget());
        }
        if patch["absenceMeansDeletion"] != false
            || patch["losses"]
                .as_array()
                .is_none_or(|losses| !losses.is_empty())
        {
            return Err(AppError::new(
                "CAPABILITY_UNAVAILABLE",
                "Owned source selection does not approve deletion by absence or representation loss",
            ));
        }
        let session = self.session(store, principal, project, context, budget)?;
        let artifact_pin: ResourceRef = decode(&patch["sourceArtifact"])?;
        let map_pin: ResourceRef = decode(&patch["sourceMap"])?;
        let artifact = parse_json(&session.resource(store, &artifact_pin)?).map_err(json_error)?;
        let source_map = parse_json(&session.resource(store, &map_pin)?).map_err(json_error)?;
        validate("SourceMap", &source_map)?;
        if source_map["inputRevision"] != project.revision().as_str() {
            return Err(revision_conflict());
        }
        let mut targets = BTreeMap::new();
        let mut policy = DeltaPolicy::default();
        for entry in entries {
            let kind = match text(entry, "kind")? {
                "update_transform" => DeltaKind::UpdateTransform,
                "update_display" => DeltaKind::UpdateDisplay,
                _ => {
                    return Err(AppError::new(
                        "CAPABILITY_UNAVAILABLE",
                        "The owned static source codec supports existing node transform/display proposals only",
                    ));
                }
            };
            let target = ObjectNode {
                instance_id: text(entry, "instanceId")?.into(),
                node_id: text(entry, "nodeId")?.into(),
            };
            if targets.insert((target.clone(), kind), entry).is_some() {
                return Err(invalid());
            }
            policy.allow(target, kind).map_err(exchange_error)?;
        }
        let selection = if artifact.get("prefabId").is_some() {
            let pin = owned_pin(project, OwnedKind::Prefab, &artifact)?;
            if session.document(store, &pin)?.document != artifact {
                return Err(revision_conflict());
            }
            let selection_id = format!("owned-selection-{}", canonical_digest(&json!({"project":project.project_id(),"revision":project.revision(),"targets":entries})).map_err(digest_error)?);
            session.selection(
                store,
                targets.keys().map(|(target, _)| target),
                &map_pin,
                &selection_id,
            )?
        } else if artifact.get("instances").is_some() && artifact.get("prefabs").is_some() {
            session.checked_selection_artifact(store, &artifact, &map_pin)?
        } else {
            return Err(AppError::new(
                "CAPABILITY_UNAVAILABLE",
                "An owned static scene source requires its actual canonical Prefab or selection artifact",
            ));
        };
        for ((target, kind), entry) in targets {
            verify_static_mapping(
                &artifact,
                &source_map,
                &artifact_pin,
                &selection,
                &target,
                kind,
                entry,
            )?;
        }
        validate_scene_patch(patch, &selection, &policy).map_err(exchange_error)?;
        session.check_context()?;
        session.check_project(store)?;
        Ok(SceneSource {
            selection,
            delta_policy: policy,
            artifact,
            source_map,
            ingested_bake: None,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Revalidation compares the actual source against all unchanged canonical planning inputs"
    )]
    pub fn validate_scene_provenance_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        source: &SceneSource,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        if source.ingested_bake.is_some() {
            return Err(AppError::new(
                "SOURCE_PROVENANCE_INVALID",
                "A static owned source cannot issue a sealed bake",
            ));
        }
        let actual =
            self.scene_source_with_store(store, principal, project, patch, context, budget)?;
        if source.selection.value() != actual.selection.value()
            || source.artifact != actual.artifact
            || source.source_map != actual.source_map
        {
            return Err(AppError::new(
                "SOURCE_PROVENANCE_INVALID",
                "Scene source changed from the actual retained owned data",
            ));
        }
        validate_scene_patch(patch, &actual.selection, &source.delta_policy).map_err(exchange_error)
    }
}

// The legacy callbacks cannot read a caller's product data without the actual
// call-scoped store. Additive production forwarding preserves fixture adapters.
impl PlanningDataPort for OwnedPlanningData {
    #[allow(
        clippy::too_many_arguments,
        reason = "Forward the same call-scoped Store and authenticated source inputs without replacing them"
    )]
    fn state_snapshot_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        instance: &Value,
        definition: &Value,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<ObservedStateSnapshot> {
        OwnedPlanningData::state_snapshot_with_store(
            self, store, principal, project, instance, definition, context, budget,
        )
    }
    fn scene_source_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<SceneSource> {
        OwnedPlanningData::scene_source_with_store(
            self, store, principal, project, patch, context, budget,
        )
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Revalidate the original scene and authorization against the same held Store"
    )]
    fn validate_scene_provenance_with_store(
        &mut self,
        store: &PlanningStore<'_>,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        source: &SceneSource,
        context: &Value,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        OwnedPlanningData::validate_scene_provenance_with_store(
            self, store, principal, project, patch, source, context, budget,
        )
    }
    fn state_snapshot(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &Value,
        _: &Value,
        budget: &RequestBudget,
    ) -> AppResult<ObservedStateSnapshot> {
        check_budget(budget)?;
        Err(store_required())
    }
    fn scene_source(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &Value,
        budget: &RequestBudget,
    ) -> AppResult<SceneSource> {
        check_budget(budget)?;
        Err(store_required())
    }
    fn validate_scene_provenance(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &SceneSource,
        _: &Value,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        check_budget(budget)?;
        Err(store_required())
    }
}

pub struct OwnedStateSource {
    session: OwnedReadSession,
    store_root: PathBuf,
    instance_pin: OwnedDocumentPin,
    prefab_pin: OwnedDocumentPin,
    instance: Instance,
    prefab: Prefab,
    instance_value: Value,
    prefab_value: Value,
    instance_blob: BlobRef,
    prefab_blob: BlobRef,
}
impl OwnedStateSource {
    pub fn project(&self) -> &ProjectCatalog {
        &self.session.project
    }
    pub fn context(&self) -> &Value {
        &self.session.context
    }
    pub fn request(&self) -> &RequestContextWitness {
        &self.session.request
    }
    pub fn instance(&self) -> &Instance {
        &self.instance
    }
    pub fn prefab(&self) -> &Prefab {
        &self.prefab
    }
    pub fn instance_blob(&self) -> &BlobRef {
        &self.instance_blob
    }
    pub fn prefab_blob(&self) -> &BlobRef {
        &self.prefab_blob
    }
    /// 읽은 원본의 authored baseline이다. false·0·scope를 보존하지만 실제
    /// target 값, live snapshot, runtime alias 또는 새 읽기 권한을 발급하지 않는다.
    pub fn authored_defaults(&self) -> AppResult<BTreeMap<StateId, ScalarValue>> {
        effective_defaults(&self.prefab, &self.instance.overrides).map_err(domain_error)
    }
    pub fn check_current(&self, store: &PlanningStore<'_>) -> AppResult<()> {
        self.session.check_context()?;
        if !store.with_read(|store| Ok(store.data_root() == self.store_root))? {
            return Err(denied());
        }
        // Revalidation consumes the original cumulative source-read allowance;
        // it never renews the deadline, byte budget or authenticated request.
        let session = self.session.clone();
        session.check_project(store)?;
        let instance = session.document(store, &self.instance_pin)?;
        let prefab = session.document(store, &self.prefab_pin)?;
        if instance.document != self.instance_value
            || prefab.document != self.prefab_value
            || instance.blob != self.instance_blob
            || prefab.blob != self.prefab_blob
        {
            return Err(revision_conflict());
        }
        session.check_context()?;
        session.check_project(store)
    }
}

#[derive(Clone)]
struct OwnedReadSession {
    request: RequestContextWitness,
    access: LocalPlanningAccess,
    authority: LocalAuthority,
    project: ProjectCatalog,
    context: Value,
    context_id: ContextId,
    failures: Rc<RefCell<Option<AppError>>>,
    bytes: Rc<Cell<u64>>,
}
impl OwnedReadSession {
    fn check_local(&self) -> AppResult<()> {
        self.request.check_local().map_err(service_error)?;
        self.access.check()?;
        self.authority.authorize_retained_scope(
            self.access.principal(),
            self.project.project_id(),
            &self.context_id,
            &decode(&self.context["policyRevision"])?,
            &self.context["scope"],
        )
    }
    fn check_context(&self) -> AppResult<()> {
        self.check_local()?;
        self.access.authorize_project(
            self.access.principal(),
            self.project.project_id(),
            Some(&self.context),
            Access::ReadProject,
        )?;
        self.check_local()
    }
    fn storage_check(&self) -> StorageResult<()> {
        self.check_local().map_err(|error| self.relay(error))
    }
    fn relay(&self, error: AppError) -> StorageError {
        let code = error.code;
        if let Ok(mut pending) = self.failures.try_borrow_mut()
            && pending.is_none()
        {
            *pending = Some(error);
        }
        StorageError::InvalidInput(code.into())
    }
    fn release(&self, error: StorageError) -> AppError {
        if let Ok(mut pending) = self.failures.try_borrow_mut()
            && let Some(original) = pending.take()
        {
            return original;
        }
        storage_error(error)
    }
    fn source_scope(&self, kind: &str, id: &str) -> StorageResult<()> {
        self.storage_check()?;
        let scope = self
            .authority
            .project_scope(self.access.principal(), self.project.project_id())
            .map_err(|error| self.relay(error))?;
        if ![&scope, &self.context["scope"]].iter().all(|scope| {
            scope[kind]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|value| value.as_str() == Some(id)))
        }) {
            return Err(self.relay(denied()));
        }
        self.storage_check()
    }
    fn remaining(&self) -> AppResult<u64> {
        MAX_TOTAL
            .checked_sub(self.bytes.get())
            .filter(|left| *left > 0)
            .ok_or_else(source_budget)
    }
    fn count(&self, bytes: u64) -> AppResult<()> {
        let total = self
            .bytes
            .get()
            .checked_add(bytes)
            .filter(|total| *total <= MAX_TOTAL)
            .ok_or_else(source_budget)?;
        self.bytes.set(total);
        Ok(())
    }
    fn check_project(&self, store: &PlanningStore<'_>) -> AppResult<()> {
        self.check_local()?;
        let mut reader =
            ProjectResourceReader::new(Box::new(self.clone()), MAX_TOTAL).map_err(storage_error)?;
        let actual = store.with_read(|store| {
            reader
                .read_project(
                    store,
                    self,
                    self.project.project_id(),
                    self.project.revision(),
                    MAX_DOCUMENT,
                )
                .map_err(|error| self.release(error))
        })?;
        if actual != *self.project.project() {
            return Err(revision_conflict());
        }
        self.check_local()
    }
    fn document(
        &self,
        store: &PlanningStore<'_>,
        pin: &OwnedDocumentPin,
    ) -> AppResult<OwnedDocumentBytes> {
        self.check_local()?;
        let mut reader =
            OwnedDocumentReader::new(Box::new(self.clone()), MAX_DOCUMENT.min(self.remaining()?))
                .map_err(storage_error)?;
        let result = store.with_read(|store| {
            reader
                .read_known_history_bytes(
                    store,
                    self,
                    self.project.project_id(),
                    self.project.revision(),
                    pin,
                )
                .map_err(|error| self.release(error))
        })?;
        self.count(result.blob.byte_length)?;
        self.check_local()?;
        Ok(result)
    }
    fn resource(&self, store: &PlanningStore<'_>, pin: &ResourceRef) -> AppResult<Vec<u8>> {
        self.check_local()?;
        let query = if self.project.resource_ids().contains(&pin.resource_id) {
            ProjectResourceQuery::Exact {
                resource_id: pin.resource_id.clone(),
                digest: pin.sha256.clone(),
            }
        } else {
            // A private artifact still requires an actual Project-owned immutable
            // registration and an explicit current resource scope. Its digest
            // or URI does not create that read permission.
            ProjectResourceQuery::RegisteredImmutable {
                resource_id: pin.resource_id.clone(),
            }
        };
        let expected = serde_json::to_value(pin).map_err(|_| invalid())?;
        let request = ProjectResourceRequest {
            project: self.project.project_id(),
            current_project_revision: self.project.revision(),
            query: &query,
            expected: Some(&expected),
        };
        let mut reader =
            ProjectResourceReader::new(Box::new(self.clone()), MAX_TOTAL).map_err(storage_error)?;
        let result = store.with_read(|store| {
            reader
                .read(store, self, &request, self.remaining()?)
                .map_err(|error| self.release(error))
        })?;
        self.count(result.bytes.len() as u64)?;
        self.check_local()?;
        Ok(result.bytes)
    }
    fn selection<'a>(
        &self,
        store: &PlanningStore<'_>,
        targets: impl Iterator<Item = &'a ObjectNode>,
        map: &ResourceRef,
        id: &str,
    ) -> AppResult<Selection> {
        let targets = targets.cloned().collect::<BTreeSet<_>>();
        if targets.is_empty() || targets.len() > MAX_TARGETS {
            return Err(source_budget());
        }
        let mut instances: BTreeMap<String, Value> = BTreeMap::new();
        let mut prefabs: BTreeMap<String, Value> = BTreeMap::new();
        for target in &targets {
            if let std::collections::btree_map::Entry::Vacant(instance_entry) =
                instances.entry(target.instance_id.clone())
            {
                let pin = self
                    .project
                    .owned_pin(OwnedKind::Instance, &target.instance_id)?
                    .clone();
                let owned = OwnedDocumentPin {
                    kind: OwnedDocumentKind::Instance,
                    object_id: pin.object_id,
                    revision: pin.revision,
                };
                let value = self.document(store, &owned)?.document;
                let prefab_id = text(&value, "prefabId")?.to_owned();
                let revision: Sha256Digest = decode(&value["prefabRevision"])?;
                match prefabs.entry(prefab_id.clone()) {
                    std::collections::btree_map::Entry::Vacant(prefab_entry) => {
                        self.project
                            .authorize_pin(OwnedKind::Prefab, &prefab_id, &revision)?;
                        let owned = OwnedDocumentPin {
                            kind: OwnedDocumentKind::Prefab,
                            object_id: decode(&value["prefabId"])?,
                            revision,
                        };
                        prefab_entry.insert(self.document(store, &owned)?.document);
                    }
                    std::collections::btree_map::Entry::Occupied(prefab_entry)
                        if prefab_entry.get()["revision"] != revision.as_str() =>
                    {
                        return Err(revision_conflict());
                    }
                    _ => {}
                }
                instance_entry.insert(value);
            }
        }
        let selected = targets
            .iter()
            .map(|target| target.node_id.clone())
            .collect::<BTreeSet<_>>();
        let value = json!({"contractVersion":mmmm_contracts::CONTRACT_VERSION,"selectionId":id,
            "projectId":self.project.project_id(),"projectRevision":self.project.revision(),
            "instances":instances.into_values().collect::<Vec<_>>(),"prefabs":prefabs.into_values().collect::<Vec<_>>(),
            "selectedNodeIds":selected,"externalReferencePolicy":"preserve","sourceMap":map});
        if encode_json(&value).map_err(json_error)?.len() as u64 > MAX_DOCUMENT {
            return Err(source_budget());
        }
        let selection = Selection::from_value(&value).map_err(exchange_error)?;
        if targets
            .iter()
            .any(|target| selection.node(target).is_none())
        {
            return Err(invalid());
        }
        Ok(selection)
    }

    fn checked_selection_artifact(
        &self,
        store: &PlanningStore<'_>,
        artifact: &Value,
        map: &ResourceRef,
    ) -> AppResult<Selection> {
        let selection = Selection::from_value(artifact).map_err(exchange_error)?;
        selection
            .check_revision(
                self.project.project_id().as_str(),
                self.project.revision().as_str(),
            )
            .map_err(exchange_error)?;
        if array(artifact, "instances")?.len() > MAX_TARGETS
            || array(artifact, "prefabs")?.len() > MAX_TARGETS
            || canonical_digest(&artifact["sourceMap"]).map_err(digest_error)?
                != canonical_digest(&serde_json::to_value(map).map_err(|_| invalid())?)
                    .map_err(digest_error)?
        {
            return Err(revision_conflict());
        }
        for instance in array(artifact, "instances")? {
            let current = self
                .project
                .owned_pin(OwnedKind::Instance, text(instance, "instanceId")?)?;
            if instance["revision"] != current.revision.as_str() {
                return Err(revision_conflict());
            }
            let pin = owned_pin(&self.project, OwnedKind::Instance, instance)?;
            if self.document(store, &pin)?.document != *instance {
                return Err(revision_conflict());
            }
        }
        for prefab in array(artifact, "prefabs")? {
            let pin = owned_pin(&self.project, OwnedKind::Prefab, prefab)?;
            if self.document(store, &pin)?.document != *prefab {
                return Err(revision_conflict());
            }
        }
        // Keep original array order and the complete selected base. A partial
        // edit does not discard other selected owned instances or nodes.
        Ok(selection)
    }
}
impl ProjectSourceRpcContext for OwnedReadSession {
    fn check(&self) -> StorageResult<()> {
        self.storage_check()
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.storage_check()?;
        Ok(self.access.principal().clone())
    }
    fn context_id(&self) -> Option<&ContextId> {
        Some(&self.context_id)
    }
}
impl ProjectResourceAuthority for OwnedReadSession {
    fn authorize_project_read(
        &mut self,
        _: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        revision: &Sha256Digest,
    ) -> StorageResult<()> {
        if principal != self.access.principal()
            || context != Some(&self.context_id)
            || project != self.project.project_id()
            || revision != self.project.revision()
        {
            return Err(self.relay(denied()));
        }
        self.storage_check()
    }
    fn authorize_resource_read(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        resource: &RegisteredProjectResource,
    ) -> StorageResult<()> {
        let revision = self.project.revision().clone();
        ProjectResourceAuthority::authorize_project_read(
            self, store, principal, context, project, &revision,
        )?;
        if resource.owner != ResourceOwner::Project(project.clone()) {
            return Err(self.relay(denied()));
        }
        self.source_scope(
            "resourceIds",
            resource.resource["resourceId"]
                .as_str()
                .ok_or_else(|| StorageError::InvalidInput("Resource identity absent".into()))?,
        )
    }
}
impl OwnedDocumentAuthority for OwnedReadSession {
    fn authorize_read(
        &mut self,
        principal: &PrincipalId,
        context: &ContextId,
        project: &ProjectId,
        revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> StorageResult<()> {
        OwnedDocumentAuthority::authorize_project_read(
            self,
            principal,
            Some(context),
            project,
            revision,
            pin,
        )
    }
    fn authorize_project_read(
        &mut self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> StorageResult<()> {
        if principal != self.access.principal()
            || context != Some(&self.context_id)
            || project != self.project.project_id()
            || revision != self.project.revision()
        {
            return Err(self.relay(denied()));
        }
        self.source_scope("objectIds", pin.object_id.as_str())
    }
}

fn owned_pin(
    project: &ProjectCatalog,
    kind: OwnedKind,
    value: &Value,
) -> AppResult<OwnedDocumentPin> {
    validate(kind.definition(), value)?;
    let revision: Sha256Digest = decode(&value["revision"])?;
    let pin = project.authorize_pin(kind, text(value, kind.id_field())?, &revision)?;
    Ok(OwnedDocumentPin {
        kind: match kind {
            OwnedKind::Prefab => OwnedDocumentKind::Prefab,
            OwnedKind::Instance => OwnedDocumentKind::Instance,
            _ => return Err(invalid()),
        },
        object_id: pin.object_id.clone(),
        revision: pin.revision.clone(),
    })
}
fn verify_static_mapping(
    artifact: &Value,
    map: &Value,
    resource: &ResourceRef,
    selection: &Selection,
    target: &ObjectNode,
    kind: DeltaKind,
    entry: &Value,
) -> AppResult<()> {
    let prefab = selection
        .prefab_for(&target.instance_id)
        .ok_or_else(invalid)?;
    let mut nodes = Vec::new();
    if artifact["prefabId"].as_str() == Some(prefab) {
        for (index, node) in array(artifact, "nodes")?
            .iter()
            .enumerate()
            .filter(|(_, node)| node["nodeId"].as_str() == Some(target.node_id.as_str()))
        {
            nodes.push((format!("/nodes/{index}"), node));
        }
    } else if artifact.get("instances").is_some() {
        for (index, definition) in array(artifact, "prefabs")?
            .iter()
            .enumerate()
            .filter(|(_, definition)| definition["prefabId"].as_str() == Some(prefab))
        {
            for (node_index, node) in array(definition, "nodes")?
                .iter()
                .enumerate()
                .filter(|(_, node)| node["nodeId"].as_str() == Some(target.node_id.as_str()))
            {
                nodes.push((format!("/prefabs/{index}/nodes/{node_index}"), node));
            }
        }
    }
    if nodes.len() != 1 {
        return Err(invalid());
    }
    let (locator, node) = &nodes[0];
    let field = match kind {
        DeltaKind::UpdateTransform => "transform",
        DeltaKind::UpdateDisplay => "display",
        _ => return Err(invalid()),
    };
    let matches = array(map, "entries")?
        .iter()
        .filter(|mapping| {
            mapping["sourceObjectId"].as_str() == Some(target.instance_id.as_str())
                && mapping["sourceNodeId"].as_str() == Some(target.node_id.as_str())
                && mapping["outputResourceId"].as_str() == Some(resource.resource_id.as_str())
                && (mapping["locator"].as_str() == Some(locator.as_str())
                    || mapping["locator"].as_str() == Some(format!("{locator}/{field}").as_str()))
        })
        .count();
    if matches != 1 {
        return Err(AppError::new(
            "OBJECT_MAPPING_AMBIGUOUS",
            "Owned scene target has no unique original qualified source-map locator",
        ));
    }
    if entry.get(field).is_none() || entry[field] != node[field] {
        return Err(revision_conflict());
    }
    Ok(())
}
fn array<'a>(value: &'a Value, key: &str) -> AppResult<&'a [Value]> {
    value[key].as_array().map(Vec::as_slice).ok_or_else(invalid)
}
fn text<'a>(value: &'a Value, key: &str) -> AppResult<&'a str> {
    value[key].as_str().ok_or_else(invalid)
}
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> AppResult<T> {
    let mut typed = value.clone();
    normalize_resource_lengths(&mut typed);
    serde_json::from_value(typed).map_err(|_| invalid())
}
// JSON Schema permits an integral sizeBytes written as 1.0. Normalize only
// that original ResourceRef's typed u64 view; retained source Values/bytes and
// their original hashes remain unchanged.
fn normalize_resource_lengths(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(normalize_resource_lengths),
        Value::Object(fields) => {
            if fields.len() == 4
                && ["resourceId", "sha256", "mediaType", "sizeBytes"]
                    .iter()
                    .all(|key| fields.contains_key(*key))
                && let Some(size) = fields["sizeBytes"].as_f64().filter(|size| {
                    size.is_finite()
                        && size.fract() == 0.0
                        && *size >= 0.0
                        && *size <= 9_007_199_254_740_991.0
                })
            {
                fields.insert("sizeBytes".into(), Value::from(size as u64));
            }
            fields.values_mut().for_each(normalize_resource_lengths);
        }
        _ => {}
    }
}
fn validate(name: &str, value: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .and_then(|validator| validator.validate(name, value))
        .map_err(|error| {
            AppError::caused_by(
                "INVALID_INPUT",
                "Owned planning input violates the canonical contract",
                error,
            )
        })
}
fn check_budget(budget: &RequestBudget) -> AppResult<()> {
    budget.check().map_err(service_error)
}
fn service_error(error: crate::service::ServiceError) -> AppError {
    AppError::caused_by(error.code, error.message, error)
}
fn storage_error(error: StorageError) -> AppError {
    let code = match &error {
        StorageError::Conflict(_) => "REVISION_CONFLICT",
        StorageError::Corrupt(_) => "INVALID_STORED_EVIDENCE",
        _ => "SOURCE_UNAVAILABLE",
    };
    AppError::caused_by(code, "Retained owned source could not be read", error)
}
fn json_error(error: mmmm_contracts::JsonError) -> AppError {
    AppError::caused_by(
        "INVALID_STORED_EVIDENCE",
        "Owned source is not bounded strict JSON",
        error,
    )
}
fn digest_error(error: mmmm_contracts::DigestError) -> AppError {
    AppError::caused_by(
        "INPUT_DIGEST_MISMATCH",
        "Owned source digest could not be verified",
        error,
    )
}
fn domain_error(error: mmmm_domain::DomainError) -> AppError {
    AppError::caused_by(error.code, "Owned source has invalid authored state", error)
}
fn exchange_error(error: mmmm_exchange::ExchangeError) -> AppError {
    AppError::caused_by(
        error.code,
        "Owned scene selection or delta provenance is invalid",
        error,
    )
}
fn denied() -> AppError {
    AppError::new(
        "PERMISSION_REQUIRED",
        "Current authenticated source scope does not cover the retained owned data",
    )
}
fn invalid() -> AppError {
    AppError::new(
        "INVALID_INPUT",
        "Owned source selection contains an absent or inconsistent canonical identity",
    )
}
fn revision_conflict() -> AppError {
    AppError::new(
        "REVISION_CONFLICT",
        "Owned planning source differs from the actual immutable Project revision",
    )
}
fn source_budget() -> AppError {
    AppError::new(
        "BUDGET_EXCEEDED",
        "Owned planning source exceeds its finite object or byte budget",
    )
}
fn state_unavailable() -> AppError {
    AppError::new(
        "STATE_SNAPSHOT_REQUIRED",
        "An actual independent complete instance-state codec is required",
    )
}
fn store_required() -> AppError {
    AppError::new(
        "STORE_REQUIRED",
        "Owned planning data requires the actual call-scoped product store",
    )
}

#[cfg(test)]
#[path = "owned_planning_data_tests.rs"]
mod tests;

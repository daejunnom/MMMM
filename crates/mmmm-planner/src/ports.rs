use crate::{NativeActionRoute, NativeKind, ObjectPin, PreparedNativeChange, ProjectCatalog};
use mmmm_adapters::{ActionDescriptor, InventorySnapshot};
use mmmm_application::{AppResult, RecoveryPreparation};
use mmmm_compiler::{PackBuildInputs, VerifiedTarget};
use mmmm_contracts::{InstanceId, ModuleId, PrincipalId, Sha256Digest, TargetProfileId};
use mmmm_domain::{
    commands::CommandLayoutSupport, instance::ResolvedStateSnapshot, types::ResourceRef,
};
use mmmm_exchange::{patch::DeltaPolicy, selection::Selection};
use mmmm_runtime::storage::WriteScope;
use serde_json::Value;
use std::collections::BTreeSet;

pub struct PinnedResourceBytes {
    pub resource: ResourceRef,
    pub bytes: Vec<u8>,
}
pub struct PinnedStateSnapshot {
    pub resource: ResourceRef,
    pub snapshot: ResolvedStateSnapshot,
}
/// A protected native manual producer supplies the exact returned static patch.
/// This is in-process source data, never a deserializable permission or bake.
/// The source port must verify its producer and call-local three-resource
/// admission; the planner independently reads this exact pin's original bytes.
pub struct ManualScenePayload {
    pub resource: ResourceRef,
    pub payload: Value,
}
pub struct SceneSource {
    pub selection: Selection,
    pub delta_policy: DeltaPolicy,
    pub artifact: Value,
    pub source_map: Value,
    pub manual_payload: Option<ManualScenePayload>,
    /// Sealed exchange ingestion is mandatory for baked clip attachment. Its
    /// canonical clip derivatives keep raw artifact/map provenance separately.
    pub ingested_bake: Option<mmmm_exchange::bake::IngestedBake>,
}

/// Immutable owned-data access. Implementations apply actual principal/project
/// ACL before loading an object or local CAS blob, bound reads, and check source
/// records; neither a ResourceRef nor membership alone is an access grant.
pub trait ProjectSourcePort {
    /// Read-only project validation without inventing a game ExecutionContext.
    /// Return exactly the current immutable authoring inventory under project
    /// ACL, within the caller's cumulative byte limit.
    fn inspect_owned(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        max_bytes: u64,
    ) -> AppResult<Vec<(ObjectPin, Value)>>;
    fn owned_object(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        pin: &ObjectPin,
        context: Option<&Value>,
        max_bytes: u64,
    ) -> AppResult<Value>;
    fn resource_pin(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        resource_id: &str,
        context: Option<&Value>,
    ) -> AppResult<ResourceRef>;
    fn resource_bytes(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        resource: &ResourceRef,
        context: Option<&Value>,
        max_bytes: u64,
    ) -> AppResult<PinnedResourceBytes>;
    /// Private cache/CAS only; this cannot install, reload, replace user files or
    /// mutate authored project state. Returned metadata is checked against bytes.
    fn stage_private(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        desired_resource_id: Option<&mmmm_contracts::ResourceId>,
        bytes: &[u8],
        media_type: &str,
        context: &Value,
    ) -> AppResult<ResourceRef>;
    fn allocate_instance_id(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        used: &BTreeSet<InstanceId>,
    ) -> AppResult<InstanceId>;
    /// Independently observed state codec pins source instance/prefab and actor
    /// scope; ChangeIntent intentionally carries no caller state-snapshot token.
    fn state_snapshot(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        instance: &Value,
        definition: &Value,
        context: &Value,
    ) -> AppResult<PinnedStateSnapshot>;
    fn scene_source(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        context: &Value,
    ) -> AppResult<SceneSource>;
    /// This verifies source artifact/source-map provenance and exact stable track
    /// attachment; raw patch or display names cannot create a proof.
    fn validate_scene_provenance(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        patch: &Value,
        source: &SceneSource,
        context: &Value,
    ) -> AppResult<()>;
}

#[derive(Clone, Debug)]
pub struct VerifiedNativeTarget {
    pub profile_id: TargetProfileId,
    pub profile_digest: Sha256Digest,
    pub artifact_digest: Sha256Digest,
    pub evidence_resource_pins: Vec<ResourceRef>,
    pub supported_kinds: BTreeSet<NativeKind>,
}

/// A target before image from the independent observer path. Exact raw bytes
/// are pinned again by the planner. Reported desired state is not a snapshot.
pub struct TargetBeforeImage {
    pub kind: &'static str,
    pub subject: String,
    pub bytes: Vec<u8>,
    pub digest: Sha256Digest,
    pub coverage: &'static str,
}

pub struct NativeTargetSnapshot {
    pub context_digest: Sha256Digest,
    pub scope: WriteScope,
    pub targets: Vec<TargetBeforeImage>,
    /// Native codec observations must bind all exact before/after projections
    /// (including command rack, display/model extents and physics carriers) to
    /// the complete footprint and independently observed target set.
    pub projection_coverage: Vec<ProjectionCoverage>,
}
pub struct ProjectionCoverage {
    pub instance_id: mmmm_contracts::InstanceId,
    pub projection_digest: Sha256Digest,
    pub footprint_digest: Sha256Digest,
    pub target_subjects: BTreeSet<String>,
}
pub struct RegisteredActionFootprint {
    pub scope: WriteScope,
    pub targets: Vec<TargetBeforeImage>,
    pub resources_read: BTreeSet<String>,
    pub resources_written: BTreeSet<String>,
    pub losses: Vec<Value>,
    pub dependency_pins: Vec<Value>,
}

/// Authenticated host/config composition supplies all observations. Implementing
/// this trait with fixtures proves pure planner behavior, not a verified target.
/// Every method is metadata/read/private staging and must honor finite budgets.
pub trait PlanningEnvironmentPort {
    /// Live host/transport admission limit. The planner intersects this with its
    /// local finite budget; invocation deadlines cannot be silently clamped.
    fn execution_budget_ms(&mut self, principal: &PrincipalId, context: &Value) -> AppResult<u64>;
    fn inventory(
        &mut self,
        principal: &PrincipalId,
        context: &Value,
    ) -> AppResult<InventorySnapshot>;
    /// Exact server-owned component provenance for the selected registered
    /// implementation. Origin labels alone cannot classify an implementation.
    /// The pin includes the selected action ID in contractIds.
    fn binding_dependency(
        &mut self,
        principal: &PrincipalId,
        binding: &mmmm_contracts::BindingId,
        implementation_digest: &Sha256Digest,
        context: &Value,
    ) -> AppResult<Value>;
    fn native_route(
        &mut self,
        principal: &PrincipalId,
        kind: NativeKind,
        context: &Value,
    ) -> AppResult<NativeActionRoute>;
    fn verified_native_target(
        &mut self,
        principal: &PrincipalId,
        profile: &TargetProfileId,
        kind: NativeKind,
        context: &Value,
    ) -> AppResult<VerifiedNativeTarget>;
    fn snapshot_native_targets(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        change: &PreparedNativeChange,
        context: &Value,
    ) -> AppResult<NativeTargetSnapshot>;
    fn registered_action_footprint(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        request: &Value,
        action: &ActionDescriptor,
        context: &Value,
    ) -> AppResult<RegisteredActionFootprint>;
    fn relocatable_modules(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        modules: &[Value],
        context: &Value,
    ) -> AppResult<BTreeSet<ModuleId>>;
    fn command_layout_support(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        module: &Value,
        context: &Value,
    ) -> AppResult<CommandLayoutSupport>;
    fn command_layout_request(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        instance: &Value,
        module: &Value,
        context: &Value,
    ) -> AppResult<Value>;
    /// Resolve declared project/external symbols under the actual principal and
    /// freeze their implementation dependencies. Preserving a string alone
    /// cannot establish that a generated command/function target exists.
    fn verify_projection_references(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        projection: &crate::InstanceProjection,
        context: &Value,
    ) -> AppResult<Vec<Value>>;
    fn compiler_target(
        &mut self,
        principal: &PrincipalId,
        profile: &TargetProfileId,
        context: &Value,
    ) -> AppResult<VerifiedTarget>;
    /// Owned compiler backend must lower every object it covers. A math-only
    /// backend returns CAPABILITY_UNAVAILABLE for uncovered authored resources.
    fn pack_inputs(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        owned_values: &[Value],
        context: &Value,
    ) -> AppResult<PackBuildInputs>;
    fn recovery_route(
        &mut self,
        principal: &PrincipalId,
        recovery: &RecoveryPreparation,
        context: &Value,
    ) -> AppResult<NativeActionRoute>;
    fn recovery_scope(
        &mut self,
        principal: &PrincipalId,
        recovery: &RecoveryPreparation,
        project: &ProjectCatalog,
        context: &Value,
    ) -> AppResult<WriteScope>;
    fn project_bindings_available(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
    ) -> AppResult<bool>;
}

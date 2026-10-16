//! FN23 uses authenticated contexts and actual host observations. Native voxel
//! boxes retain offsets and their union; no block-name or render-model fallback
//! can create geometry. Cached observations keep their original observation
//! window and are accompanied by a separate current dependency probe.

use crate::{ReadPrincipal, SnapshotPin};
use mmmm_contracts::{
    ContextId, ContractError, ContractValidator, Int32, ResourceLocation, Sha256Digest,
    canonical_digest, encode_json, parse_json, raw_digest, verify_projected_digest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub const NATIVE_VOXEL_FORMAT: &str = "mmmm.native.voxel-aabbs/1";
pub const NATIVE_VOXEL_MEDIA_TYPE: &str = "application/vnd.mmmm.native-voxel-aabbs+json";

#[derive(Debug)]
pub enum ShapeError {
    Contract(ContractError),
    InvalidObservation,
    InputLimit,
    PermissionRequired,
    StaleContext,
    SideMismatch,
    TargetDrift,
    SourceUnavailable,
    Cancelled,
    DeadlineExceeded,
    Host { code: String },
}
impl ShapeError {
    pub fn code(&self) -> &str {
        match self {
            Self::Contract(_) | Self::InvalidObservation => "SCHEMA_UNSUPPORTED",
            Self::InputLimit => "INPUT_LIMIT",
            Self::PermissionRequired => "PERMISSION_REQUIRED",
            Self::StaleContext => "STALE_CONTEXT",
            Self::SideMismatch => "SIDE_MISMATCH",
            Self::TargetDrift => "TARGET_DRIFT",
            Self::SourceUnavailable => "SOURCE_UNAVAILABLE",
            Self::Cancelled => "CANCELLED",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::Host { code } => code,
        }
    }
}
impl From<ContractError> for ShapeError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}
impl fmt::Display for ShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl Error for ShapeError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GameMode {
    Survival,
    Creative,
    Adventure,
    Spectator,
}

/// Issued by the server's principal-bound context/snapshot authority. None of
/// these values is adopted from user-supplied ShapeQueryContext fields.
#[derive(Clone, Debug)]
pub struct ShapeGrant {
    pub execution_context: Value,
    pub snapshot: SnapshotPin,
    pub host_hello: Value,
    pub allowed_modes: BTreeSet<GameMode>,
}
pub trait ShapeAuthority {
    /// Check current read permission, context ownership, policy and target
    /// readiness. Resolve any entity handle in this principal/context scope.
    /// Called before every probe and again before returning a read.
    fn authorize_shape(
        &self,
        principal: &ReadPrincipal,
        query: &Value,
    ) -> Result<ShapeGrant, ShapeError>;
}

pub struct ShapeControl<'a> {
    pub cancellation: &'a AtomicBool,
    pub deadline: Instant,
    /// Server-issued RFC3339 deadline for the exact HostRequest envelope.
    pub deadline_at: &'a str,
}
impl ShapeControl<'_> {
    pub fn check(&self) -> Result<(), ShapeError> {
        if self.cancellation.load(Ordering::Acquire) {
            return Err(ShapeError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(ShapeError::DeadlineExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShapeDependencyRegion {
    pub dimension: ResourceLocation,
    pub min: [Int32; 3],
    pub max_exclusive: [Int32; 3],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyScope {
    Complete,
    Unknown,
}

/// Private host inspection metadata, distinct from the canonical ShapeResult.
/// Nullable target facts remain unknown and never become caller expectations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShapeProbe {
    pub protocol_version: String,
    pub context_digest: Sha256Digest,
    pub environment: Value,
    pub dimension: ResourceLocation,
    pub position: [Int32; 3],
    pub game_version: String,
    pub host_build: String,
    pub artifact_sha256: Option<Sha256Digest>,
    pub target_fingerprint: Option<Sha256Digest>,
    pub registry_digest: Sha256Digest,
    pub registry_generation: String,
    pub server_pack_stack: Option<Vec<Sha256Digest>>,
    pub client_pack_stack: Option<Vec<Sha256Digest>>,
    pub mod_fingerprint_digest: Option<Sha256Digest>,
    pub locale: String,
    pub mode: GameMode,
    pub ready: bool,
    pub loaded: bool,
    pub block_state: Option<Value>,
    pub neighbor_context_digest: Option<Sha256Digest>,
    pub entity_context_handle: Option<String>,
    pub entity_context_digest: Option<Sha256Digest>,
    pub fluid_context_digest: Option<Sha256Digest>,
    pub permission_digest: Sha256Digest,
    pub observed_from_tick: String,
    pub observed_to_tick: String,
    pub observed_at: String,
    pub world_revision: Option<Sha256Digest>,
    pub dependency_scope: DependencyScope,
    pub dependency_digest: Option<Sha256Digest>,
    pub dependencies: Vec<ShapeDependencyRegion>,
}

impl ShapeProbe {
    pub fn from_value(value: &Value) -> Result<Self, ShapeError> {
        encode_json(value).map_err(|_| ShapeError::InputLimit)?;
        let result: Self =
            serde_json::from_value(value.clone()).map_err(|_| ShapeError::InvalidObservation)?;
        result.validate()?;
        Ok(result)
    }
    pub fn wire(&self) -> Result<Value, ShapeError> {
        serde_json::to_value(self).map_err(|_| ShapeError::InvalidObservation)
    }
    fn validate(&self) -> Result<(), ShapeError> {
        if self.protocol_version != mmmm_contracts::CONTRACT_VERSION
            || self.game_version.is_empty()
            || self.game_version.len() > 128
            || self.host_build.is_empty()
            || self.host_build.len() > 256
            || self.registry_generation.is_empty()
            || self.registry_generation.len() > 128
            || self.locale.is_empty()
            || self.locale.len() > 256
            || self.dependencies.len() > 256
            || self
                .server_pack_stack
                .as_ref()
                .is_some_and(|packs| packs.len() > 1024)
            || self
                .client_pack_stack
                .as_ref()
                .is_some_and(|packs| packs.len() > 1024)
        {
            return Err(ShapeError::InvalidObservation);
        }
        ContractValidator::shared()?.validate("EnvironmentRef", &self.environment)?;
        if self.environment["kind"] != "game" {
            return Err(ShapeError::StaleContext);
        }
        tick_window(&self.observed_from_tick, &self.observed_to_tick)?;
        let source = json!({"sourceId":"shape-probe","kind":"runtime_observation","locator":"mmmm-host://shape/probe",
            "sha256":null,"rights":"user_local_only","verifiedAt":self.observed_at});
        ContractValidator::shared()?.validate("SourceRef", &source)?;
        for region in &self.dependencies {
            if (0..3).any(|axis| region.min[axis].get() >= region.max_exclusive[axis].get()) {
                return Err(ShapeError::InvalidObservation);
            }
        }
        if self
            .entity_context_handle
            .as_ref()
            .is_some_and(|id| ContextId::new(id).is_err())
            || self.entity_context_handle.is_none() && self.entity_context_digest.is_some()
            || self.dependency_scope == DependencyScope::Complete
                && (self.dependency_digest.is_none() || self.dependencies.is_empty())
        {
            return Err(ShapeError::InvalidObservation);
        }
        Ok(())
    }
    fn stable_digest(&self) -> Result<Sha256Digest, ShapeError> {
        let mut value = self.wire()?;
        // Observation times document separate reads and are not dependencies.
        for field in ["observedFromTick", "observedToTick", "observedAt"] {
            value.as_object_mut().unwrap().remove(field);
        }
        canonical_digest(&value).map_err(|_| ShapeError::InputLimit)
    }
}

fn tick_window(first: &str, last: &str) -> Result<(), ShapeError> {
    fn valid(text: &str) -> bool {
        !text.is_empty()
            && text.len() <= 128
            && text.bytes().all(|b| b.is_ascii_digit())
            && (text == "0" || !text.starts_with('0'))
    }
    if !valid(first) || !valid(last) || (first.len(), first) > (last.len(), last) {
        return Err(ShapeError::InvalidObservation);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Query {
    snapshot_id: String,
    context_id: ContextId,
    dimension: ResourceLocation,
    position: [Int32; 3],
    block_state: Value,
    neighbor_context_digest: Sha256Digest,
    entity_context_handle: Option<String>,
    shape_kind: String,
    load_policy: String,
}

#[derive(Clone, Debug)]
pub struct ShapeSourceResult {
    pub result: Value,
    pub probe: ShapeProbe,
    pub observation_bytes: Arc<[u8]>,
    pub source: Value,
}
pub trait ShapePort {
    fn probe_shape(
        &mut self,
        grant: &ShapeGrant,
        query: &Value,
        control: &ShapeControl<'_>,
    ) -> Result<ShapeProbe, ShapeError>;
    /// Recheck the expected witness inside the same host game task as native
    /// shape access. A changed witness returns TARGET_DRIFT without geometry.
    fn query_shape(
        &mut self,
        principal: &ReadPrincipal,
        grant: &ShapeGrant,
        query: &Value,
        expected_probe: &ShapeProbe,
        control: &ShapeControl<'_>,
    ) -> Result<ShapeSourceResult, ShapeError>;
    /// Same current ACL for first read, cache hit and later artifact access.
    fn authorize_geometry(
        &mut self,
        principal: &ReadPrincipal,
        grant: &ShapeGrant,
        resource: &Value,
    ) -> Result<(), ShapeError>;
}

/// Implemented by the paired exact-0.2.0 transport. It sends HostRequest.inspect
/// with the installed context ID, never installs a context from this payload.
/// The host must authorize every actual neighbor/getter read against that
/// installed context and must not load chunks or acquire loading tickets.
pub trait HostShapeTransport {
    fn inspect_shape(
        &mut self,
        context: &Value,
        payload: &Value,
        control: &ShapeControl<'_>,
    ) -> Result<Value, ShapeError>;
}
pub trait ShapeGeometryStore {
    /// Flush/hash/publish raw observed bytes before issuing a retained resource
    /// reference; the application pins its lifetime outside build-cache GC.
    fn retain_geometry(
        &mut self,
        principal: &ReadPrincipal,
        context: &Value,
        query: &Value,
        bytes: &[u8],
        media_type: &str,
    ) -> Result<Value, ShapeError>;
    fn authorize_geometry(
        &mut self,
        principal: &ReadPrincipal,
        context: &Value,
        resource: &Value,
    ) -> Result<(), ShapeError>;
}

/// Actual native-host proxy composition, not a fixture-only source. The Java
/// shell supplies raw observation bytes; Rust issues the canonical ShapeResult.
pub struct PairedShapeSource<T, G> {
    pub transport: T,
    pub geometry: G,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NativeObservation {
    format: String,
    shape_kind: String,
    status: String,
    space: String,
    unit: String,
    exactness: String,
    provenance: String,
    boxes: Option<Vec<[f64; 6]>>,
    reason: Option<String>,
}
pub fn decode_native_observation(bytes: &[u8], shape_kind: &str) -> Result<(), ShapeError> {
    native_observation(bytes, shape_kind).map(|_| ())
}
fn native_observation(bytes: &[u8], shape_kind: &str) -> Result<NativeObservation, ShapeError> {
    if bytes.len() > 256 * 1024 {
        return Err(ShapeError::InputLimit);
    }
    let value = parse_json(bytes).map_err(|_| ShapeError::InvalidObservation)?;
    let observation: NativeObservation =
        serde_json::from_value(value).map_err(|_| ShapeError::InvalidObservation)?;
    if observation.format != NATIVE_VOXEL_FORMAT
        || observation.shape_kind != shape_kind
        || observation.space != "node_local"
        || observation.unit != "blocks"
        || observation.provenance != "observed"
        || !matches!(
            observation.exactness.as_str(),
            "exact" | "approximated" | "unknown"
        )
        || !matches!(
            observation.status.as_str(),
            "known" | "absent" | "unknown" | "unsupported" | "requires_runtime"
        )
    {
        return Err(ShapeError::InvalidObservation);
    }
    if observation.status == "known" {
        let boxes = observation
            .boxes
            .as_ref()
            .ok_or(ShapeError::InvalidObservation)?;
        if observation.reason.is_some() || observation.exactness == "unknown" {
            return Err(ShapeError::InvalidObservation);
        }
        if boxes.len() > 4096 {
            return Err(ShapeError::InputLimit);
        }
        if boxes.iter().any(|bounds| {
            bounds.iter().any(|v| !v.is_finite())
                || (0..3).any(|axis| bounds[axis] > bounds[axis + 3])
        }) {
            return Err(ShapeError::InvalidObservation);
        }
    } else if observation.boxes.is_some()
        || observation
            .reason
            .as_ref()
            .is_none_or(|reason| reason.is_empty() || reason.len() > 4096)
        || observation.exactness != "unknown"
    {
        return Err(ShapeError::InvalidObservation);
    }
    Ok(observation)
}

fn lower_hex(text: &str) -> Result<Vec<u8>, ShapeError> {
    if text.len() > 512 * 1024 || !text.len().is_multiple_of(2) {
        return Err(ShapeError::InputLimit);
    }
    fn digit(byte: u8) -> Result<u8, ShapeError> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(ShapeError::InvalidObservation),
        }
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(digit(pair[0])? * 16 + digit(pair[1])?))
        .collect()
}
fn source_ref(probe: &ShapeProbe, bytes: &[u8]) -> Value {
    let digest = raw_digest(bytes);
    json!({"sourceId":format!("shape-{digest}"),"kind":"runtime_observation",
        "locator":format!("mmmm-host://{}/{}/shape/{digest}",probe.environment["gameInstanceId"].as_str().unwrap(),probe.environment["sessionEpoch"].as_str().unwrap()),
        "sha256":digest,"rights":"user_local_only","verifiedAt":probe.observed_at})
}
fn validate_resource(resource: &Value, bytes: &[u8]) -> Result<(), ShapeError> {
    ContractValidator::shared()?.validate("ResourceRef", resource)?;
    if resource["sha256"] != raw_digest(bytes).as_str()
        || resource["mediaType"] != NATIVE_VOXEL_MEDIA_TYPE
        || resource["sizeBytes"].as_f64() != Some(bytes.len() as f64)
    {
        return Err(ShapeError::InvalidObservation);
    }
    Ok(())
}
fn coverage(probe: &ShapeProbe, shape_kind: &str, complete: bool, reason: Option<&str>) -> Value {
    json!({"status":if complete {"complete"} else {"partial"},
        "includedKinds":[format!("mmmm:{shape_kind}_shape")],
        "exclusions":reason.into_iter().collect::<Vec<_>>(),
        // Equal game ticks alone do not attest an atomic provider snapshot.
        "consistency":if probe.observed_from_tick==probe.observed_to_tick {"per_item_observed"} else {"bounded_window"}})
}

impl<T: HostShapeTransport, G: ShapeGeometryStore> ShapePort for PairedShapeSource<T, G> {
    fn probe_shape(
        &mut self,
        grant: &ShapeGrant,
        query: &Value,
        control: &ShapeControl<'_>,
    ) -> Result<ShapeProbe, ShapeError> {
        control.check()?;
        let payload = self.transport.inspect_shape(
            &grant.execution_context,
            &json!({"kind":"world.shape_probe","query":query}),
            control,
        )?;
        encode_json(&payload).map_err(|_| ShapeError::InputLimit)?;
        let object = payload.as_object().ok_or(ShapeError::InvalidObservation)?;
        if object.len() != 1 {
            return Err(ShapeError::InvalidObservation);
        }
        ShapeProbe::from_value(object.get("probe").ok_or(ShapeError::InvalidObservation)?)
    }
    fn query_shape(
        &mut self,
        principal: &ReadPrincipal,
        grant: &ShapeGrant,
        query: &Value,
        expected_probe: &ShapeProbe,
        control: &ShapeControl<'_>,
    ) -> Result<ShapeSourceResult, ShapeError> {
        control.check()?;
        let payload = self.transport.inspect_shape(
            &grant.execution_context,
            &json!({"kind":"world.shape_query",
            "query":query,"expectedProbe":expected_probe.wire()?}),
            control,
        )?;
        encode_json(&payload).map_err(|_| ShapeError::InputLimit)?;
        let object = payload.as_object().ok_or(ShapeError::InvalidObservation)?;
        if object.len() != 2 {
            return Err(ShapeError::InvalidObservation);
        }
        let probe =
            ShapeProbe::from_value(object.get("probe").ok_or(ShapeError::InvalidObservation)?)?;
        if probe.stable_digest()? != expected_probe.stable_digest()? {
            return Err(ShapeError::TargetDrift);
        }
        let bytes = lower_hex(
            object
                .get("observationBytesHex")
                .and_then(Value::as_str)
                .ok_or(ShapeError::InvalidObservation)?,
        )?;
        let kind = query["shapeKind"]
            .as_str()
            .ok_or(ShapeError::InvalidObservation)?;
        let observation = native_observation(&bytes, kind)?;
        if matches!(observation.status.as_str(), "known" | "absent")
            && kind == "fluid"
            && probe.fluid_context_digest.is_none()
        {
            return Err(ShapeError::InvalidObservation);
        }
        let complete = matches!(observation.status.as_str(), "known" | "absent");
        let mut result = json!({"contractVersion":"0.2.0","queryDigest":canonical_digest(query).map_err(|_|ShapeError::InputLimit)?,
            "status":observation.status,"observedFromTick":probe.observed_from_tick,"observedToTick":probe.observed_to_tick,
            "worldRevision":probe.world_revision,"coverage":coverage(&probe,kind,
                complete,if complete {None} else {observation.reason.as_deref()})});
        if observation.status == "known" {
            if !probe.ready || !probe.loaded {
                return Err(ShapeError::InvalidObservation);
            }
            let reference = self.geometry.retain_geometry(
                principal,
                &grant.execution_context,
                query,
                &bytes,
                NATIVE_VOXEL_MEDIA_TYPE,
            )?;
            validate_resource(&reference, &bytes)?;
            self.geometry
                .authorize_geometry(principal, &grant.execution_context, &reference)?;
            result["geometryRef"] = reference;
        } else {
            if observation.status == "absent" && (!probe.loaded || !probe.ready) {
                return Err(ShapeError::InvalidObservation);
            }
            result["reason"] = json!(observation.reason);
        }
        ContractValidator::shared()?.validate("ShapeResult", &result)?;
        let source = source_ref(&probe, &bytes);
        Ok(ShapeSourceResult {
            result,
            probe,
            source,
            observation_bytes: bytes.into(),
        })
    }
    fn authorize_geometry(
        &mut self,
        principal: &ReadPrincipal,
        grant: &ShapeGrant,
        resource: &Value,
    ) -> Result<(), ShapeError> {
        self.geometry
            .authorize_geometry(principal, &grant.execution_context, resource)
    }
}

#[derive(Clone, Debug)]
pub struct ShapeReadEvidence {
    pub cache_hit: bool,
    pub source_probe: ShapeProbe,
    pub current_probe: ShapeProbe,
    pub source: Value,
    pub observation_bytes: Arc<[u8]>,
}
#[derive(Clone, Debug)]
pub struct ShapeRead {
    pub result: Value,
    pub evidence: ShapeReadEvidence,
}

#[derive(Clone, Debug)]
pub struct ShapeLimits {
    pub max_cache_entries: usize,
    pub max_cache_bytes: usize,
    pub max_entry_bytes: usize,
    pub cache_ttl: Duration,
}
impl Default for ShapeLimits {
    fn default() -> Self {
        Self {
            max_cache_entries: 128,
            max_cache_bytes: 8 * 1024 * 1024,
            max_entry_bytes: 512 * 1024,
            cache_ttl: Duration::from_secs(30),
        }
    }
}
struct Cached {
    source: ShapeSourceResult,
    created: Instant,
    bytes: usize,
    principal: String,
    environment: Value,
    dependencies: Vec<ShapeDependencyRegion>,
    entity: Option<String>,
}
pub enum ShapeInvalidation {
    All,
    Principal(String),
    Environment {
        game_instance_id: String,
        session_epoch: String,
    },
    Region {
        game_instance_id: String,
        session_epoch: String,
        world_id: String,
        region: ShapeDependencyRegion,
    },
    Entity {
        game_instance_id: String,
        session_epoch: String,
        handle: String,
    },
}
pub struct ShapeService<P> {
    pub port: P,
    limits: ShapeLimits,
    cache: BTreeMap<Sha256Digest, Cached>,
    cache_bytes: usize,
}

impl<P: ShapePort> ShapeService<P> {
    pub fn new(port: P, limits: ShapeLimits) -> Result<Self, ShapeError> {
        if limits.max_cache_entries == 0
            || limits.max_cache_bytes == 0
            || limits.max_entry_bytes == 0
            || limits.cache_ttl.is_zero()
            || limits.cache_ttl > Duration::from_secs(300)
        {
            return Err(ShapeError::InputLimit);
        }
        Ok(Self {
            port,
            limits,
            cache: BTreeMap::new(),
            cache_bytes: 0,
        })
    }
    pub fn query(
        &mut self,
        input: &Value,
        principal: &ReadPrincipal,
        authority: &dyn ShapeAuthority,
        control: &ShapeControl<'_>,
    ) -> Result<ShapeRead, ShapeError> {
        control.check()?;
        encode_json(input).map_err(|_| ShapeError::InputLimit)?;
        ContractValidator::shared()?.validate("ShapeQueryContext", input)?;
        let query: Query =
            serde_json::from_value(input.clone()).map_err(|_| ShapeError::InputLimit)?;
        let grant = authority.authorize_shape(principal, input)?;
        let grant_digest = validate_grant(&grant, &query, principal)?;
        let probe = self.port.probe_shape(&grant, input, control)?;
        validate_probe(&grant, &query, &probe)?;
        control.check()?;
        let target_known = target_verified(&grant, &probe)?;
        if !probe.ready || !probe.loaded || !target_known {
            let reason = if !probe.ready {
                "host_not_ready"
            } else if !probe.loaded {
                "region_or_neighbors_not_loaded"
            } else {
                "target_identity_unverified"
            };
            let bytes = encode_json(&probe.wire()?).map_err(|_| ShapeError::InputLimit)?;
            let result = json!({"contractVersion":"0.2.0","queryDigest":canonical_digest(input).map_err(|_|ShapeError::InputLimit)?,
                "status":"unknown","observedFromTick":probe.observed_from_tick,"observedToTick":probe.observed_to_tick,
                "worldRevision":probe.world_revision,"coverage":coverage(&probe,&query.shape_kind,false,Some(reason)),"reason":reason});
            ContractValidator::shared()?.validate("ShapeResult", &result)?;
            validate_grant(
                &authority.authorize_shape(principal, input)?,
                &query,
                principal,
            )?
            .eq(&grant_digest)
            .then_some(())
            .ok_or(ShapeError::StaleContext)?;
            control.check()?;
            let mut source = source_ref(&probe, &bytes);
            // This is a derived diagnostic report of the validated probe, not
            // the raw native geometry observation supplied by the host.
            source["kind"] = json!("generated_report");
            return Ok(ShapeRead {
                result,
                evidence: ShapeReadEvidence {
                    cache_hit: false,
                    source_probe: probe.clone(),
                    current_probe: probe.clone(),
                    source,
                    observation_bytes: bytes.into(),
                },
            });
        }
        self.evict_expired();
        let cacheable = probe.dependency_scope == DependencyScope::Complete
            && probe.dependency_digest.is_some()
            && (query.shape_kind != "fluid" || probe.fluid_context_digest.is_some());
        let key=canonical_digest(&json!({"query":input,"principal":principal.principal_id,
            "permissionScope":principal.permission_scope_digest,"grant":grant_digest,"probe":probe.stable_digest()?}))
            .map_err(|_|ShapeError::InputLimit)?;
        let (source, cache_hit) = if cacheable {
            if let Some(cached) = self.cache.get(&key) {
                (cached.source.clone(), true)
            } else {
                (
                    self.port
                        .query_shape(principal, &grant, input, &probe, control)?,
                    false,
                )
            }
        } else {
            (
                self.port
                    .query_shape(principal, &grant, input, &probe, control)?,
                false,
            )
        };
        validate_source(&source, input, &grant, &query, &probe)?;
        if let Some(resource) = source.result.get("geometryRef") {
            self.port.authorize_geometry(principal, &grant, resource)?;
        }
        control.check()?;
        if validate_grant(
            &authority.authorize_shape(principal, input)?,
            &query,
            principal,
        )? != grant_digest
        {
            return Err(ShapeError::StaleContext);
        }
        control.check()?;
        if cacheable
            && !cache_hit
            && matches!(source.result["status"].as_str(), Some("known" | "absent"))
        {
            self.cache_source(key, source.clone(), principal, &query)?;
        }
        Ok(ShapeRead {
            result: source.result.clone(),
            evidence: ShapeReadEvidence {
                cache_hit,
                source_probe: source.probe,
                current_probe: probe,
                source: source.source,
                observation_bytes: source.observation_bytes,
            },
        })
    }
    pub fn invalidate(&mut self, event: ShapeInvalidation) {
        self.cache.retain(|_, cached| {
            let env = &cached.environment;
            let same = |game: &str, epoch: &str| {
                env["gameInstanceId"] == game && env["sessionEpoch"] == epoch
            };
            let remove = match &event {
                ShapeInvalidation::All => true,
                ShapeInvalidation::Principal(id) => cached.principal == *id,
                ShapeInvalidation::Environment {
                    game_instance_id,
                    session_epoch,
                } => same(game_instance_id, session_epoch),
                ShapeInvalidation::Entity {
                    game_instance_id,
                    session_epoch,
                    handle,
                } => {
                    same(game_instance_id, session_epoch) && cached.entity.as_ref() == Some(handle)
                }
                ShapeInvalidation::Region {
                    game_instance_id,
                    session_epoch,
                    world_id,
                    region,
                } => {
                    same(game_instance_id, session_epoch)
                        && env["worldId"] == *world_id
                        && cached
                            .dependencies
                            .iter()
                            .any(|old| intersects(old, region))
                }
            };
            !remove
        });
        self.cache_bytes = self.cache.values().map(|cached| cached.bytes).sum();
    }
    fn evict_expired(&mut self) {
        let ttl = self.limits.cache_ttl;
        self.cache
            .retain(|_, cached| cached.created.elapsed() < ttl);
        self.cache_bytes = self.cache.values().map(|cached| cached.bytes).sum();
    }
    fn cache_source(
        &mut self,
        key: Sha256Digest,
        source: ShapeSourceResult,
        principal: &ReadPrincipal,
        query: &Query,
    ) -> Result<(), ShapeError> {
        let result_bytes = encode_json(&source.result).map_err(|_| ShapeError::InputLimit)?;
        let probe_bytes = encode_json(&source.probe.wire()?).map_err(|_| ShapeError::InputLimit)?;
        let source_bytes = encode_json(&source.source).map_err(|_| ShapeError::InputLimit)?;
        let bytes = source
            .observation_bytes
            .len()
            .checked_add(result_bytes.len())
            .and_then(|bytes| bytes.checked_add(probe_bytes.len()))
            .and_then(|bytes| bytes.checked_add(source_bytes.len()))
            .ok_or(ShapeError::InputLimit)?;
        if bytes > self.limits.max_entry_bytes || bytes > self.limits.max_cache_bytes {
            return Ok(());
        }
        while self.cache.len() >= self.limits.max_cache_entries
            || self
                .cache_bytes
                .checked_add(bytes)
                .is_none_or(|total| total > self.limits.max_cache_bytes)
        {
            let oldest = self
                .cache
                .iter()
                .min_by_key(|(_, cached)| cached.created)
                .map(|(key, _)| key.clone())
                .ok_or(ShapeError::InputLimit)?;
            let removed = self.cache.remove(&oldest).unwrap();
            self.cache_bytes -= removed.bytes;
        }
        let cached = Cached {
            environment: source.probe.environment.clone(),
            dependencies: source.probe.dependencies.clone(),
            entity: query.entity_context_handle.clone(),
            source,
            bytes,
            created: Instant::now(),
            principal: principal.principal_id.as_str().to_owned(),
        };
        self.cache_bytes += bytes;
        self.cache.insert(key, cached);
        Ok(())
    }
}

fn intersects(a: &ShapeDependencyRegion, b: &ShapeDependencyRegion) -> bool {
    a.dimension == b.dimension
        && (0..3).all(|axis| {
            a.min[axis].get() < b.max_exclusive[axis].get()
                && b.min[axis].get() < a.max_exclusive[axis].get()
        })
}

fn validate_grant(
    grant: &ShapeGrant,
    query: &Query,
    principal: &ReadPrincipal,
) -> Result<Sha256Digest, ShapeError> {
    let validator = ContractValidator::shared()?;
    validator.validate("ExecutionContext", &grant.execution_context)?;
    validator.validate("DataSnapshot", &grant.snapshot.snapshot)?;
    validator.validate("HostHello", &grant.host_hello)?;
    verify_projected_digest("ExecutionContext", &grant.execution_context)
        .map_err(|_| ShapeError::StaleContext)?;
    let context = &grant.execution_context;
    let snapshot = &grant.snapshot.snapshot;
    let hello = &grant.host_hello;
    if context["principalRef"] != principal.principal_id.as_str() {
        return Err(ShapeError::PermissionRequired);
    }
    if context["contextId"] != query.context_id.as_str()
        || snapshot["snapshotId"] != query.snapshot_id
        || context["environment"]["kind"] != "game"
        || context["environment"] != snapshot["environment"]
        || hello["environment"] != context["environment"]
        || hello["hostProtocolVersion"] != "0.2.0"
        || context["dimension"] != query.dimension.as_str()
        || query.load_policy != "loaded_only"
    {
        return Err(ShapeError::StaleContext);
    }
    if snapshot["side"] != context["environment"]["side"] {
        return Err(ShapeError::SideMismatch);
    }
    if hello["gameVersion"] != snapshot["gameVersion"] {
        return Err(ShapeError::TargetDrift);
    }
    if grant.allowed_modes.is_empty() {
        return Err(ShapeError::PermissionRequired);
    }
    let allowed = context["scope"]["regions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|region| {
            region["contextId"] == query.context_id.as_str()
                && region["dimension"] == query.dimension.as_str()
                && region["worldId"] == context["environment"]["worldId"]
                && (0..3).all(|axis| {
                    region["min"][axis].as_f64().unwrap() <= f64::from(query.position[axis].get())
                        && region["maxExclusive"][axis].as_f64().unwrap()
                            > f64::from(query.position[axis].get())
                })
        });
    if !allowed {
        return Err(ShapeError::PermissionRequired);
    }
    let identity = serde_json::to_value(&grant.snapshot.identity)
        .map_err(|_| ShapeError::InvalidObservation)?;
    canonical_digest(
        &json!({"context":context,"snapshot":snapshot,"revision":grant.snapshot.revision,
        "snapshotIdentity":identity,"hostHello":hello,"allowedModes":grant.allowed_modes}),
    )
    .map_err(|_| ShapeError::InputLimit)
}
fn validate_probe(grant: &ShapeGrant, query: &Query, probe: &ShapeProbe) -> Result<(), ShapeError> {
    probe.validate()?;
    if probe.environment["side"] != grant.execution_context["environment"]["side"] {
        return Err(ShapeError::SideMismatch);
    }
    if probe.environment != grant.execution_context["environment"]
        || probe.context_digest.as_str()
            != grant.execution_context["contextDigest"].as_str().unwrap()
        || probe.entity_context_handle != query.entity_context_handle
    {
        return Err(ShapeError::StaleContext);
    }
    if !grant.allowed_modes.contains(&probe.mode) {
        return Err(ShapeError::PermissionRequired);
    }
    if probe.game_version != grant.snapshot.snapshot["gameVersion"].as_str().unwrap()
        || probe.host_build != grant.host_hello["hostBuild"].as_str().unwrap()
        || probe.registry_digest.as_str() != grant.host_hello["registryDigest"].as_str().unwrap()
        || probe.registry_generation != grant.snapshot.identity.registry_generation
    {
        return Err(ShapeError::TargetDrift);
    }
    if probe.dimension != query.dimension || probe.position != query.position {
        return Err(ShapeError::TargetDrift);
    }
    if probe.loaded
        && (probe.block_state.as_ref() != Some(&query.block_state)
            || probe.neighbor_context_digest.as_ref() != Some(&query.neighbor_context_digest)
            || query.entity_context_handle.is_some() && probe.entity_context_digest.is_none())
    {
        return Err(ShapeError::TargetDrift);
    }
    // A declared dependency footprint cannot authorize extra world reads.
    // Unknown mod dependencies require the host's guarded getter to check each
    // actual read; declared regions are checked here as an additional boundary.
    let scope = grant.execution_context["scope"]["regions"]
        .as_array()
        .unwrap();
    for dependency in &probe.dependencies {
        if dependency.dimension != query.dimension
            || !scope.iter().any(|region| {
                region["contextId"] == query.context_id.as_str()
                    && region["worldId"] == probe.environment["worldId"]
                    && region["dimension"] == dependency.dimension.as_str()
                    && (0..3).all(|axis| {
                        region["min"][axis].as_f64().unwrap()
                            <= f64::from(dependency.min[axis].get())
                            && region["maxExclusive"][axis].as_f64().unwrap()
                                >= f64::from(dependency.max_exclusive[axis].get())
                    })
            })
        {
            return Err(ShapeError::PermissionRequired);
        }
    }
    if probe.loaded
        && probe.dependency_scope == DependencyScope::Complete
        && !probe.dependencies.iter().any(|region| {
            (0..3).all(|axis| {
                region.min[axis].get() <= query.position[axis].get()
                    && region.max_exclusive[axis].get() > query.position[axis].get()
            })
        })
    {
        return Err(ShapeError::InvalidObservation);
    }
    Ok(())
}
fn target_verified(grant: &ShapeGrant, probe: &ShapeProbe) -> Result<bool, ShapeError> {
    let snapshot = &grant.snapshot.snapshot;
    let expected_mods = canonical_digest(
        &serde_json::to_value(&grant.snapshot.identity.mod_fingerprints)
            .map_err(|_| ShapeError::InvalidObservation)?,
    )
    .map_err(|_| ShapeError::InputLimit)?;
    let expected_mods_value = json!(expected_mods);
    let pairs = [
        (
            probe.target_fingerprint.as_ref().map(|d| json!(d)),
            snapshot.get("environmentFingerprint"),
        ),
        (
            probe.server_pack_stack.as_ref().map(|packs| json!(packs)),
            snapshot.get("serverPackStack"),
        ),
        (
            probe.client_pack_stack.as_ref().map(|packs| json!(packs)),
            snapshot.get("clientPackStack"),
        ),
        (
            probe
                .mod_fingerprint_digest
                .as_ref()
                .map(|digest| json!(digest)),
            Some(&expected_mods_value),
        ),
    ];
    let mut verified = true;
    for (actual, expected) in pairs {
        match actual {
            Some(actual) if Some(&actual) != expected => return Err(ShapeError::TargetDrift),
            None => verified = false,
            _ => {}
        }
    }
    if snapshot["artifactSha256"].is_null() {
        verified = false;
    } else if let Some(actual) = &probe.artifact_sha256 {
        if snapshot["artifactSha256"] != actual.as_str() {
            return Err(ShapeError::TargetDrift);
        }
    } else {
        verified = false;
    }
    if probe.locale != snapshot["locale"].as_str().unwrap() {
        return Err(ShapeError::TargetDrift);
    }
    Ok(verified)
}
fn validate_source(
    source: &ShapeSourceResult,
    input: &Value,
    grant: &ShapeGrant,
    query: &Query,
    expected: &ShapeProbe,
) -> Result<(), ShapeError> {
    ContractValidator::shared()?.validate("ShapeResult", &source.result)?;
    ContractValidator::shared()?.validate("SourceRef", &source.source)?;
    let observation = native_observation(&source.observation_bytes, &query.shape_kind)?;
    validate_probe(grant, query, &source.probe)?;
    if source.probe.stable_digest()? != expected.stable_digest()?
        || source.result["queryDigest"]
            != canonical_digest(input)
                .map_err(|_| ShapeError::InputLimit)?
                .as_str()
        || source.source["kind"] != "runtime_observation"
        || source.source["sha256"] != raw_digest(&source.observation_bytes).as_str()
        || source.source["verifiedAt"] != source.probe.observed_at
        || source.result["status"] != observation.status
        || source.result["observedFromTick"] != source.probe.observed_from_tick
        || source.result["observedToTick"] != source.probe.observed_to_tick
        || source.result["worldRevision"] != json!(source.probe.world_revision)
    {
        return Err(ShapeError::TargetDrift);
    }
    tick_window(
        source.result["observedFromTick"].as_str().unwrap(),
        source.result["observedToTick"].as_str().unwrap(),
    )?;
    if source.result["coverage"]["consistency"] == "provider_atomic"
        && source.probe.observed_from_tick != source.probe.observed_to_tick
    {
        return Err(ShapeError::InvalidObservation);
    }
    if source.result.get("shape").is_some() {
        return Err(ShapeError::InvalidObservation);
    }
    if observation.status != "known" && source.result["reason"] != json!(observation.reason) {
        return Err(ShapeError::InvalidObservation);
    }
    if let Some(resource) = source.result.get("geometryRef") {
        validate_resource(resource, &source.observation_bytes)?;
    }
    if matches!(source.result["status"].as_str(), Some("known" | "absent"))
        && (!source.probe.loaded
            || !source.probe.ready
            || query.shape_kind == "fluid" && source.probe.fluid_context_digest.is_none()
            || source.result["coverage"]["status"] != "complete"
            || !source.result["coverage"]["exclusions"]
                .as_array()
                .unwrap()
                .is_empty()
            || !source.result["coverage"]["includedKinds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|kind| {
                    kind.as_str() == Some(format!("mmmm:{}_shape", query.shape_kind).as_str())
                }))
    {
        return Err(ShapeError::InvalidObservation);
    }
    Ok(())
}

#[cfg(test)]
#[path = "shape_tests.rs"]
mod tests;

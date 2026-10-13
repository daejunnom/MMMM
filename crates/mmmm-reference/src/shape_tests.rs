//! Original examples do not cover host witness races, arbitrary voxel offsets,
//! cache ACL changes or invalidation. These minimal in-memory mutations cover
//! those boundaries; they are not actual game acceptance evidence.

use super::*;
use crate::SnapshotIdentity;
use mmmm_contracts::{PrincipalId, projected_digest};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

fn digest(c: char) -> Sha256Digest {
    Sha256Digest::new(c.to_string().repeat(64)).unwrap()
}
fn principal() -> ReadPrincipal {
    ReadPrincipal {
        principal_id: PrincipalId::new("principal-fixture").unwrap(),
        permission_scope_digest: digest('1'),
    }
}
fn query() -> Value {
    parse_json(include_bytes!("../../../examples/shape-query.json")).unwrap()
}
fn region(min: [i32; 3], max: [i32; 3]) -> ShapeDependencyRegion {
    serde_json::from_value(json!({"dimension":"minecraft:overworld","min":min,"maxExclusive":max}))
        .unwrap()
}
fn grant() -> ShapeGrant {
    let mut context =
        parse_json(include_bytes!("../../../examples/execution-context.json")).unwrap();
    context["scope"]["regions"] = json!([{"contextId":"context-fixture-01","worldId":"world-fixture-01",
        "dimension":"minecraft:overworld","min":[-16,0,-16],"maxExclusive":[16,128,16]}]);
    context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
    let mut snapshot = parse_json(include_bytes!("../../../examples/data-snapshot.json")).unwrap();
    snapshot["environment"] = context["environment"].clone();
    snapshot["side"] = json!("server");
    snapshot["artifactSha256"] = json!(digest('a'));
    snapshot["layers"] = json!(["environment_snapshot"]);
    let identity = SnapshotIdentity {
        registry_generation: "generation-1".into(),
        mod_fingerprints: BTreeMap::new(),
        query_context_digest: digest('2'),
        observation_window: None,
    };
    ShapeGrant {
        execution_context: context,
        snapshot: SnapshotPin {
            revision: canonical_digest(&snapshot).unwrap(),
            snapshot,
            identity,
        },
        host_hello: parse_json(include_bytes!("../../../examples/host-hello.json")).unwrap(),
        allowed_modes: BTreeSet::from([GameMode::Survival]),
    }
}
fn probe(grant: &ShapeGrant) -> ShapeProbe {
    let query = query();
    ShapeProbe::from_value(&json!({"protocolVersion":"0.2.0","contextDigest":grant.execution_context["contextDigest"],
        "environment":grant.execution_context["environment"],"dimension":query["dimension"],"position":query["position"],"gameVersion":"26.3","hostBuild":"fixture-only",
        "artifactSha256":grant.snapshot.snapshot["artifactSha256"],"targetFingerprint":grant.snapshot.snapshot["environmentFingerprint"],
        "registryDigest":grant.host_hello["registryDigest"],"registryGeneration":"generation-1",
        "serverPackStack":[],"clientPackStack":[],"modFingerprintDigest":canonical_digest(&json!({})).unwrap(),
        "locale":"ko_kr","mode":"survival","ready":true,"loaded":true,"blockState":query["blockState"],
        "neighborContextDigest":query["neighborContextDigest"],"entityContextHandle":null,"entityContextDigest":null,
        "fluidContextDigest":null,"permissionDigest":digest('3'),"observedFromTick":"10","observedToTick":"10",
        "observedAt":"2026-10-14T00:00:00Z","worldRevision":digest('4'),"dependencyScope":"complete",
        "dependencyDigest":digest('5'),"dependencies":[{"dimension":"minecraft:overworld","min":[-1,63,-1],"maxExclusive":[2,66,2]}]})).unwrap()
}
fn native(status: &str, kind: &str) -> Vec<u8> {
    encode_json(&json!({"format":NATIVE_VOXEL_FORMAT,"shapeKind":kind,"status":status,"space":"node_local","unit":"blocks",
        "exactness":if status=="known" {"exact"} else {"unknown"},"provenance":"observed",
        "boxes":if status=="known" { json!([[0.75,0.0,0.0,1.0,1.0,0.125],[0.0,0.5,0.0,0.25,0.75,1.0]]) } else {Value::Null},
        "reason":if status=="known" {Value::Null} else {json!("native_query_unavailable")}})).unwrap()
}
struct Authority {
    grant: RefCell<ShapeGrant>,
    calls: Cell<usize>,
    deny: Cell<bool>,
    change_after_first: Cell<bool>,
}
impl ShapeAuthority for Authority {
    fn authorize_shape(&self, _: &ReadPrincipal, _: &Value) -> Result<ShapeGrant, ShapeError> {
        self.calls.set(self.calls.get() + 1);
        if self.deny.get() {
            return Err(ShapeError::PermissionRequired);
        }
        let mut grant = self.grant.borrow().clone();
        if self.change_after_first.get() && self.calls.get() > 1 {
            grant.allowed_modes.insert(GameMode::Creative);
        }
        Ok(grant)
    }
}
struct HostState {
    probe: ShapeProbe,
    status: String,
    tick: u64,
    probes: usize,
    queries: usize,
    drift: bool,
    raw: Option<Vec<u8>>,
    requests: Vec<Value>,
    host_error: Option<String>,
}
struct Transport(Rc<RefCell<HostState>>);
impl HostShapeTransport for Transport {
    fn inspect_shape(
        &mut self,
        context: &Value,
        payload: &Value,
        control: &ShapeControl<'_>,
    ) -> Result<Value, ShapeError> {
        control.check()?;
        let mut state = self.0.borrow_mut();
        if let Some(code) = &state.host_error {
            return Err(ShapeError::Host { code: code.clone() });
        }
        assert_eq!(context["contextId"], payload["query"]["contextId"]);
        state.requests.push(payload.clone());
        state.tick += 1;
        let mut current = state.probe.clone();
        current.observed_from_tick = state.tick.to_string();
        current.observed_to_tick = state.tick.to_string();
        if payload["kind"] == "world.shape_probe" {
            state.probes += 1;
            return Ok(json!({"probe":current.wire()?}));
        }
        assert_eq!(payload["kind"], "world.shape_query");
        assert!(payload.get("expectedProbe").is_some());
        state.queries += 1;
        if state.drift {
            current.permission_digest = digest('6');
        }
        let bytes = state.raw.clone().unwrap_or_else(|| {
            native(
                &state.status,
                payload["query"]["shapeKind"].as_str().unwrap(),
            )
        });
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Ok(json!({"probe":current.wire()?,"observationBytesHex":hex}))
    }
}
#[derive(Default)]
struct GeometryState {
    retained: Vec<Vec<u8>>,
    acl: usize,
    deny: bool,
    bad_hash: bool,
}
struct Geometry(Rc<RefCell<GeometryState>>);
impl ShapeGeometryStore for Geometry {
    fn retain_geometry(
        &mut self,
        _: &ReadPrincipal,
        _: &Value,
        _: &Value,
        bytes: &[u8],
        media: &str,
    ) -> Result<Value, ShapeError> {
        let mut state = self.0.borrow_mut();
        state.retained.push(bytes.to_vec());
        Ok(
            json!({"resourceId":format!("geometry-{}",raw_digest(bytes)),"sha256":if state.bad_hash {digest('b')} else {raw_digest(bytes)},
            "mediaType":media,"sizeBytes":bytes.len()}),
        )
    }
    fn authorize_geometry(
        &mut self,
        _: &ReadPrincipal,
        _: &Value,
        _: &Value,
    ) -> Result<(), ShapeError> {
        let mut state = self.0.borrow_mut();
        state.acl += 1;
        if state.deny {
            Err(ShapeError::PermissionRequired)
        } else {
            Ok(())
        }
    }
}
type Service = ShapeService<PairedShapeSource<Transport, Geometry>>;
fn setup() -> (
    Service,
    Authority,
    Rc<RefCell<HostState>>,
    Rc<RefCell<GeometryState>>,
) {
    let grant = grant();
    let geometry = Rc::new(RefCell::new(GeometryState::default()));
    let host = Rc::new(RefCell::new(HostState {
        probe: probe(&grant),
        status: "known".into(),
        tick: 9,
        probes: 0,
        queries: 0,
        drift: false,
        raw: None,
        requests: vec![],
        host_error: None,
    }));
    let service = ShapeService::new(
        PairedShapeSource {
            transport: Transport(host.clone()),
            geometry: Geometry(geometry.clone()),
        },
        ShapeLimits::default(),
    )
    .unwrap();
    (
        service,
        Authority {
            grant: RefCell::new(grant),
            calls: Cell::new(0),
            deny: Cell::new(false),
            change_after_first: Cell::new(false),
        },
        host,
        geometry,
    )
}
fn read(
    service: &mut Service,
    authority: &Authority,
    input: &Value,
) -> Result<ShapeRead, ShapeError> {
    let cancel = AtomicBool::new(false);
    service.query(
        input,
        &principal(),
        authority,
        &ShapeControl {
            cancellation: &cancel,
            deadline: Instant::now() + Duration::from_secs(5),
            deadline_at: "2026-10-14T00:00:05Z",
        },
    )
}

#[test]
fn exact_raw_offsets_and_union_are_retained_without_centered_box_conversion() {
    let (mut service, authority, host, geometry) = setup();
    let result = read(&mut service, &authority, &query()).unwrap();
    assert_eq!(result.result["status"], "known");
    assert!(result.result.get("shape").is_none());
    let expected = native("known", "collision");
    assert_eq!(&*result.evidence.observation_bytes, expected.as_slice());
    assert_eq!(geometry.borrow().retained, vec![expected.clone()]);
    assert_eq!(
        result.result["geometryRef"]["sha256"],
        raw_digest(&expected).as_str()
    );
    assert_eq!(host.borrow().requests.len(), 2);
    assert_eq!(
        result.evidence.source["verifiedAt"],
        result.evidence.source_probe.observed_at
    );
}
#[test]
fn cache_reprobes_current_acl_and_preserves_geometry_observation_window() {
    let (mut service, authority, host, geometry) = setup();
    let first = read(&mut service, &authority, &query()).unwrap();
    let second = read(&mut service, &authority, &query()).unwrap();
    assert!(!first.evidence.cache_hit);
    assert!(second.evidence.cache_hit);
    assert_eq!(first.result, second.result);
    assert_eq!(second.result["observedFromTick"], "11");
    assert_eq!(second.evidence.current_probe.observed_from_tick, "12");
    assert_eq!(host.borrow().probes, 2);
    assert_eq!(host.borrow().queries, 1);
    assert_eq!(authority.calls.get(), 4);
    assert!(geometry.borrow().acl >= 3);
    geometry.borrow_mut().deny = true;
    assert_eq!(
        read(&mut service, &authority, &query()).unwrap_err().code(),
        "PERMISSION_REQUIRED"
    );
    assert_eq!(host.borrow().queries, 1);
    authority.deny.set(true);
    let probes = host.borrow().probes;
    assert_eq!(
        read(&mut service, &authority, &query()).unwrap_err().code(),
        "PERMISSION_REQUIRED"
    );
    assert_eq!(host.borrow().probes, probes);
}
#[test]
fn unknown_dependency_scope_disables_geometry_cache() {
    let (mut service, authority, host, _) = setup();
    host.borrow_mut().probe.dependency_scope = DependencyScope::Unknown;
    host.borrow_mut().probe.dependency_digest = None;
    assert!(
        !read(&mut service, &authority, &query())
            .unwrap()
            .evidence
            .cache_hit
    );
    assert!(
        !read(&mut service, &authority, &query())
            .unwrap()
            .evidence
            .cache_hit
    );
    assert_eq!(host.borrow().queries, 2);
    assert!(service.cache.is_empty());
}
#[test]
fn readiness_unloaded_and_unknown_target_are_unknown_without_native_queries() {
    for condition in 0..3 {
        let (mut service, authority, host, geometry) = setup();
        match condition {
            0 => host.borrow_mut().probe.ready = false,
            1 => {
                let mut h = host.borrow_mut();
                h.probe.loaded = false;
                h.probe.block_state = None;
                h.probe.neighbor_context_digest = None;
            }
            _ => host.borrow_mut().probe.server_pack_stack = None,
        }
        let observed = read(&mut service, &authority, &query()).unwrap();
        assert_eq!(observed.result["status"], "unknown");
        assert_eq!(observed.result["coverage"]["status"], "partial");
        assert!(observed.result.get("geometryRef").is_none());
        assert_eq!(observed.evidence.source["kind"], "generated_report");
        assert_eq!(host.borrow().queries, 0);
        assert!(geometry.borrow().retained.is_empty());
    }
}
#[test]
fn known_empty_shape_and_unsupported_shape_remain_distinct() {
    let (mut service, authority, host, geometry) = setup();
    let mut empty = parse_json(&native("known", "collision")).unwrap();
    empty["boxes"] = json!([]);
    host.borrow_mut().raw = Some(encode_json(&empty).unwrap());
    assert_eq!(
        read(&mut service, &authority, &query()).unwrap().result["status"],
        "known"
    );
    assert_eq!(geometry.borrow().retained.len(), 1);
    let (mut service, authority, host, geometry) = setup();
    host.borrow_mut().status = "unsupported".into();
    let observed = read(&mut service, &authority, &query()).unwrap();
    assert_eq!(observed.result["status"], "unsupported");
    assert_eq!(observed.result["coverage"]["status"], "partial");
    assert!(observed.result.get("geometryRef").is_none());
    assert!(geometry.borrow().retained.is_empty());
    let (mut service, authority, host, geometry) = setup();
    host.borrow_mut().status = "absent".into();
    let absent = read(&mut service, &authority, &query()).unwrap();
    assert_eq!(absent.result["status"], "absent");
    assert_eq!(absent.result["coverage"]["status"], "complete");
    assert_eq!(absent.result["coverage"]["exclusions"], json!([]));
    assert!(
        read(&mut service, &authority, &query())
            .unwrap()
            .evidence
            .cache_hit
    );
    assert!(geometry.borrow().retained.is_empty());
}
#[test]
fn probe_query_race_and_changed_authority_do_not_publish_cache_success() {
    let (mut service, authority, host, geometry) = setup();
    host.borrow_mut().drift = true;
    assert_eq!(
        read(&mut service, &authority, &query()).unwrap_err().code(),
        "TARGET_DRIFT"
    );
    assert!(service.cache.is_empty());
    assert!(geometry.borrow().retained.is_empty());
    let (mut service, authority, _, _) = setup();
    authority.change_after_first.set(true);
    assert_eq!(
        read(&mut service, &authority, &query()).unwrap_err().code(),
        "STALE_CONTEXT"
    );
    assert!(service.cache.is_empty());
}
#[test]
fn actual_dynamic_pins_cannot_be_replaced_with_query_claims() {
    for mutation in 0..9 {
        let (mut service, authority, host, geometry) = setup();
        let expected = match mutation {
            0 => {
                host.borrow_mut().probe.block_state =
                    Some(json!({"blockId":"minecraft:stone","properties":{"observed":"changed"}}));
                "TARGET_DRIFT"
            }
            1 => {
                host.borrow_mut().probe.neighbor_context_digest = Some(digest('7'));
                "TARGET_DRIFT"
            }
            2 => {
                host.borrow_mut().probe.mode = GameMode::Creative;
                "PERMISSION_REQUIRED"
            }
            3 => {
                host.borrow_mut().probe.registry_generation = "generation-2".into();
                "TARGET_DRIFT"
            }
            4 => {
                host.borrow_mut().probe.server_pack_stack = Some(vec![digest('8')]);
                "TARGET_DRIFT"
            }
            5 => {
                host.borrow_mut().probe.environment["sessionEpoch"] = json!("epoch-new");
                "STALE_CONTEXT"
            }
            6 => {
                host.borrow_mut().probe.environment["side"] = json!("client");
                "SIDE_MISMATCH"
            }
            7 => {
                host.borrow_mut().probe.artifact_sha256 = Some(digest('9'));
                "TARGET_DRIFT"
            }
            _ => {
                host.borrow_mut().probe.position =
                    serde_json::from_value(json!([1, 64, 0])).unwrap();
                "TARGET_DRIFT"
            }
        };
        assert_eq!(
            read(&mut service, &authority, &query()).unwrap_err().code(),
            expected
        );
        assert_eq!(host.borrow().queries, 0);
        assert!(geometry.borrow().retained.is_empty());
    }
}
#[test]
fn current_permission_and_world_revision_changes_never_hit_old_cache() {
    let (mut service, authority, host, _) = setup();
    read(&mut service, &authority, &query()).unwrap();
    host.borrow_mut().probe.permission_digest = digest('9');
    assert!(
        !read(&mut service, &authority, &query())
            .unwrap()
            .evidence
            .cache_hit
    );
    host.borrow_mut().probe.world_revision = Some(digest('8'));
    assert!(
        !read(&mut service, &authority, &query())
            .unwrap()
            .evidence
            .cache_hit
    );
    assert_eq!(host.borrow().queries, 3);
}
#[test]
fn entity_and_fluid_conditions_require_actual_scoped_observation() {
    let (mut service, authority, host, geometry) = setup();
    let mut input = query();
    input["entityContextHandle"] = json!("entity-fixture");
    assert_eq!(
        read(&mut service, &authority, &input).unwrap_err().code(),
        "STALE_CONTEXT"
    );
    host.borrow_mut().host_error = Some("UNSUPPORTED".into());
    assert_eq!(
        read(&mut service, &authority, &input).unwrap_err().code(),
        "UNSUPPORTED"
    );
    assert!(geometry.borrow().retained.is_empty());
    let (mut service, authority, host, _) = setup();
    let mut input = query();
    input["shapeKind"] = json!("fluid");
    host.borrow_mut().status = "unsupported".into();
    assert_eq!(
        read(&mut service, &authority, &input).unwrap().result["status"],
        "unsupported"
    );
    host.borrow_mut().status = "known".into();
    assert_eq!(
        read(&mut service, &authority, &input).unwrap_err().code(),
        "SCHEMA_UNSUPPORTED"
    );
    host.borrow_mut().probe.fluid_context_digest = Some(digest('a'));
    assert_eq!(
        read(&mut service, &authority, &input).unwrap().result["status"],
        "known"
    );
}
#[test]
fn malformed_native_observations_and_resource_digest_are_rejected() {
    let mut malformed = parse_json(&native("known", "collision")).unwrap();
    malformed["boxes"] = json!([[1.0, 0.0, 0.0, 0.0, 1.0, 1.0]]);
    assert!(decode_native_observation(&encode_json(&malformed).unwrap(), "collision").is_err());
    malformed["boxes"] = json!([]);
    malformed["reason"] = json!("unexpected");
    assert!(decode_native_observation(&encode_json(&malformed).unwrap(), "collision").is_err());
    let mut unknown = parse_json(&native("unknown", "collision")).unwrap();
    unknown["boxes"] = json!([]);
    assert!(decode_native_observation(&encode_json(&unknown).unwrap(), "collision").is_err());
    assert!(decode_native_observation(b"{\"format\":1,\"format\":2}", "collision").is_err());
    assert!(decode_native_observation(&vec![b' '; 256 * 1024 + 1], "collision").is_err());
    assert!(decode_native_observation(&native("known", "outline"), "collision").is_err());
    let (mut service, authority, _, geometry) = setup();
    geometry.borrow_mut().bad_hash = true;
    assert_eq!(
        read(&mut service, &authority, &query()).unwrap_err().code(),
        "SCHEMA_UNSUPPORTED"
    );
    assert!(service.cache.is_empty());
}
#[test]
fn invalidation_uses_full_dependency_footprint_and_epoch_scope() {
    let (mut service, authority, host, _) = setup();
    read(&mut service, &authority, &query()).unwrap();
    let event = |bounds| ShapeInvalidation::Region {
        game_instance_id: "game-fixture-01".into(),
        session_epoch: "epoch-fixture-01".into(),
        world_id: "world-fixture-01".into(),
        region: bounds,
    };
    service.invalidate(event(region([10, 64, 10], [11, 65, 11])));
    assert!(
        read(&mut service, &authority, &query())
            .unwrap()
            .evidence
            .cache_hit
    );
    service.invalidate(event(region([1, 64, 1], [2, 65, 2])));
    assert!(
        !read(&mut service, &authority, &query())
            .unwrap()
            .evidence
            .cache_hit
    );
    service.invalidate(ShapeInvalidation::Environment {
        game_instance_id: "game-fixture-01".into(),
        session_epoch: "different-epoch".into(),
    });
    assert!(
        read(&mut service, &authority, &query())
            .unwrap()
            .evidence
            .cache_hit
    );
    service.invalidate(ShapeInvalidation::Principal("principal-fixture".into()));
    assert!(
        !read(&mut service, &authority, &query())
            .unwrap()
            .evidence
            .cache_hit
    );
    service.invalidate(ShapeInvalidation::All);
    assert!(service.cache.is_empty());
    assert_eq!(service.cache_bytes, 0);
    assert_eq!(host.borrow().queries, 3);
}
#[test]
fn scope_and_integer_boundaries_fail_before_host_access() {
    let (mut service, authority, host, _) = setup();
    let mut input = query();
    input["position"] = json!([16, 64, 0]);
    assert_eq!(
        read(&mut service, &authority, &input).unwrap_err().code(),
        "PERMISSION_REQUIRED"
    );
    input["position"] = json!([2147483648_u64, 64, 0]);
    assert!(read(&mut service, &authority, &input).is_err());
    assert_eq!(host.borrow().probes, 0);
    input["position"] = json!([0.0, 64.0, 0.0]);
    assert_eq!(
        read(&mut service, &authority, &input).unwrap().result["status"],
        "known"
    );
    host.borrow_mut().probe.dependencies = vec![region([-17, 63, -1], [2, 66, 2])];
    assert_eq!(
        read(&mut service, &authority, &query()).unwrap_err().code(),
        "PERMISSION_REQUIRED"
    );
    host.borrow_mut().probe.dependencies = vec![region([4, 63, 4], [6, 66, 6])];
    assert_eq!(
        read(&mut service, &authority, &query()).unwrap_err().code(),
        "SCHEMA_UNSUPPORTED"
    );
}
#[test]
fn reversed_tick_windows_and_ttl_expiry_do_not_reuse_invalid_results() {
    assert!(tick_window("12", "11").is_err());
    assert!(tick_window("01", "2").is_err());
    let (mut service, authority, host, _) = setup();
    read(&mut service, &authority, &query()).unwrap();
    for cached in service.cache.values_mut() {
        cached.created = Instant::now() - Duration::from_secs(31);
    }
    assert!(
        !read(&mut service, &authority, &query())
            .unwrap()
            .evidence
            .cache_hit
    );
    assert_eq!(host.borrow().queries, 2);
    let mut probe = host.borrow().probe.clone();
    probe.observed_from_tick = "12".into();
    probe.observed_to_tick = "11".into();
    assert!(ShapeProbe::from_value(&probe.wire().unwrap()).is_err());
}
#[test]
fn cancellation_and_deadline_stop_before_authority_or_host_queries() {
    let (mut service, authority, host, _) = setup();
    let cancelled = AtomicBool::new(true);
    let control = ShapeControl {
        cancellation: &cancelled,
        deadline: Instant::now() + Duration::from_secs(5),
        deadline_at: "2026-10-14T00:00:05Z",
    };
    assert_eq!(
        service
            .query(&query(), &principal(), &authority, &control)
            .unwrap_err()
            .code(),
        "CANCELLED"
    );
    let active = AtomicBool::new(false);
    let expired = ShapeControl {
        cancellation: &active,
        deadline: Instant::now() - Duration::from_secs(1),
        deadline_at: "2026-10-14T00:00:05Z",
    };
    assert_eq!(
        service
            .query(&query(), &principal(), &authority, &expired)
            .unwrap_err()
            .code(),
        "DEADLINE_EXCEEDED"
    );
    assert_eq!(authority.calls.get(), 0);
    assert_eq!(host.borrow().probes, 0);
}

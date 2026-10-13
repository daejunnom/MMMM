//! FN22 converts approved actual bytes into immutable catalog input. Native
//! registry reports and local assets are decoded in Rust; source I/O, rights
//! attestation and durable evidence publication remain authenticated ports.

use crate::{
    CaptureBudget, CaptureControl, CaptureResult, CaptureSourceAccess, CaptureSourceEvidence,
    CatalogError, IndexedRecord, MissingRecordClaim, ObservationWindow, ReadPrincipal, SearchTerms,
    SnapshotIdentity, SnapshotInput, SnapshotSource,
};
use mmmm_contracts::{
    ContextId, ContractValidator, ResourceLocation, Sha256Digest, SnapshotId, SourceId,
    canonical_digest, encode_json, parse_json, raw_digest, verify_projected_digest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const NATIVE_REGISTRY_FORMAT: &str = "mmmm.native.registry/1";
pub const NATIVE_REGISTRY_MEDIA_TYPE: &str = "application/vnd.mmmm.native-registry+json";
pub const MAX_NATIVE_REGISTRY_BYTES: usize = 256 * 1024;
pub const CAPTURE_ENVIRONMENT_RECIPE: &str = "mmmm.capture-environment/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogLayer {
    VersionReference,
    LocalArtifact,
    EnvironmentSnapshot,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatalogSourceRole {
    GameArtifact,
    ServerPack,
    ClientPack,
    Mod(ResourceLocation),
    CatalogData,
}

/// Bound to an approved source descriptor, never selected from a user path.
#[derive(Clone, Debug)]
pub enum CatalogSourceCodec {
    FingerprintOnly {
        media_type: String,
    },
    NativeRegistry,
    JsonAsset {
        kind: ResourceLocation,
        resource_id: ResourceLocation,
        value_type: String,
        unit: String,
    },
    BinaryAsset {
        kind: ResourceLocation,
        resource_id: ResourceLocation,
        media_type: String,
    },
}
#[derive(Clone, Debug)]
pub struct ApprovedCatalogSource {
    pub source: Value,
    pub layer: CatalogLayer,
    pub role: CatalogSourceRole,
    /// Current authority's rights/descriptor revision, not caller rights text.
    pub rights_witness: Sha256Digest,
    pub codec: CatalogSourceCodec,
}
#[derive(Clone, Debug)]
pub struct CaptureGrant {
    pub execution_context: Value,
    /// Newly allocated by the unique Coordinator/store for each capture.
    pub snapshot_id: SnapshotId,
    pub game_version: Option<String>,
    pub locale: Option<String>,
    pub created_at: String,
    pub artifact_source: Option<SourceId>,
    /// None is unknown; Some([]) is an attested empty ordered stack.
    pub server_pack_sources: Option<Vec<SourceId>>,
    pub client_pack_sources: Option<Vec<SourceId>>,
    pub mod_sources: Option<BTreeMap<ResourceLocation, SourceId>>,
    /// Live captures use the actual native generation; fixed references may
    /// use their source-attested immutable extraction generation.
    pub registry_generation: Option<String>,
    pub sources: Vec<ApprovedCatalogSource>,
}
pub struct CapturedSourceBytes {
    pub bytes: Vec<u8>,
    pub verified_at: String,
    pub rights_witness: Sha256Digest,
}
pub trait CatalogCaptureBackend {
    /// Resolve source IDs to approved local roots/descriptors or paired host
    /// bindings. Check current principal, context ownership, source rights and
    /// actual selected pack order. No request path or hash installs a binding.
    fn resolve_capture(
        &mut self,
        principal: &ReadPrincipal,
        request: &Value,
        control: &CaptureControl<'_>,
        budget: &CaptureBudget,
    ) -> Result<CaptureGrant, CatalogError>;
    /// Recheck grant/epoch/registry/pack selection and current rights at return.
    /// Interrupted historical observations require retained-scope/current-rights
    /// authorization without new source or native reads.
    fn revalidate_capture(
        &mut self,
        principal: &ReadPrincipal,
        request: &Value,
        grant: &CaptureGrant,
        observed: Option<&RegistryCaptureWitness>,
        interrupted: bool,
        control: &CaptureControl<'_>,
    ) -> Result<(), CatalogError>;
    /// Apply max_bytes before allocating/reading; no implicit runtime mutation.
    /// Archive members must be resolved under their approved archive descriptor.
    fn read_approved_source(
        &mut self,
        principal: &ReadPrincipal,
        grant: &CaptureGrant,
        source: &ApprovedCatalogSource,
        max_bytes: usize,
        control: &CaptureControl<'_>,
    ) -> Result<CapturedSourceBytes, CatalogError>;
    /// Publish raw bytes to durable CAS and pin source/rights/owner metadata
    /// before returning ResourceRef. Product evidence is outside build-cache GC.
    fn retain_source_evidence(
        &mut self,
        principal: &ReadPrincipal,
        grant: &CaptureGrant,
        source: &Value,
        bytes: &[u8],
        media_type: &str,
    ) -> Result<Value, CatalogError>;
}
pub trait HostRegistryTransport {
    /// Exact 0.2.0 HostRequest.inspect {kind:"native_registry"}, installed
    /// principal-bound context, finite deadline and bounded response bytes.
    fn inspect_registry(
        &mut self,
        context: &Value,
        control: &CaptureControl<'_>,
        max_raw_bytes: usize,
    ) -> Result<Value, CatalogError>;
}
/// Offline composition explicitly has no runtime registry source.
pub struct NoRegistryHost;
impl HostRegistryTransport for NoRegistryHost {
    fn inspect_registry(
        &mut self,
        _: &Value,
        _: &CaptureControl<'_>,
        _: usize,
    ) -> Result<Value, CatalogError> {
        Err(CatalogError::SourceUnavailable(
            "No paired registry host is installed".into(),
        ))
    }
}
pub struct VerifiedSnapshotSource<T, B> {
    pub transport: T,
    pub backend: B,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistryCaptureWitness {
    pub context_digest: Sha256Digest,
    pub environment: Value,
    pub registry_digest: Sha256Digest,
    pub registry_generation: String,
    pub observed_from_tick: String,
    pub observed_to_tick: String,
    pub observed_at: String,
    pub game_version: String,
    pub locale: String,
}
struct RegistryRead {
    bytes: Vec<u8>,
    witness: RegistryCaptureWitness,
}
fn registry_response(payload: &Value, max_bytes: usize) -> Result<RegistryRead, CatalogError> {
    encode_json(payload).map_err(CatalogError::json)?;
    let object = payload
        .as_object()
        .ok_or_else(|| invalid("Registry response must be an object"))?;
    if object.len() != 10 {
        return Err(invalid(
            "Registry response fields differ from its inspection contract",
        ));
    }
    let encoded = object
        .get("observationBytesHex")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Registry response omitted raw bytes"))?;
    if encoded.len() > max_bytes.saturating_mul(2) || encoded.len() % 2 != 0 {
        return Err(CatalogError::InputLimit);
    }
    fn digit(byte: u8) -> Result<u8, CatalogError> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(invalid("Registry bytes must use lowercase hexadecimal")),
        }
    }
    let bytes = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|p| Ok(digit(p[0])? * 16 + digit(p[1])?))
        .collect::<Result<Vec<_>, CatalogError>>()?;
    let mut metadata = payload.clone();
    metadata
        .as_object_mut()
        .unwrap()
        .remove("observationBytesHex");
    let witness: RegistryCaptureWitness =
        serde_json::from_value(metadata).map_err(CatalogError::codec)?;
    ContractValidator::shared()?.validate("EnvironmentRef", &witness.environment)?;
    if witness.environment["kind"] != "game"
        || witness.registry_generation.is_empty()
        || witness.registry_generation.len() > 256
        || witness.game_version.is_empty()
        || witness.game_version.len() > 256
        || witness.locale.is_empty()
        || witness.locale.len() > 256
    {
        return Err(invalid(
            "Registry witness is not a bounded game observation",
        ));
    }
    validate_window(&witness.observed_from_tick, &witness.observed_to_tick)?;
    let source = json!({"sourceId":"registry-witness","kind":"runtime_observation","locator":"mmmm-host://registry/witness","sha256":null,"rights":"user_local_only","verifiedAt":witness.observed_at});
    ContractValidator::shared()?.validate("SourceRef", &source)?;
    let value = parse_json(&bytes).map_err(CatalogError::json)?;
    if canonical_digest(&value).map_err(CatalogError::digest)? != witness.registry_digest {
        return Err(unavailable(
            "Native registry digest differs from actual report bytes",
        ));
    }
    Ok(RegistryRead { bytes, witness })
}
fn validate_window(first: &str, last: &str) -> Result<(), CatalogError> {
    let valid = |s: &str| {
        !s.is_empty()
            && s.len() <= 128
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s == "0" || !s.starts_with('0'))
    };
    if !valid(first) || !valid(last) || (first.len(), first) > (last.len(), last) {
        return Err(invalid("Registry observation has an invalid tick window"));
    }
    Ok(())
}
fn invalid(text: &str) -> CatalogError {
    CatalogError::SchemaUnsupported(text.into())
}
fn unavailable(text: &str) -> CatalogError {
    CatalogError::SourceUnavailable(text.into())
}
fn check(control: &CaptureControl<'_>) -> Result<(), CatalogError> {
    if control.should_stop() {
        Err(CatalogError::Cancelled)
    } else {
        Ok(())
    }
}
fn source_id(source: &Value) -> Result<SourceId, CatalogError> {
    SourceId::new(
        source["sourceId"]
            .as_str()
            .ok_or_else(|| invalid("Source ID is missing"))?,
    )
    .map_err(CatalogError::id)
}
fn media(codec: &CatalogSourceCodec) -> &str {
    match codec {
        CatalogSourceCodec::NativeRegistry => NATIVE_REGISTRY_MEDIA_TYPE,
        CatalogSourceCodec::JsonAsset { .. } => "application/json",
        CatalogSourceCodec::FingerprintOnly { media_type }
        | CatalogSourceCodec::BinaryAsset { media_type, .. } => media_type,
    }
}
fn validate_resource(resource: &Value, bytes: &[u8], media_type: &str) -> Result<(), CatalogError> {
    ContractValidator::shared()?.validate("ResourceRef", resource)?;
    if resource["sha256"] != raw_digest(bytes).as_str()
        || resource["sizeBytes"].as_f64() != Some(bytes.len() as f64)
        || resource["mediaType"] != media_type
    {
        return Err(unavailable(
            "Retained source resource differs from acquired raw bytes",
        ));
    }
    Ok(())
}

/// Internal environment fingerprint over actual source facts. Query scope is
/// separately bound in SnapshotIdentity; it is not an environment fact.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapturedEnvironmentIdentity {
    pub environment: Value,
    pub game_version: String,
    pub artifact_sha256: Option<Sha256Digest>,
    pub server_pack_stack: Vec<Sha256Digest>,
    pub client_pack_stack: Vec<Sha256Digest>,
    pub mod_fingerprints: BTreeMap<ResourceLocation, Sha256Digest>,
    pub registry_generation: String,
    pub registry_digest: Option<Sha256Digest>,
    pub locale: String,
}
pub fn captured_environment_fingerprint(
    identity: &CapturedEnvironmentIdentity,
) -> Result<Sha256Digest, CatalogError> {
    canonical_digest(&json!({"recipe":CAPTURE_ENVIRONMENT_RECIPE,"identity":identity}))
        .map_err(CatalogError::digest)
}
struct Acquired {
    source: Value,
    bytes: Vec<u8>,
    resource: Value,
    codec: CatalogSourceCodec,
    layer: CatalogLayer,
}

impl<T: HostRegistryTransport, B: CatalogCaptureBackend> SnapshotSource
    for VerifiedSnapshotSource<T, B>
{
    fn capture(
        &mut self,
        request: &Value,
        control: &CaptureControl<'_>,
        budget: &CaptureBudget,
        access: &CaptureSourceAccess<'_>,
    ) -> Result<CaptureResult, CatalogError> {
        check(control)?;
        encode_json(request).map_err(CatalogError::json)?;
        ContractValidator::shared()?.validate("SnapshotRequest", request)?;
        let principal = access.principal();
        let grant = self
            .backend
            .resolve_capture(principal, request, control, budget)?;
        validate_grant(&grant, request, principal, budget)?;
        let mut acquired = BTreeMap::new();
        let mut total_bytes = 0usize;
        let mut native = None;
        let mut interrupted = false;
        let mut ordered = grant.sources.iter().collect::<Vec<_>>();
        // Required fingerprints precede optional assets. Pack priority remains
        // the separately attested array order, never this I/O schedule.
        ordered.sort_by_key(|source| {
            if matches!(source.codec, CatalogSourceCodec::NativeRegistry) {
                0
            } else if matches!(source.role, CatalogSourceRole::CatalogData) {
                2
            } else {
                1
            }
        });
        for approved in ordered {
            if control.should_stop() {
                interrupted = true;
                break;
            }
            access.authorize_before_read(&approved.source)?;
            let remaining = budget
                .max_source_bytes
                .checked_sub(total_bytes)
                .ok_or(CatalogError::InputLimit)?;
            let (read, witness) = if matches!(approved.codec, CatalogSourceCodec::NativeRegistry) {
                if native.is_some() {
                    return Err(invalid("Capture has multiple native registry observations"));
                }
                let payload = match self.transport.inspect_registry(
                    &grant.execution_context,
                    control,
                    remaining.min(MAX_NATIVE_REGISTRY_BYTES),
                ) {
                    Ok(value) => value,
                    Err(CatalogError::Cancelled) => {
                        interrupted = true;
                        break;
                    }
                    Err(error) => return Err(error),
                };
                let read = registry_response(&payload, remaining.min(MAX_NATIVE_REGISTRY_BYTES))?;
                if read.witness.environment != grant.execution_context["environment"]
                    || read.witness.context_digest.as_str()
                        != grant.execution_context["contextDigest"].as_str().unwrap()
                {
                    return Err(unavailable(
                        "Native registry witness differs from installed context",
                    ));
                }
                (
                    CapturedSourceBytes {
                        bytes: read.bytes,
                        verified_at: read.witness.observed_at.clone(),
                        rights_witness: approved.rights_witness.clone(),
                    },
                    Some(read.witness),
                )
            } else {
                (
                    match self
                        .backend
                        .read_approved_source(principal, &grant, approved, remaining, control)
                    {
                        Ok(value) => value,
                        Err(CatalogError::Cancelled) => {
                            interrupted = true;
                            break;
                        }
                        Err(error) => return Err(error),
                    },
                    None,
                )
            };
            if read.bytes.len() > remaining {
                return Err(CatalogError::InputLimit);
            }
            if read.rights_witness != approved.rights_witness {
                return Err(CatalogError::PermissionRequired);
            }
            total_bytes = total_bytes
                .checked_add(read.bytes.len())
                .ok_or(CatalogError::InputLimit)?;
            let mut source = approved.source.clone();
            source["sha256"] = json!(raw_digest(&read.bytes));
            source["verifiedAt"] = json!(read.verified_at);
            ContractValidator::shared()?.validate("SourceRef", &source)?;
            if !approved.source["sha256"].is_null() && approved.source["sha256"] != source["sha256"]
            {
                return Err(unavailable(
                    "Approved source fingerprint changed before capture",
                ));
            }
            let resource = self.backend.retain_source_evidence(
                principal,
                &grant,
                &source,
                &read.bytes,
                media(&approved.codec),
            )?;
            validate_resource(&resource, &read.bytes, media(&approved.codec))?;
            if let Some(witness) = witness {
                native = Some(witness);
            }
            acquired.insert(
                source_id(&source)?,
                Acquired {
                    source,
                    bytes: read.bytes,
                    resource,
                    codec: approved.codec.clone(),
                    layer: approved.layer,
                },
            );
        }
        interrupted |= control.should_stop();
        if interrupted
            && (acquired.is_empty()
                || !acquired.values().any(|source| {
                    serde_json::to_value(source.layer).ok().as_ref() == Some(&request["kind"])
                }))
        {
            return Err(CatalogError::Cancelled);
        }
        let identity = match environment_identity(&grant, &acquired, native.as_ref()) {
            Ok(identity) => identity,
            Err(_) if interrupted => return Err(CatalogError::Cancelled),
            Err(error) => return Err(error),
        };
        let fingerprint = captured_environment_fingerprint(&identity)?;
        let context =
            ContextId::new(request["contextId"].as_str().unwrap()).map_err(CatalogError::id)?;
        let scope_digest =
            Sha256Digest::new(grant.execution_context["contextDigest"].as_str().unwrap())
                .map_err(CatalogError::id)?;
        let mut records = vec![];
        let mut record_bytes = 0usize;
        let mut missing = vec![];
        let mut included = BTreeSet::new();
        let mut exclusions = BTreeSet::new();
        for entry in acquired.values() {
            interrupted |= control.should_stop();
            match &entry.codec {
                CatalogSourceCodec::NativeRegistry => {
                    let decoded = decode_registry(&entry.bytes)?;
                    let consistency = if native.as_ref().unwrap().observed_from_tick
                        == native.as_ref().unwrap().observed_to_tick
                    {
                        "per_item_observed"
                    } else {
                        "bounded_window"
                    };
                    for (kind, resource_id, value, value_type) in decoded {
                        push_record(
                            &mut records,
                            &mut record_bytes,
                            budget,
                            &grant.snapshot_id,
                            &context,
                            &scope_digest,
                            entry,
                            &kind,
                            &resource_id,
                            &value,
                            &value_type,
                            "unitless",
                            "observed",
                            consistency,
                        )?;
                        included.insert(kind);
                    }
                    for (kind, value_type) in [
                        ("minecraft:block", "block_registry_entry"),
                        ("minecraft:item", "item_registry_id"),
                        ("minecraft:entity_type", "entity_registry_id"),
                    ] {
                        missing.push(MissingRecordClaim {
                            context_id: context.clone(),
                            kind: ResourceLocation::new(kind).map_err(CatalogError::id)?,
                            scope_digest: scope_digest.clone(),
                            status: "absent".into(),
                            value_type: value_type.into(),
                            unit: "unitless".into(),
                            sources: vec![entry.source.clone()],
                            provenance: "observed".into(),
                            coverage: coverage("complete", &[kind], &[], consistency),
                            reason: "ID is absent from this complete native registry enumeration"
                                .into(),
                        });
                        included.insert(ResourceLocation::new(kind).map_err(CatalogError::id)?);
                    }
                    exclusions.insert("Native registry observation does not cover NBT schemas, commands, biomes, sounds, tags, components, assets, physics or world shapes".to_string());
                }
                CatalogSourceCodec::JsonAsset {
                    kind,
                    resource_id,
                    value_type,
                    unit,
                } => {
                    if interrupted {
                        exclusions.insert(
                            "Asset decoding was interrupted; raw evidence remains retained".into(),
                        );
                        continue;
                    }
                    let value = parse_json(&entry.bytes).map_err(CatalogError::json)?;
                    push_record(
                        &mut records,
                        &mut record_bytes,
                        budget,
                        &grant.snapshot_id,
                        &context,
                        &scope_digest,
                        entry,
                        kind,
                        resource_id,
                        &value,
                        value_type,
                        unit,
                        if entry.layer == CatalogLayer::VersionReference {
                            "documented"
                        } else {
                            "extracted"
                        },
                        "immutable",
                    )?;
                    included.insert(kind.clone());
                }
                CatalogSourceCodec::BinaryAsset {
                    kind, resource_id, ..
                } => {
                    if interrupted {
                        exclusions.insert("Asset record construction was interrupted; raw evidence remains retained".into());
                        continue;
                    }
                    push_record(
                        &mut records,
                        &mut record_bytes,
                        budget,
                        &grant.snapshot_id,
                        &context,
                        &scope_digest,
                        entry,
                        kind,
                        resource_id,
                        &entry.resource,
                        "resource_reference",
                        "bytes",
                        if entry.layer == CatalogLayer::VersionReference {
                            "documented"
                        } else {
                            "extracted"
                        },
                        "immutable",
                    )?;
                    included.insert(kind.clone());
                }
                CatalogSourceCodec::FingerprintOnly { .. } => {}
            }
        }
        if native.is_none() {
            exclusions.insert("Capture covers only explicitly approved assets; registry absence and effective pack merge are unverified".into());
        }
        if interrupted {
            exclusions.insert("Capture was interrupted; unacquired sources and final live target revalidation are excluded".into());
        }
        let included_strings = included
            .iter()
            .map(ResourceLocation::as_str)
            .collect::<Vec<_>>();
        let exclusions_strings = exclusions.iter().map(String::as_str).collect::<Vec<_>>();
        let consistency = if let Some(witness) = &native {
            if witness.observed_from_tick == witness.observed_to_tick {
                "per_item_observed"
            } else {
                "bounded_window"
            }
        } else {
            "immutable"
        };
        let layers = acquired.values().map(|s| s.layer).collect::<BTreeSet<_>>();
        let snapshot = json!({"contractVersion":"0.2.0","snapshotId":grant.snapshot_id,"gameVersion":identity.game_version,
            "environment":identity.environment,"environmentFingerprint":fingerprint,"artifactSha256":identity.artifact_sha256,
            "side":grant.execution_context["environment"]["side"],"layers":layers,"serverPackStack":identity.server_pack_stack,
            "clientPackStack":identity.client_pack_stack,"locale":identity.locale,"coverage":coverage("partial",&included_strings,&exclusions_strings,consistency),
            "sources":acquired.values().map(|e|e.source.clone()).collect::<Vec<_>>(),"createdAt":grant.created_at});
        ContractValidator::shared()?.validate("DataSnapshot", &snapshot)?;
        if encode_json(&snapshot)
            .map_err(CatalogError::json)?
            .len()
            .checked_add(record_bytes)
            .is_none_or(|bytes| bytes > budget.max_snapshot_bytes)
        {
            return Err(CatalogError::InputLimit);
        }
        self.backend.revalidate_capture(
            principal,
            request,
            &grant,
            native.as_ref(),
            interrupted,
            control,
        )?;
        if !interrupted {
            check(control)?;
        }
        let observation_window = native.as_ref().map(|w| ObservationWindow {
            first_tick: w.observed_from_tick.clone(),
            last_tick: w.observed_to_tick.clone(),
        });
        let sources = acquired
            .into_values()
            .map(|entry| CaptureSourceEvidence {
                source: entry.source,
                observed_bytes: entry.bytes,
            })
            .collect();
        Ok(CaptureResult {
            snapshot: SnapshotInput {
                snapshot,
                identity: SnapshotIdentity {
                    registry_generation: identity.registry_generation,
                    mod_fingerprints: identity.mod_fingerprints,
                    query_context_digest: scope_digest,
                    observation_window,
                },
                records,
                missing_records: missing,
            },
            sources,
            interrupted,
        })
    }
}

fn validate_grant(
    grant: &CaptureGrant,
    request: &Value,
    principal: &ReadPrincipal,
    budget: &CaptureBudget,
) -> Result<(), CatalogError> {
    let validator = ContractValidator::shared()?;
    validator.validate("ExecutionContext", &grant.execution_context)?;
    verify_projected_digest("ExecutionContext", &grant.execution_context)
        .map_err(|_| unavailable("Capture context digest is stale"))?;
    if grant.execution_context["principalRef"] != principal.principal_id.as_str() {
        return Err(CatalogError::PermissionRequired);
    }
    if grant.execution_context["contextId"] != request["contextId"]
        || grant.execution_context["environment"] != request["environment"]
    {
        return Err(unavailable(
            "Capture request differs from installed context",
        ));
    }
    if grant.sources.is_empty()
        || grant.sources.len() > budget.max_sources
        || grant
            .mod_sources
            .as_ref()
            .is_some_and(|mods| mods.len() > budget.max_records)
        || grant
            .server_pack_sources
            .as_ref()
            .is_some_and(|packs| packs.len() > budget.max_sources)
        || grant
            .client_pack_sources
            .as_ref()
            .is_some_and(|packs| packs.len() > budget.max_sources)
    {
        return Err(CatalogError::InputLimit);
    }
    let mut ids = BTreeSet::new();
    let mut metadata_bytes = 0usize;
    for source in &grant.sources {
        validator.validate("SourceRef", &source.source)?;
        metadata_bytes = metadata_bytes
            .checked_add(
                encode_json(&source.source)
                    .map_err(CatalogError::json)?
                    .len(),
            )
            .ok_or(CatalogError::InputLimit)?;
        if metadata_bytes > budget.max_snapshot_bytes {
            return Err(CatalogError::InputLimit);
        }
        if encode_json(&source.source)
            .map_err(CatalogError::json)?
            .len()
            > 16 * 1024
            || source.source["locator"].as_str().unwrap().len() > 4096
        {
            return Err(CatalogError::InputLimit);
        }
        if !ids.insert(source_id(&source.source)?) {
            return Err(invalid("Approved capture source ID is duplicated"));
        }
        if media(&source.codec).is_empty() || media(&source.codec).len() > 256 {
            return Err(invalid("Source media type is invalid"));
        }
        if let CatalogSourceCodec::JsonAsset {
            value_type, unit, ..
        } = &source.codec
            && (value_type.is_empty()
                || value_type.len() > 256
                || unit.is_empty()
                || unit.len() > 256)
        {
            return Err(invalid("Asset value type or unit is invalid"));
        }
        if matches!(source.codec, CatalogSourceCodec::NativeRegistry)
            && (source.source["kind"] != "runtime_observation"
                || request["kind"] != "environment_snapshot"
                || source.layer != CatalogLayer::EnvironmentSnapshot)
        {
            return Err(invalid(
                "Native registry source belongs to environment_snapshot only",
            ));
        }
        if matches!(
            source.codec,
            CatalogSourceCodec::JsonAsset { .. } | CatalogSourceCodec::BinaryAsset { .. }
        ) && source.layer == CatalogLayer::EnvironmentSnapshot
        {
            return Err(invalid(
                "Runtime facts require a closed native observation decoder",
            ));
        }
        if !matches!(source.codec, CatalogSourceCodec::FingerprintOnly { .. })
            && source.role != CatalogSourceRole::CatalogData
        {
            return Err(invalid(
                "Decoded catalog data cannot masquerade as an artifact, pack or mod fingerprint source",
            ));
        }
    }
    if !grant
        .sources
        .iter()
        .any(|source| serde_json::to_value(source.layer).ok().as_ref() == Some(&request["kind"]))
    {
        return Err(invalid("Approved sources omit requested data layer"));
    }
    for requested in request["sources"].as_array().unwrap() {
        let id = source_id(requested)?;
        let actual = grant
            .sources
            .iter()
            .find(|s| source_id(&s.source).ok().as_ref() == Some(&id))
            .ok_or_else(|| {
                unavailable("Requested source is not installed in the approved capture binding")
            })?;
        for field in ["kind", "locator", "rights"] {
            if requested[field] != actual.source[field] {
                return Err(unavailable(
                    "Caller source claims differ from approved source authority",
                ));
            }
        }
        if !requested["sha256"].is_null()
            && !actual.source["sha256"].is_null()
            && requested["sha256"] != actual.source["sha256"]
        {
            return Err(unavailable(
                "Caller source fingerprint differs from approved source authority",
            ));
        }
    }
    let approved = grant
        .sources
        .iter()
        .map(|s| Ok((source_id(&s.source)?, s)))
        .collect::<Result<BTreeMap<_, _>, CatalogError>>()?;
    let require_role = |id: &SourceId, role: &CatalogSourceRole| -> Result<(), CatalogError> {
        let source = approved
            .get(id)
            .ok_or_else(|| unavailable("Identity source is not in the approved capture binding"))?;
        if &source.role != role
            || !matches!(source.codec, CatalogSourceCodec::FingerprintOnly { .. })
        {
            return Err(invalid(
                "Identity source role/codec does not match its artifact, pack or mod fact",
            ));
        }
        Ok(())
    };
    if let Some(id) = &grant.artifact_source {
        require_role(id, &CatalogSourceRole::GameArtifact)?;
    }
    if let Some(packs) = &grant.server_pack_sources {
        for id in packs {
            require_role(id, &CatalogSourceRole::ServerPack)?;
        }
    }
    if let Some(packs) = &grant.client_pack_sources {
        for id in packs {
            require_role(id, &CatalogSourceRole::ClientPack)?;
        }
    }
    if let Some(mods) = &grant.mod_sources {
        for (id, source) in mods {
            require_role(source, &CatalogSourceRole::Mod(id.clone()))?;
        }
    }
    Ok(())
}
fn environment_identity(
    grant: &CaptureGrant,
    acquired: &BTreeMap<SourceId, Acquired>,
    native: Option<&RegistryCaptureWitness>,
) -> Result<CapturedEnvironmentIdentity, CatalogError> {
    let digest = |id: &SourceId| {
        acquired
            .get(id)
            .map(|source| raw_digest(&source.bytes))
            .ok_or_else(|| unavailable("Required source fingerprint was not acquired"))
    };
    let stack = |sources: &Option<Vec<SourceId>>| {
        sources
            .as_ref()
            .ok_or_else(|| unavailable("Ordered selected pack stack is unknown"))?
            .iter()
            .map(digest)
            .collect::<Result<Vec<_>, _>>()
    };
    let artifact_sha256 = grant.artifact_source.as_ref().map(digest).transpose()?;
    if grant.execution_context["environment"]["kind"] == "game" && artifact_sha256.is_none() {
        return Err(unavailable("Actual game artifact source is unknown"));
    }
    let mod_sources = grant
        .mod_sources
        .as_ref()
        .ok_or_else(|| unavailable("Actual mod source set is unknown"))?;
    let mod_fingerprints = mod_sources
        .iter()
        .map(|(id, source)| Ok((id.clone(), digest(source)?)))
        .collect::<Result<BTreeMap<_, _>, CatalogError>>()?;
    let registry_generation = if let Some(native) = native {
        if grant
            .registry_generation
            .as_ref()
            .is_some_and(|g| g != &native.registry_generation)
        {
            return Err(unavailable("Registry generation changed during capture"));
        }
        native.registry_generation.clone()
    } else {
        grant
            .registry_generation
            .clone()
            .ok_or_else(|| unavailable("Source registry/extraction generation is unknown"))?
    };
    let game_version = grant
        .game_version
        .clone()
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or_else(|| unavailable("Source game version is unknown"))?;
    let locale = grant
        .locale
        .clone()
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or_else(|| unavailable("Source locale is unknown"))?;
    if native.is_some_and(|w| w.game_version != game_version || w.locale != locale) {
        return Err(unavailable(
            "Actual native version or locale differs from approved capture",
        ));
    }
    if registry_generation.is_empty() || registry_generation.len() > 256 {
        return Err(invalid("Source registry generation is invalid"));
    }
    Ok(CapturedEnvironmentIdentity {
        environment: grant.execution_context["environment"].clone(),
        game_version,
        artifact_sha256,
        server_pack_stack: stack(&grant.server_pack_sources)?,
        client_pack_stack: stack(&grant.client_pack_sources)?,
        mod_fingerprints,
        registry_generation,
        registry_digest: native.map(|w| w.registry_digest.clone()),
        locale,
    })
}

fn coverage(status: &str, kinds: &[&str], exclusions: &[&str], consistency: &str) -> Value {
    json!({"status":status,"includedKinds":kinds,"exclusions":exclusions,"consistency":consistency})
}
#[allow(clippy::too_many_arguments)]
fn push_record(
    records: &mut Vec<IndexedRecord>,
    retained_bytes: &mut usize,
    budget: &CaptureBudget,
    snapshot_id: &SnapshotId,
    context: &ContextId,
    scope: &Sha256Digest,
    source: &Acquired,
    kind: &ResourceLocation,
    id: &ResourceLocation,
    value: &Value,
    value_type: &str,
    unit: &str,
    provenance: &str,
    consistency: &str,
) -> Result<(), CatalogError> {
    if records.len() >= budget.max_records {
        return Err(CatalogError::InputLimit);
    }
    // Reject an oversized aggregate before cloning the asset/source into a
    // record. Exact accounting follows the bounded serialization below.
    let lower_bound = encode_json(value)
        .map_err(CatalogError::json)?
        .len()
        .checked_add(
            encode_json(&source.source)
                .map_err(CatalogError::json)?
                .len(),
        )
        .ok_or(CatalogError::InputLimit)?;
    if retained_bytes
        .checked_add(lower_bound)
        .is_none_or(|bytes| bytes > budget.max_snapshot_bytes)
    {
        return Err(CatalogError::InputLimit);
    }
    let identity = canonical_digest(&json!({"kind":kind,"id":id,"source":source.source["sha256"]}))
        .map_err(CatalogError::digest)?;
    let record = json!({"contractVersion":"0.2.0","recordId":format!("record-{identity}"),"snapshotId":snapshot_id,"kind":kind,
        "resourceId":id,"status":"known","value":value,"valueType":value_type,"unit":unit,"sources":[source.source],"provenance":provenance,
        "scopeDigest":scope,"coverage":coverage("complete",&[kind.as_str()],&[],consistency)});
    ContractValidator::shared()?.validate("DataRecord", &record)?;
    *retained_bytes = retained_bytes
        .checked_add(encode_json(&record).map_err(CatalogError::json)?.len())
        .ok_or(CatalogError::InputLimit)?;
    if *retained_bytes > budget.max_snapshot_bytes {
        return Err(CatalogError::InputLimit);
    }
    records.push(IndexedRecord {
        record,
        terms: SearchTerms {
            type_terms: BTreeSet::from([value_type.into()]),
            ..SearchTerms::default()
        },
        contexts: BTreeSet::from([context.clone()]),
    });
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NativeRegistry {
    format: String,
    blocks: Vec<NativeBlock>,
    items: Vec<ResourceLocation>,
    entity_types: Vec<ResourceLocation>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NativeBlock {
    id: ResourceLocation,
    default_state: NativeBlockState,
    properties: BTreeMap<String, Vec<String>>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NativeBlockState {
    block_id: ResourceLocation,
    properties: BTreeMap<String, String>,
}
type DecodedRegistryEntry = (ResourceLocation, ResourceLocation, Value, String);
fn decode_registry(bytes: &[u8]) -> Result<Vec<DecodedRegistryEntry>, CatalogError> {
    if bytes.len() > MAX_NATIVE_REGISTRY_BYTES {
        return Err(CatalogError::InputLimit);
    }
    let value = parse_json(bytes).map_err(CatalogError::json)?;
    let report: NativeRegistry = serde_json::from_value(value).map_err(CatalogError::codec)?;
    if report.format != NATIVE_REGISTRY_FORMAT
        || report.blocks.len() > 100_000
        || report.items.len() > 100_000
        || report.entity_types.len() > 100_000
    {
        return Err(invalid("Native registry report format or count is invalid"));
    }
    let mut output = vec![];
    let mut properties = 0usize;
    let mut enums = 0usize;
    let mut block_ids = BTreeSet::new();
    for block in report.blocks {
        if !block_ids.insert(block.id.clone())
            || block.default_state.block_id != block.id
            || block.default_state.properties.len() != block.properties.len()
        {
            return Err(invalid(
                "Native block ID or complete default state is inconsistent",
            ));
        }
        properties = properties
            .checked_add(block.properties.len())
            .ok_or(CatalogError::InputLimit)?;
        for (name, values) in &block.properties {
            enums = enums
                .checked_add(values.len())
                .ok_or(CatalogError::InputLimit)?;
            if name.is_empty()
                || name.len() > 256
                || values.is_empty()
                || values.len() > 4096
                || values.iter().any(|v| v.is_empty() || v.len() > 256)
                || values.iter().collect::<BTreeSet<_>>().len() != values.len()
                || block
                    .default_state
                    .properties
                    .get(name)
                    .is_none_or(|value| !values.contains(value))
            {
                return Err(invalid(
                    "Native block property allowed values or default state are inconsistent",
                ));
            }
        }
        if properties > 10_000 || enums > 40_000 {
            return Err(CatalogError::InputLimit);
        }
        let value =
            json!({"id":block.id,"defaultState":block.default_state,"properties":block.properties});
        output.push((
            ResourceLocation::new("minecraft:block").unwrap(),
            block.id,
            value,
            "block_registry_entry".into(),
        ));
    }
    for (kind, value_type, ids) in [
        ("minecraft:item", "item_registry_id", report.items),
        (
            "minecraft:entity_type",
            "entity_registry_id",
            report.entity_types,
        ),
    ] {
        let mut seen = BTreeSet::new();
        for id in ids {
            if !seen.insert(id.clone()) {
                return Err(invalid("Native registry ID is duplicated"));
            }
            output.push((
                ResourceLocation::new(kind).unwrap(),
                id.clone(),
                json!({"id":id}),
                value_type.into(),
            ));
        }
    }
    Ok(output)
}

#[cfg(test)]
#[path = "capture_tests.rs"]
mod tests;

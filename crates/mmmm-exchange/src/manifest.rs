//! FN24/FN25: a neutral bundle contains exact immutable payloads. Archive paths
//! are logical member names, never destinations for extraction or remote URLs.
use crate::archive::{
    ArchiveLimits, read_zip, validate_member_path, validate_member_paths, write_zip,
};
use crate::coordinates::CoordinateSystem;
use crate::normalization::{
    NORMALIZATION_MAP_PATH, PROFILE, SOURCE_SELECTION_PATH, WORKING_SELECTION_PATH,
    external_selection, minecraft_coordinates, selection_source_map, working_resource_id,
};
use crate::physics::validate_physics_definition;
use crate::resources::{
    Redistribution, ResourcePort, ResourcePurpose, content_resource, parse_resource, read_resource,
    verify_resource,
};
use crate::selection::Selection;
use crate::{ExchangeError, ExchangeResult, array, json_bytes, text, validate};
use mmmm_contracts::{Sha256Digest, projected_digest, raw_digest, verify_projected_digest};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct PreparedBundle {
    manifest: Value,
    members: BTreeMap<String, Vec<u8>>,
}
impl PreparedBundle {
    pub fn manifest(&self) -> &Value {
        &self.manifest
    }
    pub fn members(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.members
    }
    pub fn zip_bytes(&self, limits: ArchiveLimits) -> ExchangeResult<Vec<u8>> {
        write_zip(&self.members, limits)
    }
    pub fn payload(&self, path: &str) -> Option<&[u8]> {
        self.members.get(path).map(Vec::as_slice)
    }
}

/// Pure preparation plus bounded authorized resource reads. Composition stages
/// these returned bytes in product CAS; this crate does not mutate user files.
pub fn exchange_prepare(
    request: &Value,
    bundle_id: &str,
    port: &mut dyn ResourcePort,
    limits: ArchiveLimits,
) -> ExchangeResult<PreparedBundle> {
    exchange_prepare_with_canonical_bytes(request, bundle_id, None, port, limits)
}
/// A caller that owns the original serialized DTO can preserve those exact raw
/// bytes. They must parse to the request's selection; no new wire field is added.
pub fn exchange_prepare_with_canonical_bytes(
    request: &Value,
    bundle_id: &str,
    canonical_bytes: Option<&[u8]>,
    port: &mut dyn ResourcePort,
    limits: ArchiveLimits,
) -> ExchangeResult<PreparedBundle> {
    validate("ExchangeBuildRequest", request)?;
    let selection = Selection::from_value(&request["selection"])?;
    let context = text(request, "contextId")?;
    port.authorize_selection(context, selection.value())?;
    let coordinates = CoordinateSystem::from_value(&request["coordinates"])?;
    let canonical_coordinates = minecraft_coordinates(&coordinates)?;
    let derived = coordinates != canonical_coordinates;
    let source_bytes = if let Some(bytes) = canonical_bytes {
        if bytes.len() as u64 > limits.max_member_bytes
            || parse_resource("SceneSelectionSnapshot", bytes)? != *selection.value()
        {
            return Err(ExchangeError::new(
                "INPUT_DIGEST_MISMATCH",
                "Canonical source bytes differ from the request DTO or exceed its bound",
            ));
        }
        bytes.to_vec()
    } else {
        json_bytes(selection.value())?
    };
    let working_physics = if let Some(physics) = request.get("physics") {
        verify_projected_digest("PhysicsDefinition", physics)
            .map_err(|e| ExchangeError::new("INPUT_DIGEST_MISMATCH", e.to_string()))?;
        validate_physics_definition(physics, selection.value())?;
        Some(crate::physics_normalization::normalize_physics(
            physics,
            &coordinates,
        )?)
    } else {
        None
    };
    let mut members = BTreeMap::new();
    let mut payloads = Vec::new();
    let working = if derived {
        let output_id = working_resource_id(selection.value(), &coordinates)?;
        let source_map = selection_source_map(selection.value(), &output_id)?;
        insert_payload(
            &mut members,
            &mut payloads,
            NORMALIZATION_MAP_PATH,
            "source_map",
            &source_map,
            limits,
        )?;
        let map_ref = payloads.last().ok_or_else(|| {
            ExchangeError::new("INCOMPLETE_OUTPUT", "Normalization map is absent")
        })?["resource"]
            .clone();
        let working = external_selection(selection.value(), &coordinates, &map_ref)?;
        let reference = content_resource(
            "canonical-source",
            "application/vnd.mmmm.canonical-selection+json",
            &source_bytes,
        );
        payloads.push(json!({"path":SOURCE_SELECTION_PATH,"kind":"opaque_source","resource":reference,"redistribution":"allowed"}));
        members.insert(SOURCE_SELECTION_PATH.to_owned(), source_bytes);
        Some((working, output_id))
    } else {
        None
    };
    insert_payload(
        &mut members,
        &mut payloads,
        WORKING_SELECTION_PATH,
        "selection",
        working
            .as_ref()
            .map_or(selection.value(), |(value, _)| value),
        limits,
    )?;
    if let Some((_, output_id)) = &working {
        payloads.last_mut().ok_or_else(|| {
            ExchangeError::new("INCOMPLETE_OUTPUT", "Working selection payload is absent")
        })?["resource"]["resourceId"] = json!(output_id);
    }
    if !derived && canonical_bytes.is_some() {
        let bytes = canonical_bytes
            .ok_or_else(|| ExchangeError::new("INCOMPLETE_OUTPUT", "Canonical bytes are absent"))?
            .to_vec();
        payloads.last_mut().ok_or_else(|| {
            ExchangeError::new("INCOMPLETE_OUTPUT", "Selection payload is absent")
        })?["resource"] = content_resource("exchange", "application/json", &bytes);
        members.insert(WORKING_SELECTION_PATH.to_owned(), bytes);
    }
    if let Some(physics) = &working_physics {
        insert_payload(
            &mut members,
            &mut payloads,
            "physics/definition.json",
            "physics",
            physics,
            limits,
        )?;
        if request["physics"] != *physics {
            let bytes = json_bytes(&request["physics"])?;
            let reference = content_resource(
                "physics-source",
                "application/vnd.mmmm.source-physics+json",
                &bytes,
            );
            payloads.push(json!({"path":crate::normalization::SOURCE_PHYSICS_PATH,"kind":"opaque_source","resource":reference,"redistribution":"allowed"}));
            members.insert(crate::normalization::SOURCE_PHYSICS_PATH.to_owned(), bytes);
        }
    }
    let mut refs = collect_resources(selection.value())?;
    if let Some(physics) = request.get("physics") {
        merge_resources(&mut refs, collect_resources(physics)?)?;
    }
    let mut observed_bytes = members.values().map(|v| v.len() as u64).sum::<u64>();
    for resource in refs.values() {
        let remaining = limits
            .max_total_bytes
            .checked_sub(observed_bytes)
            .ok_or_else(|| {
                ExchangeError::new(
                    "BUDGET_EXCEEDED",
                    "Bundle resource observation exceeds total budget",
                )
            })?;
        let read = read_resource(
            port,
            context,
            resource,
            ResourcePurpose::Read,
            limits.max_member_bytes.min(remaining),
        )?;
        if resource == &selection.value()["sourceMap"] {
            validate_source_map(&read.bytes, &selection)?;
        }
        observed_bytes = observed_bytes
            .checked_add(read.bytes.len() as u64)
            .ok_or_else(|| ExchangeError::new("BUDGET_EXCEEDED", "Bundle byte count overflow"))?;
        let id = text(resource, "resourceId")?;
        let path = format!(
            "assets/{}-{}.resource",
            &raw_digest(id.as_bytes()).as_str()[..24],
            &text(resource, "sha256")?[..24]
        );
        validate_member_path(&path, limits)?;
        if read.redistribution == Redistribution::Allowed {
            members.insert(path.clone(), read.bytes);
        }
        payloads.push(json!({"path":path,"kind":if resource==&selection.value()["sourceMap"] {"source_map"} else {"asset"},"resource":resource,"redistribution":read.redistribution.wire()}));
    }
    let object_map: Vec<Value> = selection.nodes().filter(|(node,_)|selection.selected(node)).map(|(node,_)|json!({
        "externalId":format!("{}/{}",node.instance_id,node.node_id),"instanceId":node.instance_id,"nodeId":node.node_id,"confidence":"confirmed"
    })).collect();
    let mut manifest = json!({"contractVersion":"0.2.0","bundleId":bundle_id,"bundleRevision":"0".repeat(64),
        "projectId":selection.value()["projectId"],"projectRevision":selection.value()["projectRevision"],"selectionId":selection.value()["selectionId"],
        "dataSnapshotId":request["dataSnapshotId"],"coordinates":request["coordinates"],"payloads":payloads,
        "preservedFeatures":["mmmm:stable_node_ids","mmmm:raw_affine","mmmm:external_references","mmmm:ports","mmmm:state"],"losses":[],"objectMap":object_map});
    if derived {
        manifest["preservedFeatures"]
            .as_array_mut()
            .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "Missing features"))?
            .push(json!(PROFILE));
    }
    if working_physics
        .as_ref()
        .is_some_and(|physics| &request["physics"] != physics)
    {
        manifest["preservedFeatures"]
            .as_array_mut()
            .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "Missing features"))?
            .push(json!(crate::normalization::PHYSICS_PROFILE));
    }
    manifest["bundleRevision"] = json!(
        projected_digest("SceneExchangeManifest", &manifest)
            .map_err(|e| ExchangeError::new("INPUT_DIGEST_MISMATCH", e.to_string()))?
    );
    validate("SceneExchangeManifest", &manifest)?;
    validate_member_paths(
        std::iter::once("mmmm-exchange.json").chain(
            array(&manifest, "payloads")?
                .iter()
                .filter_map(|payload| payload["path"].as_str()),
        ),
        limits,
    )?;
    members.insert("mmmm-exchange.json".to_owned(), json_bytes(&manifest)?);
    // The actual archive codec validates all member/total/output limits here.
    write_zip(&members, limits)?;
    Ok(PreparedBundle { manifest, members })
}

fn insert_payload(
    members: &mut BTreeMap<String, Vec<u8>>,
    payloads: &mut Vec<Value>,
    path: &str,
    kind: &str,
    value: &Value,
    limits: ArchiveLimits,
) -> ExchangeResult<()> {
    let bytes = json_bytes(value)?;
    if bytes.len() as u64 > limits.max_member_bytes {
        return Err(ExchangeError::new(
            "BUDGET_EXCEEDED",
            "Neutral payload exceeds member budget",
        ));
    }
    let resource = content_resource("exchange", "application/json", &bytes);
    payloads.push(json!({"path":path,"kind":kind,"resource":resource,"redistribution":"allowed"}));
    members.insert(path.to_owned(), bytes);
    Ok(())
}

pub struct InspectedBundle {
    bundle: PreparedBundle,
    inspection: Value,
    selection: Selection,
    working_selection: Selection,
    source_digest: Sha256Digest,
    source_size: u64,
}
impl InspectedBundle {
    pub fn bundle(&self) -> &PreparedBundle {
        &self.bundle
    }
    pub fn inspection(&self) -> &Value {
        &self.inspection
    }
    pub fn selection(&self) -> &Selection {
        &self.selection
    }
    /// External working transforms are a derived view, never a scope authority.
    pub fn working_selection(&self) -> &Selection {
        &self.working_selection
    }
    pub fn verify_source_resource(&self, resource: &Value) -> ExchangeResult<()> {
        validate("ResourceRef", resource)?;
        if resource["sha256"].as_str() != Some(self.source_digest.as_str())
            || crate::nonnegative_integer(&resource["sizeBytes"]) != Some(self.source_size)
        {
            return Err(ExchangeError::new(
                "INPUT_DIGEST_MISMATCH",
                "Source resource differs from the exact bytes inspected",
            ));
        }
        Ok(())
    }
}

/// FN25. The caller's ArtifactQuery authorizes only a resource read. Its manifest
/// rights declarations do not grant redistribution or access to referenced data.
pub fn exchange_inspect(
    query: &Value,
    port: &mut dyn ResourcePort,
    limits: ArchiveLimits,
) -> ExchangeResult<InspectedBundle> {
    validate("ArtifactQuery", query)?;
    let context = text(query, "contextId")?;
    let bytes = read_resource(
        port,
        context,
        &query["resource"],
        ResourcePurpose::Read,
        limits.max_archive_bytes,
    )?;
    inspect_resource(
        context,
        &bytes.bytes,
        text(&query["resource"], "mediaType")?,
        port,
        limits,
    )
}
pub fn inspect_zip(
    context: &str,
    bytes: &[u8],
    port: &mut dyn ResourcePort,
    limits: ArchiveLimits,
) -> ExchangeResult<InspectedBundle> {
    let members = read_zip(bytes, limits)?;
    inspect_members(
        context,
        members,
        raw_digest(bytes),
        bytes.len() as u64,
        port,
        limits,
    )
}
/// Detached JSON manifests (including the original examples) resolve payloads by
/// approved ResourceRef through CAS. ZIP is a concrete additional neutral codec.
pub fn inspect_resource(
    context: &str,
    bytes: &[u8],
    media_type: &str,
    port: &mut dyn ResourcePort,
    limits: ArchiveLimits,
) -> ExchangeResult<InspectedBundle> {
    if media_type == "application/zip" || media_type == "application/vnd.mmmm.exchange+zip" {
        return inspect_zip(context, bytes, port, limits);
    }
    if media_type != "application/json" && media_type != "application/vnd.mmmm.exchange+json" {
        return Err(ExchangeError::new(
            "UNSUPPORTED_FORMAT",
            "Opaque editor files are not neutral manifests",
        ));
    }
    if bytes.len() as u64 > limits.max_member_bytes {
        return Err(ExchangeError::new(
            "BUDGET_EXCEEDED",
            "Detached manifest exceeds member byte limit",
        ));
    }
    let manifest = parse_resource("SceneExchangeManifest", bytes)?;
    let mut members = BTreeMap::from([("mmmm-exchange.json".to_owned(), bytes.to_vec())]);
    let mut total = bytes.len() as u64;
    for payload in array(&manifest, "payloads")? {
        if payload["redistribution"] == "allowed" {
            let remaining = limits.max_total_bytes.checked_sub(total).ok_or_else(|| {
                ExchangeError::new("BUDGET_EXCEEDED", "Detached bundle exceeds read budget")
            })?;
            let data = read_resource(
                port,
                context,
                &payload["resource"],
                ResourcePurpose::Read,
                remaining.min(limits.max_member_bytes),
            )?;
            let path = text(payload, "path")?;
            validate_member_path(path, limits)?;
            total = total.checked_add(data.bytes.len() as u64).ok_or_else(|| {
                ExchangeError::new("BUDGET_EXCEEDED", "Detached payload length overflow")
            })?;
            if members.insert(path.to_owned(), data.bytes).is_some() {
                return Err(ExchangeError::new(
                    "ARCHIVE_INVALID",
                    "Detached bundle has duplicate/root-conflicting paths",
                ));
            }
        }
    }
    inspect_members(
        context,
        members,
        raw_digest(bytes),
        bytes.len() as u64,
        port,
        limits,
    )
}
fn inspect_members(
    context: &str,
    members: BTreeMap<String, Vec<u8>>,
    source_digest: Sha256Digest,
    source_size: u64,
    port: &mut dyn ResourcePort,
    limits: ArchiveLimits,
) -> ExchangeResult<InspectedBundle> {
    let manifest_bytes = members
        .get("mmmm-exchange.json")
        .ok_or_else(|| ExchangeError::new("ARCHIVE_INVALID", "Root neutral manifest is absent"))?;
    let manifest = parse_resource("SceneExchangeManifest", manifest_bytes)?;
    verify_projected_digest("SceneExchangeManifest", &manifest)
        .map_err(|e| ExchangeError::new("INPUT_DIGEST_MISMATCH", e.to_string()))?;
    let coordinates = CoordinateSystem::from_value(&manifest["coordinates"])?;
    let profile = array(&manifest, "preservedFeatures")?
        .iter()
        .any(|feature| feature == PROFILE);
    let physics_profile = array(&manifest, "preservedFeatures")?
        .iter()
        .any(|feature| feature == crate::normalization::PHYSICS_PROFILE);
    if coordinates != minecraft_coordinates(&coordinates)? && !profile {
        return Err(ExchangeError::new(
            "UNSUPPORTED_FORMAT",
            "Noncanonical coordinates require the declared canonical-source affine profile",
        ));
    }
    let mut paths = BTreeSet::new();
    let mut external_ids = BTreeSet::new();
    let mut node_map = BTreeSet::new();
    for mapping in array(&manifest, "objectMap")? {
        if !external_ids.insert(text(mapping, "externalId")?)
            || !node_map.insert((text(mapping, "instanceId")?, text(mapping, "nodeId")?))
        {
            return Err(ExchangeError::new(
                "OBJECT_MAPPING_AMBIGUOUS",
                "Object map contains ambiguous stable identities",
            ));
        }
    }
    let mut resources = BTreeMap::new();
    let mut selection = None;
    let mut physics = None;
    let mut source_maps = Vec::new();
    let mut canonical_source = None;
    let mut working_resource = None;
    let mut source_physics = None;
    let mut total = manifest_bytes.len() as u64;
    validate_member_paths(
        std::iter::once("mmmm-exchange.json").chain(
            array(&manifest, "payloads")?
                .iter()
                .filter_map(|payload| payload["path"].as_str()),
        ),
        limits,
    )?;
    for payload in array(&manifest, "payloads")? {
        let path = text(payload, "path")?;
        validate_member_path(path, limits)?;
        if path == "mmmm-exchange.json" || !paths.insert(path.to_owned()) {
            return Err(ExchangeError::new(
                "ARCHIVE_INVALID",
                "Payload paths must be distinct from the root manifest",
            ));
        }
        let resource = &payload["resource"];
        merge_resources(
            &mut resources,
            [(text(resource, "resourceId")?.to_owned(), resource.clone())]
                .into_iter()
                .collect(),
        )?;
        let rights = text(payload, "redistribution")?;
        let data = if let Some(contained) = members.get(path) {
            if rights != "allowed" {
                return Err(ExchangeError::new(
                    "RESOURCE_FORBIDDEN",
                    "Reference-only or unknown-rights payload must not be embedded",
                ));
            }
            // MMMM-generated neutral selection/physics are authored metadata;
            // referenced third-party assets need trusted rights confirmation.
            if !(matches!(text(payload, "kind")?, "selection" | "physics")
                || (physics_profile
                    && path == crate::normalization::SOURCE_PHYSICS_PATH
                    && payload["kind"] == "opaque_source")
                || (profile
                    && ((path == SOURCE_SELECTION_PATH && payload["kind"] == "opaque_source")
                        || (path == NORMALIZATION_MAP_PATH && payload["kind"] == "source_map"))))
                && port.embedded_rights(context, resource)? != Redistribution::Allowed
            {
                return Err(ExchangeError::new(
                    "RESOURCE_FORBIDDEN",
                    "Embedded asset has no trusted redistribution record",
                ));
            }
            verify_resource(resource, contained, limits.max_member_bytes)?;
            contained.clone()
        } else {
            if rights == "allowed" {
                return Err(ExchangeError::new(
                    "INCOMPLETE_OUTPUT",
                    "Manifest-declared embedded payload is absent",
                ));
            }
            let remaining = limits.max_total_bytes.checked_sub(total).ok_or_else(|| {
                ExchangeError::new(
                    "BUDGET_EXCEEDED",
                    "Referenced payload reads exceed total budget",
                )
            })?;
            read_resource(
                port,
                context,
                resource,
                ResourcePurpose::Read,
                limits.max_member_bytes.min(remaining),
            )?
            .bytes
        };
        total = total.checked_add(data.len() as u64).ok_or_else(|| {
            ExchangeError::new("BUDGET_EXCEEDED", "Inspection byte count overflow")
        })?;
        if total > limits.max_total_bytes {
            return Err(ExchangeError::new(
                "BUDGET_EXCEEDED",
                "Inspection exceeds the total decompressed/read byte budget",
            ));
        }
        match text(payload, "kind")? {
            "selection" => {
                if selection.is_some() {
                    return Err(ExchangeError::new(
                        "ARCHIVE_INVALID",
                        "Bundle has multiple selection snapshots",
                    ));
                }
                selection = Some(Selection::from_value(&parse_resource(
                    "SceneSelectionSnapshot",
                    &data,
                )?)?);
                working_resource = Some(resource.clone());
            }
            "physics" => {
                if physics.is_some() {
                    return Err(ExchangeError::new(
                        "ARCHIVE_INVALID",
                        "Bundle has multiple physics definitions",
                    ));
                }
                physics = Some(parse_resource("PhysicsDefinition", &data)?);
            }
            "source_map" => {
                parse_resource("SourceMap", &data)?;
                source_maps.push((resource.clone(), data));
            }
            "opaque_source" if profile && path == SOURCE_SELECTION_PATH => {
                if canonical_source.is_some()
                    || resource["mediaType"] != "application/vnd.mmmm.canonical-selection+json"
                {
                    return Err(ExchangeError::new(
                        "ARCHIVE_INVALID",
                        "Canonical source payload identity is invalid",
                    ));
                }
                canonical_source = Some(Selection::from_value(&parse_resource(
                    "SceneSelectionSnapshot",
                    &data,
                )?)?);
            }
            "opaque_source"
                if physics_profile && path == crate::normalization::SOURCE_PHYSICS_PATH =>
            {
                if source_physics.is_some()
                    || resource["mediaType"] != "application/vnd.mmmm.source-physics+json"
                {
                    return Err(ExchangeError::new(
                        "ARCHIVE_INVALID",
                        "Declared physics source identity is invalid",
                    ));
                }
                source_physics = Some(parse_resource("PhysicsDefinition", &data)?);
            }
            _ => {} // Opaque source/assets are preserved as bytes, never executed.
        }
    }
    if members
        .keys()
        .any(|path| path != "mmmm-exchange.json" && !paths.contains(path))
    {
        return Err(ExchangeError::new(
            "ARCHIVE_INVALID",
            "Archive contains an undeclared member",
        ));
    }
    let working_selection = selection.ok_or_else(|| {
        ExchangeError::new(
            "ARCHIVE_INVALID",
            "Neutral bundle requires exactly one selection snapshot",
        )
    })?;
    let selection = if profile {
        let source = canonical_source.ok_or_else(|| {
            ExchangeError::new(
                "INCOMPLETE_OUTPUT",
                "Normalized bundle requires its exact canonical source selection",
            )
        })?;
        let output_id = working_resource_id(source.value(), &coordinates)?;
        if working_resource
            .as_ref()
            .and_then(|resource| resource["resourceId"].as_str())
            != Some(output_id.as_str())
        {
            return Err(ExchangeError::new(
                "INPUT_DIGEST_MISMATCH",
                "Working selection ID is not derived from this source and coordinate profile",
            ));
        }
        let expected_map = selection_source_map(source.value(), &output_id)?;
        let expected_bytes = json_bytes(&expected_map)?;
        let expected_ref = content_resource("exchange", "application/json", &expected_bytes);
        let actual_maps: Vec<_> = source_maps
            .iter()
            .filter(|(resource, _)| resource == &expected_ref)
            .collect();
        if actual_maps.len() != 1
            || actual_maps[0].1 != expected_bytes
            || working_selection.value()
                != &external_selection(source.value(), &coordinates, &expected_ref)?
        {
            return Err(ExchangeError::new(
                "INPUT_DIGEST_MISMATCH",
                "Working selection/map differs from independently recomputed spatial derivation",
            ));
        }
        source
    } else {
        working_selection.clone()
    };
    selection.check_revision(
        text(&manifest, "projectId")?,
        text(&manifest, "projectRevision")?,
    )?;
    if selection.value()["selectionId"] != manifest["selectionId"] {
        return Err(ExchangeError::new(
            "INPUT_DIGEST_MISMATCH",
            "Manifest and selection identities differ",
        ));
    }
    port.authorize_selection(context, selection.value())?;
    let matching_maps: Vec<_> = source_maps
        .iter()
        .filter(|(resource, _)| resource == &selection.value()["sourceMap"])
        .collect();
    if matching_maps.len() != 1 {
        return Err(ExchangeError::new(
            "REFERENCE_UNRESOLVED",
            "Selection SourceMap must be declared once with its source_map payload kind",
        ));
    }
    validate_source_map(&matching_maps[0].1, &selection)?;
    for mapping in array(&manifest, "objectMap")? {
        let node = crate::selection::ObjectNode {
            instance_id: text(mapping, "instanceId")?.to_owned(),
            node_id: text(mapping, "nodeId")?.to_owned(),
        };
        if !selection.selected(&node) {
            return Err(ExchangeError::new(
                "REFERENCE_UNRESOLVED",
                "Object map points outside the selected boundary",
            ));
        }
    }
    let mut declared = collect_resources(selection.value())?;
    if physics_profile {
        let source = source_physics.as_ref().ok_or_else(|| {
            ExchangeError::new(
                "INCOMPLETE_OUTPUT",
                "Physics variant requires its exact declared source",
            )
        })?;
        validate_physics_definition(source, selection.value())?;
        let expected = crate::physics_normalization::normalize_physics(source, &coordinates)?;
        if physics.as_ref() != Some(&expected) {
            return Err(ExchangeError::new(
                "INPUT_DIGEST_MISMATCH",
                "Working physics differs from independently recomputed declared-coordinate derivation",
            ));
        }
        merge_resources(&mut declared, collect_resources(source)?)?;
    }
    if let Some(physics) = physics {
        verify_projected_digest("PhysicsDefinition", &physics)
            .map_err(|e| ExchangeError::new("INPUT_DIGEST_MISMATCH", e.to_string()))?;
        validate_physics_definition(&physics, selection.value())?;
        // JSON 1 and 1.0 denote the same coefficient. Compare the validated
        // coordinate contract exactly, while ResourceRef still pins raw bytes.
        if CoordinateSystem::from_value(&physics["coordinates"])? != coordinates {
            return Err(ExchangeError::new(
                "UNIT_MISMATCH",
                "Physics and manifest coordinate pins differ",
            ));
        }
        merge_resources(&mut declared, collect_resources(&physics)?)?;
    }
    for (id, resource) in declared {
        if resources.get(&id) != Some(&resource) {
            return Err(ExchangeError::new(
                "REFERENCE_UNRESOLVED",
                "Selection resource pin is absent or conflicting in the manifest",
            ));
        }
    }
    let inspection = json!({"manifest":manifest,"resolvedResources":resources.values().collect::<Vec<_>>(),"diagnostics":[],"losses":manifest["losses"]});
    validate("BundleInspection", &inspection)?;
    Ok(InspectedBundle {
        bundle: PreparedBundle { manifest, members },
        inspection,
        selection,
        working_selection,
        source_digest,
        source_size,
    })
}

pub(crate) fn collect_resources(value: &Value) -> ExchangeResult<BTreeMap<String, Value>> {
    let mut resources = BTreeMap::new();
    let mut stack = vec![(value, 0_usize)];
    let mut count = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        count += 1;
        if count > 100_000 || depth > 64 {
            return Err(ExchangeError::new(
                "BUDGET_EXCEEDED",
                "Resource graph exceeds traversal budget",
            ));
        }
        match value {
            Value::Object(map)
                if ["resourceId", "sha256", "mediaType", "sizeBytes"]
                    .iter()
                    .all(|key| map.contains_key(*key)) =>
            {
                validate("ResourceRef", value)?;
                let id = text(value, "resourceId")?.to_owned();
                if let Some(previous) = resources.insert(id, value.clone())
                    && previous != *value
                {
                    return Err(ExchangeError::new(
                        "RESOURCE_HASH_MISMATCH",
                        "Resource ID has inconsistent content pins",
                    ));
                }
            }
            Value::Object(map) => stack.extend(map.values().map(|child| (child, depth + 1))),
            Value::Array(values) => stack.extend(values.iter().map(|child| (child, depth + 1))),
            _ => {}
        }
    }
    Ok(resources)
}
fn merge_resources(
    destination: &mut BTreeMap<String, Value>,
    source: BTreeMap<String, Value>,
) -> ExchangeResult<()> {
    for (id, value) in source {
        if let Some(previous) = destination.insert(id, value.clone())
            && previous != value
        {
            return Err(ExchangeError::new(
                "RESOURCE_HASH_MISMATCH",
                "Resource ID has conflicting immutable pins",
            ));
        }
    }
    Ok(())
}
fn validate_source_map(bytes: &[u8], selection: &Selection) -> ExchangeResult<()> {
    let source = parse_resource("SourceMap", bytes)?;
    let revision = &source["inputRevision"];
    if revision != &selection.value()["projectRevision"]
        && !array(selection.value(), "instances")?
            .iter()
            .any(|instance| &instance["revision"] == revision)
        && !array(selection.value(), "prefabs")?
            .iter()
            .any(|prefab| &prefab["revision"] == revision)
    {
        return Err(ExchangeError::new(
            "REVISION_CONFLICT",
            "SourceMap provenance is not pinned to the selected project/instance/prefab snapshot",
        ));
    }
    Ok(())
}

//! Immutable source metadata completes scope information which has no wire
//! field. It is not a second DataSnapshot schema or an authority declaration.

use crate::catalog::{CatalogError, CatalogLimits};
use mmmm_contracts::{
    ContextId, ContractValidator, RecordId, ResourceLocation, Sha256Digest, SnapshotId,
    canonical_bytes, canonical_digest, encode_json,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Source-derived aliases never rewrite the canonical resource ID. Names are
/// indexed independently of their value payload and keep their locale.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SearchTerms {
    pub aliases: BTreeMap<String, Vec<String>>,
    pub tags: BTreeSet<ResourceLocation>,
    pub type_terms: BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub struct IndexedRecord {
    pub record: Value,
    pub terms: SearchTerms,
    /// Explicit compatible contexts from the source. Context names are not
    /// permission grants; the access port checks each request separately.
    pub contexts: BTreeSet<ContextId>,
}

/// A source's declaration for IDs not present in its returned records. There
/// is no automatic inference from an empty search. An absent claim must cover
/// the entire requested kind in this exact context, with no exclusions.
#[derive(Clone, Debug)]
pub struct MissingRecordClaim {
    pub context_id: ContextId,
    pub kind: ResourceLocation,
    pub scope_digest: Sha256Digest,
    pub status: String,
    pub value_type: String,
    pub unit: String,
    pub sources: Vec<Value>,
    pub provenance: String,
    pub coverage: Value,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObservationWindow {
    /// Canonical unsigned decimal tick strings avoid floating point rounding.
    pub first_tick: String,
    pub last_tick: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SnapshotIdentity {
    pub registry_generation: String,
    pub mod_fingerprints: BTreeMap<ResourceLocation, Sha256Digest>,
    pub query_context_digest: Sha256Digest,
    pub observation_window: Option<ObservationWindow>,
}

#[derive(Clone, Debug)]
pub struct SnapshotInput {
    pub snapshot: Value,
    pub identity: SnapshotIdentity,
    pub records: Vec<IndexedRecord>,
    pub missing_records: Vec<MissingRecordClaim>,
}

pub(crate) struct Snapshot {
    pub value: Value,
    pub id: SnapshotId,
    pub revision: Sha256Digest,
    pub fingerprint: Sha256Digest,
    pub locale: String,
    pub coverage: Value,
    pub identity: SnapshotIdentity,
    pub records: Vec<IndexedRecord>,
    pub record_costs: BTreeMap<String, ValueCost>,
    pub missing: BTreeMap<(ContextId, ResourceLocation), MissingRecordClaim>,
    pub retained_bytes: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct ValueCost {
    pub bytes: usize,
    pub nodes: usize,
    pub depth: usize,
}

pub(crate) fn value_cost(value: &Value) -> Result<ValueCost, CatalogError> {
    let bytes = encode_json(value).map_err(CatalogError::json)?.len();
    let mut pending = vec![(value, 0usize)];
    let mut nodes = 0usize;
    let mut depth = 0usize;
    while let Some((value, current_depth)) = pending.pop() {
        nodes = nodes.checked_add(1).ok_or(CatalogError::InputLimit)?;
        depth = depth.max(current_depth);
        match value {
            Value::Array(items) => {
                pending.extend(items.iter().map(|item| (item, current_depth + 1)))
            }
            Value::Object(items) => {
                pending.extend(items.values().map(|item| (item, current_depth + 1)))
            }
            _ => {}
        }
    }
    Ok(ValueCost {
        bytes,
        nodes,
        depth,
    })
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str, CatalogError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| CatalogError::SchemaUnsupported(format!("Missing validated field {name}")))
}

pub(crate) fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    // All callers use a value that crossed canonical schema validation.
    value[name].as_str().expect("validated string field")
}

fn add_bytes(total: &mut usize, amount: usize, maximum: usize) -> Result<(), CatalogError> {
    *total = total.checked_add(amount).ok_or(CatalogError::InputLimit)?;
    if *total > maximum {
        return Err(CatalogError::InputLimit);
    }
    Ok(())
}

fn validate_terms(terms: &SearchTerms, limits: &CatalogLimits) -> Result<usize, CatalogError> {
    let count = terms.aliases.values().map(Vec::len).sum::<usize>()
        + terms.tags.len()
        + terms.type_terms.len();
    if count > limits.max_terms_per_record || terms.aliases.len() > limits.max_terms_per_record {
        return Err(CatalogError::InputLimit);
    }
    for locale in terms.aliases.keys() {
        if locale.is_empty() || locale.len() > limits.max_term_bytes {
            return Err(CatalogError::InputLimit);
        }
    }
    if terms
        .tags
        .iter()
        .any(|tag| tag.as_str().len() > limits.max_term_bytes)
    {
        return Err(CatalogError::InputLimit);
    }
    for term in terms
        .aliases
        .values()
        .flatten()
        .chain(terms.type_terms.iter())
    {
        if term.is_empty() || term.len() > limits.max_term_bytes {
            return Err(CatalogError::InputLimit);
        }
    }
    let value = serde_json::to_value(terms).map_err(CatalogError::codec)?;
    Ok(canonical_bytes(&value).map_err(CatalogError::digest)?.len())
}

fn validate_window(window: &ObservationWindow) -> Result<(), CatalogError> {
    fn decimal(text: &str) -> bool {
        !text.is_empty()
            && text.len() <= 128
            && text.bytes().all(|byte| byte.is_ascii_digit())
            && (text == "0" || !text.starts_with('0'))
    }
    if !decimal(&window.first_tick)
        || !decimal(&window.last_tick)
        || (window.first_tick.len(), &window.first_tick)
            > (window.last_tick.len(), &window.last_tick)
    {
        return Err(CatalogError::SchemaUnsupported(
            "Observation window must contain ordered canonical ticks".into(),
        ));
    }
    Ok(())
}

fn source_set(snapshot: &Value) -> BTreeMap<String, &Value> {
    snapshot["sources"]
        .as_array()
        .expect("validated source array")
        .iter()
        .map(|source| (text(source, "sourceId").to_owned(), source))
        .collect()
}

fn check_sources(
    sources: &[Value],
    approved: &BTreeMap<String, &Value>,
) -> Result<(), CatalogError> {
    let mut seen = BTreeSet::new();
    for source in sources {
        ContractValidator::shared()?.validate("SourceRef", source)?;
        let id = text(source, "sourceId");
        if !seen.insert(id) || approved.get(id).is_none_or(|value| **value != *source) {
            return Err(CatalogError::SourceUnavailable(
                "Record source does not match immutable snapshot source".into(),
            ));
        }
    }
    Ok(())
}

fn check_absence(record: &Value) -> Result<(), CatalogError> {
    if record["status"] == "absent"
        && (record["coverage"]["status"] != "complete"
            || !record["coverage"]["exclusions"]
                .as_array()
                .unwrap()
                .is_empty()
            || !record["coverage"]["includedKinds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|kind| kind == &record["kind"])
            || record["sources"].as_array().unwrap().is_empty())
    {
        return Err(CatalogError::SchemaUnsupported(
            "Absence requires complete source-backed coverage of this kind and context".into(),
        ));
    }
    Ok(())
}

impl Snapshot {
    pub fn build(input: SnapshotInput, limits: &CatalogLimits) -> Result<Self, CatalogError> {
        let validator = ContractValidator::shared()?;
        validator.validate("DataSnapshot", &input.snapshot)?;
        if input.records.len() > limits.max_records_per_snapshot
            || input.missing_records.len() > limits.max_records_per_snapshot
            || input.identity.registry_generation.is_empty()
            || input.identity.registry_generation.len() > limits.max_term_bytes
            || input.identity.mod_fingerprints.len() > limits.max_records_per_snapshot
            || field(&input.snapshot, "locale")?.len() > limits.max_term_bytes
        {
            return Err(CatalogError::InputLimit);
        }
        let side = text(&input.snapshot, "side");
        if input.snapshot["environment"]["side"] != side {
            return Err(CatalogError::SchemaUnsupported(
                "Snapshot side does not match its environment".into(),
            ));
        }
        let world_observation = input.snapshot["layers"]
            .as_array()
            .expect("validated layers")
            .iter()
            .any(|layer| layer == "world_observation");
        if world_observation && input.identity.observation_window.is_none() {
            return Err(CatalogError::SchemaUnsupported(
                "World observation needs its actual observation window".into(),
            ));
        }
        if let Some(window) = &input.identity.observation_window {
            validate_window(window)?;
            if world_observation && input.snapshot["coverage"]["consistency"] == "immutable" {
                return Err(CatalogError::SchemaUnsupported(
                    "An immutable catalog does not make world observations simultaneous".into(),
                ));
            }
            if input.snapshot["coverage"]["consistency"] == "provider_atomic"
                && window.first_tick != window.last_tick
            {
                return Err(CatalogError::SchemaUnsupported(
                    "Multi-tick observation cannot be provider_atomic".into(),
                ));
            }
        }
        let id =
            SnapshotId::new(field(&input.snapshot, "snapshotId")?).map_err(CatalogError::id)?;
        let fingerprint = Sha256Digest::new(field(&input.snapshot, "environmentFingerprint")?)
            .map_err(CatalogError::id)?;
        let approved = source_set(&input.snapshot);
        if approved.len() != input.snapshot["sources"].as_array().unwrap().len() {
            return Err(CatalogError::SchemaUnsupported(
                "Duplicate snapshot source ID".into(),
            ));
        }
        let identity_value = serde_json::to_value(&input.identity).map_err(CatalogError::codec)?;
        let mut retained_bytes = encode_json(&input.snapshot)
            .map_err(CatalogError::json)?
            .len();
        add_bytes(
            &mut retained_bytes,
            encode_json(&identity_value)
                .map_err(CatalogError::json)?
                .len(),
            limits.max_snapshot_bytes,
        )?;
        let snapshot_digest = canonical_digest(&input.snapshot).map_err(CatalogError::digest)?;
        let identity_digest = canonical_digest(&identity_value).map_err(CatalogError::digest)?;
        let mut record_ids = BTreeSet::new();
        let mut record_sizes = BTreeMap::new();
        let mut lookup_keys = BTreeSet::new();
        let mut revisions = Vec::new();
        for entry in &input.records {
            validator.validate("DataRecord", &entry.record)?;
            check_absence(&entry.record)?;
            if text(&entry.record, "snapshotId") != id.as_str() || entry.contexts.is_empty() {
                return Err(CatalogError::SchemaUnsupported(
                    "Record must name this snapshot and compatible contexts".into(),
                ));
            }
            let record_id =
                RecordId::new(text(&entry.record, "recordId")).map_err(CatalogError::id)?;
            if !record_ids.insert(record_id) {
                return Err(CatalogError::SchemaUnsupported(
                    "Duplicate record ID".into(),
                ));
            }
            if entry.contexts.len() > limits.max_terms_per_record {
                return Err(CatalogError::InputLimit);
            }
            for context in &entry.contexts {
                if !lookup_keys.insert((
                    context.clone(),
                    text(&entry.record, "kind").to_owned(),
                    text(&entry.record, "resourceId").to_owned(),
                )) {
                    return Err(CatalogError::SchemaUnsupported(
                        "Ambiguous record in the same context".into(),
                    ));
                }
            }
            check_sources(entry.record["sources"].as_array().unwrap(), &approved)?;
            let cost = value_cost(&entry.record)?;
            let record_bytes = cost.bytes;
            if record_bytes > limits.max_record_bytes {
                return Err(CatalogError::InputLimit);
            }
            add_bytes(&mut retained_bytes, record_bytes, limits.max_snapshot_bytes)?;
            record_sizes.insert(text(&entry.record, "recordId").to_owned(), cost);
            add_bytes(
                &mut retained_bytes,
                validate_terms(&entry.terms, limits)?,
                limits.max_snapshot_bytes,
            )?;
            add_bytes(
                &mut retained_bytes,
                encode_json(&json!(entry.contexts))
                    .map_err(CatalogError::json)?
                    .len(),
                limits.max_snapshot_bytes,
            )?;
            revisions.push(
                canonical_digest(&json!({
                    "record": canonical_digest(&entry.record).map_err(CatalogError::digest)?,
                    "terms": entry.terms, "contexts": entry.contexts,
                }))
                .map_err(CatalogError::digest)?,
            );
        }
        let mut missing = BTreeMap::new();
        let mut missing_revisions = Vec::new();
        for claim in input.missing_records {
            check_sources(&claim.sources, &approved)?;
            let placeholder = claim.to_record(&id, "mmmm:coverage_probe")?;
            validator.validate("DataRecord", &placeholder)?;
            check_absence(&placeholder)?;
            if claim.status == "known" {
                return Err(CatalogError::SchemaUnsupported(
                    "Missing claim cannot be known".into(),
                ));
            }
            let bytes = canonical_bytes(&placeholder)
                .map_err(CatalogError::digest)?
                .len();
            if bytes > limits.max_record_bytes {
                return Err(CatalogError::InputLimit);
            }
            add_bytes(&mut retained_bytes, bytes, limits.max_snapshot_bytes)?;
            missing_revisions.push(
                canonical_digest(&json!({"contextId":claim.context_id, "record":placeholder}))
                    .map_err(CatalogError::digest)?,
            );
            if missing
                .insert((claim.context_id.clone(), claim.kind.clone()), claim)
                .is_some()
            {
                return Err(CatalogError::SchemaUnsupported(
                    "Duplicate coverage claim".into(),
                ));
            }
        }
        // This is an internal cache identity. No projection is added to the
        // original digest contract. Pack arrays retain their original order.
        revisions.sort();
        missing_revisions.sort();
        let revision = canonical_digest(&json!({
            "snapshot": snapshot_digest, "identity":identity_digest,
            "records": revisions, "missingClaims":missing_revisions,
        }))
        .map_err(CatalogError::digest)?;
        if retained_bytes > limits.max_snapshot_bytes {
            return Err(CatalogError::InputLimit);
        }
        Ok(Self {
            locale: text(&input.snapshot, "locale").to_owned(),
            coverage: input.snapshot["coverage"].clone(),
            value: input.snapshot,
            id,
            revision,
            fingerprint,
            identity: input.identity,
            records: input.records,
            record_costs: record_sizes,
            missing,
            retained_bytes,
        })
    }
}

impl MissingRecordClaim {
    pub(crate) fn to_record(
        &self,
        snapshot: &SnapshotId,
        resource: &str,
    ) -> Result<Value, CatalogError> {
        let key = canonical_digest(&json!({"snapshotId":snapshot,"kind":self.kind,
            "resourceId":resource,"contextId":self.context_id,"scopeDigest":self.scope_digest}))
        .map_err(CatalogError::digest)?;
        Ok(json!({
            "contractVersion":"0.2.0", "recordId":format!("missing-{key}"),
            "snapshotId":snapshot, "kind":self.kind, "resourceId":resource,
            "status":self.status, "valueType":self.value_type, "unit":self.unit,
            "sources":self.sources, "provenance":self.provenance,
            "scopeDigest":self.scope_digest, "coverage":self.coverage, "reason":self.reason,
        }))
    }
}

//! Approved source/runtime access is injected. Capture verifies actual byte
//! evidence supplied by that trusted port and never performs implicit loading.

use crate::{
    catalog::{AccessControl, Catalog, CatalogError, ReadPrincipal},
    snapshot::{SnapshotInput, text},
};
use mmmm_contracts::{ContractValidator, SnapshotId, SourceId, raw_digest};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

pub struct CaptureControl<'a> {
    pub cancellation: &'a AtomicBool,
    pub deadline: Instant,
}
impl CaptureControl<'_> {
    /// Ports must check this while enumerating; this pure crate cannot forcibly
    /// interrupt a port that blocks in external I/O.
    pub fn should_stop(&self) -> bool {
        self.cancellation.load(Ordering::Acquire) || Instant::now() >= self.deadline
    }
}

/// Small bounded source evidence is consumed for hash verification, not kept
/// in the catalog. The application owns durable CAS/evidence retention.
pub struct CaptureSourceEvidence {
    pub source: Value,
    pub observed_bytes: Vec<u8>,
}

pub struct CaptureResult {
    pub snapshot: SnapshotInput,
    pub sources: Vec<CaptureSourceEvidence>,
    /// Cancellation preserves only data actually obtained by the source.
    pub interrupted: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct CaptureBudget {
    pub max_source_bytes: usize,
    pub max_sources: usize,
    pub max_records: usize,
    pub max_snapshot_bytes: usize,
}

/// A port uses this gate before reading a dynamically discovered source. The
/// source reference is validated but its claims are still checked against the
/// application's approved registry/root authority, not trusted on their own.
pub struct CaptureSourceAccess<'a> {
    principal: &'a ReadPrincipal,
    access: &'a dyn AccessControl,
}
impl CaptureSourceAccess<'_> {
    /// Authenticated caller supplied by the Coordinator. A source may use this
    /// identity to resolve its approved bindings; request fields cannot replace it.
    pub fn principal(&self) -> &ReadPrincipal {
        self.principal
    }
    pub fn authorize_before_read(&self, source: &Value) -> Result<(), CatalogError> {
        ContractValidator::shared()?.validate("SourceRef", source)?;
        self.access.authorize_source(self.principal, source)
    }
}

pub trait SnapshotSource {
    /// The port resolves approved roots/connections, checks real permissions,
    /// obtains source bytes/observations, and reports accurate coverage. It
    /// must not add chunk tickets, generate worlds, reload packs or mutate data
    /// to satisfy this read. The caller's SourceRef is not an attestation.
    /// Each successful capture allocates a new immutable snapshot ID.
    fn capture(
        &mut self,
        request: &Value,
        control: &CaptureControl<'_>,
        budget: &CaptureBudget,
        source_access: &CaptureSourceAccess<'_>,
    ) -> Result<CaptureResult, CatalogError>;
}

pub(crate) fn capture(
    catalog: &mut Catalog,
    input: &Value,
    principal: &ReadPrincipal,
    access: &dyn AccessControl,
    port: &mut dyn SnapshotSource,
    control: &CaptureControl<'_>,
) -> Result<Value, CatalogError> {
    let validator = ContractValidator::shared()?;
    validator.validate("SnapshotRequest", input)?;
    access.authorize_capture(principal, input)?;
    let budget = CaptureBudget {
        max_source_bytes: catalog.limits().max_capture_evidence_bytes,
        max_sources: catalog.limits().max_records_per_snapshot,
        max_records: catalog.limits().max_records_per_snapshot,
        max_snapshot_bytes: catalog.limits().max_snapshot_bytes,
    };
    let requested_sources = input["sources"].as_array().unwrap();
    if requested_sources.len() > budget.max_sources {
        return Err(CatalogError::InputLimit);
    }
    for requested in requested_sources {
        access.authorize_source(principal, requested)?;
    }
    if control.should_stop() {
        return Err(CatalogError::Cancelled);
    }
    // One invocation. No retry, second source, fallback or live mutation.
    let source_access = CaptureSourceAccess { principal, access };
    let result = port.capture(input, control, &budget, &source_access)?;
    validator.validate("DataSnapshot", &result.snapshot.snapshot)?;
    let snapshot = &result.snapshot.snapshot;
    let snapshot_id = SnapshotId::new(text(snapshot, "snapshotId")).map_err(CatalogError::id)?;
    if catalog.contains_snapshot(&snapshot_id) {
        return Err(CatalogError::SnapshotConflict);
    }
    if snapshot["environment"] != input["environment"] {
        return Err(CatalogError::SourceUnavailable(
            "Captured environment differs from the approved request".into(),
        ));
    }
    if !snapshot["layers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|layer| layer == &input["kind"])
    {
        return Err(CatalogError::SchemaUnsupported(
            "Capture omitted the requested data layer".into(),
        ));
    }
    let interrupted = result.interrupted || control.should_stop();
    if interrupted
        && (snapshot["coverage"]["status"] != "partial"
            || snapshot["coverage"]["exclusions"]
                .as_array()
                .unwrap()
                .is_empty())
    {
        return Err(CatalogError::SchemaUnsupported(
            "Interrupted capture needs explicit partial coverage and exclusions".into(),
        ));
    }
    let max_bytes = catalog.limits().max_capture_evidence_bytes;
    let max_sources = catalog.limits().max_records_per_snapshot;
    if result.sources.len() > max_sources {
        return Err(CatalogError::InputLimit);
    }
    let mut verified = BTreeMap::new();
    let mut total = 0usize;
    for evidence in &result.sources {
        validator.validate("SourceRef", &evidence.source)?;
        access.authorize_source(principal, &evidence.source)?;
        total = total
            .checked_add(evidence.observed_bytes.len())
            .ok_or(CatalogError::InputLimit)?;
        if total > max_bytes {
            return Err(CatalogError::InputLimit);
        }
        let id = SourceId::new(text(&evidence.source, "sourceId")).map_err(CatalogError::id)?;
        let digest = raw_digest(&evidence.observed_bytes);
        if evidence.source["sha256"] != digest.as_str() {
            return Err(CatalogError::SourceUnavailable(
                "Source bytes do not match the observed source digest".into(),
            ));
        }
        if verified.insert(id, &evidence.source).is_some() {
            return Err(CatalogError::SchemaUnsupported(
                "Duplicate capture source evidence".into(),
            ));
        }
    }
    for reference in snapshot["sources"].as_array().unwrap() {
        let id = SourceId::new(text(reference, "sourceId")).map_err(CatalogError::id)?;
        if verified
            .get(&id)
            .is_none_or(|actual| **actual != *reference)
        {
            return Err(CatalogError::SourceUnavailable(
                "Snapshot source lacks matching actual-byte evidence".into(),
            ));
        }
    }
    for requested in input["sources"].as_array().unwrap() {
        let id = SourceId::new(text(requested, "sourceId")).map_err(CatalogError::id)?;
        // A null caller hash is a request to inspect, not evidence of success.
        // Other source claims (including rights) must be confirmed by the port.
        let Some(actual) = verified.get(&id) else {
            if interrupted {
                continue;
            }
            return Err(CatalogError::SourceUnavailable(
                "Requested source was not captured".into(),
            ));
        };
        let mut expected = requested.clone();
        if expected["sha256"].is_null() {
            expected["sha256"] = actual["sha256"].clone();
        }
        // verifiedAt belongs to the newly performed observation, not the input.
        expected["verifiedAt"] = actual["verifiedAt"].clone();
        if expected != **actual {
            return Err(CatalogError::SourceUnavailable(
                "Requested source claims were not confirmed by the source port".into(),
            ));
        }
    }
    access.authorize_snapshot(principal, snapshot)?;
    let output = snapshot.clone();
    // insert_snapshot validates all record/source/context and byte budgets.
    catalog.insert_snapshot(result.snapshot)?;
    Ok(output)
}

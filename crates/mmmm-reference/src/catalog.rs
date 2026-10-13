//! Catalog operations consume immutable, source-attested input. Snapshot IDs
//! cannot be reused with new content, even when environment labels are equal.

use crate::{
    query,
    snapshot::{Snapshot, SnapshotInput, text, value_cost},
    source,
};
use mmmm_contracts::{
    ContextId, ContractError, ContractValidator, JsonLimits, PrincipalId, Sha256Digest, SnapshotId,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, error::Error, fmt};

#[derive(Debug)]
pub enum CatalogError {
    Contract(ContractError),
    SchemaUnsupported(String),
    SourceUnavailable(String),
    PermissionRequired,
    SnapshotNotFound,
    SnapshotConflict,
    StaleCursor,
    InputLimit,
    Cancelled,
}

impl CatalogError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Contract(_) | Self::SchemaUnsupported(_) => "SCHEMA_UNSUPPORTED",
            Self::SourceUnavailable(_) => "SOURCE_UNAVAILABLE",
            Self::PermissionRequired => "PERMISSION_REQUIRED",
            Self::SnapshotNotFound => "SNAPSHOT_NOT_FOUND",
            Self::SnapshotConflict => "SNAPSHOT_CONFLICT",
            Self::StaleCursor => "STALE_CURSOR",
            Self::InputLimit => "INPUT_LIMIT",
            Self::Cancelled => "CANCELLED",
        }
    }
    pub(crate) fn codec(error: serde_json::Error) -> Self {
        Self::SchemaUnsupported(error.to_string())
    }
    pub(crate) fn digest(error: mmmm_contracts::DigestError) -> Self {
        Self::SchemaUnsupported(error.to_string())
    }
    pub(crate) fn id(error: mmmm_contracts::IdentityError) -> Self {
        Self::SchemaUnsupported(error.to_string())
    }
    pub(crate) fn json(error: mmmm_contracts::JsonError) -> Self {
        Self::SchemaUnsupported(error.to_string())
    }
}
impl From<ContractError> for CatalogError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}
impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(f, "{}: {error}", self.code()),
            Self::SchemaUnsupported(message) | Self::SourceUnavailable(message) => {
                write!(f, "{}: {message}", self.code())
            }
            _ => f.write_str(self.code()),
        }
    }
}
impl Error for CatalogError {}

/// Supplied by the authenticated Coordinator, never decoded from CatalogQuery.
#[derive(Clone, Debug)]
pub struct ReadPrincipal {
    pub principal_id: PrincipalId,
    /// Includes current role, permission and context authority revision.
    pub permission_scope_digest: Sha256Digest,
}

#[derive(Clone, Debug)]
pub struct SnapshotPin {
    pub snapshot: Value,
    pub revision: Sha256Digest,
    pub identity: crate::snapshot::SnapshotIdentity,
}

/// Authentication and source approval are outside the pure catalog. Cached
/// and direct reads invoke the same port. A record's scope/context labels do
/// not make it readable without the current application's authorization.
pub trait AccessControl {
    fn authorize_snapshot(
        &self,
        principal: &ReadPrincipal,
        snapshot: &Value,
    ) -> Result<(), CatalogError>;
    fn can_read_record(
        &self,
        principal: &ReadPrincipal,
        snapshot: &Value,
        record: &Value,
        context: Option<&ContextId>,
    ) -> bool;
    fn authorize_capture(
        &self,
        principal: &ReadPrincipal,
        request: &Value,
    ) -> Result<(), CatalogError>;
    fn authorize_source(
        &self,
        principal: &ReadPrincipal,
        source: &Value,
    ) -> Result<(), CatalogError>;
}

#[derive(Clone, Debug)]
pub struct CatalogLimits {
    pub max_snapshots: usize,
    pub max_records_per_snapshot: usize,
    pub max_record_bytes: usize,
    pub max_snapshot_bytes: usize,
    pub max_total_bytes: usize,
    pub max_terms_per_record: usize,
    pub max_term_bytes: usize,
    pub max_cursor_bytes: usize,
    pub max_capture_evidence_bytes: usize,
    pub max_page_bytes: usize,
    pub max_page_nodes: usize,
}
impl Default for CatalogLimits {
    fn default() -> Self {
        Self {
            max_snapshots: 16,
            max_records_per_snapshot: 10_000,
            max_record_bytes: 1024 * 1024,
            max_snapshot_bytes: 64 * 1024 * 1024,
            max_total_bytes: 128 * 1024 * 1024,
            max_terms_per_record: 64,
            max_term_bytes: 256,
            max_cursor_bytes: 4096,
            max_capture_evidence_bytes: 64 * 1024 * 1024,
            max_page_bytes: 4 * 1024 * 1024,
            max_page_nodes: 100_000,
        }
    }
}

/// The in-memory key is not serialized, logged or placed into a wire record.
/// Application startup must supply an independently generated random key.
/// Replacing the key invalidates prior continuation tokens.
pub struct Catalog {
    snapshots: BTreeMap<SnapshotId, Snapshot>,
    cursor_key: [u8; 32],
    limits: CatalogLimits,
    retained_bytes: usize,
}

impl Catalog {
    pub fn new(cursor_key: [u8; 32], limits: CatalogLimits) -> Result<Self, CatalogError> {
        if limits.max_snapshots == 0
            || limits.max_records_per_snapshot == 0
            || limits.max_record_bytes == 0
            || limits.max_snapshot_bytes == 0
            || limits.max_total_bytes == 0
            || limits.max_terms_per_record == 0
            || limits.max_term_bytes == 0
            || limits.max_cursor_bytes < 2048
            || limits.max_cursor_bytes > 16 * 1024
            || limits.max_capture_evidence_bytes == 0
            || limits.max_page_bytes == 0
            || limits.max_page_bytes > JsonLimits::default().max_bytes
            || limits.max_page_nodes == 0
            || limits.max_page_nodes > JsonLimits::default().max_nodes
        {
            return Err(CatalogError::InputLimit);
        }
        Ok(Self {
            snapshots: BTreeMap::new(),
            cursor_key,
            limits,
            retained_bytes: 0,
        })
    }

    /// Trusted source registration, not a public user-write facade. Re-inserting
    /// exactly the same immutable content is idempotent; replacement is refused.
    pub fn insert_snapshot(&mut self, input: SnapshotInput) -> Result<Sha256Digest, CatalogError> {
        let snapshot = Snapshot::build(input, &self.limits)?;
        if let Some(existing) = self.snapshots.get(&snapshot.id) {
            return if existing.revision == snapshot.revision {
                Ok(existing.revision.clone())
            } else {
                Err(CatalogError::SnapshotConflict)
            };
        }
        let retained = self
            .retained_bytes
            .checked_add(snapshot.retained_bytes)
            .ok_or(CatalogError::InputLimit)?;
        if self.snapshots.len() >= self.limits.max_snapshots
            || retained > self.limits.max_total_bytes
        {
            return Err(CatalogError::InputLimit);
        }
        let revision = snapshot.revision.clone();
        self.snapshots.insert(snapshot.id.clone(), snapshot);
        self.retained_bytes = retained;
        Ok(revision)
    }

    fn snapshot(&self, id: &SnapshotId) -> Result<&Snapshot, CatalogError> {
        self.snapshots.get(id).ok_or(CatalogError::SnapshotNotFound)
    }

    /// Internal planning inspection through the same snapshot authorization.
    /// This pin describes immutable input and does not attest the live target
    /// still has the same environment fingerprint or session epoch.
    pub fn snapshot_pin(
        &self,
        id: &SnapshotId,
        principal: &ReadPrincipal,
        access: &dyn AccessControl,
    ) -> Result<SnapshotPin, CatalogError> {
        let snapshot = self.snapshot(id)?;
        access.authorize_snapshot(principal, &snapshot.value)?;
        Ok(SnapshotPin {
            snapshot: snapshot.value.clone(),
            revision: snapshot.revision.clone(),
            identity: snapshot.identity.clone(),
        })
    }

    /// FN20. Results are deterministic exact ID → prefix → tag/type/aliases.
    /// Every result keeps its original status, value, sources and coverage.
    pub fn search(
        &self,
        input: &Value,
        principal: &ReadPrincipal,
        access: &dyn AccessControl,
    ) -> Result<Value, CatalogError> {
        let validator = ContractValidator::shared()?;
        validator.validate("CatalogQuery", input)?;
        let query: query::CatalogQuery =
            serde_json::from_value(input.clone()).map_err(CatalogError::codec)?;
        if query.locale.len() > self.limits.max_term_bytes
            || query.kinds.len() > self.limits.max_records_per_snapshot
        {
            return Err(CatalogError::InputLimit);
        }
        let snapshot = self.snapshot(&query.snapshot_id)?;
        access.authorize_snapshot(principal, &snapshot.value)?;
        if query.locale != snapshot.locale && query.cursor.is_some() {
            return Err(CatalogError::StaleCursor);
        }
        if query.locale != snapshot.locale {
            return Err(CatalogError::SourceUnavailable(
                "Requested locale does not match this immutable snapshot".into(),
            ));
        }
        let digest = query::query_digest(&query)?;
        let mut ranked = Vec::new();
        let mut restricted = false;
        for entry in &snapshot.records {
            if !access.can_read_record(principal, &snapshot.value, &entry.record, None) {
                restricted = true;
                continue;
            }
            if let Some(rank) = query::rank(&query, entry) {
                ranked.push((rank, entry));
            }
        }
        ranked.sort_by(|(rank_a, a), (rank_b, b)| {
            (
                rank_a,
                text(&a.record, "resourceId"),
                text(&a.record, "kind"),
                text(&a.record, "recordId"),
            )
                .cmp(&(
                    rank_b,
                    text(&b.record, "resourceId"),
                    text(&b.record, "kind"),
                    text(&b.record, "recordId"),
                ))
        });
        let visible = ranked.iter().map(|(_, entry)| *entry).collect::<Vec<_>>();
        let visibility = query::visibility_digest(&visible)?;
        let offset = match &query.cursor {
            None => 0,
            Some(cursor) => query::cursor_offset(
                cursor,
                &self.cursor_key,
                snapshot,
                &digest,
                principal,
                &visibility,
                self.limits.max_cursor_bytes,
            )?,
        };
        if offset > visible.len() || (query.cursor.is_some() && offset == visible.len()) {
            return Err(CatalogError::StaleCursor);
        }
        let limit = query.limit.get() as usize;
        let mut coverage = snapshot.coverage.clone();
        if restricted {
            coverage["status"] = json!("partial");
            coverage["exclusions"]
                .as_array_mut()
                .unwrap()
                .push(json!("Some records are outside the current read authority"));
        }
        // Reserve the exact coverage plus conservative fixed envelope/cursor
        // space before cloning payloads. limit is a maximum record count.
        let coverage_cost = value_cost(&coverage)?;
        let mut bytes = coverage_cost
            .bytes
            .checked_add(self.limits.max_cursor_bytes + 512)
            .ok_or(CatalogError::InputLimit)?;
        let mut nodes = coverage_cost
            .nodes
            .checked_add(8)
            .ok_or(CatalogError::InputLimit)?;
        if bytes > self.limits.max_page_bytes
            || nodes > self.limits.max_page_nodes
            || coverage_cost.depth + 1 > JsonLimits::default().max_depth
        {
            return Err(CatalogError::InputLimit);
        }
        let maximum = offset.saturating_add(limit).min(visible.len());
        let mut end = offset;
        while end < maximum {
            let cost = snapshot.record_costs[text(&visible[end].record, "recordId")];
            let next_bytes = bytes
                .checked_add(cost.bytes + 1)
                .ok_or(CatalogError::InputLimit)?;
            let next_nodes = nodes
                .checked_add(cost.nodes)
                .ok_or(CatalogError::InputLimit)?;
            if next_bytes > self.limits.max_page_bytes
                || next_nodes > self.limits.max_page_nodes
                || cost.depth + 2 > JsonLimits::default().max_depth
            {
                break;
            }
            bytes = next_bytes;
            nodes = next_nodes;
            end += 1;
        }
        if end == offset && offset < visible.len() {
            return Err(CatalogError::InputLimit);
        }
        let records = visible[offset..end]
            .iter()
            .map(|entry| entry.record.clone())
            .collect::<Vec<_>>();
        let next = if end < visible.len() {
            Some(query::create_cursor(
                &self.cursor_key,
                snapshot,
                &digest,
                principal,
                &visibility,
                end,
                self.limits.max_cursor_bytes,
            )?)
        } else {
            None
        };
        let result = json!({"snapshotId":snapshot.id,"queryDigest":digest,"records":records,
            "nextCursor":next,"coverage":coverage});
        validator.validate("CatalogPage", &result)?;
        Ok(result)
    }

    /// FN21. A context-specific source claim is required to classify a missing
    /// ID; there is no fabricated unknown provenance or zero-valued fallback.
    pub fn describe(
        &self,
        input: &Value,
        principal: &ReadPrincipal,
        access: &dyn AccessControl,
    ) -> Result<Value, CatalogError> {
        let validator = ContractValidator::shared()?;
        validator.validate("RecordQuery", input)?;
        let query: query::RecordQuery =
            serde_json::from_value(input.clone()).map_err(CatalogError::codec)?;
        let snapshot = self.snapshot(&query.snapshot_id)?;
        access.authorize_snapshot(principal, &snapshot.value)?;
        if let Some(entry) = snapshot.records.iter().find(|entry| {
            text(&entry.record, "kind") == query.kind.as_str()
                && text(&entry.record, "resourceId") == query.resource_id.as_str()
                && entry.contexts.contains(&query.context_id)
        }) {
            if !access.can_read_record(
                principal,
                &snapshot.value,
                &entry.record,
                Some(&query.context_id),
            ) {
                return Err(CatalogError::PermissionRequired);
            }
            return Ok(entry.record.clone());
        }
        let claim = snapshot
            .missing
            .get(&(query.context_id.clone(), query.kind.clone()))
            .ok_or_else(|| {
                CatalogError::SourceUnavailable(
                    "No source coverage claim exists for this kind and context".into(),
                )
            })?;
        let record = claim.to_record(&snapshot.id, query.resource_id.as_str())?;
        if !access.can_read_record(principal, &snapshot.value, &record, Some(&query.context_id)) {
            return Err(CatalogError::PermissionRequired);
        }
        validator.validate("DataRecord", &record)?;
        Ok(record)
    }

    /// FN22. Only the explicit port can access approved data or a runtime. Its
    /// actual byte evidence is verified before a new snapshot is registered.
    pub fn capture(
        &mut self,
        input: &Value,
        principal: &ReadPrincipal,
        access: &dyn AccessControl,
        port: &mut dyn source::SnapshotSource,
        control: &source::CaptureControl<'_>,
    ) -> Result<Value, CatalogError> {
        source::capture(self, input, principal, access, port, control)
    }

    pub(crate) fn limits(&self) -> &CatalogLimits {
        &self.limits
    }

    pub(crate) fn contains_snapshot(&self, id: &SnapshotId) -> bool {
        self.snapshots.contains_key(id)
    }
}

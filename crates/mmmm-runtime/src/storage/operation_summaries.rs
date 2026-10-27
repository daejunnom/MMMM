//! Small private status markers and their original CAS evidence share the same
//! operation authority, retention graph and transaction. They are not a second
//! journal and never replace original responses or effect observations.

use super::{
    BlobRef, DurableStore, StorageError, StorageResult,
    journal::{decode, encode, pin_blob},
};
use mmmm_contracts::{OperationId, Sha256Digest};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

const MAX_SUMMARY_BYTES: u64 = 65_536;
const MAX_OPERATION_ENTRIES: i64 = 4096;
const MAX_SOURCE_BLOBS: usize = 64;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryAssociation {
    summary: BlobRef,
    source_blobs: Vec<BlobRef>,
}

fn verify_retained_association(
    connection: &Connection,
    operation: &OperationId,
    association: &SummaryAssociation,
) -> StorageResult<()> {
    let refs = std::iter::once(("application_summary", &association.summary)).chain(
        association
            .source_blobs
            .iter()
            .map(|source| ("application_evidence", source)),
    );
    for (kind, blob) in refs {
        let length = i64::try_from(blob.byte_length).map_err(|_| {
            StorageError::Corrupt(
                "Operation summary source length exceeds its metadata range".into(),
            )
        })?;
        let retained: i64 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM blob_refs r JOIN blobs b ON b.digest=r.digest WHERE r.owner_kind=?1 AND r.owner_id=?2 AND r.digest=?3 AND b.byte_length=?4)",
            params![kind, operation.as_str(), blob.digest.as_str(), length],
            |row| row.get(0),
        )?;
        if retained != 1 {
            return Err(StorageError::Corrupt(
                "Operation summary/source association lost its retained pin".into(),
            ));
        }
    }
    Ok(())
}

impl DurableStore {
    /// Bounded references to retained raw evidence, without rescanning every
    /// payload. Each actual body read still verifies its CAS bytes; this lookup
    /// grants no authority and carries no proof that a changed file is intact.
    pub fn operation_evidence_refs(&self, operation: &OperationId) -> StorageResult<Vec<BlobRef>> {
        self.operation(operation)?;
        let mut statement = self.connection.prepare(
            "SELECT r.digest,b.byte_length FROM blob_refs r LEFT JOIN blobs b ON b.digest=r.digest WHERE r.owner_kind='application_evidence' AND r.owner_id=?1 ORDER BY r.digest LIMIT 4097",
        )?;
        let mut rows = statement.query([operation.as_str()])?;
        let mut refs = Vec::new();
        while let Some(row) = rows.next()? {
            if refs.len() >= MAX_OPERATION_ENTRIES as usize {
                return Err(StorageError::Corrupt(
                    "Operation evidence entry budget exceeded".into(),
                ));
            }
            let digest: String = row.get(0)?;
            let length: Option<i64> = row.get(1)?;
            let length = length.ok_or_else(|| {
                StorageError::Corrupt("Operation evidence lost its CAS metadata".into())
            })?;
            refs.push(BlobRef {
                digest: Sha256Digest::new(digest).map_err(|_| {
                    StorageError::Corrupt("Invalid retained evidence digest".into())
                })?,
                byte_length: u64::try_from(length).map_err(|_| {
                    StorageError::Corrupt("Negative retained evidence length".into())
                })?,
            });
        }
        Ok(refs)
    }

    /// Retain an operation-owned artifact such as a bounded NDJSON evidence
    /// manifest. It carries no status marker semantics and is not replayed.
    pub fn pin_operation_artifact(
        &mut self,
        operation: &OperationId,
        blob: &BlobRef,
    ) -> StorageResult<()> {
        self.operation(operation)?;
        self.cas.verify(blob)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: i64 = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM blob_refs WHERE owner_kind='operation' AND owner_id=?1 AND digest=?2)",
            params![operation.as_str(), blob.digest.as_str()], |row| row.get(0),
        )?;
        if exists == 0 {
            let count: i64 = transaction.query_row(
                "SELECT count(*) FROM blob_refs WHERE owner_kind='operation' AND owner_id=?1",
                [operation.as_str()],
                |row| row.get(0),
            )?;
            if count >= MAX_OPERATION_ENTRIES {
                return Err(StorageError::InvalidInput(
                    "Operation artifact entry budget exceeded".into(),
                ));
            }
            pin_blob(&transaction, "operation", operation.as_str(), blob)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Append a bounded private summary and atomically retain its original CAS
    /// source blobs. The application validates the marker's meaning; runtime
    /// requires exact flushed bytes and preserves the associated raw evidence.
    pub fn append_operation_summary(
        &mut self,
        operation: &OperationId,
        summary: &BlobRef,
        source_blobs: &[BlobRef],
    ) -> StorageResult<()> {
        self.operation(operation)?;
        if summary.byte_length > MAX_SUMMARY_BYTES || source_blobs.len() > MAX_SOURCE_BLOBS {
            return Err(StorageError::InvalidInput(
                "Operation summary/source budget exceeded".into(),
            ));
        }
        self.cas.verify(summary)?;
        let mut sources = source_blobs.to_vec();
        sources.sort_by(|left, right| left.digest.cmp(&right.digest));
        sources.dedup();
        for source in &sources {
            self.cas.verify(source)?;
        }
        let association = SummaryAssociation {
            summary: summary.clone(),
            source_blobs: sources,
        };
        let json = encode(&association)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<String> = transaction.query_row(
            "SELECT e.record_json FROM events e WHERE e.operation_id=?1 AND e.kind='application_summary' AND e.record_json=?2",
            params![operation.as_str(), json], |row| row.get(0),
        ).optional()?;
        if old.is_some() {
            verify_retained_association(&transaction, operation, &association)?;
            transaction.commit()?;
            return Ok(());
        }
        let summary_exists: i64 = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM blob_refs WHERE owner_kind='application_summary' AND owner_id=?1 AND digest=?2)",
            params![operation.as_str(), summary.digest.as_str()], |row| row.get(0),
        )?;
        if summary_exists == 1 {
            return Err(StorageError::Conflict(
                "Immutable operation summary/source association",
            ));
        }
        let count: i64 = transaction.query_row(
            "SELECT count(*) FROM blob_refs WHERE owner_kind='application_summary' AND owner_id=?1",
            [operation.as_str()],
            |row| row.get(0),
        )?;
        if count >= MAX_OPERATION_ENTRIES {
            return Err(StorageError::InvalidInput(
                "Operation summary entry budget exceeded".into(),
            ));
        }
        let existing_sources: i64 = transaction.query_row(
            "SELECT count(*) FROM blob_refs WHERE owner_kind='application_evidence' AND owner_id=?1",
            [operation.as_str()], |row| row.get(0),
        )?;
        let mut new_sources = 0i64;
        for source in &association.source_blobs {
            let exists: i64 = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM blob_refs WHERE owner_kind='application_evidence' AND owner_id=?1 AND digest=?2)",
                params![operation.as_str(), source.digest.as_str()], |row| row.get(0),
            )?;
            new_sources += i64::from(exists == 0);
        }
        if existing_sources + new_sources > MAX_OPERATION_ENTRIES {
            return Err(StorageError::InvalidInput(
                "Operation evidence entry budget exceeded".into(),
            ));
        }
        for source in &association.source_blobs {
            pin_blob(
                &transaction,
                "application_evidence",
                operation.as_str(),
                source,
            )?;
        }
        pin_blob(
            &transaction,
            "application_summary",
            operation.as_str(),
            summary,
        )?;
        transaction.execute(
            "INSERT INTO events(operation_id,kind,record_json) VALUES(?1,'application_summary',?2)",
            params![operation.as_str(), json],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Ordered marker references only; never parse or inline original provider
    /// bodies. Actual marker bytes are checked when consumed through read_blob.
    pub fn operation_summaries(&self, operation: &OperationId) -> StorageResult<Vec<BlobRef>> {
        self.operation(operation)?;
        let mut statement = self.connection.prepare(
            "SELECT record_json FROM events WHERE operation_id=?1 AND kind='application_summary' ORDER BY sequence LIMIT 4097",
        )?;
        let mut rows = statement.query([operation.as_str()])?;
        let mut summaries = Vec::new();
        while let Some(row) = rows.next()? {
            if summaries.len() >= MAX_OPERATION_ENTRIES as usize {
                return Err(StorageError::Corrupt(
                    "Operation summary entry budget exceeded".into(),
                ));
            }
            let json: String = row.get(0)?;
            if json.len() > 32_768 {
                return Err(StorageError::Corrupt(
                    "Operation summary association budget exceeded".into(),
                ));
            }
            let association: SummaryAssociation = decode(&json)?;
            if association.summary.byte_length > MAX_SUMMARY_BYTES
                || association.source_blobs.len() > MAX_SOURCE_BLOBS
            {
                return Err(StorageError::Corrupt(
                    "Operation summary association exceeds its limits".into(),
                ));
            }
            verify_retained_association(&self.connection, operation, &association)?;
            summaries.push(association.summary);
        }
        Ok(summaries)
    }
}

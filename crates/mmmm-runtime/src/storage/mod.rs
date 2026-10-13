//! Durable local state for one Coordinator. The caller remains responsible for
//! authentication, grants, expiry, live preconditions and independent observers.
//! None of these methods invokes a provider or automatically replays a write.

mod cas;
mod journal;
mod records;
mod types;

pub use types::*;

use cas::{Cas, create_private_dir, verify_local_filesystem, verify_plain_path};
use mmmm_contracts::{ContractValidator, Sha256Digest};
use rusqlite::{Connection, OpenFlags};
use std::{fs::{File, OpenOptions}, path::Path, time::Duration};

pub struct DurableStore {
    // Connection is dropped before the lock, so another Coordinator cannot
    // acquire the root while this connection is still closing its WAL.
    pub(crate) connection: Connection,
    pub(crate) cas: Cas,
    pub(crate) validator: ContractValidator,
    _lock: File,
}

impl DurableStore {
    pub fn open(config: StoreConfig) -> StorageResult<Self> {
        verify_plain_path(&config.data_root)?;
        create_private_dir(&config.data_root)?;
        verify_local_filesystem(&config.data_root)?;
        let lock_path = config.data_root.join("coordinator.lock");
        verify_plain_path(&lock_path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let lock = options.open(lock_path)?;
        match lock.try_lock() {
            Ok(()) => (),
            Err(std::fs::TryLockError::WouldBlock) => return Err(StorageError::Busy),
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
        let database = config.data_root.join("journal.sqlite3");
        verify_plain_path(&database)?;
        verify_plain_path(&config.data_root.join("journal.sqlite3-wal"))?;
        verify_plain_path(&config.data_root.join("journal.sqlite3-shm"))?;
        if !database.exists() { drop(cas::private_new_file(&database)?); }
        if !std::fs::metadata(&database)?.is_file() { return Err(StorageError::UnsafePath); }
        // No URI filename processing, extension loading, remote SQLite driver,
        // or secondary journal backend is enabled.
        let connection = Connection::open_with_flags(database,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        connection.busy_timeout(Duration::from_secs(2))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;
        let foreign_keys: i64 = connection.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
        let journal: String = connection.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
        let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |r| r.get(0))?;
        if foreign_keys != 1 || journal.to_lowercase() != "wal" || synchronous != 2 {
            return Err(StorageError::Corrupt("Required SQLite durability pragmas were not applied".into()));
        }
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let application: i64 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        if !matches!(version, 0|1) { return Err(StorageError::Corrupt("Unsupported durable journal schema version".into())); }
        if (version==1 && application!=0x4d4d4d4d) || (version==0 && application!=0) {
            return Err(StorageError::Corrupt("SQLite file is not an MMMM durable journal".into()));
        }
        if version==0 {
            let tables:i64=connection.query_row("SELECT count(*) FROM sqlite_master WHERE type='table'",[],|r|r.get(0))?;
            if tables!=0 { return Err(StorageError::Corrupt("Refusing to adopt a populated unversioned database".into())); }
        }
        let quick: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
        if quick != "ok" { return Err(StorageError::Corrupt("SQLite quick_check failed".into())); }
        connection.execute_batch(journal::SCHEMA)?;
        let cas = Cas::open(config.data_root.join("blobs"), config.max_blob_bytes)?;
        let validator = ContractValidator::embedded().map_err(|e| StorageError::Contract(e.to_string()))?;
        let mut store = Self { connection, cas, validator, _lock: lock };
        // A persisted intent is ambiguous after restart even if its later sent
        // record is absent. Reconciliation is recorded, never retransmission.
        store.recover_interrupted_dispatches()?;
        Ok(store)
    }

    pub fn data_root(&self) -> &Path { self.cas.root.parent().expect("CAS always has a data root") }

    /// Internal authorized callers must establish artifact/project access before
    /// returning these bytes to a transport. Digest knowledge grants no authority.
    pub fn put_blob(&self, bytes: &[u8]) -> StorageResult<BlobRef> { self.cas.put(bytes) }
    pub fn read_blob(&self, blob: &BlobRef) -> StorageResult<Vec<u8>> { self.cas.read(blob) }
    pub fn verify_blob(&self, blob: &BlobRef) -> StorageResult<()> { self.cas.verify(blob) }

    /// Collection executes under the single-root lock and the mutable store
    /// borrow. All document, operation and recovery references remain pinned.
    pub fn collect_orphan_blobs(&mut self, max_entries: usize) -> StorageResult<GcReport> {
        let mut statement = self.connection.prepare("SELECT digest FROM blob_refs UNION SELECT blob_digest FROM documents")?;
        let strings = statement.query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut keep = std::collections::BTreeSet::new();
        for text in strings {
            keep.insert(Sha256Digest::new(text).map_err(|e| StorageError::Corrupt(e.to_string()))?);
        }
        drop(statement);
        let report = self.cas.collect(&keep, max_entries)?;
        // Metadata for unreferenced deleted blobs carries no effect evidence.
        self.connection.execute("DELETE FROM blobs WHERE digest NOT IN (SELECT digest FROM blob_refs) AND digest NOT IN (SELECT blob_digest FROM documents)", [])?;
        Ok(report)
    }
}

#[cfg(test)]
mod tests;

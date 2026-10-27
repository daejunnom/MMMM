//! Immutable authoring documents are issued from an actually stored Project
//! revision. A document pin identifies content; it does not grant access. No
//! caller-supplied path, URI, document body or policy claim is used during reads.

use super::{
    BlobRef, DurableStore, StorageError, StorageResult, journal::pin_blob,
    project_resources::ProjectSourceRpcContext,
};
use mmmm_contracts::strict_json::{ControlledJsonError, parse_json_with_control};
use mmmm_contracts::{
    ContextId, JsonLimits, ObjectId, PrincipalId, ProjectId, Sha256Digest, canonical_digest,
    encode_json, parse_json_with_limits, verify_projected_digest,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// This is the existing strict-JSON storage ceiling, not a new wire format.
pub const MAX_OWNED_DOCUMENT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_OWNED_DOCUMENTS_PER_PROJECT: usize = 4096;

const REGISTRY_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS owned_documents (
    project_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('prefab','instance','command_module','clip','asset','physics_definition')),
    object_id TEXT NOT NULL,
    revision TEXT NOT NULL CHECK(length(revision)=64),
    blob_digest TEXT NOT NULL REFERENCES blobs(digest),
    byte_length INTEGER NOT NULL CHECK(byte_length>0 AND byte_length<=8388608),
    PRIMARY KEY(project_id,kind,object_id,revision)
) STRICT;
CREATE TABLE IF NOT EXISTS owned_document_provenance (
    project_id TEXT NOT NULL,
    project_revision TEXT NOT NULL,
    kind TEXT NOT NULL,
    object_id TEXT NOT NULL,
    revision TEXT NOT NULL,
    project_definition TEXT NOT NULL DEFAULT 'Project' CHECK(project_definition='Project'),
    PRIMARY KEY(project_id,project_revision,kind,object_id),
    FOREIGN KEY(project_id,kind,object_id,revision)
        REFERENCES owned_documents(project_id,kind,object_id,revision),
    FOREIGN KEY(project_definition,project_id,project_revision)
        REFERENCES documents(definition,document_id,content_hash)
) STRICT;";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OwnedDocumentKind {
    #[serde(rename = "prefab")]
    Prefab,
    #[serde(rename = "instance")]
    Instance,
    #[serde(rename = "command_module")]
    CommandModule,
    #[serde(rename = "clip")]
    AnimationClip,
    #[serde(rename = "asset")]
    Asset,
    #[serde(rename = "physics_definition")]
    PhysicsDefinition,
}
impl OwnedDocumentKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prefab => "prefab",
            Self::Instance => "instance",
            Self::CommandModule => "command_module",
            Self::AnimationClip => "clip",
            Self::Asset => "asset",
            Self::PhysicsDefinition => "physics_definition",
        }
    }
    pub const fn definition(self) -> &'static str {
        match self {
            Self::Prefab => "Prefab",
            Self::Instance => "Instance",
            Self::CommandModule => "CommandModule",
            Self::AnimationClip => "AnimationClip",
            Self::Asset => "Asset",
            Self::PhysicsDefinition => "PhysicsDefinition",
        }
    }
    pub const fn identity_field(self) -> &'static str {
        match self {
            Self::Prefab => "prefabId",
            Self::Instance => "instanceId",
            Self::CommandModule => "moduleId",
            Self::AnimationClip => "clipId",
            Self::Asset => "assetId",
            Self::PhysicsDefinition => "physicsId",
        }
    }
}

/// Internal representation of Project.ownedResources, using its exact names.
/// This does not introduce another public DTO or another schema authority.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnedDocumentPin {
    pub kind: OwnedDocumentKind,
    pub object_id: ObjectId,
    pub revision: Sha256Digest,
}

/// The document and exact original bytes come from one bounded, verified CAS
/// read. The blob digest identifies those bytes, not their JCS reserialization.
#[derive(Debug)]
pub struct OwnedDocumentBytes {
    pub document: Value,
    pub bytes: Vec<u8>,
    pub blob: BlobRef,
}

/// Trusted composition registers canonical source, never a public write RPC.
/// Historical ownership must already be present in the actual Project ledger.
pub fn register_owned_document(
    store: &mut DurableStore,
    project: &ProjectId,
    project_revision: &Sha256Digest,
    pin: &OwnedDocumentPin,
    document: &Value,
) -> StorageResult<()> {
    // Use the existing historical Project authority, not the current mutable
    // head and not a caller-supplied copy of Project.ownedResources.
    let stored_project = store.project_revision(project, project_revision)?;
    validate_owned_membership(&stored_project, pin)?;
    let bytes = validate_document(store, pin, document, false)?;
    let blob = store.cas.put(&bytes)?;
    // Keep the existing public API's encode_json bytes. The transaction helper
    // also accepts original raw bytes already placed in CAS by native ingress.
    let transaction =
        Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate)?;
    register_owned_document_blob_in(
        store,
        &transaction,
        project,
        project_revision,
        pin,
        &blob,
        &mut || Ok(()),
    )?;
    transaction.commit()?;
    Ok(())
}

/// One existing transaction owns history, immutable raw CAS association and
/// retention. This helper never commits or opens another transaction. The
/// surrounding writer must authorize current Store/Project/source access and
/// fences. A BlobRef alone supplies no ownership: actual historical Project
/// membership and strict raw CAS bytes are checked here before registration.
pub(crate) fn register_owned_document_blob_in<F>(
    store: &DurableStore,
    transaction: &Transaction<'_>,
    project: &ProjectId,
    project_revision: &Sha256Digest,
    pin: &OwnedDocumentPin,
    blob: &BlobRef,
    check: &mut F,
) -> StorageResult<()>
where
    F: FnMut() -> StorageResult<()>,
{
    check()?;
    if !std::ptr::eq(&**transaction, &store.connection) {
        return Err(StorageError::Conflict(
            "Owned source transaction belongs to another Store",
        ));
    }
    if blob.byte_length == 0 || blob.byte_length > MAX_OWNED_DOCUMENT_BYTES {
        return Err(StorageError::InvalidInput(
            "Owned document raw CAS byte budget".into(),
        ));
    }
    let stored_project = load_project_revision_checked(store, project, project_revision, check)?;
    validate_owned_membership(&stored_project, pin)?;
    let raw = store
        .cas
        .read_verified_document(blob, MAX_OWNED_DOCUMENT_BYTES, &mut *check)?;
    let document =
        parse_json_with_control(&raw, JsonLimits::default(), &mut *check).map_err(|cause| {
            match cause {
                ControlledJsonError::Control(cause) => cause,
                ControlledJsonError::Json(cause) => StorageError::Contract(cause.to_string()),
            }
        })?;
    validate_document(store, pin, &document, false)?;
    check()?;
    let owner = canonical_digest(&json!({
        "projectId":project,"kind":pin.kind,"objectId":pin.object_id,"revision":pin.revision,
    }))
    .map_err(|e| StorageError::Contract(e.to_string()))?;
    transaction.execute_batch(REGISTRY_SCHEMA)?;
    let old: Option<(String, i64)> = transaction.query_row(
        "SELECT blob_digest,byte_length FROM owned_documents WHERE project_id=?1 AND kind=?2 AND object_id=?3 AND revision=?4",
        params![project.as_str(), pin.kind.as_str(), pin.object_id.as_str(), pin.revision.as_str()],
        |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional()?;
    if let Some((digest, length)) = &old {
        if digest != blob.digest.as_str() || u64::try_from(*length).ok() != Some(blob.byte_length) {
            return Err(StorageError::Conflict("Immutable owned-document pin"));
        }
    } else {
        let count: i64 = transaction.query_row(
            "SELECT count(*) FROM owned_documents WHERE project_id=?1",
            [project.as_str()],
            |row| row.get(0),
        )?;
        if count >= MAX_OWNED_DOCUMENTS_PER_PROJECT as i64 {
            return Err(StorageError::InvalidInput(
                "Owned-document project capacity is exhausted".into(),
            ));
        }
    }
    let prior: Option<String> = transaction.query_row(
        "SELECT revision FROM owned_document_provenance WHERE project_id=?1 AND project_revision=?2 AND kind=?3 AND object_id=?4",
        params![project.as_str(), project_revision.as_str(), pin.kind.as_str(), pin.object_id.as_str()],
        |row| row.get(0),
    ).optional()?;
    if prior
        .as_ref()
        .is_some_and(|revision| revision != pin.revision.as_str())
    {
        return Err(StorageError::Conflict(
            "Immutable owned-document provenance",
        ));
    }
    pin_blob(transaction, "owned_document", owner.as_str(), blob)?;
    transaction.execute(
        "INSERT OR IGNORE INTO owned_documents(project_id,kind,object_id,revision,blob_digest,byte_length) VALUES(?1,?2,?3,?4,?5,?6)",
        params![project.as_str(), pin.kind.as_str(), pin.object_id.as_str(), pin.revision.as_str(), blob.digest.as_str(), blob.byte_length as i64],
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO owned_document_provenance(project_id,project_revision,kind,object_id,revision) VALUES(?1,?2,?3,?4,?5)",
        params![project.as_str(), project_revision.as_str(), pin.kind.as_str(), pin.object_id.as_str(), pin.revision.as_str()],
    )?;
    check()?;
    Ok(())
}

/// Internal reads verify historical provenance. The caller must separately
/// authorize current project/context access, or compose OwnedDocumentReader.
pub fn read_owned_document(
    store: &DurableStore,
    project: &ProjectId,
    project_revision: &Sha256Digest,
    pin: &OwnedDocumentPin,
) -> StorageResult<Value> {
    let mut check = || Ok(());
    let stored_project =
        load_project_revision_checked(store, project, project_revision, &mut check)?;
    validate_owned_membership(&stored_project, pin)?;
    load_owned_document_checked(
        store,
        project,
        project_revision,
        pin,
        MAX_OWNED_DOCUMENT_BYTES,
        &mut check,
    )
    .map(|loaded| loaded.document)
}

/// Implemented by the Coordinator with an opaque authenticated principal and
/// its per-request cancellation/deadline/session-generation checks. Identifiers
/// supplied in wire JSON do not construct this authority.
pub trait OwnedDocumentRpcContext {
    fn check(&self) -> StorageResult<()>;
    fn principal_for_context(&self, context: &ContextId) -> StorageResult<PrincipalId>;
}

/// Reload current context/project/document ACL at admission and return. The
/// historical Project proves source membership, not current execution rights.
pub trait OwnedDocumentAuthority {
    fn authorize_read(
        &mut self,
        principal: &PrincipalId,
        context: &ContextId,
        project: &ProjectId,
        project_revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> StorageResult<()>;

    /// Source inspection may be authenticated without a live game context.
    /// Existing context-bound implementations retain their old behavior;
    /// offline access needs a concrete current Project ACL implementation.
    fn authorize_project_read(
        &mut self,
        principal: &PrincipalId,
        context: Option<&ContextId>,
        project: &ProjectId,
        project_revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> StorageResult<()> {
        match context {
            Some(context) => {
                self.authorize_read(principal, context, project, project_revision, pin)
            }
            None => Err(StorageError::InvalidTransition(
                "Offline document source access requires current Project authorization".into(),
            )),
        }
    }
}

pub struct OwnedDocumentReader {
    authority: Box<dyn OwnedDocumentAuthority>,
    max_document_bytes: u64,
}
impl OwnedDocumentReader {
    pub fn new(
        authority: Box<dyn OwnedDocumentAuthority>,
        max_document_bytes: u64,
    ) -> StorageResult<Self> {
        if max_document_bytes == 0 || max_document_bytes > MAX_OWNED_DOCUMENT_BYTES {
            return Err(StorageError::InvalidInput(
                "Owned-document byte budget is invalid".into(),
            ));
        }
        Ok(Self {
            authority,
            max_document_bytes,
        })
    }

    pub fn read(
        &mut self,
        store: &DurableStore,
        rpc: &dyn OwnedDocumentRpcContext,
        context: &ContextId,
        project: &ProjectId,
        project_revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> StorageResult<Value> {
        rpc.check()?;
        let principal = rpc.principal_for_context(context)?;
        self.authority
            .authorize_read(&principal, context, project, project_revision, pin)?;
        rpc.check()?;
        let mut check = || rpc.check();
        let stored_project =
            load_project_revision_checked(store, project, project_revision, &mut check)?;
        validate_owned_membership(&stored_project, pin)?;
        let document = load_owned_document_checked(
            store,
            project,
            project_revision,
            pin,
            self.max_document_bytes,
            &mut check,
        )?;
        rpc.check()?;
        if rpc.principal_for_context(context)? != principal {
            return Err(StorageError::Conflict(
                "Owned-document authenticated context changed",
            ));
        }
        self.authority
            .authorize_read(&principal, context, project, project_revision, pin)?;
        rpc.check()?;
        Ok(document.document)
    }

    /// Resolve an exact immutable pin through registered historical provenance,
    /// after proving the object identity is still owned by this actual current
    /// Project. A historical digest or historical membership grants no current
    /// access. The authenticated source context may be offline; no game context
    /// is fabricated. Repeated valid provenance is normal and selected stably.
    pub fn read_known_history(
        &mut self,
        store: &DurableStore,
        rpc: &dyn ProjectSourceRpcContext,
        project: &ProjectId,
        current_project_revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> StorageResult<Value> {
        self.read_known_history_bytes(store, rpc, project, current_project_revision, pin)
            .map(|loaded| loaded.document)
    }

    /// Return the exact retained source bytes and their raw SHA pin together
    /// with the document parsed from those same bytes. This shares all current
    /// and historical ownership, configured byte ceiling and final ACL checks.
    pub fn read_known_history_bytes(
        &mut self,
        store: &DurableStore,
        rpc: &dyn ProjectSourceRpcContext,
        project: &ProjectId,
        current_project_revision: &Sha256Digest,
        pin: &OwnedDocumentPin,
    ) -> StorageResult<OwnedDocumentBytes> {
        rpc.check()?;
        let principal = rpc.authenticated_principal()?;
        let context = rpc.context_id().cloned();
        self.authority.authorize_project_read(
            &principal,
            context.as_ref(),
            project,
            current_project_revision,
            pin,
        )?;
        rpc.check()?;
        verify_current_project_head(store, project, current_project_revision)?;
        let mut check = || rpc.check();
        let current_project =
            load_project_revision_checked(store, project, current_project_revision, &mut check)?;
        validate_owned_presence(&current_project, pin, false)?;
        let historical_revision = find_registered_history(store, project, pin, &mut check)?;
        let historical_project =
            load_project_revision_checked(store, project, &historical_revision, &mut check)?;
        validate_owned_membership(&historical_project, pin)?;
        let document = load_owned_document_checked(
            store,
            project,
            &historical_revision,
            pin,
            self.max_document_bytes,
            &mut check,
        )?;
        rpc.check()?;
        if rpc.authenticated_principal()? != principal || rpc.context_id() != context.as_ref() {
            return Err(StorageError::Conflict(
                "Document source authenticated request changed",
            ));
        }
        verify_current_project_head(store, project, current_project_revision)?;
        self.authority.authorize_project_read(
            &principal,
            context.as_ref(),
            project,
            current_project_revision,
            pin,
        )?;
        rpc.check()?;
        if rpc.authenticated_principal()? != principal || rpc.context_id() != context.as_ref() {
            return Err(StorageError::Conflict(
                "Document source authenticated request changed",
            ));
        }
        verify_current_project_head(store, project, current_project_revision)?;
        Ok(document)
    }
}

fn validate_owned_membership(project: &Value, requested: &OwnedDocumentPin) -> StorageResult<()> {
    validate_owned_presence(project, requested, true)
}

fn validate_owned_presence(
    project: &Value,
    requested: &OwnedDocumentPin,
    exact_revision: bool,
) -> StorageResult<()> {
    let entries = project["ownedResources"].as_array().ok_or_else(|| {
        StorageError::Corrupt("Stored Project has no ownedResources array".into())
    })?;
    if entries.len() > MAX_OWNED_DOCUMENTS_PER_PROJECT {
        return Err(StorageError::InvalidInput(
            "Project ownership entry budget exceeded".into(),
        ));
    }
    let mut identities = BTreeSet::new();
    let mut present = false;
    for entry in entries {
        let pin: OwnedDocumentPin = serde_json::from_value(entry.clone())
            .map_err(|e| StorageError::Corrupt(e.to_string()))?;
        if !identities.insert((pin.kind, pin.object_id.clone())) {
            return Err(StorageError::Corrupt(
                "Project repeats an owned-document identity".into(),
            ));
        }
        present |= pin.kind == requested.kind
            && pin.object_id == requested.object_id
            && (!exact_revision || pin.revision == requested.revision);
    }
    if !present {
        return Err(StorageError::Conflict(
            "Document pin is not owned by this Project revision",
        ));
    }
    Ok(())
}

fn verify_current_project_head(
    store: &DurableStore,
    project: &ProjectId,
    revision: &Sha256Digest,
) -> StorageResult<()> {
    let row: Option<(String, String, Option<String>)> = store.connection.query_row(
        "SELECT h.revision,h.blob_digest,d.blob_digest FROM project_heads h LEFT JOIN documents d ON d.definition='Project' AND d.document_id=h.project_id AND d.content_hash=?2 WHERE h.project_id=?1",
        params![project.as_str(), revision.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).optional()?;
    let (actual, head_blob, historical_blob) =
        row.ok_or(StorageError::NotFound("Current Project"))?;
    if actual != revision.as_str() || historical_blob.as_deref() != Some(head_blob.as_str()) {
        return Err(StorageError::Conflict("Current Project source revision"));
    }
    Ok(())
}

fn find_registered_history<F>(
    store: &DurableStore,
    project: &ProjectId,
    pin: &OwnedDocumentPin,
    check: &mut F,
) -> StorageResult<Sha256Digest>
where
    F: FnMut() -> StorageResult<()>,
{
    check()?;
    let tables: i64 = store.connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('owned_documents','owned_document_provenance')",
        [], |row| row.get(0),
    )?;
    if tables == 0 {
        return Err(StorageError::NotFound("Owned-document history"));
    }
    if tables != 2 {
        return Err(StorageError::Corrupt(
            "Owned-document registry is incomplete".into(),
        ));
    }
    let mut statement = store.connection.prepare(
        "SELECT substr(p.project_revision,1,65) FROM owned_document_provenance p JOIN owned_documents d ON d.project_id=p.project_id AND d.kind=p.kind AND d.object_id=p.object_id AND d.revision=p.revision WHERE p.project_id=?1 AND p.kind=?2 AND p.object_id=?3 AND p.revision=?4 AND p.project_definition='Project' ORDER BY p.project_revision LIMIT 4097",
    )?;
    let rows = statement.query_map(
        params![
            project.as_str(),
            pin.kind.as_str(),
            pin.object_id.as_str(),
            pin.revision.as_str()
        ],
        |row| row.get::<_, String>(0),
    )?;
    let mut selected = None;
    for (index, row) in rows.enumerate() {
        check()?;
        if index >= MAX_OWNED_DOCUMENTS_PER_PROJECT {
            return Err(StorageError::InvalidInput(
                "Owned-document history candidate budget exceeded".into(),
            ));
        }
        let revision = Sha256Digest::new(row?).map_err(|e| StorageError::Corrupt(e.to_string()))?;
        if selected.is_none() {
            selected = Some(revision);
        }
    }
    check()?;
    // The first indexed historical Project is checked against its actual bytes.
    // A corrupt candidate is an error, never silently skipped to another one.
    selected.ok_or(StorageError::NotFound(
        "Registered exact owned-document history",
    ))
}

pub(crate) fn validate_document(
    store: &DurableStore,
    pin: &OwnedDocumentPin,
    document: &Value,
    stored: bool,
) -> StorageResult<Vec<u8>> {
    let invalid = |message: String| {
        if stored {
            StorageError::Corrupt(message)
        } else {
            StorageError::Contract(message)
        }
    };
    let bytes = encode_json(document).map_err(|e| invalid(e.to_string()))?;
    if bytes.len() as u64 > MAX_OWNED_DOCUMENT_BYTES {
        return Err(StorageError::InvalidInput(
            "Owned document exceeds its JSON byte budget".into(),
        ));
    }
    store
        .validator
        .validate(pin.kind.definition(), document)
        .map_err(|e| invalid(e.to_string()))?;
    let actual = verify_projected_digest(pin.kind.definition(), document)
        .map_err(|e| invalid(e.to_string()))?;
    if document[pin.kind.identity_field()] != pin.object_id.as_str() || actual != pin.revision {
        return Err(invalid(
            "Owned document differs from its canonical identity/revision pin".into(),
        ));
    }
    Ok(bytes)
}

fn load_project_revision_checked<F>(
    store: &DurableStore,
    project: &ProjectId,
    revision: &Sha256Digest,
    check: &mut F,
) -> StorageResult<Value>
where
    F: FnMut() -> StorageResult<()>,
{
    check()?;
    let row: Option<(String, i64)> = store.connection.query_row(
        "SELECT d.blob_digest,b.byte_length FROM documents d JOIN blobs b ON b.digest=d.blob_digest WHERE d.definition='Project' AND d.document_id=?1 AND d.content_hash=?2",
        params![project.as_str(), revision.as_str()], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    let blob = blob_from_row(row.ok_or(StorageError::NotFound("Project revision"))?)?;
    let bytes = store
        .cas
        .read_verified_document(&blob, MAX_OWNED_DOCUMENT_BYTES, &mut *check)?;
    let value = parse_json_with_limits(&bytes, JsonLimits::default())
        .map_err(|e| StorageError::Corrupt(e.to_string()))?;
    store
        .validator
        .validate("Project", &value)
        .map_err(|e| StorageError::Corrupt(e.to_string()))?;
    let actual = verify_projected_digest("Project", &value)
        .map_err(|e| StorageError::Corrupt(e.to_string()))?;
    if &actual != revision || value["projectId"] != project.as_str() {
        return Err(StorageError::Corrupt(
            "Stored Project differs from its historical identity/revision".into(),
        ));
    }
    check()?;
    Ok(value)
}

fn load_owned_document_checked<F>(
    store: &DurableStore,
    project: &ProjectId,
    project_revision: &Sha256Digest,
    pin: &OwnedDocumentPin,
    max_bytes: u64,
    check: &mut F,
) -> StorageResult<OwnedDocumentBytes>
where
    F: FnMut() -> StorageResult<()>,
{
    check()?;
    let tables: i64 = store.connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('owned_documents','owned_document_provenance')",
        [], |row| row.get(0),
    )?;
    if tables == 0 {
        return Err(StorageError::NotFound("Owned document"));
    }
    if tables != 2 {
        return Err(StorageError::Corrupt(
            "Owned-document registry is incomplete".into(),
        ));
    }
    let row: Option<(String, i64)> = store.connection.query_row(
        "SELECT d.blob_digest,d.byte_length FROM owned_documents d JOIN owned_document_provenance p ON p.project_id=d.project_id AND p.kind=d.kind AND p.object_id=d.object_id AND p.revision=d.revision WHERE d.project_id=?1 AND p.project_revision=?2 AND d.kind=?3 AND d.object_id=?4 AND d.revision=?5 AND p.project_definition='Project'",
        params![project.as_str(), project_revision.as_str(), pin.kind.as_str(), pin.object_id.as_str(), pin.revision.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    let blob = blob_from_row(row.ok_or(StorageError::NotFound("Owned document provenance"))?)?;
    let indexed_length: Option<i64> = store
        .connection
        .query_row(
            "SELECT byte_length FROM blobs WHERE digest=?1",
            [blob.digest.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    if indexed_length.and_then(|length| u64::try_from(length).ok()) != Some(blob.byte_length) {
        return Err(StorageError::Corrupt(
            "Owned document disagrees with its CAS metadata index".into(),
        ));
    }
    let bytes = store
        .cas
        .read_verified_document(&blob, max_bytes, &mut *check)?;
    let value = parse_json_with_limits(&bytes, JsonLimits::default())
        .map_err(|e| StorageError::Corrupt(e.to_string()))?;
    validate_document(store, pin, &value, true)?;
    check()?;
    Ok(OwnedDocumentBytes {
        document: value,
        bytes,
        blob,
    })
}

fn blob_from_row((digest, length): (String, i64)) -> StorageResult<BlobRef> {
    let byte_length = u64::try_from(length)
        .map_err(|_| StorageError::Corrupt("Owned document has negative byte length".into()))?;
    if byte_length == 0 || byte_length > MAX_OWNED_DOCUMENT_BYTES {
        return Err(StorageError::Corrupt(
            "Owned document exceeds its stored byte bound".into(),
        ));
    }
    Ok(BlobRef {
        digest: Sha256Digest::new(digest).map_err(|e| StorageError::Corrupt(e.to_string()))?,
        byte_length,
    })
}

#[cfg(test)]
#[path = "owned_documents_tests.rs"]
mod tests;

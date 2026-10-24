use super::journal::{decode, encode, pin_blob, register_blob};
use super::*;
use mmmm_contracts::{
    OperationId, PlanId, ProjectId, Sha256Digest, encode_json, verify_projected_digest,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::Value;

impl DurableStore {
    pub fn save_plan(&mut self, plan: &Value) -> StorageResult<BlobRef> {
        self.validator
            .validate("ExecutionPlan", plan)
            .map_err(|e| StorageError::Contract(e.to_string()))?;
        let hash = verify_projected_digest("ExecutionPlan", plan)
            .map_err(|e| StorageError::Contract(e.to_string()))?;
        let id: PlanId = serde_json::from_value(plan["planId"].clone())
            .map_err(|e| StorageError::Contract(e.to_string()))?;
        let scope: WriteScope = serde_json::from_value(plan["scope"].clone())
            .map_err(|e| StorageError::Contract(e.to_string()))?;
        scope.validate()?;
        if plan["projectId"] != scope.project_id.as_str() {
            return Err(StorageError::Conflict("Plan scope project"));
        }
        let blob = self
            .cas
            .put(&encode_json(plan).map_err(|e| StorageError::Contract(e.to_string()))?)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old:Option<String>=transaction.query_row("SELECT content_hash FROM documents WHERE definition='ExecutionPlan' AND document_id=?1 LIMIT 1",[id.as_str()],|r|r.get(0)).optional()?;
        if old.as_ref().is_some_and(|old| old != hash.as_str()) {
            return Err(StorageError::Conflict("Immutable plan ID"));
        }
        register_blob(&transaction, &blob)?;
        transaction.execute("INSERT OR IGNORE INTO documents(definition,document_id,content_hash,blob_digest) VALUES('ExecutionPlan',?1,?2,?3)",params![id.as_str(),hash.as_str(),blob.digest.as_str()])?;
        transaction.commit()?;
        Ok(blob)
    }

    pub fn plan(&self, id: &PlanId, hash: &Sha256Digest) -> StorageResult<Value> {
        Self::load_plan_in(&self.connection, &self.cas, id, hash)
    }

    /// The immutable ID resolves one frozen plan. Authorization remains with the
    /// caller; possessing a plan ID does not grant access to its contents.
    pub fn plan_by_id(&self, id: &PlanId) -> StorageResult<Value> {
        let mut statement = self.connection.prepare(
            "SELECT content_hash FROM documents WHERE definition='ExecutionPlan' AND document_id=?1 ORDER BY content_hash LIMIT 2",
        )?;
        let hashes = statement
            .query_map([id.as_str()], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let [hash] = hashes.as_slice() else {
            return if hashes.is_empty() {
                Err(StorageError::NotFound("Execution plan"))
            } else {
                Err(StorageError::Corrupt(
                    "Immutable plan ID has multiple indexed hashes".into(),
                ))
            };
        };
        let hash =
            Sha256Digest::new(hash.clone()).map_err(|e| StorageError::Corrupt(e.to_string()))?;
        let value = Self::load_plan_in(&self.connection, &self.cas, id, &hash)?;
        self.validator
            .validate("ExecutionPlan", &value)
            .map_err(|e| StorageError::Corrupt(e.to_string()))?;
        Ok(value)
    }
    pub(crate) fn load_plan_in(
        connection: &Connection,
        cas: &super::cas::Cas,
        id: &PlanId,
        hash: &Sha256Digest,
    ) -> StorageResult<Value> {
        let row:Option<(String,i64)>=connection.query_row(
            "SELECT d.blob_digest,b.byte_length FROM documents d JOIN blobs b ON b.digest=d.blob_digest WHERE d.definition='ExecutionPlan' AND d.document_id=?1 AND d.content_hash=?2",
            params![id.as_str(),hash.as_str()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (digest, length) = row.ok_or(StorageError::NotFound("Execution plan"))?;
        let blob = BlobRef {
            digest: Sha256Digest::new(digest).map_err(|e| StorageError::Corrupt(e.to_string()))?,
            byte_length: length as u64,
        };
        let value = mmmm_contracts::parse_json(&cas.read(&blob)?)
            .map_err(|e| StorageError::Corrupt(e.to_string()))?;
        let actual = verify_projected_digest("ExecutionPlan", &value)
            .map_err(|e| StorageError::Corrupt(e.to_string()))?;
        if &actual != hash || value["planId"] != id.as_str() {
            return Err(StorageError::Corrupt(
                "Stored plan hash differs from its journal identity".into(),
            ));
        }
        Ok(value)
    }

    /// Optimistic revision protects stored project edits; it is unrelated to
    /// external world side effects, which need their own plan and readback.
    pub fn save_project(
        &mut self,
        project: &Value,
        expected_revision: Option<&Sha256Digest>,
    ) -> StorageResult<BlobRef> {
        self.validator
            .validate("Project", project)
            .map_err(|e| StorageError::Contract(e.to_string()))?;
        let revision = verify_projected_digest("Project", project)
            .map_err(|e| StorageError::Contract(e.to_string()))?;
        let id: ProjectId = serde_json::from_value(project["projectId"].clone())
            .map_err(|e| StorageError::Contract(e.to_string()))?;
        let blob = self
            .cas
            .put(&encode_json(project).map_err(|e| StorageError::Contract(e.to_string()))?)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<String> = transaction
            .query_row(
                "SELECT revision FROM project_heads WHERE project_id=?1",
                [id.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        if old.as_deref() != expected_revision.map(Sha256Digest::as_str) {
            return Err(StorageError::Conflict("Project revision"));
        }
        register_blob(&transaction, &blob)?;
        transaction.execute("INSERT OR IGNORE INTO documents(definition,document_id,content_hash,blob_digest) VALUES('Project',?1,?2,?3)",params![id.as_str(),revision.as_str(),blob.digest.as_str()])?;
        transaction.execute("INSERT INTO project_heads(project_id,revision,blob_digest) VALUES(?1,?2,?3) ON CONFLICT(project_id) DO UPDATE SET revision=excluded.revision,blob_digest=excluded.blob_digest",params![id.as_str(),revision.as_str(),blob.digest.as_str()])?;
        transaction.commit()?;
        Ok(blob)
    }

    pub fn project(&self, id: &ProjectId) -> StorageResult<Value> {
        let row:Option<(String,i64)>=self.connection.query_row(
            "SELECT p.blob_digest,b.byte_length FROM project_heads p JOIN blobs b ON b.digest=p.blob_digest WHERE project_id=?1",
            [id.as_str()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (digest, length) = row.ok_or(StorageError::NotFound("Project"))?;
        let blob = BlobRef {
            digest: Sha256Digest::new(digest).map_err(|e| StorageError::Corrupt(e.to_string()))?,
            byte_length: length as u64,
        };
        let value = self
            .validator
            .parse_and_validate("Project", &self.cas.read(&blob)?)
            .map_err(|e| StorageError::Corrupt(e.to_string()))?;
        verify_projected_digest("Project", &value)
            .map_err(|e| StorageError::Corrupt(e.to_string()))?;
        Ok(value)
    }

    /// Historical authorized snapshots remain addressable after the mutable
    /// project head advances. The supplied hash is verified against actual bytes.
    pub fn project_revision(
        &self,
        id: &ProjectId,
        revision: &Sha256Digest,
    ) -> StorageResult<Value> {
        let row: Option<(String, i64)> = self.connection.query_row(
            "SELECT d.blob_digest,b.byte_length FROM documents d JOIN blobs b ON b.digest=d.blob_digest WHERE d.definition='Project' AND d.document_id=?1 AND d.content_hash=?2",
            params![id.as_str(), revision.as_str()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        let (digest, length) = row.ok_or(StorageError::NotFound("Project revision"))?;
        let blob = BlobRef {
            digest: Sha256Digest::new(digest).map_err(|e| StorageError::Corrupt(e.to_string()))?,
            byte_length: u64::try_from(length)
                .map_err(|_| StorageError::Corrupt("Negative stored blob length".into()))?,
        };
        let value = self
            .validator
            .parse_and_validate("Project", &self.cas.read(&blob)?)
            .map_err(|e| StorageError::Corrupt(e.to_string()))?;
        let actual = verify_projected_digest("Project", &value)
            .map_err(|e| StorageError::Corrupt(e.to_string()))?;
        if &actual != revision || value["projectId"] != id.as_str() {
            return Err(StorageError::Corrupt(
                "Historical project revision differs from its durable index".into(),
            ));
        }
        Ok(value)
    }

    /// The observation's bytes must be captured by an actual observer upstream.
    /// These pairs pin direct changes only, never fluid/schedule/player effects.
    pub fn save_recovery_snapshot(&mut self, snapshot: RecoverySnapshot) -> StorageResult<()> {
        if snapshot.target.is_empty() || snapshot.target.len() > 4096 {
            return Err(StorageError::InvalidInput(
                "Recovery target must fit the 4096-byte budget".into(),
            ));
        }
        mmmm_contracts::BindingId::new(snapshot.binding_id.clone())
            .map_err(|e| StorageError::InvalidInput(e.to_string()))?;
        if let Some(epoch) = &snapshot.epoch {
            mmmm_contracts::SessionEpoch::new(epoch.clone())
                .map_err(|e| StorageError::InvalidInput(e.to_string()))?;
        }
        self.cas.verify(&snapshot.before)?;
        self.cas.verify(&snapshot.after)?;
        let operation = self.operation(&snapshot.operation_id)?;
        let step = operation
            .steps
            .iter()
            .find(|s| s.step_id == snapshot.step_id)
            .ok_or(StorageError::NotFound("Recovery step"))?;
        let invocation = self.stored_invocation(&snapshot.operation_id, &snapshot.step_id)?;
        if invocation["context"]["contextId"] != snapshot.context_id.as_str()
            || invocation["bindingId"] != snapshot.binding_id
            || invocation["context"]["environment"]["sessionEpoch"].as_str()
                != snapshot.epoch.as_deref()
        {
            return Err(StorageError::Conflict(
                "Recovery invocation context/binding/epoch",
            ));
        }
        if !matches!(
            step.effect,
            EffectEvidence::SomeConfirmed | EffectEvidence::CompleteConfirmed
        ) {
            return Err(StorageError::InvalidTransition(
                "Recovery requires recorded confirmed direct effects".into(),
            ));
        }
        let json = encode(&snapshot)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<String> = transaction
            .query_row(
                "SELECT record_json FROM recovery_snapshots WHERE operation_id=?1 AND step_id=?2 AND target=?3",
                params![snapshot.operation_id.as_str(), snapshot.step_id.as_str(), snapshot.target],
                |r| r.get(0),
            )
            .optional()?;
        if old.as_ref().is_some_and(|old| old != &json) {
            return Err(StorageError::Conflict("Immutable recovery snapshot"));
        }
        if old.is_none() {
            let count: i64 = transaction.query_row(
                "SELECT count(*) FROM recovery_snapshots WHERE operation_id=?1",
                [snapshot.operation_id.as_str()],
                |row| row.get(0),
            )?;
            if count >= 4096 {
                return Err(StorageError::InvalidInput(
                    "Recovery snapshot entry budget exceeded".into(),
                ));
            }
        }
        pin_blob(
            &transaction,
            "recovery",
            snapshot.operation_id.as_str(),
            &snapshot.before,
        )?;
        pin_blob(
            &transaction,
            "recovery",
            snapshot.operation_id.as_str(),
            &snapshot.after,
        )?;
        transaction.execute("INSERT OR IGNORE INTO recovery_snapshots(operation_id,step_id,target,record_json) VALUES(?1,?2,?3,?4)",params![snapshot.operation_id.as_str(),snapshot.step_id.as_str(),snapshot.target,json])?;
        transaction.commit()?;
        Ok(())
    }

    /// Return a recorded pair for constructing a NEW recovery plan. The caller
    /// must repeat this after-state check at its eventual dispatch precondition.
    // Keep durable identity, current binding/context epoch, and independently
    // observed after-state explicit so every recovery authorization check is
    // visible at the call site; this exemption applies only to this boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn recovery_snapshot(
        &self,
        operation: &OperationId,
        step: &mmmm_contracts::StepId,
        target: &str,
        context: &mmmm_contracts::ContextId,
        binding: &str,
        epoch: Option<&str>,
        current_after: &BlobRef,
    ) -> StorageResult<RecoverySnapshot> {
        self.cas.verify(current_after)?;
        let json: Option<String> = self
            .connection
            .query_row(
                "SELECT record_json FROM recovery_snapshots WHERE operation_id=?1 AND step_id=?2 AND target=?3",
                params![operation.as_str(), step.as_str(), target],
                |r| r.get(0),
            )
            .optional()?;
        let snapshot: RecoverySnapshot =
            decode(&json.ok_or(StorageError::NotFound("Recovery snapshot"))?)?;
        if &snapshot.operation_id != operation
            || &snapshot.step_id != step
            || snapshot.target != target
        {
            return Err(StorageError::Corrupt(
                "Recovery snapshot differs from its durable identity".into(),
            ));
        }
        if &snapshot.context_id != context
            || snapshot.binding_id != binding
            || snapshot.epoch.as_deref() != epoch
        {
            return Err(StorageError::Conflict(
                "Recovery binding/context epoch expired",
            ));
        }
        if &snapshot.after != current_after {
            return Err(StorageError::Conflict("Recovery after-state"));
        }
        self.cas.verify(&snapshot.before)?;
        self.cas.verify(&snapshot.after)?;
        Ok(snapshot)
    }

    /// Read the recorded direct pairs for a new recovery plan. This does not
    /// assert that the live targets still equal those after snapshots.
    pub fn recovery_snapshots(
        &self,
        operation: &OperationId,
    ) -> StorageResult<Vec<RecoverySnapshot>> {
        let record = self.operation(operation)?;
        let mut statement = self.connection.prepare(
            "SELECT step_id,target,record_json FROM recovery_snapshots WHERE operation_id=?1 ORDER BY step_id,target LIMIT 4097",
        )?;
        let rows = statement
            .query_map([operation.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if rows.len() > 4096 {
            return Err(StorageError::InvalidInput(
                "Recovery snapshot entry budget exceeded".into(),
            ));
        }
        let mut snapshots = Vec::with_capacity(rows.len());
        for (step_id, target, json) in rows {
            let snapshot: RecoverySnapshot = decode(&json)?;
            if &snapshot.operation_id != operation
                || snapshot.step_id.as_str() != step_id
                || snapshot.target != target
            {
                return Err(StorageError::Corrupt(
                    "Recovery snapshot differs from its durable identity".into(),
                ));
            }
            let step = record
                .steps
                .iter()
                .find(|step| step.step_id == snapshot.step_id)
                .ok_or_else(|| {
                    StorageError::Corrupt(
                        "Recovery snapshot refers to an unknown operation step".into(),
                    )
                })?;
            if !matches!(
                step.effect,
                EffectEvidence::SomeConfirmed | EffectEvidence::CompleteConfirmed
            ) {
                return Err(StorageError::Corrupt(
                    "Recovery snapshot lacks retained confirmed effects".into(),
                ));
            }
            let invocation = self.stored_invocation(operation, &snapshot.step_id)?;
            if invocation["context"]["contextId"] != snapshot.context_id.as_str()
                || invocation["bindingId"] != snapshot.binding_id
                || invocation["context"]["environment"]["sessionEpoch"].as_str()
                    != snapshot.epoch.as_deref()
            {
                return Err(StorageError::Corrupt(
                    "Recovery snapshot differs from its retained invocation".into(),
                ));
            }
            self.cas.verify(&snapshot.before)?;
            self.cas.verify(&snapshot.after)?;
            snapshots.push(snapshot);
        }
        Ok(snapshots)
    }

    /// Retain an application response/diagnostic envelope in the same CAS and
    /// operation journal. The caller validates and sanitizes the envelope before
    /// publishing it, and authenticates access before returning it to clients.
    pub fn append_operation_evidence(
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
            "SELECT EXISTS(SELECT 1 FROM blob_refs WHERE owner_kind='application_evidence' AND owner_id=?1 AND digest=?2)",
            params![operation.as_str(), blob.digest.as_str()], |row| row.get(0),
        )?;
        if exists == 1 {
            transaction.commit()?;
            return Ok(());
        }
        let count: i64 = transaction.query_row(
            "SELECT count(*) FROM blob_refs WHERE owner_kind='application_evidence' AND owner_id=?1",
            [operation.as_str()], |row| row.get(0),
        )?;
        if count >= 4096 {
            return Err(StorageError::InvalidInput(
                "Operation evidence entry budget exceeded".into(),
            ));
        }
        pin_blob(
            &transaction,
            "application_evidence",
            operation.as_str(),
            blob,
        )?;
        transaction.execute("INSERT INTO events(operation_id,kind,record_json) VALUES(?1,'application_evidence',?2)",
            params![operation.as_str(), encode(blob)?])?;
        transaction.commit()?;
        Ok(())
    }

    pub fn operation_evidence(&self, operation: &OperationId) -> StorageResult<Vec<BlobRef>> {
        self.operation(operation)?;
        let mut statement = self.connection.prepare(
            "SELECT r.digest,b.byte_length FROM blob_refs r JOIN blobs b ON b.digest=r.digest WHERE r.owner_kind='application_evidence' AND r.owner_id=?1 ORDER BY r.digest LIMIT 4097",
        )?;
        let rows = statement
            .query_map([operation.as_str()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if rows.len() > 4096 {
            return Err(StorageError::InvalidInput(
                "Operation evidence entry budget exceeded".into(),
            ));
        }
        let mut blobs = Vec::with_capacity(rows.len());
        for (digest, length) in rows {
            let blob = BlobRef {
                digest: Sha256Digest::new(digest)
                    .map_err(|e| StorageError::Corrupt(e.to_string()))?,
                byte_length: u64::try_from(length)
                    .map_err(|_| StorageError::Corrupt("Negative stored blob length".into()))?,
            };
            self.cas.verify(&blob)?;
            blobs.push(blob);
        }
        Ok(blobs)
    }

    pub fn pin_artifact(&mut self, owner: &str, blob: &BlobRef) -> StorageResult<()> {
        mmmm_contracts::ArtifactId::new(owner)
            .map_err(|e| StorageError::InvalidInput(e.to_string()))?;
        self.cas.verify(blob)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        pin_blob(&transaction, "artifact", owner, blob)?;
        transaction.commit()?;
        Ok(())
    }
}

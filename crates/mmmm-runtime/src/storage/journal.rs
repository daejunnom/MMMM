use super::*;
use mmmm_contracts::{InvocationId, OperationId, StepId, encode_json, raw_digest};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::Value;

pub(crate) const SCHEMA: &str = r#"
BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS blobs (
 digest TEXT PRIMARY KEY CHECK(length(digest)=64),
 byte_length INTEGER NOT NULL CHECK(byte_length>=0)
) STRICT;
CREATE TABLE IF NOT EXISTS documents (
 definition TEXT NOT NULL,
 document_id TEXT NOT NULL,
 content_hash TEXT NOT NULL,
 blob_digest TEXT NOT NULL REFERENCES blobs(digest),
 PRIMARY KEY(definition,document_id,content_hash)
) STRICT;
CREATE TABLE IF NOT EXISTS project_heads (
 project_id TEXT PRIMARY KEY,
 revision TEXT NOT NULL,
 blob_digest TEXT NOT NULL REFERENCES blobs(digest)
) STRICT;
CREATE TABLE IF NOT EXISTS operations (
 operation_id TEXT PRIMARY KEY,
 principal TEXT NOT NULL,
 project_id TEXT NOT NULL,
 idempotency_key TEXT NOT NULL,
 plan_id TEXT NOT NULL,
 plan_hash TEXT NOT NULL,
 record_json TEXT NOT NULL,
 UNIQUE(principal,project_id,idempotency_key)
) STRICT;
CREATE TABLE IF NOT EXISTS invocations (
 invocation_id TEXT PRIMARY KEY,
 operation_id TEXT NOT NULL REFERENCES operations(operation_id),
 step_id TEXT NOT NULL,
 invocation_hash TEXT NOT NULL,
 blob_digest TEXT NOT NULL REFERENCES blobs(digest),
 UNIQUE(operation_id,step_id)
) STRICT;
CREATE TABLE IF NOT EXISTS blob_refs (
 owner_kind TEXT NOT NULL,
 owner_id TEXT NOT NULL,
 digest TEXT NOT NULL REFERENCES blobs(digest),
 PRIMARY KEY(owner_kind,owner_id,digest)
) STRICT;
CREATE TABLE IF NOT EXISTS write_fences (
 operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
 scope_json TEXT NOT NULL,
 whole_project INTEGER NOT NULL CHECK(whole_project IN(0,1))
) STRICT;
CREATE TABLE IF NOT EXISTS recovery_snapshots (
 operation_id TEXT NOT NULL REFERENCES operations(operation_id),
 step_id TEXT NOT NULL,
 target TEXT NOT NULL,
 record_json TEXT NOT NULL,
 PRIMARY KEY(operation_id,step_id,target)
) STRICT;
CREATE TABLE IF NOT EXISTS events (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 operation_id TEXT NOT NULL REFERENCES operations(operation_id),
 kind TEXT NOT NULL,
 record_json TEXT NOT NULL
) STRICT;
PRAGMA user_version=1;
PRAGMA application_id=1296911693;
COMMIT;
"#;

pub(crate) fn encode<T: serde::Serialize>(value: &T) -> StorageResult<String> {
    let value = serde_json::to_value(value).map_err(|e| StorageError::Contract(e.to_string()))?;
    let bytes = encode_json(&value).map_err(|e| StorageError::Contract(e.to_string()))?;
    String::from_utf8(bytes).map_err(|e| StorageError::Contract(e.to_string()))
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(text: &str) -> StorageResult<T> {
    let value = mmmm_contracts::parse_json(text.as_bytes())
        .map_err(|e| StorageError::Corrupt(e.to_string()))?;
    serde_json::from_value(value).map_err(|e| StorageError::Corrupt(e.to_string()))
}
pub(crate) fn register_blob(transaction: &Transaction<'_>, blob: &BlobRef) -> StorageResult<()> {
    let old: Option<i64> = transaction
        .query_row(
            "SELECT byte_length FROM blobs WHERE digest=?1",
            [blob.digest.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    let length = i64::try_from(blob.byte_length)
        .map_err(|_| StorageError::InvalidInput("Blob length exceeds SQLite bounds".into()))?;
    if old.is_some_and(|old| old != length) {
        return Err(StorageError::Corrupt(
            "CAS digest has conflicting durable length".into(),
        ));
    }
    transaction.execute(
        "INSERT OR IGNORE INTO blobs(digest,byte_length) VALUES(?1,?2)",
        params![blob.digest.as_str(), length],
    )?;
    Ok(())
}
pub(crate) fn pin_blob(
    transaction: &Transaction<'_>,
    kind: &str,
    owner: &str,
    blob: &BlobRef,
) -> StorageResult<()> {
    register_blob(transaction, blob)?;
    transaction.execute(
        "INSERT OR IGNORE INTO blob_refs(owner_kind,owner_id,digest) VALUES(?1,?2,?3)",
        params![kind, owner, blob.digest.as_str()],
    )?;
    Ok(())
}
fn read_record(
    connection: &rusqlite::Connection,
    operation: &OperationId,
) -> StorageResult<OperationRecord> {
    let text: Option<String> = connection
        .query_row(
            "SELECT record_json FROM operations WHERE operation_id=?1",
            [operation.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    let record: OperationRecord = decode(&text.ok_or(StorageError::NotFound("Operation"))?)?;
    if &record.operation_id != operation {
        return Err(StorageError::Corrupt(
            "Operation record differs from its durable identity".into(),
        ));
    }
    Ok(record)
}
fn write_record(
    transaction: &Transaction<'_>,
    record: &OperationRecord,
    event: &str,
) -> StorageResult<()> {
    let json = encode(record)?;
    if transaction.execute(
        "UPDATE operations SET record_json=?2 WHERE operation_id=?1",
        params![record.operation_id.as_str(), json],
    )? != 1
    {
        return Err(StorageError::NotFound("Operation"));
    }
    transaction.execute(
        "INSERT INTO events(operation_id,kind,record_json) VALUES(?1,?2,?3)",
        params![record.operation_id.as_str(), event, json],
    )?;
    Ok(())
}
fn check_fences(
    connection: &rusqlite::Connection,
    scope: &WriteScope,
    whole: bool,
    except: Option<&OperationId>,
) -> StorageResult<()> {
    scope.validate()?;
    let mut statement = connection.prepare(
        "SELECT operation_id,scope_json,whole_project FROM write_fences ORDER BY operation_id",
    )?;
    let rows = statement.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    let mut conflicts = Vec::new();
    for row in rows {
        let (id, json, other_whole) = row?;
        let id = OperationId::new(id).map_err(|e| StorageError::Corrupt(e.to_string()))?;
        if except == Some(&id) {
            continue;
        }
        let other: WriteScope = decode(&json)?;
        other.validate()?;
        if scope.overlaps(&other, whole, other_whole == 1) {
            conflicts.push(id);
        }
    }
    if conflicts.is_empty() {
        Ok(())
    } else {
        Err(StorageError::Fenced(conflicts))
    }
}

impl DurableStore {
    pub fn operation(&self, operation: &OperationId) -> StorageResult<OperationRecord> {
        read_record(&self.connection, operation)
    }

    pub fn reserve_operation(&mut self, request: ReserveOperation) -> StorageResult<Reservation> {
        if request.idempotency_key.is_empty() || request.idempotency_key.len() > 4096 {
            return Err(StorageError::InvalidInput(
                "Idempotency key must fit the 4096-byte runtime budget".into(),
            ));
        }
        // An existing authenticated reservation is returned before loading the
        // plan. This retrieves status after expiry; it never reauthorizes dispatch.
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = transaction.query_row(
            "SELECT record_json FROM operations WHERE principal=?1 AND project_id=?2 AND idempotency_key=?3",
            params![request.principal.as_str(),request.project_id.as_str(),request.idempotency_key], |r| r.get(0)).optional()?;
        if let Some(json) = existing {
            let record: OperationRecord = decode(&json)?;
            if record.plan_hash != request.plan_hash {
                return Err(StorageError::Conflict("Idempotency key"));
            }
            transaction.commit()?;
            return Ok(Reservation::Existing(record));
        }
        let plan_blob: Option<(String,i64)> = transaction.query_row(
            "SELECT d.blob_digest,b.byte_length FROM documents d JOIN blobs b ON b.digest=d.blob_digest WHERE d.definition='ExecutionPlan' AND d.document_id=?1 AND d.content_hash=?2",
            params![request.plan_id.as_str(),request.plan_hash.as_str()], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (digest, length) = plan_blob.ok_or(StorageError::NotFound("Execution plan"))?;
        let blob = BlobRef {
            digest: Sha256Digest::new(digest).map_err(|e| StorageError::Corrupt(e.to_string()))?,
            byte_length: length as u64,
        };
        let plan = self
            .validator
            .parse_and_validate("ExecutionPlan", &self.cas.read(&blob)?)
            .map_err(|e| StorageError::Contract(e.to_string()))?;
        let actual = mmmm_contracts::verify_projected_digest("ExecutionPlan", &plan)
            .map_err(|e| StorageError::Corrupt(e.to_string()))?;
        if actual != request.plan_hash || plan["planId"] != request.plan_id.as_str() {
            return Err(StorageError::Corrupt(
                "Frozen plan identity differs from its durable index".into(),
            ));
        }
        if plan["projectId"] != request.project_id.as_str()
            || plan["contextId"] != request.context_id.as_str()
        {
            return Err(StorageError::Conflict("Plan project/context"));
        }
        let scope: WriteScope = serde_json::from_value(plan["scope"].clone())
            .map_err(|e| StorageError::Contract(e.to_string()))?;
        scope.validate()?;
        if scope.project_id != request.project_id {
            return Err(StorageError::Conflict("Plan scope project"));
        }
        let mut steps = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        for step in plan["steps"]
            .as_array()
            .ok_or_else(|| StorageError::Corrupt("Plan steps missing".into()))?
        {
            let step_id: StepId = serde_json::from_value(step["stepId"].clone())
                .map_err(|e| StorageError::Contract(e.to_string()))?;
            if !ids.insert(step_id.clone()) {
                return Err(StorageError::Contract("Duplicate plan step ID".into()));
            }
            let verification_requirement =
                serde_json::from_value(step["verificationRequirement"].clone())
                    .map_err(|e| StorageError::Contract(e.to_string()))?;
            steps.push(StepRecord {
                step_id,
                write_effect: step["effect"] != "read",
                verification_requirement,
                dispatch: DispatchEvidence::NotSent,
                effect: EffectEvidence::NoneConfirmed,
                further_effects_possible: false,
                provider_receipt: None,
                invocation_id: None,
                invocation_digest: None,
                observation_refs: vec![],
                finished: false,
            });
        }
        let record = OperationRecord {
            operation_id: request.operation_id,
            principal: request.principal,
            project_id: request.project_id,
            idempotency_key: request.idempotency_key,
            plan_id: request.plan_id,
            plan_hash: request.plan_hash,
            context_id: request.context_id,
            state: OperationState::Queued,
            cancellation_requested: false,
            reconciliation_required: false,
            whole_project_fence: scope.is_empty() && steps.iter().any(|s| s.write_effect),
            scope,
            steps,
        };
        let json = encode(&record)?;
        transaction.execute("INSERT INTO operations(operation_id,principal,project_id,idempotency_key,plan_id,plan_hash,record_json) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![record.operation_id.as_str(),record.principal.as_str(),record.project_id.as_str(),record.idempotency_key,record.plan_id.as_str(),record.plan_hash.as_str(),json])?;
        pin_blob(
            &transaction,
            "operation",
            record.operation_id.as_str(),
            &blob,
        )?;
        transaction.execute(
            "INSERT INTO events(operation_id,kind,record_json) VALUES(?1,'reserved',?2)",
            params![record.operation_id.as_str(), json],
        )?;
        transaction.commit()?;
        Ok(Reservation::Created(record))
    }

    /// Commit the exact invocation and write fence before handing anything to a
    /// host. A repeated intent is an error, including identical bytes; callers
    /// reconcile the stored intent rather than dispatching it again.
    pub fn dispatch_intent(
        &mut self,
        operation: &OperationId,
        step_id: &StepId,
        invocation: &Value,
    ) -> StorageResult<StepRecord> {
        self.dispatch_intent_internal(operation, step_id, invocation, None, None)
    }

    pub(crate) fn dispatch_intent_internal(
        &mut self,
        operation: &OperationId,
        step_id: &StepId,
        invocation: &Value,
        resolution_witness: Option<&BlobRef>,
        undo_authorization: Option<super::undo::UndoIntentAuthorization<'_>>,
    ) -> StorageResult<StepRecord> {
        self.validator
            .validate("Invocation", invocation)
            .map_err(|e| StorageError::Contract(e.to_string()))?;
        let bytes = encode_json(invocation).map_err(|e| StorageError::Contract(e.to_string()))?;
        let blob = self.cas.put(&bytes)?;
        let invocation_id: InvocationId =
            serde_json::from_value(invocation["invocationId"].clone())
                .map_err(|e| StorageError::Contract(e.to_string()))?;
        // The unique mutable Store borrow and exclusive root lease protect
        // this connection. The undo hook shares read-only durable verification
        // on the same connection; all live provider reads precede this tx.
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let mut record = read_record(&transaction, operation)?;
        if record.cancellation_requested
            || record.reconciliation_required
            || !matches!(
                record.state,
                OperationState::Queued | OperationState::Running
            )
        {
            return Err(StorageError::InvalidTransition(
                "New dispatch requires queued or running state".into(),
            ));
        }
        let index = record
            .steps
            .iter()
            .position(|s| &s.step_id == step_id)
            .ok_or(StorageError::NotFound("Plan step"))?;
        if record.steps[index].dispatch != DispatchEvidence::NotSent || record.steps[index].finished
        {
            return Err(StorageError::Conflict(
                "Step already has a durable dispatch intent",
            ));
        }
        if invocation["operationId"] != operation.as_str()
            || invocation["stepId"] != step_id.as_str()
            || invocation["context"]["projectId"] != record.project_id.as_str()
            || invocation["context"]["principalRef"] != record.principal.as_str()
        {
            return Err(StorageError::Conflict("Invocation identity"));
        }
        if undo_authorization.is_none() {
            super::undo::reject_recovery_only_route(&transaction, invocation)?;
        } else if resolution_witness.is_some() {
            return Err(StorageError::Conflict(
                "Provider undo cannot use result resolution authorization",
            ));
        }
        // Context/action/implementation pins must match the frozen step; the
        // application separately validates expiry, grant and target preconditions.
        let plan = Self::load_plan_in(&transaction, &self.cas, &record.plan_id, &record.plan_hash)?;
        let step = plan["steps"]
            .as_array()
            .and_then(|s| s.iter().find(|s| s["stepId"] == step_id.as_str()))
            .ok_or(StorageError::NotFound("Frozen plan step"))?;
        for field in [
            "bindingId",
            "actionId",
            "actionContractVersion",
            "actionDigest",
            "implementationDigest",
        ] {
            if invocation[field] != step[field] {
                return Err(StorageError::Conflict("Frozen invocation route"));
            }
        }
        if invocation["context"]["contextId"] != step["contextId"] {
            return Err(StorageError::Conflict("Frozen step context"));
        }
        let context_hash =
            mmmm_contracts::verify_projected_digest("ExecutionContext", &invocation["context"])
                .map_err(|e| StorageError::Contract(e.to_string()))?;
        if invocation["contextDigest"] != context_hash.as_str()
            || invocation["context"]["policyRevision"] != plan["policyRevision"]
            || !plan["contextPins"].as_array().is_some_and(|pins| {
                pins.iter().any(|pin| {
                    pin["contextId"] == step["contextId"]
                        && pin["contextDigest"] == context_hash.as_str()
                })
            })
        {
            return Err(StorageError::Conflict("Frozen context digest/policy"));
        }
        let result_bound = step["resultBindings"]
            .as_array()
            .is_some_and(|bindings| !bindings.is_empty());
        let resolution_refs = match (result_bound, resolution_witness) {
            (true, Some(witness_blob)) => super::result_binding::verify_resolution(
                &transaction,
                &self.cas,
                &self.validator,
                super::result_binding::ResolutionInput {
                    record: &record,
                    plan: &plan,
                    step,
                    invocation,
                    witness_blob,
                },
            )?,
            (true, None) => {
                return Err(StorageError::InvalidTransition(
                    "Result-bound dispatch requires a registered resolution witness".into(),
                ));
            }
            (false, Some(_)) => {
                return Err(StorageError::Conflict(
                    "Resolution witness on an unbound step",
                ));
            }
            (false, None) => {
                if invocation["arguments"] != step["arguments"] {
                    return Err(StorageError::Conflict("Frozen invocation arguments"));
                }
                Vec::new()
            }
        };
        for dependency in step["dependsOn"]
            .as_array()
            .ok_or_else(|| StorageError::Corrupt("Frozen dependency list missing".into()))?
        {
            let prior = record
                .steps
                .iter()
                .find(|stored| dependency == stored.step_id.as_str())
                .ok_or_else(|| {
                    StorageError::Contract("Frozen step dependency does not exist".into())
                })?;
            if !step_verified(prior) {
                return Err(StorageError::InvalidTransition(
                    "Predecessor step has not completed its required verification".into(),
                ));
            }
        }
        let args_hash = mmmm_contracts::canonical_digest(&invocation["arguments"])
            .map_err(|e| StorageError::Contract(e.to_string()))?;
        if invocation["argumentsDigest"] != args_hash.as_str() {
            return Err(StorageError::Conflict("Invocation arguments digest"));
        }
        if let Some(authorization) = &undo_authorization {
            super::undo::reserve_undo_in(
                &transaction,
                self,
                super::undo::UndoClaimInput {
                    operation: &record,
                    plan: &plan,
                    step,
                    invocation,
                    invocation_blob: &blob,
                },
                authorization,
            )?;
        }
        if record.steps[index].write_effect {
            check_fences(
                &transaction,
                &record.scope,
                record.whole_project_fence,
                Some(operation),
            )?;
            transaction.execute("INSERT OR IGNORE INTO write_fences(operation_id,scope_json,whole_project) VALUES(?1,?2,?3)",
                params![operation.as_str(),encode(&record.scope)?,i64::from(record.whole_project_fence)])?;
        }
        pin_blob(&transaction, "operation", operation.as_str(), &blob)?;
        for source in &resolution_refs {
            pin_blob(
                &transaction,
                "result_resolution",
                invocation_id.as_str(),
                source,
            )?;
        }
        if let Some(witness) = resolution_witness {
            pin_blob(
                &transaction,
                "result_resolution_witness",
                invocation_id.as_str(),
                witness,
            )?;
        }
        transaction.execute("INSERT INTO invocations(invocation_id,operation_id,step_id,invocation_hash,blob_digest) VALUES(?1,?2,?3,?4,?5)",
            params![invocation_id.as_str(),operation.as_str(),step_id.as_str(),raw_digest(&bytes).as_str(),blob.digest.as_str()])?;
        record.state = OperationState::Running;
        let stored = &mut record.steps[index];
        stored.dispatch = DispatchEvidence::IntentDurable;
        stored.effect = if stored.write_effect {
            EffectEvidence::Unknown
        } else {
            EffectEvidence::NoneConfirmed
        };
        stored.further_effects_possible = stored.write_effect;
        stored.invocation_id = Some(invocation_id);
        stored.invocation_digest = Some(blob.digest);
        let result = stored.clone();
        write_record(&transaction, &record, "dispatch_intent")?;
        transaction.commit()?;
        Ok(result)
    }

    pub fn record_observation(
        &mut self,
        operation: &OperationId,
        step: &StepId,
        observation: StepObservation,
    ) -> StorageResult<OperationRecord> {
        for blob in &observation.observation_refs {
            self.cas.verify(blob)?;
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = read_record(&transaction, operation)?;
        if record.state.terminal() {
            return Err(StorageError::InvalidTransition(
                "Terminal operation evidence is immutable".into(),
            ));
        }
        let stored = record
            .steps
            .iter_mut()
            .find(|s| &s.step_id == step)
            .ok_or(StorageError::NotFound("Operation step"))?;
        if stored.dispatch == DispatchEvidence::NotSent || observation.dispatch < stored.dispatch {
            return Err(StorageError::InvalidTransition(
                "Observation must follow a durable intent and cannot lower dispatch evidence"
                    .into(),
            ));
        }
        if observation.finished
            && (observation.further_effects_possible
                || observation.effect == EffectEvidence::Unknown)
        {
            return Err(StorageError::InvalidTransition(
                "Unknown or still-running effects cannot be final".into(),
            ));
        }
        if stored.finished {
            return Err(StorageError::InvalidTransition(
                "Final step evidence is immutable".into(),
            ));
        }
        if observation.dispatch == DispatchEvidence::Observed
            && observation.observation_refs.is_empty()
        {
            return Err(StorageError::InvalidTransition(
                "Independent observation requires retained evidence".into(),
            ));
        }
        if matches!(
            stored.effect,
            EffectEvidence::SomeConfirmed | EffectEvidence::CompleteConfirmed
        ) && matches!(
            observation.effect,
            EffectEvidence::NoneConfirmed | EffectEvidence::Unknown
        ) {
            return Err(StorageError::InvalidTransition(
                "Confirmed effects cannot be erased".into(),
            ));
        }
        if let Some(receipt) = &observation.provider_receipt {
            mmmm_contracts::RecordId::new(receipt.clone())
                .map_err(|e| StorageError::InvalidInput(e.to_string()))?;
            if stored
                .provider_receipt
                .as_ref()
                .is_some_and(|old| old != receipt)
            {
                return Err(StorageError::Conflict("Provider receipt"));
            }
            stored.provider_receipt = Some(receipt.clone());
        }
        stored.dispatch = observation.dispatch;
        stored.effect = observation.effect;
        stored.further_effects_possible = observation.further_effects_possible;
        stored.finished = observation.finished;
        for blob in observation.observation_refs {
            pin_blob(&transaction, "operation", operation.as_str(), &blob)?;
            if !stored.observation_refs.contains(&blob) {
                stored.observation_refs.push(blob);
            }
        }
        if record.reconciliation_required
            && record
                .steps
                .iter()
                .filter(|step| step.dispatch != DispatchEvidence::NotSent)
                .all(|step| {
                    step.finished
                        && !step.further_effects_possible
                        && step.effect != EffectEvidence::Unknown
                })
        {
            // A fresh observation has completed every already-dispatched step.
            // Unsent steps still require normal policy/context/precondition checks.
            record.reconciliation_required = false;
        }
        if matches!(
            record.state,
            OperationState::OutcomeUnknown | OperationState::Partial
        ) {
            record.state = aggregate_pending(&record);
        }
        write_record(&transaction, &record, "step_observation")?;
        transaction.commit()?;
        Ok(record)
    }

    /// A timeout, lost connection or malformed write response is recorded as an
    /// uncertain outcome. Existing confirmed changes are kept separately from
    /// the possibility that the host performed additional changes.
    pub fn mark_outcome_unknown(
        &mut self,
        operation: &OperationId,
        step: &StepId,
    ) -> StorageResult<OperationRecord> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = read_record(&transaction, operation)?;
        let stored = record
            .steps
            .iter_mut()
            .find(|s| &s.step_id == step)
            .ok_or(StorageError::NotFound("Operation step"))?;
        if stored.dispatch == DispatchEvidence::NotSent
            || stored.finished
            || record.state.terminal()
        {
            return Err(StorageError::InvalidTransition(
                "Only a dispatched unfinished step can have an unknown outcome".into(),
            ));
        }
        if stored.write_effect {
            stored.further_effects_possible = true;
            if stored.effect == EffectEvidence::NoneConfirmed {
                stored.effect = EffectEvidence::Unknown;
            }
        }
        record.state = aggregate_pending(&record);
        record.reconciliation_required = true;
        if record.state == OperationState::Running {
            record.state = OperationState::OutcomeUnknown;
        }
        write_record(&transaction, &record, "outcome_unknown")?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn request_cancel(&mut self, operation: &OperationId) -> StorageResult<OperationRecord> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = read_record(&transaction, operation)?;
        if record.state == OperationState::Queued
            && record
                .steps
                .iter()
                .all(|s| s.dispatch == DispatchEvidence::NotSent)
        {
            record.cancellation_requested = true;
            record.state = OperationState::Cancelled;
        } else if !record.state.terminal() {
            record.cancellation_requested = true;
            record.state = OperationState::CancelRequested;
        }
        write_record(&transaction, &record, "cancel_requested")?;
        transaction.commit()?;
        Ok(record)
    }

    /// A terminal state is allowed only by retained step evidence. Cancellation
    /// does not erase effects, and provider reports cannot satisfy a readback pin.
    pub fn finish_operation(
        &mut self,
        operation: &OperationId,
        state: OperationState,
    ) -> StorageResult<OperationRecord> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = read_record(&transaction, operation)?;
        if record.state.terminal() {
            if record.state == state {
                return Ok(record);
            }
            return Err(StorageError::InvalidTransition(
                "Terminal operation state is immutable".into(),
            ));
        }
        let any_effect = record.steps.iter().any(|s| {
            matches!(
                s.effect,
                EffectEvidence::SomeConfirmed | EffectEvidence::CompleteConfirmed
            )
        });
        let unknown = record
            .steps
            .iter()
            .any(|s| s.further_effects_possible || s.effect == EffectEvidence::Unknown);
        let all_verified = record.steps.iter().all(step_verified);
        let no_effect_proven = record.steps.iter().all(|s| {
            s.dispatch == DispatchEvidence::NotSent
                || ((s.finished || !s.write_effect)
                    && s.effect == EffectEvidence::NoneConfirmed
                    && !s.further_effects_possible)
        });
        let valid = match state {
            OperationState::Succeeded => all_verified,
            OperationState::FailedBeforeEffects => no_effect_proven,
            OperationState::Cancelled => no_effect_proven && record.cancellation_requested,
            OperationState::Partial => any_effect,
            OperationState::OutcomeUnknown => unknown,
            _ => false,
        };
        if !valid {
            return Err(StorageError::InvalidTransition(
                "Requested final state exceeds retained verification/effect evidence".into(),
            ));
        }
        record.state = state;
        if !unknown {
            transaction.execute(
                "DELETE FROM write_fences WHERE operation_id=?1",
                [operation.as_str()],
            )?;
        }
        write_record(&transaction, &record, "operation_outcome")?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn check_write_scope(
        &self,
        scope: &WriteScope,
        whole_project: bool,
        except: Option<&OperationId>,
    ) -> StorageResult<()> {
        check_fences(&self.connection, scope, whole_project, except)
    }

    pub fn unresolved_dispatches(&self) -> StorageResult<Vec<OperationRecord>> {
        let mut statement = self
            .connection
            .prepare("SELECT record_json FROM operations ORDER BY operation_id")?;
        let json = statement
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut records = Vec::new();
        for item in json {
            let record: OperationRecord = decode(&item)?;
            if !record.state.terminal()
                && record
                    .steps
                    .iter()
                    .any(|s| s.dispatch != DispatchEvidence::NotSent && !s.finished)
            {
                records.push(record);
            }
        }
        Ok(records)
    }

    pub(crate) fn recover_interrupted_dispatches(&mut self) -> StorageResult<()> {
        let records = self.unresolved_dispatches()?;
        if records.is_empty() {
            return Ok(());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for mut record in records {
            record.reconciliation_required = true;
            for step in &mut record.steps {
                if step.dispatch != DispatchEvidence::NotSent && !step.finished && step.write_effect
                {
                    let independently_settled = step.dispatch == DispatchEvidence::Observed
                        && step.effect != EffectEvidence::Unknown
                        && !step.further_effects_possible;
                    if !independently_settled {
                        step.further_effects_possible = true;
                        if step.effect == EffectEvidence::NoneConfirmed {
                            step.effect = EffectEvidence::Unknown;
                        }
                    }
                }
            }
            record.state = if record.cancellation_requested {
                OperationState::CancelRequested
            } else {
                aggregate_pending(&record)
            };
            if record
                .steps
                .iter()
                .any(|s| s.write_effect && !s.finished && s.dispatch != DispatchEvidence::NotSent)
            {
                transaction.execute("INSERT OR IGNORE INTO write_fences(operation_id,scope_json,whole_project) VALUES(?1,?2,?3)",
                    params![record.operation_id.as_str(),encode(&record.scope)?,i64::from(record.whole_project_fence)])?;
            }
            write_record(&transaction, &record, "restart_requires_reconciliation")?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn stored_invocation(
        &self,
        operation: &OperationId,
        step: &StepId,
    ) -> StorageResult<Value> {
        self.stored_invocation_checked(operation, step, 8 * 1024 * 1024, || Ok(()))
    }

    /// Original intent metadata only. A BlobRef is not a caller read grant;
    /// transport code still verifies current operation/context authority.
    pub fn stored_invocation_blob(
        &self,
        operation: &OperationId,
        step: &StepId,
    ) -> StorageResult<BlobRef> {
        let record = read_record(&self.connection, operation)?;
        let actual = record
            .steps
            .iter()
            .find(|stored| &stored.step_id == step)
            .ok_or(StorageError::NotFound("Original invocation step"))?;
        let row: Option<(String, String, String, i64)> = self.connection.query_row(
            "SELECT i.invocation_id,i.invocation_hash,i.blob_digest,b.byte_length FROM invocations i JOIN blobs b ON b.digest=i.blob_digest WHERE i.operation_id=?1 AND i.step_id=?2",
            params![operation.as_str(),step.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let (id, hash, digest, length) = row.ok_or(StorageError::NotFound("Durable invocation"))?;
        let blob = BlobRef {
            digest: Sha256Digest::new(digest).map_err(|e| StorageError::Corrupt(e.to_string()))?,
            byte_length: u64::try_from(length)
                .map_err(|_| StorageError::Corrupt("Negative invocation blob length".into()))?,
        };
        if actual.dispatch == DispatchEvidence::NotSent
            || actual.invocation_id.as_ref().map(InvocationId::as_str) != Some(id.as_str())
            || actual.invocation_digest.as_ref() != Some(&blob.digest)
            || hash != blob.digest.as_str()
        {
            return Err(StorageError::Conflict(
                "Original invocation index and journal",
            ));
        }
        let retained: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM blob_refs WHERE owner_kind='operation' AND owner_id=?1 AND digest=?2)",
            params![operation.as_str(),blob.digest.as_str()],|r|r.get(0))?;
        if retained != 1 {
            return Err(StorageError::NotFound("Retained original invocation"));
        }
        Ok(blob)
    }

    /// Read the original bytes from one verified CAS handle with <=64KiB
    /// chunks, a finite caller ceiling and cooperative cancellation/deadline.
    pub fn stored_invocation_checked(
        &self,
        operation: &OperationId,
        step: &StepId,
        max_bytes: u64,
        mut check: impl FnMut() -> StorageResult<()>,
    ) -> StorageResult<Value> {
        check()?;
        let blob = self.stored_invocation_blob(operation, step)?;
        let value = self
            .validator
            .parse_and_validate(
                "Invocation",
                &self.read_blob_checked(&blob, max_bytes, &mut check)?,
            )
            .map_err(|e| StorageError::Contract(e.to_string()))?;
        let record = read_record(&self.connection, operation)?;
        let actual = record
            .steps
            .iter()
            .find(|stored| &stored.step_id == step)
            .ok_or(StorageError::NotFound("Original invocation step"))?;
        if value["operationId"] != operation.as_str()
            || value["stepId"] != step.as_str()
            || value["invocationId"].as_str()
                != actual.invocation_id.as_ref().map(InvocationId::as_str)
            || value["context"]["principalRef"] != record.principal.as_str()
            || value["context"]["projectId"] != record.project_id.as_str()
            || value["argumentsDigest"]
                != mmmm_contracts::canonical_digest(&value["arguments"])
                    .map_err(|e| StorageError::Contract(e.to_string()))?
                    .as_str()
            || value["contextDigest"]
                != mmmm_contracts::verify_projected_digest("ExecutionContext", &value["context"])
                    .map_err(|e| StorageError::Contract(e.to_string()))?
                    .as_str()
            || self.stored_invocation_blob(operation, step)? != blob
        {
            return Err(StorageError::Conflict(
                "Original invocation identity/digest changed",
            ));
        }
        check()?;
        Ok(value)
    }
}

fn aggregate_pending(record: &OperationRecord) -> OperationState {
    let some = record.steps.iter().any(|s| {
        matches!(
            s.effect,
            EffectEvidence::SomeConfirmed | EffectEvidence::CompleteConfirmed
        )
    });
    let unknown = record
        .steps
        .iter()
        .any(|s| s.effect == EffectEvidence::Unknown || s.further_effects_possible);
    if some && unknown {
        OperationState::Partial
    } else if unknown {
        OperationState::OutcomeUnknown
    } else {
        OperationState::Running
    }
}

pub(crate) fn step_verified(step: &StepRecord) -> bool {
    step.finished
        && !step.further_effects_possible
        && step.effect != EffectEvidence::Unknown
        && match step.verification_requirement {
            VerificationRequirement::SchemaOnly => step.dispatch >= DispatchEvidence::Sent,
            VerificationRequirement::ProviderCompletion => {
                step.dispatch >= DispatchEvidence::Acknowledged
            }
            VerificationRequirement::IndependentReadback => {
                step.dispatch == DispatchEvidence::Observed && !step.observation_refs.is_empty()
            }
        }
        && (!step.write_effect || step.effect == EffectEvidence::CompleteConfirmed)
}

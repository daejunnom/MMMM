//! Actual completed calibration issuance shared by bootstrap and production.
//! Empty construction is harmless; only the private bootstrap issuer retains
//! records. A consumer borrows the currently entered request, never a retained
//! bootstrap budget, and uses the existing Runtime operation transaction.

use crate::{
    authority::LocalAuthority,
    bootstrap::{
        NativeWorkspacePermit,
        calibration_approval::{policy_digest_for_rpc, verify_normative_plan},
    },
    host::CalibrationHostRoute,
    peer_management::{BootstrapBudget, BootstrapWitness, CompletedBootstrap, ManagementError},
    service::RequestContextWitness,
    workspace_bootstrap::NativeOwnerWitness,
};
use mmmm_application::{Access, AppError, AppResult, AuthorityPort};
use mmmm_contracts::{OperationId, PrincipalId, RequestId, StepId, canonical_digest};
use mmmm_runtime::storage::{
    BlobRef, DurableStore, OperationRecord, StepRecord, StorageError, StorageResult,
    calibration_approval::{
        CalibrationApprovalAuthority, CalibrationApprovalRecord, CalibrationApprovalRpcContext,
        CalibrationConfirmationRequest, CalibrationDispatchRequest, CalibrationSelectionRecord,
        CalibrationSelectionRequest, dispatch_calibration_intent, verify_calibration_intent_claim,
    },
    project_resources::ProjectSourceRpcContext,
};
use serde_json::Value;
use std::{cell::RefCell, collections::BTreeMap, path::PathBuf, rc::Rc, sync::Arc, time::Instant};

/// Opaque in-process composition handle. Default creates an empty registry,
/// not a confirmed record, source witness, live route, or Apply permission.
#[derive(Clone, Default)]
pub struct CalibrationRegistry {
    entries: Rc<RefCell<BTreeMap<String, Rc<ConfirmedCalibration>>>>,
    // Numeric approval records retain their exact storage contract. PACK is a
    // closed sibling record in the same process index, using the same journal.
    pack_runs: crate::calibration_pack_run::PackRunRegistry,
    pending: Rc<RefCell<BTreeMap<RequestId, Rc<()>>>>,
}

/// A private reservation follows the actual pending witness even while its
/// owner temporarily removes the pending record to perform a completion check.
/// It cannot be cloned or constructed from a public approval frame.
pub(crate) struct CalibrationPendingSlot {
    lease: CalibrationCapacityLease,
    witness: BootstrapWitness,
    budget: BootstrapBudget,
    owner: NativeOwnerWitness,
    store: *const DurableStore,
    store_root: PathBuf,
}

struct CalibrationCapacityLease {
    pending: Rc<RefCell<BTreeMap<RequestId, Rc<()>>>>,
    id: RequestId,
    identity: Rc<()>,
}

impl Drop for CalibrationCapacityLease {
    fn drop(&mut self) {
        // A conflicting borrow must retain the reservation rather than make a
        // possibly live allocation disappear from the shared capacity bound.
        if let Ok(mut pending) = self.pending.try_borrow_mut() {
            if pending
                .get(&self.id)
                .is_some_and(|actual| Rc::ptr_eq(actual, &self.identity))
            {
                pending.remove(&self.id);
            }
        }
    }
}

/// Sealed identity of a real pending reservation promoted by its own private
/// completion. A public RequestId is never sufficient to obtain this value.
pub(crate) struct CalibrationConfirmedSlot {
    identity: Rc<()>,
    witness: BootstrapWitness,
    budget: BootstrapBudget,
    owner: NativeOwnerWitness,
    store: *const DurableStore,
    store_root: PathBuf,
    completion: Arc<CompletedBootstrap>,
}

impl CalibrationPendingSlot {
    pub(crate) fn confirmed(
        &self,
        completion: &Arc<CompletedBootstrap>,
    ) -> CalibrationConfirmedSlot {
        // This is an identity transfer after the protected receipt committed,
        // not another mutable budget/owner admission that could hide its truth.
        CalibrationConfirmedSlot {
            identity: self.lease.identity.clone(),
            witness: self.witness.clone(),
            budget: self.budget.clone(),
            owner: self.owner.clone(),
            store: self.store,
            store_root: self.store_root.clone(),
            completion: completion.clone(),
        }
    }
}

impl CalibrationConfirmedSlot {
    fn matches(&self, value: &ConfirmedCalibration) -> bool {
        Arc::ptr_eq(&self.completion, &value.completion)
            && same_private_witness(&self.witness, value.completion.witness())
            && self.owner.principal() == &value.record.confirmation().principal_id
            && self.store_root == value.store_root
            && value.completion.delivered()
            && value.completion.completed_at() < self.budget.deadline()
    }
}

fn same_private_witness(actual: &BootstrapWitness, expected: &BootstrapWitness) -> bool {
    actual.id() == expected.id()
        && actual.nonce() == expected.nonce()
        && actual.offer_digest() == expected.offer_digest()
        && actual.is_calibration_plan() == expected.is_calibration_plan()
        && actual.is_manual_scene() == expected.is_manual_scene()
}

#[cfg(test)]
mod pending_capacity_tests {
    use super::*;

    #[test]
    fn pending_witness_reservations_share_the_existing_eight_slot_bound() {
        let registry = CalibrationRegistry::default();
        let mut slots = Vec::new();
        for index in 0..8 {
            let id = RequestId::new(format!("pending-{index}"))
                .unwrap_or_else(|_| panic!("valid request id"));
            slots.push(
                registry
                    .reserve_capacity(&id)
                    .unwrap_or_else(|_| panic!("available shared capacity")),
            );
        }
        let ninth = RequestId::new("pending-8").unwrap_or_else(|_| panic!("valid request id"));
        assert!(matches!(registry.len(), Ok(8)));
        assert!(matches!(
            registry.reserve_capacity(&ninth),
            Err(ManagementError::Busy)
        ));
        slots.pop();
        assert!(matches!(registry.len(), Ok(7)));
        let replacement = registry
            .reserve_capacity(&ninth)
            .unwrap_or_else(|_| panic!("retired pending slot is available"));
        assert!(matches!(registry.len(), Ok(8)));
        drop(replacement);
        drop(slots);
        assert!(matches!(registry.len(), Ok(0)));
    }

    #[test]
    fn duplicate_witness_and_conflicting_retirement_never_free_a_live_slot() {
        let registry = CalibrationRegistry::default();
        let id = RequestId::new("pending-same").unwrap_or_else(|_| panic!("valid request id"));
        let slot = registry
            .reserve_capacity(&id)
            .unwrap_or_else(|_| panic!("available shared capacity"));
        assert!(matches!(
            registry.reserve_capacity(&id),
            Err(ManagementError::WrongReply)
        ));
        let held = registry.pending.borrow();
        drop(slot);
        drop(held);
        assert!(matches!(registry.len(), Ok(1)));
        assert!(matches!(
            registry.reserve_capacity(&id),
            Err(ManagementError::WrongReply)
        ));
    }
}

pub(crate) struct ConfirmedCalibration {
    pub(crate) record: CalibrationApprovalRecord,
    pub(crate) route: CalibrationHostRoute,
    pub(crate) completion: Arc<CompletedBootstrap>,
    pub(crate) publication_failure: Option<Arc<AppError>>,
    pub(crate) store_root: PathBuf,
    pub(crate) capacity: CalibrationConfirmedSlot,
}

impl CalibrationRegistry {
    pub(crate) fn pack_runs(&self) -> &crate::calibration_pack_run::PackRunRegistry {
        &self.pack_runs
    }
    pub(crate) fn len(&self) -> Result<usize, ManagementError> {
        let entries = self
            .entries
            .try_borrow()
            .map_err(|_| ManagementError::TransportUncertain)?;
        let pending = self
            .pending
            .try_borrow()
            .map_err(|_| ManagementError::TransportUncertain)?;
        let pending = pending
            .values()
            .filter(|identity| {
                !entries.values().any(|entry| {
                    entry.capacity.matches(entry) && Rc::ptr_eq(&entry.capacity.identity, identity)
                })
            })
            .count();
        entries
            .len()
            .checked_add(self.pack_runs.len()?)
            .and_then(|count| count.checked_add(pending))
            .ok_or(ManagementError::TransportUncertain)
    }
    pub(crate) fn reserve_pending(
        &self,
        store: &DurableStore,
        witness: &BootstrapWitness,
        budget: &BootstrapBudget,
        owner: &NativeOwnerWitness,
    ) -> Result<CalibrationPendingSlot, ManagementError> {
        budget.check()?;
        owner
            .check_store(store)
            .map_err(|_| ManagementError::WrongReply)?;
        let lease = self.reserve_capacity(witness.id())?;
        Ok(CalibrationPendingSlot {
            lease,
            witness: witness.clone(),
            budget: budget.clone(),
            owner: owner.clone(),
            store: store as *const DurableStore,
            store_root: store.data_root().to_path_buf(),
        })
    }
    fn reserve_capacity(
        &self,
        id: &RequestId,
    ) -> Result<CalibrationCapacityLease, ManagementError> {
        if self.len()? >= 8 {
            return Err(ManagementError::Busy);
        }
        if self
            .entries
            .try_borrow()
            .map_err(|_| ManagementError::TransportUncertain)?
            .values()
            .any(|entry| entry.completion.witness().id() == id)
        {
            return Err(ManagementError::WrongReply);
        }
        let mut pending = self
            .pending
            .try_borrow_mut()
            .map_err(|_| ManagementError::TransportUncertain)?;
        if pending.contains_key(id) {
            return Err(ManagementError::WrongReply);
        }
        let identity = Rc::new(());
        pending.insert(id.clone(), identity.clone());
        Ok(CalibrationCapacityLease {
            pending: self.pending.clone(),
            id: id.clone(),
            identity,
        })
    }
    pub(crate) fn contains(&self, id: &str) -> Result<bool, ManagementError> {
        Ok(self
            .entries
            .try_borrow()
            .map_err(|_| ManagementError::TransportUncertain)?
            .contains_key(id))
    }
    /// No replacement: one confirmed private generation stays attached to the
    /// immutable approval until exact retirement. Failed publication is retained
    /// as a denied factual record and never becomes admitted by map presence.
    pub(crate) fn insert(
        &self,
        id: String,
        value: Rc<ConfirmedCalibration>,
    ) -> Result<(), ManagementError> {
        let total = self.len()?;
        let owns_pending = value.capacity.matches(&value)
            && self
                .pending
                .try_borrow()
                .map_err(|_| ManagementError::TransportUncertain)?
                .values()
                .any(|actual| Rc::ptr_eq(actual, &value.capacity.identity));
        // Promotion consumes the same actual witness's reservation; it is not
        // a ninth allocation. After insertion len() deduplicates that witness.
        let retained = total
            .checked_sub(usize::from(owns_pending))
            .ok_or(ManagementError::TransportUncertain)?;
        let mut entries = self
            .entries
            .try_borrow_mut()
            .map_err(|_| ManagementError::TransportUncertain)?;
        if entries.contains_key(&id)
            || entries
                .values()
                .any(|entry| entry.completion.witness().id() == value.completion.witness().id())
            || retained >= 8
            || id != value.record.selection().approval_ref()
            || !value.capacity.matches(&value)
        {
            return Err(ManagementError::WrongReply);
        }
        entries.insert(id, value);
        Ok(())
    }
    pub(crate) fn expired(&self, shutdown: bool) -> Result<Vec<String>, ManagementError> {
        let entries = self
            .entries
            .try_borrow()
            .map_err(|_| ManagementError::TransportUncertain)?;
        Ok(entries
            .iter()
            .filter(|(_, value)| shutdown || Instant::now() >= value.route.lease_expires())
            .map(|(id, _)| id.clone())
            .collect())
    }
    pub(crate) fn remove(
        &self,
        id: &str,
    ) -> Result<Option<Rc<ConfirmedCalibration>>, ManagementError> {
        Ok(self
            .entries
            .try_borrow_mut()
            .map_err(|_| ManagementError::TransportUncertain)?
            .remove(id))
    }
    pub(crate) fn matches_plan(&self, plan: &Value) -> AppResult<bool> {
        let entries = self.entries.try_borrow().map_err(|_| unavailable())?;
        Ok(entries.values().any(|entry| {
            let pins = entry.record.selection().pins();
            plan["projectId"] == pins.project_id.as_str()
                && plan["planId"] == pins.plan_id.as_str()
                && plan["planHash"] == pins.plan_hash.as_str()
        }))
    }
    pub(crate) fn enter<'a>(
        &self,
        store: &DurableStore,
        request: &'a RequestContextWitness,
        authority: &'a LocalAuthority,
        operation: &OperationId,
        original: &Value,
        access: CalibrationAccess,
    ) -> AppResult<Option<EnteredCalibration<'a>>> {
        let result = self.enter_checked(store, request, authority, operation, original, access);
        finish(result, request.check_local().map_err(request_error))
    }
    fn enter_checked<'a>(
        &self,
        store: &DurableStore,
        request: &'a RequestContextWitness,
        authority: &'a LocalAuthority,
        operation: &OperationId,
        original: &Value,
        access: CalibrationAccess,
    ) -> AppResult<Option<EnteredCalibration<'a>>> {
        request.check_local().map_err(request_error)?;
        let operation = store.operation(operation).map_err(storage_error)?;
        let entry = {
            let entries = self.entries.try_borrow().map_err(|_| unavailable())?;
            entries
                .values()
                .find(|entry| {
                    let pins = entry.record.selection().pins();
                    operation.project_id == pins.project_id
                        && operation.plan_id == pins.plan_id
                        && operation.plan_hash == pins.plan_hash
                })
                .cloned()
        };
        let Some(entry) = entry else {
            return Ok(None);
        };
        if let Some(cause) = &entry.publication_failure {
            return Err(AppError::caused_by(
                cause.code,
                cause.message,
                RetainedPublicationFailure(cause.clone()),
            ));
        }
        if !std::ptr::eq(store, entry.capacity.store)
            || store.data_root() != entry.store_root.as_path()
        {
            return Err(unavailable());
        }
        let owner = NativeOwnerWitness::capture(store, request.budget().deadline())
            .map_err(storage_error)?;
        let pins = entry.record.selection().pins();
        let plan = store
            .plan(&pins.plan_id, &pins.plan_hash)
            .map_err(storage_error)?;
        let entered = EnteredCalibration {
            registry: self.clone(),
            entry,
            request,
            authority,
            owner,
            operation,
            plan,
            original: original.clone(),
            access,
        };
        let result = (|| {
            entered.check_local(store)?;
            let suite = verify_normative_plan(&entered.plan).map_err(storage_error)?;
            let pins = entered.approval().selection().pins();
            if suite.suite_digest() != &pins.suite_digest || pins.recipe.digest != pins.suite_digest
            {
                return Err(unavailable());
            }
            let recipe = store
                .read_blob_checked(
                    &pins.recipe,
                    mmmm_runtime::storage::calibration_approval::MAX_CALIBRATION_RECIPE_BYTES,
                    || entered.check_storage(),
                )
                .map_err(storage_error)?;
            if recipe.as_slice() != suite.canonical_recipe_bytes() {
                return Err(unavailable());
            }
            // Read Policy CAS once before the writer transaction. Its exact
            // immutable Project revision is rechecked locally in every callback.
            if policy_digest_for_rpc(
                store,
                &entered.owner,
                &entered,
                &pins.project_id,
                &pins.project_base_revision,
            )
            .map_err(storage_error)?
                != pins.policy_digest
            {
                return Err(unavailable());
            }
            Ok(())
        })();
        finish(result, entered.check_local(store))?;
        Ok(Some(entered))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CalibrationAccess {
    Apply,
    Observe,
    Cancel,
}

type FreshCalibrationPrepare<'a> = dyn FnMut(&CalibrationHostRoute, &RequestContextWitness, &Value, &mut DurableStore) -> AppResult<()>
    + 'a;

/// The reference prevents this authority from outliving its actual entered
/// service request. Neither this type nor its request is stored in the registry.
pub(crate) struct EnteredCalibration<'a> {
    registry: CalibrationRegistry,
    entry: Rc<ConfirmedCalibration>,
    request: &'a RequestContextWitness,
    authority: &'a LocalAuthority,
    owner: NativeOwnerWitness,
    operation: OperationRecord,
    plan: Value,
    original: Value,
    access: CalibrationAccess,
}

impl EnteredCalibration<'_> {
    pub(crate) fn route(&self) -> &CalibrationHostRoute {
        &self.entry.route
    }
    pub(crate) fn request(&self) -> &RequestContextWitness {
        self.request
    }
    pub(crate) fn original(&self) -> &Value {
        &self.original
    }
    pub(crate) fn operation(&self) -> &OperationRecord {
        &self.operation
    }
    pub(crate) fn approval(&self) -> &CalibrationApprovalRecord {
        &self.entry.record
    }
    fn check_storage(&self) -> StorageResult<()> {
        self.request
            .check_local()
            .map_err(|cause| app_to_storage(request_error(cause)))?;
        self.owner.check()
    }
    pub(crate) fn check_local(&self, store: &DurableStore) -> AppResult<()> {
        self.check_storage().map_err(storage_error)?;
        let entries = self
            .registry
            .entries
            .try_borrow()
            .map_err(|_| unavailable())?;
        if entries
            .get(self.approval().selection().approval_ref())
            .is_none_or(|entry| !Rc::ptr_eq(entry, &self.entry))
        {
            return Err(unavailable());
        }
        drop(entries);
        let pins = self.approval().selection().pins();
        self.owner
            .check_project(store, &pins.project_id)
            .map_err(storage_error)?;
        let current = store
            .operation(&self.operation.operation_id)
            .map_err(storage_error)?;
        let context = self.route().context();
        let principal = self.request.authenticated().principal();
        if !std::ptr::eq(store, self.entry.capacity.store)
            || store.data_root() != self.entry.store_root.as_path()
            || self.owner.principal() != self.approval().selection().native_owner()
            || current.project_id != pins.project_id
            || current.plan_id != pins.plan_id
            || current.plan_hash != pins.plan_hash
            || &current.principal != principal
            || current.principal != self.approval().confirmation().principal_id
            || current.context_id.as_str() != context["contextId"].as_str().unwrap_or("")
            || store.project(&pins.project_id).map_err(storage_error)?["revision"]
                != pins.project_base_revision.as_str()
            || store
                .plan(&pins.plan_id, &pins.plan_hash)
                .map_err(storage_error)?
                != self.plan
            || canonical_digest(&self.plan["scope"]).map_err(|_| unavailable())?
                != pins.scope_digest
            || serde_json::to_value(&current.scope).map_err(|_| unavailable())?
                != self.plan["scope"]
            || self.plan["contextPins"] != pins.context_pins
            || pins.context_pins[0]["contextDigest"] != context["contextDigest"]
            || pins.context_pins[0]["environment"] != context["environment"]
            || self.plan["policyRevision"] != pins.policy_revision.as_str()
            || context["policyRevision"] != pins.policy_revision.as_str()
            || context["principalRef"] != principal.as_str()
            || context["environment"]["sessionEpoch"] != self.approval().confirmation().host_epoch
            || !self.entry.completion.delivered()
            || self.entry.completion.witness().nonce()
                != self.approval().confirmation().nonce.as_str()
            || self.entry.completion.witness().offer_digest()
                != &self.approval().confirmation().original_offer_digest
        {
            return Err(unavailable());
        }
        self.check_original(&self.original)?;
        self.route().check_current(self.request)?;
        self.authority.authorize_retained_scope(
            principal,
            &pins.project_id,
            &current.context_id,
            &pins.policy_revision,
            &self.plan["scope"],
        )?;
        self.authority.authorize_retained_scope(
            principal,
            &pins.project_id,
            &current.context_id,
            &pins.policy_revision,
            &context["scope"],
        )?;
        match self.access {
            CalibrationAccess::Apply => {
                if self.request.method() != "plan.apply" {
                    return Err(unavailable());
                }
                let expiry = time::OffsetDateTime::parse(
                    &pins.expires_at,
                    &time::format_description::well_known::Rfc3339,
                )
                .map_err(|_| unavailable())?;
                if time::OffsetDateTime::now_utc() >= expiry {
                    return Err(unavailable());
                }
                self.authority
                    .authorize_retained_apply(principal, context, &self.plan)?;
            }
            CalibrationAccess::Observe | CalibrationAccess::Cancel => {
                let mut authority = self.authority.clone();
                authority.authorize_operation(
                    principal,
                    &current,
                    if self.access == CalibrationAccess::Observe {
                        Access::ObserveOperation
                    } else {
                        Access::Cancel
                    },
                )?;
            }
        }
        self.check_storage().map_err(storage_error)
    }
    fn check_original(&self, original: &Value) -> AppResult<()> {
        let step = self.plan["steps"]
            .as_array()
            .ok_or_else(unavailable)?
            .iter()
            .find(|step| step["stepId"] == original["stepId"])
            .ok_or_else(unavailable)?;
        if original != &self.original
            || original["operationId"] != self.operation.operation_id.as_str()
            || original["context"] != *self.route().context()
            || original["contextDigest"] != original["context"]["contextDigest"]
            || original["argumentsDigest"]
                != canonical_digest(&original["arguments"])
                    .map_err(|_| unavailable())?
                    .as_str()
            || step["recovery"] != "none"
            || step["resultBindings"]
                .as_array()
                .is_none_or(|values| !values.is_empty())
            || [
                "bindingId",
                "actionId",
                "actionContractVersion",
                "actionDigest",
                "implementationDigest",
                "arguments",
            ]
            .iter()
            .any(|field| step[*field] != original[*field])
        {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(crate) fn verify_claim(&self, store: &DurableStore, original: &Value) -> AppResult<()> {
        let result = (|| {
            self.check_local(store)?;
            self.check_original(original)?;
            let step = StepId::new(original["stepId"].as_str().ok_or_else(unavailable)?)
                .map_err(|_| unavailable())?;
            verify_calibration_intent_claim(
                store,
                self.approval(),
                &self.operation.operation_id,
                &step,
                original,
                &|| self.check_storage(),
            )
            .map_err(storage_error)
        })();
        finish(result, self.check_local(store))
    }
    pub(crate) fn persist_intent(
        &self,
        store: &mut DurableStore,
        step: &StepId,
        original: &Value,
        resolution: Option<&BlobRef>,
        fresh_prepare: &mut FreshCalibrationPrepare<'_>,
    ) -> AppResult<StepRecord> {
        let result = (|| {
            self.check_local(store)?;
            self.check_original(original)?;
            if self.access != CalibrationAccess::Apply
                || resolution.is_some()
                || original["stepId"] != step.as_str()
            {
                return Err(unavailable());
            }
            // The actual private Java prepare checks current ADMIN/source and
            // the real runner. A null runner fails here before durable intent.
            finish(
                fresh_prepare(self.route(), self.request, original, store),
                self.check_local(store),
            )?;
            let mut authority = EnteredDispatchAuthority { entered: self };
            dispatch_calibration_intent(
                store,
                self,
                &mut authority,
                &CalibrationDispatchRequest {
                    approval_ref: self.approval().selection().approval_ref(),
                    operation_id: &self.operation.operation_id,
                    step_id: step,
                    invocation: original,
                },
            )
            .map_err(storage_error)
        })();
        match result {
            // Runtime already committed Invocation, fence and one-use claim.
            // Return that durable receipt unchanged. The provider's independent
            // pre-dispatch guard handles later cancellation/route retirement.
            Ok(committed) => Ok(committed),
            Err(primary) => finish(Err(primary), self.check_local(store)),
        }
    }
}

impl CalibrationApprovalRpcContext for EnteredCalibration<'_> {
    fn check(&self) -> StorageResult<()> {
        self.check_storage()
    }
    fn authenticated_local_owner(&self) -> StorageResult<PrincipalId> {
        self.check_storage()?;
        Ok(self.owner.principal().clone())
    }
    fn check_current_approval(
        &self,
        store: &DurableStore,
        approval: &CalibrationApprovalRecord,
    ) -> StorageResult<()> {
        if approval != self.approval() {
            return Err(app_to_storage(unavailable()));
        }
        // Only local ownership/request/SQLite/current grant checks; the actual
        // private prepare already ran outside the journal writer transaction.
        self.check_local(store).map_err(app_to_storage)
    }
}
impl ProjectSourceRpcContext for EnteredCalibration<'_> {
    fn check(&self) -> StorageResult<()> {
        self.check_storage()
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check_storage()?;
        Ok(self.owner.principal().clone())
    }
    fn context_id(&self) -> Option<&mmmm_contracts::ContextId> {
        None
    }
}
struct EnteredDispatchAuthority<'a, 'request> {
    entered: &'a EnteredCalibration<'request>,
}
impl CalibrationApprovalAuthority for EnteredDispatchAuthority<'_, '_> {
    fn authorize_selection(
        &mut self,
        _: &DurableStore,
        _: &PrincipalId,
        _: &CalibrationSelectionRequest,
    ) -> StorageResult<()> {
        Err(app_to_storage(unavailable()))
    }
    fn authorize_confirmation(
        &mut self,
        _: &DurableStore,
        _: &CalibrationSelectionRecord,
        _: &CalibrationConfirmationRequest,
    ) -> StorageResult<()> {
        Err(app_to_storage(unavailable()))
    }
    fn authorize_dispatch(
        &mut self,
        store: &DurableStore,
        approval: &CalibrationApprovalRecord,
        original: &Value,
    ) -> StorageResult<()> {
        if self.entered.access != CalibrationAccess::Apply || approval != self.entered.approval() {
            return Err(app_to_storage(unavailable()));
        }
        self.entered
            .check_original(original)
            .map_err(app_to_storage)?;
        self.entered.check_local(store).map_err(app_to_storage)
    }
}
fn unavailable() -> AppError {
    AppError::new(
        "CALIBRATION_APPROVAL_UNAVAILABLE",
        "원 calibration 승인, 요청, plan 또는 private route가 현재 상태와 일치하지 않습니다",
    )
}
fn storage_error(cause: StorageError) -> AppError {
    AppError::storage("CALIBRATION_APPROVAL_UNAVAILABLE", cause)
}
fn request_error(cause: crate::service::ServiceError) -> AppError {
    AppError::caused_by(cause.code, cause.message, cause)
}
fn app_to_storage(cause: AppError) -> StorageError {
    StorageError::Io(std::io::Error::other(cause))
}
#[derive(Debug)]
struct RetainedPublicationFailure(Arc<AppError>);
impl std::fmt::Display for RetainedPublicationFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("Original calibration publication failure is retained")
    }
}
impl std::error::Error for RetainedPublicationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
fn finish<T>(result: AppResult<T>, checkpoint: AppResult<()>) -> AppResult<T> {
    match (result, checkpoint) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(cause), Ok(())) | (Ok(_), Err(cause)) => Err(cause),
        (Err(primary), Err(checkpoint)) => Err(AppError::caused_by(
            primary.code,
            primary.message,
            StorageError::CalibrationCheckpointFailure {
                primary: Box::new(app_to_storage(primary)),
                checkpoint: Box::new(app_to_storage(checkpoint)),
            },
        )),
    }
}

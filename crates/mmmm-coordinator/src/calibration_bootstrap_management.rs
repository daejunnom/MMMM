//! 최초 pack bootstrap의 별도 private ADMIN 교환. numeric 승인을 확대하지 않는다.
use super::*;
use crate::{
    calibration_bootstrap::{self as purpose, BootstrapRegistry, ConfirmedBootstrap},
    host::{BootstrapHostRoute, BootstrapRouteBudget},
    workspace_bootstrap::NativeOwnerWitness,
};
use mmmm_compiler::calibration::{CalibrationPackProgram, CalibrationSourceKind};
use mmmm_contracts::{PlanId, raw_digest};

pub(super) struct BootstrapApprovals {
    pub(super) registry: BootstrapRegistry,
    pending: BTreeMap<RequestId, Pending>,
    failures: Vec<Pending>,
    diagnostics: std::cell::RefCell<Vec<Diagnostic>>,
}
struct Diagnostic {
    _original_offer: Arc<PublicFrame>,
    _cause: mmmm_application::AppError,
}
struct Pending {
    public: Arc<PublicFrame>,
    witness: BootstrapWitness,
    token: Option<SecretToken>,
    budget: BootstrapBudget,
    plan: Value,
    context: Value,
    manifest: Value,
    route: Option<BootstrapHostRoute>,
    complete_issued: bool,
    completion: Option<Arc<CompletedBootstrap>>,
    failure: Option<Arc<mmmm_application::AppError>>,
}
impl BootstrapApprovals {
    pub(super) fn new(registry: BootstrapRegistry) -> Self {
        Self {
            registry,
            pending: BTreeMap::new(),
            failures: vec![],
            diagnostics: std::cell::RefCell::new(vec![]),
        }
    }
}

fn invalid() -> ManagementError {
    ManagementError::InvalidFrame
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str, ManagementError> {
    value[key].as_str().ok_or_else(invalid)
}
fn exact(value: &Value, fields: &[&str]) -> Result<(), ManagementError> {
    purpose::exact(value, fields).map_err(|_| invalid())
}
fn sha(value: &Value, key: &str) -> Result<(), ManagementError> {
    Sha256Digest::new(field(value, key)?)
        .map(|_| ())
        .map_err(|_| invalid())
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], ManagementError> {
    value[key].as_array().map(Vec::as_slice).ok_or_else(invalid)
}
fn instant(value: &str) -> Result<time::OffsetDateTime, ManagementError> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|_| invalid())
}
fn same(a: &BootstrapWitness, b: &BootstrapWitness) -> bool {
    a.id() == b.id() && a.nonce() == b.nonce() && a.offer_digest() == b.offer_digest()
}
fn retain_error(
    approvals: &BootstrapApprovals,
    public: &Arc<PublicFrame>,
    cause: mmmm_application::AppError,
) -> ManagementError {
    if let Ok(mut diagnostics) = approvals.diagnostics.try_borrow_mut()
        && diagnostics.len() < MAX_REJECTED_COMPLETIONS
    {
        diagnostics.push(Diagnostic {
            _original_offer: public.clone(),
            _cause: cause,
        });
        return invalid();
    }
    ManagementError::TransportUncertain
}

/// Closed grammar only. The processor independently proves current owner,
/// original source CAS, active read owner and actual completed native exchange.
pub(crate) fn validate_frame(
    value: &Value,
    validator: &ContractValidator,
) -> Result<ManagementKind, ManagementError> {
    if !purpose::is_purpose(field(value, "purpose")?) {
        return Err(invalid());
    }
    match field(value, "kind")? {
        "host_apply_approval_offer" => {
            exact(
                value,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "purpose",
                    "dataRoot",
                    "projectId",
                    "principalId",
                    "playerId",
                    "planId",
                    "planHash",
                    "hostArtifactDigest",
                    "hostHello",
                    "contextIds",
                    "runtimeSourceFacts",
                ],
            )?;
            let root = field(value, "dataRoot")?;
            if root.len() > 4096
                || root.chars().any(char::is_control)
                || !Path::new(root).is_absolute()
            {
                return Err(invalid());
            }
            ProjectId::new(field(value, "projectId")?).map_err(|_| invalid())?;
            PlanId::new(field(value, "planId")?).map_err(|_| invalid())?;
            PrincipalId::new(field(value, "principalId")?).map_err(|_| invalid())?;
            RequestId::new(field(value, "playerId")?).map_err(|_| invalid())?;
            sha(value, "planHash")?;
            sha(value, "hostArtifactDigest")?;
            validator
                .validate("HostHello", &value["hostHello"])
                .map_err(|_| invalid())?;
            let ids = array(value, "contextIds")?;
            if ids.len() != 1 || !value["runtimeSourceFacts"].is_object() {
                return Err(invalid());
            }
            ContextId::new(ids[0].as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
            Ok(ManagementKind::Offer)
        }
        "host_apply_approval_authority" => {
            exact(
                value,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "purpose",
                    "contexts",
                    "approvedSources",
                    "approvedActions",
                    "permissions",
                    "manifest",
                ],
            )?;
            let contexts = array(value, "contexts")?;
            if contexts.len() != 1 {
                return Err(invalid());
            }
            validator
                .validate("ExecutionContext", &contexts[0])
                .map_err(|_| invalid())?;
            mmmm_contracts::verify_projected_digest("ExecutionContext", &contexts[0])
                .map_err(|_| invalid())?;
            let sources = value["approvedSources"].as_object().ok_or_else(invalid)?;
            if sources.len() != 1 || !sources.contains_key(NATIVE_SOURCE_ID) {
                return Err(invalid());
            }
            Sha256Digest::new(sources[NATIVE_SOURCE_ID].as_str().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
            let permissions = array(value, "permissions")?
                .iter()
                .map(|v| v.as_str().ok_or_else(invalid))
                .collect::<Result<BTreeSet<_>, _>>()?;
            if array(value, "permissions")?.len() != READ_PERMISSIONS.len()
                || permissions != BTreeSet::from(READ_PERMISSIONS)
            {
                return Err(invalid());
            }
            validate_manifest(&value["manifest"], validator)?;
            let manifest = &value["manifest"];
            let plan = &manifest["plan"];
            let context = &contexts[0];
            if value["purpose"] != manifest["purpose"]
                || context["principalRef"] != plan["principalId"]
                || context["projectId"] != plan["projectId"]
                || context["contextId"] != plan["contextPins"][0]["contextId"]
                || context["contextDigest"] != plan["contextPins"][0]["contextDigest"]
                || context["environment"] != plan["contextPins"][0]["environment"]
                || value["approvedActions"] != json!([plan["steps"][0]["actionDigest"]])
                || !plan["steps"][0]["resourcesWritten"]
                    .as_array()
                    .is_some_and(|targets| {
                        targets.iter().all(|target| {
                            context["scope"]["externalTargetIds"]
                                .as_array()
                                .is_some_and(|scope| scope.contains(target))
                        })
                    })
            {
                return Err(invalid());
            }
            Ok(ManagementKind::Authority)
        }
        "host_apply_approval_installed" => {
            exact(
                value,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "purpose",
                    "selectionDigest",
                    "manifestDigest",
                    "hostEndpoint",
                ],
            )?;
            sha(value, "selectionDigest")?;
            sha(value, "manifestDigest")?;
            let endpoint = &value["hostEndpoint"];
            exact(endpoint, &["address", "path", "hostEpoch"])?;
            let address: SocketAddr = field(endpoint, "address")?.parse().map_err(|_| invalid())?;
            if !address.is_ipv4()
                || !address.ip().is_loopback()
                || address.port() == 0
                || endpoint["path"] != "/rpc"
            {
                return Err(invalid());
            }
            SessionEpoch::new(field(endpoint, "hostEpoch")?).map_err(|_| invalid())?;
            Ok(ManagementKind::Installed)
        }
        "host_apply_approval_complete" => {
            exact(
                value,
                &[
                    "kind",
                    "protocolVersion",
                    "nonce",
                    "purpose",
                    "selectionDigest",
                    "manifestDigest",
                    "ready",
                    "coordinatorEpoch",
                    "hostEpoch",
                    "contextId",
                ],
            )?;
            sha(value, "selectionDigest")?;
            sha(value, "manifestDigest")?;
            if value["ready"] != true {
                return Err(invalid());
            }
            SessionEpoch::new(field(value, "coordinatorEpoch")?).map_err(|_| invalid())?;
            SessionEpoch::new(field(value, "hostEpoch")?).map_err(|_| invalid())?;
            ContextId::new(field(value, "contextId")?).map_err(|_| invalid())?;
            Ok(ManagementKind::Complete)
        }
        _ => Err(invalid()),
    }
}

fn validate_manifest(value: &Value, validator: &ContractValidator) -> Result<(), ManagementError> {
    exact(
        value,
        &[
            "kind",
            "purpose",
            "selectionDigest",
            "hostEpoch",
            "registryGeneration",
            "runtimeSourceFactsDigest",
            "suiteDigest",
            "recipeSha256",
            "plan",
            "sourceBundle",
            "programs",
        ],
    )?;
    let source_kind = purpose::kind_for_purpose(field(value, "purpose")?).ok_or_else(invalid)?;
    if value["kind"] != purpose::manifest_kind_for_kind(source_kind) {
        return Err(invalid());
    }
    for key in [
        "selectionDigest",
        "runtimeSourceFactsDigest",
        "suiteDigest",
        "recipeSha256",
    ] {
        sha(value, key)?;
    }
    SessionEpoch::new(field(value, "hostEpoch")?).map_err(|_| invalid())?;
    if field(value, "registryGeneration")?.is_empty()
        || field(value, "registryGeneration")?.len() > 256
    {
        return Err(invalid());
    }
    let suite = match source_kind {
        CalibrationSourceKind::Numeric47 => Some(
            mmmm_compiler::calibration_dispatch::CalibrationDispatchPlan::normative47()
                .map_err(|_| invalid())?,
        ),
        CalibrationSourceKind::PackCase => None,
    };
    let recipe_digest = match &suite {
        Some(suite) => suite.suite_digest().clone(),
        None => CalibrationPackProgram::java_26_3()
            .map_err(|_| invalid())?
            .program_digest()
            .clone(),
    };
    if value["suiteDigest"] != recipe_digest.as_str()
        || value["recipeSha256"] != recipe_digest.as_str()
    {
        return Err(invalid());
    }
    let bundle = &value["sourceBundle"];
    match source_kind {
        CalibrationSourceKind::Numeric47 => {
            exact(bundle, &["bundleDigest", "rawResource", "entries"])?;
        }
        CalibrationSourceKind::PackCase => {
            exact(
                bundle,
                &["bundleDigest", "rawResource", "entries", "sourceKind"],
            )?;
            if bundle["sourceKind"] != source_kind.name() {
                return Err(invalid());
            }
        }
    }
    let source_entries = source_kind.source_entries().map_err(|_| invalid())?;
    if source_entries.len() != source_kind.entry_count() {
        return Err(invalid());
    }
    let expected=source_entries.iter().map(|(path,bytes)|json!({"path":path,"rawSha256":raw_digest(bytes),"byteLength":bytes.len(),"rawBytesHex":bytes.iter().map(|byte|format!("{byte:02x}")).collect::<String>()})).collect::<Vec<_>>();
    if bundle["entries"] != json!(expected)
        || bundle["bundleDigest"]
            != canonical_digest(&bundle["entries"])
                .map_err(|_| invalid())?
                .as_str()
    {
        return Err(invalid());
    }
    validator
        .validate("ResourceRef", &bundle["rawResource"])
        .map_err(|_| invalid())?;
    let raw = mmmm_contracts::canonical_bytes(&bundle["entries"]).map_err(|_| invalid())?;
    if bundle["rawResource"]["sha256"] != raw_digest(&raw).as_str()
        || bundle["rawResource"]["sizeBytes"] != raw.len() as u64
    {
        return Err(invalid());
    }
    let expected = suite.as_ref().map(|suite| suite.programs().iter().map(|p|json!({"caseId":p.case().case_id(),"functionId":p.invocation_command().strip_prefix("function ").unwrap_or(""),"objective":p.scope().objective(),"storage":p.scope().storage(),"initializationCommands":p.initialization_commands()})).collect::<Vec<_>>()).unwrap_or_default();
    if value["programs"] != json!(expected) {
        return Err(invalid());
    }
    let plan = &value["plan"];
    exact(
        plan,
        &[
            "kind",
            "protocolVersion",
            "principalId",
            "projectId",
            "planId",
            "planHash",
            "policyRevision",
            "contextPins",
            "expiresAt",
            "steps",
            "nativeExecutions",
        ],
    )?;
    if plan["kind"] != "native_plan_approval"
        || plan["protocolVersion"] != mmmm_contracts::CONTRACT_VERSION
        || !array(plan, "nativeExecutions")?.is_empty()
        || array(plan, "steps")?.len() != 1
        || array(plan, "contextPins")?.len() != 1
    {
        return Err(invalid());
    }
    PrincipalId::new(field(plan, "principalId")?).map_err(|_| invalid())?;
    ProjectId::new(field(plan, "projectId")?).map_err(|_| invalid())?;
    PlanId::new(field(plan, "planId")?).map_err(|_| invalid())?;
    sha(plan, "planHash")?;
    sha(plan, "policyRevision")?;
    instant(field(plan, "expiresAt")?)?;
    validator
        .validate("ContextPin", &plan["contextPins"][0])
        .map_err(|_| invalid())?;
    let step = &plan["steps"][0];
    exact(
        step,
        &[
            "stepId",
            "bindingId",
            "actionId",
            "actionDigest",
            "implementationDigest",
            "argumentsDigest",
            "contextId",
            "contextDigest",
            "resourcesRead",
            "resourcesWritten",
            "preconditions",
        ],
    )?;
    let arguments = match source_kind {
        CalibrationSourceKind::Numeric47 => json!({"sourceBundleDigest":bundle["bundleDigest"]}),
        CalibrationSourceKind::PackCase => {
            json!({"command":"function mmmm_calibration:pack/entry"})
        }
    };
    if step["actionId"] != purpose::action_for_kind(source_kind)
        || step["contextId"] != plan["contextPins"][0]["contextId"]
        || step["contextDigest"] != plan["contextPins"][0]["contextDigest"]
        || step["argumentsDigest"]
            != canonical_digest(&arguments)
                .map_err(|_| invalid())?
                .as_str()
    {
        return Err(invalid());
    }
    for key in [
        "actionDigest",
        "implementationDigest",
        "argumentsDigest",
        "contextDigest",
    ] {
        sha(step, key)?;
    }
    for key in ["stepId", "bindingId", "contextId"] {
        RequestId::new(field(step, key)?).map_err(|_| invalid())?;
    }
    let mut targets = vec![json!(purpose::pack_target_for_kind(source_kind))];
    if let Some(suite) = &suite {
        for p in suite.programs() {
            targets.push(json!(format!(
                "calibration-objective-{}",
                p.scope().objective()
            )));
            targets.push(json!(format!(
                "calibration-storage-{}",
                raw_digest(p.scope().storage().as_str().as_bytes())
            )));
        }
    }
    let requirements = purpose::absence_requirements_for_kind(source_kind, &bundle["bundleDigest"])
        .map_err(|_| invalid())?;
    if step["resourcesRead"] != json!(targets)
        || step["resourcesWritten"] != json!(targets)
        || array(step, "preconditions")?.len() != requirements.len()
    {
        return Err(invalid());
    }
    for (condition, requirement) in array(step, "preconditions")?.iter().zip(requirements) {
        validator
            .validate("Precondition", condition)
            .map_err(|_| invalid())?;
        let expected =
            raw_digest(&mmmm_contracts::canonical_bytes(&requirement).map_err(|_| invalid())?);
        if *condition
            != json!({"kind":"resource_hash","subject":requirement["targetId"],"coverage":"full_target","expected":expected})
        {
            return Err(invalid());
        }
    }
    Ok(())
}

impl HostBootstrapProcessor {
    pub(super) fn has_bootstrap_witness(&self, witness: &BootstrapWitness) -> bool {
        self.pack_bootstrap.pending.contains_key(witness.id())
    }
    pub(super) fn bootstrap_offer(
        &mut self,
        store: &DurableStore,
        offer: HostOffer,
        budget: &BootstrapBudget,
        reply_deadline: Instant,
    ) -> Result<PublicFrame, ManagementError> {
        if self.pack_bootstrap.pending.len() + self.pack_bootstrap.failures.len() >= MAX_PENDING
            || self
                .pack_bootstrap
                .diagnostics
                .try_borrow()
                .map_err(|_| ManagementError::Busy)?
                .len()
                >= MAX_REJECTED_COMPLETIONS
        {
            return Err(ManagementError::Busy);
        }
        let (public, token, witness) = offer.into_parts();
        let public = Arc::new(public);
        let value = public.value();
        let offered_kind =
            purpose::kind_for_purpose(field(value, "purpose")?).ok_or_else(invalid)?;
        budget.check()?;
        if Instant::now() >= reply_deadline
            || token.is_none()
            || Path::new(field(value, "dataRoot")?) != store.data_root()
            || canonical_digest(value).map_err(|_| invalid())? != *witness.offer_digest()
        {
            return Err(ManagementError::WrongReply);
        }
        let effective_deadline = budget.deadline().min(reply_deadline);
        let owner = NativeOwnerWitness::capture(store, effective_deadline).map_err(|cause| {
            retain_error(
                &self.pack_bootstrap,
                &public,
                mmmm_application::AppError::storage("PERMISSION_REQUIRED", cause),
            )
        })?;
        let project = ProjectId::new(field(value, "projectId")?).map_err(|_| invalid())?;
        owner.check_project(store, &project).map_err(|cause| {
            retain_error(
                &self.pack_bootstrap,
                &public,
                mmmm_application::AppError::storage("PERMISSION_REQUIRED", cause),
            )
        })?;
        let plan = store
            .plan(
                &PlanId::new(field(value, "planId")?).map_err(|_| invalid())?,
                &Sha256Digest::new(field(value, "planHash")?).map_err(|_| invalid())?,
            )
            .map_err(|cause| {
                retain_error(
                    &self.pack_bootstrap,
                    &public,
                    mmmm_application::AppError::storage("STALE_PLAN", cause),
                )
            })?;
        let id = ContextId::new(field(&plan, "contextId")?).map_err(|_| invalid())?;
        let active = self
            .active
            .get(&id)
            .filter(|a| Instant::now() < a.expires && a.route_owner.is_some())
            .ok_or_else(invalid)?;
        if active.project != project
            || active.principal != *owner.principal()
            || active.policy.as_str() != field(&plan, "policyRevision")?
        {
            return Err(invalid());
        }
        let context = self
            .hosts
            .context_with_deadline(owner.principal(), &id, effective_deadline)
            .map_err(|cause| retain_error(&self.pack_bootstrap, &public, cause))?;
        budget.check()?;
        let hello = self
            .hosts
            .hello_with_deadline(owner.principal(), &id, effective_deadline)
            .map_err(|cause| retain_error(&self.pack_bootstrap, &public, cause))?;
        if value["principalId"] != context["principalRef"]
            || value["hostHello"] != hello
            || value["hostArtifactDigest"] != hello["hostBuild"]
            || value["contextIds"] != json!([id])
            || plan["projectId"] != project.as_str()
        {
            return Err(invalid());
        }
        self.pack_bootstrap
            .registry
            .check_source(store, &plan, &|| {
                budget.check().map_err(|cause| {
                    mmmm_application::AppError::caused_by(
                        "HOST_UNAVAILABLE",
                        "Original bootstrap source request ended",
                        cause,
                    )
                })?;
                owner.check_project(store, &project).map_err(|cause| {
                    mmmm_application::AppError::storage("PERMISSION_REQUIRED", cause)
                })?;
                if Instant::now() >= reply_deadline {
                    return Err(mmmm_application::AppError::new(
                        "TIME_BUDGET_EXCEEDED",
                        "Original bootstrap reply deadline ended",
                    ));
                }
                Ok(())
            })
            .map_err(|cause| retain_error(&self.pack_bootstrap, &public, cause))?;
        let manifest = self
            .pack_bootstrap
            .registry
            .manifest(store, &plan, &context, &value["runtimeSourceFacts"])
            .map_err(|cause| retain_error(&self.pack_bootstrap, &public, cause))?;
        // The registry chooses from its actual same-Store typed source. A
        // public purpose string may only agree with that selection, not pick it.
        if manifest["purpose"] != purpose::purpose_for_kind(offered_kind) {
            return Err(ManagementError::WrongReply);
        }
        let reply = PublicFrame::from_value(
            json!({"kind":"host_apply_approval_authority","protocolVersion":mmmm_contracts::CONTRACT_VERSION,
            "nonce":witness.nonce(),"purpose":manifest["purpose"],"contexts":[context],"approvedSources":{(NATIVE_SOURCE_ID):hello["hostBuild"]},
            "approvedActions":[plan["steps"][0]["actionDigest"]],"permissions":READ_PERMISSIONS,"manifest":manifest}),
        )?;
        budget.check()?;
        if Instant::now() >= reply_deadline {
            return Err(ManagementError::Deadline);
        }
        self.pack_bootstrap.pending.insert(
            witness.id().clone(),
            Pending {
                public,
                witness,
                token,
                budget: budget.clone(),
                plan,
                context,
                manifest,
                route: None,
                complete_issued: false,
                completion: None,
                failure: None,
            },
        );
        Ok(reply)
    }
    pub(super) fn install_bootstrap(
        &mut self,
        public: PublicFrame,
        witness: BootstrapWitness,
        epoch: &SessionEpoch,
        budget: &BootstrapBudget,
        reply_deadline: Instant,
    ) -> Result<PublicFrame, ManagementError> {
        let pending = self
            .pack_bootstrap
            .pending
            .get_mut(witness.id())
            .ok_or(ManagementError::WrongReply)?;
        if !same(&pending.witness, &witness)
            || pending.complete_issued
            || public.nonce() != witness.nonce()
            || public.value()["purpose"] != pending.manifest["purpose"]
            || public.value()["selectionDigest"] != pending.manifest["selectionDigest"]
            || public.value()["manifestDigest"]
                != canonical_digest(&pending.manifest)
                    .map_err(|_| invalid())?
                    .as_str()
            || public.value()["hostEndpoint"]["hostEpoch"]
                != pending.context["environment"]["sessionEpoch"]
        {
            return Err(ManagementError::WrongReply);
        }
        budget.check()?;
        pending.budget.check()?;
        if Instant::now() >= reply_deadline {
            return Err(ManagementError::Deadline);
        }
        let endpoint = &public.value()["hostEndpoint"];
        let record = EndpointRecord {
            schema_version: 1,
            contract_version: mmmm_contracts::CONTRACT_VERSION.into(),
            address: field(endpoint, "address")?.parse().map_err(|_| invalid())?,
            path: field(endpoint, "path")?.into(),
            coordinator_epoch: field(endpoint, "hostEpoch")?.into(),
            credential_ref: format!("MMMM.coordinator.bootstrap-{}", witness.id()),
        };
        let client = HostRpcClient::paired(
            record,
            pending.token.take().ok_or(ManagementError::WrongReply)?,
        )
        .map_err(|cause| {
            pending.failure = Some(Arc::new(mmmm_application::AppError::caused_by(
                "HOST_UNAVAILABLE",
                "Original bootstrap transport could not be created",
                cause,
            )));
            invalid()
        })?;
        let remaining =
            instant(field(&pending.plan, "expiresAt")?)? - time::OffsetDateTime::now_utc();
        let duration = Duration::try_from(remaining).map_err(|_| ManagementError::Deadline)?;
        let expires = Instant::now()
            .checked_add(duration)
            .ok_or(ManagementError::Deadline)?;
        let principal =
            PrincipalId::new(field(&pending.context, "principalRef")?).map_err(|_| invalid())?;
        let effective_deadline = pending
            .budget
            .deadline()
            .min(budget.deadline())
            .min(reply_deadline);
        let source_kind =
            purpose::kind_for_purpose(field(&pending.manifest, "purpose")?).ok_or_else(invalid)?;
        let route = self
            .hosts
            .prepare_bootstrap_route(
                client,
                principal,
                pending.context.clone(),
                pending.public.value()["hostHello"].clone(),
                expires,
                source_kind,
                BootstrapRouteBudget {
                    original: &pending.budget,
                    reply_deadline: effective_deadline,
                },
            )
            .map_err(|cause| {
                pending.failure = Some(Arc::new(cause));
                ManagementError::Disconnected
            })?;
        pending.route = Some(route);
        let complete = PublicFrame::from_value(
            json!({"kind":"host_apply_approval_complete","protocolVersion":mmmm_contracts::CONTRACT_VERSION,
            "nonce":witness.nonce(),"purpose":pending.manifest["purpose"],"selectionDigest":pending.manifest["selectionDigest"],"manifestDigest":canonical_digest(&pending.manifest).map_err(|_|invalid())?,
            "ready":true,"coordinatorEpoch":epoch,"hostEpoch":pending.context["environment"]["sessionEpoch"],"contextId":pending.context["contextId"]}),
        )?;
        budget.check()?;
        pending.budget.check()?;
        if Instant::now() >= reply_deadline {
            return Err(ManagementError::Deadline);
        }
        pending.complete_issued = true;
        Ok(complete)
    }
    pub(super) fn finish_bootstrap(
        &mut self,
        store: &DurableStore,
        receipt: CompletedBootstrap,
    ) -> Result<(), ManagementError> {
        let mut pending = self
            .pack_bootstrap
            .pending
            .remove(receipt.witness().id())
            .ok_or(ManagementError::WrongReply)?;
        if !same(&pending.witness, receipt.witness()) {
            self.pack_bootstrap
                .pending
                .insert(pending.witness.id().clone(), pending);
            return Err(ManagementError::WrongReply);
        }
        let observed = Arc::new(receipt);
        pending.completion = Some(observed.clone());
        if !pending.complete_issued
            || !observed.delivered()
            || observed.completed_at() >= pending.budget.deadline()
        {
            if let Some(route) = &pending.route {
                let _ = route.retire();
            }
            self.pack_bootstrap.failures.push(pending);
            return Err(ManagementError::TransportUncertain);
        }
        let result = (|| {
            let route = pending.route.as_ref().ok_or_else(invalid)?;
            route
                .check_bootstrap_current(&pending.budget)
                .map_err(|cause| {
                    pending.failure = Some(Arc::new(cause));
                    invalid()
                })?;
            let owner =
                NativeOwnerWitness::capture(store, pending.budget.deadline()).map_err(|cause| {
                    pending.failure = Some(Arc::new(mmmm_application::AppError::storage(
                        "PERMISSION_REQUIRED",
                        cause,
                    )));
                    invalid()
                })?;
            let project =
                ProjectId::new(field(&pending.plan, "projectId")?).map_err(|_| invalid())?;
            owner.check_project(store, &project).map_err(|cause| {
                pending.failure = Some(Arc::new(mmmm_application::AppError::storage(
                    "PERMISSION_REQUIRED",
                    cause,
                )));
                invalid()
            })?;
            self.pack_bootstrap
                .registry
                .check_source(store, &pending.plan, &|| {
                    pending.budget.check().map_err(|cause| {
                        mmmm_application::AppError::caused_by(
                            "HOST_UNAVAILABLE",
                            "Original bootstrap source request ended",
                            cause,
                        )
                    })?;
                    owner
                        .check_project(store, &project)
                        .map_err(|cause| {
                            mmmm_application::AppError::storage("PERMISSION_REQUIRED", cause)
                        })
                        .map(|_| ())
                })
                .map_err(|cause| {
                    pending.failure = Some(Arc::new(cause));
                    invalid()
                })?;
            let principal = PrincipalId::new(field(&pending.context, "principalRef")?)
                .map_err(|_| invalid())?;
            let publication = self.authority.approve_plan_with_control(
                &principal,
                &pending.plan,
                route
                    .lease_expires()
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(30 * 60)),
                pending.budget.deadline(),
                &|| {
                    pending.budget.check().map_err(|cause| {
                        mmmm_application::AppError::caused_by(
                            "HOST_UNAVAILABLE",
                            "Original bootstrap confirmation ended",
                            cause,
                        )
                    })
                },
            );
            let failed = publication.is_err();
            self.pack_bootstrap
                .registry
                .confirm(
                    store,
                    &pending.plan,
                    ConfirmedBootstrap {
                        route: route.clone(),
                        completion: observed.clone(),
                        manifest: pending.manifest.clone(),
                        publication_failure: publication.err().map(Arc::new),
                    },
                )
                .map_err(|cause| {
                    pending.failure = Some(Arc::new(cause));
                    invalid()
                })?;
            if failed {
                Err(ManagementError::TransportUncertain)
            } else {
                Ok(())
            }
        })();
        if result.is_err() {
            self.pack_bootstrap.failures.push(pending);
        }
        result
    }
    pub(super) fn cleanup_bootstrap(&mut self, shutdown: bool) -> Result<(), ManagementError> {
        let ids = self
            .pack_bootstrap
            .pending
            .iter()
            .filter(|(_, pending)| shutdown || pending.budget.check().is_err())
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        let mut failed = self
            .pack_bootstrap
            .registry
            .retire_routes(shutdown)
            .is_err();
        for id in ids {
            if self.pack_bootstrap.failures.len() >= MAX_REJECTED_COMPLETIONS {
                failed = true;
                break;
            }
            if let Some(pending) = self.pack_bootstrap.pending.remove(&id) {
                if let Some(route) = &pending.route
                    && route.retire().is_err()
                {
                    failed = true;
                }
                // Ownership and completion evidence are retained; expiry never
                // deletes product files, state or a Runtime operation.
                self.pack_bootstrap.failures.push(pending);
            }
        }
        if failed {
            Err(ManagementError::TransportUncertain)
        } else {
            Ok(())
        }
    }
    pub(super) fn has_bootstrap_completion(&self) -> bool {
        self.pack_bootstrap
            .pending
            .values()
            .any(|pending| pending.complete_issued)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack_manifest_input() -> (Value, Value) {
        // Closed-grammar inputs only. These values create no Store association,
        // typed registry source, ADMIN completion, current absence or run grant.
        let kind = CalibrationSourceKind::PackCase;
        let source = CalibrationPackProgram::java_26_3().unwrap();
        let entries = source
            .source_entries()
            .iter()
            .map(|(path, bytes)| {
                json!({
                    "path":path,"rawSha256":raw_digest(bytes),"byteLength":bytes.len(),
                    "rawBytesHex":bytes.iter().map(|byte|format!("{byte:02x}")).collect::<String>()
                })
            })
            .collect::<Vec<_>>();
        let entries = json!(entries);
        let bundle_digest = canonical_digest(&entries).unwrap();
        let raw = mmmm_contracts::canonical_bytes(&entries).unwrap();
        let bundle = json!({"sourceKind":kind.name(),"bundleDigest":bundle_digest,
            "rawResource":{"resourceId":"pack-management-source","sha256":raw_digest(&raw),
                "sizeBytes":raw.len(),"mediaType":"application/vnd.mmmm.calibration-bootstrap-source+json"},
            "entries":entries});
        let requirements =
            purpose::absence_requirements_for_kind(kind, &bundle["bundleDigest"]).unwrap();
        assert_eq!(requirements.len(), 1);
        let preconditions = requirements.iter().map(|requirement| json!({
            "kind":"resource_hash","subject":requirement["targetId"],"coverage":"full_target",
            "expected":raw_digest(&mmmm_contracts::canonical_bytes(requirement).unwrap())
        })).collect::<Vec<_>>();
        let targets = json!([purpose::pack_target_for_kind(kind)]);
        let mut context: Value =
            serde_json::from_slice(include_bytes!("../../../examples/execution-context.json"))
                .unwrap();
        context["scope"]["externalTargetIds"] = targets.clone();
        context["contextDigest"] = json!(projected_digest("ExecutionContext", &context).unwrap());
        let digest = raw_digest(b"pack management grammar only; not an approval or host");
        let arguments = json!({"command":"function mmmm_calibration:pack/entry"});
        let manifest = json!({
            "kind":purpose::manifest_kind_for_kind(kind),"purpose":purpose::purpose_for_kind(kind),
            "selectionDigest":digest,"hostEpoch":context["environment"]["sessionEpoch"],
            "registryGeneration":"pack-management-generation","runtimeSourceFactsDigest":digest,
            "suiteDigest":source.program_digest(),"recipeSha256":source.program_digest(),
            "sourceBundle":bundle,"programs":[],
            "plan":{"kind":"native_plan_approval","protocolVersion":mmmm_contracts::CONTRACT_VERSION,
                "principalId":context["principalRef"],"projectId":context["projectId"],
                "planId":"pack-management-plan","planHash":digest,"policyRevision":context["policyRevision"],
                "contextPins":[{"contextId":context["contextId"],"contextDigest":context["contextDigest"],
                    "environment":context["environment"]}],"expiresAt":"2099-01-01T00:00:00Z",
                "nativeExecutions":[],"steps":[{"stepId":"pack-management-step","bindingId":"pack-management-binding",
                    "actionId":purpose::action_for_kind(kind),"actionDigest":digest,"implementationDigest":digest,
                    "argumentsDigest":canonical_digest(&arguments).unwrap(),"contextId":context["contextId"],
                    "contextDigest":context["contextDigest"],"resourcesRead":targets,"resourcesWritten":targets,
                    "preconditions":preconditions}]}
        });
        (manifest, context)
    }

    #[test]
    fn pack_manifest_requires_its_exact_recipe_command_and_single_absence_target() {
        let validator = ContractValidator::shared().unwrap();
        let (manifest, _) = pack_manifest_input();
        validate_manifest(&manifest, validator).unwrap();
        assert_eq!(
            manifest["sourceBundle"]["entries"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(manifest["programs"], json!([]));
        assert_eq!(
            manifest["plan"]["steps"][0]["preconditions"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        for (field, value) in [
            ("purpose", json!(purpose::PURPOSE)),
            ("kind", json!(purpose::MANIFEST_KIND)),
            (
                "programs",
                json!([{"initializationCommands":["scoreboard objectives add caller dummy"]}]),
            ),
            (
                "suiteDigest",
                manifest["sourceBundle"]["bundleDigest"].clone(),
            ),
            (
                "recipeSha256",
                manifest["sourceBundle"]["rawResource"]["sha256"].clone(),
            ),
        ] {
            let mut changed = manifest.clone();
            changed[field] = value;
            assert!(validate_manifest(&changed, validator).is_err(), "{field}");
        }
        let mut changed = manifest.clone();
        changed["sourceBundle"]["sourceKind"] = json!("numeric47");
        assert!(validate_manifest(&changed, validator).is_err());
        let mut changed = manifest.clone();
        changed["sourceBundle"]
            .as_object_mut()
            .unwrap()
            .remove("sourceKind");
        assert!(validate_manifest(&changed, validator).is_err());
        let mut changed = manifest.clone();
        changed["plan"]["steps"][0]["actionId"] = json!(purpose::ACTION);
        assert!(validate_manifest(&changed, validator).is_err());
        let mut changed = manifest.clone();
        changed["plan"]["steps"][0]["argumentsDigest"] = json!(
            canonical_digest(&json!({
                "sourceBundleDigest":manifest["sourceBundle"]["bundleDigest"]
            }))
            .unwrap()
        );
        assert!(validate_manifest(&changed, validator).is_err());
        let mut changed = manifest.clone();
        changed["plan"]["steps"][0]["resourcesWritten"] = json!([purpose::PACK_TARGET]);
        assert!(validate_manifest(&changed, validator).is_err());
        let mut changed = manifest.clone();
        let condition = changed["plan"]["steps"][0]["preconditions"][0].clone();
        changed["plan"]["steps"][0]["preconditions"]
            .as_array_mut()
            .unwrap()
            .push(condition);
        assert!(validate_manifest(&changed, validator).is_err());
    }

    #[test]
    fn authority_frame_cannot_relabel_a_pack_manifest_as_numeric() {
        let validator = ContractValidator::shared().unwrap();
        let (manifest, context) = pack_manifest_input();
        let digest = raw_digest(b"pack management authority grammar only");
        let frame = json!({"kind":"host_apply_approval_authority",
            "protocolVersion":mmmm_contracts::CONTRACT_VERSION,"nonce":"pack-management-offer",
            "purpose":manifest["purpose"],"contexts":[context],"approvedSources":{(NATIVE_SOURCE_ID):digest},
            "approvedActions":[manifest["plan"]["steps"][0]["actionDigest"]],
            "permissions":READ_PERMISSIONS,"manifest":manifest});
        assert!(matches!(
            validate_frame(&frame, validator),
            Ok(ManagementKind::Authority)
        ));
        let mut changed = frame.clone();
        changed["purpose"] = json!(purpose::PURPOSE);
        assert!(validate_frame(&changed, validator).is_err());
        let mut changed = frame.clone();
        changed["purpose"] = json!("pack_calibration_bootstrap/2");
        assert!(validate_frame(&changed, validator).is_err());
        let mut changed = frame.clone();
        changed["manifest"]["plan"]["steps"][0]["resourcesRead"] = json!([
            purpose::pack_target_for_kind(CalibrationSourceKind::PackCase),
            "calibration-objective-caller"
        ]);
        assert!(validate_frame(&changed, validator).is_err());
    }
}

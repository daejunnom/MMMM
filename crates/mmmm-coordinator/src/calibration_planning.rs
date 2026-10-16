//! 실제 owner와 entered Plan 요청 아래 sealed47 원문만 공통 setup/freeze로 전달한다.
//! 계획 생성은 설치, ADMIN 승인, runner 준비 또는 numeric 인수의 증거가 아니다.

use crate::{
    bootstrap::NativeWorkspacePermit,
    calibration_bootstrap::{BootstrapRegistry, BootstrapSource},
    host::{HostBridge, HostContextWitness, HttpProviderPort},
    observer::finish_native_observation,
    service::RequestContextWitness,
    workspace_bootstrap::{NativeOwnerWitness, native_owner_resource_reader},
};
use mmmm_application::{
    AppError, AppResult, Application, PreparedPlan, ProviderPort, SetupPlanningPort, SetupSelection,
};
use mmmm_compiler::calibration_dispatch::CalibrationDispatchPlan;
use mmmm_contracts::{
    BindingId, PlanId, PrincipalId, Sha256Digest, TargetId, canonical_digest, raw_digest,
};
use mmmm_runtime::storage::{
    DurableStore, StorageError, StorageResult, WriteScope,
    project_resources::{ProjectHeadPin, ProjectSourceRpcContext, current_project_head_pin},
};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::BTreeSet, path::PathBuf, rc::Rc};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const MAX_PROJECT_BYTES: u64 = 8 * 1024 * 1024;

/// 사실상의 저장 locator만 반환한다. 공개 입력/승인/target profile 생성자는 없다.
#[derive(Debug)]
pub(crate) struct CalibrationPlanReceipt {
    plan_id: PlanId,
    plan_hash: Sha256Digest,
}
impl CalibrationPlanReceipt {
    pub(crate) fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }
    pub(crate) fn plan_hash(&self) -> &Sha256Digest {
        &self.plan_hash
    }
}

pub(crate) fn prepare_normative47_plan(
    app: &mut Application<'_>,
    request: &RequestContextWitness,
    owner: &NativeOwnerWitness,
    hosts: &HostBridge,
    selection: &SetupSelection,
) -> AppResult<CalibrationPlanReceipt> {
    prepare_selected_plan(app, request, owner, hosts, selection, None)
}

pub(crate) fn prepare_bootstrap_plan(
    app: &mut Application<'_>,
    request: &RequestContextWitness,
    owner: &NativeOwnerWitness,
    hosts: &HostBridge,
    selection: &SetupSelection,
    registry: &BootstrapRegistry,
) -> AppResult<CalibrationPlanReceipt> {
    prepare_selected_plan(app, request, owner, hosts, selection, Some(registry))
}

fn prepare_selected_plan(
    app: &mut Application<'_>,
    request: &RequestContextWitness,
    owner: &NativeOwnerWitness,
    hosts: &HostBridge,
    selection: &SetupSelection,
    bootstrap: Option<&BootstrapRegistry>,
) -> AppResult<CalibrationPlanReceipt> {
    request_check(request, owner)?;
    if !request
        .authenticated()
        .permits_context(selection.context_id.as_str())
    {
        return Err(denied());
    }
    finish_native_observation(
        app.authority.authorize(
            owner.principal(),
            &selection.project_id,
            mmmm_application::Access::Plan,
            None,
            None,
        ),
        request_check(request, owner),
    )?;
    owner
        .check_project(app.store, &selection.project_id)
        .map_err(storage)?;
    let head = finish_native_observation(
        current_project_head_pin(app.store, owner, &selection.project_id).map_err(storage),
        request_check(request, owner),
    )?;
    if head.revision != selection.expected_revision {
        return Err(revision_changed());
    }
    let host = finish_native_observation(
        hosts.observe_context_witness(
            owner.principal(),
            &selection.context_id,
            request.budget().deadline(),
        ),
        request_check(request, owner),
    )?;
    let options = mmmm_planner::PlannerOptions::default();
    let now =
        OffsetDateTime::from_unix_timestamp_nanos(app.clock.unix_nanos()).map_err(|_| invalid())?;
    let expires_at = now
        .checked_add(time::Duration::seconds(i64::from(options.expiry_seconds)))
        .ok_or_else(invalid)?
        .format(&Rfc3339)
        .map_err(|_| invalid())?;
    let sealed = CalibrationDispatchPlan::normative47().map_err(|cause| {
        AppError::caused_by(
            cause.code,
            "The sealed calibration source could not be constructed",
            cause,
        )
    })?;
    let mut creator = Creator {
        store: app.store as *const DurableStore,
        root: app.store.data_root().to_path_buf(),
        request,
        owner,
        hosts,
        host,
        head,
        selection: selection.clone(),
        sealed,
        expires_at,
        time_budget_ms: options.time_budget_ms,
        prepared: false,
        bootstrap,
        staged: None,
    };
    let plan = app.prepare_setup(owner.principal(), selection, &mut creator)?;
    if let Some(registry) = bootstrap {
        let source = creator.staged.take().ok_or_else(unavailable)?;
        // This association adds no target effect or approval. A failure keeps
        // the committed ordinary plan locator in the diagnostic source.
        if let Err(cause) = registry.retain_plan(app.store, source, &plan) {
            return Err(AppError::caused_by(
                "SETUP_PLAN_COMMITTED",
                "Bootstrap plan was saved before its source association failed",
                BootstrapPlanCommitted {
                    plan: plan.clone(),
                    cause,
                },
            ));
        }
    }
    // No extra fallible checkpoint follows the common committed-plan postcheck.
    Ok(CalibrationPlanReceipt {
        plan_id: decode(&plan["planId"])?,
        plan_hash: decode(&plan["planHash"])?,
    })
}

struct Creator<'a> {
    store: *const DurableStore,
    root: PathBuf,
    request: &'a RequestContextWitness,
    owner: &'a NativeOwnerWitness,
    hosts: &'a HostBridge,
    host: HostContextWitness,
    head: ProjectHeadPin,
    selection: SetupSelection,
    sealed: CalibrationDispatchPlan,
    expires_at: String,
    time_budget_ms: u64,
    prepared: bool,
    bootstrap: Option<&'a BootstrapRegistry>,
    staged: Option<Rc<BootstrapSource>>,
}
impl Creator<'_> {
    fn check_local(&self) -> AppResult<()> {
        request_check(self.request, self.owner)?;
        self.host.check_local()
    }
    fn check_store(&self, store: &DurableStore) -> AppResult<()> {
        self.check_local()?;
        if !std::ptr::eq(store, self.store) || store.data_root() != self.root {
            return Err(denied());
        }
        self.owner
            .check_project(store, &self.selection.project_id)
            .map_err(storage)?;
        let current = finish_native_observation(
            current_project_head_pin(store, self.owner, &self.selection.project_id)
                .map_err(storage),
            self.check_local(),
        )?;
        if current != self.head {
            return Err(revision_changed());
        }
        Ok(())
    }
    fn check_selection(
        &self,
        principal: &PrincipalId,
        selection: &SetupSelection,
    ) -> AppResult<()> {
        if principal != self.owner.principal()
            || selection.project_id != self.selection.project_id
            || selection.expected_revision != self.selection.expected_revision
            || selection.context_id != self.selection.context_id
        {
            return Err(denied());
        }
        Ok(())
    }
    fn observed_action(
        &self,
        store: &DurableStore,
        context: &Value,
    ) -> AppResult<(BindingId, Value, Value)> {
        let action_id = if self.bootstrap.is_some() {
            crate::calibration_bootstrap::ACTION
        } else {
            "mmmm:calibration_command_execute"
        };
        self.check_store(store)?;
        let inventory = finish_native_observation(
            self.hosts.inventory_with_deadline(
                self.owner.principal(),
                &self.selection.context_id,
                self.request.budget().deadline(),
            ),
            self.check_store(store),
        )?;
        let mut candidates = inventory["providers"]
            .as_array()
            .ok_or_else(unavailable)?
            .iter()
            .filter(|provider| {
                provider["origin"]["kind"] == "builtin"
                    && provider["origin"]["sourceId"] == "mmmm_host"
                    && provider["environment"] == context["environment"]
                    && provider["availability"] == "available"
                    && provider["actions"].as_array().is_some_and(|actions| {
                        actions.iter().any(|action| action["actionId"] == action_id)
                    })
            });
        let provider = candidates.next().ok_or_else(unavailable)?;
        if candidates.next().is_some() {
            return Err(unavailable());
        }
        let binding: BindingId = decode(&provider["bindingId"])?;
        let stub = json!({"bindingId":binding,"actionId":action_id});
        let descriptor = finish_native_observation(
            HttpProviderPort::with_deadline(self.hosts.clone(), self.request.budget().deadline())
                .action_descriptor(&stub, context),
            self.check_store(store),
        )?;
        validate_descriptor_for(&descriptor, action_id)?;
        if descriptor["implementationDigest"] != provider["origin"]["sourceDigest"] {
            return Err(unavailable());
        }
        let dependency = self.hosts.registered_dependency_pin(binding.as_str())?;
        if dependency["implementationDigest"] != descriptor["implementationDigest"] {
            return Err(unavailable());
        }
        finish_native_observation(
            self.hosts.verify_registered_dependencies_with_deadline(
                std::slice::from_ref(&dependency),
                context,
                self.request.budget().deadline(),
            ),
            self.check_store(store),
        )?;
        Ok((binding, descriptor, dependency))
    }
}
impl SetupPlanningPort for Creator<'_> {
    fn read_current_project_with_store(
        &mut self,
        store: &DurableStore,
        principal: &PrincipalId,
        selection: &SetupSelection,
    ) -> AppResult<Value> {
        self.check_selection(principal, selection)?;
        self.check_store(store)?;
        let rpc = SourceRpc {
            creator: self,
            failure: RefCell::new(None),
        };
        let mut reader = native_owner_resource_reader(
            self.owner,
            &selection.project_id,
            &self.head.revision,
            BTreeSet::new(),
            MAX_PROJECT_BYTES,
        )
        .map_err(storage)?;
        let result = reader
            .read_project(
                store,
                &rpc,
                &selection.project_id,
                &self.head.revision,
                MAX_PROJECT_BYTES,
            )
            .map_err(|cause| {
                rpc.failure
                    .borrow_mut()
                    .take()
                    .unwrap_or_else(|| storage(cause))
            });
        finish_native_observation(result, self.check_store(store))
    }
    fn check_current_project_with_store(
        &self,
        store: &DurableStore,
        principal: &PrincipalId,
        selection: &SetupSelection,
    ) -> AppResult<()> {
        self.check_selection(principal, selection)?;
        self.check_store(store)
    }
    fn prepare_setup_with_store(
        &mut self,
        store: &mut DurableStore,
        principal: &PrincipalId,
        selection: &SetupSelection,
        project: &Value,
        context: &Value,
    ) -> AppResult<PreparedPlan> {
        self.check_selection(principal, selection)?;
        self.check_store(store)?;
        if context != self.host.context()
            || context["environment"]["kind"] != "game"
            || context["environment"]["side"] != "server"
            || project["revision"] != selection.expected_revision.as_str()
            || self.prepared
        {
            return Err(denied());
        }
        let (binding, descriptor, dependency) = self.observed_action(store, context)?;
        if self.bootstrap.is_some() {
            let source = crate::calibration_bootstrap::stage_source(
                store,
                self.request,
                self.owner,
                selection,
                &self.sealed,
            )?;
            let targets = source.targets();
            let scope = WriteScope {
                project_id: selection.project_id.clone(),
                resource_ids: vec![],
                object_ids: vec![],
                regions: vec![],
                external_target_ids: targets.to_vec(),
            };
            scope.validate().map_err(storage)?;
            let action_digest = canonical_digest(&descriptor).map_err(|_| invalid())?;
            let step = json!({"stepId":"calibration-bootstrap","bindingId":binding,"actionId":crate::calibration_bootstrap::ACTION,
                "actionContractVersion":descriptor["contractVersion"],"actionDigest":action_digest,
                "arguments":{"sourceBundleDigest":source.digest()},"dependsOn":[],"effect":descriptor["effect"],
                "completion":descriptor["completion"],"recovery":descriptor["recovery"],"resourcesRead":targets,
                "resourcesWritten":targets,"verificationRequirement":descriptor["verificationRequirement"],
                "contextId":context["contextId"],"implementationDigest":descriptor["implementationDigest"],"resultBindings":[]});
            mmmm_contracts::ContractValidator::shared()
                .map_err(|_| invalid())?
                .validate("PlanStep", &step)
                .map_err(|_| invalid())?;
            let preconditions = source.preconditions();
            self.check_store(store)?;
            self.staged = Some(source);
            self.prepared = true;
            return Ok(PreparedPlan {
                contexts: vec![context.clone()],
                scope,
                preconditions,
                steps: vec![step],
                atomicity: "none".into(),
                losses: vec![],
                diagnostics: vec![],
                approval_requirement: "explicit_approval".into(),
                dependency_pins: vec![dependency],
                expires_at: self.expires_at.clone(),
                time_budget_ms: self.time_budget_ms,
            });
        }
        let facts = finish_native_observation(
            self.hosts.inspect_with_deadline(
                principal,
                &selection.context_id,
                json!({"kind":"runtime_sources"}),
                self.request.budget().deadline(),
            ),
            self.check_store(store),
        )?;
        crate::catalog_source::validate_source_facts(&facts, context)?;
        // The compiler projection verifies exact 47 IDs, singular resource paths,
        // raw original bytes/SHA, per-function 64KiB and aggregate 1MiB limits.
        self.sealed.loaded_source_expectations().map_err(|cause| {
            AppError::caused_by(
                cause.code,
                "Original loaded-function expectations are inconsistent",
                cause,
            )
        })?;
        // Owner selection re-verifies this sealed 47-step plan, retains its
        // exact recipe CAS and constructs the manifest from original source
        // bytes. This creator adds no unused body pin or raw-source read grant.
        let (scope, steps) =
            project_steps(&self.sealed, selection, context, &binding, &descriptor)?;
        let mut preconditions = Vec::with_capacity(94);
        for program in self.sealed.programs() {
            let images = crate::calibration_observer::plan_images(
                store,
                self.hosts,
                self.request,
                context,
                program,
                &|store| self.check_store(store),
            )?;
            if images.value["runtimeSourceFactsDigest"]
                != crate::catalog_source::source_facts_pin(&facts)?.as_str()
                || images.value["registryGeneration"] != facts["registryGeneration"]
                || images.value["hostArtifactDigest"] != descriptor["implementationDigest"]
            {
                return Err(unavailable());
            }
            for image in images.images {
                let blob = store.put_blob(&image.bytes).map_err(storage)?;
                preconditions.push(json!({"kind":"resource_hash","subject":image.target,"expected":blob.digest,"coverage":"full_target"}));
            }
            self.check_store(store)?;
        }
        self.check_store(store)?;
        self.prepared = true;
        Ok(PreparedPlan {
            contexts: vec![context.clone()],
            scope,
            preconditions,
            steps,
            atomicity: "none".into(),
            losses: vec![],
            diagnostics: vec![],
            approval_requirement: "explicit_approval".into(),
            dependency_pins: vec![dependency],
            expires_at: self.expires_at.clone(),
            time_budget_ms: self.time_budget_ms,
        })
    }
}

struct SourceRpc<'a, 'b> {
    creator: &'a Creator<'b>,
    failure: RefCell<Option<AppError>>,
}
impl ProjectSourceRpcContext for SourceRpc<'_, '_> {
    fn check(&self) -> StorageResult<()> {
        self.creator.check_local().map_err(|cause| {
            let mut first = self.failure.borrow_mut();
            if first.is_none() {
                *first = Some(cause);
            }
            StorageError::Conflict("Original calibration planning source checkpoint failed")
        })
    }
    fn authenticated_principal(&self) -> StorageResult<PrincipalId> {
        self.check()?;
        Ok(self.creator.owner.principal().clone())
    }
    fn context_id(&self) -> Option<&mmmm_contracts::ContextId> {
        None
    }
}

fn project_steps(
    sealed: &CalibrationDispatchPlan,
    selection: &SetupSelection,
    context: &Value,
    binding: &BindingId,
    descriptor: &Value,
) -> AppResult<(WriteScope, Vec<Value>)> {
    validate_descriptor(descriptor)?;
    let action_digest = canonical_digest(descriptor).map_err(|_| invalid())?;
    let mut targets = Vec::with_capacity(94);
    let mut steps = Vec::with_capacity(47);
    let mut predecessor: Option<String> = None;
    for (program, addresses) in sealed.programs().iter().zip(sealed.owned_addresses()) {
        // Deterministic footprint locators for the sealed owned addresses only;
        // they prove neither target existence nor reservation/approval. Common
        // Plan authority must still admit the complete scope before persistence.
        let owned = [
            format!("calibration-objective-{}", addresses.objective()),
            format!(
                "calibration-storage-{}",
                raw_digest(addresses.storage().as_str().as_bytes())
            ),
        ];
        for target in &owned {
            targets.push(TargetId::new(target).map_err(|_| invalid())?);
        }
        let step_id = format!("calibration-{}", program.case().case_id());
        let step = json!({"stepId":step_id,"bindingId":binding,"actionId":descriptor["actionId"],
            "actionContractVersion":descriptor["contractVersion"],"actionDigest":action_digest,
            "arguments":{"command":program.invocation_command()},"dependsOn":predecessor.iter().collect::<Vec<_>>(),
            "effect":descriptor["effect"],"completion":descriptor["completion"],"recovery":descriptor["recovery"],
            "resourcesRead":owned,"resourcesWritten":owned,"verificationRequirement":descriptor["verificationRequirement"],
            "contextId":context["contextId"],"implementationDigest":descriptor["implementationDigest"],"resultBindings":[]});
        mmmm_contracts::ContractValidator::shared()
            .map_err(|_| invalid())?
            .validate("PlanStep", &step)
            .map_err(|_| invalid())?;
        predecessor = Some(step_id);
        steps.push(step);
    }
    if steps.len() != CalibrationDispatchPlan::MAX_CASES {
        return Err(invalid());
    }
    let scope = WriteScope {
        project_id: selection.project_id.clone(),
        resource_ids: vec![],
        object_ids: vec![],
        regions: vec![],
        external_target_ids: targets,
    };
    scope.validate().map_err(storage)?;
    Ok((scope, steps))
}
fn validate_descriptor(descriptor: &Value) -> AppResult<()> {
    validate_descriptor_for(descriptor, "mmmm:calibration_command_execute")
}
fn validate_descriptor_for(descriptor: &Value, action: &str) -> AppResult<()> {
    mmmm_contracts::ContractValidator::shared()
        .map_err(|_| invalid())?
        .validate("ActionDescriptor", descriptor)
        .map_err(|_| invalid())?;
    if descriptor["actionId"] != action
        || !matches!(descriptor["effect"].as_str(), Some("write" | "unknown"))
        || descriptor["completion"] != "synchronous"
        || descriptor["recovery"] != "none"
        || descriptor["verificationRequirement"] != "independent_readback"
        || descriptor["side"] != "server"
    {
        return Err(unavailable());
    }
    Ok(())
}

#[derive(Debug)]
struct BootstrapPlanCommitted {
    plan: Value,
    cause: AppError,
}
impl std::fmt::Display for BootstrapPlanCommitted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Committed bootstrap plan {} / {} could not retain its protected source",
            self.plan["planId"], self.plan["planHash"]
        )
    }
}
impl std::error::Error for BootstrapPlanCommitted {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
fn request_check(request: &RequestContextWitness, owner: &NativeOwnerWitness) -> AppResult<()> {
    request
        .check_local()
        .map_err(|cause| AppError::caused_by(cause.code, cause.message, cause))?;
    owner.check().map_err(storage)?;
    if request.method() != "plan.create" || request.authenticated().principal() != owner.principal()
    {
        return Err(denied());
    }
    Ok(())
}
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> AppResult<T> {
    serde_json::from_value(value.clone()).map_err(|_| invalid())
}
fn storage(cause: StorageError) -> AppError {
    AppError::storage("CALIBRATION_PLAN_UNAVAILABLE", cause)
}
fn invalid() -> AppError {
    AppError::new(
        "INVALID_INPUT",
        "Sealed calibration planning data is inconsistent",
    )
}
fn denied() -> AppError {
    AppError::new(
        "PERMISSION_REQUIRED",
        "Original native owner, Store, request or selected context changed",
    )
}
fn unavailable() -> AppError {
    AppError::new(
        "CAPABILITY_UNAVAILABLE",
        "Actual native calibration action or source provenance is unavailable",
    )
}
fn revision_changed() -> AppError {
    AppError::new(
        "REVISION_CONFLICT",
        "Current Project head changed during calibration planning",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed47_projection_keeps_original_invocations_exact_chain_and_descriptor_pins() {
        // Existing fixture describes the DTO shape only, never a live source,
        // paired host, native owner, ready runner or target-profile admission.
        let provider: Value =
            serde_json::from_slice(include_bytes!("../../../examples/provider-supported.json"))
                .unwrap();
        let mut descriptor = provider["actions"][0].clone();
        descriptor["actionId"] = json!("mmmm:calibration_command_execute");
        descriptor["semanticKind"] = json!("mmmm:raw_command");
        descriptor["effect"] = json!("unknown");
        descriptor["verificationRequirement"] = json!("independent_readback");
        descriptor["inputSchema"] = json!({"type":"object","properties":{"command":{"type":"string"}},"required":["command"],"additionalProperties":false});
        let context: Value =
            serde_json::from_slice(include_bytes!("../../../examples/execution-context.json"))
                .unwrap();
        let selection = SetupSelection {
            project_id: decode(&context["projectId"]).unwrap(),
            expected_revision: raw_digest(b"fixture-project-revision"),
            context_id: decode(&context["contextId"]).unwrap(),
        };
        let sealed = CalibrationDispatchPlan::normative47().unwrap();
        let binding = BindingId::new("binding-fixture-01").unwrap();
        let (scope, steps) =
            project_steps(&sealed, &selection, &context, &binding, &descriptor).unwrap();
        assert_eq!(steps.len(), 47);
        assert_eq!(scope.external_target_ids.len(), 94);
        assert!(
            scope.regions.is_empty()
                && scope.resource_ids.is_empty()
                && scope.object_ids.is_empty()
        );
        for (index, ((step, program), address)) in steps
            .iter()
            .zip(sealed.programs())
            .zip(sealed.owned_addresses())
            .enumerate()
        {
            assert_eq!(
                step["arguments"],
                json!({"command":program.invocation_command()})
            );
            assert_eq!(
                step["actionDigest"],
                json!(canonical_digest(&descriptor).unwrap())
            );
            assert_eq!(
                step["implementationDigest"],
                descriptor["implementationDigest"]
            );
            assert_eq!(step["verificationRequirement"], "independent_readback");
            assert_eq!(step["contextId"], context["contextId"]);
            assert_eq!(
                step["dependsOn"],
                if index == 0 {
                    json!([])
                } else {
                    json!([steps[index - 1]["stepId"]])
                }
            );
            assert_eq!(step["resourcesRead"], step["resourcesWritten"]);
            let declared = json!([
                format!("calibration-objective-{}", address.objective()),
                format!(
                    "calibration-storage-{}",
                    raw_digest(address.storage().as_str().as_bytes())
                )
            ]);
            assert_eq!(step["resourcesWritten"], declared);
            assert_eq!(
                json!(&scope.external_target_ids[index * 2..index * 2 + 2]),
                declared
            );
            assert_eq!(step["resultBindings"], json!([]));
        }
        // These opaque declarations grant no target existence/reservation,
        // ADMIN approval, world/block registration or independent observation.
        for (field, value) in [
            ("actionId", "fixture:echo_text"),
            ("effect", "read"),
            ("completion", "job"),
            ("recovery", "provider_undo"),
            ("verificationRequirement", "provider_completion"),
        ] {
            let mut unsupported = descriptor.clone();
            unsupported[field] = json!(value);
            assert!(
                project_steps(&sealed, &selection, &context, &binding, &unsupported).is_err(),
                "{field}"
            );
        }
        assert_eq!(sealed.loaded_source_expectations().unwrap().len(), 47);
    }
}

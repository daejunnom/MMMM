use crate::preparation::{PreparedChange, Sources, dependency, empty_change};
use crate::*;
use mmmm_adapters::{
    ActionDescriptor, Completion, Effect, InventorySnapshot, VerificationRequirement,
    VersionEvidence,
};
use mmmm_application::{
    AppError, AppResult, PlanningPort, PreparedPlan, ProjectInspection, RecoveryPreparation,
};
use mmmm_contracts::{
    ActionId, BindingId, PrincipalId, Sha256Digest, projected_digest, raw_digest,
    verify_projected_digest,
};
use mmmm_runtime::storage::WriteScope;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

impl<'a> NativePlanner<'a> {
    pub fn new(
        source: Box<dyn ProjectSourcePort + 'a>,
        environment: Box<dyn PlanningEnvironmentPort + 'a>,
        clock: Box<dyn mmmm_application::Clock + 'a>,
        options: PlannerOptions,
    ) -> AppResult<Self> {
        options.validate()?;
        Ok(Self {
            source,
            environment,
            clock,
            options,
        })
    }
    fn inventory_for(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        context: &Value,
    ) -> AppResult<InventorySnapshot> {
        check_context(principal, project, context)?;
        let inventory = self.environment.inventory(principal, context)?;
        if inventory.context().context_id().as_str() != text(context, "contextId")?
            || inventory.context().context_digest().as_str() != text(context, "contextDigest")?
            || inventory.policy_revision().as_str() != text(context, "policyRevision")?
        {
            return Err(AppError::new(
                "INVENTORY_STALE",
                "Observed inventory does not retain the exact authorized context and policy",
            ));
        }
        Ok(inventory)
    }
    fn native_plan(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        context: &Value,
        mut prepared: PreparedChange,
        route: Option<NativeActionRoute>,
    ) -> AppResult<PreparedPlan> {
        let inventory = self.inventory_for(principal, project, context)?;
        let route = match route {
            Some(route) => route,
            None => self
                .environment
                .native_route(principal, prepared.change.kind, context)?,
        };
        let route_request = json!({"contextId":context["contextId"],"inventoryRevision":inventory.revision(),"semanticKind":route.semantic_kind,"requiredGuarantees":route.required_guarantees,"acceptableLossCodes":route.acceptable_loss_codes,"preferredBindingId":route.binding_id});
        let resolution = inventory.resolve(&route_request).map_err(adapter)?;
        let action = inventory
            .check_selection(&route_request, &resolution)
            .map_err(adapter)?
            .clone();
        if resolution["bindingId"].as_str() != Some(route.binding_id.as_str())
            || resolution["actionId"].as_str() != Some(route.action_id.as_str())
            || action.semantic_kind != route.semantic_kind
        {
            return Err(AppError::new(
                "CAPABILITY_UNAVAILABLE",
                "Exact native catalog action was not selected; no substitute is authorized",
            ));
        }
        if action.effect != Effect::Write
            || action.completion == Completion::Unobservable
            || action.verification_requirement != VerificationRequirement::IndependentReadback
        {
            return Err(AppError::new(
                "CAPABILITY_UNAVAILABLE",
                "Native mutation lacks a write declaration, observable completion and independent target readback",
            ));
        }
        if prepared.change.kind.world_effect()
            || (prepared.change.kind == NativeKind::Recovery
                && context["environment"]["kind"] == "game")
        {
            let target = self.environment.verified_native_target(
                principal,
                project.target_profile_id(),
                prepared.change.kind,
                context,
            )?;
            if target.profile_id != *project.target_profile_id()
                || !target.supported_kinds.contains(&prepared.change.kind)
                || action.version_evidence != VersionEvidence::RuntimeVerified
                || target.evidence_resource_pins.is_empty()
            {
                return Err(AppError::new(
                    "TARGET_UNVERIFIED",
                    "Native world action lacks exact target and independent runtime evidence for this kind",
                ));
            }
            let mut evidence_sources = Sources::default();
            for resource in target.evidence_resource_pins {
                self.load_resource(
                    principal,
                    project,
                    &resource,
                    context,
                    &mut evidence_sources,
                )?;
                prepared.change.source_resource_pins.push(resource);
            }
            prepared.dependencies.push(dependency(
                "target-profile",
                &target.profile_digest,
                &["FN09", "FN10"],
                "platform_shim",
            )?);
            prepared.dependencies.push(dependency(
                "target-artifact",
                &target.artifact_digest,
                &["FN09", "FN10"],
                "platform_shim",
            )?);
        }
        let snapshot = self.environment.snapshot_native_targets(
            principal,
            project,
            &prepared.change,
            context,
        )?;
        if snapshot.context_digest.as_str() != text(context, "contextDigest")? {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Independent target snapshot belongs to a different context",
            ));
        }
        validate_scope(project, context, &snapshot.scope)?;
        let object_ids: BTreeSet<_> = snapshot
            .scope
            .object_ids
            .iter()
            .map(|id| id.as_str())
            .collect();
        let resource_ids: BTreeSet<_> = snapshot
            .scope
            .resource_ids
            .iter()
            .map(|id| id.as_str())
            .collect();
        if prepared
            .change
            .object_ids()
            .iter()
            .any(|id| !object_ids.contains(id.as_str()))
            || prepared
                .change
                .resource_ids()
                .iter()
                .any(|id| !resource_ids.contains(id.as_str()))
        {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Independent native footprint omits a prepared authored or resource mutation",
            ));
        }
        validate_projection_scope(&prepared.change, context, &snapshot.scope)?;
        validate_projection_coverage(&prepared.change, &snapshot)?;
        let payload = prepared.change.to_arguments()?;
        let payload_bytes = mmmm_contracts::encode_json(&payload).map_err(|_| invalid())?;
        let prepared_resource = self.stage_bytes(
            principal,
            project,
            &payload_bytes,
            crate::PREPARED_CHANGE_MEDIA_TYPE,
            context,
        )?;
        let arguments = json!({"preparedChange":prepared_resource});
        inventory
            .validate_action_input(&route.binding_id, &route.action_id, &arguments)
            .map_err(adapter)?;
        let mut preconditions =
            source_preconditions(project, context, &inventory, &prepared.change)?;
        preconditions.push(json!({"kind":"resource_hash","subject":resource_subject(&prepared_resource),"expected":prepared_resource.sha256,"coverage":"full_target"}));
        let targets = check_targets(&snapshot.targets, self.options.max_source_bytes, true)?;
        preconditions.extend(targets);
        let reads: BTreeSet<String> = prepared
            .change
            .source_object_pins
            .iter()
            .map(object_subject)
            .chain(
                prepared
                    .change
                    .source_resource_pins
                    .iter()
                    .map(resource_subject),
            )
            .chain(snapshot.targets.iter().map(|target| target.subject.clone()))
            .chain(std::iter::once(resource_subject(&prepared_resource)))
            .collect();
        let writes: BTreeSet<String> = prepared
            .change
            .object_ids()
            .into_iter()
            .map(|id| format!("object:{id}"))
            .chain(
                prepared
                    .change
                    .resource_ids()
                    .iter()
                    .map(|id| format!("resource:{id}")),
            )
            .chain(snapshot.targets.iter().map(|target| target.subject.clone()))
            .collect();
        let losses = loss_diagnostics(&prepared.change.loss_records)?;
        prepared.diagnostics.extend(
            resolution["diagnostics"]
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .cloned(),
        );
        let step = step(
            &route.binding_id,
            &action,
            &arguments,
            context,
            &reads,
            &writes,
        )?;
        self.finish(
            principal,
            project,
            context,
            inventory,
            snapshot.scope,
            preconditions,
            step,
            losses,
            prepared.diagnostics,
            prepared.dependencies,
        )
    }
    fn registered_plan(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        context: &Value,
        request: &Value,
    ) -> AppResult<PreparedPlan> {
        validate("RegisteredActionRequest", request)?;
        if request["contextId"] != context["contextId"] {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "Registered action context differs from the plan context",
            ));
        }
        let inventory = self.inventory_for(principal, project, context)?;
        let binding: BindingId =
            serde_json::from_value(request["bindingId"].clone()).map_err(|_| invalid())?;
        let id: ActionId =
            serde_json::from_value(request["actionId"].clone()).map_err(|_| invalid())?;
        let action = inventory.action(&binding, &id).map_err(adapter)?.clone();
        let digest = projected_digest("ActionDescriptor", &wire("ActionDescriptor", &action)?)
            .map_err(|_| invalid())?;
        if request["actionDigest"].as_str() != Some(digest.as_str()) {
            return Err(AppError::new(
                "INVENTORY_STALE",
                "Requested registered action digest is not the observed descriptor",
            ));
        }
        let selection = json!({"status":"selected","bindingId":binding,"actionId":id,"actionDigest":digest,"implementationDigest":action.implementation_digest,"diagnostics":[]});
        inventory.check_selected_pin(&selection).map_err(adapter)?;
        inventory
            .validate_action_input(&binding, &id, &request["arguments"])
            .map_err(adapter)?;
        // This is Coordinator assembly of an opaque invocation. It never calls
        // a provider's effectful preview and retains the actual declaration.
        let footprint = self
            .environment
            .registered_action_footprint(principal, project, request, &action, context)?;
        validate_scope(project, context, &footprint.scope)?;
        if action.effect != Effect::Read && footprint.scope.is_empty() {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Opaque mutation requires an explicit authenticated target footprint",
            ));
        }
        let require_full = action.effect != Effect::Read
            && action.verification_requirement == VerificationRequirement::IndependentReadback;
        if action.effect != Effect::Read
            && footprint
                .targets
                .iter()
                .any(|target| !footprint.resources_written.contains(&target.subject))
        {
            return Err(AppError::new(
                "TARGET_UNVERIFIED",
                "Captured mutation target is absent from exact step resourcesWritten",
            ));
        }
        let mut preconditions = base_preconditions(project, context, &inventory)?;
        preconditions.extend(check_targets(
            &footprint.targets,
            self.options.max_source_bytes,
            require_full,
        )?);
        let losses = loss_diagnostics(&footprint.losses)?;
        let diagnostics = if action.version_evidence != VersionEvidence::RuntimeVerified {
            vec![
                json!({"code":"IMPLEMENTATION_UNVERIFIED","severity":"warning","message":"Selected registered implementation has no runtime verification evidence","objectId":binding}),
            ]
        } else {
            vec![]
        };
        let step = step(
            &binding,
            &action,
            &request["arguments"],
            context,
            &footprint.resources_read,
            &footprint.resources_written,
        )?;
        self.finish(
            principal,
            project,
            context,
            inventory,
            footprint.scope,
            preconditions,
            step,
            losses,
            diagnostics,
            footprint.dependency_pins,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn finish(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        context: &Value,
        inventory: InventorySnapshot,
        scope: WriteScope,
        preconditions: Vec<Value>,
        step: Value,
        losses: Vec<Value>,
        diagnostics: Vec<Value>,
        mut dependencies: Vec<Value>,
    ) -> AppResult<PreparedPlan> {
        dependencies.push(dependency(
            "mmmm-planner",
            &planner_digest(),
            &["FN09", "FN14", "FN34"],
            "owned_domain",
        )?);
        dependencies.push(dependency(
            "mmmm-domain",
            &domain_digest(),
            &["FN02", "FN03", "FN04", "FN05", "FN06", "FN08"],
            "owned_domain",
        )?);
        let action_digest: Sha256Digest =
            serde_json::from_value(step["implementationDigest"].clone()).map_err(|_| invalid())?;
        let binding: BindingId =
            serde_json::from_value(step["bindingId"].clone()).map_err(|_| invalid())?;
        let binding_dependency =
            self.environment
                .binding_dependency(principal, &binding, &action_digest, context)?;
        validate("DependencyPin", &binding_dependency)?;
        if binding_dependency["componentId"] != step["bindingId"]
            || binding_dependency["implementationDigest"] != step["implementationDigest"]
            || !binding_dependency["contractIds"]
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .any(|id| id == &step["actionId"])
        {
            return Err(AppError::new(
                "INVENTORY_STALE",
                "Registered implementation provenance does not retain the frozen action pin",
            ));
        }
        dependencies.push(binding_dependency);
        let dependencies = dependency_union(dependencies)?;
        let preconditions = deduplicate(preconditions, "Precondition", "subject")?;
        for value in &diagnostics {
            validate("Diagnostic", value)?;
        }
        if dependencies.len() > 1024
            || preconditions.len() > 4096
            || diagnostics.len() > 1024
            || losses.len() > 1024
        {
            return Err(AppError::new(
                "BUDGET_EXCEEDED",
                "Prepared plan metadata exceeds finite limits",
            ));
        }
        let host_budget = self.environment.execution_budget_ms(principal, context)?;
        if host_budget == 0 || host_budget > 3_600_000 {
            return Err(AppError::new(
                "BUDGET_EXCEEDED",
                "Observed host admission budget is invalid",
            ));
        }
        let time_budget_ms = self
            .options
            .time_budget_ms
            .min(host_budget)
            .min(u64::from(self.options.expiry_seconds) * 1000);
        let now = OffsetDateTime::from_unix_timestamp_nanos(self.clock.unix_nanos())
            .map_err(|_| invalid())?;
        let expires = now
            .checked_add(Duration::seconds(i64::from(self.options.expiry_seconds)))
            .ok_or_else(invalid)?
            .format(&Rfc3339)
            .map_err(|_| invalid())?;
        let explicit = step["effect"] == "unknown" || !losses.is_empty();
        // The inventory is already encoded in exact provider_revision pins.
        // Holding this value through construction prevents accidental rediscovery.
        let _ = inventory;
        let _ = project;
        Ok(PreparedPlan {
            contexts: vec![context.clone()],
            scope,
            preconditions,
            steps: vec![step],
            atomicity: "none".into(),
            losses,
            diagnostics,
            approval_requirement: if explicit {
                "explicit_approval"
            } else {
                "within_existing_grant"
            }
            .into(),
            dependency_pins: dependencies,
            expires_at: expires,
            time_budget_ms,
        })
    }
}

impl PlanningPort for NativePlanner<'_> {
    fn inspect_project(
        &mut self,
        principal: &PrincipalId,
        project: &Value,
    ) -> AppResult<ProjectInspection> {
        let catalog = ProjectCatalog::from_project(project)?;
        let objects =
            self.source
                .inspect_owned(principal, &catalog, self.options.max_source_bytes)?;
        if objects.len() != catalog.pins().len() {
            return Err(AppError::new(
                "REFERENCE_UNRESOLVED",
                "Project inspection lacks its exact current immutable authoring inventory",
            ));
        }
        let mut seen = BTreeSet::new();
        let mut bytes = 0u64;
        let mut diagnostics = Vec::new();
        let mut unresolved = BTreeSet::new();
        let owned_ids: BTreeSet<_> = catalog
            .pins()
            .iter()
            .map(|pin| pin.object_id.as_str())
            .collect();
        for (pin, value) in &objects {
            if catalog.owned_pin(pin.kind, pin.object_id.as_str())? != pin
                || !seen.insert((pin.kind, pin.object_id.clone()))
            {
                return Err(AppError::new(
                    "REVISION_CONFLICT",
                    "Project inspection returned a duplicate or different owned revision",
                ));
            }
            validate_owned_value(pin, value)?;
            bytes = bytes
                .checked_add(
                    mmmm_contracts::encode_json(value)
                        .map_err(|_| invalid())?
                        .len() as u64,
                )
                .ok_or_else(invalid)?;
            if bytes > self.options.max_source_bytes {
                return Err(AppError::new(
                    "BUDGET_EXCEEDED",
                    "Project inspection exceeds its cumulative byte budget",
                ));
            }
            if pin.kind == OwnedKind::Prefab {
                let validated = mmmm_domain::prefab_validate(value).map_err(domain)?;
                diagnostics.extend(
                    validated["diagnostics"]
                        .as_array()
                        .ok_or_else(invalid)?
                        .iter()
                        .cloned(),
                );
                for reference in value["references"].as_array().ok_or_else(invalid)? {
                    if reference["scope"] == "external"
                        || (reference["scope"] == "project"
                            && !owned_ids.contains(text(reference, "targetId")?)
                            && !catalog.resource_ids().iter().any(|id| {
                                id.as_str() == reference["targetId"].as_str().unwrap_or_default()
                            }))
                    {
                        unresolved.insert(text(reference, "targetId")?.to_owned());
                    }
                }
            }
        }
        let values: BTreeMap<_, _> = objects
            .iter()
            .map(|(pin, value)| ((pin.kind, pin.object_id.as_str()), value))
            .collect();
        for (pin, value) in &objects {
            match pin.kind {
                OwnedKind::Prefab => {
                    let definition: mmmm_domain::Prefab = decode("Prefab", value)?;
                    let nodes: BTreeSet<_> =
                        definition.nodes.iter().map(|node| &node.node_id).collect();
                    for module_id in &definition.command_module_ids {
                        let Some(module) =
                            values.get(&(OwnedKind::CommandModule, module_id.as_str()))
                        else {
                            unresolved.insert(module_id.to_string());
                            continue;
                        };
                        let module: mmmm_domain::commands::CommandModule =
                            decode("CommandModule", module)?;
                        if module.owner_prefab_id != definition.prefab_id
                            || !nodes.contains(&module.local_origin_node_id)
                        {
                            diagnostics.push(json!({"code":"REFERENCE_UNRESOLVED","severity":"error","message":"Command module owner or local origin differs from its definition","objectId":module_id}));
                        }
                    }
                    for clip_id in &definition.clip_ids {
                        let Some(clip) = values.get(&(OwnedKind::Clip, clip_id.as_str())) else {
                            unresolved.insert(clip_id.to_string());
                            continue;
                        };
                        let clip: mmmm_domain::time::AnimationClip = decode("AnimationClip", clip)?;
                        if let Err(error) = mmmm_domain::time::validate_clip(&clip) {
                            diagnostics.push(json!({"code":error.code,"severity":"error","message":"Owned animation clip is not semantically valid","objectId":clip_id}));
                        }
                        if clip.owner_prefab_id != definition.prefab_id
                            || clip
                                .tracks
                                .iter()
                                .any(|track| !nodes.contains(&track.node_id))
                        {
                            diagnostics.push(json!({"code":"REFERENCE_UNRESOLVED","severity":"error","message":"Animation clip owner or track node differs from its definition","objectId":clip_id}));
                        }
                        for event in &clip.events {
                            unresolved.insert(event.function_symbol_id.to_string());
                        }
                    }
                    for node in &definition.nodes {
                        if let Some(binding) = &node.physics_binding {
                            match values
                                .get(&(OwnedKind::PhysicsDefinition, binding.physics_id.as_str()))
                            {
                                Some(physics)
                                    if physics["bodies"].as_array().is_some_and(|bodies| {
                                        bodies.iter().any(|body| {
                                            body["bodyId"].as_str()
                                                == Some(binding.body_id.as_str())
                                        })
                                    }) => {}
                                _ => {
                                    unresolved.insert(binding.physics_id.to_string());
                                }
                            }
                        }
                    }
                }
                OwnedKind::Instance => {
                    let instance: mmmm_domain::Instance = decode("Instance", value)?;
                    let pin = catalog.authorize_pin(
                        OwnedKind::Prefab,
                        instance.prefab_id.as_str(),
                        &instance.prefab_revision,
                    )?;
                    let definition = match values
                        .get(&(OwnedKind::Prefab, instance.prefab_id.as_str()))
                    {
                        Some(value)
                            if value["revision"].as_str()
                                == Some(instance.prefab_revision.as_str()) =>
                        {
                            (*value).clone()
                        }
                        _ => {
                            let historical = self.source.owned_object(
                                principal,
                                &catalog,
                                &pin,
                                None,
                                self.options
                                    .max_source_bytes
                                    .checked_sub(bytes)
                                    .ok_or_else(invalid)?,
                            )?;
                            bytes = bytes
                                .checked_add(
                                    mmmm_contracts::encode_json(&historical)
                                        .map_err(|_| invalid())?
                                        .len() as u64,
                                )
                                .ok_or_else(invalid)?;
                            if bytes > self.options.max_source_bytes {
                                return Err(AppError::new(
                                    "BUDGET_EXCEEDED",
                                    "Historical source inspection exceeds its cumulative byte budget",
                                ));
                            }
                            historical
                        }
                    };
                    validate_owned_value(&pin, &definition)?;
                    let definition: mmmm_domain::Prefab = decode("Prefab", &definition)?;
                    if let Err(error) =
                        mmmm_domain::instance::require_source(&instance, &definition)
                    {
                        diagnostics.push(json!({"code":error.code,"severity":"error","message":"Instance overrides or bindings differ from its exact definition pin","objectId":instance.instance_id}));
                    }
                }
                OwnedKind::CommandModule => {
                    for command in value["commands"].as_array().ok_or_else(invalid)? {
                        for reference in command["references"].as_array().ok_or_else(invalid)? {
                            if reference["scope"] == "external"
                                || (reference["scope"] == "project"
                                    && !owned_ids.contains(text(reference, "targetId")?))
                            {
                                unresolved.insert(text(reference, "targetId")?.into());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        // Resource identity is checked through immutable CAS access with a
        // ReadProject grant. Inspection does not manufacture a game context.
        for id in catalog.resource_ids() {
            let resource = self
                .source
                .resource_pin(principal, &catalog, id.as_str(), None)?;
            if &resource.resource_id != id {
                return Err(AppError::new(
                    "INPUT_DIGEST_MISMATCH",
                    "Project resource metadata has a different identity",
                ));
            }
            let remaining = self
                .options
                .max_source_bytes
                .checked_sub(bytes)
                .ok_or_else(invalid)?;
            if resource.size_bytes > remaining {
                return Err(AppError::new(
                    "BUDGET_EXCEEDED",
                    "Project resource inspection exceeds its byte budget",
                ));
            }
            let read = self
                .source
                .resource_bytes(principal, &catalog, &resource, None, remaining)?;
            if !crate::preparation::same_resource(&read.resource, &resource)
                || read.bytes.len() as u64 != resource.size_bytes
                || raw_digest(&read.bytes) != resource.sha256
            {
                return Err(AppError::new(
                    "INPUT_DIGEST_MISMATCH",
                    "Project resource bytes differ from their actual immutable CAS metadata",
                ));
            }
            bytes += read.bytes.len() as u64;
        }
        if diagnostics.len() > 1024 || unresolved.len() > 4096 {
            return Err(AppError::new(
                "BUDGET_EXCEEDED",
                "Project closure diagnostics exceed their finite limits",
            ));
        }
        let runtime_bindings_available = self
            .environment
            .project_bindings_available(principal, &catalog)?;
        if !runtime_bindings_available {
            diagnostics.push(json!({"code":"RUNTIME_BINDINGS_REQUIRED","severity":"warning","message":"Authored project is not proof of connected runtime bindings"}));
        }
        Ok(ProjectInspection {
            diagnostics,
            unresolved_references: unresolved.into_iter().collect(),
            runtime_bindings_available,
        })
    }
    fn prepare(
        &mut self,
        principal: &PrincipalId,
        request: &Value,
        project: &Value,
        context: &Value,
    ) -> AppResult<PreparedPlan> {
        self.options.validate()?;
        validate("CreatePlanRequest", request)?;
        let catalog = ProjectCatalog::from_project(project)?;
        check_context(principal, &catalog, context)?;
        if request["projectId"] != project["projectId"]
            || request["expectedRevision"] != project["revision"]
            || request["contextId"] != context["contextId"]
        {
            return Err(AppError::new(
                "REVISION_CONFLICT",
                "Create request does not pin its authenticated project and context",
            ));
        }
        if request["intent"]["kind"] == "external.action" {
            return self.registered_plan(
                principal,
                &catalog,
                context,
                &request["intent"]["request"],
            );
        }
        let prepared = self.prepare_change(principal, &request["intent"], &catalog, context)?;
        self.native_plan(principal, &catalog, context, prepared, None)
    }
    fn prepare_recovery(
        &mut self,
        principal: &PrincipalId,
        recovery: &RecoveryPreparation,
        project: &Value,
        context: &Value,
    ) -> AppResult<PreparedPlan> {
        self.options.validate()?;
        let catalog = ProjectCatalog::from_project(project)?;
        check_context(principal, &catalog, context)?;
        if recovery.context_id.as_str() != text(context, "contextId")?
            || recovery.targets.is_empty()
            || recovery.targets.len() > 4096
        {
            return Err(AppError::new(
                "RECOVERY_EXPIRED",
                "Recovery lacks a bounded retained target chain for this context",
            ));
        }
        let mut change = empty_change(&catalog, NativeKind::Recovery);
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        for target in &recovery.targets {
            total = total
                .checked_add(target.before_bytes.len() as u64)
                .and_then(|n| n.checked_add(target.current_after_bytes.len() as u64))
                .ok_or_else(invalid)?;
            if total > self.options.max_source_bytes
                || !seen.insert(&target.snapshot.target)
                || target.source_snapshots.is_empty()
                || target.source_snapshots.len() > 4096
            {
                return Err(AppError::new(
                    "RECOVERY_EXPIRED",
                    "Recovery target chain is duplicate, missing or oversized",
                ));
            }
            let first = &target.source_snapshots[0];
            let last = target.source_snapshots.last().ok_or_else(invalid)?;
            if first.before.digest != raw_digest(&target.before_bytes)
                || first.before.byte_length != target.before_bytes.len() as u64
                || last.after.digest != raw_digest(&target.current_after_bytes)
                || last.after.byte_length != target.current_after_bytes.len() as u64
                || last != &target.snapshot
            {
                return Err(AppError::new(
                    "RECOVERY_EXPIRED",
                    "Recovery retained raw bytes do not match their exact first-before and last-after pins",
                ));
            }
            for pair in target.source_snapshots.windows(2) {
                if pair[0].after != pair[1].before {
                    return Err(AppError::new(
                        "RECOVERY_EXPIRED",
                        "Recovery direct target chain is not contiguous",
                    ));
                }
            }
            for snapshot in &target.source_snapshots {
                if snapshot.operation_id != recovery.operation_id
                    || snapshot.target != target.snapshot.target
                    || snapshot.context_id != recovery.context_id
                    || snapshot.binding_id != target.snapshot.binding_id
                    || snapshot.epoch != target.snapshot.epoch
                {
                    return Err(AppError::new(
                        "RECOVERY_EXPIRED",
                        "Recovery chain crosses its original operation, target, binding or epoch",
                    ));
                }
            }
            let before_resource = self.stage_bytes(
                principal,
                &catalog,
                &target.before_bytes,
                "application/octet-stream",
                context,
            )?;
            change.source_resource_pins.push(before_resource.clone());
            change.recovery_replacements.push(RecoveryReplacement {
                target: target.snapshot.target.clone(),
                before_resource,
                expected_current_sha256: last.after.digest.clone(),
                source_step_ids: target
                    .source_snapshots
                    .iter()
                    .map(|snapshot| snapshot.step_id.as_str().into())
                    .collect(),
            });
        }
        let route = self
            .environment
            .recovery_route(principal, recovery, context)?;
        let granted = self
            .environment
            .recovery_scope(principal, recovery, &catalog, context)?;
        validate_scope(&catalog, context, &granted)?;
        let retained_after_pins: Vec<_> = change
            .recovery_replacements
            .iter()
            .map(|replacement| {
                (
                    replacement.target.clone(),
                    replacement.expected_current_sha256.clone(),
                )
            })
            .collect();
        let prepared = PreparedChange {
            change,
            diagnostics: vec![
                json!({"code":"DIRECT_RECOVERY_ONLY","severity":"info","message":"Recovery restores retained direct targets; indirect game effects are not reversible by this plan"}),
            ],
            dependencies: vec![],
        };
        let plan = self.native_plan(principal, &catalog, context, prepared, Some(route))?;
        // Scope supplied for recovery is exact retained scope; a fresh observer
        // cannot broaden rollback to unrelated authored resources or regions.
        if plan.scope != granted {
            return Err(AppError::new(
                "PERMISSION_REQUIRED",
                "Recovery footprint differs from authenticated retained target scope",
            ));
        }
        for (target, after_digest) in &retained_after_pins {
            if !plan.preconditions.iter().any(|precondition| {
                precondition["subject"].as_str() == Some(target.as_str())
                    && precondition["expected"].as_str() == Some(after_digest.as_str())
                    && precondition["coverage"] == "full_target"
            }) {
                return Err(AppError::new(
                    "RECOVERY_EXPIRED",
                    "Recovery plan lacks its actual retained current-after precondition",
                ));
            }
        }
        Ok(plan)
    }
}

fn invalid() -> AppError {
    AppError::new(
        "INVALID_INPUT",
        "Planning metadata is malformed or cannot be canonically encoded",
    )
}
fn check_context(
    principal: &PrincipalId,
    project: &ProjectCatalog,
    context: &Value,
) -> AppResult<()> {
    validate("ExecutionContext", context)?;
    verify_projected_digest("ExecutionContext", context).map_err(|_| {
        AppError::new(
            "STALE_CONTEXT",
            "Execution context digest is not its actual immutable value",
        )
    })?;
    if context["principalRef"].as_str() != Some(principal.as_str())
        || context["projectId"].as_str() != Some(project.project_id().as_str())
    {
        return Err(AppError::new(
            "PERMISSION_REQUIRED",
            "Execution context belongs to a different principal or project",
        ));
    }
    Ok(())
}
fn validate_scope(project: &ProjectCatalog, context: &Value, scope: &WriteScope) -> AppResult<()> {
    scope
        .validate()
        .map_err(|error| AppError::storage("INVALID_INPUT", error))?;
    if scope.project_id != *project.project_id()
        || scope.object_ids.len() > 4096
        || scope.resource_ids.len() > 4096
        || scope.regions.len() > 4096
        || scope.external_target_ids.len() > 4096
    {
        return Err(AppError::new(
            "PERMISSION_REQUIRED",
            "Prepared footprint is invalid, oversized or belongs to another project",
        ));
    }
    for region in &scope.regions {
        if region.context_id.as_str() != text(context, "contextId")?
            || context["environment"]["worldId"].as_str() != Some(region.world_id.as_str())
        {
            return Err(AppError::new(
                "STALE_CONTEXT",
                "World region footprint belongs to another context or world",
            ));
        }
    }
    Ok(())
}
fn check_targets(
    targets: &[TargetBeforeImage],
    max_bytes: u64,
    require_full: bool,
) -> AppResult<Vec<Value>> {
    if targets.len() > 4096 || (require_full && targets.is_empty()) {
        return Err(AppError::new(
            "TARGET_UNVERIFIED",
            "Independent full target before images are required",
        ));
    }
    let mut total = 0u64;
    let mut subjects = BTreeSet::new();
    let mut output = Vec::new();
    for target in targets {
        total = total
            .checked_add(target.bytes.len() as u64)
            .ok_or_else(invalid)?;
        if total > max_bytes
            || target.subject.is_empty()
            || target.subject.len() > 1024
            || !subjects.insert(&target.subject)
            || target.digest != raw_digest(&target.bytes)
            || (require_full && target.coverage != "full_target")
        {
            return Err(AppError::new(
                "TARGET_UNVERIFIED",
                "Independent before images are incomplete, duplicate or not their pinned raw bytes",
            ));
        }
        if !matches!(target.kind, "resource_hash" | "region_snapshot") {
            return Err(invalid());
        }
        let value = json!({"kind":target.kind,"subject":target.subject,"expected":target.digest,"coverage":target.coverage});
        validate("Precondition", &value)?;
        output.push(value);
    }
    Ok(output)
}
fn base_preconditions(
    project: &ProjectCatalog,
    context: &Value,
    inventory: &InventorySnapshot,
) -> AppResult<Vec<Value>> {
    Ok(vec![
        json!({"kind":"object_revision","subject":format!("project:{}",project.project_id()),"expected":project.revision(),"coverage":"full_target"}),
        json!({"kind":"policy_revision","subject":format!("policy:{}",project.project_id()),"expected":context["policyRevision"],"coverage":"full_target"}),
        json!({"kind":"provider_revision","subject":format!("inventory:{}",text(context,"contextId")?),"expected":inventory.revision(),"coverage":"full_target"}),
    ])
}
fn object_subject(pin: &ObjectPin) -> String {
    format!(
        "owned:{}:{}:{}",
        serde_json::to_value(pin.kind)
            .expect("kind")
            .as_str()
            .expect("kind"),
        pin.object_id,
        pin.revision
    )
}
fn resource_subject(resource: &mmmm_domain::types::ResourceRef) -> String {
    format!("cas:{}:{}", resource.resource_id, resource.sha256)
}
fn source_preconditions(
    project: &ProjectCatalog,
    context: &Value,
    inventory: &InventorySnapshot,
    change: &PreparedNativeChange,
) -> AppResult<Vec<Value>> {
    let mut output = base_preconditions(project, context, inventory)?;
    output.extend(change.source_object_pins.iter().map(|pin|json!({"kind":"object_revision","subject":object_subject(pin),"expected":pin.revision,"coverage":"full_target"})));
    output.extend(change.source_resource_pins.iter().map(|resource|json!({"kind":"resource_hash","subject":resource_subject(resource),"expected":resource.sha256,"coverage":"full_target"})));
    Ok(output)
}
fn step(
    binding: &BindingId,
    action: &ActionDescriptor,
    arguments: &Value,
    context: &Value,
    reads: &BTreeSet<String>,
    writes: &BTreeSet<String>,
) -> AppResult<Value> {
    let digest = projected_digest("ActionDescriptor", &wire("ActionDescriptor", action)?)
        .map_err(|_| invalid())?;
    let value = json!({"stepId":"prepared-change","bindingId":binding,"actionId":action.action_id,"actionContractVersion":action.contract_version,"actionDigest":digest,"arguments":arguments,"dependsOn":[],"effect":action.effect,"completion":action.completion,"recovery":action.recovery,"resourcesRead":reads,"resourcesWritten":writes,"verificationRequirement":action.verification_requirement,"contextId":context["contextId"],"implementationDigest":action.implementation_digest,"resultBindings":[]});
    validate("PlanStep", &value)?;
    Ok(value)
}
fn loss_diagnostics(losses: &[Value]) -> AppResult<Vec<Value>> {
    let mut output = Vec::new();
    for loss in losses {
        validate("LossRecord", loss)?;
        if loss["severity"] == "error"
            || matches!(
                loss["disposition"].as_str(),
                Some("unsupported" | "unknown")
            )
        {
            return Err(AppError::new(
                "UNSUPPORTED_FORMAT",
                "Unsupported or unknown representation loss cannot be approved into a supported plan",
            ));
        }
        let mut value = json!({"code":loss["code"],"severity":loss["severity"],"message":loss["message"],"objectId":loss["subjectId"],"path":format!("feature:{};disposition:{}",text(loss,"feature")?,text(loss,"disposition")?)});
        if validate("Diagnostic", &value).is_err() {
            value["code"] = json!("LOSS_RECORDED");
            value["message"] = json!(format!(
                "{} (loss code: {})",
                text(loss, "message")?,
                text(loss, "code")?
            ));
        }
        validate("Diagnostic", &value)?;
        output.push(value);
    }
    Ok(output)
}
fn deduplicate(values: Vec<Value>, definition: &str, key: &str) -> AppResult<Vec<Value>> {
    let mut map = BTreeMap::new();
    for value in values {
        validate(definition, &value)?;
        let id = text(&value, key)?.to_owned();
        if let Some(previous) = map.insert(id, value.clone()) {
            if previous != value {
                return Err(AppError::new(
                    "REVISION_CONFLICT",
                    "Frozen metadata includes conflicting pins for one subject",
                ));
            }
        }
    }
    Ok(map.into_values().collect())
}

fn dependency_union(values: Vec<Value>) -> AppResult<Vec<Value>> {
    let mut map = BTreeMap::<String, Value>::new();
    for value in values {
        validate("DependencyPin", &value)?;
        let id = text(&value, "componentId")?.to_owned();
        if let Some(previous) = map.get_mut(&id) {
            if previous["implementationDigest"] != value["implementationDigest"]
                || previous["provenanceClass"] != value["provenanceClass"]
            {
                return Err(AppError::new(
                    "REVISION_CONFLICT",
                    "One component has conflicting implementation or provenance pins",
                ));
            }
            let contracts: BTreeSet<String> = previous["contractIds"]
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .chain(value["contractIds"].as_array().ok_or_else(invalid)?.iter())
                .map(|id| id.as_str().map(str::to_owned).ok_or_else(invalid))
                .collect::<AppResult<_>>()?;
            previous["contractIds"] = json!(contracts);
        } else {
            map.insert(id, value);
        }
    }
    Ok(map.into_values().collect())
}

/// This is an owned source implementation pin, distinct from host/game artifact
/// hashes. Actual composition registers and checks it as such at apply time.
pub fn planner_digest() -> Sha256Digest {
    let mut bytes = Vec::new();
    for source in [
        include_bytes!("lib.rs").as_slice(),
        include_bytes!("catalog.rs").as_slice(),
        include_bytes!("native.rs").as_slice(),
        include_bytes!("ports.rs").as_slice(),
        include_bytes!("preparation.rs").as_slice(),
        include_bytes!("planning.rs").as_slice(),
        include_bytes!("scene.rs").as_slice(),
        include_bytes!("schema.rs").as_slice(),
        mmmm_contracts::CANONICAL_SCHEMA,
        mmmm_contracts::FUNCTION_INDEX,
    ] {
        bytes.extend_from_slice(&(source.len() as u64).to_be_bytes());
        bytes.extend_from_slice(source);
    }
    raw_digest(&bytes)
}

/// Pure domain source closure used by preparation, independently pinned from
/// the registered host/game implementation artifact and planner source.
pub fn domain_digest() -> Sha256Digest {
    let mut bytes = Vec::new();
    for source in [
        include_bytes!("../../mmmm-domain/src/lib.rs").as_slice(),
        include_bytes!("../../mmmm-domain/src/types.rs").as_slice(),
        include_bytes!("../../mmmm-domain/src/commands.rs").as_slice(),
        include_bytes!("../../mmmm-domain/src/graph.rs").as_slice(),
        include_bytes!("../../mmmm-domain/src/instance.rs").as_slice(),
        include_bytes!("../../mmmm-domain/src/prefab.rs").as_slice(),
        include_bytes!("../../mmmm-domain/src/state.rs").as_slice(),
        include_bytes!("../../mmmm-domain/src/time.rs").as_slice(),
        include_bytes!("../../mmmm-domain/src/transform.rs").as_slice(),
        mmmm_contracts::CANONICAL_SCHEMA,
        mmmm_contracts::DIGEST_PROJECTIONS,
    ] {
        bytes.extend_from_slice(&(source.len() as u64).to_be_bytes());
        bytes.extend_from_slice(source);
    }
    raw_digest(&bytes)
}

fn validate_projection_scope(
    change: &PreparedNativeChange,
    context: &Value,
    scope: &WriteScope,
) -> AppResult<()> {
    for projection in &change.world_projection {
        for (instance, definition) in projection
            .before
            .iter()
            .zip(projection.before_definition.iter())
            .chain(std::iter::once((&projection.after, &projection.definition)))
        {
            if context["environment"]["worldId"].as_str() != Some(instance.world_id.as_str())
                || context["dimension"].as_str() != Some(instance.dimension.as_str())
            {
                return Err(AppError::new(
                    "STALE_CONTEXT",
                    "Prepared world projection differs from the actual context world or dimension",
                ));
            }
            let transforms = mmmm_domain::graph::world_transforms(
                definition,
                &instance.placement,
                &instance.overrides,
            )
            .map_err(domain)?;
            for node in &definition.nodes {
                let matrix = transforms.get(&node.node_id).ok_or_else(invalid)?;
                let bounds = if let Some(geometry) = &node.block_geometry {
                    Some((geometry.bounds.min, geometry.bounds.max_exclusive))
                } else {
                    None
                };
                let Some((min, max)) = bounds else { continue };
                let mut low = [f64::INFINITY; 3];
                let mut high = [f64::NEG_INFINITY; 3];
                for mask in 0..8 {
                    let point = std::array::from_fn(|axis| {
                        f64::from(if mask & (1 << axis) == 0 {
                            min[axis]
                        } else {
                            max[axis]
                        })
                    });
                    let world = matrix.transform_point(point).map_err(|_| {
                        AppError::new(
                            "UNSUPPORTED_TRANSFORM",
                            "Native projection cannot produce finite world bounds",
                        )
                    })?;
                    for axis in 0..3 {
                        low[axis] = low[axis].min(world[axis]);
                        high[axis] = high[axis].max(world[axis]);
                    }
                }
                let covered = scope.regions.iter().any(|region| {
                    region.world_id == instance.world_id
                        && region.dimension == instance.dimension
                        && (0..3).all(|axis| {
                            low[axis] >= region.min[axis] as f64
                                && high[axis] <= region.max_exclusive[axis] as f64
                        })
                });
                if !covered {
                    return Err(AppError::new(
                        "PERMISSION_REQUIRED",
                        "Independent footprint omits projected old or new geometry bounds",
                    ));
                }
            }
        }
        if projection.before.is_some() != projection.before_definition.is_some() {
            return Err(AppError::new(
                "TARGET_UNVERIFIED",
                "Before instance and before definition must be pinned together",
            ));
        }
    }
    Ok(())
}

fn validate_projection_coverage(
    change: &PreparedNativeChange,
    snapshot: &NativeTargetSnapshot,
) -> AppResult<()> {
    if snapshot.projection_coverage.len() != change.world_projection.len() {
        return Err(AppError::new(
            "TARGET_UNVERIFIED",
            "Native observer did not attest every exact world projection",
        ));
    }
    let footprint = mmmm_contracts::canonical_digest(
        &serde_json::to_value(&snapshot.scope).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    let subjects: BTreeSet<_> = snapshot
        .targets
        .iter()
        .map(|target| target.subject.as_str())
        .collect();
    let mut seen = BTreeSet::new();
    for projection in &change.world_projection {
        let digest = mmmm_contracts::canonical_digest(
            &serde_json::to_value(projection).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        let coverage = snapshot
            .projection_coverage
            .iter()
            .find(|coverage| coverage.instance_id == projection.after.instance_id)
            .ok_or_else(|| {
                AppError::new(
                    "TARGET_UNVERIFIED",
                    "Native observer lacks this projection's full footprint witness",
                )
            })?;
        if !seen.insert(&coverage.instance_id)
            || coverage.projection_digest != digest
            || coverage.footprint_digest != footprint
            || coverage.target_subjects.is_empty()
            || coverage
                .target_subjects
                .iter()
                .any(|subject| !subjects.contains(subject.as_str()))
        {
            return Err(AppError::new(
                "TARGET_UNVERIFIED",
                "Native footprint witness differs from the frozen projection, scope or independently observed targets",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn desired_state_and_incomplete_before_images_cannot_be_readback_proof() {
        let mut before = TargetBeforeImage {
            kind: "resource_hash",
            subject: "target-fixture".into(),
            bytes: b"actual-before".to_vec(),
            digest: raw_digest(b"desired-after"),
            coverage: "full_target",
        };
        assert_eq!(
            check_targets(&[before], 64, true).unwrap_err().code,
            "TARGET_UNVERIFIED"
        );
        before = TargetBeforeImage {
            kind: "resource_hash",
            subject: "target-fixture".into(),
            bytes: b"actual-before".to_vec(),
            digest: raw_digest(b"actual-before"),
            coverage: "tracked_changes_only",
        };
        assert_eq!(
            check_targets(&[before], 64, true).unwrap_err().code,
            "TARGET_UNVERIFIED"
        );
        assert_eq!(
            check_targets(&[], 64, true).unwrap_err().code,
            "TARGET_UNVERIFIED"
        );
    }
    #[test]
    fn independent_snapshot_budget_counts_the_whole_target_set() {
        let targets = (0..3)
            .map(|n| TargetBeforeImage {
                kind: "resource_hash",
                subject: format!("fixture-{n}"),
                bytes: vec![1; 8],
                digest: raw_digest(&[1; 8]),
                coverage: "full_target",
            })
            .collect::<Vec<_>>();
        assert_eq!(
            check_targets(&targets, 20, true).unwrap_err().code,
            "TARGET_UNVERIFIED"
        );
        assert_eq!(check_targets(&targets, 24, true).unwrap().len(), 3);
    }
    #[test]
    fn unknown_loss_cannot_be_approved_into_supported_plan() {
        let mut loss = json!({"code":"GEOMETRY_CODEC","severity":"warning","subjectId":"node-fixture","feature":"mmmm:geometry","disposition":"unknown","message":"Unknown source geometry codec","approvalRequired":true});
        assert_eq!(
            loss_diagnostics(&[loss.clone()]).unwrap_err().code,
            "UNSUPPORTED_FORMAT"
        );
        loss["disposition"] = json!("approximated");
        let diagnostics = loss_diagnostics(&[loss.clone()]).unwrap();
        assert_eq!(diagnostics[0]["objectId"], loss["subjectId"]);
        assert_eq!(
            diagnostics[0]["path"],
            "feature:mmmm:geometry;disposition:approximated"
        );
        loss["code"] = json!("loss report");
        let unusual = loss_diagnostics(&[loss]).unwrap();
        assert_eq!(unusual[0]["code"], "LOSS_RECORDED");
        assert!(
            unusual[0]["message"]
                .as_str()
                .unwrap()
                .contains("loss report")
        );
    }
    #[test]
    fn duplicate_subject_with_conflicting_digest_is_rejected() {
        let mut first = json!({"kind":"resource_hash","subject":"same-target","expected":raw_digest(b"one"),"coverage":"full_target"});
        let same = first.clone();
        assert_eq!(
            deduplicate(vec![first.clone(), same], "Precondition", "subject")
                .unwrap()
                .len(),
            1
        );
        first["expected"] = json!(raw_digest(b"two"));
        let original = json!({"kind":"resource_hash","subject":"same-target","expected":raw_digest(b"one"),"coverage":"full_target"});
        assert_eq!(
            deduplicate(vec![first, original], "Precondition", "subject")
                .unwrap_err()
                .code,
            "REVISION_CONFLICT"
        );
    }
}

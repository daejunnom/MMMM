use crate::*;
use mmmm_application::{AppError, AppResult};
use mmmm_contracts::{NodeId, PrincipalId, Sha256Digest, projected_digest, raw_digest};
use mmmm_domain::{
    Instance, InstanceDraft, Prefab,
    commands::CommandModule,
    time::AnimationClip,
    types::{Display, InstanceOverride, ResourceRef},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct PreparedChange {
    pub change: PreparedNativeChange,
    pub diagnostics: Vec<Value>,
    pub dependencies: Vec<Value>,
}

#[derive(Default)]
pub(crate) struct Sources {
    pub objects: BTreeMap<(OwnedKind, String, Sha256Digest), Value>,
    pub resources: BTreeMap<(String, Sha256Digest), ResourceRef>,
    exact_prefabs: BTreeSet<(OwnedKind, String, Sha256Digest)>,
    bytes: u64,
}

impl Sources {
    fn account(&mut self, bytes: usize, max: u64) -> AppResult<()> {
        self.bytes = self.bytes.checked_add(bytes as u64).ok_or_else(budget)?;
        if self.bytes > max {
            return Err(budget());
        }
        Ok(())
    }
    pub fn pins(&self) -> Vec<ObjectPin> {
        self.objects
            .keys()
            .map(|(kind, id, revision)| ObjectPin {
                kind: *kind,
                object_id: mmmm_contracts::ObjectId::new(id).expect("validated source ID"),
                revision: revision.clone(),
            })
            .collect()
    }
}

fn budget() -> AppError {
    AppError::new(
        "BUDGET_EXCEEDED",
        "Immutable planning sources exceed their finite byte budget",
    )
}
fn conflict() -> AppError {
    AppError::new(
        "REVISION_CONFLICT",
        "Requested immutable revision differs from the project source",
    )
}

impl NativePlanner<'_> {
    pub(crate) fn load_owned(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        pin: &ObjectPin,
        context: &Value,
        sources: &mut Sources,
    ) -> AppResult<Value> {
        let key = (
            pin.kind,
            pin.object_id.as_str().to_owned(),
            pin.revision.clone(),
        );
        if let Some(value) = sources.objects.get(&key) {
            return Ok(value.clone());
        }
        if sources.objects.len() >= 4096 {
            return Err(budget());
        }
        let remaining = self
            .options
            .max_source_bytes
            .checked_sub(sources.bytes)
            .ok_or_else(budget)?;
        // Only Prefabs have this raw witness requirement. Other owned source
        // reads keep their existing path and ordering.
        let raw = if pin.kind == OwnedKind::Prefab {
            self.source
                .owned_object_bytes(principal, project, pin, Some(context), remaining)?
        } else {
            None
        };
        let (value, accounted, exact_prefab) = if let Some(raw) = raw {
            if raw.bytes.len() as u64 > remaining || raw.bytes.len() > 8 * 1024 * 1024 {
                return Err(budget());
            }
            self.source
                .check_owned_source(principal, project, pin, Some(context))?;
            if raw_digest(&raw.bytes) != raw.digest {
                return Err(conflict());
            }
            let validator = mmmm_contracts::ContractValidator::shared().map_err(|_| {
                AppError::new(
                    "CAPABILITY_UNAVAILABLE",
                    "Prefab exact validation is unavailable",
                )
            })?;
            let actual = validator.parse_validate_prefab_exact_with_control(
                &raw.bytes,
                mmmm_contracts::JsonLimits::default(),
                || self.source.checkpoint_source(),
            ).map_err(|error| match error {
                mmmm_contracts::validation::ControlledPrefabContractError::Control(error) => error,
                error @ mmmm_contracts::validation::ControlledPrefabContractError::CaptureUnavailable => {
                    AppError::caused_by("CAPABILITY_UNAVAILABLE", "Prefab source capture is unavailable", error)
                }
                error => AppError::caused_by("INVALID_INPUT", "Prefab source exact validation failed", error),
            })?;
            if actual != raw.value {
                return Err(conflict());
            }
            self.source
                .check_owned_source(principal, project, pin, Some(context))?;
            // This is a cumulative source-input budget, not a heap limit.
            // Each source contributes the larger of original and encoded
            // lengths. The raw and encoded operations are separately bounded;
            // their simultaneously live allocations are not summed here.
            let encoded_len = mmmm_contracts::encode_json(&raw.value)
                .map_err(|_| budget())?
                .len();
            (raw.value, raw.bytes.len().max(encoded_len), true)
        } else {
            let value =
                self.source
                    .owned_object(principal, project, pin, Some(context), remaining)?;
            validate_owned_value(pin, &value)?;
            if pin.kind == OwnedKind::Prefab {
                require_value_only_prefab_integer_lengths(&value)?;
            }
            let length = mmmm_contracts::encode_json(&value)
                .map_err(|_| budget())?
                .len();
            (value, length, false)
        };
        validate_owned_value(pin, &value)?;
        if exact_prefab {
            // Identity/digest validation also consumes input; do not return a
            // checked source if current authority changed during that work.
            self.source
                .check_owned_source(principal, project, pin, Some(context))?;
        }
        sources.account(accounted, self.options.max_source_bytes)?;
        if exact_prefab {
            sources.exact_prefabs.insert(key.clone());
        }
        sources.objects.insert(key, value.clone());
        Ok(value)
    }

    fn decode_owned_prefab(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        pin: &ObjectPin,
        context: &Value,
        sources: &mut Sources,
    ) -> AppResult<Prefab> {
        let value = self.load_owned(principal, project, pin, context, sources)?;
        let key = (
            pin.kind,
            pin.object_id.as_str().to_owned(),
            pin.revision.clone(),
        );
        if sources.exact_prefabs.contains(&key) {
            self.source
                .check_owned_source(principal, project, pin, Some(context))?;
            let decoded = decode_prefab_scoped(&value, || self.source.checkpoint_source())?;
            self.source
                .check_owned_source(principal, project, pin, Some(context))?;
            Ok(decoded)
        } else {
            // Existing Value-only adapters have no checkpoint or raw witness.
            // Their schema-owned integer values retain the original path.
            decode("Prefab", &value)
        }
    }
    pub(crate) fn load_current(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        kind: OwnedKind,
        id: &str,
        context: &Value,
        sources: &mut Sources,
    ) -> AppResult<Value> {
        let pin = project.owned_pin(kind, id)?.clone();
        self.load_owned(principal, project, &pin, context, sources)
    }
    pub(crate) fn load_resource(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        resource: &ResourceRef,
        context: &Value,
        sources: &mut Sources,
    ) -> AppResult<Vec<u8>> {
        validate(
            "ResourceRef",
            &serde_json::to_value(resource).map_err(|_| budget())?,
        )?;
        let remaining = self
            .options
            .max_source_bytes
            .checked_sub(sources.bytes)
            .ok_or_else(budget)?;
        if resource.size_bytes > remaining {
            return Err(budget());
        }
        let resource_key = (
            resource.resource_id.as_str().to_owned(),
            resource.sha256.clone(),
        );
        if let Some(previous) = sources.resources.get(&resource_key)
            && !same_resource(previous, resource)
        {
            return Err(conflict());
        }
        let read =
            self.source
                .resource_bytes(principal, project, resource, Some(context), remaining)?;
        if !same_resource(&read.resource, resource)
            || read.bytes.len() as u64 != resource.size_bytes
            || raw_digest(&read.bytes) != resource.sha256
        {
            return Err(AppError::new(
                "INPUT_DIGEST_MISMATCH",
                "Authenticated resource bytes differ from the frozen pin",
            ));
        }
        // Repeat reads count again: a source adapter cannot bypass finite work
        // simply by returning a different allocation under an existing pin.
        sources.account(read.bytes.len(), self.options.max_source_bytes)?;
        sources.resources.insert(resource_key, resource.clone());
        Ok(read.bytes)
    }
    pub(crate) fn stage_bytes(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        bytes: &[u8],
        media_type: &str,
        context: &Value,
    ) -> AppResult<ResourceRef> {
        self.stage_named_bytes(principal, project, None, bytes, media_type, context)
    }
    pub(crate) fn stage_named_bytes(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        desired_id: Option<&mmmm_contracts::ResourceId>,
        bytes: &[u8],
        media_type: &str,
        context: &Value,
    ) -> AppResult<ResourceRef> {
        if bytes.len() as u64 > self.options.max_source_bytes {
            return Err(budget());
        }
        let resource = self
            .source
            .stage_private(principal, project, desired_id, bytes, media_type, context)?;
        validate(
            "ResourceRef",
            &serde_json::to_value(&resource).map_err(|_| budget())?,
        )?;
        if resource.sha256 != raw_digest(bytes)
            || resource.size_bytes != bytes.len() as u64
            || resource.media_type != media_type
            || desired_id.is_some_and(|id| id != &resource.resource_id)
        {
            return Err(AppError::new(
                "INPUT_DIGEST_MISMATCH",
                "Private staging did not retain the exact prepared bytes",
            ));
        }
        Ok(resource)
    }
    pub(crate) fn instance_source(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        id: &str,
        expected: Option<&Value>,
        context: &Value,
        sources: &mut Sources,
    ) -> AppResult<(Instance, Prefab)> {
        let source = self.load_current(
            principal,
            project,
            OwnedKind::Instance,
            id,
            context,
            sources,
        )?;
        if expected.is_some_and(|revision| source["revision"] != *revision) {
            return Err(conflict());
        }
        let instance: Instance = decode("Instance", &source)?;
        let pin = project.authorize_pin(
            OwnedKind::Prefab,
            instance.prefab_id.as_str(),
            &instance.prefab_revision,
        )?;
        let definition = self.decode_owned_prefab(principal, project, &pin, context, sources)?;
        mmmm_domain::instance::require_source(&instance, &definition).map_err(domain)?;
        Ok((instance, definition))
    }
    pub(crate) fn fill_projection(
        &mut self,
        principal: &PrincipalId,
        project: &ProjectCatalog,
        projection: &mut InstanceProjection,
        context: &Value,
        sources: &mut Sources,
    ) -> AppResult<Vec<Value>> {
        for module_id in &projection.definition.command_module_ids {
            if projection
                .command_modules
                .iter()
                .any(|module| &module.module_id == module_id)
            {
                continue;
            }
            let module: CommandModule = decode(
                "CommandModule",
                &self.load_current(
                    principal,
                    project,
                    OwnedKind::CommandModule,
                    module_id.as_str(),
                    context,
                    sources,
                )?,
            )?;
            if module.owner_prefab_id != projection.definition.prefab_id {
                return Err(conflict());
            }
            projection.command_modules.push(module);
        }
        for clip_id in &projection.definition.clip_ids {
            if projection.clips.iter().any(|clip| &clip.clip_id == clip_id) {
                continue;
            }
            let clip: AnimationClip = decode(
                "AnimationClip",
                &self.load_current(
                    principal,
                    project,
                    OwnedKind::Clip,
                    clip_id.as_str(),
                    context,
                    sources,
                )?,
            )?;
            if clip.owner_prefab_id != projection.definition.prefab_id {
                return Err(conflict());
            }
            mmmm_domain::time::validate_clip(&clip).map_err(domain)?;
            projection.clips.push(clip);
        }
        for binding in projection
            .definition
            .nodes
            .iter()
            .filter_map(|node| node.physics_binding.as_ref())
        {
            if projection
                .physics_definitions
                .iter()
                .any(|value| value["physicsId"].as_str() == Some(binding.physics_id.as_str()))
            {
                continue;
            }
            let definition = self.load_current(
                principal,
                project,
                OwnedKind::PhysicsDefinition,
                binding.physics_id.as_str(),
                context,
                sources,
            )?;
            projection.physics_definitions.push(definition);
        }
        let mut requested: BTreeMap<String, ResourceRef> = projection
            .definition
            .resources
            .iter()
            .cloned()
            .map(|resource| (resource.resource_id.as_str().into(), resource))
            .collect();
        for physics in &projection.physics_definitions {
            for resource in physics_mesh_resources(physics)? {
                if requested
                    .get(resource.resource_id.as_str())
                    .is_some_and(|old| !same_resource(old, &resource))
                {
                    return Err(conflict());
                }
                requested.insert(resource.resource_id.as_str().into(), resource);
            }
        }
        for node in &projection.definition.nodes {
            if let Some(resource) = &node.geometry_resource {
                if requested
                    .get(resource.resource_id.as_str())
                    .is_some_and(|old| !same_resource(old, resource))
                {
                    return Err(conflict());
                }
                requested.insert(resource.resource_id.as_str().into(), resource.clone());
            }
            if let Some(geometry) = &node.block_geometry
                && !requested.contains_key(geometry.resource_id.as_str())
            {
                let resource = self.source.resource_pin(
                    principal,
                    project,
                    geometry.resource_id.as_str(),
                    Some(context),
                )?;
                if resource.resource_id != geometry.resource_id {
                    return Err(conflict());
                }
                requested.insert(resource.resource_id.as_str().into(), resource);
            }
            let displays = node
                .display
                .iter()
                .chain(
                    projection
                        .after
                        .overrides
                        .iter()
                        .filter_map(|value| match value {
                            InstanceOverride::Display { node_id, display }
                                if node_id == &node.node_id =>
                            {
                                Some(display)
                            }
                            _ => None,
                        }),
                );
            for display in displays {
                for id in &display.resource_refs {
                    if !requested.contains_key(id.as_str()) {
                        let resource = self.source.resource_pin(
                            principal,
                            project,
                            id.as_str(),
                            Some(context),
                        )?;
                        if resource.resource_id != *id {
                            return Err(conflict());
                        }
                        requested.insert(resource.resource_id.as_str().into(), resource);
                    }
                }
            }
        }
        for resource in requested.values() {
            self.load_resource(principal, project, resource, context, sources)?;
        }
        projection.resource_pins = requested.into_values().collect();
        self.environment
            .verify_projection_references(principal, project, projection, context)
    }
    pub(crate) fn prepare_change(
        &mut self,
        principal: &PrincipalId,
        intent: &Value,
        project: &ProjectCatalog,
        context: &Value,
    ) -> AppResult<PreparedChange> {
        validate("ChangeIntent", intent)?;
        let mut sources = Sources::default();
        let mut change = empty_change(
            project,
            match text(intent, "kind")? {
                "prefab.instantiate" => NativeKind::Instantiate,
                "instance.clone" => NativeKind::Clone,
                "instance.relocate" => NativeKind::Relocate,
                "display.patch" => NativeKind::DisplayPatch,
                "command_module.patch" => NativeKind::CommandPatch,
                "clip.retime" => NativeKind::ClipRetime,
                "resource.patch" => NativeKind::ResourcePatch,
                "pack.build" => NativeKind::PackBuild,
                "scene.import_patch" => NativeKind::ScenePatch,
                "recovery.plan" => {
                    return Err(AppError::new(
                        "RECOVERY_REQUIRED",
                        "Recovery must use the common application's retained before/after chain",
                    ));
                }
                _ => {
                    return Err(AppError::new(
                        "CAPABILITY_UNAVAILABLE",
                        "Intent needs a registered action path",
                    ));
                }
            },
        );
        let mut diagnostics = Vec::new();
        let mut dependencies = Vec::new();
        match change.kind {
            NativeKind::Instantiate => {
                let revision: Sha256Digest =
                    serde_json::from_value(intent["prefabRevision"].clone())
                        .map_err(|_| conflict())?;
                let pin = project.authorize_pin(
                    OwnedKind::Prefab,
                    text(intent, "prefabId")?,
                    &revision,
                )?;
                let definition =
                    self.decode_owned_prefab(principal, project, &pin, context, &mut sources)?;
                let id = self.source.allocate_instance_id(
                    principal,
                    project,
                    project.used_instance_ids(),
                )?;
                let request = json!({"prefab":definition,"instanceId":id,"worldId":intent["worldId"],"dimension":intent["dimension"],"placement":intent["placement"],"statePolicy":"defaults"});
                let draft: InstanceDraft = decode(
                    "InstanceDraft",
                    &mmmm_domain::instance::instantiate_with_existing_ids(
                        &request,
                        project.used_instance_ids(),
                    )
                    .map_err(domain)?,
                )?;
                append_draft(&mut change, &mut diagnostics, draft, None, definition)?;
            }
            NativeKind::Clone | NativeKind::Relocate => {
                let (before, definition) = self.instance_source(
                    principal,
                    project,
                    text(intent, "instanceId")?,
                    Some(&intent["expectedRevision"]),
                    context,
                    &mut sources,
                )?;
                let before_value = wire("Instance", &before)?;
                let definition_value = wire("Prefab", &definition)?;
                let value = if change.kind == NativeKind::Clone {
                    let id = self.source.allocate_instance_id(
                        principal,
                        project,
                        project.used_instance_ids(),
                    )?;
                    let mut request = json!({"source":before_value,"definition":definition_value,"allocatedInstanceId":id,"placement":intent["placement"],"statePolicy":intent["statePolicy"]});
                    let snapshot = if intent["statePolicy"] == "explicit_snapshot" {
                        let snapshot = self.source.state_snapshot(
                            principal,
                            project,
                            &before_value,
                            &definition_value,
                            context,
                        )?;
                        self.load_resource(
                            principal,
                            project,
                            &snapshot.resource,
                            context,
                            &mut sources,
                        )?;
                        request["stateSnapshot"] =
                            serde_json::to_value(&snapshot.resource).map_err(|_| budget())?;
                        Some(snapshot)
                    } else {
                        None
                    };
                    mmmm_domain::instance::clone_with_snapshot(
                        &request,
                        snapshot.as_ref().map(|snapshot| &snapshot.snapshot),
                        project.used_instance_ids(),
                    )
                    .map_err(domain)?
                } else {
                    let mut modules = Vec::new();
                    for id in &definition.command_module_ids {
                        modules.push(self.load_current(
                            principal,
                            project,
                            OwnedKind::CommandModule,
                            id.as_str(),
                            context,
                            &mut sources,
                        )?);
                    }
                    let relocatable = self
                        .environment
                        .relocatable_modules(principal, project, &modules, context)?;
                    let request = json!({"source":before_value,"definition":definition_value,"placement":intent["placement"],"externalReferencePolicy":"preserve"});
                    mmmm_domain::instance::relocate_with_command_support(&request, &relocatable)
                        .map_err(domain)?
                };
                let draft = decode("InstanceDraft", &value)?;
                let prior = if change.kind == NativeKind::Clone {
                    None
                } else {
                    Some(before)
                };
                append_draft(&mut change, &mut diagnostics, draft, prior, definition)?;
            }
            NativeKind::DisplayPatch => {
                let (before, definition) = self.instance_source(
                    principal,
                    project,
                    text(intent, "instanceId")?,
                    Some(&intent["expectedRevision"]),
                    context,
                    &mut sources,
                )?;
                let node: NodeId =
                    serde_json::from_value(intent["nodeId"].clone()).map_err(|_| conflict())?;
                if !definition
                    .nodes
                    .iter()
                    .any(|candidate| candidate.node_id == node)
                {
                    return Err(AppError::new(
                        "REFERENCE_UNRESOLVED",
                        "Display target node is absent from the pinned definition",
                    ));
                }
                let display: Display = decode("Display", &intent["display"])?;
                let mut after = before.clone();
                after.overrides.retain(|value|!matches!(value,InstanceOverride::Display {node_id,..} if node_id==&node));
                after.overrides.push(InstanceOverride::Display {
                    node_id: node,
                    display,
                });
                revise_instance(&mut after)?;
                mmmm_domain::instance::require_source(&after, &definition).map_err(domain)?;
                append_instance(&mut change, Some(before), after, definition)?;
            }
            NativeKind::CommandPatch => {
                let (before, definition) = self.instance_source(
                    principal,
                    project,
                    text(intent, "instanceId")?,
                    Some(&intent["expectedRevision"]),
                    context,
                    &mut sources,
                )?;
                let module: CommandModule = decode("CommandModule", &intent["module"])?;
                mmmm_contracts::verify_projected_digest("CommandModule", &intent["module"])
                    .map_err(|_| conflict())?;
                if module.owner_prefab_id != definition.prefab_id
                    || !definition
                        .nodes
                        .iter()
                        .any(|node| node.node_id == module.local_origin_node_id)
                {
                    return Err(AppError::new(
                        "REFERENCE_UNRESOLVED",
                        "Command module owner or local origin differs from the target definition",
                    ));
                }
                let support = self.environment.command_layout_support(
                    principal,
                    project,
                    &intent["module"],
                    context,
                )?;
                let request = self.environment.command_layout_request(
                    principal,
                    project,
                    &wire("Instance", &before)?,
                    &intent["module"],
                    context,
                )?;
                validate("CommandLayoutRequest", &request)?;
                if request["module"] != intent["module"]
                    || request["targetProfileId"].as_str()
                        != Some(project.target_profile_id().as_str())
                    || request["activation"] != "staged_disabled"
                {
                    return Err(AppError::new(
                        "STALE_CONTEXT",
                        "Native command layout request changes pinned module or activation policy",
                    ));
                }
                let laid_out: CommandModule = decode(
                    "CommandModule",
                    &mmmm_domain::command_layout_with_support(&request, &support)
                        .map_err(domain)?,
                )?;
                self.prepare_command_variant(
                    principal,
                    project,
                    context,
                    &mut sources,
                    &mut change,
                    before,
                    definition,
                    laid_out,
                )?;
            }
            NativeKind::ClipRetime => {
                let clip = self.load_current(
                    principal,
                    project,
                    OwnedKind::Clip,
                    text(intent, "clipId")?,
                    context,
                    &mut sources,
                )?;
                if clip["revision"] != intent["expectedRevision"] {
                    return Err(conflict());
                }
                let after=mmmm_domain::clip_retime(&json!({"clip":clip,"duration":intent["newDuration"],"eventPolicy":intent["eventPolicy"]})).map_err(domain)?;
                change.loss_records = after["losses"].as_array().ok_or_else(conflict)?.clone();
                change.document_changes.push(document(
                    OwnedKind::Clip,
                    Some(
                        project
                            .owned_pin(OwnedKind::Clip, text(intent, "clipId")?)?
                            .revision
                            .clone(),
                    ),
                    after,
                )?);
            }
            NativeKind::ResourcePatch => {
                let id = text(intent, "resourceId")?;
                if !project
                    .resource_ids()
                    .iter()
                    .any(|resource| resource.as_str() == id)
                {
                    return Err(AppError::new(
                        "PERMISSION_REQUIRED",
                        "Resource patch target is outside the authored project",
                    ));
                }
                let before = self
                    .source
                    .resource_pin(principal, project, id, Some(context))?;
                if before.resource_id.as_str() != id
                    || before.sha256.as_str() != text(intent, "expectedSha256")?
                {
                    return Err(conflict());
                }
                let replacement: ResourceRef = decode("ResourceRef", &intent["replacement"])?;
                self.load_resource(principal, project, &before, context, &mut sources)?;
                self.load_resource(principal, project, &replacement, context, &mut sources)?;
                change.resource_replacements.push(ResourceReplacement {
                    target_resource_id: before.resource_id.clone(),
                    before,
                    replacement_source: replacement,
                });
            }
            NativeKind::PackBuild => {
                if intent["projectId"].as_str() != Some(project.project_id().as_str())
                    || intent["expectedRevision"].as_str() != Some(project.revision().as_str())
                    || intent["targetProfileId"].as_str()
                        != Some(project.target_profile_id().as_str())
                {
                    return Err(conflict());
                }
                let mut owned = Vec::new();
                for pin in project.pins() {
                    owned.push(self.load_owned(principal, project, pin, context, &mut sources)?);
                }
                let target = self.environment.compiler_target(
                    principal,
                    project.target_profile_id(),
                    context,
                )?;
                let inputs = self
                    .environment
                    .pack_inputs(principal, project, &owned, context)?;
                let request = json!({"contextId":context["contextId"],"projectId":project.project_id(),"expectedRevision":project.revision(),"targetProfileId":project.target_profile_id(),"outputPolicy":"private_staging_only"});
                let draft = mmmm_compiler::pack_build(&request, &target, inputs).map_err(domain)?;
                for resource in draft
                    .resources()
                    .values()
                    .chain(std::iter::once(draft.source_map()))
                {
                    let staged = self.stage_named_bytes(
                        principal,
                        project,
                        Some(&resource.reference.resource_id),
                        &resource.bytes,
                        &resource.reference.media_type,
                        context,
                    )?;
                    // Compiler manifest carries exact IDs, so private staging
                    // must retain its identity rather than silently remap it.
                    if !same_resource(&staged, &resource.reference) {
                        return Err(AppError::new(
                            "INPUT_DIGEST_MISMATCH",
                            "Private CAS identity differs from the compiler manifest pin",
                        ));
                    }
                    change.staged_resources.push(staged);
                }
                let manifest = draft.to_wire().map_err(domain)?;
                change.loss_records = manifest["losses"].as_array().ok_or_else(conflict)?.clone();
                change.pack_manifest = Some(manifest);
                dependencies.push(dependency(
                    "mmmm-compiler",
                    &mmmm_compiler::compiler_digest(),
                    &["FN07", "FN30"],
                    "owned_domain",
                )?);
                dependencies.push(dependency(
                    "target-profile",
                    draft.target_profile_digest(),
                    &["FN07", "FN30"],
                    "platform_shim",
                )?);
                dependencies.push(dependency(
                    "target-artifact",
                    draft.target_artifact_digest(),
                    &["FN07", "FN30"],
                    "platform_shim",
                )?);
            }
            NativeKind::ScenePatch => {
                dependencies.extend(self.prepare_scene_change(
                    principal,
                    project,
                    context,
                    &mut sources,
                    &mut change,
                    &intent["patch"],
                )?);
            }
            NativeKind::Recovery => unreachable!("recovery has a retained-chain entry point"),
        }
        for projection in &mut change.world_projection {
            dependencies.extend(self.fill_projection(
                principal,
                project,
                projection,
                context,
                &mut sources,
            )?);
            for clip in &projection.clips {
                for loss in &clip.losses {
                    let value = serde_json::to_value(loss).map_err(|_| budget())?;
                    if !change.loss_records.contains(&value) {
                        change.loss_records.push(value);
                    }
                }
            }
        }
        change.source_object_pins = sources.pins();
        change.source_resource_pins = sources.resources.into_values().collect();
        update_project(&mut change)?;
        change.to_arguments()?;
        Ok(PreparedChange {
            change,
            diagnostics,
            dependencies,
        })
    }
}

// Value-only physics reads do not carry an exact numeric-lexeme witness. Keep
// decimal mesh lengths unsupported here rather than treating a rounded Value
// as proof that the original bytes contained an integer. This does not assert
// mesh codec or topology support.
pub(crate) fn physics_mesh_resources(physics: &Value) -> AppResult<Vec<ResourceRef>> {
    validate("PhysicsDefinition", physics)?;
    let mut resources = BTreeMap::<String, ResourceRef>::new();
    for collider in array(physics, "colliders")? {
        let shape = &collider["shape"]["shape"];
        if text(shape, "kind")? == "mesh" {
            let geometry = &shape["geometry"];
            if geometry["sizeBytes"].as_u64().is_none() {
                return Err(AppError::new(
                    "CAPABILITY_UNAVAILABLE",
                    "Physics mesh decimal length requires an original-byte witness",
                ));
            }
            let resource: ResourceRef = decode("ResourceRef", geometry)?;
            let id = resource.resource_id.as_str().to_owned();
            if resources
                .get(&id)
                .is_some_and(|old| !same_resource(old, &resource))
            {
                return Err(conflict());
            }
            resources.insert(id, resource);
        }
    }
    Ok(resources.into_values().collect())
}

pub(crate) fn empty_change(project: &ProjectCatalog, kind: NativeKind) -> PreparedNativeChange {
    PreparedNativeChange {
        format: crate::NATIVE_CHANGE_FORMAT.into(),
        kind,
        project_id: project.project_id().clone(),
        project_base_revision: project.revision().clone(),
        target_profile_id: project.target_profile_id().clone(),
        project_after: project.project().clone(),
        document_changes: vec![],
        world_projection: vec![],
        resource_replacements: vec![],
        recovery_replacements: vec![],
        source_object_pins: vec![],
        source_resource_pins: vec![],
        staged_resources: vec![],
        scene_patch: None,
        pack_manifest: None,
        loss_records: vec![],
    }
}
pub(crate) fn document(
    kind: OwnedKind,
    before_revision: Option<Sha256Digest>,
    after: Value,
) -> AppResult<DocumentChange> {
    let revision = mmmm_contracts::verify_projected_digest(kind.definition(), &after)
        .map_err(|_| conflict())?;
    let object_id = text(&after, kind.id_field())?.to_owned();
    Ok(DocumentChange {
        kind,
        object_id,
        before_revision,
        after_revision: revision,
        after,
    })
}
fn append_draft(
    change: &mut PreparedNativeChange,
    diagnostics: &mut Vec<Value>,
    draft: InstanceDraft,
    before: Option<Instance>,
    definition: Prefab,
) -> AppResult<()> {
    diagnostics.extend(
        draft
            .diagnostics
            .iter()
            .map(|item| serde_json::to_value(item).expect("diagnostic serialization")),
    );
    change.loss_records.extend(
        draft
            .losses
            .iter()
            .map(|item| serde_json::to_value(item).expect("loss serialization")),
    );
    append_instance(change, before, draft.instance, definition)
}
pub(crate) fn append_instance(
    change: &mut PreparedNativeChange,
    before: Option<Instance>,
    after: Instance,
    definition: Prefab,
) -> AppResult<()> {
    change.document_changes.push(document(
        OwnedKind::Instance,
        before.as_ref().map(|value| value.revision.clone()),
        wire("Instance", &after)?,
    )?);
    let before_definition = before.as_ref().map(|_| definition.clone());
    change.world_projection.push(InstanceProjection {
        before,
        before_definition,
        after,
        definition,
        command_modules: vec![],
        clips: vec![],
        physics_definitions: vec![],
        resource_pins: vec![],
    });
    Ok(())
}
pub(crate) fn revise_instance(instance: &mut Instance) -> AppResult<()> {
    instance.revision =
        projected_digest("Instance", &wire("Instance", instance)?).map_err(|_| conflict())?;
    Ok(())
}
pub(crate) fn update_project(change: &mut PreparedNativeChange) -> AppResult<()> {
    let mut identities = BTreeSet::new();
    for document in &change.document_changes {
        if !identities.insert((document.kind, document.object_id.clone())) {
            return Err(AppError::new(
                "ID_COLLISION",
                "Prepared change has duplicate authored object mutations",
            ));
        }
        let owned = change.project_after["ownedResources"]
            .as_array_mut()
            .ok_or_else(conflict)?;
        let previous = owned.iter_mut().find(|pin| {
            pin["objectId"].as_str() == Some(document.object_id.as_str())
                && pin["kind"] == serde_json::to_value(document.kind).expect("owned kind")
        });
        match (previous, &document.before_revision) {
            (Some(pin), Some(before)) => {
                if pin["revision"].as_str() != Some(before.as_str())
                    || pin["kind"] != serde_json::to_value(document.kind).map_err(|_| conflict())?
                {
                    return Err(conflict());
                }
                pin["revision"] = json!(document.after_revision);
            }
            (None, None) => {
                owned.push(json!({"kind":document.kind,"objectId":document.object_id,"revision":document.after_revision}));
                let index = match document.kind {
                    OwnedKind::Instance => Some("instanceIds"),
                    OwnedKind::Prefab => Some("prefabIds"),
                    _ => None,
                };
                if let Some(index) = index {
                    change.project_after[index]
                        .as_array_mut()
                        .ok_or_else(conflict)?
                        .push(json!(document.object_id));
                }
            }
            _ => return Err(conflict()),
        }
    }
    if !change.document_changes.is_empty() {
        for resource in &change.staged_resources {
            let ids = change.project_after["resourceIds"]
                .as_array_mut()
                .ok_or_else(conflict)?;
            if !ids
                .iter()
                .any(|id| id.as_str() == Some(resource.resource_id.as_str()))
            {
                ids.push(json!(resource.resource_id));
            }
        }
    }
    change.project_after["revision"] =
        json!(projected_digest("Project", &change.project_after).map_err(|_| conflict())?);
    ProjectCatalog::from_project(&change.project_after)?;
    Ok(())
}
pub(crate) fn same_resource(left: &ResourceRef, right: &ResourceRef) -> bool {
    left.resource_id == right.resource_id
        && left.sha256 == right.sha256
        && left.media_type == right.media_type
        && left.size_bytes == right.size_bytes
}
pub(crate) fn dependency(
    id: &str,
    digest: &Sha256Digest,
    contracts: &[&str],
    provenance: &str,
) -> AppResult<Value> {
    let value = json!({"componentId":id,"implementationDigest":digest,"contractIds":contracts,"provenanceClass":provenance});
    validate("DependencyPin", &value)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cumulative_source_budget_is_not_only_a_per_object_limit() {
        let mut sources = Sources::default();
        for _ in 0..4 {
            sources.account(8, 40).unwrap();
        }
        assert_eq!(sources.account(9, 40).unwrap_err().code, "BUDGET_EXCEEDED");
    }
}

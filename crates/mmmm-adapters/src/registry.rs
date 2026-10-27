use crate::{
    ActionDescriptor, ActionReadiness, AdapterError, Availability, CompatibilityEvidence,
    ContextField, Diagnostic, DiscoveryRequest, EnvironmentRef, OriginKind, ProviderDescriptor,
    ProviderInventory, RegistrationMode, RegistrationObservation, RouteRequest, RouteResolution,
    RouteStatus, VersionEvidence, decode, wire,
};
use mmmm_contracts::{
    ActionId, BindingId, ContextId, ContractValidator, OfflineActionSchema, Sha256Digest,
    canonical_digest, projected_digest, verify_projected_digest,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const MAX_PROVIDERS: usize = 1024;
const MAX_ACTIONS_PER_PROVIDER: usize = 256;
const MAX_TOTAL_ACTIONS: usize = 8192;
const MAX_REGISTRY_METADATA_BYTES: usize = 3 * 1024 * 1024;

/// Immutable context facts plus permissions supplied from the runtime's actual
/// principal authority. A permission list in provider/profile metadata cannot
/// populate this set. Context digest verification does not authenticate a caller.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteContext {
    context_id: ContextId,
    environment: EnvironmentRef,
    context_digest: Sha256Digest,
    policy_revision: Sha256Digest,
    available_fields: BTreeSet<ContextField>,
    granted_permissions: BTreeSet<String>,
}

impl RouteContext {
    pub fn from_execution_context(
        value: &Value,
        granted_permissions: BTreeSet<String>,
    ) -> Result<Self, AdapterError> {
        ContractValidator::shared()?.validate("ExecutionContext", value)?;
        verify_projected_digest("ExecutionContext", value)?;
        let mut fields = BTreeSet::from([ContextField::Project]);
        for (name, field) in [
            ("dimension", ContextField::Dimension),
            ("executorHandle", ContextField::Executor),
            ("origin", ContextField::Origin),
            ("rotationDegrees", ContextField::Rotation),
            ("anchor", ContextField::Anchor),
            ("selectionRef", ContextField::Selection),
        ] {
            if value.get(name).is_some() {
                fields.insert(field);
            }
        }
        let environment: EnvironmentRef = decode("EnvironmentRef", &value["environment"])?;
        if environment.world_present() {
            fields.insert(ContextField::World);
        }
        Ok(Self {
            context_id: serde_json::from_value(value["contextId"].clone())
                .map_err(|error| AdapterError::new("STALE_CONTEXT", error.to_string()))?,
            environment,
            context_digest: serde_json::from_value(value["contextDigest"].clone())
                .map_err(|error| AdapterError::new("STALE_CONTEXT", error.to_string()))?,
            policy_revision: serde_json::from_value(value["policyRevision"].clone())
                .map_err(|error| AdapterError::new("STALE_CONTEXT", error.to_string()))?,
            available_fields: fields,
            granted_permissions,
        })
    }

    pub fn context_id(&self) -> &ContextId {
        &self.context_id
    }
    pub fn environment(&self) -> &EnvironmentRef {
        &self.environment
    }
    pub fn context_digest(&self) -> &Sha256Digest {
        &self.context_digest
    }
    pub fn policy_revision(&self) -> &Sha256Digest {
        &self.policy_revision
    }
}

struct RegisteredProvider {
    descriptor: ProviderDescriptor,
    observation: RegistrationObservation,
    enabled: bool,
    compatibility_binding: Option<crate::Binding>,
    metadata_bytes: usize,
}

/// Mutable registration authority. Snapshots clone metadata so new registration
/// cannot change already selected bindings or an existing inventory revision.
#[derive(Default)]
pub struct ProviderRegistry {
    providers: BTreeMap<BindingId, RegisteredProvider>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_observed_provider(
        &mut self,
        descriptor: &Value,
        observation: RegistrationObservation,
    ) -> Result<ProviderDescriptor, AdapterError> {
        let descriptor: ProviderDescriptor = decode("ProviderDescriptor", descriptor)?;
        if descriptor.registration_mode != RegistrationMode::Provider
            || observation.origin.kind == OriginKind::LocalProfile
        {
            return Err(AdapterError::new(
                "PROFILE_UNTRUSTED",
                "Compatibility registration requires an approved profile binding",
            ));
        }
        self.insert_observed(descriptor, observation, None)
    }

    pub(crate) fn insert_observed(
        &mut self,
        mut descriptor: ProviderDescriptor,
        observation: RegistrationObservation,
        compatibility_binding: Option<crate::Binding>,
    ) -> Result<ProviderDescriptor, AdapterError> {
        wire("ProviderDescriptor", &descriptor)?;
        if descriptor.environment != observation.environment
            || descriptor.host_protocol_version != observation.host_protocol_version
            || descriptor.host_protocol_version != crate::HOST_PROTOCOL_VERSION
        {
            return Err(AdapterError::new(
                "INTERFACE_MISMATCH",
                "Observed environment or host protocol differs from registration",
            ));
        }
        if descriptor.actions.len() > MAX_ACTIONS_PER_PROVIDER {
            return Err(AdapterError::new(
                "REGISTRY_LIMIT",
                "Too many actions in one provider",
            ));
        }
        let validator = ContractValidator::shared()?;
        let mut action_ids = BTreeSet::new();
        for action in &descriptor.actions {
            if !action_ids.insert(action.action_id.clone()) {
                return Err(AdapterError::new(
                    "INCOMPATIBLE_CONTRACT",
                    "Duplicate action ID in a binding",
                ));
            }
            validator.compile_action_schema(&action.input_schema)?;
            validator.compile_action_schema(&action.output_schema)?;
            if observation.implementation_digests.get(&action.action_id)
                != Some(&action.implementation_digest)
                || !observation.action_readiness.contains_key(&action.action_id)
            {
                return Err(AdapterError::new(
                    "INTERFACE_MISMATCH",
                    "Action implementation or feature readiness lacks an exact observed pin",
                ));
            }
            let readiness = &observation.action_readiness[&action.action_id];
            if readiness.possible_loss_codes.as_ref().is_some_and(|codes| {
                codes.len() > 256 || codes.iter().any(|code| code.is_empty() || code.len() > 128)
            }) {
                return Err(AdapterError::new(
                    "REGISTRY_LIMIT",
                    "Feature loss metadata exceeds bounded limits",
                ));
            }
            if action.side
                != observation.environment.execution_side().ok_or_else(|| {
                    AdapterError::new(
                        "INTERFACE_MISMATCH",
                        "An offline workspace is not an executable provider environment",
                    )
                })?
            {
                return Err(AdapterError::new(
                    "INTERFACE_MISMATCH",
                    "Action side differs from its bound environment",
                ));
            }
            if action.version_evidence > evidence_ceiling(observation.evidence) {
                return Err(AdapterError::new(
                    "INTERFACE_MISMATCH",
                    "Action evidence exceeds authenticated observation",
                ));
            }
        }
        if observation
            .implementation_digests
            .keys()
            .any(|id| !action_ids.contains(id))
            || observation
                .action_readiness
                .keys()
                .any(|id| !action_ids.contains(id))
        {
            return Err(AdapterError::new(
                "INTERFACE_MISMATCH",
                "Observation contains an undeclared action",
            ));
        }
        // Registration origin, evidence, and availability are host-owned facts.
        // The action descriptor itself is preserved byte-semantically, including
        // its unverified version declaration and implementation digest.
        descriptor.origin = observation.origin.clone();
        descriptor.compatibility_evidence = observation.evidence;
        descriptor.availability = effective_availability(&observation, true);
        wire("ProviderDescriptor", &descriptor)?;
        if let Some(existing) = self.providers.get(&descriptor.binding_id) {
            if wire("ProviderDescriptor", &existing.descriptor)?
                != wire("ProviderDescriptor", &descriptor)?
                || serde_json::to_value(&existing.observation).map_err(json_error)?
                    != serde_json::to_value(&observation).map_err(json_error)?
                || existing.compatibility_binding != compatibility_binding
            {
                return Err(AdapterError::new(
                    "BINDING_ID_REUSED",
                    "A binding ID cannot be rebound to new metadata, epoch, implementation or readiness",
                ));
            }
            return Ok(existing.descriptor.clone());
        }
        if self.providers.len() >= MAX_PROVIDERS {
            return Err(AdapterError::new(
                "REGISTRY_LIMIT",
                "Provider registry is full",
            ));
        }
        let metadata = json!({ "descriptor": descriptor, "observation": observation, "binding": compatibility_binding });
        let metadata_bytes = mmmm_contracts::encode_json(&metadata)
            .map_err(|error| AdapterError::new("REGISTRY_LIMIT", error.to_string()))?
            .len();
        if metadata_bytes
            + self
                .providers
                .values()
                .map(|provider| provider.metadata_bytes)
                .sum::<usize>()
            > MAX_REGISTRY_METADATA_BYTES
            || descriptor.actions.len()
                + self
                    .providers
                    .values()
                    .map(|provider| provider.descriptor.actions.len())
                    .sum::<usize>()
                > MAX_TOTAL_ACTIONS
        {
            return Err(AdapterError::new(
                "REGISTRY_LIMIT",
                "Aggregate registration metadata exceeds the registry budget",
            ));
        }
        self.providers.insert(
            descriptor.binding_id.clone(),
            RegisteredProvider {
                descriptor: descriptor.clone(),
                observation,
                enabled: true,
                compatibility_binding,
                metadata_bytes,
            },
        );
        Ok(descriptor)
    }

    /// Disabling affects new snapshots only. The Coordinator retains operation
    /// records for status, reconcile and recovery; this registry deletes none.
    pub fn set_enabled(&mut self, binding: &BindingId, enabled: bool) -> Result<(), AdapterError> {
        self.providers
            .get_mut(binding)
            .ok_or_else(|| {
                AdapterError::new("CAPABILITY_UNAVAILABLE", "Binding is not registered")
            })?
            .enabled = enabled;
        Ok(())
    }

    /// An authenticated host may refresh lifecycle facts without rebinding
    /// action schemas, implementation, origin or epoch. Existing snapshots stay
    /// immutable, and the next snapshot receives a different fingerprint.
    pub fn update_lifecycle(
        &mut self,
        binding: &BindingId,
        loaded: bool,
        connected: bool,
        availability: Availability,
        readiness: BTreeMap<ActionId, ActionReadiness>,
    ) -> Result<(), AdapterError> {
        let provider = self.providers.get_mut(binding).ok_or_else(|| {
            AdapterError::new("CAPABILITY_UNAVAILABLE", "Binding is not registered")
        })?;
        if readiness
            .keys()
            .ne(provider.observation.action_readiness.keys())
            || readiness.values().any(|state| {
                state.possible_loss_codes.as_ref().is_some_and(|codes| {
                    codes.len() > 256
                        || codes.iter().any(|code| code.is_empty() || code.len() > 128)
                })
            })
        {
            return Err(AdapterError::new(
                "INTERFACE_MISMATCH",
                "Lifecycle update changes the registered feature set or exceeds loss limits",
            ));
        }
        // Loss contract is part of the immutable registration. A readiness
        // update cannot quietly introduce additional losses into a pinned route.
        if readiness.iter().any(|(id, state)| {
            state.possible_loss_codes
                != provider.observation.action_readiness[id].possible_loss_codes
        }) {
            return Err(AdapterError::new(
                "INTERFACE_MISMATCH",
                "Changed loss coverage requires a new binding registration",
            ));
        }
        provider.observation.loaded = loaded;
        provider.observation.connected = connected;
        provider.observation.availability = availability;
        provider.observation.action_readiness = readiness;
        Ok(())
    }

    pub fn snapshot(
        &self,
        context: RouteContext,
        policy_revision: Sha256Digest,
    ) -> Result<InventorySnapshot, AdapterError> {
        if policy_revision != context.policy_revision {
            return Err(AdapterError::new(
                "STALE_CONTEXT",
                "Inventory policy revision differs from the frozen context policy",
            ));
        }
        let mut providers = Vec::new();
        let mut observations = BTreeMap::new();
        let mut bindings = BTreeMap::new();
        let mut diagnostics = Vec::new();
        for (binding_id, entry) in &self.providers {
            if entry.descriptor.environment != context.environment {
                continue;
            }
            let mut descriptor = entry.descriptor.clone();
            descriptor.availability = effective_availability(&entry.observation, entry.enabled);
            descriptor
                .actions
                .sort_by(|left, right| left.action_id.cmp(&right.action_id));
            if !entry.observation.loaded {
                diagnostics.push(Diagnostic::warning(
                    "PROVIDER_NOT_LOADED",
                    "Provider deployment metadata is present but its host reports it unloaded",
                    Some(binding_id.clone()),
                ));
            } else if !entry.observation.connected {
                diagnostics.push(Diagnostic::warning(
                    "PROVIDER_DISCONNECTED",
                    "Provider is loaded but disconnected from its authenticated host",
                    Some(binding_id.clone()),
                ));
            }
            for action in &descriptor.actions {
                let readiness = &entry.observation.action_readiness[&action.action_id];
                if !readiness.ready {
                    diagnostics.push(Diagnostic::warning(
                        "FEATURE_NOT_READY",
                        format!("Action {} is registered but not ready", action.action_id),
                        Some(binding_id.clone()),
                    ));
                }
                if action.version_evidence != VersionEvidence::RuntimeVerified {
                    diagnostics.push(Diagnostic::warning(
                        "IMPLEMENTATION_UNVERIFIED",
                        format!(
                            "Action {} has no runtime-verified implementation evidence",
                            action.action_id
                        ),
                        Some(binding_id.clone()),
                    ));
                }
            }
            observations.insert(binding_id.clone(), entry.observation.clone());
            if let Some(binding) = &entry.compatibility_binding {
                bindings.insert(binding_id.clone(), binding.clone());
            }
            providers.push(descriptor);
        }
        let inventory_revision = canonical_digest(&json!({
            "kind": "mmmm-observed-inventory/1", "context": context,
            "policyRevision": policy_revision, "providers": providers,
            "observations": observations, "compatibilityBindings": bindings,
        }))?;
        let inventory = ProviderInventory {
            inventory_revision,
            providers,
            diagnostics,
        };
        wire("ProviderInventory", &inventory)?;
        Ok(InventorySnapshot {
            context,
            policy_revision,
            inventory,
            observations,
            bindings,
        })
    }
}

fn evidence_ceiling(evidence: CompatibilityEvidence) -> VersionEvidence {
    match evidence {
        CompatibilityEvidence::Declared => VersionEvidence::Declared,
        CompatibilityEvidence::InterfaceChecked => VersionEvidence::InterfaceChecked,
        CompatibilityEvidence::FixtureVerified => VersionEvidence::FixtureVerified,
        CompatibilityEvidence::GameVerified => VersionEvidence::RuntimeVerified,
    }
}

fn effective_availability(observation: &RegistrationObservation, enabled: bool) -> Availability {
    if !enabled {
        Availability::Disabled
    } else if !observation.loaded || !observation.connected {
        Availability::Disconnected
    } else if observation.availability == Availability::Available
        && !observation
            .action_readiness
            .values()
            .any(|readiness| readiness.ready)
    {
        Availability::Incompatible
    } else {
        observation.availability
    }
}

fn json_error(error: serde_json::Error) -> AdapterError {
    AdapterError::new("INCOMPATIBLE_CONTRACT", error.to_string())
}

/// A fixed view. Runtime must obtain a fresh snapshot and compare its revision
/// before durable dispatch. An old snapshot remains useful as recorded evidence.
pub struct InventorySnapshot {
    context: RouteContext,
    policy_revision: Sha256Digest,
    inventory: ProviderInventory,
    observations: BTreeMap<BindingId, RegistrationObservation>,
    bindings: BTreeMap<BindingId, crate::Binding>,
}

impl InventorySnapshot {
    pub fn context(&self) -> &RouteContext {
        &self.context
    }
    pub fn policy_revision(&self) -> &Sha256Digest {
        &self.policy_revision
    }
    pub fn revision(&self) -> &Sha256Digest {
        &self.inventory.inventory_revision
    }
    pub fn inventory(&self) -> &ProviderInventory {
        &self.inventory
    }
    pub fn compatibility_binding(&self, id: &BindingId) -> Option<&crate::Binding> {
        self.bindings.get(id)
    }

    pub fn discover(&self, request: &Value) -> Result<Value, AdapterError> {
        let request: DiscoveryRequest = decode("DiscoveryRequest", request)?;
        if request.allow_effects
            || request.context_id != self.context.context_id
            || request.environment != self.context.environment
        {
            return Err(AdapterError::new(
                "STALE_CONTEXT",
                "Discovery is restricted to the pinned, effect-free connected environment",
            ));
        }
        wire("ProviderInventory", &self.inventory)
    }

    pub fn resolve(&self, request: &Value) -> Result<Value, AdapterError> {
        let request: RouteRequest = decode("RouteRequest", request)?;
        if request.inventory_revision != self.inventory.inventory_revision {
            return Err(AdapterError::new(
                "INVENTORY_STALE",
                "Route request does not pin this inventory revision",
            ));
        }
        if request.context_id != self.context.context_id {
            return Err(AdapterError::new(
                "STALE_CONTEXT",
                "Route context differs from inventory context",
            ));
        }
        let guarantees: BTreeSet<_> = request.required_guarantees.iter().collect();
        let acceptable_losses: BTreeSet<_> = request.acceptable_loss_codes.iter().collect();
        let mut candidates = Vec::new();
        let mut diagnostics = Vec::new();
        for provider in &self.inventory.providers {
            if request
                .preferred_binding_id
                .as_ref()
                .is_some_and(|pin| pin != &provider.binding_id)
            {
                continue;
            }
            for action in &provider.actions {
                if action.semantic_kind != request.semantic_kind {
                    continue;
                }
                let readiness =
                    &self.observations[&provider.binding_id].action_readiness[&action.action_id];
                let reason = rejection(
                    provider,
                    action,
                    readiness,
                    &self.context,
                    &guarantees,
                    &acceptable_losses,
                );
                if let Some(reason) = reason {
                    diagnostics.push(Diagnostic::warning(
                        "CANDIDATE_UNAVAILABLE",
                        format!("Action {}: {reason}", action.action_id),
                        Some(provider.binding_id.clone()),
                    ));
                } else {
                    candidates.push((provider, action));
                }
            }
        }
        // Evidence is an explicit observed preference. Equal candidates have
        // stable lexical order; insertion order and provider names confer no rank.
        candidates.sort_by(
            |(left_provider, left_action), (right_provider, right_action)| {
                right_provider
                    .compatibility_evidence
                    .cmp(&left_provider.compatibility_evidence)
                    .then_with(|| {
                        right_action
                            .version_evidence
                            .cmp(&left_action.version_evidence)
                    })
                    .then_with(|| left_provider.binding_id.cmp(&right_provider.binding_id))
                    .then_with(|| left_action.action_id.cmp(&right_action.action_id))
            },
        );
        let resolution = if let Some((provider, action)) = candidates.first() {
            if action.version_evidence != VersionEvidence::RuntimeVerified {
                diagnostics.push(Diagnostic::warning(
                    "IMPLEMENTATION_UNVERIFIED",
                    "The selected declaration has not been runtime verified",
                    Some(provider.binding_id.clone()),
                ));
            }
            RouteResolution {
                status: RouteStatus::Selected,
                binding_id: Some(provider.binding_id.clone()),
                action_id: Some(action.action_id.clone()),
                action_digest: Some(projected_digest(
                    "ActionDescriptor",
                    &wire("ActionDescriptor", action)?,
                )?),
                implementation_digest: Some(action.implementation_digest.clone()),
                diagnostics,
            }
        } else {
            diagnostics.push(Diagnostic::warning("CAPABILITY_UNAVAILABLE", if request.preferred_binding_id.is_some() {
                "The forced preferred binding is missing or does not satisfy the request; no substitute was selected"
            } else { "No registered action satisfies the pinned context, guarantees, permissions and loss policy" }, request.preferred_binding_id));
            RouteResolution {
                status: RouteStatus::Unavailable,
                binding_id: None,
                action_id: None,
                action_digest: None,
                implementation_digest: None,
                diagnostics,
            }
        };
        wire("RouteResolution", &resolution)
    }

    pub fn check_selected_pin(
        &self,
        resolution: &Value,
    ) -> Result<&ActionDescriptor, AdapterError> {
        let resolution: RouteResolution = decode("RouteResolution", resolution)?;
        if resolution.status != RouteStatus::Selected {
            return Err(AdapterError::new(
                "CAPABILITY_UNAVAILABLE",
                "An unavailable route cannot be dispatched",
            ));
        }
        let binding = resolution
            .binding_id
            .ok_or_else(|| AdapterError::new("INVENTORY_STALE", "Selected binding is absent"))?;
        let action_id = resolution
            .action_id
            .ok_or_else(|| AdapterError::new("INVENTORY_STALE", "Selected action is absent"))?;
        let action = self.action(&binding, &action_id)?;
        let digest = projected_digest("ActionDescriptor", &wire("ActionDescriptor", action)?)?;
        if resolution.action_digest.as_ref() != Some(&digest)
            || resolution.implementation_digest.as_ref() != Some(&action.implementation_digest)
        {
            return Err(AdapterError::new(
                "INVENTORY_STALE",
                "Action or implementation pin changed",
            ));
        }
        let provider = self
            .inventory
            .providers
            .iter()
            .find(|provider| provider.binding_id == binding)
            .ok_or_else(|| AdapterError::new("INVENTORY_STALE", "Binding is absent"))?;
        let readiness = &self.observations[&binding].action_readiness[&action_id];
        let guarantees = BTreeSet::new();
        let observed_losses: BTreeSet<&String> = readiness
            .possible_loss_codes
            .as_ref()
            .map(|losses| losses.iter().collect())
            .unwrap_or_default();
        if rejection(
            provider,
            action,
            readiness,
            &self.context,
            &guarantees,
            &observed_losses,
        )
        .is_some()
        {
            return Err(AdapterError::new(
                "CAPABILITY_UNAVAILABLE",
                "Pinned action lacks current readiness, context, side, permission or known loss coverage",
            ));
        }
        Ok(action)
    }

    /// Reproduce the full selection against its original requirements. Use this
    /// together with a fresh revision check before planning or dispatch; the
    /// narrower pin check alone cannot attest the caller's loss/guarantee policy.
    pub fn check_selection(
        &self,
        request: &Value,
        resolution: &Value,
    ) -> Result<&ActionDescriptor, AdapterError> {
        let expected = self.resolve(request)?;
        if &expected != resolution {
            return Err(AdapterError::new(
                "INVENTORY_STALE",
                "Selected route was not produced by this pinned request and inventory",
            ));
        }
        self.check_selected_pin(resolution)
    }

    pub fn action(
        &self,
        binding: &BindingId,
        action: &ActionId,
    ) -> Result<&ActionDescriptor, AdapterError> {
        self.inventory
            .providers
            .iter()
            .find(|provider| &provider.binding_id == binding)
            .and_then(|provider| {
                provider
                    .actions
                    .iter()
                    .find(|candidate| &candidate.action_id == action)
            })
            .ok_or_else(|| {
                AdapterError::new(
                    "CAPABILITY_UNAVAILABLE",
                    "Binding/action is not in this snapshot",
                )
            })
    }

    pub fn input_schema(
        &self,
        binding: &BindingId,
        action: &ActionId,
    ) -> Result<OfflineActionSchema, AdapterError> {
        Ok(ContractValidator::shared()?
            .compile_action_schema(&self.action(binding, action)?.input_schema)?)
    }

    pub fn validate_action_input(
        &self,
        binding: &BindingId,
        action: &ActionId,
        arguments: &Value,
    ) -> Result<(), AdapterError> {
        self.input_schema(binding, action)?.validate(arguments)?;
        Ok(())
    }

    /// Output validation is a provider-report check, never proof of completed
    /// effects or readback. Callers must retain known/unknown effects on error.
    pub fn validate_action_output(
        &self,
        binding: &BindingId,
        action: &ActionId,
        output: &Value,
    ) -> Result<(), AdapterError> {
        ContractValidator::shared()?
            .compile_action_schema(&self.action(binding, action)?.output_schema)?
            .validate(output)
            .map_err(|error| AdapterError::new("OUTPUT_INVALID", error.to_string()))
    }
}

fn rejection(
    provider: &ProviderDescriptor,
    action: &ActionDescriptor,
    readiness: &ActionReadiness,
    context: &RouteContext,
    guarantees: &BTreeSet<&String>,
    acceptable_losses: &BTreeSet<&String>,
) -> Option<&'static str> {
    if provider.availability != Availability::Available {
        return Some("provider is unavailable");
    }
    if !readiness.ready {
        return Some("feature is not ready");
    }
    if Some(action.side) != context.environment.execution_side() {
        return Some("execution side differs");
    }
    if !guarantees
        .iter()
        .all(|guarantee| action.guarantees.contains(guarantee))
    {
        return Some("required guarantee is absent");
    }
    if !action
        .required_context
        .iter()
        .all(|field| context.available_fields.contains(field))
    {
        return Some("required context is absent");
    }
    if !action
        .required_permissions
        .iter()
        .all(|permission| context.granted_permissions.contains(permission))
    {
        return Some("actual principal lacks permission");
    }
    let Some(losses) = &readiness.possible_loss_codes else {
        return Some("possible loss coverage is unknown");
    };
    if !losses.iter().all(|loss| acceptable_losses.contains(loss)) {
        return Some("possible loss is not accepted");
    }
    None
}

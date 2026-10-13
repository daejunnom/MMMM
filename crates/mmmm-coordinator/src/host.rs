//! Concrete paired Java host calls. Installation consumes an opaque capability
//! from an authenticated local bootstrap; public function DTOs cannot install
//! a host, principal, context, authority or replacement binding.

use crate::client::HostRpcClient;
use mmmm_application::{AppError, AppResult, ProviderPort};
use mmmm_contracts::{
    ContextId, ContractValidator, PrincipalId, Sha256Digest, verify_projected_digest,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Default)]
pub struct HostBridge {
    state: Arc<Mutex<BridgeState>>,
}
#[derive(Default)]
struct BridgeState {
    hosts: BTreeMap<ContextId, PairedHost>,
    verified_dependencies: BTreeMap<String, VerifiedDependency>,
}
/// Actual source/build verification installs the complete dependency metadata.
/// A matching digest never authorizes a caller-selected provenance or contract.
pub struct VerifiedDependency {
    component: String,
    digest: Sha256Digest,
    provenance: DependencyProvenance,
    contracts: BTreeSet<String>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DependencyProvenance {
    OwnedDomain,
    TemporaryDomainVendor,
    InfrastructureDependency,
    PlatformShim,
    UserExternalTool,
}
impl DependencyProvenance {
    fn wire(self) -> &'static str {
        match self {
            Self::OwnedDomain => "owned_domain",
            Self::TemporaryDomainVendor => "temporary_domain_vendor",
            Self::InfrastructureDependency => "infrastructure_dependency",
            Self::PlatformShim => "platform_shim",
            Self::UserExternalTool => "user_external_tool",
        }
    }
}
impl VerifiedDependency {
    pub fn new(
        component: String,
        digest: Sha256Digest,
        provenance: DependencyProvenance,
        contracts: BTreeSet<String>,
    ) -> AppResult<Self> {
        mmmm_contracts::ComponentId::new(&component)
            .map_err(|_| error("INVALID_INPUT", "Dependency identity is invalid"))?;
        if contracts.is_empty()
            || contracts.len() > 64
            || contracts
                .iter()
                .any(|contract| contract.is_empty() || contract.len() > 256)
        {
            return Err(error(
                "INVALID_INPUT",
                "Dependency contracts exceed their finite range",
            ));
        }
        Ok(Self {
            component,
            digest,
            provenance,
            contracts,
        })
    }
    fn matches(&self, pin: &Value) -> bool {
        pin["implementationDigest"] == self.digest.as_str()
            && pin["provenanceClass"] == self.provenance.wire()
            && pin["contractIds"].as_array().is_some_and(|contracts| {
                !contracts.is_empty()
                    && contracts.iter().all(|contract| {
                        contract
                            .as_str()
                            .is_some_and(|id| self.contracts.contains(id))
                    })
            })
    }
}
struct PairedHost {
    client: HostRpcClient,
    principal: PrincipalId,
    context: Value,
    hello: Value,
    expires: Instant,
    generation: [u8; 16],
}
/// Opaque in-process ownership of one actual attached route. Public context
/// JSON and a reused context ID cannot remove a later route generation.
pub struct HostRouteOwner {
    context_id: ContextId,
    generation: [u8; 16],
}
impl HostBridge {
    /// Trusted bootstrap only. The host is independently queried before this
    /// exact immutable context becomes routable. Replacement requires detach;
    /// outstanding operations continue to identify the original epoch/binding.
    pub fn attach(
        &self,
        client: HostRpcClient,
        principal: PrincipalId,
        expected_context: Value,
        expected_hello: Value,
        lease: Duration,
    ) -> AppResult<()> {
        self.attach_with_deadline(
            client,
            principal,
            expected_context,
            expected_hello,
            lease,
            Instant::now() + Duration::from_secs(10),
        )
    }
    /// Both actual host observations share one finite native bootstrap deadline.
    /// The second observation does not receive a fresh per-call time budget.
    pub fn attach_with_deadline(
        &self,
        client: HostRpcClient,
        principal: PrincipalId,
        expected_context: Value,
        expected_hello: Value,
        lease: Duration,
        deadline: Instant,
    ) -> AppResult<()> {
        self.attach_owned_with_deadline(
            client,
            principal,
            expected_context,
            expected_hello,
            lease,
            deadline,
        )
        .map(|_| ())
    }
    pub fn attach_owned_with_deadline(
        &self,
        client: HostRpcClient,
        principal: PrincipalId,
        expected_context: Value,
        expected_hello: Value,
        lease: Duration,
        deadline: Instant,
    ) -> AppResult<HostRouteOwner> {
        if lease.is_zero() || lease > Duration::from_secs(24 * 60 * 60) {
            return Err(error(
                "INVALID_INPUT",
                "Host lease is outside its finite range",
            ));
        }
        let lease_expires = Instant::now() + lease;
        validate("ExecutionContext", &expected_context)?;
        validate("HostHello", &expected_hello)?;
        verify_projected_digest("ExecutionContext", &expected_context)
            .map_err(|_| error("STALE_CONTEXT", "Host context digest is invalid"))?;
        let id = context_id(&expected_context)?;
        if expected_context["principalRef"] != principal.as_str()
            || expected_context["environment"] != expected_hello["environment"]
            || expected_hello["hostProtocolVersion"] != "0.2.0"
        {
            return Err(error(
                "STALE_CONTEXT",
                "Host principal or environment differs from bootstrap authority",
            ));
        }
        let hello_deadline = bounded_host_deadline(deadline)?;
        let actual_hello = exchange(&client, "hello", None, json!({}), Some(&hello_deadline))?;
        validate("HostHello", &actual_hello)?;
        if actual_hello != expected_hello {
            return Err(error(
                "STALE_CONTEXT",
                "Actual host hello differs from the approved pairing offer",
            ));
        }
        let context_deadline = bounded_host_deadline(deadline)?;
        let actual_context = exchange(
            &client,
            "inspect",
            Some(&id),
            json!({"kind":"execution_context"}),
            Some(&context_deadline),
        )?;
        validate("ExecutionContext", &actual_context)?;
        if actual_context != expected_context {
            return Err(error(
                "STALE_CONTEXT",
                "Actual installed host context differs from server authority",
            ));
        }
        bounded_host_deadline(deadline)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        state.hosts.retain(|_, host| Instant::now() < host.expires);
        if state.hosts.contains_key(&id) || state.hosts.len() >= 64 {
            return Err(error(
                "HOST_CAPACITY",
                "Host context is already paired or capacity is exhausted",
            ));
        }
        let mut generation = [0u8; 16];
        getrandom::fill(&mut generation)
            .map_err(|_| error("HOST_UNAVAILABLE", "Host route identity is unavailable"))?;
        let owner = HostRouteOwner {
            context_id: id.clone(),
            generation,
        };
        state.hosts.insert(
            id,
            PairedHost {
                client,
                principal,
                context: actual_context,
                hello: actual_hello,
                expires: lease_expires,
                generation,
            },
        );
        Ok(owner)
    }
    pub fn detach_owned(&self, owner: &HostRouteOwner) -> AppResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        if state
            .hosts
            .get(&owner.context_id)
            .is_some_and(|host| host.generation == owner.generation)
        {
            state.hosts.remove(&owner.context_id);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn contains_route_for_test(&self, id: &ContextId) -> AppResult<bool> {
        Ok(self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?
            .hosts
            .contains_key(id))
    }
    pub fn detach(&self, id: &ContextId) -> AppResult<()> {
        self.state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?
            .hosts
            .remove(id);
        Ok(())
    }
    /// A build/source verifier supplies actual local component digests. This
    /// method is neither serialized nor reachable through a facade function.
    pub fn register_verified_dependency(&self, dependency: VerifiedDependency) -> AppResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        if state.verified_dependencies.len() >= 128
            || state
                .verified_dependencies
                .contains_key(&dependency.component)
        {
            return Err(error(
                "DEPENDENCY_CONFLICT",
                "Owned dependency registration conflicts",
            ));
        }
        state
            .verified_dependencies
            .insert(dependency.component.clone(), dependency);
        Ok(())
    }
    pub fn context(&self, principal: &PrincipalId, id: &ContextId) -> AppResult<Value> {
        self.context_with_deadline(principal, id, Instant::now() + Duration::from_secs(10))
    }
    pub fn context_with_deadline(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        deadline: Instant,
    ) -> AppResult<Value> {
        let state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, id, Some(principal))?;
        let expires = bounded_host_deadline(deadline)?;
        let context = exchange(
            &host.client,
            "inspect",
            Some(id),
            json!({"kind":"execution_context"}),
            Some(&expires),
        )?;
        validate("ExecutionContext", &context)?;
        verify_projected_digest("ExecutionContext", &context)
            .map_err(|_| error("STALE_CONTEXT", "Live host context digest is invalid"))?;
        if context["contextId"] != id.as_str()
            || context["principalRef"] != principal.as_str()
            || context["projectId"] != host.context["projectId"]
            || context["environment"] != host.hello["environment"]
        {
            return Err(error(
                "STALE_CONTEXT",
                "Live host identity differs from its paired generation",
            ));
        }
        bounded_host_deadline(deadline)?;
        Ok(context)
    }
    pub fn inspect(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        selector: Value,
    ) -> AppResult<Value> {
        // Always validate live read permission/context before an inspection.
        self.context(principal, id)?;
        let state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, id, Some(principal))?;
        exchange(&host.client, "inspect", Some(id), selector, None)
    }
    pub fn inventory(&self, principal: &PrincipalId, id: &ContextId) -> AppResult<Value> {
        self.context(principal, id)?;
        let state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, id, Some(principal))?;
        let inventory = exchange(&host.client, "inventory", Some(id), json!({}), None)?;
        validate("ProviderInventory", &inventory)?;
        if inventory["providers"].as_array().is_none_or(|providers| {
            providers
                .iter()
                .any(|p| p["environment"] != host.hello["environment"])
        }) {
            return Err(error(
                "STALE_CONTEXT",
                "Host inventory contains a foreign environment",
            ));
        }
        Ok(inventory)
    }
    pub fn hello(&self, principal: &PrincipalId, id: &ContextId) -> AppResult<Value> {
        self.hello_with_deadline(principal, id, Instant::now() + Duration::from_secs(10))
    }
    pub fn hello_with_deadline(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        deadline: Instant,
    ) -> AppResult<Value> {
        self.context_with_deadline(principal, id, deadline)?;
        let state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, id, Some(principal))?;
        let expires = bounded_host_deadline(deadline)?;
        let hello = exchange(&host.client, "hello", None, json!({}), Some(&expires))?;
        if hello != host.hello {
            return Err(error(
                "STALE_CONTEXT",
                "Current host hello differs from its paired epoch",
            ));
        }
        bounded_host_deadline(deadline)?;
        Ok(hello)
    }
    /// The complete original response can be retained as private CAS evidence
    /// by a catalog/shape adapter before it maps an error to its own API.
    pub fn inspect_response(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        selector: Value,
    ) -> AppResult<Value> {
        self.inspect_response_with_deadline(
            principal,
            id,
            selector,
            Instant::now() + Duration::from_secs(10),
        )
    }
    pub fn inspect_response_with_deadline(
        &self,
        principal: &PrincipalId,
        id: &ContextId,
        selector: Value,
        deadline: Instant,
    ) -> AppResult<Value> {
        self.context_with_deadline(principal, id, deadline)?;
        let state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, id, Some(principal))?;
        let expires = bounded_host_deadline(deadline)?;
        let response =
            exchange_response(&host.client, "inspect", Some(id), selector, Some(&expires))?;
        bounded_host_deadline(deadline)?;
        Ok(response)
    }
    pub(crate) fn job_observation(&self, invocation: &Value) -> AppResult<Value> {
        self.invocation(
            "operation.get",
            invocation,
            json!({"invocationId":invocation["invocationId"]}),
            false,
        )
    }
    fn invocation(
        &self,
        method: &str,
        invocation: &Value,
        payload: Value,
        preserve_deadline: bool,
    ) -> AppResult<Value> {
        validate("Invocation", invocation)?;
        let id = context_id(&invocation["context"])?;
        let principal = PrincipalId::new(text(&invocation["context"], "principalRef")?)
            .map_err(|_| error("STALE_CONTEXT", "Stored invocation principal is invalid"))?;
        let current = self.context(&principal, &id)?;
        if current["environment"] != invocation["context"]["environment"] {
            return Err(error(
                "STALE_CONTEXT",
                "Original invocation belongs to a different host epoch",
            ));
        }
        if preserve_deadline
            && (current["contextDigest"] != invocation["contextDigest"]
                || current["policyRevision"] != invocation["context"]["policyRevision"])
        {
            return Err(error(
                "STALE_CONTEXT",
                "New dispatch differs from its frozen context or policy",
            ));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, &id, Some(&principal))?;
        exchange(
            &host.client,
            method,
            Some(&id),
            payload,
            preserve_deadline
                .then(|| invocation["deadlineAt"].as_str())
                .flatten(),
        )
    }
}

fn bounded_host_deadline(deadline: Instant) -> AppResult<String> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| error("TIME_BUDGET_EXCEEDED", "Host bootstrap deadline reached"))?;
    let remaining = remaining.min(Duration::from_secs(10));
    let nanoseconds = i64::try_from(remaining.as_nanos())
        .map_err(|_| error("TIME_BUDGET_EXCEEDED", "Host bootstrap deadline is invalid"))?;
    (time::OffsetDateTime::now_utc() + time::Duration::nanoseconds(nanoseconds))
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| error("HOST_UNAVAILABLE", "Host deadline is unavailable"))
}

pub struct HttpProviderPort {
    bridge: HostBridge,
}
impl HttpProviderPort {
    pub fn new(bridge: HostBridge) -> Self {
        Self { bridge }
    }
}
impl ProviderPort for HttpProviderPort {
    fn registered_read_with_store(
        &mut self,
        _store: &mmmm_runtime::storage::DurableStore,
        request: &Value,
        context: &Value,
    ) -> AppResult<Value> {
        validate("RegisteredActionRequest", request)?;
        let id = context_id(context)?;
        let principal = PrincipalId::new(text(context, "principalRef")?)
            .map_err(|_| error("STALE_CONTEXT", "Context principal is invalid"))?;
        if request["contextId"] != id.as_str() || self.bridge.context(&principal, &id)? != *context
        {
            return Err(error("STALE_CONTEXT", "Registered read context changed"));
        }
        let result = self.bridge.inspect(
            &principal,
            &id,
            json!({"kind":"registered_read","request":request}),
        )?;
        validate_registered_read_result(&result)?;
        Ok(result)
    }
    fn context(&mut self, principal: &PrincipalId, id: &ContextId) -> AppResult<Value> {
        self.bridge.context(principal, id)
    }
    fn action_descriptor(&mut self, step: &Value, context: &Value) -> AppResult<Value> {
        let id = context_id(context)?;
        let principal = PrincipalId::new(text(context, "principalRef")?)
            .map_err(|_| error("STALE_CONTEXT", "Context principal is invalid"))?;
        let live = self.bridge.context(&principal, &id)?;
        if live != *context {
            return Err(error("STALE_CONTEXT", "Action descriptor context changed"));
        }
        let state = self
            .bridge
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        let host = checked_host(&state, &id, Some(&principal))?;
        let descriptor = exchange(
            &host.client,
            "describe",
            Some(&id),
            json!({"bindingId":step["bindingId"],"actionId":step["actionId"]}),
            None,
        )?;
        validate("ActionDescriptor", &descriptor)?;
        Ok(descriptor)
    }
    fn observe_precondition(
        &mut self,
        precondition: &Value,
        context: &Value,
    ) -> AppResult<Sha256Digest> {
        validate("Precondition", precondition)?;
        let id = context_id(context)?;
        let principal = PrincipalId::new(text(context, "principalRef")?)
            .map_err(|_| error("STALE_CONTEXT", "Context principal is invalid"))?;
        let observed = self.bridge.inspect(
            &principal,
            &id,
            json!({"kind":"precondition", "precondition":precondition}),
        )?;
        Sha256Digest::new(text(&observed, "observedDigest")?)
            .map_err(|_| error("OBSERVATION_INVALID", "Host precondition digest is invalid"))
    }
    fn verify_dependencies(&mut self, pins: &[Value], context: &Value) -> AppResult<()> {
        if pins.len() > 128 {
            return Err(error(
                "BUDGET_EXCEEDED",
                "Dependency pin count exceeds its budget",
            ));
        }
        let id = context_id(context)?;
        let principal = PrincipalId::new(text(context, "principalRef")?)
            .map_err(|_| error("STALE_CONTEXT", "Context principal is invalid"))?;
        let inventory = self.bridge.inventory(&principal, &id)?;
        let state = self
            .bridge
            .state
            .lock()
            .map_err(|_| error("HOST_UNAVAILABLE", "Host state is unavailable"))?;
        for pin in pins {
            validate("DependencyPin", pin)?;
            let component = text(pin, "componentId")?;
            let digest = text(pin, "implementationDigest")?;
            let approved = state
                .verified_dependencies
                .get(component)
                .filter(|dependency| dependency.matches(pin))
                .ok_or_else(|| {
                    error(
                        "STALE_DEPENDENCY",
                        "Pinned dependency metadata has no approved source registration",
                    )
                })?;
            let host = inventory["providers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|p| p["bindingId"] == component)
                .flat_map(|p| p["actions"].as_array().into_iter().flatten())
                .any(|a| a["implementationDigest"] == digest);
            // Platform and external registrations also require the currently
            // paired host to expose the exact binding implementation. An owned
            // source cannot be relabeled as a native or third-party provider.
            if matches!(
                approved.provenance,
                DependencyProvenance::PlatformShim | DependencyProvenance::UserExternalTool
            ) && !host
            {
                return Err(error(
                    "STALE_DEPENDENCY",
                    "Pinned implementation has no current approved registration",
                ));
            }
        }
        Ok(())
    }
    fn dispatch(&mut self, invocation: &Value) -> AppResult<Value> {
        let result = self
            .bridge
            .invocation("dispatch", invocation, invocation.clone(), true)?;
        validate("ProviderResult", &result)?;
        Ok(result)
    }
    fn poll(&mut self, invocation: &Value, receipt: Option<&str>) -> AppResult<Option<Value>> {
        let observed = self.bridge.invocation(
            "operation.get",
            invocation,
            json!({"invocationId":invocation["invocationId"]}),
            false,
        )?;
        if observed["invocationId"] != invocation["invocationId"]
            || !observed["providerCompleted"].is_boolean()
        {
            return Err(error(
                "OBSERVATION_INVALID",
                "Host job observation does not identify the original invocation",
            ));
        }
        let Some(result) = observed.get("result") else {
            return Ok(None);
        };
        validate("ProviderResult", result)?;
        if receipt.is_some_and(|r| {
            result["jobHandle"]
                .as_str()
                .is_some_and(|actual| actual != r)
        }) {
            return Err(error(
                "OBSERVATION_INVALID",
                "Host job handle differs from the retained receipt",
            ));
        }
        Ok(Some(result.clone()))
    }
    fn request_cancel(&mut self, invocation: &Value, _receipt: Option<&str>) -> AppResult<()> {
        let response = self.bridge.invocation(
            "operation.cancel",
            invocation,
            json!({"invocationId":invocation["invocationId"]}),
            false,
        )?;
        if response["invocationId"] != invocation["invocationId"]
            || response["cancellationRequested"] != true
        {
            return Err(error(
                "CANCEL_UNCONFIRMED",
                "Original host did not acknowledge the cancellation request",
            ));
        }
        // This acknowledges a request only; no stopped-effect assertion.
        Ok(())
    }
}

fn checked_host<'a>(
    state: &'a BridgeState,
    id: &ContextId,
    principal: Option<&PrincipalId>,
) -> AppResult<&'a PairedHost> {
    let host = state
        .hosts
        .get(id)
        .ok_or_else(|| error("CONTEXT_UNKNOWN", "No host is paired for this context"))?;
    if Instant::now() >= host.expires || principal.is_some_and(|p| p != &host.principal) {
        return Err(error(
            "PERMISSION_REQUIRED",
            "Paired host lease or principal is invalid",
        ));
    }
    Ok(host)
}
fn exchange(
    client: &HostRpcClient,
    method: &str,
    id: Option<&ContextId>,
    payload: Value,
    deadline: Option<&str>,
) -> AppResult<Value> {
    let response = exchange_response(client, method, id, payload, deadline)?;
    if response["status"] != "ok" {
        return Err(error(
            "HOST_REQUEST_FAILED",
            "The original host rejected or could not complete the request",
        ));
    }
    response
        .get("payload")
        .cloned()
        .ok_or_else(|| error("HOST_RESPONSE_INVALID", "Host response payload is absent"))
}
fn exchange_response(
    client: &HostRpcClient,
    method: &str,
    id: Option<&ContextId>,
    payload: Value,
    deadline: Option<&str>,
) -> AppResult<Value> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|_| error("HOST_UNAVAILABLE", "Request identity is unavailable"))?;
    let request_id: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let deadline = match deadline {
        Some(deadline) => deadline.to_owned(),
        None => (time::OffsetDateTime::now_utc() + time::Duration::seconds(10))
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| error("HOST_UNAVAILABLE", "Host deadline is unavailable"))?,
    };
    let request = json!({"protocolVersion":"0.2.0","requestId":request_id,"method":method,"contextId":id.map(ContextId::as_str),"payload":payload,"deadlineAt":deadline});
    let response = client.call(&request).map_err(|_| {
        error(
            "HOST_RESULT_UNKNOWN",
            "Authenticated host call did not yield a validated response",
        )
    })?;
    Ok(response)
}
fn context_id(context: &Value) -> AppResult<ContextId> {
    ContextId::new(text(context, "contextId")?)
        .map_err(|_| error("STALE_CONTEXT", "Context identity is invalid"))
}
fn text<'a>(value: &'a Value, key: &str) -> AppResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| error("HOST_RESPONSE_INVALID", "Required host field is absent"))
}
fn validate(definition: &str, value: &Value) -> AppResult<()> {
    ContractValidator::shared()
        .and_then(|v| v.validate(definition, value))
        .map_err(|_| {
            error(
                "HOST_CONTRACT_INVALID",
                "Host value violates its canonical contract",
            )
        })
}
fn error(code: &'static str, message: &'static str) -> AppError {
    AppError::new(code, message)
}
fn validate_registered_read_result(result: &Value) -> AppResult<()> {
    validate("ProviderResult", result)?;
    if result["status"] == "job_accepted"
        || result["effects"] != "none"
        || result.get("jobHandle").is_some()
    {
        return Err(error(
            "OBSERVATION_INVALID",
            "Registered read returned a job or write-effect claim",
        ));
    }
    // A valid failed read preserves its original diagnostics and error status.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dependency_pin_cannot_change_provenance_or_claim_an_unimplemented_contract() {
        let digest = mmmm_contracts::raw_digest(b"actual owned implementation source");
        let dependency = VerifiedDependency::new(
            "mmmm.planner".into(),
            digest.clone(),
            DependencyProvenance::OwnedDomain,
            ["FN09".to_owned(), "FN15".to_owned()].into(),
        )
        .unwrap();
        let mut pin = json!({"componentId":"mmmm.planner","implementationDigest":digest,"provenanceClass":"owned_domain","contractIds":["FN09"]});
        assert!(dependency.matches(&pin));
        pin["provenanceClass"] = json!("platform_shim");
        assert!(!dependency.matches(&pin));
        pin["provenanceClass"] = json!("owned_domain");
        pin["contractIds"] = json!(["FN18"]);
        assert!(!dependency.matches(&pin));
    }
    #[test]
    fn valid_failed_registered_read_preserves_native_reason_without_resending() {
        // The ordinary example contains a successful read only; this negative
        // report checks the status/diagnostic boundary rather than native game.
        let failed = json!({"contractVersion":"0.2.0","status":"failed","data":{},"effects":"none","diagnostics":[{"severity":"error","code":"ACTUAL_NATIVE_READ_DENIED","message":"Current native read permission ended"}],"artifacts":[]});
        validate_registered_read_result(&failed).unwrap();
        assert_eq!(
            failed["diagnostics"][0]["code"],
            "ACTUAL_NATIVE_READ_DENIED"
        );
        let mut unsupported = failed.clone();
        unsupported["effects"] = json!("unknown");
        assert!(validate_registered_read_result(&unsupported).is_err());
    }
}

//! One current completed native pairing may issue a local-only registry read
//! source. Raw game/mod/pack receipts remain observations, never source grants
//! or a complete target identity. No wire input constructs this admission.

use crate::{
    auth::AuthenticatedPrincipal,
    authority::LocalAuthority,
    catalog_source::{
        CatalogEnvironmentRegistration, CatalogSourceBacking, CatalogSourceRegistration,
        NativeCatalogAdmissionState, NativeCatalogPublication, RegisteredCatalogSources,
        source_facts_pin, validate_source_facts,
    },
    host::{CompletedPairingWitness, HostBridge, NativePairingOwnerFailure},
    service::{RequestBudget, RequestContextSlot, RequestContextWitness},
};
use mmmm_application::{AppError, AppResult};
use mmmm_contracts::{
    ContextId, ContractValidator, Sha256Digest, canonical_digest, encode_json, parse_json,
};
use mmmm_reference::{
    CatalogLayer, CatalogSourceCodec, CatalogSourceRole, MAX_NATIVE_REGISTRY_BYTES,
    NATIVE_REGISTRY_FORMAT, RegistryCaptureWitness,
};
use mmmm_runtime::storage::DurableStore;
use serde_json::{Value, json};
use std::{collections::BTreeMap, rc::Rc};

/// A hook belongs only to the current borrowed CatalogCall. Absence denies
/// native source I/O; explicit source publishers never invoke this port.
pub(crate) trait NativeCatalogCheckpoint {
    fn check(&self, store: &DurableStore) -> AppResult<()>;
}
struct CurrentNativeCatalogCheckpoint {
    request: RequestContextWitness,
    principal: AuthenticatedPrincipal,
    context: Value,
    budget: RequestBudget,
    pairing: CompletedPairingWitness,
    authority: LocalAuthority,
    policy: Sha256Digest,
    sources: RegisteredCatalogSources,
    publication: NativeCatalogPublication,
}
impl NativeCatalogCheckpoint for CurrentNativeCatalogCheckpoint {
    fn check(&self, store: &DurableStore) -> AppResult<()> {
        let result = (|| {
            check_request(&self.request, &self.principal, &self.context, &self.budget)?;
            self.pairing
                .with_current_native_owner(store, &self.authority, |owner| {
                    let current = owner.read_host_policy()?;
                    if !current.policy().native_observation_user_local_only()
                        || current.policy_digest() != &self.policy
                    {
                        return Err(denied());
                    }
                    owner.check_current()
                })
        })();
        match result {
            Ok(()) => Ok(()),
            Err(primary) => combine(
                Err(primary),
                self.sources.retire_native_publication(&self.publication),
            ),
        }
    }
}

/// Private construction retains the result of the real consumer's complete
/// checks. A policy record, source descriptor or matching digest is not this
/// type. The registry accepts it only through its separate native publisher.
pub(crate) struct NativeCatalogObservation {
    registration: CatalogEnvironmentRegistration,
    proof: Sha256Digest,
    method: String,
}
impl NativeCatalogObservation {
    pub(crate) fn into_parts(self) -> (CatalogEnvironmentRegistration, Sha256Digest, String) {
        (self.registration, self.proof, self.method)
    }
}

pub(crate) struct NativeCatalogAdmission<'a> {
    pub(crate) request: &'a RequestContextSlot,
    pub(crate) authority: &'a LocalAuthority,
    pub(crate) hosts: &'a HostBridge,
    pub(crate) sources: &'a RegisteredCatalogSources,
}
impl NativeCatalogAdmission<'_> {
    /// Capture obtains a fresh call-scoped hook after access admission. The
    /// long-lived source registry retains only its origin proof and receipt.
    pub(crate) fn checkpoint(
        &self,
        principal: &AuthenticatedPrincipal,
        context: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> AppResult<Option<Rc<dyn NativeCatalogCheckpoint>>> {
        let publication = match self.sources.native_admission_state(principal, context)? {
            NativeCatalogAdmissionState::Explicit => return Ok(None),
            NativeCatalogAdmissionState::Missing => return Err(denied()),
            NativeCatalogAdmissionState::Native(publication) => publication,
        };
        let result = (|| {
            let request = self.request.occupied_witness().map_err(service_error)?;
            check_request(&request, principal, context, budget)?;
            let id = ContextId::new(text(context, "contextId")?).map_err(|_| denied())?;
            let pairing = self
                .hosts
                .completed_pairing_witness(&request, self.authority, &id)?;
            if pairing.context() != context {
                return Err(denied());
            }
            let policy = pairing.with_current_native_owner(store, self.authority, |owner| {
                let record = owner.read_host_policy()?;
                if !record.policy().native_observation_user_local_only() {
                    return Err(denied());
                }
                Ok(record.policy_digest().clone())
            })?;
            let checkpoint: Rc<dyn NativeCatalogCheckpoint> =
                Rc::new(CurrentNativeCatalogCheckpoint {
                    request,
                    principal: principal.clone(),
                    context: context.clone(),
                    budget: budget.clone(),
                    pairing,
                    authority: self.authority.clone(),
                    policy,
                    sources: self.sources.clone(),
                    publication: publication.clone(),
                });
            Ok(Some(checkpoint))
        })();
        match result {
            Ok(checkpoint) => Ok(checkpoint),
            Err(primary) => combine(
                Err(primary),
                self.sources.retire_native_publication(&publication),
            ),
        }
    }

    pub(crate) fn ensure(
        &self,
        principal: &AuthenticatedPrincipal,
        context: &Value,
        store: &DurableStore,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        let request = self.request.occupied_witness().map_err(service_error)?;
        check_request(&request, principal, context, budget)?;
        let mut publication = match self.sources.native_admission_state(principal, context)? {
            // Explicit composition has its own source/rights authority. It is
            // neither replaced nor forced through native local-owner policy.
            NativeCatalogAdmissionState::Explicit => return Ok(()),
            NativeCatalogAdmissionState::Missing if request.method() != "catalog.capture" => {
                return Ok(());
            }
            NativeCatalogAdmissionState::Missing => None,
            NativeCatalogAdmissionState::Native(publication) => Some(publication),
        };
        let result = (|| {
            let id = ContextId::new(text(context, "contextId")?).map_err(|_| denied())?;
            let pairing = self
                .hosts
                .completed_pairing_witness(&request, self.authority, &id)?;
            if pairing.context() != context {
                return Err(denied());
            }
            pairing.with_current_native_owner(store, self.authority, |owner| {
                let policy = owner.read_host_policy()?;
                if !policy.policy().native_observation_user_local_only() {
                    return Err(denied());
                }
                let checkpoint = || {
                    check_request(&request, principal, context, budget)?;
                    owner.check_current()?;
                    let current = owner.read_host_policy()?;
                    if current != policy || !current.policy().native_observation_user_local_only() {
                        return Err(denied());
                    }
                    owner.check_current()
                };
                let hello = checked(
                    || {
                        self.hosts.hello_with_deadline(
                            principal.principal(),
                            &id,
                            budget.deadline(),
                        )
                    },
                    checkpoint,
                )?;
                let facts = checked(
                    || self.inspection(principal, &id, "runtime_sources", budget),
                    checkpoint,
                )?;
                let registry = checked(
                    || self.inspection(principal, &id, "native_registry", budget),
                    checkpoint,
                )?;
                let final_facts = checked(
                    || self.inspection(principal, &id, "runtime_sources", budget),
                    checkpoint,
                )?;
                let final_hello = checked(
                    || {
                        self.hosts.hello_with_deadline(
                            principal.principal(),
                            &id,
                            budget.deadline(),
                        )
                    },
                    checkpoint,
                )?;
                let final_context = checked(
                    || {
                        self.hosts.context_with_deadline(
                            principal.principal(),
                            &id,
                            budget.deadline(),
                        )
                    },
                    checkpoint,
                )?;
                checkpoint()?;
                let witness = validate_observation(context, &hello, &facts, &registry)?;
                validate_source_facts(&final_facts, context)?;
                if hello != final_hello
                    || final_context != *context
                    || hello["hostBuild"] != policy.host_artifact_digest().as_str()
                    || source_facts_pin(&facts)? != source_facts_pin(&final_facts)?
                {
                    return Err(drift());
                }
                let proof = canonical_digest(&json!({
                    "format":"mmmm.native-catalog-source-admission/1",
                    "principal":principal.principal(), "context":context,
                    "completedOffer":pairing.offer_digest(),
                    "nativeOwner":pairing.native_owner(), "readPolicy":policy.policy_digest(),
                    "hello":hello, "sourceFacts":source_facts_pin(&facts)?,
                    "registryDigest":witness.registry_digest,
                    "generation":witness.registry_generation, "locale":witness.locale,
                }))
                .map_err(|_| invalid())?;
                let source = json!({
                    "sourceId":"native-registry-observation", "kind":"runtime_observation",
                    "locator":format!("mmmm-host://catalog/{}/native_registry", id.as_str()),
                    "sha256":null, "rights":"user_local_only", "verifiedAt":witness.observed_at,
                });
                let registration = CatalogEnvironmentRegistration {
                    context: context.clone(),
                    game_version: Some(witness.game_version),
                    locale: Some(witness.locale),
                    artifact_source: None,
                    server_pack_sources: None,
                    client_pack_sources: None,
                    mod_sources: None,
                    registry_generation: Some(witness.registry_generation),
                    native_mod_ids: BTreeMap::new(),
                    sources: vec![CatalogSourceRegistration {
                        source,
                        layer: CatalogLayer::EnvironmentSnapshot,
                        role: CatalogSourceRole::CatalogData,
                        codec: CatalogSourceCodec::NativeRegistry,
                        backing: CatalogSourceBacking::NativeRegistry,
                    }],
                };
                checkpoint()?;
                publication = Some(self.sources.register_native_observation(
                    principal,
                    budget,
                    store,
                    NativeCatalogObservation {
                        registration,
                        proof,
                        method: request.method().to_owned(),
                    },
                )?);
                checkpoint()
            })
        })();
        match result {
            Ok(()) => Ok(()),
            Err(primary) => {
                let retired = publication.as_ref().map_or(Ok(()), |publication| {
                    self.sources.retire_native_publication(publication)
                });
                combine(Err(primary), retired)
            }
        }
    }

    fn inspection(
        &self,
        principal: &AuthenticatedPrincipal,
        context: &ContextId,
        kind: &'static str,
        budget: &RequestBudget,
    ) -> AppResult<Value> {
        let response = self
            .hosts
            .inspect_acquired_with_deadline(
                principal.principal(),
                context,
                json!({"kind":kind}),
                budget.deadline(),
            )?
            .into_response()?;
        if response["status"] != "ok" {
            return Err(AppError::caused_by(
                "HOST_REQUEST_FAILED",
                "Actual native catalog inspection failed",
                NativeCatalogHostFailure { response },
            ));
        }
        response.get("payload").cloned().ok_or_else(invalid)
    }
}

fn check_request(
    request: &RequestContextWitness,
    principal: &AuthenticatedPrincipal,
    context: &Value,
    budget: &RequestBudget,
) -> AppResult<()> {
    request.check_local().map_err(service_error)?;
    if !matches!(
        request.method(),
        "catalog.capture" | "catalog.search" | "catalog.describe"
    ) || !request.authenticated().same_session(principal)
        || !principal.is_current()
        || !principal.permits(request.method())
        || !principal.permits_context(text(context, "contextId")?)
        || request.budget().deadline() != budget.deadline()
        || !std::ptr::eq(request.budget().cancellation(), budget.cancellation())
        || context["environment"]["kind"] != "game"
        || context["principalRef"] != principal.principal().as_str()
    {
        return Err(denied());
    }
    Ok(())
}

fn checked<T>(
    work: impl FnOnce() -> AppResult<T>,
    checkpoint: impl Fn() -> AppResult<()>,
) -> AppResult<T> {
    checkpoint()?;
    let output = work();
    combine(output, checkpoint())
}
fn combine<T>(output: AppResult<T>, checkpoint: AppResult<()>) -> AppResult<T> {
    match (output, checkpoint) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(cause), Ok(())) | (Ok(_), Err(cause)) => Err(cause),
        (Err(primary), Err(checkpoint)) => Err(AppError::caused_by(
            primary.code,
            primary.message,
            NativePairingOwnerFailure {
                primary,
                checkpoint,
            },
        )),
    }
}

/// This binds the raw registry envelope to the actual route and source facts.
/// The existing capture decoder still owns semantic registry record decoding.
fn validate_observation(
    context: &Value,
    hello: &Value,
    facts: &Value,
    registry: &Value,
) -> AppResult<RegistryCaptureWitness> {
    let validator = ContractValidator::shared().map_err(|_| invalid())?;
    validator
        .validate("HostHello", hello)
        .map_err(|_| invalid())?;
    validate_source_facts(facts, context)?;
    if hello["environment"] != context["environment"]
        || encode_json(registry).map_err(|_| invalid())?.len()
            > MAX_NATIVE_REGISTRY_BYTES.saturating_mul(2) + 16 * 1024
        || registry.as_object().is_none_or(|o| o.len() != 10)
    {
        return Err(invalid());
    }
    let hex = text(registry, "observationBytesHex")?;
    if hex.len() > MAX_NATIVE_REGISTRY_BYTES.saturating_mul(2) || hex.len() % 2 != 0 {
        return Err(invalid());
    }
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(invalid()),
    };
    let bytes = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|p| Ok(digit(p[0])? * 16 + digit(p[1])?))
        .collect::<AppResult<Vec<_>>>()?;
    let mut metadata = registry.clone();
    metadata
        .as_object_mut()
        .ok_or_else(invalid)?
        .remove("observationBytesHex");
    let witness: RegistryCaptureWitness =
        serde_json::from_value(metadata).map_err(|_| invalid())?;
    let valid_tick = |s: &str| {
        !s.is_empty()
            && s.len() <= 128
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s == "0" || !s.starts_with('0'))
    };
    if witness.context_digest.as_str() != text(context, "contextDigest")?
        || witness.environment != context["environment"]
        || witness.registry_digest.as_str() != text(hello, "registryDigest")?
        || witness.registry_generation != text(facts, "registryGeneration")?
        || witness.game_version != text(hello, "gameVersion")?
        || witness.locale.is_empty()
        || witness.locale.len() > 256
        || !valid_tick(&witness.observed_from_tick)
        || !valid_tick(&witness.observed_to_tick)
        || (
            witness.observed_from_tick.len(),
            &witness.observed_from_tick,
        ) > (witness.observed_to_tick.len(), &witness.observed_to_tick)
    {
        return Err(drift());
    }
    validator
        .validate(
            "SourceRef",
            &json!({
                "sourceId":"registry-witness", "kind":"runtime_observation",
                "locator":"mmmm-host://registry/witness", "sha256":null,
                "rights":"user_local_only", "verifiedAt":witness.observed_at,
            }),
        )
        .map_err(|_| invalid())?;
    let raw = parse_json(&bytes).map_err(|_| invalid())?;
    if raw.as_object().is_none_or(|o| o.len() != 4)
        || raw["format"] != NATIVE_REGISTRY_FORMAT
        || ["blocks", "items", "entityTypes"]
            .iter()
            .any(|field| raw[*field].as_array().is_none_or(|a| a.len() > 100_000))
        || canonical_digest(&raw).map_err(|_| invalid())? != witness.registry_digest
    {
        return Err(invalid());
    }
    Ok(witness)
}

/// A real validated failure response remains private and typed even when no
/// source grant exists yet. Formatting never prints its original body.
pub(crate) struct NativeCatalogHostFailure {
    pub(crate) response: Value,
}
impl std::fmt::Debug for NativeCatalogHostFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeCatalogHostFailure")
            .field("has_response", &self.response.is_object())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for NativeCatalogHostFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Opaque original native catalog failure response retained")
    }
}
impl std::error::Error for NativeCatalogHostFailure {}
fn text<'a>(value: &'a Value, field: &str) -> AppResult<&'a str> {
    value.get(field).and_then(Value::as_str).ok_or_else(invalid)
}
fn service_error(cause: crate::service::ServiceError) -> AppError {
    AppError::caused_by(cause.code, cause.message, cause)
}
fn denied() -> AppError {
    AppError::new(
        "PERMISSION_REQUIRED",
        "Current explicit native observation source authority required",
    )
}
fn invalid() -> AppError {
    AppError::new(
        "SOURCE_INVALID",
        "Actual native catalog observation is invalid",
    )
}
fn drift() -> AppError {
    AppError::new("TARGET_DRIFT", "Actual native catalog observation changed")
}

#[cfg(test)]
#[path = "native_catalog_tests.rs"]
mod tests;

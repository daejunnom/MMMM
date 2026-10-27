//! Symbol-table payloads have no canonical wire DTO in the handoff. This typed
//! internal port preserves that boundary instead of inventing a public schema.

use crate::{ContextComponent, NumericType};
use mmmm_contracts::{ResourceLocation, Sha256Digest, StateId, SymbolId, raw_digest};
use mmmm_domain::{DomainError, types::ResourceRef};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingAddress {
    Score {
        holder: String,
        objective: String,
    },
    Storage {
        storage: ResourceLocation,
        path: String,
    },
}

impl BindingAddress {
    pub(crate) fn validate(&self, numeric_type: NumericType) -> Result<(), DomainError> {
        match self {
            Self::Score { holder, objective }
                if numeric_type == NumericType::Int32
                    && safe_atom(holder, 40, true)
                    && safe_atom(objective, 16, false) =>
            {
                Ok(())
            }
            Self::Storage { storage, path }
                if storage.as_str().len() <= 256 && safe_nbt_path(path) =>
            {
                Ok(())
            }
            _ => Err(DomainError::new(
                "SCHEMA_INVALID",
                "Unsafe or type-incompatible symbol address",
            )),
        }
    }
    pub(crate) fn description(&self) -> String {
        match self {
            Self::Score { holder, objective } => format!("score:{holder}:{objective}"),
            Self::Storage { storage, path } => format!("storage:{storage}:{path}"),
        }
    }
}

fn safe_atom(value: &str, max: usize, hash: bool) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'.' | b'-')
                || (hash && byte == b'#')
        })
}

pub(crate) fn safe_nbt_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && path.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

#[derive(Debug, Clone)]
pub struct SymbolBinding {
    pub symbol_id: SymbolId,
    pub numeric_type: NumericType,
    pub unit: String,
    pub address: BindingAddress,
}

/// The port must load authorization from authenticated context, match bindings
/// to these immutable bytes, and require exact numeric NBT tags in the game
/// scope before invocation. Context bindings must be freshly prepared from the
/// same execution origin; this compiler does not fabricate an origin provider.
pub trait SymbolTableVerifier {
    fn verify_symbols(
        &self,
        resource: &ResourceRef,
        bytes: &[u8],
        states: &BTreeMap<StateId, SymbolBinding>,
        context: &BTreeMap<ContextComponent, SymbolBinding>,
    ) -> Result<Sha256Digest, DomainError>;
}

#[derive(Debug, Clone)]
pub struct ResolvedSymbols {
    resource: ResourceRef,
    states: BTreeMap<StateId, SymbolBinding>,
    context: BTreeMap<ContextComponent, SymbolBinding>,
    authority_digest: Sha256Digest,
}

impl ResolvedSymbols {
    pub fn verify(
        resource: ResourceRef,
        bytes: &[u8],
        states: BTreeMap<StateId, SymbolBinding>,
        context: BTreeMap<ContextComponent, SymbolBinding>,
        verifier: &dyn SymbolTableVerifier,
    ) -> Result<Self, DomainError> {
        if bytes.len() > 8 * 1024 * 1024
            || states.len() + context.len() > 4096
            || resource.size_bytes != bytes.len() as u64
            || raw_digest(bytes) != resource.sha256
        {
            return Err(DomainError::new(
                "RESOURCE_DIGEST_MISMATCH",
                "Symbol snapshot identity/budget mismatch",
            ));
        }
        let mut symbols = std::collections::BTreeSet::new();
        for binding in states.values().chain(context.values()) {
            binding.address.validate(binding.numeric_type)?;
            if binding.unit.is_empty()
                || binding.unit.len() > 128
                || !symbols.insert(&binding.symbol_id)
            {
                return Err(DomainError::new(
                    "SCHEMA_INVALID",
                    "Duplicate/invalid symbol binding",
                ));
            }
        }
        let authorization = verifier.verify_symbols(&resource, bytes, &states, &context)?;
        // Defensively pin the resolved interpretation as well as the original
        // bytes and authorization. A changed address/codec interpretation must
        // not reuse the same generated-state identity even if an adapter's
        // authorization witness remains unchanged.
        let authority_digest = mmmm_contracts::canonical_digest(&serde_json::json!({
            "resource": resource, "authorization": authorization,
            "states": states.iter().map(|(id, binding)| serde_json::json!({"stateId": id,
                "binding": binding_identity(binding)})).collect::<Vec<_>>(),
            "context": context.iter().map(|(component, binding)| serde_json::json!({"component": component,
                "binding": binding_identity(binding)})).collect::<Vec<_>>()
        })).map_err(|error| DomainError::new("NUMERIC_RANGE", error.to_string()))?;
        Ok(Self {
            resource,
            states,
            context,
            authority_digest,
        })
    }
    pub(crate) fn matches(&self, resource: &ResourceRef) -> bool {
        self.resource.resource_id == resource.resource_id
            && self.resource.sha256 == resource.sha256
            && self.resource.media_type == resource.media_type
            && self.resource.size_bytes == resource.size_bytes
    }
    pub(crate) fn state(&self, id: &StateId) -> Option<&SymbolBinding> {
        self.states.get(id)
    }
    pub(crate) fn context(&self, component: ContextComponent) -> Option<&SymbolBinding> {
        self.context.get(&component)
    }
    pub(crate) fn authority_digest(&self) -> &Sha256Digest {
        &self.authority_digest
    }
}

fn binding_identity(binding: &SymbolBinding) -> serde_json::Value {
    let address = match &binding.address {
        BindingAddress::Score { holder, objective } => {
            serde_json::json!({"kind": "score", "holder": holder, "objective": objective})
        }
        BindingAddress::Storage { storage, path } => {
            serde_json::json!({"kind": "storage", "storage": storage, "path": path})
        }
    };
    serde_json::json!({"symbolId": binding.symbol_id, "type": binding.numeric_type,
        "unit": binding.unit, "address": address})
}

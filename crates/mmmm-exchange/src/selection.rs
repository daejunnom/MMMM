//! Qualified stable identities, revision pins and selection boundaries. Labels
//! never participate in object identity and an omitted object is not a deletion.
use crate::{ExchangeError, ExchangeResult, array, text, validate};
use mmmm_contracts::verify_projected_digest;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectNode {
    pub instance_id: String,
    pub node_id: String,
}

#[derive(Clone, Debug)]
pub struct Selection {
    value: Value,
    nodes: BTreeMap<ObjectNode, Value>,
    instance_prefabs: BTreeMap<String, String>,
}
impl Selection {
    pub fn from_value(value: &Value) -> ExchangeResult<Self> {
        validate("SceneSelectionSnapshot", value)?;
        crate::physics::SelectionIndex::from_value(value)?;
        let instances = array(value, "instances")?;
        let prefabs = array(value, "prefabs")?;
        if instances.len() > 4096
            || prefabs.len() > 4096
            || array(value, "selectedNodeIds")?.len() > 16384
        {
            return Err(ExchangeError::new(
                "BUDGET_EXCEEDED",
                "Selection exceeds finite object budgets",
            ));
        }
        let mut prefab_map = BTreeMap::new();
        let mut total_nodes = 0_usize;
        for prefab in prefabs {
            verify_projected_digest("Prefab", prefab)
                .map_err(|e| ExchangeError::new("INPUT_DIGEST_MISMATCH", e.to_string()))?;
            let diagnostics = mmmm_domain::prefab_validate(prefab)
                .map_err(|e| ExchangeError::new("REFERENCE_UNRESOLVED", e.to_string()))?;
            if array(&diagnostics, "diagnostics")?
                .iter()
                .any(|d| d["severity"] == "error")
            {
                return Err(ExchangeError::new(
                    "REFERENCE_UNRESOLVED",
                    "Prefab graph or declared references are invalid",
                ));
            }
            total_nodes = total_nodes
                .checked_add(array(prefab, "nodes")?.len())
                .ok_or_else(|| {
                    ExchangeError::new("BUDGET_EXCEEDED", "Selection node count overflow")
                })?;
            if total_nodes > 16384 {
                return Err(ExchangeError::new(
                    "BUDGET_EXCEEDED",
                    "Selection contains too many definition nodes",
                ));
            }
            if prefab_map
                .insert(text(prefab, "prefabId")?, prefab)
                .is_some()
            {
                return Err(ExchangeError::new(
                    "OBJECT_MAPPING_AMBIGUOUS",
                    "Duplicate prefab ID",
                ));
            }
        }
        let mut nodes = BTreeMap::new();
        let mut instance_prefabs = BTreeMap::new();
        let mut expanded_bytes = 0_u64;
        for instance in instances {
            verify_projected_digest("Instance", instance)
                .map_err(|e| ExchangeError::new("INPUT_DIGEST_MISMATCH", e.to_string()))?;
            let instance_id = text(instance, "instanceId")?;
            let prefab_id = text(instance, "prefabId")?;
            if instance_prefabs
                .insert(instance_id.to_owned(), prefab_id.to_owned())
                .is_some()
            {
                return Err(ExchangeError::new(
                    "OBJECT_MAPPING_AMBIGUOUS",
                    "Duplicate instance ID",
                ));
            }
            let prefab = prefab_map.get(prefab_id).ok_or_else(|| {
                ExchangeError::new("REFERENCE_UNRESOLVED", "Instance's pinned prefab is absent")
            })?;
            if instance["prefabRevision"] != prefab["revision"] {
                return Err(ExchangeError::new(
                    "REVISION_CONFLICT",
                    "Instance prefab revision differs from the selection snapshot",
                ));
            }
            for node in array(prefab, "nodes")? {
                if nodes.len() >= 65536 {
                    return Err(ExchangeError::new(
                        "BUDGET_EXCEEDED",
                        "Qualified selection node expansion exceeds its budget",
                    ));
                }
                let node_id = text(node, "nodeId")?;
                let mut effective = node.clone();
                for override_value in array(instance, "overrides")? {
                    if override_value["nodeId"].as_str() == Some(node_id) {
                        match override_value["kind"].as_str() {
                            Some("transform") => {
                                effective["transform"] = override_value["transform"].clone()
                            }
                            Some("display") => {
                                effective["display"] = override_value["display"].clone()
                            }
                            _ => {}
                        }
                    }
                }
                expanded_bytes = expanded_bytes
                    .checked_add(crate::json_bytes(&effective)?.len() as u64)
                    .ok_or_else(|| {
                        ExchangeError::new(
                            "BUDGET_EXCEEDED",
                            "Expanded selection byte count overflow",
                        )
                    })?;
                if expanded_bytes > 64 * 1024 * 1024 {
                    return Err(ExchangeError::new(
                        "BUDGET_EXCEEDED",
                        "Expanded immutable node data exceeds its byte budget",
                    ));
                }
                nodes.insert(
                    ObjectNode {
                        instance_id: instance_id.to_owned(),
                        node_id: node_id.to_owned(),
                    },
                    effective,
                );
            }
        }
        let selected: BTreeSet<_> = array(value, "selectedNodeIds")?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        for node_id in selected {
            if !nodes.keys().any(|n| n.node_id == node_id) {
                return Err(ExchangeError::new(
                    "REFERENCE_UNRESOLVED",
                    "Selected stable node ID is not present in any qualified instance",
                ));
            }
        }
        Ok(Self {
            value: value.clone(),
            nodes,
            instance_prefabs,
        })
    }
    pub fn value(&self) -> &Value {
        &self.value
    }
    pub fn node(&self, node: &ObjectNode) -> Option<&Value> {
        self.nodes.get(node)
    }
    pub fn nodes(&self) -> impl Iterator<Item = (&ObjectNode, &Value)> {
        self.nodes.iter()
    }
    pub fn prefab_for(&self, instance: &str) -> Option<&str> {
        self.instance_prefabs.get(instance).map(String::as_str)
    }
    pub fn selected(&self, node: &ObjectNode) -> bool {
        self.node(node).is_some()
            && self.value["selectedNodeIds"].as_array().is_some_and(|ids| {
                ids.iter()
                    .any(|id| id.as_str() == Some(node.node_id.as_str()))
            })
    }
    pub fn check_revision(&self, project: &str, revision: &str) -> ExchangeResult<()> {
        if self.value["projectId"].as_str() != Some(project)
            || self.value["projectRevision"].as_str() != Some(revision)
        {
            return Err(ExchangeError::new(
                "REVISION_CONFLICT",
                "Selection belongs to a different project revision",
            ));
        }
        Ok(())
    }
}

//! Qualified stable identities, revision pins and selection boundaries. Labels
//! never participate in object identity and an omitted object is not a deletion.
use crate::{ExchangeError, ExchangeResult, array, text, validate};
use mmmm_contracts::{
    ContractValidator, JsonLimits, validation::ControlledPrefabContractError,
    verify_projected_digest,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
    sync::Arc,
};

const MAX_COMPARISON_SELECTION_BYTES: usize = 8 * 1024 * 1024;

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
    physics_index: Arc<crate::physics::SelectionIndex>,
    // Only the raw-byte constructor can populate this private semantic view.
    // Original Selection Values and expanded nodes remain unchanged.
    semantic_prefabs: Option<Arc<BTreeMap<String, SemanticPrefab>>>,
}

#[derive(Clone, Debug)]
pub(crate) struct SemanticPrefab {
    pub(crate) resources: Value,
    pub(crate) geometry: BTreeMap<String, Value>,
}

/// Errors from selection construction with each Prefab's original bytes.
/// `Control` retains the caller's actual cancellation or deadline error.
#[derive(Debug)]
pub enum ControlledSelectionError<E> {
    Exchange(ExchangeError),
    Prefab {
        index: usize,
        error: ControlledPrefabContractError<E>,
    },
    Control(E),
    PrefabBytesCountMismatch,
    PrefabValueMismatch {
        index: usize,
    },
}

impl Selection {
    pub fn from_value(value: &Value) -> ExchangeResult<Self> {
        Self::from_comparison(value, value, false)
    }

    /// Construct a selection after binding each Prefab Value to the exact
    /// corresponding source bytes and checking the selected numeric lexemes.
    /// The byte slice order must match `prefabs`. These bytes are not proof of
    /// CAS provenance, authorization, or a current Project; the caller must
    /// establish and recheck those properties. Only Prefab resource sizes in
    /// a private typed comparison copy are normalized. The returned selection,
    /// nodes and digest checks retain the original Values. Before cloning, the
    /// complete serialized selection, including opaque payloads, is limited to
    /// 8 MiB by a counting writer. This additional limit applies only here.
    pub fn from_value_with_integral_prefab_resource_comparison<E>(
        value: &Value,
        prefab_bytes: &[&[u8]],
        mut checkpoint: impl FnMut() -> Result<(), E>,
    ) -> Result<Self, ControlledSelectionError<E>> {
        checkpoint().map_err(ControlledSelectionError::Control)?;
        validate("SceneSelectionSnapshot", value).map_err(ControlledSelectionError::Exchange)?;
        crate::physics::selection_budget(value).map_err(ControlledSelectionError::Exchange)?;
        check_comparison_selection_bytes(value).map_err(ControlledSelectionError::Exchange)?;
        checkpoint().map_err(ControlledSelectionError::Control)?;
        let prefabs = array(value, "prefabs").map_err(ControlledSelectionError::Exchange)?;
        if prefabs.len() > 4096 {
            return Err(ControlledSelectionError::Exchange(ExchangeError::new(
                "BUDGET_EXCEEDED",
                "Selection exceeds finite object budgets",
            )));
        }
        if prefab_bytes.len() != prefabs.len() {
            return Err(ControlledSelectionError::PrefabBytesCountMismatch);
        }
        let mut total = 0_usize;
        for bytes in prefab_bytes {
            total = total.checked_add(bytes.len()).ok_or_else(|| {
                ControlledSelectionError::Exchange(ExchangeError::new(
                    "BUDGET_EXCEEDED",
                    "Prefab source byte count overflow",
                ))
            })?;
            if bytes.len() > 8 * 1024 * 1024 || total > 32 * 1024 * 1024 {
                return Err(ControlledSelectionError::Exchange(ExchangeError::new(
                    "BUDGET_EXCEEDED",
                    "Prefab source bytes exceed their budget",
                )));
            }
        }
        let validator = ContractValidator::shared().map_err(|error| {
            ControlledSelectionError::Exchange(ExchangeError::new(
                "SCHEMA_INVALID",
                error.to_string(),
            ))
        })?;
        let mut typed_prefabs = Vec::with_capacity(prefabs.len());
        for (index, (prefab, bytes)) in prefabs.iter().zip(prefab_bytes).enumerate() {
            checkpoint().map_err(ControlledSelectionError::Control)?;
            verify_projected_digest("Prefab", prefab).map_err(|error| {
                ControlledSelectionError::Exchange(ExchangeError::new(
                    "INPUT_DIGEST_MISMATCH",
                    error.to_string(),
                ))
            })?;
            let parsed = validator
                .parse_validate_prefab_exact_with_control(
                    bytes,
                    JsonLimits {
                        max_bytes: 8 * 1024 * 1024,
                        max_depth: 64,
                        max_nodes: 100_000,
                    },
                    &mut checkpoint,
                )
                .map_err(|error| match error {
                    ControlledPrefabContractError::Control(error) => {
                        ControlledSelectionError::Control(error)
                    }
                    error => ControlledSelectionError::Prefab { index, error },
                })?;
            if parsed != *prefab {
                return Err(ControlledSelectionError::PrefabValueMismatch { index });
            }
            typed_prefabs.push(normalize_prefab_comparison(prefab, &mut checkpoint)?);
        }
        checkpoint().map_err(ControlledSelectionError::Control)?;
        let mut comparison = value.clone();
        comparison["prefabs"] = Value::Array(typed_prefabs);
        let selection = Self::from_comparison(value, &comparison, true)
            .map_err(ControlledSelectionError::Exchange)?;
        checkpoint().map_err(ControlledSelectionError::Control)?;
        Ok(selection)
    }

    fn from_comparison(
        value: &Value,
        comparison: &Value,
        keep_semantic: bool,
    ) -> ExchangeResult<Self> {
        validate("SceneSelectionSnapshot", value)?;
        let physics_index = crate::physics::SelectionIndex::from_value(comparison)?;
        let instances = array(value, "instances")?;
        let prefabs = array(value, "prefabs")?;
        let typed_prefabs = array(comparison, "prefabs")?;
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
        let mut semantic_prefabs = BTreeMap::new();
        let mut total_nodes = 0_usize;
        for (prefab, typed_prefab) in prefabs.iter().zip(typed_prefabs) {
            verify_projected_digest("Prefab", prefab)
                .map_err(|e| ExchangeError::new("INPUT_DIGEST_MISMATCH", e.to_string()))?;
            let diagnostics = mmmm_domain::prefab_validate(typed_prefab)
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
            if keep_semantic {
                let mut geometry = BTreeMap::new();
                for node in array(typed_prefab, "nodes")? {
                    if let Some(resource) = node.get("geometryResource") {
                        if geometry
                            .insert(text(node, "nodeId")?.to_owned(), resource.clone())
                            .is_some()
                        {
                            return Err(ExchangeError::new(
                                "OBJECT_MAPPING_AMBIGUOUS",
                                "Duplicate geometry node ID",
                            ));
                        }
                    }
                }
                semantic_prefabs.insert(
                    text(prefab, "prefabId")?.to_owned(),
                    SemanticPrefab {
                        resources: typed_prefab["resources"].clone(),
                        geometry,
                    },
                );
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
            physics_index: Arc::new(physics_index),
            semantic_prefabs: keep_semantic.then(|| Arc::new(semantic_prefabs)),
        })
    }
    pub fn value(&self) -> &Value {
        &self.value
    }
    /// The validated index produced at construction. For the raw-byte path,
    /// its typed Prefab sizes derive from the exact corresponding bytes, but
    /// neither path establishes source provenance or current authorization.
    pub fn physics_index(&self) -> &crate::physics::SelectionIndex {
        &self.physics_index
    }
    pub(crate) fn semantic_prefab(&self, id: &str) -> Option<&SemanticPrefab> {
        self.semantic_prefabs.as_ref()?.get(id)
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

/// Count the complete JSON encoding without allocating a second encoded copy.
/// Synchronous serde traversal is cooperative: checkpoints surround the call,
/// but cannot preempt one serializer operation.
fn check_comparison_selection_bytes(value: &Value) -> ExchangeResult<()> {
    struct Counter(usize);
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let next = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| io::Error::other("selection byte budget"))?;
            if next > MAX_COMPARISON_SELECTION_BYTES {
                return Err(io::Error::other("selection byte budget"));
            }
            self.0 = next;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Counter(0), value).map_err(|_| {
        ExchangeError::new(
            "BUDGET_EXCEEDED",
            "Selection comparison bytes exceed their budget",
        )
    })
}

fn normalize_prefab_comparison<E>(
    prefab: &Value,
    checkpoint: &mut impl FnMut() -> Result<(), E>,
) -> Result<Value, ControlledSelectionError<E>> {
    checkpoint().map_err(ControlledSelectionError::Control)?;
    let mut typed = prefab.clone();
    checkpoint().map_err(ControlledSelectionError::Control)?;
    let resources = typed
        .get_mut("resources")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            ControlledSelectionError::Exchange(ExchangeError::new(
                "SCHEMA_INVALID",
                "Missing Prefab resources",
            ))
        })?;
    for (index, resource) in resources.iter_mut().enumerate() {
        if index % 128 == 0 {
            checkpoint().map_err(ControlledSelectionError::Control)?;
        }
        *resource =
            mmmm_domain::physics::normalize_mesh_resource_ref(resource).map_err(|error| {
                ControlledSelectionError::Exchange(ExchangeError::new(
                    error.code,
                    error.to_string(),
                ))
            })?;
    }
    let nodes = typed
        .get_mut("nodes")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            ControlledSelectionError::Exchange(ExchangeError::new(
                "SCHEMA_INVALID",
                "Missing Prefab nodes",
            ))
        })?;
    for (index, node) in nodes.iter_mut().enumerate() {
        if index % 128 == 0 {
            checkpoint().map_err(ControlledSelectionError::Control)?;
        }
        if let Some(resource) = node.get_mut("geometryResource") {
            *resource =
                mmmm_domain::physics::normalize_mesh_resource_ref(resource).map_err(|error| {
                    ControlledSelectionError::Exchange(ExchangeError::new(
                        error.code,
                        error.to_string(),
                    ))
                })?;
        }
    }
    checkpoint().map_err(ControlledSelectionError::Control)?;
    Ok(typed)
}

#[cfg(test)]
mod integral_prefab_tests {
    use super::*;
    use mmmm_contracts::{parse_json, projected_digest};
    use serde_json::json;

    fn selection_with_decimal_prefab() -> Value {
        let mut selection =
            parse_json(include_bytes!("../../../examples/scene-selection.json")).unwrap();
        selection["prefabs"][0]["resources"][0]["sizeBytes"] = json!(1.0);
        let revision = projected_digest("Prefab", &selection["prefabs"][0]).unwrap();
        selection["prefabs"][0]["revision"] = json!(revision);
        selection["instances"][0]["prefabRevision"] = json!(revision);
        let instance_revision = projected_digest("Instance", &selection["instances"][0]).unwrap();
        selection["instances"][0]["revision"] = json!(instance_revision);
        selection
    }

    #[test]
    fn original_prefab_bytes_enable_scoped_typed_comparison_without_rewriting_selection() {
        let mut selection = selection_with_decimal_prefab();
        selection["instances"][0]["overrides"] = json!([{"kind":"transform", "nodeId":"door", "transform": {
            "kind":"trs", "translation":[8,2,1], "rotationXyzw":[0,0,0,1], "scale":[1,1,1]
        }}]);
        let revision = projected_digest("Instance", &selection["instances"][0]).unwrap();
        selection["instances"][0]["revision"] = json!(revision);
        let original = selection.clone();
        let prefab = serde_json::to_vec(&selection["prefabs"][0]).unwrap();
        assert!(Selection::from_value(&selection).is_err());
        let parsed = Selection::from_value_with_integral_prefab_resource_comparison(
            &selection,
            &[&prefab],
            || Ok::<_, &'static str>(()),
        )
        .unwrap();
        assert_eq!(parsed.value(), &original);
        assert_eq!(
            parsed.physics_index().selection_id().as_str(),
            selection["selectionId"].as_str().unwrap()
        );
        assert_eq!(
            parsed.physics_index().project_revision().as_str(),
            selection["projectRevision"].as_str().unwrap()
        );
        let node = ObjectNode {
            instance_id: selection["instances"][0]["instanceId"]
                .as_str()
                .unwrap()
                .into(),
            node_id: "door".into(),
        };
        assert_eq!(
            parsed.node(&node).and_then(|node| node["nodeId"].as_str()),
            Some("door")
        );
        let indexed = crate::physics::ObjectNodeRef {
            instance_id: mmmm_contracts::InstanceId::new(node.instance_id.as_str()).unwrap(),
            node_id: mmmm_contracts::NodeId::new(node.node_id.as_str()).unwrap(),
        };
        assert!(parsed.physics_index().contains(&indexed));
        assert_eq!(
            parsed
                .physics_index()
                .world_transform(&indexed)
                .unwrap()
                .transform_point([0.0; 3])
                .unwrap(),
            [136.0, 66.0, 129.0]
        );
        let cloned = parsed.clone();
        assert!(Arc::ptr_eq(&parsed.physics_index, &cloned.physics_index));
        assert_eq!(
            Selection::from_value(&selection).unwrap_err().code,
            "SCHEMA_INVALID"
        );
    }

    #[test]
    fn raw_fraction_mismatched_value_count_and_cancellation_are_rejected() {
        let selection = selection_with_decimal_prefab();
        let prefab = serde_json::to_vec(&selection["prefabs"][0]).unwrap();
        let source = String::from_utf8(prefab.clone()).unwrap();
        let needle = "\"sizeBytes\":1.0";
        assert_eq!(source.matches(needle).count(), 1);
        let fraction = source.replacen(needle, "\"sizeBytes\":1.0000000000000001", 1);
        assert!(matches!(
            Selection::from_value_with_integral_prefab_resource_comparison(
                &selection,
                &[fraction.as_bytes()],
                || Ok::<_, &'static str>(()),
            ),
            Err(ControlledSelectionError::Prefab {
                error: ControlledPrefabContractError::ExactInteger { .. },
                ..
            })
        ));
        let mut other = selection["prefabs"][0].clone();
        other["resources"][0]["sizeBytes"] = json!(2.0);
        let other = serde_json::to_vec(&other).unwrap();
        assert!(matches!(
            Selection::from_value_with_integral_prefab_resource_comparison(
                &selection,
                &[&other],
                || Ok::<_, &'static str>(()),
            ),
            Err(ControlledSelectionError::PrefabValueMismatch { index: 0 })
        ));
        assert!(matches!(
            Selection::from_value_with_integral_prefab_resource_comparison(
                &selection,
                &[],
                || Ok::<_, &'static str>(()),
            ),
            Err(ControlledSelectionError::PrefabBytesCountMismatch)
        ));
        assert!(matches!(
            Selection::from_value_with_integral_prefab_resource_comparison(
                &selection,
                &[&prefab],
                || Err::<(), _>("cancelled"),
            ),
            Err(ControlledSelectionError::Control("cancelled"))
        ));
    }

    #[test]
    fn geometry_resource_is_normalized_only_in_typed_prefab_copy() {
        let mut selection = selection_with_decimal_prefab();
        selection["prefabs"][0]["resources"][0]["sizeBytes"] = json!(1);
        let mut geometry = selection["prefabs"][0]["resources"][0].clone();
        geometry["sizeBytes"] = json!(1.0);
        selection["prefabs"][0]["nodes"][0]["geometryResource"] = geometry;
        let revision = projected_digest("Prefab", &selection["prefabs"][0]).unwrap();
        selection["prefabs"][0]["revision"] = json!(revision);
        selection["instances"][0]["prefabRevision"] = json!(revision);
        let instance_revision = projected_digest("Instance", &selection["instances"][0]).unwrap();
        selection["instances"][0]["revision"] = json!(instance_revision);
        let prefab = serde_json::to_vec(&selection["prefabs"][0]).unwrap();
        assert!(Selection::from_value(&selection).is_err());
        let parsed = Selection::from_value_with_integral_prefab_resource_comparison(
            &selection,
            &[&prefab],
            || Ok::<_, &'static str>(()),
        )
        .unwrap();
        assert_eq!(parsed.value(), &selection);
        assert_eq!(
            parsed.value()["prefabs"][0]["nodes"][0]["geometryResource"]["sizeBytes"],
            json!(1.0)
        );
    }

    #[test]
    fn patch_semantics_use_verified_prefab_comparison_but_not_new_node_values() {
        use crate::patch::{DeltaKind, DeltaPolicy, SceneEdit, diff_scene_edits};
        let mut value = selection_with_decimal_prefab();
        let door_index = value["prefabs"][0]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .position(|node| node["nodeId"] == "door")
            .unwrap();
        value["prefabs"][0]["nodes"][door_index]["geometryResource"] =
            value["prefabs"][0]["resources"][0].clone();
        let revision = projected_digest("Prefab", &value["prefabs"][0]).unwrap();
        value["prefabs"][0]["revision"] = json!(revision);
        value["instances"][0]["prefabRevision"] = json!(revision);
        value["instances"][0]["revision"] =
            json!(projected_digest("Instance", &value["instances"][0]).unwrap());
        let bytes = serde_json::to_vec(&value["prefabs"][0]).unwrap();
        let selection = Selection::from_value_with_integral_prefab_resource_comparison(
            &value,
            &[&bytes],
            || Ok::<_, &'static str>(()),
        )
        .unwrap();
        let original = selection.value().clone();
        let target = ObjectNode {
            instance_id: value["instances"][0]["instanceId"].as_str().unwrap().into(),
            node_id: "door".into(),
        };
        let mut transform = selection.node(&target).unwrap()["transform"].clone();
        transform["translation"][0] = json!(2.0);
        let mut allowed = DeltaPolicy::default();
        allowed
            .allow(target.clone(), DeltaKind::UpdateTransform)
            .unwrap();
        let resource = &value["sourceMap"];
        let patch = diff_scene_edits(
            &selection,
            &[SceneEdit::Existing {
                target: target.clone(),
                transform: Some(transform),
                display: None,
            }],
            resource,
            resource,
            &[],
            "patch-decimal-prefab",
            &allowed,
        )
        .unwrap();
        assert_eq!(patch["entries"].as_array().unwrap().len(), 1);
        assert_eq!(selection.value(), &original);
        assert_eq!(
            selection.node(&target).unwrap()["geometryResource"]["sizeBytes"],
            json!(1.0)
        );

        // A newly submitted node has no exact Prefab byte witness. The cached
        // comparison may not normalize that new node's own ResourceRef.
        let mut created = selection.node(&target).unwrap().clone();
        created["nodeId"] = json!("new-door");
        let new_target = ObjectNode {
            instance_id: target.instance_id.clone(),
            node_id: "new-door".into(),
        };
        allowed
            .allow(new_target.clone(), DeltaKind::CreateNode)
            .unwrap();
        let error = diff_scene_edits(
            &selection,
            &[SceneEdit::Create {
                target: new_target,
                node: created,
            }],
            resource,
            resource,
            &[],
            "patch-unwitnessed-node",
            &allowed,
        )
        .unwrap_err();
        assert_eq!(error.code, "REFERENCE_UNRESOLVED");
    }

    #[test]
    fn value_only_selection_retains_its_existing_validated_index() {
        let original =
            parse_json(include_bytes!("../../../examples/scene-selection.json")).unwrap();
        let selection = Selection::from_value(&original).unwrap();
        assert_eq!(selection.value(), &original);
        assert_eq!(
            selection.physics_index().selection_id().as_str(),
            original["selectionId"].as_str().unwrap()
        );
        assert_eq!(
            selection.physics_index().project_revision().as_str(),
            original["projectRevision"].as_str().unwrap()
        );
    }

    #[test]
    fn comparison_budget_counts_opaque_escaped_bytes_before_cloning() {
        let boundary = Value::String("a".repeat(MAX_COMPARISON_SELECTION_BYTES - 2));
        assert!(check_comparison_selection_bytes(&boundary).is_ok());
        let over = Value::String("a".repeat(MAX_COMPARISON_SELECTION_BYTES - 1));
        assert_eq!(
            check_comparison_selection_bytes(&over).unwrap_err().code,
            "BUDGET_EXCEEDED"
        );

        // Each null character needs six JSON bytes although its Value string
        // occupies one byte; the limit applies to the complete encoding.
        let mut selection = selection_with_decimal_prefab();
        selection["prefabs"][0]["nodes"][0]["extensions"]["example:opaque"] =
            json!("\0".repeat(1_500_000));
        assert!(
            matches!(Selection::from_value_with_integral_prefab_resource_comparison(
            &selection, &[], || Ok::<_, &'static str>(()),
        ), Err(ControlledSelectionError::Exchange(error)) if error.code == "BUDGET_EXCEEDED")
        );
    }
}

//! Immutable authoring ownership index for one exact canonical Project revision.
//!
//! Membership authorizes a source lookup within this project; it does not prove
//! that the caller may read the project, that historical bytes exist, or that a
//! target may be changed. Authenticated source ports retain those obligations.

use mmmm_application::{AppError, AppResult};
use mmmm_contracts::{
    ContractValidator, InstanceId, ObjectId, ProjectId, ResourceId, Sha256Digest, TargetProfileId,
    encode_json, verify_projected_digest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The finite ownership kinds declared by the original Project wire contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnedKind {
    Prefab,
    Instance,
    CommandModule,
    Clip,
    Asset,
    PhysicsDefinition,
}

impl OwnedKind {
    /// Canonical schema definition used to validate the resolved source value.
    pub const fn definition(self) -> &'static str {
        match self {
            Self::Prefab => "Prefab",
            Self::Instance => "Instance",
            Self::CommandModule => "CommandModule",
            Self::Clip => "AnimationClip",
            Self::Asset => "Asset",
            Self::PhysicsDefinition => "PhysicsDefinition",
        }
    }

    /// Stable identity field in that canonical definition.
    pub const fn id_field(self) -> &'static str {
        match self {
            Self::Prefab => "prefabId",
            Self::Instance => "instanceId",
            Self::CommandModule => "moduleId",
            Self::Clip => "clipId",
            Self::Asset => "assetId",
            Self::PhysicsDefinition => "physicsId",
        }
    }

    /// Original function contracts consuming this authoring kind. These names
    /// describe a dependency's contract scope, not verification or admission.
    pub const fn contract_ids(self) -> &'static [&'static str] {
        match self {
            Self::Prefab => &["FN02", "FN03", "FN04", "FN05"],
            Self::Instance => &["FN03", "FN04", "FN05"],
            Self::CommandModule => &["FN06"],
            Self::Clip => &["FN08"],
            Self::Asset => &["FN30"],
            Self::PhysicsDefinition => &["FN24", "FN26", "FN27"],
        }
    }
}

/// A requested immutable authoring source, with the original wire lexical IDs.
/// A deserialized pin is data and does not independently grant source access.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectPin {
    pub kind: OwnedKind,
    pub object_id: ObjectId,
    pub revision: Sha256Digest,
}

/// A validated and bounded copy of one Project, with no mutable source handles.
#[derive(Clone, Debug)]
pub struct ProjectCatalog {
    project: Value,
    project_id: ProjectId,
    revision: Sha256Digest,
    target_profile_id: TargetProfileId,
    pins: Vec<ObjectPin>,
    by_identity: BTreeMap<(OwnedKind, ObjectId), usize>,
    resource_ids: BTreeSet<ResourceId>,
    used_instance_ids: BTreeSet<InstanceId>,
}

impl ProjectCatalog {
    /// Validate canonical structure, original self-digest, finite index counts
    /// and unambiguous ownership before retaining any project value.
    pub fn from_project(project: &Value) -> AppResult<Self> {
        for name in ["prefabIds", "instanceIds", "resourceIds", "ownedResources"] {
            let values = project[name].as_array().ok_or_else(schema_error)?;
            if values.len() > 4096 {
                return Err(AppError::new(
                    "BUDGET_EXCEEDED",
                    "Project ownership index exceeds its finite item budget",
                ));
            }
        }
        validate_bounded("Project", project)?;
        let revision = verify_projected_digest("Project", project).map_err(|_| {
            AppError::new(
                "REVISION_CONFLICT",
                "Project self-digest is not its actual revision",
            )
        })?;
        let project_id: ProjectId = decode(&project["projectId"])?;
        let target_profile_id: TargetProfileId = decode(&project["targetProfileId"])?;
        let resource_ids: BTreeSet<ResourceId> = decode(&project["resourceIds"])?;
        let used_instance_ids: BTreeSet<InstanceId> = decode(&project["instanceIds"])?;
        let mut pins: Vec<ObjectPin> = decode(&project["ownedResources"])?;
        pins.sort_by(|left, right| {
            (left.kind, &left.object_id).cmp(&(right.kind, &right.object_id))
        });

        let mut by_identity = BTreeMap::new();
        for (position, pin) in pins.iter().enumerate() {
            if by_identity
                .insert((pin.kind, pin.object_id.clone()), position)
                .is_some()
            {
                return Err(AppError::new(
                    "ID_COLLISION",
                    "Owned object kind and ID pairs must be unique",
                ));
            }
        }
        for (kind, index_name) in [
            (OwnedKind::Prefab, "prefabIds"),
            (OwnedKind::Instance, "instanceIds"),
        ] {
            let listed: BTreeSet<&str> = project[index_name]
                .as_array()
                .ok_or_else(schema_error)?
                .iter()
                .map(|id| id.as_str().ok_or_else(schema_error))
                .collect::<AppResult<_>>()?;
            let owned: BTreeSet<&str> = pins
                .iter()
                .filter(|pin| pin.kind == kind)
                .map(|pin| pin.object_id.as_str())
                .collect();
            if listed != owned {
                return Err(AppError::new(
                    "REFERENCE_UNRESOLVED",
                    "Project prefab and instance indexes must match their owned object pins",
                ));
            }
        }

        Ok(Self {
            project: project.clone(),
            project_id,
            revision,
            target_profile_id,
            pins,
            by_identity,
            resource_ids,
            used_instance_ids,
        })
    }

    pub fn project(&self) -> &Value {
        &self.project
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn revision(&self) -> &Sha256Digest {
        &self.revision
    }

    pub fn target_profile_id(&self) -> &TargetProfileId {
        &self.target_profile_id
    }

    /// Deterministically ordered current pins. The retained Project keeps its
    /// original array order and digest; constructing this index never edits it.
    pub fn pins(&self) -> &[ObjectPin] {
        &self.pins
    }

    pub fn owned_pin(&self, kind: OwnedKind, id: &str) -> AppResult<&ObjectPin> {
        let object_id = ObjectId::new(id).map_err(|_| schema_error())?;
        let position = self.by_identity.get(&(kind, object_id)).ok_or_else(|| {
            AppError::new(
                "NOT_FOUND",
                "The requested object is not owned by this project",
            )
        })?;
        Ok(&self.pins[*position])
    }

    /// Permit a historical revision lookup for an object already owned here.
    /// The requested revision is retained exactly. The authenticated source port
    /// must load that exact history and validate its bytes, never substitute the
    /// current head or treat this membership check as a caller permission grant.
    pub fn authorize_pin(
        &self,
        kind: OwnedKind,
        id: &str,
        revision: &Sha256Digest,
    ) -> AppResult<ObjectPin> {
        let current = self.owned_pin(kind, id)?;
        Ok(ObjectPin {
            kind: current.kind,
            object_id: current.object_id.clone(),
            revision: revision.clone(),
        })
    }

    pub fn resource_ids(&self) -> &BTreeSet<ResourceId> {
        &self.resource_ids
    }

    pub fn used_instance_ids(&self) -> &BTreeSet<InstanceId> {
        &self.used_instance_ids
    }
}

/// Check resolved bytes' decoded value against its requested canonical type,
/// original identity and exact self-digest. This checks no ACL or live effects.
pub fn validate_owned_value(pin: &ObjectPin, value: &Value) -> AppResult<()> {
    validate_bounded(pin.kind.definition(), value)?;
    if value[pin.kind.id_field()].as_str() != Some(pin.object_id.as_str()) {
        return Err(AppError::new(
            "REVISION_CONFLICT",
            "Resolved source identity differs from its requested object pin",
        ));
    }
    let actual = verify_projected_digest(pin.kind.definition(), value).map_err(|_| {
        AppError::new(
            "REVISION_CONFLICT",
            "Resolved source has an invalid self-digest",
        )
    })?;
    if actual != pin.revision {
        return Err(AppError::new(
            "REVISION_CONFLICT",
            "Resolved source revision differs from its exact requested pin",
        ));
    }
    Ok(())
}

fn validate_bounded(definition: &str, value: &Value) -> AppResult<()> {
    encode_json(value).map_err(|_| {
        AppError::new(
            "BUDGET_EXCEEDED",
            "Authoring source exceeds finite JSON boundaries",
        )
    })?;
    ContractValidator::shared()
        .and_then(|validator| validator.validate(definition, value))
        .map_err(|_| schema_error())
}

fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> AppResult<T> {
    serde_json::from_value(value.clone()).map_err(|_| schema_error())
}

fn schema_error() -> AppError {
    AppError::new(
        "SCHEMA_INVALID",
        "Authoring source violates the canonical ownership contract",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mmmm_contracts::{parse_json, projected_digest};
    use serde_json::json;

    fn project() -> Value {
        parse_json(include_bytes!("../../../examples/project.json")).unwrap()
    }

    fn revise_project(value: &mut Value) {
        value["revision"] = json!(projected_digest("Project", value).unwrap());
    }

    #[test]
    fn canonical_fixture_is_immutable_and_resolves_all_kind_pins() {
        let mut original = project();
        let saved = original.clone();
        let catalog = ProjectCatalog::from_project(&original).unwrap();
        assert_eq!(catalog.project(), &saved);
        assert_eq!(catalog.project_id().as_str(), "project-fixture");
        assert_eq!(catalog.target_profile_id().as_str(), "java-26.3");
        assert_eq!(catalog.pins().len(), 5);
        assert!(catalog.resource_ids().contains("resource-wall-blocks"));
        assert!(catalog.used_instance_ids().contains("instance-shop-a"));
        for (kind, bytes) in [
            (
                OwnedKind::Prefab,
                include_bytes!("../../../examples/prefab.json").as_slice(),
            ),
            (
                OwnedKind::Instance,
                include_bytes!("../../../examples/instance.json").as_slice(),
            ),
            (
                OwnedKind::CommandModule,
                include_bytes!("../../../examples/command-module.json").as_slice(),
            ),
            (
                OwnedKind::Clip,
                include_bytes!("../../../examples/animation-clip.json").as_slice(),
            ),
            (
                OwnedKind::Asset,
                include_bytes!("../../../examples/asset.json").as_slice(),
            ),
        ] {
            let source = parse_json(bytes).unwrap();
            let id = source[kind.id_field()].as_str().unwrap();
            validate_owned_value(catalog.owned_pin(kind, id).unwrap(), &source).unwrap();
        }
        original["name"] = json!("caller mutation");
        assert_eq!(catalog.project(), &saved);
    }

    #[test]
    fn stale_project_and_missing_or_extra_owned_indexes_are_rejected() {
        let mut source = project();
        source["name"] = json!("changed without revision");
        assert_eq!(
            ProjectCatalog::from_project(&source).unwrap_err().code,
            "REVISION_CONFLICT"
        );
        let mut source = project();
        source["prefabIds"] = json!([]);
        revise_project(&mut source);
        assert_eq!(
            ProjectCatalog::from_project(&source).unwrap_err().code,
            "REFERENCE_UNRESOLVED"
        );
        let mut source = project();
        source["instanceIds"]
            .as_array_mut()
            .unwrap()
            .push(json!("unowned-instance"));
        revise_project(&mut source);
        assert_eq!(
            ProjectCatalog::from_project(&source).unwrap_err().code,
            "REFERENCE_UNRESOLVED"
        );
    }

    #[test]
    fn identity_is_kind_qualified_and_duplicate_pairs_are_rejected() {
        let mut source = project();
        let duplicate = source["ownedResources"][0].clone();
        source["ownedResources"]
            .as_array_mut()
            .unwrap()
            .push(duplicate.clone());
        revise_project(&mut source);
        assert_eq!(
            ProjectCatalog::from_project(&source).unwrap_err().code,
            "ID_COLLISION"
        );
        source["ownedResources"].as_array_mut().unwrap().pop();
        let mut other_kind = duplicate;
        other_kind["kind"] = json!("asset");
        source["ownedResources"]
            .as_array_mut()
            .unwrap()
            .push(other_kind.clone());
        revise_project(&mut source);
        let catalog = ProjectCatalog::from_project(&source).unwrap();
        assert_eq!(
            catalog
                .owned_pin(OwnedKind::Asset, other_kind["objectId"].as_str().unwrap())
                .unwrap()
                .kind,
            OwnedKind::Asset
        );
    }

    #[test]
    fn historical_pin_requires_membership_and_never_substitutes_current_revision() {
        let catalog = ProjectCatalog::from_project(&project()).unwrap();
        let source = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
        let mut historical = source.clone();
        historical["name"] = json!("a retained historical name");
        historical["revision"] = json!(projected_digest("Prefab", &historical).unwrap());
        let revision: Sha256Digest = decode(&historical["revision"]).unwrap();
        let pin = catalog
            .authorize_pin(OwnedKind::Prefab, "prefab-shop", &revision)
            .unwrap();
        assert_ne!(
            &pin.revision,
            &catalog
                .owned_pin(OwnedKind::Prefab, "prefab-shop")
                .unwrap()
                .revision
        );
        validate_owned_value(&pin, &historical).unwrap();
        assert_eq!(
            validate_owned_value(&pin, &source).unwrap_err().code,
            "REVISION_CONFLICT"
        );
        assert_eq!(
            catalog
                .authorize_pin(OwnedKind::Prefab, "unowned-prefab", &revision)
                .unwrap_err()
                .code,
            "NOT_FOUND"
        );
        assert_eq!(
            catalog
                .authorize_pin(OwnedKind::Asset, "prefab-shop", &revision)
                .unwrap_err()
                .code,
            "NOT_FOUND"
        );
    }

    #[test]
    fn object_validation_rejects_identity_revision_and_kind_substitution() {
        let catalog = ProjectCatalog::from_project(&project()).unwrap();
        let pin = catalog.owned_pin(OwnedKind::Prefab, "prefab-shop").unwrap();
        let mut source = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
        source["prefabId"] = json!("different-prefab");
        source["revision"] = json!(projected_digest("Prefab", &source).unwrap());
        assert_eq!(
            validate_owned_value(pin, &source).unwrap_err().code,
            "REVISION_CONFLICT"
        );
        let mut source = parse_json(include_bytes!("../../../examples/prefab.json")).unwrap();
        source["name"] = json!("changed without revision");
        assert_eq!(
            validate_owned_value(pin, &source).unwrap_err().code,
            "REVISION_CONFLICT"
        );
        let asset = parse_json(include_bytes!("../../../examples/asset.json")).unwrap();
        assert_eq!(
            validate_owned_value(pin, &asset).unwrap_err().code,
            "SCHEMA_INVALID"
        );
    }

    #[test]
    fn all_owned_kind_fields_and_pin_serde_follow_original_wire_names() {
        for (kind, wire, definition, field) in [
            (OwnedKind::Prefab, "prefab", "Prefab", "prefabId"),
            (OwnedKind::Instance, "instance", "Instance", "instanceId"),
            (
                OwnedKind::CommandModule,
                "command_module",
                "CommandModule",
                "moduleId",
            ),
            (OwnedKind::Clip, "clip", "AnimationClip", "clipId"),
            (OwnedKind::Asset, "asset", "Asset", "assetId"),
            (
                OwnedKind::PhysicsDefinition,
                "physics_definition",
                "PhysicsDefinition",
                "physicsId",
            ),
        ] {
            assert_eq!(serde_json::to_value(kind).unwrap(), json!(wire));
            assert_eq!(kind.definition(), definition);
            assert_eq!(kind.id_field(), field);
            assert!(!kind.contract_ids().is_empty());
        }
        let pin = ProjectCatalog::from_project(&project()).unwrap().pins()[0].clone();
        let mut encoded = serde_json::to_value(&pin).unwrap();
        assert_eq!(decode::<ObjectPin>(&encoded).unwrap(), pin);
        encoded["untrustedGrant"] = json!(true);
        assert!(decode::<ObjectPin>(&encoded).is_err());
    }

    #[test]
    fn finite_project_ownership_count_is_checked_before_retention() {
        let mut source = project();
        // The original fixture has no oversized index; this in-memory mutation
        // isolates the 4096 item boundary without adding a duplicate disk fixture.
        source["resourceIds"] = json!(
            (0..4097)
                .map(|n| format!("resource-{n}"))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            ProjectCatalog::from_project(&source).unwrap_err().code,
            "BUDGET_EXCEEDED"
        );
    }
}

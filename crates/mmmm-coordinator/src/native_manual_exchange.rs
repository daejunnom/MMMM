//! Explicit native static scene selection. These locators and delta choices
//! carry no source ownership, redistribution permission or game-write grant.
use crate::service::ServiceError;
use mmmm_contracts::{ContextId, ProjectId, ResourceId, Sha256Digest};
use mmmm_domain::types::ResourceRef;
use mmmm_exchange::{
    patch::{DeltaKind, DeltaPolicy},
    selection::ObjectNode,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::PathBuf};

#[derive(Clone)]
pub struct NativeManualSelection {
    pub(crate) project_id: ProjectId,
    pub(crate) expected_revision: Sha256Digest,
    pub(crate) context_id: ContextId,
    pub(crate) selection_resource: ResourceId,
    pub(crate) source_map_resource: ResourceId,
    pub(crate) edit_payload_resource: ResourceId,
    pub(crate) source_map_file: PathBuf,
    pub(crate) edit_payload_file: PathBuf,
    pub(crate) allowed_deltas: Vec<(ObjectNode, DeltaKind)>,
}
impl NativeManualSelection {
    pub(crate) fn from_frame(frame: &Value) -> Result<Self, ServiceError> {
        let text = |field: &str| frame[field].as_str().ok_or_else(invalid);
        let mut allowed_deltas = Vec::new();
        let mut seen = BTreeSet::new();
        let deltas = frame["allowedDeltas"].as_array().ok_or_else(invalid)?;
        if deltas.is_empty() || deltas.len() > 256 {
            return Err(invalid());
        }
        for delta in deltas {
            let instance = delta["instanceId"].as_str().ok_or_else(invalid)?;
            let node = delta["nodeId"].as_str().ok_or_else(invalid)?;
            mmmm_contracts::InstanceId::new(instance).map_err(|_| invalid())?;
            mmmm_contracts::NodeId::new(node).map_err(|_| invalid())?;
            let kind = delta_kind(delta["kind"].as_str().ok_or_else(invalid)?)?;
            if !seen.insert((instance.to_owned(), node.to_owned(), kind)) {
                return Err(invalid());
            }
            allowed_deltas.push((
                ObjectNode {
                    instance_id: instance.to_owned(),
                    node_id: node.to_owned(),
                },
                kind,
            ));
        }
        let selection = Self {
            project_id: ProjectId::new(text("projectId")?).map_err(|_| invalid())?,
            expected_revision: Sha256Digest::new(text("expectedRevision")?)
                .map_err(|_| invalid())?,
            context_id: ContextId::new(text("contextId")?).map_err(|_| invalid())?,
            selection_resource: ResourceId::new(text("selectionResourceId")?)
                .map_err(|_| invalid())?,
            source_map_resource: ResourceId::new(text("sourceMapResourceId")?)
                .map_err(|_| invalid())?,
            edit_payload_resource: ResourceId::new(text("editPayloadResourceId")?)
                .map_err(|_| invalid())?,
            source_map_file: PathBuf::from(text("sourceMapFile")?),
            edit_payload_file: PathBuf::from(text("editPayloadFile")?),
            allowed_deltas,
        };
        if selection.selection_resource == selection.source_map_resource
            || selection.selection_resource == selection.edit_payload_resource
            || selection.source_map_resource == selection.edit_payload_resource
            || !selection.source_map_file.is_absolute()
            || !selection.edit_payload_file.is_absolute()
        {
            return Err(invalid());
        }
        Ok(selection)
    }
    pub(crate) fn policy(&self) -> Result<DeltaPolicy, ServiceError> {
        let mut policy = DeltaPolicy::default();
        for (target, kind) in &self.allowed_deltas {
            policy.allow(target.clone(), *kind).map_err(|cause| {
                ServiceError::caused_by(
                    cause.code,
                    "Manual static delta selection is invalid",
                    cause,
                )
            })?;
        }
        Ok(policy)
    }
    pub(crate) fn locators(&self) -> Value {
        json!({"projectId":self.project_id,"expectedRevision":self.expected_revision,"contextId":self.context_id,
            "selectionResourceId":self.selection_resource,"sourceMapResourceId":self.source_map_resource,"editPayloadResourceId":self.edit_payload_resource,
            "sourceMapFile":self.source_map_file,"editPayloadFile":self.edit_payload_file,
            "allowedDeltas":self.allowed_deltas.iter().map(|(target,kind)|json!({"instanceId":target.instance_id,"nodeId":target.node_id,"kind":delta_name(*kind)})).collect::<Vec<_>>()})
    }
}

pub(crate) fn delta_kind(value: &str) -> Result<DeltaKind, ServiceError> {
    match value {
        "create_node" => Ok(DeltaKind::CreateNode),
        "update_transform" => Ok(DeltaKind::UpdateTransform),
        "update_display" => Ok(DeltaKind::UpdateDisplay),
        "delete_node" => Ok(DeltaKind::DeleteNode),
        _ => Err(invalid()),
    }
}
fn delta_name(kind: DeltaKind) -> &'static str {
    match kind {
        DeltaKind::CreateNode => "create_node",
        DeltaKind::UpdateTransform => "update_transform",
        DeltaKind::UpdateDisplay => "update_display",
        DeltaKind::DeleteNode => "delete_node",
        DeltaKind::AttachClip => {
            unreachable!("Native manual selections cannot contain clip attachment")
        }
    }
}
fn invalid() -> ServiceError {
    ServiceError::new(
        "MANUAL_SOURCE_INVALID",
        "Manual selection requires exact Project resources and explicit qualified static deltas",
    )
}

#[derive(Clone, Debug)]
pub struct ManualSceneReceipt {
    pub(crate) project_id: ProjectId,
    pub(crate) patch_id: String,
    pub(crate) resource: ResourceRef,
}

/// A confirmed staging success followed by a later source/publication failure.
/// The locator is retained; this is neither a successful import nor permission
/// to retry it or to apply the proposal to a game.
#[derive(Debug)]
pub struct ManualSceneCommittedFailure {
    pub(crate) receipt: ManualSceneReceipt,
    pub(crate) cause: ServiceError,
}
impl std::fmt::Display for ManualSceneCommittedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Manual ScenePatch {} was staged; its final source checkpoint failed",
            self.receipt.patch_id
        )
    }
}
impl std::error::Error for ManualSceneCommittedFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// A staging call failed after it may have written CAS/metadata. Keep the exact
/// candidate and actual cause without claiming a commit or a safe retry.
#[derive(Debug)]
pub struct ManualSceneStagingFailure {
    pub(crate) candidate: ManualSceneReceipt,
    pub(crate) sources: [ResourceRef; 3],
    pub(crate) cause: ServiceError,
}
impl std::fmt::Display for ManualSceneStagingFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Manual ScenePatch {} staging failed with {} pinned sources; write effects require diagnosis",
            self.candidate.patch_id,
            self.sources.len()
        )
    }
}
impl std::error::Error for ManualSceneStagingFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

#[derive(Debug)]
pub(crate) struct ManualCheckpointFailure {
    pub(crate) primary: ServiceError,
    pub(crate) checkpoint: ServiceError,
}
impl std::fmt::Display for ManualCheckpointFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Manual source failed: {}; its source checkpoint also failed: {}",
            self.primary.code, self.checkpoint.code
        )
    }
}
impl std::error::Error for ManualCheckpointFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
pub(crate) fn checked<T>(
    result: Result<T, ServiceError>,
    checkpoint: Result<(), ServiceError>,
) -> Result<T, ServiceError> {
    match (result, checkpoint) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(cause), Ok(())) | (Ok(_), Err(cause)) => Err(cause),
        (Err(primary), Err(checkpoint)) => Err(ServiceError::caused_by(
            primary.code,
            primary.message,
            ManualCheckpointFailure {
                primary,
                checkpoint,
            },
        )),
    }
}

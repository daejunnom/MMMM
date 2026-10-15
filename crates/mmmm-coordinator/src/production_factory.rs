//! The foreground daemon and native owner use this one concrete composition.
//! Actual source ports and private registries are shared across planning,
//! features and execution; a public DTO never populates them.

use crate::{
    catalog_source::RegisteredCatalogSources,
    composite::{CompositeComposition, CompositeProvider, RustMetadataRegistry},
    daemon::{DaemonHandles, DaemonSourceFactory, DaemonSourceParts},
    feature_sources::{
        FeatureProductRegistry, FeatureSourceComposition, LocalFeatureSources, ManualSceneRegistry,
        ResourceRightsRegistry, SharedFeaturePermissions, SharedFeatureProducts,
        SharedFeatureSymbols, SharedManualScenes, SharedResourceRights, manual_data_adapter,
    },
    native_backend::{HostNativeBackend, NativeBackendComposition, NativeReadinessRegistry},
    owned_planning_data::OwnedPlanningData,
    planning_context::{
        RegisteredContextLocator, SharedRegisteredPlanningContexts, planning_context_adapter,
        workspace_context_resolver,
    },
    planning_source::{
        ObservedStateSnapshot, PlanningDataPort, PlanningDependencyRegistry,
        RegisteredPlanningDependency, SharedPlanningBackend, SharedPlanningData,
        SharedPlanningDependencies,
    },
    service::{RequestBudget, ServiceError},
    target_profile::RegisteredTargetProfiles,
};
use mmmm_application::{AppError, AppResult};
use mmmm_compiler::{
    VerifiedTarget,
    scene::{
        NativeSceneInstruction, ResolvedSceneCommand, SceneBlockState, SceneCodecCapabilities,
        SceneRegistryVerifier, SceneResource, SceneStateBinding,
    },
};
use mmmm_contracts::{ContextId, PrincipalId, Sha256Digest, StateId};
use mmmm_domain::{
    DomainError,
    commands::{CommandModule, CommandNode},
    transform::Matrix4,
    types::{Display, Instance, Prefab, ResourceRef},
};
use mmmm_planner::{PlannerOptions, ProjectCatalog, SceneSource};
use mmmm_runtime::storage::DurableStore;
use serde_json::Value;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

#[path = "compatibility_registration.rs"]
mod compatibility_registration;
pub use compatibility_registration::{
    NativeApprovedCompatibilityProfile, NativeCompatibilityApprovalSelection,
    RegisteredCompatibilityProfiles, approve_native_compatibility_profile,
    read_native_compatibility_profile, read_native_compatibility_profiles,
};

/// Trusted process composition accepts typed ports, never readiness flags,
/// permission strings copied from profiles, or wire source registrations.
/// Targets are registered later through the exact shared registry returned by
/// this factory, after an actual authenticated host/source observation.
pub struct NativeSourceInputs {
    pub scene_registry: Rc<dyn SceneRegistryVerifier>,
    pub data: SharedPlanningData,
    pub dependencies: SharedPlanningDependencies,
    pub permissions: Option<SharedFeaturePermissions>,
    pub symbols: Option<SharedFeatureSymbols>,
    pub readiness: NativeReadinessRegistry,
    pub planner_options: PlannerOptions,
}

/// These are the same private registries used by every returned adapter.
/// Registration still requires each registry's actual session/source witness.
/// No public management or feature method can deserialize this composition.
#[derive(Clone)]
pub struct ProductionRegistries {
    pub contexts: SharedRegisteredPlanningContexts,
    pub rights: SharedResourceRights,
    pub manual: SharedManualScenes,
    pub products: SharedFeatureProducts,
    pub catalog: RegisteredCatalogSources,
    pub targets: RegisteredTargetProfiles,
    pub dependencies: SharedPlanningDependencies,
    pub readiness: NativeReadinessRegistry,
    pub compatibility: RegisteredCompatibilityProfiles,
}

pub struct ProductionFactory {
    executable_digest: Sha256Digest,
    inputs: Option<NativeSourceInputs>,
    registries: Option<ProductionRegistries>,
    owned_data: bool,
}

impl ProductionFactory {
    /// The native entry computes this digest from its actual installed Rust
    /// executable. It is independent of every approved Java host JAR digest.
    pub fn new(executable_digest: Sha256Digest, inputs: NativeSourceInputs) -> Self {
        Self {
            executable_digest,
            inputs: Some(inputs),
            registries: None,
            owned_data: false,
        }
    }

    /// Cold local startup can inspect its actual native-owned Project and run
    /// pure functions. Authored documents use the same actual Store after
    /// composition. Missing game sources stay unavailable: this supplies no
    /// VerifiedTarget, live state snapshot, native permissions or symbols.
    pub fn offline_owned(executable_digest: Sha256Digest) -> Self {
        let mut factory = Self::new(
            executable_digest,
            NativeSourceInputs {
                scene_registry: Rc::new(UnregisteredSceneRegistry),
                data: Rc::new(RefCell::new(Box::new(UnregisteredPlanningData))),
                dependencies: Rc::new(RefCell::new(PlanningDependencyRegistry::default())),
                permissions: None,
                symbols: None,
                readiness: NativeReadinessRegistry::default(),
                planner_options: PlannerOptions::default(),
            },
        );
        factory.owned_data = true;
        factory
    }

    pub fn registries(&self) -> Option<&ProductionRegistries> {
        self.registries.as_ref()
    }
}

impl DaemonSourceFactory for ProductionFactory {
    fn compose(
        &mut self,
        handles: &DaemonHandles,
        store: &DurableStore,
    ) -> Result<DaemonSourceParts, ServiceError> {
        // Validate explicit setup before installing a resolver or dependency.
        let project = handles.configured_project.as_ref().ok_or_else(|| {
            ServiceError::new(
                "COMPOSITION_PROJECT_REQUIRED",
                "An explicit configured Project is required for daemon composition",
            )
        })?;
        let workspace = handles.workspace.as_ref().ok_or_else(|| {
            ServiceError::new(
                "COMPOSITION_WORKSPACE_REQUIRED",
                "An actual native-owner workspace witness is required",
            )
        })?;
        workspace.witness.check_store(store).map_err(|_| {
            ServiceError::new(
                "PERMISSION_REQUIRED",
                "Native workspace owner or protected Store no longer matches",
            )
        })?;
        if workspace.context["projectId"] != project.as_str() {
            return Err(ServiceError::new(
                "COMPOSITION_PROJECT_MISMATCH",
                "Native workspace differs from the explicitly configured Project",
            ));
        }
        let current_project = store.project(project).map_err(|_| {
            ServiceError::new(
                "COMPOSITION_PROJECT_UNAVAILABLE",
                "Configured Project is unavailable in the held Store",
            )
        })?;
        if current_project["revision"] != workspace.project_revision.as_str() {
            return Err(ServiceError::new(
                "STALE_CONTEXT",
                "Native workspace was prepared for a different Project revision",
            ));
        }
        let options = &self
            .inputs
            .as_ref()
            .ok_or_else(|| {
                ServiceError::new(
                    "COMPOSITION_ALREADY_USED",
                    "Production source composition has already been attempted",
                )
            })?
            .planner_options;
        if !(1..=3600).contains(&options.expiry_seconds)
            || !(1..=3_600_000).contains(&options.time_budget_ms)
            || options.max_source_bytes == 0
            || options.max_source_bytes > 256 * 1024 * 1024
        {
            return Err(ServiceError::new(
                "BUDGET_EXCEEDED",
                "Planner composition options exceed their finite range",
            ));
        }
        let default_context =
            ContextId::new(workspace.context["contextId"].as_str().ok_or_else(|| {
                ServiceError::new("INVALID_INPUT", "Native workspace context ID is missing")
            })?)
            .map_err(|_| {
                ServiceError::new("INVALID_INPUT", "Native workspace context ID is invalid")
            })?;
        let locator = Rc::new(RefCell::new(RegisteredContextLocator::new()));
        locator
            .borrow_mut()
            .register_native_owner(
                &workspace.witness,
                store,
                &handles.authority,
                workspace.context.clone(),
            )
            .map_err(composition_error)?;
        // A factory attempt is single-use. After partial private installation,
        // retries cannot silently produce a second resolver or phase registry.
        let inputs = self.inputs.take().ok_or_else(|| {
            ServiceError::new(
                "COMPOSITION_ALREADY_USED",
                "Production source composition has already been attempted",
            )
        })?;
        let contexts = planning_context_adapter(locator.clone());
        let rights = Rc::new(RefCell::new(ResourceRightsRegistry::default()));
        let manual = Rc::new(RefCell::new(ManualSceneRegistry::default()));
        let products = Rc::new(RefCell::new(FeatureProductRegistry::default()));
        let source_data: SharedPlanningData = if self.owned_data {
            Rc::new(RefCell::new(Box::new(OwnedPlanningData::new(
                handles.request.clone(),
                handles.authority.clone(),
                handles.hosts.clone(),
                contexts.clone(),
                // Actual game alias/codec observation remains unavailable.
                None,
            ))))
        } else {
            inputs.data
        };
        let data = manual_data_adapter(
            source_data,
            handles.request.clone(),
            handles.authority.clone(),
            manual.clone(),
            handles.hosts.clone(),
            contexts.clone(),
            rights.clone(),
            products.clone(),
        );
        let catalog = RegisteredCatalogSources::new(
            handles.authority.clone(),
            handles.hosts.clone(),
            contexts.clone(),
        );
        let targets = RegisteredTargetProfiles::new(
            handles.authority.clone(),
            handles.hosts.clone(),
            contexts.clone(),
            catalog.clone(),
        );
        let compatibility = RegisteredCompatibilityProfiles::new(
            handles.request.clone(),
            handles.authority.clone(),
            handles.hosts.clone(),
        );
        let metadata =
            RustMetadataRegistry::new(self.executable_digest.clone(), handles.authority.clone());
        let dependency = RegisteredPlanningDependency::owned_executable(
            metadata.binding_id().map_err(composition_error)?,
            metadata.implementation_digest().clone(),
            metadata.action_ids().into_iter().collect(),
            metadata.contract_ids(),
        )
        .map_err(composition_error)?;
        inputs
            .dependencies
            .try_borrow_mut()
            .map_err(|_| {
                ServiceError::new("SOURCE_BUSY", "Planning dependency registry is in use")
            })?
            .register(dependency)
            .map_err(composition_error)?;
        let native_backend = Rc::new(HostNativeBackend::new(NativeBackendComposition {
            request: handles.request.clone(),
            authority: handles.authority.clone(),
            hosts: handles.hosts.clone(),
            contexts: contexts.clone(),
            data: data.clone(),
            targets: targets.clone(),
            permissions: inputs.permissions.clone(),
            readiness: inputs.readiness.clone(),
            scene_registry: inputs.scene_registry,
            owned_inventory: Some(Rc::new(metadata.clone())),
            compatibility: compatibility.clone(),
        }));
        // Cloning this backend preserves its exact Rc registries. The executor
        // and observer also share one CompositeProvider invocation phase map.
        let backend: SharedPlanningBackend =
            Rc::new(RefCell::new(Box::new((*native_backend).clone())));
        let provider = CompositeProvider::new(CompositeComposition {
            hosts: handles.hosts.clone(),
            authority: handles.authority.clone(),
            request: handles.request.clone(),
            backend: native_backend,
            metadata,
            calibration: handles.calibration.clone(),
        })
        .map_err(composition_error)?;
        let observer = provider.observer();
        let features = LocalFeatureSources::new(FeatureSourceComposition {
            request: handles.request.clone(),
            authority: handles.authority.clone(),
            hosts: handles.hosts.clone(),
            contexts: contexts.clone(),
            context_locator: locator.clone(),
            data: data.clone(),
            backend: backend.clone(),
            dependencies: inputs.dependencies.clone(),
            project_id: project.clone(),
            default_context: Some(default_context),
            rights: rights.clone(),
            manual: manual.clone(),
            products: products.clone(),
            catalog: Some(catalog.clone()),
            permissions: inputs.permissions,
            symbols: inputs.symbols,
            compatibility: compatibility.clone(),
        });
        let artifacts = features.artifact_authority(Box::new(handles.authority.clone()));
        workspace.witness.check_store(store).map_err(|_| {
            ServiceError::new(
                "PERMISSION_REQUIRED",
                "Native workspace owner witness expired during composition",
            )
        })?;
        handles
            .authority
            .install_workspace_resolver(workspace_context_resolver(locator.clone()))
            .map_err(composition_error)?;
        self.registries = Some(ProductionRegistries {
            contexts: locator,
            rights,
            manual,
            products,
            catalog,
            targets,
            dependencies: inputs.dependencies.clone(),
            readiness: inputs.readiness,
            compatibility,
        });
        Ok(DaemonSourceParts {
            contexts,
            data,
            backend,
            dependencies: inputs.dependencies,
            features: Box::new(features),
            artifacts,
            provider: Box::new(provider),
            observer: Box::new(observer),
            planner_options: inputs.planner_options,
        })
    }
}

fn composition_error(error: AppError) -> ServiceError {
    ServiceError::new(error.code, "Production source composition failed")
}

fn source_unavailable(budget: &RequestBudget) -> AppError {
    match budget.check() {
        Ok(()) => AppError::new(
            "SOURCE_UNAVAILABLE",
            "Actual native data source is not registered",
        ),
        Err(error) => AppError::new(error.code, error.message),
    }
}

/// Explicit absence is a real source policy, not an observed empty snapshot.
struct UnregisteredPlanningData;
impl PlanningDataPort for UnregisteredPlanningData {
    fn state_snapshot(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &Value,
        _: &Value,
        budget: &RequestBudget,
    ) -> AppResult<ObservedStateSnapshot> {
        Err(source_unavailable(budget))
    }
    fn scene_source(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &Value,
        budget: &RequestBudget,
    ) -> AppResult<SceneSource> {
        Err(source_unavailable(budget))
    }
    fn validate_scene_provenance(
        &mut self,
        _: &PrincipalId,
        _: &ProjectCatalog,
        _: &Value,
        _: &SceneSource,
        _: &Value,
        budget: &RequestBudget,
    ) -> AppResult<()> {
        Err(source_unavailable(budget))
    }
}

fn scene_unavailable() -> DomainError {
    DomainError::new(
        "SOURCE_UNAVAILABLE",
        "Actual native scene registry is not registered",
    )
}
struct UnregisteredSceneRegistry;
impl SceneRegistryVerifier for UnregisteredSceneRegistry {
    fn verify_codec(
        &self,
        _: &VerifiedTarget,
        _: &Sha256Digest,
    ) -> Result<SceneCodecCapabilities, DomainError> {
        Err(scene_unavailable())
    }
    fn verify_encoded(
        &self,
        _: &VerifiedTarget,
        _: &Sha256Digest,
        _: &NativeSceneInstruction,
        _: &str,
    ) -> Result<(), DomainError> {
        Err(scene_unavailable())
    }
    fn display_payload(
        &self,
        _: &VerifiedTarget,
        _: &Display,
    ) -> Result<BTreeMap<String, Value>, DomainError> {
        Err(scene_unavailable())
    }
    fn block_state(
        &self,
        _: &VerifiedTarget,
        _: &SceneBlockState,
        _: i32,
    ) -> Result<SceneBlockState, DomainError> {
        Err(scene_unavailable())
    }
    fn resolve_command(
        &self,
        _: &VerifiedTarget,
        _: &CommandModule,
        _: &CommandNode,
        _: &Prefab,
        _: &Instance,
        _: &Matrix4,
        _: &BTreeMap<StateId, SceneStateBinding>,
    ) -> Result<ResolvedSceneCommand, DomainError> {
        Err(scene_unavailable())
    }
    fn asset_path(
        &self,
        _: &VerifiedTarget,
        _: &Value,
        _: &SceneResource,
    ) -> Result<Option<String>, DomainError> {
        Err(scene_unavailable())
    }
    fn resource_media(
        &self,
        _: &VerifiedTarget,
        _: &ResourceRef,
        _: &ResourceRef,
    ) -> Result<(), DomainError> {
        Err(scene_unavailable())
    }
}

#[cfg(test)]
#[path = "production_factory_tests.rs"]
mod tests;

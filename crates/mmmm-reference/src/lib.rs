//! FN20–23 reference semantics. Wire values are validated by the original
//! contract; source access and authentication remain explicit application ports.
//! This crate opens no files, connects to no game, and changes no runtime state.

pub mod capture;
pub mod catalog;
pub mod query;
pub mod shape;
pub mod snapshot;
pub mod source;

pub use capture::{
    ApprovedCatalogSource, CAPTURE_ENVIRONMENT_RECIPE, CaptureGrant, CapturedEnvironmentIdentity,
    CapturedSourceBytes, CatalogCaptureBackend, CatalogLayer, CatalogSourceCodec,
    CatalogSourceRole, HostRegistryTransport, MAX_NATIVE_REGISTRY_BYTES, NATIVE_REGISTRY_FORMAT,
    NATIVE_REGISTRY_MEDIA_TYPE, NoRegistryHost, RegistryCaptureWitness, VerifiedSnapshotSource,
    captured_environment_fingerprint,
};
pub use catalog::{
    AccessControl, Catalog, CatalogError, CatalogLimits, ReadPrincipal, SnapshotPin,
};
pub use shape::{
    DependencyScope, GameMode, HostShapeTransport, NATIVE_VOXEL_FORMAT, NATIVE_VOXEL_MEDIA_TYPE,
    PairedShapeSource, ShapeAuthority, ShapeControl, ShapeDependencyRegion, ShapeError,
    ShapeGeometryStore, ShapeGrant, ShapeInvalidation, ShapeLimits, ShapePort, ShapeProbe,
    ShapeRead, ShapeReadEvidence, ShapeService, ShapeSourceResult, decode_native_observation,
};
pub use snapshot::{
    IndexedRecord, MissingRecordClaim, ObservationWindow, SearchTerms, SnapshotIdentity,
    SnapshotInput,
};
pub use source::{
    CaptureBudget, CaptureControl, CaptureResult, CaptureSourceAccess, CaptureSourceEvidence,
    SnapshotSource,
};

#[cfg(test)]
mod tests;

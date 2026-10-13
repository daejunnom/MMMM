//! FN20–22 reference semantics. Wire values are validated by the original
//! contract; source access and authentication remain explicit application ports.
//! This crate opens no files, connects to no game, and changes no runtime state.

pub mod catalog;
pub mod query;
pub mod snapshot;
pub mod source;

pub use catalog::{
    AccessControl, Catalog, CatalogError, CatalogLimits, ReadPrincipal, SnapshotPin,
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

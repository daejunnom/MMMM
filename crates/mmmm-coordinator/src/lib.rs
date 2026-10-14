//! One authenticated local service owns the durable store. CLI and MCP clients
//! call this transport; neither opens a second operation journal.
pub mod artifacts;
pub mod auth;
pub mod authority;
pub mod bootstrap;
pub mod catalog_source;
pub mod client;
pub mod composite;
pub mod credential;
pub mod daemon;
pub mod daemon_launch;
pub mod endpoint;
pub mod feature_sources;
pub mod features;
pub mod host;
mod host_read_policy;
pub mod host_relay;
pub mod http;
pub mod lifecycle;
pub mod local_setup;
pub mod native_backend;
mod native_catalog;
pub mod native_entry;
mod native_import_files;
pub mod native_payload;
pub mod native_project;
pub mod native_read_targets;
pub mod native_source_ingress;
pub mod native_targets;
pub mod observer;
pub mod owned_planning_data;
pub mod peer;
pub mod peer_management;
pub mod planning_context;
pub mod planning_source;
pub mod production_factory;
pub mod rpc;
pub mod service;
pub mod setup;
pub mod stdio_io;
pub mod target_profile;
mod undo_context;
mod undo_material;
pub mod workspace_bootstrap;

pub use auth::{AuthenticatedPrincipal, SessionAuthority, SessionPolicy};
pub use client::{CoordinatorClient, HostRpcClient};
pub use credential::{CredentialRef, CredentialStore, NativeCredentialStore, SecretToken};
pub use endpoint::{EndpointRecord, RuntimeDirectory};
pub use lifecycle::Coordinator;
pub use service::{
    ApplicationPorts, ApplicationService, ExtensionRouter, ServiceDispatcher, ServiceError,
    ServiceExtension, ServiceExtensionContext,
};

#[cfg(test)]
mod tests;

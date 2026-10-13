//! One authenticated local service owns the durable store. CLI and MCP clients
//! call this transport; neither opens a second operation journal.
pub mod artifacts;
pub mod auth;
pub mod authority;
pub mod bootstrap;
pub mod client;
pub mod credential;
pub mod endpoint;
pub mod features;
pub mod host;
pub mod http;
pub mod lifecycle;
pub mod observer;
pub mod peer;
pub mod peer_management;
pub mod planning_source;
pub mod rpc;
pub mod service;
pub mod setup;
pub mod stdio_io;

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

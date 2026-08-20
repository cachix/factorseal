//! Factorseal's hardware-bound per-user secret agent.
//!
//! The per-user agent is the primary architecture: one process owns an
//! embedded Turso database containing encrypted, signed Automerge documents.
//! Every platform nests a Factorseal password inside its hardware key
//! wrapping, so neither factor unlocks alone. Applications use authenticated
//! local IPC and never open the database or receive its keys.
//!
mod crypto;
mod error;

#[cfg(any(feature = "agent", feature = "agent-client"))]
pub mod agent;

pub(crate) use error::{Error, Result};

#[cfg(feature = "agent-client")]
pub use agent::{
    AgentAction, AgentClient, AgentError, AgentRequest, AgentResponse, AgentResponseBody,
    AgentResponseError, AgentResponseErrorCode, AgentResult, DeviceKeyId, DeviceSeal, DocumentId,
    DocumentScope, NestedFactorKind, RequestId, Seal, SealId, SecretAddress, UnlockFactor,
    WireSecret, WireSecretAddress,
};

#[cfg(feature = "agent")]
pub use agent::{
    AgentService, AgentStore, CallerIdentity, CallerPlatform, GrantPermission, UnlockLeasePolicy,
    UnlockedSeal,
};

#[cfg(all(feature = "agent-client", target_os = "linux"))]
pub use agent::LinuxAgentClient;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub use agent::{LinuxAgentOptions, linux_caller_identity_for_executable, serve_linux_agent};

#[cfg(all(feature = "agent-client", target_os = "macos"))]
pub use agent::MacosAgentClient;

#[cfg(all(feature = "agent", target_os = "macos"))]
pub use agent::{MacosAgentOptions, macos_caller_identity_for_executable, serve_macos_agent};

#[cfg(all(feature = "agent-client", target_os = "windows"))]
pub use agent::WindowsAgentClient;

#[cfg(all(feature = "agent", target_os = "windows"))]
pub use agent::{WindowsAgentOptions, serve_windows_agent, windows_caller_identity_for_executable};

#[cfg(feature = "hardware")]
mod hardware;

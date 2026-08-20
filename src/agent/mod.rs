//! Storage and protocol primitives for the per-user agent.
//!
//! The agent is the only component that opens the embedded database. Its
//! callers use domain operations; raw Automerge mutation is deliberately not
//! part of the public API.

#[cfg(feature = "agent")]
mod document;
#[cfg(feature = "agent")]
mod envelope;
mod protocol;
mod seal;
#[cfg(feature = "agent")]
mod store;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod transport;

#[cfg(all(feature = "agent", target_os = "linux"))]
mod linux;

#[cfg(all(feature = "agent", target_os = "macos"))]
mod macos;

#[cfg(all(feature = "agent", target_os = "windows"))]
mod windows;
#[cfg(all(feature = "agent-client", target_os = "windows"))]
mod windows_client;

#[cfg(all(
    feature = "agent-client",
    any(target_os = "linux", target_os = "macos")
))]
mod unix_client;

#[cfg(all(
    feature = "agent",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
use std::collections::HashMap;
use std::fmt;
#[cfg(all(
    feature = "agent",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
use std::sync::Mutex;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(feature = "agent")]
pub(crate) use document::{DocumentMutation, SecretDocument, SecretRead};
#[cfg(feature = "agent")]
pub use envelope::{
    EncryptedSnapshot, SignatureAlgorithm, SignedChangeEnvelope, verify_and_decrypt_change,
    verify_and_decrypt_snapshot,
};
pub use protocol::{
    AgentAction, AgentClient, AgentRequest, AgentResponse, AgentResponseBody, AgentResponseError,
    AgentResponseErrorCode, CallerIdentity, CallerPlatform, RequestId, WireSecret,
    WireSecretAddress,
};
#[cfg(feature = "agent")]
pub use protocol::{AgentService, GrantPermission, UnlockLeasePolicy};
#[cfg(feature = "agent")]
pub use seal::UnlockedSeal;
pub use seal::{DeviceSeal, NestedFactorKind, Seal, UnlockFactor};
#[cfg(feature = "agent")]
pub use store::AgentStore;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub use linux::{LinuxAgentOptions, linux_caller_identity_for_executable, serve_linux_agent};
#[cfg(all(feature = "agent", target_os = "macos"))]
pub use macos::{MacosAgentOptions, macos_caller_identity_for_executable, serve_macos_agent};

// Linux and macOS share one Unix socket client; each target names it after
// the transport it talks to.
#[cfg(all(feature = "agent-client", target_os = "linux"))]
pub use unix_client::UnixAgentClient as LinuxAgentClient;
#[cfg(all(feature = "agent-client", target_os = "macos"))]
pub use unix_client::UnixAgentClient as MacosAgentClient;

#[cfg(all(feature = "agent", target_os = "windows"))]
pub use windows::{
    WindowsAgentOptions, serve_windows_agent, windows_caller_identity_for_executable,
};
#[cfg(all(feature = "agent-client", target_os = "windows"))]
pub use windows_client::WindowsAgentClient;

/// Files the store owns inside a seal root. `seal` needs their names to
/// undo a half-finished initialization, and it compiles without `agent`.
#[cfg(any(feature = "agent", feature = "hardware"))]
const DATABASE_FILE: &str = "agent.db";
#[cfg(any(feature = "agent", feature = "hardware"))]
const LOCK_FILE: &str = "agent.lock";

const SEAL_ID_BYTES: usize = 16;
const DEVICE_KEY_ID_BYTES: usize = 32;
const DOCUMENT_ID_BYTES: usize = 32;
const MAX_ADDRESS_COMPONENT_BYTES: usize = 4 * 1024;
#[cfg(all(
    feature = "agent",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
const MAX_CALLER_IDENTITY_CACHE_ENTRIES: usize = 256;

#[cfg(all(
    feature = "agent",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
#[derive(Default)]
struct CallerIdentityCache {
    entries: Mutex<HashMap<String, CallerIdentity>>,
}

#[cfg(all(
    feature = "agent",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
impl CallerIdentityCache {
    fn resolve(
        &self,
        key: String,
        create: impl FnOnce() -> AgentResult<CallerIdentity>,
    ) -> AgentResult<CallerIdentity> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| AgentError::WorkerUnavailable)?;
        if let Some(identity) = entries.get(&key) {
            return Ok(identity.clone());
        }
        let identity = create()?;
        if entries.len() >= MAX_CALLER_IDENTITY_CACHE_ENTRIES {
            entries.clear();
        }
        entries.insert(key, identity.clone());
        Ok(identity)
    }
}

/// Errors returned by the agent layer.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("secret address {component} must not be empty")]
    EmptyAddress { component: &'static str },

    #[error("secret address {component} exceeds {maximum} bytes")]
    AddressTooLong {
        component: &'static str,
        maximum: usize,
    },

    #[error("invalid agent data: {0}")]
    InvalidData(String),

    #[error("Automerge operation failed: {0}")]
    Automerge(String),

    #[error("agent cryptographic operation failed")]
    Crypto,

    #[error("agent signature verification failed")]
    Signature,

    #[error("the secret has concurrent values and requires explicit resolution")]
    Conflict,

    #[error("the secret has expired")]
    Expired,

    #[error("random-number generation failed: {0}")]
    Random(String),

    #[error("agent database operation failed: {0}")]
    Database(String),

    #[error("the agent worker is unavailable")]
    WorkerUnavailable,

    #[error("the agent is locked")]
    Locked,

    #[error("the request was already consumed")]
    Replay,

    #[error("application authorization is required")]
    AuthorizationRequired,

    #[error("invalid agent protocol message: {0}")]
    Protocol(String),

    #[error("agent seal operation failed: {0}")]
    Seal(String),
}

pub type AgentResult<T> = std::result::Result<T, AgentError>;

impl From<getrandom::Error> for AgentError {
    fn from(error: getrandom::Error) -> Self {
        Self::Random(error.to_string())
    }
}

/// Permanent random identifier for one Factorseal seal.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SealId([u8; SEAL_ID_BYTES]);

impl SealId {
    pub fn random() -> AgentResult<Self> {
        let mut bytes = [0_u8; SEAL_ID_BYTES];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; SEAL_ID_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SEAL_ID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for SealId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SealId")
            .field(&URL_SAFE_NO_PAD.encode(self.0))
            .finish()
    }
}

impl fmt::Display for SealId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

/// Digest identifier for the seal's separate signing key.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceKeyId([u8; DEVICE_KEY_ID_BYTES]);

impl DeviceKeyId {
    #[must_use]
    pub fn for_public_key(public_key: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"factorseal/device-key-id/v1\0");
        digest.update(public_key);
        Self(digest.finalize().into())
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; DEVICE_KEY_ID_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DEVICE_KEY_ID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for DeviceKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DeviceKeyId")
            .field(&URL_SAFE_NO_PAD.encode(self.0))
            .finish()
    }
}

impl fmt::Display for DeviceKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

/// Replication and authorization class for one Automerge document.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum DocumentScope {
    DeviceCache,
    DeviceLocal,
}

impl DocumentScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeviceCache => "device-cache",
            Self::DeviceLocal => "device-local",
        }
    }

    #[cfg(feature = "agent")]
    pub(crate) fn parse(value: &str) -> AgentResult<Self> {
        match value {
            "device-cache" => Ok(Self::DeviceCache),
            "device-local" => Ok(Self::DeviceLocal),
            _ => Err(AgentError::InvalidData(format!(
                "unknown document scope `{value}`"
            ))),
        }
    }
}

/// Opaque identifier for one encrypted Automerge document.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DocumentId([u8; DOCUMENT_ID_BYTES]);

impl DocumentId {
    /// Derive an opaque document ID without exposing `namespace` to SQL.
    #[must_use]
    pub fn derive(seal_id: SealId, scope: DocumentScope, namespace: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"factorseal/document-id/v1\0");
        digest.update(seal_id.as_bytes());
        digest.update(scope.as_str().as_bytes());
        digest.update((namespace.len() as u64).to_be_bytes());
        digest.update(namespace);
        Self(digest.finalize().into())
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; DOCUMENT_ID_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DOCUMENT_ID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for DocumentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DocumentId")
            .field(&URL_SAFE_NO_PAD.encode(self.0))
            .finish()
    }
}

impl fmt::Display for DocumentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

/// Factorseal's native secret coordinates.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SecretAddress {
    item: String,
    field: Option<String>,
}

impl SecretAddress {
    pub fn new(item: impl Into<String>, field: Option<String>) -> AgentResult<Self> {
        let address = Self {
            item: item.into(),
            field,
        };
        address.validate()?;
        Ok(address)
    }

    #[must_use]
    pub fn item(&self) -> &str {
        &self.item
    }

    #[must_use]
    pub fn field(&self) -> Option<&str> {
        self.field.as_deref()
    }

    #[cfg(any(feature = "agent", test))]
    pub(crate) fn storage_key(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"factorseal/secret-address/v1\0");
        digest.update((self.item.len() as u64).to_be_bytes());
        digest.update(self.item.as_bytes());
        match &self.field {
            Some(field) => {
                digest.update([1]);
                digest.update((field.len() as u64).to_be_bytes());
                digest.update(field.as_bytes());
            }
            None => digest.update([0]),
        }
        URL_SAFE_NO_PAD.encode(digest.finalize())
    }

    fn validate(&self) -> AgentResult<()> {
        validate_address_component("item", &self.item)?;
        if let Some(field) = &self.field {
            validate_address_component("field", field)?;
        }
        Ok(())
    }
}

fn validate_address_component(component: &'static str, value: &str) -> AgentResult<()> {
    if value.is_empty() {
        return Err(AgentError::EmptyAddress { component });
    }
    if value.len() > MAX_ADDRESS_COMPONENT_BYTES {
        return Err(AgentError::AddressTooLong {
            component,
            maximum: MAX_ADDRESS_COMPONENT_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_ids_are_scoped_and_installation_specific() {
        let first = SealId::from_bytes([1; SEAL_ID_BYTES]);
        let second = SealId::from_bytes([2; SEAL_ID_BYTES]);
        let cache = DocumentId::derive(first, DocumentScope::DeviceCache, b"secretspec");

        assert_ne!(
            cache,
            DocumentId::derive(first, DocumentScope::DeviceLocal, b"secretspec")
        );
        assert_ne!(
            cache,
            DocumentId::derive(second, DocumentScope::DeviceCache, b"secretspec")
        );
    }

    #[test]
    fn address_storage_key_binds_field_without_revealing_names() {
        let plain = SecretAddress::new("production/database", None).unwrap();
        let field = SecretAddress::new("production/database", Some("password".to_owned())).unwrap();

        assert_ne!(plain.storage_key(), field.storage_key());
        assert!(!field.storage_key().contains("production"));
        assert!(!field.storage_key().contains("password"));
    }
}

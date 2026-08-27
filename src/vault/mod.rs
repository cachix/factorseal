//! Storage and protocol primitives for the per-user vault.
//!
//! The vault service is the only component that opens the embedded database. Its
//! callers use domain operations; raw Automerge mutation is deliberately not
//! part of the public API.

#[cfg(feature = "vault-store")]
mod document;
#[cfg(feature = "vault-store")]
mod envelope;
#[cfg(feature = "key-protection")]
mod protection;
mod protocol;
mod seal;
#[cfg(any(feature = "key-protection", feature = "vault-store"))]
mod signature;
#[cfg(feature = "vault-store")]
mod store;
#[cfg(all(
    any(feature = "vault", feature = "vault-client"),
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
mod transport;

#[cfg(all(feature = "vault", target_os = "linux"))]
mod linux;
#[cfg(all(feature = "vault", target_os = "linux"))]
mod secret_service;

#[cfg(all(feature = "vault", target_os = "macos"))]
mod macos;

#[cfg(all(feature = "vault", target_os = "windows"))]
mod windows;
#[cfg(all(feature = "vault-client", target_os = "windows"))]
mod windows_client;

#[cfg(all(
    feature = "vault-client",
    any(target_os = "linux", target_os = "macos")
))]
mod unix_client;

#[cfg(all(
    feature = "vault",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
use std::collections::HashMap;
use std::fmt;
#[cfg(all(
    feature = "vault",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
use std::sync::Mutex;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(feature = "vault-store")]
pub(crate) use document::{DocumentMutation, DocumentOperation, SecretDocument, SecretRead};
#[cfg(feature = "vault-store")]
pub use envelope::{
    EncryptedSnapshot, SignatureAlgorithm, SignedChangeEnvelope, verify_and_decrypt_change,
    verify_and_decrypt_snapshot,
};
#[cfg(feature = "key-protection")]
pub use protection::{HardwareBackend, KeyProtector, KeyProtectorFactory};
pub use protocol::{
    ApprovalOperation, ApprovalPrincipal, CallerIdentity, CallerPlatform, PendingApproval,
    RequestId, VaultAction, VaultApplicationContext, VaultClient, VaultInteractionReference,
    VaultMutation, VaultRequest, VaultResponse, VaultResponseBody, VaultResponseError,
    VaultResponseErrorCode, WireSecret, WireSecretAddress,
};
#[cfg(feature = "vault-store")]
pub use protocol::{GrantPermission, UnsealLeasePolicy, VaultService};
pub use seal::{
    NestedFactorKind, UnlockCredentials, UnlockFactorKind, UnlockGroup, UnlockPolicy, UnsealFactor,
    UnsealedVault, Vault, VaultMetadata, VaultPlatform,
};
#[cfg(feature = "vault-store")]
pub(crate) use store::VaultStore;

#[cfg(all(feature = "vault", target_os = "linux"))]
pub use linux::{LinuxVaultOptions, linux_caller_identity_for_executable, serve_linux_vault};
#[cfg(all(feature = "vault", target_os = "macos"))]
pub use macos::{MacosVaultOptions, macos_caller_identity_for_executable, serve_macos_vault};

// Linux and macOS share one Unix socket client; each target names it after
// the transport it talks to.
#[cfg(all(feature = "vault-client", target_os = "linux"))]
pub use unix_client::UnixVaultClient as LinuxVaultClient;
#[cfg(all(feature = "vault-client", target_os = "macos"))]
pub use unix_client::UnixVaultClient as MacosVaultClient;

#[cfg(all(feature = "vault", target_os = "windows"))]
pub use windows::{
    WindowsVaultOptions, serve_windows_vault, windows_caller_identity_for_executable,
};
#[cfg(all(feature = "vault-client", target_os = "windows"))]
pub use windows_client::{WindowsVaultClient, default_windows_pipe_name};

/// Files the store owns inside a vault root. The sealing layer needs their
/// names to undo a half-finished initialization without the `vault` feature.
#[cfg(any(feature = "vault-store", all(test, feature = "key-protection")))]
const DATABASE_FILE: &str = "factorseal.db";
#[cfg(any(feature = "vault-store", all(test, feature = "key-protection")))]
const LOCK_FILE: &str = "factorseal.lock";

const VAULT_ID_BYTES: usize = 16;
const DEVICE_KEY_ID_BYTES: usize = 32;
const DOCUMENT_ID_BYTES: usize = 32;
const MAX_ADDRESS_COMPONENT_BYTES: usize = 4 * 1024;
#[cfg(all(
    feature = "vault",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
const MAX_CALLER_IDENTITY_CACHE_ENTRIES: usize = 256;

#[cfg(all(
    feature = "vault",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
#[derive(Default)]
struct CallerIdentityCache {
    entries: Mutex<HashMap<String, CallerIdentity>>,
}

#[cfg(all(
    feature = "vault",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
impl CallerIdentityCache {
    fn resolve(
        &self,
        key: String,
        create: impl FnOnce() -> VaultResult<CallerIdentity>,
    ) -> VaultResult<CallerIdentity> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| VaultError::WorkerUnavailable)?;
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

/// Errors returned by the vault layer.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("secret address {component} must not be empty")]
    EmptyAddress { component: &'static str },

    #[error("secret address {component} exceeds {maximum} bytes")]
    AddressTooLong {
        component: &'static str,
        maximum: usize,
    },

    #[error("invalid vault data: {0}")]
    InvalidData(String),

    #[error("Automerge operation failed: {0}")]
    Automerge(String),

    #[error("vault cryptographic operation failed")]
    Crypto,

    #[error("vault signature verification failed")]
    Signature,

    #[error("the secret has concurrent values and requires explicit resolution")]
    Conflict,

    #[error("the secret has expired")]
    Expired,

    #[error("random-number generation failed: {0}")]
    Random(String),

    #[error("vault database operation failed: {0}")]
    Database(String),

    #[error("the vault worker is unavailable")]
    WorkerUnavailable,

    #[error("no vault agent is listening on `{0}`")]
    AgentUnreachable(String),

    #[error("the vault is sealed")]
    Sealed,

    #[error("the request was already consumed")]
    Replay,

    #[error("application authorization is required")]
    AuthorizationRequired,

    #[error("invalid vault protocol message: {0}")]
    Protocol(String),

    #[error("vault protection operation failed: {0}")]
    Protection(String),
}

pub type VaultResult<T> = std::result::Result<T, VaultError>;

impl From<getrandom::Error> for VaultError {
    fn from(error: getrandom::Error) -> Self {
        Self::Random(error.to_string())
    }
}

/// Permanent random identifier for one Factorseal vault.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VaultId([u8; VAULT_ID_BYTES]);

impl VaultId {
    pub fn random() -> VaultResult<Self> {
        let mut bytes = [0_u8; VAULT_ID_BYTES];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; VAULT_ID_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; VAULT_ID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for VaultId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("VaultId")
            .field(&URL_SAFE_NO_PAD.encode(self.0))
            .finish()
    }
}

impl fmt::Display for VaultId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

/// Digest identifier for the vault's separate signing key.
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

    #[cfg(feature = "vault-store")]
    pub(crate) fn parse(value: &str) -> VaultResult<Self> {
        match value {
            "device-cache" => Ok(Self::DeviceCache),
            "device-local" => Ok(Self::DeviceLocal),
            _ => Err(VaultError::InvalidData(format!(
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
    pub fn derive(vault_id: VaultId, scope: DocumentScope, namespace: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"factorseal/document-id/v1\0");
        digest.update(vault_id.as_bytes());
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
    pub fn new(item: impl Into<String>, field: Option<String>) -> VaultResult<Self> {
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

    #[cfg(any(feature = "vault-store", test))]
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

    fn validate(&self) -> VaultResult<()> {
        validate_address_component("item", &self.item)?;
        if let Some(field) = &self.field {
            validate_address_component("field", field)?;
        }
        Ok(())
    }
}

fn validate_address_component(component: &'static str, value: &str) -> VaultResult<()> {
    if value.is_empty() {
        return Err(VaultError::EmptyAddress { component });
    }
    if value.len() > MAX_ADDRESS_COMPONENT_BYTES {
        return Err(VaultError::AddressTooLong {
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
        let first = VaultId::from_bytes([1; VAULT_ID_BYTES]);
        let second = VaultId::from_bytes([2; VAULT_ID_BYTES]);
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

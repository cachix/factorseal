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
use std::sync::Arc;
#[cfg(all(
    feature = "vault",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
use std::sync::Mutex;
#[cfg(all(
    feature = "vault",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
use std::sync::atomic::{AtomicBool, Ordering};

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
    CallerIdentity, CallerPlatform, MAX_LIST_PAGE_SIZE, MAX_PERMISSION_WAIT_MS, Permission,
    PermissionChange, PermissionOperation, PermissionPrincipal, PermissionState,
    PermissionWaitStatus, RequestId, VaultAction, VaultApplicationContext, VaultClient,
    VaultInteractionReference, VaultMutation, VaultRequest, VaultResponse, VaultResponseBody,
    VaultResponseError, VaultResponseErrorCode, WireSecret, WireSecretAddress,
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
pub use linux::{
    LinuxVaultLifecycle, LinuxVaultOptions, linux_caller_identity_for_executable,
    serve_linux_vault, serve_linux_vault_with_lifecycle,
};
#[cfg(all(feature = "vault", target_os = "macos"))]
pub use macos::{
    MacosVaultLifecycle, MacosVaultOptions, macos_caller_identity_for_executable,
    serve_macos_vault, serve_macos_vault_with_lifecycle,
};

// Linux and macOS share one Unix socket client; each target names it after
// the transport it talks to.
#[cfg(all(feature = "vault-client", target_os = "linux"))]
pub use unix_client::UnixVaultClient as LinuxVaultClient;
#[cfg(all(feature = "vault-client", target_os = "macos"))]
pub use unix_client::UnixVaultClient as MacosVaultClient;

#[cfg(all(feature = "vault", target_os = "windows"))]
pub use windows::{
    WindowsVaultLifecycle, WindowsVaultOptions, serve_windows_vault,
    serve_windows_vault_with_lifecycle, windows_caller_identity_for_executable,
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

/// Latches native lifecycle events before hardware-unwrapped keys enter
/// memory, then connects those events to the live service once it exists.
///
/// Registration and unsealing deliberately happen in that order. If lock or
/// suspend arrives during native authorization or database opening, attaching
/// the service observes the latch and seals it before accepting any client.
#[cfg(all(
    feature = "vault",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
struct LifecycleSignal {
    requested: AtomicBool,
    armed: AtomicBool,
    safe: AtomicBool,
    service: Mutex<Option<Arc<VaultService>>>,
}

#[cfg(all(
    feature = "vault",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
impl LifecycleSignal {
    fn new() -> Self {
        Self {
            requested: AtomicBool::new(false),
            armed: AtomicBool::new(false),
            safe: AtomicBool::new(true),
            service: Mutex::new(None),
        }
    }

    fn arm(&self) -> VaultResult<()> {
        if self.requested.load(Ordering::Acquire) {
            return Err(VaultError::NativeAuthorization(
                NativeAuthorizationError::SessionLocked,
            ));
        }
        self.safe.store(false, Ordering::Release);
        self.armed.store(true, Ordering::Release);
        // Close the check/arm race: a callback that ran between the first
        // load and `armed.store` leaves the latch set and must abort unseal.
        if self.requested.load(Ordering::Acquire) {
            self.disarm();
            return Err(VaultError::NativeAuthorization(
                NativeAuthorizationError::SessionLocked,
            ));
        }
        Ok(())
    }

    fn attach(&self, service: &Arc<VaultService>) -> VaultResult<()> {
        let mut attached = self
            .service
            .lock()
            .map_err(|_| VaultError::WorkerUnavailable)?;
        *attached = Some(Arc::clone(service));
        if self.requested.load(Ordering::Acquire) {
            service.seal()?;
            self.safe
                .store(service.is_seal_complete(), Ordering::Release);
        }
        Ok(())
    }

    fn trigger(&self) {
        self.requested.store(true, Ordering::Release);
        let service = self
            .service
            .lock()
            .ok()
            .and_then(|service| service.as_ref().map(Arc::clone));
        if let Some(service) = service {
            let _ = service.seal();
            self.safe
                .store(service.is_seal_complete(), Ordering::Release);
        }
    }

    fn requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    fn needs_emergency_exit(&self) -> bool {
        self.armed.load(Ordering::Acquire) && !self.safe.load(Ordering::Acquire)
    }

    fn disarm(&self) {
        let Ok(mut service) = self.service.lock() else {
            return;
        };
        // A lifecycle callback marks the store sealed before it finishes
        // joining the key-bearing worker. Keep emergency deadlines effective
        // until that teardown has actually completed.
        if service
            .as_ref()
            .is_some_and(|service| !service.is_seal_complete())
        {
            return;
        }
        self.armed.store(false, Ordering::Release);
        self.safe.store(true, Ordering::Release);
        *service = None;
    }
}

/// Stable outcomes from a native hardware-authorization ceremony.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum NativeAuthorizationError {
    #[error("native authorization was cancelled")]
    Cancelled,

    #[error("native authorization was denied")]
    Denied,

    #[error("native authorization UI is unavailable")]
    UiUnavailable,

    #[error("the interactive session is locked or unavailable")]
    SessionLocked,

    #[error("the native platform credential was invalidated")]
    CredentialInvalidated,
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

    #[error("no supported hardware security backend is available")]
    HardwareUnavailable,

    #[error("the requested hardware security policy is unsupported")]
    HardwarePolicyUnsupported,

    #[error("vault hardware authorization failed: {0}")]
    NativeAuthorization(#[source] NativeAuthorizationError),

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

/// Semantic type of one encrypted Automerge document.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum DocumentKind {
    Authorization,
    LinuxSecretService,
    LocalKeyring,
    SecretSpecProject,
    SecretSpecProviderCache,
}

impl DocumentKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authorization => "authorization",
            Self::LinuxSecretService => "linux-secret-service",
            Self::LocalKeyring => "local-keyring",
            Self::SecretSpecProject => "secretspec-project",
            Self::SecretSpecProviderCache => "secretspec-provider-cache",
        }
    }

    #[cfg(feature = "vault-store")]
    pub(crate) fn parse(value: &str) -> VaultResult<Self> {
        match value {
            "authorization" => Ok(Self::Authorization),
            "linux-secret-service" => Ok(Self::LinuxSecretService),
            "local-keyring" => Ok(Self::LocalKeyring),
            "secretspec-project" => Ok(Self::SecretSpecProject),
            "secretspec-provider-cache" => Ok(Self::SecretSpecProviderCache),
            _ => Err(VaultError::InvalidData(format!(
                "unknown document kind `{value}`"
            ))),
        }
    }
}

/// Opaque identifier for one encrypted Automerge document.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DocumentId([u8; DOCUMENT_ID_BYTES]);

impl DocumentId {
    /// Deterministic fixture helper. Production IDs are keyed inside the sole
    /// database worker so project names cannot be guessed from SQL metadata.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn derive_for_test(vault_id: VaultId, kind: DocumentKind, partition: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"factorseal/document-id/v1\0");
        digest.update(vault_id.as_bytes());
        digest.update(kind.as_str().as_bytes());
        digest.update((partition.len() as u64).to_be_bytes());
        digest.update(partition);
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

/// Complete SecretSpec address supplied to a provider after routing.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretSpecAddress {
    Convention {
        project: String,
        profile: String,
        key: String,
    },
    Native {
        coordinates: SecretSpecCoordinates,
    },
}

/// Native provider coordinates supported by the SecretSpec protocol.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSpecCoordinates {
    pub item: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl SecretSpecAddress {
    pub fn convention(
        project: impl Into<String>,
        profile: impl Into<String>,
        key: impl Into<String>,
    ) -> VaultResult<Self> {
        let address = Self::Convention {
            project: project.into(),
            profile: profile.into(),
            key: key.into(),
        };
        address.validate()?;
        Ok(address)
    }

    pub fn native(coordinates: SecretSpecCoordinates) -> VaultResult<Self> {
        let address = Self::Native { coordinates };
        address.validate()?;
        Ok(address)
    }

    pub fn validate(&self) -> VaultResult<()> {
        match self {
            Self::Convention {
                project,
                profile,
                key,
            } => {
                validate_address_component("project", project)?;
                validate_address_component("profile", profile)?;
                validate_address_component("key", key)
            }
            Self::Native { coordinates } => {
                validate_address_component("item", &coordinates.item)?;
                for (name, value) in [
                    ("field", &coordinates.field),
                    ("vault", &coordinates.vault),
                    ("section", &coordinates.section),
                    ("version", &coordinates.version),
                ] {
                    if let Some(value) = value {
                        validate_address_component(name, value)?;
                    }
                }
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn project(&self) -> Option<&str> {
        match self {
            Self::Convention { project, .. } => Some(project),
            Self::Native { .. } => None,
        }
    }

    fn update_digest(&self, digest: &mut Sha256) {
        match self {
            Self::Convention {
                project,
                profile,
                key,
            } => {
                digest.update([1]);
                update_digest_string(digest, project);
                update_digest_string(digest, profile);
                update_digest_string(digest, key);
            }
            Self::Native { coordinates } => {
                digest.update([2]);
                update_digest_string(digest, &coordinates.item);
                for value in [
                    &coordinates.field,
                    &coordinates.vault,
                    &coordinates.section,
                    &coordinates.version,
                ] {
                    update_digest_option(digest, value.as_deref());
                }
            }
        }
    }
}

/// Address stored atomically in an encrypted Automerge entry.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(tag = "domain", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretAddress {
    Local {
        item: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        field: Option<String>,
    },
    SecretSpec {
        address: SecretSpecAddress,
    },
}

impl SecretAddress {
    pub fn new(item: impl Into<String>, field: Option<String>) -> VaultResult<Self> {
        let address = Self::Local {
            item: item.into(),
            field,
        };
        address.validate()?;
        Ok(address)
    }

    /// Return the native keyring coordinates when this is a local address.
    #[must_use]
    pub fn as_local(&self) -> Option<(&str, Option<&str>)> {
        match self {
            Self::Local { item, field } => Some((item, field.as_deref())),
            Self::SecretSpec { .. } => None,
        }
    }

    pub fn secret_spec(address: SecretSpecAddress) -> VaultResult<Self> {
        address.validate()?;
        Ok(Self::SecretSpec { address })
    }

    #[must_use]
    pub fn as_secret_spec(&self) -> Option<&SecretSpecAddress> {
        match self {
            Self::SecretSpec { address } => Some(address),
            Self::Local { .. } => None,
        }
    }

    #[cfg(any(feature = "vault-store", test))]
    pub(crate) fn storage_key(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"factorseal/secret-address/v1\0");
        match self {
            Self::Local { item, field } => {
                digest.update([1]);
                update_digest_string(&mut digest, item);
                update_digest_option(&mut digest, field.as_deref());
            }
            Self::SecretSpec { address } => {
                digest.update([2]);
                address.update_digest(&mut digest);
            }
        }
        URL_SAFE_NO_PAD.encode(digest.finalize())
    }

    fn validate(&self) -> VaultResult<()> {
        match self {
            Self::Local { item, field } => {
                validate_address_component("item", item)?;
                if let Some(field) = field {
                    validate_address_component("field", field)?;
                }
                Ok(())
            }
            Self::SecretSpec { address } => address.validate(),
        }
    }
}

fn update_digest_string(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn update_digest_option(digest: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            digest.update([1]);
            update_digest_string(digest, value);
        }
        None => digest.update([0]),
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
    fn document_ids_are_kind_partitioned_and_installation_specific() {
        let first = VaultId::from_bytes([1; VAULT_ID_BYTES]);
        let second = VaultId::from_bytes([2; VAULT_ID_BYTES]);
        let cache = DocumentId::derive_for_test(
            first,
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
        );

        assert_ne!(
            cache,
            DocumentId::derive_for_test(first, DocumentKind::LocalKeyring, b"secretspec")
        );
        assert_ne!(
            cache,
            DocumentId::derive_for_test(
                second,
                DocumentKind::SecretSpecProviderCache,
                b"secretspec"
            )
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

    #[cfg(all(
        feature = "vault",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    #[test]
    fn lifecycle_events_latch_before_a_service_is_attached() {
        let signal = LifecycleSignal::new();
        signal.arm().unwrap();
        signal.trigger();

        assert!(signal.requested());
        assert!(signal.needs_emergency_exit());
    }

    #[cfg(all(
        feature = "vault",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    #[test]
    fn an_already_locked_session_refuses_to_arm() {
        let signal = LifecycleSignal::new();
        signal.trigger();

        assert!(matches!(
            signal.arm(),
            Err(VaultError::NativeAuthorization(
                NativeAuthorizationError::SessionLocked
            ))
        ));
    }
}

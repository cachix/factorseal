//! Factorseal's hardware-bound vault.
//!
//! A per-user background service owns an
//! embedded Turso database containing encrypted, signed Automerge documents.
//! Each installation records AND-factor groups as independently hardware-wrapped OR
//! alternatives. Applications use its keyring
//! interface over authenticated local IPC and never open the database or
//! receive its keys.
//!
mod algorithm;
#[cfg(any(feature = "key-protection", feature = "vault-store"))]
mod crypto;
#[cfg(any(feature = "key-protection", feature = "vault-store"))]
mod error;

#[cfg(feature = "vault-client")]
pub mod keyring;

#[cfg(any(
    feature = "key-protection",
    feature = "vault-client",
    feature = "vault-store"
))]
pub mod vault;

#[cfg(any(feature = "key-protection", feature = "vault-store"))]
pub(crate) use error::{Error, Result};

pub use algorithm::EncryptionAlgorithm;

#[cfg(feature = "vault-client")]
pub use keyring::{Keyring, KeyringError, KeyringResult};

#[cfg(any(
    feature = "key-protection",
    feature = "vault-client",
    feature = "vault-store"
))]
pub use vault::{
    DeclaredApplication, DeviceKeyId, DocumentId, DocumentKind, HistoryEntry, HistoryOperation,
    HistoryRetention, InstallationId, NativeAuthorizationError, NestedFactorKind, Provenance,
    RequestId, SecretAddress, SecretSpecAddress, SecretSpecCoordinates, ServiceReason,
    UnlockCredentials, UnlockFactorKind, UnlockGroup, UnlockPolicy, UnsealFactor, UnsealedVault,
    Vault, VaultCryptoProfile, VaultError, VaultId, VaultKind, VaultMetadata, VaultPlatform,
    VaultResult, VersionId,
};

#[cfg(feature = "vault-client")]
pub use vault::{
    MAX_HISTORY_PAGE_SIZE, MAX_LIST_PAGE_SIZE, MAX_PERMISSION_WAIT_MS, Permission,
    PermissionChange, PermissionOperation, PermissionPrincipal, PermissionState,
    PermissionWaitStatus, VaultAction, VaultApplicationContext, VaultClient,
    VaultInteractionReference, VaultMutation, VaultRequest, VaultResponse, VaultResponseBody,
    VaultResponseError, VaultResponseErrorCode, WireSecret, WireSecretAddress,
};

#[cfg(feature = "vault-store")]
pub use vault::{CallerIdentity, CallerPlatform, GrantPermission, UnsealLeasePolicy, VaultService};

#[cfg(feature = "key-protection")]
pub use vault::{HardwareBackend, KeyProtector, KeyProtectorFactory};

#[cfg(all(feature = "vault-client", target_os = "linux"))]
pub use vault::LinuxVaultClient;
#[cfg(all(feature = "vault-client", target_os = "linux"))]
pub type NativeVaultClient = LinuxVaultClient;

#[cfg(all(feature = "vault", target_os = "linux"))]
pub use vault::{
    LinuxVaultLifecycle, LinuxVaultOptions, linux_caller_identity_for_executable,
    serve_linux_vault, serve_linux_vault_with_lifecycle,
};

#[cfg(all(feature = "vault-client", target_os = "macos"))]
pub use vault::MacosVaultClient;
#[cfg(all(feature = "vault-client", target_os = "macos"))]
pub type NativeVaultClient = MacosVaultClient;

#[cfg(all(feature = "vault", target_os = "macos"))]
pub use vault::{
    MacosVaultLifecycle, MacosVaultOptions, macos_caller_identity_for_executable,
    serve_macos_vault, serve_macos_vault_with_lifecycle,
};

#[cfg(all(feature = "vault-client", target_os = "windows"))]
pub use vault::{WindowsVaultClient, default_windows_pipe_name};
#[cfg(all(feature = "vault-client", target_os = "windows"))]
pub type NativeVaultClient = WindowsVaultClient;

#[cfg(all(feature = "vault", target_os = "windows"))]
pub use vault::{
    WindowsVaultLifecycle, WindowsVaultOptions, serve_windows_vault,
    serve_windows_vault_with_lifecycle, windows_caller_identity_for_executable,
};

#[cfg(feature = "hardware")]
mod hardware;

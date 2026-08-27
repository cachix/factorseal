//! Factorseal's hardware-bound vault.
//!
//! A per-user background service owns an
//! embedded Turso database containing encrypted, signed Automerge documents.
//! Each vault records AND-factor groups as independently hardware-wrapped OR
//! alternatives. Applications use its keyring
//! interface over authenticated local IPC and never open the database or
//! receive its keys.
//!
#[cfg(feature = "key-protection")]
mod crypto;
#[cfg(feature = "key-protection")]
mod error;

#[cfg(feature = "vault-client")]
pub mod keyring;

#[cfg(any(
    feature = "key-protection",
    feature = "vault-client",
    feature = "vault-store"
))]
pub mod vault;

#[cfg(feature = "key-protection")]
pub(crate) use error::{Error, Result};

#[cfg(feature = "vault-client")]
pub use keyring::{Keyring, KeyringError, KeyringResult};

#[cfg(any(
    feature = "key-protection",
    feature = "vault-client",
    feature = "vault-store"
))]
pub use vault::{
    DeviceKeyId, DocumentId, DocumentScope, NestedFactorKind, RequestId, SecretAddress,
    UnlockCredentials, UnlockFactorKind, UnlockGroup, UnlockPolicy, UnsealFactor, UnsealedVault,
    Vault, VaultError, VaultId, VaultMetadata, VaultPlatform, VaultResult,
};

#[cfg(feature = "vault-client")]
pub use vault::{
    ApprovalOperation, PendingApproval, VaultAction, VaultApplicationContext, VaultClient,
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
pub use vault::{LinuxVaultOptions, linux_caller_identity_for_executable, serve_linux_vault};

#[cfg(all(feature = "vault-client", target_os = "macos"))]
pub use vault::MacosVaultClient;
#[cfg(all(feature = "vault-client", target_os = "macos"))]
pub type NativeVaultClient = MacosVaultClient;

#[cfg(all(feature = "vault", target_os = "macos"))]
pub use vault::{MacosVaultOptions, macos_caller_identity_for_executable, serve_macos_vault};

#[cfg(all(feature = "vault-client", target_os = "windows"))]
pub use vault::{WindowsVaultClient, default_windows_pipe_name};
#[cfg(all(feature = "vault-client", target_os = "windows"))]
pub type NativeVaultClient = WindowsVaultClient;

#[cfg(all(feature = "vault", target_os = "windows"))]
pub use vault::{WindowsVaultOptions, serve_windows_vault, windows_caller_identity_for_executable};

#[cfg(feature = "hardware")]
mod hardware;

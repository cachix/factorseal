//! Factorseal's hardware-bound vault.
//!
//! A per-user background service owns an
//! embedded Turso database containing encrypted, signed Automerge documents.
//! Every platform nests a Factorseal password inside its hardware key
//! wrapping, so neither factor unseals it alone. Applications use its keyring
//! interface over authenticated local IPC and never open the database or
//! receive its keys.
//!
mod crypto;
mod error;

#[cfg(feature = "vault-client")]
pub mod keyring;

#[cfg(any(feature = "vault", feature = "vault-client"))]
pub mod vault;

pub(crate) use error::{Error, Result};

#[cfg(feature = "vault-client")]
pub use keyring::{Keyring, KeyringError, KeyringResult};

#[cfg(feature = "vault-client")]
pub use vault::{
    DeviceKeyId, DocumentId, DocumentScope, NestedFactorKind, RequestId, SecretAddress,
    UnsealFactor, Vault, VaultAction, VaultClient, VaultError, VaultId, VaultMetadata,
    VaultRequest, VaultResponse, VaultResponseBody, VaultResponseError, VaultResponseErrorCode,
    VaultResult, WireSecret, WireSecretAddress,
};

#[cfg(feature = "vault")]
pub use vault::{
    CallerIdentity, CallerPlatform, GrantPermission, UnsealLeasePolicy, UnsealedVault,
    VaultService, VaultStore,
};

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
pub use vault::WindowsVaultClient;
#[cfg(all(feature = "vault-client", target_os = "windows"))]
pub type NativeVaultClient = WindowsVaultClient;

#[cfg(all(feature = "vault", target_os = "windows"))]
pub use vault::{WindowsVaultOptions, serve_windows_vault, windows_caller_identity_for_executable};

#[cfg(feature = "hardware")]
mod hardware;

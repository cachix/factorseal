//! Local encrypted credential vault for FactorSeal.
//!
//! Two-factor authentication (2FA) is required by design for supported
//! persistent vaults. The current 2FA provider combines platform hardware with
//! a PIN-protected YubiKey. Supported platform hardware can additionally
//! require biometric user verification.
//!
//! A vault is unlocked once into an [`UnlockedVault`]. The session retains a
//! zeroizing vault key, never a cache of decrypted credentials. Each `get`
//! decrypts only the requested value.

mod crypto;
mod error;
mod factor;
mod vault;

pub use error::{Error, Result};
pub use factor::FactorKind;
pub use vault::{
    CredentialMetadata, CredentialOptions, ReferenceOptions, SecretReference, UnlockedVault, Vault,
    VaultInfo,
};

#[cfg(feature = "hardware")]
mod hardware;

#[cfg(feature = "keyring")]
mod keyring;

#[cfg(feature = "keyring")]
pub use keyring::{
    EVICT_AT_ATTRIBUTE, FactorSealStore, FactorSealStoreOptions, RETENTION_SECONDS_MODIFIER,
};

#[cfg(all(target_os = "linux", feature = "secret-service"))]
mod secret_service;

#[cfg(all(target_os = "linux", feature = "secret-service"))]
pub use secret_service::{SecretServiceError, SecretServiceOptions, serve_secret_service};

#[cfg(feature = "yubikey")]
mod yubikey_factor;

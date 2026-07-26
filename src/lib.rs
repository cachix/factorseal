//! Local encrypted credential vault for FactorSeal.
//!
//! A vault is unlocked once into an [`UnlockedVault`]. The session retains a
//! zeroizing vault key, never a cache of decrypted credentials. Each `get`
//! decrypts only the requested value.

mod error;
mod vault;

pub use error::{Error, Result};
pub use vault::{UnlockedVault, Vault, VaultInfo};

#[cfg(feature = "hardware")]
mod hardware;

#[cfg(feature = "keyring")]
mod keyring;

#[cfg(feature = "keyring")]
pub use keyring::FactorSealStore;

#[cfg(all(target_os = "linux", feature = "secret-service"))]
mod secret_service;

#[cfg(all(target_os = "linux", feature = "secret-service"))]
pub use secret_service::{SecretServiceError, SecretServiceOptions, serve_secret_service};

#[cfg(feature = "yubikey")]
mod yubikey_factor;

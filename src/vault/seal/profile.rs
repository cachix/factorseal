//! Persisted cryptographic profile selected when a vault is created.

use serde::{Deserialize, Serialize};

/// Cryptographic profile used by a vault.
///
/// Both profiles use AES-256-GCM for authenticated encryption and ML-DSA-65
/// for device signatures. The default profile uses memory-hard Argon2id for
/// password factors. The FIPS profile substitutes PBKDF2-HMAC-SHA-256 so every
/// selected algorithm is NIST-standardized.
///
/// Selecting [`Self::Fips`] is not a claim that Factorseal or its RustCrypto
/// providers have completed FIPS 140-3 validation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum VaultCryptoProfile {
    /// Memory-hard password protection with Argon2id.
    #[default]
    Default,
    /// PBKDF2-HMAC-SHA-256 password protection for FIPS-oriented deployments.
    Fips,
}

impl VaultCryptoProfile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Fips => "fips",
        }
    }
}

impl std::fmt::Display for VaultCryptoProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

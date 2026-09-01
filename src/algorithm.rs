//! Persisted algorithm identifiers shared by crypto providers and clients.

use serde::{Deserialize, Serialize};

pub(crate) const AES_GCM_NONCE_BYTES: usize = 12;

/// Authenticated-encryption algorithm recorded in every protected payload.
///
/// This is an algorithm identifier, not a claim that the linked provider or
/// Factorseal itself has completed FIPS 140-3 validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
}

impl EncryptionAlgorithm {
    #[cfg(feature = "vault-store")]
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Aes256Gcm => 1,
        }
    }
}

//! Nested-factor representation and cryptography for sealed vaults.

use serde::{Deserialize, Serialize};
#[cfg(feature = "key-protection")]
use zeroize::Zeroizing;

#[cfg(feature = "key-protection")]
use super::super::VaultId;
#[cfg(feature = "key-protection")]
use super::super::signature::SIGNING_SEED_BYTES;
use super::super::{VaultError, VaultResult};

#[cfg(feature = "key-protection")]
const KEY_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
#[cfg(all(feature = "key-protection", not(test)))]
const PBKDF2_ITERATIONS: u32 = 600_000;
#[cfg(all(feature = "key-protection", test))]
const PBKDF2_ITERATIONS: u32 = 1_000;
const MIN_PBKDF2_ITERATIONS: u32 = 1_000;
const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;
#[cfg(feature = "key-protection")]
pub(super) type ProtectedKeyPayloads = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, NestedProtection);
#[cfg(feature = "key-protection")]
pub(super) type UnsealedVaultKeys = (
    Zeroizing<[u8; KEY_BYTES]>,
    Zeroizing<[u8; SIGNING_SEED_BYTES]>,
);

/// Parameters of the secret-bearing factor nested inside the platform
/// hardware wrapping.
///
/// Every variant derives its key from a NIST-approved hash or symmetric
/// primitive. This avoids adding a public-key ciphertext that creates a
/// separate store-now/decrypt-later exposure around HardwareSeal's opaque
/// native sealed-data mechanisms. A password remains entropy-limited: PBKDF2
/// raises offline-guessing cost but cannot turn a human-memorable password into
/// a post-quantum-strength factor.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "algorithm", rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
enum FactorParameters {
    Pbkdf2HmacSha256 {
        iterations: u32,
        salt: [u8; SALT_BYTES],
    },
}

impl FactorParameters {
    const fn kind(&self) -> NestedFactorKind {
        match self {
            Self::Pbkdf2HmacSha256 { .. } => NestedFactorKind::Pbkdf2HmacSha256Password,
        }
    }
}

/// The nested factor recorded for a vault, with the nonces that
/// bind its derived key to the wrapped data key and signing seed.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NestedProtection {
    factor: FactorParameters,
    encryption_algorithm: crate::EncryptionAlgorithm,
    data_key_nonce: [u8; crate::crypto::NONCE_BYTES],
    signing_seed_nonce: [u8; crate::crypto::NONCE_BYTES],
}

impl NestedProtection {
    #[allow(dead_code)]
    pub(super) const fn kind(&self) -> NestedFactorKind {
        self.factor.kind()
    }

    pub(super) fn validate(&self) -> VaultResult<()> {
        if !crate::crypto::supports_algorithm(self.encryption_algorithm) {
            return Err(VaultError::Protection(
                "unsupported nested-factor encryption algorithm".to_owned(),
            ));
        }
        validate_factor_parameters(&self.factor)
    }
}

/// Which nested factor a vault requires in addition to its platform
/// hardware key. Exactly one is always required.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum NestedFactorKind {
    /// A PBKDF2-HMAC-SHA-256-derived Factorseal password.
    Pbkdf2HmacSha256Password,
}

impl NestedFactorKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pbkdf2HmacSha256Password => "pbkdf2-hmac-sha256-password",
        }
    }
}

impl std::fmt::Display for NestedFactorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The secret material supplied by the caller to satisfy the nested factor.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum UnsealFactor<'a> {
    /// A Factorseal password stretched with PBKDF2-HMAC-SHA-256.
    Password(&'a [u8]),
}

impl UnsealFactor<'_> {
    #[must_use]
    pub const fn kind(&self) -> NestedFactorKind {
        match self {
            Self::Password(_) => NestedFactorKind::Pbkdf2HmacSha256Password,
        }
    }
}

impl std::fmt::Debug for UnsealFactor<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnsealFactor")
            .field("kind", &self.kind())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

#[cfg(feature = "key-protection")]
pub(super) fn protect_with_factor(
    vault_id: VaultId,
    data_key: &[u8; KEY_BYTES],
    signing_seed: &[u8; SIGNING_SEED_BYTES],
    factor: UnsealFactor<'_>,
) -> VaultResult<ProtectedKeyPayloads> {
    let parameters = new_factor_parameters(factor)?;
    let factor_key = derive_factor_key(factor, &parameters)?;
    let data = crate::crypto::encrypt(
        &factor_key,
        &factor_aad(vault_id, b"data-encryption-key"),
        data_key,
    )
    .map_err(|_| VaultError::Crypto)?;
    let signing = crate::crypto::encrypt(
        &factor_key,
        &factor_aad(vault_id, b"device-signing-seed"),
        signing_seed,
    )
    .map_err(|_| VaultError::Crypto)?;
    debug_assert_eq!(data.algorithm, signing.algorithm);
    Ok((
        Zeroizing::new(data.ciphertext),
        Zeroizing::new(signing.ciphertext),
        NestedProtection {
            factor: parameters,
            encryption_algorithm: data.algorithm,
            data_key_nonce: data.nonce,
            signing_seed_nonce: signing.nonce,
        },
    ))
}

#[cfg(feature = "key-protection")]
fn new_factor_parameters(factor: UnsealFactor<'_>) -> VaultResult<FactorParameters> {
    match factor {
        UnsealFactor::Password(password) => {
            if password.is_empty() {
                return Err(factor_empty_error(factor.kind()));
            }
            let mut salt = [0_u8; SALT_BYTES];
            getrandom::fill(&mut salt)?;
            Ok(FactorParameters::Pbkdf2HmacSha256 {
                iterations: PBKDF2_ITERATIONS,
                salt,
            })
        }
    }
}

#[cfg(feature = "key-protection")]
pub(super) fn unprotect_with_factor(
    vault_id: VaultId,
    protection: &NestedProtection,
    data_key_payload: &Zeroizing<Vec<u8>>,
    signing_seed_payload: &Zeroizing<Vec<u8>>,
    factor: UnsealFactor<'_>,
) -> VaultResult<UnsealedVaultKeys> {
    let factor_key = derive_factor_key(factor, &protection.factor)?;
    let data_key = crate::crypto::decrypt(
        protection.encryption_algorithm,
        &factor_key,
        &protection.data_key_nonce,
        &factor_aad(vault_id, b"data-encryption-key"),
        data_key_payload,
    )
    .map_err(|_| factor_incorrect_error(protection.factor.kind()))?;
    let signing_seed = crate::crypto::decrypt(
        protection.encryption_algorithm,
        &factor_key,
        &protection.signing_seed_nonce,
        &factor_aad(vault_id, b"device-signing-seed"),
        signing_seed_payload,
    )
    .map_err(|_| factor_incorrect_error(protection.factor.kind()))?;
    Ok((
        decode_key::<KEY_BYTES>(&data_key, "data-encryption key")?,
        decode_key::<SIGNING_SEED_BYTES>(&signing_seed, "device-signing seed")?,
    ))
}

/// Derive the nested factor's key. The supplied factor must match the one the
/// vault recorded; a mismatch is rejected rather than silently ignored.
#[cfg(feature = "key-protection")]
fn derive_factor_key(
    factor: UnsealFactor<'_>,
    parameters: &FactorParameters,
) -> VaultResult<Zeroizing<[u8; KEY_BYTES]>> {
    validate_factor_parameters(parameters)?;
    if factor.kind() != parameters.kind() {
        return Err(VaultError::Protection(format!(
            "this vault requires the {} factor",
            parameters.kind()
        )));
    }
    match (factor, parameters) {
        (
            UnsealFactor::Password(password),
            FactorParameters::Pbkdf2HmacSha256 { iterations, salt },
        ) => {
            if password.is_empty() {
                return Err(factor_empty_error(factor.kind()));
            }
            Ok(crate::crypto::derive_password_key(
                password,
                salt,
                *iterations,
            ))
        }
    }
}

fn validate_factor_parameters(parameters: &FactorParameters) -> VaultResult<()> {
    let FactorParameters::Pbkdf2HmacSha256 { iterations, .. } = parameters;
    if !(MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(iterations) {
        return Err(VaultError::Protection(
            "unsupported or unsafe nested-factor parameters".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(feature = "key-protection")]
fn factor_aad(vault_id: VaultId, purpose: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + purpose.len());
    aad.extend_from_slice(b"factorseal/vault-factor/v2\0");
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(&(purpose.len() as u64).to_be_bytes());
    aad.extend_from_slice(purpose);
    aad
}

#[cfg(feature = "key-protection")]
fn factor_incorrect_error(kind: NestedFactorKind) -> VaultError {
    VaultError::Protection(format!(
        "the {kind} factor is incorrect or vault metadata was modified"
    ))
}

#[cfg(feature = "key-protection")]
fn factor_empty_error(kind: NestedFactorKind) -> VaultError {
    VaultError::Protection(format!("the {kind} factor must not be empty"))
}
#[cfg(feature = "key-protection")]
pub(super) fn decode_key<const LENGTH: usize>(
    plaintext: &Zeroizing<Vec<u8>>,
    name: &'static str,
) -> VaultResult<Zeroizing<[u8; LENGTH]>> {
    let length = plaintext.len();
    let bytes: [u8; LENGTH] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Protection(format!("unwrapped {name} has {length} bytes")))?;
    Ok(Zeroizing::new(bytes))
}

#[cfg(all(test, feature = "key-protection"))]
mod tests {
    use super::*;

    const VAULT_ID: VaultId = VaultId::from_bytes([7; 16]);
    const DATA_KEY: [u8; KEY_BYTES] = [3; KEY_BYTES];
    const SIGNING_SEED: [u8; SIGNING_SEED_BYTES] = [9; SIGNING_SEED_BYTES];

    #[test]
    fn protected_keys_require_the_original_factor_and_vault() {
        let (data_payload, signing_payload, protection) = protect_with_factor(
            VAULT_ID,
            &DATA_KEY,
            &SIGNING_SEED,
            UnsealFactor::Password(b"correct horse"),
        )
        .unwrap();

        let (data_key, signing_seed) = unprotect_with_factor(
            VAULT_ID,
            &protection,
            &data_payload,
            &signing_payload,
            UnsealFactor::Password(b"correct horse"),
        )
        .unwrap();
        assert_eq!(*data_key, DATA_KEY);
        assert_eq!(*signing_seed, SIGNING_SEED);

        assert!(matches!(
            unprotect_with_factor(
                VAULT_ID,
                &protection,
                &data_payload,
                &signing_payload,
                UnsealFactor::Password(b"wrong factor"),
            ),
            Err(VaultError::Protection(_))
        ));
        assert!(matches!(
            unprotect_with_factor(
                VaultId::from_bytes([8; 16]),
                &protection,
                &data_payload,
                &signing_payload,
                UnsealFactor::Password(b"correct horse"),
            ),
            Err(VaultError::Protection(_))
        ));
    }

    #[test]
    fn empty_factors_and_unsafe_parameters_are_rejected() {
        assert!(matches!(
            protect_with_factor(
                VAULT_ID,
                &DATA_KEY,
                &SIGNING_SEED,
                UnsealFactor::Password(b"")
            ),
            Err(VaultError::Protection(_))
        ));

        let protection = NestedProtection {
            factor: FactorParameters::Pbkdf2HmacSha256 {
                iterations: MIN_PBKDF2_ITERATIONS - 1,
                salt: [0; SALT_BYTES],
            },
            encryption_algorithm: crate::EncryptionAlgorithm::Aes256Gcm,
            data_key_nonce: [0; crate::crypto::NONCE_BYTES],
            signing_seed_nonce: [0; crate::crypto::NONCE_BYTES],
        };
        assert!(matches!(
            protection.validate(),
            Err(VaultError::Protection(_))
        ));
    }
}

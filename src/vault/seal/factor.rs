//! Nested-factor representation and cryptography for sealed vaults.

#[cfg(feature = "key-protection")]
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
#[cfg(feature = "key-protection")]
use zeroize::Zeroizing;

#[cfg(feature = "key-protection")]
use super::super::InstallationId;
use super::super::{VaultError, VaultResult};

#[cfg(feature = "key-protection")]
const KEY_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
#[cfg(all(feature = "key-protection", not(test)))]
const ARGON2_MEMORY_KIB: u32 = 128 * 1024;
#[cfg(all(feature = "key-protection", test))]
const ARGON2_MEMORY_KIB: u32 = 8 * 1024;
#[cfg(all(feature = "key-protection", not(test)))]
const ARGON2_ITERATIONS: u32 = 3;
#[cfg(all(feature = "key-protection", test))]
const ARGON2_ITERATIONS: u32 = 1;
#[cfg(feature = "key-protection")]
const ARGON2_PARALLELISM: u32 = 1;
const MAX_ARGON2_MEMORY_KIB: u32 = 256 * 1024;
const MAX_ARGON2_ITERATIONS: u32 = 10;
const MAX_ARGON2_PARALLELISM: u32 = 16;
#[cfg(all(feature = "key-protection", not(test)))]
const PBKDF2_ITERATIONS: u32 = 600_000;
#[cfg(all(feature = "key-protection", test))]
const PBKDF2_ITERATIONS: u32 = 1_000;
const MIN_PBKDF2_ITERATIONS: u32 = 1_000;
const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;
#[cfg(feature = "key-protection")]
pub(super) type ProtectedKeyPayload = (Zeroizing<Vec<u8>>, NestedProtection);

/// Parameters of the secret-bearing factor nested inside the platform
/// hardware wrapping.
///
/// The default Argon2id variant is memory hard. The FIPS profile uses PBKDF2
/// with a NIST-approved hash. A password remains entropy-limited under either
/// profile: stretching raises offline-guessing cost but cannot turn a
/// human-memorable password into a post-quantum-strength factor.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "algorithm", rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
enum FactorParameters {
    Argon2id {
        version: u32,
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        salt: [u8; SALT_BYTES],
    },
    Pbkdf2HmacSha256 {
        iterations: u32,
        salt: [u8; SALT_BYTES],
    },
}

impl FactorParameters {
    const fn kind(&self) -> NestedFactorKind {
        match self {
            Self::Argon2id { .. } => NestedFactorKind::Argon2idPassword,
            Self::Pbkdf2HmacSha256 { .. } => NestedFactorKind::Pbkdf2HmacSha256Password,
        }
    }
}

/// The nested factor recorded for an installation, with the nonce that binds
/// its derived key to the wrapped root key.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NestedProtection {
    factor: FactorParameters,
    encryption_algorithm: crate::EncryptionAlgorithm,
    vault_root_key_nonce: [u8; crate::algorithm::AES_GCM_NONCE_BYTES],
}

impl NestedProtection {
    #[allow(dead_code)]
    pub(super) const fn kind(&self) -> NestedFactorKind {
        self.factor.kind()
    }

    pub(super) fn validate(&self) -> VaultResult<()> {
        #[cfg(any(feature = "key-protection", feature = "vault-store"))]
        if !crate::crypto::supports_algorithm(self.encryption_algorithm) {
            return Err(VaultError::Protection(
                "unsupported nested-factor encryption algorithm".to_owned(),
            ));
        }
        validate_factor_parameters(&self.factor)
    }

    pub(super) const fn matches_profile(&self, profile: super::VaultCryptoProfile) -> bool {
        matches!(
            (&self.factor, profile),
            (
                FactorParameters::Argon2id { .. },
                super::VaultCryptoProfile::Default
            ) | (
                FactorParameters::Pbkdf2HmacSha256 { .. },
                super::VaultCryptoProfile::Fips
            )
        )
    }
}

/// Password input or persisted password-derivation kind used in addition to a
/// platform hardware key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum NestedFactorKind {
    /// A password input before the vault's recorded KDF is known.
    Password,
    /// An Argon2id-derived Factorseal password.
    Argon2idPassword,
    /// A PBKDF2-HMAC-SHA-256-derived Factorseal password.
    Pbkdf2HmacSha256Password,
}

impl NestedFactorKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Argon2idPassword => "argon2id-password",
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
    /// A Factorseal password stretched with the KDF recorded by the vault.
    Password(&'a [u8]),
}

impl UnsealFactor<'_> {
    #[must_use]
    pub const fn kind(&self) -> NestedFactorKind {
        match self {
            Self::Password(_) => NestedFactorKind::Password,
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
    installation_id: InstallationId,
    vault_root_key: &[u8; KEY_BYTES],
    factor: UnsealFactor<'_>,
    profile: super::VaultCryptoProfile,
) -> VaultResult<ProtectedKeyPayload> {
    let parameters = new_factor_parameters(factor, profile)?;
    let factor_key = derive_factor_key(factor, &parameters)?;
    let root = crate::crypto::encrypt(
        &factor_key,
        &factor_aad(installation_id, b"vault-root-key"),
        vault_root_key,
    )
    .map_err(|_| VaultError::Crypto)?;
    Ok((
        Zeroizing::new(root.ciphertext),
        NestedProtection {
            factor: parameters,
            encryption_algorithm: root.algorithm,
            vault_root_key_nonce: root.nonce,
        },
    ))
}

#[cfg(feature = "key-protection")]
fn new_factor_parameters(
    factor: UnsealFactor<'_>,
    profile: super::VaultCryptoProfile,
) -> VaultResult<FactorParameters> {
    match factor {
        UnsealFactor::Password(password) => {
            if password.is_empty() {
                return Err(factor_empty_error(match profile {
                    super::VaultCryptoProfile::Default => NestedFactorKind::Argon2idPassword,
                    super::VaultCryptoProfile::Fips => NestedFactorKind::Pbkdf2HmacSha256Password,
                }));
            }
            let mut salt = [0_u8; SALT_BYTES];
            getrandom::fill(&mut salt)?;
            Ok(match profile {
                super::VaultCryptoProfile::Default => FactorParameters::Argon2id {
                    version: 0x13,
                    memory_kib: ARGON2_MEMORY_KIB,
                    iterations: ARGON2_ITERATIONS,
                    parallelism: ARGON2_PARALLELISM,
                    salt,
                },
                super::VaultCryptoProfile::Fips => FactorParameters::Pbkdf2HmacSha256 {
                    iterations: PBKDF2_ITERATIONS,
                    salt,
                },
            })
        }
    }
}

#[cfg(feature = "key-protection")]
pub(super) fn unprotect_with_factor(
    installation_id: InstallationId,
    protection: &NestedProtection,
    vault_root_key_payload: &Zeroizing<Vec<u8>>,
    factor: UnsealFactor<'_>,
) -> VaultResult<Zeroizing<[u8; KEY_BYTES]>> {
    let factor_key = derive_factor_key(factor, &protection.factor)?;
    let vault_root_key = crate::crypto::decrypt(
        protection.encryption_algorithm,
        &factor_key,
        &protection.vault_root_key_nonce,
        &factor_aad(installation_id, b"vault-root-key"),
        vault_root_key_payload,
    )
    .map_err(|_| factor_incorrect_error(protection.factor.kind()))?;
    decode_key::<KEY_BYTES>(&vault_root_key, "vault root key")
}

/// Derive the nested factor's key. The supplied factor must match the one the
/// vault recorded.
#[cfg(feature = "key-protection")]
fn derive_factor_key(
    factor: UnsealFactor<'_>,
    parameters: &FactorParameters,
) -> VaultResult<Zeroizing<[u8; KEY_BYTES]>> {
    validate_factor_parameters(parameters)?;
    match (factor, parameters) {
        (
            UnsealFactor::Password(password),
            FactorParameters::Argon2id {
                memory_kib,
                iterations,
                parallelism,
                salt,
                ..
            },
        ) => {
            if password.is_empty() {
                return Err(factor_empty_error(parameters.kind()));
            }
            let params = Params::new(*memory_kib, *iterations, *parallelism, Some(KEY_BYTES))
                .map_err(|error| {
                    VaultError::Protection(format!("invalid Argon2 parameters: {error}"))
                })?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
            argon2
                .hash_password_into(password, salt, &mut *key)
                .map_err(|error| {
                    VaultError::Protection(format!("factor derivation failed: {error}"))
                })?;
            Ok(key)
        }
        (
            UnsealFactor::Password(password),
            FactorParameters::Pbkdf2HmacSha256 { iterations, salt },
        ) => {
            if password.is_empty() {
                return Err(factor_empty_error(parameters.kind()));
            }
            Ok(crate::crypto::derive_pbkdf2_password_key(
                password,
                salt,
                *iterations,
            ))
        }
    }
}

fn validate_factor_parameters(parameters: &FactorParameters) -> VaultResult<()> {
    let valid = match parameters {
        FactorParameters::Argon2id {
            version,
            memory_kib,
            iterations,
            parallelism,
            ..
        } => {
            *version == 0x13
                && (8 * 1024..=MAX_ARGON2_MEMORY_KIB).contains(memory_kib)
                && (1..=MAX_ARGON2_ITERATIONS).contains(iterations)
                && (1..=MAX_ARGON2_PARALLELISM).contains(parallelism)
        }
        FactorParameters::Pbkdf2HmacSha256 { iterations, .. } => {
            (MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(iterations)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(VaultError::Protection(
            "unsupported or unsafe nested-factor parameters".to_owned(),
        ))
    }
}

#[cfg(feature = "key-protection")]
fn factor_aad(installation_id: InstallationId, purpose: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + purpose.len());
    aad.extend_from_slice(b"factorseal/vault-factor/v2\0");
    aad.extend_from_slice(installation_id.as_bytes());
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
    if length != LENGTH {
        return Err(VaultError::Protection(format!(
            "unwrapped {name} has {length} bytes"
        )));
    }
    let mut bytes = Zeroizing::new([0_u8; LENGTH]);
    bytes.copy_from_slice(plaintext);
    Ok(bytes)
}

#[cfg(all(test, feature = "key-protection"))]
mod tests {
    use super::*;

    const INSTALLATION_ID: InstallationId = InstallationId::from_bytes([7; 16]);
    const VAULT_ROOT_KEY: [u8; KEY_BYTES] = [3; KEY_BYTES];

    #[test]
    fn profiles_select_their_recorded_password_kdf() {
        for (profile, expected_kind) in [
            (
                super::super::VaultCryptoProfile::Default,
                NestedFactorKind::Argon2idPassword,
            ),
            (
                super::super::VaultCryptoProfile::Fips,
                NestedFactorKind::Pbkdf2HmacSha256Password,
            ),
        ] {
            let (payload, protection) = protect_with_factor(
                INSTALLATION_ID,
                &VAULT_ROOT_KEY,
                UnsealFactor::Password(b"correct horse"),
                profile,
            )
            .unwrap();
            assert_eq!(protection.kind(), expected_kind);
            assert!(protection.matches_profile(profile));

            let root_key = unprotect_with_factor(
                INSTALLATION_ID,
                &protection,
                &payload,
                UnsealFactor::Password(b"correct horse"),
            )
            .unwrap();
            assert_eq!(*root_key, VAULT_ROOT_KEY);
        }
    }

    #[test]
    fn protected_keys_require_the_original_factor_and_installation() {
        let (payload, protection) = protect_with_factor(
            INSTALLATION_ID,
            &VAULT_ROOT_KEY,
            UnsealFactor::Password(b"correct horse"),
            super::super::VaultCryptoProfile::Default,
        )
        .unwrap();

        let root_key = unprotect_with_factor(
            INSTALLATION_ID,
            &protection,
            &payload,
            UnsealFactor::Password(b"correct horse"),
        )
        .unwrap();
        assert_eq!(*root_key, VAULT_ROOT_KEY);

        assert!(matches!(
            unprotect_with_factor(
                INSTALLATION_ID,
                &protection,
                &payload,
                UnsealFactor::Password(b"wrong factor"),
            ),
            Err(VaultError::Protection(_))
        ));
        assert!(matches!(
            unprotect_with_factor(
                InstallationId::from_bytes([8; 16]),
                &protection,
                &payload,
                UnsealFactor::Password(b"correct horse"),
            ),
            Err(VaultError::Protection(_))
        ));
    }

    #[test]
    fn empty_factors_and_unsafe_parameters_are_rejected() {
        assert!(matches!(
            protect_with_factor(
                INSTALLATION_ID,
                &VAULT_ROOT_KEY,
                UnsealFactor::Password(b""),
                super::super::VaultCryptoProfile::Default,
            ),
            Err(VaultError::Protection(_))
        ));

        let protection = NestedProtection {
            factor: FactorParameters::Pbkdf2HmacSha256 {
                iterations: MIN_PBKDF2_ITERATIONS - 1,
                salt: [0; SALT_BYTES],
            },
            encryption_algorithm: crate::EncryptionAlgorithm::Aes256Gcm,
            vault_root_key_nonce: [0; crate::algorithm::AES_GCM_NONCE_BYTES],
        };
        assert!(matches!(
            protection.validate(),
            Err(VaultError::Protection(_))
        ));

        let protection = NestedProtection {
            factor: FactorParameters::Argon2id {
                version: 0x13,
                memory_kib: 8 * 1024 - 1,
                iterations: 1,
                parallelism: 1,
                salt: [0; SALT_BYTES],
            },
            encryption_algorithm: crate::EncryptionAlgorithm::Aes256Gcm,
            vault_root_key_nonce: [0; crate::algorithm::AES_GCM_NONCE_BYTES],
        };
        assert!(matches!(
            protection.validate(),
            Err(VaultError::Protection(_))
        ));
    }
}

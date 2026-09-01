//! Symmetric cryptography provider boundary for durable and bootstrap data.
//!
//! The default provider uses RustCrypto. Keeping every vault AEAD call behind
//! this interface makes the implementation replaceable by a CMVP-validated
//! provider without changing the persisted algorithm contract.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
#[cfg(feature = "key-protection")]
use pbkdf2::pbkdf2_hmac;
#[cfg(feature = "key-protection")]
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{EncryptionAlgorithm, Error, Result};

pub(crate) const KEY_BYTES: usize = 32;
pub(crate) const NONCE_BYTES: usize = crate::algorithm::AES_GCM_NONCE_BYTES;

pub(crate) const CURRENT_ENCRYPTION_ALGORITHM: EncryptionAlgorithm = EncryptionAlgorithm::Aes256Gcm;

pub(crate) struct EncryptedPayload {
    pub(crate) algorithm: EncryptionAlgorithm,
    pub(crate) nonce: [u8; NONCE_BYTES],
    pub(crate) ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct AuthenticationError;

trait CryptoProvider: Sync {
    fn algorithm(&self) -> EncryptionAlgorithm;

    fn encrypt(
        &self,
        key: &[u8; KEY_BYTES],
        nonce: &[u8; NONCE_BYTES],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>>;

    fn decrypt(
        &self,
        key: &[u8; KEY_BYTES],
        nonce: &[u8; NONCE_BYTES],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> std::result::Result<Zeroizing<Vec<u8>>, AuthenticationError>;

    #[cfg(feature = "key-protection")]
    fn derive_pbkdf2_password_key(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Zeroizing<[u8; KEY_BYTES]>;
}

struct RustCryptoAes256Gcm;

impl CryptoProvider for RustCryptoAes256Gcm {
    fn algorithm(&self) -> EncryptionAlgorithm {
        EncryptionAlgorithm::Aes256Gcm
    }

    fn encrypt(
        &self,
        key: &[u8; KEY_BYTES],
        nonce: &[u8; NONCE_BYTES],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        Aes256Gcm::new(key.into())
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Authentication)
    }

    fn decrypt(
        &self,
        key: &[u8; KEY_BYTES],
        nonce: &[u8; NONCE_BYTES],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> std::result::Result<Zeroizing<Vec<u8>>, AuthenticationError> {
        Aes256Gcm::new(key.into())
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| AuthenticationError)
    }

    #[cfg(feature = "key-protection")]
    fn derive_pbkdf2_password_key(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Zeroizing<[u8; KEY_BYTES]> {
        let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
        pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut *key);
        key
    }
}

static DEFAULT_PROVIDER: RustCryptoAes256Gcm = RustCryptoAes256Gcm;

fn provider_for(
    algorithm: EncryptionAlgorithm,
) -> std::result::Result<&'static dyn CryptoProvider, AuthenticationError> {
    if algorithm == DEFAULT_PROVIDER.algorithm() {
        Ok(&DEFAULT_PROVIDER)
    } else {
        Err(AuthenticationError)
    }
}

#[cfg(feature = "key-protection")]
pub(crate) fn derive_pbkdf2_password_key(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Zeroizing<[u8; KEY_BYTES]> {
    DEFAULT_PROVIDER.derive_pbkdf2_password_key(password, salt, iterations)
}

pub(crate) fn supports_algorithm(algorithm: EncryptionAlgorithm) -> bool {
    provider_for(algorithm).is_ok()
}

pub(crate) fn encrypt(
    key: &[u8; KEY_BYTES],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<EncryptedPayload> {
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce)?;
    let provider = &DEFAULT_PROVIDER;
    let ciphertext = provider.encrypt(key, &nonce, aad, plaintext)?;
    Ok(EncryptedPayload {
        algorithm: provider.algorithm(),
        nonce,
        ciphertext,
    })
}

pub(crate) fn decrypt(
    algorithm: EncryptionAlgorithm,
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    ciphertext: &[u8],
) -> std::result::Result<Zeroizing<Vec<u8>>, AuthenticationError> {
    provider_for(algorithm)?.decrypt(key, nonce, aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_payload_round_trips_and_authenticates_aad() {
        let key = [0x2a; KEY_BYTES];
        let encrypted = encrypt(&key, b"expected context", b"sensitive value").unwrap();

        assert_eq!(
            decrypt(
                encrypted.algorithm,
                &key,
                &encrypted.nonce,
                b"expected context",
                &encrypted.ciphertext,
            )
            .unwrap()
            .as_slice(),
            b"sensitive value"
        );
        assert!(
            decrypt(
                encrypted.algorithm,
                &key,
                &encrypted.nonce,
                b"different context",
                &encrypted.ciphertext,
            )
            .is_err()
        );
    }

    #[test]
    fn encryption_uses_a_fresh_nonce() {
        let key = [0x2a; KEY_BYTES];
        let first = encrypt(&key, b"context", b"same value").unwrap();
        let second = encrypt(&key, b"context", b"same value").unwrap();

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
        assert_eq!(first.algorithm, EncryptionAlgorithm::Aes256Gcm);
    }

    #[test]
    fn aes256_gcm_matches_nist_known_answer() {
        let key = [0_u8; KEY_BYTES];
        let nonce = [0_u8; NONCE_BYTES];
        let ciphertext = DEFAULT_PROVIDER
            .encrypt(&key, &nonce, b"", &[0_u8; 16])
            .unwrap();

        assert_eq!(
            hex::encode(ciphertext),
            concat!(
                "cea7403d4d606b6e074ec5d3baf39d18",
                "d0d1c8a799996bf0265b98b5d48ab919"
            )
        );
    }

    #[cfg(feature = "key-protection")]
    #[test]
    fn pbkdf2_hmac_sha256_matches_known_answer() {
        let output = derive_pbkdf2_password_key(b"password", b"salt", 1);
        assert_eq!(
            hex::encode(output.as_slice()),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }
}

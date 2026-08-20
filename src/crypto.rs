use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use zeroize::Zeroizing;

use crate::{Error, Result};

pub(crate) const KEY_BYTES: usize = 32;
pub(crate) const NONCE_BYTES: usize = 24;

pub(crate) struct EncryptedPayload {
    pub(crate) nonce: [u8; NONCE_BYTES],
    pub(crate) ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct AuthenticationError;

pub(crate) fn encrypt(
    key: &[u8; KEY_BYTES],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<EncryptedPayload> {
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Authentication)?;
    Ok(EncryptedPayload { nonce, ciphertext })
}

pub(crate) fn decrypt(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    ciphertext: &[u8],
) -> std::result::Result<Zeroizing<Vec<u8>>, AuthenticationError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| AuthenticationError)
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
    }
}

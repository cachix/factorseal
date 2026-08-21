//! Pure-Rust implementation of the Secret Service session wire protocol.
//!
//! This crate implements the algorithms named by the freedesktop Secret
//! Service specification. It deliberately has no D-Bus, storage, or policy
//! dependency: a service adapts [`SessionOutput`] and [`EncryptedPayload`] to
//! its own wire types.

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

/// The unencrypted Secret Service session algorithm.
pub const ALGORITHM_PLAIN: &str = "plain";
/// The standard Secret Service DH/AES-CBC session algorithm.
pub const ALGORITHM_DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

const AES_KEY_BYTES: usize = 16;
const AES_BLOCK_BYTES: usize = 16;
const DH_BYTES: usize = 128;
const DH_PRIME_BYTES: [u8; DH_BYTES] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Reply payload for an `OpenSession` call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionOutput {
    /// The D-Bus reply is an empty string variant.
    Plain,
    /// The D-Bus reply is the server's 1024-bit DH public key byte array.
    DhPublicKey(Vec<u8>),
}

/// A Secret Service secret payload after session encryption.
#[derive(Clone)]
pub struct EncryptedPayload {
    /// Empty for plain sessions; a fresh AES-CBC IV for DH sessions.
    pub parameters: Vec<u8>,
    /// The plaintext or encrypted payload. It is wiped when dropped.
    pub value: Zeroizing<Vec<u8>>,
}

/// An error returned while negotiating or using a session.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("unsupported Secret Service session algorithm `{0}")]
    UnsupportedAlgorithm(String),
    #[error("invalid Secret Service DH public key")]
    InvalidDhPublicKey,
    #[error("invalid Secret Service AES initialization vector")]
    InvalidInitializationVector,
    #[error("invalid encrypted Secret Service payload")]
    InvalidCiphertext,
    #[error("randomness unavailable: {0}")]
    Randomness(String),
}

impl From<getrandom::Error> for ProtocolError {
    fn from(error: getrandom::Error) -> Self {
        Self::Randomness(error.to_string())
    }
}

/// One negotiated session. Key material is zeroized when dropped.
#[derive(Clone)]
pub struct Session {
    key: Option<Zeroizing<[u8; AES_KEY_BYTES]>>,
}

impl Session {
    /// Negotiate a server-side Secret Service session.
    pub fn open(algorithm: &str, input: &[u8]) -> Result<(Self, SessionOutput), ProtocolError> {
        match algorithm {
            ALGORITHM_PLAIN if input.is_empty() => Ok((Self { key: None }, SessionOutput::Plain)),
            ALGORITHM_PLAIN => Err(ProtocolError::InvalidDhPublicKey),
            ALGORITHM_DH => Self::open_dh(input),
            other => Err(ProtocolError::UnsupportedAlgorithm(other.to_owned())),
        }
    }

    /// Encrypt a payload for this session.
    pub fn encrypt(&self, value: &[u8]) -> Result<EncryptedPayload, ProtocolError> {
        let Some(key) = &self.key else {
            return Ok(EncryptedPayload {
                parameters: Vec::new(),
                value: Zeroizing::new(value.to_vec()),
            });
        };
        let mut iv = [0_u8; AES_BLOCK_BYTES];
        getrandom::fill(&mut iv)?;
        let value = cbc::Encryptor::<aes::Aes128>::new(key.as_ref().into(), (&iv).into())
            .encrypt_padded_vec_mut::<Pkcs7>(value);
        Ok(EncryptedPayload {
            parameters: iv.to_vec(),
            value: Zeroizing::new(value),
        })
    }

    /// Decrypt a payload from this session.
    pub fn decrypt(
        &self,
        parameters: &[u8],
        value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let Some(key) = &self.key else {
            if parameters.is_empty() {
                return Ok(Zeroizing::new(value.to_vec()));
            }
            return Err(ProtocolError::InvalidInitializationVector);
        };
        if parameters.len() != AES_BLOCK_BYTES {
            return Err(ProtocolError::InvalidInitializationVector);
        }
        cbc::Decryptor::<aes::Aes128>::new(key.as_ref().into(), parameters.into())
            .decrypt_padded_vec_mut::<Pkcs7>(value)
            .map(Zeroizing::new)
            .map_err(|_| ProtocolError::InvalidCiphertext)
    }

    fn open_dh(input: &[u8]) -> Result<(Self, SessionOutput), ProtocolError> {
        let prime = BigUint::from_bytes_be(&DH_PRIME_BYTES);
        let client_public = BigUint::from_bytes_be(input);
        let generator = BigUint::from(2_u8);
        if client_public < generator || client_public > &prime - &generator {
            return Err(ProtocolError::InvalidDhPublicKey);
        }
        let mut private_bytes = Zeroizing::new([0_u8; DH_BYTES]);
        getrandom::fill(&mut *private_bytes)?;
        let private = BigUint::from_bytes_be(&*private_bytes);
        let server_public = generator.modpow(&private, &prime);
        let shared = client_public.modpow(&private, &prime);
        let shared = pad_dh_value(&shared)?;
        let mut key = Zeroizing::new([0_u8; AES_KEY_BYTES]);
        Hkdf::<Sha256>::new(None, &shared)
            .expand(&[], &mut *key)
            .expect("AES-128 key length is valid");
        Ok((
            Self { key: Some(key) },
            SessionOutput::DhPublicKey(pad_dh_value(&server_public)?),
        ))
    }
}

fn pad_dh_value(value: &BigUint) -> Result<Vec<u8>, ProtocolError> {
    let value = value.to_bytes_be();
    if value.len() > DH_BYTES {
        return Err(ProtocolError::InvalidDhPublicKey);
    }
    let mut padded = vec![0_u8; DH_BYTES - value.len()];
    padded.extend(value);
    Ok(padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_session_round_trips_and_interoperates_with_client_derivation() {
        let prime = BigUint::from_bytes_be(&DH_PRIME_BYTES);
        let generator = BigUint::from(2_u8);
        let private = BigUint::from(42_u8);
        let public = generator.modpow(&private, &prime);
        let (session, SessionOutput::DhPublicKey(server_public)) =
            Session::open(ALGORITHM_DH, &pad_dh_value(&public).unwrap()).unwrap()
        else {
            panic!("expected DH output");
        };
        let shared = BigUint::from_bytes_be(&server_public).modpow(&private, &prime);
        let mut client_key = [0_u8; AES_KEY_BYTES];
        Hkdf::<Sha256>::new(None, &pad_dh_value(&shared).unwrap())
            .expand(&[], &mut client_key)
            .unwrap();
        let encrypted = session.encrypt(b"secret").unwrap();
        let plain = cbc::Decryptor::<aes::Aes128>::new(
            (&client_key).into(),
            encrypted.parameters.as_slice().into(),
        )
        .decrypt_padded_vec_mut::<Pkcs7>(&encrypted.value)
        .unwrap();
        assert_eq!(plain, b"secret");
        assert_eq!(
            session
                .decrypt(&encrypted.parameters, &encrypted.value)
                .unwrap()
                .as_slice(),
            b"secret"
        );
    }
}

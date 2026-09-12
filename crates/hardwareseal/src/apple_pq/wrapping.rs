//! Experimental ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM local wrapping.
//!
//! This is an opt-in prototype, not the default Apple Keychain protector.
//! Envelopes authenticate the label, access policy, native key reference, KEM
//! encapsulation and nonce. Native decapsulation enforces the key's actual ACL.

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{call, split_output, validate_reference};
use crate::{AccessPolicy, Error, MAX_PAYLOAD_BYTES};

const MAGIC: &[u8; 8] = b"HSPQKEM1";
const KEM_PUBLIC_BYTES: usize = 1184;
const ENCAPSULATION_BYTES: usize = 1088;
const NONCE_BYTES: usize = 12;
const LABEL_BYTES: usize = 32;
const PREFIX_BYTES: usize = MAGIC.len() + 1 + LABEL_BYTES + 4;
const DOMAIN: &[u8] = b"hardwareseal/apple-mlkem768-wrap/v1\0";

/// Device-bound key owned by this prototype. Its opaque reference is included
/// in each sealed envelope, so reopening never generates or substitutes a key.
pub struct MlKem768WrappingKey {
    reference: Zeroizing<Vec<u8>>,
    public_key: Vec<u8>,
    policy: AccessPolicy,
}

impl MlKem768WrappingKey {
    pub fn generate(policy: AccessPolicy) -> Result<Self, Error> {
        let output = call(4, &[], &[], policy)?;
        let (reference, public_key) = split_output(&output, KEM_PUBLIC_BYTES)?;
        Ok(Self {
            reference: Zeroizing::new(reference.to_vec()),
            public_key: public_key.to_vec(),
            policy,
        })
    }

    pub fn seal(&self, label: &str, secret: &[u8]) -> Result<Vec<u8>, Error> {
        if secret.len() > MAX_PAYLOAD_BYTES {
            return Err(invalid("payload exceeds sealing limit"));
        }
        let encapsulated = call(5, &self.public_key, &[], AccessPolicy::None)?;
        let (encapsulation, shared) = split_output(&encapsulated, 32)?;
        if encapsulation.len() != ENCAPSULATION_BYTES {
            return Err(invalid("invalid ML-KEM encapsulation"));
        }
        let mut nonce = [0; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|error| Error::Hardware(error.to_string()))?;
        let mut header = header(label, self.policy, &self.reference, encapsulation, &nonce)?;
        let key = derive(shared, &header)?;
        let ciphertext = Aes256Gcm::new((&*key).into())
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: &header,
                },
            )
            .map_err(|_| Error::Hardware("ML-KEM wrapping encryption failed".into()))?;
        header.extend_from_slice(&ciphertext);
        Ok(header)
    }

    pub fn unseal(
        label: &str,
        policy: AccessPolicy,
        envelope: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let parsed = parse(label, policy, envelope)?;
        let shared = call(
            6,
            parsed.reference,
            parsed.encapsulation,
            AccessPolicy::None,
        )?;
        let key = derive(&shared, parsed.header)?;
        Aes256Gcm::new((&*key).into())
            .decrypt(
                Nonce::from_slice(parsed.nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: parsed.header,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| invalid("cannot authenticate ML-KEM envelope"))
    }
}

fn header(
    label: &str,
    policy: AccessPolicy,
    reference: &[u8],
    encapsulation: &[u8],
    nonce: &[u8; NONCE_BYTES],
) -> Result<Vec<u8>, Error> {
    validate_reference(reference)?;
    if encapsulation.len() != ENCAPSULATION_BYTES {
        return Err(invalid("invalid encapsulation length"));
    }
    let mut bytes =
        Vec::with_capacity(PREFIX_BYTES + reference.len() + ENCAPSULATION_BYTES + NONCE_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.push(policy_id(policy));
    bytes.extend_from_slice(&label_hash(label));
    bytes.extend_from_slice(
        &u32::try_from(reference.len())
            .map_err(|_| invalid("invalid key reference"))?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(reference);
    bytes.extend_from_slice(encapsulation);
    bytes.extend_from_slice(nonce);
    Ok(bytes)
}

struct Parsed<'a> {
    header: &'a [u8],
    reference: &'a [u8],
    encapsulation: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

fn parse<'a>(label: &str, policy: AccessPolicy, bytes: &'a [u8]) -> Result<Parsed<'a>, Error> {
    if bytes.len() < PREFIX_BYTES
        || &bytes[..8] != MAGIC
        || bytes[8] != policy_id(policy)
        || bytes[9..9 + LABEL_BYTES] != label_hash(label)
    {
        return Err(invalid("ML-KEM envelope header or policy mismatch"));
    }
    let reference_length = u32::from_be_bytes(
        bytes[PREFIX_BYTES - 4..PREFIX_BYTES]
            .try_into()
            .map_err(|_| invalid("invalid reference length"))?,
    ) as usize;
    if reference_length == 0 || reference_length > super::MAX_REFERENCE_BYTES {
        return Err(invalid("invalid reference length"));
    }
    let reference_end = PREFIX_BYTES + reference_length;
    let encapsulation_end = reference_end + ENCAPSULATION_BYTES;
    let header_end = encapsulation_end + NONCE_BYTES;
    if bytes.len() < header_end + 16 || bytes.len() > header_end + 16 + MAX_PAYLOAD_BYTES {
        return Err(invalid("invalid ML-KEM envelope length"));
    }
    Ok(Parsed {
        header: &bytes[..header_end],
        reference: &bytes[PREFIX_BYTES..reference_end],
        encapsulation: &bytes[reference_end..encapsulation_end],
        nonce: &bytes[encapsulation_end..header_end],
        ciphertext: &bytes[header_end..],
    })
}

fn derive(shared: &[u8], header: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    if shared.len() != 32 {
        return Err(invalid("invalid ML-KEM shared secret"));
    }
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(&Sha256::digest(header)), shared)
        .expand(DOMAIN, &mut *key)
        .map_err(|_| invalid("cannot derive wrapping key"))?;
    Ok(key)
}

fn label_hash(label: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(label.as_bytes());
    hash.finalize().into()
}
const fn policy_id(policy: AccessPolicy) -> u8 {
    match policy {
        AccessPolicy::None => 0,
        AccessPolicy::Biometric => 1,
    }
}
fn invalid(message: &str) -> Error {
    Error::InvalidEnvelope(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    mod measurements;
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires a physical Mac with macOS 26+ Secure Enclave access"]
    fn hardware_envelopes_reopen_without_a_live_key_object() {
        let key = MlKem768WrappingKey::generate(AccessPolicy::None).unwrap();
        let envelope = key.seal("test vault", b"installation root").unwrap();
        drop(key);
        assert_eq!(
            &*MlKem768WrappingKey::unseal("test vault", AccessPolicy::None, &envelope).unwrap(),
            b"installation root"
        );
        assert!(
            MlKem768WrappingKey::unseal("another vault", AccessPolicy::None, &envelope).is_err()
        );
        let mut corrupt = envelope;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(MlKem768WrappingKey::unseal("test vault", AccessPolicy::None, &corrupt).is_err());
    }
    #[test]
    fn envelope_authentication_binds_every_component() {
        let shared = [9; 32];
        let mut bytes = header(
            "vault",
            AccessPolicy::None,
            &[3; 16],
            &[4; ENCAPSULATION_BYTES],
            &[5; NONCE_BYTES],
        )
        .unwrap();
        let key = derive(&shared, &bytes).unwrap();
        let ciphertext = Aes256Gcm::new((&*key).into())
            .encrypt(
                Nonce::from_slice(&[5; NONCE_BYTES]),
                Payload {
                    msg: b"root",
                    aad: &bytes,
                },
            )
            .unwrap();
        bytes.extend_from_slice(&ciphertext);
        let open = |input: &[u8]| -> Result<Vec<u8>, Error> {
            let p = parse("vault", AccessPolicy::None, input)?;
            let key = derive(&shared, p.header)?;
            Aes256Gcm::new((&*key).into())
                .decrypt(
                    Nonce::from_slice(p.nonce),
                    Payload {
                        msg: p.ciphertext,
                        aad: p.header,
                    },
                )
                .map_err(|_| invalid("authentication"))
        };
        assert_eq!(open(&bytes).unwrap(), b"root");
        for position in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[position] ^= 1;
            assert!(
                open(&tampered).is_err(),
                "accepted modification at {position}"
            );
        }
        assert!(parse("another vault", AccessPolicy::None, &bytes).is_err());
        assert!(parse("vault", AccessPolicy::Biometric, &bytes).is_err());
        for length in 0..bytes.len() {
            assert!(open(&bytes[..length]).is_err());
        }
        bytes.push(0);
        assert!(open(&bytes).is_err());
    }
}

//! Post-quantum device signatures for durable vault state.
//!
//! ML-DSA-65 is the FIPS 204 parameter set selected for Factorseal. It offers
//! a practical balance between signature size and security strength, without
//! relying on a quantum-vulnerable elliptic-curve signature.

#[cfg(feature = "vault-store")]
use core::convert::TryFrom;

use ml_dsa::{KeyExport, Keypair};
use ml_dsa::{KeyInit, MlDsa65, Seed, SigningKey};
#[cfg(feature = "vault-store")]
use ml_dsa::{Signature, SignatureEncoding, Verifier, VerifyingKey};

#[cfg(feature = "vault-store")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[cfg(feature = "vault-store")]
use super::{VaultError, VaultResult};

pub(crate) const SIGNING_SEED_BYTES: usize = 32;

/// Operation-only signing capability. Callers receive public keys and signatures,
/// never a provider's private key. Every provider uses pure ML-DSA-65 with an
/// empty context, preserving the existing signed transcripts and wire format.
pub(crate) trait SigningProvider {
    fn public_key(&self) -> crate::vault::VaultResult<Vec<u8>>;

    #[cfg(feature = "vault-store")]
    fn sign(&self, payload: &[u8]) -> crate::vault::VaultResult<Vec<u8>>;
}

/// Borrows a protected seed only for the lifetime of one signing operation.
pub(crate) struct SoftwareSigner<'a>(pub(crate) &'a [u8; SIGNING_SEED_BYTES]);

impl SigningProvider for SoftwareSigner<'_> {
    fn public_key(&self) -> crate::vault::VaultResult<Vec<u8>> {
        Ok(public_key_for_seed(self.0))
    }

    #[cfg(feature = "vault-store")]
    fn sign(&self, payload: &[u8]) -> VaultResult<Vec<u8>> {
        sign(self.0, payload)
    }
}

#[cfg(all(feature = "hardware", target_os = "macos"))]
pub(crate) struct EnclaveSigner(pub(crate) hardwareseal::apple_pq::MlDsa65Key);

#[cfg(all(feature = "hardware", target_os = "macos"))]
impl SigningProvider for EnclaveSigner {
    fn public_key(&self) -> crate::vault::VaultResult<Vec<u8>> {
        Ok(self.0.public_key().to_vec())
    }

    #[cfg(feature = "vault-store")]
    fn sign(&self, payload: &[u8]) -> VaultResult<Vec<u8>> {
        let signature = self
            .0
            .sign(payload)
            .map_err(|error| VaultError::Protection(error.to_string()))?;
        // Independently verify the native result against the persisted wire
        // contract before it can authorize or commit anything.
        verify(self.0.public_key(), payload, &signature)?;
        Ok(signature)
    }
}
#[cfg(feature = "vault-store")]
pub(crate) const CURRENT_SIGNATURE_ALGORITHM: SignatureAlgorithm = SignatureAlgorithm::MlDsa65;

/// Algorithm that authenticates a signed vault object.
///
/// The identifier is written into every signed transcript, so it cannot be
/// swapped without breaking verification. It is a closed enum, so an
/// unrecognized name fails to deserialize instead of selecting a weaker
/// algorithm, and there is no "none" variant to downgrade to.
///
/// ML-DSA-65 is the only variant today. The identifier is still explicit so a
/// later algorithm migration cannot silently weaken verification.
#[cfg(feature = "vault-store")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    MlDsa65,
}

#[cfg(feature = "vault-store")]
impl SignatureAlgorithm {
    /// Stable byte written into signed transcripts. Never reuse a code.
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::MlDsa65 => 2,
        }
    }
}
#[cfg(feature = "vault-store")]
const PERMISSION_SIGNATURE_DOMAIN: &[u8] = b"factorseal/permission/v1\0";

type DeviceSigningKey = SigningKey<MlDsa65>;
#[cfg(feature = "vault-store")]
type DeviceVerifyingKey = VerifyingKey<MlDsa65>;
#[cfg(feature = "vault-store")]
type DeviceSignature = Signature<MlDsa65>;

/// Reuse the public key's expanded matrix across a vault's signature checks.
#[cfg(feature = "vault-store")]
pub(crate) struct PreparedVerifyingKey(DeviceVerifyingKey);

#[cfg(feature = "vault-store")]
impl PreparedVerifyingKey {
    pub(crate) fn new(public_key: &[u8]) -> VaultResult<Self> {
        Ok(Self(DeviceVerifyingKey::new(
            &public_key.try_into().map_err(|_| VaultError::Signature)?,
        )))
    }

    pub(crate) fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> VaultResult<()> {
        match algorithm {
            SignatureAlgorithm::MlDsa65 => {
                let signature =
                    DeviceSignature::try_from(signature).map_err(|_| VaultError::Signature)?;
                self.0
                    .verify(payload, &signature)
                    .map_err(|_| VaultError::Signature)
            }
        }
    }
}

pub(crate) fn public_key_for_seed(seed: &[u8; SIGNING_SEED_BYTES]) -> Vec<u8> {
    signing_key_from_seed(seed)
        .verifying_key()
        .to_bytes()
        .to_vec()
}

#[cfg(feature = "vault-store")]
pub(crate) fn sign(seed: &[u8; SIGNING_SEED_BYTES], payload: &[u8]) -> VaultResult<Vec<u8>> {
    let mut rng = getrandom_04::SysRng;
    Ok(signing_key_from_seed(seed)
        .expanded_key()
        .sign_randomized(payload, b"", &mut rng)
        .map_err(|_| VaultError::Crypto)?
        .to_bytes()
        .to_vec())
}

#[cfg(feature = "vault-store")]
pub(crate) fn verify(public_key: &[u8], payload: &[u8], signature: &[u8]) -> VaultResult<()> {
    PreparedVerifyingKey::new(public_key)?.verify(CURRENT_SIGNATURE_ALGORITHM, payload, signature)
}

#[cfg(feature = "vault-store")]
pub(crate) fn verify_with(
    algorithm: SignatureAlgorithm,
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> VaultResult<()> {
    match algorithm {
        SignatureAlgorithm::MlDsa65 => verify(public_key, payload, signature),
    }
}

#[cfg(feature = "vault-store")]
pub(crate) fn permission_payload(
    id: &str,
    challenge: &[u8; 32],
    duration_seconds: Option<u64>,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PERMISSION_SIGNATURE_DOMAIN.len() + 8 + id.len() + 32 + 9);
    payload.extend_from_slice(PERMISSION_SIGNATURE_DOMAIN);
    payload.extend_from_slice(&(id.len() as u64).to_be_bytes());
    payload.extend_from_slice(id.as_bytes());
    payload.extend_from_slice(challenge);
    match duration_seconds {
        Some(duration) => {
            payload.push(1);
            payload.extend_from_slice(&duration.to_be_bytes());
        }
        None => payload.push(0),
    }
    payload
}

fn signing_key_from_seed(seed: &[u8; SIGNING_SEED_BYTES]) -> DeviceSigningKey {
    let mut protected_seed = Zeroizing::new(Seed::default());
    protected_seed.copy_from_slice(seed);
    DeviceSigningKey::new(&protected_seed)
}

#[cfg(all(test, feature = "vault-store"))]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[cfg(all(feature = "hardware", target_os = "macos"))]
    #[test]
    #[ignore = "requires a physical Mac with macOS 26+ Secure Enclave access"]
    fn secure_enclave_signatures_verify_with_rustcrypto_after_reopening() {
        let key =
            hardwareseal::apple_pq::MlDsa65Key::generate(hardwareseal::AccessPolicy::None).unwrap();
        let reopened = hardwareseal::apple_pq::MlDsa65Key::from_reference(key.reference()).unwrap();
        assert_eq!(key.public_key(), reopened.public_key());
        let signer = EnclaveSigner(reopened);
        let public = signer.public_key().unwrap();
        for message in [&b""[..], &b"factorseal hardware acceptance"[..]] {
            let proof = signer.sign(message).unwrap();
            verify(&public, message, &proof).unwrap();
            assert!(verify(&public, b"different transcript", &proof).is_err());
        }
    }

    #[test]
    fn mldsa_signatures_round_trip_and_reject_tampering() {
        let seed = [0x2a; SIGNING_SEED_BYTES];
        let public_key = public_key_for_seed(&seed);
        let mut signature = sign(&seed, b"Factorseal durable state").unwrap();

        verify(&public_key, b"Factorseal durable state", &signature).unwrap();
        signature[0] ^= 1;
        assert!(verify(&public_key, b"Factorseal durable state", &signature).is_err());
    }

    #[test]
    fn mldsa_signatures_are_randomized() {
        let seed = [0x2a; SIGNING_SEED_BYTES];
        let public_key = public_key_for_seed(&seed);
        let first = sign(&seed, b"Factorseal durable state").unwrap();
        let second = sign(&seed, b"Factorseal durable state").unwrap();

        assert_ne!(first, second);
        verify(&public_key, b"Factorseal durable state", &first).unwrap();
        verify(&public_key, b"Factorseal durable state", &second).unwrap();
    }

    #[test]
    fn mldsa65_matches_nist_acvp_key_generation_vector() {
        // NIST ACVP ML-DSA-keyGen-FIPS204, commit 65370b8, ML-DSA-65,
        // test case 26. The full 1,952-byte expected public key is committed
        // by its SHA-256 digest to keep this test source reviewable.
        let seed = hex::decode("70CEFB9AED5B68E018B079DA8284B9D5CAD5499ED9C265FF73588005D85C225C")
            .unwrap()
            .try_into()
            .unwrap();
        let public_key = public_key_for_seed(&seed);

        assert_eq!(public_key.len(), 1_952);
        assert_eq!(
            hex::encode(Sha256::digest(public_key)),
            "646b26b8d09dbc9e865b6a006c693a3127b065e62fab5fbe8b159c416462feb6"
        );
    }

    #[test]
    fn malformed_mldsa_inputs_are_rejected() {
        let seed = [0x7b; SIGNING_SEED_BYTES];
        let public_key = public_key_for_seed(&seed);
        let signature = sign(&seed, b"Factorseal durable state").unwrap();

        assert!(
            verify(
                &public_key[..public_key.len() - 1],
                b"Factorseal durable state",
                &signature
            )
            .is_err()
        );
        assert!(
            verify(
                &public_key,
                b"Factorseal durable state",
                &signature[..signature.len() - 1]
            )
            .is_err()
        );
    }
}

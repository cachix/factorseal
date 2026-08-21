//! Post-quantum device signatures for durable vault state.
//!
//! ML-DSA-65 is the FIPS 204 parameter set selected for Factorseal. It offers
//! a practical balance between signature size and security strength, without
//! relying on a quantum-vulnerable elliptic-curve signature.

#[cfg(feature = "vault-store")]
use core::convert::TryFrom;

#[cfg(feature = "key-protection")]
use ml_dsa::{KeyExport, Keypair};
use ml_dsa::{KeyInit, MlDsa65, SigningKey};
#[cfg(feature = "vault-store")]
use ml_dsa::{Signature, SignatureEncoding, Signer, Verifier, VerifyingKey};

use super::{VaultError, VaultResult};

pub(crate) const SIGNING_SEED_BYTES: usize = 32;

type DeviceSigningKey = SigningKey<MlDsa65>;
#[cfg(feature = "vault-store")]
type DeviceVerifyingKey = VerifyingKey<MlDsa65>;
#[cfg(feature = "vault-store")]
type DeviceSignature = Signature<MlDsa65>;

#[cfg(feature = "key-protection")]
pub(crate) fn public_key_for_seed(seed: &[u8; SIGNING_SEED_BYTES]) -> VaultResult<Vec<u8>> {
    Ok(signing_key_from_seed(seed)?
        .verifying_key()
        .to_bytes()
        .to_vec())
}

#[cfg(feature = "vault-store")]
pub(crate) fn sign(seed: &[u8; SIGNING_SEED_BYTES], payload: &[u8]) -> VaultResult<Vec<u8>> {
    Ok(signing_key_from_seed(seed)?
        .sign(payload)
        .to_bytes()
        .to_vec())
}

#[cfg(feature = "vault-store")]
pub(crate) fn verify(public_key: &[u8], payload: &[u8], signature: &[u8]) -> VaultResult<()> {
    let public_key =
        DeviceVerifyingKey::new(&public_key.try_into().map_err(|_| VaultError::Signature)?);
    let signature = DeviceSignature::try_from(signature).map_err(|_| VaultError::Signature)?;
    public_key
        .verify(payload, &signature)
        .map_err(|_| VaultError::Signature)
}

fn signing_key_from_seed(seed: &[u8; SIGNING_SEED_BYTES]) -> VaultResult<DeviceSigningKey> {
    Ok(DeviceSigningKey::new(
        &seed
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Signature)?,
    ))
}

#[cfg(all(test, feature = "vault-store"))]
mod tests {
    use super::*;

    #[test]
    fn mldsa_signatures_round_trip_and_reject_tampering() {
        let seed = [0x2a; SIGNING_SEED_BYTES];
        let public_key = public_key_for_seed(&seed).unwrap();
        let mut signature = sign(&seed, b"Factorseal durable state").unwrap();

        verify(&public_key, b"Factorseal durable state", &signature).unwrap();
        signature[0] ^= 1;
        assert!(verify(&public_key, b"Factorseal durable state", &signature).is_err());
    }
}

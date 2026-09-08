//! RSA signing/verification uses AWS-LC without enabling ssh-key's vulnerable
//! RustCrypto RSA backend. OpenSSH omits CRT exponents: derive them using bounded
//! constant-time integer division, wiping both quotient and remainder.
use super::invalid;
use crate::vault::VaultResult;
use aws_lc_rs::{rand::SystemRandom, rsa, signature as aws_signature};
use crypto_bigint::{BoxedUint, NonZero};
use signature::{Signer, Verifier};
use ssh_key::{Algorithm, HashAlg, Mpint, PrivateKey, Signature, public::KeyData};
use zeroize::Zeroizing;

fn positive(value: &Mpint) -> VaultResult<&[u8]> {
    value.as_positive_bytes().ok_or_else(invalid)
}

fn crt_exponent(exponent: &[u8], prime: &[u8], bits: u32) -> VaultResult<Zeroizing<Box<[u8]>>> {
    let exponent = Zeroizing::new(BoxedUint::from_be_slice(exponent, bits).map_err(|_| invalid())?);
    let prime = Zeroizing::new(BoxedUint::from_be_slice(prime, bits).map_err(|_| invalid())?);
    let divisor = Zeroizing::new(
        NonZero::new(prime.wrapping_sub(BoxedUint::one_with_precision(bits)))
            .into_option()
            .ok_or_else(invalid)?,
    );
    let (quotient, remainder) = exponent.div_rem(&*divisor);
    let _quotient = Zeroizing::new(quotient);
    let remainder = Zeroizing::new(remainder);
    Ok(Zeroizing::new(remainder.to_be_bytes()))
}

pub(crate) fn sign(key: &PrivateKey, data: &[u8], flags: u32) -> VaultResult<Signature> {
    let Some(key) = key.key_data().rsa() else {
        if flags != 0 {
            return Err(invalid());
        }
        return key.try_sign(data).map_err(|_| invalid());
    };
    let (hash, padding) = match flags {
        2 => (HashAlg::Sha256, &aws_signature::RSA_PKCS1_SHA256),
        4 => (HashAlg::Sha512, &aws_signature::RSA_PKCS1_SHA512),
        _ => return Err(invalid()),
    };
    let bits = key.key_size();
    if !(2048..=8192).contains(&bits) {
        return Err(invalid());
    }
    let private = key.private();
    let exponent = positive(private.d())?;
    let prime_p = positive(private.p())?;
    let prime_q = positive(private.q())?;
    let exponent_p = crt_exponent(exponent, prime_p, bits)?;
    let exponent_q = crt_exponent(exponent, prime_q, bits)?;
    let pair = rsa::KeyPair::from_components(&rsa::KeyPairComponents {
        public_key: rsa::PublicKeyComponents {
            n: positive(key.public().n())?,
            e: positive(key.public().e())?,
        },
        d: exponent,
        p: prime_p,
        q: prime_q,
        dP: &*exponent_p,
        dQ: &*exponent_q,
        qInv: positive(private.iqmp())?,
    })
    .map_err(|_| invalid())?;
    let mut bytes = vec![0; pair.public_modulus_len()];
    pair.sign(padding, &SystemRandom::new(), data, &mut bytes)
        .map_err(|_| invalid())?;
    Signature::new(Algorithm::Rsa { hash: Some(hash) }, bytes).map_err(|_| invalid())
}

pub(crate) fn verify(key: &KeyData, data: &[u8], signature: &Signature) -> VaultResult<()> {
    if let Some(key) = key.rsa() {
        let algorithm = match signature.algorithm() {
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            } => &aws_signature::RSA_PKCS1_2048_8192_SHA256,
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            } => &aws_signature::RSA_PKCS1_2048_8192_SHA512,
            _ => return Err(invalid()),
        };
        rsa::PublicKeyComponents {
            n: positive(key.n())?,
            e: positive(key.e())?,
        }
        .verify(algorithm, data, signature.as_bytes())
        .map_err(|_| invalid())
    } else {
        key.verify(data, signature).map_err(|_| invalid())
    }
}

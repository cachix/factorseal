use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use sha2::{Digest, Sha256};
use signature::{SignatureEncoding as _, Signer as _};
use yubikey::{
    Certificate, PinPolicy, Serial, YubiKey,
    certificate::yubikey_signer::{Rsa2048, Signer, YubiRsa},
    piv::{self, AlgorithmId, ManagementAlgorithmId, SlotId},
};
use zeroize::Zeroizing;

use crate::{Error, Result};

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const RSA_2048_BYTES: usize = 256;
const SLOT: SlotId = SlotId::KeyManagement;
const SLOT_NAME: &str = "9d";

pub(crate) struct EnrolledYubiKey {
    pub(crate) serial: u32,
    pub(crate) slot: &'static str,
    pub(crate) nonce: [u8; NONCE_BYTES],
    pub(crate) wrapped_share: Vec<u8>,
}

pub(crate) fn enroll(
    vault_id: &[u8; 16],
    pin: &[u8],
    share: &[u8; KEY_BYTES],
) -> Result<EnrolledYubiKey> {
    let mut yubikey = YubiKey::open().map_err(map_yubikey_error)?;
    validate_and_authorize(&mut yubikey, pin)?;
    let serial = u32::from(yubikey.serial());
    let factor_key = derive_factor_key(&mut yubikey, vault_id)?;

    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce)?;
    let cipher = XChaCha20Poly1305::new((&*factor_key).into());
    let wrapped_share = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: share,
                aad: &factor_aad(vault_id, serial),
            },
        )
        .map_err(|_| Error::Authentication)?;

    Ok(EnrolledYubiKey {
        serial,
        slot: SLOT_NAME,
        nonce,
        wrapped_share,
    })
}

pub(crate) fn unlock_share(
    vault_id: &[u8; 16],
    serial: u32,
    slot: &str,
    nonce: &[u8; NONCE_BYTES],
    wrapped_share: &[u8],
    pin: &[u8],
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    if slot != SLOT_NAME {
        return Err(Error::InvalidMetadata(format!(
            "unsupported YubiKey slot `{slot}`"
        )));
    }
    let mut yubikey = YubiKey::open_by_serial(Serial::from(serial)).map_err(map_yubikey_error)?;
    validate_and_authorize(&mut yubikey, pin)?;
    let factor_key = derive_factor_key(&mut yubikey, vault_id)?;
    let cipher = XChaCha20Poly1305::new((&*factor_key).into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: wrapped_share,
                    aad: &factor_aad(vault_id, serial),
                },
            )
            .map_err(|_| Error::UnlockFailed)?,
    );
    let actual = plaintext.len();
    let share = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidMetadata(format!("YubiKey share has {actual} bytes")))?;
    Ok(Zeroizing::new(share))
}

fn validate_and_authorize(yubikey: &mut YubiKey, pin: &[u8]) -> Result<()> {
    if pin.is_empty() {
        return Err(Error::YubiKey("PIN must not be empty".to_owned()));
    }
    let metadata = piv::metadata(yubikey, SLOT).map_err(map_yubikey_error)?;
    if metadata.algorithm != ManagementAlgorithmId::Asymmetric(AlgorithmId::Rsa2048)
        || !matches!(
            metadata.policy,
            Some((PinPolicy::Default | PinPolicy::Once | PinPolicy::Always, _))
        )
    {
        return Err(Error::UnsupportedYubiKeySlot);
    }
    yubikey.verify_pin(pin).map_err(map_yubikey_error)
}

fn derive_factor_key(
    yubikey: &mut YubiKey,
    vault_id: &[u8; 16],
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let challenge = factor_challenge(vault_id);
    let certificate = Certificate::read(yubikey, SLOT).map_err(map_yubikey_error)?;
    let signer = Signer::<YubiRsa<Rsa2048>>::new(yubikey, SLOT, certificate.subject_pki())
        .map_err(map_yubikey_error)?;
    // The yubikey crate's high-level signer hashes the challenge and performs
    // EMSA-PKCS1-v1_5 encoding before sending the raw RSA operation to PIV.
    let signature = signer
        .try_sign(&challenge)
        .map_err(|error| Error::YubiKey(error.to_string()))?
        .to_vec();
    if signature.len() != RSA_2048_BYTES {
        return Err(Error::YubiKey(format!(
            "RSA-2048 operation returned {} bytes",
            signature.len()
        )));
    }
    let mut digest = Sha256::new();
    digest.update(b"factorseal/yubikey-factor/v2\0");
    digest.update(&*signature);
    Ok(Zeroizing::new(digest.finalize().into()))
}

fn factor_challenge(vault_id: &[u8; 16]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"factorseal/yubikey-challenge/v2\0");
    digest.update(vault_id);
    digest.finalize().into()
}

fn factor_aad(vault_id: &[u8; 16], serial: u32) -> Vec<u8> {
    let mut aad = b"factorseal/yubikey-share/v2\0".to_vec();
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(&serial.to_be_bytes());
    aad.extend_from_slice(SLOT_NAME.as_bytes());
    aad
}

fn map_yubikey_error(error: yubikey::Error) -> Error {
    match error {
        yubikey::Error::WrongPin { tries } => {
            Error::YubiKey(format!("incorrect PIN ({tries} attempts remain)"))
        }
        yubikey::Error::PinLocked => Error::YubiKey("PIN is locked".to_owned()),
        yubikey::Error::NotFound => Error::YubiKey("configured device was not found".to_owned()),
        other => Error::YubiKey(other.to_string()),
    }
}

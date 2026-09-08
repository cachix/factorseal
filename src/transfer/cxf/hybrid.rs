//! Standard age `mlkem768x25519` recipient adapter, pending native rage support.
//! Wire format: <https://c2sp.org/age#mlkem768x25519-recipient-stanza>
//! HPKE and X-Wing are provided by hpke/RustCrypto; age handles the file envelope.

use std::{collections::HashSet, path::Path, str::FromStr};

use age::secrecy::ExposeSecret as _;
use age_core::{
    format::{FileKey, Stanza},
    primitives::bech32_decode,
};
use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use hpke::{Deserializable as _, Serializable as _};
use zeroize::Zeroizing;

type Kem = hpke::kem::XWing;
const TAG: &str = "mlkem768x25519";
const INFO: &[u8] = b"age-encryption.org/mlkem768x25519";
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// A standard age `age1pq1…` hybrid post-quantum public key.
pub struct HybridRecipient(<Kem as hpke::Kem>::PublicKey);

/// A standard age `AGE-SECRET-KEY-PQ-1…` private identity.
/// Secret key storage is owned and wiped by the underlying X-Wing implementation.
pub struct HybridIdentity(<Kem as hpke::Kem>::PrivateKey);

fn decode_key(
    value: &str,
    prefix: &str,
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if value.len() > 2048 {
        return Err("age key is too long");
    }
    bech32_decode(
        value,
        |_| "invalid age key encoding",
        |hrp| {
            if hrp.to_string().eq_ignore_ascii_case(prefix) {
                Ok(())
            } else {
                Err("expected a hybrid post-quantum age key")
            }
        },
        |_, bytes| {
            let bytes = Zeroizing::new(bytes.collect::<Vec<_>>());
            if bytes.len() == length {
                Ok(bytes)
            } else {
                Err("invalid age key length")
            }
        },
    )
}

impl FromStr for HybridRecipient {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = decode_key(value, "age1pq", 1216)?;
        <Kem as hpke::Kem>::PublicKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| "invalid hybrid age recipient")
    }
}

impl FromStr for HybridIdentity {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = decode_key(value, "AGE-SECRET-KEY-PQ-", 32)?;
        <Kem as hpke::Kem>::PrivateKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| "invalid hybrid age identity")
    }
}

/// Read exactly one public hybrid recipient, allowing age comments and blank lines.
pub fn read_recipient_file(path: &Path) -> anyhow::Result<HybridRecipient> {
    let bytes = crate::security::read_regular_file(path, MAX_KEY_FILE_BYTES)
        .context("cannot read age recipient file")?;
    parse_key_file(&bytes)
}

/// Read exactly one unencrypted hybrid identity from a private regular file.
/// Encrypted identity files and plugin identities are not supported.
pub fn read_identity_file(path: &Path) -> anyhow::Result<HybridIdentity> {
    let bytes = crate::security::read_private_file(path, MAX_KEY_FILE_BYTES)
        .context("cannot read private age identity file")?;
    parse_key_file(&bytes)
}

fn parse_key_file<T: FromStr<Err = &'static str>>(bytes: &[u8]) -> anyhow::Result<T> {
    let text = std::str::from_utf8(bytes).context("age key file must be UTF-8")?;
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let key = lines.next().context("age key file contains no key")?;
    if lines.next().is_some() {
        bail!("age key file must contain exactly one hybrid key");
    }
    key.parse().map_err(anyhow::Error::msg)
}

impl age::Recipient for HybridRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let (enc, body) =
            hpke::single_shot_seal::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, Kem>(
                &hpke::OpModeS::Base,
                &self.0,
                INFO,
                file_key.expose_secret(),
                &[],
            )
            .map_err(|_| std::io::Error::other("cannot encrypt hybrid age file key"))?;
        Ok((
            vec![Stanza {
                tag: TAG.into(),
                args: vec![STANDARD_NO_PAD.encode(enc.to_bytes())],
                body,
            }],
            HashSet::from(["postquantum".into()]),
        ))
    }
}

impl age::Identity for HybridIdentity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != TAG {
            return None;
        }
        let [encoded] = stanza.args.as_slice() else {
            return Some(Err(age::DecryptError::InvalidHeader));
        };
        // Check fixed sizes before decoding or HPKE (including the partitioning-oracle bound).
        if encoded.len() != 1494 || stanza.body.len() != 32 {
            return Some(Err(age::DecryptError::InvalidHeader));
        }
        let enc = STANDARD_NO_PAD
            .decode(encoded)
            .ok()
            .and_then(|bytes| <Kem as hpke::Kem>::EncappedKey::from_bytes(&bytes).ok());
        let Some(enc) = enc else {
            return Some(Err(age::DecryptError::InvalidHeader));
        };
        let plaintext = hpke::single_shot_open::<
            hpke::aead::ChaCha20Poly1305,
            hpke::kdf::HkdfSha256,
            Kem,
        >(&hpke::OpModeR::Base, &self.0, &enc, INFO, &stanza.body, &[])
        .ok()
        .map(Zeroizing::new)?;
        Some(Ok(FileKey::init_with_mut(|key| {
            key.copy_from_slice(&plaintext);
        })))
    }
}

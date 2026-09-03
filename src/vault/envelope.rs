//! Encrypted document snapshots.
//!
//! A snapshot is authenticated by AES-256-GCM over a domain-separated header
//! and by the protected commit that names its digest. The commit chain, not
//! the snapshot, carries the device signature, so one generation costs one
//! signature. The record document and its history log are two ciphertexts
//! under the same key and header, so a read can decrypt one without the
//! other while the signed digest still covers both.

use automerge::ChangeHash;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::EncryptionAlgorithm;
use crate::crypto::{self, NONCE_BYTES};

use super::{DeviceKeyId, DocumentId, DocumentKind, VaultError, VaultId, VaultResult};

// Version 6 carries the history log as a second ciphertext beside the
// record document. Version 5 dropped the per-snapshot signature; the
// protected commit signs the snapshot digest instead.
const ENVELOPE_VERSION: u8 = 6;
const DIGEST_BYTES: usize = 32;
const SNAPSHOT_DOMAIN: &[u8] = b"factorseal/encrypted-snapshot/v6\0";

/// Which of the two ciphertexts a header authenticates. The tag keeps the
/// record document and the history log from standing in for each other.
#[derive(Clone, Copy)]
enum SnapshotPart {
    Records = 0,
    History = 1,
}

/// Encrypted Automerge snapshot persisted by the vault, with the encrypted
/// history log of the same generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedSnapshot {
    version: u8,
    encryption_algorithm: EncryptionAlgorithm,
    vault_id: VaultId,
    document_id: DocumentId,
    scope: DocumentKind,
    device_key_id: DeviceKeyId,
    generation: u64,
    key_epoch: u64,
    heads: Vec<[u8; DIGEST_BYTES]>,
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
    history_nonce: [u8; NONCE_BYTES],
    history_ciphertext: Vec<u8>,
}

impl EncryptedSnapshot {
    #[must_use]
    pub const fn encryption_algorithm(&self) -> EncryptionAlgorithm {
        self.encryption_algorithm
    }

    #[must_use]
    pub const fn document_id(&self) -> DocumentId {
        self.document_id
    }

    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    #[must_use]
    pub const fn scope(&self) -> DocumentKind {
        self.scope
    }

    #[must_use]
    pub const fn device_key_id(&self) -> DeviceKeyId {
        self.device_key_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    #[must_use]
    pub fn history_ciphertext(&self) -> &[u8] {
        &self.history_ciphertext
    }

    fn context(&self) -> EnvelopeContext {
        EnvelopeContext {
            vault_id: self.vault_id,
            document_id: self.document_id,
            scope: self.scope,
            device_key_id: self.device_key_id,
            generation: self.generation,
            key_epoch: self.key_epoch,
        }
    }

    fn decrypt(&self, part: SnapshotPart, data_key: &[u8; 32]) -> VaultResult<Zeroizing<Vec<u8>>> {
        if self.version != ENVELOPE_VERSION {
            return Err(VaultError::Signature);
        }
        let (nonce, ciphertext) = match part {
            SnapshotPart::Records => (&self.nonce, &self.ciphertext),
            SnapshotPart::History => (&self.history_nonce, &self.history_ciphertext),
        };
        let aad = snapshot_header(
            &self.context(),
            self.encryption_algorithm,
            &self.heads,
            part,
        );
        crypto::decrypt(self.encryption_algorithm, data_key, nonce, &aad, ciphertext)
            .map_err(|_| VaultError::Crypto)
    }
}

pub(crate) struct EnvelopeContext {
    pub(crate) vault_id: VaultId,
    pub(crate) document_id: DocumentId,
    pub(crate) scope: DocumentKind,
    pub(crate) device_key_id: DeviceKeyId,
    pub(crate) generation: u64,
    pub(crate) key_epoch: u64,
}

pub(crate) fn encrypt_snapshot(
    context: &EnvelopeContext,
    heads: &[ChangeHash],
    records: &[u8],
    history: &[u8],
    data_key: &[u8; 32],
) -> VaultResult<EncryptedSnapshot> {
    let heads: Vec<[u8; DIGEST_BYTES]> = heads.iter().map(|head| head.0).collect();
    let encryption_algorithm = crypto::CURRENT_ENCRYPTION_ALGORITHM;
    let records_aad = snapshot_header(context, encryption_algorithm, &heads, SnapshotPart::Records);
    let encrypted_records =
        crypto::encrypt(data_key, &records_aad, records).map_err(|_| VaultError::Crypto)?;
    let history_aad = snapshot_header(context, encryption_algorithm, &heads, SnapshotPart::History);
    let encrypted_history =
        crypto::encrypt(data_key, &history_aad, history).map_err(|_| VaultError::Crypto)?;
    Ok(EncryptedSnapshot {
        version: ENVELOPE_VERSION,
        encryption_algorithm,
        vault_id: context.vault_id,
        document_id: context.document_id,
        scope: context.scope,
        device_key_id: context.device_key_id,
        generation: context.generation,
        key_epoch: context.key_epoch,
        heads,
        nonce: encrypted_records.nonce,
        ciphertext: encrypted_records.ciphertext,
        history_nonce: encrypted_history.nonce,
        history_ciphertext: encrypted_history.ciphertext,
    })
}

/// Decrypt the record document, authenticating every header field through
/// the AEAD.
///
/// The caller is responsible for checking that the header fields match the
/// document row and that the serialized snapshot matches the digest in the
/// document's signed commit.
pub fn decrypt_snapshot(
    envelope: &EncryptedSnapshot,
    data_key: &[u8; 32],
) -> VaultResult<Zeroizing<Vec<u8>>> {
    envelope.decrypt(SnapshotPart::Records, data_key)
}

/// Decrypt the history log of the same generation under the same checks as
/// [`decrypt_snapshot`], without touching the record document.
pub(crate) fn decrypt_history(
    envelope: &EncryptedSnapshot,
    data_key: &[u8; 32],
) -> VaultResult<Zeroizing<Vec<u8>>> {
    envelope.decrypt(SnapshotPart::History, data_key)
}

fn snapshot_header(
    context: &EnvelopeContext,
    encryption_algorithm: EncryptionAlgorithm,
    heads: &[[u8; DIGEST_BYTES]],
    part: SnapshotPart,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(SNAPSHOT_DOMAIN);
    bytes.push(ENVELOPE_VERSION);
    bytes.push(part as u8);
    bytes.push(encryption_algorithm.code());
    bytes.extend_from_slice(context.vault_id.as_bytes());
    bytes.extend_from_slice(context.document_id.as_bytes());
    append_bytes(&mut bytes, context.scope.as_str().as_bytes());
    bytes.extend_from_slice(context.device_key_id.as_bytes());
    bytes.extend_from_slice(&context.generation.to_be_bytes());
    bytes.extend_from_slice(&context.key_epoch.to_be_bytes());
    append_array_list(&mut bytes, heads);
    bytes
}

fn append_bytes(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn append_array_list(target: &mut Vec<u8>, values: &[[u8; DIGEST_BYTES]]) {
    target.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        target.extend_from_slice(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{DocumentKind, InstallationId};

    fn context() -> EnvelopeContext {
        EnvelopeContext {
            vault_id: VaultId::from_bytes([6; 16]),
            document_id: DocumentId::derive_for_test(
                InstallationId::from_bytes([7; 16]),
                VaultId::from_bytes([6; 16]),
                DocumentKind::SecretSpecProviderCache,
                b"secretspec",
            ),
            scope: DocumentKind::SecretSpecProviderCache,
            device_key_id: DeviceKeyId::from_bytes([8; 32]),
            generation: 3,
            key_epoch: 3,
        }
    }

    #[test]
    fn envelopes_declare_their_algorithm() {
        let envelope = encrypt_snapshot(
            &context(),
            &[ChangeHash([1; 32])],
            b"payload",
            b"history",
            &[9; 32],
        )
        .unwrap();

        assert_eq!(
            envelope.encryption_algorithm(),
            EncryptionAlgorithm::Aes256Gcm
        );
    }

    #[test]
    fn an_unknown_or_missing_encryption_algorithm_is_refused() {
        let envelope = encrypt_snapshot(
            &context(),
            &[ChangeHash([1; 32])],
            b"payload",
            b"history",
            &[10; 32],
        )
        .unwrap();

        let mut json = serde_json::to_value(&envelope).unwrap();
        json["encryption_algorithm"] = serde_json::Value::String("unknown-encryption".to_owned());
        assert!(serde_json::from_value::<EncryptedSnapshot>(json).is_err());

        let mut absent = serde_json::to_value(&envelope).unwrap();
        absent
            .as_object_mut()
            .unwrap()
            .remove("encryption_algorithm");
        assert!(serde_json::from_value::<EncryptedSnapshot>(absent).is_err());
    }

    #[test]
    fn snapshot_is_encrypted_and_bound_to_its_header() {
        let data_key = [4; 32];
        let context = context();
        let envelope = encrypt_snapshot(
            &context,
            &[ChangeHash([1; 32])],
            b"highly classified",
            b"change log",
            &data_key,
        )
        .unwrap();

        assert!(
            !envelope
                .ciphertext()
                .windows(b"classified".len())
                .any(|window| window == b"classified")
        );
        assert!(
            !envelope
                .history_ciphertext()
                .windows(b"change log".len())
                .any(|window| window == b"change log")
        );
        assert_eq!(
            decrypt_snapshot(&envelope, &data_key).unwrap().as_slice(),
            b"highly classified"
        );
        assert_eq!(
            decrypt_history(&envelope, &data_key).unwrap().as_slice(),
            b"change log"
        );

        macro_rules! rejects {
            ($field:ident, $value:expr) => {{
                let mut changed = envelope.clone();
                changed.$field = $value;
                assert!(
                    decrypt_snapshot(&changed, &data_key).is_err(),
                    "snapshot decryption accepted changed {}",
                    stringify!($field)
                );
                assert!(
                    decrypt_history(&changed, &data_key).is_err(),
                    "history decryption accepted changed {}",
                    stringify!($field)
                );
            }};
        }

        rejects!(version, envelope.version + 1);
        rejects!(vault_id, VaultId::from_bytes([0x55; 16]));
        rejects!(document_id, DocumentId::from_bytes([0x56; 32]));
        rejects!(scope, DocumentKind::LocalKeyring);
        rejects!(device_key_id, DeviceKeyId::from_bytes([0x57; 32]));
        rejects!(generation, envelope.generation + 1);
        rejects!(key_epoch, envelope.key_epoch + 1);
        rejects!(heads, vec![[0x58; DIGEST_BYTES]]);

        let mut records_tampered = envelope.clone();
        records_tampered.ciphertext = b"replacement ciphertext".to_vec();
        assert!(decrypt_snapshot(&records_tampered, &data_key).is_err());
        let mut history_tampered = envelope.clone();
        history_tampered.history_ciphertext = b"replacement ciphertext".to_vec();
        assert!(decrypt_history(&history_tampered, &data_key).is_err());

        // The two ciphertexts share a key and header but cannot stand in for
        // each other.
        let mut swapped = envelope.clone();
        swapped.history_nonce = envelope.nonce;
        swapped.history_ciphertext = envelope.ciphertext.clone();
        assert!(decrypt_history(&swapped, &data_key).is_err());

        assert!(decrypt_snapshot(&envelope, &[0x5d; 32]).is_err());
    }
}

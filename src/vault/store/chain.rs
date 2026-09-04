use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vault::signature::{self, CURRENT_SIGNATURE_ALGORITHM, SignatureAlgorithm};
use crate::vault::{DeviceKeyId, DocumentId, DocumentKind, VaultError, VaultId, VaultResult};

// Version 6 authenticates eviction scheduling as well as document contents.
const COMMIT_VERSION: u8 = 6;
const COMMIT_DOMAIN: &[u8] = b"factorseal/protected-commit/v6\0";
const COMMIT_SIGNATURE_DOMAIN: &[u8] = b"factorseal/protected-commit-signature/v6\0";

#[derive(Clone, Copy)]
pub(super) struct CommitContents {
    pub(super) previous_commit_id: Option<[u8; 32]>,
    pub(super) vault_id: VaultId,
    pub(super) document_id: DocumentId,
    pub(super) scope: DocumentKind,
    pub(super) generation: u64,
    pub(super) key_epoch: u64,
    pub(super) wrapped_key_digest: [u8; 32],
    pub(super) snapshot_digest: [u8; 32],
    pub(super) next_eviction: Option<u64>,
    pub(super) device_key_id: DeviceKeyId,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProtectedCommit {
    pub(super) version: u8,
    pub(super) signature_algorithm: SignatureAlgorithm,
    pub(super) commit_id: [u8; 32],
    pub(super) previous_commit_id: Option<[u8; 32]>,
    pub(super) vault_id: VaultId,
    pub(super) document_id: DocumentId,
    pub(super) scope: DocumentKind,
    pub(super) generation: u64,
    pub(super) key_epoch: u64,
    pub(super) wrapped_key_digest: [u8; 32],
    pub(super) snapshot_digest: [u8; 32],
    pub(super) next_eviction: Option<u64>,
    pub(super) device_key_id: DeviceKeyId,
    pub(super) signature: Vec<u8>,
}

impl ProtectedCommit {
    pub(super) fn new(contents: CommitContents, signing_seed: &[u8; 32]) -> VaultResult<Self> {
        let signature_algorithm = CURRENT_SIGNATURE_ALGORITHM;
        let transcript = commit_transcript(signature_algorithm, &contents);
        let commit_id = digest(&transcript);
        let signature = signature::sign(signing_seed, &commit_signature_payload(&commit_id))?;
        let CommitContents {
            previous_commit_id,
            vault_id,
            document_id,
            scope,
            generation,
            key_epoch,
            wrapped_key_digest,
            snapshot_digest,
            next_eviction,
            device_key_id,
        } = contents;
        Ok(Self {
            version: COMMIT_VERSION,
            signature_algorithm,
            commit_id,
            previous_commit_id,
            vault_id,
            document_id,
            scope,
            generation,
            key_epoch,
            wrapped_key_digest,
            snapshot_digest,
            next_eviction,
            device_key_id,
            signature,
        })
    }

    pub(super) fn verify(
        &self,
        expected_commit_id: [u8; 32],
        expected_device_key_id: DeviceKeyId,
        public_key: &[u8],
    ) -> VaultResult<()> {
        if self.version != COMMIT_VERSION
            || self.commit_id != expected_commit_id
            || self.device_key_id != expected_device_key_id
        {
            return Err(VaultError::Signature);
        }
        let transcript = commit_transcript(
            self.signature_algorithm,
            &CommitContents {
                previous_commit_id: self.previous_commit_id,
                vault_id: self.vault_id,
                document_id: self.document_id,
                scope: self.scope,
                generation: self.generation,
                key_epoch: self.key_epoch,
                wrapped_key_digest: self.wrapped_key_digest,
                snapshot_digest: self.snapshot_digest,
                next_eviction: self.next_eviction,
                device_key_id: self.device_key_id,
            },
        );
        if digest(&transcript) != self.commit_id {
            return Err(VaultError::Signature);
        }
        signature::verify_with(
            self.signature_algorithm,
            public_key,
            &commit_signature_payload(&self.commit_id),
            &self.signature,
        )
    }
}

fn commit_transcript(
    signature_algorithm: SignatureAlgorithm,
    contents: &CommitContents,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(224);
    bytes.extend_from_slice(COMMIT_DOMAIN);
    bytes.push(COMMIT_VERSION);
    bytes.push(signature_algorithm.code());
    match contents.previous_commit_id {
        Some(previous) => {
            bytes.push(1);
            bytes.extend_from_slice(&previous);
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(contents.vault_id.as_bytes());
    bytes.extend_from_slice(contents.document_id.as_bytes());
    append_bytes(&mut bytes, contents.scope.as_str().as_bytes());
    bytes.extend_from_slice(&contents.generation.to_be_bytes());
    bytes.extend_from_slice(&contents.key_epoch.to_be_bytes());
    bytes.extend_from_slice(&contents.wrapped_key_digest);
    bytes.extend_from_slice(&contents.snapshot_digest);
    match contents.next_eviction {
        Some(deadline) => {
            bytes.push(1);
            bytes.extend_from_slice(&deadline.to_be_bytes());
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(contents.device_key_id.as_bytes());
    bytes
}

fn commit_signature_payload(commit_id: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(COMMIT_SIGNATURE_DOMAIN.len() + commit_id.len());
    bytes.extend_from_slice(COMMIT_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(commit_id);
    bytes
}

pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn append_bytes(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::signature::public_key_for_seed;

    fn contents() -> CommitContents {
        CommitContents {
            previous_commit_id: Some([1; 32]),
            vault_id: VaultId::from_bytes([2; 16]),
            document_id: DocumentId::from_bytes([3; 32]),
            scope: DocumentKind::LocalKeyring,
            generation: 4,
            key_epoch: 4,
            wrapped_key_digest: [5; 32],
            snapshot_digest: [6; 32],
            next_eviction: Some(100),
            device_key_id: DeviceKeyId::from_bytes([7; 32]),
        }
    }

    #[test]
    fn commit_binds_every_field_under_its_signature() {
        let seed = [9; 32];
        let public_key = public_key_for_seed(&seed);
        let commit = ProtectedCommit::new(contents(), &seed).unwrap();
        commit
            .verify(commit.commit_id, commit.device_key_id, &public_key)
            .unwrap();

        macro_rules! rejects {
            ($field:ident, $value:expr) => {{
                let mut changed = ProtectedCommit::new(contents(), &seed).unwrap();
                changed.$field = $value;
                assert!(
                    changed
                        .verify(commit.commit_id, commit.device_key_id, &public_key)
                        .is_err(),
                    "commit verification accepted changed {}",
                    stringify!($field)
                );
            }};
        }

        rejects!(version, COMMIT_VERSION + 1);
        rejects!(commit_id, [0x11; 32]);
        rejects!(previous_commit_id, None);
        rejects!(next_eviction, None);
        rejects!(next_eviction, Some(101));
        rejects!(vault_id, VaultId::from_bytes([0x12; 16]));
        rejects!(document_id, DocumentId::from_bytes([0x13; 32]));
        rejects!(scope, DocumentKind::Authorization);
        rejects!(generation, 5);
        rejects!(key_epoch, 5);
        rejects!(wrapped_key_digest, [0x14; 32]);
        rejects!(snapshot_digest, [0x15; 32]);
        rejects!(device_key_id, DeviceKeyId::from_bytes([0x16; 32]));
        rejects!(signature, vec![0x17; commit.signature.len()]);
        assert!(
            commit
                .verify(
                    commit.commit_id,
                    commit.device_key_id,
                    &public_key_for_seed(&[0x18; 32])
                )
                .is_err()
        );
    }

    /// An unrecognized algorithm must fail to load rather than be ignored or
    /// silently downgraded, which is the failure mode this identifier exists
    /// to prevent when a second algorithm is added.
    #[test]
    fn an_unknown_or_missing_signature_algorithm_is_refused() {
        let commit = ProtectedCommit::new(contents(), &[9; 32]).unwrap();

        let mut json = serde_json::to_value(&commit).unwrap();
        json["signature_algorithm"] = serde_json::Value::String("unknown-signature".to_owned());
        assert!(serde_json::from_value::<ProtectedCommit>(json).is_err());

        let mut absent = serde_json::to_value(&commit).unwrap();
        absent
            .as_object_mut()
            .unwrap()
            .remove("signature_algorithm");
        assert!(serde_json::from_value::<ProtectedCommit>(absent).is_err());
    }
}

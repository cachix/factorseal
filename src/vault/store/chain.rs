use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vault::signature;
use crate::vault::{
    DeviceKeyId, DocumentId, DocumentScope, SignedChangeEnvelope, VaultError, VaultResult,
};

const COMMIT_VERSION: u8 = 2;
const COMMIT_DOMAIN: &[u8] = b"factorseal/protected-commit/v1\0";
const COMMIT_SIGNATURE_DOMAIN: &[u8] = b"factorseal/protected-commit-signature/v1\0";

#[derive(Clone, Copy)]
pub(super) struct CommitContents {
    pub(super) previous_commit_id: Option<[u8; 32]>,
    pub(super) document_id: DocumentId,
    pub(super) scope: DocumentScope,
    pub(super) generation: u64,
    pub(super) key_epoch: u64,
    pub(super) snapshot_digest: [u8; 32],
    pub(super) changes_digest: [u8; 32],
    pub(super) device_key_id: DeviceKeyId,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProtectedCommit {
    pub(super) version: u8,
    pub(super) commit_id: [u8; 32],
    pub(super) previous_commit_id: Option<[u8; 32]>,
    pub(super) document_id: DocumentId,
    pub(super) scope: DocumentScope,
    pub(super) generation: u64,
    pub(super) key_epoch: u64,
    pub(super) snapshot_digest: [u8; 32],
    pub(super) changes_digest: [u8; 32],
    pub(super) device_key_id: DeviceKeyId,
    pub(super) signature: Vec<u8>,
}

impl ProtectedCommit {
    pub(super) fn new(contents: CommitContents, signing_seed: &[u8; 32]) -> VaultResult<Self> {
        let transcript = commit_transcript(&contents);
        let commit_id = digest(&transcript);
        let signature = signature::sign(signing_seed, &commit_signature_payload(&commit_id))?;
        let CommitContents {
            previous_commit_id,
            document_id,
            scope,
            generation,
            key_epoch,
            snapshot_digest,
            changes_digest,
            device_key_id,
        } = contents;
        Ok(Self {
            version: COMMIT_VERSION,
            commit_id,
            previous_commit_id,
            document_id,
            scope,
            generation,
            key_epoch,
            snapshot_digest,
            changes_digest,
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
        let transcript = commit_transcript(&CommitContents {
            previous_commit_id: self.previous_commit_id,
            document_id: self.document_id,
            scope: self.scope,
            generation: self.generation,
            key_epoch: self.key_epoch,
            snapshot_digest: self.snapshot_digest,
            changes_digest: self.changes_digest,
            device_key_id: self.device_key_id,
        });
        if digest(&transcript) != self.commit_id {
            return Err(VaultError::Signature);
        }
        signature::verify(
            public_key,
            &commit_signature_payload(&self.commit_id),
            &self.signature,
        )
    }
}

fn commit_transcript(contents: &CommitContents) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(COMMIT_DOMAIN);
    bytes.push(COMMIT_VERSION);
    match contents.previous_commit_id {
        Some(previous) => {
            bytes.push(1);
            bytes.extend_from_slice(&previous);
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(contents.document_id.as_bytes());
    append_bytes(&mut bytes, contents.scope.as_str().as_bytes());
    bytes.extend_from_slice(&contents.generation.to_be_bytes());
    bytes.extend_from_slice(&contents.key_epoch.to_be_bytes());
    bytes.extend_from_slice(&contents.snapshot_digest);
    bytes.extend_from_slice(&contents.changes_digest);
    bytes.extend_from_slice(contents.device_key_id.as_bytes());
    bytes
}

fn commit_signature_payload(commit_id: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(COMMIT_SIGNATURE_DOMAIN.len() + commit_id.len());
    bytes.extend_from_slice(COMMIT_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(commit_id);
    bytes
}

pub(super) fn digest_change_envelopes(
    envelopes: &[SignedChangeEnvelope],
    serialized: &[Vec<u8>],
) -> [u8; 32] {
    let mut pairs: Vec<([u8; 32], &[u8])> = envelopes
        .iter()
        .zip(serialized)
        .map(|(envelope, bytes)| (*envelope.change_hash(), bytes.as_slice()))
        .collect();
    pairs.sort_unstable_by_key(|(hash, _)| *hash);
    let mut digest = Sha256::new();
    digest.update(b"factorseal/change-envelope-set/v1\0");
    digest.update((pairs.len() as u64).to_be_bytes());
    for (hash, bytes) in pairs {
        digest.update(hash);
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    digest.finalize().into()
}

pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn append_bytes(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

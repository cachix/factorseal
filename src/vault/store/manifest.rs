//! One signed commitment to the complete set of current encrypted documents.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vault::signature::{self, CURRENT_SIGNATURE_ALGORITHM, SignatureAlgorithm};
use crate::vault::{DeviceKeyId, DocumentId, DocumentKind, VaultError, VaultId, VaultResult};

use super::chain::{CommitContents, digest};

pub(super) const CURRENT_SCHEMA_VERSION: u32 = 6;
const HEAD_DOMAIN: &[u8] = b"factorseal/current-document-head/v1\0";
const INVENTORY_DOMAIN: &[u8] = b"factorseal/current-document-inventory/v1\0";
const MANIFEST_DOMAIN: &[u8] = b"factorseal/current-state-manifest/v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"factorseal/current-state-signature/v1\0";

/// This record is authenticated by membership in the signed manifest. It is
/// deliberately not independently signed, and contains no historical link.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CurrentHead {
    pub(super) head_id: [u8; 32],
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

impl CurrentHead {
    pub(super) fn new(contents: CommitContents) -> Self {
        let mut head = Self {
            head_id: [0; 32],
            vault_id: contents.vault_id,
            document_id: contents.document_id,
            scope: contents.scope,
            generation: contents.generation,
            key_epoch: contents.key_epoch,
            wrapped_key_digest: contents.wrapped_key_digest,
            snapshot_digest: contents.snapshot_digest,
            next_eviction: contents.next_eviction,
            device_key_id: contents.device_key_id,
        };
        head.head_id = head.calculate_id();
        head
    }

    fn calculate_id(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(HEAD_DOMAIN);
        hash.update(self.vault_id.as_bytes());
        hash.update(self.document_id.as_bytes());
        hash.update((self.scope.as_str().len() as u64).to_be_bytes());
        hash.update(self.scope.as_str().as_bytes());
        hash.update(self.generation.to_be_bytes());
        hash.update(self.key_epoch.to_be_bytes());
        hash.update(self.wrapped_key_digest);
        hash.update(self.snapshot_digest);
        hash.update([u8::from(self.next_eviction.is_some())]);
        hash.update(self.next_eviction.unwrap_or_default().to_be_bytes());
        hash.update(self.device_key_id.as_bytes());
        hash.finalize().into()
    }

    /// Check the canonical head hash. This establishes authenticity only when
    /// `expected` is anchored in the verified inventory or its lease-scoped
    /// cache. Startup checks hashes first, then authenticates the whole inventory
    /// before using any returned head as trusted state.
    pub(super) fn verify(&self, expected: [u8; 32]) -> VaultResult<()> {
        if self.head_id != expected || self.calculate_id() != expected {
            return Err(VaultError::Signature);
        }
        Ok(())
    }
}

pub(super) fn inventory_digest<'a>(
    heads: impl IntoIterator<Item = (&'a DocumentId, &'a [u8; 32])>,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(INVENTORY_DOMAIN);
    for (document, head) in heads {
        hash.update(document.as_bytes());
        hash.update(head);
    }
    hash.finalize().into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StateManifest {
    version: u32,
    signature_algorithm: SignatureAlgorithm,
    vault_id: VaultId,
    device_key_id: DeviceKeyId,
    pub(super) document_count: u64,
    pub(super) inventory_digest: [u8; 32],
    /// Authenticated migration-only cleanup. Normal writes always clear this.
    pub(super) repack_pending: bool,
    pub(super) manifest_id: [u8; 32],
    signature: Vec<u8>,
}

impl StateManifest {
    pub(super) fn new(
        vault_id: VaultId,
        device_key_id: DeviceKeyId,
        document_count: u64,
        inventory_digest: [u8; 32],
        repack_pending: bool,
        signer: &dyn signature::SigningProvider,
    ) -> VaultResult<Self> {
        let mut manifest = Self {
            version: CURRENT_SCHEMA_VERSION,
            signature_algorithm: CURRENT_SIGNATURE_ALGORITHM,
            vault_id,
            device_key_id,
            document_count,
            inventory_digest,
            repack_pending,
            manifest_id: [0; 32],
            signature: Vec::new(),
        };
        manifest.manifest_id = digest(&manifest.transcript());
        manifest.signature = signer.sign(&manifest.signature_payload())?;
        Ok(manifest)
    }

    pub(super) fn verify(
        &self,
        vault_id: VaultId,
        device_key_id: DeviceKeyId,
        verifier: &signature::PreparedVerifyingKey,
    ) -> VaultResult<()> {
        if self.version != CURRENT_SCHEMA_VERSION
            || self.vault_id != vault_id
            || self.device_key_id != device_key_id
            || digest(&self.transcript()) != self.manifest_id
        {
            return Err(VaultError::Signature);
        }
        verifier.verify(
            self.signature_algorithm,
            &self.signature_payload(),
            &self.signature,
        )
    }

    fn transcript(&self) -> Vec<u8> {
        let mut bytes = MANIFEST_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.push(self.signature_algorithm.code());
        bytes.extend_from_slice(self.vault_id.as_bytes());
        bytes.extend_from_slice(self.device_key_id.as_bytes());
        bytes.extend_from_slice(&self.document_count.to_be_bytes());
        bytes.extend_from_slice(&self.inventory_digest);
        bytes.push(u8::from(self.repack_pending));
        bytes
    }

    fn signature_payload(&self) -> Vec<u8> {
        let mut bytes = SIGNATURE_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.manifest_id);
        bytes
    }
}

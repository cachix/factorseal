use std::path::Path;
use std::sync::Arc;

use zeroize::Zeroizing;

use super::{
    DocumentKind, DocumentOperation, SecretAddress, UnsealedVault, VaultMetadata, VaultResult,
};

mod bootstrap;
mod chain;
mod database;
mod worker;

use worker::{Command, WorkerControl, request};

#[derive(Clone)]
pub(crate) struct VaultStore {
    control: Arc<WorkerControl>,
    device: VaultMetadata,
}

impl VaultStore {
    /// Open the vault's embedded Turso database and consume its
    /// hardware-unwrapped secrets into the worker.
    pub(crate) fn open(root: impl AsRef<Path>, unsealed: UnsealedVault) -> VaultResult<Self> {
        let root = root.as_ref().to_owned();
        let device = unsealed.public().clone();
        let control = WorkerControl::start(root, unsealed)?;
        Ok(Self {
            control: Arc::new(control),
            device,
        })
    }

    #[must_use]
    pub(crate) const fn device(&self) -> &VaultMetadata {
        &self.device
    }

    /// Stop the sole database worker and zeroize its unsealed key material.
    /// All clones become sealed.
    pub(crate) fn seal(&self) {
        self.control.shutdown();
    }

    #[must_use]
    pub(crate) fn is_sealed(&self) -> bool {
        self.control.is_sealed()
    }

    /// Delete one secret idempotently.
    pub(crate) fn delete(
        &self,
        scope: DocumentKind,
        namespace: &[u8],
        address: &SecretAddress,
    ) -> VaultResult<bool> {
        request(&self.control.sender, |response| Command::Delete {
            scope,
            partition: namespace.to_vec(),
            address: address.clone(),
            response,
        })
    }

    /// Clear every secret from one scoped document.
    pub(crate) fn clear(&self, scope: DocumentKind, namespace: &[u8]) -> VaultResult<usize> {
        request(&self.control.sender, |response| Command::Clear {
            scope,
            partition: namespace.to_vec(),
            response,
        })
    }

    pub(crate) fn get_at(
        &self,
        scope: DocumentKind,
        namespace: &[u8],
        address: &SecretAddress,
        now: u64,
    ) -> VaultResult<Option<Zeroizing<Vec<u8>>>> {
        request(&self.control.sender, |response| Command::Get {
            scope,
            partition: namespace.to_vec(),
            address: address.clone(),
            now,
            response,
        })
    }

    pub(crate) fn put_at(
        &self,
        scope: DocumentKind,
        namespace: &[u8],
        address: &SecretAddress,
        value: &[u8],
        evict_at: Option<u64>,
    ) -> VaultResult<()> {
        request(&self.control.sender, |response| Command::Put {
            scope,
            partition: namespace.to_vec(),
            address: address.clone(),
            value: Zeroizing::new(value.to_vec()),
            evict_at,
            response,
        })
    }

    /// Apply several changes to one namespace as one encrypted and signed
    /// document generation. This is used when a higher-level adapter owns
    /// related records that must not become independently durable.
    pub(crate) fn mutate(
        &self,
        scope: DocumentKind,
        namespace: &[u8],
        operations: Vec<DocumentOperation>,
    ) -> VaultResult<()> {
        request(&self.control.sender, |response| Command::Mutate {
            scope,
            partition: namespace.to_vec(),
            operations,
            response,
        })
    }

    pub(crate) fn purge_expired_at(&self, now: u64) -> VaultResult<usize> {
        request(&self.control.sender, |response| Command::PurgeExpired {
            now,
            response,
        })
    }
}

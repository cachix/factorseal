use std::path::Path;
use std::sync::Arc;

use zeroize::Zeroizing;

use super::{
    DocumentKind, DocumentOperation, HistoryEntry, Provenance, SecretAddress, UnsealedVault,
    VaultEntryMetadata, VaultMetadata, VaultResult,
};

mod bootstrap;
mod chain;

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_commit(bytes: &[u8]) {
    use std::sync::OnceLock;
    static KEY: OnceLock<(super::DeviceKeyId, super::signature::PreparedVerifyingKey)> =
        OnceLock::new();
    let (id, key) = KEY.get_or_init(|| {
        let bytes = super::signature::public_key_for_seed(&[0; 32]);
        (
            super::DeviceKeyId::for_public_key(&bytes),
            super::signature::PreparedVerifyingKey::new(&bytes).unwrap(),
        )
    });
    if let Ok(commit) = serde_json::from_slice::<chain::ProtectedCommit>(bytes) {
        let _ = commit.verify(commit.commit_id, *id, key);
    }
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_commit_seed() -> Vec<u8> {
    let key = super::signature::public_key_for_seed(&[0; 32]);
    serde_json::to_vec(
        &chain::ProtectedCommit::new(
            chain::CommitContents {
                previous_commit_id: None,
                vault_id: super::VaultId::from_bytes([0; 16]),
                document_id: super::DocumentId::from_bytes([0; 32]),
                scope: super::DocumentKind::LocalKeyring,
                generation: 0,
                key_epoch: 0,
                wrapped_key_digest: [0; 32],
                snapshot_digest: [0; 32],
                next_eviction: None,
                device_key_id: super::DeviceKeyId::for_public_key(&key),
            },
            &[0; 32],
        )
        .unwrap(),
    )
    .unwrap()
}
mod database;
mod migration;
mod worker;
#[cfg(feature = "personal-sync")]
pub(crate) use worker::{PairingCommand, SyncCommand, SyncReply};

pub(crate) use worker::StoredSecret;
use worker::{Command, SecretValues, WorkerControl, request};

#[derive(Clone)]
pub(crate) struct VaultStore {
    control: Arc<WorkerControl>,
    device: VaultMetadata,
}

pub(crate) struct StorePage<T> {
    pub(crate) items: Vec<T>,
    pub(crate) next_cursor: Option<String>,
}

/// One newest-first page of history with the sequence number to continue
/// below, absent on the last page.
pub(crate) struct HistoryPage {
    pub(crate) items: Vec<HistoryEntry>,
    pub(crate) next_before_seq: Option<u64>,
}

impl VaultStore {
    pub(crate) fn export_revision(&self) -> VaultResult<Option<[u8; 32]>> {
        request(&self.control.sender, |response| Command::ExportRevision {
            response,
        })
    }

    pub(crate) fn seal_signal(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.control.seal_signal()
    }

    /// Open the vault's embedded Turso database and consume its
    /// hardware-unwrapped secrets into the worker.
    pub(crate) fn open(root: impl AsRef<Path>, unsealed: UnsealedVault) -> VaultResult<Self> {
        let root = root.as_ref().to_owned();
        let device = unsealed.public().clone();
        let control = crate::timing::result("vault_store", "start_worker", || {
            WorkerControl::start(root, unsealed)
        })?;
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

    pub(crate) fn request_seal(&self) {
        self.control.request_shutdown();
    }

    pub(crate) fn set_deadline(&self, deadline: std::time::Instant) -> VaultResult<()> {
        self.control.set_deadline(deadline)
    }

    pub(crate) fn deadline(&self) -> VaultResult<Option<std::time::Instant>> {
        self.control.deadline()
    }

    #[cfg(feature = "vault")]
    pub(crate) fn enable_emergency_exit(&self) {
        self.control.enable_emergency_exit();
    }

    #[must_use]
    pub(crate) fn is_sealed(&self) -> bool {
        self.control.is_sealed()
    }

    #[must_use]
    #[cfg(any(feature = "vault", all(test, feature = "hardware")))]
    pub(crate) fn is_shutdown_complete(&self) -> bool {
        self.control.is_shutdown_complete()
    }

    /// Delete one secret idempotently, recording who asked and when.
    pub(crate) fn delete(
        &self,
        scope: DocumentKind,
        namespace: &[u8],
        address: &SecretAddress,
        provenance: &Provenance,
        now: u64,
    ) -> VaultResult<bool> {
        request(&self.control.sender, |response| Command::Delete {
            scope,
            partition: namespace.to_vec(),
            address: address.clone(),
            provenance: provenance.clone(),
            now,
            response,
        })
    }

    /// Clear every secret from one scoped document.
    pub(crate) fn clear(
        &self,
        scope: DocumentKind,
        namespace: &[u8],
        provenance: &Provenance,
        now: u64,
    ) -> VaultResult<usize> {
        request(&self.control.sender, |response| Command::Clear {
            scope,
            partition: namespace.to_vec(),
            provenance: provenance.clone(),
            now,
            response,
        })
    }

    pub(crate) fn get_at(
        &self,
        scope: DocumentKind,
        namespace: &[u8],
        address: &SecretAddress,
        now: u64,
    ) -> VaultResult<Option<crate::security::LockedBytes>> {
        self.get_with_deadline(scope, namespace, address, now)
            .map(|value| value.map(|secret| secret.value))
    }

    pub(crate) fn get_with_deadline(
        &self,
        scope: DocumentKind,
        namespace: &[u8],
        address: &SecretAddress,
        now: u64,
    ) -> VaultResult<Option<StoredSecret>> {
        request(&self.control.sender, |response| Command::Get {
            scope,
            partition: namespace.to_vec(),
            address: address.clone(),
            now,
            response,
        })
    }

    pub(crate) fn export_at(
        &self,
        scope: DocumentKind,
        namespace: &[u8],
        address: &SecretAddress,
        now: u64,
    ) -> VaultResult<Option<StoredSecret>> {
        self.get_with_deadline(scope, namespace, address, now)
    }

    // Every argument is a distinct, required input of one write.
    #[allow(clippy::too_many_arguments)]
    /// Read several addresses from one document load without writing. An
    /// expired record reads as absent and is left for the eviction sweep, so
    /// an authorization check never commits a generation.
    pub(crate) fn get_many(
        &self,
        scope: DocumentKind,
        namespace: &[u8],
        addresses: &[SecretAddress],
        now: u64,
    ) -> VaultResult<SecretValues> {
        request(&self.control.sender, |response| Command::GetMany {
            scope,
            partition: namespace.to_vec(),
            addresses: addresses.to_vec(),
            now,
            response,
        })
    }

    // Every argument is a distinct, required input of one write.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn put_at(
        &self,
        scope: DocumentKind,
        namespace: &[u8],
        address: &SecretAddress,
        value: &[u8],
        evict_at: Option<u64>,
        provenance: &Provenance,
        now: u64,
    ) -> VaultResult<()> {
        request(&self.control.sender, |response| Command::Put {
            scope,
            partition: namespace.to_vec(),
            address: address.clone(),
            value: Zeroizing::new(value.to_vec()),
            evict_at,
            provenance: provenance.clone(),
            now,
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
        provenance: &Provenance,
        now: u64,
    ) -> VaultResult<()> {
        request(&self.control.sender, |response| Command::Mutate {
            scope,
            partition: namespace.to_vec(),
            operations,
            provenance: provenance.clone(),
            now,
            response,
        })
    }

    pub(crate) fn purge_expired_at(&self, now: u64) -> VaultResult<usize> {
        request(&self.control.sender, |response| Command::PurgeExpired {
            now,
            response,
        })
    }

    pub(crate) fn list_projects(
        &self,
        cursor: Option<&str>,
        limit: u16,
        now: u64,
    ) -> VaultResult<StorePage<String>> {
        request(&self.control.sender, |response| Command::ListProjects {
            cursor: cursor.map(str::to_owned),
            limit,
            now,
            response,
        })
    }

    pub(crate) fn list_project_addresses(
        &self,
        project: &str,
        cursor: Option<&str>,
        limit: u16,
        now: u64,
    ) -> VaultResult<StorePage<super::SecretSpecAddress>> {
        request(&self.control.sender, |response| {
            Command::ListProjectAddresses {
                project: project.to_owned(),
                cursor: cursor.map(str::to_owned),
                limit,
                now,
                response,
            }
        })
    }

    /// List value-free coordinates across user-facing document kinds. The
    /// authorization document is intentionally excluded and exposed through
    /// the permission-management API instead.
    pub(crate) fn list_vault_entries(
        &self,
        cursor: Option<&str>,
        limit: u16,
        now: u64,
    ) -> VaultResult<StorePage<VaultEntryMetadata>> {
        request(&self.control.sender, |response| Command::ListVaultEntries {
            cursor: cursor.map(str::to_owned),
            limit,
            now,
            response,
        })
    }

    /// Recorded changes for one document, newest first. The cursor is the
    /// sequence number below which to continue, so a page never repeats an
    /// entry that a later trim removed.
    pub(crate) fn list_history(
        &self,
        scope: DocumentKind,
        namespace: &[u8],
        address: Option<&SecretAddress>,
        before_seq: Option<u64>,
        limit: u16,
    ) -> VaultResult<HistoryPage> {
        request(&self.control.sender, |response| Command::ListHistory {
            scope,
            partition: namespace.to_vec(),
            address: address.cloned(),
            before_seq,
            limit,
            response,
        })
    }
}

#[cfg(feature = "personal-sync")]
impl VaultStore {
    pub(crate) fn personal_sync(&self, action: SyncCommand) -> VaultResult<SyncReply> {
        request(&self.control.sender, |response| Command::PersonalSync {
            action,
            response,
        })
    }
}

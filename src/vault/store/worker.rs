use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use turso::Connection;
#[cfg(all(test, feature = "hardware"))]
use turso::params;
use zeroize::{Zeroize, Zeroizing};

#[cfg(all(test, feature = "hardware"))]
use crate::vault::{DATABASE_FILE, VaultStore};
use crate::vault::{
    DocumentId, DocumentOperation, DocumentScope, SecretAddress, SecretDocument, SecretRead,
    UnsealedVault, VaultError, VaultMetadata, VaultResult,
};

use super::bootstrap::open_store;
#[cfg(all(test, feature = "hardware"))]
use super::chain::ProtectedCommit;
#[cfg(all(test, feature = "hardware"))]
use super::database::query_count;
use super::database::{database_error, document_id_from_blob, row_blob};

mod integrity;
mod mutation;

const COMMAND_QUEUE: usize = 64;
const MAX_COMMIT_CHAIN: usize = 1_000_000;
/// Chain length that triggers compaction. Every mutation appends a whole
/// encrypted document snapshot plus one signed commit, and startup verifies
/// the whole chain, so an unpruned history grows both the database and unseal
/// latency without bound in the number of writes.
const MAX_RETAINED_COMMITS: usize = 256;

pub(super) struct WorkerControl {
    pub(super) sender: mpsc::SyncSender<Command>,
    join: Mutex<Option<JoinHandle<()>>>,
    sealed: AtomicBool,
}

impl WorkerControl {
    pub(super) fn start(root: PathBuf, unsealed: UnsealedVault) -> VaultResult<Self> {
        let (sender, receiver) = mpsc::sync_channel(COMMAND_QUEUE);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let join = thread::Builder::new()
            .name("factorseal-store".to_owned())
            .spawn(move || run_worker(root, unsealed, receiver, ready_sender))
            .map_err(|error| VaultError::Database(error.to_string()))?;

        match ready_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                sender,
                join: Mutex::new(Some(join)),
                sealed: AtomicBool::new(false),
            }),
            Ok(Err(error)) => {
                let _ = join.join();
                Err(error)
            }
            Err(_) => {
                let _ = join.join();
                Err(VaultError::WorkerUnavailable)
            }
        }
    }

    pub(super) fn shutdown(&self) {
        if self.sealed.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self.sender.send(Command::Shutdown);
        if let Ok(mut join) = self.join.lock()
            && let Some(handle) = join.take()
        {
            let _ = handle.join();
        }
    }

    pub(super) fn is_sealed(&self) -> bool {
        self.sealed.load(Ordering::Acquire)
    }
}

impl Drop for WorkerControl {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub(super) enum Command {
    Get {
        document_id: DocumentId,
        scope: DocumentScope,
        address: SecretAddress,
        now: u64,
        response: mpsc::Sender<VaultResult<Option<Zeroizing<Vec<u8>>>>>,
    },
    Put {
        document_id: DocumentId,
        scope: DocumentScope,
        address: SecretAddress,
        value: Zeroizing<Vec<u8>>,
        evict_at: Option<u64>,
        response: mpsc::Sender<VaultResult<()>>,
    },
    Mutate {
        document_id: DocumentId,
        scope: DocumentScope,
        operations: Vec<DocumentOperation>,
        response: mpsc::Sender<VaultResult<()>>,
    },
    Delete {
        document_id: DocumentId,
        scope: DocumentScope,
        address: SecretAddress,
        response: mpsc::Sender<VaultResult<bool>>,
    },
    PurgeExpired {
        now: u64,
        response: mpsc::Sender<VaultResult<usize>>,
    },
    Clear {
        document_id: DocumentId,
        scope: DocumentScope,
        response: mpsc::Sender<VaultResult<usize>>,
    },
    Shutdown,
}

pub(super) fn request<T>(
    sender: &mpsc::SyncSender<Command>,
    command: impl FnOnce(mpsc::Sender<VaultResult<T>>) -> Command,
) -> VaultResult<T> {
    let (response_sender, response_receiver) = mpsc::channel();
    sender
        .send(command(response_sender))
        .map_err(|_| VaultError::WorkerUnavailable)?;
    response_receiver
        .recv()
        .map_err(|_| VaultError::WorkerUnavailable)?
}

#[allow(clippy::needless_pass_by_value)]
fn run_worker(
    root: PathBuf,
    unsealed: UnsealedVault,
    receiver: mpsc::Receiver<Command>,
    ready: mpsc::SyncSender<VaultResult<()>>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready.send(Err(VaultError::Database(error.to_string())));
            return;
        }
    };
    let mut worker = match runtime.block_on(StoreWorker::open(&root, unsealed)) {
        Ok(worker) => worker,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    if ready.send(Ok(())).is_err() {
        return;
    }
    while let Ok(command) = receiver.recv() {
        match command {
            Command::Get {
                document_id,
                scope,
                address,
                now,
                response,
            } => {
                let result = runtime.block_on(worker.get(document_id, scope, &address, now));
                let _ = response.send(result);
            }
            Command::Put {
                document_id,
                scope,
                address,
                value,
                evict_at,
                response,
            } => {
                let result =
                    runtime.block_on(worker.put(document_id, scope, &address, &value, evict_at));
                let _ = response.send(result);
            }
            Command::Mutate {
                document_id,
                scope,
                operations,
                response,
            } => {
                let result = runtime.block_on(worker.mutate(document_id, scope, &operations));
                let _ = response.send(result);
            }
            Command::Delete {
                document_id,
                scope,
                address,
                response,
            } => {
                let result = runtime.block_on(worker.delete(document_id, scope, &address));
                let _ = response.send(result);
            }
            Command::PurgeExpired { now, response } => {
                let result = runtime.block_on(worker.purge_expired(now));
                let _ = response.send(result);
            }
            Command::Clear {
                document_id,
                scope,
                response,
            } => {
                let result = runtime.block_on(worker.clear(document_id, scope));
                let _ = response.send(result);
            }
            Command::Shutdown => break,
        }
    }
}

struct StoreWorker {
    connection: Connection,
    device: VaultMetadata,
    data_key: Zeroizing<[u8; 32]>,
    signing_seed: Zeroizing<[u8; 32]>,
    lock_file: fs::File,
    chain_length: usize,
}

/// One row of `documents`, which always describes the document's current
/// state rather than any earlier generation.
struct DocumentRow {
    document_id: DocumentId,
    scope: DocumentScope,
    generation: u64,
    key_epoch: u64,
    current_commit_id: [u8; 32],
}

struct LoadedDocument {
    document: SecretDocument,
    generation: u64,
    key_epoch: u64,
}

impl StoreWorker {
    async fn open(root: &Path, unsealed: UnsealedVault) -> VaultResult<Self> {
        let opened = open_store(root, unsealed).await?;
        let mut worker = Self {
            connection: opened.connection,
            device: opened.device,
            data_key: opened.data_key,
            signing_seed: opened.signing_seed,
            lock_file: opened.lock_file,
            chain_length: 0,
        };
        worker.chain_length = worker.verify_commit_chain().await?;
        worker.purge_expired(unix_time()?).await?;
        // A database written before compaction existed still carries its whole
        // history; shrink it once here so the next unseal is fast.
        worker.compact_if_needed().await?;
        Ok(worker)
    }

    async fn get(
        &mut self,
        document_id: DocumentId,
        scope: DocumentScope,
        address: &SecretAddress,
        now: u64,
    ) -> VaultResult<Option<Zeroizing<Vec<u8>>>> {
        let Some(LoadedDocument {
            mut document,
            generation,
            key_epoch,
        }) = self.load_document(document_id, scope).await?
        else {
            return Ok(None);
        };
        match document.get(address, now)? {
            SecretRead::Missing => Ok(None),
            SecretRead::Value(value) => Ok(Some(Zeroizing::new(value))),
            SecretRead::Conflict => Err(VaultError::Conflict),
            SecretRead::Expired => {
                let mutation = document.delete(address)?.ok_or_else(|| {
                    VaultError::InvalidData("expired secret disappeared during deletion".to_owned())
                })?;
                self.commit_mutation(document_id, scope, Some(generation), key_epoch, mutation)
                    .await?;
                Ok(None)
            }
        }
    }

    async fn put(
        &mut self,
        document_id: DocumentId,
        scope: DocumentScope,
        address: &SecretAddress,
        value: &[u8],
        evict_at: Option<u64>,
    ) -> VaultResult<()> {
        let (mut document, expected_generation, key_epoch) =
            match self.load_document(document_id, scope).await? {
                Some(loaded) => (loaded.document, Some(loaded.generation), loaded.key_epoch),
                None => (
                    SecretDocument::new(self.device.actor_id())?,
                    None,
                    self.device.key_epoch(),
                ),
            };
        let mutation = document.put(address, value, evict_at)?;
        self.commit_mutation(document_id, scope, expected_generation, key_epoch, mutation)
            .await
    }

    async fn mutate(
        &mut self,
        document_id: DocumentId,
        scope: DocumentScope,
        operations: &[DocumentOperation],
    ) -> VaultResult<()> {
        let (mut document, expected_generation, key_epoch) =
            match self.load_document(document_id, scope).await? {
                Some(loaded) => (loaded.document, Some(loaded.generation), loaded.key_epoch),
                None if operations
                    .iter()
                    .any(|operation| matches!(operation, DocumentOperation::Put { .. })) =>
                {
                    (
                        SecretDocument::new(self.device.actor_id())?,
                        None,
                        self.device.key_epoch(),
                    )
                }
                None => return Ok(()),
            };
        let Some(mutation) = document.apply(operations)? else {
            return Ok(());
        };
        self.commit_mutation(document_id, scope, expected_generation, key_epoch, mutation)
            .await
    }

    async fn delete(
        &mut self,
        document_id: DocumentId,
        scope: DocumentScope,
        address: &SecretAddress,
    ) -> VaultResult<bool> {
        let Some(LoadedDocument {
            mut document,
            generation,
            key_epoch,
        }) = self.load_document(document_id, scope).await?
        else {
            return Ok(false);
        };
        let Some(mutation) = document.delete(address)? else {
            return Ok(false);
        };
        self.commit_mutation(document_id, scope, Some(generation), key_epoch, mutation)
            .await?;
        Ok(true)
    }

    async fn purge_expired(&mut self, now: u64) -> VaultResult<usize> {
        let mut rows = self
            .connection
            .query(
                "SELECT document_id FROM documents WHERE scope = 'device-cache'",
                (),
            )
            .await
            .map_err(database_error)?;
        let mut document_ids = Vec::new();
        while let Some(row) = rows.next().await.map_err(database_error)? {
            document_ids.push(document_id_from_blob(&row_blob(&row, 0)?)?);
        }
        drop(rows);

        let mut changed = 0;
        for document_id in document_ids {
            let Some(LoadedDocument {
                mut document,
                generation,
                key_epoch,
            }) = self
                .load_document(document_id, DocumentScope::DeviceCache)
                .await?
            else {
                continue;
            };
            if let Some(mutation) = document.purge_expired(now)? {
                self.commit_mutation(
                    document_id,
                    DocumentScope::DeviceCache,
                    Some(generation),
                    key_epoch,
                    mutation,
                )
                .await?;
                changed += 1;
            }
        }
        Ok(changed)
    }

    async fn clear(&mut self, document_id: DocumentId, scope: DocumentScope) -> VaultResult<usize> {
        let Some(LoadedDocument {
            mut document,
            generation,
            key_epoch,
        }) = self.load_document(document_id, scope).await?
        else {
            return Ok(0);
        };
        let Some((count, mutation)) = document.clear()? else {
            return Ok(0);
        };
        self.commit_mutation(document_id, scope, Some(generation), key_epoch, mutation)
            .await?;
        Ok(count)
    }
}

impl Drop for StoreWorker {
    fn drop(&mut self) {
        self.data_key.zeroize();
        let _ = self.lock_file.unlock();
    }
}

fn unix_time() -> VaultResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| VaultError::Database(error.to_string()))
}

#[cfg(all(test, feature = "hardware"))]
mod tests;

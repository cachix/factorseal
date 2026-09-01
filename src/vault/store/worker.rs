use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use turso::Connection;
#[cfg(all(test, feature = "hardware"))]
use turso::params;
use zeroize::{Zeroize, Zeroizing};

#[cfg(all(test, feature = "hardware"))]
use crate::vault::{DATABASE_FILE, VaultStore};
use crate::vault::{
    DocumentId, DocumentKind, DocumentOperation, SecretAddress, SecretDocument, SecretRead,
    SecretSpecAddress, UnsealedVault, VaultError, VaultMetadata, VaultResult,
};

use super::StorePage;
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
    shutdown_complete: AtomicBool,
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
                shutdown_complete: AtomicBool::new(false),
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
        if !self.sealed.swap(true, Ordering::AcqRel) {
            let _ = self.sender.send(Command::Shutdown);
        }
        let Ok(mut join) = self.join.lock() else {
            return;
        };
        if let Some(handle) = join.take() {
            let _ = handle.join();
        }
        // Concurrent callers must not observe sealing as complete until the
        // caller that took the join handle has finished waiting for it. The
        // join mutex provides that hand-off even when this caller did not
        // initiate shutdown.
        self.shutdown_complete.store(true, Ordering::Release);
    }

    pub(super) fn is_sealed(&self) -> bool {
        self.sealed.load(Ordering::Acquire)
    }

    pub(super) fn is_shutdown_complete(&self) -> bool {
        self.shutdown_complete.load(Ordering::Acquire)
    }
}

impl Drop for WorkerControl {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub(super) enum Command {
    Get {
        scope: DocumentKind,
        partition: Vec<u8>,
        address: SecretAddress,
        now: u64,
        response: mpsc::Sender<VaultResult<Option<Zeroizing<Vec<u8>>>>>,
    },
    Put {
        scope: DocumentKind,
        partition: Vec<u8>,
        address: SecretAddress,
        value: Zeroizing<Vec<u8>>,
        evict_at: Option<u64>,
        response: mpsc::Sender<VaultResult<()>>,
    },
    Mutate {
        scope: DocumentKind,
        partition: Vec<u8>,
        operations: Vec<DocumentOperation>,
        response: mpsc::Sender<VaultResult<()>>,
    },
    Delete {
        scope: DocumentKind,
        partition: Vec<u8>,
        address: SecretAddress,
        response: mpsc::Sender<VaultResult<bool>>,
    },
    PurgeExpired {
        now: u64,
        response: mpsc::Sender<VaultResult<usize>>,
    },
    Clear {
        scope: DocumentKind,
        partition: Vec<u8>,
        response: mpsc::Sender<VaultResult<usize>>,
    },
    ListProjects {
        cursor: Option<String>,
        limit: u16,
        now: u64,
        response: mpsc::Sender<VaultResult<StorePage<String>>>,
    },
    ListProjectAddresses {
        project: String,
        cursor: Option<String>,
        limit: u16,
        now: u64,
        response: mpsc::Sender<VaultResult<StorePage<SecretSpecAddress>>>,
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
        if !execute_command(&runtime, &mut worker, command) {
            break;
        }
    }
}

fn execute_command(
    runtime: &tokio::runtime::Runtime,
    worker: &mut StoreWorker,
    command: Command,
) -> bool {
    match command {
        Command::Get {
            scope,
            partition,
            address,
            now,
            response,
        } => {
            let document_id = worker.document_id(scope, &partition);
            let result =
                runtime.block_on(worker.get(document_id, scope, &partition, &address, now));
            let _ = response.send(result);
        }
        Command::Put {
            scope,
            partition,
            address,
            value,
            evict_at,
            response,
        } => {
            let document_id = worker.document_id(scope, &partition);
            let result = runtime.block_on(worker.put(
                document_id,
                scope,
                &partition,
                &address,
                &value,
                evict_at,
            ));
            let _ = response.send(result);
        }
        Command::Mutate {
            scope,
            partition,
            operations,
            response,
        } => {
            let document_id = worker.document_id(scope, &partition);
            let result =
                runtime.block_on(worker.mutate(document_id, scope, &partition, &operations));
            let _ = response.send(result);
        }
        Command::Delete {
            scope,
            partition,
            address,
            response,
        } => {
            let document_id = worker.document_id(scope, &partition);
            let result = runtime.block_on(worker.delete(document_id, scope, &partition, &address));
            let _ = response.send(result);
        }
        Command::PurgeExpired { now, response } => {
            let result = runtime.block_on(worker.purge_expired(now));
            let _ = response.send(result);
        }
        Command::Clear {
            scope,
            partition,
            response,
        } => {
            let document_id = worker.document_id(scope, &partition);
            let result = runtime.block_on(worker.clear(document_id, scope, &partition));
            let _ = response.send(result);
        }
        Command::ListProjects {
            cursor,
            limit,
            now,
            response,
        } => {
            let result = runtime.block_on(worker.list_projects(cursor.as_deref(), limit, now));
            let _ = response.send(result);
        }
        Command::ListProjectAddresses {
            project,
            cursor,
            limit,
            now,
            response,
        } => {
            let result = runtime.block_on(worker.list_project_addresses(
                &project,
                cursor.as_deref(),
                limit,
                now,
            ));
            let _ = response.send(result);
        }
        Command::Shutdown => return false,
    }
    true
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
    scope: DocumentKind,
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
    fn document_id(&self, kind: DocumentKind, partition: &[u8]) -> DocumentId {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.data_key.as_ref())
            .expect("HMAC accepts a 256-bit vault index key");
        mac.update(b"factorseal/document-id/v1\0");
        mac.update(kind.as_str().as_bytes());
        mac.update(&(partition.len() as u64).to_be_bytes());
        mac.update(partition);
        DocumentId::from_bytes(mac.finalize().into_bytes().into())
    }

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
        scope: DocumentKind,
        partition: &[u8],
        address: &SecretAddress,
        now: u64,
    ) -> VaultResult<Option<Zeroizing<Vec<u8>>>> {
        let Some(LoadedDocument {
            mut document,
            generation,
            key_epoch,
        }) = self
            .load_document(document_id, scope, Some(partition))
            .await?
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
        scope: DocumentKind,
        partition: &[u8],
        address: &SecretAddress,
        value: &[u8],
        evict_at: Option<u64>,
    ) -> VaultResult<()> {
        let (mut document, expected_generation, key_epoch) = match self
            .load_document(document_id, scope, Some(partition))
            .await?
        {
            Some(loaded) => (loaded.document, Some(loaded.generation), loaded.key_epoch),
            None => (
                SecretDocument::new(self.device.actor_id(), scope, partition)?,
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
        scope: DocumentKind,
        partition: &[u8],
        operations: &[DocumentOperation],
    ) -> VaultResult<()> {
        let (mut document, expected_generation, key_epoch) = match self
            .load_document(document_id, scope, Some(partition))
            .await?
        {
            Some(loaded) => (loaded.document, Some(loaded.generation), loaded.key_epoch),
            None if operations
                .iter()
                .any(|operation| matches!(operation, DocumentOperation::Put { .. })) =>
            {
                (
                    SecretDocument::new(self.device.actor_id(), scope, partition)?,
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
        scope: DocumentKind,
        partition: &[u8],
        address: &SecretAddress,
    ) -> VaultResult<bool> {
        let Some(LoadedDocument {
            mut document,
            generation,
            key_epoch,
        }) = self
            .load_document(document_id, scope, Some(partition))
            .await?
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
                "SELECT document_id FROM documents WHERE document_kind = 'secretspec-provider-cache'",
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
                .load_document(document_id, DocumentKind::SecretSpecProviderCache, None)
                .await?
            else {
                continue;
            };
            if let Some(mutation) = document.purge_expired(now)? {
                self.commit_mutation(
                    document_id,
                    DocumentKind::SecretSpecProviderCache,
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

    async fn clear(
        &mut self,
        document_id: DocumentId,
        scope: DocumentKind,
        partition: &[u8],
    ) -> VaultResult<usize> {
        let Some(LoadedDocument {
            mut document,
            generation,
            key_epoch,
        }) = self
            .load_document(document_id, scope, Some(partition))
            .await?
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

    async fn list_projects(
        &mut self,
        cursor: Option<&str>,
        limit: u16,
        now: u64,
    ) -> VaultResult<StorePage<String>> {
        let mut rows = self
            .connection
            .query(
                "SELECT document_id FROM documents WHERE document_kind = 'secretspec-project'",
                (),
            )
            .await
            .map_err(database_error)?;
        let mut document_ids = Vec::new();
        while let Some(row) = rows.next().await.map_err(database_error)? {
            document_ids.push(document_id_from_blob(&row_blob(&row, 0)?)?);
        }
        drop(rows);

        let mut projects = Vec::with_capacity(document_ids.len());
        for document_id in document_ids {
            let Some(LoadedDocument {
                mut document,
                generation,
                key_epoch,
            }) = self
                .load_document(document_id, DocumentKind::SecretSpecProject, None)
                .await?
            else {
                continue;
            };
            let project = String::from_utf8(document.partition().to_vec()).map_err(|_| {
                VaultError::InvalidData("project document partition is not UTF-8".to_owned())
            })?;
            SecretSpecAddress::convention(&project, "default", "validation")?;
            if let Some(mutation) = document.purge_expired(now)? {
                self.commit_mutation(
                    document_id,
                    DocumentKind::SecretSpecProject,
                    Some(generation),
                    key_epoch,
                    mutation,
                )
                .await?;
            }
            if !document.addresses()?.is_empty() {
                projects.push((project.clone(), project));
            }
        }
        projects.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        if projects.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(VaultError::InvalidData(
                "duplicate durable project partitions".to_owned(),
            ));
        }
        Ok(paginate(projects, cursor, limit))
    }

    async fn list_project_addresses(
        &mut self,
        project: &str,
        cursor: Option<&str>,
        limit: u16,
        now: u64,
    ) -> VaultResult<StorePage<SecretSpecAddress>> {
        let document_id = self.document_id(DocumentKind::SecretSpecProject, project.as_bytes());
        let Some(LoadedDocument {
            mut document,
            generation,
            key_epoch,
        }) = self
            .load_document(
                document_id,
                DocumentKind::SecretSpecProject,
                Some(project.as_bytes()),
            )
            .await?
        else {
            return Ok(StorePage {
                items: Vec::new(),
                next_cursor: None,
            });
        };
        if let Some(mutation) = document.purge_expired(now)? {
            self.commit_mutation(
                document_id,
                DocumentKind::SecretSpecProject,
                Some(generation),
                key_epoch,
                mutation,
            )
            .await?;
        }
        let mut addresses = Vec::new();
        for (storage_key, address) in document.addresses()? {
            let address = address.as_secret_spec().cloned().ok_or_else(|| {
                VaultError::InvalidData(
                    "durable project document contains a local address".to_owned(),
                )
            })?;
            if address
                .project()
                .is_some_and(|address_project| address_project != project)
            {
                return Err(VaultError::InvalidData(
                    "durable project address belongs to another project".to_owned(),
                ));
            }
            addresses.push((storage_key, address));
        }
        Ok(paginate(addresses, cursor, limit))
    }
}

fn paginate<T>(entries: Vec<(String, T)>, cursor: Option<&str>, limit: u16) -> StorePage<T> {
    let mut page: Vec<_> = entries
        .into_iter()
        .filter(|(key, _)| cursor.is_none_or(|cursor| key.as_str() > cursor))
        .take(usize::from(limit) + 1)
        .collect();
    let has_more = page.len() > usize::from(limit);
    if has_more {
        page.pop();
    }
    let next_cursor = has_more.then(|| {
        page.last()
            .expect("a positive page limit returns an item before a cursor")
            .0
            .clone()
    });
    StorePage {
        items: page.into_iter().map(|(_, item)| item).collect(),
        next_cursor,
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

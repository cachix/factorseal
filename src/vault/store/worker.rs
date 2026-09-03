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
use zeroize::Zeroizing;

#[cfg(all(test, feature = "hardware"))]
use crate::vault::{DATABASE_FILE, VaultStore};
use crate::vault::{
    DocumentId, DocumentKind, DocumentOperation, EncryptedSnapshot, HistoryEntry,
    InstallationSecrets, MutationContext, Provenance, SecretAddress, SecretDocument, SecretRead,
    SecretSpecAddress, ServiceReason, UnsealedVault, VaultError, VaultMetadata, VaultResult,
};

use super::bootstrap::open_store;
#[cfg(all(test, feature = "hardware"))]
use super::chain::ProtectedCommit;
#[cfg(all(test, feature = "hardware"))]
use super::database::query_count;
use super::database::{database_error, document_id_from_blob, row_blob, row_text, to_i64};
use super::{HistoryPage, StorePage};

mod integrity;
mod mutation;

const COMMAND_QUEUE: usize = 64;
const MAX_COMMIT_CHAIN: usize = 1_000_000;
/// Chain length that triggers compaction. Every mutation appends a whole
/// encrypted document snapshot plus one signed commit, and startup verifies
/// the whole chain, so an unpruned history grows both the database and unseal
/// latency without bound in the number of writes.
const MAX_RETAINED_COMMITS: usize = 256;
/// Provenance recorded when the store removes a record on its own because
/// its eviction deadline passed.
const EXPIRY: Provenance = Provenance::service(ServiceReason::Expiry);

/// One value per requested address, absent when missing or expired.
pub(super) type SecretValues = Vec<Option<Zeroizing<Vec<u8>>>>;

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
    GetMany {
        scope: DocumentKind,
        partition: Vec<u8>,
        addresses: Vec<SecretAddress>,
        now: u64,
        response: mpsc::Sender<VaultResult<SecretValues>>,
    },
    Put {
        scope: DocumentKind,
        partition: Vec<u8>,
        address: SecretAddress,
        value: Zeroizing<Vec<u8>>,
        evict_at: Option<u64>,
        provenance: Provenance,
        now: u64,
        response: mpsc::Sender<VaultResult<()>>,
    },
    Mutate {
        scope: DocumentKind,
        partition: Vec<u8>,
        operations: Vec<DocumentOperation>,
        provenance: Provenance,
        now: u64,
        response: mpsc::Sender<VaultResult<()>>,
    },
    Delete {
        scope: DocumentKind,
        partition: Vec<u8>,
        address: SecretAddress,
        provenance: Provenance,
        now: u64,
        response: mpsc::Sender<VaultResult<bool>>,
    },
    PurgeExpired {
        now: u64,
        response: mpsc::Sender<VaultResult<usize>>,
    },
    Clear {
        scope: DocumentKind,
        partition: Vec<u8>,
        provenance: Provenance,
        now: u64,
        response: mpsc::Sender<VaultResult<usize>>,
    },
    ListHistory {
        scope: DocumentKind,
        partition: Vec<u8>,
        address: Option<SecretAddress>,
        before_seq: Option<u64>,
        limit: u16,
        response: mpsc::Sender<VaultResult<HistoryPage>>,
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

// One flat dispatch per command keeps every worker entry point visible here.
#[allow(clippy::too_many_lines)]
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
        Command::GetMany {
            scope,
            partition,
            addresses,
            now,
            response,
        } => {
            let document_id = worker.document_id(scope, &partition);
            let result =
                runtime.block_on(worker.get_many(document_id, scope, &partition, &addresses, now));
            let _ = response.send(result);
        }
        Command::Put {
            scope,
            partition,
            address,
            value,
            evict_at,
            provenance,
            now,
            response,
        } => {
            let document_id = worker.document_id(scope, &partition);
            let context = worker.context(&provenance, now);
            let result = runtime.block_on(worker.put(
                document_id,
                scope,
                &partition,
                &address,
                &value,
                evict_at,
                &context,
            ));
            let _ = response.send(result);
        }
        Command::Mutate {
            scope,
            partition,
            operations,
            provenance,
            now,
            response,
        } => {
            let document_id = worker.document_id(scope, &partition);
            let context = worker.context(&provenance, now);
            let result = runtime.block_on(worker.mutate(
                document_id,
                scope,
                &partition,
                &operations,
                &context,
            ));
            let _ = response.send(result);
        }
        Command::Delete {
            scope,
            partition,
            address,
            provenance,
            now,
            response,
        } => {
            let document_id = worker.document_id(scope, &partition);
            let context = worker.context(&provenance, now);
            let result =
                runtime.block_on(worker.delete(document_id, scope, &partition, &address, &context));
            let _ = response.send(result);
        }
        Command::PurgeExpired { now, response } => {
            let result = runtime.block_on(worker.purge_expired(now));
            let _ = response.send(result);
        }
        Command::Clear {
            scope,
            partition,
            provenance,
            now,
            response,
        } => {
            let document_id = worker.document_id(scope, &partition);
            let context = worker.context(&provenance, now);
            let result = runtime.block_on(worker.clear(document_id, scope, &partition, &context));
            let _ = response.send(result);
        }
        Command::ListHistory {
            scope,
            partition,
            address,
            before_seq,
            limit,
            response,
        } => {
            let document_id = worker.document_id(scope, &partition);
            let result = runtime.block_on(worker.list_history(
                document_id,
                scope,
                &partition,
                address.as_ref(),
                before_seq,
                limit,
            ));
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
    secrets: InstallationSecrets,
    lock_file: fs::File,
    chain_length: usize,
}

/// One row of `documents`, which always describes the document's current
/// state rather than any earlier generation.
struct DocumentRow {
    vault_id: crate::vault::VaultId,
    document_id: DocumentId,
    scope: DocumentKind,
    generation: u64,
    key_epoch: u64,
    wrapped_key_digest: [u8; 32],
    current_commit_id: [u8; 32],
}

struct LoadedDocument {
    document: SecretDocument,
    head: DocumentHead,
}

/// Persisted position of one document. A mutation compares and swaps against
/// it, so one generation can never be written twice and the wrapped key it
/// replaces is exactly the one that was loaded. It keeps the verified
/// envelope and its unwrapped key so a mutation can carry the history log
/// forward without loading the document a second time.
struct DocumentHead {
    generation: u64,
    key_epoch: u64,
    wrapped_dek: Vec<u8>,
    envelope: EncryptedSnapshot,
    data_key: Zeroizing<[u8; 32]>,
}

impl StoreWorker {
    fn context<'a>(&self, provenance: &'a Provenance, now: u64) -> MutationContext<'a> {
        MutationContext {
            now,
            provenance,
            device_key_id: self.device.device_key_id(),
        }
    }

    fn document_id(&self, kind: DocumentKind, partition: &[u8]) -> DocumentId {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.secrets.index_key())
            .expect("HMAC accepts a 256-bit vault index key");
        mac.update(b"factorseal/document-id/v3\0");
        mac.update(self.device.device_vault_id().as_bytes());
        mac.update(&(kind.as_str().len() as u64).to_be_bytes());
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
            secrets: opened.secrets,
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
        let Some(LoadedDocument { mut document, head }) = self
            .load_document(document_id, scope, Some(partition))
            .await?
        else {
            return Ok(None);
        };
        match document.get(address, now)? {
            SecretRead::Missing => Ok(None),
            SecretRead::Value(value) => Ok(Some(value)),
            SecretRead::Conflict => Err(VaultError::Conflict),
            SecretRead::Expired => {
                let expiry = EXPIRY;
                let context = self.context(&expiry, now);
                let mutation = document.expire(address)?.ok_or_else(|| {
                    VaultError::InvalidData("expired secret disappeared during deletion".to_owned())
                })?;
                self.commit_mutation(document_id, scope, Some(head), mutation, &context)
                    .await?;
                Ok(None)
            }
        }
    }

    /// Read several addresses from one document load. Unlike `get`, this
    /// never writes: an expired record reads as absent and is left for the
    /// eviction sweep.
    async fn get_many(
        &mut self,
        document_id: DocumentId,
        scope: DocumentKind,
        partition: &[u8],
        addresses: &[SecretAddress],
        now: u64,
    ) -> VaultResult<SecretValues> {
        let Some(LoadedDocument { document, .. }) = self
            .load_document(document_id, scope, Some(partition))
            .await?
        else {
            return Ok(addresses.iter().map(|_| None).collect());
        };
        addresses
            .iter()
            .map(|address| match document.get(address, now)? {
                SecretRead::Value(value) => Ok(Some(value)),
                SecretRead::Missing | SecretRead::Expired => Ok(None),
                SecretRead::Conflict => Err(VaultError::Conflict),
            })
            .collect()
    }

    // Every argument is a distinct, required input of one write.
    #[allow(clippy::too_many_arguments)]
    async fn put(
        &mut self,
        document_id: DocumentId,
        scope: DocumentKind,
        partition: &[u8],
        address: &SecretAddress,
        value: &[u8],
        evict_at: Option<u64>,
        context: &MutationContext<'_>,
    ) -> VaultResult<()> {
        let (mut document, head) = match self
            .load_document(document_id, scope, Some(partition))
            .await?
        {
            Some(loaded) => (loaded.document, Some(loaded.head)),
            None => (
                SecretDocument::new(self.device.actor_id(), scope, partition)?,
                None,
            ),
        };
        let mutation = document.put(address, value, evict_at, context)?;
        self.commit_mutation(document_id, scope, head, mutation, context)
            .await
    }

    async fn mutate(
        &mut self,
        document_id: DocumentId,
        scope: DocumentKind,
        partition: &[u8],
        operations: &[DocumentOperation],
        context: &MutationContext<'_>,
    ) -> VaultResult<()> {
        let (mut document, head) = match self
            .load_document(document_id, scope, Some(partition))
            .await?
        {
            Some(loaded) => (loaded.document, Some(loaded.head)),
            None if operations
                .iter()
                .any(|operation| matches!(operation, DocumentOperation::Put { .. })) =>
            {
                (
                    SecretDocument::new(self.device.actor_id(), scope, partition)?,
                    None,
                )
            }
            None => return Ok(()),
        };
        let Some(mutation) = document.apply(operations, context)? else {
            return Ok(());
        };
        self.commit_mutation(document_id, scope, head, mutation, context)
            .await
    }

    async fn delete(
        &mut self,
        document_id: DocumentId,
        scope: DocumentKind,
        partition: &[u8],
        address: &SecretAddress,
        context: &MutationContext<'_>,
    ) -> VaultResult<bool> {
        let Some(LoadedDocument { mut document, head }) = self
            .load_document(document_id, scope, Some(partition))
            .await?
        else {
            return Ok(false);
        };
        let Some(mutation) = document.delete(address)? else {
            return Ok(false);
        };
        self.commit_mutation(document_id, scope, Some(head), mutation, context)
            .await?;
        Ok(true)
    }

    /// Remove every record whose eviction deadline has passed, in every
    /// document kind. Only documents whose row says a deadline is due are
    /// loaded; the row's hint is scheduling metadata, and the decrypted
    /// document decides what is actually expired.
    async fn purge_expired(&mut self, now: u64) -> VaultResult<usize> {
        let mut rows = self
            .connection
            .query(
                "SELECT document_id, document_kind FROM documents
                 WHERE next_eviction IS NOT NULL AND next_eviction <= ?1",
                [to_i64(now)?],
            )
            .await
            .map_err(database_error)?;
        let mut due = Vec::new();
        while let Some(row) = rows.next().await.map_err(database_error)? {
            due.push((
                document_id_from_blob(&row_blob(&row, 0)?)?,
                DocumentKind::parse(&row_text(&row, 1)?)?,
            ));
        }
        drop(rows);

        let expiry = EXPIRY;
        let context = self.context(&expiry, now);
        let mut changed = 0;
        for (document_id, kind) in due {
            let Some(LoadedDocument { mut document, head }) =
                self.load_document(document_id, kind, None).await?
            else {
                continue;
            };
            if let Some(mutation) = document.purge_expired(now)? {
                self.commit_mutation(document_id, kind, Some(head), mutation, &context)
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
        context: &MutationContext<'_>,
    ) -> VaultResult<usize> {
        let Some(LoadedDocument { mut document, head }) = self
            .load_document(document_id, scope, Some(partition))
            .await?
        else {
            return Ok(0);
        };
        let Some((count, mutation)) = document.clear()? else {
            return Ok(0);
        };
        self.commit_mutation(document_id, scope, Some(head), mutation, context)
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

        let expiry = EXPIRY;
        let context = self.context(&expiry, now);
        let mut projects = Vec::with_capacity(document_ids.len());
        for document_id in document_ids {
            let Some(LoadedDocument { mut document, head }) = self
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
                    Some(head),
                    mutation,
                    &context,
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
        let Some(LoadedDocument { mut document, head }) = self
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
            let expiry = EXPIRY;
            let context = self.context(&expiry, now);
            self.commit_mutation(
                document_id,
                DocumentKind::SecretSpecProject,
                Some(head),
                mutation,
                &context,
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

    async fn list_history(
        &mut self,
        document_id: DocumentId,
        scope: DocumentKind,
        partition: &[u8],
        address: Option<&SecretAddress>,
        before_seq: Option<u64>,
        limit: u16,
    ) -> VaultResult<HistoryPage> {
        let Some(log) = self
            .load_history(document_id, scope, Some(partition))
            .await?
        else {
            return Ok(HistoryPage {
                items: Vec::new(),
                next_before_seq: None,
            });
        };
        let mut entries: Vec<HistoryEntry> = log
            .entries()
            .iter()
            .filter(|entry| address.is_none_or(|address| entry.address == *address))
            .filter(|entry| before_seq.is_none_or(|before| entry.seq < before))
            .cloned()
            .collect();
        entries.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.seq));
        let has_more = entries.len() > usize::from(limit);
        entries.truncate(usize::from(limit));
        let next_before_seq = has_more
            .then(|| entries.last().map(|entry| entry.seq))
            .flatten();
        Ok(HistoryPage {
            items: entries,
            next_before_seq,
        })
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

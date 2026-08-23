use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use turso::{Connection, Value, params};
use zeroize::{Zeroize, Zeroizing};

#[cfg(all(test, feature = "hardware"))]
use crate::vault::VaultStore;
use crate::vault::envelope::{EnvelopeContext, encrypt_changes, encrypt_snapshot};
use crate::vault::{
    DATABASE_FILE, DocumentId, DocumentMutation, DocumentOperation, DocumentScope,
    EncryptedSnapshot, SecretAddress, SecretDocument, SecretRead, SignedChangeEnvelope,
    UnsealedVault, VaultError, VaultMetadata, VaultResult, verify_and_decrypt_snapshot,
};

use super::chain::{ProtectedCommit, digest, digest_change_envelopes};
use super::database::{
    array_from_blob, database_error, document_id_from_blob, from_i64, open_lock, query_count,
    query_optional_blob, row_blob, row_integer, row_optional_blob, row_text, to_i64,
};

const SCHEMA_VERSION: u32 = 1;
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

impl StoreWorker {
    async fn open(root: &Path, unsealed: UnsealedVault) -> VaultResult<Self> {
        let lock = open_lock(root)?;
        lock.try_lock_exclusive().map_err(|error| {
            VaultError::Database(format!(
                "another Factorseal vault owns `{}`: {error}",
                root.display()
            ))
        })?;
        let database_path = root.join(DATABASE_FILE);
        let database_exists = database_path
            .try_exists()
            .map_err(|error| VaultError::Database(error.to_string()))?;
        let (device, data_key, signing_seed, initialize_store) = unsealed.into_parts();
        if database_exists == initialize_store {
            let message = if initialize_store {
                "refusing to initialize over a pre-existing vault database"
            } else {
                "initialized vault database is missing"
            };
            return Err(VaultError::Database(message.to_owned()));
        }
        let database_path = database_path.to_str().ok_or_else(|| {
            VaultError::Database("vault database path is not valid Unicode".to_owned())
        })?;
        let database = turso::Builder::new_local(database_path)
            .build()
            .await
            .map_err(database_error)?;
        let connection = database.connect().map_err(database_error)?;
        let mut worker = Self {
            connection,
            device,
            data_key,
            signing_seed,
            lock_file: lock,
            chain_length: 0,
        };
        if initialize_store {
            worker.initialize_schema().await?;
            worker.insert_installation_row().await?;
        } else {
            worker.verify_schema().await?;
        }
        worker.verify_installation_row().await?;
        worker.chain_length = worker.verify_commit_chain().await?;
        worker.purge_expired(unix_time()?).await?;
        // A database written before compaction existed still carries its whole
        // history; shrink it once here so the next unseal is fast.
        worker.compact_if_needed().await?;
        Ok(worker)
    }

    async fn initialize_schema(&self) -> VaultResult<()> {
        self.connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS store_meta (
                     key TEXT PRIMARY KEY NOT NULL,
                     value BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS vault_identity (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     vault_id BLOB NOT NULL,
                     device_key_id BLOB NOT NULL,
                     public_signing_key BLOB NOT NULL,
                     actor_id BLOB NOT NULL,
                     hardware_backend TEXT NOT NULL,
                     key_epoch INTEGER NOT NULL,
                     created_at INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS documents (
                     document_id BLOB PRIMARY KEY NOT NULL,
                     scope TEXT NOT NULL,
                     generation INTEGER NOT NULL,
                     key_epoch INTEGER NOT NULL,
                     current_commit_id BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS document_snapshots (
                     document_id BLOB NOT NULL,
                     generation INTEGER NOT NULL,
                     envelope BLOB NOT NULL,
                     PRIMARY KEY (document_id, generation),
                     FOREIGN KEY (document_id) REFERENCES documents(document_id)
                 );
                 CREATE TABLE IF NOT EXISTS document_changes (
                     document_id BLOB NOT NULL,
                     change_hash BLOB NOT NULL,
                     generation INTEGER NOT NULL,
                     envelope BLOB NOT NULL,
                     PRIMARY KEY (document_id, change_hash),
                     FOREIGN KEY (document_id) REFERENCES documents(document_id)
                 );
                 CREATE TABLE IF NOT EXISTS protected_commits (
                     commit_id BLOB PRIMARY KEY NOT NULL,
                     previous_commit_id BLOB,
                     document_id BLOB NOT NULL,
                     generation INTEGER NOT NULL,
                     record BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS sync_peers (
                     peer_id BLOB PRIMARY KEY NOT NULL,
                     encrypted_state BLOB NOT NULL,
                     updated_at INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS sync_outbox (
                     sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                     document_id BLOB NOT NULL,
                     encrypted_envelope BLOB NOT NULL,
                     created_at INTEGER NOT NULL
                 );",
            )
            .await
            .map_err(database_error)?;

        let schema = SCHEMA_VERSION.to_be_bytes().to_vec();
        self.connection
            .execute(
                "INSERT OR IGNORE INTO store_meta(key, value) VALUES ('schema-version', ?1)",
                [schema.clone()],
            )
            .await
            .map_err(database_error)?;
        let stored = query_optional_blob(
            &self.connection,
            "SELECT value FROM store_meta WHERE key = 'schema-version'",
            (),
        )
        .await?
        .ok_or_else(|| VaultError::Database("missing schema version".to_owned()))?;
        if stored != schema {
            return Err(VaultError::Database(
                "unsupported vault database schema version".to_owned(),
            ));
        }
        Ok(())
    }

    async fn verify_schema(&self) -> VaultResult<()> {
        let schema = SCHEMA_VERSION.to_be_bytes().to_vec();
        let stored = query_optional_blob(
            &self.connection,
            "SELECT value FROM store_meta WHERE key = 'schema-version'",
            (),
        )
        .await?
        .ok_or_else(|| VaultError::Database("missing schema version".to_owned()))?;
        if stored != schema {
            return Err(VaultError::Database(
                "unsupported vault database schema version".to_owned(),
            ));
        }
        Ok(())
    }

    async fn insert_installation_row(&self) -> VaultResult<()> {
        self.connection
            .execute(
                "INSERT INTO vault_identity(
                     singleton, vault_id, device_key_id, public_signing_key,
                     actor_id, hardware_backend, key_epoch, created_at
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    self.device.vault_id().as_bytes().to_vec(),
                    self.device.device_key_id().as_bytes().to_vec(),
                    self.device.public_signing_key().to_vec(),
                    self.device.actor_id().to_vec(),
                    self.device.hardware_backend(),
                    to_i64(self.device.key_epoch())?,
                    to_i64(self.device.created_at())?,
                ],
            )
            .await
            .map_err(database_error)?;
        Ok(())
    }

    async fn verify_installation_row(&self) -> VaultResult<()> {
        let mut rows = self
            .connection
            .query(
                "SELECT vault_id, device_key_id, public_signing_key, actor_id,
                        hardware_backend, key_epoch, created_at
                 FROM vault_identity WHERE singleton = 1",
                (),
            )
            .await
            .map_err(database_error)?;
        let row = rows
            .next()
            .await
            .map_err(database_error)?
            .ok_or_else(|| VaultError::Database("missing vault identity row".to_owned()))?;
        let matches = row_blob(&row, 0)? == self.device.vault_id().as_bytes()
            && row_blob(&row, 1)? == self.device.device_key_id().as_bytes()
            && row_blob(&row, 2)? == self.device.public_signing_key()
            && row_blob(&row, 3)? == self.device.actor_id()
            && row_text(&row, 4)? == self.device.hardware_backend()
            && row_integer(&row, 5)? == to_i64(self.device.key_epoch())?
            && row_integer(&row, 6)? == to_i64(self.device.created_at())?;
        if !matches {
            return Err(VaultError::Database(
                "database belongs to a different vault".to_owned(),
            ));
        }
        Ok(())
    }

    async fn get(
        &mut self,
        document_id: DocumentId,
        scope: DocumentScope,
        address: &SecretAddress,
        now: u64,
    ) -> VaultResult<Option<Zeroizing<Vec<u8>>>> {
        let Some((mut document, generation, key_epoch)) =
            self.load_document(document_id, scope).await?
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
        let loaded = self.load_document(document_id, scope).await?;
        let (mut document, expected_generation, key_epoch) = match loaded {
            Some((document, generation, key_epoch)) => (document, Some(generation), key_epoch),
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
        let loaded = self.load_document(document_id, scope).await?;
        let (mut document, expected_generation, key_epoch) = match loaded {
            Some((document, generation, key_epoch)) => (document, Some(generation), key_epoch),
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
        let Some((mut document, generation, key_epoch)) =
            self.load_document(document_id, scope).await?
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
            let Some((mut document, generation, key_epoch)) = self
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
        let Some((mut document, generation, key_epoch)) =
            self.load_document(document_id, scope).await?
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

    async fn load_document(
        &self,
        document_id: DocumentId,
        expected_scope: DocumentScope,
    ) -> VaultResult<Option<(SecretDocument, u64, u64)>> {
        let mut rows = self
            .connection
            .query(
                "SELECT scope, generation, key_epoch FROM documents WHERE document_id = ?1",
                [document_id.as_bytes().to_vec()],
            )
            .await
            .map_err(database_error)?;
        let Some(row) = rows.next().await.map_err(database_error)? else {
            return Ok(None);
        };
        let scope = DocumentScope::parse(&row_text(&row, 0)?)?;
        let generation = from_i64(row_integer(&row, 1)?, "document generation")?;
        let key_epoch = from_i64(row_integer(&row, 2)?, "document key epoch")?;
        if scope != expected_scope {
            return Err(VaultError::InvalidData(
                "document scope does not match requested operation".to_owned(),
            ));
        }
        drop(rows);

        let envelope_bytes = query_optional_blob(
            &self.connection,
            "SELECT envelope FROM document_snapshots
             WHERE document_id = ?1 AND generation = ?2",
            params![document_id.as_bytes().to_vec(), to_i64(generation)?],
        )
        .await?
        .ok_or_else(|| VaultError::InvalidData("document has no current snapshot".to_owned()))?;
        let envelope: EncryptedSnapshot = serde_json::from_slice(&envelope_bytes)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        if envelope.document_id() != document_id
            || envelope.scope() != scope
            || envelope.generation() != generation
            || envelope.key_epoch() != key_epoch
        {
            return Err(VaultError::InvalidData(
                "snapshot metadata does not match document row".to_owned(),
            ));
        }
        let snapshot = verify_and_decrypt_snapshot(
            &envelope,
            self.device.device_key_id(),
            self.device.public_signing_key(),
            &self.data_key,
        )?;
        let document = SecretDocument::load(&snapshot, self.device.actor_id())?;
        Ok(Some((document, generation, key_epoch)))
    }

    #[allow(clippy::too_many_lines)]
    async fn commit_mutation(
        &mut self,
        document_id: DocumentId,
        scope: DocumentScope,
        expected_generation: Option<u64>,
        key_epoch: u64,
        mutation: DocumentMutation,
    ) -> VaultResult<()> {
        let generation = expected_generation.map_or(1, |value| value.saturating_add(1));
        if generation == u64::MAX {
            return Err(VaultError::InvalidData(
                "document generation is exhausted".to_owned(),
            ));
        }
        let context = EnvelopeContext {
            document_id,
            scope,
            device_key_id: self.device.device_key_id(),
            actor_id: self.device.actor_id(),
            generation,
            key_epoch,
        };
        let snapshot = encrypt_snapshot(
            &context,
            &mutation.heads,
            &mutation.snapshot,
            &self.data_key,
            &self.signing_seed,
        )?;
        let changes = encrypt_changes(
            &context,
            &mutation.changes,
            &self.data_key,
            &self.signing_seed,
        )?;
        let snapshot_bytes = serde_json::to_vec(&snapshot)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        let change_bytes: Vec<Vec<u8>> = changes
            .iter()
            .map(|change| {
                serde_json::to_vec(change)
                    .map_err(|error| VaultError::InvalidData(error.to_string()))
            })
            .collect::<VaultResult<_>>()?;
        let previous_commit_id = self.current_commit_head().await?;
        let protected_commit = ProtectedCommit::new(
            previous_commit_id,
            document_id,
            scope,
            generation,
            key_epoch,
            digest(&snapshot_bytes),
            digest_change_envelopes(&changes, &change_bytes),
            self.device.device_key_id(),
            &self.signing_seed,
        )?;
        let protected_bytes = serde_json::to_vec(&protected_commit)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;

        let transaction = self
            .connection
            .transaction()
            .await
            .map_err(database_error)?;
        match expected_generation {
            Some(expected) => {
                let updated = transaction
                    .execute(
                        "UPDATE documents SET generation = ?1, key_epoch = ?2,
                              current_commit_id = ?3
                         WHERE document_id = ?4 AND generation = ?5 AND scope = ?6",
                        params![
                            to_i64(generation)?,
                            to_i64(key_epoch)?,
                            protected_commit.commit_id.to_vec(),
                            document_id.as_bytes().to_vec(),
                            to_i64(expected)?,
                            scope.as_str(),
                        ],
                    )
                    .await
                    .map_err(database_error)?;
                if updated != 1 {
                    return Err(VaultError::Database(
                        "document generation changed concurrently".to_owned(),
                    ));
                }
            }
            None => {
                transaction
                    .execute(
                        "INSERT INTO documents(
                             document_id, scope, generation, key_epoch, current_commit_id
                         ) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            document_id.as_bytes().to_vec(),
                            scope.as_str(),
                            to_i64(generation)?,
                            to_i64(key_epoch)?,
                            protected_commit.commit_id.to_vec(),
                        ],
                    )
                    .await
                    .map_err(database_error)?;
            }
        }
        transaction
            .execute(
                "INSERT INTO document_snapshots(document_id, generation, envelope)
                 VALUES (?1, ?2, ?3)",
                params![
                    document_id.as_bytes().to_vec(),
                    to_i64(generation)?,
                    snapshot_bytes,
                ],
            )
            .await
            .map_err(database_error)?;
        for (envelope, bytes) in changes.iter().zip(change_bytes) {
            transaction
                .execute(
                    "INSERT INTO document_changes(document_id, change_hash, generation, envelope)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        document_id.as_bytes().to_vec(),
                        envelope.change_hash().to_vec(),
                        to_i64(generation)?,
                        bytes,
                    ],
                )
                .await
                .map_err(database_error)?;
        }
        transaction
            .execute(
                "INSERT INTO protected_commits(
                     commit_id, previous_commit_id, document_id, generation, record
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    protected_commit.commit_id.to_vec(),
                    protected_commit
                        .previous_commit_id
                        .map_or(Value::Null, |value| Value::Blob(value.to_vec())),
                    document_id.as_bytes().to_vec(),
                    to_i64(generation)?,
                    protected_bytes,
                ],
            )
            .await
            .map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO store_meta(key, value) VALUES ('current-commit-head', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [protected_commit.commit_id.to_vec()],
            )
            .await
            .map_err(database_error)?;
        transaction.commit().await.map_err(database_error)?;
        self.chain_length = self.chain_length.saturating_add(1);
        self.compact_if_needed().await
    }

    async fn current_commit_head(&self) -> VaultResult<Option<[u8; 32]>> {
        query_optional_blob(
            &self.connection,
            "SELECT value FROM store_meta WHERE key = 'current-commit-head'",
            (),
        )
        .await?
        .map(|bytes| array_from_blob(&bytes, "current commit head"))
        .transpose()
    }

    /// Verify the whole protected chain and return the number of commits in it.
    async fn verify_commit_chain(&self) -> VaultResult<usize> {
        let mut current = self.current_commit_head().await?;
        let mut visited = HashSet::new();
        let mut count = 0_usize;
        while let Some(commit_id) = current {
            count += 1;
            if count > MAX_COMMIT_CHAIN || !visited.insert(commit_id) {
                return Err(VaultError::InvalidData(
                    "protected commit chain is cyclic or too long".to_owned(),
                ));
            }
            let record = self.verify_protected_commit(commit_id).await?;
            current = record.previous_commit_id;
        }

        self.verify_protected_row_sets(count).await?;
        self.verify_document_heads(&visited).await?;
        Ok(count)
    }

    async fn verify_protected_commit(&self, commit_id: [u8; 32]) -> VaultResult<ProtectedCommit> {
        let mut rows = self
            .connection
            .query(
                "SELECT previous_commit_id, document_id, generation, record
                 FROM protected_commits WHERE commit_id = ?1",
                [commit_id.to_vec()],
            )
            .await
            .map_err(database_error)?;
        let row = rows.next().await.map_err(database_error)?.ok_or_else(|| {
            VaultError::InvalidData("protected commit chain is incomplete".to_owned())
        })?;
        let stored_previous = row_optional_blob(&row, 0)?
            .map(|bytes| array_from_blob(&bytes, "previous commit ID"))
            .transpose()?;
        let stored_document_id = document_id_from_blob(&row_blob(&row, 1)?)?;
        let stored_generation = from_i64(row_integer(&row, 2)?, "commit generation")?;
        let record_bytes = row_blob(&row, 3)?;
        drop(rows);
        let record: ProtectedCommit = serde_json::from_slice(&record_bytes)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        record.verify(
            commit_id,
            self.device.device_key_id(),
            self.device.public_signing_key(),
        )?;
        if stored_previous != record.previous_commit_id
            || stored_document_id != record.document_id
            || stored_generation != record.generation
        {
            return Err(VaultError::InvalidData(
                "protected commit SQL metadata does not match its signed record".to_owned(),
            ));
        }
        self.verify_protected_commit_payload(&record).await?;
        Ok(record)
    }

    async fn verify_protected_commit_payload(&self, record: &ProtectedCommit) -> VaultResult<()> {
        let snapshot = query_optional_blob(
            &self.connection,
            "SELECT envelope FROM document_snapshots
             WHERE document_id = ?1 AND generation = ?2",
            params![
                record.document_id.as_bytes().to_vec(),
                to_i64(record.generation)?,
            ],
        )
        .await?
        .ok_or_else(|| {
            VaultError::InvalidData("protected commit snapshot is missing".to_owned())
        })?;
        if digest(&snapshot) != record.snapshot_digest {
            return Err(VaultError::Signature);
        }
        let (envelopes, serialized_changes) = self
            .change_envelopes(record.document_id, record.generation)
            .await?;
        if digest_change_envelopes(&envelopes, &serialized_changes) != record.changes_digest {
            return Err(VaultError::Signature);
        }
        Ok(())
    }

    /// Read one generation's change envelopes together with the exact bytes
    /// the commit digest was taken over.
    async fn change_envelopes(
        &self,
        document_id: DocumentId,
        generation: u64,
    ) -> VaultResult<(Vec<SignedChangeEnvelope>, Vec<Vec<u8>>)> {
        let mut rows = self
            .connection
            .query(
                "SELECT envelope FROM document_changes
                 WHERE document_id = ?1 AND generation = ?2 ORDER BY change_hash",
                params![document_id.as_bytes().to_vec(), to_i64(generation)?],
            )
            .await
            .map_err(database_error)?;
        let mut serialized = Vec::new();
        let mut envelopes = Vec::new();
        while let Some(row) = rows.next().await.map_err(database_error)? {
            let bytes = row_blob(&row, 0)?;
            let envelope: SignedChangeEnvelope = serde_json::from_slice(&bytes)
                .map_err(|error| VaultError::InvalidData(error.to_string()))?;
            serialized.push(bytes);
            envelopes.push(envelope);
        }
        Ok((envelopes, serialized))
    }

    async fn verify_protected_row_sets(&self, chain_count: usize) -> VaultResult<()> {
        let commit_count = query_count(
            &self.connection,
            "SELECT COUNT(*) FROM protected_commits",
            (),
        )
        .await?;
        if commit_count != chain_count as u64 {
            return Err(VaultError::InvalidData(
                "database contains commits outside the protected chain".to_owned(),
            ));
        }
        let snapshot_count = query_count(
            &self.connection,
            "SELECT COUNT(*) FROM document_snapshots",
            (),
        )
        .await?;
        if snapshot_count != commit_count {
            return Err(VaultError::InvalidData(
                "database contains missing or uncommitted snapshots".to_owned(),
            ));
        }
        let orphan_changes = query_count(
            &self.connection,
            "SELECT COUNT(*) FROM document_changes AS changes
             WHERE NOT EXISTS (
                 SELECT 1 FROM protected_commits AS commits
                 WHERE commits.document_id = changes.document_id
                   AND commits.generation = changes.generation
             )",
            (),
        )
        .await?;
        if orphan_changes != 0 {
            return Err(VaultError::InvalidData(
                "database contains changes outside the protected chain".to_owned(),
            ));
        }
        Ok(())
    }

    async fn document_rows(&self) -> VaultResult<Vec<DocumentRow>> {
        let mut rows = self
            .connection
            .query(
                "SELECT document_id, scope, generation, key_epoch, current_commit_id
                 FROM documents ORDER BY document_id",
                (),
            )
            .await
            .map_err(database_error)?;
        let mut documents = Vec::new();
        while let Some(row) = rows.next().await.map_err(database_error)? {
            documents.push(DocumentRow {
                document_id: document_id_from_blob(&row_blob(&row, 0)?)?,
                scope: DocumentScope::parse(&row_text(&row, 1)?)?,
                generation: from_i64(row_integer(&row, 2)?, "document generation")?,
                key_epoch: from_i64(row_integer(&row, 3)?, "document key epoch")?,
                current_commit_id: array_from_blob(&row_blob(&row, 4)?, "document commit ID")?,
            });
        }
        Ok(documents)
    }

    async fn verify_document_heads(&self, visited: &HashSet<[u8; 32]>) -> VaultResult<()> {
        for document in self.document_rows().await? {
            if !visited.contains(&document.current_commit_id) {
                return Err(VaultError::InvalidData(
                    "document points outside the protected commit chain".to_owned(),
                ));
            }
            let record = query_optional_blob(
                &self.connection,
                "SELECT record FROM protected_commits WHERE commit_id = ?1",
                [document.current_commit_id.to_vec()],
            )
            .await?
            .ok_or_else(|| VaultError::InvalidData("document commit is missing".to_owned()))?;
            let record: ProtectedCommit = serde_json::from_slice(&record)
                .map_err(|error| VaultError::InvalidData(error.to_string()))?;
            if record.document_id != document.document_id
                || record.scope != document.scope
                || record.generation != document.generation
                || record.key_epoch != document.key_epoch
            {
                return Err(VaultError::InvalidData(
                    "document metadata does not match its signed commit".to_owned(),
                ));
            }
            // Agreeing with the commit it points at is not enough: that commit
            // must also be the document's newest one. Without this a single
            // document can be rewound to any earlier generation while the
            // global head and every row-set count stay consistent.
            let newer = query_count(
                &self.connection,
                "SELECT COUNT(*) FROM protected_commits
                 WHERE document_id = ?1 AND generation > ?2",
                params![
                    document.document_id.as_bytes().to_vec(),
                    to_i64(document.generation)?,
                ],
            )
            .await?;
            if newer != 0 {
                return Err(VaultError::InvalidData(
                    "document is behind its newest protected commit".to_owned(),
                ));
            }
        }
        Ok(())
    }

    async fn compact_if_needed(&mut self) -> VaultResult<()> {
        if self.chain_length <= MAX_RETAINED_COMMITS {
            return Ok(());
        }
        self.compact().await
    }

    /// Replace the commit history with a freshly signed minimal chain that
    /// describes exactly the current state of every document.
    ///
    /// The discarded generations were only ever read by chain verification, so
    /// re-signing preserves every invariant that verification checks: one
    /// commit per document, one snapshot per commit, no change rows outside the
    /// chain, and every document at its newest commit.
    async fn compact(&mut self) -> VaultResult<()> {
        let documents = self.document_rows().await?;
        let commits = self.resign_current_state(&documents).await?;
        self.replace_chain(&documents, &commits).await?;
        self.chain_length = commits.len();
        Ok(())
    }

    /// Sign one commit per document, chained in document order, over the state
    /// those documents are in right now.
    async fn resign_current_state(
        &self,
        documents: &[DocumentRow],
    ) -> VaultResult<Vec<ProtectedCommit>> {
        let mut previous_commit_id = None;
        let mut commits = Vec::with_capacity(documents.len());
        for document in documents {
            let snapshot = query_optional_blob(
                &self.connection,
                "SELECT envelope FROM document_snapshots
                 WHERE document_id = ?1 AND generation = ?2",
                params![
                    document.document_id.as_bytes().to_vec(),
                    to_i64(document.generation)?,
                ],
            )
            .await?
            .ok_or_else(|| {
                VaultError::InvalidData("document has no current snapshot".to_owned())
            })?;
            let (envelopes, serialized) = self
                .change_envelopes(document.document_id, document.generation)
                .await?;
            let commit = ProtectedCommit::new(
                previous_commit_id,
                document.document_id,
                document.scope,
                document.generation,
                document.key_epoch,
                digest(&snapshot),
                digest_change_envelopes(&envelopes, &serialized),
                self.device.device_key_id(),
                &self.signing_seed,
            )?;
            previous_commit_id = Some(commit.commit_id);
            commits.push(commit);
        }
        Ok(commits)
    }

    /// Swap the whole history for `commits` in one transaction, dropping every
    /// superseded snapshot and change along with it.
    async fn replace_chain(
        &mut self,
        documents: &[DocumentRow],
        commits: &[ProtectedCommit],
    ) -> VaultResult<()> {
        let transaction = self
            .connection
            .transaction()
            .await
            .map_err(database_error)?;
        for document in documents {
            for statement in [
                "DELETE FROM document_changes WHERE document_id = ?1 AND generation <> ?2",
                "DELETE FROM document_snapshots WHERE document_id = ?1 AND generation <> ?2",
            ] {
                transaction
                    .execute(
                        statement,
                        params![
                            document.document_id.as_bytes().to_vec(),
                            to_i64(document.generation)?,
                        ],
                    )
                    .await
                    .map_err(database_error)?;
            }
        }
        transaction
            .execute("DELETE FROM protected_commits", ())
            .await
            .map_err(database_error)?;
        for (document, commit) in documents.iter().zip(commits) {
            let record = serde_json::to_vec(commit)
                .map_err(|error| VaultError::InvalidData(error.to_string()))?;
            transaction
                .execute(
                    "INSERT INTO protected_commits(
                         commit_id, previous_commit_id, document_id, generation, record
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        commit.commit_id.to_vec(),
                        commit
                            .previous_commit_id
                            .map_or(Value::Null, |value| Value::Blob(value.to_vec())),
                        document.document_id.as_bytes().to_vec(),
                        to_i64(document.generation)?,
                        record,
                    ],
                )
                .await
                .map_err(database_error)?;
            transaction
                .execute(
                    "UPDATE documents SET current_commit_id = ?1 WHERE document_id = ?2",
                    params![
                        commit.commit_id.to_vec(),
                        document.document_id.as_bytes().to_vec(),
                    ],
                )
                .await
                .map_err(database_error)?;
        }
        match commits.last().map(|commit| commit.commit_id) {
            Some(head) => transaction
                .execute(
                    "INSERT INTO store_meta(key, value) VALUES ('current-commit-head', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [head.to_vec()],
                )
                .await
                .map_err(database_error)?,
            None => transaction
                .execute(
                    "DELETE FROM store_meta WHERE key = 'current-commit-head'",
                    (),
                )
                .await
                .map_err(database_error)?,
        };
        transaction.commit().await.map_err(database_error)
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
mod tests {
    use super::*;
    use crate::vault::Vault;

    fn store() -> (tempfile::TempDir, PathBuf, VaultStore) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        let unsealed = Vault::create_for_test(&root).unwrap();
        let store = VaultStore::open(&root, unsealed).unwrap();
        (directory, root, store)
    }

    fn execute_database_mutation(root: &Path, statement: &str) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let database = turso::Builder::new_local(root.join(DATABASE_FILE).to_str().unwrap())
                .build()
                .await
                .unwrap();
            let connection = database.connect().unwrap();
            connection.execute(statement, ()).await.unwrap();
        });
    }

    fn database_count(root: &Path, sql: &str) -> u64 {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let database = turso::Builder::new_local(root.join(DATABASE_FILE).to_str().unwrap())
                .build()
                .await
                .unwrap();
            let connection = database.connect().unwrap();
            query_count(&connection, sql, ()).await.unwrap()
        })
    }

    fn put_two_generations(store: &VaultStore) -> SecretAddress {
        let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
        store
            .put_at(
                DocumentScope::DeviceCache,
                b"secretspec",
                &address,
                b"first",
                None,
            )
            .unwrap();
        store
            .put_at(
                DocumentScope::DeviceCache,
                b"secretspec",
                &address,
                b"second",
                None,
            )
            .unwrap();
        address
    }

    #[test]
    fn reopening_rejects_a_missing_database() {
        let (_directory, root, store) = store();
        drop(store);
        fs::remove_file(root.join(DATABASE_FILE)).unwrap();

        let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
        assert!(matches!(reopened, Err(VaultError::Database(_))));
    }

    #[test]
    fn reopening_rejects_a_recreated_empty_database() {
        let (_directory, root, store) = store();
        drop(store);
        fs::write(root.join(DATABASE_FILE), []).unwrap();

        let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
        assert!(matches!(reopened, Err(VaultError::Database(_))));
    }

    #[test]
    fn turso_round_trip_restart_and_idempotent_delete() {
        let (_directory, root, store) = store();
        let address = SecretAddress::new("demo/default/API_TOKEN", None).unwrap();
        store
            .put_at(
                DocumentScope::DeviceCache,
                b"secretspec",
                &address,
                b"classified",
                None,
            )
            .unwrap();
        assert_eq!(
            store
                .get_at(DocumentScope::DeviceCache, b"secretspec", &address, 10,)
                .unwrap()
                .unwrap()
                .as_slice(),
            b"classified"
        );
        let expected_device = store.device().clone();
        drop(store);

        let reopened = Vault::unseal_for_test(&root).unwrap();
        let store = VaultStore::open(&root, reopened).unwrap();
        assert_eq!(store.device(), &expected_device);
        assert_eq!(
            store
                .get_at(DocumentScope::DeviceCache, b"secretspec", &address, 10,)
                .unwrap()
                .unwrap()
                .as_slice(),
            b"classified"
        );
        assert!(
            store
                .delete(DocumentScope::DeviceCache, b"secretspec", &address)
                .unwrap()
        );
        assert!(
            !store
                .delete(DocumentScope::DeviceCache, b"secretspec", &address)
                .unwrap()
        );
    }

    #[test]
    fn batch_mutation_commits_related_records_in_one_generation() {
        let (_directory, root, store) = store();
        let first = SecretAddress::new("secret-service/item/first", None).unwrap();
        let index = SecretAddress::new("secret-service/index", None).unwrap();
        store
            .mutate(
                DocumentScope::DeviceLocal,
                b"secret-service",
                vec![
                    DocumentOperation::Put {
                        address: first.clone(),
                        value: Zeroizing::new(b"secret".to_vec()),
                        evict_at: None,
                    },
                    DocumentOperation::Put {
                        address: index.clone(),
                        value: Zeroizing::new(b"index".to_vec()),
                        evict_at: None,
                    },
                ],
            )
            .unwrap();
        drop(store);

        for table in ["documents", "document_snapshots", "protected_commits"] {
            assert_eq!(
                database_count(&root, &format!("SELECT COUNT(*) FROM {table}")),
                1,
                "a batch mutation wrote more than one {table} row"
            );
        }

        let store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
        for (address, expected) in [(first, b"secret".as_slice()), (index, b"index")] {
            assert_eq!(
                store
                    .get_at(DocumentScope::DeviceLocal, b"secret-service", &address, 10)
                    .unwrap()
                    .unwrap()
                    .as_slice(),
                expected
            );
        }
    }

    #[test]
    fn expiration_is_purged_without_read_and_stays_gone() {
        let (_directory, root, store) = store();
        let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
        store
            .put_at(
                DocumentScope::DeviceCache,
                b"secretspec",
                &address,
                b"short-lived",
                Some(50),
            )
            .unwrap();
        assert_eq!(store.purge_expired_at(49).unwrap(), 0);
        assert_eq!(store.purge_expired_at(50).unwrap(), 1);
        drop(store);

        let store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
        assert!(
            store
                .get_at(DocumentScope::DeviceCache, b"secretspec", &address, 50,)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn installation_files_contain_no_secret_or_predictable_name() {
        let (_directory, root, store) = store();
        let address = SecretAddress::new("visible-project/default/API_TOKEN", None).unwrap();
        store
            .put_at(
                DocumentScope::DeviceCache,
                b"secretspec",
                &address,
                b"needle-secret-value",
                None,
            )
            .unwrap();
        drop(store);

        for needle in [
            b"visible-project".as_slice(),
            b"API_TOKEN".as_slice(),
            b"needle-secret-value".as_slice(),
        ] {
            assert_installation_tree_excludes(&root, needle);
        }
    }

    fn assert_installation_tree_excludes(root: &Path, needle: &[u8]) {
        let mut directories = vec![root.to_owned()];
        while let Some(directory) = directories.pop() {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                assert!(
                    !path
                        .as_os_str()
                        .as_encoded_bytes()
                        .windows(needle.len())
                        .any(|window| window == needle),
                    "secret coordinate appeared in a file name"
                );
                let file_type = entry.file_type().unwrap();
                if file_type.is_dir() {
                    directories.push(path);
                } else if file_type.is_file() {
                    let bytes = fs::read(path).unwrap();
                    assert!(
                        !bytes.windows(needle.len()).any(|window| window == needle),
                        "secret material appeared in a vault file"
                    );
                }
            }
        }
    }

    #[test]
    fn one_worker_owns_the_database() {
        let (_directory, root, first) = store();
        let second = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
        assert!(matches!(second, Err(VaultError::Database(_))));
        drop(first);
    }

    #[test]
    fn protected_chain_detects_snapshot_tamper() {
        let (_directory, root, store) = store();
        let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
        store
            .put_at(
                DocumentScope::DeviceCache,
                b"secretspec",
                &address,
                b"value",
                None,
            )
            .unwrap();
        drop(store);

        execute_database_mutation(&root, "UPDATE document_snapshots SET envelope = X'00'");

        let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
        assert!(matches!(
            reopened,
            Err(VaultError::Signature | VaultError::InvalidData(_))
        ));
    }

    #[test]
    fn protected_chain_detects_missing_history() {
        let (_directory, root, store) = store();
        put_two_generations(&store);
        drop(store);
        execute_database_mutation(
            &root,
            "DELETE FROM protected_commits WHERE previous_commit_id IS NULL",
        );

        let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
        assert!(matches!(reopened, Err(VaultError::InvalidData(_))));
    }

    #[test]
    fn protected_chain_detects_rolled_back_head() {
        let (_directory, root, store) = store();
        put_two_generations(&store);
        drop(store);
        execute_database_mutation(
            &root,
            "UPDATE store_meta
             SET value = (
                 SELECT previous_commit_id FROM protected_commits
                 WHERE commit_id = store_meta.value
             )
             WHERE key = 'current-commit-head'",
        );

        let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
        assert!(matches!(reopened, Err(VaultError::InvalidData(_))));
    }

    #[test]
    fn protected_chain_detects_a_rolled_back_document() {
        let (_directory, root, store) = store();
        put_two_generations(&store);
        drop(store);
        // Every global check still passes after this: the chain, the row-set
        // counts, and the document's agreement with the commit it points at.
        // Only the document itself has been rewound a generation.
        execute_database_mutation(
            &root,
            "UPDATE documents
                SET generation = 1,
                    current_commit_id = (
                        SELECT commit_id FROM protected_commits
                        WHERE document_id = documents.document_id AND generation = 1
                    )
              WHERE generation = 2",
        );

        let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
        let Err(VaultError::InvalidData(message)) = reopened else {
            panic!("a rolled-back document must not open");
        };
        assert!(
            message.contains("newest protected commit"),
            "unexpected rejection: {message}"
        );
    }

    #[test]
    fn compaction_bounds_the_chain_and_keeps_every_document_readable() {
        let (_directory, root, store) = store();
        let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
        let namespaces: [&[u8]; 2] = [b"first", b"second"];
        let mut latest = [String::new(), String::new()];
        for generation in 0..=MAX_RETAINED_COMMITS {
            let index = generation % namespaces.len();
            let value = generation.to_string();
            store
                .put_at(
                    DocumentScope::DeviceCache,
                    namespaces[index],
                    &address,
                    value.as_bytes(),
                    None,
                )
                .unwrap();
            latest[index] = value;
        }
        drop(store);

        // Compaction leaves exactly one commit and one snapshot per document,
        // rather than one of each per write.
        let documents = u64::try_from(namespaces.len()).unwrap();
        for table in ["protected_commits", "document_snapshots", "documents"] {
            assert_eq!(
                database_count(&root, &format!("SELECT COUNT(*) FROM {table}")),
                documents,
                "{table} was not compacted"
            );
        }

        let store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
        for (namespace, expected) in namespaces.iter().zip(&latest) {
            assert_eq!(
                store
                    .get_at(DocumentScope::DeviceCache, namespace, &address, 10)
                    .unwrap()
                    .unwrap()
                    .as_slice(),
                expected.as_bytes()
            );
        }
    }

    #[test]
    fn a_compacted_chain_still_detects_snapshot_tamper() {
        let (_directory, root, store) = store();
        let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
        for generation in 0..=MAX_RETAINED_COMMITS {
            store
                .put_at(
                    DocumentScope::DeviceCache,
                    b"secretspec",
                    &address,
                    generation.to_string().as_bytes(),
                    None,
                )
                .unwrap();
        }
        drop(store);
        execute_database_mutation(&root, "UPDATE document_snapshots SET envelope = X'00'");

        let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
        assert!(matches!(
            reopened,
            Err(VaultError::Signature | VaultError::InvalidData(_))
        ));
    }

    #[test]
    fn protected_chain_detects_missing_change() {
        let (_directory, root, store) = store();
        let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
        store
            .put_at(
                DocumentScope::DeviceCache,
                b"secretspec",
                &address,
                b"value",
                None,
            )
            .unwrap();
        drop(store);
        execute_database_mutation(&root, "DELETE FROM document_changes");

        let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
        assert!(matches!(reopened, Err(VaultError::Signature)));
    }

    #[test]
    fn protected_chain_detects_document_scope_tamper() {
        let (_directory, root, store) = store();
        let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
        store
            .put_at(
                DocumentScope::DeviceCache,
                b"secretspec",
                &address,
                b"value",
                None,
            )
            .unwrap();
        drop(store);
        execute_database_mutation(&root, "UPDATE documents SET scope = 'device-local'");

        let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
        assert!(matches!(reopened, Err(VaultError::InvalidData(_))));
    }

    #[test]
    fn protected_chain_detects_commit_record_tamper() {
        let (_directory, root, store) = store();
        let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
        store
            .put_at(
                DocumentScope::DeviceCache,
                b"secretspec",
                &address,
                b"value",
                None,
            )
            .unwrap();
        drop(store);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let database = turso::Builder::new_local(root.join(DATABASE_FILE).to_str().unwrap())
                .build()
                .await
                .unwrap();
            let connection = database.connect().unwrap();
            let mut rows = connection
                .query("SELECT commit_id, record FROM protected_commits", ())
                .await
                .unwrap();
            let row = rows.next().await.unwrap().unwrap();
            let commit_id = row_blob(&row, 0).unwrap();
            let mut record: ProtectedCommit =
                serde_json::from_slice(&row_blob(&row, 1).unwrap()).unwrap();
            record.signature[0] ^= 1;
            drop(rows);
            connection
                .execute(
                    "UPDATE protected_commits SET record = ?1 WHERE commit_id = ?2",
                    params![serde_json::to_vec(&record).unwrap(), commit_id],
                )
                .await
                .unwrap();
        });

        let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
        assert!(matches!(reopened, Err(VaultError::Signature)));
    }
}

//! Document snapshot loading and transactional commit persistence.

use turso::transaction::Transaction;
use turso::{Value, params};

use crate::vault::envelope::{EnvelopeContext, decrypt_history, encrypt_snapshot};
use crate::vault::history::HistoryLog;
use crate::vault::{
    DocumentId, DocumentKind, DocumentMutation, EncryptedSnapshot, MutationContext, SecretDocument,
    VaultError, VaultId, VaultResult, WrappedKey, decrypt_snapshot,
};

use super::{DocumentHead, LoadedDocument, StoreWorker};
use crate::vault::store::chain::{CommitContents, ProtectedCommit, digest};
use crate::vault::store::database::{
    array_from_blob, database_error, from_i64, query_optional_blob, row_blob, row_integer,
    row_text, to_i64,
};

struct PreparedCommit {
    vault_id: VaultId,
    document_id: DocumentId,
    scope: DocumentKind,
    expected: Option<DocumentHead>,
    generation: u64,
    key_epoch: u64,
    wrapped_dek: Vec<u8>,
    snapshot_envelope: Vec<u8>,
    protected_commit: ProtectedCommit,
    protected_record: Vec<u8>,
    next_eviction: Option<u64>,
}

impl StoreWorker {
    /// Load a document's current head: its row, its envelope verified against
    /// the signed commit the row points at, and its unwrapped key. Nothing is
    /// decrypted yet, so a caller pays only for the part it reads.
    async fn load_head(
        &self,
        document_id: DocumentId,
        expected_scope: DocumentKind,
    ) -> VaultResult<Option<DocumentHead>> {
        let mut rows = self
            .connection
            .query(
                "SELECT vault_id, document_kind, generation, key_epoch, wrapped_dek,
                        current_commit_id
                 FROM documents WHERE document_id = ?1",
                [document_id.as_bytes().to_vec()],
            )
            .await
            .map_err(database_error)?;
        let Some(row) = rows.next().await.map_err(database_error)? else {
            return Ok(None);
        };
        let vault_id = VaultId::from_bytes(array_from_blob(&row_blob(&row, 0)?, "vault ID")?);
        let scope = DocumentKind::parse(&row_text(&row, 1)?)?;
        let generation = from_i64(row_integer(&row, 2)?, "document generation")?;
        let key_epoch = from_i64(row_integer(&row, 3)?, "document key epoch")?;
        let wrapped_bytes = row_blob(&row, 4)?;
        let current_commit_id = array_from_blob(&row_blob(&row, 5)?, "document commit ID")?;
        let wrapped: WrappedKey = serde_json::from_slice(&wrapped_bytes)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        if vault_id != self.device.device_vault_id() || scope != expected_scope {
            return Err(VaultError::InvalidData(
                "document vault or kind does not match requested operation".to_owned(),
            ));
        }
        let data_key = self.secrets.unwrap_document_key(
            self.device.installation_id(),
            vault_id,
            document_id,
            scope,
            key_epoch,
            &wrapped,
        )?;
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
        if envelope.vault_id() != vault_id
            || envelope.document_id() != document_id
            || envelope.scope() != scope
            || envelope.device_key_id() != self.device.device_key_id()
            || envelope.generation() != generation
            || envelope.key_epoch() != key_epoch
        {
            return Err(VaultError::InvalidData(
                "snapshot metadata does not match document row".to_owned(),
            ));
        }
        self.verify_snapshot_against_commit(
            current_commit_id,
            document_id,
            generation,
            key_epoch,
            &envelope_bytes,
        )
        .await?;
        Ok(Some(DocumentHead {
            generation,
            key_epoch,
            wrapped_dek: wrapped_bytes,
            envelope,
            data_key,
        }))
    }

    pub(super) async fn load_document(
        &self,
        document_id: DocumentId,
        expected_scope: DocumentKind,
        expected_partition: Option<&[u8]>,
    ) -> VaultResult<Option<LoadedDocument>> {
        let Some(head) = self.load_head(document_id, expected_scope).await? else {
            return Ok(None);
        };
        let snapshot = decrypt_snapshot(&head.envelope, &head.data_key)?;
        let document = SecretDocument::load(
            &snapshot,
            self.device.actor_id(),
            expected_scope,
            expected_partition,
        )?;
        Ok(Some(LoadedDocument { document, head }))
    }

    /// Load only a document's history log. The record document stays
    /// encrypted.
    pub(super) async fn load_history(
        &self,
        document_id: DocumentId,
        expected_scope: DocumentKind,
        expected_partition: Option<&[u8]>,
    ) -> VaultResult<Option<HistoryLog>> {
        let Some(head) = self.load_head(document_id, expected_scope).await? else {
            return Ok(None);
        };
        let bytes = decrypt_history(&head.envelope, &head.data_key)?;
        HistoryLog::load(&bytes, expected_scope, expected_partition).map(Some)
    }

    pub(super) async fn commit_mutation(
        &mut self,
        document_id: DocumentId,
        scope: DocumentKind,
        current: Option<DocumentHead>,
        mutation: DocumentMutation,
        context: &MutationContext<'_>,
    ) -> VaultResult<()> {
        let prepared = self
            .prepare_commit(document_id, scope, current, mutation, context)
            .await?;
        self.persist_commit(prepared).await?;
        self.chain_length = self.chain_length.saturating_add(1);
        // The write is durable here and compaction runs in its own
        // transaction, so a compaction failure never loses the write. It is
        // still reported: the next open runs the same compaction and refuses
        // the vault if it keeps failing, so a caller must learn about it while
        // the vault is still open rather than at the next unseal.
        self.compact_if_needed().await
    }

    async fn prepare_commit(
        &self,
        document_id: DocumentId,
        scope: DocumentKind,
        current: Option<DocumentHead>,
        mutation: DocumentMutation,
        context: &MutationContext<'_>,
    ) -> VaultResult<PreparedCommit> {
        let (generation, key_epoch) = match &current {
            Some(head) => (
                head.generation.saturating_add(1),
                head.key_epoch.saturating_add(1),
            ),
            None => (1, 1),
        };
        if generation == u64::MAX || key_epoch == u64::MAX {
            return Err(VaultError::InvalidData(
                "document generation is exhausted".to_owned(),
            ));
        }
        let DocumentMutation {
            snapshot,
            heads,
            partition,
            history: pending,
            next_eviction,
        } = mutation;
        // The history log is carried forward from the current generation and
        // extended with this one's changes; it is the only part of the
        // previous generation that is decrypted on a write.
        let mut history = match &current {
            Some(head) => HistoryLog::load(
                &decrypt_history(&head.envelope, &head.data_key)?,
                scope,
                Some(&partition),
            )?,
            None => HistoryLog::new(scope, &partition),
        };
        history.record(
            pending,
            context.now,
            context.provenance,
            context.device_key_id,
        )?;
        let history_bytes = history.serialize()?;
        // Every generation is encrypted under a fresh key and the row keeps
        // only the current wrapped key. A superseded snapshot that lingers
        // until compaction therefore cannot be decrypted any more.
        let (data_key, wrapped) = self.secrets.generate_document_key(
            self.device.installation_id(),
            self.device.device_vault_id(),
            document_id,
            scope,
            key_epoch,
        )?;
        let wrapped_dek = serde_json::to_vec(&wrapped)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        let signing_seed = self
            .secrets
            .signing_seed(self.device.installation_id(), self.device.device_vault_id())?;
        let envelope_context = EnvelopeContext {
            vault_id: self.device.device_vault_id(),
            document_id,
            scope,
            device_key_id: self.device.device_key_id(),
            generation,
            key_epoch,
        };
        let envelope = encrypt_snapshot(
            &envelope_context,
            &heads,
            &snapshot,
            &history_bytes,
            &data_key,
        )?;
        let snapshot_bytes = serde_json::to_vec(&envelope)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        let previous_commit_id = self.current_commit_head().await?;
        let protected_commit = ProtectedCommit::new(
            CommitContents {
                previous_commit_id,
                vault_id: self.device.device_vault_id(),
                document_id,
                scope,
                generation,
                key_epoch,
                wrapped_key_digest: digest(&wrapped_dek),
                snapshot_digest: digest(&snapshot_bytes),
                device_key_id: self.device.device_key_id(),
            },
            &signing_seed,
        )?;
        let protected_bytes = serde_json::to_vec(&protected_commit)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;

        Ok(PreparedCommit {
            vault_id: self.device.device_vault_id(),
            document_id,
            scope,
            expected: current,
            generation,
            key_epoch,
            wrapped_dek,
            snapshot_envelope: snapshot_bytes,
            protected_commit,
            protected_record: protected_bytes,
            next_eviction,
        })
    }

    async fn persist_commit(&mut self, prepared: PreparedCommit) -> VaultResult<()> {
        let transaction = self
            .connection
            .transaction()
            .await
            .map_err(database_error)?;
        Self::persist_document_head(&transaction, &prepared).await?;
        let PreparedCommit {
            document_id,
            generation,
            snapshot_envelope,
            protected_commit,
            protected_record,
            ..
        } = prepared;
        Self::persist_snapshot(&transaction, document_id, generation, snapshot_envelope).await?;
        Self::persist_protected_record(
            &transaction,
            document_id,
            generation,
            &protected_commit,
            protected_record,
        )
        .await?;
        Self::advance_commit_head(&transaction, protected_commit.commit_id).await?;
        transaction.commit().await.map_err(database_error)?;
        Ok(())
    }

    async fn persist_document_head(
        transaction: &Transaction<'_>,
        prepared: &PreparedCommit,
    ) -> VaultResult<()> {
        // The eviction hint is scheduling metadata for the sweep, not an
        // authenticated fact: the sweep re-reads deadlines from the document
        // itself, and an expired record already reads as absent.
        let next_eviction = prepared
            .next_eviction
            .map(to_i64)
            .transpose()?
            .map_or(Value::Null, Value::Integer);
        match &prepared.expected {
            Some(expected) => {
                let updated = transaction
                    .execute(
                        "UPDATE documents SET generation = ?1, key_epoch = ?2,
                              wrapped_dek = ?3, current_commit_id = ?4,
                              next_eviction = ?10
                         WHERE document_id = ?5 AND vault_id = ?6
                           AND generation = ?7 AND document_kind = ?8
                           AND wrapped_dek = ?9",
                        params![
                            to_i64(prepared.generation)?,
                            to_i64(prepared.key_epoch)?,
                            prepared.wrapped_dek.clone(),
                            prepared.protected_commit.commit_id.to_vec(),
                            prepared.document_id.as_bytes().to_vec(),
                            prepared.vault_id.as_bytes().to_vec(),
                            to_i64(expected.generation)?,
                            prepared.scope.as_str(),
                            expected.wrapped_dek.clone(),
                            next_eviction,
                        ],
                    )
                    .await
                    .map_err(database_error)?;
                if updated != 1 {
                    return Err(VaultError::Database(
                        "document generation or wrapped key changed concurrently".to_owned(),
                    ));
                }
            }
            None => {
                transaction
                    .execute(
                        "INSERT INTO documents(
                             document_id, vault_id, document_kind, generation, key_epoch,
                             wrapped_dek, current_commit_id, next_eviction
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        params![
                            prepared.document_id.as_bytes().to_vec(),
                            prepared.vault_id.as_bytes().to_vec(),
                            prepared.scope.as_str(),
                            to_i64(prepared.generation)?,
                            to_i64(prepared.key_epoch)?,
                            prepared.wrapped_dek.clone(),
                            prepared.protected_commit.commit_id.to_vec(),
                            next_eviction,
                        ],
                    )
                    .await
                    .map_err(database_error)?;
            }
        }
        Ok(())
    }

    async fn persist_snapshot(
        transaction: &Transaction<'_>,
        document_id: DocumentId,
        generation: u64,
        snapshot_envelope: Vec<u8>,
    ) -> VaultResult<()> {
        transaction
            .execute(
                "INSERT INTO document_snapshots(document_id, generation, envelope)
                 VALUES (?1, ?2, ?3)",
                params![
                    document_id.as_bytes().to_vec(),
                    to_i64(generation)?,
                    snapshot_envelope,
                ],
            )
            .await
            .map_err(database_error)?;
        Ok(())
    }

    async fn persist_protected_record(
        transaction: &Transaction<'_>,
        document_id: DocumentId,
        generation: u64,
        protected_commit: &ProtectedCommit,
        protected_record: Vec<u8>,
    ) -> VaultResult<()> {
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
                    protected_record,
                ],
            )
            .await
            .map_err(database_error)?;
        Ok(())
    }

    async fn advance_commit_head(
        transaction: &Transaction<'_>,
        commit_id: [u8; 32],
    ) -> VaultResult<()> {
        transaction
            .execute(
                "INSERT INTO store_meta(key, value) VALUES ('current-commit-head', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [commit_id.to_vec()],
            )
            .await
            .map_err(database_error)?;
        Ok(())
    }
}

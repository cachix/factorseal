//! Document snapshot loading and transactional commit persistence.

use turso::transaction::Transaction;
use turso::{Value, params};

use crate::vault::envelope::{EnvelopeContext, encrypt_changes, encrypt_snapshot};
use crate::vault::{
    DocumentId, DocumentMutation, DocumentScope, EncryptedSnapshot, SecretDocument, VaultError,
    VaultResult, verify_and_decrypt_snapshot,
};

use super::{LoadedDocument, StoreWorker};
use crate::vault::store::chain::{
    CommitContents, ProtectedCommit, digest, digest_change_envelopes,
};
use crate::vault::store::database::{
    database_error, from_i64, query_optional_blob, row_integer, row_text, to_i64,
};

struct PreparedChange {
    change_hash: [u8; 32],
    envelope: Vec<u8>,
}

struct PreparedCommit {
    document_id: DocumentId,
    scope: DocumentScope,
    expected_generation: Option<u64>,
    generation: u64,
    key_epoch: u64,
    snapshot_envelope: Vec<u8>,
    changes: Vec<PreparedChange>,
    protected_commit: ProtectedCommit,
    protected_record: Vec<u8>,
}

impl StoreWorker {
    pub(super) async fn load_document(
        &self,
        document_id: DocumentId,
        expected_scope: DocumentScope,
    ) -> VaultResult<Option<LoadedDocument>> {
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
        Ok(Some(LoadedDocument {
            document,
            generation,
            key_epoch,
        }))
    }

    pub(super) async fn commit_mutation(
        &mut self,
        document_id: DocumentId,
        scope: DocumentScope,
        expected_generation: Option<u64>,
        key_epoch: u64,
        mutation: DocumentMutation,
    ) -> VaultResult<()> {
        let prepared = self
            .prepare_commit(document_id, scope, expected_generation, key_epoch, mutation)
            .await?;
        self.persist_commit(prepared).await?;
        self.chain_length = self.chain_length.saturating_add(1);
        self.compact_if_needed().await
    }

    async fn prepare_commit(
        &self,
        document_id: DocumentId,
        scope: DocumentScope,
        expected_generation: Option<u64>,
        key_epoch: u64,
        mutation: DocumentMutation,
    ) -> VaultResult<PreparedCommit> {
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
            CommitContents {
                previous_commit_id,
                document_id,
                scope,
                generation,
                key_epoch,
                snapshot_digest: digest(&snapshot_bytes),
                changes_digest: digest_change_envelopes(&changes, &change_bytes),
                device_key_id: self.device.device_key_id(),
            },
            &self.signing_seed,
        )?;
        let protected_bytes = serde_json::to_vec(&protected_commit)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;

        let changes = changes
            .into_iter()
            .zip(change_bytes)
            .map(|(envelope, bytes)| PreparedChange {
                change_hash: *envelope.change_hash(),
                envelope: bytes,
            })
            .collect();
        Ok(PreparedCommit {
            document_id,
            scope,
            expected_generation,
            generation,
            key_epoch,
            snapshot_envelope: snapshot_bytes,
            changes,
            protected_commit,
            protected_record: protected_bytes,
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
            changes,
            protected_commit,
            protected_record,
            ..
        } = prepared;
        Self::persist_snapshot(&transaction, document_id, generation, snapshot_envelope).await?;
        Self::persist_changes(&transaction, document_id, generation, changes).await?;
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
        match prepared.expected_generation {
            Some(expected) => {
                let updated = transaction
                    .execute(
                        "UPDATE documents SET generation = ?1, key_epoch = ?2,
                              current_commit_id = ?3
                         WHERE document_id = ?4 AND generation = ?5 AND scope = ?6",
                        params![
                            to_i64(prepared.generation)?,
                            to_i64(prepared.key_epoch)?,
                            prepared.protected_commit.commit_id.to_vec(),
                            prepared.document_id.as_bytes().to_vec(),
                            to_i64(expected)?,
                            prepared.scope.as_str(),
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
                            prepared.document_id.as_bytes().to_vec(),
                            prepared.scope.as_str(),
                            to_i64(prepared.generation)?,
                            to_i64(prepared.key_epoch)?,
                            prepared.protected_commit.commit_id.to_vec(),
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

    async fn persist_changes(
        transaction: &Transaction<'_>,
        document_id: DocumentId,
        generation: u64,
        changes: Vec<PreparedChange>,
    ) -> VaultResult<()> {
        for change in changes {
            transaction
                .execute(
                    "INSERT INTO document_changes(document_id, change_hash, generation, envelope)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        document_id.as_bytes().to_vec(),
                        change.change_hash.to_vec(),
                        to_i64(generation)?,
                        change.envelope,
                    ],
                )
                .await
                .map_err(database_error)?;
        }
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

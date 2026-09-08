//! Protected commit-chain verification and bounded-history compaction.

use std::collections::{BTreeMap, HashSet};

use turso::transaction::{Transaction, TransactionBehavior};
use turso::{Value, params};

use crate::vault::{DocumentId, DocumentKind, VaultError, VaultId, VaultResult};

use super::{
    DocumentRow, MAX_COMMIT_CHAIN, MAX_RETAINED_COMMITS, MAX_RETAINED_SNAPSHOT_BYTES, StoreWorker,
    VerifiedDocument, VerifiedStoreState,
};

const VERIFY_BATCH_SIZE: usize = 32;
use crate::vault::store::chain::{CommitContents, ProtectedCommit, digest};
use crate::vault::store::database::{
    array_from_blob, database_error, document_id_from_blob, from_i64, query_count,
    query_optional_blob, row_blob, row_deadline, row_integer, row_optional_blob, row_text, to_i64,
};

impl StoreWorker {
    pub(super) async fn current_commit_head(&self) -> VaultResult<Option<[u8; 32]>> {
        query_optional_blob(
            &self.connection,
            "SELECT value FROM store_meta WHERE key = 'current-commit-head'",
            (),
        )
        .await?
        .map(|bytes| array_from_blob(&bytes, "current commit head"))
        .transpose()
    }

    /// Build trusted state from a consistent, fully verified startup snapshot.
    pub(super) async fn verify_commit_chain(&self) -> VaultResult<VerifiedStoreState> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .await
                .map_err(database_error)?;
        let verified = self.verify_chain_in_snapshot().await?;
        transaction.commit().await.map_err(database_error)?;
        Ok(verified)
    }

    async fn verify_chain_in_snapshot(&self) -> VaultResult<VerifiedStoreState> {
        let head = self.current_commit_head().await?;
        let mut current = head;
        let mut verified = VerifiedStoreState {
            head,
            ..VerifiedStoreState::default()
        };
        let mut visited = HashSet::new();
        let mut count = 0_usize;
        while let Some(commit_id) = current {
            let records = self.verify_commit_batch(commit_id).await?;
            let sizes = self.verify_batch_payloads(&records).await?;
            for (record, snapshot_bytes) in records.into_iter().zip(sizes) {
                count += 1;
                if count > MAX_COMMIT_CHAIN || !visited.insert(record.commit_id) {
                    return Err(VaultError::InvalidData(
                        "protected commit chain is cyclic or too long".to_owned(),
                    ));
                }
                current = record.previous_commit_id;
                verified.retained_snapshot_bytes = verified
                    .retained_snapshot_bytes
                    .saturating_add(snapshot_bytes);
                // Traversal starts at the global head: first seen is newest.
                verified
                    .documents
                    .entry(record.document_id)
                    .or_insert_with(|| VerifiedDocument::new(&record, snapshot_bytes));
            }
        }

        self.verify_protected_row_sets(count).await?;
        self.verify_inventory(&verified).await?;
        verified.chain_length = count;
        Ok(verified)
    }

    /// The commit chain, not the snapshot, carries the device signature. A
    /// load therefore checks the snapshot bytes against the signed commit the
    /// document row points at.
    pub(super) async fn verify_snapshot_against_commit(
        &self,
        commit_id: [u8; 32],
        document_id: DocumentId,
        generation: u64,
        key_epoch: u64,
        snapshot_envelope: &[u8],
    ) -> VaultResult<()> {
        let trusted = self
            .verified
            .documents
            .get(&document_id)
            .ok_or(VaultError::Signature)?;
        if trusted.row.current_commit_id != commit_id
            || trusted.row.generation != generation
            || trusted.row.key_epoch != key_epoch
            || trusted.snapshot_digest != digest(snapshot_envelope)
        {
            return Err(VaultError::Signature);
        }
        let record = query_optional_blob(
            &self.connection,
            "SELECT record FROM protected_commits WHERE commit_id = ?1",
            [commit_id.to_vec()],
        )
        .await?
        .ok_or_else(|| VaultError::InvalidData("document commit is missing".to_owned()))?;
        let record: ProtectedCommit = serde_json::from_slice(&record)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        record.verify(commit_id, self.device.device_key_id(), &self.verifying_key)?;
        if record.vault_id != self.device.device_vault_id()
            || record.document_id != document_id
            || record.generation != generation
            || record.key_epoch != key_epoch
            || record.snapshot_digest != digest(snapshot_envelope)
        {
            return Err(VaultError::Signature);
        }
        Ok(())
    }

    /// Fetch only a bounded batch of small commit records. The SQL links are
    /// untrusted until each record's signature and duplicated columns agree.
    async fn verify_commit_batch(&self, commit_id: [u8; 32]) -> VaultResult<Vec<ProtectedCommit>> {
        let mut rows = self
            .connection
            .query(
                "WITH RECURSIVE batch AS (
                     SELECT commit_id, previous_commit_id, document_id, generation, record, 0 AS depth
                     FROM protected_commits WHERE commit_id = ?1
                     UNION ALL
                     SELECT parent.commit_id, parent.previous_commit_id, parent.document_id,
                            parent.generation, parent.record, batch.depth + 1
                     FROM protected_commits AS parent
                     JOIN batch ON parent.commit_id = batch.previous_commit_id
                     WHERE batch.depth + 1 < ?2
                 )
                 SELECT commit_id, previous_commit_id, document_id, generation, record
                 FROM batch ORDER BY depth",
                params![commit_id.to_vec(), to_i64(VERIFY_BATCH_SIZE as u64)?],
            )
            .await
            .map_err(database_error)?;
        let mut expected = Some(commit_id);
        let mut records = Vec::with_capacity(VERIFY_BATCH_SIZE);
        while let Some(row) = rows.next().await.map_err(database_error)? {
            let stored_id = array_from_blob(&row_blob(&row, 0)?, "commit ID")?;
            if expected != Some(stored_id) || records.len() >= VERIFY_BATCH_SIZE {
                return Err(VaultError::Signature);
            }
            let stored_previous = row_optional_blob(&row, 1)?
                .map(|bytes| array_from_blob(&bytes, "previous commit ID"))
                .transpose()?;
            let stored_document_id = document_id_from_blob(&row_blob(&row, 2)?)?;
            let stored_generation = from_i64(row_integer(&row, 3)?, "commit generation")?;
            let record: ProtectedCommit = serde_json::from_slice(&row_blob(&row, 4)?)
                .map_err(|error| VaultError::InvalidData(error.to_string()))?;
            record.verify(stored_id, self.device.device_key_id(), &self.verifying_key)?;
            if stored_previous != record.previous_commit_id
                || stored_document_id != record.document_id
                || stored_generation != record.generation
                || record.vault_id != self.device.device_vault_id()
            {
                return Err(VaultError::InvalidData(
                    "protected commit SQL metadata does not match its signed record".to_owned(),
                ));
            }
            expected = record.previous_commit_id;
            records.push(record);
        }
        if records.is_empty() {
            return Err(VaultError::InvalidData(
                "protected commit chain is incomplete".to_owned(),
            ));
        }
        Ok(records)
    }

    /// Stream ciphertext separately so batching does not retain a batch of
    /// potentially large snapshots in memory or sort their contents.
    async fn verify_batch_payloads(&self, records: &[ProtectedCommit]) -> VaultResult<Vec<u64>> {
        let mut expected = BTreeMap::new();
        let mut parameters = Vec::with_capacity(records.len() * 2);
        for (index, record) in records.iter().enumerate() {
            if expected
                .insert((record.document_id, record.generation), index)
                .is_some()
            {
                return Err(VaultError::InvalidData(
                    "duplicate protected snapshot generation".to_owned(),
                ));
            }
            parameters.push(Value::Blob(record.document_id.as_bytes().to_vec()));
            parameters.push(Value::Integer(to_i64(record.generation)?));
        }
        let predicates = std::iter::repeat_n("(document_id = ? AND generation = ?)", records.len())
            .collect::<Vec<_>>()
            .join(" OR ");
        let mut rows = self.connection.query(
            &format!("SELECT document_id, generation, envelope FROM document_snapshots WHERE {predicates}"),
            parameters,
        ).await.map_err(database_error)?;
        let mut sizes = vec![0; records.len()];
        while let Some(row) = rows.next().await.map_err(database_error)? {
            let key = (
                document_id_from_blob(&row_blob(&row, 0)?)?,
                from_i64(row_integer(&row, 1)?, "snapshot generation")?,
            );
            let index = expected.remove(&key).ok_or(VaultError::Signature)?;
            let snapshot = row_blob(&row, 2)?;
            if digest(&snapshot) != records[index].snapshot_digest {
                return Err(VaultError::Signature);
            }
            sizes[index] = snapshot.len() as u64;
        }
        if !expected.is_empty() {
            return Err(VaultError::InvalidData(
                "protected commit snapshot is missing".to_owned(),
            ));
        }
        Ok(sizes)
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
        let commits_without_documents = query_count(
            &self.connection,
            "SELECT COUNT(*) FROM protected_commits AS commits
             WHERE NOT EXISTS (
                 SELECT 1 FROM documents
                 WHERE documents.document_id = commits.document_id
             )",
            (),
        )
        .await?;
        if commits_without_documents != 0 {
            return Err(VaultError::InvalidData(
                "protected commit refers to a missing document".to_owned(),
            ));
        }
        Ok(())
    }

    async fn document_rows(&self) -> VaultResult<Vec<DocumentRow>> {
        let mut rows = self
            .connection
            .query(
                "SELECT vault_id, document_id, document_kind, generation, key_epoch,
                        wrapped_dek, current_commit_id, next_eviction
                 FROM documents ORDER BY document_id",
                (),
            )
            .await
            .map_err(database_error)?;
        let mut documents = Vec::new();
        while let Some(row) = rows.next().await.map_err(database_error)? {
            documents.push(DocumentRow {
                vault_id: VaultId::from_bytes(array_from_blob(&row_blob(&row, 0)?, "vault ID")?),
                document_id: document_id_from_blob(&row_blob(&row, 1)?)?,
                scope: DocumentKind::parse(&row_text(&row, 2)?)?,
                generation: from_i64(row_integer(&row, 3)?, "document generation")?,
                key_epoch: from_i64(row_integer(&row, 4)?, "document key epoch")?,
                wrapped_key_digest: digest(&row_blob(&row, 5)?),
                current_commit_id: array_from_blob(&row_blob(&row, 6)?, "document commit ID")?,
                next_eviction: row_deadline(&row, 7)?,
            });
        }
        Ok(documents)
    }

    async fn verify_inventory(&self, verified: &VerifiedStoreState) -> VaultResult<()> {
        if self.current_commit_head().await? != verified.head {
            return Err(VaultError::Signature);
        }
        let rows = self.document_rows().await?;
        if rows.len() != verified.documents.len() {
            return Err(VaultError::InvalidData(
                "protected document inventory changed".to_owned(),
            ));
        }
        for row in rows {
            if verified
                .documents
                .get(&row.document_id)
                .is_none_or(|expected| expected.row != row)
            {
                return Err(VaultError::InvalidData(
                    "document is not at its newest protected commit or signed metadata changed"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub(super) async fn verify_live_inventory(&self) -> VaultResult<()> {
        self.verify_inventory(&self.verified).await
    }

    pub(super) async fn compact_if_needed(&mut self) -> VaultResult<()> {
        self.compact_with_byte_limit(MAX_RETAINED_SNAPSHOT_BYTES)
            .await
    }

    pub(super) async fn compact_with_byte_limit(&mut self, byte_limit: u64) -> VaultResult<()> {
        let too_many_commits = self.verified.chain_length
            > MAX_RETAINED_COMMITS.max(self.verified.documents.len().saturating_mul(2));
        // Never compact just because the current data is large: require at
        // least half the retained ciphertext to be superseded as well.
        let too_many_bytes = self.verified.retained_snapshot_bytes > byte_limit
            && self.verified.retained_snapshot_bytes
                > self
                    .verified
                    .documents
                    .values()
                    .fold(0_u64, |total, document| {
                        total.saturating_add(document.snapshot_bytes)
                    })
                    .saturating_mul(2);
        if too_many_commits || too_many_bytes {
            self.compact().await?;
        }
        Ok(())
    }

    /// Replace the commit history with a freshly signed minimal chain that
    /// describes exactly the current state of every document.
    ///
    /// The discarded generations were only ever read by chain verification, so
    /// re-signing preserves every invariant that verification checks: one
    /// commit per document, one snapshot per commit, and every document at its
    /// newest commit.
    async fn compact(&mut self) -> VaultResult<()> {
        // Hold the writer transaction across verification, signing and
        // replacement. Queries through this connection share that snapshot.
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .await
                .map_err(database_error)?;
        self.verify_live_inventory().await?;
        // Do not erase evidence of tampered historical records either.
        let verified = self.verify_chain_in_snapshot().await?;
        if verified.chain_length != self.verified.chain_length {
            return Err(VaultError::Signature);
        }
        let documents = self.document_rows().await?;
        let commits = self.resign_current_state(&documents).await?;
        Self::replace_chain(&transaction, &documents, &commits).await?;
        transaction.commit().await.map_err(database_error)?;
        self.verified = VerifiedStoreState {
            head: commits.last().map(|commit| commit.commit_id),
            documents: commits
                .iter()
                .map(|commit| {
                    (
                        commit.document_id,
                        VerifiedDocument::new(
                            commit,
                            verified.documents[&commit.document_id].snapshot_bytes,
                        ),
                    )
                })
                .collect(),
            chain_length: commits.len(),
            retained_snapshot_bytes: verified.documents.values().fold(0_u64, |total, document| {
                total.saturating_add(document.snapshot_bytes)
            }),
        };
        self.checkpoint().await?;
        Ok(())
    }

    /// Sign one commit per document, chained in document order, over the state
    /// those documents are in right now.
    async fn resign_current_state(
        &self,
        documents: &[DocumentRow],
    ) -> VaultResult<Vec<ProtectedCommit>> {
        let signer = self
            .secrets
            .signer(self.device.installation_id(), self.device.device_vault_id());
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
            self.verify_snapshot_against_commit(
                document.current_commit_id,
                document.document_id,
                document.generation,
                document.key_epoch,
                &snapshot,
            )
            .await?;
            let commit = ProtectedCommit::new(
                CommitContents {
                    previous_commit_id,
                    vault_id: document.vault_id,
                    document_id: document.document_id,
                    scope: document.scope,
                    generation: document.generation,
                    key_epoch: document.key_epoch,
                    wrapped_key_digest: document.wrapped_key_digest,
                    snapshot_digest: digest(&snapshot),
                    next_eviction: document.next_eviction,
                    device_key_id: self.device.device_key_id(),
                },
                &signer,
            )?;
            previous_commit_id = Some(commit.commit_id);
            commits.push(commit);
        }
        Ok(commits)
    }

    /// Swap the whole history for `commits` in one transaction, dropping every
    /// superseded snapshot along with it.
    async fn replace_chain(
        transaction: &Transaction<'_>,
        documents: &[DocumentRow],
        commits: &[ProtectedCommit],
    ) -> VaultResult<()> {
        for document in documents {
            transaction
                .execute(
                    "DELETE FROM document_snapshots WHERE document_id = ?1 AND generation <> ?2",
                    params![
                        document.document_id.as_bytes().to_vec(),
                        to_i64(document.generation)?,
                    ],
                )
                .await
                .map_err(database_error)?;
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
        Ok(())
    }

    /// Best-effort retention reduction, not cryptographic erasure. Never run
    /// this from Drop/shutdown: releasing the keys must not wait on cleanup.
    pub(super) async fn checkpoint(&self) -> VaultResult<()> {
        let mut rows = self
            .connection
            .query("PRAGMA wal_checkpoint(TRUNCATE)", ())
            .await
            .map_err(database_error)?;
        let row = rows
            .next()
            .await
            .map_err(database_error)?
            .ok_or_else(|| VaultError::Database("checkpoint returned no status".to_owned()))?;
        if row_integer(&row, 0)? != 0 {
            return Err(VaultError::Database(
                "vault checkpoint is busy; cleanup incomplete".to_owned(),
            ));
        }
        if rows.next().await.map_err(database_error)?.is_some() {
            return Err(VaultError::Database("invalid checkpoint status".to_owned()));
        }
        Ok(())
    }
}

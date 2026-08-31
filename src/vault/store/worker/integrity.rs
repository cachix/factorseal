//! Protected commit-chain verification and bounded-history compaction.

use std::collections::HashSet;

use turso::{Value, params};

use crate::vault::{DocumentId, DocumentKind, SignedChangeEnvelope, VaultError, VaultResult};

use super::{DocumentRow, MAX_COMMIT_CHAIN, MAX_RETAINED_COMMITS, StoreWorker};
use crate::vault::store::chain::{
    CommitContents, ProtectedCommit, digest, digest_change_envelopes,
};
use crate::vault::store::database::{
    array_from_blob, database_error, document_id_from_blob, from_i64, query_count,
    query_optional_blob, row_blob, row_integer, row_optional_blob, row_text, to_i64,
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

    /// Verify the whole protected chain and return the number of commits in it.
    pub(super) async fn verify_commit_chain(&self) -> VaultResult<usize> {
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
                "SELECT document_id, document_kind, generation, key_epoch, current_commit_id
                 FROM documents ORDER BY document_id",
                (),
            )
            .await
            .map_err(database_error)?;
        let mut documents = Vec::new();
        while let Some(row) = rows.next().await.map_err(database_error)? {
            documents.push(DocumentRow {
                document_id: document_id_from_blob(&row_blob(&row, 0)?)?,
                scope: DocumentKind::parse(&row_text(&row, 1)?)?,
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

    pub(super) async fn compact_if_needed(&mut self) -> VaultResult<()> {
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
                CommitContents {
                    previous_commit_id,
                    document_id: document.document_id,
                    scope: document.scope,
                    generation: document.generation,
                    key_epoch: document.key_epoch,
                    snapshot_digest: digest(&snapshot),
                    changes_digest: digest_change_envelopes(&envelopes, &serialized),
                    device_key_id: self.device.device_key_id(),
                },
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

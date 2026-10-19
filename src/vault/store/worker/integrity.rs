//! Legacy signed-chain verification and current document inventory checks.

use std::collections::{BTreeMap, HashSet};
use std::time::Instant;

use turso::{Value, params};

use crate::vault::{DocumentKind, VaultError, VaultId, VaultResult};

use super::{DocumentRow, MAX_COMMIT_CHAIN, StoreWorker, VerifiedDocument, VerifiedStoreState};

const VERIFY_BATCH_SIZE: usize = 32;
use crate::vault::store::chain::{ProtectedCommit, digest};
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

    pub(super) async fn verify_chain_in_snapshot(&self) -> VaultResult<VerifiedStoreState> {
        let head = self.current_commit_head().await?;
        let mut current = head;
        let mut verified = VerifiedStoreState {
            head,
            ..VerifiedStoreState::default()
        };
        let mut visited = HashSet::new();
        let mut count = 0_usize;
        while let Some(commit_id) = current {
            let started = Instant::now();
            let result = self.verify_commit_batch(commit_id).await;
            crate::timing::record_result("store_chain", "commit_batch", started, &result);
            let records = result?;
            let started = Instant::now();
            let result = self.verify_batch_payloads(&records).await;
            crate::timing::record_result("store_chain", "snapshot_batch", started, &result);
            let sizes = result?;
            for (record, snapshot_bytes) in records.into_iter().zip(sizes) {
                count += 1;
                if count > MAX_COMMIT_CHAIN || !visited.insert(record.commit_id) {
                    return Err(VaultError::InvalidData(
                        "protected commit chain is cyclic or too long".to_owned(),
                    ));
                }
                current = record.previous_commit_id;
                // Traversal starts at the global head: first seen is newest.
                verified
                    .documents
                    .entry(record.document_id)
                    .or_insert_with(|| VerifiedDocument::from_legacy(&record, snapshot_bytes));
            }
        }

        let started = Instant::now();
        let result = self.verify_protected_row_sets(count).await;
        crate::timing::record_result("store_chain", "row_sets", started, &result);
        result?;
        let started = Instant::now();
        let result = self.verify_inventory(&verified).await;
        crate::timing::record_result("store_chain", "inventory", started, &result);
        result?;
        Ok(verified)
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
            crate::timing::result("store_chain", "commit_signature", || {
                record.verify(stored_id, self.device.device_key_id(), &self.verifying_key)
            })?;
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
            let started = Instant::now();
            let matches = digest(&snapshot) == records[index].snapshot_digest;
            crate::timing::record(
                "store_chain",
                "snapshot_digest",
                started,
                if matches { "ok" } else { "error" },
            );
            if !matches {
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

    pub(super) async fn document_rows(&self) -> VaultResult<Vec<DocumentRow>> {
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

    pub(super) async fn verify_inventory(&self, verified: &VerifiedStoreState) -> VaultResult<()> {
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
        self.verify_state_anchor().await?;
        self.verify_inventory(&self.verified).await?;
        self.verify_current_row_sets().await
    }

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

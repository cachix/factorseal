//! Current-state authentication and one-time conversion of historical stores.

use std::collections::BTreeMap;

use turso::params;
use turso::transaction::{Transaction, TransactionBehavior};

use super::{DocumentRow, StoreWorker, VerifiedDocument, VerifiedStoreState};
use crate::vault::store::chain::{CommitContents, digest};
use crate::vault::store::database::{
    array_from_blob, database_error, document_id_from_blob, query_count, query_optional_blob,
    row_blob, to_i64,
};
use crate::vault::store::manifest::{
    CURRENT_SCHEMA_VERSION, CurrentHead, StateManifest, inventory_digest,
};
use crate::vault::store::migration::{SCHEMA_VERSION, read_schema_version};
use crate::vault::{DocumentId, VaultError, VaultResult};

const MAX_MANIFEST_BYTES: usize = 32 * 1024;

impl VerifiedDocument {
    pub(super) fn new(head: &CurrentHead, snapshot_bytes: u64) -> Self {
        Self {
            row: DocumentRow {
                vault_id: head.vault_id,
                document_id: head.document_id,
                scope: head.scope,
                generation: head.generation,
                key_epoch: head.key_epoch,
                wrapped_key_digest: head.wrapped_key_digest,
                current_commit_id: head.head_id,
                next_eviction: head.next_eviction,
            },
            snapshot_digest: head.snapshot_digest,
            snapshot_bytes,
        }
    }
}

impl StoreWorker {
    pub(super) async fn initialize_current_state(&mut self) -> VaultResult<()> {
        match read_schema_version(&self.connection).await? {
            SCHEMA_VERSION => self.migrate_current_state().await?,
            CURRENT_SCHEMA_VERSION => {}
            _ => return Err(VaultError::InvalidData("unsupported store schema".into())),
        }
        self.verified = self.verify_current_state().await?;
        if self.read_manifest().await?.0.repack_pending {
            self.finish_migration_repack().await?;
        }
        Ok(())
    }

    pub(super) fn sign_manifest(
        &self,
        documents: &BTreeMap<DocumentId, VerifiedDocument>,
        repack_pending: bool,
    ) -> VaultResult<StateManifest> {
        let signer = self
            .secrets
            .signer(self.device.installation_id(), self.device.device_vault_id())?;
        StateManifest::new(
            self.device.device_vault_id(),
            self.device.device_key_id(),
            documents.len() as u64,
            inventory_digest(
                documents
                    .iter()
                    .map(|(id, document)| (id, &document.row.current_commit_id)),
            ),
            repack_pending,
            &signer,
        )
    }

    async fn read_manifest(&self) -> VaultResult<(StateManifest, Vec<u8>)> {
        let bytes = query_optional_blob(
            &self.connection,
            "SELECT value FROM store_meta WHERE key = 'current-state-manifest'",
            (),
        )
        .await?
        .ok_or_else(|| VaultError::InvalidData("current-state manifest is missing".into()))?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(VaultError::InvalidData(
                "current-state manifest is too large".into(),
            ));
        }
        let manifest = serde_json::from_slice(&bytes)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        Ok((manifest, bytes))
    }

    pub(super) async fn verify_state_anchor(&self) -> VaultResult<()> {
        let (_, bytes) = self.read_manifest().await?;
        if Some(digest(&bytes)) != self.verified.manifest_digest
            || self.current_commit_head().await? != self.verified.head
        {
            return Err(VaultError::Signature);
        }
        Ok(())
    }

    pub(super) async fn verify_current_state(&self) -> VaultResult<VerifiedStoreState> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .await
                .map_err(database_error)?;
        let (manifest, bytes) = self.read_manifest().await?;
        manifest.verify(
            self.device.device_vault_id(),
            self.device.device_key_id(),
            &self.verifying_key,
        )?;
        if self.current_commit_head().await? != Some(manifest.manifest_id) {
            return Err(VaultError::Signature);
        }
        let documents = self.read_current_heads(&manifest).await?;
        let mut verified = VerifiedStoreState {
            head: Some(manifest.manifest_id),
            manifest_digest: Some(digest(&bytes)),
            documents,
        };
        self.verify_current_payloads(&mut verified).await?;
        self.verify_inventory(&verified).await?;
        transaction.commit().await.map_err(database_error)?;
        Ok(verified)
    }

    async fn read_current_heads(
        &self,
        manifest: &StateManifest,
    ) -> VaultResult<BTreeMap<DocumentId, VerifiedDocument>> {
        let mut rows = self
            .connection
            .query(
                "SELECT document_id, head_id, record FROM document_heads ORDER BY document_id",
                (),
            )
            .await
            .map_err(database_error)?;
        let mut documents = BTreeMap::new();
        while let Some(row) = rows.next().await.map_err(database_error)? {
            if documents.len() as u64 >= manifest.document_count {
                return Err(VaultError::Signature);
            }
            let id = document_id_from_blob(&row_blob(&row, 0)?)?;
            let head_id = array_from_blob(&row_blob(&row, 1)?, "document head ID")?;
            let head: CurrentHead = serde_json::from_slice(&row_blob(&row, 2)?)
                .map_err(|error| VaultError::InvalidData(error.to_string()))?;
            head.verify(head_id)?;
            if head.document_id != id
                || head.vault_id != self.device.device_vault_id()
                || head.device_key_id != self.device.device_key_id()
            {
                return Err(VaultError::Signature);
            }
            if documents
                .insert(id, VerifiedDocument::new(&head, 0))
                .is_some()
            {
                return Err(VaultError::Signature);
            }
        }
        if documents.len() as u64 != manifest.document_count
            || inventory_digest(
                documents
                    .iter()
                    .map(|(id, d)| (id, &d.row.current_commit_id)),
            ) != manifest.inventory_digest
        {
            return Err(VaultError::Signature);
        }
        Ok(documents)
    }

    async fn verify_current_payloads(&self, verified: &mut VerifiedStoreState) -> VaultResult<()> {
        let mut rows = self.connection.query(
            "SELECT document_id, generation, envelope FROM document_snapshots ORDER BY document_id", (),
        ).await.map_err(database_error)?;
        let mut seen = std::collections::HashSet::new();
        while let Some(row) = rows.next().await.map_err(database_error)? {
            let id = document_id_from_blob(&row_blob(&row, 0)?)?;
            let document = verified
                .documents
                .get_mut(&id)
                .ok_or(VaultError::Signature)?;
            let generation = super::super::database::from_i64(
                super::super::database::row_integer(&row, 1)?,
                "snapshot generation",
            )?;
            let envelope = row_blob(&row, 2)?;
            if !seen.insert(id)
                || generation != document.row.generation
                || digest(&envelope) != document.snapshot_digest
            {
                return Err(VaultError::Signature);
            }
            document.snapshot_bytes = envelope.len() as u64;
        }
        if seen.len() != verified.documents.len() {
            return Err(VaultError::InvalidData(
                "current snapshot is missing".into(),
            ));
        }
        Ok(())
    }

    pub(super) async fn verify_snapshot_against_head(
        &self,
        head_id: [u8; 32],
        document_id: DocumentId,
        generation: u64,
        key_epoch: u64,
        envelope: &[u8],
    ) -> VaultResult<()> {
        let trusted = self
            .verified
            .documents
            .get(&document_id)
            .ok_or(VaultError::Signature)?;
        if trusted.row.current_commit_id != head_id
            || trusted.row.generation != generation
            || trusted.row.key_epoch != key_epoch
            || trusted.snapshot_digest != digest(envelope)
        {
            return Err(VaultError::Signature);
        }
        let bytes = query_optional_blob(
            &self.connection,
            "SELECT record FROM document_heads WHERE document_id = ?1 AND head_id = ?2",
            params![document_id.as_bytes().to_vec(), head_id.to_vec()],
        )
        .await?
        .ok_or_else(|| VaultError::InvalidData("document head is missing".into()))?;
        let head: CurrentHead = serde_json::from_slice(&bytes)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        head.verify(trusted.row.current_commit_id)
    }

    pub(super) async fn verify_current_row_sets(&self) -> VaultResult<()> {
        let expected = self.verified.documents.len() as u64;
        for table in ["document_heads", "document_snapshots"] {
            if query_count(
                &self.connection,
                &format!("SELECT COUNT(*) FROM {table}"),
                (),
            )
            .await?
                != expected
            {
                return Err(VaultError::InvalidData(
                    "current-state row inventory changed".into(),
                ));
            }
        }
        if query_count(
            &self.connection,
            "SELECT COUNT(*) FROM document_snapshots AS snapshots WHERE NOT EXISTS (
                SELECT 1 FROM documents WHERE documents.document_id=snapshots.document_id
                AND documents.generation=snapshots.generation)",
            (),
        )
        .await?
            != 0
        {
            return Err(VaultError::Signature);
        }
        Ok(())
    }

    pub(super) async fn persist_manifest(
        transaction: &Transaction<'_>,
        manifest: &StateManifest,
    ) -> VaultResult<[u8; 32]> {
        let bytes = serde_json::to_vec(manifest)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        let fingerprint = digest(&bytes);
        transaction.execute(
            "INSERT INTO store_meta(key, value) VALUES ('current-state-manifest', ?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [bytes],
        ).await.map_err(database_error)?;
        transaction.execute(
            "INSERT INTO store_meta(key, value) VALUES ('current-commit-head', ?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [manifest.manifest_id.to_vec()],
        ).await.map_err(database_error)?;
        Ok(fingerprint)
    }

    async fn migrate_current_state(&mut self) -> VaultResult<()> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .await
                .map_err(database_error)?;
        // Validate every retained signed generation before removing any of it.
        // The signed manifest is built exclusively from this verified state.
        let previous = self.verify_chain_in_snapshot().await?;
        transaction.execute(
            "CREATE TABLE document_heads(document_id BLOB PRIMARY KEY NOT NULL, head_id BLOB UNIQUE NOT NULL, record BLOB NOT NULL)", (),
        ).await.map_err(database_error)?;
        let mut documents = BTreeMap::new();
        for (id, document) in previous.documents {
            let row = document.row;
            let head = CurrentHead::new(CommitContents {
                previous_commit_id: None,
                vault_id: row.vault_id,
                document_id: id,
                scope: row.scope,
                generation: row.generation,
                key_epoch: row.key_epoch,
                wrapped_key_digest: row.wrapped_key_digest,
                snapshot_digest: document.snapshot_digest,
                next_eviction: row.next_eviction,
                device_key_id: self.device.device_key_id(),
            });
            let bytes = serde_json::to_vec(&head)
                .map_err(|error| VaultError::InvalidData(error.to_string()))?;
            transaction
                .execute(
                    "INSERT INTO document_heads VALUES (?1, ?2, ?3)",
                    params![id.as_bytes().to_vec(), head.head_id.to_vec(), bytes],
                )
                .await
                .map_err(database_error)?;
            transaction
                .execute(
                    "UPDATE documents SET current_commit_id=?1 WHERE document_id=?2",
                    params![head.head_id.to_vec(), id.as_bytes().to_vec()],
                )
                .await
                .map_err(database_error)?;
            transaction
                .execute(
                    "DELETE FROM document_snapshots WHERE document_id=?1 AND generation<>?2",
                    params![id.as_bytes().to_vec(), to_i64(head.generation)?],
                )
                .await
                .map_err(database_error)?;
            documents.insert(id, VerifiedDocument::new(&head, document.snapshot_bytes));
        }
        transaction
            .execute("DROP TABLE protected_commits", ())
            .await
            .map_err(database_error)?;
        let pages = query_count(&self.connection, "PRAGMA page_count", ()).await?;
        let unused = query_count(&self.connection, "PRAGMA freelist_count", ()).await?;
        let page_size = query_count(&self.connection, "PRAGMA page_size", ()).await?;
        if unused > pages || page_size == 0 {
            return Err(VaultError::InvalidData(
                "invalid database page counts".into(),
            ));
        }
        let repack = unused
            .checked_mul(page_size)
            .ok_or_else(|| VaultError::InvalidData("database size overflow".into()))?
            >= 64 * 1024 * 1024
            && unused >= pages - unused;
        let manifest = self.sign_manifest(&documents, repack)?;
        Self::persist_manifest(&transaction, &manifest).await?;
        transaction
            .execute(
                "UPDATE store_meta SET value=?1 WHERE key='schema-version'",
                [CURRENT_SCHEMA_VERSION.to_be_bytes().to_vec()],
            )
            .await
            .map_err(database_error)?;
        transaction.commit().await.map_err(database_error)?;
        self.checkpoint().await
    }

    async fn finish_migration_repack(&mut self) -> VaultResult<()> {
        self.checkpoint().await?;
        self.connection
            .execute("VACUUM", ())
            .await
            .map_err(database_error)?;
        if self.verify_current_state().await? != self.verified {
            return Err(VaultError::Signature);
        }
        let manifest = self.sign_manifest(&self.verified.documents, false)?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .await
                .map_err(database_error)?;
        self.verify_live_inventory().await?;
        let fingerprint = Self::persist_manifest(&transaction, &manifest).await?;
        transaction.commit().await.map_err(database_error)?;
        self.verified.head = Some(manifest.manifest_id);
        self.verified.manifest_digest = Some(fingerprint);
        self.checkpoint().await
    }
}

#[cfg(all(test, feature = "hardware"))]
mod tests;

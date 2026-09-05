//! Transactional migrations for authenticated vault database formats.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use turso::transaction::{Transaction, TransactionBehavior};
use turso::{Connection, Value, params};

use crate::EncryptionAlgorithm;
use crate::crypto;
use crate::vault::envelope::{EnvelopeContext, encrypt_snapshot};
use crate::vault::signature::{self, SignatureAlgorithm};
use crate::vault::{
    DeviceKeyId, DocumentId, DocumentKind, InstallationSecrets, SecretDocument, VaultError,
    VaultId, VaultMetadata, VaultResult, WrappedKey,
};

use super::chain::{CommitContents, ProtectedCommit, digest};
use super::database::{
    array_from_blob, database_error, document_id_from_blob, from_i64, query_count,
    query_optional_blob, row_blob, row_integer, row_optional_blob, row_text, to_i64,
};

pub(super) const SCHEMA_VERSION: u32 = 5;
const LEGACY_SCHEMA_VERSION: u32 = 3;
const LEGACY_ENVELOPE_VERSION: u8 = 5;
const LEGACY_COMMIT_VERSION: u8 = 5;
const LEGACY_SNAPSHOT_DOMAIN: &[u8] = b"factorseal/encrypted-snapshot/v4\0";
const LEGACY_COMMIT_DOMAIN: &[u8] = b"factorseal/protected-commit/v4\0";
const LEGACY_COMMIT_SIGNATURE_DOMAIN: &[u8] = b"factorseal/protected-commit-signature/v4\0";
const MAX_MIGRATION_COMMIT_CHAIN: usize = 1_000_000;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyEncryptedSnapshot {
    version: u8,
    encryption_algorithm: EncryptionAlgorithm,
    vault_id: VaultId,
    document_id: DocumentId,
    scope: DocumentKind,
    device_key_id: DeviceKeyId,
    generation: u64,
    key_epoch: u64,
    heads: Vec<[u8; 32]>,
    nonce: [u8; crate::algorithm::AES_GCM_NONCE_BYTES],
    ciphertext: Vec<u8>,
}

impl LegacyEncryptedSnapshot {
    fn decrypt(
        &self,
        expected: &LegacyDocumentRow,
        expected_device_key_id: DeviceKeyId,
        data_key: &[u8; 32],
    ) -> VaultResult<zeroize::Zeroizing<Vec<u8>>> {
        if self.version != LEGACY_ENVELOPE_VERSION
            || self.vault_id != expected.vault_id
            || self.document_id != expected.document_id
            || self.scope != expected.scope
            || self.device_key_id != expected_device_key_id
            || self.generation != expected.generation
            || self.key_epoch != expected.key_epoch
        {
            return Err(VaultError::Signature);
        }
        let aad = legacy_snapshot_header(self);
        crypto::decrypt(
            self.encryption_algorithm,
            data_key,
            &self.nonce,
            &aad,
            &self.ciphertext,
        )
        .map_err(|_| VaultError::Crypto)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyProtectedCommit {
    version: u8,
    signature_algorithm: SignatureAlgorithm,
    commit_id: [u8; 32],
    previous_commit_id: Option<[u8; 32]>,
    vault_id: VaultId,
    document_id: DocumentId,
    scope: DocumentKind,
    generation: u64,
    key_epoch: u64,
    wrapped_key_digest: [u8; 32],
    snapshot_digest: [u8; 32],
    device_key_id: DeviceKeyId,
    signature: Vec<u8>,
}

impl LegacyProtectedCommit {
    fn verify(&self, expected_commit_id: [u8; 32], device: &VaultMetadata) -> VaultResult<()> {
        if self.version != LEGACY_COMMIT_VERSION
            || self.commit_id != expected_commit_id
            || self.device_key_id != device.device_key_id()
            || self.vault_id != device.device_vault_id()
        {
            return Err(VaultError::Signature);
        }
        let transcript = legacy_commit_transcript(self);
        if digest(&transcript) != self.commit_id {
            return Err(VaultError::Signature);
        }
        signature::verify_with(
            self.signature_algorithm,
            device.public_signing_key(),
            &legacy_commit_signature_payload(&self.commit_id),
            &self.signature,
        )
    }
}

#[derive(Clone)]
struct LegacyDocumentRow {
    vault_id: VaultId,
    document_id: DocumentId,
    scope: DocumentKind,
    generation: u64,
    key_epoch: u64,
    wrapped_dek: Vec<u8>,
    current_commit_id: [u8; 32],
}

struct MigratedRow {
    document_id: DocumentId,
    generation: u64,
    key_epoch: u64,
    wrapped_dek: Vec<u8>,
    snapshot: Vec<u8>,
    next_eviction: Option<u64>,
    commit: ProtectedCommit,
}

/// Upgrade a supported older schema after hardware and factor authentication
/// have produced the installation secrets. A migration owns one immediate
/// transaction and advances the version only after all authenticated state is
/// rewritten successfully.
pub(super) async fn migrate_schema(
    connection: &Connection,
    device: &VaultMetadata,
    secrets: &InstallationSecrets,
) -> VaultResult<()> {
    match read_schema_version(connection).await? {
        SCHEMA_VERSION => Ok(()),
        LEGACY_SCHEMA_VERSION => migrate_v3_to_v5(connection, device, secrets).await,
        version if version > SCHEMA_VERSION => Err(VaultError::Database(format!(
            "vault database schema version {version} was written by a newer Factorseal build"
        ))),
        version => Err(VaultError::Database(format!(
            "vault database schema version {version} has no supported migration"
        ))),
    }
}

pub(super) async fn verify_schema(connection: &Connection) -> VaultResult<()> {
    let version = read_schema_version(connection).await?;
    if version != SCHEMA_VERSION {
        return Err(VaultError::Database(format!(
            "expected vault database schema version {SCHEMA_VERSION}, found {version}"
        )));
    }
    Ok(())
}

async fn read_schema_version(connection: &Connection) -> VaultResult<u32> {
    let stored = query_optional_blob(
        connection,
        "SELECT value FROM store_meta WHERE key = 'schema-version'",
        (),
    )
    .await?
    .ok_or_else(|| VaultError::Database("missing schema version".to_owned()))?;
    let bytes: [u8; 4] = stored.try_into().map_err(|_| {
        VaultError::Database("vault database schema version has the wrong size".to_owned())
    })?;
    Ok(u32::from_be_bytes(bytes))
}

async fn migrate_v3_to_v5(
    connection: &Connection,
    device: &VaultMetadata,
    secrets: &InstallationSecrets,
) -> VaultResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
        .await
        .map_err(database_error)?;
    // Refuse to transform unauthenticated or incomplete legacy state. This
    // check occurs in the same writer transaction as the rewrite.
    let latest = verify_legacy_chain(connection, device).await?;
    let rows = legacy_document_rows(connection, &latest).await?;
    let migrated = prepare_v5_rows(connection, device, secrets, rows).await?;
    persist_v5_rows(&transaction, &migrated).await?;
    transaction.commit().await.map_err(database_error)?;
    verify_schema(connection).await
}

async fn prepare_v5_rows(
    connection: &Connection,
    device: &VaultMetadata,
    secrets: &InstallationSecrets,
    rows: Vec<LegacyDocumentRow>,
) -> VaultResult<Vec<MigratedRow>> {
    let signing_seed = secrets.signing_seed(device.installation_id(), device.device_vault_id())?;
    let mut previous_commit_id = None;
    let mut migrated = Vec::with_capacity(rows.len());
    for row in rows {
        let envelope_bytes = query_optional_blob(
            connection,
            "SELECT envelope FROM document_snapshots
             WHERE document_id = ?1 AND generation = ?2",
            params![row.document_id.as_bytes().to_vec(), to_i64(row.generation)?,],
        )
        .await?
        .ok_or_else(|| VaultError::InvalidData("document has no current snapshot".to_owned()))?;
        let envelope: LegacyEncryptedSnapshot = serde_json::from_slice(&envelope_bytes)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        let wrapped: WrappedKey = serde_json::from_slice(&row.wrapped_dek)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        let old_key = secrets.unwrap_document_key(
            device.installation_id(),
            row.vault_id,
            row.document_id,
            row.scope,
            row.key_epoch,
            &wrapped,
        )?;
        let plaintext = envelope.decrypt(&row, device.device_key_id(), &old_key)?;
        let projected = SecretDocument::migrate_v2(&plaintext, device.actor_id(), row.scope)?;
        let generation = row.generation.checked_add(1).ok_or_else(|| {
            VaultError::InvalidData("document generation is exhausted".to_owned())
        })?;
        let key_epoch = row
            .key_epoch
            .checked_add(1)
            .ok_or_else(|| VaultError::InvalidData("document key epoch is exhausted".to_owned()))?;
        let (data_key, wrapped) = secrets.generate_document_key(
            device.installation_id(),
            row.vault_id,
            row.document_id,
            row.scope,
            key_epoch,
        )?;
        let wrapped_dek = serde_json::to_vec(&wrapped)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        let current_envelope = encrypt_snapshot(
            &EnvelopeContext {
                vault_id: row.vault_id,
                document_id: row.document_id,
                scope: row.scope,
                device_key_id: device.device_key_id(),
                generation,
                key_epoch,
            },
            &projected.snapshot,
            &projected.history,
            &data_key,
        )?;
        let snapshot = serde_json::to_vec(&current_envelope)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        let commit = ProtectedCommit::new(
            CommitContents {
                previous_commit_id,
                vault_id: row.vault_id,
                document_id: row.document_id,
                scope: row.scope,
                generation,
                key_epoch,
                wrapped_key_digest: digest(&wrapped_dek),
                snapshot_digest: digest(&snapshot),
                next_eviction: projected.next_eviction,
                device_key_id: device.device_key_id(),
            },
            &signing_seed,
        )?;
        previous_commit_id = Some(commit.commit_id);
        migrated.push(MigratedRow {
            document_id: row.document_id,
            generation,
            key_epoch,
            wrapped_dek,
            snapshot,
            next_eviction: projected.next_eviction,
            commit,
        });
    }
    Ok(migrated)
}

async fn persist_v5_rows(
    transaction: &Transaction<'_>,
    migrated: &[MigratedRow],
) -> VaultResult<()> {
    transaction
        .execute("ALTER TABLE documents ADD COLUMN next_eviction INTEGER", ())
        .await
        .map_err(database_error)?;
    transaction
        .execute("DELETE FROM document_snapshots", ())
        .await
        .map_err(database_error)?;
    transaction
        .execute("DELETE FROM protected_commits", ())
        .await
        .map_err(database_error)?;
    for row in migrated {
        let next_eviction = row
            .next_eviction
            .map(to_i64)
            .transpose()?
            .map_or(Value::Null, Value::Integer);
        let record = serde_json::to_vec(&row.commit)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        let updated = transaction
            .execute(
                "UPDATE documents SET generation = ?1, key_epoch = ?2,
                     wrapped_dek = ?3, current_commit_id = ?4, next_eviction = ?5
                 WHERE document_id = ?6",
                params![
                    to_i64(row.generation)?,
                    to_i64(row.key_epoch)?,
                    row.wrapped_dek.clone(),
                    row.commit.commit_id.to_vec(),
                    next_eviction,
                    row.document_id.as_bytes().to_vec(),
                ],
            )
            .await
            .map_err(database_error)?;
        if updated != 1 {
            return Err(VaultError::Database(
                "migration could not replace a document head".to_owned(),
            ));
        }
        transaction
            .execute(
                "INSERT INTO document_snapshots(document_id, generation, envelope)
                 VALUES (?1, ?2, ?3)",
                params![
                    row.document_id.as_bytes().to_vec(),
                    to_i64(row.generation)?,
                    row.snapshot.clone(),
                ],
            )
            .await
            .map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO protected_commits(
                     commit_id, previous_commit_id, document_id, generation, record
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    row.commit.commit_id.to_vec(),
                    row.commit
                        .previous_commit_id
                        .map_or(Value::Null, |value| Value::Blob(value.to_vec())),
                    row.document_id.as_bytes().to_vec(),
                    to_i64(row.generation)?,
                    record,
                ],
            )
            .await
            .map_err(database_error)?;
    }
    match migrated.last().map(|row| row.commit.commit_id) {
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
    transaction
        .execute(
            "UPDATE store_meta SET value = ?1 WHERE key = 'schema-version'",
            [SCHEMA_VERSION.to_be_bytes().to_vec()],
        )
        .await
        .map_err(database_error)?;
    Ok(())
}

async fn verify_legacy_chain(
    connection: &Connection,
    device: &VaultMetadata,
) -> VaultResult<BTreeMap<DocumentId, LegacyProtectedCommit>> {
    let head = query_optional_blob(
        connection,
        "SELECT value FROM store_meta WHERE key = 'current-commit-head'",
        (),
    )
    .await?
    .map(|bytes| array_from_blob(&bytes, "current commit head"))
    .transpose()?;
    let mut current = head;
    let mut visited = HashSet::new();
    let mut latest = BTreeMap::new();

    while let Some(commit_id) = current {
        if visited.len() >= MAX_MIGRATION_COMMIT_CHAIN || !visited.insert(commit_id) {
            return Err(VaultError::InvalidData(
                "protected commit chain is cyclic or too long".to_owned(),
            ));
        }
        let mut rows = connection
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
        if rows.next().await.map_err(database_error)?.is_some() {
            return Err(VaultError::InvalidData(
                "duplicate protected commit".to_owned(),
            ));
        }
        drop(rows);
        let commit: LegacyProtectedCommit = serde_json::from_slice(&record_bytes)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        commit.verify(commit_id, device)?;
        if stored_previous != commit.previous_commit_id
            || stored_document_id != commit.document_id
            || stored_generation != commit.generation
        {
            return Err(VaultError::InvalidData(
                "protected commit SQL metadata does not match its signed record".to_owned(),
            ));
        }
        let snapshot = query_optional_blob(
            connection,
            "SELECT envelope FROM document_snapshots
             WHERE document_id = ?1 AND generation = ?2",
            params![
                commit.document_id.as_bytes().to_vec(),
                to_i64(commit.generation)?,
            ],
        )
        .await?
        .ok_or_else(|| {
            VaultError::InvalidData("protected commit snapshot is missing".to_owned())
        })?;
        if digest(&snapshot) != commit.snapshot_digest {
            return Err(VaultError::Signature);
        }
        current = commit.previous_commit_id;
        latest.entry(commit.document_id).or_insert(commit);
    }

    let commit_count =
        query_count(connection, "SELECT COUNT(*) FROM protected_commits", ()).await?;
    let snapshot_count =
        query_count(connection, "SELECT COUNT(*) FROM document_snapshots", ()).await?;
    let document_count = query_count(connection, "SELECT COUNT(*) FROM documents", ()).await?;
    if commit_count != visited.len() as u64
        || snapshot_count != commit_count
        || document_count != latest.len() as u64
    {
        return Err(VaultError::InvalidData(
            "legacy database contains state outside its protected chain".to_owned(),
        ));
    }
    Ok(latest)
}

async fn legacy_document_rows(
    connection: &Connection,
    latest: &BTreeMap<DocumentId, LegacyProtectedCommit>,
) -> VaultResult<Vec<LegacyDocumentRow>> {
    let mut rows = connection
        .query(
            "SELECT vault_id, document_id, document_kind, generation, key_epoch,
                    wrapped_dek, current_commit_id
             FROM documents ORDER BY document_id",
            (),
        )
        .await
        .map_err(database_error)?;
    let mut documents = Vec::with_capacity(latest.len());
    while let Some(row) = rows.next().await.map_err(database_error)? {
        let document = LegacyDocumentRow {
            vault_id: VaultId::from_bytes(array_from_blob(&row_blob(&row, 0)?, "vault ID")?),
            document_id: document_id_from_blob(&row_blob(&row, 1)?)?,
            scope: DocumentKind::parse(&row_text(&row, 2)?)?,
            generation: from_i64(row_integer(&row, 3)?, "document generation")?,
            key_epoch: from_i64(row_integer(&row, 4)?, "document key epoch")?,
            wrapped_dek: row_blob(&row, 5)?,
            current_commit_id: array_from_blob(&row_blob(&row, 6)?, "document commit ID")?,
        };
        let protected = latest
            .get(&document.document_id)
            .ok_or(VaultError::Signature)?;
        if protected.vault_id != document.vault_id
            || protected.scope != document.scope
            || protected.generation != document.generation
            || protected.key_epoch != document.key_epoch
            || protected.wrapped_key_digest != digest(&document.wrapped_dek)
            || protected.commit_id != document.current_commit_id
        {
            return Err(VaultError::Signature);
        }
        documents.push(document);
    }
    Ok(documents)
}

fn legacy_snapshot_header(envelope: &LegacyEncryptedSnapshot) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(LEGACY_SNAPSHOT_DOMAIN);
    bytes.push(LEGACY_ENVELOPE_VERSION);
    bytes.push(envelope.encryption_algorithm.code());
    bytes.extend_from_slice(envelope.vault_id.as_bytes());
    bytes.extend_from_slice(envelope.document_id.as_bytes());
    append_bytes(&mut bytes, envelope.scope.as_str().as_bytes());
    bytes.extend_from_slice(envelope.device_key_id.as_bytes());
    bytes.extend_from_slice(&envelope.generation.to_be_bytes());
    bytes.extend_from_slice(&envelope.key_epoch.to_be_bytes());
    append_array_list(&mut bytes, &envelope.heads);
    bytes
}

fn legacy_commit_transcript(commit: &LegacyProtectedCommit) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(224);
    bytes.extend_from_slice(LEGACY_COMMIT_DOMAIN);
    bytes.push(LEGACY_COMMIT_VERSION);
    bytes.push(commit.signature_algorithm.code());
    match commit.previous_commit_id {
        Some(previous) => {
            bytes.push(1);
            bytes.extend_from_slice(&previous);
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(commit.vault_id.as_bytes());
    bytes.extend_from_slice(commit.document_id.as_bytes());
    append_bytes(&mut bytes, commit.scope.as_str().as_bytes());
    bytes.extend_from_slice(&commit.generation.to_be_bytes());
    bytes.extend_from_slice(&commit.key_epoch.to_be_bytes());
    bytes.extend_from_slice(&commit.wrapped_key_digest);
    bytes.extend_from_slice(&commit.snapshot_digest);
    bytes.extend_from_slice(commit.device_key_id.as_bytes());
    bytes
}

fn legacy_commit_signature_payload(commit_id: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(LEGACY_COMMIT_SIGNATURE_DOMAIN.len() + commit_id.len());
    bytes.extend_from_slice(LEGACY_COMMIT_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(commit_id);
    bytes
}

fn append_bytes(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn append_array_list(target: &mut Vec<u8>, values: &[[u8; 32]]) {
    target.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        target.extend_from_slice(value);
    }
}

#[cfg(all(test, feature = "key-protection"))]
mod tests {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    use super::*;
    use crate::vault::{
        DATABASE_FILE, MutationContext, Provenance, SecretAddress, ServiceReason, Vault, VaultStore,
    };

    #[test]
    fn schema_three_is_authenticated_and_migrated_without_losing_secrets_or_history() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        let unsealed = Vault::create_for_test(&root).unwrap();
        let (device, secrets, initialize_store) = unsealed.into_parts();
        assert!(initialize_store);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(write_legacy_store(&root, &device, &secrets));
        drop(secrets);

        let store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
        let address = SecretAddress::new("migrated-token", None).unwrap();
        assert_eq!(
            store
                .get_at(DocumentKind::LocalKeyring, b"personal", &address, 100,)
                .unwrap()
                .unwrap()
                .as_slice(),
            b"preserved secret"
        );
        let history = store
            .list_history(
                DocumentKind::LocalKeyring,
                b"personal",
                Some(&address),
                None,
                10,
            )
            .unwrap();
        assert_eq!(history.items.len(), 1);
        assert_eq!(history.items[0].seq, 0);
        store.seal();

        runtime.block_on(async {
            let database = turso::Builder::new_local(
                root.join(DATABASE_FILE).to_str().expect("UTF-8 test path"),
            )
            .build()
            .await
            .unwrap();
            let connection = database.connect().unwrap();
            assert_eq!(
                read_schema_version(&connection).await.unwrap(),
                SCHEMA_VERSION
            );
            assert_eq!(
                query_count(&connection, "SELECT COUNT(*) FROM protected_commits", ())
                    .await
                    .unwrap(),
                1
            );
        });
    }

    #[test]
    fn migration_rejects_tampered_legacy_state_without_advancing_the_schema() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        let unsealed = Vault::create_for_test(&root).unwrap();
        let (device, secrets, initialize_store) = unsealed.into_parts();
        assert!(initialize_store);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            write_legacy_store(&root, &device, &secrets).await;
            let database = turso::Builder::new_local(
                root.join(DATABASE_FILE).to_str().expect("UTF-8 test path"),
            )
            .build()
            .await
            .unwrap();
            let connection = database.connect().unwrap();
            connection
                .execute("UPDATE protected_commits SET record = x'00'", ())
                .await
                .unwrap();
        });
        drop(secrets);

        assert!(VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).is_err());
        runtime.block_on(async {
            let database = turso::Builder::new_local(
                root.join(DATABASE_FILE).to_str().expect("UTF-8 test path"),
            )
            .build()
            .await
            .unwrap();
            let connection = database.connect().unwrap();
            assert_eq!(
                read_schema_version(&connection).await.unwrap(),
                LEGACY_SCHEMA_VERSION
            );
            let mut rows = connection
                .query("PRAGMA table_info(documents)", ())
                .await
                .unwrap();
            let mut columns = Vec::new();
            while let Some(row) = rows.next().await.unwrap() {
                columns.push(row_text(&row, 1).unwrap());
            }
            assert!(!columns.iter().any(|column| column == "next_eviction"));
        });
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture spells out the historical schema"
    )]
    async fn write_legacy_store(
        root: &std::path::Path,
        device: &VaultMetadata,
        secrets: &InstallationSecrets,
    ) {
        let database =
            turso::Builder::new_local(root.join(DATABASE_FILE).to_str().expect("UTF-8 test path"))
                .build()
                .await
                .unwrap();
        let connection = database.connect().unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE store_meta (
                     key TEXT PRIMARY KEY NOT NULL,
                     value BLOB NOT NULL
                 );
                 CREATE TABLE installation_identity (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     installation_id BLOB NOT NULL,
                     device_vault_id BLOB NOT NULL,
                     device_key_id BLOB NOT NULL,
                     public_signing_key BLOB NOT NULL,
                     actor_id BLOB NOT NULL,
                     hardware_backend TEXT NOT NULL,
                     created_at INTEGER NOT NULL
                 );
                 CREATE TABLE vaults (
                     vault_id BLOB PRIMARY KEY NOT NULL,
                     vault_kind TEXT NOT NULL,
                     created_at INTEGER NOT NULL
                 );
                 CREATE TABLE documents (
                     document_id BLOB PRIMARY KEY NOT NULL,
                     vault_id BLOB NOT NULL,
                     document_kind TEXT NOT NULL,
                     generation INTEGER NOT NULL,
                     key_epoch INTEGER NOT NULL,
                     wrapped_dek BLOB NOT NULL,
                     current_commit_id BLOB NOT NULL,
                     FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
                 );
                 CREATE TABLE document_snapshots (
                     document_id BLOB NOT NULL,
                     generation INTEGER NOT NULL,
                     envelope BLOB NOT NULL,
                     PRIMARY KEY (document_id, generation),
                     FOREIGN KEY (document_id) REFERENCES documents(document_id)
                 );
                 CREATE TABLE protected_commits (
                     commit_id BLOB PRIMARY KEY NOT NULL,
                     previous_commit_id BLOB,
                     document_id BLOB NOT NULL,
                     generation INTEGER NOT NULL,
                     record BLOB NOT NULL
                 );",
            )
            .await
            .unwrap();
        connection
            .execute(
                "INSERT INTO store_meta(key, value) VALUES ('schema-version', ?1)",
                [LEGACY_SCHEMA_VERSION.to_be_bytes().to_vec()],
            )
            .await
            .unwrap();
        connection
            .execute(
                "INSERT INTO installation_identity(
                     singleton, installation_id, device_vault_id, device_key_id,
                     public_signing_key, actor_id, hardware_backend, created_at
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    device.installation_id().as_bytes().to_vec(),
                    device.device_vault_id().as_bytes().to_vec(),
                    device.device_key_id().as_bytes().to_vec(),
                    device.public_signing_key().to_vec(),
                    device.actor_id().to_vec(),
                    device.hardware_backend(),
                    to_i64(device.created_at()).unwrap(),
                ],
            )
            .await
            .unwrap();
        connection
            .execute(
                "INSERT INTO vaults(vault_id, vault_kind, created_at) VALUES (?1, 'device', ?2)",
                params![
                    device.device_vault_id().as_bytes().to_vec(),
                    to_i64(device.created_at()).unwrap(),
                ],
            )
            .await
            .unwrap();

        let scope = DocumentKind::LocalKeyring;
        let partition = b"personal";
        let document_id = legacy_document_id(secrets, device.device_vault_id(), scope, partition);
        let address = SecretAddress::new("migrated-token", None).unwrap();
        let provenance = Provenance::service(ServiceReason::GrantStorage);
        let context = MutationContext {
            now: 50,
            provenance: &provenance,
            device_key_id: device.device_key_id(),
        };
        let (plaintext, heads) = SecretDocument::legacy_v2_fixture(
            device.actor_id(),
            scope,
            partition,
            &address,
            b"preserved secret",
            Some(4_102_444_800),
            &context,
        )
        .unwrap();
        let (data_key, wrapped) = secrets
            .generate_document_key(
                device.installation_id(),
                device.device_vault_id(),
                document_id,
                scope,
                1,
            )
            .unwrap();
        let wrapped_dek = serde_json::to_vec(&wrapped).unwrap();
        let mut envelope = LegacyEncryptedSnapshot {
            version: LEGACY_ENVELOPE_VERSION,
            encryption_algorithm: crypto::CURRENT_ENCRYPTION_ALGORITHM,
            vault_id: device.device_vault_id(),
            document_id,
            scope,
            device_key_id: device.device_key_id(),
            generation: 1,
            key_epoch: 1,
            heads,
            nonce: [0; crate::algorithm::AES_GCM_NONCE_BYTES],
            ciphertext: Vec::new(),
        };
        let encrypted =
            crypto::encrypt(&data_key, &legacy_snapshot_header(&envelope), &plaintext).unwrap();
        envelope.encryption_algorithm = encrypted.algorithm;
        envelope.nonce = encrypted.nonce;
        envelope.ciphertext = encrypted.ciphertext;
        let snapshot = serde_json::to_vec(&envelope).unwrap();
        let signing_seed = secrets
            .signing_seed(device.installation_id(), device.device_vault_id())
            .unwrap();
        let mut commit = LegacyProtectedCommit {
            version: LEGACY_COMMIT_VERSION,
            signature_algorithm: crate::vault::signature::CURRENT_SIGNATURE_ALGORITHM,
            commit_id: [0; 32],
            previous_commit_id: None,
            vault_id: device.device_vault_id(),
            document_id,
            scope,
            generation: 1,
            key_epoch: 1,
            wrapped_key_digest: digest(&wrapped_dek),
            snapshot_digest: digest(&snapshot),
            device_key_id: device.device_key_id(),
            signature: Vec::new(),
        };
        commit.commit_id = digest(&legacy_commit_transcript(&commit));
        commit.signature = signature::sign(
            &signing_seed,
            &legacy_commit_signature_payload(&commit.commit_id),
        )
        .unwrap();
        let record = serde_json::to_vec(&commit).unwrap();

        connection
            .execute(
                "INSERT INTO documents(
                     document_id, vault_id, document_kind, generation, key_epoch,
                     wrapped_dek, current_commit_id
                 ) VALUES (?1, ?2, ?3, 1, 1, ?4, ?5)",
                params![
                    document_id.as_bytes().to_vec(),
                    device.device_vault_id().as_bytes().to_vec(),
                    scope.as_str(),
                    wrapped_dek,
                    commit.commit_id.to_vec(),
                ],
            )
            .await
            .unwrap();
        connection
            .execute(
                "INSERT INTO document_snapshots(document_id, generation, envelope)
                 VALUES (?1, 1, ?2)",
                params![document_id.as_bytes().to_vec(), snapshot],
            )
            .await
            .unwrap();
        connection
            .execute(
                "INSERT INTO protected_commits(
                     commit_id, previous_commit_id, document_id, generation, record
                 ) VALUES (?1, NULL, ?2, 1, ?3)",
                params![
                    commit.commit_id.to_vec(),
                    document_id.as_bytes().to_vec(),
                    record,
                ],
            )
            .await
            .unwrap();
        connection
            .execute(
                "INSERT INTO store_meta(key, value) VALUES ('current-commit-head', ?1)",
                [commit.commit_id.to_vec()],
            )
            .await
            .unwrap();
    }

    fn legacy_document_id(
        secrets: &InstallationSecrets,
        vault_id: VaultId,
        kind: DocumentKind,
        partition: &[u8],
    ) -> DocumentId {
        let mut mac = Hmac::<Sha256>::new_from_slice(secrets.index_key()).unwrap();
        mac.update(b"factorseal/document-id/v3\0");
        mac.update(vault_id.as_bytes());
        mac.update(&(kind.as_str().len() as u64).to_be_bytes());
        mac.update(kind.as_str().as_bytes());
        mac.update(&(partition.len() as u64).to_be_bytes());
        mac.update(partition);
        DocumentId::from_bytes(mac.finalize().into_bytes().into())
    }
}

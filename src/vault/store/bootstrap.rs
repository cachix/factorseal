//! Database opening, schema initialization, and installation identity checks.

use std::fs;
use std::path::Path;

use fs2::FileExt;
use turso::{Connection, params};
use zeroize::Zeroizing;

use crate::vault::{DATABASE_FILE, UnsealedVault, VaultError, VaultMetadata, VaultResult};

use super::database::{
    database_error, open_lock, query_optional_blob, row_blob, row_integer, row_text, to_i64,
};

const SCHEMA_VERSION: u32 = 1;

pub(super) struct OpenedStore {
    pub(super) connection: Connection,
    pub(super) device: VaultMetadata,
    pub(super) data_key: Zeroizing<[u8; 32]>,
    pub(super) signing_seed: Zeroizing<[u8; 32]>,
    pub(super) lock_file: fs::File,
}

pub(super) async fn open_store(root: &Path, unsealed: UnsealedVault) -> VaultResult<OpenedStore> {
    let lock_file = open_lock(root)?;
    lock_file.try_lock_exclusive().map_err(|error| {
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
    validate_database_state(database_exists, initialize_store)?;

    let database_path = database_path.to_str().ok_or_else(|| {
        VaultError::Database("vault database path is not valid Unicode".to_owned())
    })?;
    let database = turso::Builder::new_local(database_path)
        .build()
        .await
        .map_err(database_error)?;
    let connection = database.connect().map_err(database_error)?;

    if initialize_store {
        initialize_schema(&connection).await?;
        insert_installation_row(&connection, &device).await?;
    } else {
        verify_schema(&connection).await?;
    }
    verify_installation_row(&connection, &device).await?;

    Ok(OpenedStore {
        connection,
        device,
        data_key,
        signing_seed,
        lock_file,
    })
}

fn validate_database_state(database_exists: bool, initialize_store: bool) -> VaultResult<()> {
    if database_exists == initialize_store {
        let message = if initialize_store {
            "refusing to initialize over a pre-existing vault database"
        } else {
            "initialized vault database is missing"
        };
        return Err(VaultError::Database(message.to_owned()));
    }
    Ok(())
}

async fn initialize_schema(connection: &Connection) -> VaultResult<()> {
    connection
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
                 document_kind TEXT NOT NULL,
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
    connection
        .execute(
            "INSERT OR IGNORE INTO store_meta(key, value) VALUES ('schema-version', ?1)",
            [schema],
        )
        .await
        .map_err(database_error)?;
    verify_schema(connection).await
}

async fn verify_schema(connection: &Connection) -> VaultResult<()> {
    let schema = SCHEMA_VERSION.to_be_bytes().to_vec();
    let stored = query_optional_blob(
        connection,
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

async fn insert_installation_row(
    connection: &Connection,
    device: &VaultMetadata,
) -> VaultResult<()> {
    connection
        .execute(
            "INSERT INTO vault_identity(
                 singleton, vault_id, device_key_id, public_signing_key,
                 actor_id, hardware_backend, key_epoch, created_at
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                device.vault_id().as_bytes().to_vec(),
                device.device_key_id().as_bytes().to_vec(),
                device.public_signing_key().to_vec(),
                device.actor_id().to_vec(),
                device.hardware_backend(),
                to_i64(device.key_epoch())?,
                to_i64(device.created_at())?,
            ],
        )
        .await
        .map_err(database_error)?;
    Ok(())
}

async fn verify_installation_row(
    connection: &Connection,
    device: &VaultMetadata,
) -> VaultResult<()> {
    let mut rows = connection
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
    let matches = row_blob(&row, 0)? == device.vault_id().as_bytes()
        && row_blob(&row, 1)? == device.device_key_id().as_bytes()
        && row_blob(&row, 2)? == device.public_signing_key()
        && row_blob(&row, 3)? == device.actor_id()
        && row_text(&row, 4)? == device.hardware_backend()
        && row_integer(&row, 5)? == to_i64(device.key_epoch())?
        && row_integer(&row, 6)? == to_i64(device.created_at())?;
    if !matches {
        return Err(VaultError::Database(
            "database belongs to a different vault".to_owned(),
        ));
    }
    Ok(())
}

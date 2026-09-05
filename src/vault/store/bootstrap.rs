//! Database opening, schema initialization, and installation identity checks.

use std::fs;
use std::path::Path;

use fs2::FileExt;
use turso::{Connection, params};

use crate::vault::{
    DATABASE_FILE, InstallationSecrets, UnsealedVault, VaultError, VaultKind, VaultMetadata,
    VaultResult,
};

use super::database::{
    database_error, open_lock, query_count, query_optional_blob, row_blob, row_integer, row_text,
    to_i64,
};

// Version 5 authenticates the eviction deadline in each protected commit so the sweep loads
// only documents with a record due for eviction. Version 3 removed the
// per-change table: one generation is one snapshot.
const SCHEMA_VERSION: u32 = 5;

pub(super) struct OpenedStore {
    pub(super) connection: Connection,
    pub(super) device: VaultMetadata,
    pub(super) secrets: InstallationSecrets,
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
    let (device, secrets, initialize_store) = unsealed.into_parts();
    validate_database_state(database_exists, initialize_store)?;

    let database_path = database_path.to_str().ok_or_else(|| {
        VaultError::Database("vault database path is not valid Unicode".to_owned())
    })?;
    let database = turso::Builder::new_local(database_path)
        .build()
        .await
        .map_err(database_error)?;
    let connection = database.connect().map_err(database_error)?;
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .await
        .map_err(database_error)?;

    if initialize_store {
        initialize_schema(&connection).await?;
        insert_installation_row(&connection, &device).await?;
        insert_device_vault_row(&connection, &device).await?;
    } else {
        verify_schema(&connection).await?;
    }
    verify_installation_row(&connection, &device).await?;

    Ok(OpenedStore {
        connection,
        device,
        secrets,
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
             CREATE TABLE IF NOT EXISTS installation_identity (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 installation_id BLOB NOT NULL,
                 device_vault_id BLOB NOT NULL,
                 device_key_id BLOB NOT NULL,
                 public_signing_key BLOB NOT NULL,
                 actor_id BLOB NOT NULL,
                 hardware_backend TEXT NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS vaults (
                 vault_id BLOB PRIMARY KEY NOT NULL,
                 vault_kind TEXT NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS documents (
                 document_id BLOB PRIMARY KEY NOT NULL,
                 vault_id BLOB NOT NULL,
                 document_kind TEXT NOT NULL,
                 generation INTEGER NOT NULL,
                 key_epoch INTEGER NOT NULL,
                 wrapped_dek BLOB NOT NULL,
                 current_commit_id BLOB NOT NULL,
                 next_eviction INTEGER,
                 FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
             );
             CREATE TABLE IF NOT EXISTS document_snapshots (
                 document_id BLOB NOT NULL,
                 generation INTEGER NOT NULL,
                 envelope BLOB NOT NULL,
                 PRIMARY KEY (document_id, generation),
                 FOREIGN KEY (document_id) REFERENCES documents(document_id)
             );
             CREATE TABLE IF NOT EXISTS protected_commits (
                 commit_id BLOB PRIMARY KEY NOT NULL,
                 previous_commit_id BLOB,
                 document_id BLOB NOT NULL,
                 generation INTEGER NOT NULL,
                 record BLOB NOT NULL
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
                to_i64(device.created_at())?,
            ],
        )
        .await
        .map_err(database_error)?;
    Ok(())
}

async fn insert_device_vault_row(
    connection: &Connection,
    device: &VaultMetadata,
) -> VaultResult<()> {
    connection
        .execute(
            "INSERT INTO vaults(vault_id, vault_kind, created_at) VALUES (?1, ?2, ?3)",
            params![
                device.device_vault_id().as_bytes().to_vec(),
                VaultKind::Device.as_str(),
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
            "SELECT installation_id, device_vault_id, device_key_id,
                    public_signing_key, actor_id, hardware_backend, created_at
             FROM installation_identity WHERE singleton = 1",
            (),
        )
        .await
        .map_err(database_error)?;
    let row = rows
        .next()
        .await
        .map_err(database_error)?
        .ok_or_else(|| VaultError::Database("missing installation identity row".to_owned()))?;
    let matches = row_blob(&row, 0)? == device.installation_id().as_bytes()
        && row_blob(&row, 1)? == device.device_vault_id().as_bytes()
        && row_blob(&row, 2)? == device.device_key_id().as_bytes()
        && row_blob(&row, 3)? == device.public_signing_key()
        && row_blob(&row, 4)? == device.actor_id()
        && row_text(&row, 5)? == device.hardware_backend()
        && row_integer(&row, 6)? == to_i64(device.created_at())?;
    if !matches {
        return Err(VaultError::Database(
            "database belongs to a different vault".to_owned(),
        ));
    }
    drop(rows);
    let mut vault_rows = connection
        .query(
            "SELECT vault_kind, created_at FROM vaults WHERE vault_id = ?1",
            [device.device_vault_id().as_bytes().to_vec()],
        )
        .await
        .map_err(database_error)?;
    let row = vault_rows
        .next()
        .await
        .map_err(database_error)?
        .ok_or_else(|| VaultError::Database("missing device vault row".to_owned()))?;
    if VaultKind::parse(&row_text(&row, 0)?)? != VaultKind::Device
        || row_integer(&row, 1)? != to_i64(device.created_at())?
    {
        return Err(VaultError::Database(
            "database device vault is inconsistent".to_owned(),
        ));
    }
    drop(vault_rows);
    if query_count(connection, "SELECT COUNT(*) FROM vaults", ()).await? != 1 {
        return Err(VaultError::InvalidData(
            "installation must contain exactly one Device vault".to_owned(),
        ));
    }
    Ok(())
}

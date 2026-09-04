use std::fs::{self, OpenOptions};
use std::path::Path;

use turso::{Connection, Value};

use crate::vault::{DocumentId, LOCK_FILE, VaultError, VaultResult};

pub(super) fn open_lock(root: &Path) -> VaultResult<fs::File> {
    let path = root.join(LOCK_FILE);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&path).map_err(|error| {
        VaultError::Database(format!("I/O error for `{}`: {error}", path.display()))
    })
}

pub(super) async fn query_optional_blob(
    connection: &Connection,
    sql: &str,
    parameters: impl turso::IntoParams,
) -> VaultResult<Option<Vec<u8>>> {
    let mut rows = connection
        .query(sql, parameters)
        .await
        .map_err(database_error)?;
    let result = rows
        .next()
        .await
        .map_err(database_error)?
        .map(|row| row_blob(&row, 0))
        .transpose()?;
    if rows.next().await.map_err(database_error)?.is_some() {
        return Err(VaultError::InvalidData(
            "database query returned duplicate rows".to_owned(),
        ));
    }
    Ok(result)
}

pub(super) async fn query_count(
    connection: &Connection,
    sql: &str,
    parameters: impl turso::IntoParams,
) -> VaultResult<u64> {
    let mut rows = connection
        .query(sql, parameters)
        .await
        .map_err(database_error)?;
    let row = rows
        .next()
        .await
        .map_err(database_error)?
        .ok_or_else(|| VaultError::InvalidData("count query returned no row".to_owned()))?;
    from_i64(row_integer(&row, 0)?, "row count")
}

pub(super) fn row_blob(row: &turso::Row, index: usize) -> VaultResult<Vec<u8>> {
    match row.get_value(index).map_err(database_error)? {
        Value::Blob(value) => Ok(value),
        _ => Err(VaultError::InvalidData(
            "database column is not a BLOB".to_owned(),
        )),
    }
}

pub(super) fn row_optional_blob(row: &turso::Row, index: usize) -> VaultResult<Option<Vec<u8>>> {
    match row.get_value(index).map_err(database_error)? {
        Value::Null => Ok(None),
        Value::Blob(value) => Ok(Some(value)),
        _ => Err(VaultError::InvalidData(
            "database column is not a nullable BLOB".to_owned(),
        )),
    }
}

pub(super) fn row_text(row: &turso::Row, index: usize) -> VaultResult<String> {
    match row.get_value(index).map_err(database_error)? {
        Value::Text(value) => Ok(value),
        _ => Err(VaultError::InvalidData(
            "database column is not text".to_owned(),
        )),
    }
}

pub(super) fn row_integer(row: &turso::Row, index: usize) -> VaultResult<i64> {
    match row.get_value(index).map_err(database_error)? {
        Value::Integer(value) => Ok(value),
        _ => Err(VaultError::InvalidData(
            "database column is not an integer".to_owned(),
        )),
    }
}

pub(super) fn row_deadline(row: &turso::Row, index: usize) -> VaultResult<Option<u64>> {
    match row.get_value(index).map_err(database_error)? {
        Value::Null => Ok(None),
        Value::Integer(value) => from_i64(value, "eviction deadline").map(Some),
        _ => Err(VaultError::InvalidData(
            "invalid eviction deadline".to_owned(),
        )),
    }
}

pub(super) fn document_id_from_blob(bytes: &[u8]) -> VaultResult<DocumentId> {
    Ok(DocumentId::from_bytes(array_from_blob(
        bytes,
        "document ID",
    )?))
}

pub(super) fn array_from_blob<const N: usize>(bytes: &[u8], name: &str) -> VaultResult<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| VaultError::InvalidData(format!("{name} has the wrong size")))
}

pub(super) fn to_i64(value: u64) -> VaultResult<i64> {
    value
        .try_into()
        .map_err(|_| VaultError::InvalidData("integer exceeds database range".to_owned()))
}

pub(super) fn from_i64(value: i64, name: &str) -> VaultResult<u64> {
    value
        .try_into()
        .map_err(|_| VaultError::InvalidData(format!("{name} is negative")))
}

#[allow(clippy::needless_pass_by_value)]
pub(super) fn database_error(error: turso::Error) -> VaultError {
    VaultError::Database(error.to_string())
}

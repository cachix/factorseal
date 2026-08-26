use std::fs;
#[cfg(feature = "key-protection")]
use std::fs::OpenOptions;
#[cfg(feature = "key-protection")]
use std::io::Write;
use std::path::Path;
#[cfg(feature = "key-protection")]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::vault::{VaultError, VaultResult};

#[cfg(feature = "key-protection")]
pub(super) fn prepare_root(root: &Path) -> VaultResult<()> {
    if let Some(parent) = root.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| path_error(parent, error))?;
    }
    create_private_root(root).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            VaultError::Protection(format!(
                "refusing to initialize in pre-existing vault root `{}`",
                root.display()
            ))
        } else {
            path_error(root, error)
        }
    })?;
    validate_root(root)
}

#[cfg(all(feature = "key-protection", unix))]
pub(super) fn create_private_root(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(root)
}

#[cfg(all(feature = "key-protection", not(unix)))]
pub(super) fn create_private_root(root: &Path) -> std::io::Result<()> {
    fs::create_dir(root)
}

pub(super) fn validate_root(root: &Path) -> VaultResult<()> {
    let metadata = fs::symlink_metadata(root).map_err(|error| path_error(root, error))?;
    if !metadata.file_type().is_dir() {
        return Err(VaultError::Protection(format!(
            "vault root `{}` is not a directory",
            root.display()
        )));
    }
    validate_private_permissions(root, &metadata)
}

#[cfg(all(feature = "key-protection", unix))]
pub(super) fn write_new_private_file(path: &Path, bytes: &[u8]) -> VaultResult<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    write_and_sync(path, &options, bytes)
}

#[cfg(all(feature = "key-protection", not(unix)))]
pub(super) fn write_new_private_file(path: &Path, bytes: &[u8]) -> VaultResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    write_and_sync(path, &options, bytes)
}

#[cfg(feature = "key-protection")]
pub(super) fn write_and_sync(path: &Path, options: &OpenOptions, bytes: &[u8]) -> VaultResult<()> {
    let mut file = options
        .open(path)
        .map_err(|error| path_error(path, error))?;
    file.write_all(bytes)
        .map_err(|error| path_error(path, error))?;
    file.sync_all().map_err(|error| path_error(path, error))
}

#[cfg(unix)]
pub(super) fn validate_private_permissions(
    path: &Path,
    metadata: &fs::Metadata,
) -> VaultResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(VaultError::Protection(format!(
            "vault root `{}` is accessible by group or other users (mode {mode:o})",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
pub(super) fn validate_private_permissions(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> VaultResult<()> {
    Ok(())
}

#[cfg(feature = "key-protection")]
pub(super) fn unix_time() -> VaultResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| VaultError::Protection(error.to_string()))
}

#[allow(clippy::needless_pass_by_value)]
pub(super) fn path_error(path: &Path, error: std::io::Error) -> VaultError {
    VaultError::Protection(format!("I/O error for `{}`: {error}", path.display()))
}

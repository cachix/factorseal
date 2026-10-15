//! Shared filesystem locations for the desktop app and its helpers.

use std::path::PathBuf;

/// The platform's default vault location.
/// On macOS, configuration and data share a directory, so give the vault its
/// own subdirectory that configuration writes cannot create prematurely.
#[must_use]
pub fn default_vault_root(dirs: &directories::ProjectDirs) -> PathBuf {
    if cfg!(target_os = "macos") {
        dirs.data_local_dir().join("vault")
    } else {
        dirs.data_local_dir().to_path_buf()
    }
}

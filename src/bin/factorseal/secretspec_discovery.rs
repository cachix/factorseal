//! SecretSpec provider discovery for the default vault installation.

use std::fs;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::io::Read;
#[cfg(unix)]
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

use directories::ProjectDirs;
use serde::Serialize;

use super::CliError;

const CLAIM_FILE: &str = "factorseal.secretspec.json";

#[derive(Serialize)]
struct ProviderClaim<'a> {
    executable: &'a Path,
}

pub(super) fn publish_for_default_root(root: &Path) -> Result<(), CliError> {
    let default_root = ProjectDirs::from("dev", "Factorseal", "Factorseal")
        .ok_or(CliError::NoDefaultRoot)?
        .data_local_dir()
        .to_owned();
    if root != default_root {
        return Ok(());
    }
    let executable = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| CliError::CurrentExecutable(error.to_string()))?;
    let directory = provider_directory().ok_or_else(|| {
        CliError::SecretSpecDiscovery("the user configuration directory is unavailable".to_owned())
    })?;
    write_claim(&directory, &executable)
}

fn provider_directory() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .map(|base| base.join("secretspec/providers.d"))
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join("Library/Application Support/SecretSpec/providers.d"))
    }
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|base| base.join("SecretSpec/providers.d"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        None
    }
}

fn write_claim(directory: &Path, executable: &Path) -> Result<(), CliError> {
    super::timing::result("secretspec_claim", "prepare_directory", || {
        fs::create_dir_all(directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if fs::metadata(directory)?.permissions().mode() & 0o7777 != 0o700 {
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok::<(), std::io::Error>(())
    })
    .map_err(|error| CliError::SecretSpecDiscovery(error.to_string()))?;
    let destination = directory.join(CLAIM_FILE);
    let bytes = serde_json::to_vec(&ProviderClaim { executable })?;
    #[cfg(unix)]
    let bytes = {
        let mut bytes = bytes;
        bytes.push(b'\n');
        bytes
    };
    if super::timing::result("secretspec_claim", "read_existing", || {
        claim_matches(&destination, &bytes)
    })
    .map_err(|error| CliError::SecretSpecDiscovery(error.to_string()))?
    {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let temporary = directory.join(format!(".{CLAIM_FILE}.{}.{nonce}.tmp", std::process::id()));
        let result = (|| -> Result<(), CliError> {
            let file = super::timing::result("secretspec_claim", "write_temporary", || {
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&temporary)?;
                file.write_all(&bytes)?;
                Ok::<_, std::io::Error>(file)
            })
            .map_err(|error| CliError::SecretSpecDiscovery(error.to_string()))?;
            super::timing::result("secretspec_claim", "sync_file", || file.sync_all())
                .map_err(|error| CliError::SecretSpecDiscovery(error.to_string()))?;
            super::timing::result("secretspec_claim", "rename", || {
                fs::rename(&temporary, &destination)
            })
            .map_err(|error| CliError::SecretSpecDiscovery(error.to_string()))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
    #[cfg(windows)]
    {
        fs::write(destination, bytes)
            .map_err(|error| CliError::SecretSpecDiscovery(error.to_string()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (directory, executable);
        Err(CliError::SecretSpecDiscovery(
            "this platform has no provider discovery location".to_owned(),
        ))
    }
}

fn claim_matches(destination: &Path, expected: &[u8]) -> std::io::Result<bool> {
    let metadata = match fs::symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    // A symlink or an incorrectly protected claim must be replaced, even if
    // its contents happen to match. Keep reads bounded if the file changes.
    if !metadata.is_file() || metadata.len() != expected.len() as u64 {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o7777 != 0o600 {
            return Ok(false);
        }
    }
    let mut existing = Vec::with_capacity(expected.len() + 1);
    fs::File::open(destination)?
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut existing)?;
    Ok(existing == expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn secretspec_claim_contains_only_the_canonical_executable() {
        let directory = tempfile::tempdir().unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();

        write_claim(directory.path(), &executable).unwrap();

        let claim =
            fs::read_to_string(directory.path().join("factorseal.secretspec.json")).unwrap();
        let claim: serde_json::Value = serde_json::from_str(&claim).unwrap();
        assert_eq!(claim, serde_json::json!({ "executable": executable }));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(directory.path().join("factorseal.secretspec.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn secretspec_claim_is_unchanged_on_repeat_publication() {
        let directory = tempfile::tempdir().unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let claim = directory.path().join("factorseal.secretspec.json");
        write_claim(directory.path(), &executable).unwrap();
        let file = fs::OpenOptions::new().write(true).open(&claim).unwrap();
        let old_time = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
        file.set_times(fs::FileTimes::new().set_modified(old_time))
            .unwrap();
        drop(file);
        let before = fs::metadata(&claim).unwrap();
        #[cfg(unix)]
        let directory_before = fs::metadata(directory.path()).unwrap();

        write_claim(directory.path(), &executable).unwrap();

        let after = fs::metadata(&claim).unwrap();
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            assert_eq!(before.ino(), after.ino());
            assert_eq!(
                (before.ctime(), before.ctime_nsec()),
                (after.ctime(), after.ctime_nsec())
            );
            let directory_after = fs::metadata(directory.path()).unwrap();
            assert_eq!(
                (directory_before.ctime(), directory_before.ctime_nsec()),
                (directory_after.ctime(), directory_after.ctime_nsec()),
            );
        }
    }

    #[test]
    fn secretspec_claim_updates_a_changed_executable_and_repairs_corrupt_content() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first-factorseal");
        let second = directory.path().join("second-factorseal");
        let claim = directory.path().join("factorseal.secretspec.json");
        write_claim(directory.path(), &first).unwrap();
        write_claim(directory.path(), &second).unwrap();
        let expected = serde_json::json!({ "executable": second });
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&claim).unwrap()).unwrap(),
            expected
        );
        fs::write(&claim, b"invalid claim").unwrap();
        write_claim(directory.path(), &second).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&claim).unwrap()).unwrap(),
            expected
        );
    }

    #[cfg(unix)]
    #[test]
    fn secretspec_claim_repairs_permissions_even_when_content_matches() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("factorseal");
        let claim = directory.path().join("factorseal.secretspec.json");
        write_claim(directory.path(), &executable).unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&claim, fs::Permissions::from_mode(0o644)).unwrap();
        write_claim(directory.path(), &executable).unwrap();
        assert_eq!(
            fs::metadata(directory.path()).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        assert_eq!(
            fs::metadata(&claim).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn secretspec_claim_replaces_a_matching_symlink_without_changing_its_target() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("factorseal");
        let claim = directory.path().join("factorseal.secretspec.json");
        let target = directory.path().join("original-claim");
        write_claim(directory.path(), &executable).unwrap();
        fs::rename(&claim, &target).unwrap();
        let before = fs::read(&target).unwrap();
        symlink(&target, &claim).unwrap();
        write_claim(directory.path(), &executable).unwrap();
        assert!(fs::symlink_metadata(&claim).unwrap().is_file());
        assert_eq!(fs::read(&target).unwrap(), before);
        assert_eq!(fs::read(&claim).unwrap(), before);
    }
}

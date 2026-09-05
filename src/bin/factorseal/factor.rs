use std::fs;
use std::io::IsTerminal as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process;

use zeroize::Zeroizing;

use super::commands::read_bounded;
use super::{CliError, MAX_FACTOR_BYTES};

/// Where the vault obtains a password factor when the selected group needs it.
#[derive(Clone, Copy)]
pub(super) struct FactorSource<'a> {
    pub(super) password_file: Option<&'a Path>,
    pub(super) askpass: Option<&'a Path>,
}

/// Read the password factor from an explicit file, an askpass helper, or the
/// controlling terminal, in that order.
///
/// A package that starts the vault from launchd, a logon task, or a systemd
/// unit has no terminal, so it must supply one of the first two. Failing with
/// a terminal prompt error in that case would say nothing useful.
pub(super) fn read_factor(
    source: FactorSource<'_>,
    confirm: bool,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let secret = if let Some(path) = source.password_file {
        read_password_file(path)?
    } else if let Some(helper) = source.askpass {
        let first = run_askpass(helper, "Factorseal password:")?;
        if confirm {
            let second = run_askpass(helper, "Confirm Factorseal password:")?;
            if first.as_slice() != second.as_slice() {
                return Err(CliError::Password("passwords do not match".to_owned()));
            }
        }
        first
    } else if std::io::stdin().is_terminal() {
        let first = prompt_on_terminal("Factorseal password: ").map_err(CliError::Password)?;
        if confirm {
            let second =
                prompt_on_terminal("Confirm Factorseal password: ").map_err(CliError::Password)?;
            if first.as_slice() != second.as_slice() {
                return Err(CliError::Password("passwords do not match".to_owned()));
            }
        }
        first
    } else {
        return Err(CliError::NoFactorSource);
    };
    if secret.is_empty() {
        return Err(CliError::Password(
            "the Factorseal factor must not be empty".to_owned(),
        ));
    }
    if secret.len() as u64 > MAX_FACTOR_BYTES {
        return Err(CliError::Password(
            "the Factorseal factor must not exceed 64 KiB".to_owned(),
        ));
    }
    Ok(secret)
}

fn prompt_on_terminal(label: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    rpassword::prompt_password(label)
        .map(|secret| Zeroizing::new(secret.into_bytes()))
        .map_err(|error| error.to_string())
}

pub(super) fn read_archive_passphrase(
    passphrase_file: Option<&Path>,
    confirm: bool,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let passphrase = if let Some(path) = passphrase_file {
        read_private_secret_file(path).map_err(CliError::ArchivePassphrase)?
    } else if std::io::stdin().is_terminal() {
        let first =
            prompt_on_terminal("Archive passphrase: ").map_err(CliError::ArchivePassphrase)?;
        if confirm {
            let second = prompt_on_terminal("Confirm archive passphrase: ")
                .map_err(CliError::ArchivePassphrase)?;
            if first.as_slice() != second.as_slice() {
                return Err(CliError::ArchivePassphrase(
                    "passphrases do not match".to_owned(),
                ));
            }
        }
        first
    } else {
        return Err(CliError::NoArchivePassphraseSource);
    };
    if passphrase.is_empty() {
        return Err(CliError::ArchivePassphrase(
            "the archive passphrase must not be empty".to_owned(),
        ));
    }
    Ok(passphrase)
}

/// Run the askpass helper and take its standard output as the factor.
///
/// The secret crosses a pipe rather than the filesystem, so it is never
/// written next to the vault it protects.
fn run_askpass(helper: &Path, label: &str) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut child = process::Command::new(helper)
        .arg(label)
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::piped())
        .spawn()
        .map_err(|error| CliError::Askpass(format!("{}: {error}", helper.display())))?;
    let read = child
        .stdout
        .take()
        .ok_or_else(|| CliError::Askpass("helper produced no output stream".to_owned()))
        .and_then(|stdout| {
            read_bounded(stdout, MAX_FACTOR_BYTES)
                .map_err(|error| CliError::Askpass(error.to_string()))
        });
    let status = child
        .wait()
        .map_err(|error| CliError::Askpass(error.to_string()))?;
    let mut secret = read?;
    if secret.len() as u64 > MAX_FACTOR_BYTES {
        return Err(CliError::Askpass(
            "helper output must not exceed 64 KiB".to_owned(),
        ));
    }
    if !status.success() {
        return Err(CliError::Askpass(format!(
            "{} exited without providing a factor",
            helper.display()
        )));
    }
    strip_one_line_ending(&mut secret);
    Ok(secret)
}

fn strip_one_line_ending(bytes: &mut Zeroizing<Vec<u8>>) {
    if bytes.ends_with(b"\r\n") {
        let new_length = bytes.len() - 2;
        bytes.truncate(new_length);
    } else if bytes.ends_with(b"\n") {
        let new_length = bytes.len() - 1;
        bytes.truncate(new_length);
    }
}

fn read_password_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    read_private_secret_file(path).map_err(CliError::Password)
}

fn read_private_secret_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_FACTOR_BYTES {
        return Err(format!(
            "{} must be a regular file no larger than 64 KiB",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} is accessible by group or other users (mode {mode:o})",
                path.display()
            ));
        }
    }
    let file = fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut bytes = read_bounded(file, MAX_FACTOR_BYTES)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_FACTOR_BYTES {
        return Err(format!(
            "{} must be a regular file no larger than 64 KiB",
            path.display()
        ));
    }
    strip_one_line_ending(&mut bytes);
    Ok(bytes)
}

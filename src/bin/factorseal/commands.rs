//! Command implementations for vault lifecycle, keyring, and grant operations.

use std::fs;
use std::io::{IsTerminal as _, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use directories::ProjectDirs;
use factorseal::{
    GrantPermission, Keyring, UnsealFactor, UnsealLeasePolicy, Vault, VaultAction, VaultClient,
    VaultError, VaultMetadata, VaultRequest, VaultResponseBody, VaultResponseErrorCode,
    VaultService, WireSecretAddress,
};
use serde::Serialize;
use zeroize::Zeroizing;

use super::factor::{FactorSource, read_factor};
use super::platform::{caller_identity_for_executable, native_client, serve_vault};
use super::{
    CliError, KEYRING_NAMESPACE, KEYRING_PERMISSIONS, MAX_KEYRING_VALUE_BYTES,
    SECRETSPEC_CACHE_NAMESPACE,
};

#[derive(Serialize)]
struct Status<'a> {
    path: String,
    vault_id: String,
    device_key_id: String,
    public_signing_key: String,
    actor_id: String,
    platform: &'a str,
    hardware_backend: &'a str,
    nested_factor: &'a str,
    key_epoch: u64,
    created_at: u64,
    state: &'static str,
}

pub(super) fn initialize(
    root: &Path,
    biometric: bool,
    factor: FactorSource<'_>,
) -> Result<(), CliError> {
    let password = read_factor(factor, true)?;
    let unsealed = Vault::create(root, UnsealFactor::Password(&password), biometric)?;
    let device = unsealed.public().clone();
    // The vault metadata is already on disk, and `create` refuses to run again while it
    // is there. Undo what this command wrote so `init` can simply be retried
    // rather than leaving a root nothing can finish or open.
    let now = unix_time()?;
    let service = match VaultService::open(root, unsealed, now, UnsealLeasePolicy::default()) {
        Ok(service) => service,
        Err(open_error) => {
            return match Vault::discard_initialization(root) {
                Ok(()) => Err(open_error.into()),
                Err(cleanup_error) => Err(VaultError::Protection(format!(
                    "{open_error}; initialization rollback failed: {cleanup_error}"
                ))
                .into()),
            };
        }
    };
    authorize_cli(&service, now)?;
    service.seal()?;
    println!(
        "Initialized Factorseal vault {} at {} using {}",
        device.vault_id(),
        root.display(),
        device.hardware_backend()
    );
    Ok(())
}

pub(super) fn show_status(root: &Path, socket: Option<&Path>) -> Result<(), CliError> {
    let device = Vault::inspect(root)?;
    let state = live_state(root, socket, &device);
    let status = Status {
        path: root.display().to_string(),
        vault_id: device.vault_id().to_string(),
        device_key_id: device.device_key_id().to_string(),
        public_signing_key: hex::encode(device.public_signing_key()),
        actor_id: hex::encode(device.actor_id()),
        platform: device.platform(),
        hardware_backend: device.hardware_backend(),
        nested_factor: device.nested_factor().as_str(),
        key_epoch: device.key_epoch(),
        created_at: device.created_at(),
        state,
    };
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

/// Ask the running agent which state this vault is in.
///
/// A `Status` answer is itself the proof of an unsealed vault: the action is
/// served behind the live-state lock, so a sealed vault answers with the
/// `Sealed` code and a vault with no agent cannot be reached at all. Anything
/// else, including an agent serving a different vault, stays `unknown`.
fn live_state(root: &Path, socket: Option<&Path>, device: &VaultMetadata) -> &'static str {
    let Ok(request) = VaultRequest::new(VaultAction::Status) else {
        return "unknown";
    };
    let Ok(client) = native_client(root, socket) else {
        return "unknown";
    };
    match client.request(&request) {
        Ok(response) => match response.result {
            Ok(VaultResponseBody::Status {
                vault_id,
                device_key_id,
                ..
            }) if vault_id == device.vault_id().to_string()
                && device_key_id == device.device_key_id().to_string() =>
            {
                "unsealed"
            }
            Err(error) if error.code == VaultResponseErrorCode::Sealed => "sealed",
            _ => "unknown",
        },
        Err(VaultError::AgentUnreachable(_)) => "sealed",
        Err(_) => "unknown",
    }
}

pub(super) fn set_keyring_value(
    root: &Path,
    socket: Option<&Path>,
    item: String,
    field: Option<String>,
    value_file: Option<&Path>,
) -> Result<(), CliError> {
    let value = read_keyring_value(value_file)?;
    let client = native_client(root, socket)?;
    client.set(
        KEYRING_NAMESPACE,
        &WireSecretAddress::new(item, field),
        &value,
    )?;
    Ok(())
}

pub(super) fn get_keyring_value(
    root: &Path,
    socket: Option<&Path>,
    item: String,
    field: Option<String>,
) -> Result<(), CliError> {
    let client = native_client(root, socket)?;
    let value = client.get(KEYRING_NAMESPACE, &WireSecretAddress::new(item, field))?;
    let value = value.ok_or(CliError::KeyringEntryNotFound)?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(value.expose())
        .and_then(|()| stdout.flush())
        .map_err(|error| CliError::KeyringInput(error.to_string()))
}

pub(super) fn delete_keyring_value(
    root: &Path,
    socket: Option<&Path>,
    item: String,
    field: Option<String>,
) -> Result<(), CliError> {
    let client = native_client(root, socket)?;
    let existed = client.delete(KEYRING_NAMESPACE, &WireSecretAddress::new(item, field))?;
    if !existed {
        return Err(CliError::KeyringEntryNotFound);
    }
    Ok(())
}

pub(super) fn destroy_vault(
    root: &Path,
    socket: Option<&Path>,
    factor: FactorSource<'_>,
    confirmed: bool,
) -> Result<(), CliError> {
    if !confirmed {
        return Err(CliError::DestroyConfirmationRequired);
    }
    let device = Vault::inspect(root)?;
    match live_state(root, socket, &device) {
        "sealed" => {}
        "unsealed" => return Err(CliError::VaultIsLive),
        _ => return Err(CliError::VaultStateUnknown),
    }
    let password = read_factor(factor, false)?;
    Vault::destroy(root, UnsealFactor::Password(&password))?;
    println!("Destroyed Factorseal vault at {}", root.display());
    Ok(())
}

pub(super) fn read_keyring_value(path: Option<&Path>) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let value = if let Some(path) = path {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| CliError::KeyringInput(format!("{}: {error}", path.display())))?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_KEYRING_VALUE_BYTES {
            return Err(CliError::KeyringInput(format!(
                "{} must be a regular file no larger than 64 KiB",
                path.display()
            )));
        }
        let file = fs::File::open(path)
            .map_err(|error| CliError::KeyringInput(format!("{}: {error}", path.display())))?;
        read_bounded(file, MAX_KEYRING_VALUE_BYTES)
            .map_err(|error| CliError::KeyringInput(format!("{}: {error}", path.display())))?
    } else if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Keyring value: ")
            .map(|secret| Zeroizing::new(secret.into_bytes()))
            .map_err(|error| CliError::KeyringInput(error.to_string()))?
    } else {
        read_bounded(std::io::stdin().lock(), MAX_KEYRING_VALUE_BYTES)
            .map_err(|error| CliError::KeyringInput(error.to_string()))?
    };
    if value.is_empty() {
        return Err(CliError::KeyringInput(
            "the keyring value must not be empty".to_owned(),
        ));
    }
    if value.len() as u64 > MAX_KEYRING_VALUE_BYTES {
        return Err(CliError::KeyringInput(
            "the keyring value must not exceed 64 KiB".to_owned(),
        ));
    }
    Ok(value)
}

pub(super) fn read_bounded(reader: impl Read, maximum: u64) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut value = Zeroizing::new(Vec::new());
    reader
        .take(maximum.saturating_add(1))
        .read_to_end(&mut value)?;
    Ok(value)
}

pub(super) fn run_vault(
    root: &Path,
    socket: Option<&Path>,
    factor: FactorSource<'_>,
    policy: UnsealLeasePolicy,
) -> Result<(), CliError> {
    let password = read_factor(factor, false)?;
    let device = Vault::inspect(root)?;
    let unsealed = Vault::unseal(root, UnsealFactor::Password(&password))?;
    let service = Arc::new(VaultService::open(root, unsealed, unix_time()?, policy)?);
    serve_vault(&device, &service, root, socket)
}

pub(super) fn grant_secretspec(
    root: &Path,
    executable: &Path,
    expires_in_seconds: Option<u64>,
    factor: FactorSource<'_>,
) -> Result<(), CliError> {
    let now = unix_time()?;
    let expires_at = expires_in_seconds
        .map(|seconds| now.checked_add(seconds).ok_or(CliError::LifetimeOverflow))
        .transpose()?;
    let caller = caller_identity_for_executable(executable)?;
    let password = read_factor(factor, false)?;
    let unsealed = Vault::unseal(root, UnsealFactor::Password(&password))?;
    let service = VaultService::open(root, unsealed, now, UnsealLeasePolicy::default())?;
    service.authorize_cache_namespace(
        &caller,
        SECRETSPEC_CACHE_NAMESPACE,
        [
            GrantPermission::Get,
            GrantPermission::Put,
            GrantPermission::Delete,
        ],
        expires_at,
        now,
    )?;
    service.seal()?;
    println!(
        "Authorized {} for the Factorseal SecretSpec cache",
        caller.application_id()
    );
    Ok(())
}

pub(super) fn grant_cli(root: &Path, factor: FactorSource<'_>) -> Result<(), CliError> {
    let now = unix_time()?;
    let password = read_factor(factor, false)?;
    let unsealed = Vault::unseal(root, UnsealFactor::Password(&password))?;
    let service = VaultService::open(root, unsealed, now, UnsealLeasePolicy::default())?;
    authorize_cli(&service, now)?;
    service.seal()?;
    println!("Authorized this Factorseal CLI for the local keyring");
    Ok(())
}

fn authorize_cli(service: &VaultService, now: u64) -> Result<(), CliError> {
    let executable =
        std::env::current_exe().map_err(|error| CliError::CurrentExecutable(error.to_string()))?;
    let caller = caller_identity_for_executable(&executable)?;
    service.authorize_namespace(&caller, KEYRING_NAMESPACE, KEYRING_PERMISSIONS, None, now)?;
    Ok(())
}

pub(super) fn resolve_root(explicit: Option<&Path>) -> Result<PathBuf, CliError> {
    if let Some(path) = explicit {
        return Ok(path.to_owned());
    }
    let directories =
        ProjectDirs::from("dev", "Factorseal", "Factorseal").ok_or(CliError::NoDefaultRoot)?;
    Ok(directories.data_local_dir().to_owned())
}

fn unix_time() -> Result<u64, VaultError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| VaultError::Protocol(error.to_string()))
}

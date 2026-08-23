use std::fs;
use std::io::{IsTerminal as _, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use factorseal::{
    GrantPermission, Keyring, KeyringError, UnsealFactor, UnsealLeasePolicy, Vault, VaultAction,
    VaultClient, VaultError, VaultMetadata, VaultRequest, VaultResponseBody,
    VaultResponseErrorCode, VaultService, WireSecretAddress,
};
use serde::Serialize;
use std::sync::Arc;
use zeroize::Zeroizing;

#[path = "factorseal/factor.rs"]
mod factor;
#[path = "factorseal/platform.rs"]
mod platform;
#[cfg(feature = "secretspec-provider")]
#[path = "factorseal/provider.rs"]
mod provider;

use factor::{FactorSource, read_factor};
use platform::{caller_identity_for_executable, native_client, serve_vault};

const MAX_FACTOR_BYTES: u64 = 64 * 1024;
const MAX_KEYRING_VALUE_BYTES: u64 = 64 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const DEFAULT_UNIX_SOCKET: &str = "factorseal.sock";
const SECRETSPEC_CACHE_NAMESPACE: &[u8] = b"secretspec-cache/v1";
const KEYRING_NAMESPACE: &[u8] = b"factorseal/keyring/v1";
const KEYRING_PERMISSIONS: [GrantPermission; 3] = [
    GrantPermission::Get,
    GrantPermission::Put,
    GrantPermission::Delete,
];

#[derive(Debug, Parser)]
#[command(
    name = "factorseal",
    version,
    about = "Hardware-bound vault with a keyring interface and command-line access"
)]
struct Cli {
    /// Vault directory. Defaults to platform-local user data.
    #[arg(long, global = true, env = "FACTORSEAL_ROOT")]
    root: Option<PathBuf>,

    /// Local service socket or named pipe override.
    #[arg(long, global = true, env = "FACTORSEAL_SOCKET")]
    socket: Option<PathBuf>,

    /// Read the nested factor from a private regular file.
    #[arg(long, global = true)]
    password_file: Option<PathBuf>,

    /// Run this helper to obtain the nested factor and read it from the
    /// helper's standard output. Packages use it to prompt without a
    /// controlling terminal; the prompt text is passed as the one argument.
    #[arg(long, global = true, env = "FACTORSEAL_ASKPASS")]
    askpass: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create and seal a hardware-bound vault.
    Init {
        /// Require platform biometric verification when supported by key use.
        #[arg(long)]
        biometric: bool,
    },

    /// Unseal the vault service until its lease ends.
    Unseal {
        /// Idle seconds before hardware-unwrapped keys are discarded.
        #[arg(long, default_value_t = 300)]
        idle_seconds: u64,

        /// Absolute maximum seconds for one unseal lease.
        #[arg(long, default_value_t = 28_800)]
        maximum_seconds: u64,
    },

    /// Print validated non-secret vault metadata without unsealing.
    Status,

    /// Store or replace one value in the durable local keyring.
    Set {
        /// Stable name used to retrieve the value.
        item: String,

        /// Optional field within the named item.
        #[arg(long)]
        field: Option<String>,

        /// Read the value from this file instead of prompting or standard input.
        #[arg(long)]
        value_file: Option<PathBuf>,
    },

    /// Write one keyring value to standard output without adding a newline.
    Get {
        item: String,

        #[arg(long)]
        field: Option<String>,
    },

    /// Delete one value from the durable local keyring.
    Delete {
        item: String,

        #[arg(long)]
        field: Option<String>,
    },

    /// Permanently delete this vault and both of its hardware keys.
    Destroy {
        /// Required acknowledgement because this cannot be undone.
        #[arg(long)]
        yes_really_destroy: bool,
    },

    /// Reauthorize this exact Factorseal executable after an upgrade.
    GrantCli,

    /// Authorize one exact SecretSpec provider-endpoint executable.
    GrantSecretspec {
        executable: PathBuf,

        /// Optional lifetime for the cache grant.
        #[arg(long)]
        expires_in_seconds: Option<u64>,
    },

    /// Serve the SecretSpec external-provider protocol over standard I/O.
    #[cfg(feature = "secretspec-provider")]
    Provider,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Vault(#[from] VaultError),

    #[error(transparent)]
    Keyring(#[from] KeyringError),

    #[error("could not determine the platform user-data directory; pass --root")]
    NoDefaultRoot,

    #[error("the requested lifetime is outside the supported range")]
    LifetimeOverflow,

    #[error("password input failed: {0}")]
    Password(String),

    #[error("askpass helper failed: {0}")]
    Askpass(String),

    #[error("keyring value input failed: {0}")]
    KeyringInput(String),

    #[error("keyring entry was not found")]
    KeyringEntryNotFound,

    #[error("the vault is still unsealed; stop its service before destroying it")]
    VaultIsLive,

    #[error(
        "could not prove the vault is sealed; pass the correct --socket after stopping its service"
    )]
    VaultStateUnknown,

    #[error("refusing to destroy a vault without --yes-really-destroy")]
    DestroyConfirmationRequired,

    #[error("could not identify the Factorseal executable: {0}")]
    CurrentExecutable(String),

    #[error(
        "no way to obtain the Factorseal factor: there is no controlling \
         terminal, and neither --askpass nor --password-file was given"
    )]
    NoFactorSource,

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    #[error("this platform transport has not been implemented")]
    UnsupportedPlatform,

    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),

    #[cfg(feature = "secretspec-provider")]
    #[error("SecretSpec provider protocol failed: {0}")]
    ProviderProtocol(String),
}

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

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("factorseal: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    let root = resolve_root(cli.root.as_deref())?;
    let socket = cli.socket.as_deref();
    let factor = FactorSource {
        password_file: cli.password_file.as_deref(),
        askpass: cli.askpass.as_deref(),
    };
    match cli.command {
        Command::Init { biometric } => initialize(&root, biometric, factor),
        Command::Unseal {
            idle_seconds,
            maximum_seconds,
        } => run_vault(
            &root,
            socket,
            factor,
            UnsealLeasePolicy {
                idle_timeout: Duration::from_secs(idle_seconds),
                maximum_lifetime: Duration::from_secs(maximum_seconds),
            },
        ),
        Command::Status => show_status(&root, socket),
        Command::Set {
            item,
            field,
            value_file,
        } => set_keyring_value(&root, socket, item, field, value_file.as_deref()),
        Command::Get { item, field } => get_keyring_value(&root, socket, item, field),
        Command::Delete { item, field } => delete_keyring_value(&root, socket, item, field),
        Command::Destroy { yes_really_destroy } => {
            destroy_vault(&root, socket, factor, yes_really_destroy)
        }
        Command::GrantCli => grant_cli(&root, factor),
        Command::GrantSecretspec {
            executable,
            expires_in_seconds,
        } => grant_secretspec(&root, &executable, expires_in_seconds, factor),
        #[cfg(feature = "secretspec-provider")]
        Command::Provider => provider::serve(&root, socket),
    }
}

fn initialize(root: &Path, biometric: bool, factor: FactorSource<'_>) -> Result<(), CliError> {
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

fn show_status(root: &Path, socket: Option<&Path>) -> Result<(), CliError> {
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

fn set_keyring_value(
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

fn get_keyring_value(
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

fn delete_keyring_value(
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

fn destroy_vault(
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

fn read_keyring_value(path: Option<&Path>) -> Result<Zeroizing<Vec<u8>>, CliError> {
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

fn read_bounded(reader: impl Read, maximum: u64) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut value = Zeroizing::new(Vec::new());
    reader
        .take(maximum.saturating_add(1))
        .read_to_end(&mut value)?;
    Ok(value)
}

fn run_vault(
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

fn grant_secretspec(
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

fn grant_cli(root: &Path, factor: FactorSource<'_>) -> Result<(), CliError> {
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

fn resolve_root(explicit: Option<&Path>) -> Result<PathBuf, CliError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn live_endpoint_uses_the_factorseal_basename() {
        assert_eq!(DEFAULT_UNIX_SOCKET, "factorseal.sock");
    }

    /// One test writing a helper script while another forks makes the child
    /// inherit the open write handle, and the exec of that script then fails
    /// with ETXTBSY. Serializing helper use removes the overlap.
    #[cfg(unix)]
    static HELPER_EXEC: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(unix)]
    fn askpass_helper(directory: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let path = directory.join("askpass");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[cfg(unix)]
    fn lock_helper_exec() -> std::sync::MutexGuard<'static, ()> {
        HELPER_EXEC
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(unix)]
    #[test]
    fn askpass_output_is_the_factor_without_its_line_ending() {
        let _serialized = lock_helper_exec();
        let directory = tempfile::tempdir().unwrap();
        let helper = askpass_helper(directory.path(), "printf 'correct horse\\n'");

        let source = FactorSource {
            password_file: None,
            askpass: Some(&helper),
        };
        assert_eq!(
            read_factor(source, false).unwrap().as_slice(),
            b"correct horse"
        );
    }

    #[cfg(unix)]
    #[test]
    fn askpass_receives_the_prompt_and_rejects_a_mismatched_confirmation() {
        let _serialized = lock_helper_exec();
        let directory = tempfile::tempdir().unwrap();
        // Echo the prompt back, so the two confirmation prompts disagree.
        let helper = askpass_helper(directory.path(), "printf '%s' \"$1\"");

        let source = FactorSource {
            password_file: None,
            askpass: Some(&helper),
        };
        assert!(read_factor(source, true).is_err());
        assert_eq!(
            read_factor(source, false).unwrap().as_slice(),
            b"Factorseal password:"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_cancelled_askpass_helper_does_not_yield_a_factor() {
        let _serialized = lock_helper_exec();
        let directory = tempfile::tempdir().unwrap();
        let helper = askpass_helper(directory.path(), "exit 1");

        let source = FactorSource {
            password_file: None,
            askpass: Some(&helper),
        };
        assert!(matches!(
            read_factor(source, false),
            Err(CliError::Askpass(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn an_empty_factor_is_rejected() {
        let _serialized = lock_helper_exec();
        let directory = tempfile::tempdir().unwrap();
        let helper = askpass_helper(directory.path(), "printf ''");

        let source = FactorSource {
            password_file: None,
            askpass: Some(&helper),
        };
        assert!(read_factor(source, false).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn oversized_askpass_output_is_rejected_instead_of_truncated() {
        let _serialized = lock_helper_exec();
        let directory = tempfile::tempdir().unwrap();
        let helper = askpass_helper(directory.path(), "head -c 65537 /dev/zero");
        let source = FactorSource {
            password_file: None,
            askpass: Some(&helper),
        };

        assert!(matches!(
            read_factor(source, false),
            Err(CliError::Askpass(message)) if message.contains("64 KiB")
        ));
    }

    #[test]
    fn an_explicit_file_takes_precedence_over_the_helper() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("factor");
        fs::write(&file, "from the file\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let source = FactorSource {
            password_file: Some(&file),
            askpass: Some(Path::new("/nonexistent/askpass")),
        };
        assert_eq!(
            read_factor(source, false).unwrap().as_slice(),
            b"from the file"
        );
    }

    #[test]
    fn askpass_is_configurable_through_the_environment() {
        let cli =
            Cli::try_parse_from(["factorseal", "--askpass", "/usr/bin/true", "unseal"]).unwrap();
        assert_eq!(cli.askpass.unwrap(), PathBuf::from("/usr/bin/true"));
    }

    #[test]
    fn unseal_policy_and_root_are_explicitly_configurable() {
        let cli = Cli::try_parse_from([
            "factorseal",
            "--root",
            "/tmp/factorseal-test",
            "unseal",
            "--idle-seconds",
            "10",
            "--maximum-seconds",
            "20",
        ])
        .unwrap();
        assert_eq!(cli.root.unwrap(), PathBuf::from("/tmp/factorseal-test"));
        let Command::Unseal {
            idle_seconds,
            maximum_seconds,
            ..
        } = cli.command
        else {
            panic!("expected unseal command");
        };
        assert_eq!(idle_seconds, 10);
        assert_eq!(maximum_seconds, 20);
    }

    #[test]
    fn keyring_commands_accept_item_field_and_service_override() {
        let cli = Cli::try_parse_from([
            "factorseal",
            "--socket",
            "/tmp/factorseal.sock",
            "set",
            "github",
            "--field",
            "token",
            "--value-file",
            "/tmp/value",
        ])
        .unwrap();
        assert_eq!(cli.socket.unwrap(), PathBuf::from("/tmp/factorseal.sock"));
        let Command::Set {
            item,
            field,
            value_file,
        } = cli.command
        else {
            panic!("expected set command");
        };
        assert_eq!(item, "github");
        assert_eq!(field.as_deref(), Some("token"));
        assert_eq!(value_file.unwrap(), PathBuf::from("/tmp/value"));

        let cli = Cli::try_parse_from(["factorseal", "get", "github", "--field", "token"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Get { item, field }
                if item == "github" && field.as_deref() == Some("token")
        ));
    }

    #[test]
    fn keyring_value_files_preserve_exact_binary_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("value");
        fs::write(&path, b"secret\0with\nbytes").unwrap();

        assert_eq!(
            read_keyring_value(Some(&path)).unwrap().as_slice(),
            b"secret\0with\nbytes"
        );
    }

    #[test]
    fn bounded_reads_retain_one_byte_to_detect_overflow() {
        let bytes = vec![7; 5];
        let read = read_bounded(bytes.as_slice(), 4).unwrap();

        assert_eq!(read.as_slice(), &[7; 5]);
    }
}

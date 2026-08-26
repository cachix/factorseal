use std::time::Duration;

use clap::Parser;
use factorseal::{GrantPermission, KeyringError, UnsealLeasePolicy, VaultError};

#[path = "factorseal/cli.rs"]
mod cli;
#[path = "factorseal/commands.rs"]
mod commands;
#[path = "factorseal/factor.rs"]
mod factor;
#[path = "factorseal/platform.rs"]
mod platform;
#[cfg(feature = "secretspec-provider")]
#[path = "factorseal/provider.rs"]
mod provider;

use cli::{Cli, Command};
use commands::{
    delete_keyring_value, destroy_vault, get_keyring_value, grant_cli, grant_secretspec,
    initialize, resolve_root, run_vault, set_keyring_value, show_status,
};
use factor::FactorSource;

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

#[cfg(test)]
#[path = "factorseal/tests.rs"]
mod tests;

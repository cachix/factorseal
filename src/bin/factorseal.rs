use std::time::Duration;

use clap::Parser;
use factorseal::{GrantPermission, UnsealLeasePolicy, VaultError, VaultResponseErrorCode};

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
    delete_project_value, destroy_vault, export_vault, get_project_value, grant_cli,
    hardware_self_test, import_vault, initialize, list_project_addresses, list_project_history,
    list_projects, manage_permissions, resolve_root, run_agent, seal_vault, set_project_value,
    show_status,
};
use factor::FactorSource;

const MAX_FACTOR_BYTES: u64 = 64 * 1024;
const MAX_PROJECT_VALUE_BYTES: u64 = 64 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const DEFAULT_UNIX_SOCKET: &str = "factorseal.sock";
const CLI_CONTROL_NAMESPACE: &[u8] = b"factorseal/cli-control/v1";
const PERSONAL_SECRET_NAMESPACE: &[u8] = b"factorseal/personal-secrets/v1";
const PROJECT_PERMISSIONS: [GrantPermission; 4] = [
    GrantPermission::List,
    GrantPermission::Get,
    GrantPermission::Put,
    GrantPermission::Delete,
];

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Vault(#[from] VaultError),

    #[error("could not determine the platform user-data directory; pass --root")]
    NoDefaultRoot,

    #[error("password input failed: {0}")]
    Password(String),

    #[error("askpass helper failed: {0}")]
    Askpass(String),

    #[error("project value input failed: {0}")]
    ProjectInput(String),

    #[error("project secret was not found")]
    ProjectEntryNotFound,

    #[error("project metadata output failed: {0}")]
    ProjectOutput(String),

    #[error("vault transfer failed: {0}")]
    Transfer(String),

    #[error("archive passphrase input failed: {0}")]
    ArchivePassphrase(String),

    #[error("no way to obtain the archive passphrase: use a terminal or pass --passphrase-file")]
    NoArchivePassphraseSource,

    #[error("unlock group `{0}` is not configured for this vault")]
    UnlockGroupNotConfigured(String),

    #[error("vault request failed ({code:?}): {message}")]
    VaultRequest {
        code: VaultResponseErrorCode,
        message: String,
    },

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

    #[error("could not launch Factorseal Desktop: {0}")]
    DesktopLaunch(String),

    #[error("interactive permission prompting requires terminal input and error output")]
    ApprovalPromptRequiresTerminal,

    #[error("permission prompt failed: {0}")]
    ApprovalPrompt(String),

    #[error("initialization prompt failed: {0}")]
    InitPrompt(String),

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

    #[error("{0}")]
    HardwareSelfTest(String),

    #[cfg(feature = "secretspec-provider")]
    #[error("SecretSpec provider protocol failed: {0}")]
    ProviderProtocol(String),

    #[cfg(feature = "secretspec-provider")]
    #[error("could not publish SecretSpec provider discovery: {0}")]
    SecretSpecDiscovery(String),
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("factorseal: {error}");
        std::process::exit(1);
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one exhaustive CLI dispatch keeps every command route visible"
)]
fn run(cli: Cli) -> Result<(), CliError> {
    platform::disable_core_dumps()?;
    let root = resolve_root(cli.root.as_deref())?;
    let socket = cli.socket.as_deref();
    let factor = FactorSource {
        password_file: cli.password_file.as_deref(),
        askpass: cli.askpass.as_deref(),
    };
    match cli.command {
        Command::SignPermission {
            id,
            challenge,
            duration_seconds,
            unlock,
        } => commands::sign_permission(
            &root,
            factor,
            &id,
            &challenge,
            duration_seconds,
            unlock.as_ref(),
        ),
        Command::Init { unlock, fips } => initialize(&root, unlock, factor, fips),
        Command::Agent {
            unlock,
            idle_seconds,
            maximum_seconds,
        } => run_agent(
            &root,
            socket,
            factor,
            UnsealLeasePolicy {
                idle_timeout: Duration::from_secs(idle_seconds),
                maximum_lifetime: Duration::from_secs(maximum_seconds),
            },
            unlock.as_ref(),
        ),
        Command::Desktop {
            background,
            idle_seconds,
            maximum_seconds,
        } => commands::launch_desktop(&root, socket, background, idle_seconds, maximum_seconds),
        Command::Status => show_status(&root, socket),
        Command::Seal => seal_vault(&root, socket),
        Command::Set {
            project,
            profile,
            item,
            field,
            value_file,
        } => set_project_value(
            &root,
            socket,
            project,
            &profile,
            item,
            field,
            value_file.as_deref(),
        ),
        Command::Get {
            project,
            profile,
            item,
            field,
        } => get_project_value(&root, socket, project, &profile, item, field),
        Command::Delete {
            project,
            profile,
            item,
            field,
        } => delete_project_value(&root, socket, project, &profile, item, field),
        Command::Projects { json } => list_projects(&root, socket, json),
        Command::List { project, json } => list_project_addresses(&root, socket, &project, json),
        Command::History { project, json } => list_project_history(&root, socket, &project, json),
        Command::Export {
            file,
            format,
            passphrase_file,
        } => export_vault(
            &root,
            socket,
            &file,
            format.into(),
            passphrase_file.as_deref(),
        ),
        Command::Import {
            file,
            format,
            passphrase_file,
            replace_existing,
        } => import_vault(
            &root,
            socket,
            &file,
            format.into(),
            passphrase_file.as_deref(),
            replace_existing,
        ),
        Command::Destroy {
            yes_really_destroy,
            unlock,
        } => destroy_vault(&root, socket, factor, yes_really_destroy, unlock.as_ref()),
        Command::GrantCli { unlock } => grant_cli(&root, factor, unlock.as_ref()),
        Command::HardwareSelfTest { biometric } => hardware_self_test(biometric),
        Command::Permissions { action } => manage_permissions(&root, socket, factor, &action),
        #[cfg(feature = "secretspec-provider")]
        Command::Provider => provider::serve(&root, socket),
    }
}

#[cfg(test)]
#[path = "factorseal/tests.rs"]
mod tests;

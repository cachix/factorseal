use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use factorseal::{Error as VaultError, UnlockedVault, Vault};
use serde::Serialize;
use zeroize::Zeroizing;

const MAX_SECRET_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(any(feature = "password", feature = "yubikey"))]
const MAX_AUTH_INPUT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "factorseal",
    version,
    about = "A hardware-bound local keyring with optional YubiKey two-factor unlock"
)]
struct Cli {
    /// Vault directory. Defaults to the platform user-data directory.
    #[arg(long, global = true, env = "FACTORSEAL_VAULT")]
    vault: Option<PathBuf>,

    /// Read the YubiKey PIN from a file instead of prompting.
    #[cfg(feature = "yubikey")]
    #[arg(long, global = true, env = "FACTORSEAL_YUBIKEY_PIN_FILE")]
    yubikey_pin_file: Option<PathBuf>,

    /// Read a legacy vault password from a file instead of prompting.
    #[cfg(feature = "password")]
    #[arg(long, global = true, env = "FACTORSEAL_PASSWORD_FILE")]
    password_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new hardware-bound local vault.
    Init {
        /// Require a YubiKey PIV key in slot 9d as a second factor.
        #[cfg(feature = "yubikey")]
        #[arg(long)]
        yubikey: bool,

        /// Create a legacy password vault for development.
        #[cfg(feature = "password")]
        #[arg(long)]
        password: bool,
    },

    /// Store or replace a credential, reading its value from a file or stdin.
    Set {
        service: String,
        account: String,

        /// Secret input file. Standard input is used when omitted.
        #[arg(short, long)]
        input: Option<PathBuf>,
    },

    /// Retrieve a credential.
    Get {
        service: String,
        account: String,

        /// Plaintext output file. Standard output is used when omitted.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Delete a credential.
    Delete { service: String, account: String },

    /// Show non-secret vault metadata without unlocking.
    Status,

    /// Add a YubiKey as a required second factor.
    #[cfg(feature = "yubikey")]
    AddYubikey,

    /// Remove the YubiKey requirement after using both factors.
    #[cfg(feature = "yubikey")]
    RemoveYubikey,

    /// Rewrap a legacy vault key under a new password.
    #[cfg(feature = "password")]
    ChangePassword {
        /// Read the new password from a file instead of prompting.
        #[arg(long)]
        new_password_file: Option<PathBuf>,
    },

    /// Replace legacy password wrapping with platform hardware binding.
    #[cfg(feature = "password")]
    MigratePassword,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Vault(#[from] VaultError),

    #[error("could not determine the platform user-data directory; pass --vault")]
    NoDefaultVault,

    #[cfg(feature = "password")]
    #[error("passwords do not match")]
    PasswordMismatch,

    #[cfg(all(feature = "password", feature = "yubikey"))]
    #[error("--password and --yubikey cannot be used together")]
    ConflictingInitFactors,

    #[error("I/O error for `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("refusing to read more than {maximum} bytes from `{path}`")]
    InputTooLarge { path: String, maximum: u64 },
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("factorseal: {error}");
        std::process::exit(1);
    }
}

#[allow(clippy::needless_pass_by_value)]
fn run(cli: Cli) -> Result<(), CliError> {
    let vault_path = resolve_vault_path(cli.vault)?;
    match cli.command {
        Command::Init {
            #[cfg(feature = "yubikey")]
            yubikey,
            #[cfg(feature = "password")]
            password,
        } => init_vault(
            &vault_path,
            #[cfg(feature = "yubikey")]
            yubikey,
            #[cfg(feature = "password")]
            password,
            #[cfg(feature = "yubikey")]
            cli.yubikey_pin_file.as_deref(),
            #[cfg(feature = "password")]
            cli.password_file.as_deref(),
        ),
        Command::Set {
            service,
            account,
            input,
        } => {
            let vault = unlock_vault(
                &vault_path,
                #[cfg(feature = "password")]
                cli.password_file.as_deref(),
                #[cfg(feature = "yubikey")]
                cli.yubikey_pin_file.as_deref(),
            )?;
            let secret = Zeroizing::new(read_input(input.as_deref(), MAX_SECRET_BYTES)?);
            vault.set(&service, &account, &secret)?;
            Ok(())
        }
        Command::Get {
            service,
            account,
            output,
        } => {
            let vault = unlock_vault(
                &vault_path,
                #[cfg(feature = "password")]
                cli.password_file.as_deref(),
                #[cfg(feature = "yubikey")]
                cli.yubikey_pin_file.as_deref(),
            )?;
            let secret = vault.get(&service, &account)?;
            write_output(output.as_deref(), &secret)
        }
        Command::Delete { service, account } => {
            let vault = unlock_vault(
                &vault_path,
                #[cfg(feature = "password")]
                cli.password_file.as_deref(),
                #[cfg(feature = "yubikey")]
                cli.yubikey_pin_file.as_deref(),
            )?;
            vault.delete(&service, &account)?;
            Ok(())
        }
        Command::Status => {
            let info = Vault::info(&vault_path)?;
            let status = Status {
                path: info.path.display().to_string(),
                version: info.version,
                vault_id: info.vault_id,
                unlock_method: info.unlock_method,
                hardware_backend: info.hardware_backend,
                yubikey_serial: info.yubikey_serial,
                state: "locked",
            };
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        #[cfg(feature = "yubikey")]
        Command::AddYubikey => {
            let pin = read_yubikey_pin(cli.yubikey_pin_file.as_deref())?;
            Vault::add_yubikey(&vault_path, &pin)?;
            Ok(())
        }
        #[cfg(feature = "yubikey")]
        Command::RemoveYubikey => {
            let pin = read_yubikey_pin(cli.yubikey_pin_file.as_deref())?;
            Vault::remove_yubikey(&vault_path, &pin)?;
            Ok(())
        }
        #[cfg(feature = "password")]
        Command::ChangePassword { new_password_file } => {
            let current = read_current_password(cli.password_file.as_deref())?;
            let new = read_new_password(new_password_file.as_deref())?;
            Vault::change_password(&vault_path, &current, &new)?;
            Ok(())
        }
        #[cfg(feature = "password")]
        Command::MigratePassword => {
            let password = read_current_password(cli.password_file.as_deref())?;
            Vault::migrate_password_to_hardware(&vault_path, &password)?;
            Ok(())
        }
    }
}

fn resolve_vault_path(explicit: Option<PathBuf>) -> Result<PathBuf, CliError> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let directories =
        ProjectDirs::from("dev", "FactorSeal", "FactorSeal").ok_or(CliError::NoDefaultVault)?;
    Ok(directories.data_local_dir().join("vault"))
}

fn init_vault(
    path: &Path,
    #[cfg(feature = "yubikey")] yubikey: bool,
    #[cfg(feature = "password")] password: bool,
    #[cfg(feature = "yubikey")] yubikey_pin_file: Option<&Path>,
    #[cfg(feature = "password")] password_file: Option<&Path>,
) -> Result<(), CliError> {
    #[cfg(all(feature = "password", feature = "yubikey"))]
    if password && yubikey {
        return Err(CliError::ConflictingInitFactors);
    }
    #[cfg(feature = "password")]
    if password {
        let password = read_new_password(password_file)?;
        Vault::create_with_password(path, &password)?;
        println!(
            "Initialized legacy password FactorSeal vault at {}",
            path.display()
        );
        return Ok(());
    }
    #[cfg(feature = "yubikey")]
    if yubikey {
        let pin = read_yubikey_pin(yubikey_pin_file)?;
        Vault::create_with_yubikey(path, &pin)?;
        println!(
            "Initialized hardware + YubiKey FactorSeal vault at {}",
            path.display()
        );
        return Ok(());
    }
    Vault::create(path)?;
    println!(
        "Initialized hardware-bound FactorSeal vault at {}",
        path.display()
    );
    Ok(())
}

fn unlock_vault(
    path: &Path,
    #[cfg(feature = "password")] password_file: Option<&Path>,
    #[cfg(feature = "yubikey")] yubikey_pin_file: Option<&Path>,
) -> Result<UnlockedVault, CliError> {
    let info = Vault::info(path)?;
    match info.unlock_method.as_str() {
        "hardware" => Ok(Vault::unlock(path)?),
        "hardware+yubikey" => {
            #[cfg(feature = "yubikey")]
            {
                let pin = read_yubikey_pin(yubikey_pin_file)?;
                Ok(Vault::unlock_with_yubikey(path, &pin)?)
            }
            #[cfg(not(feature = "yubikey"))]
            {
                Err(VaultError::YubiKeyFeatureDisabled.into())
            }
        }
        "password" => {
            #[cfg(feature = "password")]
            {
                let password = read_current_password(password_file)?;
                Ok(Vault::unlock_with_password(path, &password)?)
            }
            #[cfg(not(feature = "password"))]
            {
                Err(VaultError::PasswordFeatureDisabled.into())
            }
        }
        method => {
            Err(VaultError::InvalidMetadata(format!("unsupported unlock method `{method}`")).into())
        }
    }
}

#[cfg(feature = "yubikey")]
fn read_yubikey_pin(path: Option<&Path>) -> Result<Zeroizing<Vec<u8>>, CliError> {
    match path {
        Some(path) => read_auth_file(path),
        None => prompt_secret("YubiKey PIN: "),
    }
}

#[cfg(feature = "password")]
fn read_current_password(path: Option<&Path>) -> Result<Zeroizing<Vec<u8>>, CliError> {
    match path {
        Some(path) => read_auth_file(path),
        None => prompt_secret("FactorSeal password: "),
    }
}

#[cfg(feature = "password")]
fn read_new_password(path: Option<&Path>) -> Result<Zeroizing<Vec<u8>>, CliError> {
    if let Some(path) = path {
        return read_auth_file(path);
    }
    let first = prompt_secret("New FactorSeal password: ")?;
    let second = prompt_secret("Confirm FactorSeal password: ")?;
    if *first != *second {
        return Err(CliError::PasswordMismatch);
    }
    Ok(first)
}

#[cfg(any(feature = "password", feature = "yubikey"))]
fn prompt_secret(prompt: &str) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let value = rpassword::prompt_password(prompt).map_err(|source| CliError::Io {
        path: "<terminal>".to_owned(),
        source,
    })?;
    Ok(Zeroizing::new(value.into_bytes()))
}

#[cfg(any(feature = "password", feature = "yubikey"))]
fn read_auth_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut value = read_file(path, MAX_AUTH_INPUT_BYTES)?;
    if value.last() == Some(&b'\n') {
        value.pop();
        if value.last() == Some(&b'\r') {
            value.pop();
        }
    }
    Ok(Zeroizing::new(value))
}

fn read_input(path: Option<&Path>, maximum: u64) -> Result<Vec<u8>, CliError> {
    match path {
        Some(path) => read_file(path, maximum),
        None => read_limited(io::stdin().lock(), "<stdin>", maximum),
    }
}

fn read_file(path: &Path, maximum: u64) -> Result<Vec<u8>, CliError> {
    let file = File::open(path).map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })?;
    read_limited(file, &path.display().to_string(), maximum)
}

fn read_limited(reader: impl Read, path: &str, maximum: u64) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    reader
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > maximum {
        return Err(CliError::InputTooLarge {
            path: path.to_owned(),
            maximum,
        });
    }
    Ok(bytes)
}

fn write_output(path: Option<&Path>, bytes: &[u8]) -> Result<(), CliError> {
    if let Some(path) = path {
        fs::write(path, bytes).map_err(|source| CliError::Io {
            path: path.display().to_string(),
            source,
        })
    } else {
        let mut stdout = io::stdout().lock();
        stdout.write_all(bytes).map_err(|source| CliError::Io {
            path: "<stdout>".to_owned(),
            source,
        })?;
        stdout.flush().map_err(|source| CliError::Io {
            path: "<stdout>".to_owned(),
            source,
        })
    }
}

#[derive(Serialize)]
struct Status {
    path: String,
    version: u32,
    vault_id: String,
    unlock_method: String,
    hardware_backend: Option<String>,
    yubikey_serial: Option<u32>,
    state: &'static str,
}

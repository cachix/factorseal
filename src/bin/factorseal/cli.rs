//! Command-line argument declarations.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "factorseal",
    version,
    about = "Hardware-bound vault with a keyring interface and command-line access"
)]
pub(super) struct Cli {
    /// Vault directory. Defaults to platform-local user data.
    #[arg(long, global = true, env = "FACTORSEAL_ROOT")]
    pub(super) root: Option<PathBuf>,

    /// Local service socket or named pipe override.
    #[arg(long, global = true, env = "FACTORSEAL_SOCKET")]
    pub(super) socket: Option<PathBuf>,

    /// Read the nested factor from a private regular file.
    #[arg(long, global = true)]
    pub(super) password_file: Option<PathBuf>,

    /// Run this helper to obtain the nested factor and read it from the
    /// helper's standard output. Packages use it to prompt without a
    /// controlling terminal; the prompt text is passed as the one argument.
    #[arg(long, global = true, env = "FACTORSEAL_ASKPASS")]
    pub(super) askpass: Option<PathBuf>,

    #[command(subcommand)]
    pub(super) command: Command,
}

#[derive(Debug, Subcommand)]
pub(super) enum Command {
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

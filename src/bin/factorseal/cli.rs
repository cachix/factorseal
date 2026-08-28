//! Command-line argument declarations.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use factorseal::UnlockGroup;

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

    /// Read the password factor from a private regular file.
    #[arg(long, global = true)]
    pub(super) password_file: Option<PathBuf>,

    /// Run this helper to obtain the password factor and read it from the
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
        /// AND-separated factors in one unlock group; repeat for OR alternatives.
        #[arg(long, value_name = "FACTORS", default_value = "password")]
        unlock: Vec<UnlockGroup>,
    },

    /// Unseal the vault service until its lease ends.
    Unseal {
        /// Exact unlock group to use; required when more than one is configured.
        #[arg(long, value_name = "FACTORS")]
        unlock: Option<UnlockGroup>,

        /// Idle seconds before hardware-unwrapped keys are discarded.
        #[arg(long, default_value_t = 300)]
        idle_seconds: u64,

        /// Absolute maximum seconds for one unseal lease.
        #[arg(long, default_value_t = 28_800)]
        maximum_seconds: u64,
    },

    /// Print validated non-secret vault metadata without unsealing.
    Status,

    /// Seal the running vault service immediately.
    Seal,

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

    /// Permanently delete this vault and all of its hardware keys.
    Destroy {
        /// Required acknowledgement because this cannot be undone.
        #[arg(long)]
        yes_really_destroy: bool,

        /// Exact unlock group to use; required when more than one is configured.
        #[arg(long, value_name = "FACTORS")]
        unlock: Option<UnlockGroup>,
    },

    /// Reauthorize this exact Factorseal executable after an upgrade.
    GrantCli {
        /// Exact unlock group to use; required when more than one is configured.
        #[arg(long, value_name = "FACTORS")]
        unlock: Option<UnlockGroup>,
    },

    /// List and manage application permissions.
    Permissions {
        #[command(subcommand)]
        action: PermissionCommand,
    },

    /// Serve the SecretSpec external-provider protocol over standard I/O.
    #[cfg(feature = "secretspec-provider")]
    Provider,
}

#[derive(Debug, Subcommand)]
pub(super) enum PermissionCommand {
    /// List pending and granted permissions.
    List {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Continue printing whenever permissions change.
    Watch {
        /// Interactively approve, deny, or ignore pending permissions.
        #[arg(long, conflicts_with = "json")]
        prompt: bool,

        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Grant a pending permission after satisfying one configured unlock group.
    Approve { id: String },

    /// Deny and remove a pending permission.
    Deny { id: String },

    /// Revoke a granted permission.
    Revoke { id: String },
}

//! Command-line argument declarations.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use factorseal::UnlockGroup;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(super) enum TransferFormat {
    #[value(name = "factorseal")]
    FactorSeal,
    #[value(name = "bitwarden-json")]
    BitwardenJson,
    #[value(name = "1password-csv")]
    OnePasswordCsv,
    #[value(name = "keepass-csv")]
    KeePassCsv,
}

impl From<TransferFormat> for factorseal::transfer::TransferFormat {
    fn from(format: TransferFormat) -> Self {
        match format {
            TransferFormat::FactorSeal => Self::FactorSeal,
            TransferFormat::BitwardenJson => Self::BitwardenJson,
            TransferFormat::OnePasswordCsv => Self::OnePasswordCsv,
            TransferFormat::KeePassCsv => Self::KeePassCsv,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "factorseal",
    version,
    about = "Hardware-bound local vault for project secrets"
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
    /// Internal desktop bootstrap over inherited private pipes.
    #[command(hide = true)]
    DesktopWorker,
    /// Internal, short-lived key owner; never connects to the agent.
    #[command(hide = true)]
    SignPermission {
        #[arg(long)]
        id: String,
        #[arg(long)]
        challenge: String,
        #[arg(long)]
        duration_seconds: Option<u64>,
        #[arg(long)]
        unlock: Option<UnlockGroup>,
    },

    /// Create and seal a hardware-bound vault.
    Init {
        /// AND-separated factors in one unlock group; repeat for OR alternatives.
        #[arg(long, value_name = "FACTORS")]
        unlock: Vec<UnlockGroup>,

        /// Use PBKDF2-HMAC-SHA-256 instead of the default Argon2id password KDF.
        /// This selects FIPS-standardized algorithms but is not a claim of
        /// FIPS 140-3 validation.
        #[arg(long)]
        fips: bool,
    },

    /// Run the vault agent, waiting for initialization before serving requests.
    Agent {
        /// Exact unlock group to use instead of the vault's preferred group.
        #[arg(long, value_name = "FACTORS")]
        unlock: Option<UnlockGroup>,

        /// Idle seconds before hardware-unwrapped keys are discarded.
        #[arg(long, default_value_t = 300)]
        idle_seconds: u64,

        /// Absolute maximum seconds for one unseal lease.
        #[arg(long, default_value_t = 28_800)]
        maximum_seconds: u64,
    },

    /// Open Factorseal Desktop, the graphical vault host and permission manager.
    Desktop {
        /// Start in the tray without opening the main window.
        #[arg(long)]
        background: bool,

        /// Idle seconds before hardware-unwrapped keys are discarded.
        #[arg(long, env = "FACTORSEAL_IDLE_SECONDS", default_value_t = 300)]
        idle_seconds: u64,

        /// Absolute maximum seconds for one unseal lease.
        #[arg(long, env = "FACTORSEAL_MAXIMUM_SECONDS", default_value_t = 28_800)]
        maximum_seconds: u64,
    },

    /// Print validated non-secret vault metadata without unsealing.
    Status,

    /// Seal the running vault service immediately.
    Seal,

    /// Store or replace one durable project secret.
    Set {
        /// SecretSpec project owning this secret.
        #[arg(long, env = "SECRETSPEC_PROJECT")]
        project: String,

        /// SecretSpec profile containing this conventional key.
        #[arg(long, default_value = "default")]
        profile: String,

        /// Stable name used to retrieve the value.
        item: String,

        /// Optional field within the named item.
        #[arg(long)]
        field: Option<String>,

        /// Read the value from this file instead of prompting or standard input.
        #[arg(long)]
        value_file: Option<PathBuf>,
    },

    /// Write one project secret to standard output without adding a newline.
    Get {
        #[arg(long, env = "SECRETSPEC_PROJECT")]
        project: String,

        #[arg(long, default_value = "default")]
        profile: String,

        item: String,

        #[arg(long)]
        field: Option<String>,
    },

    /// Delete one durable project secret.
    Delete {
        #[arg(long, env = "SECRETSPEC_PROJECT")]
        project: String,

        #[arg(long, default_value = "default")]
        profile: String,

        item: String,

        #[arg(long)]
        field: Option<String>,
    },

    /// List durable projects without reading their secret values.
    Projects {
        /// Emit one JSON array instead of one quoted project per line.
        #[arg(long)]
        json: bool,
    },

    /// List full addresses in one durable project without reading values.
    List {
        #[arg(long, env = "SECRETSPEC_PROJECT")]
        project: String,

        /// Emit one JSON array instead of one address object per line.
        #[arg(long)]
        json: bool,
    },

    /// Show recorded changes in one durable project, newest first, without
    /// reading values.
    History {
        #[arg(long, env = "SECRETSPEC_PROJECT")]
        project: String,

        /// Emit one JSON array instead of one entry object per line.
        #[arg(long)]
        json: bool,
    },

    /// Export an encrypted backup or personal secrets for a password manager.
    Export {
        /// Destination file. Existing files are replaced with mode 0600 on Unix.
        file: PathBuf,

        /// Export format. Password-manager formats are plaintext and include personal secrets only.
        #[arg(long, value_enum, default_value_t = TransferFormat::FactorSeal)]
        format: TransferFormat,

        /// Read the native archive passphrase from a private regular file.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },

    /// Import an encrypted backup or personal secrets from a password manager.
    Import {
        /// Source archive or password-manager export.
        file: PathBuf,

        /// Import format.
        #[arg(long, value_enum, default_value_t = TransferFormat::FactorSeal)]
        format: TransferFormat,

        /// Read the native archive passphrase from a private regular file.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,

        /// Replace entries whose vault address already exists.
        #[arg(long)]
        replace_existing: bool,
    },

    /// Remove this vault and backend-owned keys; retained TPM backups are not revoked.
    Destroy {
        /// Required acknowledgement because this cannot be undone.
        #[arg(long)]
        yes_really_destroy: bool,

        /// Exact unlock group to use instead of the vault's preferred group.
        #[arg(long, value_name = "FACTORS")]
        unlock: Option<UnlockGroup>,
    },

    /// Reauthorize this exact Factorseal executable after an upgrade.
    GrantCli {
        /// Exact unlock group to use instead of the vault's preferred group.
        #[arg(long, value_name = "FACTORS")]
        unlock: Option<UnlockGroup>,
    },

    /// Verify hardware sealing invariants on this physical device.
    ///
    /// Writes and removes scratch state under a reserved label. It never reads
    /// or modifies a vault, so it is safe to run beside one.
    HardwareSelfTest {
        /// Also exercise the biometric-gated policy, which asks for
        /// verification several times.
        #[arg(long)]
        biometric: bool,
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

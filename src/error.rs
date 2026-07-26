use std::path::PathBuf;

/// Errors produced while creating, unlocking, or using a FactorSeal vault.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("vault already exists at `{0}`")]
    VaultExists(PathBuf),

    #[error("no FactorSeal vault exists at `{0}`")]
    VaultNotFound(PathBuf),

    #[error("vault path `{0}` is not a directory")]
    InvalidVaultPath(PathBuf),

    #[error("vault directory `{path}` is accessible by group or other users (mode {mode:o})")]
    InsecurePermissions { path: PathBuf, mode: u32 },

    #[error("invalid vault format `{0}`")]
    InvalidFormat(String),

    #[error("unsupported vault version {0}")]
    UnsupportedVersion(u32),

    #[error("invalid vault metadata: {0}")]
    InvalidMetadata(String),

    #[error("this build does not include platform hardware support")]
    HardwareFeatureDisabled,

    #[error("no supported hardware security backend is available: {0}")]
    HardwareUnavailable(String),

    #[error("hardware security operation failed: {0}")]
    Hardware(String),

    #[error("vault requires a YubiKey second factor")]
    YubiKeyRequired,

    #[error("this build does not include YubiKey support")]
    YubiKeyFeatureDisabled,

    #[error("YubiKey operation failed: {0}")]
    YubiKey(String),

    #[error("the YubiKey PIV key-management slot must contain a PIN-protected RSA-2048 key")]
    UnsupportedYubiKeySlot,

    #[error("this password vault must be migrated with a password-enabled build")]
    PasswordFeatureDisabled,

    #[error("password must not be empty")]
    EmptyPassword,

    #[error("vault password is incorrect or vault metadata was modified")]
    UnlockFailed,

    #[error("credential service must not be empty")]
    EmptyService,

    #[error("credential account must not be empty")]
    EmptyAccount,

    #[error("secret reference item must not be empty")]
    EmptyReferenceItem,

    #[error("secret reference field must not be empty")]
    EmptyReferenceField,

    #[error("credential {field} is longer than {maximum} bytes")]
    CredentialNameTooLong { field: &'static str, maximum: usize },

    #[error("credential was not found")]
    NoEntry,

    #[error("credential data is malformed")]
    InvalidEntry,

    #[error("credential authentication failed")]
    Authentication,

    #[error("the unlocked vault session is locked")]
    VaultLocked,

    #[error("unlocked vault session state lock was poisoned")]
    VaultStatePoisoned,

    #[error("credential eviction deadline is outside the supported range")]
    InvalidEvictionTime,

    #[error("refusing to read `{path}` because it is larger than {maximum} bytes")]
    FileTooLarge { path: PathBuf, maximum: u64 },

    #[error("I/O error for `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON error for `{path}`: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("random-number generation failed: {0}")]
    Random(String),

    #[error("password derivation failed: {0}")]
    PasswordDerivation(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<getrandom::Error> for Error {
    fn from(error: getrandom::Error) -> Self {
        Self::Random(error.to_string())
    }
}

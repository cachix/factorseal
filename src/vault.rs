#[cfg(any(feature = "hardware", feature = "password"))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(feature = "password")]
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[cfg(feature = "hardware")]
use crate::hardware::{HardwareBackend, KeyProtector, PlatformProtector};
use crate::{Error, Result};

const CONFIG_FILE: &str = "vault.json";
const ENTRIES_DIRECTORY: &str = "entries";
#[cfg(all(target_os = "linux", feature = "secret-service"))]
const SECRET_SERVICE_INDEX_FILE: &str = "secret-service-index.fseal";
const VAULT_FORMAT: &str = "factorseal-vault";
const ENTRY_FORMAT: &str = "factorseal-entry";
#[cfg(all(target_os = "linux", feature = "secret-service"))]
const SECRET_SERVICE_INDEX_FORMAT: &str = "factorseal-secret-service-index";
const CURRENT_VAULT_VERSION: u32 = 2;
const PASSWORD_VAULT_VERSION: u32 = 1;
const ENTRY_VERSION: u32 = 1;
#[cfg(all(target_os = "linux", feature = "secret-service"))]
const SECRET_SERVICE_INDEX_VERSION: u32 = 1;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
#[cfg(feature = "password")]
const SALT_BYTES: usize = 16;
const VAULT_ID_BYTES: usize = 16;
const MAX_NAME_BYTES: usize = 1024;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(all(target_os = "linux", feature = "secret-service"))]
const MAX_SECRET_SERVICE_INDEX_BYTES: u64 = 16 * 1024 * 1024;
#[cfg(feature = "password")]
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
#[cfg(feature = "password")]
const ARGON2_ITERATIONS: u32 = 3;
#[cfg(feature = "password")]
const ARGON2_PARALLELISM: u32 = 1;

/// Operations that do not require a vault to remain unlocked.
pub struct Vault;

/// Public metadata about a vault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultInfo {
    pub path: PathBuf,
    pub version: u32,
    pub vault_id: String,
    pub unlock_method: String,
    pub hardware_backend: Option<String>,
    pub yubikey_serial: Option<u32>,
}

/// An unlocked vault session.
///
/// The vault key remains in zeroizing process memory for this object's
/// lifetime. Credential plaintext is decrypted only by [`Self::get`] and is
/// returned in a zeroizing buffer.
pub struct UnlockedVault {
    root: PathBuf,
    vault_id: [u8; VAULT_ID_BYTES],
    key: Zeroizing<[u8; KEY_BYTES]>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultConfig {
    format: String,
    version: u32,
    vault_id: String,
    unlock: UnlockConfig,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method")]
enum UnlockConfig {
    #[serde(rename = "password")]
    Password {
        kdf: Argon2Config,
        salt: String,
        nonce: String,
        wrapped_key: String,
    },
    #[serde(rename = "hardware")]
    Hardware {
        backend: String,
        key_label: String,
        wrapped_key: String,
    },
    #[serde(rename = "hardware+yubikey")]
    HardwareYubiKey {
        backend: String,
        key_label: String,
        wrapped_share: String,
        yubikey: YubiKeyUnlock,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct YubiKeyUnlock {
    serial: u32,
    slot: String,
    algorithm: String,
    nonce: String,
    wrapped_share: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Argon2Config {
    algorithm: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct EntryFile {
    format: String,
    version: u32,
    nonce: String,
    ciphertext: String,
}

#[cfg(all(target_os = "linux", feature = "secret-service"))]
#[derive(Debug, Serialize, Deserialize)]
struct SecretServiceIndexFile {
    format: String,
    version: u32,
    nonce: String,
    ciphertext: String,
}

impl Vault {
    /// Create a vault whose key is bound to the platform hardware backend.
    pub fn create(path: impl AsRef<Path>) -> Result<UnlockedVault> {
        #[cfg(feature = "hardware")]
        {
            create_hardware_vault(path.as_ref())
        }
        #[cfg(not(feature = "hardware"))]
        {
            let _ = path;
            Err(Error::HardwareFeatureDisabled)
        }
    }

    /// Unlock a hardware-only vault.
    ///
    /// Vaults configured with a YubiKey require [`Self::unlock_with_yubikey`].
    pub fn unlock(path: impl AsRef<Path>) -> Result<UnlockedVault> {
        #[cfg(feature = "hardware")]
        {
            unlock_hardware_vault(path.as_ref(), None)
        }
        #[cfg(not(feature = "hardware"))]
        {
            let _ = path;
            Err(Error::HardwareFeatureDisabled)
        }
    }

    /// Create a hardware-bound vault that additionally requires a YubiKey.
    pub fn create_with_yubikey(
        path: impl AsRef<Path>,
        yubikey_pin: &[u8],
    ) -> Result<UnlockedVault> {
        #[cfg(all(feature = "hardware", feature = "yubikey"))]
        {
            create_hardware_yubikey_vault(path.as_ref(), yubikey_pin)
        }
        #[cfg(not(all(feature = "hardware", feature = "yubikey")))]
        {
            let _ = (path, yubikey_pin);
            if cfg!(not(feature = "hardware")) {
                Err(Error::HardwareFeatureDisabled)
            } else {
                Err(Error::YubiKeyFeatureDisabled)
            }
        }
    }

    /// Unlock a vault using platform hardware and its configured YubiKey.
    pub fn unlock_with_yubikey(
        path: impl AsRef<Path>,
        yubikey_pin: &[u8],
    ) -> Result<UnlockedVault> {
        #[cfg(all(feature = "hardware", feature = "yubikey"))]
        {
            unlock_hardware_vault(path.as_ref(), Some(yubikey_pin))
        }
        #[cfg(not(all(feature = "hardware", feature = "yubikey")))]
        {
            let _ = (path, yubikey_pin);
            if cfg!(not(feature = "hardware")) {
                Err(Error::HardwareFeatureDisabled)
            } else {
                Err(Error::YubiKeyFeatureDisabled)
            }
        }
    }

    /// Add a YubiKey as a required second factor to a hardware-only vault.
    pub fn add_yubikey(path: impl AsRef<Path>, yubikey_pin: &[u8]) -> Result<()> {
        #[cfg(all(feature = "hardware", feature = "yubikey"))]
        {
            let path = path.as_ref();
            let vault = unlock_hardware_vault(path, None)?;
            add_yubikey_factor(path, &vault, yubikey_pin)
        }
        #[cfg(not(all(feature = "hardware", feature = "yubikey")))]
        {
            let _ = (path, yubikey_pin);
            if cfg!(not(feature = "hardware")) {
                Err(Error::HardwareFeatureDisabled)
            } else {
                Err(Error::YubiKeyFeatureDisabled)
            }
        }
    }

    /// Remove the YubiKey requirement after successfully using both factors.
    pub fn remove_yubikey(path: impl AsRef<Path>, yubikey_pin: &[u8]) -> Result<()> {
        #[cfg(all(feature = "hardware", feature = "yubikey"))]
        {
            let path = path.as_ref();
            let session = unlock_hardware_vault(path, Some(yubikey_pin))?;
            let config = read_config(path)?;
            let (backend, key_label) = hardware_fields(&config.unlock)?;
            let protector = PlatformProtector::open(path, key_label)?;
            verify_recorded_backend(&protector, backend)?;
            let wrapped_key = protector.wrap(&*session.key)?;
            let updated = VaultConfig {
                format: VAULT_FORMAT.to_owned(),
                version: CURRENT_VAULT_VERSION,
                vault_id: config.vault_id,
                unlock: UnlockConfig::Hardware {
                    backend: protector.backend().as_str().to_owned(),
                    key_label: key_label.to_owned(),
                    wrapped_key: encode(&wrapped_key),
                },
            };
            let config_path = path.join(CONFIG_FILE);
            atomic_write(&config_path, &serialize(&updated, &config_path)?)
        }
        #[cfg(not(all(feature = "hardware", feature = "yubikey")))]
        {
            let _ = (path, yubikey_pin);
            if cfg!(not(feature = "hardware")) {
                Err(Error::HardwareFeatureDisabled)
            } else {
                Err(Error::YubiKeyFeatureDisabled)
            }
        }
    }

    /// Read non-secret vault metadata without unlocking it.
    pub fn info(path: impl AsRef<Path>) -> Result<VaultInfo> {
        let path = path.as_ref();
        validate_vault_directory(path)?;
        let config = read_config(path)?;
        let (unlock_method, hardware_backend, yubikey_serial) = match &config.unlock {
            UnlockConfig::Password { .. } => ("password", None, None),
            UnlockConfig::Hardware { backend, .. } => ("hardware", Some(backend.clone()), None),
            UnlockConfig::HardwareYubiKey {
                backend, yubikey, ..
            } => (
                "hardware+yubikey",
                Some(backend.clone()),
                Some(yubikey.serial),
            ),
        };
        Ok(VaultInfo {
            path: path.to_owned(),
            version: config.version,
            vault_id: config.vault_id,
            unlock_method: unlock_method.to_owned(),
            hardware_backend,
            yubikey_serial,
        })
    }

    /// Create a legacy password vault for development or migration testing.
    #[cfg(feature = "password")]
    pub fn create_with_password(path: impl AsRef<Path>, password: &[u8]) -> Result<UnlockedVault> {
        validate_password(password)?;
        let path = path.as_ref();
        let (vault_id, vault_key) = prepare_new_vault(path)?;
        let config = make_password_config(&vault_id, &vault_key, password)?;
        write_initial_config(path, &config)?;
        Ok(UnlockedVault {
            root: path.to_owned(),
            vault_id,
            key: vault_key,
        })
    }

    /// Unlock a legacy password vault.
    #[cfg(feature = "password")]
    pub fn unlock_with_password(path: impl AsRef<Path>, password: &[u8]) -> Result<UnlockedVault> {
        validate_password(password)?;
        let path = path.as_ref();
        validate_vault_directory(path)?;
        let config = read_config(path)?;
        let vault_id = decode_array::<VAULT_ID_BYTES>(&config.vault_id, "vault_id")
            .map_err(Error::InvalidMetadata)?;
        let key = unwrap_password_key(&config, &vault_id, password)?;
        Ok(UnlockedVault {
            root: path.to_owned(),
            vault_id,
            key,
        })
    }

    /// Rewrap a legacy password vault under a new password.
    #[cfg(feature = "password")]
    pub fn change_password(
        path: impl AsRef<Path>,
        current_password: &[u8],
        new_password: &[u8],
    ) -> Result<()> {
        validate_password(new_password)?;
        let path = path.as_ref();
        let session = Self::unlock_with_password(path, current_password)?;
        let config = make_password_config(&session.vault_id, &session.key, new_password)?;
        let config_path = path.join(CONFIG_FILE);
        atomic_write(&config_path, &serialize(&config, &config_path)?)
    }

    /// Migrate a version 1 password vault to platform hardware without
    /// rewriting credential entries.
    #[cfg(feature = "password")]
    pub fn migrate_password_to_hardware(path: impl AsRef<Path>, password: &[u8]) -> Result<()> {
        #[cfg(feature = "hardware")]
        {
            let path = path.as_ref();
            let session = Self::unlock_with_password(path, password)?;
            let config = make_hardware_config(path, &session.vault_id, &session.key)?;
            let config_path = path.join(CONFIG_FILE);
            atomic_write(&config_path, &serialize(&config, &config_path)?)
        }
        #[cfg(not(feature = "hardware"))]
        {
            let _ = (path, password);
            Err(Error::HardwareFeatureDisabled)
        }
    }

    #[cfg(all(test, feature = "hardware"))]
    pub(crate) fn create_for_test(path: impl AsRef<Path>) -> Result<UnlockedVault> {
        use crate::hardware::TestProtector;

        let path = path.as_ref();
        let (vault_id, vault_key) = prepare_new_vault(path)?;
        let protector = TestProtector::new([0x5a; KEY_BYTES]);
        let wrapped_key = protector.wrap(&*vault_key)?;
        let config = VaultConfig {
            format: VAULT_FORMAT.to_owned(),
            version: CURRENT_VAULT_VERSION,
            vault_id: encode(&vault_id),
            unlock: UnlockConfig::Hardware {
                backend: protector.backend().as_str().to_owned(),
                key_label: key_label(&vault_id),
                wrapped_key: encode(&wrapped_key),
            },
        };
        write_initial_config(path, &config)?;
        Ok(UnlockedVault {
            root: path.to_owned(),
            vault_id,
            key: vault_key,
        })
    }
}

impl UnlockedVault {
    /// Store or replace one credential.
    pub fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<()> {
        validate_specifiers(service, account)?;
        let aad = entry_aad(&self.vault_id, service, account);
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce)?;
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Authentication)?;
        let entry = EntryFile {
            format: ENTRY_FORMAT.to_owned(),
            version: ENTRY_VERSION,
            nonce: encode(&nonce),
            ciphertext: encode(&ciphertext),
        };
        let path = self.entry_path(service, account);
        atomic_write(&path, &serialize(&entry, &path)?)
    }

    /// Retrieve one credential in a zeroizing buffer.
    pub fn get(&self, service: &str, account: &str) -> Result<Zeroizing<Vec<u8>>> {
        validate_specifiers(service, account)?;
        let path = self.entry_path(service, account);
        let encoded = match read_limited(&path, MAX_ENTRY_BYTES) {
            Ok(value) => value,
            Err(Error::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Err(Error::NoEntry);
            }
            Err(error) => return Err(error),
        };
        let entry: EntryFile = deserialize(&encoded, &path).map_err(|_| Error::InvalidEntry)?;
        if entry.format != ENTRY_FORMAT || entry.version != ENTRY_VERSION {
            return Err(Error::InvalidEntry);
        }
        let nonce =
            decode_array::<NONCE_BYTES>(&entry.nonce, "nonce").map_err(|_| Error::InvalidEntry)?;
        let ciphertext =
            decode(&entry.ciphertext, "ciphertext").map_err(|_| Error::InvalidEntry)?;
        let aad = entry_aad(&self.vault_id, service, account);
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Authentication)?;
        Ok(Zeroizing::new(plaintext))
    }

    /// Delete one credential.
    pub fn delete(&self, service: &str, account: &str) -> Result<()> {
        validate_specifiers(service, account)?;
        let path = self.entry_path(service, account);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Err(Error::NoEntry),
            Err(source) => Err(Error::Io { path, source }),
        }
    }

    /// Test whether a credential exists without decrypting it.
    pub fn contains(&self, service: &str, account: &str) -> Result<bool> {
        validate_specifiers(service, account)?;
        let path = self.entry_path(service, account);
        path.try_exists()
            .map_err(|source| Error::Io { path, source })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn vault_id(&self) -> String {
        encode(&self.vault_id)
    }

    #[cfg(all(target_os = "linux", feature = "secret-service"))]
    pub(crate) fn read_secret_service_index(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let path = self.root.join(SECRET_SERVICE_INDEX_FILE);
        let encoded = match read_limited(&path, MAX_SECRET_SERVICE_INDEX_BYTES) {
            Ok(value) => value,
            Err(Error::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let index: SecretServiceIndexFile =
            deserialize(&encoded, &path).map_err(|_| Error::InvalidEntry)?;
        if index.format != SECRET_SERVICE_INDEX_FORMAT
            || index.version != SECRET_SERVICE_INDEX_VERSION
        {
            return Err(Error::InvalidEntry);
        }
        let nonce =
            decode_array::<NONCE_BYTES>(&index.nonce, "nonce").map_err(|_| Error::InvalidEntry)?;
        let ciphertext =
            decode(&index.ciphertext, "ciphertext").map_err(|_| Error::InvalidEntry)?;
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &secret_service_index_aad(&self.vault_id),
                },
            )
            .map_err(|_| Error::Authentication)?;
        Ok(Some(Zeroizing::new(plaintext)))
    }

    #[cfg(all(target_os = "linux", feature = "secret-service"))]
    pub(crate) fn write_secret_service_index(&self, plaintext: &[u8]) -> Result<()> {
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce)?;
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &secret_service_index_aad(&self.vault_id),
                },
            )
            .map_err(|_| Error::Authentication)?;
        let index = SecretServiceIndexFile {
            format: SECRET_SERVICE_INDEX_FORMAT.to_owned(),
            version: SECRET_SERVICE_INDEX_VERSION,
            nonce: encode(&nonce),
            ciphertext: encode(&ciphertext),
        };
        let path = self.root.join(SECRET_SERVICE_INDEX_FILE);
        atomic_write(&path, &serialize(&index, &path)?)
    }

    fn entry_path(&self, service: &str, account: &str) -> PathBuf {
        let mut hash = Sha256::new();
        hash.update(entry_aad(&self.vault_id, service, account));
        self.root
            .join(ENTRIES_DIRECTORY)
            .join(format!("{}.fseal", hex::encode(hash.finalize())))
    }
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnlockedVault")
            .field("root", &self.root)
            .field("vault_id", &encode(&self.vault_id))
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "hardware")]
fn create_hardware_vault(path: &Path) -> Result<UnlockedVault> {
    let (vault_id, vault_key) = prepare_new_vault(path)?;
    let config = make_hardware_config(path, &vault_id, &vault_key)?;
    write_initial_config(path, &config)?;
    Ok(UnlockedVault {
        root: path.to_owned(),
        vault_id,
        key: vault_key,
    })
}

#[cfg(all(feature = "hardware", feature = "yubikey"))]
fn create_hardware_yubikey_vault(path: &Path, pin: &[u8]) -> Result<UnlockedVault> {
    let (vault_id, vault_key) = prepare_new_vault(path)?;
    let label = key_label(&vault_id);
    let protector = PlatformProtector::open(path, &label)?;

    let mut yubikey_share = Zeroizing::new([0_u8; KEY_BYTES]);
    getrandom::fill(&mut *yubikey_share)?;
    let platform_share = xor_keys(&vault_key, &yubikey_share);
    let enrolled = crate::yubikey_factor::enroll(&vault_id, pin, &yubikey_share)?;
    let wrapped_platform_share = protector.wrap(&*platform_share)?;

    let config = VaultConfig {
        format: VAULT_FORMAT.to_owned(),
        version: CURRENT_VAULT_VERSION,
        vault_id: encode(&vault_id),
        unlock: UnlockConfig::HardwareYubiKey {
            backend: protector.backend().as_str().to_owned(),
            key_label: label,
            wrapped_share: encode(&wrapped_platform_share),
            yubikey: YubiKeyUnlock {
                serial: enrolled.serial,
                slot: enrolled.slot.to_owned(),
                algorithm: "rsa2048-pkcs1v15-signature-kdf".to_owned(),
                nonce: encode(&enrolled.nonce),
                wrapped_share: encode(&enrolled.wrapped_share),
            },
        },
    };
    write_initial_config(path, &config)?;
    Ok(UnlockedVault {
        root: path.to_owned(),
        vault_id,
        key: vault_key,
    })
}

#[cfg(feature = "hardware")]
fn make_hardware_config(
    path: &Path,
    vault_id: &[u8; VAULT_ID_BYTES],
    vault_key: &[u8; KEY_BYTES],
) -> Result<VaultConfig> {
    let label = key_label(vault_id);
    let protector = PlatformProtector::open(path, &label)?;
    let wrapped_key = protector.wrap(vault_key)?;
    Ok(VaultConfig {
        format: VAULT_FORMAT.to_owned(),
        version: CURRENT_VAULT_VERSION,
        vault_id: encode(vault_id),
        unlock: UnlockConfig::Hardware {
            backend: protector.backend().as_str().to_owned(),
            key_label: label,
            wrapped_key: encode(&wrapped_key),
        },
    })
}

#[cfg(feature = "hardware")]
fn unlock_hardware_vault(path: &Path, yubikey_pin: Option<&[u8]>) -> Result<UnlockedVault> {
    validate_vault_directory(path)?;
    let config = read_config(path)?;
    let vault_id = decode_array::<VAULT_ID_BYTES>(&config.vault_id, "vault_id")
        .map_err(Error::InvalidMetadata)?;

    let key = match &config.unlock {
        UnlockConfig::Password { .. } => return Err(Error::PasswordFeatureDisabled),
        UnlockConfig::Hardware {
            backend,
            key_label,
            wrapped_key,
        } => {
            let protector = PlatformProtector::open(path, key_label)?;
            verify_recorded_backend(&protector, backend)?;
            let wrapped_key = decode(wrapped_key, "wrapped_key").map_err(Error::InvalidMetadata)?;
            decode_key(&protector.unwrap(&wrapped_key)?, "hardware vault key")?
        }
        UnlockConfig::HardwareYubiKey {
            backend,
            key_label,
            wrapped_share,
            yubikey,
        } => {
            let pin = yubikey_pin.ok_or(Error::YubiKeyRequired)?;
            let protector = PlatformProtector::open(path, key_label)?;
            verify_recorded_backend(&protector, backend)?;
            let wrapped_share =
                decode(wrapped_share, "wrapped_share").map_err(Error::InvalidMetadata)?;
            let platform_share = decode_key(
                &protector.unwrap(&wrapped_share)?,
                "hardware vault-key share",
            )?;
            #[cfg(feature = "yubikey")]
            {
                if yubikey.algorithm != "rsa2048-pkcs1v15-signature-kdf" {
                    return Err(Error::InvalidMetadata(format!(
                        "unsupported YubiKey algorithm `{}`",
                        yubikey.algorithm
                    )));
                }
                let nonce = decode_array::<NONCE_BYTES>(&yubikey.nonce, "yubikey.nonce")
                    .map_err(Error::InvalidMetadata)?;
                let wrapped = decode(&yubikey.wrapped_share, "yubikey.wrapped_share")
                    .map_err(Error::InvalidMetadata)?;
                let yubikey_share = crate::yubikey_factor::unlock_share(
                    &vault_id,
                    yubikey.serial,
                    &yubikey.slot,
                    &nonce,
                    &wrapped,
                    pin,
                )?;
                xor_keys(&platform_share, &yubikey_share)
            }
            #[cfg(not(feature = "yubikey"))]
            {
                let _ = (pin, platform_share, yubikey);
                return Err(Error::YubiKeyFeatureDisabled);
            }
        }
    };

    Ok(UnlockedVault {
        root: path.to_owned(),
        vault_id,
        key,
    })
}

#[cfg(feature = "hardware")]
fn verify_recorded_backend(protector: &impl KeyProtector, recorded_backend: &str) -> Result<()> {
    let recorded = HardwareBackend::parse(recorded_backend)?;
    let actual = protector.backend();
    if actual != recorded {
        return Err(Error::HardwareUnavailable(format!(
            "vault requires {}, but {} was selected",
            recorded.as_str(),
            actual.as_str()
        )));
    }
    Ok(())
}

#[cfg(all(feature = "hardware", feature = "yubikey"))]
fn add_yubikey_factor(path: &Path, session: &UnlockedVault, pin: &[u8]) -> Result<()> {
    let config = read_config(path)?;
    let (backend, key_label, wrapped_key) = match &config.unlock {
        UnlockConfig::Hardware {
            backend,
            key_label,
            wrapped_key,
        } => (backend, key_label, wrapped_key),
        UnlockConfig::HardwareYubiKey { .. } => {
            return Err(Error::InvalidMetadata(
                "vault already requires a YubiKey".to_owned(),
            ));
        }
        UnlockConfig::Password { .. } => return Err(Error::PasswordFeatureDisabled),
    };

    let protector = PlatformProtector::open(path, key_label)?;
    verify_recorded_backend(&protector, backend)?;
    // Confirm that the current hardware wrapping still opens the same key
    // before replacing the policy metadata.
    let current_wrapped = decode(wrapped_key, "wrapped_key").map_err(Error::InvalidMetadata)?;
    let current_key = decode_key(&protector.unwrap(&current_wrapped)?, "hardware vault key")?;
    if *current_key != *session.key {
        return Err(Error::Authentication);
    }

    let mut yubikey_share = Zeroizing::new([0_u8; KEY_BYTES]);
    getrandom::fill(&mut *yubikey_share)?;
    let platform_share = xor_keys(&session.key, &yubikey_share);
    let enrolled = crate::yubikey_factor::enroll(&session.vault_id, pin, &yubikey_share)?;
    let wrapped_platform_share = protector.wrap(&*platform_share)?;

    let updated = VaultConfig {
        format: VAULT_FORMAT.to_owned(),
        version: CURRENT_VAULT_VERSION,
        vault_id: config.vault_id,
        unlock: UnlockConfig::HardwareYubiKey {
            backend: protector.backend().as_str().to_owned(),
            key_label: key_label.clone(),
            wrapped_share: encode(&wrapped_platform_share),
            yubikey: YubiKeyUnlock {
                serial: enrolled.serial,
                slot: enrolled.slot.to_owned(),
                algorithm: "rsa2048-pkcs1v15-signature-kdf".to_owned(),
                nonce: encode(&enrolled.nonce),
                wrapped_share: encode(&enrolled.wrapped_share),
            },
        },
    };
    let config_path = path.join(CONFIG_FILE);
    atomic_write(&config_path, &serialize(&updated, &config_path)?)
}

#[cfg(all(feature = "hardware", feature = "yubikey"))]
fn hardware_fields(unlock: &UnlockConfig) -> Result<(&str, &str)> {
    match unlock {
        UnlockConfig::HardwareYubiKey {
            backend, key_label, ..
        } => Ok((backend, key_label)),
        UnlockConfig::Hardware { .. } => Err(Error::InvalidMetadata(
            "vault does not require a YubiKey".to_owned(),
        )),
        UnlockConfig::Password { .. } => Err(Error::PasswordFeatureDisabled),
    }
}

#[cfg(any(feature = "hardware", feature = "password"))]
fn prepare_new_vault(path: &Path) -> Result<([u8; VAULT_ID_BYTES], Zeroizing<[u8; KEY_BYTES]>)> {
    if path.exists() {
        return Err(Error::VaultExists(path.to_owned()));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| Error::Io {
            path: parent.to_owned(),
            source,
        })?;
    }
    create_private_directory(path)?;
    create_private_directory(&path.join(ENTRIES_DIRECTORY))?;

    let mut vault_id = [0_u8; VAULT_ID_BYTES];
    let mut vault_key = Zeroizing::new([0_u8; KEY_BYTES]);
    getrandom::fill(&mut vault_id)?;
    getrandom::fill(&mut *vault_key)?;
    Ok((vault_id, vault_key))
}

#[cfg(any(feature = "hardware", feature = "password"))]
fn write_initial_config(path: &Path, config: &VaultConfig) -> Result<()> {
    let config_path = path.join(CONFIG_FILE);
    write_new_private_file(&config_path, &serialize(config, &config_path)?)
}

#[cfg(any(feature = "hardware", feature = "password"))]
fn decode_key(plaintext: &Zeroizing<Vec<u8>>, field: &str) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let actual = plaintext.len();
    let key = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidMetadata(format!("{field} has {actual} bytes")))?;
    Ok(Zeroizing::new(key))
}

#[cfg(any(feature = "yubikey", all(test, feature = "hardware")))]
fn xor_keys(left: &[u8; KEY_BYTES], right: &[u8; KEY_BYTES]) -> Zeroizing<[u8; KEY_BYTES]> {
    let mut output = Zeroizing::new([0_u8; KEY_BYTES]);
    for (target, (left, right)) in output.iter_mut().zip(left.iter().zip(right)) {
        *target = left ^ right;
    }
    output
}

#[cfg(feature = "hardware")]
fn key_label(vault_id: &[u8; VAULT_ID_BYTES]) -> String {
    format!("vault-{}", hex::encode(vault_id))
}

#[cfg(feature = "password")]
fn make_password_config(
    vault_id: &[u8; VAULT_ID_BYTES],
    vault_key: &[u8; KEY_BYTES],
    password: &[u8],
) -> Result<VaultConfig> {
    let mut salt = [0_u8; SALT_BYTES];
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut salt)?;
    getrandom::fill(&mut nonce)?;
    let kdf = default_argon2_config();
    let password_key = derive_password_key(password, &salt, &kdf)?;
    let cipher = XChaCha20Poly1305::new((&*password_key).into());
    let wrapped_key = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: vault_key,
                aad: &vault_key_aad(vault_id),
            },
        )
        .map_err(|_| Error::Authentication)?;
    Ok(VaultConfig {
        format: VAULT_FORMAT.to_owned(),
        version: PASSWORD_VAULT_VERSION,
        vault_id: encode(vault_id),
        unlock: UnlockConfig::Password {
            kdf,
            salt: encode(&salt),
            nonce: encode(&nonce),
            wrapped_key: encode(&wrapped_key),
        },
    })
}

#[cfg(feature = "password")]
fn unwrap_password_key(
    config: &VaultConfig,
    vault_id: &[u8; VAULT_ID_BYTES],
    password: &[u8],
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let UnlockConfig::Password {
        kdf,
        salt,
        nonce,
        wrapped_key,
    } = &config.unlock
    else {
        return Err(Error::InvalidMetadata(
            "vault is not password-protected".to_owned(),
        ));
    };
    let salt = decode_array::<SALT_BYTES>(salt, "salt").map_err(Error::InvalidMetadata)?;
    let nonce = decode_array::<NONCE_BYTES>(nonce, "nonce").map_err(Error::InvalidMetadata)?;
    let wrapped_key = decode(wrapped_key, "wrapped_key").map_err(Error::InvalidMetadata)?;
    let password_key = derive_password_key(password, &salt, kdf)?;
    let cipher = XChaCha20Poly1305::new((&*password_key).into());
    let key = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &wrapped_key,
                    aad: &vault_key_aad(vault_id),
                },
            )
            .map_err(|_| Error::UnlockFailed)?,
    );
    decode_key(&key, "vault key")
}

#[cfg(feature = "password")]
fn derive_password_key(
    password: &[u8],
    salt: &[u8],
    config: &Argon2Config,
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    if config.algorithm != "argon2id"
        || config.version != 0x13
        || config.memory_kib < 8 * 1024
        || config.iterations == 0
        || config.parallelism == 0
    {
        return Err(Error::InvalidMetadata(
            "unsupported or unsafe Argon2 parameters".to_owned(),
        ));
    }
    let params = Params::new(
        config.memory_kib,
        config.iterations,
        config.parallelism,
        Some(KEY_BYTES),
    )
    .map_err(|error| Error::PasswordDerivation(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; KEY_BYTES]);
    argon2
        .hash_password_into(password, salt, &mut *output)
        .map_err(|error| Error::PasswordDerivation(error.to_string()))?;
    Ok(output)
}

#[cfg(feature = "password")]
fn default_argon2_config() -> Argon2Config {
    Argon2Config {
        algorithm: "argon2id".to_owned(),
        version: 0x13,
        memory_kib: ARGON2_MEMORY_KIB,
        iterations: ARGON2_ITERATIONS,
        parallelism: ARGON2_PARALLELISM,
    }
}

fn validate_config(config: &VaultConfig) -> Result<()> {
    if config.format != VAULT_FORMAT {
        return Err(Error::InvalidFormat(config.format.clone()));
    }
    match (&config.unlock, config.version) {
        (UnlockConfig::Password { .. }, PASSWORD_VAULT_VERSION)
        | (
            UnlockConfig::Hardware { .. } | UnlockConfig::HardwareYubiKey { .. },
            CURRENT_VAULT_VERSION,
        ) => {}
        (_, version) if version != PASSWORD_VAULT_VERSION && version != CURRENT_VAULT_VERSION => {
            return Err(Error::UnsupportedVersion(version));
        }
        _ => {
            return Err(Error::InvalidMetadata(
                "unlock method does not match vault version".to_owned(),
            ));
        }
    }
    decode_array::<VAULT_ID_BYTES>(&config.vault_id, "vault_id").map_err(Error::InvalidMetadata)?;
    Ok(())
}

#[cfg(feature = "password")]
fn validate_password(password: &[u8]) -> Result<()> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    Ok(())
}

fn validate_specifiers(service: &str, account: &str) -> Result<()> {
    if service.is_empty() {
        return Err(Error::EmptyService);
    }
    if account.is_empty() {
        return Err(Error::EmptyAccount);
    }
    if service.len() > MAX_NAME_BYTES {
        return Err(Error::CredentialNameTooLong {
            field: "service",
            maximum: MAX_NAME_BYTES,
        });
    }
    if account.len() > MAX_NAME_BYTES {
        return Err(Error::CredentialNameTooLong {
            field: "account",
            maximum: MAX_NAME_BYTES,
        });
    }
    Ok(())
}

fn validate_vault_directory(path: &Path) -> Result<()> {
    let metadata = match fs::metadata(path) {
        Ok(value) => value,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(Error::VaultNotFound(path.to_owned()));
        }
        Err(source) => {
            return Err(Error::Io {
                path: path.to_owned(),
                source,
            });
        }
    };
    if !metadata.is_dir() {
        return Err(Error::InvalidVaultPath(path.to_owned()));
    }
    validate_private_directory_permissions(path, &metadata)
}

fn read_config(root: &Path) -> Result<VaultConfig> {
    let path = root.join(CONFIG_FILE);
    let encoded = read_limited(&path, MAX_CONFIG_BYTES)?;
    let config = deserialize(&encoded, &path)?;
    validate_config(&config)?;
    Ok(config)
}

fn entry_aad(vault_id: &[u8; VAULT_ID_BYTES], service: &str, account: &str) -> Vec<u8> {
    let mut aad = b"factorseal/entry/v1\0".to_vec();
    aad.extend_from_slice(vault_id);
    append_length_prefixed(&mut aad, service.as_bytes());
    append_length_prefixed(&mut aad, account.as_bytes());
    aad
}

#[cfg(all(target_os = "linux", feature = "secret-service"))]
fn secret_service_index_aad(vault_id: &[u8; VAULT_ID_BYTES]) -> Vec<u8> {
    let mut aad = b"factorseal/secret-service-index/v1\0".to_vec();
    aad.extend_from_slice(vault_id);
    aad
}

#[cfg(feature = "password")]
fn vault_key_aad(vault_id: &[u8; VAULT_ID_BYTES]) -> Vec<u8> {
    let mut aad = b"factorseal/vault-key/v1\0".to_vec();
    aad.extend_from_slice(vault_id);
    aad
}

fn append_length_prefixed(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode(value: &str, field: &str) -> std::result::Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| format!("invalid base64 in {field}: {error}"))
}

fn decode_array<const N: usize>(value: &str, field: &str) -> std::result::Result<[u8; N], String> {
    let decoded = decode(value, field)?;
    let actual = decoded.len();
    decoded
        .try_into()
        .map_err(|_| format!("{field} must contain {N} bytes, found {actual}"))
}

fn serialize<T: Serialize>(value: &T, path: &Path) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(value).map_err(|source| Error::Json {
        path: path.to_owned(),
        source,
    })
}

fn deserialize<T: for<'de> Deserialize<'de>>(value: &[u8], path: &Path) -> Result<T> {
    serde_json::from_slice(value).map_err(|source| Error::Json {
        path: path.to_owned(),
        source,
    })
}

fn read_limited(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| Error::Io {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > maximum {
        return Err(Error::FileTooLarge {
            path: path.to_owned(),
            maximum,
        });
    }
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::InvalidMetadata("storage path has no parent directory".to_owned()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|source| Error::Io {
        path: parent.to_owned(),
        source,
    })?;
    temporary.write_all(bytes).map_err(|source| Error::Io {
        path: temporary.path().to_owned(),
        source,
    })?;
    temporary.as_file().sync_all().map_err(|source| Error::Io {
        path: temporary.path().to_owned(),
        source,
    })?;
    temporary
        .persist(path)
        .map(|_| ())
        .map_err(|error| Error::Io {
            path: path.to_owned(),
            source: error.error,
        })
}

#[cfg(any(feature = "hardware", feature = "password"))]
fn create_private_directory(path: &Path) -> Result<()> {
    create_directory(path)?;
    set_private_directory_permissions(path)
}

#[cfg(all(any(feature = "hardware", feature = "password"), unix))]
fn create_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })
}

#[cfg(all(any(feature = "hardware", feature = "password"), not(unix)))]
fn create_directory(path: &Path) -> Result<()> {
    fs::create_dir(path).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })
}

#[cfg(all(any(feature = "hardware", feature = "password"), unix))]
fn set_private_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })
}

#[cfg(all(any(feature = "hardware", feature = "password"), not(unix)))]
fn set_private_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_directory_permissions(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::InsecurePermissions {
            path: path.to_owned(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_directory_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(all(any(feature = "hardware", feature = "password"), unix))]
fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })?;
    file.write_all(bytes).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })?;
    file.sync_all().map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })
}

#[cfg(all(any(feature = "hardware", feature = "password"), not(unix)))]
fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(path).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })?;
    file.write_all(bytes).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })?;
    file.sync_all().map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })
}

#[cfg(all(test, feature = "hardware"))]
mod tests {
    use super::*;
    use crate::hardware::{KeyProtector, TestProtector};

    fn vault() -> (tempfile::TempDir, PathBuf, UnlockedVault) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault");
        let vault = Vault::create_for_test(&path).unwrap();
        (directory, path, vault)
    }

    fn unlock_for_test(path: &Path) -> UnlockedVault {
        let config = read_config(path).unwrap();
        let vault_id = decode_array::<VAULT_ID_BYTES>(&config.vault_id, "vault_id").unwrap();
        let UnlockConfig::Hardware { wrapped_key, .. } = config.unlock else {
            panic!("expected hardware config");
        };
        let protector = TestProtector::new([0x5a; KEY_BYTES]);
        let key = decode_key(
            &protector
                .unwrap(&decode(&wrapped_key, "wrapped_key").unwrap())
                .unwrap(),
            "test key",
        )
        .unwrap();
        UnlockedVault {
            root: path.to_owned(),
            vault_id,
            key,
        }
    }

    #[test]
    fn create_unlock_and_round_trip() {
        let (_directory, path, vault) = vault();
        vault
            .set("example", "DATABASE_URL", b"postgres://localhost")
            .unwrap();
        drop(vault);

        let unlocked = unlock_for_test(&path);
        assert_eq!(
            unlocked.get("example", "DATABASE_URL").unwrap().as_slice(),
            b"postgres://localhost"
        );
    }

    #[test]
    fn entry_names_are_authenticated() {
        let (_directory, _path, vault) = vault();
        vault.set("service", "first", b"secret").unwrap();
        let first = vault.entry_path("service", "first");
        let second = vault.entry_path("service", "second");
        fs::copy(first, second).unwrap();

        assert!(matches!(
            vault.get("service", "second"),
            Err(Error::Authentication)
        ));
    }

    #[cfg(all(target_os = "linux", feature = "secret-service"))]
    #[test]
    fn secret_service_index_is_encrypted() {
        let (_directory, _path, vault) = vault();
        let metadata = b"metadata marker that must not appear on disk";
        vault.write_secret_service_index(metadata).unwrap();

        let stored = fs::read(vault.path().join(SECRET_SERVICE_INDEX_FILE)).unwrap();
        assert!(
            !stored
                .windows(metadata.len())
                .any(|window| window == metadata)
        );
        assert_eq!(
            vault
                .read_secret_service_index()
                .unwrap()
                .unwrap()
                .as_slice(),
            metadata
        );
    }

    #[test]
    fn delete_and_contains() {
        let (_directory, _path, vault) = vault();
        assert!(!vault.contains("service", "account").unwrap());
        vault.set("service", "account", b"value").unwrap();
        assert!(vault.contains("service", "account").unwrap());
        vault.delete("service", "account").unwrap();
        assert!(!vault.contains("service", "account").unwrap());
        assert!(matches!(
            vault.get("service", "account"),
            Err(Error::NoEntry)
        ));
    }

    #[test]
    fn info_does_not_unlock_hardware() {
        let (_directory, path, vault) = vault();
        let expected_id = vault.vault_id();
        drop(vault);
        let info = Vault::info(path).unwrap();
        assert_eq!(info.version, 2);
        assert_eq!(info.vault_id, expected_id);
        assert_eq!(info.unlock_method, "hardware");
        assert_eq!(info.hardware_backend.as_deref(), Some("tpm"));
    }

    #[test]
    fn xor_shares_reconstruct_key() {
        let key = [0x42; KEY_BYTES];
        let share = [0xa5; KEY_BYTES];
        let other = xor_keys(&key, &share);
        assert_eq!(*xor_keys(&other, &share), key);
        assert_ne!(*other, key);
    }

    #[cfg(feature = "password")]
    #[test]
    fn password_vault_round_trip_and_change() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault");
        let vault = Vault::create_with_password(&path, b"old password").unwrap();
        vault.set("service", "account", b"survives").unwrap();
        drop(vault);

        assert!(Vault::unlock_with_password(&path, b"wrong").is_err());
        Vault::change_password(&path, b"old password", b"new password").unwrap();
        assert!(Vault::unlock_with_password(&path, b"old password").is_err());
        let unlocked = Vault::unlock_with_password(&path, b"new password").unwrap();
        assert_eq!(
            unlocked.get("service", "account").unwrap().as_slice(),
            b"survives"
        );
    }
}

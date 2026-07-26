#[cfg(any(feature = "hardware", feature = "password"))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "password")]
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{self, KEY_BYTES, NONCE_BYTES};
#[cfg(feature = "hardware")]
use crate::hardware::{HardwareBackend, KeyProtector, PlatformProtector};
use crate::{Error, Result};

const CONFIG_FILE: &str = "vault.json";
const ENTRIES_DIRECTORY: &str = "entries";
const REFERENCE_INDEX_FILE: &str = "reference-index.fseal";
#[cfg(all(target_os = "linux", feature = "secret-service"))]
const SECRET_SERVICE_INDEX_FILE: &str = "secret-service-index.fseal";
const VAULT_FORMAT: &str = "factorseal-vault";
const ENTRY_FORMAT: &str = "factorseal-entry";
const REFERENCE_INDEX_FORMAT: &str = "factorseal-reference-index";
#[cfg(all(target_os = "linux", feature = "secret-service"))]
const SECRET_SERVICE_INDEX_FORMAT: &str = "factorseal-secret-service-index";
const CURRENT_VAULT_VERSION: u32 = 2;
const PASSWORD_VAULT_VERSION: u32 = 1;
const LEGACY_ENTRY_VERSION: u32 = 1;
const ENTRY_VERSION: u32 = 2;
const REFERENCE_ENTRY_VERSION: u32 = 3;
const REFERENCE_INDEX_VERSION: u32 = 1;
#[cfg(all(target_os = "linux", feature = "secret-service"))]
const SECRET_SERVICE_INDEX_VERSION: u32 = 1;
#[cfg(feature = "password")]
const SALT_BYTES: usize = 16;
const VAULT_ID_BYTES: usize = 16;
const MAX_NAME_BYTES: usize = 1024;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 96 * 1024 * 1024;
const MAX_REFERENCE_INDEX_BYTES: u64 = 16 * 1024 * 1024;
const ENTRY_PAYLOAD_NO_EVICTION: u8 = 0;
const ENTRY_PAYLOAD_EVICT_AT: u8 = 1;
const ENTRY_PAYLOAD_EVICT_AT_BYTES: usize = 1 + size_of::<u64>();
#[cfg(all(target_os = "linux", feature = "secret-service"))]
const MAX_SECRET_SERVICE_INDEX_BYTES: u64 = 16 * 1024 * 1024;
#[cfg(feature = "yubikey")]
const YUBIKEY_ALGORITHM: &str = "rsa2048-pkcs1v15-signature-kdf";
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

/// Options applied when storing one credential.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CredentialOptions {
    /// Unix timestamp after which the credential is evicted.
    pub evict_at: Option<u64>,
}

/// Options and optional keyring metadata applied through a secret reference.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReferenceOptions {
    /// Unix timestamp after which the credential is evicted.
    pub evict_at: Option<u64>,
    /// Optional keyring service, supplied together with `account`.
    pub service: Option<String>,
    /// Optional keyring account, supplied together with `service`.
    pub account: Option<String>,
}

/// Stable coordinates for one secret.
///
/// `item` identifies a complete secret value. `field` optionally identifies a
/// value within a structured item. Keyring `service` and `account` values are
/// stored separately as searchable metadata and are not part of this identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SecretReference {
    item: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    field: Option<String>,
}

impl SecretReference {
    /// Create a reference to a complete secret item.
    pub fn new(item: impl Into<String>) -> Result<Self> {
        let reference = Self {
            item: item.into(),
            field: None,
        };
        validate_reference(&reference)?;
        Ok(reference)
    }

    /// Create a reference to one field within a structured secret item.
    pub fn with_field(item: impl Into<String>, field: impl Into<String>) -> Result<Self> {
        let reference = Self {
            item: item.into(),
            field: Some(field.into()),
        };
        validate_reference(&reference)?;
        Ok(reference)
    }

    /// Return the item coordinate.
    #[must_use]
    pub fn item(&self) -> &str {
        &self.item
    }

    /// Return the optional structured-field coordinate.
    #[must_use]
    pub fn field(&self) -> Option<&str> {
        self.field.as_deref()
    }
}

/// Authenticated metadata stored with one credential.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CredentialMetadata {
    /// Unix timestamp after which the credential is evicted.
    pub evict_at: Option<u64>,
    /// Optional keyring service associated with the stable reference.
    pub service: Option<String>,
    /// Optional keyring account associated with the stable reference.
    pub account: Option<String>,
}

/// An unlocked vault session.
///
/// The vault key remains in zeroizing process memory for this object's
/// lifetime. Credential plaintext is decrypted only by [`Self::get`] and is
/// returned in a zeroizing buffer.
pub struct UnlockedVault {
    root: PathBuf,
    vault_id: [u8; VAULT_ID_BYTES],
    key: RwLock<Option<Zeroizing<[u8; KEY_BYTES]>>>,
    reference_index: Mutex<()>,
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
struct EncryptedFile {
    format: String,
    version: u32,
    nonce: String,
    ciphertext: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReferenceIndex {
    format: String,
    version: u32,
    entries: Vec<ReferenceIndexEntry>,
}

impl Default for ReferenceIndex {
    fn default() -> Self {
        Self {
            format: REFERENCE_INDEX_FORMAT.to_owned(),
            version: REFERENCE_INDEX_VERSION,
            entries: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ReferenceIndexEntry {
    reference: SecretReference,
    service: String,
    account: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct EntryMetadata {
    evict_at: Option<u64>,
}

impl EncryptedFile {
    fn encrypt(
        format: &str,
        version: u32,
        key: &[u8; KEY_BYTES],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Self> {
        let encrypted = crypto::encrypt(key, aad, plaintext)?;
        Ok(Self {
            format: format.to_owned(),
            version,
            nonce: encode(&encrypted.nonce),
            ciphertext: encode(&encrypted.ciphertext),
        })
    }

    fn decrypt(
        &self,
        expected_format: &str,
        expected_version: u32,
        key: &[u8; KEY_BYTES],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if self.format != expected_format || self.version != expected_version {
            return Err(Error::InvalidEntry);
        }
        let nonce =
            decode_array::<NONCE_BYTES>(&self.nonce, "nonce").map_err(|_| Error::InvalidEntry)?;
        let ciphertext = decode(&self.ciphertext, "ciphertext").map_err(|_| Error::InvalidEntry)?;
        crypto::decrypt(key, &nonce, aad, &ciphertext).map_err(|_| Error::Authentication)
    }
}

impl VaultConfig {
    #[cfg(feature = "hardware")]
    fn hardware(
        vault_id: String,
        backend: HardwareBackend,
        key_label: String,
        wrapped_key: &[u8],
    ) -> Self {
        Self {
            format: VAULT_FORMAT.to_owned(),
            version: CURRENT_VAULT_VERSION,
            vault_id,
            unlock: UnlockConfig::Hardware {
                backend: backend.as_str().to_owned(),
                key_label,
                wrapped_key: encode(wrapped_key),
            },
        }
    }

    #[cfg(all(feature = "hardware", feature = "yubikey"))]
    fn hardware_yubikey(
        vault_id: String,
        backend: HardwareBackend,
        key_label: String,
        wrapped_share: &[u8],
        enrolled: &crate::yubikey_factor::EnrolledYubiKey,
    ) -> Self {
        Self {
            format: VAULT_FORMAT.to_owned(),
            version: CURRENT_VAULT_VERSION,
            vault_id,
            unlock: UnlockConfig::HardwareYubiKey {
                backend: backend.as_str().to_owned(),
                key_label,
                wrapped_share: encode(wrapped_share),
                yubikey: YubiKeyUnlock {
                    serial: enrolled.serial,
                    slot: enrolled.slot.to_owned(),
                    algorithm: YUBIKEY_ALGORITHM.to_owned(),
                    nonce: encode(&enrolled.nonce),
                    wrapped_share: encode(&enrolled.wrapped_share),
                },
            },
        }
    }
}

impl Vault {
    /// Create a transitional hardware-only vault.
    ///
    /// This compatibility API does not meet FactorSeal's 2FA design
    /// requirement. Use [`Self::create_with_yubikey`] for the current
    /// design-compliant configuration.
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
    /// Hardware-only vaults do not meet FactorSeal's 2FA design requirement.
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

    /// Create a 2FA vault requiring both platform hardware and a YubiKey.
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

    /// Unlock a 2FA vault using platform hardware and its configured YubiKey.
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

    /// Downgrade a 2FA vault to transitional hardware-only compatibility.
    ///
    /// The resulting vault does not meet FactorSeal's 2FA design requirement.
    pub fn remove_yubikey(path: impl AsRef<Path>, yubikey_pin: &[u8]) -> Result<()> {
        #[cfg(all(feature = "hardware", feature = "yubikey"))]
        {
            let path = path.as_ref();
            let session = unlock_hardware_vault(path, Some(yubikey_pin))?;
            let config = read_config(path)?;
            let (backend, key_label) = hardware_fields(&config.unlock)?;
            let protector = PlatformProtector::open(path, key_label)?;
            verify_recorded_backend(&protector, backend)?;
            let wrapped_key = session.with_key(|key| protector.wrap(key))?;
            let updated = VaultConfig::hardware(
                config.vault_id,
                protector.backend(),
                key_label.to_owned(),
                &wrapped_key,
            );
            write_config(path, &updated)
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
        Ok(UnlockedVault::new(path, vault_id, vault_key))
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
        Ok(UnlockedVault::new(path, vault_id, key))
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
        let config =
            session.with_key(|key| make_password_config(&session.vault_id, key, new_password))?;
        write_config(path, &config)
    }

    /// Migrate a version 1 password vault to transitional hardware-only
    /// compatibility without rewriting credential entries.
    ///
    /// The resulting vault does not meet FactorSeal's 2FA design requirement.
    #[cfg(feature = "password")]
    pub fn migrate_password_to_hardware(path: impl AsRef<Path>, password: &[u8]) -> Result<()> {
        #[cfg(feature = "hardware")]
        {
            let path = path.as_ref();
            let session = Self::unlock_with_password(path, password)?;
            let config =
                session.with_key(|key| make_hardware_config(path, &session.vault_id, key))?;
            write_config(path, &config)
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
        let config = VaultConfig::hardware(
            encode(&vault_id),
            protector.backend(),
            key_label(&vault_id),
            &wrapped_key,
        );
        write_initial_config(path, &config)?;
        Ok(UnlockedVault::new(path, vault_id, vault_key))
    }
}

impl UnlockedVault {
    #[cfg(any(feature = "hardware", feature = "password"))]
    fn new(root: &Path, vault_id: [u8; VAULT_ID_BYTES], key: Zeroizing<[u8; KEY_BYTES]>) -> Self {
        Self {
            root: root.to_owned(),
            vault_id,
            key: RwLock::new(Some(key)),
            reference_index: Mutex::new(()),
        }
    }

    fn with_key<T>(&self, operation: impl FnOnce(&[u8; KEY_BYTES]) -> Result<T>) -> Result<T> {
        let state = self.key.read().map_err(|_| Error::VaultStatePoisoned)?;
        let key = state.as_deref().ok_or(Error::VaultLocked)?;
        operation(key)
    }

    /// Zeroize the vault key and prevent further operations on this session.
    pub fn lock(&self) -> Result<()> {
        let mut state = self.key.write().map_err(|_| Error::VaultStatePoisoned)?;
        state.take();
        Ok(())
    }

    /// Report whether this unlocked session has been locked.
    pub fn is_locked(&self) -> Result<bool> {
        let state = self.key.read().map_err(|_| Error::VaultStatePoisoned)?;
        Ok(state.is_none())
    }

    /// Store or replace one credential, preserving its existing eviction deadline.
    pub fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<()> {
        self.set_keyring_credential(service, account, secret, None)
    }

    /// Store or replace one credential and its eviction policy.
    pub fn set_with_options(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
        options: CredentialOptions,
    ) -> Result<()> {
        validate_specifiers(service, account)?;
        self.set_keyring_credential(service, account, secret, Some(options))
    }

    /// Retrieve one credential in a zeroizing buffer.
    pub fn get(&self, service: &str, account: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.get_with_metadata(service, account)
            .map(|(secret, _)| secret)
    }

    /// Retrieve one credential together with its authenticated metadata.
    pub fn get_with_metadata(
        &self,
        service: &str,
        account: &str,
    ) -> Result<(Zeroizing<Vec<u8>>, CredentialMetadata)> {
        validate_specifiers(service, account)?;
        let _guard = self
            .reference_index
            .lock()
            .map_err(|_| Error::VaultStatePoisoned)?;
        let mut index = self.read_reference_index()?;
        if let Some(reference) = self.live_reference(&mut index, service, account)? {
            let (secret, metadata, _) = self.read_reference_credential(&reference)?;
            return Ok((
                secret,
                CredentialMetadata {
                    evict_at: metadata.evict_at,
                    service: Some(service.to_owned()),
                    account: Some(account.to_owned()),
                },
            ));
        }
        let (secret, metadata, _) = self.read_legacy_credential(service, account)?;
        Ok((
            secret,
            CredentialMetadata {
                evict_at: metadata.evict_at,
                service: Some(service.to_owned()),
                account: Some(account.to_owned()),
            },
        ))
    }

    /// Retrieve authenticated credential metadata without returning its secret.
    pub fn metadata(&self, service: &str, account: &str) -> Result<CredentialMetadata> {
        self.get_with_metadata(service, account)
            .map(|(_, metadata)| metadata)
    }

    /// Replace a credential's eviction deadline without changing its secret.
    pub fn update_eviction(
        &self,
        service: &str,
        account: &str,
        evict_at: Option<u64>,
    ) -> Result<()> {
        let secret = self.get(service, account)?;
        self.set_with_options(service, account, &secret, CredentialOptions { evict_at })
    }

    /// Store or replace a secret by stable reference, preserving its metadata.
    pub fn set_by_reference(&self, reference: &SecretReference, secret: &[u8]) -> Result<()> {
        let options = match self.metadata_by_reference(reference) {
            Ok(metadata) => ReferenceOptions {
                evict_at: metadata.evict_at,
                service: metadata.service,
                account: metadata.account,
            },
            Err(Error::NoEntry) => ReferenceOptions::default(),
            Err(error) => return Err(error),
        };
        self.set_by_reference_with_options(reference, secret, options)
    }

    /// Store or replace a secret and its optional keyring metadata by reference.
    pub fn set_by_reference_with_options(
        &self,
        reference: &SecretReference,
        secret: &[u8],
        options: ReferenceOptions,
    ) -> Result<()> {
        validate_reference(reference)?;
        validate_reference_options(&options)?;
        let ReferenceOptions {
            evict_at,
            service,
            account,
        } = options;
        let _guard = self
            .reference_index
            .lock()
            .map_err(|_| Error::VaultStatePoisoned)?;
        let mut index = self.read_reference_index()?;
        let previous = match self.read_reference_credential(reference) {
            Ok(value) => Some(value),
            Err(Error::NoEntry) => None,
            Err(error) => return Err(error),
        };
        self.write_reference_credential(reference, secret, evict_at)?;

        let changed = set_reference_metadata(
            &mut index,
            reference,
            service.as_deref(),
            account.as_deref(),
        );
        if changed {
            if let Err(error) = self.write_reference_index(&index) {
                restore_reference_entry(self, reference, previous.as_ref())?;
                return Err(error);
            }
        }
        Ok(())
    }

    /// Retrieve a secret by stable reference.
    pub fn get_by_reference(&self, reference: &SecretReference) -> Result<Zeroizing<Vec<u8>>> {
        self.get_by_reference_with_metadata(reference)
            .map(|(secret, _)| secret)
    }

    /// Retrieve a referenced secret and its authenticated metadata.
    pub fn get_by_reference_with_metadata(
        &self,
        reference: &SecretReference,
    ) -> Result<(Zeroizing<Vec<u8>>, CredentialMetadata)> {
        validate_reference(reference)?;
        let (secret, entry_metadata, _) = match self.read_reference_credential(reference) {
            Ok(value) => value,
            Err(Error::NoEntry) => {
                self.remove_reference_metadata(reference)?;
                return Err(Error::NoEntry);
            }
            Err(error) => return Err(error),
        };
        let _guard = self
            .reference_index
            .lock()
            .map_err(|_| Error::VaultStatePoisoned)?;
        let index = self.read_reference_index()?;
        let metadata = index
            .entries
            .iter()
            .find(|entry| entry.reference == *reference);
        Ok((
            secret,
            CredentialMetadata {
                evict_at: entry_metadata.evict_at,
                service: metadata.map(|entry| entry.service.clone()),
                account: metadata.map(|entry| entry.account.clone()),
            },
        ))
    }

    /// Retrieve metadata for a referenced secret without returning its value.
    pub fn metadata_by_reference(&self, reference: &SecretReference) -> Result<CredentialMetadata> {
        self.get_by_reference_with_metadata(reference)
            .map(|(_, metadata)| metadata)
    }

    /// Replace a referenced secret's eviction deadline without changing it.
    pub fn update_reference_eviction(
        &self,
        reference: &SecretReference,
        evict_at: Option<u64>,
    ) -> Result<()> {
        let (secret, metadata) = self.get_by_reference_with_metadata(reference)?;
        self.set_by_reference_with_options(
            reference,
            &secret,
            ReferenceOptions {
                evict_at,
                service: metadata.service,
                account: metadata.account,
            },
        )
    }

    /// Resolve keyring metadata to its stable reference.
    ///
    /// A legacy service/account entry is migrated to reference storage when it
    /// is first resolved through this method.
    pub fn resolve_reference(&self, service: &str, account: &str) -> Result<SecretReference> {
        validate_specifiers(service, account)?;
        let _guard = self
            .reference_index
            .lock()
            .map_err(|_| Error::VaultStatePoisoned)?;
        let mut index = self.read_reference_index()?;
        if let Some(reference) = self.live_reference(&mut index, service, account)? {
            return Ok(reference);
        }

        let (secret, metadata, legacy_path) = self.read_legacy_credential(service, account)?;
        let reference = self.new_random_reference()?;
        self.write_reference_credential(&reference, &secret, metadata.evict_at)?;
        set_reference_metadata(&mut index, &reference, Some(service), Some(account));
        if let Err(error) = self.write_reference_index(&index) {
            remove_entry_if_present(&self.reference_entry_path(&reference))?;
            return Err(error);
        }
        remove_entry_if_present(&legacy_path)?;
        Ok(reference)
    }

    /// Change optional keyring metadata without changing reference identity.
    pub fn update_reference_keyring_metadata(
        &self,
        reference: &SecretReference,
        service: Option<&str>,
        account: Option<&str>,
    ) -> Result<()> {
        validate_reference(reference)?;
        validate_keyring_metadata(service, account)?;
        let _guard = self
            .reference_index
            .lock()
            .map_err(|_| Error::VaultStatePoisoned)?;
        self.read_reference_credential(reference)?;
        let mut index = self.read_reference_index()?;
        if set_reference_metadata(&mut index, reference, service, account) {
            self.write_reference_index(&index)?;
        }
        Ok(())
    }

    fn read_legacy_credential(
        &self,
        service: &str,
        account: &str,
    ) -> Result<(Zeroizing<Vec<u8>>, EntryMetadata, PathBuf)> {
        let path = self.legacy_entry_path(service, account);
        let encoded = match read_limited(&path, MAX_ENTRY_BYTES) {
            Ok(value) => value,
            Err(Error::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Err(Error::NoEntry);
            }
            Err(error) => return Err(error),
        };
        let entry: EncryptedFile = deserialize(&encoded, &path).map_err(|_| Error::InvalidEntry)?;
        let plaintext = self.with_key(|key| match entry.version {
            LEGACY_ENTRY_VERSION => entry.decrypt(
                ENTRY_FORMAT,
                LEGACY_ENTRY_VERSION,
                key,
                &entry_aad(&self.vault_id, service, account),
            ),
            ENTRY_VERSION => entry.decrypt(
                ENTRY_FORMAT,
                ENTRY_VERSION,
                key,
                &entry_encryption_aad(&self.vault_id, service, account, ENTRY_VERSION),
            ),
            _ => Err(Error::InvalidEntry),
        })?;
        if entry.version == LEGACY_ENTRY_VERSION {
            return Ok((plaintext, EntryMetadata::default(), path));
        }
        let (secret, metadata) = decode_entry_payload(plaintext)?;
        evict_if_expired(secret, metadata, path)
    }

    fn read_reference_credential(
        &self,
        reference: &SecretReference,
    ) -> Result<(Zeroizing<Vec<u8>>, EntryMetadata, PathBuf)> {
        validate_reference(reference)?;
        let path = self.reference_entry_path(reference);
        let encoded = match read_limited(&path, MAX_ENTRY_BYTES) {
            Ok(value) => value,
            Err(Error::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Err(Error::NoEntry);
            }
            Err(error) => return Err(error),
        };
        let entry: EncryptedFile = deserialize(&encoded, &path).map_err(|_| Error::InvalidEntry)?;
        let plaintext = self.with_key(|key| {
            entry.decrypt(
                ENTRY_FORMAT,
                REFERENCE_ENTRY_VERSION,
                key,
                &reference_entry_encryption_aad(&self.vault_id, reference, REFERENCE_ENTRY_VERSION),
            )
        })?;
        let (secret, metadata) = decode_entry_payload(plaintext)?;
        evict_if_expired(secret, metadata, path)
    }

    fn write_reference_credential(
        &self,
        reference: &SecretReference,
        secret: &[u8],
        evict_at: Option<u64>,
    ) -> Result<()> {
        validate_reference(reference)?;
        let path = self.reference_entry_path(reference);
        let plaintext = encode_entry_payload(secret, evict_at);
        let aad =
            reference_entry_encryption_aad(&self.vault_id, reference, REFERENCE_ENTRY_VERSION);
        let entry = self.with_key(|key| {
            EncryptedFile::encrypt(ENTRY_FORMAT, REFERENCE_ENTRY_VERSION, key, &aad, &plaintext)
        })?;
        atomic_write(&path, &serialize(&entry, &path)?)
    }

    fn set_keyring_credential(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
        options: Option<CredentialOptions>,
    ) -> Result<()> {
        validate_specifiers(service, account)?;
        let _guard = self
            .reference_index
            .lock()
            .map_err(|_| Error::VaultStatePoisoned)?;
        let mut index = self.read_reference_index()?;
        if let Some(reference) = self.live_reference(&mut index, service, account)? {
            let evict_at = match options {
                Some(options) => options.evict_at,
                None => self.read_reference_credential(&reference)?.1.evict_at,
            };
            return self.write_reference_credential(&reference, secret, evict_at);
        }

        let legacy = match self.read_legacy_credential(service, account) {
            Ok(value) => Some(value),
            Err(Error::NoEntry) => None,
            Err(error) => return Err(error),
        };
        let evict_at = options.map_or_else(
            || {
                legacy
                    .as_ref()
                    .and_then(|(_, metadata, _)| metadata.evict_at)
            },
            |options| options.evict_at,
        );
        let reference = self.new_random_reference()?;
        self.write_reference_credential(&reference, secret, evict_at)?;
        set_reference_metadata(&mut index, &reference, Some(service), Some(account));
        if let Err(error) = self.write_reference_index(&index) {
            remove_entry_if_present(&self.reference_entry_path(&reference))?;
            return Err(error);
        }
        if let Some((_, _, path)) = legacy {
            remove_entry_if_present(&path)?;
        }
        Ok(())
    }

    fn live_reference(
        &self,
        index: &mut ReferenceIndex,
        service: &str,
        account: &str,
    ) -> Result<Option<SecretReference>> {
        let mut changed = false;
        loop {
            let candidate = index
                .entries
                .iter()
                .rev()
                .find(|entry| entry.service == service && entry.account == account)
                .map(|entry| entry.reference.clone());
            let Some(reference) = candidate else {
                if changed {
                    self.write_reference_index(index)?;
                }
                return Ok(None);
            };
            match self.read_reference_credential(&reference) {
                Ok(_) => {
                    if changed {
                        self.write_reference_index(index)?;
                    }
                    return Ok(Some(reference));
                }
                Err(Error::NoEntry) => {
                    index.entries.retain(|entry| entry.reference != reference);
                    changed = true;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn new_random_reference(&self) -> Result<SecretReference> {
        for _ in 0..4 {
            let mut bytes = [0_u8; 16];
            getrandom::fill(&mut bytes)?;
            let reference = SecretReference::new(encode(&bytes))?;
            if !self.reference_entry_path(&reference).exists() {
                return Ok(reference);
            }
        }
        Err(Error::Random(
            "could not allocate a unique secret reference".to_owned(),
        ))
    }

    /// Delete one credential.
    pub fn delete(&self, service: &str, account: &str) -> Result<()> {
        validate_specifiers(service, account)?;
        let _guard = self
            .reference_index
            .lock()
            .map_err(|_| Error::VaultStatePoisoned)?;
        let mut index = self.read_reference_index()?;
        if let Some(reference) = self.live_reference(&mut index, service, account)? {
            return self.delete_reference_locked(&reference, &mut index);
        }
        remove_entry(&self.legacy_entry_path(service, account))
    }

    /// Delete a secret by stable reference.
    pub fn delete_by_reference(&self, reference: &SecretReference) -> Result<()> {
        validate_reference(reference)?;
        let _guard = self
            .reference_index
            .lock()
            .map_err(|_| Error::VaultStatePoisoned)?;
        let mut index = self.read_reference_index()?;
        self.delete_reference_locked(reference, &mut index)
    }

    fn delete_reference_locked(
        &self,
        reference: &SecretReference,
        index: &mut ReferenceIndex,
    ) -> Result<()> {
        let previous = self.read_reference_credential(reference)?;
        remove_entry(&previous.2)?;
        let before = index.entries.len();
        let original = index.clone();
        index.entries.retain(|entry| entry.reference != *reference);
        if index.entries.len() == before {
            return Ok(());
        }
        if let Err(error) = self.write_reference_index(index) {
            self.write_reference_credential(reference, &previous.0, previous.1.evict_at)?;
            *index = original;
            return Err(error);
        }
        Ok(())
    }

    /// Test whether a non-expired credential exists.
    pub fn contains(&self, service: &str, account: &str) -> Result<bool> {
        match self.metadata(service, account) {
            Ok(_) => Ok(true),
            Err(Error::NoEntry) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Test whether a non-expired referenced secret exists.
    pub fn contains_reference(&self, reference: &SecretReference) -> Result<bool> {
        match self.metadata_by_reference(reference) {
            Ok(_) => Ok(true),
            Err(Error::NoEntry) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn remove_reference_metadata(&self, reference: &SecretReference) -> Result<()> {
        let _guard = self
            .reference_index
            .lock()
            .map_err(|_| Error::VaultStatePoisoned)?;
        let mut index = self.read_reference_index()?;
        let before = index.entries.len();
        index.entries.retain(|entry| entry.reference != *reference);
        if index.entries.len() != before {
            self.write_reference_index(&index)?;
        }
        Ok(())
    }

    fn read_reference_index(&self) -> Result<ReferenceIndex> {
        let path = self.root.join(REFERENCE_INDEX_FILE);
        let encoded = match read_limited(&path, MAX_REFERENCE_INDEX_BYTES) {
            Ok(value) => value,
            Err(Error::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(ReferenceIndex::default());
            }
            Err(error) => return Err(error),
        };
        let encrypted: EncryptedFile =
            deserialize(&encoded, &path).map_err(|_| Error::InvalidEntry)?;
        let plaintext = self.with_key(|key| {
            encrypted.decrypt(
                REFERENCE_INDEX_FORMAT,
                REFERENCE_INDEX_VERSION,
                key,
                &reference_index_aad(&self.vault_id),
            )
        })?;
        let index: ReferenceIndex =
            serde_json::from_slice(&plaintext).map_err(|_| Error::InvalidEntry)?;
        validate_reference_index(&index)?;
        Ok(index)
    }

    fn write_reference_index(&self, index: &ReferenceIndex) -> Result<()> {
        validate_reference_index(index)?;
        let path = self.root.join(REFERENCE_INDEX_FILE);
        let plaintext = serialize(index, &path)?;
        let encrypted = self.with_key(|key| {
            EncryptedFile::encrypt(
                REFERENCE_INDEX_FORMAT,
                REFERENCE_INDEX_VERSION,
                key,
                &reference_index_aad(&self.vault_id),
                &plaintext,
            )
        })?;
        atomic_write(&path, &serialize(&encrypted, &path)?)
    }

    fn reference_entry_path(&self, reference: &SecretReference) -> PathBuf {
        let mut hash = Sha256::new();
        hash.update(reference_entry_aad(&self.vault_id, reference));
        self.root
            .join(ENTRIES_DIRECTORY)
            .join(format!("{}.fseal", hex::encode(hash.finalize())))
    }

    fn legacy_entry_path(&self, service: &str, account: &str) -> PathBuf {
        let mut hash = Sha256::new();
        hash.update(entry_aad(&self.vault_id, service, account));
        self.root
            .join(ENTRIES_DIRECTORY)
            .join(format!("{}.fseal", hex::encode(hash.finalize())))
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
        let index: EncryptedFile = deserialize(&encoded, &path).map_err(|_| Error::InvalidEntry)?;
        let plaintext = self.with_key(|key| {
            index.decrypt(
                SECRET_SERVICE_INDEX_FORMAT,
                SECRET_SERVICE_INDEX_VERSION,
                key,
                &secret_service_index_aad(&self.vault_id),
            )
        })?;
        Ok(Some(plaintext))
    }

    #[cfg(all(target_os = "linux", feature = "secret-service"))]
    pub(crate) fn write_secret_service_index(&self, plaintext: &[u8]) -> Result<()> {
        let index = self.with_key(|key| {
            EncryptedFile::encrypt(
                SECRET_SERVICE_INDEX_FORMAT,
                SECRET_SERVICE_INDEX_VERSION,
                key,
                &secret_service_index_aad(&self.vault_id),
                plaintext,
            )
        })?;
        let path = self.root.join(SECRET_SERVICE_INDEX_FILE);
        atomic_write(&path, &serialize(&index, &path)?)
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
    Ok(UnlockedVault::new(path, vault_id, vault_key))
}

#[cfg(all(feature = "hardware", feature = "yubikey"))]
fn create_hardware_yubikey_vault(path: &Path, pin: &[u8]) -> Result<UnlockedVault> {
    let (vault_id, vault_key) = prepare_new_vault(path)?;
    let label = key_label(&vault_id);
    let protector = PlatformProtector::open(path, &label)?;

    let mut yubikey_share = Zeroizing::new([0_u8; KEY_BYTES]);
    getrandom::fill(&mut *yubikey_share)?;
    let platform_share = crypto::xor_keys(&vault_key, &yubikey_share);
    let enrolled = crate::yubikey_factor::enroll(&vault_id, pin, &yubikey_share)?;
    let wrapped_platform_share = protector.wrap(&*platform_share)?;

    let config = VaultConfig::hardware_yubikey(
        encode(&vault_id),
        protector.backend(),
        label,
        &wrapped_platform_share,
        &enrolled,
    );
    write_initial_config(path, &config)?;
    Ok(UnlockedVault::new(path, vault_id, vault_key))
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
    Ok(VaultConfig::hardware(
        encode(vault_id),
        protector.backend(),
        label,
        &wrapped_key,
    ))
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
                if yubikey.algorithm != YUBIKEY_ALGORITHM {
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
                crypto::xor_keys(&platform_share, &yubikey_share)
            }
            #[cfg(not(feature = "yubikey"))]
            {
                let _ = (pin, platform_share, yubikey);
                return Err(Error::YubiKeyFeatureDisabled);
            }
        }
    };

    Ok(UnlockedVault::new(path, vault_id, key))
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
    let (wrapped_platform_share, enrolled) = session.with_key(|key| {
        if *current_key != *key {
            return Err(Error::Authentication);
        }
        let mut yubikey_share = Zeroizing::new([0_u8; KEY_BYTES]);
        getrandom::fill(&mut *yubikey_share)?;
        let platform_share = crypto::xor_keys(key, &yubikey_share);
        let enrolled = crate::yubikey_factor::enroll(&session.vault_id, pin, &yubikey_share)?;
        let wrapped_platform_share = protector.wrap(&*platform_share)?;
        Ok((wrapped_platform_share, enrolled))
    })?;

    let updated = VaultConfig::hardware_yubikey(
        config.vault_id,
        protector.backend(),
        key_label.clone(),
        &wrapped_platform_share,
        &enrolled,
    );
    write_config(path, &updated)
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

#[cfg(any(feature = "password", feature = "yubikey"))]
fn write_config(path: &Path, config: &VaultConfig) -> Result<()> {
    let config_path = path.join(CONFIG_FILE);
    atomic_write(&config_path, &serialize(config, &config_path)?)
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
    getrandom::fill(&mut salt)?;
    let kdf = default_argon2_config();
    let password_key = derive_password_key(password, &salt, &kdf)?;
    let encrypted = crypto::encrypt(&password_key, &vault_key_aad(vault_id), vault_key)?;
    Ok(VaultConfig {
        format: VAULT_FORMAT.to_owned(),
        version: PASSWORD_VAULT_VERSION,
        vault_id: encode(vault_id),
        unlock: UnlockConfig::Password {
            kdf,
            salt: encode(&salt),
            nonce: encode(&encrypted.nonce),
            wrapped_key: encode(&encrypted.ciphertext),
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
    let key = crypto::decrypt(
        &password_key,
        &nonce,
        &vault_key_aad(vault_id),
        &wrapped_key,
    )
    .map_err(|_| Error::UnlockFailed)?;
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

pub(crate) fn validate_specifiers(service: &str, account: &str) -> Result<()> {
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

fn validate_reference(reference: &SecretReference) -> Result<()> {
    if reference.item.is_empty() {
        return Err(Error::EmptyReferenceItem);
    }
    if reference.item.len() > MAX_NAME_BYTES {
        return Err(Error::CredentialNameTooLong {
            field: "item",
            maximum: MAX_NAME_BYTES,
        });
    }
    if let Some(field) = &reference.field {
        if field.is_empty() {
            return Err(Error::EmptyReferenceField);
        }
        if field.len() > MAX_NAME_BYTES {
            return Err(Error::CredentialNameTooLong {
                field: "field",
                maximum: MAX_NAME_BYTES,
            });
        }
    }
    Ok(())
}

fn validate_reference_options(options: &ReferenceOptions) -> Result<()> {
    validate_keyring_metadata(options.service.as_deref(), options.account.as_deref())
}

fn validate_keyring_metadata(service: Option<&str>, account: Option<&str>) -> Result<()> {
    match (service, account) {
        (Some(service), Some(account)) => validate_specifiers(service, account),
        (None, None) => Ok(()),
        _ => Err(Error::InvalidMetadata(
            "reference service and account must be supplied together".to_owned(),
        )),
    }
}

fn validate_reference_index(index: &ReferenceIndex) -> Result<()> {
    if index.format != REFERENCE_INDEX_FORMAT || index.version != REFERENCE_INDEX_VERSION {
        return Err(Error::InvalidMetadata(
            "unsupported reference index format or version".to_owned(),
        ));
    }
    for entry in &index.entries {
        validate_reference(&entry.reference)?;
        validate_specifiers(&entry.service, &entry.account)?;
    }
    Ok(())
}

fn set_reference_metadata(
    index: &mut ReferenceIndex,
    reference: &SecretReference,
    service: Option<&str>,
    account: Option<&str>,
) -> bool {
    let before = index.entries.clone();
    index.entries.retain(|entry| entry.reference != *reference);
    if let (Some(service), Some(account)) = (service, account) {
        index.entries.push(ReferenceIndexEntry {
            reference: reference.clone(),
            service: service.to_owned(),
            account: account.to_owned(),
        });
    }
    index.entries != before
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

fn entry_encryption_aad(
    vault_id: &[u8; VAULT_ID_BYTES],
    service: &str,
    account: &str,
    version: u32,
) -> Vec<u8> {
    let mut aad = entry_aad(vault_id, service, account);
    aad.extend_from_slice(&version.to_be_bytes());
    aad
}

fn reference_entry_aad(vault_id: &[u8; VAULT_ID_BYTES], reference: &SecretReference) -> Vec<u8> {
    let mut aad = b"factorseal/reference-entry/v1\0".to_vec();
    aad.extend_from_slice(vault_id);
    append_length_prefixed(&mut aad, reference.item.as_bytes());
    match &reference.field {
        Some(field) => {
            aad.push(1);
            append_length_prefixed(&mut aad, field.as_bytes());
        }
        None => aad.push(0),
    }
    aad
}

fn reference_entry_encryption_aad(
    vault_id: &[u8; VAULT_ID_BYTES],
    reference: &SecretReference,
    version: u32,
) -> Vec<u8> {
    let mut aad = reference_entry_aad(vault_id, reference);
    aad.extend_from_slice(&version.to_be_bytes());
    aad
}

fn reference_index_aad(vault_id: &[u8; VAULT_ID_BYTES]) -> Vec<u8> {
    let mut aad = b"factorseal/reference-index/v1\0".to_vec();
    aad.extend_from_slice(vault_id);
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

fn unix_time() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Error::InvalidEvictionTime)
}

fn encode_entry_payload(secret: &[u8], evict_at: Option<u64>) -> Zeroizing<Vec<u8>> {
    let metadata_bytes = if evict_at.is_some() {
        ENTRY_PAYLOAD_EVICT_AT_BYTES
    } else {
        1
    };
    let mut payload = Zeroizing::new(Vec::with_capacity(metadata_bytes + secret.len()));
    if let Some(evict_at) = evict_at {
        payload.push(ENTRY_PAYLOAD_EVICT_AT);
        payload.extend_from_slice(&evict_at.to_be_bytes());
    } else {
        payload.push(ENTRY_PAYLOAD_NO_EVICTION);
    }
    payload.extend_from_slice(secret);
    payload
}

fn decode_entry_payload(
    mut payload: Zeroizing<Vec<u8>>,
) -> Result<(Zeroizing<Vec<u8>>, EntryMetadata)> {
    let (metadata_bytes, evict_at) = match payload.first() {
        Some(&ENTRY_PAYLOAD_NO_EVICTION) => (1, None),
        Some(&ENTRY_PAYLOAD_EVICT_AT) if payload.len() >= ENTRY_PAYLOAD_EVICT_AT_BYTES => {
            let deadline: [u8; size_of::<u64>()] = payload[1..ENTRY_PAYLOAD_EVICT_AT_BYTES]
                .try_into()
                .map_err(|_| Error::InvalidEntry)?;
            (
                ENTRY_PAYLOAD_EVICT_AT_BYTES,
                Some(u64::from_be_bytes(deadline)),
            )
        }
        _ => return Err(Error::InvalidEntry),
    };
    payload.drain(..metadata_bytes);
    Ok((payload, EntryMetadata { evict_at }))
}

fn evict_if_expired(
    secret: Zeroizing<Vec<u8>>,
    metadata: EntryMetadata,
    path: PathBuf,
) -> Result<(Zeroizing<Vec<u8>>, EntryMetadata, PathBuf)> {
    if let Some(deadline) = metadata.evict_at {
        if deadline <= unix_time()? {
            drop(secret);
            remove_expired_entry(&path)?;
            return Err(Error::NoEntry);
        }
    }
    Ok((secret, metadata, path))
}

fn remove_expired_entry(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::Io {
            path: path.to_owned(),
            source,
        }),
    }
}

fn remove_entry(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Err(Error::NoEntry),
        Err(source) => Err(Error::Io {
            path: path.to_owned(),
            source,
        }),
    }
}

fn remove_entry_if_present(path: &Path) -> Result<()> {
    match remove_entry(path) {
        Ok(()) | Err(Error::NoEntry) => Ok(()),
        Err(error) => Err(error),
    }
}

fn restore_reference_entry(
    vault: &UnlockedVault,
    reference: &SecretReference,
    previous: Option<&(Zeroizing<Vec<u8>>, EntryMetadata, PathBuf)>,
) -> Result<()> {
    if let Some((secret, metadata, _)) = previous {
        vault.write_reference_credential(reference, secret, metadata.evict_at)
    } else {
        remove_entry_if_present(&vault.reference_entry_path(reference))
    }
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
        UnlockedVault::new(path, vault_id, key)
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
    fn item_and_field_are_stable_reference_coordinates() {
        let (_directory, _path, vault) = vault();
        let item = SecretReference::new("database").unwrap();
        let username = SecretReference::with_field("database", "username").unwrap();
        let password = SecretReference::with_field("database", "password").unwrap();

        vault.set_by_reference(&item, b"document").unwrap();
        vault.set_by_reference(&username, b"alice").unwrap();
        vault.set_by_reference(&password, b"hunter2").unwrap();

        assert_eq!(
            vault.get_by_reference(&item).unwrap().as_slice(),
            b"document"
        );
        assert_eq!(
            vault.get_by_reference(&username).unwrap().as_slice(),
            b"alice"
        );
        assert_eq!(
            vault.get_by_reference(&password).unwrap().as_slice(),
            b"hunter2"
        );
        assert_ne!(
            vault.reference_entry_path(&item),
            vault.reference_entry_path(&username)
        );
        assert_ne!(
            vault.reference_entry_path(&username),
            vault.reference_entry_path(&password)
        );
    }

    #[test]
    fn keyring_metadata_can_change_without_changing_reference_identity() {
        let (_directory, _path, vault) = vault();
        let reference = SecretReference::with_field("database", "password").unwrap();
        vault
            .set_by_reference_with_options(
                &reference,
                b"secret",
                ReferenceOptions {
                    evict_at: None,
                    service: Some("old-service".to_owned()),
                    account: Some("old-account".to_owned()),
                },
            )
            .unwrap();
        let path = vault.reference_entry_path(&reference);

        vault
            .update_reference_keyring_metadata(&reference, Some("new-service"), Some("new-account"))
            .unwrap();

        assert_eq!(
            vault.get("new-service", "new-account").unwrap().as_slice(),
            b"secret"
        );
        assert!(matches!(
            vault.get("old-service", "old-account"),
            Err(Error::NoEntry)
        ));
        assert_eq!(vault.reference_entry_path(&reference), path);
        assert_eq!(
            vault.metadata_by_reference(&reference).unwrap(),
            CredentialMetadata {
                evict_at: None,
                service: Some("new-service".to_owned()),
                account: Some("new-account".to_owned()),
            }
        );
    }

    #[test]
    fn duplicate_keyring_metadata_resolves_to_the_latest_live_reference() {
        let (_directory, _path, vault) = vault();
        let first = SecretReference::new("first").unwrap();
        let second = SecretReference::new("second").unwrap();
        let options = || ReferenceOptions {
            evict_at: None,
            service: Some("service".to_owned()),
            account: Some("account".to_owned()),
        };
        vault
            .set_by_reference_with_options(&first, b"first", options())
            .unwrap();
        vault
            .set_by_reference_with_options(&second, b"second", options())
            .unwrap();

        assert_eq!(
            vault.get("service", "account").unwrap().as_slice(),
            b"second"
        );
        vault.delete_by_reference(&second).unwrap();
        assert_eq!(
            vault.get("service", "account").unwrap().as_slice(),
            b"first"
        );
    }

    #[test]
    fn keyring_metadata_index_is_encrypted() {
        let (_directory, _path, vault) = vault();
        let reference = SecretReference::new("opaque-item").unwrap();
        vault
            .set_by_reference_with_options(
                &reference,
                b"secret",
                ReferenceOptions {
                    evict_at: None,
                    service: Some("metadata-service-marker".to_owned()),
                    account: Some("metadata-account-marker".to_owned()),
                },
            )
            .unwrap();

        let stored = fs::read(vault.path().join(REFERENCE_INDEX_FILE)).unwrap();
        for marker in [
            b"metadata-service-marker".as_slice(),
            b"metadata-account-marker".as_slice(),
            b"opaque-item".as_slice(),
        ] {
            assert!(!stored.windows(marker.len()).any(|window| window == marker));
        }
    }

    #[test]
    fn entry_names_are_authenticated() {
        let (_directory, _path, vault) = vault();
        let first_reference = SecretReference::new("first").unwrap();
        let second_reference = SecretReference::new("second").unwrap();
        vault.set_by_reference(&first_reference, b"secret").unwrap();
        let first = vault.reference_entry_path(&first_reference);
        let second = vault.reference_entry_path(&second_reference);
        fs::copy(first, second).unwrap();

        assert!(matches!(
            vault.get_by_reference(&second_reference),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn encrypted_entry_envelope_is_validated() {
        let (_directory, _path, vault) = vault();
        let reference = SecretReference::new("item").unwrap();
        vault.set_by_reference(&reference, b"secret").unwrap();
        let path = vault.reference_entry_path(&reference);
        let mut entry: EncryptedFile = deserialize(&fs::read(&path).unwrap(), &path).unwrap();
        entry.version += 1;
        fs::write(&path, serialize(&entry, &path).unwrap()).unwrap();

        assert!(matches!(
            vault.get_by_reference(&reference),
            Err(Error::InvalidEntry)
        ));
    }

    #[test]
    fn legacy_entries_remain_readable() {
        let (_directory, _vault_path, vault) = vault();
        let service = "legacy";
        let account = "entry";
        let path = vault.legacy_entry_path(service, account);
        let aad = entry_aad(&vault.vault_id, service, account);
        let entry = vault
            .with_key(|key| {
                EncryptedFile::encrypt(
                    ENTRY_FORMAT,
                    LEGACY_ENTRY_VERSION,
                    key,
                    &aad,
                    b"legacy secret",
                )
            })
            .unwrap();
        atomic_write(&path, &serialize(&entry, &path).unwrap()).unwrap();

        assert_eq!(
            vault.get(service, account).unwrap().as_slice(),
            b"legacy secret"
        );
        assert_eq!(
            vault.metadata(service, account).unwrap(),
            CredentialMetadata {
                evict_at: None,
                service: Some(service.to_owned()),
                account: Some(account.to_owned()),
            }
        );
    }

    #[test]
    fn resolving_legacy_keyring_metadata_migrates_to_an_opaque_reference() {
        let (_directory, _vault_path, vault) = vault();
        let service = "legacy-service";
        let account = "legacy-account";
        let legacy_path = vault.legacy_entry_path(service, account);
        let plaintext = encode_entry_payload(b"legacy secret", Some(u64::MAX));
        let aad = entry_encryption_aad(&vault.vault_id, service, account, ENTRY_VERSION);
        let entry = vault
            .with_key(|key| {
                EncryptedFile::encrypt(ENTRY_FORMAT, ENTRY_VERSION, key, &aad, &plaintext)
            })
            .unwrap();
        atomic_write(&legacy_path, &serialize(&entry, &legacy_path).unwrap()).unwrap();

        let reference = vault.resolve_reference(service, account).unwrap();

        assert_ne!(reference.item(), service);
        assert_eq!(reference.field(), None);
        assert!(!legacy_path.exists());
        assert_eq!(
            vault.get_by_reference(&reference).unwrap().as_slice(),
            b"legacy secret"
        );
        assert_eq!(
            vault.metadata_by_reference(&reference).unwrap().evict_at,
            Some(u64::MAX)
        );
    }

    #[test]
    fn expired_credentials_are_evicted() {
        let (_directory, _vault_path, vault) = vault();
        let reference = SecretReference::with_field("database", "password").unwrap();
        vault
            .set_by_reference_with_options(
                &reference,
                b"secret",
                ReferenceOptions {
                    evict_at: Some(0),
                    service: Some("service".to_owned()),
                    account: Some("account".to_owned()),
                },
            )
            .unwrap();
        let path = vault.reference_entry_path(&reference);

        assert!(matches!(
            vault.get("service", "account"),
            Err(Error::NoEntry)
        ));
        assert!(!path.exists());
        assert!(!vault.contains("service", "account").unwrap());
        assert!(!vault.contains_reference(&reference).unwrap());
    }

    #[test]
    fn replacing_a_credential_preserves_its_eviction_deadline() {
        let (_directory, _vault_path, vault) = vault();
        vault
            .set_with_options(
                "service",
                "account",
                b"first",
                CredentialOptions {
                    evict_at: Some(u64::MAX),
                },
            )
            .unwrap();

        vault.set("service", "account", b"second").unwrap();

        assert_eq!(
            vault.metadata("service", "account").unwrap().evict_at,
            Some(u64::MAX)
        );
        assert_eq!(
            vault.get("service", "account").unwrap().as_slice(),
            b"second"
        );
    }

    #[test]
    fn locking_a_session_revokes_all_further_access() {
        let (_directory, _vault_path, vault) = vault();
        vault.set("service", "account", b"secret").unwrap();

        vault.lock().unwrap();

        assert!(vault.is_locked().unwrap());
        assert!(matches!(
            vault.get("service", "account"),
            Err(Error::VaultLocked)
        ));
        assert!(matches!(
            vault.set("service", "account", b"replacement"),
            Err(Error::VaultLocked)
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

#[cfg(feature = "key-protection")]
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[cfg(feature = "hardware")]
use crate::hardware::PlatformProtectorFactory;

use super::{DeviceKeyId, VaultError, VaultId, VaultResult};
#[cfg(feature = "key-protection")]
use super::{KeyProtector, KeyProtectorFactory};

mod filesystem;
mod metadata;
#[cfg(feature = "key-protection")]
mod protectors;

#[cfg(feature = "key-protection")]
use filesystem::path_error;
use filesystem::validate_root;
#[cfg(feature = "key-protection")]
use filesystem::{prepare_root, unix_time};
#[cfg(feature = "key-protection")]
use metadata::VAULT_FILE;
use metadata::read_vault;
#[cfg(feature = "key-protection")]
use protectors::{
    LabeledProtector, ProtectorPair, VaultCreation, create_with_protectors, unseal_with_protectors,
};

const KEY_BYTES: usize = 32;
#[cfg(all(test, feature = "key-protection"))]
const TEST_PASSWORD: &[u8] = b"factorseal-test-password";

mod factor;

pub use factor::{NestedFactorKind, UnsealFactor};

/// Public, stable identity of this vault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultMetadata {
    vault_id: VaultId,
    device_key_id: DeviceKeyId,
    public_signing_key: Vec<u8>,
    actor_id: Vec<u8>,
    platform: VaultPlatform,
    hardware_backend: String,
    nested_factor: NestedFactorKind,
    key_epoch: u64,
    created_at: u64,
}

impl VaultMetadata {
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    #[must_use]
    pub const fn device_key_id(&self) -> DeviceKeyId {
        self.device_key_id
    }

    #[must_use]
    pub fn public_signing_key(&self) -> &[u8] {
        &self.public_signing_key
    }

    #[must_use]
    pub fn actor_id(&self) -> &[u8] {
        &self.actor_id
    }

    #[must_use]
    pub fn hardware_backend(&self) -> &str {
        &self.hardware_backend
    }

    /// The nested factor this vault requires in addition to its
    /// platform hardware key. Exactly one is always required.
    #[must_use]
    pub const fn nested_factor(&self) -> NestedFactorKind {
        self.nested_factor
    }

    #[must_use]
    pub const fn platform(&self) -> &'static str {
        self.platform.as_str()
    }

    /// Platform family whose native adapter created this vault.
    #[must_use]
    pub const fn platform_kind(&self) -> VaultPlatform {
        self.platform
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }
}

/// Hardware-unwrapped vault secrets held only during an unseal lease.
#[allow(dead_code)]
pub struct UnsealedVault {
    public: VaultMetadata,
    data_key: Zeroizing<[u8; KEY_BYTES]>,
    signing_seed: Zeroizing<[u8; KEY_BYTES]>,
    initialize_store: bool,
}

impl std::fmt::Debug for UnsealedVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnsealedVault")
            .field("public", &self.public)
            .field("data_key", &"[REDACTED]")
            .field("signing_seed", &"[REDACTED]")
            .field("initialize_store", &self.initialize_store)
            .finish()
    }
}

impl UnsealedVault {
    #[must_use]
    pub const fn public(&self) -> &VaultMetadata {
        &self.public
    }

    #[allow(dead_code)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        VaultMetadata,
        Zeroizing<[u8; KEY_BYTES]>,
        Zeroizing<[u8; KEY_BYTES]>,
        bool,
    ) {
        (
            self.public,
            self.data_key,
            self.signing_seed,
            self.initialize_store,
        )
    }
}

/// Creates and unseals the permanent hardware-bound vault.
pub struct Vault;

impl Vault {
    /// Read and validate public vault metadata without unwrapping any
    /// hardware-protected key material.
    pub fn inspect(root: impl AsRef<Path>) -> VaultResult<VaultMetadata> {
        let root = root.as_ref();
        validate_root(root)?;
        read_vault(root).map(|stored| stored.public())
    }

    /// Delete a vault whose store could never be opened, so initialization can
    /// be retried.
    ///
    /// [`Self::create`] writes `factorseal.json` before the caller can open the
    /// store, and refuses to run again while that file exists, so a store that
    /// fails to open leaves a root that initialization can never complete and
    /// the user cannot recover without deleting keys by hand. Call this only
    /// on the failure path of a `create` the same process just performed: it
    /// destroys the hardware-wrapped keys along with everything they protect.
    #[cfg(feature = "hardware")]
    pub fn discard_initialization(root: impl AsRef<Path>) -> VaultResult<()> {
        discard_initialization_with_factory(root.as_ref(), &PlatformProtectorFactory, true)
    }

    /// Permanently destroy a sealed vault after proving possession of its
    /// nested factor.
    ///
    /// This deletes both native hardware keys and the local vault directory.
    /// Callers must first stop any running vault service; destruction is an
    /// explicit recovery or disposable-test operation, not a substitute for
    /// sealing a live vault.
    #[cfg(feature = "hardware")]
    pub fn destroy(root: impl AsRef<Path>, factor: UnsealFactor<'_>) -> VaultResult<()> {
        let root = root.as_ref();
        // Do not let possession of the local vault directory alone destroy a
        // user's TPM/Secure Enclave keys. A successful unseal also validates
        // the recorded public device identity before anything is deleted.
        let _verified = Self::unseal(root, factor)?;
        Self::discard_initialization(root)
    }

    /// Delete an incomplete vault and its platform keys through an injected
    /// platform adapter.
    #[cfg(feature = "key-protection")]
    pub fn discard_initialization_with_key_protector(
        root: impl AsRef<Path>,
        factory: &dyn KeyProtectorFactory,
    ) -> VaultResult<()> {
        discard_initialization_with_factory(root.as_ref(), factory, false)
    }

    /// Permanently destroy a vault created through an injected key protector.
    ///
    /// This is the portable counterpart of [`Self::destroy`]. The caller must
    /// have stopped every live service using `root` before calling it.
    #[cfg(feature = "key-protection")]
    pub fn destroy_with_key_protector(
        root: impl AsRef<Path>,
        factor: UnsealFactor<'_>,
        factory: &dyn KeyProtectorFactory,
    ) -> VaultResult<()> {
        let root = root.as_ref();
        let _verified = Self::unseal_with_key_protector(root, factor, factory)?;
        discard_initialization_with_factory(root, factory, false)
    }

    /// Create a vault with the native desktop hardware adapter.
    #[cfg(feature = "hardware")]
    pub fn create(
        root: impl AsRef<Path>,
        factor: UnsealFactor<'_>,
        biometric: bool,
    ) -> VaultResult<UnsealedVault> {
        Self::create_with_key_protector(
            root,
            current_platform()?,
            factor,
            biometric,
            &PlatformProtectorFactory,
        )
    }

    /// Create a vault using an injected hardware-key adapter.
    ///
    /// Android and iOS embedders should call this entry point with their
    /// Keystore or Secure Enclave adapter and the matching platform value.
    #[cfg(feature = "key-protection")]
    pub fn create_with_key_protector(
        root: impl AsRef<Path>,
        platform: VaultPlatform,
        factor: UnsealFactor<'_>,
        biometric: bool,
        factory: &dyn KeyProtectorFactory,
    ) -> VaultResult<UnsealedVault> {
        let root = root.as_ref();
        prepare_root(root)?;
        let mut protectors: Vec<Box<dyn KeyProtector>> = Vec::with_capacity(2);
        let result = (|| {
            let vault_id = VaultId::random()?;
            let label_suffix = hex::encode(vault_id.as_bytes());
            let wrapping_label = format!("vault-wrap-{label_suffix}");
            let signing_label = format!("vault-sign-{label_suffix}");
            protectors.push(factory.create(root, &wrapping_label, biometric)?);
            protectors.push(factory.create(root, &signing_label, biometric)?);
            create_with_protectors(
                root,
                VaultCreation {
                    vault_id,
                    biometric,
                    created_at: unix_time()?,
                    platform,
                },
                ProtectorPair {
                    wrapping: LabeledProtector {
                        label: &wrapping_label,
                        key: protectors[0].as_ref(),
                    },
                    signing: LabeledProtector {
                        label: &signing_label,
                        key: protectors[1].as_ref(),
                    },
                },
                factor,
            )
        })();

        match result {
            Ok(unsealed) => Ok(unsealed),
            Err(error) => {
                let mut cleanup_error = None;
                for protector in &protectors {
                    if let Err(cleanup) = protector.delete()
                        && cleanup_error.is_none()
                    {
                        cleanup_error = Some(cleanup.to_string());
                    }
                }
                if let Err(cleanup) = fs::remove_dir_all(root)
                    && cleanup_error.is_none()
                {
                    cleanup_error = Some(cleanup.to_string());
                }
                match cleanup_error {
                    Some(cleanup) => Err(VaultError::Protection(format!(
                        "{error}; initialization rollback failed for `{}`: {cleanup}",
                        root.display()
                    ))),
                    None => Err(error),
                }
            }
        }
    }

    #[cfg(not(feature = "hardware"))]
    pub fn create(
        _root: impl AsRef<Path>,
        _factor: UnsealFactor<'_>,
        _biometric: bool,
    ) -> VaultResult<UnsealedVault> {
        Err(VaultError::Protection(
            "this build does not include the native desktop hardware adapter; use an injected key protector".to_owned(),
        ))
    }

    /// Reopen the existing vault with its mandatory Factorseal password
    /// and require the recorded hardware backend and public signing identity
    /// to match.
    #[cfg(feature = "hardware")]
    pub fn unseal(root: impl AsRef<Path>, factor: UnsealFactor<'_>) -> VaultResult<UnsealedVault> {
        Self::unseal_with_key_protector(root, factor, &PlatformProtectorFactory)
    }

    /// Reopen a vault through an injected platform key adapter.
    #[cfg(feature = "key-protection")]
    pub fn unseal_with_key_protector(
        root: impl AsRef<Path>,
        factor: UnsealFactor<'_>,
        factory: &dyn KeyProtectorFactory,
    ) -> VaultResult<UnsealedVault> {
        let root = root.as_ref();
        validate_root(root)?;
        let stored = read_vault(root)?;
        let wrapping = factory.open(root, &stored.wrapping_key_label, stored.biometric)?;
        let signing = factory.open(root, &stored.signing_key_label, stored.biometric)?;
        unseal_with_protectors(&stored, wrapping.as_ref(), signing.as_ref(), factor)
    }

    #[cfg(not(feature = "hardware"))]
    pub fn unseal(
        _root: impl AsRef<Path>,
        _factor: UnsealFactor<'_>,
    ) -> VaultResult<UnsealedVault> {
        Err(VaultError::Protection(
            "this build does not include the native desktop hardware adapter; use an injected key protector".to_owned(),
        ))
    }

    #[cfg(all(test, feature = "key-protection"))]
    pub(crate) fn create_for_test(root: &Path) -> VaultResult<UnsealedVault> {
        use super::protection::TestProtector;

        prepare_root(root)?;
        let wrapping = TestProtector::new([0x35; KEY_BYTES]);
        let signing = TestProtector::new([0x97; KEY_BYTES]);
        create_with_protectors(
            root,
            VaultCreation {
                vault_id: VaultId::random()?,
                biometric: false,
                created_at: 1_700_000_000,
                platform: VaultPlatform::Test,
            },
            ProtectorPair {
                wrapping: LabeledProtector {
                    label: "test-vault-wrap",
                    key: &wrapping,
                },
                signing: LabeledProtector {
                    label: "test-vault-sign",
                    key: &signing,
                },
            },
            UnsealFactor::Password(TEST_PASSWORD),
        )
    }

    #[cfg(all(test, feature = "key-protection"))]
    pub(crate) fn unseal_for_test(root: &Path) -> VaultResult<UnsealedVault> {
        use super::protection::TestProtector;

        validate_root(root)?;
        let stored = read_vault(root)?;
        let wrapping = TestProtector::new([0x35; KEY_BYTES]);
        let signing = TestProtector::new([0x97; KEY_BYTES]);
        unseal_with_protectors(
            &stored,
            &wrapping,
            &signing,
            UnsealFactor::Password(TEST_PASSWORD),
        )
    }
}

#[cfg(feature = "key-protection")]
fn discard_initialization_with_factory(
    root: &Path,
    factory: &dyn KeyProtectorFactory,
    skip_test_keys: bool,
) -> VaultResult<()> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(path_error(root, error)),
    };
    if !metadata.file_type().is_dir() {
        return Err(VaultError::Protection(format!(
            "refusing to discard non-directory vault root `{}`",
            root.display()
        )));
    }

    let mut cleanup_error = None;
    let vault_path = root.join(VAULT_FILE);
    if vault_path.exists() {
        match read_vault(root) {
            Ok(stored) => {
                let delete_keys = {
                    #[cfg(test)]
                    {
                        !skip_test_keys || stored.platform != VaultPlatform::Test
                    }
                    #[cfg(not(test))]
                    {
                        let _ = skip_test_keys;
                        true
                    }
                };
                if delete_keys {
                    for label in [&stored.wrapping_key_label, &stored.signing_key_label] {
                        match factory
                            .open(root, label, stored.biometric)
                            .and_then(|protector| protector.delete())
                        {
                            Err(error) if cleanup_error.is_none() => {
                                cleanup_error = Some(error);
                            }
                            Ok(()) | Err(_) => {}
                        }
                    }
                }
            }
            Err(error) => cleanup_error = Some(error),
        }
    }

    if let Err(error) = fs::remove_dir_all(root)
        && cleanup_error.is_none()
    {
        cleanup_error = Some(path_error(root, error));
    }
    cleanup_error.map_or(Ok(()), Err)
}

/// Operating-system family whose native key adapter created a vault.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum VaultPlatform {
    Android,
    Ios,
    Linux,
    Macos,
    Windows,
    #[cfg(test)]
    Test,
}

impl VaultPlatform {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
            #[cfg(test)]
            Self::Test => "test",
        }
    }
}

#[cfg(feature = "hardware")]
fn current_platform() -> VaultResult<VaultPlatform> {
    #[cfg(target_os = "linux")]
    return Ok(VaultPlatform::Linux);
    #[cfg(target_os = "macos")]
    return Ok(VaultPlatform::Macos);
    #[cfg(target_os = "windows")]
    return Ok(VaultPlatform::Windows);
    #[allow(unreachable_code)]
    Err(VaultError::Protection(
        "this platform is not a first-release target".to_owned(),
    ))
}

#[cfg(all(test, feature = "key-protection"))]
mod tests;

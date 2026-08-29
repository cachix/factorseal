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
use metadata::{PENDING_VAULT_FILE, VAULT_FILE};
use metadata::{read_pending_vault, read_vault};
#[cfg(feature = "key-protection")]
use protectors::{
    LabeledProtector, SlotProtectors, VaultCreation, create_with_protectors, unseal_with_protectors,
};

const KEY_BYTES: usize = 32;
#[cfg(all(test, feature = "key-protection"))]
const TEST_PASSWORD: &[u8] = b"factorseal-test-password";

mod factor;
mod policy;

pub use factor::{NestedFactorKind, UnsealFactor};
pub use policy::{UnlockCredentials, UnlockFactorKind, UnlockGroup, UnlockPolicy};

/// Public, stable identity of this vault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultMetadata {
    vault_id: VaultId,
    device_key_id: DeviceKeyId,
    public_signing_key: Vec<u8>,
    actor_id: Vec<u8>,
    platform: VaultPlatform,
    hardware_backend: String,
    unlock_policy: UnlockPolicy,
    preferred_unlock_group: UnlockGroup,
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

    /// Versioned AND/OR policy accepted by this vault.
    #[must_use]
    pub const fn unlock_policy(&self) -> &UnlockPolicy {
        &self.unlock_policy
    }

    /// Unlock group used when a caller does not request one explicitly.
    #[must_use]
    pub const fn preferred_unlock_group(&self) -> &UnlockGroup {
        &self.preferred_unlock_group
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

    /// Sign one agent-issued permission challenge after this vault has been
    /// unsealed with a configured unlock group.
    #[cfg(feature = "vault-store")]
    pub fn sign_permission_challenge(
        &self,
        id: &str,
        challenge: &[u8; 32],
        duration_seconds: Option<u64>,
    ) -> VaultResult<Vec<u8>> {
        super::signature::sign(
            &self.signing_seed,
            &super::signature::permission_payload(id, challenge, duration_seconds),
        )
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
    /// Call this only on the failure path of a creation attempt by the same
    /// process. It removes staged or published metadata and destroys the
    /// hardware-wrapped keys along with everything they protect.
    #[cfg(feature = "hardware")]
    pub fn discard_initialization(root: impl AsRef<Path>) -> VaultResult<()> {
        discard_initialization_with_factory(root.as_ref(), &PlatformProtectorFactory, true)
    }

    /// Permanently destroy a legacy single-password vault after proving
    /// possession of its password factor.
    ///
    /// This deletes all native hardware keys and the local vault directory.
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

    /// Permanently destroy a native vault after satisfying one unlock group.
    #[cfg(feature = "hardware")]
    pub fn destroy_with_unlock_group(
        root: impl AsRef<Path>,
        group: &UnlockGroup,
        credentials: UnlockCredentials<'_>,
    ) -> VaultResult<()> {
        let root = root.as_ref();
        let _verified = Self::unseal_with_unlock_group(root, group, credentials)?;
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

    /// Portable policy-based counterpart of [`Self::destroy_with_unlock_group`].
    #[cfg(feature = "key-protection")]
    pub fn destroy_with_key_protector_group(
        root: impl AsRef<Path>,
        group: &UnlockGroup,
        credentials: UnlockCredentials<'_>,
        factory: &dyn KeyProtectorFactory,
    ) -> VaultResult<()> {
        let root = root.as_ref();
        let _verified = Self::unseal_with_key_protector_group(root, group, credentials, factory)?;
        discard_initialization_with_factory(root, factory, false)
    }

    /// Create a vault with the native desktop hardware adapter.
    #[cfg(feature = "hardware")]
    pub fn create(
        root: impl AsRef<Path>,
        factor: UnsealFactor<'_>,
        biometric: bool,
    ) -> VaultResult<UnsealedVault> {
        let (policy, credentials) = legacy_policy(factor, biometric)?;
        Self::create_with_unlock_policy(root, &policy, credentials)
    }

    /// Create a native desktop vault with an explicit AND/OR unlock policy.
    #[cfg(feature = "hardware")]
    pub fn create_with_unlock_policy(
        root: impl AsRef<Path>,
        policy: &UnlockPolicy,
        credentials: UnlockCredentials<'_>,
    ) -> VaultResult<UnsealedVault> {
        Self::create_with_key_protector_policy(
            root,
            current_platform()?,
            policy,
            credentials,
            &PlatformProtectorFactory,
        )
    }

    /// Prepare a native desktop vault without publishing its metadata yet.
    ///
    /// The caller must initialize the backing store and then call
    /// [`Self::complete_initialization`]. This lets `factorseal.json` act as an
    /// atomic signal that the entire vault is ready to unseal.
    #[cfg(feature = "hardware")]
    pub fn prepare_with_unlock_policy(
        root: impl AsRef<Path>,
        policy: &UnlockPolicy,
        credentials: UnlockCredentials<'_>,
    ) -> VaultResult<UnsealedVault> {
        Self::create_with_key_protector_policy_mode(
            root,
            current_platform()?,
            policy,
            credentials,
            &PlatformProtectorFactory,
            true,
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
        let (policy, credentials) = legacy_policy(factor, biometric)?;
        Self::create_with_key_protector_policy(root, platform, &policy, credentials, factory)
    }

    /// Create a vault through an injected adapter with an explicit unlock policy.
    #[cfg(feature = "key-protection")]
    pub fn create_with_key_protector_policy(
        root: impl AsRef<Path>,
        platform: VaultPlatform,
        policy: &UnlockPolicy,
        credentials: UnlockCredentials<'_>,
        factory: &dyn KeyProtectorFactory,
    ) -> VaultResult<UnsealedVault> {
        Self::create_with_key_protector_policy_mode(
            root,
            platform,
            policy,
            credentials,
            factory,
            false,
        )
    }

    #[cfg(feature = "key-protection")]
    fn create_with_key_protector_policy_mode(
        root: impl AsRef<Path>,
        platform: VaultPlatform,
        policy: &UnlockPolicy,
        credentials: UnlockCredentials<'_>,
        factory: &dyn KeyProtectorFactory,
        pending: bool,
    ) -> VaultResult<UnsealedVault> {
        let root = root.as_ref();
        prepare_root(root)?;
        policy.validate()?;
        for group in policy.groups() {
            let _ = credentials.password_for(group)?;
        }
        let mut protectors: Vec<Box<dyn KeyProtector>> =
            Vec::with_capacity(policy.groups().len() * 2);
        let result = (|| {
            let vault_id = VaultId::random()?;
            let label_suffix = hex::encode(vault_id.as_bytes());
            let labels: Vec<_> = policy
                .groups()
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    (
                        format!("vault-slot-{index}-wrap-{label_suffix}"),
                        format!("vault-slot-{index}-sign-{label_suffix}"),
                    )
                })
                .collect();
            for (group, (wrapping_label, signing_label)) in policy.groups().iter().zip(&labels) {
                let biometric = group.requires(UnlockFactorKind::Biometric);
                protectors.push(factory.create(root, wrapping_label, biometric)?);
                protectors.push(factory.create(root, signing_label, biometric)?);
            }
            let slot_protectors: Vec<_> = policy
                .groups()
                .iter()
                .zip(&labels)
                .enumerate()
                .map(
                    |(index, (group, (wrapping_label, signing_label)))| SlotProtectors {
                        group,
                        wrapping: LabeledProtector {
                            label: wrapping_label,
                            key: protectors[index * 2].as_ref(),
                        },
                        signing: LabeledProtector {
                            label: signing_label,
                            key: protectors[index * 2 + 1].as_ref(),
                        },
                    },
                )
                .collect();
            create_with_protectors(
                root,
                VaultCreation {
                    vault_id,
                    created_at: unix_time()?,
                    platform,
                },
                policy.clone(),
                &slot_protectors,
                credentials,
                pending,
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

    /// Atomically publish metadata for a vault prepared by
    /// [`Self::prepare_with_unlock_policy`].
    #[cfg(feature = "key-protection")]
    pub fn complete_initialization(root: impl AsRef<Path>) -> VaultResult<()> {
        let root = root.as_ref();
        validate_root(root)?;
        let pending = root.join(PENDING_VAULT_FILE);
        let published = root.join(VAULT_FILE);
        if published.exists() {
            return Err(VaultError::Protection(format!(
                "refusing to replace existing vault metadata `{}`",
                published.display()
            )));
        }
        // Validate the complete staged document before one atomic rename makes
        // it visible to waiting services.
        read_pending_vault(root)?;
        fs::rename(&pending, &published).map_err(|error| path_error(&published, error))
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

    /// Reopen a vault that has exactly one password-containing unlock group.
    ///
    /// Policy-aware callers should use [`Self::unseal_with_unlock_group`].
    #[cfg(feature = "hardware")]
    pub fn unseal(root: impl AsRef<Path>, factor: UnsealFactor<'_>) -> VaultResult<UnsealedVault> {
        let root = root.as_ref();
        let stored = read_vault(root)?;
        let group = single_password_group(&stored)?.clone();
        let credentials = credentials_for_factor(factor);
        Self::unseal_with_unlock_group(root, &group, credentials)
    }

    /// Unseal through one exact configured OR alternative.
    #[cfg(feature = "hardware")]
    pub fn unseal_with_unlock_group(
        root: impl AsRef<Path>,
        group: &UnlockGroup,
        credentials: UnlockCredentials<'_>,
    ) -> VaultResult<UnsealedVault> {
        Self::unseal_with_key_protector_group(root, group, credentials, &PlatformProtectorFactory)
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
        let group = single_password_group(&stored)?.clone();
        Self::unseal_with_key_protector_group(root, &group, credentials_for_factor(factor), factory)
    }

    /// Unseal one exact policy group through an injected platform adapter.
    #[cfg(feature = "key-protection")]
    pub fn unseal_with_key_protector_group(
        root: impl AsRef<Path>,
        group: &UnlockGroup,
        credentials: UnlockCredentials<'_>,
        factory: &dyn KeyProtectorFactory,
    ) -> VaultResult<UnsealedVault> {
        let root = root.as_ref();
        validate_root(root)?;
        let stored = read_vault(root)?;
        group.validate()?;
        let slot = stored
            .unlock_slots
            .iter()
            .find(|slot| &slot.group == group)
            .ok_or_else(|| {
                VaultError::Protection(format!(
                    "the {group} unlock group is not configured for this vault"
                ))
            })?;
        let biometric = group.requires(UnlockFactorKind::Biometric);
        let wrapping = factory.open(root, &slot.wrapping_key_label, biometric)?;
        let signing = factory.open(root, &slot.signing_key_label, biometric)?;
        unseal_with_protectors(
            &stored,
            slot,
            wrapping.as_ref(),
            signing.as_ref(),
            credentials,
        )
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
        let group = UnlockGroup::new([UnlockFactorKind::Password])?;
        let policy = UnlockPolicy::new([group.clone()])?;
        create_with_protectors(
            root,
            VaultCreation {
                vault_id: VaultId::random()?,
                created_at: 1_700_000_000,
                platform: VaultPlatform::Test,
            },
            policy,
            &[SlotProtectors {
                group: &group,
                wrapping: LabeledProtector {
                    label: "test-vault-wrap",
                    key: &wrapping,
                },
                signing: LabeledProtector {
                    label: "test-vault-sign",
                    key: &signing,
                },
            }],
            UnlockCredentials::with_password(TEST_PASSWORD),
            false,
        )
    }

    #[cfg(all(test, feature = "key-protection"))]
    pub(crate) fn unseal_for_test(root: &Path) -> VaultResult<UnsealedVault> {
        use super::protection::TestProtector;

        validate_root(root)?;
        let stored = read_vault(root)?;
        let wrapping = TestProtector::new([0x35; KEY_BYTES]);
        let signing = TestProtector::new([0x97; KEY_BYTES]);
        let slot = stored
            .unlock_slots
            .first()
            .ok_or_else(|| VaultError::Protection("test vault has no unlock slot".to_owned()))?;
        unseal_with_protectors(
            &stored,
            slot,
            &wrapping,
            &signing,
            UnlockCredentials::with_password(TEST_PASSWORD),
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
    let pending_path = root.join(PENDING_VAULT_FILE);
    if vault_path.exists() || pending_path.exists() {
        let stored = if vault_path.exists() {
            read_vault(root)
        } else {
            read_pending_vault(root)
        };
        match stored {
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
                    for slot in &stored.unlock_slots {
                        let biometric = slot.group.requires(UnlockFactorKind::Biometric);
                        for label in [&slot.wrapping_key_label, &slot.signing_key_label] {
                            match factory
                                .open(root, label, biometric)
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

#[cfg(feature = "key-protection")]
fn credentials_for_factor(factor: UnsealFactor<'_>) -> UnlockCredentials<'_> {
    match factor {
        UnsealFactor::Password(password) => UnlockCredentials::with_password(password),
    }
}

#[cfg(feature = "key-protection")]
fn legacy_policy(
    factor: UnsealFactor<'_>,
    biometric: bool,
) -> VaultResult<(UnlockPolicy, UnlockCredentials<'_>)> {
    let mut factors = vec![UnlockFactorKind::Password];
    if biometric {
        factors.push(UnlockFactorKind::Biometric);
    }
    let group = UnlockGroup::new(factors)?;
    Ok((UnlockPolicy::new([group])?, credentials_for_factor(factor)))
}

#[cfg(feature = "key-protection")]
fn single_password_group(stored: &metadata::VaultFile) -> VaultResult<&UnlockGroup> {
    let mut matching = stored
        .unlock_policy
        .groups()
        .iter()
        .filter(|group| group.requires(UnlockFactorKind::Password));
    let group = matching.next().ok_or_else(|| {
        VaultError::Protection(
            "this vault has no password unlock group; select an explicit unlock group".to_owned(),
        )
    })?;
    if matching.next().is_some() {
        return Err(VaultError::Protection(
            "this vault has multiple password unlock groups; select one explicitly".to_owned(),
        ));
    }
    Ok(group)
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

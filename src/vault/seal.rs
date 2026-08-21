use std::fs;
#[cfg(feature = "key-protection")]
use std::fs::OpenOptions;
use std::io::Read;
#[cfg(feature = "key-protection")]
use std::io::Write;
use std::path::Path;
#[cfg(feature = "key-protection")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "key-protection")]
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[cfg(feature = "hardware")]
use crate::hardware::PlatformProtectorFactory;

#[cfg(feature = "key-protection")]
use super::signature::{SIGNING_SEED_BYTES, public_key_for_seed};
use super::{DeviceKeyId, VaultError, VaultId, VaultResult};
#[cfg(feature = "key-protection")]
use super::{KeyProtector, KeyProtectorFactory};

const VAULT_FILE: &str = "factorseal.json";
const VAULT_FORMAT: &str = "factorseal-vault";
// Version 2 replaces the quantum-vulnerable Ed25519 device identity with an
// ML-DSA-65 identity. There are no released vaults to migrate.
const VAULT_VERSION: u32 = 2;
const MAX_VAULT_FILE_BYTES: u64 = 1024 * 1024;
const KEY_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const FACTOR_NONCE_BYTES: usize = 24;
#[cfg(all(feature = "key-protection", not(test)))]
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
#[cfg(all(feature = "key-protection", test))]
const ARGON2_MEMORY_KIB: u32 = 8 * 1024;
#[cfg(all(feature = "key-protection", not(test)))]
const ARGON2_ITERATIONS: u32 = 3;
#[cfg(all(feature = "key-protection", test))]
const ARGON2_ITERATIONS: u32 = 1;
#[cfg(feature = "key-protection")]
const ARGON2_PARALLELISM: u32 = 1;
const MAX_ARGON2_MEMORY_KIB: u32 = 256 * 1024;
const MAX_ARGON2_ITERATIONS: u32 = 10;
const MAX_ARGON2_PARALLELISM: u32 = 16;
#[cfg(all(test, feature = "key-protection"))]
const TEST_PASSWORD: &[u8] = b"factorseal-test-password";
#[cfg(feature = "key-protection")]
type ProtectedKeyPayloads = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, NestedProtection);
#[cfg(feature = "key-protection")]
type UnsealedVaultKeys = (Zeroizing<[u8; KEY_BYTES]>, Zeroizing<[u8; KEY_BYTES]>);

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

    /// Delete an incomplete vault and its platform keys through an injected
    /// platform adapter.
    #[cfg(feature = "key-protection")]
    pub fn discard_initialization_with_key_protector(
        root: impl AsRef<Path>,
        factory: &dyn KeyProtectorFactory,
    ) -> VaultResult<()> {
        discard_initialization_with_factory(root.as_ref(), factory, false)
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
                vault_id,
                &wrapping_label,
                &signing_label,
                protectors[0].as_ref(),
                protectors[1].as_ref(),
                biometric,
                unix_time()?,
                platform,
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
            VaultId::random()?,
            "test-vault-wrap",
            "test-vault-sign",
            &wrapping,
            &signing,
            false,
            1_700_000_000,
            VaultPlatform::Test,
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

/// Parameters of the secret-bearing factor nested inside the platform
/// hardware wrapping.
///
/// Every variant must derive its key from a hash or symmetric primitive.
/// That is what keeps the nested layer standing when the platform wrapping
/// key falls: TPM 2.0 and the Secure Enclave wrap with P-256 on all three
/// targets, so an elliptic-curve factor would add no independent barrier. A
/// password remains entropy-limited: Argon2id raises offline-guessing cost but
/// cannot turn a human-memorable password into a post-quantum-strength factor.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "algorithm", rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
enum FactorParameters {
    Argon2id {
        version: u32,
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        salt: [u8; SALT_BYTES],
    },
}

impl FactorParameters {
    const fn kind(&self) -> NestedFactorKind {
        match self {
            Self::Argon2id { .. } => NestedFactorKind::Argon2idPassword,
        }
    }
}

/// The nested factor recorded for an vault, with the nonces that
/// bind its derived key to the wrapped data key and signing seed.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NestedProtection {
    factor: FactorParameters,
    data_key_nonce: [u8; FACTOR_NONCE_BYTES],
    signing_seed_nonce: [u8; FACTOR_NONCE_BYTES],
}

/// Which nested factor an vault requires in addition to its platform
/// hardware key. Exactly one is always required.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum NestedFactorKind {
    /// An Argon2id-derived Factorseal password.
    Argon2idPassword,
}

impl NestedFactorKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Argon2idPassword => "argon2id-password",
        }
    }
}

impl std::fmt::Display for NestedFactorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The secret material supplied by the caller to satisfy the nested factor.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum UnsealFactor<'a> {
    /// A Factorseal password stretched with Argon2id.
    Password(&'a [u8]),
}

impl UnsealFactor<'_> {
    #[must_use]
    pub const fn kind(&self) -> NestedFactorKind {
        match self {
            Self::Password(_) => NestedFactorKind::Argon2idPassword,
        }
    }
}

impl std::fmt::Debug for UnsealFactor<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnsealFactor")
            .field("kind", &self.kind())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultFile {
    format: String,
    version: u32,
    vault_id: VaultId,
    device_key_id: DeviceKeyId,
    public_signing_key: Vec<u8>,
    actor_id: Vec<u8>,
    platform: VaultPlatform,
    hardware_backend: String,
    wrapping_key_label: String,
    signing_key_label: String,
    wrapped_data_key: Vec<u8>,
    wrapped_signing_seed: Vec<u8>,
    nested_protection: NestedProtection,
    biometric: bool,
    key_epoch: u64,
    created_at: u64,
}

#[cfg(feature = "key-protection")]
#[allow(clippy::too_many_arguments)]
fn create_with_protectors(
    root: &Path,
    vault_id: VaultId,
    wrapping_key_label: &str,
    signing_key_label: &str,
    wrapping: &dyn KeyProtector,
    signing: &dyn KeyProtector,
    biometric: bool,
    created_at: u64,
    platform: VaultPlatform,
    factor: UnsealFactor<'_>,
) -> VaultResult<UnsealedVault> {
    if wrapping_key_label == signing_key_label {
        return Err(VaultError::Protection(
            "wrapping and signing key labels must be distinct".to_owned(),
        ));
    }
    if wrapping.backend() != signing.backend() {
        return Err(VaultError::Protection(
            "wrapping and signing keys use different hardware backends".to_owned(),
        ));
    }
    if !platform_accepts_backend(platform, wrapping.backend().as_str()) {
        return Err(VaultError::Protection(format!(
            "the {} backend is not valid for {} vaults",
            wrapping.backend().as_str(),
            platform.as_str()
        )));
    }
    let mut data_key = Zeroizing::new([0_u8; KEY_BYTES]);
    let mut signing_seed = Zeroizing::new([0_u8; SIGNING_SEED_BYTES]);
    getrandom::fill(&mut *data_key)?;
    getrandom::fill(&mut *signing_seed)?;
    let public_signing_key = public_key_for_seed(&signing_seed)?;
    let device_key_id = DeviceKeyId::for_public_key(&public_signing_key);
    let actor_id = actor_id_for_public_key(&public_signing_key).to_vec();
    let (data_key_payload, signing_seed_payload, nested_protection) =
        protect_with_factor(vault_id, &data_key, &signing_seed, factor)?;
    let wrapped_data_key = wrapping
        .wrap(&data_key_payload)
        .map_err(|error| VaultError::Protection(error.to_string()))?;
    let wrapped_signing_seed = signing
        .wrap(&signing_seed_payload)
        .map_err(|error| VaultError::Protection(error.to_string()))?;
    let stored = VaultFile {
        format: VAULT_FORMAT.to_owned(),
        version: VAULT_VERSION,
        vault_id,
        device_key_id,
        public_signing_key,
        actor_id,
        platform,
        hardware_backend: wrapping.backend().as_str().to_owned(),
        wrapping_key_label: wrapping_key_label.to_owned(),
        signing_key_label: signing_key_label.to_owned(),
        wrapped_data_key,
        wrapped_signing_seed,
        nested_protection,
        biometric,
        key_epoch: 0,
        created_at,
    };
    write_vault(root, &stored)?;
    Ok(UnsealedVault {
        public: stored.public(),
        data_key,
        signing_seed,
        initialize_store: true,
    })
}

#[cfg(feature = "key-protection")]
fn unseal_with_protectors(
    stored: &VaultFile,
    wrapping: &dyn KeyProtector,
    signing: &dyn KeyProtector,
    factor: UnsealFactor<'_>,
) -> VaultResult<UnsealedVault> {
    stored.validate()?;
    if wrapping.backend().as_str() != stored.hardware_backend
        || signing.backend().as_str() != stored.hardware_backend
    {
        return Err(VaultError::Protection(
            "vault hardware backend does not match its metadata".to_owned(),
        ));
    }
    let wrapped_data_key = wrapping
        .unwrap(&stored.wrapped_data_key)
        .map_err(|error| VaultError::Protection(error.to_string()))?;
    let wrapped_signing_seed = signing
        .unwrap(&stored.wrapped_signing_seed)
        .map_err(|error| VaultError::Protection(error.to_string()))?;
    let (data_key, signing_seed) =
        unprotect_with_factor(stored, &wrapped_data_key, &wrapped_signing_seed, factor)?;
    let public_signing_key = public_key_for_seed(&signing_seed)?;
    if public_signing_key != stored.public_signing_key
        || DeviceKeyId::for_public_key(&public_signing_key) != stored.device_key_id
        || actor_id_for_public_key(&public_signing_key).as_slice() != stored.actor_id
    {
        return Err(VaultError::Protection(
            "device-signing key does not match vault identity".to_owned(),
        ));
    }
    Ok(UnsealedVault {
        public: stored.public(),
        data_key,
        signing_seed,
        initialize_store: false,
    })
}

impl VaultFile {
    fn public(&self) -> VaultMetadata {
        VaultMetadata {
            vault_id: self.vault_id,
            device_key_id: self.device_key_id,
            public_signing_key: self.public_signing_key.clone(),
            actor_id: self.actor_id.clone(),
            platform: self.platform,
            hardware_backend: self.hardware_backend.clone(),
            nested_factor: self.nested_protection.factor.kind(),
            key_epoch: self.key_epoch,
            created_at: self.created_at,
        }
    }

    fn validate(&self) -> VaultResult<()> {
        if self.format != VAULT_FORMAT || self.version != VAULT_VERSION {
            return Err(VaultError::Protection(
                "unsupported vault metadata format or version".to_owned(),
            ));
        }
        if !platform_accepts_backend(self.platform, &self.hardware_backend)
            || self.wrapping_key_label.is_empty()
            || self.signing_key_label.is_empty()
            || self.wrapping_key_label == self.signing_key_label
            || self.actor_id.is_empty()
            || self.wrapped_data_key.is_empty()
            || self.wrapped_signing_seed.is_empty()
            || DeviceKeyId::for_public_key(&self.public_signing_key) != self.device_key_id
            || actor_id_for_public_key(&self.public_signing_key).as_slice() != self.actor_id
        {
            return Err(VaultError::Protection(
                "vault metadata is inconsistent".to_owned(),
            ));
        }
        validate_factor_parameters(&self.nested_protection.factor)?;
        Ok(())
    }
}

fn platform_accepts_backend(platform: VaultPlatform, backend: &str) -> bool {
    match platform {
        VaultPlatform::Android => {
            matches!(backend, "android-strongbox" | "android-trusted-environment")
        }
        VaultPlatform::Ios | VaultPlatform::Macos => backend == "secure-enclave",
        VaultPlatform::Linux | VaultPlatform::Windows => {
            matches!(backend, "tpm" | "tpm-bridge")
        }
        #[cfg(test)]
        VaultPlatform::Test => {
            matches!(
                backend,
                "secure-enclave"
                    | "android-strongbox"
                    | "android-trusted-environment"
                    | "tpm"
                    | "tpm-bridge"
            )
        }
    }
}

#[cfg(feature = "key-protection")]
fn protect_with_factor(
    vault_id: VaultId,
    data_key: &[u8; KEY_BYTES],
    signing_seed: &[u8; SIGNING_SEED_BYTES],
    factor: UnsealFactor<'_>,
) -> VaultResult<ProtectedKeyPayloads> {
    let parameters = new_factor_parameters(factor)?;
    let factor_key = derive_factor_key(factor, &parameters)?;
    let data = crate::crypto::encrypt(
        &factor_key,
        &factor_aad(vault_id, b"data-encryption-key"),
        data_key,
    )
    .map_err(|_| VaultError::Crypto)?;
    let signing = crate::crypto::encrypt(
        &factor_key,
        &factor_aad(vault_id, b"device-signing-seed"),
        signing_seed,
    )
    .map_err(|_| VaultError::Crypto)?;
    Ok((
        Zeroizing::new(data.ciphertext),
        Zeroizing::new(signing.ciphertext),
        NestedProtection {
            factor: parameters,
            data_key_nonce: data.nonce,
            signing_seed_nonce: signing.nonce,
        },
    ))
}

#[cfg(feature = "key-protection")]
fn new_factor_parameters(factor: UnsealFactor<'_>) -> VaultResult<FactorParameters> {
    match factor {
        UnsealFactor::Password(password) => {
            if password.is_empty() {
                return Err(factor_empty_error(factor.kind()));
            }
            let mut salt = [0_u8; SALT_BYTES];
            getrandom::fill(&mut salt)?;
            Ok(FactorParameters::Argon2id {
                version: 0x13,
                memory_kib: ARGON2_MEMORY_KIB,
                iterations: ARGON2_ITERATIONS,
                parallelism: ARGON2_PARALLELISM,
                salt,
            })
        }
    }
}

#[cfg(feature = "key-protection")]
fn unprotect_with_factor(
    stored: &VaultFile,
    data_key_payload: &Zeroizing<Vec<u8>>,
    signing_seed_payload: &Zeroizing<Vec<u8>>,
    factor: UnsealFactor<'_>,
) -> VaultResult<UnsealedVaultKeys> {
    let protection = &stored.nested_protection;
    let factor_key = derive_factor_key(factor, &protection.factor)?;
    let data_key = crate::crypto::decrypt(
        &factor_key,
        &protection.data_key_nonce,
        &factor_aad(stored.vault_id, b"data-encryption-key"),
        data_key_payload,
    )
    .map_err(|_| factor_incorrect_error(protection.factor.kind()))?;
    let signing_seed = crate::crypto::decrypt(
        &factor_key,
        &protection.signing_seed_nonce,
        &factor_aad(stored.vault_id, b"device-signing-seed"),
        signing_seed_payload,
    )
    .map_err(|_| factor_incorrect_error(protection.factor.kind()))?;
    Ok((
        decode_key::<KEY_BYTES>(&data_key, "data-encryption key")?,
        decode_key::<SIGNING_SEED_BYTES>(&signing_seed, "device-signing seed")?,
    ))
}

/// Derive the nested factor's key. The supplied factor must match the one the
/// vault recorded; a mismatch is rejected rather than silently ignored.
#[cfg(feature = "key-protection")]
fn derive_factor_key(
    factor: UnsealFactor<'_>,
    parameters: &FactorParameters,
) -> VaultResult<Zeroizing<[u8; KEY_BYTES]>> {
    validate_factor_parameters(parameters)?;
    if factor.kind() != parameters.kind() {
        return Err(VaultError::Protection(format!(
            "this vault requires the {} factor",
            parameters.kind()
        )));
    }
    match (factor, parameters) {
        (
            UnsealFactor::Password(password),
            FactorParameters::Argon2id {
                memory_kib,
                iterations,
                parallelism,
                salt,
                ..
            },
        ) => {
            if password.is_empty() {
                return Err(factor_empty_error(factor.kind()));
            }
            let params = Params::new(*memory_kib, *iterations, *parallelism, Some(KEY_BYTES))
                .map_err(|error| {
                    VaultError::Protection(format!("invalid Argon2 parameters: {error}"))
                })?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
            argon2
                .hash_password_into(password, salt, &mut *key)
                .map_err(|error| {
                    VaultError::Protection(format!("factor derivation failed: {error}"))
                })?;
            Ok(key)
        }
    }
}

fn validate_factor_parameters(parameters: &FactorParameters) -> VaultResult<()> {
    let FactorParameters::Argon2id {
        version,
        memory_kib,
        iterations,
        parallelism,
        ..
    } = parameters;
    if *version != 0x13
        || *memory_kib < 8 * 1024
        || *memory_kib > MAX_ARGON2_MEMORY_KIB
        || *iterations == 0
        || *iterations > MAX_ARGON2_ITERATIONS
        || *parallelism == 0
        || *parallelism > MAX_ARGON2_PARALLELISM
    {
        return Err(VaultError::Protection(
            "unsupported or unsafe nested-factor parameters".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(feature = "key-protection")]
fn factor_aad(vault_id: VaultId, purpose: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + purpose.len());
    aad.extend_from_slice(b"factorseal/vault-factor/v1\0");
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(&(purpose.len() as u64).to_be_bytes());
    aad.extend_from_slice(purpose);
    aad
}

#[cfg(feature = "key-protection")]
fn factor_incorrect_error(kind: NestedFactorKind) -> VaultError {
    VaultError::Protection(format!(
        "the {kind} factor is incorrect or vault metadata was modified"
    ))
}

#[cfg(feature = "key-protection")]
fn factor_empty_error(kind: NestedFactorKind) -> VaultError {
    VaultError::Protection(format!("the {kind} factor must not be empty"))
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

fn actor_id_for_public_key(public_key: &[u8]) -> [u8; KEY_BYTES] {
    let mut digest = Sha256::new();
    digest.update(b"factorseal/automerge-actor/v1\0");
    digest.update(public_key);
    digest.finalize().into()
}

#[cfg(feature = "key-protection")]
fn decode_key<const LENGTH: usize>(
    plaintext: &Zeroizing<Vec<u8>>,
    name: &'static str,
) -> VaultResult<Zeroizing<[u8; LENGTH]>> {
    let length = plaintext.len();
    let bytes: [u8; LENGTH] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Protection(format!("unwrapped {name} has {length} bytes")))?;
    Ok(Zeroizing::new(bytes))
}

#[cfg(feature = "key-protection")]
fn prepare_root(root: &Path) -> VaultResult<()> {
    if let Some(parent) = root.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| path_error(parent, error))?;
    }
    create_private_root(root).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            VaultError::Protection(format!(
                "refusing to initialize in pre-existing vault root `{}`",
                root.display()
            ))
        } else {
            path_error(root, error)
        }
    })?;
    validate_root(root)
}

#[cfg(all(feature = "key-protection", unix))]
fn create_private_root(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(root)
}

#[cfg(all(feature = "key-protection", not(unix)))]
fn create_private_root(root: &Path) -> std::io::Result<()> {
    fs::create_dir(root)
}

fn validate_root(root: &Path) -> VaultResult<()> {
    let metadata = fs::symlink_metadata(root).map_err(|error| path_error(root, error))?;
    if !metadata.file_type().is_dir() {
        return Err(VaultError::Protection(format!(
            "vault root `{}` is not a directory",
            root.display()
        )));
    }
    validate_private_permissions(root, &metadata)
}

fn read_vault(root: &Path) -> VaultResult<VaultFile> {
    let path = root.join(VAULT_FILE);
    let mut file = fs::File::open(&path).map_err(|error| path_error(&path, error))?;
    let metadata = file.metadata().map_err(|error| path_error(&path, error))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_VAULT_FILE_BYTES {
        return Err(VaultError::Protection(
            "vault metadata is not a bounded regular file".to_owned(),
        ));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| VaultError::Protection("vault metadata does not fit in memory".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|error| path_error(&path, error))?;
    let stored: VaultFile = serde_json::from_slice(&bytes)
        .map_err(|error| VaultError::Protection(error.to_string()))?;
    stored.validate()?;
    Ok(stored)
}

#[cfg(feature = "key-protection")]
fn write_vault(root: &Path, stored: &VaultFile) -> VaultResult<()> {
    stored.validate()?;
    let path = root.join(VAULT_FILE);
    let bytes = serde_json::to_vec_pretty(stored)
        .map_err(|error| VaultError::Protection(error.to_string()))?;
    write_new_private_file(&path, &bytes)
}

#[cfg(all(feature = "key-protection", unix))]
fn write_new_private_file(path: &Path, bytes: &[u8]) -> VaultResult<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    write_and_sync(path, &options, bytes)
}

#[cfg(all(feature = "key-protection", not(unix)))]
fn write_new_private_file(path: &Path, bytes: &[u8]) -> VaultResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    write_and_sync(path, &options, bytes)
}

#[cfg(feature = "key-protection")]
fn write_and_sync(path: &Path, options: &OpenOptions, bytes: &[u8]) -> VaultResult<()> {
    let mut file = options
        .open(path)
        .map_err(|error| path_error(path, error))?;
    file.write_all(bytes)
        .map_err(|error| path_error(path, error))?;
    file.sync_all().map_err(|error| path_error(path, error))
}

#[cfg(unix)]
fn validate_private_permissions(path: &Path, metadata: &fs::Metadata) -> VaultResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(VaultError::Protection(format!(
            "vault root `{}` is accessible by group or other users (mode {mode:o})",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn validate_private_permissions(_path: &Path, _metadata: &fs::Metadata) -> VaultResult<()> {
    Ok(())
}

#[cfg(feature = "key-protection")]
fn unix_time() -> VaultResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| VaultError::Protection(error.to_string()))
}

#[allow(clippy::needless_pass_by_value)]
fn path_error(path: &Path, error: std::io::Error) -> VaultError {
    VaultError::Protection(format!("I/O error for `{}`: {error}", path.display()))
}

#[cfg(all(test, feature = "key-protection"))]
mod tests {
    use super::super::protection::TestProtector;
    use super::*;

    struct TestProtectorFactory;

    impl KeyProtectorFactory for TestProtectorFactory {
        fn create(
            &self,
            root: &Path,
            label: &str,
            biometric: bool,
        ) -> VaultResult<Box<dyn KeyProtector>> {
            self.open(root, label, biometric)
        }

        fn open(
            &self,
            _root: &Path,
            label: &str,
            _biometric: bool,
        ) -> VaultResult<Box<dyn KeyProtector>> {
            let key = if label.starts_with("vault-wrap-") {
                [0x35; KEY_BYTES]
            } else {
                [0x97; KEY_BYTES]
            };
            Ok(Box::new(TestProtector::with_backend(
                key,
                super::super::HardwareBackend::AndroidTrustedEnvironment,
            )))
        }
    }

    #[test]
    fn persisted_vault_artifacts_use_the_factorseal_basename() {
        assert_eq!(VAULT_FILE, "factorseal.json");
        assert_eq!(super::super::DATABASE_FILE, "factorseal.db");
        assert_eq!(super::super::LOCK_FILE, "factorseal.lock");
    }

    #[test]
    fn injected_mobile_protector_creates_unseals_and_discards() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        let created = Vault::create_with_key_protector(
            &root,
            VaultPlatform::Android,
            UnsealFactor::Password(TEST_PASSWORD),
            true,
            &TestProtectorFactory,
        )
        .unwrap();
        assert_eq!(created.public().platform(), "android");
        assert_eq!(
            created.public().hardware_backend(),
            "android-trusted-environment"
        );
        let expected = created.public().clone();
        drop(created);

        let reopened = Vault::unseal_with_key_protector(
            &root,
            UnsealFactor::Password(TEST_PASSWORD),
            &TestProtectorFactory,
        )
        .unwrap();
        assert_eq!(reopened.public(), &expected);
        drop(reopened);

        Vault::discard_initialization_with_key_protector(&root, &TestProtectorFactory).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn mobile_vault_rejects_a_backend_from_another_platform() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        prepare_root(&root).unwrap();
        let wrapping = TestProtector::new([0x35; KEY_BYTES]);
        let signing = TestProtector::new([0x97; KEY_BYTES]);

        let error = create_with_protectors(
            &root,
            VaultId::random().unwrap(),
            "platform-test-wrap",
            "platform-test-sign",
            &wrapping,
            &signing,
            false,
            1_700_000_000,
            VaultPlatform::Ios,
            UnsealFactor::Password(TEST_PASSWORD),
        )
        .unwrap_err();

        assert!(error.to_string().contains("not valid for ios vaults"));
        assert!(!root.join(VAULT_FILE).exists());
    }

    #[test]
    fn a_discarded_initialization_can_be_retried() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        Vault::create_for_test(&root).unwrap();
        // This is what a failed store open leaves behind: a vault that
        // `create` will not write over.
        assert!(Vault::create_for_test(&root).is_err());

        let hardware = root.join("hardware");
        fs::create_dir(&hardware).unwrap();
        fs::write(hardware.join("key-metadata"), b"temporary key").unwrap();

        Vault::discard_initialization_with_key_protector(&root, &TestProtectorFactory).unwrap();
        assert!(!root.exists());
        // Discarding an already discarded root is not an error, so the
        // failure path can call it without checking first.
        Vault::discard_initialization_with_key_protector(&root, &TestProtectorFactory).unwrap();
        Vault::create_for_test(&root).unwrap();
    }

    #[test]
    fn initialization_refuses_a_preexisting_root_without_mutating_it() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        fs::create_dir(&root).unwrap();
        let database = root.join(super::super::DATABASE_FILE);
        let lock = root.join(super::super::LOCK_FILE);
        fs::write(&database, b"existing database").unwrap();
        fs::write(&lock, b"existing lock").unwrap();

        let error = Vault::create_for_test(&root).unwrap_err();
        assert!(error.to_string().contains("pre-existing vault root"));
        assert_eq!(fs::read(database).unwrap(), b"existing database");
        assert_eq!(fs::read(lock).unwrap(), b"existing lock");
        assert!(!root.join(VAULT_FILE).exists());
    }

    #[test]
    fn installation_identity_and_actor_survive_unseal() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        let created = Vault::create_for_test(&root).unwrap();
        let expected = created.public().clone();
        drop(created);

        let unsealed = Vault::unseal_for_test(&root).unwrap();
        assert_eq!(unsealed.public(), &expected);
        assert_ne!(
            unsealed.public().device_key_id().as_bytes()[..16],
            unsealed.public().vault_id().as_bytes()[..]
        );
    }

    #[test]
    fn installation_uses_distinct_wrapping_and_signing_material() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        Vault::create_for_test(&root).unwrap();
        let stored = read_vault(&root).unwrap();

        assert_ne!(stored.wrapping_key_label, stored.signing_key_label);
        assert_ne!(stored.wrapped_data_key, stored.wrapped_signing_seed);
    }

    #[test]
    fn tampered_public_identity_is_rejected_before_unseal() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        Vault::create_for_test(&root).unwrap();
        let mut stored = read_vault(&root).unwrap();
        stored.actor_id[0] ^= 1;

        assert!(stored.validate().is_err());
    }

    #[test]
    fn every_platform_requires_a_nested_factor_and_hardware() {
        for platform in [
            VaultPlatform::Android,
            VaultPlatform::Ios,
            VaultPlatform::Linux,
            VaultPlatform::Macos,
            VaultPlatform::Windows,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("factorseal");
            prepare_root(&root).unwrap();
            let backend = match platform {
                VaultPlatform::Android => super::super::HardwareBackend::AndroidTrustedEnvironment,
                VaultPlatform::Ios | VaultPlatform::Macos => {
                    super::super::HardwareBackend::SecureEnclave
                }
                VaultPlatform::Linux | VaultPlatform::Windows => super::super::HardwareBackend::Tpm,
                VaultPlatform::Test => unreachable!(),
            };
            let wrapping = TestProtector::with_backend([0x35; KEY_BYTES], backend);
            let signing = TestProtector::with_backend([0x97; KEY_BYTES], backend);
            let created = create_with_protectors(
                &root,
                VaultId::random().unwrap(),
                "platform-test-wrap",
                "platform-test-sign",
                &wrapping,
                &signing,
                false,
                1_700_000_000,
                platform,
                UnsealFactor::Password(b"correct horse battery staple"),
            )
            .unwrap();
            let expected = created.public().clone();
            assert_eq!(expected.nested_factor(), NestedFactorKind::Argon2idPassword);
            drop(created);

            let stored = read_vault(&root).unwrap();
            assert!(
                unseal_with_protectors(&stored, &wrapping, &signing, UnsealFactor::Password(b""))
                    .is_err()
            );
            assert!(
                unseal_with_protectors(
                    &stored,
                    &wrapping,
                    &signing,
                    UnsealFactor::Password(b"wrong password")
                )
                .is_err()
            );

            let wrong_hardware = TestProtector::new([0x36; KEY_BYTES]);
            assert!(
                unseal_with_protectors(
                    &stored,
                    &wrong_hardware,
                    &signing,
                    UnsealFactor::Password(b"correct horse battery staple"),
                )
                .is_err()
            );
            let unsealed = unseal_with_protectors(
                &stored,
                &wrapping,
                &signing,
                UnsealFactor::Password(b"correct horse battery staple"),
            )
            .unwrap();
            assert_eq!(unsealed.public(), &expected);
        }
    }
}

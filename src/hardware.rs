use std::path::Path;

use hardware_enclave::{
    AccessPolicy, BackendKind, EnclaveConfig, EncryptorHandle, create_encryptor,
};
use zeroize::Zeroizing;

use crate::vault::{HardwareBackend, KeyProtector, KeyProtectorFactory, VaultError, VaultResult};

const APP_NAME: &str = "factorseal";
const KEYS_DIRECTORY: &str = "hardware";

pub(crate) struct PlatformProtector {
    handle: EncryptorHandle,
    label: String,
    backend: HardwareBackend,
}

impl PlatformProtector {
    pub(crate) fn open(root: &Path, label: &str, biometric: bool) -> VaultResult<Self> {
        Self::open_inner(root, label, biometric, false)
    }

    /// Open a fresh initialization key and delete it if backend validation
    /// fails after the platform has already created it.
    pub(crate) fn create(root: &Path, label: &str, biometric: bool) -> VaultResult<Self> {
        Self::open_inner(root, label, biometric, true)
    }

    fn open_inner(
        root: &Path,
        label: &str,
        biometric: bool,
        delete_on_validation_error: bool,
    ) -> VaultResult<Self> {
        let keys_dir = root.join(KEYS_DIRECTORY);
        let mut config = EnclaveConfig::new(APP_NAME, label);
        config.keys_dir = Some(keys_dir);
        config.access_policy = Some(if biometric {
            AccessPolicy::BiometricOnly
        } else {
            AccessPolicy::None
        });
        // Keep the Windows default `prefer_windows_hello_ux = false`.
        // hardware-enclave's convenience Hello path replaces the CNG key's
        // OS-mediated UI policy with a hookable application-level consent
        // result and may degrade when Hello is unavailable. Factorseal keeps
        // the hardware-enforced key-use policy and treats modern Hello prompt
        // behavior as a native release-acceptance requirement.
        let handle = create_encryptor(&config).map_err(map_hardware_error)?;
        let backend = match verify_hardware_backend(&handle, label) {
            Ok(backend) => backend,
            Err(error) => {
                // `create_encryptor` creates or opens the key eagerly. If
                // validation fails, this initialization attempt must not
                // strand either native key material or its local metadata.
                if delete_on_validation_error {
                    let _ = handle.delete_key(label);
                }
                return Err(error);
            }
        };
        Ok(Self {
            handle,
            label: label.to_owned(),
            backend,
        })
    }

    fn delete_inner(&self) -> VaultResult<()> {
        self.handle
            .delete_key(&self.label)
            .map_err(map_hardware_error)
    }
}

impl KeyProtector for PlatformProtector {
    fn backend(&self) -> HardwareBackend {
        self.backend
    }

    fn wrap(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
        self.handle
            .encrypt(&self.label, plaintext)
            .map_err(map_hardware_error)
    }

    fn unwrap(&self, ciphertext: &[u8]) -> VaultResult<Zeroizing<Vec<u8>>> {
        self.handle
            .decrypt(&self.label, ciphertext)
            .map_err(map_hardware_error)
    }

    fn delete(&self) -> VaultResult<()> {
        self.delete_inner()
    }
}

pub(crate) struct PlatformProtectorFactory;

impl KeyProtectorFactory for PlatformProtectorFactory {
    fn create(
        &self,
        root: &Path,
        label: &str,
        biometric: bool,
    ) -> VaultResult<Box<dyn KeyProtector>> {
        PlatformProtector::create(root, label, biometric)
            .map(|protector| Box::new(protector) as Box<dyn KeyProtector>)
    }

    fn open(
        &self,
        root: &Path,
        label: &str,
        biometric: bool,
    ) -> VaultResult<Box<dyn KeyProtector>> {
        PlatformProtector::open(root, label, biometric)
            .map(|protector| Box::new(protector) as Box<dyn KeyProtector>)
    }
}

/// Map the backend the platform actually initialized onto the ones Factorseal
/// accepts as hardware.
///
/// `hardware-enclave` reports the backend its storage chose rather than static
/// platform detection, so a native Linux TPM key arrives here as
/// `BackendKind::Tpm` and the keyring fallback as `BackendKind::Keyring`. That
/// holds only with the `[patch.crates-io]` pin in `Cargo.toml`
/// (godaddy/hardware-enclave#208); without it every Linux key reports
/// `Keyring` and a TPM-backed vault is rejected as software-backed.
fn verify_hardware_backend(handle: &EncryptorHandle, label: &str) -> VaultResult<HardwareBackend> {
    match handle.backend_kind() {
        BackendKind::SecureEnclave => Ok(HardwareBackend::SecureEnclave),
        BackendKind::Tpm => Ok(HardwareBackend::Tpm),
        BackendKind::TpmBridge => Ok(HardwareBackend::TpmBridge),
        BackendKind::WindowsDpapi => {
            reject_fallback(handle, label, "Windows DPAPI is software-backed")
        }
        BackendKind::Keyring => reject_fallback(
            handle,
            label,
            "Linux keyring fallback is not hardware-backed",
        ),
    }
}

fn reject_fallback<T>(handle: &EncryptorHandle, label: &str, reason: &str) -> VaultResult<T> {
    // `create_encryptor` creates its default key eagerly. Do not leave a
    // software fallback key behind after rejecting that backend.
    let _ = handle.delete_key(label);
    Err(VaultError::Protection(format!(
        "no supported hardware security backend is available: {reason}"
    )))
}

fn map_hardware_error(error: hardware_enclave::Error) -> VaultError {
    match error {
        hardware_enclave::Error::NotAvailable => VaultError::Protection(format!(
            "no supported hardware security backend is available: {error}"
        )),
        other => VaultError::Protection(format!("hardware security operation failed: {other}")),
    }
}

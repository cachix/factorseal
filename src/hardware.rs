use std::path::Path;

use hardware_enclave::{
    AccessPolicy, BackendKind, EnclaveConfig, EncryptorHandle, create_encryptor,
};
use zeroize::Zeroizing;

use crate::{Error, Result};

const APP_NAME: &str = "factorseal";
const KEYS_DIRECTORY: &str = "hardware";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HardwareBackend {
    SecureEnclave,
    Tpm,
    TpmBridge,
}

impl HardwareBackend {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::SecureEnclave => "secure-enclave",
            Self::Tpm => "tpm",
            Self::TpmBridge => "tpm-bridge",
        }
    }
}

pub(crate) trait KeyProtector {
    fn backend(&self) -> HardwareBackend;
    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn unwrap(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

pub(crate) struct PlatformProtector {
    handle: EncryptorHandle,
    label: String,
    backend: HardwareBackend,
}

impl PlatformProtector {
    pub(crate) fn open(root: &Path, label: &str, biometric: bool) -> Result<Self> {
        Self::open_inner(root, label, biometric, false)
    }

    /// Open a fresh initialization key and delete it if backend validation
    /// fails after the platform has already created it.
    pub(crate) fn create(root: &Path, label: &str, biometric: bool) -> Result<Self> {
        Self::open_inner(root, label, biometric, true)
    }

    fn open_inner(
        root: &Path,
        label: &str,
        biometric: bool,
        delete_on_validation_error: bool,
    ) -> Result<Self> {
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

    pub(crate) fn delete(&self) -> Result<()> {
        self.handle
            .delete_key(&self.label)
            .map_err(map_hardware_error)
    }
}

impl KeyProtector for PlatformProtector {
    fn backend(&self) -> HardwareBackend {
        self.backend
    }

    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.handle
            .encrypt(&self.label, plaintext)
            .map_err(map_hardware_error)
    }

    fn unwrap(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.handle
            .decrypt(&self.label, ciphertext)
            .map_err(map_hardware_error)
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
fn verify_hardware_backend(handle: &EncryptorHandle, label: &str) -> Result<HardwareBackend> {
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

fn reject_fallback<T>(handle: &EncryptorHandle, label: &str, reason: &str) -> Result<T> {
    // `create_encryptor` creates its default key eagerly. Do not leave a
    // software fallback key behind after rejecting that backend.
    let _ = handle.delete_key(label);
    Err(Error::HardwareUnavailable(reason.to_owned()))
}

fn map_hardware_error(error: hardware_enclave::Error) -> Error {
    match error {
        hardware_enclave::Error::NotAvailable => Error::HardwareUnavailable(error.to_string()),
        other => Error::Hardware(other.to_string()),
    }
}

#[cfg(test)]
pub(crate) struct TestProtector {
    key: [u8; 32],
}

#[cfg(test)]
impl TestProtector {
    pub(crate) const fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

#[cfg(test)]
impl KeyProtector for TestProtector {
    fn backend(&self) -> HardwareBackend {
        HardwareBackend::Tpm
    }

    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(plaintext
            .iter()
            .zip(self.key.iter().cycle())
            .map(|(value, key)| value ^ key)
            .collect())
    }

    fn unwrap(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            ciphertext
                .iter()
                .zip(self.key.iter().cycle())
                .map(|(value, key)| value ^ key)
                .collect(),
        ))
    }
}

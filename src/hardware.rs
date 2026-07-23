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

    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "secure-enclave" => Ok(Self::SecureEnclave),
            "tpm" => Ok(Self::Tpm),
            "tpm-bridge" => Ok(Self::TpmBridge),
            _ => Err(Error::InvalidMetadata(format!(
                "unsupported hardware backend `{value}`"
            ))),
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
    pub(crate) fn open(root: &Path, label: &str) -> Result<Self> {
        let keys_dir = root.join(KEYS_DIRECTORY);
        let mut config = EnclaveConfig::new(APP_NAME, label);
        config.keys_dir = Some(keys_dir.clone());
        config.access_policy = Some(AccessPolicy::None);

        let handle = create_encryptor(&config).map_err(map_hardware_error)?;
        let backend = verify_hardware_backend(&handle, &keys_dir, label)?;
        Ok(Self {
            handle,
            label: label.to_owned(),
            backend,
        })
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

fn verify_hardware_backend(
    handle: &EncryptorHandle,
    keys_dir: &Path,
    label: &str,
) -> Result<HardwareBackend> {
    match handle.backend_kind() {
        BackendKind::SecureEnclave => Ok(HardwareBackend::SecureEnclave),
        BackendKind::Tpm => Ok(HardwareBackend::Tpm),
        BackendKind::TpmBridge => Ok(HardwareBackend::TpmBridge),
        BackendKind::WindowsDpapi => {
            reject_fallback(handle, label, "Windows DPAPI is software-backed")
        }
        BackendKind::Keyring => {
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            {
                if is_native_linux_tpm_key(keys_dir, label)? {
                    return Ok(HardwareBackend::Tpm);
                }
            }
            reject_fallback(
                handle,
                label,
                "Linux keyring fallback is not hardware-backed",
            )
        }
    }
}

fn reject_fallback<T>(handle: &EncryptorHandle, label: &str, reason: &str) -> Result<T> {
    // `create_encryptor` creates its default key eagerly. Do not leave a
    // software fallback key behind after rejecting that backend.
    let _ = handle.delete_key(label);
    Err(Error::HardwareUnavailable(reason.to_owned()))
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn is_native_linux_tpm_key(keys_dir: &Path, label: &str) -> Result<bool> {
    let private = keys_dir.join(format!("{label}.tpm_priv"));
    let public = keys_dir.join(format!("{label}.tpm_pub"));
    Ok(is_regular_file(&private)? && is_regular_file(&public)?)
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn is_regular_file(path: &Path) -> Result<bool> {
    match path.symlink_metadata() {
        Ok(metadata) => Ok(metadata.file_type().is_file()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(Error::Io {
            path: path.to_owned(),
            source,
        }),
    }
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

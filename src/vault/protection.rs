//! Platform-neutral boundary for hardware-backed key wrapping.
//!
//! Implementations own the native key handle and must keep the key
//! non-exportable. The portable vault layer only supplies the already
//! password-protected key payload to `wrap` and receives it from `unwrap`.

use std::path::Path;

use zeroize::Zeroizing;

use super::VaultResult;

/// Hardware-backed facility that protects an installation key payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HardwareBackend {
    /// Apple Secure Enclave on macOS or iOS.
    SecureEnclave,
    /// Android StrongBox KeyMint security level.
    AndroidStrongBox,
    /// Android trusted-environment KeyMint security level.
    AndroidTrustedEnvironment,
    /// A directly accessible TPM 2.0 device on Linux.
    Tpm,
    /// A TPM 2.0 device accessed through Windows TPM Base Services.
    WindowsTpm,
}

impl HardwareBackend {
    /// Stable identifier persisted in vault metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecureEnclave => "secure-enclave",
            Self::AndroidStrongBox => "android-strongbox",
            Self::AndroidTrustedEnvironment => "android-trusted-environment",
            Self::Tpm => "tpm",
            Self::WindowsTpm => "windows-tpm",
        }
    }
}

/// One already-created or opened, non-exportable native wrapping key.
///
/// Mobile implementations normally live in a thin platform crate that calls
/// the iOS Security framework or Android Keystore. Implementors must return an
/// error rather than silently falling back to software-backed key storage.
pub trait KeyProtector {
    /// Report the backend that actually created or opened this key.
    fn backend(&self) -> HardwareBackend;

    /// Wrap a password-protected Factorseal key payload.
    fn wrap(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>>;

    /// Unwrap a password-protected Factorseal key payload.
    fn unwrap(&self, ciphertext: &[u8]) -> VaultResult<Zeroizing<Vec<u8>>>;

    /// Permanently delete this native key.
    fn delete(&self) -> VaultResult<()>;
}

/// Creates and reopens the native wrapping keys owned by one installation.
///
/// `root` is provided for adapters that keep authenticated public metadata
/// next to the vault. Mobile adapters may ignore it and use only `label`.
pub trait KeyProtectorFactory {
    /// Create a fresh native key for `label`.
    fn create(
        &self,
        root: &Path,
        label: &str,
        biometric: bool,
    ) -> VaultResult<Box<dyn KeyProtector>>;

    /// Open the existing native key for `label`.
    fn open(&self, root: &Path, label: &str, biometric: bool)
    -> VaultResult<Box<dyn KeyProtector>>;
}

#[cfg(test)]
pub(crate) struct TestProtector {
    key: [u8; 32],
    backend: HardwareBackend,
}

#[cfg(test)]
impl TestProtector {
    pub(crate) const fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            backend: HardwareBackend::Tpm,
        }
    }

    pub(crate) const fn with_backend(key: [u8; 32], backend: HardwareBackend) -> Self {
        Self { key, backend }
    }
}

#[cfg(test)]
impl KeyProtector for TestProtector {
    fn backend(&self) -> HardwareBackend {
        self.backend
    }

    fn wrap(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
        Ok(plaintext
            .iter()
            .zip(self.key.iter().cycle())
            .map(|(value, key)| value ^ key)
            .collect())
    }

    fn unwrap(&self, ciphertext: &[u8]) -> VaultResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            ciphertext
                .iter()
                .zip(self.key.iter().cycle())
                .map(|(value, key)| value ^ key)
                .collect(),
        ))
    }

    fn delete(&self) -> VaultResult<()> {
        Ok(())
    }
}

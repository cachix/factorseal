use factorseal::{KeyProtector, KeyProtectorFactory, VaultResult};
use std::path::Path;

pub(crate) struct DeviceProtection;

#[cfg(any(target_os = "android", target_os = "ios"))]
mod device {
    use factorseal::{
        HardwareBackend, KeyProtector, NativeAuthorizationError, VaultError, VaultResult,
    };
    use hardwareseal::{AccessPolicy, AuthorizationError, Backend, Protector};
    use zeroize::Zeroizing;

    pub(super) struct DeviceProtector {
        protector: Protector,
        backend: HardwareBackend,
    }

    impl DeviceProtector {
        pub(super) fn open(label: &str, biometric: bool) -> VaultResult<Self> {
            let policy = if biometric {
                AccessPolicy::Biometric
            } else {
                AccessPolicy::None
            };
            let protector = Protector::open(label, policy).map_err(error)?;
            let backend = match protector.backend() {
                Backend::AppleKeychain => HardwareBackend::SecureEnclave,
                Backend::AndroidKeystore => HardwareBackend::AndroidTrustedEnvironment,
                _ => return Err(VaultError::HardwareUnavailable),
            };
            Ok(Self { protector, backend })
        }
    }

    impl KeyProtector for DeviceProtector {
        fn backend(&self) -> HardwareBackend {
            self.backend
        }

        fn wrap(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
            self.protector.seal(plaintext).map_err(error)
        }

        fn unwrap(&self, ciphertext: &[u8]) -> VaultResult<Zeroizing<Vec<u8>>> {
            self.protector.unseal(ciphertext).map_err(error)
        }

        fn delete(&self) -> VaultResult<()> {
            self.protector.delete().map_err(error)
        }
    }

    fn error(error: hardwareseal::Error) -> VaultError {
        match error {
            hardwareseal::Error::NotAvailable => VaultError::HardwareUnavailable,
            hardwareseal::Error::PolicyNotSupported { .. } => VaultError::HardwarePolicyUnsupported,
            hardwareseal::Error::Authorization(kind) => {
                VaultError::NativeAuthorization(match kind {
                    AuthorizationError::Cancelled => NativeAuthorizationError::Cancelled,
                    AuthorizationError::Denied => NativeAuthorizationError::Denied,
                    AuthorizationError::UiUnavailable => NativeAuthorizationError::UiUnavailable,
                    AuthorizationError::SessionLocked => NativeAuthorizationError::SessionLocked,
                    AuthorizationError::CredentialInvalidated => {
                        NativeAuthorizationError::CredentialInvalidated
                    }
                    _ => {
                        return VaultError::Protection(format!(
                            "hardware authorization failed with an unknown outcome: {error}"
                        ));
                    }
                })
            }
            other => VaultError::Protection(format!("hardware security operation failed: {other}")),
        }
    }
}

impl KeyProtectorFactory for DeviceProtection {
    fn create(
        &self,
        root: &Path,
        label: &str,
        biometric: bool,
    ) -> VaultResult<Box<dyn KeyProtector>> {
        self.open(root, label, biometric)
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    fn open(
        &self,
        _root: &Path,
        label: &str,
        biometric: bool,
    ) -> VaultResult<Box<dyn KeyProtector>> {
        device::DeviceProtector::open(label, biometric)
            .map(|protector| Box::new(protector) as Box<dyn KeyProtector>)
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn open(
        &self,
        _root: &Path,
        _label: &str,
        _biometric: bool,
    ) -> VaultResult<Box<dyn KeyProtector>> {
        Err(factorseal::VaultError::HardwareUnavailable)
    }
}

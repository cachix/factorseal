use std::path::Path;

use hardwareseal::{AccessPolicy, AuthorizationError, Backend, Protector};
use zeroize::Zeroizing;

use crate::vault::{
    HardwareBackend, KeyProtector, KeyProtectorFactory, NativeAuthorizationError, VaultError,
    VaultResult,
};

#[cfg(target_os = "linux")]
const LINUX_BIOMETRIC_UNAVAILABLE: &str = "biometric unlock is not supported on Linux: Linux does not provide a hardware-bound biometric secret, and fprintd match results are not accepted as a cryptographic factor";

pub(crate) fn validate_native_biometric(biometric: bool) -> VaultResult<()> {
    #[cfg(target_os = "linux")]
    if biometric {
        return Err(VaultError::Protection(
            LINUX_BIOMETRIC_UNAVAILABLE.to_owned(),
        ));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = biometric;

    Ok(())
}

pub(crate) struct PlatformProtector {
    protector: Protector,
    backend: HardwareBackend,
}

impl PlatformProtector {
    pub(crate) fn open(root: &Path, label: &str, biometric: bool) -> VaultResult<Self> {
        Self::open_inner(root, label, biometric)
    }

    pub(crate) fn create(root: &Path, label: &str, biometric: bool) -> VaultResult<Self> {
        Self::open_inner(root, label, biometric)
    }

    fn open_inner(_root: &Path, label: &str, biometric: bool) -> VaultResult<Self> {
        // Fail before creating directories or native keys. In particular, a
        // Linux fingerprint match delivered through fprintd is only a
        // same-user software signal and must never be treated as key policy.
        validate_native_biometric(biometric)?;
        let policy = if biometric {
            AccessPolicy::Biometric
        } else {
            AccessPolicy::None
        };
        let protector = Protector::open(label, policy).map_err(map_hardware_error)?;
        let backend = map_backend(protector.backend())?;
        Ok(Self { protector, backend })
    }
}

impl KeyProtector for PlatformProtector {
    fn backend(&self) -> HardwareBackend {
        self.backend
    }

    fn wrap(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
        self.protector.seal(plaintext).map_err(map_hardware_error)
    }

    fn unwrap(&self, ciphertext: &[u8]) -> VaultResult<Zeroizing<Vec<u8>>> {
        self.protector
            .unseal(ciphertext)
            .map_err(map_hardware_error)
    }

    fn delete(&self) -> VaultResult<()> {
        self.protector.delete().map_err(map_hardware_error)
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

fn map_backend(backend: Backend) -> VaultResult<HardwareBackend> {
    match backend {
        Backend::Tpm => Ok(HardwareBackend::Tpm),
        // A Windows Hello protector adds user verification and PRF encryption
        // around the same TPM-bound payload. The unlock group records whether
        // biometric verification is required; the hardware backend records
        // the TPM that ultimately binds the secret to this Windows device.
        Backend::WindowsTpm | Backend::WindowsHello => Ok(HardwareBackend::WindowsTpm),
        Backend::AppleKeychain => Ok(HardwareBackend::SecureEnclave),
        Backend::AndroidKeystore => Err(VaultError::Protection(
            "the Android hardware backend cannot serve the desktop vault".to_owned(),
        )),
        _ => Err(VaultError::Protection(
            "hardwareseal selected an unknown backend".to_owned(),
        )),
    }
}

fn map_hardware_error(error: hardwareseal::Error) -> VaultError {
    match error {
        hardwareseal::Error::NotAvailable => VaultError::HardwareUnavailable,
        hardwareseal::Error::PolicyNotSupported { .. } => VaultError::HardwarePolicyUnsupported,
        hardwareseal::Error::Authorization(kind) => match kind {
            AuthorizationError::Cancelled => {
                VaultError::NativeAuthorization(NativeAuthorizationError::Cancelled)
            }
            AuthorizationError::Denied => {
                VaultError::NativeAuthorization(NativeAuthorizationError::Denied)
            }
            AuthorizationError::UiUnavailable => {
                VaultError::NativeAuthorization(NativeAuthorizationError::UiUnavailable)
            }
            AuthorizationError::SessionLocked => {
                VaultError::NativeAuthorization(NativeAuthorizationError::SessionLocked)
            }
            AuthorizationError::CredentialInvalidated => {
                VaultError::NativeAuthorization(NativeAuthorizationError::CredentialInvalidated)
            }
            _ => VaultError::Protection(format!(
                "hardware authorization failed with an unknown outcome: {error}"
            )),
        },
        other => VaultError::Protection(format!("hardware security operation failed: {other}")),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::vault::{UnlockCredentials, UnlockFactorKind, UnlockGroup, UnlockPolicy, Vault};

    #[test]
    fn native_linux_vault_rejects_a_biometric_policy_without_creating_a_root() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("vault");
        let group = UnlockGroup::new([UnlockFactorKind::Biometric]).unwrap();
        let policy = UnlockPolicy::new([group]).unwrap();
        let result = Vault::create_with_unlock_policy(&root, &policy, UnlockCredentials::none());

        let Err(VaultError::Protection(message)) = result else {
            panic!("expected Linux biometric policy to fail closed");
        };
        assert_eq!(message, LINUX_BIOMETRIC_UNAVAILABLE);
        assert!(!root.exists());
    }

    #[test]
    fn biometric_protection_fails_before_creating_linux_state() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("vault");
        let result = PlatformProtector::create(&root, "biometric-test", true);

        let Err(VaultError::Protection(message)) = result else {
            panic!("expected Linux biometric protection to fail closed");
        };
        assert_eq!(message, LINUX_BIOMETRIC_UNAVAILABLE);
        assert!(!root.exists());
    }

    #[test]
    fn non_biometric_linux_policy_passes_the_platform_guard() {
        validate_native_biometric(false).unwrap();
    }

    #[test]
    fn native_authorization_outcomes_remain_structured() {
        let cases = [
            (
                AuthorizationError::Cancelled,
                NativeAuthorizationError::Cancelled,
            ),
            (AuthorizationError::Denied, NativeAuthorizationError::Denied),
            (
                AuthorizationError::UiUnavailable,
                NativeAuthorizationError::UiUnavailable,
            ),
            (
                AuthorizationError::SessionLocked,
                NativeAuthorizationError::SessionLocked,
            ),
            (
                AuthorizationError::CredentialInvalidated,
                NativeAuthorizationError::CredentialInvalidated,
            ),
        ];

        for (source, expected) in cases {
            assert!(matches!(
                map_hardware_error(hardwareseal::Error::Authorization(source)),
                VaultError::NativeAuthorization(actual) if actual == expected
            ));
        }
    }

    #[test]
    fn hardware_availability_and_policy_remain_structured() {
        assert!(matches!(
            map_hardware_error(hardwareseal::Error::NotAvailable),
            VaultError::HardwareUnavailable
        ));
        assert!(matches!(
            map_hardware_error(hardwareseal::Error::PolicyNotSupported {
                policy: AccessPolicy::Biometric,
                backend: Backend::Tpm,
            }),
            VaultError::HardwarePolicyUnsupported
        ));
    }
}

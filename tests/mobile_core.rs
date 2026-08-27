#![cfg(feature = "key-protection")]

use std::path::Path;

use factorseal::{
    HardwareBackend, KeyProtector, KeyProtectorFactory, UnlockCredentials, UnlockFactorKind,
    UnlockGroup, UnlockPolicy, Vault, VaultPlatform, VaultResult,
};
use zeroize::Zeroizing;

struct MobileTestProtector {
    key: u8,
}

impl KeyProtector for MobileTestProtector {
    fn backend(&self) -> HardwareBackend {
        HardwareBackend::AndroidTrustedEnvironment
    }

    fn wrap(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
        Ok(plaintext.iter().map(|byte| byte ^ self.key).collect())
    }

    fn unwrap(&self, ciphertext: &[u8]) -> VaultResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            ciphertext.iter().map(|byte| byte ^ self.key).collect(),
        ))
    }

    fn delete(&self) -> VaultResult<()> {
        Ok(())
    }
}

struct MobileTestFactory;

impl KeyProtectorFactory for MobileTestFactory {
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
        let key = if label.contains("-wrap-") || label.ends_with("-wrap") {
            0x35
        } else {
            0x97
        };
        Ok(Box::new(MobileTestProtector { key }))
    }
}

#[test]
fn public_mobile_adapter_api_round_trips_a_vault() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("factorseal");
    let password = b"correct horse battery staple";
    let password_and_biometric =
        UnlockGroup::new([UnlockFactorKind::Password, UnlockFactorKind::Biometric]).unwrap();
    let biometric = UnlockGroup::new([UnlockFactorKind::Biometric]).unwrap();
    let policy = UnlockPolicy::new([password_and_biometric, biometric.clone()]).unwrap();

    let created = Vault::create_with_key_protector_policy(
        &root,
        VaultPlatform::Android,
        &policy,
        UnlockCredentials::with_password(password),
        &MobileTestFactory,
    )
    .unwrap();
    let expected = created.public().clone();
    assert_eq!(expected.platform_kind(), VaultPlatform::Android);
    assert_eq!(
        expected.hardware_backend(),
        HardwareBackend::AndroidTrustedEnvironment.as_str()
    );
    drop(created);

    let reopened = Vault::unseal_with_key_protector_group(
        &root,
        &biometric,
        UnlockCredentials::none(),
        &MobileTestFactory,
    )
    .unwrap();
    assert_eq!(reopened.public(), &expected);
}

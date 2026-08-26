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
        VaultCreation {
            vault_id: VaultId::random().unwrap(),
            biometric: false,
            created_at: 1_700_000_000,
            platform: VaultPlatform::Ios,
        },
        ProtectorPair {
            wrapping: LabeledProtector {
                label: "platform-test-wrap",
                key: &wrapping,
            },
            signing: LabeledProtector {
                label: "platform-test-sign",
                key: &signing,
            },
        },
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
fn destroy_requires_the_factor_and_removes_a_completed_vault() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("factorseal");
    Vault::create_with_key_protector(
        &root,
        VaultPlatform::Android,
        UnsealFactor::Password(b"acceptance-factor"),
        false,
        &TestProtectorFactory,
    )
    .unwrap();

    assert!(
        Vault::destroy_with_key_protector(
            &root,
            UnsealFactor::Password(b"wrong-factor"),
            &TestProtectorFactory,
        )
        .is_err()
    );
    assert!(root.exists());

    Vault::destroy_with_key_protector(
        &root,
        UnsealFactor::Password(b"acceptance-factor"),
        &TestProtectorFactory,
    )
    .unwrap();
    assert!(!root.exists());
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
            VaultCreation {
                vault_id: VaultId::random().unwrap(),
                biometric: false,
                created_at: 1_700_000_000,
                platform,
            },
            ProtectorPair {
                wrapping: LabeledProtector {
                    label: "platform-test-wrap",
                    key: &wrapping,
                },
                signing: LabeledProtector {
                    label: "platform-test-sign",
                    key: &signing,
                },
            },
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

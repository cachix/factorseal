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
        let key = if label.contains("-wrap-") || label.ends_with("-wrap") {
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

#[derive(Default)]
struct RecordingProtectorFactory {
    biometric_policies: std::sync::Mutex<Vec<bool>>,
}

impl KeyProtectorFactory for RecordingProtectorFactory {
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
        biometric: bool,
    ) -> VaultResult<Box<dyn KeyProtector>> {
        self.biometric_policies.lock().unwrap().push(biometric);
        let key = if label.contains("-wrap-") {
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
fn prepared_vault_metadata_is_published_atomically_on_completion() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("factorseal");
    let group = UnlockGroup::new([UnlockFactorKind::Password]).unwrap();
    let policy = UnlockPolicy::new([group]).unwrap();

    let prepared = Vault::create_with_key_protector_policy_mode(
        &root,
        VaultPlatform::Android,
        &policy,
        UnlockCredentials::with_password(TEST_PASSWORD),
        &TestProtectorFactory,
        true,
    )
    .unwrap();

    assert!(root.join(PENDING_VAULT_FILE).is_file());
    assert!(!root.join(VAULT_FILE).exists());
    assert!(Vault::inspect(&root).is_err());

    Vault::complete_initialization(&root).unwrap();

    assert!(!root.join(PENDING_VAULT_FILE).exists());
    assert!(root.join(VAULT_FILE).is_file());
    assert_eq!(Vault::inspect(&root).unwrap(), *prepared.public());
}

#[test]
fn unlock_groups_are_independent_or_slots_with_and_factors() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("factorseal");
    let password_and_biometric =
        UnlockGroup::new([UnlockFactorKind::Password, UnlockFactorKind::Biometric]).unwrap();
    let password = UnlockGroup::new([UnlockFactorKind::Password]).unwrap();
    let biometric = UnlockGroup::new([UnlockFactorKind::Biometric]).unwrap();
    let policy =
        UnlockPolicy::new([password, biometric.clone(), password_and_biometric.clone()]).unwrap();
    let factory = RecordingProtectorFactory::default();

    let created = Vault::create_with_key_protector_policy(
        &root,
        VaultPlatform::Android,
        &policy,
        UnlockCredentials::with_password(b"correct horse"),
        &factory,
    )
    .unwrap();
    let expected = created.public().clone();
    assert_eq!(expected.unlock_policy(), &policy);
    assert_eq!(expected.preferred_unlock_group(), &policy.groups()[0]);
    drop(created);

    let stored = read_vault(&root).unwrap();
    assert_eq!(
        stored.preferred_unlock_group.as_ref(),
        Some(&policy.groups()[0])
    );
    assert_eq!(stored.unlock_slots.len(), 3);
    assert!(stored.unlock_slots[0].password_protection.is_some());
    assert!(stored.unlock_slots[1].password_protection.is_none());
    assert!(stored.unlock_slots[2].password_protection.is_some());
    assert_eq!(
        *factory.biometric_policies.lock().unwrap(),
        [false, false, true, true, true, true]
    );

    assert!(
        Vault::unseal_with_key_protector_group(
            &root,
            &password_and_biometric,
            UnlockCredentials::none(),
            &factory,
        )
        .is_err()
    );
    let via_biometric = Vault::unseal_with_key_protector_group(
        &root,
        &biometric,
        UnlockCredentials::none(),
        &factory,
    )
    .unwrap();
    assert_eq!(via_biometric.public(), &expected);
    drop(via_biometric);

    let via_both = Vault::unseal_with_key_protector_group(
        &root,
        &password_and_biometric,
        UnlockCredentials::with_password(b"correct horse"),
        &factory,
    )
    .unwrap();
    assert_eq!(via_both.public(), &expected);
}

#[test]
fn metadata_without_a_preferred_group_uses_the_first_policy_group() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("factorseal");
    Vault::create_for_test(&root).unwrap();
    let stored = read_vault(&root).unwrap();

    let mut json = serde_json::to_value(&stored).unwrap();
    json.as_object_mut()
        .unwrap()
        .remove("preferred_unlock_group");
    let compatible: super::metadata::VaultFile = serde_json::from_value(json).unwrap();
    compatible.validate().unwrap();

    assert!(compatible.preferred_unlock_group.is_none());
    assert_eq!(
        compatible.public().preferred_unlock_group(),
        &compatible.unlock_policy.groups()[0]
    );
}

#[test]
fn preferred_group_must_belong_to_the_unlock_policy() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("factorseal");
    Vault::create_for_test(&root).unwrap();
    let mut stored = read_vault(&root).unwrap();
    stored.preferred_unlock_group = Some(UnlockGroup::new([UnlockFactorKind::Biometric]).unwrap());

    assert!(
        stored
            .validate()
            .unwrap_err()
            .to_string()
            .contains("preferred unlock group")
    );
}

#[test]
fn older_single_factor_metadata_versions_are_rejected_cleanly() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("factorseal");
    Vault::create_for_test(&root).unwrap();
    let mut stored = read_vault(&root).unwrap();
    stored.version = 2;

    let error = stored.validate().unwrap_err();
    assert!(error.to_string().contains("unsupported vault metadata"));
}

#[test]
fn mobile_vault_rejects_a_backend_from_another_platform() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("factorseal");
    prepare_root(&root).unwrap();
    let wrapping = TestProtector::new([0x35; KEY_BYTES]);
    let signing = TestProtector::new([0x97; KEY_BYTES]);
    let group = UnlockGroup::new([UnlockFactorKind::Password]).unwrap();

    let error = create_with_protectors(
        &root,
        VaultCreation {
            vault_id: VaultId::random().unwrap(),
            created_at: 1_700_000_000,
            platform: VaultPlatform::Ios,
        },
        UnlockPolicy::new([group.clone()]).unwrap(),
        &[SlotProtectors {
            group: &group,
            wrapping: LabeledProtector {
                label: "platform-test-wrap",
                key: &wrapping,
            },
            signing: LabeledProtector {
                label: "platform-test-sign",
                key: &signing,
            },
        }],
        UnlockCredentials::with_password(TEST_PASSWORD),
        false,
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
    let slot = &stored.unlock_slots[0];

    assert_ne!(slot.wrapping_key_label, slot.signing_key_label);
    assert_ne!(slot.wrapped_data_key, slot.wrapped_signing_seed);
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
            VaultPlatform::Linux => super::super::HardwareBackend::Tpm,
            VaultPlatform::Windows => super::super::HardwareBackend::WindowsTpm,
            VaultPlatform::Test => unreachable!(),
        };
        let wrapping = TestProtector::with_backend([0x35; KEY_BYTES], backend);
        let signing = TestProtector::with_backend([0x97; KEY_BYTES], backend);
        let group = UnlockGroup::new([UnlockFactorKind::Password]).unwrap();
        let created = create_with_protectors(
            &root,
            VaultCreation {
                vault_id: VaultId::random().unwrap(),
                created_at: 1_700_000_000,
                platform,
            },
            UnlockPolicy::new([group.clone()]).unwrap(),
            &[SlotProtectors {
                group: &group,
                wrapping: LabeledProtector {
                    label: "platform-test-wrap",
                    key: &wrapping,
                },
                signing: LabeledProtector {
                    label: "platform-test-sign",
                    key: &signing,
                },
            }],
            UnlockCredentials::with_password(b"correct horse battery staple"),
            false,
        )
        .unwrap();
        let expected = created.public().clone();
        assert_eq!(
            expected.unlock_policy().groups(),
            std::slice::from_ref(&group)
        );
        drop(created);

        let stored = read_vault(&root).unwrap();
        let slot = &stored.unlock_slots[0];
        assert!(
            unseal_with_protectors(
                &stored,
                slot,
                &wrapping,
                &signing,
                UnlockCredentials::with_password(b"")
            )
            .is_err()
        );
        assert!(
            unseal_with_protectors(
                &stored,
                slot,
                &wrapping,
                &signing,
                UnlockCredentials::with_password(b"wrong password")
            )
            .is_err()
        );

        let wrong_hardware = TestProtector::new([0x36; KEY_BYTES]);
        assert!(
            unseal_with_protectors(
                &stored,
                slot,
                &wrong_hardware,
                &signing,
                UnlockCredentials::with_password(b"correct horse battery staple"),
            )
            .is_err()
        );
        let unsealed = unseal_with_protectors(
            &stored,
            slot,
            &wrapping,
            &signing,
            UnlockCredentials::with_password(b"correct horse battery staple"),
        )
        .unwrap();
        assert_eq!(unsealed.public(), &expected);
    }
}

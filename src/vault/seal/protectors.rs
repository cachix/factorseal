//! Hardware protector orchestration for vault creation and unsealing.

use std::path::Path;

use zeroize::Zeroizing;

use super::factor::{protect_with_factor, unprotect_with_factor};
use super::metadata::{
    NewVaultFile, VaultFile, actor_id_for_public_key, platform_accepts_backend, write_vault,
};
use super::{KEY_BYTES, UnsealFactor, UnsealedVault, VaultPlatform};
use crate::vault::signature::{SIGNING_SEED_BYTES, public_key_for_seed};
use crate::vault::{DeviceKeyId, KeyProtector, VaultError, VaultId, VaultResult};

#[derive(Clone, Copy)]
pub(super) struct VaultCreation {
    pub(super) vault_id: VaultId,
    pub(super) biometric: bool,
    pub(super) created_at: u64,
    pub(super) platform: VaultPlatform,
}

pub(super) struct LabeledProtector<'a> {
    pub(super) label: &'a str,
    pub(super) key: &'a dyn KeyProtector,
}

pub(super) struct ProtectorPair<'a> {
    pub(super) wrapping: LabeledProtector<'a>,
    pub(super) signing: LabeledProtector<'a>,
}

pub(super) fn create_with_protectors(
    root: &Path,
    creation: VaultCreation,
    protectors: ProtectorPair<'_>,
    factor: UnsealFactor<'_>,
) -> VaultResult<UnsealedVault> {
    let VaultCreation {
        vault_id,
        biometric,
        created_at,
        platform,
    } = creation;
    let ProtectorPair { wrapping, signing } = protectors;
    if wrapping.label == signing.label {
        return Err(VaultError::Protection(
            "wrapping and signing key labels must be distinct".to_owned(),
        ));
    }
    if wrapping.key.backend() != signing.key.backend() {
        return Err(VaultError::Protection(
            "wrapping and signing keys use different hardware backends".to_owned(),
        ));
    }
    if !platform_accepts_backend(platform, wrapping.key.backend().as_str()) {
        return Err(VaultError::Protection(format!(
            "the {} backend is not valid for {} vaults",
            wrapping.key.backend().as_str(),
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
        .key
        .wrap(&data_key_payload)
        .map_err(|error| VaultError::Protection(error.to_string()))?;
    let wrapped_signing_seed = signing
        .key
        .wrap(&signing_seed_payload)
        .map_err(|error| VaultError::Protection(error.to_string()))?;
    let stored = VaultFile::new(NewVaultFile {
        vault_id,
        device_key_id,
        public_signing_key,
        actor_id,
        platform,
        hardware_backend: wrapping.key.backend().as_str().to_owned(),
        wrapping_key_label: wrapping.label.to_owned(),
        signing_key_label: signing.label.to_owned(),
        wrapped_data_key,
        wrapped_signing_seed,
        nested_protection,
        biometric,
        created_at,
    });
    write_vault(root, &stored)?;
    Ok(UnsealedVault {
        public: stored.public(),
        data_key,
        signing_seed,
        initialize_store: true,
    })
}

pub(super) fn unseal_with_protectors(
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
    let (data_key, signing_seed) = unprotect_with_factor(
        stored.vault_id,
        &stored.nested_protection,
        &wrapped_data_key,
        &wrapped_signing_seed,
        factor,
    )?;
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

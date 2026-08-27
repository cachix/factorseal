//! Hardware protector orchestration for policy-based creation and unsealing.

use std::path::Path;

use zeroize::Zeroizing;

use super::factor::{decode_key, protect_with_factor, unprotect_with_factor};
use super::metadata::{
    NewVaultFile, UnlockSlot, VaultFile, actor_id_for_public_key, platform_accepts_backend,
    write_vault,
};
use super::{
    KEY_BYTES, UnlockCredentials, UnlockFactorKind, UnlockGroup, UnlockPolicy, UnsealFactor,
    UnsealedVault, VaultPlatform,
};
use crate::vault::signature::{SIGNING_SEED_BYTES, public_key_for_seed};
use crate::vault::{DeviceKeyId, KeyProtector, VaultError, VaultId, VaultResult};

#[derive(Clone, Copy)]
pub(super) struct VaultCreation {
    pub(super) vault_id: VaultId,
    pub(super) created_at: u64,
    pub(super) platform: VaultPlatform,
}

pub(super) struct LabeledProtector<'a> {
    pub(super) label: &'a str,
    pub(super) key: &'a dyn KeyProtector,
}

pub(super) struct SlotProtectors<'a> {
    pub(super) group: &'a UnlockGroup,
    pub(super) wrapping: LabeledProtector<'a>,
    pub(super) signing: LabeledProtector<'a>,
}

pub(super) fn create_with_protectors(
    root: &Path,
    creation: VaultCreation,
    policy: UnlockPolicy,
    protectors: &[SlotProtectors<'_>],
    credentials: UnlockCredentials<'_>,
) -> VaultResult<UnsealedVault> {
    policy.validate()?;
    if protectors.len() != policy.groups().len() {
        return Err(VaultError::Protection(
            "unlock policy and hardware protectors do not match".to_owned(),
        ));
    }
    let VaultCreation {
        vault_id,
        created_at,
        platform,
    } = creation;
    let mut data_key = Zeroizing::new([0_u8; KEY_BYTES]);
    let mut signing_seed = Zeroizing::new([0_u8; SIGNING_SEED_BYTES]);
    getrandom::fill(&mut *data_key)?;
    getrandom::fill(&mut *signing_seed)?;
    let public_signing_key = public_key_for_seed(&signing_seed)?;
    let device_key_id = DeviceKeyId::for_public_key(&public_signing_key);
    let actor_id = actor_id_for_public_key(&public_signing_key).to_vec();
    let mut hardware_backend = None;
    let mut slots = Vec::with_capacity(protectors.len());

    for (slot, expected_group) in protectors.iter().zip(policy.groups()) {
        if slot.group != expected_group {
            return Err(VaultError::Protection(
                "unlock policy and hardware protector order do not match".to_owned(),
            ));
        }
        validate_pair(platform, slot, &mut hardware_backend)?;
        let password = credentials.password_for(slot.group)?;
        let (data_payload, signing_payload, password_protection) = if let Some(password) = password
        {
            let (data, signing, protection) = protect_with_factor(
                vault_id,
                &data_key,
                &signing_seed,
                UnsealFactor::Password(password),
            )?;
            (data, signing, Some(protection))
        } else {
            (
                Zeroizing::new(data_key.to_vec()),
                Zeroizing::new(signing_seed.to_vec()),
                None,
            )
        };
        slots.push(UnlockSlot {
            group: slot.group.clone(),
            wrapping_key_label: slot.wrapping.label.to_owned(),
            signing_key_label: slot.signing.label.to_owned(),
            wrapped_data_key: slot
                .wrapping
                .key
                .wrap(&data_payload)
                .map_err(|error| VaultError::Protection(error.to_string()))?,
            wrapped_signing_seed: slot
                .signing
                .key
                .wrap(&signing_payload)
                .map_err(|error| VaultError::Protection(error.to_string()))?,
            password_protection,
        });
    }

    let stored = VaultFile::new(NewVaultFile {
        vault_id,
        device_key_id,
        public_signing_key,
        actor_id,
        platform,
        hardware_backend: hardware_backend.ok_or_else(|| {
            VaultError::Protection("unlock policy has no hardware protector".to_owned())
        })?,
        unlock_policy: policy,
        unlock_slots: slots,
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

fn validate_pair(
    platform: VaultPlatform,
    slot: &SlotProtectors<'_>,
    common_backend: &mut Option<String>,
) -> VaultResult<()> {
    if slot.wrapping.label == slot.signing.label {
        return Err(VaultError::Protection(
            "wrapping and signing key labels must be distinct".to_owned(),
        ));
    }
    if slot.wrapping.key.backend() != slot.signing.key.backend() {
        return Err(VaultError::Protection(
            "wrapping and signing keys use different hardware backends".to_owned(),
        ));
    }
    let backend = slot.wrapping.key.backend().as_str();
    if !platform_accepts_backend(platform, backend) {
        return Err(VaultError::Protection(format!(
            "the {backend} backend is not valid for {} vaults",
            platform.as_str()
        )));
    }
    if common_backend
        .as_deref()
        .is_some_and(|common| common != backend)
    {
        return Err(VaultError::Protection(
            "unlock groups use different hardware backends".to_owned(),
        ));
    }
    *common_backend = Some(backend.to_owned());
    Ok(())
}

pub(super) fn unseal_with_protectors(
    stored: &VaultFile,
    slot: &UnlockSlot,
    wrapping: &dyn KeyProtector,
    signing: &dyn KeyProtector,
    credentials: UnlockCredentials<'_>,
) -> VaultResult<UnsealedVault> {
    stored.validate()?;
    if wrapping.backend().as_str() != stored.hardware_backend
        || signing.backend().as_str() != stored.hardware_backend
    {
        return Err(VaultError::Protection(
            "vault hardware backend does not match its metadata".to_owned(),
        ));
    }
    let data_payload = wrapping
        .unwrap(&slot.wrapped_data_key)
        .map_err(|error| VaultError::Protection(error.to_string()))?;
    let signing_payload = signing
        .unwrap(&slot.wrapped_signing_seed)
        .map_err(|error| VaultError::Protection(error.to_string()))?;
    let (data_key, signing_seed) = if let Some(protection) = &slot.password_protection {
        let password = credentials.password_for(&slot.group)?.ok_or_else(|| {
            VaultError::Protection("password-protected slot has no password factor".to_owned())
        })?;
        unprotect_with_factor(
            stored.vault_id,
            protection,
            &data_payload,
            &signing_payload,
            UnsealFactor::Password(password),
        )?
    } else {
        if slot.group.requires(UnlockFactorKind::Password) {
            return Err(VaultError::Protection(
                "password unlock group has no password protection".to_owned(),
            ));
        }
        (
            decode_key::<KEY_BYTES>(&data_payload, "data-encryption key")?,
            decode_key::<SIGNING_SEED_BYTES>(&signing_payload, "device-signing seed")?,
        )
    };
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

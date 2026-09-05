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
    UnsealedVault, VaultCryptoProfile, VaultPlatform,
};
use crate::vault::signature::{SIGNING_SEED_BYTES, public_key_for_seed};
use crate::vault::{
    DeviceKeyId, InstallationId, InstallationSecrets, KeyProtector, VaultError, VaultId,
    VaultResult,
};

#[derive(Clone, Copy)]
pub(super) struct VaultCreation {
    pub(super) installation_id: InstallationId,
    pub(super) device_vault_id: VaultId,
    pub(super) created_at: u64,
    pub(super) platform: VaultPlatform,
    pub(super) cryptographic_profile: VaultCryptoProfile,
}

pub(super) struct LabeledProtector<'a> {
    pub(super) label: &'a str,
    pub(super) key: &'a dyn KeyProtector,
}

/// The one hardware protector an unlock group wraps the installation root
/// with. Every other key is root-wrapped or root-derived, so one hardware
/// operation and, where the policy demands it, one user verification opens
/// the installation.
pub(super) struct SlotProtector<'a> {
    pub(super) group: &'a UnlockGroup,
    pub(super) wrapping: LabeledProtector<'a>,
}

pub(super) fn create_with_protectors(
    root: &Path,
    creation: VaultCreation,
    policy: UnlockPolicy,
    protectors: &[SlotProtector<'_>],
    credentials: UnlockCredentials<'_>,
    pending: bool,
) -> VaultResult<UnsealedVault> {
    policy.validate()?;
    if protectors.len() != policy.groups().len() {
        return Err(VaultError::Protection(
            "unlock policy and hardware protectors do not match".to_owned(),
        ));
    }
    let VaultCreation {
        installation_id,
        device_vault_id,
        created_at,
        platform,
        cryptographic_profile,
    } = creation;
    let mut vault_root_key = Zeroizing::new([0_u8; KEY_BYTES]);
    let mut signing_seed = Zeroizing::new([0_u8; SIGNING_SEED_BYTES]);
    getrandom::fill(&mut *vault_root_key)?;
    getrandom::fill(&mut *signing_seed)?;
    let public_signing_key = public_key_for_seed(&signing_seed);
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
        validate_protector(platform, slot, &mut hardware_backend)?;
        let password = credentials.password_for(slot.group)?;
        let (root_payload, password_protection) = if let Some(password) = password {
            let (root, protection) = protect_with_factor(
                installation_id,
                &vault_root_key,
                UnsealFactor::Password(password),
                cryptographic_profile,
            )?;
            (root, Some(protection))
        } else {
            (Zeroizing::new(vault_root_key.to_vec()), None)
        };
        slots.push(UnlockSlot {
            group: slot.group.clone(),
            wrapping_key_label: slot.wrapping.label.to_owned(),
            wrapped_vault_root_key: slot.wrapping.key.wrap(&root_payload)?,
            password_protection,
        });
    }

    let (secrets, wrapped_installation_secrets) = InstallationSecrets::generate(
        installation_id,
        device_vault_id,
        vault_root_key,
        &signing_seed,
    )?;
    let stored = VaultFile::new(NewVaultFile {
        installation_id,
        device_vault_id,
        device_key_id,
        public_signing_key,
        actor_id,
        platform,
        hardware_backend: hardware_backend.ok_or_else(|| {
            VaultError::Protection("unlock policy has no hardware protector".to_owned())
        })?,
        cryptographic_profile,
        unlock_policy: policy,
        unlock_slots: slots,
        wrapped_installation_secrets,
        created_at,
    });
    write_vault(root, &stored, pending)?;
    Ok(UnsealedVault {
        public: stored.public(),
        secrets,
        initialize_store: true,
    })
}

fn validate_protector(
    platform: VaultPlatform,
    slot: &SlotProtector<'_>,
    common_backend: &mut Option<String>,
) -> VaultResult<()> {
    if slot.wrapping.label.is_empty() {
        return Err(VaultError::Protection(
            "wrapping key label must not be empty".to_owned(),
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
    credentials: UnlockCredentials<'_>,
) -> VaultResult<UnsealedVault> {
    crate::timing::result("key_hierarchy", "validate_metadata", || stored.validate())?;
    if wrapping.backend().as_str() != stored.hardware_backend {
        return Err(VaultError::Protection(
            "vault hardware backend does not match its metadata".to_owned(),
        ));
    }
    let root_payload = crate::timing::result("key_hierarchy", "hardware_unwrap", || {
        wrapping.unwrap(&slot.wrapped_vault_root_key)
    })?;
    let vault_root_key = if let Some(protection) = &slot.password_protection {
        let password = credentials.password_for(&slot.group)?.ok_or_else(|| {
            VaultError::Protection("password-protected slot has no password factor".to_owned())
        })?;
        crate::timing::result("key_hierarchy", "password_unprotect", || {
            unprotect_with_factor(
                stored.installation_id,
                protection,
                &root_payload,
                UnsealFactor::Password(password),
            )
        })?
    } else {
        if slot.group.requires(UnlockFactorKind::Password) {
            return Err(VaultError::Protection(
                "password unlock group has no password protection".to_owned(),
            ));
        }
        crate::timing::result("key_hierarchy", "decode_root_key", || {
            decode_key::<KEY_BYTES>(&root_payload, "vault root key")
        })?
    };
    let secrets = crate::timing::result("key_hierarchy", "open_installation_secrets", || {
        InstallationSecrets::open(
            stored.installation_id,
            stored.device_vault_id,
            vault_root_key,
            &stored.wrapped_installation_secrets,
        )
    })?;
    // The root-wrapped seed is the only copy of the signing identity, so
    // derive the public key from it and refuse a metadata file whose public
    // identity does not match before anything is opened with it.
    let signing_seed = crate::timing::result("key_hierarchy", "derive_signing_seed", || {
        secrets.signing_seed(stored.installation_id, stored.device_vault_id)
    })?;
    let public_signing_key =
        crate::timing::result("key_hierarchy", "derive_public_identity", || {
            Ok::<_, VaultError>(public_key_for_seed(&signing_seed))
        })?;
    if public_signing_key != stored.public_signing_key
        || DeviceKeyId::for_public_key(&public_signing_key) != stored.device_key_id
        || actor_id_for_public_key(&public_signing_key).as_slice() != stored.actor_id
    {
        return Err(VaultError::Protection(
            "device-signing key does not match installation identity".to_owned(),
        ));
    }
    Ok(UnsealedVault {
        public: stored.public(),
        secrets,
        initialize_store: false,
    })
}

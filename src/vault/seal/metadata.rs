//! Persisted vault metadata, validation, and bounded JSON I/O.

use std::fs;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::factor::NestedProtection;
use super::filesystem::path_error;
#[cfg(feature = "key-protection")]
use super::filesystem::write_new_private_file;
use super::policy::{UnlockFactorKind, UnlockGroup, UnlockPolicy};
use super::{KEY_BYTES, VaultMetadata, VaultPlatform};
use crate::vault::{DeviceKeyId, VaultError, VaultId, VaultResult};

pub(super) const VAULT_FILE: &str = "factorseal.json";
pub(super) const PENDING_VAULT_FILE: &str = ".factorseal.json.pending";
const VAULT_FORMAT: &str = "factorseal-vault";
// Version 3 replaces the single password/biometric tuple with a versioned
// unlock policy and one independently wrapped slot per OR alternative. There
// are no released vaults to migrate; older versions are rejected explicitly.
const VAULT_VERSION: u32 = 3;
const MAX_VAULT_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VaultFile {
    pub(super) format: String,
    pub(super) version: u32,
    pub(super) vault_id: VaultId,
    pub(super) device_key_id: DeviceKeyId,
    pub(super) public_signing_key: Vec<u8>,
    pub(super) actor_id: Vec<u8>,
    pub(super) platform: VaultPlatform,
    pub(super) hardware_backend: String,
    pub(super) unlock_policy: UnlockPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) preferred_unlock_group: Option<UnlockGroup>,
    pub(super) unlock_slots: Vec<UnlockSlot>,
    pub(super) key_epoch: u64,
    pub(super) created_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UnlockSlot {
    pub(super) group: UnlockGroup,
    pub(super) wrapping_key_label: String,
    pub(super) signing_key_label: String,
    pub(super) wrapped_data_key: Vec<u8>,
    pub(super) wrapped_signing_seed: Vec<u8>,
    pub(super) password_protection: Option<NestedProtection>,
}

#[cfg(feature = "key-protection")]
pub(super) struct NewVaultFile {
    pub(super) vault_id: VaultId,
    pub(super) device_key_id: DeviceKeyId,
    pub(super) public_signing_key: Vec<u8>,
    pub(super) actor_id: Vec<u8>,
    pub(super) platform: VaultPlatform,
    pub(super) hardware_backend: String,
    pub(super) unlock_policy: UnlockPolicy,
    pub(super) unlock_slots: Vec<UnlockSlot>,
    pub(super) created_at: u64,
}

impl VaultFile {
    #[cfg(feature = "key-protection")]
    pub(super) fn new(contents: NewVaultFile) -> Self {
        let NewVaultFile {
            vault_id,
            device_key_id,
            public_signing_key,
            actor_id,
            platform,
            hardware_backend,
            unlock_policy,
            unlock_slots,
            created_at,
        } = contents;
        Self {
            format: VAULT_FORMAT.to_owned(),
            version: VAULT_VERSION,
            vault_id,
            device_key_id,
            public_signing_key,
            actor_id,
            platform,
            hardware_backend,
            preferred_unlock_group: unlock_policy.groups().first().cloned(),
            unlock_policy,
            unlock_slots,
            key_epoch: 0,
            created_at,
        }
    }

    pub(super) fn public(&self) -> VaultMetadata {
        let preferred_unlock_group = self
            .preferred_unlock_group
            .clone()
            .or_else(|| self.unlock_policy.groups().first().cloned())
            .expect("validated unlock policies contain a group");
        VaultMetadata {
            vault_id: self.vault_id,
            device_key_id: self.device_key_id,
            public_signing_key: self.public_signing_key.clone(),
            actor_id: self.actor_id.clone(),
            platform: self.platform,
            hardware_backend: self.hardware_backend.clone(),
            unlock_policy: self.unlock_policy.clone(),
            preferred_unlock_group,
            key_epoch: self.key_epoch,
            created_at: self.created_at,
        }
    }

    pub(super) fn validate(&self) -> VaultResult<()> {
        if self.format != VAULT_FORMAT || self.version != VAULT_VERSION {
            return Err(VaultError::Protection(
                "unsupported vault metadata format or version".to_owned(),
            ));
        }
        if !platform_accepts_backend(self.platform, &self.hardware_backend)
            || self.actor_id.is_empty()
            || DeviceKeyId::for_public_key(&self.public_signing_key) != self.device_key_id
            || actor_id_for_public_key(&self.public_signing_key).as_slice() != self.actor_id
        {
            return Err(VaultError::Protection(
                "vault metadata is inconsistent".to_owned(),
            ));
        }
        self.unlock_policy.validate()?;
        if let Some(preferred) = &self.preferred_unlock_group
            && !self.unlock_policy.groups().contains(preferred)
        {
            return Err(VaultError::Protection(
                "preferred unlock group is not in the unlock policy".to_owned(),
            ));
        }
        if self.unlock_slots.len() != self.unlock_policy.groups().len() {
            return Err(VaultError::Protection(
                "unlock policy and wrapping slots do not match".to_owned(),
            ));
        }
        let mut labels = Vec::with_capacity(self.unlock_slots.len() * 2);
        for (slot, group) in self.unlock_slots.iter().zip(self.unlock_policy.groups()) {
            slot.validate()?;
            if &slot.group != group {
                return Err(VaultError::Protection(
                    "unlock policy and wrapping slot order do not match".to_owned(),
                ));
            }
            labels.push(slot.wrapping_key_label.as_str());
            labels.push(slot.signing_key_label.as_str());
        }
        labels.sort_unstable();
        if labels.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(VaultError::Protection(
                "unlock wrapping key labels must be distinct".to_owned(),
            ));
        }
        Ok(())
    }
}

impl UnlockSlot {
    fn validate(&self) -> VaultResult<()> {
        self.group.validate()?;
        if self.wrapping_key_label.is_empty()
            || self.signing_key_label.is_empty()
            || self.wrapping_key_label == self.signing_key_label
            || self.wrapped_data_key.is_empty()
            || self.wrapped_signing_seed.is_empty()
            || self.password_protection.is_some() != self.group.requires(UnlockFactorKind::Password)
        {
            return Err(VaultError::Protection(
                "unlock wrapping slot is inconsistent".to_owned(),
            ));
        }
        if let Some(protection) = &self.password_protection {
            protection.validate()?;
        }
        Ok(())
    }
}

pub(super) fn read_vault(root: &Path) -> VaultResult<VaultFile> {
    read_vault_file(&root.join(VAULT_FILE))
}

pub(super) fn read_pending_vault(root: &Path) -> VaultResult<VaultFile> {
    read_vault_file(&root.join(PENDING_VAULT_FILE))
}

fn read_vault_file(path: &Path) -> VaultResult<VaultFile> {
    let file = fs::File::open(path).map_err(|error| path_error(path, error))?;
    let metadata = file.metadata().map_err(|error| path_error(path, error))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_VAULT_FILE_BYTES {
        return Err(VaultError::Protection(
            "vault metadata is not a bounded regular file".to_owned(),
        ));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| VaultError::Protection("vault metadata does not fit in memory".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_VAULT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| path_error(path, error))?;
    if bytes.len() as u64 > MAX_VAULT_FILE_BYTES {
        return Err(VaultError::Protection(
            "vault metadata is not a bounded regular file".to_owned(),
        ));
    }
    let stored: VaultFile = serde_json::from_slice(&bytes)
        .map_err(|error| VaultError::Protection(error.to_string()))?;
    stored.validate()?;
    Ok(stored)
}

#[cfg(feature = "key-protection")]
pub(super) fn write_vault(root: &Path, stored: &VaultFile, pending: bool) -> VaultResult<()> {
    stored.validate()?;
    let path = root.join(if pending {
        PENDING_VAULT_FILE
    } else {
        VAULT_FILE
    });
    let bytes = serde_json::to_vec_pretty(stored)
        .map_err(|error| VaultError::Protection(error.to_string()))?;
    write_new_private_file(&path, &bytes)
}

pub(super) fn platform_accepts_backend(platform: VaultPlatform, backend: &str) -> bool {
    match platform {
        VaultPlatform::Android => {
            matches!(backend, "android-strongbox" | "android-trusted-environment")
        }
        VaultPlatform::Ios | VaultPlatform::Macos => backend == "secure-enclave",
        VaultPlatform::Linux | VaultPlatform::Windows => {
            matches!(backend, "tpm" | "tpm-bridge")
        }
        #[cfg(test)]
        VaultPlatform::Test => {
            matches!(
                backend,
                "secure-enclave"
                    | "android-strongbox"
                    | "android-trusted-environment"
                    | "tpm"
                    | "tpm-bridge"
            )
        }
    }
}

pub(super) fn actor_id_for_public_key(public_key: &[u8]) -> [u8; KEY_BYTES] {
    let mut digest = Sha256::new();
    digest.update(b"factorseal/automerge-actor/v1\0");
    digest.update(public_key);
    digest.finalize().into()
}

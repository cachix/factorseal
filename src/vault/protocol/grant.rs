use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::vault::{DocumentScope, SecretAddress, VaultError, VaultResult, VaultStore};

use super::CallerIdentity;
use super::wire::append_digest_bytes;

// Version 2 deliberately invalidates the former namespace-wide SecretSpec
// grants. Those grants predate project approvals and must not bypass them.
const GRANT_VERSION: u8 = 2;
const GRANT_DOCUMENT_NAMESPACE: &[u8] = b"factorseal/vault-grants/v2";
const GRANT_TARGET_DOMAIN: &[u8] = b"factorseal/grant-target/v2\0";

/// Permission persisted in one caller grant.
#[cfg(feature = "vault-store")]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantPermission {
    Get,
    Put,
    Delete,
    Clear,
    Seal,
    ManageApprovals,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessGrant {
    version: u8,
    caller_fingerprint: [u8; 32],
    target_digest: [u8; 32],
    permissions: BTreeSet<GrantPermission>,
    expires_at: Option<u64>,
}
#[derive(Clone, Copy)]
pub(super) enum GrantTarget<'a> {
    Namespace {
        scope: DocumentScope,
        namespace: &'a [u8],
    },
    Entry {
        scope: DocumentScope,
        namespace: &'a [u8],
        address: &'a SecretAddress,
    },
    Project {
        scope: DocumentScope,
        namespace: &'a [u8],
        project: &'a str,
    },
}

#[cfg(feature = "vault-store")]
#[derive(Clone, Copy)]
pub(super) struct GrantRequirement<'a> {
    pub scope: DocumentScope,
    pub namespace: &'a [u8],
    pub address: Option<&'a SecretAddress>,
    pub project: Option<&'a str>,
    pub permission: GrantPermission,
}

pub(super) fn store_grant(
    store: &VaultStore,
    caller: &CallerIdentity,
    target: GrantTarget<'_>,
    permissions: impl IntoIterator<Item = GrantPermission>,
    expires_at: Option<u64>,
    now: u64,
) -> VaultResult<()> {
    caller.validate()?;
    if expires_at.is_some_and(|deadline| deadline <= now) {
        return Err(VaultError::Expired);
    }
    let caller_fingerprint = caller.fingerprint();
    let target_digest = grant_target_digest(&target);
    let permissions: BTreeSet<_> = permissions.into_iter().collect();
    if permissions.is_empty() {
        return Err(VaultError::Protocol(
            "grant must contain a permission".to_owned(),
        ));
    }
    let grant = AccessGrant {
        version: GRANT_VERSION,
        caller_fingerprint,
        target_digest,
        permissions,
        expires_at,
    };
    let bytes = Zeroizing::new(
        serde_json::to_vec(&grant).map_err(|error| VaultError::Protocol(error.to_string()))?,
    );
    store.put_at(
        DocumentScope::DeviceLocal,
        GRANT_DOCUMENT_NAMESPACE,
        &grant_address(caller_fingerprint, target_digest)?,
        &bytes,
        expires_at,
    )
}

#[cfg(feature = "vault-store")]
pub(super) fn require_grant(
    store: &VaultStore,
    caller: &CallerIdentity,
    requirement: GrantRequirement<'_>,
    now: u64,
) -> VaultResult<()> {
    let GrantRequirement {
        scope,
        namespace,
        address,
        project,
        permission,
    } = requirement;
    let caller_fingerprint = caller.fingerprint();
    let mut targets = Vec::with_capacity(2);
    if let Some(address) = address {
        targets.push(grant_target_digest(&GrantTarget::Entry {
            scope,
            namespace,
            address,
        }));
    }
    if let Some(project) = project {
        targets.push(grant_target_digest(&GrantTarget::Project {
            scope,
            namespace,
            project,
        }));
    }
    targets.push(grant_target_digest(&GrantTarget::Namespace {
        scope,
        namespace,
    }));
    for target_digest in targets {
        let Some(bytes) = store.get_at(
            DocumentScope::DeviceLocal,
            GRANT_DOCUMENT_NAMESPACE,
            &grant_address(caller_fingerprint, target_digest)?,
            now,
        )?
        else {
            continue;
        };
        let grant: AccessGrant = serde_json::from_slice(&bytes)
            .map_err(|error| VaultError::Protocol(error.to_string()))?;
        if grant.version == GRANT_VERSION
            && grant.caller_fingerprint == caller_fingerprint
            && grant.target_digest == target_digest
            && grant.expires_at.is_none_or(|deadline| deadline > now)
            && grant.permissions.contains(&permission)
        {
            return Ok(());
        }
    }
    Err(VaultError::AuthorizationRequired)
}

#[cfg(feature = "vault-store")]
pub(super) fn grant_target_digest(target: &GrantTarget<'_>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(GRANT_TARGET_DOMAIN);
    match target {
        GrantTarget::Namespace { scope, namespace } => {
            digest.update([match scope {
                DocumentScope::DeviceLocal => 1,
                DocumentScope::DeviceCache => 3,
            }]);
            append_digest_bytes(&mut digest, namespace);
        }
        GrantTarget::Entry {
            scope,
            namespace,
            address,
        } => {
            digest.update([match scope {
                DocumentScope::DeviceLocal => 2,
                DocumentScope::DeviceCache => 4,
            }]);
            append_digest_bytes(&mut digest, namespace);
            append_digest_bytes(&mut digest, address.item().as_bytes());
            if let Some(field) = address.field() {
                digest.update([1]);
                append_digest_bytes(&mut digest, field.as_bytes());
            } else {
                digest.update([0]);
            }
        }
        GrantTarget::Project {
            scope,
            namespace,
            project,
        } => {
            digest.update([match scope {
                DocumentScope::DeviceLocal => 5,
                DocumentScope::DeviceCache => 6,
            }]);
            append_digest_bytes(&mut digest, namespace);
            append_digest_bytes(&mut digest, project.as_bytes());
        }
    }
    digest.finalize().into()
}

#[cfg(feature = "vault-store")]
pub(super) fn grant_address(
    caller_fingerprint: [u8; 32],
    target_digest: [u8; 32],
) -> VaultResult<SecretAddress> {
    SecretAddress::new(
        format!(
            "grant/{}/{}",
            URL_SAFE_NO_PAD.encode(caller_fingerprint),
            URL_SAFE_NO_PAD.encode(target_digest)
        ),
        None,
    )
}

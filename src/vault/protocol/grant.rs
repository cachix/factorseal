use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::vault::{
    DocumentKind, DocumentOperation, SecretAddress, VaultError, VaultResult, VaultStore,
};

use super::wire::append_digest_bytes;
use super::{CallerIdentity, Permission, PermissionState};

// Version 3 stores each operation independently so one permission's lifetime
// or revocation cannot affect another permission for the same target.
const GRANT_VERSION: u8 = 3;
const GRANT_DOCUMENT_NAMESPACE: &[u8] = b"factorseal/vault-grants/v3";
const GRANT_TARGET_DOMAIN: &[u8] = b"factorseal/grant-target/v3\0";
const PERMISSION_REGISTRY_VERSION: u8 = 1;

/// Permission persisted in one caller grant.
#[cfg(feature = "vault-store")]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantPermission {
    List,
    Get,
    Put,
    Delete,
    Clear,
    Seal,
    ManagePermissions,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessGrant {
    version: u8,
    caller_fingerprint: [u8; 32],
    target_digest: [u8; 32],
    permissions: BTreeSet<GrantPermission>,
    expires_at: Option<u64>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PermissionRegistry {
    version: u8,
    permissions: Vec<StoredPermission>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPermission {
    permission: Permission,
    caller_fingerprint: [u8; 32],
    target_digest: [u8; 32],
    grant_permission: GrantPermission,
}
#[derive(Clone, Copy)]
pub(super) enum GrantTarget<'a> {
    Kind {
        kind: DocumentKind,
    },
    Namespace {
        scope: DocumentKind,
        namespace: &'a [u8],
    },
    Entry {
        scope: DocumentKind,
        namespace: &'a [u8],
        address: &'a SecretAddress,
    },
    Project {
        scope: DocumentKind,
        namespace: &'a [u8],
        project: &'a str,
    },
}

#[cfg(feature = "vault-store")]
#[derive(Clone, Copy)]
pub(super) struct GrantRequirement<'a> {
    pub scope: DocumentKind,
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
    for permission in permissions {
        let grant = AccessGrant {
            version: GRANT_VERSION,
            caller_fingerprint,
            target_digest,
            permissions: BTreeSet::from([permission]),
            expires_at,
        };
        let bytes = Zeroizing::new(
            serde_json::to_vec(&grant).map_err(|error| VaultError::Protocol(error.to_string()))?,
        );
        store.put_at(
            DocumentKind::Authorization,
            GRANT_DOCUMENT_NAMESPACE,
            &grant_address(caller_fingerprint, target_digest, permission)?,
            &bytes,
            expires_at,
        )?;
    }
    Ok(())
}

pub(super) fn promote_permission(
    store: &VaultStore,
    caller: &CallerIdentity,
    target: GrantTarget<'_>,
    grant_permission: GrantPermission,
    permission: Permission,
    expires_at: Option<u64>,
    now: u64,
) -> VaultResult<()> {
    caller.validate()?;
    if expires_at.is_some_and(|deadline| deadline <= now) {
        return Err(VaultError::Expired);
    }
    if !matches!(permission.state, PermissionState::Granted { .. }) {
        return Err(VaultError::Protocol(
            "promoted permission must be granted".to_owned(),
        ));
    }
    let caller_fingerprint = caller.fingerprint();
    let target_digest = grant_target_digest(&target);
    let address = grant_address(caller_fingerprint, target_digest, grant_permission)?;
    let grant = AccessGrant {
        version: GRANT_VERSION,
        caller_fingerprint,
        target_digest,
        permissions: BTreeSet::from([grant_permission]),
        expires_at,
    };

    let mut registry = load_permission_registry(store, now)?;
    registry
        .permissions
        .retain(|stored| stored.permission.id != permission.id);
    registry.permissions.push(StoredPermission {
        permission,
        caller_fingerprint,
        target_digest,
        grant_permission,
    });
    mutate_grants(store, &grant, address, &registry, None)
}

pub(super) fn list_granted_permissions(
    store: &VaultStore,
    now: u64,
) -> VaultResult<Vec<Permission>> {
    let registry = load_permission_registry(store, now)?;
    Ok(registry
        .permissions
        .into_iter()
        .filter_map(|stored| match stored.permission.state {
            PermissionState::Granted { expires_at, .. }
                if expires_at.is_none_or(|deadline| deadline > now) =>
            {
                Some(stored.permission)
            }
            _ => None,
        })
        .collect())
}

pub(super) fn revoke_permission(store: &VaultStore, id: &str, now: u64) -> VaultResult<()> {
    let mut registry = load_permission_registry(store, now)?;
    let index = registry
        .permissions
        .iter()
        .position(|stored| stored.permission.id == id)
        .ok_or_else(|| VaultError::Protocol("permission is missing or expired".to_owned()))?;
    let removed = registry.permissions.remove(index);
    let address = grant_address(
        removed.caller_fingerprint,
        removed.target_digest,
        removed.grant_permission,
    )?;
    let bytes = store
        .get_at(
            DocumentKind::Authorization,
            GRANT_DOCUMENT_NAMESPACE,
            &address,
            now,
        )?
        .ok_or_else(|| VaultError::InvalidData("permission grant is missing".to_owned()))?;
    let grant: AccessGrant =
        serde_json::from_slice(&bytes).map_err(|error| VaultError::Protocol(error.to_string()))?;
    mutate_grants(store, &grant, address.clone(), &registry, Some(address))
}

fn permission_registry_address() -> VaultResult<SecretAddress> {
    SecretAddress::new("permissions", None)
}

fn load_permission_registry(store: &VaultStore, now: u64) -> VaultResult<PermissionRegistry> {
    let Some(bytes) = store.get_at(
        DocumentKind::Authorization,
        GRANT_DOCUMENT_NAMESPACE,
        &permission_registry_address()?,
        now,
    )?
    else {
        return Ok(PermissionRegistry {
            version: PERMISSION_REGISTRY_VERSION,
            permissions: Vec::new(),
        });
    };
    let registry: PermissionRegistry =
        serde_json::from_slice(&bytes).map_err(|error| VaultError::Protocol(error.to_string()))?;
    if registry.version != PERMISSION_REGISTRY_VERSION {
        return Err(VaultError::InvalidData(
            "unsupported permission registry version".to_owned(),
        ));
    }
    Ok(registry)
}

fn mutate_grants(
    store: &VaultStore,
    grant: &AccessGrant,
    grant_address: SecretAddress,
    registry: &PermissionRegistry,
    delete_grant: Option<SecretAddress>,
) -> VaultResult<()> {
    let registry_bytes = Zeroizing::new(
        serde_json::to_vec(&registry).map_err(|error| VaultError::Protocol(error.to_string()))?,
    );
    let mut operations = Vec::with_capacity(2);
    if let Some(address) = delete_grant {
        operations.push(DocumentOperation::Delete { address });
    } else {
        let grant_bytes = Zeroizing::new(
            serde_json::to_vec(&grant).map_err(|error| VaultError::Protocol(error.to_string()))?,
        );
        operations.push(DocumentOperation::Put {
            address: grant_address,
            value: grant_bytes,
            evict_at: grant.expires_at,
        });
    }
    operations.push(DocumentOperation::Put {
        address: permission_registry_address()?,
        value: registry_bytes,
        evict_at: None,
    });
    store.mutate(
        DocumentKind::Authorization,
        GRANT_DOCUMENT_NAMESPACE,
        operations,
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
    if let Some(project) = project
        && address.is_none_or(|address| {
            address.as_secret_spec().is_some_and(|address| {
                address
                    .project()
                    .is_none_or(|address_project| address_project == project)
            })
        })
    {
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
    targets.push(grant_target_digest(&GrantTarget::Kind { kind: scope }));
    for target_digest in targets {
        let Some(bytes) = store.get_at(
            DocumentKind::Authorization,
            GRANT_DOCUMENT_NAMESPACE,
            &grant_address(caller_fingerprint, target_digest, permission)?,
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
        GrantTarget::Kind { kind } => {
            digest.update([0, document_kind_tag(*kind)]);
        }
        GrantTarget::Namespace { scope, namespace } => {
            digest.update([1, document_kind_tag(*scope)]);
            append_digest_bytes(&mut digest, namespace);
        }
        GrantTarget::Entry {
            scope,
            namespace,
            address,
        } => {
            digest.update([2, document_kind_tag(*scope)]);
            append_digest_bytes(&mut digest, namespace);
            append_digest_bytes(&mut digest, address.storage_key().as_bytes());
        }
        GrantTarget::Project {
            scope,
            namespace,
            project,
        } => {
            digest.update([3, document_kind_tag(*scope)]);
            append_digest_bytes(&mut digest, namespace);
            append_digest_bytes(&mut digest, project.as_bytes());
        }
    }
    digest.finalize().into()
}

fn document_kind_tag(kind: DocumentKind) -> u8 {
    match kind {
        DocumentKind::Authorization => 1,
        DocumentKind::LinuxSecretService => 2,
        DocumentKind::LocalKeyring => 3,
        DocumentKind::SecretSpecProject => 4,
        DocumentKind::SecretSpecProviderCache => 5,
    }
}

#[cfg(feature = "vault-store")]
pub(super) fn grant_address(
    caller_fingerprint: [u8; 32],
    target_digest: [u8; 32],
    permission: GrantPermission,
) -> VaultResult<SecretAddress> {
    SecretAddress::new(
        format!(
            "grant/{}/{}/{}",
            URL_SAFE_NO_PAD.encode(caller_fingerprint),
            URL_SAFE_NO_PAD.encode(target_digest),
            permission_name(permission),
        ),
        None,
    )
}

fn permission_name(permission: GrantPermission) -> &'static str {
    match permission {
        GrantPermission::List => "list",
        GrantPermission::Get => "get",
        GrantPermission::Put => "put",
        GrantPermission::Delete => "delete",
        GrantPermission::Clear => "clear",
        GrantPermission::Seal => "seal",
        GrantPermission::ManagePermissions => "manage-permissions",
    }
}

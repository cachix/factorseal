use std::collections::{BTreeSet, HashSet};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::vault::{
    DocumentKind, DocumentOperation, Provenance, SecretAddress, ServiceReason, VaultError,
    VaultResult, VaultStore,
};

use super::wire::append_digest_bytes;
use super::{CallerIdentity, Permission, PermissionState};

// Version 3 stores each operation independently so one permission's lifetime
// or revocation cannot affect another permission for the same target.
const GRANT_VERSION: u8 = 3;
pub(super) const GRANT_DOCUMENT_NAMESPACE: &[u8] = b"factorseal/vault-grants/v3";
const GRANT_TARGET_DOMAIN: &[u8] = b"factorseal/grant-target/v3\0";
const PERMISSION_REGISTRY_VERSION: u8 = 1;
#[cfg(target_os = "linux")]
const EXCLUSIVE_HOLDER_VERSION: u8 = 1;

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

/// Which executable currently holds an exclusive grant on one target, so the
/// next holder can remove exactly the grants it supersedes.
#[cfg(target_os = "linux")]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExclusiveHolder {
    version: u8,
    caller_fingerprint: [u8; 32],
    permissions: BTreeSet<GrantPermission>,
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
        base_dir: Option<&'a str>,
    },
}

#[cfg(feature = "vault-store")]
#[derive(Clone, Copy)]
pub(super) struct GrantRequirement<'a> {
    pub scope: DocumentKind,
    /// `None` accepts only a grant on the whole document kind.
    pub namespace: Option<&'a [u8]>,
    pub address: Option<&'a SecretAddress>,
    pub project: Option<&'a str>,
    pub base_dir: Option<&'a str>,
    pub permission: GrantPermission,
}

#[cfg(all(test, feature = "hardware"))]
pub(super) fn store_grant(
    store: &VaultStore,
    caller: &CallerIdentity,
    target: GrantTarget<'_>,
    permissions: impl IntoIterator<Item = GrantPermission>,
    expires_at: Option<u64>,
    now: u64,
) -> VaultResult<()> {
    store_prepared_grants(
        store,
        prepare_grant(caller, target, permissions, expires_at, now)?,
        now,
    )
}

pub(super) struct PreparedGrant {
    address: SecretAddress,
    value: Zeroizing<Vec<u8>>,
    expires_at: Option<u64>,
}

pub(super) fn prepare_grant(
    caller: &CallerIdentity,
    target: GrantTarget<'_>,
    permissions: impl IntoIterator<Item = GrantPermission>,
    expires_at: Option<u64>,
    now: u64,
) -> VaultResult<Vec<PreparedGrant>> {
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
    let mut grants = Vec::with_capacity(permissions.len());
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
        grants.push(PreparedGrant {
            address: grant_address(caller_fingerprint, target_digest, permission)?,
            value: bytes,
            expires_at,
        });
    }
    Ok(grants)
}

pub(super) fn store_prepared_grants(
    store: &VaultStore,
    grants: Vec<PreparedGrant>,
    now: u64,
) -> VaultResult<()> {
    // Match sequential authorization when a batch mentions one grant twice:
    // the last requested lifetime wins, even if it matches the existing value.
    let mut seen = HashSet::new();
    let mut grants: Vec<_> = grants
        .into_iter()
        .rev()
        .filter(|grant| seen.insert(grant.address.clone()))
        .collect();
    grants.reverse();
    if grants.is_empty() {
        return Ok(());
    }
    let addresses: Vec<_> = grants.iter().map(|grant| grant.address.clone()).collect();
    let existing = crate::timing::result("grant_storage", "read_existing_permissions", || {
        store.get_many(
            DocumentKind::Authorization,
            GRANT_DOCUMENT_NAMESPACE,
            &addresses,
            now,
        )
    })?;
    let operations: Vec<_> = grants
        .into_iter()
        .zip(existing)
        .filter(|(grant, existing)| {
            existing
                .as_ref()
                .is_none_or(|value| value.as_slice() != grant.value.as_slice())
        })
        .map(|(grant, _)| DocumentOperation::Put {
            address: grant.address,
            value: grant.value,
            evict_at: grant.expires_at,
        })
        .collect();
    if !operations.is_empty() {
        crate::timing::result("grant_storage", "persist_permissions", || {
            store.mutate(
                DocumentKind::Authorization,
                GRANT_DOCUMENT_NAMESPACE,
                operations,
                &Provenance::service(ServiceReason::GrantStorage),
                now,
            )
        })?;
    }
    Ok(())
}

/// Make `caller` the only holder of `permissions` on `target`.
///
/// This is for the vault's own helper processes, whose identity is the digest
/// of their executable and therefore changes with every upgrade. The grants
/// of the executable that held the target before are removed in the same
/// generation, so a superseded build keeps no access, and nothing is written
/// when `caller` already holds exactly these permissions, so a restart does
/// not cost a generation. The grants never expire.
#[cfg(target_os = "linux")]
pub(super) fn store_exclusive_grant(
    store: &VaultStore,
    caller: &CallerIdentity,
    target: GrantTarget<'_>,
    permissions: impl IntoIterator<Item = GrantPermission>,
    now: u64,
) -> VaultResult<()> {
    caller.validate()?;
    let caller_fingerprint = caller.fingerprint();
    let target_digest = grant_target_digest(&target);
    let permissions: BTreeSet<_> = permissions.into_iter().collect();
    if permissions.is_empty() {
        return Err(VaultError::Protocol(
            "grant must contain a permission".to_owned(),
        ));
    }
    let holder_address = exclusive_holder_address(target_digest)?;
    let mut addresses = Vec::with_capacity(permissions.len() + 1);
    addresses.push(holder_address.clone());
    for permission in &permissions {
        addresses.push(grant_address(
            caller_fingerprint,
            target_digest,
            *permission,
        )?);
    }
    let mut records = store
        .get_many(
            DocumentKind::Authorization,
            GRANT_DOCUMENT_NAMESPACE,
            &addresses,
            now,
        )?
        .into_iter();
    let previous = records
        .next()
        .flatten()
        .map(|bytes| serde_json::from_slice::<ExclusiveHolder>(&bytes))
        .transpose()
        .map_err(|error| VaultError::Protocol(error.to_string()))?
        .filter(|holder| holder.version == EXCLUSIVE_HOLDER_VERSION);
    let already_held = previous.as_ref().is_some_and(|holder| {
        holder.caller_fingerprint == caller_fingerprint && holder.permissions == permissions
    }) && permissions.iter().zip(records).all(|(permission, record)| {
        record.is_some_and(|bytes| {
            serde_json::from_slice::<AccessGrant>(&bytes).is_ok_and(|grant| {
                grant.expires_at.is_none()
                    && grant_satisfies(&grant, caller_fingerprint, target_digest, *permission, now)
            })
        })
    });
    if already_held {
        return Ok(());
    }

    let mut operations = Vec::new();
    if let Some(previous) = &previous {
        for permission in &previous.permissions {
            if previous.caller_fingerprint != caller_fingerprint
                || !permissions.contains(permission)
            {
                operations.push(DocumentOperation::Delete {
                    address: grant_address(
                        previous.caller_fingerprint,
                        target_digest,
                        *permission,
                    )?,
                });
            }
        }
    }
    for permission in &permissions {
        let grant = AccessGrant {
            version: GRANT_VERSION,
            caller_fingerprint,
            target_digest,
            permissions: BTreeSet::from([*permission]),
            expires_at: None,
        };
        operations.push(DocumentOperation::Put {
            address: grant_address(caller_fingerprint, target_digest, *permission)?,
            value: Zeroizing::new(
                serde_json::to_vec(&grant)
                    .map_err(|error| VaultError::Protocol(error.to_string()))?,
            ),
            evict_at: None,
        });
    }
    let holder = ExclusiveHolder {
        version: EXCLUSIVE_HOLDER_VERSION,
        caller_fingerprint,
        permissions,
    };
    operations.push(DocumentOperation::Put {
        address: holder_address,
        value: Zeroizing::new(
            serde_json::to_vec(&holder).map_err(|error| VaultError::Protocol(error.to_string()))?,
        ),
        evict_at: None,
    });
    store.mutate(
        DocumentKind::Authorization,
        GRANT_DOCUMENT_NAMESPACE,
        operations,
        &Provenance::service(ServiceReason::GrantStorage),
        now,
    )
}

#[cfg(target_os = "linux")]
fn exclusive_holder_address(target_digest: [u8; 32]) -> VaultResult<SecretAddress> {
    SecretAddress::new(
        format!("holder/{}", URL_SAFE_NO_PAD.encode(target_digest)),
        None,
    )
}

pub(super) fn promote_permission(
    store: &VaultStore,
    caller: &CallerIdentity,
    target: GrantTarget<'_>,
    grant_permission: GrantPermission,
    permission: Permission,
    now: u64,
    provenance: &Provenance,
) -> VaultResult<()> {
    caller.validate()?;
    let PermissionState::Granted { expires_at, .. } = permission.state else {
        return Err(VaultError::Protocol(
            "promoted permission must be granted".to_owned(),
        ));
    };
    if expires_at.is_some_and(|deadline| deadline <= now) {
        return Err(VaultError::Expired);
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
    let grant_bytes = Zeroizing::new(
        serde_json::to_vec(&grant).map_err(|error| VaultError::Protocol(error.to_string()))?,
    );

    let mut registry = load_permission_registry(store, now)?;
    registry.permissions.retain(|stored| {
        stored.permission.id != permission.id && !is_expired(&stored.permission, now)
    });
    registry.permissions.push(StoredPermission {
        permission,
        caller_fingerprint,
        target_digest,
        grant_permission,
    });
    write_registry(
        store,
        &registry,
        vec![DocumentOperation::Put {
            address,
            value: grant_bytes,
            evict_at: grant.expires_at,
        }],
        provenance,
        now,
    )
}

pub(super) fn list_granted_permissions(
    store: &VaultStore,
    now: u64,
) -> VaultResult<Vec<Permission>> {
    let registry = load_permission_registry(store, now)?;
    Ok(registry
        .permissions
        .into_iter()
        .filter_map(|mut stored| match stored.permission.state {
            PermissionState::Granted { expires_at, .. }
                if expires_at.is_none_or(|deadline| deadline > now) =>
            {
                if stored.permission.scope.is_none() {
                    stored.permission.scope = legacy_permission_scope(
                        &stored.permission.application,
                        stored.target_digest,
                    );
                }
                Some(stored.permission)
            }
            _ => None,
        })
        .collect())
}

pub(super) fn revoke_permission(
    store: &VaultStore,
    id: &str,
    now: u64,
    provenance: &Provenance,
) -> VaultResult<()> {
    let mut registry = load_permission_registry(store, now)?;
    let index = registry
        .permissions
        .iter()
        .position(|stored| stored.permission.id == id)
        .ok_or_else(|| VaultError::Protocol("permission is missing or expired".to_owned()))?;
    let removed = registry.permissions.remove(index);
    registry
        .permissions
        .retain(|stored| !is_expired(&stored.permission, now));
    let address = grant_address(
        removed.caller_fingerprint,
        removed.target_digest,
        removed.grant_permission,
    )?;
    // The grant record may already have expired and been swept. Deleting an
    // absent record is a no-op, so revocation still removes the registry
    // entry either way.
    write_registry(
        store,
        &registry,
        vec![DocumentOperation::Delete { address }],
        provenance,
        now,
    )
}

fn is_expired(permission: &Permission, now: u64) -> bool {
    matches!(
        permission.state,
        PermissionState::Granted {
            expires_at: Some(deadline),
            ..
        } if deadline <= now
    )
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

/// Persist the registry together with `operations` as one generation.
fn write_registry(
    store: &VaultStore,
    registry: &PermissionRegistry,
    mut operations: Vec<DocumentOperation>,
    provenance: &Provenance,
    now: u64,
) -> VaultResult<()> {
    let registry_bytes = Zeroizing::new(
        serde_json::to_vec(&registry).map_err(|error| VaultError::Protocol(error.to_string()))?,
    );
    operations.push(DocumentOperation::Put {
        address: permission_registry_address()?,
        value: registry_bytes,
        evict_at: None,
    });
    store.mutate(
        DocumentKind::Authorization,
        GRANT_DOCUMENT_NAMESPACE,
        operations,
        provenance,
        now,
    )
}

#[cfg(feature = "vault-store")]
pub(super) fn require_grant_until(
    store: &VaultStore,
    caller: &CallerIdentity,
    requirement: GrantRequirement<'_>,
    now: u64,
) -> VaultResult<Option<u64>> {
    let GrantRequirement {
        scope,
        namespace,
        address,
        project,
        base_dir,
        permission,
    } = requirement;
    let caller_fingerprint = caller.fingerprint();
    let mut targets = Vec::with_capacity(4);
    if let Some(namespace) = namespace {
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
                base_dir,
            }));
        }
        targets.push(grant_target_digest(&GrantTarget::Namespace {
            scope,
            namespace,
        }));
    }
    targets.push(grant_target_digest(&GrantTarget::Kind { kind: scope }));
    // Every candidate grant is read from one load of the authorization
    // document, and the read never writes, so an authorization check costs
    // one document load and cannot commit a generation.
    let addresses = targets
        .iter()
        .map(|target_digest| grant_address(caller_fingerprint, *target_digest, permission))
        .collect::<VaultResult<Vec<_>>>()?;
    let records = store.get_many(
        DocumentKind::Authorization,
        GRANT_DOCUMENT_NAMESPACE,
        &addresses,
        now,
    )?;
    for (target_digest, bytes) in targets.into_iter().zip(records) {
        let Some(bytes) = bytes else {
            continue;
        };
        let grant: AccessGrant = serde_json::from_slice(&bytes)
            .map_err(|error| VaultError::Protocol(error.to_string()))?;
        if grant_satisfies(&grant, caller_fingerprint, target_digest, permission, now) {
            return Ok(grant.expires_at);
        }
    }
    Err(VaultError::AuthorizationRequired)
}

fn grant_satisfies(
    grant: &AccessGrant,
    caller_fingerprint: [u8; 32],
    target_digest: [u8; 32],
    permission: GrantPermission,
    now: u64,
) -> bool {
    grant.version == GRANT_VERSION
        && grant.caller_fingerprint == caller_fingerprint
        && grant.target_digest == target_digest
        && grant.expires_at.is_none_or(|deadline| deadline > now)
        && grant.permissions.contains(&permission)
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
            base_dir,
        } => {
            digest.update([
                if base_dir.is_some() { 4 } else { 3 },
                document_kind_tag(*scope),
            ]);
            append_digest_bytes(&mut digest, namespace);
            append_digest_bytes(&mut digest, project.as_bytes());
            if let Some(base_dir) = base_dir {
                append_digest_bytes(&mut digest, base_dir.as_bytes());
            }
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

/// Recover old summaries only when the actual stored target digest matches.
fn legacy_permission_scope(
    application: &super::VaultApplicationContext,
    target_digest: [u8; 32],
) -> Option<DocumentKind> {
    let project = application.project.as_deref()?;
    [
        DocumentKind::LinuxSecretService,
        DocumentKind::SecretSpecProviderCache,
    ]
    .into_iter()
    .find(|scope| {
        grant_target_digest(&GrantTarget::Project {
            scope: *scope,
            namespace: project.as_bytes(),
            project,
            base_dir: application.base_dir.as_deref(),
        }) == target_digest
    })
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    #[test]
    fn legacy_scope_uses_target_digest_not_project_name() {
        // Base directories must be absolute on the platform running the test.
        let root = if cfg!(windows) { "C:" } else { "" };
        let base_dir = format!("{root}/projects/mcp");
        let application = super::super::VaultApplicationContext::new(
            Some("secretspec/codex-mcp".into()),
            None,
            Some(base_dir.clone()),
            None,
        )
        .unwrap();
        for scope in [
            DocumentKind::LinuxSecretService,
            DocumentKind::SecretSpecProviderCache,
        ] {
            let digest = grant_target_digest(&GrantTarget::Project {
                scope,
                namespace: b"secretspec/codex-mcp",
                project: "secretspec/codex-mcp",
                base_dir: Some(base_dir.as_str()),
            });
            assert_eq!(legacy_permission_scope(&application, digest), Some(scope));
            let mut other_folder = application.clone();
            other_folder.base_dir = Some(format!("{root}/another/project"));
            assert_eq!(legacy_permission_scope(&other_folder, digest), None);
        }
        assert_eq!(legacy_permission_scope(&application, [0; 32]), None);
    }
}

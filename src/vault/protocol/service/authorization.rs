//! Durable and cache-scoped grant authorization workflows.

use std::time::Instant;

use crate::vault::{DocumentKind, VaultResult};

#[cfg(target_os = "linux")]
use super::super::grant::store_exclusive_grant;
use super::super::grant::{GrantTarget, PreparedGrant, prepare_grant, store_prepared_grants};
use super::super::{CallerIdentity, GrantPermission, WireSecretAddress};
use super::VaultService;
use super::approvals::PERMISSION_CONTROL_NAMESPACE;

/// Scope of a trusted, in-process grant authorization.
#[derive(Clone, Copy)]
pub enum GrantAuthorizationTarget<'a> {
    /// Every partition of one document kind.
    Kind { kind: DocumentKind },
    /// One namespace within a document kind.
    Namespace {
        scope: DocumentKind,
        namespace: &'a [u8],
    },
    /// One entry within a namespace.
    Entry {
        scope: DocumentKind,
        namespace: &'a [u8],
        address: &'a WireSecretAddress,
    },
    /// The internal permission-management namespace.
    PermissionManagement,
}

/// One grant in an atomic authorization batch. Unmentioned grants are retained.
pub struct GrantAuthorization<'a> {
    pub caller: &'a CallerIdentity,
    pub target: GrantAuthorizationTarget<'a>,
    pub permissions: &'a [GrantPermission],
    pub expires_at: Option<u64>,
}

use GrantAuthorizationTarget as AuthorizationTarget;

impl VaultService {
    /// Authorize several scopes or callers in one document generation, skipping
    /// unchanged grants. All requests are validated before any grant is written.
    /// Only trusted in-process hosts can invoke this; it is not an IPC action.
    pub fn authorize_batch(&self, grants: &[GrantAuthorization<'_>], now: u64) -> VaultResult<()> {
        let mut state = self.state.lock_live(Instant::now())?;
        let mut prepared = Vec::new();
        for grant in grants {
            prepared.extend(prepare_authorization(grant, now)?);
        }
        store_prepared_grants(state.store(), prepared, now)?;
        state.touch(now, Instant::now())
    }
    /// Permit an authenticated executable to operate on every partition of a
    /// semantic document kind. Reserved for Factorseal's own CLI.
    pub fn authorize_document_kind(
        &self,
        caller: &CallerIdentity,
        kind: DocumentKind,
        permissions: impl IntoIterator<Item = GrantPermission>,
        expires_at: Option<u64>,
        now: u64,
    ) -> VaultResult<()> {
        self.authorize(
            caller,
            AuthorizationTarget::Kind { kind },
            permissions,
            expires_at,
            now,
        )
    }

    /// Permit one authenticated Factorseal CLI executable to list and resolve
    /// pending approvals.
    pub fn authorize_permission_manager(
        &self,
        caller: &CallerIdentity,
        now: u64,
    ) -> VaultResult<()> {
        self.authorize(
            caller,
            AuthorizationTarget::Namespace {
                scope: DocumentKind::Authorization,
                namespace: PERMISSION_CONTROL_NAMESPACE,
            },
            [GrantPermission::ManagePermissions],
            None,
            now,
        )
    }
    /// Persist approval for one durable keyring entry.
    pub fn authorize_entry(
        &self,
        caller: &CallerIdentity,
        namespace: &[u8],
        address: &WireSecretAddress,
        permissions: impl IntoIterator<Item = GrantPermission>,
        expires_at: Option<u64>,
        now: u64,
    ) -> VaultResult<()> {
        self.authorize(
            caller,
            AuthorizationTarget::Entry {
                scope: DocumentKind::LocalKeyring,
                namespace,
                address,
            },
            permissions,
            expires_at,
            now,
        )
    }

    /// Persist approval for one disposable application-cache entry.
    pub fn authorize_cache_entry(
        &self,
        caller: &CallerIdentity,
        namespace: &[u8],
        address: &WireSecretAddress,
        permissions: impl IntoIterator<Item = GrantPermission>,
        expires_at: Option<u64>,
        now: u64,
    ) -> VaultResult<()> {
        self.authorize(
            caller,
            AuthorizationTarget::Entry {
                scope: DocumentKind::SecretSpecProviderCache,
                namespace,
                address,
            },
            permissions,
            expires_at,
            now,
        )
    }

    /// Persist approval for durable keyring namespace operations.
    pub fn authorize_namespace(
        &self,
        caller: &CallerIdentity,
        namespace: &[u8],
        permissions: impl IntoIterator<Item = GrantPermission>,
        expires_at: Option<u64>,
        now: u64,
    ) -> VaultResult<()> {
        self.authorize(
            caller,
            AuthorizationTarget::Namespace {
                scope: DocumentKind::LocalKeyring,
                namespace,
            },
            permissions,
            expires_at,
            now,
        )
    }

    /// Make the current build of the built-in Linux Secret Service adapter the
    /// sole holder of its namespace. A superseded build loses its grants in
    /// the same generation, and an unchanged build writes nothing.
    #[cfg(target_os = "linux")]
    pub(crate) fn authorize_secret_service_namespace(
        &self,
        caller: &CallerIdentity,
        namespace: &[u8],
        permissions: impl IntoIterator<Item = GrantPermission>,
        now: u64,
    ) -> VaultResult<()> {
        self.authorize_exclusive(
            caller,
            GrantTarget::Namespace {
                scope: DocumentKind::LinuxSecretService,
                namespace,
            },
            permissions,
            now,
        )
    }

    #[cfg(target_os = "linux")]
    fn authorize_exclusive(
        &self,
        caller: &CallerIdentity,
        target: GrantTarget<'_>,
        permissions: impl IntoIterator<Item = GrantPermission>,
        now: u64,
    ) -> VaultResult<()> {
        let mut state = self.state.lock_live(Instant::now())?;
        store_exclusive_grant(state.store(), caller, target, permissions, now)?;
        state.touch(now, Instant::now())
    }

    /// Persist approval for a disposable application-cache namespace.
    pub fn authorize_cache_namespace(
        &self,
        caller: &CallerIdentity,
        namespace: &[u8],
        permissions: impl IntoIterator<Item = GrantPermission>,
        expires_at: Option<u64>,
        now: u64,
    ) -> VaultResult<()> {
        self.authorize(
            caller,
            AuthorizationTarget::Namespace {
                scope: DocumentKind::SecretSpecProviderCache,
                namespace,
            },
            permissions,
            expires_at,
            now,
        )
    }

    fn authorize(
        &self,
        caller: &CallerIdentity,
        target: AuthorizationTarget<'_>,
        permissions: impl IntoIterator<Item = GrantPermission>,
        expires_at: Option<u64>,
        now: u64,
    ) -> VaultResult<()> {
        let permissions: Vec<_> = permissions.into_iter().collect();
        self.authorize_batch(
            &[GrantAuthorization {
                caller,
                target,
                permissions: &permissions,
                expires_at,
            }],
            now,
        )
    }
}

fn prepare_authorization(
    grant: &GrantAuthorization<'_>,
    now: u64,
) -> VaultResult<Vec<PreparedGrant>> {
    let entry;
    let target = match grant.target {
        AuthorizationTarget::Kind { kind } => GrantTarget::Kind { kind },
        AuthorizationTarget::Namespace { scope, namespace } => {
            GrantTarget::Namespace { scope, namespace }
        }
        AuthorizationTarget::PermissionManagement => GrantTarget::Namespace {
            scope: DocumentKind::Authorization,
            namespace: PERMISSION_CONTROL_NAMESPACE,
        },
        AuthorizationTarget::Entry {
            scope,
            namespace,
            address,
        } => {
            entry = address.resolve()?;
            GrantTarget::Entry {
                scope,
                namespace,
                address: &entry,
            }
        }
    };
    prepare_grant(
        grant.caller,
        target,
        grant.permissions.iter().copied(),
        grant.expires_at,
        now,
    )
}

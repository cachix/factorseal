//! Durable and cache-scoped grant authorization workflows.

use std::time::Instant;

use crate::vault::{DocumentScope, VaultResult};

use super::super::grant::{GrantTarget, store_grant};
use super::super::{CallerIdentity, GrantPermission, WireSecretAddress};
use super::VaultService;
use super::approvals::PERMISSION_CONTROL_NAMESPACE;

#[derive(Clone, Copy)]
enum AuthorizationTarget<'a> {
    Namespace {
        scope: DocumentScope,
        namespace: &'a [u8],
    },
    Entry {
        scope: DocumentScope,
        namespace: &'a [u8],
        address: &'a WireSecretAddress,
    },
}

impl VaultService {
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
                scope: DocumentScope::DeviceLocal,
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
                scope: DocumentScope::DeviceLocal,
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
                scope: DocumentScope::DeviceCache,
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
                scope: DocumentScope::DeviceLocal,
                namespace,
            },
            permissions,
            expires_at,
            now,
        )
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
                scope: DocumentScope::DeviceCache,
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
        let mut state = self.state.lock_live(Instant::now())?;
        match target {
            AuthorizationTarget::Namespace { scope, namespace } => store_grant(
                state.store(),
                caller,
                GrantTarget::Namespace { scope, namespace },
                permissions,
                expires_at,
                now,
            )?,
            AuthorizationTarget::Entry {
                scope,
                namespace,
                address,
            } => {
                let address = address.resolve()?;
                store_grant(
                    state.store(),
                    caller,
                    GrantTarget::Entry {
                        scope,
                        namespace,
                        address: &address,
                    },
                    permissions,
                    expires_at,
                    now,
                )?;
            }
        }
        state.touch(now, Instant::now())
    }
}

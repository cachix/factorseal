//! Action normalization and grant-checked vault operation execution.

use zeroize::Zeroizing;

use crate::vault::{
    DocumentKind, DocumentOperation, HistoryEntry, Provenance, SecretAddress, SecretSpecAddress,
    VaultError, VaultResult, VaultStore,
};

use super::super::grant::{GrantRequirement, require_grant};
use super::super::{
    CallerIdentity, GrantPermission, PermissionPrincipal, VaultAction, VaultMutation,
    VaultResponseBody, WireSecret, WireSecretAddress,
};
use super::approvals::PERMISSION_CONTROL_NAMESPACE;

pub(super) struct ScopedAction {
    pub(super) action: VaultAction,
    pub(super) scope: DocumentKind,
}

#[derive(Clone, Copy)]
struct ActionContext<'a> {
    store: &'a VaultStore,
    caller: &'a CallerIdentity,
    scope: DocumentKind,
    now: u64,
    provenance: &'a Provenance,
}

pub(super) fn execute_action(
    store: &VaultStore,
    caller: &CallerIdentity,
    action: VaultAction,
    now: u64,
    lease_deadlines: (u64, u64),
    provenance: &Provenance,
) -> VaultResult<(VaultResponseBody, bool)> {
    let ScopedAction { action, scope } = scope_action(action);
    let context = ActionContext {
        store,
        caller,
        scope,
        now,
        provenance,
    };
    match action {
        VaultAction::Status => {
            let (idle_deadline, absolute_deadline) = lease_deadlines;
            Ok((
                VaultResponseBody::Status {
                    installation_id: store.device().installation_id().to_string(),
                    device_vault_id: store.device().device_vault_id().to_string(),
                    device_key_id: store.device().device_key_id().to_string(),
                    hardware_backend: store.device().hardware_backend().to_owned(),
                    idle_deadline,
                    absolute_deadline,
                },
                false,
            ))
        }
        VaultAction::Get { namespace, address } => Ok((context.get(&namespace, &address)?, true)),
        VaultAction::Put {
            namespace,
            address,
            value,
            evict_at,
        } => Ok((context.put(&namespace, &address, &value, evict_at)?, true)),
        VaultAction::Mutate {
            namespace,
            mutations,
        } => Ok((context.mutate(&namespace, mutations)?, true)),
        VaultAction::Delete { namespace, address } => {
            Ok((context.delete(&namespace, &address)?, true))
        }
        VaultAction::Clear { namespace } => Ok((context.clear(&namespace)?, true)),
        VaultAction::Seal { namespace } => Ok((context.seal(&namespace)?, false)),
        VaultAction::GetProject { project, address }
        | VaultAction::GetCache { project, address } => {
            Ok((context.get_secret_spec(&project, &address)?, true))
        }
        VaultAction::PutProject {
            project,
            address,
            value,
        } => Ok((
            context.put_secret_spec(&project, &address, &value, None)?,
            true,
        )),
        VaultAction::PutCache {
            project,
            address,
            value,
            evict_at,
        } => Ok((
            context.put_secret_spec(&project, &address, &value, evict_at)?,
            true,
        )),
        VaultAction::DeleteProject { project, address }
        | VaultAction::DeleteCache { project, address } => {
            Ok((context.delete_secret_spec(&project, &address)?, true))
        }
        VaultAction::ListProjects { cursor, limit } => {
            Ok((context.list_projects(cursor.as_deref(), limit)?, true))
        }
        VaultAction::ListProjectAddresses {
            project,
            cursor,
            limit,
        } => Ok((
            context.list_project_addresses(&project, cursor.as_deref(), limit)?,
            true,
        )),
        VaultAction::ListHistory { .. }
        | VaultAction::ListProjectHistory { .. }
        | VaultAction::ListCacheHistory { .. } => Ok((context.history(action)?, true)),
        VaultAction::ClearCache { project } => Ok((context.clear(project.as_bytes())?, true)),
        VaultAction::SealCache { project } => Ok((context.seal(project.as_bytes())?, false)),
        VaultAction::ListPermissions
        | VaultAction::WaitPermissions { .. }
        | VaultAction::WaitPermission { .. }
        | VaultAction::ApprovePermission { .. }
        | VaultAction::DenyPermission { .. }
        | VaultAction::RevokePermission { .. } => {
            unreachable!("action was handled before execution")
        }
    }
}

impl ActionContext<'_> {
    fn require(
        self,
        namespace: &[u8],
        address: Option<&SecretAddress>,
        permission: GrantPermission,
    ) -> VaultResult<()> {
        require_grant(
            self.store,
            self.caller,
            GrantRequirement {
                scope: self.scope,
                namespace: Some(namespace),
                address,
                project: None,
                permission,
            },
            self.now,
        )
    }

    fn require_project(
        self,
        project: &str,
        address: Option<&SecretAddress>,
        permission: GrantPermission,
    ) -> VaultResult<()> {
        require_grant(
            self.store,
            self.caller,
            GrantRequirement {
                scope: self.scope,
                namespace: Some(project.as_bytes()),
                address,
                project: Some(project),
                permission,
            },
            self.now,
        )
    }

    /// Only a grant on the whole kind satisfies a kind-wide operation; no
    /// namespace grant, whatever its name, can stand in for one.
    fn require_kind(self, permission: GrantPermission) -> VaultResult<()> {
        require_grant(
            self.store,
            self.caller,
            GrantRequirement {
                scope: self.scope,
                namespace: None,
                address: None,
                project: None,
                permission,
            },
            self.now,
        )
    }

    fn get(self, namespace: &[u8], address: &WireSecretAddress) -> VaultResult<VaultResponseBody> {
        let address = address.resolve()?;
        self.require(namespace, Some(&address), GrantPermission::Get)?;
        let value = self
            .store
            .get_at(self.scope, namespace, &address, self.now)?
            .map(|value| WireSecret::new(value.to_vec()));
        Ok(VaultResponseBody::Secret { value })
    }

    fn get_secret_spec(
        self,
        project: &str,
        address: &SecretSpecAddress,
    ) -> VaultResult<VaultResponseBody> {
        let address = SecretAddress::secret_spec(address.clone())?;
        let namespace = project.as_bytes();
        self.require_project(project, Some(&address), GrantPermission::Get)?;
        let value = self
            .store
            .get_at(self.scope, namespace, &address, self.now)?
            .map(|value| WireSecret::new(value.to_vec()));
        Ok(VaultResponseBody::Secret { value })
    }

    fn put(
        self,
        namespace: &[u8],
        address: &WireSecretAddress,
        value: &WireSecret,
        evict_at: Option<u64>,
    ) -> VaultResult<VaultResponseBody> {
        let address = address.resolve()?;
        self.require(namespace, Some(&address), GrantPermission::Put)?;
        validate_evict_at(evict_at, self.now)?;
        self.store.put_at(
            self.scope,
            namespace,
            &address,
            value.expose(),
            evict_at,
            self.provenance,
            self.now,
        )?;
        Ok(VaultResponseBody::Stored)
    }

    fn put_secret_spec(
        self,
        project: &str,
        address: &SecretSpecAddress,
        value: &WireSecret,
        evict_at: Option<u64>,
    ) -> VaultResult<VaultResponseBody> {
        let address = SecretAddress::secret_spec(address.clone())?;
        let namespace = project.as_bytes();
        self.require_project(project, Some(&address), GrantPermission::Put)?;
        validate_evict_at(evict_at, self.now)?;
        self.store.put_at(
            self.scope,
            namespace,
            &address,
            value.expose(),
            evict_at,
            self.provenance,
            self.now,
        )?;
        Ok(VaultResponseBody::Stored)
    }

    fn mutate(
        self,
        namespace: &[u8],
        mutations: Vec<VaultMutation>,
    ) -> VaultResult<VaultResponseBody> {
        let operations = self.prepare_mutations(namespace, mutations)?;
        self.store
            .mutate(self.scope, namespace, operations, self.provenance, self.now)?;
        Ok(VaultResponseBody::Mutated)
    }

    fn delete(
        self,
        namespace: &[u8],
        address: &WireSecretAddress,
    ) -> VaultResult<VaultResponseBody> {
        let address = address.resolve()?;
        self.require(namespace, Some(&address), GrantPermission::Delete)?;
        let existed =
            self.store
                .delete(self.scope, namespace, &address, self.provenance, self.now)?;
        Ok(VaultResponseBody::Deleted { existed })
    }

    fn delete_secret_spec(
        self,
        project: &str,
        address: &SecretSpecAddress,
    ) -> VaultResult<VaultResponseBody> {
        let address = SecretAddress::secret_spec(address.clone())?;
        let namespace = project.as_bytes();
        self.require_project(project, Some(&address), GrantPermission::Delete)?;
        let existed =
            self.store
                .delete(self.scope, namespace, &address, self.provenance, self.now)?;
        Ok(VaultResponseBody::Deleted { existed })
    }

    fn clear(self, namespace: &[u8]) -> VaultResult<VaultResponseBody> {
        self.require(namespace, None, GrantPermission::Clear)?;
        let entries = self
            .store
            .clear(self.scope, namespace, self.provenance, self.now)?;
        Ok(VaultResponseBody::Cleared { entries })
    }

    fn list_projects(self, cursor: Option<&str>, limit: u16) -> VaultResult<VaultResponseBody> {
        self.require_kind(GrantPermission::List)?;
        let page = self.store.list_projects(cursor, limit, self.now)?;
        Ok(VaultResponseBody::Projects {
            projects: page.items,
            next_cursor: page.next_cursor,
        })
    }

    fn list_project_addresses(
        self,
        project: &str,
        cursor: Option<&str>,
        limit: u16,
    ) -> VaultResult<VaultResponseBody> {
        self.require_project(project, None, GrantPermission::List)?;
        let page = self
            .store
            .list_project_addresses(project, cursor, limit, self.now)?;
        Ok(VaultResponseBody::ProjectAddresses {
            addresses: page.items,
            next_cursor: page.next_cursor,
        })
    }

    fn history(self, action: VaultAction) -> VaultResult<VaultResponseBody> {
        match action {
            VaultAction::ListHistory {
                namespace,
                address,
                cursor,
                limit,
            } => {
                let address = address
                    .as_ref()
                    .map(WireSecretAddress::resolve)
                    .transpose()?;
                self.require(&namespace, None, GrantPermission::List)?;
                self.list_history(&namespace, address.as_ref(), cursor, limit)
            }
            VaultAction::ListProjectHistory {
                project,
                address,
                cursor,
                limit,
            }
            | VaultAction::ListCacheHistory {
                project,
                address,
                cursor,
                limit,
            } => {
                let address = address.map(SecretAddress::secret_spec).transpose()?;
                self.require_project(&project, None, GrantPermission::List)?;
                self.list_history(project.as_bytes(), address.as_ref(), cursor, limit)
            }
            _ => unreachable!("only history actions reach this helper"),
        }
    }

    /// The caller has already been authorized to list the namespace or
    /// project; an address only narrows the page.
    fn list_history(
        self,
        namespace: &[u8],
        address: Option<&SecretAddress>,
        before_seq: Option<u64>,
        limit: u16,
    ) -> VaultResult<VaultResponseBody> {
        let page = self
            .store
            .list_history(self.scope, namespace, address, before_seq, limit)?;
        Ok(VaultResponseBody::History {
            entries: self.redact_history(page.items)?,
            next_cursor: page.next_before_seq,
        })
    }

    /// Who performed a change is identity data about another application.
    /// A permission manager sees every principal, the way `ListPermissions`
    /// shows them; any other reader sees its own entries in full and other
    /// callers' entries with the principal and declared context withheld.
    fn redact_history(self, mut entries: Vec<HistoryEntry>) -> VaultResult<Vec<HistoryEntry>> {
        let manager = match require_grant(
            self.store,
            self.caller,
            GrantRequirement {
                scope: DocumentKind::Authorization,
                namespace: Some(PERMISSION_CONTROL_NAMESPACE),
                address: None,
                project: None,
                permission: GrantPermission::ManagePermissions,
            },
            self.now,
        ) {
            Ok(()) => true,
            Err(VaultError::AuthorizationRequired) => false,
            Err(error) => return Err(error),
        };
        if manager {
            return Ok(entries);
        }
        let reader = PermissionPrincipal::from(self.caller);
        for entry in &mut entries {
            if matches!(&entry.provenance, Provenance::Caller { principal, .. } if *principal != reader)
            {
                entry.provenance = Provenance::Redacted;
            }
        }
        Ok(entries)
    }

    fn seal(self, namespace: &[u8]) -> VaultResult<VaultResponseBody> {
        self.require(namespace, None, GrantPermission::Seal)?;
        self.store.seal();
        Ok(VaultResponseBody::Sealed)
    }

    fn prepare_mutations(
        self,
        namespace: &[u8],
        mutations: Vec<VaultMutation>,
    ) -> VaultResult<Vec<DocumentOperation>> {
        let mut operations = Vec::with_capacity(mutations.len());
        for mutation in mutations {
            match mutation {
                VaultMutation::Put {
                    address,
                    value,
                    evict_at,
                } => {
                    let address = address.resolve()?;
                    self.require(namespace, Some(&address), GrantPermission::Put)?;
                    validate_evict_at(evict_at, self.now)?;
                    operations.push(DocumentOperation::Put {
                        address,
                        value: Zeroizing::new(value.expose().to_vec()),
                        evict_at,
                    });
                }
                VaultMutation::Delete { address } => {
                    let address = address.resolve()?;
                    self.require(namespace, Some(&address), GrantPermission::Delete)?;
                    operations.push(DocumentOperation::Delete { address });
                }
            }
        }
        Ok(operations)
    }
}

pub(super) fn scope_action(action: VaultAction) -> ScopedAction {
    let scope = match action {
        VaultAction::GetProject { .. }
        | VaultAction::PutProject { .. }
        | VaultAction::DeleteProject { .. }
        | VaultAction::ListProjects { .. }
        | VaultAction::ListProjectAddresses { .. }
        | VaultAction::ListProjectHistory { .. } => DocumentKind::SecretSpecProject,
        VaultAction::GetCache { .. }
        | VaultAction::PutCache { .. }
        | VaultAction::DeleteCache { .. }
        | VaultAction::ClearCache { .. }
        | VaultAction::SealCache { .. }
        | VaultAction::ListCacheHistory { .. } => DocumentKind::SecretSpecProviderCache,
        VaultAction::Get { ref namespace, .. }
        | VaultAction::Put { ref namespace, .. }
        | VaultAction::Mutate { ref namespace, .. }
        | VaultAction::Delete { ref namespace, .. }
        | VaultAction::Clear { ref namespace }
        | VaultAction::Seal { ref namespace }
        | VaultAction::ListHistory { ref namespace, .. }
            if namespace == b"factorseal/secret-service/v1" =>
        {
            DocumentKind::LinuxSecretService
        }
        _ => DocumentKind::LocalKeyring,
    };
    ScopedAction { action, scope }
}

/// A deadline equal to the vault's whole-second clock is a valid
/// immediately-expired write. This lets sub-second upstream TTLs round down
/// without exceeding their bound.
pub(super) fn validate_evict_at(evict_at: Option<u64>, now: u64) -> VaultResult<()> {
    if evict_at.is_some_and(|deadline| deadline < now) {
        return Err(VaultError::Expired);
    }
    Ok(())
}

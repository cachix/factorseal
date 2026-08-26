//! Action normalization and grant-checked vault operation execution.

use zeroize::Zeroizing;

use crate::vault::{
    DocumentOperation, DocumentScope, SecretAddress, VaultError, VaultResult, VaultStore,
};

use super::super::grant::require_grant;
use super::super::{
    CallerIdentity, GrantPermission, VaultAction, VaultMutation, VaultResponseBody, WireSecret,
    WireSecretAddress,
};

pub(super) struct ScopedAction {
    pub(super) action: VaultAction,
    pub(super) scope: DocumentScope,
}

#[derive(Clone, Copy)]
struct ActionContext<'a> {
    store: &'a VaultStore,
    caller: &'a CallerIdentity,
    scope: DocumentScope,
    now: u64,
}

pub(super) fn execute_action(
    store: &VaultStore,
    caller: &CallerIdentity,
    action: VaultAction,
    now: u64,
    lease_deadlines: (u64, u64),
) -> VaultResult<(VaultResponseBody, bool)> {
    let ScopedAction { action, scope } = scope_action(action);
    let context = ActionContext {
        store,
        caller,
        scope,
        now,
    };
    match action {
        VaultAction::Status => {
            let (idle_deadline, absolute_deadline) = lease_deadlines;
            Ok((
                VaultResponseBody::Status {
                    vault_id: store.device().vault_id().to_string(),
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
        VaultAction::GetCache { .. }
        | VaultAction::PutCache { .. }
        | VaultAction::DeleteCache { .. }
        | VaultAction::ClearCache { .. }
        | VaultAction::SealCache { .. } => unreachable!("cache action was normalized"),
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
            self.scope,
            namespace,
            address,
            permission,
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
        self.store
            .put_at(self.scope, namespace, &address, value.expose(), evict_at)?;
        Ok(VaultResponseBody::Stored)
    }

    fn mutate(
        self,
        namespace: &[u8],
        mutations: Vec<VaultMutation>,
    ) -> VaultResult<VaultResponseBody> {
        let operations = self.prepare_mutations(namespace, mutations)?;
        self.store.mutate(self.scope, namespace, operations)?;
        Ok(VaultResponseBody::Mutated)
    }

    fn delete(
        self,
        namespace: &[u8],
        address: &WireSecretAddress,
    ) -> VaultResult<VaultResponseBody> {
        let address = address.resolve()?;
        self.require(namespace, Some(&address), GrantPermission::Delete)?;
        let existed = self.store.delete(self.scope, namespace, &address)?;
        Ok(VaultResponseBody::Deleted { existed })
    }

    fn clear(self, namespace: &[u8]) -> VaultResult<VaultResponseBody> {
        self.require(namespace, None, GrantPermission::Clear)?;
        let entries = self.store.clear(self.scope, namespace)?;
        Ok(VaultResponseBody::Cleared { entries })
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
    let (action, scope) = match action {
        VaultAction::GetCache { namespace, address } => (
            VaultAction::Get { namespace, address },
            DocumentScope::DeviceCache,
        ),
        VaultAction::PutCache {
            namespace,
            address,
            value,
            evict_at,
        } => (
            VaultAction::Put {
                namespace,
                address,
                value,
                evict_at,
            },
            DocumentScope::DeviceCache,
        ),
        VaultAction::DeleteCache { namespace, address } => (
            VaultAction::Delete { namespace, address },
            DocumentScope::DeviceCache,
        ),
        VaultAction::ClearCache { namespace } => {
            (VaultAction::Clear { namespace }, DocumentScope::DeviceCache)
        }
        VaultAction::SealCache { namespace } => {
            (VaultAction::Seal { namespace }, DocumentScope::DeviceCache)
        }
        action => (action, DocumentScope::DeviceLocal),
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

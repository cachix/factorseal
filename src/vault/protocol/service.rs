use std::path::Path;
use std::time::{Duration, Instant};

use crate::vault::{DocumentKind, Provenance, UnsealedVault, VaultError, VaultResult, VaultStore};

use super::wire::PROTOCOL_VERSION;
#[cfg(all(test, feature = "hardware"))]
use super::wire::{MAX_MESSAGE_BYTES, REQUEST_ID_BYTES};
use super::{
    CallerIdentity, GrantPermission, UnsealLeasePolicy, VaultAction, VaultRequest, VaultResponse,
    VaultResponseBody, VaultResponseError, VaultResponseErrorCode,
};
#[cfg(all(test, feature = "hardware"))]
use super::{
    CallerPlatform, PermissionChange, PermissionState, PermissionWaitStatus, RequestId,
    VaultApplicationContext, VaultMutation, WireSecret, WireSecretAddress,
};

#[cfg(feature = "vault-store")]
mod actions;
#[cfg(feature = "vault-store")]
mod approvals;
#[cfg(feature = "vault-store")]
mod authorization;
pub use authorization::{GrantAuthorization, GrantAuthorizationTarget};
#[cfg(feature = "vault-store")]
mod state;
mod time;

use time::{RequestTime, tighten};

#[cfg(feature = "vault-store")]
use super::grant::GrantRequirement;
#[cfg(all(test, feature = "hardware"))]
use actions::{ScopedAction, scope_action};
#[cfg(feature = "vault-store")]
use actions::{execute_action, validate_evict_at};
#[cfg(feature = "vault-store")]
use approvals::{ApprovalCandidate, PERMISSION_CONTROL_NAMESPACE};
#[cfg(feature = "vault-store")]
use state::{LiveStateGuard, ServiceState};

#[cfg(feature = "vault-store")]
struct RequestFailure {
    error: VaultError,
    interaction: Option<super::VaultInteractionReference>,
}

#[cfg(feature = "vault-store")]
impl From<VaultError> for RequestFailure {
    fn from(error: VaultError) -> Self {
        Self {
            error,
            interaction: None,
        }
    }
}

/// Shared request processor used behind every platform transport.
#[cfg(feature = "vault-store")]
pub struct VaultService {
    state: ServiceState,
}

#[cfg(feature = "vault-store")]
impl VaultService {
    /// Open the encrypted store and create the sole request-processing service.
    ///
    /// The raw store deliberately remains internal so every application action
    /// goes through grant checks, replay protection, and lease enforcement.
    pub fn open(
        root: impl AsRef<Path>,
        unsealed: UnsealedVault,
        now: u64,
        policy: UnsealLeasePolicy,
    ) -> VaultResult<Self> {
        let store = crate::timing::result("vault_service", "open_store_worker", || {
            VaultStore::open(root, unsealed)
        })?;
        crate::timing::result("vault_service", "initialize_service_state", || {
            Self::new(store, now, policy)
        })
    }

    pub(crate) fn new(store: VaultStore, now: u64, policy: UnsealLeasePolicy) -> VaultResult<Self> {
        Ok(Self {
            state: ServiceState::new(store, now, policy)?,
        })
    }

    #[cfg(all(test, feature = "hardware"))]
    fn purge_count(&self) -> usize {
        self.state.purge_count()
    }

    /// Panic while holding the request-state mutex, the way a panicking
    /// request does. Callers wrap this in `catch_unwind`.
    #[cfg(all(test, feature = "hardware"))]
    pub(crate) fn poison_state_for_test(&self) {
        self.state.poison_for_test();
    }

    /// Handle one already-decoded request for a transport-authenticated caller.
    #[must_use]
    pub fn handle(
        &self,
        caller: &CallerIdentity,
        request: VaultRequest,
        now: u64,
    ) -> VaultResponse {
        self.handle_at(caller, request, now, Instant::now())
    }

    fn handle_at(
        &self,
        caller: &CallerIdentity,
        request: VaultRequest,
        now: u64,
        monotonic_now: Instant,
    ) -> VaultResponse {
        let request_id = request.request_id();
        let clock = RequestTime::new(now, monotonic_now);
        let valid_until = std::cell::Cell::new(None);
        let result = self
            .handle_inner(caller, request, clock, &valid_until)
            .map_err(|failure| {
                use crate::security::events::{Kind, record};
                match &failure.error {
                    VaultError::AuthorizationRequired => record(Kind::AuthorizationDenied),
                    VaultError::ApprovalLimited => record(Kind::ApprovalLimited),
                    VaultError::Replay => record(Kind::ReplayRejected),
                    VaultError::Signature | VaultError::InvalidData(_) => {
                        record(Kind::IntegrityFailure);
                    }
                    VaultError::Protocol(_) => record(Kind::MalformedRequest),
                    _ => {}
                }
                response_error_with_interaction(&failure.error, failure.interaction)
            });
        let result = match result {
            Ok(VaultResponseBody::Sealed) => {
                self.state.seal();
                Ok(VaultResponseBody::Sealed)
            }
            _ if self.state.check_live(clock.sample().1).is_err() => {
                Err(response_error(&VaultError::Sealed))
            }
            Ok(_) if clock.check(valid_until.get()).is_err() => {
                Err(response_error(&VaultError::Expired))
            }
            result => result,
        };
        let delivery_deadline = if matches!(&result, Ok(body) if !matches!(body, VaultResponseBody::Sealed))
        {
            self.state
                .deadline()
                .ok()
                .flatten()
                .into_iter()
                .chain(valid_until.get().map(|deadline| clock.deadline(deadline)))
                .min()
        } else {
            // Error and seal acknowledgements contain no released secrets.
            None
        };
        VaultResponse {
            version: PROTOCOL_VERSION,
            request_id,
            result,
            delivery_deadline,
            delivery_cancelled: delivery_deadline.map(|_| self.state.seal_signal()),
        }
    }

    /// Run storage eviction and enforce the lease even when no request arrives.
    ///
    /// Returns `true` once the service has sealed and should stop accepting
    /// connections. Platform event loops call this from their bounded timer.
    pub fn expire_if_needed(&self, now: u64) -> VaultResult<bool> {
        self.expire_if_needed_at(now, Instant::now())
    }

    fn expire_if_needed_at(&self, now: u64, monotonic_now: Instant) -> VaultResult<bool> {
        self.state.expire_if_needed(now, monotonic_now)
    }

    /// Logout, suspend, and shutdown hooks use the same immediate seal path.
    pub fn seal(&self) -> VaultResult<()> {
        self.state.seal();
        Ok(())
    }

    pub(crate) fn is_seal_complete(&self) -> bool {
        self.state.is_seal_complete()
    }

    /// Native desktop agents own their process and terminate if a wedged
    /// operation prevents timely key teardown. Library embedders do not opt in.
    pub(crate) fn enable_emergency_exit(&self) {
        self.state.enable_emergency_exit();
    }

    #[allow(clippy::too_many_lines)]
    fn handle_inner(
        &self,
        caller: &CallerIdentity,
        request: VaultRequest,
        clock: RequestTime,
        valid_until: &std::cell::Cell<Option<u64>>,
    ) -> Result<VaultResponseBody, RequestFailure> {
        caller.validate()?;
        request.validate()?;
        let application = request.application().cloned();
        let approval =
            ApprovalCandidate::for_request(caller, application.as_ref(), &request.action);
        let provenance = Provenance::caller(caller, application.as_ref());
        let mut state = crate::timing::result("vault_request", "lock_live", || {
            self.state.lock_live(clock.sample().1)
        })?;
        let now = clock.wall();
        state.consume(request.request_id())?;
        let result = match request.action {
            VaultAction::ExportRevision => {
                require_live_manager(&state, caller, clock, valid_until)?;
                state.store().purge_expired_at(now)?;
                return Ok(VaultResponseBody::ExportRevision {
                    revision: state.store().export_revision()?,
                });
            }
            VaultAction::ListVaultEntries { cursor, limit } => {
                return inventory(
                    &mut state,
                    caller,
                    cursor.as_deref(),
                    limit,
                    clock,
                    valid_until,
                );
            }
            VaultAction::ExportVaultEntry { entry } => {
                require_live_manager(&state, caller, clock, valid_until)?;
                let secret = state
                    .store()
                    .export_at(entry.document_kind, &entry.partition, &entry.address, now)?
                    .ok_or_else(|| {
                        VaultError::InvalidData("vault entry disappeared during export".to_owned())
                    })?;
                tighten(valid_until, secret.expires_at);
                let (now, monotonic_now) = clock.sample();
                clock.check(valid_until.get())?;
                state.touch(now, monotonic_now)?;
                let value = if entry.document_kind == DocumentKind::LinuxSecretService {
                    let index = secret_service_index(state.store(), now)?;
                    let item = index
                        .items
                        .into_iter()
                        .find(|item| item.address().is_ok_and(|address| address == entry.address))
                        .ok_or_else(|| {
                            VaultError::InvalidData("keyring value has no index entry".to_owned())
                        })?;
                    crate::vault::secret_service_data::PortableItem::new(
                        item,
                        super::WireSecret::from_locked(secret.value),
                    )
                    .encode()?
                } else {
                    super::WireSecret::from_locked(secret.value)
                };
                return Ok(VaultResponseBody::VaultEntrySecret {
                    value,
                    evict_at: secret.expires_at,
                });
            }
            VaultAction::ImportVaultEntry {
                mut entry,
                mut value,
                evict_at,
                replace_existing,
            } => {
                require_live_manager(&state, caller, clock, valid_until)?;
                validate_evict_at(evict_at, now)?;
                if entry.document_kind == DocumentKind::LinuxSecretService {
                    let status = import_secret_service_item(
                        state.store(),
                        &entry,
                        &value,
                        evict_at,
                        replace_existing,
                        &provenance,
                        now,
                    )?;
                    let (now, monotonic_now) = clock.sample();
                    clock.check(valid_until.get())?;
                    state.touch(now, monotonic_now)?;
                    return Ok(VaultResponseBody::VaultEntryImported { status });
                }
                if entry.document_kind == DocumentKind::LocalKeyring
                    && entry.partition == crate::personal::PERSONAL_SECRET_NAMESPACE
                {
                    let (title, field) = entry
                        .address
                        .as_local()
                        .ok_or_else(|| VaultError::Protocol("invalid personal address".into()))?;
                    if field.is_some() || evict_at.is_some() {
                        return Err(VaultError::Protocol(
                            "personal items cannot have fields or expiry".into(),
                        )
                        .into());
                    }
                    let item = crate::personal::PersonalSecret::decode(title, value.expose())
                        .map_err(|_| VaultError::Protocol("invalid personal item".into()))?;
                    entry.address = crate::vault::SecretAddress::new(item.id.clone(), None)?;
                    value = super::WireSecret::new(
                        item.encode()
                            .map_err(|_| VaultError::Protocol("invalid personal item".into()))?
                            .to_vec(),
                    )?;
                }
                let existing = state.store().get_at(
                    entry.document_kind,
                    &entry.partition,
                    &entry.address,
                    now,
                )?;
                let status = if existing.is_some() && !replace_existing {
                    super::VaultEntryImportStatus::KeptExisting
                } else {
                    state.store().put_at(
                        entry.document_kind,
                        &entry.partition,
                        &entry.address,
                        value.expose(),
                        evict_at,
                        &provenance,
                        now,
                    )?;
                    if existing.is_some() {
                        super::VaultEntryImportStatus::Replaced
                    } else {
                        super::VaultEntryImportStatus::Added
                    }
                };
                let (now, monotonic_now) = clock.sample();
                clock.check(valid_until.get())?;
                state.touch(now, monotonic_now)?;
                return Ok(VaultResponseBody::VaultEntryImported { status });
            }
            VaultAction::ListPermissions | VaultAction::ListPermissionsPage { .. } => {
                require_live_manager(&state, caller, clock, valid_until)?;
                let (revision, permissions) = state.list_permissions(now)?;
                let cursor = if let VaultAction::ListPermissionsPage {
                    revision: expected,
                    ref cursor,
                } = request.action
                {
                    if revision != expected {
                        return Err(VaultError::Conflict.into());
                    }
                    Some(cursor.as_str())
                } else {
                    None
                };
                return permission_page(revision, permissions, cursor).map_err(Into::into);
            }
            VaultAction::WaitPermissions {
                after_revision,
                timeout_ms,
            } => {
                require_live_manager(&state, caller, clock, valid_until)?;
                let (revision, permissions) = state.wait_for_approvals(
                    caller,
                    after_revision,
                    Duration::from_millis(timeout_ms),
                    clock,
                )?;
                return permission_page(revision, permissions, None).map_err(Into::into);
            }
            VaultAction::WaitPermission { id, timeout_ms } => {
                let status = state.wait_for_permission(
                    caller,
                    &id,
                    Duration::from_millis(timeout_ms),
                    clock,
                )?;
                return Ok(VaultResponseBody::PermissionWait { status });
            }
            VaultAction::DenyPermission { id } => {
                require_live_manager(&state, caller, clock, valid_until)?;
                state.deny_approval(&id, clock.wall())?;
                return Ok(VaultResponseBody::PermissionChanged {
                    status: super::PermissionChange::Denied,
                });
            }
            VaultAction::ApprovePermission {
                id,
                signature,
                duration_seconds,
            } => {
                require_live_manager(&state, caller, clock, valid_until)?;
                state.approve(&id, &signature, duration_seconds, clock.wall(), &provenance)?;
                let (now, monotonic_now) = clock.sample();
                state.touch(now, monotonic_now)?;
                return Ok(VaultResponseBody::PermissionChanged {
                    status: super::PermissionChange::Granted,
                });
            }
            VaultAction::RevokePermission { id } => {
                require_live_manager(&state, caller, clock, valid_until)?;
                state.revoke_permission(&id, clock.wall(), &provenance)?;
                let (now, monotonic_now) = clock.sample();
                state.touch(now, monotonic_now)?;
                return Ok(VaultResponseBody::PermissionChanged {
                    status: super::PermissionChange::Revoked,
                });
            }
            action => execute_action(
                state.store(),
                caller,
                action,
                state.lease_deadlines(),
                &provenance,
                clock,
                valid_until,
            ),
        };
        let (result, refresh_lease) = match result {
            Ok(result) => result,
            Err(VaultError::AuthorizationRequired) if approval.is_some() => {
                let interaction = state.create_approval(approval.expect("checked above"), now)?;
                return Err(RequestFailure {
                    error: VaultError::AuthorizationRequired,
                    interaction: Some(interaction),
                });
            }
            Err(error) => return Err(error.into()),
        };
        if refresh_lease {
            let (now, monotonic_now) = clock.sample();
            clock.check(valid_until.get())?;
            state.touch(now, monotonic_now)?;
        }
        Ok(result)
    }
}

#[cfg(feature = "vault-store")]
fn inventory(
    state: &mut LiveStateGuard<'_>,
    caller: &CallerIdentity,
    cursor: Option<&str>,
    limit: u16,
    clock: RequestTime,
    valid_until: &std::cell::Cell<Option<u64>>,
) -> Result<VaultResponseBody, RequestFailure> {
    require_live_manager(state, caller, clock, valid_until)?;
    let now = clock.wall();
    let page = state.store().list_vault_entries(cursor, limit, now)?;
    let (now, monotonic_now) = clock.sample();
    clock.check(valid_until.get())?;
    state.touch(now, monotonic_now)?;
    Ok(VaultResponseBody::VaultEntries {
        entries: page.items,
        next_cursor: page.next_cursor,
    })
}

fn permission_manager_deadline(
    state: &LiveStateGuard<'_>,
    caller: &CallerIdentity,
    now: u64,
) -> VaultResult<Option<u64>> {
    super::grant::require_grant_until(
        state.store(),
        caller,
        GrantRequirement {
            scope: DocumentKind::Authorization,
            namespace: Some(PERMISSION_CONTROL_NAMESPACE),
            address: None,
            project: None,
            permission: GrantPermission::ManagePermissions,
        },
        now,
    )
}

#[cfg(feature = "vault-store")]
fn require_permission_manager(
    state: &LiveStateGuard<'_>,
    caller: &CallerIdentity,
    now: u64,
) -> VaultResult<()> {
    permission_manager_deadline(state, caller, now).map(|_| ())
}

fn require_live_manager(
    state: &LiveStateGuard<'_>,
    caller: &CallerIdentity,
    clock: RequestTime,
    valid_until: &std::cell::Cell<Option<u64>>,
) -> VaultResult<()> {
    tighten(
        valid_until,
        permission_manager_deadline(state, caller, clock.wall())?,
    );
    clock.check(valid_until.get())
}

#[cfg(feature = "vault-store")]
fn response_error(error: &VaultError) -> VaultResponseError {
    response_error_with_interaction(error, None)
}

#[cfg(feature = "vault-store")]
fn response_error_with_interaction(
    error: &VaultError,
    interaction: Option<super::VaultInteractionReference>,
) -> VaultResponseError {
    let code = match error {
        VaultError::AuthorizationRequired | VaultError::ApprovalLimited => {
            VaultResponseErrorCode::AuthorizationRequired
        }
        VaultError::Replay => VaultResponseErrorCode::Replay,
        VaultError::Sealed | VaultError::WorkerUnavailable | VaultError::AgentUnreachable(_) => {
            VaultResponseErrorCode::Sealed
        }
        VaultError::Conflict => VaultResponseErrorCode::Conflict,
        VaultError::EmptyAddress { .. }
        | VaultError::AddressTooLong { .. }
        | VaultError::Expired
        | VaultError::Protocol(_) => VaultResponseErrorCode::InvalidRequest,
        VaultError::InvalidData(_)
        | VaultError::Automerge(_)
        | VaultError::Crypto
        | VaultError::Signature
        | VaultError::Random(_)
        | VaultError::Database(_)
        | VaultError::HardwareUnavailable
        | VaultError::HardwarePolicyUnsupported
        | VaultError::NativeAuthorization(_)
        | VaultError::Protection(_) => VaultResponseErrorCode::Internal,
    };
    let message = match code {
        VaultResponseErrorCode::InvalidRequest => "the request is invalid",
        VaultResponseErrorCode::AuthorizationRequired
            if matches!(error, VaultError::ApprovalLimited) =>
        {
            "approval request limit reached; retry later"
        }
        VaultResponseErrorCode::AuthorizationRequired => "application authorization is required",
        VaultResponseErrorCode::Replay => "the request was already consumed",
        VaultResponseErrorCode::Sealed => "the vault is sealed",
        VaultResponseErrorCode::Conflict => "the secret has unresolved concurrent values",
        VaultResponseErrorCode::Internal => "the vault could not complete the request",
    };
    VaultResponseError {
        code,
        message: message.to_owned(),
        interaction,
    }
}
#[cfg(all(test, feature = "vault-store", feature = "hardware"))]
mod tests;

// Reserve ample framing, revision and cursor overhead. Count escaped JSON
// bytes, not source string lengths, before returning a transport-sized page.
fn permission_page(
    revision: u64,
    permissions: Vec<super::Permission>,
    cursor: Option<&str>,
) -> VaultResult<VaultResponseBody> {
    let mut remaining = super::wire::MAX_MESSAGE_BYTES - 4096;
    let mut page = Vec::new();
    let mut next_cursor = None;
    for permission in permissions
        .into_iter()
        .filter(|p| cursor.is_none_or(|cursor| p.id.as_str() > cursor))
    {
        let bytes = serde_json::to_vec(&permission)
            .map_err(|e| VaultError::Protocol(e.to_string()))?
            .len()
            + 1;
        if bytes > remaining {
            if page.is_empty() {
                return Err(VaultError::Protocol(
                    "permission exceeds page budget".to_owned(),
                ));
            }
            next_cursor = page.last().map(|p: &super::Permission| p.id.clone());
            break;
        }
        remaining -= bytes;
        page.push(permission);
    }
    Ok(VaultResponseBody::Permissions {
        revision,
        permissions: page,
        next_cursor,
    })
}

fn secret_service_index(
    store: &VaultStore,
    now: u64,
) -> VaultResult<crate::vault::secret_service_data::Index> {
    use crate::vault::secret_service_data::{INDEX_ITEM, Index, NAMESPACE};
    let bytes = store.get_at(
        DocumentKind::LinuxSecretService,
        NAMESPACE,
        &crate::vault::SecretAddress::new(INDEX_ITEM, None)?,
        now,
    )?;
    Index::decode(bytes.as_deref())
}

#[allow(clippy::too_many_arguments)]
fn import_secret_service_item(
    store: &VaultStore,
    entry: &super::VaultEntryMetadata,
    value: &super::WireSecret,
    evict_at: Option<u64>,
    replace_existing: bool,
    provenance: &Provenance,
    now: u64,
) -> VaultResult<super::VaultEntryImportStatus> {
    use crate::vault::secret_service_data::{INDEX_ITEM, NAMESPACE, PortableItem};
    use crate::vault::{DocumentOperation, SecretAddress};
    if entry.partition != NAMESPACE || evict_at.is_some() {
        return Err(VaultError::Protocol(
            "unsupported portable keyring partition or expiry".to_owned(),
        ));
    }
    let portable = PortableItem::decode(value.expose(), &entry.address)?;
    let mut index = secret_service_index(store, now)?;
    let existing = index
        .items
        .iter()
        .position(|item| item.id == portable.item.id);
    if existing.is_some() && !replace_existing {
        return Ok(super::VaultEntryImportStatus::KeptExisting);
    }
    if let Some(position) = existing {
        index.items[position] = portable.item;
    } else {
        index.items.push(portable.item);
    }
    let index_bytes =
        serde_json::to_vec(&index).map_err(|e| VaultError::InvalidData(e.to_string()))?;
    // An imported index must remain writable through the bounded native
    // adapter's normal mutation path.
    VaultRequest::new(VaultAction::Mutate {
        namespace: NAMESPACE.to_vec(),
        mutations: vec![
            super::VaultMutation::Put {
                address: super::WireSecretAddress::new(
                    entry
                        .address
                        .as_local()
                        .ok_or_else(|| VaultError::Protocol("invalid keyring address".to_owned()))?
                        .0,
                    None,
                ),
                value: super::WireSecret::new(portable.value.expose().to_vec())?,
                evict_at: None,
            },
            super::VaultMutation::Put {
                address: super::WireSecretAddress::new(INDEX_ITEM, None),
                value: super::WireSecret::new(index_bytes.clone())?,
                evict_at: None,
            },
        ],
    })?
    .validate()?;
    store.mutate(
        DocumentKind::LinuxSecretService,
        NAMESPACE,
        vec![
            DocumentOperation::Put {
                address: entry.address.clone(),
                value: zeroize::Zeroizing::new(portable.value.expose().to_vec()),
                evict_at: None,
            },
            DocumentOperation::Put {
                address: SecretAddress::new(INDEX_ITEM, None)?,
                value: zeroize::Zeroizing::new(index_bytes),
                evict_at: None,
            },
        ],
        provenance,
        now,
    )?;
    Ok(if existing.is_some() {
        super::VaultEntryImportStatus::Replaced
    } else {
        super::VaultEntryImportStatus::Added
    })
}

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
#[cfg(feature = "vault-store")]
mod state;
mod time;

use time::{RequestTime, tighten};

#[cfg(feature = "vault-store")]
use super::grant::GrantRequirement;
#[cfg(feature = "vault-store")]
use actions::execute_action;
#[cfg(all(test, feature = "hardware"))]
use actions::{ScopedAction, scope_action, validate_evict_at};
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
        Self::new(VaultStore::open(root, unsealed)?, now, policy)
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
        let mut state = self.state.lock_live(clock.sample().1)?;
        let now = clock.wall();
        state.consume(request.request_id())?;
        let result = match request.action {
            VaultAction::ListPermissions => {
                require_live_manager(&state, caller, clock, valid_until)?;
                let (revision, permissions) = state.list_permissions(now)?;
                return Ok(VaultResponseBody::Permissions {
                    revision,
                    permissions,
                });
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
                return Ok(VaultResponseBody::Permissions {
                    revision,
                    permissions,
                });
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
fn require_permission_manager(
    state: &LiveStateGuard<'_>,
    caller: &CallerIdentity,
    now: u64,
) -> VaultResult<()> {
    permission_manager_deadline(state, caller, now).map(|_| ())
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
        VaultError::AuthorizationRequired => VaultResponseErrorCode::AuthorizationRequired,
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

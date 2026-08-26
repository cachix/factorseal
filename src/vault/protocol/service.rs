use std::path::Path;
use std::time::Instant;

#[cfg(all(test, feature = "hardware"))]
use crate::vault::DocumentScope;
use crate::vault::{UnsealedVault, VaultError, VaultResult, VaultStore};

use super::wire::PROTOCOL_VERSION;
#[cfg(all(test, feature = "hardware"))]
use super::wire::{MAX_MESSAGE_BYTES, REQUEST_ID_BYTES};
use super::{
    CallerIdentity, UnsealLeasePolicy, VaultRequest, VaultResponse, VaultResponseBody,
    VaultResponseError, VaultResponseErrorCode,
};
#[cfg(all(test, feature = "hardware"))]
use super::{
    CallerPlatform, GrantPermission, RequestId, VaultAction, VaultMutation, WireSecret,
    WireSecretAddress,
};

#[cfg(feature = "vault-store")]
mod actions;
#[cfg(feature = "vault-store")]
mod authorization;
#[cfg(feature = "vault-store")]
mod state;

#[cfg(feature = "vault-store")]
use actions::execute_action;
#[cfg(all(test, feature = "hardware"))]
use actions::{ScopedAction, scope_action, validate_evict_at};
#[cfg(feature = "vault-store")]
use state::ServiceState;

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
        let result = self.handle_inner(caller, request, now, monotonic_now);
        let result = match result {
            Ok(VaultResponseBody::Sealed) => Ok(VaultResponseBody::Sealed),
            _ if self.state.is_sealed() => Err(VaultError::Sealed),
            result => result,
        };
        VaultResponse {
            version: PROTOCOL_VERSION,
            request_id,
            result: result.map_err(|error| response_error(&error)),
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

    fn handle_inner(
        &self,
        caller: &CallerIdentity,
        request: VaultRequest,
        now: u64,
        monotonic_now: Instant,
    ) -> VaultResult<VaultResponseBody> {
        caller.validate()?;
        request.validate()?;
        let mut state = self.state.lock_live(monotonic_now)?;
        state.consume(request.request_id())?;
        let (result, refresh_lease) = execute_action(
            state.store(),
            caller,
            request.action,
            now,
            state.lease_deadlines(),
        )?;
        if refresh_lease {
            state.touch(now, monotonic_now)?;
        }
        Ok(result)
    }
}

#[cfg(feature = "vault-store")]
fn response_error(error: &VaultError) -> VaultResponseError {
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
    }
}
#[cfg(all(test, feature = "vault-store", feature = "hardware"))]
mod tests;

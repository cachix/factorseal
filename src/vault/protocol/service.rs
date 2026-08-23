use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use zeroize::Zeroizing;

use crate::vault::{
    DocumentOperation, DocumentScope, UnsealedVault, VaultError, VaultResult, VaultStore,
};

use super::grant::{GrantTarget, require_grant, store_grant};
use super::lease::{ReplayWindow, UnsealLease};
use super::wire::PROTOCOL_VERSION;
#[cfg(all(test, feature = "hardware"))]
use super::wire::{MAX_MESSAGE_BYTES, REQUEST_ID_BYTES};
use super::{
    CallerIdentity, GrantPermission, UnsealLeasePolicy, VaultAction, VaultMutation, VaultRequest,
    VaultResponse, VaultResponseBody, VaultResponseError, VaultResponseErrorCode, WireSecret,
    WireSecretAddress,
};
#[cfg(all(test, feature = "hardware"))]
use super::{CallerPlatform, RequestId};

/// Shared request processor used behind every platform transport.
#[cfg(feature = "vault-store")]
pub struct VaultService {
    state: Mutex<ServiceState>,
    seal_handle: VaultStore,
}

#[cfg(feature = "vault-store")]
struct ServiceState {
    store: VaultStore,
    lease: UnsealLease,
    replay: ReplayWindow,
    /// Whole second the storage eviction sweep last ran in. The sweep
    /// decrypts, verifies, and re-parses every cached document, while platform
    /// event loops poll `expire_if_needed` about ten times a second, so it must
    /// not run once per iteration.
    last_purge_at: u64,
    #[cfg(all(test, feature = "hardware"))]
    purges: usize,
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
        let seal_handle = store.clone();
        Ok(Self {
            state: Mutex::new(ServiceState {
                store,
                lease: UnsealLease::new(now, policy)?,
                replay: ReplayWindow::new(),
                // Opening the store already swept this second.
                last_purge_at: now,
                #[cfg(all(test, feature = "hardware"))]
                purges: 0,
            }),
            seal_handle,
        })
    }

    #[cfg(all(test, feature = "hardware"))]
    fn purge_count(&self) -> usize {
        self.state.lock().unwrap().purges
    }

    /// Panic while holding the request-state mutex, the way a panicking
    /// request does. Callers wrap this in `catch_unwind`.
    #[cfg(all(test, feature = "hardware"))]
    pub(crate) fn poison_state_for_test(&self) {
        let _state = self.state.lock().unwrap();
        panic!("poison request state");
    }

    /// Persist approval for one durable keyring entry.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_entry(
        &self,
        caller: &CallerIdentity,
        namespace: &[u8],
        address: &WireSecretAddress,
        permissions: impl IntoIterator<Item = GrantPermission>,
        expires_at: Option<u64>,
        now: u64,
    ) -> VaultResult<()> {
        let mut state = self.lock_live_state(Instant::now())?;
        store_grant(
            &state.store,
            caller,
            GrantTarget::Entry {
                scope: DocumentScope::DeviceLocal,
                namespace,
                address: &address.resolve()?,
            },
            permissions,
            expires_at,
            now,
        )?;
        state.lease.touch(now, Instant::now())
    }

    /// Persist approval for one disposable application-cache entry.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_cache_entry(
        &self,
        caller: &CallerIdentity,
        namespace: &[u8],
        address: &WireSecretAddress,
        permissions: impl IntoIterator<Item = GrantPermission>,
        expires_at: Option<u64>,
        now: u64,
    ) -> VaultResult<()> {
        let mut state = self.lock_live_state(Instant::now())?;
        store_grant(
            &state.store,
            caller,
            GrantTarget::Entry {
                scope: DocumentScope::DeviceCache,
                namespace,
                address: &address.resolve()?,
            },
            permissions,
            expires_at,
            now,
        )?;
        state.lease.touch(now, Instant::now())
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
        let mut state = self.lock_live_state(Instant::now())?;
        store_grant(
            &state.store,
            caller,
            GrantTarget::Namespace {
                scope: DocumentScope::DeviceLocal,
                namespace,
            },
            permissions,
            expires_at,
            now,
        )?;
        state.lease.touch(now, Instant::now())
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
        let mut state = self.lock_live_state(Instant::now())?;
        store_grant(
            &state.store,
            caller,
            GrantTarget::Namespace {
                scope: DocumentScope::DeviceCache,
                namespace,
            },
            permissions,
            expires_at,
            now,
        )?;
        state.lease.touch(now, Instant::now())
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
            _ if self.seal_handle.is_sealed() => Err(VaultError::Sealed),
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
        if self.seal_handle.is_sealed() {
            return Ok(true);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| VaultError::WorkerUnavailable)?;
        if state.store.is_sealed() {
            return Ok(true);
        }
        if state.lease.is_expired(monotonic_now) {
            state.store.seal();
            return Ok(true);
        }
        if state.last_purge_at != now {
            state.store.purge_expired_at(now)?;
            state.last_purge_at = now;
            #[cfg(all(test, feature = "hardware"))]
            {
                state.purges += 1;
            }
        }
        Ok(false)
    }

    /// Logout, suspend, and shutdown hooks use the same immediate seal path.
    pub fn seal(&self) -> VaultResult<()> {
        // This clone sits outside the request-state mutex so a lifecycle event
        // can fail closed even if a request panics and poisons that mutex.
        self.seal_handle.seal();
        Ok(())
    }

    fn lock_live_state(
        &self,
        monotonic_now: Instant,
    ) -> VaultResult<std::sync::MutexGuard<'_, ServiceState>> {
        if self.seal_handle.is_sealed() {
            return Err(VaultError::Sealed);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| VaultError::WorkerUnavailable)?;
        if state.store.is_sealed() || state.lease.is_expired(monotonic_now) {
            state.store.seal();
            return Err(VaultError::Sealed);
        }
        Ok(state)
    }

    #[allow(clippy::too_many_lines)]
    fn handle_inner(
        &self,
        caller: &CallerIdentity,
        request: VaultRequest,
        now: u64,
        monotonic_now: Instant,
    ) -> VaultResult<VaultResponseBody> {
        caller.validate()?;
        request.validate()?;
        let mut state = self.lock_live_state(monotonic_now)?;
        state.replay.consume(request.request_id())?;

        // Normalize explicit cache operations so authorization and mutation
        // share one implementation while the document scope remains explicit.
        let (action, document_scope) = match request.action {
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

        let (result, refresh_lease) = match action {
            VaultAction::Status => (
                VaultResponseBody::Status {
                    vault_id: state.store.device().vault_id().to_string(),
                    device_key_id: state.store.device().device_key_id().to_string(),
                    hardware_backend: state.store.device().hardware_backend().to_owned(),
                    idle_deadline: state.lease.idle_deadline,
                    absolute_deadline: state.lease.absolute_deadline,
                },
                false,
            ),
            VaultAction::Get { namespace, address } => {
                let address = address.resolve()?;
                require_grant(
                    &state.store,
                    caller,
                    document_scope,
                    &namespace,
                    Some(&address),
                    GrantPermission::Get,
                    now,
                )?;
                let value = state
                    .store
                    .get_at(document_scope, &namespace, &address, now)?
                    .map(|value| WireSecret::new(value.to_vec()));
                (VaultResponseBody::Secret { value }, true)
            }
            VaultAction::Put {
                namespace,
                address,
                value,
                evict_at,
            } => {
                let address = address.resolve()?;
                require_grant(
                    &state.store,
                    caller,
                    document_scope,
                    &namespace,
                    Some(&address),
                    GrantPermission::Put,
                    now,
                )?;
                // A deadline equal to the vault's whole-second clock is a
                // valid immediately-expired write. This lets sub-second
                // upstream TTLs round down without exceeding their bound.
                if evict_at.is_some_and(|deadline| deadline < now) {
                    return Err(VaultError::Expired);
                }
                state.store.put_at(
                    document_scope,
                    &namespace,
                    &address,
                    value.expose(),
                    evict_at,
                )?;
                (VaultResponseBody::Stored, true)
            }
            VaultAction::Mutate {
                namespace,
                mutations,
            } => {
                let mut operations = Vec::with_capacity(mutations.len());
                for mutation in mutations {
                    match mutation {
                        VaultMutation::Put {
                            address,
                            value,
                            evict_at,
                        } => {
                            let address = address.resolve()?;
                            require_grant(
                                &state.store,
                                caller,
                                document_scope,
                                &namespace,
                                Some(&address),
                                GrantPermission::Put,
                                now,
                            )?;
                            // As with an ordinary Put, allow an immediately
                            // expired record but never accept a deadline that
                            // predates the request's whole-second clock.
                            if evict_at.is_some_and(|deadline| deadline < now) {
                                return Err(VaultError::Expired);
                            }
                            operations.push(DocumentOperation::Put {
                                address,
                                value: Zeroizing::new(value.expose().to_vec()),
                                evict_at,
                            });
                        }
                        VaultMutation::Delete { address } => {
                            let address = address.resolve()?;
                            require_grant(
                                &state.store,
                                caller,
                                document_scope,
                                &namespace,
                                Some(&address),
                                GrantPermission::Delete,
                                now,
                            )?;
                            operations.push(DocumentOperation::Delete { address });
                        }
                    }
                }
                state.store.mutate(document_scope, &namespace, operations)?;
                (VaultResponseBody::Mutated, true)
            }
            VaultAction::Delete { namespace, address } => {
                let address = address.resolve()?;
                require_grant(
                    &state.store,
                    caller,
                    document_scope,
                    &namespace,
                    Some(&address),
                    GrantPermission::Delete,
                    now,
                )?;
                let existed = state.store.delete(document_scope, &namespace, &address)?;
                (VaultResponseBody::Deleted { existed }, true)
            }
            VaultAction::Clear { namespace } => {
                require_grant(
                    &state.store,
                    caller,
                    document_scope,
                    &namespace,
                    None,
                    GrantPermission::Clear,
                    now,
                )?;
                let entries = state.store.clear(document_scope, &namespace)?;
                (VaultResponseBody::Cleared { entries }, true)
            }
            VaultAction::Seal { namespace } => {
                require_grant(
                    &state.store,
                    caller,
                    document_scope,
                    &namespace,
                    None,
                    GrantPermission::Seal,
                    now,
                )?;
                state.store.seal();
                (VaultResponseBody::Sealed, false)
            }
            VaultAction::GetCache { .. }
            | VaultAction::PutCache { .. }
            | VaultAction::DeleteCache { .. }
            | VaultAction::ClearCache { .. }
            | VaultAction::SealCache { .. } => unreachable!("cache action was normalized"),
        };
        if refresh_lease {
            state.lease.touch(now, monotonic_now)?;
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
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::Vault;

    fn service(now: u64, policy: UnsealLeasePolicy) -> (tempfile::TempDir, VaultService) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        let unsealed = Vault::create_for_test(&root).unwrap();
        let store = VaultStore::open(root, unsealed).unwrap();
        (directory, VaultService::new(store, now, policy).unwrap())
    }

    fn caller() -> CallerIdentity {
        CallerIdentity::new(
            CallerPlatform::Linux,
            "uid:1000",
            "dev.secretspec.cli",
            [7; 32],
            None,
        )
        .unwrap()
    }

    fn address() -> WireSecretAddress {
        WireSecretAddress::new("secretspec/demo/default/API_KEY", None)
    }

    #[test]
    fn request_round_trip_is_versioned_and_bounded() {
        let request = VaultRequest::new(VaultAction::Mutate {
            namespace: b"secretspec".to_vec(),
            mutations: vec![VaultMutation::Put {
                address: address(),
                value: WireSecret::new(b"secret".to_vec()),
                evict_at: None,
            }],
        })
        .unwrap();
        let bytes = request.encode().unwrap();
        let decoded = VaultRequest::decode(&bytes).unwrap();
        assert_eq!(decoded.request_id(), request.request_id());
        assert!(matches!(decoded.action, VaultAction::Mutate { .. }));
        assert!(VaultRequest::decode(&vec![0; MAX_MESSAGE_BYTES + 1]).is_err());
    }

    #[test]
    fn wire_errors_never_echo_internal_or_secret_details() {
        let marker = "visible-project/API_TOKEN=needle-secret-value";
        for error in [
            VaultError::InvalidData(marker.to_owned()),
            VaultError::Protocol(marker.to_owned()),
            VaultError::Database(marker.to_owned()),
            VaultError::Protection(marker.to_owned()),
        ] {
            let response = response_error(&error);
            assert!(!response.message.contains(marker));
            assert!(!response.message.contains("API_TOKEN"));
        }
    }

    #[test]
    fn exact_grant_is_required_and_replay_is_rejected() {
        let (_directory, service) = service(100, UnsealLeasePolicy::default());
        let caller = caller();
        let put_id = RequestId::from_bytes([1; REQUEST_ID_BYTES]);
        let put = || {
            VaultRequest::with_id(
                put_id,
                VaultAction::Put {
                    namespace: b"secretspec".to_vec(),
                    address: address(),
                    value: WireSecret::new(b"secret".to_vec()),
                    evict_at: None,
                },
            )
        };
        let denied = service.handle(&caller, put(), 101);
        assert_eq!(
            denied.result.unwrap_err().code,
            VaultResponseErrorCode::AuthorizationRequired
        );

        service
            .authorize_entry(
                &caller,
                b"secretspec",
                &address(),
                [GrantPermission::Put],
                None,
                101,
            )
            .unwrap();
        let replayed = service.handle(&caller, put(), 102);
        assert_eq!(
            replayed.result.unwrap_err().code,
            VaultResponseErrorCode::Replay
        );

        let accepted = service.handle(
            &caller,
            VaultRequest::new(VaultAction::Put {
                namespace: b"secretspec".to_vec(),
                address: address(),
                value: WireSecret::new(b"secret".to_vec()),
                evict_at: None,
            })
            .unwrap(),
            102,
        );
        assert!(matches!(accepted.result, Ok(VaultResponseBody::Stored)));
    }

    #[test]
    fn caller_identity_is_part_of_grant_authority() {
        let (_directory, service) = service(100, UnsealLeasePolicy::default());
        let caller = caller();
        service
            .authorize_entry(
                &caller,
                b"secretspec",
                &address(),
                [GrantPermission::Get],
                None,
                100,
            )
            .unwrap();
        let other = CallerIdentity::new(
            CallerPlatform::Linux,
            "uid:1000",
            "dev.secretspec.cli",
            [8; 32],
            None,
        )
        .unwrap();
        let response = service.handle(
            &other,
            VaultRequest::new(VaultAction::Get {
                namespace: b"secretspec".to_vec(),
                address: address(),
            })
            .unwrap(),
            101,
        );
        assert_eq!(
            response.result.unwrap_err().code,
            VaultResponseErrorCode::AuthorizationRequired
        );
    }

    #[test]
    fn local_keyring_operations_are_separate_from_disposable_cache_entries() {
        let (_directory, service) = service(100, UnsealLeasePolicy::default());
        let caller = caller();
        service
            .authorize_namespace(
                &caller,
                b"factorseal/keyring/v1",
                [GrantPermission::Get, GrantPermission::Put],
                None,
                100,
            )
            .unwrap();

        let stored = service.handle(
            &caller,
            VaultRequest::new(VaultAction::Put {
                namespace: b"factorseal/keyring/v1".to_vec(),
                address: address(),
                value: WireSecret::new(b"durable secret".to_vec()),
                evict_at: None,
            })
            .unwrap(),
            101,
        );
        assert!(matches!(stored.result, Ok(VaultResponseBody::Stored)));

        service
            .authorize_cache_namespace(
                &caller,
                b"factorseal/keyring/v1",
                [GrantPermission::Get],
                None,
                101,
            )
            .unwrap();
        let cache_read = service.handle(
            &caller,
            VaultRequest::new(VaultAction::GetCache {
                namespace: b"factorseal/keyring/v1".to_vec(),
                address: address(),
            })
            .unwrap(),
            102,
        );
        assert!(matches!(
            cache_read.result,
            Ok(VaultResponseBody::Secret { value: None })
        ));

        let local_read = service.handle(
            &caller,
            VaultRequest::new(VaultAction::Get {
                namespace: b"factorseal/keyring/v1".to_vec(),
                address: address(),
            })
            .unwrap(),
            103,
        );
        let Ok(VaultResponseBody::Secret { value: Some(value) }) = local_read.result else {
            panic!("expected durable keyring secret");
        };
        assert_eq!(value.expose(), b"durable secret");
    }

    #[test]
    fn cache_grants_cannot_authorize_durable_keyring_operations() {
        let (_directory, service) = service(100, UnsealLeasePolicy::default());
        let caller = caller();
        service
            .authorize_cache_namespace(&caller, b"shared-name", [GrantPermission::Put], None, 100)
            .unwrap();

        let response = service.handle(
            &caller,
            VaultRequest::new(VaultAction::Put {
                namespace: b"shared-name".to_vec(),
                address: address(),
                value: WireSecret::new(b"must not persist".to_vec()),
                evict_at: None,
            })
            .unwrap(),
            101,
        );
        assert_eq!(
            response.result.unwrap_err().code,
            VaultResponseErrorCode::AuthorizationRequired
        );
    }

    #[test]
    fn batch_mutations_are_pre_authorized_and_commit_together() {
        let (_directory, service) = service(100, UnsealLeasePolicy::default());
        let caller = caller();
        let first = WireSecretAddress::new("secretspec/demo/first", None);
        let second = WireSecretAddress::new("secretspec/demo/second", None);
        service
            .authorize_entry(
                &caller,
                b"secretspec",
                &first,
                [GrantPermission::Get, GrantPermission::Put],
                None,
                100,
            )
            .unwrap();

        let denied = service.handle(
            &caller,
            VaultRequest::new(VaultAction::Mutate {
                namespace: b"secretspec".to_vec(),
                mutations: vec![
                    VaultMutation::Put {
                        address: first.clone(),
                        value: WireSecret::new(b"first".to_vec()),
                        evict_at: None,
                    },
                    VaultMutation::Put {
                        address: second.clone(),
                        value: WireSecret::new(b"second".to_vec()),
                        evict_at: None,
                    },
                ],
            })
            .unwrap(),
            101,
        );
        assert_eq!(
            denied.result.unwrap_err().code,
            VaultResponseErrorCode::AuthorizationRequired
        );

        let absent = service.handle(
            &caller,
            VaultRequest::new(VaultAction::Get {
                namespace: b"secretspec".to_vec(),
                address: first.clone(),
            })
            .unwrap(),
            102,
        );
        assert!(matches!(
            absent.result,
            Ok(VaultResponseBody::Secret { value: None })
        ));

        service
            .authorize_entry(
                &caller,
                b"secretspec",
                &second,
                [GrantPermission::Get, GrantPermission::Put],
                None,
                102,
            )
            .unwrap();
        let stored = service.handle(
            &caller,
            VaultRequest::new(VaultAction::Mutate {
                namespace: b"secretspec".to_vec(),
                mutations: vec![
                    VaultMutation::Put {
                        address: first.clone(),
                        value: WireSecret::new(b"first".to_vec()),
                        evict_at: None,
                    },
                    VaultMutation::Put {
                        address: second.clone(),
                        value: WireSecret::new(b"second".to_vec()),
                        evict_at: None,
                    },
                ],
            })
            .unwrap(),
            103,
        );
        assert!(matches!(stored.result, Ok(VaultResponseBody::Mutated)));

        for (address, expected) in [(first, b"first".as_slice()), (second, b"second")] {
            let response = service.handle(
                &caller,
                VaultRequest::new(VaultAction::Get {
                    namespace: b"secretspec".to_vec(),
                    address,
                })
                .unwrap(),
                104,
            );
            let Ok(VaultResponseBody::Secret { value: Some(value) }) = response.result else {
                panic!("expected a stored batch secret");
            };
            assert_eq!(value.expose(), expected);
        }
    }

    #[test]
    fn idle_deadline_seals_without_a_request() {
        let policy = UnsealLeasePolicy {
            idle_timeout: Duration::from_secs(5),
            maximum_lifetime: Duration::from_secs(10),
        };
        let (_directory, service) = service(100, policy);
        let idle_expires_at = service.state.lock().unwrap().lease.idle_expires_at;
        assert!(
            !service
                .expire_if_needed_at(
                    104,
                    idle_expires_at.checked_sub(Duration::from_secs(1)).unwrap(),
                )
                .unwrap()
        );
        assert!(service.expire_if_needed_at(105, idle_expires_at).unwrap());

        let response = service.handle(
            &caller(),
            VaultRequest::new(VaultAction::Status).unwrap(),
            105,
        );
        assert_eq!(
            response.result.unwrap_err().code,
            VaultResponseErrorCode::Sealed
        );
    }

    #[test]
    fn status_requests_do_not_refresh_the_idle_deadline() {
        let policy = UnsealLeasePolicy {
            idle_timeout: Duration::from_secs(5),
            maximum_lifetime: Duration::from_secs(10),
        };
        let (_directory, service) = service(100, policy);
        let idle_expires_at = service.state.lock().unwrap().lease.idle_expires_at;

        let response = service.handle_at(
            &caller(),
            VaultRequest::new(VaultAction::Status).unwrap(),
            104,
            idle_expires_at.checked_sub(Duration::from_secs(1)).unwrap(),
        );
        let VaultResponseBody::Status { idle_deadline, .. } = response.result.unwrap() else {
            panic!("expected status response");
        };
        assert_eq!(idle_deadline, 105);
        assert!(service.expire_if_needed_at(105, idle_expires_at).unwrap());
    }

    #[test]
    fn wall_clock_rollback_does_not_extend_the_unseal_lease() {
        let policy = UnsealLeasePolicy {
            idle_timeout: Duration::from_secs(5),
            maximum_lifetime: Duration::from_secs(10),
        };
        let (_directory, service) = service(100, policy);
        let idle_expires_at = service.state.lock().unwrap().lease.idle_expires_at;

        assert!(
            service.expire_if_needed_at(50, idle_expires_at).unwrap(),
            "the monotonic deadline must win even if Unix time moves backward"
        );
    }

    #[test]
    fn storage_eviction_sweeps_at_most_once_a_second() {
        let (_directory, service) = service(100, UnsealLeasePolicy::default());
        for _ in 0..5 {
            assert!(!service.expire_if_needed(100).unwrap());
        }
        assert_eq!(
            service.purge_count(),
            0,
            "opening the store already swept this second"
        );

        for _ in 0..5 {
            assert!(!service.expire_if_needed(101).unwrap());
        }
        assert_eq!(service.purge_count(), 1);

        assert!(!service.expire_if_needed(102).unwrap());
        assert_eq!(service.purge_count(), 2);
    }

    #[test]
    fn explicit_seal_invalidates_the_service() {
        let (_directory, service) = service(100, UnsealLeasePolicy::default());
        let caller = caller();
        service
            .authorize_namespace(&caller, b"secretspec", [GrantPermission::Seal], None, 100)
            .unwrap();
        let response = service.handle(
            &caller,
            VaultRequest::new(VaultAction::Seal {
                namespace: b"secretspec".to_vec(),
            })
            .unwrap(),
            101,
        );
        assert!(matches!(response.result, Ok(VaultResponseBody::Sealed)));
        assert!(service.expire_if_needed(101).unwrap());
    }

    #[test]
    fn lifecycle_seal_survives_a_poisoned_request_mutex() {
        let (_directory, service) = service(100, UnsealLeasePolicy::default());
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            service.poison_state_for_test();
        }));
        assert!(poisoned.is_err());

        service.seal().unwrap();
        assert!(service.seal_handle.is_sealed());
    }
}

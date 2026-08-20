#[cfg(feature = "vault")]
use std::collections::{BTreeSet, HashSet, VecDeque};
use std::fmt;
#[cfg(feature = "vault")]
use std::sync::Mutex;
#[cfg(feature = "vault")]
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
#[cfg(feature = "vault")]
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "vault")]
use super::{DocumentScope, VaultStore};
use super::{SecretAddress, VaultError, VaultResult};

const PROTOCOL_VERSION: u8 = 1;
#[cfg(feature = "vault")]
const GRANT_VERSION: u8 = 1;
const REQUEST_ID_BYTES: usize = 16;
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_IDENTITY_COMPONENT_BYTES: usize = 4 * 1024;
const MAX_NAMESPACE_BYTES: usize = 4 * 1024;
#[cfg(feature = "vault")]
const MAX_REPLAY_IDS: usize = 4096;
#[cfg(feature = "vault")]
const GRANT_DOCUMENT_NAMESPACE: &[u8] = b"factorseal/vault-grants/v1";
#[cfg(feature = "vault")]
const CALLER_FINGERPRINT_DOMAIN: &[u8] = b"factorseal/caller-identity/v1\0";
#[cfg(feature = "vault")]
const GRANT_TARGET_DOMAIN: &[u8] = b"factorseal/grant-target/v1\0";

/// Platform that authenticated one local IPC caller.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CallerPlatform {
    Linux,
    Macos,
    Windows,
}

/// Transport-authenticated application identity. These fields must be
/// produced by the platform adapter, not trusted from the request body.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerIdentity {
    platform: CallerPlatform,
    user_id: String,
    application_id: String,
    executable_digest: [u8; 32],
    signer_id: Option<String>,
}

impl CallerIdentity {
    pub fn new(
        platform: CallerPlatform,
        user_id: impl Into<String>,
        application_id: impl Into<String>,
        executable_digest: [u8; 32],
        signer_id: Option<String>,
    ) -> VaultResult<Self> {
        let identity = Self {
            platform,
            user_id: user_id.into(),
            application_id: application_id.into(),
            executable_digest,
            signer_id,
        };
        identity.validate()?;
        Ok(identity)
    }

    #[must_use]
    pub const fn platform(&self) -> CallerPlatform {
        self.platform
    }

    #[must_use]
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    #[must_use]
    pub fn application_id(&self) -> &str {
        &self.application_id
    }

    #[must_use]
    pub const fn executable_digest(&self) -> &[u8; 32] {
        &self.executable_digest
    }

    #[must_use]
    pub fn signer_id(&self) -> Option<&str> {
        self.signer_id.as_deref()
    }

    #[cfg(feature = "vault")]
    fn fingerprint(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(CALLER_FINGERPRINT_DOMAIN);
        digest.update([match self.platform {
            CallerPlatform::Linux => 1,
            CallerPlatform::Macos => 2,
            CallerPlatform::Windows => 3,
        }]);
        append_digest_bytes(&mut digest, self.user_id.as_bytes());
        append_digest_bytes(&mut digest, self.application_id.as_bytes());
        digest.update(self.executable_digest);
        if let Some(signer_id) = &self.signer_id {
            digest.update([1]);
            append_digest_bytes(&mut digest, signer_id.as_bytes());
        } else {
            digest.update([0]);
        }
        digest.finalize().into()
    }

    fn validate(&self) -> VaultResult<()> {
        validate_identity_component("user ID", &self.user_id)?;
        validate_identity_component("application ID", &self.application_id)?;
        if let Some(signer_id) = &self.signer_id {
            validate_identity_component("signer ID", signer_id)?;
        }
        Ok(())
    }
}

/// Replay-resistant request identifier.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId([u8; REQUEST_ID_BYTES]);

impl RequestId {
    pub fn random() -> VaultResult<Self> {
        let mut bytes = [0_u8; REQUEST_ID_BYTES];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; REQUEST_ID_BYTES]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RequestId")
            .field(&URL_SAFE_NO_PAD.encode(self.0))
            .finish()
    }
}

/// Wire representation of Factorseal item/field coordinates.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireSecretAddress {
    pub item: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl WireSecretAddress {
    #[must_use]
    pub fn new(item: impl Into<String>, field: Option<String>) -> Self {
        Self {
            item: item.into(),
            field,
        }
    }

    /// Validate the public wire address without performing an keyring request.
    pub fn validate(&self) -> VaultResult<()> {
        self.resolve().map(|_| ())
    }

    fn resolve(&self) -> VaultResult<SecretAddress> {
        SecretAddress::new(self.item.clone(), self.field.clone())
    }
}

/// Secret bytes that wipe their allocation on drop.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct WireSecret(Vec<u8>);

impl fmt::Debug for WireSecret {
    /// Requests and responses carry this type and derive `Debug`, so a
    /// derived one would put plaintext into every `{:?}` panic message,
    /// assertion failure, and log line that formats them.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WireSecret([REDACTED])")
    }
}

impl WireSecret {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for WireSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Versioned request sent over an authenticated local transport.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultRequest {
    version: u8,
    request_id: RequestId,
    pub action: VaultAction,
}

impl VaultRequest {
    pub fn new(action: VaultAction) -> VaultResult<Self> {
        Ok(Self {
            version: PROTOCOL_VERSION,
            request_id: RequestId::random()?,
            action,
        })
    }

    #[must_use]
    pub const fn with_id(request_id: RequestId, action: VaultAction) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            action,
        }
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    pub fn decode(bytes: &[u8]) -> VaultResult<Self> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(VaultError::Protocol("request is too large".to_owned()));
        }
        let request: Self = serde_json::from_slice(bytes)
            .map_err(|error| VaultError::Protocol(error.to_string()))?;
        request.validate()?;
        Ok(request)
    }

    pub fn encode(&self) -> VaultResult<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|error| VaultError::Protocol(error.to_string()))?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(VaultError::Protocol("request is too large".to_owned()));
        }
        Ok(Zeroizing::new(bytes))
    }

    fn validate(&self) -> VaultResult<()> {
        if self.version != PROTOCOL_VERSION {
            return Err(VaultError::Protocol(
                "unsupported request version".to_owned(),
            ));
        }
        self.action.validate()
    }
}

/// Operations available to an authenticated local client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum VaultAction {
    Status,
    /// Read from the durable local keyring.
    Get {
        namespace: Vec<u8>,
        address: WireSecretAddress,
    },
    /// Write to the durable local keyring.
    Put {
        namespace: Vec<u8>,
        address: WireSecretAddress,
        value: WireSecret,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evict_at: Option<u64>,
    },
    /// Delete from the durable local keyring.
    Delete {
        namespace: Vec<u8>,
        address: WireSecretAddress,
    },
    /// Clear one durable local-keyring namespace.
    Clear {
        namespace: Vec<u8>,
    },
    /// Read from the disposable application cache.
    GetCache {
        namespace: Vec<u8>,
        address: WireSecretAddress,
    },
    /// Write to the disposable application cache.
    PutCache {
        namespace: Vec<u8>,
        address: WireSecretAddress,
        value: WireSecret,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evict_at: Option<u64>,
    },
    /// Delete from the disposable application cache.
    DeleteCache {
        namespace: Vec<u8>,
        address: WireSecretAddress,
    },
    /// Clear one disposable application-cache namespace.
    ClearCache {
        namespace: Vec<u8>,
    },
    Seal {
        namespace: Vec<u8>,
    },
    /// Seal the vault using a disposable-cache namespace grant.
    SealCache {
        namespace: Vec<u8>,
    },
}

impl VaultAction {
    fn validate(&self) -> VaultResult<()> {
        match self {
            Self::Status => Ok(()),
            Self::Get { namespace, address }
            | Self::GetCache { namespace, address }
            | Self::Delete { namespace, address }
            | Self::DeleteCache { namespace, address }
            | Self::Put {
                namespace, address, ..
            }
            | Self::PutCache {
                namespace, address, ..
            } => {
                validate_namespace(namespace)?;
                address.resolve().map(|_| ())
            }
            Self::Clear { namespace }
            | Self::ClearCache { namespace }
            | Self::Seal { namespace }
            | Self::SealCache { namespace } => validate_namespace(namespace),
        }
    }
}

/// Permission persisted in one caller grant.
#[cfg(feature = "vault")]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantPermission {
    Get,
    Put,
    Delete,
    Clear,
    Seal,
}

/// Successful or failed response bound to the request ID.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultResponse {
    version: u8,
    request_id: RequestId,
    pub result: Result<VaultResponseBody, VaultResponseError>,
}

/// Transport-independent vault client used by the keyring interface and integrations such
/// as SecretSpec. Implementations authenticate the caller through their native
/// platform transport; they never open the vault database directly.
pub trait VaultClient: Send + Sync {
    fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse>;
}

impl VaultResponse {
    /// Construct a successful response for a [`VaultClient`] implementation.
    #[must_use]
    pub const fn success(request_id: RequestId, body: VaultResponseBody) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            result: Ok(body),
        }
    }

    /// Construct a failed response for a [`VaultClient`] implementation.
    #[must_use]
    pub const fn failure(request_id: RequestId, error: VaultResponseError) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            result: Err(error),
        }
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    pub fn decode(bytes: &[u8]) -> VaultResult<Self> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(VaultError::Protocol("response is too large".to_owned()));
        }
        let response: Self = serde_json::from_slice(bytes)
            .map_err(|error| VaultError::Protocol(error.to_string()))?;
        if response.version != PROTOCOL_VERSION {
            return Err(VaultError::Protocol(
                "unsupported response version".to_owned(),
            ));
        }
        Ok(response)
    }

    pub fn encode(&self) -> VaultResult<Zeroizing<Vec<u8>>> {
        let bytes =
            serde_json::to_vec(self).map_err(|error| VaultError::Protocol(error.to_string()))?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(VaultError::Protocol("response is too large".to_owned()));
        }
        Ok(Zeroizing::new(bytes))
    }
}

/// Response data. Secret bytes are zeroized when this value is dropped.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum VaultResponseBody {
    Status {
        unsealed: bool,
        vault_id: String,
        device_key_id: String,
        hardware_backend: String,
        idle_deadline: u64,
        absolute_deadline: u64,
    },
    Secret {
        value: Option<WireSecret>,
    },
    Stored,
    Deleted {
        existed: bool,
    },
    Cleared {
        entries: usize,
    },
    Sealed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultResponseError {
    pub code: VaultResponseErrorCode,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VaultResponseErrorCode {
    InvalidRequest,
    AuthorizationRequired,
    Replay,
    Sealed,
    Conflict,
    Internal,
}

/// Bounded lifetime for one hardware-unsealed vault session.
#[cfg(feature = "vault")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsealLeasePolicy {
    pub idle_timeout: Duration,
    pub maximum_lifetime: Duration,
}

#[cfg(feature = "vault")]
impl Default for UnsealLeasePolicy {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_mins(5),
            maximum_lifetime: Duration::from_hours(8),
        }
    }
}

#[cfg(feature = "vault")]
impl UnsealLeasePolicy {
    fn validate(self) -> VaultResult<()> {
        if self.idle_timeout.is_zero()
            || self.maximum_lifetime.is_zero()
            || self.idle_timeout > self.maximum_lifetime
        {
            return Err(VaultError::Protocol(
                "unseal lease timeouts are invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "vault")]
struct UnsealLease {
    idle_timeout: Duration,
    idle_deadline: u64,
    absolute_deadline: u64,
    idle_expires_at: Instant,
    absolute_expires_at: Instant,
}

#[cfg(feature = "vault")]
impl UnsealLease {
    fn new(now: u64, policy: UnsealLeasePolicy) -> VaultResult<Self> {
        Self::new_at(now, Instant::now(), policy)
    }

    fn new_at(now: u64, monotonic_now: Instant, policy: UnsealLeasePolicy) -> VaultResult<Self> {
        policy.validate()?;
        let idle_timeout_seconds = policy.idle_timeout.as_secs();
        let absolute_deadline = now
            .checked_add(policy.maximum_lifetime.as_secs())
            .ok_or_else(|| VaultError::Protocol("unseal lease overflows time".to_owned()))?;
        let idle_deadline = now
            .checked_add(idle_timeout_seconds)
            .ok_or_else(|| VaultError::Protocol("unseal lease overflows time".to_owned()))?
            .min(absolute_deadline);
        let absolute_expires_at = monotonic_now
            .checked_add(policy.maximum_lifetime)
            .ok_or_else(|| VaultError::Protocol("unseal lease overflows time".to_owned()))?;
        let idle_expires_at = monotonic_now
            .checked_add(policy.idle_timeout)
            .ok_or_else(|| VaultError::Protocol("unseal lease overflows time".to_owned()))?
            .min(absolute_expires_at);
        Ok(Self {
            idle_timeout: policy.idle_timeout,
            idle_deadline,
            absolute_deadline,
            idle_expires_at,
            absolute_expires_at,
        })
    }

    fn is_expired(&self, monotonic_now: Instant) -> bool {
        monotonic_now >= self.idle_expires_at || monotonic_now >= self.absolute_expires_at
    }

    fn touch(&mut self, now: u64, monotonic_now: Instant) -> VaultResult<()> {
        self.idle_deadline = now
            .checked_add(self.idle_timeout.as_secs())
            .ok_or_else(|| VaultError::Protocol("unseal lease overflows time".to_owned()))?
            .min(self.absolute_deadline);
        self.idle_expires_at = monotonic_now
            .checked_add(self.idle_timeout)
            .ok_or_else(|| VaultError::Protocol("unseal lease overflows time".to_owned()))?
            .min(self.absolute_expires_at);
        Ok(())
    }
}

#[cfg(feature = "vault")]
struct ReplayWindow {
    set: HashSet<RequestId>,
    order: VecDeque<RequestId>,
}

#[cfg(feature = "vault")]
impl ReplayWindow {
    fn new() -> Self {
        Self {
            set: HashSet::with_capacity(MAX_REPLAY_IDS),
            order: VecDeque::with_capacity(MAX_REPLAY_IDS),
        }
    }

    fn consume(&mut self, request_id: RequestId) -> VaultResult<()> {
        if !self.set.insert(request_id) {
            return Err(VaultError::Replay);
        }
        self.order.push_back(request_id);
        if self.order.len() > MAX_REPLAY_IDS
            && let Some(expired) = self.order.pop_front()
        {
            self.set.remove(&expired);
        }
        Ok(())
    }
}

#[cfg(feature = "vault")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessGrant {
    version: u8,
    caller_fingerprint: [u8; 32],
    target_digest: [u8; 32],
    permissions: BTreeSet<GrantPermission>,
    expires_at: Option<u64>,
}

/// Shared request processor used behind every platform transport.
#[cfg(feature = "vault")]
pub struct VaultService {
    state: Mutex<ServiceState>,
    seal_handle: VaultStore,
}

#[cfg(feature = "vault")]
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

#[cfg(feature = "vault")]
impl VaultService {
    pub fn new(store: VaultStore, now: u64, policy: UnsealLeasePolicy) -> VaultResult<Self> {
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
        let request_id = request.request_id;
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
        state.replay.consume(request.request_id)?;

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
                    unsealed: true,
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

#[cfg(feature = "vault")]
#[derive(Clone, Copy)]
enum GrantTarget<'a> {
    Namespace {
        scope: DocumentScope,
        namespace: &'a [u8],
    },
    Entry {
        scope: DocumentScope,
        namespace: &'a [u8],
        address: &'a SecretAddress,
    },
}

#[cfg(feature = "vault")]
fn store_grant(
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
    let grant = AccessGrant {
        version: GRANT_VERSION,
        caller_fingerprint,
        target_digest,
        permissions,
        expires_at,
    };
    let bytes = Zeroizing::new(
        serde_json::to_vec(&grant).map_err(|error| VaultError::Protocol(error.to_string()))?,
    );
    store.put_at(
        DocumentScope::DeviceLocal,
        GRANT_DOCUMENT_NAMESPACE,
        &grant_address(caller_fingerprint, target_digest)?,
        &bytes,
        expires_at,
    )
}

#[cfg(feature = "vault")]
fn require_grant(
    store: &VaultStore,
    caller: &CallerIdentity,
    scope: DocumentScope,
    namespace: &[u8],
    address: Option<&SecretAddress>,
    permission: GrantPermission,
    now: u64,
) -> VaultResult<()> {
    let caller_fingerprint = caller.fingerprint();
    let mut targets = Vec::with_capacity(2);
    if let Some(address) = address {
        targets.push(grant_target_digest(&GrantTarget::Entry {
            scope,
            namespace,
            address,
        }));
    }
    targets.push(grant_target_digest(&GrantTarget::Namespace {
        scope,
        namespace,
    }));
    for target_digest in targets {
        let Some(bytes) = store.get_at(
            DocumentScope::DeviceLocal,
            GRANT_DOCUMENT_NAMESPACE,
            &grant_address(caller_fingerprint, target_digest)?,
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

#[cfg(feature = "vault")]
fn grant_target_digest(target: &GrantTarget<'_>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(GRANT_TARGET_DOMAIN);
    match target {
        GrantTarget::Namespace { scope, namespace } => {
            digest.update([match scope {
                DocumentScope::DeviceLocal => 1,
                DocumentScope::DeviceCache => 3,
            }]);
            append_digest_bytes(&mut digest, namespace);
        }
        GrantTarget::Entry {
            scope,
            namespace,
            address,
        } => {
            digest.update([match scope {
                DocumentScope::DeviceLocal => 2,
                DocumentScope::DeviceCache => 4,
            }]);
            append_digest_bytes(&mut digest, namespace);
            append_digest_bytes(&mut digest, address.item().as_bytes());
            if let Some(field) = address.field() {
                digest.update([1]);
                append_digest_bytes(&mut digest, field.as_bytes());
            } else {
                digest.update([0]);
            }
        }
    }
    digest.finalize().into()
}

#[cfg(feature = "vault")]
fn grant_address(
    caller_fingerprint: [u8; 32],
    target_digest: [u8; 32],
) -> VaultResult<SecretAddress> {
    SecretAddress::new(
        format!(
            "grant/{}/{}",
            URL_SAFE_NO_PAD.encode(caller_fingerprint),
            URL_SAFE_NO_PAD.encode(target_digest)
        ),
        None,
    )
}

#[cfg(feature = "vault")]
fn response_error(error: &VaultError) -> VaultResponseError {
    let code = match error {
        VaultError::AuthorizationRequired => VaultResponseErrorCode::AuthorizationRequired,
        VaultError::Replay => VaultResponseErrorCode::Replay,
        VaultError::Sealed | VaultError::WorkerUnavailable => VaultResponseErrorCode::Sealed,
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

fn validate_identity_component(name: &str, value: &str) -> VaultResult<()> {
    if value.is_empty() || value.len() > MAX_IDENTITY_COMPONENT_BYTES {
        return Err(VaultError::Protocol(format!(
            "caller {name} is empty or too long"
        )));
    }
    Ok(())
}

fn validate_namespace(namespace: &[u8]) -> VaultResult<()> {
    if namespace.is_empty() || namespace.len() > MAX_NAMESPACE_BYTES {
        return Err(VaultError::Protocol(
            "document namespace is empty or too long".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(feature = "vault")]
fn append_digest_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    /// Every enclosing type derives `Debug`, so the redaction has to hold
    /// through a whole request and response, not only on the leaf type.
    #[test]
    fn debug_output_never_carries_secret_bytes() {
        const NEEDLE: &[u8] = b"needle-secret-value";

        let request = VaultRequest::new(VaultAction::Put {
            namespace: b"secretspec".to_vec(),
            address: WireSecretAddress::new("demo/default/TOKEN", None),
            value: WireSecret::new(NEEDLE.to_vec()),
            evict_at: None,
        })
        .unwrap();
        let response = VaultResponse::success(
            request.request_id(),
            VaultResponseBody::Secret {
                value: Some(WireSecret::new(NEEDLE.to_vec())),
            },
        );

        for rendered in [
            format!("{:?}", WireSecret::new(NEEDLE.to_vec())),
            format!("{request:?}"),
            format!("{response:?}"),
        ] {
            assert!(
                !rendered.contains(str::from_utf8(NEEDLE).unwrap()),
                "secret bytes appeared in Debug output: {rendered}"
            );
            assert!(rendered.contains("REDACTED"));
        }
    }
}

#[cfg(all(test, feature = "vault", feature = "hardware"))]
mod tests {
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
        let request = VaultRequest::new(VaultAction::Get {
            namespace: b"secretspec".to_vec(),
            address: address(),
        })
        .unwrap();
        let bytes = request.encode().unwrap();
        let decoded = VaultRequest::decode(&bytes).unwrap();
        assert_eq!(decoded.request_id(), request.request_id());
        assert!(matches!(decoded.action, VaultAction::Get { .. }));
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

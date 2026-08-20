#[cfg(feature = "agent")]
use std::collections::{BTreeSet, HashSet, VecDeque};
use std::fmt;
#[cfg(feature = "agent")]
use std::sync::Mutex;
#[cfg(feature = "agent")]
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
#[cfg(feature = "agent")]
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::{AgentError, AgentResult, SecretAddress};
#[cfg(feature = "agent")]
use super::{AgentStore, DocumentScope};

const PROTOCOL_VERSION: u8 = 1;
#[cfg(feature = "agent")]
const GRANT_VERSION: u8 = 1;
const REQUEST_ID_BYTES: usize = 16;
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_IDENTITY_COMPONENT_BYTES: usize = 4 * 1024;
const MAX_NAMESPACE_BYTES: usize = 4 * 1024;
#[cfg(feature = "agent")]
const MAX_REPLAY_IDS: usize = 4096;
#[cfg(feature = "agent")]
const GRANT_DOCUMENT_NAMESPACE: &[u8] = b"factorseal-agent-grants/v1";
#[cfg(feature = "agent")]
const CALLER_FINGERPRINT_DOMAIN: &[u8] = b"factorseal/caller-identity/v1\0";
#[cfg(feature = "agent")]
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
    ) -> AgentResult<Self> {
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

    #[cfg(feature = "agent")]
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

    fn validate(&self) -> AgentResult<()> {
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
    pub fn random() -> AgentResult<Self> {
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

    /// Validate the public wire address without performing an agent request.
    pub fn validate(&self) -> AgentResult<()> {
        self.resolve().map(|_| ())
    }

    fn resolve(&self) -> AgentResult<SecretAddress> {
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
pub struct AgentRequest {
    version: u8,
    request_id: RequestId,
    pub action: AgentAction,
}

impl AgentRequest {
    pub fn new(action: AgentAction) -> AgentResult<Self> {
        Ok(Self {
            version: PROTOCOL_VERSION,
            request_id: RequestId::random()?,
            action,
        })
    }

    #[must_use]
    pub const fn with_id(request_id: RequestId, action: AgentAction) -> Self {
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

    pub fn decode(bytes: &[u8]) -> AgentResult<Self> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(AgentError::Protocol("request is too large".to_owned()));
        }
        let request: Self = serde_json::from_slice(bytes)
            .map_err(|error| AgentError::Protocol(error.to_string()))?;
        request.validate()?;
        Ok(request)
    }

    pub fn encode(&self) -> AgentResult<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|error| AgentError::Protocol(error.to_string()))?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(AgentError::Protocol("request is too large".to_owned()));
        }
        Ok(Zeroizing::new(bytes))
    }

    fn validate(&self) -> AgentResult<()> {
        if self.version != PROTOCOL_VERSION {
            return Err(AgentError::Protocol(
                "unsupported request version".to_owned(),
            ));
        }
        self.action.validate()
    }
}

/// Operations available to an authenticated local client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AgentAction {
    Status,
    Get {
        namespace: Vec<u8>,
        address: WireSecretAddress,
    },
    Put {
        namespace: Vec<u8>,
        address: WireSecretAddress,
        value: WireSecret,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evict_at: Option<u64>,
    },
    Delete {
        namespace: Vec<u8>,
        address: WireSecretAddress,
    },
    Clear {
        namespace: Vec<u8>,
    },
    Lock {
        namespace: Vec<u8>,
    },
}

impl AgentAction {
    fn validate(&self) -> AgentResult<()> {
        match self {
            Self::Status => Ok(()),
            Self::Get { namespace, address }
            | Self::Delete { namespace, address }
            | Self::Put {
                namespace, address, ..
            } => {
                validate_namespace(namespace)?;
                address.resolve().map(|_| ())
            }
            Self::Clear { namespace } | Self::Lock { namespace } => validate_namespace(namespace),
        }
    }
}

/// Permission persisted in one caller grant.
#[cfg(feature = "agent")]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantPermission {
    Get,
    Put,
    Delete,
    Clear,
    Lock,
}

/// Successful or failed response bound to the request ID.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResponse {
    version: u8,
    request_id: RequestId,
    pub result: Result<AgentResponseBody, AgentResponseError>,
}

/// Transport-independent client boundary used by integrations such as
/// SecretSpec. Implementations authenticate the caller through their native
/// platform transport; they never open the agent database directly.
pub trait AgentClient: Send + Sync {
    fn request(&self, request: &AgentRequest) -> AgentResult<AgentResponse>;
}

impl AgentResponse {
    /// Construct a successful response for an [`AgentClient`] implementation.
    #[must_use]
    pub const fn success(request_id: RequestId, body: AgentResponseBody) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            result: Ok(body),
        }
    }

    /// Construct a failed response for an [`AgentClient`] implementation.
    #[must_use]
    pub const fn failure(request_id: RequestId, error: AgentResponseError) -> Self {
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

    pub fn decode(bytes: &[u8]) -> AgentResult<Self> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(AgentError::Protocol("response is too large".to_owned()));
        }
        let response: Self = serde_json::from_slice(bytes)
            .map_err(|error| AgentError::Protocol(error.to_string()))?;
        if response.version != PROTOCOL_VERSION {
            return Err(AgentError::Protocol(
                "unsupported response version".to_owned(),
            ));
        }
        Ok(response)
    }

    pub fn encode(&self) -> AgentResult<Zeroizing<Vec<u8>>> {
        let bytes =
            serde_json::to_vec(self).map_err(|error| AgentError::Protocol(error.to_string()))?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(AgentError::Protocol("response is too large".to_owned()));
        }
        Ok(Zeroizing::new(bytes))
    }
}

/// Response data. Secret bytes are zeroized when this value is dropped.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AgentResponseBody {
    Status {
        unlocked: bool,
        seal_id: String,
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
    Locked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResponseError {
    pub code: AgentResponseErrorCode,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentResponseErrorCode {
    InvalidRequest,
    AuthorizationRequired,
    Replay,
    Locked,
    Conflict,
    Internal,
}

/// Bounded lifetime for one hardware-unlocked agent session.
#[cfg(feature = "agent")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnlockLeasePolicy {
    pub idle_timeout: Duration,
    pub maximum_lifetime: Duration,
}

#[cfg(feature = "agent")]
impl Default for UnlockLeasePolicy {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_mins(5),
            maximum_lifetime: Duration::from_hours(8),
        }
    }
}

#[cfg(feature = "agent")]
impl UnlockLeasePolicy {
    fn validate(self) -> AgentResult<()> {
        if self.idle_timeout.is_zero()
            || self.maximum_lifetime.is_zero()
            || self.idle_timeout > self.maximum_lifetime
        {
            return Err(AgentError::Protocol(
                "unlock lease timeouts are invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "agent")]
struct UnlockLease {
    idle_timeout_seconds: u64,
    idle_deadline: u64,
    absolute_deadline: u64,
}

#[cfg(feature = "agent")]
impl UnlockLease {
    fn new(now: u64, policy: UnlockLeasePolicy) -> AgentResult<Self> {
        policy.validate()?;
        let idle_timeout_seconds = policy.idle_timeout.as_secs();
        let absolute_deadline = now
            .checked_add(policy.maximum_lifetime.as_secs())
            .ok_or_else(|| AgentError::Protocol("unlock lease overflows time".to_owned()))?;
        let idle_deadline = now
            .checked_add(idle_timeout_seconds)
            .ok_or_else(|| AgentError::Protocol("unlock lease overflows time".to_owned()))?
            .min(absolute_deadline);
        Ok(Self {
            idle_timeout_seconds,
            idle_deadline,
            absolute_deadline,
        })
    }

    fn is_expired(&self, now: u64) -> bool {
        now >= self.idle_deadline || now >= self.absolute_deadline
    }

    fn touch(&mut self, now: u64) -> AgentResult<()> {
        self.idle_deadline = now
            .checked_add(self.idle_timeout_seconds)
            .ok_or_else(|| AgentError::Protocol("unlock lease overflows time".to_owned()))?
            .min(self.absolute_deadline);
        Ok(())
    }
}

#[cfg(feature = "agent")]
struct ReplayWindow {
    set: HashSet<RequestId>,
    order: VecDeque<RequestId>,
}

#[cfg(feature = "agent")]
impl ReplayWindow {
    fn new() -> Self {
        Self {
            set: HashSet::with_capacity(MAX_REPLAY_IDS),
            order: VecDeque::with_capacity(MAX_REPLAY_IDS),
        }
    }

    fn consume(&mut self, request_id: RequestId) -> AgentResult<()> {
        if !self.set.insert(request_id) {
            return Err(AgentError::Replay);
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

#[cfg(feature = "agent")]
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
#[cfg(feature = "agent")]
pub struct AgentService {
    state: Mutex<ServiceState>,
    lock_handle: AgentStore,
}

#[cfg(feature = "agent")]
struct ServiceState {
    store: AgentStore,
    lease: UnlockLease,
    replay: ReplayWindow,
    /// Whole second the storage eviction sweep last ran in. The sweep
    /// decrypts, verifies, and re-parses every cached document, while platform
    /// event loops poll `expire_if_needed` about ten times a second, so it must
    /// not run once per iteration.
    last_purge_at: u64,
    #[cfg(all(test, feature = "hardware"))]
    purges: usize,
}

#[cfg(feature = "agent")]
impl AgentService {
    pub fn new(store: AgentStore, now: u64, policy: UnlockLeasePolicy) -> AgentResult<Self> {
        let lock_handle = store.clone();
        Ok(Self {
            state: Mutex::new(ServiceState {
                store,
                lease: UnlockLease::new(now, policy)?,
                replay: ReplayWindow::new(),
                // Opening the store already swept this second.
                last_purge_at: now,
                #[cfg(all(test, feature = "hardware"))]
                purges: 0,
            }),
            lock_handle,
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

    /// Persist approval for exactly one caller, namespace, and secret entry.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_entry(
        &self,
        caller: &CallerIdentity,
        namespace: &[u8],
        address: &WireSecretAddress,
        permissions: impl IntoIterator<Item = GrantPermission>,
        expires_at: Option<u64>,
        now: u64,
    ) -> AgentResult<()> {
        let mut state = self.lock_live_state(now)?;
        store_grant(
            &state.store,
            caller,
            GrantTarget::Entry {
                namespace,
                address: &address.resolve()?,
            },
            permissions,
            expires_at,
            now,
        )?;
        state.lease.touch(now)
    }

    /// Persist approval for namespace-wide operations such as cache clear or
    /// a trusted SecretSpec process serving multiple declared entries.
    pub fn authorize_namespace(
        &self,
        caller: &CallerIdentity,
        namespace: &[u8],
        permissions: impl IntoIterator<Item = GrantPermission>,
        expires_at: Option<u64>,
        now: u64,
    ) -> AgentResult<()> {
        let mut state = self.lock_live_state(now)?;
        store_grant(
            &state.store,
            caller,
            GrantTarget::Namespace(namespace),
            permissions,
            expires_at,
            now,
        )?;
        state.lease.touch(now)
    }

    /// Handle one already-decoded request for a transport-authenticated caller.
    #[must_use]
    pub fn handle(
        &self,
        caller: &CallerIdentity,
        request: AgentRequest,
        now: u64,
    ) -> AgentResponse {
        let request_id = request.request_id;
        let result = self.handle_inner(caller, request, now);
        let result = match result {
            Ok(AgentResponseBody::Locked) => Ok(AgentResponseBody::Locked),
            _ if self.lock_handle.is_locked() => Err(AgentError::Locked),
            result => result,
        };
        AgentResponse {
            version: PROTOCOL_VERSION,
            request_id,
            result: result.map_err(|error| response_error(&error)),
        }
    }

    /// Run storage eviction and enforce the lease even when no request arrives.
    ///
    /// Returns `true` once the service has locked and should stop accepting
    /// connections. Platform event loops call this from their bounded timer.
    pub fn expire_if_needed(&self, now: u64) -> AgentResult<bool> {
        if self.lock_handle.is_locked() {
            return Ok(true);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| AgentError::WorkerUnavailable)?;
        if state.store.is_locked() {
            return Ok(true);
        }
        if state.lease.is_expired(now) {
            state.store.lock();
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

    /// Logout, suspend, and shutdown hooks use the same immediate lock path.
    pub fn lock(&self) -> AgentResult<()> {
        // This clone sits outside the request-state mutex so a lifecycle event
        // can fail closed even if a request panics and poisons that mutex.
        self.lock_handle.lock();
        Ok(())
    }

    fn lock_live_state(&self, now: u64) -> AgentResult<std::sync::MutexGuard<'_, ServiceState>> {
        if self.lock_handle.is_locked() {
            return Err(AgentError::Locked);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| AgentError::WorkerUnavailable)?;
        if state.store.is_locked() || state.lease.is_expired(now) {
            state.store.lock();
            return Err(AgentError::Locked);
        }
        Ok(state)
    }

    #[allow(clippy::too_many_lines)]
    fn handle_inner(
        &self,
        caller: &CallerIdentity,
        request: AgentRequest,
        now: u64,
    ) -> AgentResult<AgentResponseBody> {
        caller.validate()?;
        request.validate()?;
        let mut state = self.lock_live_state(now)?;
        state.replay.consume(request.request_id)?;

        let result = match request.action {
            AgentAction::Status => AgentResponseBody::Status {
                unlocked: true,
                seal_id: state.store.device().seal_id().to_string(),
                device_key_id: state.store.device().device_key_id().to_string(),
                hardware_backend: state.store.device().hardware_backend().to_owned(),
                idle_deadline: state.lease.idle_deadline,
                absolute_deadline: state.lease.absolute_deadline,
            },
            AgentAction::Get { namespace, address } => {
                let address = address.resolve()?;
                require_grant(
                    &state.store,
                    caller,
                    &namespace,
                    Some(&address),
                    GrantPermission::Get,
                    now,
                )?;
                let value = state
                    .store
                    .get_at(DocumentScope::DeviceCache, &namespace, &address, now)?
                    .map(|value| WireSecret::new(value.to_vec()));
                AgentResponseBody::Secret { value }
            }
            AgentAction::Put {
                namespace,
                address,
                value,
                evict_at,
            } => {
                let address = address.resolve()?;
                require_grant(
                    &state.store,
                    caller,
                    &namespace,
                    Some(&address),
                    GrantPermission::Put,
                    now,
                )?;
                // A deadline equal to the agent's whole-second clock is a
                // valid immediately-expired write. This lets sub-second
                // upstream TTLs round down without exceeding their bound.
                if evict_at.is_some_and(|deadline| deadline < now) {
                    return Err(AgentError::Expired);
                }
                state.store.put_at(
                    DocumentScope::DeviceCache,
                    &namespace,
                    &address,
                    value.expose(),
                    evict_at,
                )?;
                AgentResponseBody::Stored
            }
            AgentAction::Delete { namespace, address } => {
                let address = address.resolve()?;
                require_grant(
                    &state.store,
                    caller,
                    &namespace,
                    Some(&address),
                    GrantPermission::Delete,
                    now,
                )?;
                let existed =
                    state
                        .store
                        .delete(DocumentScope::DeviceCache, &namespace, &address)?;
                AgentResponseBody::Deleted { existed }
            }
            AgentAction::Clear { namespace } => {
                require_grant(
                    &state.store,
                    caller,
                    &namespace,
                    None,
                    GrantPermission::Clear,
                    now,
                )?;
                let entries = state.store.clear(DocumentScope::DeviceCache, &namespace)?;
                AgentResponseBody::Cleared { entries }
            }
            AgentAction::Lock { namespace } => {
                require_grant(
                    &state.store,
                    caller,
                    &namespace,
                    None,
                    GrantPermission::Lock,
                    now,
                )?;
                state.store.lock();
                AgentResponseBody::Locked
            }
        };
        if !state.store.is_locked() {
            state.lease.touch(now)?;
        }
        Ok(result)
    }
}

#[cfg(feature = "agent")]
#[derive(Clone, Copy)]
enum GrantTarget<'a> {
    Namespace(&'a [u8]),
    Entry {
        namespace: &'a [u8],
        address: &'a SecretAddress,
    },
}

#[cfg(feature = "agent")]
fn store_grant(
    store: &AgentStore,
    caller: &CallerIdentity,
    target: GrantTarget<'_>,
    permissions: impl IntoIterator<Item = GrantPermission>,
    expires_at: Option<u64>,
    now: u64,
) -> AgentResult<()> {
    caller.validate()?;
    if expires_at.is_some_and(|deadline| deadline <= now) {
        return Err(AgentError::Expired);
    }
    let caller_fingerprint = caller.fingerprint();
    let target_digest = grant_target_digest(&target);
    let permissions: BTreeSet<_> = permissions.into_iter().collect();
    if permissions.is_empty() {
        return Err(AgentError::Protocol(
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
        serde_json::to_vec(&grant).map_err(|error| AgentError::Protocol(error.to_string()))?,
    );
    store.put_at(
        DocumentScope::DeviceLocal,
        GRANT_DOCUMENT_NAMESPACE,
        &grant_address(caller_fingerprint, target_digest)?,
        &bytes,
        expires_at,
    )
}

#[cfg(feature = "agent")]
fn require_grant(
    store: &AgentStore,
    caller: &CallerIdentity,
    namespace: &[u8],
    address: Option<&SecretAddress>,
    permission: GrantPermission,
    now: u64,
) -> AgentResult<()> {
    let caller_fingerprint = caller.fingerprint();
    let mut targets = Vec::with_capacity(2);
    if let Some(address) = address {
        targets.push(grant_target_digest(&GrantTarget::Entry {
            namespace,
            address,
        }));
    }
    targets.push(grant_target_digest(&GrantTarget::Namespace(namespace)));
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
            .map_err(|error| AgentError::Protocol(error.to_string()))?;
        if grant.version == GRANT_VERSION
            && grant.caller_fingerprint == caller_fingerprint
            && grant.target_digest == target_digest
            && grant.expires_at.is_none_or(|deadline| deadline > now)
            && grant.permissions.contains(&permission)
        {
            return Ok(());
        }
    }
    Err(AgentError::AuthorizationRequired)
}

#[cfg(feature = "agent")]
fn grant_target_digest(target: &GrantTarget<'_>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(GRANT_TARGET_DOMAIN);
    match target {
        GrantTarget::Namespace(namespace) => {
            digest.update([1]);
            append_digest_bytes(&mut digest, namespace);
        }
        GrantTarget::Entry { namespace, address } => {
            digest.update([2]);
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

#[cfg(feature = "agent")]
fn grant_address(
    caller_fingerprint: [u8; 32],
    target_digest: [u8; 32],
) -> AgentResult<SecretAddress> {
    SecretAddress::new(
        format!(
            "grant/{}/{}",
            URL_SAFE_NO_PAD.encode(caller_fingerprint),
            URL_SAFE_NO_PAD.encode(target_digest)
        ),
        None,
    )
}

#[cfg(feature = "agent")]
fn response_error(error: &AgentError) -> AgentResponseError {
    let code = match error {
        AgentError::AuthorizationRequired => AgentResponseErrorCode::AuthorizationRequired,
        AgentError::Replay => AgentResponseErrorCode::Replay,
        AgentError::Locked | AgentError::WorkerUnavailable => AgentResponseErrorCode::Locked,
        AgentError::Conflict => AgentResponseErrorCode::Conflict,
        AgentError::EmptyAddress { .. }
        | AgentError::AddressTooLong { .. }
        | AgentError::Expired
        | AgentError::Protocol(_) => AgentResponseErrorCode::InvalidRequest,
        AgentError::InvalidData(_)
        | AgentError::Automerge(_)
        | AgentError::Crypto
        | AgentError::Signature
        | AgentError::Random(_)
        | AgentError::Database(_)
        | AgentError::Seal(_) => AgentResponseErrorCode::Internal,
    };
    let message = match code {
        AgentResponseErrorCode::InvalidRequest => "the request is invalid",
        AgentResponseErrorCode::AuthorizationRequired => "application authorization is required",
        AgentResponseErrorCode::Replay => "the request was already consumed",
        AgentResponseErrorCode::Locked => "the agent is locked",
        AgentResponseErrorCode::Conflict => "the secret has unresolved concurrent values",
        AgentResponseErrorCode::Internal => "the agent could not complete the request",
    };
    AgentResponseError {
        code,
        message: message.to_owned(),
    }
}

fn validate_identity_component(name: &str, value: &str) -> AgentResult<()> {
    if value.is_empty() || value.len() > MAX_IDENTITY_COMPONENT_BYTES {
        return Err(AgentError::Protocol(format!(
            "caller {name} is empty or too long"
        )));
    }
    Ok(())
}

fn validate_namespace(namespace: &[u8]) -> AgentResult<()> {
    if namespace.is_empty() || namespace.len() > MAX_NAMESPACE_BYTES {
        return Err(AgentError::Protocol(
            "document namespace is empty or too long".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(feature = "agent")]
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

        let request = AgentRequest::new(AgentAction::Put {
            namespace: b"secretspec".to_vec(),
            address: WireSecretAddress::new("demo/default/TOKEN", None),
            value: WireSecret::new(NEEDLE.to_vec()),
            evict_at: None,
        })
        .unwrap();
        let response = AgentResponse::success(
            request.request_id(),
            AgentResponseBody::Secret {
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

#[cfg(all(test, feature = "agent", feature = "hardware"))]
mod tests {
    use super::*;
    use crate::Seal;

    fn service(now: u64, policy: UnlockLeasePolicy) -> (tempfile::TempDir, AgentService) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        let seal = Seal::create_for_test(&root).unwrap();
        let store = AgentStore::open(root, seal).unwrap();
        (directory, AgentService::new(store, now, policy).unwrap())
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
        let request = AgentRequest::new(AgentAction::Get {
            namespace: b"secretspec".to_vec(),
            address: address(),
        })
        .unwrap();
        let bytes = request.encode().unwrap();
        let decoded = AgentRequest::decode(&bytes).unwrap();
        assert_eq!(decoded.request_id(), request.request_id());
        assert!(matches!(decoded.action, AgentAction::Get { .. }));
        assert!(AgentRequest::decode(&vec![0; MAX_MESSAGE_BYTES + 1]).is_err());
    }

    #[test]
    fn wire_errors_never_echo_internal_or_secret_details() {
        let marker = "visible-project/API_TOKEN=needle-secret-value";
        for error in [
            AgentError::InvalidData(marker.to_owned()),
            AgentError::Protocol(marker.to_owned()),
            AgentError::Database(marker.to_owned()),
            AgentError::Seal(marker.to_owned()),
        ] {
            let response = response_error(&error);
            assert!(!response.message.contains(marker));
            assert!(!response.message.contains("API_TOKEN"));
        }
    }

    #[test]
    fn exact_grant_is_required_and_replay_is_rejected() {
        let (_directory, service) = service(100, UnlockLeasePolicy::default());
        let caller = caller();
        let put_id = RequestId::from_bytes([1; REQUEST_ID_BYTES]);
        let put = || {
            AgentRequest::with_id(
                put_id,
                AgentAction::Put {
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
            AgentResponseErrorCode::AuthorizationRequired
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
            AgentResponseErrorCode::Replay
        );

        let accepted = service.handle(
            &caller,
            AgentRequest::new(AgentAction::Put {
                namespace: b"secretspec".to_vec(),
                address: address(),
                value: WireSecret::new(b"secret".to_vec()),
                evict_at: None,
            })
            .unwrap(),
            102,
        );
        assert!(matches!(accepted.result, Ok(AgentResponseBody::Stored)));
    }

    #[test]
    fn caller_identity_is_part_of_grant_authority() {
        let (_directory, service) = service(100, UnlockLeasePolicy::default());
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
            AgentRequest::new(AgentAction::Get {
                namespace: b"secretspec".to_vec(),
                address: address(),
            })
            .unwrap(),
            101,
        );
        assert_eq!(
            response.result.unwrap_err().code,
            AgentResponseErrorCode::AuthorizationRequired
        );
    }

    #[test]
    fn idle_deadline_locks_without_a_request() {
        let policy = UnlockLeasePolicy {
            idle_timeout: Duration::from_secs(5),
            maximum_lifetime: Duration::from_secs(10),
        };
        let (_directory, service) = service(100, policy);
        assert!(!service.expire_if_needed(104).unwrap());
        assert!(service.expire_if_needed(105).unwrap());

        let response = service.handle(
            &caller(),
            AgentRequest::new(AgentAction::Status).unwrap(),
            105,
        );
        assert_eq!(
            response.result.unwrap_err().code,
            AgentResponseErrorCode::Locked
        );
    }

    #[test]
    fn storage_eviction_sweeps_at_most_once_a_second() {
        let (_directory, service) = service(100, UnlockLeasePolicy::default());
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
    fn explicit_lock_invalidates_the_service() {
        let (_directory, service) = service(100, UnlockLeasePolicy::default());
        let caller = caller();
        service
            .authorize_namespace(&caller, b"secretspec", [GrantPermission::Lock], None, 100)
            .unwrap();
        let response = service.handle(
            &caller,
            AgentRequest::new(AgentAction::Lock {
                namespace: b"secretspec".to_vec(),
            })
            .unwrap(),
            101,
        );
        assert!(matches!(response.result, Ok(AgentResponseBody::Locked)));
        assert!(service.expire_if_needed(101).unwrap());
    }

    #[test]
    fn lifecycle_lock_survives_a_poisoned_request_mutex() {
        let (_directory, service) = service(100, UnlockLeasePolicy::default());
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            service.poison_state_for_test();
        }));
        assert!(poisoned.is_err());

        service.lock().unwrap();
        assert!(service.lock_handle.is_locked());
    }
}

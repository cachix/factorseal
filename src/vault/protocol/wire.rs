use std::fmt;
#[cfg(feature = "vault-store")]
use std::io;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
#[cfg(feature = "vault-store")]
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::vault::{SecretAddress, VaultError, VaultResult};

pub(super) const PROTOCOL_VERSION: u8 = 2;
pub(super) const REQUEST_ID_BYTES: usize = 16;
pub(super) const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_IDENTITY_COMPONENT_BYTES: usize = 4 * 1024;
const MAX_APPLICATION_COMPONENT_BYTES: usize = 4 * 1024;
const MAX_APPLICATION_BASE_DIR_BYTES: usize = 32 * 1024;
const MAX_NAMESPACE_BYTES: usize = 4 * 1024;
const MAX_MUTATIONS_PER_REQUEST: usize = 64;
#[cfg(feature = "vault-store")]
const CALLER_FINGERPRINT_DOMAIN: &[u8] = b"factorseal/caller-identity/v1\0";

/// Platform that authenticated one local IPC caller.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CallerPlatform {
    Android,
    Ios,
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

    #[cfg(feature = "vault-store")]
    pub(super) fn fingerprint(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(CALLER_FINGERPRINT_DOMAIN);
        digest.update([match self.platform {
            CallerPlatform::Android => 4,
            CallerPlatform::Ios => 5,
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

    pub(super) fn validate(&self) -> VaultResult<()> {
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

    pub(super) fn resolve(&self) -> VaultResult<SecretAddress> {
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
    /// Caller-declared application metadata for display and audit. This is
    /// never transport-authenticated identity or authorization input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application: Option<VaultApplicationContext>,
    pub action: VaultAction,
}

/// Caller-declared application metadata forwarded by integrations such as
/// SecretSpec. The transport-authenticated [`CallerIdentity`] remains the only
/// application principal used for grants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultApplicationContext {
    pub project: Option<String>,
    pub profile: Option<String>,
    pub base_dir: Option<String>,
    pub reason: Option<String>,
}

impl VaultApplicationContext {
    pub fn new(
        project: Option<String>,
        profile: Option<String>,
        base_dir: Option<String>,
        reason: Option<String>,
    ) -> VaultResult<Self> {
        let context = Self {
            project,
            profile,
            base_dir,
            reason,
        };
        context.validate()?;
        Ok(context)
    }

    fn validate(&self) -> VaultResult<()> {
        for (name, value) in [
            ("project", self.project.as_deref()),
            ("profile", self.profile.as_deref()),
        ] {
            if let Some(value) = value
                && (value.is_empty() || value.len() > MAX_APPLICATION_COMPONENT_BYTES)
            {
                return Err(VaultError::Protocol(format!(
                    "application {name} is empty or too long"
                )));
            }
        }
        if self
            .base_dir
            .as_ref()
            .is_some_and(|value| value.len() > MAX_APPLICATION_BASE_DIR_BYTES)
        {
            return Err(VaultError::Protocol(
                "application base directory is too long".to_owned(),
            ));
        }
        if let Some(base_dir) = &self.base_dir
            && !std::path::Path::new(base_dir).is_absolute()
        {
            return Err(VaultError::Protocol(
                "application base directory must be absolute".to_owned(),
            ));
        }
        if self
            .reason
            .as_ref()
            .is_some_and(|value| value.len() > MAX_APPLICATION_COMPONENT_BYTES)
        {
            return Err(VaultError::Protocol(
                "application reason is too long".to_owned(),
            ));
        }
        Ok(())
    }
}

impl VaultRequest {
    pub fn new(action: VaultAction) -> VaultResult<Self> {
        Ok(Self {
            version: PROTOCOL_VERSION,
            request_id: RequestId::random()?,
            application: None,
            action,
        })
    }

    pub fn new_with_application(
        action: VaultAction,
        application: VaultApplicationContext,
    ) -> VaultResult<Self> {
        application.validate()?;
        Ok(Self {
            version: PROTOCOL_VERSION,
            request_id: RequestId::random()?,
            application: Some(application),
            action,
        })
    }

    #[must_use]
    pub const fn with_id(request_id: RequestId, action: VaultAction) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            application: None,
            action,
        }
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    #[must_use]
    pub const fn application(&self) -> Option<&VaultApplicationContext> {
        self.application.as_ref()
    }

    pub fn decode(bytes: &[u8]) -> VaultResult<Self> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(VaultError::Protocol("request is too large".to_owned()));
        }
        let request: Self = serde_json::from_slice(bytes)
            .map_err(|error| VaultError::Protocol(error.to_string()))?;
        request.validate_fields()?;
        Ok(request)
    }

    pub fn encode(&self) -> VaultResult<Zeroizing<Vec<u8>>> {
        self.validate_fields()?;
        let bytes =
            serde_json::to_vec(self).map_err(|error| VaultError::Protocol(error.to_string()))?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(VaultError::Protocol("request is too large".to_owned()));
        }
        Ok(Zeroizing::new(bytes))
    }

    #[cfg(feature = "vault-store")]
    pub(super) fn validate(&self) -> VaultResult<()> {
        self.validate_fields()?;
        let mut writer = BoundedMessageWriter::new(MAX_MESSAGE_BYTES);
        serde_json::to_writer(&mut writer, self)
            .map_err(|_| VaultError::Protocol("request is too large".to_owned()))?;
        Ok(())
    }

    fn validate_fields(&self) -> VaultResult<()> {
        if self.version != PROTOCOL_VERSION {
            return Err(VaultError::Protocol(
                "unsupported request version".to_owned(),
            ));
        }
        if let Some(application) = &self.application {
            application.validate()?;
        }
        self.action.validate()
    }
}

/// Count serialized bytes without making a second secret-bearing allocation.
/// Direct embedders call `VaultService::handle` without transport framing, so
/// the service must enforce the same bound as `decode` itself.
#[cfg(feature = "vault-store")]
struct BoundedMessageWriter {
    remaining: usize,
}

#[cfg(feature = "vault-store")]
impl BoundedMessageWriter {
    const fn new(maximum: usize) -> Self {
        Self { remaining: maximum }
    }
}

#[cfg(feature = "vault-store")]
impl io::Write for BoundedMessageWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other("message exceeds configured bound"));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
    /// Atomically apply ordered durable-keyring mutations to one namespace.
    /// Each entry is authorized independently before the store receives any
    /// mutation, and the store commits the entire group in one generation.
    Mutate {
        namespace: Vec<u8>,
        mutations: Vec<VaultMutation>,
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
    pub(super) fn validate(&self) -> VaultResult<()> {
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
            Self::Mutate {
                namespace,
                mutations,
            } => {
                validate_namespace(namespace)?;
                if mutations.is_empty() || mutations.len() > MAX_MUTATIONS_PER_REQUEST {
                    return Err(VaultError::Protocol(format!(
                        "mutation request must contain between one and {MAX_MUTATIONS_PER_REQUEST} operations"
                    )));
                }
                for mutation in mutations {
                    mutation.validate()?;
                }
                Ok(())
            }
            Self::Clear { namespace }
            | Self::ClearCache { namespace }
            | Self::Seal { namespace }
            | Self::SealCache { namespace } => validate_namespace(namespace),
        }
    }
}

/// One ordered change in a [`VaultAction::Mutate`] request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum VaultMutation {
    Put {
        address: WireSecretAddress,
        value: WireSecret,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evict_at: Option<u64>,
    },
    Delete {
        address: WireSecretAddress,
    },
}

impl VaultMutation {
    pub(super) fn validate(&self) -> VaultResult<()> {
        match self {
            Self::Put { address, .. } | Self::Delete { address } => address.resolve().map(|_| ()),
        }
    }
}
/// Successful or failed response bound to the request ID.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultResponse {
    pub(super) version: u8,
    pub(super) request_id: RequestId,
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
    /// Only a live, unsealed vault answers this: `Status` is served behind the
    /// live-state lock, which fails closed once the lease expires or the vault
    /// seals.
    Status {
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
    Mutated,
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

#[cfg(feature = "vault-store")]
pub(super) fn append_digest_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

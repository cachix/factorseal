use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use zeroize::Zeroizing;

/// Version of FactorSeal's protocol-neutral phone unlock exchange.
pub const PHONE_UNLOCK_VERSION: u8 = 1;
/// Number of bytes in a FactorSeal vault identifier.
pub const PHONE_VAULT_ID_BYTES: usize = 16;
/// Number of bytes in a phone credential identifier.
pub const PHONE_CREDENTIAL_ID_BYTES: usize = 16;
/// Number of bytes in a one-time phone unlock request identifier.
pub const PHONE_REQUEST_ID_BYTES: usize = 16;
/// Number of bytes in a one-time phone unlock challenge.
pub const PHONE_CHALLENGE_BYTES: usize = 32;
/// Number of bytes in the independent share retained by a phone.
pub const PHONE_SHARE_BYTES: usize = 32;
/// Longest phone unlock request accepted by the protocol-neutral boundary.
pub const MAX_PHONE_UNLOCK_LIFETIME: Duration = Duration::from_secs(60);

const MAX_LAPTOP_NAME_BYTES: usize = 255;

/// Action authorized by a phone unlock request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PhoneUnlockAction {
    /// Release the enrolled phone share for a keyring unlock.
    UnlockKeyring,
}

impl PhoneUnlockAction {
    /// Return the stable wire name used by protocol adapters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnlockKeyring => "unlock-keyring",
        }
    }
}

/// Public, vault-scoped identifier for one enrolled phone credential.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PhoneCredentialId([u8; PHONE_CREDENTIAL_ID_BYTES]);

impl PhoneCredentialId {
    /// Construct an identifier from its canonical bytes.
    #[must_use]
    pub const fn new(bytes: [u8; PHONE_CREDENTIAL_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the canonical identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PHONE_CREDENTIAL_ID_BYTES] {
        &self.0
    }
}

/// Secret phone-held material used to reconstruct or unwrap a vault key.
///
/// The bytes are zeroized when this value is dropped. This type deliberately
/// does not implement `Clone`, `Serialize`, or a revealing `Debug` format.
pub struct PhoneShare(Zeroizing<[u8; PHONE_SHARE_BYTES]>);

impl PhoneShare {
    /// Move plaintext phone-share bytes into zeroizing memory.
    #[must_use]
    pub fn new(bytes: [u8; PHONE_SHARE_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Expose the share to the vault-key derivation operation.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; PHONE_SHARE_BYTES] {
        &self.0
    }

    /// Move the share into its zeroizing buffer.
    #[must_use]
    pub fn into_zeroizing(self) -> Zeroizing<[u8; PHONE_SHARE_BYTES]> {
        self.0
    }
}

impl fmt::Debug for PhoneShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PhoneShare([REDACTED])")
    }
}

/// One-shot request passed to an authenticated phone-factor transport.
///
/// The transport may serialize these fields using its own framing. An Aliro
/// adapter, for example, can carry them in an encrypted third-party exchange
/// without introducing Aliro types into FactorSeal.
#[derive(Debug, Eq, PartialEq)]
pub struct PhoneUnlockRequest {
    version: u8,
    vault_id: [u8; PHONE_VAULT_ID_BYTES],
    request_id: [u8; PHONE_REQUEST_ID_BYTES],
    challenge: [u8; PHONE_CHALLENGE_BYTES],
    action: PhoneUnlockAction,
    expires_at: u64,
    laptop_name: String,
}

impl PhoneUnlockRequest {
    /// Create a fresh request with random request and challenge values.
    ///
    /// `now` is the current Unix timestamp in seconds. Lifetimes are limited
    /// to [`MAX_PHONE_UNLOCK_LIFETIME`] so a stale authenticated transport
    /// cannot retain a useful request indefinitely.
    pub fn new(
        vault_id: [u8; PHONE_VAULT_ID_BYTES],
        laptop_name: impl Into<String>,
        now: u64,
        lifetime: Duration,
    ) -> PhoneFactorResult<Self> {
        let laptop_name = laptop_name.into();
        if laptop_name.is_empty()
            || laptop_name.len() > MAX_LAPTOP_NAME_BYTES
            || laptop_name.contains('\0')
        {
            return Err(PhoneFactorError::InvalidLaptopName);
        }

        let lifetime_seconds = lifetime.as_secs();
        if lifetime_seconds == 0 || lifetime > MAX_PHONE_UNLOCK_LIFETIME {
            return Err(PhoneFactorError::InvalidLifetime {
                maximum_seconds: MAX_PHONE_UNLOCK_LIFETIME.as_secs(),
            });
        }
        let expires_at = now
            .checked_add(lifetime_seconds)
            .ok_or(PhoneFactorError::ExpirationOverflow)?;

        let mut request_id = [0_u8; PHONE_REQUEST_ID_BYTES];
        getrandom::fill(&mut request_id)
            .map_err(|error| PhoneFactorError::Random(error.to_string()))?;
        let mut challenge = [0_u8; PHONE_CHALLENGE_BYTES];
        getrandom::fill(&mut challenge)
            .map_err(|error| PhoneFactorError::Random(error.to_string()))?;

        Ok(Self {
            version: PHONE_UNLOCK_VERSION,
            vault_id,
            request_id,
            challenge,
            action: PhoneUnlockAction::UnlockKeyring,
            expires_at,
            laptop_name,
        })
    }

    /// Return the FactorSeal phone exchange version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Return the vault identifier bound to this request.
    #[must_use]
    pub const fn vault_id(&self) -> &[u8; PHONE_VAULT_ID_BYTES] {
        &self.vault_id
    }

    /// Return the fresh, one-time request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &[u8; PHONE_REQUEST_ID_BYTES] {
        &self.request_id
    }

    /// Return the fresh, one-time challenge.
    #[must_use]
    pub const fn challenge(&self) -> &[u8; PHONE_CHALLENGE_BYTES] {
        &self.challenge
    }

    /// Return the requested action.
    #[must_use]
    pub const fn action(&self) -> PhoneUnlockAction {
        self.action
    }

    /// Return the exclusive Unix expiration timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Return the laptop name displayed for user authorization.
    #[must_use]
    pub fn laptop_name(&self) -> &str {
        &self.laptop_name
    }

    /// Verify and consume a response from an authenticated current session.
    ///
    /// Consuming the request makes the intended one-response lifecycle
    /// explicit. The caller must still invalidate the transport session and
    /// request ID after any success or failure.
    pub fn accept_response(
        self,
        response: PhoneUnlockResponse,
        now: u64,
        enrolled_credentials: &[PhoneCredentialId],
    ) -> PhoneFactorResult<ValidatedPhoneShare> {
        if now >= self.expires_at {
            return Err(PhoneFactorError::Expired);
        }
        if response.version != self.version {
            return Err(PhoneFactorError::UnsupportedVersion {
                expected: self.version,
                actual: response.version,
            });
        }
        if response.vault_id != self.vault_id {
            return Err(PhoneFactorError::BindingMismatch { field: "vault ID" });
        }
        if response.request_id != self.request_id {
            return Err(PhoneFactorError::BindingMismatch {
                field: "request ID",
            });
        }
        if response.challenge != self.challenge {
            return Err(PhoneFactorError::BindingMismatch { field: "challenge" });
        }
        if response.action != self.action {
            return Err(PhoneFactorError::BindingMismatch { field: "action" });
        }
        if !enrolled_credentials.contains(&response.credential_id) {
            return Err(PhoneFactorError::CredentialNotEnrolled);
        }

        Ok(ValidatedPhoneShare {
            credential_id: response.credential_id,
            phone_share: response.phone_share,
        })
    }
}

/// Response produced only after authenticating the phone and authorizing use.
///
/// Implementations of [`PhoneFactor`] must not construct this response from an
/// unauthenticated transport or from a different protocol session.
#[derive(Debug)]
pub struct PhoneUnlockResponse {
    version: u8,
    vault_id: [u8; PHONE_VAULT_ID_BYTES],
    request_id: [u8; PHONE_REQUEST_ID_BYTES],
    challenge: [u8; PHONE_CHALLENGE_BYTES],
    action: PhoneUnlockAction,
    credential_id: PhoneCredentialId,
    phone_share: PhoneShare,
}

impl PhoneUnlockResponse {
    /// Construct a response decoded from an authenticated phone session.
    #[must_use]
    pub fn new(
        version: u8,
        vault_id: [u8; PHONE_VAULT_ID_BYTES],
        request_id: [u8; PHONE_REQUEST_ID_BYTES],
        challenge: [u8; PHONE_CHALLENGE_BYTES],
        action: PhoneUnlockAction,
        credential_id: PhoneCredentialId,
        phone_share: PhoneShare,
    ) -> Self {
        Self {
            version,
            vault_id,
            request_id,
            challenge,
            action,
            credential_id,
            phone_share,
        }
    }
}

/// An enrolled phone share after complete request/response binding checks.
#[derive(Debug)]
pub struct ValidatedPhoneShare {
    credential_id: PhoneCredentialId,
    phone_share: PhoneShare,
}

impl ValidatedPhoneShare {
    /// Return the enrolled credential that released this share.
    #[must_use]
    pub const fn credential_id(&self) -> PhoneCredentialId {
        self.credential_id
    }

    /// Borrow the zeroizing phone share for vault-key derivation.
    #[must_use]
    pub fn phone_share(&self) -> &PhoneShare {
        &self.phone_share
    }

    /// Split the validated response into its credential and share.
    #[must_use]
    pub fn into_parts(self) -> (PhoneCredentialId, PhoneShare) {
        (self.credential_id, self.phone_share)
    }
}

/// Error returned while constructing or executing a phone-factor request.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PhoneFactorError {
    /// No configured phone transport is currently available.
    #[error("phone factor transport is unavailable: {0}")]
    Unavailable(String),
    /// The request made no progress before its transport deadline.
    #[error("phone factor request timed out")]
    TimedOut,
    /// The caller or phone dismissed the request.
    #[error("phone factor request was cancelled")]
    Cancelled,
    /// The phone rejected user authentication or authorization.
    #[error("phone factor authorization was denied")]
    AuthorizationDenied,
    /// The authenticated transport failed its protocol exchange.
    #[error("phone factor protocol failed: {0}")]
    Protocol(String),
    /// The request's user-visible laptop name is invalid.
    #[error("phone unlock laptop name must be non-empty, contain no NUL, and fit in 255 bytes")]
    InvalidLaptopName,
    /// The request lifetime is zero or exceeds the configured maximum.
    #[error("phone unlock lifetime must be between 1 and {maximum_seconds} seconds")]
    InvalidLifetime { maximum_seconds: u64 },
    /// The expiration timestamp cannot be represented.
    #[error("phone unlock expiration timestamp overflowed")]
    ExpirationOverflow,
    /// Secure random request generation failed.
    #[error("phone unlock random-number generation failed: {0}")]
    Random(String),
    /// The response arrived after the request expired.
    #[error("phone unlock request expired")]
    Expired,
    /// The response used a different FactorSeal phone exchange version.
    #[error("unsupported phone unlock version {actual}; expected {expected}")]
    UnsupportedVersion { expected: u8, actual: u8 },
    /// An echoed response field did not match the active request.
    #[error("phone unlock response is not bound to the active {field}")]
    BindingMismatch { field: &'static str },
    /// The responding credential is not enrolled for this vault.
    #[error("phone credential is not enrolled for this vault")]
    CredentialNotEnrolled,
}

/// Result produced by a phone-factor adapter.
pub type PhoneFactorResult<T> = std::result::Result<T, PhoneFactorError>;

/// Future returned by a dynamically selected phone-factor adapter.
pub type PhoneFactorFuture<'a> =
    Pin<Box<dyn Future<Output = PhoneFactorResult<PhoneUnlockResponse>> + Send + 'a>>;

/// Protocol-neutral provider for one authenticated phone-factor exchange.
///
/// Implementations are responsible for mutual authentication, encryption,
/// user verification, timeouts, cancellation, and ensuring the response came
/// from the same current session that received `request`. FactorSeal performs
/// the remaining vault/request/action/credential binding checks with
/// [`PhoneUnlockRequest::accept_response`].
pub trait PhoneFactor: Send {
    /// Ask an authenticated phone to release its enrolled share.
    fn request_share<'a>(&'a mut self, request: &'a PhoneUnlockRequest) -> PhoneFactorFuture<'a>;
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT_ID: [u8; PHONE_VAULT_ID_BYTES] = [0x11; PHONE_VAULT_ID_BYTES];
    const CREDENTIAL_ID: PhoneCredentialId =
        PhoneCredentialId::new([0x22; PHONE_CREDENTIAL_ID_BYTES]);

    fn new_request() -> PhoneUnlockRequest {
        PhoneUnlockRequest::new(VAULT_ID, "domen-laptop", 1_000, Duration::from_secs(10)).unwrap()
    }

    fn response_for(request: &PhoneUnlockRequest) -> PhoneUnlockResponse {
        PhoneUnlockResponse::new(
            request.version(),
            *request.vault_id(),
            *request.request_id(),
            *request.challenge(),
            request.action(),
            CREDENTIAL_ID,
            PhoneShare::new([0x33; PHONE_SHARE_BYTES]),
        )
    }

    #[test]
    fn request_fields_are_versioned_and_short_lived() {
        let request = new_request();

        assert_eq!(request.version(), PHONE_UNLOCK_VERSION);
        assert_eq!(request.vault_id(), &VAULT_ID);
        assert_eq!(request.action().as_str(), "unlock-keyring");
        assert_eq!(request.expires_at(), 1_010);
        assert_eq!(request.laptop_name(), "domen-laptop");
    }

    #[test]
    fn matching_response_releases_zeroizing_share() {
        let request = new_request();
        let response = response_for(&request);

        let validated = request
            .accept_response(response, 1_009, &[CREDENTIAL_ID])
            .unwrap();

        assert_eq!(validated.credential_id(), CREDENTIAL_ID);
        assert_eq!(
            validated.phone_share().expose_secret(),
            &[0x33; PHONE_SHARE_BYTES]
        );
        assert_eq!(
            format!("{:?}", validated.phone_share()),
            "PhoneShare([REDACTED])"
        );
    }

    #[test]
    fn expired_response_is_rejected() {
        let request = new_request();
        let response = response_for(&request);

        assert!(matches!(
            request.accept_response(response, 1_010, &[CREDENTIAL_ID]),
            Err(PhoneFactorError::Expired)
        ));
    }

    #[test]
    fn response_must_match_the_active_request() {
        let request = new_request();
        let mut wrong_request_id = *request.request_id();
        wrong_request_id[0] ^= 0xff;
        let response = PhoneUnlockResponse::new(
            request.version(),
            *request.vault_id(),
            wrong_request_id,
            *request.challenge(),
            request.action(),
            CREDENTIAL_ID,
            PhoneShare::new([0x33; PHONE_SHARE_BYTES]),
        );

        assert!(matches!(
            request.accept_response(response, 1_001, &[CREDENTIAL_ID]),
            Err(PhoneFactorError::BindingMismatch {
                field: "request ID"
            })
        ));
    }

    #[test]
    fn response_must_match_version_vault_and_challenge() {
        let request = new_request();
        let mut response = response_for(&request);
        response.version = request.version().wrapping_add(1);
        assert!(matches!(
            request.accept_response(response, 1_001, &[CREDENTIAL_ID]),
            Err(PhoneFactorError::UnsupportedVersion { .. })
        ));

        let request = new_request();
        let mut response = response_for(&request);
        response.vault_id[0] ^= 0xff;
        assert!(matches!(
            request.accept_response(response, 1_001, &[CREDENTIAL_ID]),
            Err(PhoneFactorError::BindingMismatch { field: "vault ID" })
        ));

        let request = new_request();
        let mut response = response_for(&request);
        response.challenge[0] ^= 0xff;
        assert!(matches!(
            request.accept_response(response, 1_001, &[CREDENTIAL_ID]),
            Err(PhoneFactorError::BindingMismatch { field: "challenge" })
        ));
    }

    #[test]
    fn response_requires_an_enrolled_credential() {
        let request = new_request();
        let response = response_for(&request);

        assert!(matches!(
            request.accept_response(response, 1_001, &[]),
            Err(PhoneFactorError::CredentialNotEnrolled)
        ));
    }

    #[test]
    fn request_rejects_invalid_names_and_lifetimes() {
        assert!(matches!(
            PhoneUnlockRequest::new(VAULT_ID, "", 1_000, Duration::from_secs(10)),
            Err(PhoneFactorError::InvalidLaptopName)
        ));
        assert!(matches!(
            PhoneUnlockRequest::new(VAULT_ID, "laptop", 1_000, Duration::ZERO),
            Err(PhoneFactorError::InvalidLifetime { .. })
        ));
        assert!(matches!(
            PhoneUnlockRequest::new(VAULT_ID, "laptop", 1_000, Duration::from_secs(61)),
            Err(PhoneFactorError::InvalidLifetime { .. })
        ));
    }
}

//! Small, fail-closed API for sealing secrets to platform security hardware.
//!
//! `hardwareseal` deliberately exposes opaque sealing rather than public-key
//! encryption. For short, local key payloads, symmetric hardware sealing is
//! simpler and avoids store-now/decrypt-later exposure to public-key
//! cryptanalysis.

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

#[cfg(all(feature = "android", any(test, target_os = "android")))]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
mod android;
#[cfg(all(feature = "apple", target_vendor = "apple"))]
mod apple;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod tpm2;
#[cfg(any(test, target_os = "windows"))]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
mod windows;

const LABEL_HASH_BYTES: usize = 32;
const MAX_PAYLOAD_BYTES: usize = 64;

/// User authorization required before hardware releases a sealed secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AccessPolicy {
    /// Hardware possession is sufficient.
    None,
    /// A platform biometric ceremony must authorize every unseal operation.
    Biometric,
}

/// Hardware implementation that actually protects a sealed secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Backend {
    /// A directly accessible TPM 2.0 device.
    Tpm,
    /// Apple's Data Protection Keychain, with Secure Enclave biometric gating
    /// when requested.
    AppleKeychain,
    /// The Windows TPM exposed through TPM Base Services.
    WindowsTpm,
    /// The Windows Hello platform authenticator with PRF-derived sealing.
    WindowsHello,
    /// Android Keystore, backed by StrongBox or a trusted execution environment.
    AndroidKeystore,
}

/// A native user-authorization ceremony that did not release the secret.
///
/// These outcomes are intentionally separate from [`Error::Hardware`] so a
/// caller can decide whether to retry, wait for an interactive session, or
/// start recovery without parsing platform-specific error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthorizationError {
    /// The user or caller cancelled the native ceremony.
    #[error("authorization was cancelled")]
    Cancelled,
    /// The native policy evaluated but did not authorize access.
    #[error("authorization was denied")]
    Denied,
    /// No interactive authorization UI can be presented in this context.
    #[error("authorization UI is unavailable")]
    UiUnavailable,
    /// The interactive user session is locked or no longer exists.
    #[error("the interactive session is locked or unavailable")]
    SessionLocked,
    /// The platform credential was removed or invalidated after enrollment.
    #[error("the platform credential was invalidated")]
    CredentialInvalidated,
}

/// Errors returned by hardware sealing operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No supported hardware backend is reachable.
    #[error("no supported hardware security backend is available")]
    NotAvailable,
    /// The selected backend cannot enforce the requested access policy.
    #[error("the {policy:?} access policy is not supported by the {backend:?} backend")]
    PolicyNotSupported {
        /// Requested policy.
        policy: AccessPolicy,
        /// Selected backend.
        backend: Backend,
    },
    /// The caller supplied an invalid label.
    #[error("invalid key label: {0}")]
    InvalidLabel(String),
    /// The secret is too large for the portable sealed-data profile.
    #[error("secret is too large: {actual} bytes; maximum is {maximum}")]
    SecretTooLarge {
        /// Supplied size.
        actual: usize,
        /// Maximum supported size.
        maximum: usize,
    },
    /// The sealed envelope is malformed or belongs to another label or policy.
    #[error("invalid sealed envelope: {0}")]
    InvalidEnvelope(String),
    /// Native user authorization did not release the protected secret.
    #[error("native hardware authorization failed: {0}")]
    Authorization(#[source] AuthorizationError),
    /// A platform hardware operation failed.
    #[error("hardware security operation failed: {0}")]
    Hardware(String),
}

/// Handle for sealing secrets under one label and access policy.
#[derive(Debug)]
pub struct Protector {
    label_hash: [u8; LABEL_HASH_BYTES],
    policy: AccessPolicy,
    backend: Backend,
}

impl Protector {
    /// Open the platform hardware protector for `label`.
    pub fn open(label: &str, policy: AccessPolicy) -> Result<Self, Error> {
        validate_label(label)?;

        #[cfg(target_os = "linux")]
        {
            linux::ensure_available()?;
            if policy != AccessPolicy::None {
                return Err(Error::PolicyNotSupported {
                    policy,
                    backend: Backend::Tpm,
                });
            }
            Ok(Self {
                label_hash: Sha256::digest(label.as_bytes()).into(),
                policy,
                backend: Backend::Tpm,
            })
        }

        #[cfg(all(feature = "apple", target_vendor = "apple"))]
        {
            apple::ensure_available(policy)?;
            Ok(Self {
                label_hash: Sha256::digest(label.as_bytes()).into(),
                policy,
                backend: Backend::AppleKeychain,
            })
        }

        #[cfg(target_os = "windows")]
        {
            windows::ensure_available(policy)?;
            Ok(Self {
                label_hash: Sha256::digest(label.as_bytes()).into(),
                policy,
                backend: match policy {
                    AccessPolicy::None => Backend::WindowsTpm,
                    AccessPolicy::Biometric => Backend::WindowsHello,
                },
            })
        }

        #[cfg(all(feature = "android", target_os = "android"))]
        {
            let label_hash = Sha256::digest(label.as_bytes()).into();
            android::open(label_hash, policy)?;
            Ok(Self {
                label_hash,
                policy,
                backend: Backend::AndroidKeystore,
            })
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "windows",
            all(feature = "apple", target_vendor = "apple"),
            all(feature = "android", target_os = "android")
        )))]
        {
            let _ = policy;
            Err(Error::NotAvailable)
        }
    }

    /// Report the backend selected for this handle.
    #[must_use]
    pub const fn backend(&self) -> Backend {
        self.backend
    }

    /// Seal a short secret to this device.
    pub fn seal(&self, secret: &[u8]) -> Result<Vec<u8>, Error> {
        if secret.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::SecretTooLarge {
                actual: secret.len(),
                maximum: MAX_PAYLOAD_BYTES,
            });
        }

        #[cfg(target_os = "linux")]
        {
            linux::seal(self.label_hash, self.policy, secret)
        }

        #[cfg(all(feature = "apple", target_vendor = "apple"))]
        {
            apple::seal(self.label_hash, self.policy, secret)
        }

        #[cfg(target_os = "windows")]
        {
            windows::seal(self.label_hash, self.policy, secret)
        }

        #[cfg(all(feature = "android", target_os = "android"))]
        {
            android::seal(self.label_hash, self.policy, secret)
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "windows",
            all(feature = "apple", target_vendor = "apple"),
            all(feature = "android", target_os = "android")
        )))]
        {
            let _ = secret;
            Err(Error::NotAvailable)
        }
    }

    /// Unseal a secret after validating its label and policy binding.
    pub fn unseal(&self, envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        #[cfg(target_os = "linux")]
        {
            linux::unseal(self.label_hash, self.policy, envelope)
        }

        #[cfg(all(feature = "apple", target_vendor = "apple"))]
        {
            apple::unseal(self.label_hash, self.policy, envelope)
        }

        #[cfg(target_os = "windows")]
        {
            windows::unseal(self.label_hash, self.policy, envelope)
        }

        #[cfg(all(feature = "android", target_os = "android"))]
        {
            android::unseal(self.label_hash, self.policy, envelope)
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "windows",
            all(feature = "apple", target_vendor = "apple"),
            all(feature = "android", target_os = "android")
        )))]
        {
            let _ = envelope;
            Err(Error::NotAvailable)
        }
    }

    /// Remove persistent platform state associated with this protector.
    ///
    /// TPM envelopes are self-contained, so this is a no-op on Linux. Key-store
    /// backends remove their persistent item or key.
    pub fn delete(&self) -> Result<(), Error> {
        #[cfg(target_os = "linux")]
        {
            Ok(())
        }

        #[cfg(all(feature = "apple", target_vendor = "apple"))]
        {
            apple::delete(self.label_hash, self.policy)
        }

        #[cfg(target_os = "windows")]
        {
            windows::delete(self.label_hash, self.policy)
        }

        #[cfg(all(feature = "android", target_os = "android"))]
        {
            android::delete(self.label_hash, self.policy)
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "windows",
            all(feature = "apple", target_vendor = "apple"),
            all(feature = "android", target_os = "android")
        )))]
        {
            Err(Error::NotAvailable)
        }
    }
}

fn validate_label(label: &str) -> Result<(), Error> {
    if label.is_empty() {
        return Err(Error::InvalidLabel("label is empty".to_owned()));
    }
    if label.len() > 128 {
        return Err(Error::InvalidLabel("label exceeds 128 bytes".to_owned()));
    }
    if !label
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(Error::InvalidLabel(
            "label contains characters outside [A-Za-z0-9._-]".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_restricted() {
        assert!(validate_label("vault.wrapping-key_1").is_ok());
        assert!(validate_label("").is_err());
        assert!(validate_label("../escape").is_err());
        assert!(validate_label("contains spaces").is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn real_tpm_roundtrip_when_requested() {
        if std::env::var_os("HARDWARESEAL_REAL_TPM_TEST").is_none() {
            return;
        }
        let protector = Protector::open("hardwareseal-real-roundtrip", AccessPolicy::None)
            .expect("open real TPM");
        let expected = b"hardwareseal-roundtrip";
        let envelope = protector.seal(expected).expect("seal with real TPM");
        let actual = protector.unseal(&envelope).expect("unseal with real TPM");
        assert_eq!(actual.as_slice(), expected);

        let wrong_label = Protector::open("hardwareseal-wrong-label", AccessPolicy::None)
            .expect("open same TPM under another label");
        assert!(wrong_label.unseal(&envelope).is_err());
        #[cfg(target_os = "linux")]
        assert!(matches!(
            Protector::open("hardwareseal-biometric", AccessPolicy::Biometric),
            Err(Error::PolicyNotSupported { .. })
        ));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn real_windows_hello_roundtrip_when_requested() {
        if std::env::var_os("HARDWARESEAL_REAL_WINDOWS_HELLO_TEST").is_none() {
            return;
        }
        let protector = Protector::open("hardwareseal-real-windows-hello", AccessPolicy::Biometric)
            .expect("open Windows Hello");
        let envelope = protector
            .seal(b"hardwareseal-roundtrip")
            .expect("seal with Windows Hello");
        let actual = protector
            .unseal(&envelope)
            .expect("unseal with Windows Hello");
        assert_eq!(actual.as_slice(), b"hardwareseal-roundtrip");
        protector.delete().expect("delete Windows Hello credential");
    }

    #[cfg(all(feature = "apple", target_vendor = "apple"))]
    #[test]
    fn real_apple_roundtrip_when_requested() {
        if std::env::var_os("HARDWARESEAL_REAL_APPLE_TEST").is_none() {
            return;
        }
        let protector =
            Protector::open("hardwareseal-real-apple", AccessPolicy::None).expect("open Keychain");
        let envelope = protector.seal(b"hardwareseal-roundtrip").expect("seal");
        let actual = protector.unseal(&envelope).expect("unseal");
        assert_eq!(actual.as_slice(), b"hardwareseal-roundtrip");
        protector.delete().expect("delete Keychain item");
    }

    #[cfg(all(feature = "android", target_os = "android"))]
    #[test]
    fn real_android_roundtrip_when_requested() {
        if std::env::var_os("HARDWARESEAL_REAL_ANDROID_TEST").is_none() {
            return;
        }
        let protector = Protector::open("hardwareseal-real-android", AccessPolicy::None)
            .expect("open Android Keystore");
        let envelope = protector.seal(b"hardwareseal-roundtrip").expect("seal");
        let actual = protector.unseal(&envelope).expect("unseal");
        assert_eq!(actual.as_slice(), b"hardwareseal-roundtrip");
        protector.delete().expect("delete Android Keystore key");
    }
}

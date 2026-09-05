//! Small, fail-closed API for sealing secrets to platform security hardware.
//!
//! `hardwareseal` deliberately exposes opaque sealing rather than public-key
//! encryption. For short, local key payloads, symmetric hardware sealing is
//! simpler and avoids store-now/decrypt-later exposure to public-key
//! cryptanalysis.

use zeroize::Zeroizing;

#[cfg(all(feature = "android", any(test, target_os = "android")))]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
mod android;
#[cfg(all(feature = "apple", target_vendor = "apple"))]
mod apple;
// `windows` is compiled under `test` on every platform so its envelope and
// authorization tests run everywhere, which means the modules it depends on
// have to follow the same gate.
#[cfg(any(test, target_os = "linux", target_os = "windows"))]
#[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
mod envelope;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(test, target_os = "linux", target_os = "windows"))]
mod timing;
#[cfg(any(test, target_os = "linux", target_os = "windows"))]
#[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
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
    /// A [`self_test`] invariant did not hold on this device.
    #[error("hardware self-test failed: {0}")]
    SelfTest(String),
}

/// Label reserved for [`self_test`].
///
/// A protector opened under this label is scratch space: [`self_test`] removes
/// its state before and after each run, so no real secret may use it.
pub const SELF_TEST_LABEL: &str = "hardwareseal-self-test";
const SELF_TEST_CONTROL_LABEL: &str = "hardwareseal-self-test-control";

/// Verify on this device the sealing invariants a single seal cannot observe.
///
/// Continuous integration cannot run this. It needs the real TPM, Keychain
/// item, or platform credential, which no virtual machine or mock provides.
/// The properties it checks are exactly the ones a create-once flow misses:
/// that re-sealing under a label leaves an earlier envelope openable, that a
/// different label cannot open it, and that [`Protector::delete`] forgets only
/// the secrets it claims to. These have been silently wrong on key-store
/// backends before.
///
/// Cleanup is attempted before returning, including after a failure and after
/// an earlier run that was interrupted. Returns the backend that served the
/// test.
pub fn self_test(policy: AccessPolicy) -> Result<Backend, Error> {
    let protector = Protector::open(SELF_TEST_LABEL, policy)?;
    let control = Protector::open(SELF_TEST_CONTROL_LABEL, policy)?;
    let backend = protector.backend();
    // An interrupted earlier run may have left scratch state behind.
    protector.delete()?;
    control.delete()?;

    let outcome = run_self_test(&protector, &control, backend);
    // Attempt both cleanups before returning either error.
    let protector_cleanup = protector.delete();
    let control_cleanup = control.delete();
    outcome?;
    protector_cleanup?;
    control_cleanup?;
    Ok(backend)
}

fn run_self_test(
    protector: &Protector,
    control: &Protector,
    backend: Backend,
) -> Result<(), Error> {
    const FIRST: &[u8] = b"hardwareseal-self-test-first";
    const SECOND: &[u8] = b"hardwareseal-self-test-second";
    const CONTROL: &[u8] = b"hardwareseal-self-test-control";

    let control_envelope = control.seal(CONTROL)?;
    check_unseal(control, &control_envelope, CONTROL, "the control envelope")?;

    let first = protector.seal(FIRST)?;
    check_unseal(protector, &first, FIRST, "the sealed secret")?;

    let second = protector.seal(SECOND)?;
    if first == second {
        return Err(Error::SelfTest(
            "re-sealing produced a byte-identical envelope, so the two secrets \
             cannot be told apart"
                .to_owned(),
        ));
    }
    check_unseal(
        protector,
        &first,
        FIRST,
        "the earlier envelope after re-sealing",
    )?;
    check_unseal(protector, &second, SECOND, "the newest envelope")?;
    match control.unseal(&first) {
        Err(Error::InvalidEnvelope(_)) => {}
        Ok(_) => {
            return Err(Error::SelfTest(
                "a protector under another label opened the sealed secret".to_owned(),
            ));
        }
        Err(error) => {
            return Err(Error::SelfTest(format!(
                "the cross-label check failed for an unrelated reason: {error}"
            )));
        }
    }

    // Linux and the non-biometric Windows policy hold nothing to remove: their
    // envelopes are self-contained and `delete` is documented as a no-op.
    // Every other backend must actually forget.
    if !matches!(backend, Backend::Tpm | Backend::WindowsTpm) {
        protector.delete()?;
        check_deleted(protector, &first, "the earlier envelope")?;
        check_deleted(protector, &second, "the newest envelope")?;
    }
    check_unseal(
        control,
        &control_envelope,
        CONTROL,
        "another label's envelope after deleting the test label",
    )?;
    Ok(())
}

fn check_deleted(protector: &Protector, envelope: &[u8], what: &str) -> Result<(), Error> {
    match protector.unseal(envelope) {
        Err(Error::Authorization(AuthorizationError::CredentialInvalidated)) => Ok(()),
        Ok(_) => Err(Error::SelfTest(format!(
            "delete reported success but {what} is still recoverable"
        ))),
        Err(error) => Err(Error::SelfTest(format!(
            "{what} failed for an unrelated reason after delete: {error}"
        ))),
    }
}

fn check_unseal(
    protector: &Protector,
    envelope: &[u8],
    expected: &[u8],
    what: &str,
) -> Result<(), Error> {
    match protector.unseal(envelope) {
        Ok(actual) if actual.as_slice() == expected => Ok(()),
        Ok(_) => Err(Error::SelfTest(format!(
            "{what} opened to the wrong secret"
        ))),
        Err(error) => Err(Error::SelfTest(format!("{what} did not open: {error}"))),
    }
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
                label_hash: label_hash(label),
                policy,
                backend: Backend::Tpm,
            })
        }

        #[cfg(all(feature = "apple", target_vendor = "apple"))]
        {
            apple::ensure_available(policy)?;
            Ok(Self {
                label_hash: label_hash(label),
                policy,
                backend: Backend::AppleKeychain,
            })
        }

        #[cfg(target_os = "windows")]
        {
            windows::ensure_available(policy)?;
            Ok(Self {
                label_hash: label_hash(label),
                policy,
                backend: match policy {
                    AccessPolicy::None => Backend::WindowsTpm,
                    AccessPolicy::Biometric => Backend::WindowsHello,
                },
            })
        }

        #[cfg(all(feature = "android", target_os = "android"))]
        {
            let label_hash = label_hash(label);
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
    /// backends remove every persistent item, key, or credential this label
    /// has stored, including generations superseded by a later [`Self::seal`].
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

// Only the backend blocks hash labels, so a target that selects no backend
// compiles this away rather than warning on an unused `sha2` import.
#[cfg_attr(
    not(any(
        target_os = "linux",
        target_os = "windows",
        all(feature = "apple", target_vendor = "apple"),
        all(feature = "android", target_os = "android")
    )),
    allow(dead_code)
)]
fn label_hash(label: &str) -> [u8; LABEL_HASH_BYTES] {
    use sha2::{Digest as _, Sha256};

    Sha256::digest(label.as_bytes()).into()
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

    /// Re-sealing must never invalidate or repoint an envelope already handed
    /// to a caller. A caller that keeps the previous wrapped blob for rollback,
    /// or writes a new vault slot before committing it, depends on this.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn real_tpm_generations_are_independent_when_requested() {
        if std::env::var_os("HARDWARESEAL_REAL_TPM_TEST").is_none() {
            return;
        }
        let protector =
            Protector::open("hardwareseal-real-generations", AccessPolicy::None).expect("open");
        let first = protector.seal(b"first-generation").expect("seal first");
        let second = protector.seal(b"second-generation").expect("seal second");

        assert_ne!(first, second);
        assert_eq!(
            protector.unseal(&first).expect("unseal first").as_slice(),
            b"first-generation"
        );
        assert_eq!(
            protector.unseal(&second).expect("unseal second").as_slice(),
            b"second-generation"
        );
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

    /// Enrollment must be reused across seals and actually removable.
    ///
    /// A non-discoverable credential is invisible to the platform credential
    /// list, which would make `delete` a silent no-op and leave every seal
    /// enrolling another orphan. Deleting the enrollment must also make both
    /// generations unopenable, since the PRF that keys them is gone.
    #[cfg(target_os = "windows")]
    #[test]
    fn real_windows_hello_enrollment_is_reused_and_removable_when_requested() {
        if std::env::var_os("HARDWARESEAL_REAL_WINDOWS_HELLO_TEST").is_none() {
            return;
        }
        let protector = Protector::open(
            "hardwareseal-real-windows-hello-generations",
            AccessPolicy::Biometric,
        )
        .expect("open Windows Hello");
        let first = protector.seal(b"first-generation").expect("seal first");
        let second = protector.seal(b"second-generation").expect("seal second");

        assert_eq!(
            protector.unseal(&first).expect("unseal first").as_slice(),
            b"first-generation"
        );
        assert_eq!(
            protector.unseal(&second).expect("unseal second").as_slice(),
            b"second-generation"
        );

        protector.delete().expect("delete Windows Hello credential");
        assert!(
            protector.unseal(&first).is_err(),
            "delete must remove the credential the first envelope depends on"
        );
        assert!(
            protector.unseal(&second).is_err(),
            "delete must remove the credential the second envelope depends on"
        );
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
        assert!(
            protector.unseal(&envelope).is_err(),
            "delete must remove the keychain item the envelope names"
        );
    }

    /// Each seal owns its own keychain item, and `delete` sweeps all of them.
    ///
    /// The sweep enumerates the service and matches accounts by label prefix,
    /// so a wrong attribute key would leave every item in place while still
    /// reporting success. Asserting that both generations stop unsealing is
    /// what makes that failure visible.
    #[cfg(all(feature = "apple", target_vendor = "apple"))]
    #[test]
    fn real_apple_generations_are_independent_when_requested() {
        if std::env::var_os("HARDWARESEAL_REAL_APPLE_TEST").is_none() {
            return;
        }
        let protector = Protector::open("hardwareseal-real-apple-generations", AccessPolicy::None)
            .expect("open Keychain");
        let first = protector.seal(b"first-generation").expect("seal first");
        let second = protector.seal(b"second-generation").expect("seal second");

        assert_ne!(first, second, "each seal must name its own keychain item");
        assert_eq!(
            protector.unseal(&first).expect("unseal first").as_slice(),
            b"first-generation",
            "re-sealing must not repoint or destroy the previous item"
        );
        assert_eq!(
            protector.unseal(&second).expect("unseal second").as_slice(),
            b"second-generation"
        );

        protector.delete().expect("delete Keychain items");
        assert!(
            protector.unseal(&first).is_err(),
            "delete must sweep the superseded generation"
        );
        assert!(
            protector.unseal(&second).is_err(),
            "delete must sweep the current generation"
        );
    }

    /// A protector under another label must not see this label's items.
    ///
    /// The Apple sweep deletes by account prefix, so a prefix that is too
    /// loose would delete another label's secrets.
    #[cfg(all(feature = "apple", target_vendor = "apple"))]
    #[test]
    fn real_apple_delete_is_scoped_to_its_label_when_requested() {
        if std::env::var_os("HARDWARESEAL_REAL_APPLE_TEST").is_none() {
            return;
        }
        let kept = Protector::open("hardwareseal-real-apple-kept", AccessPolicy::None)
            .expect("open Keychain");
        let removed = Protector::open("hardwareseal-real-apple-removed", AccessPolicy::None)
            .expect("open Keychain");
        let kept_envelope = kept.seal(b"kept-secret").expect("seal kept");
        let removed_envelope = removed.seal(b"removed-secret").expect("seal removed");

        removed.delete().expect("delete one label");

        assert!(removed.unseal(&removed_envelope).is_err());
        assert_eq!(
            kept.unseal(&kept_envelope)
                .expect("another label must survive")
                .as_slice(),
            b"kept-secret"
        );
        kept.delete().expect("clean up");
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

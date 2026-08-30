# hardwareseal

A small, fail-closed Rust API for sealing short secrets to platform hardware.

The crate intentionally exposes opaque `seal` and `unseal` operations instead
of public-key encryption. Linux and non-biometric Windows secrets use a TPM 2.0
sealed-data object beneath an AES-256-CFB storage primary. Windows biometric
secrets use an AES-256-GCM envelope keyed by a Windows Hello PRF output.

## Platform model

`hardwareseal` uses the strongest native symmetric sealing mechanism available and
never silently falls back to a software-only key:

| Platform | Native backend | Biometric policy |
| --- | --- | --- |
| Linux | TPM 2.0 sealed-data object | Not yet available |
| Windows | TPM 2.0 through TPM Base Services, nested inside Windows Hello PRF encryption for biometric secrets | Fingerprint, face, or PIN verification, implemented |
| macOS (`apple` feature) | Data Protection Keychain | Touch ID, implemented |
| iPhone/iPad (`apple` feature) | Data Protection Keychain | Face ID/Touch ID, implemented |
| Android (`android` feature) | Hardware-backed Android Keystore AES-256-GCM | Host bridge planned |

The mobile backends are opt-in and disabled by default:

```toml
[dependencies]
hardwareseal = { path = "crates/hardwareseal", features = ["apple"] }   # macOS/iOS
# hardwareseal = { path = "crates/hardwareseal", features = ["android"] } # Android
```

With its platform feature disabled, `Protector::open` returns
`Error::NotAvailable` on that platform.

Apple does not expose general symmetric encryption in the Secure Enclave. The
Data Protection Keychain is therefore the correct native primitive: a
device-only item is released only after the configured Secure Enclave-backed
authentication ceremony. No sealed secret or wrapping key depends on P-256.
Each `seal` writes its own keychain item and returns an envelope naming that
item, so re-sealing under a label never destroys or silently repoints the
previous secret, and `delete` removes every generation stored under the label.
Android requires a StrongBox or TEE security level and rejects software-only
Keystore keys.

Android's non-interactive policy is implemented directly through JNI. The
embedding runtime must initialize `ndk-context` (as `android-activity` does).
Biometric Android unsealing remains fail-closed until the crate includes the
small host-side `BiometricPrompt` bridge needed to bind a prompt to each cipher
operation.

On iOS, applications using the biometric policy must provide
`NSFaceIDUsageDescription`. Keychain work may block while the system presents
authentication UI, so callers should invoke it away from their UI thread.

Unsupported policies and unavailable hardware fail closed. On mobile,
biometric operations must run away from the UI thread and applications must
provide the platform usage descriptions and entitlements required by the OS.

On Windows, biometric-policy enrollment creates a platform WebAuthn credential
with PRF enabled. Every secret is first sealed to the physical TPM and then
encrypted with AES-256-GCM under the 32-byte PRF output. Unsealing therefore
requires both Windows Hello user verification and the original TPM. The outer
envelope contains only the credential ID, a fresh random PRF input, nonce, and
authenticated TPM envelope. PRF inputs use the standard WebAuthn domain
separation rather than raw `hmac-secret` semantics. Assertions must match the
RP-ID hash and confirm both user presence and user verification. Windows may
offer the enrolled Hello PIN when fingerprint or face verification is
unavailable. Windows WebAuthn API version 6 or newer is required, external
security keys are excluded by requiring the platform authenticator, and each
ceremony uses a process-owned window with a two-minute timeout.

The envelope is opaque and versioned; callers should persist it without
inspecting it.

## Authorization errors

Native authorization outcomes are returned as
`Error::Authorization(AuthorizationError)` instead of platform error strings.
Callers can distinguish cancellation, denial, unavailable authorization UI, a
locked or missing interactive session, and an invalidated platform credential.
`Error::NotAvailable` remains the distinct signal for unavailable hardware,
while unclassified device and operating-system failures remain
`Error::Hardware`.

The biometric policy performs a native authorization ceremony on every
`unseal` call. HardwareSeal does not cache an approval or an unsealed secret;
an embedding application that keeps a secret available after unsealing owns
that session policy and must bound it separately.

## Development

Enter the development environment and run the checks:

```console
devenv shell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

A real TPM round trip is opt-in:

```console
HARDWARESEAL_REAL_TPM_TEST=1 cargo test real_tpm_roundtrip_when_requested
```

Windows Hello acceptance is also opt-in and presents native enrollment and
verification UI:

```console
HARDWARESEAL_REAL_WINDOWS_HELLO_TEST=1 cargo test real_windows_hello_roundtrip_when_requested
```

The selected algorithms are compatible with common compliance profiles, but
using them does not by itself make this crate or a product FIPS validated.

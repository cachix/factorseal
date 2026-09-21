# hardwareseal

Seal short secrets to platform security hardware with a small Rust API.
Secrets stay bound to the device; unavailable hardware and unsupported policies
return errors without falling back to software.

## Quick start

```toml
[dependencies]
hardwareseal = "0.1"
```

Use [`Protector`](https://docs.rs/hardwareseal/latest/hardwareseal/struct.Protector.html)
to seal and unseal a secret:

```rust
use hardwareseal::{AccessPolicy, Protector};

fn main() -> Result<(), hardwareseal::Error> {
    let protector = Protector::open("my-app-key", AccessPolicy::None)?;

    let envelope = protector.seal(b"example secret")?;
    // Persist these opaque envelope bytes in your application's storage.

    // Later, reopen with the same label and policy on the same device.
    let protector = Protector::open("my-app-key", AccessPolicy::None)?;
    let secret = protector.unseal(&envelope)?;
    assert_eq!(secret.as_slice(), b"example secret");
    // The returned secret buffer is zeroized when dropped.
    Ok(())
}
```

Secrets can be at most **64 bytes**, suitable for sealing an encryption key
used to protect larger data. Store the returned envelope as opaque bytes.
Labels must contain 1–128 ASCII letters, digits, dots, underscores, or hyphens.

`AccessPolicy::None` requires hardware possession without a biometric prompt.
`AccessPolicy::Biometric` requests native user verification on every `unseal`.
The crate does not cache approvals or unsealed secrets; the caller controls how
long it retains the returned secret.

## Platform setup

| Platform | Backend | `Biometric` policy |
| --- | --- | --- |
| Linux | TPM 2.0 | Unsupported |
| Windows | TPM 2.0; Windows Hello PRF for biometric secrets | Fingerprint, face, or PIN |
| macOS | Data Protection Keychain | Touch ID |
| iPhone/iPad | Data Protection Keychain | Face ID / Touch ID |
| Android | Hardware-backed Keystore AES-256-GCM | Unsupported; host bridge pending |

### Linux and Windows

Both backends are enabled by default. Linux requires access to `/dev/tpmrm0`;
Windows requires a TPM 2.0 device accessible through TPM Base Services.

On Windows, `Biometric` additionally requires Windows Hello with PRF support
and WebAuthn API version 6 or newer. Enrollment creates a platform credential;
unsealing requires both the original TPM and Windows Hello verification.
Windows may offer the enrolled Hello PIN when biometrics are unavailable.
External security keys are excluded, and each ceremony has a two-minute timeout.

### macOS and iOS

Enable the `apple` feature:

```toml
hardwareseal = { version = "0.1", features = ["apple"] }
```

The backend requires Secure Enclave hardware and rejects simulators. It stores
each secret as a device-only Data Protection Keychain item under the requested
access policy. With `Biometric`, changes to biometric enrollment invalidate
access to the item.

On macOS, building with `apple` requires Xcode 26+. The host executable must be
in an app-like bundle signed with a provisioning profile authorizing its
`com.apple.application-identifier` entitlement. An unsigned command-line tool
fails with `errSecMissingEntitlement` (`-34018`). On iOS, applications using
Face ID must provide `NSFaceIDUsageDescription`. Run Keychain operations away
from the UI thread because authentication may block.

The feature also exposes macOS 26+ non-exportable ML-DSA signing and an opt-in
ML-KEM wrapping prototype through `apple_pq`. See the
[design and acceptance requirements](https://github.com/cachix/factorseal/blob/main/security/macos-crypto-and-isolation.md)
for these separate APIs.

### Android

Enable the `android` feature:

```toml
hardwareseal = { version = "0.1", features = ["android"] }
```

The embedding runtime must initialize `ndk-context`, as `android-activity` does.
The backend requires StrongBox or TEE-backed Keystore keys and supports
`AccessPolicy::None`. Biometric operations remain unsupported until the
host-side `BiometricPrompt` bridge is implemented.

On Apple and Android, omitting the platform feature causes `Protector::open`
to return `Error::NotAvailable`.

## Storage and deletion

Each `seal` returns a new envelope. Re-sealing under the same label leaves
previous envelopes usable.

`Protector::delete` removes all persistent platform state for its label on
Keychain, Android Keystore, and Windows Hello. On Linux and non-biometric
Windows, TPM envelopes are self-contained and `delete` is a no-op: callers
must remove the stored envelopes and any backups themselves.

See the [security model](https://github.com/cachix/factorseal/blob/main/crates/hardwareseal/SECURITY.md)
for backend cryptography and protection boundaries. The crate is not FIPS
validated.

## Errors

- `Error::NotAvailable`: no supported hardware backend is reachable.
- `Error::PolicyNotSupported`: the backend cannot enforce the requested policy.
- `Error::Authorization`: native authorization was cancelled or denied, the UI
  or session is unavailable, or the platform credential was invalidated.
- `Error::Hardware`: an unclassified device or operating-system failure.

Input validation errors cover invalid labels, oversized secrets, and malformed
or mismatched envelopes. See the
[API reference](https://docs.rs/hardwareseal/latest/hardwareseal/enum.Error.html)
for all variants.

## Development

From the repository root on Linux:

```sh
devenv shell -- cargo fmt --all -- --check
devenv shell -- cargo clippy -p hardwareseal --all-targets --all-features -- -D warnings
devenv shell -- cargo test -p hardwareseal --all-features
```

On macOS and Windows, run the Cargo commands directly. Physical-hardware tests
are opt-in and can create credentials, show authentication UI, and write or
remove test state. In a shell with Cargo available, run the command for your
platform (the Windows example uses PowerShell):

```sh
HARDWARESEAL_REAL_TPM_TEST=1 cargo test -p hardwareseal real_tpm_
HARDWARESEAL_REAL_APPLE_TEST=1 cargo test -p hardwareseal --features apple real_apple
```

```powershell
$env:HARDWARESEAL_REAL_WINDOWS_HELLO_TEST = "1"
cargo test -p hardwareseal real_windows_hello
```

Run the round-trip and generations tests on real hardware before changing a
key-store backend. They check that re-sealing preserves earlier envelopes and
that deletion is scoped to the intended label.

[`self_test`](https://docs.rs/hardwareseal/latest/hardwareseal/fn.self_test.html)
checks these invariants on a device using reserved scratch labels, including
rejection of envelopes under another label. It attempts cleanup even after a
failure. FactorSeal exposes it as `factorseal hardware-self-test` for machines
without a Rust toolchain.

## License

Apache-2.0. See [LICENSE](LICENSE).

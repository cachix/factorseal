# Mobile embedding

Factorseal's mobile build is an in-process vault, not a port of the desktop
background service. The app sandbox is the trust boundary and the host app
owns lifecycle-driven sealing.

## Rust features

Build the reusable store and hardware-injection boundary without desktop IPC,
lifecycle monitors, the CLI, or `hardwareseal`:

```console
cargo build --no-default-features \
  --features vault-store,key-protection \
  --target aarch64-apple-ios

cargo build --no-default-features \
  --features vault-store,key-protection \
  --target aarch64-linux-android
```

The `vault` feature remains the full desktop service for compatibility. The
mobile-safe layers are:

- `vault-store`: encrypted Automerge documents, Turso persistence, and the
  in-process service/domain API;
- `key-protection`: default Argon2id or FIPS-profile PBKDF2-HMAC-SHA-256 key
  derivation, AES-256-GCM nesting, and the `KeyProtectorFactory` boundary;
- `vault-client`: the desktop local-IPC protocol and clients, not needed by an
  app that embeds `VaultService` directly.

## Platform adapter contract

Implement `KeyProtectorFactory` and return distinct non-exportable native keys.
Factorseal creates a wrapping/signing pair for each unlock group, generates
their stable labels, and calls the factory to create, open, and delete them.
Each `KeyProtector` must:

- report the security level that actually created the key;
- reject software fallback;
- honor the requested biometric policy;
- wrap and unwrap only the payload supplied by Factorseal;
- permanently delete the native key when requested.

Accepted mobile combinations are deliberately fail-closed:

- iOS: `VaultPlatform::Ios` with `HardwareBackend::SecureEnclave`;
- Android: `VaultPlatform::Android` with either
  `HardwareBackend::AndroidStrongBox` or
  `HardwareBackend::AndroidTrustedEnvironment`.

For explicit AND/OR policies, call
`Vault::create_with_key_protector_policy`,
`Vault::unseal_with_key_protector_group`, and
`Vault::discard_initialization_with_key_protector`. After unsealing, open
`VaultService` in the application process with `VaultService::open`. Grant the
app's authenticated caller identity only the operations it needs, then route
all app actions through `VaultRequest`; the raw encrypted store is not public.
The standard creation method uses `VaultCryptoProfile::Default`; call
`Vault::create_with_key_protector_policy_and_profile` with
`VaultCryptoProfile::Fips` when the embedding deployment requires the
standardized-algorithm profile.

Each policy group creates two distinct native keys. Factors inside a group are
AND requirements and groups are OR alternatives. The same password credential
is used by every password-containing group in the initial API. A biometric-only
group receives `UnlockCredentials::none()` and has no password-derived AEAD
layer.

The current Rust boundary is synchronous. A biometric adapter must run the
Factorseal call on a background thread, dispatch native prompt presentation to
the UI thread, and complete the native operation before returning. It must
never block the UI thread waiting for its own biometric callback.

## FFI and application lifecycle

Keep generated FFI and native SDK calls in separate wrapper crates so the core
can retain `unsafe_code = "deny"`. A narrow wrapper should own the vault handle
and expose create, unseal, seal, get, put, delete, and clear operations; it
should not expose raw database handles, signing seeds, or data-encryption keys.

The host application must also:

- seal on protected-data loss/device lock and on its chosen background lease;
- handle native key invalidation and biometric cancellation as sealed/error
  states;
- keep the vault in an OS backup-excluded application directory;
- serialize access to one `VaultService` per root;
- benchmark the recorded Argon2id or PBKDF2-HMAC-SHA-256 parameters on
  supported devices without silently weakening an existing vault;
- test reboot, app upgrade, biometric enrollment changes, cancellation,
  background suspension, and tampered vault files on physical devices.

Cross-application access is outside this embedding model. It needs a separate
platform-native broker and identity design rather than reusing the desktop
Unix-socket or named-pipe assumptions.

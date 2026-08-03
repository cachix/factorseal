<p align="center">
  <img src="assets/logo/factorseal-logo-fused.svg" alt="FactorSeal logo" width="660">
</p>

<p align="center">
  <a href="https://github.com/domenkozar/factorseal/actions/workflows/ci.yml"><img src="https://github.com/domenkozar/factorseal/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-16697A.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/rust-1.85%2B-16697A.svg" alt="Rust 1.85+">
</p>

> [!WARNING]
> FactorSeal is an unaudited prototype. Do not use it for production secrets
> until its vault format and platform integrations have received independent
> review.

FactorSeal is a local secret store built around the machine's hardware
enclave: Apple Secure Enclave on macOS or TPM 2.0 on Windows and Linux. The
enclave protects one share of the vault key, while a PIN-protected YubiKey
protects the other. **Two-factor authentication (2FA) is required by design**
for every supported persistent vault unlock; neither factor can unlock the
vault alone. On supported platforms, the hardware operation can additionally
require biometric verification. FactorSeal can serve Linux applications
through the standard Secret Service API and supports expiring secrets through
per-credential eviction deadlines.

The prototype still exposes hardware-only and legacy-password compatibility
paths. They do not satisfy FactorSeal's 2FA design requirement and are not
supported deployment profiles.

It is built around three controls that are often conflated:

- how long an application may access one secret;
- how long the unlocked vault key remains in memory;
- how long the stored secret itself exists.

FactorSeal gives each control its own deadline.

## Linux keyrings are not all the same thing

On Linux, “keyring” can refer to an API, a desktop vault, an in-kernel
credential cache, or an encrypted directory:

- [Secret Service](https://specifications.freedesktop.org/secret-service/latest/)
  is a D-Bus protocol for collections and items. It is not a storage format.
- [libsecret](https://gnome.pages.gitlab.gnome.org/libsecret/) is a client
  library and backend abstraction for password storage. Applications use it to
  talk to a Secret Service provider.
- GNOME Keyring, KWallet, KeePassXC, and FactorSeal can provide secret storage
  to desktop applications. Only one process can own
  `org.freedesktop.secrets` in a D-Bus session at a time.
- The Linux kernel key retention service is a different system. Applications
  reach it through `add_key`, `request_key`, and `keyctl`; the `keyctl` command
  is a userspace front end to those kernel facilities.

### Comparison matrix

| Option | Storage | Interfaces | Unlock | App access | Lock scope | Credential expiry |
| --- | --- | --- | --- | --- | --- | --- |
| **FactorSeal** | Encrypted file per entry | CLI, Rust, Secret Service | **2FA:** TPM/Secure Enclave + YubiKey; optional biometric gate | Per-caller, per-item grants | Vault timer; item/collection locks | **Deletes secret** |
| **GNOME Keyring** | Encrypted keyring + RAM session | Secret Service/libsecret | Password, often via PAM | Shared by same-user apps | Keyring; logout clears session | None |
| **KWallet** | Encrypted wallet file | D-Bus/C++ | Password or GPG | Per-app, wallet-wide | Inactivity, screen lock, last app | None |
| **KeePassXC** | KDBX database | GUI, CLI, browser, Secret Service | Password + optional key/YubiKey | Site rules; optional prompts | Whole database | Marks expired; retains |
| **Linux kernel keyrings** | Kernel memory | Syscalls, `keyctl` | Permissions; optional TPM keys | Per-key permissions | Thread/process/session/user | Native timeout; later GC |
| **`pass`** | GPG file per entry | CLI, files, Git | GPG key | Filesystem + GPG | External GPG-agent cache | None |

Expiry is literal here: FactorSeal deletes, kernel keys become inaccessible,
and KeePassXC keeps the entry but marks it expired.

The comparison is about behavior, not a single security ranking. These tools
solve different problems:

- Use GNOME Keyring or KWallet for the desktop's native, login-integrated
  credential store.
- Use KeePassXC for a portable, user-managed password database that can also
  serve desktop applications.
- Use kernel keyrings for short-lived credentials consumed by processes or
  kernel services, not as a general desktop password manager.
- Use `pass` for a small, inspectable GPG-and-files workflow.
- Use FactorSeal when persistent local secrets must be decryptable only with
  this machine's security hardware and need explicit application grants or
  deletion deadlines.

The comparison motivates FactorSeal's current shape: Secret Service
compatibility and default/session collections from the desktop ecosystem,
whole-vault idle locking as a separate lifecycle control, per-object deadlines
like kernel keys, and explicit per-client approval. FactorSeal applies those
ideas to persistent, hardware-protected application secrets.

The [Secret Service Item interface](https://specifications.freedesktop.org/secret-service/latest-single/#org.freedesktop.Secret.Item)
defines labels, lookup attributes, lock state, and creation/modification
timestamps, but no expiry property. A provider can add its own convention,
but generic libsecret clients cannot assume per-item expiry. FactorSeal exposes
eviction through its native API, CLI, and `keyring-core` modifiers.

Useful primary references for the other rows are the
[GNOME Keyring overview](https://wiki.gnome.org/Projects/GnomeKeyring),
[GNOME Keyring security FAQ](https://wiki.gnome.org/Projects/GnomeKeyring/SecurityFAQ),
[KWallet handbook](https://docs.kde.org/stable_kf6/en/kwalletmanager/kwalletmanager/kwallet-kcontrol-module.html),
[KWallet access control](https://docs.kde.org/trunk_kf6/en/kwalletmanager/kwalletmanager/wallet-access-control.html),
[KeePassXC entry handling](https://keepassxc.org/docs/KeePassXC_UserGuide#_entry_handling),
[KeePassXC Secret Service guide](https://keepassxc.org/docs/KeePassXC_UserGuide#_secret_service_integration),
[kernel key retention documentation](https://docs.kernel.org/security/keys/core.html),
[TPM-backed trusted keys](https://docs.kernel.org/security/keys/trusted-encrypted.html),
and [`pass` documentation](https://www.passwordstore.org/).

## What FactorSeal does differently

### Hardware enclave protection

Two-factor authentication is a design invariant, not an opt-in hardening
setting. The currently implemented 2-of-2 configuration requires both:

- the machine's supported TPM or Secure Enclave; and
- a PIN-protected YubiKey.

Every version 2 vault requires a supported platform backend through
[`hardware-enclave`](https://docs.rs/hardware-enclave):

- macOS Secure Enclave;
- Windows TPM 2.0;
- native Linux TPM 2.0;
- Windows TPM through its WSL bridge.

FactorSeal rejects Windows DPAPI and the Linux software-keyring fallback. A
vault records its hardware backend and cannot silently switch to another one.

The current second-factor provider, enabled by the `yubikey` Cargo feature,
uses a PIN-protected RSA-2048 PIV key in slot `9d`:

```text
vault key = platform share XOR YubiKey share
```

Factor support is capability-based. A factor may protect key material or gate
another factor's key operation; those are different security properties.

| Factor | Role | Status |
| --- | --- | --- |
| Platform hardware | Protects a vault-key share | Implemented; required by version 2 |
| Biometric | Gates the platform hardware operation | Implemented with `--biometric` where `hardware-enclave` can enforce `BiometricOnly` |
| YubiKey | Protects an independent share through PIV | Implemented behind `yubikey` |
| Passkey | Must protect a share with stable WebAuthn PRF/CTAP `hmac-secret` output | Provider planned |
| Phone | Holds an independently protected share and releases it through an authenticated, user-authorized session | Protocol-neutral boundary implemented; transport and vault enrollment planned |

Biometric verification does not create another independently protected share,
so `hardware + biometric` remains a transitional profile. Combining
`--biometric` with `--yubikey` retains the 2-of-2 share construction and adds
biometric verification before the platform share is released. The current
`hardware-enclave` integration enforces this on macOS and Windows; unsupported
platforms fail instead of silently dropping the policy.

A conventional six-digit TOTP app cannot independently protect an offline
vault share: a local verifier would have to retain the TOTP seed, and a copied
verifier could then calculate the same codes. A phone provider must hold its
own key material and answer a vault-bound challenge. FactorSeal now exposes a
protocol-neutral, one-shot phone-factor request/response boundary; Aliro,
Bluetooth, Android, enrollment, and vault wrapping remain separate work.
Likewise, a passkey provider must use stable PRF or `hmac-secret` output; an
ordinary authentication signature is not treated as a wrapping key.

The current prototype supports one YubiKey. Backup authenticators, passkeys,
phone enrollment and transport adapters, atomic authenticator replacement, and
recovery remain target features.

Hardware-only version 2 APIs remain temporarily available for prototype
development and migration. They do not meet the project's 2FA design
requirement.

### Three independent lifetimes

FactorSeal treats access, unlock, and storage lifetime separately:

1. **Access-grant TTL** controls how long an approved Secret Service client
   may access one item without another prompt. Expiry does not lock the vault
   or delete the secret.
2. **Vault idle timeout** controls how long the Secret Service provider retains
   the unlocked vault key without a vault operation. Expiry zeroizes the key
   and stops the provider, but does not delete persistent entries.
3. **Credential eviction** is an optional authenticated deadline on one
   persistent secret. At or after the deadline, the next read, metadata lookup,
   or existence check deletes the entry and reports it as missing.

This differs from KWallet's inactivity setting, which closes a whole wallet,
and from `KEYCTL_SET_TIMEOUT`, which expires an in-kernel key rather than a
persistent desktop-vault entry.

### Stable secret references

FactorSeal implements the `item` and optional `field` coordinates from
[SecretSpec references](https://secretspec.dev/concepts/references/):

```rust
use factorseal::{ReferenceOptions, SecretReference};

let reference =
    SecretReference::with_field("production/database", "password")?;
vault.set_by_reference_with_options(
    &reference,
    b"secret",
    ReferenceOptions {
        evict_at: None,
        service: Some("postgres".into()),
        account: Some("app".into()),
    },
)?;
let secret = vault.get_by_reference(&reference)?;
```

`service` and `account` are optional, additional keyring metadata. They live in
a separate encrypted index and can change without changing the reference,
entry path, or authenticated storage identity. The familiar
`get(service, account)` and `set(service, account, ...)` APIs remain as a
compatibility view.

## Implementation status

The current version 2 prototype implements:

- vault creation and unlock through the platform hardware enclave;
- optional platform-biometric gating of hardware unlock on supported systems;
- single-YubiKey 2-of-2 unlock with platform hardware;
- provider-neutral factor reporting through the Rust API and CLI status;
- independently authenticated and encrypted credential entries;
- SecretSpec `item` and optional `field` references;
- optional per-credential eviction;
- a `keyring-core` store;
- a Linux Secret Service provider with persistent `default` and RAM-only
  `session` collections;
- approval grants scoped to one caller and one item.

It does not yet implement independent backup authenticators, passkey providers,
or a phone-backed vault provider. The phone-factor boundary validates
short-lived, vault-bound responses and zeroizes returned shares; enrollment,
transport, vault wrapping, recovery, atomic factor replacement, audit events,
and rollback protection remain future work.

The prototype also retains hardware-only and legacy-password compatibility
paths. Those paths are implementation gaps relative to the required 2FA design,
not alternative security modes.

## Quick start

Native Linux requires the `tpm2-tss` runtime and access to `/dev/tpmrm0`, or a
reachable `tpm2-abrmd` resource manager.

```console
devenv shell
cargo run --features yubikey -- init --yubikey
printf 'postgres://localhost/mydb' |
  cargo run --features yubikey -- set my-project DATABASE_URL
cargo run --features yubikey -- get my-project DATABASE_URL
cargo run --features yubikey -- status
```

On macOS or Windows, require platform biometrics in addition to the two
independently protected shares:

```console
cargo run --features yubikey -- init --biometric --yubikey
```

The default vault location is the platform-specific user-data directory.
Override it with `--vault` or `FACTORSEAL_VAULT`.

Set or clear a persistent credential's eviction policy:

```console
printf 'temporary token' |
  cargo run -- set my-service API_TOKEN --retention-seconds 3600
printf 'replacement token' |
  cargo run -- set my-service API_TOKEN --evict-at 1800000000
printf 'permanent token' |
  cargo run -- set my-service API_TOKEN --no-eviction
```

Replacing a value without an eviction option preserves its existing deadline.

## Linux Secret Service

FactorSeal implements `org.freedesktop.secrets`, including plain and standard
DH/AES sessions, item search and mutation, collection and item locking, and
prompts. Stop any other Secret Service provider, then run:

```console
cargo run --features yubikey -- serve
```

The fixed `default` collection stores encrypted, hardware-protected entries in
the persistent vault. The fixed `session` collection keeps values only in
zeroizing process memory and wipes them when the provider locks or exits.

Unlocking the vault does not grant every application access. FactorSeal
associates each D-Bus cryptographic session with its caller and reports
matching items as locked until the user approves access. A grant applies to
one Linux process instance and one item. The defaults are a 15-minute grant
and a separate 30-minute vault idle timeout:

```console
cargo run --features yubikey -- serve --grant-seconds 300 --vault-idle-seconds 1800
```

The prototype prompts through `/dev/tty`, so it must run in the foreground. A
desktop approval UI is still needed before it can be installed as a headless
D-Bus-activated service.

## Rust keyring integration

FactorSeal implements the `keyring-core` store and credential APIs:

```rust
use factorseal::{FactorSealStore, Vault};
use keyring_core::{Entry, set_default_store};
use zeroize::Zeroizing;

let yubikey_pin = Zeroizing::new(rpassword::prompt_password("YubiKey PIN: ")?);
let vault = Vault::unlock_with_yubikey("/path/to/vault", yubikey_pin.as_bytes())?;
set_default_store(FactorSealStore::new(vault));

let entry = Entry::new("my-project", "DATABASE_URL")?;
entry.set_password("postgres://localhost/mydb")?;
let value = entry.get_password()?;
```

Use `retention_seconds` to compute a new eviction deadline on every successful
write, or `evict_at` with a Unix timestamp or `never`:

```rust
use std::collections::HashMap;
use keyring_core::Entry;

let modifiers = HashMap::from([("retention_seconds", "3600")]);
let entry =
    Entry::new_with_modifiers("my-service", "API_TOKEN", &modifiers)?;
entry.set_password("temporary token")?;
```

`get_attributes` reports the resolved `evict_at` timestamp, and
`update_attributes` can replace or clear it. A store-wide default is available
through `FactorSealStoreOptions`.

## Feature flags

- `hardware` (default): hardware-backed wrapping and optional biometric access
  policy through `hardware-enclave`.
- `cli` (default): builds the `factorseal` command.
- `keyring` (default): implements `keyring-core`.
- `secret-service` (Linux default): provides `org.freedesktop.secrets`.
- `yubikey`: enables the current required second-factor provider. The feature is
  not in the default build while hardware-only prototype compatibility remains.
- `password`: enables legacy version 1 password vaults and migration only.

Minimal consumers can build the credential-vault types without a provider:

```console
cargo build --no-default-features
```

## Security boundary

Hardware-backed key protection prevents a copied vault from being decrypted
offline. It cannot prevent an approved or compromised application from reading
and exfiltrating a secret returned to it. Per-item grants reduce ambient
access; they do not make a malicious authorized client safe.

Losing or resetting the required TPM, Secure Enclave, or current YubiKey can
permanently lose access. The platform EC and YubiKey RSA operations are not
post-quantum.

See [Architecture](docs/architecture.md),
[Unlock providers](docs/providers.md), and [Security](SECURITY.md) for the
implemented format, provider requirements, and current limitations.

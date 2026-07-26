# FactorSeal

> [!WARNING]
> FactorSeal is an unaudited prototype. Do not use it for production secrets
> until its vault format and platform integrations have received independent
> review.

FactorSeal is a hardware-bound local keyring designed around mandatory,
backup-ready multifactor unlock.

```text
platform hardware
       AND
any one enrolled authenticator
       |
reconstruct one vault key
       |
get(service, account) -> secret
```

Every completed vault must have at least two independent authenticators
enrolled. Only one is required for an ordinary unlock; the other exists so
that losing a phone or security key does not permanently lock the user out.

Examples of a valid enrollment are:

- a primary YubiKey and a backup YubiKey;
- a YubiKey and a phone;
- two independently enrolled phones.

The TPM or Secure Enclave is always required in addition to one enrolled
authenticator. Two enrolled authenticators are alternatives, not two devices
that must be presented together.

## Implementation status

This README describes the target design for FactorSeal's next vault format.
The current version 2 prototype implements platform hardware with one optional
YubiKey and can provide an unlocked vault through the Linux Secret Service
D-Bus API. It does not yet enforce two enrolled authenticators, support phones
or fingerprints, or implement atomic authenticator replacement.

Until the new format is implemented, the commands and APIs in the repository
retain their version 2 behavior. The target CLI examples below are a design
contract, not yet available commands.

## One identity, multiple authenticators

A FactorSeal vault has one stable, random identity. Each phone or security key
is a separate credential enrolled under that identity.

```text
vault 7c9e...
  |
  +-- YubiKey "primary"       factor 01
  +-- iPhone "personal"       factor 02
  +-- Android phone "backup"  factor 03
```

Authenticators never share or clone a private key. Each device has its own
credential, label, provider metadata, and stable factor ID. A public-key
fingerprint identifies the credential; a device serial number is only a hint
for locating it.

The unlock policy is:

```text
platform_required       = true
authenticator_threshold = 1
minimum_enrolled        = 2
```

These are separate rules. The threshold says that one authenticator can
unlock. The minimum says that FactorSeal must maintain a backup.

## Authenticator lifecycle

### Initialize

Initialization generates a random 256-bit vault key and enrolls two distinct
authenticators in one uninterrupted ceremony. FactorSeal verifies that each
authenticator can independently complete an unlock before activating the
vault.

The vault key must remain only in zeroizing process memory while enrollment is
incomplete. FactorSeal must not write a temporary hardware-only wrapping that
could later be restored to bypass multifactor unlock.

The target flow is:

```console
factorseal init
# Enroll primary authenticator
# Enroll backup authenticator
# Verify both, then activate the vault
```

### Unlock

FactorSeal discovers the available enrolled authenticators and uses one
selected device. It must not try PINs or biometric operations indiscriminately
across devices.

```text
TPM / Secure Enclave + primary YubiKey  -> unlock
TPM / Secure Enclave + backup phone     -> unlock
TPM / Secure Enclave alone              -> reject
YubiKey or phone alone                   -> reject
```

### Add

An already unlocked vault may enroll additional authenticators:

```console
factorseal factor add yubikey --label "office key"
factorseal factor add phone --label "personal phone"
factorseal factor list
```

Enrollment requires proof of control of the new authenticator. FactorSeal
rejects duplicate credential fingerprints.

### Lose or replace

If an authenticator is lost, the user unlocks with a remaining authenticator
and performs an atomic replacement:

```console
factorseal factor replace <lost-factor-id>
```

Replacement must:

1. Enroll and verify a new authenticator.
2. Generate a new authenticator share and the corresponding platform share
   for the unchanged vault key.
3. Rewrap the platform share and protect the authenticator share for every
   remaining authenticator.
4. Remove the lost authenticator.
5. Commit the new policy atomically.

FactorSeal refuses an ordinary removal that would leave fewer than two
enrolled authenticators. It never offers a command that downgrades a current
vault to platform-hardware-only unlock.

Restoring old policy metadata must not silently reactivate a revoked
authenticator. The final format therefore needs authenticated policy metadata
and rollback protection in addition to atomic filesystem updates.

## Cryptographic composition

FactorSeal extends its existing split-key construction to an authenticator
group:

```text
vault key = platform share XOR authenticator share

platform hardware wraps platform share

authenticator A wraps authenticator share
authenticator B wraps authenticator share
authenticator C wraps authenticator share
```

Each independently protected envelope contains the same uniformly random
authenticator share. Recovering any one envelope is sufficient, but it reveals
nothing useful without the platform share.

Adding an authenticator creates another envelope and does not rewrite stored
credentials. Revoking one rotates both shares while preserving the vault key,
so credential entries do not need to be rewritten and an old authenticator
envelope cannot participate in the current unlock policy.

XChaCha20-Poly1305 encrypts every credential independently with the reconstructed
256-bit vault key. Credential service and account names are authenticated and
hashed for their storage paths. An unlocked session retains only the zeroizing
vault key, not a plaintext credential cache.

## Authenticator providers

All providers must preserve the split-key property. A provider must decrypt a
wrapped share, perform key agreement, or produce a stable high-entropy secret.
A simple yes/no approval is not sufficient.

### YubiKey

The current prototype uses a PIN-protected RSA-2048 PIV key in slot `9d`.
The next format will treat each YubiKey as one member of the authenticator
group rather than as a special single-device unlock method.

Each YubiKey must have its own key and certificate. FactorSeal must not clone a
PIV private key across backup devices.

### Phones

The planned phone provider uses a small companion application:

- iOS generates a device-bound key in the Secure Enclave;
- Android generates a non-exportable, preferably hardware-backed key in
  Android Keystore;
- Face ID, Touch ID, a strong biometric, or the device credential authorizes
  each key use;
- the desktop and phone pair through an authenticated QR ceremony;
- the phone decrypts the authenticator share and returns it over a fresh,
  transcript-bound encrypted session.

The initial transport should work locally with a one-time QR code. Paired
local-network or Bluetooth discovery can improve routine unlocks later. An
optional end-to-end encrypted push relay may be added for remote approval, but
the relay must never receive a vault key or factor share in plaintext.

Phone credentials are device-bound by default. Restoring an application backup
does not restore the private key; the user recovers through another enrolled
authenticator.

WebAuthn hybrid transport with the PRF extension is a possible future provider,
subject to reliable cross-platform capability detection. Ordinary WebAuthn
signatures alone are authorization assertions and cannot reconstruct a vault
key share.

### Recovery keys

A high-entropy offline recovery key may be offered as an additional escape
hatch. It does not count toward the two-authenticator enrollment minimum by
default and must not be replaced with a password or short numeric code.

TOTP is not an appropriate offline vault-key provider. Its short code cannot
safely wrap a cryptographic share, and storing its verifier beside a local
vault would not provide the intended hardware separation.

## Platform hardware

Every version 2 hardware vault, and every vault in the target format, requires
a supported platform backend through
[`hardware-enclave`](https://docs.rs/hardware-enclave):

- macOS Secure Enclave;
- Windows TPM 2.0;
- native Linux TPM 2.0;
- Windows TPM through its WSL bridge.

FactorSeal fails closed when the package selects Windows DPAPI or the Linux
software keyring fallback. A vault that records one hardware backend cannot be
opened after silently switching to another.

Multiple authenticators protect against losing an enrolled phone or security
key. They do not recover a vault after losing or resetting its required TPM or
Secure Enclave. Cross-machine access and platform recovery require a separate,
explicitly designed policy.

## Credential storage and sessions

Applications address credentials by the familiar `service + account`
identity:

```rust
use factorseal::{FactorSealStore, Vault};
use keyring_core::{Entry, set_default_store};

let vault = Vault::unlock("/path/to/vault")?;
set_default_store(FactorSealStore::new(vault));

let entry = Entry::new("my-project", "DATABASE_URL")?;
entry.set_password("postgres://localhost/mydb")?;
let value = entry.get_password()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The example reflects the current API and will evolve to accept a generic
authenticator session.

An unlocked session holds one zeroizing vault key and never caches plaintext
credential values. Every `get` decrypts only the requested credential. The
session can be explicitly locked, after which all access through that shared
session fails.

Three independent lifetimes apply:

- **Access-grant TTL** controls how long an approved Secret Service client may
  access one item without another prompt. It does not delete the credential or
  extend the unlocked vault-key lifetime.
- **Vault idle timeout** controls how long the Secret Service provider retains
  the unlocked vault key without a vault operation. At the deadline the key is
  zeroized and the provider exits. It does not delete credentials.
- **Credential eviction** is an optional deadline stored as authenticated,
  encrypted metadata inside each credential entry. At or after the deadline,
  the next read, metadata lookup, or existence check deletes the entry and
  reports it as missing.

The current CLI accepts either an absolute Unix timestamp or a retention
duration for credential eviction. Replacing a value without an eviction flag
preserves its existing deadline:

```console
printf 'temporary token' |
  factorseal set my-service API_TOKEN --retention-seconds 3600
printf 'replacement token' |
  factorseal set my-service API_TOKEN --evict-at 1800000000
printf 'permanent token' |
  factorseal set my-service API_TOKEN --no-eviction
```

The `keyring-core` adapter exposes the same policy generically through entry
modifiers. `retention_seconds` computes a fresh deadline on every successful
write; `evict_at` accepts a Unix timestamp or `never`. The resolved deadline
is returned by `get_attributes` as `evict_at` and can be changed with
`update_attributes`:

```rust
use std::collections::HashMap;
use keyring_core::Entry;

let modifiers = HashMap::from([("retention_seconds", "3600")]);
let entry = Entry::new_with_modifiers("my-service", "API_TOKEN", &modifiers)?;
entry.set_password("temporary token")?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

A store-wide default can be applied to otherwise ordinary `Entry::new`
credentials with
`FactorSealStoreOptions { default_retention: Some(duration) }`.

The agent still needs:

- audit events;
- authenticator enrollment and replacement;
- policy integrity and rollback detection.

### Linux Secret Service provider

On Linux, the current agent implements `org.freedesktop.secrets`, including
plain and standard DH/AES sessions, the default collection, item search,
creation, updates, deletion, locking, and prompts. This lets applications that
already use libsecret, the Secret Service API, or a compatible language
keyring use FactorSeal without application-specific integration.

Run it in a terminal after stopping any other process that owns
`org.freedesktop.secrets`:

```console
factorseal serve
```

The vault is fully unlocked once when the agent starts. That does not give
every application vault-wide access. FactorSeal binds each cryptographic
session to the caller's unique D-Bus connection and reports matching items as
locked until the user approves them. Approval creates a grant for only that
Linux process instance and item, keyed by PID plus process start time and
cached for 15 minutes by default. A keyring library may reconnect during that
period without prompting the same running application again:

```console
factorseal serve --grant-seconds 300 --vault-idle-seconds 1800
```

The first provider uses `/dev/tty` for approval, so it must run in the
foreground. A desktop approval UI and fingerprint-backed confirmation are
still required before installing it as a headless D-Bus-activated service.
Closing a Secret Service session or calling `Lock` removes its grants; grants
also expire automatically. The default grant TTL is 15 minutes, while the
separate default vault idle timeout is 30 minutes.

Secret values remain in the existing FactorSeal entry files. Secret Service
labels and searchable attributes are kept in a separately authenticated,
encrypted index inside the vault. An existing CLI entry is imported into that
index when an application searches for its exact `service + username`.

## Current prototype quick start

The existing version 2 CLI can still be exercised as follows:

```console
devenv shell
cargo run -- init
printf 'postgres://localhost/mydb' |
  cargo run -- set my-project DATABASE_URL
cargo run -- get my-project DATABASE_URL
cargo run -- status
```

The default vault location is the platform-specific user-data directory.
Override it with `--vault` or `FACTORSEAL_VAULT`.

Current single-YubiKey support is behind the non-default `yubikey` feature:

```console
cargo run --features yubikey -- init --yubikey
cargo run --features yubikey -- add-yubikey
cargo run --features yubikey -- remove-yubikey
```

These commands are transitional and do not satisfy the target invariant that
requires two enrolled authenticators.

Password support is deliberately non-default and exists only for version 1
migration and development:

```console
cargo run --features password -- migrate-password
```

A password is not an acceptable fallback for a current hardware-bound vault.

## Features

- `hardware` (default): hardware-backed wrapping through `hardware-enclave`.
- `cli` (default): builds the current `factorseal` command.
- `keyring` (default): implements the `keyring-core` store and credential APIs.
- `secret-service` (Linux default): provides `org.freedesktop.secrets` with
  caller-bound, item-specific approval grants.
- `yubikey`: current version 2 single-YubiKey PIV support.
- `password`: legacy version 1 password vaults and hardware migration.

Minimal consumers can build the credential-vault types without a provider:

```console
cargo build --no-default-features
```

See [Architecture](docs/architecture.md),
[Unlock providers](docs/providers.md), and [Security](SECURITY.md). Those
documents currently describe the implemented version 2 format and must be
updated alongside the new format.

## Security scope

Hardware binding protects a copied vault from offline decryption. It cannot
prevent an already-authorized application from reading and exfiltrating a
credential returned to it.

The strength of an `any` authenticator group is bounded by its weakest enrolled
provider. FactorSeal must communicate provider strength clearly and must not
silently add passwords, short recovery codes, or approval-only mechanisms as
equivalent alternatives to hardware-backed authenticators.

Credential encryption has a post-quantum symmetric security margin, but the
current platform EC and YubiKey RSA wrapping operations are not post-quantum.
FactorSeal cannot offer end-to-end post-quantum hardware binding until the
relevant hardware interfaces expose suitable primitives.

# FactorSeal

> [!WARNING]
> FactorSeal is an unaudited prototype. Do not use it for production secrets
> until its vault format and platform integrations have received independent
> review.

FactorSeal is a hardware-bound local keyring. It stores credentials by the
same `service + account` identity used by keyring APIs:

```text
platform hardware [AND optional YubiKey]
                  |
          reconstruct one vault key
                  |
      get(service, account) -> secret
```

There are no recipients and no encrypted secret files in a project repository.
Applications use the keyring API while the encrypted vault remains local to
the machine.

## Hardware support

The default `hardware` feature uses
[`hardware-enclave`](https://docs.rs/hardware-enclave) for:

- macOS Secure Enclave;
- Windows TPM 2.0;
- native Linux TPM 2.0;
- Windows TPM through its WSL bridge.

FactorSeal fails closed when the package selects Windows DPAPI or the Linux
software keyring fallback. A vault that records one hardware backend cannot be
opened after silently switching to another.

## How it works

- Initialization generates a random 256-bit vault key.
- Platform hardware protects that key using a vault-specific asymmetric key.
- XChaCha20-Poly1305 encrypts every credential independently.
- Credential service and account names are authenticated and hashed for their
  storage paths.
- An unlocked session retains only the zeroizing vault key, not decrypted
  credential values.
- Each `get` decrypts one requested value into a zeroizing buffer.

With YubiKey two-factor unlock, FactorSeal splits the vault key into two random
XOR shares. Platform hardware protects one share. A PIN-protected RSA-2048 PIV
key in YubiKey slot `9d` derives the wrapping key for the other share. Both
shares are required; neither factor protects a complete vault key.

XChaCha20's 256-bit key provides a post-quantum margin for stored credential
encryption. The current platform EC and YubiKey RSA wrapping operations are
not post-quantum, because current TPM, Secure Enclave, and PIV interfaces do
not expose suitable post-quantum primitives.

## Quick start

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

### YubiKey second factor

Build with the non-default `yubikey` feature:

```console
cargo run --features yubikey -- init --yubikey
cargo run --features yubikey -- add-yubikey
cargo run --features yubikey -- remove-yubikey
```

The PIV key-management slot (`9d`) must already contain an RSA-2048 key and
matching certificate. The device must expose PIV slot metadata (YubiKey
firmware 5.2.3+). Its PIN policy must not be `Never`; configure a touch policy
on the key if physical user presence is also required. FactorSeal never
provisions or overwrites a PIV slot.

The CLI prompts for the PIN without echo. `--yubikey-pin-file` and
`FACTORSEAL_YUBIKEY_PIN_FILE` are intended for controlled non-interactive use.

## Keyring API

The default `keyring` feature exposes the primary application interface:

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

Use `Vault::unlock_with_yubikey` for a two-factor vault. The store keeps the
vault key for its process lifetime but never keeps a plaintext credential
cache.

## Password migration

Password support is deliberately non-default:

```console
cargo run --features password -- migrate-password
```

The `password` feature can read and create version 1 password vaults for
migration and development. It is not a fallback for version 2 hardware vaults.
Migration only rewraps the vault key; credential entries are not decrypted or
rewritten.

## Features

- `hardware` (default): hardware-backed wrapping through `hardware-enclave`,
  including native Linux TPM support.
- `cli` (default): builds the `factorseal` command.
- `keyring` (default): implements the `keyring-core` store and credential APIs.
- `yubikey`: adds PIN-protected YubiKey PIV as an optional required factor.
- `password`: enables legacy password vaults and hardware migration.

Minimal consumers can still build the credential-vault types without a
provider:

```console
cargo build --no-default-features
```

See [Architecture](docs/architecture.md),
[Unlock providers](docs/providers.md), and [Security](SECURITY.md).

## Roadmap

The main remaining component is a desktop unlock agent. It will authorize
once, retain only the vault key for a bounded session, and serve keyring
requests without caching plaintext credentials. Session expiry, explicit
locking, application authorization, audit events, and recovery-key exports
belong there.

Existing applications only use FactorSeal automatically when their keyring
library supports selecting this backend. System-wide Secret Service or native
keychain bridges are separate platform integrations.

<p align="center">
  <img src="assets/logo/factorseal-logo-fused.svg" alt="Factorseal logo" width="660">
</p>

<p align="center">
  <a href="https://github.com/domenkozar/factorseal/actions/workflows/ci.yml"><img src="https://github.com/domenkozar/factorseal/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-16697A.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/rust-1.91%2B-16697A.svg" alt="Rust 1.91+">
</p>

> [!WARNING]
> Factorseal is an unaudited prototype. It is not ready for production secrets.

Factorseal is a hardware-bound local vault for Linux, macOS, and Windows. The
vault can be sealed or unsealed, implements a durable keyring interface for
applications, provides the same operations through its CLI, and keeps a
separate disposable application-cache scope intended for SecretSpec. Each vault
has its own stable keys.

The reusable store and key-protection boundary also cross-compile for Android
and iOS. Mobile applications embed the vault in-process and supply a native
Android Keystore/StrongBox or iOS Secure Enclave adapter; the desktop daemon,
IPC, and lifecycle integration are not used. See
[Mobile embedding](docs/mobile.md).

The project is intentionally narrower than a password manager and broader than
an encrypted file:

- TPM 2.0 on Linux and Windows, or Secure Enclave on macOS, wraps the local
  data-encryption key;
- every platform nests one factor inside that wrapping, so neither the factor
  nor the platform key unseals the vault alone; ML-DSA-65 provides
  post-quantum authentication for durable vault state;
- the nested password factor is Argon2id-hardened but remains limited by the
  password's entropy; it is not a substitute for a high-entropy recovery
  secret against a post-quantum attacker;
- a separate hardware-wrapped signing key gives the vault a stable
  device identity and Automerge actor ID;
- encrypted, device-signed Automerge snapshots and changes are persisted in an
  embedded local Turso database;
- one per-user background service owns that database and applies caller grants,
  unseal leases, expiry, and replay protection;
- document scope keeps disposable device caches separate from local keyring
  policy.

Factorseal is a broker backed by platform security hardware. It is not itself a
"secure enclave," and it does not claim to transparently implement every Apple
Keychain or Windows Credential Manager API.

In the Rust API, `Keyring` means the credential capability implemented by a
`VaultClient`; it does not mean Linux's in-kernel `keyctl` keyrings. On Linux,
the unsealed service also exposes the standard `org.freedesktop.secrets`
session-bus API, backed by the same encrypted vault. It is a single Secret
Service provider, so do not run oo7, GNOME Keyring, or another provider that
owns that name alongside it. macOS Keychain and Windows Credential Manager
remain distinct platform interfaces.

The first release is deliberately the user profile: a logged-in user, local
application callers, interactive verification, and session-bound sealing. A
future headless workload profile would require its own workload identity,
hardware-bound unattended activation, lifecycle, and threat model. It is not a
passwordless mode of the user profile and is outside the MVP.

## Architecture

```text
    Factorseal CLI / SecretSpec endpoint / aware application
                         |
       cache adapter or Factorseal `Keyring` interface
                         |
                  `VaultClient`
                         |
        authenticated, length-bounded native transport
                         |
             per-user Factorseal vault service
          caller grants | lease | expiry scheduler
                         |
            scoped Automerge domain operations
                         |
       encrypted + device-signed change envelopes
                         |
                embedded Turso database
                         |
          TPM 2.0 / Secure Enclave key wrapping
```

The architecture has three protocol layers: an application adapter owns the
portable application contract, and Factorseal's lightweight `VaultClient` and
native transport form the host-local trust boundary. The `Keyring` trait
provides durable credential operations on top of that protocol. The
`factorseal provider` endpoint implements SecretSpec's typed Rust IPC contract
and maps its disposable cache operations to the native transport. The local
protocol is not a remote secret API.

Turso is a persistence engine, not a trust boundary. Factorseal encrypts
application data before Turso sees it. Turso Cloud Sync is not enabled and is
not an authorization mechanism.

The local Factorseal directory contains `factorseal.json`, `factorseal.db`, and
`factorseal.lock`. While the vault is unsealed, Linux and macOS also use
`factorseal.sock` in that directory. Windows instead uses the vault-scoped named
pipe `\\.\pipe\factorseal-<vault-id>`. `FACTORSEAL_SOCKET` overrides the native
endpoint on every platform.

Automerge is the document/change and convergence interface. Applications do
not receive raw `AutoCommit` access. They call operations such as get, put,
delete, and clear. Concurrent secret values are treated as explicit conflicts,
not silently resolved by choosing a display winner.

The code-level storage and security boundaries are documented in
[docs/architecture.md](docs/architecture.md).

## Current implementation

The storage foundation currently implements:

- permanent `VaultId`, `DeviceKeyId`, public signing identity, and stable
  Automerge actor ID;
- distinct platform key labels for wrapping the DEK and signing seed;
- fail-closed rejection of Windows DPAPI and Linux software-keyring hardware
  fallbacks through the existing `hardware-enclave` adapter;
- `device-cache` and `device-local` document scopes;
- an Automerge secret domain model with explicit conflict detection;
- XChaCha20-Poly1305 encrypted and ML-DSA-65-signed snapshots and changes;
- signed linear protected commits, document generation compare-and-swap, and
  tamper verification at database open;
- an embedded Turso schema owned by one sealed worker;
- startup and live-call expiry cleanup, idempotent deletion, and full cache
  clear;
- a versioned local vault protocol with caller-bound grants, request replay
  rejection, zeroizing wire secret buffers, and bounded idle/absolute leases;
- a transport-neutral `VaultClient` implemented by the native platform
  clients, available separately through the lightweight `vault-client` crate
  feature, plus a `Keyring` trait implemented for every vault client;
- native authenticated transports on all three targets: Linux peer-credential
  sockets, macOS audit-token sockets, and same-user Windows named pipes;
- native developer package builders and lifecycle manifests, exercised by each
  platform's CI job;
- fail-closed native lifecycle monitors for logind sleep/shutdown/session-lock
  events, AppKit sleep/power-off/session-resign notifications, and Windows
  suspend/shutdown/session notifications.
- durable `set`, `get`, and `delete` commands in the Factorseal CLI, using the
  same authenticated transport and caller grants as application clients.
- a `factorseal provider` stdio endpoint for SecretSpec IPC, with typed-session
  tests covering initialization and cache-backed get/set/expiring-set/delete.

Still required before MVP release:

- merging and releasing SecretSpec's IPC provider API, followed by installed
  end-to-end conformance coverage on Linux, macOS, and Windows;
- signed/notarized release artifacts, native lifecycle acceptance, and
  physical hardware tests on every target, including verification of the
  OS-mediated Windows TPM prompt and modern Windows Hello UX.

The opt-in physical-host runners and release-evidence procedure are in
[`acceptance/`](acceptance/README.md). Passing a runner is evidence for one
machine and event; release approval still needs the documented platform matrix.
On NixOS/Linux, run the real-TPM suite with
`nix run .#acceptance-linux -- --root /absolute/test/root --password-file /private/file`.

No item in that list is implied complete merely because the shared Rust core
builds on Linux.

## SecretSpec provider endpoint

`factorseal provider` is a SecretSpec external-provider endpoint. SecretSpec
launches it with private stdin/stdout pipes; the endpoint uses the committed
typed Rust IPC API and then connects to the already-running Factorseal service
over its native local transport. It never opens the vault database or receives
the calling application's identity.

Register the installed binary as the `factorseal` scheme (the executable path
must be absolute):

```json
{
  "schema_version": 1,
  "scheme": "factorseal",
  "executable": "/absolute/path/to/factorseal",
  "arguments": ["provider"],
  "credential_names": []
}
```

Place that file at `factorseal.json` in SecretSpec's provider-registration
directory. The URI is `factorseal://default`. Before SecretSpec can use it,
authorize the endpoint binary itself and keep the Factorseal service unsealed
in another terminal:

```console
$ factorseal grant-secretspec /absolute/path/to/factorseal
$ factorseal unseal
```

The grant is cache-scoped only: convention and native addresses map to the
`secretspec-cache/v1` disposable cache, and get/set/expiring-set/delete cannot
read or change durable `Keyring` data. Replacing the endpoint executable
changes its digest and requires a new grant. The endpoint cannot prompt on its
stdio protocol streams, so a sealed service reports `interaction_required`.

This endpoint follows the currently committed SecretSpec IPC API while that API
is in its upstream PR; release packaging still waits for the corresponding
published SecretSpec IPC crate and installed cross-platform conformance.

## Command-line keyring

`factorseal init` authorizes the exact CLI executable that created the vault.
With the per-user vault unsealed, durable local values can be
stored, retrieved, and deleted without giving the CLI direct database access:

```console
factorseal set github --field token
printf '%s' 'secret value' | factorseal set github --field token
factorseal get github --field token
factorseal delete github --field token
```

`set` prompts without echo when standard input is a terminal, accepts exact
bytes from standard input, or reads `--value-file`. `get` writes exact bytes
without adding a newline. After replacing or upgrading the Factorseal binary,
stop the service and run `factorseal grant-cli` to authorize the new executable
digest.

`factorseal destroy --yes-really-destroy` permanently deletes a **sealed**
vault, including its TPM or Secure Enclave keys. It requires the nested factor
and is intended for deliberate vault retirement and disposable native
acceptance vaults; it is irreversible.

## Build and test

The repository uses [devenv](https://devenv.sh/) on Linux:

```console
devenv shell cargo test --all-targets --all-features
devenv shell cargo clippy --all-targets --all-features -- -D warnings
devenv shell cargo fmt --all -- --check
```

On macOS and Windows with Rust 1.91 or newer:

```console
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

CI runs native jobs on Linux, macOS, and Windows. Hardware behavior still needs
physical-runner acceptance tests; unit tests use separate deterministic mock
protectors and never weaken production backend selection.

On Linux, the flake also exposes `nixosModules.factorseal` and a NixOS VM test
that boots with a virtual TPM, initializes and restarts the installed user
service, exercises its real Unix socket, checks executable and cross-user
authorization, and proves idle lockout.

## Security model in brief

- The plaintext DEK is never persisted. It exists only in zeroizing vault
  memory during an unseal lease.
- Copying `factorseal.db` and `factorseal.json` to another machine must not
  recover its secrets because the wrapping keys are hardware-bound.
- A local application receives only an explicitly requested secret after its
  transport-authenticated identity matches a durable grant.
- Grants, unseal lifetime, and secret storage lifetime are independent.
- Hardware binding cannot stop an already authorized process from exfiltrating
  a secret returned to it.
- Current ML-DSA-65 device signing keys are hardware-wrapped rather than executed
  inside a platform signing primitive; migrating to non-exportable native
  signing operations is tracked as platform hardening.
- The signed commit chain detects content tamper, missing commits, divergent
  writers, and inconsistent partial rollback when a newer protected head or
  commit remains. Nothing stored in the same vault directory can
  detect rollback of that directory as a whole. The offline MVP does not claim
  that property; detecting it needs a checkpoint held outside that directory.

Please report vulnerabilities according to [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

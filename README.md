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

Factorseal is a hardware-rooted secret agent for local applications on Linux,
macOS, and Windows. Its first job is to provide an interactive, per-user
replacement for the OS keyring used as a SecretSpec cache and to serve
Factorseal-aware applications. Each seal is created as a permanent device with
its own stable keys.

The project is intentionally narrower than a password manager and broader than
an encrypted file:

- TPM 2.0 on Linux and Windows, or Secure Enclave on macOS, wraps the local
  data-encryption key;
- every platform nests one factor inside that wrapping, so neither the factor
  nor the platform key opens a seal alone, and because the nested factor is
  hash-derived it is also the only layer that survives a quantum adversary;
- a separate hardware-wrapped signing key gives the seal a stable
  device identity and Automerge actor ID;
- encrypted, device-signed Automerge snapshots and changes are persisted in an
  embedded local Turso database;
- one per-user agent owns that database and applies caller grants, unlock
  leases, expiry, and replay protection;
- document scope keeps disposable device caches separate from local agent
  policy.

Factorseal is a broker backed by platform security hardware. It is not itself a
"secure enclave," and it does not claim to transparently implement every Apple
Keychain or Windows Credential Manager API.

The first release is deliberately the user profile: a logged-in user, local
application callers, interactive verification, and session-bound locking. A
future headless workload profile would require its own workload identity,
hardware-bound unattended activation, lifecycle, and threat model. It is not a
passwordless mode of the user profile and is outside the MVP.

## Architecture

```text
         SecretSpec / aware application
                         |
       compiled SecretSpec `factorseal` provider
                         |
          Factorseal `AgentClient` interface
                         |
        authenticated, length-bounded native transport
                         |
                 per-user Factorseal agent
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

The architecture has three protocol layers: SecretSpec's compiled provider or
an application adapter owns the portable application contract, and Factorseal's
lightweight `AgentClient` and native transport form the host-local trust
boundary. The local agent protocol is not a remote secret API.

Turso is a persistence engine, not a trust boundary. Factorseal encrypts
application data before Turso sees it. Turso Cloud Sync is not enabled and is
not an authorization mechanism.

Automerge is the document/change and convergence interface. Applications do
not receive raw `AutoCommit` access. They call operations such as get, put,
delete, and clear. Concurrent secret values are treated as explicit conflicts,
not silently resolved by choosing a display winner.

The code-level storage and security boundaries are documented in
[docs/architecture.md](docs/architecture.md).

## Current implementation

The storage foundation currently implements:

- permanent `SealId`, `DeviceKeyId`, public signing identity, and stable
  Automerge actor ID;
- distinct platform key labels for wrapping the DEK and signing seed;
- fail-closed rejection of Windows DPAPI and Linux software-keyring hardware
  fallbacks through the existing `hardware-enclave` adapter;
- `device-cache` and `device-local` document scopes;
- an Automerge secret domain model with explicit conflict detection;
- XChaCha20-Poly1305 encrypted and Ed25519-signed snapshots and changes;
- signed linear protected commits, document generation compare-and-swap, and
  tamper verification at database open;
- an embedded Turso schema owned by one locked worker;
- startup and live-call expiry cleanup, idempotent deletion, and full cache
  clear;
- a versioned local agent protocol with caller-bound grants, request replay
  rejection, zeroizing wire secret buffers, and bounded idle/absolute leases;
- a transport-neutral `AgentClient` interface implemented by the native
  platform clients, available separately through the lightweight
  `agent-client` crate feature;
- a built-in provider in SecretSpec that maps `factorseal://` addresses,
  reads, writes, expiry, and deletion directly into that authenticated Rust
  client interface;
- native authenticated transports on all three targets: Linux peer-credential
  sockets, macOS audit-token sockets, and same-user Windows named pipes;
- native developer package builders and lifecycle manifests, exercised by each
  platform's CI job;
- fail-closed native lifecycle monitors for logind sleep/shutdown/session-lock
  events, AppKit sleep/power-off/session-resign notifications, and Windows
  suspend/shutdown/session notifications.

Still required before MVP release:

- installed SecretSpec end-to-end conformance coverage for direct Factorseal
  agent access on Linux, macOS, and Windows;
- signed/notarized release artifacts, native lifecycle acceptance, and
  physical hardware tests on every target, including verification of the
  OS-mediated Windows TPM prompt and modern Windows Hello UX.

No item in that list is implied complete merely because the shared Rust core
builds on Linux.

## SecretSpec provider

SecretSpec builds the `factorseal` provider into its Rust library. It accepts
`factorseal://default` and `factorseal://default?namespace=cache` and calls the
Factorseal Rust `AgentClient` directly over the platform-native transport.
There is no provider subprocess or registration file.

Factorseal authenticates the process that actually opens the socket. Authorize
the SecretSpec executable when using its CLI, or authorize the host application
when SecretSpec is embedded as a library:

```console
factorseal grant-secretspec /absolute/path/to/secretspec
```

The provider uses the agent's default root and socket;
`FACTORSEAL_AGENT_ROOT` and `FACTORSEAL_AGENT_SOCKET` provide explicit
overrides. Replacing an authorized executable changes its digest and requires a
new grant. Installed native lifecycle and end-to-end conformance remain release
gates.

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

- The plaintext DEK is never persisted. It exists only in zeroizing agent
  memory during an unlock lease.
- Copying the database and seal metadata to another machine must not
  recover its secrets because the wrapping keys are hardware-bound.
- A local application receives only an explicitly requested secret after its
  transport-authenticated identity matches a durable grant.
- Grants, unlock lifetime, and secret storage lifetime are independent.
- Hardware binding cannot stop an already authorized process from exfiltrating
  a secret returned to it.
- Current Ed25519 device signing keys are hardware-wrapped rather than executed
  inside a platform signing primitive; migrating to non-exportable native
  signing operations is tracked as platform hardening.
- The signed commit chain detects content tamper, missing commits, divergent
  writers, and inconsistent partial rollback when a newer protected head or
  commit remains. Nothing stored in the same seal directory can
  detect rollback of that directory as a whole. The offline MVP does not claim
  that property; detecting it needs a checkpoint held outside that directory.

Please report vulnerabilities according to [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

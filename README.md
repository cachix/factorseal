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

Factorseal is an enclave-backed local secrets vault for Linux, macOS, and
Windows. The platform enclave is TPM 2.0 on Linux and Windows, and Apple's
Secure Enclave on macOS. One per-user service owns the encrypted database and
exposes narrowly scoped operations to local applications through authenticated
native IPC. Applications never open the database or receive the vault's
encryption and signing keys.

Factorseal provides:

- a durable keyring for the CLI and Factorseal-aware applications;
- a separate disposable cache for SecretSpec;
- the standard `org.freedesktop.secrets` interface on Linux;
- an embeddable store and key-protection boundary for Android and iOS.

It is the local broker around that platform enclave, not a password manager or
remote secrets service. It also does not attempt to replace every Apple
Keychain or Windows Credential Manager API.

## Quick start

Factorseal requires a supported platform enclave: TPM 2.0 on Linux and Windows,
or Secure Enclave on macOS. Software keyring and DPAPI-only fallbacks are
rejected. Once the `factorseal` binary is installed, create a vault:

```console
$ factorseal init
```

Initialization prompts for a Factorseal password, creates the enclave-protected
vault, authorizes that exact CLI executable for the durable keyring, and leaves
the vault sealed.

Start an unsealed service in one terminal:

```console
$ factorseal unseal
```

Then use the keyring from another terminal:

```console
$ factorseal set github --field token
$ factorseal get github --field token
$ factorseal delete github --field token
```

`set` prompts without echo when standard input is a terminal. It can also read
exact bytes from standard input or `--value-file`:

```console
$ printf '%s' 'secret value' | factorseal set github --field token
$ factorseal set github --field token --value-file ./token.bin
```

`get` writes the exact stored bytes without adding a newline. `factorseal
status` reads validated public metadata without unsealing and reports whether a
matching service is reachable.

Replacing or upgrading the binary changes its executable digest. Stop the
service and run `factorseal grant-cli` to authorize the new CLI executable.

## How it works

```text
        Platform enclave                 Factorseal password
  TPM 2.0 (Linux/Windows)              Argon2id nested factor
     Secure Enclave (macOS)
                  \                       /
                   +---- create/unseal ---+
                              |
                   DEK + device signing seed
                              |
                              v
   CLI / SecretSpec endpoint / aware application
                              |
                    Keyring or cache adapter
                              |
                         VaultClient
                              |
          authenticated, length-bounded native transport
                              |
                   per-user VaultService
              caller grants | replay | lease | expiry
                              |
                  scoped Automerge operations
                              |
            encrypted and device-signed envelopes
                              |
                     embedded Turso database
```

The platform enclave and password protect vault bootstrap keys during creation
and unsealing; enclave operations are not in the database write path. Once
unsealed, the data-encryption key and signing seed exist only in zeroizing
memory owned by the store worker until the vault seals.

### Creation and unsealing

Creation generates a random 256-bit data-encryption key and a separate
ML-DSA-65 signing seed. The signing identity also determines the permanent
`DeviceKeyId` and stable Automerge actor ID.

The password is hardened with Argon2id and separately encrypts the data key and
signing seed with XChaCha20-Poly1305. Two distinct enclave keys then wrap those
ciphertexts. Neither a copied vault plus its password nor the enclave keys
without the password can recover the vault keys.

Unsealing reverses those layers, derives the public signing identity again, and
rejects any mismatch before opening the database. The store then verifies its
schema, public vault identity, signed commit chain, and current document heads
before serving requests.

### Authenticated local requests

The local protocol uses strict, versioned JSON messages with random 128-bit
request IDs and a 1 MiB limit. Secret-bearing buffers zeroize on drop where the
Rust API permits. Responses are bound to their request IDs, and the service
keeps a bounded replay window.

Caller identity comes from the native transport, never from request JSON:

- Linux uses a private Unix socket, `SO_PEERCRED`, the peer PID, and a digest
  of `/proc/<pid>/exe`;
- macOS uses a private Unix socket, kernel peer credentials, the peer PID, and
  its audit token, then binds grants to the executable digest;
- Windows uses a same-user named pipe, client impersonation, SID and PID
  verification, and the executable digest.

Durable grants bind the complete caller identity to a scope, namespace or exact
item/field, explicit permissions, and an optional expiry. An executable change
therefore requires a new grant. These grants are defense in depth between
same-user applications; they do not protect a granted program from debugging,
preloading, or compromise by that same user.

### Documents and persistence

Each vault namespace maps to an opaque document ID derived from the vault ID,
scope, and namespace. Secret names and values live only inside the encrypted
Automerge document, not in SQL columns or filenames.

Applications receive domain operations such as get, put, delete, clear, and
bounded batch mutation; they never receive raw `AutoCommit` access. Reads use
all visible Automerge values. Different concurrent values return an explicit
conflict rather than silently selecting Automerge's display winner.

Every mutation produces an encrypted snapshot and encrypted Automerge changes
using fresh XChaCha20-Poly1305 nonces. ML-DSA-65 signatures bind their document,
scope, device, actor, generation, key epoch, dependencies, and ciphertext.

One worker thread owns the Turso connection, exclusive `factorseal.lock`,
plaintext vault keys, and all decrypted document state. A mutation uses one
transaction to compare-and-swap the document generation, append its encrypted
state, append a signed protected commit, and advance the global head. The
history is periodically compacted to the current state of every document; it is
a tamper check, not an audit log.

For the full storage and verification invariants, see
[Architecture](docs/architecture.md).

## Interfaces and scopes

| Interface | Scope | Persistence | Authenticated principal |
| --- | --- | --- | --- |
| CLI and Rust `Keyring` | `device-local` | durable | exact native client executable |
| SecretSpec provider | `device-cache` | disposable, optionally expiring | exact `factorseal provider` executable |
| Linux Secret Service | dedicated `device-local` namespace | durable | Factorseal service mediating its D-Bus clients |

The two document scopes are intentionally separate. A cache grant cannot read
or modify durable keyring data:

- `device-local` stores keyring entries, caller grants, and local policy;
- `device-cache` stores disposable application caches and is never replicated.

In the Rust API, `Keyring` is the credential capability implemented by a
`VaultClient`; it does not refer to Linux's in-kernel `keyctl` keyrings.

### SecretSpec provider

`factorseal provider` implements SecretSpec's typed external-provider protocol
over private stdin/stdout pipes. The endpoint translates SecretSpec addresses
into cache-only Factorseal requests and connects to the already-running native
vault service. It never opens the database, receives vault keys, or accepts the
embedding application's identity as authority.

Register the installed binary as the `factorseal` scheme using an absolute
path:

```json
{
  "schema_version": 1,
  "scheme": "factorseal",
  "executable": "/absolute/path/to/factorseal",
  "arguments": ["provider"],
  "credential_names": []
}
```

Place this registration at `factorseal.json` in SecretSpec's provider
registration directory. The provider URI is `factorseal://default`.

Authorize the endpoint executable before using it:

```console
$ factorseal grant-secretspec /absolute/path/to/factorseal
$ factorseal unseal
```

The endpoint itself is the caller seen by Factorseal. Replacing it requires a
new grant. Because it cannot prompt on its protocol streams, a sealed service
is reported to SecretSpec as `interaction_required`.

Factorseal currently follows the committed SecretSpec IPC API from its pinned
Git revision. Release packaging still depends on publishing that API and
passing installed end-to-end conformance on Linux, macOS, and Windows.

### Linux Secret Service

While unsealed on Linux, Factorseal can own `org.freedesktop.secrets` on the
session bus and back its default collection with the same encrypted vault. Do
not run another provider that owns that bus name, such as GNOME Keyring or oo7,
at the same time. macOS Keychain and Windows Credential Manager remain separate
platform interfaces.

## Vault lifecycle

An unseal lease has independent idle and absolute deadlines. Authorized secret
operations refresh only the idle deadline and can never extend the absolute
deadline. Status checks do not refresh the lease.

Explicit sealing, lease expiry, termination, logout, session lock, suspend, and
shutdown all converge on the same worker shutdown path. The platform adapters
monitor logind on Linux, AppKit notifications on macOS, and power/session window
messages on Windows. Sealing invalidates every store handle and zeroizes the
worker's data key and signing seed.

The vault directory contains:

- `factorseal.json`: public identity, key labels, factor parameters, and
  enclave-wrapped bootstrap material;
- `factorseal.db`: encrypted, signed vault state;
- `factorseal.lock`: exclusive store ownership;
- `factorseal.sock`: the live Linux/macOS endpoint, present only while served.

Windows uses `\\.\pipe\factorseal-<vault-id>` instead of a socket.
`FACTORSEAL_ROOT` overrides the vault directory and `FACTORSEAL_SOCKET`
overrides the native endpoint.

`factorseal destroy --yes-really-destroy` permanently deletes a sealed vault,
including its enclave keys. It requires the nested factor and is irreversible.

## Mobile embedding

Android and iOS applications embed the reusable vault in-process; they do not
run the desktop daemon, IPC transports, or lifecycle monitors. The application
sandbox becomes the caller boundary, and the host supplies an Android
Keystore/StrongBox or iOS Secure Enclave implementation of
`KeyProtectorFactory`.

Build the portable layers with `vault-store` and `key-protection`. The host app
must serialize access, keep the vault in a backup-excluded directory, and seal
on device lock or protected-data loss. See [Mobile embedding](docs/mobile.md)
for the adapter and lifecycle contract.

## Security properties and limitations

Factorseal is designed so that:

- the plaintext data-encryption key is never persisted;
- copying `factorseal.db` and `factorseal.json` to another machine does not
  recover secrets without the enclave keys;
- Turso receives no plaintext document content and is not an authorization
  boundary;
- an application receives a secret only after its transport-derived identity
  matches a suitable grant;
- signed envelopes and commits detect content tampering, missing history,
  divergent writers, and inconsistent partial rollback when newer protected
  state remains.

The design does not detect rollback of the complete vault directory. Doing so
requires a trusted checkpoint stored elsewhere. The offline MVP deliberately
excludes whole-directory rollback from its security claim.

The password remains limited by its entropy: Argon2id raises offline guessing
cost but cannot turn a human-memorable password into a high-entropy
post-quantum recovery secret. ML-DSA-65 protects state authenticity, while the
current platform wrapping mechanisms have their own cryptographic assumptions.

The signing seed is enclave-wrapped but exists in zeroizing process memory
while unsealed; signing is not yet performed by a non-exportable native signing
primitive. Enclave binding also cannot stop an authorized or compromised
client from exfiltrating a secret returned to it. Recovery is not implemented,
so losing the enclave keys loses the vault.

See [Security](SECURITY.md) for the complete threat model and vulnerability
reporting instructions.

## Build and test

The repository uses [devenv](https://devenv.sh/) on Linux:

```console
$ devenv shell cargo test --all-targets --all-features
$ devenv shell cargo clippy --all-targets --all-features -- -D warnings
$ devenv shell cargo fmt --all -- --check
```

On macOS and Windows with Rust 1.91 or newer:

```console
$ cargo test --all-targets --all-features
$ cargo clippy --all-targets --all-features -- -D warnings
$ cargo fmt --all -- --check
```

The feature split is intentional:

- `vault-client`: lightweight native IPC protocol and clients;
- `vault-store`: Automerge documents, encrypted envelopes, Turso, and
  `VaultService`;
- `key-protection`: factor nesting and the injectable enclave boundary;
- `vault`: the full desktop service and platform adapters;
- `hardware`, `cli`, and `secretspec-provider`: native enclave adapter, product
  CLI, and SecretSpec endpoint respectively.

CI runs native Linux, macOS, and Windows jobs. Unit tests use deterministic mock
protectors and never weaken production backend selection. The Nix flake also
provides `nixosModules.factorseal` and a NixOS VM test with a virtual TPM.

## Release status

The shared core, native transports, lifecycle monitors, CLI, Secret Service,
SecretSpec endpoint, developer package builders, and physical-host acceptance
runners are implemented. Before an MVP release, Factorseal still needs:

- the SecretSpec IPC API published and installed end-to-end conformance on all
  desktop targets;
- signed and notarized release artifacts;
- native lifecycle and physical TPM/Secure Enclave acceptance across the
  release matrix, including Windows prompt and modern Windows Hello behavior;
- independent security review.

The release-candidate procedures are in
[Physical enclave and lifecycle acceptance](acceptance/README.md). Passing one
runner proves only that machine and event; it does not approve the release
matrix. On NixOS/Linux, the real-TPM suite can be run with:

```console
$ nix run .#acceptance-linux -- \
    --root /absolute/test/root \
    --password-file /private/file
```

Developer packaging inputs are described in [Packaging](packaging/README.md).
No platform is considered release-ready merely because the shared Rust core
builds or its unit tests pass.

## License

Apache-2.0. See [LICENSE](LICENSE).

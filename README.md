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

Factorseal is a hardware-backed local secrets vault. It stores encrypted
secrets on your device and makes them available through a per-user service
protected by [TPM 2.0](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
on Linux and Windows or Apple's
[Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
on macOS.

The basic lifecycle is:

1. **Create** a vault and choose a password and/or biometric unlock policy.
2. **Unseal** it by satisfying one of those policies.
3. **Authorize** local applications for only the secrets and operations they
   need.
4. **Use** the vault through the CLI or an integration while it is unsealed.
5. **Seal** it to stop the service and remove plaintext vault keys from memory.

Applications ask the service to perform narrowly scoped operations such as
getting or storing a secret. They never open the database or receive the
vault's encryption and signing keys.

Factorseal provides:

- durable, project-partitioned secrets for the CLI, plus a local
  [keyring](#interfaces-and-document-kinds) for Factorseal-aware applications;
- a separate disposable [provider cache](https://secretspec.dev/concepts/providers/caching/)
  for [SecretSpec](https://secretspec.dev/);
- the standard
  [`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/latest/)
  interface on Linux.

Factorseal is a local security broker around platform hardware. It is not a
password manager or remote secrets service, and it does not attempt to replace
every Apple Keychain or Windows Credential Manager API.

## Platform unlock support

| Platform | Biometric method | Intended hardware binding | Status |
| --- | --- | --- | --- |
| macOS | Touch ID | Keychain/Secure Enclave key-use policy | Implemented; physical-device release acceptance remains |
| Windows | Windows Hello fingerprint, face, or PIN | TPM sealed-data object nested inside Windows Hello PRF encryption | Implemented; physical-device prompt and policy acceptance remains |
| Linux | No portable built-in biometric path | TPM 2.0 supports hardware wrapping, but `fprintd` does not provide a hardware-bound secret | Password-backed TPM unlock only |
| iPhone and iPad | Face ID or Touch ID | Keychain/Secure Enclave-protected share | Mobile core and adapter boundary implemented; native app adapter remains |
| Android | `BiometricPrompt` | StrongBox or trusted-environment Keystore-protected share | Mobile core and adapter boundary implemented; native app adapter remains |
| Any desktop using a phone | Phone Face ID or fingerprint | Phone-held share returned over an authenticated post-quantum-hybrid channel | Planned optional feature |

The vault encryption and ML-DSA signatures are designed to resist quantum
attacks. Native biometric enforcement still inherits the cryptographic and
certification properties of Secure Enclave, Windows Hello, or Android
Keystore, so Factorseal does not claim that those complete platform paths are
post-quantum certified. Phone unlock is intended to give Linux and machines
without a suitable local sensor the same approval flow without treating a
software-only biometric result as a cryptographic factor.

## Quick start

Factorseal requires a supported platform enclave: TPM 2.0 on Linux and Windows,
or Secure Enclave on macOS. Software keyring and DPAPI-only fallbacks are
rejected. Once the `factorseal` binary is installed, create a vault:

```console
$ factorseal init
```

When run in a terminal, initialization briefly introduces the vault and asks
you to choose password, biometric, password AND biometric, or password OR
biometric unlocking. The default is password. It then creates the
hardware-protected vault, authorizes that exact CLI executable for the durable
keyring, and leaves the vault sealed. Non-interactive initialization also
defaults to password unless `--unlock` is passed explicitly.

Unlock policies use AND inside one comma-separated group and OR between
repeated groups. Platform hardware binding is implicit in every group:

```console
$ factorseal init --unlock password,biometric
$ factorseal init --unlock password --unlock biometric
```

The first policy requires password AND biometric approval. The second accepts
password OR biometric approval. A biometric-only policy does not ask for a
Factorseal password. The first repeated group is the preferred unlock method;
override it when starting the agent, for example `factorseal agent --unlock
biometric`.

Start an unsealed service in one terminal:

```console
$ factorseal agent
```

If the vault does not exist yet, `factorseal agent` stays alive, logs the
initialization instruction, and continues automatically after `factorseal init`
creates it. Packaged background launchers use this same behavior on every
desktop platform.

Then store a durable project secret from another terminal:

```console
$ factorseal set --project my-app github --field token
$ factorseal get --project my-app github --field token
$ factorseal delete --project my-app github --field token
```

Browse project and address metadata without retrieving any values:

```console
$ factorseal projects
"my-app"
$ factorseal list --project my-app
{"kind":"native","coordinates":{"item":"github","field":"token"}}
```

Both commands follow every bounded vault cursor automatically. Pass `--json`
to emit one JSON array instead of JSON-quoted projects or one compact address
object per line.

`set` prompts without echo when standard input is a terminal. It can also read
exact bytes from standard input or `--value-file`:

```console
$ printf '%s' 'secret value' | factorseal set --project my-app github --field token
$ factorseal set --project my-app github --field token --value-file ./token.bin
```

`--project` may also come from `SECRETSPEC_PROJECT`. Without `--field`, the CLI
stores a conventional SecretSpec address using `--profile` (which defaults to
`default`). With `--field`, it stores a native SecretSpec address. `get` writes
the exact stored bytes without adding a newline. `factorseal status` reads
validated public metadata without unsealing and reports whether a matching
service is reachable.

Replacing or upgrading the binary changes its executable digest. Stop the
service and run `factorseal grant-cli` to authorize the new CLI executable. The
project-approval upgrade also requires this once because legacy broad provider
grants are intentionally ignored.

Seal the running service immediately when it is no longer needed:

```console
$ factorseal seal
```

## How it works

Once unsealed, clients send requests over authenticated native IPC to the
per-user vault service. The service identifies the calling executable, checks
its grant, applies the requested operation, and persists only encrypted,
device-signed data.

```text
        Platform enclave               Selected unlock group
  TPM 2.0 (Linux/Windows)          password and/or biometric
     Secure Enclave (macOS)
                  \                       /
                   +---- wrapping slot ---+
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

Every configured OR alternative has an independent pair of hardware-wrapping
keys. A biometric factor gates those keys through the platform policy; a
password factor additionally encrypts the wrapped payload with Argon2id and
XChaCha20-Poly1305. Enclave operations are not in the database write path.
Once unsealed, the data-encryption key and signing seed exist only in zeroizing
memory owned by the store worker until the vault seals.

### Creation and unsealing

Creation generates a random 256-bit data-encryption key and a separate
ML-DSA-65 signing seed. The signing identity also determines the permanent
`DeviceKeyId` and stable Automerge actor ID.

Factors inside a group are all required; each repeated group is an independent
OR alternative. Password groups harden the shared password with Argon2id and
separately encrypt the data key and signing seed with XChaCha20-Poly1305 before
two distinct enclave keys wrap them. Biometric-only groups wrap those keys
directly with a separate pair whose use requires platform biometric approval.

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

Durable grants bind the complete caller identity to a document kind, partition,
or exact address, explicit permissions, and an optional expiry. An executable
change therefore requires a new grant. These grants are defense in depth between
same-user applications; they do not protect a granted program from debugging,
preloading, or compromise by that same user.

### Documents and persistence

Factorseal stores multiple encrypted Automerge documents. A document ID is an
HMAC under the vault data key over its semantic kind and private partition, so
SQL does not reveal or permit offline guessing of project names. Secret names,
addresses, project partitions, and values live only inside encrypted Automerge
snapshots, not in SQL columns or filenames.

Every Automerge document has this version-1 root shape:

```text
format:          <document-kind>
format-version:  1
partition:       <bytes>
entries:         { <address-digest>: <serialized-record> }
```

Each record contains `version`, the complete typed address, `value`, and an
optional `evict_at` deadline. SecretSpec convention addresses retain project,
profile, and key; native addresses retain item plus optional field, vault,
section, and version. The map key is only an index—the record is validated
against the requested full address on every read.

An authorized management client can enumerate this encrypted metadata through
paginated `ListProjects` and `ListProjectAddresses` operations. Listing has its
own grant permission and returns only project names or full addresses—never
secret values. Pages contain at most eight entries so even maximally escaped
addresses remain within the protocol's one-MiB response limit. Expired records
are removed before listing, and concurrent values for one authenticated
address appear as one metadata entry. The `projects` and `list --project`
commands consume these pages through the native vault transport.

Applications receive domain operations such as get, put, delete, clear, and
bounded batch mutation; they never receive raw `AutoCommit` access. Reads use
all visible Automerge values. Different concurrent values return an explicit
conflict rather than silently selecting Automerge's display winner.

Every mutation produces an encrypted snapshot and encrypted Automerge changes
using fresh XChaCha20-Poly1305 nonces. ML-DSA-65 signatures bind their document
kind, device, actor, generation, key epoch, dependencies, and ciphertext.

One worker thread owns the Turso connection, exclusive `factorseal.lock`,
plaintext vault keys, and all decrypted document state. A mutation uses one
transaction to compare-and-swap the document generation, append its encrypted
state, append a signed protected commit, and advance the global head. The
history is periodically compacted to the current state of every document; it is
a tamper check, not an audit log.

For the full storage and verification invariants, see
[Architecture](docs/architecture.md).

## Interfaces and document kinds

| Interface | Document kind | Partition | Persistence |
| --- | --- | --- | --- |
| Factorseal CLI | `secretspec-project` | project name | durable |
| SecretSpec provider | `secretspec-provider-cache` | project name | disposable, optionally expiring |
| Rust `Keyring` | `local-keyring` | caller namespace | durable |
| Linux Secret Service | `linux-secret-service` | service namespace | durable |
| Grants | `authorization` | authorization namespace | durable |

Each row is a separate authorization domain. In particular, a provider-cache
grant cannot read or modify a durable project document, even when both use the
same project name.

In the Rust API, `Keyring` is the credential capability implemented by a
`VaultClient`; it does not refer to Linux's in-kernel `keyctl` keyrings.

### SecretSpec provider

`factorseal provider` implements SecretSpec's typed external-provider protocol
over private stdin/stdout pipes. SecretSpec's existing IPC already carries the
application project context and complete convention or native address. The
endpoint preserves that structure in cache-only Factorseal requests and
connects to the already-running native vault service. It never opens the
database, receives vault keys, or accepts the embedding application's identity
as authority.

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
registration directory. The provider URI is `factorseal://default`. Factorseal
requires SecretSpec to supply a project context so cache access can be isolated.

Start the service with `factorseal agent`. Because the endpoint cannot prompt
on its protocol streams, a sealed service is reported to SecretSpec as
`interaction_required`.

When a project lacks a cache permission, Factorseal creates a pending permission
with a stable opaque ID and retains it in memory for seven days. Equivalent
requests reuse the ID and refresh its expiry. Grant, deny, or later revoke it
through one command family:

```console
$ factorseal permissions list
$ factorseal permissions watch
$ factorseal permissions watch --prompt
$ factorseal permissions approve prm_7K3M
$ factorseal permissions deny prm_7K3M
$ factorseal permissions revoke prm_7K3M
```

Watch mode uses a bounded native revision wait: it wakes immediately when the
permission set changes without polling once per second. The agent permits a small
bounded set of concurrent local connections, allowing provider requests to
create pending permissions while CLI and future GUI notification listeners wait.
The SecretSpec endpoint waits internally for its own pending permission while
the original provider request remains within its deadline. Approval completes
that request without exposing permission-management APIs to SecretSpec; a later
approval remains useful when the caller retries after its deadline.

Granting requires one configured unlock group and creates only the requested
permission for the declared project. Before asking for the factor, Factorseal
prompts for the permission lifetime; Enter accepts the app-requested default (or one
hour when the app supplied none), and values such as `30m`, `8h`, `7d`, and
`forever` override it. The chosen lifetime is bound into the vault signature,
so it cannot be changed after factor confirmation. Factorseal verifies the
typed address and project partition before accepting the project permission,
so declaring an approved project cannot reach another project's secrets.
Interactive prompts distinguish the transport-authenticated executable identity
and digest from caller-declared project, profile, base directory, and reason.
They require a terminal and never approve by default. A vault with multiple
unlock groups asks which one to use only after the user chooses Approve.

Factorseal currently follows the SecretSpec IPC API from the sibling
`../secretspec` checkout. No IPC schema change is required for this storage
model. Release packaging still depends on publishing and pinning that API,
then passing installed end-to-end conformance on Linux, macOS, and Windows.

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

`factorseal seal`, lease expiry, termination, logout, session lock, suspend, and
shutdown all converge on the same worker shutdown path. The platform adapters
monitor logind on Linux, AppKit notifications on macOS, and power/session window
messages on Windows. Sealing invalidates every store handle and zeroizes the
worker's data key and signing seed.

The vault directory contains:

- `factorseal.json`: public identity, unlock policy, per-group key labels,
  factor parameters, and enclave-wrapped bootstrap material;
- `factorseal.db`: encrypted, signed vault state;
- `factorseal.lock`: exclusive store ownership;
- `factorseal.sock`: the live Linux/macOS endpoint, present only while served.

Windows uses `\\.\pipe\factorseal-<vault-id>` instead of a socket.
`FACTORSEAL_ROOT` overrides the vault directory and `FACTORSEAL_SOCKET`
overrides the native endpoint.

`factorseal destroy --yes-really-destroy` permanently deletes a sealed vault,
including every unlock group's enclave keys. It requires one configured unlock
group and is irreversible.

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

Password groups remain limited by password entropy: Argon2id raises offline
guessing cost but cannot turn a human-memorable password into a high-entropy
post-quantum recovery secret. An OR policy is only as strong as its weakest
group. ML-DSA-65 protects state authenticity, while the current platform
wrapping mechanisms have their own cryptographic assumptions.

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

# Architecture

This document describes Factorseal's hardware-bound vault, its keyring
interface, and its per-user background service.

## Trust boundaries

Factorseal separates five responsibilities:

1. a platform adapter authenticates the local caller and handles lifecycle
   events;
2. `VaultService` validates protocol, grants, replay, and the unseal lease;
3. the Automerge domain wrapper applies allowed secret operations;
4. the envelope layer encrypts and device-signs durable state;
5. the sole `VaultStore` worker persists envelopes in Turso.

Neither Turso nor Automerge authorizes a caller. Turso receives no plaintext
document content. Automerge accepts changes only through Factorseal's domain
and envelope verification paths.

## Vault bootstrap

The platform-local Factorseal directory contains only Factorseal-named
artifacts: `factorseal.json`, `factorseal.db`, `factorseal.lock`, and—while the
vault is unsealed—`factorseal.sock` on Unix. The JSON file and database together
form the persisted vault; the socket is only the live service endpoint.

`factorseal.json` contains non-secret public identity and hardware-wrapped
bootstrap material:

- random permanent `VaultId`;
- `DeviceKeyId`, ML-DSA-65 public key, and stable Automerge actor ID;
- recorded TPM/Secure Enclave backend and a versioned unlock policy;
- one independently labeled wrapping/signing key pair for each OR group;
- one wrapped 256-bit DEK and ML-DSA-65 seed payload per group;
- Argon2id parameters and separate AEAD nonces for groups containing password;
- local key epoch and creation time.

Factors inside one unlock group are AND requirements; groups are OR
alternatives. Hardware binding is implicit in every group. Creation opens two
distinct `hardware-enclave` keys per group and rejects DPAPI-only and Linux
software-keyring fallbacks. Password groups apply Argon2id and separate
XChaCha20-Poly1305 layers before hardware wrapping. Biometric groups create
their pair with the platform biometric policy; biometric-only groups have no
password layer. Unsealing opens only the selected group's labels, checks its
backend and policy, unwraps both values, applies its password layer when
required, derives the public signing identity again, and rejects any mismatch
before opening the database.

The present ML-DSA-65 signing seed is hardware-wrapped and lives in zeroizing
vault memory during the lease. A later native adapter may implement signatures
with a non-exportable platform key while keeping the `DeviceKeyId` and envelope
contract stable.

## Document scopes

| Scope | MVP use | Replication |
| --- | --- | --- |
| `device-cache` | SecretSpec cache documents | never |
| `device-local` | durable CLI/application keyring, caller grants, and local policy | never |

A document ID is a domain-separated digest of vault ID, scope, and
namespace. It is opaque in SQL. The namespace and secret item/field live only
inside the encrypted Automerge document.

The secret domain stores one serialized record as an Automerge byte value. A
record binds its item, optional field, value, format version, and optional
eviction deadline. The map key is a separate digest of item and field. On read,
Factorseal checks that the record and requested coordinates match. Automerge's
`get_all` is used so concurrent values cannot be hidden by its deterministic
display winner. Different visible values return `Conflict`.

## Encrypted change envelopes

Every durable snapshot and change uses XChaCha20-Poly1305 with a fresh 192-bit
nonce and ML-DSA-65 signatures cover a domain-separated
transcript including:

- envelope version;
- document ID and scope;
- device key and Automerge actor;
- generation and data-key epoch;
- Automerge dependencies and change hash for a change;
- snapshot heads for a snapshot;
- nonce and ciphertext digest.

Verification checks the signature before accepting data, decrypts with the
same associated data, decodes the Automerge change, and compares its actor,
hash, and dependencies to the signed header.

## Turso persistence

One worker thread owns one Turso connection and the exclusive `factorseal.lock`
file. All in-process handles send bounded commands to that worker. Sealing the
shared control stops the worker and zeroizes the DEK; every clone is
invalidated.

The schema contains:

- `store_meta` for schema version and current protected head;
- `vault_identity` for the checked public vault identity;
- `documents` for opaque ID, scope, generation, epoch, and current commit;
- `document_snapshots` for encrypted signed snapshots;
- `document_changes` for encrypted signed changes;
- `protected_commits` for the signed global commit chain;
- `sync_peers` and `sync_outbox` reserved for encrypted future sync state.

Mutation first builds and signs envelopes, then uses one Turso transaction to
compare-and-swap the document generation, append snapshot and changes, append a
protected commit, and move the current head. Opening the store walks the entire
head chain, rejects cycles/orphans/missing commits, verifies signatures, and
checks each snapshot/change-set digest.

This detects database content tamper and inconsistent partial rollback when a
newer protected head or commit remains. No cross-platform local primitive can
prove that an attacker did not roll back the complete vault directory.
The offline MVP therefore excludes whole-directory rollback from its threat
claim. Detecting it needs a checkpoint held outside that directory.

## Expiry

Storage deadlines are inside encrypted records. Reads delete an expired entry
before returning a miss. The store also scans every `device-cache` document at
startup and exposes a purge operation for the live scheduler. Packaged vault services
must call it at the next deadline or at a short bounded interval; tests prove
that explicit purge removes an entry without a read and that it remains absent
after restart.

An unresolved conflict containing any expired value is removed as a whole.
For a cache, failing closed and refetching from the authoritative provider is
safer than returning a possibly stale concurrent value.

## Local protocol and grants

Requests and responses are JSON envelopes with a fixed version, random 128-bit
request ID, strict fields, and a 1 MiB limit. Secret request/response values use
buffers that zeroize on drop. The service retains a bounded replay window and
binds each response to its request ID.

`CallerIdentity` includes platform, user identity, application identity,
executable digest, and optional signing identity. These values are supplied by
the authenticated transport adapter. A digest of the complete caller identity
is part of every durable grant.

Grants bind the document scope and can target one exact namespace/item/field or
an entire namespace. They contain an explicit set of
get/put/delete/clear/seal permissions and an optional expiry that is also
applied as a storage eviction deadline. A disposable cache grant therefore
cannot authorize a durable keyring write. Grants are stored in the encrypted
`device-local` document.

An unseal lease has independent idle and absolute deadlines. Authorized
operations refresh only the idle deadline and can never pass the absolute
deadline. Explicit seal and timer, logout, suspend, or shutdown hooks all call
the same vault-sealing path.

## SecretSpec seam

SecretSpec owns provider discovery, address syntax, operation dispatch, and
the typed IPC wire contract. Factorseal implements its `factorseal provider`
subcommand against the Rust IPC crate, which is the external-provider endpoint
SecretSpec launches over private stdin/stdout pipes.

The endpoint translates convention and native addresses into a versioned
Factorseal address beneath a derived project prefix and sends get, set,
expiring set, and delete as `device-cache` requests in the
`secretspec-cache/v1` namespace. The service verifies that prefix before it
considers a project grant, preventing an approved project context from naming
another project's cached secrets. The endpoint never opens the embedded
database, handles vault keys, or performs durable `Keyring` operations. The
`vault-client` feature remains the lightweight native seam for Factorseal-aware
applications.

The endpoint executable, not the SecretSpec CLI or embedding application, is
the principal authenticated by Factorseal's Unix socket or Windows named pipe.
Project approval therefore grants that exact executable cache-only permission
for the declared project. The endpoint forwards SecretSpec's project, profile,
base directory, reason, and optional requested authorization duration with
every native request for future approval, notification, and audit presentation.
That context is metadata only: it does
not replace the transport-authenticated executable identity and is never grant
authority. The remaining release proof is publishing the IPC dependency and
running installed end-to-end conformance on each platform.

Missing project permissions create bounded in-memory approvals with a
seven-day retention window. The agent deduplicates equivalent requests,
refreshes their expiry, and returns an opaque correlation ID; it does not
accept that ID as authority. `factorseal approvals approve`
must satisfy one configured unlock group and sign the agent's one-time
challenge with the vault identity before the agent stores a project-scoped
grant. Denial needs no factor but is restricted to the separately authorized
Factorseal CLI executable. `factorseal approvals --watch --prompt` displays
that trusted principal separately from declared application context and
requires an explicit terminal choice of approve, deny, or ignore. It selects a
sole configured unlock group automatically and asks when multiple alternatives
exist. Approval asks for the final grant lifetime before satisfying a factor;
the app request is only the prompt default, and the resulting project grant
expires at the signed duration. Approval state disappears on expiry or sealing.

## Platform adapters

The shared core implements the following native adapters:

- Linux: TPM 2.0 plus the configured unlock group, a private Unix socket authenticated
  with `SO_PEERCRED`, executable digest grants, and a systemd user unit;
- macOS: Secure Enclave user verification, a private Unix socket authenticated
  with kernel peer credentials, peer PID, and audit token, plus a LaunchAgent;
- Windows: TPM 2.0 plus an OS-mediated CNG key-use policy, a local-only named
  pipe protected by a same-user DACL and verified through client
  impersonation, SID, PID, and executable digest, plus a per-user Scheduled
  Task template.

- Linux subscribes to logind session-lock and pre-sleep/pre-shutdown signals
  while holding a delay inhibitor until the vault is sealed;
- macOS observes AppKit sleep, power-off, and session-resign notifications;
- Windows registers a hidden-window power/session listener and seals directly
  from suspend, shutdown, session-lock, logout, and disconnect callbacks.

The transports, lifecycle monitors, and developer packaging inputs are
implemented. Code-signature identities, official signing/notarization, and
physical-hardware/lifecycle acceptance remain release work. Windows uses the
CNG key's OS-mediated UI-protection policy; the current hardware library's
application-level modern Hello convenience gate is intentionally disabled
because it is not bound to the TPM operation and can degrade when Hello is not
available. The shared caller identity type is never populated from untrusted
JSON fields.

Linux executable authentication reads the ptrace-gated
`/proc/<SO_PEERCRED pid>/exe` link. Filesystem mount-namespace directives on an
unprivileged systemd user service make that link unreadable on the tested
NixOS configuration, so the current unit deliberately retains non-namespace
hardening only. A future IPC principal based on a verified sandbox/application
identity, or a privileged broker design, is required before mount-namespace
isolation can be restored without weakening caller authentication.

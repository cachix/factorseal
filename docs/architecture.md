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
distinct `hardwareseal` protectors per group and rejects unsupported or
software-only backends. Password groups apply Argon2id and separate
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

## Automerge documents

| Document kind | Partition | Use | Replication |
| --- | --- | --- | --- |
| `secretspec-project` | project name | durable CLI project secrets | never |
| `secretspec-provider-cache` | project name | disposable SecretSpec provider cache | never |
| `local-keyring` | native namespace | Rust keyring clients | never |
| `linux-secret-service` | service namespace | Linux Secret Service collections | never |
| `authorization` | authorization namespace | caller grants and local policy | never |

A document ID is HMAC-SHA-256 under the vault data key over the document kind
and partition. It is opaque in SQL and does not expose guessable project names.
The partition and secret address live only inside the encrypted Automerge
document.

The version-1 Automerge root contains `format` (the document kind),
`format-version`, `partition` bytes, and an `entries` map. Loading checks this
descriptor against the protected document metadata before serving a value.

The secret domain stores one serialized record as an Automerge byte value. A
record binds its complete typed address, value, format version, and optional
eviction deadline. A SecretSpec convention address contains project, profile,
and key. A native address contains item and optional field, vault, section, and
version. The map key is a separate digest of the full address. On read,
Factorseal checks that the record and requested address match. Automerge's
`get_all` is used so concurrent values cannot be hidden by its deterministic
display winner. Different visible values return `Conflict`.

## Encrypted change envelopes

Every durable snapshot and change uses XChaCha20-Poly1305 with a fresh 192-bit
nonce and ML-DSA-65 signatures cover a domain-separated
transcript including:

- envelope version;
- document ID and kind;
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
- `documents` for opaque ID, document kind, generation, epoch, and current commit;
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
before returning a miss. Metadata listing also purges expired records and hides
projects left empty by that purge. The store scans every
`secretspec-provider-cache` document at startup and exposes a purge operation
for the live scheduler. Packaged vault services must call it at the next
deadline or at a short bounded interval; tests prove
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

Grants bind the document kind and can target the entire kind, one exact
partition/address, or an entire partition. They contain an explicit set of
list/get/put/delete/clear/seal permissions and an optional expiry that is also
applied as a storage eviction deadline. A disposable cache grant therefore
cannot authorize a durable keyring write. Grants are stored in the encrypted
`authorization` document.

`ListProjects` and `ListProjectAddresses` are metadata-only, cursor-paginated
operations for a future management UI. They decrypt and validate Automerge
records inside the sole store worker; they never enumerate SQL hashes or return
values. `List` is independent from `Get`, and the maximum page size is chosen
so worst-case JSON escaping remains within the one-MiB wire limit. Concurrent
values at one authenticated address collapse to one list item; conflicting
addresses under one index fail closed. The Factorseal CLI's `projects` and
`list --project` commands exercise the same native protocol and transparently
consume every page.

An unseal lease has independent idle and absolute deadlines. Authorized
operations refresh only the idle deadline and can never pass the absolute
deadline. Explicit seal and timer, logout, suspend, or shutdown hooks all call
the same vault-sealing path.

## SecretSpec seam

SecretSpec owns provider discovery, address syntax, operation dispatch, and
the typed IPC wire contract. Factorseal implements its `factorseal provider`
subcommand against the Rust IPC crate, which is the external-provider endpoint
SecretSpec launches over private stdin/stdout pipes.

Provider discovery is published automatically as
`factorseal.secretspec.json` in SecretSpec's per-user provider directory. The
claim contains only Factorseal's canonical executable path; its filename names
the scheme and SecretSpec supplies the fixed `provider` argument. Initialization
creates the claim and agent startup refreshes it after executable upgrades.

The endpoint sends get, set, expiring set, and delete as typed
`secretspec-provider-cache` requests partitioned by project. It preserves
SecretSpec convention addresses (`project`, `profile`, `key`) and native
coordinates (`item` plus optional `field`, `vault`, `section`, and `version`)
without flattening. The service rejects a convention address whose project
does not match the request partition before it considers a project grant. The
endpoint never opens the embedded database, handles vault keys, or performs
durable project or `Keyring` operations. The `vault-client` feature remains the
lightweight native seam for Factorseal-aware applications.

The endpoint executable, not the SecretSpec CLI or embedding application, is
the principal authenticated by Factorseal's Unix socket or Windows named pipe.
Project approval therefore grants that exact executable cache-only permission
for the declared project. The endpoint forwards SecretSpec's project, profile,
base directory, reason, and optional requested permission duration with
every native request for future approval, notification, and audit presentation.
That context is metadata only: it does
not replace the transport-authenticated executable identity and is never grant
authority. The remaining release proof is publishing the IPC dependency and
running installed end-to-end conformance on each platform.

Missing project permissions create bounded in-memory pending permission records
with a seven-day retention window. The agent deduplicates equivalent requests,
refreshes their expiry, and returns an opaque `prm_` correlation ID; it does not
accept that ID as authority. `factorseal permissions approve`
must satisfy one configured unlock group and sign the agent's one-time
challenge with the vault identity before the same ID becomes a durable,
project-scoped granted permission. Denial and revocation need no factor but are
restricted to the separately authorized Factorseal CLI executable.
`factorseal permissions watch --prompt` displays
that trusted principal separately from declared application context and
requires an explicit terminal choice of approve, deny, or ignore. It selects a
sole configured unlock group automatically and asks when multiple alternatives
exist. Approval asks for the final permission lifetime before satisfying a factor;
the app request is only the prompt default, and the resulting project permission
expires at the signed duration. Pending state disappears on denial or sealing;
granted state disappears on revocation or expiry. SecretSpec's audit log owns
the historical record. Watchers use a bounded native long-poll keyed by the
permission revision. Local
transports accept at most eight concurrent requests, so a waiting CLI or GUI
listener releases the approval-state mutex and cannot block a provider request
that creates or refreshes an approval.

The provider's internal wait is narrower than the management watch. Its native
request names one permission ID and the service accepts it only from the
transport-authenticated principal that created that permission. The provider
can therefore complete the original SecretSpec request after approval without
giving SecretSpec permission-list or decision authority. Pending and recently
resolved decisions live only in the bounded in-memory approval queue; durable
grants are consulted only when authorizing secret operations.

## Platform adapters

The shared core implements the following native adapters:

- Linux: TPM 2.0 plus the configured unlock group, a private Unix socket authenticated
  with `SO_PEERCRED`, executable digest grants, and a systemd user unit;
- macOS: Secure Enclave user verification, a private Unix socket authenticated
  with kernel peer credentials, peer PID, and audit token, plus a LaunchAgent;
- Windows: TPM 2.0 plus Windows Hello platform-credential PRF policy, a local-only named
  pipe protected by a same-user DACL and verified through client
  impersonation, SID, PID, and executable digest, plus a per-user Scheduled
  Task template.

- Linux watches `LockedHint` for every logind session owned by the user, with
  session-lock signals as an eager fallback, and holds a delay inhibitor across
  pre-sleep/pre-shutdown sealing;
- macOS checks the Core Graphics login-session lock state and observes AppKit
  sleep, wake, power-off, and session-resign notifications;
- Windows registers a hidden-window power/session listener, checks the initial
  WTS lock state, and seals on suspend/resume, shutdown, session lock, logout,
  and disconnect. A suspend deadline aborts the process if synchronous store
  shutdown cannot finish inside Windows' callback window.

All three lifecycle subscriptions are installed and armed before native
authorization begins. Events during authorization or database opening latch;
the new service seals before its IPC listener can accept a request.

The transports, lifecycle monitors, and developer packaging inputs are
implemented. Code-signature identities, official signing/notarization, and
physical-hardware/lifecycle acceptance remain release work. Windows biometric
groups require a platform WebAuthn credential with PRF support; its output
authenticates an outer AES-256-GCM envelope around the TPM sealed-data object,
so neither a separate consent result nor a software fallback can authorize
unsealing. The shared caller identity type is never populated from untrusted
JSON fields.

Linux executable authentication reads the ptrace-gated
`/proc/<SO_PEERCRED pid>/exe` link. Filesystem mount-namespace directives on an
unprivileged systemd user service make that link unreadable on the tested
NixOS configuration, so the current unit deliberately retains non-namespace
hardening only. A future IPC principal based on a verified sandbox/application
identity, or a privileged broker design, is required before mount-namespace
isolation can be restored without weakening caller authentication.

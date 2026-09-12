# FactorSeal architecture

[Back to the project overview](../README.md).

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
                     installation root
                              |
                              v
                 derived document-index key
              per-operation signing seed / DEK
                              |
   CLI / SecretSpec endpoint / aware application
                              |
                    Keyring or cache adapter
                              |
                         VaultClient
                              |
          authenticated, length-bounded native transport
                              |
                   per-user VaultService
         caller grants | request deduplication | lease | expiry
                              |
                  scoped Automerge operations
                              |
          encrypted snapshots + device-signed commits
                              |
                     embedded Turso database
```

Every configured OR alternative has one independent hardware-wrapping key. A
biometric factor gates that key through the platform policy; a password factor
additionally derives a key with Argon2id by default, or PBKDF2-HMAC-SHA-256 in
the persisted FIPS profile, and encrypts the wrapped payload with AES-256-GCM.
Hardware-protector operations are not in the database write path, and
unsealing costs one hardware operation. Once unsealed, only the installation
root and the document-index key derived from it remain in zeroizing worker
memory for the lease. Document DEKs and signing capabilities are unwrapped
only for the operation that needs them and zeroized immediately afterward.
New vaults on macOS 26+ use non-exportable Secure Enclave ML-DSA-65 keys;
their opaque references are root-encrypted. Existing vaults, older macOS, and
other platforms use root-encrypted software signing seeds. Enclave signing
adds a native operation to each signature; it never falls back on failure.

### Creation and unsealing

Creation generates distinct random installation and device-vault IDs, a
256-bit installation root, and a separate ML-DSA-65 signing identity; the
document-index key is derived from the root and both IDs.
The signing identity also determines the permanent `DeviceKeyId`
and stable Automerge actor ID. Each document generation is encrypted under its
own random 256-bit DEK; the document row keeps only the current wrapped key.

Factors inside a group are all required; each repeated group is an independent
OR alternative. Password groups derive an encryption key with the vault's
recorded KDF—Argon2id by default or PBKDF2-HMAC-SHA-256 in the FIPS profile—and
encrypt the installation root with AES-256-GCM before one hardware-backed key
wraps it. Biometric-only groups wrap the root directly with a key whose use
requires platform biometric approval, so unsealing needs one native ceremony.

Unsealing reverses those layers, reconstructs the selected signing provider,
and rejects any public-identity mismatch before opening the database.
The store then verifies its schema, installation/device-vault identity, signed
commit chain, wrapped document-key digests, and current document heads before
serving requests.

### Authenticated local requests

The local protocol uses strict, versioned JSON messages with random 128-bit
request IDs and a 1 MiB limit. Secret-bearing buffers zeroize on drop where the
Rust API permits. Responses are bound to their request IDs, and the service
keeps a bounded window of consumed IDs so a resubmitted request is not applied
twice.

Caller identity comes from the native transport, never from request JSON:

- Linux uses a private Unix socket, `SO_PEERCRED`, the peer PID, and a digest
  of `/proc/<pid>/exe`;
- macOS uses a private Unix socket, kernel peer credentials, the peer PID, and
  its audit token, then binds grants to the executable digest;
- Windows uses a same-user named pipe, client impersonation, SID and PID
  verification, and the executable digest.

Clients also authenticate the server before sending request bytes: its UID must
match on Unix, and both the pipe owner and server process must have the client's
SID on Windows. Windows clients request identification-only tokens.

Durable grants bind the complete caller identity to a document kind, partition,
or exact address, explicit permissions, and an optional expiry. An executable
change therefore requires a new grant. These grants are defense in depth between
same-user applications; they do not protect a granted program from debugging,
preloading, or compromise by that same user. The Linux transport rejects a peer
that is being traced or was started with `LD_PRELOAD` or `LD_AUDIT` set, which
stops the direct forms of that access but not a same-user process that injects
code and hides the evidence before it connects.

### Documents and persistence

Factorseal stores multiple encrypted Automerge documents in one non-replicating
Device vault. A document ID is an HMAC under the installation's index key over
the Device-vault ID, semantic kind, and private partition, so SQL does not
reveal or permit offline guessing of project names. Secret names, addresses,
project partitions, and values live only inside encrypted Automerge snapshots,
not in SQL columns or filenames.

Every Automerge document has this version-3 root shape:

```text
format:          <document-kind>
format-version:  3
partition:       <bytes>
entries:         { <address-digest>: <serialized-record> }
```

Each version-2 record contains the complete typed address, base64-encoded
`value`, an optional `evict_at` deadline, a `version_id`, and `created_at` and
`updated_at` timestamps. SecretSpec convention addresses retain project,
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

Every mutation persists one encrypted snapshot. The snapshot is a fresh-genesis
projection of the document's current records, so deleted and overwritten
values do not survive in it, and it is encrypted under a fresh DEK for that
generation with AES-256-GCM and a 96-bit nonce. The AEAD header binds its
device-vault ID, document ID and kind, generation, and key epoch. Plaintext
Automerge heads are never published in the header. One ML-DSA-65 signed
protected commit per generation binds the snapshot digest, wrapped key and
eviction deadline. Live reads and compaction compare against verified in-memory
heads; compaction cannot certify a partially rolled-back document.

Each document also keeps a bounded history of its changes: which address
changed, when, on whose behalf, and which value version replaced which.
History never contains a secret value, and it is trimmed per document kind so
a busy cache cannot grow without bound. The history is its own ciphertext in
the same envelope as the record document, under the same key and covered by
the same signed commit, so reading records never decrypts it, a write appends
to it without rebuilding it inside the record document, and listing history
never decrypts a value. History listing requires the scoped `List` permission.
An entry made by another application is shown with its principal and declared
context redacted unless the reader holds the `manage-permissions` grant.

One worker thread owns the Turso connection, exclusive `factorseal.lock`, and
lease-scoped installation root/index capability. It unwraps only the requested
document DEK and the signing capability while processing an operation. A mutation
uses one transaction to compare-and-swap the document generation, append its
encrypted state, append a signed protected commit, and advance the global head.
The protected commit chain is periodically compacted to the current state of
every document; it is a tamper check, not an audit log. The separate value-free
history log retains entries according to its document kind's limits.

The store re-verifies these storage and protected-chain invariants whenever
the vault is opened.

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

FactorSeal Desktop uses a permission-manager-only, value-free inventory request
to group entry addresses under Projects, System keyring, Application
keyrings, Portal secrets, and the advanced provider cache. Authorization
documents remain separate and are represented through the Access view. Secret
values are never returned by the inventory operation.

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

For the default vault root, `factorseal init` publishes the installed binary as
the `factorseal` scheme in SecretSpec's user provider directory:

```json
{
  "executable": "/absolute/path/to/factorseal"
}
```

The public claim is named `factorseal.secretspec.json`; users do not create or
manage it. The agent refreshes its canonical executable path at startup so
packaged upgrades remain discoverable. SecretSpec always launches the claimed
executable with the fixed `provider` argument. The provider URI is
`factorseal://default`. Factorseal requires SecretSpec to supply a project
context so cache access can be isolated.

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

Factorseal currently pins the SecretSpec IPC API to an unpublished Git revision.
Release packaging still depends on publishing and pinning that API, then
passing installed end-to-end conformance on Linux,
macOS, and Windows.

### Linux Secret Service

On Linux, Factorseal Desktop registers `org.freedesktop.secrets` for D-Bus
activation and serves a locked collection while the vault is sealed. Item
labels and lookup attributes remain in the encrypted index; no plaintext search
cache is written. Sealed searches open a separate access dialog showing the
requesting executable, working directory, process, and lookup attributes. The
standard SecretSpec service path also supplies the project, profile, and secret
name. These project labels are caller-provided; they are not a verified project
identity. Unlocking and grant approval stay in one popup, reusing the secure
password entry. The signed grant binds the authenticated executable, project,
folder, and operation, either for one hour or until revoked. Keyring requests
use the nearest `secretspec.toml` ancestor of the OS-reported working directory
(or that directory itself); SecretSpec IPC supplies its canonical project folder. Grants appear in Access
Grants and are checked again for each secret operation. SecretSpec IPC uses the
same approval flow, with separate grants for its provider-cache scope.
Desktop writes open a masked, editable secret-entry dialog and authorize only
that save, without creating a write grant. Native IPC transports the value over
a private file descriptor. Its current `set` protocol already supplies a value;
starting the prompt before that value exists requires a SecretSpec-side change.
Explicit denial returns `org.freedesktop.Secret.Error.AccessDenied`, dismissal
returns `org.freedesktop.Secret.Error.Cancelled`, and expiration returns
`org.freedesktop.Secret.Error.TimedOut`. Clients may impose a shorter D-Bus
timeout. Clients that explicitly call `Unlock` use the normal prompt flow.

Do not run another provider that owns that bus name, such as GNOME Keyring or
oo7, at the same time. macOS Keychain and Windows Credential Manager remain
separate platform interfaces.

## Vault lifecycle

An unseal lease has independent idle and absolute deadlines. Authorized secret
operations refresh only the idle deadline and can never extend the absolute
deadline. Status checks do not refresh the lease.

`factorseal seal`, lease expiry, termination, logout, session lock, suspend, and
shutdown all converge on the same worker shutdown path. The platform adapters
monitor logind on Linux, AppKit notifications on macOS, and power/session window
messages on Windows. Sealing invalidates every store handle and zeroizes the
worker's installation root, index key, and any active operation keys.

The vault directory contains:

- `factorseal.json`: public identity, unlock policy, per-group key labels,
  factor parameters, and hardware-wrapped bootstrap material;
- `factorseal.db`: encrypted, signed vault state;
- `factorseal.lock`: exclusive store ownership;
- `factorseal.sock`: the live Linux/macOS endpoint, present only while served.

Windows uses `\\.\pipe\factorseal-<installation-id>` instead of a socket.
`FACTORSEAL_ROOT` overrides the vault directory and `FACTORSEAL_SOCKET`
overrides the native endpoint.

`factorseal destroy --yes-really-destroy` removes a sealed vault directory and
asks each backend to remove its locally owned keys. It requires one configured
unlock group. This is local removal, not backup revocation: self-contained TPM
envelopes remain usable on the original TPM with valid factors if a copy was
retained. Public metadata and encrypted database schemas are versioned
independently. Supported database upgrades run transactionally after unseal;
the service verifies the old signed chain before rewriting it and advances the
schema version only when the new signed state is durable. Unknown formats are
rejected and never automatically removed.

## Security properties and limitations

Factorseal is designed so that:

- plaintext installation, signing, index, and document keys are never
  persisted;
- copying `factorseal.db` and `factorseal.json` to another machine does not
  recover secrets without the hardware keys;
- Turso receives no plaintext document content and is not an authorization
  boundary;
- an application receives a secret only after its transport-derived identity
  matches a suitable grant;
- snapshots authenticated by signed commits detect content tampering, missing
  generations, divergent writers, and inconsistent partial rollback when newer
  protected state remains;
- a deleted or overwritten value is absent from the next persisted snapshot,
  and the superseded generation's key is replaced. This is logical deletion,
  not cryptographic erasure: a root holder may recover earlier values from
  retained wrapped keys in database remnants, filesystem snapshots or backups.
  Checked WAL checkpoint/truncation reduces retention but cannot revoke copies.

The design does not detect rollback of the complete vault directory. Doing so
requires a trusted checkpoint stored elsewhere. The offline MVP deliberately
excludes whole-directory rollback from its security claim.

Password groups remain limited by password entropy: memory-hard Argon2id is the
default defense against offline guessing, while the FIPS profile trades that
memory hardness for standardized PBKDF2-HMAC-SHA-256. Neither can turn a
human-memorable password into a high-entropy post-quantum recovery secret. An
OR policy is only as strong as its weakest group. ML-DSA-65 protects state
authenticity, while platform wrapping has its own cryptographic assumptions.

The opt-in FIPS profile selects AES-256-GCM, SHA-256/HMAC, PBKDF2, and
ML-DSA-65 from NIST standards so a future deployment can place them behind a
validated provider. Argon2id remains the default profile because it is
memory-hard, but it is not a FIPS-approved KDF. The current RustCrypto
implementations and Factorseal product boundary have not completed CAVP or
CMVP validation, so neither profile makes Factorseal FIPS 140-3 validated.
Platform biometric paths inherit the algorithms and certification properties
of their TPM, Secure Enclave, or Windows Hello components and are not
claimed to be completely post-quantum certified.

Software signing seeds briefly exist in zeroizing process memory for each
signature. New macOS 26+ vaults instead use non-exportable enclave signing
keys, with root-wrapped opaque references. Existing identities remain unchanged
on upgrade; see the [migration design](../security/macos-crypto-and-isolation.md).
The retained installation root can
unwrap any local document during an active lease, so this hierarchy reduces
passive key retention rather than defeating code execution in the unsealed
process. Hardware binding also cannot stop an authorized or compromised client
from exfiltrating a secret returned to it. Encrypted `.factorseal` archives support portable backup and restore using a
separate archive passphrase. Hardware loss still loses data that was not exported
beforehand; a native vault-directory copy cannot replace a portable backup. Zeroization is best-effort; locked
memory and complete process-dump protection are not yet implemented.

See [Security](../SECURITY.md) for the complete threat model and vulnerability
reporting instructions.


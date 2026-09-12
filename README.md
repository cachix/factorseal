<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/factorseal-mark-paper.svg">
    <img src="assets/logo/factorseal-mark-ink.svg" alt="FactorSeal logo" width="120">
  </picture>
</p>

<h1 align="center">FactorSeal</h1>

<p align="center">
  <a href="https://github.com/domenkozar/factorseal/actions/workflows/ci.yml"><img src="https://github.com/domenkozar/factorseal/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-151515.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/rust-1.91%2B-151515.svg" alt="Rust 1.91+">
</p>

> [!WARNING]
> FactorSeal is an unaudited prototype. It is not ready for production secrets.

FactorSeal is a hardware-backed vault for personal passwords and application
secrets. Manage logins, notes, and other personal records in Desktop, or give
local applications scoped access to project secrets and keyring entries.
Secrets are encrypted on your device, with vault unlock protected by
[TPM 2.0](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
on Linux and Windows or Apple's
[Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
on macOS.

## What you can do

- **Manage personal secrets:** Desktop provides typed records for logins,
  secure notes, cards, identities, SSH keys, API credentials, and more, with
  custom fields and masked input. See [personal item types](#personal-item-types-and-migration).
- **Migrate and back up:** Import from Bitwarden, 1Password, and KeePass export
  formats, or create an encrypted FactorSeal archive for portable backup and
  restore. See [import and export](#import-and-export).
- **Use secrets in development:** Store durable project secrets through the
  CLI and provide a separate disposable
  [provider cache](https://secretspec.dev/concepts/providers/caching/) for
  [SecretSpec](https://secretspec.dev/).
- **Serve local applications:** Provide a native
  [keyring](#interfaces-and-document-kinds) and the standard
  [`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/latest/)
  interface on Linux, with explicit application access grants.
- **Pair devices for personal sync:** Desktop offers experimental encrypted
  peer sync with QR/ticket pairing and code approval. See
  [personal sync](#personal-sync-experimental) for its current limits.

Personal password management is still incomplete: browser autofill, usable
passkeys, auto-type, and TOTP code generation are not currently provided.
Storing an SSH key or importing a TOTP seed does not provide SSH-agent or
authenticator functionality.

## Hardware binding and application access

The native vault is bound to your device's hardware keys. Copying its database
and configuration to another machine is not enough to unlock it. Recovery after
hardware loss requires a portable export made beforehand; keep an
[encrypted backup](#import-and-export).

Desktop and local clients access the vault through a per-user service. The
service authenticates calling executables and checks grants for the requested
secrets and operations. Applications never open the database or receive its
encryption and signing keys. These grants provide defense in depth between
same-user applications; a compromised authorized client can still disclose
secrets it receives. See the [security model](SECURITY.md).

The basic lifecycle is:

1. **Create** a vault and choose a password and/or biometric unlock policy.
2. **Unseal** it by satisfying one of those policies.
3. **Authorize** local applications for only the secrets and operations they
   need.
4. **Use** the vault through Desktop, the CLI, or an integration while it is unsealed.
5. **Seal** it to stop the service and remove plaintext vault keys from memory.

## Desktop unlock support

| Platform | Biometric method | Intended hardware binding | Status |
| --- | --- | --- | --- |
| macOS | Touch ID | Keychain/Secure Enclave key-use policy | Implemented; physical-device release acceptance remains |
| Windows | Windows Hello fingerprint, face, or PIN | TPM sealed-data object nested inside Windows Hello PRF encryption | Implemented; physical-device prompt and policy acceptance remains |
| Linux | No portable built-in biometric path | TPM 2.0 supports hardware wrapping, but `fprintd` does not provide a hardware-bound secret | Password-backed TPM unlock only |

The vault encryption and ML-DSA signatures are designed to resist quantum
attacks. Native biometric enforcement still inherits the cryptographic and
certification properties of Secure Enclave or Windows Hello, so Factorseal does
not claim that those complete platform paths are post-quantum certified.

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

Password slots use memory-hard Argon2id by default. Deployments that require a
NIST-standardized algorithm profile can opt into PBKDF2-HMAC-SHA-256 with
`factorseal init --fips`. This selects algorithms suitable for a future
validated provider boundary; it does not make the current build FIPS validated.

Unlock policies use AND inside one comma-separated group and OR between
repeated groups. Platform hardware binding is implicit in every group:

```console
$ factorseal init --unlock password,biometric
$ factorseal init --unlock password --unlock biometric
$ factorseal init --fips
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

Or use the separately packaged graphical host:

```console
$ factorseal desktop
```

Desktop initializes and unseals the same vault through a dedicated CLI worker,
which hosts the authenticated endpoint. On Linux, Desktop hosts the
`org.freedesktop.secrets` adapter and accesses the worker through authenticated
IPC. The GUI releases its unlock password after
handoff; the worker wipes that factor before serving. Install the CLI alongside
Desktop or set `FACTORSEAL_CLI_EXECUTABLE` to its absolute path. It is an
alternative to `factorseal agent`, not a client of it, so do not configure both
to autostart. Repeated Desktop launches activate the existing per-vault
instance. On Linux, the Desktop package registers D-Bus activation for
`org.freedesktop.secrets`. Desktop keeps answering while sealed, but credential
searches open a compact access dialog and resume after approval and authentication. Native
socket and SecretSpec clients also require Desktop to be unsealed first.
Request parsing and personal sync run in separate confined helper processes
installed beside the CLI. On Linux the sync helper requires Landlock ABI 3, so
personal sync needs kernel 6.2 or later; distributions such as Debian 12 and
Ubuntu 22.04 ship older kernels and cannot run it. The parser helper works on
every supported kernel.
Sealing removes the native service endpoint and all unwrapped vault keys.

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

Show what changed in a project, newest first, without reading any value:

```console
$ factorseal history --project my-app
{"version":1,"seq":1,"at":1756742400,"operation":{"type":"delete"},"address":{"domain":"secret_spec","address":{"kind":"native","coordinates":{"item":"github","field":"token"}}},"previous_version_id":"…","provenance":{"source":"caller","principal":{…}},"device_key_id":[…]}
```

An entry names the address, the operation, the value version it created or
replaced, and the transport-authenticated caller or service reason it was
performed for. It never contains the value itself.

All three commands follow every bounded vault cursor automatically. Pass
`--json` to emit one JSON array instead of JSON-quoted projects or one compact
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
project approval must also be renewed for the new executable.

Seal the running service immediately when it is no longer needed:

```console
$ factorseal seal
```

### Import and export

Create or restore a portable, versioned FactorSeal archive while the vault is
unsealed:

```console
$ factorseal export backup.factorseal
Archive passphrase:
Confirm archive passphrase:
$ factorseal import backup.factorseal
Archive passphrase:
$ factorseal import backup.factorseal --replace-existing
```

Native archives include every portable vault document and are encrypted with
AES-256-GCM using a separate Argon2id-stretched passphrase. For unattended
jobs, use `--passphrase-file` with a private regular file (mode `0600` on
Unix). Imports preserve existing entries unless `--replace-existing` is
explicitly passed. Exports read the live vault and fail if its contents change
during collection; retry the export in that case. Linux keyring metadata and
values restore together, preserving unrelated destination items. Archive v2
readers also convert v1 archives during import.

Password-manager formats operate on Personal Secrets only:

```console
$ factorseal import bitwarden.json --format bitwarden-json
$ factorseal export onepassword.csv --format 1password-csv
$ factorseal export keepass.csv --format keepass-csv
```

Bitwarden JSON, 1Password CSV, and KeePass CSV are plaintext formats. FactorSeal
prints a warning and writes exports through a private temporary file before
atomically replacing the destination. Exports reject items whose fields or
metadata the selected format cannot preserve; use an encrypted FactorSeal
archive for a lossless backup. Duplicate imported titles receive stable,
collision-free suffixes.

### Personal item types and migration

Personal items use a versioned record with a stable ID, category, ordered sections,
and typed fields. Templates cover logins, secure notes, cards, identities, SSH
keys, API credentials, passports, bank accounts, documents, and generic secrets.
Fields have independent IDs and labels, so repeated labels and multiple passwords
are supported. The desktop creation form offers templates and custom fields;
values use masked, locked-memory input, including multiline values.

Existing v1 records and UTF-8 secret values migrate on read; subsequent writes use
v2. Native encrypted archives retain all sections, fields, and source metadata.
Unknown CSV columns become concealed custom fields. Bitwarden custom-field types
and linked-field IDs are preserved. Unmapped Bitwarden properties are retained in
encrypted source metadata and prevent exports to formats that would discard them.

Import 1Password's richer export with:

```console
$ factorseal import account.1pux --format 1password-1pux
```

1PUX v3 imports preserve sections, typed values, source metadata (including password
history), and files. Files are currently stored as separate document items; source
metadata retains their document IDs. The importer never extracts ZIP paths to disk,
limits expanded archives to 128 MiB, and rejects missing referenced files. Each
encoded personal item is limited to 512 KiB to fit the vault protocol. An oversized
item fails preparation before any imported items are written. 1PUX is import-only;
use an encrypted FactorSeal archive to back up these richer records. Preserving
passkey or other unrecognized source data does not make it usable for authentication.

### Personal sync (experimental)

Desktop can pair devices using QR codes or tickets with explicit code approval
and exchange encrypted personal-item changes through an iroh courier. Once
configured, the courier can continue transferring ciphertext while Desktop
remains open and the vault is sealed. Applying changes requires the vault worker
to be unsealed. Project secrets, application grants, and device keys remain local.

Sync is experimental. Mobile camera integration, peer application receipts, a
conflict-resolution chooser, and controller transfer and removal UI are still
missing. A connected peer does not confirm that it has applied your changes.
Personal history includes old and deleted values, and newly enrolled readers
receive that history. Sync does not replace a portable backup.

See the [personal sync boundary](security/personal-sync-wire.md) for protocol,
history-retention, and platform limitations.

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
on upgrade; see the [migration design](security/macos-crypto-and-isolation.md).
The retained installation root can
unwrap any local document during an active lease, so this hierarchy reduces
passive key retention rather than defeating code execution in the unsealed
process. Hardware binding also cannot stop an authorized or compromised client
from exfiltrating a secret returned to it. Encrypted `.factorseal` archives support portable backup and restore using a
separate archive passphrase. Hardware loss still loses data that was not exported
beforehand; a native vault-directory copy cannot replace a portable backup. Zeroization is best-effort; locked
memory and complete process-dump protection are not yet implemented.

See [Security](SECURITY.md) for the complete threat model and vulnerability
reporting instructions.

## Build and test

The repository uses [devenv](https://devenv.sh/) on Linux:

```console
$ devenv shell cargo test --workspace --all-targets --all-features
$ devenv shell cargo clippy --workspace --all-targets --all-features -- -D warnings
$ devenv shell cargo fmt --all -- --check
```

On macOS and Windows with Rust 1.91 or newer:

```console
$ cargo test --workspace --all-targets --all-features
$ cargo clippy --workspace --all-targets --all-features -- -D warnings
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

The outstanding security checks are tracked in the
[security release gates](acceptance/security-release-gates.md), including
cross-account transport tests and packaged-build crash recovery and fault
injection. The release-candidate procedures are in
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

## Diagnostics

FactorSeal keeps local crash reports and bounded operation logs for Desktop,
the CLI, and vault workers. Export them from Desktop's Settings → Diagnostics,
or run `factorseal diagnostics --output factorseal-diagnostics.json` without
unlocking the vault. Desktop can automatically submit crash reports when a Sentry
DSN is configured; its Diagnostics settings control submission. See the
[diagnostics guide](factorseal-desktop/README.md#crash-reports-and-logs) for
storage, privacy, retention, and crash-capture limits.

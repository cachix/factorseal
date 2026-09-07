# Changelog

All notable changes to FactorSeal will be documented in this file.

## Unreleased

- Add experimental personal-sync packet encryption and a durable ciphertext
  spool behind the optional `personal-sync` feature. Packets wrap a fresh content
  key for each reader using ML-KEM HPKE and authenticate the complete envelope
  with ML-DSA. Storage and forwarding need only public membership information.
  Vault-worker integration, persistent reader keys, pairing, and transport are
  still pending; this does not enable live device sync.
- Move personal items into the core model and address them by stable IDs.
  Migrate existing items and their history together on unlock, preserve colliding
  source IDs, and display titles separately from storage addresses. Personal
  documents now atomically retain local causal revisions, pending publication
  metadata, and deletion markers without keeping superseded password values.
  This is the local sync foundation; pairing and network replication are not
  implemented yet. Personal documents use format v4 and native IPC uses v13;
  update the service, CLI, and Desktop together.
- Keep Secret Service search metadata encrypted. Sealed searches return
  `IsLocked` immediately and require manual Desktop unlock before lookup.
- Store root/index, signing, document, password-derived and archive keys in
  locked pages with guard pages; wipe before release and fail on lock errors.
  Exclude Linux key mappings from dumps and wipe them in fork children. Suppress
  Windows WER heap collection. Document remaining plaintext and native-test limits
  in `acceptance/memory-hardening.md`.
- Extend locked storage to retained CLI/Desktop passwords, secret editor text,
  wire values, store responses, archive payloads, and bounded IPC frames. Fail
  edits/operations on lock exhaustion; preserve existing base64/wire formats.
  `WireSecret::new` is now fallible and request/response `encode` returns
  `LockedBytes`. Large archives require a sufficient OS memory-lock quota.

The current formats are metadata v8, database schema v5, snapshot envelope v7,
protected commit v6, document v3 (personal documents v4), record v2, and native protocol v13. Database
schema v3 is authenticated and migrated transactionally after unseal: current
document heads are projected into the new record/history envelope, document
keys are rotated, and a compact current-format commit chain is signed before
the schema version advances. Unknown formats are rejected and never deleted.

- Fix keyring backup/restore with atomic metadata/value imports and v1 archive
  conversion; new archives use v2. Export from live inventory and reject a
  concurrently changed vault. Preserve source items with colliding titles and
  reject password-manager exports that would discard fields or metadata.
- Paginate permission listings within the IPC message budget and bind pages to
  one revision. Honor record expiry during export delivery. Native protocol v12
  requires updating the service, CLI, and Desktop together.
- Release Secret Service sessions when clients disconnect and honor
  `CreateItem(replace=false)` for duplicate attributes. Add regression coverage
  for all eight audit findings.

- Split the installation root from per-document keys: a permanent
  `InstallationId`, a distinct non-replicating Device `VaultId`, a
  hardware-wrapped installation root, and an independently wrapped DEK per
  document.
- Persist every document generation as a fresh-genesis projection under a
  fresh DEK. Deleted and overwritten values are absent from the new snapshot,
  and the current row's wrapped key is replaced in the same
  transaction. Per-change envelopes are no longer written, and one ML-DSA-65
  signature per generation lives in the protected commit, which now records
  its signature algorithm. A rejected mutation is discarded from memory rather
  than left to ride along with the next write, and the vault-owned buffers
  that carry a serialized value are wiped on drop. This is logical deletion,
  not cryptographic erasure: retained wrapped keys and ciphertext can still
  recover earlier values when the installation root is available.
- Record a bounded, value-free change history beside every document: the
  address, operation, time, value version created and replaced, and the
  transport-authenticated caller or service reason. The history is its own
  ciphertext in the document's envelope, under the same key and signed
  commit, so reads never decrypt it and writes append to it instead of
  rebuilding it inside Automerge. Retention is bounded per document kind.
  Expose it as `ListHistory`, `ListProjectHistory`, and `ListCacheHistory`
  under the `List` permission and as `factorseal history --project`; an entry
  made by another application shows a redacted provenance unless the reader
  holds `manage-permissions`. Secret bytes now travel and persist as base64.
- Hardware-wrap only the installation root for each unlock group and derive
  the document-index key from the root, so unsealing needs one hardware
  operation and at most one user verification. The signing seed and document
  keys are root-unwrapped only for the operations that need them.
- Make `factorseal destroy --yes-really-destroy` remove a sealed vault's local
  directory and ask each backend to remove its locally owned keys. Older
  metadata can be removed without unsealing, but retained stateless TPM
  envelopes may remain usable on their original TPM with valid factors.
  Destruction does not revoke backups or guarantee cryptographic erasure.
- Evaluate every candidate grant from one load of the authorization document
  without writing, accept only a kind-wide grant for kind-wide operations,
  prune expired permission registry entries on write, and let revocation
  remove registry entries even after their expired grant records are swept.
  Updating the Linux Secret Service helper atomically replaces its old
  executable-specific grants without rewriting unchanged grants.
- Authenticate the connected Unix server UID and Windows pipe-owner and
  server-process SIDs before sending request bytes. Windows clients request
  identification-only tokens rather than resource-impersonation authority.
- Verify live reads, inventory, mutations, and transactional compaction against
  trusted in-memory document and global heads. Sign eviction deadlines, remove
  public Automerge heads, and seal on storage-integrity failures. Check WAL
  truncation after writes as retention reduction, not erasure.
- Recheck lease, grant, and record expiry after queueing and before response
  delivery. Sealing cancels unsent responses and queued work; native watchdogs
  terminate wedged key owners without deliberately generating a core dump.
- Escape caller-controlled approval text and isolate approval signing in a
  short-lived helper. Wipe caller-owned Argon2, JNI, and WebAuthN secret buffers;
  disable Unix core files and Linux key-owner dumpability.
- Authenticate Linux lifecycle signals and detect tracked session removal.
  Require a transient Secure Enclave key probe before Apple protector use.
- Update ChaCha20 to 0.10.2, add dependency-audit CI, and expand workspace and
  client-only checks. Track outstanding native acceptance, durability tests,
  and independent review in the
  [security release gates](acceptance/security-release-gates.md).
- Replace XChaCha20-Poly1305 vault envelopes with AES-256-GCM
  envelopes and add persisted `default` and `fips` vault profiles. The default
  password KDF is memory-hard Argon2id; `factorseal init --fips` selects
  PBKDF2-HMAC-SHA-256 with 600,000 iterations. Both profiles retain
  AES-256-GCM and ML-DSA-65. Route vault AEAD and PBKDF2 through
  a replaceable provider boundary. The FIPS profile selects standardized
  algorithms but does not claim that the RustCrypto build or Factorseal
  product is FIPS 140-3 validated.
- Forward SecretSpec's declared project, profile, base directory, reason, and
  requested permission duration through each provider request, supporting
  contextual audit and
  approval surfaces without treating caller-provided metadata as identity.
- Add a unified permission lifecycle with structured SecretSpec interaction
  IDs and `factorseal permissions list`, `watch`, `approve`, `deny`, and
  `revoke`. Granting requires a vault-signed challenge
  produced after satisfying one configured unlock group. Pending requests stay
  in memory for seven days, with equivalent requests refreshing the same
  `prm_` ID; approval promotes that ID into durable granted state.
  Interactive watch mode shows the authenticated provider principal and
  requires an explicit terminal decision, prompting for an unlock-group choice
  only when multiple alternatives exist; approval commands expose no factor
  selection flag. Approval prompts let the user accept the app-requested grant
  duration or choose another duration, including `forever`; the signed approval
  binds that choice and the project grant expires accordingly. SecretSpec cache
  addresses are project-derived and checked before project grants are accepted.
  Approval watches now block on a bounded native revision wait instead of
  polling once per second. The local transports serve a bounded number of
  concurrent connections so a watcher cannot prevent providers from creating
  new approval requests.
- Add an owner-bound native permission wait. The Factorseal provider uses it
  internally to complete the original SecretSpec operation after approval,
  without exposing permission-management APIs to SecretSpec.
- Replace the password-plus-biometric boolean with versioned unlock policies:
  comma-separated factors are AND requirements and repeated `--unlock` groups
  are independently hardware-wrapped OR alternatives. Support password,
  biometric-only, and combined groups.
- Add `factorseal seal` so users and scripts can immediately seal the running
  vault through the authenticated local protocol.
- Replace the legacy file format with the per-user Factorseal vault and make
  `factorseal` the sole product CLI.
- Add the per-user vault: embedded Turso persistence, Automerge
  documents, encrypted snapshots authenticated by ML-DSA-65-signed commits,
  scoped grants, bounded leases, and expiration.
- Add authenticated Linux, macOS, and Windows local transports plus native
  developer packaging inputs, a locally signed macOS pkg builder, and CI
  package smoke tests.
- Obtain the vault's nested factor from `--password-file`, an `--askpass`
  helper, or the controlling terminal, and ship askpass helpers with the macOS
  and Windows packages so both can keep unsealing the vault at login without a
  console and without writing the factor to disk. The helpers are interim:
  prompting and asking are planned to move into the vault itself.
- Seal and zeroize the vault from native Linux logind, macOS AppKit, and
  Windows power/session lifecycle notifications; bound IPC frame time as well
  as size so a stalled client cannot hold the vault indefinitely.
- Record the signature algorithm in each protected commit and bind it into
  the signed transcript. Unknown or absent algorithms are refused rather than
  ignored. ML-DSA-65 supplies the vault's device signing identity and protected
  commit signatures.
- Verify signed Turso commit metadata against SQL rows and detect missing
  history, rolled-back heads, a single document rewound behind its newest
  commit, orphaned snapshots, scope tamper, and signature tamper when opening
  the store.
- Re-sign and compact the protected commit chain once it passes a bound,
  down to one commit and one snapshot per document. Every mutation appends a
  whole encrypted document snapshot, so an unpruned chain grew both the
  database and unseal latency without bound in the number of writes. The chain
  is a tamper check, not an audit log.
- Add the password factor used by password-containing unlock groups.
  Nested secret factors must derive their keys from hash or symmetric
  primitives so they do not introduce a separate public-key ciphertext around
  the platform's opaque native sealed-data mechanism.
- Expose the native transport through a lightweight Rust `vault-client`
  feature and implement `factorseal provider` against SecretSpec's typed IPC
  API. The subprocess translates provider operations into cache-only native
  vault requests; its executable is the authenticated principal. Packages ship
  the endpoint in the main binary. For the default vault root, `init` publishes
  the user's provider claim and the agent refreshes it at startup.
- Generate the Linux systemd user unit from a template so its absolute
  `ExecStart` comes from whichever packager installed the binary, rather than
  a hardcoded prefix that only one install location satisfied.
- Add a Nix package, NixOS module, and virtual-TPM VM test for the Linux user
  service, native socket authorization, persistence, delay inhibition, idle
  lockout, and session-lock shutdown. Bundle HardwareSeal's raw TPM 2.0 command
  codec instead of relying on a patched external hardware crate or a dynamic
  TSS library.
- Preserve structured native hardware outcomes through the public vault API:
  unavailable hardware, unsupported policy, cancellation, denial, unavailable
  authorization UI, locked sessions, invalidated credentials, and generic
  hardware failures remain distinguishable without parsing error strings.
- Add `factorseal completions <SHELL>`, which writes a completion script for
  Bash, Elvish, Fish, Nushell, PowerShell, or Zsh to standard output. The
  script asks `factorseal` for suggestions as you type, so completions always
  match the installed binary and cover every command, option, and possible
  value. Path arguments complete files and directories, and internal commands
  stay hidden. Completion answers from the command definition alone: it never
  resolves a vault root, reads vault metadata, or contacts the service.
- Keep the Secret Service name under FactorSeal's control on Linux: when
  another provider still owns `org.freedesktop.secrets` at unseal, the vault
  now takes the name over as soon as that provider releases it or crashes,
  instead of giving up for the rest of the session. The desktop keyring
  activation helper exits with a failure when the Desktop does not publish the
  name in time, so dbus-broker fails waiting clients instead of queuing them
  forever.
- Keep the system keyring available while the vault is sealed on Linux. The
  Desktop now owns `org.freedesktop.secrets` for the whole session and
  bridges to its vault worker over the native socket under an adapter grant
  of its own, so the collection stays registered and reports `Locked` while
  sealed, reads and writes answer `IsLocked`, and `Unlock` returns a prompt
  that raises the unseal window and completes on unseal or dismissal. The
  headless agent keeps serving in-process. On NixOS the Desktop is a
  bus-activated `dev.factorseal.Desktop` user service instead of an XDG
  autostart entry, so dbus-broker starts that instance on demand and systemd
  restarts it if it exits. Instances started with `--no-secret-service`, with
  `FACTORSEAL_DESKTOP_SECRET_SERVICE=0`, or on a non-default `--root` leave
  the bus name to the configured Desktop.

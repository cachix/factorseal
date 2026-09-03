# Security

Factorseal is an unaudited prototype. Do not use it for production secrets
until its native Linux, macOS, and Windows acceptance suites pass and an
independent review has been completed.

Please report suspected vulnerabilities privately to the maintainers. Do not
open a public issue before a coordinated fix is available.

## Vault security boundary

The per-user vault is the intended product architecture. Its keyring interface
is one authorized way to retrieve and update credentials:

- one per-user process is the sole owner of the embedded Turso database, the
  lease-scoped installation root/index capability, and active operation keys;
- every Automerge document has an independent random DEK; snapshots and
  changes are encrypted with AES-256-GCM, and every durable change and commit
  is signed by the installation's device key;
- secret names and values exist inside encrypted documents, not plaintext SQL
  columns or filenames;
- the vault root directory is created mode 0700 on Unix and with a protected,
  owner-only DACL on Windows, and both are re-validated every time the vault
  is opened;
- project and address enumeration requires a separate authenticated `List`
  grant, is available only while unsealed, and never returns secret values;
- a bounded local protocol authorizes transport-derived user, executable, and
  application identities against durable scoped grants;
- duplicated and oversized requests fail closed, and secret buffers use
  zeroizing storage where the API permits;
- idle and absolute unseal leases, explicit sealing, termination signals, startup
  cleanup, native suspend/shutdown/session notifications, and live expiration
  all converge on the same store shutdown path.

Every unlock group is hardware-bound. Factors inside a group are AND
requirements and independently wrapped groups are OR alternatives. Password
groups use memory-hard Argon2id by default. The opt-in FIPS profile instead
uses PBKDF2-HMAC-SHA-256 with 600,000 iterations. Both encrypt the installation
root with AES-256-GCM before one hardware key per group wraps it. The root
derives the document-index key and authenticates the wrapped signing seed and
each generation's independently wrapped DEK.
Biometric groups gate their hardware keys with the platform biometric policy;
biometric-only groups do not contain a password layer. Password files are
accepted only as private
bounded regular files and are intended for short-lived session launch handoff.
Software keyring and DPAPI-only fallbacks are rejected.

Each biometric HardwareSeal unseal performs a native authorization ceremony.
Factorseal then holds only the installation root and document-index key for its
independently bounded idle and absolute lease. A document DEK and exportable
signing seed are root-unwrapped into zeroizing memory only for the operation
that needs them. Native cancellation, denial, unavailable UI, locked session,
and invalidated credentials remain distinct vault errors; unavailable hardware
and unsupported policy are distinct as well. None is treated as a prompt
success or silently downgraded.

## Cryptographic profile and FIPS status

Every persisted vault profile uses AES-256-GCM for authenticated encryption,
SHA-256 and HMAC-SHA-256 for digests and keyed identifiers, and FIPS 204
ML-DSA-65 for device signatures. The default profile uses Argon2id for
password-containing unlock groups because it is memory-hard. The opt-in FIPS
profile uses PBKDF2-HMAC-SHA-256 instead. Its NIST-standardized symmetric,
password-derivation, and post-quantum algorithms are intended to make a future
validated provider and deployment boundary possible.

The current RustCrypto implementations have not been validated through CAVP or
CMVP, Factorseal has no FIPS 140-3 certificate, and algorithm selection alone
does not make a product FIPS compliant or validated. Argon2id is not a
FIPS-approved KDF and is therefore excluded from the FIPS profile. Deployment
status also depends on the exact TPM, operating-system module, device
configuration, build, entropy source, approved operating mode, and product boundary. Platform
biometric ceremonies may depend on classical algorithms and are not claimed to
be completely post-quantum certified.

## Authenticated transports

- Linux uses a mode-0600 Unix socket, `SO_PEERCRED`, same-UID enforcement, peer
  PID, and a digest of `/proc/<pid>/exe`. A peer that is being traced, or that
  was started with `LD_PRELOAD` or `LD_AUDIT` in its environment, is rejected
  before its executable is resolved.
- macOS uses a mode-0600 Unix socket, kernel peer credentials, peer PID, and an
  audit token, then binds the grant to the executable digest.
- Windows uses a local-only named pipe with a current-user/System/admin DACL,
  impersonates each client, verifies its immutable SID against the vault SID,
  and binds the grant to its PID-resolved executable digest.

Caller identity is never accepted from request JSON. Replacing or updating an
executable changes its digest and invalidates its grant. The digest is taken
from a descriptor opened once, so the path, size, and bytes always describe the
same image, and the peer's process start time is compared before and after
resolution, so a reused process ID cannot inherit another process's grant.

## Honest limitations

- An OR policy is bounded by its weakest unlock group. Biometric-only access
  has no independent recovery secret and can be lost after hardware reset,
  biometric enrollment changes, or platform-key invalidation.

- Native lifecycle monitors are implemented on all targets, but packaged
  artifacts remain development-only until suspend, shutdown, logout, and
  session-lock behavior passes on native machines.
- A signed local commit chain detects modified content, missing generations,
  divergent writers, and partial rollback when a newer protected head or
  commit remains, including a single document rewound while the global head is
  untouched. The chain is a tamper check, not an audit log: once it grows past
  a bound it is re-signed and compacted down to the current state of every
  document, and superseded generations are discarded. Every generation is
  encrypted under a fresh document key and each persisted snapshot contains
  only current records, so a superseded generation that has not been compacted
  yet holds no recoverable deleted value. The value-free change history beside
  each document is as trustworthy as the installation root holder during a
  lease; it is a record for the user, not an audit log. It cannot detect rollback
  of the complete vault directory. Detecting that needs a checkpoint held
  outside the directory; the offline MVP does not claim whole-directory
  rollback detection.
- The implemented `factorseal provider` endpoint uses SecretSpec's typed IPC
  protocol over private standard-I/O pipes and translates requests into the
  disposable, project-partitioned `secretspec-provider-cache` document kind
  through the native `VaultClient`. The
  endpoint executable—not the SecretSpec CLI or embedding application—is the
  authenticated vault principal. Its IPC dependency is still pinned to an
  unpublished Git revision, registration is not installed by the packages,
  and installed end-to-end conformance remains required on every target.
- Linux executable authentication depends on access to the ptrace-gated
  `/proc/<pid>/exe` link. The current systemd user unit therefore cannot use
  filesystem mount-namespace hardening. A verified IPC sandbox/application
  identity or different broker design is required to close that isolation gap.
- Executable identity is resolved after the connection is accepted, and no
  supported platform reports the image a peer had at connect time. A same-user
  process can therefore connect, queue its request, and only then execute a
  granted binary. Executable grants are defense in depth against the wrong
  program reaching the vault, not a boundary between same-user processes: a
  process that can execute a granted binary can also debug or preload it. The
  Linux transport rejects a peer that is under a tracer or carries a loader
  injection variable when it connects, which closes the direct debugger and
  `LD_PRELOAD` paths, but a same-user process can inject code and scrub those
  signals before it connects. The boundary the vault does enforce is the Unix
  user or Windows SID.
- Physical TPM/Secure Enclave matrices, official code signing/notarization,
  process-dump protection, locked memory, recovery, and independent audit are
  not complete.
- Windows biometric groups encrypt a TPM sealed-data object under a Windows
  Hello platform-credential PRF output. Native acceptance must establish PRF
  support, TPM binding, timeout/cancellation behavior, the application-owned
  prompt window, and the supported Windows Hello prompt before the release
  gate can pass.
- The current ML-DSA-65 signing seed is root-wrapped and exists in
  zeroizing vault memory only while signing. Signing is not yet performed by a
  non-exportable platform primitive. The retained installation root still has
  authority to unwrap every local document during an active lease, so code
  execution in the unsealed process remains outside this protection.
- Hardware binding cannot prevent an already authorized or compromised client
  from exfiltrating a secret returned to it.
- Losing the platform keys loses the protected data. Recovery is not
  implemented.
- The bounded request-ID window is an idempotency guard against a client
  resubmitting a request, not a replay defense: the local transport is a
  peer-credentialed, owner-only socket or pipe with no intermediary to replay
  through.
- The embedded database is a pre-release Turso build and the sole durable
  store. Its crash consistency is trusted for the one-transaction commit
  path; the signed commit chain detects a torn or tampered result but cannot
  repair it.

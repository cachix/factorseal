# Security

Factorseal is an unaudited prototype. Do not use it for production secrets
until its native Linux, macOS, and Windows acceptance suites pass and an
independent review has been completed.

Please report suspected vulnerabilities privately to the maintainers. Do not
open a public issue before a coordinated fix is available.

## Agent security boundary

The per-user agent is the intended product architecture:

- one per-user process is the sole owner of the embedded Turso database and
  plaintext seal keys;
- every Automerge snapshot and change is encrypted with XChaCha20-Poly1305 and
  every durable change and commit is signed by the seal device key;
- secret names and values exist inside encrypted documents, not plaintext SQL
  columns or filenames;
- a bounded local protocol authorizes transport-derived user, executable, and
  application identities against durable scoped grants;
- replayed and oversized requests fail closed, and secret buffers use
  zeroizing storage where the API permits;
- idle and absolute unlock leases, explicit lock, termination signals, startup
  cleanup, native suspend/shutdown/session notifications, and live expiration
  all converge on the same store shutdown path.

Every seal requires two nested factors. Argon2id uses 64 MiB and three
iterations to derive a password key; that key separately encrypts the DEK and
device-signing seed, and the TPM then wraps both ciphertexts. Neither a copied
seal plus its password nor the TPM material without the password can
recover the keys. Password files are accepted only as private bounded regular
files and are intended for short-lived session launch handoff.

New macOS and Windows seals may additionally require platform user verification
when opening their Secure Enclave or TPM-backed keys. Software keyring and
DPAPI-only fallbacks are rejected.

## Authenticated transports

- Linux uses a mode-0600 Unix socket, `SO_PEERCRED`, same-UID enforcement, peer
  PID, and a digest of `/proc/<pid>/exe`.
- macOS uses a mode-0600 Unix socket, kernel peer credentials, peer PID, and an
  audit token, then binds the grant to the executable digest.
- Windows uses a local-only named pipe with a current-user/System/admin DACL,
  impersonates each client, verifies its immutable SID against the agent SID,
  and binds the grant to its PID-resolved executable digest.

Caller identity is never accepted from request JSON. Replacing or updating an
executable changes its digest and invalidates its grant. The digest is taken
from a descriptor opened once, so the path, size, and bytes always describe the
same image, and the peer's process start time is compared before and after
resolution, so a reused process ID cannot inherit another process's grant.

## Honest limitations

- Native lifecycle monitors are implemented on all targets, but packaged
  artifacts remain development-only until suspend, shutdown, logout, and
  session-lock behavior passes on native machines.
- A signed local commit chain detects modified content, missing history,
  divergent writers, and partial rollback when a newer protected head or
  commit remains, including a single document rewound while the global head is
  untouched. The chain is a tamper check, not an audit log: once it grows past
  a bound it is re-signed and compacted down to the current state of every
  document, and superseded generations are discarded. It cannot detect rollback
  of the complete seal directory. Detecting that needs a checkpoint held
  outside the directory; the offline MVP does not claim whole-directory
  rollback detection.
- SecretSpec compiles its Factorseal provider against the native `AgentClient`.
  Packaged end-to-end conformance remains required on every target.
- Linux executable authentication depends on access to the ptrace-gated
  `/proc/<pid>/exe` link. The current systemd user unit therefore cannot use
  filesystem mount-namespace hardening. A verified IPC sandbox/application
  identity or different broker design is required to close that isolation gap.
- Executable identity is resolved after the connection is accepted, and no
  supported platform reports the image a peer had at connect time. A same-user
  process can therefore connect, queue its request, and only then execute a
  granted binary. Executable grants are defense in depth against the wrong
  program reaching the agent, not a boundary between same-user processes: a
  process that can execute a granted binary can also debug or preload it. The
  boundary the agent does enforce is the Unix user or Windows SID.
- Physical TPM/Secure Enclave matrices, official code signing/notarization,
  process-dump protection, locked memory, recovery, and independent audit are
  not complete.
- Windows currently selects the hardware-enforced CNG UI-protection policy,
  not the hardware crate's hookable application-level Hello convenience gate.
  Native acceptance must establish the supported Windows prompt behavior and
  modern Windows Hello path before the release gate can pass.
- The current Ed25519 signing seed is hardware-wrapped and exists in zeroizing
  agent memory during a lease. Signing is not yet performed by a non-exportable
  platform signing primitive.
- Hardware binding cannot prevent an already authorized or compromised client
  from exfiltrating a secret returned to it.
- Losing the platform keys loses the protected data. Recovery is not
  implemented.

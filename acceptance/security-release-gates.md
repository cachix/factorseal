# Security remediation release gates

Compatibility is defined by the source constants and decoder/migration tests:
[metadata](../src/vault/seal/metadata.rs), [database schema](../src/vault/store/migration.rs),
[protocol](../src/vault/protocol/wire.rs), and the encrypted-document codecs.
Metadata v7 remains readable alongside v8; database schema v3 migrates to v5. Unsupported formats fail closed and are
not automatically deleted. Do not destroy the only copy of needed data to test
an upgrade. Portable encrypted archives are the supported cross-device restore
mechanism; they must be exported before losing access to the source vault.

## Implemented checks

- Authenticate Unix server UID and Windows pipe-owner/server-process SID before
  sending request bytes. Windows clients use identification-only SQOS.
- Keep verified document/global heads in memory. Check live reads, inventory,
  mutation preconditions and transactional compaction against them. Seal on
  storage-integrity failures; never certify corrupt or rolled-back history.
- Sign eviction deadlines and schedule from the verified inventory.
- Remove public Automerge heads; encrypted records/history remain domain-bound.
- Recheck elapsed time after queueing/waits and before releasing results. Cap
  transport delivery by lease, grant and record expiry; refuse expired renewal.
- Announce shutdown outside the command queue, discard queued work, and publish
  completion only after the worker and queued secret buffers are dropped.
  Native watchdogs start before potentially blocking lifecycle teardown and
  terminate wedged owners without deliberately generating a core dump.
- Escape externally supplied approval fields as quoted ASCII; visibly truncate
  long reasons but not identity/scope. Approval signing runs in a separate
  short-lived key-owning helper, not the inspectable IPC client.
- Clear caller-owned Argon2 workspace and writable JNI/WebAuthN secret buffers.
  Disable Unix core files and Linux key-owner dumpability before acquiring keys.
- Detect tracked Linux session removal, authenticate logind signal senders, and
  require a transient Secure Enclave key probe before Apple protector use.
- Preserve typed native failures through public create/unseal APIs.
- Use ChaCha20 0.10.2 in the lockfile and check the RustSec advisory database.

Regression tests cover rollback and compaction rejection, missing documents,
eviction tampering, empty snapshot headers, queued lease expiry, grant/record
delivery limits, clock changes, full-queue shutdown, watchdog termination in a
subprocess, Linux dump settings in a subprocess, terminal controls, native error
propagation and same-account transport checks. These do not replace native
hardware acceptance or independent review.

Current automated verification is recorded by [CI](../.github/workflows/ci.yml)
and the [daily dependency check](../.github/workflows/dependency-security.yml).
The dependency checker reports six explicitly tracked maintenance exceptions;
these are not vulnerability fixes. Automated tests and cross-compilation are
not evidence of native GUI/Windows/macOS execution or physical TPM, Secure
Enclave, Android or two-account acceptance.

## Required native evidence before release

- Desktop: exercise initialization/unlock success, wrong factor, biometric
  cancellation, helper startup failure, sealing, lease expiry, GUI crash and
  parent loss during a native prompt. Confirm the worker exits, endpoints stop
  serving, and a second unlock uses a fresh worker. Check Unicode/IME, paste,
  selection and clearing of all secret fields; verify plaintext never enters
  the renderer's text cache. Linux CLI-owner dumpability must remain disabled.
- Windows private files: run ACL creation/replacement tests in shared parent
  directories and verify a second account cannot read intermediate or final
  export files. Test reparse-point/password inputs and permission-query failure.

- Windows: run tests on Windows, including the connected-pipe owner test;
  additionally squat a permissive pipe from a different account and capture
  zero request bytes. Verify failed identity queries fail closed, custom
  endpoints and busy-pipe timeouts, normal CRUD, and identification-only tokens
  that cannot be used for resource impersonation. Cross-compilation is not this
  evidence.
- Linux: physical TPM, suspend, shutdown, lock, logout with lingering services,
  and removal of one of several tracked sessions. Removing another user's
  untracked session must not seal this vault.
- Apple: compile and run the signed/entitled package on a physical SEP machine;
  reject a non-SEP machine/simulator, including password-only policy. Confirm
  Keychain access policy, biometric cancellation/denial and lock/sleep teardown.
- Android: CheckJNI tests must demonstrate Java-array cleanup on successful and
  failed operations. Biometric use remains unsupported until the host bridge
  is implemented; it must continue to fail closed.
- Exercise database checkpoint contention, crash recovery and fault injection
  against native packaged builds, not just the single-connection test fixtures.
- Review the new native handle operations and shutdown paths independently.

## Deliberately excluded guarantees

Deletion, overwrite, clear, expiry and `destroy` provide logical/local removal,
not cryptographic erasure or retained-backup revocation. Checked WAL truncation
reduces retention; it cannot erase all free pages, storage remnants or copies.
Stateless TPM envelopes may remain usable on their original TPM with valid
factors. Whole-directory rollback still needs an external trusted checkpoint.

Locked/guarded memory, comprehensive wiping of crypto/Automerge/OS internal
copies, Windows dump policy and hard key-retention limits for library embedders
remain open hardening work. Privileged inspection, same-user code injection
and exfiltration by an already authorized client are not prevented by executable
grants. See [SECURITY.md](../SECURITY.md) for the actual security boundary.

# Security remediation release gates

This unreleased format replaces metadata v7/schema v4/envelope v6/commit v5
with v8/v5/v7/v6. Older vaults are rejected, not migrated or automatically
deleted. Do not destroy the only copy of needed data to test an upgrade.

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

Local verification on Linux: 234 workspace/all-feature/all-target tests passed;
workspace Clippy with warnings denied, documentation with warnings denied,
formatting, the nine CI feature combinations and `git diff --check` passed.
RustSec scan: no reported vulnerabilities or yanked dependencies. Windows
MSVC full-workspace/all-target and client-only cross-Clippy passed. These are
local checks, not evidence of native Windows/macOS execution or physical TPM,
Secure Enclave, Android or two-account pipe acceptance.

## Required native evidence before release

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

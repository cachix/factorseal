**Memory hardening verification — 2026-09-06**

Implemented owned key, retained password/editor, wire-value, store-response,
archive-payload and framed-IPC storage with dedicated locked pages, inaccessible
guards, full-region zeroization before release, Linux dump exclusion and
child-fork wiping, and Windows WER heap suppression. Lock failures propagate;
there is no pageable fallback for these allocations. See
`acceptance/memory-hardening.md` for exact coverage, remaining plaintext copies,
Rust API changes, and deployment limits.

Verification of the expanded implementation:

- Full workspace, all targets/features: **340 tests passed** (excluding a
  separately reported subprocess rerun). Includes OS-enforced guard faults,
  zero-lock-limit rejection, Linux mapping flags, fork wiping, multi-page wiping
  including padding, exact serialization bounds, base64 compatibility and
  malformed input, ownership transfer, Desktop UTF-8 edits and simulated lock
  failure/recovery, existing crypto vectors, and vault regressions.
- Workspace Clippy with warnings denied: passed.
- Lightweight `vault-client` Clippy with warnings denied: passed. This check
  caught and corrected a newly unused transport import under this feature.
- Nine feature configurations passed: `vault-client`, `key-protection`,
  `vault-store`, `vault-store,key-protection`, `vault-client,hardware`, `hardware`,
  `cli`, `vault`, `vault,cli,hardware`. Feature-limited test builds retain existing
  unused/dead-code warnings.
- Formatting, documentation with warnings denied, and diff whitespace: passed.
- The exact new security/memory source and Windows tests were copied into a
  minimal check crate with Windows 0.61.3, then cross-compiled and Clippy-checked
  for `x86_64-pc-windows-msvc`. This isolates the new code from the existing Turso
  cross-build blocker; it is not a full Windows app build or native execution.
- Real Linux TPM create/unseal/storage/import/export/seal drill: passed for three
  isolated synthetic vaults. `/proc/<agent>/status` reported 8, 12, and 12 KiB
  locked during sampling. This is evidence of active locking, not peak memory
  accounting: temporary operation keys and IPC buffers may coexist with the two
  retained root/index pages. Exact NUL/newline bytes survived storage; duplicate
  and repeated imports, v2 backup restore, and v1 keep/replace imports into empty
  and populated vaults passed. Subsequent writes, permission listing and explicit
  sealing also passed. Test agents exited after sealing.

Native Windows/macOS behavior and comprehensive plaintext memory protection
remain unverified/out of scope for the guarantee of this implementation.
Closure of issue #3 does not establish those guarantees or complete the
documented release gates. Full interactive Desktop validation of the
allocation-error display remains outstanding; the
editor behavior is tested without a native window.

Local detailed verification logs: `/tmp/factorseal-buffers-tests.log`,
`/tmp/factorseal-buffers-clippy.log`, `/tmp/factorseal-buffers-validation.log`,
`/tmp/factorseal-buffers-windows.log`, and
`/tmp/factorseal-buffers-native-drill.log`. Native synthetic drill artifacts:
`/tmp/factorseal-release-drill._0h_prv7`.

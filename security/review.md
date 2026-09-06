# Security review and release evidence

Scope: issue #3, including process memory, local storage integrity, native
authentication, authorization abuse, diagnostic privacy and parser assurance.
This is an internal code/implementation review by the coding agent, not an
independent security audit, penetration test, certification or production
approval. The unaudited-prototype warning remains in force.

## Findings and dispositions

| Finding | Disposition and evidence |
| --- | --- |
| A caller could displace unrelated pending approvals | Fixed in `0c2a960`: per-caller/global capacity and monotonic rate limits; no eviction on overload. Duplicate requests preserve expiry/revision. Unit and service tests cover churn, denial, clock changes and capacity. |
| Metadata could block on FIFO open or follow a final link | Fixed: validated-handle opens reject final links, non-regular files and hard links. FIFO regression runs in a timeout-bounded subprocess. The lock file uses the same opener. |
| Windows root validation omitted ownership | Fixed: explicitly set and verify current-user owner; protected DACL and child inheritance tests. Two-account acceptance tests real file access and the production pipe listener. |
| ACL inspection missed inherited entries | Fixed after native CI exposed it: enumerate every ACE with `GetAce`, including inherited grants, and reject unfamiliar entry types. Native child-inheritance and second-account access tests pass. |
| Export rename was not followed by parent synchronization | Fixed on Unix: sync the private file, atomically replace the destination, then sync its parent. Volume-specific durability and Windows power-loss behavior still require native fault injection. |
| Lease-retained keys and operation keys could be paged | Fixed for the keys enumerated in the memory profile: dedicated guarded mappings, mandatory locks, direct protected key unwrap and zeroization before release. Bootstrap/password/document/library copies are explicitly excluded. |
| Linux fork could leave an unlocked child copy of keys | Fixed with `MADV_WIPEONFORK`, verified in a fork regression. The parent copy remains intact. Other platforms require embedder fork/process policy. |
| Windows crash reporting could include key pages/heap | Added WER NOHEAP and per-key excluded-memory registration; failures are propagated. Administrative/full/third-party dumps remain outside the process-local guarantee. |
| Security telemetry could leak credential context or amplify disk writes | Fixed-shape aggregate counters take only an enum. Serialization tests check the shape; hot-path recording cannot accept identifiers or perform I/O. Existing diagnostics snapshots persist them. |
| No continuously exercised parser corpus | Ten libFuzzer targets use production codecs and validators, valid synthetic seeds, address sanitizer and RSS/input/time limits. Product/fuzz lockfile drift fails CI. Local smoke runs are not a substitute for continuing CI. |
| Malformed Automerge bundles could panic before checksum validation | Found by hosted document fuzzing. [Upstream PR #1540](https://github.com/automerge/automerge/pull/1540) uses the existing fallible column loader; Factorseal pins the patched fork. The synthetic crash is retained in the corpus and a load/migration regression. No application-level binary parser was added. |
| Linux CI could hide an earlier test-command failure | Fixed: the multi-command test shell now exits on its first failure. A later successful integration test cannot mask a failed workspace suite. |
| Complete-directory rollback cannot establish freshness | Explicitly excluded by the offline profile. A genuine external witness requires authenticated monotonic state and a crash/recovery protocol; merely moving a file outside the directory is insufficient. |

## Verification record

Local Linux checks cover process dump settings, locked/dump-excluded pages,
zero-lock-budget failure, fork wiping, key and document round trips, signed
chain tampering/partial rollback, authorization abuse, diagnostics privacy and
all ten parser smoke runs. Windows code and test bodies are cross-compiled and
linted separately; that is not native runtime evidence.

Native runtime evidence is now available from
[the passing macOS and Windows security run](https://github.com/cachix/factorseal/actions/runs/34032047320)
at `bbca3af`. It includes the Windows two-account file/pipe denial and foreign
server zero-byte-disclosure probe. The full macOS test/package job also passed
in [the main CI run](https://github.com/cachix/factorseal/actions/runs/34031642807)
at `94bd402`. Production code is identical between those revisions; subsequent
changes fixed assurance workflow selection and test synchronization.

The Windows workflow invokes `acceptance/windows-security.ps1` on an isolated
administrator runner. It creates only synthetic fixtures and a temporary
non-administrator account, checks owner positive controls and second-account
file/pipe denial, and tests client rejection of a permissive foreign pipe with
zero request-byte disclosure. It removes its processes, account and fixtures
in cleanup. Normal Windows/macOS test jobs execute the platform memory tests.
Use the job results for the exact reviewed commit, not an older passing run.

Native TPM/SEP/Hello, lifecycle and physical two-account acceptance remain
tracked in #2. Hosted-runner file/pipe tests do not establish those hardware
properties. Fuzzing has finite coverage: retain and resolve any discovered
crash, timeout or OOM. Automerge/Turso and native OS internals remain
dependencies, not newly verified implementations.

## Independent-review handoff

Provide the reviewer with the exact commit and lockfiles, `SECURITY.md`, both
profiles, this findings table, the native CI artifacts, the fuzz corpus and
workflow, and the physical acceptance evidence from #2. The reviewer should
independently examine the unsafe memory/handle operations, key lifetime and
error cleanup, peer authentication races, inherited ACLs, database recovery,
destruction/backup semantics, compressed parser resource use and authorization
abuse. Require reproducible findings, severity, fixes, retest results and a
written scope/limitations statement. Release-blocking findings must be closed
by that reviewer. No independent review has been commissioned or completed by
this internal implementation pass; issue #3 cannot honestly claim that gate.
